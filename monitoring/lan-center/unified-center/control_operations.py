"""Bounded, authenticated operation coordination for the unified center.

HTTP authentication is owned by :mod:`unified_center`.  This module only
discovers local, reviewed extensions and runs their operations behind one
revision check, one bounded queue and one cross-process write lock.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
SENSITIVE = re.compile(
    r"(?:password|passwd|secret|token|private|credential|authorization|cookie|key|jwt|totp)$", re.I,
)
MODULES = {
    "subscriptions": ("subscription_lifecycle", "extensions.subscription_lifecycle"),
    "dns": ("dns_management", "extensions.dns_management"),
    "monitors": ("kuma_management", "extensions.kuma_management"),
}


class OperationError(RuntimeError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code, self.status = code, status


def _atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        with open(temporary, "x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _public(value: Any, depth: int = 0, key: str = "") -> Any:
    """Bound and redact extension output before it reaches a LAN client."""
    if SENSITIVE.search(key):
        return "[已隐藏]"
    if depth > 7:
        return None
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, str):
        return "".join(ch for ch in value if ch >= " " and ch not in "\x7f\r\n")[:2048]
    if isinstance(value, list):
        return [_public(item, depth + 1) for item in value[:2000]]
    if isinstance(value, dict):
        output = {}
        for raw_key, item in list(value.items())[:256]:
            name = str(raw_key)[:96]
            output[name] = _public(item, depth + 1, name)
        return output
    return str(value)[:256]


def _revision(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class NodesExtension:
    """Read inventory and run native provider tests without selector writes."""

    def __init__(self, center: Any):
        self.center = center

    def actions(self) -> dict[str, dict[str, Any]]:
        return {
            "nodes.test": {"write": False, "timeout_seconds": 20},
            "nodes.bulk_test": {"write": False, "timeout_seconds": 120},
        }

    def snapshot(self) -> dict[str, Any]:
        # The management endpoint must never start the multi-upstream overview
        # fan-out.  It reuses the latest independently collected evidence; the
        # normal overview poll refreshes that cache.
        with self.center.cache_lock:
            overview = self.center.cache
            cache_age = time.monotonic() - self.center.cache_at if overview is not None else None
        rows = overview.get("nodes", []) if isinstance(overview, dict) else []
        if not isinstance(rows, list):
            rows = []
        identities = sorted(
            (str(row.get("provider", "")), str(row.get("name", "")))
            for row in rows if isinstance(row, dict)
        )
        revision = _revision(identities)
        return {
            "state": "ok" if rows else "pending" if overview is None else "unknown",
            "revision": revision,
            "capabilities": {
                "actions": list(self.actions()),
                "latency_test": "native_mihomo_https",
                "business_capability_retest": False,
                "scheduler_control": "read_only",
            },
            "count": len(rows),
            "nodes": rows,
            "inventory_scope": "loaded_runtime_only",
            "candidate_channel": "isolated_admission_queue",
            "candidate_nodes_in_runtime": False,
            "evidence_age_seconds": int(cache_age) if cache_age is not None and cache_age >= 0 else None,
            "detail": (
                "单测/批测是 Mihomo 原生 HTTPS 延迟检查；业务能力由独立调度器周期评估，当前仅展示其证据，不伪装支持立即复测"
                if rows else ("等待总览采集节点证据" if overview is None else "暂无节点运行证据")
            ),
        }

    def execute(self, action: str, params: dict[str, Any], progress: Any) -> dict[str, Any]:
        if action == "nodes.test":
            progress("testing")
            return self.center.node_test(params)
        if action != "nodes.bulk_test":
            raise OperationError("operation_action_unsupported", 404)
        rows = params.get("nodes")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 10:
            raise OperationError("node_bulk_fields_invalid")
        for row in rows:
            if not isinstance(row, dict):
                raise OperationError("node_bulk_fields_invalid")

        def test_one(index: int, row: dict[str, Any]) -> tuple[int, dict[str, Any]]:
            try:
                return index, {"state": "ok", **self.center.node_test(row)}
            except Exception as error:
                code = getattr(error, "code", "node_test_failed")
                code = code if isinstance(code, str) and IDENTIFIER.fullmatch(code) else "node_test_failed"
                return index, {
                    "state": "error", "provider": str(row.get("provider", ""))[:160],
                    "name": str(row.get("name", ""))[:160], "error": code,
                }

        results: list[dict[str, Any] | None] = [None] * len(rows)
        progress("testing", completed=0, total=len(rows))
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="center-node-batch") as pool:
            futures = [pool.submit(test_one, index, row) for index, row in enumerate(rows)]
            for completed, future in enumerate(as_completed(futures), 1):
                index, result = future.result()
                results[index] = result
                progress("testing", completed=completed, total=len(rows))
        progress("readback", completed=len(rows), total=len(rows))
        output = [item for item in results if item is not None]
        return {"state": "ok" if all(item["state"] == "ok" for item in output) else "warning", "results": output}


class DnsRuntimeAdapter:
    """Bounded bridge from DNS transactions to the PID-1 supervisor."""

    def __init__(self, center: Any, corefile: Path, fragment: Path, hosts: Path):
        self.center, self.corefile, self.fragment, self.hosts = center, corefile, fragment, hosts
        self.runtime_root = center.data_root / "unified"
        self.requests = self.runtime_root / "requests"
        self.status = self.runtime_root / "status.json"
        self.deadline_seconds = 28.0

    @staticmethod
    def _safe_hash(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    def verify_writable_directory(self) -> bool:
        parent = self.corefile.parent
        if not parent.is_dir() or self.fragment.parent != parent or self.hosts.parent != parent:
            return False
        first = parent / (".center-write-probe-" + secrets.token_hex(8))
        second = parent / (".center-write-proof-" + secrets.token_hex(8))
        payload = secrets.token_bytes(32)
        try:
            with open(first, "xb") as stream:
                os.chmod(first, 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if first.read_bytes() != payload:
                return False
            os.replace(first, second)
            if second.read_bytes() != payload:
                return False
            directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            second.unlink()
            directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return True
        except OSError:
            return False
        finally:
            first.unlink(missing_ok=True)
            second.unlink(missing_ok=True)

    def reload(
        self, *, request_id: str, expected_core_sha256: str,
        expected_fragment_sha256: str, purpose: str, recovery_of: str | None,
    ) -> dict[str, Any]:
        recovery_reference = (
            isinstance(recovery_of, str) and len(recovery_of) >= 8
            and IDENTIFIER.fullmatch(recovery_of) is not None
        )
        if (not isinstance(request_id, str) or not IDENTIFIER.fullmatch(request_id)
                or len(request_id) < 8 or not self._safe_hash(expected_core_sha256)
                or not self._safe_hash(expected_fragment_sha256)
                or purpose not in {"apply", "rollback", "recovery"}
                or (purpose == "recovery" and not recovery_reference)
                or (purpose != "recovery" and recovery_of is not None)
                or recovery_of == request_id):
            return {"state": "error", "error_code": "invalid_reload_request"}
        now = time.time()
        expires = now + self.deadline_seconds
        self.requests.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.requests / ("dns-" + hashlib.sha256(request_id.encode()).hexdigest()[:24] + ".json")
        _atomic(path, {
            "component": "dns", "request_id": request_id,
            "created_at": now, "expires_at": expires,
            "expected_core_sha256": expected_core_sha256,
            "expected_fragment_sha256": expected_fragment_sha256,
            "purpose": purpose, "recovery_of": recovery_of,
        })
        deadline = time.monotonic() + self.deadline_seconds
        try:
            while time.monotonic() < deadline:
                try:
                    if self.status.stat().st_size > 256 * 1024:
                        raise OSError
                    status = json.loads(self.status.read_text(encoding="utf-8"))
                except (OSError, ValueError, TypeError):
                    time.sleep(.2)
                    continue
                evidence = status.get("last_request") if isinstance(status, dict) else None
                if not isinstance(evidence, dict) or evidence.get("id") != request_id:
                    time.sleep(.2)
                    continue
                if evidence.get("purpose") != purpose or evidence.get("recovery_of") != recovery_of:
                    return {"state": "error", "request_id": request_id, "error_code": "dns_reload_ack_mismatch"}
                state = evidence.get("state")
                if state == "failed":
                    code = evidence.get("error_code")
                    code = code if isinstance(code, str) and IDENTIFIER.fullmatch(code) else "dns_reload_failed"
                    return {
                        "state": "error", "request_id": request_id, "error_code": code,
                        # PID 1 is the sole authority on whether the failed
                        # request crossed the terminate boundary.  Only that
                        # condition mints one linked recovery restart.
                        "recovery_required": evidence.get("recoverable") is True,
                    }
                if state != "completed":
                    time.sleep(.2)
                    continue
                old_pid, new_pid = evidence.get("old_pid"), evidence.get("new_pid")
                fragment_hash = evidence.get("loaded_fragment_sha256")
                if (evidence.get("loaded_core_sha256") != expected_core_sha256
                        or fragment_hash != expected_fragment_sha256
                        or not isinstance(new_pid, int) or new_pid <= 0
                        or isinstance(old_pid, int) and old_pid == new_pid
                        or not isinstance(evidence.get("finished_at"), (int, float))
                        or evidence["finished_at"] > expires + 1):
                    return {"state": "error", "request_id": request_id, "error_code": "dns_reload_ack_mismatch"}
                return {
                    "state": "completed", "request_id": request_id,
                    "old_pid": old_pid, "new_pid": new_pid,
                    "loaded_core_sha256": expected_core_sha256,
                    "loaded_fragment_sha256": expected_fragment_sha256,
                    "purpose": purpose, "recovery_of": recovery_of,
                    "finished_at": evidence["finished_at"],
                }
            return {"state": "error", "request_id": request_id, "error_code": "dns_reload_timeout"}
        finally:
            # If PID 1 has not consumed it, deletion plus expires_at prevents a
            # late restart after this operation has already failed.
            path.unlink(missing_ok=True)

    def probe(self) -> dict[str, Any]:
        def http(name: str, default: str) -> tuple[str, dict[str, Any]]:
            url = os.getenv("CENTER_DNS_" + name.upper() + "_URL", default)
            try:
                request = urllib.request.Request(url, headers={"Accept": "text/plain"})
                with self.center.opener.open(request, timeout=2) as response:
                    response.read(1024)
                    status = int(getattr(response, "status", 0))
                return name, {"state": "ok" if status == 200 else "error", "status": status}
            except Exception:
                return name, {"state": "error"}

        def dns(transport: str) -> tuple[str, dict[str, Any]]:
            try:
                from dns_diagnostics import query_wire
                value = query_wire("example.com", "A", "127.0.0.1:53", transport, 2)
                return transport, {"state": "pending", "rcode": value.get("rcode")}
            except Exception:
                return transport, {"state": "error"}

        evidence: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-runtime-probe") as pool:
            futures = [
                pool.submit(http, "health", "http://127.0.0.1:18080/health"),
                pool.submit(http, "ready", "http://127.0.0.1:18181/ready"),
                pool.submit(dns, "udp"), pool.submit(dns, "tcp"),
            ]
            for future in futures:
                name, row = future.result(timeout=3)
                evidence[name] = row
        valid = {"NOERROR", "NXDOMAIN"}
        dns_ok = (
            evidence.get("udp", {}).get("rcode") in valid
            and evidence.get("tcp", {}).get("rcode") == evidence.get("udp", {}).get("rcode")
        )
        for transport in ("udp", "tcp"):
            if evidence.get(transport, {}).get("state") == "pending":
                evidence[transport]["state"] = "ok" if dns_ok else "error"
        state = "ok" if all(row.get("state") == "ok" for row in evidence.values()) else "error"
        return {"state": state, "checked_at": int(time.time()), "evidence": evidence}


class ControlPlane:
    def __init__(self, center: Any):
        self.center = center
        self.root = center.center_root / "operations"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="center-operation")
        self.slots = threading.BoundedSemaphore(12)
        self.jobs: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.quarantined: set[tuple[str, str]] = set()
        self.snapshot_lock = threading.Lock()
        self.snapshot_cache: dict[str, tuple[int, float, dict[str, Any]]] = {}
        self.snapshot_refreshing: set[str] = set()
        self.extensions: dict[str, Any] = {"nodes": NodesExtension(center)}
        context = {
            "data_root": center.data_root,
            "center_root": center.center_root,
            "namespace": center.namespace,
            "manager": center.manager,
            "clash": center.clash,
            "remote_timeout": center.remote_timeout,
            "opener": center.opener,
            "write_lock_managed": True,
            "execute_locked": True,
        }
        corefile = Path(os.getenv("CENTER_COREFILE", "/etc/coredns/Corefile"))
        fragment = Path(os.getenv("CENTER_DNS_FRAGMENT", "/etc/coredns/Corefile.managed"))
        hosts = Path(os.getenv("CENTER_DNS_HOSTS", "/etc/coredns/hosts"))
        binary = os.getenv("CENTER_COREDNS_BIN", "/usr/local/bin/coredns")
        context.update({
            "corefile": corefile, "dns_fragment": fragment, "dns_hosts": hosts,
            "coredns_binary": binary, "dns_validator_timeout": 12,
        })
        try:
            adapter = DnsRuntimeAdapter(center, corefile, fragment, hosts)
            executable = Path(binary).is_file() and os.access(binary, os.X_OK) or shutil.which(binary) is not None
            status_ready = adapter.status.is_file() and adapter.status.stat().st_size <= 256 * 1024
            writable = executable and status_ready and corefile.is_file() and adapter.verify_writable_directory()
            proof = adapter.probe() if writable else {"state": "unsupported"}
            if writable and proof.get("state") == "ok":
                from dns_validator import create_validator
                context.update({
                    "dns_validator": create_validator(context),
                    "dns_reloader": adapter.reload,
                    "dns_probe": adapter.probe,
                    "dns_runtime_deadline_enforced": True,
                    "dns_runtime_writable_verified": True,
                })
        except Exception:
            # Runtime DNS writes stay unsupported unless every proof exists.
            center.audit("dns-runtime", "unsupported", error_code="dns_runtime_adapter_unavailable")
        self.extension_errors: dict[str, str] = {}
        for name, module_names in MODULES.items():
            found = False
            try:
                module = None
                for module_name in module_names:
                    if importlib.util.find_spec(module_name) is not None:
                        found = True
                        module = importlib.import_module(module_name)
                        break
                if module is None:
                    continue
                factory = getattr(module, "create_extension")
                extension = factory(context)
                if not all(callable(getattr(extension, method, None)) for method in ("snapshot", "actions", "execute")):
                    raise TypeError("extension_contract_invalid")
                self.extensions[name] = extension
            except Exception as error:
                # Optional modules are explicit unsupported capabilities, never a fake success.
                if found:
                    code = (
                        "extension_contract_invalid" if isinstance(error, (AttributeError, TypeError))
                        else "extension_start_failed"
                    )
                    self.extension_errors[name] = code
                    center.audit("extension-load", "error", module=name, error_code=code)
                continue
        self._recover_jobs()

    def _recover_jobs(self) -> None:
        for path in sorted(self.root.glob("*.json"))[-100:]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict) or value.get("job_id") != path.stem:
                    continue
                if value.get("state") in {"pending", "running"}:
                    value.update(state="error", stage="interrupted", error="operation_interrupted", completed_at=int(time.time()))
                    _atomic(path, value)
                self.jobs[path.stem] = value
            except (OSError, ValueError, TypeError):
                continue

    @staticmethod
    def _allowed_actions(extension: Any) -> list[str]:
        actions = extension.actions()
        if not isinstance(actions, dict):
            raise TypeError("actions_invalid")
        return [
            action for action, meta in actions.items()
            if isinstance(action, str) and IDENTIFIER.fullmatch(action)
            and isinstance(meta, dict) and meta.get("supported", True) is not False
            and type(meta.get("write")) is bool
            and (meta["write"] is False or meta.get("deadline_enforced") is True)
            and type(meta.get("timeout_seconds", 30)) in (int, float)
            and 1 <= meta.get("timeout_seconds", 30) <= 300
        ]

    @classmethod
    def _action_capabilities(cls, extension: Any) -> tuple[list[str], dict[str, Any], dict[str, str]]:
        actions = extension.actions()
        if not isinstance(actions, dict):
            raise TypeError("actions_invalid")
        allowed = cls._allowed_actions(extension)
        allowed_set = set(allowed)
        metadata: dict[str, Any] = {}
        unavailable: dict[str, str] = {}
        for action, meta in actions.items():
            if not isinstance(action, str) or not IDENTIFIER.fullmatch(action) or not isinstance(meta, dict):
                continue
            if action in allowed_set:
                row = {
                    key: meta[key] for key in (
                        "write", "scope", "timeout_seconds", "sensitive_input", "sensitive_fields",
                    ) if key in meta
                }
                metadata[action] = _public(row)
            else:
                reason = meta.get("reason") or meta.get("error_code") or (
                    "unsupported" if meta.get("supported", True) is False else "capability_contract_incomplete"
                )
                unavailable[action] = str(reason)[:96] if IDENTIFIER.fullmatch(str(reason)[:96]) else "unsupported"
        return allowed, metadata, unavailable

    def _collect_module_snapshot(self, name: str) -> dict[str, Any]:
        extension = self.extensions.get(name)
        if extension is None:
            error = self.extension_errors.get(name)
            return {
                "state": "error" if error else "unsupported", "revision": None,
                "error_code": error,
                "capabilities": {"actions": []},
                "detail": "管理模块启动失败" if error else "当前镜像未接入此管理模块",
            }
        try:
            value = extension.snapshot()
            if not isinstance(value, dict):
                raise TypeError("snapshot_invalid")
            allowed, action_meta, unavailable = self._action_capabilities(extension)
            value.setdefault("state", "unknown")
            value.setdefault("revision", _revision(value))
            capabilities = value.get("capabilities")
            capabilities = dict(capabilities) if isinstance(capabilities, dict) else {}
            capabilities["actions"] = allowed
            capabilities["action_meta"] = action_meta
            capabilities["unavailable_actions"] = unavailable
            value["capabilities"] = capabilities
            return _public(value)
        except Exception:
            return {
                "state": "error", "revision": None,
                "capabilities": {"actions": []}, "detail": "管理模块读取失败",
            }

    def _refresh_module_snapshot(self, name: str, extension: Any) -> None:
        try:
            value = self._collect_module_snapshot(name)
            with self.snapshot_lock:
                if self.extensions.get(name) is extension:
                    self.snapshot_cache[name] = (id(extension), time.monotonic(), value)
        finally:
            with self.snapshot_lock:
                self.snapshot_refreshing.discard(name)

    def _module_snapshot(self, name: str) -> dict[str, Any]:
        extension = self.extensions.get(name)
        is_slow = (
            extension is not None and name == "monitors"
            and extension.__class__.__module__.split(".")[-1] == "kuma_management"
        )
        if not is_slow:
            return self._collect_module_snapshot(name)
        with self.snapshot_lock:
            cached = self.snapshot_cache.get(name)
            if cached and cached[0] != id(extension):
                self.snapshot_cache.pop(name, None)
                cached = None
            if name not in self.snapshot_refreshing and (not cached or time.monotonic() - cached[1] >= 5):
                self.snapshot_refreshing.add(name)
                threading.Thread(
                    target=self._refresh_module_snapshot, args=(name, extension),
                    name="center-snapshot-" + name, daemon=True,
                ).start()
            if cached:
                value = dict(cached[2])
                value["evidence_age_seconds"] = max(0, int(time.monotonic() - cached[1]))
                if time.monotonic() - cached[1] >= 30:
                    value["stale"] = True
                return value
        try:
            allowed, action_meta, unavailable = self._action_capabilities(extension)
        except Exception:
            allowed, action_meta, unavailable = [], {}, {}
        return {
            "state": "pending", "revision": None,
            "capabilities": {
                "actions": allowed, "action_meta": action_meta,
                "unavailable_actions": unavailable,
            },
            "detail": "正在后台读取 Kuma 原生状态，管理总览不会被慢探测阻塞",
        }

    def snapshot(self) -> dict[str, Any]:
        modules = {name: self._module_snapshot(name) for name in ("subscriptions", "nodes", "dns", "monitors")}
        revision = _revision({name: value.get("revision") for name, value in modules.items()})
        return {"schema": 2, "revision": revision, "updated_at": int(time.time()), "modules": modules}

    def _persist(self, job: dict[str, Any]) -> None:
        _atomic(self.root / (job["job_id"] + ".json"), job)

    def _prune_job_files(self) -> None:
        try:
            paths = sorted(
                (path for path in self.root.glob("*.json") if path.is_file() and not path.is_symlink()
                 and IDENTIFIER.fullmatch(path.stem)),
                key=lambda path: path.stat().st_mtime, reverse=True,
            )
        except OSError:
            return
        for path in paths[200:]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if value.get("state") in {"ok", "error", "conflict"}:
                    path.unlink(missing_ok=True)
            except (OSError, ValueError, TypeError):
                continue

    def _update(self, job_id: str, **changes: Any) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.update(_public(changes))
            self._persist(job)

    def start(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._start(request, sensitive=False)

    def start_sensitive_bind(self, request: dict[str, Any]) -> dict[str, Any]:
        """Queue a Kuma credential exchange without persisting its input.

        The route using this entrypoint still owns authentication, same-origin
        and CSRF checks.  Only a bounded, reviewed ``bind_sensitive`` adapter
        receives the credential dictionary, and the dictionary is cleared when
        the worker finishes.
        """
        params = request.get("params")
        if not isinstance(params, dict) or set(params) - {"username", "password", "totp"}:
            raise OperationError("kuma_binding_fields_invalid")
        username, password = params.get("username"), params.get("password")
        totp = params.get("totp", "")
        if (not isinstance(username, str) or not 1 <= len(username) <= 256 or
                not isinstance(password, str) or not 1 <= len(password) <= 1024 or
                not isinstance(totp, str) or len(totp) > 64):
            raise OperationError("kuma_binding_fields_invalid")
        normalized = {
            "module": "monitors", "action": "kuma.bind",
            "expected_revision": request.get("expected_revision"),
            "params": {"username": username, "password": password, "totp": totp},
        }
        return self._start(normalized, sensitive=True)

    def _start(self, request: dict[str, Any], sensitive: bool) -> dict[str, Any]:
        module, action = request.get("module"), request.get("action")
        expected = request.get("expected_revision")
        params = request.get("params", {})
        if (not isinstance(module, str) or module not in {"subscriptions", "nodes", "dns", "monitors"} or
                not isinstance(action, str) or not IDENTIFIER.fullmatch(action) or
                not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or
                not isinstance(params, dict)):
            raise OperationError("operation_fields_invalid")
        extension = self.extensions.get(module)
        if extension is None:
            raise OperationError("operation_module_unsupported", 404)
        actions = extension.actions()
        meta = actions.get(action) if isinstance(actions, dict) else None
        if (not isinstance(meta, dict) or meta.get("supported", True) is False
                or type(meta.get("write")) is not bool):
            raise OperationError("operation_action_unsupported", 404)
        is_sensitive = meta.get("sensitive_input") is True
        if is_sensitive and not sensitive:
            raise OperationError("operation_sensitive_route_required", 403)
        if sensitive and (not is_sensitive or module != "monitors" or action != "kuma.bind"
                          or not callable(getattr(extension, "bind_sensitive", None))):
            raise OperationError("operation_action_unsupported", 404)
        current = self._module_snapshot(module).get("revision")
        if not current or current != expected:
            raise OperationError("operation_revision_conflict", 409)
        # A stale client gets the conflict it can act on even when a newer
        # server version no longer advertises the same deadline capability.
        if meta["write"] and meta.get("deadline_enforced") is not True:
            raise OperationError("operation_write_deadline_unverified", 503)
        timeout = meta.get("timeout_seconds", 30)
        if type(timeout) not in (int, float) or not 1 <= timeout <= 300:
            raise OperationError("operation_deadline_invalid", 503)
        if meta["write"] and not self.center.write_enabled:
            raise OperationError("writes_disabled", 503)
        if (module, action) in self.quarantined:
            raise OperationError("operation_action_quarantined", 503)
        if not self.slots.acquire(blocking=False):
            raise OperationError("operation_queue_full", 429)
        job_id = time.strftime("%Y%m%d-%H%M%S") + "-op-" + secrets.token_hex(4)
        job = {
            "job_id": job_id, "state": "pending", "stage": "queued", "module": module,
            "action": action, "created_at": int(time.time()), "expected_revision": expected,
        }
        try:
            with self.lock:
                self.jobs[job_id] = job
                while len(self.jobs) > 100:
                    oldest = min(self.jobs, key=lambda key: self.jobs[key].get("created_at", 0))
                    if self.jobs[oldest].get("state") in {"pending", "running"}:
                        break
                    self.jobs.pop(oldest, None)
                self._persist(job)
                self._prune_job_files()
            self.pool.submit(
                self._run, job_id, module, action, expected, params,
                meta["write"], float(timeout), sensitive,
            )
        except Exception:
            with self.lock:
                self.jobs.pop(job_id, None)
            self.slots.release()
            raise OperationError("operation_start_failed", 503) from None
        return {"job_id": job_id, "state": "pending", "stage": "queued"}

    def _run(
        self, job_id: str, module: str, action: str, expected: str,
        params: dict[str, Any], write: bool, timeout: float, sensitive: bool = False,
    ) -> None:
        def progress(stage: str, **values: Any) -> None:
            safe_stage = stage if isinstance(stage, str) and IDENTIFIER.fullmatch(stage) else "running"
            self._update(job_id, state="running", stage=safe_stage, **values)

        try:
            self._update(job_id, state="running", stage="starting")
            extension = self.extensions[module]

            def execute() -> dict[str, Any]:
                current = self._collect_module_snapshot(module).get("revision")
                if not current or current != expected:
                    raise OperationError("operation_revision_conflict", 409)
                if sensitive:
                    result = extension.bind_sensitive(params, progress)
                elif write:
                    # Write extensions only advertise deadline_enforced after
                    # bounding every external call and rollback path.
                    result = extension.execute(action, params, progress)
                else:
                    result = self._bounded_read(module, action, extension, params, progress, timeout)
                if not isinstance(result, dict):
                    raise OperationError("operation_result_invalid", 503)
                reported_state = str(result.get("state", "")).lower()
                if reported_state in {"error", "failed", "unavailable", "unsupported", "conflict"}:
                    code = result.get("error_code") or result.get("error") or "operation_reported_error"
                    if not isinstance(code, str) or not IDENTIFIER.fullmatch(code):
                        code = "operation_reported_error"
                    raise OperationError(code, 409 if reported_state == "conflict" else 503)
                return result

            if write:
                with self.center.route_lock():
                    result = execute()
            else:
                result = execute()
            readback = self._collect_module_snapshot(module)
            with self.snapshot_lock:
                self.snapshot_cache[module] = (
                    id(self.extensions[module]), time.monotonic(), readback,
                )
            self.center.audit("operation", "ok", module=module, operation_action=action, job_id=job_id)
            with self.center.cache_lock:
                self.center.cache_at = 0
            self._update(
                job_id, state="ok", stage="done", result=_public(result), error=None,
                revision=readback.get("revision"),
                readback={
                    "state": readback.get("state", "unknown"),
                    "revision": readback.get("revision"),
                },
                completed_at=int(time.time()),
            )
        except Exception as error:
            code = getattr(error, "code", "operation_failed")
            code = code if isinstance(code, str) and IDENTIFIER.fullmatch(code) else "operation_failed"
            state = "conflict" if getattr(error, "status", 0) == 409 or "conflict" in code else "error"
            self._update(job_id, state=state, stage="failed", error=code, completed_at=int(time.time()))
            self.center.audit("operation", state, module=module, operation_action=action, job_id=job_id)
        finally:
            if sensitive:
                params.clear()
            self.slots.release()

    def _bounded_read(self, module: str, action: str, extension: Any, params: dict[str, Any], progress: Any, timeout: float) -> Any:
        completed = threading.Event()
        holder: dict[str, Any] = {}

        def target() -> None:
            try:
                holder["result"] = extension.execute(action, params, progress)
            except BaseException as error:
                holder["error"] = error
            finally:
                completed.set()

        thread = threading.Thread(
            target=target, name="center-read-" + module + "-" + secrets.token_hex(3), daemon=True,
        )
        thread.start()
        if not completed.wait(timeout):
            # Threads cannot be killed safely. Quarantine prevents an adapter
            # from consuming more than one abandoned daemon thread per action.
            with self.lock:
                self.quarantined.add((module, action))
            raise OperationError("operation_timeout", 503)
        if "error" in holder:
            raise holder["error"]
        return holder.get("result")

    def job_status(self, job_id: str) -> dict[str, Any] | None:
        if not IDENTIFIER.fullmatch(job_id):
            return None
        with self.lock:
            value = self.jobs.get(job_id)
            return _public(dict(value)) if value else None
