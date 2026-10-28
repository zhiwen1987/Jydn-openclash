"""Authenticated backend for the unified LAN Clash center.

The module is installed into the existing subscription controller process.  It
does not own provider publication and deliberately keeps every legacy route in
the previous handler chain.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import yaml
except ImportError:  # The production controller already depends on PyYAML.
    yaml = None


ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
SCHEMA = 1
MAX_JSON = 64 * 1024
MAX_REMOTE = 4 * 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
SAFE_UPSTREAM = re.compile(
    r"^(?:(?:tls|https)://)?(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|"
    r"\[[0-9A-Fa-f:]+\]|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$"
)
TECHNICAL_GROUPS = {"GLOBAL", "🧪 节点能力检测", "🔬 节点归属校验"}


class CenterError(RuntimeError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code, self.status = code, status


def _clamp_env(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(low, min(high, value))


def _safe_text(value: Any, limit: int = 160) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if ch >= " " and ch not in "\x7f\r\n")[:limit]


def _state(value: Any) -> str:
    value = str(value or "").lower()
    mapping = {
        "healthy": "ok", "available": "ok", "loaded": "ok", "success": "ok",
        "checking": "running", "starting": "pending", "cached": "warning",
        "degraded": "warning", "unavailable": "error", "failed": "error",
    }
    value = mapping.get(value, value)
    return value if value in {"ok", "running", "pending", "warning", "error", "stale", "unknown"} else "unknown"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


class Center:
    def __init__(self, namespace: dict[str, Any], manager: Any, access: Any):
        self.namespace, self.manager, self.access = namespace, manager, access
        controller_root = Path(namespace["DATA"]).resolve()
        configured_root = os.getenv("CENTER_DATA_ROOT", "").strip()
        self.data_root = Path(configured_root).resolve() if configured_root else (
            controller_root.parent if controller_root.name in {"subscription-controller", "controller"} else controller_root
        )
        self.center_root = self.data_root / "unified-center"
        self.backup_root = self.center_root / "backups"
        self.center_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.cache_ttl = _clamp_env("CENTER_CACHE_SECONDS", 12, 2, 120)
        self.remote_timeout = _clamp_env("CENTER_REMOTE_TIMEOUT", 2.5, .2, 10)
        self.stale_after = int(_clamp_env("CENTER_STALE_SECONDS", 180, 30, 86400))
        self.cache_lock = threading.Condition()
        self.cache: dict[str, Any] | None = None
        self.cache_at = 0.0
        self.refreshing = False
        self.refresh_thread: threading.Thread | None = None
        self.pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="unified-center")
        self.jobs: dict[str, dict[str, Any]] = {}
        self.jobs_lock = threading.Lock()
        self.backup_slot = threading.Lock()
        self.node_test_slots = threading.BoundedSemaphore(2)
        self.route_thread_lock = threading.Lock()
        self.write_enabled = os.getenv("CENTER_WRITES_ENABLED", "1") == "1"
        self.routing_lock = Path(getattr(manager, "routing_lock", self.data_root / "routing-owner.lock"))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from control_operations import ControlPlane
        self.operations = ControlPlane(self)

    def audit(self, action: str, result: str, **fields: Any) -> None:
        row = {"at": int(time.time()), "action": action, "result": result}
        for key, value in fields.items():
            cleaned = _safe_text(value, 96)
            if cleaned:
                row[key] = cleaned
        line = _json_bytes(row) + b"\n"
        path = self.center_root / "activity.jsonl"
        try:
            with open(path, "ab") as stream:
                os.chmod(path, 0o600)
                stream.write(line)
        except OSError:
            pass

    def fetch_json(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with self.opener.open(request, timeout=self.remote_timeout) as response:
            if int(getattr(response, "status", 200)) != 200:
                raise CenterError("upstream_http_error", 503)
            raw = response.read(MAX_REMOTE + 1)
            if len(raw) > MAX_REMOTE:
                raise CenterError("upstream_response_too_large", 503)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise CenterError("upstream_response_invalid", 503)
        return value

    def http_probe(self, url: str, accepted: set[int] | None = None) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"Accept": "text/plain"})
        with self.opener.open(request, timeout=self.remote_timeout) as response:
            status = int(getattr(response, "status", 0))
            response.read(1024)
        accepted = accepted or {200}
        return {"state": "ok" if status in accepted else "error", "status": status}

    def clash(self, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/") or "?" in path and method != "GET":
            raise CenterError("clash_path_invalid")
        raw = _json_bytes(body) if body is not None else None
        return self.namespace["api_request"](method, path, raw, timeout=max(1, int(self.remote_timeout + .999)))

    def controller_status(self) -> dict[str, Any]:
        getter = self.namespace.get("latest_status")
        if not callable(getter):
            raise CenterError("controller_status_unavailable", 503)
        value = getter()
        return value if isinstance(value, dict) else {}

    def manifest_status(self) -> dict[str, Any]:
        getter = self.namespace.get("current_manifest")
        releases = self.namespace.get("RELEASES")
        if not callable(getter) or releases is None:
            return {"available": False, "sources": []}
        manifest = getter()
        if not isinstance(manifest, dict):
            return {"available": False, "sources": []}
        release_id = manifest.get("release_id")
        if not isinstance(release_id, str) or Path(release_id).name != release_id:
            raise CenterError("manifest_invalid", 503)
        release_dir = Path(releases) / release_id
        if not _inside(release_dir, Path(releases)):
            raise CenterError("manifest_invalid", 503)
        sources = []
        for item in manifest.get("sources", []):
            if not isinstance(item, dict):
                raise CenterError("manifest_invalid", 503)
            provider = item.get("provider_name")
            file_name = item.get("file")
            expected_count = item.get("node_count")
            if (not isinstance(provider, str) or not provider or len(provider) > 160 or
                    not isinstance(file_name, str) or Path(file_name).name != file_name or
                    not isinstance(expected_count, int) or expected_count < 0):
                raise CenterError("manifest_invalid", 503)
            path = release_dir / file_name
            if path.is_symlink() or not _inside(path, release_dir) or path.stat().st_size > 20 * 1024 * 1024:
                raise CenterError("manifest_invalid", 503)
            if yaml is None:
                raise CenterError("manifest_parser_unavailable", 503)
            document = yaml.safe_load(path.read_bytes())
            rows = document.get("proxies", []) if isinstance(document, dict) else []
            if not isinstance(rows, list):
                raise CenterError("manifest_invalid", 503)
            names = [row.get("name") for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str)]
            if len(names) != expected_count:
                raise CenterError("manifest_name_count_invalid", 503)
            sources.append({"provider_name": provider, "node_count": expected_count, "names": names})
        pointer_time = None
        try:
            pointer = json.loads((Path(self.namespace["DATA"]) / "current.json").read_text(encoding="utf-8"))
            if pointer.get("release_id") == release_id and isinstance(pointer.get("published_at"), (int, float)):
                pointer_time = pointer["published_at"]
        except (OSError, ValueError, TypeError):
            pass
        return {
            "available": True, "release_id": release_id,
            "created_at": manifest.get("created_at") if isinstance(manifest.get("created_at"), (int, float)) else None,
            "published_at": pointer_time, "sources": sources,
        }

    def node_status(self) -> dict[str, Any]:
        url = os.getenv("CENTER_NODE_API", "http://127.0.0.1:8081/api/nodes")
        return self.fetch_json(url)

    def usage_status(self) -> dict[str, Any]:
        url = os.getenv("CENTER_USAGE_API", "http://127.0.0.1:8082/api/subscription-usage")
        return self.fetch_json(url)

    def clash_status(self) -> dict[str, Any]:
        result, errors = {}, []
        for key, path in (
            ("proxies", "/proxies"), ("rules", "/rules"),
            ("providers", "/providers/proxies"), ("configs", "/configs"),
        ):
            try:
                value = self.clash(path)
                result[key] = value if isinstance(value, dict) else {}
            except Exception:
                result[key] = {}
                errors.append(key)
        result["errors"] = errors
        return result

    def fixed_file_status(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        allow = {
            "controller_health": self.data_root / "subscription-controller" / "health.json",
            "controller_current": self.data_root / "subscription-controller" / "current.json",
            "controller_pending": self.data_root / "subscription-controller" / "publish-pending.json",
            "local_runtime": self.data_root / "local-source" / "runtime.json",
            "usage_sync": self.data_root / "subscription-usage" / "sync-state.json",
        }
        # In the integrated process DATA usually points to /data/subscription-controller.
        controller_data = Path(self.namespace["DATA"])
        allow["controller_health"] = controller_data / "health.json"
        allow["controller_current"] = controller_data / "current.json"
        allow["controller_pending"] = controller_data / "publish-pending.json"
        local_root = Path(getattr(self.manager, "root", self.data_root / "local-source"))
        allow["local_runtime"] = local_root / "runtime.json"
        for key, path in allow.items():
            try:
                if path.is_symlink() or not _inside(path, self.data_root):
                    continue
                if path.stat().st_size > 256 * 1024:
                    continue
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    continue
                result[key] = {
                    k: value.get(k) for k in (
                        "status", "state", "mode", "epoch", "at", "version", "release_id",
                        "release_status", "node_count", "effective_node_count", "risk_score",
                        "last_attempt", "last_success", "last_change", "managed_count", "manual_count",
                    ) if k in value
                }
            except (OSError, ValueError, TypeError):
                continue
        return result

    def dns_status(self) -> dict[str, Any]:
        configured = os.getenv("CENTER_COREFILE", "/etc/coredns/Corefile")
        path = Path(configured)
        allowed_roots = [self.data_root, Path("/app/data"), Path("/etc/coredns")]
        upstreams: list[str] = []
        config_state, mtime = "error", None
        try:
            if path.is_symlink() or not any(_inside(path, root) for root in allowed_roots):
                raise CenterError("dns_config_path_forbidden", 503)
            if path.stat().st_size > 256 * 1024:
                raise CenterError("dns_config_too_large", 503)
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line.startswith("forward "):
                    continue
                parts = line.split()
                for item in parts[2:]:
                    if item == "{" or item.startswith("{"):
                        break
                    if SAFE_UPSTREAM.fullmatch(item) and item not in upstreams:
                        upstreams.append(item)
            config_state, mtime = "ok", int(path.stat().st_mtime)
        except (OSError, UnicodeError, CenterError):
            pass
        probes = {}
        for name, default in (
            ("health", "http://127.0.0.1:18080/health"),
            ("ready", "http://127.0.0.1:18181/ready"),
        ):
            try:
                probes[name] = self.http_probe(os.getenv("CENTER_DNS_" + name.upper() + "_URL", default))
            except Exception:
                probes[name] = {"state": "error", "status": None}
        health_state = "ok" if all(value["state"] == "ok" for value in probes.values()) else "error"
        return {"upstreams": upstreams[:16], "mtime": mtime, "config_state": config_state, "health_state": health_state, "probes": probes}

    def kuma_status(self) -> dict[str, Any]:
        health_url = os.getenv("CENTER_KUMA_HEALTH_URL", "http://127.0.0.1:3001/")
        parsed_health = urllib.parse.urlsplit(health_url)
        if (parsed_health.scheme != "http" or parsed_health.hostname not in {"127.0.0.1", "localhost"} or
                parsed_health.username or parsed_health.password or parsed_health.path not in {"", "/"} or parsed_health.query or parsed_health.fragment):
            raise CenterError("monitor_health_target_forbidden", 503)
        try:
            http_health = self.http_probe(health_url, set(range(200, 400)))
        except Exception:
            http_health = {"state": "error", "status": None}
        path = Path(os.getenv("CENTER_KUMA_DB", "/app/data/kuma.db"))
        if path.is_symlink() or not any(_inside(path, root) for root in (self.data_root, Path("/app/data"))):
            raise CenterError("monitor_database_path_forbidden", 503)
        uri = "file:" + urllib.parse.quote(str(path), safe="/:\\") + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=self.remote_timeout)
        conn.row_factory = sqlite3.Row
        try:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"monitor", "heartbeat"}.issubset(tables):
                raise CenterError("monitor_schema_unsupported", 503)
            monitor_cols = {row[1] for row in conn.execute("PRAGMA table_info(monitor)")}
            beat_cols = {row[1] for row in conn.execute("PRAGMA table_info(heartbeat)")}
            if not {"id", "name"}.issubset(monitor_cols) or not {"monitor_id", "status", "time"}.issubset(beat_cols):
                raise CenterError("monitor_schema_unsupported", 503)
            active = "WHERE active=1" if "active" in monitor_cols else ""
            rows = conn.execute(f"SELECT id,name{',interval' if 'interval' in monitor_cols else ''} FROM monitor {active} ORDER BY id LIMIT 200").fetchall()
            output = []
            now = time.time()
            for row in rows:
                beat = conn.execute(
                    "SELECT status,time" + (",ping" if "ping" in beat_cols else "") +
                    " FROM heartbeat WHERE monitor_id=? ORDER BY time DESC LIMIT 1", (row["id"],),
                ).fetchone()
                checked = None
                if beat:
                    value = beat["time"]
                    try:
                        if isinstance(value, (int, float)):
                            checked = int(value)
                        else:
                            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                            if parsed.tzinfo is None:
                                parsed = parsed.replace(tzinfo=timezone.utc)
                            checked = int(parsed.timestamp())
                    except (ValueError, TypeError, OverflowError):
                        checked = None
                interval = int(row["interval"] or 60) if "interval" in row.keys() else 60
                clock_invalid = checked is not None and checked > now + 300
                stale = checked is None or clock_invalid or now - checked > max(interval * 4, self.stale_after)
                status = int(beat["status"]) if beat and str(beat["status"]).lstrip("-").isdigit() else None
                state = "stale" if stale else ("ok" if status == 1 else "error" if status == 0 else "unknown")
                output.append({
                    "id": str(row["id"]), "name": _safe_text(row["name"], 100) or "Monitor",
                    "state": state, "checked_at": checked,
                    "detail": "Heartbeat 时间超出未来容差" if clock_invalid else ("Heartbeat 已过期" if stale else ("Heartbeat 正常" if state == "ok" else "Heartbeat 异常")),
                })
            return {
                "monitors": output, "http": http_health, "database_state": "ok",
                "health_state": "ok" if http_health["state"] == "ok" else "error",
            }
        finally:
            conn.close()

    def _collect(self) -> tuple[dict[str, Any], dict[str, str]]:
        collectors: dict[str, Callable[[], dict[str, Any]]] = {
            "controller": self.controller_status,
            "manifest": self.manifest_status,
            "nodes": self.node_status,
            "usage": self.usage_status,
            "files": self.fixed_file_status,
            "dns": self.dns_status,
            "kuma": self.kuma_status,
            "clash_proxies": lambda: self.clash("/proxies"),
            "clash_rules": lambda: self.clash("/rules"),
            "clash_providers": lambda: self.clash("/providers/proxies"),
            "clash_configs": lambda: self.clash("/configs"),
        }
        futures = {self.pool.submit(function): name for name, function in collectors.items()}
        values, errors = {}, {}
        pending = set(futures)
        budget = _clamp_env("CENTER_OVERVIEW_TIMEOUT", 9, 2, 20)
        # Leave a fixed scheduling/serialization reserve inside the advertised
        # wall-clock budget.  Windows can resume a timed wait several hundred
        # milliseconds late under CPU pressure; using the whole budget here
        # previously let a nominal 2 s fan-out escape past the HTTP deadline.
        reserve = min(1.5, max(.75, budget * .6))
        deadline = time.monotonic() + max(.25, budget - reserve)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                name = futures[future]
                try:
                    value = future.result()
                    values[name] = value if isinstance(value, dict) else {}
                except Exception:
                    errors[name] = "unavailable"
                    values[name] = {}
        for future, name in futures.items():
            if name not in values:
                future.cancel()
                errors[name] = "timeout"
                values[name] = {}
        clash_errors = []
        clash = {}
        for key in ("proxies", "rules", "providers", "configs"):
            task = "clash_" + key
            clash[key] = values.pop(task, {})
            if task in errors:
                clash_errors.append(key)
                errors.pop(task, None)
        clash["errors"] = clash_errors
        values["clash"] = clash
        if len(clash_errors) == 4:
            errors["clash"] = "unavailable"
        return values, errors

    @staticmethod
    def _collector_error_map(state: str = "unavailable") -> dict[str, str]:
        return {
            name: state for name in
            ("controller", "manifest", "nodes", "usage", "clash", "files", "dns", "kuma")
        }

    def _refresh_overview(self) -> None:
        try:
            try:
                values, errors = self._collect()
                result = self.compose(values, errors)
            except Exception:
                # A collector integration failure must produce explicit evidence
                # loss, never an empty-but-green dashboard.
                result = self.compose({}, self._collector_error_map())
            with self.cache_lock:
                self.cache, self.cache_at = result, time.monotonic()
        finally:
            with self.cache_lock:
                self.refreshing = False
                self.refresh_thread = None
                self.cache_lock.notify_all()

    def _start_overview_refresh_locked(self) -> None:
        if self.refreshing:
            return
        self.refreshing = True
        thread = threading.Thread(
            target=self._refresh_overview, name="unified-overview-refresh", daemon=True,
        )
        self.refresh_thread = thread
        thread.start()

    def _pending_overview(self) -> dict[str, Any]:
        epoch = int(time.time())
        stages = [
            {"id": key, "label": label, "state": "pending", "detail": "后台正在采集真实证据", "last_success": None, "next_due": None}
            for key, label in (
                ("information", "信息来源读取"), ("evaluation", "节点检测"),
                ("publication", "受控发布"), ("runtime", "运行加载"),
            )
        ]
        services = [
            {"id": key, "name": label, "state": "pending", "checked_at": None,
             "detail": "尚未完成首轮采集，不代表服务异常"}
            for key, label in (
                ("controller", "订阅发布"), ("nodes", "节点检测"), ("usage", "用量采集"),
                ("clash", "Clash 运行时"), ("dns", "DNS"), ("kuma", "Kuma 监控"),
            )
        ]
        environment = "isolated" if os.getenv("CENTER_ENVIRONMENT", "production").strip().lower() == "isolated" else "production"
        return {
            "schema": SCHEMA, "updated_at": epoch, "environment": environment,
            "stale": False, "refreshing": True, "evidence_age_seconds": None,
            "overall": {"state": "pending", "title": "正在采集", "detail": "首轮真实证据正在后台采集；空列表不代表数量为零"},
            "metrics": {"nodes": None, "subscriptions": None, "selectors": None, "rules": None},
            "sync": {"state": "pending", "stages": stages, "information_sources": None, "node_sources": None},
            "services": services, "businesses": [], "nodes": [],
            "subscriptions": {"providers": [], "source_sync": {}},
            "dns": {"state": "pending", "upstreams": [], "probes": {}, "detail": "等待 DNS 诊断证据"},
            "monitors": [], "backups": [], "events": [],
            "issues": [{"id": "overview-collecting", "title": "正在采集系统状态", "detail": "结果将在后台刷新，未使用假数据补齐", "page": "overview", "state": "pending"}],
            "capabilities": {
                "writes": self.write_enabled, "advanced_monitor_path": "/#/monitors",
                "native_monitor_proxy": False, "advanced_router_path": "/cgi-bin/luci/",
            },
            "evidence": {"files": {}, "runtime_config": {}},
        }

    def _cached_overview(self, age: float, stale: bool) -> dict[str, Any]:
        assert self.cache is not None
        # Composed snapshots are immutable after publication; a shallow top-level
        # copy is sufficient for cache metadata and avoids duplicating a large
        # node inventory on every viewer request.
        result = dict(self.cache)
        result["stale"] = stale
        result["refreshing"] = self.refreshing
        result["evidence_age_seconds"] = round(max(0.0, age), 3)
        if stale:
            previous = result.get("overall") if isinstance(result.get("overall"), dict) else {}
            result["overall"] = {
                "state": "stale", "title": "数据已过期",
                "detail": "正在后台更新；上次状态：" + _safe_text(previous.get("state"), 24),
            }
            issues = result.get("issues") if isinstance(result.get("issues"), list) else []
            result["issues"] = [{
                "id": "overview-cache-stale", "title": "总览证据已过期",
                "detail": "页面已立即返回上次证据，后台单飞刷新中",
                "page": "overview", "state": "stale",
            }] + [item for item in issues if isinstance(item, dict) and item.get("id") != "overview-cache-stale"]
        return result

    def overview(self, force: bool = False) -> dict[str, Any]:
        now_mono = time.monotonic()
        with self.cache_lock:
            age = now_mono - self.cache_at if self.cache is not None else None
            fresh = age is not None and age < self.cache_ttl
            if force or not fresh:
                self._start_overview_refresh_locked()
            if self.cache is None:
                return self._pending_overview()
            return self._cached_overview(age or 0.0, stale=not fresh)

    def compose(self, values: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
        epoch = int(time.time())
        controller = values.get("controller", {})
        nodes_raw = values.get("nodes", {})
        usage = values.get("usage", {})
        clash = values.get("clash", {})
        files = values.get("files", {})
        kuma_raw = values.get("kuma", {})
        kuma_monitors = kuma_raw.get("monitors", []) if isinstance(kuma_raw.get("monitors"), list) else []
        proxies = clash.get("proxies", {}).get("proxies", {})
        if not isinstance(proxies, dict):
            proxies = {}
        providers_raw = clash.get("providers", {}).get("providers", {})
        if not isinstance(providers_raw, dict):
            providers_raw = {}
        rules_raw = clash.get("rules", {}).get("rules", [])
        if not isinstance(rules_raw, list):
            rules_raw = []
        progress = nodes_raw.get("progress") if isinstance(nodes_raw.get("progress"), dict) else {}
        controller_stamp = controller.get("epoch")
        controller_fresh = isinstance(controller_stamp, (int, float)) and -300 <= epoch - controller_stamp <= _clamp_env("CENTER_CONTROLLER_STALE_SECONDS", 7500, 300, 86400)
        node_progress_stamp = progress.get("epoch")
        node_progress_fresh = isinstance(node_progress_stamp, (int, float)) and -300 <= epoch - node_progress_stamp <= _clamp_env("CENTER_NODE_PROGRESS_STALE_SECONDS", 180, 30, 3600)

        nodes = []
        for item in nodes_raw.get("nodes", []) if isinstance(nodes_raw.get("nodes"), list) else []:
            if not isinstance(item, dict):
                continue
            capabilities = {}
            for key, record in list((item.get("capabilities") or {}).items())[:32] if isinstance(item.get("capabilities"), dict) else []:
                if not isinstance(key, str) or not isinstance(record, dict):
                    continue
                capabilities[_safe_text(key, 64)] = {
                    "status": _safe_text(record.get("status"), 32) or "unknown",
                    "last_checked": record.get("last_checked") if isinstance(record.get("last_checked"), (int, float)) else None,
                    "reason": _safe_text(record.get("reason"), 80) if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", str(record.get("reason", ""))) else "",
                    "confidence": record.get("confidence") if isinstance(record.get("confidence"), (int, float)) else None,
                    "consecutive_success": record.get("consecutive_success") if isinstance(record.get("consecutive_success"), int) else None,
                    "consecutive_failure": record.get("consecutive_failure") if isinstance(record.get("consecutive_failure"), int) else None,
                }
            schedule = item.get("health_schedule") if isinstance(item.get("health_schedule"), dict) else {}
            clean_schedule = {
                key: schedule.get(key) for key in (
                    "last_observation", "last_success", "last_attempt", "cooldown_until", "next_due",
                    "failure_streak", "success_streak", "latency_sample_at",
                ) if isinstance(schedule.get(key), (int, float))
            }
            if isinstance(schedule.get("detector_error"), bool):
                clean_schedule["detector_error"] = schedule["detector_error"]
            for key in ("status", "error_scope", "reason", "latency_source"):
                value = schedule.get(key)
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", value):
                    clean_schedule[key] = value
            schedule = clean_schedule
            egress = item.get("egress") if isinstance(item.get("egress"), dict) else {}
            egress = {
                "country": _safe_text(egress.get("country"), 40), "colo": _safe_text(egress.get("colo"), 40),
                "changed_count": egress.get("changed_count") if isinstance(egress.get("changed_count"), int) else None,
                "last_checked": egress.get("last_checked") if isinstance(egress.get("last_checked"), (int, float)) else None,
            }
            latency_summary = item.get("latency_summary") if isinstance(item.get("latency_summary"), dict) else {}
            latency_summary = {
                key: latency_summary.get(key) for key in ("samples", "median_ms", "p95_ms")
                if isinstance(latency_summary.get(key), (int, float)) or latency_summary.get(key) is None
            }
            nodes.append({
                "id": _safe_text(item.get("id"), 128), "name": _safe_text(item.get("name"), 120),
                "provider": _safe_text(item.get("provider"), 100), "state": _state(item.get("state")),
                "node_type": _safe_text(item.get("node_type"), 40),
                "score": item.get("score") if isinstance(item.get("score"), (int, float)) else None,
                "general_success_ratio": item.get("general_success_ratio") if isinstance(item.get("general_success_ratio"), (int, float)) else None,
                "latency_ms": item.get("latency_ms") if isinstance(item.get("latency_ms"), (int, float)) else None,
                "jitter_ms": item.get("jitter_ms") if isinstance(item.get("jitter_ms"), (int, float)) else None,
                "confidence": item.get("confidence") if isinstance(item.get("confidence"), (int, float)) else None,
                "fresh_until": item.get("fresh_until") if isinstance(item.get("fresh_until"), (int, float)) else None,
                "fresh": item.get("fresh") is True,
                "updated_at": item.get("updated_at") if isinstance(item.get("updated_at"), (int, float)) else None,
                "last_seen": item.get("last_seen") if isinstance(item.get("last_seen"), (int, float)) else None,
                "health_schedule": schedule, "latency_kind": item.get("latency_kind") if item.get("latency_kind") in {"Clash HTTPS HEAD", "legacy_http"} else "unknown",
                "latency_summary": latency_summary, "egress": egress, "capabilities": capabilities,
            })

        node_by_name = {item["name"]: item for item in nodes if item["name"]}
        capability_labels = {}
        for field in ("business_labels", "route_labels"):
            for key, label in (nodes_raw.get(field) or {}).items() if isinstance(nodes_raw.get(field), dict) else []:
                if isinstance(key, str) and isinstance(label, str):
                    key, label = _safe_text(key, 64), _safe_text(label, 80)
                    if len(key) >= 3 and len(label) >= 2:
                        capability_labels[key] = label

        def resolve_leaf(selected: str | None) -> tuple[str | None, list[str], str | None]:
            current, chain, seen = selected, [], set()
            for _ in range(32):
                if not current:
                    return None, chain, "selection_missing"
                if current in seen:
                    return None, chain + [current], "selection_cycle"
                seen.add(current); chain.append(current)
                entry = proxies.get(current)
                if not isinstance(entry, dict):
                    return current, chain, None
                proxy_type = str(entry.get("type", "")).lower()
                is_group = (isinstance(entry.get("all"), list) and isinstance(entry.get("now"), str)) or proxy_type in {
                    "selector", "urltest", "fallback", "loadbalance", "relay",
                }
                if not is_group:
                    return current, chain, None
                next_name = entry.get("now")
                if not isinstance(next_name, str) or not next_name:
                    return None, chain, "group_current_unknown"
                current = next_name
            return None, chain, "selection_depth_exceeded"

        businesses = []
        for name, entry in list(proxies.items())[:500]:
            if name in TECHNICAL_GROUPS or not isinstance(entry, dict) or str(entry.get("type", "")).lower() != "selector":
                continue
            options = [_safe_text(x, 120) for x in entry.get("all", []) if isinstance(x, str)][:300]
            selected = _safe_text(entry.get("now"), 120) or None
            leaf, chain, resolution_error = resolve_leaf(selected)
            state, detail = "unknown", "已读取当前选择，但无可用性证据"
            if selected not in options:
                state, detail = "warning", "当前选择不在成员证据中"
            elif resolution_error:
                detail = "策略链无法解析：" + resolution_error
            elif leaf == "REJECT":
                state, detail = "warning", "已阻断：策略链主动选择 REJECT（可能是未配置入口或有意阻断）"
            elif leaf in node_by_name:
                node = node_by_name[leaf]
                key = next((key for key, label in capability_labels.items()
                            if key.casefold() in str(name).casefold() or label.casefold() in str(name).casefold()), None)
                capability = node["capabilities"].get(key) if key else None
                if not node["fresh"]:
                    state, detail = "stale", "叶子节点健康数据已过期"
                elif not capability:
                    detail = "已解析叶子节点，但无对应业务能力证据"
                else:
                    cap_state = str(capability.get("status", "unknown"))
                    state = {"available": "ok", "unavailable": "error", "checking": "pending", "cooling": "warning", "stale": "stale"}.get(cap_state, "unknown")
                    detail = f"叶子节点 {leaf} 的 {key} 能力证据：{cap_state}"
            businesses.append({
                "id": _safe_text(name, 120), "name": _safe_text(name, 120), "selection": selected,
                "leaf": leaf, "chain": chain, "options": options, "state": state, "detail": detail,
            })

        provider_rows = []
        for item in usage.get("providers", []) if isinstance(usage.get("providers"), list) else []:
            if not isinstance(item, dict):
                continue
            metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else None
            provider_rows.append({
                "id": _safe_text(item.get("id"), 96), "name": _safe_text(item.get("name"), 120),
                "name_origin": _safe_text(item.get("name_origin"), 40),
                "state": "stale" if item.get("stale") else _state(item.get("usage_status")),
                "metrics": {k: v for k, v in (metrics or {}).items() if k in {"upload", "download", "total", "expire"} and isinstance(v, (int, float))} or None,
                "last_success": item.get("last_success") if isinstance(item.get("last_success"), (int, float)) else None,
                "next_due": item.get("next_due") if isinstance(item.get("next_due"), (int, float)) else None,
            })

        services = []
        labels = {"controller": "订阅发布", "nodes": "节点检测", "usage": "用量采集", "clash": "Clash 运行时", "dns": "DNS", "kuma": "Kuma 监控"}
        for key, label in labels.items():
            detail = "读取失败，其他模块不受影响"
            state = "error" if key in errors else "unknown"
            if key == "controller" and key not in errors:
                state = _state(controller.get("status")) if key not in errors else "error"
                detail = "发布控制器状态：" + str(controller.get("status", "unknown"))
                if not controller_fresh:
                    state, detail = "stale", "发布控制器心跳无有效时效证据"
            elif key == "nodes" and key not in errors:
                state = _state((nodes_raw.get("progress") or {}).get("status"))
                detail = "节点检测进度状态：" + str((nodes_raw.get("progress") or {}).get("status", "unknown"))
                if not node_progress_fresh:
                    state, detail = "stale", "节点检测工作器进度心跳已过期"
                elif not nodes:
                    state, detail = "unknown", "检测工作器心跳可读，但无节点证据"
            elif key == "usage" and key not in errors:
                state = "ok" if usage.get("registry_state") == "ok" else "warning" if usage.get("registry_state") else "unknown"
                detail = "用量工作器状态：" + str(usage.get("registry_state", "unknown"))
            elif key == "clash" and key not in errors:
                state = "warning" if clash.get("errors") else "ok"
                detail = "Clash 白名单接口已读取" if state == "ok" else "Clash 仅部分白名单接口可用"
            elif key == "dns" and key not in errors:
                state = _state(values.get("dns", {}).get("health_state"))
                detail = "DNS health/ready 均通过" if state == "ok" else "仅配置可读不代表 DNS 可用，health/ready 未全通过"
            elif key == "kuma" and key not in errors:
                state = _state(kuma_raw.get("health_state")) if kuma_raw.get("database_state") == "ok" else "error"
                detail = "Kuma 本机 HTTP 存活且 SQLite 可读" if state == "ok" else "Kuma 本机 HTTP 或 SQLite 健康证据不完整"
            services.append({"id": key, "name": label, "state": state, "checked_at": epoch, "detail": detail})

        issues = []
        page_for = {"controller": "subscriptions", "manifest": "subscriptions", "nodes": "nodes", "usage": "subscriptions", "clash": "routing", "files": "overview", "dns": "dns", "kuma": "monitors"}
        for source in errors:
            issues.append({"id": "source-" + source, "title": labels.get(source, source) + "不可用", "detail": "本次读取失败，未使用假数据补齐", "page": page_for.get(source, "overview"), "state": "error"})
        for key in clash.get("errors", []):
            issues.append({"id": "clash-" + _safe_text(key, 24), "title": "Clash 部分接口不可用", "detail": _safe_text(key, 24) + " 未读取，其他结果仍保留", "page": "routing", "state": "warning"})

        release_status = _safe_text(controller.get("release_status"), 40) or _safe_text((controller.get("releases") or [{}])[0].get("status") if isinstance(controller.get("releases"), list) and controller.get("releases") else "", 40)
        reason = _safe_text(controller.get("reason"), 100)
        same_current = release_status == "same_as_current" or reason == "same_as_current"
        if same_current:
            issues.append({"id": "same-as-current", "title": "本轮未发布新版本", "detail": "候选内容与当前版本相同，保留告警以免被误认为新发布", "page": "subscriptions", "state": "warning"})
        stale_providers = sum(item["state"] in {"stale", "error", "warning"} for item in provider_rows)
        if stale_providers:
            issues.append({"id": "subscription-metadata-stale", "title": "部分信息来源过期或异常", "detail": f"{stale_providers} 个来源没有新鲜用量证据", "page": "subscriptions", "state": "warning"})
        if nodes and not any(item["fresh"] for item in nodes):
            issues.append({"id": "all-node-evidence-stale", "title": "无新鲜节点健康证据", "detail": "已读取节点清单，但所有健康记录均不新鲜", "page": "nodes", "state": "stale"})
        abnormal_monitors = sum(item.get("state") in {"error", "warning"} for item in kuma_monitors if isinstance(item, dict))
        stale_monitors = sum(item.get("state") == "stale" for item in kuma_monitors if isinstance(item, dict))
        if abnormal_monitors or stale_monitors:
            count = abnormal_monitors + stale_monitors
            issues.append({
                "id": "monitor-heartbeats-abnormal", "title": f"{count} 项监控异常/过期",
                "detail": "Kuma 服务仍可用；这是子监控项的 heartbeat 状态，不代表 Kuma 进程停止",
                "page": "monitors", "state": "warning" if abnormal_monitors else "stale",
            })
        relevant_businesses = {
            item["id"] for item in businesses
            if any(key.casefold() in item["id"].casefold() or label.casefold() in item["id"].casefold()
                   for key, label in capability_labels.items())
        }
        for business in businesses:
            if business["id"] in relevant_businesses and business["state"] != "ok":
                issues.append({"id": "business-" + hashlib.sha256(business["id"].encode()).hexdigest()[:12], "title": business["name"] + " 当前路径异常", "detail": business["detail"], "page": "routing", "state": business["state"]})

        info_sources = usage.get("source_count") if isinstance(usage.get("source_count"), int) else len(provider_rows) if provider_rows else None
        manifest = values.get("manifest", {})
        manifest_sources = manifest.get("sources", []) if manifest.get("available") and isinstance(manifest.get("sources"), list) else []
        node_sources = len(manifest_sources) if manifest.get("available") else None
        published_nodes = sum(item["node_count"] for item in manifest_sources) if manifest.get("available") else None
        source_matches = []
        for source in manifest_sources:
            runtime = providers_raw.get(source["provider_name"])
            rows = runtime.get("proxies", []) if isinstance(runtime, dict) else []
            runtime_names = [row.get("name") for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str)]
            source_matches.append(len(runtime_names) == source["node_count"] and Counter(runtime_names) == Counter(source["names"]))
        match = bool(manifest_sources) and len(source_matches) == len(manifest_sources) and all(source_matches)
        raw_source_sync = usage.get("source_sync") if isinstance(usage.get("source_sync"), dict) else {}
        source_sync = {}
        if raw_source_sync.get("state") in {"ok", "error", "stale", "unavailable"}:
            source_sync["state"] = raw_source_sync["state"]
        for key in ("last_attempt", "last_success", "last_change", "managed_count", "manual_count"):
            if isinstance(raw_source_sync.get(key), (int, float)):
                source_sync[key] = raw_source_sync[key]
        stages = [
            {"id": "information", "label": "信息来源读取", "state": "error" if "usage" in errors else _state(source_sync.get("state", "unknown")), "detail": (f"已读取 {info_sources} 家信息来源；不等于节点来源" if info_sources is not None else "来源数量无证据"), "last_success": source_sync.get("last_success") if isinstance(source_sync.get("last_success"), (int, float)) else None, "next_due": None},
            {"id": "evaluation", "label": "节点检测", "state": "error" if "nodes" in errors else "stale" if not node_progress_fresh else _state(progress.get("status", "unknown")), "detail": f"已取得 {len(nodes)} 个节点的检测记录" if nodes and node_progress_fresh else "未取得新鲜节点检测证据", "last_success": progress.get("last_probe_epoch") if isinstance(progress.get("last_probe_epoch"), (int, float)) else None, "next_due": None},
            {"id": "publication", "label": "受控发布", "state": "stale" if not controller_fresh else "warning" if same_current else _state(controller.get("status")), "detail": "发布控制器心跳已过期" if not controller_fresh else ("候选与当前版本相同，未产生新发布" if same_current else f"最新记录：{release_status or '未知'}"), "last_success": manifest.get("published_at") if isinstance(manifest.get("published_at"), (int, float)) else None, "next_due": None},
            {"id": "runtime", "label": "运行加载", "state": "ok" if match else "warning" if manifest.get("available") and providers_raw else "unknown", "detail": ("发布 manifest 与运行时各 provider 的节点名称及数量一致（不代表端点或业务全部通过）" if match else "未获得 manifest 与运行时名称/数量完全一致的证据"), "last_success": None, "next_due": None},
        ]

        dns_raw = values.get("dns", {})
        dns_state = "error" if "dns" in errors else _state(dns_raw.get("health_state"))
        monitors = kuma_monitors
        events = self.recent_events()
        backups = self.backup_list()
        states = [item["state"] for item in services] + [item["state"] for item in issues]
        overall_state = "error" if "error" in states else "warning" if "warning" in states else "stale" if "stale" in states else "unknown" if "unknown" in states else "running" if "running" in states else "pending" if "pending" in states else "ok"
        overall_title = {"ok": "运行正常", "warning": "存在待处理告警", "error": "部分服务不可用", "stale": "数据已过期", "unknown": "证据不足", "running": "正在检测", "pending": "等待检测"}[overall_state]
        environment = "isolated" if os.getenv("CENTER_ENVIRONMENT", "production").strip().lower() == "isolated" else "production"
        stage_states = [item["state"] for item in stages]
        sync_state = "error" if "error" in stage_states else "warning" if "warning" in stage_states else "stale" if "stale" in stage_states else "running" if "running" in stage_states else "pending" if "pending" in stage_states else "unknown" if "unknown" in stage_states else "ok"
        return {
            "schema": SCHEMA, "updated_at": epoch, "environment": environment,
            "overall": {"state": overall_state, "title": overall_title, "detail": f"已检查 {len(services)} 个可观测服务"},
            "metrics": {
                "nodes": len(nodes) if "nodes" not in errors else None, "subscriptions": info_sources,
                "selectors": len(businesses) if "proxies" not in clash.get("errors", []) else None,
                "rules": len(rules_raw) if "rules" not in clash.get("errors", []) else None,
            },
            "sync": {"state": sync_state, "stages": stages, "information_sources": info_sources, "node_sources": node_sources},
            "services": services, "businesses": businesses, "nodes": nodes,
            "subscriptions": {"providers": provider_rows, "source_sync": source_sync},
            "dns": {"state": dns_state, "upstreams": dns_raw.get("upstreams", []), "probes": {
                name: {key: probe.get(key) for key in ("state", "status", "checked_at") if key in probe}
                for name in ("health", "ready")
                if isinstance((probe := dns_raw.get("probes", {}).get(name)), dict)
            }, "detail": ("Corefile 配置可读，且 health/ready 均通过" if dns_state == "ok" and dns_raw.get("config_state") == "ok" else "Corefile 配置读取与 DNS health/ready 是独立证据，当前未全部通过")},
            "monitors": monitors, "backups": backups, "events": events, "issues": issues,
            "capabilities": {
                "writes": self.write_enabled,
                "advanced_monitor_path": "/#/monitors",
                "native_monitor_proxy": False,
                "advanced_router_path": "/cgi-bin/luci/",
            },
            "evidence": {
                "files": files,
                "runtime_config": {
                    key: clash.get("configs", {}).get(key) for key in
                    ("mode", "mixed-port", "redir-port", "tproxy-port", "allow-lan", "ipv6", "log-level")
                    if key in clash.get("configs", {})
                },
            },
        }

    def recent_events(self) -> list[dict[str, Any]]:
        path = self.center_root / "activity.jsonl"
        try:
            if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                return []
            lines = path.read_text(encoding="utf-8").splitlines()[-30:]
        except OSError:
            return []
        output = []
        for line in reversed(lines):
            try:
                item = json.loads(line)
                action, result = _safe_text(item.get("action"), 64), _safe_text(item.get("result"), 32)
                output.append({"at": item.get("at") if isinstance(item.get("at"), int) else None, "title": action or "center_operation", "detail": result, "state": "ok" if result in {"ok", "completed"} else "warning" if result in {"started", "conflict"} else "error"})
            except (ValueError, TypeError):
                continue
        return output

    def backup_list(self) -> list[dict[str, Any]]:
        output = []
        try:
            entries = sorted(self.backup_root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:30]
        except OSError:
            return []
        for path in entries:
            try:
                if path.is_symlink() or not IDENTIFIER.fullmatch(path.stem) or path.stat().st_size > 32768:
                    continue
                value = self.backup_complete(path.stem)
                if value is None:
                    continue
                output.append({
                    "id": value.get("id"), "name": "中心侧备份 " + str(value.get("id", "")),
                    "created_at": value.get("created_at"), "state": "ok", "scope": value.get("scope"),
                    "size_bytes": value.get("size") if isinstance(value.get("size"), int) else None,
                    "download_ready": True,
                })
            except (OSError, ValueError, TypeError):
                continue
        return output

    def backup_complete(self, backup_id: str) -> dict[str, Any] | None:
        if not IDENTIFIER.fullmatch(backup_id):
            return None
        manifest = self.backup_root / (backup_id + ".json")
        archive = self.backup_root / (backup_id + ".tar.gz")
        try:
            if (manifest.is_symlink() or archive.is_symlink() or not _inside(manifest, self.backup_root) or
                    not _inside(archive, self.backup_root) or manifest.stat().st_size > 32768 or not archive.is_file()):
                return None
            value = json.loads(manifest.read_text(encoding="utf-8"))
            if (value.get("state") != "ok" or value.get("id") != backup_id or
                    value.get("size") != archive.stat().st_size or
                    not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))):
                return None
            return value
        except (OSError, ValueError, TypeError):
            return None

    def session(self, handler: Any) -> tuple[str | None, dict[str, Any] | None]:
        return self.access.session(handler.headers.get("Cookie", ""))

    def origin_ok(self, handler: Any) -> bool:
        host = handler.headers.get("Host", "")
        allowed = {item.strip() for item in os.getenv("LOCAL_SOURCE_HOSTS", "10.88.0.249:3103,127.0.0.1:8082,localhost:8082").split(",") if item.strip()}
        origin = handler.headers.get("Origin", "")
        return host in allowed and origin in {"http://" + host, "https://" + host}

    def require_auth(self, handler: Any, csrf: bool = False) -> tuple[str, dict[str, Any]]:
        sid, session = self.session(handler)
        if not sid or not session:
            raise CenterError("login_required", 401)
        if csrf and not hmac.compare_digest(handler.headers.get("X-CSRF-Token", ""), session["csrf"]):
            raise CenterError("session_or_csrf_invalid", 403)
        return sid, session

    def read_body(self, handler: Any) -> dict[str, Any]:
        if not self.origin_ok(handler) or handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json" or handler.headers.get("Transfer-Encoding"):
            raise CenterError("origin_or_content_type_forbidden", 403)
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError:
            raise CenterError("request_size_invalid") from None
        if length < 2 or length > MAX_JSON:
            raise CenterError("request_size_invalid")
        handler.connection.settimeout(10)
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise CenterError("request_incomplete")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise CenterError("request_json_invalid") from None
        if not isinstance(value, dict):
            raise CenterError("request_object_required")
        return value

    @contextlib.contextmanager
    def route_lock(self):
        self.routing_lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stream = open(self.routing_lock, "a")
        os.chmod(self.routing_lock, 0o600)
        thread_acquired = False
        used_fcntl = False
        try:
            try:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                used_fcntl = True
            except ImportError:
                thread_acquired = self.route_thread_lock.acquire(blocking=False)
                if not thread_acquired:
                    raise CenterError("routing_busy", 409)
            except BlockingIOError:
                raise CenterError("routing_busy", 409) from None
            yield
        finally:
            if used_fcntl:
                try:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_UN)
                except OSError:
                    pass
            if thread_acquired:
                self.route_thread_lock.release()
            stream.close()

    def select(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.write_enabled:
            raise CenterError("writes_disabled", 503)
        group, choice, expected = request.get("group"), request.get("choice"), request.get("expected")
        if not all(isinstance(item, str) and 0 < len(item) <= 160 for item in (group, choice, expected)):
            raise CenterError("selection_fields_invalid")
        if group in TECHNICAL_GROUPS:
            raise CenterError("technical_group_write_forbidden", 403)
        path = "/proxies/" + urllib.parse.quote(group, safe="")
        with self.route_lock():
            current = self.clash(path)
            if not isinstance(current, dict) or str(current.get("type", "")).lower() != "selector":
                raise CenterError("selection_group_invalid")
            if current.get("now") != expected:
                self.audit("select", "conflict", group=group)
                raise CenterError("selection_conflict", 409)
            members = current.get("all")
            if not isinstance(members, list) or choice not in members:
                raise CenterError("selection_choice_not_member")
            if choice == current.get("now"):
                self.audit("select", "ok", group=group, choice=choice)
                return {"state": "ok", "group": group, "selected": choice, "previous": expected, "changed": False}
            self.clash(path, "PUT", {"name": choice})
            verified = self.clash(path)
            if not isinstance(verified, dict) or verified.get("now") != choice:
                self.audit("select", "conflict", group=group)
                raise CenterError("selection_readback_conflict", 409)
        self.audit("select", "ok", group=group, choice=choice)
        with self.cache_lock:
            self.cache_at = 0
        return {"state": "ok", "group": group, "selected": choice, "previous": expected, "changed": True}

    def node_test(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.node_test_slots.acquire(blocking=False):
            raise CenterError("node_test_busy_retry_later", 429)
        try:
            return self._node_test(request)
        finally:
            self.node_test_slots.release()

    def _node_test(self, request: dict[str, Any]) -> dict[str, Any]:
        provider, name = request.get("provider"), request.get("name")
        if not all(isinstance(item, str) and 0 < len(item) <= 160 for item in (provider, name)):
            raise CenterError("node_test_fields_invalid")
        try:
            from clash_measurement import measure
        except ImportError:
            raise CenterError("node_test_measurement_unavailable", 503) from None

        def api(path: str) -> Any:
            return self.clash(path)

        result = measure(
            api, {"id": hashlib.sha256((provider + "\0" + name).encode()).hexdigest(), "provider": provider, "name": name},
            time.time(), timeout=int(_clamp_env("CENTER_NODE_TEST_TIMEOUT_MS", 5000, 1000, 15000)), force=True,
        )
        delay = result.get("latency") if isinstance(result, dict) else None
        if not isinstance(result, dict) or result.get("success") is not True or not isinstance(delay, (int, float)) or delay <= 0:
            self.audit("node-test", "failed", provider=provider, name=name)
            category = result.get("error_category") if isinstance(result, dict) else "node_test_failed"
            safe_category = category if isinstance(category, str) and re.fullmatch(r"[a-z0-9_]{1,80}", category) else "node_test_failed"
            raise CenterError(safe_category, 503)
        self.audit("node-test", "ok", provider=provider, name=name)
        return {"state": "ok", "provider": provider, "name": name, "delay_ms": int(delay), "origin": _safe_text(result.get("origin"), 32)}

    def management_snapshot(self) -> dict[str, Any]:
        return self.operations.snapshot()

    def start_operation(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.operations.start(request)
        except Exception as error:
            code = getattr(error, "code", "operation_failed")
            status = getattr(error, "status", 500)
            if not isinstance(code, str) or not IDENTIFIER.fullmatch(code):
                code, status = "operation_failed", 500
            raise CenterError(code, status) from None

    def bind_kuma(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.operations.start_sensitive_bind(request)
        except Exception as error:
            code = getattr(error, "code", "kuma_binding_failed")
            status = getattr(error, "status", 500)
            if not isinstance(code, str) or not IDENTIFIER.fullmatch(code):
                code, status = "kuma_binding_failed", 500
            raise CenterError(code, status) from None

    def start_backup(self) -> dict[str, Any]:
        if not self.write_enabled:
            raise CenterError("writes_disabled", 503)
        if not self.backup_slot.acquire(blocking=False):
            raise CenterError("backup_busy_retry_later", 409)
        job_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
        job = {"job_id": job_id, "state": "pending", "stage": "queued", "created_at": int(time.time()), "download": None}
        with self.jobs_lock:
            if len(self.jobs) >= 100:
                for old_id in sorted(self.jobs, key=lambda key: self.jobs[key].get("created_at", 0))[:-99]:
                    self.jobs.pop(old_id, None)
            self.jobs[job_id] = job
        self.audit("backup", "started", job_id=job_id)
        try:
            threading.Thread(target=self._backup_worker, args=(job_id,), name="center-backup-" + job_id[-8:], daemon=True).start()
        except Exception:
            with self.jobs_lock:
                self.jobs.pop(job_id, None)
            self.backup_slot.release()
            raise CenterError("backup_start_failed", 503) from None
        return {"job_id": job_id, "state": "pending"}

    def _job(self, job_id: str, **changes: Any) -> None:
        with self.jobs_lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(changes)

    def _backup_worker(self, job_id: str) -> None:
        archive = self.backup_root / (job_id + ".tar.gz")
        manifest_path = self.backup_root / (job_id + ".json")
        try:
            self._job(job_id, state="running", stage="snapshot")
            with tempfile.TemporaryDirectory(prefix="center-backup-", dir=self.center_root) as temporary:
                stage = Path(temporary)
                files, omitted = [], []
                db_candidates = [
                    (Path(self.namespace.get("DB_PATH", Path(self.namespace["DATA"]) / "controller.db")), "controller.db", True),
                    (self.data_root / "node-capability.db", "node-capability.db", False),
                    (Path(os.getenv("CENTER_KUMA_DB", "/app/data/kuma.db")), "kuma.db", True),
                ]
                for source, name, required in db_candidates:
                    if source.is_symlink() or not any(_inside(source, root) for root in (self.data_root, Path("/app/data"))) or not source.is_file():
                        omitted.append({"name": name, "reason": "required_missing" if required else "not_present"})
                        if required:
                            raise CenterError("backup_required_source_missing", 503)
                        continue
                    target = stage / name
                    uri = "file:" + urllib.parse.quote(str(source), safe="/:\\") + "?mode=ro"
                    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=5)) as src:
                        with contextlib.closing(sqlite3.connect(target)) as dst:
                            src.backup(dst, pages=256, sleep=.05)
                            integrity = dst.execute("PRAGMA integrity_check").fetchone()
                            if not integrity or integrity[0] != "ok":
                                raise CenterError("backup_integrity_failed", 503)
                    os.chmod(target, 0o600)
                    files.append(name)
                fixed = [
                    (Path(self.namespace["DATA"]) / "health.json", "controller-health.json", False),
                    (Path(self.namespace["DATA"]) / "current.json", "controller-current.json", True),
                    (Path(getattr(self.manager, "root", self.data_root / "local-source")) / "state.json", "local-source-state.json", False),
                    (Path(getattr(self.manager, "root", self.data_root / "local-source")) / "runtime.json", "local-source-runtime.json", False),
                    (self.data_root / "subscription-usage" / "sync-state.json", "usage-sync-state.json", False),
                    (Path(os.getenv("CENTER_COREFILE", "/etc/coredns/Corefile")), "Corefile", True),
                ]
                sources_file = self.namespace.get("SOURCES_FILE")
                if sources_file:
                    fixed.append((Path(sources_file), "subscription-sources.json", True))
                for source, name, required in fixed:
                    if source.is_symlink() or not any(_inside(source, root) for root in (self.data_root, Path("/app/data"), Path("/etc/coredns"))) or not source.is_file() or source.stat().st_size > 20 * 1024 * 1024:
                        omitted.append({"name": name, "reason": "required_missing" if required else "not_present"})
                        if required:
                            raise CenterError("backup_required_source_missing", 503)
                        continue
                    shutil.copyfile(source, stage / name, follow_symlinks=False)
                    os.chmod(stage / name, 0o600)
                    files.append(name)
                guide = (
                    "中心侧备份恢复说明\n\n"
                    "本归档仅包含已列出的中心侧数据库、状态和配置快照，不是路由器备份，也不是整机灾备镜像。\n"
                    "备份不包含 local-source 的 admin-token、provider-token、identity-key 等凭据/密钥文件；"
                    "恢复后必须使用独立安全渠道提供或重建这些凭据。\n"
                    "本系统不会自动覆盖运行中数据库。请先停止相应的隔离服务，核对版本与 schema，"
                    "再做一次恢复前备份，逐个组件恢复，最后进行健康检查、读回和业务验收。\n"
                    "路由器配置、OpenClash 运行状态及整机恢复能力必须另行建立并验证。\n"
                )
                (stage / "RESTORE-GUIDE.txt").write_text(guide, encoding="utf-8")
                files.append("RESTORE-GUIDE.txt")
                files.append("BACKUP-CONTENTS.json")
                contents = {
                    "schema": 1, "scope": "center_only", "included": sorted(files), "omitted": omitted,
                    "excludes": ["router_configuration", "whole_machine_state", "admin_token", "provider_token", "identity_key"],
                }
                (stage / "BACKUP-CONTENTS.json").write_bytes(_json_bytes(contents))
                self._job(job_id, stage="archive")
                with tarfile.open(archive, "w:gz") as bundle:
                    for name in sorted(files):
                        bundle.add(stage / name, arcname=name, recursive=False)
            os.chmod(archive, 0o600)
            max_bytes = int(_clamp_env("CENTER_BACKUP_MAX_BYTES", 2 * 1024**3, 10 * 1024**2, 20 * 1024**3))
            if archive.stat().st_size > max_bytes:
                raise CenterError("backup_size_limit_exceeded", 503)
            digest = hashlib.sha256()
            with open(archive, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            manifest = {"id": job_id, "created_at": int(time.time()), "state": "ok", "scope": "center_only", "sha256": digest.hexdigest(), "size": archive.stat().st_size, "included": sorted(files), "omitted": omitted}
            manifest_path.write_bytes(_json_bytes(manifest))
            os.chmod(manifest_path, 0o600)
            self.prune_backups(job_id, max_bytes)
            self._job(job_id, state="ok", stage="done", completed_at=manifest["created_at"], download=f"/api/center/backups/{job_id}/download", download_url=f"/api/center/backups/{job_id}/download")
            self.audit("backup", "completed", job_id=job_id)
        except Exception:
            archive.unlink(missing_ok=True)
            manifest_path.unlink(missing_ok=True)
            self._job(job_id, state="error", stage="failed", error="backup_failed")
            self.audit("backup", "failed", job_id=job_id)
        finally:
            self.backup_slot.release()

    def prune_backups(self, current_id: str, max_bytes: int) -> None:
        limit = int(_clamp_env("CENTER_BACKUP_RETAIN", 20, 1, 100))
        records = []
        for manifest in self.backup_root.glob("*.json"):
            try:
                if manifest.is_symlink() or not IDENTIFIER.fullmatch(manifest.stem) or manifest.stat().st_size > 32768:
                    continue
                value = json.loads(manifest.read_text(encoding="utf-8"))
                archive = self.backup_root / (manifest.stem + ".tar.gz")
                if value.get("state") == "ok" and archive.is_file() and not archive.is_symlink():
                    records.append((int(value.get("created_at", 0)), manifest.stem, archive.stat().st_size, manifest, archive))
            except (OSError, ValueError, TypeError):
                continue
        total = 0
        for index, (_created, backup_id, size, manifest, archive) in enumerate(sorted(records, reverse=True)):
            retain = backup_id == current_id or (index < limit and total + size <= max_bytes)
            if retain:
                total += size
                continue
            # Exact validated files only; never recurse and never follow links.
            manifest.unlink(missing_ok=True)
            try:
                archive.unlink(missing_ok=True)
            except OSError:
                # An orphaned private archive is invisible and can be cleaned by
                # an operator; never recreate a public-looking manifest for it.
                pass

    def job_status(self, job_id: str) -> dict[str, Any]:
        if not IDENTIFIER.fullmatch(job_id):
            raise CenterError("job_not_found", 404)
        operation = self.operations.job_status(job_id)
        if operation is not None:
            return operation
        with self.jobs_lock:
            job = dict(self.jobs.get(job_id, {}))
        if job:
            if job.get("state") == "ok" and self.backup_complete(job_id) is None:
                job.update(state="error", stage="missing", error="backup_artifact_unavailable", download=None, download_url=None)
            return job
        manifest = self.backup_root / (job_id + ".json")
        try:
            if manifest.is_symlink() or not _inside(manifest, self.backup_root) or manifest.stat().st_size > 32768:
                raise OSError
            value = self.backup_complete(job_id)
            if value is None:
                raise OSError
            return {"job_id": job_id, "state": value.get("state"), "stage": "done", "created_at": value.get("created_at"), "download": f"/api/center/backups/{job_id}/download", "download_url": f"/api/center/backups/{job_id}/download"}
        except (OSError, ValueError, TypeError):
            raise CenterError("job_not_found", 404) from None

    def download(self, handler: Any, backup_id: str) -> None:
        self.require_auth(handler)
        if not IDENTIFIER.fullmatch(backup_id):
            raise CenterError("backup_not_found", 404)
        path = self.backup_root / (backup_id + ".tar.gz")
        manifest = self.backup_root / (backup_id + ".json")
        completed = self.backup_complete(backup_id)
        if completed is None or path.is_symlink() or manifest.is_symlink():
            raise CenterError("backup_not_found", 404)
        size = path.stat().st_size
        handler.send_response(200)
        handler.send_header("Content-Type", "application/gzip")
        handler.send_header("Content-Disposition", f'attachment; filename="center-backup-{backup_id}.tar.gz"')
        handler.send_header("Content-Length", str(size))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()
        with open(path, "rb") as stream:
            shutil.copyfileobj(stream, handler.wfile, length=64 * 1024)


def install(namespace: dict[str, Any], manager: Any, access: Any) -> Center | None:
    """Install the center routes after the legacy editor and usage extensions."""
    if os.getenv("CENTER_UI_ENABLED", "0") != "1":
        return None
    Handler = namespace["Handler"]
    center = Center(namespace, manager, access)
    previous_get, previous_post = Handler.do_GET, Handler.do_POST
    previous_head = getattr(Handler, "do_HEAD", None)
    classic_dashboard = namespace["dashboard"]

    def send_json(handler: Any, status: int, value: Any) -> None:
        payload = _json_bytes(value)
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("X-Frame-Options", "DENY")
        handler.end_headers()
        handler.wfile.write(payload)

    def maybe_proxy(handler: Any) -> bool:
        path = urllib.parse.urlsplit(handler.path).path
        # Kuma is managed through the native center API.  Its original admin
        # GUI and websocket are not a second management entry.  Public status
        # pages remain independently usable and are not an admin interface.
        # The retired root service worker remains handled by unified_proxy so
        # older browsers can unregister it; LuCI proxying remains unchanged.
        kuma_roots = (
            "/dashboard", "/edit", "/clone", "/add", "/list", "/settings",
            "/manage-status-page", "/add-status-page", "/maintenance",
            "/add-maintenance", "/setup", "/setup-database",
            "/setup-database-info", "/empty", "/socket.io", "/metrics",
            "/api/auth",
        )
        if os.getenv("CENTER_KUMA_NATIVE_PROXY_ENABLED", "0") != "1" and (
            any(path == root or path.startswith(root + "/") for root in kuma_roots)
        ):
            send_json(handler, 410, {"error": "kuma_native_ui_retired"})
            return True
        try:
            from unified_proxy import proxy_request
        except ImportError:
            return False
        try:
            return bool(proxy_request(handler, access=access))
        except Exception:
            send_json(handler, 502, {"error": "advanced_proxy_unavailable"})
            return True

    def serve_asset(handler: Any, relative: str) -> None:
        relative = urllib.parse.unquote(relative)
        if not relative or "\x00" in relative:
            raise CenterError("asset_not_found", 404)
        path = ASSETS.joinpath(*Path(relative).parts)
        if path.is_symlink() or not _inside(path, ASSETS) or not path.is_file():
            raise CenterError("asset_not_found", 404)
        payload = path.read_bytes()
        if relative == "index.html":
            for name in ("app.js", "app.css", "logo.png"):
                digest = hashlib.sha256((ASSETS / name).read_bytes()).hexdigest()[:16]
                asset = ("/center-assets/" + name).encode()
                payload = payload.replace(asset + b'"', asset + ("?v=" + digest).encode() + b'"')
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        handler.send_response(200)
        handler.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"} else ""))
        handler.send_header("Content-Length", str(len(payload)))
        handler.send_header("Cache-Control", "no-store" if relative == "index.html" else "public, max-age=300")
        handler.send_header("X-Content-Type-Options", "nosniff")
        if relative == "index.html":
            handler.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; font-src 'self'; "
                "connect-src 'self' https://*.t.dnsleak.dev; "
                "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
        handler.end_headers()
        handler.wfile.write(payload)

    def get(handler: Any) -> None:
        try:
            path = urllib.parse.urlsplit(handler.path).path
            if path == "/":
                serve_asset(handler, "index.html")
            elif path == "/classic/subscriptions":
                handler.send(200, "text/html; charset=utf-8", classic_dashboard())
            elif path.startswith("/center-assets/"):
                serve_asset(handler, path[len("/center-assets/"):])
            elif path == "/api/center/overview":
                send_json(handler, 200, center.overview())
            elif path == "/api/center/session":
                _, session = center.session(handler)
                send_json(handler, 200, {"authenticated": True, "csrf": session["csrf"]} if session else {"authenticated": False})
            elif path == "/api/center/manage/snapshot":
                center.require_auth(handler)
                send_json(handler, 200, center.management_snapshot())
            elif (match := re.fullmatch(r"/api/center/jobs/([A-Za-z0-9_.-]{1,96})", path)):
                center.require_auth(handler)
                send_json(handler, 200, center.job_status(match.group(1)))
            elif (match := re.fullmatch(r"/api/center/backups/([A-Za-z0-9_.-]{1,96})/download", path)):
                center.download(handler, match.group(1))
            elif maybe_proxy(handler):
                return
            else:
                previous_get(handler)
        except CenterError as error:
            send_json(handler, error.status, {"error": error.code})
        except Exception:
            send_json(handler, 500, {"error": "center_request_failed"})

    def post(handler: Any) -> None:
        try:
            path = urllib.parse.urlsplit(handler.path).path
            if not path.startswith("/api/center/"):
                if maybe_proxy(handler):
                    return
                previous_post(handler)
                return
            request = center.read_body(handler)
            center.require_auth(handler, csrf=True)
            if path == "/api/center/select":
                send_json(handler, 200, center.select(request))
            elif path == "/api/center/node-test":
                send_json(handler, 200, center.node_test(request))
            elif path == "/api/center/backup":
                if request:
                    raise CenterError("backup_body_must_be_empty")
                send_json(handler, 202, center.start_backup())
            elif path == "/api/center/operations":
                send_json(handler, 202, center.start_operation(request))
            elif path == "/api/center/kuma/bind":
                send_json(handler, 202, center.bind_kuma(request))
            else:
                raise CenterError("not_found", 404)
        except CenterError as error:
            send_json(handler, error.status, {"error": error.code})
        except Exception:
            send_json(handler, 500, {"error": "center_operation_failed"})

    def head(handler: Any) -> None:
        if maybe_proxy(handler):
            return
        if previous_head is not None:
            previous_head(handler)
        else:
            handler.send_error(404)

    Handler.do_GET, Handler.do_POST, Handler.do_HEAD = get, post, head
    namespace["unified_center"] = center
    return center
