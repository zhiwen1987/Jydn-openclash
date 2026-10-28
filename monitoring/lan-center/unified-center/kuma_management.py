"""Native Uptime Kuma management extension for the unified Clash Center.

The center owns HTTP authentication, same-origin/CSRF checks, optimistic
revision checks, the global write lock and the asynchronous job deadline.  This
module owns only a bounded local JSONL subprocess connected to Kuma's official
authenticated Socket.IO handlers.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable


class KumaError(RuntimeError):
    def __init__(self, code: str, status: int = 503):
        super().__init__(code)
        self.code, self.status = code, status


def _get(context: Any, name: str, default: Any = None) -> Any:
    return context.get(name, default) if isinstance(context, dict) else getattr(context, name, default)


def _revision(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


SENSITIVE_KEY = re.compile(r"(?:password|passwd|secret|token|authorization|cookie|private_key)$", re.I)


def _safe(value: Any, depth: int = 0, key: str = "") -> Any:
    """Defence-in-depth: never let credentials cross the extension boundary."""
    if SENSITIVE_KEY.search(key):
        return "[hidden]"
    if depth > 8:
        return None
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, str):
        return "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in value)[:4096]
    if isinstance(value, list):
        return [_safe(item, depth + 1) for item in value[:2000]]
    if isinstance(value, dict):
        return {str(k)[:96]: _safe(v, depth + 1, str(k)) for k, v in list(value.items())[:512]}
    return str(value)[:256]


class JsonLineBridge:
    """One serialized request at a time; writes are never replayed."""

    def __init__(self, script: Path, token_file: Path, url: str, node: str = "node", request_timeout: float = 8.0):
        self.script, self.token_file, self.url, self.node = Path(script), Path(token_file), url, node
        self.request_timeout = max(1.0, min(float(request_timeout), 20.0))
        self.process: subprocess.Popen[str] | None = None
        self.responses: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=8)
        self.lock = threading.Lock()
        self.reader: threading.Thread | None = None

    def _start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        self.close()
        if not self.script.is_file():
            raise KumaError("kuma_bridge_unavailable")
        environment = os.environ.copy()
        environment.update({
            "CENTER_KUMA_TOKEN_FILE": str(self.token_file),
            "CENTER_KUMA_URL": self.url,
            "CENTER_KUMA_REQUEST_TIMEOUT_MS": str(int(self.request_timeout * 1000)),
        })
        try:
            self.process = subprocess.Popen(
                [self.node, str(self.script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
                env=environment, close_fds=os.name != "nt",
            )
        except (OSError, ValueError):
            self.process = None
            raise KumaError("kuma_bridge_unavailable") from None
        self.reader = threading.Thread(target=self._read, name="kuma-jsonl-reader", daemon=True)
        self.reader.start()

    def _read(self) -> None:
        process = self.process
        if not process or not process.stdout:
            return
        try:
            for line in process.stdout:
                if len(line) > 2 * 1024 * 1024:
                    continue
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        self.responses.put(value, timeout=0.2)
                except (ValueError, queue.Full):
                    continue
        finally:
            try:
                self.responses.put_nowait(None)
            except queue.Full:
                pass

    def request(self, action: str, params: dict[str, Any] | None = None, *, timeout: float | None = None, write: bool = False) -> dict[str, Any]:
        deadline = max(1.0, min(float(timeout or self.request_timeout + 2), 25.0))
        with self.lock:
            self._start()
            process = self.process
            if not process or not process.stdin or process.poll() is not None:
                raise KumaError("kuma_bridge_unavailable")
            request_id = uuid.uuid4().hex
            try:
                process.stdin.write(json.dumps({"id": request_id, "action": action, "params": params or {}}, ensure_ascii=False, separators=(",", ":")) + "\n")
                process.stdin.flush()
            except (OSError, BrokenPipeError):
                self.close()
                raise KumaError("kuma_bridge_unavailable") from None
            end = time.monotonic() + deadline
            while True:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    self.close()
                    raise KumaError("kuma_write_outcome_unknown" if write else "kuma_timeout")
                try:
                    response = self.responses.get(timeout=remaining)
                except queue.Empty:
                    self.close()
                    raise KumaError("kuma_write_outcome_unknown" if write else "kuma_timeout") from None
                if response is None:
                    self.close()
                    raise KumaError("kuma_bridge_unavailable")
                if response.get("id") != request_id:
                    continue
                if response.get("ok") is not True:
                    error = response.get("error") if isinstance(response.get("error"), dict) else {}
                    code = error.get("code") if isinstance(error.get("code"), str) else "kuma_upstream_failed"
                    status = 409 if code in {"kuma_binding_required", "kuma_conflict"} else 401 if code in {"kuma_auth_failed", "kuma_totp_required"} else 400 if "validation" in code or "unsupported" in code else 503
                    raise KumaError(code, status)
                result = response.get("result")
                if not isinstance(result, dict):
                    raise KumaError("kuma_protocol_mismatch")
                return result

    def close(self) -> None:
        process, self.process = self.process, None
        if process:
            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        process.kill()
                        process.wait(timeout=1)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            if self.reader and self.reader is not threading.current_thread():
                self.reader.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        self.reader = None
        while True:
            try:
                self.responses.get_nowait()
            except queue.Empty:
                break


class KumaExtension:
    READ_ACTIONS = {"kuma.monitor_detail", "kuma.monitor_history", "kuma.notification_detail"}
    WRITE_ACTIONS = {
        "kuma.monitor_create", "kuma.monitor_update", "kuma.monitor_delete", "kuma.monitor_pause", "kuma.monitor_resume",
        "kuma.notification_create", "kuma.notification_update", "kuma.notification_delete", "kuma.notification_test",
    }

    def __init__(self, context: Any):
        namespace = _get(context, "namespace", {}) or {}
        data_root = Path(_get(context, "data_root", namespace.get("DATA", "/data")))
        center_root = Path(_get(context, "center_root", data_root / "center"))
        self.token_file = Path(os.getenv("CENTER_KUMA_TOKEN_FILE", str(data_root / "unified" / "kuma-bridge.jwt")))
        script = Path(os.getenv("CENTER_KUMA_BRIDGE", str(Path(__file__).with_name("kuma_bridge.js"))))
        timeout = max(2.0, min(float(_get(context, "remote_timeout", 2.5)) * 2.0, 8.0))
        injected = _get(context, "kuma_bridge_transport")
        self.transport = injected if callable(injected) else JsonLineBridge(
            script, self.token_file, os.getenv("CENTER_KUMA_URL", "http://127.0.0.1:3001"),
            os.getenv("CENTER_NODE", "node"), timeout,
        ).request
        self._last_state = "ready" if callable(injected) or self.token_file.is_file() else "unbound"
        self._last_snapshot: dict[str, Any] | None = None

    def actions(self) -> dict[str, dict[str, Any]]:
        ready = self._last_state == "ready"
        actions: dict[str, dict[str, Any]] = {
            # Coordinator worst case: pre-snapshot 12 s + bind/write phase +
            # post-snapshot 12 s.  Keep the public deadline above that entire
            # chain while the individual bridge calls retain tighter bounds.
            "kuma.bind": {"write": True, "supported": True, "sensitive_input": True, "timeout_seconds": 60, "deadline_enforced": True},
        }
        for action in self.READ_ACTIONS:
            # Job deadline covers coordinator pre/post snapshots (12 s each)
            # plus the adapter's independently bounded 12 s read.
            actions[action] = {"write": False, "supported": ready, "timeout_seconds": 45}
        for action in self.WRITE_ACTIONS:
            actions[action] = {"write": True, "supported": ready, "timeout_seconds": 60, "deadline_enforced": True}
        return actions

    def _call(self, action: str, params: dict[str, Any] | None = None, *, write: bool = False, timeout: float | None = None) -> dict[str, Any]:
        try:
            if callable(self.transport):
                return self.transport(action, params or {}, timeout=timeout, write=write)
        except KumaError:
            raise
        except Exception:
            raise KumaError("kuma_bridge_unavailable") from None
        raise KumaError("kuma_bridge_unavailable")

    def snapshot(self) -> dict[str, Any]:
        try:
            value = self._call("kuma.snapshot", timeout=12)
            state = value.get("state") if isinstance(value.get("state"), str) else "error"
            self._last_state = state
            safe = _safe(value)
            if not isinstance(safe, dict):
                raise KumaError("kuma_protocol_mismatch")
            safe["capabilities"] = {
                "actions": [name for name, meta in self.actions().items() if meta.get("supported") is True],
                "monitor_types": ["http", "ping", "port", "dns", "group"],
                "notification_types": ["webhook"],
                "monitor_test": False,
            }
            if not isinstance(safe.get("revision"), str) or len(safe["revision"]) != 64:
                safe["revision"] = _revision({"state": state, "error_code": safe.get("error_code")})
            self._last_snapshot = safe
            return safe
        except KumaError as error:
            state = "unbound" if error.code == "kuma_binding_required" else "auth_failed" if error.code == "kuma_auth_failed" else "error"
            self._last_state = state
            value = {"state": state, "error_code": error.code, "revision": _revision({"state": state, "error_code": error.code}), "version": None, "connection": {"state": state, "checked_at": None, "detail": error.code}, "capabilities": {"actions": ["kuma.bind"], "monitor_types": ["http", "ping", "port", "dns", "group"], "notification_types": ["webhook"], "monitor_test": False}, "monitors": [], "groups": [], "notifications": []}
            self._last_snapshot = value
            return value

    def bind_sensitive(self, params: dict[str, Any], progress: Callable[..., Any] = lambda *_args, **_kwargs: None) -> dict[str, Any]:
        progress("authenticating")
        # The bridge credential phase is 10 s; coordinator pre/post snapshots
        # are separately bounded and covered by the advertised 60 s deadline.
        result = self._call("internal.bind", params, write=True, timeout=10)
        params.clear()
        progress("readback")
        readback = self.snapshot()
        if readback.get("state") != "ready" or not readback.get("revision"):
            raise KumaError("kuma_readback_failed")
        return {"state": "bound", "revision": readback["revision"], "readback": {"state": "ready", "monitor_count": len(readback.get("monitors", [])), "notification_count": len(readback.get("notifications", []))}}

    def execute(self, action: str, params: dict[str, Any] | None, progress: Callable[..., Any] = lambda *_args, **_kwargs: None) -> dict[str, Any]:
        if action == "kuma.bind":
            raise KumaError("operation_sensitive_route_required", 403)
        meta = self.actions().get(action)
        if not meta or meta.get("supported") is not True:
            raise KumaError("kuma_action_unsupported", 404)
        progress("dispatching")
        # 25 s write plus coordinator pre/post snapshots stays below 60 s.
        result = self._call(action, params or {}, write=bool(meta["write"]), timeout=25 if meta["write"] else 12)
        if meta["write"]:
            progress("readback")
            if result.get("state") != "ok" or not isinstance(result.get("readback"), dict) and action != "kuma.notification_test":
                raise KumaError("kuma_readback_failed")
        return _safe(result)


def create_extension(context: Any) -> KumaExtension:
    return KumaExtension(context)
