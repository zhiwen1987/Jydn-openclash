"""Strict, disposable CoreDNS candidate validator.

The production Corefile is never opened for writing.  A candidate is accepted
only when its known listeners can be moved to random loopback ports and a real
CoreDNS child answers both UDP and TCP before the hard deadline.
"""
from __future__ import annotations

import errno
import hashlib
import ipaddress
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


class ValidatorError(RuntimeError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code, self.status = code, status


PLUGIN_OPTIONS = {
    "errors": {"consolidate"},
    "health": {"lameduck"},
    "ready": {"monitor"},
    "acl": {"allow", "block", "filter"},
    "cache": {"success", "denial", "servfail", "prefetch", "disable"},
    "forward": {
        "policy", "health_check", "max_fails", "expire", "force_tcp",
        "prefer_udp", "tls", "tls_servername", "max_concurrent",
        "next", "failover", "failfast_all_unhealthy_upstreams",
        "max_connect_attempts",
    },
    "hosts": {"ttl", "no_reverse", "reload", "fallthrough"},
}
SINGLE_PLUGINS = {"bind", "prometheus", "loop", "reload", "rewrite"}
BLOCK_PLUGINS = set(PLUGIN_OPTIONS)
SERVER = re.compile(r"^\s*\.:53\s*\{\s*$")
HEALTH = re.compile(r"^(\s*)health\s+127\.0\.0\.1:\d+\s*\{\s*$")
READY = re.compile(r"^(\s*)ready\s+127\.0\.0\.1:\d+\s*\{\s*$")
PROMETHEUS = re.compile(r"^(\s*)prometheus\s+127\.0\.0\.1:\d+\s*$")
BIND = re.compile(r"^(\s*)bind\s+(?:0\.0\.0\.0|127\.0\.0\.1)\s*$")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _direct_http_ok(url: str, timeout: float) -> bool:
    # Never let HTTP(S)_PROXY turn loopback readiness into remote proxy evidence.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"Accept": "text/plain"})
    with opener.open(request, timeout=timeout) as response:
        response.read(1024)
        return int(getattr(response, "status", 0)) == 200


def _line_token(line: str) -> str:
    value = line.split("#", 1)[0].strip()
    return value.split(None, 1)[0] if value else ""


def _inspect_known(text: str, fragment: bool = False) -> dict[str, int]:
    """Reject syntax we cannot safely relocate; this is not a YAML-like parser."""
    lines = text.splitlines()
    if fragment:
        lines = [".:53 {"] + lines + ["}"]
    depth = 0
    active: list[tuple[str, int]] = []
    counts: dict[str, int] = {}
    server_count = 0
    for raw in lines:
        clean = raw.split("#", 1)[0].strip()
        if not clean:
            continue
        if depth == 0:
            if not SERVER.fullmatch(raw):
                raise ValidatorError("unsupported_corefile")
            server_count += 1
            if server_count != 1:
                raise ValidatorError("unsupported_corefile")
            depth = 1
            continue
        if clean == "}":
            depth -= 1
            while active and active[-1][1] > depth:
                active.pop()
            if depth < 0:
                raise ValidatorError("unsupported_corefile")
            continue
        opens, closes = clean.count("{"), clean.count("}")
        token = _line_token(raw)
        if depth == 1:
            if token == "import":
                counts[token] = counts.get(token, 0) + 1
                if opens or closes or len(clean.split()) != 2:
                    raise ValidatorError("unsupported_corefile")
            elif token in SINGLE_PLUGINS or token in BLOCK_PLUGINS:
                counts[token] = counts.get(token, 0) + 1
                if opens:
                    if token not in BLOCK_PLUGINS or opens != 1 or closes:
                        raise ValidatorError("unsupported_corefile")
                    active.append((token, depth + 1))
                elif closes:
                    raise ValidatorError("unsupported_corefile")
            else:
                raise ValidatorError("unsupported_plugin")
        else:
            plugin = active[-1][0] if active else ""
            if token not in PLUGIN_OPTIONS.get(plugin, set()) or opens or closes:
                raise ValidatorError("unsupported_plugin_option")
        depth += opens - closes
        if depth < 0 or depth > 2:
            raise ValidatorError("unsupported_corefile")
    if depth != 0 or server_count != 1:
        raise ValidatorError("unsupported_corefile")
    return counts


def _validate_hosts(text: str) -> None:
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ValidatorError("invalid_hosts_candidate")
        try:
            ipaddress.ip_address(fields[0])
        except ValueError:
            raise ValidatorError("invalid_hosts_candidate") from None
        if len(fields[1]) > 253 or any(not part or len(part) > 63 for part in fields[1].rstrip(".").split(".")):
            raise ValidatorError("invalid_hosts_candidate")


class IsolatedCoreDnsValidator:
    def __init__(self, fragment_path: str | Path, hosts_path: str | Path,
                 executable: str = "coredns", timeout: float = 12.0):
        self.fragment_path = str(fragment_path)
        self.hosts_path = str(hosts_path)
        self.executable = shutil.which(executable) or executable
        self.timeout = max(4.0, min(float(timeout), 20.0))

    def _rewrite(self, core: str, fragment: str, root: Path,
                 dns_port: int, health_port: int, ready_port: int,
                 metrics_port: int) -> tuple[str, str]:
        core_counts = _inspect_known(core)
        fragment_counts = _inspect_known(fragment, fragment=True)
        if core_counts.get("import") != 1 or fragment_counts.get("forward") != 1:
            raise ValidatorError("unsupported_corefile")
        if core_counts.get("health") != 1 or core_counts.get("ready") != 1:
            raise ValidatorError("isolated_readiness_unavailable")
        if core.count(self.fragment_path) != 1:
            raise ValidatorError("managed_import_mismatch")
        temp_fragment, temp_hosts = root / "Corefile.managed", root / "hosts"
        rewritten = core.replace(self.fragment_path, str(temp_fragment), 1)
        out = []
        seen = {"server": 0, "bind": 0, "health": 0, "ready": 0, "prometheus": 0}
        for line in rewritten.splitlines():
            if SERVER.fullmatch(line):
                out.append(f".:{dns_port} {{"); seen["server"] += 1
            elif (match := BIND.fullmatch(line)):
                out.append(match.group(1) + "bind 127.0.0.1"); seen["bind"] += 1
            elif (match := HEALTH.fullmatch(line)):
                out.append(match.group(1) + f"health 127.0.0.1:{health_port} {{"); seen["health"] += 1
            elif (match := READY.fullmatch(line)):
                out.append(match.group(1) + f"ready 127.0.0.1:{ready_port} {{"); seen["ready"] += 1
            elif (match := PROMETHEUS.fullmatch(line)):
                out.append(match.group(1) + f"prometheus 127.0.0.1:{metrics_port}"); seen["prometheus"] += 1
            else:
                out.append(line)
        if seen["server"] != 1 or seen["bind"] != 1 or seen["health"] != 1 or seen["ready"] != 1 or seen["prometheus"] > 1:
            raise ValidatorError("listener_rewrite_incomplete")
        if self.hosts_path in fragment:
            if fragment.count(self.hosts_path) != 1:
                raise ValidatorError("managed_hosts_mismatch")
            fragment = fragment.replace(self.hosts_path, str(temp_hosts), 1)
        return "\n".join(out) + "\n", fragment

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=1.5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise ValidatorError("isolated_process_cleanup_failed", 503) from None

    def __call__(self, core: str, fragment: str, hosts: str) -> dict:
        if not all(isinstance(value, str) for value in (core, fragment, hosts)):
            raise ValidatorError("invalid_candidate")
        _validate_hosts(hosts)
        deadline = time.monotonic() + self.timeout
        ports = []
        while len(ports) < 4:
            port = _free_port()
            if port not in ports:
                ports.append(port)
        dns_port, health_port, ready_port, metrics_port = ports
        with tempfile.TemporaryDirectory(prefix="jydn-dns-validator-") as temporary:
            root = Path(temporary)
            candidate, managed = self._rewrite(core, fragment, root, *ports)
            core_path, fragment_path, hosts_path = root / "Corefile", root / "Corefile.managed", root / "hosts"
            core_path.write_text(candidate, encoding="utf-8")
            fragment_path.write_text(managed, encoding="utf-8")
            hosts_path.write_text(hosts, encoding="utf-8")
            for path in (core_path, fragment_path, hosts_path):
                os.chmod(path, 0o600)
            try:
                process = subprocess.Popen(
                    [self.executable, "-conf", str(core_path)], cwd=root,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, start_new_session=True,
                )
            except FileNotFoundError:
                raise ValidatorError("coredns_binary_unavailable", 503) from None
            except PermissionError as error:
                code = "coredns_execution_denied" if error.errno in {errno.EACCES, errno.EPERM} else "coredns_start_failed"
                raise ValidatorError(code, 503) from None
            except (OSError, ValueError):
                raise ValidatorError("coredns_start_failed", 503) from None
            output = b""
            try:
                ready = f"http://127.0.0.1:{ready_port}/ready"
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        output = process.stdout.read(65536) if process.stdout else b""
                        raise ValidatorError("isolated_coredns_exited", 422)
                    try:
                        if _direct_http_ok(ready, min(.4, max(.05, deadline - time.monotonic()))):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise ValidatorError("isolated_ready_timeout", 422)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValidatorError("isolated_query_timeout", 422)
                from dns_diagnostics import query_wire
                udp = query_wire("example.com", "A", f"127.0.0.1:{dns_port}", "udp", min(1.5, remaining))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValidatorError("isolated_query_timeout", 422)
                tcp = query_wire("example.com", "A", f"127.0.0.1:{dns_port}", "tcp", min(1.5, remaining))
                if udp.get("rcode") not in {"NOERROR", "NXDOMAIN"} or tcp.get("rcode") != udp.get("rcode"):
                    raise ValidatorError("isolated_dns_readback_failed", 422)
                return {
                    "state": "ok", "isolated": True,
                    "candidate_core_sha256": _sha(core.encode()),
                    "candidate_fragment_sha256": _sha(fragment.encode()),
                    "udp": {"rcode": udp.get("rcode"), "elapsed_ms": udp.get("elapsed_ms")},
                    "tcp": {"rcode": tcp.get("rcode"), "elapsed_ms": tcp.get("elapsed_ms")},
                }
            finally:
                try:
                    self._stop(process)
                finally:
                    if process.stdout:
                        process.stdout.close()


def create_validator(context) -> IsolatedCoreDnsValidator:
    def get(name, default=None):
        return context.get(name, default) if isinstance(context, dict) else getattr(context, name, default)
    state = Path(os.getenv("CENTER_DNS_MANAGED_DIR", str(Path(get("center_root", "/data/center")) / "dns-management")))
    return IsolatedCoreDnsValidator(
        get("dns_fragment", state / "Corefile.managed"),
        get("dns_hosts", state / "hosts"),
        get("coredns_binary", os.getenv("CENTER_COREDNS_BIN", "coredns")),
        get("dns_validator_timeout", 12),
    )
