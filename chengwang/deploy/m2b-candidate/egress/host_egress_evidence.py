#!/usr/bin/env python3
"""Read-only host egress evidence collector and fail-closed verifier.

The collector executes only fixed read commands (docker inspect, docker network
inspect, and nft --json list ruleset).  It never starts a container and never
changes a firewall.  Raw command output is reduced in memory to a strict,
secret-free projection before it is written.  The verifier consumes two
projections and validates the nftables contract and counter movement.  It
deliberately emits a BLOCKED report, not a start-verify evidence artifact, while the
repository's start gate requires an internal Docker network.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable


SNAPSHOT_SCHEMA = "chengwang.host-egress-snapshot/v1"
PLAN_SCHEMA = "chengwang.host-egress-plan/v1"
REPORT_SCHEMA = "chengwang.host-egress-verification/v1"
EVIDENCE_SCHEMA = "chengwang.m2b-probe-egress-evidence/v1"
COLLECTOR = "host-firewall-counter-capture/v1"
FIREWALL_SCOPE = "probe-container-default-deny"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
NETWORK_ID = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
EVIDENCE_ID = re.compile(r"^evidence:[a-z0-9][a-z0-9._-]{0,127}$")
BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_INPUT = 8 * 1024 * 1024
MAX_CAPTURE_GAP = 300
MAX_EVIDENCE_LIFETIME = 300
MAX_SINGLE_CAPTURE_SECONDS = 20
APPROVED_EXECUTABLES = {
    "docker": frozenset({"/usr/bin/docker"}),
    "nft": frozenset({"/usr/bin/nft", "/usr/sbin/nft"}),
}
PROHIBITED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
    "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fec0::/10",
))
PROHIBITED_METADATA = {
    ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("168.63.129.16"),
    ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("169.254.170.2"),
}


class ContractError(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_symlink_components(path: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute():
        raise ContractError(f"path must be absolute: {path}")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = os.lstat(current).st_mode
        except OSError as exc:
            raise ContractError(f"path component cannot be inspected: {current}") from exc
        if stat.S_ISLNK(mode):
            raise ContractError(f"symlink path component is prohibited: {current}")
    return path


def _require_trusted_ancestors(path: pathlib.Path) -> None:
    if os.name != "posix":
        return
    current = pathlib.Path(path.anchor)
    root_info = os.lstat(current)
    if root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022:
        raise ContractError(f"path ancestor must be root-owned and not group/world writable: {current}")
    for part in path.parts[1:-1]:
        current = current / part
        info = os.lstat(current)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ContractError(f"path ancestor must be root-owned and not group/world writable: {current}")


def secure_read(path: pathlib.Path, maximum: int = MAX_INPUT) -> bytes:
    _reject_symlink_components(path)
    _require_trusted_ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"input cannot be opened safely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ContractError(f"input must be a single-link regular file: {path}")
        if before.st_size > maximum:
            raise ContractError(f"input exceeds {maximum} bytes: {path}")
        if os.name == "posix" and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o077):
            raise ContractError(f"input must be root-owned and mode 0600 or stricter: {path}")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise ContractError(f"input exceeds {maximum} bytes: {path}")
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size)
        identity_after = (after.st_dev, after.st_ino, after.st_size)
        if os.name == "posix":
            identity_before += (before.st_mtime_ns, before.st_ctime_ns)
            identity_after += (after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after or len(raw) != after.st_size:
            raise ContractError(f"input changed while it was read: {path}")
        return raw
    finally:
        os.close(descriptor)


def load_json(path: pathlib.Path, maximum: int = MAX_INPUT) -> tuple[Any, bytes]:
    raw = secure_read(path, maximum)
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON input: {path}") from exc
    return value, raw


def _read_proc_file(path: pathlib.Path, maximum: int) -> bytes:
    if not str(path).startswith("/proc/") or ".." in path.parts:
        raise ContractError("proc input path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"proc input cannot be opened safely: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError(f"proc input is not a regular file: {path}")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum:
            raise ContractError(f"proc input exceeds {maximum} bytes: {path}")
        return raw
    finally:
        os.close(descriptor)


def _fd_stat_path(path: pathlib.Path, follow_final_symlink: bool) -> os.stat_result:
    if not follow_final_symlink:
        _reject_symlink_components(path)
    flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
    if not follow_final_symlink:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"namespace path cannot be opened safely: {path}") from exc
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def exact_fields(value: Any, expected: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ContractError(f"{label} field set is invalid")
    return value


def integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


def text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ContractError(f"{label} must be a non-empty trimmed string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ContractError(f"{label} contains a control character")
    if pattern is not None and not pattern.fullmatch(value):
        raise ContractError(f"{label} format is invalid")
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(raw)


def atomic_write_new(path: pathlib.Path, value: Any) -> None:
    if not path.is_absolute():
        raise ContractError("output path must be absolute")
    if path.exists() or path.is_symlink():
        raise ContractError("output path already exists")
    parent = path.parent.resolve(strict=True)
    _reject_symlink_components(parent)
    _require_trusted_ancestors(parent / ".output-placeholder")
    parent_stat = parent.stat()
    if not parent.is_dir() or (os.name == "posix" and (parent_stat.st_uid != 0 or stat.S_IMODE(parent_stat.st_mode) != 0o700)):
        raise ContractError("output parent is not a directory")
    if path.parent != parent:
        raise ContractError("output parent must not contain symlinks")
    path = parent / path.name
    descriptor, temporary = tempfile.mkstemp(prefix=".egress-evidence.", dir=str(parent))
    temporary_path = pathlib.Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, path, follow_symlinks=False)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def _approved_executable(path_text: str, label: str, executable_kind: str) -> tuple[str, int]:
    path = pathlib.Path(path_text)
    _reject_symlink_components(path)
    _require_trusted_ancestors(path)
    try:
        real_path = pathlib.Path(os.path.realpath(path, strict=True))
    except OSError as exc:
        raise ContractError(f"{label} cannot be resolved") from exc
    allowed = APPROVED_EXECUTABLES.get(executable_kind, frozenset())
    if str(path) != str(real_path) or str(real_path) not in allowed:
        raise ContractError(f"{label} is not an approved fixed executable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(real_path, flags)
    except OSError as exc:
        raise ContractError(f"{label} cannot be opened safely") from exc
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or not os.access(real_path, os.X_OK):
        os.close(descriptor)
        raise ContractError(f"{label} must be an executable regular file")
    if os.name == "posix" and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(descriptor)
        raise ContractError(f"{label} must be root-owned and not group/world writable")
    return str(real_path), descriptor


def _kill_and_reap_process_group(process: subprocess.Popen[bytes]) -> None:
    # The group kill is unconditional once start_new_session Popen succeeds.
    # The direct child may already have exited while a descendant still owns a
    # pipe or remains hung in the same session/process group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    else:
        process.wait()


def _run_bounded_process(command: list[str], executable_fd: int, timeout_seconds: float, maximum: int) -> tuple[int, bytes, bytes]:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            executable=f"/proc/self/fd/{executable_fd}", pass_fds=(executable_fd,),
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContractError(f"read-only command timed out: {command[0]}")
            events = selector.select(remaining)
            if not events and process.poll() is not None:
                break
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    raise ContractError(f"read-only command output is too large: {command[0]}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError(f"read-only command timed out: {command[0]}")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ContractError(f"read-only command timed out: {command[0]}") from exc
    except ContractError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContractError(f"read-only command failed: {command[0]}") from exc
    finally:
        if process is not None:
            _kill_and_reap_process_group(process)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if selector is not None:
            selector.close()
    return return_code, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def run_json(command: list[str], executable_fd: int | None = None) -> Any:
    if not command or not pathlib.Path(command[0]).is_absolute():
        raise ContractError("read-only command must use an approved absolute executable path")
    if executable_fd is None or executable_fd < 0 or sys.platform != "linux":
        raise ContractError("read-only command requires a bound Linux executable descriptor")
    return_code, stdout, _ = _run_bounded_process(command, executable_fd, MAX_SINGLE_CAPTURE_SECONDS, MAX_INPUT)
    if return_code != 0:
        raise ContractError(f"read-only command failed with status {return_code}: {command[0]}")
    try:
        return json.loads(stdout, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"read-only command returned invalid JSON: {command[0]}") from exc


def _proc_starttime(pid: int) -> int:
    if pid <= 0:
        raise ContractError("container PID must be positive")
    raw = _read_proc_file(pathlib.Path(f"/proc/{pid}/stat"), 8192).decode("ascii")
    close = raw.rfind(")")
    fields = raw[close + 2:].split() if close >= 0 else []
    if len(fields) < 20:
        raise ContractError("container process stat is malformed")
    try:
        value = int(fields[19])
    except ValueError as exc:
        raise ContractError("container process starttime is malformed") from exc
    if value <= 0:
        raise ContractError("container process starttime is invalid")
    return value


def _project_nft_expression(expression: Any) -> dict[str, Any]:
    if not isinstance(expression, dict) or len(expression) != 1:
        raise ContractError("managed nft expression is malformed")
    kind, body = next(iter(expression.items()))
    if kind == "counter":
        exact_fields(body, {"packets", "bytes"}, "nft counter")
        integer(body["packets"], "nft packet counter")
        integer(body["bytes"], "nft byte counter")
        return {"counter": {"packets": body["packets"], "bytes": body["bytes"]}}
    if kind in {"accept", "drop"}:
        if body is not None:
            raise ContractError("managed nft verdict is malformed")
        return {kind: None}
    if kind == "jump":
        jump = exact_fields(body, {"target"}, "nft jump")
        return {"jump": {"target": text(jump["target"], "nft jump target", SAFE_NAME)}}
    if kind != "match":
        raise ContractError("managed nft expression kind is prohibited")
    match_value = exact_fields(body, {"op", "left", "right"}, "nft match")
    if match_value["op"] != "==" or not isinstance(match_value["left"], dict):
        raise ContractError("managed nft match operator is invalid")
    left = match_value["left"]
    right = match_value["right"]
    if left in ({"meta": {"key": "nfproto"}}, {"meta": {"key": "l4proto"}}):
        permitted = {"ipv4", "ipv6"} if left["meta"]["key"] == "nfproto" else {"tcp"}
        if right not in permitted:
            raise ContractError("managed nft protocol match is invalid")
    elif left == {"meta": {"key": "iifname"}}:
        text(right, "nft input interface", SAFE_NAME)
    elif left in ({"payload": {"protocol": "ip", "field": "daddr"}}, {"payload": {"protocol": "ip6", "field": "daddr"}}):
        values = right.get("set") if isinstance(right, dict) and set(right) == {"set"} else [right]
        if not isinstance(values, list) or not values:
            raise ContractError("managed nft destination set is invalid")
        for address in values:
            _public_ip(text(address, "nft destination address"))
    elif left == {"payload": {"protocol": "tcp", "field": "dport"}}:
        if right not in {443, 853}:
            raise ContractError("managed nft destination port is invalid")
    else:
        raise ContractError("managed nft match field is prohibited")
    return {"match": {"op": "==", "left": left, "right": right}}


def _project_nft_ruleset(value: Any, family: str, table: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"nftables"} or not isinstance(value["nftables"], list):
        raise ContractError("nft command returned an invalid envelope")
    projected = []
    for entry in value["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            continue
        kind, body = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        if not isinstance(body, dict):
            continue
        belongs = body.get("family") == family and (kind == "table" and body.get("name") == table or body.get("table") == table)
        if not belongs:
            continue
        if kind == "table":
            if not set(body).issubset({"family", "name", "handle"}):
                raise ContractError("managed nft table has unsupported flags")
            projected.append({"table": {key: body[key] for key in ("family", "name", "handle") if key in body}})
        elif kind == "chain":
            allowed = ("family", "table", "name", "handle", "type", "hook", "prio", "policy")
            if not set(body).issubset(allowed):
                raise ContractError("managed nft chain has unsupported fields")
            projected.append({"chain": {key: body[key] for key in allowed if key in body}})
        elif kind == "rule":
            comment = body.get("comment")
            if comment not in {
                "chengwang:v1:entry", "chengwang:v1:allow-dot4", "chengwang:v1:allow-dot6",
                "chengwang:v1:allow-probe4", "chengwang:v1:allow-probe6",
                "chengwang:v1:deny4", "chengwang:v1:deny6",
            }:
                raise ContractError("managed nft table contains an unlabelled rule")
            allowed = ("family", "table", "chain", "handle", "expr", "comment")
            if not set(body).issubset(allowed) or not isinstance(body.get("expr"), list):
                raise ContractError("managed nft rule has unsupported fields")
            projected.append({"rule": {
                **{key: body[key] for key in ("family", "table", "chain", "handle", "comment") if key in body},
                "expr": [_project_nft_expression(expression) for expression in body["expr"]],
            }})
        else:
            raise ContractError("managed nft table contains an unsupported object")
    if not projected:
        raise ContractError("managed nft table is absent")
    encoded = json.dumps({"nftables": projected}, separators=(",", ":")).encode()
    if len(encoded) > MAX_INPUT:
        raise ContractError("projected nft contract exceeds its size limit")
    return {"nftables": projected}


def _project_docker(container_object: dict[str, Any], network_object: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    labels = container_object.get("Config", {}).get("Labels") or {}
    networks = container_object.get("NetworkSettings", {}).get("Networks")
    if not isinstance(labels, dict) or not isinstance(networks, dict) or len(networks) != 1:
        raise ContractError("Docker identity projection input is malformed")
    network_name, attachment = next(iter(networks.items()))
    text(network_name, "Docker network name", SAFE_NAME)
    if not isinstance(attachment, dict):
        raise ContractError("Docker network attachment is malformed")
    network_id = text(attachment.get("NetworkID"), "network id", NETWORK_ID)
    attached = network_object.get("Containers") or {}
    options = network_object.get("Options") or {}
    if not isinstance(attached, dict) or not isinstance(options, dict):
        raise ContractError("Docker network projection input is malformed")
    container_id = text(container_object.get("Id"), "Docker container id", CONTAINER_ID)
    image_id = text(container_object.get("Image"), "Docker image id")
    if not image_id.startswith("sha256:") or not HEX_64.fullmatch(image_id.removeprefix("sha256:")):
        raise ContractError("Docker image id is invalid")
    project_name = text(labels.get("com.docker.compose.project"), "Compose project", SAFE_NAME)
    if labels.get("com.docker.compose.service") != "probe-agent":
        raise ContractError("Compose service identity is invalid")
    if network_object.get("Id") != network_id or network_object.get("Name") != network_name:
        raise ContractError("Docker network identity is inconsistent")
    for attached_id in attached:
        text(attached_id, "attached container id", CONTAINER_ID)
    for field in ("IPAddress", "GlobalIPv6Address"):
        if attachment.get(field, ""):
            try:
                ipaddress.ip_address(attachment[field])
            except ValueError as exc:
                raise ContractError("Docker source address is malformed") from exc
    bridge_name = options.get("com.docker.network.bridge.name") or ("br-" + network_id[:12])
    text(bridge_name, "Docker bridge name", SAFE_NAME)
    container_projection = {
        "id": container_id, "imageId": image_id,
        "running": container_object.get("State", {}).get("Running"),
        "projectName": project_name,
        "serviceName": "probe-agent",
        "networkName": network_name, "networkId": network_id,
        "ipv4Address": attachment.get("IPAddress", ""),
        "ipv6Address": attachment.get("GlobalIPv6Address", ""),
    }
    network_projection = {
        "id": network_object.get("Id"), "name": network_object.get("Name"),
        "internal": network_object.get("Internal"), "attachable": network_object.get("Attachable"),
        "bridgeName": bridge_name,
        "attachedContainerIds": sorted(attached),
    }
    return container_projection, network_projection


def capture_snapshot(container_id: str, output: pathlib.Path, nft_family: str, nft_table: str, docker_bin: str, nft_bin: str, now: int | None = None) -> None:
    text(container_id, "container id", CONTAINER_ID)
    if nft_family != "inet":
        raise ContractError("managed nft family must be inet")
    text(nft_table, "managed nft table", SAFE_NAME)
    if sys.platform != "linux":
        raise ContractError("host capture is supported only on Linux")
    docker, docker_fd = _approved_executable(docker_bin, "Docker executable", "docker")
    try:
        nft, nft_fd = _approved_executable(nft_bin, "nft executable", "nft")
    except Exception:
        os.close(docker_fd)
        raise
    try:
        started = int(time.time()) if now is None else integer(now, "capture start time")
        container = run_json([docker, "--host", "unix:///var/run/docker.sock", "inspect", container_id], docker_fd)
        container_object = _one_inspect(container, "container inspect")
        full_id = text(container_object.get("Id"), "inspected container id", CONTAINER_ID)
        if full_id != container_id:
            raise ContractError("requested and inspected container ids differ")
        networks = container_object.get("NetworkSettings", {}).get("Networks")
        if not isinstance(networks, dict) or len(networks) != 1:
            raise ContractError("container must have exactly one Docker network")
        attachment = next(iter(networks.values()))
        if not isinstance(attachment, dict):
            raise ContractError("container network attachment is malformed")
        network_id = text(attachment.get("NetworkID"), "network id", NETWORK_ID)
        network_raw = run_json([docker, "--host", "unix:///var/run/docker.sock", "network", "inspect", network_id], docker_fd)
        network_object = _one_inspect(network_raw, "network inspect")
        nftables = _project_nft_ruleset(run_json([nft, "--json", "list", "ruleset"], nft_fd), nft_family, nft_table)
    finally:
        os.close(docker_fd)
        os.close(nft_fd)
    state = container_object.get("State")
    if not isinstance(state, dict) or state.get("Running") is not True:
        raise ContractError("capture requires an already-running container")
    pid = integer(state.get("Pid"), "container PID")
    process_started = _proc_starttime(pid)
    sandbox_key = text(container_object.get("NetworkSettings", {}).get("SandboxKey"), "network namespace path")
    sandbox_path = pathlib.Path(sandbox_key)
    sandbox_stat = _fd_stat_path(sandbox_path, False)
    proc_netns_stat = _fd_stat_path(pathlib.Path(f"/proc/{pid}/ns/net"), True)
    if (sandbox_stat.st_dev, sandbox_stat.st_ino) != (proc_netns_stat.st_dev, proc_netns_stat.st_ino):
        raise ContractError("Docker sandbox and container process network namespaces differ")
    if _proc_starttime(pid) != process_started:
        raise ContractError("container process changed during capture")
    boot_id = _read_proc_file(pathlib.Path("/proc/sys/kernel/random/boot_id"), 128).decode("ascii").strip()
    text(boot_id, "boot id", BOOT_ID)
    finished = started if now is not None else int(time.time())
    if finished < started or finished - started > MAX_SINGLE_CAPTURE_SECONDS:
        raise ContractError("capture window is invalid or too long")
    container_projection, network_projection = _project_docker(container_object, network_object)
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "capturedStartedUnix": started,
        "capturedFinishedUnix": finished,
        "bootId": boot_id,
        "netns": {"path": sandbox_key, "device": sandbox_stat.st_dev, "inode": sandbox_stat.st_ino, "pid": pid, "processStartTicks": process_started},
        "container": container_projection,
        "network": network_projection,
        "nftRuleset": nftables,
    }
    atomic_write_new(output, snapshot)


def _one_inspect(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ContractError(f"{label} must contain exactly one object")
    return value[0]


def validate_snapshot(value: Any, label: str) -> dict[str, Any]:
    result = exact_fields(
        value,
        {"schema", "capturedStartedUnix", "capturedFinishedUnix", "bootId", "netns", "container", "network", "nftRuleset"},
        label,
    )
    if result["schema"] != SNAPSHOT_SCHEMA:
        raise ContractError(f"{label} schema is invalid")
    started = integer(result["capturedStartedUnix"], f"{label} capture start time")
    finished = integer(result["capturedFinishedUnix"], f"{label} capture finish time")
    if finished < started or finished - started > MAX_SINGLE_CAPTURE_SECONDS:
        raise ContractError(f"{label} capture window is invalid")
    text(result["bootId"], f"{label} boot id", BOOT_ID)
    netns = exact_fields(result["netns"], {"path", "device", "inode", "pid", "processStartTicks"}, f"{label} network namespace")
    text(netns["path"], f"{label} network namespace path")
    integer(netns["device"], f"{label} network namespace device")
    if integer(netns["inode"], f"{label} network namespace inode") == 0:
        raise ContractError(f"{label} network namespace inode must be non-zero")
    if integer(netns["pid"], f"{label} container PID") == 0 or integer(netns["processStartTicks"], f"{label} process start ticks") == 0:
        raise ContractError(f"{label} process identity is invalid")
    exact_fields(result["container"], {"id", "imageId", "running", "projectName", "serviceName", "networkName", "networkId", "ipv4Address", "ipv6Address"}, f"{label} container projection")
    exact_fields(result["network"], {"id", "name", "internal", "attachable", "bridgeName", "attachedContainerIds"}, f"{label} network projection")
    nft = result["nftRuleset"]
    if not isinstance(nft, dict) or set(nft) != {"nftables"} or not isinstance(nft["nftables"], list):
        raise ContractError(f"{label} nft ruleset envelope is invalid")
    return result


def validate_plan(value: Any, raw: bytes, catalog_sha: str, policy: dict[str, Any], now: int, candidate_root: str, project: str, image_id: str) -> dict[str, Any]:
    plan = exact_fields(
        value,
        {
            "schema", "revision", "approval", "candidateRoot", "projectName", "imageId",
            "catalogSha256", "catalogDigest", "validUntilUnix", "resolver",
            "nft", "probeResolutions",
        },
        "egress plan",
    )
    if plan["schema"] != PLAN_SCHEMA:
        raise ContractError("egress plan schema is invalid")
    if plan["candidateRoot"] != candidate_root or plan["projectName"] != project or plan["imageId"] != image_id:
        raise ContractError("egress plan candidate identity mismatch")
    text(plan["revision"], "egress plan revision", SAFE_NAME)
    approval = exact_fields(plan["approval"], {"status", "owner", "approvedUnix"}, "plan approval")
    if approval["status"] != "approved":
        raise ContractError("egress plan is not approved")
    text(approval["owner"], "plan approval owner", SAFE_NAME)
    approved = integer(approval["approvedUnix"], "plan approval time")
    valid_until = integer(plan["validUntilUnix"], "plan expiry")
    if approved > now or valid_until <= now or valid_until - now > MAX_EVIDENCE_LIFETIME:
        raise ContractError("egress plan approval or expiry is invalid")
    if text(plan["catalogSha256"], "plan catalog SHA-256", HEX_64) != catalog_sha:
        raise ContractError("egress plan catalog SHA-256 mismatch")

    resolver = exact_fields(plan["resolver"], {"endpoint", "serverName"}, "resolver contract")
    endpoint = _public_endpoint(text(resolver["endpoint"], "resolver endpoint"), 853)
    text(resolver["serverName"], "resolver server name", SAFE_NAME)

    nft = exact_fields(
        plan["nft"],
        {"family", "table", "entryChain", "entryPriority", "policyChain", "bridgeName"},
        "nft contract",
    )
    if nft["family"] != "inet":
        raise ContractError("nft family must be inet")
    for field in ("table", "entryChain", "policyChain", "bridgeName"):
        text(nft[field], f"nft {field}", SAFE_NAME)
    if not isinstance(nft["entryPriority"], int) or isinstance(nft["entryPriority"], bool) or nft["entryPriority"] > -1 or nft["entryPriority"] < -300:
        raise ContractError("nft entry priority must be an integer from -300 through -1")
    if nft["entryChain"] == nft["policyChain"]:
        raise ContractError("nft entry and policy chains must differ")

    probes, catalog_digest = _catalog_probes(policy.pop("__catalog"))
    if plan["catalogDigest"] != catalog_digest:
        raise ContractError("egress plan semantic catalog digest mismatch")
    resolutions = plan["probeResolutions"]
    if not isinstance(resolutions, list) or len(resolutions) != len(probes):
        raise ContractError("probe resolutions must cover every catalog probe exactly once")
    expected_ids = set(probes)
    seen: set[str] = set()
    addresses: list[str] = []
    for index, resolution_value in enumerate(resolutions):
        resolution = exact_fields(
            resolution_value,
            {"probeId", "queryName", "cnameChain", "addresses", "resolvedUnix", "expiresUnix"},
            f"probe resolution {index}",
        )
        probe_id = text(resolution["probeId"], f"probe resolution {index} id", SAFE_NAME)
        if probe_id not in expected_ids or probe_id in seen:
            raise ContractError("probe resolution id is unknown or duplicated")
        seen.add(probe_id)
        if resolution["queryName"] != probes[probe_id]["host"]:
            raise ContractError("probe resolution query name does not match the catalog")
        chain = resolution["cnameChain"]
        if not isinstance(chain, list) or not chain or chain[0] != resolution["queryName"]:
            raise ContractError("probe resolution CNAME chain is incomplete")
        for name in chain:
            text(name, "CNAME value", SAFE_NAME)
            if name != name.lower():
                raise ContractError("probe resolution CNAME values must be canonical lowercase")
        if len(chain) != len(set(chain)):
            raise ContractError("probe resolution CNAME chain contains a duplicate or loop")
        if any(name not in probes[probe_id]["allowedNames"] for name in chain[1:]):
            raise ContractError("probe resolution CNAME chain leaves the catalog allowlist")
        resolved = integer(resolution["resolvedUnix"], "probe resolution time")
        expires = integer(resolution["expiresUnix"], "probe resolution expiry")
        if resolved > now or expires <= now or expires > valid_until or expires - resolved < 30 or expires - resolved > MAX_EVIDENCE_LIFETIME:
            raise ContractError("probe resolution is stale, future-dated, or exceeds plan expiry")
        if not isinstance(resolution["addresses"], list) or not resolution["addresses"]:
            raise ContractError("probe resolution has no addresses")
        resolution_addresses = []
        for address in resolution["addresses"]:
            resolution_addresses.append(_public_ip(text(address, "probe address")))
        if len(resolution_addresses) != len(set(resolution_addresses)):
            raise ContractError("one probe resolution contains duplicate addresses")
        addresses.extend(resolution_addresses)
    if seen != expected_ids:
        raise ContractError("probe resolution coverage is incomplete")
    addresses = sorted(set(addresses), key=lambda item: ipaddress.ip_address(item).packed)

    evidence_id = "evidence:" + sha256(raw)
    enforcement = policy.get("enforcement")
    if not isinstance(enforcement, dict) or enforcement.get("runtimeEvidence") != evidence_id:
        raise ContractError("policy runtimeEvidence does not bind the exact egress plan bytes")
    _validate_policy_destinations(policy, endpoint, resolver["serverName"], expected_ids, catalog_digest, now)
    return {"plan": plan, "evidenceId": evidence_id, "dotAddress": str(endpoint), "probeAddresses": addresses}


def _catalog_probes(catalog: Any) -> tuple[dict[str, dict[str, Any]], str]:
    exact_fields(catalog, {"schema", "revision", "agent", "paths", "probes"}, "catalog")
    if catalog.get("schema") != "chengwang.probe-catalog/v1":
        raise ContractError("catalog schema is invalid")
    text(catalog.get("revision"), "catalog revision", SAFE_NAME)
    agent = exact_fields(catalog.get("agent"), {"id", "independence", "advisoryOnly"}, "catalog agent")
    text(agent["id"], "catalog agent id", SAFE_NAME)
    if agent["independence"] != "P1" or agent["advisoryOnly"] is not True:
        raise ContractError("catalog agent must be advisory-only P1")
    paths = catalog.get("paths")
    if not isinstance(paths, list) or not paths:
        raise ContractError("catalog paths are missing")
    canonical_paths = []
    path_ids: set[str] = set()
    for item in paths:
        path = exact_fields(item, {"id", "kind"}, "catalog path")
        path_id = text(path["id"], "catalog path id", SAFE_NAME)
        if path_id in path_ids or path["kind"] != "direct":
            raise ContractError("catalog path is duplicated or not direct")
        path_ids.add(path_id)
        canonical_paths.append({"id": path_id, "kind": "direct"})
    probes = catalog.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ContractError("catalog probes are missing")
    result: dict[str, dict[str, Any]] = {}
    canonical_probes = []
    for item in probes:
        required = {
            "id", "pathId", "kind", "host", "port", "requestPath", "method", "expectedStatus",
            "intervalSeconds", "timeoutSeconds", "ttlSeconds", "maxBodyBytes",
        }
        if not isinstance(item, dict) or not required.issubset(item) or not set(item).issubset(required | {"allowedCNAMEs", "requiredMarker"}):
            raise ContractError("catalog probe field set is invalid")
        probe_id = text(item.get("id"), "catalog probe id", SAFE_NAME)
        host = text(item.get("host"), "catalog probe host", SAFE_NAME)
        path_id = text(item.get("pathId"), "catalog probe path id", SAFE_NAME)
        if item.get("kind") != "https" or item.get("port") != 443 or probe_id in result or path_id not in path_ids:
            raise ContractError("catalog probe must be unique HTTPS on TCP/443")
        statuses = item.get("expectedStatus")
        cname_values = item.get("allowedCNAMEs", [])
        if not isinstance(statuses, list) or not statuses or any(not isinstance(status, int) or isinstance(status, bool) for status in statuses):
            raise ContractError("catalog expectedStatus is invalid")
        if not isinstance(cname_values, list) or any(not isinstance(name, str) for name in cname_values):
            raise ContractError("catalog allowedCNAMEs is invalid")
        result[probe_id] = {"host": host, "allowedNames": {host, *cname_values}}
        canonical_probe = {
            "id": probe_id,
            "pathId": path_id,
            "kind": "https",
            "host": host,
        }
        if cname_values:
            canonical_probe["allowedCNAMEs"] = sorted(cname_values)
        canonical_probe.update({
            "port": 443,
            "requestPath": item["requestPath"],
            "method": item["method"],
            "expectedStatus": sorted(statuses),
        })
        if item.get("requiredMarker", ""):
            canonical_probe["requiredMarker"] = item["requiredMarker"]
        canonical_probe.update({
            "intervalSeconds": item["intervalSeconds"],
            "timeoutSeconds": item["timeoutSeconds"],
            "ttlSeconds": item["ttlSeconds"],
            "maxBodyBytes": item["maxBodyBytes"],
        })
        canonical_probes.append(canonical_probe)
    canonical = {
        "schema": catalog["schema"],
        "revision": catalog["revision"],
        "agent": {"id": agent["id"], "independence": "P1", "advisoryOnly": True},
        "paths": sorted(canonical_paths, key=lambda item: item["id"]),
        "probes": sorted(canonical_probes, key=lambda item: item["id"]),
    }
    encoded = json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8")
    return result, "sha256:" + sha256(encoded)


def _validate_policy_destinations(
    policy: dict[str, Any], endpoint: ipaddress.IPv4Address | ipaddress.IPv6Address,
    server_name: str, probe_ids: set[str], catalog_sha: str, now: int,
) -> None:
    if not isinstance(policy, dict) or not {"schema", "revision", "approval", "enforcement", "allowedDestinations"}.issubset(policy) or not set(policy).issubset({"schema", "revision", "approval", "enforcement", "allowedDestinations", "notes"}):
        raise ContractError("policy field set is invalid")
    if policy.get("schema") != "chengwang.probe-egress-policy/v1":
        raise ContractError("policy schema is invalid")
    text(policy.get("revision"), "policy revision", SAFE_NAME)
    approval = policy.get("approval")
    enforcement = policy.get("enforcement")
    exact_fields(approval, {"status", "owner", "approvedAt"}, "policy approval")
    if approval.get("status") != "approved":
        raise ContractError("policy is not approved")
    text(approval.get("owner"), "policy approval owner", SAFE_NAME)
    approved_at = text(approval.get("approvedAt"), "policy approval time")
    try:
        parsed_approval = dt.datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("policy approval time is invalid") from exc
    if parsed_approval.tzinfo is None:
        raise ContractError("policy approval time must include a timezone")
    if parsed_approval.timestamp() > now:
        raise ContractError("policy approval time is in the future")
    exact_fields(enforcement, {"state", "mode", "runtimeEvidence"}, "policy enforcement")
    if enforcement.get("state") != "enforced" or enforcement.get("mode") != "default-deny":
        raise ContractError("policy does not require default-deny enforcement")
    destinations = policy.get("allowedDestinations")
    if not isinstance(destinations, list) or len(destinations) != len(probe_ids) + 1:
        raise ContractError("policy destinations do not cover the catalog")
    fixed = 0
    seen: set[str] = set()
    for destination in destinations:
        if not isinstance(destination, dict) or destination.get("schema") != "chengwang.probe-egress-destination/v1":
            raise ContractError("policy destination schema is invalid")
        if destination.get("kind") == "fixed-dot":
            exact_fields(destination, {"schema", "kind", "endpoint", "serverName"}, "fixed DoT destination")
            endpoint_text = f"[{endpoint}]:853" if endpoint.version == 6 else f"{endpoint}:853"
            if destination.get("endpoint") != endpoint_text or destination.get("serverName") != server_name:
                raise ContractError("policy fixed DoT destination differs from the plan")
            fixed += 1
        elif destination.get("kind") == "catalog-probe":
            exact_fields(destination, {"schema", "kind", "probeId", "catalogDigest"}, "catalog probe destination")
            probe_id = destination.get("probeId")
            if probe_id not in probe_ids or destination.get("catalogDigest") != catalog_sha or probe_id in seen:
                raise ContractError("policy catalog destination is invalid or duplicated")
            seen.add(probe_id)
        else:
            raise ContractError("policy destination kind is invalid")
    if fixed != 1 or seen != probe_ids:
        raise ContractError("policy destinations are incomplete")


def _public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ContractError("destination address is invalid") from exc
    if (
        not address.is_global or address.is_unspecified or address.is_loopback or address.is_private
        or address.is_link_local or address.is_multicast or address in PROHIBITED_METADATA
        or any(address in network for network in PROHIBITED_NETWORKS if network.version == address.version)
        or (address.version == 6 and address.ipv4_mapped is not None)
    ):
        raise ContractError("destination address is not globally routable")
    return str(address)


def _public_endpoint(value: str, port: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        host, separator, port_text = value.rpartition(":")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not separator or int(port_text) != port:
            raise ValueError
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError) as exc:
        raise ContractError(f"endpoint must be a public IP on TCP/{port}") from exc
    if _public_ip(str(address)) != str(address):
        raise ContractError(f"endpoint must be a public IP on TCP/{port}")
    canonical = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    if value != canonical:
        raise ContractError(f"endpoint must use canonical public IP syntax on TCP/{port}")
    return address


def _normalized_ruleset(value: dict[str, Any]) -> Any:
    def normalize(item: Any) -> Any:
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, dict):
            if set(item) == {"metainfo"}:
                return None
            result = {}
            for key, child in item.items():
                if key in {"packets", "bytes"} and set(item).issuperset({"packets", "bytes"}):
                    continue
                result[key] = normalize(child)
            return result
        return item
    nftables = [item for item in (normalize(entry) for entry in value["nftables"]) if item is not None]
    return {"nftables": nftables}


def _inspect_identity(snapshot: dict[str, Any], project: str, container_id: str) -> tuple[dict[str, Any], dict[str, Any], str, str, dict[str, Any], list[str]]:
    container = snapshot["container"]
    if container.get("id") != container_id:
        raise ContractError("container inspect identity mismatch")
    if container.get("projectName") != project or container.get("serviceName") != "probe-agent":
        raise ContractError("container Compose identity mismatch")
    if container.get("running") is not True:
        raise ContractError("counter capture requires an already-running probe container")
    network_name = text(container.get("networkName"), "attached network name", SAFE_NAME)
    network_id = text(container.get("networkId"), "attached network id", NETWORK_ID)
    source_addresses = []
    for field in ("ipv4Address", "ipv6Address"):
        address = container.get(field, "")
        if address:
            try:
                source_addresses.append(str(ipaddress.ip_address(address)))
            except ValueError as exc:
                raise ContractError("container source address is malformed") from exc
    if not source_addresses or len(source_addresses) != len(set(source_addresses)):
        raise ContractError("container source addresses are absent or duplicated")
    network = snapshot["network"]
    if network.get("id") != network_id or network.get("name") != network_name:
        raise ContractError("network inspect identity mismatch")
    if network.get("internal") is not False or network.get("attachable") is not False:
        raise ContractError("runtime egress proof requires a non-internal, non-attachable network")
    containers = network.get("attachedContainerIds")
    if not isinstance(containers, list) or containers != [container_id]:
        raise ContractError("candidate container must be the network's only attached container")
    return container, network, network_name, network_id, snapshot["netns"], source_addresses


def _rule_entries(ruleset: dict[str, Any], family: str, table: str) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, dict[str, Any]] = {}
    table_count = 0
    for entry in ruleset["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            continue
        if "table" in entry:
            value = entry["table"]
            if isinstance(value, dict) and value.get("family") == family and value.get("name") == table:
                table_count += 1
        elif "chain" in entry:
            value = entry["chain"]
            if isinstance(value, dict) and value.get("family") == family and value.get("table") == table:
                name = text(value.get("name"), "nft chain name", SAFE_NAME)
                if name in chains:
                    raise ContractError("duplicate nft chain")
                chains[name] = value
        elif "rule" in entry:
            value = entry["rule"]
            if isinstance(value, dict) and value.get("family") == family and value.get("table") == table:
                comment = text(value.get("comment"), "managed nft rule comment", SAFE_NAME)
                if comment in rules:
                    raise ContractError("duplicate managed nft rule comment")
                rules[comment] = value
        elif any(isinstance(value, dict) and value.get("family") == family and value.get("table") == table for value in entry.values()):
            raise ContractError("managed nft table contains an unsupported object")
    if table_count != 1:
        raise ContractError("managed nft table is absent")
    return chains, rules


def _counter(rule: dict[str, Any]) -> int:
    values = [expression["counter"] for expression in rule.get("expr", []) if isinstance(expression, dict) and "counter" in expression]
    if len(values) != 1 or not isinstance(values[0], dict):
        raise ContractError("managed nft rule must contain exactly one counter")
    return integer(values[0].get("packets"), "nft packet counter")


def _match(expression: Any, left: dict[str, Any], right: Any) -> bool:
    return isinstance(expression, dict) and expression.get("match") == {"op": "==", "left": left, "right": right}


def _require_rule(rule: dict[str, Any], expected: list[tuple[str, Any]], verdict: str) -> int:
    expressions = rule.get("expr")
    if not isinstance(expressions, list) or len(expressions) != len(expected) + 2:
        raise ContractError(f"managed nft rule expression set is invalid: {rule.get('comment')}")
    for expression, (kind, value) in zip(expressions, expected):
        if kind == "nfproto":
            left = {"meta": {"key": "nfproto"}}
        elif kind == "l4proto":
            left = {"meta": {"key": "l4proto"}}
        elif kind == "iifname":
            left = {"meta": {"key": "iifname"}}
        elif kind == "daddr4":
            left = {"payload": {"protocol": "ip", "field": "daddr"}}
        elif kind == "daddr6":
            left = {"payload": {"protocol": "ip6", "field": "daddr"}}
        elif kind == "dport":
            left = {"payload": {"protocol": "tcp", "field": "dport"}}
        else:
            raise AssertionError(kind)
        if not _match(expression, left, value):
            raise ContractError(f"managed nft rule match is invalid: {rule.get('comment')}")
    if not isinstance(expressions[-2], dict) or set(expressions[-2]) != {"counter"}:
        raise ContractError(f"managed nft rule counter position is invalid: {rule.get('comment')}")
    if expressions[-1] != {verdict: None}:
        raise ContractError(f"managed nft rule verdict is invalid: {rule.get('comment')}")
    return _counter(rule)


def _address_match(addresses: list[str]) -> str | dict[str, list[str]]:
    ordered = sorted(addresses, key=lambda item: ipaddress.ip_address(item).packed)
    return ordered[0] if len(ordered) == 1 else {"set": ordered}


def validate_ruleset(snapshot: dict[str, Any], plan: dict[str, Any]) -> dict[str, int]:
    nft = plan["plan"]["nft"]
    chains, rules = _rule_entries(snapshot["nftRuleset"], nft["family"], nft["table"])
    if set(chains) != {nft["entryChain"], nft["policyChain"]}:
        raise ContractError("managed nft table must contain exactly the declared chains")
    entry_chain = chains[nft["entryChain"]]
    if entry_chain.get("type") != "filter" or entry_chain.get("hook") != "forward" or entry_chain.get("policy") != "accept" or entry_chain.get("prio") != nft["entryPriority"]:
        raise ContractError("managed nft entry chain contract is invalid")
    policy_chain = chains[nft["policyChain"]]
    if any(field in policy_chain for field in ("hook", "policy", "type")):
        raise ContractError("managed nft policy chain must be a regular chain")

    expected_comments = {"chengwang:v1:entry", "chengwang:v1:deny4", "chengwang:v1:deny6"}
    dot4 = [plan["dotAddress"]] if ipaddress.ip_address(plan["dotAddress"]).version == 4 else []
    dot6 = [plan["dotAddress"]] if ipaddress.ip_address(plan["dotAddress"]).version == 6 else []
    probes4 = [item for item in plan["probeAddresses"] if ipaddress.ip_address(item).version == 4]
    probes6 = [item for item in plan["probeAddresses"] if ipaddress.ip_address(item).version == 6]
    if dot4:
        expected_comments.add("chengwang:v1:allow-dot4")
    if dot6:
        expected_comments.add("chengwang:v1:allow-dot6")
    if probes4:
        expected_comments.add("chengwang:v1:allow-probe4")
    if probes6:
        expected_comments.add("chengwang:v1:allow-probe6")
    if set(rules) != expected_comments:
        raise ContractError("managed nft rule comments are incomplete or contain an undeclared rule")
    if any(rule.get("chain") != nft["policyChain"] for comment, rule in rules.items() if comment != "chengwang:v1:entry"):
        raise ContractError("managed nft policy rule is in the wrong chain")

    entry = rules["chengwang:v1:entry"]
    if entry.get("chain") != nft["entryChain"]:
        raise ContractError("managed nft entry rule is in the wrong chain")
    entry_expr = entry.get("expr")
    if not isinstance(entry_expr, list) or len(entry_expr) != 3 or not _match(entry_expr[0], {"meta": {"key": "iifname"}}, nft["bridgeName"]):
        raise ContractError("managed nft entry selector is invalid")
    if not isinstance(entry_expr[1], dict) or set(entry_expr[1]) != {"counter"} or entry_expr[2] != {"jump": {"target": nft["policyChain"]}}:
        raise ContractError("managed nft entry jump is invalid")

    counters: dict[str, int] = {}
    if dot4:
        counters["dot4"] = _require_rule(rules["chengwang:v1:allow-dot4"], [("nfproto", "ipv4"), ("daddr4", _address_match(dot4)), ("l4proto", "tcp"), ("dport", 853)], "accept")
    if dot6:
        counters["dot6"] = _require_rule(rules["chengwang:v1:allow-dot6"], [("nfproto", "ipv6"), ("daddr6", _address_match(dot6)), ("l4proto", "tcp"), ("dport", 853)], "accept")
    if probes4:
        counters["probe4"] = _require_rule(rules["chengwang:v1:allow-probe4"], [("nfproto", "ipv4"), ("daddr4", _address_match(probes4)), ("l4proto", "tcp"), ("dport", 443)], "accept")
    if probes6:
        counters["probe6"] = _require_rule(rules["chengwang:v1:allow-probe6"], [("nfproto", "ipv6"), ("daddr6", _address_match(probes6)), ("l4proto", "tcp"), ("dport", 443)], "accept")
    counters["deny4"] = _require_rule(rules["chengwang:v1:deny4"], [("nfproto", "ipv4")], "drop")
    counters["deny6"] = _require_rule(rules["chengwang:v1:deny6"], [("nfproto", "ipv6")], "drop")

    order = [rule["rule"].get("comment") for rule in snapshot["nftRuleset"]["nftables"] if isinstance(rule, dict) and isinstance(rule.get("rule"), dict) and rule["rule"].get("family") == nft["family"] and rule["rule"].get("table") == nft["table"] and rule["rule"].get("chain") == nft["policyChain"]]
    if order[-2:] != ["chengwang:v1:deny4", "chengwang:v1:deny6"]:
        raise ContractError("IPv4 and IPv6 terminal deny rules must be last")
    return counters


def verify(
    before_path: pathlib.Path, after_path: pathlib.Path, plan_path: pathlib.Path,
    catalog_path: pathlib.Path, policy_path: pathlib.Path, compose_path: pathlib.Path,
    candidate_root: str, project: str, image_id: str, container_id: str,
    output: pathlib.Path, now: int | None = None,
) -> None:
    current = int(time.time()) if now is None else integer(now, "current time")
    before_value, _ = load_json(before_path)
    after_value, _ = load_json(after_path)
    plan_value, plan_raw = load_json(plan_path, 256 * 1024)
    catalog, catalog_raw = load_json(catalog_path, 1024 * 1024)
    policy, policy_raw = load_json(policy_path, 256 * 1024)
    compose_raw = secure_read(compose_path, 1024 * 1024)
    if not pathlib.PurePosixPath(candidate_root).is_absolute() or candidate_root != candidate_root.strip():
        raise ContractError("candidate root must be a trimmed absolute POSIX path")
    if os.name == "posix":
        candidate_path = _reject_symlink_components(pathlib.Path(candidate_root))
        candidate_stat = candidate_path.stat()
        if not candidate_path.is_dir() or candidate_stat.st_uid != 0 or stat.S_IMODE(candidate_stat.st_mode) != 0o700:
            raise ContractError("candidate root must be a root-owned mode-0700 directory")
    text(project, "project name", SAFE_NAME)
    if not image_id.startswith("sha256:") or not HEX_64.fullmatch(image_id.removeprefix("sha256:")):
        raise ContractError("image id is invalid")
    text(container_id, "container id", CONTAINER_ID)
    if not isinstance(policy, dict):
        raise ContractError("policy root must be an object")
    policy["__catalog"] = catalog

    before = validate_snapshot(before_value, "before snapshot")
    after = validate_snapshot(after_value, "after snapshot")
    if before["bootId"] != after["bootId"]:
        raise ContractError("snapshots span different host boots")
    if before["capturedFinishedUnix"] >= after["capturedStartedUnix"] or after["capturedFinishedUnix"] - before["capturedStartedUnix"] > MAX_CAPTURE_GAP:
        raise ContractError("snapshot order or capture gap is invalid")
    if after["capturedFinishedUnix"] > current + 5 or current - after["capturedFinishedUnix"] > MAX_EVIDENCE_LIFETIME:
        raise ContractError("after snapshot is stale or future-dated")

    before_identity = _inspect_identity(before, project, container_id)
    after_identity = _inspect_identity(after, project, container_id)
    if before_identity[2:] != after_identity[2:]:
        raise ContractError("container network identity changed during capture")
    if after_identity[0].get("imageId") != image_id or before_identity[0].get("imageId") != image_id:
        raise ContractError("container image identity mismatch")

    plan = validate_plan(plan_value, plan_raw, sha256(catalog_raw), policy, current, candidate_root, project, image_id)
    expected_bridge = plan["plan"]["nft"]["bridgeName"]
    actual_bridge = after_identity[1].get("bridgeName")
    if actual_bridge != expected_bridge:
        raise ContractError("Docker bridge identity does not match the nft plan")

    before_normalized = _normalized_ruleset(before["nftRuleset"])
    after_normalized = _normalized_ruleset(after["nftRuleset"])
    if before_normalized != after_normalized:
        raise ContractError("nft ruleset structure changed during capture")
    before_counters = validate_ruleset(before, plan)
    after_counters = validate_ruleset(after, plan)
    for counter_name, before_value in before_counters.items():
        if after_counters.get(counter_name, -1) <= before_value:
            raise ContractError(f"managed nft counter did not increase: {counter_name}")
    resolver_before = before_counters.get("dot4", 0) + before_counters.get("dot6", 0)
    resolver_after = after_counters.get("dot4", 0) + after_counters.get("dot6", 0)
    probe_before = before_counters.get("probe4", 0) + before_counters.get("probe6", 0)
    probe_after = after_counters.get("probe4", 0) + after_counters.get("probe6", 0)
    deny_before = before_counters["deny4"] + before_counters["deny6"]
    deny_after = after_counters["deny4"] + after_counters["deny6"]
    # The current start gate insists that Docker Network.Internal is true.  A
    # successful outbound counter capture necessarily uses a routable network.
    # Emitting its accepted schema here would turn contradictory contracts into
    # a false green result, so this candidate reports the verified facts and
    # remains blocked until the integration gate is revised and reviewed.
    report = {
        "schema": REPORT_SCHEMA,
        "status": "BLOCKED",
        "reason": "INTEGRATION_CONTRACTS_INCOMPLETE",
        "candidateEvidenceSchema": EVIDENCE_SCHEMA,
        "evidenceId": plan["evidenceId"],
        "capturedUnix": after["capturedFinishedUnix"],
        "candidateRoot": candidate_root,
        "projectName": project,
        "imageId": image_id,
        "composeSha256": sha256(compose_raw),
        "catalogSha256": sha256(catalog_raw),
        "policySha256": sha256(policy_raw),
        "containerId": container_id,
        "networkName": after_identity[2],
        "networkId": after_identity[3],
        "networkNamespace": after_identity[4],
        "sourceAddresses": after_identity[5],
        "rulesetSha256": canonical_sha256(after_normalized),
        "bootId": after["bootId"],
        "collector": COLLECTOR,
        "firewallScope": FIREWALL_SCOPE,
        "counters": {
            "resolverAllowedBefore": resolver_before,
            "resolverAllowedAfter": resolver_after,
            "canaryAllowedBefore": probe_before,
            "canaryAllowedAfter": probe_after,
            "deniedBefore": deny_before,
            "deniedAfter": deny_after,
        },
        "blockers": [
            "current start-verify requires Docker Network.Internal=true",
            "validated TCP/853 and TCP/443 egress requires a routable Docker network",
            "observed counter deltas are not yet bound to cryptographically unique test vectors",
            "shared destination-set counters do not prove each individual probe IP independently",
            "first-start evidence still requires an independently controlled test namespace or signed verifier",
            "Compose bytes are digest-bound but this candidate does not independently parse Compose semantics",
            "Python policy/catalog validation must be replaced by the shared Go validator before acceptance",
            "the aggregate effect of unrelated host nft base chains is not yet proven",
            "no accepted start evidence is emitted until those contracts are reconciled and independently reviewed",
        ],
    }
    atomic_write_new(output, report)
    raise SystemExit(78)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    capture = subcommands.add_parser("capture", help="capture one read-only host snapshot")
    capture.add_argument("--container-id", required=True)
    capture.add_argument("--nft-family", required=True, choices=("inet",))
    capture.add_argument("--nft-table", required=True)
    capture.add_argument("--docker-bin", required=True)
    capture.add_argument("--nft-bin", required=True)
    capture.add_argument("--output", required=True, type=pathlib.Path)
    verify_command = subcommands.add_parser("verify", help="validate two snapshots and emit a BLOCKED report")
    for name in ("before", "after", "plan", "catalog", "policy", "compose"):
        verify_command.add_argument(f"--{name}", required=True, type=pathlib.Path)
    verify_command.add_argument("--candidate-root", required=True)
    verify_command.add_argument("--project", required=True)
    verify_command.add_argument("--image-id", required=True)
    verify_command.add_argument("--container-id", required=True)
    verify_command.add_argument("--output", required=True, type=pathlib.Path)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "capture":
            capture_snapshot(arguments.container_id, arguments.output, arguments.nft_family, arguments.nft_table, arguments.docker_bin, arguments.nft_bin)
            return 0
        verify(
            arguments.before, arguments.after, arguments.plan, arguments.catalog, arguments.policy,
            arguments.compose, arguments.candidate_root, arguments.project, arguments.image_id,
            arguments.container_id, arguments.output,
        )
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
