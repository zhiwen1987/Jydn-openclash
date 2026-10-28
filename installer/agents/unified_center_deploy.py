"""Guarded, single-service deployment for the unified Clash Center image.

The agent is intentionally stdlib-only.  It keeps private snapshots on the
target host, emits only controlled reason codes, and never reads router state.
Actions are supplied in a JSON request: ``prepare``, ``apply``, ``verify``,
``accept``, ``rollback`` or ``guard``.
"""
from __future__ import annotations

import contextlib
try:
    import fcntl
except ImportError:  # Local Windows unit tests only; deployment requires Linux/root.
    class _FcntlForTests:
        LOCK_EX = LOCK_NB = 0

        @staticmethod
        def flock(_file, _flags):
            return None

    fcntl = _FcntlForTests()
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request


BASE_IMAGE_ID = "sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2"
DEFAULT_STATE_DIR = Path("/opt/clash-center-ui")
DEFAULT_COMPOSE = Path("/root/dpanel/compose/lan-center/docker-compose.yml")
LEGACY_STATE = Path("/opt/clash-stack/production/state.json")
DEFAULT_CONTAINER = "clash-center"
MANAGED_CODE_TARGETS = {
    "/node-capability.py", "/subscription-controller.py", "/healthcheck.sh"
}
PROTECTED_IMAGE_TARGETS = MANAGED_CODE_TARGETS | {
    "/subscription_impl.py", "/unified-center", "/local-subscription"
}
OVERLAY_DIRS = ("node-health/code", "subscription-usage/code")
DNS_FILE_TARGET = "/etc/coredns/Corefile"
DNS_DIRECTORY_TARGET = "/etc/coredns"
DNS_MANAGED_RELATIVE = Path("dns-management/coredns")
KUMA_CONTAINER_PORT = "3001/tcp"
KUMA_HOST_PORT = "3101"
MANAGED_ENV_KEYS = {
    "CENTER_UI_ENABLED", "ADMISSION_CORE", "ADMISSION_CORE_PIN", "ADMISSION_NATIVE_SSH",
}


def check(value: object, code: str) -> None:
    if not value:
        raise RuntimeError(code)


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def secure_mode(fd: int, path: str, mode: int) -> None:
    if hasattr(os, "fchmod"):
        os.fchmod(fd, mode)
    else:  # Windows unit-test compatibility; deployment is Linux-only.
        os.chmod(path, mode)


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".unified-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            secure_mode(stream.fileno(), temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def encoded_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_bytes(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".unified-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            secure_mode(stream.fileno(), temporary, mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def fsync_path(path: Path) -> None:
    """Durably persist a regular file or directory on the Linux target."""
    if os.name == "nt":  # Windows unit tests; production deployment is Linux-only.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) if path.is_dir() else os.O_RDONLY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Runner:
    def run(self, args: list[str], timeout: int = 60, data: bytes | None = None) -> bytes:
        try:
            result = subprocess.run(
                args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("command_timeout:" + Path(args[0]).name) from None
        if result.returncode:
            raise RuntimeError("command_failed:" + Path(args[0]).name + ":" + str(result.returncode))
        return result.stdout


RUNNER = Runner()


def inspect_object(kind: str, name: str) -> dict:
    output = RUNNER.run(["docker", kind, "inspect", name], timeout=30)
    value = json.loads(output)
    check(isinstance(value, list) and len(value) == 1, "docker_inspect_shape_invalid")
    return value[0]


def validate_image_lineage(image: dict, base_image: dict, manifest: dict) -> None:
    check(base_image.get("Id") == BASE_IMAGE_ID, "audited_base_image_identity_mismatch")
    check(manifest.get("base_image_id") == BASE_IMAGE_ID, "base_image_identity_invalid")
    labels = image.get("Config", {}).get("Labels", {}) or {}
    check(labels.get("io.jydn.clash-center.base-image") == BASE_IMAGE_ID, "new_image_base_label_mismatch")
    check(labels.get("io.jydn.clash-center.build-method") == "docker-build-offline-increment", "new_image_build_method_invalid")
    if manifest.get("runtime_code_policy") == "image_only":
        check(labels.get("io.jydn.clash-center.runtime-code-policy") == "image-only",
              "new_image_runtime_code_label_invalid")
        check(labels.get("io.jydn.clash-center.version") == manifest.get("version"),
              "new_image_version_label_invalid")
    base_rootfs = base_image.get("RootFS", {})
    image_rootfs = image.get("RootFS", {})
    check(base_rootfs.get("Type") == "layers" and image_rootfs.get("Type") == "layers", "image_rootfs_type_invalid")
    base_layers = base_rootfs.get("Layers")
    image_layers = image_rootfs.get("Layers")
    check(isinstance(base_layers, list) and base_layers, "audited_base_rootfs_layers_missing")
    check(isinstance(image_layers, list) and len(image_layers) > len(base_layers), "new_image_rootfs_layers_missing")
    check(image_layers[:len(base_layers)] == base_layers, "new_image_base_rootfs_prefix_mismatch")


def container_shape(value: dict) -> dict:
    return {
        "id": value.get("Id"),
        "image": value.get("Image"),
        "running": value.get("State", {}).get("Running"),
        "started_at": value.get("State", {}).get("StartedAt"),
        "restart_count": value.get("RestartCount"),
    }


def all_container_shapes() -> dict[str, dict]:
    ids = RUNNER.run(["docker", "ps", "-aq"], timeout=30).decode().split()
    if not ids:
        return {}
    values = json.loads(RUNNER.run(["docker", "inspect", *ids], timeout=60))
    return {item["Name"].lstrip("/"): container_shape(item) for item in values}


def compose_config(path: Path) -> dict:
    return json.loads(RUNNER.run(
        ["docker", "compose", "-f", str(path), "config", "--format", "json"], timeout=45
    ))


def compose_service(config: dict, service: str, container: str) -> dict:
    services = config.get("services", {})
    check(service in services, "compose_service_missing")
    selected = services[service]
    check(selected.get("container_name", container) == container, "compose_container_name_mismatch")
    collisions = [name for name, value in services.items() if value.get("container_name") == container]
    check(collisions in ([], [service]), "compose_container_ambiguous")
    return selected


def parse_short_mount(value: str) -> tuple[str, str]:
    raw = value.strip().strip("'\"")
    parts = raw.split(":")
    check(len(parts) in (2, 3), "structured_or_invalid_mount_requires_review")
    return parts[0], parts[1]


def normalized_mounts(values: dict[str, str], compose_directory: Path) -> dict[str, str]:
    result = {}
    for target, source in values.items():
        path = Path(source)
        if not path.is_absolute():
            path = compose_directory / path
        result[target] = str(path.resolve())
    return result


def valid_managed_mount_set(values: dict[str, str]) -> None:
    targets = set(values)
    check(targets in (set(), MANAGED_CODE_TARGETS), "managed_code_mount_set_changed")


def is_kuma_port_mapping(value: str) -> bool:
    raw = value.strip().strip("'\"")
    if raw.endswith("/tcp"):
        raw = raw[:-4]
    return raw == KUMA_HOST_PORT + ":" + KUMA_CONTAINER_PORT.split("/", 1)[0]


def patch_compose_json(
    text: str, service: str, image: str, dns_config_source: str | None = None,
    remove_kuma_port: bool = False, admission_native_ssh: str | None = None,
) -> tuple[str, dict[str, str]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError("compose_json_invalid") from None
    check(isinstance(document, dict), "compose_json_root_invalid")
    services = document.get("services")
    check(isinstance(services, dict), "compose_services_block_missing")
    selected = services.get(service)
    check(isinstance(selected, dict), "compose_service_source_ambiguous")
    check(selected.get("container_name") == DEFAULT_CONTAINER, "compose_container_name_mismatch")
    environment = selected.get("environment")
    check(isinstance(environment, dict), "structured_or_missing_environment_requires_review")
    volumes = selected.get("volumes")
    check(isinstance(volumes, list), "compose_volumes_block_missing_or_ambiguous")
    removed: dict[str, str] = {}
    preserved: list[str] = []
    corefile_replaced = 0
    for mount in volumes:
        check(isinstance(mount, str), "structured_or_invalid_mount_requires_review")
        source, target = parse_short_mount(mount)
        if target in PROTECTED_IMAGE_TARGETS and target not in MANAGED_CODE_TARGETS:
            raise RuntimeError("private_image_code_override_requires_review")
        if target in {"/etc/coredns/Corefile", "/etc/coredns"} and dns_config_source is not None:
            check(corefile_replaced == 0, "duplicate_corefile_mount")
            preserved.append(dns_config_source + ":/etc/coredns:rw")
            corefile_replaced += 1
        elif target in MANAGED_CODE_TARGETS:
            check(target not in removed, "duplicate_managed_code_mount")
            removed[target] = source
        else:
            preserved.append(mount)
    valid_managed_mount_set(removed)
    if dns_config_source is not None:
        check(corefile_replaced == 1, "corefile_mount_missing")
    if remove_kuma_port:
        ports = selected.get("ports")
        check(isinstance(ports, list), "compose_ports_block_missing_or_ambiguous")
        check(all(isinstance(item, str) for item in ports), "structured_port_requires_review")
        retained_ports = [item for item in ports if not is_kuma_port_mapping(item)]
        check(len(ports) - len(retained_ports) == 1, "kuma_port_mapping_changed")
        selected["ports"] = retained_ports
    selected["image"] = image
    environment["CENTER_UI_ENABLED"] = "1"
    if admission_native_ssh is not None:
        check(admission_native_ssh in {"0", "1"}, "admission_native_ssh_target_invalid")
        check(str(environment.get("ADMISSION_NATIVE_SSH")) in {"0", "1"},
              "admission_native_ssh_source_missing")
        environment["ADMISSION_NATIVE_SSH"] = admission_native_ssh
    selected["volumes"] = preserved
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n", removed


def patch_compose(
    text: str, service: str, image: str, dns_config_source: str | None = None,
    remove_kuma_port: bool = False, admission_native_ssh: str | None = None,
) -> tuple[str, dict[str, str]]:
    """Conservatively patch one service in JSON or simple block YAML.

    JSON preserves every unrelated parsed value. Advanced YAML constructs are
    refused because a lossy rewrite could destroy comments or private settings.
    """
    if text.lstrip().startswith("{"):
        return patch_compose_json(
            text, service, image, dns_config_source, remove_kuma_port, admission_native_ssh,
        )
    lines = text.splitlines(keepends=True)
    services_index = next((i for i, line in enumerate(lines) if re.fullmatch(r"services:\s*\r?\n?", line)), None)
    check(services_index is not None, "compose_services_block_missing")
    header = re.compile(r"^(\s+)" + re.escape(service) + r":\s*(?:#.*)?\r?\n?$")
    found = [(i, header.match(line)) for i, line in enumerate(lines[services_index + 1 :], services_index + 1) if header.match(line)]
    check(len(found) == 1, "compose_service_source_ambiguous")
    start, match = found[0]
    indent = len(match.group(1))
    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            continue
        leading = len(lines[index]) - len(lines[index].lstrip())
        if leading <= indent:
            end = index
            break
    child = " " * (indent + 2)
    direct = re.compile(r"^" + re.escape(child) + r"([A-Za-z0-9_.-]+):")
    direct_positions = [(i, direct.match(lines[i]).group(1)) for i in range(start + 1, end) if direct.match(lines[i])]

    image_rows = [i for i, key in direct_positions if key == "image"]
    check(len(image_rows) <= 1, "compose_image_ambiguous")
    if image_rows:
        lines[image_rows[0]] = child + "image: " + image + "\n"
    else:
        lines.insert(start + 1, child + "image: " + image + "\n")
        end += 1

    # Recompute direct children after possible insertion.
    direct_positions = [(i, direct.match(lines[i]).group(1)) for i in range(start + 1, end) if direct.match(lines[i])]
    env_rows = [i for i, key in direct_positions if key == "environment"]
    check(len(env_rows) <= 1, "compose_environment_ambiguous")
    if env_rows:
        env_start = env_rows[0]
        check(lines[env_start].split(":", 1)[1].strip() == "", "inline_environment_requires_review")
        env_end = next((i for i, _ in direct_positions if i > env_start), end)
        item_indent = child + "  "
        check(not any(lines[i].lstrip().startswith("-") for i in range(env_start + 1, env_end)), "list_environment_requires_review")
        center_rows = [i for i in range(env_start + 1, env_end) if re.match(r"^" + re.escape(item_indent) + r"CENTER_UI_ENABLED\s*:", lines[i])]
        check(len(center_rows) <= 1, "center_environment_ambiguous")
        if center_rows:
            lines[center_rows[0]] = item_indent + 'CENTER_UI_ENABLED: "1"\n'
        else:
            lines.insert(env_end, item_indent + 'CENTER_UI_ENABLED: "1"\n')
            end += 1
    else:
        insert = next((i for i, key in direct_positions if key == "volumes"), end)
        lines[insert:insert] = [child + "environment:\n", child + '  CENTER_UI_ENABLED: "1"\n']
        end += 2

    if admission_native_ssh is not None:
        check(admission_native_ssh in {"0", "1"}, "admission_native_ssh_target_invalid")
        # Recompute the environment extent after CENTER_UI_ENABLED insertion.
        direct_positions = [(i, direct.match(lines[i]).group(1)) for i in range(start + 1, end) if direct.match(lines[i])]
        env_start = next((i for i, key in direct_positions if key == "environment"), None)
        check(env_start is not None, "compose_environment_ambiguous")
        env_end = next((i for i, _ in direct_positions if i > env_start), end)
        item_indent = child + "  "
        native_rows = [i for i in range(env_start + 1, env_end)
                       if re.match(r"^" + re.escape(item_indent) + r"ADMISSION_NATIVE_SSH\s*:", lines[i])]
        check(len(native_rows) == 1, "admission_native_ssh_source_missing")
        current_value = lines[native_rows[0]].split(":", 1)[1].strip().strip("'\"")
        check(current_value in {"0", "1"}, "admission_native_ssh_source_invalid")
        lines[native_rows[0]] = item_indent + 'ADMISSION_NATIVE_SSH: "' + admission_native_ssh + '"\n'

    # Remove exactly the three known code binds, retaining /data and all other
    # volumes.  Any other image-code shadow is rejected before this function.
    direct_positions = [(i, direct.match(lines[i]).group(1)) for i in range(start + 1, end) if direct.match(lines[i])]
    volume_rows = [i for i, key in direct_positions if key == "volumes"]
    check(len(volume_rows) == 1, "compose_volumes_block_missing_or_ambiguous")
    volumes_start = volume_rows[0]
    volumes_end = next((i for i, _ in direct_positions if i > volumes_start), end)
    removed: dict[str, str] = {}
    remove_indices: list[int] = []
    corefile_replaced = 0
    item_prefix = child + "  - "
    for index in range(volumes_start + 1, volumes_end):
        if not lines[index].strip() or lines[index].lstrip().startswith("#"):
            continue
        check(lines[index].startswith(item_prefix), "long_form_volume_requires_review")
        source, target = parse_short_mount(lines[index][len(item_prefix):].split(" #", 1)[0])
        if target in PROTECTED_IMAGE_TARGETS and target not in MANAGED_CODE_TARGETS:
            raise RuntimeError("private_image_code_override_requires_review")
        if target in {"/etc/coredns/Corefile", "/etc/coredns"} and dns_config_source is not None:
            check(corefile_replaced == 0, "duplicate_corefile_mount")
            lines[index] = item_prefix + dns_config_source + ":/etc/coredns:rw\n"
            corefile_replaced += 1
        elif target in MANAGED_CODE_TARGETS:
            check(target not in removed, "duplicate_managed_code_mount")
            removed[target] = source
            remove_indices.append(index)
    valid_managed_mount_set(removed)
    if dns_config_source is not None:
        check(corefile_replaced == 1, "corefile_mount_missing")
    for index in reversed(remove_indices):
        del lines[index]
    if remove_kuma_port:
        # Refuse YAML anchors/long syntax.  Only the single explicitly owned
        # 3101 -> 3001/tcp short mapping may be removed.
        current_end = len(lines)
        for index in range(start + 1, len(lines)):
            stripped = lines[index].strip()
            if not stripped or stripped.startswith("#"):
                continue
            if len(lines[index]) - len(lines[index].lstrip()) <= indent:
                current_end = index
                break
        direct_positions = []
        for index in range(start + 1, current_end):
            match = re.match(r"^(\s+)([A-Za-z0-9_.-]+):", lines[index])
            if match and match.group(1) == child:
                direct_positions.append((index, match.group(2)))
        ports_positions = [index for index, key in direct_positions if key == "ports"]
        check(len(ports_positions) == 1, "compose_ports_block_missing_or_ambiguous")
        ports_start = ports_positions[0]
        ports_end = next((i for i, _ in direct_positions if i > ports_start), current_end)
        item_prefix = child + "  - "
        matches = []
        for index in range(ports_start + 1, ports_end):
            if not lines[index].strip() or lines[index].lstrip().startswith("#"):
                continue
            check(lines[index].startswith(item_prefix), "structured_port_requires_review")
            raw = lines[index][len(item_prefix):].split(" #", 1)[0].strip()
            if is_kuma_port_mapping(raw):
                matches.append(index)
        check(len(matches) == 1, "kuma_port_mapping_changed")
        del lines[matches[0]]
    return "".join(lines), removed


def find_data_mount(container: dict) -> tuple[Path, list[dict]]:
    mounts = container.get("Mounts", [])
    data = [item for item in mounts if item.get("Destination") == "/data"]
    check(len(data) == 1 and data[0].get("Type") == "bind", "data_bind_mount_required")
    return Path(data[0]["Source"]), mounts


def regular_file_bytes(root: Path) -> int:
    check(root.is_dir() and not root.is_symlink(), "bind_source_invalid")
    total = 0
    for path in root.rglob("*"):
        check(not path.is_symlink(), "symlink_in_private_data_requires_review")
        if path.is_file() and not path.name.endswith(("-wal", "-shm", ".sock", ".lock")):
            total += path.stat().st_size
    return total


def mount_fingerprint(mounts: list[dict], exclude: set[str] | None = None) -> list[dict]:
    exclude = exclude or set()
    return sorted(({
        "type": item.get("Type"), "source": item.get("Source"),
        "destination": item.get("Destination"), "rw": item.get("RW"),
    } for item in mounts if item.get("Destination") not in exclude), key=lambda item: str(item["destination"]))


def stable_runtime(
    container: dict,
    exclude_mounts: set[str] | None = None,
    exclude_ports: set[str] | None = None,
) -> dict:
    environment = sorted(
        item for item in container.get("Config", {}).get("Env", [])
        if item.split("=", 1)[0] not in MANAGED_ENV_KEYS
    )
    host = container.get("HostConfig", {})
    ports = dict(host.get("PortBindings", {}) or {})
    for port in exclude_ports or set():
        ports.pop(port, None)
    return {
        "ports": ports,
        "network_mode": host.get("NetworkMode"),
        "restart_policy": host.get("RestartPolicy", {}),
        "environment_without_center_flag": environment,
        "mounts": mount_fingerprint(container.get("Mounts", []), exclude_mounts),
    }


def sqlite_backup(source: Path, target: Path) -> str:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect("file:" + str(source) + "?mode=ro", uri=True, timeout=30)) as old:
        check(old.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "source_sqlite_integrity_failed")
        with contextlib.closing(sqlite3.connect(target)) as new:
            old.backup(new, pages=256, sleep=0.02)
            check(new.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "backup_sqlite_integrity_failed")
    target.chmod(0o600)
    return sha256(target)


def snapshot_bind(source: Path, target: Path) -> dict:
    check(source.is_dir() and not source.is_symlink(), "bind_source_invalid")
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    files: dict[str, str] = {}
    databases: dict[str, dict] = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        check(not path.is_symlink(), "symlink_in_private_data_requires_review")
        if not path.is_file() or path.name.endswith(("-wal", "-shm", ".sock", ".lock")):
            continue
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        is_database = path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}
        if is_database:
            result = sqlite_backup(path, destination)
            databases[relative.as_posix()] = {"sha256": result, "integrity": "ok"}
        else:
            shutil.copyfile(path, destination)
            destination.chmod(0o600)
            files[relative.as_posix()] = sha256(destination)
    return {"files": files, "databases": databases}


def verify_snapshot(snapshot: dict, root: Path) -> None:
    for relative, expected in snapshot.get("files", {}).items():
        check(sha256(root / relative) == expected, "private_backup_checksum_failed")
    for relative, detail in snapshot.get("databases", {}).items():
        path = root / relative
        check(sha256(path) == detail["sha256"], "database_backup_checksum_failed")
        with contextlib.closing(sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)) as db:
            check(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "database_backup_integrity_failed")


def snapshot_bound_files(mounts: list[dict], target: Path) -> dict[str, dict[str, str]]:
    """Back up regular bind-mounted configuration files with target identity."""
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    result: dict[str, dict[str, str]] = {}
    seen_sources: set[str] = set()
    index = 0
    for mount in sorted(mounts, key=lambda item: str(item.get("Destination"))):
        if mount.get("Type") != "bind":
            continue
        raw_source = Path(str(mount.get("Source", "")))
        check(not raw_source.is_symlink(), "symlink_in_bound_config_requires_review")
        source = raw_source.resolve()
        if not source.is_file():
            continue
        check(not source.is_symlink(), "symlink_in_bound_config_requires_review")
        source_text = str(source)
        if source_text in seen_sources:
            continue
        seen_sources.add(source_text)
        name = "file-" + str(index)
        index += 1
        payload = source.read_bytes()
        atomic_bytes(target / name, payload)
        result[str(mount.get("Destination"))] = {
            "source": source_text, "backup": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "rw": bool(mount.get("RW", True)),
        }
    return result


def verify_bound_files(snapshot: dict[str, dict[str, str]], root: Path) -> None:
    for detail in snapshot.values():
        source = Path(detail["source"])
        backup = root / detail["backup"]
        check(source.is_file() and not source.is_symlink(), "bound_config_changed")
        check(sha256(source) == detail["sha256"], "bound_config_changed")
        check(sha256(backup) == detail["sha256"], "bound_config_backup_corrupt")


def validate_dns_directory(root: Path, expected_corefile_sha256: str | None = None) -> dict:
    """Validate the full directory that will shadow ``/etc/coredns``."""
    check(root.is_dir() and not root.is_symlink(), "dns_config_directory_invalid")
    files: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        check(not stat.S_ISLNK(mode), "dns_config_symlink_refused")
        check(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "dns_config_special_file_refused")
        if stat.S_ISREG(mode):
            total += path.stat().st_size
            check(total <= 32 * 1024 * 1024, "dns_config_directory_too_large")
            files[path.relative_to(root).as_posix()] = sha256(path)
    check("Corefile" in files, "dns_corefile_missing")
    if expected_corefile_sha256 is not None:
        check(files["Corefile"] == expected_corefile_sha256, "dns_corefile_baseline_changed")
    return {"files": files, "total_bytes": total, "corefile_sha256": files["Corefile"]}


def dns_mount_plan(data_root: Path, mounts: list[dict], expected: dict) -> dict:
    relevant = [item for item in mounts if str(item.get("Destination", "")) == DNS_DIRECTORY_TARGET
                or str(item.get("Destination", "")).startswith(DNS_DIRECTORY_TARGET + "/")]
    check(len(relevant) == 1, "coredns_mount_layout_requires_review")
    mount = relevant[0]
    check(mount.get("Type") == "bind", "coredns_bind_mount_required")
    raw_source = Path(str(mount.get("Source", "")))
    check(not raw_source.is_symlink(), "corefile_source_invalid")
    source = raw_source.resolve()
    desired = (data_root / DNS_MANAGED_RELATIVE).resolve()
    destination = mount.get("Destination")
    if destination == DNS_FILE_TARGET:
        check(not mount.get("RW", True), "readonly_corefile_bind_mount_required")
        check(source.is_file() and not source.is_symlink(), "corefile_source_invalid")
        check("corefile_source" in expected, "production_snapshot_corefile_source_required")
        check(source == Path(str(expected["corefile_source"])).resolve(), "production_snapshot_corefile_mount_changed")
        check(not desired.exists(), "dns_managed_directory_preexists_requires_review")
        digest = sha256(source)
        mode = "readonly_file_to_managed_directory"
        layout = {"files": {"Corefile": digest}, "total_bytes": source.stat().st_size,
                  "corefile_sha256": digest}
    else:
        check(destination == DNS_DIRECTORY_TARGET and mount.get("RW") is True, "managed_coredns_directory_mount_required")
        check(source == desired, "managed_coredns_source_changed")
        if expected.get("dns_config_source") is not None:
            check(source == Path(str(expected["dns_config_source"])).resolve(), "production_snapshot_dns_config_mount_changed")
        layout = validate_dns_directory(source)
        digest = layout["corefile_sha256"]
        mode = "managed_directory"
    expected_digest = expected.get("dns_corefile_sha256")
    check(isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
          "production_snapshot_dns_corefile_hash_required")
    check(digest == expected_digest, "production_snapshot_dns_corefile_changed")
    return {"mode": mode, "old_source": str(source), "old_destination": destination,
            "old_rw": bool(mount.get("RW")), "managed_source": str(desired),
            "corefile_sha256": digest, "layout": layout}


def stage_dns_directory(transaction: dict) -> dict:
    plan = transaction["dns_config"]
    target = Path(plan["managed_source"])
    if plan["mode"] == "managed_directory":
        return validate_dns_directory(target, plan["corefile_sha256"])
    check(plan["mode"] == "readonly_file_to_managed_directory", "dns_config_mode_invalid")
    check(not target.exists(), "dns_managed_directory_created_concurrently")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".coredns-stage-", dir=target.parent))
    try:
        RUNNER.run(["docker", "cp", transaction["container_name"] + ":/etc/coredns/.", str(temporary)], timeout=90)
        layout = validate_dns_directory(temporary, plan["corefile_sha256"])
        check(layout["files"] == plan["layout"]["files"], "dns_directory_layout_changed")
        for path in temporary.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        for path in temporary.rglob("*"):
            if path.is_file():
                fsync_path(path)
        for path in sorted((item for item in temporary.rglob("*") if item.is_dir()),
                           key=lambda item: len(item.parts), reverse=True):
            fsync_path(path)
        temporary.chmod(0o700)
        fsync_path(temporary)
        os.replace(temporary, target)
        fsync_path(target.parent)
        return validate_dns_directory(target, plan["corefile_sha256"])
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def verify_dns_runtime(current: dict, transaction: dict) -> dict:
    plan = transaction["dns_config"]
    relevant = [item for item in current.get("Mounts", [])
                if str(item.get("Destination", "")) == DNS_DIRECTORY_TARGET
                or str(item.get("Destination", "")).startswith(DNS_DIRECTORY_TARGET + "/")]
    check(len(relevant) == 1, "managed_coredns_runtime_mount_missing")
    mount = relevant[0]
    check(mount.get("Type") == "bind" and mount.get("Destination") == DNS_DIRECTORY_TARGET
          and mount.get("RW") is True
          and Path(str(mount.get("Source", ""))).resolve() == Path(plan["managed_source"]).resolve(),
          "managed_coredns_runtime_mount_changed")
    layout = validate_dns_directory(Path(plan["managed_source"]), plan["corefile_sha256"])
    output = RUNNER.run(["docker", "exec", transaction["container_name"], "sha256sum", DNS_FILE_TARGET], timeout=30).decode().split()
    check(output and output[0] == plan["corefile_sha256"], "container_dns_corefile_changed")
    return layout


def cleanup_unaccepted_dns_stage(transaction: dict) -> dict:
    plan = transaction.get("dns_config", {})
    if plan.get("mode") != "readonly_file_to_managed_directory":
        return {"removed": False, "reason": "not_transition_owned"}
    target = Path(plan["managed_source"])
    if not target.exists():
        return {"removed": False, "reason": "not_present"}
    actual = validate_dns_directory(target)
    expected = plan.get("staged_layout") or plan.get("layout")
    if not isinstance(expected, dict) or actual.get("files") != expected.get("files"):
        return {"removed": False, "reason": "changed_after_stage"}
    shutil.rmtree(target)
    fsync_path(target.parent)
    return {"removed": True, "reason": "unaccepted_owned_stage"}


def context_destination(relative: str) -> str | None:
    if relative.startswith("runtime/upstream/"):
        name = relative.rsplit("/", 1)[-1]
        return "/subscription_impl.py" if name == "subscription-controller.py" else "/" + name
    if relative == "runtime/portable_subscriptions.py":
        return "/subscription-controller.py"
    if relative.startswith("local-subscription/"):
        return "/" + relative
    if relative.startswith("unified-center/"):
        return "/" + relative
    return None


def normalized_source_digest(path: Path) -> str:
    payload = path.read_bytes()
    if path.suffix.lower() in {".py", ".js", ".html"}:
        payload = payload.replace(b"\r\n", b"\n")
    return hashlib.sha256(payload).hexdigest()


def verify_overlays(data_root: Path, context_files: dict[str, str]) -> dict[str, dict[str, str]]:
    by_name: dict[str, set[str]] = {}
    for relative, digest in context_files.items():
        destination = context_destination(relative)
        if destination:
            # subscription-controller.py is deliberately renamed to
            # subscription_impl.py inside the image and node-health overlay.
            by_name.setdefault(Path(destination).name, set()).add(digest)
    result: dict[str, dict[str, str]] = {}
    for relative_dir in OVERLAY_DIRS:
        directory = data_root / relative_dir
        check(directory.is_dir(), "required_data_code_overlay_missing")
        found = False
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            found = True
            raw_value = sha256(path)
            source_value = normalized_source_digest(path)
            check(source_value in by_name.get(path.name, set()), "data_code_overlay_not_same_source")
            result[path.relative_to(data_root).as_posix()] = {
                "raw_sha256": raw_value, "normalized_source_sha256": source_value,
            }
        check(found, "required_data_code_overlay_empty")
    return result


def fingerprint_overlays(data_root: Path) -> dict[str, dict[str, str]]:
    """Record legacy code trees without treating them as executable sources.

    Image-to-image upgrades require ``runtime_code_policy=image_only``.  The
    old trees remain part of the private data backup for recovery evidence, but
    their contents must not be synchronized into or loaded by the new image.
    """
    result: dict[str, dict[str, str]] = {}
    for relative_dir in OVERLAY_DIRS:
        directory = data_root / relative_dir
        if not directory.exists():
            continue
        check(directory.is_dir() and not directory.is_symlink(), "legacy_overlay_path_invalid")
        for path in sorted(directory.rglob("*")):
            check(not path.is_symlink(), "symlink_in_private_data_requires_review")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                result[path.relative_to(data_root).as_posix()] = {
                    "raw_sha256": sha256(path),
                }
    return result


def optional_private_file_identity(path: Path) -> dict:
    check(not path.is_symlink(), "private_state_symlink_requires_review")
    if not path.exists():
        return {"path": str(path), "existed": False, "sha256": None}
    check(path.is_file(), "private_state_path_invalid")
    return {"path": str(path), "existed": True, "sha256": sha256(path)}


def verify_optional_private_file_identity(detail: dict) -> None:
    actual = optional_private_file_identity(Path(detail["path"]))
    check(actual["existed"] == detail["existed"] and actual["sha256"] == detail["sha256"],
          "subscription_override_changed_during_unaccepted_deployment")


def validate_mount_overrides(mounts: list[dict]) -> dict[str, str]:
    managed: dict[str, str] = {}
    for item in mounts:
        target = item.get("Destination")
        if target in PROTECTED_IMAGE_TARGETS:
            check(target in MANAGED_CODE_TARGETS, "private_image_code_override_requires_review")
            check(item.get("Type") == "bind" and not item.get("RW", True), "managed_code_mount_not_read_only")
            check(target not in managed, "duplicate_managed_code_mount")
            managed[target] = item.get("Source")
    valid_managed_mount_set(managed)
    return managed


def transaction_path(base: Path) -> Path:
    return base / "transaction.json"


def read_transaction(base: Path) -> dict:
    path = transaction_path(base)
    check(path.is_file(), "no_pending_transaction")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_existing_unified_state(
    state: dict, current: dict, compose: Path, base_image: dict,
) -> None:
    check(state.get("kind") == "unified-center-installation", "unified_state_kind_invalid")
    check(state.get("container_id") == current.get("Id"), "unified_state_container_identity_mismatch")
    check(state.get("image_id") == current.get("Image"), "unified_state_image_identity_mismatch")
    check(state.get("compose_sha256") == sha256(compose), "unified_state_compose_identity_mismatch")
    old_manifest = state.get("manifest")
    check(isinstance(old_manifest, dict), "unified_state_manifest_missing")
    old_image = inspect_object("image", current.get("Image"))
    validate_image_lineage(old_image, base_image, old_manifest)


def prepare(args: dict, base: Path) -> dict:
    check(os.geteuid() == 0, "root_required")
    check(not transaction_path(base).exists(), "unfinished_transaction_exists")
    compose = Path(args.get("compose_path", DEFAULT_COMPOSE)).resolve()
    container_name = args.get("container_name", DEFAULT_CONTAINER)
    service = args["service"]
    check(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", service), "invalid_service")
    check(container_name == DEFAULT_CONTAINER, "unexpected_container_name")
    check(compose.is_file(), "compose_file_missing")
    manifest_path = Path(args["manifest_path"]).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    check(manifest.get("kind") == "unified-center-image", "image_manifest_kind_invalid")
    check(manifest.get("base_image_id") == BASE_IMAGE_ID, "base_image_identity_invalid")
    check(manifest.get("runtime_code_policy") == "image_only", "new_image_runtime_code_policy_invalid")
    image_name = args["image"]
    image = inspect_object("image", image_name)
    check(image.get("Id") == manifest.get("image_id"), "new_image_identity_mismatch")
    check(image.get("Architecture") in (None, "amd64") and image.get("Os") in (None, "linux"), "new_image_platform_invalid")
    base_image = inspect_object("image", BASE_IMAGE_ID)
    validate_image_lineage(image, base_image, manifest)
    current = inspect_object("container", container_name)
    check(current.get("State", {}).get("Running") is True, "current_container_not_running")
    labels = current.get("Config", {}).get("Labels", {})
    check(labels.get("com.docker.compose.service") == service, "running_container_service_mismatch")
    config_files = labels.get("com.docker.compose.project.config_files", "").split(",")
    check(str(compose) in [str(Path(item).resolve()) for item in config_files if item], "running_container_compose_mismatch")
    config = compose_config(compose)
    selected = compose_service(config, service, container_name)
    selected_environment = selected.get("environment")
    check(isinstance(selected_environment, dict), "structured_or_missing_environment_requires_review")
    old_admission_native_ssh = str(selected_environment.get("ADMISSION_NATIVE_SSH"))
    check(old_admission_native_ssh in {"0", "1"}, "admission_native_ssh_source_missing")
    runtime_admission_values = [
        item.split("=", 1)[1] for item in current.get("Config", {}).get("Env", [])
        if item.split("=", 1)[0] == "ADMISSION_NATIVE_SSH"
    ]
    check(runtime_admission_values == [old_admission_native_ssh],
          "admission_native_ssh_runtime_compose_mismatch")
    data_root, mounts = find_data_mount(current)
    expected = args.get("expected_snapshot")
    check(isinstance(expected, dict), "expected_production_snapshot_required")
    check(expected.get("container_id") == current.get("Id"), "production_snapshot_container_changed")
    check(expected.get("current_image_id") == current.get("Image"), "production_snapshot_image_changed")
    check(expected.get("compose_sha256") == sha256(compose), "production_snapshot_compose_changed")
    check(expected.get("service") == service, "production_snapshot_service_changed")
    check(expected.get("mount_count") == len(mounts), "production_snapshot_mounts_changed")
    app_data = [item for item in mounts if item.get("Destination") == "/app/data" and item.get("Type") == "bind"]
    check(len(app_data) == 1, "app_data_bind_mount_required")
    check(str(data_root.resolve()) == str(Path(expected.get("data_source", "")).resolve()), "production_snapshot_data_mount_changed")
    check(str(Path(app_data[0]["Source"]).resolve()) == str(Path(expected.get("app_data_source", "")).resolve()), "production_snapshot_app_data_mount_changed")
    dns_config = dns_mount_plan(data_root, mounts, expected)
    port_binding = current.get("HostConfig", {}).get("PortBindings", {}).get(KUMA_CONTAINER_PORT)
    if port_binding:
        check(isinstance(port_binding, list) and len(port_binding) == 1
              and str(port_binding[0].get("HostPort")) == KUMA_HOST_PORT,
              "kuma_port_mapping_changed")
        old_kuma_port_published = True
    else:
        old_kuma_port_published = False
    legacy_path = Path(args.get("legacy_state_path", LEGACY_STATE)).resolve()
    check(legacy_path == LEGACY_STATE, "legacy_installer_state_path_invalid")
    check(legacy_path.is_file(), "legacy_installer_state_missing")
    legacy_bytes = legacy_path.read_bytes()
    legacy = json.loads(legacy_bytes)
    check(legacy.get("container_name") == container_name, "legacy_installer_container_name_mismatch")
    check(legacy.get("container_id") == current.get("Id"), "legacy_watchdog_container_identity_mismatch")
    check(legacy.get("manifest", {}).get("image_id") == current.get("Image"), "legacy_watchdog_image_identity_mismatch")
    managed_mounts = validate_mount_overrides(mounts)
    # Source Compose must describe the same removable mounts.  An accepted
    # unified image has none; the original three-bind migration has all three.
    planned_compose, raw_source_mounts = patch_compose(
        compose.read_text(encoding="utf-8"), service, image_name,
        dns_config["managed_source"], remove_kuma_port=old_kuma_port_published,
        admission_native_ssh="0",
    )
    source_mounts = normalized_mounts(raw_source_mounts, compose.parent)
    check(set(source_mounts) == set(managed_mounts), "compose_runtime_code_mount_mismatch")
    for target, source in source_mounts.items():
        check(Path(source).resolve() == Path(managed_mounts[target]).resolve(), "compose_runtime_code_mount_mismatch")
    unified_state_path = base / "state.json"
    unified_state_bytes = unified_state_path.read_bytes() if unified_state_path.exists() else None
    if managed_mounts:
        deployment_mode = "legacy_bind_migration"
        overlay_policy = "legacy_source_match"
        overlay_hashes = verify_overlays(data_root, manifest.get("context_files", {}))
    else:
        deployment_mode = "unified_image_upgrade"
        overlay_policy = "inert_preserved"
        check(unified_state_bytes is not None, "accepted_unified_state_required_for_image_upgrade")
        validate_existing_unified_state(
            json.loads(unified_state_bytes), current, compose, base_image,
        )
        overlay_hashes = fingerprint_overlays(data_root)
    subscription_override = optional_private_file_identity(
        data_root / "subscription-usage/source-overrides.json",
    )
    free = shutil.disk_usage(base.parent if base.parent.exists() else Path("/opt")).free
    unique_state_sources = {
        str(Path(item["Source"]).resolve()) for item in mounts
        if item.get("Type") == "bind" and item.get("Destination") in ("/data", "/app/data")
    }
    snapshot_bytes = sum(regular_file_bytes(Path(source)) for source in unique_state_sources)
    requested_free = max(int(args.get("required_free_bytes", 6 * 1024**3)), snapshot_bytes * 2 + 1024**3)
    check(free >= requested_free, "insufficient_host_space")

    stamp = str(time.time_ns())
    backup = base / "backups" / stamp
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    compose_bytes = compose.read_bytes()
    atomic_bytes(backup / "compose.before.yml", compose_bytes)
    atomic_json(backup / "container.before.private.json", current)
    atomic_json(backup / "image-manifest.json", manifest)
    atomic_bytes(backup / "legacy-state.before.json", legacy_bytes)
    if unified_state_bytes is not None:
        atomic_bytes(backup / "unified-state.before.json", unified_state_bytes)
    bound_files = snapshot_bound_files(mounts, backup / "bound-files")
    if dns_config["mode"] == "readonly_file_to_managed_directory":
        check(DNS_FILE_TARGET in bound_files, "corefile_backup_missing")
    snapshots: dict[str, dict] = {}
    seen_sources: set[str] = set()
    for index, mount in enumerate(mounts):
        if mount.get("Type") != "bind" or mount.get("Destination") not in ("/data", "/app/data"):
            continue
        source = str(Path(mount["Source"]).resolve())
        if source in seen_sources:
            continue
        seen_sources.add(source)
        snapshots[mount["Destination"]] = {
            "source": source,
            "backup": "bind-" + str(index),
            "receipt": snapshot_bind(Path(source), backup / ("bind-" + str(index))),
        }
    check(any("kuma.db" in name for item in snapshots.values() for name in item["receipt"]["databases"]), "kuma_database_backup_missing")
    other = all_container_shapes()
    other.pop(container_name, None)
    other_running = sum(1 for item in other.values() if item.get("running") is True)
    check(expected.get("other_container_total_count") == len(other), "production_snapshot_other_container_total_count_changed")
    check(expected.get("other_container_running_count") == other_running, "production_snapshot_other_container_running_count_changed")
    transaction = {
        "schema": 2,
        "id": stamp,
        "phase": "prepared",
        "created_at": time.time(),
        "compose_path": str(compose),
        "compose_before_sha256": hashlib.sha256(compose_bytes).hexdigest(),
        "service": service,
        "container_name": container_name,
        "old_container": container_shape(current),
        "old_runtime": stable_runtime(
            current,
            set(managed_mounts) | {DNS_FILE_TARGET, DNS_DIRECTORY_TARGET},
            {KUMA_CONTAINER_PORT},
        ),
        "old_admission_native_ssh": old_admission_native_ssh,
        "old_kuma_port_published": old_kuma_port_published,
        "old_image": current.get("Config", {}).get("Image"),
        "new_image": image_name,
        "new_image_id": image.get("Id"),
        "manifest": manifest,
        "backup": str(backup),
        "managed_mounts": managed_mounts,
        "deployment_mode": deployment_mode,
        "data_mounts": snapshots,
        "overlay_hashes": overlay_hashes,
        "overlay_policy": overlay_policy,
        "subscription_override": subscription_override,
        "bound_files": bound_files,
        "dns_config": dns_config,
        "planned_compose_sha256": hashlib.sha256(planned_compose.encode("utf-8")).hexdigest(),
        "removed_port": {"container": KUMA_CONTAINER_PORT, "host": KUMA_HOST_PORT},
        "other_containers": other,
        "legacy_state": {
            "path": str(legacy_path), "before_sha256": hashlib.sha256(legacy_bytes).hexdigest(),
            "before_container_id": legacy["container_id"],
            "before_image_id": legacy["manifest"]["image_id"],
        },
        "unified_state_before": {
            "existed": unified_state_bytes is not None,
            "sha256": hashlib.sha256(unified_state_bytes).hexdigest() if unified_state_bytes is not None else None,
        },
        "guard_timeout_seconds": max(120, min(int(args.get("guard_timeout_seconds", 900)), 3600)),
        "selected_service_fingerprint": hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest(),
        "interruption_scope": "target_container_dns_kuma_and_center_ports",
        "space_check": {"free_bytes": free, "required_bytes": requested_free, "snapshot_source_bytes": snapshot_bytes},
    }
    atomic_json(backup / "transaction.private.json", transaction)
    atomic_json(transaction_path(base), transaction)
    return {
        "transaction": stamp,
        "phase": "prepared",
        "backup_verified": True,
        "sqlite_integrity": "ok",
        "service": service,
        "container": container_name,
        "short_interruption_required": True,
        "deployment_mode": deployment_mode,
    }


def assert_owned_before_apply(transaction: dict) -> dict:
    compose = Path(transaction["compose_path"])
    check(sha256(compose) == transaction["compose_before_sha256"], "concurrent_compose_edit_refused")
    current = inspect_object("container", transaction["container_name"])
    check(current.get("Id") == transaction["old_container"]["id"], "concurrent_container_change_refused")
    check(current.get("Image") == transaction["old_container"]["image"], "concurrent_image_change_refused")
    return current


def start_guard(base: Path, transaction: dict) -> str:
    backup = Path(transaction["backup"])
    agent = backup / "guard-agent.py"
    shutil.copyfile(Path(__file__), agent)
    agent.chmod(0o700)
    request = backup / "guard-request.json"
    atomic_json(request, {"action": "guard", "state_dir": str(base), "transaction": transaction["id"]})
    unit = "clash-unified-rollback-" + transaction["id"]
    delay = str(transaction["guard_timeout_seconds"]) + "s"
    RUNNER.run([
        "systemd-run", "--quiet", "--unit", unit, "--on-active=" + delay,
        "--timer-property=AccuracySec=1s", "/usr/bin/python3", str(agent), str(request),
    ], timeout=30)
    active = RUNNER.run(["systemctl", "is-active", unit + ".timer"], timeout=15).decode().strip()
    check(active == "active", "rollback_guard_timer_not_active")
    return unit


def apply(args: dict, base: Path) -> dict:
    transaction = read_transaction(base)
    check(transaction["phase"] == "prepared", "apply_phase_invalid")
    assert_owned_before_apply(transaction)
    backup = Path(transaction["backup"])
    for detail in transaction["data_mounts"].values():
        verify_snapshot(detail["receipt"], backup / detail["backup"])
    verify_bound_files(transaction.get("bound_files", {}), backup / "bound-files")
    unit = start_guard(base, transaction)
    source = Path(transaction["compose_path"])
    staged_dns = stage_dns_directory(transaction)
    patched, raw_removed = patch_compose(
        source.read_text(encoding="utf-8"), transaction["service"], transaction["new_image"],
        transaction["dns_config"]["managed_source"],
        remove_kuma_port=transaction["old_kuma_port_published"],
        admission_native_ssh="0",
    )
    removed = normalized_mounts(raw_removed, source.parent)
    check(removed == transaction["managed_mounts"], "managed_mounts_changed_after_prepare")
    check(hashlib.sha256(patched.encode("utf-8")).hexdigest() == transaction["planned_compose_sha256"],
          "planned_compose_changed_after_prepare")
    transaction["guard_unit"] = unit
    transaction["phase"] = "applying"
    transaction["dns_config"]["staged_layout"] = staged_dns
    transaction["compose_after_sha256"] = hashlib.sha256(patched.encode("utf-8")).hexdigest()
    atomic_json(transaction_path(base), transaction)
    atomic_bytes(source, patched.encode("utf-8"))
    check(sha256(source) == transaction["compose_after_sha256"], "compose_atomic_write_failed")
    try:
        RUNNER.run([
            "docker", "compose", "-f", str(source), "up", "-d", "--no-deps",
            "--no-build", "--pull", "never", transaction["service"],
        ], timeout=300)
        current = inspect_object("container", transaction["container_name"])
        check(current.get("Image") == transaction["new_image_id"], "new_container_image_mismatch")
        transaction["new_container_id"] = current.get("Id")
        transaction["phase"] = "applied"
        transaction["applied_at"] = time.time()
        atomic_json(transaction_path(base), transaction)
        atomic_json(backup / "transaction.private.json", transaction)
    except Exception:
        # The guard remains armed.  Do not conceal the apply failure or attempt
        # to restore databases; a safe rollback will restore only owned Compose.
        raise
    return {
        "transaction": transaction["id"], "phase": "applied",
        "container_id": transaction["new_container_id"],
        "short_interruption_occurred": True,
        "guard_armed": True,
    }


def image_paths(manifest: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative, digest in manifest.get("context_files", {}).items():
        destination = context_destination(relative)
        if destination:
            result[destination] = digest
    return result


def live_sqlite_integrity(transaction: dict) -> None:
    for detail in transaction["data_mounts"].values():
        source = Path(detail["source"])
        for relative in detail["receipt"]["databases"]:
            path = source / relative
            with contextlib.closing(sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True, timeout=15)) as db:
                check(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "live_sqlite_integrity_failed")


def verify_dns_protocols(container_name: str) -> dict:
    script = r'''import socket,struct
q=b"\x4a\x59\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+b"\x03www\x05baidu\x03com\x00\x00\x01\x00\x01"
def recv_exact(s,n):
 out=b""
 while len(out)<n:
  part=s.recv(n-len(out));assert part;out+=part
 return out
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
 s=socket.socket(socket.AF_INET,kind);s.settimeout(4)
 if kind==socket.SOCK_DGRAM:s.sendto(q,("127.0.0.1",53));r=s.recvfrom(4096)[0]
 else:
  s.connect(("127.0.0.1",53));s.sendall(struct.pack("!H",len(q))+q);n=struct.unpack("!H",recv_exact(s,2))[0];r=recv_exact(s,n)
 s.close();assert len(r)>=12 and r[:2]==q[:2] and r[2]&128 and (r[3]&15) in (0,3)
print("udp_tcp_ok")'''
    output = RUNNER.run(["docker", "exec", container_name, "python3", "-c", script], timeout=20).decode().strip()
    check(output == "udp_tcp_ok", "dns_udp_tcp_probe_failed")
    return {"udp": "ok", "tcp": "ok", "query": "www.baidu.com/A"}


def verify_admission_runtime(container_name: str) -> dict:
    script = r'''import hashlib,os,pathlib,socket,subprocess,tempfile,time
core=pathlib.Path(os.environ['ADMISSION_CORE']);pin=pathlib.Path(os.environ['ADMISSION_CORE_PIN'])
digest=hashlib.sha256(core.read_bytes()).hexdigest();assert digest==pin.read_text().strip() and os.access(core,os.X_OK)
with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
with tempfile.TemporaryDirectory(prefix='admission-smoke-') as d:
 cfg=pathlib.Path(d)/'config.yaml';cfg.write_text('mixed-port: '+str(port)+'\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nipv6: false\nlog-level: silent\ndns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n')
 test=subprocess.run([str(core),'-d',d,'-f',str(cfg),'-t'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8);assert test.returncode==0
 process=subprocess.Popen([str(core),'-d',d,'-f',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  ready=False
  for _ in range(40):
   if process.poll() is not None:break
   try:
    with socket.create_connection(('127.0.0.1',port),timeout=.1):ready=True;break
   except OSError:time.sleep(.1)
  assert ready
 finally:
  process.terminate()
  try:process.wait(timeout=3)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
print('admission_ok '+digest)'''
    output = RUNNER.run(["docker", "exec", container_name, "python3", "-c", script], timeout=20).decode().strip().split()
    check(len(output) == 2 and output[0] == "admission_ok" and re.fullmatch(r"[0-9a-f]{64}", output[1]),
          "admission_runtime_probe_failed")
    return {"state": "ok", "core_sha256": output[1], "bind": "127.0.0.1"}


def verify_kuma_native_runtime(container_name: str) -> dict:
    """Prove the native Kuma bridge without exporting any credential material.

    The script executes the exact image-owned extension that the control plane
    uses.  It only stats the JWT file (never reads or hashes it), then asks the
    bridge for its already-sanitised read-only snapshot.  The host receives a
    fixed summary rather than the snapshot, so notification configuration and
    monitor details cannot escape through deployment logs.
    """
    script = r'''import json,os,pathlib,re,stat,sys,time
token=pathlib.Path(os.environ.get('CENTER_KUMA_TOKEN_FILE','/data/unified/kuma-bridge.jwt'))
info=token.lstat();assert stat.S_ISREG(info.st_mode) and not token.is_symlink()
assert info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size>0
sys.path.insert(0,'/unified-center')
from kuma_management import create_extension
extension=create_extension({'data_root':'/data','center_root':'/data/center','remote_timeout':3})
value=extension.snapshot()
actions=((value.get('capabilities') or {}).get('actions') or []) if isinstance(value,dict) else []
connection=value.get('connection') if isinstance(value,dict) else None
ok=(isinstance(value,dict) and value.get('state')=='ready' and isinstance(connection,dict)
 and connection.get('state')=='ready' and value.get('version')=='2.5.6'
 and isinstance(value.get('revision'),str) and re.fullmatch(r'[0-9a-f]{64}',value['revision'])
 and isinstance(value.get('monitors'),list) and len(value['monitors'])>0
 and isinstance(value.get('notifications'),list)
 and 'kuma.monitor_detail' in actions and 'kuma.monitor_history' in actions)
assert ok
print(json.dumps({'state':'ok','revision':value['revision'],'monitors':len(value['monitors']),
 'notifications':len(value['notifications']),'credential_file':'root-0600-regular'},separators=(',',':')))'''
    raw = RUNNER.run(["docker", "exec", container_name, "python3", "-c", script], timeout=35).decode().strip()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("kuma_native_runtime_probe_invalid") from None
    check(isinstance(value, dict) and value.get("state") == "ok"
          and value.get("credential_file") == "root-0600-regular"
          and isinstance(value.get("revision"), str)
          and re.fullmatch(r"[0-9a-f]{64}", value["revision"])
          and isinstance(value.get("monitors"), int) and value["monitors"] > 0
          and isinstance(value.get("notifications"), int) and value["notifications"] >= 0,
          "kuma_native_runtime_probe_invalid")
    return value


def verify_http_probes(probes: list[str]) -> list[dict]:
    check(isinstance(probes, list) and 1 <= len(probes) <= 12, "mandatory_probe_list_invalid")
    check(all(isinstance(probe, str) and re.fullmatch(
        r"http://(?:127\.0\.0\.1|10\.88\.0\.249):[0-9]{1,5}/[^\s]*", probe,
    ) for probe in probes), "probe_url_not_local")
    check(any(urllib.parse.urlsplit(probe).path == "/api/center/overview" for probe in probes),
          "unified_overview_probe_required")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    results = []
    for probe in probes:
        with opener.open(probe, timeout=8) as response:
            check(200 <= response.status < 400, "http_probe_failed")
            payload = response.read(1024 * 1024)
        if urllib.parse.urlsplit(probe).path == "/api/center/overview":
            try:
                value = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RuntimeError("unified_overview_probe_invalid") from None
            check(isinstance(value, dict) and value.get("schema") == 1
                  and value.get("environment") == "production",
                  "unified_overview_probe_invalid")
            services = {
                item.get("id"): item.get("state") for item in value.get("services", [])
                if isinstance(item, dict)
            }
            check(all(services.get(name) == "ok" for name in ("kuma", "dns", "clash")),
                  "unified_overview_critical_service_unhealthy")
        results.append({"url": probe, "status": "ok"})
    return results


def critical_runtime_gate(current: dict, transaction: dict, probes: list[str]) -> dict:
    check(current.get("State", {}).get("Running") is True, "new_container_not_running")
    check(current.get("Image") == transaction["new_image_id"], "new_container_image_mismatch")
    check(current.get("State", {}).get("Health", {}).get("Status") == "healthy",
          "new_container_health_not_healthy")
    check(stable_runtime(
        current, {DNS_FILE_TARGET, DNS_DIRECTORY_TARGET}, {KUMA_CONTAINER_PORT},
    ) == transaction["old_runtime"], "runtime_contract_changed")
    check(not current.get("HostConfig", {}).get("PortBindings", {}).get(KUMA_CONTAINER_PORT),
          "kuma_external_port_still_published")
    dns_layout = verify_dns_runtime(current, transaction)
    protocols = verify_dns_protocols(transaction["container_name"])
    environment = set(current.get("Config", {}).get("Env", []))
    check("ADMISSION_CORE=/local-subscription/core" in environment
          and "ADMISSION_CORE_PIN=/local-subscription/core.sha256" in environment
          and "ADMISSION_NATIVE_SSH=0" in environment,
          "admission_environment_invalid")
    admission = verify_admission_runtime(transaction["container_name"])
    kuma_native = verify_kuma_native_runtime(transaction["container_name"])
    http = verify_http_probes(probes)
    return {
        "dns_layout": dns_layout, "dns_protocols": protocols, "admission": admission,
        "kuma_native": kuma_native, "http": http,
    }


def verify(args: dict, base: Path) -> dict:
    transaction = read_transaction(base)
    check(transaction["phase"] in ("applied", "verified"), "verify_phase_invalid")
    compose = Path(transaction["compose_path"])
    check(sha256(compose) == transaction["compose_after_sha256"], "concurrent_compose_edit_refused")
    current = inspect_object("container", transaction["container_name"])
    check(current.get("Id") == transaction["new_container_id"], "concurrent_container_change_refused")
    probes = args.get("probes", [])
    runtime_gate = critical_runtime_gate(current, transaction, probes)
    environment = current.get("Config", {}).get("Env", [])
    check("CENTER_UI_ENABLED=1" in environment, "center_ui_flag_missing")
    actual_other = all_container_shapes()
    actual_other.pop(transaction["container_name"], None)
    check(actual_other == transaction["other_containers"], "unrelated_container_changed")
    expected_paths = image_paths(transaction["manifest"])
    script = "sha256sum " + " ".join(sorted(expected_paths))
    lines = RUNNER.run(["docker", "exec", transaction["container_name"], "sh", "-c", script], timeout=90).decode().splitlines()
    actual_paths = {line.split(None, 1)[1].strip(): line.split(None, 1)[0] for line in lines}
    check(actual_paths == expected_paths, "image_runtime_source_checksum_failed")
    dns_layout = runtime_gate["dns_layout"]
    data_root = next(Path(item["source"]) for destination, item in transaction["data_mounts"].items() if destination == "/data")
    if transaction.get("overlay_policy") == "legacy_source_match":
        actual_overlays = verify_overlays(data_root, transaction["manifest"]["context_files"])
    else:
        check(transaction.get("overlay_policy") == "inert_preserved", "overlay_policy_invalid")
        actual_overlays = fingerprint_overlays(data_root)
    check(actual_overlays == transaction["overlay_hashes"], "data_overlay_changed")
    verify_optional_private_file_identity(transaction["subscription_override"])
    verify_bound_files(transaction.get("bound_files", {}), Path(transaction["backup"]) / "bound-files")
    live_sqlite_integrity(transaction)
    probe_results = runtime_gate["http"]
    transaction["phase"] = "verified"
    transaction["verified_at"] = time.time()
    transaction["verification"] = {
        "image_sources": len(expected_paths), "other_containers_unchanged": True,
        "sqlite_integrity": "ok", "probes": probe_results,
        "deployment_mode": transaction.get("deployment_mode"),
        "bound_files_unchanged": len(transaction.get("bound_files", {})),
        "runtime_code_policy": transaction["manifest"].get("runtime_code_policy"),
        "dns_corefile_unchanged": dns_layout["corefile_sha256"],
        "dns_directory_file_count": len(dns_layout["files"]),
        "dns_protocols": runtime_gate["dns_protocols"],
        "admission_runtime": runtime_gate["admission"],
        "kuma_native_runtime": runtime_gate["kuma_native"],
        "kuma_external_port_removed": transaction["old_kuma_port_published"],
        "kuma_external_port_published": False,
    }
    atomic_json(transaction_path(base), transaction)
    atomic_json(Path(transaction["backup"]) / "transaction.private.json", transaction)
    return {"phase": "verified", **transaction["verification"]}


def cancel_guard(transaction: dict) -> None:
    unit = transaction.get("guard_unit")
    if unit:
        RUNNER.run(["systemctl", "stop", unit + ".timer"], timeout=30)


def accept(args: dict, base: Path) -> dict:
    transaction = read_transaction(base)
    check(transaction["phase"] == "verified", "accept_requires_verified_phase")
    compose = Path(transaction["compose_path"])
    check(sha256(compose) == transaction["compose_after_sha256"], "concurrent_compose_edit_refused")
    current = inspect_object("container", transaction["container_name"])
    check(current.get("Id") == transaction["new_container_id"], "concurrent_container_change_refused")
    prior_probes = [item["url"] for item in transaction.get("verification", {}).get("probes", [])]
    critical_runtime_gate(current, transaction, prior_probes)
    verify_optional_private_file_identity(transaction["subscription_override"])
    legacy_detail = transaction["legacy_state"]
    legacy_path = Path(legacy_detail["path"])
    legacy_bytes = legacy_path.read_bytes()
    check(hashlib.sha256(legacy_bytes).hexdigest() == legacy_detail["before_sha256"], "legacy_installer_state_concurrent_edit_refused")
    legacy = json.loads(legacy_bytes)
    check(legacy.get("container_id") == legacy_detail["before_container_id"], "legacy_watchdog_container_identity_changed")
    check(legacy.get("manifest", {}).get("image_id") == legacy_detail["before_image_id"], "legacy_watchdog_image_identity_changed")
    previous = None
    state_path = base / "state.json"
    state_before = transaction.get("unified_state_before", {})
    if state_before.get("existed"):
        check(state_path.is_file() and sha256(state_path) == state_before.get("sha256"), "unified_state_concurrent_edit_refused")
        previous = json.loads(state_path.read_text(encoding="utf-8"))
    else:
        check(not state_path.exists(), "unified_state_concurrent_create_refused")
    accepted_at = time.time()
    legacy["container_id"] = transaction["new_container_id"]
    legacy["manifest"]["image_id"] = transaction["new_image_id"]
    legacy["unified_image"] = {
        "schema": 1, "transaction": transaction["id"], "accepted_at": accepted_at,
        "image": transaction["new_image"], "image_id": transaction["new_image_id"],
        "compose_sha256": transaction["compose_after_sha256"],
        "managed_code_overlays": False,
        "dns_config": {
            "source": transaction["dns_config"]["managed_source"],
            "target": DNS_DIRECTORY_TARGET,
            "corefile_sha256_at_accept": transaction["dns_config"]["corefile_sha256"],
            "rollback_policy": "preserve_managed_directory_after_accept",
        },
        "kuma_external_port_published": False,
    }
    legacy_after = encoded_json(legacy)
    legacy_detail["after_sha256"] = hashlib.sha256(legacy_after).hexdigest()
    transaction["phase"] = "accepting"
    transaction["accepted_at"] = accepted_at
    atomic_json(transaction_path(base), transaction)
    atomic_bytes(legacy_path, legacy_after)
    check(sha256(legacy_path) == legacy_detail["after_sha256"], "legacy_installer_state_write_failed")
    state = {
        "schema": 1,
        "kind": "unified-center-installation",
        "transaction": transaction["id"],
        "accepted_at": accepted_at,
        "service": transaction["service"],
        "container_name": transaction["container_name"],
        "container_id": transaction["new_container_id"],
        "image": transaction["new_image"],
        "image_id": transaction["new_image_id"],
        "compose_path": transaction["compose_path"],
        "compose_sha256": transaction["compose_after_sha256"],
        "manifest": transaction["manifest"],
        "backup": transaction["backup"],
        "previous_transaction": previous.get("transaction") if isinstance(previous, dict) else None,
        "legacy_installer_state_sha256": legacy_detail["after_sha256"],
        "legacy_watchdog_identity_synchronized": True,
        "managed_code_overlays": False,
        "dns_config": {
            "source": transaction["dns_config"]["managed_source"],
            "target": DNS_DIRECTORY_TARGET,
            "corefile_sha256_at_accept": transaction["dns_config"]["corefile_sha256"],
            "rollback_policy": "preserve_managed_directory_after_accept",
        },
        "kuma_external_port_published": False,
    }
    state_bytes = encoded_json(state)
    transaction["unified_state_after_sha256"] = hashlib.sha256(state_bytes).hexdigest()
    # Persist the exact after-state identity before writing it.  If the write
    # fails, the still-armed guard can distinguish and restore either the old
    # or the fully written new state without guessing.
    transaction["phase"] = "accepting"
    atomic_json(transaction_path(base), transaction)
    atomic_bytes(state_path, state_bytes)
    transaction["phase"] = "accepted"
    atomic_json(Path(transaction["backup"]) / "accepted.json", state)
    atomic_json(Path(transaction["backup"]) / "transaction.private.json", transaction)
    atomic_json(transaction_path(base), transaction)
    # The guard remains armed through both state writes.  Since the guard now
    # blocks on this operation lock, it can only observe either a recoverable
    # accepting transaction or this fully committed accepted transaction.
    cancel_guard(transaction)
    transaction_path(base).unlink()
    return {"phase": "accepted", "transaction": state["transaction"], "guard_armed": False}


def rollback(args: dict, base: Path, guard: bool = False) -> dict:
    accepted_restore = False
    if transaction_path(base).exists():
        transaction = read_transaction(base)
    else:
        if guard:
            return {"restored": False, "reason": "no_pending_transaction"}
        state_path = base / "state.json"
        if not state_path.is_file():
            return {"restored": False, "reason": "no_pending_transaction"}
        state = json.loads(state_path.read_text(encoding="utf-8"))
        check(state.get("kind") == "unified-center-installation", "unified_state_kind_invalid")
        backup_transaction = Path(state["backup"]) / "transaction.private.json"
        check(backup_transaction.is_file(), "accepted_transaction_backup_missing")
        transaction = json.loads(backup_transaction.read_text(encoding="utf-8"))
        check(transaction.get("phase") == "accepted", "accepted_transaction_phase_invalid")
        check(sha256(state_path) == transaction.get("unified_state_after_sha256"), "accepted_unified_state_concurrent_edit_refused")
        accepted_restore = True
    expected = args.get("transaction")
    if expected and expected != transaction["id"]:
        return {"restored": False, "reason": "stale_guard"}
    if transaction["phase"] == "accepted" and not accepted_restore:
        if guard:
            state_path = base / "state.json"
            legacy_path = Path(transaction["legacy_state"]["path"])
            check(state_path.is_file() and sha256(state_path) == transaction.get("unified_state_after_sha256"),
                  "accepted_unified_state_concurrent_edit_refused")
            check(legacy_path.is_file() and sha256(legacy_path) == transaction["legacy_state"].get("after_sha256"),
                  "legacy_installer_state_concurrent_edit_refused")
            check(Path(transaction["compose_path"]).is_file()
                  and sha256(Path(transaction["compose_path"])) == transaction.get("compose_after_sha256"),
                  "concurrent_compose_edit_restore_refused")
            transaction_path(base).unlink()
            return {"restored": False, "reason": "accepted_commit_confirmed", "guard_cleanup": True}
        return {"restored": False, "reason": "already_accepted"}
    compose = Path(transaction["compose_path"])
    current_hash = sha256(compose) if compose.is_file() else None
    owned_hashes = {transaction["compose_before_sha256"], transaction.get("compose_after_sha256")}
    if current_hash not in owned_hashes:
        atomic_json(Path(transaction["backup"]) / "rollback-refused.json", {
            "at": time.time(), "reason": "concurrent_compose_edit_restore_refused"
        })
        raise RuntimeError("concurrent_compose_edit_restore_refused")
    try:
        current = inspect_object("container", transaction["container_name"])
    except RuntimeError as error:
        # During a Compose recreate there can briefly be no container.  Only
        # that uncommitted apply phase is owned; all other inspect failures stop.
        if transaction["phase"] == "applying" and not transaction.get("new_container_id") and str(error) == "command_failed:docker:1":
            current = None
        else:
            raise
    if transaction.get("new_container_id") and (not current or current.get("Id") != transaction["new_container_id"]):
        atomic_json(Path(transaction["backup"]) / "rollback-refused.json", {
            "at": time.time(), "reason": "concurrent_container_change_restore_refused"
        })
        raise RuntimeError("concurrent_container_change_restore_refused")
    if not transaction.get("new_container_id") and current:
        owned_images = {transaction["old_container"]["image"], transaction["new_image_id"]}
        check(current.get("Image") in owned_images, "concurrent_container_change_restore_refused")
    legacy_detail = transaction["legacy_state"]
    legacy_path = Path(legacy_detail["path"])
    legacy_current_sha = sha256(legacy_path)
    legacy_owned_hashes = {legacy_detail["before_sha256"], legacy_detail.get("after_sha256")}
    check(legacy_current_sha in legacy_owned_hashes, "legacy_installer_state_concurrent_edit_refused")
    subscription_override_drift = False
    if transaction.get("subscription_override"):
        try:
            actual_override = optional_private_file_identity(Path(transaction["subscription_override"]["path"]))
            subscription_override_drift = not (
                actual_override["existed"] == transaction["subscription_override"]["existed"]
                and actual_override["sha256"] == transaction["subscription_override"]["sha256"]
            )
        except RuntimeError:
            subscription_override_drift = True
    backup = Path(transaction["backup"])
    before = backup / "compose.before.yml"
    check(sha256(before) == transaction["compose_before_sha256"], "compose_backup_corrupt")
    rollback_bytes = before.read_bytes()
    dns_preserved = False
    if accepted_restore and transaction.get("deployment_mode") == "unified_image_upgrade":
        # Once an accepted release can mutate managed DNS, an image rollback
        # must never silently replace that live DNS state with the pre-migration
        # read-only file.  Restore the old image/ports while retaining the
        # owned directory mount and its current contents.
        rollback_text, removed = patch_compose(
            rollback_bytes.decode("utf-8"), transaction["service"], transaction["old_image"],
            transaction["dns_config"]["managed_source"], remove_kuma_port=False,
            admission_native_ssh=transaction["old_admission_native_ssh"],
        )
        check(not removed, "accepted_upgrade_rollback_code_mounts_changed")
        rollback_bytes = rollback_text.encode("utf-8")
        validate_dns_directory(Path(transaction["dns_config"]["managed_source"]))
        dns_preserved = True
    atomic_bytes(compose, rollback_bytes)
    RUNNER.run([
        "docker", "compose", "-f", str(compose), "up", "-d", "--no-deps",
        "--no-build", "--pull", "never", transaction["service"],
    ], timeout=300)
    restored = inspect_object("container", transaction["container_name"])
    check(restored.get("Image") == transaction["old_container"]["image"], "old_image_not_restored")
    check(stable_runtime(
        restored,
        set(transaction.get("managed_mounts", {})) | {DNS_FILE_TARGET, DNS_DIRECTORY_TARGET},
        {KUMA_CONTAINER_PORT},
    ) == transaction["old_runtime"], "old_runtime_contract_not_restored")
    restored_environment = set(restored.get("Config", {}).get("Env", []))
    check("ADMISSION_NATIVE_SSH=" + transaction["old_admission_native_ssh"] in restored_environment,
          "old_admission_native_ssh_not_restored")
    restored_port = restored.get("HostConfig", {}).get("PortBindings", {}).get(KUMA_CONTAINER_PORT)
    if transaction["old_kuma_port_published"]:
        check(isinstance(restored_port, list) and len(restored_port) == 1
              and str(restored_port[0].get("HostPort")) == KUMA_HOST_PORT,
              "old_kuma_port_not_restored")
    else:
        check(not restored_port, "old_kuma_port_absence_not_restored")
    if dns_preserved:
        live_digest = validate_dns_directory(Path(transaction["dns_config"]["managed_source"]))["corefile_sha256"]
        runtime_transaction = dict(transaction)
        runtime_transaction["dns_config"] = dict(transaction["dns_config"], corefile_sha256=live_digest)
        verify_dns_runtime(restored, runtime_transaction)
    dns_stage_cleanup = ({"removed": False, "reason": "accepted_dns_preserved"}
                         if accepted_restore else cleanup_unaccepted_dns_stage(transaction))
    check(sha256(legacy_path) == legacy_current_sha, "legacy_installer_state_concurrent_edit_refused")
    legacy_before = json.loads((backup / "legacy-state.before.json").read_text(encoding="utf-8"))
    legacy_before["container_id"] = restored["Id"]
    legacy_before["manifest"]["image_id"] = transaction["old_container"]["image"]
    if dns_preserved and isinstance(legacy_before.get("unified_image"), dict):
        legacy_before["unified_image"]["compose_sha256"] = sha256(compose)
        legacy_before["unified_image"]["dns_config"] = {
            "source": transaction["dns_config"]["managed_source"],
            "target": DNS_DIRECTORY_TARGET,
            "rollback_policy": "preserved_live_managed_directory",
        }
        legacy_before["unified_image"]["kuma_external_port_published"] = transaction["old_kuma_port_published"]
    atomic_bytes(legacy_path, encoded_json(legacy_before))
    actual_other = all_container_shapes()
    actual_other.pop(transaction["container_name"], None)
    check(actual_other == transaction["other_containers"], "unrelated_container_changed_during_rollback")
    receipt = {
        "at": time.time(), "restored": True, "old_image_restored": True,
        "compose_restored": True, "data_restored": False,
        "compose_exact_predeployment": not dns_preserved,
        "managed_dns_preserved": dns_preserved,
        "dns_stage_cleanup": dns_stage_cleanup,
        "subscription_override_drift": subscription_override_drift,
        "live_subscription_override_preserved": True,
        "old_image_override_behavior": (
            "retained_but_not_interpreted_until_reupgrade" if subscription_override_drift
            else "unchanged_from_deployment_start"
        ),
        "data_policy": "retained_new_history_and_live_databases",
        "trigger": "guard" if guard else "manual",
    }
    atomic_json(backup / "rollback-result.json", receipt)
    if transaction_path(base).exists():
        transaction_path(base).unlink()
    restore_unified_state = accepted_restore or transaction.get("phase") == "accepting"
    if restore_unified_state:
        state_path = base / "state.json"
        state_before_detail = transaction.get("unified_state_before", {})
        current_state_sha = sha256(state_path) if state_path.is_file() else None
        owned_state_hashes = {transaction.get("unified_state_after_sha256")}
        if state_before_detail.get("existed"):
            owned_state_hashes.add(state_before_detail.get("sha256"))
        else:
            owned_state_hashes.add(None)
        check(current_state_sha in owned_state_hashes, "accepted_unified_state_concurrent_edit_refused")
        before_state = backup / "unified-state.before.json"
        if state_before_detail.get("existed"):
            check(before_state.is_file() and sha256(before_state) == state_before_detail["sha256"], "unified_state_backup_corrupt")
            previous_state = json.loads(before_state.read_text(encoding="utf-8"))
            if previous_state.get("container_name") == transaction["container_name"]:
                previous_state["container_id"] = restored["Id"]
                previous_state["image_id"] = transaction["old_container"]["image"]
                previous_state["compose_sha256"] = sha256(compose)
                if dns_preserved:
                    previous_state["dns_config"] = {
                        "source": transaction["dns_config"]["managed_source"],
                        "target": DNS_DIRECTORY_TARGET,
                        "rollback_policy": "preserved_live_managed_directory",
                    }
                    previous_state["kuma_external_port_published"] = transaction["old_kuma_port_published"]
            atomic_bytes(state_path, encoded_json(previous_state))
        else:
            state_path.unlink(missing_ok=True)
    if not guard and not accepted_restore:
        cancel_guard(transaction)
    return receipt


def main(args: dict) -> dict:
    base = Path(args.get("state_dir", DEFAULT_STATE_DIR)).resolve()
    check(str(base) != "/" and len(base.parts) >= 3, "unsafe_state_directory")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    action = args["action"]
    with (base / "operations.lock").open("a") as lock:
        os.chmod(base / "operations.lock", 0o600)
        # A one-shot external guard must wait for an in-flight apply/accept to
        # release ownership; a non-blocking miss would permanently consume the
        # only rollback attempt.  Interactive actions continue to fail fast.
        flags = fcntl.LOCK_EX if action == "guard" else fcntl.LOCK_EX | fcntl.LOCK_NB
        fcntl.flock(lock, flags)
        if action == "prepare":
            return prepare(args, base)
        if action == "apply":
            return apply(args, base)
        if action == "verify":
            return verify(args, base)
        if action == "accept":
            return accept(args, base)
        if action == "rollback":
            return rollback(args, base)
        if action == "guard":
            return rollback(args, base, guard=True)
        raise RuntimeError("unsupported_action")


if __name__ == "__main__":
    try:
        request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        print(json.dumps({"ok": True, "result": main(request)}, ensure_ascii=False))
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) and re.fullmatch(r"[A-Za-z0-9_:.+-]{1,160}", str(error)) else type(error).__name__
        print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
        raise SystemExit(1)
