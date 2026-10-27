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
import subprocess
import sys
import tempfile
import time
import urllib.request


BASE_IMAGE_ID = "sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2"
DEFAULT_STATE_DIR = Path("/opt/lan-center-unified")
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


def patch_compose(text: str, service: str, image: str) -> tuple[str, dict[str, str]]:
    """Conservatively patch only one YAML service block.

    JSON Compose and advanced YAML constructs are deliberately refused because
    a lossy rewrite could destroy interpolation, comments or private settings.
    """
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

    # Remove exactly the three known code binds, retaining /data and all other
    # volumes.  Any other image-code shadow is rejected before this function.
    direct_positions = [(i, direct.match(lines[i]).group(1)) for i in range(start + 1, end) if direct.match(lines[i])]
    volume_rows = [i for i, key in direct_positions if key == "volumes"]
    check(len(volume_rows) == 1, "compose_volumes_block_missing_or_ambiguous")
    volumes_start = volume_rows[0]
    volumes_end = next((i for i, _ in direct_positions if i > volumes_start), end)
    removed: dict[str, str] = {}
    remove_indices: list[int] = []
    item_prefix = child + "  - "
    for index in range(volumes_start + 1, volumes_end):
        if not lines[index].strip() or lines[index].lstrip().startswith("#"):
            continue
        check(lines[index].startswith(item_prefix), "long_form_volume_requires_review")
        source, target = parse_short_mount(lines[index][len(item_prefix):].split(" #", 1)[0])
        if target in PROTECTED_IMAGE_TARGETS and target not in MANAGED_CODE_TARGETS:
            raise RuntimeError("private_image_code_override_requires_review")
        if target in MANAGED_CODE_TARGETS:
            check(target not in removed, "duplicate_managed_code_mount")
            removed[target] = source
            remove_indices.append(index)
    check(set(removed) == MANAGED_CODE_TARGETS, "managed_code_mount_set_changed")
    for index in reversed(remove_indices):
        del lines[index]
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


def stable_runtime(container: dict, exclude_mounts: set[str] | None = None) -> dict:
    environment = sorted(
        item for item in container.get("Config", {}).get("Env", [])
        if not item.startswith("CENTER_UI_ENABLED=")
    )
    host = container.get("HostConfig", {})
    return {
        "ports": host.get("PortBindings", {}),
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


def validate_mount_overrides(mounts: list[dict]) -> dict[str, str]:
    managed: dict[str, str] = {}
    for item in mounts:
        target = item.get("Destination")
        if target in PROTECTED_IMAGE_TARGETS:
            check(target in MANAGED_CODE_TARGETS, "private_image_code_override_requires_review")
            check(item.get("Type") == "bind" and not item.get("RW", True), "managed_code_mount_not_read_only")
            check(target not in managed, "duplicate_managed_code_mount")
            managed[target] = item.get("Source")
    check(set(managed) == MANAGED_CODE_TARGETS, "managed_code_mount_set_changed")
    return managed


def transaction_path(base: Path) -> Path:
    return base / "transaction.json"


def read_transaction(base: Path) -> dict:
    path = transaction_path(base)
    check(path.is_file(), "no_pending_transaction")
    return json.loads(path.read_text(encoding="utf-8"))


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
    corefile = [item for item in mounts if item.get("Destination") == "/etc/coredns/Corefile" and item.get("Type") == "bind"]
    check(len(corefile) == 1 and not corefile[0].get("RW", True), "readonly_corefile_bind_mount_required")
    check(str(data_root.resolve()) == str(Path(expected.get("data_source", "")).resolve()), "production_snapshot_data_mount_changed")
    check(str(Path(app_data[0]["Source"]).resolve()) == str(Path(expected.get("app_data_source", "")).resolve()), "production_snapshot_app_data_mount_changed")
    check(str(Path(corefile[0]["Source"]).resolve()) == str(Path(expected.get("corefile_source", "")).resolve()), "production_snapshot_corefile_mount_changed")
    legacy_path = Path(args.get("legacy_state_path", LEGACY_STATE)).resolve()
    check(legacy_path == LEGACY_STATE, "legacy_installer_state_path_invalid")
    check(legacy_path.is_file(), "legacy_installer_state_missing")
    legacy_bytes = legacy_path.read_bytes()
    legacy = json.loads(legacy_bytes)
    check(legacy.get("container_name") == container_name, "legacy_installer_container_name_mismatch")
    check(legacy.get("container_id") == current.get("Id"), "legacy_watchdog_container_identity_mismatch")
    check(legacy.get("manifest", {}).get("image_id") == current.get("Image"), "legacy_watchdog_image_identity_mismatch")
    managed_mounts = validate_mount_overrides(mounts)
    # Source YAML must describe the same three removable mounts.
    _, raw_source_mounts = patch_compose(compose.read_text(encoding="utf-8"), service, image_name)
    source_mounts = normalized_mounts(raw_source_mounts, compose.parent)
    check(set(source_mounts) == set(managed_mounts), "compose_runtime_code_mount_mismatch")
    for target, source in source_mounts.items():
        check(Path(source).resolve() == Path(managed_mounts[target]).resolve(), "compose_runtime_code_mount_mismatch")
    overlay_hashes = verify_overlays(data_root, manifest.get("context_files", {}))
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
    unified_state_path = base / "state.json"
    unified_state_bytes = unified_state_path.read_bytes() if unified_state_path.exists() else None
    if unified_state_bytes is not None:
        atomic_bytes(backup / "unified-state.before.json", unified_state_bytes)
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
        "schema": 1,
        "id": stamp,
        "phase": "prepared",
        "created_at": time.time(),
        "compose_path": str(compose),
        "compose_before_sha256": hashlib.sha256(compose_bytes).hexdigest(),
        "service": service,
        "container_name": container_name,
        "old_container": container_shape(current),
        "old_runtime": stable_runtime(current, MANAGED_CODE_TARGETS),
        "old_image": current.get("Config", {}).get("Image"),
        "new_image": image_name,
        "new_image_id": image.get("Id"),
        "manifest": manifest,
        "backup": str(backup),
        "managed_mounts": managed_mounts,
        "data_mounts": snapshots,
        "overlay_hashes": overlay_hashes,
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
    return unit


def apply(args: dict, base: Path) -> dict:
    transaction = read_transaction(base)
    check(transaction["phase"] == "prepared", "apply_phase_invalid")
    assert_owned_before_apply(transaction)
    backup = Path(transaction["backup"])
    for detail in transaction["data_mounts"].values():
        verify_snapshot(detail["receipt"], backup / detail["backup"])
    unit = start_guard(base, transaction)
    source = Path(transaction["compose_path"])
    patched, raw_removed = patch_compose(source.read_text(encoding="utf-8"), transaction["service"], transaction["new_image"])
    removed = normalized_mounts(raw_removed, source.parent)
    check(removed == transaction["managed_mounts"], "managed_mounts_changed_after_prepare")
    transaction["guard_unit"] = unit
    transaction["phase"] = "applying"
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


def verify(args: dict, base: Path) -> dict:
    transaction = read_transaction(base)
    check(transaction["phase"] in ("applied", "verified"), "verify_phase_invalid")
    compose = Path(transaction["compose_path"])
    check(sha256(compose) == transaction["compose_after_sha256"], "concurrent_compose_edit_refused")
    current = inspect_object("container", transaction["container_name"])
    check(current.get("Id") == transaction["new_container_id"], "concurrent_container_change_refused")
    check(current.get("Image") == transaction["new_image_id"], "new_container_image_mismatch")
    check(current.get("State", {}).get("Running") is True, "new_container_not_running")
    check(stable_runtime(current) == transaction["old_runtime"], "runtime_contract_changed")
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
    data_root = next(Path(item["source"]) for destination, item in transaction["data_mounts"].items() if destination == "/data")
    check(verify_overlays(data_root, transaction["manifest"]["context_files"]) == transaction["overlay_hashes"], "data_overlay_changed")
    live_sqlite_integrity(transaction)
    probes = args.get("probes", [])
    check(isinstance(probes, list) and len(probes) <= 12, "probe_list_invalid")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    probe_results = []
    for probe in probes:
        check(isinstance(probe, str) and re.fullmatch(r"http://(?:127\.0\.0\.1|10\.88\.0\.249):[0-9]{1,5}/[^\s]*", probe), "probe_url_not_local")
        with opener.open(probe, timeout=8) as response:
            check(200 <= response.status < 400, "http_probe_failed")
            response.read(1024 * 1024)
        probe_results.append({"url": probe, "status": "ok"})
    transaction["phase"] = "verified"
    transaction["verified_at"] = time.time()
    transaction["verification"] = {
        "image_sources": len(expected_paths), "other_containers_unchanged": True,
        "sqlite_integrity": "ok", "probes": probe_results,
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
    # Cancel only after every ownership check, and before either state mutation.
    cancel_guard(transaction)
    accepted_at = time.time()
    legacy["container_id"] = transaction["new_container_id"]
    legacy["manifest"]["image_id"] = transaction["new_image_id"]
    legacy["unified_image"] = {
        "schema": 1, "transaction": transaction["id"], "accepted_at": accepted_at,
        "image": transaction["new_image"], "image_id": transaction["new_image_id"],
        "compose_sha256": transaction["compose_after_sha256"],
        "managed_code_overlays": False,
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
    }
    state_bytes = encoded_json(state)
    transaction["unified_state_after_sha256"] = hashlib.sha256(state_bytes).hexdigest()
    transaction["phase"] = "accepted"
    atomic_bytes(state_path, state_bytes)
    atomic_json(Path(transaction["backup"]) / "accepted.json", state)
    atomic_json(Path(transaction["backup"]) / "transaction.private.json", transaction)
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
    backup = Path(transaction["backup"])
    before = backup / "compose.before.yml"
    check(sha256(before) == transaction["compose_before_sha256"], "compose_backup_corrupt")
    atomic_bytes(compose, before.read_bytes())
    RUNNER.run([
        "docker", "compose", "-f", str(compose), "up", "-d", "--no-deps",
        "--no-build", "--pull", "never", transaction["service"],
    ], timeout=300)
    restored = inspect_object("container", transaction["container_name"])
    check(restored.get("Image") == transaction["old_container"]["image"], "old_image_not_restored")
    check(sha256(legacy_path) == legacy_current_sha, "legacy_installer_state_concurrent_edit_refused")
    legacy_before = json.loads((backup / "legacy-state.before.json").read_text(encoding="utf-8"))
    legacy_before["container_id"] = restored["Id"]
    legacy_before["manifest"]["image_id"] = transaction["old_container"]["image"]
    atomic_bytes(legacy_path, encoded_json(legacy_before))
    actual_other = all_container_shapes()
    actual_other.pop(transaction["container_name"], None)
    check(actual_other == transaction["other_containers"], "unrelated_container_changed_during_rollback")
    receipt = {
        "at": time.time(), "restored": True, "old_image_restored": True,
        "compose_restored": True, "data_restored": False,
        "data_policy": "retained_new_history_and_live_databases",
        "trigger": "guard" if guard else "manual",
    }
    atomic_json(backup / "rollback-result.json", receipt)
    if transaction_path(base).exists():
        transaction_path(base).unlink()
    if accepted_restore:
        state_path = base / "state.json"
        check(sha256(state_path) == transaction["unified_state_after_sha256"], "accepted_unified_state_concurrent_edit_refused")
        before_state = backup / "unified-state.before.json"
        if transaction.get("unified_state_before", {}).get("existed"):
            check(before_state.is_file() and sha256(before_state) == transaction["unified_state_before"]["sha256"], "unified_state_backup_corrupt")
            previous_state = json.loads(before_state.read_text(encoding="utf-8"))
            if previous_state.get("container_name") == transaction["container_name"]:
                previous_state["container_id"] = restored["Id"]
                previous_state["image_id"] = transaction["old_container"]["image"]
                previous_state["compose_sha256"] = transaction["compose_before_sha256"]
            atomic_bytes(state_path, encoded_json(previous_state))
        else:
            state_path.unlink()
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
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
