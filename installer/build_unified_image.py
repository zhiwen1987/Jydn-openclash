"""Create a deterministic, credential-free Docker context and image bundle.

This utility never connects to production and never uses ``docker commit``.
The caller builds ``Dockerfile`` from the emitted context with the already
audited base image present in the local Docker content store, exports the
result with ``docker image save``, then calls ``bundle``.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BASE_IMAGE = "sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2"
SCHEMA = 1
LOCAL_FILES = (
    "node_links.py", "local_source.py", "local_web.py", "editor.html",
    "editor.js", "subscription_usage.py", "usage.html", "usage_ui.js",
)
REQUIRED_UNIFIED = ("unified_center.py", "unified_proxy.py", "assets/logo.png")
PRIVATE_NAMES = re.compile(
    r"(?:^|[-_.])(token|secret|credential|private|password|passwd|\.env|data|db|sqlite)(?:$|[-_.])",
    re.IGNORECASE,
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".unified-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def checked_copy(source: Path, target: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise RuntimeError(f"required_regular_file_missing:{source.name}")
    if PRIVATE_NAMES.search(source.name):
        raise RuntimeError(f"private_filename_refused:{source.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = source.read_bytes()
    if source.suffix in {".py", ".sh", ".js", ".html", ".json", ".md"}:
        payload = payload.replace(b"\r\n", b"\n")
    target.write_bytes(payload)


def deterministic_tar(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as raw, gzip.GzipFile(
        fileobj=raw, mode="wb", compresslevel=6, mtime=0
    ) as compressed, tarfile.open(fileobj=compressed, mode="w|") as archive:
        for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise RuntimeError("symlink_in_build_context")
            if not path.is_file():
                continue
            relative = path.relative_to(source).as_posix()
            info = archive.gettarinfo(str(path), relative)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.mode = 0o755 if path.suffix == ".sh" else 0o644
            with path.open("rb") as stream:
                archive.addfile(info, stream)


def file_manifest(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): digest(path)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    }


def validate_docker_archive(path: Path, image_id: str) -> None:
    expected = image_id.removeprefix("sha256:")
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            for member in members:
                relative = Path(member.name)
                if relative.is_absolute() or ".." in relative.parts or not (member.isfile() or member.isdir()):
                    raise RuntimeError("unsafe_docker_archive_member")
            manifest_member = archive.getmember("manifest.json")
            with archive.extractfile(manifest_member) as stream:
                manifest = json.load(stream)
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise RuntimeError("docker_archive_image_count_invalid")
            config_name = manifest[0].get("Config")
            if not isinstance(config_name, str):
                raise RuntimeError("docker_archive_config_missing")
            with archive.extractfile(archive.getmember(config_name)) as stream:
                config = stream.read()
            if hashlib.sha256(config).hexdigest() != expected:
                raise RuntimeError("docker_archive_image_id_mismatch")
            names = {member.name for member in members}
            if not all(isinstance(layer, str) and layer in names for layer in manifest[0].get("Layers", [])):
                raise RuntimeError("docker_archive_layer_missing")
    except (tarfile.TarError, KeyError, json.JSONDecodeError):
        raise RuntimeError("docker_archive_invalid") from None


def build_context(output: Path, version: str, source_commit: str) -> dict[str, object]:
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("context_output_not_empty")
    output.mkdir(parents=True, exist_ok=True)
    checked_copy(HERE / "Dockerfile.unified", output / "Dockerfile")
    runtime = HERE / "runtime"
    for path in sorted((runtime / "upstream").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            checked_copy(path, output / "runtime/upstream" / path.relative_to(runtime / "upstream"))
    for name in ("portable_subscriptions.py",):
        checked_copy(runtime / name, output / "runtime" / name)
    local = REPO / "monitoring/lan-center/local-subscription"
    for name in LOCAL_FILES:
        checked_copy(local / name, output / "local-subscription" / name)
    unified = REPO / "monitoring/lan-center/unified-center"
    for name in REQUIRED_UNIFIED:
        checked_copy(unified / name, output / "unified-center" / name)
    # Only runtime assets enter the image.  Tests, notes and __pycache__ remain
    # source-side evidence and cannot accidentally enlarge the production image.
    for path in sorted((unified / "assets").rglob("*")):
        if path.is_file() and path.relative_to(unified).as_posix() not in REQUIRED_UNIFIED:
            check_suffix = path.suffix.lower()
            if check_suffix not in {".css", ".html", ".js", ".png", ".svg", ".webp", ".ico"}:
                raise RuntimeError("unsupported_unified_asset_type:" + check_suffix.lstrip("."))
            checked_copy(path, output / "unified-center" / path.relative_to(unified))
    files = file_manifest(output)
    manifest = {
        "schema": SCHEMA,
        "kind": "unified-center-build-context",
        "version": version,
        "platform": "linux/amd64",
        "base_image_id": BASE_IMAGE,
        "source_commit": source_commit,
        "files": files,
        "contains_production_data": False,
        "build_method": "docker_build_then_docker_image_save",
        "forbidden_method": "docker_commit",
    }
    atomic_json(output / "context.manifest.json", manifest)
    archive = output.parent / (output.name + ".tar.gz")
    deterministic_tar(output, archive)
    result = dict(manifest)
    result.update(context=str(output), context_archive=str(archive), context_archive_sha256=digest(archive))
    return result


def bundle(context: Path, image_archive: Path, image_id: str, output: Path, version: str) -> dict[str, object]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise RuntimeError("invalid_image_id")
    if not image_archive.is_file():
        raise RuntimeError("image_archive_missing")
    validate_docker_archive(image_archive, image_id)
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("bundle_output_not_empty")
    context_manifest = json.loads((context / "context.manifest.json").read_text(encoding="utf-8"))
    if context_manifest.get("base_image_id") != BASE_IMAGE:
        raise RuntimeError("base_image_identity_changed")
    expected = context_manifest.get("files", {})
    actual = file_manifest(context)
    actual.pop("context.manifest.json", None)
    if actual != expected:
        raise RuntimeError("build_context_changed_after_manifest")
    output.mkdir(parents=True, exist_ok=True)
    copied = output / "clash-center-unified.tar"
    shutil.copyfile(image_archive, copied)
    copied_context_manifest = output / "context.manifest.json"
    shutil.copyfile(context / "context.manifest.json", copied_context_manifest)
    manifest = {
        "schema": SCHEMA,
        "kind": "unified-center-image",
        "version": version,
        "platform": "linux/amd64",
        "base_image_id": BASE_IMAGE,
        "image_id": image_id,
        "image_archive": copied.name,
        "image_archive_sha256": digest(copied),
        "context_manifest": copied_context_manifest.name,
        "context_manifest_sha256": digest(copied_context_manifest),
        "source_commit": context_manifest.get("source_commit"),
        "context_files": expected,
        "contains_production_data": False,
        "build_method": "docker_build_then_docker_image_save",
    }
    atomic_json(output / "manifest.json", manifest)
    sums = (
        f"{manifest['image_archive_sha256']}  {copied.name}\n"
        f"{manifest['context_manifest_sha256']}  {copied_context_manifest.name}\n"
        f"{digest(output / 'manifest.json')}  manifest.json\n"
    )
    (output / "SHA256SUMS").write_text(sums, encoding="ascii", newline="\n")
    deterministic_tar(output, output.parent / (output.name + ".tar.gz"))
    return {"bundle": str(output), "manifest": manifest}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    context = sub.add_parser("context")
    context.add_argument("--output", type=Path, required=True)
    context.add_argument("--version", required=True)
    context.add_argument("--source-commit", default="uncommitted")
    package = sub.add_parser("bundle")
    package.add_argument("--context", type=Path, required=True)
    package.add_argument("--image-archive", type=Path, required=True)
    package.add_argument("--image-id", required=True)
    package.add_argument("--output", type=Path, required=True)
    package.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.action == "context":
        result = build_context(args.output.resolve(), args.version, args.source_commit)
    else:
        result = bundle(args.context.resolve(), args.image_archive.resolve(), args.image_id, args.output.resolve(), args.version)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
