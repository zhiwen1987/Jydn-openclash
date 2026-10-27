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
from pathlib import Path, PurePosixPath
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


OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_GZIP_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"
DIGEST = re.compile(r"sha256:([0-9a-f]{64})")


def strict_json_bytes(payload: bytes, code: str):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError("docker_archive_json_duplicate_key")
            value[key] = item
        return value
    try:
        return json.loads(payload, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError(code) from None


def validate_docker_archive(path: Path, image_id: str) -> None:
    expected_match = DIGEST.fullmatch(image_id)
    if not expected_match:
        raise RuntimeError("invalid_image_id")
    expected = expected_match.group(1)
    try:
        with tarfile.open(path, "r:*") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                name = member.name
                raw = name[:-1] if member.isdir() and name.endswith("/") else name
                parts = raw.split("/")
                relative = PurePosixPath(raw)
                if (not raw or "\\" in raw or relative.is_absolute()
                        or any(part in ("", ".", "..") for part in parts)
                        or not (member.isfile() or member.isdir())):
                    raise RuntimeError("unsafe_docker_archive_member")
                if name in members:
                    raise RuntimeError("duplicate_docker_archive_member")
                members[name] = member

            def member_bytes(name: str, max_size: int = 16 * 1024 * 1024) -> bytes:
                member = members.get(name)
                if not member or not member.isfile():
                    raise RuntimeError("docker_archive_referenced_file_missing")
                if member.size > max_size:
                    raise RuntimeError("docker_archive_json_too_large")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError("docker_archive_referenced_file_missing")
                with stream:
                    return stream.read()

            blob_members: dict[str, tarfile.TarInfo] = {}
            for name, member in members.items():
                if not member.isfile() or not name.startswith("blobs/"):
                    continue
                match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
                if not match:
                    raise RuntimeError("docker_archive_blob_path_invalid")
                value = hashlib.sha256()
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError("docker_archive_blob_missing")
                with stream:
                    while block := stream.read(1024 * 1024):
                        value.update(block)
                if value.hexdigest() != match.group(1):
                    raise RuntimeError("docker_archive_blob_digest_mismatch")
                blob_members[match.group(1)] = member

            def descriptor_blob(descriptor: object, media_types: set[str], read_payload: bool = True) -> tuple[str, bytes]:
                if not isinstance(descriptor, dict):
                    raise RuntimeError("docker_archive_descriptor_media_type_invalid")
                media_type = descriptor.get("mediaType")
                if not isinstance(media_type, str) or media_type not in media_types:
                    raise RuntimeError("docker_archive_descriptor_media_type_invalid")
                digest_value = descriptor.get("digest")
                digest_match = DIGEST.fullmatch(digest_value) if isinstance(digest_value, str) else None
                size = descriptor.get("size")
                if not digest_match or isinstance(size, bool) or not isinstance(size, int) or size < 0:
                    raise RuntimeError("docker_archive_descriptor_invalid")
                encoded = digest_match.group(1)
                member = blob_members.get(encoded)
                if member is None:
                    raise RuntimeError("docker_archive_descriptor_blob_missing")
                if member.size != size:
                    raise RuntimeError("docker_archive_descriptor_size_mismatch")
                return encoded, member_bytes("blobs/sha256/" + encoded) if read_payload else b""

            has_layout = "oci-layout" in members or "index.json" in members
            if has_layout:
                if "oci-layout" not in members or "index.json" not in members:
                    raise RuntimeError("docker_archive_oci_layout_incomplete")
                layout = strict_json_bytes(member_bytes("oci-layout"), "docker_archive_oci_layout_invalid")
                if not isinstance(layout, dict) or layout.get("imageLayoutVersion") != "1.0.0":
                    raise RuntimeError("docker_archive_oci_layout_invalid")
                index = strict_json_bytes(member_bytes("index.json"), "docker_archive_oci_index_invalid")
                if (not isinstance(index, dict) or index.get("schemaVersion") != 2
                        or index.get("mediaType") != OCI_INDEX
                        or not isinstance(index.get("manifests"), list)
                        or len(index["manifests"]) != 1):
                    raise RuntimeError("docker_archive_oci_root_count_invalid")
                root = index["manifests"][0]
                platform = root.get("platform") if isinstance(root, dict) else None
                if platform is not None and (not isinstance(platform, dict)
                        or platform.get("os") != "linux" or platform.get("architecture") != "amd64"):
                    raise RuntimeError("docker_archive_oci_platform_invalid")
                root_digest, manifest_payload = descriptor_blob(root, {OCI_MANIFEST})
                if root_digest != expected:
                    raise RuntimeError("docker_archive_image_id_mismatch")
                manifest = strict_json_bytes(manifest_payload, "docker_archive_oci_manifest_invalid")
                if (not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2
                        or manifest.get("mediaType") != OCI_MANIFEST
                        or not isinstance(manifest.get("layers"), list) or not manifest["layers"]):
                    raise RuntimeError("docker_archive_oci_manifest_invalid")
                config_digest, config_payload = descriptor_blob(manifest.get("config"), {OCI_CONFIG})
                config = strict_json_bytes(config_payload, "docker_archive_oci_config_invalid")
                if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "amd64":
                    raise RuntimeError("docker_archive_oci_platform_invalid")
                layer_paths: list[str] = []
                layer_descriptors: list[tuple[str, tarfile.TarInfo]] = []
                for descriptor in manifest["layers"]:
                    layer_digest, _ = descriptor_blob(descriptor, {OCI_GZIP_LAYER, DOCKER_GZIP_LAYER}, read_payload=False)
                    layer_paths.append("blobs/sha256/" + layer_digest)
                    layer_descriptors.append((layer_digest, blob_members[layer_digest]))
                rootfs = config.get("rootfs")
                diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
                if (not isinstance(rootfs, dict) or rootfs.get("type") != "layers"
                        or not isinstance(diff_ids, list) or len(diff_ids) != len(layer_descriptors)
                        or not all(isinstance(value, str) and DIGEST.fullmatch(value) for value in diff_ids)):
                    raise RuntimeError("docker_archive_oci_diff_ids_invalid")
                uncompressed: dict[str, str] = {}
                for index_value, (layer_digest, member) in enumerate(layer_descriptors):
                    if layer_digest not in uncompressed:
                        value = hashlib.sha256()
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise RuntimeError("docker_archive_layer_missing")
                        try:
                            with stream, gzip.GzipFile(fileobj=stream) as expanded:
                                while block := expanded.read(1024 * 1024):
                                    value.update(block)
                        except (OSError, EOFError):
                            raise RuntimeError("docker_archive_layer_compression_invalid") from None
                        uncompressed[layer_digest] = value.hexdigest()
                    if diff_ids[index_value] != "sha256:" + uncompressed[layer_digest]:
                        raise RuntimeError("docker_archive_layer_diff_id_mismatch")
                legacy = strict_json_bytes(member_bytes("manifest.json"), "docker_archive_manifest_invalid")
                if not isinstance(legacy, list) or len(legacy) != 1 or not isinstance(legacy[0], dict):
                    raise RuntimeError("docker_archive_image_count_invalid")
                if legacy[0].get("Config") != "blobs/sha256/" + config_digest:
                    raise RuntimeError("docker_archive_legacy_config_mismatch")
                if legacy[0].get("Layers") != layer_paths:
                    raise RuntimeError("docker_archive_legacy_layers_mismatch")
            else:
                legacy = strict_json_bytes(member_bytes("manifest.json"), "docker_archive_manifest_invalid")
                if not isinstance(legacy, list) or len(legacy) != 1 or not isinstance(legacy[0], dict):
                    raise RuntimeError("docker_archive_image_count_invalid")
                config_name = legacy[0].get("Config")
                if not isinstance(config_name, str):
                    raise RuntimeError("docker_archive_config_missing")
                config_payload = member_bytes(config_name)
                if hashlib.sha256(config_payload).hexdigest() != expected:
                    raise RuntimeError("docker_archive_image_id_mismatch")
                layers = legacy[0].get("Layers")
                if not isinstance(layers, list) or not all(isinstance(layer, str) and layer in members and members[layer].isfile() for layer in layers):
                    raise RuntimeError("docker_archive_layer_missing")
    except (tarfile.TarError, KeyError):
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
