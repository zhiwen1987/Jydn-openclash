#!/usr/bin/env python3
"""Offline, fail-closed supply-chain evidence candidate.

This verifier intentionally cannot authorize an image.  It proves structural and
digest relationships between an OCI image, an SPDX SBOM, an in-toto statement,
and a signature-verifier receipt.  Cryptographic trust is still an external,
unimplemented gate, so every successful run is BLOCKED and exits 78.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import gzip
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import tempfile
import time
import zlib
from dataclasses import dataclass
from typing import Any, Iterable


POLICY_SCHEMA = "chengwang.supply-chain-policy/v1"
REPORT_SCHEMA = "chengwang.supply-chain-verification/v1"
RECEIPT_SCHEMA = "chengwang.signature-verifier-receipt/v1"
SIGNATURE_BUNDLE_SCHEMA = "chengwang.signature-bundle-candidate/v1"
OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
OCI_CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
OCI_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
SUPPORTED_SIGNATURE_ALGORITHMS = {"ECDSA_P256_SHA256", "ED25519"}
IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
SPDX_VERSION = "SPDX-2.3"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_REPOSITORY = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$")
IDENTITY = re.compile(r"^[\x21-\x7e]{1,512}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+,-]{0,511}$")
PORT_SPEC = re.compile(r"^([0-9]{1,5})/(tcp|udp|sctp)$")
RFC3339_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
OCI_RFC3339_NANO = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$")
MAX_JSON = 16 * 1024 * 1024
MAX_LAYER = 1024 * 1024 * 1024
MAX_UNCOMPRESSED_LAYER = 4 * 1024 * 1024 * 1024
MAX_TOTAL_LAYERS = 4 * 1024 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_LAYERS = 8 * 1024 * 1024 * 1024
MAX_LAYER_EXPANSION_RATIO = 512
MAX_LAYERS = 256
MAX_TAR_ENTRIES = 100_000
MAX_LAYER_PROCESS_SECONDS = 60
MAX_VALIDATION_SECONDS = 300
MAX_SIGNATURES = 16
MAX_SUBJECTS = 16
MAX_PACKAGES = 100000
BLOCKED_EXIT = 78


class ContractError(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number is prohibited: {value}")


def _reject_float(value: str) -> None:
    raise ContractError(f"floating-point JSON numbers are prohibited: {value}")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_json_shape(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > 1_000_000:
            raise ContractError("JSON document has too many values")
        if depth > 64:
            raise ContractError("JSON document nesting exceeds 64 levels")
        if isinstance(current, dict):
            for key in current:
                _text(key, "JSON object key", MAX_JSON, allow_empty=True)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            _text(current, "JSON string", MAX_JSON, allow_empty=True)
        elif not isinstance(current, (str, int, bool, type(None))):
            raise ContractError(f"unsupported JSON value type: {type(current).__name__}")


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    return value


def _array(value: Any, name: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ContractError(f"{name} must be an array with at most {maximum} entries")
    return value


def _text(value: Any, name: str, maximum: int = 4096, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ContractError(f"{name} must be {qualifier} no longer than {maximum} bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{name} must contain valid Unicode scalar values") from exc
    if len(encoded) > maximum:
        raise ContractError(f"{name} exceeds {maximum} UTF-8 bytes")
    return value


def _string(value: Any, name: str, maximum: int = 4096) -> str:
    return _text(value, name, maximum, allow_empty=False)


def _integer(value: Any, name: str, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{name} must be boolean")
    return value


def _exact_keys(value: dict[str, Any], required: Iterable[str], optional: Iterable[str], name: str) -> None:
    required_set, optional_set = set(required), set(optional)
    missing = required_set - value.keys()
    unknown = value.keys() - required_set - optional_set
    if missing:
        raise ContractError(f"{name} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ContractError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")


def _digest(value: Any, name: str) -> str:
    text = _string(value, name, 200)
    if not text.startswith("sha256:") or not HEX64.fullmatch(text[7:]):
        raise ContractError(f"{name} must use lowercase sha256:<64 hex>")
    return text


def _timestamp(value: Any, name: str) -> int:
    text = _string(value, name, 64)
    if not RFC3339_SECONDS.fullmatch(text):
        raise ContractError(f"{name} must be UTC RFC3339 with whole seconds")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError(f"{name} is not valid RFC3339") from exc
    if parsed.microsecond:
        raise ContractError(f"{name} must use whole seconds")
    return int(parsed.timestamp())


def _oci_timestamp(value: Any, name: str) -> str:
    text = _string(value, name, 64)
    if not OCI_RFC3339_NANO.fullmatch(text):
        raise ContractError(f"{name} must be OCI RFC3339Nano UTC")
    try:
        dt.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ContractError(f"{name} is not a valid calendar timestamp") from exc
    return text


def _base64(value: Any, name: str, encoded_maximum: int, decoded_minimum: int, decoded_maximum: int) -> bytes:
    text = _string(value, name, encoded_maximum)
    try:
        decoded = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise ContractError(f"{name} is not valid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != text:
        raise ContractError(f"{name} is not canonical base64")
    if not decoded_minimum <= len(decoded) <= decoded_maximum:
        raise ContractError(f"{name} decoded byte length is invalid")
    return decoded


def _reject_symlink_components(path: pathlib.Path, allow_missing_final: bool = False) -> pathlib.Path:
    if not path.is_absolute():
        raise ContractError(f"path must be absolute: {path}")
    current = pathlib.Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_final and index == len(parts) - 1:
                return path
            raise ContractError(f"path component does not exist: {current}")
        except OSError as exc:
            raise ContractError(f"path component cannot be inspected: {current}") from exc
        if stat.S_ISLNK(info.st_mode) or (hasattr(os.path, "isjunction") and os.path.isjunction(current)):
            raise ContractError(f"symlink path component is prohibited: {current}")
    return path


def _require_trusted_ancestors(path: pathlib.Path) -> None:
    if os.name != "posix":
        return
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        info = os.lstat(current)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ContractError(f"path ancestor must be root-owned and not group/world writable: {current}")


@dataclass(frozen=True)
class ReadResult:
    raw: bytes
    digest: str
    size: int


def secure_read(path: pathlib.Path, maximum: int) -> ReadResult:
    _reject_symlink_components(path)
    _require_trusted_ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ContractError(f"input exceeds {maximum} bytes: {path}")
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after or total != after.st_size:
            raise ContractError(f"input changed while it was read: {path}")
        return ReadResult(b"".join(chunks), "sha256:" + digest.hexdigest(), total)
    finally:
        os.close(descriptor)


def secure_hash(path: pathlib.Path, maximum: int, deadline: float | None = None) -> tuple[str, int]:
    _reject_symlink_components(path)
    _require_trusted_ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
        digest = hashlib.sha256()
        total = 0
        while True:
            if deadline is not None and time.monotonic() > deadline:
                raise ContractError("file hashing exceeded validation deadline")
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ContractError(f"input exceeds {maximum} bytes: {path}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after or total != after.st_size:
            raise ContractError(f"input changed while it was read: {path}")
        return "sha256:" + digest.hexdigest(), total
    finally:
        os.close(descriptor)


class _BoundedReader:
    def __init__(self, stream: Any, maximum: int, deadline: float):
        self.stream = stream
        self.maximum = maximum
        self.deadline = deadline
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        if time.monotonic() > self.deadline:
            raise ContractError("layer semantic validation exceeded deadline")
        chunk = self.stream.read(size)
        self.total += len(chunk)
        if self.total > self.maximum:
            raise ContractError(f"uncompressed layer exceeds {self.maximum} bytes")
        return chunk


def _validate_layer_semantics(path: pathlib.Path, media_type: str, expected_diff_id: str, remaining_uncompressed: int, validation_deadline: float) -> tuple[int, int]:
    _reject_symlink_components(path)
    _require_trusted_ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"layer cannot be opened safely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_LAYER:
            raise ContractError("layer must be a bounded single-link regular file")
        if os.name == "posix" and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o077):
            raise ContractError("layer must be root-owned and mode 0600 or stricter")
        compressed = media_type.endswith("+gzip") or media_type == "application/vnd.docker.image.rootfs.diff.tar.gzip"
        if media_type.endswith("+zstd"):
            raise ContractError("zstd layers are blocked until a pinned streaming decoder is integrated")
        effective_limit = min(
            MAX_UNCOMPRESSED_LAYER,
            max(1024 * 1024, before.st_size * MAX_LAYER_EXPANSION_RATIO),
            remaining_uncompressed,
        )
        if effective_limit <= 0:
            raise ContractError("total uncompressed layer budget is exhausted")
        deadline = min(validation_deadline, time.monotonic() + MAX_LAYER_PROCESS_SECONDS)

        os.lseek(descriptor, 0, os.SEEK_SET)
        raw_for_hash = os.fdopen(os.dup(descriptor), "rb", closefd=True)
        try:
            decoded_for_hash: Any = gzip.GzipFile(fileobj=raw_for_hash, mode="rb") if compressed else raw_for_hash
            bounded = _BoundedReader(decoded_for_hash, effective_limit, deadline)
            digest = hashlib.sha256()
            while True:
                chunk = bounded.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            if decoded_for_hash is not raw_for_hash:
                decoded_for_hash.close()
        except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
            raise ContractError("layer compression stream is invalid") from exc
        finally:
            raw_for_hash.close()
        if "sha256:" + digest.hexdigest() != expected_diff_id:
            raise ContractError("layer uncompressed diff_id does not match config.rootfs.diff_ids")
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw_for_tar = os.fdopen(os.dup(descriptor), "rb", closefd=True)
        decoded_for_tar: Any = gzip.GzipFile(fileobj=raw_for_tar, mode="rb") if compressed else raw_for_tar
        bounded_tar = _BoundedReader(decoded_for_tar, effective_limit, deadline)
        try:
            member_count = 0
            with tarfile.open(fileobj=bounded_tar, mode="r|") as archive:
                for index, member in enumerate(archive):
                    if index >= MAX_TAR_ENTRIES:
                        raise ContractError("layer tar has too many entries")
                    member_count += 1
                    member_name = _string(member.name, "layer tar member name", 4096)
                    name = pathlib.PurePosixPath(member_name)
                    if member_name == "." or name.is_absolute() or ".." in name.parts:
                        raise ContractError("layer tar contains unsafe member path")
                    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
                        raise ContractError("layer tar contains unsupported member type")
                    if member.issym() or member.islnk():
                        link = pathlib.PurePosixPath(_string(member.linkname, "layer tar link target", 4096))
                        if link.is_absolute() or ".." in link.parts:
                            raise ContractError("layer tar contains unsafe link target")
        except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
            raise ContractError("layer payload is not a valid bounded tar archive") from exc
        finally:
            if decoded_for_tar is not raw_for_tar:
                decoded_for_tar.close()
            raw_for_tar.close()
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise ContractError("layer changed during semantic validation")
        return bounded.total, member_count
    finally:
        os.close(descriptor)


def load_json(path: pathlib.Path, maximum: int = MAX_JSON) -> tuple[dict[str, Any], ReadResult]:
    result = secure_read(path, maximum)
    try:
        value = json.loads(result.raw, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant, parse_float=_reject_float)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError(f"invalid JSON input: {path}") from exc
    _validate_json_shape(value)
    return _object(value, str(path)), result


def _fixed_child(root: pathlib.Path, *parts: str) -> pathlib.Path:
    for part in parts:
        if not part or part in {".", ".."} or "/" in part or "\\" in part:
            raise ContractError("invalid fixed child path")
    result = root.joinpath(*parts)
    try:
        result.relative_to(root)
    except ValueError as exc:
        raise ContractError("child path escapes evidence root") from exc
    return result


def _tree_snapshot(root: pathlib.Path) -> tuple[tuple[str, str, int, int, int, int, int, int], ...]:
    """Record a bounded metadata fingerprint and reject unexpected tree types."""
    entries: list[tuple[str, str, int, int, int, int, int, int]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            children = list(os.scandir(current))
        except OSError as exc:
            raise ContractError(f"evidence directory cannot be scanned: {current}") from exc
        if len(entries) + len(children) > MAX_LAYERS + 16:
            raise ContractError("evidence tree has too many entries")
        for child in children:
            # DirEntry.stat() reports st_nlink=0 on some Windows Python/filesystem
            # combinations; lstat() returns the usable link count.
            info = os.lstat(child.path)
            relative = pathlib.Path(child.path).relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise ContractError(f"symlink in evidence tree is prohibited: {relative}")
            if stat.S_ISDIR(info.st_mode):
                kind = "directory"
                if os.name == "posix" and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077):
                    raise ContractError(f"evidence directory must be root-owned mode 0700 or stricter: {relative}")
                pending.append(pathlib.Path(child.path))
            elif stat.S_ISREG(info.st_mode):
                kind = "file"
                if info.st_nlink != 1:
                    raise ContractError(f"evidence file must have one hard link: {relative}")
            else:
                raise ContractError(f"unsupported object in evidence tree: {relative}")
            entries.append((relative, kind, info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns))
    return tuple(sorted(entries))


def _validate_tree_contract(snapshot: tuple[tuple[str, str, int, int, int, int, int, int], ...], layer_digests: list[str]) -> None:
    paths = {entry[0]: entry[1] for entry in snapshot}
    expected: dict[str, str] = {
        "manifest.json": "file", "config.json": "file", "sbom.spdx.json": "file",
        "attestation.dsse.json": "file", "signature.bundle.json": "file", "signature-evidence.json": "file",
        "blobs": "directory", "blobs/sha256": "directory",
    }
    expected.update({f"blobs/sha256/{item[7:]}": "file" for item in layer_digests})
    if paths != expected:
        missing = sorted(set(expected) - set(paths))
        unknown = sorted(set(paths) - set(expected))
        wrong = sorted(path for path in set(paths) & set(expected) if paths[path] != expected[path])
        raise ContractError(f"evidence tree shape mismatch; missing={missing}, unknown={unknown}, wrongType={wrong}")


def validate_policy(policy: dict[str, Any], now: int) -> dict[str, Any]:
    _exact_keys(policy, {
        "schema", "issuedAt", "expiresAt", "maxEvidenceAgeSeconds", "maxFutureSkewSeconds",
        "expectedImageRepository", "expectedImageDigest", "expectedIssuer", "expectedSubject",
        "allowedBuilderIds", "allowedPredicateTypes", "allowedSignatureAlgorithms", "expectedVerifier",
        "expectedTrustRootDigest", "expectedRunId", "requireTransparencyLog",
    }, set(), "policy")
    if policy["schema"] != POLICY_SCHEMA:
        raise ContractError("unsupported policy schema")
    issued, expires = _timestamp(policy["issuedAt"], "policy.issuedAt"), _timestamp(policy["expiresAt"], "policy.expiresAt")
    max_age = _integer(policy["maxEvidenceAgeSeconds"], "policy.maxEvidenceAgeSeconds", 1, 604800)
    skew = _integer(policy["maxFutureSkewSeconds"], "policy.maxFutureSkewSeconds", 0, 300)
    if issued > now + skew or expires <= now or expires <= issued or expires - issued > 604800:
        raise ContractError("policy is not currently valid or exceeds seven-day lifetime")
    repository = _string(policy["expectedImageRepository"], "policy.expectedImageRepository", 512)
    if not IMAGE_REPOSITORY.fullmatch(repository):
        raise ContractError("expected image repository is not canonical lowercase repository syntax")
    expected_digest = _digest(policy["expectedImageDigest"], "policy.expectedImageDigest")
    trust_root_digest = _digest(policy["expectedTrustRootDigest"], "policy.expectedTrustRootDigest")
    issuer = _string(policy["expectedIssuer"], "policy.expectedIssuer", 512)
    subject = _string(policy["expectedSubject"], "policy.expectedSubject", 512)
    if not IDENTITY.fullmatch(issuer) or not IDENTITY.fullmatch(subject):
        raise ContractError("issuer and subject must be exact printable identities")
    verifier = _object(policy["expectedVerifier"], "policy.expectedVerifier")
    _exact_keys(verifier, {"name", "version", "binaryDigest"}, set(), "policy.expectedVerifier")
    verifier_name = _string(verifier["name"], "policy expected verifier name", 128)
    verifier_version = _string(verifier["version"], "policy expected verifier version", 128)
    verifier_digest = _digest(verifier["binaryDigest"], "policy expected verifier binaryDigest")
    run_id = _string(policy["expectedRunId"], "policy.expectedRunId", 512)
    if not SAFE_ID.fullmatch(run_id):
        raise ContractError("policy.expectedRunId is invalid")
    builders = _array(policy["allowedBuilderIds"], "policy.allowedBuilderIds", 32)
    predicates = _array(policy["allowedPredicateTypes"], "policy.allowedPredicateTypes", 32)
    algorithms = _array(policy["allowedSignatureAlgorithms"], "policy.allowedSignatureAlgorithms", 8)
    if not builders or not predicates or not algorithms:
        raise ContractError("builder, predicate, and signature algorithm allowlists cannot be empty")
    normalized_allowlists: dict[str, list[str]] = {}
    for field_name, values in (("builder", builders), ("predicate", predicates), ("signature algorithm", algorithms)):
        normalized = [_string(item, f"{field_name} allowlist item", 512) for item in values]
        if any(not SAFE_ID.fullmatch(item) for item in normalized):
            raise ContractError(f"{field_name} allowlist contains invalid identity")
        if len(normalized) != len(set(normalized)):
            raise ContractError(f"{field_name} allowlist contains duplicates")
        normalized_allowlists[field_name] = normalized
    if not set(normalized_allowlists["signature algorithm"]).issubset(SUPPORTED_SIGNATURE_ALGORITHMS):
        raise ContractError("policy signature algorithm allowlist contains unsupported algorithm")
    if not _boolean(policy["requireTransparencyLog"], "policy.requireTransparencyLog"):
        raise ContractError("transparency log verification is mandatory in policy v1")
    return {
        "issued": issued, "expires": expires, "maxAge": max_age, "skew": skew,
        "repository": repository, "digest": expected_digest, "issuer": issuer,
        "subject": subject, "builders": set(normalized_allowlists["builder"]),
        "predicates": set(normalized_allowlists["predicate"]),
        "algorithms": set(normalized_allowlists["signature algorithm"]),
        "verifierName": verifier_name, "verifierVersion": verifier_version,
        "verifierDigest": verifier_digest, "trustRootDigest": trust_root_digest,
        "runId": run_id,
        "requireTransparency": policy["requireTransparencyLog"],
    }


def validate_descriptor(value: Any, name: str, media_types: set[str]) -> tuple[str, int, str]:
    descriptor = _object(value, name)
    _exact_keys(descriptor, {"mediaType", "digest", "size"}, set(), name)
    media_type = _string(descriptor["mediaType"], f"{name}.mediaType", 256)
    if media_type not in media_types:
        raise ContractError(f"{name}.mediaType is not allowed")
    return _digest(descriptor["digest"], f"{name}.digest"), _integer(descriptor["size"], f"{name}.size", 0, MAX_LAYER), media_type


def _validate_oci_execution_config(value: Any) -> None:
    execution = _object(value, "config.config")
    allowed = {"User", "ExposedPorts", "Env", "Entrypoint", "Cmd", "Volumes", "WorkingDir", "Labels", "StopSignal", "ArgsEscaped", "OnBuild"}
    _exact_keys(execution, set(), allowed, "config.config")
    for key in ("User", "WorkingDir", "StopSignal"):
        if key in execution:
            _text(execution[key], f"config.config.{key}", 4096, allow_empty=True)
    for key in ("Env", "Entrypoint", "Cmd", "OnBuild"):
        if key not in execution or execution[key] is None:
            continue
        values = _array(execution[key], f"config.config.{key}", 4096)
        for index, item in enumerate(values):
            _text(item, f"config.config.{key}[{index}]", 65536, allow_empty=True)
    if "ArgsEscaped" in execution:
        _boolean(execution["ArgsEscaped"], "config.config.ArgsEscaped")
    if "Labels" in execution and execution["Labels"] is not None:
        labels = _object(execution["Labels"], "config.config.Labels")
        if len(labels) > 4096:
            raise ContractError("config.config.Labels has too many entries")
        for key, item in labels.items():
            _string(key, "image label key", 4096)
            _text(item, "image label value", 65536, allow_empty=True)
    if "ExposedPorts" in execution and execution["ExposedPorts"] is not None:
        ports = _object(execution["ExposedPorts"], "config.config.ExposedPorts")
        if len(ports) > 4096:
            raise ContractError("config.config.ExposedPorts has too many entries")
        for key, item in ports.items():
            match = PORT_SPEC.fullmatch(_string(key, "exposed port", 32))
            if match is None or not 1 <= int(match.group(1)) <= 65535 or item != {}:
                raise ContractError("invalid exposed port declaration")
    if "Volumes" in execution and execution["Volumes"] is not None:
        volumes = _object(execution["Volumes"], "config.config.Volumes")
        if len(volumes) > 4096:
            raise ContractError("config.config.Volumes has too many entries")
        for key, item in volumes.items():
            path = pathlib.PurePosixPath(_string(key, "volume path", 4096))
            if not path.is_absolute() or ".." in path.parts or item != {}:
                raise ContractError("invalid image volume declaration")


def _validate_oci_history(value: Any, diff_id_count: int) -> None:
    history = _array(value, "config.history", 100000)
    nonempty_layers = 0
    for index, raw_item in enumerate(history):
        item = _object(raw_item, f"config.history[{index}]")
        _exact_keys(item, set(), {"created", "author", "created_by", "comment", "empty_layer"}, f"config.history[{index}]")
        if "created" in item:
            _oci_timestamp(item["created"], f"config.history[{index}].created")
        for key in ("author", "created_by", "comment"):
            if key in item:
                _text(item[key], f"config.history[{index}].{key}", 65536, allow_empty=True)
        empty = False
        if "empty_layer" in item:
            empty = _boolean(item["empty_layer"], f"config.history[{index}].empty_layer")
        if not empty:
            nonempty_layers += 1
    if nonempty_layers != diff_id_count:
        raise ContractError("non-empty config history entries do not match rootfs diff_ids count")


def validate_oci(root: pathlib.Path, expected_digest: str, validation_deadline: float) -> dict[str, Any]:
    manifest, manifest_file = load_json(_fixed_child(root, "manifest.json"))
    if manifest_file.digest != expected_digest:
        raise ContractError("manifest bytes do not match expected image digest")
    _exact_keys(manifest, {"schemaVersion", "mediaType", "config", "layers"}, {"annotations"}, "manifest")
    if _integer(manifest["schemaVersion"], "manifest.schemaVersion", 2, 2) != 2 or _string(manifest["mediaType"], "manifest.mediaType", 256) not in OCI_MANIFEST_MEDIA_TYPES:
        raise ContractError("unsupported OCI manifest profile")
    if "annotations" in manifest:
        annotations = _object(manifest["annotations"], "manifest.annotations")
        if len(annotations) > 64 or any(len(_string(k, "annotation key", 256)) > 256 or len(_string(v, "annotation value", 4096)) > 4096 for k, v in annotations.items()):
            raise ContractError("manifest annotations exceed limits")
    config_digest, config_size, _ = validate_descriptor(manifest["config"], "manifest.config", OCI_CONFIG_MEDIA_TYPES)
    config, config_file = load_json(_fixed_child(root, "config.json"))
    if (config_file.digest, config_file.size) != (config_digest, config_size):
        raise ContractError("config descriptor does not match config bytes")
    _exact_keys(config, {"architecture", "os", "rootfs"}, {"created", "author", "config", "history", "variant", "os.version", "os.features"}, "config")
    if _string(config["architecture"], "config.architecture", 32) not in {"amd64", "arm64"}:
        raise ContractError("unsupported image architecture")
    if _string(config["os"], "config.os", 32) != "linux":
        raise ContractError("image os must be linux")
    rootfs = _object(config["rootfs"], "config.rootfs")
    _exact_keys(rootfs, {"type", "diff_ids"}, set(), "config.rootfs")
    if rootfs["type"] != "layers":
        raise ContractError("config.rootfs.type must be layers")
    diff_ids = _array(rootfs["diff_ids"], "config.rootfs.diff_ids", MAX_LAYERS)
    normalized_diff_ids = [_digest(diff_id, f"config.rootfs.diff_ids[{index}]") for index, diff_id in enumerate(diff_ids)]
    if "created" in config:
        _oci_timestamp(config["created"], "config.created")
    for key in ("author", "variant", "os.version"):
        if key in config:
            _text(config[key], f"config.{key}", 4096, allow_empty=True)
    if "os.features" in config:
        features = _array(config["os.features"], "config.os.features", 1024)
        for index, feature in enumerate(features):
            _string(feature, f"config.os.features[{index}]", 256)
    if "config" in config and config["config"] is not None:
        _validate_oci_execution_config(config["config"])
    if "history" in config:
        _validate_oci_history(config["history"], len(normalized_diff_ids))
    layers = _array(manifest["layers"], "manifest.layers", MAX_LAYERS)
    if not layers or len(layers) != len(diff_ids):
        raise ContractError("manifest layer count must be nonzero and equal rootfs diff_ids count")
    layer_digests, total, total_uncompressed, total_tar_entries = [], 0, 0, 0
    for index, descriptor in enumerate(layers):
        digest, size, media_type = validate_descriptor(descriptor, f"manifest.layers[{index}]", OCI_LAYER_MEDIA_TYPES)
        if digest in layer_digests:
            raise ContractError("duplicate layer digest")
        total += size
        if total > MAX_TOTAL_LAYERS:
            raise ContractError("total declared layer size exceeds limit")
        layer_path = _fixed_child(root, "blobs", "sha256", digest[7:])
        actual_digest, actual_size = secure_hash(layer_path, MAX_LAYER, validation_deadline)
        if (actual_digest, actual_size) != (digest, size):
            raise ContractError(f"layer {index} descriptor does not match blob")
        uncompressed_size, tar_entries = _validate_layer_semantics(
            layer_path, media_type, normalized_diff_ids[index],
            MAX_TOTAL_UNCOMPRESSED_LAYERS - total_uncompressed, validation_deadline,
        )
        total_uncompressed += uncompressed_size
        total_tar_entries += tar_entries
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_LAYERS:
            raise ContractError("total uncompressed layer size exceeds limit")
        layer_digests.append(digest)
    return {
        "manifestDigest": manifest_file.digest, "manifestSize": manifest_file.size,
        "configDigest": config_file.digest, "configSize": config_file.size,
        "layerDigests": layer_digests, "layerDiffIds": normalized_diff_ids,
        "layerCount": len(layer_digests), "uncompressedLayerBytes": total_uncompressed,
        "tarEntryCount": total_tar_entries,
    }


def validate_sbom(root: pathlib.Path, image_repository: str, image_digest: str) -> dict[str, Any]:
    sbom, sbom_file = load_json(_fixed_child(root, "sbom.spdx.json"))
    _exact_keys(sbom, {"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages", "documentDescribes"}, set(), "sbom")
    if sbom["spdxVersion"] != SPDX_VERSION or sbom["dataLicense"] != "CC0-1.0" or sbom["SPDXID"] != "SPDXRef-DOCUMENT":
        raise ContractError("unsupported SPDX document profile")
    _string(sbom["name"], "sbom.name", 1024)
    namespace = _string(sbom["documentNamespace"], "sbom.documentNamespace", 1024)
    if not namespace.startswith("https://"):
        raise ContractError("SPDX document namespace must be https")
    creation = _object(sbom["creationInfo"], "sbom.creationInfo")
    _exact_keys(creation, {"created", "creators"}, set(), "sbom.creationInfo")
    created = _timestamp(creation["created"], "sbom.creationInfo.created")
    creators = _array(creation["creators"], "sbom.creationInfo.creators", 32)
    if not creators or any(not _string(item, "sbom creator", 512).startswith(("Tool: ", "Organization: ", "Person: ")) for item in creators):
        raise ContractError("SPDX creators must use a recognized prefix")
    described = _array(sbom["documentDescribes"], "sbom.documentDescribes", MAX_SUBJECTS)
    described_ids = [_string(item, "sbom.documentDescribes item", 256) for item in described]
    packages = _array(sbom["packages"], "sbom.packages", MAX_PACKAGES)
    if not described or not packages:
        raise ContractError("SPDX document must describe at least one package")
    package_ids: set[str] = set()
    subject_found = False
    expected_ref = f"{image_repository}@{image_digest}"
    for index, raw_package in enumerate(packages):
        package = _object(raw_package, f"sbom.packages[{index}]")
        _exact_keys(package, {"SPDXID", "name", "downloadLocation", "filesAnalyzed", "externalRefs"}, set(), f"sbom.packages[{index}]")
        package_id = _string(package["SPDXID"], "package SPDXID", 256)
        if not package_id.startswith("SPDXRef-") or package_id in package_ids:
            raise ContractError("SPDX package IDs must be unique SPDXRef values")
        package_ids.add(package_id)
        _string(package["name"], "package name", 1024)
        _string(package["downloadLocation"], "package downloadLocation", 2048)
        _boolean(package["filesAnalyzed"], "package filesAnalyzed")
        for external in _array(package["externalRefs"], "package externalRefs", 64):
            external_ref = _object(external, "package externalRef")
            _exact_keys(external_ref, {"referenceCategory", "referenceType", "referenceLocator"}, set(), "package externalRef")
            _string(external_ref["referenceCategory"], "external reference category", 128)
            reference_type = _string(external_ref["referenceType"], "external reference type", 128)
            locator = _string(external_ref["referenceLocator"], "external reference locator", 2048)
            if package_id in described_ids and reference_type == "purl" and locator == f"pkg:oci/{expected_ref}":
                subject_found = True
    if any(item not in package_ids for item in described_ids) or len(described_ids) != len(set(described_ids)):
        raise ContractError("documentDescribes contains missing or duplicate package IDs")
    if not subject_found:
        raise ContractError("SPDX described package is not bound to the expected image digest by purl")
    return {"digest": sbom_file.digest, "size": sbom_file.size, "created": created, "namespace": namespace}


def validate_attestation(root: pathlib.Path, policy: dict[str, Any], image_digest: str) -> dict[str, Any]:
    envelope, envelope_file = load_json(_fixed_child(root, "attestation.dsse.json"))
    _exact_keys(envelope, {"payloadType", "payload", "signatures"}, set(), "attestation envelope")
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        raise ContractError("unsupported DSSE payload type")
    signatures = _array(envelope["signatures"], "attestation signatures", MAX_SIGNATURES)
    if not signatures:
        raise ContractError("attestation envelope has no signatures")
    seen_keys = set()
    for index, raw_signature in enumerate(signatures):
        signature = _object(raw_signature, f"attestation.signatures[{index}]")
        _exact_keys(signature, {"keyid", "sig"}, set(), f"attestation.signatures[{index}]")
        keyid = _string(signature["keyid"], "signature keyid", 512)
        if keyid in seen_keys:
            raise ContractError("duplicate attestation signature keyid")
        seen_keys.add(keyid)
        _base64(signature["sig"], "attestation signature", 16384, 32, 8192)
    try:
        payload_raw = _base64(envelope["payload"], "attestation payload", MAX_JSON * 2, 2, MAX_JSON)
        statement = json.loads(payload_raw, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant, parse_float=_reject_float)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("attestation payload is not valid base64 JSON") from exc
    statement = _object(statement, "attestation statement")
    _validate_json_shape(statement)
    _exact_keys(statement, {"_type", "subject", "predicateType", "predicate"}, set(), "attestation statement")
    if statement["_type"] != IN_TOTO_STATEMENT:
        raise ContractError("unsupported in-toto statement type")
    predicate_type = _string(statement["predicateType"], "attestation predicateType", 512)
    if predicate_type not in policy["predicates"]:
        raise ContractError("attestation predicate type is not allowed")
    subjects = _array(statement["subject"], "attestation subject", MAX_SUBJECTS)
    if len(subjects) != 1:
        raise ContractError("attestation must have exactly one image subject")
    subject = _object(subjects[0], "attestation subject[0]")
    _exact_keys(subject, {"name", "digest"}, set(), "attestation subject[0]")
    digest_map = _object(subject["digest"], "attestation subject digest")
    _exact_keys(digest_map, {"sha256"}, set(), "attestation subject digest")
    if subject["name"] != policy["repository"] or "sha256:" + _string(digest_map["sha256"], "subject sha256", 64) != image_digest:
        raise ContractError("attestation subject does not match expected image")
    predicate = _object(statement["predicate"], "attestation predicate")
    _exact_keys(predicate, {"buildType", "builder", "metadata", "materials"}, set(), "attestation predicate")
    _string(predicate["buildType"], "attestation buildType", 512)
    builder = _object(predicate["builder"], "attestation builder")
    _exact_keys(builder, {"id"}, set(), "attestation builder")
    builder_id = _string(builder["id"], "attestation builder id", 512)
    if builder_id not in policy["builders"]:
        raise ContractError("attestation builder is not allowed")
    metadata = _object(predicate["metadata"], "attestation metadata")
    _exact_keys(metadata, {"buildStartedOn", "buildFinishedOn", "invocationId"}, set(), "attestation metadata")
    if _string(metadata["invocationId"], "attestation invocationId", 512) != policy["runId"]:
        raise ContractError("attestation invocationId does not match policy run ID")
    started = _timestamp(metadata["buildStartedOn"], "attestation buildStartedOn")
    finished = _timestamp(metadata["buildFinishedOn"], "attestation buildFinishedOn")
    if finished < started or finished - started > 86400:
        raise ContractError("attestation build time window is invalid")
    materials = _array(predicate["materials"], "attestation materials", 1024)
    if not materials:
        raise ContractError("attestation materials cannot be empty")
    seen_materials: set[tuple[str, str]] = set()
    for index, raw_material in enumerate(materials):
        material = _object(raw_material, f"attestation materials[{index}]")
        _exact_keys(material, {"uri", "digest"}, set(), f"attestation materials[{index}]")
        uri = _string(material["uri"], "material uri", 2048)
        digest_values = _object(material["digest"], "material digest")
        _exact_keys(digest_values, {"sha256"}, set(), "material digest")
        material_digest = _string(digest_values["sha256"], "material sha256", 64)
        if not HEX64.fullmatch(material_digest):
            raise ContractError("material digest must be lowercase sha256")
        if (uri, material_digest) in seen_materials:
            raise ContractError("attestation contains duplicate material")
        seen_materials.add((uri, material_digest))
    return {"digest": envelope_file.digest, "size": envelope_file.size, "finished": finished, "builder": builder_id, "predicateType": predicate_type}


def validate_signature_bundle(root: pathlib.Path, policy: dict[str, Any], image_digest: str, now: int) -> dict[str, Any]:
    bundle, bundle_file = load_json(_fixed_child(root, "signature.bundle.json"))
    _exact_keys(bundle, {"schema", "runId", "signedArtifactDigest", "signature", "certificate", "transparencyLog"}, set(), "signature bundle")
    if bundle["schema"] != SIGNATURE_BUNDLE_SCHEMA:
        raise ContractError("unsupported signature bundle schema")
    if _string(bundle["runId"], "signature bundle runId", 512) != policy["runId"]:
        raise ContractError("signature bundle runId does not match policy")
    if _digest(bundle["signedArtifactDigest"], "signature bundle signedArtifactDigest") != image_digest:
        raise ContractError("signature bundle is not bound to expected image digest")
    signature = _object(bundle["signature"], "signature bundle signature")
    _exact_keys(signature, {"algorithm", "value"}, set(), "signature bundle signature")
    algorithm = _string(signature["algorithm"], "signature algorithm", 64)
    if algorithm not in policy["algorithms"] or algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ContractError("signature algorithm is not allowed")
    _base64(signature["value"], "signature value", 16384, 32, 8192)
    certificate = _object(bundle["certificate"], "signature bundle certificate")
    _exact_keys(certificate, {"der", "sha256", "issuer", "subject", "notBefore", "notAfter"}, set(), "signature bundle certificate")
    der = _base64(certificate["der"], "certificate DER", 131072, 128, 65536)
    certificate_digest = "sha256:" + hashlib.sha256(der).hexdigest()
    if _digest(certificate["sha256"], "certificate sha256") != certificate_digest:
        raise ContractError("certificate DER digest mismatch")
    if certificate["issuer"] != policy["issuer"] or certificate["subject"] != policy["subject"]:
        raise ContractError("signature bundle certificate identity does not match policy")
    not_before = _timestamp(certificate["notBefore"], "signature bundle certificate notBefore")
    not_after = _timestamp(certificate["notAfter"], "signature bundle certificate notAfter")
    if not_before > now + policy["skew"] or not_after < now - policy["maxAge"] or not_after <= not_before:
        raise ContractError("signature bundle certificate validity is outside evidence window")
    log = _object(bundle["transparencyLog"], "signature bundle transparencyLog")
    _exact_keys(log, {"logId", "logIndex", "integratedTime", "inclusionProof"}, set(), "signature bundle transparencyLog")
    _string(log["logId"], "signature bundle logId", 512)
    _integer(log["logIndex"], "signature bundle logIndex", 0)
    integrated = _timestamp(log["integratedTime"], "signature bundle integratedTime")
    if integrated > now + policy["skew"] or now - integrated > policy["maxAge"]:
        raise ContractError("signature bundle transparency time is outside evidence window")
    if not_before > integrated or not_after < integrated:
        raise ContractError("certificate validity does not cover transparency integration time")
    proof = _object(log["inclusionProof"], "signature bundle inclusionProof")
    _exact_keys(proof, {"rootHash", "treeSize", "hashes"}, set(), "signature bundle inclusionProof")
    if not HEX64.fullmatch(_string(proof["rootHash"], "inclusion rootHash", 64)):
        raise ContractError("inclusion rootHash must be lowercase sha256 hex")
    _integer(proof["treeSize"], "inclusion treeSize", 1)
    hashes = _array(proof["hashes"], "inclusion hashes", 64)
    if not hashes or any(not HEX64.fullmatch(_string(value, "inclusion hash", 64)) for value in hashes):
        raise ContractError("inclusion hashes must be non-empty lowercase sha256 hex")
    return {
        "digest": bundle_file.digest, "size": bundle_file.size, "algorithm": algorithm,
        "certificateDigest": certificate_digest, "certificateNotBefore": not_before,
        "certificateNotAfter": not_after, "logId": log["logId"], "logIndex": log["logIndex"],
        "integrated": integrated,
    }


def validate_receipt(root: pathlib.Path, policy: dict[str, Any], policy_digest: str, oci: dict[str, Any], sbom: dict[str, Any], attestation: dict[str, Any], signature_bundle: dict[str, Any], now: int) -> dict[str, Any]:
    receipt, receipt_file = load_json(_fixed_child(root, "signature-evidence.json"))
    _exact_keys(receipt, {"schema", "runId", "verifiedAt", "imageRepository", "imageDigest", "manifestDigest", "configDigest", "layerDigests", "sbomDigest", "attestationDigest", "signatureBundleDigest", "issuer", "subject", "certificate", "transparencyLog", "verifier", "verification"}, set(), "signature receipt")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise ContractError("unsupported signature receipt schema")
    if _string(receipt["runId"], "receipt.runId", 512) != policy["runId"]:
        raise ContractError("signature receipt runId does not match policy")
    verified = _timestamp(receipt["verifiedAt"], "receipt.verifiedAt")
    if verified > now + policy["skew"] or now - verified > policy["maxAge"]:
        raise ContractError("signature receipt is stale or from the future")
    expected_pairs = {
        "imageRepository": policy["repository"], "imageDigest": policy["digest"],
        "manifestDigest": oci["manifestDigest"], "configDigest": oci["configDigest"],
        "sbomDigest": sbom["digest"], "attestationDigest": attestation["digest"], "signatureBundleDigest": signature_bundle["digest"],
        "issuer": policy["issuer"], "subject": policy["subject"],
    }
    for key, expected in expected_pairs.items():
        if receipt[key] != expected:
            raise ContractError(f"signature receipt {key} does not match policy/evidence")
    layers = _array(receipt["layerDigests"], "receipt.layerDigests", MAX_LAYERS)
    if layers != oci["layerDigests"]:
        raise ContractError("signature receipt layer digest order does not match manifest")
    certificate = _object(receipt["certificate"], "receipt.certificate")
    _exact_keys(certificate, {"sha256", "notBefore", "notAfter"}, set(), "receipt.certificate")
    certificate_digest = _digest(certificate["sha256"], "receipt.certificate.sha256")
    if certificate_digest != signature_bundle["certificateDigest"]:
        raise ContractError("signature receipt certificate digest does not match signature bundle")
    not_before = _timestamp(certificate["notBefore"], "receipt.certificate.notBefore")
    not_after = _timestamp(certificate["notAfter"], "receipt.certificate.notAfter")
    if not_before > verified or not_after < verified or not_after <= not_before:
        raise ContractError("certificate validity does not cover verification time")
    if (not_before, not_after) != (signature_bundle["certificateNotBefore"], signature_bundle["certificateNotAfter"]):
        raise ContractError("signature receipt certificate time bounds do not match signature bundle")
    log = _object(receipt["transparencyLog"], "receipt.transparencyLog")
    _exact_keys(log, {"included", "integratedTime", "logId", "logIndex"}, set(), "receipt.transparencyLog")
    included = _boolean(log["included"], "receipt.transparencyLog.included")
    integrated = _timestamp(log["integratedTime"], "receipt.transparencyLog.integratedTime")
    if policy["requireTransparency"] and not included:
        raise ContractError("transparency log inclusion is required")
    if integrated > verified + policy["skew"] or verified - integrated > policy["maxAge"]:
        raise ContractError("transparency log integration time is outside allowed window")
    _string(log["logId"], "receipt.transparencyLog.logId", 512)
    _integer(log["logIndex"], "receipt.transparencyLog.logIndex", 0)
    if (log["logId"], log["logIndex"], integrated) != (signature_bundle["logId"], signature_bundle["logIndex"], signature_bundle["integrated"]):
        raise ContractError("signature receipt transparency log coordinates do not match signature bundle")
    verifier = _object(receipt["verifier"], "receipt.verifier")
    _exact_keys(verifier, {"name", "version", "binaryDigest", "trustRootDigest", "offline", "policyDigest"}, set(), "receipt.verifier")
    if _string(verifier["name"], "receipt.verifier.name", 128) != policy["verifierName"]:
        raise ContractError("signature receipt verifier name does not match policy")
    if _string(verifier["version"], "receipt.verifier.version", 128) != policy["verifierVersion"]:
        raise ContractError("signature receipt verifier version does not match policy")
    if _digest(verifier["binaryDigest"], "receipt.verifier.binaryDigest") != policy["verifierDigest"]:
        raise ContractError("signature receipt verifier binary digest does not match policy")
    if _digest(verifier["trustRootDigest"], "receipt.verifier.trustRootDigest") != policy["trustRootDigest"]:
        raise ContractError("signature receipt trust-root digest does not match policy")
    if not _boolean(verifier["offline"], "receipt.verifier.offline"):
        raise ContractError("receipt must record offline verification")
    if _digest(verifier["policyDigest"], "receipt.verifier.policyDigest") != policy_digest:
        raise ContractError("signature receipt policyDigest does not match policy bytes")
    checks = _object(receipt["verification"], "receipt.verification")
    check_names = {"signatureVerified", "certificateChainVerified", "issuerMatched", "subjectMatched", "manifestDigestMatched", "sbomDigestMatched", "attestationDigestMatched", "transparencyProofVerified"}
    _exact_keys(checks, check_names, set(), "receipt.verification")
    for name in check_names:
        if not _boolean(checks[name], f"receipt.verification.{name}"):
            raise ContractError(f"external receipt check is false: {name}")
    return {"digest": receipt_file.digest, "verified": verified, "certificateDigest": certificate_digest, "externalChecksTrue": True}


def verify(evidence_root: pathlib.Path, policy_path: pathlib.Path, now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    validation_deadline = time.monotonic() + MAX_VALIDATION_SECONDS
    _reject_symlink_components(evidence_root)
    root_info = os.stat(evidence_root, follow_symlinks=False)
    if not stat.S_ISDIR(root_info.st_mode):
        raise ContractError("evidence root must be a directory")
    if os.name == "posix" and (root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) & 0o077):
        raise ContractError("evidence root must be root-owned mode 0700 or stricter")
    before_tree = _tree_snapshot(evidence_root)
    policy_document, policy_file = load_json(policy_path)
    policy = validate_policy(policy_document, now)
    oci = validate_oci(evidence_root, policy["digest"], validation_deadline)
    _validate_tree_contract(before_tree, oci["layerDigests"])
    sbom = validate_sbom(evidence_root, policy["repository"], policy["digest"])
    attestation = validate_attestation(evidence_root, policy, policy["digest"])
    signature_bundle = validate_signature_bundle(evidence_root, policy, policy["digest"], now)
    receipt = validate_receipt(evidence_root, policy, policy_file.digest, oci, sbom, attestation, signature_bundle, now)
    oldest_allowed = now - policy["maxAge"]
    if sbom["created"] < oldest_allowed or sbom["created"] > now + policy["skew"]:
        raise ContractError("SBOM creation time is outside evidence window")
    if attestation["finished"] < oldest_allowed or attestation["finished"] > now + policy["skew"]:
        raise ContractError("attestation finish time is outside evidence window")
    if signature_bundle["integrated"] < max(sbom["created"], attestation["finished"]):
        raise ContractError("signature transparency integration predates SBOM or completed build")
    if receipt["verified"] < signature_bundle["integrated"]:
        raise ContractError("signature receipt predates transparency integration")
    after_tree = _tree_snapshot(evidence_root)
    if before_tree != after_tree:
        raise ContractError("evidence tree changed while it was validated")
    remaining_blockers = [
        "no authenticated approval signature for the policy itself",
        "no in-process DSSE or image-signature verification against a pinned trust root",
        "no in-process X.509 certificate-chain and transparency-log proof verification",
        "signature receipt is an unauthenticated external assertion",
        "SBOM digest is receipt-bound but not covered by a verified signed predicate",
        "no real registry digest readback",
        "no single-use nonce or durable monotonic ledger prevents evidence replay",
        "no Linux candidate-host runtime evidence",
    ]
    platform_assurance = "POSIX_ROOT_OWNERSHIP_AND_MODE_ENFORCED" if os.name == "posix" else "DEVELOPMENT_ONLY_NON_POSIX"
    if os.name != "posix":
        remaining_blockers.append("non-POSIX platform cannot prove Linux ownership, mode, inode, or mount semantics")
    return {
        "schema": REPORT_SCHEMA,
        "status": "BLOCKED",
        "reason": "CRYPTOGRAPHIC_TRUST_GATE_NOT_IMPLEMENTED",
        "exitCode": BLOCKED_EXIT,
        "readOnly": True,
        "offline": True,
        "authorizationGranted": False,
        "platformAssurance": platform_assurance,
        "outputContract": "CREATE_NEW_ONLY_NEVER_ACCEPTED",
        "replayProtection": "UNAVAILABLE_OFFLINE",
        "verifiedAtUnix": now,
        "policy": {"digest": policy_file.digest, "issuedAtUnix": policy["issued"], "expiresAtUnix": policy["expires"], "runId": policy["runId"]},
        "image": {"repository": policy["repository"], "digest": policy["digest"], **oci},
        "sbom": sbom,
        "attestation": attestation,
        "signatureBundle": signature_bundle,
        "signatureReceipt": receipt,
        "structuralChecks": "PASS",
        "cryptographicChecks": "UNTRUSTED_EXTERNAL_ASSERTIONS_ONLY",
        "remainingBlockers": remaining_blockers,
    }


def _atomic_write_new(path: pathlib.Path, payload: bytes) -> None:
    _reject_symlink_components(path, allow_missing_final=True)
    _require_trusted_ancestors(path)
    parent = path.parent
    parent_info = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent_info.st_mode):
        raise ContractError("output parent is not a directory")
    if os.name == "posix" and (parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise ContractError("output parent must be root-owned mode 0700")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".chengwang-supply-chain-", dir=parent)
    temporary_path = pathlib.Path(temporary_name)
    published = False
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write while creating report")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary_path, path, follow_symlinks=False)
        published = True
        os.unlink(temporary_path)
        if os.name == "posix":
            directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path.exists():
            try:
                os.unlink(temporary_path)
            except OSError:
                if not published:
                    raise


def _safe_error(exc: BaseException, maximum: int = 4096) -> str:
    raw = str(exc).encode("utf-8", errors="replace")
    if len(raw) <= maximum:
        return raw.decode("utf-8")
    suffix = f"...[sha256:{hashlib.sha256(raw).hexdigest()}]".encode("ascii")
    prefix = raw[: maximum - len(suffix)].decode("utf-8", errors="ignore").encode("utf-8")
    return (prefix + suffix).decode("utf-8")


class _FailClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ContractError("invalid command line")


def main(argv: list[str] | None = None) -> int:
    parser = _FailClosedArgumentParser(description="Offline fail-closed supply-chain evidence candidate", add_help=False)
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("--evidence-root", required=True, type=pathlib.Path)
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    output_path: pathlib.Path | None = None
    try:
        arguments = parser.parse_args(argv)
        output_path = arguments.output
        report = verify(arguments.evidence_root, arguments.policy)
    except (ContractError, OSError) as exc:
        report = {
            "schema": REPORT_SCHEMA, "status": "BLOCKED", "reason": "EVIDENCE_CONTRACT_FAILED",
            "exitCode": BLOCKED_EXIT, "readOnly": True, "offline": True,
            "authorizationGranted": False, "error": _safe_error(exc),
        }
    except Exception as exc:  # Last-resort fail-closed boundary; never grants authorization.
        report = {
            "schema": REPORT_SCHEMA, "status": "BLOCKED", "reason": "INTERNAL_VALIDATION_FAILURE",
            "exitCode": BLOCKED_EXIT, "readOnly": True, "offline": True,
            "authorizationGranted": False, "error": f"internal validator exception: {type(exc).__name__}",
        }
    payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if output_path is None:
        sys.stdout.write(payload.decode("utf-8"))
        return BLOCKED_EXIT
    try:
        _atomic_write_new(output_path, payload)
    except (ContractError, OSError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": "REPORT_WRITE_FAILED", "errorType": type(exc).__name__}, separators=(",", ":")), file=sys.stderr)
        return BLOCKED_EXIT
    print(json.dumps({"status": "BLOCKED", "report": str(output_path)}, separators=(",", ":")))
    return BLOCKED_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
