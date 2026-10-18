#!/usr/bin/env python3
"""Validate an operator-owned static canary contract without using the network.

The command deliberately never emits an accepted/start-evidence schema.  A
valid contract produces a BLOCKED advisory report and exit status 78.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import sys
import time
import urllib.parse
import uuid
from typing import Any


CONTRACT_SCHEMA = "chengwang.static-canary-contract/v1"
REPORT_SCHEMA = "chengwang.static-canary-validation/v1"
CATALOG_SCHEMA = "chengwang.probe-catalog/v1"
MAX_INPUT_BYTES = 256 * 1024
MAX_CONTRACT_LIFETIME = 24 * 60 * 60
MAX_PROBES = 256
MAX_NAMES = 17
MAX_ADDRESSES = 32
BLOCKED_EXIT = 78

SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SAFE_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

PROHIBITED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96",
        "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
        "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fec0::/10",
    )
)
PROHIBITED_ADDRESSES = {
    ipaddress.ip_address(value)
    for value in ("100.100.100.200", "168.63.129.16", "169.254.169.254", "169.254.170.2")
}


class ContractError(ValueError):
    pass


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Never echo an attacker-controlled key to stderr.  A lone
            # surrogate can make the diagnostic encoding itself fail.
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractError(f"{label} field set is invalid")
    return value


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ContractError(f"{label} must be an integer")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} is invalid")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ContractError(f"{label} is not valid Unicode") from exc
    if encoded_length > limit:
        raise ContractError(f"{label} is invalid")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ContractError(f"{label} is invalid")
    return value


def _hostname(value: Any, label: str, wildcard: bool = False) -> str:
    name = _text(value, label, limit=253)
    if name != name.lower() or name.endswith(".") or any(char in name for char in ":/@[]\\%\r\n\t "):
        raise ContractError(f"{label} must be canonical lowercase DNS")
    labels = name.split(".")
    if wildcard and labels[0] == "*":
        labels = labels[1:]
    elif "*" in name:
        raise ContractError(f"{label} wildcard is invalid")
    if len(labels) < 2 or any(HOST_LABEL.fullmatch(item) is None for item in labels):
        raise ContractError(f"{label} contains an invalid DNS label")
    return name


def _wildcard_matches(pattern: str, host: str) -> bool:
    if not pattern.startswith("*."):
        return pattern == host
    return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])


def _request_path(value: Any, label: str) -> str:
    path = _text(value, label, limit=1024)
    if not path.startswith("/") or path.startswith("//") or "\\" in path or any(char in path for char in "\r\n\x00"):
        raise ContractError(f"{label} is not a safe absolute path")
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ContractError(f"{label} must not contain authority, query, or fragment")
    return path


def _public_ip(value: Any) -> str:
    text = _text(value, "canary address", limit=64)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ContractError("canary address is invalid") from exc
    if text != address.compressed:
        raise ContractError("canary address must use canonical compressed form")
    if getattr(address, "ipv4_mapped", None) is not None:
        raise ContractError("IPv4-mapped IPv6 canary addresses are prohibited")
    if address.is_unspecified:
        raise ContractError("unspecified canary addresses are prohibited")
    if address.is_loopback:
        raise ContractError("loopback canary addresses are prohibited")
    if address.is_link_local:
        raise ContractError("link-local canary addresses are prohibited")
    if address.is_multicast:
        raise ContractError("multicast canary addresses are prohibited")
    if address.is_reserved:
        raise ContractError("reserved canary addresses are prohibited")
    if address.is_private or not address.is_global:
        raise ContractError("canary address is not permitted global unicast")
    if address in PROHIBITED_ADDRESSES or any(address in network for network in PROHIBITED_NETWORKS):
        raise ContractError("canary address is in a prohibited range")
    return str(address)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    # Windows st_ctime_ns is creation-time metadata and can be surfaced with
    # delayed updates by the filesystem.  POSIX ctime participates in the
    # immutable fingerprint; the Windows limitation is an explicit report
    # blocker and never produces accepted evidence.
    change_time = value.st_ctime_ns if os.name == "posix" else 0
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_size, value.st_mtime_ns, change_time,
    )


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_nlink


def _trusted_owner_mode(value: os.stat_result, label: str, directory: bool = False) -> None:
    if os.name != "posix":
        return
    trusted_owners = {0, os.geteuid()}
    if value.st_uid not in trusted_owners:
        raise ContractError(f"{label} owner is not trusted")
    writable = stat.S_IMODE(value.st_mode) & 0o022
    # Root-owned sticky ancestors such as /tmp cannot replace a child owned by
    # another user.  The immediate private evidence directory is checked
    # separately and may not rely on this exception.
    if writable and not (directory and value.st_uid == 0 and value.st_mode & stat.S_ISVTX):
        raise ContractError(f"{label} is group/other writable")
    mode = stat.S_IMODE(value.st_mode)
    if not directory and (not mode & stat.S_IRUSR or mode & 0o7137):
        raise ContractError(f"{label} mode is not a trusted read-only evidence mode")


def _require_posix_dirfd_capabilities() -> None:
    if os.name != "posix":
        return
    required = (os.open, os.stat, os.unlink, os.link)
    if any(function not in os.supports_dir_fd for function in required):
        raise ContractError("platform lacks required POSIX dirfd operations")
    if os.link not in os.supports_follow_symlinks:
        raise ContractError("platform lacks no-follow dirfd link support")


def _check_components(path: pathlib.Path, leaf_kind: str) -> None:
    if not path.is_absolute():
        raise ContractError(f"{leaf_kind} path must be absolute")
    parts = path.parts
    current = pathlib.Path(parts[0])
    anchor_status = os.lstat(current)
    if stat.S_ISLNK(anchor_status.st_mode) or not stat.S_ISDIR(anchor_status.st_mode):
        raise ContractError(f"{leaf_kind} path anchor is not a trusted directory")
    _trusted_owner_mode(anchor_status, f"{leaf_kind} path anchor", directory=True)
    for index, part in enumerate(parts[1:], start=1):
        current = current / part
        try:
            current_status = os.lstat(current)
        except OSError as exc:
            raise ContractError(f"{leaf_kind} path component is unavailable") from exc
        is_leaf = index == len(parts) - 1
        if stat.S_ISLNK(current_status.st_mode):
            raise ContractError(f"{leaf_kind} path contains a symbolic link")
        if is_leaf and leaf_kind == "input":
            if not stat.S_ISREG(current_status.st_mode) or current_status.st_nlink != 1:
                raise ContractError("input must be a regular single-link file")
            _trusted_owner_mode(current_status, "input file")
        elif not stat.S_ISDIR(current_status.st_mode):
            raise ContractError(f"{leaf_kind} path component is not a directory")
        else:
            _trusted_owner_mode(current_status, f"{leaf_kind} directory", directory=True)


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ContractError("input exceeds size limit")
    return b"".join(chunks)


def _read_immutable_once(path: pathlib.Path, maximum: int) -> tuple[bytes, tuple[int, ...]]:
    _check_components(path, "input")
    before_path = os.lstat(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    if os.name == "posix":
        _require_posix_dirfd_capabilities()
        parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = os.open(path.parent, parent_flags)
        try:
            parent_open = os.fstat(parent_descriptor)
            parent_path = os.lstat(path.parent)
            if _fingerprint(parent_open) != _fingerprint(parent_path):
                raise ContractError("input parent identity changed before open")
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        except BaseException:
            os.close(parent_descriptor)
            raise
    else:
        descriptor = os.open(path, flags)
    try:
        try:
            before_fd = os.fstat(descriptor)
            if _identity(before_fd) != _identity(before_path):
                raise ContractError("input identity changed before read")
            raw = _read_bounded(descriptor, maximum)
            after_fd = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise
    try:
        after_path = os.lstat(path)
        if _fingerprint(before_fd) != _fingerprint(after_fd) or _fingerprint(after_fd) != _fingerprint(after_path):
            raise ContractError("input changed during read")
        if parent_descriptor is not None:
            if _fingerprint(os.fstat(parent_descriptor)) != _fingerprint(os.lstat(path.parent)):
                raise ContractError("input parent changed during read")
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    return raw, _fingerprint(after_fd)


def _reject_json_constant(value: str) -> Any:
    raise ContractError(f"non-standard JSON numeric constant is prohibited: {value}")


def _reject_excessive_json_nesting(raw: bytes, maximum_depth: int = 128) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > maximum_depth:
                raise ContractError("input JSON nesting exceeds the safety limit")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                break


def load_immutable_json(path: pathlib.Path, maximum: int = MAX_INPUT_BYTES) -> tuple[Any, bytes]:
    if not path.is_absolute():
        raise ContractError("input path must be absolute")
    raw, first_fingerprint = _read_immutable_once(path, maximum)
    second_raw, second_fingerprint = _read_immutable_once(path, maximum)
    if first_fingerprint != second_fingerprint or _sha256(raw) != _sha256(second_raw) or raw != second_raw:
        raise ContractError("input changed between verification reads")
    try:
        _reject_excessive_json_nesting(raw)
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object_no_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("input is not one valid UTF-8 JSON document") from exc
    return value, raw


def _catalog(value: Any) -> dict[str, dict[str, Any]]:
    catalog = _exact(value, {"schema", "revision", "agent", "paths", "probes"}, "catalog")
    if catalog["schema"] != CATALOG_SCHEMA:
        raise ContractError("catalog schema is invalid")
    _text(catalog["revision"], "catalog revision", SAFE_REVISION)
    agent = _exact(catalog["agent"], {"id", "independence", "advisoryOnly"}, "catalog agent")
    _text(agent["id"], "catalog agent id", SAFE_ID)
    if agent["independence"] != "P1" or agent["advisoryOnly"] is not True:
        raise ContractError("catalog agent must be advisory-only P1")
    paths = catalog["paths"]
    if not isinstance(paths, list) or not paths:
        raise ContractError("catalog paths are missing")
    path_ids: set[str] = set()
    for item in paths:
        entry = _exact(item, {"id", "kind"}, "catalog path")
        path_id = _text(entry["id"], "catalog path id", SAFE_ID)
        if path_id in path_ids or entry["kind"] != "direct":
            raise ContractError("catalog path is duplicated or not direct")
        path_ids.add(path_id)
    probes = catalog["probes"]
    if not isinstance(probes, list) or not probes or len(probes) > MAX_PROBES:
        raise ContractError("catalog probe set is invalid")
    result: dict[str, dict[str, Any]] = {}
    required = {"id", "pathId", "kind", "host", "port", "requestPath", "method", "expectedStatus", "requiredMarker", "intervalSeconds", "timeoutSeconds", "ttlSeconds", "maxBodyBytes"}
    allowed = required | {"allowedCNAMEs"}
    for item in probes:
        if not isinstance(item, dict) or not required.issubset(item) or not set(item).issubset(allowed):
            raise ContractError("catalog probe field set is invalid")
        probe_id = _text(item["id"], "catalog probe id", SAFE_ID)
        host = _hostname(item["host"], "catalog probe host")
        path_id = _text(item["pathId"], "catalog path id", SAFE_ID)
        cnames = item.get("allowedCNAMEs", [])
        if not isinstance(cnames, list) or len(cnames) > MAX_NAMES - 1:
            raise ContractError("catalog CNAME allowlist is invalid")
        allowed_names = [host] + [_hostname(name, "catalog CNAME") for name in cnames]
        if len(allowed_names) != len(set(allowed_names)):
            raise ContractError("catalog CNAME allowlist contains a duplicate")
        statuses = item["expectedStatus"]
        if not isinstance(statuses, list) or len(statuses) != 1 or _integer(statuses[0], "catalog HTTP status") != 200:
            raise ContractError("owned canary must declare exact integer status [200]")
        port = _integer(item["port"], "catalog probe port")
        interval = _integer(item["intervalSeconds"], "catalog interval")
        timeout = _integer(item["timeoutSeconds"], "catalog timeout")
        if item["method"] != "GET" or item["kind"] != "https" or port != 443:
            raise ContractError("owned canary must be HTTPS GET with exact status [200]")
        marker = _text(item["requiredMarker"], "catalog required marker", limit=256)
        if any(ord(char) < 0x20 and char != "\t" for char in marker):
            raise ContractError("catalog required marker contains a control character")
        if probe_id in result or path_id not in path_ids:
            raise ContractError("catalog probe identity is duplicated or unbound")
        ttl = _integer(item["ttlSeconds"], "catalog TTL")
        body_limit = _integer(item["maxBodyBytes"], "catalog body limit")
        if interval < 30 or interval > 3600 or timeout < 1 or timeout > 10:
            raise ContractError("catalog interval or timeout is outside probe bounds")
        if ttl < 30 or ttl > 7200 or ttl < interval or ttl > 2 * interval or body_limit < 1 or body_limit > 65536:
            raise ContractError("catalog TTL relationship or body limit is outside probe bounds")
        result[probe_id] = {
            "host": host, "allowedNames": set(allowed_names), "requestPath": item["requestPath"],
            "method": "GET", "expectedStatus": [200], "requiredMarker": marker,
            "ttlSeconds": ttl, "maxBodyBytes": body_limit,
        }
        _request_path(item["requestPath"], "catalog request path")
    return result


def validate_contract(contract: Any, contract_raw: bytes, catalog: Any, catalog_raw: bytes, now: int) -> dict[str, Any]:
    top = _exact(contract, {"schema", "revision", "issuedUnix", "validFromUnix", "validUntilUnix", "catalogSha256", "approval", "canaries"}, "canary contract")
    if top["schema"] != CONTRACT_SCHEMA:
        raise ContractError("canary contract schema is invalid")
    revision = _text(top["revision"], "canary contract revision", SAFE_REVISION)
    issued = _integer(top["issuedUnix"], "contract issue time")
    valid_from = _integer(top["validFromUnix"], "contract valid-from time")
    valid_until = _integer(top["validUntilUnix"], "contract expiry")
    if min(issued, valid_from, valid_until) <= 0 or issued > now or valid_from > now or valid_until <= now or issued > valid_from or valid_until - valid_from > MAX_CONTRACT_LIFETIME:
        raise ContractError("canary contract is stale, future-dated, or excessively long")
    catalog_sha = _text(top["catalogSha256"], "catalog SHA-256", HEX64)
    if catalog_sha != _sha256(catalog_raw):
        raise ContractError("catalog SHA-256 mismatch")
    approval = _exact(top["approval"], {"status", "owner", "approvedUnix", "evidenceSha256"}, "contract approval")
    if approval["status"] != "approved":
        raise ContractError("canary contract is not approved")
    _text(approval["owner"], "approval owner", SAFE_ID)
    approved = _integer(approval["approvedUnix"], "approval time")
    _text(approval["evidenceSha256"], "approval evidence SHA-256", HEX64)
    if approved > now or approved < issued or approved > valid_from:
        raise ContractError("approval time is invalid or in the future")

    probes = _catalog(catalog)
    entries = top["canaries"]
    if not isinstance(entries, list) or len(entries) != len(probes):
        raise ContractError("canaries must cover every catalog probe exactly once")
    seen: set[str] = set()
    address_users: dict[str, list[str]] = {}
    families: set[str] = set()
    for index, value in enumerate(entries):
        entry = _exact(value, {"probeId", "queryName", "cnameChain", "addresses", "resolvedUnix", "expiresUnix", "ownership", "tls", "http"}, f"canary {index}")
        probe_id = _text(entry["probeId"], f"canary {index} probe id", SAFE_ID)
        if probe_id not in probes or probe_id in seen:
            raise ContractError("canary probe id is unknown or duplicated")
        seen.add(probe_id)
        probe = probes[probe_id]
        if entry["queryName"] != probe["host"]:
            raise ContractError("canary query name does not match catalog")
        chain = entry["cnameChain"]
        if not isinstance(chain, list) or not chain or len(chain) > MAX_NAMES or chain[0] != probe["host"]:
            raise ContractError("CNAME chain is incomplete or too long")
        names = [_hostname(name, "CNAME chain name") for name in chain]
        if len(names) != len(set(names)):
            raise ContractError("CNAME chain contains a duplicate or loop")
        if any(name not in probe["allowedNames"] for name in names[1:]):
            raise ContractError("CNAME chain leaves the catalog allowlist")
        resolved = _integer(entry["resolvedUnix"], "resolution time")
        expires = _integer(entry["expiresUnix"], "resolution expiry")
        if resolved <= 0 or expires <= 0 or resolved > now or expires <= now or resolved < valid_from or expires > valid_until or expires - resolved != probe["ttlSeconds"]:
            raise ContractError("resolution is stale, future-dated, or violates catalog TTL")
        addresses = entry["addresses"]
        if not isinstance(addresses, list) or not addresses or len(addresses) > MAX_ADDRESSES:
            raise ContractError("canary address set is invalid")
        parsed = [_public_ip(address) for address in addresses]
        if len(parsed) != len(set(parsed)):
            raise ContractError("one canary contains a duplicate address")
        for address in parsed:
            families.add("ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6")
            address_users.setdefault(address, []).append(probe_id)

        ownership = _exact(entry["ownership"], {"mode", "owner", "evidenceSha256"}, "canary ownership")
        if ownership["mode"] != "operator-controlled":
            raise ContractError("canary ownership mode is not operator-controlled")
        canary_owner = _text(ownership["owner"], "canary owner", SAFE_ID)
        if canary_owner != approval["owner"]:
            raise ContractError("canary owner differs from approval owner")
        _text(ownership["evidenceSha256"], "canary ownership evidence", HEX64)

        tls = _exact(entry["tls"], {"serverName", "verifyHostname", "certificateDNSNames", "minimumVersion"}, "canary TLS contract")
        server_name = _hostname(tls["serverName"], "TLS server name")
        verify_name = _hostname(tls["verifyHostname"], "TLS verify hostname")
        if server_name != probe["host"] or verify_name != probe["host"] or tls["minimumVersion"] != "TLS1.2":
            raise ContractError("TLS hostname or minimum version differs from the catalog contract")
        certificate_names = tls["certificateDNSNames"]
        if not isinstance(certificate_names, list) or not certificate_names or len(certificate_names) > MAX_NAMES:
            raise ContractError("certificate DNS name set is invalid")
        cert_names = [_hostname(name, "certificate DNS name", wildcard=True) for name in certificate_names]
        if len(cert_names) != len(set(cert_names)) or not any(_wildcard_matches(name, verify_name) for name in cert_names):
            raise ContractError("certificate DNS names are duplicated or do not cover verifyHostname")

        http = _exact(entry["http"], {"method", "requestPath", "expectedStatus", "requiredMarker", "maxBodyBytes", "statusSemantics"}, "canary HTTP contract")
        _request_path(http["requestPath"], "HTTP request path")
        http_statuses = http["expectedStatus"]
        if not isinstance(http_statuses, list) or len(http_statuses) != 1 or _integer(http_statuses[0], "HTTP expected status") != 200:
            raise ContractError("HTTP expected status must be exact integer [200]")
        http_body_limit = _integer(http["maxBodyBytes"], "HTTP body limit")
        if http["method"] != probe["method"] or http["requestPath"] != probe["requestPath"]:
            raise ContractError("HTTP method, path, or success status differs from catalog")
        if http["requiredMarker"] != probe["requiredMarker"] or http_body_limit != probe["maxBodyBytes"]:
            raise ContractError("HTTP marker or body limit differs from catalog")
        if http["statusSemantics"] != "owned-canary-success-only":
            raise ContractError("HTTP status semantics must be owned-canary-success-only")
    if seen != set(probes):
        raise ContractError("canary coverage is incomplete")

    shared = [
        {"address": address, "probeIds": sorted(set(users))}
        for address, users in sorted(address_users.items(), key=lambda item: ipaddress.ip_address(item[0]).packed)
        if len(set(users)) > 1
    ]
    blockers = [
        "approval and ownership evidence hashes were not cryptographically verified by this tool",
        "actual DNS response was not observed",
        "actual TLS certificate and hostname verification were not observed",
        "actual HTTP status and marker were not observed",
        "runtime egress isolation and unique traffic attribution remain separate gates",
    ]
    filesystem_assurance = "posix-dirfd-owner-mode-double-read-fsync"
    if os.name != "posix":
        filesystem_assurance = "non-posix-best-effort-blocked"
        blockers.extend([
            "non-POSIX platforms cannot prove uid/gid ownership or POSIX mode/ACL equivalence",
            "Windows chmod does not prove equivalent NTFS ACL isolation",
            "Windows creation-time metadata is not equivalent to POSIX ctime mutation evidence",
            "non-POSIX platforms do not provide this tool with dirfd-bound durable directory fsync",
        ])
    return {
        "schema": REPORT_SCHEMA,
        "status": "BLOCKED",
        "reason": "VALID_CONTRACT_IS_NOT_START_EVIDENCE",
        "validatedAtUnix": now,
        "contractSchema": CONTRACT_SCHEMA,
        "contractRevision": revision,
        "contractSha256": _sha256(contract_raw),
        "catalogSha256": catalog_sha,
        "probeCount": len(probes),
        "addressFamilies": sorted(families),
        "sharedAddresses": shared,
        "readOnly": True,
        "advisoryOnly": True,
        "acceptedStartEvidenceEmitted": False,
        "filesystemAssurance": filesystem_assurance,
        "unresolvedBlockers": blockers,
    }


def atomic_publish_new(path: pathlib.Path, payload: bytes) -> None:
    if not path.is_absolute():
        raise ContractError("output path must be absolute")
    parent = path.parent
    _check_components(parent, "output")
    parent_status = os.lstat(parent)
    _trusted_owner_mode(parent_status, "output parent", directory=True)
    if os.name == "posix" and stat.S_IMODE(parent_status.st_mode) & 0o077:
        raise ContractError("output parent must be private on POSIX")
    if path.exists() or path.is_symlink():
        raise ContractError("output parent must exist and output must not exist")
    temporary_name = f".canary-validation-{uuid.uuid4().hex}"
    published = False
    if os.name == "posix":
        _require_posix_dirfd_capabilities()
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(parent, directory_flags)
        try:
            if _fingerprint(os.fstat(directory_fd)) != _fingerprint(parent_status):
                raise ContractError("output parent identity changed before publication")
            descriptor = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.link(temporary_name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
                published = True
                os.fsync(directory_fd)
                os.unlink(temporary_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                published_status = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
                if published_status.st_nlink != 1 or stat.S_IMODE(published_status.st_mode) != 0o600:
                    raise ContractError("published output ownership, mode, or link count is invalid")
                _trusted_owner_mode(published_status, "published output")
            except BaseException:
                if published:
                    try:
                        os.unlink(path.name, dir_fd=directory_fd)
                        published = False
                        os.fsync(directory_fd)
                    except OSError:
                        pass
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
                raise
        except FileExistsError as exc:
            raise ContractError("output already exists") from exc
        finally:
            os.close(directory_fd)
        return

    temporary = parent / temporary_name
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path)
        published = True
    except FileExistsError as exc:
        raise ContractError("output already exists") from exc
    except BaseException:
        if published:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            if published:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise


def run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate",))
    parser.add_argument("--contract", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)
    try:
        contract, contract_raw = load_immutable_json(pathlib.Path(arguments.contract))
        catalog, catalog_raw = load_immutable_json(pathlib.Path(arguments.catalog))
        report = validate_contract(contract, contract_raw, catalog, catalog_raw, int(time.time()))
        payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        atomic_publish_new(pathlib.Path(arguments.output), payload)
    except (ContractError, OSError, UnicodeError, RecursionError, OverflowError, MemoryError) as exc:
        print(f"canary contract validation failed: {exc}", file=sys.stderr)
        return 2
    print("CANARY_CONTRACT=VALIDATED_BUT_BLOCKED")
    return BLOCKED_EXIT


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
