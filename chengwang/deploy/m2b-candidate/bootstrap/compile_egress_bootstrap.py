#!/usr/bin/env python3
"""Compile and validate a deterministic, deliberately non-executable egress plan.

This command is an offline contract checker.  It never invokes Docker, nft, a
resolver, or the network.  A valid input produces a BLOCKED report and exits
78: runtime identity and host-global firewall ordering cannot exist before the
candidate container has been created and observed.
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
import tempfile
from typing import Any, Iterable


INPUT_SCHEMA = "chengwang.m2b-egress-bootstrap-input/v1"
PLAN_SCHEMA = "chengwang.m2b-egress-bootstrap-plan/v1"
REPORT_SCHEMA = "chengwang.m2b-egress-bootstrap-report/v1"
BLOCKED_EXIT = 78
MAX_INPUT = 512 * 1024
MAX_ADDRESSES = 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
SAFE_DNS = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$")
BRIDGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
NFT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
COUNTER_LABEL = re.compile(r"^cw:[a-z0-9-]+:[0-9]{4}:[0-9a-f]{10}$")
RFC1918 = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PROHIBITED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
    "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fec0::/10",
))
PROHIBITED_ADDRESSES = {
    ipaddress.ip_address(value)
    for value in ("100.100.100.200", "168.63.129.16", "169.254.169.254", "169.254.170.2")
}


class ContractError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ContractError("non-standard JSON number")


def _exact(value: Any, names: Iterable[str], label: str) -> dict[str, Any]:
    expected = set(names)
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{label} field set is invalid")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None, maximum: int = 253) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ContractError(f"{label} is invalid")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ContractError(f"{label} is not valid Unicode") from exc
    if encoded_length > maximum:
        raise ContractError(f"{label} is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise ContractError(f"{label} contains a control character")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ContractError(f"{label} format is invalid")
    return value


def _integer(value: Any, label: str, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ContractError(f"{label} is invalid")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be boolean")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    ctime = info.st_ctime_ns if os.name == "posix" else 0
    return info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, ctime


def _check_path(path: pathlib.Path, leaf: str) -> None:
    if not path.is_absolute():
        raise ContractError(f"{leaf} path must be absolute")
    current = pathlib.Path(path.anchor)
    for index, part in enumerate(path.parts[1:], start=1):
        current /= part
        try:
            info = os.lstat(current)
        except OSError as exc:
            if leaf == "output" and index == len(path.parts) - 1:
                return
            raise ContractError(f"{leaf} path component is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ContractError(f"{leaf} path contains a symlink")
        final = index == len(path.parts) - 1
        if final and leaf == "input":
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ContractError("input must be a single-link regular file")
        elif final and leaf == "output":
            raise ContractError("output must not already exist")
        elif not stat.S_ISDIR(info.st_mode):
            raise ContractError(f"{leaf} ancestor is not a directory")
        if os.name == "posix":
            if info.st_uid != 0:
                raise ContractError(f"{leaf} path must be root-owned")
            if stat.S_IMODE(info.st_mode) & 0o022 and not (stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX):
                raise ContractError(f"{leaf} path is group/world writable")
            if final and leaf == "input" and stat.S_IMODE(info.st_mode) & 0o077:
                raise ContractError("input mode must be 0600 or stricter")


def _read_once(path: pathlib.Path) -> tuple[bytes, tuple[int, ...]]:
    _check_path(path, "input")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_INPUT:
            raise ContractError("input type, links, or size is invalid")
        chunks: list[bytes] = []
        remaining = MAX_INPUT + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > MAX_INPUT or _fingerprint(before) != _fingerprint(after) or len(raw) != after.st_size:
            raise ContractError("input changed while being read or exceeds size limit")
    finally:
        os.close(descriptor)
    if _fingerprint(after) != _fingerprint(os.lstat(path)):
        raise ContractError("input path identity changed")
    return raw, _fingerprint(after)


def load_immutable_json(path: pathlib.Path) -> tuple[Any, bytes]:
    first, first_fp = _read_once(path)
    second, second_fp = _read_once(path)
    if first_fp != second_fp or first != second:
        raise ContractError("input changed between verification reads")
    try:
        value = json.loads(first.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except ContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ContractError("input is not strict UTF-8 JSON") from exc
    return value, first


def atomic_write_new(path: pathlib.Path, value: Any) -> None:
    _check_path(path, "output")
    parent = path.parent.resolve(strict=True)
    if parent != path.parent:
        raise ContractError("output parent must not traverse a symlink")
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode):
        raise ContractError("output parent is not a directory")
    if os.name == "posix" and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise ContractError("output parent must be root:root mode 0700")
    descriptor, temporary = tempfile.mkstemp(prefix=".egress-bootstrap.", dir=str(parent))
    temp = pathlib.Path(temporary)
    try:
        os.fchmod(descriptor, 0o600) if hasattr(os, "fchmod") else os.chmod(temp, 0o600)
        payload = _canonical(value) + b"\n"
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        published = False
        try:
            os.link(temp, path, follow_symlinks=False)
            published = True
            if os.name == "posix":
                directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                directory_fd = os.open(parent, directory_flags)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except BaseException:
            if published:
                path.unlink(missing_ok=True)
            raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temp.unlink(missing_ok=True)


def _public_address(value: Any, label: str) -> str:
    source = _text(value, label, maximum=64)
    try:
        address = ipaddress.ip_address(source)
    except ValueError as exc:
        raise ContractError(f"{label} is not an IP address") from exc
    if source != address.compressed or getattr(address, "ipv4_mapped", None) is not None:
        raise ContractError(f"{label} is not canonical")
    if not address.is_global or address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ContractError(f"{label} is not permitted public unicast")
    if address in PROHIBITED_ADDRESSES or any(address in network for network in PROHIBITED_NETWORKS):
        raise ContractError(f"{label} is in an explicitly prohibited range")
    return source


def _address_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ADDRESSES:
        raise ContractError(f"{label} address count is invalid")
    result = [_public_address(item, label) for item in value]
    if len(result) != len(set(result)) or result != sorted(result, key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item).packed)):
        raise ContractError(f"{label} addresses must be unique and canonically sorted")
    return result


def _network(value: Any) -> tuple[dict[str, Any], ipaddress._BaseNetwork, ipaddress._BaseAddress, ipaddress._BaseAddress]:
    item = _exact(value, {"subnet", "gateway", "containerAddress"}, "network family")
    try:
        network = ipaddress.ip_network(_text(item["subnet"], "subnet", maximum=64), strict=True)
        gateway = ipaddress.ip_address(_text(item["gateway"], "gateway", maximum=64))
        container = ipaddress.ip_address(_text(item["containerAddress"], "container address", maximum=64))
    except ValueError as exc:
        raise ContractError("network address is invalid or non-canonical") from exc
    if item["subnet"] != network.with_prefixlen or item["gateway"] != gateway.compressed or item["containerAddress"] != container.compressed:
        raise ContractError("network address is not canonical")
    if gateway.version != network.version or container.version != network.version or gateway not in network or container not in network or gateway == container:
        raise ContractError("gateway/container address is outside or conflicts within subnet")
    if network.version == 4:
        if not any(network.subnet_of(parent) for parent in RFC1918) or network.prefixlen < 24 or network.prefixlen > 29:
            raise ContractError("IPv4 bridge subnet must be RFC1918 /24 through /29")
        if gateway in (network.network_address, network.broadcast_address) or container in (network.network_address, network.broadcast_address):
            raise ContractError("IPv4 gateway/container cannot be network or broadcast")
    else:
        if not network.subnet_of(ipaddress.ip_network("fc00::/7")) or network.prefixlen != 64:
            raise ContractError("IPv6 bridge subnet must be a ULA /64")
        if gateway == network.network_address or container == network.network_address:
            raise ContractError("IPv6 subnet-router anycast address cannot be gateway or container")
    return item, network, gateway, container


def _label(chain: str, kind: str, ordinal: int, match: dict[str, Any], verdict: str) -> str:
    suffix = _sha(_canonical({"chain": chain, "match": match, "verdict": verdict}))[:10]
    value = f"cw:{kind}:{ordinal:04d}:{suffix}"
    if COUNTER_LABEL.fullmatch(value) is None:
        raise AssertionError("generated counter label is invalid")
    return value


def _rule(chain: str, ordinal: int, kind: str, match: dict[str, Any], verdict: str, owners: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "chain": chain,
        "ordinal": ordinal,
        "kind": kind,
        "match": match,
        "counterLabel": _label(chain, kind, ordinal, match, verdict),
        "verdict": verdict,
    }
    if owners is not None:
        result["owners"] = owners
    return result


def compile_report(value: Any, raw: bytes) -> dict[str, Any]:
    root = _exact(value, {"schema", "revision", "validationUnix", "candidate", "network", "identityBinding", "firewall", "resolver", "canary"}, "input")
    if root["schema"] != INPUT_SCHEMA:
        raise ContractError("input schema is invalid")
    revision = _text(root["revision"], "revision", SAFE_NAME)
    validation_unix = _integer(root["validationUnix"], "validationUnix", 1)

    candidate = _exact(root["candidate"], {"projectName", "serviceName", "imageId", "composeSha256", "resolverMode"}, "candidate")
    project = _text(candidate["projectName"], "projectName", SAFE_NAME)
    service = _text(candidate["serviceName"], "serviceName", SAFE_NAME)
    image = _text(candidate["imageId"], "imageId", re.compile(r"^sha256:[0-9a-f]{64}$"), 71)
    compose_sha = _text(candidate["composeSha256"], "composeSha256", HEX64, 64)
    if candidate["resolverMode"] != "DIRECT_DOT_ONLY_NO_SYSTEM_RESOLVER":
        raise ContractError("candidate resolverMode must prohibit Docker embedded/system DNS")

    network = _exact(root["network"], {"name", "driver", "internal", "attachable", "bridgeName", "enableIcc", "enableIpv6", "ipv4", "ipv6"}, "network")
    network_name = _text(network["name"], "network name", SAFE_NAME)
    bridge_name = _text(network["bridgeName"], "bridgeName", BRIDGE_NAME, 15)
    if network["driver"] != "bridge" or _boolean(network["internal"], "internal") is not False:
        raise ContractError("egress bootstrap requires a routable non-internal bridge")
    if _boolean(network["attachable"], "attachable") or _boolean(network["enableIcc"], "enableIcc"):
        raise ContractError("attachable and inter-container communication must be false")
    if not _boolean(network["enableIpv6"], "enableIpv6"):
        raise ContractError("dual-stack bootstrap requires IPv6 to be explicitly enabled")
    ipv4, subnet4, gateway4, container4 = _network(network["ipv4"])
    ipv6, subnet6, gateway6, container6 = _network(network["ipv6"])
    if subnet4.version != 4 or subnet6.version != 6:
        raise ContractError("IPv4 and IPv6 family objects are reversed")

    binding = _exact(root["identityBinding"], {"mode", "containerId", "containerPid", "pidStartTime", "netnsInode", "cgroupId", "vethHostIfindex"}, "identityBinding")
    if binding != {"mode": "pending-runtime", "containerId": None, "containerPid": None, "pidStartTime": None, "netnsInode": None, "cgroupId": None, "vethHostIfindex": None}:
        raise ContractError("offline bootstrap identity must remain pending-runtime with null runtime identifiers")

    firewall = _exact(root["firewall"], {"family", "table", "forwardEntryChain", "forwardPolicyChain", "inputEntryChain", "inputPolicyChain", "forwardPriority", "inputPriority", "basePolicy", "allowPlainDns", "allowDhcp", "allowIpv6NeighborDiscovery", "globalImpactApproval"}, "firewall")
    if firewall["family"] != "inet" or firewall["basePolicy"] != "accept":
        raise ContractError("firewall must use inet base chains with accept policy")
    table = _text(firewall["table"], "table", NFT_NAME, 32)
    forward_entry_chain = _text(firewall["forwardEntryChain"], "forwardEntryChain", NFT_NAME, 32)
    forward_policy_chain = _text(firewall["forwardPolicyChain"], "forwardPolicyChain", NFT_NAME, 32)
    input_entry_chain = _text(firewall["inputEntryChain"], "inputEntryChain", NFT_NAME, 32)
    input_policy_chain = _text(firewall["inputPolicyChain"], "inputPolicyChain", NFT_NAME, 32)
    if len({table, forward_entry_chain, forward_policy_chain, input_entry_chain, input_policy_chain}) != 5:
        raise ContractError("table and all chain names must be distinct")
    forward_priority = _integer(firewall["forwardPriority"], "forwardPriority", -300, 300)
    input_priority = _integer(firewall["inputPriority"], "inputPriority", -300, 300)
    if _boolean(firewall["allowPlainDns"], "allowPlainDns"):
        raise ContractError("plain DNS must remain denied")
    if _boolean(firewall["allowDhcp"], "allowDhcp"):
        raise ContractError("DHCP is prohibited because both container addresses are static")
    if not _boolean(firewall["allowIpv6NeighborDiscovery"], "allowIpv6NeighborDiscovery"):
        raise ContractError("IPv6 neighbor discovery must be explicitly contracted for the routed ULA bridge")
    if firewall["globalImpactApproval"] != "unproven":
        raise ContractError("offline plan cannot assert host-global impact approval")

    resolver = _exact(root["resolver"], {"serverName", "port", "transport", "addresses", "observedUnix", "expiresUnix"}, "resolver")
    server_name = _text(resolver["serverName"], "resolver serverName", SAFE_DNS)
    if resolver["transport"] != "tcp-tls" or _integer(resolver["port"], "resolver port", 1, 65535) != 853:
        raise ContractError("resolver must be fixed TCP/TLS port 853")
    resolver_addresses = _address_list(resolver["addresses"], "resolver")
    resolver_observed = _integer(resolver["observedUnix"], "resolver observedUnix", 1)
    resolver_expires = _integer(resolver["expiresUnix"], "resolver expiresUnix", 1)
    if not resolver_observed <= validation_unix < resolver_expires or resolver_expires - resolver_observed > 86400:
        raise ContractError("resolver address lifetime is invalid at validationUnix")

    canary = _exact(root["canary"], {"contractSha256", "observedUnix", "expiresUnix", "probes"}, "canary")
    contract_sha = _text(canary["contractSha256"], "canary contractSha256", HEX64, 64)
    observed = _integer(canary["observedUnix"], "canary observedUnix", 1)
    expires = _integer(canary["expiresUnix"], "canary expiresUnix", 1)
    if not observed <= validation_unix < expires or expires - observed > 86400:
        raise ContractError("canary address lifetime is invalid at validationUnix")
    if not isinstance(canary["probes"], list) or not canary["probes"] or len(canary["probes"]) > 64:
        raise ContractError("canary probe count is invalid")

    ownership: dict[str, set[str]] = {}
    probe_ids: set[str] = set()
    canary_rows: list[dict[str, Any]] = []
    for item in canary["probes"]:
        probe = _exact(item, {"id", "host", "port", "addresses"}, "canary probe")
        probe_id = _text(probe["id"], "probe id", SAFE_NAME)
        if probe_id in probe_ids:
            raise ContractError("duplicate canary probe id")
        probe_ids.add(probe_id)
        host = _text(probe["host"], "canary host", SAFE_DNS)
        if _integer(probe["port"], "canary port", 1, 65535) != 443:
            raise ContractError("canary HTTPS port must be 443")
        addresses = _address_list(probe["addresses"], f"canary {probe_id}")
        for address in addresses:
            ownership.setdefault(address, set()).add(probe_id)
        canary_rows.append({"id": probe_id, "host": host, "port": 443, "addresses": addresses})
    canary_rows.sort(key=lambda item: item["id"])
    if len(ownership) > MAX_ADDRESSES:
        raise ContractError("combined canary address count exceeds the rule-budget limit")

    destination_owners: dict[tuple[str, int, str], set[str]] = {}
    for address in resolver_addresses:
        destination_owners.setdefault((address, 853, "dot"), set()).add(f"resolver:{server_name}")
    for row in canary_rows:
        for address in row["addresses"]:
            destination_owners.setdefault((address, 443, "https"), set()).add(f"canary:{row['id']}")
    if len(destination_owners) > 2 * MAX_ADDRESSES:
        raise ContractError("combined DoT and canary endpoint count exceeds the rule-budget limit")

    forward_entry_rules: list[dict[str, Any]] = []
    forward_policy_rules: list[dict[str, Any]] = []
    input_entry_rules: list[dict[str, Any]] = []
    input_policy_rules: list[dict[str, Any]] = []
    ordinal = 10
    forward_entry_rules.append(_rule(forward_entry_chain, ordinal, "scope-out", {"iifname": bridge_name}, f"jump:{forward_policy_chain}")); ordinal += 10
    forward_entry_rules.append(_rule(forward_entry_chain, ordinal, "return-established", {"oifname": bridge_name, "ctState": ["established", "related"]}, "accept")); ordinal += 10
    forward_entry_rules.append(_rule(forward_entry_chain, ordinal, "return-invalid", {"oifname": bridge_name, "ctState": ["invalid"]}, "drop")); ordinal += 10
    forward_entry_rules.append(_rule(forward_entry_chain, ordinal, "inbound-default", {"oifname": bridge_name}, "drop")); ordinal += 10
    for source, family, nfproto in ((str(container4), "ip", "ipv4"), (str(container6), "ip6", "ipv6")):
        forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-invalid", {"nfproto": nfproto, "source": source, "ctState": ["invalid"]}, "drop")); ordinal += 10
        forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-established", {"nfproto": nfproto, "source": source, "ctState": ["established", "related"]}, "accept")); ordinal += 10
        for address, port, purpose in sorted(destination_owners, key=lambda item: (ipaddress.ip_address(item[0]).version, ipaddress.ip_address(item[0]).packed, item[1], item[2])):
            if (family == "ip") != (ipaddress.ip_address(address).version == 4):
                continue
            owners = sorted(destination_owners[(address, port, purpose)])
            match = {"nfproto": nfproto, "source": source, "protocol": "tcp", "destination": address, "destinationPort": port, "ctState": ["new"]}
            forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-{purpose}", match, "accept", owners)); ordinal += 10
        forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-plain-dns-udp", {"nfproto": nfproto, "source": source, "protocol": "udp", "destinationPort": 53}, "drop")); ordinal += 10
        forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-plain-dns-tcp", {"nfproto": nfproto, "source": source, "protocol": "tcp", "destinationPort": 53}, "drop")); ordinal += 10
        forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-default", {"nfproto": nfproto, "source": source}, "drop")); ordinal += 10
        forward_policy_rules.append(_rule(forward_policy_chain, ordinal, f"{family}-source-spoof", {"nfproto": nfproto, "iifname": bridge_name, "sourceNot": source}, "drop")); ordinal += 10

    input_entry_rules.append(_rule(input_entry_chain, ordinal, "host-scope-in", {"iifname": bridge_name}, f"jump:{input_policy_chain}")); ordinal += 10
    input_policy_rules.append(_rule(input_policy_chain, ordinal, "host-invalid", {"ctState": ["invalid"]}, "drop")); ordinal += 10
    input_policy_rules.append(_rule(input_policy_chain, ordinal, "host-nd-rs", {"nfproto": "ipv6", "sourceSet": [str(container6), "fe80::/64"], "protocol": "ipv6-icmp", "icmpv6Type": [133], "hopLimit": 255}, "accept")); ordinal += 10
    input_policy_rules.append(_rule(input_policy_chain, ordinal, "host-nd-ns", {"nfproto": "ipv6", "sourceSet": ["::", str(container6), "fe80::/64"], "protocol": "ipv6-icmp", "icmpv6Type": [135], "hopLimit": 255}, "accept")); ordinal += 10
    input_policy_rules.append(_rule(input_policy_chain, ordinal, "host-nd-na", {"nfproto": "ipv6", "sourceSet": [str(container6), "fe80::/64"], "protocol": "ipv6-icmp", "icmpv6Type": [136], "hopLimit": 255}, "accept")); ordinal += 10
    for family, nfproto, dhcp_port in (("ip", "ipv4", 67), ("ip6", "ipv6", 547)):
        for protocol, port, suffix in (("udp", dhcp_port, "dhcp-server"), ("udp", 53, "plain-dns-udp"), ("tcp", 53, "plain-dns-tcp"), ("tcp", 853, "dot-host-bypass"), ("tcp", 443, "https-host-bypass")):
            input_policy_rules.append(_rule(input_policy_chain, ordinal, f"host-{family}-{suffix}", {"nfproto": nfproto, "protocol": protocol, "destinationPort": port}, "drop")); ordinal += 10
    input_policy_rules.append(_rule(input_policy_chain, ordinal, "host-default", {"all": True}, "drop")); ordinal += 10

    rules = forward_entry_rules + forward_policy_rules + input_entry_rules + input_policy_rules

    labels = [rule["counterLabel"] for rule in rules]
    matches = [_canonical({"chain": rule["chain"], "match": rule["match"], "verdict": rule["verdict"]}) for rule in rules]
    if labels != list(dict.fromkeys(labels)) or len(matches) != len(set(matches)):
        raise ContractError("generated rules contain duplicate labels or shadow-equivalent matches")
    if [rule["ordinal"] for rule in rules] != sorted(rule["ordinal"] for rule in rules):
        raise ContractError("generated rules are not strictly ordered")
    expected_membership = {
        forward_entry_chain: forward_entry_rules,
        forward_policy_chain: forward_policy_rules,
        input_entry_chain: input_entry_rules,
        input_policy_chain: input_policy_rules,
    }
    if any(not chain_rules or any(rule["chain"] != chain for rule in chain_rules) for chain, chain_rules in expected_membership.items()):
        raise ContractError("generated rule chain membership is invalid")
    if forward_entry_rules[0]["verdict"] != f"jump:{forward_policy_chain}" or input_entry_rules[0]["verdict"] != f"jump:{input_policy_chain}":
        raise ContractError("base-chain dispatch target is invalid")

    shared = [{"address": address, "probeIds": sorted(owners)} for address, owners in sorted(ownership.items(), key=lambda item: (ipaddress.ip_address(item[0]).version, ipaddress.ip_address(item[0]).packed)) if len(owners) > 1]
    blockers = [
        "RUNTIME_CONTAINER_PID_STARTTIME_NETNS_CGROUP_VETH_BINDING_MISSING",
        "FIRST_START_REQUIRES_INDEPENDENT_NETNS_OR_PAUSED_NO_NETWORK_SHIM",
        "HOST_BASE_CHAIN_HOOK_PRIORITY_AND_GLOBAL_EFFECT_UNPROVEN",
        "BRIDGE_SUBNET_AND_GATEWAY_COLLISION_UNPROVEN_OFFLINE",
        "STATIC_DOT_AND_CANARY_TTL_MUST_BE_RECHECKED_AT_RUNTIME",
        "LINUX_NFT_SEMANTICS_AND_DOCKER_NETWORK_READBACK_NOT_EXECUTED",
        "ROLLBACK_HAS_NOT_BEEN_FAULT_INJECTED_ON_TARGET_HOST",
        "SOURCE_ADDRESS_MATCH_IS_NOT_RUNTIME_PROCESS_IDENTITY_PROOF",
        "NFT_IP_ALLOWSET_CANNOT_PROVE_TLS_SNI_CERTIFICATE_OR_HTTP_MARKER",
        "DOCKER_EMBEDDED_DNS_127_0_0_11_BYPASS_UNPROVEN",
    ]
    if shared:
        blockers.append("SHARED_DESTINATION_IP_CANNOT_PROVE_PER_PROBE_ATTRIBUTION")
    if os.name != "posix":
        blockers.append("WINDOWS_CANNOT_PROVE_POSIX_OWNER_MODE_OR_LINUX_DIRFD_SEMANTICS")

    nft_plan: dict[str, Any] = {
        "family": "inet", "table": table,
        "baseChains": [
            {"name": forward_entry_chain, "hook": "forward", "priority": forward_priority, "policy": "accept"},
            {"name": input_entry_chain, "hook": "input", "priority": input_priority, "policy": "accept"},
        ],
        "policyChains": [forward_policy_chain, input_policy_chain],
        "rules": rules,
        "forwardDefaultDenyForManagedBridge": True,
        "hostInputDefaultDenyForManagedBridge": True,
        "globalDefaultPolicyChanged": False,
    }
    nft_object_sha = _sha(_canonical(nft_plan))
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "revision": revision,
        "candidate": {"projectName": project, "serviceName": service, "imageId": image, "composeSha256": compose_sha, "resolverMode": "DIRECT_DOT_ONLY_NO_SYSTEM_RESOLVER"},
        "network": {
            "name": network_name, "driver": "bridge", "internal": False, "attachable": False,
            "bridgeName": bridge_name, "enableIcc": False, "enableIpv6": True, "ipv4": ipv4, "ipv6": ipv6,
            "runtimeCollisionCheckRequired": True,
        },
        "runtimeBinding": {
            "status": "BLOCKED_NO_RUNTIME_IDENTITY_BEFORE_PROCESS_START",
            "bootstrapMechanism": "INDEPENDENT_NETNS_OR_PAUSED_NO_NETWORK_SHIM_REQUIRED",
            "required": ["containerId", "containerPid", "pidStartTime", "netnsInode", "cgroupId", "vethHostIfindex", "networkId", "bridgeIfindex", "bootId", "containerResolvConfSha256"],
            "sourceAddressFallbackIsNotIdentityProof": True,
        },
        "nftObjectSha256": nft_object_sha,
        "nft": nft_plan,
        "allowset": {
            "plainDns": [],
            "dot": [{"serverName": server_name, "address": address, "port": 853, "transport": "tcp-tls"} for address in resolver_addresses],
            "https": canary_rows,
            "sharedDestinationAttribution": shared,
            "validationUnix": validation_unix,
            "resolverObservedUnix": resolver_observed,
            "resolverExpiresUnix": resolver_expires,
            "canaryContractSha256": contract_sha,
            "canaryObservedUnix": observed,
            "canaryExpiresUnix": expires,
        },
        "rollback": {
            "operation": "DELETE_ONLY_EXACT_MANAGED_TABLE",
            "family": "inet", "table": table,
            "managedChains": [forward_entry_chain, forward_policy_chain, input_entry_chain, input_policy_chain],
            "expectedNftObjectSha256": nft_object_sha,
            "preconditions": ["sameBootId", "sameNftObjectSha256", "sameTableDigest", "sameRuntimeIdentityBinding", "noForeignObjectsInManagedTable"],
            "automaticExecutionPermitted": False,
        },
        "globalImpact": {
            "scopeClaim": "ONLY_TRAFFIC_ON_EXACT_MANAGED_BRIDGE",
            "hostBaseChainInventoryRequired": True,
            "otherBaseChainOrderingMayOverrideOrBypassPlan": True,
            "dockerManagedRulesInteractionUnproven": True,
            "approval": "unproven",
        },
    }
    plan_sha = _sha(_canonical(plan))
    return {
        "schema": REPORT_SCHEMA,
        "status": "BLOCKED",
        "reason": "OFFLINE_PLAN_CANNOT_PROVE_RUNTIME_EGRESS_ENFORCEMENT",
        "exitCode": BLOCKED_EXIT,
        "advisoryOnly": True,
        "executionPermitted": False,
        "acceptedEvidenceProduced": False,
        "inputSha256": _sha(raw),
        "canonicalInputSha256": _sha(_canonical(value)),
        "planSha256": plan_sha,
        "plan": plan,
        "blockers": blockers,
    }


def command_compile(input_path: pathlib.Path, output_path: pathlib.Path) -> int:
    value, raw = load_immutable_json(input_path)
    report = compile_report(value, raw)
    atomic_write_new(output_path, report)
    print(f"BOOTSTRAP_PLAN=BLOCKED sha256={report['planSha256']}")
    return BLOCKED_EXIT


def command_validate(input_path: pathlib.Path, report_path: pathlib.Path) -> int:
    value, raw = load_immutable_json(input_path)
    report, _ = load_immutable_json(report_path)
    expected = compile_report(value, raw)
    if report != expected or _sha(_canonical(report["plan"])) != report.get("planSha256"):
        raise ContractError("report is not the exact deterministic compilation of the input")
    print(f"BOOTSTRAP_PLAN=VALID_BLOCKED sha256={report['planSha256']}")
    return BLOCKED_EXIT


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    compile_command = commands.add_parser("compile")
    compile_command.add_argument("--input", required=True, type=pathlib.Path)
    compile_command.add_argument("--output", required=True, type=pathlib.Path)
    validate_command = commands.add_parser("validate")
    validate_command.add_argument("--input", required=True, type=pathlib.Path)
    validate_command.add_argument("--report", required=True, type=pathlib.Path)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "compile":
            return command_compile(arguments.input, arguments.output)
        return command_validate(arguments.input, arguments.report)
    except (ContractError, OSError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
