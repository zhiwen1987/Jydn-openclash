#!/bin/sh
# Purely offline/static verification. This script never invokes Docker, starts
# a container/probe/network service, installs firewall rules, resolves DNS, or
# performs network I/O. It only runs bounded local read-only inspection tools.
set -eu

blocked() {
  printf '%s\n' 'ACTIVE_START=BLOCKED'
}
trap blocked EXIT

fail() {
  printf '%s\n' "probe config rejected: $*" >&2
  exit 1
}

ENV_FILE=
COMPOSE_FILE=
CATALOG_FILE=
DOT_CA_FILE=
EGRESS_POLICY_FILE=
CANDIDATE_ROOT=

while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "every option requires one explicit value"
  case "$1" in
    --env) ENV_FILE=$2 ;;
    --compose) COMPOSE_FILE=$2 ;;
    --catalog) CATALOG_FILE=$2 ;;
    --dot-ca) DOT_CA_FILE=$2 ;;
    --egress-policy) EGRESS_POLICY_FILE=$2 ;;
    --candidate-root) CANDIDATE_ROOT=$2 ;;
    *) fail "unknown option: $1" ;;
  esac
  shift 2
done

for required_value in ENV_FILE COMPOSE_FILE CATALOG_FILE DOT_CA_FILE EGRESS_POLICY_FILE CANDIDATE_ROOT; do
  eval "resolved_value=\${$required_value}"
  [ -n "$resolved_value" ] || fail "missing explicit --$(printf '%s' "$required_value" | tr 'A-Z_' 'a-z-')"
done
command -v python3 >/dev/null 2>&1 || fail "python3 is required for offline verification"
command -v findmnt >/dev/null 2>&1 || fail "findmnt is required for mount-boundary verification"
command -v realpath >/dev/null 2>&1 || fail "realpath is required for repository-file verification"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
EXPECTED_COMPOSE=$(realpath "$SCRIPT_DIR/../compose.probe-agent.yaml")

python3 - "$ENV_FILE" "$COMPOSE_FILE" "$CATALOG_FILE" "$DOT_CA_FILE" "$EGRESS_POLICY_FILE" "$CANDIDATE_ROOT" "$EXPECTED_COMPOSE" <<'PY'
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

env_arg, compose_arg, catalog_arg, ca_arg, policy_arg, root_arg, expected_compose_arg = sys.argv[1:]

def reject(message):
    raise SystemExit(f"probe config rejected: {message}")

def explicit_absolute_file(raw, label):
    path = pathlib.Path(raw)
    if not path.is_absolute():
        reject(f"{label} must be an explicit absolute path")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            reject(f"{label} does not exist: {path}")
        if stat.S_ISLNK(info.st_mode):
            reject(f"{label} contains a symlink component: {current}")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        reject(f"{label} must be a regular file: {path}")
    return path.resolve(strict=True)

def explicit_absolute_directory(raw, label):
    path = pathlib.Path(raw)
    if not path.is_absolute():
        reject(f"{label} must be an explicit absolute path")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            reject(f"{label} does not exist: {path}")
        if stat.S_ISLNK(info.st_mode):
            reject(f"{label} contains a symlink component: {current}")
    if not path.is_dir():
        reject(f"{label} must be a real directory: {path}")
    return path.resolve(strict=True)

def is_within(parent, child):
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False

def reject_production(path, label):
    production = pathlib.Path("/opt/chengwang")
    broad = {pathlib.Path("/"), pathlib.Path("/etc"), pathlib.Path("/opt"), pathlib.Path("/var"), pathlib.Path("/var/lib"), pathlib.Path("/srv")}
    if path in broad or path == production or is_within(production, path):
        reject(f"{label} points at a production or broad system path: {path}")

def mount_signature(path, label):
    try:
        completed = subprocess.run(
            ["findmnt", "--target", str(path), "--noheadings", "--raw", "--output", "TARGET,MAJ:MIN,FSROOT"],
            check=True, capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        reject(f"cannot inspect mount boundary for {label}: {error}")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        reject(f"mount boundary for {label} is ambiguous")
    return lines[0]

env_path = explicit_absolute_file(env_arg, "env file")
compose_path = explicit_absolute_file(compose_arg, "compose file")
expected_compose_path = explicit_absolute_file(expected_compose_arg, "repository compose file")
catalog_path = explicit_absolute_file(catalog_arg, "catalog file")
ca_path = explicit_absolute_file(ca_arg, "DoT CA file")
policy_path = explicit_absolute_file(policy_arg, "egress policy file")
root_path = explicit_absolute_directory(root_arg, "candidate root")
reject_production(root_path, "candidate root")
if compose_path != expected_compose_path:
    reject("compose file must be the repository-owned compose.probe-agent.yaml next to this verifier")
for path, label in (
    (env_path, "env file"), (compose_path, "compose file"),
    (catalog_path, "catalog file"), (ca_path, "DoT CA file"),
    (policy_path, "egress policy file"),
):
    reject_production(path, label)

root_text = root_path.as_posix()
match = re.fullmatch(r"/(?:var/lib|srv)/chengwang-m2b-candidate/([a-z0-9][a-z0-9_-]{0,19})", root_text)
if not match:
    reject("candidate root must be one dedicated, single-segment instance under /var/lib or /srv")
namespace_parent = root_path.parent
namespace_info = namespace_parent.stat()
if namespace_info.st_uid != 0 or namespace_info.st_mode & 0o022:
    reject("candidate namespace parent must be root-owned and not group/world writable")
root_info = root_path.stat()
if root_info.st_uid != 0 or root_info.st_mode & 0o022:
    reject("candidate root must be root-owned and not group/world writable")
namespace_base = pathlib.Path("/var/lib") if root_text.startswith("/var/lib/") else pathlib.Path("/srv")
base_info = namespace_base.stat()
base_mount = mount_signature(namespace_base, "candidate namespace base")
if (
    base_info.st_dev != namespace_info.st_dev or namespace_info.st_dev != root_info.st_dev
    or base_mount != mount_signature(namespace_parent, "candidate namespace")
    or base_mount != mount_signature(root_path, "candidate root")
):
    reject("candidate root must not be a separate or bind-mounted filesystem")
marker = explicit_absolute_file(str(root_path / ".chengwang-m2b-candidate-root"), "candidate root marker")
marker_info = marker.stat()
if marker_info.st_uid != 0 or stat.S_IMODE(marker_info.st_mode) != 0o600 or marker_info.st_nlink != 1:
    reject("candidate root marker must be root-owned, mode 0600, with one hard link")
if marker.read_bytes() != b"chengwang-m2b-candidate-root/v1\n":
    reject("candidate root marker content is invalid")
config_directory = explicit_absolute_directory(str(root_path / "config"), "candidate config directory")
config_info = config_directory.stat()
if config_info.st_uid != 0 or config_info.st_gid != 10001 or stat.S_IMODE(config_info.st_mode) != 0o750:
    reject("candidate config directory must be root:10001 with mode 0750")
expected_config_paths = (
    (env_path, config_directory / "probe.env"),
    (catalog_path, config_directory / "catalog.json"),
    (ca_path, config_directory / "dot-ca.pem"),
    (policy_path, config_directory / "egress-policy.json"),
)
for actual, expected in expected_config_paths:
    if actual != expected:
        reject(f"candidate configuration path must be exact: {expected}")
env_info = env_path.stat()
if env_info.st_uid != 0 or env_info.st_gid != 0 or stat.S_IMODE(env_info.st_mode) != 0o600 or env_info.st_nlink != 1:
    reject("probe env file must be root:root, mode 0600, with one hard link")

values = {}
allowed = {
    "M2B_PROBE_RELEASE_ID", "M2B_PROBE_PROJECT_NAME", "M2B_PROBE_CANDIDATE_ROOT",
    "M2B_PROBE_CATALOG_FILE", "M2B_PROBE_DOT_CA_FILE", "M2B_PROBE_EGRESS_POLICY_FILE",
    "M2B_PROBE_SPOOL_DIR", "M2B_PROBE_LEDGER_DIR", "M2B_PROBE_DOT_UPSTREAM",
    "M2B_PROBE_DOT_SERVER_NAME", "M2B_PROBE_CATALOG_SHA256", "M2B_PROBE_DOT_CA_SHA256",
    "M2B_PROBE_EGRESS_POLICY_SHA256", "M2B_PROBE_ACTIVE_APPROVAL",
}
for number, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), 1):
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        reject(f"env line {number} is not KEY=VALUE")
    key, value = line.split("=", 1)
    if key not in allowed:
        reject(f"env line {number} contains an unknown or unsafe key: {key}")
    if key in values:
        reject(f"env key is duplicated: {key}")
    if value != value.strip() or not value:
        reject(f"env value is empty or has surrounding whitespace: {key}")
    values[key] = value
if set(values) != allowed:
    reject("env file must contain every allowed key exactly once")

configured_paths = {
    "M2B_PROBE_CANDIDATE_ROOT": root_path,
    "M2B_PROBE_CATALOG_FILE": catalog_path,
    "M2B_PROBE_DOT_CA_FILE": ca_path,
    "M2B_PROBE_EGRESS_POLICY_FILE": policy_path,
}
for key, actual in configured_paths.items():
    configured = pathlib.Path(values[key])
    if not configured.is_absolute() or configured != actual:
        reject(f"{key} does not exactly match its explicit verified path")

spool = explicit_absolute_directory(values["M2B_PROBE_SPOOL_DIR"], "probe spool")
ledger = explicit_absolute_directory(values["M2B_PROBE_LEDGER_DIR"], "probe ledger")
if spool != root_path / "probe-spool" or ledger != root_path / "probe-ledger":
    reject("probe spool and ledger must use the dedicated candidate-root/probe-spool and probe-ledger paths")
for path, label in ((spool, "probe spool"), (ledger, "probe ledger")):
    reject_production(path, label)
    if not is_within(root_path, path) or path == root_path:
        reject(f"{label} must be a dedicated child of the candidate root")
    info = path.stat()
    if info.st_uid != 10001 or stat.S_IMODE(info.st_mode) != 0o700:
        reject(f"{label} must be owned by uid 10001 with mode 0700")
if is_within(spool, ledger) or is_within(ledger, spool):
    reject("probe spool and ledger must not overlap")
for config_path in (catalog_path, ca_path, policy_path):
    if is_within(spool, config_path) or is_within(ledger, config_path):
        reject("read-only configuration must stay outside writable spool and ledger")
    info = config_path.stat()
    if info.st_uid != 0 or info.st_gid != 10001 or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1:
        reject("mounted configuration must be root:10001, mode 0640, with one hard link")
if len({(os.stat(path).st_dev, os.stat(path).st_ino) for path in (catalog_path, ca_path, policy_path)}) != 3:
    reject("catalog, DoT CA, and egress policy must be distinct files")
root_device = root_path.stat().st_dev
if any(path.stat().st_dev != root_device for path in (spool, ledger, config_directory, env_path, catalog_path, ca_path, policy_path, marker)):
    reject("candidate state and configuration must remain on the candidate root filesystem")
root_mount = mount_signature(root_path, "candidate root")
for path, label in (
    (spool, "probe spool"), (ledger, "probe ledger"),
    (config_directory, "candidate config directory"), (env_path, "probe env"),
    (catalog_path, "catalog"), (ca_path, "DoT CA"),
    (policy_path, "egress policy"), (marker, "candidate marker"),
):
    if mount_signature(path, label) != root_mount:
        reject(f"{label} must not use an independent or bind mount")

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

for key, path in (
    ("M2B_PROBE_CATALOG_SHA256", catalog_path),
    ("M2B_PROBE_DOT_CA_SHA256", ca_path),
    ("M2B_PROBE_EGRESS_POLICY_SHA256", policy_path),
):
    expected = values[key]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        reject(f"{key} must be 64 lowercase hexadecimal characters")
    if sha256(path) != expected:
        reject(f"{key} does not match {path}")

def no_duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject(f"JSON contains a duplicate key: {key}")
        result[key] = value
    return result

try:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_object)
    policy = json.loads(policy_path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_object)
except (UnicodeError, json.JSONDecodeError) as error:
    reject(f"JSON parsing failed: {error}")
catalog_text = json.dumps(catalog, ensure_ascii=True).lower()
if any(token in catalog_text for token in ("probe.invalid", "placeholder", "replace-with")):
    reject("catalog contains a blocked host or contract placeholder")
if catalog.get("schema") != "chengwang.probe-catalog/v1" or not catalog.get("probes"):
    reject("catalog schema or probe set is invalid")
if catalog.get("agent", {}).get("advisoryOnly") is not True:
    reject("catalog must remain advisory-only")

if policy.get("schema") != "chengwang.probe-egress-policy/v1":
    reject("egress policy schema is invalid")
if policy.get("approval", {}).get("status") != "approved":
    reject("egress policy is not approved")
if policy.get("enforcement", {}).get("state") != "enforced":
    reject("egress policy is not enforced")
if policy.get("enforcement", {}).get("runtimeEvidence") in (None, "", "not-collected"):
    reject("egress policy has no runtime evidence reference")

if values["M2B_PROBE_ACTIVE_APPROVAL"] != "approved-candidate-only":
    reject("active candidate approval phrase is absent")
release_id = values["M2B_PROBE_RELEASE_ID"]
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", release_id) or any(token in release_id for token in ("replace", "placeholder", "local", "latest")):
    reject("release id is a placeholder or mutable label")

try:
    upstream_text, port_text = values["M2B_PROBE_DOT_UPSTREAM"].rsplit(":", 1)
    upstream = ipaddress.ip_address(upstream_text.strip("[]"))
    port = int(port_text)
except ValueError:
    reject("DoT upstream must be a fixed IP:port")
documentation_ranges = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
if (
    port != 853 or upstream.is_unspecified or upstream.is_loopback
    or upstream.is_link_local or upstream.is_multicast
    or any(upstream in network for network in documentation_ranges)
):
    reject("DoT upstream must be an approved unicast IP on TCP 853, not a placeholder or local-only address")
server_name = values["M2B_PROBE_DOT_SERVER_NAME"].lower()
if server_name.endswith(".invalid") or "placeholder" in server_name or "replace-with" in server_name:
    reject("DoT server name is a placeholder")

instance_base = match.group(1)
root_hash = hashlib.sha256(root_text.encode("utf-8")).hexdigest()[:12]
expected_project = f"chengwang-m2b-probe-{instance_base}-{root_hash}-candidate"
if values["M2B_PROBE_PROJECT_NAME"] != expected_project:
    reject("project name is not uniquely derived from the normalized candidate root")

compose_text = compose_path.read_text(encoding="utf-8")
required_fragments = (
    "profiles:\n      - active-probe-candidate", 'restart: "no"', 'user: "10001:10001"',
    "read_only: true", "privileged: false", "cap_drop:\n      - ALL",
    "no-new-privileges:true", "internal: true", "attachable: false",
    "Dockerfile.probe-agent", "--health-file", "/run/m2b-probe-health/health.json",
    '["CMD", "/app/probe-agent", "health"', "create_host_path: false",
)
for fragment in required_fragments:
    if fragment not in compose_text:
        reject(f"compose security contract is missing: {fragment!r}")
for forbidden in ("network_mode: host", "pid: host", "ipc: host", "/var/run/docker.sock", "ports:"):
    if forbidden in compose_text:
        reject(f"compose contains a forbidden setting: {forbidden}")

ca_text = ca_path.read_text(encoding="ascii")
if "-----BEGIN CERTIFICATE-----" not in ca_text or any(token in ca_text.lower() for token in ("placeholder", "replace-with")):
    reject("DoT CA bundle is missing or contains a placeholder")

print("OFFLINE_INPUT_CHECK=PASS")
print("STATIC_COMPOSE_CONTRACT=PASS")
print("COMPOSE_PARSE=NOT_RUN")
print("EGRESS_RUNTIME=NOT_PROVEN")
PY

trap - EXIT
blocked
