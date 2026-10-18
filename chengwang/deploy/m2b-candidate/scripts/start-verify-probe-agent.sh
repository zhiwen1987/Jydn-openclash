#!/bin/sh
# Fail-closed pre-start wrapper. It deliberately does not call `compose up`
# while the only declared network is the internal quarantine network.
set -eu
umask 077

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 3 ] || fail "usage: $0 ABSOLUTE_FRESH_BACKUP_DIR ABSOLUTE_EGRESS_EVIDENCE_FILE EXPECTED_EVIDENCE_SHA256"

BACKUP_REQUESTED=$1
EVIDENCE_REQUESTED=$2
EXPECTED_EVIDENCE_SHA256=$3
case "$EXPECTED_EVIDENCE_SHA256" in
  *[!0-9a-f]*|'') fail "expected egress evidence SHA-256 must be lowercase hexadecimal" ;;
esac
[ "${#EXPECTED_EVIDENCE_SHA256}" -eq 64 ] || fail "expected egress evidence SHA-256 must contain 64 characters"

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/candidate-root-lib.sh"
. "$SCRIPT_DIR/probe-lifecycle-lib.sh"

for probe_command in awk cp docker findmnt grep head mktemp mkdir python3 realpath rm sha256sum stat; do
  probe_require "$probe_command"
done
probe_load_contract
probe_acquire_lifecycle_lock
probe_offline_verify

[ -d "$PROBE_BACKUP_ROOT" ] && [ ! -L "$PROBE_BACKUP_ROOT" ] || fail "probe backup root is missing"
[ -d "$PROBE_EVIDENCE_DIR" ] && [ ! -L "$PROBE_EVIDENCE_DIR" ] || fail "probe evidence directory is missing"
probe_assert_private_admin_directory "$PROBE_BACKUP_ROOT"
probe_assert_private_admin_directory "$PROBE_EVIDENCE_DIR"

case "$EVIDENCE_REQUESTED" in /*) ;; *) fail "egress evidence path must be absolute" ;; esac
[ -f "$EVIDENCE_REQUESTED" ] && [ ! -L "$EVIDENCE_REQUESTED" ] || fail "egress evidence must be a regular non-symlink file"
candidate_assert_no_symlink_components "$EVIDENCE_REQUESTED"
EVIDENCE_FILE=$(realpath "$EVIDENCE_REQUESTED")
[ "$EVIDENCE_FILE" = "$PROBE_EVIDENCE_DIR/egress.json" ] || fail "egress evidence must use the dedicated candidate-root/evidence/egress.json path"
candidate_assert_admin_file "$EVIDENCE_FILE"
candidate_assert_same_mount "$CANDIDATE_ROOT" "$EVIDENCE_FILE"
[ "$(sha256sum "$EVIDENCE_FILE" | awk '{print $1}')" = "$EXPECTED_EVIDENCE_SHA256" ] || fail "egress evidence SHA-256 mismatch"

CHECK_STAGE=$(mktemp -d "$CANDIDATE_ROOT/.probe-start-check.XXXXXX")
chmod 700 "$CHECK_STAGE"
cleanup() {
  case "${CHECK_STAGE:-}" in "$CANDIDATE_ROOT"/.probe-start-check.*) rm -rf -- "$CHECK_STAGE" || true ;; esac
}
trap cleanup EXIT HUP INT TERM

CONFIG_JSON=$CHECK_STAGE/compose.json
probe_render_compose_json "$CONFIG_JSON"
probe_verify_compose_json "$CONFIG_JSON"

IMAGE_REFERENCE=$(probe_image_reference)
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_REFERENCE")
printf '%s\n' "$IMAGE_ID" | grep -Eq '^sha256:[0-9a-f]{64}$' || fail "probe image has no immutable image id"

probe_copy_validate_backup "$BACKUP_REQUESTED" "$CHECK_STAGE/backup" "$PROBE_BACKUP_MAX_AGE_SECONDS" "$IMAGE_ID" yes

CID=$(probe_compose ps -aq "$PROBE_SERVICE")
PROJECT_CONTAINERS=$(docker ps -aq --filter "label=com.docker.compose.project=$M2B_PROBE_PROJECT_NAME")
if [ -n "$CID" ]; then
  [ "$PROJECT_CONTAINERS" = "$CID" ] || fail "unexpected container exists in the probe candidate project"
  probe_assert_container_identity "$CID"
  probe_assert_container_mounts "$CID"
  probe_assert_unique_container_and_mounts "$CID"
  [ "$(docker inspect --format '{{.Image}}' "$CID")" = "$IMAGE_ID" ] || fail "stopped candidate uses a different image"
  [ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || fail "probe-agent must be stopped before the pre-start gate"
else
  [ -z "$PROJECT_CONTAINERS" ] || fail "project contains an unrecognized container"
  probe_assert_unique_container_and_mounts ""
  printf '%s\n' "ACTIVE_START=BLOCKED_NO_EXISTING_CONTAINER_NETWORK_IDENTITY"
  exit 78
fi
probe_assert_no_uid10001_writers

cp -- "$EVIDENCE_FILE" "$CHECK_STAGE/egress.json"
chmod 600 "$CHECK_STAGE/egress.json"
[ "$(sha256sum "$CHECK_STAGE/egress.json" | awk '{print $1}')" = "$EXPECTED_EVIDENCE_SHA256" ] || fail "staged egress evidence SHA-256 mismatch"
POLICY_SHA256=$(sha256sum "$PROBE_EGRESS_POLICY_FILE" | awk '{print $1}')
CATALOG_SHA256=$(sha256sum "$PROBE_CATALOG_FILE" | awk '{print $1}')
COMPOSE_SHA256=$(sha256sum "$PROBE_COMPOSE_FILE" | awk '{print $1}')
python3 - "$CHECK_STAGE/egress.json" "$PROBE_EGRESS_POLICY_FILE" "$PROBE_EGRESS_EVIDENCE_SCHEMA" "$CANDIDATE_ROOT" "$M2B_PROBE_PROJECT_NAME" "$IMAGE_ID" "$POLICY_SHA256" "$CATALOG_SHA256" "$COMPOSE_SHA256" "$CID" <<'PY'
import json, pathlib, re, subprocess, sys, time
path, policy_path, schema, root, project, image_id, policy_sha, catalog_sha, compose_sha, cid = sys.argv[1:]
def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate egress evidence key: {key}")
        result[key] = value
    return result
with open(path, encoding="utf-8") as stream:
    value = json.load(stream, object_pairs_hook=no_duplicates)
with open(policy_path, encoding="utf-8") as stream:
    policy = json.load(stream, object_pairs_hook=no_duplicates)
required = {
    "schema", "evidenceId", "capturedUnix", "expiresUnix", "candidateRoot", "projectName",
    "imageId", "composeSha256", "catalogSha256", "policySha256", "containerId",
    "networkName", "networkId", "rulesetSha256", "bootId", "collector",
    "firewallScope", "counters",
}
if not isinstance(value, dict) or set(value) != required:
    raise SystemExit("egress evidence field set is invalid")
if not isinstance(value["evidenceId"], str) or not re.fullmatch(r"evidence:[a-z0-9][a-z0-9._-]{0,127}", value["evidenceId"]):
    raise SystemExit("egress evidence id is invalid")
if policy.get("enforcement", {}).get("runtimeEvidence") != value["evidenceId"]:
    raise SystemExit("egress policy and evidence artifact id are not mutually bound")
if value["schema"] != schema or value["candidateRoot"] != root or value["projectName"] != project:
    raise SystemExit("egress evidence candidate identity mismatch")
if value["imageId"] != image_id or value["policySha256"] != policy_sha or value["catalogSha256"] != catalog_sha or value["composeSha256"] != compose_sha:
    raise SystemExit("egress evidence artifact identity mismatch")
if value["containerId"] != cid or value["collector"] != "host-firewall-counter-capture/v1":
    raise SystemExit("egress evidence collector or container identity mismatch")
if value["firewallScope"] != "probe-container-default-deny":
    raise SystemExit("egress evidence firewall scope is invalid")
boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
if value["bootId"] != boot_id:
    raise SystemExit("egress evidence belongs to another host boot")
if not isinstance(value["rulesetSha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["rulesetSha256"]):
    raise SystemExit("egress evidence ruleset digest is invalid")
container_raw = subprocess.run(["docker", "inspect", cid], check=True, capture_output=True, text=True, timeout=15)
container = json.loads(container_raw.stdout)
if not isinstance(container, list) or len(container) != 1:
    raise SystemExit("container inspect result is ambiguous")
networks = container[0].get("NetworkSettings", {}).get("Networks")
if not isinstance(networks, dict) or len(networks) != 1:
    raise SystemExit("probe container must have exactly one network")
network_name, attachment = next(iter(networks.items()))
network_id = attachment.get("NetworkID") if isinstance(attachment, dict) else None
if value["networkName"] != network_name or value["networkId"] != network_id:
    raise SystemExit("egress evidence network identity mismatch")
network_raw = subprocess.run(["docker", "network", "inspect", network_id], check=True, capture_output=True, text=True, timeout=15)
network = json.loads(network_raw.stdout)
if not isinstance(network, list) or len(network) != 1 or network[0].get("Internal") is not True or network[0].get("Attachable") is not False:
    raise SystemExit("probe quarantine network runtime contract mismatch")
if cid not in (network[0].get("Containers") or {}):
    raise SystemExit("probe container is absent from its inspected network")
captured = value["capturedUnix"]
expires = value["expiresUnix"]
if not all(isinstance(item, int) and not isinstance(item, bool) for item in (captured, expires)):
    raise SystemExit("egress evidence timestamps must be integers")
now = int(time.time())
if captured > now + 5 or expires <= now or expires - captured > 600 or now - captured > 300:
    raise SystemExit("egress evidence is stale, future-dated, or has an excessive lifetime")
counters = value["counters"]
names = {
    "resolverAllowedBefore", "resolverAllowedAfter", "canaryAllowedBefore",
    "canaryAllowedAfter", "deniedBefore", "deniedAfter",
}
if not isinstance(counters, dict) or set(counters) != names:
    raise SystemExit("egress evidence counter set is invalid")
if any(not isinstance(counters[name], int) or isinstance(counters[name], bool) or counters[name] < 0 for name in names):
    raise SystemExit("egress evidence counters must be non-negative integers")
for prefix in ("resolverAllowed", "canaryAllowed", "denied"):
    if counters[prefix + "After"] <= counters[prefix + "Before"]:
        raise SystemExit(f"egress evidence counter did not increase: {prefix}")
PY

printf '%s\n' "OFFLINE_INPUT_CHECK=PASS"
printf '%s\n' "COMPOSE_STRUCTURE_READBACK=PASS"
printf '%s\n' "FRESH_BACKUP_GATE=PASS"
printf '%s\n' "EGRESS_EVIDENCE_ARTIFACT_FORMAT_AND_BINDING=PASS"
printf '%s\n' "EGRESS_RUNTIME=NOT_PROVEN_BY_THIS_HOST"
printf '%s\n' "ACTIVE_START=BLOCKED_INTERNAL_QUARANTINE_HAS_NO_APPROVED_EGRESS_DATA_PLANE"
exit 78
