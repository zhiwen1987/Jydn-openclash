#!/bin/sh
# Validate and stage an active-probe backup. This version intentionally blocks
# before switching state because the current probe-agent exposes no offline
# spool+ledger semantic validation command.
set -eu
umask 077

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail "usage: $0 ABSOLUTE_PROBE_BACKUP_DIR"
[ "${M2B_CONFIRM_PROBE_RESTORE:-}" = RESTORE_DISPOSABLE_ACTIVE_PROBE ] || \
  fail "set M2B_CONFIRM_PROBE_RESTORE=RESTORE_DISPOSABLE_ACTIVE_PROBE"
BACKUP_REQUESTED=$1

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/candidate-root-lib.sh"
. "$SCRIPT_DIR/probe-lifecycle-lib.sh"

for probe_command in chmod chown cp docker findmnt flock grep head mktemp mkdir python3 realpath rm sha256sum stat tr wc; do
  probe_require "$probe_command"
done
probe_load_contract
probe_acquire_lifecycle_lock

[ -d "$PROBE_BACKUP_ROOT" ] && [ ! -L "$PROBE_BACKUP_ROOT" ] || fail "probe backup root is missing"
probe_assert_private_admin_directory "$PROBE_BACKUP_ROOT"

RESTORE_STAGE=$(mktemp -d "$CANDIDATE_ROOT/.probe-restore-check.XXXXXX")
chmod 700 "$RESTORE_STAGE"
cleanup() {
  case "${RESTORE_STAGE:-}" in "$CANDIDATE_ROOT"/.probe-restore-check.*) rm -rf -- "$RESTORE_STAGE" || true ;; esac
}
trap cleanup EXIT HUP INT TERM

probe_copy_validate_backup "$BACKUP_REQUESTED" "$RESTORE_STAGE/backup" -1 "" no

read_backup_field() {
  python3 - "$RESTORE_STAGE/backup/backup-meta.json" "$1" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
field = value.get(sys.argv[2])
if not isinstance(field, str) or not field:
    raise SystemExit("backup metadata string field is missing")
print(field)
PY
}
BACKUP_IMAGE_ID=$(read_backup_field imageId)
BACKUP_IMAGE_REFERENCE=$(read_backup_field imageReference)
CURRENT_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$BACKUP_IMAGE_REFERENCE")
[ "$CURRENT_IMAGE_ID" = "$BACKUP_IMAGE_ID" ] || fail "backup image differs from the current immutable local image"

CID_LIST=$(docker ps -aq \
  --filter "label=com.jydn.chengwang.component=$PROBE_COMPONENT" \
  --filter "label=com.docker.compose.project=$M2B_PROBE_PROJECT_NAME")
case "$CID_LIST" in
  '') CID= ;;
  *' '*) fail "multiple active probe component containers are forbidden" ;;
  *)
    [ "$(printf '%s\n' "$CID_LIST" | wc -l | tr -d ' ')" -eq 1 ] || fail "multiple active probe component containers are forbidden"
    CID=$CID_LIST
    ;;
esac
if [ -n "$CID" ]; then
  probe_assert_container_identity "$CID"
  probe_assert_container_mounts "$CID"
  [ "$(docker inspect --format '{{.Image}}' "$CID")" = "$BACKUP_IMAGE_ID" ] || fail "container image differs from the backup image"
  docker stop -t 20 "$CID" >/dev/null
  [ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || fail "probe-agent did not stop"
  probe_assert_unique_container_and_mounts "$CID"
else
  probe_assert_unique_container_and_mounts ""
fi
probe_assert_no_uid10001_writers

python3 - "$RESTORE_STAGE/backup" "$CANDIDATE_ROOT" "$M2B_PROBE_PROJECT_NAME" <<'PY'
import hashlib, ipaddress, json, pathlib, re, sys
backup, root, project = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
allowed = {
    "M2B_PROBE_RELEASE_ID", "M2B_PROBE_PROJECT_NAME", "M2B_PROBE_CANDIDATE_ROOT",
    "M2B_PROBE_CATALOG_FILE", "M2B_PROBE_DOT_CA_FILE", "M2B_PROBE_EGRESS_POLICY_FILE",
    "M2B_PROBE_SPOOL_DIR", "M2B_PROBE_LEDGER_DIR", "M2B_PROBE_DOT_UPSTREAM",
    "M2B_PROBE_DOT_SERVER_NAME", "M2B_PROBE_CATALOG_SHA256", "M2B_PROBE_DOT_CA_SHA256",
    "M2B_PROBE_EGRESS_POLICY_SHA256", "M2B_PROBE_ACTIVE_APPROVAL",
}
values = {}
for number, raw in enumerate((backup / "probe.env").read_text(encoding="utf-8").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit(f"backup env line {number} is invalid")
    key, value = line.split("=", 1)
    if key not in allowed or key in values or not value or value != value.strip():
        raise SystemExit(f"backup env key is invalid or duplicated: {key}")
    values[key] = value
if set(values) != allowed:
    raise SystemExit("backup env field set is invalid")
expected_paths = {
    "M2B_PROBE_CANDIDATE_ROOT": root,
    "M2B_PROBE_CATALOG_FILE": root / "config/catalog.json",
    "M2B_PROBE_DOT_CA_FILE": root / "config/dot-ca.pem",
    "M2B_PROBE_EGRESS_POLICY_FILE": root / "config/egress-policy.json",
    "M2B_PROBE_SPOOL_DIR": root / "probe-state/probe-spool",
    "M2B_PROBE_LEDGER_DIR": root / "probe-state/probe-ledger",
}
for key, expected in expected_paths.items():
    if pathlib.Path(values[key]) != expected:
        raise SystemExit(f"backup env path mismatch: {key}")
if values["M2B_PROBE_PROJECT_NAME"] != project or values["M2B_PROBE_ACTIVE_APPROVAL"] != "approved-candidate-only":
    raise SystemExit("backup env project or approval mismatch")
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", values["M2B_PROBE_RELEASE_ID"]):
    raise SystemExit("backup release id is invalid")
for key, name in (
    ("M2B_PROBE_CATALOG_SHA256", "catalog.json"),
    ("M2B_PROBE_DOT_CA_SHA256", "dot-ca.pem"),
    ("M2B_PROBE_EGRESS_POLICY_SHA256", "egress-policy.json"),
):
    if values[key] != hashlib.sha256((backup / name).read_bytes()).hexdigest():
        raise SystemExit(f"backup env digest mismatch: {key}")
def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate backup JSON key: {key}")
        result[key] = value
    return result
catalog = json.loads((backup / "catalog.json").read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
policy = json.loads((backup / "egress-policy.json").read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
if catalog.get("schema") != "chengwang.probe-catalog/v1" or not catalog.get("probes") or catalog.get("agent", {}).get("advisoryOnly") is not True:
    raise SystemExit("backup catalog contract is invalid")
if policy.get("schema") != "chengwang.probe-egress-policy/v1" or policy.get("approval", {}).get("status") != "approved" or policy.get("enforcement", {}).get("state") != "enforced":
    raise SystemExit("backup egress policy contract is invalid")
ca = (backup / "dot-ca.pem").read_text(encoding="ascii")
if "-----BEGIN CERTIFICATE-----" not in ca:
    raise SystemExit("backup DoT CA bundle is invalid")
PY

REPLACEMENT=$RESTORE_STAGE/replacement
mkdir -m 700 -- "$REPLACEMENT"
python3 - "$RESTORE_STAGE/backup/probe-state.tar.gz" "$REPLACEMENT/probe-state" "$PROBE_ARCHIVE_MAX_ENTRIES" "$PROBE_ARCHIVE_MAX_BYTES" <<'PY'
import os, pathlib, shutil, stat, sys, tarfile
archive, destination = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
maximum_entries, maximum_bytes = map(int, sys.argv[3:])
destination.mkdir(mode=0o700)
os.chown(destination, 10001, 10001)
count = 0
total = 0
with tarfile.open(archive, "r|gz") as source:
    for member in source:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()):
            raise SystemExit("unsafe probe state archive member")
        if not path.parts or path.parts[0] not in {"probe-spool", "probe-ledger"}:
            raise SystemExit("unexpected probe state archive root")
        count += 1
        if count > maximum_entries + 2:
            raise SystemExit("probe state archive entry limit exceeded")
        target = destination.joinpath(*path.parts)
        if member.isdir():
            target.mkdir(mode=0o700, parents=False, exist_ok=False)
            os.chown(target, 10001, 10001)
            continue
        total += member.size
        if total > maximum_bytes:
            raise SystemExit("probe state archive byte limit exceeded")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                extracted = source.extractfile(member)
                if extracted is None:
                    raise SystemExit("probe state archive member has no payload")
                shutil.copyfileobj(extracted, output, length=65536)
                output.flush()
                os.fsync(output.fileno())
            os.chown(target, 10001, 10001)
            if target.stat().st_size != member.size:
                raise SystemExit("probe state archive member was truncated during extraction")
        finally:
            os.close(descriptor)
for required in (destination / "probe-spool", destination / "probe-ledger"):
    if not required.is_dir():
        raise SystemExit("probe state archive is missing a required directory")
PY

mkdir -m 750 -- "$REPLACEMENT/config"
chown 0:10001 "$REPLACEMENT/config"
cp -- "$RESTORE_STAGE/backup/probe.env" "$REPLACEMENT/config/probe.env"
cp -- "$RESTORE_STAGE/backup/catalog.json" "$REPLACEMENT/config/catalog.json"
cp -- "$RESTORE_STAGE/backup/dot-ca.pem" "$REPLACEMENT/config/dot-ca.pem"
cp -- "$RESTORE_STAGE/backup/egress-policy.json" "$REPLACEMENT/config/egress-policy.json"
chown 0:0 "$REPLACEMENT/config/probe.env"
chmod 600 "$REPLACEMENT/config/probe.env"
chown 0:10001 "$REPLACEMENT/config/catalog.json" "$REPLACEMENT/config/dot-ca.pem" "$REPLACEMENT/config/egress-policy.json"
chmod 640 "$REPLACEMENT/config/catalog.json" "$REPLACEMENT/config/dot-ca.pem" "$REPLACEMENT/config/egress-policy.json"

printf '%s\n' "PROBE_RESTORE_ARCHIVE_AND_CONFIG=PASS"
printf '%s\n' "PROBE_CONTAINER_STATE=STOPPED"
printf '%s\n' "PROBE_RESTORE=BLOCKED_NO_OFFLINE_GO_SPOOL_LEDGER_VALIDATOR"
exit 78
