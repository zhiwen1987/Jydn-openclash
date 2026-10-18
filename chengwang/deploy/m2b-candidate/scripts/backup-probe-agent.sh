#!/bin/sh
# Stop (if present) and create a bounded, self-describing backup of the active
# probe candidate. The candidate is always left stopped.
set -eu
umask 077

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 0 ] || fail "usage: $0"

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/candidate-root-lib.sh"
. "$SCRIPT_DIR/probe-lifecycle-lib.sh"

for probe_command in awk chmod cp date docker findmnt grep head mkdir mktemp mv python3 realpath rm sha256sum stat sync tr wc; do
  probe_require "$probe_command"
done
probe_load_contract
probe_acquire_lifecycle_lock
probe_offline_verify

[ -d "$PROBE_BACKUP_ROOT" ] && [ ! -L "$PROBE_BACKUP_ROOT" ] || \
  fail "probe backup root must already exist: $PROBE_BACKUP_ROOT"
probe_assert_private_admin_directory "$PROBE_BACKUP_ROOT"

CONFIG_JSON=$(mktemp "$CANDIDATE_ROOT/.probe-compose-backup.XXXXXX")
chmod 600 "$CONFIG_JSON"
cleanup_config() { rm -f -- "$CONFIG_JSON" || true; }
trap cleanup_config EXIT HUP INT TERM
probe_render_compose_json "$CONFIG_JSON"
probe_verify_compose_json "$CONFIG_JSON"

IMAGE_REFERENCE=$(probe_image_reference)
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_REFERENCE")
printf '%s\n' "$IMAGE_ID" | grep -Eq '^sha256:[0-9a-f]{64}$' || fail "probe image has no immutable image id"

CID=$(probe_compose ps -aq "$PROBE_SERVICE")
PROJECT_CONTAINERS=$(docker ps -aq --filter "label=com.docker.compose.project=$M2B_PROBE_PROJECT_NAME")
if [ -n "$CID" ]; then
  [ "$(printf '%s\n' "$CID" | wc -l | tr -d ' ')" -eq 1 ] || fail "multiple probe-agent containers are forbidden"
  [ "$PROJECT_CONTAINERS" = "$CID" ] || fail "unexpected container exists in the probe candidate project"
  probe_assert_container_identity "$CID"
  probe_assert_container_mounts "$CID"
  probe_assert_unique_container_and_mounts "$CID"
  [ "$(docker inspect --format '{{.Image}}' "$CID")" = "$IMAGE_ID" ] || fail "container image differs from the immutable release image"
  probe_compose stop -t 20 "$PROBE_SERVICE"
  [ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || fail "probe-agent did not stop"
else
  [ -z "$PROJECT_CONTAINERS" ] || fail "project contains an unrecognized container"
  probe_assert_unique_container_and_mounts ""
fi
probe_assert_no_uid10001_writers

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FINAL_DESTINATION=$PROBE_BACKUP_ROOT/$STAMP-$$
DESTINATION=$PROBE_BACKUP_ROOT/.pending-$STAMP-$$
[ ! -e "$FINAL_DESTINATION" ] && [ ! -e "$DESTINATION" ] || fail "probe backup destination already exists"
mkdir -m 700 -- "$DESTINATION"
cleanup_pending() {
  case "${DESTINATION:-}" in "$PROBE_BACKUP_ROOT"/.pending-*) rm -rf -- "$DESTINATION" || true ;; esac
  cleanup_config
}
trap cleanup_pending EXIT HUP INT TERM

probe_validate_state_snapshot \
  "$IMAGE_ID" \
  "$PROBE_CATALOG_FILE" \
  "$PROBE_SPOOL_DIR" \
  "$PROBE_LEDGER_DIR" \
  "$DESTINATION/state-validation.json"

python3 - "$PROBE_SPOOL_DIR" "$PROBE_LEDGER_DIR" "$DESTINATION/probe-state.tar.gz" "$PROBE_ARCHIVE_MAX_ENTRIES" "$PROBE_ARCHIVE_MAX_BYTES" <<'PY'
import os, pathlib, stat, sys, tarfile
spool, ledger, archive = map(pathlib.Path, sys.argv[1:4])
maximum_entries, maximum_bytes = map(int, sys.argv[4:])
roots = ((spool, "probe-spool"), (ledger, "probe-ledger"))
entries = 0
total = 0
members = []
for root, archive_root in roots:
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 10001 or stat.S_IMODE(info.st_mode) != 0o700:
        raise SystemExit(f"unsafe probe state root: {root}")
    members.append((root, archive_root))
    for base, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories + files:
            path = pathlib.Path(base, name)
            info = path.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise SystemExit(f"unsafe probe state entry: {path}")
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise SystemExit(f"hard-linked probe state file is forbidden: {path}")
            entries += 1
            if entries > maximum_entries:
                raise SystemExit("probe state entry limit exceeded")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > maximum_bytes:
                    raise SystemExit("probe state byte limit exceeded")
            relative = path.relative_to(root).as_posix()
            members.append((path, f"{archive_root}/{relative}"))
with tarfile.open(archive, "w:gz", compresslevel=6) as target:
    for path, name in members:
        before = path.lstat()
        if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
            raise SystemExit(f"probe state changed type during backup: {path}")
        target.add(path, arcname=name, recursive=False)
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size) != (after.st_dev, after.st_ino, after.st_mode, after.st_size):
            raise SystemExit(f"probe state changed during backup: {path}")
PY
[ "$(stat -c %s "$DESTINATION/probe-state.tar.gz")" -le "$PROBE_ARCHIVE_MAX_BYTES" ] || fail "compressed probe state archive exceeds its limit"

# Snapshot the configuration before revalidating the archived state.  In
# particular, the validator must consume the catalog that will be published in
# this backup, not a live path that could change between validation and copy.
cp -- "$PROBE_ENV_FILE" "$DESTINATION/probe.env"
cp -- "$PROBE_CATALOG_FILE" "$DESTINATION/catalog.json"
cp -- "$PROBE_DOT_CA_FILE" "$DESTINATION/dot-ca.pem"
cp -- "$PROBE_EGRESS_POLICY_FILE" "$DESTINATION/egress-policy.json"

# Re-extract and validate the actual archive before publication.  Exact report
# equality closes the gap between live validation and a concurrently changing
# tar input; any mismatch leaves only the private pending directory, which the
# EXIT trap removes.
probe_extract_state_archive \
  "$DESTINATION/probe-state.tar.gz" \
  "$DESTINATION/.archive-state"
probe_validate_state_snapshot \
  "$IMAGE_ID" \
  "$DESTINATION/catalog.json" \
  "$DESTINATION/.archive-state/probe-spool" \
  "$DESTINATION/.archive-state/probe-ledger" \
  "$DESTINATION/.archive-state-validation.json"
RELATIONSHIP_COMPLETE=$(probe_compare_state_validation_reports \
  "$DESTINATION/state-validation.json" \
  "$DESTINATION/.archive-state-validation.json")
rm -rf -- "$DESTINATION/.archive-state"
rm -f -- "$DESTINATION/.archive-state-validation.json"

docker image inspect "$IMAGE_ID" >"$DESTINATION/image-inspect.json"
COMPOSE_SHA256=$(sha256sum "$PROBE_COMPOSE_FILE" | awk '{print $1}')
CREATED_UNIX=$(date -u +%s)
python3 - "$DESTINATION/backup-meta.json" "$DESTINATION/state-validation.json" "$PROBE_BACKUP_SCHEMA" "$CREATED_UNIX" "$CANDIDATE_ROOT" "$M2B_PROBE_PROJECT_NAME" "$IMAGE_ID" "$IMAGE_REFERENCE" "$COMPOSE_SHA256" "${CID:+yes}" <<'PY'
import json, os, sys
path, validation_path, schema, created, root, project, image_id, image_reference, compose_sha, active_present = sys.argv[1:]
with open(validation_path, encoding="utf-8") as stream:
    validation = json.load(stream)
relationship_complete = validation.get("relationshipComplete")
if not isinstance(relationship_complete, bool):
    raise SystemExit("state validation relationship completeness is missing")
value = {
    "schema": schema,
    "createdUnix": int(created),
    "candidateRoot": root,
    "projectName": project,
    "imageId": image_id,
    "imageReference": image_reference,
    "composeSha256": compose_sha,
    "activeContainerPresent": active_present == "yes",
    "relationshipComplete": relationship_complete,
}
with open(path, "x", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
PY

chmod 600 "$DESTINATION"/*
(
  cd "$DESTINATION"
  sha256sum backup-meta.json catalog.json dot-ca.pem egress-policy.json image-inspect.json probe-state.tar.gz probe.env state-validation.json >SHA256SUMS
)
chmod 600 "$DESTINATION/SHA256SUMS"
sync "$DESTINATION"
mv -- "$DESTINATION" "$FINAL_DESTINATION"
sync "$PROBE_BACKUP_ROOT"
DESTINATION=
trap - EXIT HUP INT TERM
cleanup_config
printf '%s\n' "PROBE_STATE_SEMANTIC_VALIDATION=PASS"
printf '%s\n' "PROBE_STATE_ARCHIVE_REVALIDATION=PASS"
printf '%s\n' "PROBE_STATE_RELATIONSHIP_COMPLETE=$RELATIONSHIP_COMPLETE"
if [ "$RELATIONSHIP_COMPLETE" = true ]; then
  printf '%s\n' "PROBE_BACKUP=PASS"
  printf '%s\n' "PROBE_BACKUP_QUALITY=COMPLETE"
else
  printf '%s\n' "PROBE_BACKUP=PASS_DEGRADED"
  printf '%s\n' "PROBE_BACKUP_QUALITY=DEGRADED_RELATIONSHIP_INCOMPLETE"
fi
printf '%s\n' "PROBE_CONTAINER_STATE=STOPPED"
printf '%s\n' "PROBE_BACKUP_PATH=$FINAL_DESTINATION"
