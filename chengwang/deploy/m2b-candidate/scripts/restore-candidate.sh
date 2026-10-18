#!/bin/sh
# Restore only a bounded disposable candidate spool. The previous spool is
# retained and automatically put back if the final directory switch fails.
set -eu
umask 077

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"; }

[ "$#" -eq 2 ] || fail "usage: $0 ABSOLUTE_BACKUP_DIR ABSOLUTE_CANDIDATE_SPOOL_DIR"
[ "${M2B_CONFIRM_RESTORE:-}" = RESTORE_DISPOSABLE_CANDIDATE ] || fail "set M2B_CONFIRM_RESTORE=RESTORE_DISPOSABLE_CANDIDATE"
for command_name in docker findmnt head python3 realpath sha256sum stat; do require "$command_name"; done

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/candidate-root-lib.sh"
candidate_load_existing_root

BACKUP_DIR=$(realpath "$1")
[ -d "$BACKUP_DIR" ] && [ ! -L "$1" ] || fail "backup must be a real directory"
SPOOL_PARENT=$(realpath "$(dirname -- "$2")")
SPOOL_DIR=$SPOOL_PARENT/$(basename -- "$2")
case "$BACKUP_DIR:$SPOOL_DIR" in "$CANDIDATE_ROOT"/*:"$CANDIDATE_ROOT"/*) ;; *) fail "backup and spool must stay under candidate root" ;; esac
[ "$SPOOL_DIR" != "$CANDIDATE_ROOT" ] || fail "candidate root itself cannot be replaced"
[ "$SPOOL_DIR" = "$CANDIDATE_ROOT/spool" ] || fail "restore target must be the dedicated root/spool directory"
case "$BACKUP_DIR" in "$CANDIDATE_ROOT/backups"/*) ;; *) fail "backup must be below the dedicated root/backups directory" ;; esac
case "$BACKUP_DIR" in "$SPOOL_DIR"|"$SPOOL_DIR"/*) fail "backup cannot be inside the spool" ;; esac
case "$SPOOL_DIR" in "$BACKUP_DIR"|"$BACKUP_DIR"/*) fail "spool cannot be inside the selected backup" ;; esac
candidate_assert_no_symlink_components "$BACKUP_DIR"
candidate_assert_no_symlink_components "$SPOOL_PARENT"
candidate_assert_admin_directory "$CANDIDATE_ROOT/backups"
candidate_assert_admin_directory "$BACKUP_DIR"
if [ -e "$SPOOL_DIR" ]; then candidate_assert_no_symlink_components "$SPOOL_DIR"; fi
candidate_assert_same_mount "$CANDIDATE_ROOT" "$CANDIDATE_ROOT/backups"
candidate_assert_same_mount "$CANDIDATE_ROOT" "$BACKUP_DIR"
if [ -e "$SPOOL_DIR" ]; then
  candidate_assert_same_mount "$CANDIDATE_ROOT" "$SPOOL_DIR"
else
  candidate_assert_same_mount "$CANDIDATE_ROOT" "$SPOOL_PARENT"
fi
[ -f "$BACKUP_DIR/SHA256SUMS" ] && [ ! -L "$BACKUP_DIR/SHA256SUMS" ] || fail "backup checksum is missing"
[ -f "$BACKUP_DIR/spool.tar.gz" ] && [ ! -L "$BACKUP_DIR/spool.tar.gz" ] || fail "backup archive is missing"
[ -f "$BACKUP_DIR/catalog.json" ] && [ ! -L "$BACKUP_DIR/catalog.json" ] || fail "backup catalog is missing"
[ -f "$BACKUP_DIR/image-inspect.json" ] && [ ! -L "$BACKUP_DIR/image-inspect.json" ] || fail "backup image evidence is missing"
for backup_file in SHA256SUMS spool.tar.gz catalog.json image-inspect.json; do
  candidate_assert_admin_file "$BACKUP_DIR/$backup_file"
done
[ "$(stat -c %s "$BACKUP_DIR/spool.tar.gz")" -le 134217728 ] || fail "compressed spool archive exceeds 128 MiB"

compose() { docker compose --project-name "$M2B_PROJECT_NAME" --project-directory "$ROOT_DIR" -f "$ROOT_DIR/compose.yaml" "$@"; }
CID=$(compose ps -aq candidate-guard)
[ -n "$CID" ] || fail "candidate container must exist so mount source can be verified"
[ "$(docker inspect --format '{{index .Config.Labels "com.jydn.chengwang.component"}}' "$CID")" = m2b-candidate-guard ] || fail "container identity mismatch"
MOUNTED_SPOOL=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/chengwang-probe"}}{{.Source}}{{end}}{{end}}' "$CID")
[ -n "$MOUNTED_SPOOL" ] || fail "candidate spool mount source is missing"
MOUNTED_SPOOL=$(realpath "$MOUNTED_SPOOL")
if [ -e "$SPOOL_DIR" ]; then TARGET_CANONICAL=$(realpath "$SPOOL_DIR"); else TARGET_CANONICAL=$SPOOL_DIR; fi
[ "$MOUNTED_SPOOL" = "$TARGET_CANONICAL" ] || fail "restore target is not the candidate mount source"
candidate_assert_same_mount "$CANDIDATE_ROOT" "$MOUNTED_SPOOL"

MOUNTED_CATALOG=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/run/chengwang-probe/catalog.json"}}{{.Source}}{{end}}{{end}}' "$CID")
[ -n "$MOUNTED_CATALOG" ] || fail "candidate catalog mount source is missing"
MOUNTED_CATALOG=$(realpath "$MOUNTED_CATALOG")

STAGE=$(mktemp -d "$SPOOL_PARENT/.m2b-restore-stage.XXXXXX")
cleanup() { [ -z "${STAGE:-}" ] || rm -rf -- "$STAGE" || printf '%s\n' "WARNING: temporary restore cleanup requires attention: $STAGE" >&2; }
trap cleanup EXIT HUP INT TERM
cp -- "$BACKUP_DIR/spool.tar.gz" "$BACKUP_DIR/catalog.json" "$BACKUP_DIR/image-inspect.json" "$BACKUP_DIR/SHA256SUMS" "$STAGE/"
python3 - "$STAGE" <<'PY'
import hashlib, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
expected_names = {"catalog.json", "image-inspect.json", "spool.tar.gz"}
lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
entries = {}
for line in lines:
    match = re.fullmatch(r"([0-9a-f]{64})  (catalog\.json|image-inspect\.json|spool\.tar\.gz)", line)
    if not match or match.group(2) in entries:
        raise SystemExit("backup checksum manifest is invalid")
    entries[match.group(2)] = match.group(1)
if set(entries) != expected_names:
    raise SystemExit("backup checksum manifest must contain exactly three required files")
for name, expected in entries.items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"backup checksum mismatch: {name}")
PY
[ "$(sha256sum "$STAGE/catalog.json" | awk '{print $1}')" = "$(sha256sum "$MOUNTED_CATALOG" | awk '{print $1}')" ] || fail "backup catalog differs from the mounted candidate catalog"
BACKUP_IMAGE_ID=$(python3 - "$STAGE/image-inspect.json" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
    raise SystemExit("backup image evidence schema is invalid")
image_id = value[0].get("Id")
if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    raise SystemExit("backup image id is invalid")
print(image_id)
PY
)
[ "$BACKUP_IMAGE_ID" = "$(docker inspect --format '{{.Image}}' "$CID")" ] || fail "backup image id differs from the candidate container image"
RESTORE_DIR=$STAGE/payload
mkdir -m 700 "$RESTORE_DIR"
python3 - "$STAGE/spool.tar.gz" "$RESTORE_DIR" <<'PY'
import pathlib, shutil, sys, tarfile
archive, destination = sys.argv[1], pathlib.Path(sys.argv[2])
count = 0
total = 0
with tarfile.open(archive, "r|gz") as source:
    for member in source:
        if member.name in (".", "./"):
            if not member.isdir():
                raise SystemExit("archive root entry is unsafe")
            continue
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or not (member.isfile() or member.isdir()):
            raise SystemExit("archive contains unsafe entry")
        count += 1
        if count > 4096:
            raise SystemExit("archive entry limit exceeded")
        if member.isfile():
            total += member.size
            if total > 128 * 1024 * 1024:
                raise SystemExit("archive byte limit exceeded")
with tarfile.open(archive, "r:gz") as source:
    for member in source:
        if member.name in (".", "./"):
            continue
        target = destination.joinpath(*pathlib.PurePosixPath(member.name).parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            stream = source.extractfile(member)
            if stream is None:
                raise SystemExit("archive file payload is missing")
            with target.open("xb") as output:
                shutil.copyfileobj(stream, output, 1024 * 1024)
            target.chmod(0o600)
PY
if find "$RESTORE_DIR" -type l -o \( ! -type f ! -type d \) | grep -q .; then fail "restored tree contains an unsafe entry"; fi
chown -R 10001:10001 "$RESTORE_DIR"

compose stop -t 20 candidate-guard
[ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || fail "candidate did not stop"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FAILED_DIR=$SPOOL_PARENT/$(basename -- "$SPOOL_DIR").failed.$STAMP
[ ! -e "$FAILED_DIR" ] || fail "retained spool destination already exists"
HAD_OLD=false
if [ -e "$SPOOL_DIR" ]; then mv -- "$SPOOL_DIR" "$FAILED_DIR"; HAD_OLD=true; fi
if ! mv -- "$RESTORE_DIR" "$SPOOL_DIR"; then
  if [ -e "$FAILED_DIR" ] && [ ! -e "$SPOOL_DIR" ]; then
    if ! mv -- "$FAILED_DIR" "$SPOOL_DIR"; then
      printf '%s\n' "CRITICAL: restore switch and automatic rollback both failed; candidate remains stopped" >&2
      exit 2
    fi
  fi
  fail "restored spool switch failed; prior spool was put back"
fi
if rm -f -- "$STAGE/spool.tar.gz" "$STAGE/catalog.json" "$STAGE/image-inspect.json" "$STAGE/SHA256SUMS" && rmdir -- "$STAGE"; then
  STAGE=
else
  printf '%s\n' "WARNING: restore succeeded but temporary cleanup requires attention: $STAGE" >&2
fi
if [ "$HAD_OLD" = true ]; then
  printf '%s\n' "candidate spool restored; previous spool retained at: $FAILED_DIR"
else
  printf '%s\n' "candidate spool restored; no previous spool existed"
fi
if [ "$HAD_OLD" = true ]; then
  printf '%s\n' "candidate remains stopped; run verify-candidate.sh before removing the retained spool"
else
  printf '%s\n' "candidate remains stopped; run verify-candidate.sh before use"
fi
