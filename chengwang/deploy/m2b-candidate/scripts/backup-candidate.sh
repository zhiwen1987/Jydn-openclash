#!/bin/sh
# Consistent backup of the disposable candidate spool. Every mutable path must
# remain under one explicitly bounded candidate root.
set -eu
umask 077

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"; }

[ "$#" -eq 3 ] || fail "usage: $0 ABSOLUTE_SPOOL_DIR ABSOLUTE_CATALOG_FILE ABSOLUTE_BACKUP_ROOT"
for command_name in docker findmnt head python3 realpath sha256sum stat tar; do require "$command_name"; done

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/candidate-root-lib.sh"
candidate_load_existing_root

SPOOL_DIR=$(realpath "$1")
CATALOG_FILE=$(realpath "$2")
BACKUP_ROOT=$(realpath "$3")
[ -d "$SPOOL_DIR" ] && [ ! -L "$1" ] || fail "spool must be a real directory"
[ -f "$CATALOG_FILE" ] && [ ! -L "$2" ] || fail "catalog must be a real regular file"
[ -d "$BACKUP_ROOT" ] && [ ! -L "$3" ] || fail "backup root must already be a real directory"
case "$SPOOL_DIR:$BACKUP_ROOT" in "$CANDIDATE_ROOT"/*:"$CANDIDATE_ROOT"/*) ;; *) fail "spool and backup root must stay under candidate root" ;; esac
[ "$SPOOL_DIR" = "$CANDIDATE_ROOT/spool" ] || fail "spool must be the dedicated root/spool directory"
[ "$BACKUP_ROOT" = "$CANDIDATE_ROOT/backups" ] || fail "backup root must be the dedicated root/backups directory"
case "$BACKUP_ROOT" in "$SPOOL_DIR"|"$SPOOL_DIR"/*) fail "backup root cannot be inside the spool" ;; esac
case "$SPOOL_DIR" in "$BACKUP_ROOT"|"$BACKUP_ROOT"/*) fail "spool cannot be inside the backup root" ;; esac
candidate_assert_no_symlink_components "$SPOOL_DIR"
candidate_assert_no_symlink_components "$BACKUP_ROOT"
candidate_assert_admin_directory "$BACKUP_ROOT"
candidate_assert_same_mount "$CANDIDATE_ROOT" "$SPOOL_DIR"
candidate_assert_same_mount "$CANDIDATE_ROOT" "$BACKUP_ROOT"
python3 - "$SPOOL_DIR" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
count = 0
total = 0
for base, directories, files in os.walk(root, followlinks=False):
    for name in directories + files:
        path = pathlib.Path(base, name)
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise SystemExit(f"unsafe spool entry: {path}")
        count += 1
        if count > 4096:
            raise SystemExit("spool entry limit exceeded")
        if stat.S_ISREG(mode):
            total += path.stat().st_size
            if total > 128 * 1024 * 1024:
                raise SystemExit("spool byte limit exceeded")
PY

compose() { docker compose --project-name "$M2B_PROJECT_NAME" --project-directory "$ROOT_DIR" -f "$ROOT_DIR/compose.yaml" "$@"; }
CID=$(compose ps -aq candidate-guard)
[ -n "$CID" ] || fail "candidate container must exist so mounts can be verified"
[ "$(docker inspect --format '{{index .Config.Labels "com.jydn.chengwang.component"}}' "$CID")" = m2b-candidate-guard ] || fail "container identity mismatch"
MOUNTED_SPOOL=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/chengwang-probe"}}{{.Source}}{{end}}{{end}}' "$CID")
MOUNTED_CATALOG=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/run/chengwang-probe/catalog.json"}}{{.Source}}{{end}}{{end}}' "$CID")
[ -n "$MOUNTED_SPOOL" ] && [ "$(realpath "$MOUNTED_SPOOL")" = "$SPOOL_DIR" ] || fail "spool argument is not the container mount source"
[ -n "$MOUNTED_CATALOG" ] && [ "$(realpath "$MOUNTED_CATALOG")" = "$CATALOG_FILE" ] || fail "catalog argument is not the container mount source"

compose stop -t 20 candidate-guard
[ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || fail "candidate did not stop"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FINAL_DESTINATION=$BACKUP_ROOT/$STAMP
DESTINATION=$BACKUP_ROOT/.pending-$STAMP-$$
[ ! -e "$FINAL_DESTINATION" ] && [ ! -e "$DESTINATION" ] || fail "backup destination already exists"
mkdir -m 700 "$DESTINATION"
cleanup_pending() {
  [ -z "${DESTINATION:-}" ] || rm -rf -- "$DESTINATION" || printf '%s\n' "WARNING: incomplete backup cleanup requires attention: $DESTINATION" >&2
}
trap cleanup_pending EXIT HUP INT TERM
tar -C "$SPOOL_DIR" -czf "$DESTINATION/spool.tar.gz" .
[ "$(stat -c %s "$DESTINATION/spool.tar.gz")" -le 134217728 ] || fail "compressed spool archive exceeds 128 MiB"
python3 - "$DESTINATION/spool.tar.gz" <<'PY'
import pathlib, sys, tarfile
count = 0
total = 0
with tarfile.open(sys.argv[1], "r|gz") as source:
    for member in source:
        if member.name not in (".", "./"):
            count += 1
            if member.isfile():
                total += member.size
        if count > 4096 or total > 128 * 1024 * 1024:
            raise SystemExit("generated archive limits exceeded")
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
            raise SystemExit("generated archive contains an unsafe entry")
PY
cp -- "$CATALOG_FILE" "$DESTINATION/catalog.json"
IMAGE_ID=$(docker inspect --format '{{.Image}}' "$CID")
[ -n "$IMAGE_ID" ] || fail "candidate image id is missing"
docker image inspect "$IMAGE_ID" >"$DESTINATION/image-inspect.json"
(
  cd "$DESTINATION"
  sha256sum catalog.json image-inspect.json spool.tar.gz >SHA256SUMS
)
chmod 600 "$DESTINATION"/*
mv -- "$DESTINATION" "$FINAL_DESTINATION"
DESTINATION=
trap - EXIT HUP INT TERM
printf '%s\n' "candidate backup complete and candidate left stopped: $FINAL_DESTINATION"
