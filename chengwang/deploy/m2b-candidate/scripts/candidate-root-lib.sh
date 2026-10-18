#!/bin/sh
# Shared candidate-root policy. Callers must set ROOT_DIR first.

M2B_ROOT_MARKER=.chengwang-m2b-candidate-root
M2B_ROOT_MARKER_VALUE=chengwang-m2b-candidate-root/v1

candidate_fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

candidate_assert_no_symlink_components() {
  python3 - "$1" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(os.path.abspath(sys.argv[1]))
current = pathlib.Path(path.anchor)
for part in path.parts[1:]:
    current /= part
    try:
        mode = os.lstat(current).st_mode
    except FileNotFoundError:
        raise SystemExit(f"path component is missing: {current}")
    if stat.S_ISLNK(mode):
        raise SystemExit(f"symlink path component is forbidden: {current}")
PY
}

candidate_mount_signature() {
  findmnt --target "$1" --noheadings --raw --output TARGET,MAJ:MIN,FSROOT | head -n 1
}

candidate_assert_same_mount() {
  candidate_left_mount=$(candidate_mount_signature "$1")
  candidate_right_mount=$(candidate_mount_signature "$2")
  [ -n "$candidate_left_mount" ] && [ "$candidate_left_mount" = "$candidate_right_mount" ] || \
    candidate_fail "independent/bind mount is forbidden below candidate root: $2"
}

candidate_check_allowed_root() {
  candidate_root=$1
  candidate_default_root=$(realpath -m "$ROOT_DIR/runtime")
  case "$candidate_root" in
    /opt/chengwang|/opt/chengwang/*)
      candidate_fail "production control path is forbidden: $candidate_root"
      ;;
  esac
  case "$candidate_root" in
    "$candidate_default_root") ;;
    /var/lib/chengwang-m2b-candidate/*)
      candidate_suffix=${candidate_root#/var/lib/chengwang-m2b-candidate/}
      case "$candidate_suffix" in ''|*/*) candidate_fail "candidate instance path must contain exactly one segment" ;; esac
      candidate_assert_admin_directory /var/lib/chengwang-m2b-candidate
      candidate_assert_same_mount /var/lib /var/lib/chengwang-m2b-candidate
      ;;
    /srv/chengwang-m2b-candidate/*)
      candidate_suffix=${candidate_root#/srv/chengwang-m2b-candidate/}
      case "$candidate_suffix" in ''|*/*) candidate_fail "candidate instance path must contain exactly one segment" ;; esac
      candidate_assert_admin_directory /srv/chengwang-m2b-candidate
      candidate_assert_same_mount /srv /srv/chengwang-m2b-candidate
      ;;
    *) candidate_fail "candidate root is outside the dedicated allowlist: $candidate_root" ;;
  esac
}

candidate_verify_marker() {
  candidate_marker=$1/$M2B_ROOT_MARKER
  [ -f "$candidate_marker" ] && [ ! -L "$candidate_marker" ] || candidate_fail "candidate root marker is missing or unsafe: $candidate_marker"
  [ "$(cat "$candidate_marker")" = "$M2B_ROOT_MARKER_VALUE" ] || candidate_fail "candidate root marker content is invalid"
  python3 - "$1" "$candidate_marker" <<'PY'
import os, pathlib, stat, sys
root, marker = map(pathlib.Path, sys.argv[1:])
for path, expected in ((root, stat.S_IFDIR), (marker, stat.S_IFREG)):
    info = path.lstat()
    if stat.S_IFMT(info.st_mode) != expected or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit(f"candidate root/marker must be root-owned and not group/world writable: {path}")
marker_info = marker.lstat()
if stat.S_IMODE(marker_info.st_mode) != 0o600 or marker_info.st_nlink != 1:
    raise SystemExit("candidate root marker must have mode 0600 and exactly one hard link")
PY
  candidate_assert_same_mount "$1" "$candidate_marker"
}

candidate_assert_admin_directory() {
  python3 - "$1" <<'PY'
import pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
info = path.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
    raise SystemExit(f"admin directory must be root-owned and not group/world writable: {path}")
PY
}

candidate_assert_admin_file() {
  python3 - "$1" <<'PY'
import pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
    raise SystemExit(f"admin file must be root-owned, mode 0600, and have one hard link: {path}")
PY
}

candidate_set_instance_id() {
  candidate_default_root=$(realpath -m "$ROOT_DIR/runtime")
  if [ "$CANDIDATE_ROOT" = "$candidate_default_root" ]; then
    candidate_instance_base=local
  else
    candidate_instance_base=$(basename -- "$CANDIDATE_ROOT")
  fi
  case "$candidate_instance_base" in
    [a-z0-9]*) ;;
    *) candidate_fail "candidate instance id must start with a lowercase letter or digit" ;;
  esac
  case "$candidate_instance_base" in
    *[!a-z0-9_-]*|'') candidate_fail "candidate instance id contains an unsafe character" ;;
  esac
  [ "${#candidate_instance_base}" -le 20 ] || candidate_fail "candidate instance id exceeds 20 characters"
  candidate_root_hash=$(python3 - "$CANDIDATE_ROOT" <<'PY'
import hashlib, sys
print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:12])
PY
)
  M2B_INSTANCE_ID=$candidate_instance_base-$candidate_root_hash
  M2B_PROJECT_NAME=chengwang-m2b-$M2B_INSTANCE_ID-candidate
  unset COMPOSE_PROJECT_NAME
  export M2B_INSTANCE_ID M2B_PROJECT_NAME
}

candidate_load_existing_root() {
  [ "$(id -u)" = 0 ] || candidate_fail "candidate lifecycle scripts must run as root"
  candidate_requested=${M2B_CANDIDATE_ROOT:-$ROOT_DIR/runtime}
  case "$candidate_requested" in /*) ;; *) candidate_fail "candidate root must be absolute" ;; esac
  [ -d "$candidate_requested" ] && [ ! -L "$candidate_requested" ] || candidate_fail "candidate root must already be a real directory"
  candidate_assert_no_symlink_components "$candidate_requested"
  CANDIDATE_ROOT=$(realpath "$candidate_requested")
  candidate_check_allowed_root "$CANDIDATE_ROOT"
  candidate_assert_same_mount "$(dirname -- "$CANDIDATE_ROOT")" "$CANDIDATE_ROOT"
  candidate_verify_marker "$CANDIDATE_ROOT"
  candidate_set_instance_id
  export CANDIDATE_ROOT
}

candidate_initialize_default_root() {
  [ "$(id -u)" = 0 ] || candidate_fail "candidate lifecycle scripts must run as root"
  [ -z "${M2B_CANDIDATE_ROOT:-}" ] || candidate_fail "custom roots must be initialized separately and contain the required marker"
  candidate_default=$ROOT_DIR/runtime
  if [ ! -e "$candidate_default" ]; then
    mkdir -m 700 -- "$candidate_default"
  fi
  [ -d "$candidate_default" ] && [ ! -L "$candidate_default" ] || candidate_fail "default candidate root must be a real directory"
  candidate_assert_no_symlink_components "$candidate_default"
  CANDIDATE_ROOT=$(realpath "$candidate_default")
  candidate_check_allowed_root "$CANDIDATE_ROOT"
  candidate_assert_same_mount "$(dirname -- "$CANDIDATE_ROOT")" "$CANDIDATE_ROOT"
  candidate_assert_admin_directory "$CANDIDATE_ROOT"
  candidate_marker=$CANDIDATE_ROOT/$M2B_ROOT_MARKER
  [ ! -L "$candidate_marker" ] || candidate_fail "dangling/symlink candidate root marker is forbidden"
  if [ ! -e "$candidate_marker" ]; then
    python3 - "$candidate_marker" "$M2B_ROOT_MARKER_VALUE" <<'PY'
import os, sys
path, value = sys.argv[1:]
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
try:
    os.write(descriptor, (value + "\n").encode("ascii"))
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  fi
  candidate_verify_marker "$CANDIDATE_ROOT"
  candidate_set_instance_id
  export CANDIDATE_ROOT
}
