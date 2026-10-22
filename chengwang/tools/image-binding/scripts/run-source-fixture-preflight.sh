#!/usr/bin/env bash
# Independent adversarial source fixture prerequisites, never product proof.
set -euo pipefail
umask 077

test "$#" -eq 8
source_root=$(/usr/bin/realpath -e -- "$1")
run_root=$(/usr/bin/realpath -e -- "$2")
parent_netns=$3
parent_mountns=$4
source_commit=$5
runner_uid=$6
runner_gid=$7
parent_fixture_mountns=$8
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]]
[[ "$runner_uid" =~ ^[1-9][0-9]*$ && "$runner_gid" =~ ^[1-9][0-9]*$ ]]
test "$(/usr/bin/id -u)" -eq 0
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$parent_netns"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$parent_mountns"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$parent_fixture_mountns"
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
test -z "$(/usr/sbin/ip -o route show default)"
test -z "$(/usr/sbin/ip -6 -o route show default)"
/usr/bin/findmnt -n -T "$source_root" -o OPTIONS | /usr/bin/grep -qE '(^|,)ro(,|$)'
for path in "$source_root" "$run_root"; do
  case "$path/" in /tmp/*) exit 1;; esac
done
case "$run_root/" in "$source_root/"*) exit 1;; esac
test -d "$run_root/evidence" && test ! -L "$run_root/evidence"
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in ext4|xfs) ;; *) exit 1;; esac

base="$source_root/chengwang/deploy/product-candidate"
prefix="$run_root/evidence/product-source-fixture"
private="$run_root/source-fixture-private"
tmp_mounted=false
for suffix in tests.log checker-tests.log observations.json cleanup.json preflight.json; do
  test ! -e "$prefix-$suffix" && test ! -L "$prefix-$suffix"
done
test ! -e "$private" && test ! -L "$private"

handoff_reports() {
  for suffix in tests.log checker-tests.log observations.json cleanup.json preflight.json; do
    path="$prefix-$suffix"
    if test -f "$path" && test ! -L "$path"; then
      /usr/bin/chmod 0600 "$path"
      /usr/bin/chown "$runner_uid:$runner_gid" "$path"
    fi
  done
}

cleanup_private() {
  # Validate all exact targets within this new private backing directory before
  # deleting any; never enumerate or delete the host /tmp or source tree.
  /usr/bin/python3 -B - "$run_root" "$private" <<'PY'
import os, pathlib, re, shutil, stat, sys
run, private = map(pathlib.Path, sys.argv[1:])
assert run.is_absolute() and run.resolve() == run
assert str(run) not in ('/', '/tmp') and not str(run).startswith('/tmp/')
assert private == run / 'source-fixture-private' and private.resolve() == private
info = private.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
tmp = private / 'tmp'
if tmp.exists():
    t = tmp.lstat()
    assert stat.S_ISDIR(t.st_mode) and t.st_uid == 0 and stat.S_IMODE(t.st_mode) == 0o1777
    targets = list(tmp.iterdir())
    for target in targets:
        assert re.fullmatch(r'chengwang-product-lifecycle-[a-f0-9]{32}', target.name)
        s = target.lstat()
        assert stat.S_ISDIR(s.st_mode) and s.st_dev == t.st_dev and not target.is_symlink()
        assert target.resolve().parent == tmp and s.st_uid in (0, 10001)
        for directory, dirs, files in os.walk(target, followlinks=False):
            for name in dirs + files:
                assert os.lstat(os.path.join(directory, name)).st_dev == t.st_dev
    for target in targets:
        shutil.rmtree(target)
    assert not list(tmp.iterdir())
PY
}

finish() {
  status=$?
  trap - EXIT
  cleanup_ok=true
  if ! cleanup_private; then cleanup_ok=false; fi
  if "$tmp_mounted"; then
    if ! /usr/bin/umount -- /tmp; then cleanup_ok=false; fi
  fi
  if "$cleanup_ok"; then
    /usr/bin/rmdir -- "$private/tmp" "$private" || cleanup_ok=false
  fi
  /usr/bin/python3 -B - "$cleanup_ok" "$status" <<'PY' > "$prefix-cleanup.json"
import json, sys
print(json.dumps({'schema':'chengwang.product-source-preflight-cleanup/v1',
 'privateTreeRemoved':sys.argv[1]=='true','testExitCode':int(sys.argv[2]),
 'hostTmpTouched':False,'parentMountNamespaceChanged':False,
 'production':False,'authorization':'BLOCKED','deviceActionsExecuted':False},sort_keys=True))
PY
  if "$cleanup_ok" && test "$status" -eq 0; then
    if ! /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 \
      /usr/bin/python3 -B "$base/check_source_preflight.py" \
        --source-root "$source_root" --evidence-dir "$run_root/evidence" \
        --source-commit "$source_commit" > "$prefix-preflight.json"; then
      status=1
    fi
  fi
  handoff_reports
  if ! "$cleanup_ok"; then exit 1; fi
  if test "$status" -eq 0; then
    echo 'D12_SOURCE_FIXTURE_PREFLIGHT=PASS source_readonly=true external_network=false helpers_uid=10001 helpers_capabilities=none actual_product_source_matrix_proven=false authorization=BLOCKED production=false'
  fi
  exit "$status"
}

/usr/bin/install -d -m 0700 -o 0 -g 0 "$private"
trap finish EXIT
/usr/bin/install -d -m 1777 -o 0 -g 0 "$private/tmp"
/usr/bin/mount --make-rprivate /
/usr/bin/mount --bind "$private/tmp" /tmp
tmp_mounted=true
test "$(/usr/bin/stat -c '%u:%g:%a' /tmp)" = 0:0:1777
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in ext4|xfs) ;; *) exit 1;; esac

# Trusted root only provisions private test files and reaps measured helpers.
# It does not execute a product, call Docker or claim host sockets are hidden.
ulimit -c 0
ulimit -t 120
ulimit -n 256
ulimit -f 32768
ulimit -u 256
ulimit -v 1048576
/usr/bin/timeout --signal=TERM --kill-after=5s 180s \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
    /usr/bin/python3 -B "$base/test_fixture_source.py" --evidence-dir "$run_root/evidence" \
    2>&1 | /usr/bin/tee "$prefix-tests.log"
/usr/bin/timeout --signal=TERM --kill-after=5s 30s \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
    /usr/bin/python3 -B "$base/test_check_source_preflight.py" \
    2>&1 | /usr/bin/tee "$prefix-checker-tests.log"
