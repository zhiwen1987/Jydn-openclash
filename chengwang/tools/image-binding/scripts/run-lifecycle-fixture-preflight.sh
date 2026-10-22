#!/usr/bin/env bash
# D12 prerequisites only. No product process, API, image or production device.
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
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in ext4|xfs) ;; *) exit 1;; esac
case "$run_root/" in "$source_root/"*) exit 1;; esac
# These CI paths must remain visible after the private /tmp overmount.
for path in "$source_root" "$run_root"; do
  case "$path/" in /tmp/*) exit 1;; esac
done
test -d "$run_root/evidence" && test ! -L "$run_root/evidence"
base="$source_root/chengwang/deploy/product-candidate"
prefix="$run_root/evidence/product-lifecycle"
private="$run_root/lifecycle-fixture-private"
tmp_mounted=false
handoff_reports() {
  for suffix in lease-tests.log feed-tests.log checker-tests.log preflight.json cleanup.json; do
    path="$prefix-$suffix"
    if test -f "$path" && test ! -L "$path"; then
      /usr/bin/chmod 0600 "$path"
      /usr/bin/chown "$runner_uid:$runner_gid" "$path"
    fi
  done
  if test -f "$run_root/evidence/product-crash-blob-lease-tests.log"; then
    /usr/bin/chmod 0600 "$run_root/evidence/product-crash-blob-lease-tests.log"
    /usr/bin/chown "$runner_uid:$runner_gid" "$run_root/evidence/product-crash-blob-lease-tests.log"
  fi
}
for suffix in lease-tests.log feed-tests.log checker-tests.log preflight.json cleanup.json; do
  test ! -e "$prefix-$suffix" && test ! -L "$prefix-$suffix"
done
test ! -e "$run_root/evidence/product-crash-blob-lease-tests.log" && test ! -L "$run_root/evidence/product-crash-blob-lease-tests.log"
test ! -e "$private" && test ! -L "$private"
cleanup_private() {
  # No host /tmp enumeration/deletion. This brand-new root-owned backing
  # directory is visible only through our child mount namespace's /tmp.
  /usr/bin/python3 -B - "$run_root" "$private" <<'PY'
import os, pathlib, re, shutil, stat, sys
run, private = map(pathlib.Path, sys.argv[1:])
assert run.is_absolute() and run.resolve() == run
assert str(run) != '/' and str(run) != '/tmp' and not str(run).startswith('/tmp/')
assert private == run / 'lifecycle-fixture-private' and private.resolve() == private
info = private.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
tmp = private / 'tmp'
if tmp.exists():
    t = tmp.lstat()
    assert stat.S_ISDIR(t.st_mode) and t.st_uid == 0 and stat.S_IMODE(t.st_mode) == 0o1777
    names = list(tmp.iterdir())
    # Validate every exact target before deleting any. Inner intentional
    # symlinks from negative tests are unlinked by rmtree, never followed.
    for target in names:
        assert re.fullmatch(r'chengwang-product-lifecycle-[a-f0-9]{32}', target.name)
        s = target.lstat()
        assert stat.S_ISDIR(s.st_mode) and s.st_dev == t.st_dev and not target.is_symlink()
        assert target.resolve().parent == tmp and s.st_uid in (0, 10001)
        for directory, dirs, files in os.walk(target, followlinks=False):
            for name in dirs + files:
                assert os.lstat(os.path.join(directory, name)).st_dev == t.st_dev
    for target in names:
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
print(json.dumps({'schema':'chengwang.product-lifecycle-preflight-cleanup/v1',
 'privateTreeRemoved':sys.argv[1]=='true','testExitCode':int(sys.argv[2]),
 'hostTmpTouched':False,'parentMountNamespaceChanged':False,
 'production':False,'authorization':'BLOCKED','deviceActionsExecuted':False},sort_keys=True))
PY
  if "$cleanup_ok" && test "$status" -eq 0; then
    if ! /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 \
      /usr/bin/python3 -B "$base/check_lifecycle_preflight.py" \
        --source-root "$source_root" --evidence-dir "$run_root/evidence" \
        --source-commit "$source_commit" > "$prefix-preflight.json"; then
      status=1
    fi
  fi
  handoff_reports
  if ! "$cleanup_ok"; then exit 1; fi
  if test "$status" -eq 0; then
    echo 'D12_FIXTURE_PREFLIGHT=PASS source_readonly=true external_network=false helpers_uid=10001 helpers_capabilities=none actual_product_lifecycle_proven=false authorization=BLOCKED production=false'
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
# Root only provisions/reaps exact private fixtures. All measured helpers are
# separately setpriv'd UID10001/GID10001, cap0 and NNP, and check this in code.
# Source is read-only; there is no external interface/default route or
# inherited application/GitHub credential in the environment supplied below.
# This trusted root test orchestrator is not the product sandbox: it does not
# call Docker, but does not claim host Unix sockets are hidden by the netns.
ulimit -c 0
ulimit -t 120
ulimit -n 256
ulimit -f 32768
ulimit -u 256
ulimit -v 1048576
for suite in lease feed; do
  /usr/bin/timeout --signal=TERM --kill-after=5s 180s \
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
      PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
      /usr/bin/python3 -B "$base/test_fixture_$suite.py" \
      2>&1 | /usr/bin/tee "$prefix-$suite-tests.log"
done
/usr/bin/timeout --signal=TERM --kill-after=5s 120s \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
    /usr/bin/python3 -B "$base/test_fixture_blob_lease.py" \
    2>&1 | /usr/bin/tee "$run_root/evidence/product-crash-blob-lease-tests.log"
/usr/bin/grep -qx 'D12_BLOB_LEASE_TESTS=PASS tests=13 passed=13 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none readonly_file_bind=true' \
  "$run_root/evidence/product-crash-blob-lease-tests.log"
/usr/bin/timeout --signal=TERM --kill-after=5s 30s \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -B "$base/test_check_lifecycle_preflight.py" \
    2>&1 | /usr/bin/tee "$prefix-checker-tests.log"
