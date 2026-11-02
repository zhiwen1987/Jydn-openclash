#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 5
source_root="$1"; outer="$2"; outer_net="$3"; profile="$4"; commit="$5"
test "$(/usr/bin/id -u)" -eq 0
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$outer_net"
case "$profile" in units|product) ;; *) exit 1 ;; esac
/usr/bin/mount --make-rprivate /
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=16m tmpfs /mnt
alias_root=/mnt/joint-control-plane
/usr/bin/install -d -m 0755 "$alias_root" "$alias_root/source" "$alias_root/bin" "$alias_root/evidence"
/usr/bin/mount --bind "$source_root" "$alias_root/source"; /usr/bin/mount -o remount,bind,ro,nosuid,nodev,noexec "$alias_root/source"
/usr/bin/mount --bind "$outer/bin" "$alias_root/bin"; /usr/bin/mount -o remount,bind,ro,nosuid,nodev,exec "$alias_root/bin"
/usr/bin/mount --bind "$outer/evidence" "$alias_root/evidence"; /usr/bin/mount -o remount,bind,nosuid,nodev,noexec "$alias_root/evidence"
/usr/bin/mount -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=384m tmpfs /tmp
/usr/sbin/ip link set lo up
/usr/sbin/ip address add 8.8.4.4/32 dev lo
/usr/bin/mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
/usr/sbin/sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
test -z "$(/usr/sbin/ip -4 route show default)"; test -z "$(/usr/sbin/ip -6 route show default)"
private=/tmp/joint-private-$(/usr/bin/openssl rand -hex 16)
/usr/bin/install -d -m 0700 "$private"
/usr/bin/mount -t tmpfs -o mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec,size=256m tmpfs "$private"
/usr/bin/install -d -m 0700 -o 10001 -g 10001 "$private/lab" "$private/harness-logs"
lab_private="$private/lab"
private_logs="$private/harness-logs"
progress="$alias_root/evidence/staging/failure-localization.private"
for log in units.stdout units.stderr isolation.stdout isolation.stderr runner.stdout runner.stderr sanitizer.stdout sanitizer.stderr; do
  /usr/bin/install -m 0600 -o 10001 -g 10001 /dev/null "$private_logs/$log"
done
cleanup(){ /usr/bin/umount "$private" 2>/dev/null || true; /usr/bin/rmdir "$private" 2>/dev/null || true; }
scripts="$alias_root/source/chengwang/deploy/joint-control-plane"
run_user(){ /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 TMPDIR="$private" /usr/bin/python3 -I -B "$@"; }
finish(){
  code=$?; trap - EXIT
  if test "$code" -ne 0 && test "$profile" = product && test -d "$alias_root/evidence/staging"; then
    set +e
    run_user "$scripts/sanitize_publication.py" failure --input "$private" --progress-root "$progress" --source-commit "$commit" --code PRIVATE_SCENE_FAILED --output "$alias_root/evidence/staging/private-failure-identity.json" >/dev/null 2>/dev/null
    set -e
  fi
  cleanup
  exit "$code"
}
trap finish EXIT
if test "$profile" = units; then
  /usr/bin/install -d -m 0700 -o 10001 -g 10001 "$alias_root/evidence/staging/cpu"
  run_user "$scripts/ci_joint_control_plane.py" units --output "$alias_root/evidence/staging/cpu/units.json" >"$private_logs/units.stdout" 2>"$private_logs/units.stderr"
else
  /usr/bin/test -d "$alias_root/evidence/staging/lab"
  record(){ run_user "$scripts/ci_joint_control_plane.py" progress --progress-root "$progress" --source-commit "$commit" --phase "$1" --state "$2"; }
  record NAMESPACE_SETUP COMPLETED
  record ISOLATION_CHECK ENTERED
  run_user "$scripts/ci_joint_control_plane.py" isolation --outer-net-namespace "$outer_net" --progress-root "$progress" --source-commit "$commit" --output "$alias_root/evidence/staging/lab/isolation.json" >"$private_logs/isolation.stdout" 2>"$private_logs/isolation.stderr"
  record ISOLATION_CHECK COMPLETED
  record RUNNER_PREPARE ENTERED
  run_user "$scripts/run_joint_control_plane.py" --server-binary "$alias_root/bin/server" --fixture-script "$scripts/joint_fixture.py" --private-root "$lab_private" --evidence-dir "$alias_root/evidence/staging/lab" --progress-root "$progress" --source-commit "$commit" >"$private_logs/runner.stdout" 2>"$private_logs/runner.stderr"
  record PRIVATE_SANITIZER ENTERED
  run_user "$scripts/sanitize_publication.py" private --private-root "$lab_private" --input "$alias_root/evidence/staging/lab" --progress-root "$progress" --source-commit "$commit" --output "$alias_root/evidence/staging/lab/private-checks.json" >"$private_logs/sanitizer.stdout" 2>"$private_logs/sanitizer.stderr"
  record PRIVATE_SANITIZER COMPLETED
fi
