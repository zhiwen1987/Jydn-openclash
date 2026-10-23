#!/usr/bin/env bash
# CI only. This script is invoked by unshare, never directly on a LAN host.
set -euo pipefail
test "$#" -eq 5
source_root="$1"
lab_outer="$2"
outer_net="$3"
profile="$4"
source_commit="$5"
test "$(/usr/bin/id -u)" -eq 0
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$outer_net"
test "$profile" = units -o "$profile" = product
/usr/bin/mount --make-rprivate /
# Hosted runners may have /home/runner=0750. Do not chmod the host or expect
# UID 10001 to traverse it. Exact read-only inputs and the bounded export get
# aliases on a private mount; the private data remains on noexec /tmp tmpfs.
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=16m tmpfs /mnt
alias_root=/mnt/subscription-lab
/usr/bin/install -d -m 0755 "$alias_root" "$alias_root/source" "$alias_root/bin" "$alias_root/evidence"
/usr/bin/mount --bind "$source_root" "$alias_root/source"
/usr/bin/mount -o remount,bind,ro,nosuid,nodev,noexec "$alias_root/source"
/usr/bin/mount --bind "$lab_outer/bin" "$alias_root/bin"
/usr/bin/mount -o remount,bind,ro,nosuid,nodev,exec "$alias_root/bin"
/usr/bin/mount --bind "$lab_outer/evidence" "$alias_root/evidence"
/usr/bin/mount -o remount,bind,nosuid,nodev,noexec "$alias_root/evidence"
source_root="$alias_root/source"
lab_outer="$alias_root"
/usr/bin/mount -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=256m tmpfs /tmp
/usr/sbin/ip link set lo up
/usr/sbin/ip address add 8.8.4.4/32 dev lo
# sysfs was mounted before entering the new network namespace. Re-mount only
# this private mount namespace so /sys/class/net also observes the private net.
/usr/bin/mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
/usr/sbin/sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
test -z "$(/usr/sbin/ip -4 route show default)"
test -z "$(/usr/sbin/ip -6 route show default)"
private_root="/tmp/chengwang-subscription-private-$(/usr/bin/openssl rand -hex 16)"
/usr/bin/install -d -m 0700 -o 10001 -g 10001 "$private_root"
script_root="$source_root/chengwang/deploy/subscription-readback"
run_unprivileged() {
  /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 TMPDIR="$private_root" \
      /usr/bin/python3 -I -B "$@"
}
if test "$profile" = units; then
  # The native wire tests are the root orchestrator in this private namespace.
  # Each fixture child is then independently setpriv-dropped to UID 10001,
  # capabilities=0 and NNP=1, which the child re-verifies. This is not root TLS.
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 TMPDIR="$private_root" \
    /usr/bin/python3 -I -B "$script_root/ci_subscription_lab.py" units --unit-profile wire \
    --output "$lab_outer/evidence/wire-units.json"
  run_unprivileged "$script_root/ci_subscription_lab.py" units --unit-profile contracts \
    --output "$lab_outer/evidence/contract-units.json"
else
  run_unprivileged "$script_root/ci_subscription_lab.py" isolation \
    --outer-net-namespace "$outer_net" --output "$lab_outer/evidence/lab/isolation.json"
  run_unprivileged "$script_root/run_subscription_lab.py" \
    --server-binary "$lab_outer/bin/server" --wire-script "$script_root/wire_fixture.py" \
    --private-root "$private_root" --evidence-dir "$lab_outer/evidence/lab" \
    --source-commit "$source_commit" --build-record "$lab_outer/evidence/lab/build.json"
fi
