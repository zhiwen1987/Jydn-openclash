#!/usr/bin/env bash
# CI-only private CPU experiment. Never invokes Mihomo, a service or HTTP.
set -euo pipefail
test "$#" -eq 4 || test "$#" -eq 5
repo="$1"
out="$2"
goroot="$3"
commit="$4"
diagnostic_mode="${5:-SINGLE_CASE}"
case "$diagnostic_mode" in SINGLE_CASE|FULL_CONTRACTS) ;; *) exit 2 ;; esac
test "$(id -u)" -eq 0
test -d "$repo/chengwang/vendor"
test -x "$goroot/bin/go"
test -x "$goroot/bin/gofmt"
test -d "$out"
test ! -L "$out"
test -f "$out/host-before.json"
test -f "$out/source-before.json"
test -z "$(find "$out" -mindepth 1 -maxdepth 1 ! -name host-before.json ! -name source-before.json -print -quit)"
[[ "$commit" =~ ^[a-f0-9]{40}$ ]]
mount --make-rprivate /
ip link set lo up
mount --bind "$repo" "$repo"
mount -o remount,bind,ro "$repo"
mount --bind "$goroot" "$goroot"
mount -o remount,bind,ro,nosuid,nodev "$goroot"
mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs /tmp
install -d -m 0700 -o 10001 -g 10001 /tmp/chengwang-capacity-profile-private /tmp/chengwang-capacity-profile-home /tmp/chengwang-capacity-profile-cache /tmp/chengwang-capacity-profile-mod
install -d -m 0755 /tmp/chengwang-capacity-profile-source /tmp/chengwang-capacity-profile-export
mount --bind "$repo/chengwang" /tmp/chengwang-capacity-profile-source
mount -o remount,bind,ro,nosuid,nodev,noexec /tmp/chengwang-capacity-profile-source
mount --bind "$out" /tmp/chengwang-capacity-profile-export
mount -o remount,bind,rw,nosuid,nodev,noexec /tmp/chengwang-capacity-profile-export
cd /tmp/chengwang-capacity-profile-source
common=(setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  env -i "PATH=$goroot/bin:/usr/bin:/bin" "GOROOT=$goroot" HOME=/tmp/chengwang-capacity-profile-home TMPDIR=/tmp/chengwang-capacity-profile-home
  GOCACHE=/tmp/chengwang-capacity-profile-cache GOMODCACHE=/tmp/chengwang-capacity-profile-mod GOPROXY=off GOSUMDB=off
  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
  "CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT=$commit")
diagnostic_args=()
if test "$diagnostic_mode" = FULL_CONTRACTS; then
  common+=(CHENGWANG_CAPACITY_PROFILE_MODE=FULL_CONTRACTS)
  diagnostic_args=(--diagnostic-mode FULL_CONTRACTS)
fi
helper=/tmp/chengwang-capacity-profile-source/deploy/mihomo-capacity-profile/profile_evidence.py
"${common[@]}" python3 -B "$helper" sandbox --goroot "$goroot" "${diagnostic_args[@]}" > /tmp/chengwang-capacity-profile-export/sandbox.json
set +e
"${common[@]}" python3 -B "$helper" commands --goroot "$goroot" "${diagnostic_args[@]}"
capture_code=$?
set -e
env -i PATH=/usr/bin:/bin "CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT=$commit" python3 -B "$helper" export --out /tmp/chengwang-capacity-profile-export "${diagnostic_args[@]}"
test "$capture_code" -eq 0
# Preserve the real original Go exit and nonempty formatter patch as failure.
python3 -B - /tmp/chengwang-capacity-profile-export <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);v=json.loads((p/'execution.json').read_bytes())
assert all(v[k]==0 and type(v[k]) is int for k in ('versionExit','formatExit','goExit','topExit','cumExit'))
assert (p/'gofmt.patch').read_bytes()==(p/'gofmt.stderr').read_bytes()==b''
assert v['profileCaptureComplete'] is True
PY
