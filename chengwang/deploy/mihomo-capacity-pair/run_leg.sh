#!/usr/bin/env bash
# One source-bound leg of the opt-in A/B diagnostic. Actual Go retains180s.
set -euo pipefail
test "$#" -eq 6
repo="$1"
out="$2"
goroot="$3"
commit="$4"
mode="$5"
context="$6"
case "$mode" in A|B) ;; *) exit 2 ;; esac
test "$(id -u)" -eq 0
test -d "$repo/chengwang/vendor"
test -x "$goroot/bin/go"
test -x "$goroot/bin/gofmt"
test -d "$out" && test ! -L "$out"
test -f "$context" && test ! -L "$context" && test "$(stat -c %h "$context")" -eq 1
for name in host-before.json source-before.json pair-context.json; do
  test -f "$out/$name" && test ! -L "$out/$name" && test "$(stat -c %h "$out/$name")" -eq 1
done
test "$(readlink -f "$context")" = "$(readlink -f "$out/pair-context.json")"
test -z "$(find "$out" -mindepth 1 -maxdepth 1 ! -name host-before.json ! -name source-before.json ! -name pair-context.json -print -quit)"
[[ "$commit" =~ ^[a-f0-9]{40}$ ]]
context_sha="$(sha256sum "$context")"; context_sha="${context_sha%% *}"
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
  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC)
pair_helper=/tmp/chengwang-capacity-profile-source/deploy/mihomo-capacity-pair/pair_evidence.py
profile_helper=/tmp/chengwang-capacity-profile-source/deploy/mihomo-capacity-profile/profile_evidence.py
if test "$mode" = A; then
  common+=("CHENGWANG_CAPACITY_PAIR_SOURCE_COMMIT=$commit" "CHENGWANG_CAPACITY_PAIR_CONTEXT_SHA256=$context_sha")
  "${common[@]}" python3 -B "$pair_helper" sandbox --goroot "$goroot" > /tmp/chengwang-capacity-profile-export/sandbox.json
  "${common[@]}" python3 -B "$pair_helper" commands --goroot "$goroot"
  env -i PATH=/usr/bin:/bin python3 -B "$pair_helper" export --out /tmp/chengwang-capacity-profile-export
else
  common+=("CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT=$commit" CHENGWANG_CAPACITY_PROFILE_MODE=FULL_CONTRACTS)
  "${common[@]}" python3 -B "$profile_helper" sandbox --goroot "$goroot" --diagnostic-mode FULL_CONTRACTS > /tmp/chengwang-capacity-profile-export/sandbox.json
  "${common[@]}" python3 -B "$profile_helper" commands --goroot "$goroot" --diagnostic-mode FULL_CONTRACTS
  env -i PATH=/usr/bin:/bin "CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT=$commit" python3 -B "$profile_helper" export --out /tmp/chengwang-capacity-profile-export --diagnostic-mode FULL_CONTRACTS
fi
env -i PATH=/usr/bin:/bin "CHENGWANG_CAPACITY_PAIR_SOURCE_COMMIT=$commit" python3 -B "$pair_helper" bind \
  --out /tmp/chengwang-capacity-profile-export --mode "$mode" --context /tmp/chengwang-capacity-profile-export/pair-context.json
