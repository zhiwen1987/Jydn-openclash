#!/usr/bin/env bash
# CI-only isolated Fixture B invocation. Raw Go output never leaves private tmpfs.
set -euo pipefail
test "$#" -eq 6
repo="$1"
public="$2"
goroot="$3"
commit="$4"
lane="$5"
contract_sha="$6"
test "$lane" = ordinary || test "$lane" = race
case "$commit" in (*[!0-9a-f]*|'') exit 2;; esac
test "${#commit}" -eq 40
test -d "$repo/.git" -o -f "$repo/.git"
test -d "$goroot"
test -d "$public"

mount --make-rprivate /
ip link set lo up
mount --bind "$repo" "$repo"
mount -o remount,bind,ro,nosuid,nodev "$repo"
mount --bind "$goroot" "$goroot"
mount -o remount,bind,ro,nosuid,nodev "$goroot"
mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs /tmp
install -d -m 0700 -o 10001 -g 10001 /tmp/fixture-home /tmp/fixture-cache /tmp/fixture-mod /tmp/fixture-private
install -d -m 0755 /tmp/fixture-source /tmp/fixture-export
mount --bind "$repo/chengwang" /tmp/fixture-source
mount -o remount,bind,ro,nosuid,nodev,noexec /tmp/fixture-source
mount --bind "$public" /tmp/fixture-export
mount -o remount,bind,rw,nosuid,nodev,noexec /tmp/fixture-export
cd /tmp/fixture-source

checker=/tmp/fixture-source/deploy/mihomo-capacity-fixture-b/check_fixture_b.py
contract=/tmp/fixture-source/deploy/mihomo-capacity-fixture-b/fixture_b_contract.json
common=(setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  env -i "PATH=$goroot/bin:/usr/bin:/bin" "GOROOT=$goroot" HOME=/tmp/fixture-home TMPDIR=/tmp/fixture-home
  GOCACHE=/tmp/fixture-cache GOMODCACHE=/tmp/fixture-mod GOPROXY=off GOSUMDB=off GOENV=off GOWORK=off
  GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC)

"${common[@]}" go env -json CGO_ENABLED GOARCH GOENV GOFLAGS GOOS GOPROXY GOSUMDB GOTOOLCHAIN GOVERSION GOWORK \
  >/tmp/fixture-private/go-env.json 2>/tmp/fixture-private/go-env.stderr
test ! -s /tmp/fixture-private/go-env.stderr
/usr/bin/python3 -B "$checker" toolchain --contract "$contract" --contract-sha256 "$contract_sha" \
  --go-env /tmp/fixture-private/go-env.json --out /tmp/fixture-export/toolchain.json

set +e
"${common[@]}" gofmt -d internal/mihomodeploy/lifecycle_recovery_transitions_test.go \
  >/tmp/fixture-private/gofmt.patch 2>/tmp/fixture-private/gofmt.stderr
format_exit=$?
set -e
set +e
/usr/bin/python3 -B "$checker" format --contract "$contract" --contract-sha256 "$contract_sha" \
  --patch /tmp/fixture-private/gofmt.patch --public-patch /tmp/fixture-export/gofmt.patch \
  --stderr /tmp/fixture-private/gofmt.stderr --exit "$format_exit" --out /tmp/fixture-export/format-status.json
format_gate=$?
set -e
test "$format_gate" -eq 0

command=(go test -json -mod=vendor -count=1 -p=1 -shuffle=off -timeout=180s
  -run '^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$' ./internal/mihomodeploy)
if test "$lane" = race; then
  command=(go test -race -json -mod=vendor -count=1 -p=1 -shuffle=off -timeout=180s
    -run '^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$' ./internal/mihomodeploy)
fi
set +e
if test "$lane" = race; then
  "${common[@]}" GORACE=atexit_sleep_ms=0 "${command[@]}" \
    >/tmp/fixture-private/events.jsonl 2>/tmp/fixture-private/go.stderr
else
  "${common[@]}" "${command[@]}" \
    >/tmp/fixture-private/events.jsonl 2>/tmp/fixture-private/go.stderr
fi
go_exit=$?
set -e
set +e
/usr/bin/python3 -B "$checker" events --contract "$contract" --contract-sha256 "$contract_sha" \
  --lane "$lane" --source-before /tmp/fixture-export/source-before.json \
  --toolchain /tmp/fixture-export/toolchain.json --format-status /tmp/fixture-export/format-status.json \
  --events /tmp/fixture-private/events.jsonl --stderr /tmp/fixture-private/go.stderr --go-exit "$go_exit" \
  --out /tmp/fixture-export/summary.json
oracle_exit=$?
set -e
test "$oracle_exit" -eq 0
