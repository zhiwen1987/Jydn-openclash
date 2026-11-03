#!/usr/bin/env bash
# CI-only isolated Fixture B invocation. Raw Go output never leaves private tmpfs.
set -euo pipefail
test "$#" -eq 10
repo="$1"
public="$2"
goroot="$3"
commit="$4"
tree="$5"
run_id="$6"
run_attempt="$7"
lane="$8"
contract_sha="$9"
trusted_owner_uid="${10}"
test "$lane" = ordinary || test "$lane" = race
case "$commit" in (*[!0-9a-f]*|'') exit 2;; esac
case "$tree" in (*[!0-9a-f]*|'') exit 2;; esac
case "$run_id" in (*[!0-9]*|'') exit 2;; esac
case "$run_attempt" in (*[!0-9]*|'') exit 2;; esac
case "$trusted_owner_uid" in (*[!0-9]*|'') exit 2;; esac
test "${#commit}" -eq 40
test "${#tree}" -eq 40
test -d "$repo/.git" -o -f "$repo/.git"
test -d "$goroot"
test -d "$public"

host_checker="$repo/chengwang/deploy/mihomo-capacity-fixture-b/check_fixture_b.py"
contract="$repo/chengwang/deploy/mihomo-capacity-fixture-b/fixture_b_contract.json"
journal="$public/.setup-journal"
setup_common=(--contract "$contract" --contract-sha256 "$contract_sha" --journal "$journal"
  --source-commit "$commit" --source-tree "$tree" --run-id "$run_id" --run-attempt "$run_attempt"
  --lane "$lane" --trusted-owner-uid "$trusted_owner_uid")
active_phase=""
setup_event() {
  local phase="$1" status="$2"
  shift 2
  if test "$#" -eq 1; then
    /usr/bin/python3 -B "$host_checker" setup-event "${setup_common[@]}" \
      --phase "$phase" --status "$status" --command-exit-status "$1"
  else
    /usr/bin/python3 -B "$host_checker" setup-event "${setup_common[@]}" \
      --phase "$phase" --status "$status"
  fi
}
phase_enter() { active_phase="$1"; setup_event "$active_phase" ENTERED; }
phase_pass() { local status="${1:-0}"; setup_event "$active_phase" PASS "$status"; active_phase=""; }
on_exit() {
  local status=$?
  trap - EXIT
  if test "$status" -ne 0 && test -n "$active_phase"; then
    setup_event "$active_phase" FAIL "$status" || true
  fi
  exit "$status"
}
trap on_exit EXIT

phase_enter NAMESPACE_ENTRY
phase_pass
phase_enter MOUNT_PRIVATE
mount --make-rprivate /
phase_pass
phase_enter LOOPBACK
ip link set lo up
phase_pass
phase_enter REPO_BIND
mount --bind "$repo" "$repo"
phase_pass
phase_enter REPO_READONLY
mount -o remount,bind,ro,nosuid,nodev "$repo"
phase_pass
phase_enter GOROOT_BIND
mount --bind "$goroot" "$goroot"
phase_pass
phase_enter GOROOT_READONLY
mount -o remount,bind,ro,nosuid,nodev "$goroot"
phase_pass
phase_enter TMPFS
mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs /tmp
phase_pass
phase_enter UID_STORAGE
install -d -m 0700 -o 10001 -g 10001 /tmp/fixture-home /tmp/fixture-cache /tmp/fixture-mod /tmp/fixture-private
phase_pass
phase_enter SOURCE_ALIAS
install -d -m 0755 /tmp/fixture-source /tmp/fixture-export
mount --bind "$repo/chengwang" /tmp/fixture-source
phase_pass
phase_enter SOURCE_READONLY
mount -o remount,bind,ro,nosuid,nodev,noexec /tmp/fixture-source
phase_pass
phase_enter EXPORT_ALIAS
mount --bind "$public" /tmp/fixture-export
phase_pass
phase_enter EXPORT_READWRITE
mount -o remount,bind,rw,nosuid,nodev,noexec /tmp/fixture-export
phase_pass
phase_enter SOURCE_CWD
cd /tmp/fixture-source
phase_pass

checker=/tmp/fixture-source/deploy/mihomo-capacity-fixture-b/check_fixture_b.py
contract=/tmp/fixture-source/deploy/mihomo-capacity-fixture-b/fixture_b_contract.json
common=(setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  env -i "PATH=$goroot/bin:/usr/bin:/bin" "GOROOT=$goroot" HOME=/tmp/fixture-home TMPDIR=/tmp/fixture-home
  GOCACHE=/tmp/fixture-cache GOMODCACHE=/tmp/fixture-mod GOPROXY=off GOSUMDB=off GOENV=off GOWORK=off
  GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC)

phase_enter UID_PREFLIGHT_SCRIPT
"${common[@]}" test -r "$checker"
phase_pass
phase_enter UID_PREFLIGHT_MODULE_ROOT
"${common[@]}" test -r go.mod
"${common[@]}" test -x .
phase_pass
phase_enter UID_PREFLIGHT_GOROOT_EXEC
"${common[@]}" test -x "$goroot/bin/go"
phase_pass
phase_enter GO_ENV_COMMAND
set +e
"${common[@]}" go env -json CGO_ENABLED GOARCH GOENV GOFLAGS GOOS GOPROXY GOSUMDB GOTOOLCHAIN GOVERSION GOWORK \
  >/tmp/fixture-private/go-env.json 2>/tmp/fixture-private/go-env.stderr
go_env_exit=$?
set -e
phase_pass "$go_env_exit"
phase_enter GO_ENV_EXIT
test "$go_env_exit" -eq 0
phase_pass
phase_enter GO_ENV_STDERR_EMPTY
test ! -s /tmp/fixture-private/go-env.stderr
phase_pass
phase_enter TOOLCHAIN_WRITER
/usr/bin/python3 -B "$checker" toolchain --contract "$contract" --contract-sha256 "$contract_sha" \
  --go-env /tmp/fixture-private/go-env.json --out /tmp/fixture-export/toolchain.json
phase_pass

phase_enter FORMAT_GATE
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
phase_pass

command=(go test -json -mod=vendor -count=1 -p=1 -shuffle=off -timeout=180s
  -run '^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$' ./internal/mihomodeploy)
if test "$lane" = race; then
  command=(go test -race -json -mod=vendor -count=1 -p=1 -shuffle=off -timeout=180s
    -run '^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$' ./internal/mihomodeploy)
fi
phase_enter GO_INVOKE
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
phase_pass "$go_exit"
phase_enter ORACLE_VALIDATE
set +e
/usr/bin/python3 -B "$checker" events --contract "$contract" --contract-sha256 "$contract_sha" \
  --lane "$lane" --source-before /tmp/fixture-export/source-before.json \
  --toolchain /tmp/fixture-export/toolchain.json --format-status /tmp/fixture-export/format-status.json \
  --events /tmp/fixture-private/events.jsonl --stderr /tmp/fixture-private/go.stderr --go-exit "$go_exit" \
  --out /tmp/fixture-export/summary.json
oracle_exit=$?
set -e
test "$oracle_exit" -eq 0
phase_pass
