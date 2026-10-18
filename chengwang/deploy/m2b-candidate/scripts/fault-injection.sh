#!/bin/sh
# Safe fault injections against the disposable candidate guard only.
set -eu
umask 077

fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/candidate-root-lib.sh"
for command_name in findmnt head python3 realpath; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: $command_name"
done
candidate_load_existing_root
compose() {
  docker compose --project-name "$M2B_PROJECT_NAME" --project-directory "$ROOT_DIR" -f "$ROOT_DIR/compose.yaml" "$@"
}

docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
CID=$(compose ps -q candidate-guard)
[ -n "$CID" ] || fail "candidate guard must already be running"
[ "$(docker inspect --format '{{index .Config.Labels "com.jydn.chengwang.component"}}' "$CID")" = m2b-candidate-guard ] || fail "container identity mismatch"
[ "$(docker inspect --format '{{.State.Health.Status}}' "$CID")" = healthy ] || fail "candidate must be healthy before fault injection"
[ "$(docker inspect --format '{{.State.Health.FailingStreak}}' "$CID")" = 0 ] || fail "candidate has a pre-existing health failure streak"
docker exec "$CID" /app/m2b-candidate-guard health --health-file /run/m2b/health.json --max-age 20s >/dev/null || fail "candidate health command failed before fault injection"
IMAGE=$(docker inspect --format '{{.Image}}' "$CID")
[ -n "$IMAGE" ] || fail "candidate image is missing"
case "$IMAGE" in sha256:*) ;; *) fail "candidate image is not bound to an immutable image id" ;; esac

TMPDIR_PRIVATE=$(mktemp -d)
cleanup() {
  docker kill --signal CONT "$CID" >/dev/null 2>&1 || true
  rm -rf "$TMPDIR_PRIVATE"
}
trap cleanup EXIT HUP INT TERM
chmod 755 "$TMPDIR_PRIVATE"
printf '%s\n' '{}' >"$TMPDIR_PRIVATE/invalid.json"
chmod 644 "$TMPDIR_PRIVATE/invalid.json"
mkdir "$TMPDIR_PRIVATE/spool"
chown 10001:10001 "$TMPDIR_PRIVATE/spool"
chmod 700 "$TMPDIR_PRIVATE/spool"
RUN_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')

if docker run --rm --label "com.jydn.chengwang.fault-run=$RUN_ID" --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 10001:10001 \
  --tmpfs /run/m2b:size=1m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec \
  --mount "type=bind,src=$TMPDIR_PRIVATE/invalid.json,dst=/run/chengwang-probe/catalog.json,readonly" \
  --mount "type=bind,src=$TMPDIR_PRIVATE/spool,dst=/var/lib/chengwang-probe" \
  "$IMAGE" serve --catalog /run/chengwang-probe/catalog.json --spool /var/lib/chengwang-probe --health-file /run/m2b/health.json >"$TMPDIR_PRIVATE/invalid.log" 2>&1; then
  fail "invalid catalog did not fail closed"
fi
grep -q 'parse catalog' "$TMPDIR_PRIVATE/invalid.log" || fail "invalid catalog failed for an unrelated reason"

CATALOG_SOURCE=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/run/chengwang-probe/catalog.json"}}{{.Source}}{{end}}{{end}}' "$CID")
[ -n "$CATALOG_SOURCE" ] || fail "cannot locate candidate catalog source"
if docker run --rm --label "com.jydn.chengwang.fault-run=$RUN_ID" --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 10001:10001 \
  --tmpfs /run/m2b:size=1m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec \
  --mount "type=bind,src=$CATALOG_SOURCE,dst=/run/chengwang-probe/catalog.json,readonly" \
  --mount "type=bind,src=$TMPDIR_PRIVATE/spool,dst=/var/lib/chengwang-probe,readonly" \
  "$IMAGE" serve --catalog /run/chengwang-probe/catalog.json --spool /var/lib/chengwang-probe --health-file /run/m2b/health.json >"$TMPDIR_PRIVATE/readonly.log" 2>&1; then
  fail "read-only spool did not fail closed"
fi
grep -q 'verify candidate spool' "$TMPDIR_PRIVATE/readonly.log" || fail "read-only spool failed for an unrelated reason"

docker kill --signal STOP "$CID" >/dev/null
remaining=60
STATE=unknown
while [ "$remaining" -gt 0 ]; do
  STATE=$(docker inspect --format '{{.State.Health.Status}}' "$CID")
  [ "$STATE" = unhealthy ] && break
  sleep 2
  remaining=$((remaining - 2))
done
[ "$STATE" = unhealthy ] || fail "stopped heartbeat did not become unhealthy (state=$STATE)"
[ "$(docker inspect --format '{{.State.Health.FailingStreak}}' "$CID")" -gt 0 ] || fail "unhealthy state lacks a failing health streak"
docker kill --signal CONT "$CID" >/dev/null

remaining=30
while [ "$remaining" -gt 0 ]; do
  STATE=$(docker inspect --format '{{.State.Health.Status}}' "$CID")
  [ "$STATE" = healthy ] && break
  sleep 2
  remaining=$((remaining - 2))
done
[ "$STATE" = healthy ] || fail "candidate did not recover after heartbeat resumed"
[ "$(docker inspect --format '{{.State.Health.FailingStreak}}' "$CID")" = 0 ] || fail "health failure streak did not clear after recovery"
docker exec "$CID" /app/m2b-candidate-guard health --health-file /run/m2b/health.json --max-age 20s >/dev/null || fail "candidate health command failed after recovery"

printf '%s\n' 'INVALID_CATALOG_FAIL_CLOSED=PASS'
printf '%s\n' 'READONLY_SPOOL_FAIL_CLOSED=PASS'
printf '%s\n' 'STALE_HEARTBEAT_DETECTION=PASS'
printf '%s\n' 'DNS_TCP_TLS_HTTP_BUSINESS_FAULTS=BLOCKED_NO_ACTIVE_AGENT'
