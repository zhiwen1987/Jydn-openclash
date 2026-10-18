#!/bin/sh
# Local/isolated candidate guard acceptance. This does not validate active
# probes, public egress, a resolver, OpenClash nodes, or business availability.
set -eu
umask 077

fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

compose() {
  docker compose --project-name "$M2B_PROJECT_NAME" --project-directory "$ROOT_DIR" -f "$ROOT_DIR/compose.yaml" "$@"
}

wait_healthy() {
  candidate_id=$1
  remaining=60
  while [ "$remaining" -gt 0 ]; do
    state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$candidate_id" 2>/dev/null || true)
    [ "$state" = healthy ] && return 0
    [ "$state" = unhealthy ] && fail "candidate became unhealthy"
    sleep 2
    remaining=$((remaining - 2))
  done
  fail "candidate did not become healthy within 60 seconds"
}

for command_name in chown docker findmnt grep head jq od python3 realpath sha256sum stat tr; do
  require_command "$command_name"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

. "$SCRIPT_DIR/candidate-root-lib.sh"
if [ -n "${M2B_CANDIDATE_ROOT:-}" ]; then
  candidate_load_existing_root
else
  candidate_initialize_default_root
fi
REQUESTED_SPOOL=${M2B_SPOOL_DIR:-$CANDIDATE_ROOT/spool}
[ "$(realpath -m -- "$REQUESTED_SPOOL")" = "$CANDIDATE_ROOT/spool" ] || fail "candidate spool must be the dedicated root/spool directory"
if [ ! -e "$REQUESTED_SPOOL" ]; then mkdir -m 700 -- "$REQUESTED_SPOOL"; fi
[ -d "$REQUESTED_SPOOL" ] && [ ! -L "$REQUESTED_SPOOL" ] || fail "candidate spool must be a real directory"
candidate_assert_no_symlink_components "$REQUESTED_SPOOL"
REQUESTED_SPOOL=$(realpath "$REQUESTED_SPOOL")
candidate_assert_same_mount "$CANDIDATE_ROOT" "$REQUESTED_SPOOL"
chown 10001:10001 "$REQUESTED_SPOOL" || fail "candidate spool must be owned by uid 10001"
chmod 700 "$REQUESTED_SPOOL"
export M2B_SPOOL_DIR=$REQUESTED_SPOOL
compose config -q
compose build --pull=false candidate-guard
compose up -d candidate-guard

CID=$(compose ps -q candidate-guard)
[ -n "$CID" ] || fail "candidate container id is missing"
wait_healthy "$CID"

docker inspect "$CID" | jq -e '
  .[0]
  | .Config.Labels["com.jydn.chengwang.component"] == "m2b-candidate-guard"
  and .HostConfig.RestartPolicy.Name == "no"
  and .HostConfig.Init == true
  and .Config.StopSignal == "SIGTERM"
  and (.HostConfig.Devices | length) == 0
  and (.NetworkSettings.Networks | length) == 1
  and ([.Mounts[] | select(.Type == "bind") | .Destination] | sort == ["/run/chengwang-probe/catalog.json","/var/lib/chengwang-probe"])
  and ([.Mounts[] | select(.Type != "bind" and .Type != "tmpfs")] | length) == 0
  and ([.HostConfig.Tmpfs | keys[]] | sort == ["/run/m2b","/tmp"])
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("size=1m"))
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("mode=0700"))
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("uid=10001"))
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("gid=10001"))
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("nosuid"))
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("nodev"))
  and (.HostConfig.Tmpfs["/run/m2b"] | contains("noexec"))
  and (.HostConfig.Tmpfs["/tmp"] | contains("size=4m"))
  and (.HostConfig.Tmpfs["/tmp"] | contains("mode=1777"))
  and (.HostConfig.Tmpfs["/tmp"] | contains("nosuid"))
  and (.HostConfig.Tmpfs["/tmp"] | contains("nodev"))
  and (.HostConfig.Tmpfs["/tmp"] | contains("noexec"))
' >/dev/null || fail "container envelope contains an unexpected label, lifecycle, device, network, or mount"

[ "$(docker inspect --format '{{.Config.User}}' "$CID")" = '10001:10001' ] || fail "configured user is not 10001:10001"
[ "$(docker exec "$CID" id -u)" = '10001' ] || fail "runtime user is not uid 10001"
[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CID")" = true ] || fail "root filesystem is not read-only"
[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$CID")" = false ] || fail "container is privileged"
[ "$(docker inspect --format '{{.HostConfig.PidMode}}' "$CID")" != host ] || fail "host PID namespace is forbidden"
[ "$(docker inspect --format '{{.HostConfig.IpcMode}}' "$CID")" != host ] || fail "host IPC namespace is forbidden"
[ "$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$CID")" = '64' ] || fail "PID limit differs from 64"
[ "$(docker inspect --format '{{.HostConfig.Memory}}' "$CID")" = '67108864' ] || fail "memory limit differs from 64 MiB"
[ "$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$CID")" = '250000000' ] || fail "CPU limit differs from 0.25"
[ "$(docker inspect --format '{{range .HostConfig.Ulimits}}{{if eq .Name "nofile"}}{{.Soft}}:{{.Hard}}{{end}}{{end}}' "$CID")" = '256:256' ] || fail "nofile limit differs from 256:256"
docker inspect --format '{{range .HostConfig.CapDrop}}{{println .}}{{end}}' "$CID" | grep -qx ALL || fail "ALL capabilities were not dropped"
docker inspect --format '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}' "$CID" | grep -qx 'no-new-privileges:true' || fail "no-new-privileges is missing"
[ -z "$(docker port "$CID")" ] || fail "candidate unexpectedly publishes a port"
docker inspect --format '{{range .Mounts}}{{println .Destination .RW}}{{end}}' "$CID" | grep -qx '/run/chengwang-probe/catalog.json false' || fail "catalog mount is not read-only"
docker inspect --format '{{range .Mounts}}{{println .Destination .RW}}{{end}}' "$CID" | grep -qx '/var/lib/chengwang-probe true' || fail "spool mount is not independently writable"
SPOOL_SOURCE=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/chengwang-probe"}}{{.Source}}{{end}}{{end}}' "$CID")
[ -n "$SPOOL_SOURCE" ] || fail "candidate spool source is missing"
SPOOL_SOURCE=$(realpath "$SPOOL_SOURCE")
[ "$SPOOL_SOURCE" = "$REQUESTED_SPOOL" ] || fail "runtime spool source differs from the approved spool"
candidate_assert_same_mount "$CANDIDATE_ROOT" "$SPOOL_SOURCE"
case "$SPOOL_SOURCE" in
  "$CANDIDATE_ROOT"/*) ;;
  *) fail "candidate spool escaped the approved root: $SPOOL_SOURCE" ;;
esac
[ "$SPOOL_SOURCE" != /opt/chengwang/data ] || fail "production control data is forbidden"
[ "$(stat -c %u "$SPOOL_SOURCE")" = 10001 ] || fail "candidate spool host owner is not uid 10001"
if docker inspect --format '{{range .Mounts}}{{println .Destination}}{{end}}' "$CID" | grep -qx '/var/run/docker.sock'; then
  fail "Docker socket must not be mounted"
fi

NETWORK_ID=$(docker inspect --format '{{range $name, $network := .NetworkSettings.Networks}}{{$network.NetworkID}}{{end}}' "$CID")
[ -n "$NETWORK_ID" ] || fail "candidate network id is missing"
[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_ID")" = true ] || fail "candidate bridge is not internal"
[ "$(docker network inspect --format '{{.Attachable}}' "$NETWORK_ID")" = false ] || fail "candidate bridge must not be attachable"
[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.enable_icc"}}' "$NETWORK_ID")" = false ] || fail "candidate bridge ICC is not disabled"

if docker exec "$CID" sh -c 'touch /rootfs-must-remain-read-only' >/dev/null 2>&1; then
  fail "read-only root filesystem accepted a write"
fi
if docker exec "$CID" sh -c 'printf x >>/run/chengwang-probe/catalog.json' >/dev/null 2>&1; then
  fail "read-only catalog accepted a write"
fi
RUN_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
SENTINEL=/var/lib/chengwang-probe/.acceptance-$RUN_ID
cleanup_sentinel() {
  [ -z "${SENTINEL:-}" ] || docker exec "$CID" rm -f -- "$SENTINEL" >/dev/null 2>&1 || true
}
trap cleanup_sentinel EXIT HUP INT TERM
docker exec "$CID" sh -ec 'set -C; printf candidate-persistence >"$1"' sh "$SENTINEL"
docker exec "$CID" /app/m2b-candidate-guard health --health-file /run/m2b/health.json --max-age 20s

compose stop -t 20 candidate-guard
docker logs "$CID" 2>&1 | grep -q 'M2b candidate guard shutdown complete' || fail "graceful shutdown evidence is missing"
compose up -d candidate-guard
CID=$(compose ps -q candidate-guard)
wait_healthy "$CID"
[ "$(docker exec "$CID" cat "$SENTINEL")" = candidate-persistence ] || fail "candidate spool did not persist across restart"
docker exec "$CID" rm -- "$SENTINEL"
SENTINEL=
trap - EXIT HUP INT TERM

printf '%s\n' 'CANDIDATE_GUARD=PASS'
printf '%s\n' 'ACTIVE_PROBE_EXECUTION=BLOCKED_SEPARATE_PROFILE_EGRESS_AND_RUNTIME_UNPROVEN'
printf '%s\n' 'FIXED_TRUSTED_RESOLVER=IMPLEMENTED_LOCAL_ONLY_RUNTIME_NOT_PROVEN'
printf '%s\n' 'UNIQUE_EGRESS_ENFORCEMENT=BLOCKED_NOT_PROVEN'
