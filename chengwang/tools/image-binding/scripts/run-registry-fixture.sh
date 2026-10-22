#!/usr/bin/env bash
# Real Distribution Registry compatibility only. Never executes a product image.
set -euo pipefail
umask 077
if (( $# != 3 )); then
  echo 'usage: run-registry-fixture.sh ABSOLUTE_RUN_DIRECTORY GO_BINARY MODULE_CACHE' >&2
  exit 2
fi
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
module_root=$(/usr/bin/realpath -e -- "$script_root/..")
source_root=$(/usr/bin/realpath -e -- "$(/usr/bin/git -C "$module_root" rev-parse --show-toplevel)")
runner_uid=$(/usr/bin/id -u)
runner_gid=$(/usr/bin/id -g)
test "$runner_uid" != 0
test "$("$go_binary" env GOVERSION)" = go1.25.8
case "$run_root/" in "$source_root/"*) echo 'run directory must be outside source' >&2; exit 2;; esac
test -x "$run_root/bin/registrycli.test"
test -x "$run_root/bin/registrycli-race.test"
registry_image=registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
test "${REGISTRY_FIXTURE_IMAGE:-$registry_image}" = "$registry_image"
test "$(/usr/bin/docker image inspect --format '{{.Os}}/{{.Architecture}}' "$registry_image")" = linux/amd64
expected_image_id=$(/usr/bin/docker image inspect --format '{{.Id}}' "$registry_image")
fixture_id="cw-imgbind-$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')"
network_name="$fixture_id-net"
container_name="$fixture_id-registry"
label_key=org.chengwang.image-binding-fixture
network_id=
container_id=
tls_root="$run_root/registry-tls"
cleanup() {
  original_status=$?
  trap - EXIT
  cleanup_failed=0
  if /usr/bin/docker container inspect "$container_name" >/dev/null 2>&1; then
    if test "$(/usr/bin/docker container inspect --format '{{ index .Config.Labels "org.chengwang.image-binding-fixture" }}' "$container_name")" = "$fixture_id"; then
      /usr/bin/docker logs "$container_name" > "$run_root/evidence/registry-service.log" 2>&1 || cleanup_failed=1
      /usr/bin/docker container rm --force "$container_name" >/dev/null || cleanup_failed=1
    else
      echo 'Refusing to remove container without the exact fixture ownership label' >&2
      cleanup_failed=1
    fi
  fi
  if /usr/bin/docker network inspect "$network_name" >/dev/null 2>&1; then
    if test "$(/usr/bin/docker network inspect --format '{{ index .Labels "org.chengwang.image-binding-fixture" }}' "$network_name")" = "$fixture_id"; then
      /usr/bin/docker network rm "$network_name" >/dev/null || cleanup_failed=1
    else
      echo 'Refusing to remove network without the exact fixture ownership label' >&2
      cleanup_failed=1
    fi
  fi
  if /usr/bin/docker container inspect "$container_name" >/dev/null 2>&1 || /usr/bin/docker network inspect "$network_name" >/dev/null 2>&1; then
    cleanup_failed=1
  fi
  # Remove only the ephemeral keys created at these exact run-owned paths.
  /usr/bin/rm -f -- "$tls_root/ca-key.pem" "$tls_root/server-key.pem" || cleanup_failed=1
  if (( cleanup_failed != 0 )); then
    echo 'REGISTRY_FIXTURE_CLEANUP=FAIL' >&2
    exit 1
  fi
  echo 'REGISTRY_FIXTURE_CLEANUP=PASS only_owned_objects=true ephemeral_private_keys_removed=true'
  exit "$original_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/install -d -m 0700 "$tls_root" "$run_root/evidence"
/usr/bin/openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj /CN=Chengwang-Registry-CI-Only-CA \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$tls_root/ca-key.pem" -out "$tls_root/ca.pem" >/dev/null 2>&1
/usr/bin/openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -subj /CN=registry.fixture.invalid \
  -keyout "$tls_root/server-key.pem" -out "$tls_root/server.csr" >/dev/null 2>&1
/usr/bin/openssl x509 -req -sha256 -days 1 -in "$tls_root/server.csr" \
  -CA "$tls_root/ca.pem" -CAkey "$tls_root/ca-key.pem" -CAcreateserial \
  -extfile "$script_root/registry-server-ext.cnf" -out "$tls_root/server.pem" >/dev/null 2>&1
# File mounts expose only the fixture server certificate/key, not the CA key.
/usr/bin/chmod 0444 "$tls_root/server.pem" "$tls_root/server-key.pem"
network_id=$(/usr/bin/docker network create --internal --driver bridge --label "$label_key=$fixture_id" "$network_name")
container_id=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
  --name "$container_name" --label "$label_key=$fixture_id" \
  --network "$network_name" --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 256m --cpus 1 --restart no \
  --tmpfs /var/lib/registry:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700 \
  --mount "type=bind,src=$script_root/distribution-config.yml,dst=/etc/distribution/config.yml,readonly" \
  --mount "type=bind,src=$tls_root/server.pem,dst=/certs/server.pem,readonly" \
  --mount "type=bind,src=$tls_root/server-key.pem,dst=/certs/server-key.pem,readonly" \
  --env OTEL_TRACES_EXPORTER=none --env OTEL_METRICS_EXPORTER=none --env OTEL_LOGS_EXPORTER=none \
  "$registry_image")
/usr/bin/docker container start "$container_id" >/dev/null
/usr/bin/docker network inspect "$network_id" > "$run_root/evidence/registry-network.json"
/usr/bin/docker container inspect "$container_id" \
  | /usr/bin/python3 -B "$script_root/check-registry-fixture.py" \
      "$run_root/evidence/registry-network.json" "$fixture_id" "$network_name" "$network_id" "$expected_image_id" \
  | /usr/bin/tee "$run_root/evidence/registry-fixture-security.json"
registry_pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$container_id")
test "$registry_pid" -gt 1
parent_mountns=$(/usr/bin/readlink /proc/self/ns/mnt)
parent_netns=$(/usr/bin/readlink /proc/self/ns/net)
ready=false
for attempt in {1..30}; do
  if /usr/bin/sudo --non-interactive /usr/bin/nsenter --target "$registry_pid" --net -- \
    /usr/bin/curl --silent --show-error --fail --connect-timeout 1 --max-time 2 \
      --proxy '' --noproxy '*' --cacert "$tls_root/ca.pem" \
      --resolve registry.fixture.invalid:5443:127.0.0.1 https://registry.fixture.invalid:5443/v2/ >/dev/null 2>&1; then
    ready=true
    break
  fi
  test "$(/usr/bin/docker container inspect --format '{{.State.Running}}' "$container_id")" = true
  /usr/bin/sleep 1
done
test "$ready" = true
for mode in ordinary race; do
  binary="$run_root/bin/registrycli.test"
  if test "$mode" = race; then binary="$run_root/bin/registrycli-race.test"; fi
  /usr/bin/sudo --non-interactive /usr/bin/nsenter --target "$registry_pid" --net -- \
    /usr/bin/unshare --mount -- /usr/bin/bash -c '
      set -euo pipefail
      /usr/bin/mount --make-rprivate /
      /usr/bin/mount --bind "$9" "$9"
      /usr/bin/mount -o remount,bind,ro "$9"
      /usr/bin/mount --bind "$5" "$5"
      /usr/bin/mount -o remount,bind,ro "$5"
      exec /usr/bin/setpriv \
        --reuid="$1" --regid="$2" --clear-groups \
        --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
        /usr/bin/env -i \
          HOME="$4/home" TMPDIR="$4/tmp" GOTMPDIR="$4/go-tmp" GOCACHE="$4/build-cache" \
          GOMODCACHE="$5" GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
          GOPROXY=off GOSUMDB=off CGO_ENABLED=1 GOMEMLIMIT=2GiB \
          PATH="$(/usr/bin/dirname -- "$6"):/usr/bin:/bin" \
          LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
          MODULE_ROOT="$3" RUN_ROOT="$4" GO_BINARY="$6" \
          PARENT_NETNS="$7" PARENT_MOUNTNS="$8" TEST_BINARY="${10}" TEST_MODE="${11}" \
          REGISTRYCLI_ENDPOINT=https://registry.fixture.invalid:5443 REGISTRYCLI_IP=127.0.0.1 \
          REGISTRYCLI_CA_FILE="$4/registry-tls/ca.pem" \
          REGISTRYCLI_SERVER_CERT_FILE="$4/registry-tls/server.pem" \
          /usr/bin/bash --noprofile --norc "$3/scripts/run-registry-gate.sh"
    ' chengwang-registry-binding "$runner_uid" "$runner_gid" "$module_root" "$run_root" "$module_cache" \
      "$go_binary" "$parent_netns" "$parent_mountns" "$source_root" "$binary" "$mode" \
    2>&1 | /usr/bin/tee "$run_root/evidence/registry-$mode.log"
done
/usr/bin/python3 -B "$script_root/check-go-json.py" --mode registry \
  "$run_root/evidence/registry-ordinary.json" "$run_root/evidence/registry-race.json"
for mode in ordinary race; do
  for kind in message-signature dsse; do
    marker="MANAGED_REAL_DISTRIBUTION=PASS kind=$kind replay=rejected reopen=true"
    # Check the actual per-kind test Output events, not a generic shell echo
    # or a fixture server log. Both ordinary and race must attest separately.
    /usr/bin/python3 -B - "$run_root/evidence/registry-$mode.json" "$kind" "$marker" <<'PY'
import json
import pathlib
import sys
path, kind, marker = sys.argv[1:]
events = [json.loads(line) for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines()]
matches = [event for event in events
           if event.get("Package") == "chengwang/image-binding"
           and event.get("Action") == "output"
           and event.get("Test") == "TestRegistryCLIBindingLifecycle/" + kind
           and event.get("Output", "").strip() == marker]
if len(matches) != 1:
    raise SystemExit("missing or duplicate per-kind managed Registry lifecycle evidence")
print("REGISTRY_MANAGED_LIFECYCLE_EVIDENCE=PASS kind=" + kind)
PY
  done
done
echo 'REGISTRY_BINDING_REAL_DISTRIBUTION=PASS transcripts=2 registry=3 image_pinned=true tls=true internal_network=true no_host_ports=true product_images_executed=0 authorization=BLOCKED production=false'
