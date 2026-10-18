#!/bin/sh
# Read-only evidence capture for the control plane surrounding an M2b candidate.
# The output contains hashes only. Temporary raw Controller/UCI data is removed.
set -eu

umask 077

fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  fail "usage: $0 OUTPUT OPENCLASH_ACTIVE_CONFIG CONTROL_COMPOSE [CONTROL_CONTAINER]"
fi

OUTPUT=$1
OPENCLASH_ACTIVE_CONFIG=$2
CONTROL_COMPOSE=$3
CONTROL_CONTAINER=${4:-chengwang}

case "$OUTPUT" in
  /*) ;;
  *) fail "OUTPUT must be an absolute path" ;;
esac
[ ! -e "$OUTPUT" ] || fail "refusing to overwrite existing evidence: $OUTPUT"
[ -f "$OPENCLASH_ACTIVE_CONFIG" ] && [ ! -L "$OPENCLASH_ACTIVE_CONFIG" ] || fail "active OpenClash config must be a regular non-symlink file"
[ -f "$CONTROL_COMPOSE" ] && [ ! -L "$CONTROL_COMPOSE" ] || fail "control compose must be a regular non-symlink file"

for command_name in awk curl docker grep jq mktemp sha256sum uci; do
  require_command "$command_name"
done

MIHOMO_BASE_URL=${M2B_MIHOMO_URL:-http://127.0.0.1:9090}
if ! printf '%s\n' "$MIHOMO_BASE_URL" | grep -Eq '^(https://[A-Za-z0-9.-]+(:[0-9]{1,5})?|http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?)$'; then
  fail "Controller URL must be remote HTTPS or loopback HTTP, without a path or query"
fi
case "${M2B_MIHOMO_TOKEN:-}" in
  *[!A-Za-z0-9._~-]*) fail "Controller token contains a character unsafe for curl config input" ;;
esac

TMPDIR_PRIVATE=$(mktemp -d)
cleanup() {
  rm -rf "$TMPDIR_PRIVATE"
}
trap cleanup EXIT HUP INT TERM

uci -q export openclash >"$TMPDIR_PRIVATE/openclash.uci" || fail "cannot export OpenClash UCI state"
uci -q export dhcp >"$TMPDIR_PRIVATE/dhcp.uci" || fail "cannot export DNS/DHCP UCI state"

{
  printf '%s\n' 'silent' 'show-error' 'fail' 'connect-timeout = 5' 'max-time = 15'
  printf 'url = "%s/proxies"\n' "${MIHOMO_BASE_URL%/}"
  if [ -n "${M2B_MIHOMO_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$M2B_MIHOMO_TOKEN"
  fi
} | curl --config - --output "$TMPDIR_PRIVATE/proxies.json" || fail "cannot read Mihomo selector state"

jq -ceS '
  [.proxies | to_entries[]
    | select(.value.type == "Selector")
    | {name: .key, now: .value.now}]
  | sort_by(.name)
' "$TMPDIR_PRIVATE/proxies.json" >"$TMPDIR_PRIVATE/selectors.json" || fail "cannot canonicalize selector state"

docker inspect --format '{{.Id}}|{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.RestartCount}}|{{.State.Status}}|{{.State.Health.Status}}' "$CONTROL_CONTAINER" >"$TMPDIR_PRIVATE/control.runtime" || fail "cannot inspect control container"

OUTPUT_DIR=$(dirname "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
TEMP_OUTPUT="$OUTPUT.tmp.$$"
{
  printf 'schema=%s\n' 'chengwang.m2b-unchanged-evidence/v1'
  printf 'openclash_active_config_path_sha256=%s\n' "$(printf '%s' "$OPENCLASH_ACTIVE_CONFIG" | sha256sum | awk '{print $1}')"
  printf 'openclash_active_config_sha256=%s\n' "$(hash_file "$OPENCLASH_ACTIVE_CONFIG")"
  printf 'openclash_uci_sha256=%s\n' "$(hash_file "$TMPDIR_PRIVATE/openclash.uci")"
  printf 'dns_dhcp_uci_sha256=%s\n' "$(hash_file "$TMPDIR_PRIVATE/dhcp.uci")"
  printf 'dns_resolv_conf_sha256=%s\n' "$(hash_file /etc/resolv.conf)"
  printf 'selector_state_sha256=%s\n' "$(hash_file "$TMPDIR_PRIVATE/selectors.json")"
  printf 'control_compose_sha256=%s\n' "$(hash_file "$CONTROL_COMPOSE")"
  printf 'control_runtime_sha256=%s\n' "$(hash_file "$TMPDIR_PRIVATE/control.runtime")"
} >"$TEMP_OUTPUT"
chmod 600 "$TEMP_OUTPUT"
mv "$TEMP_OUTPUT" "$OUTPUT"
printf '%s\n' "baseline captured: $OUTPUT"
