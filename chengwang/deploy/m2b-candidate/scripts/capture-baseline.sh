#!/bin/sh
# Read-only evidence capture for the control plane surrounding an M2b candidate.
# The output contains hashes only. Temporary raw Controller/UCI data is removed.
set -efu

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

reject_symlink_components() (
  checked_path=$1
  case "$checked_path" in /*) ;; *) fail "path must be absolute: $checked_path" ;; esac
  old_ifs=$IFS
  IFS=/
  set -- ${checked_path#/}
  IFS=$old_ifs
  checked_component=
  for component in "$@"; do
    [ -n "$component" ] || continue
    checked_component=$checked_component/$component
    [ ! -L "$checked_component" ] || fail "symlink path component is forbidden: $checked_component"
  done
)

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
[ ! -L "$OUTPUT" ] || fail "refusing dangling/symlink evidence output: $OUTPUT"
[ -f "$OPENCLASH_ACTIVE_CONFIG" ] && [ ! -L "$OPENCLASH_ACTIVE_CONFIG" ] || fail "active OpenClash config must be a regular non-symlink file"
[ -f "$CONTROL_COMPOSE" ] && [ ! -L "$CONTROL_COMPOSE" ] || fail "control compose must be a regular non-symlink file"

for command_name in awk curl docker grep id jq ln mktemp realpath sha256sum stat sync uci; do
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

OUTPUT_DIR=$(dirname -- "$OUTPUT")
EVIDENCE_ROOT=${M2B_EVIDENCE_ROOT:-/root/m2b-evidence}
case "$EVIDENCE_ROOT" in /*) ;; *) fail "M2B_EVIDENCE_ROOT must be absolute" ;; esac
[ -d "$EVIDENCE_ROOT" ] && [ ! -L "$EVIDENCE_ROOT" ] || fail "evidence root must already be a real directory"
reject_symlink_components "$EVIDENCE_ROOT"
EVIDENCE_ROOT=$(realpath "$EVIDENCE_ROOT")
reject_symlink_components "$OUTPUT_DIR"
OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
[ "$OUTPUT_DIR" = "$EVIDENCE_ROOT" ] || fail "OUTPUT must be a direct child of M2B_EVIDENCE_ROOT"
[ "$(stat -c %u "$OUTPUT_DIR")" = "$(id -u)" ] || fail "evidence root must be owned by the effective user"
[ "$(stat -c %a "$OUTPUT_DIR")" = 700 ] || fail "evidence root mode must be 0700"
TEMP_OUTPUT=$(mktemp "$OUTPUT_DIR/.m2b-baseline.XXXXXX")
cleanup_output() {
  [ -z "${TEMP_OUTPUT:-}" ] || rm -f -- "$TEMP_OUTPUT" || true
}
trap 'cleanup_output; cleanup' EXIT HUP INT TERM
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
sync
ln -T -- "$TEMP_OUTPUT" "$OUTPUT" || fail "refusing to replace a concurrently created evidence path"
rm -f -- "$TEMP_OUTPUT"
TEMP_OUTPUT=
[ -f "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || fail "published evidence is not a regular file"
[ "$(stat -c %a "$OUTPUT")" = 600 ] && [ "$(stat -c %h "$OUTPUT")" = 1 ] || fail "published evidence has unsafe mode or link count"
sync
printf '%s\n' "baseline captured: $OUTPUT"
