#!/bin/sh
# Compare two hash-only evidence manifests. Any changed or missing key fails.
set -eu

fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

[ "$#" -eq 2 ] || fail "usage: $0 BEFORE AFTER"
BEFORE=$1
AFTER=$2
[ -f "$BEFORE" ] && [ ! -L "$BEFORE" ] || fail "BEFORE must be a regular non-symlink file"
[ -f "$AFTER" ] && [ ! -L "$AFTER" ] || fail "AFTER must be a regular non-symlink file"

EXPECTED_KEYS='schema
openclash_active_config_path_sha256
openclash_active_config_sha256
openclash_uci_sha256
dns_dhcp_uci_sha256
dns_resolv_conf_sha256
selector_state_sha256
control_compose_sha256
control_runtime_sha256'

validate_manifest() {
  manifest=$1
  for key in $EXPECTED_KEYS; do
    count=$(awk -F= -v wanted="$key" '$1 == wanted {count++} END {print count+0}' "$manifest")
    [ "$count" -eq 1 ] || fail "$manifest must contain exactly one $key"
  done
  count=$(awk -F= 'NF != 2 || $1 !~ /^[a-z0-9_]+$/ || ($1 != "schema" && $2 !~ /^[0-9a-f]{64}$/) {bad++} END {print bad+0}' "$manifest")
  [ "$count" -eq 0 ] || fail "$manifest contains malformed entries"
  count=$(wc -l <"$manifest" | tr -d ' ')
  [ "$count" -eq 9 ] || fail "$manifest contains an unexpected key"
  grep -qx 'schema=chengwang.m2b-unchanged-evidence/v1' "$manifest" || fail "$manifest has the wrong schema"
}

validate_manifest "$BEFORE"
validate_manifest "$AFTER"

if ! cmp -s "$BEFORE" "$AFTER"; then
  printf '%s\n' 'UNCHANGED_GATE=FAIL'
  diff -u "$BEFORE" "$AFTER" || true
  exit 1
fi
printf '%s\n' 'UNCHANGED_GATE=PASS'
