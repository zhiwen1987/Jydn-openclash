#!/bin/sh
set -eu

fail() {
  printf '%s\n' "probe-agent startup blocked: $*" >&2
  exit 78
}

[ "$#" -gt 0 ] && [ "$1" = /app/probe-agent ] || fail "unexpected command"
[ "${M2B_PROBE_ACTIVE_APPROVAL:-}" = approved-candidate-only ] || fail "explicit candidate approval is missing"

catalog=/run/chengwang-probe/catalog.json
dot_ca=/run/chengwang-probe/dot-ca.pem
egress_policy=/run/chengwang-probe/egress-policy.json
for candidate_file in "$catalog" "$dot_ca" "$egress_policy"; do
  [ -f "$candidate_file" ] && [ ! -L "$candidate_file" ] || fail "required read-only file is missing or unsafe: $candidate_file"
done

valid_hash() {
  printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{64}$'
}

verify_hash() {
  expected=$1
  file=$2
  valid_hash "$expected" || fail "expected SHA-256 is not 64 lowercase hex for $file"
  actual=$(sha256sum "$file" | awk '{print $1}')
  [ "$actual" = "$expected" ] || fail "SHA-256 mismatch for $file"
}

verify_hash "${M2B_PROBE_EXPECTED_CATALOG_SHA256:-}" "$catalog"
verify_hash "${M2B_PROBE_EXPECTED_DOT_CA_SHA256:-}" "$dot_ca"
verify_hash "${M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256:-}" "$egress_policy"

grep -Eiq 'probe\.invalid|placeholder|replace-with' "$catalog" && fail "catalog contains a blocked placeholder"
grep -Eq -e '-----BEGIN CERTIFICATE-----' "$dot_ca" || fail "DoT CA bundle has no PEM certificate"
grep -Eiq 'placeholder|replace-with' "$dot_ca" && fail "DoT CA bundle contains a placeholder"
grep -Eq '"status"[[:space:]]*:[[:space:]]*"approved"' "$egress_policy" || fail "egress policy is not approved"
grep -Eq '"state"[[:space:]]*:[[:space:]]*"enforced"' "$egress_policy" || fail "egress policy is not enforced"
grep -Eiq 'unapproved|"state"[[:space:]]*:[[:space:]]*"blocked"|not-collected|placeholder|replace-with' "$egress_policy" \
  && fail "egress policy contains a blocked or unproven state"

case "${M2B_PROBE_DOT_UPSTREAM:-}" in
  192.0.2.*|198.51.100.*|203.0.113.*|2001:db8:*|'') fail "DoT upstream is absent or uses a documentation placeholder" ;;
  \[2001:db8:*) fail "DoT upstream uses an IPv6 documentation placeholder" ;;
  *:853) ;;
  *) fail "DoT upstream is malformed or not on TCP 853" ;;
esac
case "${M2B_PROBE_DOT_SERVER_NAME:-}" in
  ''|*.invalid|*placeholder*|*replace-with*) fail "DoT server name is absent or placeholder" ;;
esac

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
exec "$@"
