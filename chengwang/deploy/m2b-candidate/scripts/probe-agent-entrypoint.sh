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

/app/probe-agent preflight \
  --catalog "$catalog" \
  --dot-ca "$dot_ca" \
  --egress-policy "$egress_policy" \
  --dot-upstream "${M2B_PROBE_DOT_UPSTREAM:-}" \
  --dot-server-name "${M2B_PROBE_DOT_SERVER_NAME:-}" \
  --expected-catalog-sha256 "${M2B_PROBE_EXPECTED_CATALOG_SHA256:-}" \
  --expected-dot-ca-sha256 "${M2B_PROBE_EXPECTED_DOT_CA_SHA256:-}" \
  --expected-egress-policy-sha256 "${M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256:-}" \
  || fail "structured desired-contract preflight failed"

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
exec "$@"
