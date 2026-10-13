#!/bin/sh
# Production smoke test: switch only the isolated probe group and restore it.
set -eu

: "${OPENCLASH_API:=http://10.88.0.254:9090}"
: "${OPENCLASH_SECRET:?missing OPENCLASH_SECRET}"
: "${CAPABILITY_PROXY:=http://10.88.0.254:7895}"
: "${CAPABILITY_PROXY_AUTH:?missing CAPABILITY_PROXY_AUTH}"
: "${CAPABILITY_SMOKE_MAX_NODES:=15}"

group='%F0%9F%A7%AA%20%E8%8A%82%E7%82%B9%E8%83%BD%E5%8A%9B%E6%A3%80%E6%B5%8B'
api="$OPENCLASH_API/proxies/$group"
auth="Authorization: Bearer $OPENCLASH_SECRET"

cleanup() {
  [ -n "${previous:-}" ] || return 0
  body="$(jq -nc --arg name "$previous" '{name:$name}')"
  curl -fsS -X PUT -H "$auth" -H 'Content-Type: application/json' \
    -d "$body" "$api" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

data="$(curl -fsS -H "$auth" "$api")"
previous="$(printf '%s' "$data" | jq -r '.now')"
attempt=0
success=0
for token in $(printf '%s' "$data" | jq -r '.all[] | select(. != "REJECT") | @base64'); do
  attempt=$((attempt + 1))
  [ "$attempt" -le "$CAPABILITY_SMOKE_MAX_NODES" ] || break
  node="$(printf '%s' "$token" | base64 -d)"
  body="$(jq -nc --arg name "$node" '{name:$name}')"
  curl -fsS -X PUT -H "$auth" -H 'Content-Type: application/json' \
    -d "$body" "$api" >/dev/null
  code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' \
    -x "$CAPABILITY_PROXY" -U "$CAPABILITY_PROXY_AUTH" \
    https://www.gstatic.com/generate_204 || true)"
  if [ "$code" = 204 ]; then
    success=1
    break
  fi
done
printf 'ISOLATED_LISTENER_HTTP=%s ATTEMPTS=%s\n' "${code:-000}" "$attempt"
[ "$success" = 1 ]
