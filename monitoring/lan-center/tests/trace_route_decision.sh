#!/bin/sh
# Read-only acceptance check for live OpenClash rule decisions.
set -eu

: "${OPENCLASH_API:=http://10.88.0.254:9090}"
: "${OPENCLASH_SECRET:?missing OPENCLASH_SECRET}"
: "${PROXY:=http://10.88.0.254:7893}"
: "${PROXY_AUTH:?missing PROXY_AUTH}"

trace_one() {
  label="$1"
  host="$2"
  url="$3"
  output="/tmp/route-trace-$$-$label"
  curl -sS --max-time 12 --limit-rate 64 -H 'Accept-Encoding: identity' \
    -x "$PROXY" -U "$PROXY_AUTH" -o /dev/null "$url" >/dev/null 2>&1 &
  curl_pid=$!
  sleep 2
  curl -fsS -H "Authorization: Bearer $OPENCLASH_SECRET" \
    "$OPENCLASH_API/connections" \
    | jq -c --arg host "$host" \
      '[.connections[] | select(.metadata.host == $host) | {chains,rule,rulePayload}]' \
      > "$output"
  kill "$curl_pid" 2>/dev/null || true
  wait "$curl_pid" 2>/dev/null || true
  count="$(jq 'length' "$output")"
  direct="$(jq '[.[] | select(.chains | index("DIRECT"))] | length' "$output")"
  rm -f "$output"
  printf '%s_CONNECTIONS=%s DIRECT=%s\n' "$label" "$count" "$direct"
  [ "$count" -ge 1 ] && [ "$direct" -eq "$count" ]
}

trace_one AMD_CN developer.amd.com.cn https://developer.amd.com.cn/radeon/tokenfactory
trace_one TUYA_CN www.tuya.com https://www.tuya.com/cn/
