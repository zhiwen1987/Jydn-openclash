#!/bin/sh
# Select a ChatGPT-capable node without exposing node names or controller secrets.
set -u

: "${OPENCLASH_API:=http://10.88.0.254:9090}"
: "${CHATGPT_CONTROL_INTERVAL:=300}"
: "${CHATGPT_PARALLEL:=6}"
: "${CHATGPT_TIMEOUT_MS:=8000}"
: "${OPENCLASH_SECRET:=}"

POOL='%F0%9F%A4%96%20ChatGPT%20%E4%B8%93%E7%94%A8%E8%8A%82%E7%82%B9%E6%B1%A0'
BUSINESS='%F0%9F%A4%96%20%E5%AF%B9%E8%AF%9D%E5%8A%A9%E6%89%8B%EF%BC%88ChatGPT%EF%BC%89'
FALLBACK='🧠 人工智能'
POOL_NAME='🤖 ChatGPT 专用节点池'
PROBE_URL='https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fsession'
LOG=/data/chatgpt-controller.log
HEALTH=/data/chatgpt-controller.health

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

api_get() {
  curl -fsS --max-time 12 -H "Authorization: Bearer $OPENCLASH_SECRET" "$OPENCLASH_API$1"
}

api_select() {
  path="$1"
  target="$2"
  body="$(jq -nc --arg name "$target" '{name:$name}')"
  curl -fsS --max-time 12 -X PUT -H "Authorization: Bearer $OPENCLASH_SECRET" \
    -H 'Content-Type: application/json' -d "$body" "$OPENCLASH_API/proxies/$path" >/dev/null
}

run_check() {
  [ -n "$OPENCLASH_SECRET" ] || { log 'status=error reason=missing_secret'; echo error > "$HEALTH"; return 1; }
  group="$(api_get "/proxies/$POOL")" || { log 'status=error reason=pool_api'; echo error > "$HEALTH"; return 1; }
  [ "$(echo "$group" | jq -r '.type')" = Selector ] || { log 'status=error reason=pool_not_selector'; echo error > "$HEALTH"; return 1; }

  work="$(mktemp -d /tmp/chatgpt-control.XXXXXX)" || return 1
  results="$work/results"
  : > "$results"
  echo "$group" | jq -r --arg fallback "$FALLBACK" '.all[] | select(. != $fallback) | @base64' \
    | xargs -r -P "$CHATGPT_PARALLEL" -n 1 sh -c '
        work=$1; encoded=$2
        name=$(printf "%s" "$encoded" | base64 -d)
        path=$(jq -rn --arg value "$name" "\$value|@uri")
        answer=$(curl -fsS --max-time 12 -H "Authorization: Bearer $OPENCLASH_SECRET" \
          "$OPENCLASH_API/proxies/$path/delay?url=$PROBE_URL&timeout=$CHATGPT_TIMEOUT_MS" 2>/dev/null) || exit 0
        delay=$(printf "%s" "$answer" | jq -r ".delay // empty")
        case "$delay" in ""|*[!0-9]*) exit 0;; esac
        printf "%09d\t%s\n" "$delay" "$encoded" >> "$work/results"
      ' _ "$work"

  best="$(sort -n "$results" | head -n 1)"
  if [ -n "$best" ]; then
    delay="$(printf '%s\n' "$best" | cut -f 1)"
    encoded="$(printf '%s\n' "$best" | cut -f 2-)"
    node="$(printf '%s' "$encoded" | base64 -d)"
    api_select "$POOL" "$node" || { rm -f "$results"; rmdir "$work"; log 'status=error reason=select_node'; echo error > "$HEALTH"; return 1; }
    hash="$(printf '%s' "$node" | sha256sum | cut -c1-12)"
    delay_display="$(printf '%s' "$delay" | sed 's/^0*//')"
    [ -n "$delay_display" ] || delay_display=0
    log "status=selected working=$(wc -l < "$results") node_hash=$hash delay_ms=$delay_display"
    echo ok > "$HEALTH"
  else
    api_select "$POOL" "$FALLBACK" || { rm -f "$results"; rmdir "$work"; log 'status=error reason=select_fallback'; echo error > "$HEALTH"; return 1; }
    log 'status=fallback working=0 target=ai_parent'
    echo fallback > "$HEALTH"
  fi
  api_select "$BUSINESS" "$POOL_NAME" || { rm -f "$results"; rmdir "$work"; log 'status=error reason=select_business'; echo error > "$HEALTH"; return 1; }
  rm -f "$results"
  rmdir "$work"
}

log "controller_started interval=${CHATGPT_CONTROL_INTERVAL}s parallel=$CHATGPT_PARALLEL"
while true; do
  run_check || true
  sleep "$CHATGPT_CONTROL_INTERVAL"
done
