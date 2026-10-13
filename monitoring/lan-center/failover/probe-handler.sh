#!/bin/sh
# Minimal Docker-network-only HTTP service for Uptime Kuma and its local alert sink.
set -u

: "${ALERT_WEBHOOK_URL:=}"

read -r request_line || exit 0
request_line="$(printf '%s' "$request_line" | tr -d '\r')"
method="$(printf '%s' "$request_line" | awk '{print $1}')"
path="$(printf '%s' "$request_line" | awk '{print $2}' | cut -d'?' -f1)"
content_length=0
while IFS= read -r header; do
  header="$(printf '%s' "$header" | tr -d '\r')"
  [ -z "$header" ] && break
  case "$header" in
    [Cc]ontent-[Ll]ength:*) content_length="$(printf '%s' "$header" | cut -d: -f2- | tr -d ' ')" ;;
  esac
done

body=''
case "$content_length" in ''|*[!0-9]*) content_length=0 ;; esac
if [ "$content_length" -gt 0 ] && [ "$content_length" -le 65536 ]; then
  body="$(dd bs=1 count="$content_length" 2>/dev/null)"
fi

respond() {
  code="$1"
  reason="$2"
  payload="$3"
  length="$(printf '%s' "$payload" | wc -c | tr -d ' ')"
  printf 'HTTP/1.1 %s %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
    "$code" "$reason" "$length" "$payload"
}

probe_via_proxy() {
  probe_url="$1"
  expected="$2"
  attempt=1
  while [ "$attempt" -le 2 ]; do
    code="$(curl -sS --max-time 7 -o /dev/null -w '%{http_code}' \
      -x "${PROXY:-http://10.88.0.254:7893}" -U "${PROXY_AUTH:-}" \
      -H 'User-Agent: Mozilla/5.0' "$probe_url" 2>/dev/null)" || code='000'
    [ "$code" = "$expected" ] && return 0
    attempt=$((attempt + 1))
  done
  return 1
}

probe_chatgpt_post() {
  result="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}|%{content_type}' \
    -x "${PROXY:-http://10.88.0.254:7893}" -U "${PROXY_AUTH:-}" \
    -X POST -H 'Content-Type: application/json' -H 'User-Agent: Mozilla/5.0' \
    -d '{}' 'https://chatgpt.com/backend-api/codex/responses' 2>/dev/null)" || return 1
  code="${result%%|*}"
  content_type="${result#*|}"
  case "$code" in 400|401) ;; *) return 1 ;; esac
  case "$content_type" in *json*) return 0 ;; *) return 1 ;; esac
}

record_alert() {
  monitor="$(printf '%s' "$body" | jq -r '.monitor.name // "unknown"' 2>/dev/null | tr '\r\n' '  ' | cut -c1-120)"
  message="$(printf '%s' "$body" | jq -r '.msg // "state_changed"' 2>/dev/null | tr '\r\n' '  ' | cut -c1-300)"
  printf '%s monitor=%s message=%s\n' "$(date '+%F %T')" "$monitor" "$message" >> /data/alerts.log
  if [ -n "$ALERT_WEBHOOK_URL" ]; then
    curl -fsS --max-time 10 -H 'Content-Type: application/json' -d "$body" "$ALERT_WEBHOOK_URL" >/dev/null || true
  fi
}

case "$method:$path" in
  GET:/health)
    respond 200 OK '{"status":"ok"}'
    ;;
  GET:/probe/chatgpt)
    if probe_chatgpt_post; then
      respond 204 'No Content' ''
    else
      respond 503 'Service Unavailable' '{"status":"down","probe":"chatgpt"}'
    fi
    ;;
  GET:/probe/gemini)
    if probe_via_proxy "https://generativelanguage.googleapis.com/\$discovery/rest?version=v1beta" 200; then
      respond 204 'No Content' ''
    else
      respond 503 'Service Unavailable' '{"status":"down","probe":"gemini"}'
    fi
    ;;
  GET:/probe/google)
    if probe_via_proxy 'https://www.gstatic.com/generate_204' 204; then
      respond 204 'No Content' ''
    else
      respond 503 'Service Unavailable' '{"status":"down","probe":"google"}'
    fi
    ;;
  POST:/alert)
    record_alert
    respond 204 'No Content' ''
    ;;
  *)
    respond 404 'Not Found' '{"status":"not_found"}'
    ;;
esac
