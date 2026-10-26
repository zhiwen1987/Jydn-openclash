#!/bin/sh
# Minimal Docker-network-only HTTP service for Uptime Kuma and its local alert sink.
set -u

: "${ALERT_WEBHOOK_URL:=}"
: "${BUSINESS_PROBE_ATTEMPTS:=2}"
: "${BUSINESS_PROBE_TIMEOUT:=8}"
: "${BUSINESS_PROBE_BACKOFF:=2}"
: "${BUSINESS_PROBE_LOG:=/data/business-probe.log}"
: "${BUSINESS_PROBE_STATE_DIR:=/data}"
: "${CURL_BIN:=curl}"
: "${CHATGPT_PROBE_ATTEMPTS:=2}"
: "${CHATGPT_PROBE_TIMEOUT:=6}"
: "${CHATGPT_PROBE_BACKOFF:=1}"

case "$BUSINESS_PROBE_ATTEMPTS" in ''|*[!0-9]*) BUSINESS_PROBE_ATTEMPTS=2 ;; esac
case "$BUSINESS_PROBE_TIMEOUT" in ''|*[!0-9]*) BUSINESS_PROBE_TIMEOUT=8 ;; esac
case "$BUSINESS_PROBE_BACKOFF" in ''|*[!0-9]*) BUSINESS_PROBE_BACKOFF=2 ;; esac
[ "$BUSINESS_PROBE_ATTEMPTS" -ge 1 ] && [ "$BUSINESS_PROBE_ATTEMPTS" -le 3 ] || BUSINESS_PROBE_ATTEMPTS=2
[ "$BUSINESS_PROBE_TIMEOUT" -ge 5 ] && [ "$BUSINESS_PROBE_TIMEOUT" -le 15 ] || BUSINESS_PROBE_TIMEOUT=8
[ "$BUSINESS_PROBE_BACKOFF" -le 5 ] || BUSINESS_PROBE_BACKOFF=2
case "$CHATGPT_PROBE_ATTEMPTS" in ''|*[!0-9]*) CHATGPT_PROBE_ATTEMPTS=2 ;; esac
case "$CHATGPT_PROBE_TIMEOUT" in ''|*[!0-9]*) CHATGPT_PROBE_TIMEOUT=6 ;; esac
case "$CHATGPT_PROBE_BACKOFF" in ''|*[!0-9]*) CHATGPT_PROBE_BACKOFF=1 ;; esac
[ "$CHATGPT_PROBE_ATTEMPTS" -ge 1 ] && [ "$CHATGPT_PROBE_ATTEMPTS" -le 3 ] || CHATGPT_PROBE_ATTEMPTS=2
[ "$CHATGPT_PROBE_TIMEOUT" -ge 5 ] && [ "$CHATGPT_PROBE_TIMEOUT" -le 6 ] || CHATGPT_PROBE_TIMEOUT=6
[ "$CHATGPT_PROBE_BACKOFF" -le 2 ] || CHATGPT_PROBE_BACKOFF=1

rotate_business_probe_log() {
  [ -f "$BUSINESS_PROBE_LOG" ] || return 0
  log_size="$(wc -c < "$BUSINESS_PROBE_LOG" 2>/dev/null || printf 0)"
  case "$log_size" in ''|*[!0-9]*) log_size=0 ;; esac
  if [ "$log_size" -ge 1048576 ]; then
    mv -f "$BUSINESS_PROBE_LOG" "${BUSINESS_PROBE_LOG}.1"
  fi
}

rotate_business_probe_log

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

classify_failure() {
  curl_code="$1"
  code="$2"
  case "$curl_code:$code" in
    28:*) printf timeout ;;
    5:*|6:*) printf dns_error ;;
    7:*|52:*|56:*) printf connect_error ;;
    35:*|51:*|58:*|59:*|60:*|77:*|80:*|82:*|83:*|90:*|91:*) printf tls_error ;;
    0:403) printf access_denied ;;
    0:429) printf rate_limited ;;
    0:451) printf geo_restricted ;;
    0:500|0:502|0:503|0:504) printf upstream_error ;;
    0:000) printf no_response ;;
    0:*) printf unexpected_http ;;
    *) printf transport_error ;;
  esac
}

probe_via_proxy() {
  probe_name="$1"
  probe_url="$2"
  expected="$3"
  degraded_marker="${BUSINESS_PROBE_STATE_DIR}/.business-probe-${probe_name}-degraded"
  attempt=1
  while [ "$attempt" -le "$BUSINESS_PROBE_ATTEMPTS" ]; do
    result="$("$CURL_BIN" -sS --connect-timeout 5 --max-time "$BUSINESS_PROBE_TIMEOUT" \
      -o /dev/null -w '%{http_code}|%{time_total}|%{content_type}' \
      -x "${PROXY:-http://10.88.0.254:7893}" -U "${PROXY_AUTH:-}" \
      -H 'User-Agent: Mozilla/5.0 lan-center-business-probe' "$probe_url" 2>/dev/null)"
    curl_code=$?
    code="${result%%|*}"
    remainder="${result#*|}"
    seconds="${remainder%%|*}"
    content_type="${remainder#*|}"
    latency_ms="$(awk -v seconds="$seconds" 'BEGIN { printf "%d", seconds * 1000 }')"
    [ -n "$code" ] || code=000
    [ -n "$latency_ms" ] || latency_ms=0

    if [ "$curl_code" -eq 0 ] && [ "$code" = "$expected" ]; then
      if [ -f "$degraded_marker" ]; then
        printf '%s probe=%s status=recovered attempt=%s http_code=%s curl_code=%s latency_ms=%s content_type=%s\n' \
          "$(date '+%F %T')" "$probe_name" "$attempt" "$code" "$curl_code" \
          "$latency_ms" "${content_type%%;*}" >> "$BUSINESS_PROBE_LOG"
        rm -f "$degraded_marker"
      fi
      return 0
    fi

    reason="$(classify_failure "$curl_code" "$code")"
    : > "$degraded_marker"
    printf '%s probe=%s status=failed attempt=%s http_code=%s curl_code=%s latency_ms=%s reason=%s content_type=%s\n' \
      "$(date '+%F %T')" "$probe_name" "$attempt" "$code" "$curl_code" \
      "$latency_ms" "$reason" "${content_type%%;*}" >> "$BUSINESS_PROBE_LOG"

    PROBE_LAST_CODE="$code"
    PROBE_LAST_CURL_CODE="$curl_code"
    PROBE_LAST_LATENCY_MS="$latency_ms"
    PROBE_LAST_REASON="$reason"
    attempt=$((attempt + 1))
    [ "$attempt" -le "$BUSINESS_PROBE_ATTEMPTS" ] && sleep "$BUSINESS_PROBE_BACKOFF"
  done
  printf '%s probe=%s status=down attempts=%s http_code=%s curl_code=%s latency_ms=%s reason=%s\n' \
    "$(date '+%F %T')" "$probe_name" "$BUSINESS_PROBE_ATTEMPTS" \
    "$PROBE_LAST_CODE" "$PROBE_LAST_CURL_CODE" "$PROBE_LAST_LATENCY_MS" \
    "$PROBE_LAST_REASON" >> "$BUSINESS_PROBE_LOG"
  return 1
}

probe_chatgpt_post() {
  probe_name=chatgpt
  degraded_marker="${BUSINESS_PROBE_STATE_DIR}/.business-probe-${probe_name}-degraded"
  attempt=1
  while [ "$attempt" -le "$CHATGPT_PROBE_ATTEMPTS" ]; do
    result="$("$CURL_BIN" -sS --connect-timeout 4 --max-time "$CHATGPT_PROBE_TIMEOUT" \
      -o /dev/null -w '%{http_code}|%{time_total}|%{content_type}' \
      -x "${PROXY:-http://10.88.0.254:7893}" -U "${PROXY_AUTH:-}" \
      -X POST -H 'Content-Type: application/json' \
      -H 'User-Agent: Mozilla/5.0 lan-center-business-probe' \
      -d '{}' 'https://chatgpt.com/backend-api/codex/responses' 2>/dev/null)"
    curl_code=$?
    code="${result%%|*}"
    remainder="${result#*|}"
    seconds="${remainder%%|*}"
    content_type="${remainder#*|}"
    latency_ms="$(awk -v seconds="$seconds" 'BEGIN { printf "%d", seconds * 1000 }')"
    [ -n "$code" ] || code=000
    [ -n "$latency_ms" ] || latency_ms=0

    case "$code:$content_type" in
      400:*json*|401:*json*) expected_result=1 ;;
      *) expected_result=0 ;;
    esac
    if [ "$curl_code" -eq 0 ] && [ "$expected_result" -eq 1 ]; then
      if [ -f "$degraded_marker" ]; then
        printf '%s probe=%s status=recovered attempt=%s http_code=%s curl_code=%s latency_ms=%s content_type=%s\n' \
          "$(date '+%F %T')" "$probe_name" "$attempt" "$code" "$curl_code" \
          "$latency_ms" "${content_type%%;*}" >> "$BUSINESS_PROBE_LOG"
        rm -f "$degraded_marker"
      fi
      return 0
    fi

    if [ "$curl_code" -eq 0 ] && { [ "$code" = 400 ] || [ "$code" = 401 ]; }; then
      reason=unexpected_content
    else
      reason="$(classify_failure "$curl_code" "$code")"
    fi
    : > "$degraded_marker"
    printf '%s probe=%s status=failed attempt=%s http_code=%s curl_code=%s latency_ms=%s reason=%s content_type=%s\n' \
      "$(date '+%F %T')" "$probe_name" "$attempt" "$code" "$curl_code" \
      "$latency_ms" "$reason" "${content_type%%;*}" >> "$BUSINESS_PROBE_LOG"
    PROBE_LAST_CODE="$code"
    PROBE_LAST_CURL_CODE="$curl_code"
    PROBE_LAST_LATENCY_MS="$latency_ms"
    PROBE_LAST_REASON="$reason"
    attempt=$((attempt + 1))
    [ "$attempt" -le "$CHATGPT_PROBE_ATTEMPTS" ] && sleep "$CHATGPT_PROBE_BACKOFF"
  done
  printf '%s probe=%s status=down attempts=%s http_code=%s curl_code=%s latency_ms=%s reason=%s\n' \
    "$(date '+%F %T')" "$probe_name" "$CHATGPT_PROBE_ATTEMPTS" \
    "$PROBE_LAST_CODE" "$PROBE_LAST_CURL_CODE" "$PROBE_LAST_LATENCY_MS" \
    "$PROBE_LAST_REASON" >> "$BUSINESS_PROBE_LOG"
  return 1
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
      respond 503 'Service Unavailable' \
        "{\"status\":\"down\",\"probe\":\"chatgpt\",\"reason\":\"$PROBE_LAST_REASON\",\"http_code\":\"$PROBE_LAST_CODE\",\"curl_code\":$PROBE_LAST_CURL_CODE,\"latency_ms\":$PROBE_LAST_LATENCY_MS}"
    fi
    ;;
  GET:/probe/gemini)
    if probe_via_proxy gemini "https://generativelanguage.googleapis.com/\$discovery/rest?version=v1beta" 200; then
      respond 204 'No Content' ''
    else
      respond 503 'Service Unavailable' \
        "{\"status\":\"down\",\"probe\":\"gemini\",\"reason\":\"$PROBE_LAST_REASON\",\"http_code\":\"$PROBE_LAST_CODE\",\"curl_code\":$PROBE_LAST_CURL_CODE,\"latency_ms\":$PROBE_LAST_LATENCY_MS}"
    fi
    ;;
  GET:/probe/google)
    google_evidence="$(python3 -B /google_probe_evidence.py)"
    google_result=$?
    if [ "$google_result" -eq 0 ]; then
      respond 204 'No Content' ''
    else
      respond 503 'Service Unavailable' "$google_evidence"
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
