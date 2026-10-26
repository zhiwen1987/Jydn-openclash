#!/bin/sh
# Keep ChatGPT on a sticky node verified by the real Codex endpoint.
set -u

: "${OPENCLASH_API:=http://10.88.0.254:9090}"
: "${OPENCLASH_SECRET:=}"
: "${PROXY:=http://10.88.0.254:7893}"
: "${PROXY_AUTH:=}"
: "${CURL_BIN:=curl}"
: "${CHATGPT_CONTROL_INTERVAL:=60}"
: "${CHATGPT_MAX_CANDIDATE_TRIALS:=5}"
: "${CHATGPT_REJECT_COOLDOWN:=900}"
: "${CHATGPT_VERIFY_ATTEMPTS:=3}"
: "${CHATGPT_VERIFY_MIN_SUCCESS:=2}"
: "${CHATGPT_VERIFY_TIMEOUT:=8}"
: "${CHATGPT_VERIFY_BACKOFF:=1}"
: "${CHATGPT_CAPABILITY_API:=http://127.0.0.1:8081/api/nodes}"
: "${CHATGPT_CAPABILITY_MAX_AGE:=28800}"

case "$CHATGPT_VERIFY_ATTEMPTS" in ''|*[!0-9]*) CHATGPT_VERIFY_ATTEMPTS=3 ;; esac
case "$CHATGPT_VERIFY_MIN_SUCCESS" in ''|*[!0-9]*) CHATGPT_VERIFY_MIN_SUCCESS=2 ;; esac
case "$CHATGPT_VERIFY_TIMEOUT" in ''|*[!0-9]*) CHATGPT_VERIFY_TIMEOUT=8 ;; esac
case "$CHATGPT_VERIFY_BACKOFF" in ''|*[!0-9]*) CHATGPT_VERIFY_BACKOFF=1 ;; esac
[ "$CHATGPT_VERIFY_ATTEMPTS" -ge 2 ] && [ "$CHATGPT_VERIFY_ATTEMPTS" -le 5 ] || CHATGPT_VERIFY_ATTEMPTS=3
[ "$CHATGPT_VERIFY_MIN_SUCCESS" -ge 1 ] && [ "$CHATGPT_VERIFY_MIN_SUCCESS" -le "$CHATGPT_VERIFY_ATTEMPTS" ] || CHATGPT_VERIFY_MIN_SUCCESS=2
[ "$CHATGPT_VERIFY_TIMEOUT" -ge 5 ] && [ "$CHATGPT_VERIFY_TIMEOUT" -le 15 ] || CHATGPT_VERIFY_TIMEOUT=8
[ "$CHATGPT_VERIFY_BACKOFF" -le 5 ] || CHATGPT_VERIFY_BACKOFF=1

POOL_NAME='🤖 ChatGPT 专用节点池'
BUSINESS_NAME='🤖 对话助手（ChatGPT）'
FALLBACK='🧠 人工智能'
CODEX_URL='https://chatgpt.com/backend-api/codex/responses'
LOG=/data/chatgpt-controller.log
HEALTH=/data/chatgpt-controller.health
STATE=/data/chatgpt-controller.state
REJECTS=/data/chatgpt-controller.rejects

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }
uri() { jq -rn --arg value "$1" '$value|@uri'; }

atomic_write() {
  destination="$1"
  content="$2"
  temporary="${destination}.tmp.$$"
  printf '%s\n' "$content" > "$temporary" && mv -f "$temporary" "$destination"
}

write_health() {
  status="$1"
  detail="$2"
  atomic_write "$HEALTH" "$(jq -nc --arg status "$status" --arg detail "$detail" \
    --argjson epoch "$(date +%s)" '{status:$status,detail:$detail,epoch:$epoch}')"
}

api_get() {
  "$CURL_BIN" -fsS --max-time 15 -H "Authorization: Bearer $OPENCLASH_SECRET" "$OPENCLASH_API$1"
}

api_select() {
  group_name="$1"
  target_name="$2"
  group_path="$(uri "$group_name")"
  body="$(jq -nc --arg name "$target_name" '{name:$name}')"
  "$CURL_BIN" -fsS --max-time 15 -X PUT -H "Authorization: Bearer $OPENCLASH_SECRET" \
    -H 'Content-Type: application/json' -d "$body" "$OPENCLASH_API/proxies/$group_path" >/dev/null
  [ "$(api_get "/proxies/$group_path" | jq -r '.now // empty')" = "$target_name" ]
}

classify_failure() {
  curl_code="$1"
  code="$2"
  content_type="$3"
  case "$curl_code:$code" in
    28:*) printf timeout ;;
    5:*|6:*) printf dns_error ;;
    7:*|52:*|56:*) printf connect_error ;;
    35:*|51:*|58:*|59:*|60:*|77:*|80:*|82:*|83:*|90:*|91:*) printf tls_error ;;
    0:403) printf access_denied ;;
    0:429) printf rate_limited ;;
    0:451) printf geo_restricted ;;
    0:500|0:502|0:503|0:504) printf upstream_error ;;
    0:400|0:401)
      case "$content_type" in *json*) printf ok ;; *) printf unexpected_content ;; esac
      ;;
    0:000) printf no_response ;;
    0:*) printf unexpected_http ;;
    *) printf transport_error ;;
  esac
}

probe_codex_once() {
  result="$("$CURL_BIN" -sS --connect-timeout 5 --max-time "$CHATGPT_VERIFY_TIMEOUT" \
    -o /dev/null -w '%{http_code}|%{time_total}|%{content_type}' \
    -x "$PROXY" -U "$PROXY_AUTH" -X POST \
    -H 'Content-Type: application/json' -H 'User-Agent: Mozilla/5.0 lan-center-chatgpt-controller' \
    -d '{}' "$CODEX_URL" 2>/dev/null)"
  VERIFY_LAST_CURL_CODE=$?
  VERIFY_LAST_CODE="${result%%|*}"
  remainder="${result#*|}"
  seconds="${remainder%%|*}"
  VERIFY_LAST_CONTENT_TYPE="${remainder#*|}"
  VERIFY_LAST_LATENCY_MS="$(awk -v seconds="$seconds" 'BEGIN { printf "%d", seconds * 1000 }')"
  [ -n "$VERIFY_LAST_CODE" ] || VERIFY_LAST_CODE=000
  [ -n "$VERIFY_LAST_LATENCY_MS" ] || VERIFY_LAST_LATENCY_MS=0
  VERIFY_LAST_REASON="$(classify_failure "$VERIFY_LAST_CURL_CODE" "$VERIFY_LAST_CODE" "$VERIFY_LAST_CONTENT_TYPE")"
  [ "$VERIFY_LAST_REASON" = ok ]
}

verify_codex_post() {
  attempt=1
  successes=0
  while [ "$attempt" -le "$CHATGPT_VERIFY_ATTEMPTS" ]; do
    if probe_codex_once; then
      successes=$((successes + 1))
      if [ "$successes" -ge "$CHATGPT_VERIFY_MIN_SUCCESS" ]; then
        return 0
      fi
    else
      log "status=probe_failed context=${VERIFY_CONTEXT:-unknown} attempt=$attempt http_code=$VERIFY_LAST_CODE curl_code=$VERIFY_LAST_CURL_CODE latency_ms=$VERIFY_LAST_LATENCY_MS reason=$VERIFY_LAST_REASON"
    fi
    remaining=$((CHATGPT_VERIFY_ATTEMPTS - attempt))
    [ $((successes + remaining)) -ge "$CHATGPT_VERIFY_MIN_SUCCESS" ] || break
    attempt=$((attempt + 1))
    [ "$attempt" -le "$CHATGPT_VERIFY_ATTEMPTS" ] && sleep "$CHATGPT_VERIFY_BACKOFF"
  done
  return 1
}

ensure_business_group() {
  business_path="$(uri "$BUSINESS_NAME")"
  selected="$(api_get "/proxies/$business_path" | jq -r '.now // empty')" || return 1
  [ "$selected" = "$POOL_NAME" ] || api_select "$BUSINESS_NAME" "$POOL_NAME"
}

load_state() {
  last_switch=0
  if [ -s "$STATE" ] && jq -e . "$STATE" >/dev/null 2>&1; then
    last_switch="$(jq -r '.last_switch // 0' "$STATE")"
  fi
}

save_state() {
  atomic_write "$STATE" "$(jq -nc --argjson last_switch "$last_switch" \
    '{capable_count:0,last_switch:$last_switch}')"
}

cleanup_rejects() {
  now="$1"
  temporary="${REJECTS}.tmp.$$"
  : > "$temporary"
  if [ -f "$REJECTS" ]; then
    while read -r hash epoch; do
      case "$epoch" in ''|*[!0-9]*) continue ;; esac
      [ $((now - epoch)) -lt "$CHATGPT_REJECT_COOLDOWN" ] && printf '%s %s\n' "$hash" "$epoch" >> "$temporary"
    done < "$REJECTS"
  fi
  mv -f "$temporary" "$REJECTS"
}

is_rejected() {
  hash="$1"
  grep -q "^${hash} " "$REJECTS" 2>/dev/null
}

mark_rejected() {
  hash="$1"
  now="$2"
  grep -v "^${hash} " "$REJECTS" 2>/dev/null > "${REJECTS}.tmp.$$" || true
  printf '%s %s\n' "$hash" "$now" >> "${REJECTS}.tmp.$$"
  mv -f "${REJECTS}.tmp.$$" "$REJECTS"
}

discover_candidates() {
  group_json="$1"
  output="$2"
  now="$3"
  capability_json="$("$CURL_BIN" -fsS --max-time 8 "$CHATGPT_CAPABILITY_API")" || return 1
  printf '%s' "$capability_json" | jq -e '.nodes | type == "array"' >/dev/null 2>&1 || return 1
  printf '%s' "$capability_json" | jq -r \
    --argjson allowed "$(printf '%s' "$group_json" | jq '.all')" \
    --arg fallback "$FALLBACK" --argjson now "$now" \
    --argjson max_age "$CHATGPT_CAPABILITY_MAX_AGE" '
      .nodes[]
      | select(.name != $fallback)
      | select(.name as $name | ($allowed | index($name)) != null)
      | (.capabilities.chatgpt // {}) as $cap
      | select(($cap.status // "") == "available")
      | select(($cap.last_checked // 0) > 0)
      | select(($now - ($cap.last_checked // 0)) <= $max_age)
      | select((.state == "healthy") or (.state == "degraded") or (.state == "business-limited"))
      | [((((100 - (.score // 0)) * 1000000) + (.latency_ms // 999999)) | floor), (.name | @base64)]
      | @tsv
    ' | sort -n > "$output"
  [ -s "$output" ]
}

try_candidates() {
  results="$1"
  now="$2"
  attempts=0
  while IFS="$(printf '\t')" read -r rank encoded; do
    [ -n "$encoded" ] || continue
    node="$(printf '%s' "$encoded" | base64 -d)"
    hash="$(printf '%s' "$node" | sha256sum | cut -c1-12)"
    is_rejected "$hash" && continue
    attempts=$((attempts + 1))
    if ! api_select "$POOL_NAME" "$node"; then
      log "status=error reason=candidate_selection_failed candidate_hash=$hash attempts=$attempts"
      return 1
    fi
    VERIFY_CONTEXT=candidate
    if verify_codex_post; then
      last_switch="$now"
      log "status=switched reason=capability_verified candidate_hash=$hash rank=$rank attempts=$attempts"
      return 0
    fi
    mark_rejected "$hash" "$now"
    log "status=rejected reason=$VERIFY_LAST_REASON candidate_hash=$hash http_code=$VERIFY_LAST_CODE curl_code=$VERIFY_LAST_CURL_CODE attempts=$attempts"
    [ "$attempts" -ge "$CHATGPT_MAX_CANDIDATE_TRIALS" ] && break
  done < "$results"
  return 1
}

select_verified_fallback() {
  if ! api_select "$POOL_NAME" "$FALLBACK"; then
    log 'status=error reason=fallback_selection_failed'
    write_health error fallback_selection_failed
    return 1
  fi
  VERIFY_CONTEXT=fallback
  if verify_codex_post; then
    last_switch="$(date +%s)"
    save_state
    log 'status=fallback reason=verified_fallback'
    write_health fallback verified_fallback
    return 0
  fi
  log "status=error reason=fallback_unavailable probe_reason=$VERIFY_LAST_REASON http_code=$VERIFY_LAST_CODE curl_code=$VERIFY_LAST_CURL_CODE"
  write_health error fallback_unavailable
  return 1
}

recover_route() {
  group="$1"
  now="$2"
  work="$(mktemp -d /tmp/chatgpt-control.XXXXXX)" || return 1
  results="$work/results"
  if discover_candidates "$group" "$results" "$now"; then
    working="$(wc -l < "$results" | tr -d ' ')"
    if try_candidates "$results" "$now"; then
      rm -rf "$work"
      save_state
      write_health ok capable_node_selected
      return 0
    fi
    log "status=recovery_failed reason=no_verified_candidate eligible=$working"
  else
    log 'status=recovery_deferred reason=capability_data_unavailable'
  fi
  rm -rf "$work"
  select_verified_fallback
}

run_check() {
  if [ -z "$OPENCLASH_SECRET" ] || [ -z "$PROXY_AUTH" ]; then
    log 'status=error reason=missing_secret'
    write_health error missing_secret
    return 1
  fi
  ensure_business_group || {
    log 'status=error reason=business_group_readback_failed'
    write_health error business_group_readback_failed
    return 1
  }

  pool_path="$(uri "$POOL_NAME")"
  group="$(api_get "/proxies/$pool_path")" || {
    log 'status=error reason=pool_api'
    write_health error pool_api
    return 1
  }
  current="$(printf '%s' "$group" | jq -r '.now // empty')"
  now="$(date +%s)"
  load_state
  cleanup_rejects "$now"

  if [ "$current" != "$FALLBACK" ]; then
    VERIFY_CONTEXT=current
    if verify_codex_post; then
      current_hash="$(printf '%s' "$current" | sha256sum | cut -c1-12)"
      log "status=retained reason=codex_post_verified current_hash=$current_hash"
      write_health ok capable_node_selected
      return 0
    fi
    current_hash="$(printf '%s' "$current" | sha256sum | cut -c1-12)"
    mark_rejected "$current_hash" "$now"
    log "status=current_failed reason=$VERIFY_LAST_REASON current_hash=$current_hash http_code=$VERIFY_LAST_CODE curl_code=$VERIFY_LAST_CURL_CODE"
  fi

  recover_route "$group" "$now"
}

case "${1:-}" in
  --self-test)
    [ "$(classify_failure 28 000 '')" = timeout ]
    [ "$(classify_failure 35 000 '')" = tls_error ]
    [ "$(classify_failure 0 403 text/html)" = access_denied ]
    [ "$(classify_failure 0 401 application/json)" = ok ]
    printf 'chatgpt controller self-test: ok\n'
    exit 0
    ;;
  --validate-candidates)
    [ -n "$OPENCLASH_SECRET" ] || exit 64
    pool_path="$(uri "$POOL_NAME")"
    group="$(api_get "/proxies/$pool_path")" || exit 65
    work="$(mktemp -d /tmp/chatgpt-candidates.XXXXXX)" || exit 66
    results="$work/results"
    if discover_candidates "$group" "$results" "$(date +%s)"; then
      printf 'eligible_candidates=%s\n' "$(wc -l < "$results" | tr -d ' ')"
      rm -rf "$work"
      exit 0
    fi
    rm -rf "$work"
    exit 67
    ;;
esac

log "controller_started interval=${CHATGPT_CONTROL_INTERVAL}s attempts=$CHATGPT_VERIFY_ATTEMPTS min_success=$CHATGPT_VERIFY_MIN_SUCCESS capability_source=shadow"
while true; do
  if [ "${QUALITY_CONTROL_ENABLED:-0}" = 1 ]; then
    # A disabled/damaged quality policy means freeze, not permission for legacy writes.
    write_health ok quality_controller_owner
    sleep 30
    continue
  fi
  run_check || true
  sleep "$CHATGPT_CONTROL_INTERVAL"
done
