#!/bin/sh
# Keep ChatGPT on a sticky node that passes a real Codex POST check.
set -u

: "${OPENCLASH_API:=http://10.88.0.254:9090}"
: "${OPENCLASH_SECRET:=}"
: "${PROXY:=http://10.88.0.254:7893}"
: "${PROXY_AUTH:=}"
: "${CHATGPT_CONTROL_INTERVAL:=300}"
: "${CHATGPT_TIMEOUT_MS:=8000}"
: "${CHATGPT_PASS_THRESHOLD:=2}"
: "${CHATGPT_MAX_CANDIDATE_TRIALS:=5}"
: "${CHATGPT_REJECT_COOLDOWN:=3600}"

POOL_NAME='🤖 ChatGPT 专用节点池'
BUSINESS_NAME='🤖 对话助手（ChatGPT）'
FALLBACK='🧠 人工智能'
DISCOVERY_URL='https://api.openai.com/v1/models'
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
  curl -fsS --max-time 15 -H "Authorization: Bearer $OPENCLASH_SECRET" "$OPENCLASH_API$1"
}

api_select() {
  group_name="$1"
  target_name="$2"
  group_path="$(uri "$group_name")"
  body="$(jq -nc --arg name "$target_name" '{name:$name}')"
  curl -fsS --max-time 15 -X PUT -H "Authorization: Bearer $OPENCLASH_SECRET" \
    -H 'Content-Type: application/json' -d "$body" "$OPENCLASH_API/proxies/$group_path" >/dev/null
  [ "$(api_get "/proxies/$group_path" | jq -r '.now // empty')" = "$target_name" ]
}

verify_codex_post() {
  result="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}|%{content_type}' \
    -x "$PROXY" -U "$PROXY_AUTH" -X POST \
    -H 'Content-Type: application/json' -H 'User-Agent: Mozilla/5.0' \
    -d '{}' "$CODEX_URL" 2>/dev/null)" || return 1
  code="${result%%|*}"
  content_type="${result#*|}"
  case "$code" in 400|401) ;; *) return 1 ;; esac
  case "$content_type" in *json*) return 0 ;; *) return 1 ;; esac
}

ensure_business_group() {
  business_path="$(uri "$BUSINESS_NAME")"
  selected="$(api_get "/proxies/$business_path" | jq -r '.now // empty')" || return 1
  [ "$selected" = "$POOL_NAME" ] || api_select "$BUSINESS_NAME" "$POOL_NAME"
}

load_state() {
  capable_count=0
  last_switch=0
  if [ -s "$STATE" ] && jq -e . "$STATE" >/dev/null 2>&1; then
    capable_count="$(jq -r '.capable_count // 0' "$STATE")"
    last_switch="$(jq -r '.last_switch // 0' "$STATE")"
  fi
}

save_state() {
  atomic_write "$STATE" "$(jq -nc --argjson capable_count "$capable_count" \
    --argjson last_switch "$last_switch" \
    '{capable_count:$capable_count,last_switch:$last_switch}')"
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
  pool_path="$(uri "$POOL_NAME")"
  target_url="$(uri "$DISCOVERY_URL")"
  delay_result="$(api_get "/group/$pool_path/delay?url=$target_url&timeout=$CHATGPT_TIMEOUT_MS&expected=401")" || return 1
  printf '%s' "$delay_result" | jq -r \
    --argjson allowed "$(printf '%s' "$group_json" | jq '.all')" --arg fallback "$FALLBACK" '
      to_entries[]
      | select(.key != $fallback)
      | select(.key as $name | ($allowed | index($name)) != null)
      | select(.value | type == "number")
      | [.value, (.key | @base64)] | @tsv
    ' | sort -n > "$output"
}

try_candidates() {
  results="$1"
  now="$2"
  attempts=0
  while IFS="$(printf '\t')" read -r delay encoded; do
    [ -n "$encoded" ] || continue
    node="$(printf '%s' "$encoded" | base64 -d)"
    hash="$(printf '%s' "$node" | sha256sum | cut -c1-12)"
    is_rejected "$hash" && continue
    attempts=$((attempts + 1))
    if api_select "$POOL_NAME" "$node" && verify_codex_post; then
      last_switch="$now"
      log "status=switched reason=codex_post_verified candidate_hash=$hash delay_ms=$delay attempts=$attempts"
      return 0
    fi
    mark_rejected "$hash" "$now"
    log "status=rejected reason=codex_post_failed candidate_hash=$hash attempts=$attempts"
    api_select "$POOL_NAME" "$FALLBACK" || return 1
    [ "$attempts" -ge "$CHATGPT_MAX_CANDIDATE_TRIALS" ] && break
  done < "$results"
  return 1
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
    if verify_codex_post; then
      current_hash="$(printf '%s' "$current" | sha256sum | cut -c1-12)"
      capable_count=0
      save_state
      log "status=retained reason=codex_post_verified current_hash=$current_hash"
      write_health ok capable_node_selected
      return 0
    fi
    current_hash="$(printf '%s' "$current" | sha256sum | cut -c1-12)"
    mark_rejected "$current_hash" "$now"
    api_select "$POOL_NAME" "$FALLBACK" || {
      write_health error fallback_selection_failed
      return 1
    }
    capable_count=0
    last_switch="$now"
    save_state
    log "status=fallback reason=current_codex_post_failed rejected_hash=$current_hash"
    write_health fallback current_codex_post_failed
    return 0
  fi

  if ! verify_codex_post; then
    log 'status=error reason=fallback_codex_post_failed'
    write_health error fallback_codex_post_failed
    return 1
  fi

  work="$(mktemp -d /tmp/chatgpt-control.XXXXXX)" || return 1
  results="$work/results"
  if ! discover_candidates "$group" "$results"; then
    rm -rf "$work"
    log 'status=error reason=batch_probe_api'
    write_health error batch_probe_api
    return 1
  fi
  working="$(wc -l < "$results" | tr -d ' ')"
  if [ "$working" -gt 0 ]; then capable_count=$((capable_count + 1)); else capable_count=0; fi

  if [ "$capable_count" -ge "$CHATGPT_PASS_THRESHOLD" ] && try_candidates "$results" "$now"; then
    capable_count=0
    save_state
    write_health ok capable_node_selected
  else
    api_select "$POOL_NAME" "$FALLBACK" || true
    save_state
    log "status=fallback reason=waiting_or_no_verified_candidate working=$working confirmed=$capable_count"
    write_health fallback verified_fallback
  fi
  rm -rf "$work"
}

log "controller_started interval=${CHATGPT_CONTROL_INTERVAL}s mode=codex_post"
while true; do
  run_check || true
  sleep "$CHATGPT_CONTROL_INTERVAL"
done
