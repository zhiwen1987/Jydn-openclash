#!/bin/sh
# Supervise the route observer, business probes, and ChatGPT controller.
set -u

: "${PROXY:=http://10.88.0.254:7893}"
: "${RULE_ID:=3}"
: "${INTERVAL:=15}"
: "${FAIL_N:=3}"
: "${OK_N:=3}"
: "${DRY_RUN:=1}"
: "${LOG_MAX_BYTES:=5242880}"
: "${LOG_KEEP:=5}"
: "${CAPABILITY_ENABLED:=0}"
: "${SUBSCRIPTION_CONTROLLER_ENABLED:=0}"

LOG=/data/failover.log
HEALTH=/data/health

[ "$DRY_RUN" = 1 ] || {
  printf '%s status=fatal reason=production_requires_dry_run\n' "$(date '+%F %T')" >&2
  exit 64
}

rotate_one() {
  file="$1"
  [ -f "$file" ] || return 0
  size="$(wc -c < "$file" | tr -d ' ')"
  [ "$size" -lt "$LOG_MAX_BYTES" ] && return 0
  index="$LOG_KEEP"
  while [ "$index" -gt 1 ]; do
    previous=$((index - 1))
    [ -f "$file.$previous" ] && mv -f "$file.$previous" "$file.$index"
    index="$previous"
  done
  mv -f "$file" "$file.1"
  : > "$file"
}

rotate_logs() {
  rotate_one /data/failover.log
  rotate_one /data/chatgpt-controller.log
  rotate_one /data/node-capability.log
  rotate_one /data/subscription-controller/controller.log
  rotate_one /data/alerts.log
}

log() {
  rotate_logs
  printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"
}

atomic_health() {
  route_probe="$1"
  temporary="${HEALTH}.tmp.$$"
  jq -nc --arg status ok --arg route_probe "$route_probe" --argjson epoch "$(date +%s)" \
    '{status:$status,route_probe:$route_probe,epoch:$epoch}' > "$temporary" \
    && mv -f "$temporary" "$HEALTH"
}

if [ "${IKUAI_OBSERVER_ENABLED:-1}" = 1 ] && { ! ikuai-cli auth set-url "$IKUAI_URL" >/dev/null \
  || ! ikuai-cli auth set-token "$IKUAI_TOKEN" >/dev/null; }; then
  log 'status=warning reason=ikuai_auth_setup_failed'
fi

probe() {
  for url in https://www.gstatic.com/generate_204 https://www.cloudflare.com/cdn-cgi/trace; do
    curl -fsS -o /dev/null --max-time 8 -x "$PROXY" -U "$PROXY_AUTH" "$url" && return 0
  done
  return 1
}

state() {
  [ "${IKUAI_OBSERVER_ENABLED:-1}" = 1 ] || { printf "unknown\n"; return 0; }
  ikuai-cli routing stream five-tuple get "$RULE_ID" -f json 2>/dev/null \
    | jq -r '.data[0].enabled // empty' | head -1
}

set_rule() {
  log "status=dry_run requested_rule_state=$1"
  printf '%s\n' "$1" > /data/sim_state
}

current_state() {
  if [ -f /data/sim_state ]; then
    cat /data/sim_state
  else
    state
  fi
}

start_controller() {
  /bin/sh /chatgpt-controller.sh &
  controller_pid=$!
  printf '%s\n' "$controller_pid" > /data/chatgpt-controller.pid
  log 'status=started child=chatgpt_controller'
}

start_probe_server() {
  /bin/sh /probe-server.sh &
  probe_pid=$!
  printf '%s\n' "$probe_pid" > /data/probe-server.pid
  log 'status=started child=probe_server'
}

start_capability_evaluator() {
  [ "$CAPABILITY_ENABLED" = 1 ] || return 0
  rm -f /data/node-capability.health
  /usr/bin/python3 /node-capability.py &
  capability_pid=$!
  printf '%s\n' "$capability_pid" > /data/node-capability.pid
  log 'status=started child=node_capability mode=shadow'
}

start_subscription_controller() {
  [ "$SUBSCRIPTION_CONTROLLER_ENABLED" = 1 ] || return 0
  rm -f /data/subscription-controller/health.json
  /usr/bin/python3 /subscription-controller.py &
  subscription_pid=$!
  printf '%s\n' "$subscription_pid" > /data/subscription-controller.pid
  log "status=started child=subscription_controller mode=${SUBSCRIPTION_CONTROLLER_MODE:-shadow}"
}

supervise_children() {
  if ! kill -0 "$controller_pid" 2>/dev/null; then
    if restart_allowed chatgpt_controller; then start_controller; fi
  fi
  if ! kill -0 "$probe_pid" 2>/dev/null; then
    if restart_allowed probe_server; then start_probe_server; fi
  fi
  if [ "$CAPABILITY_ENABLED" = 1 ] && ! kill -0 "$capability_pid" 2>/dev/null; then
    if restart_allowed node_capability; then start_capability_evaluator; fi
  fi
  if [ "$SUBSCRIPTION_CONTROLLER_ENABLED" = 1 ] && ! kill -0 "$subscription_pid" 2>/dev/null; then
    if restart_allowed subscription_controller; then start_subscription_controller; fi
  fi
}

restart_allowed() {
  if python3 -c 'import sys,time; from autonomy_store import reserve_restart; sys.exit(0 if reserve_restart("/data/child-restarts.json",sys.argv[1],int(time.time())) else 1)' "$1"; then
    log "status=restarting child=$1"
    return 0
  fi
  log "status=cooling reason=child_restart_budget child=$1"
  return 1
}

cleanup() {
  [ -z "$controller_pid" ] || kill "$controller_pid" 2>/dev/null || true
  [ -z "$probe_pid" ] || kill "$probe_pid" 2>/dev/null || true
  [ -z "$capability_pid" ] || kill "$capability_pid" 2>/dev/null || true
  [ -z "$subscription_pid" ] || kill "$subscription_pid" 2>/dev/null || true
  [ -z "$controller_pid" ] || wait "$controller_pid" 2>/dev/null || true
  [ -z "$probe_pid" ] || wait "$probe_pid" 2>/dev/null || true
  [ -z "$capability_pid" ] || wait "$capability_pid" 2>/dev/null || true
  [ -z "$subscription_pid" ] || wait "$subscription_pid" 2>/dev/null || true
  rm -f /data/chatgpt-controller.pid /data/probe-server.pid /data/node-capability.pid /data/subscription-controller.pid
}
controller_pid=''
probe_pid=''
capability_pid=''
subscription_pid=''
trap cleanup EXIT INT TERM

log "status=started dry_run=$DRY_RUN interval=${INTERVAL}s"
rm -f /data/sim_state
start_controller
start_probe_server
start_capability_evaluator
start_subscription_controller
failures=0
successes=0

while true; do
  supervise_children
  rotate_logs
  if probe; then
    successes=$((successes + 1))
    failures=0
    route_probe=ok
  else
    failures=$((failures + 1))
    successes=0
    route_probe=fail
    log "status=warning reason=proxy_probe_failed consecutive=$failures"
  fi
  atomic_health "$route_probe"

  current="$(current_state)"
  [ "$failures" -ge "$FAIL_N" ] && [ "$current" = yes ] && set_rule no
  [ "$successes" -ge "$OK_N" ] && [ "$current" = no ] && set_rule yes
  sleep "$INTERVAL"
done
