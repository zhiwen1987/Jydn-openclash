#!/bin/sh
# OpenClash proxy health observer. DRY_RUN=1 is intentionally enforced by Compose.
set -u

: "${PROXY:=http://10.88.0.254:7893}" "${RULE_ID:=3}" "${INTERVAL:=15}" "${FAIL_N:=3}" "${OK_N:=3}" "${DRY_RUN:=1}"
LOG=/data/failover.log

log() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

ikuai-cli auth set-url "$IKUAI_URL" >/dev/null \
  && ikuai-cli auth set-token "$IKUAI_TOKEN" >/dev/null \
  || log "爱快登录配置失败"

probe() {
  for url in https://www.gstatic.com/generate_204 https://www.cloudflare.com/cdn-cgi/trace; do
    curl -s -o /dev/null -m 8 -x "$PROXY" -U "$PROXY_AUTH" "$url" && return 0
  done
  return 1
}

state() {
  ikuai-cli routing stream five-tuple get "$RULE_ID" -f json 2>/dev/null \
    | jq -r '.data[0].enabled // empty' \
    | head -1
}

set_rule() {
  if [ "$DRY_RUN" = 1 ]; then
    log "[演练] 此时应把 PT_3 设为 enabled=$1（未执行）"
    echo "$1" > /data/sim_state
  else
    ikuai-cli routing stream five-tuple toggle "$RULE_ID" --enabled "$1" >/dev/null 2>&1 \
      && log "已把 PT_3 设为 enabled=$1" \
      || log "切换 PT_3 失败"
  fi
}

current_state() {
  if [ "$DRY_RUN" = 1 ] && [ -f /data/sim_state ]; then
    cat /data/sim_state
  else
    state
  fi
}

log "启动：演练模式=$DRY_RUN 间隔=${INTERVAL}s PT_3当前=$(state)"
rm -f /data/sim_state
/bin/sh /chatgpt-controller.sh &
chatgpt_controller_pid=$!
trap 'kill "$chatgpt_controller_pid" 2>/dev/null || true' EXIT INT TERM
failures=0
successes=0

while true; do
  if probe; then
    successes=$((successes + 1))
    failures=0
    echo ok > /data/health
  else
    failures=$((failures + 1))
    successes=0
    echo fail > /data/health
    log "代理检测失败 第${failures}次"
  fi

  current=$(current_state)
  [ "$failures" -ge "$FAIL_N" ] && [ "$current" = yes ] && {
    log ".254 代理连续失败，演练切换为直连"
    set_rule no
  }
  [ "$successes" -ge "$OK_N" ] && [ "$current" = no ] && {
    log ".254 代理已恢复，演练切回代理"
    set_rule yes
  }
  sleep "$INTERVAL"
done
