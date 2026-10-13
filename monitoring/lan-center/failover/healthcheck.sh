#!/bin/sh
set -eu

: "${INTERVAL:=15}"
: "${CHATGPT_CONTROL_INTERVAL:=600}"
: "${CAPABILITY_ENABLED:=0}"
: "${CAPABILITY_NODE_INTERVAL:=30}"
: "${SUBSCRIPTION_CONTROLLER_ENABLED:=0}"
: "${SUBSCRIPTION_FETCH_INTERVAL:=3600}"

now="$(date +%s)"
main_epoch="$(jq -r '.epoch // 0' /data/health 2>/dev/null)"
main_status="$(jq -r '.status // empty' /data/health 2>/dev/null)"
[ "$main_status" = ok ]
[ $((now - main_epoch)) -le $((INTERVAL * 4 + 30)) ]

controller_epoch="$(jq -r '.epoch // 0' /data/chatgpt-controller.health 2>/dev/null)"
controller_status="$(jq -r '.status // empty' /data/chatgpt-controller.health 2>/dev/null)"
case "$controller_status" in ok|fallback) ;; *) exit 1 ;; esac
[ $((now - controller_epoch)) -le $((CHATGPT_CONTROL_INTERVAL * 2 + 180)) ]

for pid_file in /data/chatgpt-controller.pid /data/probe-server.pid; do
  pid="$(cat "$pid_file" 2>/dev/null)"
  [ -n "$pid" ]
  kill -0 "$pid" 2>/dev/null
done

curl -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null

if [ "$CAPABILITY_ENABLED" = 1 ]; then
  capability_pid="$(cat /data/node-capability.pid 2>/dev/null)"
  [ -n "$capability_pid" ]
  kill -0 "$capability_pid" 2>/dev/null
  capability_epoch="$(jq -r '.epoch // 0' /data/node-capability.health 2>/dev/null)"
  capability_status="$(jq -r '.status // empty' /data/node-capability.health 2>/dev/null)"
  [ "$capability_status" = ok ]
  [ $((now - capability_epoch)) -le $((CAPABILITY_NODE_INTERVAL * 4 + 60)) ]
  curl -fsS --max-time 5 http://127.0.0.1:8081/health >/dev/null
fi

if [ "$SUBSCRIPTION_CONTROLLER_ENABLED" = 1 ]; then
  subscription_pid="$(cat /data/subscription-controller.pid 2>/dev/null)"
  [ -n "$subscription_pid" ]
  kill -0 "$subscription_pid" 2>/dev/null
  subscription_epoch="$(jq -r '.epoch // 0' /data/subscription-controller/health.json 2>/dev/null)"
  subscription_status="$(jq -r '.status // empty' /data/subscription-controller/health.json 2>/dev/null)"
  case "$subscription_status" in ok|degraded) ;; *) exit 1 ;; esac
  [ $((now - subscription_epoch)) -le $((SUBSCRIPTION_FETCH_INTERVAL * 2 + 300)) ]
  curl -fsS --max-time 5 http://127.0.0.1:8082/health >/dev/null
fi
