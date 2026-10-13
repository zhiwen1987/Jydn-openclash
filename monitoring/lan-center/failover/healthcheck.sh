#!/bin/sh
set -eu

: "${INTERVAL:=15}"
: "${CHATGPT_CONTROL_INTERVAL:=600}"

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
