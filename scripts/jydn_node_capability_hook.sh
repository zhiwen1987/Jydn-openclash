#!/bin/sh
# OpenClash custom-overwrite hook for the isolated node capability listener.
set -u

CONFIG_FILE="$1"
PATCH_SCRIPT="/etc/openclash/custom/jydn_patch_node_capability_probe.rb"
AUTH_FILE="/etc/openclash/custom/jydn_node_capability_auth.yaml"
LOG_FILE="/tmp/openclash.log"

if [ ! -f "$PATCH_SCRIPT" ] || [ ! -f "$AUTH_FILE" ]; then
  printf '%s [警告] Jydn node capability files are missing\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
  exit 1
fi

TMP_LOG="/tmp/jydn-node-capability.$$.log"
if ruby "$PATCH_SCRIPT" "$CONFIG_FILE" "$AUTH_FILE" "$CONFIG_FILE" > "$TMP_LOG" 2>&1; then
  while IFS= read -r line; do
    printf '%s [信息] Jydn node capability: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$LOG_FILE"
  done < "$TMP_LOG"
  rm -f "$TMP_LOG"
  exit 0
fi

while IFS= read -r line; do
  printf '%s [错误] Jydn node capability: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$LOG_FILE"
done < "$TMP_LOG"
rm -f "$TMP_LOG"
exit 1
