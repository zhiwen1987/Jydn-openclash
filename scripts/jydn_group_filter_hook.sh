#!/bin/sh
# OpenClash custom-overwrite hook: preserve deliberately small business menus
# and hide only empty node-group references after conversion.

CONFIG_FILE="$1"
PATCH_SCRIPT="/etc/openclash/custom/jydn_patch_runtime_groups.rb"
CATALOG_FILE="/etc/openclash/custom/jydn_business_group_catalog.json"
LOG_FILE="/tmp/openclash.log"

if [ ! -f "$PATCH_SCRIPT" ] || [ ! -f "$CATALOG_FILE" ]; then
  printf '%s Warning: Jydn group filter files are missing\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
  exit 1
fi

TMP_LOG="/tmp/jydn-group-filter.$$.log"
if ruby "$PATCH_SCRIPT" "$CONFIG_FILE" "$CATALOG_FILE" "$CONFIG_FILE" > "$TMP_LOG" 2>&1; then
  while IFS= read -r line; do
    printf '%s [信息] Jydn group filter: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$LOG_FILE"
  done < "$TMP_LOG"
  rm -f "$TMP_LOG"
  exit 0
fi

while IFS= read -r line; do
  printf '%s [错误] Jydn group filter: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$LOG_FILE"
done < "$TMP_LOG"
rm -f "$TMP_LOG"
exit 1
