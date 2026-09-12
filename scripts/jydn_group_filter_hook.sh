#!/bin/sh
# OpenClash custom-overwrite hook: keep business choices complete and hide empty
# node-group references after the subscription has been converted.

CONFIG_FILE="$1"
PATCH_SCRIPT="/etc/openclash/custom/jydn_patch_runtime_groups.rb"
CATALOG_FILE="/etc/openclash/custom/jydn_business_group_catalog.json"
LOG_FILE="/tmp/openclash.log"

if [ ! -f "$PATCH_SCRIPT" ] || [ ! -f "$CATALOG_FILE" ]; then
  printf '%s Warning: Jydn group filter files are missing\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
  exit 1
fi

ruby "$PATCH_SCRIPT" "$CONFIG_FILE" "$CATALOG_FILE" "$CONFIG_FILE" >> "$LOG_FILE" 2>&1
