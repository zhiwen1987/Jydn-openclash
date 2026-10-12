#!/bin/sh
# Restore the known-good R3 config if an R4 switch is not explicitly accepted.

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: openclash_r4_rollback_guard.sh BACKUP_DIR [DELAY_SECONDS]" >&2
  exit 2
fi

backup_dir="$1"
delay_seconds="${2:-1800}"
confirmed_marker="$backup_dir/r4-switch-confirmed"
catalog_backup="$backup_dir/jydn_business_group_catalog.r3.json"
catalog_live="/etc/openclash/custom/jydn_business_group_catalog.json"
r3_config="/etc/openclash/config/精准稳定-v1-r3.yaml"
guard_log="$backup_dir/r4-rollback-guard.log"

case "$backup_dir" in
  /root/openclash-backups/*) ;;
  *) echo "unsafe backup directory: $backup_dir" >&2; exit 2 ;;
esac

case "$delay_seconds" in
  ''|*[!0-9]*) echo "delay must be an integer" >&2; exit 2 ;;
esac

if [ ! -s "$catalog_backup" ] || [ ! -s "$r3_config" ]; then
  echo "rollback prerequisites are missing" >&2
  exit 1
fi

echo "guard_started=$(date '+%Y-%m-%d %H:%M:%S %z') delay_seconds=$delay_seconds" >> "$guard_log"
sleep "$delay_seconds"

if [ -e "$confirmed_marker" ]; then
  echo "guard_confirmed=$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$guard_log"
  exit 0
fi

cp "$catalog_backup" "$catalog_live.rollback-tmp"
chmod 600 "$catalog_live.rollback-tmp"
mv "$catalog_live.rollback-tmp" "$catalog_live"
uci set openclash.config.config_path="$r3_config"
uci commit openclash
/etc/init.d/openclash restart >> "$guard_log" 2>&1
echo "guard_rolled_back=$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$guard_log"
logger -t openclash-r4 "R4 was not confirmed; restored R3"
