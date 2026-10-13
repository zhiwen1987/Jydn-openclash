#!/bin/sh
# Restore the previous OpenClash config if the subscription-controller switch
# is not explicitly confirmed after end-to-end acceptance.
set -eu

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || {
  echo "usage: openclash_subscription_switch_guard.sh BACKUP_DIR [DELAY_SECONDS]" >&2
  exit 2
}

backup_dir="$1"
delay_seconds="${2:-600}"
previous_path_file="$backup_dir/config_path.before"
previous_auto_update_file="$backup_dir/auto_update.before"
marker="$backup_dir/subscription-switch-confirmed"
log_file="$backup_dir/subscription-switch-guard.log"

case "$backup_dir" in /root/openclash-backups/*) ;; *) echo "unsafe backup directory" >&2; exit 2;; esac
case "$delay_seconds" in ''|*[!0-9]*) echo "delay must be an integer" >&2; exit 2;; esac
[ -s "$previous_path_file" ] || { echo "previous config path missing" >&2; exit 1; }
previous_path="$(cat "$previous_path_file")"
case "$previous_path" in /etc/openclash/config/*.yaml) ;; *) echo "unsafe previous config path" >&2; exit 2;; esac
[ -s "$previous_path" ] || { echo "previous config missing" >&2; exit 1; }

echo "guard_started=$(date '+%F %T %z') delay=$delay_seconds" >> "$log_file"
sleep "$delay_seconds"
if [ -e "$marker" ]; then
  echo "guard_confirmed=$(date '+%F %T %z')" >> "$log_file"
  exit 0
fi
uci set openclash.config.config_path="$previous_path"
if [ -s "$previous_auto_update_file" ]; then
  previous_auto_update="$(cat "$previous_auto_update_file")"
  case "$previous_auto_update" in 0|1) ;; *) echo "unsafe previous auto_update value" >&2; exit 2;; esac
  uci set openclash.config.auto_update="$previous_auto_update"
fi
uci commit openclash
/etc/init.d/openclash restart >> "$log_file" 2>&1
echo "guard_rolled_back=$(date '+%F %T %z')" >> "$log_file"
logger -t openclash-subscription-controller "candidate unconfirmed; restored previous config"
