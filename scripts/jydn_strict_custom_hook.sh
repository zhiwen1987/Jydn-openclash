#!/bin/sh
# Run LAST, after the existing group, DNS and business-specific overwrite hooks.
set -eu
umask 077
stage=$1.strict-$$
stats=$stage.stats
trap 'rm -f "$stage" "$stats"' EXIT INT TERM
if ! ruby -E UTF-8 /etc/openclash/custom/jydn_strict_custom.rb "$1" \
  /etc/openclash/custom/strict-custom-policy.json \
  /etc/openclash/custom/strict-custom-private.yaml "$stage" \
  /etc/openclash/custom/strict-custom-locks.yaml >"$stats" 2>>/tmp/openclash.log; then
  exit 1
fi
mv "$stage" "$1"
printf '%s [信息] Strict custom selectors applied (empty or invalid private input stays REJECT)\n' "$(date '+%Y-%m-%d %H:%M:%S')" >>/tmp/openclash.log
