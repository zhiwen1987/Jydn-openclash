#!/usr/bin/env bash
# CI-only. The caller must already own fresh net/mount/PID namespaces.
set -euo pipefail
test "$#" -eq 5
test "$(id -u)" -eq 0
repo="$1"
exec python3 -B "$repo/chengwang/deploy/mihomo-lifecycle-lab/compat_worker.py" "$@"
