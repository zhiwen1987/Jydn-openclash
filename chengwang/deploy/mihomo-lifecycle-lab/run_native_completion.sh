#!/usr/bin/env bash
# Isolated Linux CI only; caller owns new net/mount/PID namespaces.
set -euo pipefail
test "$#" -eq 5
test "$(id -u)" -eq 0
exec python3 -B "$1/chengwang/deploy/mihomo-lifecycle-lab/native_completion_worker.py" "$@"
