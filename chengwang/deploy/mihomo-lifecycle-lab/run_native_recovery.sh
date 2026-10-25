#!/usr/bin/env bash
# Isolated Linux CI only; caller owns new net/mount/PID namespaces.
# Acquisition and source manifests are performed by the outer fixed workflow.
set -euo pipefail
test "$#" -eq 5
test "$(id -u)" -eq 0
exec python3 -B "$1/chengwang/deploy/mihomo-lifecycle-lab/native_recovery_worker.py" "$@"
