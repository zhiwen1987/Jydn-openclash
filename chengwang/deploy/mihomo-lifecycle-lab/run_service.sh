#!/usr/bin/env bash
# Isolated CI only; the caller owns fresh network, mount and PID namespaces.
set -euo pipefail
test "$#" -eq 5
test "$(id -u)" -eq 0
exec python3 -B "$1/chengwang/deploy/mihomo-lifecycle-lab/service_worker.py" "$@"
