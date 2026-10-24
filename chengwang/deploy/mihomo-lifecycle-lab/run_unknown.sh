#!/usr/bin/env bash
# Isolated Linux CI only; fresh namespaces are provided by the caller.
set -euo pipefail
test "$#" -eq 5
test "$(id -u)" -eq 0
exec python3 -B "$1/chengwang/deploy/mihomo-lifecycle-lab/unknown_worker.py" "$@"
