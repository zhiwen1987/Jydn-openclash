#!/bin/sh
set -eu
stack_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1
exec python3 "$stack_directory/clash_stack.py" "$@"
