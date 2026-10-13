#!/bin/sh
set -eu
exec nc -lk -p 8080 -e /probe-handler.sh
