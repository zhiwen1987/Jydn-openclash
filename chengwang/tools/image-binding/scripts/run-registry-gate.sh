#!/usr/bin/env bash
set -euo pipefail
umask 077
ulimit -c 0
ulimit -t 600
ulimit -n 1024
ulimit -f 131072
ulimit -u 1024
test "$(/usr/bin/id -u)" != 0
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$PARENT_NETNS"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$PARENT_MOUNTNS"
/usr/bin/grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  /usr/bin/grep -qE "^${field}:[[:space:]]+0000000000000000$" /proc/self/status
done
test -z "$(/usr/sbin/ip -o route show default)"
test -z "$(/usr/sbin/ip -6 -o route show default)"
for mount_path in "$MODULE_ROOT" "$GOMODCACHE"; do
  /usr/bin/findmnt -n -T "$mount_path" -o OPTIONS | /usr/bin/grep -qE '(^|,)ro(,|$)'
done
/usr/bin/python3 -B - <<'PY'
import socket
for family, address in ((socket.AF_INET, ("1.1.1.1", 443)),
                        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0))):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as stream:
            stream.settimeout(1)
            stream.connect(address)
    except OSError:
        continue
    raise SystemExit("Registry network unexpectedly has external connectivity")
print("REGISTRY_TEST_NAMESPACE=PASS external_ipv4=blocked external_ipv6=blocked default_routes=0 capabilities=none")
PY
cd "$MODULE_ROOT"
/usr/bin/timeout --signal=TERM --kill-after=10s 240s \
  "$GO_BINARY" tool test2json -t -p chengwang/image-binding "$TEST_BINARY" \
    -test.v=test2json -test.run '^TestRegistryCLIBindingLifecycle$' -test.count=1 -test.timeout=3m \
  | /usr/bin/tee "$RUN_ROOT/evidence/registry-$TEST_MODE.json"
