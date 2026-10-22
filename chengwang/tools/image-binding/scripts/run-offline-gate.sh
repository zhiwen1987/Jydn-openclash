#!/usr/bin/env bash
set -euo pipefail
umask 077
ulimit -c 0
ulimit -t 1800
ulimit -n 1024
ulimit -f 131072
ulimit -u 1024
test "$(/usr/bin/id -u)" != 0
test "$GOWORK" = off
test "$("$GO_BINARY" env GOVERSION)" = go1.25.8
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$PARENT_NETNS"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$PARENT_MOUNTNS"
/usr/bin/grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  /usr/bin/grep -qE "^${field}:[[:space:]]+0000000000000000$" /proc/self/status
done
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
test -z "$(/usr/sbin/ip -o route show default)"
test -z "$(/usr/sbin/ip -6 -o route show default)"
for mount_path in "$MODULE_ROOT" "$GOMODCACHE" "$RUN_ROOT/remote-verification"; do
  /usr/bin/findmnt -n -T "$mount_path" -o OPTIONS | /usr/bin/grep -qE '(^|,)ro(,|$)'
done
/usr/bin/python3 -B - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    with socket.create_connection(server.getsockname(), timeout=1) as client:
        connection, _ = server.accept()
        connection.close()
for family, address in ((socket.AF_INET, ("1.1.1.1", 443)),
                        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0))):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as stream:
            stream.settimeout(1)
            stream.connect(address)
    except OSError:
        continue
    raise SystemExit("external connectivity unexpectedly available")
print("IMAGE_BINDING_NETWORK_NAMESPACE=PASS loopback=usable external_interfaces=0 ipv4_external=blocked ipv6_external=blocked")
PY
/usr/bin/id
/usr/bin/grep -E '^(NoNewPrivs|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
/usr/sbin/ip -o link show
/usr/sbin/ip -o route show table all
cd "$MODULE_ROOT"
/usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum > "$RUN_ROOT/evidence/source-before.sha256"
/usr/bin/python3 -B scripts/check-go-json.py --self-test
(
  cd "$RUN_ROOT/remote-verification"
  test "$("$GO_BINARY" env GOWORK)" = off
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" list -m -json all \
    > "$RUN_ROOT/evidence/remote-modules-offline.json"
  /usr/bin/python3 -B "$MODULE_ROOT/scripts/module-verification.py" check \
    "$RUN_ROOT" "$GOMODCACHE" "$RUN_ROOT/evidence/remote-modules-offline.json"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" mod verify \
    | /usr/bin/tee "$RUN_ROOT/evidence/module-verification-offline.txt"
  /usr/bin/python3 -B "$MODULE_ROOT/scripts/module-verification.py" check \
    "$RUN_ROOT" "$GOMODCACHE" "$RUN_ROOT/evidence/remote-modules-offline.json"
)
test "$("$GO_BINARY" env GOWORK)" = off
echo 'IMAGE_BINDING_BUILD_WORKSPACE=off'
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -timeout=4m -count=1 ./... \
  | /usr/bin/tee "$RUN_ROOT/evidence/go-test.json"
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -race -timeout=4m -count=1 ./... \
  | /usr/bin/tee "$RUN_ROOT/evidence/go-race.json"
/usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" vet ./... \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/go-vet.log"
/usr/bin/python3 -B scripts/check-go-json.py --mode ordinary "$RUN_ROOT/evidence/go-test.json" "$RUN_ROOT/evidence/go-race.json"
# Independently retain the parent OCI verifier scenarios. This transcript is
# not merged into the three-package child-module test contract.
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -timeout=4m -count=1 chengwang/internal/restoreimage \
  | /usr/bin/tee "$RUN_ROOT/evidence/parent-restoreimage.json"
# Compile genuine Registry integration test executables while still offline.
# Their only later network access is inside the private Registry's own netns.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c -tags registrycli -o "$RUN_ROOT/bin/registrycli.test" .
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c -race -tags registrycli -o "$RUN_ROOT/bin/registrycli-race.test" .
/usr/bin/python3 -B scripts/module-verification.py check \
  "$RUN_ROOT" "$GOMODCACHE" "$RUN_ROOT/evidence/remote-modules-offline.json"
/usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum > "$RUN_ROOT/evidence/source-after.sha256"
/usr/bin/cmp "$RUN_ROOT/evidence/source-before.sha256" "$RUN_ROOT/evidence/source-after.sha256"
echo 'IMAGE_BINDING_OFFLINE_GATE=PASS toolchain=go1.25.8 readonly_source=true readonly_module_cache=true capabilities=none no_new_privileges=true authorization=BLOCKED production=false'
