#!/usr/bin/env bash
# Called only after real namespace isolation, read-only mounts and privilege drop.
set -euo pipefail
umask 077
ulimit -c 0
ulimit -t 1200
ulimit -n 1024
ulimit -f 131072
ulimit -u 1024
test "$(/usr/bin/id -u)" != 0
test "$("$GO_BINARY" env GOVERSION)" = go1.25.8
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$PARENT_NETNS"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$PARENT_MOUNTNS"
/usr/bin/grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  /usr/bin/grep -qE "^${field}:[[:space:]]+0000000000000000$" /proc/self/status
done
test -z "$(/usr/sbin/ip -o route show table all)"
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
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
    raise SystemExit("external connectivity unexpectedly available")
print("IMAGE_VERIFIER_NETWORK_NAMESPACE=PASS no_external_interfaces=true routes=0 ipv4=blocked ipv6=blocked")
PY
/usr/bin/id
/usr/bin/grep -E '^(NoNewPrivs|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
/usr/bin/findmnt -n -T "$MODULE_ROOT" -o TARGET,OPTIONS
/usr/bin/findmnt -n -T "$GOMODCACHE" -o TARGET,OPTIONS
cd "$MODULE_ROOT"
/usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum > "$RUN_ROOT/evidence/source-before.sha256"
/usr/bin/python3 -B scripts/check-go-json.py --self-test
/usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" mod verify \
  | /usr/bin/tee "$RUN_ROOT/evidence/module-verification-offline.txt"
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -timeout=4m -count=1 ./... \
  | /usr/bin/tee "$RUN_ROOT/evidence/go-test.json"
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -race -timeout=4m -count=1 ./... \
  | /usr/bin/tee "$RUN_ROOT/evidence/go-race.json"
/usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" vet ./... \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/go-vet.log"
/usr/bin/python3 -B scripts/check-go-json.py "$RUN_ROOT/evidence/go-test.json" "$RUN_ROOT/evidence/go-race.json"
/usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum > "$RUN_ROOT/evidence/source-after.sha256"
/usr/bin/cmp "$RUN_ROOT/evidence/source-before.sha256" "$RUN_ROOT/evidence/source-after.sha256"
echo 'IMAGE_VERIFIER_OFFLINE_GATE=PASS toolchain=go1.25.8 readonly_source=true readonly_module_cache=true capabilities=none no_new_privileges=true authorization=BLOCKED production=false'
