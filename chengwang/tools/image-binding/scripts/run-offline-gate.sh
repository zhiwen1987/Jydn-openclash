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
# Durable state tests need native Linux filesystems, not tmpfs/overlay/NFS.
# No additional source/cache write permission is granted: TMPDIR is already
# the run-owned, private temporary directory established by run-linux-ci.sh.
test "$TMPDIR" = "$RUN_ROOT/tmp"
test "$(/usr/bin/stat -c '%u:%g:%a' -- "$TMPDIR")" = "$(/usr/bin/id -u):$(/usr/bin/id -g):700"
case "$(/usr/bin/findmnt -n -T "$TMPDIR" -o FSTYPE)" in
  ext4|xfs) ;;
  *) echo 'durable trust-state tests require native ext4 or XFS' >&2; exit 1;;
esac
echo 'IMAGE_BINDING_TRUSTSTATE_FILESYSTEM=PASS private_run_tmp=true native_ext4_or_xfs=true'
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$PARENT_NETNS"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$PARENT_MOUNTNS"
/usr/bin/grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  /usr/bin/grep -qE "^${field}:[[:space:]]+0000000000000000$" /proc/self/status
done
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
test -z "$(/usr/sbin/ip -o route show default)"
test -z "$(/usr/sbin/ip -6 -o route show default)"
source_root=$(/usr/bin/git -C "$MODULE_ROOT" rev-parse --show-toplevel)
for mount_path in "$source_root" "$MODULE_ROOT" "$GOMODCACHE" "$RUN_ROOT/remote-verification"; do
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
# The backend now composes the parent API, authn/authz, evidence and DTO
# packages as well as the sibling signature verifier. Bind their actual
# checkout bytes too, not only the nested module's source directory.
(
  cd "$source_root"
  /usr/bin/git ls-files -z -- 'chengwang/**' '.github/workflows/chengwang-image-binding.yml' \
    | /usr/bin/xargs -0 /usr/bin/sha256sum --
) > "$RUN_ROOT/evidence/checkout-before.sha256"
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
# Build and exercise the actual opt-in candidate command, rather than calling
# a test binary a release artifact. --help exits before opening any stores or
# starting a listener. Only its digest/build metadata/help become evidence.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" build -trimpath \
  -o "$RUN_ROOT/bin/image-trust-api" ./cmd/image-trust-api
/usr/bin/sha256sum -- "$RUN_ROOT/bin/image-trust-api" > "$RUN_ROOT/evidence/candidate-binary.sha256"
"$GO_BINARY" version -m "$RUN_ROOT/bin/image-trust-api" > "$RUN_ROOT/evidence/candidate-binary-buildinfo.txt"
/usr/bin/timeout --signal=TERM --kill-after=1s 10s "$RUN_ROOT/bin/image-trust-api" --help \
  > "$RUN_ROOT/evidence/candidate-binary-help.txt" 2>&1
echo 'IMAGE_TRUST_CANDIDATE_COMMAND=PASS trimpath=true help_only=true listener_started=false store_opened=false release_signed=false product_image_executed=false'
# Independently retain the parent OCI verifier scenarios. This transcript is
# not merged into the seven-package child-module test contract.
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
(
  cd "$source_root"
  /usr/bin/git ls-files -z -- 'chengwang/**' '.github/workflows/chengwang-image-binding.yml' \
    | /usr/bin/xargs -0 /usr/bin/sha256sum --
) > "$RUN_ROOT/evidence/checkout-after.sha256"
/usr/bin/cmp "$RUN_ROOT/evidence/checkout-before.sha256" "$RUN_ROOT/evidence/checkout-after.sha256"
echo 'IMAGE_BINDING_OFFLINE_GATE=PASS toolchain=go1.25.8 readonly_source=true readonly_module_cache=true capabilities=none no_new_privileges=true authorization=BLOCKED production=false'
