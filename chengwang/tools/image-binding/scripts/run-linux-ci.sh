#!/usr/bin/env bash
# Network-isolated unit tests may use only loopback TLS servers.
set -euo pipefail
if (( $# != 3 )); then
  echo 'usage: run-linux-ci.sh ABSOLUTE_RUN_DIRECTORY GO_BINARY MODULE_CACHE' >&2
  exit 2
fi
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
module_root=$(/usr/bin/realpath -e -- "$script_root/..")
source_root=$(/usr/bin/realpath -e -- "$(/usr/bin/git -C "$module_root" rev-parse --show-toplevel)")
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
runner_uid=$(/usr/bin/id -u)
runner_gid=$(/usr/bin/id -g)
node_binary=$(/usr/bin/realpath -e -- "$(command -v node)")
chrome_binary=$(/usr/bin/realpath -e -- "$(command -v google-chrome)")
certutil_binary=$(/usr/bin/realpath -e -- "$(command -v certutil)")
test "$runner_uid" != 0
test "$("$go_binary" env GOVERSION)" = go1.25.8
case "$run_root/" in "$source_root/"*) echo 'run directory must be outside source' >&2; exit 2;; esac
/usr/bin/install -d -m 0700 "$run_root/evidence" "$run_root/home" "$run_root/tmp" "$run_root/build-cache" "$run_root/go-tmp" "$run_root/bin"
parent_netns=$(/usr/bin/readlink /proc/self/ns/net)
parent_mountns=$(/usr/bin/readlink /proc/self/ns/mnt)
/usr/bin/sudo --non-interactive /usr/bin/unshare --mount --net -- /usr/bin/bash -c '
  set -euo pipefail
  /usr/bin/mount --make-rprivate /
  /usr/bin/mount --bind "$9" "$9"
  /usr/bin/mount -o remount,bind,ro "$9"
  /usr/bin/mount --bind "$9/chengwang/web/node_modules" "$9/chengwang/web/node_modules"
  /usr/bin/mount -o remount,bind,ro "$9/chengwang/web/node_modules"
  /usr/bin/mount --bind "$5" "$5"
  /usr/bin/mount -o remount,bind,ro "$5"
  /usr/bin/mount --bind "$4/remote-verification" "$4/remote-verification"
  /usr/bin/mount -o remount,bind,ro "$4/remote-verification"
  /usr/bin/mount --bind "$4/fonts" "$4/fonts"
  /usr/bin/mount -o remount,bind,ro "$4/fonts"
  /usr/sbin/ip link set lo up
  # Separate root fixture provisioning from the original unprivileged suite.
  # Root never runs a product or gains a production network: source/cache are
  # already read-only and this fresh namespace contains only loopback.
  /usr/bin/unshare --mount -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    /usr/bin/bash --noprofile --norc "$3/scripts/run-lifecycle-fixture-preflight.sh" \
      "$9" "$4" "$7" "$8" "${13}" "$1" "$2" "$(/usr/bin/readlink /proc/self/ns/mnt)"
  /usr/bin/unshare --mount -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    /usr/bin/bash --noprofile --norc "$3/scripts/run-source-fixture-preflight.sh" \
      "$9" "$4" "$7" "$8" "${13}" "$1" "$2" "$(/usr/bin/readlink /proc/self/ns/mnt)"
  exec /usr/bin/setpriv \
    --reuid="$1" --regid="$2" --clear-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    /usr/bin/env -i \
      HOME="$4/home" TMPDIR="$4/tmp" GOTMPDIR="$4/go-tmp" GOCACHE="$4/build-cache" \
      GOMODCACHE="$5" GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
      GOPROXY=off GOSUMDB=off CGO_ENABLED=1 GOMEMLIMIT=2GiB \
      PATH="$(/usr/bin/dirname -- "$6"):$(/usr/bin/dirname -- "${10}"):/usr/bin:/bin" \
      LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
      MODULE_ROOT="$3" RUN_ROOT="$4" GO_BINARY="$6" \
      NODE_BINARY="${10}" CHROME_BINARY="${11}" CHENGWANG_VITE_CACHE_DIR="$4/vite-cache" \
      FONTCONFIG_FILE="$4/fontconfig.conf" \
      CERTUTIL_BINARY="${12}" \
      PARENT_NETNS="$7" PARENT_MOUNTNS="$8" \
      /usr/bin/bash --noprofile --norc "$3/scripts/run-offline-gate.sh"
' chengwang-image-binding "$runner_uid" "$runner_gid" "$module_root" "$run_root" "$module_cache" "$go_binary" "$parent_netns" "$parent_mountns" "$source_root" "$node_binary" "$chrome_binary" "$certutil_binary" "$source_commit" \
  2>&1 | /usr/bin/tee "$run_root/evidence/offline-gate.log"
