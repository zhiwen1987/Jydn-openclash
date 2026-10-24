#!/usr/bin/env bash
# CI-only source contracts. This never executes the candidate Mihomo binary.
set -euo pipefail
test "$#" -eq 3
repo="$1"
out="$2"
goroot="$3"
test "$(id -u)" -eq 0
test -d "$repo/chengwang/vendor"
test -x "$goroot/bin/go"
test -x "$goroot/bin/gofmt"
test -d "$out"
test ! -L "$out"
test -f "$out/host-before.json"
test ! -L "$out/host-before.json"
test "$(stat -c %h "$out/host-before.json")" -eq 1
test -z "$(find "$out" -mindepth 1 -maxdepth 1 ! -name host-before.json -print -quit)"
mount --make-rprivate /
ip link set lo up
mount --bind "$repo" "$repo"
mount -o remount,bind,ro "$repo"
mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs /tmp
install -d -m 0700 -o 10001 -g 10001 /tmp/contracts-home /tmp/contracts-cache /tmp/contracts-mod
chmod 0755 "$out"
cd "$repo/chengwang"
common=(setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  env -i "PATH=$goroot/bin:/usr/bin:/bin" "GOROOT=$goroot" HOME=/tmp/contracts-home
  GOCACHE=/tmp/contracts-cache GOMODCACHE=/tmp/contracts-mod GOPROXY=off GOSUMDB=off
  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC)
"${common[@]}" python3 -B -c 'import json,os; s=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line); assert os.getuid()==os.getgid()==10001 and int(s["CapEff"].strip(),16)==0 and s["NoNewPrivs"].strip()=="1"; print(json.dumps(dict(uid=os.getuid(),gid=os.getgid(),effectiveCaps=s["CapEff"].strip(),noNewPrivileges=True,networkNamespace=os.readlink("/proc/self/ns/net"),mountNamespace=os.readlink("/proc/self/ns/mnt"),pidNamespace=os.readlink("/proc/self/ns/pid"),environmentKeys=sorted(os.environ))))' > "$out/sandbox.json"
"${common[@]}" "$goroot/bin/go" version > "$out/go-version.txt"
files=(internal/adapter/mihomo/write_client.go internal/adapter/mihomo/write_client_test.go internal/mihomodeploy/config.go internal/mihomodeploy/config_test.go)
set +e
"${common[@]}" "$goroot/bin/gofmt" -d "${files[@]}" > "$out/gofmt.patch" 2> "$out/gofmt.stderr"
format_code=$?
"${common[@]}" "$goroot/bin/go" test -json -count=1 -timeout=180s ./internal/adapter/mihomo ./internal/mihomodeploy > "$out/ordinary.json" 2> "$out/ordinary.stderr"
ordinary_code=$?
"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s ./internal/adapter/mihomo ./internal/mihomodeploy > "$out/race.json" 2> "$out/race.stderr"
race_code=$?
set -e
printf '{"schema":"chengwang.mihomo-contract-execution/v1","formatExit":%d,"ordinaryExit":%d,"raceExit":%d,"realMihomoExecuted":false,"production":false}\n' "$format_code" "$ordinary_code" "$race_code" > "$out/execution.json"
chmod 0644 "$out/"*.json "$out/"*.stderr "$out/go-version.txt" "$out/gofmt.patch"
test "$format_code" -eq 0
test "$ordinary_code" -eq 0
test "$race_code" -eq 0
# Formatting drift is an independent failure. Originals and patch survive it.
test ! -s "$out/gofmt.patch"
