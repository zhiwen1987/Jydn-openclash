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
# Hosted checkout ancestors may be inaccessible to UID10001. Give exact
# source bytes a read-only alias on this private mount, never chmod the host.
install -d -m 0755 /tmp/contracts-source
mount --bind "$repo/chengwang" /tmp/contracts-source
mount -o remount,bind,ro,nosuid,nodev,noexec /tmp/contracts-source
module_sha="$(sha256sum "$repo/chengwang/go.mod")"
module_sha="${module_sha%% *}"
chmod 0755 "$out"
cd /tmp/contracts-source
common=(setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  env -i "PATH=$goroot/bin:/usr/bin:/bin" "GOROOT=$goroot" HOME=/tmp/contracts-home TMPDIR=/tmp/contracts-home
  GOCACHE=/tmp/contracts-cache GOMODCACHE=/tmp/contracts-mod GOPROXY=off GOSUMDB=off
  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC)
"${common[@]}" python3 -B - "$module_sha" > "$out/sandbox.json" <<'PY'
import hashlib,json,os,stat,sys
from pathlib import Path
s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert os.getuid()==os.getgid()==10001 and int(s['CapEff'].strip(),16)==0 and s['NoNewPrivs'].strip()=='1'
assert Path.cwd()==Path('/tmp/contracts-source')
module=Path('/tmp/contracts-source/go.mod').read_bytes()
module_sha=hashlib.sha256(module).hexdigest()
assert module==Path('go.mod').read_bytes() and module_sha==sys.argv[1]
readonly=bool(os.statvfs('/tmp/contracts-source').f_flag & os.ST_RDONLY)
tmp=Path('/tmp/contracts-home');info=tmp.lstat()
private=stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o700
assert readonly and private and os.environ['TMPDIR']==os.environ['HOME']==str(tmp)
print(json.dumps(dict(uid=os.getuid(),gid=os.getgid(),effectiveCaps=s['CapEff'].strip(),noNewPrivileges=True,
    networkNamespace=os.readlink('/proc/self/ns/net'),mountNamespace=os.readlink('/proc/self/ns/mnt'),
    pidNamespace=os.readlink('/proc/self/ns/pid'),environmentKeys=sorted(os.environ),
    sourceModuleSHA256=module_sha,sourceAliasReadOnly=readonly,temporaryRootPrivate=private)))
PY
"${common[@]}" "$goroot/bin/go" version > "$out/go-version.txt"
files=(internal/adapter/mihomo/write_client.go internal/adapter/mihomo/write_client_test.go internal/mihomodeploy/config.go internal/mihomodeploy/config_test.go)
files+=(internal/mihomodeploy/artifact.go internal/mihomodeploy/artifact_linux.go internal/mihomodeploy/artifact_unsupported.go
  internal/mihomodeploy/artifact_test.go internal/mihomodeploy/artifact_linux_test.go internal/mihomodeploy/plan.go internal/mihomodeploy/plan_test.go)
files+=(internal/mihomodeploy/prepare.go internal/mihomodeploy/prepare_test.go)
files+=(internal/mihomodeploy/lifecycle_disk.go internal/mihomodeploy/lifecycle.go internal/mihomodeploy/lifecycle_test.go
  internal/mihomodeploy/lifecycle_linux.go internal/mihomodeploy/lifecycle_linux_test.go
  internal/mihomodeploy/lifecycle_unsupported.go internal/mihomodeploy/lifecycle_unsupported_test.go
  internal/mihomodeploy/private_atomic_linux.go)
files+=(internal/authn/store.go internal/authn/store_test.go internal/authn/snapshot_manager.go internal/authn/snapshot_manager_test.go
  internal/authn/snapshot_manager_linux.go internal/authn/snapshot_manager_linux_test.go internal/authn/snapshot_manager_unsupported.go)
files+=(internal/adapter/mihomo/lab_readback.go internal/adapter/mihomo/lab_readback_test.go
  internal/adapter/mihomo/lab_evidence.go internal/adapter/mihomo/lab_evidence_test.go
  internal/mihomodeploy/lab_authority.go internal/mihomodeploy/lab_authority_test.go
  internal/mihomodeploy/lab_expectation.go internal/mihomodeploy/lab_expectation_test.go
  internal/mihomodeploy/lab_kernel.go internal/mihomodeploy/lab_kernel_linux.go internal/mihomodeploy/lab_kernel_linux_test.go
  internal/mihomodeploy/lab_kernel_unsupported.go internal/mihomodeploy/lab_kernel_unsupported_test.go)
set +e
"${common[@]}" "$goroot/bin/gofmt" -d "${files[@]}" > "$out/gofmt.patch" 2> "$out/gofmt.stderr"
format_code=$?
"${common[@]}" "$goroot/bin/go" test -json -count=1 -timeout=180s ./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn > "$out/ordinary.json" 2> "$out/ordinary.stderr"
ordinary_code=$?
"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s ./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn > "$out/race.json" 2> "$out/race.stderr"
race_code=$?
set -e
printf '{"schema":"chengwang.mihomo-contract-execution/v1","formatExit":%d,"ordinaryExit":%d,"raceExit":%d,"realMihomoExecuted":false,"production":false}\n' "$format_code" "$ordinary_code" "$race_code" > "$out/execution.json"
chmod 0644 "$out/"*.json "$out/"*.stderr "$out/go-version.txt" "$out/gofmt.patch"
test "$format_code" -eq 0
test "$ordinary_code" -eq 0
test "$race_code" -eq 0
# Formatting drift is an independent failure. Originals and patch survive it.
test ! -s "$out/gofmt.patch"
