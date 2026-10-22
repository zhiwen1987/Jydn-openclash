#!/usr/bin/env bash
# D12: real product interruption/reconciliation with external Linux leases.
# No image build, external push, production network or device action is allowed.
set -euo pipefail
umask 077
export PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1
test "$#" -eq 5 || { echo 'usage: run-product-crash-gate.sh RUNROOT GOBIN MODCACHE IMAGEID PRIVATE_ARCHIVE' >&2; exit 2; }
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
image_id=$4
archive=$(/usr/bin/realpath -e -- "$5")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
source_root=$(/usr/bin/git -C "$script_root" rev-parse --show-toplevel)
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
checker="$source_root/chengwang/deploy/product-candidate/check_product_crash.py"
registry_image=registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
evidence="$run_root/evidence"
private="$run_root/product-crash-private"
fixture_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
fixture_root="/tmp/chengwang-product-lifecycle-$fixture_uuid"
label_key=org.chengwang.product-crash-fixture
registry_id=''
registry_pid=''
send_job=''
audit_job=''
blob_job=''
stage=''
kind=''
product_id=''
product_pid=''
product_start=''
last_relation=''
last_helper_type=''
last_helper_log=''
helper_stopped=0
sender_stopped=0
phase=initialization
cleaned=false
accepted=false
last_action_log=''
last_action_kind=''
last_action=''
last_case=''
declare -a owned_ids=()
test "$(/usr/bin/id -u)" != 0
[[ "$source_commit" =~ ^[a-f0-9]{40}$ && "$image_id" =~ ^sha256:[a-f0-9]{64}$ && "$fixture_uuid" =~ ^[a-f0-9]{32}$ ]]
case "$run_root/" in "$source_root/"*) exit 2;; esac
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in ext4|xfs) ;; *) echo 'D12 requires durable native /tmp' >&2; exit 1;; esac
test -x "$run_root/bin/product-crash.test"
test -f "$evidence/product-image-packaged-contents.json"
test -f "$evidence/product-image-staging.json"
test -f "$evidence/product-registry-outcome.json"
test -f "$evidence/product-lifecycle-outcome.json"
test -f "$archive" && test ! -L "$archive"
test ! -e "$private" && test ! -e "$fixture_root"
/usr/bin/install -d -m 0700 "$private"
exec 3>&2
exec 2> "$private/shell.private.log"


cleanup_owned() {
  local failed=0 item index job
  for item in audit blob; do
    job=''
    if test "$item" = audit; then job=$audit_job; else job=$blob_job; fi
    if test -n "$job"; then
      control emergency "$item" "$job" >/dev/null 2>&1 || true
      wait "$job" >/dev/null 2>&1 || true
      failed=1
    fi
  done
  if test -n "$send_job"; then
    control emergency send "$send_job" >/dev/null 2>&1 || true
    wait "$send_job" >/dev/null 2>&1 || true
    failed=1
  fi
  for ((index=${#owned_ids[@]}-1; index>=0; index--)); do
    item=${owned_ids[$index]}
    if /usr/bin/docker container inspect "$item" >/dev/null 2>&1; then
      if test "$(/usr/bin/docker inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$item")" != "$fixture_uuid"; then failed=1; continue; fi
      if test "$(/usr/bin/docker inspect --format '{{.State.Running}}' "$item")" = true; then
        failed=1; /usr/bin/docker rm --force "$item" >/dev/null 2>&1 || failed=1
      else /usr/bin/docker rm "$item" >/dev/null 2>&1 || failed=1; fi
      if /usr/bin/docker inspect "$item" >/dev/null 2>&1; then failed=1; fi
    fi
  done
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY' || failed=1
import os,pathlib,re,stat,sys
root,identity=pathlib.Path(sys.argv[1]),sys.argv[2]
assert re.fullmatch(r'[a-f0-9]{32}',identity) and str(root)=='/tmp/chengwang-product-lifecycle-'+identity
if root.exists() or root.is_symlink():
    info=root.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o700 and root.resolve()==root
    owner=root/'.fixture-owner'; meta=owner.lstat()
    assert stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and meta.st_uid==meta.st_gid==10001 and stat.S_IMODE(meta.st_mode)==0o600 and owner.read_bytes()==(identity+'\n').encode()
    def remove(directory):
        for entry in os.scandir(directory):
            current=entry.stat(follow_symlinks=False)
            assert current.st_dev==info.st_dev and current.st_uid in (0,10001)
            if stat.S_ISDIR(current.st_mode): remove(entry.path); os.rmdir(entry.path)
            else: os.unlink(entry.path)
    remove(root); os.rmdir(root)
assert not root.exists() and not root.is_symlink()
PY
  /usr/bin/docker image inspect "$image_id" >/dev/null 2>&1 || failed=1
  /usr/bin/docker image inspect "$registry_image" >/dev/null 2>&1 || failed=1
  test -f "$archive" && test ! -L "$archive" || failed=1
  # Only this runner's explicit private directory is eligible; never export
  # raw inspect, HTTP, token, namespace-path or Registry logging material.
  test "$private" = "$run_root/product-crash-private" && test -d "$private" && test ! -L "$private" || failed=1
  /usr/bin/find "$private" -maxdepth 1 -type f -delete || failed=1
  test "$failed" -eq 0
}
on_exit() {
  local result=$?
  trap - EXIT HUP INT TERM
  if test "$result" -ne 0; then
    echo "D12_PRODUCT_CRASH_FAILURE_PHASE=$phase" >&3
    /usr/bin/python3 -B - "$phase" "$stage" "$kind" "$private" "$last_action_log" "$last_helper_type" "$last_helper_log" > "$evidence/product-crash-failure-diagnostic.json" <<'PY'
import json,os,pathlib,re,stat,sys
phase,stage,kind,private,log,helper_type,helper_log=sys.argv[1:]
assert re.fullmatch(r'[a-z0-9-]{1,128}',phase) and stage in ('','prepared','reserved','consumed') and kind in ('','message-signature','dsse')
assert helper_type in ('','audit','blob')

def safe_log_projection(raw):
    """Pure closed-set projection: never return a log substring or message."""
    result={'failureReason':'NONE','bootstrapStep':'NONE','exceptionClass':'NONE','sourceKind':'NONE','sourceLine':0,'errno':0}
    if type(raw) is not bytes or len(raw)>256<<10: return result
    reasons=frozenset(('ARGUMENTS','UNSUPPORTED','IDENTITY','CAPABILITIES','KERNEL_BREAK_TIME','UNSAFE_DIRECTORY','UNSAFE_FILE','PATH_CHANGED','CONTROL_CONTENT','CONTROL_WRITE','CONTROL_RELEASE','LEASE_UNAVAILABLE','LEASE_RELEASE','DEADLINE','TERMINATED','INTERNAL'))
    classes=frozenset(('AssertionError','OSError','PermissionError','FileNotFoundError','FileExistsError','NotADirectoryError','IsADirectoryError','CalledProcessError','ValueError','TypeError','RuntimeError','ModuleNotFoundError','ImportError','UnicodeDecodeError','MemoryError','SystemExit','OverflowError','TimeoutError','INTERNAL'))
    steps=frozenset(('ARGUMENTS','CONTAINER_IDENTITY','PID_IDENTITY','SOURCE_OPEN','SOURCE_VALIDATE','TARGET_VALIDATE','BIND_ALIAS','REMOUNT_ALIAS','BIND_IDENTITY','PID_RECHECK','BIND_BIN','REMOUNT_BIN','EXEC_SET_PRIV','RESOURCE_LIMITS','RECORD_IDENTITY','RECORD_PUBLISH','EXEC_HELPER'))
    reason_count=bootstrap_count=0; frame=('NONE',0)
    for line in raw.decode('utf-8',errors='replace').splitlines():
        if line.startswith(('D12_BLOB_LEASE_FAILURE=','D12_LEASE_FAILURE=')):
            reason_count+=1
            match=re.fullmatch(r'D12_(?:BLOB_)?LEASE_FAILURE=([A-Z_]{1,40})',line)
            result['failureReason']=match[1] if reason_count==1 and match and match[1] in reasons else 'INVALID'
        match=re.fullmatch(r'D12_(BLOB|HOLDER)_BOOTSTRAP_FAILURE step=([A-Z_]{1,40}) class=([A-Za-z]{1,40}) line=([0-9]{1,5}) errno=([0-9]{1,4})',line)
        if match:
            bootstrap_count+=1; role,step,exception,number,errno=match.groups()
            if bootstrap_count==1 and step in steps and exception in classes and 0<=int(number)<=65535 and 0<=int(errno)<=4095:
                result.update(bootstrapStep=step,exceptionClass=exception,sourceKind='INLINE_STDIN' if role=='BLOB' else 'INLINE_STRING',sourceLine=int(number),errno=int(errno))
            else: result.update(bootstrapStep='INVALID',exceptionClass='NONE',sourceKind='NONE',sourceLine=0,errno=0)
            continue
        if bootstrap_count: continue
        match=re.fullmatch(r'\s*File "(<stdin>|<string>|/tmp/chengwang-product-lifecycle-[a-f0-9]{32}/bin/checker/fixture_(?:blob_)?lease\.py)", line ([1-9][0-9]{0,4})(?:, in [A-Za-z_][A-Za-z0-9_]*)?',line)
        if match and int(match[2])<=65535:
            name=match[1]
            source_kind='INLINE_STDIN' if name=='<stdin>' else 'INLINE_STRING' if name=='<string>' else 'BLOB_HELPER' if name.endswith('/fixture_blob_lease.py') else 'AUDIT_HELPER'
            frame=(source_kind,int(match[2]))
            continue
        match=re.match(r'^([A-Za-z]{1,40})(?::|$)',line)
        if match and match[1] in classes:
            errno=re.search(r'\[Errno ([1-9][0-9]{0,3})\]',line)
            result.update(exceptionClass=match[1],sourceKind=frame[0],sourceLine=frame[1],errno=int(errno[1]) if errno and int(errno[1])<=4095 else 0)
    return result

def read_private_log(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=256<<10
        raw=f.read(before.st_size); after=os.fstat(f.fileno()); named=path.lstat()
        identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid)
        assert len(raw)==before.st_size and identity(before)==identity(after)==identity(named) and before.st_size<=after.st_size
    return raw

source_line=0
if log:
    path=pathlib.Path(log)
    assert path.parent==pathlib.Path(private) and re.fullmatch(r'(prepared|reserved|consumed)-(message-signature|dsse)-(prepare|ready|send|reserved|blocked|cut|recovered|reopen-first|idempotent|probe|reopen-final)\.private\.log',path.name)
    raw=read_private_log(path)
    for row in raw.splitlines():
        match=re.fullmatch(rb'D12_PRODUCT_CRASH_ASSERT_LINE=([1-9][0-9]{0,5})',row.strip())
        if match: source_line=int(match[1])
helper_projection=safe_log_projection(b'')
if helper_log:
    path=pathlib.Path(helper_log)
    assert path.parent==pathlib.Path(private) and path.name==f'{stage}-{kind}-{helper_type}.private.log'
    helper_projection=safe_log_projection(read_private_log(path))
control_projection=safe_log_projection(read_private_log(pathlib.Path(private)/'shell.private.log'))
print(json.dumps({'schema':'chengwang.product-crash-failure/v1','outcome':'FAIL','phase':phase,'stage':stage,'kind':kind,'driverSourceLine':source_line,'helperType':helper_type,'helperDiagnostic':helper_projection,'controlDiagnostic':control_projection,'rawPrivateLogPublished':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
  fi
  if test "$cleaned" != true; then
    if cleanup_owned; then cleaned=true; else echo 'D12_PRODUCT_CRASH_CLEANUP=FAIL production=false' >&3; exit 1; fi
  fi
  if test "$result" -eq 0 && test "$accepted" != true; then exit 1; fi
  exit "$result"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

phase=private-provision
/usr/bin/python3 -B - "$evidence/product-registry-outcome.json" "$source_commit" "$image_id" <<'PY'
import json,pathlib,sys
path,commit,image=sys.argv[1:]; value=json.loads(pathlib.Path(path).read_text())
assert value['schema']=='chengwang.product-registry-gate/v1' and value['outcome']=='PASS' and value['sourceCommit']==commit and value['localImageID']==image
assert value['authorization']=='BLOCKED' and value['production'] is False and value['deviceActionsExecuted'] is False
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1]); root.mkdir(mode=0o700); os.chown(root,10001,10001)
for name in ('bin','tmp','evidence','prepared','reserved','consumed','control','blob','holders'):
    (root/name).mkdir(mode=0o700); os.chown(root/name,10001,10001)
with (root/'.fixture-owner').open('x',encoding='ascii') as f: f.write(sys.argv[2]+'\n')
os.chmod(root/'.fixture-owner',0o600); os.chown(root/'.fixture-owner',10001,10001)
PY
/usr/bin/sudo --non-interactive /usr/bin/install -m 0555 -o 0 -g 0 "$run_root/bin/product-crash.test" "$fixture_root/bin/product-crash.test"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$archive" "$fixture_root/bin/product-image.private.tar"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0444 -o 0 -g 0 "$evidence/product-image-packaged-contents.json" "$fixture_root/bin/product-image-packaged-contents.json"
# OpenSSL output and signing keys remain private. Each CA has a distinct key.
/usr/bin/sudo --non-interactive /usr/bin/bash -euo pipefail -c '
  root=$1
  for purpose in registry api; do
    hostname=$purpose
    if test "$purpose" = source; then hostname=feed; fi
    /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 -subj "/CN=Chengwang isolated D12 $purpose CA" -keyout "$root/bin/$purpose-ca-key.private.pem" -out "$root/$purpose-ca.pem"
    /usr/bin/openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=$hostname.fixture.invalid" -keyout "$root/$purpose-key.private.pem" -out "$root/bin/$purpose.private.csr"
    /usr/bin/printf "subjectAltName=DNS:%s.fixture.invalid,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n" "$hostname" > "$root/bin/$purpose.private.ext"
    /usr/bin/openssl x509 -req -days 2 -sha256 -in "$root/bin/$purpose.private.csr" -CA "$root/$purpose-ca.pem" -CAkey "$root/bin/$purpose-ca-key.private.pem" -set_serial 11 -extfile "$root/bin/$purpose.private.ext" -out "$root/$purpose-cert.pem"
    /usr/bin/chmod 0600 "$root/$purpose-ca.pem" "$root/$purpose-cert.pem" "$root/$purpose-key.private.pem"
    /usr/bin/chown 10001:10001 "$root/$purpose-ca.pem" "$root/$purpose-cert.pem" "$root/$purpose-key.private.pem"
  done
' _ "$fixture_root" > "$private/openssl.private.log" 2>&1
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1])
configuration='''version: 0.1
log:
  level: info
  formatter: json
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/registry
  maintenance:
    uploadpurging:
      enabled: false
http:
  addr: 127.0.0.1:5443
  draintimeout: 5s
  secret: isolated-d11-fixture-not-production
  tls:
    certificate: /certs/server.pem
    key: /certs/server-key.pem
'''
with (root/'registry-config.private.yml').open('x') as f: f.write(configuration)
os.chmod(root/'registry-config.private.yml',0o600); os.chown(root/'registry-config.private.yml',10001,10001)
PY
# A minimal Git-bound helper tree is available to non-root UID10001 even when
# the hosted checkout's parent directories are not traversable. Never chmod HOME.
/usr/bin/python3 -B - "$source_root" "$source_commit" > "$private/tool-input.json" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]); commit=sys.argv[2]
names=tuple('chengwang/deploy/product-candidate/'+name for name in ('check_product_crash.py','check_product_image.py','check_product_registry.py','check_product_lifecycle.py','fixture_lease.py','fixture_blob_lease.py','test_fixture_blob_lease.py','test_crash_image_profile.py','test_check_product_crash.py'))
files={}
for name in names:
    path=root/name
    assert path.is_file() and not path.is_symlink()
    raw=path.read_bytes()
    assert raw==subprocess.check_output(['/usr/bin/git','-C',str(root),'show',commit+':'+name]) and len(raw)<=256<<10
    files[name]=hashlib.sha256(raw).hexdigest()
print(json.dumps({'sourceCommit':commit,'files':files},sort_keys=True))
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_root" "$fixture_root" "$private/tool-input.json" > "$evidence/product-crash-harness.json" <<'PY'
import hashlib,json,os,pathlib,sys
source,root,record=map(pathlib.Path,sys.argv[1:]); data=json.loads(record.read_text())
destination=root/'bin/checker'
destination.mkdir(mode=0o555); os.chmod(destination,0o555)
for name,digest in data['files'].items():
    if pathlib.Path(name).name.startswith('test_'): continue
    original=source/name; raw=original.read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest
    target=destination/pathlib.Path(name).name
    with target.open('xb') as f: f.write(raw)
    os.chmod(target,0o444)
print(json.dumps({'schema':'chengwang.product-crash-harness/v1',**data,'checkoutBytesMatched':True,'permissionReadOnly':True,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY

phase=registry-start
registry_id=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
  --name "cw-product-crash-$fixture_uuid" --label "$label_key=$fixture_uuid" \
  --network none --user 10001:10001 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --env OTEL_TRACES_EXPORTER=none --env OTEL_METRICS_EXPORTER=none --env OTEL_LOGS_EXPORTER=none \
  --memory 256m --memory-swap 256m --cpus 1 --pids-limit 128 --ulimit nofile=1024:1024 --restart no --stop-timeout 15 \
  --tmpfs /var/lib/registry:rw,noexec,nosuid,nodev,size=192m,uid=10001,gid=10001,mode=0700 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700 \
  --mount "type=bind,src=$fixture_root/registry-config.private.yml,dst=/etc/distribution/config.yml,readonly,bind-propagation=rprivate" \
  --mount "type=bind,src=$fixture_root/registry-cert.pem,dst=/certs/server.pem,readonly,bind-propagation=rprivate" \
  --mount "type=bind,src=$fixture_root/registry-key.private.pem,dst=/certs/server-key.pem,readonly,bind-propagation=rprivate" \
  "$registry_image")
[[ "$registry_id" =~ ^[a-f0-9]{64}$ ]]
owned_ids+=("$registry_id")
/usr/bin/docker container start "$registry_id" >/dev/null
registry_pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$registry_id")
[[ "$registry_pid" =~ ^[1-9][0-9]*$ ]]
/usr/bin/docker image inspect "$image_id" > "$private/product-image-inspect.json"
/usr/bin/docker image inspect "$registry_image" > "$private/registry-image-inspect.json"
/usr/bin/docker container inspect "$registry_id" > "$private/registry-container-inspect.json"

in_fixture() {
  /usr/bin/sudo --non-interactive /usr/bin/nsenter --net="/proc/$registry_pid/ns/net" -- \
    /usr/bin/unshare --mount --propagation private /usr/bin/bash -euo pipefail -c '
      root=$1; shift
      cd "$root"
      test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
      test -z "$(/usr/sbin/ip -o route show default)"
      test -z "$(/usr/sbin/ip -6 -o route show default)"
      /usr/bin/mount --bind "$root/bin" "$root/bin"
      /usr/bin/mount -o remount,bind,ro "$root/bin"
      exec /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
        /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1 HOME="$root" TMPDIR="$root/tmp" \
          /usr/bin/bash -euo pipefail -c '\''
            test "$(/usr/bin/id -u):$(/usr/bin/id -g)" = 10001:10001
            /usr/bin/grep -qE "^NoNewPrivs:[[:space:]]+1$" /proc/self/status
            for field in CapInh CapPrm CapEff CapBnd CapAmb; do /usr/bin/grep -qE "^${field}:[[:space:]]+0000000000000000$" /proc/self/status; done
            exec /usr/bin/env "$@"
          '\'' _ "$@"
    ' _ "$fixture_root" "$@"
}
wait_tls() {
  in_fixture /usr/bin/python3 -B -c '
import pathlib,socket,ssl,sys,time
root,role,port=sys.argv[1],sys.argv[2],int(sys.argv[3]); ctx=ssl.create_default_context(cafile=root+"/"+role+"-ca.pem")
hostname="feed" if role=="source" else role
deadline=time.monotonic()+15
while True:
    try:
        with socket.create_connection(("127.0.0.1",port),timeout=1) as raw:
            with ctx.wrap_socket(raw,server_hostname=hostname+".fixture.invalid") as secure:
                assert secure.version() in ("TLSv1.2","TLSv1.3")
        break
    except (OSError,ssl.SSLError):
        if time.monotonic()>=deadline: raise SystemExit("D12_TLS_READINESS=FAIL")
        time.sleep(.1)
print("D12_TLS_READINESS=PASS normal_tls=true http_requests=0")
' "$fixture_root" "$1" "$2"
}
in_fixture /usr/bin/python3 -B -c '
import json,socket,sys
for family,address in ((socket.AF_INET,("1.1.1.1",443)),(socket.AF_INET6,("2606:4700:4700::1111",443,0,0))):
    try:
        with socket.socket(family,socket.SOCK_STREAM) as stream:
            stream.settimeout(.5); stream.connect(address)
    except OSError: continue
    raise SystemExit("D12_EXTERNAL_CONNECTIVITY=FAIL")
print(json.dumps({"schema":"chengwang.product-registry-network/v1","sourceCommit":sys.argv[1],"registryContainerID":sys.argv[2],"loopbackOnly":True,"defaultRoutes":0,"externalIPv4Blocked":True,"externalIPv6Blocked":True,"authorization":"BLOCKED","production":False,"deviceActionsExecuted":False},sort_keys=True))
' "$source_commit" "$registry_id" > "$evidence/product-crash-network.json"
wait_tls registry 5443
/usr/bin/python3 -B - "$private/registry-image-inspect.json" "$private/registry-container-inspect.json" "$registry_id" "$registry_image" "$fixture_root" "$source_commit" > "$evidence/product-crash-isolation.json" <<'PY'
import hashlib,json,pathlib,re,sys
ip,cp,identity,pin,root,commit=sys.argv[1:]; image=json.loads(pathlib.Path(ip).read_text())[0]; c=json.loads(pathlib.Path(cp).read_text())[0]
h=c['HostConfig']; cfg=c['Config']; state=c['State']
canonical_pin='registry@'+pin.split('@',1)[1]
assert c['Id']==identity and c['Image']==image['Id'] and canonical_pin in image['RepoDigests'] and image['Os']=='linux' and image['Architecture']=='amd64'
assert cfg['User']=='10001:10001' and cfg['Entrypoint']==image['Config']['Entrypoint'] and cfg['Cmd']==image['Config']['Cmd']
otel=['OTEL_TRACES_EXPORTER=none','OTEL_METRICS_EXPORTER=none','OTEL_LOGS_EXPORTER=none']
def env_mapping(value):
    # Docker's inherited/explicit merge has no meaningful ordering contract.
    # Preserve every base name/value while rejecting duplicate keys and malformed
    # records, rather than sorting a list that could hide duplicate authority.
    shape=isinstance(value,list) and len(value)<=256
    unique=True
    result={}
    if shape:
        for item in value:
            if not isinstance(item,str) or not 1<=len(item)<=32768 or '\0' in item or '=' not in item:
                shape=False
                continue
            name,content=item.split('=',1)
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name) is None:
                shape=False
                continue
            if name in result: unique=False
            result[name]=content
    return (result if shape and unique else None),shape,unique

def registry_environment_projection(base,actual):
    inherited,base_shape,base_unique=env_mapping(base)
    observed,actual_shape,actual_unique=env_mapping(actual)
    expected=None if inherited is None else {**inherited,**dict(item.split('=',1) for item in otel)}
    equivalent=expected is not None and observed is not None and expected==observed
    digest=lambda value: hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return equivalent,{'schema':'chengwang.product-crash-env-diagnostic/v1','baseShapeValid':base_shape,'baseKeysUnique':base_unique,'actualShapeValid':actual_shape,'actualKeysUnique':actual_unique,'expectedCount':len(expected) if expected is not None else 0,'actualCount':len(observed) if observed is not None else 0,'expectedMappingSHA256':digest(expected),'actualMappingSHA256':digest(observed),'equivalent':equivalent}

base_environment=image['Config'].get('Env')
if base_environment is None: base_environment=[]
environment_ok,environment_diagnostic=registry_environment_projection(base_environment,cfg.get('Env'))
if not environment_ok:
    print(json.dumps(environment_diagnostic,sort_keys=True),file=sys.stderr)
    raise SystemExit('D12_REGISTRY_ENV_CHECK=FAIL raw_environment_suppressed=true')
assert h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['Privileged'] is False and h['CapDrop']==['ALL'] and not h.get('CapAdd')
assert h['SecurityOpt'] in (['no-new-privileges'],['no-new-privileges:true'],['no-new-privileges=true'])
for key,value in {'Memory':268435456,'MemorySwap':268435456,'NanoCpus':1000000000,'PidsLimit':128}.items(): assert type(h[key]) is int and h[key]==value
assert h['Ulimits']==[{'Name':'nofile','Hard':1024,'Soft':1024}] and h['RestartPolicy']=={'Name':'no','MaximumRetryCount':0} and cfg['StopTimeout']==15 and h['AutoRemove'] is False and not h.get('Init')
for key in ('Devices','DeviceRequests','DeviceCgroupRules','VolumesFrom','Links','ExtraHosts','Dns','DnsSearch','DnsOptions','GroupAdd','Sysctls','PortBindings','PublishAllPorts','PidMode','UTSMode','UsernsMode','CgroupParent','OomKillDisable'): assert not h.get(key)
assert h.get('IpcMode') in ('private','',None) and h.get('CgroupnsMode') in ('private','',None)
expected={'/etc/distribution/config.yml':root+'/registry-config.private.yml','/certs/server.pem':root+'/registry-cert.pem','/certs/server-key.pem':root+'/registry-key.private.pem'}
binds=[m for m in c['Mounts'] if m['Type']=='bind']; assert len(binds)==3 and {m['Destination'] for m in binds}==set(expected)
for m in binds: assert m['Source']==expected[m['Destination']] and m['RW'] is False and m['Propagation']=='rprivate'
assert all(m['Type'] in ('bind','tmpfs') for m in c['Mounts'])
tmp=h['Tmpfs']; assert set(tmp)=={'/tmp','/var/lib/registry'}
for dest,size in (('/tmp','16m'),('/var/lib/registry','192m')):
    options=set(tmp[dest].split(',')); assert {'rw','noexec','nosuid','nodev','size='+size,'uid=10001','gid=10001','mode=0700'}==options
ports=c['NetworkSettings'].get('Ports') or {}
assert isinstance(ports,dict) and all(value in (None,[]) for value in ports.values())
assert state['Running'] is True and state['Pid']>0 and not state['OOMKilled'] and not state.get('Error')
print(json.dumps({'schema':'chengwang.product-registry-isolation/v1','sourceCommit':commit,'registryContainerID':identity,'pinnedImage':pin,'actualImageID':image['Id'],'pinnedImageMatched':True,'networkMode':'none','securityProfileVerified':True,'normalTLSVerified':True,'readOnlyRootfs':True,'user':'10001:10001','capDrop':['ALL'],'noNewPrivileges':True,'memory':268435456,'memorySwap':268435456,'nanoCpus':1000000000,'pidsLimit':128,'tmpfsBytes':201326592,'tmpBytes':16777216,'roFileBindCount':3,'hostPorts':0,'privileged':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY

control() {
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$source_commit" "$stage" "$kind" "$registry_pid" "$product_pid" "$product_start" "$source_root" "$registry_id" "$last_relation" "$@" <<'PY'
import hashlib,json,os,pathlib,re,signal,stat,subprocess,sys,time
root,commit,stage,kind,registry,product,start,source,registry_id,last_relation,mode,*args=sys.argv[1:]
root=pathlib.Path(root)
assert re.fullmatch(r'/tmp/chengwang-product-lifecycle-[a-f0-9]{32}',str(root))
assert stage in ('prepared','reserved','consumed') and kind in ('message-signature','dsse')
boundary={'sourceCommit':commit,'stage':stage,'kind':kind,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False}
limits={'cpuSeconds':10,'addressSpaceBytes':268435456,'fileBytes':1048576,'openFiles':64,'processes':64,'coreBytes':0}
def emit(schema,**values): print(json.dumps({'schema':schema,**boundary,**values},sort_keys=True))
def safe(path,limit=65536):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno()); assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==s.st_gid==10001 and 0<=s.st_size<=limit
        raw=f.read(limit+1); assert len(raw)==s.st_size and (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(os.fstat(f.fileno()).st_dev,os.fstat(f.fileno()).st_ino,os.fstat(f.fileno()).st_size,os.fstat(f.fileno()).st_mtime_ns)
    return raw
def load(path): return json.loads(safe(path))
def process(pid):
    p=pathlib.Path('/proc')/str(pid); raw=(p/'stat').read_text().rsplit(')',1)[1].split()
    assert raw[0] not in ('Z','X')
    fields=dict(row.split(':',1) for row in (p/'status').read_text().splitlines())
    assert all(fields[n].split()==['10001']*4 for n in ('Uid','Gid')) and fields['NoNewPrivs'].strip()=='1'
    assert all(int(fields[n].strip(),16)==0 for n in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    return p,int(raw[19]),fields
def record(which):
    assert which in ('audit','blob','send')
    value=load(root/'holders'/f'{which}-{stage}-{kind}'/'process.private.json')
    assert set(value)=={'pid','startTime'} and type(value['pid']) is int and value['pid']>1 and type(value['startTime']) is int and value['startTime']>0
    return value
def ancestry(pid,job):
    for _ in range(24):
        if pid==job: return
        pid=int(dict(row.split(':',1) for row in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines())['PPid'])
        assert pid>1
    raise AssertionError('ancestry')
def control_dir(which): return root/'control'/((f'blob-{stage}-{kind}') if which=='blob' else f'{stage}-{kind}')
def helper(which,job):
    rec=record(which); p,at,fields=process(rec['pid']); assert at==rec['startTime']; ancestry(rec['pid'],int(job))
    name='fixture_blob_lease.py' if which=='blob' else 'fixture_lease.py'
    expected=['/usr/bin/python3','-B',str(root/'bin/checker'/name),'hold','--fixture-root',str(root),'--case',stage,'--kind',kind,'--control-dir',str(control_dir(which))]
    if which=='blob': expected+=['--digest',load(root/'evidence'/f'product-crash-{stage}-{kind}-prepare.json')['configSHA256']]
    expected+=['--deadline-seconds','8']
    assert (p/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==expected
    assert (p/'ns/net').readlink()==pathlib.Path(f'/proc/{registry}/ns/net').readlink() and (p/'ns/mnt').readlink()!=pathlib.Path('/proc/self/ns/mnt').readlink()
    names={'cpuSeconds':'Max cpu time','addressSpaceBytes':'Max address space','fileBytes':'Max file size','openFiles':'Max open files','processes':'Max processes','coreBytes':'Max core file size'}
    rows=(p/'limits').read_text().splitlines()
    for key,name_limit in names.items():
        selected=[row for row in rows if row.startswith(name_limit+' ')]
        assert len(selected)==1 and re.fullmatch(re.escape(name_limit)+r'\s+'+str(limits[key])+r'\s+'+str(limits[key])+r'(?:\s+[a-z]+)?\s*',selected[0])
    copied=root/'bin/checker'/name; original=pathlib.Path(source)/'chengwang/deploy/product-candidate'/name
    script_digest=hashlib.sha256(copied.read_bytes()).hexdigest(); assert script_digest==hashlib.sha256(original.read_bytes()).hexdigest()
    executable=hashlib.sha256((p/'exe').read_bytes()).hexdigest(); assert executable==hashlib.sha256(pathlib.Path('/usr/bin/python3').read_bytes()).hexdigest()
    return rec,{'hostPID':rec['pid'],'startTime':at,'uid':10001,'gid':10001,'capabilities':'none','noNewPrivileges':True,'privateMountNamespace':True,'registryNetworkNamespaceMatched':True,'sourceSHA256':script_digest,'pythonExecutableSHA256':executable,'sourceLimits':limits,'sourceLimitsVerified':True}
def config_target():
    digest=load(root/'evidence'/f'product-crash-{stage}-{kind}-prepare.json')['configSHA256']; assert re.fullmatch(r'sha256:[a-f0-9]{64}',digest)
    h=digest[7:]; path='/var/lib/registry/docker/registry/v2/blobs/sha256/'+h[:2]+'/'+h+'/data'
    return pathlib.Path('/proc')/registry/'root'/path[1:],path,digest
def target(which):
    if which=='blob': file,named,digest=config_target()
    else: file=root/stage/kind/'data/evidence/events.jsonl'; named=str(file); digest=None
    # Never open a leased blob here: a second reader would itself break it.
    s=file.stat(); assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==s.st_gid==10001 and stat.S_IMODE(s.st_mode) in ((0o600,0o644) if which=='blob' else (0o600,))
    return file,named,s,digest
lock_re=re.compile(r'^(\d+):\s+(?:(->)\s+)?LEASE\s+(ACTIVE|BREAKING|BREAKER)\s+(READ|WRITE|UNLCK)\s+(\d+)\s+((?:[0-9a-fA-F]+:[0-9a-fA-F]+:\d+)|(?:<none>:0))\s+0\s+EOF$')
def lock_rows():
    raw=pathlib.Path('/proc/locks').read_text(); assert len(raw)<=4<<20
    return [(line,lock_re.fullmatch(line)) for line in raw.splitlines() if 'LEASE' in line]
def inode_key(s): return (os.major(s.st_dev),os.minor(s.st_dev),s.st_ino)
def parsed_key(value):
    if value=='<none>:0': return None
    a,b,c=value.split(':'); return int(a,16),int(b,16),int(c)
def wait_sample(which,holder,waiter,expected_start,named,s):
    hp,hat,_=process(holder['pid']); assert hat==holder['startTime']
    wp,wat,fields=process(waiter); assert wat==expected_start and fields['NSpid'].split()[-1]=='1'
    tids={int(p.name) for p in (wp/'task').iterdir()}; candidates=[]
    rows=lock_rows()
    for hline,h in rows:
        if h is None or h[2] or h[3]!='BREAKING' or int(h[5])!=holder['pid'] or parsed_key(h[6])!=inode_key(s): continue
        wanted='READ' if which=='blob' else 'UNLCK'; access='READ' if which=='blob' else 'WRITE'
        assert h[4]==wanted
        for wline,w in rows:
            if w is None or not w[2] or w[1]!=h[1] or w[3]!='BREAKER' or w[4]!=access or int(w[5]) not in tids|{int(waiter)}: continue
            assert parsed_key(w[6]) in (None,inode_key(s))
            for tid in tids:
                task=wp/'task'/str(tid)
                try:
                    call=(task/'syscall').read_text().split()
                    if not call or call[0]!='257': continue
                    flags=int(call[3],0)
                    mem=os.open(wp/'mem',os.O_RDONLY|os.O_CLOEXEC)
                    try: raw_name=os.pread(mem,4096,int(call[2],0))
                    finally: os.close(mem)
                    assert b'\0' in raw_name
                    if raw_name.split(b'\0',1)[0].decode()!=named: continue
                    assert flags & os.O_ACCMODE==(os.O_RDONLY if which=='blob' else os.O_WRONLY) and not flags & os.O_NONBLOCK
                    assert int(dict(row.split(':',1) for row in (task/'status').read_text().splitlines())['Tgid'])==int(waiter)
                    wchan=(task/'wchan').read_text().strip(); assert re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}',wchan)
                    candidates.append({'lockID':int(h[1]),'holderState':h[3],'holderTarget':h[4],'waiterPID':int(w[5]),'waiterTarget':w[4],'waiterHasInode':parsed_key(w[6]) is not None,'waiterTID':tid,'syscallNumber':257,'syscallName':'openat','openFlags':flags,'wchan':wchan,'sameTargetPath':True,'holderInodeMatched':True,'waiterTGIDMatched':True,'monotonicNS':time.monotonic_ns(),'holderLockLine':hline,'waiterLockLine':wline})
                except (FileNotFoundError,ProcessLookupError): continue
    assert len(candidates)==1
    return candidates[0]
def counters():
    import collections
    result=subprocess.run(['/usr/bin/docker','logs',registry_id],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True)
    assert len(result.stdout)<=32<<20
    digests,other=collections.Counter(),collections.Counter()
    for line in result.stdout.decode().splitlines():
        if not line.startswith('{'): continue
        value=json.loads(line)
        if value.get('msg')!='response completed': continue
        method,uri,status=value.get('http.request.method'),value.get('http.request.uri'),value.get('http.response.status')
        assert method in ('GET','HEAD','POST','PATCH','PUT','DELETE','OPTIONS') and type(status) is int and 100<=status<=599 and isinstance(uri,str)
        match=re.fullmatch(r'/v2/chengwang/product-candidate/(?:manifests|blobs)/(sha256:[a-f0-9]{64})',uri)
        if method in ('GET','HEAD') and match: digests[(method,match[1],status)]+=1
        else: other[(method,status)]+=1
    return {'digestRequests':[{'method':m,'digest':d,'status':s,'count':n} for (m,d,s),n in sorted(digests.items())],'otherRequests':[{'method':m,'status':s,'count':n} for (m,s),n in sorted(other.items())]}
if mode=='wait':
    which,event,job=args; deadline=time.monotonic()+2
    while True:
        try:
            value=load(control_dir(which)/(event+'.json'))
            projection=helper(which,job)[1] if event!='released' else None
            if event=='released':
                rec=record(which)
                try:
                    status=pathlib.Path('/proc',str(rec['pid']),'stat').read_text().rsplit(')',1)[1].split()
                    assert int(status[19])!=rec['startTime'] or status[0] in ('Z','X')
                except FileNotFoundError: pass
            assert value['event']==event.upper() and value['case']==stage and value['kind']==kind and value['deadlineSeconds']==8 and value['uid']==value['gid']==10001 and value['capNone'] is True and value['authorization']=='BLOCKED' and value['production'] is False
            assert value['blockedObserved'] is (event!='ready')
            print(json.dumps({'event':value,'process':projection},sort_keys=True)); break
        except FileNotFoundError:
            if time.monotonic()>=deadline: raise
            time.sleep(.01)
elif mode=='observe':
    which,job=args; holder,_=helper(which,job); file,named,s,digest=target(which)
    if which=='blob':
        ready=load(control_dir(which)/'ready.json')
        assert (ready['deviceMajor'],ready['deviceMinor'],ready['inode'],ready['size'],ready['digest'])==(*inode_key(s),s.st_size,digest)
        waiter=int(registry); expected_start=int(pathlib.Path('/proc',registry,'stat').read_text().rsplit(')',1)[1].split()[19])
    else:
        waiter=int(product); expected_start=int(start); digest='sha256:'+hashlib.sha256(safe(file,4<<20)).hexdigest()
    deadline=time.monotonic()+1; samples=[]
    while len(samples)<2:
        try: samples.append(wait_sample(which,holder,waiter,expected_start,named,s)); time.sleep(.005)
        except AssertionError:
            if time.monotonic()>=deadline: raise
            samples=[]; time.sleep(.005)
    print(json.dumps({'type':which,'target':{'deviceMajor':os.major(s.st_dev),'deviceMinor':os.minor(s.st_dev),'inode':s.st_ino,'size':s.st_size,'digest':digest},'holderPID':holder['pid'],'holderStartTime':holder['startTime'],'waiterTGID':waiter,'waiterStartTime':expected_start,'expectedAccess':'READ' if which=='blob' else 'WRITE','samples':samples},sort_keys=True))
elif mode=='release':
    which,=args; folder=control_dir(which)
    fd=os.open(folder/'release',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    os.fchown(fd,10001,10001); os.fsync(fd); os.close(fd); print(time.monotonic_ns())
elif mode=='emergency':
    which,job=args; rec=record(which); fd=os.pidfd_open(rec['pid'])
    try:
        _,at,_=process(rec['pid']); assert at==rec['startTime']; ancestry(rec['pid'],int(job)); signal.pidfd_send_signal(fd,signal.SIGTERM)
    finally: os.close(fd)
elif mode=='kill':
    container,image,job=args; pid=int(product); held=os.pidfd_open(pid)
    try:
        p,at,fields=process(pid); assert at==int(start) and fields['NSpid'].split()[-1]=='1'
        assert (p/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==['/app/image-trust-api','--config',str(root/stage/kind/'trust-config.json'),'--product-config',str(root/stage/kind/'product-config.json')]
        assert (p/'ns/net').readlink()==pathlib.Path(f'/proc/{registry}/ns/net').readlink()
        assert hashlib.sha256((p/'exe').read_bytes()).hexdigest()==json.loads((root/'bin/product-image-packaged-contents.json').read_bytes())['files']['app/image-trust-api']['sha256']
        client=record('send'); _,client_start,_=process(client['pid']); assert client_start==client['startTime']; ancestry(client['pid'],int(job))
        assert (root/stage/kind/'intent-send.private').is_file() and not (root/'evidence'/f'product-crash-{stage}-{kind}-send.json').exists()
        relation=json.loads(pathlib.Path(last_relation).read_bytes()); last=relation['samples'][-1]['monotonicNS']; now=time.monotonic_ns(); assert 0<now-last<2000000000
        signal.pidfd_send_signal(held,signal.SIGKILL)
        emit('chengwang.product-crash-kill/v1',localImageID=image,containerID=container,hostPID=pid,startTime=at,signal='SIGKILL',signalNumber=9,pidfd=True,identityVerified=True,clientPendingBeforeSignal=True,lastBlockMonotonicNS=last,signalMonotonicNS=now,exitCode=137,oomKilled=False,pid=0)
    finally: os.close(held)
elif mode=='snapshot':
    window,position,record_path=args; assert window in ('prepare','drain','recover','idempotent','probe') and position in ('before','after')
    path=pathlib.Path(record_path); values=json.loads(path.read_bytes()) if path.exists() else []
    values.append({'ordinal':len(values)+1,'stage':stage,'kind':kind,'window':window,'position':position,**counters()})
    with path.open('w',encoding='ascii') as f: json.dump(values,f,sort_keys=True); f.write('\n')
    os.chmod(path,0o600)
elif mode=='drain':
    file,_,s,_=target('blob'); deadline=time.monotonic()+5; samples=[]
    while len(samples)<2:
        active=subprocess.check_output(['/usr/bin/nsenter','--net=/proc/'+registry+'/ns/net','--','/usr/bin/ss','-Hnt','(','sport','=','5443','or','dport','=','5443',')']).decode().splitlines()
        active=[line for line in active if line.split()[0] not in ('TIME-WAIT','CLOSED')]
        opened=0
        for fd in pathlib.Path('/proc',registry,'fd').iterdir():
            try:
                current=fd.stat()
                if inode_key(current)==inode_key(s): opened+=1
            except FileNotFoundError: pass
        leases=sum(1 for _,row in lock_rows() if row is not None and parsed_key(row[6])==inode_key(s))
        count=counters(); digest=hashlib.sha256(json.dumps(count,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if not active and opened==leases==0:
            item={'ordinal':len(samples)+1,'activeConnections':0,'targetOpenFDs':0,'pendingLeases':0,'completedRequests':sum(v['count'] for rows in count.values() for v in rows),'countersSHA256':digest,'monotonicNS':time.monotonic_ns()}
            if samples and samples[-1]['countersSHA256']!=digest: samples=[]; item['ordinal']=1
            samples.append(item)
        else: samples=[]
        if time.monotonic()>=deadline: raise AssertionError('drain deadline')
        if len(samples)<2: time.sleep(.15)
    emit('chengwang.product-crash-drain/v1',samples=samples)
else: raise AssertionError('control mode')
PY
}

blob_in_fixture() {
  /usr/bin/sudo --non-interactive /usr/bin/nsenter --net="/proc/$registry_pid/ns/net" -- \
    /usr/bin/unshare --mount --propagation private /usr/bin/python3 -B - "$fixture_root" "$stage" "$kind" "$config_digest" "$registry_pid" "$evidence/product-crash-registry-process.json" "$registry_id" "$@" <<'PY'
import hashlib,json,os,pathlib,re,stat,subprocess,sys
bootstrap_step='ARGUMENTS'
try:
    bootstrap_step='ARGUMENTS'
    root,stage,kind,digest,pid,record,container,*command=sys.argv[1:]
    assert re.fullmatch(r'/tmp/chengwang-product-lifecycle-[a-f0-9]{32}',root) and stage in ('reserved','consumed') and kind in ('message-signature','dsse') and re.fullmatch(r'sha256:[a-f0-9]{64}',digest)
    identity=json.loads(pathlib.Path(record).read_bytes())
    assert identity['hostPID']==int(pid) and identity['registryContainerID']==container and re.fullmatch(r'[a-f0-9]{64}',container)
    bootstrap_step='CONTAINER_IDENTITY'
    actual=json.loads(subprocess.check_output(['/usr/bin/docker','inspect',container]))[0]
    assert actual['Id']==container and actual['State']['Running'] is True and actual['State']['Pid']==int(pid) and actual['Config']['Labels']['org.chengwang.product-crash-fixture']==root.rsplit('-',1)[1]
    bootstrap_step='PID_IDENTITY'
    held=os.pidfd_open(int(pid))
    try:
        process=pathlib.Path('/proc')/pid
        assert int((process/'stat').read_text().rsplit(')',1)[1].split()[19])==json.loads(pathlib.Path(record).read_bytes())['startTime']
        h=digest[7:]; original=process/'root/var/lib/registry/docker/registry/v2/blobs/sha256'/h[:2]/h/'data'
        bootstrap_step='SOURCE_OPEN'
        fd=os.open(original,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            bootstrap_step='SOURCE_VALIDATE'
            info=os.fstat(fd); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode) in (0o600,0o644) and 0<info.st_size<=1<<20
            raw=os.read(fd,(1<<20)+1); assert len(raw)==info.st_size and 'sha256:'+hashlib.sha256(raw).hexdigest()==digest
            bootstrap_step='TARGET_VALIDATE'
            target=pathlib.Path(root)/'blob'/stage/kind/'data'; placeholder=target.lstat()
            assert stat.S_ISREG(placeholder.st_mode) and placeholder.st_size==0 and placeholder.st_nlink==1 and placeholder.st_uid==placeholder.st_gid==10001 and stat.S_IMODE(placeholder.st_mode)==0o600
            # The validated blob mount belongs to Registry, not this helper
            # namespace. Clone there, restore here, then attach only read-only.
            bootstrap_step='BIND_ALIAS'
            sys.path.insert(0,root+'/bin/checker')
            import fixture_blob_lease
            source_mount_ns_fd=os.open(process/'ns/mnt',os.O_RDONLY|os.O_CLOEXEC)
            try:
                fixture_blob_lease.bind_readonly_foreign_blob(fd,source_mount_ns_fd,str(target))
            finally: os.close(source_mount_ns_fd)
            bootstrap_step='BIND_IDENTITY'
            current=target.stat(); assert (current.st_dev,current.st_ino,current.st_size)==(info.st_dev,info.st_ino,info.st_size)
        finally: os.close(fd)
        bootstrap_step='PID_RECHECK'
        assert int((process/'stat').read_text().rsplit(')',1)[1].split()[19])==json.loads(pathlib.Path(record).read_bytes())['startTime']
        bootstrap_step='BIND_BIN'
        subprocess.run(['/usr/bin/mount','--bind',root+'/bin',root+'/bin'],check=True)
        bootstrap_step='REMOUNT_BIN'
        subprocess.run(['/usr/bin/mount','-o','remount,bind,ro',root+'/bin'],check=True)
    finally: os.close(held)
    os.chdir(root)
    bootstrap_step='EXEC_SET_PRIV'
    os.execv('/usr/bin/setpriv',['/usr/bin/setpriv','--reuid=10001','--regid=10001','--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','TZ=UTC','PYTHONOPTIMIZE=0','PYTHONDONTWRITEBYTECODE=1','HOME='+root,'TMPDIR='+root+'/tmp',*command])
except BaseException as error:
    allowed=frozenset(('AssertionError','OSError','PermissionError','FileNotFoundError','FileExistsError','NotADirectoryError','IsADirectoryError','CalledProcessError','ValueError','TypeError','RuntimeError','ModuleNotFoundError','ImportError','UnicodeDecodeError','MemoryError','SystemExit','OverflowError','TimeoutError'))
    exception=type(error).__name__; exception=exception if exception in allowed else 'INTERNAL'
    errno=getattr(error,'errno',0); errno=errno if type(errno) is int and 0<=errno<=4095 else 0
    line=0; frame=error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename=='<stdin>': line=frame.tb_lineno
        frame=frame.tb_next
    line=line if type(line) is int and 0<=line<=65535 else 0
    print(f'D12_BLOB_BOOTSTRAP_FAILURE step={bootstrap_step} class={exception} line={line} errno={errno}',file=sys.stderr)
    raise SystemExit(1) from None
PY
}

# The same bounded wrapper atomically records its identity, then execs the
# actual helper/driver. The record never appears inside an empty control dir.
record_exec_code='
import ctypes,json,os,pathlib,resource,sys
bootstrap_step="RESOURCE_LIMITS"
try:
    record,role,*command=sys.argv[1:]
    if role!="send":
        for limit,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,10),(resource.RLIMIT_AS,256<<20),(resource.RLIMIT_FSIZE,1<<20),(resource.RLIMIT_NOFILE,64),(resource.RLIMIT_NPROC,64)):
            resource.setrlimit(limit,(value,value))
    bootstrap_step="RECORD_IDENTITY"
    path=pathlib.Path(record); pending=path.with_name(".process.private.pending")
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,"wb") as output:
        output.write(json.dumps({"pid":os.getpid(),"startTime":int(pathlib.Path("/proc/self/stat").read_text().rsplit(")",1)[1].split()[19])},sort_keys=True).encode()+b"\n"); output.flush(); os.fsync(output.fileno())
    bootstrap_step="RECORD_PUBLISH"
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        rename=ctypes.CDLL(None,use_errno=True).renameat2
        rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint); rename.restype=ctypes.c_int
        assert rename(directory,pending.name.encode(),directory,path.name.encode(),1)==0
        os.fsync(directory)
    finally: os.close(directory)
    bootstrap_step="EXEC_HELPER"
    os.execv(command[0],command)
except BaseException as error:
    allowed=frozenset(("AssertionError","OSError","PermissionError","FileNotFoundError","FileExistsError","NotADirectoryError","IsADirectoryError","CalledProcessError","ValueError","TypeError","RuntimeError","ModuleNotFoundError","ImportError","UnicodeDecodeError","MemoryError","SystemExit","OverflowError","TimeoutError"))
    exception=type(error).__name__; exception=exception if exception in allowed else "INTERNAL"
    errno=getattr(error,"errno",0); errno=errno if type(errno) is int and 0<=errno<=4095 else 0
    line=0; frame=error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename=="<string>": line=frame.tb_lineno
        frame=frame.tb_next
    line=line if type(line) is int and 0<=line<=65535 else 0
    print(f"D12_HOLDER_BOOTSTRAP_FAILURE step={bootstrap_step} class={exception} line={line} errno={errno}",file=sys.stderr)
    raise SystemExit(1) from None
'

fixture_action() {
  local action=$1 log marker marker_action
  log="$private/$stage-$kind-$action.private.log"
  last_action_log=$log
  phase="$action-$stage-$kind"
  if test "$action" = send; then
    in_fixture /usr/bin/env CHENGWANG_CRASH_ROOT="$fixture_root" CHENGWANG_CRASH_STAGE="$stage" \
      CHENGWANG_CRASH_KIND="$kind" CHENGWANG_CRASH_ACTION="$action" CHENGWANG_CRASH_IMAGE_ID="$image_id" \
      CHENGWANG_CRASH_COMMIT="$source_commit" CHENGWANG_CRASH_ARCHIVE="$fixture_root/bin/product-image.private.tar" \
      /usr/bin/python3 -B -c "$record_exec_code" "$fixture_root/holders/send-$stage-$kind/process.private.json" send \
      /usr/bin/timeout --signal=TERM --kill-after=3s 60s "$fixture_root/bin/product-crash.test" \
      -test.run='^TestProductCrashD12Fixture$' -test.v -test.timeout=55s 2>&1 | /usr/bin/tee "$log" >/dev/null
  else
    in_fixture /usr/bin/env CHENGWANG_CRASH_ROOT="$fixture_root" CHENGWANG_CRASH_STAGE="$stage" \
      CHENGWANG_CRASH_KIND="$kind" CHENGWANG_CRASH_ACTION="$action" CHENGWANG_CRASH_IMAGE_ID="$image_id" \
      CHENGWANG_CRASH_COMMIT="$source_commit" CHENGWANG_CRASH_ARCHIVE="$fixture_root/bin/product-image.private.tar" \
      /usr/bin/timeout --signal=TERM --kill-after=3s 60s "$fixture_root/bin/product-crash.test" \
      -test.run='^TestProductCrashD12Fixture$' -test.v -test.timeout=55s 2>&1 | /usr/bin/tee "$log" >/dev/null
  fi
  marker_action=${action^^}; marker_action=${marker_action//-/_}
  marker="D12_PRODUCT_CRASH_$marker_action=PASS stage=$stage kind=$kind authorization=BLOCKED production=false"
  test "$(/usr/bin/grep -Fxc -- "$marker" "$log")" -eq 1
  test "$(/usr/bin/grep -Ec '^--- PASS: TestProductCrashD12Fixture \(' "$log")" -eq 1
  echo "$marker"
}

start_holder() {
  local which=$1 directory control_path
  phase="start-holder-$which-$stage-$kind"
  last_helper_type=$which
  last_helper_log="$private/$stage-$kind-$which.private.log"
  directory="$fixture_root/holders/$which-$stage-$kind"
  if test "$which" = blob; then
    control_path="$fixture_root/control/blob-$stage-$kind"
    blob_in_fixture /usr/bin/python3 -B -c "$record_exec_code" "$directory/process.private.json" blob \
      /usr/bin/python3 -B "$fixture_root/bin/checker/fixture_blob_lease.py" hold \
      --fixture-root "$fixture_root" --case "$stage" --kind "$kind" --control-dir "$control_path" \
      --digest "$config_digest" --deadline-seconds 8 > "$private/$stage-$kind-blob.private.log" 2>&1 &
    blob_job=$!
    phase="wait-holder-ready-blob-$stage-$kind"
    control wait blob ready "$blob_job" > "$private/$stage-$kind-blob-ready.json"
  else
    control_path="$fixture_root/control/$stage-$kind"
    in_fixture /usr/bin/python3 -B -c "$record_exec_code" "$directory/process.private.json" audit \
      /usr/bin/python3 -B "$fixture_root/bin/checker/fixture_lease.py" hold \
      --fixture-root "$fixture_root" --case "$stage" --kind "$kind" --control-dir "$control_path" \
      --deadline-seconds 8 > "$private/$stage-$kind-audit.private.log" 2>&1 &
    audit_job=$!
    phase="wait-holder-ready-audit-$stage-$kind"
    control wait audit ready "$audit_job" > "$private/$stage-$kind-audit-ready.json"
  fi
}
observe_holder() {
  local which=$1 job
  phase="wait-holder-blocked-$which-$stage-$kind"
  last_helper_type=$which
  last_helper_log="$private/$stage-$kind-$which.private.log"
  if test "$which" = blob; then job=$blob_job; else job=$audit_job; fi
  control wait "$which" blocked "$job" > "$private/$stage-$kind-$which-blocked.json"
  phase="observe-holder-$which-$stage-$kind"
  last_relation="$private/$stage-$kind-$which-wait.json"
  control observe "$which" "$job" > "$last_relation"
}
release_holder() {
  local which=$1 job
  if test "$which" = blob; then job=$blob_job; else job=$audit_job; fi
  control release "$which" > "$private/$stage-$kind-$which-release-ns.json"
  wait "$job"
  control wait "$which" released "$job" > "$private/$stage-$kind-$which-released.json"
  if test "$which" = blob; then blob_job=''; else audit_job=''; fi
  helper_stopped=$((helper_stopped+1))
}

snapshot() { control snapshot "$1" "$2" "$private/snapshots.private.json"; }

inspect_product() {
  local label=$1 status=$2
  local -a planned=()
  if test "$label" = killed; then planned=(--planned-sigkill); fi
  /usr/bin/docker inspect "$product_id" > "$private/container-inspect.json"
  /usr/bin/python3 -B "$checker" inspect --image-inspect "$private/product-image-inspect.json" \
    --container-inspect "$private/container-inspect.json" --image-id "$image_id" --source-commit "$source_commit" \
    --expected-private-source "$fixture_root/$stage/$kind" --expected-state-source "$fixture_root/$stage/$kind/trust" \
    --expected-network-mode "container:$registry_id" --container-status "$status" "${planned[@]}" \
    --report "$evidence/product-crash-$stage-$kind-$label-inspect.json"
}
record_pid1() {
  local label=$1
  product_pid=$(/usr/bin/docker inspect --format '{{.State.Pid}}' "$product_id")
  [[ "$product_pid" =~ ^[1-9][0-9]*$ ]]
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$product_pid" "$fixture_root/$stage/$kind" "$run_root/bin/image-trust-api-static" "$source_commit" "$image_id" "$product_id" "$registry_pid" \
    > "$evidence/product-crash-$stage-$kind-$label-pid1.json" <<'PY'
import hashlib,json,pathlib,sys
pid,endpoint,binary,commit,image,container,registry=sys.argv[1:]; p=pathlib.Path('/proc')/pid
assert (p/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==['/app/image-trust-api','--config',endpoint+'/trust-config.json','--product-config',endpoint+'/product-config.json']
s=dict(row.split(':',1) for row in (p/'status').read_text().splitlines())
assert all(s[k].split()==['10001']*4 for k in ('Uid','Gid')) and s['NSpid'].split()[-1]=='1' and s['NoNewPrivs'].strip()=='1'
assert all(int(s[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
assert (p/'ns/net').readlink()==pathlib.Path('/proc',registry,'ns/net').readlink()
actual=hashlib.sha256((p/'exe').read_bytes()).hexdigest(); assert actual==hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
start=int((p/'stat').read_text().rsplit(')',1)[1].split()[19])
print(json.dumps({'schema':'chengwang.product-image-pid1/v1','authorization':'BLOCKED','production':False,'deviceActionsExecuted':False,'sourceCommit':commit,'localImageID':image,'containerID':container,'hostPID':int(pid),'namespacePID':1,'startTime':start,'uid':10001,'gid':10001,'capabilities':'none','noNewPrivileges':True,'defaultProductEntrypoint':True,'expectedConfigurationArguments':True,'actualExecutableSHA256':actual},sort_keys=True))
PY
  product_start=$(/usr/bin/python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["startTime"])' "$evidence/product-crash-$stage-$kind-$label-pid1.json")
  test "$(/usr/bin/docker inspect --format '{{.State.Pid}}' "$product_id")" = "$product_pid"
}
stop_product() {
  /usr/bin/docker stop --signal SIGTERM --timeout 15 "$product_id" > "$private/stop.private.log" 2>&1
  inspect_product "$1" exited
}
barrier_report() {
  /usr/bin/python3 -B - "$private" "$source_commit" "$stage" "$kind" \
    > "$evidence/product-crash-$stage-$kind-barriers.json" <<'PY'
import json,pathlib,sys
folder,commit,stage,kind=sys.argv[1:]; folder=pathlib.Path(folder)
types=['audit'] if stage=='prepared' else ['blob'] if stage=='reserved' else ['blob','audit']
holders=[]; relations=[]
for role in types:
    prefix=folder/f'{stage}-{kind}-{role}'
    read=lambda suffix:json.loads(pathlib.Path(str(prefix)+suffix).read_bytes())
    ready,blocked,released=read('-ready.json'),read('-blocked.json'),read('-released.json')
    assert ready['process']==blocked['process'] and released['process'] is None
    holders.append({'type':role,'ready':ready['event'],'blocked':blocked['event'],'released':released['event'],'process':{**ready['process'],'exitCode':0,'joined':True},'releaseMonotonicNS':read('-release-ns.json')})
    relations.append(read('-wait.json'))
print(json.dumps({'schema':'chengwang.product-crash-barriers/v1','sourceCommit':commit,'stage':stage,'kind':kind,'holders':holders,'waitRelations':relations,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
}

phase=registry-process-identity
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$registry_pid" "$registry_id" "$source_commit" \
  > "$evidence/product-crash-registry-process.json" <<'PY'
import hashlib,json,pathlib,sys
pid,container,commit=sys.argv[1:]; p=pathlib.Path('/proc')/pid
fields=dict(row.split(':',1) for row in (p/'status').read_text().splitlines())
assert all(fields[name].split()==['10001']*4 for name in ('Uid','Gid')) and fields['NSpid'].split()[-1]=='1' and fields['NoNewPrivs'].strip()=='1'
assert all(int(fields[name].strip(),16)==0 for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
assert (p/'uid_map').read_text().split()==['0','0','4294967295']
print(json.dumps({'schema':'chengwang.product-crash-registry-process/v1','sourceCommit':commit,'registryContainerID':container,'hostPID':int(pid),'startTime':int((p/'stat').read_text().rsplit(')',1)[1].split()[19]),'namespacePID':1,'uid':10001,'gid':10001,'capabilities':'none','noNewPrivileges':True,'actualExecutableSHA256':hashlib.sha256((p/'exe').read_bytes()).hexdigest(),'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY

for stage in prepared reserved consumed; do
  for kind in message-signature dsse; do
    last_relation=''; product_pid=''; product_start=''; last_helper_type=''; last_helper_log=''; last_action_log=''
    phase="prepare-$stage-$kind"
    snapshot prepare before
    fixture_action prepare
    snapshot prepare after
    config_digest=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["configSHA256"])' "$fixture_root/evidence/product-crash-$stage-$kind-prepare.json")
    [[ "$config_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
    manifest_digest=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B -c 'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$fixture_root/$stage/$kind/graph/manifest.json")
    in_fixture /usr/bin/python3 -B "$fixture_root/bin/checker/check_product_crash.py" graph \
      --graph-dir "$fixture_root/$stage/$kind/graph" --packaged-report "$fixture_root/bin/product-image-packaged-contents.json" \
      --source-commit "$source_commit" --manifest-digest "$manifest_digest" \
      --report "$fixture_root/evidence/product-crash-$stage-$kind-graph.json"
    /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$stage" "$kind" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1]); stage,kind=sys.argv[2:]
def directory(path):
    if not path.exists(): path.mkdir(mode=0o700); os.chown(path,10001,10001)
    s=path.lstat(); assert s.st_uid==s.st_gid==10001 and (s.st_mode&0o7777)==0o700 and path.is_dir() and not path.is_symlink()
for role in ('audit','blob','send'): directory(root/'holders'/f'{role}-{stage}-{kind}')
if stage in ('prepared','consumed'): directory(root/'control'/f'{stage}-{kind}')
if stage in ('reserved','consumed'):
    directory(root/'control'/f'blob-{stage}-{kind}')
    directory(root/'blob'/stage); directory(root/'blob'/stage/kind)
    fd=os.open(root/'blob'/stage/kind/'data',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.fchown(fd,10001,10001); os.close(fd)
PY
    endpoint="$fixture_root/$stage/$kind"
    phase="start-$stage-$kind"
    product_id=$(/usr/bin/docker create --pull never --platform linux/amd64 --name "cw-crash-product-$fixture_uuid-$stage-$kind" \
      --label "$label_key=$fixture_uuid" --network "container:$registry_id" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
      --memory 256m --memory-swap 256m --cpus 1 --pids-limit 128 --ulimit nofile=1024:1024 --restart no --stop-timeout 15 \
      --mount "type=bind,src=$endpoint,dst=$endpoint,readonly,bind-propagation=rprivate" \
      --mount "type=bind,src=$endpoint/trust,dst=$endpoint/trust,bind-propagation=rprivate" \
      --mount "type=bind,src=$endpoint/data,dst=$endpoint/data,bind-propagation=rprivate" \
      "$image_id" --config "$endpoint/trust-config.json" --product-config "$endpoint/product-config.json")
    [[ "$product_id" =~ ^[a-f0-9]{64}$ ]]; owned_ids+=("$product_id")
    /usr/bin/docker start "$product_id" >/dev/null
    inspect_product running running; record_pid1 running
    if test "$kind" = message-signature; then api_port=17831; else api_port=17832; fi
    wait_tls api "$api_port"
    fixture_action ready
    snapshot drain before
    if test "$stage" = prepared; then start_holder audit; else start_holder blob; fi
    fixture_action send &
    send_job=$!
    if test "$stage" = prepared; then
      observe_holder audit
    else
      observe_holder blob
      if test "$stage" = consumed; then
        fixture_action reserved
        start_holder audit
        release_holder blob
        observe_holder audit
      fi
    fi
    fixture_action blocked
    phase="sigkill-$stage-$kind"
    test "$(/usr/bin/docker inspect --format '{{.State.Pid}}' "$product_id")" = "$product_pid"
    test "$(/usr/bin/docker inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$product_id")" = "$fixture_uuid"
    control kill "$product_id" "$image_id" "$send_job" > "$private/$stage-$kind-kill.json"
    test "$(/usr/bin/docker wait "$product_id")" = 137
    inspect_product killed exited
    /usr/bin/cp "$private/$stage-$kind-kill.json" "$evidence/product-crash-$stage-$kind-kill.json"
    wait "$send_job"; send_job=''; sender_stopped=$((sender_stopped+1))
    if test -n "$audit_job"; then release_holder audit; fi
    if test -n "$blob_job"; then release_holder blob; fi
    barrier_report
    phase="drain-$stage-$kind"
    control drain > "$evidence/product-crash-$stage-$kind-drain.json"
    snapshot drain after
    fixture_action cut
    snapshot recover before
    /usr/bin/docker start "$product_id" >/dev/null
    inspect_product recovered-running running; record_pid1 recovered-running
    wait_tls api "$api_port"
    fixture_action recovered
    stop_product recovered-exited
    fixture_action reopen-first
    snapshot recover after
    snapshot idempotent before
    /usr/bin/docker start "$product_id" >/dev/null
    inspect_product idempotent-running running; record_pid1 idempotent-running
    wait_tls api "$api_port"
    fixture_action idempotent
    snapshot idempotent after
    snapshot probe before
    fixture_action probe
    snapshot probe after
    stop_product idempotent-exited
    fixture_action reopen-final
  done
done

phase=safe-evidence-export
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$private" <<'PY'
import json,os,pathlib,stat,sys
root,destination=map(pathlib.Path,sys.argv[1:]); names=set()
for stage in ('prepared','reserved','consumed'):
    for kind in ('message-signature','dsse'):
        actions=['prepare','ready','send','blocked','cut','recovered','reopen-first','idempotent','probe','reopen-final','graph']
        if stage=='consumed': actions.append('reserved')
        names.update(f'product-crash-{stage}-{kind}-{action}.json' for action in actions)
assert len(names)==68 and {path.name for path in (root/'evidence').iterdir()}==names
secrets=[]
for stage in ('prepared','reserved','consumed'):
    for kind in ('message-signature','dsse'):
        token=(root/stage/kind/'admin-token.private').read_bytes().strip()
        assert 16<=len(token)<=4096; secrets.append(token)
        def collect(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if isinstance(item,str) and any(word in key.lower() for word in ('token','secret','password')) and len(item)>=12: secrets.append(item.encode())
                    else: collect(item)
            elif isinstance(value,list):
                for item in value: collect(item)
        for config in ('trust-config.json','product-config.json'): collect(json.loads((root/stage/kind/config).read_bytes()))
for name in sorted(names):
    path=root/'evidence'/name; fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno()); assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==10001 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=512<<10
        raw=f.read((512<<10)+1); after=os.fstat(f.fileno()); named=path.lstat()
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_nlink,s.st_uid,s.st_gid)
        assert len(raw)==before.st_size and identity(before)==identity(after)==identity(named)
    value=json.loads(raw); assert value['authorization']=='BLOCKED' and value['production'] is False and value['deviceActionsExecuted'] is False
    assert b'PRIVATE KEY' not in raw and not any(secret in raw for secret in secrets)
    fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f: f.write(raw)
PY
for stage in prepared reserved consumed; do
  for kind in message-signature dsse; do
    for action in prepare ready send blocked cut recovered reopen-first idempotent probe reopen-final graph; do
      /usr/bin/sudo --non-interactive /usr/bin/cat "$private/product-crash-$stage-$kind-$action.json" > "$evidence/product-crash-$stage-$kind-$action.json"
    done
    if test "$stage" = consumed; then
      /usr/bin/sudo --non-interactive /usr/bin/cat "$private/product-crash-$stage-$kind-reserved.json" > "$evidence/product-crash-$stage-$kind-reserved.json"
    fi
  done
done
phase=safe-observations-export
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$private/snapshots.private.json" "$source_commit" "$image_id" "$registry_id" "$registry_image" \
  > "$evidence/product-crash-observations.json" <<'PY'
import json,os,pathlib,stat,sys
path,commit,image,container,pin=sys.argv[1:]; path=pathlib.Path(path)
assert path.name=='snapshots.private.json' and path.parent.name=='product-crash-private'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as handle:
    before=os.fstat(handle.fileno())
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=2<<20
    raw=handle.read((2<<20)+1); after=os.fstat(handle.fileno()); named=path.lstat()
    identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)==identity(named)
values=json.loads(raw); assert type(values) is list and len(values)==60
print(json.dumps({'schema':'chengwang.product-crash-observations/v1','sourceCommit':commit,'localImageID':image,'registryContainerID':container,'pinnedRegistryImage':pin,'snapshots':values,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
phase=graceful-registry-stop
/usr/bin/docker stop --signal SIGTERM --timeout 15 "$registry_id" >/dev/null
/usr/bin/docker inspect "$registry_id" > "$private/registry-exited.private.json"
/usr/bin/python3 -B - "$private/registry-exited.private.json" <<'PY'
import json,pathlib,sys
s=json.loads(pathlib.Path(sys.argv[1]).read_bytes())[0]['State']
assert s['Status']=='exited' and s['Running'] is False and type(s['ExitCode']) is int and s['ExitCode']==0 and s['Pid']==0 and not s['OOMKilled'] and not s.get('Error')
print('D12_CRASH_REGISTRY_GRACEFUL_STOP=PASS exit_code=0 oom=false pid=0')
PY
phase=exact-owned-cleanup
test "$helper_stopped" -eq 8 && test "${#owned_ids[@]}" -eq 7
test "$sender_stopped" -eq 6
test -z "$audit_job$blob_job$send_job"
cleanup_owned
cleaned=true
/usr/bin/python3 -B - "$source_commit" "$image_id" > "$evidence/product-crash-runtime-cleanup.json" <<'PY'
import json,sys
print(json.dumps({'schema':'chengwang.product-crash-cleanup/v1','sourceCommit':sys.argv[1],'localImageID':sys.argv[2],'ownedContainersRemoved':7,'ownedHelpersJoined':8,'helperExitCodes':[0]*8,'ownedSendersJoined':6,'senderExitCodes':[0]*6,'privateFixtureRemoved':True,'outerProductImagePreserved':True,'registryImagePreserved':True,'outcome':'PASS','authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
echo 'D12_PRODUCT_CRASH_CLEANUP=PASS exact_owned_containers=7 owned_helpers_joined=8 owned_senders_joined=6 outer_image_preserved=true private_fixture_removed=true production=false'
phase=independent-final-check
/usr/bin/python3 -B "$checker" verify --evidence-dir "$evidence" --source-commit "$source_commit" --report "$evidence/product-crash-outcome.json"
accepted=true
echo 'D12_PRODUCT_CRASH_GATE=PASS actual_product_image=true phases=3 signatures=2 sigkill=6 normal_stops=12 second_restart_idempotent=true authorization=BLOCKED production=false'
