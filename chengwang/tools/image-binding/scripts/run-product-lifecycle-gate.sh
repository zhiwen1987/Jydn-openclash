#!/usr/bin/env bash
# D12: actual product automatic refresh with isolated normal-TLS Registry/source.
# No image build, external push, production network or device action is allowed.
set -euo pipefail
umask 077
export PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1
test "$#" -eq 5 || { echo 'usage: run-product-lifecycle-gate.sh RUNROOT GOBIN MODCACHE IMAGEID PRIVATE_ARCHIVE' >&2; exit 2; }
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
image_id=$4
archive=$(/usr/bin/realpath -e -- "$5")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
source_root=$(/usr/bin/git -C "$script_root" rev-parse --show-toplevel)
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
checker="$source_root/chengwang/deploy/product-candidate/check_product_lifecycle.py"
registry_image=registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
evidence="$run_root/evidence"
private="$run_root/product-lifecycle-private"
fixture_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
fixture_root="/tmp/chengwang-product-lifecycle-$fixture_uuid"
label_key=org.chengwang.product-lifecycle-fixture
registry_id=''
registry_pid=''
source_pid=''
source_job=''
source_kind=''
source_stopped=0
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
test -x "$run_root/bin/product-lifecycle.test"
test -f "$evidence/product-image-packaged-contents.json"
test -f "$evidence/product-image-staging.json"
test -f "$evidence/product-registry-outcome.json"
test -f "$archive" && test ! -L "$archive"
test ! -e "$private" && test ! -e "$fixture_root"
/usr/bin/install -d -m 0700 "$private"
exec 3>&2
exec 2> "$private/shell.private.log"

cleanup_owned() {
  local failed=0 item index
  if test -n "$source_job"; then
    stop_source true || failed=1
  fi
  # Shared-network dependants must be removed before their Registry anchor.
  for ((index=${#owned_ids[@]}-1; index>=0; index--)); do
    item=${owned_ids[$index]}
    if /usr/bin/docker container inspect "$item" >/dev/null 2>&1; then
      if test "$(/usr/bin/docker container inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$item")" != "$fixture_uuid"; then failed=1; continue; fi
      if test "$(/usr/bin/docker container inspect --format '{{.State.Running}}' "$item")" = true; then
        # Emergency force removal never counts as graceful acceptance.
        failed=1
        /usr/bin/docker container rm --force "$item" >/dev/null 2>&1 || failed=1
      else /usr/bin/docker container rm "$item" >/dev/null 2>&1 || failed=1
      fi
      if /usr/bin/docker container inspect "$item" >/dev/null 2>&1; then failed=1; fi
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
    assert stat.S_ISREG(meta.st_mode) and meta.st_uid==meta.st_gid==10001 and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==0o600 and owner.read_text() == identity+'\n'
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
  /usr/bin/find "$private" -maxdepth 1 -type f -delete
  test "$failed" -eq 0
}
on_exit() {
  local original=$?
  trap - EXIT HUP INT TERM
  if test "$original" -ne 0; then
    echo "D12_PRODUCT_LIFECYCLE_FAILURE_PHASE=$phase" >&3
    if ! /usr/bin/python3 -B - "$private" "$last_action_log" "$phase" > "$evidence/product-lifecycle-failure-diagnostic.json" <<'PY'
import json,os,pathlib,re,stat,sys
private,log,phase=sys.argv[1:]; assert re.fullmatch(r'[a-z0-9-]{1,96}',phase)
line_number=0
if log:
    path=pathlib.Path(log)
    assert path.parent==pathlib.Path(private) and re.fullmatch(r'(message-signature|dsse)-(prepare|exercise|resume|reopen-first|reopen-final)-(0|[1-9])\.private\.log',path.name)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<=info.st_size<=256<<10
        raw=handle.read((256<<10)+1); assert len(raw)==info.st_size
    for row in raw.splitlines():
        match=re.fullmatch(rb'\s*product_lifecycle_d12_linux_test\.go:([1-9][0-9]{0,5}): .*',row)
        if match: line_number=int(match[1])
print(json.dumps({'schema':'chengwang.product-lifecycle-failure/v1','phase':phase,'driverSourceLine':line_number,'outcome':'FAIL','rawPrivateLogPublished':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
    then
      /usr/bin/rm -f -- "$evidence/product-lifecycle-failure-diagnostic.json"
      echo 'D12_PRODUCT_LIFECYCLE_FAILURE_DIAGNOSTIC=WITHHELD' >&3
    fi
  fi
  if test "$cleaned" != true; then
    if cleanup_owned; then cleaned=true; else echo 'D12_PRODUCT_LIFECYCLE_CLEANUP=FAIL production=false' >&3; exit 1; fi
  fi
  if test "$original" -eq 0 && test "$accepted" != true; then exit 1; fi
  exit "$original"
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
for name in ('bin','tmp','evidence','refresh','source'):
    (root/name).mkdir(mode=0o700); os.chown(root/name,10001,10001)
with (root/'.fixture-owner').open('x',encoding='ascii') as f: f.write(sys.argv[2]+'\n')
os.chmod(root/'.fixture-owner',0o600); os.chown(root/'.fixture-owner',10001,10001)
PY
/usr/bin/sudo --non-interactive /usr/bin/install -m 0555 -o 0 -g 0 "$run_root/bin/product-lifecycle.test" "$fixture_root/bin/product-lifecycle.test"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$archive" "$fixture_root/bin/product-image.private.tar"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0444 -o 0 -g 0 "$evidence/product-image-packaged-contents.json" "$fixture_root/bin/product-image-packaged-contents.json"
# OpenSSL output and signing keys remain private. Each CA has a distinct key.
/usr/bin/sudo --non-interactive /usr/bin/bash -euo pipefail -c '
  root=$1
  for purpose in registry api source; do
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
names=('chengwang/deploy/product-candidate/check_product_lifecycle.py','chengwang/deploy/product-candidate/check_product_image.py','chengwang/deploy/product-candidate/check_product_registry.py','chengwang/deploy/product-candidate/fixture_feed.py')
files={}
for name in names:
    path=root/name
    assert path.is_file() and not path.is_symlink()
    raw=path.read_bytes()
    assert raw==subprocess.check_output(['/usr/bin/git','-C',str(root),'show',commit+':'+name]) and len(raw)<=256<<10
    files[name]=hashlib.sha256(raw).hexdigest()
print(json.dumps({'sourceCommit':commit,'files':files},sort_keys=True))
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_root" "$fixture_root" "$private/tool-input.json" > "$evidence/product-lifecycle-harness.json" <<'PY'
import hashlib,json,os,pathlib,sys
source,root,record=map(pathlib.Path,sys.argv[1:]); data=json.loads(record.read_text())
destination=root/'bin/checker'
destination.mkdir(mode=0o555); os.chmod(destination,0o555)
for name,digest in data['files'].items():
    original=source/name; raw=original.read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest
    target=destination/pathlib.Path(name).name
    with target.open('xb') as f: f.write(raw)
    os.chmod(target,0o444)
print(json.dumps({'schema':'chengwang.product-lifecycle-harness/v1',**data,'checkoutBytesMatched':True,'permissionReadOnly':True,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY

phase=registry-start
registry_id=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
  --name "cw-product-lifecycle-$fixture_uuid" --label "$label_key=$fixture_uuid" \
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
' "$source_commit" "$registry_id" > "$evidence/product-lifecycle-network.json"
wait_tls registry 5443
/usr/bin/python3 -B - "$private/registry-image-inspect.json" "$private/registry-container-inspect.json" "$registry_id" "$registry_image" "$fixture_root" "$source_commit" > "$evidence/product-lifecycle-isolation.json" <<'PY'
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
    return equivalent,{'schema':'chengwang.product-lifecycle-env-diagnostic/v1','baseShapeValid':base_shape,'baseKeysUnique':base_unique,'actualShapeValid':actual_shape,'actualKeysUnique':actual_unique,'expectedCount':len(expected) if expected is not None else 0,'actualCount':len(observed) if observed is not None else 0,'expectedMappingSHA256':digest(expected),'actualMappingSHA256':digest(observed),'equivalent':equivalent}

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

fixture_action() {
  local action=$1 kind=$2 case_number=${3:-0} log marker marker_action
  log="$private/$kind-$action-$case_number.private.log"
  last_action_log=$log; last_action_kind=$kind; last_action=$action; last_case=$case_number
  phase="$action-$kind-$case_number"
  in_fixture CHENGWANG_D12_ROOT="$fixture_root" CHENGWANG_D12_ACTION="$action" \
    CHENGWANG_D12_KIND="$kind" CHENGWANG_D12_CASE="$case_number" CHENGWANG_D12_IMAGE_ID="$image_id" \
    CHENGWANG_D12_COMMIT="$source_commit" CHENGWANG_D12_ARCHIVE="$fixture_root/bin/product-image.private.tar" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 60s "$fixture_root/bin/product-lifecycle.test" \
      -test.run='^TestProductLifecycleD12Fixture$' -test.v -test.timeout=55s 2>&1 | /usr/bin/tee "$log" >/dev/null
  marker_action=${action^^}; marker_action=${marker_action//-/_}
  marker="D12_PRODUCT_LIFECYCLE_$marker_action=PASS kind=$kind case=$case_number authorization=BLOCKED production=false"
  test "$(/usr/bin/grep -Fxc -- "$marker" "$log")" -eq 1
  test "$(/usr/bin/grep -Ec '^--- PASS: TestProductLifecycleD12Fixture \(' "$log")" -eq 1
  echo "$marker"
}
# Request observations are derived from Distribution's completed-request JSON,
# never product-reported counters. Upload UUIDs, query strings and raw lines are
# private; only fixed methods/digest/status/count are projected.
snapshot() {
  local kind=$1 action=$2 case_number=$3 position=$4
  phase="observe-$kind-$action-$case_number-$position"
  /usr/bin/docker logs "$registry_id" > "$private/registry-log.private" 2>&1
  /usr/bin/python3 -B - "$private/registry-log.private" "$private/snapshots.private.json" "$kind" "$action" "$case_number" "$position" <<'PY'
import collections,json,pathlib,re,sys
log,record,kind,action,number,position=sys.argv[1:]; raw=pathlib.Path(log).read_bytes(); assert len(raw)<=32<<20
digest=collections.Counter(); other=collections.Counter()
for line in raw.decode('utf-8').splitlines():
    if not line.startswith('{'): continue
    value=json.loads(line)
    if value.get('msg')!='response completed': continue
    method=value.get('http.request.method'); uri=value.get('http.request.uri'); status=value.get('http.response.status')
    assert method in ('GET','HEAD','POST','PATCH','PUT','DELETE','OPTIONS') and type(status) is int and 100<=status<=599 and isinstance(uri,str)
    match=re.fullmatch(r'/v2/chengwang/product-candidate/(?:manifests|blobs)/(sha256:[a-f0-9]{64})',uri)
    if method in ('GET','HEAD') and match: digest[(method,match[1],status)]+=1
    else: other[(method,status)]+=1
path=pathlib.Path(record); data=json.loads(path.read_text()) if path.exists() else []
data.append({'ordinal':len(data)+1,'kind':kind,'action':action,'case':int(number),'position':position,'digestRequests':[{'method':m,'digest':d,'status':s,'count':n} for (m,d,s),n in sorted(digest.items())],'otherRequests':[{'method':m,'status':s,'count':n} for (m,s),n in sorted(other.items())]})
path.write_text(json.dumps(data,sort_keys=True)+'\n'); path.chmod(0o600)
PY
}
after_snapshot() {
  # Two stable observations; never retry the business call or await a desired
  # request budget. The independent checker must reject missing/extra requests.
  snapshot "$1" "$2" "$3" after
  /usr/bin/sleep 0.15
  /usr/bin/docker logs "$registry_id" > "$private/registry-log.private" 2>&1
  /usr/bin/python3 -B - "$private/registry-log.private" "$private/registry-stable.private" <<'PY'
import hashlib,json,pathlib,sys
raw=pathlib.Path(sys.argv[1]).read_bytes(); assert len(raw)<=32<<20
rows=[]
for line in raw.decode().splitlines():
    if line.startswith('{'):
        value=json.loads(line)
        if value.get('msg')=='response completed': rows.append(value)
pathlib.Path(sys.argv[2]).write_text(str(len(rows)))
PY
  # Reparse a second time without exporting an extra ordinal; compare only safe
  # projected counters so timestamps cannot make a stable request set differ.
  /usr/bin/cp "$private/snapshots.private.json" "$private/snapshots-before-stability.private.json"
  snapshot "$1" "$2" "$3" after
  /usr/bin/python3 -B - "$private/snapshots.private.json" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]); data=json.loads(path.read_text()); a,b=data[-2:]
assert a['digestRequests']==b['digestRequests'] and a['otherRequests']==b['otherRequests'],'Registry completed log not stable'
data.pop(); path.write_text(json.dumps(data,sort_keys=True)+'\n')
PY
}
inspect_product() {
  local id=$1 kind=$2 state=$3 label=$4
  /usr/bin/docker container inspect "$id" > "$private/container-inspect.json"
  /usr/bin/python3 -B "$checker" inspect --image-inspect "$private/product-image-inspect.json" \
    --container-inspect "$private/container-inspect.json" --image-id "$image_id" --source-commit "$source_commit" \
    --expected-private-source "$fixture_root/refresh/$kind" --expected-state-source "$fixture_root/refresh/$kind/trust" \
    --expected-network-mode "container:$registry_id" --container-status "$state" \
    --report "$evidence/product-lifecycle-$kind-$label-inspect.json"
}
record_pid1() {
  local id=$1 kind=$2 label=$3 pid
  pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$id")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$pid" "$fixture_root/refresh/$kind" "$run_root/bin/image-trust-api-static" "$source_commit" "$image_id" "$id" > "$evidence/product-lifecycle-$kind-$label-pid1.json" <<'PY'
import hashlib,json,pathlib,sys
pid,endpoint,binary,commit,image,container=sys.argv[1:]; proc=pathlib.Path('/proc')/pid
args=(proc/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
assert args==['/app/image-trust-api','--config',endpoint+'/trust-config.json','--product-config',endpoint+'/product-config.json']
s=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines())
assert all(s[k].split()==['10001']*4 for k in ('Uid','Gid')) and s['NSpid'].split()[-1]=='1' and s['NoNewPrivs'].strip()=='1'
assert all(int(s[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
digest=hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(); assert hashlib.sha256((proc/'exe').read_bytes()).hexdigest()==digest
print(json.dumps({'schema':'chengwang.product-image-pid1/v1','authorization':'BLOCKED','production':False,'deviceActionsExecuted':False,'sourceCommit':commit,'localImageID':image,'containerID':container,'hostPID':int(pid),'namespacePID':1,'uid':10001,'gid':10001,'capabilities':'none','noNewPrivileges':True,'defaultProductEntrypoint':True,'expectedConfigurationArguments':True,'actualExecutableSHA256':digest},sort_keys=True))
PY
  test "$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$id")" = "$pid"
}
stop_product() {
  local stop_label
  case "$3" in exited) stop_label=first;; restarted-exited) stop_label=final;; *) return 2;; esac
  record_stop_window "$2" "$stop_label" before
  /usr/bin/docker stop --signal SIGTERM --timeout 15 "$1" > "$private/stop.private.log" 2>&1
  inspect_product "$1" "$2" exited "$3"
  record_stop_window "$2" "$stop_label" after
}

record_stop_window() {
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$1" "$2" "$3" "$source_pid" <<'PY'
import ctypes,hashlib,json,os,pathlib,re,stat,sys,time
root,kind,label,position,pid=sys.argv[1:]
assert kind in ('message-signature','dsse') and label in ('first','final') and position in ('before','after')
directory=pathlib.Path(root)/'source'/kind; log=directory/'feed/events.jsonl'; proc=pathlib.Path('/proc')/pid
process=json.loads((directory/'source-process.private.json').read_text()); assert process['pid']==int(pid)
deadline=time.monotonic()+4
def regular(info):
    assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o600
def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def unique(pairs):
    value={}
    for key,item in pairs:
        assert key not in value; value[key]=item
    return value
def parse(raw):
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda value: (_ for _ in ()).throw(ValueError('noncanonical number')))
while True:
    assert int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])==process['startTime']
    if position=='after' and len(list((proc/'task').iterdir()))!=1:
        assert time.monotonic()<deadline; time.sleep(.025); continue
    fd=os.open(log,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as handle:
        before=os.fstat(handle.fileno()); regular(before); assert 0<=before.st_size<=4<<20
        raw=handle.read((4<<20)+1); after=os.fstat(handle.fileno()); named=log.lstat(); regular(after); regular(named)
        stable=identity(before)==identity(after)==identity(named) and len(raw)==before.st_size
    if not stable or raw and not raw.endswith(b'\n'):
        assert time.monotonic()<deadline; time.sleep(.025); continue
    if position=='after' and len(list((proc/'task').iterdir()))!=1:
        assert time.monotonic()<deadline; time.sleep(.025); continue
    lines=raw.splitlines()
    for ordinal,line in enumerate(lines,1):
        event=parse(line)
        assert type(event) is dict and set(event)=={'schema','ordinal','epoch','pathClass','generation','status','bodySHA256','bytes','tls','authPresent','reason','sentComplete'}
        assert event['schema']=='chengwang.product-lifecycle-feed-event/v1' and type(event['ordinal']) is int and event['ordinal']==ordinal
    projection={'eventCount':len(lines),'sha256':hashlib.sha256(raw).hexdigest()}
    break
record=directory/'stop-windows.private.json'; data=[]
if record.exists() or record.is_symlink():
    fd=os.open(record,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno()); regular(info); assert 0<info.st_size<=16<<10
        data=parse(handle.read((16<<10)+1)); assert type(data) is list
index=0 if label=='first' else 1
assert len(data)==index+(position=='after')
for prior in data[:index]: assert set(prior)=={'label','before','after'} and prior['label']=='first'
if position=='before': data.append({'label':label,'before':projection})
else:
    assert set(data[-1])=={'label','before'} and data[-1]['label']==label and projection['eventCount']>=data[-1]['before']['eventCount']
    data[-1]['after']=projection
pending=directory/'.stop-windows.private.pending'; fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
with os.fdopen(fd,'wb') as output:
    os.fchown(output.fileno(),10001,10001); output.write(json.dumps(data,sort_keys=True).encode()+b'\n'); output.flush(); os.fsync(output.fileno())
os.replace(pending,record)
fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try: os.fsync(fd)
finally: os.close(fd)
PY
}

start_source() {
  source_kind=$1
  /usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$fixture_root/source-cert.pem" "$fixture_root/source/$source_kind/feed/server.crt"
  /usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$fixture_root/source-key.private.pem" "$fixture_root/source/$source_kind/feed/server.key"
  in_fixture /usr/bin/python3 -B -c '
import ctypes,json,os,pathlib,resource,sys
root,kind=sys.argv[1:]; path=pathlib.Path(root)/"source"/kind/"source-process.private.json"
for limit,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,60),(resource.RLIMIT_AS,512<<20),(resource.RLIMIT_FSIZE,16<<20),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_NPROC,128)):
    resource.setrlimit(limit,(value,value))
start=int(pathlib.Path("/proc/self/stat").read_text().rsplit(")",1)[1].split()[19])
pending=path.with_name(".source-process.private.pending")
fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"wb") as output:
    output.write(json.dumps({"pid":os.getpid(),"startTime":start},sort_keys=True).encode()+b"\n"); output.flush(); os.fsync(output.fileno())
directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    rename=ctypes.CDLL(None,use_errno=True).renameat2
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint); rename.restype=ctypes.c_int
    assert rename(directory,pending.name.encode(),directory,path.name.encode(),1)==0
    os.fsync(directory)
finally: os.close(directory)
os.execv("/usr/bin/python3",["/usr/bin/python3","-B",root+"/bin/checker/fixture_feed.py","serve","--fixture-root",root,"--case","source","--kind",kind,"--port","5444","--deadline-seconds","600"])
' "$fixture_root" "$source_kind" > "$private/$source_kind-source.private.log" 2>&1 &
  source_job=$!
  source_pid=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$source_kind" <<'PY'
import json,os,pathlib,stat,sys,time
root,kind=sys.argv[1:]; path=pathlib.Path(root)/'source'/kind/'source-process.private.json'; deadline=time.monotonic()+10
while not path.exists():
    if time.monotonic()>=deadline: raise SystemExit(1)
    time.sleep(.05)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as handle:
    info=os.fstat(handle.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=1024
    data=json.loads(handle.read(1025)); assert set(data)=={'pid','startTime'} and type(data['pid']) is int and data['pid']>1 and type(data['startTime']) is int and data['startTime']>0
print(data['pid'])
PY
)
  [[ "$source_pid" =~ ^[1-9][0-9]*$ ]]
  wait_tls source 5444
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$source_kind" "$source_pid" "$source_job" "$registry_pid" "$source_commit" "$source_root" > "$evidence/product-lifecycle-$source_kind-source.json" <<'PY'
import hashlib,json,pathlib,re,sys
root,kind,pid,job,registry,commit,source=sys.argv[1:]; proc=pathlib.Path('/proc')/pid
expected=['/usr/bin/python3','-B',root+'/bin/checker/fixture_feed.py','serve','--fixture-root',root,'--case','source','--kind',kind,'--port','5444','--deadline-seconds','600']
assert (proc/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==expected
fields=dict(row.split(':',1) for row in (proc/'status').read_text().splitlines())
assert all(fields[name].split()==['10001']*4 for name in ('Uid','Gid')) and fields['NoNewPrivs'].strip()=='1'
assert all(int(fields[name].strip(),16)==0 for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
assert (proc/'ns/net').readlink()==(pathlib.Path('/proc')/registry/'ns/net').readlink()
assert (proc/'ns/mnt').readlink()!=pathlib.Path('/proc/self/ns/mnt').readlink()
ancestor=int(pid)
for _ in range(16):
    if ancestor==int(job): break
    ancestor=int(dict(row.split(':',1) for row in pathlib.Path(f'/proc/{ancestor}/status').read_text().splitlines())['PPid'].strip())
    assert ancestor>1
else: raise AssertionError('source ancestry rejected')
copied=pathlib.Path(root)/'bin/checker/fixture_feed.py'; original=pathlib.Path(source)/'chengwang/deploy/product-candidate/fixture_feed.py'
script_hash=hashlib.sha256(copied.read_bytes()).hexdigest(); assert script_hash==hashlib.sha256(original.read_bytes()).hexdigest()
python_hash=hashlib.sha256((proc/'exe').read_bytes()).hexdigest(); assert python_hash==hashlib.sha256(pathlib.Path('/usr/bin/python3').read_bytes()).hexdigest()
limits={'cpuSeconds':60,'addressSpaceBytes':512<<20,'fileBytes':16<<20,'openFiles':128,'processes':128,'coreBytes':0}
names={'cpuSeconds':'Max cpu time','addressSpaceBytes':'Max address space','fileBytes':'Max file size','openFiles':'Max open files','processes':'Max processes','coreBytes':'Max core file size'}
rows=(proc/'limits').read_text().splitlines()
for key,name in names.items():
    matches=[row for row in rows if row.startswith(name+' ')]
    assert len(matches)==1 and re.fullmatch(re.escape(name)+r'\s+'+str(limits[key])+r'\s+'+str(limits[key])+r'(?:\s+[a-z]+)?\s*',matches[0])
print(json.dumps({'schema':'chengwang.product-lifecycle-source/v1','sourceCommit':commit,'kind':kind,'sourceCase':'source','hostPID':int(pid),'uid':10001,'gid':10001,'capabilities':'none','noNewPrivileges':True,'registryNetworkNamespaceMatched':True,'privateMountNamespace':True,'sourceSHA256':script_hash,'pythonExecutableSHA256':python_hash,'gitBoundSourceMatched':True,'sourceLimitsVerified':True,'sourceLimits':limits,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
}

stop_source() {
  local emergency=${1:-false} result=0 stopped_pid=$source_pid
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$source_kind" "$source_job" "$registry_pid" <<'PY' || result=1
import json,os,pathlib,signal,stat,sys
root,kind,job,registry=sys.argv[1:]; path=pathlib.Path(root)/'source'/kind/'source-process.private.json'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as handle:
    info=os.fstat(handle.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=1024
    record=json.loads(handle.read(1025)); assert set(record)=={'pid','startTime'} and type(record['pid']) is int and record['pid']>1 and type(record['startTime']) is int
pid=record['pid']; proc=pathlib.Path('/proc')/str(pid); held=os.pidfd_open(pid)
try:
    current=(proc/'stat').read_text().rsplit(')',1)[1].split(); assert current[0] not in ('Z','X') and int(current[19])==record['startTime']
    fields=dict(row.split(':',1) for row in (proc/'status').read_text().splitlines())
    assert all(fields[name].split()==['10001']*4 for name in ('Uid','Gid')) and fields['NoNewPrivs'].strip()=='1'
    assert all(int(fields[name].strip(),16)==0 for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    assert (proc/'ns/net').readlink()==(pathlib.Path('/proc')/registry/'ns/net').readlink()
    ancestor=pid
    for _ in range(16):
        if ancestor==int(job): break
        ancestor=int(dict(row.split(':',1) for row in pathlib.Path(f'/proc/{ancestor}/status').read_text().splitlines())['PPid'].strip()); assert ancestor>1
    else: raise AssertionError('source ancestry rejected')
    signal.pidfd_send_signal(held,signal.SIGTERM)
finally: os.close(held)
PY
  if ! wait "$source_job"; then result=1; fi
  source_job=''; source_pid=''
  if test "$result" -ne 0; then return 1; fi
  if test "$emergency" = false; then
    /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_commit" "$source_kind" "$stopped_pid" "$fixture_root" > "$evidence/product-lifecycle-$source_kind-source-stop.json" <<'PY'
import json,os,pathlib,stat,sys
commit,kind,pid,root=sys.argv[1:]; path=pathlib.Path(root)/'source'/kind/'stop-windows.private.json'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as handle:
    info=os.fstat(handle.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=16<<10
    windows=json.loads(handle.read((16<<10)+1))
assert type(windows) is list and len(windows)==2 and [value['label'] for value in windows]==['first','final']
assert all(set(value)=={'label','before','after'} for value in windows)
print(json.dumps({'schema':'chengwang.product-lifecycle-source-stop/v1','sourceCommit':commit,'kind':kind,'hostPID':int(pid),'signal':'SIGTERM','exitCode':0,'joined':True,'productStopWindows':windows,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
    source_stopped=$((source_stopped+1))
  fi
}

for kind in message-signature dsse; do
  phase="prepare-$kind"
  snapshot "$kind" prepare 0 before
  fixture_action prepare "$kind" 0
  after_snapshot "$kind" prepare 0
  manifest_digest=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B -c 'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$fixture_root/refresh/$kind/graph/manifest.json")
  in_fixture /usr/bin/python3 -B "$fixture_root/bin/checker/check_product_lifecycle.py" graph --graph-dir "$fixture_root/refresh/$kind/graph" \
    --packaged-report "$fixture_root/bin/product-image-packaged-contents.json" --source-commit "$source_commit" \
    --manifest-digest "$manifest_digest" --report "$fixture_root/evidence/product-lifecycle-$kind-graph.json"
  phase="source-start-$kind"
  start_source "$kind"
  phase="start-$kind"
  endpoint="$fixture_root/refresh/$kind"
  product_id=$(/usr/bin/docker create --pull never --platform linux/amd64 --name "cw-lifecycle-product-$fixture_uuid-$kind" \
    --label "$label_key=$fixture_uuid" --network "container:$registry_id" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --memory 256m --memory-swap 256m --cpus 1 --pids-limit 128 --ulimit nofile=1024:1024 --restart no --stop-timeout 15 \
    --mount "type=bind,src=$endpoint,dst=$endpoint,readonly,bind-propagation=rprivate" \
    --mount "type=bind,src=$endpoint/trust,dst=$endpoint/trust,bind-propagation=rprivate" \
    --mount "type=bind,src=$endpoint/data,dst=$endpoint/data,bind-propagation=rprivate" \
    "$image_id" --config "$endpoint/trust-config.json" --product-config "$endpoint/product-config.json")
  [[ "$product_id" =~ ^[a-f0-9]{64}$ ]]; owned_ids+=("$product_id")
  /usr/bin/docker start "$product_id" >/dev/null
  inspect_product "$product_id" "$kind" running running
  record_pid1 "$product_id" "$kind" running
  if test "$kind" = message-signature; then api_port=17821; else api_port=17822; fi
  wait_tls api "$api_port"
  for case_number in 1 2 3 4 5 6 7 8 9; do
    snapshot "$kind" exercise "$case_number" before
    fixture_action exercise "$kind" "$case_number"
    after_snapshot "$kind" exercise "$case_number"
  done
  phase="stop-$kind"
  stop_product "$product_id" "$kind" exited
  snapshot "$kind" reopen-first 0 before
  fixture_action reopen-first "$kind" 0
  after_snapshot "$kind" reopen-first 0
  phase="restart-$kind"
  /usr/bin/docker start "$product_id" >/dev/null
  inspect_product "$product_id" "$kind" running restarted-running
  record_pid1 "$product_id" "$kind" restarted-running
  wait_tls api "$api_port"
  for case_number in 1 2 3 4 5 6; do
    snapshot "$kind" resume "$case_number" before
    fixture_action resume "$kind" "$case_number"
    after_snapshot "$kind" resume "$case_number"
  done
  phase="final-stop-$kind"
  stop_product "$product_id" "$kind" restarted-exited
  snapshot "$kind" reopen-final 0 before
  fixture_action reopen-final "$kind" 0
  after_snapshot "$kind" reopen-final 0
  phase="source-stop-$kind"
  stop_source false
done

phase=safe-evidence-export
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$private" <<'PY'
import json,os,pathlib,re,stat,sys
root,destination=map(pathlib.Path,sys.argv[1:]); names=[]
for kind in ('message-signature','dsse'):
    for action in ('prepare','reopen-first','reopen-final',*(f'exercise-{n}' for n in range(1,10)),*(f'resume-{n}' for n in range(1,7)),'graph'):
        names.append(f'product-lifecycle-{kind}-{action}.json')
assert {path.name for path in (root/'evidence').iterdir()}==set(names)
secrets=[]
for path in root.rglob('*'):
    if path.is_file() and not path.is_symlink() and path.stat().st_size<=1<<20:
        if path.name=='admin-token.private':
            value=path.read_bytes().strip(); assert 16<=len(value)<=4096; secrets.append(value)
        elif path.name.endswith('config.json'):
            try:
                def collect(value):
                    if isinstance(value,dict):
                        for key,item in value.items():
                            if isinstance(item,str) and any(word in key.lower() for word in ('token','secret','password')) and len(item)>=12: secrets.append(item.encode())
                            else: collect(item)
                    elif isinstance(value,list):
                        for item in value: collect(item)
                collect(json.loads(path.read_text()))
            except (ValueError,UnicodeError): pass
def read_private(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=limit
        raw=handle.read(limit+1); after=os.fstat(handle.fileno()); named=path.lstat()
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_mode,value.st_nlink,value.st_uid,value.st_gid)
        assert identity(info)==identity(after)==identity(named) and len(raw)==info.st_size
        assert b'PRIVATE KEY' not in raw and not any(secret in raw for secret in secrets)
        return raw
for name in names:
    raw=read_private(root/'evidence'/name,256<<10); value=json.loads(raw)
    assert value.get('authorization')=='BLOCKED' and value.get('production') is False
    with (destination/name).open('xb') as output: output.write(raw)
for kind in ('message-signature','dsse'):
    for original,label,extension,limit in (('ready.json','feed-ready','json',16<<10),('events.jsonl','feed-events','jsonl',8<<20)):
        raw=read_private(root/'source'/kind/'feed'/original,limit)
        if original=='ready.json':
            value=json.loads(raw); assert value['schema']=='chengwang.product-lifecycle-feed-ready/v1'
        else:
            for line in raw.splitlines():
                value=json.loads(line); assert value['schema']=='chengwang.product-lifecycle-feed-event/v1'
            import hashlib
            windows=json.loads((root/'source'/kind/'stop-windows.private.json').read_text())
            assert windows[-1]['label']=='final' and windows[-1]['after']=={'eventCount':len(raw.splitlines()),'sha256':hashlib.sha256(raw).hexdigest()}
        with (destination/f'product-lifecycle-{kind}-{label}.{extension}').open('xb') as output: output.write(raw)
PY
for kind in message-signature dsse; do
  for action in prepare reopen-first reopen-final exercise-1 exercise-2 exercise-3 exercise-4 exercise-5 exercise-6 exercise-7 exercise-8 exercise-9 resume-1 resume-2 resume-3 resume-4 resume-5 resume-6 graph feed-ready feed-events; do
    extension=json
    if test "$action" = feed-events; then extension=jsonl; fi
    /usr/bin/sudo --non-interactive /usr/bin/cat "$private/product-lifecycle-$kind-$action.$extension" > "$evidence/product-lifecycle-$kind-$action.$extension"
  done
done
/usr/bin/python3 -B - "$private/snapshots.private.json" "$source_commit" "$image_id" "$registry_id" "$registry_image" > "$evidence/product-lifecycle-observations.json" <<'PY'
import json,pathlib,sys
path,commit,image,registry,pin=sys.argv[1:]; snapshots=json.loads(pathlib.Path(path).read_text()); assert len(snapshots)==72
print(json.dumps({'schema':'chengwang.product-lifecycle-observations/v1','sourceCommit':commit,'localImageID':image,'registryContainerID':registry,'pinnedRegistryImage':pin,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False,'snapshots':snapshots},sort_keys=True))
PY
phase=graceful-registry-stop
/usr/bin/docker stop --signal SIGTERM --timeout 15 "$registry_id" >/dev/null
/usr/bin/docker inspect "$registry_id" > "$private/registry-exited.private.json"
/usr/bin/python3 -B - "$private/registry-exited.private.json" <<'PY'
import json,pathlib,sys
s=json.loads(pathlib.Path(sys.argv[1]).read_text())[0]['State']
assert s['Status']=='exited' and s['Running'] is False and type(s['ExitCode']) is int and s['ExitCode']==0 and s['Pid']==0 and not s['OOMKilled'] and not s.get('Error')
print('D12_REGISTRY_GRACEFUL_STOP=PASS exit_code=0 oom=false pid=0')
PY
phase=exact-owned-cleanup
test "$source_stopped" -eq 2
test "${#owned_ids[@]}" -eq 3
cleanup_owned
cleaned=true
echo 'D12_PRODUCT_LIFECYCLE_CLEANUP=PASS exact_owned_containers=3 owned_sources_joined=2 outer_image_preserved=true private_fixture_removed=true production=false'
/usr/bin/python3 -B - "$source_commit" "$image_id" > "$evidence/product-lifecycle-runtime-cleanup.json" <<'PY'
import json,sys
print(json.dumps({'schema':'chengwang.product-lifecycle-cleanup/v1','sourceCommit':sys.argv[1],'localImageID':sys.argv[2],'ownedContainersRemoved':3,'ownedSourcesJoined':2,'sourceExitCodes':[0,0],'privateFixtureRemoved':True,'outerProductImagePreserved':True,'registryImagePreserved':True,'production':False,'authorization':'BLOCKED','deviceActionsExecuted':False,'outcome':'PASS'},sort_keys=True))
PY
phase=independent-final-check
/usr/bin/python3 -B "$checker" verify --evidence-dir "$evidence" --source-commit "$source_commit" --report "$evidence/product-lifecycle-outcome.json"
accepted=true
echo 'D12_PRODUCT_LIFECYCLE_GATE=PASS actual_product_image=true normal_tls=true automatic_refresh=true signatures=2 cross_restart=true request_observation=per_case external_push=false authorization=BLOCKED production=false'
