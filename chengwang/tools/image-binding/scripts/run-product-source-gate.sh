#!/usr/bin/env bash
# D12: actual product automatic refresh with isolated normal-TLS Registry/source.
# No image build, external push, production network or device action is allowed.
set -euo pipefail
umask 077
export PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1
test "$#" -eq 5 || { echo 'usage: run-product-source-gate.sh RUNROOT GOBIN MODCACHE IMAGEID PRIVATE_ARCHIVE' >&2; exit 2; }
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
image_id=$4
archive=$(/usr/bin/realpath -e -- "$5")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
source_root=$(/usr/bin/git -C "$script_root" rev-parse --show-toplevel)
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
checker="$source_root/chengwang/deploy/product-candidate/check_product_source.py"
registry_image=registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
evidence="$run_root/evidence"
private="$run_root/product-source-private"
fixture_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
fixture_root="/tmp/chengwang-product-lifecycle-$fixture_uuid"
label_key=org.chengwang.product-source-fixture
registry_id=''
registry_pid=''
source_pid=''
source_job=''
source_kind=''
source_flow=''
product_stopped=0
maximum_owned=0
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
test -x "$run_root/bin/product-source.test"
test -f "$evidence/product-image-packaged-contents.json"
test -f "$evidence/product-image-staging.json"
test -f "$evidence/product-state-outcome.json"
test -f "$evidence/product-source-fixture-preflight.json"
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
    echo "D12_PRODUCT_SOURCE_FAILURE_PHASE=$phase" >&3
    if ! /usr/bin/python3 -B - "$private" "$last_action_log" "$phase" > "$evidence/product-source-failure-diagnostic.json" <<'PY'
import json,os,pathlib,re,stat,sys
private,log,phase=sys.argv[1:]; assert re.fullmatch(r'[a-z0-9-]{1,96}',phase)
line_number=0
if log:
    path=pathlib.Path(log)
    assert path.parent==pathlib.Path(private) and re.fullmatch(r'(http-recovery|bad-signature|prefix-recovery)-(message-signature|dsse)-(prepare|run|reopen)\.private\.log',path.name)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<=info.st_size<=256<<10
        raw=handle.read((256<<10)+1); assert len(raw)==info.st_size
    for row in raw.splitlines():
        match=re.fullmatch(rb'\s*product_source_d12_linux_test\.go:([1-9][0-9]{0,5}): .*',row)
        if match: line_number=int(match[1])
print(json.dumps({'schema':'chengwang.product-source-failure/v1','phase':phase,'driverSourceLine':line_number,'outcome':'FAIL','rawPrivateLogPublished':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
    then
      /usr/bin/rm -f -- "$evidence/product-source-failure-diagnostic.json"
      echo 'D12_PRODUCT_SOURCE_FAILURE_DIAGNOSTIC=WITHHELD' >&3
    fi
  fi
  if test "$cleaned" != true; then
    if cleanup_owned; then cleaned=true; else echo 'D12_PRODUCT_SOURCE_CLEANUP=FAIL production=false' >&3; exit 1; fi
  fi
  if test "$original" -eq 0 && test "$accepted" != true; then exit 1; fi
  exit "$original"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

phase=private-provision
/usr/bin/python3 -B - "$evidence/product-state-outcome.json" "$source_commit" "$image_id" <<'PY'
import json,pathlib,sys
path,commit,image=sys.argv[1:]; value=json.loads(pathlib.Path(path).read_text())
assert value['schema']=='chengwang.product-state-gate/v1' and value['outcome']=='PASS' and value['sourceCommit']==commit and value['localImageID']==image
assert value['authorization']=='BLOCKED' and value['production'] is False and value['deviceActionsExecuted'] is False
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1]); root.mkdir(mode=0o700); os.chown(root,10001,10001)
for name in ('bin','tmp','evidence','refresh',*("source-"+flow for flow in ('http-recovery','bad-signature','prefix-recovery'))):
    (root/name).mkdir(mode=0o700); os.chown(root/name,10001,10001)
for flow in ('http-recovery','bad-signature','prefix-recovery'):
    (root/'refresh'/flow).mkdir(mode=0o700); os.chown(root/'refresh'/flow,10001,10001)
with (root/'.fixture-owner').open('x',encoding='ascii') as f: f.write(sys.argv[2]+'\n')
os.chmod(root/'.fixture-owner',0o600); os.chown(root/'.fixture-owner',10001,10001)
PY
/usr/bin/sudo --non-interactive /usr/bin/install -m 0555 -o 0 -g 0 "$run_root/bin/product-source.test" "$fixture_root/bin/product-source.test"
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
base='chengwang/deploy/product-candidate/'
runtime=('check_product_source.py','check_product_image.py','check_product_registry.py','check_product_lifecycle.py','check_source_preflight.py','check_lifecycle_preflight.py','fixture_source.py','fixture_feed.py')
names=runtime+('test_check_product_source.py','test_source_image_profile.py')
files={}
for name in names:
    path=root/(base+name); assert path.is_file() and not path.is_symlink()
    raw=path.read_bytes(); assert len(raw)<=256<<10
    assert raw==subprocess.check_output(['/usr/bin/git','-C',str(root),'cat-file','blob',commit+':'+base+name])
    files[base+name]=hashlib.sha256(raw).hexdigest()
print(json.dumps({'sourceCommit':commit,'files':files},sort_keys=True))
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_root" "$fixture_root" "$private/tool-input.json" > "$evidence/product-source-harness.json" <<'PY'
import hashlib,json,os,pathlib,sys
source,root,record=map(pathlib.Path,sys.argv[1:]); data=json.loads(record.read_text())
runtime={'check_product_source.py','check_product_image.py','check_product_registry.py','check_product_lifecycle.py','check_source_preflight.py','check_lifecycle_preflight.py','fixture_source.py','fixture_feed.py'}
destination=root/'bin/checker'; destination.mkdir(mode=0o555); os.chmod(destination,0o555)
for name,digest in data['files'].items():
    raw=(source/name).read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest
    if pathlib.Path(name).name in runtime:
        target=destination/pathlib.Path(name).name
        with target.open('xb') as output: output.write(raw)
        os.chmod(target,0o444)
assert {p.name for p in destination.iterdir()}==runtime
print(json.dumps({'schema':'chengwang.product-source-harness/v1',**data,'checkoutBytesMatched':True,'permissionReadOnly':True,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
/usr/bin/timeout --signal=TERM --kill-after=5s 60s /usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_source_image_profile.py" > "$evidence/product-source-profile-tests.log" 2>&1
/usr/bin/timeout --signal=TERM --kill-after=5s 60s /usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_check_product_source.py" > "$evidence/product-source-verifier-tests.log" 2>&1

phase=registry-start
registry_id=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
  --name "cw-product-source-$fixture_uuid" --label "$label_key=$fixture_uuid" \
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
maximum_owned=1
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
' "$source_commit" "$registry_id" > "$evidence/product-source-network.json"
wait_tls registry 5443
/usr/bin/python3 -B - "$private/registry-image-inspect.json" "$private/registry-container-inspect.json" "$registry_id" "$registry_image" "$fixture_root" "$source_commit" > "$evidence/product-source-isolation.json" <<'PY'
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
    return equivalent,{'schema':'chengwang.product-source-env-diagnostic/v1','baseShapeValid':base_shape,'baseKeysUnique':base_unique,'actualShapeValid':actual_shape,'actualKeysUnique':actual_unique,'expectedCount':len(expected) if expected is not None else 0,'actualCount':len(observed) if observed is not None else 0,'expectedMappingSHA256':digest(expected),'actualMappingSHA256':digest(observed),'equivalent':equivalent}

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


# Source-wave1 action and lifecycle implementation follows.
fixture_action() {
  local action=$1 log marker deadline=60 test_deadline=55
  if test "$action" = run; then deadline=120; test_deadline=110; fi
  log="$private/$flow-$kind-$action.private.log"
  last_action_log=$log
  phase="$action-$flow-$kind"
  in_fixture CHENGWANG_D12_SOURCE_ROOT="$fixture_root" CHENGWANG_D12_SOURCE_FLOW="$flow" \
    CHENGWANG_D12_SOURCE_KIND="$kind" CHENGWANG_D12_SOURCE_ACTION="$action" \
    CHENGWANG_D12_SOURCE_COMMIT="$source_commit" CHENGWANG_D12_SOURCE_IMAGE_ID="$image_id" \
    CHENGWANG_D12_SOURCE_ARCHIVE="$fixture_root/bin/product-image.private.tar" \
    /usr/bin/timeout --signal=TERM --kill-after=5s "$deadline"s "$fixture_root/bin/product-source.test" \
      -test.run='^TestProductSourceD12Fixture$' -test.v -test.timeout="$test_deadline"s 2>&1 | /usr/bin/tee "$log" >/dev/null
  marker="D12_PRODUCT_SOURCE_$(/usr/bin/printf %s "$action" | /usr/bin/tr '[:lower:]' '[:upper:]')=PASS flow=$flow kind=$kind authorization=BLOCKED production=false"
  test "$(/usr/bin/grep -Fxc -- "$marker" "$log")" -eq 1
  test "$(/usr/bin/grep -Ec '^--- PASS: TestProductSourceD12Fixture \(' "$log")" -eq 1
  echo "$marker"
}

snapshot() {
  local flow=$1 kind=$2 action=$3 position=$4
  phase="observe-$flow-$kind-$action-$position"
  /usr/bin/docker logs "$registry_id" > "$private/registry-log.private" 2>&1
  /usr/bin/python3 -B - "$private/registry-log.private" "$private/snapshots.private.json" "$flow" "$kind" "$action" "$position" <<'PY'
import collections,json,pathlib,re,sys
log,record,flow,kind,action,position=sys.argv[1:]; raw=pathlib.Path(log).read_bytes(); assert len(raw)<=32<<20
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
data.append({'ordinal':len(data)+1,'flow':flow,'kind':kind,'action':action,'position':position,'digestRequests':[{'method':m,'digest':d,'status':s,'count':n} for (m,d,s),n in sorted(digest.items())],'otherRequests':[{'method':m,'status':s,'count':n} for (m,s),n in sorted(other.items())]})
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
    --expected-private-source "$fixture_root/refresh/$flow/$kind" --expected-state-source "$fixture_root/refresh/$flow/$kind/trust" \
    --expected-network-mode "container:$registry_id" --container-status "$state" \
    --report "$evidence/product-source-$flow-$kind-$label-inspect.json"
}
record_pid1() {
  local id=$1 kind=$2 label=$3 pid
  pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$id")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$pid" "$fixture_root/refresh/$flow/$kind" "$run_root/bin/image-trust-api-static" "$source_commit" "$image_id" "$id" > "$evidence/product-source-$flow-$kind-$label-pid1.json" <<'PY'
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
# Root-only observer. The source itself remains UID10001/cap0/NNP.
source_control() {
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$source_flow" "$source_kind" \
    "$source_job" "$registry_pid" "$source_commit" "$source_root" "$@" <<'PY'
import hashlib,json,os,pathlib,re,signal,stat,sys,time
root,flow,kind,job,registry,commit,source,mode=sys.argv[1:]
assert re.fullmatch(r'/tmp/chengwang-product-lifecycle-[a-f0-9]{32}',root)
assert flow in ('http-recovery','bad-signature','prefix-recovery') and kind in ('message-signature','dsse')
directory=pathlib.Path(root)/('source-'+flow)/kind; feed=directory/'feed'
boundary={'sourceCommit':commit,'flow':flow,'kind':kind,'sourceCase':'source-'+flow,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False}
limits={'cpuSeconds':60,'addressSpaceBytes':536870912,'fileBytes':16777216,'openFiles':128,'processes':128,'coreBytes':0}
def identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def read(path,limit,empty=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==10001 and stat.S_IMODE(before.st_mode)==0o600
        assert (0 if empty else 1)<=before.st_size<=limit
        chunks=[]; remaining=limit+1
        while remaining:
            value=os.read(fd,min(65536,remaining))
            if not value: break
            chunks.append(value); remaining-=len(value)
        raw=b''.join(chunks)
        assert len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
        return raw
    finally: os.close(fd)
def unique(pairs):
    result={}
    for key,value in pairs:
        assert key not in result; result[key]=value
    return result
def parse(raw):
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid-number')))
def record():
    value=parse(read(directory/'source-process.private.json',1024))
    assert set(value)=={'pid','startTime'} and all(type(value[k]) is int and value[k]>0 for k in value) and value['pid']>1
    return value
def process(value):
    pid=value['pid']; proc=pathlib.Path('/proc')/str(pid)
    parts=(proc/'stat').read_text().rsplit(')',1)[1].split()
    assert parts[0] not in ('Z','X') and int(parts[19])==value['startTime']
    fields=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines())
    assert all(fields[k].split()==['10001']*4 for k in ('Uid','Gid')) and fields['NoNewPrivs'].strip()=='1' and not fields['Groups'].strip()
    assert all(int(fields[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    expected=['/usr/bin/python3','-B',root+'/bin/checker/fixture_source.py','serve','--fixture-root',root,'--case','source-'+flow,'--kind',kind,'--port','5444','--deadline-seconds','600']
    assert (proc/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==expected
    assert (proc/'ns/net').readlink()==pathlib.Path('/proc',registry,'ns/net').readlink()
    assert (proc/'ns/mnt').readlink()!=pathlib.Path('/proc/self/ns/mnt').readlink()
    ancestor=pid
    for _ in range(24):
        if ancestor==int(job): break
        ancestor=int(dict(line.split(':',1) for line in pathlib.Path(f'/proc/{ancestor}/status').read_text().splitlines())['PPid']); assert ancestor>1
    else: raise AssertionError('source-ancestry')
    names={'cpuSeconds':'Max cpu time','addressSpaceBytes':'Max address space','fileBytes':'Max file size','openFiles':'Max open files','processes':'Max processes','coreBytes':'Max core file size'}
    rows=(proc/'limits').read_text().splitlines()
    for key,name in names.items():
        selected=[row for row in rows if row.startswith(name+' ')]
        assert len(selected)==1 and re.fullmatch(re.escape(name)+r'\s+'+str(limits[key])+r'\s+'+str(limits[key])+r'(?:\s+[a-z]+)?\s*',selected[0])
    return proc
def events(raw):
    assert not raw or raw.endswith(b'\n')
    keys={'schema','ordinal','connection','event','reason','epoch','planSHA256','pathClass','generation','mode','status','representationSHA256','representationBytes','wireSHA256','wireBytes','writtenBytes','wireComplete','authPresent','tls'}
    reasons={'accepted','ok','failed','timeout','stopping','closed','planned','request-invalid','method-invalid','auth-present','plan-unavailable','plan-invalid','epoch-rollback','epoch-conflict','not-planned','body-unavailable','body-mismatch'}
    modes={'','json','forbidden','unavailable','redirect','content-type-missing','content-type-duplicate','content-type-wrong','content-encoding','trailer','chunked','length-missing','length-zero','length-oversize','length-short','body-truncated','header-oversize','stall-headers','stall-body','close-before-headers'}
    values=[]
    for ordinal,line in enumerate(raw.splitlines(),1):
        assert len(line)<=4096; value=parse(line)
        assert type(value) is dict and set(value)==keys and value['schema']=='chengwang.product-source-event/v1' and type(value['ordinal']) is int and value['ordinal']==ordinal
        assert value['event'] in ('connect','tls','http','close') and value['reason'] in reasons and value['mode'] in modes and value['pathClass'] in ('','latest','generation','invalid')
        for key in ('connection','epoch','generation','status','representationBytes','wireBytes','writtenBytes'):
            assert type(value[key]) is int and 0<=value[key]<1<<64
        for key in ('planSHA256','representationSHA256','wireSHA256'):
            assert value[key]=='' or type(value[key]) is str and re.fullmatch(r'[a-f0-9]{64}',value[key])
        assert all(type(value[key]) is bool for key in ('wireComplete','authPresent','tls'))
        values.append(value)
    assert len(values)<=4096
    return values
def prefix():
    raw=read(feed/'events.jsonl',4<<20,True); values=events(raw)
    return {'eventCount':len(values),'sha256':hashlib.sha256(raw).hexdigest()}
if mode=='ready':
    deadline=time.monotonic()+10
    while True:
        try:
            value=record(); ready=parse(read(feed/'ready.json',16384)); proc=process(value)
            assert ready=={'schema':'chengwang.product-source-ready/v1','port':5444,'pid':value['pid'],'uid':10001,'gid':10001,'tls':True,'listenLoopback':True,'deadlineSeconds':600}
            assert read(feed/'events.jsonl',4<<20,True)==b'' and len(list((proc/'task').iterdir()))==1
            break
        except FileNotFoundError:
            assert time.monotonic()<deadline; time.sleep(.025)
    script=pathlib.Path(root)/'bin/checker/fixture_source.py'; dependency=script.with_name('fixture_feed.py')
    original=pathlib.Path(source)/'chengwang/deploy/product-candidate'
    script_sha=hashlib.sha256(script.read_bytes()).hexdigest(); dependency_sha=hashlib.sha256(dependency.read_bytes()).hexdigest()
    assert script_sha==hashlib.sha256((original/'fixture_source.py').read_bytes()).hexdigest()
    assert dependency_sha==hashlib.sha256((original/'fixture_feed.py').read_bytes()).hexdigest()
    executable=hashlib.sha256((proc/'exe').read_bytes()).hexdigest(); assert executable==hashlib.sha256(pathlib.Path('/usr/bin/python3').read_bytes()).hexdigest()
    print(json.dumps({'schema':'chengwang.product-source-process/v1',**boundary,'hostPID':value['pid'],'hostStartTime':value['startTime'],'uid':10001,'gid':10001,'capabilities':'none','noNewPrivileges':True,'registryNetworkNamespaceMatched':True,'privateMountNamespace':True,'sourceSHA256':script_sha,'dependencySHA256':dependency_sha,'pythonExecutableSHA256':executable,'gitBoundSourceMatched':True,'sourceLimitsVerified':True,'sourceLimits':limits},sort_keys=True))
elif mode in ('before-stop','after-stop'):
    value=record(); deadline=time.monotonic()+4
    while True:
        proc=process(value)
        try:
            if mode=='after-stop' and len(list((proc/'task').iterdir()))!=1: raise ValueError('pending-source-worker')
            current=prefix()
            if mode=='after-stop' and len(list((proc/'task').iterdir()))!=1: raise ValueError('pending-source-worker')
            break
        except (ValueError,AssertionError):
            assert time.monotonic()<deadline; time.sleep(.025)
    path=directory/'stop-windows.private.json'
    if mode=='before-stop':
        assert not path.exists() and not path.is_symlink(); windows=[{'label':'final','before':current}]
    else:
        windows=parse(read(path,16384)); assert len(windows)==1 and windows[0]['label']=='final' and set(windows[0])=={'label','before'}
        assert current['eventCount']>=windows[0]['before']['eventCount']; windows[0]['after']=current
    pending=directory/'.stop-windows.private.pending'; fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as handle:
        os.fchown(handle.fileno(),10001,10001); handle.write(json.dumps(windows,sort_keys=True).encode()+b'\n'); handle.flush(); os.fsync(handle.fileno())
    os.replace(pending,path)
elif mode=='signal':
    value=record(); held=os.pidfd_open(value['pid'])
    try:
        process(value); signal.pidfd_send_signal(held,signal.SIGTERM)
    finally: os.close(held)
elif mode=='stopped':
    value=record()
    try:
        current=pathlib.Path('/proc',str(value['pid']),'stat').read_text().rsplit(')',1)[1].split()
        assert int(current[19])!=value['startTime'] or current[0] in ('Z','X')
    except FileNotFoundError: pass
    windows=parse(read(directory/'stop-windows.private.json',16384))
    assert len(windows)==1 and windows[0]['label']=='final' and set(windows[0])=={'label','before','after'}
    assert windows[0]['after']==prefix()
    print(json.dumps({'schema':'chengwang.product-source-stop/v1',**boundary,'hostPID':value['pid'],'startTime':value['startTime'],'signal':'SIGTERM','exitCode':0,'joined':True,'productStopWindows':windows},sort_keys=True))
else: raise AssertionError('source-control-mode')
PY
}

start_source() {
  source_flow=$flow; source_kind=$kind
  phase="source-start-$flow-$kind"
  /usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$fixture_root/source-cert.pem" "$fixture_root/source-$flow/$kind/feed/server.crt"
  /usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$fixture_root/source-key.private.pem" "$fixture_root/source-$flow/$kind/feed/server.key"
  in_fixture /usr/bin/python3 -B -c '
import ctypes,json,os,pathlib,resource,sys
root,flow,kind=sys.argv[1:]; directory=pathlib.Path(root)/("source-"+flow)/kind; path=directory/"source-process.private.json"
for limit,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,60),(resource.RLIMIT_AS,512<<20),(resource.RLIMIT_FSIZE,16<<20),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_NPROC,128)):
    resource.setrlimit(limit,(value,value))
start=int(pathlib.Path("/proc/self/stat").read_text().rsplit(")",1)[1].split()[19])
pending=path.with_name(".source-process.private.pending"); fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
with os.fdopen(fd,"wb") as output:
    output.write(json.dumps({"pid":os.getpid(),"startTime":start},sort_keys=True).encode()+b"\n"); output.flush(); os.fsync(output.fileno())
parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    rename=ctypes.CDLL(None,use_errno=True).renameat2
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint); rename.restype=ctypes.c_int
    assert rename(parent,pending.name.encode(),parent,path.name.encode(),1)==0; os.fsync(parent)
finally: os.close(parent)
os.execv("/usr/bin/python3",["/usr/bin/python3","-B",root+"/bin/checker/fixture_source.py","serve","--fixture-root",root,"--case","source-"+flow,"--kind",kind,"--port","5444","--deadline-seconds","600"])
' "$fixture_root" "$flow" "$kind" > "$private/$flow-$kind-source.private.log" 2>&1 &
  source_job=$!
  phase="source-ready-$flow-$kind"
  # No TCP, TLS or HTTP source readiness probe: all source connections belong
  # to the closed product exercise, not the orchestrator's health checks.
  source_control ready > "$evidence/product-source-$flow-$kind-source.json"
  source_pid=$(/usr/bin/python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["hostPID"])' "$evidence/product-source-$flow-$kind-source.json")
  [[ "$source_pid" =~ ^[1-9][0-9]*$ ]]
}
stop_source() {
  local emergency=$1 result=0
  source_control signal || result=1
  if ! wait "$source_job"; then result=1; fi
  if test "$result" -eq 0 && test "$emergency" = false; then
    source_control stopped > "$evidence/product-source-$source_flow-$source_kind-source-stop.json" || result=1
    if test "$result" -eq 0; then source_stopped=$((source_stopped+1)); fi
  fi
  source_job=''; source_pid=''
  test "$result" -eq 0
}
record_created() {
  local role=$1 id=$2
  /usr/bin/python3 -B - "$private/created.private.json" "$role" "$id" "$flow" "$kind" <<'PY'
import json,pathlib,re,sys
path,role,container,flow,kind=sys.argv[1:]; path=pathlib.Path(path)
assert role in ('product','registry') and re.fullmatch(r'[a-f0-9]{64}',container)
if role=='registry': flow=kind=''
else: assert flow in ('http-recovery','bad-signature','prefix-recovery') and kind in ('message-signature','dsse')
values=json.loads(path.read_bytes()) if path.exists() else []
assert container not in {value['containerID'] for value in values}
values.append({'containerID':container,'role':role,'flow':flow,'kind':kind})
with path.open('w',encoding='ascii') as handle: json.dump(values,handle,sort_keys=True); handle.write('\n')
path.chmod(0o600)
PY
}
flow=''; kind=''
record_created registry "$registry_id"
for flow in http-recovery bad-signature prefix-recovery; do
  for kind in message-signature dsse; do
    phase="prepare-$flow-$kind"
    snapshot "$flow" "$kind" prepare before
    fixture_action prepare
    after_snapshot "$flow" "$kind" prepare
    endpoint="$fixture_root/refresh/$flow/$kind"
    manifest_digest=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B -c 'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$endpoint/graph/manifest.json")
    in_fixture /usr/bin/python3 -B "$fixture_root/bin/checker/check_product_source.py" graph --graph-dir "$endpoint/graph" \
      --packaged-report "$fixture_root/bin/product-image-packaged-contents.json" --source-commit "$source_commit" \
      --manifest-digest "$manifest_digest" --report "$fixture_root/evidence/product-source-$flow-$kind-graph.json"
    start_source
    snapshot "$flow" "$kind" run before
    phase="start-$flow-$kind"
    product_id=$(/usr/bin/docker create --pull never --platform linux/amd64 --name "cw-source-product-$fixture_uuid-$flow-$kind" \
      --label "$label_key=$fixture_uuid" --network "container:$registry_id" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
      --memory 256m --memory-swap 256m --cpus 1 --pids-limit 128 --ulimit nofile=1024:1024 --restart no --stop-timeout 15 \
      --mount "type=bind,src=$endpoint,dst=$endpoint,readonly,bind-propagation=rprivate" \
      --mount "type=bind,src=$endpoint/trust,dst=$endpoint/trust,bind-propagation=rprivate" \
      --mount "type=bind,src=$endpoint/data,dst=$endpoint/data,bind-propagation=rprivate" \
      "$image_id" --config "$endpoint/trust-config.json" --product-config "$endpoint/product-config.json")
    [[ "$product_id" =~ ^[a-f0-9]{64}$ ]]; owned_ids+=("$product_id")
    record_created product "$product_id"
    actual_owned=$(/usr/bin/docker container ls -aq --filter "label=$label_key=$fixture_uuid" | /usr/bin/wc -l)
    test "$actual_owned" -eq 2
    if test "$actual_owned" -gt "$maximum_owned"; then maximum_owned=$actual_owned; fi
    /usr/bin/docker start "$product_id" >/dev/null
    inspect_product "$product_id" "$kind" running running
    record_pid1 "$product_id" "$kind" running
    if test "$kind" = message-signature; then api_port=17821; else api_port=17822; fi
    wait_tls api "$api_port"
    fixture_action run
    phase="stop-$flow-$kind"
    source_control before-stop
    /usr/bin/docker stop --signal SIGTERM --timeout 15 "$product_id" > "$private/stop.private.log" 2>&1
    inspect_product "$product_id" "$kind" exited exited
    source_control after-stop
    product_stopped=$((product_stopped+1))
    after_snapshot "$flow" "$kind" run
    snapshot "$flow" "$kind" reopen before
    fixture_action reopen
    after_snapshot "$flow" "$kind" reopen
    phase="source-stop-$flow-$kind"
    stop_source false
    phase="remove-product-$flow-$kind"
    test "$(/usr/bin/docker inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$product_id")" = "$fixture_uuid"
    /usr/bin/docker rm "$product_id" >/dev/null
    if /usr/bin/docker inspect "$product_id" >/dev/null 2>&1; then exit 1; fi
    test "$(/usr/bin/docker container ls -aq --filter "label=$label_key=$fixture_uuid" | /usr/bin/wc -l)" -eq 1
    product_id=''
  done
done

phase=safe-evidence-export
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$private" <<'PY'
import hashlib,json,os,pathlib,re,stat,sys
root,destination=map(pathlib.Path,sys.argv[1:])
flows=('http-recovery','bad-signature','prefix-recovery'); kinds=('message-signature','dsse')
names={f'product-source-{flow}-{kind}-{action}.json' for flow in flows for kind in kinds for action in ('prepare','run','reopen','graph')}
assert {path.name for path in (root/'evidence').iterdir()}==names
secrets=[]
for flow in flows:
    for kind in kinds:
        path=root/'refresh'/flow/kind/'admin-token.private'
        token=path.read_bytes().strip(); assert 16<=len(token)<=4096; secrets.append(token)
def identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==10001 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=limit
        chunks=[]; remaining=limit+1
        while remaining:
            chunk=os.read(fd,min(65536,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        raw=b''.join(chunks)
        assert len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
        assert b'PRIVATE KEY' not in raw and not any(token in raw for token in secrets)
        return raw
    finally: os.close(fd)
def output(name,raw):
    fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
for name in sorted(names):
    raw=read(root/'evidence'/name,512<<10); value=json.loads(raw)
    assert value['authorization']=='BLOCKED' and value['production'] is False and value['deviceActionsExecuted'] is False
    output(name,raw)
for flow in flows:
    for kind in kinds:
        directory=root/('source-'+flow)/kind
        ready=read(directory/'feed/ready.json',16384); value=json.loads(ready)
        assert set(value)=={'schema','port','pid','uid','gid','tls','listenLoopback','deadlineSeconds'} and value['schema']=='chengwang.product-source-ready/v1'
        assert value['uid']==value['gid']==10001 and value['tls'] is True and value['listenLoopback'] is True and value['port']==5444 and value['deadlineSeconds']==600
        log=read(directory/'feed/events.jsonl',4<<20); assert log.endswith(b'\n')
        for ordinal,line in enumerate(log.splitlines(),1):
            event=json.loads(line); assert event['schema']=='chengwang.product-source-event/v1' and type(event['ordinal']) is int and event['ordinal']==ordinal
        windows=json.loads(read(directory/'stop-windows.private.json',16384))
        assert len(windows)==1 and windows[0]['label']=='final'
        assert windows[0]['after']=={'eventCount':len(log.splitlines()),'sha256':hashlib.sha256(log).hexdigest()}
        output(f'product-source-{flow}-{kind}-feed-ready.json',ready)
        output(f'product-source-{flow}-{kind}-feed-events.jsonl',log)
PY
for flow in http-recovery bad-signature prefix-recovery; do
  for kind in message-signature dsse; do
    for action in prepare run reopen graph feed-ready feed-events; do
      extension=json
      if test "$action" = feed-events; then extension=jsonl; fi
      /usr/bin/sudo --non-interactive /usr/bin/cat "$private/product-source-$flow-$kind-$action.$extension" > "$evidence/product-source-$flow-$kind-$action.$extension"
    done
  done
done
phase=safe-observations-export
/usr/bin/python3 -B - "$private/snapshots.private.json" "$source_commit" "$image_id" "$registry_id" "$registry_image" > "$evidence/product-source-observations.json" <<'PY'
import json,os,pathlib,stat,sys
path,commit,image,registry,pin=sys.argv[1:]; path=pathlib.Path(path)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
    before=os.fstat(fd); assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=2<<20
    raw=os.read(fd,(2<<20)+1); after=os.fstat(fd); named=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)==identity(named)
finally: os.close(fd)
values=json.loads(raw); assert type(values) is list and len(values)==36
print(json.dumps({'schema':'chengwang.product-source-observations/v1','sourceCommit':commit,'localImageID':image,'registryContainerID':registry,'pinnedRegistryImage':pin,'snapshots':values,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
phase=graceful-registry-stop
/usr/bin/docker stop --signal SIGTERM --timeout 15 "$registry_id" > "$private/registry-stop.private.log" 2>&1
/usr/bin/docker inspect "$registry_id" > "$private/registry-exited.private.json"
/usr/bin/python3 -B - "$private/registry-exited.private.json" <<'PY'
import json,pathlib,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_bytes())[0]['State']
assert value['Status']=='exited' and value['Running'] is False and type(value['ExitCode']) is int and value['ExitCode']==0 and value['Pid']==0 and not value['OOMKilled'] and not value.get('Error')
print('D12_SOURCE_REGISTRY_GRACEFUL_STOP=PASS exit_code=0 oom=false pid=0')
PY
phase=exact-owned-cleanup
test "$source_stopped" -eq 6 && test "$product_stopped" -eq 6 && test "$maximum_owned" -eq 2
test "${#owned_ids[@]}" -eq 7
cleanup_projection=$(/usr/bin/python3 -B - "$private/created.private.json" <<'PY'
import json,pathlib,sys
values=json.loads(pathlib.Path(sys.argv[1]).read_bytes())
assert len(values)==7 and len({value['containerID'] for value in values})==7
assert sum(value['role']=='registry' for value in values)==1 and sum(value['role']=='product' for value in values)==6
print(json.dumps(values,sort_keys=True,separators=(',',':')))
PY
)
cleanup_owned
cleaned=true
test -z "$(/usr/bin/docker container ls -aq --filter "label=$label_key=$fixture_uuid")"
# Retain only safe IDs across private cleanup; publish PASS only after every
# exact owned container/source/tree was actually removed and joined.
/usr/bin/python3 -B - "$cleanup_projection" "$source_commit" "$image_id" > "$evidence/product-source-runtime-cleanup.json" <<'PY'
import json,sys
records,commit,image=sys.argv[1:]
print(json.dumps({'schema':'chengwang.product-source-cleanup/v1','sourceCommit':commit,'localImageID':image,'ownedContainersRemoved':7,'ownedSourcesJoined':6,'sourceExitCodes':[0]*6,'normalProductStops':6,'maximumConcurrentOwnedContainers':2,'noOwnedContainersRemain':True,'removedContainers':json.loads(records),'registryStop':{'signal':'SIGTERM','exitCode':0,'oomKilled':False,'pid':0},'privateFixtureRemoved':True,'outerProductImagePreserved':True,'registryImagePreserved':True,'outcome':'PASS','authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
echo 'D12_PRODUCT_SOURCE_CLEANUP=PASS exact_owned_containers=7 owned_sources_joined=6 normal_product_stops=6 maximum_concurrent_owned_containers=2 outer_image_preserved=true private_fixture_removed=true production=false'
phase=independent-final-check
/usr/bin/python3 -B "$checker" verify --evidence-dir "$evidence" --source-commit "$source_commit" --report "$evidence/product-source-outcome.json"
accepted=true
echo 'D12_PRODUCT_SOURCE_GATE=PASS actual_product_image=true flows=3 signatures=2 sdk_consumptions=0 source_readiness_no_probe=true authorization=BLOCKED production=false'
