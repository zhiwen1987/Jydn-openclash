#!/usr/bin/env bash
# D11: consume this round's actual product image through an isolated TLS Registry.
# No image build, external push, production network or device action is allowed.
set -euo pipefail
umask 077
export PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1
test "$#" -eq 5 || { echo 'usage: run-product-registry-gate.sh RUNROOT GOBIN MODCACHE IMAGEID PRIVATE_ARCHIVE' >&2; exit 2; }
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
image_id=$4
archive=$(/usr/bin/realpath -e -- "$5")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
source_root=$(/usr/bin/git -C "$script_root" rev-parse --show-toplevel)
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
checker="$source_root/chengwang/deploy/product-candidate/check_product_registry.py"
registry_image=registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
evidence="$run_root/evidence"
private="$run_root/product-registry-private"
fixture_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
fixture_root="/tmp/chengwang-product-registry-$fixture_uuid"
label_key=org.chengwang.product-registry-fixture
registry_id=''
registry_pid=''
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
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in ext4|xfs) ;; *) echo 'D11 requires durable native /tmp' >&2; exit 1;; esac
test -x "$run_root/bin/product-registry.test"
test -f "$evidence/product-image-packaged-contents.json"
test -f "$evidence/product-image-staging.json"
test -f "$archive" && test ! -L "$archive"
test ! -e "$private" && test ! -e "$fixture_root"
/usr/bin/install -d -m 0700 "$private"

cleanup_owned() {
  local failed=0 item index
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
assert re.fullmatch(r'[a-f0-9]{32}',identity) and str(root)=='/tmp/chengwang-product-registry-'+identity
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
  /usr/bin/find "$private" -maxdepth 1 -type f -delete
  test "$failed" -eq 0
}
on_exit() {
  local original=$?
  trap - EXIT HUP INT TERM
  if test "$original" -ne 0; then
    echo "D11_PRODUCT_REGISTRY_FAILURE_PHASE=$phase" >&2
    # Diagnostic extraction cannot prevent cleanup. Only four fixed Go stage
    # constants survive; not a byte of arbitrary stderr, error text or paths.
    if ! /usr/bin/python3 -B - "$private" "$last_action_log" "$phase" "$last_action_kind" "$last_action" "$last_case" \
      > "$evidence/product-registry-failure-diagnostic.json" <<'PY'
import json,os,pathlib,re,stat,sys
private,log,phase,kind,action,case=sys.argv[1:]
assert re.fullmatch(r'[a-z0-9-]{1,96}',phase)
assert kind in ('','message-signature','dsse') and action in ('','prepare','exercise','resume','catalogue','verify') and case in ('','0','1','2','3','4','first','final')
stages=[]
fixture_source_line=0
if log:
    path=pathlib.Path(log)
    assert path.parent==pathlib.Path(private) and re.fullmatch(r'(message-signature|dsse)-(prepare|exercise|resume|catalogue|verify)-(0|[1-4]|first|final)\.private\.log',path.name)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as handle:
        info=os.fstat(handle.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<=info.st_size<=128<<10
        raw=handle.read((128<<10)+1)
        assert len(raw)==info.st_size
    for line in raw.splitlines():
        match=re.fullmatch(rb'D11_PRODUCT_REGISTRY_STAGE=(archive-validated|uploaded-readback-matched|signed-catalogues-validated|store-created) kind=(message-signature|dsse)',line)
        if match and match[2].decode('ascii')==kind: stages.append(match[1].decode('ascii'))
        source_match=re.fullmatch(rb'\s*product_registry_d11_linux_test\.go:([1-9][0-9]{0,5}): isolated product registry fixture rejected',line)
        if source_match: fixture_source_line=int(source_match[1])
print(json.dumps({'schema':'chengwang.product-registry-failure/v1','outcome':'FAIL','phase':phase,'kind':kind,'action':action,'case':case,'safeStages':stages,'fixtureSourceLine':fixture_source_line,'rawPrivateLogPublished':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
    then
      /usr/bin/rm -f -- "$evidence/product-registry-failure-diagnostic.json"
      echo 'D11_PRODUCT_REGISTRY_FAILURE_DIAGNOSTIC=WITHHELD' >&2
    fi
  fi
  if test "$cleaned" != true; then
    if cleanup_owned; then cleaned=true; else echo 'D11_PRODUCT_REGISTRY_CLEANUP=FAIL production=false' >&2; exit 1; fi
  fi
  if test "$original" -eq 0 && test "$accepted" != true; then exit 1; fi
  exit "$original"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

phase=private-provision
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1]); root.mkdir(mode=0o700); os.chown(root,10001,10001)
for name in ('bin','tmp','evidence'):
    (root/name).mkdir(mode=0o700); os.chown(root/name,10001,10001)
with (root/'.fixture-owner').open('x',encoding='ascii') as f: f.write(sys.argv[2]+'\n')
os.chmod(root/'.fixture-owner',0o600); os.chown(root/'.fixture-owner',10001,10001)
PY
/usr/bin/sudo --non-interactive /usr/bin/install -m 0555 -o 0 -g 0 "$run_root/bin/product-registry.test" "$fixture_root/bin/product-registry.test"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0600 -o 10001 -g 10001 "$archive" "$fixture_root/bin/product-image.private.tar"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0444 -o 0 -g 0 "$evidence/product-image-packaged-contents.json" "$fixture_root/bin/product-image-packaged-contents.json"
# OpenSSL output and signing keys remain private. Each CA has a distinct key.
/usr/bin/sudo --non-interactive /usr/bin/bash -euo pipefail -c '
  root=$1
  for purpose in registry api; do
    /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 -subj "/CN=Chengwang isolated D11 $purpose CA" -keyout "$root/bin/$purpose-ca-key.private.pem" -out "$root/$purpose-ca.pem"
    /usr/bin/openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=$purpose.fixture.invalid" -keyout "$root/$purpose-key.private.pem" -out "$root/bin/$purpose.private.csr"
    /usr/bin/printf "subjectAltName=DNS:%s.fixture.invalid,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n" "$purpose" > "$root/bin/$purpose.private.ext"
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
names=('chengwang/deploy/product-candidate/check_product_registry.py','chengwang/deploy/product-candidate/check_product_image.py')
files={}
for name in names:
    path=root/name
    assert path.is_file() and not path.is_symlink()
    raw=path.read_bytes()
    assert raw==subprocess.check_output(['/usr/bin/git','-C',str(root),'show',commit+':'+name]) and len(raw)<=256<<10
    files[name]=hashlib.sha256(raw).hexdigest()
print(json.dumps({'sourceCommit':commit,'files':files},sort_keys=True))
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_root" "$fixture_root" "$private/tool-input.json" > "$evidence/product-registry-harness.json" <<'PY'
import hashlib,json,os,pathlib,sys
source,root,record=map(pathlib.Path,sys.argv[1:]); data=json.loads(record.read_text())
destination=root/'bin/checker'
destination.mkdir(mode=0o555); os.chmod(destination,0o555)
for name,digest in data['files'].items():
    original=source/name; raw=original.read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest
    target=destination/pathlib.Path(name).name
    with target.open('xb') as f: f.write(raw)
    os.chmod(target,0o444)
print(json.dumps({'schema':'chengwang.product-registry-harness/v1',**data,'checkoutBytesMatched':True,'permissionReadOnly':True,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY

phase=registry-start
registry_id=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
  --name "cw-product-registry-$fixture_uuid" --label "$label_key=$fixture_uuid" \
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
deadline=time.monotonic()+15
while True:
    try:
        with socket.create_connection(("127.0.0.1",port),timeout=1) as raw:
            with ctx.wrap_socket(raw,server_hostname=role+".fixture.invalid") as secure:
                assert secure.version() in ("TLSv1.2","TLSv1.3")
        break
    except (OSError,ssl.SSLError):
        if time.monotonic()>=deadline: raise SystemExit("D11_TLS_READINESS=FAIL")
        time.sleep(.1)
print("D11_TLS_READINESS=PASS normal_tls=true http_requests=0")
' "$fixture_root" "$1" "$2"
}
in_fixture /usr/bin/python3 -B -c '
import json,socket,sys
for family,address in ((socket.AF_INET,("1.1.1.1",443)),(socket.AF_INET6,("2606:4700:4700::1111",443,0,0))):
    try:
        with socket.socket(family,socket.SOCK_STREAM) as stream:
            stream.settimeout(.5); stream.connect(address)
    except OSError: continue
    raise SystemExit("D11_EXTERNAL_CONNECTIVITY=FAIL")
print(json.dumps({"schema":"chengwang.product-registry-network/v1","sourceCommit":sys.argv[1],"registryContainerID":sys.argv[2],"loopbackOnly":True,"defaultRoutes":0,"externalIPv4Blocked":True,"externalIPv6Blocked":True,"authorization":"BLOCKED","production":False,"deviceActionsExecuted":False},sort_keys=True))
' "$source_commit" "$registry_id" > "$evidence/product-registry-network.json"
wait_tls registry 5443
/usr/bin/python3 -B - "$private/registry-image-inspect.json" "$private/registry-container-inspect.json" "$registry_id" "$registry_image" "$fixture_root" "$source_commit" > "$evidence/product-registry-isolation.json" <<'PY'
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
    return equivalent,{'schema':'chengwang.product-registry-env-diagnostic/v1','baseShapeValid':base_shape,'baseKeysUnique':base_unique,'actualShapeValid':actual_shape,'actualKeysUnique':actual_unique,'expectedCount':len(expected) if expected is not None else 0,'actualCount':len(observed) if observed is not None else 0,'expectedMappingSHA256':digest(expected),'actualMappingSHA256':digest(observed),'equivalent':equivalent}

base_environment=image['Config'].get('Env')
if base_environment is None: base_environment=[]
environment_ok,environment_diagnostic=registry_environment_projection(base_environment,cfg.get('Env'))
if not environment_ok:
    print(json.dumps(environment_diagnostic,sort_keys=True),file=sys.stderr)
    raise SystemExit('D11_REGISTRY_ENV_CHECK=FAIL raw_environment_suppressed=true')
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
  local action=$1 kind=$2 case_number=${3:-0} log marker
  log="$private/$kind-$action-$case_number.private.log"
  last_action_log=$log; last_action_kind=$kind; last_action=$action; last_case=$case_number
  phase="$action-$kind-$case_number"
  in_fixture CHENGWANG_D11_ROOT="$fixture_root" CHENGWANG_D11_ACTION="$action" \
    CHENGWANG_D11_KIND="$kind" CHENGWANG_D11_CASE="$case_number" CHENGWANG_D11_IMAGE_ID="$image_id" \
    CHENGWANG_D11_COMMIT="$source_commit" CHENGWANG_D11_ARCHIVE="$fixture_root/bin/product-image.private.tar" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 60s "$fixture_root/bin/product-registry.test" \
      -test.run='^TestProductRegistryD11Fixture$' -test.v -test.timeout=55s 2>&1 | /usr/bin/tee "$log" >/dev/null
  marker="D11_PRODUCT_REGISTRY_${action^^}=PASS kind=$kind"
  if test "$action" = exercise || test "$action" = resume; then marker+=" case=$case_number"; fi
  if test "$action" = verify; then marker+=" phase=$case_number"; fi
  marker+=' authorization=BLOCKED production=false'
  test "$(/usr/bin/grep -Fxc -- "$marker" "$log")" -eq 1
  test "$(/usr/bin/grep -Ec '^--- PASS: TestProductRegistryD11Fixture \(' "$log")" -eq 1
  echo "$marker"
}
# Request observations are derived from Distribution's completed-request JSON,
# never product-reported counters. Upload UUIDs, query strings and raw lines are
# private; only fixed methods/digest/status/count are projected.
snapshot() {
  local kind=$1 action=$2 case_number=$3 position=$4
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
    --expected-private-source "$fixture_root/$kind" --expected-state-source "$fixture_root/$kind/trust" \
    --expected-network-mode "container:$registry_id" --container-status "$state" \
    --report "$evidence/product-registry-$kind-$label-inspect.json"
}
record_pid1() {
  local id=$1 kind=$2 label=$3 pid
  pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$id")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$pid" "$fixture_root/$kind" "$run_root/bin/image-trust-api-static" "$source_commit" "$image_id" "$id" > "$evidence/product-registry-$kind-$label-pid1.json" <<'PY'
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
  /usr/bin/docker stop --signal SIGTERM --timeout 15 "$1" > "$private/stop.private.log" 2>&1
  inspect_product "$1" "$2" exited "$3"
}

for kind in message-signature dsse; do
  phase="prepare-$kind"
  snapshot "$kind" prepare 0 before
  fixture_action prepare "$kind"
  after_snapshot "$kind" prepare 0
  manifest_digest=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B -c 'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$fixture_root/$kind/graph/manifest.json")
  in_fixture /usr/bin/python3 -B "$fixture_root/bin/checker/check_product_registry.py" graph --graph-dir "$fixture_root/$kind/graph" \
    --packaged-report "$fixture_root/bin/product-image-packaged-contents.json" --source-commit "$source_commit" \
    --manifest-digest "$manifest_digest" --report "$fixture_root/evidence/product-registry-$kind-graph.json"
  /usr/bin/sudo --non-interactive /usr/bin/cat "$fixture_root/evidence/product-registry-$kind-graph.json" > "$evidence/product-registry-$kind-graph.json"
  phase="start-$kind"
  endpoint="$fixture_root/$kind"
  product_id=$(/usr/bin/docker create --pull never --platform linux/amd64 --name "cw-registry-product-$fixture_uuid-$kind" \
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
  for case_number in 1 2 3 4; do
    phase="exercise-$kind-$case_number"
    snapshot "$kind" exercise "$case_number" before
    fixture_action exercise "$kind" "$case_number"
    after_snapshot "$kind" exercise "$case_number"
  done
  stop_product "$product_id" "$kind" exited
  fixture_action verify "$kind" first
  phase="restart-$kind"
  /usr/bin/docker start "$product_id" >/dev/null
  inspect_product "$product_id" "$kind" running restarted-running
  record_pid1 "$product_id" "$kind" restarted-running
  wait_tls api "$api_port"
  snapshot "$kind" resume 1 before
  fixture_action resume "$kind" 1
  after_snapshot "$kind" resume 1
  snapshot "$kind" catalogue 0 before
  fixture_action catalogue "$kind"
  after_snapshot "$kind" catalogue 0
  for case_number in 2 3 4; do
    phase="resume-$kind-$case_number"
    snapshot "$kind" resume "$case_number" before
    fixture_action resume "$kind" "$case_number"
    after_snapshot "$kind" resume "$case_number"
  done
  snapshot "$kind" final 0 before
  stop_product "$product_id" "$kind" restarted-exited
  fixture_action verify "$kind" final
  after_snapshot "$kind" final 0
done

phase=safe-evidence-export
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$private" <<'PY'
import json,pathlib,re,stat,sys
root,destination=map(pathlib.Path,sys.argv[1:])
names=[]
for kind in ('message-signature','dsse'):
    for action in ('prepare','exercise','resume','catalogue','verify-first','verify-final',*(f'exercise-{n}' for n in range(1,5)),*(f'resume-{n}' for n in range(1,5))):
        names.append(f'product-registry-{kind}-{action}.json')
actual={p.name for p in (root/'evidence').iterdir()}
assert actual==set(names)|{f'product-registry-{kind}-graph.json' for kind in ('message-signature','dsse')},'unexpected fixture evidence set'
secret_material=[]
for path in root.rglob('*'):
    if path.is_file() and not path.is_symlink() and path.stat().st_size<=1<<20 and ('token' in path.name or path.name.endswith('config.json')):
        if path.name=='admin-token.private':
            token=path.read_bytes().strip()
            assert 16<=len(token)<=4096
            secret_material.append(token)
            continue
        try:
            value=json.loads(path.read_text())
            def collect(v):
                if isinstance(v,dict):
                    for k,item in v.items():
                        if isinstance(item,str) and any(term in k.lower() for term in ('token','secret','password')) and len(item)>=12: secret_material.append(item.encode())
                        else: collect(item)
                elif isinstance(v,list):
                    for item in v: collect(item)
            collect(value)
        except (ValueError,UnicodeError): pass
for name in names:
    path=root/'evidence'/name; info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=256<<10
    raw=path.read_bytes(); value=json.loads(raw)
    assert value.get('authorization')=='BLOCKED' and value.get('production') is False
    assert b'PRIVATE KEY' not in raw and not any(secret in raw for secret in secret_material)
    with (destination/name).open('xb') as f: f.write(raw)
PY
for kind in message-signature dsse; do
  for action in prepare exercise resume catalogue verify-first verify-final exercise-1 exercise-2 exercise-3 exercise-4 resume-1 resume-2 resume-3 resume-4; do
    /usr/bin/sudo --non-interactive /usr/bin/cat "$private/product-registry-$kind-$action.json" > "$evidence/product-registry-$kind-$action.json"
  done
done
/usr/bin/python3 -B - "$private/snapshots.private.json" "$source_commit" "$image_id" "$registry_id" "$registry_image" > "$evidence/product-registry-observations.json" <<'PY'
import json,pathlib,sys
path,commit,image,registry,pin=sys.argv[1:]; snapshots=json.loads(pathlib.Path(path).read_text()); assert len(snapshots)==44
print(json.dumps({'schema':'chengwang.product-registry-observations/v1','sourceCommit':commit,'localImageID':image,'registryContainerID':registry,'pinnedRegistryImage':pin,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False,'snapshots':snapshots},sort_keys=True))
PY
phase=graceful-registry-stop
/usr/bin/docker stop --signal SIGTERM --timeout 15 "$registry_id" >/dev/null
/usr/bin/docker inspect "$registry_id" > "$private/registry-exited.private.json"
/usr/bin/python3 -B - "$private/registry-exited.private.json" <<'PY'
import json,pathlib,sys
s=json.loads(pathlib.Path(sys.argv[1]).read_text())[0]['State']
assert s['Status']=='exited' and s['Running'] is False and type(s['ExitCode']) is int and s['ExitCode']==0 and s['Pid']==0 and not s['OOMKilled'] and not s.get('Error')
PY
phase=exact-owned-cleanup
test "${#owned_ids[@]}" -eq 3
cleanup_owned
cleaned=true
echo 'D11_PRODUCT_REGISTRY_CLEANUP=PASS exact_owned_containers=3 outer_image_preserved=true private_fixture_removed=true production=false'
/usr/bin/python3 -B - "$source_commit" "$image_id" > "$evidence/product-registry-cleanup.json" <<'PY'
import json,sys
print(json.dumps({'schema':'chengwang.product-registry-cleanup/v1','sourceCommit':sys.argv[1],'localImageID':sys.argv[2],'ownedContainersRemoved':3,'privateFixtureRemoved':True,'outerProductImagePreserved':True,'registryImagePreserved':True,'production':False,'authorization':'BLOCKED','deviceActionsExecuted':False,'outcome':'PASS'},sort_keys=True))
PY
phase=independent-final-check
/usr/bin/python3 -B "$checker" verify --evidence-dir "$evidence" --source-commit "$source_commit" --report "$evidence/product-registry-outcome.json"
accepted=true
echo 'D11_PRODUCT_REGISTRY_GATE=PASS actual_product_image=true normal_tls=true signatures=2 cross_restart=true request_observation=per_case external_push=false authorization=BLOCKED production=false'
