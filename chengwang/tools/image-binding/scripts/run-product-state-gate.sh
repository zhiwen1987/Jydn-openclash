#!/usr/bin/env bash
# D12: pre-seeded product state recovery/rejection matrix; not a crash claim.
# No image build, external push, production network or device action is allowed.
set -euo pipefail
umask 077
export PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1
test "$#" -eq 5 || { echo 'usage: run-product-state-gate.sh RUNROOT GOBIN MODCACHE IMAGEID PRIVATE_ARCHIVE' >&2; exit 2; }
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
image_id=$4
archive=$(/usr/bin/realpath -e -- "$5")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
source_root=$(/usr/bin/git -C "$script_root" rev-parse --show-toplevel)
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
checker="$source_root/chengwang/deploy/product-candidate/check_product_state.py"
registry_image=registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
evidence="$run_root/evidence"
private="$run_root/product-state-private"
fixture_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
fixture_root="/tmp/chengwang-product-lifecycle-$fixture_uuid"
label_key=org.chengwang.product-state-fixture
registry_id=''
registry_pid=''
product_id=''
lane=''
scenario=''
kind=''
case_kind=''
endpoint=''
phase=initialization
last_action_log=''
cleaned=false
accepted=false
removed_products=0
healthy_stops=0
rejected_exits=0
declare -a owned_ids=()
test "$(/usr/bin/id -u)" != 0
[[ "$source_commit" =~ ^[a-f0-9]{40}$ && "$image_id" =~ ^sha256:[a-f0-9]{64}$ && "$fixture_uuid" =~ ^[a-f0-9]{32}$ ]]
case "$run_root/" in "$source_root/"*) exit 2;; esac
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in ext4|xfs) ;; *) exit 1;; esac
test -x "$run_root/bin/product-state.test"
for required in product-image-packaged-contents.json product-image-staging.json product-registry-outcome.json product-lifecycle-outcome.json product-crash-outcome.json; do test -f "$evidence/$required"; done
test -f "$archive" && test ! -L "$archive"
test ! -e "$private" && test ! -e "$fixture_root"
/usr/bin/install -d -m 0700 "$private"
exec 3>&2
exec 2> "$private/shell.private.log"

# All product cases are sequential: exact UUID-labelled deletion after each
# case, with only the Registry and the current product ever alive together.
cleanup_owned() {
  local failed=0 item index
  for ((index=${#owned_ids[@]}-1; index>=0; index--)); do
    item=${owned_ids[$index]}
    if /usr/bin/docker inspect "$item" >/dev/null 2>&1; then
      if test "$(/usr/bin/docker inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$item")" != "$fixture_uuid"; then failed=1; continue; fi
      if test "$(/usr/bin/docker inspect --format '{{.State.Running}}' "$item")" = true; then
        failed=1; /usr/bin/docker rm --force "$item" >/dev/null 2>&1 || failed=1
      else /usr/bin/docker rm "$item" >/dev/null 2>&1 || failed=1; fi
      /usr/bin/docker inspect "$item" >/dev/null 2>&1 && failed=1
    fi
  done
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY' || failed=1
import os,pathlib,re,stat,sys
root=pathlib.Path(sys.argv[1]); identity=sys.argv[2]
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
  test "$private" = "$run_root/product-state-private" && test -d "$private" && test ! -L "$private" || failed=1
  /usr/bin/find "$private" -maxdepth 1 -type f -delete || failed=1
  test "$failed" -eq 0
}
on_exit() {
  local result=$?
  trap - EXIT HUP INT TERM
  if test "$result" -ne 0; then
    /usr/bin/python3 -B - "$phase" "$lane" "$scenario" "$kind" "$last_action_log" > "$evidence/product-state-failure-diagnostic.json" <<'PY'
import json,os,pathlib,re,stat,sys
phase,lane,scenario,kind,log=sys.argv[1:]
assert re.fullmatch(r'[a-z0-9-]{1,160}',phase)
assert lane in ('','update','verify-reserved','verify-consumed') and kind in ('','message-signature','dsse')
assert scenario in ('','after-journal-prepare','after-prepared-audit','before-result-audit','after-journal-outcome','after-result-audit','after-journal-ack','acked-audit-missing','prepared-audit-missing','wrong-prefix','prepared-key-conflict','result-key-conflict','wrong-scope','bad-checkpoint','later-invalid-acked')
line=0
if log:
    path=pathlib.Path(log)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno()); assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=256<<10
        raw=f.read(s.st_size)
    matches=re.findall(rb'^D12_PRODUCT_STATE_ASSERT_LINE=([1-9][0-9]{0,4})$',raw,re.M)
    if len(matches)==1 and int(matches[0])<=65535: line=int(matches[0])
print(json.dumps({'schema':'chengwang.product-state-failure/v1','outcome':'FAIL','phase':phase,'lane':lane,'scenario':scenario,'kind':kind,'driverSourceLine':line,'rawPrivateLogPublished':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
  fi
  if test "$cleaned" != true; then
    if cleanup_owned; then cleaned=true; else echo 'D12_PRODUCT_STATE_CLEANUP=FAIL production=false' >&3; exit 1; fi
  fi
  if test "$result" -eq 0 && test "$accepted" != true; then exit 1; fi
  exit "$result"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

phase=private-provision
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1]); root.mkdir(mode=0o700); os.chown(root,10001,10001)
for name in ('bin','tmp','evidence','state'):
    (root/name).mkdir(mode=0o700); os.chown(root/name,10001,10001)
with (root/'.fixture-owner').open('x',encoding='ascii') as f: f.write(sys.argv[2]+'\n')
os.chmod(root/'.fixture-owner',0o600); os.chown(root/'.fixture-owner',10001,10001)
PY
/usr/bin/sudo --non-interactive /usr/bin/install -m 0555 -o 0 -g 0 "$run_root/bin/product-state.test" "$fixture_root/bin/product-state.test"
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
names=tuple('chengwang/deploy/product-candidate/'+name for name in ('check_product_state.py','check_product_image.py','check_product_registry.py','check_product_lifecycle.py','check_product_crash.py','test_state_image_profile.py','test_check_product_state.py'))
files={}
for name in names:
    path=root/name
    assert path.is_file() and not path.is_symlink()
    raw=path.read_bytes()
    assert raw==subprocess.check_output(['/usr/bin/git','-C',str(root),'show',commit+':'+name]) and len(raw)<=256<<10
    files[name]=hashlib.sha256(raw).hexdigest()
print(json.dumps({'sourceCommit':commit,'files':files},sort_keys=True))
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_root" "$fixture_root" "$private/tool-input.json" > "$evidence/product-state-harness.json" <<'PY'
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
print(json.dumps({'schema':'chengwang.product-state-harness/v1',**data,'checkoutBytesMatched':True,'permissionReadOnly':True,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY

phase=registry-start
registry_id=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
  --name "cw-product-state-$fixture_uuid" --label "$label_key=$fixture_uuid" \
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
' "$source_commit" "$registry_id" > "$evidence/product-state-network.json"
wait_tls registry 5443
/usr/bin/python3 -B - "$private/registry-image-inspect.json" "$private/registry-container-inspect.json" "$registry_id" "$registry_image" "$fixture_root" "$source_commit" > "$evidence/product-state-isolation.json" <<'PY'
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
    return equivalent,{'schema':'chengwang.product-state-env-diagnostic/v1','baseShapeValid':base_shape,'baseKeysUnique':base_unique,'actualShapeValid':actual_shape,'actualKeysUnique':actual_unique,'expectedCount':len(expected) if expected is not None else 0,'actualCount':len(observed) if observed is not None else 0,'expectedMappingSHA256':digest(expected),'actualMappingSHA256':digest(observed),'equivalent':equivalent}

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
  local action=$1 log marker
  log="$private/$lane-$scenario-$kind-$action.private.log"
  last_action_log=$log
  phase="$action-$lane-$scenario-$kind"
  in_fixture CHENGWANG_STATE_ROOT="$fixture_root" CHENGWANG_STATE_ACTION="$action" \
    CHENGWANG_STATE_LANE="$lane" CHENGWANG_STATE_SCENARIO="$scenario" CHENGWANG_STATE_KIND="$kind" \
    CHENGWANG_STATE_IMAGE_ID="$image_id" CHENGWANG_STATE_COMMIT="$source_commit" \
    CHENGWANG_STATE_ARCHIVE="$fixture_root/bin/product-image.private.tar" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 60s "$fixture_root/bin/product-state.test" \
      -test.run='^TestProductStateD12Fixture$' -test.v -test.timeout=55s 2>&1 | /usr/bin/tee "$log" >/dev/null
  marker=${action^^}; marker=${marker//-/_}
  marker="D12_PRODUCT_STATE_${marker}=PASS lane=$lane scenario=$scenario kind=$kind authorization=BLOCKED production=false"
  test "$(/usr/bin/grep -Fxc -- "$marker" "$log")" -eq 1
  test "$(/usr/bin/grep -Ec '^--- PASS: TestProductStateD12Fixture \(' "$log")" -eq 1
  echo "$marker"
}

# Only completed Distribution requests are counted. Logs and upload paths stay
# private; the projection contains closed methods, digest identities and counts.
snapshot() {
  local window=$1 position=$2
  /usr/bin/docker logs "$registry_id" > "$private/registry-log.private" 2>&1
  /usr/bin/python3 -B - "$private/registry-log.private" "$private/snapshots.private.json" "$lane" "$scenario" "$kind" "$case_kind" "$window" "$position" <<'PY'
import collections,json,pathlib,re,sys
log,record,lane,scenario,kind,case_kind,window,position=sys.argv[1:]
assert window in ('prepare','seed','first','second') and position in ('before','after')
raw=pathlib.Path(log).read_bytes(); assert len(raw)<=32<<20
digests=collections.Counter(); other=collections.Counter()
for line in raw.decode('utf-8').splitlines():
    if not line.startswith('{'): continue
    row=json.loads(line)
    if row.get('msg')!='response completed': continue
    method,uri,status=row.get('http.request.method'),row.get('http.request.uri'),row.get('http.response.status')
    assert method in ('GET','HEAD','POST','PATCH','PUT','DELETE','OPTIONS') and type(status) is int and 100<=status<=599 and isinstance(uri,str)
    match=re.fullmatch(r'/v2/chengwang/product-candidate/(?:manifests|blobs)/(sha256:[a-f0-9]{64})',uri)
    if method in ('GET','HEAD') and match: digests[(method,match[1],status)]+=1
    else: other[(method,status)]+=1
path=pathlib.Path(record); rows=json.loads(path.read_bytes()) if path.exists() else []
rows.append({'ordinal':len(rows)+1,'lane':lane,'scenario':scenario,'kind':kind,'caseKind':case_kind,'window':window,'position':position,
    'digestRequests':[{'method':m,'digest':d,'status':s,'count':n} for (m,d,s),n in sorted(digests.items())],
    'otherRequests':[{'method':m,'status':s,'count':n} for (m,s),n in sorted(other.items())]})
with path.open('w',encoding='ascii') as f: json.dump(rows,f,sort_keys=True); f.write('\n')
path.chmod(0o600)
PY
}
after_snapshot() {
  snapshot "$1" after
  /usr/bin/sleep 0.15
  snapshot "$1" after
  /usr/bin/python3 -B - "$private/snapshots.private.json" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]); rows=json.loads(path.read_bytes()); a,b=rows[-2:]
assert a['digestRequests']==b['digestRequests'] and a['otherRequests']==b['otherRequests']
rows.pop()
with path.open('w',encoding='ascii') as f: json.dump(rows,f,sort_keys=True); f.write('\n')
PY
}
inspect_product() {
  local label=$1 status=$2
  local -a rejected=()
  if test "$case_kind" = rejected; then rejected=(--startup-rejected); fi
  /usr/bin/docker inspect "$product_id" > "$private/container-inspect.json"
  /usr/bin/python3 -B "$checker" inspect --image-inspect "$private/product-image-inspect.json" \
    --container-inspect "$private/container-inspect.json" --image-id "$image_id" --source-commit "$source_commit" \
    --expected-private-source "$endpoint" --expected-state-source "$endpoint/trust" \
    --expected-network-mode "container:$registry_id" --container-status "$status" "${rejected[@]}" \
    --report "$evidence/product-state-$lane-$scenario-$kind-$label-inspect.json"
}
record_pid1() {
  local attempt=$1 pid
  pid=$(/usr/bin/docker inspect --format '{{.State.Pid}}' "$product_id")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$pid" "$endpoint" "$run_root/bin/image-trust-api-static" "$source_commit" "$image_id" "$product_id" "$registry_pid" \
    > "$evidence/product-state-$lane-$scenario-$kind-$attempt-running-pid1.json" <<'PY'
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
  test "$(/usr/bin/docker inspect --format '{{.State.Pid}}' "$product_id")" = "$pid"
}

# This is deliberately a finite observation, not a claim to capture all
# transient LISTEN states. TLS identity errors and timeouts fail the fixture.
observe_rejected_start() {
  local attempt=$1 code
  phase="start-rejected-$lane-$scenario-$kind-$attempt"
  /usr/bin/docker start "$product_id" >/dev/null
  in_fixture /usr/bin/python3 -B -c '
import errno,json,socket,ssl,sys,time
root,port=sys.argv[1],int(sys.argv[2]); ctx=ssl.create_default_context(cafile=root+"/api-ca.pem")
start=time.monotonic_ns(); probes=[]
for ordinal in range(1,4):
    transport="CONNECTION_CLOSED"; status=0; tls_established=False
    try:
        with socket.create_connection(("127.0.0.1",port),timeout=.5) as raw:
            with ctx.wrap_socket(raw,server_hostname="api.fixture.invalid") as secure:
                tls_established=True
                secure.settimeout(.5)
                secure.sendall(b"GET /api/v1/image-trust HTTP/1.1\r\nHost: api.fixture.invalid\r\nConnection: close\r\n\r\n")
                response=secure.recv(1024)
                if response:
                    fields=response.split(b"\r\n",1)[0].split()
                    assert len(fields)>=2 and fields[0] in (b"HTTP/1.0",b"HTTP/1.1") and fields[1].isdigit()
                    status=int(fields[1]); assert 100<=status<=599
                    transport="TLS_HTTP"
    except ConnectionRefusedError: transport="CONNECTION_REFUSED"
    except ConnectionResetError: transport="CONNECTION_RESET"
    except ssl.SSLEOFError: transport="CONNECTION_CLOSED"
    except ssl.SSLError: raise SystemExit("D12_STATE_STARTUP_TLS_IDENTITY=FAIL")
    except TimeoutError: raise SystemExit("D12_STATE_STARTUP_PROBE_TIMEOUT=FAIL")
    except OSError as exc:
        if exc.errno==errno.ECONNREFUSED: transport="CONNECTION_REFUSED"
        elif exc.errno==errno.ECONNRESET: transport="CONNECTION_RESET"
        else: raise SystemExit("D12_STATE_STARTUP_TRANSPORT=FAIL")
    probes.append({"ordinal":ordinal,"monotonicNS":time.monotonic_ns(),"transport":transport,"httpStatus":status})
    assert not tls_established and transport!="TLS_HTTP" and status==0
    time.sleep(.02)
print(json.dumps({"observationStartMonotonicNS":start,"observationEndMonotonicNS":time.monotonic_ns(),"probes":probes},sort_keys=True))
' "$fixture_root" "$api_port" > "$private/startup-probes.private.json"
  # timeout is only a failure bound for Docker wait; its expiry is never an
  # accepted rejection and never signals/kills the product container.
  code=$(/usr/bin/timeout --signal=TERM --kill-after=5s 25s /usr/bin/docker wait "$product_id")
  test "$code" = 1
  /usr/bin/docker inspect "$product_id" > "$private/rejected-inspect.private.json"
  started_at=$(/usr/bin/python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["State"]["StartedAt"])' "$private/rejected-inspect.private.json")
  /usr/bin/docker logs --since "$started_at" "$product_id" > "$private/rejected-log.private" 2>&1
  in_fixture /usr/bin/python3 -B -c '
import pathlib,sys
port=int(sys.argv[1])
for name in ("tcp","tcp6"):
    for row in pathlib.Path("/proc/net",name).read_text().splitlines()[1:]:
        fields=row.split()
        assert not (int(fields[1].rsplit(":",1)[1],16)==port and fields[3]=="0A")
print("D12_STATE_NO_FINAL_LISTEN=PASS")
' "$api_port" > "$private/final-listen.private.log"
  /usr/bin/python3 -B - "$private" "$source_commit" "$image_id" "$lane" "$scenario" "$kind" "$product_id" "$attempt" \
    > "$evidence/product-state-$lane-$scenario-$kind-$attempt-startup.json" <<'PY'
import datetime,json,pathlib,re,sys
folder,commit,image,lane,scenario,kind,container,attempt=sys.argv[1:]; folder=pathlib.Path(folder)
row=json.loads((folder/'rejected-inspect.private.json').read_bytes())[0]; state=row['State']
assert row['Id']==container and row['Image']==image and state['Status']=='exited' and state['Running'] is False and type(state['ExitCode']) is int and state['ExitCode']==1 and state['Pid']==0 and state['OOMKilled'] is False and not state.get('Error')
for field in ('StartedAt','FinishedAt'):
    assert re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state[field])
assert datetime.datetime.fromisoformat(state['FinishedAt'].replace('Z','+00:00'))>=datetime.datetime.fromisoformat(state['StartedAt'].replace('Z','+00:00'))
raw=(folder/'rejected-log.private').read_bytes(); assert 0<len(raw)<=16384
lines=raw.decode('ascii').splitlines()
assert len(lines)==1 and re.fullmatch(r'[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} image trust candidate stopped without deployment authorization',lines[0])
assert (folder/'final-listen.private.log').read_bytes()==b'D12_STATE_NO_FINAL_LISTEN=PASS\n'
probes=json.loads((folder/'startup-probes.private.json').read_bytes())
print(json.dumps({'schema':'chengwang.product-state-startup/v1','sourceCommit':commit,'localImageID':image,'lane':lane,'scenario':scenario,'kind':kind,'caseKind':'rejected','attempt':attempt,'containerID':container,'startedAt':state['StartedAt'],'finishedAt':state['FinishedAt'],**probes,'finalNamespaceAPINotListening':True,'exitCode':1,'oomKilled':False,'pid':0,'naturalExit':True,'cliDiagnostic':{'code':'CANDIDATE_CONFIGURATION_REJECTED','count':1},'pid1SampleCaptured':False,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
  inspect_product "$attempt-rejected" exited
  rejected_exits=$((rejected_exits+1))
}

remove_container() {
  local identity=$1 role=$2
  /usr/bin/docker inspect "$identity" > "$private/removal-inspect.private.json"
  /usr/bin/python3 -B - "$private/removal-inspect.private.json" "$identity" "$label_key" "$fixture_uuid" <<'PY'
import json,pathlib,sys
path,identity,label,uuid=sys.argv[1:]; rows=json.loads(pathlib.Path(path).read_bytes())
assert len(rows)==1 and rows[0]['Id']==identity and rows[0]['Config']['Labels'][label]==uuid and rows[0]['State']['Running'] is False and rows[0]['State']['Pid']==0
PY
  /usr/bin/docker rm "$identity" >/dev/null
  if /usr/bin/docker inspect "$identity" >/dev/null 2>&1; then return 1; fi
  /usr/bin/python3 -B - "$private/removals.private.json" "$identity" "$role" "$lane" "$scenario" "$kind" <<'PY'
import json,pathlib,sys
path,identity,role,lane,scenario,kind=sys.argv[1:]; path=pathlib.Path(path)
assert role in ('product','registry')
rows=json.loads(path.read_bytes()) if path.exists() else []
assert identity not in {row['containerID'] for row in rows}
rows.append({'containerID':identity,'role':role,'lane':lane if role=='product' else '', 'scenario':scenario if role=='product' else '', 'kind':kind if role=='product' else ''})
with path.open('w',encoding='ascii') as f: json.dump(rows,f,sort_keys=True); f.write('\n')
PY
}

for lane in update verify-reserved verify-consumed; do
  for scenario in after-journal-prepare after-prepared-audit before-result-audit after-journal-outcome after-result-audit after-journal-ack acked-audit-missing prepared-audit-missing wrong-prefix prepared-key-conflict result-key-conflict wrong-scope bad-checkpoint later-invalid-acked; do
    case "$scenario" in after-journal-prepare|after-prepared-audit|before-result-audit|after-journal-outcome|after-result-audit|after-journal-ack) case_kind=healthy;; *) case_kind=rejected;; esac
    for kind in message-signature dsse; do
      last_action_log=''
      phase="provision-$lane-$scenario-$kind"
      /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$lane" "$scenario" <<'PY'
import os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); lane,scenario=sys.argv[2:]
for path in (root/'state'/lane,root/'state'/lane/scenario):
    if not path.exists(): path.mkdir(mode=0o700); os.chown(path,10001,10001)
    s=path.lstat(); assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==10001 and stat.S_IMODE(s.st_mode)==0o700
PY
      endpoint="$fixture_root/state/$lane/$scenario/$kind"
      if test "$kind" = message-signature; then api_port=17841; else api_port=17842; fi
      snapshot prepare before
      fixture_action prepare
      manifest_digest=$(/usr/bin/sudo --non-interactive /usr/bin/python3 -B -c 'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$endpoint/graph/manifest.json")
      in_fixture /usr/bin/python3 -B "$fixture_root/bin/checker/check_product_state.py" graph --graph-dir "$endpoint/graph" \
        --packaged-report "$fixture_root/bin/product-image-packaged-contents.json" --source-commit "$source_commit" \
        --manifest-digest "$manifest_digest" --report "$fixture_root/evidence/product-state-$lane-$scenario-$kind-graph.json"
      after_snapshot prepare
      snapshot seed before
      fixture_action seed
      after_snapshot seed
      phase="create-$lane-$scenario-$kind"
      existing=$(/usr/bin/docker ps -aq --no-trunc --filter "label=$label_key=$fixture_uuid")
      test "$existing" = "$registry_id"
      product_id=$(/usr/bin/docker create --pull never --platform linux/amd64 --name "cw-state-product-$fixture_uuid-$lane-$scenario-$kind" \
        --label "$label_key=$fixture_uuid" --network "container:$registry_id" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --memory 256m --memory-swap 256m --cpus 1 --pids-limit 128 --ulimit nofile=1024:1024 --restart no --stop-timeout 15 \
        --mount "type=bind,src=$endpoint,dst=$endpoint,readonly,bind-propagation=rprivate" \
        --mount "type=bind,src=$endpoint/trust,dst=$endpoint/trust,bind-propagation=rprivate" \
        --mount "type=bind,src=$endpoint/data,dst=$endpoint/data,bind-propagation=rprivate" \
        "$image_id" --config "$endpoint/trust-config.json" --product-config "$endpoint/product-config.json")
      [[ "$product_id" =~ ^[a-f0-9]{64}$ ]]; owned_ids+=("$product_id")
      test "$(/usr/bin/docker ps -aq --no-trunc --filter "label=$label_key=$fixture_uuid" | /usr/bin/wc -l)" -eq 2
      for attempt in first second; do
        snapshot "$attempt" before
        if test "$case_kind" = healthy; then
          phase="start-healthy-$lane-$scenario-$kind-$attempt"
          /usr/bin/docker start "$product_id" >/dev/null
          inspect_product "$attempt-running" running
          record_pid1 "$attempt"
          wait_tls api "$api_port"
          fixture_action "$attempt-read"
          phase="stop-healthy-$lane-$scenario-$kind-$attempt"
          /usr/bin/docker stop --signal SIGTERM --timeout 15 "$product_id" >/dev/null
          inspect_product "$attempt-exited" exited
          healthy_stops=$((healthy_stops+1))
        else
          observe_rejected_start "$attempt"
        fi
        fixture_action "reopen-$attempt"
        after_snapshot "$attempt"
      done
      phase="remove-product-$lane-$scenario-$kind"
      remove_container "$product_id" product
      removed_products=$((removed_products+1))
      product_id=''
    done
  done
done

phase=safe-evidence-export
# Source files are private UID10001; this root-only orchestrator validates the
# complete closed set and bounded bytes before any public handoff. The root
# copies remain0600; sudo cat feeds a non-root-owned evidence redirection.
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$private" <<'PY'
import json,os,pathlib,stat,sys
root,destination=map(pathlib.Path,sys.argv[1:]); names=set(); endpoints=[]
healthy=('after-journal-prepare','after-prepared-audit','before-result-audit','after-journal-outcome','after-result-audit','after-journal-ack')
faults=('acked-audit-missing','prepared-audit-missing','wrong-prefix','prepared-key-conflict','result-key-conflict','wrong-scope','bad-checkpoint','later-invalid-acked')
for lane in ('update','verify-reserved','verify-consumed'):
    for scenario in healthy+faults:
        for kind in ('message-signature','dsse'):
            endpoints.append(root/'state'/lane/scenario/kind)
            actions=('prepare','seed','reopen-first','reopen-second','graph')
            if scenario in healthy: actions+=('first-read','second-read')
            names.update(f'product-state-{lane}-{scenario}-{kind}-{action}.json' for action in actions)
assert len(names)==492 and {p.name for p in (root/'evidence').iterdir()}==names
def private_bytes(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as handle:
        before=os.fstat(handle.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==10001 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=limit
        raw=handle.read(limit+1); after=os.fstat(handle.fileno()); named=path.lstat()
        identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        assert len(raw)==before.st_size and identity(before)==identity(after)==identity(named)
    return raw
secrets=[]
def collect(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if isinstance(item,str) and any(word in key.lower() for word in ('token','secret','password')) and len(item)>=12: secrets.append(item.encode())
            else: collect(item)
    elif isinstance(value,list):
        for item in value: collect(item)
for endpoint in endpoints:
    token=private_bytes(endpoint/'admin-token.private',4096).strip(); assert 16<=len(token)<=4096; secrets.append(token)
    for config in ('trust-config.json','product-config.json'): collect(json.loads(private_bytes(endpoint/config,16<<10)))
for name in sorted(names):
    raw=private_bytes(root/'evidence'/name,512<<10); value=json.loads(raw)
    assert value['authorization']=='BLOCKED' and value['production'] is False and value['deviceActionsExecuted'] is False
    assert b'PRIVATE KEY' not in raw and not any(secret in raw for secret in secrets)
    fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as handle: handle.write(raw)
PY
/usr/bin/python3 -B - > "$private/export-names.private" <<'PY'
healthy=('after-journal-prepare','after-prepared-audit','before-result-audit','after-journal-outcome','after-result-audit','after-journal-ack')
faults=('acked-audit-missing','prepared-audit-missing','wrong-prefix','prepared-key-conflict','result-key-conflict','wrong-scope','bad-checkpoint','later-invalid-acked')
names=[]
for lane in ('update','verify-reserved','verify-consumed'):
    for scenario in healthy+faults:
        for kind in ('message-signature','dsse'):
            actions=('prepare','seed','reopen-first','reopen-second','graph')+ (('first-read','second-read') if scenario in healthy else ())
            names.extend(f'product-state-{lane}-{scenario}-{kind}-{action}.json' for action in actions)
assert len(names)==len(set(names))==492
print('\n'.join(sorted(names)))
PY
while IFS= read -r name; do
  /usr/bin/sudo --non-interactive /usr/bin/cat "$private/$name" > "$evidence/$name"
done < "$private/export-names.private"
phase=safe-observations-export
/usr/bin/python3 -B - "$private/snapshots.private.json" "$source_commit" "$image_id" "$registry_id" "$registry_image" \
  > "$evidence/product-state-observations.json" <<'PY'
import json,os,pathlib,stat,sys
path,commit,image,container,pin=sys.argv[1:]; path=pathlib.Path(path)
assert path.name=='snapshots.private.json' and path.parent.name=='product-state-private'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as handle:
    before=os.fstat(handle.fileno())
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and before.st_gid==os.getgid() and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4<<20
    raw=handle.read((4<<20)+1); after=os.fstat(handle.fileno()); named=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)==identity(named)
values=json.loads(raw); assert type(values) is list and len(values)==672
print(json.dumps({'schema':'chengwang.product-state-observations/v1','sourceCommit':commit,'localImageID':image,'registryContainerID':container,'pinnedRegistryImage':pin,'snapshots':values,'authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
phase=graceful-registry-stop
/usr/bin/docker stop --signal SIGTERM --timeout 15 "$registry_id" >/dev/null
/usr/bin/docker inspect "$registry_id" > "$private/registry-exited.private.json"
/usr/bin/python3 -B - "$private/registry-exited.private.json" <<'PY'
import json,pathlib,sys
state=json.loads(pathlib.Path(sys.argv[1]).read_bytes())[0]['State']
assert state['Status']=='exited' and state['Running'] is False and type(state['ExitCode']) is int and state['ExitCode']==0 and state['Pid']==0 and state['OOMKilled'] is False and not state.get('Error')
print('D12_STATE_REGISTRY_GRACEFUL_STOP=PASS exit_code=0 oom=false pid=0')
PY
phase=exact-owned-cleanup
test "$removed_products" -eq 84 && test "${#owned_ids[@]}" -eq 85
test "$healthy_stops" -eq 72 && test "$rejected_exits" -eq 96
remove_container "$registry_id" registry
test -z "$(/usr/bin/docker ps -aq --no-trunc --filter "label=$label_key=$fixture_uuid")"
removal_records=$(/usr/bin/cat "$private/removals.private.json")
cleanup_owned
cleaned=true
test -z "$(/usr/bin/docker ps -aq --no-trunc --filter "label=$label_key=$fixture_uuid")"
/usr/bin/python3 -B - "$source_commit" "$image_id" "$removal_records" \
  > "$evidence/product-state-runtime-cleanup.json" <<'PY'
import json,re,sys
commit,image,raw=sys.argv[1:]; records=json.loads(raw)
assert len(records)==85 and len({row['containerID'] for row in records})==85
assert all(re.fullmatch(r'[a-f0-9]{64}',row['containerID']) for row in records)
assert sum(row['role']=='product' for row in records)==84 and records[-1]['role']=='registry'
print(json.dumps({'schema':'chengwang.product-state-cleanup/v1','sourceCommit':commit,'localImageID':image,'ownedContainersRemoved':85,'removedContainers':records,'healthyNormalStops':72,'rejectedNaturalExits':96,'maximumConcurrentOwnedContainers':2,'noOwnedContainersRemain':True,'ownedHelpersJoined':0,'privateFixtureRemoved':True,'outerProductImagePreserved':True,'registryImagePreserved':True,'registryStop':{'exitCode':0,'oomKilled':False,'pid':0,'signal':'SIGTERM'},'outcome':'PASS','authorization':'BLOCKED','production':False,'deviceActionsExecuted':False},sort_keys=True))
PY
echo 'D12_PRODUCT_STATE_CLEANUP=PASS exact_owned_containers=85 healthy_stops=72 rejected_natural_exits=96 owned_helpers=0 private_fixture_removed=true production=false'
phase=independent-final-check
/usr/bin/python3 -B "$checker" verify --evidence-dir "$evidence" --source-commit "$source_commit" --report "$evidence/product-state-outcome.json"
accepted=true
echo 'D12_PRODUCT_STATE_GATE=PASS actual_product_image=true healthy_cases=36 rejected_cases=48 signatures=2 seeded_state_only=true authorization=BLOCKED production=false'
