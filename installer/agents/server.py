"""Remote root agent. Stdlib only; receipts exclude credentials and raw config."""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def check(condition, message):
    if not condition:raise RuntimeError(message)


def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        while chunk:=f.read(1048576):h.update(chunk)
    return h.hexdigest()


def atomic(path, value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.stack-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            os.fchmod(f.fileno(),0o600);json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def read(path):return json.loads(Path(path).read_text())


def stop_transient_timer(unit):
    state=subprocess.run(['systemctl','show',unit,'--property=LoadState','--value'],capture_output=True,timeout=5)
    if state.stdout.strip()==b'not-found':return True
    return subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=15).returncode==0


def command(args, timeout=60, data=None, cwd=None):
    try:p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,cwd=cwd)
    except subprocess.TimeoutExpired:raise RuntimeError('command_timeout:'+Path(args[0]).name) from None
    if p.returncode:
        if 'LOG' in globals():
            # Keep raw stderr on the target, never send it over a user receipt.
            with open(LOG,'ab') as f:os.chmod(LOG,0o600);f.write(p.stderr[-32768:])
        raise RuntimeError('command_failed:'+Path(args[0]).name+':'+str(p.returncode))
    return p.stdout


def docker_info(name):
    p=subprocess.run(['docker','inspect',name],capture_output=True,timeout=15)
    return json.loads(p.stdout)[0] if p.returncode==0 else None


def shape(container):
    if not container:return None
    return {'id':container['Id'],'image':container['Image'],'started':container['State']['StartedAt'],'running':container['State']['Running'],'restarts':container['RestartCount']}


def all_shapes():
    ids=command(['docker','ps','-aq']).decode().split()
    return {r['Name'].lstrip('/'):shape(r) for r in json.loads(command(['docker','inspect']+ids))} if ids else {}


def socket_free(host, port, udp=False):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:s.bind((host,port))
        return True
    except OSError:return False


def doctor(p):
    check(os.geteuid()==0,'root_required')
    check(sys.version_info>=(3,9),'server_python_39_required')
    engine=json.loads(command(['docker','info','--format','{{json .}}']))
    check(engine['OSType']=='linux' and engine['Architecture'] in ('x86_64','amd64'),'unsupported_docker_platform')
    command(['docker','compose','version'])
    name='clash-center-'+p['site'] if p['mode']=='fresh' else p['existing_container']
    current=docker_info(name)
    ports={str(p['ports'][k]):socket_free(p['server']['host'],p['ports'][k]) for k in ('kuma','capability','subscription')}
    if p['dns']['publish']:
        port=p['ports']['dns'];ports[str(port)]=socket_free(p['server']['host'],port) and socket_free(p['server']['host'],port,True)
    state_path=Path('/opt/clash-stack')/p['site']/'state.json'
    state=read(state_path) if state_path.exists() else {}
    return {'platform':'linux/amd64','docker':engine['ServerVersion'],'free_bytes':shutil.disk_usage('/opt').free,'container':shape(current),'managed_version':state.get('manifest',{}).get('version'),'managed_profile_sha256':state.get('profile_sha256'),'transaction_pending':(state_path.parent/'transaction.json').exists(),'recovery_review_required':(state_path.parent/'recovery-status.json').exists(),'ports_free':ports,'container_count':len(all_shapes()),'profile_sha256':hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest()}


def extract_payload(archive, target):
    with tarfile.open(archive,'r:gz') as t:
        members=t.getmembers()
        for item in members:
            rel=Path(item.name)
            check(not rel.is_absolute() and '..' not in rel.parts and (item.isfile() or item.isdir()),'unsafe_package_member')
        for item in members:
            path=target/item.name
            if item.isdir():path.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with t.extractfile(item) as src,open(path,'wb') as dst:shutil.copyfileobj(src,dst)
                path.chmod(0o600)


def backup_db(source, target):
    with contextlib.closing(sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True,timeout=10)) as a,contextlib.closing(sqlite3.connect(target)) as b:
        a.backup(b,pages=128,sleep=.02)
        check(b.execute('PRAGMA integrity_check').fetchone()[0]=='ok','sqlite_backup_invalid')
    target.chmod(0o600)


def snapshot_directory(source, target):
    source=Path(source);target=Path(target);target.mkdir(mode=0o700,parents=True,exist_ok=True)
    for path in source.rglob('*'):
        check(not path.is_symlink(),'symlink_in_data_backup')
        if not path.is_file() or path.name.endswith(('.db-wal','.db-shm','.sock','.lock')):continue
        dest=target/path.relative_to(source);dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if path.name.endswith('.db'):backup_db(path,dest)
        else:
            try:shutil.copyfile(path,dest)
            except FileNotFoundError:continue
            dest.chmod(0o600)
    return {str(f.relative_to(target)):sha(f) for f in target.rglob('*') if f.is_file()}


def prepare(p, base, package, manifest, inputs):
    check(not (base/'transaction.json').exists(),'unfinished_transaction_restore_first')
    check(isinstance(inputs,dict) and set(inputs)<=set(('subscriptions','kuma')),'installer_inputs_invalid')
    urls=inputs.get('subscriptions',[])
    check(isinstance(urls,list) and len(urls)<=16 and all(isinstance(u,str) and len(u)<=8192 for u in urls),'subscription_input_limit')
    package=Path(package)
    check(package.is_relative_to(Path('/opt/clash-stack/_packages')),'invalid_package_location')
    check(sha(package/'payload.tar.gz')==manifest['payload_sha256'],'payload_checksum_failed')
    release=base/'releases'/manifest['version'];release.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not (release/'payload').exists():extract_payload(package/'payload.tar.gz',release)
    for name,digest in manifest['payload_files'].items():check(sha(release/name)==digest,'payload_file_checksum_failed')
    for script in (release/'payload/center').glob('*.sh'):script.chmod(0o700)
    current=read(base/'state.json') if (base/'state.json').exists() else None
    if current:check(current.get('profile')==p,'managed_profile_migration_requires_review')
    name=current['container_name'] if current else ('clash-center-'+p['site'] if p['mode']=='fresh' else p['existing_container'])
    old=docker_info(name)
    if current:check(old and old['Id']==current['container_id'],'managed_container_identity_changed')
    if not current and p['mode']=='fresh':check(old is None,'container_name_in_use')
    stamp=str(time.time_ns());backup=base/'backups'/stamp;backup.mkdir(mode=0o700,parents=True)
    original_compose=Path(current['compose_path']) if current else (Path(p['existing_compose']) if p['mode']=='adopt' else None)
    if original_compose is None and (base/'compose.json').exists():
        # A prerelease rollback retained this site's Compose file. Reuse it
        # only when a prior, completed rollback proves exact ownership.
        candidate=base/'compose.json';known=False
        for record in (base/'backups').glob('*/restored-transaction.private.json'):
            try:prior=read(record)
            except (OSError,ValueError):continue
            if prior.get('profile')==p and prior.get('compose_path')==str(candidate) and prior.get('compose_after_sha256')==sha(candidate):known=True;break
        check(known,'unmanaged_compose_file_requires_review')
        original_compose=candidate
    original=read(original_compose) if original_compose else None
    if p['mode']=='adopt' and not current:
        check(old is not None,'adopt_container_missing')
        check(original_compose.is_file() and isinstance(original,dict),'adopt_requires_json_compose')
        check(not (original_compose.parent/'docker-compose.override.yml').exists(),'adopt_override_requires_review')
    if original_compose:
        shutil.copyfile(original_compose,backup/'compose.before.json');(backup/'compose.before.json').chmod(0o600)
    data_hashes={}
    if old:
        atomic(backup/'container.private.json',old)
        for index,mount in enumerate(old['Mounts']):
            if mount['Destination'] in ('/data','/app/data'):
                check(mount['Type']=='bind','named_volume_adoption_not_supported')
                data_hashes[mount['Destination']]=snapshot_directory(mount['Source'],backup/('volume-'+str(index)))
    elif p['mode']=='fresh':
        for folder,target in (('control','/data'),('kuma','/app/data')):
            source=base/'data'/folder
            if source.is_dir():data_hashes[target]=snapshot_directory(source,backup/('retained-'+folder))
    transaction={'schema':1,'id':stamp,'profile':p,'previous':current,'old_container':shape(old),'container_name':name,'compose_path':str(original_compose) if original_compose else str(base/'compose.json'),'compose_before_sha256':sha(original_compose) if original_compose else None,'release':str(release),'manifest':manifest,'backup':str(backup),'other_containers':all_shapes(),'data_backup_hashes':data_hashes,'phase':'prepared','started_at':time.time()}
    if old:
        env=dict(item.split('=',1) for item in old['Config'].get('Env',[]) if '=' in item)
        # Preserve runtime credentials, controller choices and volumes on adoption.
        material={'api_secret':env.get('OPENCLASH_SECRET',''),'proxy_auth':env.get('PROXY_AUTH',''),'probe_auth':env.get('CAPABILITY_PROXY_AUTH',''),'publish_token':env.get('SUBSCRIPTION_PUBLISH_TOKEN',''),'hmac_key':env.get('SUBSCRIPTION_HMAC_KEY','')}
        check(all(material.values()),'adopt_existing_secrets_incomplete')
        material['local_provider_token']=command(['docker','exec',name,'cat','/data/subscription-controller/local-source/provider-token']).decode().strip()
        atomic(backup/'existing-env.private.json',env)
    else:
        material_file=base/'data/control/installer-material.json';owner_file=base/'data/control/installer-profile.json'
        retained=material_file.exists()
        if retained:
            check(owner_file.exists() and read(owner_file)==p,'retained_data_profile_requires_review')
            material=read(material_file)
            check(all(isinstance(material.get(k),str) and len(material[k])>=24 for k in ('api_secret','publish_token','hmac_key','local_provider_token','proxy_auth','probe_auth')),'retained_material_invalid')
        else:
            check(not (base/'data/kuma/kuma.db').exists(),'unmanaged_existing_database_requires_review')
            material={k:secrets.token_urlsafe(36) for k in ('api_secret','publish_token','hmac_key','local_provider_token')}
            material.update(proxy_auth='stack:'+secrets.token_urlsafe(24),probe_auth='probe:'+secrets.token_urlsafe(24))
            atomic(material_file,material);atomic(owner_file,p)
        sources=[]
        for index,url in enumerate(inputs.get('subscriptions',[]),1):
            import urllib.parse
            u=urllib.parse.urlsplit(url);check(u.scheme in ('http','https') and u.hostname and not u.username,'subscription_url_invalid')
            sources.append({'id':'public'+str(index),'name':'公共订阅 '+str(index),'url':url,'provider_name':'Public_'+str(index)})
        if not retained:
            atomic(base/'data/control/subscription-sources.json',{'sources':sources})
            atomic(base/'data/control/route-quality-policy.json',{'enabled':True,'manual_override_seconds':0})
        elif sources:
            existing=read(base/'data/control/subscription-sources.json')
            check(existing=={'sources':sources},'retained_sources_change_requires_review')
        key=base/'data/control/subscription-controller/local-source/provider-token';key.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if retained:check(key.exists() and key.read_text().strip()==material['local_provider_token'],'retained_provider_token_changed_requires_review')
        else:key.write_text(material['local_provider_token']+'\n')
        key.chmod(0o600)
        if inputs.get('kuma') and not retained:
            atomic(base/'data/control/setup-kuma.private.json',inputs['kuma'])
    transaction['kuma_requested']=(base/'data/control/setup-kuma.private.json').exists() and not old
    atomic(base/'transaction.json',transaction)
    atomic(backup/'transaction.json',transaction)
    count=len(inputs.get('subscriptions',[]))
    if p['mode']=='fresh':
        count=sum(item.get('enabled',True) is not False for item in read(base/'data/control/subscription-sources.json')['sources'])
    return {'transaction':stamp,'backup':str(backup),'private':material,'release':str(release),'container_name':name,'source_count':count,'data_snapshot_verified':True}


def render_compose(p, base, transaction):
    release=Path(transaction['release']);old=transaction['old_container'];manifest=transaction['manifest']
    image=manifest['image_id']
    code_mounts=[str(release/'payload/center'/name)+':/'+name+':ro' for name in ('node-capability.py','healthcheck.sh','subscription-controller.py')]
    if old:
        config=read(Path(transaction['backup'])/'compose.before.json')
        services=config.get('services',{})
        matches=[(name,service) for name,service in services.items() if service.get('container_name')==transaction['container_name']]
        if not matches and len(services)==1:matches=list(services.items())
        check(len(matches)==1,'adopt_compose_service_ambiguous')
        _,service=matches[0];service['image']=image;service['pull_policy']='never'
        targets={'/'+name for name in ('node-capability.py','healthcheck.sh','subscription-controller.py')}
        mounts=service.get('volumes',[])
        check(all(isinstance(mount,str) for mount in mounts),'structured_mount_upgrade_requires_review')
        external_override=any(len(parts)>1 and parts[1] in targets and not parts[0].startswith(str(base/'releases')+'/') for parts in (mount.split(':') for mount in mounts))
        if p['mode']=='fresh' or not external_override:
            preserved=[]
            for mount in mounts:
                check(isinstance(mount,str),'structured_mount_upgrade_requires_review')
                parts=mount.split(':')
                if len(parts)>1 and parts[1] in targets:
                    check(parts[0].startswith(str(base/'releases')+'/'),'external_code_override_requires_review')
                else:preserved.append(mount)
            service['volumes']=preserved+code_mounts
            transaction['managed_code_overlays']=True
        # Legacy bind mounts preserve reviewed runtime code/data; don't replace
        # them with empty package defaults during an adoption.
        service.setdefault('labels',{})['io.jydn.clash-stack.site']=p['site']
        return config
    m=read(base/'data/control/installer-material.json');router=p['router'].get('api_host',p['router']['host']);ports=p['ports']
    env={'TZ':'Asia/Shanghai','KUMA_TZ':'Etc/UTC','HOME':'/data','PYTHONDONTWRITEBYTECODE':'1','DRY_RUN':'1','INTERVAL':'60','IKUAI_OBSERVER_ENABLED':'0','IKUAI_URL':'http://127.0.0.1','IKUAI_TOKEN':'','OPENCLASH_API':'http://'+router+':'+str(ports['api']),'OPENCLASH_SECRET':m['api_secret'],'PROXY':'http://'+router+':'+str(ports['proxy']),'PROXY_AUTH':m['proxy_auth'],'CAPABILITY_ENABLED':'1','CAPABILITY_MODE':'shadow','CAPABILITY_PROXY':'http://'+router+':'+str(ports['probe']),'CAPABILITY_PROXY_AUTH':m['probe_auth'],'CAPABILITY_GROUP':'🧪 节点能力检测','CAPABILITY_NODE_INTERVAL':'10','CAPABILITY_DISCOVERY_INTERVAL':'600','CAPABILITY_BUSINESS_RECHECK':'3600','CAPABILITY_HEALTHY_RECHECK':'1800','CAPABILITY_UNHEALTHY_RECHECK':'300','QUALITY_CONTROL_ENABLED':'1','SUBSCRIPTION_CONTROLLER_ENABLED':'1','SUBSCRIPTION_CONTROLLER_MODE':'automatic','SUBSCRIPTION_ISOLATED_ADMISSION':'1','SUBSCRIPTION_ADMISSION_BUDGET':'2','SUBSCRIPTION_FETCH_INTERVAL':'300','SUBSCRIPTION_PUBLISH_TOKEN':m['publish_token'],'SUBSCRIPTION_HMAC_KEY':m['hmac_key'],'SUBSCRIPTION_MIN_APPROVED':str(p.get('public_minimum',1)),'SUBSCRIPTION_SOURCES_FILE':'/data/subscription-sources.json','SUBSCRIPTION_ALLOWED_PROVIDER_CLIENTS':p['router'].get('provider_client',router)+',127.0.0.1','LOCAL_SOURCE_HOSTS':p['server']['host']+':'+str(ports['subscription'])+',127.0.0.1:8082','ADMISSION_NATIVE_SSH':'0','ADMISSION_CORE':'/local-subscription/core','UPTIME_KUMA_DB_TYPE':'sqlite'}
    bindings=[p['server']['host']+':'+str(ports[name])+':'+str(internal) for name,internal in [('kuma',3001),('capability',8081),('subscription',8082)]]
    if p['dns']['publish']:bindings += [p['server']['host']+':'+str(ports['dns'])+':53/'+protocol for protocol in ('tcp','udp')]
    core='''.:53 {
 bind 0.0.0.0
 errors
 health 127.0.0.1:18080
 ready 127.0.0.1:18181 {
  monitor continuously
 }
 loop
 reload 10s
 acl {
  allow net ALLOWED
  block
 }
 cache 300 {
  denial 9984 60 5
  servfail 0
 }
 forward . UPSTREAMS {
  policy sequential
  max_fails 2
  max_concurrent 1000
  failfast_all_unhealthy_upstreams
 }
}
'''.replace('ALLOWED',' '.join(p['dns']['allowed_cidrs']+['127.0.0.0/8','172.16.0.0/12'])).replace('UPSTREAMS',' '.join(p['dns']['upstreams']))
    (base/'Corefile').write_text(core);(base/'Corefile').chmod(0o600)
    (base/'data/kuma').mkdir(mode=0o700,parents=True,exist_ok=True)
    service={'container_name':transaction['container_name'],'image':image,'pull_policy':'never','restart':'unless-stopped','stop_grace_period':'45s','environment':env,'ports':bindings,'volumes':[str(base/'data/control')+':/data',str(base/'data/kuma')+':/app/data',str(base/'Corefile')+':/etc/coredns/Corefile:ro'],'extra_hosts':['failover:127.0.0.1','uptime-kuma:127.0.0.1'],'labels':{'io.jydn.clash-stack.site':p['site']},'logging':{'driver':'json-file','options':{'max-size':'5m','max-file':'3'}},'deploy':{'resources':{'limits':{'cpus':'1.5','memory':'768M'}}}}
    service['volumes']+=code_mounts
    return {'name':'clash-stack-'+p['site'],'services':{'center':service}}


def install(p, base, package):
    t=read(base/'transaction.json');check(t['phase']=='prepared','transaction_phase_invalid')
    check(shutil.disk_usage(base).free>=t['manifest'].get('required_free_bytes',6*1024**3),'insufficient_disk')
    existing=subprocess.run(['docker','image','inspect',t['manifest']['image_id']],capture_output=True,timeout=15)
    if existing.returncode:
        archive=Path(package)/'clash-center.tar.gz';check(sha(archive)==t['manifest']['image_archive_sha256'],'image_archive_checksum_failed')
        command(['docker','load','--input',str(archive)],timeout=900)
    image=json.loads(command(['docker','image','inspect',t['manifest']['image_id']]))[0]
    check(image['Architecture']=='amd64' and image['Os']=='linux','wrong_loaded_image')
    if t['old_container']:
        old_version=command(['docker','exec',t['container_name'],'node','-p',"require('/app/package.json').version"]).decode().strip()
        check(old_version==t['manifest']['kuma_version'],'kuma_database_migration_requires_separate_rehearsal')
    compose_path=Path(t['compose_path']);config=render_compose(p,base,t)
    check((sha(compose_path) if compose_path.is_file() else None)==t['compose_before_sha256'],'compose_changed_before_apply')
    if not t['old_container']:validate_corefile(base,t['manifest']['image_id'])
    # Recovery runs outside the managed container and survives client loss.
    request={'action':'restore','profile':p,'base':str(base),'transaction':t['id']}
    atomic(base/'guard-request.json',request)
    agent=base/'guard-agent.py';agent.write_text(globals().get('AGENT_SOURCE') or Path(__file__).read_text());agent.chmod(0o700)
    unit='clash-stack-rollback-'+p['site']+'-'+t['id']
    command(['systemd-run','--unit',unit,'--on-active=10m','/usr/bin/python3',str(agent),str(base/'guard-request.json')])
    t['guard_unit']=unit;t['phase']='applying';atomic(base/'transaction.json',t)
    intent=base/'compose.intent.json';atomic(intent,config)
    t['compose_after_sha256']=sha(intent);atomic(base/'transaction.json',t)
    os.replace(intent,compose_path)
    command(['docker','compose','-f',str(compose_path),'config','--quiet'])
    command(['docker','compose','-f',str(compose_path),'up','-d','--no-build','--pull','never'],timeout=180)
    now=docker_info(t['container_name']);t['new_container_id']=now['Id'];t['phase']='installed';atomic(base/'transaction.json',t)
    return {'installed':True,'container_id':now['Id'],'guard_armed':True,'transaction':t['id']}


def validate_corefile(base,image):
    code="""import subprocess,time,urllib.request,sys
p=subprocess.Popen(['/usr/local/bin/coredns','-conf','/etc/coredns/Corefile'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
try:
 for _ in range(25):
  if p.poll() is not None:
   sys.stderr.buffer.write(p.stderr.read());raise SystemExit(3)
  try:
   with urllib.request.urlopen('http://127.0.0.1:18080/health',timeout=.3) as r:
    if r.status==200:raise SystemExit(0)
  except OSError:pass
  time.sleep(.2)
 raise SystemExit(4)
finally:
 if p.poll() is None:
  p.terminate()
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait()
"""
    command(['docker','run','--rm','--network','none','--cpus','0.5','--memory','96m','--pids-limit','64','--cap-drop','ALL','--cap-add','NET_BIND_SERVICE','-v',str(base/'Corefile')+':/etc/coredns/Corefile:ro','--entrypoint','python3',image,'-c',code],timeout=30)


def verify(p, base, accept=False):
    t=read(base/'transaction.json') if (base/'transaction.json').exists() else read(base/'state.json')
    x=docker_info(t['container_name']);check(x and x['State']['Running'],'center_not_running')
    check(x['Image']==t['manifest']['image_id'],'center_image_changed')
    check(x['State'].get('Health',{}).get('Status')=='healthy','center_health_pending')
    checks={}
    if p['mode']=='fresh' or t.get('managed_code_overlays'):
        for name in ('node-capability.py','healthcheck.sh','subscription-controller.py'):
            source=Path(t['release'])/'payload/center'/name
            mount=next((m for m in x['Mounts'] if m['Destination']=='/'+name),None)
            check(mount and mount['Type']=='bind' and mount['Source']==str(source) and not mount['RW'],'runtime_code_mount_changed')
            check(sha(source)==t['manifest']['payload_files']['payload/center/'+name],'runtime_code_checksum_changed')
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for key in ('kuma','capability','subscription'):
        url='http://'+p['server']['host']+':'+str(p['ports'][key])+'/'
        with op.open(url,timeout=5) as response:
            body=response.read(2*1024*1024);check(response.status==200,'http_not_ready')
            if key=='subscription':check('本地自建订阅'.encode() in body,'local_subscription_editor_missing')
        checks[key]='ready'
    if t.get('kuma_requested'):
        code="import json;from pathlib import Path;p=Path('/data/setup-kuma.status.json');print(json.dumps({'ok':p.exists() and json.loads(p.read_text()).get('ok') is True}))"
        setup=json.loads(command(['docker','exec',t['container_name'],'python3','-c',code]))
        check(setup['ok'],'kuma_initialization_pending_or_failed');checks['kuma_setup']='ready'
    if p['dns']['publish']:
        import struct
        labels=p['dns'].get('test_name','www.baidu.com').rstrip('.').encode('ascii').split(b'.')
        check(all(0<len(label)<=63 for label in labels),'dns_test_name_invalid')
        question=b''.join(bytes([len(label)])+label for label in labels)+b'\x00'+struct.pack('!2H',1,1)
        query=b'\x19\x26'+struct.pack('!5H',0x100,1,0,0,0)+question
        for tcp in (False,True):
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
                s.settimeout(5);s.connect((p['server']['host'],p['ports']['dns']))
                if tcp:
                    s.sendall(struct.pack('!H',len(query))+query);prefix=s.recv(2);check(len(prefix)==2,'dns_tcp_incomplete');n=struct.unpack('!H',prefix)[0];raw=b''
                    while len(raw)<n:
                        chunk=s.recv(n-len(raw));check(bool(chunk),'dns_tcp_eof');raw+=chunk
                else:s.send(query);raw=s.recv(4096)
            check(len(raw)>=12,'dns_response_incomplete')
            header=struct.unpack('!6H',raw[:12]);check(header[0]==0x1926 and header[1]&0x8000 and not header[1]&0x0200 and header[1]&15==0 and header[2]==1 and header[3]>0 and raw[12:12+len(question)].lower()==question.lower(),'dns_query_failed')
            checks['dns_tcp' if tcp else 'dns_udp']='ready'
    comparison=t['phase']=='installed'
    if comparison:
        current=all_shapes()
        changes=[{'name':name,'before':old,'now':current.get(name)} for name,old in t.get('other_containers',{}).items() if name!=t['container_name'] and current.get(name)!=old]
        if changes:
            atomic(base/'unrelated-changes.json',{'at':time.time(),'changes':changes})
            raise RuntimeError('unrelated_container_changed:'+changes[0]['name'][:64])
    if accept:
        check(t['phase']=='installed','cannot_accept_phase')
        t['phase']='accepted';t['accepted_at']=time.time();t['container_id']=x['Id']
        t['profile_sha256']=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest()
        atomic(Path(t['backup'])/'transaction.json',t)
        atomic(base/'state.json',t);atomic(Path(t['backup'])/'accepted.json',{'at':time.time()})
        (base/'transaction.json').unlink()
        (base/'recovery-status.json').unlink(missing_ok=True)
        command(['systemctl','stop',t['guard_unit']+'.timer'])
        if p['mode']=='fresh':install_watchdog(p,base)
    return {'checks':checks,'container_id':x['Id'],'unrelated_containers_unchanged':True if comparison else None,'unrelated_comparison':'deployment_window' if comparison else 'not_compared_outside_deployment','accepted':t['phase']=='accepted','business_account_acceptance':'pending_real_node_and_account'}


def restore(p, base, manual=False, transaction=None):
    if not (base/'transaction.json').exists():
        if not manual or not (base/'state.json').exists():return {'restored':False,'reason':'no_pending_transaction'}
        state=read(base/'state.json')
        if transaction and state['id']!=transaction:
            history=base/'backups'/transaction if re.fullmatch(r'[0-9]{15,24}',transaction) else None
            if history and (history/'restore-result.json').exists() and (history/'restored-transaction.private.json').exists():
                recovered=read(history/'restored-transaction.private.json')
                if recovered['id']==transaction and (recovered.get('previous') or {}).get('id')==state['id']:
                    return {'restored':False,'already_recovered':True,'data_retained':True,'previous_managed_version':state.get('manifest',{}).get('version')}
            raise RuntimeError('restore_transaction_not_current')
        saved=read(Path(state['backup'])/'transaction.json')
        check(state['manifest']['image_id']==saved['manifest']['image_id'] and state.get('compose_after_sha256')==saved.get('compose_after_sha256'),'restore_is_not_latest_backup')
        actual=docker_info(state['container_name']);check(actual and actual['Id']==state['container_id'],'managed_container_identity_changed')
        saved['new_container_id']=actual['Id']
        atomic(base/'transaction.json',saved)
    t=read(base/'transaction.json');backup=Path(t['backup']);path=Path(t['compose_path']);current=docker_info(t['container_name'])
    if transaction and t['id']!=transaction:return {'restored':False,'reason':'stale_guard'}
    if t.get('compose_after_sha256'):
        current_hash=sha(path) if path.is_file() else None
        check(current_hash in (t['compose_after_sha256'],t['compose_before_sha256']),'concurrent_compose_edit_restore_refused')
    if current and t.get('new_container_id'):check(current['Id']==t['new_container_id'],'container_identity_changed_restore_refused')
    if not manual and not t['old_container'] and current:
        # A separate router may still be serving a protected private selection.
        # Do not tear down its only new center without authenticated orchestration.
        atomic(base/'recovery-status.json',{'at':time.time(),'transaction':t['id'],'reason':'new_center_retained_until_coordinated_restore','requires_review':True})
        return {'restored':False,'data_retained':True,'reason':'new_center_retained_until_coordinated_restore'}
    if t['old_container']:
        check(sha(backup/'compose.before.json')==t['compose_before_sha256'],'compose_backup_corrupt')
        shutil.copyfile(backup/'compose.before.json',path);path.chmod(0o600)
        command(['docker','compose','-f',str(path),'up','-d','--no-build','--pull','never'],timeout=180)
    else:
        if current:
            check(current['Config'].get('Labels',{}).get('io.jydn.clash-stack.site')==p['site'],'not_owned_container')
            command(['docker','rm','-f',current['Id']],timeout=60)
        if t['compose_before_sha256']:
            check(sha(backup/'compose.before.json')==t['compose_before_sha256'],'compose_backup_corrupt')
            shutil.copyfile(backup/'compose.before.json',path);path.chmod(0o600)
        elif t.get('compose_after_sha256') and path.exists():path.unlink()
    if t.get('previous'):
        previous=t['previous'];previous['container_id']=docker_info(t['container_name'])['Id'];atomic(base/'state.json',previous)
    elif (base/'state.json').exists():(base/'state.json').unlink()
    cleanup_warnings=[]
    if p['mode']=='fresh' and not t.get('previous'):
        unit='clash-stack-watchdog-'+p['site']
        if Path('/etc/systemd/system',unit+'.timer').exists():
            try:
                stopped=subprocess.run(['systemctl','disable','--now',unit+'.timer'],capture_output=True,timeout=15)
                if stopped.returncode:cleanup_warnings.append('watchdog_timer_cleanup_failed')
            except subprocess.TimeoutExpired:cleanup_warnings.append('watchdog_timer_cleanup_timeout')
    atomic(backup/'restore-result.json',{'at':time.time(),'data_retained':True,'cleanup_warnings':cleanup_warnings})
    atomic(backup/'restored-transaction.private.json',t)
    (base/'transaction.json').unlink()
    (base/'recovery-status.json').unlink(missing_ok=True)
    if t.get('guard_unit'):
        try:
            if not stop_transient_timer(t['guard_unit']+'.timer'):cleanup_warnings.append('rollback_timer_cleanup_failed')
        except subprocess.TimeoutExpired:cleanup_warnings.append('rollback_timer_cleanup_timeout')
    atomic(backup/'restore-result.json',{'at':time.time(),'data_retained':True,'cleanup_warnings':cleanup_warnings})
    return {'restored':True,'data_retained':True,'backup':str(backup),'cleanup_warnings':cleanup_warnings,'previous_managed_version':t.get('previous',{}).get('manifest',{}).get('version') if t.get('previous') else None}


def backup(p,base):
    check(not (base/'transaction.json').exists(),'unfinished_transaction_restore_first')
    state=read(base/'state.json');container=docker_info(state['container_name'])
    check(container and container['Id']==state['container_id'],'managed_container_identity_changed')
    dest=base/'backups'/('manual-'+str(time.time_ns()));dest.mkdir(mode=0o700,parents=True)
    atomic(dest/'state.private.json',state)
    compose=Path(state['compose_path']);shutil.copyfile(compose,dest/'compose.json');(dest/'compose.json').chmod(0o600)
    hashes={}
    for i,m in enumerate(container['Mounts']):
        if m['Destination'] in ('/data','/app/data'):
            check(m['Type']=='bind','named_volume_backup_not_supported')
            hashes[m['Destination']]=snapshot_directory(m['Source'],dest/('volume-'+str(i)))
    atomic(dest/'checksums.json',hashes)
    return {'backup':str(dest),'sqlite_integrity':'ok','data_changed':False}


def install_watchdog(p,base):
    agent=base/'guard-agent.py'
    request=base/'watchdog-request.json';atomic(request,{'action':'watchdog','profile':p,'base':str(base)})
    unit='clash-stack-watchdog-'+p['site']
    service='[Unit]\nDescription=Clash Stack bounded health recovery\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(agent)+' '+str(request)+'\n'
    timer='[Unit]\nDescription=Clash Stack health timer\n[Timer]\nOnBootSec=120\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n'
    for suffix,body in (('service',service),('timer',timer)):
        path=Path('/etc/systemd/system')/(unit+'.'+suffix)
        path.write_text(body);path.chmod(0o644)
    command(['systemctl','daemon-reload']);command(['systemctl','enable','--now',unit+'.timer'])


def watchdog(p,base):
    if (base/'transaction.json').exists() or not (base/'state.json').exists() or (base/'automation-freeze').exists():return {'action':'none','reason':'frozen_or_installing'}
    state=read(base/'state.json');x=docker_info(state['container_name'])
    check(x and x['Id']==state['container_id'] and x['Image']==state['manifest']['image_id'],'watchdog_identity_changed')
    # Respect a deliberate stop; recover only the managed running container.
    if not x['State']['Running']:return {'action':'none','reason':'stopped'}
    if x['State'].get('Health',{}).get('Status')=='unhealthy' and local_services_alive(p,state['container_name']):
        return {'action':'none','reason':'local_services_alive_dependency_or_readiness_failure'}
    path=base/'watchdog-state.json';s=read(path) if path.exists() else {'bad':0,'events':[]}
    now=time.time();events=[t for t in s['events'] if 0<=now-t<3600]
    s['bad']=s['bad']+1 if x['State'].get('Health',{}).get('Status')=='unhealthy' else 0
    s['events']=events
    if s['bad']>=3 and len(events)<2 and (not events or now-events[-1]>=900):
        s['events'].append(now);s['bad']=0;atomic(path,s)
        command(['docker','restart','--time','30',state['container_name']],timeout=75)
        return {'action':'restarted','bounded':True}
    atomic(path,s);return {'action':'none','bad_streak':s['bad']}


def local_services_alive(p,name):
    """An upstream DNS/router outage does not justify restarting local services."""
    try:
        op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for key in ('kuma','capability','subscription'):
            with op.open('http://'+p['server']['host']+':'+str(p['ports'][key])+'/',timeout=2) as response:
                if response.status!=200:return False
        command(['docker','exec',name,'curl','-fsS','--max-time','2','http://127.0.0.1:18080/health'],timeout=5)
        return True
    except Exception:return False


def main(args):
    p=args['profile'];check(re.fullmatch(r'[a-z][a-z0-9-]{0,31}',p['site']),'invalid_site')
    base=Path('/opt/clash-stack')/p['site'];check(str(base)==args.get('base',str(base)),'base_mismatch')
    if args['action']=='doctor':return doctor(p)
    base.mkdir(mode=0o700,parents=True,exist_ok=True)
    global LOG;LOG=str(base/'operations.private.log')
    with open(base/'operations.lock','a') as lock:
        os.chmod(base/'operations.lock',0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        action=args['action']
        if action=='prepare':return prepare(p,base,args['package'],args['manifest'],args.get('inputs',{}))
        if action=='install':return install(p,base,args['package'])
        if action=='verify':return verify(p,base,args.get('accept',False))
        if action=='restore':return restore(p,base,args.get('manual',False),args.get('transaction'))
        if action=='backup':return backup(p,base)
        if action=='watchdog':return watchdog(p,base)
        raise RuntimeError('unsupported_action')


if __name__=='__main__':
    try:
        if 'ARGS' not in globals():ARGS=read(sys.argv[1])
        print(json.dumps({'ok':True,'result':main(ARGS)},ensure_ascii=False))
    except Exception as error:
        # Only controlled codes, not arbitrary exception messages / secret URLs.
        message=str(error) if isinstance(error,RuntimeError) and re.fullmatch(r'[A-Za-z0-9_:.+-]{1,140}',str(error)) else type(error).__name__
        print(json.dumps({'ok':False,'error':message}));raise SystemExit(1)
