"""Scoped deployment/recovery for the existing unified container.

Run on 249 as root with a freshly verified backup directory. Never recreate the
container: DNS and Kuma process IDs must remain unchanged. Secrets stay local.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

COMPOSE = Path('/root/dpanel/compose/lan-center/docker-compose.yml')
DATA = COMPOSE.parent / 'data/failover'
FILES = ['node_links.py', 'local_source.py', 'local_web.py', 'editor.html', 'editor.js', 'core']
CHILDREN = ['subscription-controller', 'node-capability']


def run(args, timeout=30, payload=None):
    p = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode:
        raise RuntimeError('extension_command_failed:' + args[0])
    return p.stdout


def save(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2));path.chmod(0o600)


def inspect():
    return json.loads(run(['docker','inspect','clash-center']))[0]


def proc_snapshot():
    code = '''import json,time
from pathlib import Path
state=json.loads(Path('/data/unified/status.json').read_text())
assert 0<=time.time()-state['epoch']<35
out={}
for name,exe in [('kuma','node'),('dns','coredns')]:
 p=state['services'][name]['pid'];assert state['services'][name]['running']
 actual=Path('/proc/'+str(p)+'/exe').resolve().name;assert actual==exe
 stat=Path('/proc/'+str(p)+'/stat').read_text().rsplit(')',1)[1].split()
 out[name]={'pid':p,'exe':actual,'start_ticks':stat[19]}
print(json.dumps(out))'''
    value=json.loads(run(['docker','exec','clash-center','python3','-c',code]))
    if set(value)!={'kuma','dns'}:raise RuntimeError('protected_services_not_identified')
    return value


def restart_children():
    code='''import os,signal,json
from pathlib import Path
for name in ['subscription-controller','node-capability']:
 p=int(Path('/data/'+name+'.pid').read_text())
 cmd=Path('/proc/'+str(p)+'/cmdline').read_bytes().split(b'\\0')
 if cmd[:2]!=[b'/usr/bin/python3',('/'+name+'.py').encode()]:raise RuntimeError('child_identity_changed')
 os.kill(p,signal.SIGTERM)
print('only_subscription_and_capability_signalled')'''
    run(['docker','exec','clash-center','python3','-c',code])


def code_write(filename, raw):
    target='/'+filename
    mount=next((m for m in inspect()['Mounts'] if m['Destination']==target),None)
    if mount:
        # Preserve the inode of a bind-mounted file. Existing processes have
        # already compiled the source; child restart happens after this fsync.
        with open(mount['Source'],'wb') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
    else:
        code='import sys,os; p="'+target+'"; f=open(p,"wb"); f.write(sys.stdin.buffer.read());f.flush();os.fsync(f.fileno());f.close();os.chmod(p,0o644)'
        run(['docker','exec','-i','clash-center','python3','-c',code],payload=raw)


def backup_check(b):
    if b.parent!=Path('/var/backups') or not b.name.startswith('local-source-20261026-'):
        raise ValueError('unexpected_backup_directory')
    m=json.loads((b/'manifest.json').read_text())
    for name, digest in m['files'].items():
        if hashlib.sha256((b/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('backup_checksum_failed')
    return m


def protected_check(m):
    current=inspect()
    if any(current[k]!=m['container'][k] for k in ['Id','Image']):raise RuntimeError('container_identity_changed')
    if current['State']['StartedAt']!=m['container']['StartedAt']:raise RuntimeError('container_restarted')
    if current['RestartCount']!=m['container']['RestartCount']:raise RuntimeError('container_restart_count_changed')
    if proc_snapshot()!=m['protected_processes']:raise RuntimeError('dns_or_kuma_restarted')


def prepare(b, stage):
    backup_check(b)
    if (b/'extension.json').exists():raise RuntimeError('extension_already_prepared')
    x=inspect();old_code={}
    for name in CHILDREN:
        raw=run(['docker','exec','clash-center','cat','/'+name+'.py'])
        captured=(stage.parent/(name+'.py')).read_bytes()
        if raw!=captured:raise RuntimeError('runtime_changed_during_rehearsal')
        path=b/(name+'.py');path.write_bytes(raw);path.chmod(0o600)
        old_code[name+'.py']=hashlib.sha256(raw).hexdigest()
    # Existing canonical sources, caches and pointers are backed up separately
    # from consistent online SQLite snapshots created during initial backup.
    tree=b/'subscription-private-state';tree.mkdir(mode=0o700,exist_ok=True)
    state_hashes={}
    sources=list((DATA/'subscription-controller').rglob('*'))
    if (DATA/'subscription-sources.json').is_file():sources.append(DATA/'subscription-sources.json')
    for source in sources:
        if not source.is_file() or any(source.name.endswith(s) for s in ('.db','.db-wal','.db-shm')):
            continue
        try:raw=source.read_bytes()
        except FileNotFoundError:continue  # unreferenced cache/prune race
        rel=source.relative_to(DATA);dest=tree/rel
        dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(0o600)
        state_hashes[str(rel)]=hashlib.sha256(raw).hexdigest()
    if not all(hashlib.sha256((tree/name).read_bytes()).hexdigest()==value for name,value in state_hashes.items()):
        raise RuntimeError('private_state_backup_integrity_failed')
    release=Path('/opt/lan-center-local-subscription/releases')/str(time.time_ns());release.mkdir(mode=0o700,parents=True)
    for name in FILES+[n+'.py' for n in CHILDREN]:
        shutil.copyfile(stage/name,release/name);(release/name).chmod(0o700 if name=='core' else 0o600)
    shutil.copyfile(Path(__file__),b/'server_extension.py');(b/'server_extension.py').chmod(0o600)
    m={'release':str(release),'old_code':old_code,'private_state_backup_sha256':state_hashes,'new_code':{n+'.py':hashlib.sha256((release/(n+'.py')).read_bytes()).hexdigest() for n in CHILDREN},'container':{'Id':x['Id'],'Image':x['Image'],'StartedAt':x['State']['StartedAt'],'RestartCount':x['RestartCount']},'protected_processes':proc_snapshot(),'compose_before':hashlib.sha256(COMPOSE.read_bytes()).hexdigest()}
    save(b/'extension.json',m)
    # Stage new modules without changing either running child yet.
    run(['docker','exec','clash-center','mkdir','-p','/local-subscription'])
    for name in FILES:run(['docker','cp',str(release/name),'clash-center:/local-subscription/'+name],timeout=90)
    code='import sys;sys.path.insert(0,"/local-subscription");from local_source import Manager;Manager("/data/subscription-controller/local-source",lambda *a:None,lambda *a:None);print("private_source_initialized")'
    run(['docker','exec','clash-center','python3','-B','-c',code])
    protected_check(m)
    return {'prepared':True,'protected_processes_unchanged':True,'backup':str(b),'release':str(release),'children_not_restarted':True}


def install(b):
    m=json.loads((b/'extension.json').read_text());protected_check(m)
    if hashlib.sha256(COMPOSE.read_bytes()).hexdigest()!=m['compose_before']:raise RuntimeError('concurrent_compose_edit')
    unit='lan-center-local-rollback-'+str(int(time.time()))
    run(['systemd-run','--unit',unit,'--on-active=10m','/usr/bin/python3',str(b/'server_extension.py'),'rollback','--backup',str(b)])
    m['guard_unit']=unit;save(b/'extension.json',m)
    compose=json.loads(COMPOSE.read_text());volumes=compose['services']['center']['volumes']
    targets={'/local-subscription','/subscription-controller.py','/node-capability.py'}
    volumes[:]=[v for v in volumes if (v.get('target') if isinstance(v,dict) else v.split(':')[1]) not in targets]
    release=Path(m['release'])
    volumes.extend([str(release)+':/local-subscription:ro']+[str(release/(n+'.py'))+':/'+n+'.py:ro' for n in CHILDREN])
    COMPOSE.write_text(json.dumps(compose,ensure_ascii=False,indent=2)+'\n')
    run(['docker','compose','-f',str(COMPOSE),'config','--quiet'])
    m['compose_after']=hashlib.sha256(COMPOSE.read_bytes()).hexdigest();save(b/'extension.json',m)
    for name in CHILDREN:code_write(name+'.py',(release/(name+'.py')).read_bytes())
    restart_children();protected_check(m)
    save(b/'INSTALLED.json',{'at':time.time()})
    return {'installed':True,'container_not_recreated':True,'dns_and_kuma_not_restarted':True,'rollback_guard':unit,'mounts_persist_on_recreate':True}


def rollback(b):
    backup_check(b);m=json.loads((b/'extension.json').read_text());protected_check(m)
    if hashlib.sha256(COMPOSE.read_bytes()).hexdigest() not in {m['compose_before'],m.get('compose_after')}:
        raise RuntimeError('concurrent_compose_edit_recovery_refused')
    for name in CHILDREN:
        raw=(b/(name+'.py')).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=m['old_code'][name+'.py']:raise RuntimeError('code_backup_invalid')
    COMPOSE.write_bytes((b/'docker-compose.yml').read_bytes())
    for name in CHILDREN:code_write(name+'.py',(b/(name+'.py')).read_bytes())
    restart_children();protected_check(m)
    save(b/'ROLLED_BACK.json',{'at':time.time(),'canonical_private_source_retained':True})
    return {'rolled_back':True,'dns_and_kuma_not_restarted':True,'private_user_data_retained':True}


def accept(b):
    backup_check(b);m=json.loads((b/'extension.json').read_text());protected_check(m)
    for name in CHILDREN:
        raw=run(['docker','exec','clash-center','cat','/'+name+'.py'])
        if hashlib.sha256(raw).hexdigest()!=m['new_code'][name+'.py']:raise RuntimeError('deployed_code_differs')
    if hashlib.sha256(COMPOSE.read_bytes()).hexdigest()!=m['compose_after']:raise RuntimeError('compose_changed')
    run(['systemctl','stop',m['guard_unit']+'.timer'])
    save(b/'ACCEPTED.json',{'at':time.time()})
    return {'accepted':True,'dns_and_kuma_processes_unchanged':True,'rollback_guard_disarmed':True}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','install','rollback','accept']);p.add_argument('--backup',type=Path,required=True);p.add_argument('--stage',type=Path);a=p.parse_args()
    print(json.dumps(prepare(a.backup,a.stage) if a.action=='prepare' else globals()[a.action](a.backup),ensure_ascii=False))
