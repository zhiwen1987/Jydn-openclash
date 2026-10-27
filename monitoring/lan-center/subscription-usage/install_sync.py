"""Receipt-owned systemd importer installation. Never calls the node publisher.

The metadata code overlay and router exporter have separate scoped receipts.
Rollback first stops this timer; the previous collector ignores retained data.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HOME=Path('/opt/clash-stack/production/subscription-info-sync')
DATA=Path('/root/dpanel/compose/lan-center/data/failover/subscription-usage')
SERVICE='clash-subscription-info-sync.service'
TIMER='clash-subscription-info-sync.timer'
ALLOWED={HOME/'source_sync.py',HOME/'config.json',HOME/'known_hosts',
         Path('/etc/systemd/system')/SERVICE,Path('/etc/systemd/system')/TIMER}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def atomic(p,raw):
    tmp=p.with_name(p.name+'.sync-stage')
    with tmp.open('wb') as f:
        os.chmod(tmp,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(tmp,p)
def save(p,value):atomic(p,json.dumps(value,ensure_ascii=False).encode())
def system(*args):subprocess.run(['systemctl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
def check(b):
    j=json.loads((b/'sync-journal.json').read_text())
    for name,i in j['files'].items():
        p=Path(name);assert p in ALLOWED
        assert sha(p) in (i['before'],i['after']),'later_edit_requires_review'
        assert i['before'] is None or sha(Path(i['backup']))==i['before'],'backup_corrupt'
    return j
def rollback(b):
    j=check(b)
    # The units were absent at prepare. Stop only these dedicated units.
    subprocess.run(['systemctl','disable','--now',TIMER],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
    subprocess.run(['systemctl','stop',SERVICE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
    for name,i in j['files'].items():
        p=Path(name)
        if i['before'] is None:p.unlink(missing_ok=True)
        else:atomic(p,Path(i['backup']).read_bytes());p.chmod(i['mode'])
    system('daemon-reload')
    save(b/'SYNC_ROLLED_BACK.json',{'at':time.time(),'information_data_retained':True})
    return {'restored':True,'information_data_retained':True,'container_restarted':False}
def main():
    action,value=sys.argv[1:3];b=Path(value).resolve()
    assert b.parent==Path('/var/backups') and b.name.startswith('clash-usage-auto-') and b.is_dir()
    if action=='prepare':
        assert not (b/'sync-journal.json').exists()
        assert all(not (Path('/etc/systemd/system')/x).exists() for x in (SERVICE,TIMER))
        payload=json.load(sys.stdin);assert set(map(Path,payload))==ALLOWED
        files={}
        for name,encoded in payload.items():
            p=Path(name);raw=base64.b64decode(encoded,validate=True);before=sha(p);n=str(len(files));backup=b/('sync-before-'+n);stage=b/('sync-after-'+n)
            if before:atomic(backup,p.read_bytes())
            atomic(stage,raw);files[name]={'before':before,'after':sha(stage),'backup':str(backup),'stage':str(stage),'mode':p.stat().st_mode&0o777 if before else 0o600}
        save(b/'sync-journal.json',{'files':files,'prepared_at':time.time()});check(b);return {'prepared':True}
    if action=='apply':
        j=check(b);assert not (b/'SYNC_ACCEPTED.json').exists()
        assert all(sha(Path(p))==i['before'] for p,i in j['files'].items())
        for i in j['files'].values():assert sha(Path(i['stage']))==i['after']
        with (b/'sync-guard.log').open('ab') as log:
            subprocess.Popen([sys.executable,str(b/'install_sync.py'),'guard',str(b)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        try:
            for name,i in j['files'].items():atomic(Path(name),Path(i['stage']).read_bytes())
            system('daemon-reload')
        except Exception:rollback(b);raise
        return {'applied':True,'timer_enabled':False,'guard_seconds':1200}
    if action=='enable':check(b);system('enable','--now',TIMER);return {'timer_enabled':True}
    if action=='check':check(b);return {'rollback_precheck':True}
    if action=='rollback':return rollback(b)
    if action=='accept':check(b);save(b/'SYNC_ACCEPTED.json',{'at':time.time()});return {'accepted':True}
    if action=='guard':
        deadline=time.monotonic()+1200
        while time.monotonic()<deadline:
            if (b/'SYNC_ACCEPTED.json').exists() or (b/'SYNC_ROLLED_BACK.json').exists():return {'guard_stopped':True}
            time.sleep(5)
        return rollback(b)
    raise ValueError('unknown_action')

if __name__=='__main__':
    try:print(json.dumps(main()))
    except Exception as e:print(json.dumps({'ok':False,'error_class':type(e).__name__}));sys.exit(1)
