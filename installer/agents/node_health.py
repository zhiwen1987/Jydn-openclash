"""Scoped health-code overlay with independent rollback; no container restart."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CONTROL=Path('/root/dpanel/compose/lan-center/data/failover')
CODE=CONTROL/'node-health/code'
RELEASE=Path('/opt/clash-stack/production/releases/0.1.1/payload/center')
STATE=Path('/opt/clash-stack/production/state.json')
NAMES={'health_policy.py','clash_measurement.py','admission_queue.py','subscription_impl.py','node_admission.py','route_quality.py'}

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).is_file() else None
def write(p,raw,inplace=False,mode=0o600):
 p=Path(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if inplace:
  with p.open('r+b') as f:f.seek(0);f.write(raw);f.truncate();f.flush();os.fsync(f.fileno())
  return
 temp=p.with_name(p.name+'.node-health-stage')
 with temp.open('wb') as f:os.chmod(temp,mode);f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(temp,p)
def save(p,value):write(p,json.dumps(value,ensure_ascii=False,indent=2).encode())
def identity():
 x=json.loads(subprocess.check_output(['docker','inspect','clash-center']))[0]
 return {k:x['State'][k] for k in ['StartedAt']}|{'id':x['Id'],'image':x['Image']}
def reload_workers():
 script="""import json,os,signal
from pathlib import Path
for f,target in [('/data/node-capability.pid','/node-capability.py'),('/data/subscription-controller.pid','/subscription-controller.py')]:
 p=int(Path(f).read_text());args=Path('/proc/'+str(p)+'/cmdline').read_bytes().split(b'\\0');assert target.encode() in args,'worker_identity_changed';os.kill(p,signal.SIGTERM)
print(json.dumps({'worker_only_reload':True}))
"""
 subprocess.check_output(['docker','exec','clash-center','python3','-B','-c',script],stderr=subprocess.DEVNULL,timeout=15)
def check(b):
 j=json.loads((b/'health-journal.json').read_text());assert identity()==j['container'],'container_changed'
 for name,r in j['files'].items():
  assert sha(name) in (r['before'],r['after']),'later_edit_requires_review'
  assert r['before'] is None or sha(r['backup'])==r['before'],'backup_corrupt'
 return j
def rollback(b):
 j=check(b)
 write(CONTROL/'node-health/pause-admission',b'rollback')
 for name,r in j['files'].items():
  if r['before'] is None:Path(name).unlink(missing_ok=True)
  else:write(name,Path(r['backup']).read_bytes(),Path(name).parent==RELEASE,r['mode'])
 (CONTROL/'node-health/acceptance-hold.json').unlink(missing_ok=True)
 reload_workers();save(b/'ROLLED_BACK.json',{'at':time.time(),'databases_restored':False,'history_retained':True})
 return {'restored':True,'container_restarted':False,'history_retained':True}
def main():
 action,directory=sys.argv[1:3];b=Path(directory).resolve();assert b.parent==Path('/var/backups') and b.name.startswith('clash-node-health-') and b.is_dir()
 if action=='prepare':
  assert not (b/'health-journal.json').exists();payload=json.load(sys.stdin)
  allowed={str(RELEASE/n) for n in ['node-capability.py','subscription-controller.py']}|{str(CODE/n) for n in NAMES}
  assert set(payload)==allowed,'unexpected_code_targets'
  state=json.loads(STATE.read_text());files={}
  for name,encoded in payload.items():
   p=Path(name);raw=base64.b64decode(encoded,validate=True);compile(raw,name,'exec');before=sha(p)
   if p.parent==RELEASE:assert before==state['manifest']['payload_files']['payload/center/'+p.name],'managed_code_drift'
   else:assert before is None,'overlay_already_exists'
   n=str(len(files));backup=b/('code-before-'+n);stage=b/('code-after-'+n)
   if before:write(backup,p.read_bytes())
   write(stage,raw);files[name]={'before':before,'after':sha(stage),'backup':str(backup),'stage':str(stage),'mode':p.stat().st_mode&0o777 if before else 0o600}
  for n in ['node-capability.py','subscription-controller.py']:state['manifest']['payload_files']['payload/center/'+n]=files[str(RELEASE/n)]['after']
  state.setdefault('node_health_history',[]).append({'receipt':str(b),'at':time.time(),'scope':'node_health_only','dns_changed':False})
  stage=b/'state-after.json';save(stage,state);backup=b/'state-before.json';write(backup,STATE.read_bytes());files[str(STATE)]={'before':sha(STATE),'after':sha(stage),'backup':str(backup),'stage':str(stage),'mode':0o600}
  save(b/'health-journal.json',{'files':files,'container':identity()});check(b);return {'prepared':True,'rollback_precheck':True}
 if action=='apply':
  j=check(b);assert all(sha(p)==v['before'] for p,v in j['files'].items())
  for r in j['files'].values():assert sha(r['stage'])==r['after']
  for n in ['publish-pending.json','release-probation.json','recovery-refresh.json']:assert not (CONTROL/'subscription-controller'/n).exists(),'publication_in_progress'
  assert not json.loads((CONTROL/'route-quality.json').read_text()).get('trial'),'quality_trial_in_progress'
  with (b/'guard.log').open('ab') as log:subprocess.Popen([sys.executable,str(b/'node_health.py'),'guard',str(b)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
  try:
   health=json.loads((CONTROL/'subscription-controller/health.json').read_text())
   save(CONTROL/'node-health/acceptance-hold.json',{'until':time.time()+1200,'health':health})
   write(CONTROL/'node-health/pause-admission',b'acceptance')
   for name,r in j['files'].items():write(name,Path(r['stage']).read_bytes(),Path(name).parent==RELEASE,r['mode'])
   reload_workers();check(b)
  except Exception:rollback(b);raise
  return {'applied':True,'guard_seconds':1200,'container_restarted':False,'publication_and_quality_held':True}
 if action=='check':check(b);return {'rollback_precheck':True}
 if action=='rollback':return rollback(b)
 if action=='accept':
  check(b);(CONTROL/'node-health/acceptance-hold.json').unlink(missing_ok=True);(CONTROL/'node-health/pause-admission').unlink(missing_ok=True);save(b/'ACCEPTED.json',{'at':time.time()});return {'accepted':True}
 if action=='guard':
  until=time.monotonic()+1200
  while time.monotonic()<until:
   if (b/'ACCEPTED.json').exists() or (b/'ROLLED_BACK.json').exists():return {'guard_stopped':True}
   time.sleep(5)
  return rollback(b)
 raise ValueError('unknown_action')

if __name__=='__main__':
 try:print(json.dumps(main()))
 except Exception as e:print(json.dumps({'ok':False,'error_class':type(e).__name__}));sys.exit(1)
