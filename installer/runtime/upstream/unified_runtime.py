"""One-container service supervision with persistent bounded component recovery."""
import hashlib,json,os,re,signal,subprocess,sys,time,urllib.request,uuid
from pathlib import Path
from autonomy_store import atomic_json,checkpoint,recover_document
from upgrade_policy import budget_allows
ROOT=Path(os.getenv('UNIFIED_STATE_DIR','/data/unified'))
SERVICES={'dns':['/usr/local/bin/coredns','-conf','/etc/coredns/Corefile'],
 'kuma':['node','/app/server/server.js'],
 'control':['/bin/sh','/failover.sh']}
if os.getenv('LAN_CENTER_PASSIVE')=='1':SERVICES['control']=['python3','-B','/passive_control.py']

def valid(v):
 return isinstance(v,dict) and v.get('schema')==1 and isinstance(v.get('events'),list) and all(isinstance(e,dict) and e.get('component') in SERVICES and type(e.get('at')) in (int,float) for e in v['events'])

class Supervisor:
 def __init__(self,services=None,root=ROOT):
  self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.services=services or SERVICES;self.children={};self.stop=False
  self.state,recovery=recover_document(self.root/'budget.json',valid)
  if self.state is None:
   unknown=any((self.root/name).exists() for name in ['budget.json','budget.json.good'])
   self.state={'schema':1,'events':[],'highwater':0,'frozen_until':time.time()+1800 if unknown else 0}
  self.last_save=0
  self.last_request=None
  # Recovery budget exceptions are deliberately process-local and one-shot.
  # A supervisor restart therefore fails closed instead of replaying an old
  # failed transaction as authority for an extra DNS restart.
  self.failed_requests={};self.consumed_recoveries=set()
 def launch(self,name,recovery=False):
  now=time.time()
  if recovery:
   if now<self.state.get('highwater',0) or now<self.state.get('frozen_until',0) or not budget_allows(self.state['events'],now,name):return False
   self.state['events'].append({'component':name,'at':now});self.state['events']=self.state['events'][-30:]
   self.persist()
  environment=os.environ.copy()
  if name=='kuma':environment['TZ']=os.getenv('KUMA_TZ','Etc/UTC')
  self.children[name]=subprocess.Popen(self.services[name],cwd='/app' if name=='kuma' and Path('/app').exists() else '/',start_new_session=True,env=environment)
  return True
 def persist(self):
  self.state['highwater']=max(time.time(),self.state.get('highwater',0));atomic_json(self.root/'budget.json',self.state);checkpoint(self.root/'budget.json',self.state)
 def terminate(self,name,grace=20):
  p=self.children.get(name)
  if p:
   try:os.killpg(p.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   if p.poll() is None:
    try:p.wait(timeout=grace)
    except subprocess.TimeoutExpired:pass
   # Clean surviving grandchildren even when the original group leader died.
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   if p.poll() is None:p.wait(timeout=3)
 def status(self):
  value={'schema':1,'epoch':time.time(),'services':{n:{'running':p.poll() is None,'pid':p.pid,'exit':p.poll()} for n,p in self.children.items()},'restart_events':self.state['events']}
  if self.last_request is not None:value['last_request']=self.last_request
  atomic_json(self.root/'status.json',value);self.last_save=value['epoch']
 def request_result(self,request_id,state,started,old_pid,new_pid=None,loaded=None,fragment=None,error=None,purpose=None,recovery_of=None,budget_override=False,recoverable=False):
  finished=time.time() if state in ('completed','failed') else None
  self.last_request={'id':request_id,'state':state,'started_at':started,'finished_at':finished,'old_pid':old_pid,'new_pid':new_pid,'loaded_core_sha256':loaded,'loaded_fragment_sha256':fragment,'error_code':error,'purpose':purpose,'recovery_of':recovery_of,'budget_override':bool(budget_override),'recoverable':bool(state=='failed' and recoverable and purpose in ('apply','rollback'))}
  if state in ('completed','failed') and recoverable and purpose in ('apply','rollback'):
   self.failed_requests[request_id]={'at':finished,'component':'dns','purpose':purpose,'terminal_state':state,'consumed':False,'recoverable':True}
   self.failed_requests={key:value for key,value in self.failed_requests.items() if finished-value['at']<=120}
  self.status()
 def request(self,name,request_id=None,expected_core_sha256=None,expected_fragment_sha256=None,created_at=None,expires_at=None,purpose=None,recovery_of=None):
  if name not in self.services:return False
  started=time.time();old=self.children.get(name);old_pid=old.pid if old else None
  if name=='dns' and not request_id:return False
  if request_id:
   self.request_result(request_id,'accepted',started,old_pid,purpose=purpose,recovery_of=recovery_of)
   recovery_reference=isinstance(recovery_of,str) and bool(re.fullmatch(r'[A-Za-z0-9_.-]{8,96}',recovery_of))
   if name!='dns' or not re.fullmatch(r'[A-Za-z0-9_.-]{8,96}',request_id or '') or not re.fullmatch(r'[0-9a-f]{64}',expected_core_sha256 or '') or type(created_at) not in (int,float) or type(expires_at) not in (int,float) or not created_at<=time.time()<=expires_at or not 1<=expires_at-created_at<=30 or purpose not in ('apply','rollback','recovery') or (purpose=='recovery')!=recovery_reference or recovery_of==request_id:
    code='request_expired' if type(expires_at) in (int,float) and time.time()>expires_at else 'invalid_request'
    self.request_result(request_id,'failed',started,old_pid,error=code,purpose=purpose,recovery_of=recovery_of);return False
   if expected_fragment_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}',expected_fragment_sha256):
    self.request_result(request_id,'failed',started,old_pid,error='invalid_request',purpose=purpose,recovery_of=recovery_of);return False
   if purpose!='recovery' and (old is None or old.poll() is not None or not isinstance(old_pid,int) or old_pid<=0):
    self.request_result(request_id,'failed',started,old_pid,error='dns_process_not_running',purpose=purpose,recovery_of=recovery_of);return False
   try:loaded=hashlib.sha256(Path('/etc/coredns/Corefile').read_bytes()).hexdigest()
   except OSError:
    self.request_result(request_id,'failed',started,old_pid,error='corefile_unreadable',purpose=purpose,recovery_of=recovery_of);return False
   if loaded!=expected_core_sha256:
    self.request_result(request_id,'failed',started,old_pid,loaded=loaded,error='corefile_hash_mismatch',purpose=purpose,recovery_of=recovery_of);return False
   fragment=None
   if expected_fragment_sha256 is not None:
    try:fragment=hashlib.sha256(Path('/etc/coredns/Corefile.managed').read_bytes()).hexdigest()
    except OSError:
     self.request_result(request_id,'failed',started,old_pid,loaded=loaded,error='fragment_unreadable',purpose=purpose,recovery_of=recovery_of);return False
    if fragment!=expected_fragment_sha256:
     self.request_result(request_id,'failed',started,old_pid,loaded=loaded,fragment=fragment,error='fragment_hash_mismatch',purpose=purpose,recovery_of=recovery_of);return False
   if purpose=='recovery':
    prior=self.failed_requests.get(recovery_of)
    if not prior or prior.get('component')!='dns' or prior.get('purpose') not in ('apply','rollback') or prior.get('recoverable') is not True or prior.get('consumed') or started-prior.get('at',0)>120 or started<prior.get('at',0):
     self.request_result(request_id,'failed',started,old_pid,loaded=loaded,fragment=fragment,error='invalid_recovery_reference',purpose=purpose,recovery_of=recovery_of);return False
  now=time.time()
  budget_denied=now<self.state.get('highwater',0) or now<self.state.get('frozen_until',0) or not budget_allows(self.state['events'],now,name)
  budget_override=bool(budget_denied and request_id and purpose=='recovery' and not (now<self.state.get('highwater',0) or now<self.state.get('frozen_until',0)))
  if budget_denied and not budget_override:
   if request_id:self.request_result(request_id,'failed',started,old_pid,error='restart_budget_refused',purpose=purpose,recovery_of=recovery_of)
   return False
  if request_id and purpose=='recovery':self.failed_requests[recovery_of]['consumed']=True;self.consumed_recoveries.add(recovery_of)
  self.state['events'].append({'component':name,'at':now,'request_id':request_id,'purpose':purpose,'recovery_of':recovery_of,'budget_override':budget_override});self.state['events']=self.state['events'][-30:];self.persist()
  if request_id and time.time()>expires_at:
   self.request_result(request_id,'failed',started,old_pid,loaded=loaded,fragment=fragment,error='request_expired',purpose=purpose,recovery_of=recovery_of,budget_override=budget_override);return False
  try:self.terminate(name,3 if request_id else 20)
  except Exception:
   crossed=bool(old is not None and old.poll() is not None)
   current=self.children.get(name)
   if crossed and (current is None or current.poll() is not None):
    try:self.launch(name,False)
    except Exception:pass
   current=self.children.get(name);new_pid=current.pid if current and current.poll() is None else None
   if request_id:self.request_result(request_id,'failed',started,old_pid,new_pid,loaded,fragment,'request_processing_failed',purpose,recovery_of,budget_override,recoverable=crossed and purpose in ('apply','rollback'))
   return False
  expired_before_launch=bool(request_id and time.time()>expires_at)
  try:launched=self.launch(name,False)
  except Exception:
   # The stop boundary has already been crossed.  Make one best-effort
   # availability launch, but never report the requested configuration as
   # accepted; the manager must restore bytes and use the linked authority.
   try:launched=self.launch(name,False)
   except Exception:launched=False
   current=self.children.get(name);new_pid=current.pid if launched and current and current.poll() is None else None
   if request_id:self.request_result(request_id,'failed',started,old_pid,new_pid,loaded,fragment,'request_processing_failed',purpose,recovery_of,budget_override,recoverable=purpose in ('apply','rollback'))
   return False
  if not launched:
   if request_id:self.request_result(request_id,'failed',started,old_pid,error='launch_failed',purpose=purpose,recovery_of=recovery_of,budget_override=budget_override,recoverable=purpose in ('apply','rollback'))
   return False
  if not request_id:return True
  new=self.children[name]
  if expired_before_launch:
   self.request_result(request_id,'failed',started,old_pid,new.pid,loaded,fragment,'request_expired',purpose,recovery_of,budget_override,recoverable=purpose in ('apply','rollback'));return False
  deadline=min(time.monotonic()+20,time.monotonic()+max(0,expires_at-time.time()))
  ready=False
  while time.monotonic()<deadline and new.poll() is None:
   try:
    with urllib.request.urlopen('http://127.0.0.1:18181/ready',timeout=1) as response:ready=response.status==200
   except Exception:ready=False
   if ready:break
   time.sleep(.25)
  try:loaded=hashlib.sha256(Path('/etc/coredns/Corefile').read_bytes()).hexdigest()
  except OSError:loaded=None
  if expected_fragment_sha256 is not None:
   try:fragment=hashlib.sha256(Path('/etc/coredns/Corefile.managed').read_bytes()).hexdigest()
   except OSError:fragment=None
  if ready and time.time()<=expires_at and new.pid!=old_pid and loaded==expected_core_sha256 and fragment==expected_fragment_sha256:
   self.request_result(request_id,'completed',started,old_pid,new.pid,loaded,fragment,purpose=purpose,recovery_of=recovery_of,budget_override=budget_override,recoverable=purpose in ('apply','rollback'));return True
  error='request_expired' if time.time()>expires_at else 'dns_restart_not_verified'
  self.request_result(request_id,'failed',started,old_pid,new.pid,loaded,fragment,error,purpose,recovery_of,budget_override,recoverable=purpose in ('apply','rollback'));return False
 def tick(self):
  for name,p in list(self.children.items()):
   if p.poll() is not None:
    if not getattr(p,'group_cleaned',False):self.terminate(name);p.group_cleaned=True
    self.launch(name,True)
  requests=self.root/'requests';requests.mkdir(exist_ok=True)
  for path in list(requests.glob('*.json'))[:8]:
   value=None
   try:
    value=json.loads(path.read_text());name=value.get('component');created=value.get('created_at',value.get('at',0));age=time.time()-created
    if name=='dns' and value.get('request_id'):
     self.request(name,value.get('request_id'),value.get('expected_core_sha256'),value.get('expected_fragment_sha256'),created,value.get('expires_at'),value.get('purpose'),value.get('recovery_of'))
    elif 0<=age<=30 and name in self.services:self.request(name)
   except Exception as error:
    try:
     request_id=value.get('request_id') if isinstance(value,dict) else None;name=value.get('component') if isinstance(value,dict) else None
     if name=='dns' and isinstance(request_id,str) and re.fullmatch(r'[A-Za-z0-9_.-]{8,96}',request_id):
      old=self.children.get('dns');self.request_result(request_id,'failed',time.time(),old.pid if old else None,error='request_processing_failed')
    except Exception:pass
   try:path.unlink(missing_ok=True)
   except OSError:pass
  now=time.time()
  if now-self.last_save>=10:
   self.status()
 def run(self):
  def stop(_sig,_frame):self.stop=True
  signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
  try:
   for name in self.services:
    if name=='control' and 'dns' in self.children:
     deadline=time.monotonic()+10
     while time.monotonic()<deadline:
      try:
       with urllib.request.urlopen('http://127.0.0.1:18181/ready',timeout=1) as response:
        if response.status==200:break
      except Exception:pass
      time.sleep(.2)
    self.launch(name);self.status()
   while not self.stop:self.tick();time.sleep(1)
  finally:
   for name in reversed(list(self.services)):self.terminate(name)
   self.persist()

def health():
 try:
  s=json.loads((ROOT/'status.json').read_text());assert 0<=time.time()-s['epoch']<35
  assert all(s['services'][k]['running'] for k in SERVICES)
  for url in ['http://127.0.0.1:3001/','http://127.0.0.1:18080/health','http://127.0.0.1:18181/ready','http://127.0.0.1:8080/health']:
   with urllib.request.urlopen(url,timeout=1.5) as r:assert r.status==200
  return 0
 except Exception:return 1

if __name__=='__main__':
 os.umask(0o077)
 if len(sys.argv)>1 and sys.argv[1]=='health':raise SystemExit(health())
 Supervisor().run()
