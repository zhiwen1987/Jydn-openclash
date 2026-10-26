"""One-container service supervision with persistent bounded component recovery."""
import json,os,signal,subprocess,sys,time,urllib.request,uuid
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
 def terminate(self,name):
  p=self.children.get(name)
  if p:
   try:os.killpg(p.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   if p.poll() is None:
    try:p.wait(timeout=20)
    except subprocess.TimeoutExpired:pass
   # Clean surviving grandchildren even when the original group leader died.
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   if p.poll() is None:p.wait(timeout=3)
 def request(self,name):
  if name not in self.services:return False
  now=time.time()
  if now<self.state.get('highwater',0) or now<self.state.get('frozen_until',0) or not budget_allows(self.state['events'],now,name):return False
  self.state['events'].append({'component':name,'at':now});self.state['events']=self.state['events'][-30:];self.persist()
  self.terminate(name);return self.launch(name,False)
 def tick(self):
  for name,p in list(self.children.items()):
   if p.poll() is not None:
    if not getattr(p,'group_cleaned',False):self.terminate(name);p.group_cleaned=True
    self.launch(name,True)
  requests=self.root/'requests';requests.mkdir(exist_ok=True)
  for path in list(requests.glob('*.json'))[:8]:
   try:
    value=json.loads(path.read_text());name=value.get('component');age=time.time()-value.get('at',0)
    if 0<=age<=30 and name in self.services:self.request(name)
   except (OSError,ValueError,TypeError):pass
   path.unlink(missing_ok=True)
  now=time.time()
  if now-self.last_save>=10:
   atomic_json(self.root/'status.json',{'schema':1,'epoch':now,'services':{n:{'running':p.poll() is None,'pid':p.pid,'exit':p.poll()} for n,p in self.children.items()},'restart_events':self.state['events']});self.last_save=now
 def run(self):
  def stop(_sig,_frame):self.stop=True
  signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
  try:
   for name in self.services:self.launch(name)
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
