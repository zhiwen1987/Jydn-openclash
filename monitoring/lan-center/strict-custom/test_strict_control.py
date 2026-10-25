"""Real r2 controller regression plus strict business-only activation tests."""
import copy,importlib.util,json,sys,tempfile,unittest,urllib.parse
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE/'tests/fixtures'))
from strict_custom_guard import is_strict_path
from strict_select import activate,PREFIX
from patch_quality import patch as patch_source

class FakeAPI:
 def __init__(self):
  self.business='Google';self.wrapper=PREFIX['node']+self.business;self.events=[]
  self.groups={'Google':{'type':'Selector','all':['public',self.wrapper],'now':'public'},'Gemini':{'type':'Selector','all':['other'],'now':'other'},
   self.wrapper:{'type':'Selector','all':['REJECT','🔐 自建节点 · own'],'now':'REJECT'}}
  self.connections=[{'id':'google-old','chains':['public','Google']},{'id':'gemini-old','chains':['other','Gemini']}]
 def __call__(self,path,method='GET',body=None):
  self.events.append((method,path,body))
  if path=='/proxies':return {'proxies':copy.deepcopy(self.groups)}
  if path=='/connections':return {'connections':copy.deepcopy(self.connections)}
  if path.startswith('/connections/'):
   cid=urllib.parse.unquote(path.rsplit('/',1)[1]);self.connections=[v for v in self.connections if v['id']!=cid];return {}
  name=urllib.parse.unquote(path[len('/proxies/'):])
  if method=='PUT':self.groups[name]['now']=body['name']
  return copy.deepcopy(self.groups[name])

class ControlTests(unittest.TestCase):
 def test_activation_fences_then_closes_only_business(self):
  api=FakeAPI();result=activate(api,'Google','node','🔐 自建节点 · own')
  self.assertEqual(result['matching_connections_closed'],1);self.assertEqual(api.connections,[{'id':'gemini-old','chains':['other','Gemini']}])
  writes=[x for x in api.events if x[0]=='PUT'];self.assertEqual(writes[0][2],{'name':'REJECT'});self.assertEqual(writes[-1][2],{'name':'🔐 自建节点 · own'})
  self.assertEqual(api.groups['Gemini']['now'],'other')
 def test_empty_activation_stays_rejected(self):
  api=FakeAPI();r=activate(api,'Google','node');self.assertTrue(r['closed_until_configured']);self.assertEqual(api.groups[api.wrapper]['now'],'REJECT')
 def test_native_null_connection_list(self):
  api=FakeAPI();api.connections=None;r=activate(api,'Google','node');self.assertEqual(r['matching_connections_closed'],0)
 def test_foreign_target_refused_before_writes(self):
  api=FakeAPI()
  with self.assertRaises(ValueError):activate(api,'Google','node','DIRECT')
  self.assertFalse(any(x[0]=='PUT' for x in api.events))
 def test_missing_wrapper_refused_before_writes(self):
  api=FakeAPI();api.groups.pop(api.wrapper)
  with self.assertRaises(ValueError):activate(api,'Google','node')
  self.assertFalse(any(x[0]=='PUT' for x in api.events))
 def test_private_path_through_parent(self):
  p={'Gemini':{'now':'AI'},'AI':{'now':'🔐 自定义节点 · AI'}}
  self.assertTrue(is_strict_path(p,'Gemini'));self.assertFalse(is_strict_path({'AI':{'now':'public'}},'AI'))
 def test_source_overlay_rejects_unknown_version(self):
  with self.assertRaises(ValueError):patch_source('unsupported controller')
 def test_normal_expired_manual_selection_still_reclaimable(self):
  from strict_custom_guard import may_reclaim
  self.assertTrue(may_reclaim('public-manual',{'manual_override_seconds':60}))
  self.assertFalse(may_reclaim(PREFIX['group']+'Google',{'manual_override_seconds':60}))
 def test_real_controller_never_reclaims_expired_strict_selection(self):
  with tempfile.TemporaryDirectory() as td:
   directory=Path(td);source=HERE/'tests/fixtures/route_quality.py';target=directory/'quality.py';target.write_text(patch_source(source.read_text(encoding='utf-8')),encoding='utf-8')
   spec=importlib.util.spec_from_file_location('tested_quality',target);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
   m.ROOT=directory;m.POLICY=directory/'policy.json';m.STATE=directory/'state.json'
   m.POLICY.write_text(json.dumps({'schema':1,'enabled':True,'manual_override_seconds':1}))
   pool,outer=m.BUSINESSES['chatgpt'];wrapper=PREFIX['node']+outer
   groups={outer:{'type':'Selector','all':[pool,wrapper],'now':wrapper},pool:{'type':'Selector','all':['public'],'now':'public'},wrapper:{'type':'Selector','all':['REJECT'],'now':'REJECT'}};writes=[]
   def api(path,method='GET',body=None):
    if method!='GET':writes.append((path,method,body));raise AssertionError('strict takeover attempted')
    if path=='/proxies':return {'proxies':copy.deepcopy(groups)}
    return copy.deepcopy(groups[urllib.parse.unquote(path.split('/proxies/',1)[1])])
   c=m.Controller(api,lambda:{'nodes':[]},clock=lambda:10000,probe_fn=lambda b:{'ok':False,'ms':8000,'reason':'test'})
   c.state['businesses']['chatgpt']={'manual_selection':wrapper,'manual_since':1,'bad_streak':0}
   c.tick();self.assertEqual(writes,[]);self.assertTrue(c.state['businesses']['chatgpt']['strict_locked'])

if __name__=='__main__':unittest.main(verbosity=2)
