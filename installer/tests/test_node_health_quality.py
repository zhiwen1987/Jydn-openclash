"""Exercise the real quality loop without any production selector or network."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/upstream'))
import route_quality as quality

class QualityCoordinationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name)
  for name in ['STATE','POLICY']:
   p=patch.object(quality,name,root/(name+'.json'));p.start();self.addCleanup(p.stop)
  quality.POLICY.write_text(json.dumps({'enabled':False}))
  self.clock=10000;self.selected='A';self.writes=[];pool,outer=quality.BUSINESSES['default']
  nodes=[{'name':name,'score':100,'general_success_ratio':1,'provider':'source','capabilities':{'general':{'status':'available'}}} for name in 'ABCDE']
  graph={pool:{'type':'Selector','now':'A','all':list('ABCDE')},outer:{'type':'Selector','now':pool},'A':{'type':'SS'}}
  def api(path):
   if path=='/proxies':return {'proxies':graph}
   return {'now':self.selected,'all':list('ABCDE')}
  self.controller=quality.Controller(api,lambda:{'nodes':nodes},clock=lambda:self.clock,probe_fn=lambda business:{'ok':True,'ms':100,'http':'204','reason':'ok'})
  def select(group,node):
   self.assertEqual(group,'🧪 节点能力检测');self.writes.append((group,node));old=self.selected;self.selected=node;return old
  self.controller.select=select
 def test_empty_valid_sample_list_survives_real_candidate_rotation(self):
  self.controller.state['samples']['default:'+hashlib.sha256(b'B').hexdigest()[:16]]=[]
  with patch.object(quality.time,'sleep'):self.assertTrue(self.controller._tick())
  self.assertTrue(self.writes)
 def test_rotation_eventually_probes_nodes_outside_first_four(self):
  with patch.object(quality.time,'sleep'):
   for _ in range(20):self.controller._tick();self.clock+=30
  observed={key.split(':')[1] for key,rows in self.controller.state['samples'].items() if rows}
  self.assertTrue({hashlib.sha256(n.encode()).hexdigest()[:16] for n in 'ABCDE'}<=observed)
 def test_deployment_hold_never_reads_or_writes_selectors(self):
  self.controller.api=lambda *_:self.fail('control API forbidden during hold')
  with patch('health_policy.acceptance_hold',return_value=True):self.assertFalse(self.controller.tick())
  self.assertFalse(self.writes)

if __name__=='__main__':unittest.main()
