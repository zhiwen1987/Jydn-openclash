import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import urllib.error
from unittest.mock import patch
if sys.platform == "win32":
 # Windows unit tests exercise queue semantics with a process-local lock shim;
 # Linux rehearsal/production still exercise the real non-blocking flock.
 fake_fcntl=types.ModuleType('fcntl');fake_fcntl.LOCK_EX=1;fake_fcntl.LOCK_NB=2
 fake_fcntl.flock=lambda _stream,_mode:None
 sys.modules.setdefault('fcntl',fake_fcntl)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/upstream'))
import health_policy as hp
import clash_measurement as cm
import admission_queue as aq

class PolicyTests(unittest.TestCase):
 def test_single_failure_not_permanent_and_confirmed_cooldown_exact_hour(self):
  r=hp.transition({},False,1000,'timeout');self.assertEqual(r['status'],'checking')
  r=hp.transition(r,False,1011,'timeout');self.assertEqual(r['status'],'checking')
  r=hp.transition(r,False,1022,'timeout');self.assertEqual(r['status'],'unavailable');self.assertEqual(r['next_due'],4622)
 def test_recovery_needs_two_separate_successes_after_cooldown(self):
  r={}
  for t in [1000,1011,1022]:r=hp.transition(r,False,t,'timeout')
  r=hp.transition(r,True,1100);self.assertFalse(hp.eligible(r,1100))
  r=hp.transition(r,True,4622);self.assertTrue(hp.eligible(r,4622))
 def test_repeated_cached_sample_does_not_increase_streak(self):
  r=hp.transition({},True,1000,observed_at=995)
  r=hp.transition(r,True,1040,observed_at=995);self.assertEqual(r['success_streak'],1);self.assertFalse(hp.eligible(r,1040))
 def test_busy_does_not_increment_or_renew_old_success(self):
  r=hp.transition({},True,1000);r=hp.transition(r,True,1011);old=r['at']
  r=hp.transition(r,False,2000,'busy');self.assertEqual(r['failure_streak'],0);self.assertEqual(r['at'],old);self.assertEqual(r['next_due'],2030)
 def test_restart_preserves_cooldown_and_due(self):
  r={}
  for t in [1000,1011,1022]:r=hp.transition(r,False,t,'timeout')
  r=json.loads(json.dumps(r));self.assertEqual(hp.due(r,3000),4622)
 def test_legacy_busy_not_six_hour_failure(self):self.assertEqual(hp.due({'at':1000,'reason':'busy','ok':False},1010),1030)
 def test_future_deadline_bounded(self):self.assertEqual(hp.due({'next_due':1e15},1000),1000)
 def test_small_sample_no_fake_p95_and_invalid_delays_ignored(self):
  self.assertEqual(hp.latency_summary([100,200,0,-1,float('nan')]),{'samples':2,'median_ms':150.0,'p95_ms':None})
  self.assertEqual(hp.latency_summary(list(range(1,21)))['p95_ms'],19)

class MeasurementTests(unittest.TestCase):
 def setUp(self):cm._inventory=(0,{})
 def api(self,results,history=None):
  self.paths=[]
  def call(path):
   self.paths.append(path)
   if path=='/version':return {'version':'fixture'}
   if path=='/providers/proxies':return {'providers':{'source':{'proxies':[{'name':'node','extra':history or {}}]}}}
   result=results.pop(0)
   if isinstance(result,Exception):raise result
   return result
  return call
 def test_native_milliseconds_not_api_wall_time_or_fabricated_http_code(self):
  r=cm.measure(self.api([{'delay':123}]),{'name':'node','provider':'source'},1000)
  self.assertTrue(r['success']);self.assertEqual(r['latency'],123);self.assertEqual(r['code'],0)
  self.assertTrue(all('/group/' not in p and '/delay' not in p for p in self.paths))
 def test_fresh_exact_target_cache_reused(self):
  from datetime import datetime,timezone
  h={cm.TARGETS[0]:{'history':[{'time':datetime.fromtimestamp(990,timezone.utc).isoformat(),'delay':234}]}}
  r=cm.measure(self.api([],h),{'name':'node','provider':'source'},1000)
  self.assertEqual(r['origin'],'clash_history');self.assertEqual(len(self.paths),1)
 def test_failed_first_target_verifies_independent_second(self):
  r=cm.measure(self.api([urllib.error.HTTPError('',503,'',{},None),{'delay':321}]),{'name':'node','provider':'source'},1000)
  self.assertTrue(r['success']);self.assertEqual(len(self.paths),3)
 def test_unsupported_api_is_detector_fault(self):
  r=cm.measure(self.api([urllib.error.HTTPError('',404,'',{},None)]),{'name':'node','provider':'source'},1000)
  self.assertEqual(hp.error_scope(r['error_category']),'detector')
 def test_two_endpoint_failures_are_retestable_not_zero_delay_success(self):
  r=cm.measure(self.api([urllib.error.HTTPError('',504,'',{},None)]*2),{'name':'node','provider':'source'},1000)
  self.assertFalse(r['success']);self.assertEqual(r['latency'],0)

class QueueTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  data=self.root/'subscription-controller';data.mkdir();cache=data/'cache';cache.mkdir()
  rows=[{'name':'fixture-a','type':'ss','server':'example.test','port':1}]
  (cache/'source.yaml').write_text(json.dumps({'proxies':rows}))
  self.module=types.SimpleNamespace(DATA=data,CACHE=cache,MAX_BYTES=10000,current_manifest=lambda:{},previous_fingerprints=lambda m:set(),load_sources=lambda:[types.SimpleNamespace(source_id='source')],normalized_nodes=lambda n:n,parse_nodes=lambda raw:json.loads(raw)['proxies'],fingerprint=lambda n:'a'*64)
 def test_independent_tick_no_publish_and_busy_keeps_retest(self):
  aq.tick(self.module,lambda n:(False,'busy'),epoch=1000)
  r=aq.read_cache(self.module.DATA/'admission-cache.json')['a'*64]
  self.assertEqual(r['next_due'],1030);self.assertNotIn('failure_streak',r)
  aq.tick(self.module,lambda n:(True,'ok'),epoch=1030)
  aq.tick(self.module,lambda n:(True,'ok'),epoch=1060)
  r=aq.read_cache(self.module.DATA/'admission-cache.json')['a'*64];self.assertTrue(hp.eligible(r,1060))
 def test_confirmed_failures_cool_down_and_restore_after_restart(self):
  for t in [1000,1030,1090]:aq.tick(self.module,lambda n:(False,'isolated_transport_failed'),epoch=t)
  p=self.module.DATA/'admission-cache.json';r=aq.read_cache(p)['a'*64];self.assertEqual(r['next_due'],4690)
  self.assertFalse(aq.tick(self.module,lambda n:self.fail('must wait'),epoch=4600))
  aq.tick(self.module,lambda n:(True,'ok'),epoch=4690);aq.tick(self.module,lambda n:(True,'ok'),epoch=4720)
  self.assertTrue(hp.eligible(aq.read_cache(p)['a'*64],4720))
 def test_corrupt_queue_never_silently_overwritten(self):
  p=self.module.DATA/'admission-cache.json';p.write_text('{broken')
  with self.assertRaises(ValueError):aq.tick(self.module,lambda n:(True,'ok'),epoch=1000)
  self.assertEqual(p.read_text(),'{broken')
 def test_bounded_batch_and_per_source_progress_have_no_fake_percentage(self):
  rows=[{'name':f'fixture-{i}','type':'ss','server':f'{i}.example.test','port':1} for i in range(3)]
  (self.module.CACHE/'source.yaml').write_text(json.dumps({'proxies':rows}))
  self.module.fingerprint=lambda n:(str(rows.index(n)+1)*64)[:64]
  calls=[]
  with patch.dict(os.environ,{'SUBSCRIPTION_ADMISSION_BATCH_SIZE':'2'}):
   self.assertTrue(aq.tick(self.module,lambda n:(calls.append(n['name']) or (True,'ok')),epoch=1000))
  self.assertEqual(len(calls),2)
  progress=json.loads((self.root/'node-health'/'admission-progress.json').read_text())
  source=progress['sources'][0]
  self.assertEqual((source['parsed_count'],source['candidate_count'],source['tested_count']),(3,3,2))
  self.assertNotIn('percent',json.dumps(progress).lower())
 def test_batch_is_fair_across_sources_before_second_node(self):
  rows_a=[{'name':f'a-{i}','type':'ss','server':f'a{i}.test','port':1} for i in range(3)]
  rows_b=[{'name':'b-0','type':'ss','server':'b0.test','port':1}]
  (self.module.CACHE/'a.yaml').write_text(json.dumps({'proxies':rows_a}))
  (self.module.CACHE/'b.yaml').write_text(json.dumps({'proxies':rows_b}))
  self.module.load_sources=lambda:[types.SimpleNamespace(source_id='a'),types.SimpleNamespace(source_id='b')]
  self.module.fingerprint=lambda n:__import__('hashlib').sha256(n['server'].encode()).hexdigest()
  calls=[]
  aq.tick(self.module,lambda n:(calls.append(n['name']) or (True,'ok')),epoch=1000)
  self.assertEqual({name.split('-',1)[0] for name in calls},{'a','b'})

class IntegratedPolicyTests(unittest.TestCase):
 def setUp(self):
  path=Path(__file__).resolve().parents[1]/'runtime/upstream/node-capability.py'
  spec=importlib.util.spec_from_file_location('health_fixture_capability',path);self.mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=self.mod;spec.loader.exec_module(self.mod)
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.mod.DB_PATH=Path(self.tmp.name)/'cap.db';self.mod.init_db()
  with self.mod.db_session() as c:c.execute("INSERT INTO nodes(id,name,node_type,provider,first_seen,last_seen,active) VALUES('fixture','node','ss','source',100,100,1)")
 def test_database_confirmation_and_detector_failure_keep_history(self):
  m=self.mod
  with m.db_session() as c:
   m.update_capability(c,'fixture','general',False,0,1000,'timeout')
   self.assertEqual(c.execute('select status from capabilities').fetchone()[0],'checking')
   m.update_capability(c,'fixture','general',False,0,1011,'timeout');m.update_capability(c,'fixture','general',False,0,1022,'timeout')
   state=json.loads(c.execute('select record_json from probe_schedule').fetchone()[0]);self.assertEqual(state['next_due'],4622)
   m.update_capability(c,'fixture','general',False,0,1033,'detector_api_unavailable')
   state=json.loads(c.execute('select record_json from probe_schedule').fetchone()[0]);self.assertEqual(state['failure_streak'],3)
  # A reopened SQLite connection preserves the due time and failure evidence.
  with m.db_session() as c:self.assertEqual(c.execute('select consecutive_failure from capabilities').fetchone()[0],3)
 def test_basic_native_test_never_selects_shared_or_business_group(self):
  m=self.mod;clock=[100000]
  with m.db_session() as c:
   for business,*_ in m.BUSINESS_PROBES:
    c.execute('INSERT INTO capabilities(node_id,business,status,score,last_checked) VALUES(?,?,?,?,?)',('fixture',business,'available',100,clock[0]))
   c.execute('INSERT INTO egress_observations(node_id,last_checked) VALUES(?,?)',('fixture',clock[0]))
  cm._inventory=(0,{});cm._failures=[];cm._paused_until=0
  def api(path):
   if path=='/providers/proxies':return {'providers':{'source':{'proxies':[{'name':'node'}]}}}
   self.assertIn('/healthcheck?',path);return {'delay':345}
  m.api_request=api;m.select_probe_node=lambda _:self.fail('selector write forbidden');m.log=lambda *_:None
  with patch.object(m,'now',side_effect=lambda:clock[0]),patch.object(cm.time,'time',side_effect=lambda:clock[0]):
   m.probe_node({'id':'fixture','name':'node','provider':'source'})
   clock[0]+=30;m.probe_node({'id':'fixture','name':'node','provider':'source'})
  with m.db_session() as c:
   state=json.loads(c.execute("select record_json from probe_schedule where business='general'").fetchone()[0]);self.assertEqual(state['status'],'available')
   rows=c.execute('select latency_ms,http_code from probe_results').fetchall();self.assertEqual([(r[0],r[1]) for r in rows],[(345,0),(345,0)])
 def test_global_outage_guard_needs_distinct_nodes_and_providers(self):
  cm._failures=[];cm._paused_until=0
  for i in range(4):result=cm.suspect_batch({'id':str(i),'provider':'a'},{'success':False},1000+i)
  self.assertFalse(result)
  self.assertTrue(cm.suspect_batch({'id':'other','provider':'b'},{'success':False},1005))
  cm.pause_batch(1005);self.assertTrue(cm.batch_paused(1064));self.assertFalse(cm.batch_paused(1065))
  cm._failures=[];cm._paused_until=0
 def test_legacy_measurements_not_relabelled_as_native_head(self):
  item=self.mod.status_payload()['nodes'][0]
  self.assertEqual(item['latency_kind'],'legacy_http');self.assertEqual(item['latency_summary']['samples'],0)

if __name__=='__main__':unittest.main()
