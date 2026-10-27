"""Bootstrap cooldown must keep the established recovery maintenance alive."""
import contextlib,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('portable_subscriptions',Path(__file__).resolve().parents[1]/'runtime/portable_subscriptions.py')
wrapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(wrapper)
class EndRun(BaseException):pass
class SchedulerTests(unittest.TestCase):
 def test_information_only_acceptance_never_calls_node_maintenance(self):
  with tempfile.TemporaryDirectory() as directory:
   data=Path(directory);clock=[100];health=[]
   (data/'usage-reload-defer.json').write_text(json.dumps({'until':160,'release_id':'accepted','health':{'status':'ok'},'information_only_acceptance':True}))
   module=types.SimpleNamespace(DATA=data,HEALTH_PATH=data/'health.json',now=lambda:clock[0],current_manifest=lambda:{'release_id':'accepted'},atomic_json=lambda p,v:health.append(dict(v)),maintain_probation=lambda:self.fail('node maintenance forbidden'),repair_pointer=lambda:self.fail('node repair forbidden'))
   def sleep(seconds):clock[0]+=seconds
   with patch.object(wrapper.time,'monotonic',side_effect=lambda:clock[0]),patch.object(wrapper.time,'sleep',side_effect=sleep):wrapper.resume_metadata_reload(module)
   self.assertEqual(clock[0],160);self.assertTrue(health[-1]['metadata_reload_deferred'])
 def test_metadata_reload_preserves_deadline_and_maintenance(self):
  with tempfile.TemporaryDirectory() as directory:
   data=Path(directory);clock=[100];health=[];maintenance=[]
   path=data/'usage-reload-defer.json'
   path.write_text(json.dumps({'until':160,'release_id':'accepted','health':{'epoch':90,'status':'ok'}}))
   module=types.SimpleNamespace(DATA=data,HEALTH_PATH=data/'health.json',now=lambda:clock[0],current_manifest=lambda:{'release_id':'accepted'},atomic_json=lambda p,v:health.append(dict(v)),maintain_probation=lambda:maintenance.append(clock[0]),repair_pointer=lambda:False,log=lambda *a:None)
   def sleep(seconds):clock[0]+=seconds
   with patch.object(wrapper.time,'monotonic',side_effect=lambda:clock[0]),patch.object(wrapper.time,'sleep',side_effect=sleep):wrapper.resume_metadata_reload(module)
   self.assertEqual(clock[0],160);self.assertEqual(maintenance,[130,160]);self.assertFalse(path.exists())
   self.assertEqual(health[-1]['next_cycle_epoch'],160);self.assertEqual(health[-1]['previous_cycle_epoch'],90)
   self.assertEqual(health[-1]['status'],'ok')
 def test_metadata_reload_rejects_foreign_release_or_unbounded_deadline(self):
  with tempfile.TemporaryDirectory() as directory:
   data=Path(directory);path=data/'usage-reload-defer.json'
   module=types.SimpleNamespace(DATA=data,now=lambda:100,current_manifest=lambda:{'release_id':'accepted'})
   for deadline,release in [(5000,'accepted'),(99,'accepted'),(150,'foreign')]:
    path.write_text(json.dumps({'until':deadline,'release_id':release}))
    wrapper.resume_metadata_reload(module);self.assertFalse(path.exists())
 def test_idle_cooldown_keeps_recovery_tick_without_busy_polling(self):
  clock=[0];health=[];maintenance=[];queries=[]
  def sleep(seconds):
   if clock[0]>=30:raise EndRun()
   clock[0]+=seconds
  module=types.SimpleNamespace(LOCK=contextlib.nullcontext(),MODE='automatic',HEALTH_PATH=Path('/not-written'),DATA=Path('/not-written'),now=lambda:clock[0],load_sources=lambda:queries.append(clock[0]) or [],atomic_json=lambda path,data:health.append(data),maintain_probation=lambda:maintenance.append(clock[0]),repair_pointer=lambda:False,log=lambda *a:None)
  with patch.object(wrapper.time,'monotonic',side_effect=lambda:clock[0]),patch.object(wrapper.time,'sleep',side_effect=sleep):
   with self.assertRaises(EndRun):wrapper.scheduler(module)()
  self.assertEqual(maintenance,[30]);self.assertEqual(queries,[0,30])
  self.assertTrue(all(x['status']=='awaiting_sources' for x in health))
if __name__=='__main__':unittest.main()
