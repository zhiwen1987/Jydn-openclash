"""Bootstrap cooldown must keep the established recovery maintenance alive."""
import contextlib,importlib.util,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('portable_subscriptions',Path(__file__).resolve().parents[1]/'runtime/portable_subscriptions.py')
wrapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(wrapper)
class EndRun(BaseException):pass
class SchedulerTests(unittest.TestCase):
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
