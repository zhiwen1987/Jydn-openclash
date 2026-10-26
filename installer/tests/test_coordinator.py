"""Failure before router changes must still release the prepared server state."""
import sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stack.coordinator import Coordinator
from stack.model import Failure

class PreflightTests(unittest.TestCase):
 def test_restore_waits_for_previous_services_but_not_removed_first_install(self):
  for previous in (None,'old'):
   with self.subTest(previous=previous):
    c=object.__new__(Coordinator);c.emit=Mock();c.router_action=Mock(return_value={'restored':True})
    c.server_action=Mock(return_value={'restored':True,'previous_managed_version':previous})
    c.verify=Mock(side_effect=[Failure('center_health_pending'),{'ready':True}])
    with patch('stack.coordinator.time.sleep'):
     result=c.restore()
    if previous:self.assertEqual(result['verification'],{'ready':True});self.assertEqual(c.verify.call_count,2)
    else:c.verify.assert_not_called()

 def test_empty_published_dns_rolls_back_before_router_prepare(self):
  c=object.__new__(Coordinator)
  c.p={'mode':'fresh','dns':{'publish':True}}
  c.manifest={'version':'test'};c.package='/owned/package'
  c._validate_plan=Mock();c.stage_package=Mock();c.emit=Mock()
  c.server_action=Mock(side_effect=[{'private':{},'source_count':0,'transaction':'1000000000000000000'}, {'restored':True}])
  c.router_action=Mock()
  with self.assertRaisesRegex(Failure,'空订阅'):
   c.install({'inventory':{'server':{}}})
  self.assertEqual([call.args[0] for call in c.server_action.call_args_list],['prepare','restore'])
  c.router_action.assert_not_called()

 def test_center_commits_first_and_failed_router_commit_compensates(self):
  for fail in (False,True):
   with self.subTest(router_commit_failure=fail):
    events=[];c=object.__new__(Coordinator)
    c.p={'site':'lab','mode':'fresh','dns':{'publish':False}};c.manifest={'version':'test','core_sha256':'0'*64};c.package='/owned/package'
    c._validate_plan=Mock();c.stage_package=Mock();c.stage_router=Mock();c.emit=Mock()
    def server(action,**args):
     events.append(('server',action,args.get('accept',False)))
     return {'private':{},'source_count':1,'backup':'/saved','transaction':'1000000000000000000'} if action=='prepare' else {'accepted':args.get('accept',False)}
    def router(action,**args):
     events.append(('router',action,args.get('accept',False)))
     if fail and action=='verify' and args.get('accept'):raise Failure('injected_commit_failure')
     return {'accepted':args.get('accept',False)}
    c.server_action=server;c.router_action=router
    plan={'inventory':{'server':{},'router':{}},'pending_user_actions':[]}
    if fail:
     with self.assertRaisesRegex(Failure,'injected_commit_failure'):c.install(plan)
     self.assertEqual(events[-2:],[('router','restore',False),('server','restore',False)])
    else:
     result=c.install(plan);self.assertTrue(result['router']['accepted'] and result['server']['accepted'])
    self.assertLess(events.index(('server','verify',True)),events.index(('router','verify',True)))

if __name__=='__main__':unittest.main()
