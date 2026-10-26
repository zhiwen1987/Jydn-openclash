"""Failure before router changes must still release the prepared server state."""
import sys,unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stack.coordinator import Coordinator
from stack.model import Failure

class PreflightTests(unittest.TestCase):
 def test_empty_published_dns_rolls_back_before_router_prepare(self):
  c=object.__new__(Coordinator)
  c.p={'mode':'fresh','dns':{'publish':True}}
  c.manifest={'version':'test'};c.package='/owned/package'
  c._validate_plan=Mock();c.stage_package=Mock();c.emit=Mock()
  c.server_action=Mock(side_effect=[{'private':{},'source_count':0}, {'restored':True}])
  c.router_action=Mock()
  with self.assertRaisesRegex(Failure,'空订阅'):
   c.install({'inventory':{'server':{}}})
  self.assertEqual([call.args[0] for call in c.server_action.call_args_list],['prepare','restore'])
  c.router_action.assert_not_called()

if __name__=='__main__':unittest.main()
