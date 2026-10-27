import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('health_deployment',Path(__file__).resolve().parents[1]/'agents/node_health.py')
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)

class RecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.receipt=self.root/'receipt';self.receipt.mkdir();self.control=self.root/'control';self.control.mkdir();self.target=self.root/'code.py';self.target.write_bytes(b'new');before=self.receipt/'before';before.write_bytes(b'old')
  self.item={'before':agent.sha(before),'after':agent.sha(self.target),'backup':str(before),'mode':0o600}
  (self.receipt/'health-journal.json').write_text(json.dumps({'container':{'id':'fixture'},'files':{str(self.target):self.item}}))
  for name,value in [('CONTROL',self.control),('RELEASE',self.root/'release')]:
   p=patch.object(agent,name,value);p.start();self.addCleanup(p.stop)
  p=patch.object(agent,'identity',return_value={'id':'fixture'});p.start();self.addCleanup(p.stop)
 def test_rollback_keeps_current_release_and_database_history(self):
  ptr=self.control/'current.json';ptr.write_bytes(b'current production release');db=self.control/'history.db';db.write_bytes(b'history after deployment')
  with patch.object(agent,'reload_workers') as reload:agent.rollback(self.receipt)
  self.assertEqual(self.target.read_bytes(),b'old');self.assertEqual(ptr.read_bytes(),b'current production release');self.assertEqual(db.read_bytes(),b'history after deployment');reload.assert_called_once()
 def test_later_operator_edit_refused_before_reload(self):
  self.target.write_bytes(b'operator edit')
  with patch.object(agent,'reload_workers') as reload:
   with self.assertRaises(AssertionError):agent.rollback(self.receipt)
  reload.assert_not_called();self.assertEqual(self.target.read_bytes(),b'operator edit')

if __name__=='__main__':unittest.main()
