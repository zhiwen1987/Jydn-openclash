import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import install_sync as deploy

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.receipt=self.root/'receipt';self.receipt.mkdir()
        self.target=self.root/'owned-service';self.target.write_bytes(b'new')
        self.backup=self.receipt/'before';self.backup.write_bytes(b'old')
        self.patch=patch.object(deploy,'ALLOWED',{self.target});self.patch.start();self.addCleanup(self.patch.stop)
        self.item={'before':deploy.sha(self.backup),'after':deploy.sha(self.target),'backup':str(self.backup),'mode':0o600}
        (self.receipt/'sync-journal.json').write_text(json.dumps({'files':{str(self.target):self.item}}))
    def test_rollback_stops_only_owned_timer_and_preserves_information_and_other_files(self):
        manual=self.root/'information-sources.json';manual.write_bytes(b'operator additions')
        other=self.root/'foreign.timer';other.write_bytes(b'foreign')
        with patch.object(deploy,'system') as system,patch.object(deploy.subprocess,'run') as run:
            deploy.rollback(self.receipt)
        self.assertEqual(self.target.read_bytes(),b'old');self.assertEqual(manual.read_bytes(),b'operator additions');self.assertEqual(other.read_bytes(),b'foreign')
        self.assertEqual(run.call_args_list[0].args[0],['systemctl','disable','--now',deploy.TIMER])
        self.assertEqual(run.call_args_list[1].args[0],['systemctl','stop',deploy.SERVICE]);system.assert_called_once_with('daemon-reload')
    def test_rollback_refuses_later_operator_edit_before_stopping_service(self):
        self.target.write_bytes(b'operator edit')
        with patch.object(deploy.subprocess,'run') as run:
            with self.assertRaises(AssertionError):deploy.rollback(self.receipt)
        run.assert_not_called();self.assertEqual(self.target.read_bytes(),b'operator edit')
    def test_corrupt_backup_refused(self):
        self.backup.write_bytes(b'corrupt')
        with self.assertRaises(AssertionError):deploy.check(self.receipt)

if __name__=='__main__':unittest.main()
