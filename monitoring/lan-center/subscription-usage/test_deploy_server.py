import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('deploy_server',Path(__file__).with_name('deploy_server.py'))
deploy=importlib.util.module_from_spec(spec);spec.loader.exec_module(deploy)


class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.receipt=self.root/'backup';self.receipt.mkdir()
        self.wrapper=self.root/'subscription-controller.py';self.wrapper.write_bytes(b'old wrapper')
        self.state=self.root/'state.json';self.state.write_text(json.dumps({'container_id':'fixed','manifest':{'payload_files':{'payload/center/subscription-controller.py':deploy.sha(self.wrapper)}}}))
        self.control=self.root/'data';self.code=self.control/'subscription-usage/code'
        for name,value in [('WRAPPER',self.wrapper),('STATE',self.state),('CONTROL',self.control),('CODE',self.code)]:
            p=patch.object(deploy,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(deploy,'identity',return_value={'id':'fixed'});p.start();self.addCleanup(p.stop)
        p=patch.object(deploy,'restart_subscription');self.restart=p.start();self.addCleanup(p.stop)

    def prepare(self):
        bundle={str(self.wrapper):base64.b64encode(b'new wrapper').decode(),str(self.code/'usage_ui.js'):base64.b64encode(b'new UI').decode()}
        deploy.prepare(self.receipt,bundle)
        return json.loads((self.receipt/'usage-journal.json').read_text())

    def install_staged(self,j):
        for path,item in j['files'].items():deploy.atomic(path,Path(item['stage']).read_bytes(),inplace=Path(path)==self.wrapper)

    def test_roundtrip_preserves_bind_inode_and_removes_only_owned_new_code(self):
        before=self.wrapper.stat().st_ino;state=self.state.read_bytes();j=self.prepare();self.install_staged(j)
        self.assertEqual(self.wrapper.stat().st_ino,before)
        self.assertTrue(deploy.rollback(self.receipt)['restored'])
        self.assertEqual(self.wrapper.read_bytes(),b'old wrapper');self.assertEqual(self.state.read_bytes(),state)
        self.assertFalse((self.code/'usage_ui.js').exists());self.restart.assert_called_once()

    def test_later_foreign_edit_prevents_entire_rollback(self):
        j=self.prepare();self.install_staged(j);self.state.write_bytes(b'foreign edit')
        with self.assertRaisesRegex(ValueError,'later_edit'):deploy.rollback(self.receipt)
        self.assertEqual(self.wrapper.read_bytes(),b'new wrapper');self.restart.assert_not_called()

    def test_corrupt_backup_refused_before_any_write(self):
        j=self.prepare();self.install_staged(j);Path(j['files'][str(self.wrapper)]['backup']).write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'backup_corrupt'):deploy.rollback(self.receipt)
        self.restart.assert_not_called()

    def test_unknown_target_refused(self):
        with self.assertRaisesRegex(AssertionError,'target_not_allowed'):
            deploy.prepare(self.receipt,{str(self.root/'foreign.py'):base64.b64encode(b'never').decode()})


if __name__=='__main__':unittest.main()
