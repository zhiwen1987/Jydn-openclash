"""Pure descriptor/export contracts, never execution of a namespace or browser."""
import ast
import json
import pathlib
import stat
import types
import unittest
from unittest import mock

import run_probe_browser as R


class RequestBindingRunnerContracts(unittest.TestCase):
    def check(self, value='7', **changes):
        bundle = pathlib.Path('/tmp/chengwang-probe-harness-' + 'a' * 32)
        info = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_size=0)
        info.update(changes)
        with mock.patch.dict(R.os.environ, {R.BINDING_FD_ENV: value}, clear=True), \
             mock.patch.object(R.os, 'fstat', return_value=types.SimpleNamespace(**info)), \
             mock.patch.object(R.os, 'readlink', return_value=str(bundle / 'logs/request-binding.private')), \
             mock.patch.object(R.os, 'set_inheritable') as inherit:
            result = R.binding_descriptor(bundle)
            inherit.assert_called_once_with(7, True)
            return result

    def test_01_exact_owned_descriptor_is_inherited(self):
        self.assertEqual(self.check(), 7)

    def test_02_invalid_descriptor_numbers_rejected(self):
        for value in ('', '0', '1', '2', '1024', '-7', '+7', '07', '7.0', ' 7', 'SECRET'):
            with self.subTest(value=value), self.assertRaises(R.N.Failure):
                self.check(value)

    def test_03_wrong_type_owner_or_mode_rejected(self):
        for changes in (dict(st_mode=stat.S_IFIFO | 0o600), dict(st_mode=stat.S_IFREG | 0o640),
                        dict(st_uid=10001), dict(st_gid=10001)):
            with self.subTest(changes=changes), self.assertRaises(R.N.Failure):
                self.check(**changes)

    def test_04_hardlinked_descriptor_rejected(self):
        with self.assertRaises(R.N.Failure):
            self.check(st_nlink=2)

    def test_05_prepopulated_descriptor_rejected(self):
        with self.assertRaises(R.N.Failure):
            self.check(st_size=1)

    def test_06_wrong_exact_descriptor_path_rejected(self):
        original = R.os.readlink
        with mock.patch.object(R.os, 'readlink', side_effect=lambda _path: '/private/SECRET'):
            # check() sets a nested readlink stub; exercise the helper directly.
            bundle = pathlib.Path('/tmp/chengwang-probe-harness-' + 'a' * 32)
            info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_size=0)
            with mock.patch.dict(R.os.environ, {R.BINDING_FD_ENV: '7'}, clear=True), \
                 mock.patch.object(R.os, 'fstat', return_value=info), \
                 self.assertRaises(R.N.Failure):
                R.binding_descriptor(bundle)
        self.assertIs(R.os.readlink, original)

    def test_07_source_keeps_budgets_and_fd_pass_explicit(self):
        source = pathlib.Path(R.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'Popen'
                 and any(keyword.arg == 'pass_fds' for keyword in node.keywords)]
        self.assertEqual(len(calls), 1)
        self.assertEqual(R.STATUS_DIAGNOSTICS.MAX_LOG_BYTES, 329728)
        self.assertEqual(R.BROWSER_IDENTITY.MAX_LOG, 329728)
        self.assertEqual(len(R.N.EXPECTED), 22)
        self.assertIn("environment[BINDING_FD_ENV] = str(binding_descriptor(bundle))", source)
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW", source)

    def test_08_export_is_separate_and_bound_to_old_original_bytes(self):
        bundle, output = pathlib.Path('/private/bundle'), pathlib.Path('/public/lab')
        helper = types.SimpleNamespace(MAX_BYTES=524288, project=mock.Mock(return_value=dict(schema='synthetic')))
        old = b'{"syntheticOld":true}\n'
        def stable(path, *_args):
            return (old if path.name == 'status-diagnostic.json' else b'SYNTHETIC_TRACE'), None
        with mock.patch.object(pathlib.Path, 'exists', return_value=True), \
             mock.patch.object(R, 'load_request_binding', return_value=helper), \
             mock.patch.object(R.N, 'stable_read', side_effect=stable), \
             mock.patch.object(R.N, 'exclusive') as exclusive:
            R.public_request_binding(bundle, output, 'a' * 40, 'chrome-cdp', 'b' * 32)
        helper.project.assert_called_once_with(b'SYNTHETIC_TRACE')
        path, raw = exclusive.call_args.args
        self.assertEqual(path, output / 'request-binding.json')
        value = json.loads(raw)
        self.assertEqual(value['oldDiagnosticSHA256'], R.N.sha(old))
        self.assertEqual(value['sourceCommit'], 'a' * 40)
        self.assertEqual(value['fixtureId'], 'b' * 32)
        self.assertNotIn('SYNTHETIC_TRACE', raw.decode())


if __name__ == '__main__':
    unittest.main(verbosity=2)
