"""Pure runner contract checks, not Linux isolation or backend acceptance."""
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import io
import json
import pathlib
import stat
import tempfile
import types
import unittest
from unittest import mock

import run_probe_readback as runner


class TestRunnerContract(unittest.TestCase):
    def test_exact_twenty_two_public_files_and_backend_only_boundary(self):
        expected = {
            'prepare.json', 'collect-first.json', 'collect-final.json', 'verify-fresh.json',
            'verify-restarted.json', 'verify-expired.json', 'api-fresh-status.json',
            'api-fresh-details.json', 'api-restarted-status.json', 'api-restarted-details.json',
            'api-expired-status.json', 'api-expired-details.json', 'wire-ready.json',
            'wire-events.jsonl', 'wire-stopped.json', 'source-metadata-before.json',
            'source-metadata-after.json', 'isolation.json', 'processes.json', 'runtime.json',
            'cleanup.json', 'outcome.json',
        }
        self.assertEqual(runner.EXPECTED, {runner.PREFIX + name for name in expected})
        options = types.SimpleNamespace(source_commit='a' * 40, fixture_id='b' * 32)
        value = runner.base('outcome', options)
        self.assertEqual(value['acceptanceScope'], 'NATIVE_BACKEND_ONLY')
        self.assertIs(value['browserE2EProven'], False)
        self.assertEqual(value['authorization'], 'BLOCKED')
        self.assertIs(value['production'], False)
        self.assertIs(value['deviceActionsExecuted'], False)

    def test_cli_has_no_build_network_or_profile_escape_flags(self):
        with mock.patch.object(runner, 'checked_path', side_effect=pathlib.Path):
            result = runner.arguments(['--agent', '/private/agent', '--server', '/private/server',
                                       '--driver', '/private/driver', '--source-commit', 'a' * 40,
                                       '--output-dir', '/private/output'])
        self.assertEqual(result.source_commit, 'a' * 40)
        for flag in ('--go-build', '--insecure', '--target-ip', '--proxy', '--allow-loopback', '--browser'):
            with self.assertRaises(runner.Failure):
                runner.arguments([flag, 'SECRET'])

    def test_cli_errors_never_echo_raw_arguments(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(runner.Failure):
            runner.arguments(['--unknown-SECRET', '/secret/path'])
        self.assertEqual(output.getvalue(), '')
        for commit in ('A' * 40, 'a' * 39, '../SECRET'):
            with self.assertRaises(runner.Failure):
                runner.arguments(['--source-commit', commit])

    def test_wall_clock_parser_preserves_all_nine_decimal_places(self):
        self.assertEqual(runner.timestamp_ns('1970-01-01T00:00:00.000000001Z'), 1)
        self.assertEqual(runner.timestamp_ns('1970-01-01T00:00:01.123456789Z'), 1123456789)
        self.assertEqual(runner.timestamp_ns('1970-01-01T00:00:01.1Z'), 1100000000)
        self.assertEqual(runner.timestamp_ns('1970-01-01T00:00:01Z'), 1000000000)
        for invalid in ('1970-01-01T00:00:00.1234567890Z', '1970-01-01T00:00:00+00:00', 'SECRET'):
            with self.assertRaises(runner.Failure):
                runner.timestamp_ns(invalid)

    def test_expiry_bounds_include_every_result_and_earlier_layer(self):
        files = []
        for index in range(6):
            result = {'expiresAt': '1970-01-01T00:02:' + str(10 + index) + 'Z',
                      'layers': {'dns': {'expiresAt': '1970-01-01T00:02:09.000000001Z'},
                                 'business': {'expiresAt': '1970-01-01T00:02:14Z'}}}
            raw = json.dumps({'result': result}).encode()
            files.append({'raw': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()})
        report = json.dumps({'spoolSegments': files}).encode()
        with mock.patch.object(runner, 'stable_read', return_value=(report, None)):
            self.assertEqual(runner.expiry_bounds(pathlib.Path('/unused')), (129000000001, 135000000000))
        files[0]['sha256'] = '0' * 64
        with mock.patch.object(runner, 'stable_read', return_value=(json.dumps({'spoolSegments': files}).encode(), None)):
            with self.assertRaises(runner.Failure):
                runner.expiry_bounds(pathlib.Path('/unused'))

    def test_snapshot_digest_matches_go_directory_mode_and_nul_grammar(self):
        entries = [dict(path='spool/.', bytes=0, modeGo=2147484096, uid=10001,
                        gid=10001, nlink=3, sha256='directory'),
                   dict(path='ledger/.probe-start-ledger.lock', bytes=0, modeGo=384,
                        uid=10001, gid=10001, nlink=1, sha256='e3b0c442')]
        independent = (b'ledger/.probe-start-ledger.lock\x000\x00384\x0010001\x0010001\x001\x00e3b0c442\x00'
                       b'spool/.\x000\x002147484096\x0010001\x0010001\x003\x00directory\x00')
        self.assertEqual(runner.snapshot_digest(entries), 'sha256:' + hashlib.sha256(independent).hexdigest())
        changed = [dict(item) for item in entries]
        changed[0]['modeGo'] = 448
        self.assertNotEqual(runner.snapshot_digest(changed), runner.snapshot_digest(entries))

    def test_json_rejects_duplicate_keys_trailing_data_and_nonfinite(self):
        self.assertEqual(runner.decode(b'{"a":[1,true,null]}'), {'a': [1, True, None]})
        for raw in (b'{"a":1,"a":2}', b'{}{}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises((runner.Failure, ValueError)):
                runner.decode(raw)

    def test_closed_failure_projection_never_calls_exception_string(self):
        class Hostile:
            def __str__(self):
                raise AssertionError('must-not-stringify')
        self.assertEqual(runner.safe_failure(runner.Failure('SIGNAL'), 'HOST_BEFORE'), ('HOST_BEFORE', 'SIGNAL'))
        for error in (ValueError('SECRET/private/path'), runner.Failure('SECRET'), runner.Failure(Hostile())):
            self.assertEqual(runner.safe_failure(error, 'SECRET'), ('INTERNAL', 'UNEXPECTED'))
        valid = b'PROBE_READBACK_RUNNER=FAIL phase=WIRE_START code=WIRE_READY raw_input_suppressed=true\n'
        self.assertEqual(runner.private_diagnostic(valid), ('WIRE_START', 'WIRE_READY'))
        for raw in (valid + valid, valid.replace(b'WIRE_READY', b'SECRET'), b'SECRET/path', None, b'x' * 65537):
            self.assertIsNone(runner.private_diagnostic(raw))

    def test_all_exec_environments_are_closed_not_inherited(self):
        self.assertFalse(any(key.startswith(('CHENGWANG_', 'SSL_', 'HTTP_', 'HTTPS_', 'ALL_'))
                             or key.lower().endswith('_proxy') for key in runner.BASE_ENV))
        source = pathlib.Path(runner.__file__).read_text()
        self.assertNotIn('os.environ.copy', source)
        self.assertNotIn('shell=True', source)
        self.assertIn("'--no-new-privs'", source)
        self.assertIn("'--bounding-set=-all'", source)
        self.assertIn("'--clear-groups'", source)

    def test_stable_read_and_output_exclusive_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix='probe-runner-contract-') as temporary:
            path = pathlib.Path(temporary) / 'evidence.json'
            # Windows has no fchmod; this is only a synthetic O_EXCL/data test,
            # not a POSIX-permission acceptance or a production fallback.
            permissions = (contextlib.nullcontext() if hasattr(runner.os, 'fchmod')
                           else mock.patch.object(runner.os, 'fchmod', create=True))
            with permissions:
                runner.exclusive(path, b'{"safe":true}\n')
            if runner.sys.platform.startswith('linux'):
                raw, before = runner.stable_read(path)
            else:
                # Windows FD/path file identities are not the Linux contract.
                # Exercise only the public byte/O_EXCL portion here.
                raw, before = path.read_bytes(), path.stat()
            self.assertEqual(raw, b'{"safe":true}\n')
            self.assertTrue(stat.S_ISREG(before.st_mode))
            with self.assertRaises(FileExistsError):
                runner.exclusive(path, b'SECRET')
            self.assertEqual(path.read_bytes(), raw)

    def test_nonregular_descriptor_is_rejected_before_any_read(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_nlink=1, st_size=0)
        with mock.patch.object(runner.os, 'open', return_value=73), \
                mock.patch.object(runner.os, 'fstat', return_value=info), \
                mock.patch.object(runner.os, 'close') as close, \
                mock.patch.object(runner.os, 'read') as read:
            with self.assertRaises(runner.Failure):
                runner.stable_read('/unopened-fixture')
            read.assert_not_called()
            close.assert_called_once_with(73)
        # Namespace-wide LISTEN is not proof of ownership. Pure proc projection
        # counterexample: an unrelated inode must never satisfy API readiness.
        row = '0: 0100007F:45C5 00000000:0000 0A 0:0 00:0 0 10001 0 77\n'
        with mock.patch.object(runner.pathlib.Path, 'iterdir', return_value=[pathlib.Path('/proc/11/fd/3')]), \
                mock.patch.object(runner.pathlib.Path, 'read_text', return_value='header\n' + row), \
                mock.patch.object(runner.os, 'readlink', return_value='socket:[55]'):
            self.assertFalse(runner.listening(11, 17861))
        with mock.patch.object(runner.pathlib.Path, 'iterdir', return_value=[pathlib.Path('/proc/11/fd/3')]), \
                mock.patch.object(runner.pathlib.Path, 'read_text', return_value='header\n' + row), \
                mock.patch.object(runner.os, 'readlink', return_value='socket:[77]'):
            self.assertTrue(runner.listening(11, 17861))

    def test_import_has_no_live_namespace_or_binary_execution(self):
        tree = ast.parse(pathlib.Path(runner.__file__).read_bytes())
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                self.fail('unexpected-top-level-execution')
        self.assertEqual(len([n for n in ast.walk(tree) if isinstance(n, ast.Call)
                              and isinstance(n.func, ast.Name) and n.func.id == 'outer']), 1)
        self.assertTrue(runner.ROOT_RE.fullmatch('/tmp/chengwang-probe-readback-' + 'a' * 32))
        self.assertFalse(runner.ROOT_RE.fullmatch('/tmp/chengwang-probe-readback-' + 'a' * 32 + '/..'))


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestRunnerContract)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != 12 or result.skipped:
        return 1
    print('PROBE_READBACK_RUNNER_TESTS=PASS tests=12 skipped=0 synthetic_only=true')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
