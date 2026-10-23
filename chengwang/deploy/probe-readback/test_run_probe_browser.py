"""Pure orchestration contracts, never real browser or namespace acceptance."""
import ast
import contextlib
import io
import json
import pathlib
import types
import unittest
from unittest import mock

import run_probe_browser as browser
import probe_chrome_launcher as launcher


class TestBrowserOrchestration(unittest.TestCase):
    def config(self, **extra):
        return dict(schema='chengwang.probe-browser-config/v1', engine='chrome-cdp',
                    root='/tmp/chengwang-probe-readback-' + 'a' * 32,
                    chrome='/opt/google/chrome/chrome', **extra)

    def test_launcher_binds_engine_and_uuid_without_aliases(self):
        bundle = pathlib.PurePosixPath('/tmp/chengwang-probe-harness-' + 'a' * 32)
        for engine in browser.ENGINES:
            value = self.config(); value['engine'] = engine
            self.assertEqual(launcher.validate_config(value, bundle)[0], 'a' * 32)
        for change in ({'engine': 'cdp'}, {'engine': 'pw'}, {'root': '/tmp/other'},
                       {'chrome': '/opt/../SECRET'}, {'extra': True}, {'chrome': 'relative'}):
            value = self.config(); value.update(change)
            with self.assertRaises(launcher.Rejected): launcher.validate_config(value, bundle)

    def test_launcher_requires_one_exact_owned_profile_and_no_tls_bypass(self):
        profile = pathlib.PurePosixPath('/tmp/chengwang-probe-readback-' + 'a' * 32 + '/browser/chrome-profile')
        valid = ['--no-sandbox', '--user-data-dir=' + str(profile), '--headless=new']
        launcher.validate_arguments(valid, profile)
        for arguments in (valid * 2, valid + ['--user-data-dir=/SECRET'],
                          [valid[1]], [], valid + ['--headless=\0SECRET']):
            with self.assertRaises(launcher.Rejected): launcher.validate_arguments(arguments, profile)
        for flag in ('--ignore-certificate-errors', '--ignore-certificate-errors-spki-list=SECRET',
                     '--allow-insecure-localhost', '--ignore-ssl-errors', '--disable-web-security',
                     '--unsafely-treat-insecure-origin-as-secure=https://SECRET'):
            with self.assertRaises(launcher.Rejected): launcher.validate_arguments(valid + [flag], profile)

    def test_browser_cli_is_separate_and_never_adds_native_escape_flags(self):
        args = ['--source-commit', 'a' * 40, '--engine', 'playwright']
        for name in ('agent', 'server', 'driver', 'output-dir', 'web-dir', 'fonts-dir', 'node', 'chrome'):
            args.extend(['--' + name, '/private/' + name])
        with mock.patch.object(browser.N, 'checked_path', side_effect=lambda path, *_: pathlib.Path(path)):
            self.assertEqual(browser.arguments(args).engine, 'playwright')
            for flag in ('--insecure', '--target-ip', '--proxy', '--go-build', '--home'):
                with self.assertRaises(browser.N.Failure): browser.arguments(args + [flag, 'SECRET'])

    def test_cli_failures_are_fixed_and_do_not_print_private_arguments(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            self.assertEqual(browser.main(['--unknown-SECRET', '/private/SECRET']), 1)
        self.assertIn('raw_input_suppressed=true', stream.getvalue())
        self.assertNotIn('SECRET', stream.getvalue())

    def test_original_default_hooks_are_noops_and_entrypoint_remains_runner(self):
        lab = object.__new__(browser.N.Lab); lab.bundle = pathlib.Path('/private/bundle')
        self.assertEqual(lab.role_entrypoint(), lab.bundle / 'runner')
        self.assertIsNone(lab.after_prepared())
        self.assertIsNone(lab.after_restarted(1, 2))
        self.assertIsNone(lab.after_expired())
        self.assertEqual(len(browser.N.EXPECTED), 22)

    def test_wrapper_entrypoint_is_truthful_not_original_runner(self):
        lab = object.__new__(browser.BrowserLab); lab.bundle = pathlib.Path('/private/bundle')
        self.assertEqual(lab.role_entrypoint(), lab.bundle / 'browser-runner')
        source = pathlib.Path(browser.__file__).read_text(encoding='utf-8')
        self.assertIn("backendSupervisorMode='WRAPPER_IMPORTS_NATIVE_HELPERS'", source)
        self.assertNotIn('N.__file__ =', source)
        self.assertNotIn('HOME=', source)

    def test_copy_rejects_writable_input_before_any_export(self):
        info = types.SimpleNamespace(st_mode=0o100666)
        with mock.patch.object(browser.N, 'stable_read', return_value=(b'input', info)), \
             mock.patch.object(browser.N, 'exclusive') as write:
            with self.assertRaises(browser.N.Failure):
                browser.copy_file(pathlib.Path('/input'), pathlib.Path('/out'), [], 'input')
        write.assert_not_called()

    def test_fresh_signal_waits_for_real_deadline_and_has_no_clock_mutation(self):
        source = ast.parse(pathlib.Path(browser.__file__).read_bytes())
        cls = next(item for item in source.body if isinstance(item, ast.ClassDef) and item.name == 'BrowserLab')
        hook = next(item for item in cls.body if isinstance(item, ast.FunctionDef) and item.name == 'after_restarted')
        text = ast.unparse(hook)
        self.assertIn('minimum - 25000000000', text)
        self.assertIn('minimum - 5000000000', text)
        self.assertIn('fresh-complete.private.json', text)
        self.assertNotIn('clock_settime', text)

    def test_launcher_actual_wait_is_required_before_exit_report(self):
        text = pathlib.Path(launcher.__file__).read_text(encoding='utf-8')
        self.assertLess(text.index('code = child.wait(timeout=330)'), text.index("'exitCode': code"))
        self.assertIn('start_new_session=True', text)
        self.assertIn('close_fds=False', text)
        self.assertIn("'HOME' not in os.environ", text)

    def test_fake_launcher_publishes_real_wait_value_not_close_command(self):
        for code in (0, 7):
            value = self.config()
            fixture = value['root']
            child = mock.Mock(pid=23)
            child.wait.return_value = code; child.poll.return_value = code
            backend = types.SimpleNamespace(
                stable_read=mock.Mock(side_effect=[(b'config', types.SimpleNamespace(st_uid=0, st_gid=10001)),
                                                  (b'\x7fELF', types.SimpleNamespace(st_uid=0, st_mode=0o100755))]),
                decode=lambda _: value, checked_path=pathlib.PurePosixPath, BASE_ENV={'PATH': '/usr/bin:/bin'},
                canonical=lambda data: json.dumps(data).encode(), publish_atomic=mock.Mock())
            error = io.StringIO()
            with mock.patch.object(launcher.sys, 'platform', 'linux'), \
                 mock.patch.object(launcher, '__file__', '/tmp/chengwang-probe-harness-' + 'a' * 32 + '/chrome-launcher'), \
                 mock.patch.object(launcher.os, 'geteuid', return_value=10001, create=True), \
                 mock.patch.object(launcher.os, 'getegid', return_value=10001, create=True), \
                 mock.patch.object(launcher.os, 'getpgid', return_value=23, create=True), \
                 mock.patch.object(launcher.os, 'getsid', return_value=23, create=True), \
                 mock.patch.dict(launcher.os.environ, {}, clear=True), \
                 mock.patch.object(launcher, 'native_module', return_value=backend), \
                 mock.patch.object(launcher, 'validate_config', return_value=('a' * 32, pathlib.PurePosixPath(fixture))), \
                 mock.patch.object(launcher, 'start_ticks', return_value=45), \
                 mock.patch.object(launcher.signal, 'signal'), \
                 mock.patch.object(launcher.subprocess, 'Popen', return_value=child) as launch, \
                 contextlib.redirect_stderr(error):
                result = launcher.main(['--no-sandbox', '--user-data-dir=' + fixture + '/browser/chrome-profile'])
            self.assertEqual(result, 0 if code == 0 else 1)
            observed = json.loads(backend.publish_atomic.call_args_list[-1].args[1])
            self.assertEqual(observed['exitCode'], code)
            self.assertIs(observed['forced'], False)
            child.wait.assert_called_once_with(timeout=330)
            self.assertNotIn('HOME', launch.call_args.kwargs['env'])
            self.assertIn('XDG_DATA_HOME', launch.call_args.kwargs['env'])

    def test_atomic_handoff_uses_complete_pending_and_kernel_noreplace(self):
        rename = mock.Mock(return_value=0)
        events = []
        rename.side_effect = lambda *_: events.append('rename') or 0
        with mock.patch.object(browser.N.sys, 'platform', 'linux'), \
             mock.patch.object(browser.N, 'exclusive', side_effect=lambda *_: events.append('write-fsync')), \
             mock.patch.object(browser.N.ctypes, 'CDLL', return_value=types.SimpleNamespace(renameat2=rename)), \
             mock.patch.object(browser.N.pathlib.Path, 'exists', return_value=False):
            browser.N.publish_atomic(pathlib.Path('/private/signal'), b'{}', 0o444)
        self.assertEqual(events, ['write-fsync', 'rename'])
        self.assertEqual(rename.call_args.args[-1], 1)  # RENAME_NOREPLACE

    def test_failed_atomic_publish_never_overwrites_destination(self):
        rename = mock.Mock(return_value=-1)
        with mock.patch.object(browser.N.sys, 'platform', 'linux'), \
             mock.patch.object(browser.N, 'exclusive'), \
             mock.patch.object(browser.N.ctypes, 'CDLL', return_value=types.SimpleNamespace(renameat2=rename)), \
             mock.patch.object(browser.N.pathlib.Path, 'exists', return_value=True), \
             mock.patch.object(browser.N.pathlib.Path, 'unlink') as remove:
            with self.assertRaises(browser.N.Failure): browser.N.publish_atomic(pathlib.Path('/private/signal'), b'{}')
        remove.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
