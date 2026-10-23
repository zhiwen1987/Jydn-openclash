"""Pure orchestration contracts, never real browser or namespace acceptance."""
import ast
import contextlib
import io
import json
import pathlib
import types
import tempfile
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
        diagnostic = io.StringIO()
        private = (b'raw SECRET exception\nPROBE_BROWSER_DRIVER_STAGE=HOME\nPROBE_BROWSER_DRIVER_STAGE=CLOSE_DRAIN\n'
                   b'PROBE_BROWSER_DRIVER_STAGE=SECRET\n'
                   b'PROBE_BROWSER_FLOW_STAGE=FRESH_API\nPROBE_BROWSER_FLOW_STAGE=SECRET\n'
                   b'PROBE_BROWSER_PAIR_STAGE=EXPIRED_MODEL\nPROBE_BROWSER_PAIR_STAGE=SECRET\n'
                   b'PROBE_BROWSER_DRIVER_OPERATION=NETWORK\nPROBE_BROWSER_DRIVER_OPERATION=SECRET\n'
                   b'PROBE_BROWSER_NETWORK_FAILURE=PROBE_STATUS:CANCELED:ABORTED:RUNNING\n'
                   b'PROBE_BROWSER_NETWORK_FAILURE=SECRET:CANCELED:ABORTED:RUNNING\n'
                   b'PROBE_BROWSER_LAUNCH_FATAL=base/files/file.cc:123\n'
                   b'PROBE_BROWSER_LAUNCH_FATAL=base/../SECRET.cc:123\n'
                   b'PROBE_BROWSER_LAB=FAIL stage=PREWARM code=SECRET raw_input_suppressed=true\n')
        with mock.patch.object(browser.pathlib.Path, 'exists', return_value=True), \
             mock.patch.object(browser.N, 'stable_read', return_value=(private, None)), \
             contextlib.redirect_stderr(diagnostic):
            browser.public_failure_diagnostic(pathlib.Path('/private'))
        self.assertEqual(diagnostic.getvalue(), 'PROBE_BROWSER_DRIVER_STAGE=HOME\nPROBE_BROWSER_DRIVER_STAGE=CLOSE_DRAIN\nPROBE_BROWSER_FLOW_STAGE=FRESH_API\nPROBE_BROWSER_PAIR_STAGE=EXPIRED_MODEL\nPROBE_BROWSER_DRIVER_OPERATION=NETWORK\nPROBE_BROWSER_NETWORK_FAILURE=PROBE_STATUS:CANCELED:ABORTED:RUNNING\nPROBE_BROWSER_LAUNCH_FATAL=base/files/file.cc:123\n')
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'fixture'
            (root / 'browser/out').mkdir(parents=True)
            candidate = root / 'browser/out/probe-browser-cdp-fresh-status.json'
            candidate.touch()
            def read_candidate(path, *_args, **_kwargs):
                return (b'{"safe":true}' if path == candidate else b'PRIVATE_TOKEN_123'), None
            with mock.patch.object(browser.N, 'stable_read', side_effect=read_candidate), \
                 mock.patch.object(browser.N.os, 'fchmod', create=True):
                browser.preserve_failed_captures(root, pathlib.Path(directory))
                result = json.loads((pathlib.Path(directory) / 'failed-browser/failure-candidates.json').read_bytes())
                self.assertIs(result['runtimeAcceptanceProven'], False)
                self.assertIs(result['production'], False)
                self.assertEqual(len(result['files']), 1)
                with mock.patch.object(browser.N, 'stable_read', return_value=(b'PRIVATE_TOKEN_123', None)):
                    with self.assertRaises(browser.N.Failure):
                        browser.preserve_failed_captures(root, pathlib.Path(directory))
            # Enabling hidden uploads admits only this exact public manifest,
            # never profiles, .env files, links or an empty archive.
            archive = pathlib.Path(directory) / 'public'
            archive.mkdir()
            with self.assertRaises(browser.N.Failure): browser.check_public_archive(archive)
            manifest = archive / 'lab/browser/web/.vite/manifest.json'
            manifest.parent.mkdir(parents=True)
            manifest.touch()
            with self.assertRaises(browser.N.Failure): browser.check_public_archive(archive)
            with mock.patch.object(pathlib.Path, 'lstat', return_value=types.SimpleNamespace(st_mode=0o100644, st_nlink=1, st_size=2)):
                browser.check_public_archive(archive)
                secret = archive / '.env'; secret.touch()
                with self.assertRaises(browser.N.Failure): browser.check_public_archive(archive)
            secret.unlink()
            with mock.patch.object(pathlib.Path, 'is_symlink', return_value=True):
                with self.assertRaises(browser.N.Failure): browser.check_public_archive(archive)
            with mock.patch.object(pathlib.Path, 'lstat', return_value=types.SimpleNamespace(st_mode=0o100644, st_nlink=2, st_size=2)):
                with self.assertRaises(browser.N.Failure): browser.check_public_archive(archive)

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
        self.assertIn("chrome=str(bundle / 'chrome/chrome')", source)
        self.assertIn("'toolchain/chrome', executable_inputs=True", source)
        self.assertIn("os.chdir(root / 'browser')", source)
        self.assertNotIn('N.__file__ =', source)
        self.assertNotIn('HOME=', source)
        self.assertLess(source.index("here['mnt'] != init['mnt']"), source.index('temporary = browser_temporary_mount()'))
        self.assertIn("environment['TMPDIR'] = temporary", source)
        mounted = types.SimpleNamespace(st_mode=0o40700, st_uid=10001, st_gid=10001)
        with mock.patch.object(pathlib.Path, 'lstat', return_value=mounted), \
             mock.patch.object(pathlib.Path, 'is_symlink', return_value=False), \
             mock.patch.object(pathlib.Path, 'read_text', return_value='1 0 0:1 / /var/tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n'), \
             mock.patch.object(browser.N, 'command') as command, \
             mock.patch.object(browser.N, 'mount_flags', return_value=['rw', 'nosuid', 'nodev', 'noexec']):
            self.assertEqual(browser.browser_temporary_mount(), '/var/tmp')
            command.assert_called_once_with(['mount', '-t', 'tmpfs', '-o',
                'size=64m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec',
                'chengwang-probe-browser-tmp', '/var/tmp'])
            with mock.patch.object(browser.N, 'mount_flags', return_value=['rw', 'nosuid', 'nodev']):
                with self.assertRaises(browser.N.Failure):
                    browser.browser_temporary_mount()
            with mock.patch.object(pathlib.Path, 'read_text', return_value='1 0 0:1 / /var/tmp rw,nosuid,nodev,noexec - ext4 /dev/test rw\n'):
                with self.assertRaises(browser.N.Failure):
                    browser.browser_temporary_mount()
        # The longest temporary singleton suffix now fits Linux sun_path[108].
        self.assertLess(len('/var/tmp/.org.chromium.Chromium.XXXXXX/SingletonSocket'), 108)

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
        self.assertTrue(text.startswith('#!/usr/bin/python3 -I\n'))

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
                 mock.patch.dict(launcher.os.environ, {'TMPDIR': '/var/tmp'}, clear=True), \
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
            self.assertEqual(launch.call_args.kwargs['env']['TMPDIR'], '/var/tmp')
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

    def test_rejected_failure_diagnostic_cannot_skip_emergency_cleanup(self):
        for error in (browser.N.Failure('BROWSER_IDENTITY'), RecursionError('PRIVATE')):
            lab = object.__new__(browser.BrowserLab)
            lab.browser = mock.Mock()
            lab.browser.poll.return_value = None
            with mock.patch.object(lab, 'publish_launch_failure', side_effect=error), \
                 mock.patch.object(browser.N.Lab, 'emergency') as original_cleanup:
                lab.emergency()
                original_cleanup.assert_called_once()
            lab.browser.terminate.assert_called_once()
            lab.browser.wait.assert_called_once_with(timeout=15)
            lab.browser.wait.side_effect = OSError('PRIVATE')
            with mock.patch.object(lab, 'publish_launch_failure', side_effect=error), \
                 mock.patch.object(browser.N.Lab, 'emergency') as original_cleanup:
                with self.assertRaises(OSError): lab.emergency()
                original_cleanup.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
