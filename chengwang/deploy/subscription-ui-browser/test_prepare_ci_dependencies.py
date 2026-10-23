"""Synthetic CPU fixtures only: no apt, npm, sudo, browser or subprocess executes."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import prepare_ci_dependencies as D

COMMIT = 'a' * 40
PLATFORM = dict(githubActions=True, runnerOS='Linux', system='Linux', ubuntu='24.04', architecture='amd64')
SOURCES = [dict(path='/etc/apt/sources.list.d/ubuntu.sources', bytes=10, sha256='b' * 64)]


class PrepareDependencyTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, *, platform=None, sources=None, execute=None, metadata=None):
        with tempfile.TemporaryDirectory(prefix='chengwang-dependency-unit-') as directory:
            reports = Path(directory).resolve()
            reports.chmod(0o700)
            calls = []

            def successful(argv, timeout):
                calls.append((argv, timeout))
                if '/usr/bin/apt-get' in argv:
                    raw = b'synthetic package acquisition output\n'
                elif argv[0] == '/usr/bin/fc-match':
                    style = 'Bold' if 'style=Bold:' in argv[-1] else 'Regular'
                    path = dict(D.FONTS)[style]
                    raw = ('Noto Sans CJK SC\t' + style + '\t' + path + '\n').encode()
                elif argv[1] == '-S':
                    raw = ('fonts-noto-cjk: ' + argv[-1] + '\n').encode()
                else:
                    raw = b'fonts-noto-cjk\tinstall ok installed\t1:20230817+repack1-3\nlibnss3-tools:amd64\tinstall ok installed\t2:3.98-1ubuntu0.3\n'
                result = (0, raw, False, 3, False)
                return execute(argv, timeout, result, len(calls)) if execute else result

            def system_metadata(path, maximum, **kwargs):
                self.assertTrue(kwargs.get('system_owned'))
                if metadata:
                    metadata(path)
                return b'synthetic binary', dict(path=path, bytes=16, sha256='c' * 64, uid=0, gid=0,
                                                 mode=0o755 if path == '/usr/bin/certutil' else 0o644)

            # Windows cannot enforce chmod0700; this is explicitly a mocked
            # filesystem boundary, not evidence of a real Linux private directory.
            original_mode = stat.S_IMODE
            mode = lambda bits: 0o700 if stat.S_ISDIR(bits) else original_mode(bits)
            with patch.object(D, 'platform_readback', return_value=PLATFORM if platform is None else platform), \
                 patch.object(D, 'source_inputs', return_value=[dict(path=p, bytes=10, sha256='d' * 64) for p in D.INPUTS]), \
                 patch.object(D, 'sources_snapshot', side_effect=sources or [SOURCES, SOURCES]), \
                 patch.object(D, 'read_file', side_effect=system_metadata), \
                 patch.object(D.stat, 'S_IMODE', side_effect=mode), \
                 patch.object(D.subprocess, 'Popen', side_effect=AssertionError('a real subprocess is forbidden')):
                yield reports, calls, successful

    def test_import_is_pure_and_never_starts_a_process(self):
        with patch.object(D.subprocess, 'Popen', side_effect=AssertionError('process forbidden')):
            spec = importlib.util.spec_from_file_location('ci_dependency_pure_import', D.__file__)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(module.phase_argv('UPDATE'), D.phase_argv('UPDATE'))

    def test_fixed_apt_commands_use_root_timeout_and_only_closed_packages(self):
        for stage, duration in [('UPDATE', '120s'), ('INSTALL', '240s')]:
            argv = D.phase_argv(stage)
            self.assertEqual(argv[:10], ['/usr/bin/sudo', '--non-interactive', '/usr/bin/timeout', '--signal=TERM',
                '--kill-after=15s', duration, '/usr/bin/env', 'DEBIAN_FRONTEND=noninteractive', 'LC_ALL=C', '/usr/bin/apt-get'])
            self.assertEqual(argv[10:16], ['-o', 'Acquire::Retries=1', '-o', 'Acquire::http::Timeout=15', '-o', 'Acquire::https::Timeout=15'])
            self.assertNotIn('--allow-unauthenticated', argv)
            self.assertNotIn('upgrade', argv)
            self.assertFalse(any('Dir::' in value or 'trusted=' in value or 'Verify-Peer=false' in value for value in argv))
        self.assertEqual(D.phase_argv('UPDATE')[16:], ['-o', 'APT::Update::Error-Mode=any', 'update'])
        self.assertEqual(D.phase_argv('INSTALL')[16:], ['install', '-y', '--no-install-recommends', *D.PACKAGES])
        with self.assertRaises(ValueError):
            D.phase_argv('UPGRADE')
        # Pure fake: EOF arrives before process termination. The deadline still
        # owns the child and its timed wait/kill path must actually be joined.
        process, selector = MagicMock(), MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = [D.subprocess.TimeoutExpired('fake', 2), -9, -9]
        selector.__enter__.return_value = selector
        registered = {7: object()}
        selector.get_map.side_effect = lambda: registered
        selector.select.return_value = [(SimpleNamespace(fileobj=process.stdout), None)]
        selector.unregister.side_effect = lambda stream: registered.clear()
        with patch.object(D.subprocess, 'Popen', return_value=process), \
             patch.object(D.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(D.os, 'read', return_value=b''), \
             patch.object(D.time, 'monotonic', side_effect=[0, 0, 2, 3]):
            result = D.invoke(['synthetic-no-execution'], 1)
        self.assertEqual(result, (-9, b'', True, 3000, False))
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 3)

    def test_wrong_ci_platform_fails_without_any_command_or_fabricated_readback(self):
        with self.fixture(platform={**PLATFORM, 'githubActions': False}) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'PLATFORM')
            self.assertEqual(calls, [])
            self.assertEqual([row['executed'] for row in result['commands']], [False, False])
            self.assertTrue(all(row['exitCode'] is None and row['elapsedMilliseconds'] is None for row in result['commands']))
            self.assertEqual(result['packages'], [])

    def test_update_failure_does_not_attempt_install_or_readback(self):
        with self.fixture(execute=lambda a, t, r, n: (100, b'failed\n', False, 4, False)) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['outcome'], 'FAIL')
            self.assertEqual(result['failureStage'], 'UPDATE')
            self.assertEqual(len(calls), 1)
            self.assertFalse(result['commands'][1]['executed'])
        def interrupted(*_args):
            raise RuntimeError('synthetic collector interruption')
        with self.fixture(execute=interrupted) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['outcome'], 'FAIL')
            self.assertTrue(result['commands'][0]['executed'])
            self.assertIsNone(result['commands'][0]['exitCode'])
            self.assertFalse(result['commands'][1]['executed'])

    def test_update_timeout_124_is_explicit_without_an_outer_retry(self):
        with self.fixture(execute=lambda a, t, r, n: (124, b'timed out\n', True, 120000, False)) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(len(calls), 1)
            self.assertTrue(result['commands'][0]['timedOut'])
            self.assertEqual(result['commands'][0]['exitCode'], 124)

    def test_install_kill_137_stops_before_readback(self):
        with self.fixture(execute=lambda a, t, r, n: (137, b'killed\n', True, 255000, False) if n == 2 else r) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'INSTALL')
            self.assertEqual(len(calls), 2)
            self.assertFalse(result['readbackComplete'])
            self.assertIsNone(result['certutil'])

    def test_oversize_log_is_bounded_marked_and_fails_closed(self):
        with self.fixture(execute=lambda a, t, r, n: (0, b'x' * (D.MAX_LOG + 1), False, 1, False)) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['outcome'], 'FAIL')
            self.assertEqual(len(calls), 1)
            self.assertEqual((reports / D.LOG_NAMES[0]).stat().st_size, D.MAX_LOG)
            self.assertTrue(result['logs'][0]['truncated'])

    def test_package_partial_status_version_and_duplicate_rows_are_rejected(self):
        for raw in [b'fonts-noto-cjk\tinstall ok installed\t1\n',
                    b'fonts-noto-cjk\tdeinstall ok config-files\t1\nlibnss3-tools\tinstall ok installed\t1\n',
                    b'fonts-noto-cjk\tinstall ok installed\tsecret\nlibnss3-tools\tinstall ok installed\t1\n',
                    b'fonts-noto-cjk\tinstall ok installed\t1\nfonts-noto-cjk\tinstall ok installed\t1\n']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                D.parse_packages(raw)

    def test_missing_or_unsafe_certutil_is_not_declared_usable(self):
        def reject(path):
            if path == '/usr/bin/certutil':
                raise ValueError('synthetic unsafe file')
        with self.fixture(metadata=reject) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'CERTUTIL')
            self.assertIsNone(result['certutil'])
            self.assertEqual(len(calls), 3)

    def test_regular_font_fallback_is_rejected_even_when_fc_match_returns_zero(self):
        with self.fixture(execute=lambda a, t, r, n: (0, b'DejaVu Sans\tBook\t/fallback.ttf\n', False, 1, False) if n == 4 else r) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'FONT_REGULAR')
            self.assertEqual(result['fonts'], [])
            self.assertEqual(len(calls), 4)

    def test_bold_font_failure_retains_only_the_real_regular_partial_readback(self):
        with self.fixture(execute=lambda a, t, r, n: (1, b'font unavailable\n', False, 2, False) if n == 6 else r) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'FONT_BOLD')
            self.assertEqual([font['style'] for font in result['fonts']], ['Regular'])
            self.assertFalse(result['readbackComplete'])

    def test_font_package_ownership_mismatch_fails_without_inventing_a_font(self):
        with self.fixture(execute=lambda a, t, r, n: (0, b'other-package: /unexpected\n', False, 1, False) if n == 5 else r) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'OWNER_REGULAR')
            self.assertEqual(result['fonts'], [])

    def test_source_configuration_mutation_is_reported_and_rejects_otherwise_good_readback(self):
        changed = [{**SOURCES[0], 'sha256': 'e' * 64}]
        with self.fixture(sources=[SOURCES, changed]) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['outcome'], 'FAIL')
            self.assertEqual(result['failureStage'], 'SOURCES_AFTER')
            self.assertTrue(result['sourceConfigurationModified'])

    def test_existing_report_or_log_is_never_overwritten_or_used_as_a_target(self):
        for name in [*D.LOG_NAMES, 'ci-dependencies.json']:
            with self.fixture() as (reports, calls, run):
                (reports / name).write_bytes(b'original')
                with self.assertRaises(ValueError):
                    D.prepare(reports, COMMIT, execute=run)
                self.assertEqual((reports / name).read_bytes(), b'original')
                self.assertEqual(calls, [])

    def test_success_requires_all_real_readback_shapes_and_hashes_three_original_logs(self):
        with self.fixture() as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['outcome'], 'PASS')
            self.assertEqual(result['failureStage'], 'NONE')
            self.assertTrue(result['readbackComplete'])
            self.assertFalse(result['sourceConfigurationModified'])
            self.assertEqual([row['name'] for row in result['packages']], D.PACKAGES)
            self.assertEqual([row['style'] for row in result['fonts']], ['Regular', 'Bold'])
            self.assertEqual(len(calls), 7)
            self.assertEqual([timeout for _, timeout in calls], [140, 260, 5, 5, 5, 5, 5])
            self.assertEqual(result, json.loads((reports / 'ci-dependencies.json').read_bytes()))
            for row in result['logs']:
                raw = (reports / row['path']).read_bytes()
                self.assertEqual((row['bytes'], row['sha256']), (len(raw), D.sha(raw)))

    def test_file_reader_refuses_oversize_directory_and_hardlink_targets(self):
        with tempfile.TemporaryDirectory(prefix='chengwang-dependency-file-unit-') as directory:
            path = Path(directory) / 'file'
            path.write_bytes(b'fixture')
            raw, metadata = D.read_file(path, 100)
            self.assertEqual(raw, b'fixture')
            self.assertEqual(metadata['sha256'], D.sha(raw))
            with self.assertRaises(ValueError):
                D.read_file(path, 2)
            with self.assertRaises(ValueError):
                D.read_file(Path(directory), 100)
            os.link(path, Path(directory) / 'hardlink')
            with self.assertRaises(ValueError):
                D.read_file(path, 100)


if __name__ == '__main__':
    unittest.main(verbosity=2)
