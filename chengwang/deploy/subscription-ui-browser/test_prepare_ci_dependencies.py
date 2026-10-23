"""Synthetic CPU fixtures only: no apt, npm, sudo, browser or subprocess executes."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import prepare_ci_dependencies as D

COMMIT = 'a' * 40
PLATFORM = dict(githubActions=True, runnerOS='Linux', system='Linux', ubuntu='24.04', architecture='amd64')
SOURCES = [dict(path=D.HOST_MIRROR, bytes=D.HOST_MIRROR_SIZE, sha256=D.HOST_MIRROR_SHA),
           dict(path=D.HOST_SOURCE, bytes=D.HOST_SOURCE_SIZE, sha256=D.HOST_SOURCE_SHA)]
PRIVATE_DIRECTORY = '/tmp/chengwang-ci-apt-abcdefgh'


def private_fixture():
    def directory(path):
        return dict(path=path, uid=1001, gid=1001, mode=0o755)
    def file(path, size, root=False):
        return dict(path=path, bytes=size, sha256='f' * 64, uid=0 if root else 1001,
                    gid=0 if root else 1001, mode=0o644)
    source = file(PRIVATE_DIRECTORY + '/ubuntu.sources', D.HOST_SOURCE_SIZE + 2 *
                  (len('mirror+file:' + PRIVATE_DIRECTORY + '/mirrors.txt') - len(D.HOST_MIRROR_URI)))
    source.update(normalizedHostSHA256=D.HOST_SOURCE_SHA, replacedURIs=2)
    return dict(directory=directory(PRIVATE_DIRECTORY), source=source,
                mirrors={**file(PRIVATE_DIRECTORY + '/mirrors.txt', len(D.mirror_bytes())), 'sha256': D.sha(D.mirror_bytes())},
                parts={**directory(PRIVATE_DIRECTORY + '/sourceparts'), 'empty': True},
                keyring=file(D.KEYRING, 100, True), effectiveConfigurationChanged=True)


def synthetic_source():
    return ('# Explicitly synthetic deb822 fixture, not the real 2995-byte host file.\n'
            'Types: deb\nURIs: ' + D.HOST_MIRROR_URI + '\n'
            'Suites: noble noble-updates noble-backports\n'
            'Components: main restricted universe multiverse\nSigned-By: ' + D.KEYRING + '\n\n'
            'Types: deb\nURIs: ' + D.HOST_MIRROR_URI + '\nSuites: noble-security\n'
            'Components: main restricted universe multiverse\nSigned-By: ' + D.KEYRING + '\n').encode()


class PrepareDependencyTests(unittest.TestCase):
    @contextlib.contextmanager
    def copied_private_fixture(self, source_override=None):
        # The production profile is never configurable. Only this explicitly
        # synthetic CPU fixture substitutes its own source SHA/size and path.
        with tempfile.TemporaryDirectory(prefix='chengwang-private-copy-unit-') as directory:
            path = Path(directory).resolve()
            source = source_override if source_override is not None else synthetic_source()
            original_reader = D.read_file

            def reader(name, maximum, **kwargs):
                if str(name) == D.KEYRING:
                    return b'unit keyring', dict(path=D.KEYRING, bytes=12, sha256='c' * 64, uid=0, gid=0, mode=0o644)
                return original_reader(name, maximum)

            mode = lambda bits: 0o755 if stat.S_ISDIR(bits) else 0o644
            with patch.object(D, 'HOST_SOURCE_SIZE', len(source)), patch.object(D, 'HOST_SOURCE_SHA', D.sha(source)), \
                 patch.object(D, 'DIRECTORY_PATTERN', re.escape(str(path))), \
                 patch.object(D, 'read_file', side_effect=reader), patch.object(D.stat, 'S_IMODE', side_effect=mode):
                D.private_files(path, source)
                yield path, source

    @contextlib.contextmanager
    def fixture(self, *, platform=None, sources=None, execute=None, metadata=None, version_result=None,
                private_builder=None, private_checks=None, policy_result=None):
        with tempfile.TemporaryDirectory(prefix='chengwang-dependency-unit-') as directory:
            reports = Path(directory).resolve()
            reports.chmod(0o700)
            calls = []
            version_calls = []
            policy_calls = []

            def successful(argv, timeout):
                if argv == ['/usr/bin/apt-get', '--version']:
                    version_calls.append((argv, timeout))
                    return version_result or (0, b'apt 2.7.14 (amd64)\nSupported modules:\n', False, 2, False)
                if '/usr/bin/apt-config' in argv:
                    policy_calls.append((argv, timeout))
                    return policy_result or (0, b'', False, 1, False)
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
            successful.version_calls = version_calls
            successful.policy_calls = policy_calls

            def system_metadata(path, maximum, **kwargs):
                self.assertTrue(kwargs.get('system_owned'))
                if metadata:
                    metadata(path)
                payload = ('synthetic binary for ' + path).encode()
                return payload, dict(path=path, bytes=len(payload), sha256=D.sha(payload), uid=0, gid=0,
                                                 mode=0o755 if path == '/usr/bin/certutil' else 0o644)

            # Windows cannot enforce chmod0700; this is explicitly a mocked
            # filesystem boundary, not evidence of a real Linux private directory.
            original_mode = stat.S_IMODE
            mode = lambda bits: 0o700 if stat.S_ISDIR(bits) else original_mode(bits)
            with patch.object(D, 'platform_readback', return_value=PLATFORM if platform is None else platform), \
                 patch.object(D, 'source_inputs', return_value=[dict(path=p, bytes=10, sha256='d' * 64) for p in D.INPUTS]), \
                 patch.object(D, 'sources_snapshot', side_effect=sources or [SOURCES, SOURCES]), \
                 patch.object(D, 'read_file', side_effect=system_metadata), \
                 patch.object(D, 'create_private_sources', side_effect=private_builder or private_fixture), \
                 patch.object(D, 'private_readback', side_effect=private_checks or (lambda _path: private_fixture())), \
                 patch.object(D.stat, 'S_IMODE', side_effect=mode), \
                 patch.object(D.subprocess, 'Popen', side_effect=AssertionError('a real subprocess is forbidden')):
                yield reports, calls, successful

    def test_import_is_pure_and_never_starts_a_process(self):
        with patch.object(D.subprocess, 'Popen', side_effect=AssertionError('process forbidden')):
            spec = importlib.util.spec_from_file_location('ci_dependency_pure_import', D.__file__)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(module.phase_argv('UPDATE', PRIVATE_DIRECTORY), D.phase_argv('UPDATE', PRIVATE_DIRECTORY))

    def test_fixed_apt_commands_use_root_timeout_and_only_closed_packages(self):
        for stage, duration in [('UPDATE', '120s'), ('INSTALL', '240s')]:
            argv = D.phase_argv(stage, PRIVATE_DIRECTORY)
            self.assertEqual(argv[:12], ['/usr/bin/sudo', '--non-interactive', '/usr/bin/timeout', '--signal=TERM',
                '--kill-after=15s', duration, '/usr/bin/env', '-u', 'APT_CONFIG', 'DEBIAN_FRONTEND=noninteractive', 'LC_ALL=C', '/usr/bin/apt-get'])
            self.assertEqual(argv[12:18], ['-o', 'Acquire::Retries=1', '-o', 'Acquire::http::Timeout=15', '-o', 'Acquire::https::Timeout=15'])
            self.assertNotIn('--allow-unauthenticated', argv)
            self.assertNotIn('upgrade', argv)
            self.assertFalse(any('trusted=' in value or 'Verify-Peer=false' in value for value in argv))
            self.assertEqual(argv[18:22], ['-o', 'Dir::Etc::sourcelist=' + PRIVATE_DIRECTORY + '/ubuntu.sources',
                                         '-o', 'Dir::Etc::sourceparts=' + PRIVATE_DIRECTORY + '/sourceparts'])
            contract = json.loads(Path(D.__file__).with_name('ci-dependencies-contract.json').read_bytes())
            self.assertEqual(argv[22:48], [item for value in contract['securityOptions'] for item in ['-o', value]])
        self.assertEqual(D.phase_argv('UPDATE', PRIVATE_DIRECTORY)[48:], ['-o', 'APT::Update::Error-Mode=any', 'update'])
        self.assertEqual(D.phase_argv('INSTALL', PRIVATE_DIRECTORY)[48:], ['install', '-y', '--no-install-recommends', *D.PACKAGES])
        with self.assertRaises(ValueError):
            D.phase_argv('UPGRADE', PRIVATE_DIRECTORY)
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
            self.assertEqual(run.version_calls, [(['/usr/bin/apt-get', '--version'], 5)])
            self.assertEqual(run.policy_calls, [(D.policy_argv(PRIVATE_DIRECTORY), 5)])
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

    def test_apt_version_parser_only_accepts_bounded_ascii_amd64_header(self):
        self.assertEqual(D.parse_apt_version(b'apt 2.7.14 (amd64)\nSupported modules:\n'),
                         dict(version='2.7.14', architecture='amd64'))
        for raw in [b'', b'apt 2.7.14 (arm64)\n', b'apt 2.7.14 (amd64)\r\n',
                    b'apt unknown (amd64)\n', b'prefix apt 2.7.14 (amd64)\n',
                    b'apt 2.7.14 (amd64)\n\xff', b'apt 2.7.14 (amd64)\n' + b'x' * D.MAX_TOOLCHAIN]:
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                D.parse_apt_version(raw)

    def test_apt_version_failure_preserves_unexecuted_empty_phase_argv(self):
        with self.fixture(version_result=(124, b'version timeout\n', True, 5000, False)) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'APT_VERSION')
            self.assertIsNone(result['aptVersion'])
            self.assertIsNone(result['privateSources'])
            self.assertEqual(calls, [])
            self.assertTrue(all(row['argv'] == [] and row['executed'] is False for row in result['commands']))

    def test_private_source_preflight_failure_preserves_version_but_no_phase_argv(self):
        def reject():
            raise ValueError('synthetic host fingerprint mismatch')
        with self.fixture(private_builder=reject) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'PRIVATE_SOURCES')
            self.assertEqual(result['aptVersion']['version'], '2.7.14')
            self.assertIsNone(result['privateSources'])
            self.assertEqual(calls, [])
            self.assertTrue(all(row['argv'] == [] and row['executed'] is False for row in result['commands']))
            self.assertEqual(run.policy_calls, [])

    def test_deb822_parser_rejects_unknown_duplicate_and_continuation_fields(self):
        raw = synthetic_source()
        self.assertEqual(D.parse_ubuntu_sources(raw), 2)
        for changed in [raw + b'Trusted: yes\n', raw + b'Check-Valid-Until: no\n',
                        raw.replace(b'Types: deb\n', b'Types: deb\nTypes: deb\n', 1),
                        raw.replace(b'Suites: noble ', b' Suites: noble ', 1),
                        raw.replace(b'Signed-By: ', b'Unknown: ', 1)]:
            with self.subTest(changed=changed[:40]), self.assertRaises(ValueError):
                D.parse_ubuntu_sources(changed)

    def test_deb822_parser_rejects_wrong_suite_component_architecture_and_signer(self):
        raw = synthetic_source()
        for changed in [raw.replace(b'noble-security', b'jammy-security'),
                        raw.replace(b'noble-updates', b'noble noble-updates', 1),
                        raw.replace(b'main restricted universe multiverse', b'main universe', 1),
                        raw + b'Architectures: arm64\n',
                        raw.replace(D.KEYRING.encode(), b'/private/untrusted.gpg', 1),
                        raw.replace(D.HOST_MIRROR_URI.encode(), b'https://unapproved.invalid/ubuntu/', 1)]:
            with self.subTest(changed=changed[:40]), self.assertRaises(ValueError):
                D.parse_ubuntu_sources(changed)

    def test_host_fingerprint_mismatch_is_rejected_before_private_directory_creation(self):
        with patch.object(D, 'read_file', return_value=(b'wrong-host', {})), \
             patch.object(D, 'make_private_directory', side_effect=AssertionError('must not create a directory')) as create:
            with self.assertRaises(ValueError):
                D.create_private_sources()
            create.assert_not_called()

    def test_private_source_copy_roundtrips_only_the_uri_under_synthetic_profile(self):
        with self.copied_private_fixture() as (path, host):
            source = (path / 'ubuntu.sources').read_bytes()
            replacement = ('mirror+file:' + str(path / 'mirrors.txt')).encode()
            self.assertEqual(source.replace(replacement, D.HOST_MIRROR_URI.encode()), host)
            self.assertEqual((path / 'mirrors.txt').read_bytes(), D.mirror_bytes())
            projection = D.private_readback(path)
            self.assertEqual(projection['source']['normalizedHostSHA256'], D.sha(host))
            self.assertEqual(projection['source']['replacedURIs'], 2)
            self.assertEqual(projection['source']['bytes'], len(source))
            self.assertTrue(projection['parts']['empty'])
            self.assertTrue(projection['effectiveConfigurationChanged'])

    def test_component_order_is_preserved_but_duplicates_are_rejected(self):
        source = synthetic_source().replace(b'main restricted universe multiverse', b'main universe restricted multiverse')
        self.assertEqual(D.parse_ubuntu_sources(source), 2)
        with self.copied_private_fixture(source) as (path, host):
            replacement = ('mirror+file:' + str(path / 'mirrors.txt')).encode()
            actual = (path / 'ubuntu.sources').read_bytes()
            self.assertIn(b'Components: main universe restricted multiverse\n', actual)
            self.assertEqual(actual.replace(replacement, D.HOST_MIRROR_URI.encode()), source)
            self.assertEqual(D.private_readback(path)['source']['normalizedHostSHA256'], D.sha(host))
        duplicate = source.replace(b'main universe restricted multiverse', b'main universe main multiverse', 1)
        with self.assertRaises(ValueError):
            D.parse_ubuntu_sources(duplicate)

    def test_private_configuration_tamper_and_nonempty_parts_fail_closed(self):
        for target in ['ubuntu.sources', 'mirrors.txt', 'sourceparts']:
            with self.subTest(target=target), self.copied_private_fixture() as (path, host):
                if target == 'sourceparts':
                    (path / target / 'unexpected.list').write_bytes(b'unapproved')
                else:
                    with (path / target).open('ab') as output:
                        output.write(b'# changed bytes\n')
                with self.assertRaises(ValueError):
                    D.private_readback(path)

    def test_private_directory_path_and_mirror_priorities_are_closed(self):
        self.assertEqual(D.mirror_bytes(), b'https://archive.ubuntu.com/ubuntu/\tpriority:1\n'
                         b'https://security.ubuntu.com/ubuntu/\tpriority:2\n'
                         b'http://azure.archive.ubuntu.com/ubuntu/\tpriority:3\n')
        for path in ['/tmp/chengwang-ci-apt-abcdefg', '/tmp/chengwang-ci-apt-ABCDEFGHI',
                     '/tmp/chengwang-ci-apt-abcdefgh/../escape', '/home/runner/lab/private',
                     '/tmp/chengwang-ci-apt-abcdefgh;command']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                D.phase_argv('UPDATE', path)

    def test_post_apt_private_source_mutation_rejects_readback(self):
        changed = private_fixture()
        changed['mirrors']['sha256'] = 'e' * 64
        with self.fixture(private_checks=[private_fixture(), changed, changed]) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'PRIVATE_SOURCES_AFTER')
            self.assertEqual(result['outcome'], 'FAIL')
            self.assertEqual(len(calls), 2)
            self.assertEqual(result['packages'], [])

    def test_extra_sources_probe_uses_both_effective_trees_without_raw_export(self):
        argv = D.policy_argv(PRIVATE_DIRECTORY)
        self.assertEqual(argv[:8], ['/usr/bin/sudo', '--non-interactive', '/usr/bin/env', '-u', 'APT_CONFIG',
                                    'DEBIAN_FRONTEND=noninteractive', 'LC_ALL=C', '/usr/bin/apt-config'])
        self.assertEqual(argv[8:-5], D.apt_options(PRIVATE_DIRECTORY))
        self.assertEqual(argv[-5:], ['-o', 'APT::Config::Dump::EmptyValue=false', 'dump',
                                    'APT::Sources::With', 'Binary::apt-get::APT::Sources::With'])
        with self.fixture() as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['privateSources']['extraSourcesProbe'],
                             dict(argv=argv, exitCode=0, timedOut=False, elapsedMilliseconds=1, emptyOutput=True))
            self.assertEqual(len(result), 20)
            self.assertEqual(len(result['logs']), 4)

    def test_extra_sources_nonempty_failure_is_not_logged_or_used_for_install(self):
        private = b'APT::Sources::With::private "/secret/PRIVATE-PATH";\n'
        with self.fixture(policy_result=(0, private, False, 2, False)) as (reports, calls, run):
            result = D.prepare(reports, COMMIT, execute=run)
            self.assertEqual(result['failureStage'], 'APT_POLICY')
            self.assertFalse(result['privateSources']['extraSourcesProbe']['emptyOutput'])
            self.assertEqual(calls, [])
            self.assertEqual(len(run.policy_calls), 1)
            for name in [*D.LOG_NAMES, 'ci-dependencies.json']:
                self.assertNotIn(b'PRIVATE-PATH', (reports / name).read_bytes())
            self.assertTrue(all(row['executed'] is False and row['argv'] == [] for row in result['commands']))

    def test_extra_sources_error_timeout_and_overflow_never_attempt_update(self):
        for observed in [(100, b'PRIVATE-PATH', False, 1, False), (124, b'PRIVATE-PATH', True, 5000, False),
                         (0, b'', False, 1, True), (0, b'x' * 4097, False, 1, False),
                         (0, b'', False, 5001, False)]:
            with self.subTest(observed=observed[:1]), self.fixture(policy_result=observed) as (reports, calls, run):
                result = D.prepare(reports, COMMIT, execute=run)
                self.assertEqual(result['failureStage'], 'APT_POLICY')
                self.assertEqual(result['outcome'], 'FAIL')
                self.assertEqual(calls, [])
                self.assertTrue(all(row['executed'] is False for row in result['commands']))
                for name in [*D.LOG_NAMES, 'ci-dependencies.json']:
                    self.assertNotIn(b'PRIVATE-PATH', (reports / name).read_bytes())

    def test_private_rejection_reason_allowlist_and_parser_diagnostics_are_closed(self):
        expected = {'FORMAT', 'STRUCTURE', 'TYPES', 'URIS', 'SIGNED_BY', 'COMPONENTS', 'ARCHITECTURES',
                    'SUITES', 'SUITE_COVERAGE', 'HOST_SOURCE_READ', 'HOST_SOURCE_DIGEST', 'HOST_MIRROR_READ',
                    'HOST_MIRROR_DIGEST', 'KEYRING_READ', 'KEYRING_PERMISSION', 'DIRECTORY', 'FILES', 'READBACK'}
        self.assertEqual(D.PRIVATE_REASONS, expected)
        for invalid in ['PRIVATE-CANARY', 'types', '', None, ['TYPES']]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError) as caught:
                D.PrivateSourceRejected(invalid)
            self.assertNotIn('PRIVATE-CANARY', str(caught.exception))
        raw = synthetic_source()
        cases = [('FORMAT', b'\xff'), ('FORMAT', raw + b'Trusted: yes\n'),
                 ('FORMAT', raw.replace(b'Types: deb\n', b'Types: deb\nTypes: deb\n', 1)),
                 ('FORMAT', raw.replace(b'Suites: noble ', b' Suites: noble ', 1)),
                 ('STRUCTURE', raw.replace(b'Types: deb\n', b'', 1)),
                 ('TYPES', raw.replace(b'Types: deb\n', b'Types: deb deb-src\n', 1)),
                 ('URIS', raw.replace(D.HOST_MIRROR_URI.encode(), b'https://unapproved.invalid/', 1)),
                 ('SIGNED_BY', raw.replace(D.KEYRING.encode(), b'/PRIVATE-CANARY/keyring', 1)),
                 ('COMPONENTS', raw.replace(b'main restricted universe multiverse', b'main universe', 1)),
                 ('ARCHITECTURES', raw + b'Architectures: arm64\n'),
                 ('SUITES', raw.replace(b'noble-updates', b'noble noble-updates', 1)),
                 ('SUITE_COVERAGE', raw.replace(b'Suites: noble-security', b'Suites: noble'))]
        for reason, content in cases:
            with self.subTest(reason=reason), self.assertRaises(D.PrivateSourceRejected) as caught:
                D.parse_ubuntu_sources(content)
            self.assertEqual(caught.exception.reason, reason)
            self.assertNotIn('PRIVATE-CANARY', str(caught.exception))

    def test_private_stage_wrappers_preserve_precise_codes_without_leaking_canaries(self):
        canary = 'PRIVATE-CANARY-source-and-error'
        source, mirror = synthetic_source(), b'synthetic host mirror\n'
        for expected in ['HOST_SOURCE_READ', 'HOST_SOURCE_DIGEST', 'HOST_MIRROR_READ', 'HOST_MIRROR_DIGEST',
                         'KEYRING_READ', 'KEYRING_PERMISSION', 'DIRECTORY', 'FILES', 'READBACK']:
            def reader(path, maximum, **kwargs):
                if path == D.HOST_SOURCE:
                    if expected == 'HOST_SOURCE_READ':
                        raise OSError(canary)
                    return (b'wrong source' if expected == 'HOST_SOURCE_DIGEST' else source), {}
                if path == D.HOST_MIRROR:
                    if expected == 'HOST_MIRROR_READ':
                        raise OSError(canary)
                    return (b'wrong mirror' if expected == 'HOST_MIRROR_DIGEST' else mirror), {}
                if expected == 'KEYRING_READ':
                    raise OSError(canary)
                return b'unit keyring', {'mode': 0o600 if expected == 'KEYRING_PERMISSION' else 0o644}

            def reject():
                raise OSError(canary)

            with self.subTest(expected=expected), \
                 patch.object(D, 'HOST_SOURCE_SIZE', len(source)), patch.object(D, 'HOST_SOURCE_SHA', D.sha(source)), \
                 patch.object(D, 'HOST_MIRROR_SIZE', len(mirror)), patch.object(D, 'HOST_MIRROR_SHA', D.sha(mirror)), \
                 patch.object(D, 'read_file', side_effect=reader), \
                 patch.object(D, 'make_private_directory', side_effect=reject if expected == 'DIRECTORY' else lambda: Path(PRIVATE_DIRECTORY)), \
                 patch.object(D, 'private_files', side_effect=reject if expected == 'FILES' else lambda *_: None), \
                 patch.object(D, 'private_readback', side_effect=reject if expected == 'READBACK' else lambda *_: private_fixture()):
                with self.assertRaises(D.PrivateSourceRejected) as caught:
                    D.create_private_sources()
                self.assertEqual(caught.exception.reason, expected)
                self.assertNotIn(canary, str(caught.exception))
        def precise():
            raise D.PrivateSourceRejected('TYPES')
        with self.assertRaises(D.PrivateSourceRejected) as caught:
            D.private_operation('FILES', precise)
        self.assertEqual(caught.exception.reason, 'TYPES')
        for mutated in [False, True]:
            def builder():
                error = D.PrivateSourceRejected('TYPES')
                error.args = (canary,)
                if mutated:
                    error.reason = canary
                raise error
            with self.subTest(mutated=mutated), self.fixture(private_builder=builder) as (reports, calls, run):
                result = D.prepare(reports, COMMIT, execute=run)
                self.assertEqual(result['failureStage'], 'PRIVATE_SOURCES' if mutated else 'PRIVATE_TYPES')
                self.assertEqual(result['outcome'], 'FAIL')
                self.assertEqual(len(result), 20)
                self.assertEqual(calls, [])
                self.assertTrue(all(not row['executed'] and not row['argv'] for row in result['commands']))
                for name in [*D.LOG_NAMES, 'ci-dependencies.json']:
                    self.assertNotIn(canary.encode(), (reports / name).read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
