"""Explicit CPU-only entry point; mocked formatter, no Go or gofmt execution."""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('overview_format_cpu_subject', BASE / 'overview_format.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


class OverviewFormatContracts(unittest.TestCase):
    def fixture(self, root):
        repo = root / 'repo'
        repo.mkdir()
        for relative in F.GO_PATHS:
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'package fixture\nvar value = 1\n')
        return repo, root / 'evidence'

    def test_fixed_feature_paths_and_formatter_command_have_no_write_or_inherited_environment(self):
        expected = {'chengwang/internal/overview/model.go', 'chengwang/internal/overview/provider.go',
            'chengwang/internal/overview/provider_test.go', 'chengwang/internal/api/overview.go',
            'chengwang/internal/api/overview_test.go', 'chengwang/internal/api/server.go',
            'chengwang/internal/serverruntime/overview_config.go', 'chengwang/internal/serverruntime/overview_config_test.go',
            'chengwang/internal/serverruntime/overview_runtime_linux_test.go', 'chengwang/internal/serverruntime/runtime.go'}
        self.assertEqual(set(F.GO_PATHS), expected)
        self.assertEqual(len(F.GO_PATHS), 10)
        result = types.SimpleNamespace(returncode=0, stdout=b'formatted\n', stderr=b'')
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'private-inherited', 'GOFLAGS': '-private'}), \
                mock.patch.object(F.subprocess, 'run', return_value=result) as run:
            self.assertEqual(F.format_source(b'original\n'), b'formatted\n')
        args, kwargs = run.call_args
        self.assertEqual(args, (['/opt/hostedtoolcache/go/1.23.12/x64/bin/gofmt'],))
        self.assertNotIn('-w', args[0])
        self.assertEqual(kwargs['input'], b'original\n')
        self.assertEqual(kwargs['timeout'], 30)
        self.assertFalse(kwargs['shell'])
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'GOMAXPROCS': '1'})

    def test_collection_records_real_before_and_mock_formatted_bytes_without_source_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            before = {name: (repo / name).read_bytes() for name in F.GO_PATHS}
            with mock.patch.object(F, 'format_source', side_effect=lambda raw: raw.replace(b'\nvar', b'\n\nvar')) as formatter:
                report = F.collect(str(repo), 'a' * 40, str(output))
            self.assertEqual(formatter.call_count, 10)
            self.assertTrue(report['sourceUnchanged'])
            self.assertTrue(report['needsFormatting'])
            self.assertEqual(report['commitBinding'], 'CALLER_SUPPLIED_LABEL_SOURCE_BLOBS_CHECKED_BY_PARENT_GATE')
            self.assertFalse(report['compilationVerified'])
            self.assertFalse(report['runtimeVerified'])
            self.assertEqual(json.loads((output / 'report.json').read_bytes()), report)
            difference = (output / 'overview-format-diff.txt').read_bytes()
            self.assertIn(b'--- a/chengwang/internal/overview/model.go\n+++ b/chengwang/internal/overview/model.go\n', difference)
            self.assertEqual(F.sha(difference), report['diff']['sha256'])
            for row in report['files']:
                self.assertEqual((repo / row['path']).read_bytes(), before[row['path']])
                self.assertEqual(row['beforeSHA256'], F.sha(before[row['path']]))
                self.assertEqual(row['afterSHA256'], F.sha(before[row['path']].replace(b'\nvar', b'\n\nvar')))

    def test_unchanged_formatting_has_empty_diff_but_still_only_collects_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            with mock.patch.object(F, 'format_source', side_effect=lambda raw: raw):
                report = F.collect(str(repo), 'b' * 40, str(output))
            self.assertFalse(report['needsFormatting'])
            self.assertTrue(report['collectionOnly'])
            self.assertFalse(report['testsVerified'])
            self.assertEqual((output / 'overview-format-diff.txt').read_bytes(), b'')

    def test_source_byte_drift_rejects_without_a_success_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            def changed(raw):
                (repo / F.GO_PATHS[0]).write_bytes(b'package changed\n')
                return raw
            with mock.patch.object(F, 'format_source', side_effect=changed), self.assertRaises(F.FormatEvidenceError):
                F.collect(str(repo), 'a' * 40, str(output))
            self.assertFalse((output / 'report.json').exists())

    def test_metadata_drift_with_identical_source_bytes_is_also_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            target = repo / F.GO_PATHS[0]
            def changed(raw):
                info = target.stat()
                os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
                return raw
            with mock.patch.object(F, 'format_source', side_effect=changed), self.assertRaises(F.FormatEvidenceError):
                F.collect(str(repo), 'a' * 40, str(output))
            self.assertFalse((output / 'report.json').exists())
        # Synthetic metadata channels exercise this portability boundary on
        # every OS without replacing native metadata in the positive tests.
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / 'source.go'
            payload = b'package fixture\n'
            target.write_bytes(payload)
            original_lstat = pathlib.Path.lstat
            def info(ctime, **changes):
                values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600, st_size=len(payload),
                    st_mtime_ns=100, st_ctime_ns=ctime, st_birthtime_ns=5)
                values.update(changes)
                return types.SimpleNamespace(**values)
            def read_channels(windows, path_before, path_after, descriptor_before, descriptor_after):
                path_calls = 0
                def observed(path):
                    nonlocal path_calls
                    if path != target:
                        return original_lstat(path)
                    path_calls += 1
                    return path_before if path_calls <= 2 else path_after
                with mock.patch.object(F, 'WINDOWS_METADATA', windows), mock.patch.object(pathlib.Path, 'lstat', observed), \
                        mock.patch.object(F.os, 'fstat', side_effect=[descriptor_before, descriptor_after]):
                    return F.stable_read(target, 4096)
            path_info, descriptor_info = info(10), info(20)
            observed, token = read_channels(True, path_info, path_info, descriptor_info, descriptor_info)
            self.assertEqual(observed, payload)
            self.assertNotEqual(token[0][-1], token[1][-1])
            with self.assertRaises(F.FormatEvidenceError):
                read_channels(False, path_info, path_info, descriptor_info, descriptor_info)
            for path_after, descriptor_after in [(info(11), descriptor_info), (path_info, info(21))]:
                with self.assertRaises(F.FormatEvidenceError):
                    read_channels(True, path_info, path_after, descriptor_info, descriptor_after)
            for field, replacement in [('st_dev', 3), ('st_ino', 3), ('st_mode', stat.S_IFDIR),
                    ('st_size', len(payload) + 1), ('st_mtime_ns', 101), ('st_birthtime_ns', 6)]:
                altered = info(20, **{field: replacement})
                with self.subTest(field=field), self.assertRaises(F.FormatEvidenceError):
                    read_channels(True, path_info, path_info, altered, altered)
            absent = info(20)
            del absent.st_birthtime_ns
            with self.assertRaises(F.FormatEvidenceError):
                read_channels(True, path_info, path_info, absent, absent)
            no_birth_path, no_birth_descriptor = info(10), info(20)
            del no_birth_path.st_birthtime_ns
            del no_birth_descriptor.st_birthtime_ns
            self.assertEqual(read_channels(True, no_birth_path, no_birth_path, no_birth_descriptor, no_birth_descriptor)[0], payload)

    def test_output_inside_repository_or_preexisting_output_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            output.mkdir()
            sentinel = output / 'report.json'
            sentinel.write_bytes(b'preexisting-original')
            for target in [repo / 'evidence', output]:
                with mock.patch.object(F, 'format_source') as formatter, self.assertRaises(F.FormatEvidenceError):
                    F.collect(str(repo), 'a' * 40, str(target))
                formatter.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b'preexisting-original')

    def test_source_symlink_observation_is_rejected_before_formatter(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            target = repo / F.GO_PATHS[0]
            original = pathlib.Path.lstat
            def observed(path):
                return types.SimpleNamespace(st_mode=stat.S_IFLNK) if path == target else original(path)
            with mock.patch.object(pathlib.Path, 'lstat', observed), mock.patch.object(F, 'format_source') as formatter, \
                    self.assertRaises(F.FormatEvidenceError):
                F.collect(str(repo), 'a' * 40, str(output))
            formatter.assert_not_called()

    def test_output_parent_reparse_observation_is_rejected_without_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo, _ = self.fixture(root)
            parent = root / 'reparse-parent'
            parent.mkdir()
            output = parent / 'evidence'
            original = pathlib.Path.lstat
            def observed(path):
                if path == parent:
                    return types.SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
                return original(path)
            with mock.patch.object(pathlib.Path, 'lstat', observed), mock.patch.object(F, 'format_source') as formatter, \
                    self.assertRaises(F.FormatEvidenceError):
                F.collect(str(repo), 'a' * 40, str(output))
            formatter.assert_not_called()
            self.assertFalse(output.exists())

    def test_raw_and_aggregate_source_limits_reject_before_formatter(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            (repo / F.GO_PATHS[0]).write_bytes(b'x' * (F.MAX_SOURCE_BYTES + 1))
            with mock.patch.object(F, 'format_source') as formatter, self.assertRaises(F.FormatEvidenceError):
                F.collect(str(repo), 'a' * 40, str(output))
            formatter.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            with mock.patch.object(F, 'MAX_SOURCE_TOTAL', 30), mock.patch.object(F, 'format_source') as formatter, \
                    self.assertRaises(F.FormatEvidenceError):
                F.collect(str(repo), 'a' * 40, str(output))
            formatter.assert_not_called()

    def test_formatted_and_diff_limits_do_not_publish_a_success_report(self):
        with mock.patch.object(F.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=b'x' * (F.MAX_FORMATTED_BYTES + 1), stderr=b'')):
            with self.assertRaises(F.FormatEvidenceError):
                F.format_source(b'package fixture\n')
        for bound in ['MAX_FORMATTED_TOTAL', 'MAX_DIFF_BYTES']:
            with tempfile.TemporaryDirectory() as temporary:
                repo, output = self.fixture(pathlib.Path(temporary))
                with mock.patch.object(F, bound, 1), mock.patch.object(F, 'format_source', side_effect=lambda raw: raw + b'\n'), \
                        self.assertRaises(F.FormatEvidenceError):
                    F.collect(str(repo), 'a' * 40, str(output))
                self.assertFalse((output / 'report.json').exists())

    def test_unified_diff_handles_missing_final_newline_and_crlf_changes(self):
        raw = F.source_diff('chengwang/internal/overview/model.go', b'package fixture', b'package fixture\n')
        self.assertIn(b'-package fixture\n\\ No newline at end of file\n+package fixture\n', raw)
        self.assertNotIn(b'-package fixture+package', raw)
        endings = F.source_diff('chengwang/internal/overview/model.go', b'package fixture\r\n', b'package fixture\n')
        self.assertIn(b'-package fixture\r\n+package fixture\n', endings)

    def test_invalid_commit_and_noncanonical_paths_never_reach_formatter(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            for source_commit, repo_value, output_value in [('A' * 40, str(repo), str(output)),
                    ('sentinel-private-label', str(repo), str(output)), ('a' * 40, 'relative', str(output)),
                    ('a' * 40, str(repo), str(output.parent / '..' / 'evidence'))]:
                with mock.patch.object(F, 'format_source') as formatter, self.assertRaises(F.FormatEvidenceError):
                    F.collect(repo_value, source_commit, output_value)
                formatter.assert_not_called()

    def test_cli_failures_suppress_formatter_stderr_exception_text_and_argument_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            cases = [types.SimpleNamespace(returncode=2, stdout=b'', stderr=b'sentinel-private-source-error'),
                types.SimpleNamespace(returncode=0, stdout=b'package fixture\n', stderr=b'sentinel-private-warning'),
                subprocess.TimeoutExpired(F.FORMATTER, 30, stderr=b'sentinel-private-timeout')]
            for index, value in enumerate(cases):
                with self.subTest(case=index):
                    target = output.with_name('evidence-' + str(index))
                    patch = dict(side_effect=value) if isinstance(value, Exception) else dict(return_value=value)
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with mock.patch.object(F.subprocess, 'run', **patch), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        code = F.main(['--repo', str(repo), '--source-commit', 'a' * 40, '--output', str(target)])
                    self.assertEqual(code, 1)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertEqual(stderr.getvalue(), 'OVERVIEW_FORMAT=REJECTED details_suppressed=true\n')
                    self.assertFalse((target / 'report.json').exists())
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(F.main(['--sentinel-private-argument']), 1)
            self.assertNotIn('sentinel', stderr.getvalue())

    def test_cli_success_return_zero_is_collection_not_format_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, output = self.fixture(pathlib.Path(temporary))
            stdout = io.StringIO()
            with mock.patch.object(F, 'format_source', side_effect=lambda raw: raw + b'\n'), contextlib.redirect_stdout(stdout):
                code = F.main(['--repo', str(repo), '--source-commit', 'a' * 40, '--output', str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads((output / 'report.json').read_bytes())['needsFormatting'])
            self.assertEqual(stdout.getvalue(), 'OVERVIEW_FORMAT=COLLECTED format_admission=independent\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
