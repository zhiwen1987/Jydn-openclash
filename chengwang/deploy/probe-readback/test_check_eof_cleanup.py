"""Synthetic helper contracts only; never real browser or original CLI proof."""
import contextlib
import ast
import copy
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import check_eof_cleanup as C
import check_probe_readback as B
import test_check_request_binding as T
from test_probe_request_binding import reseal, trace


def successful_rows(count=7):
    sample = trace()
    prefix = [copy.deepcopy(row) for row in sample if row['e'] in ('SESSION', 'DOCUMENT', 'CONTEXT')
              or row['e'] == 'JS' and row['j'] == 'MOUNT']
    request = [row for row in sample if row['e'] not in ('SESSION', 'DOCUMENT', 'CONTEXT', 'META', 'CANCEL_RESULT')
               and not (row['e'] == 'JS' and row['j'] in ('MOUNT', 'CANCEL'))]
    for number in range(1, count + 1):
        for template in request:
            row = copy.deepcopy(template)
            if 'r' in row:
                row['r'] = number
            if 'n' in row and row['e'].startswith('NET_'):
                row['n'] = number
            if row['e'] in ('JS', 'SEND'):
                row['t'] += 10 * number
            if 'x' in row:
                row['x'] += 100 * number
            if 'w' in row:
                row['w'] += 100 * number
            if row['e'] == 'JS' and row['j'] == 'READ_END':
                row['f'] = True
            prefix.append(row)
    return reseal(prefix)


class EOFCleanupVerifierContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='eof-helper-unit-', dir=os.environ.get('CHENGWANG_EOF_TEST_TMP'))
        self.base = pathlib.Path(self.tmp.name)
        self.evidence, self.repo = self.base / 'evidence', self.base / 'repo'
        self.evidence.mkdir(); self.repo.mkdir()
        (self.evidence / 'lab/browser').mkdir(parents=True)
        (self.evidence / 'lab/backend').mkdir()
        self.blobs = {name: (C.HOST_ROOT / name).read_bytes() for name in C.CONTRACT['requiredSourceFiles']}
        self.commands = []; self.fail_script = None; self.bad_stdout = False; self.after_replay = None
        self.write_fixture()
        self.git_mock = patch.object(C, 'git_blob', side_effect=lambda _repo, _commit, name: self.blobs[name])
        self.run_mock = patch.object(C.subprocess, 'run', side_effect=self.fake_original_cli)
        self.git_mock.start(); self.run_mock.start()

    def tearDown(self):
        self.run_mock.stop(); self.git_mock.stop(); self.tmp.cleanup()

    def put(self, relative, value):
        raw = value if isinstance(value, bytes) else B.encoded(value) + b'\n'
        (self.evidence / relative).write_bytes(raw)

    def write_fixture(self, rows=None, engine='chrome-cdp'):
        self.engine = engine
        self.rows = successful_rows() if rows is None else reseal(rows)
        binding, old, build = T.fixture(self.rows, engine)
        sources = [dict(path=name, bytes=len(raw), sha256=C.sha(raw)) for name, raw in self.blobs.items()]
        build['sourceFilesBefore'] = sources
        build['sourceFilesAfter'] = copy.deepcopy(sources)
        # The original runtime-copy check is mocked only in these synthetic
        # unit fixtures. New host-only source binding itself needs no copy.
        build['copiedInputs'] = []
        self.build = build
        self.browser_report = dict(sourceCommit=T.COMMIT, engine=engine, fixtureId=T.FIXTURE,
                                   production=False, authorization='BLOCKED', outcome='PASS', browserE2EProven=True)
        self.binding_report = dict(sourceCommit=T.COMMIT, engine=engine, fixtureId=T.FIXTURE,
                                   production=False, authorization='BLOCKED', requestIdentityBindingProven=True,
                                   requests=7, sends=7, boundRequests=7, unboundAttempts=0, missingSends=0,
                                   openNetworks=0, missingFinally=0, missingCancellationResults=0,
                                   cancellationResults=0, networkFailures=0)
        self.browser_raw = B.encoded(self.browser_report) + b'\n'
        self.binding_raw = B.encoded(self.binding_report) + b'\n'
        self.put('browser-verification.json', self.browser_raw)
        self.put('request-binding-verification.json', self.binding_raw)
        self.put('lab/request-binding.json', binding)
        self.put('lab/status-diagnostic.json', old)
        self.put('lab/browser/browser-build.json', build)
        self.put('lab/browser/browser-driver.json', {name: 0 for name in C.COUNTERS})
        self.put('lab/backend/fixture.json', {})

    def fake_original_cli(self, command, **kwargs):
        self.commands.append((command, kwargs))
        name = pathlib.Path(command[2]).name
        self.assertIn(name, ('check_probe_browser.py', 'check_request_binding.py'))
        report = pathlib.Path(command[command.index('--report') + 1])
        self.assertFalse(report.resolve().is_relative_to(self.evidence.resolve()))
        self.assertFalse(report.resolve().is_relative_to(self.repo.resolve()))
        self.assertFalse(report.exists())
        report.write_bytes(self.browser_raw if name == 'check_probe_browser.py' else self.binding_raw)
        if name == 'check_request_binding.py' and self.after_replay is not None:
            self.after_replay()
        marker = C.BROWSER_SUCCESS if name == 'check_probe_browser.py' else C.BINDING_SUCCESS
        return SimpleNamespace(returncode=1 if self.fail_script == name else 0,
                               stdout=b'UNEXPECTED\n' if self.bad_stdout else marker + b'\n', stderr=b'')

    def verify(self):
        return C.verify(self.evidence, self.repo, T.COMMIT, self.engine, self.base)

    def manifest_rows(self, count):
        # Extend the complete EOF fixture, not the mocked original CLI's scope.
        # Only the sixteen required real host/Git bindings are consumed here;
        # the extra records exercise this helper's exact build decoder entry.
        rows = copy.deepcopy(self.build['sourceFilesBefore'])
        self.assertGreaterEqual(count, len(rows))
        for number in range(count - len(rows)):
            rows.append(dict(path='chengwang/internal/eof_fixture_%04d.go' % number,
                             bytes=1, sha256=C.sha(b'x')))
        return rows

    def rejected(self):
        with self.assertRaises((ValueError, B.Rejected, C.R.D.Rejected)):
            self.verify()

    def test_01_seven_normal_reads_accept_both_engines_but_not_root_cause(self):
        for engine in ('chrome-cdp', 'playwright'):
            self.write_fixture(engine=engine)
            value = self.verify()
            self.assertEqual(value['normalJSONEOFs'], 7)
            self.assertEqual(value['cancellationResults'], 0)
            self.assertEqual(value['cancelRecords'], 0)
            for field in ('perRequestDTOSchemaProven', 'cancellationRootCauseProven', 'packetCausalityProven',
                          'independentBrowserInternalAttestationProven', 'longTermStabilityProven', 'production'):
                self.assertIs(value[field], False)
            self.assertEqual(value['authorization'], 'BLOCKED')
            for count in (1035, 2000):
                self.write_fixture(engine=engine)
                rows = self.manifest_rows(count)
                self.build['sourceFilesBefore'] = rows
                self.build['sourceFilesAfter'] = copy.deepcopy(rows)
                self.put('lab/browser/browser-build.json', self.build)
                # The default decoder still rejects these exact original bytes.
                with self.assertRaises(B.Rejected):
                    B.decoded((self.evidence / 'lab/browser/browser-build.json').read_bytes())
                expanded = self.verify()
                self.assertEqual(expanded['normalJSONEOFs'], 7)
                self.assertEqual(expanded['requiredGitBlobsVerified'], 16)
                self.assertFalse(expanded['cancellationRootCauseProven'])

    def test_02_original_clis_are_actually_called_before_observation_acceptance(self):
        self.verify()
        self.assertEqual([pathlib.Path(c[0][2]).name for c in self.commands],
                         ['check_probe_browser.py', 'check_request_binding.py'])
        for command, kwargs in self.commands:
            self.assertEqual(command[:2], [sys.executable, '-B'])
            self.assertEqual(kwargs['cwd'], self.repo)
            self.assertEqual(kwargs['timeout'], 600)
            self.assertEqual(kwargs['stdout'], subprocess.PIPE)
        self.assertIn('--repo', self.commands[1][0])

    def test_03_new_host_only_sources_need_no_runtime_copy(self):
        value = self.verify()
        self.assertEqual(self.build['copiedInputs'], [])
        self.assertEqual(value['requiredGitBlobsVerified'], 16)
        paths = {row['path'] for row in value['sourceBindings']}
        self.assertIn('chengwang/deploy/probe-readback/check_eof_cleanup.py', paths)
        self.assertIn(C.CONTRACT_PATH, paths)
        self.assertIn('.github/workflows/chengwang-probe-browser.yml', paths)
        tree = ast.parse(pathlib.Path(__file__).read_bytes())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
        names = sorted(node.name for node in cls.body
                       if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        full = ['test_check_eof_cleanup.' + cls.name + '.' + name for name in names]
        pins = C.CONTRACT['syntheticContract']
        self.assertEqual(len(names), pins['tests'])
        self.assertEqual(C.sha('\n'.join(names).encode()), pins['methodNamesSHA256'])
        self.assertEqual(C.sha('\n'.join(full).encode()), pins['fullNamesSHA256'])

    def test_04_failed_original_browser_cli_rejects_even_with_a_written_pass_report(self):
        self.fail_script = 'check_probe_browser.py'
        self.rejected()
        self.assertEqual(len(self.commands), 1)

    def test_05_failed_original_binding_cli_rejects_even_with_a_written_pass_report(self):
        self.fail_script = 'check_request_binding.py'
        self.rejected()
        self.assertEqual(len(self.commands), 2)

    def test_06_stored_browser_pass_cannot_replace_original_replay(self):
        self.put('browser-verification.json', {**self.browser_report, 'forged': True})
        self.rejected()

    def test_07_stored_binding_pass_cannot_replace_original_replay(self):
        self.put('request-binding-verification.json', {**self.binding_report, 'forged': True})
        self.rejected()

    def test_08_missing_or_duplicate_eof_refuses_normal_completion(self):
        for duplicate in (False, True):
            rows = successful_rows()
            eof = next(row for row in rows if row['e'] == 'JS' and row['j'] == 'EOF')
            if duplicate:
                rows.insert(rows.index(eof) + 1, copy.deepcopy(eof))
            else:
                rows.remove(eof)
            self.write_fixture(rows)
            self.rejected()

    def test_09_eof_ok_without_true_eof_or_matching_bytes_is_rejected(self):
        for field, value in (('f', False), ('n', 9), ('k', 'JSON_REJECT')):
            rows = successful_rows()
            next(row for row in rows if row['e'] == 'JS' and row['j'] == 'READ_END')[field] = value
            self.write_fixture(rows)
            self.rejected()

    def test_10_missing_read_end_or_finally_is_rejected(self):
        for kind in ('READ_END', 'FINALLY'):
            rows = successful_rows()
            target = next(row for row in rows if row['e'] == 'JS' and row['j'] == kind)
            rows.remove(target)
            self.write_fixture(rows)
            self.rejected()

    def test_11_cancel_or_fabricated_settlement_never_counts_as_skipped_eof(self):
        for kind in ('CANCEL', 'CANCEL_RESULT'):
            rows = successful_rows()
            source = next(row for row in trace() if row['e'] == kind
                          or kind == 'CANCEL' and row['e'] == 'JS' and row['j'] == kind)
            rows.insert(-1, copy.deepcopy(source))
            self.write_fixture(rows)
            self.rejected()

    def test_12_abort_observation_never_passes_normal_cleanup(self):
        rows = successful_rows()
        rows.insert(-1, dict(v=1, e='JS', s=1, q=1, c=1, j='ABORT', m=1, r=1,
                             t=100, a=True, cause='DEADLINE', p='BEFORE'))
        self.write_fixture(rows)
        self.rejected()

    def test_13_network_failure_rejects_even_when_mocked_old_reports_say_pass(self):
        rows = successful_rows()
        row = next(row for row in rows if row['e'] == 'NET_FINISH')
        row.update(e='NET_FAIL', canceled='YES', error='ABORTED')
        self.write_fixture(rows)
        self.rejected()

    def test_14_non_200_status_is_not_normal_json_eof_evidence(self):
        rows = successful_rows()
        next(row for row in rows if row['e'] == 'NET_HEADERS')['st'] = 201
        self.write_fixture(rows)
        self.rejected()

    def test_15_missing_or_duplicate_send_identity_is_rejected(self):
        for duplicate in (False, True):
            rows = successful_rows()
            send = next(row for row in rows if row['e'] == 'SEND')
            if duplicate:
                rows.insert(rows.index(send) + 1, copy.deepcopy(send))
            else:
                rows.remove(send)
            self.write_fixture(rows)
            self.rejected()

    def test_16_duplicate_network_identity_is_rejected(self):
        rows = successful_rows()
        starts = [row for row in rows if row['e'] == 'NET_START']
        starts[1]['n'] = starts[0]['n']
        self.write_fixture(rows)
        self.rejected()

    def test_17_every_original_driver_counter_must_be_integer_zero(self):
        for name in C.COUNTERS:
            self.put('lab/browser/browser-driver.json', {**{key: 0 for key in C.COUNTERS}, name: 1})
            self.rejected()
        self.put('lab/browser/browser-driver.json', {**{key: 0 for key in C.COUNTERS}, 'failedRequests': False})
        self.rejected()

    def test_18_this_closed_run_requires_exactly_seven_normal_reads(self):
        for count in (6, 8):
            self.write_fixture(successful_rows(count))
            self.rejected()

    def test_19_missing_changed_duplicate_or_after_changed_source_refuses_before_cli(self):
        for kind in ('missing', 'changed', 'duplicate', 'after'):
            self.write_fixture()
            if kind == 'missing':
                self.build['sourceFilesBefore'].pop()
                self.build['sourceFilesAfter'].pop()
            elif kind == 'changed':
                self.build['sourceFilesBefore'][0]['sha256'] = 'f' * 64
                self.build['sourceFilesAfter'][0]['sha256'] = 'f' * 64
            elif kind == 'duplicate':
                self.build['sourceFilesBefore'].append(copy.deepcopy(self.build['sourceFilesBefore'][0]))
                self.build['sourceFilesAfter'] = copy.deepcopy(self.build['sourceFilesBefore'])
            else:
                self.build['sourceFilesAfter'][0]['bytes'] += 1
            self.put('lab/browser/browser-build.json', self.build)
            self.commands.clear()
            self.rejected()
            self.assertEqual(self.commands, [])
        for kind in ('oversize_before', 'oversize_after', 'unrelated_list', 'nested_lookalike'):
            self.write_fixture()
            if kind in ('oversize_before', 'oversize_after'):
                field = 'sourceFilesBefore' if kind == 'oversize_before' else 'sourceFilesAfter'
                self.build[field] = self.manifest_rows(2001)
            elif kind == 'unrelated_list':
                self.build['copiedInputs'] = [None] * 1025
            else:
                self.build['nested'] = dict(sourceFilesBefore=[None] * 1025)
            self.put('lab/browser/browser-build.json', self.build)
            self.commands.clear()
            self.rejected()
            self.assertEqual(self.commands, [])

    def test_20_host_executed_source_must_equal_bound_git_blob(self):
        name = C.CONTRACT_PATH
        self.blobs[name] += b'\n'
        for field in ('sourceFilesBefore', 'sourceFilesAfter'):
            row = next(row for row in self.build[field] if row['path'] == name)
            row.update(bytes=len(self.blobs[name]), sha256=C.sha(self.blobs[name]))
        self.put('lab/browser/browser-build.json', self.build)
        self.rejected()

    def test_21_complete_workflow_source_binding_is_mandatory(self):
        for field in ('sourceFilesBefore', 'sourceFilesAfter'):
            row = next(row for row in self.build[field] if row['path'] == '.github/workflows/chengwang-probe-browser.yml')
            row['sha256'] = 'd' * 64
        self.put('lab/browser/browser-build.json', self.build)
        self.rejected()

    def test_22_original_input_changed_during_replay_is_rejected(self):
        self.after_replay = lambda: self.put('lab/backend/fixture.json', {'changed': True})
        self.rejected()

    def test_23_original_input_file_set_changed_during_replay_is_rejected(self):
        self.after_replay = lambda: self.put('lab/backend/extra.json', {})
        self.rejected()

    def test_24_report_must_be_new_and_outside_evidence_and_repository(self):
        occupied = self.base / 'occupied.json'
        occupied.write_bytes(b'old\n')
        for report in (self.evidence / 'out.json', self.repo / 'out.json', occupied):
            argv = ['check_eof_cleanup.py', '--evidence-root', str(self.evidence), '--repo', str(self.repo),
                    '--source-commit', T.COMMIT, '--engine', self.engine, '--report', str(report)]
            with patch.object(sys, 'argv', argv), patch.object(C, 'verify') as verify:
                with self.assertRaises(ValueError):
                    C.main()
                verify.assert_not_called()
        self.assertEqual(occupied.read_bytes(), b'old\n')

    def test_25_successful_cli_writes_only_new_external_report(self):
        report = self.base / 'out.json'
        argv = ['check_eof_cleanup.py', '--evidence-root', str(self.evidence), '--repo', str(self.repo),
                '--source-commit', T.COMMIT, '--engine', self.engine, '--report', str(report)]
        stdout = io.StringIO()
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(stdout):
            C.main()
        self.assertEqual(B.decoded(report.read_bytes())['normalJSONEOFs'], 7)
        self.assertIn('cancellation_root_cause_proven=false', stdout.getvalue())

    def test_26_js_cdp_arrival_and_clock_domains_are_not_causally_sorted(self):
        rows = successful_rows()
        for number in range(1, 8):
            end = next(row for row in rows if row['e'] == 'NET_FINISH' and row['n'] == number)
            rows.remove(end)
            headers = next(row for row in rows if row['e'] == 'NET_HEADERS' and row['n'] == number)
            rows.insert(rows.index(headers) + 1, end)
            self.assertLess(end['x'], headers['x'])
        self.write_fixture(rows)
        self.assertEqual(self.verify()['normalNetworkFinishes'], 7)
        # Reversing the original per-network terminal/header arrival chain is
        # different: the original v1 verifier itself rejects that chain. Do not
        # pretend this auxiliary gate authorizes bypassing its original rule.
        invalid = copy.deepcopy(rows)
        h = next(i for i, row in enumerate(invalid) if row['e'] == 'NET_HEADERS' and row['n'] == 1)
        f = next(i for i, row in enumerate(invalid) if row['e'] == 'NET_FINISH' and row['n'] == 1)
        invalid[h], invalid[f] = invalid[f], invalid[h]
        value, old, _build = T.fixture(invalid)
        old_rows, _complete = C.R.old_observations(old, T.COMMIT, 'chrome-cdp')
        with self.assertRaises(C.R.D.Rejected):
            C.R.reconstruct(value['records'], old_rows)


if __name__ == '__main__':
    unittest.main()
