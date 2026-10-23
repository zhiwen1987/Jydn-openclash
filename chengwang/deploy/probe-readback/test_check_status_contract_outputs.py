"""Pure synthetic tamper checks; fixture transcripts are not real test runs.

The original five suites are read only for names, never imported or executed.
These tests belong to a separate frozen increment, not the original 80.
"""
import ast
import contextlib
import copy
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

import check_status_contract_outputs as C


def encoded(value):
    return (json.dumps(value, separators=(',', ':')) + '\n').encode()


class TestStatusContractOriginals(unittest.TestCase):
    def fixture(self):
        base = pathlib.Path(__file__).resolve().parent
        source = base.parents[2]
        names = {}
        for pin, relative, pattern in [
            ('collector', 'chengwang/tools/probe-browser/test-probe-status-diagnostics.mjs', r"^test\('([^']+)',"),
            ('subscriptionDOM', 'chengwang/tools/subscription-browser/test-collect-subscription-dom.mjs', r"^test\('([^']+)',"),
            ('frontend', 'chengwang/web/tools/check-probe-status-observation.mjs', r"^await check\('([^']+)',"),
        ]:
            names[pin] = re.findall(pattern, (source / relative).read_text(encoding='utf-8'), re.M)
        for pin, module in [('pythonProjection', 'test_probe_status_diagnostics'), ('artifactChecker', 'test_check_status_diagnostic')]:
            tree = ast.parse((base / (module + '.py')).read_bytes())
            names[pin] = sorted(module + '.' + cls.name + '.' + method.name
                for cls in tree.body if isinstance(cls, ast.ClassDef)
                for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'))
        self.assertEqual({p: C.fingerprint(n) for p, n in names.items()}, C.PINS)
        files = {}
        for pin in ('collector', 'subscriptionDOM'):
            count = len(names[pin])
            text = 'TAP version 13\n'
            text += ''.join('# Subtest: ' + name + '\nok ' + str(i + 1) + ' - ' + name + '\n'
                            for i, name in enumerate(names[pin]))
            text += '1..' + str(count) + '\n'
            text += ''.join('# ' + key + ' ' + str(value) + '\n' for key, value in [
                ('tests', count), ('suites', 0), ('pass', count), ('fail', 0), ('cancelled', 0), ('skipped', 0), ('todo', 0)])
            files[C.OUTPUTS[pin][0]] = text.encode()
        files['frontend.json'] = encoded(dict(schema='chengwang.probe-status-observation-synthetic/v1',
            syntheticOnly=True, realBrowserProof=False, passed=12, failed=0, names=names['frontend']))
        for pin in ('pythonProjection', 'artifactChecker'):
            rows = [dict(event=event, name=name) for name in names[pin] for event in ('RUN', 'PASS')]
            rows.append(dict(event='SUMMARY', testsRun=len(names[pin]), testsPassed=len(names[pin]),
                failures=0, errors=0, skipped=0, expectedFailures=0, unexpectedSuccesses=0))
            files[C.OUTPUTS[pin][0]] = b''.join(encoded(row) for row in rows)
            text = ''.join(name.rsplit('.', 1)[1] + ' (' + name + ') ... ok\n' for name in names[pin])
            text += '\n' + '-' * 70 + '\nRan ' + str(len(names[pin])) + ' tests in 0.001s\n\nOK\n'
            files[C.OUTPUTS[pin][1]] = text.encode()
        groups = {pin: dict(mode='IN_PROCESS_UNITTEST', outcome='RETURNED', captureComplete=True) for pin in C.PINS}
        for pin in ('collector', 'subscriptionDOM', 'frontend'):
            groups[pin].update(mode='SUBPROCESS', exitCode=0)
        files['execution.json'] = encoded(dict(schema='chengwang.status-contract-execution/v1', groups=groups))
        return files

    def tree(self, parent, files):
        root = pathlib.Path(parent) / 'originals'; root.mkdir()
        for name, raw in files.items():
            if raw:
                (root / name).write_bytes(raw)
        manifest = dict(schema='chengwang.status-contract-originals/v1', files=[dict(path=name,
            bytes=len(raw), sha256=C.sha(raw), stored=bool(raw)) for name, raw in sorted(files.items())])
        (root / 'manifest.json').write_bytes(encoded(manifest))
        return root

    def reject(self, files):
        with self.assertRaises((ValueError, UnicodeError, json.JSONDecodeError)):
            C.recompute(files)

    def test_original_five_closed_outputs_recompute_exactly_eighty_synthetic_only(self):
        report = C.recompute(self.fixture())
        self.assertEqual((report['testsRun'], report['testsPassed'], report['skipped']), (80, 80, 0))
        self.assertFalse(report['browserE2EProven']); self.assertFalse(report['production'])

    def test_original_bytes_and_exact_v1_reports_survive_independent_tree_verification(self):
        files = self.fixture(); report = C.recompute(files)
        with tempfile.TemporaryDirectory() as parent:
            checked = C.verify_tree(self.tree(parent, files), encoded(report))
        self.assertEqual(checked['originalFiles'], 9)
        self.assertEqual(report['reports']['collector']['originalOutputSHA256'], C.sha(files['collector.tap']))
        self.assertNotIn('originalOutputSHA256', report['reports']['pythonProjection'])

    def test_duplicate_json_keys_are_rejected_before_projection(self):
        for name in ('frontend.json', 'execution.json'):
            files = self.fixture(); files[name] = files[name].replace(b'{', b'{"schema":"substituted",', 1)
            self.reject(files)

    def test_tap_duplicate_execution_and_result_names_cannot_hide_under_totals(self):
        files = self.fixture(); raw = files['collector.tap']
        line = next(line for line in raw.splitlines() if line.startswith(b'ok '))
        files['collector.tap'] += line + b'\n'; self.reject(files)

    def test_tap_extra_nested_result_is_not_ignored(self):
        files = self.fixture(); files['subscription-dom.tap'] += b'  ok 1 - invented\n'; self.reject(files)

    def test_tap_skip_todo_cancelled_and_bailout_are_never_pass(self):
        for change in (b'# skip unavailable\n', b'# TODO later\n', b'not ok 99 - fail\n', b'Bail out!\n'):
            files = self.fixture(); files['collector.tap'] += change; self.reject(files)

    def test_tap_forged_or_duplicate_summary_plan_and_version_are_rejected(self):
        for old, new in [(b'# fail 0', b'# fail 1'), (b'1..12', b'1..13'),
                         (b'TAP version 13', b'TAP version 14'), (b'# tests 12', b'# tests 12\n# tests 12')]:
            files = self.fixture(); files['collector.tap'] = files['collector.tap'].replace(old, new); self.reject(files)

    def test_tap_wrong_frozen_name_cannot_be_rebaselined_by_report_sha(self):
        files = self.fixture(); files['collector.tap'] = files['collector.tap'].replace(b'status diagnostic parser', b'changed diagnostic parser')
        self.reject(files)

    def test_frontend_duplicate_or_extra_names_cannot_pass_fixed_twelve(self):
        for change in ('duplicate', 'extra', 'replace'):
            files = self.fixture(); value = C.decoded(files['frontend.json'])
            if change == 'duplicate': value['names'][1] = value['names'][0]
            elif change == 'extra': value['names'].append('synthetic extra')
            else: value['names'][0] = 'synthetic replaced'
            files['frontend.json'] = encoded(value); self.reject(files)

    def test_frontend_boolean_totals_extra_fields_and_real_browser_claims_are_rejected(self):
        for key, value in [('failed', False), ('passed', True), ('realBrowserProof', True), ('secret', 'SYNTHETIC')]:
            files = self.fixture(); changed = C.decoded(files['frontend.json']); changed[key] = value
            files['frontend.json'] = encoded(changed); self.reject(files)

    def test_python_duplicate_run_is_rejected_even_with_correct_summary(self):
        files = self.fixture(); key = 'python-projection.events.jsonl'; rows = files[key].splitlines(keepends=True)
        rows[1] = rows[0]; files[key] = b''.join(rows); self.reject(files)

    def test_python_missing_or_reordered_success_is_not_a_pass(self):
        for change in ('missing', 'reordered'):
            files = self.fixture(); key = 'artifact-checker.events.jsonl'; rows = files[key].splitlines(keepends=True)
            if change == 'missing': del rows[1]
            else: rows[0], rows[1] = rows[1], rows[0]
            files[key] = b''.join(rows); self.reject(files)

    def test_python_all_failure_skip_and_unexpected_events_are_rejected(self):
        for event in ('FAIL', 'ERROR', 'SKIP', 'EXPECTED_FAILURE', 'UNEXPECTED_SUCCESS', 'SUBTEST_ERROR'):
            files = self.fixture(); files['python-projection.events.jsonl'] = files['python-projection.events.jsonl'].replace(
                b'"event":"PASS"', ('"event":"' + event + '"').encode(), 1)
            self.reject(files)

    def test_python_summary_forgery_boolean_and_duplicate_summary_are_rejected(self):
        for change in ('count', 'boolean', 'extra'):
            files = self.fixture(); key = 'python-projection.events.jsonl'; rows = files[key].splitlines(keepends=True)
            value = C.decoded(rows[-1])
            if change == 'count': value['testsPassed'] = 11
            elif change == 'boolean': value['skipped'] = False
            else: rows.append(rows[-1])
            if change != 'extra': rows[-1] = encoded(value)
            files[key] = b''.join(rows); self.reject(files)

    def test_python_text_log_must_agree_with_every_success_event(self):
        for change in (b'not ok', b'skipped', b'FAILED'):
            files = self.fixture(); files['artifact-checker.log'] = files['artifact-checker.log'].replace(b' ... ok', b' ... ' + change, 1)
            self.reject(files)

    def test_derived_original_output_sha_cannot_substitute_for_original_bytes(self):
        files = self.fixture(); value = C.recompute(files)
        value['reports']['collector']['originalOutputSHA256'] = 'a' * 64
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaises(ValueError): C.verify_tree(self.tree(parent, files), encoded(value))

    def test_derived_report_extra_fields_and_boolean_integer_substitution_are_rejected(self):
        for key, value in [('skipped', False), ('testsRun', True), ('browserE2EProven', 0), ('extra', 'SYNTHETIC')]:
            files = self.fixture(); report = C.recompute(files); report[key] = value
            with tempfile.TemporaryDirectory() as parent:
                with self.assertRaises(ValueError): C.verify_tree(self.tree(parent, files), encoded(report))

    def test_nonzero_exit_timeout_partial_capture_and_extra_execution_fields_are_rejected(self):
        for key, value in [('exitCode', 1), ('exitCode', False), ('outcome', 'TIMED_OUT'), ('captureComplete', False), ('extra', 0)]:
            files = self.fixture(); execution = C.decoded(files['execution.json']); execution['groups']['collector'][key] = value
            files['execution.json'] = encoded(execution); self.reject(files)
        import run_status_diagnostic_contracts as runner
        for timed_out in (False, True):
            with tempfile.TemporaryDirectory() as parent:
                store = runner.RawStore(pathlib.Path(parent) / 'raw')
                child = mock.Mock(stdout=io.BytesIO(b'SYNTHETIC_FAILED_ORIGINAL\n'))
                child.poll.return_value = -9 if timed_out else 1
                child.wait.side_effect = ([runner.subprocess.TimeoutExpired('SYNTHETIC', 60), -9]
                                          if timed_out else [1])
                with mock.patch.object(runner.subprocess, 'Popen', return_value=child):
                    runner.execute(['SYNTHETIC_NOT_EXECUTED'], store, 'collector')
                self.assertEqual(store.files['collector.tap'], b'SYNTHETIC_FAILED_ORIGINAL\n')
                self.assertEqual((store.root / 'collector.tap').read_bytes(), store.files['collector.tap'])
                self.assertEqual(store.execution['collector']['outcome'], 'TIMED_OUT' if timed_out else 'RETURNED')
                self.assertEqual(store.execution['collector']['captureComplete'], not timed_out)

    def test_manifest_missing_extra_and_duplicate_rows_are_rejected(self):
        for change in ('missing', 'extra', 'duplicate'):
            files = self.fixture(); report = encoded(C.recompute(files))
            with tempfile.TemporaryDirectory() as parent:
                root = self.tree(parent, files); manifest = C.decoded((root / 'manifest.json').read_bytes())
                if change == 'missing': manifest['files'].pop()
                else:
                    row = copy.deepcopy(manifest['files'][0])
                    if change == 'extra': row['path'] = 'extra.tap'
                    manifest['files'].append(row)
                (root / 'manifest.json').write_bytes(encoded(manifest))
                with self.assertRaises(ValueError): C.verify_tree(root, report)

    def test_manifest_wrong_digest_size_and_boolean_storage_are_rejected(self):
        for key, value in [('sha256', 'b' * 64), ('bytes', 1), ('bytes', True), ('stored', 1)]:
            files = self.fixture(); report = encoded(C.recompute(files))
            with tempfile.TemporaryDirectory() as parent:
                root = self.tree(parent, files); manifest = C.decoded((root / 'manifest.json').read_bytes())
                manifest['files'][0][key] = value; (root / 'manifest.json').write_bytes(encoded(manifest))
                with self.assertRaises(ValueError): C.verify_tree(root, report)

    def test_genuine_empty_omission_preserves_empty_digest_but_never_yields_pass(self):
        files = self.fixture(); report = encoded(C.recompute(files)); files['collector.tap'] = b''
        with tempfile.TemporaryDirectory() as parent:
            root = self.tree(parent, files)
            self.assertFalse((root / 'collector.tap').exists())
            with self.assertRaises(ValueError): C.verify_tree(root, report)
        # Exercise custody on a mocked failed child, not an original suite.
        import run_status_diagnostic_contracts as runner
        with tempfile.TemporaryDirectory() as parent:
            store = runner.RawStore(pathlib.Path(parent) / 'raw')
            child = mock.Mock(stdout=io.BytesIO(b''))
            child.wait.return_value = 1; child.poll.return_value = 1
            with mock.patch.object(runner.subprocess, 'Popen', return_value=child):
                runner.execute(['SYNTHETIC_NOT_EXECUTED'], store, 'collector')
            self.assertEqual(store.files['collector.tap'], b'')
            self.assertFalse((store.root / 'collector.tap').exists())
            self.assertEqual(store.execution['collector']['exitCode'], 1)
            for name, raw in self.fixture().items():
                if name not in {'collector.tap', 'execution.json'}: store.write(name, raw)
            groups = C.decoded(self.fixture()['execution.json'])['groups']
            store.execution.update({p: row for p, row in groups.items() if p != 'collector'})
            store.finish()
            manifest = C.decoded((store.root / 'manifest.json').read_bytes())
            row = next(r for r in manifest['files'] if r['path'] == 'collector.tap')
            self.assertEqual(row, dict(path='collector.tap', bytes=0, sha256=C.sha(b''), stored=False))
            with self.assertRaises(ValueError): C.verify_tree(store.root, report)

    def test_extra_tree_file_directory_and_hardlink_are_rejected(self):
        for change in ('file', 'directory', 'hardlink'):
            files = self.fixture(); report = encoded(C.recompute(files))
            with tempfile.TemporaryDirectory() as parent:
                root = self.tree(parent, files)
                if change == 'file': (root / 'extra').write_bytes(b'SYNTHETIC')
                elif change == 'directory': (root / 'extra').mkdir()
                else: os.link(root / 'collector.tap', pathlib.Path(parent) / 'outside-link')
                with self.assertRaises(ValueError): C.verify_tree(root, report)

    def test_oversized_invalid_utf8_and_symlink_inputs_are_rejected(self):
        for raw in (b'X' * (C.MAX_BYTES + 1), b'\xff'):
            files = self.fixture(); files['frontend.json'] = raw; self.reject(files)
        with tempfile.TemporaryDirectory() as parent:
            target = pathlib.Path(parent) / 'target'; target.write_bytes(b'SYNTHETIC')
            link = pathlib.Path(parent) / 'link'
            # Mock the lstat mode only; creating Windows symlinks requires a
            # host privilege and is not part of this pure fixture acceptance.
            with mock.patch.object(pathlib.Path, 'lstat', return_value=mock.Mock(st_mode=0o120777)):
                with self.assertRaises(ValueError): C.read_file(link)
        import run_status_diagnostic_contracts as runner
        stream = runner.BoundedText(); stream.write('S' * C.MAX_BYTES)
        with self.assertRaises(ValueError): stream.write('X')
        self.assertFalse(stream.complete); self.assertEqual(len(stream.getvalue()), C.MAX_BYTES)
        with tempfile.TemporaryDirectory() as parent:
            store = runner.RawStore(pathlib.Path(parent) / 'raw')
            child = mock.Mock(stdout=io.BytesIO(b'S' * (C.MAX_BYTES + 1)))
            child.wait.return_value = -9; child.poll.return_value = -9
            with mock.patch.object(runner.subprocess, 'Popen', return_value=child):
                runner.execute(['SYNTHETIC_NOT_EXECUTED'], store, 'collector')
            self.assertEqual(len(store.files['collector.tap']), C.MAX_BYTES)
            self.assertEqual(store.execution['collector']['outcome'], 'OUTPUT_LIMIT')
            self.assertFalse(store.execution['collector']['captureComplete'])
            child.kill.assert_called_once()

    def test_cli_requires_new_report_outside_original_tree_and_never_overwrites(self):
        files = self.fixture()
        with tempfile.TemporaryDirectory() as parent:
            root = self.tree(parent, files); contracts = pathlib.Path(parent) / 'contracts.json'
            contracts.write_bytes(encoded(C.recompute(files))); output = pathlib.Path(parent) / 'verified.json'
            args = ['checker', '--raw-root', str(root), '--contracts-report', str(contracts), '--report', str(output)]
            with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()): C.main()
            with mock.patch.object(sys, 'argv', args):
                with self.assertRaises(ValueError): C.main()
            args[-1] = str(root / 'not-allowed.json')
            with mock.patch.object(sys, 'argv', args):
                with self.assertRaises(ValueError): C.main()
        import run_status_diagnostic_contracts as runner
        with tempfile.TemporaryDirectory() as parent:
            store = runner.RawStore(pathlib.Path(parent) / 'raw')
            with self.assertRaises(FileExistsError): runner.RawStore(store.root)
            store.write('collector.tap', b'SYNTHETIC')
            with self.assertRaises(ValueError): store.write('collector.tap', b'SUBSTITUTED')
            self.assertEqual((store.root / 'collector.tap').read_bytes(), b'SYNTHETIC')


if __name__ == '__main__':
    unittest.main()
