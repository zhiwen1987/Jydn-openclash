"""Synthetic CPU contracts only, never browser or production evidence."""
import copy
import json
import pathlib
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

import status_network_lifecycle as D
import check_status_network_lifecycle as C
import run_probe_browser as R
from test_check_request_binding import fixture as binding_fixture, COMMIT, FIXTURE
from test_probe_request_binding import trace, reseal


def rows(failed=False):
    out = [dict(v=1, e='SESSION', q=1, s=1),
           dict(v=1, e='CONTEXT', q=2, s=1, k='DOCUMENT', c=None, phase='RUNNING'),
           dict(v=1, e='CONTEXT', q=3, s=1, k='DEFAULT_CREATED', c=1, phase='RUNNING')]
    f = dict(length=455, transfer=None, encoding=None, connection=None)
    for n in range(1, 8):
        out.append(dict(v=1, e='REQUEST', q=len(out)+1, s=1, n=n, m=1, r=n, startUs=n*1000000,
            responseUs=n*1000000+1000, endUs=n*1000000+2000,
            response=dict(status=200, protocol='http/1.1', connection=1, reused='YES', diskCache='NOT_OBSERVED',
                          serviceWorker='NO', prefetchCache='NOT_OBSERVED', framing=copy.deepcopy(f)),
            extra=None, chunks=1, dataBytes=455, encodedBytes=455,
            terminal='FAILED' if failed and n == 4 else 'FINISHED',
            canceled='YES' if failed and n == 4 else None, error='ABORTED' if failed and n == 4 else None,
            blocked=None, cors=None, hasExtra='NO'))
    out.append(dict(v=1, e='META', q=len(out)+1, s=1, requests=7, contexts=2, rejected=0, overflow=False, sinkFailed=False))
    return out


def encoded(values): return b''.join(D.PREFIX.encode() + D.encoded(r) + b'\n' for r in values)


def full_fixture(failed=False):
    # Reuse the unchanged binding adversarial fixture, then make seven distinct
    # complete identities. These are synthetic observations, not an accepted run.
    base = trace(); segment = [r for r in base if r.get('e') not in {'SESSION', 'DOCUMENT', 'CONTEXT', 'META'}]
    prefix = [r for r in base if r.get('e') in {'SESSION', 'DOCUMENT', 'CONTEXT'}]
    expanded = copy.deepcopy(prefix)
    for n in range(1, 8):
        for original in segment:
            r = copy.deepcopy(original)
            if r.get('e') == 'JS' and r.get('j') == 'MOUNT':
                if n != 1: continue
            if 'r' in r and r['r'] != 0: r['r'] = n
            if 't' in r and r.get('j') != 'MOUNT': r['t'] += n*100
            if 'n' in r and r['e'].startswith('NET_'): r['n'] = n
            if 'x' in r:
                r['x'] = n*1000000 + (0 if r['e'] == 'NET_START' else 1000 if r['e'] == 'NET_HEADERS' else 2000)
            if failed and n == 4 and r.get('e') == 'NET_FINISH':
                r['e'] = 'NET_FAIL'; r['canceled'] = 'YES'; r['error'] = 'ABORTED'
            expanded.append(r)
    binding, old, build = binding_fixture(reseal(expanded))
    for name in C.REQUIRED_SOURCES - {r['path'] for r in build['sourceFilesBefore']}:
        build['sourceFilesBefore'].append(dict(path=name, bytes=10, sha256='c'*64))
    build['sourceFilesBefore'].sort(key=lambda r:r['path']); build['sourceFilesAfter'] = copy.deepcopy(build['sourceFilesBefore'])
    build['copiedInputs'] = [copy.deepcopy(r) for r in build['sourceFilesBefore'] if r['path'] in C.REQUIRED_COPIES | C.RB.REQUIRED_COPIES]
    raw = json.dumps(binding, separators=(',', ':')).encode()
    value = D.project(encoded(rows(failed)))
    value.update(sourceCommit=COMMIT, engine='chrome-cdp', fixtureId=FIXTURE, bindingSHA256=C.sha(raw), clockDomains=C.RB.CLOCKS)
    return value, raw, old, build


class LifecycleReaderTests(unittest.TestCase):
    def test_01_complete_seven_identity_projection_is_not_acceptance(self):
        p = D.project(encoded(rows()))
        self.assertTrue(p['complete']); self.assertFalse(p['browserAcceptanceProven']); self.assertFalse(p['cancellationRootCauseProven'])

    def test_02_complete_metadata_can_include_failed_network(self):
        p = D.project(encoded(rows(True))); self.assertTrue(p['complete'])
        self.assertEqual(sum(r.get('terminal') == 'FAILED' for r in p['records']), 1)

    def test_03_absent_stream_never_fabricates_zero_health(self):
        p = D.project(b''); self.assertFalse(p['complete']); self.assertFalse(p['sinkClosed'])
        self.assertIn('SEVEN_REQUESTS', p['incompleteReasons'])

    def test_04_missing_response_data_terminal_and_expected_extra_are_incomplete(self):
        for change, reason in ((dict(response=None, responseUs=None), 'RESPONSE'),
            (dict(chunks=None, dataBytes=None, encodedBytes=None), 'DATA'),
            (dict(terminal='MISSING', endUs=None), 'TERMINAL'), (dict(hasExtra='YES'), 'EXPECTED_EXTRA'),
            (dict(hasExtra='NOT_OBSERVED'), 'EXTRA_EXPECTATION')):
            with self.subTest(reason=reason):
                r = rows(); r[3].update(change); p = D.project(encoded(r))
                self.assertFalse(p['complete']); self.assertIn(reason, p['incompleteReasons'])

    def test_05_missing_optional_cache_values_are_explicit_not_observed(self):
        p = D.project(encoded(rows())); self.assertEqual(p['records'][3]['response']['diskCache'], 'NOT_OBSERVED')

    def test_06_unknown_secret_fields_duplicate_json_keys_and_foreign_lines_are_suppressed(self):
        raw = encoded(rows())
        for bad in (b'PRIVATE_SECRET\n', D.PREFIX.encode()+b'{"v":1,"v":1}\n',
                    D.PREFIX.encode()+b'{"url":"https://PRIVATE"}\n'):
            p = D.project(raw+bad); self.assertFalse(p['complete']); self.assertEqual(p['rejectedLines'], 1)
            self.assertNotIn('PRIVATE', json.dumps(p))

    def test_07_noncanonical_trailing_overlong_and_nan_values_rejected(self):
        for raw in (encoded(rows()).replace(b'"v":1', b'"v":true', 1),
                    encoded(rows()).replace(b'"q":1', b'"q":NaN', 1), b'X'*4097+b'\n'):
            self.assertFalse(D.project(raw)['complete'])

    def test_08_body_limits_and_bool_numbers_rejected(self):
        for value in (True, -1, 1048577, 1.5):
            r = rows(); r[3]['dataBytes'] = value; self.assertFalse(D.project(encoded(r))['complete'])

    def test_09_truncated_sink_overflow_and_collector_rejection_are_incomplete(self):
        for key, v in (('overflow', True), ('sinkFailed', True), ('rejected', 1)):
            r = rows(); r[-1][key] = v; self.assertFalse(D.project(encoded(r))['complete'])
        self.assertFalse(D.project(encoded(rows()[:-1]))['complete'])

    def test_10_duplicate_identity_order_or_request_count_cannot_be_complete(self):
        r = rows(); r[4]['r'] = 1; self.assertFalse(D.project(encoded(r))['complete'])
        r = rows(); r[3]['n'] = 2; self.assertFalse(D.project(encoded(r))['complete'])
        r = rows(); del r[3];
        for n, v in enumerate(r, 1): v['q'] = n
        self.assertFalse(D.project(encoded(r))['complete'])

    def test_11_compression_preserves_decoded_and_encoded_difference(self):
        r = rows(); r[3]['encodedBytes'] = 40; r[3]['response']['framing'].update(length=40, encoding='gzip')
        p = D.project(encoded(r)); self.assertTrue(p['complete']); self.assertEqual(p['records'][3]['dataBytes'], 455)

    def test_12_framing_closed_enums_and_nested_shape_reject_secrets(self):
        for f in (dict(length='PRIVATE'), dict(transfer='PRIVATE'), dict(secret='PRIVATE')):
            r = rows(); r[3]['response']['framing'].update(f); p = D.project(encoded(r))
            self.assertFalse(p['complete']); self.assertNotIn('PRIVATE', json.dumps(p))

    def test_13_terminal_cannot_contain_fake_failure_or_fictitious_timestamp(self):
        for changes in (dict(terminal='FAILED'), dict(endUs=None), dict(endUs=1), dict(canceled='YES')):
            r = rows(); r[3].update(changes); self.assertFalse(D.project(encoded(r))['complete'])

    def test_14_stream_byte_limit_is_strict(self):
        with self.assertRaises(D.Rejected): D.project(b'x'*(D.MAX_BYTES+1))


class LifecycleCheckerTests(unittest.TestCase):
    def test_15_independent_binding_match_preserves_network_failure(self):
        for failed in (False, True):
            a = full_fixture(failed); p = C.verify(*a, COMMIT, 'chrome-cdp')
            self.assertTrue(p['diagnosticComplete']); self.assertEqual(p['networkFailures'], int(failed))
            self.assertFalse(p['browserAcceptanceProven']); self.assertFalse(p['oldEightZeroErrorCountersRelaxed'])

    def test_16_binding_hash_source_commit_engine_and_fixture_tamper_rejected(self):
        for key, v in (('bindingSHA256', '0'*64), ('sourceCommit', 'd'*40), ('engine', 'playwright'), ('fixtureId', 'd'*32)):
            a = full_fixture(); a[0][key] = v
            with self.subTest(key=key), self.assertRaises(Exception): C.verify(*a, COMMIT, 'chrome-cdp')

    def test_17_cross_binding_timestamp_identity_status_and_terminal_tamper_rejected(self):
        for changes in (dict(startUs=1000001), dict(r=88), dict(endUs=1002001), dict(terminal='FAILED', canceled='YES', error='ABORTED')):
            a = full_fixture(); a[0]['records'][3].update(changes)
            with self.subTest(changes=changes), self.assertRaises(Exception): C.verify(*a, COMMIT, 'chrome-cdp')

    def test_18_fake_completeness_success_and_missing_source_binding_rejected(self):
        a = full_fixture(); a[0]['browserAcceptanceProven'] = True
        with self.assertRaises(Exception): C.verify(*a, COMMIT, 'chrome-cdp')
        a = full_fixture(); a[3]['copiedInputs'] = [r for r in a[3]['copiedInputs'] if r['path'] not in C.REQUIRED_COPIES]
        with self.assertRaises(Exception): C.verify(*a, COMMIT, 'chrome-cdp')


class LifecycleRunnerTests(unittest.TestCase):
    def test_19_safe_export_uses_evidence_top_level_not_old_lab_closed_set(self):
        bundle, output = pathlib.Path('/private/bundle'), pathlib.Path('/public/evidence/lab')
        helper = types.SimpleNamespace(MAX_BYTES=131072, project=mock.Mock(return_value=dict(complete=False)))
        with mock.patch.object(R, 'load_status_network_lifecycle', return_value=helper), \
             mock.patch.object(pathlib.Path, 'exists', return_value=True), \
             mock.patch.object(R.N, 'stable_read', side_effect=lambda p,*a: (b'BINDING' if p.name=='request-binding.json' else b'PRIVATE', None)), \
             mock.patch.object(R.N, 'exclusive') as exclusive:
            R.public_status_network_lifecycle(bundle, output, COMMIT, 'chrome-cdp', FIXTURE)
        path, raw = exclusive.call_args.args
        self.assertEqual(path, output.parent/'status-network-lifecycle.json'); self.assertNotIn(b'PRIVATE', raw)
        self.assertEqual(json.loads(raw)['bindingSHA256'], R.N.sha(b'BINDING'))

    def test_20_missing_private_stream_exports_explicit_incomplete(self):
        with mock.patch.object(pathlib.Path, 'exists', return_value=False), mock.patch.object(R.N, 'exclusive') as exclusive:
            R.public_status_network_lifecycle(pathlib.Path('/private'), pathlib.Path('/public/lab'), COMMIT, 'chrome-cdp', FIXTURE)
        value = json.loads(exclusive.call_args.args[1]); self.assertFalse(value['complete']); self.assertFalse(value['sinkClosed'])

    def test_21_runner_owns_independent_readonly_contract_consumption_and_source_copies(self):
        source = pathlib.Path(R.__file__).read_text(encoding='utf8')
        self.assertIn('str(lifecycle_descriptor(bundle))', source)
        self.assertIn('pass_fds=(binding, lifecycle)', source)
        self.assertIn("'status-network-lifecycle.mjs'", source)
        self.assertIn("'status_network_lifecycle.py'", source)
        self.assertIn('alias / contract', source)
        self.assertEqual(R.STATUS_DIAGNOSTICS.MAX_LOG_BYTES, 329728)

    def test_22_descriptor_rejects_wrong_owner_mode_path_alias_or_existing_data(self):
        bundle = pathlib.Path('/private/bundle')
        defaults = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_size=0)
        for changes, rawfd, target, other in (({}, '8', str(bundle/'logs/status-network.private'), '7'),
             ({'st_uid': 10001}, '8', str(bundle/'logs/status-network.private'), '7'),
             ({'st_nlink': 2}, '8', str(bundle/'logs/status-network.private'), '7'),
             ({'st_size': 1}, '8', str(bundle/'logs/status-network.private'), '7'),
             ({'st_mode': stat.S_IFREG | 0o640}, '8', str(bundle/'logs/status-network.private'), '7'),
             ({}, '8', '/private/OTHER', '7'), ({}, '8', str(bundle/'logs/status-network.private'), '8'),
             ({}, '08', str(bundle/'logs/status-network.private'), '7')):
            info = types.SimpleNamespace(**{**defaults, **changes})
            valid = not changes and rawfd == '8' and target.endswith('status-network.private') and other == '7'
            with self.subTest(changes=changes, rawfd=rawfd, other=other), \
                 mock.patch.dict(R.os.environ, {R.LIFECYCLE_FD_ENV: rawfd, R.BINDING_FD_ENV: other}, clear=True), \
                 mock.patch.object(R.os, 'fstat', return_value=info), mock.patch.object(R.os, 'readlink', return_value=target), \
                 mock.patch.object(R.os, 'set_inheritable'):
                if valid: self.assertEqual(R.lifecycle_descriptor(bundle), 8)
                else:
                    with self.assertRaises(Exception): R.lifecycle_descriptor(bundle)


class LifecycleCliTests(unittest.TestCase):
    def exercise(self, kind='complete'):
        # A synthetic filesystem/Git seam validates fail-closed host custody;
        # these tests make no claim about actual checked-in Git or browser data.
        parent = pathlib.Path('D:/CodexData/workspace') if sys.platform == 'win32' else None
        with tempfile.TemporaryDirectory(prefix='status-network-unit-', dir=parent) as directory:
            base = pathlib.Path(directory); repo = base/'repo'; repo.mkdir(); root = base/'evidence'; root.mkdir()
            (root/'lab/browser').mkdir(parents=True); report = base/'result.json'
            value, binding, old, build = full_fixture()
            if kind == 'incomplete':
                value['records'][3]['hasExtra'] = 'YES'
                p = D.project(encoded(value['records']))
                value.update(p)
            contract = D.load_contract()
            blobs = {p:b'SYNTHETIC' for p in C.REQUIRED_SOURCES}; blobs[C.CONTRACT] = D.encoded(contract)
            for item in build['sourceFilesBefore']:
                blob = blobs[item['path']]; item.update(bytes=len(blob), sha256=C.sha(blob))
            build['sourceFilesAfter'] = copy.deepcopy(build['sourceFilesBefore'])
            build['copiedInputs'] = [copy.deepcopy(r) for r in build['sourceFilesBefore'] if r['path'] in C.REQUIRED_COPIES | C.RB.REQUIRED_COPIES]
            host = {}
            for n, name in enumerate(C.host_helpers()):
                path = base/f'host-{n}.py'; path.write_bytes(blobs[name]); host[name] = path
            if kind == 'host-drift': next(iter(host.values())).write_bytes(b'DRIFT')
            paths = {'sidecar':root/'status-network-lifecycle.json', 'binding':root/'lab/request-binding.json',
                     'old':root/'lab/status-diagnostic.json', 'build':root/'lab/browser/browser-build.json'}
            for name, body in dict(sidecar=D.encoded(value), binding=binding, old=old, build=D.encoded(build)).items(): paths[name].write_bytes(body)
            if kind == 'source-drift': blobs[next(iter(host))] = b'GIT_DRIFT'
            original_read = C.B.read_file; reads = {}
            def read(path, limit=2 << 20):
                raw = original_read(path, limit); reads[path] = reads.get(path, 0)+1
                if kind == 'host-after-drift' and path in host.values() and reads[path] > 1: return raw+b'DRIFT'
                if kind == 'input-after-drift' and path == paths['binding'] and reads[path] > 1: return raw+b'DRIFT'
                return raw
            argv = ['checker', '--evidence-root', str(root), '--repo', str(repo), '--source-commit', COMMIT,
                    '--engine', 'chrome-cdp', '--report', str(report)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(C, 'host_helpers', return_value=host), \
                 mock.patch.object(C.D, 'load_contract', return_value=contract), \
                 mock.patch.object(C.subprocess, 'check_output', side_effect=lambda cmd,**kw: blobs[cmd[-1].split(':',1)[1]]), \
                 mock.patch.object(C.B, 'read_file', side_effect=read):
                if kind == 'complete': C.main()
                else:
                    with self.assertRaises(Exception): C.main()
            if kind in {'complete', 'incomplete'}:
                result = json.loads(report.read_bytes())
                self.assertEqual(result['diagnosticComplete'], kind == 'complete')
                self.assertFalse(result['browserAcceptanceProven']); self.assertTrue(result['hostHelpersMatchedGitAndStable'])
            else: self.assertFalse(report.exists())

    def test_23_cli_binds_host_helpers_and_git_with_stable_inputs(self): self.exercise()
    def test_24_incomplete_report_is_written_but_cli_exits_nonzero(self): self.exercise('incomplete')
    def test_25_host_helper_cannot_drift_from_git_before_execution_check(self): self.exercise('host-drift')
    def test_26_git_binding_cannot_drift_from_captured_manifest(self): self.exercise('source-drift')
    def test_27_host_helper_after_check_mutation_prevents_report(self): self.exercise('host-after-drift')
    def test_28_input_after_check_mutation_prevents_report(self): self.exercise('input-after-drift')


if __name__ == '__main__': unittest.main(verbosity=2)
