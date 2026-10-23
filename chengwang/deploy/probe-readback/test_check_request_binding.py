"""Independent verifier's pure adversarial contracts, not real browser runs."""
import copy
import json
import unittest

import check_request_binding as C
import probe_request_binding as D
import probe_status_diagnostics as OLD
from test_probe_request_binding import encoded, reseal, trace

COMMIT = 'a' * 40
FIXTURE = 'b' * 32


def originals(rows, engine='chrome-cdp'):
    old_rows = []
    for row in rows:
        event = row['e']
        if event == 'DOCUMENT':
            old_rows.append(dict(v=1, e='DOCUMENT', x=10, w=100, h=1, l=1))
        elif event == 'JS':
            item = {k: v for k, v in row.items() if k not in {'q', 's', 'c'}}
            item['u'] = 1000 + len(old_rows)
            if 'cause' in item: item['c'] = item.pop('cause')
            old_rows.append(item)
        elif event.startswith('NET_'):
            item = {k: v for k, v in row.items() if k not in {'q', 's', 'n', 'd', 'm', 'r', 'h'}}
            item['s'] = row['n']
            if event == 'NET_START': item.update(h=1, l=1)
            if event == 'NET_FAIL': item['c'] = item.pop('canceled'); item['ec'] = item.pop('error')
            old_rows.append(item)
    for i, row in enumerate(old_rows): row['q'] = i + 1
    old_rows.append(dict(v=1, e='META', q=len(old_rows) + 1,
                         js=sum(r['e'] == 'JS' for r in old_rows),
                         net=sum(r['e'] == 'NET_START' for r in old_rows), rej=0, over=False))
    old = OLD.project(b'\n'.join((OLD.PREFIX + json.dumps(r, separators=(',', ':'))).encode() for r in old_rows))
    old.update(sourceCommit=COMMIT, engine=engine, clockDomains=C.CLOCKS)
    return json.dumps(old, separators=(',', ':')).encode()


def fixture(rows=None, engine='chrome-cdp'):
    rows = reseal(trace() if rows is None else rows)
    old = originals(rows, engine)
    value = D.project(encoded(rows))
    value.update(sourceCommit=COMMIT, engine=engine, fixtureId=FIXTURE, clockDomains=C.CLOCKS,
                 oldDiagnosticSHA256=C.sha(old))
    sources = [dict(path=p, bytes=10, sha256='c' * 64) for p in sorted(C.REQUIRED_SOURCES)]
    copies = [copy.deepcopy(r) for r in sources if r['path'] in C.REQUIRED_COPIES]
    build = dict(schema='chengwang.probe-browser-build/v1', sourceCommit=COMMIT, fixtureId=FIXTURE,
                 engine=engine, production=False, sourceFilesBefore=sources, sourceFilesAfter=copy.deepcopy(sources),
                 copiedInputs=copies, hostBefore={'test': 1}, hostAfter={'test': 1},
                 buildScope='TRUSTED_CI_INPUTS_NOT_INDEPENDENT_REBUILD',
                 backendSupervisorMode='WRAPPER_IMPORTS_NATIVE_HELPERS')
    return value, old, build


class RequestBindingVerifierContracts(unittest.TestCase):
    def check(self, args, engine='chrome-cdp'): return C.verify(*args, COMMIT, engine)

    def reject(self, rows):
        with self.assertRaises((D.Rejected, OLD.Rejected)): self.check(fixture(rows))

    def test_complete_bijection_both_engines_never_proves_browser(self):
        for engine in ('chrome-cdp', 'playwright'):
            report = self.check(fixture(engine=engine), engine)
            self.assertTrue(report['requestIdentityBindingProven'])
            self.assertEqual(report['boundRequests'], 1)
            for field in ('browserAcceptanceProven', 'cancellationRootCauseProven', 'production', 'rawOnWireHeaderAttestationProven'):
                self.assertIs(report[field], False)
            self.assertEqual(report['authorization'], 'BLOCKED')

    def test_bound_network_failure_is_observation_not_acceptance(self):
        rows = trace(); row = next(r for r in rows if r['e'] == 'NET_FINISH')
        row.update(e='NET_FAIL', canceled='YES', error='ABORTED')
        report = self.check(fixture(rows))
        self.assertTrue(report['requestIdentityBindingProven']); self.assertEqual(report['networkFailures'], 1)
        self.assertFalse(report['browserAcceptanceProven'])

    def test_headers_time_may_exceed_terminal_and_cancel_may_follow_finally(self):
        report = self.check(fixture())
        self.assertTrue(report['requestIdentityBindingProven']); self.assertEqual(report['cancellationResults'], 1)

    def test_network_dispatch_may_precede_send_console_delivery(self):
        rows = trace(); send = next(r for r in rows if r['e'] == 'SEND')
        rows.remove(send); rows.insert(next(i for i, r in enumerate(rows) if r['e'] == 'NET_HEADERS'), send)
        self.assertTrue(self.check(fixture(rows))['requestIdentityBindingProven'])

    def test_missing_network_is_explicit_unbound_not_invented(self):
        rows = [r for r in trace() if not r['e'].startswith('NET_')]
        report = self.check(fixture(rows))
        self.assertFalse(report['requestIdentityBindingProven']); self.assertEqual(report['unboundAttempts'], 1)
        self.assertEqual(report['boundRequests'], 0)

    def test_network_without_send_is_rejected(self):
        self.reject([r for r in trace() if r['e'] != 'SEND'])

    def test_duplicate_send_is_rejected(self):
        rows = trace(); rows.insert(7, copy.deepcopy(rows[6])); self.reject(rows)

    def test_many_networks_for_one_request_is_rejected(self):
        rows = trace(); duplicate = copy.deepcopy(next(r for r in rows if r['e'] == 'NET_START'))
        duplicate.update(n=2, x=101, w=200001); rows.insert(8, duplicate); self.reject(rows)

    def test_wrong_context_or_frame_is_rejected(self):
        for event, field in [('SEND', 'c'), ('NET_START', 'h'), ('CONTEXT', 'h')]:
            rows = trace(); next(r for r in rows if r['e'] == event)[field] = 2; self.reject(rows)

    def test_wrong_session_and_document_nonce_alias_are_rejected(self):
        value, old, build = fixture(); value['records'][0]['s'] = 2
        with self.assertRaises(D.Rejected): self.check((value, old, build))
        rows = trace(); next(r for r in rows if r['e'] == 'SEND')['d'] = 2; self.reject(rows)

    def test_missing_or_duplicate_document_refuses_proof(self):
        self.reject([r for r in trace() if r['e'] != 'DOCUMENT'])
        rows = trace(); rows.insert(2, copy.deepcopy(rows[1])); self.reject(rows)

    def test_nondefault_or_ambiguous_execution_context_is_rejected(self):
        rows = trace(); next(r for r in rows if r['e'] == 'CONTEXT')['default'] = False; self.reject(rows)
        rows = trace(); extra = copy.deepcopy(rows[2]); extra['c'] = 2; rows.insert(3, extra); self.reject(rows)

    def test_send_before_original_begin_is_rejected(self):
        rows = trace(); send = next(r for r in rows if r['e'] == 'SEND'); rows.remove(send); rows.insert(4, send)
        self.reject(rows)

    def test_terminal_before_network_start_is_rejected(self):
        rows = trace(); terminal = next(r for r in rows if r['e'] == 'NET_FINISH')
        rows.remove(terminal); rows.insert(7, terminal); self.reject(rows)

    def test_duplicate_network_headers_are_rejected(self):
        rows = trace(); row = next(r for r in rows if r['e'] == 'NET_HEADERS')
        rows.insert(rows.index(row) + 1, copy.deepcopy(row)); self.reject(rows)

    def test_duplicate_or_mixed_terminal_is_rejected(self):
        for failure in (False, True):
            rows = trace(); row = next(r for r in rows if r['e'] == 'NET_FINISH'); extra = copy.deepcopy(row)
            if failure: extra.update(e='NET_FAIL', canceled='NO', error='OTHER')
            rows.insert(rows.index(row) + 1, extra); self.reject(rows)

    def test_terminal_timestamp_before_start_is_rejected(self):
        rows = trace(); next(r for r in rows if r['e'] == 'NET_FINISH')['x'] = 99; self.reject(rows)

    def test_missing_network_terminal_is_incomplete(self):
        report = self.check(fixture([r for r in trace() if r['e'] != 'NET_FINISH']))
        self.assertFalse(report['requestIdentityBindingProven']); self.assertEqual(report['openNetworks'], 1)

    def test_missing_cancel_settlement_or_finally_is_incomplete(self):
        for event in ('CANCEL_RESULT', 'FINALLY'):
            rows = [r for r in trace() if not (r['e'] == event or r['e'] == 'JS' and r['j'] == event)]
            self.assertFalse(self.check(fixture(rows))['requestIdentityBindingProven'])

    def test_settlement_without_original_cancel_or_duplicate_result_rejected(self):
        self.reject([r for r in trace() if not (r['e'] == 'JS' and r['j'] == 'CANCEL')])
        rows = trace(); row = next(r for r in rows if r['e'] == 'CANCEL_RESULT')
        rows.insert(rows.index(row) + 1, copy.deepcopy(row)); self.reject(rows)
        for outcome in ('REJECTED', 'THREW', 'NO_BODY'):
            rows = trace(); next(r for r in rows if r['e'] == 'CANCEL_RESULT')['o'] = outcome
            self.assertTrue(self.check(fixture(rows))['requestIdentityBindingProven'])

    def test_old_raw_sha_source_engine_and_scope_cannot_be_substituted(self):
        for field, val in [('sourceCommit', 'd' * 40), ('engine', 'playwright'), ('fixtureId', 'bad'),
                           ('clockDomains', 'merged'), ('oldDiagnosticSHA256', 'e' * 64)]:
            value, old, build = fixture(); value[field] = val
            with self.assertRaises(D.Rejected): self.check((value, old, build))
        value, old, build = fixture()
        with self.assertRaises(D.Rejected): self.check((value, old + b' ', build))

    def test_old_js_and_network_observations_are_independently_bound(self):
        for event, field, val in [('JS', 't', 99), ('NET_START', 'w', 200001), ('NET_HEADERS', 'st', 201)]:
            value, old, build = fixture(); prior = json.loads(old)
            next(r for r in prior['records'] if r['e'] == event and (event != 'JS' or r['j'] == 'BEGIN'))[field] = val
            old = json.dumps(prior, separators=(',', ':')).encode(); value['oldDiagnosticSHA256'] = C.sha(old)
            with self.assertRaises(D.Rejected): self.check((value, old, build))

    def test_build_missing_changed_duplicate_or_uncopied_helpers_rejected(self):
        for kind in ('absent', 'duplicate', 'changed', 'source', 'host', 'fixture'):
            value, old, build = fixture()
            if kind == 'absent': build['copiedInputs'].pop()
            elif kind == 'duplicate': build['copiedInputs'].append(copy.deepcopy(build['copiedInputs'][0]))
            elif kind == 'changed': build['copiedInputs'][0]['sha256'] = 'd' * 64
            elif kind == 'source': build['sourceFilesAfter'][0]['bytes'] += 1
            elif kind == 'host': build['hostAfter']['test'] = 2
            else: build['fixtureId'] = 'd' * 32
            with self.assertRaises(D.Rejected): self.check((value, old, build))
        value, old, _ = fixture()
        with self.assertRaises(D.Rejected): self.check((value, old, None))

    def test_self_reported_completeness_and_unknown_fields_are_not_trusted(self):
        for field, val in [('complete', False), ('sinkClosed', False), ('eventCount', True),
                           ('browserAcceptanceProven', True), ('cancellationRootCauseProven', True), ('rawSecret', 'SECRET')]:
            value, old, build = fixture(); value[field] = val
            with self.assertRaises(D.Rejected): self.check((value, old, build))
        value, old, build = fixture(); value['records'][-1]['overflow'] = True; value['complete'] = False
        self.assertFalse(self.check((value, old, build))['requestIdentityBindingProven'])


if __name__ == '__main__': unittest.main()
