"""Frozen pure synthetic matrix tamper contracts, never real runtime evidence.

These fixtures are independently constructed literal bytes and observations.
They do not import or execute the Node driver, fixture server, launcher, browser,
Go, TLS endpoints, network, or namespace tools. Passing is not project E2E.
"""
import copy
import hashlib
import unittest

import check_matrix as M

CASES = ('split-success', 'boundary-success', 'oversize', 'truncated', 'abort')
LIMIT = 1048576
SERVER_SCHEMA = 'chengwang.stream-matrix-server-event/v1'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def body(case):
    if case in ('split-success', 'truncated', 'abort'):
        return b'{"ok":true}'
    size = LIMIT + (case == 'oversize')
    return b'{"data":"' + b'a' * (size - 11) + b'"}'


def case_fixture(case):
    positive, aborted = case.endswith('-success'), case == 'abort'
    raw = body(case)
    js = dict(bytes=len(raw) if positive or case == 'oversize' else 6,
        eof=positive, readEnd='EOF_OK' if positive else 'SIZE_REJECT' if case == 'oversize'
        else 'ABORT_ERROR' if aborted else 'READ_ERROR', signalAborted=aborted,
        abortRequested=aborted, abortError=aborted, cancelAttempted=not positive,
        cancelCompleted=case == 'oversize', parsed=positive,
        sha256=digest(raw) if positive else None, elapsedMs=23, chunks=2)
    terminal = dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE') if positive or case == 'oversize' else dict(
        event='FAIL', canceled='YES' if aborted else 'NO', errorCode='ABORTED' if aborted else 'CONTENT_LENGTH_MISMATCH')
    return dict(case=case, js=js, networkOrdinal=CASES.index(case) + 2,
        requestId='123.' + str(CASES.index(case) + 2), terminal=terminal,
        hostBody=dict(bytes=len(raw), sha256=digest(raw)) if positive else None)


def case_fixtures():
    return [case_fixture(case) for case in CASES]


def network_fixture():
    rows = []
    for ordinal, case in enumerate(('DOCUMENT', *CASES), 1):
        base = dict(v=1, ordinal=ordinal, requestId='123.' + str(ordinal), case=case,
                    clock='CDP_MONOTONIC_US')
        time_us = 1000000 + ordinal * 1000
        rows.append(dict(base, seq=len(rows) + 1, event='START', timeUs=time_us,
                         wallTimeUs=1790000000000000 + ordinal * 1000))
        rows.append(dict(base, seq=len(rows) + 1, event='HEADERS', timeUs=time_us + 10,
            status=200, mimeType='text/html' if case == 'DOCUMENT' else 'application/json',
            noStore=True, contentLength=199 if case == 'DOCUMENT' else None if case == 'oversize' else len(body(case))))
        if case in ('truncated', 'abort'):
            rows.append(dict(base, seq=len(rows) + 1, event='FAIL', timeUs=time_us + 20,
                canceled='YES' if case == 'abort' else 'NO',
                errorCode='ABORTED' if case == 'abort' else 'CONTENT_LENGTH_MISMATCH'))
        else:
            rows.append(dict(base, seq=len(rows) + 1, event='FINISH', timeUs=time_us + 20,
                encodedDataLength=(199 if case == 'DOCUMENT' else len(body(case))) + 256))
    return rows


def server_fixture():
    rows = []

    def emit(event, case='none', body_bytes=0, framed_bytes=0, reason='OK'):
        rows.append(dict(schema=SERVER_SCHEMA, ordinal=len(rows) + 1, event=event,
            caseId=case, bodyBytes=body_bytes, framedBytes=framed_bytes, reason=reason))

    emit('REQUEST'); emit('WRITE_RETURNED', body_bytes=199, framed_bytes=199)
    emit('COMPLETE', body_bytes=199, framed_bytes=199)
    for case in CASES:
        emit('REQUEST', case)
        raw = body(case)
        if case in ('truncated', 'abort'):
            emit('WRITE_RETURNED', case, 6, 6)
            if case == 'abort': emit('PEER_CLOSED', case, 6, 6, 'PEER_CLOSED')
            emit('COMPLETE', case, 6, 6)
        else:
            parts = (raw[:6], raw[6:]) if case == 'split-success' else (raw[:LIMIT // 2], raw[LIMIT // 2:])
            total_body = total_frames = 0
            for part in parts:
                length = len(part)
                framed = length + len(format(length, 'x')) + 4 if case == 'oversize' else length
                emit('WRITE_RETURNED', case, length, framed)
                total_body += length; total_frames += framed
            if case == 'oversize':
                emit('WRITE_RETURNED', case, 0, 5); total_frames += 5
            emit('COMPLETE', case, total_body, total_frames)
    emit('SERVER_STOPPED')
    assert len(rows) == 24
    return rows


class TestMatrixContracts(unittest.TestCase):
    def reject_case(self, value, case):
        with self.assertRaises(ValueError): M.validate_case(value, case)

    def reject_network(self, rows, cases=None):
        with self.assertRaises(ValueError): M.validate_network(rows, case_fixtures() if cases is None else cases)

    def reject_server(self, rows):
        with self.assertRaises(ValueError): M.validate_server(rows)

    def test_01_literal_payload_sizes_and_sha_are_independently_recomputed(self):
        for case in CASES:
            raw = body(case)
            self.assertEqual(M.expected_body(case), raw)
            self.assertEqual(M.sha(raw), digest(raw))
        self.assertEqual((len(body('split-success')), len(body('boundary-success')), len(body('oversize'))), (11, LIMIT, LIMIT + 1))
        self.assertEqual(digest(body('split-success')), '4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93')
        self.assertEqual(digest(body('boundary-success')), 'a16afce611b74e58817bfd620274cbd56a627e56d004038ea0224f680a899c28')

    def test_02_all_five_synthetic_closed_case_expectations_are_accepted(self):
        for case in CASES:
            self.assertIsNone(M.validate_case(case_fixture(case), case))
        changed = case_fixture('oversize')
        changed['terminal'] = dict(event='FAIL', canceled='YES', errorCode='ABORTED')
        self.assertIsNone(M.validate_case(changed, 'oversize'))

    def test_03_positive_cases_require_eof_and_bounded_json_success(self):
        for case in CASES[:2]:
            for key, value in [('eof', False), ('parsed', False), ('readEnd', 'READ_ERROR'), ('signalAborted', True)]:
                changed = case_fixture(case); changed['js'][key] = value
                self.reject_case(changed, case)

    def test_04_oversize_cannot_claim_eof_json_or_a_successful_body_digest(self):
        for key, value in [('eof', True), ('parsed', True), ('sha256', digest(body('oversize'))), ('readEnd', 'EOF_OK')]:
            changed = case_fixture('oversize'); changed['js'][key] = value
            self.reject_case(changed, 'oversize')

    def test_05_oversize_must_read_the_extra_byte_and_actually_attempt_cancel(self):
        for key, value in [('bytes', LIMIT), ('bytes', LIMIT + 2), ('cancelAttempted', False), ('cancelCompleted', False)]:
            changed = case_fixture('oversize'); changed['js'][key] = value
            self.reject_case(changed, 'oversize')

    def test_06_truncation_requires_exact_six_byte_prefix_not_an_empty_failure(self):
        for value in (0, 5, 7, 11):
            changed = case_fixture('truncated'); changed['js']['bytes'] = value
            self.reject_case(changed, 'truncated')

    def test_07_truncation_cannot_be_relabelled_native_finish_or_eof(self):
        for field, value in [('terminal', dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE')),
                             ('js', dict(case_fixture('truncated')['js'], eof=True)),
                             ('js', dict(case_fixture('truncated')['js'], readEnd='EOF_OK'))]:
            changed = case_fixture('truncated'); changed[field] = value
            self.reject_case(changed, 'truncated')

    def test_08_abort_requires_explicit_request_signal_and_abort_error_observations(self):
        for key in ('abortRequested', 'signalAborted', 'abortError'):
            changed = case_fixture('abort'); changed['js'][key] = False
            self.reject_case(changed, 'abort')

    def test_09_abort_cannot_substitute_generic_read_failure_or_native_success(self):
        changed = case_fixture('abort'); changed['js']['readEnd'] = 'READ_ERROR'; self.reject_case(changed, 'abort')
        changed = case_fixture('abort'); changed['terminal']['errorCode'] = 'OTHER'; self.reject_case(changed, 'abort')
        changed = case_fixture('abort'); changed['terminal'] = dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE')
        self.reject_case(changed, 'abort')

    def test_10_positive_host_body_bytes_and_sha_cannot_be_self_asserted_or_missing(self):
        for case in CASES[:2]:
            for host in (None, dict(bytes=11, sha256='0' * 64), dict(bytes=1, sha256=digest(body(case)))):
                changed = case_fixture(case); changed['hostBody'] = host
                self.reject_case(changed, case)
        changed = case_fixture('oversize'); changed['hostBody'] = dict(bytes=LIMIT + 1, sha256=digest(body('oversize')))
        self.reject_case(changed, 'oversize')

    def test_11_unknown_case_and_nested_fields_never_enter_closed_observations(self):
        for location in ('top', 'js', 'terminal', 'hostBody'):
            changed = case_fixture('split-success')
            (changed if location == 'top' else changed[location])['private'] = 'SYNTHETIC_ONLY'
            self.reject_case(changed, 'split-success')
        self.reject_case(case_fixture('split-success'), 'unknown')
        changed = case_fixture('split-success'); changed['case'] = 'unknown'; self.reject_case(changed, 'split-success')

    def test_12_boolean_values_cannot_impersonate_integer_case_or_body_fields(self):
        for location, key in [('js', 'bytes'), ('js', 'elapsedMs'), ('js', 'chunks'), ('top', 'networkOrdinal'), ('hostBody', 'bytes')]:
            changed = case_fixture('split-success')
            (changed if location == 'top' else changed[location])[key] = True
            self.reject_case(changed, 'split-success')

    def test_13_positive_native_failures_and_unknown_terminal_enums_are_not_ignored(self):
        for case in CASES[:2]:
            changed = case_fixture(case); changed['terminal'] = dict(event='FAIL', canceled='YES', errorCode='ABORTED')
            self.reject_case(changed, case)
        for key in ('event', 'canceled', 'errorCode'):
            changed = case_fixture('abort'); changed['terminal'][key] = 'UNKNOWN'
            self.reject_case(changed, 'abort')

    def test_14_eighteen_synthetic_network_rows_bind_the_fixed_five_cases(self):
        self.assertEqual(len(network_fixture()), 18)
        self.assertIsNone(M.validate_network(network_fixture(), case_fixtures()))

    def test_15_network_clock_domains_and_safe_integer_types_remain_distinct(self):
        for index, key, value in [(0, 'clock', 'JS_ELAPSED_MS'), (0, 'timeUs', True),
                                  (0, 'wallTimeUs', -1), (1, 'timeUs', 9007199254740992)]:
            changed = network_fixture(); changed[index][key] = value
            self.reject_network(changed)

    def test_16_network_request_id_ordinal_and_case_ownership_cannot_be_swapped(self):
        for index, key, value in [(3, 'requestId', '123.999'), (4, 'ordinal', 3), (3, 'case', 'boundary-success')]:
            changed = network_fixture(); changed[index][key] = value
            self.reject_network(changed)
        cases = case_fixtures(); cases[0]['requestId'] = '123.3'; self.reject_network(network_fixture(), cases)
        cases = case_fixtures(); cases[0]['networkOrdinal'] = 3; self.reject_network(network_fixture(), cases)

    def test_17_network_headers_require_no_store_status_mime_and_declared_length(self):
        for index, key, value in [(4, 'noStore', False), (4, 'status', 403), (4, 'mimeType', 'text/plain'),
                                  (4, 'contentLength', 12), (10, 'contentLength', LIMIT + 1)]:
            changed = network_fixture(); changed[index][key] = value
            self.reject_network(changed)

    def test_18_network_missing_duplicate_or_reordered_terminal_events_are_rejected(self):
        changed = network_fixture(); del changed[-1]; self.reject_network(changed)
        changed = network_fixture(); changed.append(copy.deepcopy(changed[-1])); self.reject_network(changed)
        changed = network_fixture(); changed[16], changed[17] = changed[17], changed[16]; self.reject_network(changed)

    def test_19_network_extra_requests_duplicate_sequences_and_wrong_case_order_are_rejected(self):
        changed = network_fixture(); changed[3]['seq'] = changed[2]['seq']; self.reject_network(changed)
        changed = network_fixture(); changed.extend(copy.deepcopy(changed[:3])); self.reject_network(changed)
        cases = case_fixtures(); cases[0], cases[1] = cases[1], cases[0]; self.reject_network(network_fixture(), cases)

    def test_20_network_unknown_fields_and_boolean_header_or_byte_counts_are_rejected(self):
        for index, key, value in [(0, 'rawHeaders', 'SYNTHETIC_ONLY'), (1, 'status', True),
                                  (1, 'contentLength', True), (2, 'encodedDataLength', True), (0, 'ordinal', True)]:
            changed = network_fixture(); changed[index][key] = value
            self.reject_network(changed)

    def test_21_twenty_four_synthetic_server_events_preserve_actual_write_return_contract(self):
        rows = server_fixture(); self.assertEqual(len(rows), 24)
        self.assertIsNone(M.validate_server(rows))
        complete = next(r for r in rows if r['caseId'] == 'oversize' and r['event'] == 'COMPLETE')
        self.assertEqual((complete['bodyBytes'], complete['framedBytes']), (LIMIT + 1, LIMIT + 24))

    def test_22_server_body_and_chunk_frame_counts_must_match_every_write_and_total(self):
        for event in ('WRITE_RETURNED', 'COMPLETE'):
            for field in ('bodyBytes', 'framedBytes'):
                rows = server_fixture(); target = next(r for r in rows if r['caseId'] == 'oversize' and r['event'] == event)
                target[field] += 1; self.reject_server(rows)
        rows = server_fixture(); next(r for r in rows if r['caseId'] == 'truncated' and r['event'] == 'COMPLETE')['bodyBytes'] = 11
        self.reject_server(rows)

    def test_23_server_duplicate_cases_or_unexpected_errors_are_never_normal_completions(self):
        rows = server_fixture(); rows[3]['caseId'] = 'boundary-success'; self.reject_server(rows)
        rows = server_fixture(); target = next(r for r in rows if r['event'] == 'PEER_CLOSED')
        target.update(event='ERROR', reason='UNEXPECTED'); self.reject_server(rows)
        rows = server_fixture(); rows.append(copy.deepcopy(rows[-1])); self.reject_server(rows)

    def test_24_server_closed_schema_order_reason_and_integer_types_are_enforced(self):
        for index, key, value in [(0, 'schema', 'unknown'), (0, 'ordinal', True), (1, 'bodyBytes', True),
                                  (1, 'framedBytes', True), (0, 'reason', 'UNKNOWN'), (0, 'private', 'SYNTHETIC_ONLY')]:
            rows = server_fixture(); rows[index][key] = value; self.reject_server(rows)
        rows = server_fixture(); del rows[-1]; self.reject_server(rows)
        rows = server_fixture(); rows[0], rows[1] = rows[1], rows[0]; self.reject_server(rows)


FROZEN_NAMES = tuple(unittest.defaultTestLoader.getTestCaseNames(TestMatrixContracts))
FROZEN_NAMES_SHA256 = 'ffeca5e08c45508e80018b869fb5a16428b2c772e45811d5dc76a7c9b2d06b55'
FROZEN_FULL_NAMES_SHA256 = '2a3112ab35d0200dc90c19b6989ecdd3f6e15c6bd01415eef8b0ed8d7a6d1e43'
assert len(FROZEN_NAMES) == len(set(FROZEN_NAMES)) == 24
assert digest('\n'.join(sorted(FROZEN_NAMES)).encode()) == FROZEN_NAMES_SHA256
assert digest('\n'.join('test_check_matrix.TestMatrixContracts.' + name for name in sorted(FROZEN_NAMES)).encode()) == FROZEN_FULL_NAMES_SHA256

if __name__ == '__main__':
    unittest.main(verbosity=2)
