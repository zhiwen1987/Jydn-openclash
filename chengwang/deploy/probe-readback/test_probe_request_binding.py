"""Pure synthetic closed-projection counterexamples, never browser evidence."""
import copy
import json
import unittest

import probe_request_binding as D


def line(row): return (D.PREFIX + json.dumps(row, separators=(',', ':'))).encode('ascii')


def trace():
    items = [
        ('SESSION', {}), ('DOCUMENT', dict(h=1)), ('CONTEXT', dict(c=1, h=1, default=True)),
        ('JS', dict(c=1, j='MOUNT', m=1, r=0, t=0, a=False)),
        ('JS', dict(c=1, j='BEGIN', m=1, r=1, t=1, a=False, tr='INITIAL')),
        ('JS', dict(c=1, j='ARM', m=1, r=1, t=1, a=False)),
        ('SEND', dict(c=1, d=1, m=1, r=1, t=1, a=False)),
        ('NET_START', dict(n=1, d=1, m=1, r=1, h=1, x=100, w=200000)),
        ('NET_HEADERS', dict(n=1, x=150, st=200)),
        ('JS', dict(c=1, j='HEADERS', m=1, r=1, t=2, a=False)),
        ('JS', dict(c=1, j='EOF', m=1, r=1, t=3, a=False, n=8)),
        ('JS', dict(c=1, j='READ_END', m=1, r=1, t=3, a=False, k='EOF_OK', n=8, f=False)),
        ('JS', dict(c=1, j='CANCEL', m=1, r=1, t=3, a=False, p='BEFORE', n=8, f=False)),
        ('JS', dict(c=1, j='CANCEL', m=1, r=1, t=3, a=False, p='AFTER', n=8, f=False)),
        ('NET_FINISH', dict(n=1, x=140)),  # CDP dispatch need not sort timestamps.
        ('JS', dict(c=1, j='FINALLY', m=1, r=1, t=4, a=False)),
        ('CANCEL_RESULT', dict(c=1, d=1, m=1, r=1, t=5, a=False, o='RESOLVED')),
    ]
    rows = [dict(v=1, e=event, q=i + 1, s=1, **fields) for i, (event, fields) in enumerate(items)]
    return reseal(rows)


def reseal(rows):
    rows = copy.deepcopy([r for r in rows if r['e'] != 'META'])
    for i, row in enumerate(rows): row['q'] = i + 1
    counts = {name: sum(r['e'] == event for r in rows) for name, event in D.COUNT_EVENTS.items()}
    rows.append(dict(v=1, e='META', q=len(rows) + 1, s=1, **counts, rejected=0, overflow=False))
    return rows


def encoded(rows): return b'\n'.join(line(row) for row in rows) + b'\n'


class RequestBindingProjectionContracts(unittest.TestCase):
    def test_closed_trace_exports_no_acceptance_or_cause(self):
        value = D.project(encoded(trace()))
        self.assertTrue(value['complete']); self.assertFalse(value['browserAcceptanceProven'])
        self.assertFalse(value['cancellationRootCauseProven']); self.assertEqual(value['eventCount'], 18)

    def test_foreign_lines_are_counted_and_suppressed(self):
        value = D.project(b'SECRET_PRIVATE_ERROR\n' + encoded(trace()))
        self.assertEqual(value['rejectedLines'], 1); self.assertFalse(value['complete'])
        self.assertNotIn('SECRET', json.dumps(value))

    def test_unknown_payload_fields_never_escape(self):
        row = trace()[0]; row['token'] = 'SECRET'
        value = D.project(line(row)); self.assertEqual(value['records'], [])
        self.assertEqual(value['rejectedLines'], 1)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(D.Rejected): D.decode_line(b'CW_PROBE_BIND_DIAG:{"v":1,"v":1,"e":"SESSION","q":1,"s":1}')

    def test_canonical_ascii_only(self):
        for raw in (b'CW_PROBE_BIND_DIAG: {"v":1,"e":"SESSION","q":1,"s":1}',
                    b'CW_PROBE_BIND_DIAG:{"v":1,"e":"SESSION","q":1e0,"s":1}',
                    b'CW_PROBE_BIND_DIAG:{"v":1,"e":"\\u0053ESSION","q":1,"s":1}', b'\xff'):
            with self.assertRaises(D.Rejected): D.decode_line(raw)

    def test_bool_cannot_substitute_for_integer(self):
        for field in ('v', 'q', 's'):
            row = trace()[0]; row[field] = True
            with self.assertRaises(D.Rejected): D.decode_line(line(row))

    def test_version_and_session_are_fixed(self):
        for field in ('v', 's'):
            row = trace()[0]; row[field] = 2
            with self.assertRaises(D.Rejected): D.decode_line(line(row))

    def test_private_and_row_budgets_are_independent(self):
        with self.assertRaises(D.Rejected): D.project(b'x' * (D.MAX_BYTES + 1))
        with self.assertRaises(D.Rejected): D.decode_line(b'x' * 513)
        value = D.project((line(trace()[0]) + b'\n') * 1025)
        self.assertFalse(value['complete']); self.assertGreater(value['rejectedLines'], 0)
        # The new 256-row frontend cap includes JS, SEND and CANCEL_RESULT.
        rows = trace(); exemplar = next(r for r in rows if r['e'] == 'JS' and r['j'] == 'ARM')
        rows[6:6] = [copy.deepcopy(exemplar) for _ in range(246)]
        self.assertFalse(D.project(encoded(reseal(rows)))['complete'])

    def test_sequence_gap_or_duplicate_refuses_completeness(self):
        for ordinal in (1, 3):
            rows = trace(); rows[1]['q'] = ordinal
            self.assertFalse(D.project(encoded(rows))['complete'])

    def test_missing_meta_is_incomplete(self):
        value = D.project(encoded(trace()[:-1]))
        self.assertFalse(value['complete']); self.assertFalse(value['sinkClosed'])

    def test_post_meta_rows_are_rejected(self):
        value = D.project(encoded(trace()) + line(trace()[0]))
        self.assertTrue(value['sinkClosed']); self.assertFalse(value['complete'])
        self.assertEqual(value['rejectedLines'], 1)

    def test_meta_counts_overflow_and_rejected_are_not_trusted(self):
        for field, val in [('js', 0), ('rejected', 1), ('overflow', True)]:
            rows = trace(); rows[-1][field] = val
            self.assertFalse(D.project(encoded(rows))['complete'])

    def test_cancel_outcomes_are_closed_not_raw_errors(self):
        row = next(r for r in trace() if r['e'] == 'CANCEL_RESULT')
        for val in ('RESOLVED', 'REJECTED', 'THREW', 'NO_BODY'):
            row['o'] = val; self.assertEqual(D.decode_line(line(row))['o'], val)
        row['o'] = 'SECRET'; self.assertEqual(D.project(line(row))['records'], [])

    def test_net_failure_enums_do_not_export_error_text(self):
        row = dict(v=1, e='NET_FAIL', q=1, s=1, n=1, x=100, canceled='YES', error='ABORTED')
        D.decode_line(line(row)); row['error'] = 'net::ERR_ABORTED'
        with self.assertRaises(D.Rejected): D.decode_line(line(row))

    def test_js_abort_cause_is_separate_from_context(self):
        row = dict(v=1, e='JS', q=1, s=1, c=1, j='ABORT', m=1, r=1, t=1, a=True, cause='CLEANUP', p='BEFORE')
        D.decode_line(line(row)); row['c'] = 'CLEANUP'
        with self.assertRaises(D.Rejected): D.decode_line(line(row))

    def test_numeric_and_boolean_closed_field_boundaries(self):
        for event, field, val in [('CONTEXT', 'default', 1), ('SEND', 'd', 17), ('SEND', 'a', 0),
                                  ('NET_START', 'x', -1), ('NET_HEADERS', 'st', 600), ('JS', 'm', 129)]:
            row = next(r for r in trace() if r['e'] == event); row[field] = val
            with self.assertRaises(D.Rejected): D.decode_line(line(row))


if __name__ == '__main__': unittest.main()
