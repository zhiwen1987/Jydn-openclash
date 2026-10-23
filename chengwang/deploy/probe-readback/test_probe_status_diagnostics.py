"""Synthetic decoder tests only; no Chrome, network, TLS or product runtime."""
import copy
import contextlib
import io
import json
import pathlib
import unittest
from unittest import mock

import probe_status_diagnostics as D


def line(row):
    return (D.PREFIX + json.dumps(row, separators=(',', ':'))).encode('ascii')


class TestStatusDiagnostics(unittest.TestCase):
    def js(self, kind='MOUNT', **extra):
        return dict(v=1, e='JS', q=1, u=1700000000000000, j=kind, m=1,
                    r=0 if kind in ('MOUNT', 'CLEANUP') else 1, t=0, a=False, **extra)

    def test_all_closed_js_events_decode_without_raw_strings(self):
        cases = [('MOUNT', {}), ('BEGIN', dict(tr='INITIAL')), ('ARM', {}), ('HEADERS', {}),
                 ('EOF', dict(n=20)), ('ABORT', dict(c='DEADLINE', p='BEFORE')),
                 ('CLEANUP', {}), ('READ_END', dict(k='EOF_OK', n=20, f=True)),
                 ('CANCEL', dict(p='AFTER', n=20, f=True)), ('FINALLY', {})]
        for kind, extra in cases:
            row = self.js(kind, **extra)
            self.assertEqual(D.decode_line(line(row)), row)

    def test_network_clock_domains_and_aliases_are_kept_separate(self):
        cases = [('NET_START', dict(s=1, x=123, w=1700000000000000, h=1, l=2)),
                 ('NET_HEADERS', dict(s=1, x=124, st=200)),
                 ('NET_FAIL', dict(s=1, x=125, c='YES', ec='ABORTED')),
                 ('NET_FINISH', dict(s=1, x=126)), ('DOCUMENT', dict(x=100, w=200, h=1, l=2)),
                 ('FRAME_NAV', dict(h=1, l=2, p=0))]
        for event, fields in cases:
            row = dict(v=1, e=event, q=1, **fields)
            self.assertEqual(D.decode_line(line(row)), row)

    def test_duplicate_unknown_nested_and_noncanonical_fields_rejected(self):
        good = line(self.js())
        for raw in (good.replace(b'"v":1', b'"v":1,"v":1'), good + b' ',
                    good.replace(b'"u":1700000000000000', b'"u":1.7e15'),
                    line(dict(self.js(), token='SECRET')), line(dict(self.js(), j='SECRET')),
                    line(dict(self.js(), x={'secret': 1})), b'CW_PROBE_DIAG:[{}]'):
            with self.assertRaises(D.Rejected): D.decode_line(raw)

    def test_boolean_floats_unsafe_integers_and_enum_aliases_rejected(self):
        for key, values in {'q': [True, 0, 513], 'm': [False, 0, 129],
                            'r': [False, -1, 129], 'u': [1.0, -1, 9007199254740992],
                            't': [-1, 2147483648], 'a': [0, 'false']}.items():
            for value in values:
                with self.assertRaises(D.Rejected): D.decode_line(line(dict(self.js(), **{key: value})))
        for value in ('read_error', 'SECRET', None):
            with self.assertRaises(D.Rejected): D.decode_line(line(self.js('READ_END', k=value, n=0, f=False)))

    def test_line_and_log_budgets_do_not_export_oversize_or_nonascii(self):
        for raw in (b'CW_PROBE_DIAG:' + b'X' * 512, line(self.js()) + b'\x00',
                    line(self.js()).replace(b'MOUNT', b'\xff')):
            with self.assertRaises(D.Rejected): D.decode_line(raw)
        with self.assertRaises(D.Rejected): D.project(b'x' * (D.MAX_LOG_BYTES + 1))

    def test_complete_projection_requires_terminal_meta_and_exact_counts(self):
        js = self.js()
        meta = dict(v=1, e='META', q=2, js=1, net=0, rej=0, over=False)
        result = D.project(b'arbitrary PRIVATE_TOKEN suppressed\n' + line(js) + b'\n' + line(meta))
        self.assertTrue(result['complete']); self.assertEqual(result['eventCount'], 2)
        self.assertFalse(result['browserAcceptanceProven']); self.assertFalse(result['causalRequestBindingProven'])
        self.assertNotIn('PRIVATE_TOKEN', json.dumps(result))
        for changed in (dict(meta, js=0), dict(meta, rej=1), dict(meta, over=True)):
            self.assertFalse(D.project(line(js) + b'\n' + line(changed))['complete'])

    def test_missing_meta_reordering_and_post_meta_rows_are_incomplete(self):
        js = self.js(); meta = dict(v=1, e='META', q=2, js=1, net=0, rej=0, over=False)
        self.assertFalse(D.project(line(js))['complete'])
        for rows in ([meta, js], [js, meta, dict(js, q=3)], [dict(js, q=2), meta], [js, js, meta]):
            self.assertFalse(D.project(b'\n'.join(map(line, rows)))['complete'])

    def test_rejected_lines_are_never_echoed_and_cannot_claim_completeness(self):
        raw = line(self.js()) + b'\nCW_PROBE_DIAG:{"SECRET":"PRIVATE_TOKEN"}'
        result = D.project(raw)
        self.assertEqual(result['rejectedLines'], 1); self.assertFalse(result['complete'])
        self.assertNotIn('SECRET', json.dumps(result)); self.assertNotIn('PRIVATE_TOKEN', json.dumps(result))

    def test_state_and_count_limits_reject_more_than_512_rows(self):
        rows = [line(dict(v=1, e='FRAME_NAV', q=i, h=1, l=1, p=0)) for i in range(1, 513)]
        result = D.project(b'\n'.join(rows + [line(dict(v=1, e='META', q=512, js=0, net=0, rej=0, over=True))]))
        self.assertEqual(result['eventCount'], 512); self.assertEqual(result['rejectedLines'], 1)
        self.assertFalse(result['complete'])

    def test_input_objects_are_not_mutated_and_error_message_is_fixed(self):
        row = self.js(); before = copy.deepcopy(row)
        self.assertEqual(D.decode_line(line(row)), before); self.assertEqual(row, before)
        try: D.decode_line(b'CW_PROBE_DIAG:PRIVATE_TOKEN')
        except D.Rejected as error: self.assertEqual(str(error), 'status diagnostic rejected')

    def test_wrapper_exports_only_closed_projection_outside_original_sets(self):
        import run_probe_browser as browser
        raw = line(self.js()) + b'\n' + line(dict(v=1, e='META', q=2, js=1, net=0, rej=0, over=False))
        captured = []
        with mock.patch.object(browser.pathlib.Path, 'exists', return_value=True), \
             mock.patch.object(browser.N, 'stable_read', return_value=(raw, None)) as read, \
             mock.patch.object(browser.N, 'exclusive', side_effect=lambda p, b: captured.append((p, b))), \
             contextlib.redirect_stdout(io.StringIO()):
            browser.public_status_diagnostic(pathlib.Path('/private'), pathlib.Path('/public/lab'), 'a' * 40, 'chrome-cdp')
        read.assert_called_once_with(pathlib.Path('/private/logs/browser.private'), D.MAX_LOG_BYTES)
        self.assertEqual(captured[0][0], pathlib.Path('/public/lab/status-diagnostic.json'))
        body = json.loads(captured[0][1]); self.assertTrue(body['complete'])
        self.assertEqual(body['sourceCommit'], 'a' * 40); self.assertFalse(body['browserAcceptanceProven'])

    def test_wrapper_missing_log_is_not_synthesized_into_observations(self):
        import run_probe_browser as browser
        with mock.patch.object(browser.pathlib.Path, 'exists', return_value=False), \
             mock.patch.object(browser.N, 'exclusive') as write:
            browser.public_status_diagnostic(pathlib.Path('/private'), pathlib.Path('/public/lab'), 'a' * 40, 'playwright')
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
