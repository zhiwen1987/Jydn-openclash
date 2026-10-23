"""Synthetic artifact tamper tests, not live browser or POSIX custody proof."""
import copy
import json
import unittest

import check_status_diagnostic as C
import probe_status_diagnostics as D


class TestDiagnosticArtifact(unittest.TestCase):
    def fixture(self):
        rows = [dict(v=1, e='JS', q=1, u=100000, j='MOUNT', m=1, r=0, t=0, a=False),
                dict(v=1, e='JS', q=2, u=100100, j='BEGIN', m=1, r=1, t=1, a=False, tr='INITIAL'),
                dict(v=1, e='NET_START', q=3, s=1, x=100, w=100000, h=1, l=1),
                dict(v=1, e='META', q=4, js=2, net=1, rej=0, over=False)]
        raw = b'\n'.join((D.PREFIX + json.dumps(row, separators=(',', ':'))).encode() for row in rows)
        value = D.project(raw)
        value.update(sourceCommit='a' * 40, engine='chrome-cdp', clockDomains=C.CLOCKS)
        sources = [dict(path=p, bytes=100, sha256='b' * 64) for p in sorted(C.REQUIRED_COPIES)]
        build = dict(sourceCommit='a' * 40, engine='chrome-cdp', production=False,
                     sourceFilesBefore=sources, sourceFilesAfter=copy.deepcopy(sources), copiedInputs=copy.deepcopy(sources))
        return value, build

    def check(self, value, build):
        return C.verify(value, build, 'a' * 40, 'chrome-cdp')

    def test_complete_observations_still_do_not_prove_browser_or_causality(self):
        report = self.check(*self.fixture())
        self.assertEqual(report['outcome'], 'OBSERVATIONS_COMPLETE')
        self.assertFalse(report['browserAcceptanceProven']); self.assertFalse(report['causalRequestBindingProven'])

    def test_extra_secret_fields_and_report_identity_substitution_rejected(self):
        for key, changed in [('token', 'SECRET'), ('sourceCommit', 'c' * 40), ('engine', 'playwright'),
                             ('clockDomains', 'SECRET'), ('browserAcceptanceProven', True)]:
            value, build = self.fixture(); value[key] = changed
            with self.assertRaises(D.Rejected): self.check(value, build)

    def test_record_extra_unknown_enum_and_duplicate_sequence_are_rejected(self):
        for field, changed in [('rawError', 'SECRET'), ('j', 'SECRET'), ('q', 2), ('a', 0)]:
            value, build = self.fixture(); value['records'][0][field] = changed
            with self.assertRaises(D.Rejected): self.check(value, build)

    def test_forged_complete_and_count_fields_are_rejected(self):
        for key, changed in [('eventCount', 3), ('complete', False), ('sinkClosed', False), ('rejectedLines', True)]:
            value, build = self.fixture(); value[key] = changed
            with self.assertRaises(D.Rejected): self.check(value, build)

    def test_original_required_helper_copy_cannot_be_removed_or_replaced(self):
        value, build = self.fixture(); build['copiedInputs'].pop()
        with self.assertRaises(D.Rejected): self.check(value, build)
        value, build = self.fixture(); build['copiedInputs'][0]['sha256'] = 'c' * 64
        with self.assertRaises(D.Rejected): self.check(value, build)

    def test_duplicate_copy_and_changed_source_are_rejected(self):
        value, build = self.fixture(); build['copiedInputs'].append(copy.deepcopy(build['copiedInputs'][0]))
        with self.assertRaises(D.Rejected): self.check(value, build)
        value, build = self.fixture(); build['sourceFilesAfter'][0]['bytes'] += 1
        with self.assertRaises(D.Rejected): self.check(value, build)

    def test_missing_real_frontend_or_network_observations_cannot_pass(self):
        for kind in ('JS', 'NET_START'):
            value, build = self.fixture(); value['records'] = [r for r in value['records'] if r['e'] != kind]
            value['eventCount'] = len(value['records'])
            with self.assertRaises(D.Rejected): self.check(value, build)

    def test_overflow_is_explicitly_incomplete_and_never_silently_green(self):
        value, build = self.fixture(); value['records'][-1]['over'] = True; value['complete'] = False
        report = self.check(value, build)
        self.assertEqual(report['outcome'], 'OBSERVATIONS_INCOMPLETE')
        self.assertFalse(report['browserAcceptanceProven'])


if __name__ == '__main__':
    unittest.main()
