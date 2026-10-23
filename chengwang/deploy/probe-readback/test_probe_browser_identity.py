"""Synthetic identity contracts; no browser/process/network execution."""
import copy
import hashlib
import json
import unittest

import probe_browser_identity as I
import check_browser_identity_units as U


def line(value): return I.PREFIX + json.dumps(value, separators=(',', ':')).encode('ascii')


class TestBrowserIdentity(unittest.TestCase):
    def row(self):
        return dict(schema=I.OBSERVATION_SCHEMA, engine='chrome-cdp', fixtureId='a' * 32,
            browser=dict(product='Chrome/155.0.8059.39', revision='@' + 'b' * 40, protocolVersion='1.3'),
            chrome=dict(pid=11, startTicks=123, argvSHA256=hashlib.sha256(b'/synthetic/chrome\0--no-sandbox\0').hexdigest()))

    def copies(self):
        return [dict(path=p, bytes=123, sha256='d' * 64) for p in sorted(I.HELPERS | {'toolchain/chrome/chrome'})]

    def fixture(self):
        row = self.row(); copies = self.copies()
        value = I.project(line(row), 'e' * 40, 'chrome-cdp', 'a' * 32, copies)
        build = dict(sourceCommit='e' * 40, engine='chrome-cdp', fixtureId='a' * 32, copiedInputs=copies, production=False)
        processes = dict(sourceCommit='e' * 40, records=[dict(role='chrome', pid=11, startTime='123',
            argvSHA256=row['chrome']['argvSHA256'], exeSHA256='d' * 64)], production=False,
            chromeArgv=['/synthetic/chrome', '--no-sandbox'],
            chromeExecutable=dict(bytes=123, sha256='d' * 64, path='/synthetic/chrome', sourceScope='SYNTHETIC_ONLY'))
        driver = dict.fromkeys(I.DRIVER_FIELDS)
        driver.update(engine='chrome-cdp', fixtureId='a' * 32, realBrowser=row['browser']['product'], chrome=row['chrome'])
        return value, build, processes, driver

    def check(self, data): return I.verify(*data, 'e' * 40, 'chrome-cdp')

    def test_closed_native_observation_and_zero_revision_preserve_no_ancestry_claim(self):
        row = self.row(); row['browser']['revision'] = '@' + '0' * 40
        self.assertEqual(I.decode_line(line(row)), row)
        report = self.check(self.fixture())
        self.assertFalse(report['patchAncestryProven']); self.assertFalse(report['browserAcceptanceProven'])
        self.assertFalse(report['processBindingVerified']); self.assertTrue(report['identityFieldsMatched'])

    def test_duplicate_unknown_excluded_and_noncanonical_payloads_are_rejected(self):
        good = line(self.row())
        for raw in (good.replace(b'"engine":"chrome-cdp"', b'"engine":"chrome-cdp","engine":"chrome-cdp"'),
                    good + b' ', good.replace(b'"pid":11', b'"pid":1.1e1'),
                    line(dict(self.row(), userAgent='SECRET')), I.PREFIX + b'null'):
            with self.assertRaises(I.Rejected): I.decode_line(raw)

    def test_formats_types_booleans_and_unbounded_identifiers_are_rejected(self):
        for key, value in [('product', 'SECRET'), ('revision', 'b' * 40), ('revision', '@' + 'B' * 40),
                           ('protocolVersion', '1.3\nSECRET'), ('protocolVersion', 1.3)]:
            row = self.row(); row['browser'][key] = value
            with self.assertRaises(I.Rejected): I.decode_line(line(row))
        for key, value in [('pid', True), ('pid', 1), ('startTicks', 9007199254740992), ('argvSHA256', 'SECRET')]:
            row = self.row(); row['chrome'][key] = value
            with self.assertRaises(I.Rejected): I.decode_line(line(row))
        for engine in ([], {}, None, True):
            row = self.row(); row['engine'] = engine
            with self.assertRaises(I.Rejected): I.decode_line(line(row))
            projected = I.project(line(row), 'e' * 40, 'chrome-cdp', 'a' * 32, self.copies())
            self.assertEqual(projected['state'], 'rejected')

    def test_private_unrelated_log_lines_are_never_echoed(self):
        value = I.project(b'PRIVATE_TOKEN\n' + line(self.row()), 'e' * 40, 'chrome-cdp', 'a' * 32, self.copies())
        self.assertEqual(value['state'], 'observed'); self.assertNotIn('PRIVATE_TOKEN', json.dumps(value))

    def test_missing_invalid_and_multiple_identity_observations_are_not_green(self):
        for raw, expected in [(b'other', 'missing'), (I.PREFIX + b'SECRET', 'rejected'),
                              (line(self.row()) + b'\n' + line(self.row()), 'rejected')]:
            value = I.project(raw, 'e' * 40, 'chrome-cdp', 'a' * 32, self.copies())
            self.assertEqual(value['state'], expected); self.assertIsNone(value['observation'])

    def test_line_and_combined_log_budgets_are_fixed(self):
        with self.assertRaises(I.Rejected): I.decode_line(I.PREFIX + b'x' * 1024)
        with self.assertRaises(I.Rejected): I.project(b'x' * (I.MAX_LOG + 1), 'e' * 40, 'chrome-cdp', 'a' * 32, self.copies())

    def test_engine_fixture_and_copy_substitution_is_not_observed(self):
        for engine, fixture, copies in [('playwright', 'a' * 32, self.copies()),
                                        ('chrome-cdp', 'f' * 32, self.copies()),
                                        ('chrome-cdp', 'a' * 32, [])]:
            value = I.project(line(self.row()), 'e' * 40, engine, fixture, copies)
            self.assertNotEqual(value['state'], 'observed')

    def test_pid_start_ticks_and_argv_must_bind_actual_process_record(self):
        for key, value in [('pid', 12), ('startTime', '124'), ('startTime', 123.9), ('startTime', '0123'),
                           ('startTime', '123.0'), ('argvSHA256', 'f' * 64)]:
            data = self.fixture(); data[2]['records'][0][key] = value
            with self.assertRaises(I.Rejected): self.check(data)
        for argv in (['--ignore-certificate-errors'], ['/synthetic/chrome', '--ignore-certificate-errors'],
                     ['/synthetic/chrome', '--disable-web-security'], ['/synthetic/chrome', '--new-flag']):
            data = self.fixture(); data[2]['chromeArgv'] = argv
            with self.assertRaises(I.Rejected): self.check(data)

    def test_elf_bytes_and_hash_cannot_be_self_reported_or_swapped(self):
        for changed in [dict(bytes=124, sha256='d' * 64), dict(bytes=123, sha256='f' * 64)]:
            data = self.fixture(); data[0]['executable'] = changed
            with self.assertRaises(I.Rejected): self.check(data)
        data = self.fixture(); data[2]['chromeExecutable']['sha256'] = 'f' * 64
        with self.assertRaises(I.Rejected): self.check(data)

    def test_missing_source_helper_or_wrong_build_identity_rejected(self):
        data = self.fixture(); data[1]['copiedInputs'].pop(0)
        with self.assertRaises(I.Rejected): self.check(data)
        for key, value in [('sourceCommit', 'f' * 40), ('fixtureId', 'f' * 32), ('engine', 'playwright')]:
            data = self.fixture(); data[1][key] = value
            with self.assertRaises(I.Rejected): self.check(data)

    def test_old_driver_binding_and_product_must_match_identity_sidecar(self):
        for key, value in [('engine', 'playwright'), ('fixtureId', 'f' * 32), ('realBrowser', 'Chrome/1.2.3.4')]:
            data = self.fixture(); data[3][key] = value
            with self.assertRaises(I.Rejected): self.check(data)

    def test_forged_scope_flags_and_mutation_do_not_hide_invalid_input(self):
        for key in ('patchAncestryProven', 'browserAcceptanceProven'):
            data = self.fixture(); data[0][key] = True
            with self.assertRaises(I.Rejected): self.check(data)
        for index in (1, 2):
            data = self.fixture(); data[index]['production'] = True
            with self.assertRaises(I.Rejected): self.check(data)
        data = self.fixture(); data[3]['privateMaterial'] = 'SYNTHETIC'
        with self.assertRaises(I.Rejected): self.check(data)
        data = self.fixture(); before = copy.deepcopy(data)
        self.check(data); self.assertEqual(data, before)
        name = 'synthetic.Case.test_original'
        pin = U.sha(name.encode())
        self.assertEqual(U.python_names('test_original (' + name + ') ... ok\n', 'synthetic', 1, pin), [name])
        with self.assertRaises(ValueError):
            U.python_names('test_NONEXISTENT (' + name + ') ... ok\n', 'synthetic', 1, pin)


if __name__ == '__main__': unittest.main()
