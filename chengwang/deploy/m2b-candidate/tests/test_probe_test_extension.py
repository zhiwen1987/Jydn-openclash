"""Synthetic contracts for the exact capability increment, not Go execution."""
from __future__ import annotations

import collections
import hashlib
import pathlib
import re
import unittest
from unittest import mock

import probe_test_extension as subject


class CapabilityExtensionTests(unittest.TestCase):
    def setUp(self):
        self.new = subject.CAPABILITY_REQUIRED_PAIRS
        self.packages = {package for package, _ in self.new | subject.REQUIRED_PAIRS}
        self.old = frozenset({("chengwang/internal/api", "TestHistoricalAPI"),
                              ("chengwang/internal/capability", "TestHistoricalCapability")})
        self.previous = self.old | subject.REQUIRED_PAIRS

    @staticmethod
    def projection(pairs):
        result = collections.defaultdict(set)
        for package, name in pairs:
            result[package].add(name)
        return result

    @staticmethod
    def fingerprint(pairs):
        return hashlib.sha256("".join(package + "\t" + name + "\n"
                                      for package, name in sorted(pairs)).encode()).hexdigest()

    def synthetic_previous(self, pairs=None):
        """A small explicit synthetic baseline; real constants are pinned below."""
        if pairs is None:
            pairs = self.previous
        patcher = mock.patch.multiple(subject, PRE_CAPABILITY_COUNT=len(pairs),
                                      PRE_CAPABILITY_SHA256=self.fingerprint(pairs))
        return patcher

    def test_exact_twelve_pairs_and_packages(self):
        self.assertEqual(len(self.new), 12)
        self.assertEqual(collections.Counter(package for package, _ in self.new), {
            "chengwang/internal/api": 4, "chengwang/internal/capability": 8})
        self.assertEqual(subject.CAPABILITY_PREFIXES, ("TestProbeCapabilitiesAPI", "TestProbeReadback"))
        self.assertEqual(self.fingerprint(self.new), "2daf951da91974d83b2030dfdbd03cbfde528ce9172b429fb0f33e3f3764cc43")
        root = pathlib.Path(__file__).resolve().parents[3]
        actual = set()
        for package, filename in (("chengwang/internal/api", "internal/api/probe_capabilities_test.go"),
                                  ("chengwang/internal/capability", "internal/capability/probe_test.go")):
            source = (root / filename).read_text(encoding="utf-8")
            actual.update((package, name) for name in re.findall(r"^func (Test\w+)\(t \*testing\.T\)", source, re.MULTILINE))
        self.assertEqual(actual, self.new)

    def test_only_exact_new_pairs_are_removed(self):
        retained = subject._split_capability_extension(self.projection(self.new | self.previous), self.packages)
        self.assertEqual(retained, self.previous)

    def test_each_missing_new_pair_is_rejected(self):
        for pair in self.new:
            with self.subTest(pair=pair), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
                subject._split_capability_extension(self.projection(self.new - {pair}), self.packages)

    def test_each_renamed_new_pair_is_rejected(self):
        for package, name in self.new:
            changed = self.new - {(package, name)} | {(package, name + "Renamed")}
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
                subject._split_capability_extension(self.projection(changed), self.packages)

    def test_each_wrong_package_new_pair_is_rejected(self):
        for package, name in self.new:
            changed = self.new - {(package, name)} | {("chengwang/internal/wrong", name)}
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
                subject._split_capability_extension(self.projection(changed), self.packages | {"chengwang/internal/wrong"})

    def test_extra_new_prefix_names_are_rejected(self):
        for prefix in subject.CAPABILITY_PREFIXES:
            for package in ("chengwang/internal/api", "chengwang/internal/capability", "wrong"):
                with self.subTest(prefix=prefix, package=package), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
                    subject._split_capability_extension(self.projection(self.new | {(package, prefix + "Unreviewed")}),
                                                        self.packages | {package})

    def test_pseudo_subtests_are_never_excluded(self):
        for package, name in self.new:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
                subject._split_capability_extension(self.projection(self.new | {(package, name + "/unreviewed")}), self.packages)

    def test_each_new_terminal_package_is_required(self):
        for package in {package for package, _ in self.new}:
            with self.subTest(package=package), self.assertRaisesRegex(RuntimeError, "capability package has no terminal pass"):
                subject._split_capability_extension(self.projection(self.new), self.packages - {package})

    def test_historical_constants_and_exact_sets_are_not_recalibrated(self):
        import run_static_gate as gate
        self.assertEqual(subject.PRE_CAPABILITY_COUNT, 2391)
        self.assertEqual(subject.PRE_CAPABILITY_SHA256, "5faa2eeda5f6c6db5cbc52dead9bdf3e84d00bf67acd5d25f599a0fce33a4fdc")
        self.assertEqual(len(subject.REQUIRED_PAIRS), 71)
        self.assertEqual(self.fingerprint(subject.REQUIRED_PAIRS), "011ab60836f83cd89a3952c173f851d9a45e6cd64f9e28189829d71f22f06ca6")
        self.assertEqual(gate.P0D9_GO_TEST_COUNT, 2320)
        self.assertEqual(gate.P0D9_GO_TEST_SHA256, "fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8")

    def test_composed_guard_preserves_old_pairs(self):
        with self.synthetic_previous():
            retained = subject.split_extension(self.projection(self.new | self.previous), self.packages)
        self.assertEqual({(package, name) for package, names in retained.items() for name in names}, self.old)

    def test_missing_original_seventy_one_is_still_rejected(self):
        # Even a mistaken future recalibration of the outer baseline must not
        # bypass the historical exact-71 contract.
        for pair in subject.REQUIRED_PAIRS:
            changed = self.previous - {pair}
            with self.subTest(pair=pair), self.synthetic_previous(changed), self.assertRaisesRegex(RuntimeError, "P1 probe test"):
                subject.split_extension(self.projection(self.new | changed), self.packages)

    def test_extra_unrelated_pair_changes_previous_fingerprint(self):
        with self.synthetic_previous(), self.assertRaisesRegex(RuntimeError, "2391-name Go test baseline changed"):
            subject.split_extension(self.projection(self.new | self.previous | {("other", "TestUnreviewed")}), self.packages | {"other"})

    def test_old_pair_rename_cannot_be_hidden_by_new_increment(self):
        pair = sorted(self.old)[0]
        changed = self.previous - {pair} | {(pair[0], pair[1] + "Renamed")}
        with self.synthetic_previous(), self.assertRaisesRegex(RuntimeError, "2391-name Go test baseline changed"):
            subject.split_extension(self.projection(self.new | changed), self.packages)

    def test_full_guard_rejects_absent_new_increment(self):
        with self.synthetic_previous(), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
            subject.split_extension(self.projection(self.previous), self.packages)

    def test_replacement_subtest_cannot_satisfy_top_level_pair(self):
        for package, name in self.new:
            changed = self.new - {(package, name)} | {(package, name + "/fake")}
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "P1 capability test"):
                subject.split_extension(self.projection(changed | self.previous), self.packages)

    def test_production_previous_baseline_rejects_small_synthetic_set(self):
        # No count/hash patch: the production guard cannot accept this small
        # fixture even though it contains all 71+12 reviewed new names.
        with self.assertRaisesRegex(RuntimeError, "2391-name Go test baseline changed"):
            subject.split_extension(self.projection(self.previous | self.new), self.packages)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CapabilityExtensionTests))
    if result.testsRun != 16 or result.skipped or result.expectedFailures or result.unexpectedSuccesses or not result.wasSuccessful():
        raise SystemExit(1)
    print("P1_CAPABILITY_INCREMENT_SELFTEST=PASS tests=16 skips=0 synthetic_only=true")
