#!/usr/bin/env python3
"""Synthetic exact P1 extension tests; never substitutes for actual Go runs."""
import importlib.util
import pathlib
import sys
import unittest
from unittest import mock

source = pathlib.Path(__file__).with_name("check-go-json.py")
spec = importlib.util.spec_from_file_location("probe_json_gate", source)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

EXPECTED = frozenset((gate.COMMAND, name) for name in (
    "TestCandidateP1ProbeOmittedConfigurationPreservesLegacyJSON",
    "TestCandidateP1ProbeExplicitConfigurationHasClosedBounds",
    "TestCandidateP1ProbeNestedConfigurationRejectsUnknownFields",
    "TestCandidateP1ProbeDisabledRuntimeIgnoresInheritedEnvironment",
))


class ProbeExtensionTests(unittest.TestCase):
    old = frozenset((gate.ROOT, "TestSyntheticRetained" + str(i)) for i in range(728))

    def test_exact_four_protocol_and_old_constants_unchanged(self):
        self.assertEqual(gate.P1_PROBE_REQUIRED_PAIRS, EXPECTED)
        self.assertEqual(gate.D12_ORDINARY_COUNT, 728)
        self.assertEqual(gate.ACCEPTED_D9_COUNT, 700)
        self.assertEqual(gate.ACCEPTED_D9_SHA256, "b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999")
        self.assertEqual(gate.P1_PROBE_ORDINARY_COUNT, 732)

    def test_only_exact_four_are_removed_before_original_validator(self):
        with mock.patch.object(gate, "check_ordinary_test_set") as original:
            gate.check_probe_ordinary_test_set(self.old | EXPECTED)
            original.assert_called_once_with(self.old)

    def test_missing_each_reviewed_pair_fails(self):
        for pair in EXPECTED:
            with self.assertRaises(ValueError):
                gate.check_probe_ordinary_test_set(self.old | (EXPECTED - {pair}))

    def test_renamed_same_count_fails(self):
        for pair in EXPECTED:
            changed = (self.old | EXPECTED) - {pair} | {(pair[0], pair[1] + "Renamed")}
            with self.assertRaises(ValueError):
                gate.check_probe_ordinary_test_set(changed)

    def test_same_name_wrong_package_fails(self):
        for pair in EXPECTED:
            changed = (self.old | EXPECTED) - {pair} | {(gate.PRODUCT, pair[1])}
            with self.assertRaises(ValueError):
                gate.check_probe_ordinary_test_set(changed)

    def test_unknown_prefix_name_is_not_excluded(self):
        with self.assertRaises(ValueError):
            gate.check_probe_ordinary_test_set(self.old | EXPECTED | {(gate.COMMAND, "TestCandidateP1ProbeUnreviewed")})

    def test_fake_subtest_is_not_reviewed_extension(self):
        for pair in EXPECTED:
            with self.assertRaises(ValueError):
                gate.check_probe_ordinary_test_set(self.old | EXPECTED | {(pair[0], pair[1] + "/fake")})

    def test_extra_unrelated_pair_fails_count(self):
        with self.assertRaises(ValueError):
            gate.check_probe_ordinary_test_set(self.old | EXPECTED | {(gate.COMMAND, "TestUnrelatedExtra")})

    def test_deleted_old_pair_is_not_replaced_by_extension(self):
        with self.assertRaises(ValueError):
            gate.check_probe_ordinary_test_set((self.old - {next(iter(self.old))}) | EXPECTED)

    def test_original_validator_failure_is_not_masked(self):
        with mock.patch.object(gate, "check_ordinary_test_set", side_effect=ValueError("old baseline rejected")):
            with self.assertRaisesRegex(ValueError, "old baseline rejected"):
                gate.check_probe_ordinary_test_set(self.old | EXPECTED)
        # No mock: arbitrary 728 names cannot pass the real historical chain.
        with self.assertRaises(ValueError):
            gate.check_probe_ordinary_test_set(self.old | EXPECTED)

    def test_original_728_validator_still_requires_all_historical_checks(self):
        names = ("check_baseline", "check_managed_baseline", "check_product_packages", "check_product_baseline",
                 "check_complete_packages", "check_current_packages", "check_d9_complete_packages")
        retained = frozenset((gate.ROOT, "TestRetained" + str(i)) for i in range(700))
        calls = []
        patches = [mock.patch.object(gate, name, side_effect=lambda value, name=name: calls.append((name, value))) for name in names]
        for patch in patches:
            patch.start()
        try:
            gate.check_ordinary_test_set(retained | gate.D12_REQUIRED_PAIRS)
        finally:
            for patch in reversed(patches):
                patch.stop()
        self.assertEqual(calls, [(name, retained) for name in names])

    def test_historical_names_similar_to_prefix_are_retained(self):
        old = frozenset(((gate.COMMAND, "TestCandidateP1Other"), (gate.ROOT, "TestProbeReadOther")))
        self.assertEqual(gate.split_probe_extension(old | EXPECTED), old)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProbeExtensionTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    accepted = result.wasSuccessful() and not result.skipped and result.testsRun == 12
    if accepted:
        print("P1_PROBE_GO_JSON_TESTS=PASS tests=12 skipped=0 synthetic_only=true")
    sys.exit(0 if accepted else 1)
