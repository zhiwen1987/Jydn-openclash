"""Closed P1 increment. Synthetic guards are not native execution evidence."""
from __future__ import annotations

import collections
import hashlib
import unittest

# Reviewed new pairs only. Never regenerate the accepted 2320-name baseline.
REQUIRED_PAIRS = frozenset((
    ("chengwang/internal/api", "TestProbeReadAPIAnonymousStatusIsMinimalCacheOnly"),
    ("chengwang/internal/api", "TestProbeReadAPIDisabledStatusAndProtectedDetails"),
    ("chengwang/internal/api", "TestProbeReadAPIUnauthorizedDoesNotReadDetails"),
    ("chengwang/internal/api", "TestProbeReadAPIPlaintextCredentialsFailBeforeDetails"),
    ("chengwang/internal/api", "TestProbeReadAPICrossScopeFailsBeforeDetails"),
    ("chengwang/internal/api", "TestProbeReadAPIReadResourceReturnsBoundedSafeDetails"),
    ("chengwang/internal/api", "TestProbeReadAPIMethodsAndQueriesNeverTriggerReads"),
    ("chengwang/internal/api", "TestProbeReadAPIRejectsOversizedProjectionWithoutPartialSuccess"),
    ("chengwang/internal/api", "TestProbeReadAPIMissingIdentityPrecedesDisabledAndQueryChecks"),
    ("chengwang/internal/api", "TestProbeReadAPILegacyObservationAndWriteGatesRemainDisabled"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeDisabledRejectsResidualConfiguration"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeEnabledRequiresCompleteConfiguration"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeIntervalsHaveClosedBounds"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbePathsAreAbsoluteCanonicalAndDistinct"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeEnvironmentIsStrictAndComplete"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeConfigurationErrorsNeverExposeInput"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbePartialConfigurationFailsBeforeListen"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeTypedConfigIgnoresProbeEnvironment"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeEnabledReadbackJoinsWithoutChangingInputs"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP1ProbeUnsafeCatalogFailsBeforeListen"),
    ("chengwang/internal/probeview", "TestProbeViewP1NewAndDisabledAreZeroIO"),
    ("chengwang/internal/probeview", "TestProbeViewP1ConfigurationBoundsAndCatalogDigest"),
    ("chengwang/internal/probeview", "TestProbeViewP1CatalogIsDeeplyOwned"),
    ("chengwang/internal/probeview", "TestProbeViewP1ReadUsesFixedNowOwnerAndLimits"),
    ("chengwang/internal/probeview", "TestProbeViewP1AnonymousStatusIsFixedSafeCacheOnly"),
    ("chengwang/internal/probeview", "TestProbeViewP1DetailsAreExplicitDeepCopies"),
    ("chengwang/internal/probeview", "TestProbeViewP1TwoPassThreeFailureHysteresis"),
    ("chengwang/internal/probeview", "TestProbeViewP1RestrictedAndRateLimitedStayDistinct"),
    ("chengwang/internal/probeview", "TestProbeViewP1Global200WindowDoesNotClaim256Coverage"),
    ("chengwang/internal/probeview", "TestProbeViewP1EvidenceTTLIsNotRenewedByPolling"),
    ("chengwang/internal/probeview", "TestProbeViewP1CacheAgeAndLayerTTLBoundDetails"),
    ("chengwang/internal/probeview", "TestProbeViewP1WallRollbackRequiresCatchupAndNewRead"),
    ("chengwang/internal/probeview", "TestProbeViewP1FutureAndNormalExpiredEvidenceAreNotGreen"),
    ("chengwang/internal/probeview", "TestProbeViewP1ReadFailuresNeverPreserveGreenCache"),
    ("chengwang/internal/probeview", "TestProbeViewP1ContentRejectionsCannotRevealOlderGreen"),
    ("chengwang/internal/probeview", "TestProbeViewP1MalformedCountsAndCrossScopeFailClosed"),
    ("chengwang/internal/probeview", "TestProbeViewP1ConcurrentSnapshotsDoNotAlias"),
    ("chengwang/internal/probeview", "TestProbeViewP1SingleWorkerCancellationActuallyJoins"),
    ("chengwang/internal/probeview", "TestProbeViewP1NativeReverseCatalogReadbackPreservesOriginalBytes"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreHealthyReadOnly"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreWriterLockDoesNotBlockRead"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreExpiredCountsAreNotCorruption"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreHistoricalEligibilityCounts"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreGlobalLimitIsActuallyTruncated"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreContentRejectionHasNoFilename"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreWrongOwnerRejected"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreWrongGroupRejected"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreLooseDirectoryRejectedWithoutRepair"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreLooseSegmentRejectedWithoutRepair"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreHardlinkRejected"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreSegmentSymlinkRejected"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreSegmentsDirectorySymlinkRejected"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreAncestorSymlinkRejected"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreFIFOIsBounded"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreOversizeFailsWithNoPartialView"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreAbsoluteEnumerationCountsAreReal"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreByteBudgetCountsAreReal"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreCanceledContextNoIO"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreExpiredDeadlineNoIO"),
    ("chengwang/internal/probe", "TestProbeSecureP1HeldFileRejectsNamedInodeReplacement"),
    ("chengwang/internal/probe", "TestProbeSecureP1HeldFileRejectsInPlaceMutation"),
    ("chengwang/internal/probe", "TestProbeSecureP1DirectoryRejectsParentReplacement"),
    ("chengwang/internal/probe", "TestProbeSecureP1DirectoryRejectsEntryMutation"),
    ("chengwang/internal/probe", "TestProbeSecureP1HeldReadHonorsCancellation"),
    ("chengwang/internal/probe", "TestProbeSecureP1StoreDoesNotLeakDescriptors"),
    ("chengwang/internal/probe", "TestProbeSecureP1CatalogValidBytesAndNoMutation"),
    ("chengwang/internal/probe", "TestProbeSecureP1CatalogRejectsSymlinkAndHardlink"),
    ("chengwang/internal/probe", "TestProbeSecureP1CatalogRejectsPermissionsAndRawErrors"),
    ("chengwang/internal/probe", "TestProbeSecureP1CatalogRootGroupMetadataPolicy"),
    ("chengwang/internal/probe", "TestProbeSecureP1InvalidInputsHaveClosedErrors"),
    ("chengwang/internal/probe", "TestProbeSecureP1FilesystemRejectsProcWithoutFallback"),
))
PREFIXES = ("TestProbeReadAPI", "TestServerRuntimeP1Probe", "TestProbeViewP1", "TestProbeSecureP1")

# Keep this increment separate from the already accepted 71-pair increment.
# Prefixes detect unreviewed names; only these exact pairs are ever removed.
CAPABILITY_REQUIRED_PAIRS = frozenset((
    ("chengwang/internal/api", "TestProbeCapabilitiesAPIUnconfiguredIsBlocked"),
    ("chengwang/internal/api", "TestProbeCapabilitiesAPIConfiguredCacheIsNotRead"),
    ("chengwang/internal/api", "TestProbeCapabilitiesAPIExpiredEvidenceDoesNotClaimHealth"),
    ("chengwang/internal/api", "TestProbeCapabilitiesAPIReportsDetachedProjection"),
    ("chengwang/internal/capability", "TestProbeReadbackCapabilityDefaultsBlocked"),
    ("chengwang/internal/capability", "TestProbeReadbackCapabilityConfiguredIsReadOnlyLocal"),
    ("chengwang/internal/capability", "TestProbeReadbackCapabilityEvidenceIsGETOnly"),
    ("chengwang/internal/capability", "TestProbeReadbackCapabilityDisclosesConfigurationNotHealth"),
    ("chengwang/internal/capability", "TestProbeReadbackRuntimeFactsPreserveLegacyCapabilities"),
    ("chengwang/internal/capability", "TestProbeReadbackLegacyOptionalObservationArityPreserved"),
    ("chengwang/internal/capability", "TestProbeReadbackCapabilityNeverEnablesProduction"),
    ("chengwang/internal/capability", "TestProbeReadbackBusinessProbeScopeRemainsDesignOnly"),
))
CAPABILITY_PREFIXES = ("TestProbeCapabilitiesAPI", "TestProbeReadback")
PRE_CAPABILITY_COUNT = 2391
PRE_CAPABILITY_SHA256 = "5faa2eeda5f6c6db5cbc52dead9bdf3e84d00bf67acd5d25f599a0fce33a4fdc"


def pair_fingerprint(pairs):
    return hashlib.sha256("".join(package + "\t" + name + "\n"
                                  for package, name in sorted(pairs)).encode("utf-8")).hexdigest()


def _split_capability_extension(passed_tests, terminal_packages):
    pairs = frozenset((package, name) for package, names in passed_tests.items() for name in names)
    observed = frozenset((package, name) for package, name in pairs if name.startswith(CAPABILITY_PREFIXES))
    if len(CAPABILITY_REQUIRED_PAIRS) != 12 or observed != CAPABILITY_REQUIRED_PAIRS:
        raise RuntimeError("missing, renamed, extra or wrong-package P1 capability test")
    if not {package for package, _ in CAPABILITY_REQUIRED_PAIRS}.issubset(terminal_packages):
        raise RuntimeError("P1 capability package has no terminal pass")
    return pairs - CAPABILITY_REQUIRED_PAIRS


def split_extension(passed_tests, terminal_packages):
    retained = _split_capability_extension(passed_tests, terminal_packages)
    if len(retained) != PRE_CAPABILITY_COUNT or pair_fingerprint(retained) != PRE_CAPABILITY_SHA256:
        raise RuntimeError("complete pre-capability 2391-name Go test baseline changed")
    projection = collections.defaultdict(set)
    for package, name in retained:
        projection[package].add(name)
    return _split_probe_extension(projection, terminal_packages)


def _split_probe_extension(passed_tests, terminal_packages):
    pairs = frozenset((package, name) for package, names in passed_tests.items() for name in names)
    observed = frozenset((package, name) for package, name in pairs if name.startswith(PREFIXES))
    if len(REQUIRED_PAIRS) != 71 or observed != REQUIRED_PAIRS:
        raise RuntimeError("missing, renamed, extra or wrong-package P1 probe test")
    if not {package for package, _ in REQUIRED_PAIRS}.issubset(terminal_packages):
        raise RuntimeError("P1 probe package has no terminal pass")
    retained = collections.defaultdict(set)
    for package, name in pairs - REQUIRED_PAIRS:
        retained[package].add(name)
    return retained


class ExtensionTests(unittest.TestCase):
    # These historical guards keep exercising the unchanged 71-pair contract,
    # independently of the new outer 12-pair and 2391-pair checks.
    def projection(self, pairs):
        result = collections.defaultdict(set)
        for package, name in pairs:
            result[package].add(name)
        return result

    def test_exact_protocol(self):
        self.assertEqual(len(REQUIRED_PAIRS), 71)
        self.assertEqual(collections.Counter(p for p, _ in REQUIRED_PAIRS), {
            "chengwang/internal/api": 10, "chengwang/internal/serverruntime": 10,
            "chengwang/internal/probe": 32, "chengwang/internal/probeview": 19})

    def test_retains_every_old_pair(self):
        old = {("chengwang/internal/probe", "TestOldUnchanged"), ("other", "TestRetained")}
        remaining = _split_probe_extension(self.projection(REQUIRED_PAIRS | old), {p for p, _ in REQUIRED_PAIRS})
        self.assertEqual({(p, n) for p, names in remaining.items() for n in names}, old)

    def test_missing_all_rejected(self):
        with self.assertRaises(RuntimeError): _split_probe_extension({}, set())

    def test_each_missing_pair_rejected(self):
        for pair in REQUIRED_PAIRS:
            with self.assertRaises(RuntimeError): _split_probe_extension(self.projection(REQUIRED_PAIRS - {pair}), {p for p, _ in REQUIRED_PAIRS})

    def test_each_wrong_package_rejected(self):
        for p, n in REQUIRED_PAIRS:
            with self.assertRaises(RuntimeError): _split_probe_extension(self.projection(REQUIRED_PAIRS - {(p, n)} | {("wrong", n)}), {p for p, _ in REQUIRED_PAIRS})

    def test_unknown_prefix_match_not_excluded(self):
        with self.assertRaises(RuntimeError): _split_probe_extension(self.projection(REQUIRED_PAIRS | {("chengwang/internal/probe", "TestProbeSecureP1Unknown")}), {p for p, _ in REQUIRED_PAIRS})

    def test_unreviewed_subtest_rejected(self):
        p, n = sorted(REQUIRED_PAIRS)[0]
        with self.assertRaises(RuntimeError): _split_probe_extension(self.projection(REQUIRED_PAIRS | {(p, n + "/unreviewed")}), {p for p, _ in REQUIRED_PAIRS})

    def test_every_terminal_package_required(self):
        packages = {p for p, _ in REQUIRED_PAIRS}
        for package in packages:
            with self.assertRaises(RuntimeError): _split_probe_extension(self.projection(REQUIRED_PAIRS), packages - {package})

    def test_old_hash_constants_not_recalibrated(self):
        import run_static_gate as gate
        self.assertEqual(gate.P0D9_GO_TEST_COUNT, 2320)
        self.assertEqual(gate.P0D9_GO_TEST_SHA256, "fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8")

    def test_cli_always_enables_increment(self):
        from unittest import mock
        import run_static_gate as gate
        with mock.patch("sys.argv", ["gate", "--go-json", "ordinary.json", "--go-json", "race.json"]), mock.patch.object(gate, "validate_go_json", return_value=0) as validator:
            self.assertEqual(gate.main(), 0)
            self.assertTrue(validator.call_args.kwargs.get("probe_extension"))


if __name__ == "__main__":
    from test_probe_test_extension import CapabilityExtensionTests
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ExtensionTests)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CapabilityExtensionTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != 26 or result.skipped or result.expectedFailures or result.unexpectedSuccesses or not result.wasSuccessful():
        raise SystemExit(1)
    print("P1_PARENT_INCREMENT_SELFTEST=PASS tests=26 skips=0 synthetic_only=true")
