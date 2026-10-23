"""Reviewed subscription increment; synthetic guard tests are not runtime proof."""
from __future__ import annotations

import collections
import hashlib
import json
import pathlib
import unittest

PACKAGE = "chengwang/internal/subscription"
# Frozen from independently assigned task contracts, not generated from a CI
# transcript or from whatever tests happen to exist in the working tree.
REQUIRED_NAMES = frozenset((
    "TestSubscriptionPipelineTLSQuarantineManySourcesAndRestart",
    "TestSubscriptionCoreLimitsAreClosed",
    "TestSubscriptionCoreScopesRejectAmbiguousValues",
    "TestSubscriptionCoreSourceIDsAreOpaque",
    "TestSubscriptionCoreIdempotencyBounds",
    "TestSubscriptionCoreKeyedIdentityIsolation",
    "TestSubscriptionCoreJSONDoesNotExposePrivateIngress",
    "TestSubscriptionCoreNodeViewIsDetachedUnknown",
    "TestSubscriptionCoreFailureRedaction",
    "TestSubscriptionParserMihomoProtocols",
    "TestSubscriptionParserURIProtocols",
    "TestSubscriptionParserBase64VariantsAndAuto",
    "TestSubscriptionParserShadowsocksSIP002AndLegacy",
    "TestSubscriptionParserVMessStrictJSON",
    "TestSubscriptionParserPrivateTransportPreservation",
    "TestSubscriptionParserUnsupportedFieldsRejectWholeBatch",
    "TestSubscriptionParserUnsupportedProtocolsRejectWholeBatch",
    "TestSubscriptionParserYAMLComplexityLimits",
    "TestSubscriptionParserYAMLDuplicateKeys",
    "TestSubscriptionParserYAMLAnchorsAliasesTags",
    "TestSubscriptionParserYAMLDocumentsAndRoot",
    "TestSubscriptionParserInputBoundsAndUTF8",
    "TestSubscriptionParserScopeSourceKeyValidation",
    "TestSubscriptionParserIdentityStableRenameAndReorder",
    "TestSubscriptionParserIdentityScopeSourceKeySeparation",
    "TestSubscriptionParserIdentityCredentialAndConnectionChanges",
    "TestSubscriptionParserDedupDeterministicNames",
    "TestSubscriptionParserPrivateJSONNeverLeaks",
    "TestSubscriptionParserInputOutputDetached",
    "TestSubscriptionParserURIQueryAndAuthorityClosed",
    "TestSubscriptionParserTypedOptionsNoCoercion",
    "TestSubscriptionParserPortsHostsCredentials",
    "TestSubscriptionParserFailureSanitization",
    "TestSubscriptionParserDeterministicReparse",
    "TestSubscriptionParserConcurrentParsingNoSharedState",
    "TestSubscriptionStoreCreateSourcePrivateAndDetached",
    "TestSubscriptionStoreSourceScopeIsolation",
    "TestSubscriptionStoreTwoSourceProvenance",
    "TestSubscriptionStoreImportQuarantinedByDefault",
    "TestSubscriptionStoreAdmitAdvancesLocalPointer",
    "TestSubscriptionStoreRejectPreservesLastKnownValid",
    "TestSubscriptionStoreParseFailurePreservesLastKnownValid",
    "TestSubscriptionStoreRepeatedContentIsIdempotent",
    "TestSubscriptionStoreRenameKeepsStableNodes",
    "TestSubscriptionStoreReorderedNodesKeepIdentity",
    "TestSubscriptionStoreIdempotencyMismatchRejected",
    "TestSubscriptionStoreIdempotencyActorAndScopeBound",
    "TestSubscriptionStoreExpectedRevisionConflict",
    "TestSubscriptionStoreStaleCandidateCannotAdmit",
    "TestSubscriptionStoreRollbackRequiresPreviouslyAdmitted",
    "TestSubscriptionStoreRollbackCreatesNewRevision",
    "TestSubscriptionStoreRollbackExpectedRevisionConflict",
    "TestSubscriptionStoreRestartRevalidatesPrivateSnapshot",
    "TestSubscriptionStorePublicViewsNeverRevealPrivateMaterial",
    "TestSubscriptionStoreTamperedRawRejectedOnOpen",
    "TestSubscriptionStoreTamperedConfigRejectedOnOpen",
    "TestSubscriptionStoreUnknownDuplicateAndTrailingJSONRejected",
    "TestSubscriptionStoreSourceCandidateAuditAndByteLimits",
    "TestSubscriptionStoreConcurrentMutationSerialized",
    "TestSubscriptionStoreSecondControllerRejected",
    "TestSubscriptionStoreCloseReleasesProcessLock",
    "TestSubscriptionStoreExistingWideDirectoryRejectedUnchanged",
    "TestSubscriptionStoreSymlinkAncestorsAndFilesRejected",
    "TestSubscriptionStoreHardlinkAndFIFORejected",
    "TestSubscriptionStoreWrongOwnerAndModesRejected",
    "TestSubscriptionStoreReplacedDirectoryLockOrSnapshotFailClosed",
    "TestSubscriptionStoreFailedPreRenameWritePreservesSnapshot",
    "TestSubscriptionStoreDirectorySyncFailurePoisonsStore",
    "TestSubscriptionStoreAuditRecordsBoundedAndSecretFree",
    "TestFetchPolicyRejectsUnsafeExactURLs",
    "TestFetcherRequiresTrustedResolverAndScope",
    "TestFetchPinsCompleteSnapshotAndNormalTLS",
    "TestFetchRejectsMixedAndUnsafeDNSBeforeDial",
    "TestFetchRejectsIncompleteUnapprovedCNAMEChains",
    "TestFetchRejectsTLSMismatchAndUntrustedRoots",
    "TestFetchRejectsRedirectWithoutFollowing",
    "TestFetchRejectsHTTPStatusesAndRateLimit",
    "TestFetchRejectsEncodedAndCookieResponses",
    "TestFetchEnforcesBodyBudgetAndTruncation",
    "TestFetchEnforcesHeaderBudget",
    "TestFetchUsesFixedTimeoutBudgets",
    "TestFetchHonorsContextCancellationAcrossPhases",
    "TestFetchIgnoresEnvironmentProxyAndSendsNoCookies",
    "TestFetchPolicyAndResultsDoNotSerializePrivateBytes",
    "TestFetchErrorsNeverExposeSecretSentinel",
    "TestFetchDoesNotRetryOrFetchNestedProviders",
    "TestFetcherCopiesTrustedPolicyAndRoots",
))
REQUIRED_PAIRS = frozenset((PACKAGE, name) for name in REQUIRED_NAMES)
PRE_COUNT = 2403
PRE_SHA256 = "4988f181a389575003152bfd2194485f030506f63859133229019f8d5db4441b"


def fingerprint(pairs):
    return hashlib.sha256("".join(package + "\t" + name + "\n"
        for package, name in sorted(pairs)).encode()).hexdigest()


def strip_reviewed(passed_tests, terminal_packages):
    pairs = frozenset((package, name) for package, names in passed_tests.items() for name in names)
    observed = frozenset(pair for pair in pairs if pair[0] == PACKAGE or pair[1] in REQUIRED_NAMES)
    if len(REQUIRED_PAIRS) != 87 or observed != REQUIRED_PAIRS or PACKAGE not in terminal_packages:
        raise RuntimeError("subscription exact reviewed test increment missing or changed")
    return pairs - REQUIRED_PAIRS


def split_extension(passed_tests, terminal_packages):
    retained = strip_reviewed(passed_tests, terminal_packages)
    if len(retained) != PRE_COUNT or fingerprint(retained) != PRE_SHA256:
        raise RuntimeError("pre-subscription complete 2403-test baseline changed")
    result = collections.defaultdict(set)
    for package, name in retained:
        result[package].add(name)
    return result


def validate_events(events):
    runs, passes, terminal = collections.Counter(), collections.Counter(), 0
    expected = collections.Counter({name: 1 for name in REQUIRED_NAMES})
    for event in events:
        if not isinstance(event, dict):
            raise RuntimeError("subscription Go event is not an object")
        package, name, action = event.get("Package"), event.get("Test"), event.get("Action")
        if name in REQUIRED_NAMES and package != PACKAGE:
            raise RuntimeError("subscription test moved to an unreviewed package")
        if package != PACKAGE:
            continue
        if terminal:
            raise RuntimeError("subscription event after terminal package pass")
        if action in ("fail", "skip"):
            raise RuntimeError("subscription test or package failed or skipped")
        if name is not None:
            if not isinstance(name, str) or name not in REQUIRED_NAMES:
                raise RuntimeError("subscription unreviewed test or subtest")
            if action == "run":
                runs[name] += 1
            if action == "pass":
                if runs[name] != 1:
                    raise RuntimeError("subscription pass without exactly one preceding run")
                passes[name] += 1
        elif action == "pass":
            if runs != expected or passes != expected:
                raise RuntimeError("subscription terminal before complete run/pass")
            terminal += 1
    if runs != expected or passes != expected or terminal != 1:
        raise RuntimeError("subscription actual run/pass or terminal package mismatch")


def validate_transcript(path):
    def closed_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate Go event field")
            value[key] = item
        return value
    def events():
        with pathlib.Path(path).open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    yield json.loads(line, object_pairs_hook=closed_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonstandard Go event number")))
    validate_events(events())


class SubscriptionIncrementTests(unittest.TestCase):
    def events(self):
        result = []
        for name in sorted(REQUIRED_NAMES):
            result.extend([dict(Package=PACKAGE, Test=name, Action=action) for action in ("run", "pass")])
        return result + [dict(Package=PACKAGE, Action="pass")]

    def projection(self, pairs):
        result = collections.defaultdict(set)
        for package, name in pairs:
            result[package].add(name)
        return result

    def test_exact_increment_and_synthetic_positive(self):
        self.assertEqual(len(REQUIRED_NAMES), 87)
        validate_events(self.events())
        self.assertEqual(strip_reviewed(self.projection(REQUIRED_PAIRS | {("legacy", "TestLegacy")}), {PACKAGE}), {("legacy", "TestLegacy")})

    def test_every_missing_or_renamed_pair_rejected(self):
        for pair in REQUIRED_PAIRS:
            for changed in (REQUIRED_PAIRS - {pair}, REQUIRED_PAIRS - {pair} | {(pair[0], pair[1] + "Renamed")}):
                with self.assertRaises(RuntimeError):
                    strip_reviewed(self.projection(changed), {PACKAGE})

    def test_every_wrong_package_and_unreviewed_pair_rejected(self):
        for pair in REQUIRED_PAIRS:
            with self.assertRaises(RuntimeError):
                strip_reviewed(self.projection(REQUIRED_PAIRS - {pair} | {("wrong", pair[1])}), {PACKAGE})
        with self.assertRaises(RuntimeError):
            strip_reviewed(self.projection(REQUIRED_PAIRS | {(PACKAGE, "TestUnreviewed")}), {PACKAGE})

    def test_terminal_and_legacy_baselines_are_mandatory(self):
        with self.assertRaises(RuntimeError):
            strip_reviewed(self.projection(REQUIRED_PAIRS), set())
        with self.assertRaises(RuntimeError):
            split_extension(self.projection(REQUIRED_PAIRS | {("legacy", "TestReplacedBaseline")}), {PACKAGE})

    def test_duplicate_run_or_pass_and_missing_terminal_rejected(self):
        sample = sorted(REQUIRED_NAMES)[0]
        for action in ("run", "pass"):
            events = self.events()
            events.insert(1, dict(Package=PACKAGE, Test=sample, Action=action))
            with self.assertRaises(RuntimeError):
                validate_events(events)
        for events in (self.events()[:-1], self.events() + [dict(Package=PACKAGE, Action="pass")],
                       self.events()[-1:] + self.events()[:-1],
                       self.events() + [dict(Package=PACKAGE, Test=sample, Action="output")]):
            with self.assertRaises(RuntimeError):
                validate_events(events)

    def test_fail_skip_pass_without_run_and_subtest_rejected(self):
        for event in (dict(Package=PACKAGE, Action="fail"), dict(Package=PACKAGE, Action="skip"),
                      dict(Package=PACKAGE, Test=sorted(REQUIRED_NAMES)[0], Action="skip"),
                      dict(Package=PACKAGE, Test="TestUnreviewed/subtest", Action="run")):
            with self.assertRaises(RuntimeError):
                validate_events(self.events() + [event])
        with self.assertRaises(RuntimeError):
            validate_events(self.events()[1:])


if __name__ == "__main__":
    unittest.main()
