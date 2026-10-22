#!/usr/bin/env python3
"""Require actual run/pass evidence for each binding layer and real Registry gate."""
import argparse
import collections
import hashlib
import io
import json
import pathlib

ROOT = "chengwang/image-binding"
POLICY = ROOT + "/policy"
REGISTRY = ROOT + "/registry"
CATALOG = ROOT + "/trustcatalog"
STATE = ROOT + "/truststate"
PRODUCT = ROOT + "/product"
COMMAND = ROOT + "/cmd/image-trust-api"
# Actual ordinary/race run sets from accepted P0-d4 run 39749344500,
# commit 90299930429c147ebde14c71739159ea20c5e6d7.  The encoding is
# sorted (package + TAB + test + LF), UTF-8, case-sensitive.  New root
# scenarios must use TestManaged*, rather than changing the old baseline.
BASELINE_PACKAGES = frozenset((ROOT, POLICY, REGISTRY))
BASELINE_COUNT = 234
BASELINE_SHA256 = "4b9a6d165db8f38febb92f0c9fd9e193a7816127c942d9732b423354090a81d8"
# P0-d5 run 39755876523 / commit 6a387bcd8a11a0590e5990723c5638fefa445adf.
# Both original ordinary/race artifacts contain precisely this 379-pair set.
# New P0-d6 tests are excluded only under their reviewed package/prefix pairs.
MANAGED_BASELINE_PACKAGES = frozenset((ROOT, POLICY, REGISTRY, CATALOG, STATE))
MANAGED_BASELINE_COUNT = 379
MANAGED_BASELINE_SHA256 = "5798a932b7ba01db90c067333c8ae93f6f0452f75f893f40669d7ba72534ac94"
NEW_MANAGED_PREFIXES = {
    ROOT: "TestManagedAPI",
    CATALOG: "TestProductCatalogue",
    STATE: "TestProductTrustState",
}
# Actual complete ordinary/race package sets from run 39763157348,
# commit 9590cce61b3d26dad3a93a7be80c07700c5fa5a1. Each hash encodes
# sorted test names joined by LF, without a terminal LF (parent-gate format).
PRODUCT_PACKAGE_FINGERPRINTS = {
    PRODUCT: (47, "3ca2523c7135cea4d0023460ebdc27e3a52f3cc1960650227ec69d915206554c"),
    COMMAND: (46, "54ff84975166165b073c1844ce727a23fdd3582295683663b8fb7d9cf67ec365"),
}
REQUIRED_ORDINARY = {
    ROOT: {
        "TestBindSignedRegistryImage", "TestBindSignedRegistryImage/message-signature", "TestBindSignedRegistryImage/dsse",
        "TestRejectInvalidBeforeRegistryAccess", "TestRejectOtherSignerAndRegistryTamper",
        "TestBindingZeroAndImportedReceiptsHaveNoAuthority",
        "TestUnmodifiedMinimalRegistryIsRejected",
        "TestUnmodifiedMinimalRegistryIsRejected/message-signature",
        "TestUnmodifiedMinimalRegistryIsRejected/dsse",
        "TestGeneratedSigningMaterial", "TestGeneratedSigningMaterial/message-signature", "TestGeneratedSigningMaterial/dsse",
        "TestGeneratedSameSignerPair", "TestGeneratedSameSignerPair/message-signature", "TestGeneratedSameSignerPair/dsse",
        "TestRejectSameSignerDifferentManifest", "TestRejectSameSignerDifferentManifest/message-signature", "TestRejectSameSignerDifferentManifest/dsse",
        "TestManagedBindPersistentReplay", "TestManagedBindPersistentReplay/message-signature",
        "TestManagedBindPersistentReplay/dsse", "TestManagedFailureBurnsGrant",
        "TestManagedConcurrentSingleWinner", "TestManagedRevocationDuringRegistryRead",
        "TestManagedRevocationDuringRegistryRead/message-signature", "TestManagedRevocationDuringRegistryRead/dsse",
        "TestManagedOpaqueAndInvalidInputs", "TestManagedGrantRenewalAndRevocation",
        "TestManagedAPIRealLifecycleAndBoundaries", "TestManagedAPINetworkRevocationAndBusy",
        "TestManagedAPIAuditFailureAfterConsumption",
    } | {"TestManagedAPIRealLifecycleAndBoundaries/" + case for case in (
        "anonymous", "wrong-role", "tenant", "site", "object", "environment", "query",
        "identity-injection", "duplicate", "noncanonical-base64", "operator-cannot-update")
    } | {"TestRejectInvalidBeforeRegistryAccess/" + case for case in (
        "approval", "bundle", "root", "key", "pin", "revision", "canceled", "nil_context")},
    POLICY: {
        "TestVerifySignedApproval", "TestValidityBoundariesAndRealClock",
        "TestNumericAndEnvelopeBoundaries", "TestTrustSignatureAndPinFailures",
        "TestTrustSignatureAndPinFailures/unsigned-spki-substitution",
        "TestSignedInvalidDocuments", "TestRegistryIPPolicies",
        "TestReferenceAndMessagePolicies", "TestStrictJSONAndEnvelope",
        "TestZeroValueCannotBeImportedAsApproval",
    } | {"TestSignedInvalidDocuments/" + case for case in (
        "spki-empty", "spki-uppercase", "spki-short", "spki-nonhex", "spki-unprefixed",
        "spki-null", "spki-number", "spki-alias", "missing-registrySPKISHA256")},
    REGISTRY: {
        "TestReadApprovedRegistryGraph", "TestPinnedIPBypassesDNSAndEnvironmentProxy",
        "TestDigestHeaderMayBeAbsent", "TestRejectApprovalAndTLSFailures",
        "TestRejectRedirectAndAuthRealmWithoutLeakingToken", "TestRejectResponseFramingAndMetadata",
        "TestRejectReadbackDriftAndGraphMismatch", "TestRejectDeclaredImageBudgets",
        "TestContextAndApprovalExpiry",
        "TestContextAndApprovalExpiry/nil_context", "TestContextAndApprovalExpiry/already_canceled",
        "TestContextAndApprovalExpiry/header_deadline", "TestContextAndApprovalExpiry/cancel_in_flight",
        "TestContextAndApprovalExpiry/expiry_after_first_request",
        "TestApprovalExpiryInterruptsBlockedResponse", "TestApprovalExpiryInterruptsBlockedResponse/body",
        "TestApprovalExpiryInterruptsBlockedResponse/eof", "TestRawHeaderRejectsHiddenDuplicateLength",
        "TestRegistrySPKIPinRejectsDifferentTrustedKey", "TestRegistrySPKIPinMissingOrWrong",
    },
    CATALOG: {
        "TestCatalogueLifecycle", "TestCatalogueRootThresholdRotation",
        "TestCatalogueExpiredHistoryAndFinalFreshness", "TestCatalogueGenerationAndAnchorBinding",
        "TestCatalogueMonotonicFloorsAndRevocation", "TestCatalogueHistoricalGrantIDCannotRebind",
        "TestCatalogueHistoricalGrantIDCannotRebind/approver",
        "TestCatalogueStrictJSONAndSignatures", "TestCatalogueStructuralResourceLimits",
        "TestCatalogueHistoryLimits", "TestCatalogueZeroAndImportedReceiptsHaveNoAuthority",
        "TestProductCatalogueSummaryDetachedAndRedacted",
    } | {"TestCatalogueRootThresholdRotation/" + case for case in (
        "old_only", "new_only", "partial_new", "duplicated_new", "wrong_signer", "retired_root",
        "initial_anchor_and_self")}
      | {"TestCatalogueMonotonicFloorsAndRevocation/" + case for case in (
        "floor_raise", "floor_rollback_nonzero", "key", "approval", "manifest", "floor_delete", "floor_zero", "floor_mismatch",
        "unapproved_key", "revoked_old_root_rotation", "revoked_active_root")}
      | {"TestCatalogueHistoryLimits/" + case for case in ("count", "total_bytes", "historical_grants")}
      | {"TestCatalogueStrictJSONAndSignatures/" + case for case in (
        "payload_duplicate", "payload_case_alias", "payload_escape_alias", "payload_float", "payload_exponent",
        "payload_negative", "payload_overflow", "payload_null_array", "payload_duplicate_floor",
        "payload_invalid_utf8", "payload_depth", "envelope_wrong_domain", "envelope_duplicate_signature",
        "envelope_unknown_signer", "envelope_short_signature", "base64_unpadded")},
    STATE: {
        "TestTrustStateCreateReserveConsumeReopen", "TestTrustStateConcurrentSingleWinner",
        "TestTrustStateUpdateRevokesInFlightGrant", "TestTrustStateExpiryAndClockRollback",
        "TestTrustStateSafeOpenRejectsMissingTruncatedAndLinks", "TestTrustStateLiveIdentityChangePoisons",
        "TestTrustStateTransactionFaultsFailClosed", "TestTrustStateLedgerCapacityNeverEvicts",
        "TestTrustStateTicketsAndInvalidInputsHaveNoAuthority", "TestTrustStateAnchorIsCopied",
        "TestTrustStateProcessLockAndCrashDurability", "TestTrustStateRecordChecksumRejectsParseableMutation",
        "TestTrustStateFinalExpiryBurnsConsumedGrant", "TestTrustStateFinalExpiryBurnsConsumedGrant/approval",
        "TestTrustStateFinalExpiryBurnsConsumedGrant/catalogue", "TestTrustStateFinalExpiryBurnsConsumedGrant/clock-rollback",
        "TestProductTrustStateInspectReadOnlyDetachedAndRedacted",
        "TestProductTrustStateInspectExpiredAndClockReadOnly", "TestProductTrustStateInspectInvalidContextsAndClosed",
    } | {"TestTrustStateUpdateRevokesInFlightGrant/" + case for case in (
        "key", "approval", "manifest", "new-generation")}
      | {"TestTrustStateExpiryAndClockRollback/" + case for case in (
        "approval-expiry", "catalogue-expiry", "clock-rollback", "expired-catalogue-refresh")}
      | {"TestTrustStateSafeOpenRejectsMissingTruncatedAndLinks/" + case for case in (
        "missing-dir", "missing-db", "empty-db", "truncated-db", "missing-marker", "bad-marker",
        "db-symlink", "db-hardlink", "db-mode", "directory-symlink", "wrong-anchor")}
      | {"TestTrustStateLiveIdentityChangePoisons/" + case for case in (
        "directory", "database", "marker", "mode", "database-hardlink")}
      | {"TestTrustStateTransactionFaultsFailClosed/" + case for case in (
        "before-put", "before-commit", "after-commit")}
      | {"TestTrustStateProcessLockAndCrashDurability/" + case for case in (
        "locked", "reserve-crash", "consume-crash")},
    PRODUCT: {
        "TestProductBackendDirectRBACAndWriteGateNoConsumption",
        "TestProductBackendStatusReadOnlyAndNoSecrets", "TestProductBackendCatalogueUpdateRealAuditAndSignature",
        "TestProductBackendAuditFailureBeforeMutationAndAfterCommit",
        "TestProductBackendRealVerifierBurnsGrantAndAuditsFailure", "TestProductBackendAuditFailureAfterVerifierBurn",
        "TestProductBackendTamperedAuditRefusesWrites", "TestProductBackendBusyAndRateBudgetNoReservation",
        "TestProductBackendConcurrentHealthyAuditAndUpdate", "TestProductBackendConstructorFixedScopeAndAuditHealth",
        "TestProductBackendAuditStatusFreshness", "TestProductBackendAuditResultSemantics",
    } | {"TestProductBackendDirectRBACAndWriteGateNoConsumption/" + case for case in (
        "viewer", "operator", "approver", "auditor", "admin", "anonymous", "tenant", "site", "object",
        "environment", "unknown-role")}
      | {"TestProductBackendAuditFailureBeforeMutationAndAfterCommit/" + case for case in (
        "before-pre-audit", "before-result-audit")}
      | {"TestProductBackendConstructorFixedScopeAndAuditHealth/" + case for case in (
        "nil-store", "nil-audit", "nil-roots", "wrong-store", "missing-tenant", "missing-site", "missing-env",
        "wrong-type", "header-token", "space-token", "tab-token", "unicode-token")}
      | {"TestProductBackendAuditStatusFreshness/" + case for case in (
        "stale", "future", "invalid", "issue", "count", "head")}
      | {"TestProductBackendAuditResultSemantics/" + case for case in (
        "verification-consumed", "verification-rejected", "catalogue-committed", "catalogue-rejected")},
    COMMAND: {
        "TestCandidateStrictConfigurationDecode", "TestCandidatePrivateFilesRejectUnsafeInputs",
        "TestCandidateNonLoopbackRequiresTLSBeforeListen", "TestCandidateMissingStoreNeverBootstraps",
        "TestCandidateRunAuthenticatedReadDefaultLockedAndGracefulClose", "TestCandidateRejectRelativeStatePaths",
        "TestCandidateTLSListenerRequiresValidExplicitTrust",
        "TestCandidateStrictIdentityProfile",
        "TestCandidateMissingAuditNeverInitializes",
    } | {"TestCandidateStrictConfigurationDecode/" + case for case in (
        "duplicate", "nested_duplicate", "unknown", "null", "trailing", "deep", "empty",
        "case_alias", "write_alias", "escaped_alias", "invalid_utf8")}
      | {"TestCandidateRejectRelativeStatePaths/" + case for case in ("store", "audit", "identities")}
      | {"TestCandidateStrictIdentityProfile/" + case for case in (
        "role-case-alias", "role-duplicate", "scope-case-alias")}
      | {"TestCandidateMissingAuditNeverInitializes/" + case for case in (
        "directory", "log", "checkpoint")}
      | {"TestCandidatePrivateFilesRejectUnsafeInputs/" + case for case in (
        "symlink", "hardlink", "mode", "directory_mode", "directory_symlink", "ancestor_write", "relative",
        "unclean", "missing", "directory", "empty", "oversized", "valid")},
}
REQUIRED_REGISTRY = {ROOT: {"TestRegistryCLIBindingLifecycle", "TestRegistryCLIBindingLifecycle/message-signature", "TestRegistryCLIBindingLifecycle/dsse"}}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON event key")
        result[key] = value
    return result


def read_events(stream, required):
    runs, passes, package_passes = collections.Counter(), collections.Counter(), collections.Counter()
    packages = set()
    for number, line in enumerate(stream, 1):
        event = json.loads(line, object_pairs_hook=unique_object)
        if not isinstance(event, dict):
            raise ValueError(f"invalid event at line {number}")
        package, action, test = event.get("Package"), event.get("Action"), event.get("Test")
        if not isinstance(package, str) or not package or action not in {"start", "run", "pause", "cont", "pass", "output"}:
            raise ValueError(f"invalid, skipped, failed or unsupported Go event at line {number}")
        if test is not None and (not isinstance(test, str) or not test.startswith("Test")):
            raise ValueError("invalid test name")
        packages.add(package)
        key = (package, test)
        if test and action == "run":
            runs[key] += 1
            if runs[key] != 1 or package_passes[package]:
                raise ValueError("repeated/late run")
        elif test and action == "pass":
            passes[key] += 1
            if runs[key] != 1 or passes[key] != 1 or package_passes[package]:
                raise ValueError("unmatched/repeated/late test pass")
        elif test is None and action == "pass":
            package_passes[package] += 1
            if package_passes[package] != 1:
                raise ValueError("repeated package pass")
    if not runs or runs != passes or packages != set(required) or set(package_passes) != packages:
        raise ValueError("missing tests, package, terminal pass, or mismatched test passes")
    required_pairs = {(package, test) for package, tests in required.items() for test in tests}
    if required_pairs - runs.keys():
        raise ValueError(f"required package/test pairs missing: {sorted(required_pairs - runs.keys())}")
    for package in packages:
        if not any(key[0] == package for key in runs):
            raise ValueError("package without executed tests")
    return frozenset(runs), frozenset(packages)


def synthetic(required):
    events = []
    for package, tests in sorted(required.items()):
        events.append({"Action": "start", "Package": package})
        for name in sorted(tests):
            events.extend(({"Action": "run", "Package": package, "Test": name},
                           {"Action": "pass", "Package": package, "Test": name}))
        events.append({"Action": "pass", "Package": package})
    return events


def check_baseline(tests):
    baseline = sorted((package, name) for package, name in tests
                      if package in BASELINE_PACKAGES and
                      not (package == ROOT and name.startswith("TestManaged")))
    digest = hashlib.sha256("".join(package + "\t" + name + "\n"
                                  for package, name in baseline).encode("utf-8")).hexdigest()
    if len(baseline) != BASELINE_COUNT or digest != BASELINE_SHA256:
        raise ValueError(f"accepted P0-d4 test baseline changed: count={len(baseline)} sha256={digest}")


def check_managed_baseline(tests):
    baseline = sorted((package, name) for package, name in tests
                      if package in MANAGED_BASELINE_PACKAGES and
                      not name.startswith(NEW_MANAGED_PREFIXES.get(package, "\x00")))
    digest = hashlib.sha256("".join(package + "\t" + name + "\n"
                                  for package, name in baseline).encode("utf-8")).hexdigest()
    if len(baseline) != MANAGED_BASELINE_COUNT or digest != MANAGED_BASELINE_SHA256:
        raise ValueError(f"accepted P0-d5 test baseline changed: count={len(baseline)} sha256={digest}")


def check_product_packages(tests):
    for package, (count, expected) in PRODUCT_PACKAGE_FINGERPRINTS.items():
        names = sorted(name for actual, name in tests if actual == package)
        digest = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()
        if len(names) != count or digest != expected:
            raise ValueError(f"accepted product package test set changed: {package} count={len(names)} sha256={digest}")


def self_test():
    negative_count = 0
    for required in (REQUIRED_ORDINARY, REQUIRED_REGISTRY):
        valid = synthetic(required)
        def parse(events):
            return read_events(io.StringIO("".join(json.dumps(e) + "\n" for e in events)), required)
        parse(valid)
        missing_name = sorted(required[ROOT])[0]
        bad = [[], valid[:-1], valid + [valid[-1]],
               valid + [{"Action": "skip", "Package": ROOT}],
               valid + [{"Action": "fail", "Package": ROOT}],
               valid + [{"Action": "pass", "Package": ROOT + "/unexpected"}],
               [e for e in valid if e.get("Test") != missing_name],
               [dict(e, Package=ROOT + "/forged") if e.get("Test") == missing_name else e for e in valid],
               valid + [{"Action": "run", "Package": ROOT, "Test": "TestLate"}],
               valid + [{"Action": "bench", "Package": ROOT}],
               valid + [{"Action": "output"}],
               [e for e in valid if e["Package"] != ROOT]]
        for events in bad:
            try:
                parse(events)
            except ValueError:
                negative_count += 1
                continue
            raise ValueError("gate accepted invalid synthetic transcript")
    for raw in ('{}', '[]', '\n', '{"Action":"pass","Action":"run","Package":"x"}'):
        try:
            read_events(io.StringIO(raw), REQUIRED_ORDINARY)
        except ValueError:
            negative_count += 1
            continue
        raise ValueError("gate accepted malformed synthetic JSON")
    for checker in (check_baseline, check_managed_baseline, check_product_packages):
        for tests in (frozenset(), frozenset({(ROOT, "TestManagedForgedBaseline")}),
                      frozenset({(ROOT, "TestBindSignedRegistryImage")})):
            try:
                checker(tests)
            except ValueError:
                negative_count += 1
                continue
            raise ValueError("gate accepted missing or substituted accepted test baseline")
    print(f"IMAGE_BINDING_JSON_SELFTEST=PASS negative_cases={negative_count}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--mode", choices=("ordinary", "registry"), default="ordinary")
    parser.add_argument("transcripts", nargs="*", type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if not args.transcripts and args.self_test:
        return
    if len(args.transcripts) != 2 or args.transcripts[0].resolve() == args.transcripts[1].resolve():
        parser.error("two distinct ordinary and race transcripts required")
    required = REQUIRED_ORDINARY if args.mode == "ordinary" else REQUIRED_REGISTRY
    results = []
    for path in args.transcripts:
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("missing or oversized transcript")
        with path.open(encoding="utf-8") as stream:
            results.append(read_events(stream, required))
    if results[0] != results[1]:
        raise ValueError("ordinary/race test or package sets differ")
    if args.mode == "ordinary":
        check_baseline(results[0][0])
        check_managed_baseline(results[0][0])
        check_product_packages(results[0][0])
    print(f"IMAGE_BINDING_GO_JSON_GATE=PASS mode={args.mode} transcripts=2 "
          f"tests={len(results[0][0])} packages={len(results[0][1])} skips=0 race=pass "
          "authorization=BLOCKED production=false")


if __name__ == "__main__":
    main()
