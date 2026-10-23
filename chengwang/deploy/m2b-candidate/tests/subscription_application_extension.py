"""Exact P2-05 increment. Guard unit fixtures are synthetic, not Go proof."""
from __future__ import annotations
import collections
import hashlib
import json
import pathlib
import unittest
import subscription_test_extension as core

# Frozen from independent task cards before CI, not inferred from green output.
REQUIRED_PAIRS = frozenset((
    ("chengwang/internal/authz", "TestSubscriptionAuthzRoleMatrix"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzCrossTenantAndSiteDenied"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzObjectGrantsAreExact"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzControlAndDraftDoNotGrantSubscription"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzBreakGlassAlwaysDenied"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzUnknownAndMixedRolesDenied"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzInvalidResourcesFailClosed"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzCollectionCannotMutateSource"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzCombinedRolesStayScoped"),
    ("chengwang/internal/authz", "TestSubscriptionAuthzNonSubscriptionPoliciesUnchanged"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205DisabledDefaultsAndResidualClosed"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205IdentityTLSAndScopeRequired"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205PolicyPathIsCanonical"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205EnvironmentBooleanIsStrict"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205EnvironmentCompleteAndIndependent"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205ShortWriteTimeoutFailsBeforePrivateRead"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205PolicyOptionalForManualAdmissionOnly"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205ScopeNeverTruncatedOrHashed"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205NormalTLSMultiSourceAdmissionAndRestart"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205IndependentRolesAndTenantOverTLS"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205DisabledDoesNotOpenSubscriptionPaths"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205WriteGateCannotMutateRealInventory"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205UnsafeStoreFailsBeforeListen"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205UnsafePolicyFailsBeforeStoreAndListen"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205ShutdownReleasesInventoryAndAudit"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeP205TypedConfigIgnoresSubscriptionEnvironment"),
    ("chengwang/internal/api", "TestSubscriptionAPIProtectedRoutesRequireStrictBearer"),
    ("chengwang/internal/api", "TestSubscriptionAPILegacyAdminCannotAuthenticate"),
    ("chengwang/internal/api", "TestSubscriptionAPIPlaintextRequiresSecureTransport"),
    ("chengwang/internal/api", "TestSubscriptionAPIScopeCacheCPUOnly"),
    ("chengwang/internal/api", "TestSubscriptionAPIBackendUnavailableAndTypedNil"),
    ("chengwang/internal/api", "TestSubscriptionAPIRolesHaveIndependentActions"),
    ("chengwang/internal/api", "TestSubscriptionAPICrossTenantSiteEnvironmentDeniedBeforePrivateRead"),
    ("chengwang/internal/api", "TestSubscriptionAPISourceGrantCannotListOrCreateCollection"),
    ("chengwang/internal/api", "TestSubscriptionAPIWritesDisabledBeforeBodyRead"),
    ("chengwang/internal/api", "TestSubscriptionAPIDeniedAuditFailureDoesNotOpenPrivatePath"),
    ("chengwang/internal/api", "TestSubscriptionAPIContextCancellationDoesNotCallBackend"),
    ("chengwang/internal/api", "TestSubscriptionAPIMethodsClosedAcrossRoutes"),
    ("chengwang/internal/api", "TestSubscriptionAPIQueryIsClosedAndCanonical"),
    ("chengwang/internal/api", "TestSubscriptionAPIRequestEncodingAndContentTypeClosed"),
    ("chengwang/internal/api", "TestSubscriptionAPIBodyBudgetAndTruncation"),
    ("chengwang/internal/api", "TestSubscriptionAPIJSONDuplicateUnknownAndTrailingRejected"),
    ("chengwang/internal/api", "TestSubscriptionAPIJSONUTF8DepthAndScalarTypesRejected"),
    ("chengwang/internal/api", "TestSubscriptionAPICreateUnicodeLabelAndRouteOwnedKind"),
    ("chengwang/internal/api", "TestSubscriptionAPIImportCanonicalBase64PreservesPrivateBytes"),
    ("chengwang/internal/api", "TestSubscriptionAPIImportFormatsAndRawBudgetClosed"),
    ("chengwang/internal/api", "TestSubscriptionAPIDecisionOnlyLocalStatesAndCAS"),
    ("chengwang/internal/api", "TestSubscriptionAPIRollbackApprovalAndFetchCommandsAreClosed"),
    ("chengwang/internal/api", "TestSubscriptionAPIIdempotencyHeaderIsUniqueAndBounded"),
    ("chengwang/internal/api", "TestSubscriptionAPISourceAndCandidatePathsRejectAliases"),
    ("chengwang/internal/api", "TestSubscriptionAPISourcePageSafeBoundary"),
    ("chengwang/internal/api", "TestSubscriptionAPICandidateSummariesNeverExposeNodes"),
    ("chengwang/internal/api", "TestSubscriptionAPINodePagesBoundedAndRevisionFenced"),
    ("chengwang/internal/api", "TestSubscriptionAPIReceiptRoutesAreProtectedAndSafe"),
    ("chengwang/internal/api", "TestSubscriptionAPIBackendErrorsAreClosedAndStateExplicit"),
    ("chengwang/internal/api", "TestSubscriptionAPIUnknownBackendErrorsSuppressRawSecrets"),
    ("chengwang/internal/api", "TestSubscriptionAPIInvalidBackendProjectionFailsClosed"),
    ("chengwang/internal/api", "TestSubscriptionAPIActualIdentityStoreAuthentication"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205ParseValidAndImmutable"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205StrictJSON"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205FieldTypesAndRequired"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205VersionAndSourceBudgets"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205ExactHTTPSAndCNAMEs"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205FixedDoTOnly"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205RootPools"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205MaterialBindsAllInputs"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205MaterialCanonicalOrder"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205DescribeCopies"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205ScopeAndReferenceRejected"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SourceIDRejected"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205NilAndZero"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205PrivateFmtAndJSON"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205ContextCancellation"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureLoadAndNoMutation"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureRejectsPermissions"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureRejectsSymlinkAndHardlink"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureRejectsFIFO"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureRejectsOwnerAndFilesystem"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureDetectsHeldMutation"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205SecureRejectsPathsAndBudgets"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205DoTNormalTLS"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205DoTWrongTrust"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205DoTWrongName"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205DoTTimeoutAndCancellation"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205FetchUsesConfiguredResolver"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionPolicyP205PlatformBoundary"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlNewRejectsInvalidConfiguration"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlDisabledWritesNeverTouchesDomain"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlDirectAuthorizationAndScope"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlActorIdentityBoundWithoutTruncation"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlListSourcesSafeBounded"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlCandidateSummariesHideNodes"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlNodesPaginationBounded"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlContinuationRevisionRequired"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlContinuationRevisionConflict"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlPreparedAuditFailureNoDomainOrFetch"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlPreparedAuditFailureNoParse"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlCreateReceiptImmutable"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlImportDecisionRollbackReceipts"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlCommandReplaySameActor"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlCommandReplayOtherActorDenied"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlCommandKeyConflict"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlPostAuditFailureReturnsDegraded"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlRecoverRepairsCommittedWithoutReplay"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlRecoverPreparedWithoutMutationUnknown"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlRecoverNoopReceiptAcrossRestart"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlApprovalBoundToMaterialAndRevision"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlApprovalSurvivesRestart"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlFetchRequiresCurrentApproval"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlFetchRechecksApprovalAfterNetwork"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlFetchRechecksSourceCASAfterNetwork"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlFetchFailureNeverImports"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlCancellationBeforeMutation"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlDenialAuditNoPrivateReadsOrNetwork"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlExternalEvidenceActorAndSafeMetadata"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlRealLinuxRestartAuditChainAndReceipts"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlConcurrentCommandsSingleFlight"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionControlJournalCapacityAndClosedErrors"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlMutationReceiptUsesHistoricalAudit"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlMutationReceiptBindsScopeActorKey"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlMutationReceiptAbsentOnNoop"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlLegacySnapshotCompatible"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlImmutableCommandBindings"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlResultAndAckMonotonic"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlRestartValidation"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlUnknownDoesNotReplay"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlApprovalPersistentHMAC"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlApprovalCASAndInvalidation"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlJournalCapacity"),
    ("chengwang/internal/subscription", "TestSubscriptionStoreControlTamperRejected"),
))
REQUIRED_NAMES = frozenset(name for _, name in REQUIRED_PAIRS)
REQUIRED_PACKAGES = frozenset(package for package, _ in REQUIRED_PAIRS)
PRE_COUNT = 2490
PRE_SHA256 = "1c3d08f5f99f1d34861a6439d8cde3d95422232dc8fa70206e2d0f09ea229dd4"

def fingerprint(pairs):
    return hashlib.sha256("".join(p + "\t" + n + "\n" for p,n in sorted(pairs)).encode()).hexdigest()

def split_extension(passed_tests, terminal_packages):
    pairs = frozenset((p,n) for p,names in passed_tests.items() for n in names)
    observed = frozenset(pair for pair in pairs if pair in REQUIRED_PAIRS or pair[1] in REQUIRED_NAMES
                         or pair[0] in ("chengwang/internal/subscriptionctl", "chengwang/internal/subscriptionpolicy"))
    if len(REQUIRED_PAIRS) != 130 or observed != REQUIRED_PAIRS or not REQUIRED_PACKAGES <= terminal_packages:
        raise RuntimeError("subscription application exact increment missing or changed")
    retained = pairs - REQUIRED_PAIRS
    if len(retained) != PRE_COUNT or fingerprint(retained) != PRE_SHA256:
        raise RuntimeError("pre-application complete 2490-test baseline changed")
    result = collections.defaultdict(set)
    for p,n in retained:
        result[p].add(n)
    return result

def projected_core_events(events):
    # Only exact new pairs are removed. Unknown names/pseudo-subtests still
    # reach the unchanged original 87-test validator and must be rejected.
    return [e for e in events if (e.get("Package"),e.get("Test")) not in REQUIRED_PAIRS]

def validate_events(events):
    runs, passes, terminal = collections.Counter(), collections.Counter(), collections.Counter()
    expected = collections.Counter({pair:1 for pair in REQUIRED_PAIRS})
    for event in events:
        if not isinstance(event,dict):
            raise RuntimeError("application event is not object")
        p,n,a = event.get("Package"),event.get("Test"),event.get("Action")
        if n in REQUIRED_NAMES and (p,n) not in REQUIRED_PAIRS:
            raise RuntimeError("application test in wrong package")
        if p not in REQUIRED_PACKAGES:
            continue
        if a in ("fail","skip"):
            raise RuntimeError("application package/test failed or skipped")
        if terminal[p]:
            raise RuntimeError("application event after terminal")
        if (p,n) in REQUIRED_PAIRS:
            if a=="run": runs[p,n]+=1
            if a=="pass":
                if runs[p,n]!=1: raise RuntimeError("application pass without unique run")
                passes[p,n]+=1
        elif n is not None and p in ("chengwang/internal/subscriptionctl","chengwang/internal/subscriptionpolicy"):
            raise RuntimeError("application unreviewed test/subtest")
        if n is None and a=="pass":
            required = {pair for pair in REQUIRED_PAIRS if pair[0]==p}
            if any(runs[pair]!=1 or passes[pair]!=1 for pair in required):
                raise RuntimeError("application premature terminal")
            terminal[p]+=1
    if runs!=expected or passes!=expected or terminal!=collections.Counter({p:1 for p in REQUIRED_PACKAGES}):
        raise RuntimeError("application actual run/pass or terminal mismatch")

def validate_transcript(path):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError("duplicate Go event key")
            result[key]=value
        return result
    events=[]
    with pathlib.Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                events.append(json.loads(line,object_pairs_hook=unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonstandard Go number"))))
    validate_events(events)
    core.validate_events(projected_core_events(events))

class ApplicationIncrementTests(unittest.TestCase):
    def events(self):
        values=[]
        for p in sorted(REQUIRED_PACKAGES):
            for pair in sorted(x for x in REQUIRED_PAIRS if x[0]==p):
                values.extend(dict(Package=p,Test=pair[1],Action=a) for a in ("run","pass"))
            values.append(dict(Package=p,Action="pass"))
        return values
    def passed(self,pairs):
        result=collections.defaultdict(set)
        for p,n in pairs:result[p].add(n)
        return result
    def test_synthetic_positive_and_count(self):
        self.assertEqual(len(REQUIRED_PAIRS),130)
        self.assertEqual(len(REQUIRED_NAMES),130)
        validate_events(self.events())
    def test_every_missing_renamed_or_wrong_package_rejected(self):
        for pair in REQUIRED_PAIRS:
            for mode in ("missing","renamed","package"):
                events=[e.copy() for e in self.events()]
                for e in events:
                    if (e.get("Package"),e.get("Test"))==pair:
                        if mode=="missing": e["Test"]="TestMissingReplacement"
                        elif mode=="renamed": e["Test"]+="Renamed"
                        else:e["Package"]="wrong"
                with self.assertRaises(RuntimeError):validate_events(events)
    def test_duplicate_run_or_pass_rejected(self):
        sample=self.events()[0]
        for action in ("run","pass"):
            event=dict(sample,Action=action)
            with self.assertRaises(RuntimeError):validate_events([event]+self.events())
    def test_test_or_package_skip_fail_rejected(self):
        for p in REQUIRED_PACKAGES:
            for action in ("fail","skip"):
                with self.assertRaises(RuntimeError):validate_events([dict(Package=p,Action=action)]+self.events())
    def test_terminal_must_be_last_and_unique(self):
        p=sorted(REQUIRED_PACKAGES)[0]
        for events in ([dict(Package=p,Action="pass")]+self.events(),self.events()+[dict(Package=p,Action="pass")],
                       self.events()+[dict(Package=p,Test=next(n for pp,n in REQUIRED_PAIRS if pp==p),Action="output")]):
            with self.assertRaises(RuntimeError):validate_events(events)
    def test_unknown_new_package_and_subtest_rejected(self):
        for package in ("chengwang/internal/subscriptionctl","chengwang/internal/subscriptionpolicy"):
            with self.assertRaises(RuntimeError):validate_events([dict(Package=package,Test="TestUnreviewed/child",Action="run")]+self.events())
    def test_old_baseline_not_replaced(self):
        with self.assertRaises(RuntimeError):split_extension(self.passed(REQUIRED_PAIRS),set(REQUIRED_PACKAGES))
        for pair in REQUIRED_PAIRS:
            with self.assertRaises(RuntimeError):split_extension(self.passed(REQUIRED_PAIRS-{pair}),set(REQUIRED_PACKAGES))
    def test_projection_only_strips_exact_pairs(self):
        pair=next(x for x in REQUIRED_PAIRS if x[0]==core.PACKAGE)
        legacy=dict(Package=core.PACKAGE,Test="TestLegacyUnreviewed",Action="run")
        events=[dict(Package=pair[0],Test=pair[1],Action="run"),legacy]
        self.assertEqual(projected_core_events(events),[legacy])
        with self.assertRaises(RuntimeError):core.validate_events(projected_core_events(events))
    def test_original_core_validator_preserved(self):
        events=[]
        for name in sorted(core.REQUIRED_NAMES):
            events.extend(dict(Package=core.PACKAGE,Test=name,Action=a) for a in ("run","pass"))
        events.append(dict(Package=core.PACKAGE,Action="pass"))
        new_pair=next(x for x in REQUIRED_PAIRS if x[0]==core.PACKAGE)
        events=[dict(Package=new_pair[0],Test=new_pair[1],Action=a) for a in ("run","pass")]+events
        core.validate_events(projected_core_events(events))
        with self.assertRaises(RuntimeError):core.validate_events(events)
    def test_every_terminal_is_required(self):
        for p in REQUIRED_PACKAGES:
            with self.assertRaises(RuntimeError):validate_events([e for e in self.events() if not (e["Package"]==p and e.get("Test") is None)])

if __name__=="__main__":unittest.main()
