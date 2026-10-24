"""Exact overview increment. Definitions and synthetic guards are not Go proof.

Only the reviewed 36 roots and three subtests may be removed before replaying
the original 2670-test gates. Ordinary and race transcripts are checked alone.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import pathlib
import stat

import capability_truth_extension as capability

TOP_LEVEL_PAIRS = frozenset((
    ("chengwang/internal/overview", "TestOverviewConstructorIsCacheSilentAndPreservesCustomMode"),
    ("chengwang/internal/overview", "TestOverviewNilAndTypedNilSourcesAreExplicitUnknown"),
    ("chengwang/internal/overview", "TestOverviewCurrentControllerDoesNotClaimBusinessOrDNSHealth"),
    ("chengwang/internal/overview", "TestOverviewStoppedCollectorInvalidatesStillFreshCache"),
    ("chengwang/internal/overview", "TestOverviewExpiryDoesNotRenewOriginalEvidenceTimes"),
    ("chengwang/internal/overview", "TestOverviewClockRollbackRetainsHistoryWithoutCurrentClaims"),
    ("chengwang/internal/overview", "TestOverviewProbeCoverageIsAnonymousCurrentViewNotBusinessHealth"),
    ("chengwang/internal/overview", "TestOverviewExpiredStoppedAndUntrustedProbeHidesHistoricalCounts"),
    ("chengwang/internal/overview", "TestOverviewRejectsMalformedProbeSourceWithoutRawErrors"),
    ("chengwang/internal/overview", "TestOverviewRejectsMalformedObservationAndHealthyClockFuture"),
    ("chengwang/internal/overview", "TestOverviewProjectionOwnsTimesCoverageAndMissingList"),
    ("chengwang/internal/overview", "TestOverviewNormalizesSourceZeroTimesAndOffsetsWithoutInventingEvidence"),
    ("chengwang/internal/overview", "TestOverviewCanceledBeforeReadNeverCallsSources"),
    ("chengwang/internal/overview", "TestOverviewCanceledAfterObservationSkipsProbeAndClock"),
    ("chengwang/internal/overview", "TestOverviewCanceledAfterProbeSkipsAssembly"),
    ("chengwang/internal/overview", "TestOverviewSequentialSourcesSampleClockOnlyAfterBothGetters"),
    ("chengwang/internal/overview", "TestOverviewValidatorRejectsMalformedAlternateDTOWithoutPanic"),
    ("chengwang/internal/overview", "TestOverviewValidatorMissingFreshObservedTimeReturnsError"),
    ("chengwang/internal/api", "TestOverviewAPIDisabledAndTypedNilReturn503WithoutDemo"),
    ("chengwang/internal/api", "TestOverviewAPIPublicResponseIsBoundedVersionedAndAnonymous"),
    ("chengwang/internal/api", "TestOverviewAPIHeadPostAndQueriesRejectBeforeCacheRead"),
    ("chengwang/internal/api", "TestOverviewAPIBodyTransferAndEncodingRejectWithoutRead"),
    ("chengwang/internal/api", "TestOverviewAPIRejectsEncodedAliasInHandler"),
    ("chengwang/internal/api", "TestOverviewAPIProviderErrorNeverReflectsPrivateCause"),
    ("chengwang/internal/api", "TestOverviewAPIInvalidDTOAndOversizedProjectionNeverWritePartial200"),
    ("chengwang/internal/api", "TestOverviewAPICanceledRequestDoesNotReadProvider"),
    ("chengwang/internal/api", "TestOverviewAPIDeadlineAndLateProviderCannotReturnSuccess"),
    ("chengwang/internal/api", "TestOverviewAPIBudgetIsCooperativeAndDoesNotExtendCallerDeadline"),
    ("chengwang/internal/api", "TestOverviewAPIOriginalSnapshotRemainsExplicitDemo"),
    ("chengwang/internal/serverruntime", "TestLiveOverviewEnvironmentDefaultsDisabled"),
    ("chengwang/internal/serverruntime", "TestLiveOverviewEnvironmentEnablesOnlyCanonicalTrue"),
    ("chengwang/internal/serverruntime", "TestLiveOverviewEnvironmentRejectsNoncanonicalWithoutMutation"),
    ("chengwang/internal/serverruntime", "TestLiveOverviewEnvironmentErrorsAreFixedAndNonEchoing"),
    ("chengwang/internal/serverruntime", "TestLiveOverviewEnvironmentRejectsNilConfig"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeOverviewDefaultRemainsDisabledAndSnapshotDemo"),
    ("chengwang/internal/serverruntime", "TestServerRuntimeOverviewEnabledUsesActualProviderWithoutInventoryFallback"),
))
SUBTEST_NAMES = {
    ("chengwang/internal/serverruntime", "TestLiveOverviewEnvironmentDefaultsDisabled"): ("unset", "empty", "false"),
}
REQUIRED_PAIRS = TOP_LEVEL_PAIRS | frozenset(
    (package, root + "/" + child)
    for (package, root), children in SUBTEST_NAMES.items() for child in children
)
ROOT_NAMES = frozenset(name for _, name in TOP_LEVEL_PAIRS)
REQUIRED_NAMES = frozenset(name for _, name in REQUIRED_PAIRS)
REQUIRED_PACKAGES = frozenset(package for package, _ in REQUIRED_PAIRS)
NEW_PACKAGE = "chengwang/internal/overview"
PRE_COUNT = 2670
PRE_SHA256 = "e6bac5168b142d1891c666e5f04f100df415a9bcf59d171829800bd393f77f9d"
INCREMENT_COUNT = 39
INCREMENT_SHA256 = "227c2aeffef94be98b37780d9d20b290e7c6d85d0ba0c78b7ff865e1c2853361"
FULL_COUNT = 2709
FULL_SHA256 = "e52b1aece0fea01169ef72a03851297cf7d4e8acdf2282d85cbc18199d6ab7f5"
# The reviewed historical 2670 projection has 41 passing packages and one
# existing no-test package. The only new package is internal/overview.
PRE_TERMINAL_PACKAGES = frozenset("chengwang/" + name for name in (
    "cmd/docker-runtime-readonly-proxy", "cmd/probe-agent", "cmd/server", "cmd/verify-shadow",
    "deploy/m2b-candidate/cmd/candidate-guard", "internal/adapter/mihomo", "internal/api",
    "internal/attestation", "internal/authn", "internal/authz", "internal/capability", "internal/control",
    "internal/dockerreadonlyproxy", "internal/evidence", "internal/imagetrust", "internal/kernel",
    "internal/lease", "internal/observation", "internal/operation", "internal/policy", "internal/probe",
    "internal/proberestore", "internal/probeview", "internal/proxyiface", "internal/restoreclock",
    "internal/restorecontracts", "internal/restorecoordinator", "internal/restorecurrent",
    "internal/restoreevidence", "internal/restoreimage", "internal/restorelease", "internal/restoreruntime",
    "internal/routing", "internal/runtimewire", "internal/serverruntime", "internal/store",
    "internal/subscription", "internal/subscriptionctl", "internal/subscriptionpolicy", "internal/truth", "internal/webui",
))
FULL_TERMINAL_PACKAGES = PRE_TERMINAL_PACKAGES | frozenset((NEW_PACKAGE,))
PACKAGE_SKIPS = frozenset((("chengwang/internal/domain", None),))
MAX_TRANSCRIPT_BYTES = 32 << 20
MAX_EVENTS = 100000


def fingerprint(pairs):
    return hashlib.sha256("".join(p + "\t" + n + "\n" for p, n in sorted(pairs)).encode()).hexdigest()


def definition():
    if (len(TOP_LEVEL_PAIRS) != 36 or len(REQUIRED_PAIRS) != INCREMENT_COUNT
            or fingerprint(REQUIRED_PAIRS) != INCREMENT_SHA256
            or capability.FULL_COUNT != PRE_COUNT or capability.FULL_SHA256 != PRE_SHA256
            or len(PRE_TERMINAL_PACKAGES) != 41 or len(FULL_TERMINAL_PACKAGES) != 42
            or NEW_PACKAGE in PRE_TERMINAL_PACKAGES):
        raise RuntimeError("overview exact increment definition changed")


def split_extension(passed_tests, terminal_packages):
    definition()
    pairs = frozenset((package, name) for package, names in passed_tests.items() for name in names)
    observed = frozenset(pair for pair in pairs if pair in REQUIRED_PAIRS or pair[1] in REQUIRED_NAMES)
    if observed != REQUIRED_PAIRS or frozenset(terminal_packages) != FULL_TERMINAL_PACKAGES:
        raise RuntimeError("overview exact increment or package scope missing or misplaced")
    if len(pairs) != FULL_COUNT or fingerprint(pairs) != FULL_SHA256:
        raise RuntimeError("complete expected 2709-test overview baseline changed")
    retained = pairs - REQUIRED_PAIRS
    if len(retained) != PRE_COUNT or fingerprint(retained) != PRE_SHA256:
        raise RuntimeError("pre-overview complete 2670-test baseline changed")
    result = collections.defaultdict(set)
    for package, name in retained:
        result[package].add(name)
    return result


def projected_capability_events(events):
    # Remove exactly reviewed Test identities plus the new package's enclosing
    # start/output/terminal records. Existing package records are retained.
    return [event for event in events if event.get("Package") != NEW_PACKAGE
            and (event.get("Package"), event.get("Test")) not in REQUIRED_PAIRS]


def validate_events(events):
    definition()
    runs, passes, terminal = collections.Counter(), collections.Counter(), collections.Counter()
    expected = collections.Counter({pair: 1 for pair in REQUIRED_PAIRS})
    for event in events:
        if type(event) is not dict:
            raise RuntimeError("overview event is not an object")
        package, name, action = event.get("Package"), event.get("Test"), event.get("Action")
        if (not isinstance(package, str) or not package or not isinstance(action, str)
                or name is not None and not isinstance(name, str)):
            raise RuntimeError("overview event identity is malformed")
        pair = (package, name)
        if isinstance(name, str) and ((name.split("/", 1)[0] in ROOT_NAMES or package == NEW_PACKAGE) and pair not in REQUIRED_PAIRS):
            raise RuntimeError("overview test or subtest is misplaced or unreviewed")
        if package not in REQUIRED_PACKAGES:
            continue
        if action in ("fail", "skip"):
            raise RuntimeError("overview package/test failed or skipped")
        if terminal[package]:
            raise RuntimeError("overview event after package terminal")
        if pair in REQUIRED_PAIRS:
            root = (package, name.split("/", 1)[0])
            if action == "run":
                if runs[pair] or passes[pair]:
                    raise RuntimeError("overview duplicate or late run")
                if pair != root and (runs[root] != 1 or passes[root]):
                    raise RuntimeError("overview subtest outside running parent")
                runs[pair] += 1
            if action == "pass":
                if runs[pair] != 1 or passes[pair]:
                    raise RuntimeError("overview pass without unique run")
                if pair in SUBTEST_NAMES and any(passes[package, name + "/" + child] != 1 for child in SUBTEST_NAMES[pair]):
                    raise RuntimeError("overview parent passed before its subtests")
                passes[pair] += 1
        if name is None and action == "pass":
            if any(runs[pair] != 1 or passes[pair] != 1 for pair in REQUIRED_PAIRS if pair[0] == package):
                raise RuntimeError("overview premature package terminal")
            terminal[package] += 1
    if runs != expected or passes != expected or terminal != collections.Counter({p: 1 for p in REQUIRED_PACKAGES}):
        raise RuntimeError("overview actual run/pass or terminal mismatch")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Go event key")
        result[key] = value
    return result


def _metadata_stable(before, named_before, after, named_after, *, windows):
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    if not identity(before) == identity(named_before) == identity(after) == identity(named_after):
        return False
    if before.st_ctime_ns != after.st_ctime_ns or named_before.st_ctime_ns != named_after.st_ctime_ns:
        return False
    # CPython on Windows can expose change time via fstat and birth time via
    # lstat. Each channel must stay stable; POSIX retains cross-channel ctime.
    return windows or before.st_ctime_ns == named_before.st_ctime_ns


def validate_transcript(path):
    path = pathlib.Path(path)
    with path.open("rb") as stream:
        before, named_before = os.fstat(stream.fileno()), path.lstat()
        raw = stream.read(MAX_TRANSCRIPT_BYTES + 1)
        after, named_after = os.fstat(stream.fileno()), path.lstat()
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(named_before.st_mode)
            or len(raw) > MAX_TRANSCRIPT_BYTES or len(raw) != before.st_size
            or not _metadata_stable(before, named_before, after, named_after, windows=os.name == "nt")):
        raise RuntimeError("overview Go transcript custody or budget changed")
    events = []
    for line in raw.decode("utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line, object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonstandard Go number"))))
        if len(events) > MAX_EVENTS:
            raise RuntimeError("overview Go event budget exceeded")
    validate_events(events)
    passed = collections.defaultdict(set)
    terminals, skips = set(), set()
    for event in events:
        package, name, action = event.get("Package"), event.get("Test"), event.get("Action")
        if action == "fail" or action == "skip" and name is not None:
            raise RuntimeError("overview complete Go transcript failed or skipped")
        if action == "pass" and isinstance(name, str) and name.startswith("Test"):
            passed[package].add(name)
        if name is None and action == "pass":
            terminals.add(package)
        if action == "skip":
            skips.add((package, name))
    if skips != PACKAGE_SKIPS:
        raise RuntimeError("overview no-test package scope changed")
    split_extension(passed, terminals)
    # Replay the exact existing semantic validators after projecting away only
    # the reviewed increment. None of their names, pins or predicates change.
    old = projected_capability_events(events)
    capability.validate_events(old)
    access_events = capability.projected_access_events(old)
    capability.access.validate_events(access_events)
    application_events = capability.access.projected_application_events(access_events)
    capability.access.application.validate_events(application_events)
    capability.access.application.core.validate_events(
        capability.access.application.projected_core_events(application_events))
