"""Exact SYS-01 increment; synthetic guard tests are not Go execution proof.

Fourteen source-declared roots and twelve explicitly named t.Run cases extend
the unchanged 2644-name baseline. Only these exact pairs may be projected away
before the original subscription/access/probe and historical validators run.
The full 2670 fingerprint is a pre-CI expectation, not a claimed test result.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import pathlib
import stat

import subscription_access_extension as access

TOP_LEVEL_PAIRS = frozenset((
    ("chengwang/internal/capability", "TestSubscriptionCapabilityDefaultsBlockedAndLegacyCompatible"),
    ("chengwang/internal/capability", "TestSubscriptionCapabilityRequiresBackendAndIdentity"),
    ("chengwang/internal/capability", "TestSubscriptionCapabilityDisclosesLocalWriteAndPolicyBoundaries"),
    ("chengwang/internal/capability", "TestSubscriptionCapabilityListsImplementedLocalRoutes"),
    ("chengwang/internal/capability", "TestSubscriptionRuntimeFactsPreserveUnrelatedCapabilities"),
    ("chengwang/internal/capability", "TestSubscriptionOrchestrationRemainsDesignOnlyWithLocalFoundation"),
    ("chengwang/internal/capability", "TestEvidenceCapabilityDoesNotDenyConfiguredLocalIdentity"),
    ("chengwang/internal/capability", "TestConfiguredReadOnlyAdaptersDoNotClaimConnectionOrProduction"),
    ("chengwang/internal/capability", "TestSubscriptionCapabilityReportsAreDetached"),
    ("chengwang/internal/api", "TestSubscriptionCapabilitiesAPIDefaultIsBlocked"),
    ("chengwang/internal/api", "TestSubscriptionCapabilitiesAPIRequiresConfiguredBackendScopeAndIdentity"),
    ("chengwang/internal/api", "TestSubscriptionCapabilitiesAPIUsesOnlyCachedScope"),
    ("chengwang/internal/api", "TestSubscriptionCapabilitiesAPIWriteGateDoesNotGrantHealthOrExposeState"),
    ("chengwang/internal/api", "TestSubscriptionCapabilitiesAPIReportsDetachedProjection"),
))
SUBTEST_NAMES = {
    ("chengwang/internal/capability", "TestSubscriptionCapabilityRequiresBackendAndIdentity"): (
        "neither", "identity_only", "backend_only", "both",
    ),
    ("chengwang/internal/api", "TestSubscriptionCapabilitiesAPIRequiresConfiguredBackendScopeAndIdentity"): (
        "nil_backend", "typed_nil_backend", "wrong_object_type", "missing_tenant",
        "nil_identity", "typed_nil_identity", "configured_write_gate_closed", "configured_write_gate_open",
    ),
}
REQUIRED_PAIRS = TOP_LEVEL_PAIRS | frozenset(
    (package, root + "/" + child)
    for (package, root), children in SUBTEST_NAMES.items() for child in children
)
REQUIRED_NAMES = frozenset(name for _, name in REQUIRED_PAIRS)
ROOT_NAMES = frozenset(name for _, name in TOP_LEVEL_PAIRS)
REQUIRED_PACKAGES = frozenset(package for package, _ in REQUIRED_PAIRS)
PRE_COUNT = 2644
PRE_SHA256 = "cae9dc917b3b289bb949626a20ab43906a0686fe78fb8cf3d5b2657d1893d530"
INCREMENT_COUNT = 26
INCREMENT_SHA256 = "0222761783b0a170a059d5b891d2225cd358a8c7e1a796bd0fcdbecec8c4f589"
FULL_COUNT = 2670
FULL_SHA256 = "e6bac5168b142d1891c666e5f04f100df415a9bcf59d171829800bd393f77f9d"
MAX_TRANSCRIPT_BYTES = 32 << 20
MAX_EVENTS = 100000


def fingerprint(pairs):
    return hashlib.sha256("".join(p + "\t" + n + "\n" for p, n in sorted(pairs)).encode()).hexdigest()


def definition():
    if (len(TOP_LEVEL_PAIRS) != 14 or len(REQUIRED_PAIRS) != INCREMENT_COUNT
            or fingerprint(REQUIRED_PAIRS) != INCREMENT_SHA256
            or access.FULL_COUNT != PRE_COUNT or access.FULL_SHA256 != PRE_SHA256):
        raise RuntimeError("capability truth exact increment definition changed")


def projected_access_events(events):
    return [event for event in events if (event.get("Package"), event.get("Test")) not in REQUIRED_PAIRS]


def split_extension(passed_tests, terminal_packages):
    definition()
    pairs = frozenset((package, name) for package, names in passed_tests.items() for name in names)
    observed = frozenset(pair for pair in pairs if pair in REQUIRED_PAIRS or pair[1] in REQUIRED_NAMES)
    if observed != REQUIRED_PAIRS or not REQUIRED_PACKAGES <= terminal_packages:
        raise RuntimeError("capability truth exact increment missing or misplaced")
    if len(pairs) != FULL_COUNT or fingerprint(pairs) != FULL_SHA256:
        raise RuntimeError("complete pre-frozen 2670-test baseline changed")
    retained = pairs - REQUIRED_PAIRS
    if len(retained) != PRE_COUNT or fingerprint(retained) != PRE_SHA256:
        raise RuntimeError("pre-capability complete 2644-test baseline changed")
    result = collections.defaultdict(set)
    for package, name in retained:
        result[package].add(name)
    return result


def validate_events(events):
    definition()
    runs, passes, terminal = collections.Counter(), collections.Counter(), collections.Counter()
    expected = collections.Counter({pair: 1 for pair in REQUIRED_PAIRS})
    for event in events:
        if type(event) is not dict:
            raise RuntimeError("capability truth event is not object")
        package, name, action = event.get("Package"), event.get("Test"), event.get("Action")
        if (not isinstance(package, str) or not package or not isinstance(action, str)
                or name is not None and not isinstance(name, str)):
            raise RuntimeError("capability truth event identity is malformed")
        if isinstance(name, str) and name.split("/", 1)[0] in ROOT_NAMES and (package, name) not in REQUIRED_PAIRS:
            raise RuntimeError("capability truth test or subtest is misplaced or unreviewed")
        if package not in REQUIRED_PACKAGES:
            continue
        if action in ("fail", "skip"):
            raise RuntimeError("capability truth package/test failed or skipped")
        if terminal[package]:
            raise RuntimeError("capability truth event after package terminal")
        pair = (package, name)
        if pair in REQUIRED_PAIRS:
            root = (package, name.split("/", 1)[0])
            if action == "run":
                if runs[pair] or passes[pair]:
                    raise RuntimeError("capability truth duplicate or late run")
                if pair != root and (runs[root] != 1 or passes[root]):
                    raise RuntimeError("capability truth subtest outside its running parent")
                runs[pair] += 1
            if action == "pass":
                if runs[pair] != 1 or passes[pair]:
                    raise RuntimeError("capability truth pass without unique run")
                if pair in SUBTEST_NAMES and any(
                        passes[package, name + "/" + child] != 1 for child in SUBTEST_NAMES[pair]):
                    raise RuntimeError("capability truth parent passed before its subtests")
                passes[pair] += 1
        if name is None and action == "pass":
            if any(runs[pair] != 1 or passes[pair] != 1 for pair in REQUIRED_PAIRS if pair[0] == package):
                raise RuntimeError("capability truth premature package terminal")
            terminal[package] += 1
    if runs != expected or passes != expected or terminal != collections.Counter({p: 1 for p in REQUIRED_PACKAGES}):
        raise RuntimeError("capability truth actual run/pass or terminal mismatch")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Go event key")
        result[key] = value
    return result


def validate_transcript(path):
    path = pathlib.Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        named_before = path.stat()
        raw = stream.read(MAX_TRANSCRIPT_BYTES + 1)
        after = os.fstat(stream.fileno())
        named_after = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)
    if (not stat.S_ISREG(before.st_mode) or len(raw) > MAX_TRANSCRIPT_BYTES or len(raw) != before.st_size
            or not identity(before) == identity(named_before) == identity(after) == identity(named_after)
            or before.st_ctime_ns != after.st_ctime_ns or named_before.st_ctime_ns != named_after.st_ctime_ns):
        raise RuntimeError("capability truth Go transcript budget or custody changed")
    events = []
    for line in raw.decode("utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line, object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonstandard Go number"))))
        if len(events) > MAX_EVENTS:
            raise RuntimeError("capability truth Go event budget exceeded")
    validate_events(events)
    # Preserve the original access/application/core event validators, with
    # only the 26 reviewed pairs projected away. No old module is relaxed.
    old = projected_access_events(events)
    access.validate_events(old)
    application_events = access.projected_application_events(old)
    access.application.validate_events(application_events)
    access.application.core.validate_events(access.application.projected_core_events(application_events))
