"""P2-06 exact access-metadata increment, frozen from task cards before CI.

The ten guard tests below are synthetic gate checks, not Go execution evidence.
Only these 24 exact (package, name) pairs may be projected away before replaying
the unchanged P2-05 130 and P2 core 87 validators and earlier baselines.
"""
from __future__ import annotations

import collections
import hashlib
import json
import pathlib
import unittest

import subscription_application_extension as application

REQUIRED_PAIRS = frozenset((
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServiceScopeAndResource"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServiceRoleActionsAreResourceSpecific"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServiceWriteGateDoesNotRewritePermissions"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServicePoliciesNotConfigured"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServicePoliciesUnsupportedOrUnavailable"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServiceReferencesBoundedSortedAndDetached"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServiceAuthorizationPrecedesMetadata"),
    ("chengwang/internal/subscriptionctl", "TestSubscriptionAccessServiceNoPrivateIOAndCanceledContexts"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionCatalogAccessSortedDetachedReferences"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionCatalogAccessRejectsInvalidAndDuplicateReferences"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionCatalogAccessBudgetsAndNilFailClosed"),
    ("chengwang/internal/subscriptionpolicy", "TestSubscriptionCatalogAccessNeverExportsPrivateMaterial"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIRequiresStrictBearer"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIRequiresTLSIncludingLoopback"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIIndependentReadScope"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIGetShapeClosedBeforeMetadata"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIUnavailableAndTypedNil"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIOptionalBackendPreservesLegacyInterface"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPICollectionActionsCannotGrantSource"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPISourceActionsMatchCurrentPrincipal"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIEffectiveWriteGateIntersection"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIRejectsUnsafeMetadata"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPIReferencesAndPolicyStateClosed"),
    ("chengwang/internal/api", "TestSubscriptionAccessAPISafeEnvelopeAndNoPrivateCalls"),
))
REQUIRED_NAMES = frozenset(n for _, n in REQUIRED_PAIRS)
REQUIRED_PACKAGES = frozenset(p for p, _ in REQUIRED_PAIRS)
PRE_COUNT = 2620
PRE_SHA256 = "06e0e29fbb80a30ce7819be7dda5859cccd8daed8a60060e71174138e51a1b14"
INCREMENT_SHA256 = "37ae5c7ce9c5d2fe6a4361fe03950dcff9131ad7160ce6822b26ec8c1415b363"
FULL_COUNT = 2644
FULL_SHA256 = "cae9dc917b3b289bb949626a20ab43906a0686fe78fb8cf3d5b2657d1893d530"


def fingerprint(pairs):
    return hashlib.sha256("".join(p + "\t" + n + "\n" for p, n in sorted(pairs)).encode()).hexdigest()


def projected_application_events(events):
    return [e for e in events if (e.get("Package"), e.get("Test")) not in REQUIRED_PAIRS]


def split_extension(passed_tests, terminal_packages):
    pairs = frozenset((p, n) for p, names in passed_tests.items() for n in names)
    observed = frozenset(pair for pair in pairs if pair in REQUIRED_PAIRS or pair[1] in REQUIRED_NAMES)
    if len(REQUIRED_PAIRS) != 24 or fingerprint(REQUIRED_PAIRS) != INCREMENT_SHA256 or observed != REQUIRED_PAIRS or not REQUIRED_PACKAGES <= terminal_packages:
        raise RuntimeError("subscription access exact increment missing or changed")
    if len(pairs) != FULL_COUNT or fingerprint(pairs) != FULL_SHA256:
        raise RuntimeError("complete pre-frozen 2644-test baseline changed")
    retained = pairs - REQUIRED_PAIRS
    if len(retained) != PRE_COUNT or fingerprint(retained) != PRE_SHA256:
        raise RuntimeError("pre-access complete 2620-test baseline changed")
    result = collections.defaultdict(set)
    for p, n in retained:
        result[p].add(n)
    return result


def validate_events(events):
    runs, passes, terminal = collections.Counter(), collections.Counter(), collections.Counter()
    expected = collections.Counter({pair: 1 for pair in REQUIRED_PAIRS})
    for event in events:
        if type(event) is not dict:
            raise RuntimeError("access event is not object")
        p, n, action = event.get("Package"), event.get("Test"), event.get("Action")
        if n in REQUIRED_NAMES and (p, n) not in REQUIRED_PAIRS:
            raise RuntimeError("access test in wrong package")
        if p not in REQUIRED_PACKAGES:
            continue
        if action in ("fail", "skip"):
            raise RuntimeError("access package/test failed or skipped")
        if terminal[p]:
            raise RuntimeError("access event after package terminal")
        if (p, n) in REQUIRED_PAIRS:
            if action == "run":
                runs[p, n] += 1
            if action == "pass":
                if runs[p, n] != 1:
                    raise RuntimeError("access pass without unique run")
                passes[p, n] += 1
        if n is None and action == "pass":
            if any(runs[pair] != 1 or passes[pair] != 1 for pair in REQUIRED_PAIRS if pair[0] == p):
                raise RuntimeError("access premature package terminal")
            terminal[p] += 1
    if runs != expected or passes != expected or terminal != collections.Counter({p: 1 for p in REQUIRED_PACKAGES}):
        raise RuntimeError("access actual run/pass or terminal mismatch")


def validate_transcript(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate Go event key")
            result[key] = value
        return result
    path = pathlib.Path(path)
    if path.stat().st_size > 32 << 20:
        raise RuntimeError("access Go transcript budget exceeded")
    events = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                events.append(json.loads(line, object_pairs_hook=unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonstandard Go number"))))
            if len(events) > 100000:
                raise RuntimeError("access Go event budget exceeded")
    validate_events(events)
    old = projected_application_events(events)
    application.validate_events(old)
    application.core.validate_events(application.projected_core_events(old))


class AccessIncrementTests(unittest.TestCase):
    def events(self):
        values = []
        for p in sorted(REQUIRED_PACKAGES):
            for pair in sorted(x for x in REQUIRED_PAIRS if x[0] == p):
                values.extend(dict(Package=p, Test=pair[1], Action=a) for a in ("run", "pass"))
            values.append(dict(Package=p, Action="pass"))
        return values

    def test_synthetic_positive_and_frozen_count(self):
        self.assertEqual(len(REQUIRED_PAIRS), 24)
        self.assertEqual(len(REQUIRED_NAMES), 24)
        self.assertEqual(fingerprint(REQUIRED_PAIRS), INCREMENT_SHA256)
        validate_events(self.events())

    def test_every_missing_or_renamed_pair_rejected(self):
        for pair in REQUIRED_PAIRS:
            for mode in ("missing", "renamed"):
                values = [e.copy() for e in self.events()]
                for e in values:
                    if (e.get("Package"), e.get("Test")) == pair:
                        e["Test"] = "TestMissingReplacement" if mode == "missing" else pair[1] + "Changed"
                with self.assertRaises(RuntimeError):
                    validate_events(values)

    def test_wrong_package_rejected(self):
        for pair in REQUIRED_PAIRS:
            values = [dict(e, Package="wrong") if (e.get("Package"), e.get("Test")) == pair else e for e in self.events()]
            with self.assertRaises(RuntimeError):
                validate_events(values)

    def test_duplicate_run_and_pass_rejected(self):
        sample = self.events()[0]
        for action in ("run", "pass"):
            with self.assertRaises(RuntimeError):
                validate_events([dict(sample, Action=action)] + self.events())

    def test_test_and_package_skip_or_fail_rejected(self):
        for p in REQUIRED_PACKAGES:
            for action in ("skip", "fail"):
                for name in (None, next(n for pp, n in REQUIRED_PAIRS if pp == p)):
                    with self.assertRaises(RuntimeError):
                        validate_events([dict(Package=p, Test=name, Action=action)] + self.events())

    def test_terminal_order_and_uniqueness(self):
        p = sorted(REQUIRED_PACKAGES)[0]
        for values in ([dict(Package=p, Action="pass")] + self.events(),
                       self.events() + [dict(Package=p, Action="pass")],
                       self.events() + [dict(Package=p, Action="output")]):
            with self.assertRaises(RuntimeError):
                validate_events(values)

    def test_projection_removes_only_exact_pairs(self):
        pair = next(iter(REQUIRED_PAIRS))
        unknown = dict(Package=pair[0], Test=pair[1] + "/unreviewed", Action="run")
        values = [dict(Package=pair[0], Test=pair[1], Action="run"), unknown]
        self.assertEqual(projected_application_events(values), [unknown])

    def test_legacy_baseline_cannot_be_replaced(self):
        passed = collections.defaultdict(set)
        for p, n in REQUIRED_PAIRS:
            passed[p].add(n)
        with self.assertRaises(RuntimeError):
            split_extension(passed, set(REQUIRED_PACKAGES))

    def test_original_application_and_core_are_still_strict(self):
        pair = next(x for x in REQUIRED_PAIRS if x[0] == "chengwang/internal/subscriptionctl")
        unknown = dict(Package=pair[0], Test="TestUnreviewedReplacement", Action="run")
        with self.assertRaises(RuntimeError):
            application.validate_events(projected_application_events([unknown]))
        with self.assertRaises(RuntimeError):
            application.core.validate_events(application.projected_core_events([unknown]))

    def test_all_package_terminals_required(self):
        for p in REQUIRED_PACKAGES:
            with self.assertRaises(RuntimeError):
                validate_events([e for e in self.events() if not (e["Package"] == p and e.get("Test") is None)])


if __name__ == "__main__":
    unittest.main()
