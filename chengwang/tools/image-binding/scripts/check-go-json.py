#!/usr/bin/env python3
"""Require actual run/pass evidence for each binding layer and real Registry gate."""
import argparse
import collections
import io
import json
import pathlib

ROOT = "chengwang/image-binding"
POLICY = ROOT + "/policy"
REGISTRY = ROOT + "/registry"
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
    print(f"IMAGE_BINDING_GO_JSON_GATE=PASS mode={args.mode} transcripts=2 "
          f"tests={len(results[0][0])} packages={len(results[0][1])} skips=0 race=pass "
          "authorization=BLOCKED production=false")


if __name__ == "__main__":
    main()
