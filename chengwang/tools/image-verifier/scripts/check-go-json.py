#!/usr/bin/env python3
"""Fail closed on missing, skipped, incomplete or mismatched Go test evidence."""

import argparse
import collections
import io
import json
import pathlib


LIBRARY_PACKAGE = "chengwang-image-verifier"
CLI_PACKAGE = "chengwang-image-verifier/cmd/image-verifier"
EXPECTED_PACKAGES = frozenset({LIBRARY_PACKAGE, CLI_PACKAGE})
REQUIRED_TESTS = frozenset({
    "TestVerifyMessageBundle",
    "TestVerifyDSSEBundle",
    "TestRejectCryptographicTampering",
    "TestOfficialFixtureBytes",
    "TestRejectPolicyMismatch",
    "TestRejectJSONAmbiguity",
    "TestRejectMalformedDSSEStatements",
    "TestCancellationAndDeadline",
    "TestZeroResultHasNoVerificationAuthority",
    "TestOpaqueResultCannotBeImported",
    "TestOfflineSourceContract",
    "TestStrictJSONBudgetsAndAmbiguity",
    "TestRekorGlobalAndShardIndexes",
    "TestExactByteLimits",
    "TestRejectProofMixingAndEntryBudgets",
    "TestRejectRootBudgetsAndDuplicateLogIDs",
    "TestRejectJSONResourceExhaustion",
    "TestCheckpointTreeSizeIsBound",
    "TestCheckpointTreeSizeIsBound/message",
    "TestCheckpointTreeSizeIsBound/dsse",
})
REQUIRED_CRYPTO_CASES = frozenset({
    "signature", "artifact", "certificate", "issuer", "san", "set", "sct",
    "checkpoint", "proof",
})
REQUIRED_CRYPTO_TESTS = frozenset(
    f"TestRejectCryptographicTampering/{kind}/{case}"
    for kind in ("message-signature", "dsse") for case in REQUIRED_CRYPTO_CASES
)
REQUIRED_INDEX_TESTS = frozenset(
    f"TestRekorGlobalAndShardIndexes/{kind}/{case}"
    for kind in ("message-signature", "dsse")
    for case in ("distinct_original_indexes_verify", "tampered_global_index", "tampered_shard_index_in_bounds")
)
REQUIRED_LIMIT_TESTS = frozenset(
    f"TestExactByteLimits/{kind}/{case}"
    for kind in ("message-signature", "dsse") for case in ("bundle", "root", "both")
)
REQUIRED_PROOF_TESTS = frozenset(
    f"TestRejectProofMixingAndEntryBudgets/{kind}/{case}"
    for kind in ("message-signature", "dsse")
    for case in (
        "other_entry_proof", "other_entry_set", "other_entry_body", "duplicate_entry",
        "proof_negative_index", "global_negative_index", "proof_index_outside_tree",
        "tree_size_zero", "proof_root_short", "proof_hash_short", "proof_hashes_64",
        "proof_no_hashes", "checkpoint_oversize", "set_oversize", "body_oversize",
        "certificate_oversize", "signature_oversize", "unexpected_timestamp_material",
        "proof_unknown_field", "entry_unknown_field", "checkpoint_unknown_field",
        "body_unknown_field", "entry_integer_overflow", "log_id_short",
    )
)
REQUIRED_ROOT_TESTS = frozenset(
    f"TestRejectRootBudgetsAndDuplicateLogIDs/{case}"
    for case in (
        "duplicate_rekor_id", "duplicate_ct_id", "rekor_logs_9", "ct_logs_9",
        "certificate_authorities_9", "timestamp_authorities_9", "cert_chain_9",
        "certificate_oversize", "public_key_oversize", "rekor_unknown_field",
        "ct_unknown_field", "certificate_unknown_field", "root_nested_duplicate",
        "root_escaped_duplicate",
    )
)
REQUIRED_JSON_TESTS = frozenset(
    f"TestStrictJSONBudgetsAndAmbiguity/{case}"
    for case in (
        "depth", "nodes", "escaped_duplicate", "invalid_utf8", "unpaired_surrogate_key",
        "unpaired_surrogate_value", "null", "trailing", "mismatched_array", "missing_colon",
    )
)
REQUIRED_CLI_TESTS = frozenset({
    "TestRunOfficialFixtures", "TestRunOfficialFixtures/message", "TestRunOfficialFixtures/dsse",
    "TestRunRejectsAmbiguousRequests", "TestParseOfficialRequests", "TestCLIProcessContract",
    "TestCLIProcessContract/message", "TestCLIProcessContract/dsse",
    "TestCLIProcessContract/tampered-policy", "TestCLIProcessContract/external-hard-deadline",
    "TestParseRejectsBase64AndSizes", "TestIOErrorsAndCancellationAreClosed",
})
REQUIRED_TEST_PAIRS = frozenset(
    {(LIBRARY_PACKAGE, name) for name in (
        REQUIRED_TESTS | REQUIRED_CRYPTO_TESTS | REQUIRED_INDEX_TESTS | REQUIRED_LIMIT_TESTS
        | REQUIRED_PROOF_TESTS | REQUIRED_ROOT_TESTS | REQUIRED_JSON_TESTS
    )} | {(CLI_PACKAGE, name) for name in REQUIRED_CLI_TESTS}
)


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON event key: {key}")
        result[key] = value
    return result


def read_events(stream):
    runs, passes = collections.Counter(), collections.Counter()
    package_passes = collections.Counter()
    observed_packages = set()
    for line_number, line in enumerate(stream, 1):
        if not line.strip():
            raise ValueError(f"empty event at line {line_number}")
        event = json.loads(line, object_pairs_hook=reject_duplicates)
        if not isinstance(event, dict):
            raise ValueError("event must be a JSON object")
        package = event.get("Package")
        action = event.get("Action")
        test = event.get("Test")
        if not isinstance(package, str) or not package:
            raise ValueError("Go event has no package")
        if action not in {"start", "run", "pause", "cont", "pass", "fail", "skip", "output", "bench"}:
            raise ValueError(f"unexpected Go event action: {action}")
        if action in {"fail", "skip", "bench"}:
            raise ValueError(f"forbidden {action} event: {package}/{test or ''}")
        if test is not None and (not isinstance(test, str) or not test.startswith("Test")):
            raise ValueError(f"invalid test name: {test}")
        observed_packages.add(package)
        key = (package, test)
        if test and action == "run":
            runs[key] += 1
            if runs[key] != 1 or package_passes[package]:
                raise ValueError(f"repeated or late run event: {key}")
        elif test and action == "pass":
            passes[key] += 1
            if runs[key] != 1 or passes[key] != 1 or package_passes[package]:
                raise ValueError(f"unmatched or repeated test pass: {key}")
        elif not test and action == "pass":
            package_passes[package] += 1
            if package_passes[package] != 1:
                raise ValueError(f"repeated package pass: {package}")
    if not runs or runs != passes:
        raise ValueError("tests missing, incomplete, or not all passed")
    if set(package_passes) != observed_packages:
        raise ValueError("package missing a passing terminal event")
    if observed_packages != EXPECTED_PACKAGES:
        raise ValueError(f"unexpected or missing package set: {sorted(observed_packages)}")
    for package in observed_packages:
        if not any(key[0] == package for key in runs):
            raise ValueError(f"package without executed tests: {package}")
    missing = REQUIRED_TEST_PAIRS - runs.keys()
    if missing:
        raise ValueError(f"required package/test pairs missing: {sorted(missing)}")
    return frozenset(runs), frozenset(observed_packages)


def self_test():
    events = []
    for package in sorted(EXPECTED_PACKAGES):
        events.append({"Action": "start", "Package": package})
        tree = {}
        for p, name in REQUIRED_TEST_PAIRS:
            if p == package:
                node = tree
                for part in name.split("/"):
                    node = node.setdefault(part, {})
        def emit(node, prefix=""):
            for part, children in sorted(node.items()):
                name = prefix + part
                events.append({"Action": "run", "Package": package, "Test": name})
                emit(children, name + "/")
                events.append({"Action": "pass", "Package": package, "Test": name})
        emit(tree)
        events.append({"Action": "pass", "Package": package})
    def parse(items):
        return read_events(io.StringIO("".join(json.dumps(item) + "\n" for item in items)))
    parse(events)
    bad = [[], events[:-1], events[:-2] + events[-1:],
           events + [{"Action": "skip", "Package": LIBRARY_PACKAGE}],
           events + [{"Action": "fail", "Package": LIBRARY_PACKAGE}],
           events + [{"Action": "pass", "Package": "untested"}],
           events + [events[-1]], events[1:3] + events,
           events + [{"Action": "mystery", "Package": LIBRARY_PACKAGE}],
           events + [{"Action": "run", "Package": LIBRARY_PACKAGE, "Test": "TestLate"}],
           [e for e in events if e.get("Test") != "TestVerifyDSSEBundle"],
           [e for e in events if e.get("Test") != "TestRejectCryptographicTampering/dsse/set"],
           [e for e in events if e["Package"] != CLI_PACKAGE],
           [dict(e, Package=CLI_PACKAGE) if e.get("Test") == "TestVerifyMessageBundle" else e for e in events],
           [e for e in events if e.get("Test") != "TestCLIProcessContract/external-hard-deadline"],
           [e for e in events if e.get("Test") != "TestRekorGlobalAndShardIndexes/dsse/tampered_global_index"],
           [e for e in events if e.get("Test") != "TestOpaqueResultCannotBeImported"],
           [e for e in events if e.get("Test") != "TestOfflineSourceContract"],
           [e for e in events if e.get("Test") != "TestRejectProofMixingAndEntryBudgets/dsse/other_entry_proof"]]
    for items in bad:
        try:
            parse(items)
        except ValueError:
            continue
        raise ValueError("JSON gate accepted invalid synthetic evidence")
    for raw in ('{}', '{"Action":"pass","Action":"run","Package":"fixture"}', '[]', '\n'):
        try:
            read_events(io.StringIO(raw))
        except ValueError:
            continue
        raise ValueError("JSON gate accepted malformed synthetic evidence")
    print(f"IMAGE_VERIFIER_JSON_SELFTEST=PASS negative_cases={len(bad) + 4}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("transcripts", nargs="*", type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if not args.transcripts:
        if args.self_test:
            return
        parser.error("ordinary and race transcripts required")
    if len(args.transcripts) != 2 or args.transcripts[0].resolve() == args.transcripts[1].resolve():
        parser.error("two distinct ordinary and race transcripts required")
    parsed = []
    for path in args.transcripts:
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError(f"missing or oversized transcript: {path}")
        with path.open(encoding="utf-8") as stream:
            parsed.append(read_events(stream))
    if parsed[0] != parsed[1]:
        raise ValueError("ordinary/race package or test coverage differs")
    print(f"IMAGE_VERIFIER_GO_JSON_GATE=PASS transcripts=2 tests={len(parsed[0][0])} "
          f"packages={len(parsed[0][1])} skips=0 race=pass authorization=BLOCKED production=false")


if __name__ == "__main__":
    main()
