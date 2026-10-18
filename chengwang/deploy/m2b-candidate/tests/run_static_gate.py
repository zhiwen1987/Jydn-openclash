#!/usr/bin/env python3
"""Run the offline M2b candidate static gate without touching production.

Linux CI is deliberately strict: every discovered test must run, so any skip is
an error.  Windows is a developer convenience gate and may skip only the
explicit POSIX/Linux filesystem and process-group cases listed below.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import pathlib
import sys
import unittest


# The gate must be self-contained: callers should not need an environment
# variable or ``python -B`` to keep the reviewed candidate tree immutable.
sys.dont_write_bytecode = True


REQUIRED_TEST_SUITES = {
    "canary/tests": 39,
    "supply-chain/tests": 45,
    "egress/tests": 19,
    "bootstrap/tests": 29,
}

REQUIRED_SCHEMA_COUNT = 11
SCHEMA_VALIDATOR_PACKAGE = "chengwang/internal/restorecontracts"
SCHEMA_VALIDATOR_TEST = "TestSchemasDraft2020CompileAndValidate"
SCHEMA_METASCHEMA_STATUS = "PENDING_GO_VALIDATOR"
SCHEMA_METASCHEMA_PASS = (
    "SCHEMA_METASCHEMA=PASS "
    "validator=santhosh-tekuri-jsonschema-v6.0.3 schemas=11"
)

WINDOWS_PLATFORM_SKIPS = frozenset(
    {
        ("test_static_canary_contract.ValidationTests.test_group_writable_or_executable_input_rejected", "POSIX ownership and mode behavior"),
        ("test_static_canary_contract.ValidationTests.test_post_link_fsync_failure_removes_output", "POSIX directory fsync behavior"),
        ("test_static_canary_contract.ValidationTests.test_hard_link_input_rejected", "hard links are unavailable"),
        ("test_static_canary_contract.ValidationTests.test_symlink_input_rejected_when_supported", "symlink creation is unavailable"),
        ("test_static_canary_contract.ValidationTests.test_symlink_directory_component_rejected_when_supported", "directory symlink creation is unavailable"),
        ("test_verify_supply_chain.SupplyChainTests.test_symlink_input_rejected", "symlink unavailable"),
        ("test_verify_supply_chain.SupplyChainTests.test_symlink_input_rejected", "symlink creation not permitted"),
        ("test_verify_supply_chain.SupplyChainTests.test_hardlink_input_rejected", "hardlink creation not permitted"),
        ("test_host_egress_evidence.EvidenceTests.test_hardlinked_input_is_rejected", "hardlinks are unavailable"),
        ("test_host_egress_evidence.EvidenceTests.test_closed_pipes_then_hang_is_killed_and_reaped", "process-group regression requires Linux"),
        ("test_host_egress_evidence.EvidenceTests.test_exited_parent_cannot_leave_pipe_holding_grandchild", "process-group regression requires Linux"),
        ("test_compile_egress_bootstrap.CliTests.test_parent_fsync_failure_removes_published_output", "directory fsync is a POSIX publication gate"),
        ("test_compile_egress_bootstrap.CliTests.test_symlink_input_is_rejected", "symlinks unsupported"),
        ("test_compile_egress_bootstrap.CliTests.test_symlink_input_is_rejected", "symlink creation not permitted"),
    }
)

REQUIRED_GO_TEST_RUNS = {
    "chengwang/cmd/probe-agent": 105,
    "chengwang/cmd/server": 17,
    "chengwang/cmd/verify-shadow": 5,
    "chengwang/deploy/m2b-candidate/cmd/candidate-guard": 5,
    "chengwang/internal/adapter/mihomo": 7,
    "chengwang/internal/api": 39,
    "chengwang/internal/attestation": 29,
    "chengwang/internal/authn": 28,
    "chengwang/internal/authz": 80,
    "chengwang/internal/capability": 8,
    "chengwang/internal/control": 22,
    "chengwang/internal/evidence": 40,
    "chengwang/internal/kernel": 2,
    "chengwang/internal/lease": 14,
    "chengwang/internal/observation": 13,
    "chengwang/internal/operation": 61,
    "chengwang/internal/policy": 3,
    "chengwang/internal/probe": 224,
    "chengwang/internal/proberestore": 16,
    "chengwang/internal/proxyiface": 5,
    "chengwang/internal/restorecoordinator": 24,
    "chengwang/internal/restorelease": 2,
    "chengwang/internal/routing": 4,
    "chengwang/internal/store": 4,
    "chengwang/internal/truth": 20,
    "chengwang/internal/webui": 3,
}

REQUIRED_GO_TEST_FINGERPRINTS = {
    "chengwang/internal/restorecontracts": {
        "count": 227,
        "sha256": "36b2b9c67a3e742ccaf9a6694fb6665844002f27cd83a2422949df4c7073e7ff",
    },
    "chengwang/internal/restorecoordinator": {
        "count": 24,
        "sha256": "641b77a1e952f67645760bf0babd7d352b51c77a7c6957134f9592b736ccb0d3",
    }
}

REQUIRED_GO_TEST_NAMES = {
    "chengwang/internal/restorecontracts": frozenset(
        {
            "TestGoldenContractsParse",
            "TestStrictJSONRejectsStructuralAmbiguity",
            "TestEveryRequiredFieldDeletionRejected",
            "TestBackupSemanticBoundaries",
            "TestStateOnlyRejectsEveryBindingDifference",
            "TestEveryEvidenceKindHasExactPhaseAndRequiredChecks",
            "TestEvidenceTopologyMatrix",
            "TestEvidenceTransitionsMatchProbeRestore",
            "TestRescueAndLockdownPreserveUnknownTopology",
            "TestEvidenceReasonPolicyMatchesJournal",
            "TestEvidenceContextFreshnessBootAndRawDigest",
            "TestAnchorClaimsRequireTrustedContext",
            "TestCheckpointClaimsRequireIndependentIndexes",
            "TestAnchorAndCheckpointBoundaries",
            "TestValidatedObjectsAreOpaqueSnapshots",
            "TestSchemaParityAndLocalReferences",
            SCHEMA_VALIDATOR_TEST,
        }
    ),
    "chengwang/internal/restorecoordinator": frozenset(
        {
            "TestPrepareBindsExactBackupBytes",
            "TestPrepareRejectsSameOldAndTargetState",
            "TestCoordinatorAdvancesOnlyThroughInputVerified",
            "TestCoordinatorIdempotentAfterJournalCommit",
            "TestCoordinatorRetriesEvidenceCommittedBeforeJournalSave",
            "TestCoordinatorRebuildsPreparedModelFromDurableIdentity",
            "TestCoordinatorIdempotenceRequiresExactTailEvent",
            "TestCoordinatorFailureRetryIsIdempotentFromEveryPreLivePhase",
            "TestCoordinatorHasNoProductionConstructor",
            "TestCoordinatorProductionSurfaceRemainsBlocked",
            "TestCoordinatorRejectsDiagnosticOrUncommittedEvidence",
            "TestCoordinatorRejectsEveryIndependentContextMismatch",
            "TestCoordinatorAllowsOnlyExactPreLiveRequests",
            "TestCoordinatorActualTransitionSetIsExact",
        }
    ),
    "chengwang/internal/restorelease": frozenset(
        {
            "TestNilAndZeroLeaseFailClosed",
            "TestProductionCandidatePathPolicy",
        }
    ),
}

ALLOWED_GO_PACKAGE_SKIPS = frozenset({"chengwang/internal/domain"})


class RecordingResult(unittest.TextTestResult):
    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:  # noqa: N802
        super().addSkip(test, reason)


def _reject_duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonstandard_number(value: str) -> object:
    raise ValueError(f"non-standard JSON number: {value}")


def _test_name_fingerprint(names: set[str]) -> str:
    canonical = "\n".join(sorted(names)).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _assert_no_python_cache(candidate_root: pathlib.Path) -> None:
    artifacts = sorted(
        path.relative_to(candidate_root).as_posix()
        for path in candidate_root.rglob("*")
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
    )
    if artifacts:
        raise RuntimeError("Python cache artifacts are forbidden: " + ", ".join(artifacts))


def _parse_schemas(candidate_root: pathlib.Path) -> int:
    schemas = sorted(candidate_root.rglob("*.schema.json"))
    if len(schemas) != REQUIRED_SCHEMA_COUNT:
        raise RuntimeError(
            f"schema count is {len(schemas)} under {candidate_root}; "
            f"required exact count is {REQUIRED_SCHEMA_COUNT}"
        )
    for path in schemas:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_key,
                parse_constant=_reject_nonstandard_number,
            )
        if not isinstance(value, dict):
            raise RuntimeError(f"schema root must be an object: {path}")
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise RuntimeError(f"unexpected or missing $schema declaration: {path}")
    return len(schemas)


def _load_tests(candidate_root: pathlib.Path) -> tuple[unittest.TestSuite, dict[str, int]]:
    combined = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    suite_roots: list[pathlib.Path] = []
    counts: dict[str, int] = {}
    for relative, minimum in REQUIRED_TEST_SUITES.items():
        suite_root = candidate_root / relative
        if not suite_root.is_dir():
            raise RuntimeError(f"test suite directory is missing: {suite_root}")
        suite = loader.discover(str(suite_root), pattern="test_*.py")
        count = suite.countTestCases()
        if count < minimum:
            raise RuntimeError(
                f"test suite {relative} has {count} tests; required minimum is {minimum}"
            )
        counts[relative] = count
        combined.addTests(suite)
        suite_roots.append(suite_root)

    for suite_root in sorted(candidate_root.rglob("tests")):
        if suite_root.is_dir() and any(suite_root.glob("test_*.py")) and suite_root not in suite_roots:
            suite = loader.discover(str(suite_root), pattern="test_*.py")
            count = suite.countTestCases()
            if count == 0:
                raise RuntimeError(f"no tests discovered under {suite_root}")
            relative = suite_root.relative_to(candidate_root).as_posix()
            counts[relative] = count
            combined.addTests(suite)
    return combined, counts


def _validate_skips(result: RecordingResult) -> None:
    skips = [(test.id(), reason) for test, reason in result.skipped]
    if sys.platform.startswith("linux"):
        if skips:
            details = "; ".join(f"{test}: {reason}" for test, reason in skips)
            raise RuntimeError(f"Linux gate forbids skipped tests: {details}")
        return

    if os.name != "nt":
        raise RuntimeError(f"unsupported developer platform: {sys.platform}")

    unexpected = [(test, reason) for test, reason in skips if (test, reason) not in WINDOWS_PLATFORM_SKIPS]
    if unexpected:
        details = "; ".join(f"{test}: {reason}" for test, reason in unexpected)
        raise RuntimeError(f"Windows gate saw a non-platform skip: {details}")


def _validate_unittest_outcomes(result: RecordingResult) -> None:
    if result.expectedFailures:
        tests = ", ".join(test.id() for test, _ in result.expectedFailures)
        raise RuntimeError(f"expected failures are forbidden: {tests}")
    if result.unexpectedSuccesses:
        tests = ", ".join(test.id() for test in result.unexpectedSuccesses)
        raise RuntimeError(f"unexpected successes are forbidden: {tests}")


def validate_go_json(paths: list[pathlib.Path]) -> int:
    total_run_events = 0
    total_packages = set()
    for source in paths:
        source = source.resolve(strict=True)
        run_events: collections.Counter[str] = collections.Counter()
        started_tests: dict[str, set[str]] = collections.defaultdict(set)
        passed_tests: dict[str, set[str]] = collections.defaultdict(set)
        terminal_package_passes = set()
        package_skips = set()
        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(
                        line,
                        object_pairs_hook=_reject_duplicate_key,
                        parse_constant=_reject_nonstandard_number,
                    )
                except (json.JSONDecodeError, ValueError) as error:
                    raise RuntimeError(f"invalid Go JSON at {source}:{line_number}: {error}") from error
                if not isinstance(event, dict):
                    raise RuntimeError(f"Go JSON event is not an object at {source}:{line_number}")
                package = event.get("Package")
                if isinstance(package, str) and package:
                    total_packages.add(package)
                test_name = event.get("Test")
                action = event.get("Action")
                if action == "fail":
                    target = f"{package or '?'}::{test_name}" if test_name else package or "?"
                    raise RuntimeError(f"Go test failure event is forbidden: {target}")
                if isinstance(test_name, str) and action == "skip":
                    raise RuntimeError(f"Go test skip is forbidden: {package or '?'}::{test_name}")
                if isinstance(test_name, str) and test_name.startswith("Test") and action == "run":
                    run_events[package] += 1
                    started_tests[package].add(test_name)
                if isinstance(test_name, str) and test_name.startswith("Test") and action == "pass":
                    if test_name not in started_tests[package]:
                        raise RuntimeError(
                            f"Go test pass without a preceding run event is forbidden: "
                            f"{package or '?'}::{test_name}"
                        )
                    passed_tests[package].add(test_name)
                if test_name is None and isinstance(package, str) and action == "pass":
                    terminal_package_passes.add(package)
                if test_name is None and action == "skip":
                    if package not in ALLOWED_GO_PACKAGE_SKIPS:
                        raise RuntimeError(f"Go package skip is forbidden: {package or '?'}")
                    package_skips.add(package)
        if not run_events:
            raise RuntimeError(f"Go JSON contains no test run events: {source}")
        if package_skips != ALLOWED_GO_PACKAGE_SKIPS:
            missing = sorted(ALLOWED_GO_PACKAGE_SKIPS - package_skips)
            raise RuntimeError(f"Go no-test package baseline is missing from {source}: {missing}")
        for package, minimum in REQUIRED_GO_TEST_RUNS.items():
            actual = run_events[package]
            if actual < minimum:
                raise RuntimeError(
                    f"Go package {package} has {actual} test run events in {source}; "
                    f"required minimum is {minimum}"
                )
            if package not in terminal_package_passes:
                raise RuntimeError(
                    f"Go package {package} has no terminal package pass event in {source}"
                )
        for package, expected in REQUIRED_GO_TEST_FINGERPRINTS.items():
            names = passed_tests[package]
            actual_count = len(names)
            actual_digest = _test_name_fingerprint(names)
            if actual_count != expected["count"] or actual_digest != expected["sha256"]:
                raise RuntimeError(
                    f"Go package {package} passed Test* fingerprint mismatch in {source}: "
                    f"count={actual_count} sha256={actual_digest}; "
                    f"expected count={expected['count']} sha256={expected['sha256']}"
                )
            if package not in terminal_package_passes:
                raise RuntimeError(
                    f"Go package {package} has no terminal package pass event in {source}"
                )
        for package, required_names in REQUIRED_GO_TEST_NAMES.items():
            missing = sorted(required_names - passed_tests[package])
            if missing:
                raise RuntimeError(
                    f"Go package {package} is missing required top-level passing tests in {source}: {missing}"
                )
        if SCHEMA_VALIDATOR_TEST not in passed_tests[SCHEMA_VALIDATOR_PACKAGE]:
            raise RuntimeError(
                f"required Draft 2020-12 validator test did not pass in {source}: "
                f"{SCHEMA_VALIDATOR_PACKAGE}::{SCHEMA_VALIDATOR_TEST}"
            )
        total_run_events += sum(run_events.values())
    print(SCHEMA_METASCHEMA_PASS)
    print(
        "GO_JSON_GATE=PASS "
        f"files={len(paths)} semanticRunEvents={total_run_events} packages={len(total_packages)} skips=0"
    )
    return 0


def run(candidate_root: pathlib.Path, verbosity: int = 2) -> int:
    candidate_root = candidate_root.resolve(strict=True)
    if sys.platform.startswith("linux") and os.geteuid() != 0:
        raise RuntimeError("Linux static gate must run as root so ownership tests cannot skip")

    _assert_no_python_cache(candidate_root)
    schema_count = _parse_schemas(candidate_root)
    suite, suite_counts = _load_tests(candidate_root)
    runner = unittest.TextTestRunner(verbosity=verbosity, resultclass=RecordingResult)
    result = runner.run(suite)
    _validate_skips(result)
    _validate_unittest_outcomes(result)
    _assert_no_python_cache(candidate_root)
    if not result.wasSuccessful():
        return 1

    print(
        "STATIC_GATE=PASS "
        f"platform={sys.platform} tests={result.testsRun} skips={len(result.skipped)} "
        f"schemas={schema_count} schemaMetaschema={SCHEMA_METASCHEMA_STATUS} "
        f"suiteCounts={json.dumps(suite_counts, separators=(',', ':'), sort_keys=True)}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
        help="absolute or relative m2b-candidate directory (defaults beside this runner)",
    )
    parser.add_argument("--quiet", action="store_true", help="reduce unittest output")
    parser.add_argument(
        "--go-json",
        action="append",
        type=pathlib.Path,
        default=[],
        help="validate a go test -json transcript; may be repeated",
    )
    args = parser.parse_args()
    try:
        if args.go_json:
            return validate_go_json(args.go_json)
        return run(args.candidate_root, verbosity=1 if args.quiet else 2)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"STATIC_GATE=FAIL reason={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
