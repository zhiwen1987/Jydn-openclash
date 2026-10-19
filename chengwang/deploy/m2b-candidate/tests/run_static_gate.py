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
import re
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
    "tests": 26,
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
    "chengwang/cmd/docker-runtime-readonly-proxy": 1,
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
    "chengwang/internal/dockerreadonlyproxy": 20,
    "chengwang/internal/evidence": 40,
    "chengwang/internal/kernel": 2,
    "chengwang/internal/lease": 14,
    "chengwang/internal/observation": 13,
    "chengwang/internal/operation": 61,
    "chengwang/internal/policy": 3,
    "chengwang/internal/probe": 260,
    "chengwang/internal/proberestore": 16,
    "chengwang/internal/proxyiface": 5,
    "chengwang/internal/restorecoordinator": 24,
    "chengwang/internal/restoreclock": 13,
    "chengwang/internal/restorecurrent": 148,
    "chengwang/internal/restoreimage": 201,
    "chengwang/internal/restorelease": 2,
    "chengwang/internal/restoreruntime": 50,
    "chengwang/internal/routing": 4,
    "chengwang/internal/store": 4,
    "chengwang/internal/truth": 20,
    "chengwang/internal/runtimewire": 1,
    "chengwang/internal/webui": 3,
}

REQUIRED_GO_TEST_FINGERPRINTS = {
    "chengwang/cmd/docker-runtime-readonly-proxy": {
        "count": 1,
        "sha256": "7d37f6a69b4a0dbe1954268fce30c54fcf73d4a008c3ccd94640d26563313e2d",
    },
    "chengwang/internal/dockerreadonlyproxy": {
        "count": 20,
        "sha256": "ca9b3fefd09d90a495db1297f0babf48999fe8c4e12b03cb6a6f5975415bcdcf",
    },
    "chengwang/internal/restorecontracts": {
        "count": 227,
        "sha256": "36b2b9c67a3e742ccaf9a6694fb6665844002f27cd83a2422949df4c7073e7ff",
    },
    "chengwang/internal/restorecoordinator": {
        "count": 24,
        "sha256": "641b77a1e952f67645760bf0babd7d352b51c77a7c6957134f9592b736ccb0d3",
    },
    "chengwang/internal/restorecurrent": {
        "count": 148,
        "sha256": "518d0474814e656cafd2012fcf400a56e52374f4cb184df652e38bd7822558cd",
    },
    "chengwang/internal/restoreimage": {
        "count": 201,
        "sha256": "45899b6ac978ee4d618af8f41e1a3c43c78326899ff4332584650cd2f9ff96b5",
    },
    "chengwang/internal/restoreruntime": {
        "count": 50,
        "sha256": "78f5e0401f2b04b01e236d73defa02ea53f6b16ab5f58857ee0d3a995cc5415b",
    },
    "chengwang/internal/runtimewire": {
        "count": 1,
        "sha256": "7baf3d7086d45cffb3e0596325b145a905fb1d571358716a88c5a14b912f61f8",
    },
}

REQUIRED_GO_TEST_NAMES = {
    "chengwang/cmd/docker-runtime-readonly-proxy": frozenset(
        {"TestProxyCommandKeepsFixedPrivilegeBoundary"}
    ),
    "chengwang/internal/dockerreadonlyproxy": frozenset(
        {
            "TestCollectorUsesOnlyFixedGETsAndReturnsSecretFreeProjection",
            "TestCollectorRejectsRuntimeDriftAndAmbiguousJSON",
            "TestServerRejectsEveryUnapprovedRequestShape",
            "TestServerDoesNotExposeCollectorError",
        }
    ),
    "chengwang/internal/probe": frozenset(
        {
            "TestStateTreeDigestV1GoldenAndFieldBinding",
            "TestStateValidationReportV1WireFieldsUnchanged",
            "TestLockedStateSnapshotHoldsBothWriterLocksUntilClose",
            "TestLockedStateSnapshotReleasesSpoolWhenLedgerLockFails",
            "TestLockedStateSnapshotVerifyDetectsMutationAndPoisons",
            "TestLockedStateSnapshotVerifyDetectsMutationAndPoisons/spool",
            "TestLockedStateSnapshotVerifyDetectsMutationAndPoisons/ledger",
            "TestLockedStateSnapshotSemanticFailureReleasesBothLocks",
            "TestLockedStateSnapshotSemanticFailureReleasesBothLocks/spool",
            "TestLockedStateSnapshotSemanticFailureReleasesBothLocks/ledger",
            "TestLockedStateSnapshotDetectsLockPathReplacement",
            "TestLockedStateSnapshotDetectsLockPathReplacement/spool",
            "TestLockedStateSnapshotDetectsLockPathReplacement/ledger",
            "TestLockedStateSnapshotSharedLifecycleAndCloseIdempotence",
            "TestLockedStateSnapshotMatchesCompatibilityWrapper",
            "TestLockedStateSnapshotDetectsRootRebinding",
            "TestLockedStateSnapshotDetectsRootRebinding/spool",
            "TestLockedStateSnapshotDetectsRootRebinding/ledger",
            "TestLockedStateSnapshotNilAndZeroValuesFailClosed",
            "TestLockedStateSnapshotConcurrentLifecycleIsSerialized",
            "TestLockedStateSnapshotInteroperatesWithWriterLocksAcrossProcesses",
            "TestLockedStateSnapshotInteroperatesWithWriterLocksAcrossProcesses/validator_blocks_both_child_writers_and_releases_them",
            "TestLockedStateSnapshotInteroperatesWithWriterLocksAcrossProcesses/child_ledger_writer_blocks_validator_without_leaking_spool_lock",
            "TestLockedStateSnapshotDescriptorsDoNotSurviveExec",
        }
    ),
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
    "chengwang/internal/restoreclock": frozenset(
        {
            "TestOpenAndObserveReturnOpaqueMonotonicSnapshots",
            "TestClockRejectsBootChangeAndPoisons",
            "TestClockRejectsWallAndBoottimeRollback",
            "TestObserveWithinRejectsForeignExcessiveAndDivergentWindows",
            "TestClockRejectsInvalidSamplesAndBounds",
            "TestNilAndZeroClockFailClosed",
        }
    ),
    "chengwang/internal/restorecurrent": frozenset(
        {
            "TestAdvisoryObservationBlockersAreExactStableAndImmutable",
            "TestIdentityBoundBlockersKeepExternalAttestationGap",
            "TestOpenAdvisoryRejectsEveryUnsafeCandidatePathBeforeCollection",
            "TestNilZeroClosedAndCopiedHandlesFailClosed",
            "TestValidateConfigurationAcceptsOnlyExactFixedBindings",
            "TestValidateConfigurationAcceptsOnlyExactFixedBindings/env_binding",
            "TestValidateConfigurationAcceptsOnlyExactFixedBindings/catalog_bytes",
            "TestValidateConfigurationAcceptsOnlyExactFixedBindings/ca_bytes",
            "TestValidateConfigurationAcceptsOnlyExactFixedBindings/policy_bytes",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/root",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/project",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/generation",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/unknown",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/duplicate_key",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/trailing_token",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/wrong_type",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/wrong_schema",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/wrong_candidate_id",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/wrong_instance",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/wrong_service",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/wrong_state_mount_target",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/invalid_nonce",
            "TestCandidateIdentityBindsRootNonceProjectAndGeneration/all_zero_nonce",
            "TestLocalReleaseBindsExactBytesSemanticsAndKeepsAllBlockers",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/source_guard_role",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/rendered_extra_service",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/rendered_privileged",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/rendered_mount_mode",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_duplicate",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_trailing",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_unknown",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_wrong_type",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_identity",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_source_digest",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_rendered_digest",
            "TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens/binding_renderer_claim",
            "TestLocalReleaseAcceptsAbsoluteExternalBuildContextClaim",
            "TestLocalReleaseRejectsMalformedBuildContextClaims",
            "TestLocalReleaseRejectsMalformedBuildContextClaims/backslash",
            "TestLocalReleaseRejectsMalformedBuildContextClaims/newline",
            "TestLocalReleaseRejectsMalformedBuildContextClaims/nul",
            "TestLocalReleaseRejectsMalformedBuildContextClaims/relative",
            "TestLocalReleaseRejectsMalformedBuildContextClaims/root",
            "TestLocalReleaseRejectsMalformedBuildContextClaims/unclean",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/extra_service",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/privileged",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/build_context",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/network_name",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/network_attachment",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/duplicate_tmpfs",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/proxy_environment",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/mount_mode",
            "TestRenderedSemanticDigestNormalizesAcceptedRepresentations",
            "TestReleaseObserverSourcePurityASTGate",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/raw_import_alias",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/unicode_import_alias",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/commented_import_alias",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/indexed_receiver",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/parenthesized_method",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/numeric_write_flags",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/parenthesized_syscall",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/syscall_function_value",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/release_println",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/release_package_write",
            "TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses/release_package_address",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/file_chmod",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/fmt_fprint",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/io_copy",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/json_encoder",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/bufio_writer",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/encoder_encode",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/writer_flush",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/fmt_print",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/builtin_println",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/internal_store",
            "TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods/writer_write_to",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/profile",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/stdin_open",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/tty",
            "TestRenderedComposeRejectsEverySecurityProjectionDrift/network_driver",
            "TestEnvironmentParserRejectsUnknownDuplicateMissingAndSecretValues",
            "TestPolicyRejectsDuplicateKeysAndUnapprovedClaims",
            "TestConfigurationErrorsNeverExposeRawSecretCanary",
            "TestCatalogAndPolicyErrorsNeverExposeUntrustedTokens",
            "TestCatalogAndPolicyErrorsNeverExposeUntrustedTokens/catalog_trailing_token",
            "TestCatalogAndPolicyErrorsNeverExposeUntrustedTokens/catalog_unknown_key",
            "TestCatalogAndPolicyErrorsNeverExposeUntrustedTokens/policy_trailing_token",
            "TestCatalogAndPolicyErrorsNeverExposeUntrustedTokens/policy_duplicate_key",
            "TestDigestUsesPrefixedRawSHA256",
        }
    ),
    "chengwang/internal/restorelease": frozenset(
        {
            "TestNilAndZeroLeaseFailClosed",
            "TestProductionCandidatePathPolicy",
        }
    ),
    "chengwang/internal/restoreimage": frozenset(
        {
            "TestValidateLocalBindsRawOCIAndDockerBytes",
            "TestValidateLocalRequiresExactRawByteDigests",
            "TestValidateLocalRequiresExactRawByteDigests/config-id-is-not-manifest-digest",
            "TestValidateLocalRequiresExactRawByteDigests/manifest-id-is-not-config-digest",
            "TestValidateLocalRejectsAmbiguousJSON",
            "TestValidateLocalBoundsOpaqueInputWork",
            "TestContentHasNoAuthorizationOrRawConfigSurface",
            "TestAssociationKeepsDigestRolesAndNineBlockers",
            "TestCandidateIDContractMatchesActualUpstreamProducer",
            "TestAssociationRejectsIncompleteAndSubstitutedRuntime/candidate-is-not-sha256",
            "TestAssociationRejectsIncompleteAndSubstitutedRuntime/manifest-digest-is-not-runtime-image-id",
            "TestBindLocalRejectsZeroOpaqueInputs",
            "TestLocalBytesCannotAuthenticateRepositoryOrLayerContent",
            "TestProductionSourcesKeepPureByteAndParentTypeBoundary",
            "TestProductionSourceScannerRejectsCapabilityChanges",
            "TestProductionSourceScannerRejectsNativeAttachments",
        }
    ),
    "chengwang/internal/restoreruntime": frozenset(
        {
            "TestCaptureFactsDoubleReadsAndKeepsEveryAuthorizationBlocker",
            "TestCaptureFactsFailsClosedOnReleaseOrRuntimeDrift",
            "TestRuntimeSnapshotAcceptsOnlyExactHardenedProductShape",
            "TestRuntimeSnapshotDoubleReadDetectsEveryIdentityDrift",
            "TestRuntimeSnapshotStrictDecoderRejectsAmbiguityAndSecretsRemainAbsent",
            "TestObserverProductionSourcesForbidDockerWriteCapabilities",
        }
    ),
    "chengwang/internal/runtimewire": frozenset(
        {"TestSnapshotWireSchemaIsVersionedAndSecretFree"}
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


def _validate_restorecurrent_sources(candidate_root: pathlib.Path) -> None:
    package_root = candidate_root.parents[1] / "internal" / "restorecurrent"
    _validate_restorecurrent_package(package_root)
    snapshot = package_root / "compose_probe_agent.snapshot.yaml"
    source = candidate_root / "compose.probe-agent.yaml"
    if not snapshot.is_file() or snapshot.read_bytes() != source.read_bytes():
        raise RuntimeError("restorecurrent Compose source snapshot differs from compose.probe-agent.yaml")


def _validate_runtime_observer_sources(candidate_root: pathlib.Path) -> None:
    chengwang_root = candidate_root.parents[1]
    observer_root = chengwang_root / "internal" / "restoreruntime"
    proxy_root = chengwang_root / "internal" / "dockerreadonlyproxy"
    command_root = chengwang_root / "cmd" / "docker-runtime-readonly-proxy"
    for package in (observer_root, proxy_root, command_root):
        if not package.is_dir():
            raise RuntimeError(f"runtime observer package is missing: {package}")

    observer_sources = sorted(
        path for path in observer_root.glob("*.go") if not path.name.endswith("_test.go")
    )
    if len(observer_sources) < 3:
        raise RuntimeError("runtime observer production source set is incomplete")
    observer_text = "\n".join(path.read_text(encoding="utf-8") for path in observer_sources)
    observer_forbidden = {
        "/var/run/docker.sock": "standard Docker socket",
        "/run/docker.sock": "standard Docker socket",
        '"os/exec"': "subprocess execution",
        '"github.com/docker/': "Docker SDK",
        "DOCKER_HOST": "environment-selected Docker endpoint",
        "DOCKER_CONTEXT": "environment-selected Docker context",
        "ProxyFromEnvironment": "environment-selected HTTP proxy",
        "os.Getenv": "environment-selected runtime input",
        "os.LookupEnv": "environment-selected runtime input",
        "http.MethodPost": "HTTP write method",
        "http.MethodPut": "HTTP write method",
        "http.MethodPatch": "HTTP write method",
        "http.MethodDelete": "HTTP write method",
        "restorecontracts.StateOnlyCurrent": "authoritative current-state output",
        '"chengwang/internal/restorecoordinator"': "restore coordinator integration",
    }
    for token, capability in observer_forbidden.items():
        if token in observer_text:
            raise RuntimeError(f"runtime observer contains forbidden {capability}: {token}")
    if observer_text.count('/run/chengwang-runtime-observer/readonly.sock') != 1:
        raise RuntimeError("runtime observer must contain exactly one fixed read-only proxy socket")

    proxy_sources = sorted(
        path for path in proxy_root.glob("*.go") if not path.name.endswith("_test.go")
    )
    if len(proxy_sources) < 3:
        raise RuntimeError("Docker read-only collector production source set is incomplete")
    proxy_text = "\n".join(path.read_text(encoding="utf-8") for path in proxy_sources)
    proxy_forbidden = {
        '"os/exec"': "subprocess execution",
        '"github.com/docker/': "Docker SDK",
        "DOCKER_HOST": "environment-selected Docker endpoint",
        "DOCKER_CONTEXT": "environment-selected Docker context",
        "ProxyFromEnvironment": "environment-selected HTTP proxy",
        "http.MethodPost": "Docker write method",
        "http.MethodPut": "Docker write method",
        "http.MethodPatch": "Docker write method",
        "http.MethodDelete": "Docker write method",
        "/logs": "unbounded container logs",
        "/archive": "container filesystem archive",
        "/exec": "container execution API",
        "/stats": "unbounded container statistics",
        "/events": "unbounded daemon events",
        "/images/get": "image export API",
        "/containers/create": "container creation API",
        "/start": "container start API",
        "/stop": "container stop API",
        "/kill": "container kill API",
        "/remove": "Docker removal API",
    }
    for token, capability in proxy_forbidden.items():
        if token in proxy_text:
            raise RuntimeError(f"Docker read-only collector contains forbidden {capability}: {token}")
    if proxy_text.count('/run/docker.sock') != 1 or '/var/run/docker.sock' in proxy_text:
        raise RuntimeError("Docker read-only collector backend socket contract drifted")
    if 'SnapshotPathPrefix = "/v1/runtime-snapshot/"' not in proxy_text:
        raise RuntimeError("Docker read-only collector endpoint contract is missing")


def _validate_restorecurrent_package(package_root: pathlib.Path) -> None:
    if not package_root.is_dir():
        raise RuntimeError(f"restorecurrent package is missing: {package_root}")
    allowed_imports = {
        "bufio", "bytes", "crypto/sha256", "embed", "encoding/hex", "encoding/json",
        "errors", "fmt", "io", "net/netip", "os", "path", "regexp", "sort",
        "strconv", "strings", "sync", "syscall", "time", "unicode/utf8",
        "chengwang/internal/probe", "chengwang/internal/restoreclock",
        "chengwang/internal/restorelease",
    }
    forbidden = {
        '"os/exec"': "shell or subprocess execution",
        '"net/http"': "network clients",
        '"github.com/docker/': "Docker SDK",
        "restorecontracts.StateOnlyCurrent": "authoritative current-state output",
        '"chengwang/internal/restorecoordinator"': "coordinator integration",
        "AcquireLockedStateSnapshot": "state collection without quiesce authority",
        "os.ReadFile": "path-based configuration reads",
        "exec.Command": "subprocess execution",
        "os.WriteFile": "filesystem mutation",
        "os.OpenFile": "potentially writable filesystem access",
        "os.Create": "filesystem mutation",
        "os.Rename": "filesystem mutation",
        "os.Remove": "filesystem mutation",
        "os.Chmod": "filesystem mutation",
        "os.Chown": "filesystem mutation",
        "os.Truncate": "filesystem mutation",
        "WriteTo(": "filesystem or output mutation",
        "fmt.Print(": "standard output mutation",
        "fmt.Printf(": "standard output mutation",
        "fmt.Println(": "standard output mutation",
        "syscall.Socket": "raw network access",
        "syscall.Connect": "raw network access",
        "syscall.Syscall": "unreviewed raw syscall access",
        "syscall.RawSyscall": "unreviewed raw syscall access",
        "syscall.O_WRONLY": "writable file descriptor access",
        "syscall.O_RDWR": "writable file descriptor access",
        "syscall.O_CREAT": "filesystem mutation",
        "syscall.O_TRUNC": "filesystem mutation",
        "syscall.O_APPEND": "filesystem mutation",
    }
    production = sorted(
        path for path in package_root.glob("*.go") if not path.name.endswith("_test.go")
    )
    if not production:
        raise RuntimeError("restorecurrent production sources are missing")
    for source in production:
        text = source.read_text(encoding="utf-8")
        imports = set(
            re.findall(
                r'^\s*(?:[._A-Za-z][A-Za-z0-9_]*\s+)?"([^"\n]+)"\s*$',
                text,
                flags=re.MULTILINE,
            )
        )
        imports.update(
            re.findall(
                r'^\s*import\s+(?:[._A-Za-z][A-Za-z0-9_]*\s+)?"([^"\n]+)"\s*$',
                text,
                flags=re.MULTILINE,
            )
        )
        import_aliases: dict[str, str] = {}
        for alias, import_path in re.findall(
            r'^\s*([._A-Za-z][A-Za-z0-9_]*)?\s*"([^"\n]+)"\s*$',
            text,
            flags=re.MULTILINE,
        ):
            effective = alias if alias and alias != "import" else import_path.rsplit("/", 1)[-1]
            import_aliases[effective] = import_path
        for alias, import_path in re.findall(
            r'^\s*import\s+(?:([._A-Za-z][A-Za-z0-9_]*)\s+)?"([^"\n]+)"\s*$',
            text,
            flags=re.MULTILINE,
        ):
            import_aliases[alias or import_path.rsplit("/", 1)[-1]] = import_path
        unexpected_imports = sorted(imports - allowed_imports)
        if unexpected_imports:
            raise RuntimeError(
                f"restorecurrent source {source.name} imports forbidden packages: {unexpected_imports}"
            )
        for token, capability in forbidden.items():
            if token in text:
                raise RuntimeError(
                    f"restorecurrent source {source.name} contains forbidden {capability}: {token}"
                )
        if re.search(r"(?<![.A-Za-z0-9_])(?:panic|print|println)\s*\(", text):
            raise RuntimeError(
                f"restorecurrent source {source.name} contains forbidden builtin side effect"
            )
        privileged_aliases = {
            alias: import_path
            for alias, import_path in import_aliases.items()
            if import_path in {"os", "syscall"}
        }
        if any(alias in {".", "_"} for alias in privileged_aliases):
            raise RuntimeError(f"restorecurrent source {source.name} uses an unreviewed privileged import form")
        privileged_calls = set()
        for alias, import_path in privileged_aliases.items():
            for method in re.findall(
                rf"\b{re.escape(alias)}\.([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                text,
            ):
                privileged_calls.add(f"{import_path}.{method}")
        unexpected_privileged = sorted(
            privileged_calls
            - {"os.NewFile", "os.Open", "syscall.Close", "syscall.Fstat", "syscall.Open", "syscall.Openat"}
        )
        if unexpected_privileged:
            raise RuntimeError(
                f"restorecurrent source {source.name} calls unreviewed OS or syscall APIs: {unexpected_privileged}"
            )
    release_source = package_root / "release.go"
    if not release_source.is_file():
        return
    release_text = release_source.read_text(encoding="utf-8")
    release_imports = set(
        re.findall(
            r'^\s*(?:[._A-Za-z][A-Za-z0-9_]*\s+)?"([^"\n]+)"\s*$',
            release_text,
            flags=re.MULTILINE,
        )
    )
    release_allowed = {
        "bytes", "crypto/sha256", "embed", "encoding/hex", "encoding/json", "errors", "fmt", "io",
        "path", "regexp", "strings", "unicode/utf8",
    }
    if release_imports - release_allowed:
        raise RuntimeError(
            f"restorecurrent release observer imports side-effect-capable packages: {sorted(release_imports - release_allowed)}"
        )
    for token in (
        "os.", "syscall.", "net.", "WriteFile", "OpenFile", "Rename", "Remove", "Chmod", "Chown", "Socket", "Dial",
    ):
        if token in release_text:
            raise RuntimeError(f"restorecurrent release observer contains forbidden side-effect token: {token}")
    declared = set(
        re.findall(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", release_text, flags=re.MULTILINE)
    )
    unqualified_calls = set(
        re.findall(r"(?<![.A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*\(", release_text)
    )
    unqualified_calls.update(
        re.findall(
            r"(?<![.A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]\n]+\]\s*\(",
            release_text,
        )
    )
    builtins_and_keywords = {
        "append", "byte", "const", "func", "import", "int64", "len", "make", "type", "uint64", "var",
    }
    external_helpers = sorted(unqualified_calls - declared - builtins_and_keywords)
    if external_helpers:
        raise RuntimeError(
            "restorecurrent release observer calls helpers declared outside its pure source file: "
            + ", ".join(external_helpers)
        )
    allowed_selector_calls = {
        "bytes.Equal", "bytes.IndexByte", "bytes.NewReader",
        "decoder.Decode", "decoder.DisallowUnknownFields", "decoder.More", "decoder.Token", "decoder.UseNumber",
        "errors.Join", "errors.New", "fmt.Sprint", "hex.EncodeToString",
        "json.Delim", "json.Marshal", "json.NewDecoder", "json.Unmarshal",
        "path.Clean", "path.IsAbs", "path.Join", "regexp.MustCompile",
        "releaseHashPattern.MatchString", "rendererVersionPattern.MatchString", "sha256.Sum256",
        "strings.ContainsAny", "strings.HasPrefix", "strings.Repeat", "strings.TrimPrefix",
        "utf8.Valid", "value.String",
    }
    selector_calls = {
        f"{match.group(1)}.{match.group(2)}"
        for match in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]\n]+\])?\s*\(",
            release_text,
        )
    }
    unexpected_selectors = sorted(selector_calls - allowed_selector_calls)
    if unexpected_selectors:
        raise RuntimeError(
            "restorecurrent release observer calls unreviewed selector methods: "
            + ", ".join(unexpected_selectors)
        )
    if re.search(
        r"\)\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]\n]+\])?\s*\(",
        release_text,
    ):
        raise RuntimeError("restorecurrent release observer calls a chained selector method")


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
    _validate_restorecurrent_sources(candidate_root)
    _validate_runtime_observer_sources(candidate_root)
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
