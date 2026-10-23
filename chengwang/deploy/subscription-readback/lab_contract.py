"""Frozen CI laboratory protocol; never an endpoint or production setting.

Actual networking/process execution is Linux isolated CI only. Importing this
module has no side effects. Public artifacts must never contain input tokens,
source URLs, upstream names/passwords, private keys or the private inventory.
"""
from __future__ import annotations

SCHEMA = "chengwang.subscription-product-lab/v1"
READY_SCHEMA = "chengwang.subscription-wire-ready/v1"
EVENT_SCHEMA = "chengwang.subscription-wire-event/v1"
STOPPED_SCHEMA = "chengwang.subscription-wire-stopped/v1"
CAPTURE_SCHEMA = "chengwang.subscription-api-capture/v1"
BUILD_SCHEMA = "chengwang.subscription-build/v1"
ISOLATION_SCHEMA = "chengwang.subscription-isolation/v1"
RUNTIME_SCHEMA = "chengwang.subscription-runtime/v1"
READBACK_SCHEMA = "chengwang.subscription-private-readback/v1"
BOUNDARY = "LOCAL_SUBSCRIPTION_ADMISSION_ONLY"
SCOPE = {"tenantId": "subscription-lab", "siteId": "isolated", "environment": "candidate"}
OBJECT_ID = "local"
UID = GID = 10001
API_HOST, API_PORT = "127.0.0.1", 17871
DOT_HOST, DOT_PORT, DOT_NAME = "127.0.0.1", 1853, "resolver.subscription.example"
SOURCE_IP, SOURCE_PORT = "8.8.4.4", 443  # lo only, in a private no-egress namespace
MAX_INPUT = 1 << 20
MAX_CONNECTIONS, MAX_EVENTS = 128, 1024
MAX_CAPTURE_BYTES, MAX_ARTIFACT_BYTES = 65536, 8 << 20
REFERENCE_IDS = ("good-a", "good-b", "bad", "redirect", "private", "wrongca", "wrongname", "oversize")
SOURCE_HOSTS = {ref: ref + ".subscription.example" for ref in REFERENCE_IDS}
SOURCE_CERT_NAMES = tuple(SOURCE_HOSTS[ref] for ref in REFERENCE_IDS if ref != "wrongname")
ROLES = ("viewer", "operator", "approver", "auditor", "admin", "other-operator", "foreign")

# (case, process epoch, actual HTTP status). The sequence is frozen before CI.
# Epochs are separate executions of the actual cmd/server binary, not RunWith
# goroutines or httptest. Epoch 2 changes private policy material; epoch 3 locks
# writes. Every call uses ordinary CA/SAN verification, never TLS bypass.
CAPTURES = (
    ("anonymous_list", 0, 401), ("foreign_list", 0, 403), ("viewer_create", 0, 403),
    ("create_a", 0, 200), ("create_b", 0, 200), ("operator_approve_denied", 0, 403),
    ("unapproved_fetch", 0, 409), ("approve_a", 0, 200), ("approve_b", 0, 200),
    ("fetch_a", 0, 200), ("fetch_b", 0, 200), ("admit_a", 0, 200), ("admit_b", 0, 200),
    ("sources_admitted", 0, 200), ("nodes_a", 0, 200), ("nodes_b", 0, 200),
    ("replay_fetch_a", 0, 200), ("other_actor_receipt", 0, 403),
    ("approve_bad_a", 0, 200), ("fetch_bad_a", 0, 400), ("sources_after_bad", 0, 200),
    ("approve_redirect_a", 0, 200), ("fetch_redirect_a", 0, 503), ("sources_after_redirect", 0, 200),
    ("approve_private_a", 0, 200), ("fetch_private_a", 0, 503), ("sources_after_private", 0, 200),
    ("approve_wrongca_a", 0, 200), ("fetch_wrongca_a", 0, 503), ("sources_after_wrongca", 0, 200),
    ("approve_wrongname_a", 0, 200), ("fetch_wrongname_a", 0, 503), ("sources_after_wrongname", 0, 200),
    ("approve_oversize_a", 0, 200), ("fetch_oversize_a", 0, 503), ("sources_after_oversize", 0, 200),
    ("approve_good_a", 0, 200), ("sources_before_restart", 0, 200),
    ("sources_after_restart", 1, 200), ("receipt_after_restart", 1, 200),
    ("replay_after_restart", 1, 200), ("fetch_noop_after_restart", 1, 200),
    ("fetch_changed_policy", 2, 409), ("sources_after_policy_change", 2, 200),
    ("writes_locked", 3, 423), ("sources_locked", 3, 200),
)

PUBLIC_FILES = frozenset((
    "build.json", "source-before.json", "source-after.json", "isolation.json",
    "captures.jsonl", "runtime.json", "private-readback.json", "audit-events.jsonl",
    "audit-checkpoint.json", "wire-ready.json", "wire-events.jsonl", "wire-stopped.json",
    "api-ca.pem", "api-leaf.pem", "source-ca.pem", "source-leaf.pem", "resolver-ca.pem",
    "resolver-leaf.pem", "wrong-ca.pem", "outcome.json",
))

EVENT_KEYS = frozenset(("schema", "ordinal", "connection", "service", "event", "reference",
                        "queryType", "status", "bytes", "tls", "reason", "receivedUnixNano"))
CAPTURE_KEYS = frozenset(("schema", "ordinal", "name", "epoch", "method", "path", "status",
                          "requestPublic", "responseBase64", "responseSHA256", "tlsPeerDERBase64",
                          "wireBefore", "wireAfter", "receivedUnixNano", "commandIdHeader"))

READY_KEYS = frozenset(("schema", "pid", "uid", "gid", "dotAddress", "dotPort",
                        "httpsAddress", "httpsPort", "tls", "deadlineSeconds"))
STOPPED_KEYS = frozenset(("schema", "pid", "termination", "accepted", "closed", "events",
                          "workerThreadsAlive", "listenersClosed", "normalStop"))
EVENT_REASONS = frozenset(("ok", "closed", "partial", "failed", "timeout", "stopping",
                           "capacity", "query-invalid", "request-invalid", "auth-invalid",
                           "transport-error"))
BUILD_KEYS = frozenset(("schema", "sourceCommit", "goVersion", "moduleMode",
                        "dependencyDownloads", "authorization", "production", "server"))
ISOLATION_KEYS = frozenset(("schema", "outerNetNamespace", "netNamespace", "mountNamespace",
    "pidNamespace", "uid", "gid", "capabilities", "noNewPrivileges", "interfaces",
    "ipv4Addresses", "ipv4DefaultRoutes", "ipv6DefaultRoutes", "unprivilegedPortStart"))

# Names frozen from the three task cards BEFORE execution. Not generated from a
# successful run. Unit evidence is separate from the real product experiment.
UNIT_NAMES = {
    "test_wire_fixture": {
        "ShapeTests": (
            "dns_a_aaaa_and_private_wire", "dns_invalid_questions_fail_closed",
            "http_exact_token_request_and_redaction", "http_fixed_response_modes_and_oversize",
            "input_json_and_base64_are_closed", "cli_profile_and_event_shape",
            "record_signal_never_touches_event_lock", "bootstrap_and_diagnostics_are_bounded"),
        "LinuxTests": (
            "normal_dot_ca_and_san", "wrong_dot_ca_and_san_rejected",
            "https_good_sources_same_private_yaml", "https_bad_yaml_redirect_and_oversize",
            "wrong_source_ca_rejected_without_http", "wrong_source_name_rejected_without_http",
            "invalid_token_and_sensitive_headers_redacted", "unknown_dns_and_http_fail_closed",
            "private_modes_owner_and_extra_inputs_rejected", "symlink_hardlink_and_fifo_inputs_rejected",
            "input_replacement_and_mutation_fail_closed", "term_joins_inflight_tls",
            "int_joins_partial_request", "request_timeout_and_deadline_not_normal_stop",
            "worker_capacity_and_connection_budget", "ready_stopped_and_active_listener_are_atomic"),
    },
    "test_run_subscription_lab": {"RunnerContracts": (
        "cli_requires_exact_inputs", "platform_identity_fails_closed", "capability_and_no_new_privileges",
        "private_root_is_empty_and_canonical", "evidence_root_separate_and_exclusive",
        "nofollow_owner_mode_and_links", "bounded_private_inputs", "certificate_commands_are_fixed",
        "private_credentials_are_high_entropy", "policy_material_change_is_single_input",
        "environment_is_closed", "server_argv_has_no_secrets", "process_identity_and_starttime",
        "process_profile_rejects_privilege", "stop_requires_normal_exit_zero",
        "cleanup_never_claims_success_on_kill", "capture_contract_order_is_exact",
        "api_body_is_bounded_and_typed", "public_request_projection_is_closed",
        "tls_peer_certificate_is_bound", "wire_fences_are_complete_prefixes",
        "state_and_receipt_revision_assertions", "publication_scans_secret_variants",
        "publication_rejects_unknown_and_partial")},
    "test_check_subscription_lab": {"CheckerTests": (
        "valid_complete_lab", "exact_public_file_set", "file_custody_and_budgets",
        "json_duplicates_nan_and_trailing", "source_commit_binding", "source_manifests_and_raw_git_blobs",
        "build_and_binary_binding", "isolation_no_egress_profile", "four_actual_server_epochs",
        "normal_shutdown_and_no_residue", "api_certificate_peers_and_normal_tls",
        "certificate_identities_and_roots", "capture_exact_order_and_status", "capture_raw_base64_and_sha",
        "capture_request_whitelist", "capture_response_closed_dtos", "role_401_403_boundaries",
        "sources_revisions_and_lkg", "opaque_nodes_cross_source", "failed_fetch_preserves_lkg",
        "receipt_restart_immutable", "replay_has_no_wire", "new_key_noop",
        "changed_policy_unapproved_no_wire", "writes_locked_423", "wire_event_closed_sequence",
        "wire_connection_closure", "wire_capture_fences", "wire_fixed_dns_and_https_budget",
        "external_audit_hash_chain", "audit_checkpoint_and_command_bindings",
        "private_projection_and_outcome_not_authority")},
}
