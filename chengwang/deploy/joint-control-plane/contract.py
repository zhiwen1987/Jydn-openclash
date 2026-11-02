"""Closed contract for the isolated cmd/server joint-control-plane experiment."""
from __future__ import annotations

import copy
import hashlib
import json
import re

SCHEMA = "chengwang.joint-control-plane/v2"
CAPTURE_SCHEMA = "chengwang.joint-control-plane-capture/v2"
RUNTIME_SCHEMA = "chengwang.joint-control-plane-runtime/v2"
WIRE_SCHEMA = "chengwang.joint-control-plane-wire/v2"
READBACK_SCHEMA = "chengwang.joint-control-plane-readback/v2"
OUTCOME_SCHEMA = "chengwang.joint-control-plane-outcome/v2"
READY_SCHEMA = "chengwang.joint-control-plane-fixture-ready/v2"
STOPPED_SCHEMA = "chengwang.joint-control-plane-fixture-stopped/v2"
BOUNDARY = "LOCAL_SUBSCRIPTION_ADMISSION_ONLY"
SCENARIO_BOUNDARY = "ISOLATED_CMD_SERVER_BUSINESS_E2E"
SCOPE = {"tenantId": "joint-control-plane", "siteId": "isolated", "environment": "candidate"}
FOREIGN_TENANT = "foreign-joint-control-plane"
MANAGEMENT_OBJECT = "local"
UID = GID = 10001
API = ("127.0.0.1", 17871)
DOT = ("127.0.0.1", 1853)
SOURCE = ("8.8.4.4", 443)
MIHOMO = ("8.8.4.4", 9443)
DOT_NAME = "resolver.joint.example"
SOURCE_HOSTS = {"success": "success.subscription.example", "failure": "failure.subscription.example"}
SOURCE_IP = "8.8.4.4"
ROLES = ("viewer", "operator", "approver", "auditor", "foreign")
MACHINE_ID = "refresh-machine"
MACHINE_ROLE = "subscription_refresher"
REFRESH_INTERVAL = 60
EXPERIMENT_DEADLINE = 50
POLL_SECONDS = 5
GRACE_SECONDS = 10
HARNESS_STOP_SECONDS = 15
MAX_CAPTURE = 65536
MAX_ARTIFACT = 16 << 20
MAX_EVENTS = 4096
COMMAND = re.compile(r"^cmd_[a-f0-9]{32}$")
SOURCE_ID = re.compile(r"^src_[a-f0-9]{32}$")
CANDIDATE_ID = re.compile(r"^cand_[a-f0-9]{32}$")
DIGEST = re.compile(r"^hmac-sha256:[a-f0-9]{64}$")

IDEMPOTENCY = {
    case: {
        "viewer_create_neg": f"joint-v2-{case}-viewer-create-neg-v1",
        "create_source": f"joint-v2-{case}-create-source-v1",
        "operator_approve_r1_neg": f"joint-v2-{case}-operator-approve-r1-neg-v1",
        "approve_r1": f"joint-v2-{case}-approve-r1-v1",
        "fetch_r1": f"joint-v2-{case}-fetch-r1-v1",
        "admit_r2": f"joint-v2-{case}-admit-r2-v1",
        "approve_r3": f"joint-v2-{case}-approve-r3-v1",
    } for case in SOURCE_HOSTS
}

REFRESH_REQUIRED = frozenset((
    "scope", "binding", "bindingSeal", "bindingGeneration", "state", "attemptCount",
    "consecutiveFailures", "stale", "clockState", "auditRecorded", "stateMayHaveChanged",
))
REFRESH_OPTIONAL = frozenset((
    "failure", "attemptSequence", "attemptKey", "fence", "commandId", "commandOwnerId",
    "commandEpoch", "candidateId", "candidateDigest", "resultRevision", "startedAt", "completedAt",
    "lastSuccessAt", "freshUntil", "nextAttemptAt", "clockReason", "reservation", "storagePending",
    "storageRetryCount", "storageNextRetryAt",
))
BINDING_KEYS = frozenset((
    "sourceId", "referenceId", "policyRevision", "approvalId", "approvalSourceRevision",
    "intervalSeconds", "approvalTtlSeconds", "maxStaleSeconds", "maxBackoffSeconds",
))
RESERVATION_KEYS = frozenset((
    "attemptSequence", "attemptKey", "fence", "commandSlots", "candidateSlots", "domainAuditSlots", "bytes",
))
TERMINAL_STATES = frozenset(("candidate_quarantined", "failed"))
PUBLIC_FILES = frozenset((
    "build.json", "source-before.json", "source-after.json", "isolation.json", "runtime.json",
    "captures.jsonl", "wire-events.jsonl", "readback.json", "outcome.json", "api-ca.pem",
    "api-leaf.pem", "resolver-ca.pem", "resolver-leaf.pem", "source-ca.pem", "source-leaf.pem",
    "mihomo-ca.pem", "mihomo-leaf.pem", "private-checks.json", "transport-negatives.json",
))
SOURCE_CONTRACT_SCENE = frozenset((
    "chengwang/deploy/joint-control-plane/check_joint_control_plane.py",
    "chengwang/deploy/joint-control-plane/ci_joint_control_plane.py",
    "chengwang/deploy/joint-control-plane/ci_namespace.sh",
    "chengwang/deploy/joint-control-plane/contract.py",
    "chengwang/deploy/joint-control-plane/joint_fixture.py",
    "chengwang/deploy/joint-control-plane/run_joint_control_plane.py",
    "chengwang/deploy/joint-control-plane/sanitize_publication.py",
    "chengwang/deploy/joint-control-plane/test_check_joint_control_plane.py",
    "chengwang/deploy/joint-control-plane/test_joint_fixture.py",
    "chengwang/deploy/joint-control-plane/test_run_joint_control_plane.py",
    "chengwang/deploy/joint-control-plane/test_sanitize_publication.py",
))

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok, label="contract"):
    if not ok:
        raise ValueError("joint-control-plane-" + label + "-rejected")

def human_grant(tenant):
    return {"tenantId": tenant, "siteId": SCOPE["siteId"], "environment": SCOPE["environment"]}

def machine_grants(source_ids):
    require(set(source_ids) == set(SOURCE_HOSTS), "machine-grants")
    return [{**SCOPE, "objectType": "subscription-source", "objectId": source_ids[k]} for k in sorted(source_ids)]

def idempotency(case, operation):
    require(case in IDEMPOTENCY and operation in IDEMPOTENCY[case], "idempotency")
    return IDEMPOTENCY[case][operation]

def append_refresh(base, source_ids, approval_ids):
    require(set(source_ids) == set(approval_ids) == set(SOURCE_HOSTS), "policy")
    result = copy.deepcopy(base)
    indexed = {entry["referenceId"]: entry for entry in result["sources"]}
    require(set(indexed) == set(SOURCE_HOSTS), "policy")
    for case in sorted(SOURCE_HOSTS):
        indexed[case]["refresh"] = {
            "sourceId": source_ids[case], "approvalId": approval_ids[case],
            "approvalSourceRevision": 3, "intervalSeconds": REFRESH_INTERVAL,
            "approvalTtlSeconds": 600, "maxStaleSeconds": 300, "maxBackoffSeconds": 600,
        }
    validate_policy_transition(base, result)
    return result

def validate_policy_transition(base, refreshed):
    stripped = copy.deepcopy(refreshed)
    for entry in stripped.get("sources", []):
        entry.pop("refresh", None)
    require(stripped == base, "policy-transition")
    for entry in refreshed["sources"]:
        require(set(entry) == {"referenceId", "revision", "secretVersion", "url", "allowedCnames", "caPEM", "refresh"}, "policy-transition")

def refresh_keys(value):
    require(type(value) is dict and REFRESH_REQUIRED <= set(value) <= REFRESH_REQUIRED | REFRESH_OPTIONAL, "refresh-dto")
    require("lease" not in value and type(value["binding"]) is dict and set(value["binding"]) == BINDING_KEYS, "refresh-dto")
    require(DIGEST.fullmatch(value["bindingSeal"]) and value["bindingGeneration"]>0 and type(value["stale"])is bool and value["clockState"] in ("normal","frozen") and (value["clockState"]=="normal")==(not value.get("clockReason")), "refresh-dto")
    require(value.get("storagePending",False)==(value.get("storageRetryCount",0)>0), "refresh-dto")
    if "reservation" in value:
        require(type(value["reservation"]) is dict and set(value["reservation"]) == RESERVATION_KEYS, "refresh-dto")
    if value["state"] == "running":
        require("reservation" in value, "refresh-dto")
    else:
        require("reservation" not in value, "refresh-dto")
    state=value["state"]
    common={"attemptSequence","attemptKey","fence","startedAt","completedAt"}
    if state in ("candidate_quarantined","failed"):
        require(common <= set(value) and value["attemptCount"]>0 and value["attemptSequence"]>0 and re.fullmatch(r"refresh_[a-f0-9]{32}",value["attemptKey"]) and re.fullmatch(r"[a-f0-9]{64}",value["fence"]) and value["stateMayHaveChanged"] is False, "refresh-dto")
        require(COMMAND.fullmatch(value.get("commandId","")) and value.get("commandOwnerId")==MACHINE_ID and re.fullmatch(r"[a-f0-9]{64}",value.get("commandEpoch","")), "refresh-dto")
    if state=="candidate_quarantined":
        require({"commandId","commandOwnerId","commandEpoch","candidateId","candidateDigest","resultRevision","lastSuccessAt","freshUntil"} <= set(value), "refresh-dto")
        require(CANDIDATE_ID.fullmatch(value["candidateId"]) and DIGEST.fullmatch(value["candidateDigest"]) and value["resultRevision"]==4 and "failure" not in value and value["auditRecorded"] is True and value["consecutiveFailures"]==0, "refresh-dto")
    if state=="failed":
        require(value.get("failure")=="http" and value["consecutiveFailures"]>0 and "nextAttemptAt" in value and {"commandId","commandOwnerId","commandEpoch"}<=set(value) and value["auditRecorded"] is True, "refresh-dto")
        require("candidateId" not in value and "candidateDigest" not in value and "resultRevision" not in value, "refresh-dto")
    return value

def outcome(source_commit, fixture_id, status):
    require(status in ("CAPTURED", "FAIL"), "outcome")
    return {"schema": OUTCOME_SCHEMA, "sourceCommit": source_commit, "fixtureId": fixture_id,
            "status": status, "production": False, "deviceActionsExecuted": False,
            "lifecycleLabProven": False, "realBrowserProven": False, "actualSKUObservation": "UNKNOWN",
            "authorization": "BLOCKED", "runtimeAcceptanceProven": False,
            "refreshWorkerProven": status == "CAPTURED", "mainStoreRestartPersistenceProven": status == "CAPTURED",
            "refreshSidecarUnchangedDuringReadback": status == "CAPTURED",
            "refreshRestartPersistenceProven": False, "boundary": BOUNDARY,
            "scenarioBoundary": SCENARIO_BOUNDARY}
