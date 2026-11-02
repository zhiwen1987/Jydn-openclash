"""Closed contract for the isolated cmd/server joint-control-plane experiment."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import ssl
import stat
import subprocess

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

FAILURE_PHASES = (
    "NAMESPACE_SETUP", "ISOLATION_CHECK", "RUNNER_PREPARE", "FIXTURE_START",
    "B0", "J1", "R2", "RUNNER_FINALIZE", "PRIVATE_SANITIZER",
)
FAILURE_PHASE_VALUES = frozenset((*FAILURE_PHASES, "UNKNOWN"))
LAST_COMPLETED_PHASE_VALUES = frozenset(("NONE", *FAILURE_PHASES))
EXCEPTION_TYPES = frozenset((
    "HARNESS_FAILURE", "COMMAND_NONZERO", "PERMISSION_ERROR", "FILE_NOT_FOUND",
    "FILE_EXISTS", "TIMEOUT", "SUBPROCESS_ERROR", "JSON_ERROR", "TLS_ERROR",
    "OS_ERROR", "VALUE_ERROR", "TYPE_ERROR", "KEY_ERROR", "UNKNOWN",
))
FAILURE_REASON_CODES = frozenset((
    "COMMIT", "DUPLICATE-AUTH", "ENVELOPE", "EVIDENCE", "FIXTURE", "FIXTURE-STOP",
    "HTTP", "LISTENER", "OVERVIEW", "PLAINTEXT", "PLATFORM", "PROFILE", "READ",
    "RESIDUE", "ROOT", "SIDECAR", "SLO", "SOURCE", "STABLE", "START", "STOP",
    "TLS", "WIRE", "WORKER-DELTA", "WORKER-RECEIPT", "WRONG-CA", "UNKNOWN",
))
CAPTURE_SUFFIXES = (
    "-viewer-create-neg", "-create", "-operator-approve-neg", "-approve-r1",
    "-fetch-r1", "-admit-r2", "-approve-r3", "-baseline-source",
    "-baseline-candidates", "-approval-receipt", "-refresh-poll",
    "-worker-receipt-auditor", "-worker-receipt-viewer-denied",
    "-worker-receipt-operator-denied", "-r2-worker-receipt", "-r2-candidates",
)
CAPTURE_NAMES = frozenset((
    "anonymous-list", "foreign-list", "overview-anonymous", "mihomo-status-anonymous",
    "mihomo-runtime-viewer", "mihomo-runtime-anonymous-denied",
    "mihomo-runtime-foreign-denied", "r2-sources",
)) | frozenset(case + suffix for case in SOURCE_HOSTS for suffix in CAPTURE_SUFFIXES)
PROGRESS_SCHEMA = "chengwang.joint-control-plane-private-progress/v1"
FAILURE_DETAIL_SCHEMA = "chengwang.joint-control-plane-private-failure-detail/v1"
FAILURE_CLASSIFICATION_KEYS = frozenset((
    "failurePhase", "lastCompletedPhase", "exceptionType", "failureReasonCode",
    "failedCaptureName", "lastCompletedCaptureName",
))
FAILURE_DETAIL_NAME = "failure-classification.private.json"
PROGRESS_SEQUENCE = tuple(
    (phase, state) for phase in FAILURE_PHASES for state in ("ENTERED", "COMPLETED")
)

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok, label="contract"):
    if not ok:
        raise ValueError("joint-control-plane-" + label + "-rejected")

def progress_name(index, phase, state):
    require((phase, state) == PROGRESS_SEQUENCE[index], "progress-name")
    return f"{index:02d}-{phase}-{state}.json"

def _strict_object(raw):
    def pairs(values):
        out = {}
        for key, value in values:
            require(key not in out, "private-json")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))

def _private_root(root):
    root = pathlib.Path(root)
    meta = root.lstat()
    require(stat.S_ISDIR(meta.st_mode) and not root.is_symlink(), "private-root")
    return root

def _private_read(path, maximum=4096):
    path = pathlib.Path(path); before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and before.st_nlink == 1 and
            0 < before.st_size <= maximum, "private-read")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd); chunks = []; seen = 0
        while True:
            chunk = os.read(fd, min(4096, maximum - seen + 1))
            if not chunk:
                break
            chunks.append(chunk); seen += len(chunk)
            require(seen <= maximum, "private-read")
        raw = b"".join(chunks); after = os.fstat(fd); named_after = path.lstat()
        signature = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                   value.st_nlink, value.st_size, value.st_mtime_ns)
        require(signature(before) == signature(opened) == signature(after) == signature(named_after) and
                before.st_ctime_ns == named_after.st_ctime_ns and
                opened.st_ctime_ns == after.st_ctime_ns and len(raw) == opened.st_size,
                "private-read")
        return raw
    finally:
        os.close(fd)

def _fsync_dir(path):
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def _exclusive_private(root, name, value):
    root = _private_root(root); path = root / name; raw = canonical(value)
    require(len(raw) <= 4096 and path.parent == root, "private-write")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(_private_read(path) == raw, "private-write")
    _fsync_dir(root)

def _progress_rows(root, source_commit):
    require(re.fullmatch(r"[a-f0-9]{40}", source_commit or "") is not None, "progress-commit")
    root = _private_root(root)
    expected = [progress_name(i, *item) for i, item in enumerate(PROGRESS_SEQUENCE)]
    allowed = set(expected) | {FAILURE_DETAIL_NAME}
    entries = list(root.iterdir())
    require(len(entries) <= len(allowed) and all(p.name in allowed for p in entries), "progress-files")
    present = [name for name in expected if (root / name).exists() or (root / name).is_symlink()]
    require(present == expected[:len(present)], "progress-order")
    rows = []
    for index, name in enumerate(present):
        value = _strict_object(_private_read(root / name))
        phase, state = PROGRESS_SEQUENCE[index]
        require(set(value) == {"schema", "sourceCommit", "ordinal", "phase", "state"} and
                value == {"schema": PROGRESS_SCHEMA, "sourceCommit": source_commit,
                          "ordinal": index + 1, "phase": phase, "state": state},
                "progress-record")
        rows.append(value)
    return root, rows

def record_progress(root, source_commit, phase, state):
    root, rows = _progress_rows(root, source_commit)
    require(len(rows) < len(PROGRESS_SEQUENCE) and
            (phase, state) == PROGRESS_SEQUENCE[len(rows)], "progress-next")
    index = len(rows)
    _exclusive_private(root, progress_name(index, phase, state), {
        "schema": PROGRESS_SCHEMA, "sourceCommit": source_commit, "ordinal": index + 1,
        "phase": phase, "state": state,
    })

def exception_type(error):
    code = getattr(error, "code", None)
    if code in FAILURE_REASON_CODES and code != "UNKNOWN":
        return "HARNESS_FAILURE"
    ordered = (
        (subprocess.TimeoutExpired, "TIMEOUT"), (TimeoutError, "TIMEOUT"),
        (subprocess.CalledProcessError, "COMMAND_NONZERO"),
        (subprocess.SubprocessError, "SUBPROCESS_ERROR"),
        (PermissionError, "PERMISSION_ERROR"), (FileNotFoundError, "FILE_NOT_FOUND"),
        (FileExistsError, "FILE_EXISTS"), (json.JSONDecodeError, "JSON_ERROR"),
        (ssl.SSLError, "TLS_ERROR"), (OSError, "OS_ERROR"),
        (ValueError, "VALUE_ERROR"), (TypeError, "TYPE_ERROR"), (KeyError, "KEY_ERROR"),
    )
    return next((category for kind, category in ordered if isinstance(error, kind)), "UNKNOWN")

def _capture_value(value, missing="NONE"):
    if value is None or value == "":
        return missing
    return value if value in CAPTURE_NAMES else "UNKNOWN"

def record_failure_detail(root, source_commit, error, failed_capture=None,
                          last_completed_capture=None):
    root, _ = _progress_rows(root, source_commit)
    code = getattr(error, "code", None)
    value = {
        "schema": FAILURE_DETAIL_SCHEMA,
        "sourceCommit": source_commit,
        "exceptionType": exception_type(error),
        "failureReasonCode": code if code in FAILURE_REASON_CODES else "UNKNOWN",
        "failedCaptureName": _capture_value(failed_capture),
        "lastCompletedCaptureName": _capture_value(last_completed_capture),
    }
    _exclusive_private(root, FAILURE_DETAIL_NAME, value)

def unknown_failure_classification():
    return {
        "failurePhase": "UNKNOWN", "lastCompletedPhase": "NONE",
        "exceptionType": "UNKNOWN", "failureReasonCode": "UNKNOWN",
        "failedCaptureName": "UNKNOWN", "lastCompletedCaptureName": "UNKNOWN",
    }

def failure_classification(root, source_commit):
    default = unknown_failure_classification()
    try:
        root, rows = _progress_rows(root, source_commit)
    except Exception:
        return default
    if rows:
        last_completed = next((row["phase"] for row in reversed(rows)
                               if row["state"] == "COMPLETED"), "NONE")
        tail = rows[-1]
        if tail["state"] == "ENTERED":
            failure_phase = tail["phase"]
        elif len(rows) < len(PROGRESS_SEQUENCE):
            failure_phase = PROGRESS_SEQUENCE[len(rows)][0]
        else:
            failure_phase = "UNKNOWN"
    else:
        failure_phase, last_completed = "UNKNOWN", "NONE"
    result = {**default, "failurePhase": failure_phase,
              "lastCompletedPhase": last_completed}
    detail = root / FAILURE_DETAIL_NAME
    if not detail.exists() and not detail.is_symlink():
        return result
    try:
        value = _strict_object(_private_read(detail))
        keys = {"schema", "sourceCommit", "exceptionType", "failureReasonCode",
                "failedCaptureName", "lastCompletedCaptureName"}
        require(set(value) == keys and value["schema"] == FAILURE_DETAIL_SCHEMA and
                value["sourceCommit"] == source_commit and
                value["exceptionType"] in EXCEPTION_TYPES and
                value["failureReasonCode"] in FAILURE_REASON_CODES and
                value["failedCaptureName"] in CAPTURE_NAMES | {"NONE", "UNKNOWN"} and
                value["lastCompletedCaptureName"] in CAPTURE_NAMES | {"NONE", "UNKNOWN"},
                "failure-detail")
    except Exception:
        return default
    return {**result, **{key: value[key] for key in (
        "exceptionType", "failureReasonCode", "failedCaptureName",
        "lastCompletedCaptureName")}}

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
