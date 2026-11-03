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
    "chengwang/deploy/joint-control-plane/uid_probe_diagnostic.py",
    "chengwang/deploy/joint-control-plane/check_uid_probe_diagnostic.py",
    "chengwang/deploy/joint-control-plane/test_uid_probe_diagnostic.py",
    "chengwang/deploy/joint-control-plane/test_check_uid_probe_diagnostic.py",
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
LOCALIZATION_KEYS = frozenset((
    "progressRootState", "failureDetailState", "bootstrapStepOutcome",
    "bootstrapRecordState", "bootstrapChildState", "bootstrapObservationScope",
    "bootstrapObservedRecordState", "bootstrapObservedChildState",
    "bootstrapObservedChildOperation", "bootstrapObservedChildOperationAuthority",
    "bootstrapLifecycleRecordState", "bootstrapLifecycleFirstFailure",
    "bootstrapLifecycleScope",
))
PROGRESS_STATES = frozenset(("ABSENT", "EMPTY", "ACCEPTED", "INVALID", "READ_FAILED", "SOURCE_MISMATCH"))
DETAIL_STATES = frozenset(("NOT_EVALUATED", "ABSENT", "ACCEPTED", "INVALID", "READ_FAILED", "SOURCE_MISMATCH"))
BOOTSTRAP_RECORD_STATES = frozenset(("ABSENT", "ACCEPTED", "INVALID", "READ_FAILED", "SOURCE_MISMATCH"))
BOOTSTRAP_CHILD_STATES = frozenset(("UNKNOWN", "PASS", "COMMAND_NONZERO", "TIMEOUT", "STDOUT_INVALID", "STDOUT_OVERSIZE", "SPAWN_ERROR"))
BOOTSTRAP_RECORDED_STATES = BOOTSTRAP_CHILD_STATES - {"UNKNOWN"}
BOOTSTRAP_SCHEMA = "chengwang.joint-control-plane-private-bootstrap/v2"
BOOTSTRAP_RECEIPT_SCHEMA = "chengwang.joint-control-plane-bootstrap-child-receipt/v1"
BOOTSTRAP_FAILURE_RECEIPT_SCHEMA = "chengwang.joint-control-plane-bootstrap-child-failure/v1"
BOOTSTRAP_DIRECTORY = "bootstrap-localization.private"
BOOTSTRAP_FILE = "status.json"
BOOTSTRAP_MAXIMUM = 512
BOOTSTRAP_STEP_ID = "bootstrap_progress"
BOOTSTRAP_OBSERVATION_SCOPE = "NON_AUTHORITATIVE_BOOTSTRAP_CHILD_OBSERVATION_NOT_CAUSE"
BOOTSTRAP_CHILD_OPERATIONS = frozenset(("NONE","OBSERVED_UNKNOWN","PROGRESS_ROOT_VALIDATE","PROGRESS_CONTRACT_VALIDATE","PROGRESS_EXCLUSIVE_CREATE","PROGRESS_WRITE","PROGRESS_FILE_FSYNC","PROGRESS_READBACK","PROGRESS_DIR_FSYNC"))
BOOTSTRAP_CHILD_AUTHORITIES = frozenset(("NONE","FIXED_SOURCE_CLASSIFICATION","OBSERVED_UNKNOWN"))
BOOTSTRAP_LIFECYCLE_SCHEMA = "chengwang.joint-control-plane-bootstrap-lifecycle/v1"
BOOTSTRAP_LIFECYCLE_FILE = "bootstrap-lifecycle.private.json"
BOOTSTRAP_LIFECYCLE_SCOPE = "NON_AUTHORITATIVE_BOOTSTRAP_LIFECYCLE_OBSERVATION_NOT_CAUSE"
BOOTSTRAP_LIFECYCLE_STATES = frozenset(("PASS","FAIL","NOT_ATTEMPTED","UNKNOWN"))
BOOTSTRAP_LIFECYCLE_STAGES = ("BRIDGE_SETUP","SOURCE_PREFLIGHT","PROGRESS_SETUP","PROGRESS_PREFLIGHT","BOOTSTRAP_CHILD","PROGRESS_TRANSFER","BRIDGE_CLEANUP","BRIDGE_FINAL_ABSENCE")
BOOTSTRAP_LIFECYCLE_RECORD_STATES = frozenset(("ABSENT","ACCEPTED","INVALID","READ_FAILED","SOURCE_MISMATCH"))
BOOTSTRAP_STEP_OUTCOMES = frozenset((
    "SUCCESS", "FAILURE", "CANCELLED", "SKIPPED", "MISSING", "UNKNOWN",
))

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
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
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

class ProgressDiagnosticFailure(Exception):
    def __init__(self, operation):
        require(operation in BOOTSTRAP_CHILD_OPERATIONS - {"NONE","OBSERVED_UNKNOWN"}, "progress-operation")
        self.operation = operation

def _diagnostic_stage(operation, call):
    try:
        return call()
    except BaseException:
        raise ProgressDiagnosticFailure(operation) from None

def record_bootstrap_progress(root, source_commit):
    root = _diagnostic_stage("PROGRESS_ROOT_VALIDATE", lambda: _private_root(root))
    root, rows = _diagnostic_stage("PROGRESS_CONTRACT_VALIDATE", lambda: _progress_rows(root, source_commit))
    require(not rows, "progress-bootstrap-empty"); name = progress_name(0, "NAMESPACE_SETUP", "ENTERED")
    value = {"schema": PROGRESS_SCHEMA, "sourceCommit": source_commit, "ordinal": 1, "phase": "NAMESPACE_SETUP", "state": "ENTERED"}; raw = canonical(value); path = root / name
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
    except BaseException:
        raise ProgressDiagnosticFailure("PROGRESS_EXCLUSIVE_CREATE") from None
    try:
        try:
            seen = 0
            while seen < len(raw):
                count = os.write(fd, raw[seen:]); require(count > 0, "progress-write"); seen += count
        except BaseException:
            raise ProgressDiagnosticFailure("PROGRESS_WRITE") from None
        try: os.fsync(fd)
        except BaseException: raise ProgressDiagnosticFailure("PROGRESS_FILE_FSYNC") from None
    finally:
        os.close(fd)
    _diagnostic_stage("PROGRESS_READBACK", lambda: require(_private_read(path) == raw, "progress-readback"))
    _diagnostic_stage("PROGRESS_DIR_FSYNC", lambda: _fsync_dir(root))

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

def _identity(meta):
    return (meta.st_dev, meta.st_ino)

def _stable_signature(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink, meta.st_size,
            meta.st_mtime_ns, meta.st_ctime_ns)

def _file_signature(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink, meta.st_size,
            meta.st_mtime_ns)

def _owned_mode(meta, uid, gid, mode):
    if os.name != "posix":
        return True
    return meta.st_uid == uid and meta.st_gid == gid and stat.S_IMODE(meta.st_mode) == mode

def _localized_read(path, maximum, uid, gid, mode):
    path = pathlib.Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return "ABSENT", None, None
    except OSError:
        return "READ_FAILED", None, None
    if (not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_nlink != 1 or
            not 0 < before.st_size <= maximum or not _owned_mode(before, uid, gid, mode)):
        return "INVALID", None, None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return "READ_FAILED", None, None
    try:
        opened = os.fstat(fd); chunks = []; seen = 0
        if _identity(opened) != _identity(before):
            return "READ_FAILED", None, None
        while True:
            chunk = os.read(fd, min(4096, maximum - seen + 1))
            if not chunk:
                break
            chunks.append(chunk); seen += len(chunk)
            if seen > maximum:
                return "INVALID", None, None
        after = os.fstat(fd)
        try:
            named_after = path.lstat()
        except OSError:
            return "READ_FAILED", None, None
        if (_file_signature(before) != _file_signature(opened) or
                _file_signature(opened) != _file_signature(after) or
                _file_signature(after) != _file_signature(named_after) or
                before.st_ctime_ns != named_after.st_ctime_ns or
                opened.st_ctime_ns != after.st_ctime_ns or
                seen != opened.st_size):
            return "READ_FAILED", None, None
        return "ACCEPTED", b"".join(chunks), opened
    except OSError:
        return "READ_FAILED", None, None
    finally:
        os.close(fd)

def _progress_localization(root, source_commit):
    if root is None:
        return "ABSENT", None
    root = pathlib.Path(root)
    try:
        before = root.lstat()
    except FileNotFoundError:
        return "ABSENT", None
    except OSError:
        return "READ_FAILED", None
    if (not stat.S_ISDIR(before.st_mode) or root.is_symlink() or
            not _owned_mode(before, UID, GID, 0o700)):
        return "INVALID", None
    try:
        names_before = sorted(p.name for p in root.iterdir())
    except OSError:
        return "READ_FAILED", None
    expected = [progress_name(i, *item) for i, item in enumerate(PROGRESS_SEQUENCE)]
    allowed = set(expected) | {FAILURE_DETAIL_NAME}
    if len(names_before) > len(allowed) or any(name not in allowed for name in names_before):
        structural = "INVALID"
    else:
        present = [name for name in expected if name in names_before]
        structural = "ACCEPTED" if present == expected[:len(present)] else "INVALID"
    sources = set()
    if structural == "ACCEPTED":
        for index, name in enumerate(present):
            state, raw, _ = _localized_read(root / name, 4096, UID, GID, 0o600)
            if state == "ABSENT":
                structural = "READ_FAILED"; break
            if state != "ACCEPTED":
                structural = state; break
            try:
                value = _strict_object(raw)
            except Exception:
                structural = "INVALID"; break
            phase, progress_state = PROGRESS_SEQUENCE[index]
            keys = {"schema", "sourceCommit", "ordinal", "phase", "state"}
            if (raw != canonical(value) or set(value) != keys or value.get("schema") != PROGRESS_SCHEMA or
                    value.get("ordinal") != index + 1 or value.get("phase") != phase or
                    value.get("state") != progress_state or
                    re.fullmatch(r"[a-f0-9]{40}", value.get("sourceCommit", "")) is None):
                structural = "INVALID"; break
            sources.add(value["sourceCommit"])
    try:
        after = root.lstat(); names_after = sorted(p.name for p in root.iterdir())
    except OSError:
        return "READ_FAILED", None
    if _stable_signature(before) != _stable_signature(after) or names_before != names_after:
        return "READ_FAILED", None
    if structural != "ACCEPTED":
        return structural, root
    if len(sources) > 1:
        return "INVALID", root
    if sources and sources != {source_commit}:
        return "SOURCE_MISMATCH", root
    return ("ACCEPTED" if present else "EMPTY"), root

def _detail_localization(root, source_commit):
    state, raw, _ = _localized_read(root / FAILURE_DETAIL_NAME, 4096, UID, GID, 0o600)
    if state != "ACCEPTED":
        return state
    try:
        value = _strict_object(raw)
    except Exception:
        return "INVALID"
    keys = {"schema", "sourceCommit", "exceptionType", "failureReasonCode",
            "failedCaptureName", "lastCompletedCaptureName"}
    if (raw != canonical(value) or set(value) != keys or value.get("schema") != FAILURE_DETAIL_SCHEMA or
            re.fullmatch(r"[a-f0-9]{40}", value.get("sourceCommit", "")) is None or
            value.get("exceptionType") not in EXCEPTION_TYPES or
            value.get("failureReasonCode") not in FAILURE_REASON_CODES or
            value.get("failedCaptureName") not in CAPTURE_NAMES | {"NONE", "UNKNOWN"} or
            value.get("lastCompletedCaptureName") not in CAPTURE_NAMES | {"NONE", "UNKNOWN"}):
        return "INVALID"
    return "ACCEPTED" if value["sourceCommit"] == source_commit else "SOURCE_MISMATCH"

def bootstrap_record_state(path, source_commit, expected_parent=None,
                           expected_directory=None, expected_file=None,
                           directory_name=BOOTSTRAP_DIRECTORY, include_operation=False):
    if path is None:
        return "ABSENT", "UNKNOWN"
    path = pathlib.Path(path); directory = path.parent; staging = directory.parent
    if directory.name != directory_name or path.name != BOOTSTRAP_FILE:
        return "INVALID", "UNKNOWN"
    try:
        staging_before = staging.lstat()
        directory_before = directory.lstat()
    except FileNotFoundError:
        return "ABSENT", "UNKNOWN"
    except OSError:
        return "READ_FAILED", "UNKNOWN"
    if (not stat.S_ISDIR(staging_before.st_mode) or staging.is_symlink() or
            not stat.S_ISDIR(directory_before.st_mode) or directory.is_symlink() or
            not _owned_mode(directory_before, 0, 0, 0o555)):
        return "INVALID", "UNKNOWN"
    try:
        names_before = sorted(p.name for p in directory.iterdir())
    except OSError:
        return "READ_FAILED", "UNKNOWN"
    if names_before != [BOOTSTRAP_FILE]:
        return "INVALID", "UNKNOWN"
    state, raw, file_meta = _localized_read(path, BOOTSTRAP_MAXIMUM, 0, 0, 0o444)
    if state == "ABSENT":
        return "READ_FAILED", "UNKNOWN"
    if state != "ACCEPTED":
        return state, "UNKNOWN"
    try:
        value = _strict_object(raw)
    except Exception:
        return "INVALID", "UNKNOWN"
    keys = {"schema", "sourceCommit", "bootstrapChildState", "bootstrapChildOperation", "bootstrapChildOperationAuthority"}
    if (raw != canonical(value) or set(value) != keys or value.get("schema") != BOOTSTRAP_SCHEMA or
            re.fullmatch(r"[a-f0-9]{40}", value.get("sourceCommit", "")) is None or
            value.get("bootstrapChildState") not in BOOTSTRAP_RECORDED_STATES or
            value.get("bootstrapChildOperation") not in BOOTSTRAP_CHILD_OPERATIONS or
            value.get("bootstrapChildOperationAuthority") not in BOOTSTRAP_CHILD_AUTHORITIES or
            (value["bootstrapChildState"] == "PASS") != (value["bootstrapChildOperation"] == value["bootstrapChildOperationAuthority"] == "NONE") or
            (value["bootstrapChildOperation"] == "OBSERVED_UNKNOWN") != (value["bootstrapChildOperationAuthority"] == "OBSERVED_UNKNOWN")):
        return "INVALID", "UNKNOWN"
    try:
        staging_after = staging.lstat(); directory_after = directory.lstat()
        names_after = sorted(p.name for p in directory.iterdir())
    except OSError:
        return "READ_FAILED", "UNKNOWN"
    if (_stable_signature(staging_before) != _stable_signature(staging_after) or
            _stable_signature(directory_before) != _stable_signature(directory_after) or
            names_before != names_after):
        return "READ_FAILED", "UNKNOWN"
    if ((expected_parent is not None and _identity(staging_after) != expected_parent) or
            (expected_directory is not None and _identity(directory_after) != expected_directory) or
            (expected_file is not None and _identity(file_meta) != expected_file)):
        return "INVALID", "UNKNOWN"
    if value["sourceCommit"] != source_commit:
        return "SOURCE_MISMATCH", "UNKNOWN"
    result = ("ACCEPTED", value["bootstrapChildState"])
    return result + (value["bootstrapChildOperation"], value["bootstrapChildOperationAuthority"]) if include_operation else result

def bootstrap_step_outcome(step_id, outcome, witness_source, source_commit):
    values = (step_id, outcome, witness_source)
    if any(value is None or value == "" for value in values):
        return "MISSING"
    if (step_id != BOOTSTRAP_STEP_ID or
            re.fullmatch(r"[a-f0-9]{40}", witness_source or "") is None or
            witness_source != source_commit):
        return "UNKNOWN"
    mapped = {"success": "SUCCESS", "failure": "FAILURE",
              "cancelled": "CANCELLED", "skipped": "SKIPPED"}.get(outcome)
    return mapped if mapped is not None else "UNKNOWN"

def record_bootstrap_lifecycle(path, source_commit, run_id, run_attempt, nonce,
                               payload_digest, stage_statuses, primary_exit, final_exit):
    require(_root_writer() and re.fullmatch(r"[a-f0-9]{40}", source_commit or "") and
            re.fullmatch(r"[1-9][0-9]*", run_id or "") and
            re.fullmatch(r"[1-9][0-9]*", run_attempt or "") and
            re.fullmatch(r"[a-f0-9]{32}", nonce or "") and
            re.fullmatch(r"[a-f0-9]{64}", payload_digest or "") and
            type(stage_statuses) is tuple and len(stage_statuses) == len(BOOTSTRAP_LIFECYCLE_STAGES) and
            all(type(value) is int and 0 <= value <= 255 for value in stage_statuses) and
            type(primary_exit) is int and type(final_exit) is int and
            0 <= primary_exit <= 255 and 0 <= final_exit <= 255, "bootstrap-lifecycle-input")
    path = pathlib.Path(path); require(path.is_absolute() and path.name == BOOTSTRAP_LIFECYCLE_FILE and path.parent.is_dir() and not path.parent.is_symlink() and not path.exists() and not path.is_symlink(), "bootstrap-lifecycle-path")
    stages = {stage:("PASS" if status == 0 else "FAIL") for stage,status in zip(BOOTSTRAP_LIFECYCLE_STAGES,stage_statuses)}
    first_failure = next((stage for stage in BOOTSTRAP_LIFECYCLE_STAGES if stages[stage] == "FAIL"), "NONE")
    require((primary_exit == 0) == (all(value == 0 for value in stage_statuses[:6])) and
            (final_exit == 0) == (all(value == 0 for value in stage_statuses)), "bootstrap-lifecycle-exit")
    value = {"schema":BOOTSTRAP_LIFECYCLE_SCHEMA,"sourceCommit":source_commit,"runId":run_id,
             "runAttempt":run_attempt,"bridgeNonce":nonce,"payloadDigest":payload_digest,
             "scope":BOOTSTRAP_LIFECYCLE_SCOPE,"stages":stages,"firstFailure":first_failure,
             "primaryExit":primary_exit,"finalExit":final_exit}
    raw = canonical(value); require(len(raw) <= 2048, "bootstrap-lifecycle-size")
    fd = os.open(path, os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0), 0o600)
    try:
        seen=0
        while seen < len(raw):
            count=os.write(fd,raw[seen:]);require(count>0,"bootstrap-lifecycle-write");seen+=count
        os.fchown(fd,0,0);os.fsync(fd);os.lseek(fd,0,os.SEEK_SET);require(os.read(fd,len(raw)+1)==raw,"bootstrap-lifecycle-readback");os.fchmod(fd,0o444);os.fsync(fd);meta=os.fstat(fd);require(_owned_mode(meta,0,0,0o444) and stat.S_ISREG(meta.st_mode) and meta.st_nlink==1,"bootstrap-lifecycle-mode")
    finally:os.close(fd)
    _fsync_dir(path.parent);state,observed=_bootstrap_lifecycle_state(path,source_commit);require(state=="ACCEPTED" and observed==first_failure,"bootstrap-lifecycle-final")

def _bootstrap_lifecycle_state(path, source_commit):
    if path is None:return "ABSENT","UNKNOWN"
    path=pathlib.Path(path)
    try:raw=_private_read(path);meta=path.lstat()
    except FileNotFoundError:return "ABSENT","UNKNOWN"
    except OSError:return "READ_FAILED","UNKNOWN"
    if path.name != BOOTSTRAP_LIFECYCLE_FILE or path.is_symlink() or not _owned_mode(meta,0,0,0o444) or not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or len(raw)>2048:return "INVALID","UNKNOWN"
    try:value=_strict_object(raw)
    except Exception:return "INVALID","UNKNOWN"
    keys={"schema","sourceCommit","runId","runAttempt","bridgeNonce","payloadDigest","scope","stages","firstFailure","primaryExit","finalExit"}
    stages=value.get("stages")
    if raw!=canonical(value) or set(value)!=keys or value.get("schema")!=BOOTSTRAP_LIFECYCLE_SCHEMA or value.get("scope")!=BOOTSTRAP_LIFECYCLE_SCOPE or type(stages)is not dict or set(stages)!=set(BOOTSTRAP_LIFECYCLE_STAGES) or any(stages.get(stage) not in {"PASS","FAIL"} for stage in BOOTSTRAP_LIFECYCLE_STAGES) or value.get("firstFailure")!=next((stage for stage in BOOTSTRAP_LIFECYCLE_STAGES if stages[stage]=="FAIL"),"NONE") or re.fullmatch(r"[1-9][0-9]*",value.get("runId","") or "") is None or re.fullmatch(r"[1-9][0-9]*",value.get("runAttempt","") or "") is None or re.fullmatch(r"[a-f0-9]{32}",value.get("bridgeNonce","") or "") is None or re.fullmatch(r"[a-f0-9]{64}",value.get("payloadDigest","") or "") is None or type(value.get("primaryExit")) is not int or type(value.get("finalExit")) is not int or not 0<=value["primaryExit"]<=255 or not 0<=value["finalExit"]<=255 or ((value["primaryExit"]==0) != all(stages[stage]=="PASS" for stage in BOOTSTRAP_LIFECYCLE_STAGES[:6])) or ((value["finalExit"]==0) != all(stages[stage]=="PASS" for stage in BOOTSTRAP_LIFECYCLE_STAGES)):return "INVALID","UNKNOWN"
    if value.get("sourceCommit")!=source_commit:return "SOURCE_MISMATCH","UNKNOWN"
    return "ACCEPTED",value["firstFailure"]

def localization_evidence(progress_root, bootstrap_record, source_commit,
                          bootstrap_step_id=None, bootstrap_step_outcome_value=None,
                          bootstrap_step_source=None):
    progress_state, root = _progress_localization(progress_root, source_commit)
    detail_state = (_detail_localization(root, source_commit)
                    if progress_state in ("EMPTY", "ACCEPTED") else "NOT_EVALUATED")
    step_outcome = bootstrap_step_outcome(
        bootstrap_step_id, bootstrap_step_outcome_value,
        bootstrap_step_source, source_commit)
    observed = bootstrap_record_state(bootstrap_record, source_commit, include_operation=True)
    observed_record_state, observed_child_state = observed[:2]
    observed_operation, observed_authority = (observed[2:] if len(observed) == 4 else ("OBSERVED_UNKNOWN", "OBSERVED_UNKNOWN"))
    lifecycle_path = (pathlib.Path(bootstrap_record).parent.parent / BOOTSTRAP_LIFECYCLE_FILE
                      if bootstrap_record is not None else None)
    lifecycle_state, lifecycle_first = _bootstrap_lifecycle_state(lifecycle_path, source_commit)
    record_state, child_state = observed_record_state, observed_child_state
    require(progress_state in PROGRESS_STATES and detail_state in DETAIL_STATES and
            step_outcome in BOOTSTRAP_STEP_OUTCOMES and
            record_state in BOOTSTRAP_RECORD_STATES and child_state in BOOTSTRAP_CHILD_STATES,
            "localization")
    if record_state == "ACCEPTED" and step_outcome != "SUCCESS":
        record_state = "INVALID"
        child_state = "UNKNOWN"
    elif record_state != "ACCEPTED":
        child_state = "UNKNOWN"
    return {"progressRootState": progress_state, "failureDetailState": detail_state,
            "bootstrapStepOutcome": step_outcome,
            "bootstrapRecordState": record_state, "bootstrapChildState": child_state,
            "bootstrapObservationScope": BOOTSTRAP_OBSERVATION_SCOPE,
            "bootstrapObservedRecordState": observed_record_state,
            "bootstrapObservedChildState": (observed_child_state
                                            if observed_record_state == "ACCEPTED"
                                            else "UNKNOWN"),
            "bootstrapObservedChildOperation": (observed_operation if observed_record_state == "ACCEPTED" else "OBSERVED_UNKNOWN"),
            "bootstrapObservedChildOperationAuthority": (observed_authority if observed_record_state == "ACCEPTED" else "OBSERVED_UNKNOWN"),
            "bootstrapLifecycleRecordState": lifecycle_state,
            "bootstrapLifecycleFirstFailure": lifecycle_first,
            "bootstrapLifecycleScope": BOOTSTRAP_LIFECYCLE_SCOPE}

def _root_writer():
    return os.name == "posix" and os.geteuid() == 0

def record_bootstrap_status(path, source_commit, child_state, child_operation="NONE", child_authority="NONE"):
    require(_root_writer(), "bootstrap-platform")
    require(re.fullmatch(r"[a-f0-9]{40}", source_commit or "") is not None and
            child_state in BOOTSTRAP_RECORDED_STATES and child_operation in BOOTSTRAP_CHILD_OPERATIONS and child_authority in BOOTSTRAP_CHILD_AUTHORITIES and
            ((child_state == "PASS" and child_operation == child_authority == "NONE") or
             (child_state != "PASS" and ((child_operation == "OBSERVED_UNKNOWN" and child_authority == "OBSERVED_UNKNOWN") or
              (child_operation not in ("NONE", "OBSERVED_UNKNOWN") and child_authority == "FIXED_SOURCE_CLASSIFICATION")))), "bootstrap-value")
    path = pathlib.Path(path); directory = path.parent; staging = directory.parent
    require(directory.name == BOOTSTRAP_DIRECTORY and path.name == BOOTSTRAP_FILE,
            "bootstrap-path")
    staging_meta = staging.lstat()
    require(stat.S_ISDIR(staging_meta.st_mode) and not staging.is_symlink(), "bootstrap-parent")
    try:
        directory.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError("bootstrap-record-exists")
    os.mkdir(directory, 0o700); os.chmod(directory, 0o700)
    directory_meta = directory.lstat()
    require(stat.S_ISDIR(directory_meta.st_mode) and not directory.is_symlink() and
            _owned_mode(directory_meta, 0, 0, 0o700), "bootstrap-directory")
    value = {"schema": BOOTSTRAP_SCHEMA, "sourceCommit": source_commit,
             "bootstrapChildState": child_state, "bootstrapChildOperation": child_operation,
             "bootstrapChildOperationAuthority": child_authority}
    raw = canonical(value); require(len(raw) <= BOOTSTRAP_MAXIMUM, "bootstrap-size")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
    file_identity = None
    try:
        seen = 0
        while seen < len(raw):
            count = os.write(fd, raw[seen:])
            require(count > 0, "bootstrap-write")
            seen += count
        os.fsync(fd); os.lseek(fd, 0, os.SEEK_SET); chunks = []; read_total = 0
        while True:
            chunk = os.read(fd, min(4096, BOOTSTRAP_MAXIMUM - read_total + 1))
            if not chunk:
                break
            chunks.append(chunk); read_total += len(chunk)
            require(read_total <= BOOTSTRAP_MAXIMUM, "bootstrap-readback")
        opened = os.fstat(fd); named = path.lstat()
        require(b"".join(chunks) == raw and _identity(opened) == _identity(named) and
                _owned_mode(opened, 0, 0, 0o600), "bootstrap-readback")
        os.fchmod(fd, 0o444); final_open = os.fstat(fd); final_named = path.lstat()
        require(_identity(final_open) == _identity(opened) == _identity(final_named) and
                _owned_mode(final_open, 0, 0, 0o444) and stat.S_ISREG(final_open.st_mode) and
                final_open.st_nlink == 1, "bootstrap-mode")
        os.fsync(fd); file_identity = _identity(final_open)
    finally:
        os.close(fd)
    os.chmod(directory, 0o555); directory_final = directory.lstat()
    require(_identity(directory_final) == _identity(directory_meta) and
            _owned_mode(directory_final, 0, 0, 0o555) and
            sorted(p.name for p in directory.iterdir()) == [BOOTSTRAP_FILE],
            "bootstrap-directory")
    _fsync_dir(directory); _fsync_dir(staging)
    state, recorded, operation, authority = bootstrap_record_state(
        path, source_commit, expected_parent=_identity(staging_meta),
        expected_directory=_identity(directory_final), expected_file=file_identity,
        include_operation=True)
    require(state == "ACCEPTED" and (recorded, operation, authority) ==
            (child_state, child_operation, child_authority), "bootstrap-final")

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
