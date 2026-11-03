#!/usr/bin/env python3
"""Fail-closed source and event oracle for the isolated Capacity Fixture B lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

WORKFLOW_TEMPLATE_SHA256 = "67abf3de08f5cde3efdabf4a70aa0877599db31033c516251782fb3e8facb625"
WORKFLOW_PATH = ".github/workflows/chengwang-mihomo-capacity-fixture-b.yml"
COMPONENT = "chengwang/deploy/mihomo-capacity-fixture-b"
PIN_NAMES = ("CONTRACT_SHA256", "CHECKER_SHA256", "MODEL_SHA256", "RUNNER_SHA256")
SETUP_PHASES = (
    "NAMESPACE_ENTRY", "MOUNT_PRIVATE", "LOOPBACK", "REPO_BIND", "REPO_READONLY",
    "GOROOT_BIND", "GOROOT_READONLY", "TMPFS", "UID_STORAGE", "SOURCE_ALIAS",
    "SOURCE_READONLY", "EXPORT_ALIAS", "EXPORT_READWRITE", "SOURCE_CWD",
    "UID_PREFLIGHT_SCRIPT", "UID_PREFLIGHT_MODULE_ROOT", "UID_PREFLIGHT_GOROOT_EXEC",
    "GO_ENV_COMMAND", "GO_ENV_EXIT", "GO_ENV_STDERR_EMPTY", "TOOLCHAIN_WRITER",
    "FORMAT_GATE", "GO_INVOKE", "ORACLE_VALIDATE",
)
SETUP_STATUSES = ("ENTERED", "PASS", "FAIL")
PRIVATE_UID = 10001
GOENV_POLICY = "off"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TEST_NAME = re.compile(r"Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_.-]+)*")
ALLOWED_EVENT_KEYS = {"Time", "Action", "Package", "Test", "Elapsed", "Output", "FailedBuild"}
ALLOWED_ACTIONS = {"start", "run", "pause", "cont", "pass", "fail", "output", "skip"}
FAILURE_CODES = {
    "FORMAT_REJECTED",
    "INTERNAL_UNKNOWN",
    "PACKAGE_REJECTED",
    "PROCESS_NONZERO",
    "SOURCE_MISMATCH",
    "STDERR_NONEMPTY",
    "STREAM_INCOMPLETE",
    "TEST_SET_MISMATCH",
    "TEST_STATE_REJECTED",
    "TOOLCHAIN_MISMATCH",
}


class GateError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        if code not in FAILURE_CODES:
            code = "INTERNAL_UNKNOWN"
        super().__init__(message or code)
        self.code = code


def need(value: bool, code: str, message: str = "") -> None:
    if not value:
        raise GateError(code, message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def reject_constant(value: str) -> object:
    raise ValueError("non-finite JSON constant: " + value)


def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode_json(raw: bytes) -> object:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_pairs,
        parse_constant=reject_constant,
    )


def exact_keys(value: object, keys: tuple[str, ...], code: str) -> dict[str, object]:
    need(type(value) is dict and tuple(value) == keys, code)
    return value  # type: ignore[return-value]


def strict_int(value: object, low: int = 0, high: int = (1 << 31) - 1) -> int:
    need(type(value) is int and low <= value <= high, "INTERNAL_UNKNOWN")
    return value  # type: ignore[return-value]


def safe_read(path: Path, maximum: int) -> bytes:
    need(path.is_file() and not path.is_symlink(), "INTERNAL_UNKNOWN")
    size = path.stat().st_size
    need(0 <= size <= maximum, "INTERNAL_UNKNOWN")
    raw = path.read_bytes()
    need(len(raw) == size, "INTERNAL_UNKNOWN")
    return raw


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def write_new(path: Path, raw: bytes, maximum: int = 1 << 20) -> None:
    need(0 <= len(raw) <= maximum, "INTERNAL_UNKNOWN")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o644)
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            need(count > 0, "INTERNAL_UNKNOWN")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        if os.name != "nt":
            raise


def fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        if os.name != "nt":
            raise


def setup_binding(contract_sha: str, source_commit: str, source_tree: str, run_id: str, run_attempt: int, lane: str, contract: dict[str, object]) -> dict[str, object]:
    need(HEX64.fullmatch(contract_sha) is not None, "SOURCE_MISMATCH")
    need(HEX40.fullmatch(source_commit) is not None and HEX40.fullmatch(source_tree) is not None, "SOURCE_MISMATCH")
    need(type(run_id) is str and run_id.isascii() and run_id.isdigit() and 1 <= len(run_id) <= 32, "INTERNAL_UNKNOWN")
    strict_int(run_attempt, 1, 1000)
    need(lane in contract["lanes"], "TEST_SET_MISMATCH")
    return {
        "contractSHA256": contract_sha,
        "lane": lane,
        "runAttempt": run_attempt,
        "runId": run_id,
        "schema": "chengwang.capacity-fixture-b-setup-journal/v1",
        "sourceCommit": source_commit,
        "sourceTree": source_tree,
    }


def path_uid(path: Path) -> int:
    value = getattr(path.lstat(), "st_uid", 0)
    need(type(value) is int and value >= 0, "INTERNAL_UNKNOWN")
    return value


def trusted_path(path: Path, trusted_owner_uid: int, directory: bool) -> os.stat_result:
    need(type(trusted_owner_uid) is int and 0 <= trusted_owner_uid <= (1 << 31) - 1 and trusted_owner_uid != PRIVATE_UID, "INTERNAL_UNKNOWN")
    need(path.exists() and not path.is_symlink(), "INTERNAL_UNKNOWN")
    meta = path.lstat()
    need((stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode)), "INTERNAL_UNKNOWN")
    if not directory:
        need(meta.st_nlink == 1, "INTERNAL_UNKNOWN")
    need(path_uid(path) in {0, trusted_owner_uid} and path_uid(path) != PRIVATE_UID, "INTERNAL_UNKNOWN")
    if os.name != "nt":
        need(meta.st_mode & 0o022 == 0, "INTERNAL_UNKNOWN")
    return meta


def setup_init(journal: Path, binding: dict[str, object], trusted_owner_uid: int) -> None:
    parent = journal.parent
    need(parent.is_dir() and not parent.is_symlink(), "INTERNAL_UNKNOWN")
    need(not journal.exists() and not journal.is_symlink(), "INTERNAL_UNKNOWN")
    os.mkdir(journal, 0o700)
    os.chmod(journal, 0o700)
    trusted_path(journal, trusted_owner_uid, True)
    write_new(journal / "meta.json", canonical(binding), 16 << 10)
    fsync_directory(parent)


def setup_event_value(binding: dict[str, object], ordinal: int, phase: str, status: str, command_exit_status: int | None) -> dict[str, object]:
    need(phase in SETUP_PHASES and status in SETUP_STATUSES, "INTERNAL_UNKNOWN")
    strict_int(ordinal, 0, len(SETUP_PHASES) * 2)
    if status == "ENTERED":
        need(command_exit_status is None, "INTERNAL_UNKNOWN")
    elif status == "FAIL":
        strict_int(command_exit_status, 1, 255)
    else:
        strict_int(command_exit_status, 0, 255)
        if phase not in {"GO_ENV_COMMAND", "GO_INVOKE"}:
            need(command_exit_status == 0, "INTERNAL_UNKNOWN")
    return {
        "commandExitStatus": command_exit_status,
        "contractSHA256": binding["contractSHA256"],
        "lane": binding["lane"],
        "ordinal": ordinal,
        "phase": phase,
        "runAttempt": binding["runAttempt"],
        "runId": binding["runId"],
        "schema": "chengwang.capacity-fixture-b-setup-event/v1",
        "sourceCommit": binding["sourceCommit"],
        "sourceTree": binding["sourceTree"],
        "status": status,
    }


def verify_setup_event(raw: bytes, binding: dict[str, object], ordinal: int) -> dict[str, object]:
    value = exact_keys(decode_json(raw), ("commandExitStatus", "contractSHA256", "lane", "ordinal", "phase", "runAttempt", "runId", "schema", "sourceCommit", "sourceTree", "status"), "INTERNAL_UNKNOWN")
    need(raw == canonical(value) and value["schema"] == "chengwang.capacity-fixture-b-setup-event/v1", "INTERNAL_UNKNOWN")
    expected = setup_event_value(binding, ordinal, str(value["phase"]), str(value["status"]), value["commandExitStatus"])  # type: ignore[arg-type]
    need(value == expected, "INTERNAL_UNKNOWN")
    return value


def validate_setup_sequence(events: list[dict[str, object]]) -> tuple[int, str | None, bool]:
    next_phase = 0
    active: str | None = None
    failed = False
    for event in events:
        need(not failed, "INTERNAL_UNKNOWN")
        phase = str(event["phase"])
        status = str(event["status"])
        if status == "ENTERED":
            need(active is None and next_phase < len(SETUP_PHASES) and phase == SETUP_PHASES[next_phase], "INTERNAL_UNKNOWN")
            active = phase
        else:
            need(active == phase, "INTERNAL_UNKNOWN")
            active = None
            if status == "FAIL":
                failed = True
            else:
                next_phase += 1
    return next_phase, active, failed


def read_setup_journal(journal: Path, expected_binding: dict[str, object], trusted_owner_uid: int) -> tuple[list[dict[str, object]], bytes, int, str | None, bool]:
    trusted_path(journal, trusted_owner_uid, True)
    entries = sorted(journal.iterdir(), key=lambda item: item.name.encode())
    meta_path = journal / "meta.json"
    need(meta_path in entries, "INTERNAL_UNKNOWN")
    trusted_path(meta_path, trusted_owner_uid, False)
    meta_raw = safe_read(meta_path, 16 << 10)
    meta = exact_keys(decode_json(meta_raw), ("contractSHA256", "lane", "runAttempt", "runId", "schema", "sourceCommit", "sourceTree"), "INTERNAL_UNKNOWN")
    need(meta_raw == canonical(meta) and meta == expected_binding, "INTERNAL_UNKNOWN")
    events: list[dict[str, object]] = []
    event_raws: list[bytes] = []
    event_paths = [path for path in entries if path != meta_path]
    for ordinal, path in enumerate(event_paths):
        need(path.name == f"event-{ordinal:04d}.json", "INTERNAL_UNKNOWN")
        trusted_path(path, trusted_owner_uid, False)
        raw = safe_read(path, 16 << 10)
        events.append(verify_setup_event(raw, expected_binding, ordinal))
        event_raws.append(raw)
    next_phase, active, failed = validate_setup_sequence(events)
    return events, b"".join(event_raws), next_phase, active, failed


def setup_append_event(journal: Path, binding: dict[str, object], trusted_owner_uid: int, phase: str, status: str, command_exit_status: int | None) -> dict[str, object]:
    events, _, _, _, _ = read_setup_journal(journal, binding, trusted_owner_uid)
    value = setup_event_value(binding, len(events), phase, status, command_exit_status)
    validate_setup_sequence([*events, value])
    write_new(journal / f"event-{len(events):04d}.json", canonical(value), 16 << 10)
    return value


def setup_flags(events: list[dict[str, object]]) -> dict[str, bool]:
    completed = {(str(event["phase"]), str(event["status"])) for event in events}
    entered = {str(event["phase"]) for event in events if event["status"] == "ENTERED"}
    return {
        "formatGatePassed": ("FORMAT_GATE", "PASS") in completed,
        "goEnvExitObserved": ("GO_ENV_COMMAND", "PASS") in completed,
        "goEnvExitZero": ("GO_ENV_EXIT", "PASS") in completed,
        "goEnvInvoked": "GO_ENV_COMMAND" in entered,
        "goEnvStderrEmpty": ("GO_ENV_STDERR_EMPTY", "PASS") in completed,
        "goExitObserved": ("GO_INVOKE", "PASS") in completed,
        "goInvoked": "GO_INVOKE" in entered,
        "oracleValidationPassed": ("ORACLE_VALIDATE", "PASS") in completed,
        "toolchainWritten": ("TOOLCHAIN_WRITER", "PASS") in completed,
    }


def observed_setup_exit(events: list[dict[str, object]], phase: str) -> int | None:
    for event in events:
        if event["phase"] == phase and event["status"] == "PASS":
            value = event["commandExitStatus"]
            strict_int(value, 0, 255)
            return value  # type: ignore[return-value]
    return None


def setup_finalize(journal: Path, binding: dict[str, object], trusted_owner_uid: int, host_exit_status: int) -> dict[str, object]:
    strict_int(host_exit_status, 0, 255)
    events, journal_raw, next_phase, active, failed = read_setup_journal(journal, binding, trusted_owner_uid)
    flags = setup_flags(events)
    if not events:
        need(host_exit_status != 0, "INTERNAL_UNKNOWN")
        phase, status, phase_exit, namespace_entered = "HOST_EXECUTION", "FAIL", host_exit_status, False
    else:
        namespace_entered = True
        last = events[-1]
        phase, status, phase_exit = str(last["phase"]), str(last["status"]), last["commandExitStatus"]
        if host_exit_status == 0:
            need(not failed and active is None and next_phase == len(SETUP_PHASES), "INTERNAL_UNKNOWN")
            need(phase == "ORACLE_VALIDATE" and status == "PASS" and flags["oracleValidationPassed"], "INTERNAL_UNKNOWN")
        else:
            need(failed or active is not None, "INTERNAL_UNKNOWN")
            need(status in {"ENTERED", "FAIL"}, "INTERNAL_UNKNOWN")
    value = {
        "contractSHA256": binding["contractSHA256"],
        "diagnosticOnly": True,
        **flags,
        "goEnvExitStatus": observed_setup_exit(events, "GO_ENV_COMMAND"),
        "goProcessExitStatus": observed_setup_exit(events, "GO_INVOKE"),
        "hostExitStatus": host_exit_status,
        "hostStatus": "PASS" if host_exit_status == 0 else "FAIL",
        "journalEventCount": len(events),
        "journalSHA256": sha(journal_raw),
        "lane": binding["lane"],
        "namespaceEntered": namespace_entered,
        "oracleAcceptanceProven": False,
        "phase": phase,
        "phaseExitStatus": phase_exit,
        "runAttempt": binding["runAttempt"],
        "runId": binding["runId"],
        "schema": "chengwang.capacity-fixture-b-setup-status/v1",
        "sourceCommit": binding["sourceCommit"],
        "sourceTree": binding["sourceTree"],
        "status": status,
    }
    verify_setup_status(canonical(value), binding, False)
    return value


def verify_setup_status(raw: bytes, binding: dict[str, object], require_ready: bool) -> dict[str, object]:
    keys = ("contractSHA256", "diagnosticOnly", "formatGatePassed", "goEnvExitObserved", "goEnvExitStatus", "goEnvExitZero", "goEnvInvoked", "goEnvStderrEmpty", "goExitObserved", "goInvoked", "goProcessExitStatus", "hostExitStatus", "hostStatus", "journalEventCount", "journalSHA256", "lane", "namespaceEntered", "oracleAcceptanceProven", "oracleValidationPassed", "phase", "phaseExitStatus", "runAttempt", "runId", "schema", "sourceCommit", "sourceTree", "status", "toolchainWritten")
    value = exact_keys(decode_json(raw), keys, "INTERNAL_UNKNOWN")
    need(raw == canonical(value) and value["schema"] == "chengwang.capacity-fixture-b-setup-status/v1", "INTERNAL_UNKNOWN")
    for key in ("contractSHA256", "lane", "runAttempt", "runId", "sourceCommit", "sourceTree"):
        need(value[key] == binding[key], "SOURCE_MISMATCH")
    need(value["diagnosticOnly"] is True and value["oracleAcceptanceProven"] is False, "INTERNAL_UNKNOWN")
    for key in ("formatGatePassed", "goEnvExitObserved", "goEnvExitZero", "goEnvInvoked", "goEnvStderrEmpty", "goExitObserved", "goInvoked", "namespaceEntered", "oracleValidationPassed", "toolchainWritten"):
        need(type(value[key]) is bool, "INTERNAL_UNKNOWN")
    strict_int(value["hostExitStatus"], 0, 255)
    strict_int(value["journalEventCount"], 0, len(SETUP_PHASES) * 2)
    for key in ("goEnvExitStatus", "goProcessExitStatus"):
        if value[key] is not None:
            strict_int(value[key], 0, 255)
    need(HEX64.fullmatch(str(value["journalSHA256"])) is not None, "INTERNAL_UNKNOWN")
    need(value["hostStatus"] == ("PASS" if value["hostExitStatus"] == 0 else "FAIL"), "INTERNAL_UNKNOWN")
    need(value["phase"] == "HOST_EXECUTION" or value["phase"] in SETUP_PHASES, "INTERNAL_UNKNOWN")
    need(value["status"] in SETUP_STATUSES, "INTERNAL_UNKNOWN")
    if value["status"] == "ENTERED":
        need(value["phaseExitStatus"] is None, "INTERNAL_UNKNOWN")
    elif value["status"] == "FAIL":
        strict_int(value["phaseExitStatus"], 1, 255)
    else:
        strict_int(value["phaseExitStatus"], 0, 255)
    need(not value["goEnvExitObserved"] or value["goEnvInvoked"], "INTERNAL_UNKNOWN")
    need(value["goEnvExitObserved"] is (value["goEnvExitStatus"] is not None), "INTERNAL_UNKNOWN")
    need(not value["goEnvExitZero"] or value["goEnvExitObserved"], "INTERNAL_UNKNOWN")
    need(not value["goEnvStderrEmpty"] or value["goEnvExitZero"], "INTERNAL_UNKNOWN")
    need(not value["toolchainWritten"] or value["goEnvStderrEmpty"], "INTERNAL_UNKNOWN")
    need(not value["formatGatePassed"] or value["toolchainWritten"], "INTERNAL_UNKNOWN")
    need(not value["goInvoked"] or value["formatGatePassed"], "INTERNAL_UNKNOWN")
    need(not value["goExitObserved"] or value["goInvoked"], "INTERNAL_UNKNOWN")
    need(value["goExitObserved"] is (value["goProcessExitStatus"] is not None), "INTERNAL_UNKNOWN")
    need(not value["oracleValidationPassed"] or value["goExitObserved"], "INTERNAL_UNKNOWN")
    if not value["namespaceEntered"]:
        need(value["phase"] == "HOST_EXECUTION" and value["status"] == "FAIL" and value["hostExitStatus"] != 0, "INTERNAL_UNKNOWN")
        need(value["journalEventCount"] == 0 and value["journalSHA256"] == sha(b""), "INTERNAL_UNKNOWN")
    else:
        need(value["journalEventCount"] > 0, "INTERNAL_UNKNOWN")
    if value["hostStatus"] == "PASS":
        need(value["namespaceEntered"] is True and value["phase"] == "ORACLE_VALIDATE" and value["status"] == "PASS" and value["oracleValidationPassed"] is True, "INTERNAL_UNKNOWN")
    else:
        need(value["status"] in {"ENTERED", "FAIL"}, "INTERNAL_UNKNOWN")
    if require_ready:
        need(value["hostStatus"] == "PASS" and value["phase"] == "ORACLE_VALIDATE" and value["status"] == "PASS", "INTERNAL_UNKNOWN")
        need(value["oracleValidationPassed"] is True, "INTERNAL_UNKNOWN")
    return value


def load_contract(path: Path, expected_sha: str) -> tuple[dict[str, object], bytes]:
    need(HEX64.fullmatch(expected_sha) is not None, "SOURCE_MISMATCH")
    raw = safe_read(path, 1 << 20)
    need(sha(raw) == expected_sha, "SOURCE_MISMATCH")
    value = exact_keys(
        decode_json(raw),
        (
            "authoringBase", "commands", "eventPackage", "fullSubtests", "lanes", "limits",
            "moduleWorkingDirectory", "requiredTop", "schema", "scope", "setupPhases",
            "setupStatuses", "sourceFiles", "toolchain",
        ),
        "SOURCE_MISMATCH",
    )
    need(raw == canonical(value), "SOURCE_MISMATCH")
    need(value["schema"] == "chengwang.capacity-fixture-b-oracle-contract/v3", "SOURCE_MISMATCH")
    need(value["scope"] == "isolated-fixture-b-synthetic-model-not-full-suite", "SOURCE_MISMATCH")
    need(value["moduleWorkingDirectory"] == "chengwang", "SOURCE_MISMATCH")
    base = exact_keys(value["authoringBase"], ("commit", "tree"), "SOURCE_MISMATCH")
    need(HEX40.fullmatch(str(base["commit"])) is not None and HEX40.fullmatch(str(base["tree"])) is not None, "SOURCE_MISMATCH")
    lanes = value["lanes"]
    need(lanes == ["ordinary", "race"], "SOURCE_MISMATCH")
    top = value["requiredTop"]
    need(type(top) is str and TEST_NAME.fullmatch(top) is not None and "/" not in top, "SOURCE_MISMATCH")
    children = value["fullSubtests"]
    need(type(children) is list and len(children) == 5 and len(set(children)) == 5, "SOURCE_MISMATCH")
    need(all(type(item) is str and TEST_NAME.fullmatch(item) is not None and item.startswith(top + "/") for item in children), "SOURCE_MISMATCH")
    need(value["eventPackage"] == "chengwang/internal/mihomodeploy", "SOURCE_MISMATCH")
    need(value["setupPhases"] == list(SETUP_PHASES), "SOURCE_MISMATCH")
    need(value["setupStatuses"] == list(SETUP_STATUSES), "SOURCE_MISMATCH")
    commands = value["commands"]
    need(type(commands) is dict and tuple(commands) == ("ordinary", "race"), "SOURCE_MISMATCH")
    ordinary = ["go", "test", "-json", "-mod=vendor", "-count=1", "-p=1", "-shuffle=off", "-timeout=180s", "-run", "^" + top + "$", "./internal/mihomodeploy"]
    race = ordinary[:2] + ["-race"] + ordinary[2:]
    need(commands == {"ordinary": ordinary, "race": race}, "SOURCE_MISMATCH")
    limits = exact_keys(value["limits"], ("eventCount", "eventsBytes", "gofmtPatchBytes", "jsonLineBytes", "publicSummaryBytes", "stderrBytes"), "SOURCE_MISMATCH")
    need(strict_int(limits["eventCount"], 1, 100000) == 20000, "SOURCE_MISMATCH")
    need(strict_int(limits["eventsBytes"], 1) == 64 << 20, "SOURCE_MISMATCH")
    need(strict_int(limits["gofmtPatchBytes"], 1) == 1 << 20, "SOURCE_MISMATCH")
    need(strict_int(limits["jsonLineBytes"], 1) == 1 << 20, "SOURCE_MISMATCH")
    need(strict_int(limits["publicSummaryBytes"], 1) == 16 << 10, "SOURCE_MISMATCH")
    need(strict_int(limits["stderrBytes"], 1) == 1 << 20, "SOURCE_MISMATCH")
    sources = value["sourceFiles"]
    need(type(sources) is list and len(sources) == 1, "SOURCE_MISMATCH")
    source = exact_keys(sources[0], ("bytes", "gitBlobSHA1", "path", "sha256"), "SOURCE_MISMATCH")
    need(source["path"] == "chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go", "SOURCE_MISMATCH")
    need(source["bytes"] == 31111 and source["gitBlobSHA1"] == "fb11ac12b551d8428d9a68f515a48d84031d270a", "SOURCE_MISMATCH")
    need(source["sha256"] == "fab19f1ca714105f5002d31e2e37ca4cdb0296c5133431951ac81a1576056bc4", "SOURCE_MISMATCH")
    toolchain = exact_keys(value["toolchain"], ("cgoEnabled", "compiler", "goEnvPolicy", "goVersion", "goWork", "goarch", "goos", "offline", "packageParallelism", "shuffle", "timeoutSeconds", "vendor"), "SOURCE_MISMATCH")
    need(toolchain == {"cgoEnabled": True, "compiler": "gc", "goEnvPolicy": GOENV_POLICY, "goVersion": "go1.23.12", "goarch": "amd64", "goos": "linux", "goWork": "off", "offline": True, "packageParallelism": 1, "shuffle": "off", "timeoutSeconds": 180, "vendor": True}, "SOURCE_MISMATCH")
    return value, raw


def git(repo: Path, *args: str, maximum: int = 128 << 20) -> bytes:
    env = os.environ.copy()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=env,
        timeout=30,
        check=False,
    )
    need(result.returncode == 0 and len(result.stdout) <= maximum and len(result.stderr) <= 1 << 20, "SOURCE_MISMATCH")
    return result.stdout


def source_snapshot(repo: Path, commit: str, contract: dict[str, object], contract_sha: str) -> dict[str, object]:
    need(HEX40.fullmatch(commit) is not None and repo.is_dir(), "SOURCE_MISMATCH")
    head = git(repo, "rev-parse", "HEAD").strip().decode("ascii")
    need(head == commit, "SOURCE_MISMATCH")
    tree = git(repo, "rev-parse", commit + "^{tree}").strip().decode("ascii")
    need(HEX40.fullmatch(tree) is not None, "SOURCE_MISMATCH")
    need(git(repo, "status", "--porcelain", "--untracked-files=all") == b"", "SOURCE_MISMATCH")
    rows: list[dict[str, object]] = []
    for item in contract["sourceFiles"]:  # type: ignore[index]
        source = item  # type: ignore[assignment]
        relative = source["path"]  # type: ignore[index]
        pure = PurePosixPath(relative)
        need(not pure.is_absolute() and ".." not in pure.parts, "SOURCE_MISMATCH")
        raw = safe_read(repo / relative, 16 << 20)
        need(len(raw) == source["bytes"] and sha(raw) == source["sha256"], "SOURCE_MISMATCH")  # type: ignore[index]
        entry = git(repo, "ls-tree", commit, "--", relative).decode("utf-8").strip()
        match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t(.+)", entry)
        need(match is not None and match.group(1) == source["gitBlobSHA1"] and match.group(2) == relative, "SOURCE_MISMATCH")  # type: ignore[index]
        rows.append({"bytes": len(raw), "gitBlobSHA1": match.group(1), "path": relative, "sha256": sha(raw)})
    return {
        "contractSHA256": contract_sha,
        "schema": "chengwang.capacity-fixture-b-source/v1",
        "sourceCommit": commit,
        "sourceFiles": rows,
        "sourceGitVerified": True,
        "sourceTree": tree,
        "worktreeClean": True,
    }


def verify_source(raw: bytes, contract: dict[str, object], contract_sha: str) -> dict[str, object]:
    value = exact_keys(decode_json(raw), ("contractSHA256", "schema", "sourceCommit", "sourceFiles", "sourceGitVerified", "sourceTree", "worktreeClean"), "SOURCE_MISMATCH")
    need(raw == canonical(value), "SOURCE_MISMATCH")
    need(value["schema"] == "chengwang.capacity-fixture-b-source/v1" and value["contractSHA256"] == contract_sha, "SOURCE_MISMATCH")
    need(HEX40.fullmatch(str(value["sourceCommit"])) is not None and HEX40.fullmatch(str(value["sourceTree"])) is not None, "SOURCE_MISMATCH")
    need(value["sourceGitVerified"] is True and value["worktreeClean"] is True, "SOURCE_MISMATCH")
    expected = contract["sourceFiles"]
    need(value["sourceFiles"] == expected, "SOURCE_MISMATCH")
    return value


def toolchain_report(raw: bytes, contract_sha: str) -> dict[str, object]:
    value = exact_keys(decode_json(raw), ("CGO_ENABLED", "GOARCH", "GOENV", "GOFLAGS", "GOOS", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOVERSION", "GOWORK"), "TOOLCHAIN_MISMATCH")
    # Go 1.23.12 reports an empty GOENV config-file path when the pinned
    # operating-system policy is GOENV=off. GOWORK keeps its literal "off".
    expected = {"CGO_ENABLED": "1", "GOARCH": "amd64", "GOENV": "", "GOFLAGS": "-mod=vendor", "GOOS": "linux", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOVERSION": "go1.23.12", "GOWORK": "off"}
    need(value == expected, "TOOLCHAIN_MISMATCH")
    return {
        "accepted": True,
        "cgoEnabled": True,
        "compiler": "gc",
        "contractSHA256": contract_sha,
        "goVersion": "go1.23.12",
        "goarch": "amd64",
        # This is the contract-pinned persistence policy, not the raw GOENV
        # config-file path observed above.
        "goenv": GOENV_POLICY,
        "goflags": "-mod=vendor",
        "goos": "linux",
        "goproxy": "off",
        "gosumdb": "off",
        "gotoolchain": "local",
        "gowork": "off",
        "schema": "chengwang.capacity-fixture-b-toolchain/v1",
    }


def verify_toolchain(raw: bytes, contract_sha: str) -> dict[str, object]:
    value = exact_keys(decode_json(raw), ("accepted", "cgoEnabled", "compiler", "contractSHA256", "goVersion", "goarch", "goenv", "goflags", "goos", "goproxy", "gosumdb", "gotoolchain", "gowork", "schema"), "TOOLCHAIN_MISMATCH")
    need(raw == canonical(value), "TOOLCHAIN_MISMATCH")
    need(value == toolchain_report(canonical({"CGO_ENABLED": "1", "GOARCH": "amd64", "GOENV": "", "GOFLAGS": "-mod=vendor", "GOOS": "linux", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOVERSION": "go1.23.12", "GOWORK": "off"}), contract_sha), "TOOLCHAIN_MISMATCH")
    return value


def format_report(patch: bytes, stderr: bytes, exit_code: int, contract_sha: str) -> dict[str, object]:
    accepted = exit_code == 0 and not patch and not stderr
    return {
        "accepted": accepted,
        "contractSHA256": contract_sha,
        "exit": exit_code,
        "patchBytes": len(patch),
        "patchSHA256": sha(patch),
        "schema": "chengwang.capacity-fixture-b-format/v1",
        "stderrBytes": len(stderr),
        "stderrSHA256": sha(stderr),
        "tool": "gofmt-go1.23.12",
    }


def verify_format(raw: bytes, contract_sha: str, require_accepted: bool = True) -> dict[str, object]:
    value = exact_keys(decode_json(raw), ("accepted", "contractSHA256", "exit", "patchBytes", "patchSHA256", "schema", "stderrBytes", "stderrSHA256", "tool"), "FORMAT_REJECTED")
    need(raw == canonical(value), "FORMAT_REJECTED")
    need(value["schema"] == "chengwang.capacity-fixture-b-format/v1" and value["contractSHA256"] == contract_sha and value["tool"] == "gofmt-go1.23.12", "FORMAT_REJECTED")
    need(type(value["accepted"]) is bool and type(value["exit"]) is int, "FORMAT_REJECTED")
    for field in ("patchBytes", "stderrBytes"):
        strict_int(value[field], 0, 1 << 20)
    need(HEX64.fullmatch(str(value["patchSHA256"])) is not None and HEX64.fullmatch(str(value["stderrSHA256"])) is not None, "FORMAT_REJECTED")
    computed = value["exit"] == 0 and value["patchBytes"] == 0 and value["stderrBytes"] == 0
    need(value["accepted"] is computed, "FORMAT_REJECTED")
    if require_accepted:
        need(computed, "FORMAT_REJECTED")
    return value


def failure_summary(contract: dict[str, object], contract_sha: str, lane: str, commit: str, tree: str, code: str, actual_go: bool = False) -> dict[str, object]:
    need(lane in contract["lanes"] and HEX40.fullmatch(commit) is not None and HEX40.fullmatch(tree) is not None, "INTERNAL_UNKNOWN")
    return {
        "accepted": False,
        "actualGoExecutionProven": actual_go,
        "businessRuntimeProven": False,
        "contractSHA256": contract_sha,
        "expectedFailureCount": 0,
        "failCount": 0,
        "failureCode": code if code in FAILURE_CODES else "INTERNAL_UNKNOWN",
        "fixtureDataSynthetic": True,
        "lane": lane,
        "outputEventCount": 0,
        "package": contract["eventPackage"],
        "packagePassCount": 0,
        "processExit": -1,
        "productionProven": False,
        "schema": "chengwang.capacity-fixture-b-result/v1",
        "skipCount": 0,
        "sourceCommit": commit,
        "sourceTree": tree,
        "streamClosure": "UNKNOWN",
        "subtests": contract["fullSubtests"],
        "subtestsPassCount": 0,
        "top": contract["requiredTop"],
        "topPassCount": 0,
        "unknownCount": 0,
        "wholeSuiteProven": False,
    }


def verify_events(events_raw: bytes, stderr: bytes, go_exit: int, contract: dict[str, object], contract_sha: str, lane: str, commit: str, tree: str) -> dict[str, object]:
    limits = contract["limits"]
    need(len(events_raw) > 0 and len(events_raw) <= limits["eventsBytes"] and events_raw.endswith(b"\n"), "STREAM_INCOMPLETE")  # type: ignore[index]
    need(len(stderr) <= limits["stderrBytes"], "STDERR_NONEMPTY")  # type: ignore[index]
    need(not stderr, "STDERR_NONEMPTY")
    need(go_exit == 0, "PROCESS_NONZERO")
    package = contract["eventPackage"]
    top = contract["requiredTop"]
    children = contract["fullSubtests"]
    expected_tests = [top, *children]
    package_started = False
    package_pass = False
    open_tests: set[str] = set()
    runs: list[str] = []
    passes: list[str] = []
    output_count = 0
    lines = events_raw.splitlines()
    need(0 < len(lines) <= limits["eventCount"], "STREAM_INCOMPLETE")  # type: ignore[index]
    for line in lines:
        need(0 < len(line) <= limits["jsonLineBytes"], "STREAM_INCOMPLETE")  # type: ignore[index]
        try:
            event = decode_json(line)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise GateError("STREAM_INCOMPLETE") from exc
        need(type(event) is dict and set(event).issubset(ALLOWED_EVENT_KEYS), "TEST_STATE_REJECTED")
        need(type(event.get("Action")) is str and event["Action"] in ALLOWED_ACTIONS, "TEST_STATE_REJECTED")
        need(event.get("Package") == package, "PACKAGE_REJECTED")
        for field in ("Time", "Output", "FailedBuild"):
            if field in event:
                need(type(event[field]) is str, "TEST_STATE_REJECTED")
        if "Elapsed" in event:
            elapsed = event["Elapsed"]
            need(type(elapsed) in (int, float) and not isinstance(elapsed, bool) and math.isfinite(elapsed) and elapsed >= 0, "TEST_STATE_REJECTED")
        action = event["Action"]
        test = event.get("Test", "")
        need(type(test) is str, "TEST_STATE_REJECTED")
        if action == "output":
            need("Output" in event and package_started and not package_pass, "TEST_STATE_REJECTED")
            need(test == "" or test in open_tests, "TEST_STATE_REJECTED")
            output_count += 1
            continue
        need("Output" not in event and "FailedBuild" not in event, "TEST_STATE_REJECTED")
        if test == "":
            if action == "start":
                need(not package_started and not package_pass, "PACKAGE_REJECTED")
                package_started = True
                continue
            need(package_started and not package_pass, "PACKAGE_REJECTED")
            need(action == "pass", "PACKAGE_REJECTED")
            need(runs == expected_tests and passes == [*children, top] and not open_tests, "PACKAGE_REJECTED")
            package_pass = True
            continue
        need(package_started and not package_pass and test in expected_tests, "TEST_SET_MISMATCH")
        need(action not in {"fail", "skip", "pause", "cont", "start"}, "TEST_STATE_REJECTED")
        if action == "run":
            need(len(runs) < len(expected_tests) and test == expected_tests[len(runs)] and test not in open_tests and test not in passes, "TEST_STATE_REJECTED")
            if test != top:
                need(top in open_tests, "TEST_STATE_REJECTED")
            runs.append(test)
            open_tests.add(test)
        elif action == "pass":
            need(test in open_tests and test not in passes, "TEST_STATE_REJECTED")
            if test == top:
                need(passes == children and runs == expected_tests, "TEST_STATE_REJECTED")
            else:
                need(test == children[len(passes)] if len(passes) < len(children) else False, "TEST_STATE_REJECTED")
            open_tests.remove(test)
            passes.append(test)
        else:
            raise GateError("TEST_STATE_REJECTED")
    need(package_started and package_pass and runs == expected_tests and passes == [*children, top] and not open_tests, "STREAM_INCOMPLETE")
    return {
        "accepted": True,
        "actualGoExecutionProven": True,
        "businessRuntimeProven": False,
        "contractSHA256": contract_sha,
        "expectedFailureCount": 0,
        "failCount": 0,
        "failureCode": "NONE",
        "fixtureDataSynthetic": True,
        "lane": lane,
        "outputEventCount": output_count,
        "package": package,
        "packagePassCount": 1,
        "processExit": 0,
        "productionProven": False,
        "schema": "chengwang.capacity-fixture-b-result/v1",
        "skipCount": 0,
        "sourceCommit": commit,
        "sourceTree": tree,
        "streamClosure": "COMPLETE_EOF",
        "subtests": children,
        "subtestsPassCount": 5,
        "top": top,
        "topPassCount": 1,
        "unknownCount": 0,
        "wholeSuiteProven": False,
    }


def verify_result(raw: bytes, contract: dict[str, object], contract_sha: str, require_accepted: bool) -> dict[str, object]:
    keys = ("accepted", "actualGoExecutionProven", "businessRuntimeProven", "contractSHA256", "expectedFailureCount", "failCount", "failureCode", "fixtureDataSynthetic", "lane", "outputEventCount", "package", "packagePassCount", "processExit", "productionProven", "schema", "skipCount", "sourceCommit", "sourceTree", "streamClosure", "subtests", "subtestsPassCount", "top", "topPassCount", "unknownCount", "wholeSuiteProven")
    value = exact_keys(decode_json(raw), keys, "INTERNAL_UNKNOWN")
    need(raw == canonical(value), "INTERNAL_UNKNOWN")
    need(value["schema"] == "chengwang.capacity-fixture-b-result/v1" and value["contractSHA256"] == contract_sha, "SOURCE_MISMATCH")
    need(value["lane"] in contract["lanes"] and value["package"] == contract["eventPackage"] and value["top"] == contract["requiredTop"] and value["subtests"] == contract["fullSubtests"], "TEST_SET_MISMATCH")
    need(HEX40.fullmatch(str(value["sourceCommit"])) is not None and HEX40.fullmatch(str(value["sourceTree"])) is not None, "SOURCE_MISMATCH")
    need(type(value["actualGoExecutionProven"]) is bool, "INTERNAL_UNKNOWN")
    need(value["fixtureDataSynthetic"] is True and value["businessRuntimeProven"] is False and value["productionProven"] is False and value["wholeSuiteProven"] is False, "INTERNAL_UNKNOWN")
    for field in ("expectedFailureCount", "failCount", "outputEventCount", "packagePassCount", "skipCount", "subtestsPassCount", "topPassCount", "unknownCount"):
        strict_int(value[field], 0, 20000)
    need(type(value["processExit"]) is int and type(value["accepted"]) is bool, "INTERNAL_UNKNOWN")
    if value["accepted"]:
        need(value["actualGoExecutionProven"] is True, "INTERNAL_UNKNOWN")
        need(value["failureCode"] == "NONE" and value["processExit"] == 0 and value["streamClosure"] == "COMPLETE_EOF", "INTERNAL_UNKNOWN")
        need(value["expectedFailureCount"] == value["failCount"] == value["skipCount"] == value["unknownCount"] == 0, "INTERNAL_UNKNOWN")
        need(value["packagePassCount"] == 1 and value["topPassCount"] == 1 and value["subtestsPassCount"] == 5, "INTERNAL_UNKNOWN")
    else:
        need(value["failureCode"] in FAILURE_CODES and value["streamClosure"] in {"UNKNOWN", "COMPLETE_EOF"}, "INTERNAL_UNKNOWN")
    if require_accepted:
        need(value["accepted"] is True, "INTERNAL_UNKNOWN")
    return value


def normalized_workflow(raw: bytes) -> bytes:
    text = raw.decode("utf-8")
    for name in PIN_NAMES:
        pattern = re.compile(r"(?m)^(  " + re.escape(name) + r": )([0-9a-f]{64})$")
        matches = list(pattern.finditer(text))
        need(len(matches) == 1, "SOURCE_MISMATCH")
        text = pattern.sub(r"\1<" + name + ">", text)
    return text.encode("utf-8")


def validate_workflow(repo: Path, pins: dict[str, str]) -> dict[str, object]:
    workflow = safe_read(repo / WORKFLOW_PATH, 1 << 20)
    need(sha(normalized_workflow(workflow)) == WORKFLOW_TEMPLATE_SHA256, "SOURCE_MISMATCH")
    text = workflow.decode("utf-8")
    need("branches: [codex/chengwang-unified-20261102]" in text and "workflow_dispatch" not in text, "SOURCE_MISMATCH")
    need(text.count("working-directory: chengwang") >= 2, "SOURCE_MISMATCH")
    forbidden = ("docker login", "ssh ", "scp ", "gh api", "curl ", "wget ", "GITHUB_TOKEN", "packages: write", "raw-events", "stderr.private")
    need(all(token not in text for token in forbidden), "SOURCE_MISMATCH")
    for name, value in pins.items():
        need(text.count(f"  {name}: {value}") == 1, "SOURCE_MISMATCH")
    file_map = {
        "CONTRACT_SHA256": f"{COMPONENT}/fixture_b_contract.json",
        "CHECKER_SHA256": f"{COMPONENT}/check_fixture_b.py",
        "MODEL_SHA256": f"{COMPONENT}/test_check_fixture_b.py",
        "RUNNER_SHA256": f"{COMPONENT}/run_fixture_b.sh",
    }
    for name, relative in file_map.items():
        need(sha(safe_read(repo / relative, 2 << 20)) == pins[name], "SOURCE_MISMATCH")
    return {"schema": "chengwang.capacity-fixture-b-workflow-source/v1", "accepted": True, "workflowTemplateSHA256": WORKFLOW_TEMPLATE_SHA256, "pins": pins}


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--contract", required=True)
    common.add_argument("--contract-sha256", required=True)

    source = sub.add_parser("source", parents=[common])
    source.add_argument("--repo", required=True)
    source.add_argument("--source-commit", required=True)
    source.add_argument("--out", required=True)

    toolchain = sub.add_parser("toolchain", parents=[common])
    toolchain.add_argument("--go-env", required=True)
    toolchain.add_argument("--out", required=True)

    fmt = sub.add_parser("format", parents=[common])
    fmt.add_argument("--patch", required=True)
    fmt.add_argument("--public-patch", required=True)
    fmt.add_argument("--stderr", required=True)
    fmt.add_argument("--exit", required=True, type=int)
    fmt.add_argument("--out", required=True)

    events = sub.add_parser("events", parents=[common])
    events.add_argument("--lane", required=True)
    events.add_argument("--source-before", required=True)
    events.add_argument("--toolchain", required=True)
    events.add_argument("--format-status", required=True)
    events.add_argument("--events", required=True)
    events.add_argument("--stderr", required=True)
    events.add_argument("--go-exit", required=True, type=int)
    events.add_argument("--out", required=True)

    report = sub.add_parser("report", parents=[common])
    report.add_argument("--source-before", required=True)
    report.add_argument("--source-after", required=True)
    report.add_argument("--setup-status", required=True)
    report.add_argument("--toolchain", required=True)
    report.add_argument("--format-status", required=True)
    report.add_argument("--summary", required=True)
    report.add_argument("--run-id", required=True)
    report.add_argument("--run-attempt", required=True, type=int)

    fallback = sub.add_parser("fallback", parents=[common])
    fallback.add_argument("--lane", required=True)
    fallback.add_argument("--source-commit", required=True)
    fallback.add_argument("--source-tree", required=True)
    fallback.add_argument("--out", required=True)

    pair = sub.add_parser("pair", parents=[common])
    pair.add_argument("--ordinary", required=True)
    pair.add_argument("--race", required=True)
    pair.add_argument("--ordinary-setup-status", required=True)
    pair.add_argument("--race-setup-status", required=True)
    pair.add_argument("--run-id", required=True)
    pair.add_argument("--run-attempt", required=True, type=int)
    pair.add_argument("--out", required=True)

    setup_parsers = {}
    for name in ("setup-init", "setup-event", "setup-finalize", "setup-check"):
        setup_parser = sub.add_parser(name, parents=[common])
        setup_parser.add_argument("--journal", required=name != "setup-check")
        setup_parser.add_argument("--source-commit", required=True)
        setup_parser.add_argument("--source-tree", required=True)
        setup_parser.add_argument("--run-id", required=True)
        setup_parser.add_argument("--run-attempt", required=True, type=int)
        setup_parser.add_argument("--lane", required=True)
        if name != "setup-check":
            setup_parser.add_argument("--trusted-owner-uid", required=True, type=int)
        setup_parsers[name] = setup_parser
    setup_parsers["setup-event"].add_argument("--phase", required=True)
    setup_parsers["setup-event"].add_argument("--status", required=True)
    setup_parsers["setup-event"].add_argument("--command-exit-status", type=int)
    setup_parsers["setup-finalize"].add_argument("--host-exit-status", required=True, type=int)
    setup_parsers["setup-finalize"].add_argument("--out", required=True)
    setup_parsers["setup-check"].add_argument("--setup-status", required=True)
    setup_parsers["setup-check"].add_argument("--require-ready", action="store_true")

    workflow = sub.add_parser("workflow")
    workflow.add_argument("--repo", required=True)
    for name in PIN_NAMES:
        workflow.add_argument("--" + name.lower().replace("_", "-"), required=True)

    args = parser.parse_args()
    if args.command == "workflow":
        pins = {name: getattr(args, name.lower()) for name in PIN_NAMES}
        need(all(HEX64.fullmatch(value) is not None for value in pins.values()), "SOURCE_MISMATCH")
        print(canonical(validate_workflow(Path(args.repo).resolve(), pins)).decode("ascii"), end="")
        return

    contract, _ = load_contract(Path(args.contract), args.contract_sha256)
    limits = contract["limits"]
    if args.command.startswith("setup-"):
        binding = setup_binding(args.contract_sha256, args.source_commit, args.source_tree, args.run_id, args.run_attempt, args.lane, contract)
        if args.command == "setup-init":
            setup_init(Path(args.journal), binding, args.trusted_owner_uid)
        elif args.command == "setup-event":
            setup_append_event(Path(args.journal), binding, args.trusted_owner_uid, args.phase, args.status, args.command_exit_status)
        elif args.command == "setup-finalize":
            value = setup_finalize(Path(args.journal), binding, args.trusted_owner_uid, args.host_exit_status)
            write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
        else:
            value = verify_setup_status(safe_read(Path(args.setup_status), limits["publicSummaryBytes"]), binding, args.require_ready)  # type: ignore[index]
            print(canonical({"diagnosticOnly": True, "phase": value["phase"], "schema": "chengwang.capacity-fixture-b-setup-check/v1", "status": value["status"]}).decode("ascii"), end="")
    elif args.command == "source":
        value = source_snapshot(Path(args.repo).resolve(), args.source_commit, contract, args.contract_sha256)
        write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
    elif args.command == "toolchain":
        raw = safe_read(Path(args.go_env), 1 << 20)
        value = toolchain_report(raw, args.contract_sha256)
        write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
    elif args.command == "format":
        patch_raw = safe_read(Path(args.patch), limits["gofmtPatchBytes"])  # type: ignore[index]
        stderr_raw = safe_read(Path(args.stderr), limits["stderrBytes"])  # type: ignore[index]
        write_new(Path(args.public_patch), patch_raw, limits["gofmtPatchBytes"])  # type: ignore[index]
        value = format_report(patch_raw, stderr_raw, args.exit, args.contract_sha256)
        write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
        need(value["accepted"] is True, "FORMAT_REJECTED")
    elif args.command == "events":
        source_value = verify_source(safe_read(Path(args.source_before), limits["publicSummaryBytes"]), contract, args.contract_sha256)  # type: ignore[index]
        verify_toolchain(safe_read(Path(args.toolchain), limits["publicSummaryBytes"]), args.contract_sha256)  # type: ignore[index]
        verify_format(safe_read(Path(args.format_status), limits["publicSummaryBytes"]), args.contract_sha256)  # type: ignore[index]
        try:
            value = verify_events(
                safe_read(Path(args.events), limits["eventsBytes"]),  # type: ignore[index]
                safe_read(Path(args.stderr), limits["stderrBytes"]),  # type: ignore[index]
                args.go_exit, contract, args.contract_sha256, args.lane,
                source_value["sourceCommit"], source_value["sourceTree"],  # type: ignore[arg-type]
            )
        except GateError as exc:
            value = failure_summary(contract, args.contract_sha256, args.lane, source_value["sourceCommit"], source_value["sourceTree"], exc.code, True)  # type: ignore[arg-type]
            if exc.code == "STREAM_INCOMPLETE":
                value["streamClosure"] = "UNKNOWN"
            write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
            raise
        write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
    elif args.command == "report":
        before_raw = safe_read(Path(args.source_before), limits["publicSummaryBytes"])  # type: ignore[index]
        after_raw = safe_read(Path(args.source_after), limits["publicSummaryBytes"])  # type: ignore[index]
        need(before_raw == after_raw, "SOURCE_MISMATCH")
        source_value = verify_source(before_raw, contract, args.contract_sha256)
        summary_raw = safe_read(Path(args.summary), limits["publicSummaryBytes"])  # type: ignore[index]
        preview = verify_result(summary_raw, contract, args.contract_sha256, False)
        need(preview["sourceCommit"] == source_value["sourceCommit"] and preview["sourceTree"] == source_value["sourceTree"], "SOURCE_MISMATCH")
        binding = setup_binding(args.contract_sha256, preview["sourceCommit"], preview["sourceTree"], args.run_id, args.run_attempt, preview["lane"], contract)  # type: ignore[arg-type]
        verify_setup_status(safe_read(Path(args.setup_status), limits["publicSummaryBytes"]), binding, False)  # type: ignore[index]
        verify_toolchain(safe_read(Path(args.toolchain), limits["publicSummaryBytes"]), args.contract_sha256)  # type: ignore[index]
        verify_format(safe_read(Path(args.format_status), limits["publicSummaryBytes"]), args.contract_sha256)  # type: ignore[index]
        result = verify_result(summary_raw, contract, args.contract_sha256, True)
        need(result["sourceCommit"] == source_value["sourceCommit"] and result["sourceTree"] == source_value["sourceTree"], "SOURCE_MISMATCH")
        binding = setup_binding(args.contract_sha256, result["sourceCommit"], result["sourceTree"], args.run_id, args.run_attempt, result["lane"], contract)  # type: ignore[arg-type]
        verify_setup_status(safe_read(Path(args.setup_status), limits["publicSummaryBytes"]), binding, True)  # type: ignore[index]
        print(canonical({"accepted": True, "lane": result["lane"], "schema": "chengwang.capacity-fixture-b-report-check/v1"}).decode("ascii"), end="")
    elif args.command == "fallback":
        value = failure_summary(contract, args.contract_sha256, args.lane, args.source_commit, args.source_tree, "INTERNAL_UNKNOWN")
        write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]
        raise GateError("INTERNAL_UNKNOWN")
    elif args.command == "pair":
        ordinary = verify_result(safe_read(Path(args.ordinary), limits["publicSummaryBytes"]), contract, args.contract_sha256, True)  # type: ignore[index]
        race = verify_result(safe_read(Path(args.race), limits["publicSummaryBytes"]), contract, args.contract_sha256, True)  # type: ignore[index]
        need(ordinary["lane"] == "ordinary" and race["lane"] == "race", "TEST_SET_MISMATCH")
        need(ordinary["sourceCommit"] == race["sourceCommit"] and ordinary["sourceTree"] == race["sourceTree"], "SOURCE_MISMATCH")
        ordinary_binding = setup_binding(args.contract_sha256, ordinary["sourceCommit"], ordinary["sourceTree"], args.run_id, args.run_attempt, "ordinary", contract)  # type: ignore[arg-type]
        race_binding = setup_binding(args.contract_sha256, race["sourceCommit"], race["sourceTree"], args.run_id, args.run_attempt, "race", contract)  # type: ignore[arg-type]
        verify_setup_status(safe_read(Path(args.ordinary_setup_status), limits["publicSummaryBytes"]), ordinary_binding, True)  # type: ignore[index]
        verify_setup_status(safe_read(Path(args.race_setup_status), limits["publicSummaryBytes"]), race_binding, True)  # type: ignore[index]
        value = {"accepted": True, "contractSHA256": args.contract_sha256, "ordinarySummarySHA256": sha(canonical(ordinary)), "raceSummarySHA256": sha(canonical(race)), "schema": "chengwang.capacity-fixture-b-pair/v1", "sourceCommit": ordinary["sourceCommit"], "sourceTree": ordinary["sourceTree"], "wholeSuiteProven": False}
        write_new(Path(args.out), canonical(value), limits["publicSummaryBytes"])  # type: ignore[index]


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
