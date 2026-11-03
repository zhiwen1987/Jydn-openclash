from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


SCHEMA = "chengwang.joint-uid-probe-diagnostic/v2"
MAX_BYTES = 4096
NORMAL = ("root-setup", "uid-prepublish-denials", "root-finalize", "uid-final-read-and-rename", "uid-install-replacement", "root-reject-replacement")
CLEANUP = ("root-cleanup", "root-final-absence")
PREFLIGHT = frozenset(("BOTH_ACCESSIBLE", "RUNNER_TEMP_NOT_SEARCHABLE", "SOURCE_SCRIPT_NOT_READABLE", "BOTH_INACCESSIBLE", "PREFLIGHT_EXECUTION_FAILED"))
PREFLIGHT_SCOPE = "RUNNER_TEMP_SEARCH_AND_SOURCE_SCRIPT_READ_ONLY"
BRIDGE_PREFLIGHT = frozenset(("BRIDGE_ACCESSIBLE", "BRIDGE_RUNNER_NOT_SEARCHABLE", "BRIDGE_PAYLOAD_NOT_READABLE", "BRIDGE_BOTH_INACCESSIBLE", "BRIDGE_PREFLIGHT_EXECUTION_FAILED"))
BRIDGE_PREFLIGHT_SCOPE = "DEDICATED_RUNNER_SEARCH_AND_PINNED_TWO_FILE_PAYLOAD_READ_ONLY"


def need(condition: bool) -> None:
    if not condition:
        raise ValueError("uid-probe-diagnostic-check-rejected")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(raw: bytes, source_commit: str, run_id: str, run_attempt: str) -> bytes:
    need(0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n"))
    need(re.fullmatch(r"[a-f0-9]{40}", source_commit or "") is not None)
    need(re.fullmatch(r"[1-9][0-9]*", run_id or "") is not None and re.fullmatch(r"[1-9][0-9]*", run_attempt or "") is not None)
    value = json.loads(raw)
    need(type(value) is dict and set(value) == {"schema", "authority", "diagnosticOnly", "sourceCommit", "runId", "runAttempt", "hostPreflightScope", "hostPreflightClassification", "hostPreflightExitStatus", "bridgePreflightScope", "bridgePreflightClassification", "bridgePreflightExitStatus", "bridgePayloadSetSHA256", "bridgeSetupExitStatus", "bridgeCleanupExitStatus", "bridgeFinalAbsenceExitStatus", "events", "probeStatus", "finalExitStatus"})
    need(value["authority"] == "NON_AUTHORITATIVE" and value["diagnosticOnly"] is True)
    need(value["schema"] == SCHEMA and value["sourceCommit"] == source_commit and value["runId"] == run_id and value["runAttempt"] == run_attempt)
    need(value["hostPreflightScope"] == PREFLIGHT_SCOPE and value["hostPreflightClassification"] in PREFLIGHT)
    need(value["bridgePreflightScope"] == BRIDGE_PREFLIGHT_SCOPE and (value["bridgePreflightClassification"] in BRIDGE_PREFLIGHT or value["bridgePreflightClassification"] is None))
    for field in ("hostPreflightExitStatus", "bridgeSetupExitStatus", "bridgeCleanupExitStatus", "bridgeFinalAbsenceExitStatus"):
        need(type(value[field]) is int and 0 <= value[field] <= 255)
    need(value["bridgePreflightExitStatus"] is None or type(value["bridgePreflightExitStatus"]) is int and 0 <= value["bridgePreflightExitStatus"] <= 255)
    need(re.fullmatch(r"[a-f0-9]{64}", value["bridgePayloadSetSHA256"] or "") is not None and value["probeStatus"] in ("PASS", "FAIL"))
    host_expected = {0: "BOTH_ACCESSIBLE", 41: "RUNNER_TEMP_NOT_SEARCHABLE", 42: "SOURCE_SCRIPT_NOT_READABLE", 43: "BOTH_INACCESSIBLE"}.get(value["hostPreflightExitStatus"], "PREFLIGHT_EXECUTION_FAILED")
    need(value["hostPreflightClassification"] == host_expected)
    if value["bridgeSetupExitStatus"] == 0:
        need(value["bridgePreflightExitStatus"] is not None)
        bridge_expected = {0: "BRIDGE_ACCESSIBLE", 41: "BRIDGE_RUNNER_NOT_SEARCHABLE", 42: "BRIDGE_PAYLOAD_NOT_READABLE", 43: "BRIDGE_BOTH_INACCESSIBLE"}.get(value["bridgePreflightExitStatus"], "BRIDGE_PREFLIGHT_EXECUTION_FAILED")
        need(value["bridgePreflightClassification"] == bridge_expected)
    else: need(value["bridgePreflightClassification"] is None and value["bridgePreflightExitStatus"] is None)
    need(type(value["finalExitStatus"]) is int and 0 <= value["finalExitStatus"] <= 255)
    events = value["events"]
    need(type(events) is list and 0 <= len(events) <= 8)
    modes = []
    for event in events:
        need(type(event) is dict and set(event) == {"mode", "exitStatus", "outcome"})
        need(type(event["exitStatus"]) is int and 0 <= event["exitStatus"] <= 255)
        need(event["outcome"] == ("PASS" if event["exitStatus"] == 0 else "FAIL"))
        modes.append(event["mode"])
    need(len(modes) == len(set(modes)) and (not modes or modes[-2:] == list(CLEANUP)))
    prefix = modes[:-2]
    need(prefix == list(NORMAL[:len(prefix)]))
    failures = [index for index, event in enumerate(events[:-2]) if event["exitStatus"] != 0]
    need(not failures or failures == [len(prefix) - 1])
    need(events or value["bridgeSetupExitStatus"] != 0 or value["bridgePreflightClassification"] != "BRIDGE_ACCESSIBLE")
    if prefix and len(prefix) < len(NORMAL):
        need(prefix and events[len(prefix)-1]["exitStatus"] != 0)
    need(not events or value["bridgeSetupExitStatus"] == 0 and value["bridgePreflightClassification"] == "BRIDGE_ACCESSIBLE")
    ordered_failures = []
    if value["hostPreflightClassification"] == "PREFLIGHT_EXECUTION_FAILED": ordered_failures.append(value["hostPreflightExitStatus"])
    if value["bridgeSetupExitStatus"] != 0: ordered_failures.append(value["bridgeSetupExitStatus"])
    if value["bridgeSetupExitStatus"] == 0 and value["bridgePreflightClassification"] != "BRIDGE_ACCESSIBLE": ordered_failures.append(value["bridgePreflightExitStatus"])
    ordered_failures.extend(event["exitStatus"] for event in events if event["exitStatus"] != 0)
    ordered_failures.extend(status for status in (value["bridgeCleanupExitStatus"], value["bridgeFinalAbsenceExitStatus"]) if status != 0)
    if ordered_failures:
        need(value["finalExitStatus"] == ordered_failures[0])
    all_pass = value["hostPreflightClassification"] != "PREFLIGHT_EXECUTION_FAILED" and value["bridgeSetupExitStatus"] == 0 and value["bridgePreflightClassification"] == "BRIDGE_ACCESSIBLE" and modes == list(NORMAL + CLEANUP) and all(event["exitStatus"] == 0 for event in events) and value["bridgeCleanupExitStatus"] == 0 and value["bridgeFinalAbsenceExitStatus"] == 0
    need((value["probeStatus"] == "PASS") == all_pass)
    need((value["finalExitStatus"] == 0) == all_pass)
    canonical = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    need(raw == canonical)
    return canonical


def write_new(path: Path, raw: bytes) -> None:
    parent = path.parent
    metadata = parent.lstat()
    need(not parent.is_symlink() and parent.is_dir())
    if os.name == "posix":
        need(metadata.st_uid == os.geteuid() and metadata.st_gid == os.getegid())
        need((metadata.st_mode & 0o777) == 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--expected-producer-sha256", required=True)
    parser.add_argument("--expected-checker-sha256", required=True)
    args = parser.parse_args()
    producer = Path(args.producer)
    need(re.fullmatch(r"[a-f0-9]{64}", args.expected_producer_sha256 or "") is not None)
    need(re.fullmatch(r"[a-f0-9]{64}", args.expected_checker_sha256 or "") is not None)
    need(sha(producer) == args.expected_producer_sha256 and sha(Path(__file__)) == args.expected_checker_sha256)
    raw = validate(Path(args.input).read_bytes(), args.source_commit, args.run_id, args.run_attempt)
    write_new(Path(args.output), raw)


if __name__ == "__main__":
    main()
