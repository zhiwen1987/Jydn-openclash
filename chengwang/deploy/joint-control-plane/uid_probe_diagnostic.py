from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re


SCHEMA = "chengwang.joint-uid-probe-diagnostic/v1"
MAX_BYTES = 4096
NORMAL = (
    "root-setup",
    "uid-prepublish-denials",
    "root-finalize",
    "uid-final-read-and-rename",
    "uid-install-replacement",
    "root-reject-replacement",
)
CLEANUP = ("root-cleanup", "root-final-absence")
MODES = NORMAL + CLEANUP
PREFLIGHT = frozenset((
    "BOTH_ACCESSIBLE",
    "RUNNER_TEMP_NOT_SEARCHABLE",
    "SOURCE_SCRIPT_NOT_READABLE",
    "BOTH_INACCESSIBLE",
    "PREFLIGHT_EXECUTION_FAILED",
))
PREFLIGHT_SCOPE = "RUNNER_TEMP_SEARCH_AND_SOURCE_SCRIPT_READ_ONLY"


def need(condition: bool) -> None:
    if not condition:
        raise ValueError("uid-probe-diagnostic-rejected")


def binding(source_commit: str, run_id: str, run_attempt: str) -> None:
    need(re.fullmatch(r"[a-f0-9]{40}", source_commit or "") is not None)
    need(re.fullmatch(r"[1-9][0-9]*", run_id or "") is not None)
    need(re.fullmatch(r"[1-9][0-9]*", run_attempt or "") is not None)


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


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


def replace(path: Path, value: dict[str, object]) -> None:
    raw = canonical(value)
    need(len(raw) <= MAX_BYTES)
    temporary = path.with_name("." + path.name + ".next")
    write_new(temporary, raw)
    os.replace(temporary, path)


def load(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    need(0 < len(raw) <= MAX_BYTES)
    value = json.loads(raw)
    need(type(value) is dict)
    return value


def initialize(path: Path, source_commit: str, run_id: str, run_attempt: str) -> None:
    binding(source_commit, run_id, run_attempt)
    write_new(path, canonical({
        "schema": SCHEMA,
        "authority": "NON_AUTHORITATIVE",
        "diagnosticOnly": True,
        "sourceCommit": source_commit,
        "runId": run_id,
        "runAttempt": run_attempt,
        "preflightScope": PREFLIGHT_SCOPE,
        "preflightClassification": None,
        "events": [],
    }))


def same(value: dict[str, object], source_commit: str, run_id: str, run_attempt: str) -> None:
    binding(source_commit, run_id, run_attempt)
    need(value.get("schema") == SCHEMA and value.get("sourceCommit") == source_commit)
    need(value.get("runId") == run_id and value.get("runAttempt") == run_attempt)
    need(set(value) == {"schema", "authority", "diagnosticOnly", "sourceCommit", "runId", "runAttempt", "preflightScope", "preflightClassification", "events"})
    need(value.get("authority") == "NON_AUTHORITATIVE" and value.get("diagnosticOnly") is True)
    need(value.get("preflightScope") == PREFLIGHT_SCOPE)
    need(type(value.get("events")) is list)


def set_preflight(path: Path, source_commit: str, run_id: str, run_attempt: str, classification: str) -> None:
    value = load(path)
    same(value, source_commit, run_id, run_attempt)
    need(classification in PREFLIGHT and value["preflightClassification"] is None and value["events"] == [])
    value["preflightClassification"] = classification
    replace(path, value)


def expected_next(events: list[object]) -> set[str]:
    modes = [event["mode"] for event in events if type(event) is dict]
    need(len(modes) == len(events) and len(modes) == len(set(modes)))
    if not modes:
        return {NORMAL[0]}
    if modes[-1] == CLEANUP[1]:
        return set()
    if modes[-1] == CLEANUP[0]:
        return {CLEANUP[1]}
    need(modes == list(NORMAL[:len(modes)]))
    if events[-1]["exitStatus"] == 0 and len(modes) < len(NORMAL):
        return {NORMAL[len(modes)], CLEANUP[0]}
    return {CLEANUP[0]}


def add_event(path: Path, source_commit: str, run_id: str, run_attempt: str, mode: str, exit_status: int) -> None:
    value = load(path)
    same(value, source_commit, run_id, run_attempt)
    need(value["preflightClassification"] in PREFLIGHT)
    need(mode in expected_next(value["events"]) and type(exit_status) is int and 0 <= exit_status <= 255)
    value["events"].append({"mode": mode, "exitStatus": exit_status, "outcome": "PASS" if exit_status == 0 else "FAIL"})
    replace(path, value)


def finalize(path: Path, output: Path, source_commit: str, run_id: str, run_attempt: str, final_exit_status: int) -> None:
    value = load(path)
    same(value, source_commit, run_id, run_attempt)
    need(value["preflightClassification"] in PREFLIGHT)
    events = value["events"]
    expected_next(events)
    need(len(events) >= 3 and [event["mode"] for event in events[-2:]] == list(CLEANUP))
    need(type(final_exit_status) is int and 0 <= final_exit_status <= 255)
    failures = [event for event in events if event["exitStatus"] != 0]
    need(not failures or final_exit_status == failures[0]["exitStatus"])
    all_pass = value["preflightClassification"] != "PREFLIGHT_EXECUTION_FAILED" and len(events) == len(MODES) and all(event["exitStatus"] == 0 for event in events)
    need((final_exit_status == 0) == all_pass)
    result = {**value, "probeStatus": "PASS" if all_pass else "FAIL", "finalExitStatus": final_exit_status}
    raw = canonical(result)
    need(len(raw) <= MAX_BYTES)
    write_new(output, raw)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("init", "preflight", "event", "finalize"))
    parser.add_argument("--journal", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--classification")
    parser.add_argument("--mode")
    parser.add_argument("--exit-status", type=int)
    parser.add_argument("--output")
    args = parser.parse_args()
    path = Path(args.journal)
    if args.action == "init":
        need(args.classification is None and args.mode is None and args.exit_status is None and args.output is None)
        initialize(path, args.source_commit, args.run_id, args.run_attempt)
    elif args.action == "preflight":
        need(args.classification is not None and args.mode is None and args.exit_status is None and args.output is None)
        set_preflight(path, args.source_commit, args.run_id, args.run_attempt, args.classification)
    elif args.action == "event":
        need(args.classification is None and args.mode is not None and args.exit_status is not None and args.output is None)
        add_event(path, args.source_commit, args.run_id, args.run_attempt, args.mode, args.exit_status)
    else:
        need(args.classification is None and args.mode is None and args.exit_status is not None and args.output is not None)
        finalize(path, Path(args.output), args.source_commit, args.run_id, args.run_attempt, args.exit_status)


if __name__ == "__main__":
    main()
