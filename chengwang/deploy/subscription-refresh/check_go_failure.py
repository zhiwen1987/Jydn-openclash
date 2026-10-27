"""Project a bounded, non-accepting diagnostic from private ``go test -json``.

The raw event stream remains runner-local.  Every name emitted by this module
comes from the pinned source contract; Output, elapsed time, subtest names, and
decoder errors are never copied into the public report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


SCHEMA = "chengwang.subscription-refresh-go-failure/v1"
SCOPE = "NON_ACCEPTING_SOURCE_DECLARED_TOP_LEVEL_FAILURE_PROJECTION"
MAX_EVENTS_BYTES = 64 << 20
MAX_CONTRACT_BYTES = 8 << 20
MAX_LINE_BYTES = 1 << 20
MAX_EVENT_LINES = 1_000_000
DIGEST = re.compile(r"^[0-9a-f]{64}$")
TOP = re.compile(r"^Test[A-Za-z0-9_]+$")
ACTIONS = {"start", "run", "pause", "cont", "pass", "fail", "output", "skip"}
EVENT_KEYS = {"Time", "Action", "Package", "Test", "Elapsed", "Output"}
STATES = ("PASS", "FAIL", "RUNNING", "NOT_STARTED")
STAGES = ("NO_EVENTS", "PACKAGE_SETUP", "TOP_TESTS", "PACKAGE_TERMINAL", "COMPLETE_EVENTS", "INVALID_STREAM")
FAILURE_CLASSES = (
    "EVENT_STREAM_REJECTED",
    "TIMEOUT_TEXT_MARKER_OBSERVED",
    "PANIC_TEXT_MARKER_OBSERVED",
    "TIMEOUT_AND_PANIC_TEXT_MARKERS_OBSERVED",
    "TOP_TERMINAL_NONPASS",
    "PACKAGE_TERMINAL_NONPASS",
    "INCOMPLETE_EVENT_STREAM",
    "NONZERO_EXIT_AFTER_COMPLETE_EVENTS",
    "EVENT_CHECKER_REJECTED_AFTER_COMPLETE_EVENTS",
    "NO_EVENT_EVIDENCE",
    "UNKNOWN_NONZERO_EXIT",
)
MARKERS = ("NONE", "TIMEOUT_TEXT", "PANIC_TEXT", "TIMEOUT_AND_PANIC_TEXT")


class FailureDiagnosticError(AssertionError):
    pass


def need(value: bool, message: str) -> None:
    if not value:
        raise FailureDiagnosticError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def decode_json(raw: bytes) -> object:
    def pairs(values):
        result = {}
        for key, value in values:
            need(type(key) is str and key not in result, "duplicate/non-string JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise FailureDiagnosticError("non-finite JSON number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FailureDiagnosticError("invalid JSON") from exc


def safe_read(path: Path, maximum: int) -> bytes:
    need(path.is_file() and not path.is_symlink(), "missing/non-regular input")
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    need(len(raw) <= maximum, "input exceeds budget")
    return raw


def write_new(path: Path, raw: bytes) -> None:
    need(path.parent.is_dir() and not path.parent.is_symlink(), "output parent")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            need(written > 0, "short output write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def expected(contract: object) -> tuple[list[str], dict[str, list[str]]]:
    need(type(contract) is dict and contract.get("schema") == "chengwang.subscription-refresh-source/v3", "contract schema")
    go_test = contract.get("goTest")
    need(type(go_test) is dict and type(go_test.get("packages")) is list, "Go package contract")
    packages = go_test["packages"]
    need(packages == list(dict.fromkeys(packages)) and len(packages) == 7, "Go packages")
    definitions = contract.get("packages")
    need(type(definitions) is dict and list(definitions) == packages, "package definitions")
    wanted: dict[str, list[str]] = {}
    for package in packages:
        value = definitions[package]
        need(type(package) is str and type(value) is dict, "package entry")
        qualified = value.get("requiredRunTops")
        need(type(qualified) is list and qualified == sorted(set(qualified)), "required top set")
        prefix = package + "::"
        names = []
        for item in qualified:
            need(type(item) is str and item.startswith(prefix), "qualified top")
            name = item.removeprefix(prefix)
            need(TOP.fullmatch(name) is not None, "top name")
            names.append(name)
        wanted[package] = names
    need(sum(map(len, wanted.values())) == 481, "required top cardinality")
    return packages, wanted


def event_shape(event: object) -> bool:
    if type(event) is not dict or not set(event).issubset(EVENT_KEYS):
        return False
    if type(event.get("Action")) is not str or event["Action"] not in ACTIONS:
        return False
    if type(event.get("Package")) is not str:
        return False
    if "Test" in event and event["Test"] is not None and type(event["Test"]) is not str:
        return False
    if "Time" in event and type(event["Time"]) is not str:
        return False
    if "Output" in event and type(event["Output"]) is not str:
        return False
    if "Elapsed" in event and (type(event["Elapsed"]) not in (int, float) or type(event["Elapsed"]) is bool):
        return False
    return True


def project(events_raw: bytes, contract_raw: bytes, contract_sha256: str, go_exit: int, event_check_exit: int) -> dict:
    need(type(contract_sha256) is str and DIGEST.fullmatch(contract_sha256) is not None, "contract digest")
    need(sha(contract_raw) == contract_sha256, "contract pin")
    need(type(go_exit) is int and 0 <= go_exit <= 255, "Go exit")
    need(type(event_check_exit) is int and 0 <= event_check_exit <= 255, "event-check exit")
    need(go_exit != 0 or event_check_exit != 0, "diagnostic requires a failed Go/event gate")
    packages, wanted = expected(decode_json(contract_raw))
    state = {package: {name: "NOT_STARTED" for name in names} for package, names in wanted.items()}
    package_started = {package: False for package in packages}
    package_terminal: dict[str, str] = {}
    invalid = False
    timeout_marker = False
    panic_marker = False
    event_count = 0
    output_count = 0
    ignored_subtest_count = 0
    lines = events_raw.splitlines()
    if not lines or len(lines) > MAX_EVENT_LINES:
        invalid = len(lines) > MAX_EVENT_LINES
    for raw_line in lines[:MAX_EVENT_LINES]:
        if invalid:
            break
        event_count += 1
        if not raw_line or len(raw_line) > MAX_LINE_BYTES:
            invalid = True
            break
        try:
            event = decode_json(raw_line)
        except FailureDiagnosticError:
            invalid = True
            break
        if not event_shape(event):
            invalid = True
            break
        action = event["Action"]
        package = event["Package"]
        test = event.get("Test")
        if package not in wanted:
            invalid = True
            break
        if action == "output":
            output_count += 1
            output = event.get("Output", "")
            timeout_marker = timeout_marker or "panic: test timed out after " in output
            panic_marker = panic_marker or output.startswith("panic:")
        if test is None:
            if action == "start":
                if package_started[package] or package in package_terminal:
                    invalid = True
                    break
                package_started[package] = True
            elif action in {"pass", "fail", "skip"}:
                if not package_started[package] or package in package_terminal:
                    invalid = True
                    break
                package_terminal[package] = action
            elif not package_started[package] or package in package_terminal:
                invalid = True
                break
            continue
        if not package_started[package] or package in package_terminal:
            invalid = True
            break
        if "/" in test:
            parent = test.split("/", 1)[0]
            if parent not in state[package] or state[package][parent] != "RUNNING":
                invalid = True
                break
            ignored_subtest_count += 1
            continue
        if test not in state[package]:
            invalid = True
            break
        current = state[package][test]
        if action == "run":
            if current != "NOT_STARTED":
                invalid = True
                break
            state[package][test] = "RUNNING"
        elif action == "pass":
            if current != "RUNNING":
                invalid = True
                break
            state[package][test] = "PASS"
        elif action in {"fail", "skip"}:
            if current != "RUNNING":
                invalid = True
                break
            state[package][test] = "FAIL"
        elif action not in {"output", "pause", "cont"} or current != "RUNNING":
            invalid = True
            break

    by_state = {name: [] for name in STATES}
    rows = []
    for package in packages:
        counts = {name: 0 for name in STATES}
        for name in wanted[package]:
            status = state[package][name]
            counts[status] += 1
            if status != "PASS":
                by_state[status].append(package + "::" + name)
        rows.append({
            "package": package,
            "passCount": counts["PASS"],
            "failCount": counts["FAIL"],
            "runningCount": counts["RUNNING"],
            "notStartedCount": counts["NOT_STARTED"],
        })
    all_complete = all(state[package][name] == "PASS" for package in packages for name in wanted[package])
    packages_complete = all(package_terminal.get(package) == "pass" for package in packages)
    if invalid:
        stage = "INVALID_STREAM"
        failure_class = "EVENT_STREAM_REJECTED"
    elif all_complete and packages_complete:
        stage = "COMPLETE_EVENTS"
        failure_class = "NONZERO_EXIT_AFTER_COMPLETE_EVENTS" if go_exit else "EVENT_CHECKER_REJECTED_AFTER_COMPLETE_EVENTS"
    elif package_terminal:
        stage = "PACKAGE_TERMINAL"
        failure_class = "PACKAGE_TERMINAL_NONPASS" if any(value != "pass" for value in package_terminal.values()) else "INCOMPLETE_EVENT_STREAM"
    elif any(value != "NOT_STARTED" for values in state.values() for value in values.values()):
        stage = "TOP_TESTS"
        failure_class = "TOP_TERMINAL_NONPASS" if by_state["FAIL"] else "INCOMPLETE_EVENT_STREAM"
    elif any(package_started.values()):
        stage = "PACKAGE_SETUP"
        failure_class = "INCOMPLETE_EVENT_STREAM"
    else:
        stage = "NO_EVENTS"
        failure_class = "NO_EVENT_EVIDENCE" if not lines else "UNKNOWN_NONZERO_EXIT"
    if not invalid and (timeout_marker or panic_marker):
        if timeout_marker and panic_marker:
            failure_class = "TIMEOUT_AND_PANIC_TEXT_MARKERS_OBSERVED"
        elif timeout_marker:
            failure_class = "TIMEOUT_TEXT_MARKER_OBSERVED"
        else:
            failure_class = "PANIC_TEXT_MARKER_OBSERVED"
    marker = "TIMEOUT_AND_PANIC_TEXT" if timeout_marker and panic_marker else "TIMEOUT_TEXT" if timeout_marker else "PANIC_TEXT" if panic_marker else "NONE"
    return {
        "schema": SCHEMA,
        "scope": SCOPE,
        "reportOutcome": "FAILURE_DIAGNOSTIC_ONLY",
        "accepted": False,
        "contractSHA256": contract_sha256,
        "goExit": go_exit,
        "eventCheckExit": event_check_exit,
        "stage": stage,
        "failureClass": failure_class,
        "markerObservation": marker,
        "eventLineCount": event_count,
        "outputEventCount": output_count,
        "ignoredSubtestEventCount": ignored_subtest_count,
        "declaredPackageCount": len(packages),
        "declaredTopCount": sum(map(len, wanted.values())),
        "passCount": sum(row["passCount"] for row in rows),
        "failCount": len(by_state["FAIL"]),
        "runningCount": len(by_state["RUNNING"]),
        "notStartedCount": len(by_state["NOT_STARTED"]),
        "packages": rows,
        "failedTops": by_state["FAIL"],
        "runningTops": by_state["RUNNING"],
        "notStartedTops": by_state["NOT_STARTED"],
    }


def verify_report(
    report_raw: bytes,
    events_raw: bytes,
    contract_raw: bytes,
    contract_sha256: str,
    go_exit: int,
    event_check_exit: int,
) -> dict:
    report = decode_json(report_raw)
    keys = (
        "schema", "scope", "reportOutcome", "accepted", "contractSHA256", "goExit", "eventCheckExit",
        "stage", "failureClass", "markerObservation", "eventLineCount", "outputEventCount",
        "ignoredSubtestEventCount", "declaredPackageCount", "declaredTopCount", "passCount", "failCount",
        "runningCount", "notStartedCount", "packages", "failedTops", "runningTops", "notStartedTops",
    )
    need(type(report) is dict and tuple(report) == keys, "report shape")
    need(report["schema"] == SCHEMA and report["scope"] == SCOPE, "report schema/scope")
    need(report["reportOutcome"] == "FAILURE_DIAGNOSTIC_ONLY" and report["accepted"] is False, "report is non-accepting")
    need(sha(contract_raw) == contract_sha256 == report["contractSHA256"], "report contract pin")
    packages, wanted = expected(decode_json(contract_raw))
    need(type(report["goExit"]) is int and 0 <= report["goExit"] <= 255, "report Go exit")
    need(type(report["eventCheckExit"]) is int and 0 <= report["eventCheckExit"] <= 255, "report event exit")
    need(report["goExit"] != 0 or report["eventCheckExit"] != 0, "report failure exits")
    need(report["stage"] in STAGES and report["failureClass"] in FAILURE_CLASSES and report["markerObservation"] in MARKERS, "report enums")
    for name in ("eventLineCount", "outputEventCount", "ignoredSubtestEventCount", "declaredPackageCount", "declaredTopCount", "passCount", "failCount", "runningCount", "notStartedCount"):
        need(type(report[name]) is int and report[name] >= 0, "report count")
    need(report["declaredPackageCount"] == len(packages) and report["declaredTopCount"] == 481, "report declared cardinality")
    need(report["passCount"] + report["failCount"] + report["runningCount"] + report["notStartedCount"] == 481, "report state partition")
    declared = {package + "::" + name for package in packages for name in wanted[package]}
    emitted = []
    for key, count_key in (("failedTops", "failCount"), ("runningTops", "runningCount"), ("notStartedTops", "notStartedCount")):
        values = report[key]
        need(type(values) is list and values == sorted(set(values)) and set(values).issubset(declared), "report top list")
        need(len(values) == report[count_key], "report top count")
        emitted.extend(values)
    need(len(emitted) == len(set(emitted)), "report state lists overlap")
    rows = report["packages"]
    need(type(rows) is list and len(rows) == len(packages), "report package rows")
    for package, row in zip(packages, rows):
        need(type(row) is dict and tuple(row) == ("package", "passCount", "failCount", "runningCount", "notStartedCount"), "report package row")
        need(row["package"] == package, "report package order")
        for key in ("passCount", "failCount", "runningCount", "notStartedCount"):
            need(type(row[key]) is int and row[key] >= 0, "report package count")
        need(sum(row[key] for key in ("passCount", "failCount", "runningCount", "notStartedCount")) == len(wanted[package]), "report package partition")
        prefix = package + "::"
        fail_count = sum(value.startswith(prefix) for value in report["failedTops"])
        running_count = sum(value.startswith(prefix) for value in report["runningTops"])
        not_started_count = sum(value.startswith(prefix) for value in report["notStartedTops"])
        need(row["failCount"] == fail_count and row["runningCount"] == running_count and row["notStartedCount"] == not_started_count, "report package listed states")
        need(row["passCount"] == len(wanted[package]) - fail_count - running_count - not_started_count, "report package pass complement")
    need(sum(row["passCount"] for row in rows) == report["passCount"], "report pass aggregate")
    need(sum(row["failCount"] for row in rows) == report["failCount"], "report fail aggregate")
    need(sum(row["runningCount"] for row in rows) == report["runningCount"], "report running aggregate")
    need(sum(row["notStartedCount"] for row in rows) == report["notStartedCount"], "report not-started aggregate")
    if report["stage"] == "INVALID_STREAM":
        need(report["failureClass"] == "EVENT_STREAM_REJECTED", "invalid stream class")
    if report["stage"] == "NO_EVENTS":
        need(report["passCount"] == report["failCount"] == report["runningCount"] == 0 and report["notStartedCount"] == 481, "no-event state")
        need(report["failureClass"] in {"NO_EVENT_EVIDENCE", "UNKNOWN_NONZERO_EXIT"}, "no-event class")
    if report["stage"] == "COMPLETE_EVENTS":
        need(report["passCount"] == 481 and report["failCount"] == report["runningCount"] == report["notStartedCount"] == 0, "complete event state")
        need(report["failureClass"] in {"NONZERO_EXIT_AFTER_COMPLETE_EVENTS", "EVENT_CHECKER_REJECTED_AFTER_COMPLETE_EVENTS"}, "complete event class")
    marker_classes = {
        "TIMEOUT_TEXT": "TIMEOUT_TEXT_MARKER_OBSERVED",
        "PANIC_TEXT": "PANIC_TEXT_MARKER_OBSERVED",
        "TIMEOUT_AND_PANIC_TEXT": "TIMEOUT_AND_PANIC_TEXT_MARKERS_OBSERVED",
    }
    if report["markerObservation"] != "NONE":
        need(report["failureClass"] == marker_classes[report["markerObservation"]], "marker class")
    expected_report = project(events_raw, contract_raw, contract_sha256, go_exit, event_check_exit)
    need(report == expected_report, "report does not match runner-private events")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--output")
    modes.add_argument("--report")
    parser.add_argument("--events", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--go-exit", required=True, type=int)
    parser.add_argument("--event-check-exit", required=True, type=int)
    args = parser.parse_args()
    contract_raw = safe_read(Path(args.contract), MAX_CONTRACT_BYTES)
    events_raw = safe_read(Path(args.events), MAX_EVENTS_BYTES)
    if args.output is not None:
        result = project(events_raw, contract_raw, args.contract_sha256, args.go_exit, args.event_check_exit)
        write_new(Path(args.output), json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
    else:
        result = verify_report(
            safe_read(Path(args.report), MAX_CONTRACT_BYTES),
            events_raw,
            contract_raw,
            args.contract_sha256,
            args.go_exit,
            args.event_check_exit,
        )
    print(json.dumps({"schema": result["schema"], "accepted": False, "failureClass": result["failureClass"]}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
