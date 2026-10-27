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
from pathlib import Path, PurePosixPath
import re


SCHEMA = "chengwang.subscription-refresh-go-failure/v4"
SCOPE = "NON_ACCEPTING_SOURCE_DECLARED_TOP_LEVEL_FAILURE_PROJECTION"
MAX_EVENTS_BYTES = 64 << 20
MAX_CONTRACT_BYTES = 8 << 20
MAX_STDERR_BYTES = 8 << 20
MAX_LINE_BYTES = 1 << 20
MAX_EVENT_LINES = 1_000_000
MAX_BUILD_LOCATIONS = 8
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
BUILD_DIAGNOSTIC_STATUSES = (
    "BUILD_DIAGNOSTIC_LOCATION_OBSERVED",
    "BUILD_DIAGNOSTIC_LOCATION_TRUNCATED",
    "BUILD_DIAGNOSTIC_LOCATION_UNKNOWN",
)
BUILD_DIAGNOSTIC_REASONS = (
    "NOT_ELIGIBLE",
    "STDERR_OVER_BUDGET",
    "CONTROL_BYTE",
    "INVALID_UTF8",
    "LINE_OVER_BUDGET",
    "UNMATCHED_GO_POSITION",
    "POSITION_SYNTAX",
    "POSITION_RANGE",
    "NO_SOURCE_POSITION",
    "LOCATION_COUNT_OVERFLOW",
    "OBSERVED",
)
BUILD_STDERR_CLASSES = ("EMPTY", "NONEMPTY", "OVER_BUDGET")
BUILD_POSITION_COUNTS = tuple(str(value) for value in range(MAX_BUILD_LOCATIONS + 1)) + ("OVER8",)
BUILD_LOCATION_TARGET_PACKAGE = "chengwang/internal/subscriptionctl"
BUILD_LOCATION_SOURCES = {
    "chengwang/internal/subscriptionctl/access.go": "01872130f73000775a3d1b051447f837a576639f8a0428d671f8d392aae708e4",
    "chengwang/internal/subscriptionctl/access_test.go": "f6dea00963efd7395b2be60f68354c00c66590ca49c645f282d0f33573eab1dd",
    "chengwang/internal/subscriptionctl/contract.go": "8bf567cf6294dc6907d1932b240e244f2f80fe03ae17f277e098b2523cca2637",
    "chengwang/internal/subscriptionctl/refresh.go": "6ca1bdc725b035b9d6eed26724e77aafd5abd6a06b1f60d69c49dfa92b26cf0d",
    "chengwang/internal/subscriptionctl/service.go": "28d72d50d061cfc6d8c6263a6d941520a238186b791640c9f2bc3e76d1d392aa",
    "chengwang/internal/subscriptionctl/service_linux_test.go": "ecacaf5cf16e09b70e95779a75b75478f70578df99f203e2042ad228d3de3680",
    "chengwang/internal/subscriptionctl/service_read_linux_test.go": "2e3c28a09a2962b1fc385ab03246f6a8787caf42c676e8829b54d0079ef636cf",
}
LOCATION_TAIL = re.compile(r"^(?P<line>[1-9][0-9]{0,6})(?::(?P<column>[1-9][0-9]{0,2}))?: .+$")
LOCATION_LIKE = re.compile(r"\.go:[0-9]")


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


def safe_read_stderr(path: Path) -> bytes:
    need(path.is_file() and not path.is_symlink(), "missing/non-regular stderr")
    with path.open("rb") as source:
        return source.read(MAX_STDERR_BYTES + 1)


def build_location_sources(repo: Path) -> list[tuple[str, bytes]]:
    root = repo.resolve()
    need(root.is_dir() and not root.is_symlink(), "repository root")
    need(list(BUILD_LOCATION_SOURCES) == sorted(BUILD_LOCATION_SOURCES), "build source declaration order")
    result = []
    for relative, expected_sha in BUILD_LOCATION_SOURCES.items():
        pure = PurePosixPath(relative)
        need(
            relative == pure.as_posix()
            and not pure.is_absolute()
            and ".." not in pure.parts
            and pure.parent.as_posix() == BUILD_LOCATION_TARGET_PACKAGE
            and relative.endswith(".go"),
            "build source declaration",
        )
        path = root.joinpath(*pure.parts)
        need(path.is_file() and not path.is_symlink(), "missing/non-regular build source")
        need(path.resolve().is_relative_to(root), "build source escapes repository")
        raw = path.read_bytes()
        need(sha(raw) == expected_sha, "build source pin")
        result.append((relative, raw))
    return result


def project_build_locations(stderr_raw: bytes, repo: Path, eligible: bool) -> tuple[str, str, str, str, bool, list[dict]]:
    stderr_class = (
        "OVER_BUDGET" if len(stderr_raw) > MAX_STDERR_BYTES
        else "EMPTY" if len(stderr_raw) == 0
        else "NONEMPTY"
    )

    def unknown(reason: str, count: str = "0") -> tuple[str, str, str, str, bool, list[dict]]:
        need(reason in BUILD_DIAGNOSTIC_REASONS and reason != "OBSERVED", "unknown build diagnostic reason")
        need(count in BUILD_POSITION_COUNTS, "unknown build diagnostic count")
        return "BUILD_DIAGNOSTIC_LOCATION_UNKNOWN", reason, stderr_class, count, False, []

    if not eligible:
        return unknown("NOT_ELIGIBLE")
    if len(stderr_raw) > MAX_STDERR_BYTES:
        return unknown("STDERR_OVER_BUDGET")
    if any(byte in stderr_raw for byte in (0, 13, 27)):
        return unknown("CONTROL_BYTE")
    try:
        text = stderr_raw.decode("utf-8")
    except UnicodeDecodeError:
        return unknown("INVALID_UTF8")
    sources = build_location_sources(repo)
    root_prefix = repo.resolve().as_posix().rstrip("/") + "/"
    prefixes = []
    source_lines = {}
    source_order = {}
    for index, (relative, raw) in enumerate(sources):
        module_relative = relative.removeprefix("chengwang/")
        prefixes.append((relative, relative + ":"))
        prefixes.append((relative, module_relative + ":"))
        prefixes.append((relative, root_prefix + relative + ":"))
        source_lines[relative] = raw.splitlines()
        source_order[relative] = index

    def location_key(value: tuple[str, int, int | None]) -> tuple[int, int, int]:
        return source_order[value[0]], value[1], -1 if value[2] is None else value[2]

    selected: list[tuple[str, int, int | None]] = []
    overflow = False
    for line in text.split("\n"):
        if line == "":
            continue
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            return unknown("LINE_OVER_BUDGET", "OVER8" if overflow else str(len(selected)))
        matched = False
        for relative, prefix in prefixes:
            if not line.startswith(prefix):
                continue
            matched = True
            match = LOCATION_TAIL.fullmatch(line[len(prefix):])
            if match is None:
                return unknown("POSITION_SYNTAX", "OVER8" if overflow else str(len(selected)))
            line_number = int(match.group("line"))
            column_text = match.group("column")
            column = int(column_text) if column_text is not None else None
            lines = source_lines[relative]
            if line_number > len(lines):
                return unknown("POSITION_RANGE", "OVER8" if overflow else str(len(selected)))
            if column is not None and (column > 254 or column > len(lines[line_number - 1]) + 1):
                return unknown("POSITION_RANGE", "OVER8" if overflow else str(len(selected)))
            location = (relative, line_number, column)
            if location not in selected:
                if len(selected) < MAX_BUILD_LOCATIONS:
                    selected.append(location)
                    selected.sort(key=location_key)
                else:
                    overflow = True
                    if location_key(location) < location_key(selected[-1]):
                        selected[-1] = location
                        selected.sort(key=location_key)
            break
        if not matched and LOCATION_LIKE.search(line) is not None:
            return unknown("UNMATCHED_GO_POSITION", "OVER8" if overflow else str(len(selected)))
    if not selected:
        return unknown("NO_SOURCE_POSITION")
    ordered = sorted(selected, key=location_key)
    locations = [{"source": source, "line": line, "column": column} for source, line, column in ordered]
    if overflow:
        return (
            "BUILD_DIAGNOSTIC_LOCATION_TRUNCATED",
            "LOCATION_COUNT_OVERFLOW",
            stderr_class,
            "OVER8",
            True,
            locations,
        )
    return (
        "BUILD_DIAGNOSTIC_LOCATION_OBSERVED",
        "OBSERVED",
        stderr_class,
        str(len(ordered)),
        False,
        locations,
    )


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


def project(
    events_raw: bytes,
    stderr_raw: bytes,
    repo: Path,
    contract_raw: bytes,
    contract_sha256: str,
    go_exit: int,
    event_check_exit: int,
) -> dict:
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
    target_zero_top = (
        BUILD_LOCATION_TARGET_PACKAGE in state
        and all(value == "NOT_STARTED" for value in state[BUILD_LOCATION_TARGET_PACKAGE].values())
    )
    build_status, build_reason, build_stderr_class, build_position_count, build_truncated, build_locations = project_build_locations(
        stderr_raw, repo, target_zero_top,
    )
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
        "buildDiagnosticStatus": build_status,
        "buildDiagnosticReason": build_reason,
        "buildStderrClass": build_stderr_class,
        "buildSourcePositionCount": build_position_count,
        "buildDiagnosticTruncated": build_truncated,
        "buildDiagnosticLocations": build_locations,
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
    stderr_raw: bytes,
    repo: Path,
    contract_raw: bytes,
    contract_sha256: str,
    go_exit: int,
    event_check_exit: int,
) -> dict:
    report = decode_json(report_raw)
    keys = (
        "schema", "scope", "reportOutcome", "accepted", "contractSHA256", "goExit", "eventCheckExit",
        "stage", "failureClass", "markerObservation", "buildDiagnosticStatus", "buildDiagnosticReason",
        "buildStderrClass", "buildSourcePositionCount", "buildDiagnosticTruncated", "buildDiagnosticLocations",
        "eventLineCount", "outputEventCount",
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
    need(report["buildDiagnosticStatus"] in BUILD_DIAGNOSTIC_STATUSES, "build diagnostic status")
    need(report["buildDiagnosticReason"] in BUILD_DIAGNOSTIC_REASONS, "build diagnostic reason")
    need(report["buildStderrClass"] in BUILD_STDERR_CLASSES, "build stderr class")
    need(report["buildSourcePositionCount"] in BUILD_POSITION_COUNTS, "build source-position count")
    need(type(report["buildDiagnosticTruncated"]) is bool, "build diagnostic truncated flag")
    locations = report["buildDiagnosticLocations"]
    need(type(locations) is list and len(locations) <= MAX_BUILD_LOCATIONS, "build diagnostic locations")
    for value in locations:
        need(type(value) is dict and tuple(value) == ("source", "line", "column"), "build diagnostic location shape")
        need(value["source"] in BUILD_LOCATION_SOURCES, "build diagnostic source")
        need(type(value["line"]) is int and value["line"] > 0, "build diagnostic line")
        need(value["column"] is None or type(value["column"]) is int and 0 < value["column"] <= 254, "build diagnostic column")
    if report["buildDiagnosticStatus"] == "BUILD_DIAGNOSTIC_LOCATION_UNKNOWN":
        need(locations == [], "unknown build diagnostic must be empty")
        need(report["buildDiagnosticReason"] not in {"OBSERVED", "LOCATION_COUNT_OVERFLOW"}, "unknown build diagnostic reason")
        need(report["buildDiagnosticTruncated"] is False, "unknown build diagnostic truncation")
    elif report["buildDiagnosticStatus"] == "BUILD_DIAGNOSTIC_LOCATION_OBSERVED":
        need(len(locations) > 0, "observed build diagnostic must have locations")
        need(report["buildDiagnosticReason"] == "OBSERVED", "observed build diagnostic reason")
        need(report["buildSourcePositionCount"] == str(len(locations)), "observed build diagnostic count")
        need(report["buildDiagnosticTruncated"] is False, "observed build diagnostic truncation")
    else:
        need(len(locations) == MAX_BUILD_LOCATIONS, "truncated build diagnostic locations")
        need(report["buildDiagnosticReason"] == "LOCATION_COUNT_OVERFLOW", "truncated build diagnostic reason")
        need(report["buildSourcePositionCount"] == "OVER8", "truncated build diagnostic count")
        need(report["buildDiagnosticTruncated"] is True, "truncated build diagnostic flag")
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
    expected_report = project(events_raw, stderr_raw, repo, contract_raw, contract_sha256, go_exit, event_check_exit)
    need(report == expected_report, "report does not match runner-private events/stderr/exits")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--output")
    modes.add_argument("--report")
    parser.add_argument("--events", required=True)
    parser.add_argument("--stderr", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--go-exit", required=True, type=int)
    parser.add_argument("--event-check-exit", required=True, type=int)
    args = parser.parse_args()
    contract_raw = safe_read(Path(args.contract), MAX_CONTRACT_BYTES)
    events_raw = safe_read(Path(args.events), MAX_EVENTS_BYTES)
    stderr_raw = safe_read_stderr(Path(args.stderr))
    repo = Path(args.repo)
    if args.output is not None:
        result = project(events_raw, stderr_raw, repo, contract_raw, args.contract_sha256, args.go_exit, args.event_check_exit)
        write_new(Path(args.output), json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
    else:
        result = verify_report(
            safe_read(Path(args.report), MAX_CONTRACT_BYTES),
            events_raw,
            stderr_raw,
            repo,
            contract_raw,
            args.contract_sha256,
            args.go_exit,
            args.event_check_exit,
        )
    print(json.dumps({"schema": result["schema"], "accepted": False, "failureClass": result["failureClass"]}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
