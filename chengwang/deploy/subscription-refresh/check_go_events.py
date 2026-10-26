"""Bounded verifier for the P207A seven-package ``go test -json`` stream."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


MAX_EVENTS_BYTES = 64 << 20
MAX_LINE_BYTES = 1 << 20
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ACTIONS = {"start", "run", "pause", "cont", "pass", "fail", "output", "skip"}


class EventError(AssertionError):
    pass


def need(value: bool, message: str) -> None:
    if not value:
        raise EventError(message)


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
        raise EventError("non-finite JSON number")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventError("invalid event JSON") from exc


def safe_read(path: Path, maximum: int) -> bytes:
    need(path.is_file() and not path.is_symlink(), "missing/non-regular input")
    raw = path.read_bytes()
    need(len(raw) <= maximum, "input exceeds budget")
    return raw


def write_new(path: Path, raw: bytes) -> None:
    need(path.parent.is_dir() and not path.parent.is_symlink(), "output parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            need(count > 0, "short output write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def expected(contract: dict) -> dict[str, list[str]]:
    need(contract.get("schema") == "chengwang.subscription-refresh-source/v3", "contract schema")
    go_test = contract.get("goTest")
    need(type(go_test) is dict and set(go_test) == {"packages", "goos", "goarch", "compiler", "goVersion", "cgoEnabled", "buildTags", "runPattern", "count", "timeoutSeconds"}, "Go test contract")
    need(type(go_test["packages"]) is list and len(go_test["packages"]) == len(set(go_test["packages"])), "Go packages")
    need(go_test["goos"] == "linux" and go_test["goarch"] == "amd64" and go_test["compiler"] == "gc" and go_test["goVersion"] == "go1.23.12" and go_test["cgoEnabled"] is False, "Go target")
    need(type(go_test["buildTags"]) is list and go_test["buildTags"] == sorted(set(go_test["buildTags"])), "Go build tags")
    need(go_test["runPattern"] == "^Test", "Go run pattern")
    need(type(go_test["count"]) is int and go_test["count"] == 1, "Go count")
    need(type(go_test["timeoutSeconds"]) is int and go_test["timeoutSeconds"] == 180, "Go timeout")
    packages = contract.get("packages")
    need(type(packages) is dict, "contract packages")
    need(list(packages) == go_test["packages"], "Go package order")
    result = {}
    for package, value in packages.items():
        need(type(package) is str and type(value) is dict, "contract package entry")
        names = value.get("requiredRunTops")
        need(type(names) is list and all(type(name) is str for name in names), "required run names")
        need(names == sorted(set(names)) and all(name.startswith(package + "::Test") for name in names), "required run set")
        result[package] = [name.split("::", 1)[1] for name in names]
    return result


def verify(events_raw: bytes, contract_raw: bytes, contract_sha256: str, go_exit: int) -> dict:
    need(type(go_exit) is int and go_exit == 0, "go test exit was not zero")
    need(type(contract_sha256) is str and DIGEST.fullmatch(contract_sha256) is not None, "contract digest")
    need(sha(contract_raw) == contract_sha256, "contract pin")
    contract = decode_json(contract_raw)
    wanted = expected(contract)
    begun = {package: [] for package in wanted}
    terminal = {package: {} for package in wanted}
    started = {package: False for package in wanted}
    package_terminal = {}
    lines = events_raw.splitlines()
    need(lines and len(lines) <= 1_000_000, "event line count")
    for raw_line in lines:
        need(0 < len(raw_line) <= MAX_LINE_BYTES, "event line budget")
        try:
            event = decode_json(raw_line)
        except EventError:
            raise
        need(type(event) is dict, "event object")
        action = event.get("Action")
        package = event.get("Package")
        test = event.get("Test")
        need(type(action) is str and action in ACTIONS, "event action")
        need(type(package) is str, "event package")
        need(package in wanted, "unexpected package")
        need(test is None or type(test) is str, "event test type")
        if test is None:
            if action == "start":
                need(not started[package] and package not in package_terminal, "duplicate/late package start")
                started[package] = True
                continue
            if action in {"pass", "fail", "skip"}:
                need(started[package] and package not in package_terminal, "duplicate/early package terminal")
                need(action == "pass", "package failure or skip")
                need(sorted(begun[package]) == wanted[package], "package terminal before all tests began")
                need(sorted(terminal[package]) == wanted[package], "package terminal before all tests passed")
                package_terminal[package] = action
                continue
            need(action == "output" and started[package] and package not in package_terminal, "package output outside lifetime")
            continue
        need(started[package] and package not in package_terminal, "test outside package lifetime")
        if action in {"fail", "skip"}:
            raise EventError("test failure or skip")
        if "/" in test:
            parent = test.split("/", 1)[0]
            need(parent in begun[package] and parent not in terminal[package], "subtest outside parent lifetime")
            continue
        need(re.fullmatch(r"Test[A-Za-z0-9_]+", test) is not None, "top test name")
        if action == "run":
            need(test not in begun[package], "duplicate test run")
            begun[package].append(test)
        elif action == "pass":
            need(test in begun[package] and test not in terminal[package], "unbegun/duplicate test terminal")
            terminal[package][test] = action
    for package, names in wanted.items():
        need(sorted(begun[package]) == names and len(begun[package]) == len(set(begun[package])), f"{package}: begun set")
        need(sorted(terminal[package]) == names and all(value == "pass" for value in terminal[package].values()), f"{package}: terminal set")
        need(package_terminal.get(package) == "pass", f"{package}: package terminal")
    return {
        "schema": "chengwang.subscription-refresh-go-events/v1",
        "scope": "SANITIZED_TOP_LEVEL_EVENTS_WITHOUT_OUTPUT_OR_TIMING",
        "contractSHA256": contract_sha256,
        "packageCount": len(wanted),
        "topLevelPassCount": sum(len(names) for names in wanted.values()),
        "skipCount": 0,
        "packageFailureCount": 0,
        "goExit": 0,
        "packages": [{"package": package, "passed": names} for package, names in wanted.items()],
    }


def verify_report(report_raw: bytes, contract_raw: bytes, contract_sha256: str) -> dict:
    report = decode_json(report_raw)
    need(
        type(report) is dict and tuple(report) == (
            "schema", "scope", "contractSHA256", "packageCount", "topLevelPassCount",
            "skipCount", "packageFailureCount", "goExit", "packages",
        ),
        "report shape",
    )
    need(report["schema"] == "chengwang.subscription-refresh-go-events/v1", "report schema")
    need(report["scope"] == "SANITIZED_TOP_LEVEL_EVENTS_WITHOUT_OUTPUT_OR_TIMING", "report scope")
    need(sha(contract_raw) == contract_sha256 == report["contractSHA256"], "report contract pin")
    wanted = expected(decode_json(contract_raw))
    package_rows = [{"package": package, "passed": names} for package, names in wanted.items()]
    need(report["packages"] == package_rows, "report package/test set")
    need(type(report["packageCount"]) is int and report["packageCount"] == len(wanted), "report package count")
    need(type(report["topLevelPassCount"]) is int and report["topLevelPassCount"] == sum(map(len, wanted.values())), "report top count")
    need(report["skipCount"] == 0 and report["packageFailureCount"] == 0 and report["goExit"] == 0, "report terminal state")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--events")
    modes.add_argument("--report")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--go-exit", type=int)
    parser.add_argument("--output")
    args = parser.parse_args()
    contract_raw = safe_read(Path(args.contract), 8 << 20)
    if args.events is not None:
        need(args.go_exit is not None and args.output is not None, "producer arguments")
        result = verify(safe_read(Path(args.events), MAX_EVENTS_BYTES), contract_raw, args.contract_sha256, args.go_exit)
        raw = json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        write_new(Path(args.output), raw)
    else:
        need(args.go_exit is None and args.output is None, "reader arguments")
        result = verify_report(safe_read(Path(args.report), 8 << 20), contract_raw, args.contract_sha256)
    print(json.dumps({"schema": result["schema"], "packageCount": result["packageCount"], "topLevelPassCount": result["topLevelPassCount"], "accepted": True}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
