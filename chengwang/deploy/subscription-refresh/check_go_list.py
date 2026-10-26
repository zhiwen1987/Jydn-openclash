"""Verify official ``go list -json`` file selection for the P207A lane."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re


MAX_INPUT = 16 << 20
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ListError(AssertionError):
    pass


def need(value: bool, message: str) -> None:
    if not value:
        raise ListError(message)


def pairs(values):
    result = {}
    for key, value in values:
        need(type(key) is str and key not in result, "duplicate/non-string JSON key")
        result[key] = value
    return result


def constant(_value):
    raise ListError("non-finite JSON number")


def decode_one(raw: bytes) -> object:
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ListError("invalid JSON") from exc


def decode_stream(raw: bytes) -> list[dict]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ListError("go list output is not utf-8") from exc
    decoder = json.JSONDecoder(object_pairs_hook=pairs, parse_constant=constant)
    index = 0
    values = []
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise ListError("invalid go list JSON stream") from exc
        need(type(value) is dict, "go list item")
        values.append(value)
    need(values, "empty go list stream")
    return values


def safe_read(path: Path) -> bytes:
    need(path.is_file() and not path.is_symlink(), "missing/non-regular input")
    raw = path.read_bytes()
    need(len(raw) <= MAX_INPUT, "input exceeds budget")
    return raw


def contract_packages(contract: dict) -> dict[str, list[str]]:
    go_test = contract.get("goTest")
    packages = contract.get("packages")
    need(type(go_test) is dict and type(packages) is dict, "contract shape")
    need(go_test.get("goos") == "linux" and go_test.get("goarch") == "amd64" and go_test.get("compiler") == "gc" and go_test.get("cgoEnabled") is False, "contract Go target")
    need(go_test.get("goVersion") == "go1.23.12", "contract Go version")
    order = go_test.get("packages")
    need(type(order) is list and order == list(packages), "contract package order")
    result = {}
    for package in order:
        value = packages[package]
        files = value.get("requiredRunTestFiles") if type(value) is dict else None
        need(type(files) is list and files == sorted(set(files)), "contract run files")
        need(all(PurePosixPath(path).parent.as_posix() == package and path.endswith("_test.go") for path in files), "contract run file path")
        result[package] = files
    return result


def verify(list_raw: bytes, env_raw: bytes, contract_raw: bytes, contract_sha256: str) -> dict:
    import hashlib
    need(type(contract_sha256) is str and DIGEST.fullmatch(contract_sha256) is not None, "contract digest")
    need(hashlib.sha256(contract_raw).hexdigest() == contract_sha256, "contract pin")
    contract = decode_one(contract_raw)
    wanted = contract_packages(contract)
    environment = decode_one(env_raw)
    need(type(environment) is dict and set(environment) == {"CGO_ENABLED", "GOARCH", "GOOS", "GOVERSION"}, "Go env shape")
    need(environment == {"CGO_ENABLED": "0", "GOARCH": "amd64", "GOOS": "linux", "GOVERSION": "go1.23.12"}, "Go env target")
    observed = {}
    for value in decode_stream(list_raw):
        package = value.get("ImportPath")
        need(type(package) is str and package in wanted and package not in observed, "unexpected/duplicate package")
        names = []
        for key in ("TestGoFiles", "XTestGoFiles"):
            files = value.get(key, [])
            need(type(files) is list and all(type(name) is str for name in files), "go list test files")
            for name in files:
                need(name == PurePosixPath(name).name and name.endswith("_test.go"), "go list basename")
                names.append(package + "/" + name)
        need(len(names) == len(set(names)), "duplicate selected test file")
        observed[package] = sorted(names)
    need(list(observed) == list(wanted), "go list package order/set")
    need(observed == wanted, "official selected test-file set")
    return {
        "schema": "chengwang.subscription-refresh-go-list/v1",
        "scope": "OFFICIAL_GO_LIST_FILE_SELECTION_NOT_TEST_EXECUTION",
        "contractSHA256": contract_sha256,
        "goos": "linux",
        "goarch": "amd64",
        "compiler": "gc",
        "goVersion": "go1.23.12",
        "cgoEnabled": False,
        "packages": [{"package": package, "testFiles": files} for package, files in wanted.items()],
    }


def verify_report(report_raw: bytes, contract_raw: bytes, contract_sha256: str) -> dict:
    report = decode_one(report_raw)
    wanted = contract_packages(decode_one(contract_raw))
    need(type(report) is dict and tuple(report) == ("schema", "scope", "contractSHA256", "goos", "goarch", "compiler", "goVersion", "cgoEnabled", "packages"), "report shape")
    need(report["schema"] == "chengwang.subscription-refresh-go-list/v1" and report["scope"] == "OFFICIAL_GO_LIST_FILE_SELECTION_NOT_TEST_EXECUTION", "report schema/scope")
    import hashlib
    need(hashlib.sha256(contract_raw).hexdigest() == contract_sha256 == report["contractSHA256"], "report contract pin")
    need(report["goos"] == "linux" and report["goarch"] == "amd64" and report["compiler"] == "gc" and report["goVersion"] == "go1.23.12" and report["cgoEnabled"] is False, "report target")
    need(report["packages"] == [{"package": package, "testFiles": files} for package, files in wanted.items()], "report packages")
    return report


def write_new(path: Path, raw: bytes) -> None:
    need(path.parent.is_dir() and not path.parent.is_symlink(), "output parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            need(count > 0, "short output write")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--go-list")
    modes.add_argument("--report")
    parser.add_argument("--go-env")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    contract_raw = safe_read(Path(args.contract))
    if args.go_list is not None:
        need(args.go_env is not None and args.output is not None, "producer arguments")
        result = verify(safe_read(Path(args.go_list)), safe_read(Path(args.go_env)), contract_raw, args.contract_sha256)
        write_new(Path(args.output), json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
    else:
        need(args.go_env is None and args.output is None, "reader arguments")
        result = verify_report(safe_read(Path(args.report)), contract_raw, args.contract_sha256)
    print(json.dumps({"schema": result["schema"], "packageCount": len(result["packages"]), "accepted": True}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
