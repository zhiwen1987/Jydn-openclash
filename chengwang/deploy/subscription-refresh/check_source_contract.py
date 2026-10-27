"""Verify the closed P207A source and Go test-declaration contract.

The closure is conservative rather than a claim that Python reconstructed the
Go build graph: every tracked non-deploy/non-document module-tree input is
bound, together with declared non-Go fixtures discovered from source and an
explicit fixture set. Expected digests are supplied by the workflow as well as
by the contract.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess


SCHEMA = "chengwang.subscription-refresh-source/v3"
SCOPE = "CONSERVATIVE_TRACKED_SOURCE_CLOSURE_NOT_GO_DEPENDENCY_GRAPH_OR_EXECUTION"
PACKAGE_NAMES = (
    "chengwang/internal/api",
    "chengwang/internal/authn",
    "chengwang/internal/authz",
    "chengwang/internal/serverruntime",
    "chengwang/internal/subscription",
    "chengwang/internal/subscriptionctl",
    "chengwang/internal/subscriptionpolicy",
)
MODULE_METADATA = ("chengwang/go.mod", "chengwang/go.sum", "chengwang/vendor/modules.txt")
GATE_FILES = (
    ".github/workflows/chengwang-subscription-refresh.yml",
    "chengwang/deploy/subscription-refresh/check_go_events.py",
    "chengwang/deploy/subscription-refresh/check_go_failure.py",
    "chengwang/deploy/subscription-refresh/check_go_list.py",
    "chengwang/deploy/subscription-refresh/check_source_contract.py",
    "chengwang/deploy/subscription-refresh/source_contract.json",
    "chengwang/deploy/subscription-refresh/test_go_events.py",
    "chengwang/deploy/subscription-refresh/test_go_failure.py",
    "chengwang/deploy/subscription-refresh/test_go_list.py",
    "chengwang/deploy/subscription-refresh/test_source_contract.py",
)
SOURCE_MODEL_FILES = (
    "test_source_contract.py",
    "test_go_events.py",
    "test_go_failure.py",
    "test_go_list.py",
)
TEST = re.compile(
    r"^func\s+(Test[A-Za-z0-9_]+)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s+\*testing\.T\s*\)\s*\{",
    re.M,
)
EMBED = re.compile(r"^\s*//go:embed\s+(.+?)\s*$", re.M)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ACCEPTED_GATE_LINES = (
    'test "$formatCode" = 0',
    'test -f "$out/gofmt.patch"',
    'test ! -s "$out/gofmt.patch"',
    'test -f "$out/gofmt.stderr"',
    'test ! -s "$out/gofmt.stderr"',
    'test "$code" = 0',
    'test "$eventCode" = 0',
    'test "$failureCode" = 0',
    'test -f "$out/go.stderr"',
    'test ! -s "$out/go.stderr"',
    'test -s "$out/source-before.json"',
    'test -s "$out/source-after.json"',
    'test -s "$out/go-list-report.json"',
    'test -s "$out/go-events-report.json"',
    'test -s "$out/format-exit.txt"',
    'test -s "$out/go-exit.txt"',
    'test -s "$out/event-check-exit.txt"',
    'test "$(cat "$out/format-exit.txt")" = 0',
    'test "$(cat "$out/go-exit.txt")" = 0',
    'test "$(cat "$out/event-check-exit.txt")" = 0',
)
FRESH_GATE_LINES = (
    'test -s "$root/source-before.json"',
    'test -s "$root/source-after.json"',
    'test -s "$root/go-list-report.json"',
    'test -s "$root/go-events-report.json"',
    'test -s "$root/format-exit.txt"',
    'test -s "$root/go-exit.txt"',
    'test -s "$root/event-check-exit.txt"',
    'test -f "$root/gofmt.patch"',
    'test ! -s "$root/gofmt.patch"',
    'test -f "$root/gofmt.stderr"',
    'test ! -s "$root/gofmt.stderr"',
    'test "$(cat "$root/format-exit.txt")" = 0',
    'test "$(cat "$root/go-exit.txt")" = 0',
    'test "$(cat "$root/event-check-exit.txt")" = 0',
)


class ContractError(AssertionError):
    pass


def need(value: bool, message: str) -> None:
    if not value:
        raise ContractError(message)


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
        raise ContractError("non-finite JSON number")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("invalid contract JSON") from exc


def strict_int(value: object, minimum: int = 0) -> int:
    need(type(value) is int and value >= minimum, "invalid integer")
    return value


def strict_digest(value: object) -> str:
    need(type(value) is str and DIGEST.fullmatch(value) is not None, "invalid sha256")
    return value


def exact_keys(value: object, keys: tuple[str, ...], where: str) -> dict:
    need(type(value) is dict and tuple(value) == keys, f"{where}: keys/order")
    return value


def sorted_unique_strings(value: object, where: str) -> list[str]:
    need(type(value) is list and all(type(item) is str for item in value), f"{where}: strings")
    need(value == sorted(set(value)), f"{where}: sorted unique")
    return value


def safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    need(value == path.as_posix() and not path.is_absolute(), "non-canonical path")
    need(value != "" and ".." not in path.parts and "." not in path.parts, "unsafe path")
    return value


def read_bound(root: Path, relative: str) -> bytes:
    relative = safe_relative(relative)
    path = root.joinpath(*PurePosixPath(relative).parts)
    need(path.is_file() and not path.is_symlink(), f"missing/non-regular source: {relative}")
    resolved = path.resolve()
    need(resolved.is_relative_to(root), f"source escapes root: {relative}")
    return path.read_bytes()


def git_tracked(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "-c", "core.quotepath=false", "ls-files", "-z", "--", "chengwang"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    need(proc.returncode == 0 and proc.stderr == b"", "git ls-files failed")
    try:
        paths = [item.decode("utf-8") for item in proc.stdout.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise ContractError("tracked path is not utf-8") from exc
    need(paths == sorted(set(paths)), "tracked paths are not sorted unique")
    return paths


def module_paths(tracked: list[str]) -> list[str]:
    selected = [
        path for path in tracked
        if path.startswith("chengwang/")
        and not path.startswith("chengwang/deploy/")
        and not path.startswith("chengwang/docs/")
    ]
    need(all(path.startswith("chengwang/") for path in selected), "module path escaped")
    need(all(path in tracked for path in MODULE_METADATA), "module metadata missing")
    need(all(path in selected for path in MODULE_METADATA), "module metadata excluded")
    return selected


def source_aggregate(root: Path, paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        raw = read_bound(root, relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha(raw).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def names_digest(names: list[str]) -> str:
    return sha("\n".join(names).encode("utf-8"))


def source_model_names(root: Path) -> list[str]:
    gate = PurePosixPath("chengwang/deploy/subscription-refresh")
    names: list[str] = []
    for filename in SOURCE_MODEL_FILES:
        try:
            tree = ast.parse(read_bound(root, (gate / filename).as_posix()).decode("utf-8"))
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ContractError("source model AST") from exc
        names.extend(
            filename + "::" + method.name
            for item in tree.body
            if isinstance(item, ast.ClassDef)
            for method in item.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_")
        )
    names.sort()
    need(len(names) == len(set(names)), "source model names duplicate")
    return names


def source_model_inventory(text: str, files: tuple[str, ...]) -> list[str]:
    need(type(text) is str and type(files) is tuple, "source model log inputs")
    observed: list[str] = []
    for filename in files:
        need(type(filename) is str and re.fullmatch(r"test_[A-Za-z0-9_]+\.py", filename) is not None,
             "source model filename")
        stem = filename.removesuffix(".py")
        pattern = re.compile(
            r"^(?P<name>test_[A-Za-z0-9_]+) \((?:[A-Za-z0-9_]+\.)?" +
            re.escape(stem) +
            r"\.[A-Za-z0-9_]+(?:\.(?P=name))?\) \.\.\. ok$",
            re.M,
        )
        observed.extend(filename + "::" + match.group("name") for match in pattern.finditer(text))
    return observed


def verify_source_model_log(text: str, files: tuple[str, ...], expected: list[str]) -> None:
    need(type(expected) is list and expected == sorted(set(expected)), "source model expected names")
    observed = source_model_inventory(text, files)
    result_lines = re.findall(r"^test_[A-Za-z0-9_]+ \([^\r\n()]+\) \.\.\. ok$", text, re.M)
    need(sorted(observed) == expected and len(observed) == len(expected), "source model result inventory")
    need(len(result_lines) == len(expected), "source model extra/unrecognized result")
    need(re.findall(r"^Ran ([0-9]+) tests in [0-9.]+s$", text, re.M) == [str(len(expected))],
         "source model ran count")
    need(re.findall(r"^OK$", text, re.M) == ["OK"], "source model final status")
    need(re.search(r"^FAILED|^ERROR:|^FAIL:|\.\.\. skipped|^OK \(skipped=", text, re.M) is None,
         "source model failure/skip")


def map_digest(values: dict[str, str]) -> str:
    raw = b"".join(path.encode("utf-8") + b"\0" + value.encode("ascii") + b"\n" for path, value in values.items())
    return sha(raw)


def package_observation(root: Path, tracked: list[str], package: str) -> tuple[list[str], list[str], dict[str, list[str]]]:
    files = [path for path in tracked if PurePosixPath(path).parent.as_posix() == package and path.endswith("_test.go")]
    names: list[str] = []
    by_file: dict[str, list[str]] = {}
    for relative in files:
        try:
            text = read_bound(root, relative).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"non-utf8 test source: {relative}") from exc
        file_names = sorted(package + "::" + item for item in TEST.findall(text))
        by_file[relative] = file_names
        names.extend(file_names)
    names.sort()
    need(len(names) == len(set(names)), f"duplicate test top in {package}")
    return files, names, by_file


def load_foundation(root: Path, relative: str):
    path = root.joinpath(*PurePosixPath(safe_relative(relative)).parts)
    spec = importlib.util.spec_from_file_location("p207a_foundation_checker", path)
    need(spec is not None and spec.loader is not None, "foundation checker import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(hasattr(module, "FILES") and hasattr(module, "required_names"), "foundation checker interface")
    sources = {name: read_bound(root, name) for name in module.FILES}
    required = module.required_names(sources)
    need(type(required) is dict, "foundation required_names shape")
    names = sorted(package + "::" + name for package, package_names in required.items() for name in package_names)
    need(len(names) == len(set(names)), "foundation names duplicate")
    return module, names


def observed_embed_paths(root: Path, tracked: list[str], go_paths: list[str]) -> list[str]:
    observed: list[str] = []
    for relative in go_paths:
        raw = read_bound(root, relative)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"non-utf8 Go source: {relative}") from exc
        directory = PurePosixPath(relative).parent
        for expression in EMBED.findall(text):
            try:
                patterns = shlex.split(expression)
            except ValueError as exc:
                raise ContractError("invalid go:embed expression") from exc
            for source_pattern in patterns:
                pattern = source_pattern[4:] if source_pattern.startswith("all:") else source_pattern
                need(pattern != "" and not pattern.startswith("/"), "unsafe go:embed pattern")
                candidate = (directory / pattern).as_posix()
                exact = candidate in tracked
                prefix = candidate.rstrip("/") + "/"
                matches = [
                    path for path in tracked
                    if path == candidate
                    or path.startswith(prefix)
                    or (PurePosixPath(path).parent == directory and PurePosixPath(path).match(candidate))
                ]
                need(exact or matches, "go:embed pattern has no tracked source")
                observed.extend(matches or [candidate])
    return sorted(set(observed))


def automatic_fixture_paths(root: Path, tracked: list[str], go_paths: list[str]) -> list[str]:
    package_prefixes = tuple(package + "/" for package in PACKAGE_NAMES)
    package_non_go = [
        path for path in tracked
        if path.startswith(package_prefixes) and not path.endswith(".go")
    ]
    return sorted(set(package_non_go) | set(observed_embed_paths(root, tracked, [path for path in go_paths if path.endswith(".go")])))


def workflow_gate_script(text: str, name: str, expected: tuple[str, ...]) -> str:
    need(type(text) is str and re.fullmatch(r"P207A_[A-Z_]+_GATE", name) is not None, "workflow gate inputs")
    pattern = re.compile(
        r"^          # BEGIN " + re.escape(name) + r"\n"
        r"(?P<body>(?:^          [^\n]+\n)+)"
        r"^          # END " + re.escape(name) + r"$",
        re.M,
    )
    matches = list(pattern.finditer(text))
    need(len(matches) == 1, "workflow fixed gate markers")
    lines = tuple(line.removeprefix("          ") for line in matches[0].group("body").splitlines())
    need(lines == expected, "workflow fixed gate commands")
    return "set -euo pipefail\n" + "\n".join(lines) + "\n"


def workflow_accepted_gate_script(text: str) -> str:
    return workflow_gate_script(text, "P207A_ACCEPTED_GATE", ACCEPTED_GATE_LINES)


def workflow_upload_paths(text: str) -> dict[str, tuple[str, ...]]:
    blocks = re.findall(r"(?ms)^      - (?P<body>.*?)(?=^      - |^  [A-Za-z0-9_-]+:|\Z)", text)
    uploads: dict[str, tuple[str, ...]] = {}
    for block in blocks:
        if "uses: actions/upload-artifact@" not in block:
            continue
        name_match = re.search(r"^          name: (.+)$", block, re.M)
        need(name_match is not None, "workflow upload artifact name")
        name = name_match.group(1)
        need(name not in uploads, "workflow duplicate upload artifact name")
        lines = block.splitlines()
        paths: list[str] = []
        for index, line in enumerate(lines):
            if not line.startswith("          path:"):
                continue
            value = line.removeprefix("          path:").strip()
            if value not in ("", "|"):
                paths.append(value)
                continue
            for continuation in lines[index + 1:]:
                if continuation.startswith("            "):
                    paths.append(continuation.strip())
                    continue
                break
        need(paths, "workflow upload artifact paths")
        need(
            all("go-events.private.jsonl" not in path and not path.endswith("/go.stderr") for path in paths),
            "workflow upload exposes private Go stream",
        )
        need(all(not any(marker in path for marker in ("*", "?", "[")) for path in paths), "workflow upload path must be explicit")
        uploads[name] = tuple(paths)
    return uploads


def verify_workflow_surface(root: Path, changed_paths: list[str], packages: tuple[str, ...]) -> None:
    raw = read_bound(root, ".github/workflows/chengwang-subscription-refresh.yml")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("workflow is not utf-8") from exc
    need("\r" not in text, "workflow must be LF")
    accepted_gate = workflow_accepted_gate_script(text)
    fresh_gate = workflow_gate_script(text, "P207A_FRESH_GATE", FRESH_GATE_LINES)
    need("&&" not in accepted_gate and "&&" not in fresh_gate, "workflow fixed gates must not use AND lists")
    model_names = source_model_names(root)
    model_digest = names_digest(model_names)
    need(text.count(f"          assert len(names)==len(set(names))=={len(model_names)}\n") == 1,
         "workflow source-model count pin")
    need(text.count("          assert hashlib.sha256('\\n'.join(names).encode()).hexdigest()=="
                    f"'{model_digest}'\n") == 1, "workflow source-model names pin")
    need(text.count(f"          print('P207A_SOURCE_MODELS=PASS count={len(model_names)} go_execution_proven=false')\n") == 1,
         "workflow source-model result pin")
    match = re.search(r"^          fmt=\(\n(?P<body>(?:^            [^\n]+\n)+)^          \)$", text, re.M)
    need(match is not None, "workflow formatter block")
    observed = [line.strip() for line in match.group("body").splitlines()]
    need(observed == changed_paths, "workflow formatter paths are not the exact changed-Go set")
    relative_packages = ["./" + package.removeprefix("chengwang/") for package in packages]
    logical = re.sub(r"[ \t]*\\\n[ \t]*", " ", text)
    package_args = " ".join(relative_packages)
    need(logical.count("go list -json ") == 1, "workflow must have one Go list selection")
    need(logical.count("go test -json -count=1 -timeout=180s -run '^Test' ") == 1, "workflow must have one Go test selection")
    need(
        len(re.findall(r"^\s*go list -json " + re.escape(package_args) + r" > ", logical, re.M)) == 1,
        "workflow go-list command/package order",
    )
    need(
        len(re.findall(r"^\s*go test -json -count=1 -timeout=180s -run '\^Test' " + re.escape(package_args) + r" > ", logical, re.M)) == 1,
        "workflow go-test command/package order",
    )
    need("GOOS: linux" in text and "GOARCH: amd64" in text and "CGO_ENABLED: '0'" in text, "workflow target")
    markers = (
        '          set +e\n          gofmt -d "${fmt[@]}" > "$out/gofmt.patch" 2> "$out/gofmt.stderr"\n          formatCode=$?',
        "          go test -json -count=1 -timeout=180s -run '^Test' ",
        '          code=$?',
        '          cd "$GITHUB_WORKSPACE"\n          set -e',
        '          printf \'%s\\n\' "$formatCode" > "$out/format-exit.txt"',
        '          printf \'%s\\n\' "$code" > "$out/go-exit.txt"',
        '          verify_source > "$out/source-after.json"',
        '          cmp "$out/source-before.json" "$out/source-after.json"',
        '          set +e\n          python3 -I -B chengwang/deploy/subscription-refresh/check_go_events.py',
        '          eventCode=$?\n          set -e',
        '          printf \'%s\\n\' "$eventCode" > "$out/event-check-exit.txt"',
        '          failureCode=0',
        '          if test "$code" != 0 || test "$eventCode" != 0; then',
        '            python3 -I -B chengwang/deploy/subscription-refresh/check_go_failure.py',
        '--events "$out/go-events.private.jsonl" --stderr "$out/go.stderr" --repo "$GITHUB_WORKSPACE"',
        '--go-exit "$code" --event-check-exit "$eventCode"',
        '--output "$out/go-failure-report.json"',
        '--report "$out/go-failure-report.json" --events "$out/go-events.private.jsonl"',
        '--stderr "$out/go.stderr" --repo "$GITHUB_WORKSPACE"',
        '--go-exit "$code" --event-check-exit "$eventCode" --contract "$CONTRACT"',
        '          printf \'%s\\n\' "$failureCode" > "$out/failure-check-exit.txt"',
        '          # BEGIN P207A_ACCEPTED_GATE',
        '          test "$formatCode" = 0',
        '          test -f "$out/gofmt.patch"',
        '          test ! -s "$out/gofmt.patch"',
        '          test -f "$out/gofmt.stderr"',
        '          test ! -s "$out/gofmt.stderr"',
        '          test "$code" = 0',
        '          test "$eventCode" = 0',
        '          test "$failureCode" = 0',
        '          test -f "$out/go.stderr"',
        '          test ! -s "$out/go.stderr"',
        '          test -s "$out/go-events-report.json"',
        '          # END P207A_ACCEPTED_GATE',
    )
    cursor = -1
    for marker in markers:
        cursor = text.find(marker, cursor + 1)
        need(cursor >= 0, "workflow capture/final-gate order")
    go_test_at = text.index("          go test -json -count=1 -timeout=180s -run '^Test' ")
    format_gate = '          test ! -s "$out/gofmt.patch"'
    need(text.find(format_gate) > go_test_at, "workflow formatting gate must follow Go execution")
    accepted_upload = "          name: p207a-source-go-${{ github.run_id }}-${{ github.run_attempt }}"
    accepted_upload_at = text.find(accepted_upload)
    need(accepted_upload_at >= 0, "workflow accepted artifact identity missing")
    need(text.find("          # END P207A_ACCEPTED_GATE") < accepted_upload_at,
         "workflow accepted gate must precede upload")
    need(text.find("          # END P207A_FRESH_GATE") < text.find('          cmp "$root/source-before.json" "$root/source-after.json"'),
         "workflow fresh gate must precede report reads")
    for required_private in (
        '> "$out/go-events.private.jsonl" 2> "$out/go.stderr"',
        '--events "$out/go-events.private.jsonl"',
        '--stderr "$out/go.stderr"',
    ):
        need(required_private in text, "workflow private Go stream remains runner-local")
    for required_original in (
        '${{ runner.temp }}/p207a-refresh/format-exit.txt',
        '${{ runner.temp }}/p207a-refresh/go-exit.txt',
        '${{ runner.temp }}/p207a-refresh/event-check-exit.txt',
        '${{ runner.temp }}/p207a-refresh/failure-check-exit.txt',
    ):
        need(required_original in text, "workflow failure originals")
    expected_uploads = {
        "p207a-source-models-${{ github.run_id }}-${{ github.run_attempt }}": (
            "chengwang/deploy/subscription-refresh/source-models.log",
        ),
        "p207a-source-go-${{ github.run_id }}-${{ github.run_attempt }}": (
            "${{ runner.temp }}/p207a-refresh/source-before.json",
            "${{ runner.temp }}/p207a-refresh/source-after.json",
            "${{ runner.temp }}/p207a-refresh/go-list-report.json",
            "${{ runner.temp }}/p207a-refresh/go-events-report.json",
            "${{ runner.temp }}/p207a-refresh/format-exit.txt",
            "${{ runner.temp }}/p207a-refresh/go-exit.txt",
            "${{ runner.temp }}/p207a-refresh/event-check-exit.txt",
            "${{ runner.temp }}/p207a-refresh/gofmt.patch",
            "${{ runner.temp }}/p207a-refresh/gofmt.stderr",
        ),
        "p207a-source-go-failure-${{ github.run_id }}-${{ github.run_attempt }}": (
            "${{ runner.temp }}/p207a-refresh/source-before.json",
            "${{ runner.temp }}/p207a-refresh/source-after.json",
            "${{ runner.temp }}/p207a-refresh/format-exit.txt",
            "${{ runner.temp }}/p207a-refresh/go-exit.txt",
            "${{ runner.temp }}/p207a-refresh/event-check-exit.txt",
            "${{ runner.temp }}/p207a-refresh/failure-check-exit.txt",
            "${{ runner.temp }}/p207a-refresh/go-failure-report.json",
            "${{ runner.temp }}/p207a-refresh/gofmt.patch",
            "${{ runner.temp }}/p207a-refresh/gofmt.stderr",
        ),
    }
    need(workflow_upload_paths(text) == expected_uploads, "workflow upload artifact path sets")


def verify(root: Path, contract_relative: str, pins: dict) -> dict:
    root = root.resolve()
    exact_keys(
        pins,
        (
            "contractSHA256", "checkerSHA256", "modelSHA256", "eventCheckerSHA256", "eventModelSHA256",
            "failureCheckerSHA256", "failureModelSHA256", "goListCheckerSHA256", "goListModelSHA256", "moduleCount", "moduleSHA256",
            "fixtureCount", "fixtureSHA256", "testTopCount", "testTopsSHA256",
            "runTopCount", "runTopsSHA256", "changedGoCount", "changedGoSHA256",
        ),
        "workflow pins",
    )
    contract_raw = read_bound(root, contract_relative)
    need(sha(contract_raw) == strict_digest(pins["contractSHA256"]), "workflow contract pin")
    contract = decode_json(contract_raw)
    exact_keys(
        contract,
        (
            "schema", "scope", "authoringBaseCommit", "moduleClosure", "fixtureClosure",
            "changedGoSources", "changedGoSourcesSHA256", "goTest", "packages", "allPackageTestTopCount",
            "allPackageTestTopsSHA256", "allRequiredRunTopCount", "allRequiredRunTopsSHA256",
            "p207aAddedTestTopCount", "p207aAddedTestTopsSHA256", "p207aAddedTestTops",
            "baselinePackageTestTopCount", "baselinePackageTestTopsSHA256",
            "baselineRequiredRunTopCount", "baselineRequiredRunTopsSHA256", "foundation",
        ),
        "contract",
    )
    need(contract["schema"] == SCHEMA and contract["scope"] == SCOPE, "schema/scope")
    need(type(contract["authoringBaseCommit"]) is str and re.fullmatch(r"[0-9a-f]{40}", contract["authoringBaseCommit"]), "base commit")
    go_test = exact_keys(contract["goTest"], ("packages", "goos", "goarch", "compiler", "goVersion", "cgoEnabled", "buildTags", "runPattern", "count", "timeoutSeconds"), "goTest")
    need(tuple(go_test["packages"]) == PACKAGE_NAMES, "Go package order")
    need(go_test["goos"] == "linux" and go_test["goarch"] == "amd64" and go_test["compiler"] == "gc" and go_test["goVersion"] == "go1.23.12" and go_test["cgoEnabled"] is False, "Go target")
    sorted_unique_strings(go_test["buildTags"], "goTest.buildTags")
    need(go_test["runPattern"] == "^Test", "Go run pattern")
    need(strict_int(go_test["count"], 1) == 1 and strict_int(go_test["timeoutSeconds"], 1) == 180, "Go count/timeout")

    gate_dir = PurePosixPath(contract_relative).parent
    need(sha(read_bound(root, (gate_dir / "check_source_contract.py").as_posix())) == strict_digest(pins["checkerSHA256"]), "workflow checker pin")
    need(sha(read_bound(root, (gate_dir / "test_source_contract.py").as_posix())) == strict_digest(pins["modelSHA256"]), "workflow model pin")
    need(sha(read_bound(root, (gate_dir / "check_go_events.py").as_posix())) == strict_digest(pins["eventCheckerSHA256"]), "workflow event checker pin")
    need(sha(read_bound(root, (gate_dir / "test_go_events.py").as_posix())) == strict_digest(pins["eventModelSHA256"]), "workflow event model pin")
    need(sha(read_bound(root, (gate_dir / "check_go_failure.py").as_posix())) == strict_digest(pins["failureCheckerSHA256"]), "workflow failure checker pin")
    need(sha(read_bound(root, (gate_dir / "test_go_failure.py").as_posix())) == strict_digest(pins["failureModelSHA256"]), "workflow failure model pin")
    need(sha(read_bound(root, (gate_dir / "check_go_list.py").as_posix())) == strict_digest(pins["goListCheckerSHA256"]), "workflow go-list checker pin")
    need(sha(read_bound(root, (gate_dir / "test_go_list.py").as_posix())) == strict_digest(pins["goListModelSHA256"]), "workflow go-list model pin")

    tracked = git_tracked(root)
    observed_module_paths = module_paths(tracked)
    module = exact_keys(contract["moduleClosure"], ("pathCount", "pathsSHA256", "contentSHA256"), "moduleClosure")
    need(strict_int(module["pathCount"], 1) == strict_int(pins["moduleCount"], 1) == len(observed_module_paths), "module path count")
    need(names_digest(observed_module_paths) == strict_digest(module["pathsSHA256"]), "module path-set pin")
    module_sha = source_aggregate(root, observed_module_paths)
    need(module_sha == strict_digest(module["contentSHA256"]) == strict_digest(pins["moduleSHA256"]), "module aggregate pin")

    fixture = exact_keys(contract["fixtureClosure"], ("additionalPaths", "paths", "pathCount", "pathsSHA256", "contentSHA256"), "fixtureClosure")
    additional_paths = sorted_unique_strings(fixture["additionalPaths"], "fixtureClosure.additionalPaths")
    fixture_paths = sorted_unique_strings(fixture["paths"], "fixtureClosure.paths")
    need(all(path in tracked and path.startswith("chengwang/") and not path.endswith(".go") for path in additional_paths), "additional fixture invalid")
    need(all("/docs/" not in path and "/evidence/" not in path and path not in GATE_FILES for path in additional_paths), "docs/evidence/gate cannot be fixture")
    automatic = automatic_fixture_paths(root, tracked, observed_module_paths)
    need(fixture_paths == sorted(set(automatic) | set(additional_paths)), "fixture closure is not exact")
    need(strict_int(fixture["pathCount"]) == strict_int(pins["fixtureCount"]) == len(fixture_paths), "fixture count")
    need(names_digest(fixture_paths) == strict_digest(fixture["pathsSHA256"]), "fixture path-set pin")
    fixture_sha = source_aggregate(root, fixture_paths)
    need(fixture_sha == strict_digest(fixture["contentSHA256"]) == strict_digest(pins["fixtureSHA256"]), "fixture aggregate pin")

    changed = contract["changedGoSources"]
    need(type(changed) is dict and list(changed) == sorted(changed), "changed Go map order")
    need(len(changed) == strict_int(pins["changedGoCount"], 1), "changed Go count")
    for relative, expected in changed.items():
        need(relative.endswith(".go") and relative in observed_module_paths, "changed Go path not tracked")
        need(sha(read_bound(root, relative)) == strict_digest(expected), f"changed Go source: {relative}")
    changed_sha = map_digest(changed)
    need(changed_sha == strict_digest(contract["changedGoSourcesSHA256"]) == strict_digest(pins["changedGoSHA256"]), "changed Go map pin")
    verify_workflow_surface(root, list(changed), PACKAGE_NAMES)

    packages = contract["packages"]
    need(type(packages) is dict and tuple(packages) == PACKAGE_NAMES, "package set/order")
    all_names: list[str] = []
    all_run_names: list[str] = []
    for package in PACKAGE_NAMES:
        declared = exact_keys(
            packages[package],
            (
                "testFiles", "requiredRunTestFiles", "excludedRunTestFiles", "sourceTestTopCount", "sourceTestTopsSHA256", "sourceTestTops",
                "requiredRunTopCount", "requiredRunTopsSHA256", "requiredRunTops", "excludedRunTops",
            ),
            package,
        )
        files = sorted_unique_strings(declared["testFiles"], package + ".testFiles")
        run_files = sorted_unique_strings(declared["requiredRunTestFiles"], package + ".requiredRunTestFiles")
        excluded_files = sorted_unique_strings(declared["excludedRunTestFiles"], package + ".excludedRunTestFiles")
        names = sorted_unique_strings(declared["sourceTestTops"], package + ".sourceTestTops")
        required_run = sorted_unique_strings(declared["requiredRunTops"], package + ".requiredRunTops")
        excluded_run = sorted_unique_strings(declared["excludedRunTops"], package + ".excludedRunTops")
        observed_files, observed_names, names_by_file = package_observation(root, tracked, package)
        need(files == observed_files, f"{package}: exact test-file set")
        need(not set(run_files).intersection(excluded_files) and sorted(run_files + excluded_files) == files, f"{package}: run file partition")
        need(names == observed_names, f"{package}: exact test-top set")
        need(strict_int(declared["sourceTestTopCount"]) == len(names), f"{package}: source test count")
        need(strict_digest(declared["sourceTestTopsSHA256"]) == names_digest(names), f"{package}: source test hash")
        expected_run = sorted(name for path in run_files for name in names_by_file[path])
        expected_excluded = sorted(name for path in excluded_files for name in names_by_file[path])
        need(required_run == expected_run and excluded_run == expected_excluded, f"{package}: run top/file binding")
        need(strict_int(declared["requiredRunTopCount"]) == len(required_run), f"{package}: run count")
        need(strict_digest(declared["requiredRunTopsSHA256"]) == names_digest(required_run), f"{package}: run hash")
        all_names.extend(names)
        all_run_names.extend(required_run)
    all_names.sort()
    all_run_names.sort()
    need(len(all_names) == len(set(all_names)), "cross-package duplicate test top")
    need(strict_int(contract["allPackageTestTopCount"]) == strict_int(pins["testTopCount"]) == len(all_names), "all-package top count")
    need(strict_digest(contract["allPackageTestTopsSHA256"]) == strict_digest(pins["testTopsSHA256"]) == names_digest(all_names), "all-package top hash")
    need(strict_int(contract["allRequiredRunTopCount"]) == strict_int(pins["runTopCount"]) == len(all_run_names), "all-package run count")
    need(strict_digest(contract["allRequiredRunTopsSHA256"]) == strict_digest(pins["runTopsSHA256"]) == names_digest(all_run_names), "all-package run hash")
    added_tops = sorted_unique_strings(contract["p207aAddedTestTops"], "p207aAddedTestTops")
    need(strict_int(contract["p207aAddedTestTopCount"], 1) == len(added_tops), "P207A added top count")
    need(strict_digest(contract["p207aAddedTestTopsSHA256"]) == names_digest(added_tops), "P207A added top hash")
    need(set(added_tops).issubset(all_names) and set(added_tops).issubset(all_run_names), "P207A added tops must run")
    baseline_names = sorted(set(all_names) - set(added_tops))
    baseline_run = sorted(set(all_run_names) - set(added_tops))
    need(len(baseline_names) == strict_int(contract["baselinePackageTestTopCount"]), "baseline source-top count")
    need(names_digest(baseline_names) == strict_digest(contract["baselinePackageTestTopsSHA256"]), "baseline source-top hash")
    need(len(baseline_run) == strict_int(contract["baselineRequiredRunTopCount"]), "baseline run-top count")
    need(names_digest(baseline_run) == strict_digest(contract["baselineRequiredRunTopsSHA256"]), "baseline run-top hash")

    foundation = exact_keys(
        contract["foundation"],
        ("checkerPath", "checkerSHA256", "currentCount", "currentNamesSHA256", "p207aAddedNames", "previousCount", "previousNamesSHA256"),
        "foundation",
    )
    foundation_path = safe_relative(foundation["checkerPath"])
    need(sha(read_bound(root, foundation_path)) == strict_digest(foundation["checkerSHA256"]), "foundation checker pin")
    _, foundation_names = load_foundation(root, foundation_path)
    need(strict_int(foundation["currentCount"]) == len(foundation_names), "foundation current count")
    need(strict_digest(foundation["currentNamesSHA256"]) == names_digest(foundation_names), "foundation current hash")
    added = sorted_unique_strings(foundation["p207aAddedNames"], "foundation.p207aAddedNames")
    need(set(added).issubset(foundation_names), "foundation added names missing")
    previous = sorted(set(foundation_names) - set(added))
    need(len(previous) == strict_int(foundation["previousCount"]), "foundation previous count")
    need(names_digest(previous) == strict_digest(foundation["previousNamesSHA256"]), "foundation previous hash")

    return {
        "schema": SCHEMA,
        "modulePathCount": len(observed_module_paths),
        "moduleContentSHA256": module_sha,
        "automaticFixturePathCount": len(automatic),
        "additionalFixturePathCount": len(additional_paths),
        "fixturePathCount": len(fixture_paths),
        "fixtureContentSHA256": fixture_sha,
        "packageTestTopCount": len(all_names),
        "packageTestTopsSHA256": names_digest(all_names),
        "requiredRunTopCount": len(all_run_names),
        "requiredRunTopsSHA256": names_digest(all_run_names),
        "p207aAddedTestTopCount": len(added_tops),
        "baselinePackageTestTopCount": len(baseline_names),
        "baselineRequiredRunTopCount": len(baseline_run),
        "changedGoSourceCount": len(changed),
        "changedGoSourcesSHA256": changed_sha,
        "foundationCurrentCount": len(foundation_names),
        "foundationPreviousCount": len(previous),
        "goExecutionProven": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--contract", required=True)
    for name in ("contract-sha256", "checker-sha256", "model-sha256", "event-checker-sha256", "event-model-sha256", "failure-checker-sha256", "failure-model-sha256", "go-list-checker-sha256", "go-list-model-sha256", "module-sha256", "fixture-sha256", "test-tops-sha256", "run-tops-sha256", "changed-go-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("module-count", "fixture-count", "test-top-count", "run-top-count", "changed-go-count"):
        parser.add_argument("--" + name, required=True, type=int)
    args = parser.parse_args()
    pins = {
        "contractSHA256": args.contract_sha256,
        "checkerSHA256": args.checker_sha256,
        "modelSHA256": args.model_sha256,
        "eventCheckerSHA256": args.event_checker_sha256,
        "eventModelSHA256": args.event_model_sha256,
        "failureCheckerSHA256": args.failure_checker_sha256,
        "failureModelSHA256": args.failure_model_sha256,
        "goListCheckerSHA256": args.go_list_checker_sha256,
        "goListModelSHA256": args.go_list_model_sha256,
        "moduleCount": args.module_count,
        "moduleSHA256": args.module_sha256,
        "fixtureCount": args.fixture_count,
        "fixtureSHA256": args.fixture_sha256,
        "testTopCount": args.test_top_count,
        "testTopsSHA256": args.test_tops_sha256,
        "runTopCount": args.run_top_count,
        "runTopsSHA256": args.run_tops_sha256,
        "changedGoCount": args.changed_go_count,
        "changedGoSHA256": args.changed_go_sha256,
    }
    print(json.dumps(verify(Path(args.repo), args.contract, pins), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
