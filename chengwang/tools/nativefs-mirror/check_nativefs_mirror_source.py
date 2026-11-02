#!/usr/bin/env python3
"""Static and object-identity checks for the native-filesystem mirror."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import generate_nativefs_mirror as generator


FORBIDDEN_ARGUMENT_WORDS = ("revision", "commit", "tree", "blob", "hash", "magic", "source-path")
MAGIC_PATTERN = re.compile(r"0[xX](?:0*ef53|0*58465342|0*1021994)\b", re.IGNORECASE)


class CheckError(Exception):
    pass


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def check_generator_policy(script: Path) -> None:
    raw = script.read_bytes()
    if b"\r" in raw:
        raise CheckError("generator_crlf")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename=str(script))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise CheckError("generator_parse_failed") from exc
    functions = _functions(tree)
    git_function = functions.get("_git")
    if git_function is None:
        raise CheckError("git_wrapper_missing")
    run_owners: list[str] = []
    for name, function in functions.items():
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" and node.func.attr == "run":
                run_owners.append(name)
    if run_owners != ["_git"]:
        raise CheckError("direct_subprocess_path")
    has_argv_defense = any(
        isinstance(node, ast.Constant) and node.value == "--no-replace-objects"
        for node in ast.walk(git_function)
    )
    has_env_defense = any(
        isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and node.value.value == "1"
        and any(
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "child_env"
            and isinstance(target.slice, ast.Constant)
            and target.slice.value == "GIT_NO_REPLACE_OBJECTS"
            for target in node.targets
        )
        for node in ast.walk(git_function)
    )
    has_shell_false = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in node.keywords)
        for node in ast.walk(git_function)
    )
    if not has_argv_defense or not has_env_defense or not has_shell_false:
        raise CheckError("git_replacement_protection_missing")
    option_names = {
        value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        for value in node.args
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value.startswith("--")
    }
    for option in option_names:
        if any(word in option.lower() for word in FORBIDDEN_ARGUMENT_WORDS):
            raise CheckError("source_identity_argument_forbidden")
    if option_names != {"--repo", "--output", "--tracked"}:
        raise CheckError("unexpected_cli_option")


def check_go_sources(repo: Path, normative: bytes, expected: bytes) -> None:
    module = repo / "chengwang"
    legacy = module / "internal/subscription/store_linux.go"
    generated = module / "internal/nativefs/linux_magic_generated.go"
    class_file = module / "internal/nativefs/linux_class.go"
    evidence_linux = module / "internal/evidence/archive_existing_linux.go"
    if legacy.read_bytes() != normative:
        raise CheckError("legacy_worktree_drift")
    if generated.read_bytes() != expected:
        raise CheckError("generated_worktree_drift")
    if MAGIC_PATTERN.search(class_file.read_text(encoding="utf-8")):
        raise CheckError("handwritten_magic_literal")
    if "nativefs.ClassifyLinuxMagic" not in evidence_linux.read_text(encoding="utf-8"):
        raise CheckError("evidence_classifier_call_missing")
    scoped_sources = [
        *(module / "internal/evidence").glob("archive_existing*.go"),
        *(module / "internal/nativefs").glob("*.go"),
        *(module / "internal/subscription").glob("archive_source*.go"),
    ]
    for path in scoped_sources:
        if path.name.endswith("_test.go") or path.resolve() == generated.resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise CheckError("go_source_utf8_failed") from exc
        if MAGIC_PATTERN.search(text):
            raise CheckError("second_production_magic_list")


def check(repo: Path) -> None:
    repo = repo.resolve(strict=True)
    script = Path(__file__).with_name("generate_nativefs_mirror.py")
    check_generator_policy(script)
    normative = generator.verify_fixed_roles(repo)
    expected = generator.render(generator.extract_magic_values(normative))
    if len(expected) != generator.EXPECTED_OUTPUT_BYTES:
        raise CheckError("expected_output_size")
    if hashlib.sha256(expected).hexdigest() != generator.EXPECTED_OUTPUT_SHA256:
        raise CheckError("expected_output_sha256")
    check_go_sources(repo, normative, expected)


def main() -> int:
    parser = argparse.ArgumentParser(prog="check_nativefs_mirror_source.py")
    parser.add_argument("--repo", required=True, type=Path)
    args = parser.parse_args()
    try:
        check(args.repo)
    except (CheckError, generator.MirrorError, OSError) as exc:
        reason = exc.args[0] if exc.args else "source_check_failed"
        print(json.dumps({"status": "REJECT", "reason": reason}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "sha256": generator.EXPECTED_OUTPUT_SHA256}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
