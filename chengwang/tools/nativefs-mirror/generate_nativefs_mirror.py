#!/usr/bin/env python3
"""Generate or verify the A1 native-filesystem mirror from fixed Git objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable, Sequence


NORMATIVE = {
    "role": "NORMATIVE_RENDER_SOURCE",
    "commit": "3444578ed42454fb460d6c3b45242c6717786782",
    "tree": "fb5bcebd073aeacb301f7025adcc56dbe79ce8ee",
    "path": "chengwang/internal/subscription/store_linux.go",
    "blob": "7998676a5ac9cc033f76d05796522cf1e0852c4f",
    "bytes": 13576,
    "sha256": "52f212a3ea1986df9cab76a31dd2fecb38da51e163355c8016ea934d0c5626d2",
}
COMPATIBILITY = {
    "role": "IMPLEMENTATION_COMPATIBILITY_CHECK",
    "commit": "74730eb025189647e9deb2c4df72eec62bb54899",
    "tree": "4adb8ec4dcf70a1a399f5a071b29624481b7682c",
    "path": "chengwang/internal/subscription/store_linux.go",
    "blob": "7998676a5ac9cc033f76d05796522cf1e0852c4f",
    "bytes": 13576,
    "sha256": "52f212a3ea1986df9cab76a31dd2fecb38da51e163355c8016ea934d0c5626d2",
}
EXPECTED_VALUES = ("0xef53", "0x58465342", "0x01021994")
EXPECTED_OUTPUT_SHA256 = "eb4d256d46777d3cda733df03c847fece4134fb1142e1afd6fa69d73044ec50b"
EXPECTED_OUTPUT_BYTES = 714


class MirrorError(Exception):
    """A fixed, privacy-safe generator failure."""


def _git_executable() -> str:
    executable = shutil.which("git")
    if not executable:
        raise MirrorError("git_unavailable")
    return executable


def _git(
    repo: Path,
    args: Sequence[str],
    recorder: list[tuple[list[str], dict[str, str]]] | None = None,
) -> bytes:
    argv = [_git_executable(), "--no-replace-objects", "-C", str(repo), *args]
    child_env = os.environ.copy()
    child_env["GIT_NO_REPLACE_OBJECTS"] = "1"
    if recorder is not None:
        recorder.append((argv.copy(), {"GIT_NO_REPLACE_OBJECTS": "1"}))
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            shell=False,
        )
    except OSError as exc:
        raise MirrorError("git_object_read_failed") from exc
    if completed.returncode != 0:
        raise MirrorError("git_object_read_failed")
    return completed.stdout


def _one_line(raw: bytes, check: str) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MirrorError(check) from exc
    if not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
        raise MirrorError(check)
    return text[:-1]


def _one_utf8_line(raw: bytes, check: str) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MirrorError(check) from exc
    if not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
        raise MirrorError(check)
    return text[:-1]


def _verify_role(
    repo: Path,
    role: dict[str, object],
    recorder: list[tuple[list[str], dict[str, str]]] | None = None,
) -> bytes:
    commit, path = str(role["commit"]), str(role["path"])
    resolved = _one_line(
        _git(repo, ["rev-parse", "--verify", f"{commit}^{{commit}}"], recorder),
        "commit_identity_mismatch",
    )
    if resolved != commit:
        raise MirrorError("commit_identity_mismatch")
    tree = _one_line(
        _git(repo, ["rev-parse", f"{commit}^{{tree}}"], recorder),
        "tree_identity_mismatch",
    )
    if tree != role["tree"]:
        raise MirrorError("tree_identity_mismatch")
    blob = _one_line(
        _git(repo, ["rev-parse", f"{commit}:{path}"], recorder),
        "blob_identity_mismatch",
    )
    if blob != role["blob"]:
        raise MirrorError("blob_identity_mismatch")
    object_type = _one_line(
        _git(repo, ["cat-file", "-t", blob], recorder), "blob_type_mismatch"
    )
    if object_type != "blob":
        raise MirrorError("blob_type_mismatch")
    size_text = _one_line(
        _git(repo, ["cat-file", "-s", blob], recorder), "blob_size_mismatch"
    )
    if not size_text.isdecimal() or int(size_text) != role["bytes"]:
        raise MirrorError("blob_size_mismatch")
    raw = _git(repo, ["cat-file", "blob", blob], recorder)
    if len(raw) != role["bytes"] or b"\r" in raw:
        raise MirrorError("blob_bytes_mismatch")
    if hashlib.sha256(raw).hexdigest() != role["sha256"]:
        raise MirrorError("blob_sha256_mismatch")
    return raw


def verify_fixed_roles(
    repo: Path,
    recorder: list[tuple[list[str], dict[str, str]]] | None = None,
) -> bytes:
    repo = repo.resolve(strict=True)
    normative = _verify_role(repo, NORMATIVE, recorder)
    compatible = _verify_role(repo, COMPATIBILITY, recorder)
    if compatible != normative:
        raise MirrorError("compatibility_bytes_mismatch")
    return normative


def _lex_go(raw: bytes) -> list[str]:
    if b"\r" in raw:
        raise MirrorError("source_crlf_rejected")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MirrorError("source_utf8_rejected") from exc
    tokens: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            i = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise MirrorError("source_comment_unterminated")
            i = end + 2
            continue
        if ch in ('"', "'", "`"):
            quote, start = ch, i
            i += 1
            while i < len(text):
                if quote != "`" and text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            else:
                raise MirrorError("source_literal_unterminated")
            tokens.append(text[start:i])
            continue
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] == "_"):
                i += 1
            tokens.append(text[start:i])
            continue
        if ch.isdigit():
            start = i
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] == "_"):
                i += 1
            tokens.append(text[start:i])
            continue
        two = text[i : i + 2]
        if two in ("!=", "==", "||", "&&", ":=", "<=", ">="):
            tokens.append(two)
            i += 2
            continue
        tokens.append(ch)
        i += 1
    return tokens


_FUNCTION_PATTERN = [
    "func", "storeNativeFS", "(", "file", "*", "os", ".", "File", ")", "bool", "{",
    "var", "fs", "syscall", ".", "Statfs_t",
    "if", "syscall", ".", "Fstatfs", "(", "int", "(", "file", ".", "Fd", "(", ")", ")", ",", "&", "fs", ")", "!=", "nil", "{",
    "return", "false", "}",
    "return", "fs", ".", "Type", "==", "HEX", "||", "fs", ".", "Type", "==", "HEX", "||", "fs", ".", "Type", "==", "HEX",
    "}",
]


def extract_magic_values(raw: bytes) -> tuple[str, str, str]:
    tokens = _lex_go(raw)
    starts = [
        i
        for i in range(len(tokens) - 1)
        if tokens[i] == "func" and tokens[i + 1] == "storeNativeFS"
    ]
    if len(starts) != 1:
        raise MirrorError("function_count_mismatch")
    start = starts[0]
    try:
        body_start = tokens.index("{", start)
    except ValueError as exc:
        raise MirrorError("function_structure_mismatch") from exc
    depth, end = 0, -1
    for index in range(body_start, len(tokens)):
        if tokens[index] == "{":
            depth += 1
        elif tokens[index] == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
            if depth < 0:
                break
    if end < 0:
        raise MirrorError("function_structure_mismatch")
    function = tokens[start:end]
    if len(function) != len(_FUNCTION_PATTERN):
        raise MirrorError("function_structure_mismatch")
    values: list[str] = []
    for actual, expected in zip(function, _FUNCTION_PATTERN):
        if expected == "HEX":
            if not actual.startswith(("0x", "0X")):
                raise MirrorError("function_magic_mismatch")
            values.append(actual)
        elif actual != expected:
            raise MirrorError("function_structure_mismatch")
    if len(values) != 3 or len(set(values)) != 3 or tuple(values) != EXPECTED_VALUES:
        raise MirrorError("function_magic_mismatch")
    return values[0], values[1], values[2]


def render(values: Iterable[str]) -> bytes:
    ext4, xfs, tmpfs = tuple(values)
    text = f"""// Code generated by generate_nativefs_mirror.py; DO NOT EDIT.
// Source: {NORMATIVE['path']}
// Source commit: {NORMATIVE['commit']}
// Source blob: {NORMATIVE['blob']}
// Source SHA-256: {NORMATIVE['sha256']}

package nativefs

const (
\tLinuxExt4Magic  int64 = {ext4}
\tLinuxXFSMagic   int64 = {xfs}
\tLinuxTmpfsMagic int64 = {tmpfs}
)

func ClassifyLinuxMagic(magic int64) (LinuxClass, bool) {{
\tswitch magic {{
\tcase LinuxExt4Magic:
\t\treturn LinuxExt4, true
\tcase LinuxXFSMagic:
\t\treturn LinuxXFS, true
\tcase LinuxTmpfsMagic:
\t\treturn LinuxTmpfs, true
\tdefault:
\t\treturn LinuxUnknown, false
\t}}
}}
"""
    raw = text.encode("utf-8")
    if len(raw) != EXPECTED_OUTPUT_BYTES:
        raise MirrorError("rendered_output_size_mismatch")
    if hashlib.sha256(raw).hexdigest() != EXPECTED_OUTPUT_SHA256:
        raise MirrorError("rendered_output_sha256_mismatch")
    return raw


def expected_output(
    repo: Path,
    recorder: list[tuple[list[str], dict[str, str]]] | None = None,
) -> bytes:
    return render(extract_magic_values(verify_fixed_roles(repo, recorder)))


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _exclusive_write(repo: Path, output: Path, raw: bytes) -> None:
    repo = repo.resolve(strict=True)
    parent = output.parent.resolve(strict=True)
    target = parent / output.name
    git_dir = Path(
        _one_utf8_line(
            _git(repo, ["rev-parse", "--path-format=absolute", "--git-dir"]),
            "git_dir_resolution_failed",
        )
    ).resolve(strict=True)
    common_dir = Path(
        _one_utf8_line(
            _git(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"]),
            "git_common_dir_resolution_failed",
        )
    ).resolve(strict=True)
    if any(_inside(target, forbidden) for forbidden in (repo, git_dir, common_dir)):
        raise MirrorError("output_forbidden_root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(target, flags, 0o600)
    except OSError as exc:
        raise MirrorError("output_exclusive_create_failed") from exc
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise MirrorError("output_short_write")
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    if target.read_bytes() != raw:
        raise MirrorError("output_readback_mismatch")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="generate_nativefs_mirror.py")
    modes = parser.add_subparsers(dest="mode", required=True)
    generate = modes.add_parser("generate")
    generate.add_argument("--repo", required=True, type=Path)
    generate.add_argument("--output", required=True, type=Path)
    verify = modes.add_parser("verify")
    verify.add_argument("--repo", required=True, type=Path)
    verify.add_argument("--tracked", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = expected_output(args.repo)
        if args.mode == "generate":
            _exclusive_write(args.repo, args.output, raw)
        elif args.tracked.read_bytes() != raw:
            raise MirrorError("tracked_output_mismatch")
    except (MirrorError, OSError) as exc:
        reason = exc.args[0] if isinstance(exc, MirrorError) and exc.args else "filesystem_failure"
        print(json.dumps({"status": "REJECT", "reason": reason}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "sha256": EXPECTED_OUTPUT_SHA256}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
