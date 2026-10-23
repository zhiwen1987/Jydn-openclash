#!/usr/bin/env python3
"""Verify original pinned ZIP and actual expansion; never execute the browser."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import zipfile
import zlib

HERE = "chengwang/tools/browser-runtime-candidate"
PIN_SHA256 = "404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea"
ZIP_SHA256 = "7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853"
SOURCE_PATHS = (HERE + "/pin.json", HERE + "/consume_pin.py", HERE + "/check_consumption.py",
    "chengwang/tools/browser-acquisition/check_acquisition.py", "chengwang/tools/browser-acquisition/candidate.json")
EXECUTABLES = frozenset(("chrome-linux64/chrome", "chrome-linux64/chrome-wrapper",
    "chrome-linux64/chrome_crashpad_handler", "chrome-linux64/chrome_sandbox",
    "chrome-linux64/libEGL.so", "chrome-linux64/libGLESv2.so", "chrome-linux64/libvk_swiftshader.so",
    "chrome-linux64/libvulkan.so.1", "chrome-linux64/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so"))
LIMITATIONS = ["download-and-expansion-not-browser-execution", "not-runtime-version-or-revision-proof",
    "not-publisher-signature", "not-project-fix-acceptance", "alpha-not-stable-production",
    "historical-reference-pin-not-mutated"]
MANIFEST_FIELDS = {"schema", "sourceCommit", "sourceFiles", "pinSHA256", "zip", "httpReceipt", "mode",
    "inventory", "expanded", "elf", "pinEnforced", "browserExecuted", "production", "limitations"}


def need(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def snapshot(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_small(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, "REGULAR_BOUNDED_FILE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        need(snapshot(before) == snapshot(opened), "FILE_CHANGED")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(maximum + 1)
        need(len(raw) == before.st_size and snapshot(opened) == snapshot(os.fstat(fd)) == snapshot(path.lstat()), "FILE_CHANGED")
        return raw
    finally:
        os.close(fd)


def write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def strict_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "JSON_DUPLICATE")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("JSON_NONFINITE")
    result = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=constant)
    need(type(result) is dict, "JSON_OBJECT")
    return result


def load_pin(raw: bytes) -> dict:
    need(sha(raw) == PIN_SHA256, "PIN_REFERENCE_BYTES")
    pin = strict_json(raw)
    need(pin["state"] == "PINNED_REFERENCE_NOT_EXECUTED" and pin["authorization"] == "BLOCKED" and
         all(pin[key] is False for key in ("production", "consumedByExecutionHarness", "browserRuntimeProven", "projectFixProven")), "PIN_REFERENCE_SCOPE")
    browser = pin["browser"]
    need(browser["sha256"] == ZIP_SHA256 and browser["bytes"] == 202676171 and
         browser["url"] == "https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.6/linux64/chrome-linux64.zip" and
         browser["generation"] == "1792024099984701" and browser["md5Base64"] == "5qChIL/Gh+8hZv73vzEakQ==" and
         browser["inventoryEntries"] == 309 and browser["declaredUncompressedBytes"] == 425547397 and
         browser["inventoryMembersSHA256"] == "40a84f87dd5799295c8a50582ee893af1e284f7e5d2a85e79683f299b688c015" and
         all(browser[key] is None for key in ("observedRuntimeProduct", "observedRuntimeRevision", "observedRuntimeProtocolVersion")), "PIN_CONSTANTS")
    return pin


def bind_sources(repo: Path, commit: str) -> dict:
    need(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "SOURCE_COMMIT")
    records = {}
    for name in SOURCE_PATHS:
        original = subprocess.run(["git", "-C", str(repo), "show", commit + ":" + name], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout
        need(0 < len(original) <= 262144 and read_small(repo / name, 262144) == original, "SOURCE_GIT_BYTES")
        records[name] = {"bytes": len(original), "sha256": sha(original)}
    return records


def load_context(repo: Path, commit: str):
    binding = bind_sources(repo, commit)
    pin = load_pin(read_small(repo / HERE / "pin.json", 262144))
    source = repo / "chengwang/tools/browser-acquisition/check_acquisition.py"
    spec = importlib.util.spec_from_file_location("chengwang_pinned_original_zip_contract", source)
    need(spec is not None and spec.loader is not None, "ORIGINAL_CHECKER_IMPORT")
    acquisition = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acquisition)
    candidate = acquisition.load_candidate(read_small(repo / "chengwang/tools/browser-acquisition/candidate.json", 262144))
    for key in ("url", "bytes", "generation", "md5Base64"):
        need(pin["browser"][key] == candidate["browser"][key], "ORIGINAL_CANDIDATE_BINDING")
    return pin, binding, acquisition, candidate


def require_linux_ci(platform: str, environment: dict) -> None:
    need(platform == "linux" and environment.get("GITHUB_ACTIONS") == "true" and
         environment.get("RUNNER_OS") == "Linux" and bool(getattr(os, "O_NOFOLLOW", 0)), "LINUX_GITHUB_CI_REQUIRED")


def safe_mode(member: dict) -> int:
    name, mode = member["path"], member["unixMode"]
    kind = stat.S_IFMT(mode)
    need(kind in (0, stat.S_IFREG, stat.S_IFDIR), "MEMBER_TYPE")
    if name.endswith("/"):
        need(kind in (0, stat.S_IFDIR) and member["bytes"] == 0, "DIRECTORY_MEMBER")
        return 0o500
    need(kind in (0, stat.S_IFREG), "MEMBER_TYPE")
    if mode & 0o111:
        need(name in EXECUTABLES, "EXECUTABLE_NOT_ALLOWLISTED")
        return 0o500
    need(name not in EXECUTABLES, "REQUIRED_EXECUTABLE_SOURCE_MODE")
    return 0o400


def validate_inventory(value: dict, browser: dict) -> None:
    need(value["entries"] == browser["inventoryEntries"] and
         value["uncompressedBytes"] == browser["declaredUncompressedBytes"] and
         value["membersSha256"] == browser["inventoryMembersSHA256"], "PIN_INVENTORY")
    actual = set()
    for member in value["members"]:
        safe_mode(member)
        if not member["path"].endswith("/") and member["unixMode"] & 0o111:
            actual.add(member["path"])
    need(actual == EXECUTABLES, "EXECUTABLE_ALLOWLIST_SET")


def member_chunks(handle, item: zipfile.ZipInfo, total_limit: int):
    """Bound raw decompression directly: no ZipExtFile size clipping or extract()."""
    # Semantics checked against docs.python.org/3/library/zlib.html and
    # github.com/python/cpython/blob/v3.12.12/Lib/zipfile/__init__.py.
    # Require raw-deflate EOF and reject unused compressed suffixes, while each
    # decompress() output is capped before any write or accepted-byte hashing.
    need(item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
         not item.flag_bits & 1 and 0 <= item.file_size <= total_limit, "MEMBER_STREAM_POLICY")
    handle.seek(item.header_offset)
    local = handle.read(30)
    need(len(local) == 30 and local[:4] == b"PK\x03\x04", "MEMBER_LOCAL_HEADER")
    fields = struct.unpack("<4s5H3I2H", local)
    handle.seek(fields[-2] + fields[-1], os.SEEK_CUR)
    compressed_left, count, crc = item.compress_size, 0, 0
    decoder = zlib.decompressobj(-15) if item.compress_type == zipfile.ZIP_DEFLATED else None
    while compressed_left:
        raw = handle.read(min(65536, compressed_left))
        need(bool(raw), "MEMBER_COMPRESSED_TRUNCATED")
        compressed_left -= len(raw)
        pending = raw
        while pending:
            if decoder is None:
                block, pending = pending, b""
            else:
                old_pending = len(pending)
                block = decoder.decompress(pending, min(65536, item.file_size - count + 1))
                pending = decoder.unconsumed_tail
                need(not decoder.unused_data and (bool(block) or len(pending) < old_pending), "MEMBER_DEFLATE_TRAILING_OR_STALLED")
            count += len(block)
            need(count <= item.file_size and count <= total_limit, "MEMBER_ACTUAL_SIZE")
            crc = zlib.crc32(block, crc)
            if block:
                yield block
        if decoder is not None and decoder.eof:
            need(compressed_left == 0, "MEMBER_DEFLATE_TRAILING_OR_STALLED")
    need(decoder is None or (decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail), "MEMBER_DEFLATE_TRUNCATED")
    need(count == item.file_size and f"{crc & 0xffffffff:08x}" == f"{item.CRC:08x}", "MEMBER_CRC_OR_SIZE")


def desired_directories(members: list) -> list[str]:
    result = set()
    for member in members:
        parts = member["path"].rstrip("/").split("/")
        stop = len(parts) if member["path"].endswith("/") else len(parts) - 1
        result.update("/".join(parts[:length]) for length in range(1, stop + 1))
    return sorted(result)


@contextmanager
def original_zip_handle(path: Path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "ZIP_REGULAR_FILE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(snapshot(before) == snapshot(os.fstat(fd)), "ZIP_CHANGED")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            yield handle
        need(snapshot(before) == snapshot(os.fstat(fd)) == snapshot(path.lstat()), "ZIP_CHANGED")
    finally:
        os.close(fd)


def open_parent(root_fd: int, components: list[str], create: bool) -> int:
    fd = os.dup(root_fd)
    try:
        for part in components:
            need(part not in ("", ".", "..") and "/" not in part and "\\" not in part, "DIRECTORY_COMPONENT")
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def expand_original(zip_path: Path, root: Path, inventory: dict, maximum: int) -> dict:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed, total = [], 0
    before = snapshot(zip_path.lstat())
    try:
        with original_zip_handle(zip_path) as raw, zipfile.ZipFile(raw, "r") as archive:
            items = archive.infolist()
            need(len(items) == len(inventory["members"]), "MEMBER_COUNT")
            for item, member in zip(items, inventory["members"]):
                need(item.orig_filename == member["path"] and item.file_size == member["bytes"], "MEMBER_BINDING")
                mode = safe_mode(member)
                parts = member["path"].rstrip("/").split("/")
                directory = member["path"].endswith("/")
                parent = open_parent(root_fd, parts if directory else parts[:-1], create=True)
                digest, crc, count = hashlib.sha256(), 0, 0
                try:
                    if directory:
                        need(not list(member_chunks(raw, item, maximum - total)), "DIRECTORY_DATA")
                    else:
                        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent)
                        try:
                            with os.fdopen(fd, "wb", closefd=False) as target:
                                for block in member_chunks(raw, item, maximum - total):
                                    count += len(block)
                                    digest.update(block)
                                    crc = zlib.crc32(block, crc)
                                    target.write(block)
                                target.flush()
                                os.fsync(fd)
                            os.fchmod(fd, mode)
                        finally:
                            os.close(fd)
                finally:
                    os.close(parent)
                total += count
                need(total <= maximum, "EXPANDED_TOTAL")
                observed.append({"path": member["path"], "type": "directory" if directory else "file",
                    "bytes": count, "sha256": digest.hexdigest(), "crc32": f"{crc & 0xffffffff:08x}",
                    "mode": mode, "sourceUnixMode": member["unixMode"]})
        directories = desired_directories(inventory["members"])
        for name in sorted(directories, key=lambda value: (-value.count("/"), value)):
            descriptor = open_parent(root_fd, name.split("/"), create=False)
            try:
                os.fchmod(descriptor, 0o500)
            finally:
                os.close(descriptor)
        need(before == snapshot(zip_path.lstat()), "ZIP_CHANGED_DURING_EXPANSION")
    finally:
        os.close(root_fd)
    return {"members": observed, "membersSha256": sha(canonical(observed)), "fileBytes": total,
            "directories": directories, "setuidAndSetgidStripped": True, "allMemberCRCsVerified": True}


def parse_elf(header: bytes, program_headers: bytes, size: int) -> dict:
    need(len(header) == 64 and header[:4] == b"\x7fELF", "ELF_MAGIC")
    values = struct.unpack("<16sHHIQQQIHHHHHH", header)
    ident, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = values
    need(ident[4:7] == b"\x02\x01\x01" and ident[7] in (0, 3) and kind in (2, 3) and
         machine == 62 and version == 1 and ehsize == 64 and phsize == 56 and 1 <= phnum <= 256 and
         64 <= phoff <= size and phoff + phsize * phnum <= size and len(program_headers) == phsize * phnum, "ELF_X86_64_LAYOUT")
    executable_entry, loads = False, 0
    for offset in range(0, len(program_headers), 56):
        ptype, flags, fileoff, vaddr, _, filesz, memsz, align = struct.unpack("<IIQQQQQQ", program_headers[offset:offset + 56])
        need(fileoff <= size and filesz <= size - fileoff and memsz >= filesz, "ELF_SEGMENT_BOUNDS")
        need(align in (0, 1) or align & (align - 1) == 0, "ELF_SEGMENT_ALIGNMENT")
        if ptype == 1:
            loads += 1
            executable_entry |= bool(flags & 1 and vaddr <= entry < vaddr + memsz)
    need(loads > 0 and executable_entry, "ELF_EXECUTABLE_ENTRY")
    return {"class": "ELF64", "byteOrder": "little", "machine": "x86_64", "type": "DYN" if kind == 3 else "EXEC",
            "entryPoint": entry, "programHeaderCount": phnum, "loadSegments": loads}


def elf_file(path: Path) -> dict:
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 64 <= before.st_size <= 512 << 20, "ELF_REGULAR_FILE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(snapshot(before) == snapshot(os.fstat(fd)), "ELF_CHANGED")
        header = os.pread(fd, 64, 0)
        need(len(header) == 64 and header[:4] == b"\x7fELF", "ELF_MAGIC")
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        phoff, phsize, phnum = fields[5], fields[9], fields[10]
        need(phsize == 56 and 1 <= phnum <= 256 and phoff + phsize * phnum <= before.st_size, "ELF_PROGRAM_HEADER_BUDGET")
        result = parse_elf(header, os.pread(fd, phsize * phnum, phoff), before.st_size)
        need(snapshot(before) == snapshot(os.fstat(fd)) == snapshot(path.lstat()), "ELF_CHANGED")
        return result
    finally:
        os.close(fd)


def check_tree(root: Path, zip_path: Path, inventory: dict, maximum: int) -> dict:
    """Re-decompress original ZIP and separately hash actual descriptor-opened files."""
    expected_files = {member["path"] for member in inventory["members"] if not member["path"].endswith("/")}
    directories = desired_directories(inventory["members"])
    actual_files, actual_dirs = set(), set()
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(current) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and stat.S_IMODE(info.st_mode) == 0o500, "TREE_DIRECTORY")
            actual_dirs.add(relative)
        for name in files:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            need(relative in expected_files or relative in ("browser.zip", "consumption.json"), "TREE_EXTRA_FILE")
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink(), "TREE_SPECIAL_FILE")
            actual_files.add(relative)
    need(actual_dirs == set(directories) and actual_files == expected_files | {"browser.zip", "consumption.json"}, "TREE_CLOSED_SET")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed, total = [], 0
    before_zip = snapshot(zip_path.lstat())
    try:
        with original_zip_handle(zip_path) as raw, zipfile.ZipFile(raw, "r") as archive:
            items = archive.infolist()
            need(len(items) == len(inventory["members"]), "MEMBER_COUNT")
            for item, member in zip(items, inventory["members"]):
                need(item.orig_filename == member["path"] and item.file_size == member["bytes"], "MEMBER_BINDING")
                mode, directory = safe_mode(member), member["path"].endswith("/")
                zip_digest, zip_crc, count = hashlib.sha256(), 0, 0
                for block in member_chunks(raw, item, maximum - total):
                    count += len(block)
                    zip_digest.update(block)
                    zip_crc = zlib.crc32(block, zip_crc)
                parts = member["path"].rstrip("/").split("/")
                parent = open_parent(root_fd, parts if directory else parts[:-1], create=False)
                try:
                    if not directory:
                        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                        try:
                            before = os.fstat(fd)
                            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == count and
                                 stat.S_IMODE(before.st_mode) == mode, "EXPANDED_FILE_IDENTITY")
                            file_digest, file_crc, file_bytes = hashlib.sha256(), 0, 0
                            while block := os.read(fd, min(65536, count - file_bytes + 1)):
                                file_bytes += len(block)
                                need(file_bytes <= count, "EXPANDED_FILE_SIZE")
                                file_digest.update(block)
                                file_crc = zlib.crc32(block, file_crc)
                            named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                            need(snapshot(before) == snapshot(os.fstat(fd)) == snapshot(named) and file_bytes == count and
                                 file_digest.hexdigest() == zip_digest.hexdigest() and file_crc == zip_crc, "EXPANDED_FILE_CONTENT")
                        finally:
                            os.close(fd)
                finally:
                    os.close(parent)
                total += count
                need(total <= maximum, "EXPANDED_TOTAL")
                observed.append({"path": member["path"], "type": "directory" if directory else "file", "bytes": count,
                    "sha256": zip_digest.hexdigest(), "crc32": f"{zip_crc & 0xffffffff:08x}", "mode": mode,
                    "sourceUnixMode": member["unixMode"]})
        need(before_zip == snapshot(zip_path.lstat()), "ZIP_CHANGED_DURING_READBACK")
    finally:
        os.close(root_fd)
    return {"members": observed, "membersSha256": sha(canonical(observed)), "fileBytes": total,
            "directories": directories, "setuidAndSetgidStripped": True, "allMemberCRCsVerified": True}


def outside_report(root: Path, report: Path) -> None:
    parent = report.parent.resolve(strict=True)
    resolved_root = root.resolve(strict=False)
    need(parent != resolved_root and resolved_root not in parent.parents and not report.exists() and not report.is_symlink(), "NEW_REPORT_OUTSIDE_TREE")


def verify_consumption(repo: Path, root: Path, commit: str) -> dict:
    pin, binding, acquisition, candidate = load_context(repo, commit)
    need(root.is_absolute() and stat.S_ISDIR(root.lstat().st_mode) and not root.is_symlink() and
         stat.S_IMODE(root.lstat().st_mode) == 0o700, "OUTPUT_ROOT")
    manifest = strict_json(read_small(root / "consumption.json", 2 << 20))
    need(set(manifest) == MANIFEST_FIELDS and manifest["schema"] == "chengwang.pinned-browser-consumption/v1" and
         manifest["sourceCommit"] == commit and manifest["sourceFiles"] == binding and manifest["pinSHA256"] == PIN_SHA256 and
         manifest["pinEnforced"] is True and manifest["browserExecuted"] is False and manifest["production"] is False and
         manifest["limitations"] == LIMITATIONS, "CONSUMPTION_MANIFEST")
    original = root / "browser.zip"
    zip_snapshot = snapshot(original.lstat())
    digest = acquisition.hash_browser(original, candidate["browser"])
    need(digest["sha256"] == pin["browser"]["sha256"] == ZIP_SHA256 and digest == manifest["zip"], "PIN_ZIP_SHA256")
    need(manifest["mode"] in ("PUBLIC_HTTPS_PINNED_ARCHIVE", "EXISTING_PINNED_ARCHIVE"), "ACQUISITION_MODE")
    if manifest["mode"] == "EXISTING_PINNED_ARCHIVE":
        need(manifest["httpReceipt"] is None, "NO_NEW_TLS_RECEIPT_FOR_EXISTING_ARCHIVE")
    else:
        receipt = acquisition.http_receipt(manifest["httpReceipt"])
        need(receipt["url"] == pin["browser"]["url"] and receipt["sha256"] == ZIP_SHA256 and
             receipt["bytes"] == 202676171 and receipt["contentLength"] == "202676171" and
             receipt["generation"] == pin["browser"]["generation"] and sorted(receipt["googleHashes"]) ==
             sorted(["md5=" + pin["browser"]["md5Base64"], "crc32c=" + candidate["browser"]["crc32cBase64"]]), "PIN_HTTP_RECEIPT")
    inventory = acquisition.inventory(original, candidate["limits"])
    validate_inventory(inventory, pin["browser"])
    need(manifest["inventory"] == {key: value for key, value in inventory.items() if key != "members"}, "INVENTORY_BINDING")
    expanded = check_tree(root, original, inventory, candidate["limits"]["zipUncompressedBytes"])
    need(expanded == manifest["expanded"], "EXPANDED_READBACK")
    chrome = next(member for member in expanded["members"] if member["path"] == "chrome-linux64/chrome")
    elf = {"path": chrome["path"], "bytes": chrome["bytes"], "sha256": chrome["sha256"], **elf_file(root / chrome["path"])}
    need(elf == manifest["elf"] and binding == bind_sources(repo, commit) and
         zip_snapshot == snapshot(original.lstat()), "ELF_OR_SOURCE_READBACK")
    return {"schema": "chengwang.pinned-browser-consumption-verification/v1", "sourceCommit": commit,
        "state": "PIN_ENFORCED_EXPANDED_NOT_EXECUTED", "pinSHA256": PIN_SHA256, "sourceFilesVerified": len(binding),
        "mode": manifest["mode"], "zip": digest, "expandedMemberCount": len(expanded["members"]), "expandedBytes": expanded["fileBytes"],
        "expandedMembersSHA256": expanded["membersSha256"], "elf": elf, "pinEnforced": True,
        "allMemberCRCsVerified": True, "actualExpandedFileHashesVerified": True,
        "browserExecuted": False, "runtimeVersionProven": False, "projectFixProven": False,
        "publisherSignatureProven": False, "production": False, "limitations": LIMITATIONS}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require_linux_ci(sys.platform, os.environ)
    repo, root, report = args.repo.resolve(strict=True), args.evidence.absolute(), args.report.absolute()
    outside_report(root, report)
    result = verify_consumption(repo, root, args.source_commit)
    write_new(report, canonical(result))
    print(canonical(result).decode(), end="")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("pinned browser consumption rejected: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
