#!/usr/bin/env python3
"""Recompute acquire-only evidence. No browser installation or execution."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import unicodedata
import zipfile

SOURCE_DIRECTORY = "chengwang/tools/browser-acquisition"
SOURCE_NAMES = ("candidate.json", "acquire_browser.py", "check_acquisition.py",
                "test_acquisition.py", "README.md")
SOURCE_PATHS = tuple(f"{SOURCE_DIRECTORY}/{name}" for name in SOURCE_NAMES)
METADATA_NAMES = frozenset(("cft-version.json", "npm-package.json", "pw-browsers.json",
    "pw-registry.txt", "chromium-tag.json", "fix-included-in.json", "chromium-loader.b64",
    "chromium-webtest.b64", "chromium-fix.json"))
MANIFEST_KEYS = {"schemaVersion", "kind", "sourceCommit", "sourceFiles", "candidateSha256",
                 "files", "browser", "inventory", "limitations"}
LIMITATIONS = ["acquisition-only-not-browser-execution", "not-publisher-signature",
               "not-project-fix-acceptance", "alpha-is-not-stable-production",
               "cft-position-is-not-runtime-git-revision", "zip-members-not-decompressed"]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def demand(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def closed(value: object, names: set[str], code: str) -> dict:
    demand(type(value) is dict and set(value) == names, code)
    return value


def strict_json(raw: bytes, *, gerrit: bool = False) -> object:
    if gerrit:
        demand(raw.startswith(b")]}'\n"), "GERRIT_PREFIX")
        raw = raw[5:]
    demand(len(raw) <= 2 * 1024 * 1024, "JSON_LIMIT")

    def pairs(items: list) -> dict:
        result = {}
        for key, value in items:
            demand(key not in result, "JSON_DUPLICATE")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError("JSON_NONFINITE")

    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_constant=constant)


def read_regular(path: Path, limit: int) -> bytes:
    """Reject links and changes across the descriptor read; Linux O_NOFOLLOW required by CLI."""
    before = path.lstat()
    demand(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "REGULAR_FILE_REQUIRED")
    demand(before.st_size <= limit, "FILE_LIMIT")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        demand((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
               (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns), "FILE_CHANGED")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)
        after = os.fstat(fd)
        demand(len(raw) <= limit and len(raw) == before.st_size, "FILE_LIMIT")
        demand((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
               (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "FILE_CHANGED")
        final = path.lstat()
        demand((final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) ==
               (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns), "FILE_CHANGED")
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


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()


def http_receipt(value: object) -> dict:
    receipt = closed(value, {"url", "status", "bytes", "sha256", "contentLength", "generation", "googleHashes"}, "HTTP_RECEIPT_SCHEMA")
    demand(type(receipt["url"]) is str and len(receipt["url"]) <= 1024 and
           type(receipt["status"]) is int and receipt["status"] == 200 and
           type(receipt["bytes"]) is int and receipt["bytes"] >= 0 and
           type(receipt["sha256"]) is str and HEX64.fullmatch(receipt["sha256"]) is not None,
           "HTTP_RECEIPT_TYPES")
    for key in ("contentLength", "generation"):
        value = receipt[key]
        demand(value is None or (type(value) is str and value.isascii() and value.isdigit() and len(value) <= 24), "HTTP_RECEIPT_TYPES")
    demand(type(receipt["googleHashes"]) is list and len(receipt["googleHashes"]) <= 4 and
           all(type(item) is str and len(item) <= 100 and item.isascii() for item in receipt["googleHashes"]),
           "HTTP_RECEIPT_TYPES")
    demand(receipt["contentLength"] is None or int(receipt["contentLength"]) == receipt["bytes"], "HTTP_RECEIPT_LENGTH")
    return receipt


def source_binding(repo: Path, commit: str) -> dict:
    demand(HEX40.fullmatch(commit) is not None, "SOURCE_COMMIT")
    result = {}
    for relative in SOURCE_PATHS:
        original = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{relative}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout
        demand(len(original) <= 262144, "SOURCE_LIMIT")
        actual = read_regular(repo / relative, 262144)
        demand(actual == original, "SOURCE_GIT_MISMATCH")
        result[relative] = {"bytes": len(original), "sha256": sha256(original)}
    return result


def load_candidate(raw: bytes) -> dict:
    data = closed(strict_json(raw), {"schemaVersion", "kind", "browser", "playwright", "metadata", "limits"}, "CANDIDATE_SCHEMA")
    demand(data["schemaVersion"] == 1 and type(data["schemaVersion"]) is int and
           data["kind"] == "chengwang-ci-browser-acquisition-only", "CANDIDATE_KIND")
    browser = closed(data["browser"], {"version", "platform", "binary", "url", "bytes", "generation",
        "md5Base64", "crc32cBase64", "sha256", "cftRevision", "sourceTagCommit", "fixCommit", "regressionTestGitBlob"}, "BROWSER_SCHEMA")
    demand(browser == {
        "version": "157.0.8103.6", "platform": "linux64", "binary": "chrome",
        "url": "https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.6/linux64/chrome-linux64.zip",
        "bytes": 202676171, "generation": "1792024099984701", "md5Base64": "5qChIL/Gh+8hZv73vzEakQ==",
        "crc32cBase64": "EJCYzQ==", "sha256": None, "cftRevision": "1717349",
        "sourceTagCommit": "41520584daa68d0040db7746ae562a0ff82187f6",
        "fixCommit": "62473ad0f747e245e514c93e741bb8e168a2a207",
        "regressionTestGitBlob": "4c0aacd74a59cd6a5049b263335ad2b1f17e4cc4"}, "BROWSER_CONSTANTS")
    pw = closed(data["playwright"], {"version", "gitHead", "browserBuildRevision", "tarball", "integrity", "license", "node"}, "PW_SCHEMA")
    demand(pw == {"version": "1.65.0-alpha-2026-10-23", "gitHead": "20a2087ea43412b90c172c88faef80786ee18b8b",
        "browserBuildRevision": "1251", "tarball": "https://registry.npmjs.org/playwright-core/-/playwright-core-1.65.0-alpha-2026-10-23.tgz",
        "integrity": "sha512-2vqfxKkSB94itSPN4IeJlDiw3Ulsr+FVbqiS7HL2j/lE5gI5T7V7b4HkTG3om6ou35KTie0jaiGdCk3+FCxeKw==",
        "license": "Apache-2.0", "node": ">=20"}, "PW_CONSTANTS")
    closed(data["metadata"], set(METADATA_NAMES), "METADATA_SET")
    tag = "https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8103.6"
    pw_source = "https://raw.githubusercontent.com/microsoft/playwright/" + pw["gitHead"]
    expected_urls = {
        "cft-version.json": "https://googlechromelabs.github.io/chrome-for-testing/157.0.8103.6.json",
        "npm-package.json": "https://registry.npmjs.org/playwright-core/1.65.0-alpha-2026-10-23",
        "pw-browsers.json": pw_source + "/packages/playwright-core/browsers.json",
        "pw-registry.txt": pw_source + "/packages/playwright-core/src/server/registry/index.ts",
        "chromium-tag.json": tag + "?format=JSON",
        "fix-included-in.json": "https://chromium-review.googlesource.com/projects/chromium%2Fsrc/commits/" + browser["fixCommit"] + "/in",
        "chromium-loader.b64": tag + "/third_party/blink/renderer/platform/loader/fetch/response_body_loader.cc?format=TEXT",
        "chromium-webtest.b64": tag + "/third_party/blink/web_tests/http/tests/inspector-protocol/network/fetch-completed-body-loading-finished.js?format=TEXT",
        "chromium-fix.json": "https://chromium.googlesource.com/chromium/src/+/" + browser["fixCommit"] + "?format=JSON"}
    demand(data["metadata"] == expected_urls, "METADATA_URLS")
    demand(data["limits"] == {"httpTimeoutSeconds": 30, "totalBudgetSeconds": 300,
        "metadataBytesPerFile": 262144, "metadataBytesTotal": 2097152,
        "zipEntries": 4096, "zipUncompressedBytes": 1610612736, "zipMaxMemberRatio": 300}, "LIMIT_CONSTANTS")
    return data


def validate_metadata(candidate: dict, raw: dict[str, bytes]) -> None:
    demand(set(raw) == METADATA_NAMES, "METADATA_SET")
    limits, browser, pw = candidate["limits"], candidate["browser"], candidate["playwright"]
    demand(sum(map(len, raw.values())) <= limits["metadataBytesTotal"] and
           all(len(value) <= limits["metadataBytesPerFile"] for value in raw.values()), "METADATA_LIMIT")
    cft = strict_json(raw["cft-version.json"])
    demand(cft["version"] == browser["version"] and cft["revision"] == browser["cftRevision"], "CFT_VERSION")
    matches = [item for item in cft["downloads"]["chrome"] if item.get("platform") == "linux64"]
    demand(matches == [{"platform": "linux64", "url": browser["url"]}], "CFT_DOWNLOAD")
    npm = strict_json(raw["npm-package.json"])
    demand(npm["name"] == "playwright-core" and npm["version"] == pw["version"] and
           npm["gitHead"] == pw["gitHead"] and npm["license"] == pw["license"] and
           npm["engines"] == {"node": pw["node"]} and npm["bin"] == {"playwright-core": "cli.js"} and
           not npm.get("dependencies") and not npm.get("optionalDependencies") and
           npm["dist"]["tarball"] == pw["tarball"] and npm["dist"]["integrity"] == pw["integrity"], "PW_PACKAGE")
    browsers = strict_json(raw["pw-browsers.json"])
    chromium = [item for item in browsers["browsers"] if item.get("name") == "chromium"]
    demand(len(chromium) == 1 and chromium[0]["revision"] == pw["browserBuildRevision"] and
           chromium[0]["browserVersion"] == browser["version"] and
           chromium[0]["title"] == "Chrome for Testing", "PW_BROWSER")
    registry = raw["pw-registry.txt"].decode("utf-8", errors="strict")
    demand("builds/cft/${browserVersion}/${suffix}" in registry and
           "cftUrl('linux64/chrome-linux64.zip')" in registry and
           "'https://cdn.playwright.dev'" in registry, "PW_REGISTRY")
    tag = strict_json(raw["chromium-tag.json"], gerrit=True)
    demand(tag["commit"] == browser["sourceTagCommit"], "CHROMIUM_TAG")
    included = strict_json(raw["fix-included-in.json"], gerrit=True)
    demand(type(included.get("tags")) is list and browser["version"] in included["tags"], "FIX_ANCESTRY")
    loader = base64.b64decode(raw["chromium-loader.b64"].strip(b" \t\r\n"), validate=True).decode("utf-8", errors="strict")
    demand(re.search(r"HandleResult\(result\);\s*if \(bytes_consumer_client_\) \{\s*bytes_consumer_client_->OnStateChange\(\);", loader) is not None,
           "FIX_ORDER")
    webtest = base64.b64decode(raw["chromium-webtest.b64"].strip(b" \t\r\n"), validate=True)
    git_blob = hashlib.sha1(b"blob " + str(len(webtest)).encode() + b"\0" + webtest).hexdigest()
    demand(git_blob == browser["regressionTestGitBlob"], "REGRESSION_BLOB")
    fix = strict_json(raw["chromium-fix.json"], gerrit=True)
    demand(fix["commit"] == browser["fixCommit"] and any(item.get("new_id") == git_blob and
        item.get("new_path") == "third_party/blink/web_tests/http/tests/inspector-protocol/network/fetch-completed-body-loading-finished.js"
        for item in fix["tree_diff"]), "FIX_SOURCE_BINDING")


def inventory(path: Path, limits: dict) -> dict:
    """Inspect only; deliberately never decompress members, write them, or run them."""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - 65557))
        tail = handle.read(65557)
        end = tail.rfind(b"PK\x05\x06")
        demand(end >= 0 and len(tail) - end >= 22, "ZIP_EOCD")
        fields = struct.unpack("<4s4H2IH", tail[end:end + 22])
        _, disk, central_disk, disk_count, count, central_bytes, central_start, comment = fields
        eocd_offset = size - len(tail) + end
        demand(disk == 0 and central_disk == 0 and disk_count == count and 0 < count <= limits["zipEntries"], "ZIP_ENTRY_COUNT")
        demand(count != 65535 and central_start != 0xffffffff and central_bytes != 0xffffffff and
               central_start + central_bytes == eocd_offset and end + 22 + comment == len(tail), "ZIP_LAYOUT")
    names, members, total, offsets = set(), [], 0, []
    with zipfile.ZipFile(path, "r") as archive, path.open("rb") as handle:
        entries = archive.infolist()
        demand(len(entries) == count, "ZIP_ENTRY_COUNT")
        for item in entries:
            name = item.orig_filename
            demand(name == item.filename and bool(name) and len(name.encode("utf-8")) <= 512 and
                   not any(ord(char) < 32 or ord(char) == 127 for char in name)
                   and "\\" not in name and ":" not in name and not name.startswith("/"), "ZIP_PATH")
            components = name.rstrip("/").split("/")
            demand(all(part not in ("", ".", "..") for part in components) and
                   PurePosixPath(name).parts[0] == "chrome-linux64", "ZIP_PATH")
            normalized = unicodedata.normalize("NFC", name).casefold().rstrip("/")
            demand(normalized not in names, "ZIP_DUPLICATE")
            names.add(normalized)
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            demand(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not stat.S_ISLNK(mode), "ZIP_LINK_OR_SPECIAL")
            demand(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "ZIP_ENCRYPTION_OR_METHOD")
            demand(item.file_size >= 0 and item.compress_size >= 0 and
                   item.file_size <= max(1, item.compress_size) * limits["zipMaxMemberRatio"], "ZIP_RATIO")
            demand(not item.is_dir() or item.file_size == 0, "ZIP_DIRECTORY_DATA")
            total += item.file_size
            demand(total <= limits["zipUncompressedBytes"], "ZIP_TOTAL_LIMIT")
            handle.seek(item.header_offset)
            local = handle.read(30)
            demand(len(local) == 30 and local[:4] == b"PK\x03\x04", "ZIP_LOCAL_HEADER")
            local_fields = struct.unpack("<4s5H3I2H", local)
            name_size, extra_size = local_fields[-2:]
            local_name = handle.read(name_size)
            encoding = "utf-8" if item.flag_bits & 0x800 else "cp437"
            demand(local_name.decode(encoding, errors="strict") == name and
                   local_fields[2] == item.flag_bits and local_fields[3] == item.compress_type, "ZIP_LOCAL_MISMATCH")
            if not item.flag_bits & 8:
                demand(local_fields[6:9] == (item.CRC, item.compress_size, item.file_size), "ZIP_LOCAL_SIZE_CRC")
            data_end = item.header_offset + 30 + name_size + extra_size + item.compress_size
            demand(0 <= item.header_offset < data_end <= central_start, "ZIP_MEMBER_BOUNDS")
            offsets.append((item.header_offset, data_end))
            members.append({"path": name, "compressedBytes": item.compress_size, "bytes": item.file_size,
                            "crc32": f"{item.CRC:08x}", "method": item.compress_type, "unixMode": mode})
        offsets.sort()
        demand(all(left[1] <= right[0] for left, right in zip(offsets, offsets[1:])), "ZIP_MEMBER_OVERLAP")
    demand(any(item["path"] == "chrome-linux64/chrome" and item["bytes"] > 0 for item in members), "ZIP_BROWSER_MISSING")
    demand(len(canonical(members)) <= 1024 * 1024, "ZIP_INVENTORY_LIMIT")
    return {"entries": len(members), "uncompressedBytes": total, "membersSha256": sha256(canonical(members)),
            "members": members, "decompressed": False, "executed": False}


def hash_browser(path: Path, browser: dict) -> dict:
    before = path.lstat()
    demand(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == browser["bytes"], "BROWSER_FILE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    sha, md5, count = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    try:
        opened = os.fstat(fd)
        demand((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "FILE_CHANGED")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            while chunk := handle.read(65536):
                count += len(chunk)
                demand(count <= browser["bytes"], "BROWSER_SIZE")
                sha.update(chunk)
                md5.update(chunk)
        after = os.fstat(fd)
        final = path.lstat()
        demand((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
               (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns), "FILE_CHANGED")
    finally:
        os.close(fd)
    encoded_md5 = base64.b64encode(md5.digest()).decode()
    demand(count == browser["bytes"] and encoded_md5 == browser["md5Base64"], "BROWSER_MD5_OR_SIZE")
    return {"bytes": count, "sha256": sha.hexdigest(), "md5Base64": encoded_md5}


def evidence_paths(evidence: Path) -> set[str]:
    demand(evidence.is_absolute() and stat.S_ISDIR(evidence.lstat().st_mode), "EVIDENCE_DIRECTORY")
    result = set()
    for directory, directories, filenames in os.walk(evidence, followlinks=False):
        for name in directories:
            path = Path(directory) / name
            demand(stat.S_ISDIR(path.lstat().st_mode) and not path.is_symlink(), "EVIDENCE_LINK")
            demand(path.relative_to(evidence).as_posix() == "sources", "EVIDENCE_DIRECTORY_SET")
        for name in filenames:
            path = Path(directory) / name
            demand(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink() and path.lstat().st_nlink == 1,
                   "EVIDENCE_LINK")
            result.add(path.relative_to(evidence).as_posix())
    expected = {"browser.zip", "acquisition.json"} | {"sources/" + name for name in METADATA_NAMES}
    demand(result == expected, "EVIDENCE_FILE_SET")
    return result


def check_evidence(repo: Path, evidence: Path, commit: str) -> dict:
    binding = source_binding(repo, commit)
    candidate_raw = read_regular(repo / SOURCE_DIRECTORY / "candidate.json", 262144)
    candidate = load_candidate(candidate_raw)
    evidence_paths(evidence)
    manifest = closed(strict_json(read_regular(evidence / "acquisition.json", 2 * 1024 * 1024)), MANIFEST_KEYS, "MANIFEST_SCHEMA")
    demand(manifest["schemaVersion"] == 1 and manifest["kind"] == "acquisition-only" and
           manifest["sourceCommit"] == commit and manifest["sourceFiles"] == binding and
           manifest["candidateSha256"] == sha256(candidate_raw) and manifest["limitations"] == LIMITATIONS,
           "MANIFEST_BINDING")
    files = closed(manifest["files"], {"browser.zip"} | {"sources/" + name for name in METADATA_NAMES}, "MANIFEST_FILE_SET")
    metadata = {}
    for name in METADATA_NAMES:
        raw = read_regular(evidence / "sources" / name, candidate["limits"]["metadataBytesPerFile"])
        metadata[name] = raw
        receipt = http_receipt(files["sources/" + name])
        demand(receipt["url"] == candidate["metadata"][name] and receipt["status"] == 200 and
               receipt["bytes"] == len(raw) and receipt["sha256"] == sha256(raw), "METADATA_RECEIPT")
    validate_metadata(candidate, metadata)
    digest = hash_browser(evidence / "browser.zip", candidate["browser"])
    receipt = http_receipt(files["browser.zip"])
    demand(receipt["url"] == candidate["browser"]["url"] and receipt["status"] == 200 and
           receipt["bytes"] == digest["bytes"] and receipt["sha256"] == digest["sha256"] and
           receipt["contentLength"] == str(digest["bytes"]) and receipt["generation"] == candidate["browser"]["generation"] and
           sorted(receipt["googleHashes"]) == sorted(["crc32c=" + candidate["browser"]["crc32cBase64"],
               "md5=" + candidate["browser"]["md5Base64"]]), "BROWSER_RECEIPT")
    demand(manifest["browser"] == digest, "BROWSER_MANIFEST")
    actual_inventory = inventory(evidence / "browser.zip", candidate["limits"])
    demand(actual_inventory == manifest["inventory"], "INVENTORY_MANIFEST")
    demand(binding == source_binding(repo, commit), "SOURCE_CHANGED")
    return {"schemaVersion": 1, "outcome": "ACQUISITION_VERIFIED_NOT_EXECUTED", "sourceCommit": commit,
            "candidateSha256": sha256(candidate_raw), "browser": digest,
            "inventory": {key: value for key, value in actual_inventory.items() if key != "members"},
            "filesVerified": len(files), "sourceFilesVerified": len(binding), "limitations": LIMITATIONS}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    demand(sys.platform == "linux" and bool(getattr(os, "O_NOFOLLOW", 0)), "LINUX_REQUIRED")
    repo, evidence, report = args.repo.resolve(strict=True), args.evidence.absolute(), args.report.absolute()
    demand(report.parent.resolve(strict=True) != evidence.resolve(strict=True) and
           evidence.resolve(strict=True) not in report.parent.resolve(strict=True).parents, "REPORT_INSIDE_EVIDENCE")
    result = check_evidence(repo, evidence, args.source_commit)
    write_new(report, canonical(result))
    print(canonical(result).decode(), end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError,
            zipfile.BadZipFile, struct.error) as error:
        print("acquisition verification rejected: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
