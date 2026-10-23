#!/usr/bin/env python3
"""Enforce reviewed ZIP SHA and expand in isolated Linux CI, never run browser."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import ssl
import stat
import sys
import time
import urllib.request

import check_consumption as C


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("REDIRECT_FORBIDDEN")


def public_opener():
    C.need(not any(os.environ.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")), "CA_OVERRIDE_FORBIDDEN")
    context = ssl.create_default_context()
    C.need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "PUBLIC_TLS_REQUIRED")
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                      urllib.request.HTTPSHandler(context=context))


def remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    C.need(value > 0, "CONSUMPTION_TOTAL_BUDGET")
    return min(30, value)


def download_original(target: Path, browser: dict, crc32c: str, deadline: float) -> dict:
    request = urllib.request.Request(browser["url"], headers={"Accept-Encoding": "identity",
        "User-Agent": "chengwang-ci-pinned-browser-consumption/1"}, method="GET")
    with public_opener().open(request, timeout=remaining(deadline)) as response:
        C.need(response.status == 200 and response.geturl() == browser["url"], "HTTP_IDENTITY")
        encoding = response.headers.get_all("Content-Encoding", [])
        C.need(not encoding or encoding == ["identity"], "HTTP_ENCODING")
        C.need(response.headers.get_all("Content-Length", []) == [str(browser["bytes"])], "HTTP_EXACT_LENGTH")
        C.need(response.headers.get_all("x-goog-generation", []) == [browser["generation"]], "HTTP_GENERATION")
        hashes = [value.strip() for item in response.headers.get_all("x-goog-hash", []) for value in item.split(",")]
        C.need(sorted(hashes) == sorted(["md5=" + browser["md5Base64"], "crc32c=" + crc32c]), "HTTP_GOOGLE_HASHES")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest, count = hashlib.sha256(), 0
        try:
            with os.fdopen(fd, "wb", closefd=False) as handle:
                while True:
                    remaining(deadline)
                    chunk = response.read(min(65536, browser["bytes"] - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    C.need(count <= browser["bytes"], "HTTP_BYTE_LIMIT")
                    digest.update(chunk)
                    handle.write(chunk)
                remaining(deadline)
                C.need(count == browser["bytes"] and digest.hexdigest() == browser["sha256"], "PIN_DOWNLOAD_SHA256")
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
    return {"url": browser["url"], "status": 200, "bytes": count, "sha256": digest.hexdigest(),
        "contentLength": str(count), "generation": browser["generation"], "googleHashes": hashes}


def copy_original(source: Path, target: Path, browser: dict, deadline: float) -> None:
    """No network and no inferred TLS claim. Keep the original input unchanged."""
    before = source.lstat()
    C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == browser["bytes"], "ARCHIVE_SOURCE")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    target_fd = None
    try:
        C.need(C.snapshot(before) == C.snapshot(os.fstat(fd)), "ARCHIVE_SOURCE_CHANGED")
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest, count = hashlib.sha256(), 0
        with os.fdopen(fd, "rb", closefd=False) as original, os.fdopen(target_fd, "wb", closefd=False) as output:
            while chunk := original.read(65536):
                remaining(deadline)
                count += len(chunk)
                C.need(count <= browser["bytes"], "ARCHIVE_BYTE_LIMIT")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(target_fd)
        C.need(count == browser["bytes"] and digest.hexdigest() == browser["sha256"] and
            C.snapshot(before) == C.snapshot(os.fstat(fd)) == C.snapshot(source.lstat()), "PIN_ARCHIVE_SHA256_OR_CHANGED")
    finally:
        os.close(fd)
        if target_fd is not None:
            os.close(target_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    C.require_linux_ci(sys.platform, os.environ)
    repo, output, report = args.repo.resolve(strict=True), args.output.absolute(), args.report.absolute()
    C.need(output.parent == output.parent.resolve(strict=True), "OUTPUT_PARENT_ALIAS")
    C.outside_report(output, report)
    pin, binding, acquisition, candidate = C.load_context(repo, args.source_commit)
    os.mkdir(output, mode=0o700)
    os.chmod(output, 0o700)
    original = output / "browser.zip"
    deadline = time.monotonic() + 300
    receipt = None
    if args.archive is None:
        mode = "PUBLIC_HTTPS_PINNED_ARCHIVE"
        receipt = download_original(original, pin["browser"], candidate["browser"]["crc32cBase64"], deadline)
    else:
        mode = "EXISTING_PINNED_ARCHIVE"
        copy_original(args.archive.absolute(), original, pin["browser"], deadline)
    digest = acquisition.hash_browser(original, candidate["browser"])
    C.need(digest["sha256"] == pin["browser"]["sha256"] == C.ZIP_SHA256, "PIN_ZIP_SHA256")
    inventory = acquisition.inventory(original, candidate["limits"])
    C.validate_inventory(inventory, pin["browser"])
    expanded = C.expand_original(original, output, inventory, candidate["limits"]["zipUncompressedBytes"])
    chrome = next(member for member in expanded["members"] if member["path"] == "chrome-linux64/chrome")
    elf = {"path": chrome["path"], "bytes": chrome["bytes"], "sha256": chrome["sha256"],
           **C.elf_file(output / chrome["path"])}
    remaining(deadline)
    C.need(binding == C.bind_sources(repo, args.source_commit), "SOURCE_CHANGED")
    manifest = {"schema": "chengwang.pinned-browser-consumption/v1", "sourceCommit": args.source_commit,
        "sourceFiles": binding, "pinSHA256": C.PIN_SHA256, "mode": mode, "zip": digest, "httpReceipt": receipt,
        "inventory": {key: value for key, value in inventory.items() if key != "members"},
        "expanded": expanded, "elf": elf, "pinEnforced": True, "browserExecuted": False,
        "production": False, "limitations": C.LIMITATIONS}
    C.write_new(output / "consumption.json", C.canonical(manifest))
    result = C.verify_consumption(repo, output, args.source_commit)
    remaining(deadline)
    C.write_new(report, C.canonical(result))
    print(C.canonical(result).decode(), end="")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("pinned browser consumption rejected: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
