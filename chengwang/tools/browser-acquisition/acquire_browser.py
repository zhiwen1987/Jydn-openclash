#!/usr/bin/env python3
"""Linux CI acquisition only: public TLS bytes, no extraction/install/browser execution."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import ssl
import sys
import time
import urllib.error
import urllib.request

from check_acquisition import (LIMITATIONS, SOURCE_DIRECTORY, canonical, demand,
    hash_browser, inventory, load_candidate, read_regular, sha256, source_binding,
    validate_metadata, write_new)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("REDIRECT_FORBIDDEN")


def public_opener() -> urllib.request.OpenerDirector:
    demand(not any(os.environ.get(name) for name in (
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")), "CA_OVERRIDE_FORBIDDEN")
    context = ssl.create_default_context()
    demand(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "PUBLIC_TLS_REQUIRED")
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                      urllib.request.HTTPSHandler(context=context))


def remaining(deadline: float, per_request: int) -> float:
    value = deadline - time.monotonic()
    demand(value > 0, "TOTAL_BUDGET")
    return min(per_request, value)


def acquire_file(opener: urllib.request.OpenerDirector, url: str, target: Path,
                 maximum: int, deadline: float, timeout: int, expected: dict | None = None) -> dict:
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity",
        "User-Agent": "chengwang-ci-browser-acquisition/1"}, method="GET")
    with opener.open(request, timeout=remaining(deadline, timeout)) as response:
        demand(response.status == 200 and response.geturl() == url, "HTTP_STATUS_OR_URL")
        encodings = response.headers.get_all("Content-Encoding", [])
        demand(len(encodings) <= 1 and (not encodings or encodings[0].lower() == "identity"), "HTTP_ENCODING")
        lengths = response.headers.get_all("Content-Length", [])
        demand(len(lengths) <= 1 and (not lengths or (len(lengths[0]) <= 24 and lengths[0].isascii() and lengths[0].isdigit())), "HTTP_LENGTH")
        length = lengths[0] if lengths else None
        demand(length is None or int(length) <= maximum, "HTTP_LENGTH_LIMIT")
        generations = response.headers.get_all("x-goog-generation", [])
        demand(len(generations) <= 1 and (not generations or (len(generations[0]) <= 24 and generations[0].isascii() and generations[0].isdigit())), "HTTP_GENERATION")
        generation = generations[0] if generations else None
        google_hashes = [item.strip() for header in response.headers.get_all("x-goog-hash", []) for item in header.split(",")]
        demand(len(google_hashes) <= 4 and all(len(item) <= 100 for item in google_hashes), "HTTP_HASH_HEADERS")
        if expected is not None:
            demand(length == str(expected["bytes"]) and generation == expected["generation"] and
                   sorted(google_hashes) == sorted(["crc32c=" + expected["crc32cBase64"],
                       "md5=" + expected["md5Base64"]]), "BROWSER_HTTP_IDENTITY")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest, count = hashlib.sha256(), 0
        try:
            with os.fdopen(fd, "wb", closefd=False) as handle:
                while True:
                    remaining(deadline, timeout)
                    chunk = response.read(min(65536, maximum - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    demand(count <= maximum, "TRANSFER_LIMIT")
                    digest.update(chunk)
                    handle.write(chunk)
                remaining(deadline, timeout)
                demand(length is None or count == int(length), "HTTP_TRUNCATED")
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
    return {"url": url, "status": 200, "bytes": count, "sha256": digest.hexdigest(),
            "contentLength": length, "generation": generation, "googleHashes": google_hashes}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    demand(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true" and
           os.environ.get("RUNNER_OS") == "Linux" and bool(getattr(os, "O_NOFOLLOW", 0)), "LINUX_CI_REQUIRED")
    repo, output = args.repo.resolve(strict=True), args.output.absolute()
    demand(output.parent == output.parent.resolve(strict=True), "OUTPUT_PARENT_ALIAS")
    before = source_binding(repo, args.source_commit)
    raw = read_regular(repo / SOURCE_DIRECTORY / "candidate.json", 262144)
    candidate = load_candidate(raw)
    os.mkdir(output, mode=0o700)
    os.chmod(output, 0o700)
    os.mkdir(output / "sources", mode=0o700)
    opener = public_opener()
    limits = candidate["limits"]
    deadline = time.monotonic() + limits["totalBudgetSeconds"]
    receipts, metadata, metadata_total = {}, {}, 0
    for name, url in candidate["metadata"].items():
        target = output / "sources" / name
        receipts["sources/" + name] = acquire_file(opener, url, target,
            min(limits["metadataBytesPerFile"], limits["metadataBytesTotal"] - metadata_total),
            deadline, limits["httpTimeoutSeconds"])
        metadata[name] = read_regular(target, limits["metadataBytesPerFile"])
        metadata_total += len(metadata[name])
    validate_metadata(candidate, metadata)
    receipts["browser.zip"] = acquire_file(opener, candidate["browser"]["url"], output / "browser.zip",
        candidate["browser"]["bytes"], deadline, limits["httpTimeoutSeconds"], candidate["browser"])
    digest = hash_browser(output / "browser.zip", candidate["browser"])
    actual_inventory = inventory(output / "browser.zip", limits)
    remaining(deadline, limits["httpTimeoutSeconds"])
    demand(before == source_binding(repo, args.source_commit), "SOURCE_CHANGED")
    manifest = {"schemaVersion": 1, "kind": "acquisition-only", "sourceCommit": args.source_commit,
        "sourceFiles": before, "candidateSha256": sha256(raw), "files": receipts,
        "browser": digest, "inventory": actual_inventory, "limitations": LIMITATIONS}
    write_new(output / "acquisition.json", canonical(manifest))
    print(canonical({"outcome": "ACQUIRED_NOT_EXECUTED", "sourceCommit": args.source_commit,
        "browser": digest, "files": len(receipts) + 1, "zipEntries": actual_inventory["entries"],
        "limitations": LIMITATIONS}).decode(), end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, urllib.error.URLError) as error:
        print("browser acquisition rejected: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
