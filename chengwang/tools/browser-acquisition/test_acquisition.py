#!/usr/bin/env python3
"""Frozen synthetic-only contracts. No HTTP, TLS, browser, Go, or production operations."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

from acquire_browser import NoRedirect, remaining
from check_acquisition import (canonical, demand, evidence_paths, hash_browser, inventory,
    load_candidate, read_regular, strict_json, validate_metadata, write_new)

CASE_NAMES = (
    "test_browser_hash_rejects_mutated_original",
    "test_candidate_rejects_fabricated_sha256",
    "test_candidate_rejects_changed_origin",
    "test_candidate_rejects_weakened_limits",
    "test_deadline_rejects_expired_budget",
    "test_evidence_rejects_extra_file",
    "test_inventory_accepts_small_synthetic_full_layout",
    "test_inventory_rejects_absolute_and_parent_paths",
    "test_inventory_rejects_compression_bomb",
    "test_inventory_rejects_duplicate_members",
    "test_inventory_rejects_encrypted_members",
    "test_inventory_rejects_entry_and_total_limits",
    "test_inventory_rejects_symlinks",
    "test_inventory_rejects_truncated_archive",
    "test_json_rejects_duplicate_and_nonfinite",
    "test_metadata_rejects_mismatched_source_chain",
    "test_redirect_is_rejected_without_following",
    "test_write_new_refuses_overwrite",
)
CASE_NAMES_SHA256 = "0558c8dc1ef5c52b839bc81f30047b1b242ad67b2dfe67a0c89ffa81c1b59f9a"


class AcquisitionContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chengwang-acquire-synthetic-")
        self.root = Path(self.temp.name)
        self.candidate_raw = (Path(__file__).parent / "candidate.json").read_bytes()
        self.candidate = load_candidate(self.candidate_raw)
        self.limits = dict(self.candidate["limits"])

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, names=None, payload=b"synthetic-not-a-browser", *, mode=None, compression=zipfile.ZIP_STORED):
        path = self.root / "synthetic.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                for name in names or ["chrome-linux64/chrome"]:
                    if mode is None:
                        archive.writestr(name, payload)
                    else:
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = mode << 16
                        archive.writestr(info, payload)
        # Force synthetic writes to disk before POSIX-style change detection.
        # This is fixture preparation, not a relaxed checker on Windows.
        with path.open("r+b") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        return path

    def test_inventory_accepts_small_synthetic_full_layout(self):
        result = inventory(self.archive(), self.limits)
        self.assertEqual(result["entries"], 1)
        self.assertFalse(result["executed"])
        self.assertFalse(result["decompressed"])

    def test_candidate_rejects_fabricated_sha256(self):
        candidate = copy.deepcopy(self.candidate)
        candidate["browser"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "BROWSER_CONSTANTS"):
            load_candidate(canonical(candidate))

    def test_candidate_rejects_changed_origin(self):
        candidate = copy.deepcopy(self.candidate)
        candidate["metadata"]["cft-version.json"] = "http://127.0.0.1/fake"
        with self.assertRaisesRegex(ValueError, "METADATA_URLS"):
            load_candidate(canonical(candidate))

    def test_candidate_rejects_weakened_limits(self):
        candidate = copy.deepcopy(self.candidate)
        candidate["limits"]["zipEntries"] = 100000
        with self.assertRaisesRegex(ValueError, "LIMIT_CONSTANTS"):
            load_candidate(canonical(candidate))

    def test_json_rejects_duplicate_and_nonfinite(self):
        for raw in [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_redirect_is_rejected_without_following(self):
        with self.assertRaisesRegex(ValueError, "REDIRECT_FORBIDDEN"):
            NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.invalid/")

    def test_deadline_rejects_expired_budget(self):
        with self.assertRaisesRegex(ValueError, "TOTAL_BUDGET"):
            remaining(0, 30)

    def test_write_new_refuses_overwrite(self):
        path = self.root / "once.json"
        write_new(path, b"first")
        with self.assertRaises(FileExistsError):
            write_new(path, b"second")
        self.assertEqual(read_regular(path, 100), b"first")

    def test_browser_hash_rejects_mutated_original(self):
        path = self.archive()
        raw = path.read_bytes()
        browser = {"bytes": len(raw), "md5Base64": base64.b64encode(hashlib.md5(raw, usedforsecurity=False).digest()).decode()}
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with path.open("r+b") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        # Windows lstat/fstat ctime representations can disagree on a rewritten
        # fixture; fail-closed FILE_CHANGED is also a valid rejection. The real
        # acquisition/checker CLIs remain Linux-only with their full race checks.
        with self.assertRaisesRegex(ValueError, "BROWSER_MD5_OR_SIZE|FILE_CHANGED"):
            hash_browser(path, browser)

    def test_inventory_rejects_absolute_and_parent_paths(self):
        for name in ["/chrome-linux64/chrome", "chrome-linux64/../chrome",
                     "chrome-linux64//chrome", "elsewhere/chrome"]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "ZIP_PATH"):
                inventory(self.archive([name]), self.limits)
        # ZipInfo normalizes native backslashes on Windows: inject the invalid
        # byte into both serialized headers so the checker sees original bytes.
        path = self.archive(["chrome-linux64/a/chrome"])
        path.write_bytes(path.read_bytes().replace(b"chrome-linux64/a/chrome", b"chrome-linux64/a\\chrome"))
        with self.assertRaisesRegex(ValueError, "ZIP_PATH"):
            inventory(path, self.limits)

    def test_inventory_rejects_duplicate_members(self):
        with self.assertRaisesRegex(ValueError, "ZIP_DUPLICATE"):
            inventory(self.archive(["chrome-linux64/chrome", "chrome-linux64/chrome"]), self.limits)

    def test_inventory_rejects_symlinks(self):
        with self.assertRaisesRegex(ValueError, "ZIP_LINK_OR_SPECIAL"):
            inventory(self.archive(mode=stat.S_IFLNK | 0o777), self.limits)

    def test_inventory_rejects_encrypted_members(self):
        path = self.archive()
        raw = bytearray(path.read_bytes())
        central = raw.index(b"PK\x01\x02")
        raw[6] |= 1
        raw[central + 8] |= 1
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "ZIP_ENCRYPTION_OR_METHOD"):
            inventory(path, self.limits)

    def test_inventory_rejects_compression_bomb(self):
        with self.assertRaisesRegex(ValueError, "ZIP_RATIO"):
            inventory(self.archive(payload=b"x" * 1000000, compression=zipfile.ZIP_DEFLATED), self.limits)

    def test_inventory_rejects_entry_and_total_limits(self):
        limits = dict(self.limits, zipEntries=1)
        with self.assertRaisesRegex(ValueError, "ZIP_ENTRY_COUNT"):
            inventory(self.archive(["chrome-linux64/chrome", "chrome-linux64/other"]), limits)
        limits = dict(self.limits, zipUncompressedBytes=1)
        with self.assertRaisesRegex(ValueError, "ZIP_TOTAL_LIMIT"):
            inventory(self.archive(), limits)

    def test_inventory_rejects_truncated_archive(self):
        path = self.archive()
        path.write_bytes(path.read_bytes()[:-7])
        with self.assertRaisesRegex(ValueError, "ZIP_EOCD|ZIP_LAYOUT"):
            inventory(path, self.limits)

    def test_evidence_rejects_extra_file(self):
        (self.root / "extra").write_bytes(b"synthetic")
        with self.assertRaisesRegex(ValueError, "EVIDENCE_FILE_SET"):
            evidence_paths(self.root.absolute())

    def test_metadata_rejects_mismatched_source_chain(self):
        browser, pw = self.candidate["browser"], self.candidate["playwright"]
        # Explicit synthetic validator seam: no official fetched file or browser
        # is used. Production load_candidate still locks the real regression blob.
        synthetic_webtest = b"synthetic-regression-not-upstream-test\n"
        candidate = copy.deepcopy(self.candidate)
        blob = hashlib.sha1(b"blob " + str(len(synthetic_webtest)).encode() + b"\0" + synthetic_webtest).hexdigest()
        candidate["browser"]["regressionTestGitBlob"] = blob
        raw = {
            "cft-version.json": canonical({"version": browser["version"], "revision": browser["cftRevision"],
                "downloads": {"chrome": [{"platform": "linux64", "url": browser["url"]}]}}),
            "npm-package.json": canonical({"name": "playwright-core", "version": pw["version"],
                "gitHead": pw["gitHead"], "license": pw["license"], "engines": {"node": pw["node"]},
                "bin": {"playwright-core": "cli.js"}, "dist": {"tarball": pw["tarball"], "integrity": pw["integrity"]}}),
            "pw-browsers.json": canonical({"browsers": [{"name": "chromium", "revision": pw["browserBuildRevision"],
                "browserVersion": browser["version"], "title": "Chrome for Testing"}]}),
            "pw-registry.txt": b"builds/cft/${browserVersion}/${suffix}\ncftUrl('linux64/chrome-linux64.zip')\n'https://cdn.playwright.dev'",
            "chromium-tag.json": b")]}'\n" + canonical({"commit": browser["sourceTagCommit"]}),
            "fix-included-in.json": b")]}'\n" + canonical({"tags": [browser["version"]]}),
            "chromium-loader.b64": base64.b64encode(b"HandleResult(result); if (bytes_consumer_client_) { bytes_consumer_client_->OnStateChange();"),
            "chromium-webtest.b64": base64.b64encode(synthetic_webtest),
            "chromium-fix.json": b")]}'\n" + canonical({"commit": browser["fixCommit"], "tree_diff": [{"new_id": blob,
                "new_path": "third_party/blink/web_tests/http/tests/inspector-protocol/network/fetch-completed-body-loading-finished.js"}]})}
        validate_metadata(candidate, raw)
        changes = [
            ("cft-version.json", canonical({"version": "wrong", "revision": "1717349"}), "CFT_VERSION"),
            ("npm-package.json", raw["npm-package.json"].replace(pw["gitHead"].encode(), b"0" * 40), "PW_PACKAGE"),
            ("pw-browsers.json", raw["pw-browsers.json"].replace(b'"1251"', b'"1248"'), "PW_BROWSER"),
            ("pw-registry.txt", b"wrong-download-origin", "PW_REGISTRY"),
            ("chromium-tag.json", b")]}'\n" + canonical({"commit": "0" * 40}), "CHROMIUM_TAG"),
            ("fix-included-in.json", b")]}'\n" + canonical({"tags": []}), "FIX_ANCESTRY"),
            ("chromium-loader.b64", base64.b64encode(b"OnStateChange(); HandleResult(result);"), "FIX_ORDER"),
            ("chromium-webtest.b64", base64.b64encode(b"wrong-regression-test"), "REGRESSION_BLOB"),
            ("chromium-fix.json", b")]}'\n" + canonical({"commit": browser["fixCommit"], "tree_diff": []}), "FIX_SOURCE_BINDING")]
        for name, replacement, expected in changes:
            damaged = dict(raw, **{name: replacement})
            with self.subTest(metadata=name), self.assertRaisesRegex(ValueError, expected):
                validate_metadata(candidate, damaged)


if __name__ == "__main__":
    actual = sorted(unittest.defaultTestLoader.getTestCaseNames(AcquisitionContracts))
    demand(actual == sorted(CASE_NAMES) and len(actual) == 18 and hashlib.sha256(
        "\n".join(actual).encode()).hexdigest() == CASE_NAMES_SHA256, "FROZEN_TEST_NAME_SET")
    print(json.dumps({"syntheticCases": 18, "sortedNamesSha256": hashlib.sha256(
        "\n".join(actual).encode()).hexdigest(), "network": False, "browserExecuted": False}), flush=True)
    unittest.main(verbosity=2)
