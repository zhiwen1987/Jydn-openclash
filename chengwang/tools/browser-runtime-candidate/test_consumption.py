#!/usr/bin/env python3
"""Finite synthetic byte/policy cases only; no browser ZIP/network/execution."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zipfile

import check_consumption as C
import consume_pin as P

CASE_NAMES = (
    "test_compressed_member_truncation_rejected",
    "test_corrupt_member_crc_rejected",
    "test_deadline_is_fail_closed",
    "test_deflate_trailing_compressed_bytes_rejected",
    "test_elf64_minimal_structure_is_bytes_only",
    "test_elf_magic_machine_entry_and_bounds_rejected",
    "test_extra_source_executable_is_rejected",
    "test_json_duplicate_and_nonfinite_rejected",
    "test_linux_ci_gate_rejects_host_or_missing_ci",
    "test_member_actual_size_overflow_rejected",
    "test_new_report_existing_path_rejected",
    "test_new_report_inside_evidence_rejected",
    "test_permissions_strip_setuid_and_setgid",
    "test_pin_changed_byte_and_fake_sha_rejected",
    "test_pin_historical_reference_remains_unexecuted",
    "test_redirect_is_refused_without_network",
    "test_required_executable_source_mode_is_enforced",
    "test_special_member_types_are_rejected",
    "test_stored_and_deflate_actual_crc_and_hash",
    "test_total_member_budget_is_enforced",
)
CASE_NAMES_SHA256 = "28d61521916e7bd80da9303a9bb4ec25549fd12d6e984849af1fa1c4e361f103"


def synthetic_member(payload=b"synthetic-no-browser" * 257, method=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=method) as archive:
        archive.writestr("chrome-linux64/synthetic.data", payload)
    raw = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        info = copy.copy(archive.infolist()[0])
    return raw, info, payload


def synthetic_elf():
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\0" * 7
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 62, 1, 0x400080,
                         64, 0, 0, 64, 56, 1, 0, 0, 0)
    programs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, 512, 512, 4096)
    return header, programs, 512


class ConsumptionContracts(unittest.TestCase):
    def test_pin_historical_reference_remains_unexecuted(self):
        raw = (Path(__file__).parent / "pin.json").read_bytes()
        value = C.load_pin(raw)
        self.assertEqual(C.sha(raw), C.PIN_SHA256)
        self.assertFalse(value["consumedByExecutionHarness"])
        self.assertIsNone(value["browser"]["observedRuntimeRevision"])
        self.assertEqual(C.sha((Path(__file__).parent / "pin.json").read_bytes()), C.PIN_SHA256)

    def test_pin_changed_byte_and_fake_sha_rejected(self):
        raw = (Path(__file__).parent / "pin.json").read_bytes()
        for changed in (raw + b" ", raw.replace(C.ZIP_SHA256.encode(), b"0" * 64)):
            with self.subTest(changeBytes=len(changed)), self.assertRaisesRegex(ValueError, "PIN_REFERENCE_BYTES"):
                C.load_pin(changed)

    def test_linux_ci_gate_rejects_host_or_missing_ci(self):
        for platform, environment in (("win32", {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"}),
            ("linux", {}), ("linux", {"GITHUB_ACTIONS": "false", "RUNNER_OS": "Linux"}),
            ("linux", {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows"})):
            with self.subTest(platform=platform, environment=environment), self.assertRaisesRegex(ValueError, "LINUX_GITHUB_CI_REQUIRED"):
                C.require_linux_ci(platform, environment)

    def test_redirect_is_refused_without_network(self):
        with self.assertRaisesRegex(ValueError, "REDIRECT_FORBIDDEN"):
            P.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.invalid/")

    def test_deadline_is_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "CONSUMPTION_TOTAL_BUDGET"):
            P.remaining(0)

    def test_json_duplicate_and_nonfinite_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                C.strict_json(raw)

    def test_extra_source_executable_is_rejected(self):
        member = {"path": "chrome-linux64/unreviewed-executable", "unixMode": stat.S_IFREG | 0o755, "bytes": 1}
        with self.assertRaisesRegex(ValueError, "EXECUTABLE_NOT_ALLOWLISTED"):
            C.safe_mode(member)

    def test_required_executable_source_mode_is_enforced(self):
        member = {"path": "chrome-linux64/chrome", "unixMode": stat.S_IFREG | 0o644, "bytes": 1}
        with self.assertRaisesRegex(ValueError, "REQUIRED_EXECUTABLE_SOURCE_MODE"):
            C.safe_mode(member)

    def test_special_member_types_are_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "MEMBER_TYPE"):
                C.safe_mode({"path": "chrome-linux64/special", "unixMode": kind | 0o755, "bytes": 1})

    def test_permissions_strip_setuid_and_setgid(self):
        for extra in (0o4000, 0o2000, 0o6000):
            self.assertEqual(C.safe_mode({"path": "chrome-linux64/chrome", "unixMode": stat.S_IFREG | 0o755 | extra, "bytes": 1}), 0o500)
            self.assertEqual(C.safe_mode({"path": "chrome-linux64/data", "unixMode": stat.S_IFREG | 0o644 | extra, "bytes": 1}), 0o400)

    def test_stored_and_deflate_actual_crc_and_hash(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raw, info, payload = synthetic_member(payload=bytes(range(256)) * 1024, method=method)
            blocks = list(C.member_chunks(io.BytesIO(raw), info, len(payload)))
            self.assertEqual(b"".join(blocks), payload)
            self.assertEqual(hashlib.sha256(b"".join(blocks)).hexdigest(), hashlib.sha256(payload).hexdigest())
            self.assertTrue(all(0 < len(block) <= 65536 for block in blocks))

    def test_corrupt_member_crc_rejected(self):
        raw, info, _ = synthetic_member()
        info.CRC ^= 1
        with self.assertRaisesRegex(ValueError, "MEMBER_CRC_OR_SIZE"):
            list(C.member_chunks(io.BytesIO(raw), info, 100000))

    def test_member_actual_size_overflow_rejected(self):
        raw, info, _ = synthetic_member()
        info.file_size -= 1
        with self.assertRaisesRegex(ValueError, "MEMBER_ACTUAL_SIZE"):
            list(C.member_chunks(io.BytesIO(raw), info, 100000))

    def test_compressed_member_truncation_rejected(self):
        raw, info, _ = synthetic_member()
        fields = struct.unpack("<4s5H3I2H", raw[:30])
        end = 30 + fields[-2] + fields[-1] + info.compress_size
        with self.assertRaisesRegex(ValueError, "MEMBER_COMPRESSED_TRUNCATED|MEMBER_DEFLATE_TRUNCATED"):
            list(C.member_chunks(io.BytesIO(raw[:end - 2]), info, 100000))

    def test_deflate_trailing_compressed_bytes_rejected(self):
        raw, info, _ = synthetic_member()
        info.compress_size += 2
        with self.assertRaisesRegex(ValueError, "MEMBER_DEFLATE_TRAILING_OR_STALLED"):
            list(C.member_chunks(io.BytesIO(raw), info, 100000))

    def test_total_member_budget_is_enforced(self):
        raw, info, payload = synthetic_member()
        with self.assertRaisesRegex(ValueError, "MEMBER_STREAM_POLICY"):
            list(C.member_chunks(io.BytesIO(raw), info, len(payload) - 1))

    def test_elf64_minimal_structure_is_bytes_only(self):
        value = C.parse_elf(*synthetic_elf())
        self.assertEqual(value["class"], "ELF64")
        self.assertEqual(value["machine"], "x86_64")
        self.assertEqual(value["loadSegments"], 1)

    def test_elf_magic_machine_entry_and_bounds_rejected(self):
        header, programs, size = synthetic_elf()
        cases = [(b"NOPE" + header[4:], programs, size)]
        for index, value in ((2, 183), (4, 0x500000), (5, 500), (10, 257)):
            fields = list(struct.unpack("<16sHHIQQQIHHHHHH", header))
            fields[index] = value
            cases.append((struct.pack("<16sHHIQQQIHHHHHH", *fields), programs, size))
        segment = list(struct.unpack("<IIQQQQQQ", programs)); segment[5] = 513
        cases.append((header, struct.pack("<IIQQQQQQ", *segment), size))
        for case in cases:
            with self.subTest(headerSHA=C.sha(case[0])), self.assertRaises(ValueError):
                C.parse_elf(*case)

    def test_new_report_inside_evidence_rejected(self):
        with tempfile.TemporaryDirectory(prefix="cw-consume-synthetic-") as raw:
            root = Path(raw)
            with self.assertRaisesRegex(ValueError, "NEW_REPORT_OUTSIDE_TREE"):
                C.outside_report(root, root / "report.json")

    def test_new_report_existing_path_rejected(self):
        with tempfile.TemporaryDirectory(prefix="cw-consume-synthetic-") as raw:
            root = Path(raw)
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ValueError, "NEW_REPORT_OUTSIDE_TREE"):
                C.outside_report(root / "output-not-created", existing)


if __name__ == "__main__":
    actual = sorted(unittest.defaultTestLoader.getTestCaseNames(ConsumptionContracts))
    C.need(actual == sorted(CASE_NAMES) and len(actual) == 20 and hashlib.sha256(
        "\n".join(actual).encode()).hexdigest() == CASE_NAMES_SHA256, "FROZEN_CONSUMPTION_NAME_SET")
    print(json.dumps({"syntheticCases": 20, "namesSHA256": hashlib.sha256("\n".join(actual).encode()).hexdigest(),
        "network": False, "realBrowserArchiveDownloadedOrExpanded": False, "browserExecuted": False}), flush=True)
    unittest.main(verbosity=2)
