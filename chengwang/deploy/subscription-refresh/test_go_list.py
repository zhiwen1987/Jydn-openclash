"""Pure-CPU models for the official Go file-selection reader."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("p207a_go_list", HERE / "check_go_list.py")
assert SPEC is not None and SPEC.loader is not None
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class GoListModels(unittest.TestCase):
    def setUp(self) -> None:
        self.packages = ("example/a", "example/b")
        self.contract = {
            "goTest": {"packages": list(self.packages), "goos": "linux", "goarch": "amd64", "compiler": "gc", "goVersion": "go1.23.12", "cgoEnabled": False},
            "packages": {
                package: {"requiredRunTestFiles": [package + "/source_test.go"]}
                for package in self.packages
            },
        }

    def contract_raw(self) -> bytes:
        return json.dumps(self.contract, separators=(",", ":")).encode() + b"\n"

    def env_raw(self) -> bytes:
        return b'{"CGO_ENABLED":"0","GOARCH":"amd64","GOOS":"linux","GOVERSION":"go1.23.12"}\n'

    def list_raw(self) -> bytes:
        return b"".join(
            json.dumps({"ImportPath": package, "TestGoFiles": ["source_test.go"]}, separators=(",", ":")).encode() + b"\n"
            for package in self.packages
        )

    def verify(self, list_raw: bytes | None = None, env_raw: bytes | None = None):
        contract = self.contract_raw()
        import hashlib
        return L.verify(list_raw if list_raw is not None else self.list_raw(), env_raw if env_raw is not None else self.env_raw(), contract, hashlib.sha256(contract).hexdigest())

    def test_exact_official_selection_accepts_without_claiming_test_execution(self) -> None:
        result = self.verify()
        self.assertEqual(result["scope"], "OFFICIAL_GO_LIST_FILE_SELECTION_NOT_TEST_EXECUTION")
        raw = json.dumps(result, separators=(",", ":")).encode() + b"\n"
        import hashlib
        contract = self.contract_raw()
        self.assertEqual(L.verify_report(raw, contract, hashlib.sha256(contract).hexdigest()), result)

    def test_missing_selected_test_file_rejected(self) -> None:
        raw = self.list_raw().replace(b'"TestGoFiles":["source_test.go"]', b'"TestGoFiles":[]', 1)
        with self.assertRaises(L.ListError):
            self.verify(raw)

    def test_extra_selected_test_file_rejected(self) -> None:
        raw = self.list_raw().replace(b'["source_test.go"]', b'["source_test.go","extra_test.go"]', 1)
        with self.assertRaises(L.ListError):
            self.verify(raw)

    def test_wrong_or_duplicate_package_rejected(self) -> None:
        with self.assertRaises(L.ListError):
            self.verify(self.list_raw().replace(b'"example/b"', b'"example/a"', 1))

    def test_wrong_target_or_cgo_rejected(self) -> None:
        for raw in (
            b'{"CGO_ENABLED":"1","GOARCH":"amd64","GOOS":"linux","GOVERSION":"go1.23.12"}\n',
            b'{"CGO_ENABLED":"0","GOARCH":"arm64","GOOS":"linux","GOVERSION":"go1.23.12"}\n',
            b'{"CGO_ENABLED":"0","GOARCH":"amd64","GOOS":"linux","GOVERSION":"go1.23.11"}\n',
        ):
            with self.subTest(raw=raw), self.assertRaises(L.ListError):
                self.verify(env_raw=raw)

    def test_duplicate_json_key_rejected(self) -> None:
        with self.assertRaises(L.ListError):
            self.verify(self.list_raw().replace(b'{"ImportPath":', b'{"ImportPath":"other","ImportPath":', 1))

    def test_report_cannot_replace_selected_file(self) -> None:
        result = self.verify()
        result["packages"][0]["testFiles"] = ["example/a/replacement_test.go"]
        raw = json.dumps(result, separators=(",", ":")).encode() + b"\n"
        import hashlib
        contract = self.contract_raw()
        with self.assertRaises(L.ListError):
            L.verify_report(raw, contract, hashlib.sha256(contract).hexdigest())


if __name__ == "__main__":
    unittest.main()
