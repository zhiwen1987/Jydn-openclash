"""Pure-CPU models for the bounded P207A Go JSON event verifier."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("p207a_go_events", HERE / "check_go_events.py")
assert SPEC is not None and SPEC.loader is not None
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)


class GoEventModels(unittest.TestCase):
    def setUp(self) -> None:
        self.packages = ("example/a", "example/b")
        self.names = {"example/a": ["TestA"], "example/b": ["TestB"]}
        self.contract = {
            "schema": "chengwang.subscription-refresh-source/v3",
            "goTest": {"packages": list(self.packages), "goos": "linux", "goarch": "amd64", "compiler": "gc", "goVersion": "go1.23.12", "cgoEnabled": False, "buildTags": [], "runPattern": "^Test", "count": 1, "timeoutSeconds": 180},
            "packages": {
                package: {"requiredRunTops": [package + "::" + name for name in names]}
                for package, names in self.names.items()
            }
        }

    def raw_contract(self) -> bytes:
        return (json.dumps(self.contract, separators=(",", ":")) + "\n").encode()

    def events(self) -> bytes:
        values = []
        for package, names in self.names.items():
            values.append({"Action": "start", "Package": package})
            for name in names:
                values.extend((
                    {"Action": "run", "Package": package, "Test": name},
                    {"Action": "pass", "Package": package, "Test": name},
                ))
            values.append({"Action": "pass", "Package": package})
        return b"".join(json.dumps(value, separators=(",", ":")).encode() + b"\n" for value in values)

    def verify(self, events: bytes | None = None, go_exit: int = 0):
        contract = self.raw_contract()
        return G.verify(events if events is not None else self.events(), contract, G.sha(contract), go_exit)

    def test_exact_events_accept(self) -> None:
        result = self.verify()
        self.assertEqual(result["topLevelPassCount"], 2)
        self.assertEqual(result["skipCount"], 0)
        raw = json.dumps(result, separators=(",", ":")).encode() + b"\n"
        self.assertEqual(G.verify_report(raw, self.raw_contract(), G.sha(self.raw_contract())), result)

    def test_nonzero_go_exit_rejected(self) -> None:
        with self.assertRaises(G.EventError):
            self.verify(go_exit=1)

    def test_missing_top_rejected(self) -> None:
        with self.assertRaises(G.EventError):
            self.verify(self.events().replace(b'{"Action":"run","Package":"example/a","Test":"TestA"}\n', b""))

    def test_extra_top_rejected(self) -> None:
        extra = b'{"Action":"run","Package":"example/a","Test":"TestExtra"}\n{"Action":"pass","Package":"example/a","Test":"TestExtra"}\n'
        with self.assertRaises(G.EventError):
            self.verify(self.events() + extra)

    def test_skip_rejected(self) -> None:
        with self.assertRaises(G.EventError):
            self.verify(self.events().replace(b'"Action":"pass","Package":"example/a","Test":"TestA"', b'"Action":"skip","Package":"example/a","Test":"TestA"'))

    def test_failure_rejected_without_echoing_output(self) -> None:
        raw = self.events() + b'{"Action":"output","Package":"example/a","Output":"private"}\n'
        raw = raw.replace(b'{"Action":"pass","Package":"example/a"}\n', b'{"Action":"fail","Package":"example/a"}\n')
        with self.assertRaisesRegex(G.EventError, "package failure or skip") as found:
            self.verify(raw)
        self.assertNotIn("private", str(found.exception))

    def test_contract_pin_rejected(self) -> None:
        contract = self.raw_contract()
        with self.assertRaises(G.EventError):
            G.verify(self.events(), contract, "0" * 64, 0)

    def test_package_terminal_before_test_events_rejected(self) -> None:
        lines = self.events().splitlines(keepends=True)
        lines[1], lines[3] = lines[3], lines[1]
        with self.assertRaises(G.EventError):
            self.verify(b"".join(lines))

    def test_unexpected_package_rejected(self) -> None:
        with self.assertRaises(G.EventError):
            self.verify(self.events() + b'{"Action":"start","Package":"example/extra"}\n')

    def test_package_output_before_start_or_after_terminal_is_rejected(self) -> None:
        for raw in (
            b'{"Action":"output","Package":"example/a","Output":"fixed"}\n' + self.events(),
            self.events() + b'{"Action":"output","Package":"example/b","Output":"fixed"}\n',
        ):
            with self.subTest(raw=raw), self.assertRaises(G.EventError):
                self.verify(raw)

    def test_benchmark_and_orphan_subtest_events_are_rejected(self) -> None:
        benchmark = self.events().replace(
            b'{"Action":"run","Package":"example/a","Test":"TestA"}',
            b'{"Action":"bench","Package":"example/a","Test":"TestA"}',
            1,
        )
        orphan = self.events().replace(
            b'{"Action":"run","Package":"example/a","Test":"TestA"}',
            b'{"Action":"run","Package":"example/a","Test":"Unknown/child"}\n{"Action":"run","Package":"example/a","Test":"TestA"}',
            1,
        )
        for raw in (benchmark, orphan):
            with self.subTest(raw=raw), self.assertRaises(G.EventError):
                self.verify(raw)

    def test_duplicate_event_key_rejected(self) -> None:
        raw = self.events().replace(
            b'{"Action":"start","Package":"example/a"}',
            b'{"Action":"start","Action":"pass","Package":"example/a"}',
            1,
        )
        with self.assertRaises(G.EventError):
            self.verify(raw)

    def test_report_cannot_drop_or_replace_a_test(self) -> None:
        result = self.verify()
        result["packages"][0]["passed"] = ["TestReplacement"]
        raw = json.dumps(result, separators=(",", ":")).encode() + b"\n"
        with self.assertRaises(G.EventError):
            G.verify_report(raw, self.raw_contract(), G.sha(self.raw_contract()))


if __name__ == "__main__":
    unittest.main()
