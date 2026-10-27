"""Pure-CPU privacy and shape models for the non-accepting Go failure projection."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("p207a_go_failure", HERE / "check_go_failure.py")
assert SPEC is not None and SPEC.loader is not None
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class GoFailureProjectionModels(unittest.TestCase):
    def setUp(self) -> None:
        self.packages = [f"example/p{index}" for index in range(7)]
        remaining = 481
        self.names = {}
        for index, package in enumerate(self.packages):
            count = remaining if index == len(self.packages) - 1 else 68
            remaining -= count
            self.names[package] = [f"TestP{index}_{item:03d}" for item in range(count)]
        self.contract = {
            "schema": "chengwang.subscription-refresh-source/v3",
            "goTest": {"packages": self.packages},
            "packages": {
                package: {"requiredRunTops": [package + "::" + name for name in names]}
                for package, names in self.names.items()
            },
        }

    def raw_contract(self) -> bytes:
        return (json.dumps(self.contract, separators=(",", ":")) + "\n").encode()

    def encode(self, values: list[dict]) -> bytes:
        return b"".join(json.dumps(value, separators=(",", ":")).encode() + b"\n" for value in values)

    def complete_events(self) -> list[dict]:
        values = []
        for package in self.packages:
            values.append({"Action": "start", "Package": package})
            for name in self.names[package]:
                values.extend((
                    {"Action": "run", "Package": package, "Test": name},
                    {"Action": "pass", "Package": package, "Test": name},
                ))
            values.append({"Action": "pass", "Package": package})
        return values

    def project(self, events: bytes, go_exit: int = 1, event_exit: int = 1):
        contract = self.raw_contract()
        return F.project(events, contract, F.sha(contract), go_exit, event_exit)

    def roundtrip(self, result: dict, events: bytes, go_exit: int = 1, event_exit: int = 1) -> dict:
        raw = json.dumps(result, separators=(",", ":")).encode() + b"\n"
        contract = self.raw_contract()
        return F.verify_report(raw, events, contract, F.sha(contract), go_exit, event_exit)

    def test_declared_top_failure_projects_only_source_names_and_counts(self) -> None:
        package = self.packages[0]
        name = self.names[package][0]
        secret = "DO_NOT_EXPORT_PRIVATE_OUTPUT"
        events = self.encode([
            {"Action": "start", "Package": package},
            {"Action": "run", "Package": package, "Test": name},
            {"Action": "output", "Package": package, "Test": name, "Output": secret},
            {"Action": "fail", "Package": package, "Test": name},
            {"Action": "fail", "Package": package},
        ])
        result = self.project(events)
        self.assertEqual(result["failureClass"], "PACKAGE_TERMINAL_NONPASS")
        self.assertEqual(result["failedTops"], [package + "::" + name])
        self.assertEqual(result["failCount"], 1)
        self.assertEqual(result["notStartedCount"], 480)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(self.roundtrip(result, events), result)

    def test_complete_success_events_with_failed_gate_are_never_accepted(self) -> None:
        result = self.project(self.encode(self.complete_events()), go_exit=1, event_exit=0)
        self.assertEqual(result["stage"], "COMPLETE_EVENTS")
        self.assertEqual(result["failureClass"], "NONZERO_EXIT_AFTER_COMPLETE_EVENTS")
        self.assertEqual(result["passCount"], 481)
        self.assertIs(result["accepted"], False)
        self.assertEqual(result["reportOutcome"], "FAILURE_DIAGNOSTIC_ONLY")

    def test_event_checker_failure_after_complete_events_is_distinct(self) -> None:
        result = self.project(self.encode(self.complete_events()), go_exit=0, event_exit=1)
        self.assertEqual(result["failureClass"], "EVENT_CHECKER_REJECTED_AFTER_COMPLETE_EVENTS")
        self.assertEqual(result["passCount"], 481)
        self.assertIs(result["accepted"], False)

    def test_partial_stream_reports_running_and_not_started_declared_tops(self) -> None:
        package = self.packages[0]
        first, second = self.names[package][:2]
        result = self.project(self.encode([
            {"Action": "start", "Package": package},
            {"Action": "run", "Package": package, "Test": first},
            {"Action": "pass", "Package": package, "Test": first},
            {"Action": "run", "Package": package, "Test": second},
        ]))
        self.assertEqual(result["failureClass"], "INCOMPLETE_EVENT_STREAM")
        self.assertEqual(result["passCount"], 1)
        self.assertEqual(result["runningTops"], [package + "::" + second])
        self.assertEqual(result["notStartedCount"], 479)

    def test_unknown_package_top_and_event_key_are_fixed_rejections_without_echo(self) -> None:
        secret = "secret.example.invalid/private/path"
        variants = (
            [{"Action": "start", "Package": secret}],
            [{"Action": "start", "Package": self.packages[0]}, {"Action": "run", "Package": self.packages[0], "Test": "Test" + secret}],
            [{"Action": "start", "Package": self.packages[0], "PrivateKey": secret}],
        )
        for values in variants:
            with self.subTest(values=values):
                result = self.project(self.encode(values))
                encoded = json.dumps(result)
                self.assertEqual(result["failureClass"], "EVENT_STREAM_REJECTED")
                self.assertEqual(result["stage"], "INVALID_STREAM")
                self.assertNotIn(secret, encoded)

    def test_malformed_duplicate_key_and_oversized_line_are_fixed_rejections(self) -> None:
        package = self.packages[0]
        variants = (
            b"{not-json}\n",
            ('{"Action":"start","Action":"pass","Package":"' + package + '"}\n').encode(),
            b"x" * (F.MAX_LINE_BYTES + 1) + b"\n",
        )
        for raw in variants:
            with self.subTest(size=len(raw)):
                result = self.project(raw)
                self.assertEqual(result["failureClass"], "EVENT_STREAM_REJECTED")
                self.assertEqual(result["stage"], "INVALID_STREAM")

    def test_timeout_and_panic_are_marker_observations_not_dynamic_output(self) -> None:
        package = self.packages[0]
        name = self.names[package][0]
        secret = "PRIVATE_STACK_AND_ARGUMENTS"
        events = self.encode([
            {"Action": "start", "Package": package},
            {"Action": "run", "Package": package, "Test": name},
            {"Action": "output", "Package": package, "Test": name, "Output": "panic: test timed out after 3m0s\n" + secret},
        ])
        result = self.project(events)
        self.assertEqual(result["failureClass"], "TIMEOUT_AND_PANIC_TEXT_MARKERS_OBSERVED")
        self.assertEqual(result["markerObservation"], "TIMEOUT_AND_PANIC_TEXT")
        self.assertNotIn(secret, json.dumps(result))

    def test_compile_like_package_failure_is_only_an_observed_package_terminal(self) -> None:
        package = self.packages[0]
        secret = "private/compiler/location.go:999: secret"
        result = self.project(self.encode([
            {"Action": "start", "Package": package},
            {"Action": "output", "Package": package, "Output": secret},
            {"Action": "fail", "Package": package},
        ]))
        self.assertEqual(result["stage"], "PACKAGE_TERMINAL")
        self.assertEqual(result["failureClass"], "PACKAGE_TERMINAL_NONPASS")
        self.assertEqual(result["notStartedCount"], 481)
        self.assertNotIn(secret, json.dumps(result))

    def test_skip_is_a_nonpass_bucket_without_dynamic_reason(self) -> None:
        package = self.packages[0]
        name = self.names[package][0]
        secret = "PRIVATE_SKIP_REASON"
        result = self.project(self.encode([
            {"Action": "start", "Package": package},
            {"Action": "run", "Package": package, "Test": name},
            {"Action": "output", "Package": package, "Test": name, "Output": secret},
            {"Action": "skip", "Package": package, "Test": name},
        ]))
        self.assertEqual(result["failedTops"], [package + "::" + name])
        self.assertNotIn(secret, json.dumps(result))

    def test_unbegun_subtest_is_rejected_without_exporting_dynamic_subtest(self) -> None:
        package = self.packages[0]
        secret = "private-subtest-value"
        result = self.project(self.encode([
            {"Action": "start", "Package": package},
            {"Action": "run", "Package": package, "Test": self.names[package][0] + "/" + secret},
        ]))
        self.assertEqual(result["failureClass"], "EVENT_STREAM_REJECTED")
        self.assertNotIn(secret, json.dumps(result))

    def test_report_cannot_claim_acceptance_or_fabricate_state(self) -> None:
        events = b""
        result = self.project(events)
        mutations = []
        accepted = json.loads(json.dumps(result)); accepted["accepted"] = True; mutations.append(accepted)
        count = json.loads(json.dumps(result)); count["notStartedCount"] -= 1; mutations.append(count)
        foreign = json.loads(json.dumps(result)); foreign["notStartedTops"][0] = "foreign/package::TestForeign"; mutations.append(foreign)
        enum = json.loads(json.dumps(result)); enum["failureClass"] = "PRIVATE_ERROR"; mutations.append(enum)
        package_swap = json.loads(json.dumps(result)); package_swap["packages"][0]["notStartedCount"] -= 1; package_swap["packages"][0]["passCount"] += 1; mutations.append(package_swap)
        class_swap = json.loads(json.dumps(result)); class_swap["failureClass"] = "TOP_TERMINAL_NONPASS"; mutations.append(class_swap)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(F.FailureDiagnosticError):
                self.roundtrip(value, events)

    def test_reader_reprojects_partial_events_and_rejects_stage_class_marker_count_and_name_tampering(self) -> None:
        package = self.packages[0]
        first, second = self.names[package][:2]
        events = self.encode([
            {"Action": "start", "Package": package},
            {"Action": "run", "Package": package, "Test": first},
            {"Action": "pass", "Package": package, "Test": first},
            {"Action": "run", "Package": package, "Test": second},
        ])
        result = self.project(events)
        mutations = []
        stage = json.loads(json.dumps(result)); stage["stage"] = "PACKAGE_TERMINAL"; stage["failureClass"] = "PACKAGE_TERMINAL_NONPASS"; mutations.append(stage)
        failure_class = json.loads(json.dumps(result)); failure_class["failureClass"] = "TOP_TERMINAL_NONPASS"; mutations.append(failure_class)
        unknown_class = json.loads(json.dumps(result)); unknown_class["failureClass"] = "UNKNOWN_NONZERO_EXIT"; mutations.append(unknown_class)
        marker = json.loads(json.dumps(result)); marker["markerObservation"] = "PANIC_TEXT"; marker["failureClass"] = "PANIC_TEXT_MARKER_OBSERVED"; mutations.append(marker)
        count = json.loads(json.dumps(result)); count["passCount"] -= 1; count["notStartedCount"] += 1; count["packages"][0]["passCount"] -= 1; count["packages"][0]["notStartedCount"] += 1; count["notStartedTops"].append(package + "::" + first); count["notStartedTops"].sort(); mutations.append(count)
        name = json.loads(json.dumps(result)); name["runningTops"] = [package + "::" + self.names[package][2]]; mutations.append(name)
        for value in mutations:
            with self.subTest(stage=value["stage"], failure_class=value["failureClass"]), self.assertRaises(F.FailureDiagnosticError):
                self.roundtrip(value, events)

    def test_boolean_float_and_zero_zero_exits_are_rejected(self) -> None:
        contract = self.raw_contract()
        for go_exit, event_exit in ((True, 1), (1.0, 1), (1, False), (1, 1.0), (0, 0)):
            with self.subTest(go_exit=go_exit, event_exit=event_exit), self.assertRaises(F.FailureDiagnosticError):
                F.project(b"", contract, F.sha(contract), go_exit, event_exit)


if __name__ == "__main__":
    unittest.main()
