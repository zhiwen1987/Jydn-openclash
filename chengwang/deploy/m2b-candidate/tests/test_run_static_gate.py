from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import run_static_gate


PACKAGE = "chengwang/internal/restorecontracts"
SCHEMA_VALIDATOR_TEST = run_static_gate.SCHEMA_VALIDATOR_TEST
EXPECTED_NAMES = {"TestContract", "TestContract/subcase", SCHEMA_VALIDATOR_TEST}


def _event(action: str, test: str | None = None) -> dict[str, str]:
    value = {"Action": action, "Package": PACKAGE}
    if test is not None:
        value["Test"] = test
    return value


def _transcript(names: set[str], *, fuzz: bool = False, terminal: bool = True) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for name in sorted(names):
        events.extend((_event("run", name), _event("pass", name)))
    if fuzz:
        events.extend(
            (
                _event("run", "FuzzContract"),
                _event("pass", "FuzzContract"),
                _event("run", "FuzzContract/seed#0"),
                _event("pass", "FuzzContract/seed#0"),
            )
        )
    if terminal:
        events.append(_event("pass"))
    return events


class GoJSONFingerprintTests(unittest.TestCase):
    def _validate(
        self,
        events: list[dict[str, str]],
        *,
        fingerprint_names: set[str] | None = None,
    ) -> int:
        if fingerprint_names is None:
            fingerprint_names = EXPECTED_NAMES
        expected = {
            PACKAGE: {
                "count": len(fingerprint_names),
                "sha256": run_static_gate._test_name_fingerprint(fingerprint_names),
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            transcript = pathlib.Path(directory) / "go-test.json"
            transcript.write_text(
                "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events),
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                mock.patch.object(run_static_gate, "REQUIRED_GO_TEST_RUNS", {}),
                mock.patch.object(run_static_gate, "REQUIRED_GO_TEST_NAMES", {PACKAGE: frozenset({"TestContract"})}),
                mock.patch.object(run_static_gate, "REQUIRED_GO_TEST_FINGERPRINTS", expected),
                mock.patch.object(run_static_gate, "ALLOWED_GO_PACKAGE_SKIPS", frozenset()),
                contextlib.redirect_stdout(output),
            ):
                result = run_static_gate.validate_go_json([transcript])
            self.last_output = output.getvalue()
            return result

    def test_exact_passed_name_set_is_accepted(self) -> None:
        self.assertEqual(self._validate(_transcript(EXPECTED_NAMES)), 0)
        self.assertIn(run_static_gate.SCHEMA_METASCHEMA_PASS, self.last_output)

    def test_deleted_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fingerprint mismatch"):
            self._validate(_transcript({"TestContract"}))

    def test_added_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fingerprint mismatch"):
            self._validate(_transcript(EXPECTED_NAMES | {"TestUnexpected"}))

    def test_renamed_name_is_rejected_at_same_count(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fingerprint mismatch"):
            self._validate(_transcript({"TestContract", "TestContract/renamed"}))

    def test_fuzz_names_do_not_change_test_fingerprint(self) -> None:
        self.assertEqual(self._validate(_transcript(EXPECTED_NAMES, fuzz=True)), 0)

    def test_missing_terminal_package_pass_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no terminal package pass"):
            self._validate(_transcript(EXPECTED_NAMES, terminal=False))

    def test_missing_schema_validator_test_is_rejected(self) -> None:
        names = EXPECTED_NAMES - {SCHEMA_VALIDATOR_TEST}
        with self.assertRaisesRegex(RuntimeError, "Draft 2020-12 validator test did not pass"):
            self._validate(_transcript(names), fingerprint_names=names)

    def test_failure_event_is_rejected_before_signing(self) -> None:
        events = _transcript(EXPECTED_NAMES)
        events.insert(0, _event("fail", "TestFailed"))
        with self.assertRaisesRegex(RuntimeError, "failure event is forbidden"):
            self._validate(events)

    def test_pass_without_preceding_run_is_rejected(self) -> None:
        events = _transcript(EXPECTED_NAMES)
        events.insert(0, _event("pass", "TestInjected"))
        with self.assertRaisesRegex(RuntimeError, "pass without a preceding run"):
            self._validate(events)


class RestoreCurrentSourceGateTests(unittest.TestCase):
    def _package(self, source: str) -> pathlib.Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        package = pathlib.Path(temporary.name) / "restorecurrent"
        package.mkdir()
        (package / "current.go").write_text(source, encoding="utf-8")
        return package

    def test_allowlisted_side_effect_free_import_is_accepted(self) -> None:
        package = self._package('package restorecurrent\nimport "errors"\nvar _ = errors.New\n')
        run_static_gate._validate_restorecurrent_package(package)

    def test_subprocess_import_is_rejected(self) -> None:
        package = self._package('package restorecurrent\nimport runner "os/exec"\nvar _ = runner.Command\n')
        with self.assertRaisesRegex(RuntimeError, "forbidden packages"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_authoritative_or_state_collection_api_is_rejected(self) -> None:
        for token in ("restorecontracts.StateOnlyCurrent", "AcquireLockedStateSnapshot"):
            with self.subTest(token=token):
                package = self._package(f"package restorecurrent\n// test\nvar _ = {token}\n")
                with self.assertRaisesRegex(RuntimeError, "forbidden"):
                    run_static_gate._validate_restorecurrent_package(package)


if __name__ == "__main__":
    unittest.main()
