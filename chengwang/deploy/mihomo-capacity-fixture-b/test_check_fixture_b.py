#!/usr/bin/env python3
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_fixture_b as gate


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CONTRACT_PATH = HERE / "fixture_b_contract.json"
CONTRACT_RAW = CONTRACT_PATH.read_bytes()
CONTRACT_SHA = hashlib.sha256(CONTRACT_RAW).hexdigest()
CONTRACT, _ = gate.load_contract(CONTRACT_PATH, CONTRACT_SHA)
COMMIT = "1" * 40
TREE = "2" * 40
RUN_ID = "41550851758"
RUN_ATTEMPT = 1


def setup_binding(lane="ordinary"):
    return gate.setup_binding(CONTRACT_SHA, COMMIT, TREE, RUN_ID, RUN_ATTEMPT, lane, CONTRACT)


def append_passed_phase(journal, binding, trusted_uid, phase, command_exit=0):
    gate.setup_append_event(journal, binding, trusted_uid, phase, "ENTERED", None)
    gate.setup_append_event(journal, binding, trusted_uid, phase, "PASS", command_exit)


def event(action, test=None, output=None):
    value = {"Action": action, "Package": CONTRACT["eventPackage"]}
    if test is not None:
        value["Test"] = test
    if output is not None:
        value["Output"] = output
    return value


def valid_events(include_output=True):
    top = CONTRACT["requiredTop"]
    rows = [event("start"), event("run", top)]
    if include_output:
        rows.append(event("output", top, "PRIVATE-CANARY\n"))
    for child in CONTRACT["fullSubtests"]:
        rows.extend((event("run", child), event("pass", child)))
    rows.extend((event("pass", top), event("pass")))
    return rows


def encode(rows, final_lf=True):
    raw = b"\n".join(gate.canonical(row).rstrip(b"\n") for row in rows)
    return raw + (b"\n" if final_lf else b"")


class ContractModels(unittest.TestCase):
    def test_contract_is_canonical_and_exact(self):
        self.assertEqual(CONTRACT_RAW, gate.canonical(CONTRACT))
        self.assertEqual(CONTRACT["lanes"], ["ordinary", "race"])
        self.assertEqual(len(CONTRACT["fullSubtests"]), 5)
        self.assertEqual(CONTRACT["sourceFiles"][0]["gitBlobSHA1"], "fb11ac12b551d8428d9a68f515a48d84031d270a")

    def test_contract_tamper_and_duplicate_key_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_bytes(CONTRACT_RAW.replace(b'"timeoutSeconds":180', b'"timeoutSeconds":181'))
            with self.assertRaises(gate.GateError):
                gate.load_contract(path, CONTRACT_SHA)
        with self.assertRaises(ValueError):
            gate.decode_json(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            gate.decode_json(b'{"a":NaN}')

    def test_command_boundary_is_fixed(self):
        for lane in CONTRACT["lanes"]:
            command = CONTRACT["commands"][lane]
            self.assertIn("-mod=vendor", command)
            self.assertIn("-count=1", command)
            self.assertIn("-p=1", command)
            self.assertIn("-shuffle=off", command)
            self.assertIn("-timeout=180s", command)
        self.assertNotIn("-race", CONTRACT["commands"]["ordinary"])
        self.assertIn("-race", CONTRACT["commands"]["race"])


class EventModels(unittest.TestCase):
    def verify(self, rows=None, raw=None, stderr=b"", exit_code=0, lane="ordinary"):
        if raw is None:
            raw = encode(valid_events() if rows is None else rows)
        return gate.verify_events(raw, stderr, exit_code, CONTRACT, CONTRACT_SHA, lane, COMMIT, TREE)

    def test_ordinary_and_race_accept_exact_state(self):
        for lane in ("ordinary", "race"):
            result = self.verify(lane=lane)
            self.assertTrue(result["accepted"])
            self.assertTrue(result["actualGoExecutionProven"])
            self.assertTrue(result["fixtureDataSynthetic"])
            self.assertFalse(result["businessRuntimeProven"])
            self.assertEqual(result["packagePassCount"], 1)
            self.assertEqual(result["topPassCount"], 1)
            self.assertEqual(result["subtestsPassCount"], 5)
            self.assertEqual(result["streamClosure"], "COMPLETE_EOF")

    def test_output_is_counted_but_never_copied(self):
        result = self.verify()
        public = gate.canonical(result)
        self.assertEqual(result["outputEventCount"], 1)
        self.assertNotIn(b"PRIVATE-CANARY", public)

    def test_process_stderr_and_eof_fail_closed(self):
        cases = (
            (encode(valid_events()), b"", 1, "PROCESS_NONZERO"),
            (encode(valid_events()), b"private", 0, "STDERR_NONEMPTY"),
            (encode(valid_events(), False), b"", 0, "STREAM_INCOMPLETE"),
            (b"", b"", 0, "STREAM_INCOMPLETE"),
        )
        for raw, stderr, code, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(gate.GateError) as caught:
                    self.verify(raw=raw, stderr=stderr, exit_code=code)
                self.assertEqual(caught.exception.code, expected)

    def test_test_state_mutations_reject(self):
        top = CONTRACT["requiredTop"]
        children = CONTRACT["fullSubtests"]
        base = valid_events(False)
        mutations = {}
        mutations["missing-child"] = [row for row in base if row.get("Test") != children[2]]
        mutations["extra-child"] = base[:-2] + [event("run", top + "/extra"), event("pass", top + "/extra")] + base[-2:]
        mutations["duplicate-run"] = base[:3] + [base[2]] + base[3:]
        skipped = [dict(row) for row in base]
        skipped[3]["Action"] = "skip"
        mutations["skip"] = skipped
        failed = [dict(row) for row in base]
        failed[3]["Action"] = "fail"
        mutations["fail"] = failed
        paused = [dict(row) for row in base]
        paused[2]["Action"] = "pause"
        mutations["pause"] = paused
        reordered = [dict(row) for row in base]
        reordered[2], reordered[4] = reordered[4], reordered[2]
        mutations["reordered"] = reordered
        early_top = [dict(row) for row in base]
        early_top.insert(2, event("pass", top))
        mutations["early-top-pass"] = early_top
        package_fail = [dict(row) for row in base]
        package_fail[-1]["Action"] = "fail"
        mutations["package-fail"] = package_fail
        wrong_package = [dict(row) for row in base]
        wrong_package[0]["Package"] = "other/package"
        mutations["wrong-package"] = wrong_package
        for name, rows in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(gate.GateError):
                    self.verify(rows=rows)

    def test_unknown_action_key_and_bad_scalars_reject(self):
        variants = []
        unknown = valid_events(False)
        unknown[1]["Action"] = "mystery"
        variants.append(unknown)
        extra = valid_events(False)
        extra[1]["Secret"] = "x"
        variants.append(extra)
        boolean_elapsed = valid_events(False)
        boolean_elapsed[1]["Elapsed"] = True
        variants.append(boolean_elapsed)
        output_after_close = valid_events(False) + [event("output", None, "late")]
        variants.append(output_after_close)
        for rows in variants:
            with self.assertRaises(gate.GateError):
                self.verify(rows=rows)

    def test_duplicate_key_invalid_utf8_and_oversize_line_reject(self):
        prefix = gate.canonical(event("start"))
        duplicate = prefix + b'{"Action":"run","Action":"pass","Package":"chengwang/internal/mihomodeploy"}\n'
        invalid = prefix + b'\xff\n'
        oversized = prefix + b'{' + b' ' * ((1 << 20) + 1) + b'}\n'
        for raw in (duplicate, invalid, oversized):
            with self.assertRaises((gate.GateError, UnicodeDecodeError, ValueError)):
                self.verify(raw=raw)


class EvidenceModels(unittest.TestCase):
    def test_toolchain_exact_and_mutations(self):
        expected = {"CGO_ENABLED": "1", "GOARCH": "amd64", "GOENV": "", "GOFLAGS": "-mod=vendor", "GOOS": "linux", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOVERSION": "go1.23.12", "GOWORK": "off"}
        accepted = gate.toolchain_report(gate.canonical(expected), CONTRACT_SHA)
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["goenv"], gate.GOENV_POLICY)
        raw_policy_literal = dict(expected)
        raw_policy_literal["GOENV"] = "off"
        with self.assertRaises(gate.GateError) as rejected:
            gate.toolchain_report(gate.canonical(raw_policy_literal), CONTRACT_SHA)
        self.assertEqual(rejected.exception.code, "TOOLCHAIN_MISMATCH")
        for key, value in (("GOVERSION", "go1.23.11"), ("GOPROXY", "https://proxy.golang.org"), ("GOWORK", "/tmp/go.work"), ("CGO_ENABLED", "0")):
            changed = dict(expected)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(gate.GateError):
                gate.toolchain_report(gate.canonical(changed), CONTRACT_SHA)

    def test_format_requires_zero_exit_empty_patch_and_stderr(self):
        self.assertTrue(gate.format_report(b"", b"", 0, CONTRACT_SHA)["accepted"])
        for patch, stderr, code in ((b"diff", b"", 0), (b"", b"err", 0), (b"", b"", 1)):
            self.assertFalse(gate.format_report(patch, stderr, code, CONTRACT_SHA)["accepted"])

    def test_creation_only_writer_and_empty_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty"
            gate.write_new(path, b"", 1)
            self.assertEqual(path.read_bytes(), b"")
            with self.assertRaises(FileExistsError):
                gate.write_new(path, b"x", 1)

    def test_result_reader_rejects_waivers(self):
        accepted = gate.verify_events(encode(valid_events()), b"", 0, CONTRACT, CONTRACT_SHA, "ordinary", COMMIT, TREE)
        gate.verify_result(gate.canonical(accepted), CONTRACT, CONTRACT_SHA, True)
        for field, value in (("skipCount", 1), ("expectedFailureCount", 1), ("wholeSuiteProven", True), ("processExit", 1)):
            changed = dict(accepted)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(gate.GateError):
                gate.verify_result(gate.canonical(changed), CONTRACT, CONTRACT_SHA, True)

    def test_failure_summary_is_closed_and_nonaccepting(self):
        value = gate.failure_summary(CONTRACT, CONTRACT_SHA, "race", COMMIT, TREE, "INTERNAL_UNKNOWN")
        self.assertFalse(value["accepted"])
        self.assertFalse(value["actualGoExecutionProven"])
        self.assertTrue(value["fixtureDataSynthetic"])
        self.assertFalse(value["businessRuntimeProven"])
        self.assertFalse(value["wholeSuiteProven"])
        self.assertFalse(value["productionProven"])
        gate.verify_result(gate.canonical(value), CONTRACT, CONTRACT_SHA, False)


class SetupDiagnosticModels(unittest.TestCase):
    def test_contract_has_exact_fixed_setup_enums(self):
        self.assertEqual(CONTRACT["setupPhases"], list(gate.SETUP_PHASES))
        self.assertEqual(CONTRACT["setupStatuses"], ["ENTERED", "PASS", "FAIL"])
        self.assertEqual(len(gate.SETUP_PHASES), len(set(gate.SETUP_PHASES)))

    def test_successful_journal_is_typed_but_never_oracle_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / ".setup-journal"
            trusted_uid = gate.path_uid(Path(directory))
            binding = setup_binding()
            gate.setup_init(journal, binding, trusted_uid)
            for phase in gate.SETUP_PHASES:
                append_passed_phase(journal, binding, trusted_uid, phase)
            value = gate.setup_finalize(journal, binding, trusted_uid, 0)
            raw = gate.canonical(value)
            self.assertEqual(value["phase"], "ORACLE_VALIDATE")
            self.assertEqual(value["status"], "PASS")
            self.assertTrue(value["oracleValidationPassed"])
            self.assertFalse(value["oracleAcceptanceProven"])
            self.assertTrue(value["diagnosticOnly"])
            gate.verify_setup_status(raw, binding, True)

    def test_host_preentry_and_every_namespace_phase_failure_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted_uid = gate.path_uid(root)
            binding = setup_binding()
            host_journal = root / "host"
            gate.setup_init(host_journal, binding, trusted_uid)
            host = gate.setup_finalize(host_journal, binding, trusted_uid, 124)
            self.assertEqual((host["phase"], host["status"], host["hostExitStatus"]), ("HOST_EXECUTION", "FAIL", 124))
            self.assertFalse(host["namespaceEntered"])
            for index, phase in enumerate(gate.SETUP_PHASES):
                with self.subTest(phase=phase):
                    journal = root / f"phase-{index:02d}"
                    gate.setup_init(journal, binding, trusted_uid)
                    for prior in gate.SETUP_PHASES[:index]:
                        append_passed_phase(journal, binding, trusted_uid, prior)
                    gate.setup_append_event(journal, binding, trusted_uid, phase, "ENTERED", None)
                    gate.setup_append_event(journal, binding, trusted_uid, phase, "FAIL", 37)
                    value = gate.setup_finalize(journal, binding, trusted_uid, 37)
                    self.assertEqual((value["phase"], value["status"], value["phaseExitStatus"], value["hostExitStatus"]), (phase, "FAIL", 37, 37))
                    self.assertTrue(value["namespaceEntered"])
                    self.assertNotIn("PRIVATE-CANARY", gate.canonical(value).decode("ascii"))

    def test_foreign_owner_mismatch_unknown_duplicate_and_exit_mutations_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / ".setup-journal"
            trusted_uid = gate.path_uid(Path(directory))
            binding = setup_binding()
            gate.setup_init(journal, binding, trusted_uid)
            with mock.patch.object(gate, "path_uid", return_value=gate.PRIVATE_UID), self.assertRaises(gate.GateError):
                gate.read_setup_journal(journal, binding, trusted_uid)
            changed = dict(binding)
            changed["sourceTree"] = "3" * 40
            with self.assertRaises(gate.GateError):
                gate.read_setup_journal(journal, changed, trusted_uid)
            with self.assertRaises(gate.GateError):
                gate.setup_append_event(journal, binding, trusted_uid, "UNKNOWN", "ENTERED", None)
            with self.assertRaises(gate.GateError):
                gate.setup_append_event(journal, binding, trusted_uid, "NAMESPACE_ENTRY", "PASS", 0)
            gate.setup_append_event(journal, binding, trusted_uid, "NAMESPACE_ENTRY", "ENTERED", None)
            with self.assertRaises(FileExistsError):
                gate.write_new(journal / "event-0000.json", b"{}\n", 16 << 10)
            with self.assertRaises(gate.GateError):
                gate.setup_append_event(journal, binding, trusted_uid, "NAMESPACE_ENTRY", "FAIL", 0)

    def test_setup_status_rejects_unknown_fields_and_binding_or_boolean_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / ".setup-journal"
            trusted_uid = gate.path_uid(Path(directory))
            binding = setup_binding("race")
            gate.setup_init(journal, binding, trusted_uid)
            gate.setup_append_event(journal, binding, trusted_uid, "NAMESPACE_ENTRY", "ENTERED", None)
            gate.setup_append_event(journal, binding, trusted_uid, "NAMESPACE_ENTRY", "FAIL", 19)
            value = gate.setup_finalize(journal, binding, trusted_uid, 19)
            variants = []
            extra = dict(value); extra["privateError"] = "PRIVATE-CANARY"; variants.append(extra)
            wrong_tree = dict(value); wrong_tree["sourceTree"] = "3" * 40; variants.append(wrong_tree)
            raw_bool = dict(value); raw_bool["goEnvInvoked"] = "unknown"; variants.append(raw_bool)
            forged = dict(value); forged["oracleAcceptanceProven"] = True; variants.append(forged)
            for changed in variants:
                with self.subTest(keys=tuple(changed)), self.assertRaises(gate.GateError):
                    gate.verify_setup_status(gate.canonical(changed), binding, False)

    def test_bash_exit_stub_preserves_each_original_failure_code(self):
        runner = (HERE / "run_fixture_b.sh").read_text("utf-8")
        self.assertIn('local status=$?', runner)
        self.assertIn('setup_event "$active_phase" FAIL "$status" || true', runner)
        bash = shutil.which("bash")
        if bash is None:
            for phase in gate.SETUP_PHASES:
                self.assertIn(f"phase_enter {phase}", runner)
            return
        script = r'''set -euo pipefail
active_phase="$1"
output="$2"
setup_event() { printf '%s|%s|%s\n' "$1" "$2" "$3" >"$output"; }
on_exit() { local status=$?; trap - EXIT; if test "$status" -ne 0 && test -n "$active_phase"; then setup_event "$active_phase" FAIL "$status" || true; fi; exit "$status"; }
trap on_exit EXIT
exit 37
'''
        for phase in gate.SETUP_PHASES:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "event"
                result = subprocess.run([bash, "-c", script, "setup-stub", phase, str(output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(result.returncode, 37)
                self.assertEqual(output.read_text("utf-8"), f"{phase}|FAIL|37\n")
                self.assertNotIn(b"PRIVATE-CANARY", result.stdout + result.stderr + output.read_bytes())


class WorkflowModels(unittest.TestCase):
    def test_actual_workflow_and_four_source_pins(self):
        pins = {
            "CONTRACT_SHA256": hashlib.sha256((HERE / "fixture_b_contract.json").read_bytes()).hexdigest(),
            "CHECKER_SHA256": hashlib.sha256((HERE / "check_fixture_b.py").read_bytes()).hexdigest(),
            "MODEL_SHA256": hashlib.sha256((HERE / "test_check_fixture_b.py").read_bytes()).hexdigest(),
            "RUNNER_SHA256": hashlib.sha256((HERE / "run_fixture_b.sh").read_bytes()).hexdigest(),
        }
        value = gate.validate_workflow(ROOT, pins)
        self.assertTrue(value["accepted"])

    def test_workflow_has_exact_public_allowlist_and_no_raw_upload(self):
        text = (ROOT / gate.WORKFLOW_PATH).read_text("utf-8")
        names = ("source-before.json", "source-after.json", "toolchain.json", "format-status.json", "gofmt.patch", "summary.json", "setup-status.json")
        for name in names:
            self.assertIn(name, text)
        upload = text.split("name: capacity-fixture-b-${{ matrix.lane }}", 1)[1].split("retention-days:", 1)[0]
        self.assertEqual(sum(upload.count(name) for name in names), 7)
        for forbidden in ("events.jsonl", "go.stderr", "gofmt.stderr", "*.json", "*.log"):
            self.assertNotIn(forbidden, text)

    def test_runner_has_fixed_isolation_and_commands(self):
        text = (HERE / "run_fixture_b.sh").read_text("utf-8")
        workflow = (ROOT / gate.WORKFLOW_PATH).read_text("utf-8")
        self.assertIn("sudo unshare --net --mount --pid", workflow)
        for required in ("GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOENV=off", "-p=1", "-count=1", "-shuffle=off", "-timeout=180s", "setpriv", "--no-new-privs"):
            self.assertIn(required, text)
        positions = [text.index(f"phase_enter {phase}") for phase in gate.SETUP_PHASES]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("setup-init", workflow)
        self.assertIn("setup-finalize", workflow)
        self.assertIn("setup-check", workflow)
        self.assertNotIn("eval ", text)

    def test_workflow_mutations_change_normalized_fingerprint(self):
        raw = (ROOT / gate.WORKFLOW_PATH).read_bytes()
        normalized = gate.normalized_workflow(raw)
        self.assertEqual(hashlib.sha256(normalized).hexdigest(), gate.WORKFLOW_TEMPLATE_SHA256)
        for old, new in ((b" 600s", b" 601s"), (b"working-directory: chengwang", b"working-directory: ."), (b"cancel-in-progress: false", b"cancel-in-progress: true")):
            self.assertNotEqual(hashlib.sha256(normalized.replace(old, new, 1)).hexdigest(), gate.WORKFLOW_TEMPLATE_SHA256)


if __name__ == "__main__":
    unittest.main()
