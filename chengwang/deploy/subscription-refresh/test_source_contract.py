"""Pure-CPU negative models for the P207A v3 source closure."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("p207a_source_contract", HERE / "check_source_contract.py")
assert SPEC is not None and SPEC.loader is not None
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def command(cwd: Path, *args: str) -> None:
    subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)


class ClosedSourceContractModels(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        command(self.root, "git", "init", "-q")
        command(self.root, "git", "config", "user.name", "source-model")
        command(self.root, "git", "config", "user.email", "source-model@example.invalid")
        self.gate = self.root / "chengwang/deploy/subscription-refresh"
        self.gate.mkdir(parents=True)
        (self.root / "chengwang/vendor").mkdir(parents=True)
        (self.root / "chengwang/go.mod").write_bytes(b"module example.invalid/source-model\n\ngo 1.23.0\n")
        (self.root / "chengwang/go.sum").write_bytes(b"")
        (self.root / "chengwang/vendor/modules.txt").write_bytes(b"# source model\n")
        self.checker = self.gate / "check_source_contract.py"
        self.model = self.gate / "test_source_contract.py"
        self.event_checker = self.gate / "check_go_events.py"
        self.event_model = self.gate / "test_go_events.py"
        self.failure_checker = self.gate / "check_go_failure.py"
        self.failure_model = self.gate / "test_go_failure.py"
        self.go_list_checker = self.gate / "check_go_list.py"
        self.go_list_model = self.gate / "test_go_list.py"
        self.checker.write_bytes((HERE / "check_source_contract.py").read_bytes())
        self.model.write_bytes(b"# independently workflow-pinned model\n")
        self.event_checker.write_bytes(b"# independently workflow-pinned event checker\n")
        self.event_model.write_bytes(b"# independently workflow-pinned event model\n")
        self.failure_checker.write_bytes(b"# independently workflow-pinned failure checker\n")
        self.failure_model.write_bytes(b"# independently workflow-pinned failure model\n")
        self.go_list_checker.write_bytes(b"# independently workflow-pinned go-list checker\n")
        self.go_list_model.write_bytes(b"# independently workflow-pinned go-list model\n")
        self.foundation = self.root / "chengwang/deploy/foundation.py"
        self.foundation.parent.mkdir(parents=True, exist_ok=True)
        self.workflow = self.root / ".github/workflows/chengwang-subscription-refresh.yml"
        self.workflow.parent.mkdir(parents=True, exist_ok=True)
        self.fixture = self.root / "chengwang/internal/api/fixture.txt"
        for index, package in enumerate(C.PACKAGE_NAMES):
            directory = self.root.joinpath(*package.split("/"))
            directory.mkdir(parents=True, exist_ok=True)
            extra = '//go:embed fixture.txt\nvar fixture string\n' if index == 0 else ''
            imports = 'import _ "embed"\n\n' if index == 0 else ''
            (directory / "source.go").write_text(f"package p{index}\n\n{imports}{extra}", encoding="utf-8", newline="\n")
            (directory / "source_test.go").write_text(
                f'package p{index}\n\nimport "testing"\n\nfunc TestP{index}(t *testing.T) {{}}\n',
                encoding="utf-8",
                newline="\n",
            )
        self.fixture.write_bytes(b"fixture\n")
        self.foundation.write_text(
            "FILES=('chengwang/internal/api/source_test.go',)\n"
            "def required_names(sources): return {'chengwang/internal/api':['TestP0']}\n",
            encoding="utf-8",
            newline="\n",
        )
        self.workflow.write_text("placeholder\n", encoding="utf-8", newline="\n")
        command(self.root, "git", "add", ".")
        command(self.root, "git", "commit", "-qm", "model")
        self.contract_path = self.gate / "source_contract.json"
        self.write_contract()
        command(self.root, "git", "add", ".")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_contract(self) -> None:
        tracked = C.git_tracked(self.root)
        module_paths = C.module_paths(tracked)
        packages = {}
        all_names = []
        for package in C.PACKAGE_NAMES:
            files, names, _ = C.package_observation(self.root, tracked, package)
            packages[package] = {
                "testFiles": files,
                "requiredRunTestFiles": files,
                "excludedRunTestFiles": [],
                "sourceTestTopCount": len(names),
                "sourceTestTopsSHA256": C.names_digest(names),
                "sourceTestTops": names,
                "requiredRunTopCount": len(names),
                "requiredRunTopsSHA256": C.names_digest(names),
                "requiredRunTops": names,
                "excludedRunTops": [],
            }
            all_names.extend(names)
        all_names.sort()
        changed = {"chengwang/internal/api/source.go": C.sha((self.root / "chengwang/internal/api/source.go").read_bytes())}
        relative_packages = ["./" + package.removeprefix("chengwang/") for package in C.PACKAGE_NAMES]
        list_lines = " ".join(relative_packages)
        self.workflow.write_text(
            "env:\n  GOOS: linux\n  GOARCH: amd64\n  CGO_ENABLED: '0'\n"
            "          assert len(names)==len(set(names))==0\n"
            "          assert hashlib.sha256('\\n'.join(names).encode()).hexdigest()=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'\n"
            "          print('P207A_SOURCE_MODELS=PASS count=0 go_execution_proven=false')\n"
            "run: |\n          fmt=(\n"
            + "".join("            " + path + "\n" for path in changed)
            + "          )\n          go list -json " + list_lines + " > go-list.private.json\n"
            + "          set +e\n          gofmt -d \"${fmt[@]}\" > \"$out/gofmt.patch\" 2> \"$out/gofmt.stderr\"\n"
            + "          formatCode=$?\n          cd chengwang\n"
            + "          go test -json -count=1 -timeout=180s -run '^Test' " + list_lines + " > \"$out/go-events.private.jsonl\" 2> \"$out/go.stderr\"\n"
            + "          code=$?\n          cd \"$GITHUB_WORKSPACE\"\n          set -e\n"
            + "          printf '%s\\n' \"$formatCode\" > \"$out/format-exit.txt\"\n"
            + "          printf '%s\\n' \"$code\" > \"$out/go-exit.txt\"\n"
            + "          verify_source > \"$out/source-after.json\"\n"
            + "          cmp \"$out/source-before.json\" \"$out/source-after.json\"\n"
            + "          set +e\n          python3 -I -B chengwang/deploy/subscription-refresh/check_go_events.py --events \"$out/go-events.private.jsonl\"\n"
            + "          eventCode=$?\n          set -e\n"
            + "          printf '%s\\n' \"$eventCode\" > \"$out/event-check-exit.txt\"\n"
            + "          failureCode=0\n"
            + "          if test \"$code\" != 0 || test \"$eventCode\" != 0; then\n"
            + "            set +e\n"
            + "            python3 -I -B chengwang/deploy/subscription-refresh/check_go_failure.py --events \"$out/go-events.private.jsonl\" --stderr \"$out/go.stderr\" --repo \"$GITHUB_WORKSPACE\" --go-exit \"$code\" --event-check-exit \"$eventCode\" --output \"$out/go-failure-report.json\"\n"
            + "            failureCode=$?\n"
            + "            if test \"$failureCode\" = 0; then\n"
            + "              python3 -I -B chengwang/deploy/subscription-refresh/check_go_failure.py --report \"$out/go-failure-report.json\" --events \"$out/go-events.private.jsonl\" --stderr \"$out/go.stderr\" --repo \"$GITHUB_WORKSPACE\" --go-exit \"$code\" --event-check-exit \"$eventCode\" --contract \"$CONTRACT\"\n"
            + "              failureCode=$?\n"
            + "            fi\n"
            + "            set -e\n"
            + "          fi\n"
            + "          printf '%s\\n' \"$failureCode\" > \"$out/failure-check-exit.txt\"\n"
            + "          # BEGIN P207A_ACCEPTED_GATE\n"
            + "          test \"$formatCode\" = 0\n"
            + "          test -f \"$out/gofmt.patch\"\n"
            + "          test ! -s \"$out/gofmt.patch\"\n"
            + "          test -f \"$out/gofmt.stderr\"\n"
            + "          test ! -s \"$out/gofmt.stderr\"\n"
            + "          test \"$code\" = 0\n"
            + "          test \"$eventCode\" = 0\n"
            + "          test \"$failureCode\" = 0\n"
            + "          test -f \"$out/go.stderr\"\n"
            + "          test ! -s \"$out/go.stderr\"\n"
            + "          test -s \"$out/source-before.json\"\n"
            + "          test -s \"$out/source-after.json\"\n"
            + "          test -s \"$out/go-list-report.json\"\n"
            + "          test -s \"$out/go-events-report.json\"\n"
            + "          test -s \"$out/format-exit.txt\"\n"
            + "          test -s \"$out/go-exit.txt\"\n"
            + "          test -s \"$out/event-check-exit.txt\"\n"
            + "          test \"$(cat \"$out/format-exit.txt\")\" = 0\n"
            + "          test \"$(cat \"$out/go-exit.txt\")\" = 0\n"
            + "          test \"$(cat \"$out/event-check-exit.txt\")\" = 0\n"
            + "          # END P207A_ACCEPTED_GATE\n"
            + "          # BEGIN P207A_FRESH_GATE\n"
            + "          test -s \"$root/source-before.json\"\n"
            + "          test -s \"$root/source-after.json\"\n"
            + "          test -s \"$root/go-list-report.json\"\n"
            + "          test -s \"$root/go-events-report.json\"\n"
            + "          test -s \"$root/format-exit.txt\"\n"
            + "          test -s \"$root/go-exit.txt\"\n"
            + "          test -s \"$root/event-check-exit.txt\"\n"
            + "          test -f \"$root/gofmt.patch\"\n"
            + "          test ! -s \"$root/gofmt.patch\"\n"
            + "          test -f \"$root/gofmt.stderr\"\n"
            + "          test ! -s \"$root/gofmt.stderr\"\n"
            + "          test \"$(cat \"$root/format-exit.txt\")\" = 0\n"
            + "          test \"$(cat \"$root/go-exit.txt\")\" = 0\n"
            + "          test \"$(cat \"$root/event-check-exit.txt\")\" = 0\n"
            + "          # END P207A_FRESH_GATE\n"
            + "          cmp \"$root/source-before.json\" \"$root/source-after.json\"\n"
            + "      - uses: actions/upload-artifact@pinned\n"
            + "        with:\n"
            + "          name: p207a-source-models-${{ github.run_id }}-${{ github.run_attempt }}\n"
            + "          path: chengwang/deploy/subscription-refresh/source-models.log\n"
            + "      - uses: actions/upload-artifact@pinned\n"
            + "        with:\n"
            + "          name: p207a-source-go-${{ github.run_id }}-${{ github.run_attempt }}\n"
            + "          path: |\n"
            + "            ${{ runner.temp }}/p207a-refresh/source-before.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/source-after.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/go-list-report.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/go-events-report.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/format-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/go-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/event-check-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/gofmt.patch\n"
            + "            ${{ runner.temp }}/p207a-refresh/gofmt.stderr\n"
            + "      - uses: actions/upload-artifact@pinned\n"
            + "        with:\n"
            + "          name: p207a-source-go-failure-${{ github.run_id }}-${{ github.run_attempt }}\n"
            + "          path: |\n"
            + "            ${{ runner.temp }}/p207a-refresh/source-before.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/source-after.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/format-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/go-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/event-check-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/failure-check-exit.txt\n"
            + "            ${{ runner.temp }}/p207a-refresh/go-failure-report.json\n"
            + "            ${{ runner.temp }}/p207a-refresh/gofmt.patch\n"
            + "            ${{ runner.temp }}/p207a-refresh/gofmt.stderr\n",
            encoding="utf-8",
            newline="\n",
        )
        fixture_paths = C.automatic_fixture_paths(self.root, tracked, module_paths)
        foundation_names = ["chengwang/internal/api::TestP0"]
        value = {
            "schema": C.SCHEMA,
            "scope": C.SCOPE,
            "authoringBaseCommit": "0" * 40,
            "moduleClosure": {
                "pathCount": len(module_paths),
                "pathsSHA256": C.names_digest(module_paths),
                "contentSHA256": C.source_aggregate(self.root, module_paths),
            },
            "fixtureClosure": {
                "additionalPaths": [],
                "paths": fixture_paths,
                "pathCount": len(fixture_paths),
                "pathsSHA256": C.names_digest(fixture_paths),
                "contentSHA256": C.source_aggregate(self.root, fixture_paths),
            },
            "changedGoSources": changed,
            "changedGoSourcesSHA256": C.map_digest(changed),
            "goTest": {"packages": list(C.PACKAGE_NAMES), "goos": "linux", "goarch": "amd64", "compiler": "gc", "goVersion": "go1.23.12", "cgoEnabled": False, "buildTags": [], "runPattern": "^Test", "count": 1, "timeoutSeconds": 180},
            "packages": packages,
            "allPackageTestTopCount": len(all_names),
            "allPackageTestTopsSHA256": C.names_digest(all_names),
            "allRequiredRunTopCount": len(all_names),
            "allRequiredRunTopsSHA256": C.names_digest(all_names),
            "p207aAddedTestTopCount": len(all_names),
            "p207aAddedTestTopsSHA256": C.names_digest(all_names),
            "p207aAddedTestTops": all_names,
            "baselinePackageTestTopCount": 0,
            "baselinePackageTestTopsSHA256": C.names_digest([]),
            "baselineRequiredRunTopCount": 0,
            "baselineRequiredRunTopsSHA256": C.names_digest([]),
            "foundation": {
                "checkerPath": "chengwang/deploy/foundation.py",
                "checkerSHA256": C.sha(self.foundation.read_bytes()),
                "currentCount": 1,
                "currentNamesSHA256": C.names_digest(foundation_names),
                "p207aAddedNames": foundation_names,
                "previousCount": 0,
                "previousNamesSHA256": C.names_digest([]),
            },
        }
        self.contract_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")

    def pins(self) -> dict:
        value = json.loads(self.contract_path.read_bytes())
        return {
            "contractSHA256": C.sha(self.contract_path.read_bytes()),
            "checkerSHA256": C.sha(self.checker.read_bytes()),
            "modelSHA256": C.sha(self.model.read_bytes()),
            "eventCheckerSHA256": C.sha(self.event_checker.read_bytes()),
            "eventModelSHA256": C.sha(self.event_model.read_bytes()),
            "failureCheckerSHA256": C.sha(self.failure_checker.read_bytes()),
            "failureModelSHA256": C.sha(self.failure_model.read_bytes()),
            "goListCheckerSHA256": C.sha(self.go_list_checker.read_bytes()),
            "goListModelSHA256": C.sha(self.go_list_model.read_bytes()),
            "moduleCount": value["moduleClosure"]["pathCount"],
            "moduleSHA256": value["moduleClosure"]["contentSHA256"],
            "fixtureCount": value["fixtureClosure"]["pathCount"],
            "fixtureSHA256": value["fixtureClosure"]["contentSHA256"],
            "testTopCount": value["allPackageTestTopCount"],
            "testTopsSHA256": value["allPackageTestTopsSHA256"],
            "runTopCount": value["allRequiredRunTopCount"],
            "runTopsSHA256": value["allRequiredRunTopsSHA256"],
            "changedGoCount": len(value["changedGoSources"]),
            "changedGoSHA256": value["changedGoSourcesSHA256"],
        }

    def verify(self, pins: dict | None = None) -> dict:
        return C.verify(self.root, "chengwang/deploy/subscription-refresh/source_contract.json", pins or self.pins())

    def assert_rejected(self, action) -> None:
        pins = self.pins()
        action()
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def test_exact_contract_accepts_without_claiming_go_execution(self) -> None:
        result = self.verify()
        self.assertEqual(result["packageTestTopCount"], 7)
        self.assertIs(result["goExecutionProven"], False)

    def test_actual_workflow_independently_pins_the_complete_contract_surface(self) -> None:
        repo = HERE.parents[2]
        workflow = (repo / ".github/workflows/chengwang-subscription-refresh.yml").read_text(encoding="utf-8")
        keys = {
            "CONTRACT_SHA256": "contractSHA256",
            "CHECKER_SHA256": "checkerSHA256",
            "MODEL_SHA256": "modelSHA256",
            "EVENT_CHECKER_SHA256": "eventCheckerSHA256",
            "EVENT_MODEL_SHA256": "eventModelSHA256",
            "FAILURE_CHECKER_SHA256": "failureCheckerSHA256",
            "FAILURE_MODEL_SHA256": "failureModelSHA256",
            "GO_LIST_CHECKER_SHA256": "goListCheckerSHA256",
            "GO_LIST_MODEL_SHA256": "goListModelSHA256",
            "MODULE_COUNT": "moduleCount",
            "MODULE_SHA256": "moduleSHA256",
            "FIXTURE_COUNT": "fixtureCount",
            "FIXTURE_SHA256": "fixtureSHA256",
            "TEST_TOP_COUNT": "testTopCount",
            "TEST_TOPS_SHA256": "testTopsSHA256",
            "RUN_TOP_COUNT": "runTopCount",
            "RUN_TOPS_SHA256": "runTopsSHA256",
            "CHANGED_GO_COUNT": "changedGoCount",
            "CHANGED_GO_SHA256": "changedGoSHA256",
        }
        observed = {}
        for source, target in keys.items():
            match = __import__("re").search(r"^  " + source + r": '?([0-9a-f]+)'?$", workflow, __import__("re").M)
            self.assertIsNotNone(match, source)
            value = match.group(1)
            observed[target] = int(value) if source.endswith("_COUNT") else value
            self.assertGreaterEqual(workflow.count('"$' + source + '"'), 2)
        result = C.verify(repo, "chengwang/deploy/subscription-refresh/source_contract.json", observed)
        self.assertFalse(result["goExecutionProven"])
        self.assertEqual(result["foundationCurrentCount"], 689)
        self.assertEqual(result["p207aAddedTestTopCount"], 33)
        self.assertEqual(result["baselinePackageTestTopCount"], 453)
        self.assertEqual(result["baselineRequiredRunTopCount"], 448)

        files = ("test_source_contract.py", "test_go_events.py")
        names = ["test_go_events.py::test_legacy", "test_source_contract.py::test_standard"]
        valid = (
            "test_standard (test_source_contract.ContractTests.test_standard) ... ok\n"
            "test_legacy (compat.test_go_events.EventTests) ... ok\n"
            "\n----------------------------------------------------------------------\n"
            "Ran 2 tests in 0.001s\n\nOK\n"
        )
        C.verify_source_model_log(valid, files, names)
        invalid = {
            "mismatched method": valid.replace("ContractTests.test_standard", "ContractTests.test_other"),
            "duplicate": valid.replace("test_legacy (compat", "test_standard (test_source_contract.ContractTests.test_standard) ... ok\n"
                                       "test_legacy (compat"),
            "skip": valid.replace("... ok\n", "... skipped 'not run'\n", 1),
            "extra": valid.replace("\n----------------------------------------------------------------------\n",
                                   "test_extra (test_other.OtherTests.test_extra) ... ok\n"
                                   "\n----------------------------------------------------------------------\n"),
            "missing": valid.replace("test_legacy (compat.test_go_events.EventTests) ... ok\n", ""),
        }
        for label, log in invalid.items():
            with self.subTest(label=label), self.assertRaises(C.ContractError):
                C.verify_source_model_log(log, files, names)

    def test_workflow_fixed_gate_is_bash_fail_closed_and_rejects_and_lists(self) -> None:
        if os.name == "nt":
            git = shutil.which("git")
            self.assertIsNotNone(git)
            bash = Path(git).resolve().parents[1] / "bin/bash.exe"
            self.assertTrue(bash.is_file())
        else:
            located = shutil.which("bash")
            self.assertIsNotNone(located)
            bash = Path(located)
        script = C.workflow_accepted_gate_script(self.workflow.read_text(encoding="utf-8"))

        def run_case(*, format_code="0", go_code="0", event_code="0", failure_code="0",
                     patch=b"", format_stderr=b"", go_stderr=b"", missing=None) -> int:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                out = root / "out"
                out.mkdir()
                content = {
                    "source-before.json": b"{}\n",
                    "source-after.json": b"{}\n",
                    "go-list-report.json": b"{}\n",
                    "go-events-report.json": b"{}\n",
                    "format-exit.txt": (format_code + "\n").encode(),
                    "go-exit.txt": (go_code + "\n").encode(),
                    "event-check-exit.txt": (event_code + "\n").encode(),
                    "gofmt.patch": patch,
                    "gofmt.stderr": format_stderr,
                    "go.stderr": go_stderr,
                }
                for name, raw in content.items():
                    if name != missing:
                        (out / name).write_bytes(raw)
                environment = os.environ.copy()
                for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
                    environment.pop(name, None)
                environment.update({
                    "out": "out", "formatCode": format_code, "code": go_code,
                    "eventCode": event_code, "failureCode": failure_code,
                })
                completed = subprocess.run(
                    [str(bash), "--noprofile", "--norc", "-euo", "pipefail"],
                    cwd=root,
                    env=environment,
                    input=script.encode(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(completed.stdout, b"")
                return completed.returncode

        self.assertEqual(run_case(), 0)
        cases = (
            {"go_code": "1", "event_code": "1"},
            {"event_code": "1"},
            {"patch": b"FORMAT_DIFF\n"},
            {"format_stderr": b"FORMAT_ERROR\n"},
            {"missing": "go-events-report.json"},
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertNotEqual(run_case(**case), 0)
        for required in (
            "source-before.json", "source-after.json", "go-list-report.json", "go-events-report.json",
            "format-exit.txt", "go-exit.txt", "event-check-exit.txt", "gofmt.patch", "gofmt.stderr",
        ):
            with self.subTest(missing=required):
                self.assertNotEqual(run_case(missing=required), 0)

        original = self.workflow.read_text(encoding="utf-8")
        pins = self.pins()
        variants = (
            original.replace(
                '          test ! -s "$out/gofmt.patch"\n          test -f "$out/gofmt.stderr"\n          test ! -s "$out/gofmt.stderr"',
                '          test ! -s "$out/gofmt.patch" && test ! -s "$out/gofmt.stderr"',
                1,
            ),
            original.replace(
                '          test "$code" = 0\n          test "$eventCode" = 0',
                '          test "$code" = 0 && test "$eventCode" = 0',
                1,
            ),
        )
        for value in variants:
            with self.subTest(and_list=value):
                self.workflow.write_text(value, encoding="utf-8", newline="\n")
                with self.assertRaisesRegex(C.ContractError, "workflow fixed gate"):
                    self.verify(pins)

    def test_deleted_source_is_rejected(self) -> None:
        self.assert_rejected(lambda: (self.root / "chengwang/internal/authz/source.go").unlink())

    def test_changed_fixture_is_rejected(self) -> None:
        self.assert_rejected(lambda: self.fixture.write_bytes(b"changed fixture\n"))

    def test_workflow_formatter_path_omission_is_rejected(self) -> None:
        self.assert_rejected(lambda: self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace("            chengwang/internal/api/source.go\n", ""),
            encoding="utf-8",
            newline="\n",
        ))

    def test_workflow_package_omission_is_rejected(self) -> None:
        self.assert_rejected(lambda: self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace(" ./internal/subscriptionpolicy", "", 1),
            encoding="utf-8",
            newline="\n",
        ))

    def test_workflow_target_change_is_rejected(self) -> None:
        self.assert_rejected(lambda: self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace("  GOARCH: amd64\n", "  GOARCH: arm64\n", 1),
            encoding="utf-8",
            newline="\n",
        ))

    def test_workflow_early_format_gate_is_rejected(self) -> None:
        self.assert_rejected(lambda: self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace(
                "          formatCode=$?\n",
                "          formatCode=$?\n          test ! -s \"$out/gofmt.patch\" && test ! -s \"$out/gofmt.stderr\"\n",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        ))

    def test_workflow_capture_order_swap_is_rejected(self) -> None:
        self.assert_rejected(lambda: self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace(
                "          formatCode=$?\n          cd chengwang\n",
                "          cd chengwang\n          formatCode=$?\n",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        ))

    def test_workflow_failure_upload_private_events_is_rejected(self) -> None:
        pins = self.pins()
        marker = (
            "          name: p207a-source-go-failure-${{ github.run_id }}-${{ github.run_attempt }}\n"
            "          path: |\n"
        )
        self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace(
                marker,
                marker + "            ${{ runner.temp }}/p207a-refresh/go-events.private.jsonl\n",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(C.ContractError, "workflow upload exposes private Go stream"):
            self.verify(pins)

    def test_workflow_accepted_upload_private_stderr_is_rejected(self) -> None:
        pins = self.pins()
        marker = "            ${{ runner.temp }}/p207a-refresh/go-events-report.json\n"
        self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace(
                marker,
                marker + "            ${{ runner.temp }}/p207a-refresh/go.stderr\n",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(C.ContractError, "workflow upload exposes private Go stream"):
            self.verify(pins)

    def test_workflow_upload_directory_glob_is_rejected(self) -> None:
        pins = self.pins()
        marker = "            ${{ runner.temp }}/p207a-refresh/gofmt.stderr\n"
        self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace(
                marker,
                marker + "            ${{ runner.temp }}/p207a-refresh/**\n",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(C.ContractError, "workflow upload path must be explicit"):
            self.verify(pins)

    def test_workflow_failure_diagnostic_paths_are_exactly_scoped(self) -> None:
        pins = self.pins()
        original = self.workflow.read_text(encoding="utf-8")
        accepted_marker = "            ${{ runner.temp }}/p207a-refresh/go-events-report.json\n"
        failure_marker = (
            "          name: p207a-source-go-failure-${{ github.run_id }}-${{ github.run_attempt }}\n"
            "          path: |\n"
        )
        variants = (
            original.replace(
                accepted_marker,
                accepted_marker + "            ${{ runner.temp }}/p207a-refresh/go-failure-report.json\n",
                1,
            ),
            original.replace(
                failure_marker,
                failure_marker + "            ${{ runner.temp }}/p207a-refresh/arbitrary-dynamic.json\n",
                1,
            ),
        )
        for value in variants:
            with self.subTest(value=value):
                self.workflow.write_text(value, encoding="utf-8", newline="\n")
                with self.assertRaisesRegex(C.ContractError, "workflow upload artifact path sets"):
                    self.verify(pins)
        reader_events = '--report "$out/go-failure-report.json" --events "$out/go-events.private.jsonl"'
        reader_exits = '--go-exit "$code" --event-check-exit "$eventCode" --contract "$CONTRACT"'
        for value in (
            original.replace(reader_events, '--report "$out/go-failure-report.json"', 1),
            original.replace(reader_exits, '--contract "$CONTRACT"', 1),
        ):
            with self.subTest(reader_binding=value):
                self.workflow.write_text(value, encoding="utf-8", newline="\n")
                with self.assertRaisesRegex(C.ContractError, "workflow capture/final-gate order"):
                    self.verify(pins)

    def test_renamed_test_top_is_rejected(self) -> None:
        path = self.root / "chengwang/internal/authn/source_test.go"
        self.assert_rejected(lambda: path.write_text(path.read_text().replace("TestP1", "TestRenamed"), encoding="utf-8", newline="\n"))

    def test_missing_test_top_is_rejected(self) -> None:
        path = self.root / "chengwang/internal/authn/source_test.go"
        self.assert_rejected(lambda: path.write_text("package p1\n", encoding="utf-8", newline="\n"))

    def test_extra_test_top_is_rejected(self) -> None:
        path = self.root / "chengwang/internal/authn/source_test.go"
        self.assert_rejected(lambda: path.write_bytes(path.read_bytes() + b"func TestExtra(t *testing.T) {}\n"))

    def test_hard_filled_count_is_rejected_even_when_contract_hash_pin_is_refreshed(self) -> None:
        value = json.loads(self.contract_path.read_bytes())
        value["allPackageTestTopCount"] += 1
        self.contract_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")
        pins = self.pins()
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def test_contract_and_source_rewrite_is_rejected_by_stale_workflow_pins(self) -> None:
        pins = self.pins()
        path = self.root / "chengwang/internal/api/source.go"
        path.write_bytes(path.read_bytes() + b"// coordinated rewrite\n")
        self.write_contract()
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def test_missing_embed_fixture_is_rejected_before_go_execution(self) -> None:
        value = json.loads(self.contract_path.read_bytes())
        value["fixtureClosure"]["paths"] = []
        value["fixtureClosure"]["additionalPaths"] = []
        value["fixtureClosure"]["pathCount"] = 0
        value["fixtureClosure"]["pathsSHA256"] = C.names_digest([])
        value["fixtureClosure"]["contentSHA256"] = C.source_aggregate(self.root, [])
        self.contract_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")
        pins = self.pins()
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def test_duplicate_contract_key_is_rejected(self) -> None:
        pins = self.pins()
        raw = self.contract_path.read_bytes().replace(b'{\n  "schema":', b'{\n  "schema":"duplicate",\n  "schema":', 1)
        self.contract_path.write_bytes(raw)
        pins["contractSHA256"] = C.sha(raw)
        with self.assertRaises(C.ContractError):
            self.verify(pins)


if __name__ == "__main__":
    unittest.main()
