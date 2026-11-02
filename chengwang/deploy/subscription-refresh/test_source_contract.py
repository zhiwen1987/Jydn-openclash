"""Pure-CPU negative models for the P207A v4 source closure."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("p207a_source_contract", HERE / "check_source_contract.py")
assert SPEC is not None and SPEC.loader is not None
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
PRODUCTION_WORKFLOW_TEMPLATE_SHA256 = C.WORKFLOW_TEMPLATE_SHA256


def command(cwd: Path, *args: str) -> None:
    subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)


class ClosedSourceContractModels(unittest.TestCase):
    def setUp(self) -> None:
        C.HISTORICAL_BASELINE_SOURCE_COUNT = 0
        C.HISTORICAL_BASELINE_SOURCE_SHA256 = C.names_digest([])
        C.HISTORICAL_BASELINE_REQUIRED_RUN_COUNT = 0
        C.HISTORICAL_BASELINE_REQUIRED_RUN_SHA256 = C.names_digest([])
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
        normalized, _values = C.normalize_workflow_template(self.workflow.read_text(encoding="utf-8"))
        C.WORKFLOW_TEMPLATE_SHA256 = C.sha(normalized.encode("utf-8"))
        self.synthetic_workflow_template_sha256 = C.WORKFLOW_TEMPLATE_SHA256
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
        pin_lines = "".join(
            f"  {name}: {'0' * 64 if kind == 'digest' else "'0'"}\n"
            for name, _pin, kind in C.WORKFLOW_PIN_SPECS
        )
        self.workflow.write_text(
            "env:\n" + pin_lines + "          GOFLAGS: -mod=vendor\n  GOOS: linux\n  GOARCH: amd64\n  CGO_ENABLED: '0'\n"
            "          assert len(names)==len(set(names))==0\n"
            "          assert hashlib.sha256('\\n'.join(names).encode()).hexdigest()=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'\n"
            "          print('P207A_SOURCE_MODELS=PASS count=0 go_execution_proven=false')\n"
            "  source-models:\n"
            "      - uses: actions/checkout@pinned\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "          fetch-depth: 0\n"
            "run: |\n"
            "          # BEGIN P207A_NATIVEFS_MIRROR_GATE\n"
            + "".join("          " + line + "\n" for line in C.NATIVEFS_MIRROR_GATE_LINES)
            + "          # END P207A_NATIVEFS_MIRROR_GATE\n"
            + "          fmt=(\n"
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
            + "          path: |\n"
            + "            chengwang/deploy/subscription-refresh/source-models.log\n"
            + "            ${{ runner.temp }}/p207a-nativefs-mirror/nativefs-mirror-tests.log\n"
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
            "p207aAddedSourceTestTopCount": len(all_names),
            "p207aAddedSourceTestTopsSHA256": C.names_digest(all_names),
            "p207aAddedSourceTestTops": all_names,
            "p207aAddedRequiredRunTopCount": len(all_names),
            "p207aAddedRequiredRunTopsSHA256": C.names_digest(all_names),
            "p207aAddedRequiredRunTops": all_names,
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
        pins = self.pins()
        workflow = self.workflow.read_text(encoding="utf-8")
        for name, pin, kind in C.WORKFLOW_PIN_SPECS:
            old = "0" * 64 if kind == "digest" else "'0'"
            new = pins[pin] if kind == "digest" else f"'{pins[pin]}'"
            workflow = workflow.replace(f"  {name}: {old}\n", f"  {name}: {new}\n", 1)
        self.workflow.write_text(workflow, encoding="utf-8", newline="\n")

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

    def sync_workflow_pins(self, pins: dict) -> None:
        lines = self.workflow.read_text(encoding="utf-8").splitlines(keepends=True)
        for name, pin, kind in C.WORKFLOW_PIN_SPECS:
            indexes = [index for index, line in enumerate(lines) if line.startswith(f"  {name}: ")]
            self.assertEqual(indexes, [indexes[0]] if indexes else [], name)
            self.assertEqual(len(indexes), 1, name)
            value = pins[pin] if kind == "digest" else f"'{pins[pin]}'"
            lines[indexes[0]] = f"  {name}: {value}\n"
        self.workflow.write_text("".join(lines), encoding="utf-8", newline="\n")

    def verify(self, pins: dict | None = None) -> dict:
        values = pins or self.pins()
        if pins is None:
            self.sync_workflow_pins(values)
        return C.verify(self.root, "chengwang/deploy/subscription-refresh/source_contract.json", values)

    def cli_output(self, pins: dict | None = None) -> bytes:
        values = pins or self.pins()
        if pins is None:
            self.sync_workflow_pins(values)
        arguments = [
            "check_source_contract.py",
            "--repo", str(self.root),
            "--contract", "chengwang/deploy/subscription-refresh/source_contract.json",
        ]
        names = (
            ("contract-sha256", "contractSHA256"), ("checker-sha256", "checkerSHA256"),
            ("model-sha256", "modelSHA256"), ("event-checker-sha256", "eventCheckerSHA256"),
            ("event-model-sha256", "eventModelSHA256"), ("failure-checker-sha256", "failureCheckerSHA256"),
            ("failure-model-sha256", "failureModelSHA256"), ("go-list-checker-sha256", "goListCheckerSHA256"),
            ("go-list-model-sha256", "goListModelSHA256"), ("module-count", "moduleCount"),
            ("module-sha256", "moduleSHA256"), ("fixture-count", "fixtureCount"),
            ("fixture-sha256", "fixtureSHA256"), ("test-top-count", "testTopCount"),
            ("test-tops-sha256", "testTopsSHA256"), ("run-top-count", "runTopCount"),
            ("run-tops-sha256", "runTopsSHA256"), ("changed-go-count", "changedGoCount"),
            ("changed-go-sha256", "changedGoSHA256"),
        )
        for argument, key in names:
            arguments.extend(("--" + argument, str(values[key])))
        saved = sys.argv
        output = io.StringIO()
        try:
            sys.argv = arguments
            with redirect_stdout(output):
                C.main()
        finally:
            sys.argv = saved
        return output.getvalue().encode("utf-8")

    def assert_rejected(self, action) -> None:
        pins = self.pins()
        action()
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def write_contract_value(self, value: dict) -> None:
        self.contract_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")

    def assert_contract_rejected(self, mutate) -> None:
        value = json.loads(self.contract_path.read_bytes())
        mutate(value)
        self.write_contract_value(value)
        pins = self.pins()
        self.sync_workflow_pins(pins)
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def make_source_only(self) -> str:
        value = json.loads(self.contract_path.read_bytes())
        package = C.PACKAGE_NAMES[0]
        declared = value["packages"][package]
        path = declared["requiredRunTestFiles"].pop(0)
        declared["excludedRunTestFiles"].append(path)
        top = declared["requiredRunTops"].pop(0)
        declared["excludedRunTops"].append(top)
        declared["requiredRunTopCount"] = len(declared["requiredRunTops"])
        declared["requiredRunTopsSHA256"] = C.names_digest(declared["requiredRunTops"])
        all_run = sorted(
            name
            for item in value["packages"].values()
            for name in item["requiredRunTops"]
        )
        value["allRequiredRunTopCount"] = len(all_run)
        value["allRequiredRunTopsSHA256"] = C.names_digest(all_run)
        value["p207aAddedRequiredRunTops"].remove(top)
        value["p207aAddedRequiredRunTopCount"] = len(value["p207aAddedRequiredRunTops"])
        value["p207aAddedRequiredRunTopsSHA256"] = C.names_digest(value["p207aAddedRequiredRunTops"])
        self.write_contract_value(value)
        return top

    def test_exact_contract_accepts_without_claiming_go_execution(self) -> None:
        result = self.verify()
        self.assertEqual(result["packageTestTopCount"], 9)
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
        C.HISTORICAL_BASELINE_SOURCE_COUNT = 453
        C.HISTORICAL_BASELINE_SOURCE_SHA256 = "319025b42a43817ed041ae2cb7349f6a3164e295cad2dbc143718f6a6002b81b"
        C.HISTORICAL_BASELINE_REQUIRED_RUN_COUNT = 448
        C.HISTORICAL_BASELINE_REQUIRED_RUN_SHA256 = "34221f6a5f60aa7a3ad5a47e776f7b789c9295df15ab8c40f298ea8d4932afd7"
        C.WORKFLOW_TEMPLATE_SHA256 = PRODUCTION_WORKFLOW_TEMPLATE_SHA256
        try:
            result = C.verify(repo, "chengwang/deploy/subscription-refresh/source_contract.json", observed)
        finally:
            C.HISTORICAL_BASELINE_SOURCE_COUNT = 0
            C.HISTORICAL_BASELINE_SOURCE_SHA256 = C.names_digest([])
            C.HISTORICAL_BASELINE_REQUIRED_RUN_COUNT = 0
            C.HISTORICAL_BASELINE_REQUIRED_RUN_SHA256 = C.names_digest([])
            C.WORKFLOW_TEMPLATE_SHA256 = self.synthetic_workflow_template_sha256
        self.assertFalse(result["goExecutionProven"])
        self.assertEqual(result["modulePathCount"], 842)
        self.assertEqual(result["fixturePathCount"], 21)
        self.assertEqual(result["packageTestTopCount"], 545)
        self.assertEqual(result["requiredRunTopCount"], 528)
        self.assertEqual(result["changedGoSourceCount"], 39)
        self.assertEqual(result["foundationCurrentCount"], 689)
        self.assertEqual(result["p207aAddedSourceTestTopCount"], 92)
        self.assertEqual(result["p207aAddedRequiredRunTopCount"], 80)
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

    def test_workflow_nativefs_mirror_gate_and_full_history_are_exact(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        script = C.workflow_nativefs_mirror_gate_script(text)
        self.assertEqual(script, "set -euo pipefail\n" + "\n".join(C.NATIVEFS_MIRROR_GATE_LINES) + "\n")
        self.assertEqual(text.count("          fetch-depth: 0\n"), 1)
        self.assertIn('--repo "$GITHUB_WORKSPACE"', script)
        self.assertIn('--tracked "$GITHUB_WORKSPACE/chengwang/internal/nativefs/linux_magic_generated.go"', script)
        self.assertIn('CHENGWANG_NATIVEFS_MIRROR_FIXTURE_ROOT="$nativefsRoot"', script)
        self.assertIn('CHENGWANG_NATIVEFS_MIRROR_REPO="$GITHUB_WORKSPACE"', script)

    def test_v4_source_only_added_top_maps_to_excluded_file_and_accepts(self) -> None:
        top = self.make_source_only()
        result = self.verify()
        self.assertEqual(result["p207aAddedSourceTestTopCount"], 9)
        self.assertEqual(result["p207aAddedRequiredRunTopCount"], 8)
        self.assertNotIn(top, json.loads(self.contract_path.read_bytes())["p207aAddedRequiredRunTops"])

    def test_v4_added_required_run_top_absent_from_added_source_rejected(self) -> None:
        def mutate(value: dict) -> None:
            value["p207aAddedSourceTestTops"].pop(0)
            value["p207aAddedSourceTestTopCount"] -= 1
            value["p207aAddedSourceTestTopsSHA256"] = C.names_digest(value["p207aAddedSourceTestTops"])
        self.assert_contract_rejected(mutate)

    def test_v4_source_only_top_mapped_to_required_file_rejected(self) -> None:
        top = self.make_source_only()
        value = json.loads(self.contract_path.read_bytes())
        package = C.PACKAGE_NAMES[0]
        declared = value["packages"][package]
        path = declared["excludedRunTestFiles"].pop(0)
        declared["requiredRunTestFiles"].append(path)
        declared["requiredRunTops"].append(top)
        declared["requiredRunTops"].sort()
        declared["excludedRunTops"].remove(top)
        declared["requiredRunTopCount"] = len(declared["requiredRunTops"])
        declared["requiredRunTopsSHA256"] = C.names_digest(declared["requiredRunTops"])
        all_run = sorted(
            name
            for item in value["packages"].values()
            for name in item["requiredRunTops"]
        )
        value["allRequiredRunTopCount"] = len(all_run)
        value["allRequiredRunTopsSHA256"] = C.names_digest(all_run)
        self.write_contract_value(value)
        with self.assertRaises(C.ContractError):
            self.verify(self.pins())

    def test_v4_coherent_source_baseline_repin_cannot_change_historical_identity(self) -> None:
        def mutate(value: dict) -> None:
            omitted = value["p207aAddedSourceTestTops"].pop(0)
            value["p207aAddedSourceTestTopCount"] -= 1
            value["p207aAddedSourceTestTopsSHA256"] = C.names_digest(value["p207aAddedSourceTestTops"])
            value["baselinePackageTestTopCount"] = 1
            value["baselinePackageTestTopsSHA256"] = C.names_digest([omitted])
        self.assert_contract_rejected(mutate)

    def test_v4_coherent_run_baseline_repin_cannot_change_historical_identity(self) -> None:
        def mutate(value: dict) -> None:
            omitted = value["p207aAddedRequiredRunTops"].pop(0)
            value["p207aAddedRequiredRunTopCount"] -= 1
            value["p207aAddedRequiredRunTopsSHA256"] = C.names_digest(value["p207aAddedRequiredRunTops"])
            value["baselineRequiredRunTopCount"] = 1
            value["baselineRequiredRunTopsSHA256"] = C.names_digest([omitted])
        self.assert_contract_rejected(mutate)

    def test_v4_added_source_count_corruption_rejected_with_refreshed_outer_digest(self) -> None:
        self.assert_contract_rejected(lambda value: value.__setitem__(
            "p207aAddedSourceTestTopCount", value["p207aAddedSourceTestTopCount"] + 1))

    def test_v4_added_source_hash_corruption_rejected_with_refreshed_outer_digest(self) -> None:
        self.assert_contract_rejected(lambda value: value.__setitem__(
            "p207aAddedSourceTestTopsSHA256", "0" * 64))

    def test_v4_added_run_count_corruption_rejected_with_refreshed_outer_digest(self) -> None:
        self.assert_contract_rejected(lambda value: value.__setitem__(
            "p207aAddedRequiredRunTopCount", value["p207aAddedRequiredRunTopCount"] + 1))

    def test_v4_added_run_hash_corruption_rejected_with_refreshed_outer_digest(self) -> None:
        self.assert_contract_rejected(lambda value: value.__setitem__(
            "p207aAddedRequiredRunTopsSHA256", "0" * 64))

    def test_v4_legacy_mixed_extra_reordered_and_duplicate_contract_surfaces_rejected(self) -> None:
        original = json.loads(self.contract_path.read_bytes())
        variants = []
        legacy = dict(original)
        legacy["p207aAddedTestTopCount"] = legacy["p207aAddedSourceTestTopCount"]
        variants.append(legacy)
        mixed = dict(original)
        mixed["p207aAddedTestTops"] = list(mixed["p207aAddedSourceTestTops"])
        variants.append(mixed)
        reordered = dict(original)
        moved = reordered.pop("p207aAddedSourceTestTopCount")
        reordered["p207aAddedSourceTestTopCount"] = moved
        variants.append(reordered)
        for value in variants:
            with self.subTest(keys=tuple(value)):
                self.write_contract_value(value)
                with self.assertRaises(C.ContractError):
                    self.verify(self.pins())
        raw = json.dumps(original, indent=2).encode() + b"\n"
        raw = raw.replace(b'  "p207aAddedSourceTestTopCount":',
                          b'  "p207aAddedSourceTestTopCount": 7,\n  "p207aAddedSourceTestTopCount":', 1)
        self.contract_path.write_bytes(raw)
        pins = self.pins()
        with self.assertRaises(C.ContractError):
            self.verify(pins)

    def test_v4_nonempty_contract_build_tags_rejected(self) -> None:
        self.assert_contract_rejected(lambda value: value["goTest"].__setitem__("buildTags", ["a1actualfs"]))

    def test_v4_workflow_go_list_tag_selection_rejected(self) -> None:
        self.assert_rejected(lambda: self.workflow.write_text(
            self.workflow.read_text(encoding="utf-8").replace("go list -json ", "go list -tags a1actualfs -json ", 1),
            encoding="utf-8", newline="\n"))

    def test_v4_workflow_go_test_and_goflags_tag_selection_rejected(self) -> None:
        original = self.workflow.read_text(encoding="utf-8")
        fragmented = (
            "          n=GO\n"
            "          n=${n}FLAGS\n"
            "          v=-ta\n"
            "          v=${v}gs=a1actualfs\n"
            "          export \"$n=$v\"\n"
        )
        contract_pin = next(line for line in original.splitlines(keepends=True)
                            if line.startswith("  CONTRACT_SHA256: "))
        variants = {
            "go-test-tag": original.replace("go test -json ", "go test -tags=a1actualfs -json ", 1),
            "direct": original.replace("GOFLAGS: -mod=vendor", "GOFLAGS: -tags=a1actualfs", 1),
            "double-quoted-root-counterexample": original.replace(
                "GOFLAGS: -mod=vendor", "GOFLAGS: \"-tags=a1actualfs\"", 1),
            "single-quoted": original.replace("GOFLAGS: -mod=vendor", "GOFLAGS: '-tags=a1actualfs'", 1),
            "flow-yaml": original.replace("GOFLAGS: -mod=vendor", "{GOFLAGS: -tags=a1actualfs}", 1),
            "empty": original.replace("GOFLAGS: -mod=vendor", "GOFLAGS:", 1),
            "expression": original.replace("GOFLAGS: -mod=vendor", "GOFLAGS: ${{ env.EXTRA_GOFLAGS }}", 1),
            "literal-export": original.replace(
                "GOFLAGS: -mod=vendor", "GOFLAGS: -mod=vendor\n          export GOFLAGS=-tags=a1actualfs", 1),
            "env-inline": original.replace(
                "go test -json ", "env GOFLAGS=-tags=a1actualfs go test -json ", 1),
            "fragmented-shell-root-counterexample": original.replace(
                "          go list -json ", fragmented + "          go list -json ", 1),
            "moved-env": original.replace("          GOFLAGS: -mod=vendor\n", "", 1).replace(
                "  GOOS: linux\n", "  GOOS: linux\n  GOFLAGS: -mod=vendor\n", 1),
            "extra-execution": original.replace("          go list -json ", "          true\n          go list -json ", 1),
            "opaque-dynamic-execution": original.replace(
                "          go list -json ", "          eval \"$P207_EXTRA\"\n          go list -json ", 1),
            "normalizer-missing-pin": original.replace(contract_pin, "", 1),
            "normalizer-duplicate-pin": original.replace(contract_pin, contract_pin + contract_pin, 1),
            "normalizer-unknown-pin": original.replace(
                contract_pin, contract_pin + "  UNKNOWN_SHA256: " + "0" * 64 + "\n", 1),
            "normalizer-valid-format-value-tamper": original.replace(
                contract_pin, contract_pin[:contract_pin.index(": ") + 2] + "0" * 64 + "\n", 1),
        }
        for label, value in variants.items():
            with self.subTest(label=label):
                self.workflow.write_text(value, encoding="utf-8", newline="\n")
                with self.assertRaises(C.ContractError):
                    self.verify(self.pins())

    def test_v4_source_report_has_exact_split_bounded_projection(self) -> None:
        result = self.verify()
        self.assertEqual(tuple(result), (
            "schema", "modulePathCount", "moduleContentSHA256", "automaticFixturePathCount",
            "additionalFixturePathCount", "fixturePathCount", "fixtureContentSHA256",
            "packageTestTopCount", "packageTestTopsSHA256", "requiredRunTopCount",
            "requiredRunTopsSHA256", "p207aAddedSourceTestTopCount",
            "p207aAddedSourceTestTopsSHA256", "p207aAddedRequiredRunTopCount",
            "p207aAddedRequiredRunTopsSHA256", "baselinePackageTestTopCount",
            "baselineRequiredRunTopCount", "changedGoSourceCount", "changedGoSourcesSHA256",
            "foundationCurrentCount", "foundationPreviousCount", "goExecutionProven",
        ))
        self.assertFalse(any("Tops" in key and key.endswith("Tops") for key in result))
        self.assertNotIn("p207aAddedTestTopCount", result)

    def test_v4_actual_cli_report_bytes_preserve_exact_declared_projection_and_repeat(self) -> None:
        result = self.verify()
        before = self.cli_output()
        after = self.cli_output()
        expected = (json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8")
        self.assertEqual(before, expected)
        self.assertEqual(after, before)
        pairs = json.loads(before, object_pairs_hook=lambda values: values)
        self.assertEqual([key for key, _value in pairs], list(result))
        self.assertNotIn(b"p207aAddedTestTopCount", before)
        self.assertNotIn(b"p207aAddedSourceTestTops\"", before)
        self.assertNotIn(b"p207aAddedRequiredRunTops\"", before)

    def test_v4_split_projection_contract_keys_cannot_be_removed_or_reordered(self) -> None:
        original = json.loads(self.contract_path.read_bytes())
        variants = []
        missing = dict(original)
        missing.pop("p207aAddedRequiredRunTopsSHA256")
        variants.append(missing)
        reordered = dict(original)
        moved = reordered.pop("p207aAddedRequiredRunTopCount")
        reordered["p207aAddedRequiredRunTopCount"] = moved
        variants.append(reordered)
        for value in variants:
            with self.subTest(keys=tuple(value)):
                self.write_contract_value(value)
                with self.assertRaises(C.ContractError):
                    self.verify(self.pins())

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
