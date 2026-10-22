from __future__ import annotations

import contextlib

import hashlib
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
                mock.patch.object(run_static_gate, "P0D6_GO_TEST_COUNT", len(fingerprint_names)),
                mock.patch.object(run_static_gate, "P0D6_GO_TEST_SHA256", hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(fingerprint_names)).encode("utf-8")).hexdigest()),
                mock.patch.object(run_static_gate, "P0D7_GO_TEST_COUNT", len(fingerprint_names)),
                mock.patch.object(run_static_gate, "P0D7_GO_TEST_SHA256", hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(fingerprint_names)).encode("utf-8")).hexdigest()),
                mock.patch.object(run_static_gate, "P0D8_GO_TEST_COUNT", len(fingerprint_names)),
                mock.patch.object(run_static_gate, "P0D8_GO_TEST_SHA256", hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(fingerprint_names)).encode("utf-8")).hexdigest()),
                mock.patch.object(run_static_gate, "P0D9_GO_TEST_COUNT", len(fingerprint_names)),
                mock.patch.object(run_static_gate, "P0D9_GO_TEST_SHA256", hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(fingerprint_names)).encode("utf-8")).hexdigest()),
                mock.patch.object(run_static_gate, "P0D9_GO_TEST_FINGERPRINTS", expected),
                mock.patch.object(run_static_gate, "CURRENT_GO_TEST_FINGERPRINTS", expected),
                contextlib.redirect_stdout(output),
            ):
                result = run_static_gate.validate_go_json([transcript])
            self.last_output = output.getvalue()
            return result

    def test_exact_passed_name_set_is_accepted(self) -> None:
        self.assertEqual(self._validate(_transcript(EXPECTED_NAMES)), 0)
        self.assertIn(run_static_gate.SCHEMA_METASCHEMA_PASS, self.last_output)
        # The whole-parent baseline is independent of individual package
        # fingerprints and must reject renamed/missing old names even when
        # a reviewed D7 extension is present.
        digest = hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(EXPECTED_NAMES)).encode("utf-8")).hexdigest()
        with (
            mock.patch.object(run_static_gate, "P0D6_GO_TEST_COUNT", len(EXPECTED_NAMES)),
            mock.patch.object(run_static_gate, "P0D6_GO_TEST_SHA256", digest),
        ):
            run_static_gate._validate_p0d6_go_baseline({PACKAGE: EXPECTED_NAMES})
            run_static_gate._validate_p0d6_go_baseline({PACKAGE: EXPECTED_NAMES, "chengwang/internal/evidence": {"TestImageTrustD7New"}})
            for names in (EXPECTED_NAMES - {"TestContract"}, (EXPECTED_NAMES - {"TestContract"}) | {"TestRenamed"}):
                with self.assertRaisesRegex(RuntimeError, "P0-d6 Go test baseline changed"):
                    run_static_gate._validate_p0d6_go_baseline({PACKAGE: names})
            with self.assertRaisesRegex(RuntimeError, "P0-d6 Go test baseline changed"):
                run_static_gate._validate_p0d6_go_baseline({PACKAGE: EXPECTED_NAMES, "chengwang/internal/api": {"TestImageTrustD7WrongPackage"}})

    def test_complete_d8_set_rejects_missing_replaced_and_added_names(self) -> None:
        names = EXPECTED_NAMES | {"TestD8Current"}
        digest = hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(names)).encode("utf-8")).hexdigest()
        expected = {PACKAGE: {"count": len(names), "sha256": run_static_gate._test_name_fingerprint(names)}}
        with (
            mock.patch.object(run_static_gate, "P0D8_GO_TEST_COUNT", len(names)),
            mock.patch.object(run_static_gate, "P0D8_GO_TEST_SHA256", digest),
            mock.patch.object(run_static_gate, "CURRENT_GO_TEST_FINGERPRINTS", expected),
        ):
            run_static_gate._validate_p0d8_go_baseline({PACKAGE: names})
            for changed in (names - {"TestD8Current"}, (names - {"TestD8Current"}) | {"TestRenamed"}, names | {"TestNew"}):
                with self.assertRaisesRegex(RuntimeError, "complete P0-d8 Go test set changed"):
                    run_static_gate._validate_p0d8_go_baseline({PACKAGE: changed})
            with mock.patch.object(run_static_gate, "CURRENT_GO_TEST_FINGERPRINTS", {PACKAGE: {"count": len(names), "sha256": "0" * 64}}):
                with self.assertRaisesRegex(RuntimeError, "P0-d8 Go package fingerprint mismatch"):
                    run_static_gate._validate_p0d8_go_baseline({PACKAGE: names})

    def test_deleted_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fingerprint mismatch"):
            self._validate(_transcript({"TestContract"}))

    def test_d9_extension_requires_cases_and_preserves_all_old_fingerprints(self) -> None:
        runtime = "chengwang/internal/serverruntime"
        required = run_static_gate.REQUIRED_GO_TEST_NAMES[runtime]
        baseline = hashlib.sha256("".join(PACKAGE + "\t" + name + "\n" for name in sorted(EXPECTED_NAMES)).encode("utf-8")).hexdigest()
        expected = {PACKAGE: {"count": len(EXPECTED_NAMES), "sha256": run_static_gate._test_name_fingerprint(EXPECTED_NAMES)}}
        complete_pairs = sorted([(PACKAGE, name) for name in EXPECTED_NAMES] + [(runtime, name) for name in required])
        complete_digest = hashlib.sha256("".join(package + "\t" + name + "\n" for package, name in complete_pairs).encode("utf-8")).hexdigest()

        def validate(runtime_names: set[str], *, package: str = runtime, bad_baseline: str | None = None, check_required: bool = True) -> int:
            events = _transcript(EXPECTED_NAMES)
            for name in sorted(runtime_names):
                events.extend(({"Action": "run", "Package": package, "Test": name}, {"Action": "pass", "Package": package, "Test": name}))
            events.append({"Action": "pass", "Package": package})
            with tempfile.TemporaryDirectory() as directory:
                transcript = pathlib.Path(directory) / "go-test.json"
                transcript.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
                with (
                    mock.patch.object(run_static_gate, "REQUIRED_GO_TEST_RUNS", {}),
                    mock.patch.object(run_static_gate, "REQUIRED_GO_TEST_NAMES", {runtime: required} if package == runtime and check_required else {}),
                    mock.patch.object(run_static_gate, "REQUIRED_GO_TEST_FINGERPRINTS", expected),
                    mock.patch.object(run_static_gate, "ALLOWED_GO_PACKAGE_SKIPS", frozenset()),
                    mock.patch.object(run_static_gate, "P0D6_GO_TEST_COUNT", len(EXPECTED_NAMES)),
                    mock.patch.object(run_static_gate, "P0D6_GO_TEST_SHA256", "0" * 64 if bad_baseline == "d6" else baseline),
                    mock.patch.object(run_static_gate, "P0D7_GO_TEST_COUNT", len(EXPECTED_NAMES)),
                    mock.patch.object(run_static_gate, "P0D7_GO_TEST_SHA256", "0" * 64 if bad_baseline == "d7" else baseline),
                    mock.patch.object(run_static_gate, "P0D8_GO_TEST_COUNT", len(EXPECTED_NAMES)),
                    mock.patch.object(run_static_gate, "P0D8_GO_TEST_SHA256", "0" * 64 if bad_baseline == "d8" else baseline),
                    mock.patch.object(run_static_gate, "P0D9_GO_TEST_COUNT", len(complete_pairs)),
                    mock.patch.object(run_static_gate, "P0D9_GO_TEST_SHA256", "0" * 64 if bad_baseline == "d9" else complete_digest),
                    mock.patch.object(run_static_gate, "P0D9_GO_TEST_FINGERPRINTS", {runtime: {"count": len(required), "sha256": "0" * 64 if bad_baseline == "d9-package" else run_static_gate._test_name_fingerprint(required)}}),
                    mock.patch.object(run_static_gate, "CURRENT_GO_TEST_FINGERPRINTS", expected),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    return run_static_gate.validate_go_json([transcript])

        self.assertEqual(validate(set(required)), 0)
        for name in required:
            with self.subTest(missing=name), self.assertRaisesRegex(RuntimeError, "missing required top-level passing tests"):
                validate(set(required) - {name})
        for baseline_name, message in (("d6", "P0-d6 Go test baseline changed"), ("d7", "P0-d7 Go test baseline changed"), ("d8", "complete P0-d8 Go test set changed"), ("d9", "complete P0-d9 Go test set changed"), ("d9-package", "P0-d9 Go package fingerprint mismatch")):
            with self.subTest(bad_baseline=baseline_name), self.assertRaisesRegex(RuntimeError, message):
                validate(set(required), bad_baseline=baseline_name)
        for package, extra in (("chengwang/cmd/server", "TestServerRuntimeD9WrongPackage"), (runtime, "TestUnreviewedRuntimeExtension")):
            with self.subTest(package=package), self.assertRaisesRegex(RuntimeError, "P0-d6 Go test baseline changed"):
                if package == runtime:
                    validate(set(required) | {extra})
                else:
                    validate({extra}, package=package)
        # The complete D9 guard is independent of the required-name guard and
        # must reject a same-prefix substitution even at the accepted count.
        first = sorted(required)[0]
        for changed in (set(required) - {first}, (set(required) - {first}) | {first + "Renamed"}, set(required) | {"TestServerRuntimeD9Unexpected"}):
            with self.subTest(complete_d9=sorted(changed)), self.assertRaisesRegex(RuntimeError, "complete P0-d9 Go test set changed"):
                validate(changed, check_required=False)

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

    def test_release_observer_side_effect_import_is_rejected(self) -> None:
        package = self._package('package restorecurrent\nimport "errors"\nvar _ = errors.New\n')
        (package / "release.go").write_text(
            'package restorecurrent\nimport "os"\nvar _ = os.WriteFile\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "forbidden filesystem mutation|side-effect-capable packages"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_release_observer_cannot_call_same_package_helper(self) -> None:
        package = self._package("package restorecurrent\nfunc mutate() {}\n")
        (package / "release.go").write_text(
            "package restorecurrent\nfunc observe() { mutate() }\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "helpers declared outside"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_release_observer_cannot_call_println(self) -> None:
        package = self._package("package restorecurrent\n")
        (package / "release.go").write_text(
            "package restorecurrent\nfunc observe(secret string) { println(secret) }\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "builtin side effect"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_restorecurrent_cannot_call_fmt_print(self) -> None:
        package = self._package(
            'package restorecurrent\nimport "fmt"\nfunc mutate(secret string) { fmt.Print(secret) }\n'
        )
        with self.assertRaisesRegex(RuntimeError, "standard output mutation"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_restorecurrent_cannot_call_builtin_println(self) -> None:
        package = self._package(
            "package restorecurrent\nfunc mutate(secret string) { println(secret) }\n"
        )
        with self.assertRaisesRegex(RuntimeError, "builtin side effect"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_release_observer_cannot_call_same_package_selector_method(self) -> None:
        package = self._package(
            "package restorecurrent\ntype helper struct{}\nfunc (helper) mutate() {}\n"
        )
        (package / "release.go").write_text(
            "package restorecurrent\nfunc observe(value helper) { value.mutate() }\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "unreviewed selector methods"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_release_observer_cannot_call_same_package_generic_helper(self) -> None:
        package = self._package("package restorecurrent\nfunc mutate[T any]() {}\n")
        (package / "release.go").write_text(
            "package restorecurrent\nfunc observe() { mutate[int]() }\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "helpers declared outside"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_unreviewed_os_mutator_is_rejected_package_wide(self) -> None:
        package = self._package(
            'package restorecurrent\nimport "os"\nfunc mutate() { _ = os.Mkdir("/tmp/x", 0700) }\n'
        )
        with self.assertRaisesRegex(RuntimeError, "unreviewed OS or syscall APIs"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_aliased_os_mutator_is_rejected_package_wide(self) -> None:
        package = self._package(
            'package restorecurrent\nimport fs "os"\nfunc mutate() { _ = fs.Mkdir("/tmp/x", 0700) }\n'
        )
        with self.assertRaisesRegex(RuntimeError, "unreviewed OS or syscall APIs"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_release_observer_cannot_call_chained_same_package_method(self) -> None:
        package = self._package(
            "package restorecurrent\ntype helper struct{}\nfunc (helper) mutate() {}\n"
        )
        (package / "release.go").write_text(
            "package restorecurrent\nfunc localFactory() helper { return helper{} }\nfunc observe() { localFactory().mutate() }\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "chained selector method"):
            run_static_gate._validate_restorecurrent_package(package)

    def test_compose_snapshot_drift_is_rejected(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        chengwang = pathlib.Path(temporary.name) / "chengwang"
        candidate = chengwang / "deploy" / "m2b-candidate"
        package = chengwang / "internal" / "restorecurrent"
        candidate.mkdir(parents=True)
        package.mkdir(parents=True)
        (package / "current.go").write_text("package restorecurrent\n", encoding="utf-8")
        (package / "compose_probe_agent.snapshot.yaml").write_bytes(b"reviewed\n")
        (candidate / "compose.probe-agent.yaml").write_bytes(b"drifted\n")
        with self.assertRaisesRegex(RuntimeError, "snapshot differs"):
            run_static_gate._validate_restorecurrent_sources(candidate)

    def test_authoritative_or_state_collection_api_is_rejected(self) -> None:
        for token in ("restorecontracts.StateOnlyCurrent", "AcquireLockedStateSnapshot"):
            with self.subTest(token=token):
                package = self._package(f"package restorecurrent\n// test\nvar _ = {token}\n")
                with self.assertRaisesRegex(RuntimeError, "forbidden"):
                    run_static_gate._validate_restorecurrent_package(package)


class RuntimeObserverSourceGateTests(unittest.TestCase):
    def _tree(self, observer_source: str, proxy_source: str) -> pathlib.Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        chengwang = pathlib.Path(temporary.name) / "chengwang"
        candidate = chengwang / "deploy" / "m2b-candidate"
        observer = chengwang / "internal" / "restoreruntime"
        proxy = chengwang / "internal" / "dockerreadonlyproxy"
        command = chengwang / "cmd" / "docker-runtime-readonly-proxy"
        for path in (candidate, observer, proxy, command):
            path.mkdir(parents=True, exist_ok=True)
        (observer / "runtime.go").write_text(observer_source, encoding="utf-8")
        (observer / "client.go").write_text(
            'package restoreruntime\nconst socket = "/run/chengwang-runtime-observer/readonly.sock"\n',
            encoding="utf-8",
        )
        (observer / "unsupported.go").write_text("package restoreruntime\n", encoding="utf-8")
        (proxy / "server.go").write_text(
            'package dockerreadonlyproxy\nconst SnapshotPathPrefix = "/v1/runtime-snapshot/"\n',
            encoding="utf-8",
        )
        (proxy / "collector.go").write_text(proxy_source, encoding="utf-8")
        (proxy / "unsupported.go").write_text("package dockerreadonlyproxy\n", encoding="utf-8")
        (command / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
        return candidate

    def test_minimal_fixed_readonly_boundary_is_accepted(self) -> None:
        candidate = self._tree(
            "package restoreruntime\n",
            'package dockerreadonlyproxy\nconst backend = "/run/docker.sock"\n',
        )
        run_static_gate._validate_runtime_observer_sources(candidate)

    def test_observer_standard_docker_socket_or_write_method_is_rejected(self) -> None:
        for token in ('const bad = "/var/run/docker.sock"', "const bad = http.MethodPost"):
            with self.subTest(token=token):
                candidate = self._tree(
                    "package restoreruntime\n" + token + "\n",
                    'package dockerreadonlyproxy\nconst backend = "/run/docker.sock"\n',
                )
                with self.assertRaisesRegex(RuntimeError, "forbidden"):
                    run_static_gate._validate_runtime_observer_sources(candidate)

    def test_proxy_docker_write_or_broad_read_path_is_rejected(self) -> None:
        for token in ("http.MethodDelete", 'const bad = "/logs"'):
            with self.subTest(token=token):
                candidate = self._tree(
                    "package restoreruntime\n",
                    'package dockerreadonlyproxy\nconst backend = "/run/docker.sock"\nvar bad = ' + token + "\n",
                )
                with self.assertRaisesRegex(RuntimeError, "forbidden"):
                    run_static_gate._validate_runtime_observer_sources(candidate)


if __name__ == "__main__":
    unittest.main()
