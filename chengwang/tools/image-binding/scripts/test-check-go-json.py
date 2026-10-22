#!/usr/bin/env python3
"""Exercise exact scoped extensions without requiring or mutating Go inputs."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

source = pathlib.Path(__file__).with_name("check-go-json.py")
spec = importlib.util.spec_from_file_location("image_binding_json_gate", source)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class D9BaselineScopeTests(unittest.TestCase):
    old = frozenset(((gate.ROOT, "TestRootOld"), (gate.COMMAND, "TestCandidateOld"), (gate.PRODUCT, "TestProductOld")))
    extension = frozenset(((gate.COMMAND, "TestCandidateD9Known"),))

    def validate_full_d9(self, pairs):
        accepted = self.old | self.extension
        fingerprints = {package: (len(names := sorted(name for actual, name in accepted if actual == package)),
                                  hashlib.sha256("\n".join(names).encode()).hexdigest()) for package, _ in accepted}
        def digest(values):
            return hashlib.sha256("".join(package + "\t" + name + "\n" for package, name in sorted(values)).encode()).hexdigest()
        with (mock.patch.object(gate, "D9_PACKAGE_FINGERPRINTS", fingerprints),
              mock.patch.object(gate, "ACCEPTED_D9_COUNT", len(accepted)),
              mock.patch.object(gate, "ACCEPTED_D9_SHA256", digest(accepted)),
              mock.patch.object(gate, "ACCEPTED_D9_NEW_COUNT", len(self.extension)),
              mock.patch.object(gate, "ACCEPTED_D9_NEW_SHA256", digest(self.extension))):
            gate.check_d9_complete_packages(pairs)

    def validate(self, pairs):
        fingerprints = {package: (1, hashlib.sha256(name.encode()).hexdigest()) for package, name in self.old}
        digest = hashlib.sha256("".join(package + "\t" + name + "\n" for package, name in sorted(self.old)).encode()).hexdigest()
        with (mock.patch.object(gate, "CURRENT_PACKAGE_FINGERPRINTS", fingerprints),
              mock.patch.object(gate, "COMPLETE_PACKAGE_FINGERPRINTS", fingerprints),
              mock.patch.object(gate, "ACCEPTED_D8_COUNT", len(self.old)),
              mock.patch.object(gate, "ACCEPTED_D8_SHA256", digest)):
            gate.check_complete_packages(pairs)
            gate.check_current_packages(pairs)

    def test_original_exact_set_survives(self):
        self.validate(self.old)
        self.validate_full_d9(self.old | self.extension)
        with self.assertRaises(ValueError):
            self.validate_full_d9(self.old)

    def test_only_reviewed_command_d9_extension_is_excluded(self):
        self.validate(self.old | {(gate.COMMAND, "TestCandidateD9LiveHTTPSProductBrowserFixture")})
        self.validate_full_d9(self.old | self.extension)
        # The older baseline may exclude reviewed D9 names; the new complete
        # baseline must not exclude a missing or substituted D9 scenario.
        with self.assertRaises(ValueError):
            self.validate_full_d9(self.old | {(gate.COMMAND, "TestCandidateD9Renamed")})

    def test_deleted_old_name_is_not_replaced_by_d9(self):
        with self.assertRaises(ValueError):
            self.validate((self.old - {(gate.COMMAND, "TestCandidateOld")}) | {(gate.COMMAND, "TestCandidateD9New")})
        with self.assertRaises(ValueError):
            self.validate_full_d9((self.old - {(gate.COMMAND, "TestCandidateOld")}) | self.extension)

    def test_same_count_old_name_substitution_fails(self):
        with self.assertRaises(ValueError):
            self.validate((self.old - {(gate.COMMAND, "TestCandidateOld")}) | {(gate.COMMAND, "TestCandidateRenamed")})
        with self.assertRaises(ValueError):
            self.validate_full_d9((self.old - {(gate.COMMAND, "TestCandidateOld")}) | self.extension | {(gate.COMMAND, "TestCandidateRenamed")})

    def test_wrong_package_d9_name_is_not_excluded(self):
        for package in (gate.ROOT, gate.PRODUCT):
            with self.subTest(package=package), self.assertRaises(ValueError):
                self.validate(self.old | {(package, "TestCandidateD9New")})
            with self.subTest(package=package, full_d9=True), self.assertRaises(ValueError):
                self.validate_full_d9(self.old | self.extension | {(package, "TestCandidateD9New")})

    def test_unreviewed_command_prefix_is_not_excluded(self):
        with self.assertRaises(ValueError):
            self.validate(self.old | {(gate.COMMAND, "TestCandidateD10Unreviewed")})
        with self.assertRaises(ValueError):
            self.validate_full_d9(self.old | self.extension | {(gate.COMMAND, "TestCandidateD10Unreviewed")})


class D12RejectionExtensionTests(unittest.TestCase):
    """Exact synthetic run sets; no Go/runtime/cryptographic acceptance claim."""

    old = D9BaselineScopeTests.old
    extension = D9BaselineScopeTests.extension

    def validate_pipeline(self, pairs):
        baseline = self.old | self.extension
        def digest(values):
            return hashlib.sha256("".join(package + "\t" + name + "\n" for package, name in sorted(values)).encode()).hexdigest()
        fingerprints = {package: (len(names := sorted(name for actual, name in baseline if actual == package)),
            hashlib.sha256("\n".join(names).encode()).hexdigest()) for package, _ in baseline}
        historical = ("check_baseline", "check_managed_baseline", "check_product_packages", "check_product_baseline",
                      "check_complete_packages", "check_current_packages")
        with contextlib.ExitStack() as stack:
            mocks = [stack.enter_context(mock.patch.object(gate, name)) for name in historical]
            stack.enter_context(mock.patch.object(gate, "D9_PACKAGE_FINGERPRINTS", fingerprints))
            stack.enter_context(mock.patch.object(gate, "ACCEPTED_D9_COUNT", len(baseline)))
            stack.enter_context(mock.patch.object(gate, "ACCEPTED_D9_SHA256", digest(baseline)))
            stack.enter_context(mock.patch.object(gate, "ACCEPTED_D9_NEW_COUNT", len(self.extension)))
            stack.enter_context(mock.patch.object(gate, "ACCEPTED_D9_NEW_SHA256", digest(self.extension)))
            stack.enter_context(mock.patch.object(gate, "D12_ORDINARY_COUNT", len(baseline) + 28))
            gate.check_ordinary_test_set(pairs)
            for checker in mocks: checker.assert_called_once_with(baseline)

    def test_closed_28_top_level_names_have_exact_reviewed_packages(self):
        self.assertEqual({package: len(names) for package, names in gate.D12_REQUIRED_TESTS.items()},
                         {gate.STATE: 8, gate.PRODUCT: 16, gate.COMMAND: 4})
        self.assertEqual(len(gate.D12_REQUIRED_PAIRS), 28)
        self.assertEqual(gate.D12_ORDINARY_COUNT, 728)
        self.assertTrue(all("/" not in name for _, name in gate.D12_REQUIRED_PAIRS))

    def test_only_closed_exact_pairs_are_excluded_before_all_old_checks(self):
        baseline = self.old | self.extension
        self.assertEqual(gate.split_d12_extension(baseline | gate.D12_REQUIRED_PAIRS), baseline)
        self.validate_pipeline(baseline | gate.D12_REQUIRED_PAIRS)

    def test_each_missing_new_pair_is_rejected(self):
        for pair in gate.D12_REQUIRED_PAIRS:
            with self.subTest(pair=pair), self.assertRaises(ValueError):
                gate.split_d12_extension((self.old | self.extension | gate.D12_REQUIRED_PAIRS) - {pair})

    def test_each_renamed_new_pair_is_rejected_even_with_same_count(self):
        for package, name in gate.D12_REQUIRED_PAIRS:
            changed = (self.old | self.extension | gate.D12_REQUIRED_PAIRS) - {(package, name)} | {(package, name + "Renamed")}
            with self.subTest(name=name), self.assertRaises(ValueError): gate.split_d12_extension(changed)

    def test_unknown_d12_prefixes_never_become_broad_exclusions(self):
        valid = self.old | self.extension | gate.D12_REQUIRED_PAIRS
        for package, name in ((gate.STATE, "TestProductTrustStateD12Unreviewed"),
                              (gate.PRODUCT, "TestProductD12Unreviewed"), (gate.COMMAND, "TestCandidateD12Unreviewed")):
            with self.subTest(name=name), self.assertRaises(ValueError): gate.split_d12_extension(valid | {(package, name)})

    def test_each_new_name_moved_to_another_package_is_rejected(self):
        valid = self.old | self.extension | gate.D12_REQUIRED_PAIRS
        for pair in gate.D12_REQUIRED_PAIRS:
            with self.subTest(pair=pair), self.assertRaises(ValueError):
                gate.split_d12_extension((valid - {pair}) | {(gate.ROOT, pair[1])})

    def test_swapped_packages_cannot_preserve_extension_authority(self):
        left, right = sorted(gate.D12_REQUIRED_PAIRS)[0], sorted(gate.D12_REQUIRED_PAIRS)[-1]
        changed = (self.old | self.extension | gate.D12_REQUIRED_PAIRS) - {left, right} | {(right[0], left[1]), (left[0], right[1])}
        with self.assertRaises(ValueError): gate.split_d12_extension(changed)

    def test_added_subtest_is_not_a_reviewed_top_level_test(self):
        valid = self.old | self.extension | gate.D12_REQUIRED_PAIRS
        package, name = sorted(gate.D12_REQUIRED_PAIRS)[0]
        for changed in (valid | {(package, name + "/extra")}, (valid - {(package, name)}) | {(package, name + "/extra")}):
            with self.assertRaises(ValueError): gate.split_d12_extension(changed)

    def test_old_deleted_or_same_count_substituted_pairs_still_fail(self):
        valid = self.old | self.extension | gate.D12_REQUIRED_PAIRS
        pair = sorted(self.old)[0]
        for changed in (valid - {pair}, (valid - {pair}) | {(pair[0], "TestOldSubstituted")}, valid | {(gate.ROOT, "TestExtraOld")}):
            with self.assertRaises(ValueError): self.validate_pipeline(changed)

    def test_new_runs_require_unique_matching_pass_and_no_skip(self):
        required = {package: set(names) for package, names in gate.D12_REQUIRED_TESTS.items()}
        required[gate.ROOT] = {"TestOldRoot"}
        events = gate.synthetic(required)
        name = sorted(gate.D12_REQUIRED_TESTS[gate.PRODUCT])[0]
        read = lambda values: gate.read_events(io.StringIO("".join(json.dumps(item) + "\n" for item in values)), required)
        read(events)
        for action in ("skip", "fail"):
            changed = [dict(item, Action=action) if item.get("Test") == name and item["Action"] == "pass" else item for item in events]
            with self.subTest(action=action), self.assertRaises(ValueError): read(changed)
        duplicate = next(item for item in events if item.get("Test") == name and item["Action"] == "pass")
        with self.assertRaises(ValueError): read(events + [duplicate])
        with self.assertRaises(ValueError): read([item for item in events if not(item.get("Test") == name and item["Action"] == "pass")])

    def test_historical_constants_and_fingerprints_are_not_recalibrated(self):
        self.assertEqual((gate.ACCEPTED_D9_COUNT, gate.ACCEPTED_D9_SHA256),
            (700, "b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999"))
        self.assertEqual((gate.ACCEPTED_D8_COUNT, gate.ACCEPTED_D8_SHA256),
            (669, "a55d7427fd64491017c7a0fe20756cac0051cfb426218d7082e0ccb83baeb4eb"))
        self.assertEqual(gate.D9_PACKAGE_FINGERPRINTS[gate.PRODUCT],
            (90, "a13f6e205758f8c73774c5a57d20408984a098847a50b6dd0d5a280945ff0b26"))
        self.assertEqual(gate.D9_PACKAGE_FINGERPRINTS[gate.COMMAND],
            (128, "21a7ea8e3b507f2af78d46ead04b2d4f9ad38da835d9ffe61d6b4a7466b6242e"))
        self.assertEqual(gate.D9_PACKAGE_FINGERPRINTS[gate.STATE],
            (68, "0aff387f31c7c7688b5552ecc887f38082a33ded00faf20c7256f9915dece155"))

    def test_registry_mode_cannot_import_ordinary_extension(self):
        events = gate.synthetic(gate.REQUIRED_REGISTRY)
        package = gate.ROOT; name = sorted(gate.D12_REQUIRED_TESTS[gate.COMMAND])[0]
        events[-1:-1] = [{"Action": "run", "Package": package, "Test": name}, {"Action": "pass", "Package": package, "Test": name}]
        with tempfile.TemporaryDirectory() as temporary:
            paths = [pathlib.Path(temporary) / name for name in ("ordinary.json", "race.json")]
            for path in paths: path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
            with mock.patch.object(sys, "argv", [str(source), "--mode", "registry", *map(str, paths)]), self.assertRaises(ValueError):
                gate.main()


class D9BrowserReportGateTests(unittest.TestCase):
    """Synthetic validator tests, not browser/TLS/screenshot acceptance evidence."""

    @classmethod
    def setUpClass(cls):
        shell = source.with_name("run-browser-gate.sh").read_text(encoding="utf-8")
        cls.program = shell.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        tree = ast.parse(cls.program)
        cls.checks = set()
        for statement in ast.walk(tree):
            if isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "required_checks" for target in statement.targets):
                cls.checks |= ast.literal_eval(statement.value)
            if isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name) and statement.target.id == "required_checks":
                cls.extra_checks = ast.literal_eval(statement.value)

    def exercise(self, https=True, mutate=None, secret_log=False, missing_marker=False):
        mode = "https" if https else "http"
        prefix = "trust-https-console-" if https else "trust-console-"
        report = {
            "schema": "chengwang.trust-console-browser-https/v1" if https else "chengwang.trust-console-browser/v1",
            "outcome": "PASS", "boundary": "ISOLATED_REAL_BROWSER_REAL_CANDIDATE",
            "authorization": "BLOCKED", "deviceActionsExecuted": False,
            "transport": "HTTPS_127_PRIVATE_NSS_NORMAL_VERIFICATION" if https else "HTTP_127_LOOPBACK_ONLY_NOT_BROWSER_TLS_ACCEPTANCE",
            "chromeSandbox": "DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED", "browserGroupStopped": True,
            "cjkFontVerified": True, "mockedResponses": False, "injectedFetch": False,
            "tlsBypass": False, "screenshotCount": 4,
            "cjkFonts": [{"family": "Noto Sans CJK SC", "postscript": "NotoSansCJKsc-Bold", "glyphCount": 7, "custom": False}],
            "checks": sorted(self.checks | (self.extra_checks if https else set())),
            "httpStatusCounts": {"200": 1, "401": 1, "403": 1},
            "runtimeErrors": 0, "cspErrors": 0, "assetErrors": 0, "forbiddenRequests": 0,
            "consoleErrors": 0, "consoleWarnings": 0,
        }
        if https:
            report.update({
                "normalTrust": {"method": "PRIVATE_NSS_SQL_LOCAL_CA", "legacyDatabaseAbsent": True,
                                "trustFlags": "C,,", "tool": "preinstalled-certutil", "caSHA256": "a" * 64, "leafSHA256": "b" * 64},
                "tls": {"securityState": "secure", "protocol": "TLS 1.3", "cipher": "AES_128_GCM",
                        "leafSHA256": "b" * 64, "caSHA256": "a" * 64, "serverChainLength": 2,
                        "leafSignatureVerified": True, "ipSANVerified": True},
                "negativeTLS": [{"kind": kind, "error": error, "businessMounted": False,
                                 "httpResponses": 0, "apiRequests": 0, "authorizationHeaders": 0}
                                for kind, error in (("untrusted", "net::ERR_CERT_AUTHORITY_INVALID"),
                                                    ("wrong-san", "net::ERR_CERT_COMMON_NAME_INVALID"),
                                                    ("expired", "net::ERR_CERT_DATE_INVALID"))],
                "parentAPI": {"operationsStatus": 200, "capabilitiesStatus": 200},
            })
        if mutate:
            mutate(report)
        marker = ("CANDIDATE_D9_HTTPS_PRODUCT_FIXTURE=PASS actual_product_runtime=true shared_audit=true journal=22 audit=44 readonly=true negative_http=0 authorization=BLOCKED" if https else
                  "CANDIDATE_D8_UI_FIXTURE=PASS actual_candidate=true journal=22 audit=44 readonly=true authorization=BLOCKED")
        with tempfile.TemporaryDirectory(prefix="chengwang-d9-report-test-") as temporary:
            root = pathlib.Path(temporary)
            ready = {name: "synthetic-not-an-identity-" + name for name in ("auditorToken", "viewerToken", "wrongToken")}
            (root / "ready.private.json").write_text(json.dumps(ready), encoding="utf-8")
            log = "no marker" if missing_marker else marker
            if secret_log:
                log += "\n" + ready["auditorToken"]
            (root / "fixture.private.log").write_text(log, encoding="utf-8")
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / ("trust-https-browser-report.json" if https else "trust-browser-report.json")).write_text(json.dumps(report), encoding="utf-8")
            for index in range(4):
                (evidence / (prefix + str(index) + ".png")).write_bytes(b"\x89PNG\r\n\x1a\n")
            result = subprocess.run([sys.executable, "-B", "-", str(root / "ready.private.json"),
                                     str(root / "fixture.private.log"), str(evidence), "0", "0", mode],
                                    input=self.program, text=True, capture_output=True, timeout=10, check=False)
            if secret_log:
                self.assertFalse((evidence / "browser-https-fixture.log").exists(), "credential-bearing private log was exported")
            return result.returncode

    def test_old_http_contract_still_passes(self):
        self.assertEqual(self.exercise(https=False), 0)

    def test_https_complete_report_passes(self):
        self.assertEqual(self.exercise(), 0)

    def test_http_cannot_be_claimed_as_https(self):
        self.assertNotEqual(self.exercise(mutate=lambda report: report.update(transport="HTTP_127_LOOPBACK_ONLY_NOT_BROWSER_TLS_ACCEPTANCE")), 0)

    def test_https_leaf_must_match_private_trust(self):
        self.assertNotEqual(self.exercise(mutate=lambda report: report["tls"].update(leafSHA256="c" * 64)), 0)

    def test_every_negative_must_stop_before_http(self):
        self.assertNotEqual(self.exercise(mutate=lambda report: report["negativeTLS"][1].update(httpResponses=1)), 0)

    def test_missing_certificate_failure_is_rejected(self):
        self.assertNotEqual(self.exercise(mutate=lambda report: report["negativeTLS"].pop()), 0)

    def test_complete_parent_api_evidence_is_required(self):
        self.assertNotEqual(self.exercise(mutate=lambda report: report.update(parentAPI=None)), 0)
        for field in ("consoleErrors", "consoleWarnings"):
            for value in (1, False, "0", None):
                with self.subTest(field=field, value=value):
                    self.assertNotEqual(self.exercise(mutate=lambda report: report.update({field: value})), 0)

    def test_secret_log_is_withheld(self):
        self.assertNotEqual(self.exercise(secret_log=True), 0)

    def test_fixture_readonly_completion_is_required(self):
        self.assertNotEqual(self.exercise(missing_marker=True), 0)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    passed = result.wasSuccessful() and not result.skipped and result.testsRun == 27
    if passed:
        print("D9_BINDING_GATE_TESTS=PASS tests=27 old_baseline_preserved=true scoped_extensions_only=true synthetic_report_validation=true")
    raise SystemExit(0 if passed else 1)
