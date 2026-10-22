#!/usr/bin/env python3
"""Exercise scoped D9 extension without requiring or mutating real Go inputs."""
import ast
import hashlib
import importlib.util
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

    def test_only_reviewed_command_d9_extension_is_excluded(self):
        self.validate(self.old | {(gate.COMMAND, "TestCandidateD9LiveHTTPSProductBrowserFixture")})

    def test_deleted_old_name_is_not_replaced_by_d9(self):
        with self.assertRaises(ValueError):
            self.validate((self.old - {(gate.COMMAND, "TestCandidateOld")}) | {(gate.COMMAND, "TestCandidateD9New")})

    def test_same_count_old_name_substitution_fails(self):
        with self.assertRaises(ValueError):
            self.validate((self.old - {(gate.COMMAND, "TestCandidateOld")}) | {(gate.COMMAND, "TestCandidateRenamed")})

    def test_wrong_package_d9_name_is_not_excluded(self):
        for package in (gate.ROOT, gate.PRODUCT):
            with self.subTest(package=package), self.assertRaises(ValueError):
                self.validate(self.old | {(package, "TestCandidateD9New")})

    def test_unreviewed_command_prefix_is_not_excluded(self):
        with self.assertRaises(ValueError):
            self.validate(self.old | {(gate.COMMAND, "TestCandidateD10Unreviewed")})


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

    def test_secret_log_is_withheld(self):
        self.assertNotEqual(self.exercise(secret_log=True), 0)

    def test_fixture_readonly_completion_is_required(self):
        self.assertNotEqual(self.exercise(missing_marker=True), 0)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    passed = result.wasSuccessful() and not result.skipped and result.testsRun == 15
    if passed:
        print("D9_BINDING_GATE_TESTS=PASS tests=15 old_baseline_preserved=true scoped_extensions_only=true synthetic_report_validation=true")
    raise SystemExit(0 if passed else 1)
