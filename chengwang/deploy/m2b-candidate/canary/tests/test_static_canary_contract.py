import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
MODULE_DIR = HERE.parent
sys.path.insert(0, str(MODULE_DIR))
import static_canary_contract as subject  # noqa: E402


NOW = 2_000_000_000
HASH_A = "a" * 64
HASH_B = "b" * 64


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def catalog(two=False):
    probes = [{
        "id": "owned-a", "pathId": "direct", "kind": "https", "host": "canary-a.example.com",
        "allowedCNAMEs": ["edge.shared.example.net"], "port": 443, "requestPath": "/healthz",
        "method": "GET", "expectedStatus": [200], "requiredMarker": "chengwang-canary-ok-a",
        "intervalSeconds": 300, "timeoutSeconds": 5, "ttlSeconds": 600, "maxBodyBytes": 4096,
    }]
    if two:
        probes.append({
            "id": "owned-b", "pathId": "direct", "kind": "https", "host": "canary-b.example.com",
            "allowedCNAMEs": ["edge.shared.example.net"], "port": 443, "requestPath": "/healthz",
            "method": "GET", "expectedStatus": [200], "requiredMarker": "chengwang-canary-ok-b",
            "intervalSeconds": 300, "timeoutSeconds": 5, "ttlSeconds": 600, "maxBodyBytes": 4096,
        })
    return {
        "schema": subject.CATALOG_SCHEMA, "revision": "test-v1",
        "agent": {"id": "probe-agent-candidate", "independence": "P1", "advisoryOnly": True},
        "paths": [{"id": "direct", "kind": "direct"}], "probes": probes,
    }


def canary(probe_id="owned-a", host="canary-a.example.com", marker="chengwang-canary-ok-a", address="8.8.8.8"):
    return {
        "probeId": probe_id, "queryName": host, "cnameChain": [host, "edge.shared.example.net"],
        "addresses": [address], "resolvedUnix": NOW - 100, "expiresUnix": NOW + 500,
        "ownership": {"mode": "operator-controlled", "owner": "network-team", "evidenceSha256": HASH_B},
        "tls": {"serverName": host, "verifyHostname": host, "certificateDNSNames": ["*.example.com"], "minimumVersion": "TLS1.2"},
        "http": {"method": "GET", "requestPath": "/healthz", "expectedStatus": [200], "requiredMarker": marker, "maxBodyBytes": 4096, "statusSemantics": "owned-canary-success-only"},
    }


def contract(cat, two=False):
    cat_raw = encoded(cat)
    entries = [canary()]
    if two:
        entries.append(canary("owned-b", "canary-b.example.com", "chengwang-canary-ok-b", "8.8.8.8"))
    return {
        "schema": subject.CONTRACT_SCHEMA, "revision": "test-v1", "issuedUnix": NOW - 200,
        "validFromUnix": NOW - 150, "validUntilUnix": NOW + 1000,
        "catalogSha256": hashlib.sha256(cat_raw).hexdigest(),
        "approval": {"status": "approved", "owner": "network-team", "approvedUnix": NOW - 175, "evidenceSha256": HASH_A},
        "canaries": entries,
    }, cat_raw


class ValidationTests(unittest.TestCase):
    def valid(self, two=False):
        cat = catalog(two)
        value, cat_raw = contract(cat, two)
        return value, encoded(value), cat, cat_raw

    def test_valid_contract_is_explicitly_blocked(self):
        value, raw, cat, cat_raw = self.valid()
        report = subject.validate_contract(value, raw, cat, cat_raw, NOW)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["acceptedStartEvidenceEmitted"])
        self.assertEqual(report["addressFamilies"], ["ipv4"])

    def test_ipv6_is_supported(self):
        value, _, cat, cat_raw = self.valid()
        value["canaries"][0]["addresses"] = ["2606:4700:4700::1111"]
        report = subject.validate_contract(value, encoded(value), cat, cat_raw, NOW)
        self.assertEqual(report["addressFamilies"], ["ipv6"])

    def test_shared_cdn_ip_is_reported_not_rejected(self):
        value, raw, cat, cat_raw = self.valid(two=True)
        report = subject.validate_contract(value, raw, cat, cat_raw, NOW)
        self.assertEqual(report["sharedAddresses"], [{"address": "8.8.8.8", "probeIds": ["owned-a", "owned-b"]}])

    def assert_rejected(self, mutate, text):
        value, _, cat, cat_raw = self.valid()
        mutate(value, cat)
        with self.assertRaisesRegex(subject.ContractError, text):
            subject.validate_contract(value, encoded(value), cat, cat_raw, NOW)

    def test_duplicate_probe_rejected(self):
        value, _, cat, cat_raw = self.valid(two=True)
        value["canaries"][1]["probeId"] = "owned-a"
        with self.assertRaisesRegex(subject.ContractError, "unknown or duplicated"):
            subject.validate_contract(value, encoded(value), cat, cat_raw, NOW)

    def test_stale_contract_rejected(self):
        self.assert_rejected(lambda v, c: v.update(validUntilUnix=NOW), "stale")

    def test_future_contract_rejected(self):
        self.assert_rejected(lambda v, c: v.update(validFromUnix=NOW + 1), "future")

    def test_future_approval_rejected(self):
        self.assert_rejected(lambda v, c: v["approval"].update(approvedUnix=NOW + 1), "approval time")

    def test_future_resolution_rejected(self):
        def mutate(v, _):
            v["canaries"][0].update(resolvedUnix=NOW + 1, expiresUnix=NOW + 601)
        self.assert_rejected(mutate, "resolution")

    def test_expired_resolution_rejected(self):
        self.assert_rejected(lambda v, c: v["canaries"][0].update(expiresUnix=NOW), "resolution")

    def test_resolution_ttl_mismatch_rejected(self):
        self.assert_rejected(lambda v, c: v["canaries"][0].update(expiresUnix=NOW + 499), "TTL")

    def test_cname_loop_rejected(self):
        self.assert_rejected(lambda v, c: v["canaries"][0].update(cnameChain=["canary-a.example.com", "canary-a.example.com"]), "loop")

    def test_unapproved_cname_rejected(self):
        self.assert_rejected(lambda v, c: v["canaries"][0].update(cnameChain=["canary-a.example.com", "evil.example.net"]), "allowlist")

    def test_duplicate_address_rejected(self):
        self.assert_rejected(lambda v, c: v["canaries"][0].update(addresses=["8.8.8.8", "8.8.8.8"]), "duplicate address")

    def test_private_and_special_addresses_rejected(self):
        for address in (
            "0.0.0.0", "::", "10.0.0.1", "127.0.0.1", "::1",
            "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1",
            "240.0.0.1", "2001:db8::1", "169.254.169.254",
            "192.0.2.1", "::ffff:8.8.8.8",
        ):
            with self.subTest(address=address):
                self.assert_rejected(lambda v, c, a=address: v["canaries"][0].update(addresses=[a]), "address")

    def test_catalog_numeric_fields_are_strict_integers(self):
        mutations = (
            lambda c: c["probes"][0].update(port=True),
            lambda c: c["probes"][0].update(intervalSeconds=300.0),
            lambda c: c["probes"][0].update(timeoutSeconds="5"),
            lambda c: c["probes"][0].update(ttlSeconds=False),
            lambda c: c["probes"][0].update(maxBodyBytes=4096.0),
            lambda c: c["probes"][0].update(expectedStatus=[200.0]),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value, _, cat, cat_raw = self.valid()
                mutation(cat)
                with self.assertRaises(subject.ContractError):
                    subject.validate_contract(value, encoded(value), cat, cat_raw, NOW)

    def test_catalog_numeric_ranges_and_ttl_relationship_are_enforced(self):
        for field, value in (("intervalSeconds", 29), ("timeoutSeconds", 11), ("ttlSeconds", 299), ("maxBodyBytes", 65537)):
            with self.subTest(field=field):
                self.assert_rejected(lambda v, c, f=field, x=value: c["probes"][0].update({f: x}), "outside probe bounds")

    def test_contract_and_runtime_numeric_fields_reject_bool_or_float(self):
        self.assert_rejected(lambda v, c: v.update(issuedUnix=True), "integer")
        self.assert_rejected(lambda v, c: v["canaries"][0].update(resolvedUnix=float(NOW - 100)), "integer")
        self.assert_rejected(lambda v, c: v["canaries"][0]["http"].update(maxBodyBytes=True), "integer")
        self.assert_rejected(lambda v, c: v["canaries"][0]["http"].update(expectedStatus=[200.0]), "integer")

    def test_certificate_must_cover_hostname(self):
        self.assert_rejected(lambda v, c: v["canaries"][0]["tls"].update(certificateDNSNames=["*.other.example"]), "do not cover")

    def test_wildcard_matches_only_one_label(self):
        self.assert_rejected(lambda v, c: v["canaries"][0]["tls"].update(certificateDNSNames=["*.com"]), "invalid DNS label")

    def test_tls_server_name_must_match_catalog(self):
        self.assert_rejected(lambda v, c: v["canaries"][0]["tls"].update(serverName="other.example.com"), "TLS hostname")

    def test_http_403_cannot_be_success(self):
        self.assert_rejected(lambda v, c: v["canaries"][0]["http"].update(expectedStatus=[403]), "expected status")

    def test_http_marker_must_match_catalog(self):
        self.assert_rejected(lambda v, c: v["canaries"][0]["http"].update(requiredMarker="wrong"), "marker")

    def test_control_character_marker_rejected(self):
        def mutate(v, c):
            c["probes"][0]["requiredMarker"] = "ok\nforged"
            v["canaries"][0]["http"]["requiredMarker"] = "ok\nforged"
        self.assert_rejected(mutate, "control character")

    def test_http_path_with_query_rejected_even_when_catalog_matches(self):
        def mutate(v, c):
            c["probes"][0]["requestPath"] = "/healthz?debug=1"
            v["canaries"][0]["http"]["requestPath"] = "/healthz?debug=1"
        self.assert_rejected(mutate, "query")

    def test_canary_owner_must_match_approval(self):
        self.assert_rejected(lambda v, c: v["canaries"][0]["ownership"].update(owner="other-team"), "differs")

    def test_catalog_digest_must_match_raw_bytes(self):
        self.assert_rejected(lambda v, c: v.update(catalogSha256="f" * 64), "SHA-256 mismatch")

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory).resolve() / "duplicate.json"
            path.write_text('{"schema":1,"schema":2}', encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)
            with self.assertRaisesRegex(subject.ContractError, "duplicate JSON key"):
                subject.load_immutable_json(path)

    def test_duplicate_lone_surrogate_key_is_controlled_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory).resolve() / "duplicate-surrogate.json"
            path.write_bytes(b'{"\\ud800":1,"\\ud800":2}')
            if os.name == "posix":
                path.chmod(0o600)
            with self.assertRaisesRegex(subject.ContractError, "^duplicate JSON key$"):
                subject.load_immutable_json(path)

    def test_non_standard_json_numbers_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory).resolve() / "constant.json"
                path.write_text('{"value":' + constant + '}', encoding="utf-8")
                if os.name == "posix":
                    path.chmod(0o600)
                with self.assertRaisesRegex(subject.ContractError, "non-standard"):
                    subject.load_immutable_json(path)

    def test_excessive_json_nesting_is_controlled_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory).resolve() / "deep.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)
            with self.assertRaisesRegex(subject.ContractError, "nesting"):
                subject.load_immutable_json(path)

    def test_lone_surrogate_text_is_controlled_failure(self):
        with self.assertRaisesRegex(subject.ContractError, "valid Unicode"):
            subject._text("\ud800", "test")

    def test_hard_link_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            original, linked = root / "original.json", root / "linked.json"
            original.write_text("{}", encoding="utf-8")
            try:
                os.link(original, linked)
            except OSError:
                self.skipTest("hard links are unavailable")
            with self.assertRaisesRegex(subject.ContractError, "single-link"):
                subject.load_immutable_json(original)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and mode behavior")
    def test_group_writable_or_executable_input_rejected(self):
        for mode in (0o660, 0o700):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory).resolve() / "input.json"
                path.write_text("{}", encoding="utf-8")
                path.chmod(mode)
                with self.assertRaisesRegex(subject.ContractError, "mode|writable"):
                    subject.load_immutable_json(path)

    def test_second_read_digest_mismatch_rejected(self):
        fingerprint = (1, 2, 3, 1, 2, 4, 5)
        with mock.patch.object(subject, "_read_immutable_once", side_effect=[(b"{}", fingerprint), (b"[]", fingerprint)]):
            with self.assertRaisesRegex(subject.ContractError, "between verification reads"):
                subject.load_immutable_json(pathlib.Path.cwd() / "synthetic.json")

    def test_symlink_input_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            target = root / "target.json"
            link = root / "link.json"
            target.write_text("{}", encoding="utf-8")
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(subject.ContractError, "non-symlink"):
                subject.load_immutable_json(link)

    def test_symlink_directory_component_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            real = root / "real"
            link = root / "link"
            real.mkdir()
            (real / "input.json").write_text("{}", encoding="utf-8")
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable")
            with self.assertRaisesRegex(subject.ContractError, "symbolic link"):
                subject.load_immutable_json(link / "input.json")

    def test_atomic_output_refuses_clobber(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve() / "report.json"
            subject.atomic_publish_new(output, b"first")
            with self.assertRaisesRegex(subject.ContractError, "must not exist"):
                subject.atomic_publish_new(output, b"second")
            self.assertEqual(output.read_bytes(), b"first")

    @unittest.skipUnless(os.name == "posix", "POSIX directory fsync behavior")
    def test_post_link_fsync_failure_removes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory).resolve() / "report.json"
            real_fsync = os.fsync
            calls = 0

            def fail_second(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated directory fsync failure")
                return real_fsync(descriptor)

            with mock.patch.object(subject.os, "fsync", side_effect=fail_second):
                with self.assertRaises(OSError):
                    subject.atomic_publish_new(output, b"blocked")
            self.assertFalse(output.exists())

    def test_cli_writes_blocked_report_and_exits_78(self):
        current = int(time.time())
        cat = catalog()
        value, _ = contract(cat)
        value.update(issuedUnix=current - 200, validFromUnix=current - 150, validUntilUnix=current + 1000)
        value["approval"]["approvedUnix"] = current - 175
        value["canaries"][0].update(resolvedUnix=current - 100, expiresUnix=current + 500)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            contract_path, catalog_path, output = root / "contract.json", root / "catalog.json", root / "report.json"
            catalog_path.write_bytes(encoded(cat))
            value["catalogSha256"] = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
            contract_path.write_bytes(encoded(value))
            if os.name == "posix":
                os.chmod(catalog_path, 0o600)
                os.chmod(contract_path, 0o600)
            process = subprocess.run(
                [sys.executable, str(MODULE_DIR / "static_canary_contract.py"), "validate", "--contract", str(contract_path), "--catalog", str(catalog_path), "--output", str(output)],
                capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False,
            )
            self.assertEqual(process.returncode, subject.BLOCKED_EXIT, process.stderr)
            self.assertEqual(process.stderr, "")
            self.assertEqual(process.stdout, "CANARY_CONTRACT=VALIDATED_BUT_BLOCKED\n")
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "BLOCKED")
            self.assertFalse(report["acceptedStartEvidenceEmitted"])
            self.assertTrue(any("cryptographically verified" in item for item in report["unresolvedBlockers"]))
            if os.name != "posix":
                self.assertEqual(report["filesystemAssurance"], "non-posix-best-effort-blocked")
                self.assertTrue(any("Windows chmod" in item for item in report["unresolvedBlockers"]))


if __name__ == "__main__":
    unittest.main()
