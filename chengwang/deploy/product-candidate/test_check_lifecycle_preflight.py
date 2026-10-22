"""Synthetic rejection checks for the prerequisite transcript verifier only."""
import unittest

import check_lifecycle_preflight as check


SOURCE = b"import unittest\nclass Sample(unittest.TestCase):\n def test_alpha(self): pass\n def test_beta(self): pass\n"
LOG = ("test_alpha (__main__.Sample.test_alpha) ... ok\n"
       "test_beta (__main__.Sample.test_beta) ... ok\n"
       "\n----------------------------------------------------------------------\n"
       "Ran 2 tests in 0.123s\n\nOK\n"
       "D12_LEASE_TESTS=PASS tests=2 passed=2 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none\n").encode()


class TranscriptTests(unittest.TestCase):
    def reject(self, raw, source=SOURCE):
        with self.assertRaises((check.Rejected, UnicodeDecodeError)):
            check.verify_transcript(raw, source, "lease")

    def test_exact_names_and_raw_hashes(self):
        result = check.verify_transcript(LOG, SOURCE, "lease")
        self.assertEqual((result["tests"], result["passed"], result["skipped"]), (2, 2, 0))
        self.assertEqual(result["transcriptSHA256"], check.hashlib.sha256(LOG).hexdigest())

    def test_marker_alone_is_not_proof(self):
        self.reject(LOG.splitlines()[-1])

    def test_missing_named_test(self):
        self.reject(LOG.replace(b"test_beta (__main__.Sample.test_beta) ... ok\n", b""))

    def test_duplicate_named_test(self):
        self.reject(LOG + LOG.splitlines()[0] + b"\n")

    def test_renamed_or_mismatched_test(self):
        self.reject(LOG.replace(b"Sample.test_beta", b"Sample.test_gamma"))

    def test_skipped_real_linux_test_rejected(self):
        self.reject(LOG.replace(b"... ok", b"... skipped 'Linux required'", 1))

    def test_failure_or_error_or_unexpected_output_rejected(self):
        for bad in (b"FAIL", b"ERROR", b"warning", b"private arbitrary text"):
            with self.subTest(label=bad):
                self.reject(LOG + bad + b"\n")

    def test_count_forgery_and_duplicate_summary(self):
        self.reject(LOG.replace(b"Ran 2 tests", b"Ran 1 test"))
        self.reject(LOG + b"OK\n")
        self.reject(LOG + b"Ran 2 tests in 0.1s\n")

    def test_auxiliary_marker_cannot_pass(self):
        self.reject(LOG.replace(b"D12_LEASE_TESTS", b"D12_LEASE_AUXILIARY_TESTS"))
        self.reject(LOG.replace(b"real_linux=true", b"real_linux=false"))

    def test_new_source_test_cannot_be_omitted(self):
        self.reject(LOG, SOURCE + b" def test_added(self): pass\n")

    def test_empty_test_source_and_escape_output_rejected(self):
        self.reject(LOG, b"pass\n")
        self.reject(b"\x1b[32m" + LOG)
        self.reject(b"\xff" + LOG)

    def test_exact_cleanup_required(self):
        value = {"schema": "chengwang.product-lifecycle-preflight-cleanup/v1",
                 "privateTreeRemoved": True, "testExitCode": 0,
                 "hostTmpTouched": False, "parentMountNamespaceChanged": False,
                 "production": False, "authorization": "BLOCKED", "deviceActionsExecuted": False}
        raw = check.json.dumps(value).encode()
        self.assertTrue(check.verify_cleanup(raw)["privateTreeRemoved"])
        for key, bad in (("privateTreeRemoved", False), ("testExitCode", 1),
                         ("testExitCode", False), ("hostTmpTouched", True),
                         ("parentMountNamespaceChanged", True), ("authorization", "ALLOWED")):
            with self.subTest(key=key), self.assertRaises(check.Rejected):
                check.verify_cleanup(check.json.dumps({**value, key: bad}).encode())

    def test_extra_missing_and_duplicate_cleanup_fields_rejected(self):
        value = {"schema": "chengwang.product-lifecycle-preflight-cleanup/v1",
                 "privateTreeRemoved": True, "testExitCode": 0,
                 "hostTmpTouched": False, "parentMountNamespaceChanged": False,
                 "production": False, "authorization": "BLOCKED", "deviceActionsExecuted": False}
        for bad in ({**value, "extra": True}, {key: val for key, val in value.items() if key != "production"}):
            with self.assertRaises(check.Rejected):
                check.verify_cleanup(check.json.dumps(bad).encode())
        raw = check.json.dumps(value).encode()
        with self.assertRaises(check.Rejected):
            check.verify_cleanup(raw[:-1] + b',"privateTreeRemoved":true}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
