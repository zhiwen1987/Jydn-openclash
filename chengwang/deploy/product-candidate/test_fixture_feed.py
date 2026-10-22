"""D12 feed fixture tests. These do not attest product automatic refresh."""
from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import unittest
import uuid

import fixture_feed as feed


HERE = pathlib.Path(__file__).resolve().parent
SOURCE = (HERE / "fixture_feed.py").read_bytes()


def remove_fixture_root(root):
    resolved = root.resolve()
    if resolved.parent != pathlib.Path("/tmp") or not feed.FIXTURE_ID.fullmatch(str(resolved)) or resolved != root:
        raise RuntimeError("refusing fixture cleanup outside its exact temporary root")
    shutil.rmtree(resolved)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def decode_event_lines(raw):
    if not raw:
        return []
    if len(raw) > 8 << 20 or not raw.endswith(b"\n"):
        raise ValueError("incomplete bounded event log")
    values = []
    for line in raw.decode("utf-8").splitlines():
        value = json.loads(line, object_pairs_hook=feed.unique_object)
        if type(value) is not dict:
            raise ValueError("invalid event log shape")
        values.append(value)
    return values


def plan(epoch=1, body=b'{"generation":1}\n', *, one_shot=False):
    value = {"schema": feed.PLAN_SCHEMA, "epoch": epoch, "responses": {
        "latest.json": {"status": 200, "bodySHA256": feed.sha(body)}}}
    if one_shot:
        value["oneShot"] = True
    return value


class MemoryFiles:
    """Pure shape harness; not filesystem or real TLS acceptance."""

    def __init__(self, value=None, body=b'{"generation":1}\n'):
        self.values = {"plan.json": encoded(plan(body=body) if value is None else value),
                       feed.sha(body) + ".json": body}

    def audit_entries(self):
        pass

    def read(self, name, limit, body=False):
        value = self.values[name]
        if not 0 < len(value) <= limit:
            raise feed.Rejected("security-invalid")
        return value


class ShapeTests(unittest.TestCase):
    def test_plan_only_exact_fields_and_optional_boolean_one_shot(self):
        self.assertEqual(feed.parse_plan(encoded(plan()))["epoch"], 1)
        self.assertTrue(feed.parse_plan(encoded(plan(one_shot=True)))["oneShot"])
        for mutate in (lambda v: v.update(extra=True), lambda v: v.pop("schema"),
                       lambda v: v.update(oneShot=1), lambda v: v.update(responses=[])):
            value = plan()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(feed.Rejected):
                feed.parse_plan(encoded(value))

    def test_duplicate_fields_and_non_json_numbers_rejected(self):
        samples = [b'{"schema":"x","schema":"y"}',
                   encoded(plan()).replace(b'"epoch":1', b'"epoch":1,"epoch":1'),
                   encoded(plan()).replace(b'"status":200', b'"status":200,"status":200'),
                   encoded(plan()).replace(b'"epoch":1', b'"epoch":NaN'),
                   encoded(plan()) + b'{}', b'\xef\xbb\xbf' + encoded(plan()), b'\xff']
        for raw in samples:
            with self.subTest(sample=feed.sha(raw)), self.assertRaises(feed.Rejected):
                feed.parse_plan(raw)

    def test_epoch_is_canonical_positive_bounded_integer(self):
        for value in (0, -1, True, 1.0, "1", None, feed.UINT64 + 1):
            candidate = plan()
            candidate["epoch"] = value
            with self.subTest(epoch=value), self.assertRaises(feed.Rejected):
                feed.parse_plan(encoded(candidate))
        self.assertEqual(feed.parse_plan(encoded(plan(feed.UINT64)))["epoch"], feed.UINT64)

    def test_only_latest_and_canonical_generation_names(self):
        for name in ("0.json", "01.json", "-1.json", "1e2.json", "1.json?x", "../1.json",
                     "LATEST.json", "1%2ejson", str(feed.UINT64 + 1) + ".json", "a/1.json"):
            candidate = plan()
            candidate["responses"] = {name: {"status": 503, "bodySHA256": ""}}
            with self.subTest(name=name), self.assertRaises(feed.Rejected):
                feed.parse_plan(encoded(candidate))
        candidate = plan()
        candidate["responses"][str(feed.UINT64) + ".json"] = {"status": 503, "bodySHA256": ""}
        feed.parse_plan(encoded(candidate))

    def test_response_status_and_digest_shapes(self):
        for response in ({"status": True, "bodySHA256": ""}, {"status": 404, "bodySHA256": ""},
                         {"status": 200, "bodySHA256": ""}, {"status": 200, "bodySHA256": "A" * 64},
                         {"status": 503, "bodySHA256": "a" * 64},
                         {"status": 200, "bodySHA256": "a" * 64, "body": "not-allowed"}):
            candidate = plan()
            candidate["responses"]["latest.json"] = response
            with self.subTest(response=response), self.assertRaises(feed.Rejected):
                feed.parse_plan(encoded(candidate))

    def test_plan_size_utf8_and_deep_json_are_bounded(self):
        for raw in (b"", b" " * (feed.MAX_PLAN + 1), b"[" * 1100 + b"]" * 1100):
            with self.assertRaises(feed.Rejected):
                feed.parse_plan(raw)

    def test_target_classification_never_normalizes_untrusted_paths(self):
        self.assertEqual(feed.classify_target("/feed/latest.json"), ("latest", 0, "latest.json"))
        self.assertEqual(feed.classify_target("/feed/23.json"), ("generation", 23, "23.json"))
        for target in ("//feed/latest.json", "/feed/../latest.json", "/feed/%6catest.json",
                       "/feed/latest.json?secret=private", "/feed/latest.json#x", "/feed/01.json",
                       "https://feed.fixture.invalid/feed/latest.json", "/feed/latest.json/", "/FEED/latest.json"):
            with self.subTest(target=target):
                self.assertEqual(feed.classify_target(target), ("invalid", 0, ""))

    def test_cli_closed_shape_and_bounded_canonical_decimal(self):
        base = ["serve", "--fixture-root", "/tmp/chengwang-product-lifecycle-" + "a" * 32,
                "--case", "shape", "--kind", "dsse", "--port", "15443"]
        self.assertEqual(feed.arguments(base).deadline_seconds, 300)
        self.assertEqual(feed.arguments(base + ["--deadline-seconds", "1"]).deadline_seconds, 1)
        for extra in (["--deadline-seconds", "0"], ["--deadline-seconds", "060"],
                      ["--deadline-seconds", "601"], ["--unknown", "secret"]):
            with self.assertRaises(feed.Rejected):
                feed.arguments(base + extra)
        for raw in ("0", "+1", "01", " 1", "1.0", "65536", "1023"):
            candidate = base[:-1] + [raw]
            with self.subTest(port=raw), self.assertRaises(feed.Rejected):
                feed.arguments(candidate)

    def test_same_epoch_raw_changes_and_epoch_rollback_rejected(self):
        files, state = MemoryFiles(), feed.PlanState()
        self.assertEqual(state.choose(files, "latest.json")[1], "ok")
        files.values["plan.json"] += b"\n"
        self.assertEqual(state.choose(files, "latest.json")[1], "epoch-conflict")
        files.values["plan.json"] = encoded(plan(2))
        self.assertEqual(state.choose(files, "latest.json")[1], "ok")
        files.values["plan.json"] = encoded(plan(1))
        self.assertEqual(state.choose(files, "latest.json")[1], "epoch-rollback")

    def test_one_shot_is_atomic_per_epoch_and_path(self):
        candidate = plan(one_shot=True)
        candidate["responses"]["2.json"] = copy.deepcopy(candidate["responses"]["latest.json"])
        files, state = MemoryFiles(candidate), feed.PlanState()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            reasons = list(workers.map(lambda _: state.choose(files, "latest.json")[1], range(8)))
        self.assertEqual(reasons.count("ok"), 1)
        self.assertEqual(reasons.count("one-shot-exhausted"), 7)
        self.assertEqual(state.choose(files, "2.json")[1], "ok")
        candidate["epoch"] = 2
        files.values["plan.json"] = encoded(candidate)
        self.assertEqual(state.choose(files, "latest.json")[1], "ok")

    def test_rejected_request_does_not_consume_one_shot(self):
        files, state = MemoryFiles(plan(one_shot=True)), feed.PlanState()
        self.assertEqual(state.choose(files, "latest.json", "auth-present")[1], "auth-present")
        self.assertEqual(state.choose(files, "latest.json")[1], "ok")

    def test_body_real_hash_and_size_are_checked(self):
        files, state = MemoryFiles(), feed.PlanState()
        name = next(name for name in files.values if name != "plan.json")
        files.values[name] = b"different"
        self.assertEqual(state.choose(files, "latest.json")[1], "body-mismatch")
        files.values[name] = b"x" * (feed.MAX_BODY + 1)
        self.assertEqual(state.choose(files, "latest.json")[1], "body-unavailable")

    def test_fixed_error_body_is_independent_of_plan_input(self):
        candidate = plan()
        candidate["responses"]["latest.json"] = {"status": 503, "bodySHA256": ""}
        epoch, reason, body = feed.PlanState().choose(MemoryFiles(candidate), "latest.json")
        self.assertEqual((epoch, reason, body), (1, "planned-unavailable", feed.ERROR_BODY))
        self.assertNotIn(b"latest", body)

    def test_bad_or_incomplete_event_log_is_not_zero_http_evidence(self):
        self.assertEqual(decode_event_lines(b""), [])
        for raw in (b"{", b"\n", b"[]\n", b"\xff\n", b'{"ordinal":1,"ordinal":2}\n'):
            with self.subTest(sample=feed.sha(raw)), self.assertRaises(ValueError):
                decode_event_lines(raw)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux real TLS/setpriv tests; auxiliary platform only")
class LinuxRealFeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("Linux feed tests require the root orchestrator; skipping is forbidden")
        for command in ("/usr/bin/openssl", "/usr/bin/setpriv"):
            if not pathlib.Path(command).is_file():
                raise RuntimeError("required Linux fixture tool is unavailable")
        cls.authority_root = pathlib.Path("/tmp/chengwang-product-lifecycle-" + uuid.uuid4().hex)
        cls.authority_root.mkdir(mode=0o700)
        cls.addClassCleanup(remove_fixture_root, cls.authority_root)
        cls.cert_root = cls.authority_root / "authority"
        cls.cert_root.mkdir(mode=0o700)
        cls.ca, cls.leaf, cls.key = cls.certificates("normal", "DNS:feed.fixture.invalid")
        cls.other_ca, _, _ = cls.certificates("other", "DNS:feed.fixture.invalid")
        cls.context = ssl.create_default_context(cafile=str(cls.ca))

    @classmethod
    def openssl(cls, *args, input=None):
        completed = subprocess.run(["/usr/bin/openssl", *map(str, args)], input=input,
                                   capture_output=True, timeout=10)
        if completed.returncode:
            raise RuntimeError("isolated OpenSSL fixture preparation failed")
        return completed.stdout

    @classmethod
    def certificates(cls, name, san):
        directory = cls.cert_root / name
        directory.mkdir(mode=0o700)
        ca, ca_key = directory / "ca.pem", directory / "ca-key.pem"
        leaf, key, csr = directory / "leaf.pem", directory / "leaf-key.pem", directory / "leaf.csr"
        extension = directory / "extension.cnf"
        extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                             "extendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n")
        cls.openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-days", "2", "-sha256", "-subj", "/CN=Isolated D12 fixture CA",
                    "-keyout", ca_key, "-out", ca)
        cls.openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-sha256", "-subj", "/CN=feed.fixture.invalid", "-keyout", key, "-out", csr)
        cls.openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                    "-set_serial", "1", "-days", "2", "-sha256", "-extfile", extension, "-out", leaf)
        return ca, leaf, key

    def setUp(self):
        self.root = pathlib.Path("/tmp/chengwang-product-lifecycle-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        os.chown(self.root, 10001, 10001)
        self.directory = self.root / "real-case" / "message-signature" / "feed"
        current = self.root
        for name in ("real-case", "message-signature", "feed", "bodies"):
            current = current / name
            current.mkdir(mode=0o700)
            os.chown(current, 10001, 10001)
        self.put("server.crt", self.leaf.read_bytes())
        self.put("server.key", self.key.read_bytes())
        self.body = b'{"syntheticFeedOnly":true,"generation":1}\n'
        self.put("bodies/" + feed.sha(self.body) + ".json", self.body)
        self.put("plan.json", encoded(plan(body=self.body)))
        self.process = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=3)
        remove_fixture_root(self.root)

    def put(self, relative, raw):
        path = self.directory / relative
        # Each call replaces the private immutable input atomically. The helper
        # may observe an incomplete replacement as unavailable, never as valid.
        temporary = path.with_name(path.name + ".next")
        temporary.write_bytes(raw)
        temporary.chmod(0o600)
        os.chown(temporary, 10001, 10001)
        temporary.replace(path)

    def start(self, deadline=20, *, expect_ready=True):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        command = ["/usr/bin/setpriv", "--reuid=10001", "--regid=10001", "--clear-groups",
                   "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
                   sys.executable, "-I", "-B", "-c", SOURCE.decode("utf-8"), "serve", "--fixture-root",
                   str(self.root), "--case", "real-case", "--kind", "message-signature", "--port",
                   str(self.port), "--deadline-seconds", str(deadline)]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
                                             "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"})
        if not expect_ready:
            return
        until = time.monotonic() + 5
        while time.monotonic() < until:
            ready = self.directory / "ready.json"
            if ready.exists():
                value = json.loads(ready.read_bytes())
                self.assertEqual(set(value), {"schema", "port", "pid", "uid", "gid", "tls",
                                              "listenLoopback", "deadlineSeconds"})
                self.assertEqual(value, {"schema": feed.READY_SCHEMA, "port": self.port,
                                         "pid": self.process.pid, "uid": 10001, "gid": 10001, "tls": True,
                                         "listenLoopback": True, "deadlineSeconds": deadline})
                self.assertEqual(ready.stat().st_mode & 0o7777, 0o600)
                self.assertEqual((ready.stat().st_uid, ready.stat().st_gid), (10001, 10001))
                status = pathlib.Path("/proc") / str(self.process.pid) / "status"
                values = dict(x.split(":", 1) for x in status.read_text().splitlines() if ":" in x)
                for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    self.assertEqual(int(values[name].strip(), 16), 0)
                self.assertEqual(values["NoNewPrivs"].strip(), "1")
                self.assertEqual([int(x) for x in values["Uid"].split()], [10001] * 4)
                self.assertEqual([int(x) for x in values["Gid"].split()], [10001] * 4)
                self.assertEqual(values["Groups"].strip(), "")
                return
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                self.fail("real helper failed before safe readiness; stdout empty=" + str(not stdout)
                          + " stderr fixed=" + str(stderr.startswith(b"D12_FEED_ERROR=")))
            time.sleep(0.01)
        self.fail("real helper readiness deadline exceeded")

    def connect(self, context=None, hostname="feed.fixture.invalid"):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        try:
            return (self.context if context is None else context).wrap_socket(raw, server_hostname=hostname)
        except BaseException:
            raw.close()
            raise

    def request(self, target="/feed/latest.json", method="GET", headers=()):
        with self.connect() as connection:
            raw = (method + " " + target + " HTTP/1.1\r\nHost: feed.fixture.invalid\r\n"
                   + "".join(name + ": " + value + "\r\n" for name, value in headers) + "\r\n").encode("ascii")
            connection.sendall(raw)
            response = http.client.HTTPResponse(connection, method=method)
            response.begin()
            body = response.read(feed.MAX_BODY + 1)
            self.assertEqual(response.getheader("Content-Type"), "application/json")
            status = response.status
            response.close()
            return status, body

    def events(self, minimum=0):
        until = time.monotonic() + 3
        while True:
            try:
                path = self.directory / "events.jsonl"
                values = decode_event_lines(path.read_bytes())
            except (ValueError, OSError):
                values = None
            if values is not None and len(values) >= minimum:
                info = path.stat()
                self.assertEqual(info.st_mode & 0o7777, 0o600)
                self.assertEqual((info.st_uid, info.st_gid, info.st_nlink), (10001, 10001, 1))
                for ordinal, value in enumerate(values, 1):
                    self.assertEqual(set(value), {"schema", "ordinal", "epoch", "pathClass", "generation",
                                                  "status", "bodySHA256", "bytes", "tls", "authPresent",
                                                  "reason", "sentComplete"})
                    self.assertEqual(value["schema"], feed.EVENT_SCHEMA)
                    self.assertEqual(value["ordinal"], ordinal)
                    self.assertIn(value["reason"], feed.REASONS)
                    self.assertIn(value["pathClass"], ("latest", "generation", "invalid"))
                    self.assertIn(value["status"], (200, 503))
                    self.assertRegex(value["bodySHA256"], r"^[a-f0-9]{64}$")
                    self.assertIs(value["tls"], True)
                    self.assertIs(type(value["authPresent"]), bool)
                    self.assertIs(type(value["sentComplete"]), bool)
                    if not value["sentComplete"]:
                        self.assertEqual(value["bytes"], 0)
                return values
            if time.monotonic() >= until:
                self.fail("independent safe event deadline exceeded")
            time.sleep(0.01)

    def stop(self, signum=signal.SIGTERM):
        self.process.send_signal(signum)
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertEqual(self.process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")

    def test_real_tls_normal_ca_san_and_safe_independent_event(self):
        self.start()
        self.assertEqual(self.request(), (200, self.body))
        event = self.events(1)[0]
        self.assertEqual((event["status"], event["bodySHA256"], event["bytes"], event["reason"], event["sentComplete"]),
                         (200, feed.sha(self.body), len(self.body), "ok", True))
        self.stop()

    def test_fixture_certificate_spki_identity_from_real_tls_peer(self):
        self.start()
        with self.connect() as connection:
            actual = connection.getpeercert(binary_form=True)
            self.assertIn(connection.version(), ("TLSv1.2", "TLSv1.3"))
        expected = ssl.PEM_cert_to_DER_cert(self.leaf.read_text())
        self.assertEqual(actual, expected)
        public = self.openssl("x509", "-inform", "DER", "-pubkey", "-noout", input=actual)
        spki = self.openssl("pkey", "-pubin", "-outform", "DER", input=public)
        expected_public = self.openssl("x509", "-in", self.leaf, "-pubkey", "-noout")
        expected_spki = self.openssl("pkey", "-pubin", "-outform", "DER", input=expected_public)
        self.assertEqual(hashlib.sha256(spki).digest(), hashlib.sha256(expected_spki).digest())
        self.assertEqual(self.events(), [])
        self.stop()
        self.assertEqual(self.events(), [])

    def test_normal_client_rejects_wrong_ca_and_wrong_san_before_http(self):
        self.start()
        other = ssl.create_default_context(cafile=str(self.other_ca))
        for context, hostname in ((other, "feed.fixture.invalid"), (self.context, "wrong.fixture.invalid")):
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.connect(context, hostname)
        self.assertEqual(self.events(), [])
        self.stop()
        self.assertEqual(self.events(), [])

    def test_generation_and_planned_unavailable_have_actual_body_hashes(self):
        candidate = plan(body=self.body)
        candidate["responses"].update({"2.json": copy.deepcopy(candidate["responses"]["latest.json"]),
                                        "3.json": {"status": 503, "bodySHA256": ""}})
        self.put("plan.json", encoded(candidate))
        self.start()
        self.assertEqual(self.request("/feed/2.json"), (200, self.body))
        self.events(1)
        self.assertEqual(self.request("/feed/3.json"), (503, feed.ERROR_BODY))
        values = self.events(2)
        self.assertEqual([(v["pathClass"], v["generation"]) for v in values], [("generation", 2), ("generation", 3)])
        self.assertEqual(values[1]["bodySHA256"], feed.sha(feed.ERROR_BODY))
        self.assertEqual(values[1]["bytes"], len(feed.ERROR_BODY))
        self.stop()

    def test_auth_methods_and_raw_target_variants_are_rejected_without_echo(self):
        self.start()
        secret = "never-publish-fixture-secret"
        requests = [("/feed/latest.json", "GET", (("Authorization", secret),), "auth-present"),
                    ("/feed/latest.json", "GET", (("Authorization", ""),), "auth-present"),
                    ("/feed/latest.json", "POST", (), "method-invalid"),
                    ("/feed/latest.json", "HEAD", (), "method-invalid"),
                    ("/feed/latest.json?" + secret, "GET", (), "request-invalid"),
                    ("//feed/latest.json", "GET", (), "request-invalid"),
                    ("/feed/%6catest.json", "GET", (), "request-invalid"),
                    ("/feed/../latest.json", "GET", (), "request-invalid"),
                    ("/feed/01.json", "GET", (), "request-invalid")]
        for ordinal, (target, method, headers, _) in enumerate(requests, 1):
            status, body = self.request(target, method, headers)
            self.assertEqual(status, 503)
            self.assertNotIn(secret.encode(), body)
            self.events(ordinal)
        values = self.events(len(requests))
        self.assertEqual([v["reason"] for v in values], [row[3] for row in requests])
        self.assertTrue(values[0]["authPresent"] and values[1]["authPresent"])
        self.assertEqual(values[3]["bytes"], 0)
        self.assertEqual(values[3]["bodySHA256"], feed.sha(b""))
        raw = (self.directory / "events.jsonl").read_bytes()
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(b"/feed/", raw)
        self.stop()

    def test_each_request_rereads_plan_epoch_conflict_rollback_and_recovery(self):
        self.start()
        self.assertEqual(self.request()[0], 200)
        self.events(1)
        self.put("plan.json", encoded(plan(body=self.body)) + b"\n")
        self.assertEqual(self.request()[0], 503)
        self.events(2)
        self.put("plan.json", encoded(plan(2, self.body)))
        self.assertEqual(self.request()[0], 200)
        self.events(3)
        self.put("plan.json", encoded(plan(1, self.body)))
        self.assertEqual(self.request()[0], 503)
        self.events(4)
        self.put("plan.json", encoded(plan(3, self.body)))
        self.assertEqual(self.request()[0], 200)
        self.assertEqual([v["reason"] for v in self.events(5)],
                         ["ok", "epoch-conflict", "ok", "epoch-rollback", "ok"])
        self.stop()

    def test_real_concurrent_one_shot_per_path_and_new_epoch(self):
        candidate = plan(body=self.body, one_shot=True)
        candidate["responses"]["2.json"] = copy.deepcopy(candidate["responses"]["latest.json"])
        self.put("plan.json", encoded(candidate))
        self.start()
        barrier = threading.Barrier(4)
        def request(_):
            barrier.wait(timeout=3)
            return self.request()[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
            statuses = list(workers.map(request, range(4)))
        self.assertEqual(sorted(statuses), [200, 503, 503, 503])
        self.assertEqual(self.request("/feed/2.json")[0], 200)
        candidate["epoch"] = 2
        self.put("plan.json", encoded(candidate))
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(sum(v["status"] == 200 for v in self.events(6)), 3)
        self.stop()

    def test_invalid_duplicate_and_oversized_plan_fail_closed_then_recover(self):
        self.start()
        for raw in (b'{"epoch":1,"epoch":2}', b"[", b"x" * (feed.MAX_PLAN + 1)):
            self.put("plan.json", raw)
            self.assertEqual(self.request(), (503, feed.ERROR_BODY))
        self.put("plan.json", encoded(plan(2, self.body)))
        self.assertEqual(self.request(), (200, self.body))
        self.assertEqual([v["status"] for v in self.events(4)], [503, 503, 503, 200])
        self.stop()

    def test_changed_or_missing_body_never_returns_200(self):
        self.start()
        relative = "bodies/" + feed.sha(self.body) + ".json"
        self.put(relative, b"different but private")
        self.assertEqual(self.request(), (503, feed.ERROR_BODY))
        self.assertEqual(self.events(1)[0]["reason"], "body-mismatch")
        (self.directory / relative).unlink()
        self.assertEqual(self.request(), (503, feed.ERROR_BODY))
        self.assertEqual(self.events(2)[1]["reason"], "body-unavailable")
        self.stop()

    def test_plan_symlink_hardlink_and_fifo_rejected_without_blocking(self):
        self.start()
        target = self.directory / "plan.json"
        body = self.directory / "bodies" / (feed.sha(self.body) + ".json")
        for kind in ("symlink", "hardlink", "fifo"):
            target.unlink()
            if kind == "symlink":
                target.symlink_to(body)
            elif kind == "hardlink":
                os.link(body, target)
            else:
                os.mkfifo(target, 0o600)
                os.chown(target, 10001, 10001)
            started = time.monotonic()
            self.assertEqual(self.request(), (503, feed.ERROR_BODY))
            self.assertLess(time.monotonic() - started, 2)
            target.unlink()
            self.put("plan.json", encoded(plan(2, self.body)))
        self.assertEqual(len(self.events(3)), 3)
        self.stop()

    def test_input_wrong_mode_owner_and_oversized_body_are_rejected(self):
        self.start()
        target = self.directory / "plan.json"
        target.chmod(0o644)
        self.assertEqual(self.request()[0], 503)
        target.chmod(0o600)
        os.chown(target, 0, 0)
        self.assertEqual(self.request()[0], 503)
        os.chown(target, 10001, 10001)
        self.put("bodies/" + feed.sha(self.body) + ".json", b"x" * (feed.MAX_BODY + 1))
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(len(self.events(3)), 3)
        self.stop()

    def test_certificate_hardlink_fails_startup(self):
        # A certificate hardlink cannot be loaded even with the right bytes.
        key = self.directory / "server.key"
        key.unlink()
        os.link(self.directory / "server.crt", key)
        self.start(expect_ready=False)
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertNotEqual(self.process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"D12_FEED_ERROR=REJECTED reason=security-invalid\n")
        self.assertFalse((self.directory / "ready.json").exists())

    def test_feed_directory_symlink_fails_startup(self):
        original = self.directory.with_name("feed-original")
        self.directory.rename(original)
        self.directory.symlink_to(original, target_is_directory=True)
        self.start(expect_ready=False)
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertNotEqual(self.process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"D12_FEED_ERROR=REJECTED reason=security-invalid\n")
        self.assertFalse((original / "ready.json").exists())

    def test_private_directory_special_mode_fails_startup(self):
        self.directory.chmod(0o2700)
        self.start(expect_ready=False)
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertNotEqual(self.process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"D12_FEED_ERROR=REJECTED reason=security-invalid\n")

    def test_ready_is_atomic_and_existing_ready_is_not_replaced(self):
        marker = b"existing-ready-must-survive\n"
        self.put("ready.json", marker)
        self.start(expect_ready=False)
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertNotEqual(self.process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"D12_FEED_ERROR=REJECTED reason=security-invalid\n")
        self.assertEqual((self.directory / "ready.json").read_bytes(), marker)
        self.assertFalse((self.directory / "ready.pending").exists())

    def test_existing_output_is_not_overwritten(self):
        marker = b"existing-output-must-survive\n"
        self.put("events.jsonl", marker)
        self.start(expect_ready=False)
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertNotEqual(self.process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"D12_FEED_ERROR=REJECTED reason=filesystem-or-tls-invalid\n")
        self.assertEqual((self.directory / "events.jsonl").read_bytes(), marker)

    def test_term_closes_eight_slow_tls_handshakes_and_joins(self):
        self.start()
        connections = [socket.create_connection(("127.0.0.1", self.port), timeout=2) for _ in range(8)]
        self.addCleanup(lambda: [connection.close() for connection in connections])
        until = time.monotonic() + 1.5
        tasks = pathlib.Path("/proc") / str(self.process.pid) / "task"
        while len(list(tasks.iterdir())) < feed.MAX_WORKERS + 1:
            if time.monotonic() >= until:
                self.fail("eight real TLS worker threads did not become independently observable")
            time.sleep(0.01)
        started = time.monotonic()
        self.stop()
        self.assertLess(time.monotonic() - started, 3)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=1)

    def test_int_closes_incomplete_http_headers_and_joins(self):
        self.start()
        connections = [self.connect() for _ in range(4)]
        self.addCleanup(lambda: [connection.close() for connection in connections])
        for connection in connections:
            connection.sendall(b"GET /feed/latest.json HTTP/1.1\r\nHost:")
        time.sleep(0.05)
        started = time.monotonic()
        self.stop(signal.SIGINT)
        self.assertLess(time.monotonic() - started, 3)

    def test_real_deadline_exits_and_closes_inflight_handshake(self):
        self.start(deadline=1)
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        self.addCleanup(connection.close)
        started = time.monotonic()
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertEqual(self.process.returncode, 0)
        self.assertEqual((stdout, stderr), (b"", b""))
        self.assertLess(time.monotonic() - started, 3)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=1)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    real_linux = sys.platform.startswith("linux")
    okay = result.wasSuccessful() and (not real_linux or not result.skipped)
    passed = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
    if real_linux:
        print("D12_FEED_TESTS=" + ("PASS" if okay else "FAIL")
              + f" tests={result.testsRun} passed={passed} skipped={len(result.skipped)}"
              + " real_linux=true helper_uid=10001 helper_capabilities=none")
    else:
        print("D12_FEED_AUXILIARY_TESTS=" + ("PASS" if okay else "FAIL")
              + f" tests={result.testsRun} passed={passed} skipped={len(result.skipped)}"
              + " real_linux=false auxiliary_only=true")
    raise SystemExit(0 if okay else 1)
