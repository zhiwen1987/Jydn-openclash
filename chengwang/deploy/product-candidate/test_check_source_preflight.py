"""Synthetic verifier counterexamples; no product or native fixture proof."""
from __future__ import annotations

import contextlib
import copy
import io
import pathlib
import tempfile
import unittest
from unittest import mock

import check_source_preflight as check


def native_source():
    text = "import unittest\nclass ShapeTests(unittest.TestCase):\n"
    text += "".join(f" def test_shape_{i}(self): pass\n" for i in range(8))
    text += "class LinuxTests(unittest.TestCase):\n"
    text += "".join(f" def {name}(self): pass\n" for name in check.CASE_LABELS)
    return text.encode()


def transcript(source, suite):
    names = sorted(check.prerequisite.expected_tests(source))
    lines = [f"{name.split('.')[1]} (__main__.{name}) ... ok" for name in names]
    lines += ["", "-" * 70, f"Ran {len(names)} tests in 0.123s", "", "OK"]
    lines += ([f"D12_SOURCE_FIXTURE_TESTS=PASS tests={len(names)} passed={len(names)} skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none"]
              if suite == "fixture" else [f"D12_SOURCE_PREFLIGHT_CHECKER_TESTS=PASS tests={len(names)} skipped=0 synthetic_only=true"])
    return ("\n".join(lines) + "\n").encode()


def event(kind, connection=1, **changes):
    value = {"schema": "chengwang.product-source-event/v1", "ordinal": 1,
             "connection": connection, "event": kind, "reason": "", "tls": False,
             **check.NON_HTTP_EMPTY}
    value.update(changes)
    return value


def response(mode="json", epoch=1, label="", reason="planned", **changes):
    if reason != "planned":
        mode = "unavailable"
    body = b"x" * check.MAX_BODY if label == "body-boundary" else check.DEFAULT_BODY
    status, representation, wire = check.expected_wire(mode, body)
    plan_mode = label if label in check.MODES else "json"
    value = event("http", tls=True, reason=reason, epoch=epoch, planSHA256=check.sha(check.plan_bytes(epoch, plan_mode, body, label == "normal")),
                  pathClass="latest", generation=0, mode=mode, status=status,
                  representationSHA256=check.sha(representation), representationBytes=len(representation),
                  wireSHA256=check.sha(wire), wireBytes=len(wire), writtenBytes=len(wire), wireComplete=True)
    value.update(changes)
    return value


def chain(http=None, tls_reason="ok", close_reason="closed", no_tls=False):
    values = [event("connect", reason="accepted")]
    tls = not no_tls and tls_reason == "ok"
    if not no_tls:
        values.append(event("tls", reason=tls_reason, tls=tls))
    if http is not None:
        values.append(http)
    values.append(event("close", reason=close_reason, tls=tls))
    return values


def combine(chains):
    values = []
    for number, part in enumerate(chains, 1):
        for item in part:
            item = copy.deepcopy(item)
            item["connection"] = number
            item["ordinal"] = len(values) + 1
            values.append(item)
    return values


def observations():
    cases = []
    for method, labels in check.CASE_LABELS.items():
        for label in labels:
            if label in check.MODES:
                parts = [chain(response(label, label=label))]
                if label == "stall-body":
                    second = response(label, label=label)
                    _, _, wire = check.expected_wire(label, check.DEFAULT_BODY)
                    second.update(writtenBytes=wire.index(b"\r\n\r\n") + 4,
                                  wireComplete=False)
                    parts.append(chain(second, close_reason="stopping"))
            elif label in ("wrong-ca", "wrong-san"):
                parts = [chain(tls_reason="failed")]
            elif label == "normal":
                parts = [chain(response(label="normal")), chain(response(label="normal", pathClass="generation", generation=2))]
            elif label == "epoch-sequence":
                parts = [chain(response(epoch=1)), chain(response(epoch=2)),
                         chain(response(epoch=2, reason="epoch-conflict", planSHA256=check.sha(check.plan_bytes(2) + b" "))),
                         chain(response(epoch=1, reason="epoch-rollback")), chain(response(epoch=3))]
            elif label == "sensitive-request":
                parts = [chain(response(reason="auth-present", authPresent=True)),
                         chain(response(reason="request-invalid", pathClass="invalid")),
                         chain(response(reason="method-invalid"))]
            elif label in ("stop-term", "stop-int", "deadline"):
                parts = [chain(tls_reason="stopping", close_reason="stopping")]
            elif label == "body-mismatch":
                parts = [chain(response()), chain(response(reason="body-mismatch")),
                         chain(response(reason="plan-unavailable", epoch=0, planSHA256=""))]
            elif label == "missing-body":
                parts = [chain(response()), chain(response(reason="body-unavailable"))]
            elif label == "capacity-stop":
                parts = [chain(tls_reason="stopping", close_reason="stopping") for _ in range(8)] + [chain(no_tls=True)]
            else:
                parts = [chain(response(label=label))]
            events = combine(parts)
            if label == "capacity-stop":
                events = ([e for e in events if e["event"] == "connect"]
                          + [e for e in events if e["connection"] == 9 and e["event"] == "close"]
                          + [e for e in events if e["connection"] != 9 and e["event"] != "connect"])
                for ordinal, item in enumerate(events, 1):
                    item["ordinal"] = ordinal
            cases.append({"testName": method, "label": label, "events": events})
    return {"schema": "chengwang.product-source-observations/v1", "cases": cases}


def cleanup():
    return {"schema": "chengwang.product-source-preflight-cleanup/v1", "privateTreeRemoved": True,
            "testExitCode": 0, "hostTmpTouched": False, "parentMountNamespaceChanged": False,
            "production": False, "authorization": "BLOCKED", "deviceActionsExecuted": False}


def material():
    sources = {path: b"synthetic source only\n" for path in check.SOURCE_PATHS}
    sources[check.BASE + "test_fixture_source.py"] = native_source()
    sources[check.BASE + "test_check_source_preflight.py"] = pathlib.Path(__file__).read_bytes()
    inputs = {check.INPUT_NAMES[0]: transcript(native_source(), "fixture"),
              check.INPUT_NAMES[1]: transcript(sources[check.BASE + "test_check_source_preflight.py"], "checker"),
              check.INPUT_NAMES[2]: check.encoded(observations()), check.INPUT_NAMES[3]: check.encoded(cleanup())}
    return inputs, sources


class TranscriptTests(unittest.TestCase):
    def reject(self, raw, source=None, suite="fixture"):
        with self.assertRaises((check.Rejected, check.prerequisite.Rejected, UnicodeError)):
            check.verify_transcript(raw, native_source() if source is None else source, suite)

    def test_exact_fixture_and_checker_named_markers(self):
        value = check.verify_transcript(transcript(native_source(), "fixture"), native_source(), "fixture")
        self.assertEqual((value["tests"], value["passed"], value["skipped"]), (24, 24, 0))
        source = pathlib.Path(__file__).read_bytes()
        self.assertEqual(check.verify_transcript(transcript(source, "checker"), source, "checker")["tests"], 32)

    def test_marker_alone_is_not_proof(self):
        self.reject(transcript(native_source(), "fixture").splitlines()[-1])

    def test_missing_or_duplicate_named_tests(self):
        raw = transcript(native_source(), "fixture")
        self.reject(b"\n".join(raw.splitlines()[1:]) + b"\n")
        self.reject(raw + raw.splitlines()[0] + b"\n")

    def test_skips_errors_and_failures_rejected(self):
        for bad in (b"skipped 'linux'", b"FAIL", b"ERROR"):
            self.reject(transcript(native_source(), "fixture").replace(b"... ok", b"... " + bad, 1))

    def test_renamed_classes_or_mismatched_method_rejected(self):
        raw = transcript(native_source(), "fixture")
        self.reject(raw.replace(b"LinuxTests.", b"ForeignTests.", 1))
        self.reject(raw.replace(b"test_body_bytes_remain_immutable_and_mismatch_is_rejected (", b"test_foreign (", 1))

    def test_unexpected_private_output_and_escape_rejected(self):
        for extra in (b"private /path token=SENTINEL\n", b"\x1b[32m", b"\xff"):
            self.reject(transcript(native_source(), "fixture") + extra)

    def test_count_forgery_duplicate_summary_rejected(self):
        raw = transcript(native_source(), "fixture")
        self.reject(raw.replace(b"Ran 24 tests", b"Ran 23 tests"))
        self.reject(raw + b"OK\n")
        self.reject(raw + b"Ran 24 tests in 0.1s\n")

    def test_auxiliary_or_forged_linux_marker_rejected(self):
        raw = transcript(native_source(), "fixture")
        self.reject(raw.replace(b"FIXTURE_TESTS=", b"FIXTURE_AUXILIARY_TESTS="))
        self.reject(raw.replace(b"real_linux=true", b"real_linux=false"))


class ConnectionTests(unittest.TestCase):
    def reject(self, values):
        with self.assertRaises(check.Rejected):
            check.verify_connections(values)

    def test_valid_closed_and_interleaved_connections(self):
        values = combine([chain(response()), chain(tls_reason="failed")])
        self.assertEqual(check.verify_connections(values)["connections"], 2)
        a, b = chain(response()), chain(response())
        values = [a[0], b[0], a[1], b[1], b[2], a[2], a[3], b[3]]
        for i, item in enumerate(values, 1):
            item["ordinal"] = i
            if item is b[0] or any(item is entry for entry in b):
                item["connection"] = 2
        self.assertEqual(check.verify_connections(values)["http"], 2)

    def test_ordinal_and_connection_number_forgery_rejected(self):
        values = combine([chain(response())]); values[1]["ordinal"] = 1; self.reject(values)
        values = combine([chain(response())]); values[0]["connection"] = 2; self.reject(values)

    def test_missing_close_or_late_event_rejected(self):
        values = combine([chain(response())]); self.reject(values[:-1])
        values.append({**values[2], "ordinal": 5}); self.reject(values)

    def test_tls_failure_cannot_emit_http(self):
        self.reject(combine([chain(response(), tls_reason="failed")]))
        self.reject(combine([chain(response(), no_tls=True)]))

    def test_duplicate_tls_or_http_rejected(self):
        for at in (1, 2):
            values = chain(response()); values.insert(at, copy.deepcopy(values[at])); self.reject(combine([values]))

    def test_non_http_fabricated_plan_or_bytes_rejected(self):
        for key, value in (("epoch", 1), ("wireBytes", 10), ("pathClass", "latest"), ("authPresent", True)):
            values = combine([chain(response())]); values[0][key] = value; self.reject(values)

    def test_unknown_fields_and_secret_reason_rejected(self):
        values = combine([chain(response())]); values[2]["rawAuthorization"] = "SENTINEL"; self.reject(values)
        values = combine([chain(response())]); values[2]["reason"] = "/private/exception SENTINEL"; self.reject(values)

    def test_boolean_numbers_and_noncanonical_digest_rejected(self):
        for key, value in (("ordinal", True), ("connection", False), ("epoch", True), ("wireBytes", True), ("planSHA256", "A" * 64)):
            values = combine([chain(response())]); values[2][key] = value; self.reject(values)

    def test_response_status_and_rejection_forgery_rejected(self):
        values = combine([chain(response(reason="auth-present", authPresent=True))]); values[2]["mode"] = "json"; self.reject(values)
        values = combine([chain(response())]); values[2]["authPresent"] = True; self.reject(values)
        # Auth may coexist with an earlier parser/method/plan failure; it
        # cannot turn that fixed refusal into a successful planned response.
        for reason in ("request-invalid", "method-invalid", "epoch-rollback"):
            self.assertEqual(check.verify_connections(combine([chain(response(reason=reason, authPresent=True))]))["http"], 1)

    def test_written_bytes_and_complete_flag_must_agree(self):
        values = combine([chain(response())]); values[2]["writtenBytes"] -= 1; self.reject(values)
        values = combine([chain(response())]); values[2]["wireComplete"] = False; self.reject(values)


class ObservationTests(unittest.TestCase):
    def reject(self, value):
        with self.assertRaises(check.Rejected):
            check.verify_observations(check.encoded(value), native_source())

    def test_complete_closed_capability_matrix(self):
        value = check.verify_observations(check.encoded(observations()), native_source())
        self.assertEqual(len(value["cases"]), sum(map(len, check.CASE_LABELS.values())))

    def test_missing_unknown_duplicate_case_rejected(self):
        value = observations(); value["cases"].pop(); self.reject(value)
        value = observations(); value["cases"][0]["label"] = "unknown-SENTINEL"; self.reject(value)
        value = observations(); value["cases"][-1] = copy.deepcopy(value["cases"][0]); self.reject(value)

    def test_required_wire_mode_cannot_be_substituted(self):
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "chunked"); case["events"] = combine([chain(response())]); self.reject(value)
        for mutation in ("missing-cancel", "false-zero", "complete", "not-stopped"):
            value = observations(); case = next(c for c in value["cases"] if c["label"] == "stall-body")
            if mutation == "missing-cancel": case["events"] = case["events"][:4]
            elif mutation == "false-zero": case["events"][6]["writtenBytes"] = 0
            elif mutation == "complete":
                case["events"][6]["writtenBytes"] = case["events"][6]["wireBytes"]
                case["events"][6]["wireComplete"] = True
            else: case["events"][7]["reason"] = "closed"
            self.reject(value)

    def test_wire_and_representation_hash_tampering_rejected(self):
        for key, changed in (("wireSHA256", "f" * 64), ("representationSHA256", "f" * 64), ("wireBytes", 9), ("representationBytes", 9), ("planSHA256", "f" * 64)):
            value = observations(); event = next(e for e in value["cases"][0]["events"] if e["event"] == "http"); event[key] = changed; self.reject(value)

    def test_missing_tls_refusal_is_not_zero_http_proof(self):
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "wrong-ca"); case["events"] = combine([chain(no_tls=True)]); self.reject(value)

    def test_epoch_conflict_rollback_and_recovery_required(self):
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "epoch-sequence"); case["events"] = combine([chain(response())]); self.reject(value)
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "epoch-sequence")
        conflict = next(e for e in case["events"] if e["event"] == "http" and e["reason"] == "epoch-conflict")
        conflict["planSHA256"] = check.sha(check.plan_bytes(2)); self.reject(value)

    def test_sensitive_request_evidence_cannot_be_omitted(self):
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "sensitive-request"); case["events"] = combine([chain(response())]); self.reject(value)

    def test_capacity_and_stop_require_actual_connection_chains(self):
        for label in ("capacity-stop", "stop-term", "stop-int", "deadline"):
            value = observations(); case = next(c for c in value["cases"] if c["label"] == label); case["events"] = combine([chain(response())]); self.reject(value)
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "capacity-stop")
        next(e for e in case["events"] if e["connection"] == 9 and e["event"] == "close")["reason"] = "stopping"
        self.reject(value)
        value = observations(); case = next(c for c in value["cases"] if c["label"] == "capacity-stop")
        # A ninth close only after older workers have stopped is not capacity
        # evidence, even when all complete connection chains are individually valid.
        case["events"] = combine([chain(tls_reason="stopping", close_reason="stopping") for _ in range(8)] + [chain(no_tls=True)])
        self.reject(value)


class BoundaryTests(unittest.TestCase):
    def test_exact_cleanup_and_raw_digest(self):
        raw = check.encoded(cleanup()); self.assertEqual(check.verify_cleanup(raw)["sha256"], check.sha(raw))

    def test_cleanup_changes_extra_duplicate_fields_rejected(self):
        for key, bad in (("privateTreeRemoved", False), ("testExitCode", False), ("testExitCode", 1), ("hostTmpTouched", True), ("authorization", "ALLOWED"), ("secret", "SENTINEL")):
            with self.assertRaises(check.Rejected): check.verify_cleanup(check.encoded({**cleanup(), key: bad}))
        with self.assertRaises(check.Rejected): check.verify_cleanup(check.encoded(cleanup())[:-1] + b',"production":false}')

    def test_full_artifact_is_deterministic_and_not_product_proof(self):
        inputs, sources = material(); result = check.verify_artifacts(inputs, sources, "a" * 40)
        self.assertEqual(check.encoded(result), check.encoded(check.verify_artifacts(inputs, sources, "a" * 40)))
        self.assertTrue(result["fixturePrerequisitesOnly"]); self.assertFalse(result["actualProductSourceMatrixProven"])
        self.assertFalse(result["productTLSRefusalProven"]); self.assertFalse(result["production"])
        self.assertEqual(len(result["sources"]), 8); self.assertEqual(len(result["evidenceSHA256"]), 4)

    def test_missing_or_extra_inputs_and_sources_rejected(self):
        inputs, sources = material()
        for mapping, key in ((inputs, check.INPUT_NAMES[0]), (sources, check.SOURCE_PATHS[0])):
            removed = mapping.pop(key)
            with self.assertRaises(check.Rejected): check.verify_artifacts(inputs, sources, "a" * 40)
            mapping[key] = removed
            mapping["extra-SENTINEL"] = b"x"
            with self.assertRaises(check.Rejected): check.verify_artifacts(inputs, sources, "a" * 40)
            del mapping["extra-SENTINEL"]

    def test_added_renamed_or_wrong_package_source_test_rejected(self):
        for raw in (native_source() + b" def test_extra(self): pass\n", native_source().replace(b"class LinuxTests", b"class ForeignTests"), native_source().replace(b"test_normal_tls_json_and_generation", b"test_unknown")):
            with self.assertRaises(check.Rejected): check.native_source_tests(raw)

    def test_regular_bounded_input_and_cli_failure_do_not_leak(self):
        with tempfile.TemporaryDirectory() as task_dir:
            path = pathlib.Path(task_dir) / "safe.json"; path.write_bytes(b"{}")
            self.assertEqual(check.read_file(path, 2), b"{}")
            with self.assertRaises(check.Rejected): check.read_file(path, 1)
            with self.assertRaises(check.Rejected): check.read_file(path.parent, 100)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            with self.assertRaises(SystemExit) as error: check.main(["--unknown-secret-SENTINEL"])
        self.assertEqual(str(error.exception), "D12_SOURCE_PREFLIGHT_CHECK=FAIL"); self.assertNotIn("SENTINEL", stream.getvalue())
        with mock.patch.object(check, "verify", side_effect=OSError("/private SENTINEL")):
            with self.assertRaises(SystemExit) as error: check.main(["--source-root", "/a", "--evidence-dir", "/b", "--source-commit", "a" * 40])
        self.assertEqual(str(error.exception), "D12_SOURCE_PREFLIGHT_CHECK=FAIL")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__)))
    accepted = result.wasSuccessful() and not result.skipped and result.testsRun == 32
    if accepted:
        print("D12_SOURCE_PREFLIGHT_CHECKER_TESTS=PASS tests=32 skipped=0 synthetic_only=true")
    raise SystemExit(0 if accepted else 1)
