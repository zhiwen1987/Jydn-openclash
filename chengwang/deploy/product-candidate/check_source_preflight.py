"""Strict verifier for source-fixture prerequisites, not product acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess

import check_lifecycle_preflight as prerequisite


class Rejected(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Rejected(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "fields")


def integer(value, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, "integer")
    return value


def digest(value, empty=False):
    require(type(value) is str and (empty and value == "" or re.fullmatch(r"[a-f0-9]{64}", value)), "digest")
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate-json-field")
        value[key] = item
    return value


def parse(raw, limit=8 << 20):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "json-size")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("json-number")))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("json") from None


MODES = frozenset((
    "json", "forbidden", "unavailable", "redirect", "content-type-missing",
    "content-type-duplicate", "content-type-wrong", "content-encoding", "trailer",
    "chunked", "length-missing", "length-zero", "length-oversize", "length-short",
    "body-truncated", "header-oversize", "stall-headers", "stall-body", "close-before-headers",
))
EVENT_FIELDS = frozenset((
    "schema", "ordinal", "connection", "event", "reason", "epoch", "planSHA256",
    "pathClass", "generation", "mode", "status", "representationSHA256", "representationBytes",
    "wireSHA256", "wireBytes", "writtenBytes", "wireComplete", "authPresent", "tls",
))
NON_HTTP_EMPTY = {
    "epoch": 0, "planSHA256": "", "pathClass": "", "generation": 0, "mode": "",
    "status": 0, "representationSHA256": "", "representationBytes": 0,
    "wireSHA256": "", "wireBytes": 0, "writtenBytes": 0, "wireComplete": False,
    "authPresent": False,
}
DEFAULT_BODY = b'{"fixture":"source"}\n'
MAX_BODY = 262145
MAX_WIRE = MAX_BODY + (32 << 10)
ERROR_BODY = b'{"code":"fixture_source_unavailable"}\n'
HTTP_REJECTIONS = frozenset(("request-invalid", "method-invalid", "auth-present", "plan-unavailable",
    "plan-invalid", "epoch-rollback", "epoch-conflict", "not-planned", "body-unavailable", "body-mismatch", "stopping"))
NO_BODY_MODES = frozenset(("forbidden", "unavailable", "redirect", "stall-headers", "close-before-headers"))
CASE_LABELS = {
    "test_normal_tls_json_and_generation": ("normal",),
    "test_wrong_ca_and_san_record_failed_tls": ("wrong-ca", "wrong-san"),
    "test_real_wire_modes": tuple(sorted(MODES)),
    "test_plan_epochs_reject_conflict_rollback_then_recover": ("epoch-sequence",),
    "test_sensitive_request_headers_and_targets_are_redacted": ("sensitive-request",),
    "test_body_bytes_remain_immutable_and_mismatch_is_rejected": ("body-mismatch",),
    "test_private_input_links_and_fifo_rejected": (),
    "test_private_tree_and_certificate_rejections_preserve_bytes": (),
    "test_ready_atomic_and_outputs_never_overwritten": ("ready-atomic",),
    "test_fixed_port_rebind_and_active_listener_exclusivity": ("fixed-port-first", "fixed-port-second"),
    "test_term_joins_slow_tls_connections": ("stop-term",),
    "test_int_joins_incomplete_http_headers": ("stop-int",),
    "test_deadline_closes_inflight_tls": ("deadline",),
    "test_body_size_boundary_and_oversize_refusal": ("body-boundary",),
    "test_worker_capacity_is_logged_and_joined": ("capacity-stop",),
    "test_missing_or_changed_body_never_reflects_private_bytes": ("missing-body",),
}
NATIVE_TEST_COUNT = 24
CHECKER_TEST_COUNT = 32
BASE = "chengwang/deploy/product-candidate/"
SCRIPTS = "chengwang/tools/image-binding/scripts/"
SOURCE_PATHS = tuple(sorted([BASE + name for name in (
    "fixture_feed.py", "check_lifecycle_preflight.py", "fixture_source.py", "test_fixture_source.py",
    "check_source_preflight.py", "test_check_source_preflight.py")] + [SCRIPTS + name for name in (
    "run-source-fixture-preflight.sh", "run-linux-ci.sh")]))
INPUT_NAMES = ("product-source-fixture-tests.log", "product-source-fixture-checker-tests.log",
               "product-source-fixture-observations.json", "product-source-fixture-cleanup.json")
OUTPUT_NAME = "product-source-fixture-preflight.json"


def verify_transcript(raw, source, suite):
    require(suite in ("fixture", "checker"), "suite")
    require(type(raw) is bytes and 0 < len(raw) <= 1 << 20 and b"\x1b" not in raw, "transcript-size")
    try:
        expected = prerequisite.expected_tests(source)
        lines = raw.decode("utf-8").splitlines()
    except (ValueError, SyntaxError, UnicodeError):
        raise Rejected("test-source-or-transcript") from None
    count = len(expected)
    marker = (f"D12_SOURCE_FIXTURE_TESTS=PASS tests={count} passed={count} skipped=0 "
              "real_linux=true helper_uid=10001 helper_capabilities=none" if suite == "fixture" else
              f"D12_SOURCE_PREFLIGHT_CHECKER_TESTS=PASS tests={count} skipped=0 synthetic_only=true")
    seen, summaries, ok, markers = set(), [], 0, 0
    for line in lines:
        if not line.strip() or re.fullmatch(r"-{5,}", line):
            continue
        test = re.fullmatch(r"(test_[A-Za-z0-9_]+) \(__main__\.([A-Za-z0-9_]+)\.(test_[A-Za-z0-9_]+)\) \.\.\. ok", line)
        summary = re.fullmatch(r"Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s", line)
        if test:
            first, cls, method = test.groups()
            name = cls + "." + method
            require(first == method and name in expected and name not in seen, "named-test")
            seen.add(name)
        elif summary:
            summaries.append(int(summary[1]))
        elif line == "OK":
            ok += 1
        elif line == marker:
            markers += 1
        else:
            raise Rejected("unexpected-transcript-line")
    require(seen == expected and summaries == [count] and ok == 1 and markers == 1, "test-completeness")
    return {"suite": suite, "tests": count, "passed": count, "skipped": 0,
            "testSourceSHA256": sha(source), "transcriptSHA256": sha(raw),
            "namedTestsSHA256": sha(("\n".join(sorted(seen)) + "\n").encode()),
            "syntheticOnly": suite == "checker", "realLinux": suite == "fixture"}


def verify_cleanup(raw):
    value = parse(raw, 4096)
    expected = {"schema": "chengwang.product-source-preflight-cleanup/v1", "privateTreeRemoved": True,
                "testExitCode": 0, "hostTmpTouched": False, "parentMountNamespaceChanged": False,
                "production": False, "authorization": "BLOCKED", "deviceActionsExecuted": False}
    exact(value, expected)
    require(all(type(value[key]) is type(want) and value[key] == want for key, want in expected.items()), "cleanup")
    return {"sha256": sha(raw), **value}


def verify_connections(events):
    require(type(events) is list and 0 < len(events) <= 4096, "events-size")
    connections = {}
    counts = {"connections": 0, "tlsSucceeded": 0, "tlsFailed": 0, "http": 0, "incompleteWire": 0}
    for ordinal, event in enumerate(events, 1):
        exact(event, EVENT_FIELDS)
        require(event["schema"] == "chengwang.product-source-event/v1", "event-schema")
        require(integer(event["ordinal"], 1, 4096) == ordinal, "ordinal")
        connection = integer(event["connection"], 1, 512)
        require(type(event["tls"]) is bool and type(event["wireComplete"]) is bool
                and type(event["authPresent"]) is bool, "event-booleans")
        kind = event["event"]
        require(type(kind) is str and kind in ("connect", "tls", "http", "close"), "event-kind")
        if kind == "connect":
            require(connection == len(connections) + 1 and connection not in connections
                    and event["reason"] == "accepted" and event["tls"] is False, "connect")
            connections[connection] = {"stage": "connect", "tls": False}
            counts["connections"] += 1
        else:
            require(connection in connections and connections[connection]["stage"] != "close", "connection-order")
            state = connections[connection]
            if kind == "tls":
                require(state["stage"] == "connect" and event["reason"] in ("ok", "failed", "timeout", "stopping")
                        and event["tls"] is (event["reason"] == "ok"), "tls")
                state["tls"] = event["tls"]
                counts["tlsSucceeded" if event["tls"] else "tlsFailed"] += 1
            elif kind == "http":
                require(state["stage"] == "tls" and state["tls"] and event["tls"] is True, "http-without-tls")
                verify_http(event)
                counts["http"] += 1
                counts["incompleteWire"] += not event["wireComplete"]
            else:
                require(event["reason"] in ("closed", "stopping") and event["tls"] is state["tls"], "close")
            state["stage"] = kind
        if kind != "http":
            require(all(type(event[key]) is type(want) and event[key] == want
                        for key, want in NON_HTTP_EMPTY.items()), "non-http-fields")
    require(all(value["stage"] == "close" for value in connections.values()), "unclosed-connection")
    return counts


def verify_http(event):
    require(type(event["mode"]) is str and type(event["reason"]) is str
            and type(event["pathClass"]) is str, "http-label-types")
    integer(event["epoch"])
    digest(event["planSHA256"], empty=True)
    require(event["epoch"] == 0 or bool(event["planSHA256"]), "http-plan")
    require(event["pathClass"] in ("latest", "generation", "invalid"), "path-class")
    integer(event["generation"], 1 if event["pathClass"] == "generation" else 0)
    require(event["pathClass"] == "generation" or event["generation"] == 0, "path-generation")
    require(event["mode"] in MODES, "mode")
    integer(event["status"], 0, 599)
    digest(event["representationSHA256"])
    digest(event["wireSHA256"])
    integer(event["representationBytes"], 0, MAX_BODY)
    integer(event["wireBytes"], 0, MAX_WIRE)
    integer(event["writtenBytes"], 0, event["wireBytes"])
    require(event["wireComplete"] is (event["writtenBytes"] == event["wireBytes"]), "wire-completion")
    require(event["reason"] == "planned" or event["reason"] in HTTP_REJECTIONS, "http-reason")
    if event["reason"] != "planned":
        require(event["mode"] == "unavailable" and event["status"] == 503, "rejection-response")
    else:
        require(event["epoch"] > 0 and bool(event["planSHA256"])
                and event["pathClass"] != "invalid" and not event["authPresent"], "planned-http")
    if event["authPresent"]:
        # Parsing, method and plan failures can precede the auth refusal.
        require(event["reason"] in HTTP_REJECTIONS, "sensitive-request")
    if event["reason"] == "plan-unavailable":
        require(event["epoch"] == 0 and event["planSHA256"] == "", "unavailable-plan")
    if event["reason"] == "plan-invalid":
        require(event["epoch"] == 0 and bool(event["planSHA256"]), "invalid-plan")


def expected_wire(mode, body):
    """Independent protocol formula: never call the fixture's wire builder."""
    require(mode in MODES and type(body) is bytes, "wire-input")
    if mode == "close-before-headers":
        return 0, b"", b""
    status = {"forbidden": 403, "unavailable": 503, "redirect": 302, "stall-headers": 503}.get(mode, 200)
    representation = {"forbidden": b'{"code":"fixture_source_forbidden"}\n',
                      "unavailable": ERROR_BODY, "redirect": b'{"code":"fixture_source_redirect"}\n',
                      "stall-headers": ERROR_BODY}.get(mode, body)
    reason = {200: "OK", 403: "Forbidden", 503: "Service Unavailable", 302: "Found"}[status]
    headers = [f"HTTP/1.1 {status} {reason}\r\n".encode()]
    if mode != "content-type-missing":
        headers.append(b"Content-Type: text/plain\r\n" if mode == "content-type-wrong" else b"Content-Type: application/json\r\n")
    if mode == "content-type-duplicate":
        headers.append(b"Content-Type: application/json\r\n")
    if mode == "chunked":
        headers.append(b"Transfer-Encoding: chunked\r\n")
    elif mode != "length-missing":
        size = 0 if mode == "length-zero" else 262145 if mode == "length-oversize" else max(0, len(representation) - 1) if mode == "length-short" else len(representation)
        headers.append(f"Content-Length: {size}\r\n".encode())
    if mode == "redirect":
        headers.append(b"Location: https://redirect.fixture.invalid/blocked\r\n")
    elif mode == "content-encoding":
        headers.append(b"Content-Encoding: identity\r\n")
    elif mode == "trailer":
        headers.append(b"Trailer: X-Fixture-Trailer\r\n")
    elif mode == "header-oversize":
        headers.append(b"X-Fixture-Padding: " + b"x" * 17408 + b"\r\n")
    headers.extend((b"Cache-Control: no-store\r\n", b"Connection: close\r\n", b"\r\n"))
    payload = representation
    if mode == "chunked":
        payload = f"{len(representation):x}\r\n".encode() + representation + b"\r\n0\r\n\r\n"
    elif mode == "body-truncated":
        payload = representation[:-1]
    return status, representation, b"".join(headers) + payload


def verify_wire(event, label):
    body = b"x" * MAX_BODY if label == "body-boundary" else DEFAULT_BODY
    status, representation, wire = expected_wire(event["mode"], body)
    require(event["status"] == status and event["representationBytes"] == len(representation)
            and event["representationSHA256"] == sha(representation)
            and event["wireBytes"] == len(wire) and event["wireSHA256"] == sha(wire), "wire-bytes")


def plan_bytes(epoch, mode="json", body=DEFAULT_BODY, both_paths=False):
    response = {"mode": mode, "bodySHA256": "" if mode in NO_BODY_MODES else sha(body)}
    responses = {"latest.json": response}
    if both_paths:
        responses["2.json"] = dict(response)
    return encoded({"schema": "chengwang.product-source-plan/v1", "epoch": epoch, "responses": responses})


def verify_plan(event, label):
    if label == "epoch-sequence":
        # Exact sequence and the one deliberate same-epoch byte conflict are
        # checked together, below, rather than assuming global epoch ordering.
        return
    if label == "body-mismatch" and event["reason"] == "plan-unavailable":
        require(event["epoch"] == 0 and event["planSHA256"] == "", "replaced-body-plan")
        return
    mode = label if label in MODES else "json"
    body = b"x" * MAX_BODY if label == "body-boundary" else DEFAULT_BODY
    require(event["epoch"] == 1 and event["planSHA256"] == sha(plan_bytes(1, mode, body, label == "normal")), "plan-bytes")


def native_source_tests(raw):
    try:
        names = prerequisite.expected_tests(raw)
    except (ValueError, SyntaxError, UnicodeError):
        raise Rejected("native-test-source") from None
    require(len(names) == NATIVE_TEST_COUNT and {n for n in names if n.startswith("LinuxTests.")}
            == {"LinuxTests." + name for name in CASE_LABELS}, "native-test-set")
    require(len([name for name in names if name.startswith("ShapeTests.")]) == 8, "shape-test-set")
    return names


def verify_observations(raw, native_source):
    native_source_tests(native_source)
    value = parse(raw)
    exact(value, ("schema", "cases"))
    require(value["schema"] == "chengwang.product-source-observations/v1" and type(value["cases"]) is list, "observations-schema")
    expected = {(name, label) for name, labels in CASE_LABELS.items() for label in labels}
    require(len(value["cases"]) == len(expected), "observation-count")
    seen, summaries = set(), []
    for case in value["cases"]:
        exact(case, ("testName", "label", "events"))
        require(type(case["testName"]) is str and type(case["label"]) is str, "case-identity")
        pair = (case["testName"], case["label"])
        require(pair in expected and pair not in seen, "case-set")
        seen.add(pair)
        summary = verify_connections(case["events"])
        http = [e for e in case["events"] if e["event"] == "http"]
        for event in http:
            verify_wire(event, case["label"])
            verify_plan(event, case["label"])
        if case["label"] not in ("stop-term", "stop-int", "deadline", "capacity-stop", "stall-body"):
            require(all(e["wireComplete"] for e in http), "unexpected-incomplete-wire")
        verify_capability(case["label"], case["events"], summary)
        summaries.append({"testName": pair[0], "label": pair[1], "events": len(case["events"]),
                          "eventsSHA256": sha(encoded(case["events"])), **summary})
    require(seen == expected, "missing-observation")
    return {"schema": value["schema"], "sha256": sha(raw), "cases": sorted(summaries, key=lambda item: (item["testName"], item["label"]))}


def verify_capability(label, events, summary):
    http = [event for event in events if event["event"] == "http"]
    if label in MODES:
        require(any(e["mode"] == label and e["reason"] == "planned" and e["wireComplete"] for e in http), "missing-wire-mode")
        require(len(http) == (2 if label == "stall-body" else 1)
                and all(e["mode"] == label and e["reason"] == "planned" for e in http), "wire-mode-count")
        if label == "stall-body":
            require(http[0]["wireComplete"] and not http[1]["wireComplete"], "stall-cancellation")
            _, _, wire = expected_wire(label, DEFAULT_BODY)
            expected_written = wire.index(b"\r\n\r\n") + 4
            require(http[1]["writtenBytes"] == expected_written
                    and any(e["event"] == "close" and e["reason"] == "stopping"
                            and e["connection"] == http[1]["connection"] for e in events), "stall-stop-window")
    elif label in ("wrong-ca", "wrong-san"):
        require(not http and summary["tlsFailed"] >= 1, "missing-tls-refusal")
    elif label == "normal":
        require([(e["pathClass"], e["generation"]) for e in http] == [("latest", 0), ("generation", 2)]
                and all(e["reason"] == "planned" and e["mode"] == "json" and e["wireComplete"] for e in http), "normal-paths")
    elif label in ("stop-term", "stop-int", "deadline"):
        require(any(e["event"] == "close" and e["reason"] == "stopping" for e in events), "missing-stop")
        require((label == "stop-int" or not http) and all(e["reason"] == "stopping" for e in http), "stop-http")
    elif label == "epoch-sequence":
        expected = [(1, "planned", sha(plan_bytes(1))), (2, "planned", sha(plan_bytes(2))),
                    (2, "epoch-conflict", sha(plan_bytes(2) + b" ")),
                    (1, "epoch-rollback", sha(plan_bytes(1))), (3, "planned", sha(plan_bytes(3)))]
        require([(e["epoch"], e["reason"], e["planSHA256"]) for e in http] == expected
                and all(e["wireComplete"] and e["pathClass"] == "latest" for e in http), "epoch-capability")
    elif label == "sensitive-request":
        require(any(e["reason"] == "auth-present" and e["authPresent"] for e in http)
                and any(e["reason"] == "request-invalid" and e["pathClass"] == "invalid" for e in http)
                and any(e["reason"] == "method-invalid" for e in http), "request-capability")
    elif label == "body-mismatch":
        require([e["reason"] for e in http] == ["planned", "body-mismatch", "plan-unavailable"], "body-mismatch")
    elif label == "missing-body":
        require([e["reason"] for e in http] == ["planned", "body-unavailable"], "body-unavailable")
    elif label == "capacity-stop":
        ninth = [e for e in events if e["connection"] == 9]
        require(not http and summary["connections"] == 9
                and [e["event"] for e in ninth] == ["connect", "close"]
                and ninth[-1]["reason"] == "closed" and not ninth[-1]["tls"], "capacity-ninth")
        before_refusal = events[:ninth[-1]["ordinal"] - 1]
        require(all([e["event"] for e in before_refusal if e["connection"] == number] == ["connect"]
                    for number in range(1, 9)), "capacity-before-stop")
    else:
        require(label in ("ready-atomic", "fixed-port-first", "fixed-port-second", "body-boundary")
                and bool(http) and all(e["reason"] == "planned" and e["mode"] == "json" and e["wireComplete"] for e in http), "positive-capability")


def verify_artifacts(inputs, sources, source_commit):
    require(type(source_commit) is str and re.fullmatch(r"[a-f0-9]{40}", source_commit), "source-commit")
    exact(inputs, INPUT_NAMES)
    exact(sources, SOURCE_PATHS)
    require(all(type(raw) is bytes and 0 < len(raw) <= 2 << 20 for raw in sources.values()), "source-bytes")
    native = sources[BASE + "test_fixture_source.py"]
    native_source_tests(native)
    checker = sources[BASE + "test_check_source_preflight.py"]
    require(len(prerequisite.expected_tests(checker)) == CHECKER_TEST_COUNT, "checker-test-set")
    suites = [verify_transcript(inputs[INPUT_NAMES[0]], native, "fixture"),
              verify_transcript(inputs[INPUT_NAMES[1]], checker, "checker")]
    observations = verify_observations(inputs[INPUT_NAMES[2]], native)
    cleanup = verify_cleanup(inputs[INPUT_NAMES[3]])
    return {"schema": "chengwang.product-source-preflight/v1", "sourceCommit": source_commit,
            "outcome": "PASS", "sources": [{"path": path, "sha256": sha(sources[path])} for path in SOURCE_PATHS],
            "suites": suites, "observations": observations, "cleanup": cleanup,
            "evidenceSHA256": {name: sha(inputs[name]) for name in INPUT_NAMES},
            "authorization": "BLOCKED", "production": False, "deviceActionsExecuted": False,
            "fixturePrerequisitesOnly": True, "actualProductSourceMatrixProven": False,
            "productTLSRefusalProven": False, "productAutomaticRefreshProven": False,
            "wireFormulaIndependentlyRecomputed": True, "serverWriteIsNotClientAcceptance": True}


def read_file(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit, "input-file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns), "opened-input")
        raw = handle.read(limit + 1)
        finished = os.fstat(handle.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns), "input-changed")
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == before.st_size, "input-changed")
    return raw


def verify(args):
    root, directory = pathlib.Path(args.source_root), pathlib.Path(args.evidence_dir)
    require(root.is_absolute() and root.resolve() == root and directory.is_absolute()
            and directory.resolve() == directory, "paths")
    require(type(args.source_commit) is str and re.fullmatch(r"[a-f0-9]{40}", args.source_commit), "source-commit")
    git = shutil.which("git")
    require(bool(git), "git-missing")
    command = [git, "-c", "safe.directory=" + str(root), "-C", str(root)]
    head = subprocess.check_output(command + ["rev-parse", "HEAD"], timeout=5).decode("ascii").strip()
    require(head == args.source_commit, "source-head")
    sources = {path: subprocess.check_output(command + ["cat-file", "blob", args.source_commit + ":" + path], timeout=5)
               for path in SOURCE_PATHS}
    names = {entry.name for entry in directory.iterdir() if entry.name.startswith("product-source-")}
    require(set(INPUT_NAMES) <= names <= set(INPUT_NAMES) | {OUTPUT_NAME}, "input-name-set")
    inputs = {name: read_file(directory / name, 8 << 20) for name in INPUT_NAMES}
    return verify_artifacts(inputs, sources, args.source_commit)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise SystemExit("D12_SOURCE_PREFLIGHT_CHECK=FAIL")


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args)
    except (Rejected, prerequisite.Rejected, OSError, ValueError, TypeError, KeyError,
            RecursionError, subprocess.SubprocessError):
        raise SystemExit("D12_SOURCE_PREFLIGHT_CHECK=FAIL") from None
    print(encoded(result).decode("ascii"))


if __name__ == "__main__":
    main()
