#!/usr/bin/env python3
"""Independent wave-1 product-source evidence replay; never release authority.

Reviewer replay uses safe graph projections, not private graph/database bytes.
Public catalogue and approval signatures are independently verified by OpenSSL.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
import check_product_image as image
import check_product_registry as registry
import check_product_lifecycle as lifecycle
import check_source_preflight as wirecheck
import check_lifecycle_preflight as preflight

CheckError = image.CheckError
require, exact, integer = image.require, registry.exact, registry.integer
digest, bare_hash = registry.digest, registry.bare_hash
BOUNDARY, KINDS = registry.BOUNDARY, registry.KINDS
FLOWS = ("http-recovery", "bad-signature", "prefix-recovery")
ACTIONS = ("prepare", "run", "reopen")
BASE = "chengwang/deploy/product-candidate/"
HARNESS_PATHS = tuple(BASE + n for n in (
    "check_product_source.py", "check_product_image.py", "check_product_registry.py",
    "check_product_lifecycle.py", "check_source_preflight.py", "check_lifecycle_preflight.py",
    "fixture_source.py", "fixture_feed.py", "test_check_product_source.py", "test_source_image_profile.py"))
MATERIAL_FIELDS = (*lifecycle.MATERIAL_FIELDS, "anchorRaw", "approvalRaw", "catalogues")
POLICY_FIELDS = ("name", "policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256",
                 "bundleSHA256", "bundleArtifactSHA256", "trustedRootSHA256", "registrySPKI")
REPORT_FIELDS = ("schema", "sourceCommit", "localImageID", "flow", "kind", "action", *BOUNDARY,
                 "material", "observations", "feedPlans", "offline")
CORPUS = ("g1", "g2", "g3", "bad-g2", "bad-g3")
DOCUMENT_FIELDS = ("schema", "storeID", "generation", "notBeforeUnix", "notAfterUnix", "rootKeys",
                   "threshold", "approvers", "grants", "policyFloors", "revokedKeys", "revokedApprovals", "revokedManifests")
OBSERVATIONS = {
    "http-recovery": (("unconfirmed", 1, 1, 0, False), ("confirmed", 1, 1, 0, True),
                      ("forbidden", 1, 1, 0, None), ("stale", 1, 1, 0, False), ("recovered", 1, 1, 0, True)),
    "bad-signature": (("confirmed", 1, 1, 0, True), ("rejected", 5, 1, 1, None),
                      ("deduplicated", 5, 1, 1, None), ("stale", 5, 1, 1, False), ("recovered", 9, 2, 2, True)),
    "prefix-recovery": (("confirmed", 1, 1, 0, True), ("prefix-rejected", 9, 2, 2, False),
                        ("deduplicated", 9, 2, 2, False), ("recovered", 13, 3, 3, True)),
}
PLAN_NAMES = {"http-recovery": (("forbidden",), ("g1",), ("forbidden",), ("g1",)),
              "bad-signature": (("g1",), ("bad-g2",), ("g2",)),
              "prefix-recovery": (("g1",), ("bad-g3", "g2"), ("g3",))}
OPERATIONS = {"http-recovery": (), "bad-signature": (("bad-g2", False), ("g2", True)),
              "prefix-recovery": (("g2", True), ("bad-g3", False), ("g3", True))}
SUPPORT_NAMES = frozenset(("product-source-profile-tests.log", "product-source-verifier-tests.log"))
FIXTURE_NAMES = frozenset("product-source-fixture-" + n for n in (
    "tests.log", "checker-tests.log", "observations.json", "cleanup.json", "preflight.json"))


def encoded(value, *, ordered=False):
    return lifecycle.encoded(value, ordered=ordered)


def parse(raw):
    try:
        return wirecheck.parse(raw)
    except wirecheck.Rejected as error:
        raise CheckError("strict public JSON rejected") from error


def binary(value, maximum=256 << 10):
    require(type(value) is str and len(value) <= (maximum + 2) // 3 * 4, "public bytes rejected")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CheckError("public bytes rejected") from error
    require(len(raw) <= maximum and base64.b64encode(raw).decode() == value, "noncanonical public bytes")
    return raw


def prefixed(raw):
    return "sha256:" + image.sha(raw)


def openssl_path():
    executable = shutil.which("openssl")
    if executable:
        return executable
    git = shutil.which("git")
    if git:
        candidate = pathlib.Path(git).parent.parent / "usr" / "bin" / "openssl.exe"
        if candidate.is_file():
            return str(candidate)
    raise CheckError("independent signature verifier unavailable")


def signature(public, message, signed):
    require(type(public) is bytes and len(public) == 32 and type(signed) is bytes and len(signed) == 64
            and type(message) is bytes and len(message) <= (256 << 10) + 128, "signature inputs rejected")
    # Only public synthetic bytes enter this owned, bounded temporary directory.
    with tempfile.TemporaryDirectory(prefix="chengwang-source-signature-") as directory:
        root = pathlib.Path(directory)
        for name, raw in (("key.der", bytes.fromhex("302a300506032b6570032100") + public),
                          ("message.bin", message), ("signature.bin", signed)):
            image.write_exclusive(root / name, raw)
        try:
            result = subprocess.run([openssl_path(), "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", str(root / "key.der"), "-rawin", "-in", str(root / "message.bin"),
                "-sigfile", str(root / "signature.bin")], capture_output=True, timeout=5, check=False)
        except (subprocess.SubprocessError, OSError) as error:
            raise CheckError("independent signature verification failed") from error
        require(result.returncode in (0, 1) and len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
                "independent signature verifier failed")
        return result.returncode == 0


def keys(value):
    require(type(value) is list and len(value) == 1, "single public root required")
    key = value[0]
    exact(key, ("id", "publicKey"))
    raw = binary(key["publicKey"], 32)
    require(len(raw) == 32 and key["id"] == image.sha(raw), "public key identity mismatch")
    return key["id"], raw


def material(value, kind, source, local_id, graph):
    exact(value, MATERIAL_FIELDS)
    require(value["kind"] == kind and value["sourceCommit"] == source
            and value["configSHA256"] == value["localImageID"] == local_id
            and value["manifestSHA256"] == graph["registryManifestDigest"]
            and value["layerSHA256s"] == [x["digest"] for x in graph["layerDescriptors"]]
            and value["diffIDs"] == [x["diffID"] for x in graph["layerDescriptors"]]
            and re.fullmatch(r"[0-9a-f]{32}", value["storeID"]), "public material graph mismatch")
    require(value["feedURL"] == lifecycle.FEED_URL, "fixed source URL changed")
    for name, expected in (("refreshIntervalSeconds", 2), ("refreshMaxAgeSeconds", 15), ("refreshTimeoutSeconds", 2)):
        require(type(value[name]) is int and value[name] == expected, "refresh budget changed")
    digest(value["feedSPKI"]); digest(value["feedCASHA256"])
    require(type(value["policies"]) is list and len(value["policies"]) == 1, "one source policy required")
    policy = value["policies"][0]
    exact(policy, POLICY_FIELDS)
    require(policy["name"] == "a" and policy["policyID"] == "d12-source-policy", "source policy changed")
    registry.public_id(policy["grantID"])
    for name in POLICY_FIELDS[3:]:
        digest(policy[name])
    require(policy["bundleArtifactSHA256"] == value["manifestSHA256"]
            and policy["registrySPKI"] != value["feedSPKI"], "signature or TLS roles conflated")
    anchor = parse(binary(value["anchorRaw"]))
    exact(anchor, ("storeID", "initialSHA256", "keys", "threshold"))
    require(anchor["storeID"] == value["storeID"] and type(anchor["threshold"]) is int and anchor["threshold"] == 1,
            "provisioning anchor mismatch")
    key_id, public = keys(anchor["keys"])
    require(type(value["catalogues"]) is list and len(value["catalogues"]) == 5, "public catalogue corpus incomplete")
    corpus, documents, envelopes = {}, {}, {}
    for record, name in zip(value["catalogues"], CORPUS):
        exact(record, ("name", "generation", "raw", "sha256"))
        raw = binary(record["raw"])
        generation = int(name[-1])
        require(record["name"] == name and type(record["generation"]) is int and record["generation"] == generation
                and record["sha256"] == prefixed(raw), "raw catalogue identity mismatch")
        envelope = parse(raw)
        exact(envelope, ("payload", "signatures"))
        require(type(envelope["signatures"]) is list and len(envelope["signatures"]) == 1, "single catalogue signature required")
        signed = envelope["signatures"][0]
        exact(signed, ("keyID", "signature"))
        payload, sig = binary(envelope["payload"]), binary(signed["signature"], 64)
        require(signed["keyID"] == key_id and len(sig) == 64, "catalogue signer mismatch")
        doc = parse(payload)
        exact(doc, DOCUMENT_FIELDS)
        require(doc["schema"] == "chengwang.trust-catalog/v1" and doc["storeID"] == value["storeID"]
                and type(doc["generation"]) is int and doc["generation"] == generation
                and doc["rootKeys"] == anchor["keys"] and type(doc["threshold"]) is int and doc["threshold"] == 1,
                "catalogue document authority changed")
        integer(doc["notBeforeUnix"], 1); integer(doc["notAfterUnix"], doc["notBeforeUnix"] + 1)
        approver_id, _ = keys(doc["approvers"])
        grant = {"id": policy["grantID"], "policyID": policy["policyID"], "approvalSHA256": policy["approvalSHA256"],
                 "approverKeyID": approver_id, "manifestSHA256": value["manifestSHA256"], "revision": 1}
        require(doc["grants"] == [grant] and type(doc["grants"][0]["revision"]) is int
                and doc["policyFloors"] == {policy["policyID"]: 1} and type(doc["policyFloors"][policy["policyID"]]) is int
                and doc["revokedKeys"] == doc["revokedApprovals"] == doc["revokedManifests"] == [],
                "source catalogue grant corpus changed")
        require(signature(public, b"chengwang.trust-catalog/v1\0" + payload, sig) is (not name.startswith("bad-")),
                "independent catalogue signature mismatch")
        corpus[name], documents[name], envelopes[name] = raw, doc, envelope
    require(anchor["initialSHA256"] == value["catalogue1SHA256"] == prefixed(corpus["g1"])
            and value["catalogue2SHA256"] == prefixed(corpus["g2"]), "anchor raw catalogue mismatch")
    for name in CORPUS[1:]:
        require({k: v for k, v in documents[name].items() if k != "generation"}
                == {k: v for k, v in documents["g1"].items() if k != "generation"}, "catalogue changed beyond generation")
    for name in ("g2", "g3"):
        valid, bad = envelopes[name], envelopes["bad-" + name]
        sig = bytearray(binary(valid["signatures"][0]["signature"], 64)); sig[0] ^= 1
        expected = {"payload": valid["payload"], "signatures": [{"keyID": key_id, "signature": base64.b64encode(sig).decode()}]}
        require(bad == expected, "bad signature is not a single-byte mutation")
    approval_raw = binary(value["approvalRaw"])
    approval = parse(approval_raw)
    exact(approval, ("payload", "signature"))
    payload = binary(approval["payload"])
    approval_doc = parse(payload)
    exact(approval_doc, ("schema", "policyID", "revision", "approverKeyID", "notBeforeUnix", "notAfterUnix", "reference",
                         "os", "architecture", "variant", "registryIPs", "registrySPKISHA256", "signature"))
    approval_signature = approval_doc["signature"]
    require(type(approval_signature) is dict and {"artifactSHA256", "trustedRootSHA256", "logID", "issuer", "san", "kind"}
            <= set(approval_signature) <= {"artifactSHA256", "trustedRootSHA256", "logID", "issuer", "san", "kind", "subjectName", "predicateType"},
            "approval signature contract rejected")
    require(approval_doc["schema"] == "chengwang.image-approval/v1"
            and approval_doc["reference"] == "registry.fixture.invalid:5443/chengwang/product-candidate@" + value["manifestSHA256"]
            and approval_doc["os"] == "linux" and approval_doc["architecture"] == "amd64" and approval_doc["variant"] == ""
            and approval_doc["registryIPs"] == ["127.0.0.1"] and approval_doc["registrySPKISHA256"] == policy["registrySPKI"]
            and approval_signature["artifactSHA256"] == value["manifestSHA256"]
            and approval_signature["trustedRootSHA256"] == policy["trustedRootSHA256"], "signed approval graph/profile mismatch")
    integer(approval_doc["notBeforeUnix"], 1)
    integer(approval_doc["notAfterUnix"], approval_doc["notBeforeUnix"] + 1, approval_doc["notBeforeUnix"] + 86400)
    bare_hash(approval_signature["logID"])
    require(type(approval_signature["issuer"]) is str and re.fullmatch(r"https://[A-Za-z0-9./_-]{1,256}", approval_signature["issuer"])
            and type(approval_signature["san"]) is str and re.fullmatch(r"[A-Za-z0-9@./:_-]{1,256}", approval_signature["san"]),
            "signed approval public identity rejected")
    if kind == "message-signature":
        require(approval_signature.get("subjectName", "") == approval_signature.get("predicateType", "") == "", "message signature roles changed")
    else:
        require(approval_signature.get("subjectName") == "registry.fixture.invalid:5443/chengwang/product-candidate"
                and type(approval_signature.get("predicateType")) is str
                and re.fullmatch(r"https://[A-Za-z0-9./_-]{1,256}", approval_signature["predicateType"]), "DSSE subject binding rejected")
    approver_id, approver = keys(documents["g1"]["approvers"])
    require(prefixed(approval_raw) == policy["approvalEnvelopeSHA256"] and prefixed(payload) == policy["approvalSHA256"]
            and approval_doc.get("policyID") == policy["policyID"] and approval_doc.get("approverKeyID") == approver_id
            and approval_doc.get("revision") == 1 and type(approval_doc.get("revision")) is int
            and approval_doc.get("signature", {}).get("kind") == kind
            and signature(approver, b"chengwang.image-approval/v1\0" + payload, binary(approval["signature"], 64)),
            "independent approval signature mismatch")
    return corpus, documents


def plan_records(prepare, running, flow, corpus):
    plans = [*prepare, *running]
    require(type(prepare) is list and len(prepare) == 1 and type(running) is list
            and len(plans) == len(PLAN_NAMES[flow]), "source plan stages incomplete")
    result = {}
    for epoch, (record, names) in enumerate(zip(plans, PLAN_NAMES[flow]), 1):
        exact(record, ("epoch", "raw", "sha256"))
        responses = {}
        for path, name in zip(("latest.json", "2.json"), names):
            responses[path] = {"mode": "forbidden" if name == "forbidden" else "json",
                               "bodySHA256": "" if name == "forbidden" else image.sha(corpus[name])}
        expected = {"schema": "chengwang.product-source-plan/v1", "epoch": epoch, "responses": responses}
        raw = binary(record["raw"])
        require(type(record["epoch"]) is int and record["epoch"] == epoch and raw == encoded(expected)
                and record["sha256"] == prefixed(raw), "actual source plan raw bytes mismatch")
        result[epoch] = (expected, image.sha(raw))
    return result


def fence(value, raw_lines):
    exact(value, ("eventCount", "sha256"))
    count = integer(value["eventCount"], 0, len(raw_lines))
    require(value["sha256"] == image.sha(b"".join(raw_lines[:count])), "source fence prefix mismatch")
    return count


def source_events(raw, plans, corpus, windows):
    require(type(raw) is bytes and 0 < len(raw) <= 4 << 20 and raw.endswith(b"\n"), "complete original source log required")
    lines = raw.splitlines(keepends=True)
    events = [parse(line) for line in lines]
    try:
        summary = wirecheck.verify_connections(events)
    except wirecheck.Rejected as error:
        raise CheckError("source connection state machine rejected") from error
    require(type(windows) is list and len(windows) == 1, "one exact product stop window required")
    window = windows[0]
    exact(window, ("label", "before", "after"))
    require(window["label"] == "final", "source stop label mismatch")
    before, after = fence(window["before"], lines), fence(window["after"], lines)
    require(before <= after == len(lines), "source stop window omits final events")
    bodies = {image.sha(value): value for value in corpus.values()}
    incomplete, error_partial, complete = 0, 0, []
    for event in events:
        if event["event"] != "http":
            continue
        require(event["reason"] == "planned" and event["epoch"] in plans and not event["authPresent"],
                "unexpected product source request failure")
        plan, plan_hash = plans[event["epoch"]]
        path = "latest.json" if event["pathClass"] == "latest" else str(event["generation"]) + ".json"
        require(event["planSHA256"] == plan_hash and path in plan["responses"], "source response unbound to original plan")
        response = plan["responses"][path]
        mode = response["mode"]
        body = bodies[response["bodySHA256"]] if mode == "json" else b'{"code":"fixture_source_forbidden"}\n'
        code = 200 if mode == "json" else 403
        reason = "OK" if code == 200 else "Forbidden"
        wire = (f"HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                "Cache-Control: no-store\r\nConnection: close\r\n\r\n").encode() + body
        require(event["mode"] == mode and event["status"] == code
                and event["representationBytes"] == len(body) and event["representationSHA256"] == image.sha(body)
                and event["wireBytes"] == len(wire) and event["wireSHA256"] == image.sha(wire),
                "independent raw response wire mismatch")
        if event["wireComplete"]:
            complete.append(event)
        elif code == 403 and event["writtenBytes"] >= len(wire) - len(body):
            # A client may stop reading after a rejected HTTP status. Complete
            # response headers prove the 403; they do not prove body delivery.
            error_partial += 1
            complete.append(event)
        else:
            require(before < event["ordinal"] <= after and event["writtenBytes"] < len(wire), "incomplete response outside product stop")
            incomplete += 1
    summary["completeHTTPResponses"] = sum(event["wireComplete"] for event in complete)
    summary["errorBodyNotFullyWritten"] = error_partial
    summary["incompleteResponsesDuringStop"] = incomplete
    return events, lines, complete, summary


def status(value, wanted, info, docs):
    name, sequence, generation, total, fresh = wanted
    exact(value, registry.STATUS_FIELDS)
    require(value["boundary"] == "ADVISORY_TRUST_POLICY_STATE" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and value["healthy"] is True and value["fresh"] is True
            and value["storeId"] == info["storeID"] and value["refreshRequired"] is True
            and type(value["refreshFresh"]) is bool, "source API authority boundary rejected")
    for field, expected in {"sequence": sequence, "generation": generation, "ledgerEntries": 0, "reserved": 0,
                            "consumed": 0, "revokedKeys": 0, "revokedApprovals": 0, "revokedManifests": 0,
                            "recoveryCompleted": 0}.items():
        require(type(value[field]) is int and value[field] == expected, "source durable API counts rejected")
    require(value["catalogueSHA256"] == next(c["sha256"] for c in info["catalogues"] if c["name"] == "g" + str(generation)),
            "source API raw catalogue mismatch")
    integer(value["ledgerCapacity"], 1, 1 << 20)
    observed = integer(value["observedAtUnix"], 1)
    integer(value["auditVerifiedAtUnix"], 1, observed)
    doc = docs["g" + str(generation)]
    require(doc["notBeforeUnix"] <= observed < value["notAfterUnix"] == doc["notAfterUnix"], "catalogue time window rejected")
    last, until = integer(value["refreshLastSuccessUnix"], 0, observed), integer(value["refreshUntilUnix"], 0)
    require(until == (min(last + 15, value["notAfterUnix"]) if last else 0), "source freshness deadline forged")
    if value["refreshFresh"]:
        require(last > 0 and observed <= until, "source freshness expired")
    if fresh is not None:
        require(value["refreshFresh"] is fresh, "source freshness transition missing")
    if name == "unconfirmed":
        require(last == until == 0, "HTTP refusal created a confirmation")
    if name == "stale":
        require(last > 0 and observed > until, "natural freshness expiry not observed")
    policy = info["policies"][0]
    require(value["policies"] == [{"policyId": policy["policyID"], "grantId": policy["grantID"], "revision": 1,
             "manifestSHA256": info["manifestSHA256"], "state": "AVAILABLE"}]
            and type(value["policies"][0]["revision"]) is int, "source flow consumed or reserved grant")


def history(value, wanted):
    _, sequence, generation, total, _ = wanted
    exact(value, registry.HISTORY_FIELDS)
    require(value["boundary"] == "ADVISORY_TRUST_OPERATION_HISTORY" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and type(value["sequence"]) is int and value["sequence"] == sequence
            and type(value["total"]) is int and value["total"] == total and type(value["offset"]) is int and value["offset"] == 0
            and type(value["limit"]) is int and value["limit"] == 50 and type(value["entries"]) is list
            and len(value["entries"]) == total, "source complete paginated history tally rejected")
    integer(value["observedAtUnix"], 1)
    entries = {}
    for row in value["entries"]:
        exact(row, registry.ENTRY_FIELDS)
        identifier = registry.public_id(row["operationId"])
        require(identifier not in entries and row["acknowledged"] is True, "source history duplicate or missing ACK")
        entries[identifier] = row
        require(row["actorId"] == "image-trust-refresh" and row["kind"] == "update"
                and row["policyId"] == row["grantId"] == "", "nonautomatic operation in source history")
        bare_hash(row["preparedAuditHash"]); bare_hash(row["resultAuditHash"])
        integer(row["preparedAtUnix"], 1); integer(row["resultAtUnix"], row["preparedAtUnix"])
        integer(row["generation"], 0, 3)
        require((row["state"], row["outcome"]) in (("COMMITTED", "CATALOGUE_COMMITTED"), ("PREPARED", "REJECTED")),
                "source history outcome rejected")
    return entries


def observations(reports, flow, info, docs, lines, complete):
    rows = reports["run"]["observations"]
    require(type(rows) is list and len(rows) == len(OBSERVATIONS[flow]), "source API observation stages incomplete")
    prefixes, previous_history, prior_count = {}, {}, 0
    by_name = {}
    for row, wanted in zip(rows, OBSERVATIONS[flow]):
        exact(row, ("name", "status", "history", "sourceFence"))
        require(row["name"] == wanted[0], "source observation name changed")
        status(row["status"], wanted, info, docs)
        current_history = history(row["history"], wanted)
        require(all(identifier in current_history and current_history[identifier] == entry
                    for identifier, entry in previous_history.items()), "already-ACKed history changed")
        previous_history = current_history
        count = fence(row["sourceFence"], lines)
        require(count >= prior_count, "source observation fence moved backwards")
        prior_count = count
        prefixes[row["name"]], by_name[row["name"]] = count, row
    # Positive source evidence is the complete real HTTP event, never a plan,
    # arbitrary polling count, incomplete response or driver Fresh conclusion.
    def count(epoch, name, before_name, after_name=None):
        low = prefixes[before_name] if before_name else 0
        high = prefixes[after_name] if after_name else len(lines)
        sha = image.sha(next(binary(c["raw"]) for c in info["catalogues"] if c["name"] == name)) if name else None
        return sum(low < e["ordinal"] <= high and e["epoch"] == epoch
                   and (e["status"] == 403 if name is None else e["status"] == 200 and e["representationSHA256"] == sha)
                   for e in complete)
    if flow == "http-recovery":
        require(count(1, None, None, "unconfirmed") >= 2 and count(2, "g1", None, "confirmed") >= 1
                and count(3, None, None, "forbidden") >= 2 and count(4, "g1", None, "recovered") >= 1,
                "HTTP refusal or restoration lacks completed source responses")
        baseline, ending = by_name["forbidden"], by_name["stale"]
    else:
        rejected = "rejected" if flow == "bad-signature" else "prefix-rejected"
        bad = "bad-g2" if flow == "bad-signature" else "bad-g3"
        final = "g2" if flow == "bad-signature" else "g3"
        require(count(1, "g1", None, "confirmed") >= 1 and count(2, bad, None, rejected) >= 1
                and count(2, bad, rejected, "deduplicated") >= 3 and count(3, final, None, "recovered") >= 1,
                "bad-signature suppression lacks completed repeated raw responses")
        if flow == "prefix-recovery":
            require(count(2, "g2", None, rejected) >= 1, "valid fetched prefix absent")
        baseline, ending = by_name[rejected], by_name["deduplicated"]
        for other in (by_name["deduplicated"], *([by_name["stale"]] if flow == "bad-signature" else [])):
            require(all(other["status"][key] == baseline["status"][key]
                        for key in ("refreshLastSuccessUnix", "refreshUntilUnix"))
                    and other["history"]["entries"] == baseline["history"]["entries"],
                    "repeated rejected candidate wrote state or renewed freshness")
    if flow == "http-recovery":
        require(all(ending["status"][key] == baseline["status"][key]
                    for key in ("refreshLastSuccessUnix", "refreshUntilUnix")), "HTTP failures renewed freshness")
    require(by_name["recovered"]["status"]["refreshLastSuccessUnix"] > baseline["status"]["refreshLastSuccessUnix"],
            "restoration did not establish a new real confirmation")
    return rows[-1]


def raw_hash(value, raw):
    exact(value, ("bytes", "sha256"))
    require(type(value["bytes"]) is int and value["bytes"] == len(raw) and value["sha256"] == image.sha(raw),
            "raw durable bytes digest mismatch")


def offline(value, last, info, flow, corpus, docs):
    exact(value, ("inspection", "journal", "audit", "auditEvents", "auditBindings", "auditLog", "checkpoint", "trustRecordSHA256"))
    bare_hash(value["trustRecordSHA256"])
    inspection, audit, journal = value["inspection"], value["audit"], value["journal"]
    final = OBSERVATIONS[flow][-1]
    _, sequence, generation, total, _ = final
    exact(inspection, ("authorization", "catalogue", "catalogueValid", "sequence", "ledgerCapacity", "ledgerUsed", "ledgerRemaining", "consumptions"))
    require(inspection["authorization"] == "BLOCKED" and inspection["catalogueValid"] is True
            and type(inspection["sequence"]) is int and inspection["sequence"] == sequence
            and inspection["ledgerCapacity"] == last["status"]["ledgerCapacity"]
            and type(inspection["ledgerCapacity"]) is int and type(inspection["ledgerUsed"]) is int
            and type(inspection["ledgerRemaining"]) is int and inspection["ledgerUsed"] == 0
            and inspection["ledgerRemaining"] == inspection["ledgerCapacity"] and inspection["consumptions"] == [],
            "offline source domain state rejected")
    doc = docs["g" + str(generation)]
    expected_catalogue = {"storeID": info["storeID"], "generation": generation, "sha256": prefixed(corpus["g" + str(generation)]),
        "notBeforeUnix": doc["notBeforeUnix"], "notAfterUnix": doc["notAfterUnix"], "rootKeyCount": 1, "rootThreshold": 1,
        "approverCount": 1, "grants": doc["grants"], "policyFloors": doc["policyFloors"],
        "revokedKeyCount": 0, "revokedApprovalCount": 0, "revokedManifestCount": 0}
    require(encoded(inspection["catalogue"]) == encoded(expected_catalogue), "offline catalogue differs from signed raw bytes")
    exact(audit, ("valid", "count", "expectedCount", "lastHash", "expectedLastHash", "verifiedAt"))
    require(audit["valid"] is True and type(audit["count"]) is int and type(audit["expectedCount"]) is int
            and audit["count"] == audit["expectedCount"] == total * 2, "offline audit tally rejected")
    lifecycle.event_time(audit["verifiedAt"])
    require(type(journal) is list and type(value["auditBindings"]) is list and type(value["auditEvents"]) is list
            and len(journal) == len(value["auditBindings"]) == total and len(value["auditEvents"]) == total * 2,
            "offline actual journal/audit set incomplete")
    old_history = {row["operationId"]: row for row in last["history"]["entries"]}
    scope = {"tenantId": "d12-tenant", "siteId": "d12-site", "objectType": "image-trust", "objectId": info["storeID"], "environment": "candidate"}
    scope_sha = prefixed(encoded(scope, ordered=True))
    ops, expected_events, prefixes = {}, {}, ["0" * 64]
    for entry, binding, (name, committed) in zip(journal, value["auditBindings"], OPERATIONS[flow]):
        exact(entry, ("operation", "state", "outcome", "outcomeData", "acknowledged", "resultAuditHash", "grantID",
                      "generation", "catalogueSHA256", "manifestSHA256", "evidenceSHA256"))
        op = entry["operation"]
        exact(op, ("id", "actorID", "scopeSHA256", "kind", "data", "auditBaseCount", "auditBaseHash", "preparedAuditHash"))
        identifier = registry.public_id(op["id"])
        require(identifier not in ops and identifier in old_history and op["actorID"] == "image-trust-refresh"
                and op["kind"] == "update" and op["scopeSHA256"] == scope_sha
                and op["data"] == {"catalogueSHA256": prefixed(corpus[name])}, "original automatic update request binding rejected")
        wanted_data = {"catalogueSHA256": prefixed(corpus[name])} if committed else {}
        require(entry["state"] == ("COMMITTED" if committed else "PREPARED")
                and entry["outcome"] == ("CATALOGUE_COMMITTED" if committed else "REJECTED")
                and entry["outcomeData"] == wanted_data and entry["acknowledged"] is True
                and type(entry["generation"]) is int and entry["generation"] == (docs[name]["generation"] if committed else 0)
                and entry["catalogueSHA256"] == (prefixed(corpus[name]) if committed else "")
                and entry["grantID"] == entry["manifestSHA256"] == entry["evidenceSHA256"] == "",
                "rejected update acquired domain state or committed prefix was lost")
        exact(binding, ("operationID", "prepared", "result"))
        require(binding["operationID"] == identifier, "audit binding identity mismatch")
        historical = old_history[identifier]
        for field, old_field in (("state", "state"), ("outcome", "outcome"), ("generation", "generation"),
                                 ("catalogueSHA256", "catalogueSHA256"), ("resultAuditHash", "resultAuditHash")):
            require(entry[field] == historical[old_field], "HTTP history and offline journal differ")
        require(historical["preparedAuditHash"] == op["preparedAuditHash"], "history prepared audit hash differs")
        ops[identifier] = (op, entry, binding, historical)
        for phase, data, result in (("prepared", op["data"], "prepared"),
                                    ("result", wanted_data, "completed" if committed else "rejected")):
            key = "image-trust/" + identifier + "/" + phase
            expected_events[key] = (op, phase, data, result, binding[phase])
    previous, event_ids, seen, serialized, positions = "0" * 64, set(), set(), [], {}
    for index, event in enumerate(value["auditEvents"], 1):
        key = event.get("idempotencyKey")
        require(key in expected_events and key not in seen, "unknown or duplicate actual audit event")
        op, phase, data, result, binding = expected_events[key]
        require(event == binding and event["id"] not in event_ids, "actual audit event/binding identity mismatch")
        when = lifecycle.audit_event(event, op, phase, previous, data,
            {"target": "image-trust/" + info["storeID"], "result": result})
        historical = ops[op["id"]][3]
        require(event["hash"] == (op["preparedAuditHash"] if phase == "prepared" else ops[op["id"]][1]["resultAuditHash"])
                and historical["preparedAtUnix" if phase == "prepared" else "resultAtUnix"] == when,
                "actual audit ACK/hash/time binding rejected")
        positions[(op["id"], phase)] = index
        previous = event["hash"]; prefixes.append(previous); seen.add(key); event_ids.add(event["id"])
        ordered = {field: event[field] for field in ("id", "idempotencyKey", "traceId", "actorId", "action", "target", "result", "occurredAt")}
        if data:
            ordered["data"] = dict(sorted(data.items()))
        ordered.update(previousHash=event["previousHash"], hash=event["hash"])
        serialized.append(encoded(ordered, ordered=True) + b"\n")
    require(seen == set(expected_events) and audit["lastHash"] == audit["expectedLastHash"] == previous,
            "audit chain/checkpoint final tail mismatch")
    for identifier, (op, _, _, _) in ops.items():
        base = integer(op["auditBaseCount"], 0, len(prefixes) - 1)
        require(base < positions[(identifier, "prepared")] < positions[(identifier, "result")]
                and op["auditBaseHash"] == prefixes[base], "operation original audit prefix or phase order rejected")
    raw_hash(value["auditLog"], b"".join(serialized))
    raw_hash(value["checkpoint"], encoded({"count": total * 2, "lastHash": previous}, ordered=True))
    return {"sequence": sequence, "generation": generation, "journalEntries": total, "auditEntries": total * 2, "ledgerEntries": 0}


def source_process(process, stopped, ready, source, flow, kind, harness):
    limits = {"cpuSeconds": 60, "addressSpaceBytes": 536870912, "fileBytes": 16777216,
              "openFiles": 128, "processes": 128, "coreBytes": 0}
    expected = {"schema": "chengwang.product-source-process/v1", "sourceCommit": source, "flow": flow, "kind": kind,
        "sourceCase": "source-" + flow, "uid": 10001, "gid": 10001, "capabilities": "none", "noNewPrivileges": True,
        "registryNetworkNamespaceMatched": True, "privateMountNamespace": True,
        "sourceSHA256": harness[BASE + "fixture_source.py"], "dependencySHA256": harness[BASE + "fixture_feed.py"],
        "gitBoundSourceMatched": True, "sourceLimitsVerified": True, "sourceLimits": limits, **BOUNDARY}
    exact(process, (*expected, "hostPID", "hostStartTime", "pythonExecutableSHA256"))
    require(all(type(process[k]) is type(v) and process[k] == v for k, v in expected.items())
            and encoded(process["sourceLimits"]) == encoded(limits), "actual source security profile rejected")
    pid = integer(process["hostPID"], 1); start = integer(process["hostStartTime"], 1)
    bare_hash(process["pythonExecutableSHA256"])
    expected_stop = {"schema": "chengwang.product-source-stop/v1", "sourceCommit": source, "flow": flow, "kind": kind,
        "sourceCase": "source-" + flow, "hostPID": pid, "startTime": start, "signal": "SIGTERM", "exitCode": 0,
        "joined": True, **BOUNDARY}
    exact(stopped, (*expected_stop, "productStopWindows"))
    require(all(type(stopped[k]) is type(v) and stopped[k] == v for k, v in expected_stop.items()), "owned source join not proven")
    exact(ready, ("schema", "port", "pid", "uid", "gid", "tls", "listenLoopback", "deadlineSeconds"))
    require(ready["schema"] == "chengwang.product-source-ready/v1" and type(ready["pid"]) is int and ready["pid"] == pid
            and type(ready["port"]) is int and ready["port"] == 5444 and ready["tls"] is True and ready["listenLoopback"] is True
            and type(ready["uid"]) is int and ready["uid"] == 10001 and type(ready["gid"]) is int and ready["gid"] == 10001,
            "actual atomic source ready record rejected")
    integer(ready["deadlineSeconds"], 1, 600)
    return pid, start


def traffic(value, source, local_id, graphs):
    exact(value, ("schema", "sourceCommit", "localImageID", "registryContainerID", "pinnedRegistryImage", "snapshots", *BOUNDARY))
    registry.boundary(value)
    require(value["schema"] == "chengwang.product-source-observations/v1" and value["sourceCommit"] == source
            and value["localImageID"] == local_id and value["pinnedRegistryImage"] == registry.REGISTRY_IMAGE,
            "source Registry counter identity rejected")
    bare_hash(value["registryContainerID"])
    expected = [(flow, kind, action, position) for flow in FLOWS for kind in KINDS for action in ACTIONS for position in ("before", "after")]
    require(type(value["snapshots"]) is list and len(value["snapshots"]) == 36, "source Registry counter stages incomplete")
    counts, previous = [], {}
    for ordinal, (snapshot, step) in enumerate(zip(value["snapshots"], expected), 1):
        exact(snapshot, ("ordinal", "flow", "kind", "action", "position", "digestRequests", "otherRequests"))
        require(type(snapshot["ordinal"]) is int and snapshot["ordinal"] == ordinal
                and (snapshot["flow"], snapshot["kind"], snapshot["action"], snapshot["position"]) == step, "source Registry counter order rejected")
        current = registry.traffic_counts(snapshot)
        require(all(current.get(key, 0) >= count for key, count in previous.items()), "source Registry counters regressed")
        if ordinal == 1:
            require(not current, "source prepare seeding hidden before first snapshot")
        elif snapshot["position"] == "before":
            require(current == previous, "source Registry unobserved request gap")
        counts.append(current); previous = current
    for index in range(0, 36, 2):
        snapshot = value["snapshots"][index]
        before, after = counts[index:index + 2]
        delta = {k: v - before.get(k, 0) for k, v in after.items() if v != before.get(k, 0)}
        if snapshot["action"] == "prepare":
            graph = graphs[(snapshot["flow"], snapshot["kind"])]
            wanted = {("GET", graph["registryManifestDigest"], 200): 1,
                      ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                      ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
            for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                wanted[("GET", desc["digest"], 200)] = 1
            require(delta == wanted, "source preparation upload/readback exact budget rejected")
        else:
            require(not delta, "source read-only flow reached Registry HTTP")
    return value["registryContainerID"]


def own_names():
    names = {"product-source-" + name + ".json" for name in ("harness", "network", "isolation", "observations", "runtime-cleanup", "outcome")}
    for flow in FLOWS:
        for kind in KINDS:
            prefix = "product-source-" + flow + "-" + kind + "-"
            names.update(prefix + suffix + ".json" for suffix in (*ACTIONS, "graph", "running-inspect", "exited-inspect", "running-pid1", "source", "source-stop", "feed-ready"))
            names.add(prefix + "feed-events.jsonl")
    return frozenset(names)


def transcript(raw, source, suite, count):
    require(len(raw) <= 1 << 20 and b"\x1b" not in raw, "synthetic transcript budget rejected")
    expected = preflight.expected_tests(source)
    require(len(expected) == count, "synthetic source suite count changed")
    seen, summaries, ok, markers = set(), [], 0, 0
    marker = f"D12_SOURCE_{suite}_TESTS=PASS tests={count} skipped=0 synthetic_only=true"
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line.strip() or re.fullmatch(r"-{5,}", line):
            continue
        match = re.fullmatch(r"(test_\w+) \(__main__\.(\w+)\.(test_\w+)\) \.\.\. ok", line)
        if match:
            method, cls, repeated = match.groups(); name = cls + "." + method
            require(method == repeated and name in expected and name not in seen, "unknown/duplicate named synthetic test")
            seen.add(name)
        elif (summary := re.fullmatch(r"Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s", line)):
            summaries.append(int(summary.group(1)))
        elif line == "OK":
            ok += 1
        elif line == marker:
            markers += 1
        else:
            raise CheckError("unexpected synthetic transcript line")
    require(seen == expected and summaries == [count] and ok == markers == 1, "synthetic named suite incomplete")
    return {"tests": count, "skipped": 0, "syntheticOnly": True, "testSourceSHA256": image.sha(source),
            "transcriptSHA256": image.sha(raw), "namedTestsSHA256": image.sha(("\n".join(sorted(seen)) + "\n").encode())}


def cleanup(value, source, local_id, products, registry_id):
    wanted = {"schema": "chengwang.product-source-cleanup/v1", "sourceCommit": source, "localImageID": local_id,
        "ownedContainersRemoved": 7, "ownedSourcesJoined": 6, "sourceExitCodes": [0] * 6,
        "normalProductStops": 6, "maximumConcurrentOwnedContainers": 2, "noOwnedContainersRemain": True,
        "registryStop": {"signal": "SIGTERM", "exitCode": 0, "oomKilled": False, "pid": 0},
        "privateFixtureRemoved": True, "outerProductImagePreserved": True, "registryImagePreserved": True, "outcome": "PASS", **BOUNDARY}
    exact(value, (*wanted, "removedContainers"))
    require(all(type(value[k]) is type(v) and encoded(value[k]) == encoded(v) for k, v in wanted.items()), "exact owned cleanup not proven")
    require(type(value["removedContainers"]) is list and len(value["removedContainers"]) == 7, "owned cleanup IDs incomplete")
    seen = set()
    for row in value["removedContainers"]:
        exact(row, ("containerID", "role", "flow", "kind"))
        identifier = bare_hash(row["containerID"])
        require(identifier not in seen, "owned cleanup duplicate container")
        seen.add(identifier)
        if identifier == registry_id:
            require(row["role"] == "registry" and row["flow"] == row["kind"] == "", "Registry cleanup role rejected")
        else:
            require((row["flow"], row["kind"]) in products and row["role"] == "product"
                    and products[(row["flow"], row["kind"])] == identifier, "foreign or misbound cleanup container")
    require(seen == {registry_id, *products.values()}, "owned cleanup set mismatch")


def verify(args):
    require(registry.COMMIT.fullmatch(args.source_commit), "source commit rejected")
    source = args.source_commit
    directory = image.checked_path(args.evidence_dir, directory=True)
    expected = own_names()
    present = {p.name for p in directory.iterdir() if p.name.startswith("product-source-")}
    require(expected - {"product-source-outcome.json"} <= present and present <= expected | SUPPORT_NAMES | FIXTURE_NAMES,
            "unknown, missing or stale product-source evidence")
    hashes = {}
    def load(name, raw=False):
        content = registry.read_file(directory / name, 4 << 20)
        require(name not in hashes, "duplicate source evidence load")
        hashes[name] = image.sha(content)
        return content if raw else parse(content)
    staging, packaged = load("product-image-staging.json"), load("product-image-packaged-contents.json")
    packaged_raw = registry.read_file(directory / "product-image-packaged-contents.json", 4 << 20)
    require(staging.get("sourceCommit") == source and staging.get("authorization") == "BLOCKED"
            and staging.get("deviceActionsExecuted") is False and staging.get("imageBuilt") is False
            and staging.get("imageExecuted") is False and type(staging.get("binary")) is dict, "staging boundary rejected")
    binary_sha = bare_hash(staging["binary"].get("sha256"))
    require(staging["binary"].get("sourceCommit") == source and staging["binary"].get("sourceModified") is False, "binary source mismatch")
    local_id = digest(packaged.get("localImageID"))
    require(packaged.get("schema") == "chengwang.product-image-packaged-content/v1" and packaged.get("sourceCommit") == source
            and packaged.get("authorization") == "BLOCKED" and packaged.get("production") is False
            and packaged.get("registryManifestDigestVerified") is False and packaged.get("configDigestMatched") is True
            and packaged.get("secretsPackaged") is False and packaged.get("rawArchivePublished") is False, "packaged image boundary rejected")
    files, contexts = packaged.get("files"), staging.get("contextFiles")
    require(type(files) is dict and type(contexts) is dict and "Dockerfile" in contexts
            and files.get("app/image-trust-api", {}).get("sha256") == binary_sha
            and files["app/image-trust-api"].get("bytes") == staging["binary"].get("bytes")
            and {n.removeprefix("rootfs/"): v for n, v in contexts.items() if n != "Dockerfile"} == {n: v["sha256"] for n, v in files.items()},
            "actual packaged executable/context bytes mismatch")
    harness = load("product-source-harness.json")
    exact(harness, ("schema", "sourceCommit", "files", "checkoutBytesMatched", "permissionReadOnly", *BOUNDARY))
    registry.boundary(harness)
    require(harness["schema"] == "chengwang.product-source-harness/v1" and harness["sourceCommit"] == source
            and harness["checkoutBytesMatched"] is True and harness["permissionReadOnly"] is True, "source harness boundary rejected")
    exact(harness["files"], HARNESS_PATHS)
    for path, wanted in harness["files"].items():
        bare_hash(wanted)
        require(image.sha(registry.read_file(pathlib.Path(__file__).with_name(pathlib.PurePosixPath(path).name), 256 << 10)) == wanted,
                "running checker/helper differs from Git-bound harness source")
    suites = {}
    for suite, name, count in (("IMAGE_PROFILE", "test_source_image_profile.py", 8), ("VERIFIER", "test_check_product_source.py", 32)):
        log = "product-source-" + ("profile" if suite == "IMAGE_PROFILE" else "verifier") + "-tests.log"
        suites[suite] = transcript(load(log, True), registry.read_file(pathlib.Path(__file__).with_name(name), 256 << 10), suite, count)
    graphs = {}
    for flow in FLOWS:
        for kind in KINDS:
            graph = load("product-source-" + flow + "-" + kind + "-graph.json")
            registry.graph_projection(graph, source, local_id, packaged_raw)
            require([x["diffID"] for x in graph["layerDescriptors"]] == packaged["layerDiffIDs"]
                    and graph["packagedFileCount"] == packaged["packagedFileCount"]
                    and binary_sha not in {local_id[7:], graph["registryManifestDigest"][7:]}, "binary/config/manifest roles conflated")
            graphs[(flow, kind)] = graph
    require(all(graph == next(iter(graphs.values())) for graph in graphs.values()), "six cells used different image graphs")
    registry_id = traffic(load("product-source-observations.json"), source, local_id, graphs)
    isolation, network = load("product-source-isolation.json"), load("product-source-network.json")
    registry.registry_isolation(isolation, network, source, registry_id)
    require(isolation["actualImageID"] != local_id, "Registry/product image roles conflated")
    products, sources, materials, cells = {}, set(), [], {}
    for flow in FLOWS:
        for kind in KINDS:
            prefix = "product-source-" + flow + "-" + kind + "-"
            reports = {action: load(prefix + action + ".json") for action in ACTIONS}
            info = reports["prepare"]["material"]
            corpus, docs = material(info, kind, source, local_id, graphs[(flow, kind)])
            materials.append(info)
            for action, report in reports.items():
                exact(report, REPORT_FIELDS); registry.boundary(report)
                require(report["schema"] == "chengwang.product-source-driver/v1" and report["flow"] == flow
                        and report["kind"] == kind and report["action"] == action and report["sourceCommit"] == source
                        and report["localImageID"] == local_id and report["material"] == info, "source report identity/material changed")
                if action != "run":
                    require(report["observations"] == [], "nonrunning API observations fabricated")
                if action != "reopen":
                    require(report["offline"] is None, "running report fabricated offline state")
            require(reports["reopen"]["feedPlans"] == [], "reopen published a new source plan")
            plans = plan_records(reports["prepare"]["feedPlans"], reports["run"]["feedPlans"], flow, corpus)
            stopped, process, ready = load(prefix + "source-stop.json"), load(prefix + "source.json"), load(prefix + "feed-ready.json")
            sources.add(source_process(process, stopped, ready, source, flow, kind, harness["files"]))
            _, lines, complete, summary = source_events(load(prefix + "feed-events.jsonl", True), plans, corpus, stopped["productStopWindows"])
            require(all(type(row) is dict and type(row.get("sourceFence")) is dict
                        and integer(row["sourceFence"].get("eventCount"), 0, len(lines))
                        <= stopped["productStopWindows"][0]["before"]["eventCount"]
                        for row in reports["run"]["observations"]), "API observation fence extends beyond product stop")
            last = observations(reports, flow, info, docs, lines, complete)
            reopened = offline(reports["reopen"]["offline"], last, info, flow, corpus, docs)
            products[(flow, kind)] = registry.runtime_projections(
                {stage: load(prefix + stage + "-inspect.json") for stage in ("running", "exited")},
                {"running": load(prefix + "running-pid1.json")}, source, local_id, registry_id, binary_sha)
            cells[flow + "/" + kind] = {"source": summary, "finalReopen": reopened}
    require(len(set(products.values())) == len(sources) == 6 and registry_id not in products.values()
            and len({m["storeID"] for m in materials}) == len({m["policies"][0]["grantID"] for m in materials})
            == len({m["policies"][0]["trustedRootSHA256"] for m in materials})
            == len({parse(binary(m["anchorRaw"]))["keys"][0]["id"] for m in materials}) == 6,
            "six independent product/store/grant/authority/source cells not proven")
    cleanup(load("product-source-runtime-cleanup.json"), source, local_id, products, registry_id)
    require(set(hashes) == expected - {"product-source-outcome.json"} | SUPPORT_NAMES
            | {"product-image-staging.json", "product-image-packaged-contents.json"} and len(hashes) == 75,
            "product-source 75 input relation set changed")
    result = {"schema": "chengwang.product-source-gate/v1", "outcome": "PASS", **BOUNDARY,
        "sourceCommit": source, "localImageID": local_id, "registryManifestDigest": next(iter(graphs.values()))["registryManifestDigest"],
        "binarySHA256": binary_sha, "authority": "EPHEMERAL_TEST_ONLY", "graphBytesOrigin": registry.GRAPH_ORIGIN,
        "signatureKinds": list(KINDS), "flows": list(FLOWS), "cells": cells, "testSuites": suites,
        "independentPublicSignatureVerification": "OPENSSL_ED25519_FIXED_ARGV", "registryCounterSnapshots": 36,
        "prepareUploadReadbackWindows": 6, "zeroRequestWindows": 12, "normalProductStops": 6,
        "sourceGracefulStops": 6, "cleanupVerified": True, "wave1Only": True,
        "reservedRevocationProven": False, "sourceTLSNegativeMatrixProven": False, "sourceRestartMatrixProven": False,
        "completeSourceFaultMatrixProven": False, "releaseAuthorized": False, "physicalPowerLossProven": False,
        "privateGraphDownloadedByReviewer": False, "productImagePublishedOutsideIsolatedRegistry": False,
        "evidenceSHA256": dict(sorted(hashes.items()))}
    existing = directory / "product-source-outcome.json"
    if existing.exists() or existing.is_symlink():
        require(encoded(parse(registry.read_file(existing, 4 << 20))) == encoded(result), "existing product-source outcome differs from independent replay")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    graph = sub.add_parser("graph")
    for name in ("graph-dir", "packaged-report", "report"):
        graph.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("source-commit", "manifest-digest"):
        graph.add_argument("--" + name, required=True)
    inspect = sub.add_parser("inspect")
    for name in ("image-inspect", "container-inspect", "report"):
        inspect.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("image-id", "source-commit", "expected-private-source", "expected-state-source", "expected-network-mode"):
        inspect.add_argument("--" + name, required=True)
    inspect.add_argument("--container-status", choices=("running", "exited"), required=True)
    verification = sub.add_parser("verify")
    for name in ("evidence-dir", "report"):
        verification.add_argument("--" + name, type=pathlib.Path, required=True)
    verification.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "graph":
            result = registry.graph(args)
        elif args.command == "inspect":
            require(re.fullmatch(r"container:[0-9a-f]{64}", args.expected_network_mode), "source product namespace rejected")
            result = image.inspect_projection(image.one_inspect(registry.read_file(args.image_inspect, 8 << 20)),
                image.one_inspect(registry.read_file(args.container_inspect, 8 << 20)), image_id=args.image_id,
                source=args.source_commit, private=args.expected_private_source, state=args.expected_state_source,
                network=args.expected_network_mode, status=args.container_status, fixture_kind="product-source")
            result.update(production=False, networkPeerContainerID=args.expected_network_mode.removeprefix("container:"))
        else:
            result = verify(args)
        image.write_exclusive(args.report, encoded(result) + b"\n")
    except (OSError, CheckError, ValueError, TypeError, KeyError, AttributeError, OverflowError, preflight.Rejected):
        print("PRODUCT_SOURCE_CHECK=FAIL rejected=true raw_input_suppressed=true", file=sys.stderr)
        return 1
    print("PRODUCT_SOURCE_CHECK=PASS mode=" + args.command + " authorization=BLOCKED production=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
