"""Synthetic wave-1 evidence counterexamples, not product/TLS acceptance."""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import check_product_source as check
import test_check_product_registry as graph_fixture
import test_check_product_lifecycle as old

SOURCE, NOW = "a" * 40, old.NOW
raw, h, d, stamp = old.raw, old.h, old.d, old.stamp


def b64(value):
    return base64.b64encode(value).decode()


class Signer:
    def __init__(self, label):
        self.temporary = tempfile.TemporaryDirectory(prefix="source-synthetic-signer-")
        self.root = pathlib.Path(self.temporary.name)
        self.private = self.root / "private.der"
        graph_fixture.put(self.private, bytes.fromhex("302e020100300506032b657004220420") + bytes.fromhex(h(label)))
        result = subprocess.run([check.openssl_path(), "pkey", "-inform", "DER", "-in", str(self.private),
                                 "-pubout", "-outform", "DER"], capture_output=True, timeout=5, check=True)
        self.public = result.stdout[-32:]
        self.key = {"id": check.image.sha(self.public), "publicKey": b64(self.public)}

    def sign(self, message):
        target = self.root / "message.bin"
        target.write_bytes(message)
        return subprocess.run([check.openssl_path(), "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(self.private),
                               "-in", str(target)], capture_output=True, timeout=5, check=True).stdout

    def close(self):
        self.temporary.cleanup()


def signed_material(flow, kind, graph):
    label = flow + kind
    root, approver = Signer(label + "-root"), Signer(label + "-approver")
    try:
        info = {"kind": kind, "sourceCommit": SOURCE, "localImageID": graph["localImageID"], "configSHA256": graph["localImageID"],
            "manifestSHA256": graph["registryManifestDigest"], "layerSHA256s": [x["digest"] for x in graph["layerDescriptors"]],
            "diffIDs": [x["diffID"] for x in graph["layerDescriptors"]], "storeID": h(label)[:32], "feedURL": check.lifecycle.FEED_URL,
            "feedSPKI": d("source-spki"), "feedCASHA256": d("source-ca"), "refreshIntervalSeconds": 2,
            "refreshMaxAgeSeconds": 15, "refreshTimeoutSeconds": 2}
        policy = {"name": "a", "policyID": "d12-source-policy", "grantID": h(label + "-grant")[:32],
            "bundleSHA256": d(label + "-bundle"), "bundleArtifactSHA256": info["manifestSHA256"],
            "trustedRootSHA256": d(label + "-trustedroot"), "registrySPKI": d("registry-spki")}
        sig = {"artifactSHA256": info["manifestSHA256"], "trustedRootSHA256": policy["trustedRootSHA256"], "logID": h("log"),
               "issuer": "https://issuer.fixture.invalid", "san": "builder@fixture.invalid", "kind": kind}
        if kind == "dsse":
            sig.update(subjectName="registry.fixture.invalid:5443/chengwang/product-candidate", predicateType="https://fixture.invalid/predicate")
        approval_doc = {"schema": "chengwang.image-approval/v1", "policyID": policy["policyID"], "revision": 1,
            "approverKeyID": approver.key["id"], "notBeforeUnix": NOW - 100, "notAfterUnix": NOW + 3600,
            "reference": "registry.fixture.invalid:5443/chengwang/product-candidate@" + info["manifestSHA256"],
            "os": "linux", "architecture": "amd64", "variant": "", "registryIPs": ["127.0.0.1"],
            "registrySPKISHA256": policy["registrySPKI"], "signature": sig}
        approval_payload = raw(approval_doc)
        approval = raw({"payload": b64(approval_payload), "signature": b64(approver.sign(b"chengwang.image-approval/v1\0" + approval_payload))})
        policy.update(approvalSHA256=check.prefixed(approval_payload), approvalEnvelopeSHA256=check.prefixed(approval))
        info["policies"], info["approvalRaw"] = [policy], b64(approval)
        grant = {"id": policy["grantID"], "policyID": policy["policyID"], "approvalSHA256": policy["approvalSHA256"],
                 "approverKeyID": approver.key["id"], "manifestSHA256": info["manifestSHA256"], "revision": 1}
        corpus = []
        for generation in (1, 2, 3):
            doc = {"schema": "chengwang.trust-catalog/v1", "storeID": info["storeID"], "generation": generation,
                "notBeforeUnix": NOW - 100, "notAfterUnix": NOW + 3600, "rootKeys": [root.key], "threshold": 1,
                "approvers": [approver.key], "grants": [grant], "policyFloors": {policy["policyID"]: 1},
                "revokedKeys": [], "revokedApprovals": [], "revokedManifests": []}
            payload = raw(doc)
            envelope = {"payload": b64(payload), "signatures": [{"keyID": root.key["id"],
                         "signature": b64(root.sign(b"chengwang.trust-catalog/v1\0" + payload))}]}
            content = raw(envelope)
            corpus.append({"name": "g" + str(generation), "generation": generation, "raw": b64(content), "sha256": check.prefixed(content)})
        for generation in (2, 3):
            envelope = check.parse(check.binary(corpus[generation - 1]["raw"]))
            signature = bytearray(check.binary(envelope["signatures"][0]["signature"])); signature[0] ^= 1
            envelope["signatures"][0]["signature"] = b64(signature)
            content = raw(envelope)
            corpus.append({"name": "bad-g" + str(generation), "generation": generation, "raw": b64(content), "sha256": check.prefixed(content)})
        info.update(catalogues=corpus, catalogue1SHA256=corpus[0]["sha256"], catalogue2SHA256=corpus[1]["sha256"],
            anchorRaw=b64(raw({"storeID": info["storeID"], "initialSHA256": corpus[0]["sha256"], "keys": [root.key], "threshold": 1})))
        return info
    finally:
        root.close(); approver.close()


def plans_fixture(flow, info):
    corpus = {c["name"]: check.binary(c["raw"]) for c in info["catalogues"]}
    plans = []
    for epoch, names in enumerate(check.PLAN_NAMES[flow], 1):
        responses = {path: {"mode": "forbidden" if name == "forbidden" else "json",
                     "bodySHA256": "" if name == "forbidden" else check.image.sha(corpus[name])}
                     for path, name in zip(("latest.json", "2.json"), names)}
        content = raw({"schema": "chengwang.product-source-plan/v1", "epoch": epoch, "responses": responses})
        plans.append({"epoch": epoch, "raw": b64(content), "sha256": check.prefixed(content)})
    return plans


def events_fixture(flow, info, plans):
    events, fences = [], {}
    corpus = {c["name"]: check.binary(c["raw"]) for c in info["catalogues"]}
    def request(epoch, name, generation=0):
        connection = len(events) // 4 + 1
        common = {key: value for key, value in check.wirecheck.NON_HTTP_EMPTY.items()}
        for event, tls, reason in (("connect", False, "accepted"), ("tls", True, "ok"), ("http", True, "planned"), ("close", True, "closed")):
            row = {"schema": "chengwang.product-source-event/v1", "ordinal": len(events) + 1,
                   "connection": connection, "event": event, "reason": reason, **common, "tls": tls}
            if event == "http":
                mode = "forbidden" if name == "forbidden" else "json"
                body = b"" if name == "forbidden" else corpus[name]
                code, representation, wire = check.wirecheck.expected_wire(mode, body)
                row.update(epoch=epoch, planSHA256=plans[epoch - 1]["sha256"][7:], pathClass="generation" if generation else "latest",
                    generation=generation, mode=mode, status=code, representationSHA256=check.image.sha(representation),
                    representationBytes=len(representation), wireSHA256=check.image.sha(wire), wireBytes=len(wire), writtenBytes=len(wire), wireComplete=True)
            events.append(row)
    if flow == "http-recovery":
        request(1, "forbidden"); request(1, "forbidden"); fences["unconfirmed"] = len(events)
        request(2, "g1"); fences["confirmed"] = len(events)
        request(3, "forbidden"); request(3, "forbidden"); fences["forbidden"] = len(events); fences["stale"] = len(events)
        request(4, "g1"); fences["recovered"] = len(events)
    else:
        request(1, "g1"); fences["confirmed"] = len(events)
        if flow == "prefix-recovery":
            request(2, "g2", 2)
        bad = "bad-g2" if flow == "bad-signature" else "bad-g3"
        request(2, bad); fences["rejected" if flow == "bad-signature" else "prefix-rejected"] = len(events)
        for _ in range(3):
            request(2, bad)
        fences["deduplicated"] = len(events); fences["stale"] = len(events)
        request(3, "g2" if flow == "bad-signature" else "g3"); fences["recovered"] = len(events)
    return events, fences


def audit_fixture(flow, info):
    journal, bindings, events, history = [], [], [], []
    for index, (name, committed) in enumerate(check.OPERATIONS[flow]):
        catalogue = next(c for c in info["catalogues"] if c["name"] == name)
        previous = events[-1]["hash"] if events else "0" * 64
        scope = {"tenantId": "d12-tenant", "siteId": "d12-site", "objectType": "image-trust", "objectId": info["storeID"], "environment": "candidate"}
        op = {"id": "op-" + h(info["storeID"] + name)[:24], "actorID": "image-trust-refresh", "kind": "update",
              "scopeSHA256": check.prefixed(raw(scope, ordered=True)), "data": {"catalogueSHA256": catalogue["sha256"]},
              "auditBaseCount": len(events), "auditBaseHash": previous, "preparedAuditHash": ""}
        data = op["data"] if committed else {}
        prepared = old.event(op, "prepared", previous, op["data"], "prepared", info["storeID"], len(events) + 1)
        op["preparedAuditHash"] = prepared["hash"]
        result = old.event(op, "result", prepared["hash"], data, "completed" if committed else "rejected", info["storeID"], len(events) + 2)
        entry = {"operation": op, "state": "COMMITTED" if committed else "PREPARED",
            "outcome": "CATALOGUE_COMMITTED" if committed else "REJECTED", "outcomeData": data,
            "acknowledged": True, "resultAuditHash": result["hash"], "grantID": "", "generation": catalogue["generation"] if committed else 0,
            "catalogueSHA256": catalogue["sha256"] if committed else "", "manifestSHA256": "", "evidenceSHA256": ""}
        historical = {"operationId": op["id"], "actorId": op["actorID"], "kind": "update", "state": entry["state"], "outcome": entry["outcome"],
            "acknowledged": True, "policyId": "", "grantId": "", "generation": entry["generation"], "catalogueSHA256": entry["catalogueSHA256"],
            "preparedAuditHash": prepared["hash"], "resultAuditHash": result["hash"],
            "preparedAtUnix": NOW + len(events) + 1, "resultAtUnix": NOW + len(events) + 2}
        journal.append(entry); bindings.append({"operationID": op["id"], "prepared": prepared, "result": result})
        events.extend((prepared, result)); history.append(historical)
    return journal, bindings, events, history


def cell_fixture(flow, kind, info):
    plans = plans_fixture(flow, info)
    events, fences = events_fixture(flow, info, plans)
    lines = [raw(e) + b"\n" for e in events]
    journal, bindings, audit_events, historical = audit_fixture(flow, info)
    reports = {}
    for action in check.ACTIONS:
        reports[action] = {"schema": "chengwang.product-source-driver/v1", "sourceCommit": SOURCE, "localImageID": info["localImageID"],
            "flow": flow, "kind": kind, "action": action, **check.BOUNDARY, "material": info,
            "observations": [], "feedPlans": plans[:1] if action == "prepare" else plans[1:] if action == "run" else [], "offline": None}
    for wanted in check.OBSERVATIONS[flow]:
        name, seq, generation, total, fresh = wanted
        observed = NOW + (40 if name == "stale" else 45 if name == "recovered" else 10)
        last = 0 if name == "unconfirmed" else NOW + (44 if name == "recovered" else 1)
        value = graph_fixture.synthetic_status(info, (seq, min(generation, 2), 0, 0, total))
        value.update(generation=generation, catalogueSHA256=next(c["sha256"] for c in info["catalogues"] if c["name"] == "g" + str(generation)),
            notAfterUnix=NOW + 3600, observedAtUnix=observed, auditVerifiedAtUnix=observed, revokedApprovals=0,
            refreshRequired=True, refreshFresh=bool(fresh), refreshLastSuccessUnix=last, refreshUntilUnix=last + 15 if last else 0)
        value["policies"] = [{"policyId": "d12-source-policy", "grantId": info["policies"][0]["grantID"], "revision": 1,
                              "manifestSHA256": info["manifestSHA256"], "state": "AVAILABLE"}]
        hist = graph_fixture.synthetic_history((seq, generation, 0, 0, total), historical[:total])
        hist["observedAtUnix"] = observed
        reports["run"]["observations"].append({"name": name, "status": value, "history": hist,
            "sourceFence": {"eventCount": fences[name], "sha256": check.image.sha(b"".join(lines[:fences[name]]))}})
    seq, gen, total = check.OBSERVATIONS[flow][-1][1:4]
    doc = check.parse(check.binary(check.parse(check.binary(info["catalogues"][gen - 1]["raw"]))["payload"]))
    catalogue = {"storeID": info["storeID"], "generation": gen, "sha256": info["catalogues"][gen - 1]["sha256"],
        "notBeforeUnix": doc["notBeforeUnix"], "notAfterUnix": doc["notAfterUnix"], "rootKeyCount": 1, "rootThreshold": 1,
        "approverCount": 1, "grants": doc["grants"], "policyFloors": doc["policyFloors"], "revokedKeyCount": 0, "revokedApprovalCount": 0, "revokedManifestCount": 0}
    tail = audit_events[-1]["hash"] if audit_events else "0" * 64
    audit_raw = b"".join(raw(e, ordered=True) + b"\n" for e in audit_events)
    cp_raw = raw({"count": total * 2, "lastHash": tail}, ordered=True)
    reports["reopen"]["offline"] = {"inspection": {"authorization": "BLOCKED", "catalogue": catalogue, "catalogueValid": True,
        "sequence": seq, "ledgerCapacity": 4096, "ledgerUsed": 0, "ledgerRemaining": 4096, "consumptions": []},
        "journal": journal, "auditBindings": bindings, "auditEvents": audit_events,
        "audit": {"valid": True, "count": total * 2, "expectedCount": total * 2, "lastHash": tail, "expectedLastHash": tail, "verifiedAt": stamp(NOW + 50)},
        "auditLog": {"bytes": len(audit_raw), "sha256": check.image.sha(audit_raw)},
        "checkpoint": {"bytes": len(cp_raw), "sha256": check.image.sha(cp_raw)}, "trustRecordSHA256": h(flow + kind + "record")}
    stop = [{"label": "final", "before": {"eventCount": len(lines), "sha256": check.image.sha(b"".join(lines))},
             "after": {"eventCount": len(lines), "sha256": check.image.sha(b"".join(lines))}}]
    return reports, b"".join(lines), stop


def transcript(source, suite):
    names = sorted(check.preflight.expected_tests(source))
    lines = [f"{method} (__main__.{cls}.{method}) ... ok" for cls, method in (n.split(".", 1) for n in names)]
    lines += ["", "----------------------------------------------------------------------", f"Ran {len(names)} tests in 0.001s", "", "OK",
              f"D12_SOURCE_{suite}_TESTS=PASS tests={len(names)} skipped=0 synthetic_only=true"]
    return ("\n".join(lines) + "\n").encode()


def final_fixture(root, graph, old_values, materials):
    values = {n: copy.deepcopy(old_values[n]) for n in ("product-image-staging.json", "product-image-packaged-contents.json")}
    harness = {p: check.image.sha(pathlib.Path(check.__file__).with_name(pathlib.PurePosixPath(p).name).read_bytes()) for p in check.HARNESS_PATHS}
    values["product-source-harness.json"] = {"schema": "chengwang.product-source-harness/v1", "sourceCommit": SOURCE, "files": harness,
                                            "checkoutBytesMatched": True, "permissionReadOnly": True, **check.BOUNDARY}
    registry_id = old_values["product-registry-observations.json"]["registryContainerID"]
    for name in ("network", "isolation"):
        values["product-source-" + name + ".json"] = copy.deepcopy(old_values["product-registry-" + name + ".json"])
    snapshots, counts, removed = [], {}, []
    for index, (flow, kind) in enumerate((f, k) for f in check.FLOWS for k in check.KINDS):
        prefix = "product-source-" + flow + "-" + kind + "-"
        reports, log, windows = cell_fixture(flow, kind, materials[(flow, kind)])
        values.update({prefix + a + ".json": r for a, r in reports.items()})
        values[prefix + "graph.json"] = graph
        values[prefix + "feed-events.jsonl"] = log
        pid, start = 1000 + index, 2000 + index
        values[prefix + "source.json"] = {"schema": "chengwang.product-source-process/v1", "sourceCommit": SOURCE, "flow": flow, "kind": kind,
            "sourceCase": "source-" + flow, "hostPID": pid, "hostStartTime": start, "uid": 10001, "gid": 10001, "capabilities": "none",
            "noNewPrivileges": True, "registryNetworkNamespaceMatched": True, "privateMountNamespace": True,
            "sourceSHA256": harness[check.BASE + "fixture_source.py"], "dependencySHA256": harness[check.BASE + "fixture_feed.py"],
            "pythonExecutableSHA256": h("python"), "gitBoundSourceMatched": True, "sourceLimitsVerified": True,
            "sourceLimits": {"cpuSeconds": 60, "addressSpaceBytes": 536870912, "fileBytes": 16777216, "openFiles": 128, "processes": 128, "coreBytes": 0}, **check.BOUNDARY}
        values[prefix + "source-stop.json"] = {"schema": "chengwang.product-source-stop/v1", "sourceCommit": SOURCE, "flow": flow,
            "kind": kind, "sourceCase": "source-" + flow, "hostPID": pid, "startTime": start, "signal": "SIGTERM", "exitCode": 0,
            "joined": True, "productStopWindows": windows, **check.BOUNDARY}
        values[prefix + "feed-ready.json"] = {"schema": "chengwang.product-source-ready/v1", "port": 5444, "pid": pid,
            "uid": 10001, "gid": 10001, "tls": True, "listenLoopback": True, "deadlineSeconds": 600}
        product_id = h(flow + kind + "-container")
        for label in ("running", "exited"):
            projection = copy.deepcopy(old_values["product-registry-" + kind + "-" + label + "-inspect.json"])
            projection.update(containerID=product_id, pid=3000 + index if label == "running" else 0)
            values[prefix + label + "-inspect.json"] = projection
        process = copy.deepcopy(old_values["product-registry-" + kind + "-running-pid1.json"])
        process.update(containerID=product_id, hostPID=3000 + index)
        values[prefix + "running-pid1.json"] = process
        removed.append({"containerID": product_id, "role": "product", "flow": flow, "kind": kind})
        for action in check.ACTIONS:
            for position in ("before", "after"):
                if action == "prepare" and position == "after":
                    delta = {("GET", graph["registryManifestDigest"], 200): 1, ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                             ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
                    for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                        delta[("GET", desc["digest"], 200)] = 1
                    for key, count in delta.items():
                        counts[key] = counts.get(key, 0) + count
                snapshots.append({"ordinal": len(snapshots) + 1, "flow": flow, "kind": kind, "action": action, "position": position,
                    "digestRequests": [{"method": m, "digest": d, "status": s, "count": c} for (m, d, s), c in sorted(counts.items()) if d],
                    "otherRequests": [{"method": m, "status": s, "count": c} for (m, d, s), c in sorted(counts.items()) if not d]})
    values["product-source-observations.json"] = {"schema": "chengwang.product-source-observations/v1", "sourceCommit": SOURCE,
        "localImageID": graph["localImageID"], "registryContainerID": registry_id, "pinnedRegistryImage": check.registry.REGISTRY_IMAGE,
        "snapshots": snapshots, **check.BOUNDARY}
    removed.append({"containerID": registry_id, "role": "registry", "flow": "", "kind": ""})
    values["product-source-runtime-cleanup.json"] = {"schema": "chengwang.product-source-cleanup/v1", "sourceCommit": SOURCE,
        "localImageID": graph["localImageID"], "ownedContainersRemoved": 7, "ownedSourcesJoined": 6, "sourceExitCodes": [0] * 6,
        "normalProductStops": 6, "maximumConcurrentOwnedContainers": 2, "noOwnedContainersRemain": True, "removedContainers": removed,
        "registryStop": {"signal": "SIGTERM", "exitCode": 0, "oomKilled": False, "pid": 0}, "privateFixtureRemoved": True,
        "outerProductImagePreserved": True, "registryImagePreserved": True, "outcome": "PASS", **check.BOUNDARY}
    for label, suite, name in (("profile", "IMAGE_PROFILE", "test_source_image_profile.py"), ("verifier", "VERIFIER", "test_check_product_source.py")):
        values["product-source-" + label + "-tests.log"] = transcript(pathlib.Path(check.__file__).with_name(name).read_bytes(), suite)
    directory = root / "new-evidence"
    for name, value in values.items():
        graph_fixture.put(directory / name, value if type(value) is bytes else raw(value))
    return argparse.Namespace(evidence_dir=directory, source_commit=SOURCE, report=root / "outcome.json"), values


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.temporary.name)
        _, cls.old_values = graph_fixture.synthetic_final_evidence(cls.root)
        cls.graph = cls.old_values["product-registry-message-signature-graph.json"]
        cls.materials = {(f, k): signed_material(f, k, cls.graph) for f in check.FLOWS for k in check.KINDS}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.flow, self.kind = "bad-signature", "message-signature"
        self.info = copy.deepcopy(self.materials[(self.flow, self.kind)])
        self.reports, self.log, self.windows = cell_fixture(self.flow, self.kind, self.info)
        self.corpus = {c["name"]: check.binary(c["raw"]) for c in self.info["catalogues"]}
        self.docs = {n: check.parse(check.binary(check.parse(v)["payload"])) for n, v in self.corpus.items()}

    def reject(self, function, *args):
        with self.assertRaises(check.CheckError):
            function(*args)

    def verify_material(self, value):
        return check.material(value, self.kind, SOURCE, self.graph["localImageID"], self.graph)

    def replay(self, reports=None, log=None, windows=None):
        reports = self.reports if reports is None else reports
        plans = check.plan_records(reports["prepare"]["feedPlans"], reports["run"]["feedPlans"], self.flow, self.corpus)
        _, lines, complete, _ = check.source_events(self.log if log is None else log, plans, self.corpus, self.windows if windows is None else windows)
        last = check.observations(reports, self.flow, self.info, self.docs, lines, complete)
        return check.offline(reports["reopen"]["offline"], last, self.info, self.flow, self.corpus, self.docs)

    def test_good_public_signatures_both_kinds_all_three_flows(self):
        for (flow, kind), info in self.materials.items():
            check.material(info, kind, SOURCE, self.graph["localImageID"], self.graph)

    def test_mutated_signature_payload_anchor_or_key_rejected(self):
        for field, value in (("anchorRaw", b64(b'{}')), ("approvalRaw", b64(b'{}')), ("catalogue1SHA256", d("foreign"))):
            changed = copy.deepcopy(self.info); changed[field] = value
            self.reject(self.verify_material, changed)

    def test_noncanonical_base64_duplicate_json_and_private_extra_rejected(self):
        self.reject(check.binary, "YQ==\n"); self.reject(check.parse, b'{"a":1,"a":2}')
        changed = copy.deepcopy(self.info); changed["token"] = "sentinel"
        self.reject(self.verify_material, changed)

    def test_missing_wrong_order_or_wrong_kind_public_corpus_rejected(self):
        for edit in (lambda v: v["catalogues"].pop(), lambda v: v["catalogues"].reverse(), lambda v: v.update(kind="dsse")):
            changed = copy.deepcopy(self.info); edit(changed)
            self.reject(self.verify_material, changed)

    def test_bad_signature_must_be_exact_one_byte_mutation(self):
        changed = copy.deepcopy(self.info)
        changed["catalogues"][3] = copy.deepcopy(changed["catalogues"][1]); changed["catalogues"][3]["name"] = "bad-g2"
        self.reject(self.verify_material, changed)

    def test_verifier_tool_failure_is_not_classified_invalid_candidate(self):
        with mock.patch.object(check.subprocess, "run", return_value=argparse.Namespace(returncode=2, stdout=b"", stderr=b"")):
            self.reject(check.signature, b"a" * 32, b"message", b"b" * 64)

    def test_original_plan_bytes_epoch_paths_and_body_hash_are_required(self):
        for edit in (lambda p: p[1].update(epoch=3), lambda p: p[1].update(raw=b64(check.binary(p[1]["raw"]) + b" ")),
                     lambda p: p[1].update(sha256=d("foreign"))):
            plans = copy.deepcopy([*self.reports["prepare"]["feedPlans"], *self.reports["run"]["feedPlans"]]); edit(plans)
            self.reject(check.plan_records, plans[:1], plans[1:], self.flow, self.corpus)

    def test_full_flow_dedup_staleness_restoration_and_offline_replay(self):
        self.assertEqual(self.replay()["sequence"], 9)

    def test_source_connection_missing_close_or_duplicate_ordinal_rejected(self):
        events = [check.parse(x) for x in self.log.splitlines()]
        for changed in (events[:-1], [dict(events[0], ordinal=2), *events[1:]]):
            self.reject(self.replay, None, b"".join(raw(e) + b"\n" for e in changed))

    def test_source_plan_wire_body_or_auth_lie_rejected(self):
        for key, value in (("wireSHA256", h("foreign")), ("representationSHA256", h("foreign")), ("planSHA256", h("foreign")), ("authPresent", True)):
            events = [check.parse(x) for x in self.log.splitlines()]; events[2][key] = value
            self.reject(self.replay, None, b"".join(raw(e) + b"\n" for e in events))

    def test_source_fence_requires_actual_complete_raw_prefix(self):
        changed = copy.deepcopy(self.reports); changed["run"]["observations"][1]["sourceFence"]["sha256"] = h("foreign")
        self.reject(self.replay, changed)

    def test_source_completion_epochs_need_not_be_monotonic(self):
        plans = check.plan_records(self.reports["prepare"]["feedPlans"], self.reports["run"]["feedPlans"], self.flow, self.corpus)
        events = [check.parse(x) for x in self.log.splitlines()]
        http = copy.deepcopy(events[2]); http.update(ordinal=len(events) + 3, connection=len(events) // 4 + 1)
        tail = []
        for row in events[:4]:
            entry = copy.deepcopy(row); entry.update(ordinal=len(events) + len(tail) + 1, connection=len(events) // 4 + 1); tail.append(entry)
        content = b"".join(raw(e) + b"\n" for e in [*events, *tail])
        window = [{"label": "final", "before": {"eventCount": len(events), "sha256": check.image.sha(self.log)},
                   "after": {"eventCount": len(events) + 4, "sha256": check.image.sha(content)}}]
        check.source_events(content, plans, self.corpus, window)

    def test_partial_candidate_outside_stop_window_rejected(self):
        events = [check.parse(x) for x in self.log.splitlines()]; events[2].update(writtenBytes=1, wireComplete=False)
        self.reject(self.replay, None, b"".join(raw(e) + b"\n" for e in events))

    def test_partial_candidate_inside_exact_stop_window_is_not_positive_evidence(self):
        events = [check.parse(x) for x in self.log.splitlines()]; events[-2].update(writtenBytes=1, wireComplete=False)
        content = b"".join(raw(e) + b"\n" for e in events)
        windows = [{"label": "final", "before": {"eventCount": len(events) - 4, "sha256": check.image.sha(b"".join(raw(e) + b"\n" for e in events[:-4]))},
                    "after": {"eventCount": len(events), "sha256": check.image.sha(content)}}]
        self.reject(self.replay, None, content, windows)

    def test_http_403_header_complete_does_not_require_error_body_delivery(self):
        info = self.materials[("http-recovery", self.kind)]
        reports, log, _ = cell_fixture("http-recovery", self.kind, info)
        corpus = {c["name"]: check.binary(c["raw"]) for c in info["catalogues"]}
        plans = check.plan_records(reports["prepare"]["feedPlans"], reports["run"]["feedPlans"], "http-recovery", corpus)
        events = [check.parse(x) for x in log.splitlines()]
        events[2].update(writtenBytes=events[2]["wireBytes"] - events[2]["representationBytes"], wireComplete=False)
        content = b"".join(raw(e) + b"\n" for e in events)
        point = {"eventCount": len(events), "sha256": check.image.sha(content)}
        summary = check.source_events(content, plans, corpus, [{"label": "final", "before": point, "after": point}])[-1]
        self.assertEqual(summary["errorBodyNotFullyWritten"], 1)
        events[2]["writtenBytes"] -= 1
        self.reject(check.source_events, b"".join(raw(e) + b"\n" for e in events), plans, corpus, [{"label": "final", "before": point, "after": point}])

    def test_dedup_requires_three_real_bad_responses_after_ack_fence(self):
        changed = copy.deepcopy(self.reports)
        changed["run"]["observations"][2]["sourceFence"] = copy.deepcopy(changed["run"]["observations"][1]["sourceFence"])
        self.reject(self.replay, changed)

    def test_rejected_candidate_cannot_renew_freshness_or_write_another_history(self):
        for key in ("refreshLastSuccessUnix", "refreshUntilUnix", "sequence"):
            changed = copy.deepcopy(self.reports); changed["run"]["observations"][2]["status"][key] += 1
            self.reject(self.replay, changed)

    def test_natural_stale_requires_observed_time_strictly_after_until(self):
        changed = copy.deepcopy(self.reports); row = changed["run"]["observations"][3]
        row["status"]["observedAtUnix"] = row["status"]["refreshUntilUnix"]
        row["status"]["auditVerifiedAtUnix"] = row["status"]["observedAtUnix"]
        self.reject(self.replay, changed)

    def test_prefix_generation_three_and_no_whole_batch_confirmation(self):
        self.flow = "prefix-recovery"; self.info = self.materials[(self.flow, self.kind)]
        self.reports, self.log, self.windows = cell_fixture(self.flow, self.kind, self.info)
        self.corpus = {c["name"]: check.binary(c["raw"]) for c in self.info["catalogues"]}
        self.docs = {n: check.parse(check.binary(check.parse(v)["payload"])) for n, v in self.corpus.items()}
        self.assertEqual(self.replay()["generation"], 3)
        changed = copy.deepcopy(self.reports); changed["run"]["observations"][1]["status"]["refreshFresh"] = True
        self.reject(self.replay, changed)
        changed = copy.deepcopy(self.reports); changed["run"]["observations"][-1]["history"]["entries"][-1]["generation"] = 4
        self.reject(self.replay, changed)

    def test_audit_original_request_scope_actor_or_ack_tamper_rejected(self):
        for key, value in (("scopeSHA256", d("foreign")), ("actorID", "d12-admin"), ("data", {"catalogueSHA256": d("foreign")})):
            changed = copy.deepcopy(self.reports); changed["reopen"]["offline"]["journal"][0]["operation"][key] = value
            self.reject(self.replay, changed)
        changed = copy.deepcopy(self.reports); changed["reopen"]["offline"]["journal"][0]["acknowledged"] = False
        self.reject(self.replay, changed)

    def test_full_audit_event_chain_not_binding_boolean_is_required(self):
        for field in ("auditEvents", "auditBindings"):
            changed = copy.deepcopy(self.reports); changed["reopen"]["offline"][field].pop()
            self.reject(self.replay, changed)
        # Legitimate interleaving P1/P2/R1/R2: bind by key/hash and original
        # prefix, never assume each operation owns adjacent audit rows.
        changed = copy.deepcopy(self.reports)
        offline = changed["reopen"]["offline"]
        events = offline["auditEvents"]
        events[:] = [events[0], events[2], events[1], events[3]]
        previous = "0" * 64
        for event in events:
            event["previousHash"] = previous; event["hash"] = ""
            event["hash"] = check.image.sha(raw(event, ordered=True)); previous = event["hash"]
        by_key = {e["idempotencyKey"]: e for e in events}
        for index, entry in enumerate(offline["journal"]):
            op = entry["operation"]
            prepared = by_key["image-trust/" + op["id"] + "/prepared"]
            result = by_key["image-trust/" + op["id"] + "/result"]
            op.update(auditBaseCount=index, auditBaseHash="0" * 64 if index == 0 else events[0]["hash"], preparedAuditHash=prepared["hash"])
            entry["resultAuditHash"] = result["hash"]
            offline["auditBindings"][index].update(prepared=prepared, result=result)
            for observation in changed["run"]["observations"]:
                for historical in observation["history"]["entries"]:
                    if historical["operationId"] == op["id"]:
                        historical.update(preparedAuditHash=prepared["hash"], resultAuditHash=result["hash"])
        offline["audit"].update(lastHash=previous, expectedLastHash=previous)
        audit_raw = b"".join(raw(e, ordered=True) + b"\n" for e in events)
        cp_raw = raw({"count": 4, "lastHash": previous}, ordered=True)
        offline["auditLog"] = {"bytes": len(audit_raw), "sha256": check.image.sha(audit_raw)}
        offline["checkpoint"] = {"bytes": len(cp_raw), "sha256": check.image.sha(cp_raw)}
        self.assertEqual(self.replay(changed)["auditEntries"], 4)

    def test_audit_hash_prefix_checkpoint_or_raw_log_tamper_rejected(self):
        for field in ("auditLog", "checkpoint"):
            changed = copy.deepcopy(self.reports); changed["reopen"]["offline"][field]["sha256"] = h("foreign")
            self.reject(self.replay, changed)
        changed = copy.deepcopy(self.reports); changed["reopen"]["offline"]["journal"][0]["operation"]["auditBaseHash"] = h("foreign")
        self.reject(self.replay, changed)

    def test_offline_catalogue_or_ledger_must_match_raw_signed_final(self):
        for key, value in (("ledgerUsed", 1), ("sequence", 10), ("consumptions", [{}])):
            changed = copy.deepcopy(self.reports); changed["reopen"]["offline"]["inspection"][key] = value
            self.reject(self.replay, changed)

    def test_missing_log_marker_only_skip_or_unknown_named_test_rejected(self):
        source = b'import unittest\nclass Tests(unittest.TestCase):\n def test_one(self): pass\n'
        valid = transcript(source, "VERIFIER")
        check.transcript(valid, source, "VERIFIER", 1)
        for content in (valid.splitlines()[-1], valid.replace(b'... ok', b'... skipped'), valid.replace(b'test_one', b'test_other', 1)):
            self.reject(check.transcript, content, source, "VERIFIER", 1)

    def test_closed_own_set_has_seventy_two_files(self):
        self.assertEqual(len(check.own_names()), 72)
        self.assertFalse(check.own_names() & check.FIXTURE_NAMES)

    def test_full_seventy_five_relations_canonical_outcome_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _ = final_fixture(pathlib.Path(temporary), self.graph, self.old_values, self.materials)
            for name in check.FIXTURE_NAMES:
                graph_fixture.put(args.evidence_dir / name, b'{}')
            result = check.verify(args)
            self.assertEqual(len(result["evidenceSHA256"]), 75)
            graph_fixture.put(args.evidence_dir / "product-source-outcome.json", raw(result))
            self.assertEqual(check.verify(args), result)

    def test_missing_unknown_or_outcome_tamper_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _ = final_fixture(pathlib.Path(temporary), self.graph, self.old_values, self.materials)
            graph_fixture.put(args.evidence_dir / "product-source-unknown.json", b'{}')
            self.reject(check.verify, args)
            (args.evidence_dir / "product-source-unknown.json").unlink()
            graph_fixture.put(args.evidence_dir / "product-source-fixture-unknown.json", b'{}')
            self.reject(check.verify, args)
            (args.evidence_dir / "product-source-fixture-unknown.json").unlink()
            graph_fixture.put(args.evidence_dir / "product-source-outcome.json", b'{"outcome":"PASS"}')
            self.reject(check.verify, args)
            (args.evidence_dir / "product-source-outcome.json").unlink()
            name = next(n for n in check.own_names() if n.endswith("-prepare.json")); (args.evidence_dir / name).unlink()
            self.reject(check.verify, args)

    def test_exact_cleanup_rejects_foreign_ids_or_unjoined_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, values = final_fixture(pathlib.Path(temporary), self.graph, self.old_values, self.materials)
            value = values["product-source-runtime-cleanup.json"]
            products = {(r["flow"], r["kind"]): r["containerID"] for r in value["removedContainers"] if r["role"] == "product"}
            rid = value["removedContainers"][-1]["containerID"]
            check.cleanup(value, SOURCE, self.graph["localImageID"], products, rid)
            for edit in (lambda v: v.update(ownedSourcesJoined=5), lambda v: v["removedContainers"][0].update(containerID=h("foreign")),
                         lambda v: v["sourceExitCodes"].__setitem__(0, True)):
                changed = copy.deepcopy(value); edit(changed)
                self.reject(check.cleanup, changed, SOURCE, self.graph["localImageID"], products, rid)

    def test_registry_prepare_budget_zero_windows_and_hidden_gap_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = final_fixture(pathlib.Path(temporary), self.graph, self.old_values, self.materials)
            value = values["product-source-observations.json"]
            graphs = {(f, k): self.graph for f in check.FLOWS for k in check.KINDS}
            check.traffic(value, SOURCE, self.graph["localImageID"], graphs)
            for index in (0, 3, 4):
                changed = copy.deepcopy(value); changed["snapshots"][index]["otherRequests"].append({"method": "GET", "status": 200, "count": 1})
                self.reject(check.traffic, changed, SOURCE, self.graph["localImageID"], graphs)

    def test_source_security_limits_ready_identity_or_stop_join_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = final_fixture(pathlib.Path(temporary), self.graph, self.old_values, self.materials)
            prefix = "product-source-bad-signature-message-signature-"
            process, stopped, ready = [values[prefix + n + ".json"] for n in ("source", "source-stop", "feed-ready")]
            harness = values["product-source-harness.json"]["files"]
            check.source_process(process, stopped, ready, SOURCE, self.flow, self.kind, harness)
            for key, value in (("uid", 0), ("capabilities", "CAP_SYS_ADMIN"), ("sourceCase", "refresh"), ("sourceLimitsVerified", False)):
                changed = copy.deepcopy(process); changed[key] = value
                self.reject(check.source_process, changed, stopped, ready, SOURCE, self.flow, self.kind, harness)

    def test_cli_failure_suppresses_private_exception_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = pathlib.Path(temporary) / "report.json"
            with contextlib.redirect_stderr(io.StringIO()) as errors, mock.patch.object(check, "verify", side_effect=check.CheckError("TOKEN_SENTINEL")):
                code = check.main(["verify", "--evidence-dir", temporary, "--source-commit", SOURCE, "--report", str(report)])
            self.assertEqual(code, 1); self.assertFalse(report.exists()); self.assertNotIn("TOKEN_SENTINEL", errors.getvalue())

    def test_exclusive_output_never_overwrites_existing_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = pathlib.Path(temporary) / "report.json"; graph_fixture.put(report, b"original")
            with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(check, "verify", return_value={"outcome": "PASS"}):
                self.assertEqual(check.main(["verify", "--evidence-dir", temporary, "--source-commit", SOURCE, "--report", str(report)]), 1)
            self.assertEqual(report.read_bytes(), b"original")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SourceTests))
    accepted = result.wasSuccessful() and result.testsRun == 32 and not result.skipped
    if accepted:
        print("D12_SOURCE_VERIFIER_TESTS=PASS tests=32 skipped=0 synthetic_only=true")
    raise SystemExit(0 if accepted else 1)
