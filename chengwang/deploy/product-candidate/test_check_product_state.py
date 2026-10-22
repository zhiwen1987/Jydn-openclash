"""Synthetic state-matrix verifier tests, never real product startup evidence."""
from __future__ import annotations

import argparse
import contextlib
import copy
import io
import pathlib
import tempfile
import unittest

import check_product_state as check
import test_check_product_registry as graph_fixture
import test_check_product_lifecycle as events_fixture
import test_check_product_crash as crash_fixture

SOURCE, NOW = "a" * 40, 1700000000
raw, h, d = events_fixture.raw, events_fixture.h, events_fixture.d
SEQUENCES = {"update": (2, 2, 4, 4, 4, 5), "verify-reserved": (2, 2, 4, 5, 5, 6), "verify-consumed": (2, 2, 5, 5, 5, 6)}
RUNTIME_TEMPLATES = {}


def info_fixture(lane, scenario, kind, graph):
    info = crash_fixture.material(lane + "/" + scenario, kind, graph)
    info.pop("catalogueSHA256")
    info.update(catalogue1SHA256=d(info["storeID"] + "cat1"), catalogue2SHA256=d(info["storeID"] + "cat2"))
    info["policies"][0]["policyID"] = "d12-state-" + lane
    return info


def sdk_fixture(info, graph):
    policy = info["policies"][0]
    projection = {"Schema": "chengwang.managed-binding-evidence/v1", "Grant": policy["grantID"],
        "Catalogue": info["catalogue1SHA256"], "Generation": 1,
        "Reference": "registry.fixture.invalid:5443/chengwang/product-candidate@" + info["manifestSHA256"],
        "Approval": policy["approvalSHA256"], "Manifest": info["manifestSHA256"], "Config": info["configSHA256"],
        "Graph": "", "Bundle": policy["bundleSHA256"], "Root": policy["trustedRootSHA256"],
        "ObservedAtUnixNano": NOW * 1_000_000_000 + 123, "ValidUntilUnix": NOW + 10000}
    data = ("chengwang.local-oci-digest-graph/v1\x00" + projection["Reference"] + "\x00" + projection["Config"] + "\x00").encode()
    for layer in graph["layerDescriptors"]:
        data += (layer["digest"] + "\x00" + layer["diffID"] + "\x00" + str(layer["size"]) + "\x00" + str(layer["uncompressedBytes"]) + "\x00").encode()
    projection["Graph"] = "sha256:" + check.image.sha(data)
    return {"boundary": "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND", "authorization": "BLOCKED", "verified": True,
        "policyID": policy["policyID"], "policyRevision": 1, "evidenceSHA256": "sha256:" + check.image.sha(raw(projection, ordered=True)),
        "projection": projection}


def make_event(op, phase, previous, data, result, info, index, actor=None):
    event_op = dict(op)
    if actor is not None: event_op["actorID"] = actor
    return events_fixture.event(event_op, phase, previous, data, result, info["storeID"], index)


def offline_fixture(info, lane, scenario, phase, sdk):
    initial = phase == "prepare"; healthy = scenario in check.BOUNDARIES
    recovered = healthy and phase in {"reopen-first", "reopen-second"}
    index = check.BOUNDARIES.index(scenario) if healthy else -1
    early = healthy and index < 2
    state = "PREPARED" if early or initial else "COMMITTED" if lane == "update" else "RESERVED" if lane == "verify-reserved" else "CONSUMED"
    outcome = ("INTERRUPTED" if recovered else "") if early or initial else (
        "CATALOGUE_COMMITTED" if lane == "update" else "VERIFICATION_CONSUMED" if lane == "verify-consumed" else
        "" if healthy and index == 2 and not recovered else "VERIFICATION_RESERVED_NOT_COMPLETED")
    sequence = 1 if initial else SEQUENCES[lane][index] if healthy and not recovered else (
        5 if lane == "update" or early else 6)
    if not initial and not healthy:
        sequence = (5 if lane == "update" else 6) - int(scenario in {"prepared-audit-missing", "result-key-conflict"}) + int(scenario == "later-invalid-acked")
    gen = 2 if state == "COMMITTED" else 1
    ledger = state if state in {"RESERVED", "CONSUMED"} else "AVAILABLE"
    policy = info["policies"][0]
    adapted = dict(info); adapted["catalogueSHA256"] = info["catalogue%dSHA256" % gen]
    evidence = sdk["evidenceSHA256"] if sdk is not None and state == "CONSUMED" else ""
    fields = crash_fixture.offline_fields(adapted, sequence, ledger, [], [])
    fields["inspection"]["catalogue"]["generation"] = gen
    if ledger != "AVAILABLE": fields["inspection"]["consumptions"][0]["evidenceSHA256"] = evidence
    entries, events = [], []
    if scenario == "wrong-prefix" and not initial:
        base_op = {"id": "d12-state-base", "actorID": "d12-state-admin", "kind": "read"}
        base = make_event(base_op, "prepared", "0" * 64, {}, "observed", info, 1)
        base["idempotencyKey"] = "state-matrix/base"; base["hash"] = ""
        base["hash"] = check.image.sha(raw(base, ordered=True)); events.append(base)
    for entry_index in range(0 if initial else 2 if scenario == "later-invalid-acked" else 1):
        first_later = scenario == "later-invalid-acked" and entry_index == 0
        desired_state, desired_outcome = ("PREPARED", "") if first_later else (state, outcome)
        data = {"catalogueSHA256": info["catalogue2SHA256"]} if lane == "update" else {"policyId": policy["policyID"],
            "approvalSHA256": policy["approvalEnvelopeSHA256"], "bundleSHA256": policy["bundleSHA256"], "rootSHA256": policy["trustedRootSHA256"]}
        op = {"id": h(info["storeID"] + str(entry_index))[:32], "actorID": "d12-state-admin",
            "scopeSHA256": "sha256:" + check.image.sha(raw(check.scope(info["storeID"]), ordered=True)), "kind": "update" if lane == "update" else "verify",
            "data": data, "auditBaseCount": int(scenario == "wrong-prefix"), "auditBaseHash": "1" * 64 if scenario == "wrong-prefix" else "0" * 64,
            "preparedAuditHash": ""}
        has_domain = desired_state in {"RESERVED", "CONSUMED"}
        cat = info["catalogue2SHA256"] if desired_state == "COMMITTED" else info["catalogue1SHA256"]
        out_data = {"catalogueSHA256": cat} if desired_state == "COMMITTED" else ({"grantId": policy["grantID"],
            "manifestSHA256": info["manifestSHA256"], "catalogueSHA256": cat} if has_domain and desired_outcome else {})
        if desired_state == "CONSUMED": out_data["evidenceSHA256"] = evidence
        ack = not first_later and (recovered or healthy and index == 5 or not healthy and scenario not in {"prepared-audit-missing", "result-key-conflict"})
        entry = {"operation": op, "state": desired_state, "outcome": desired_outcome, "outcomeData": out_data, "acknowledged": ack,
            "resultAuditHash": "", "grantID": policy["grantID"] if has_domain else "", "generation": 2 if desired_state == "COMMITTED" else int(has_domain),
            "catalogueSHA256": cat if has_domain or desired_state == "COMMITTED" else "", "manifestSHA256": info["manifestSHA256"] if has_domain else "",
            "evidenceSHA256": evidence if desired_state == "CONSUMED" else ""}
        if not first_later:
            event_count = 2 if recovered else (0, 1, 1, 1, 2, 2)[index] if healthy else 2
            previous = events[-1]["hash"] if events else "0" * 64
            if event_count:
                prepared = make_event(op, "prepared", previous, data, "prepared", info, len(events) + 1,
                    "d12-state-foreign" if scenario in {"prepared-key-conflict", "later-invalid-acked"} else None)
                if recovered or not healthy or index >= 2: op["preparedAuditHash"] = prepared["hash"]
                events.append(prepared)
            if event_count == 2:
                result = make_event(op, "result", events[-1]["hash"], out_data,
                    "completed" if desired_outcome == "CATALOGUE_COMMITTED" else "verification_consumed" if desired_outcome == "VERIFICATION_CONSUMED"
                    else "interrupted" if desired_outcome == "INTERRUPTED" else "rejected", info, len(events) + 1,
                    "d12-state-foreign" if scenario == "result-key-conflict" else None)
                events.append(result)
                if ack: entry["resultAuditHash"] = result["hash"]
        entries.append(entry)
    if scenario in {"acked-audit-missing", "prepared-audit-missing"} and not initial: events = []
    mapping = {event["idempotencyKey"]: event for event in events}
    bindings = [{"operationID": entry["operation"]["id"], "prepared": mapping.get("image-trust/" + entry["operation"]["id"] + "/prepared"),
        "result": mapping.get("image-trust/" + entry["operation"]["id"] + "/result")} for entry in entries]
    tail = events[-1]["hash"] if events else "0" * 64
    audit = {"valid": True, "count": len(events), "expectedCount": len(events), "lastHash": tail, "expectedLastHash": tail,
             "verifiedAt": events_fixture.stamp(NOW + 50)}
    payload = b"".join(check.crash.event_bytes(event) for event in events)
    checkpoint = b"{}\n" if scenario == "bad-checkpoint" and not initial else raw({"count": len(events), "lastHash": tail}, ordered=True)
    result = {"inspection": fields["inspection"], "journal": entries, "auditOpen": "rejected-checkpoint" if scenario == "bad-checkpoint" and not initial else "verified",
        "audit": None if scenario == "bad-checkpoint" and not initial else audit, "auditEvents": events, "auditBindings": bindings,
        "auditLog": {"bytes": len(payload), "sha256": check.image.sha(payload)},
        "checkpoint": {"bytes": len(checkpoint), "sha256": check.image.sha(checkpoint)}}
    result["trustRecordSHA256"] = h(raw({"inspection": result["inspection"], "journal": entries}).decode())
    return result


def report_fixture(lane, scenario, kind, graph):
    info = info_fixture(lane, scenario, kind, graph)
    sdk = sdk_fixture(info, graph) if lane == "verify-consumed" and (scenario in check.FAULTS or check.BOUNDARIES.index(scenario) >= 2) else None
    reports = {}
    for action in check.actions(scenario):
        report = {"schema": "chengwang.product-state-action/v1", "action": action, "lane": lane, "scenario": scenario,
            "caseKind": "healthy" if scenario in check.BOUNDARIES else "rejected", **copy.deepcopy(info), "boundary": "ADVISORY_PRODUCT_STATE_FIXTURE",
            "authority": "EPHEMERAL_TEST_ONLY", "graphOrigin": check.registry.GRAPH_ORIGIN, **check.BOUNDARY,
            "canonicalScope": check.scope(info["storeID"]), "configuredScope": check.scope(info["storeID"], configured=True, scenario=scenario)}
        if action != "prepare" and sdk: report["sdk"] = copy.deepcopy(sdk)
        if action in {"first-read", "second-read"}:
            offline = offline_fixture(info, lane, scenario, "reopen-first", sdk)
            adapted = dict(info); adapted["catalogueSHA256"] = info["catalogue%dSHA256" % offline["inspection"]["catalogue"]["generation"]]
            ledger = offline["inspection"]["consumptions"][0]["status"] if offline["inspection"]["ledgerUsed"] else "AVAILABLE"
            status = crash_fixture.snapshot(adapted, offline["inspection"]["sequence"], ledger,
                int(action == "first-read" and scenario != "after-journal-ack"))
            status["generation"] = offline["inspection"]["catalogue"]["generation"]
            rows = []
            for entry, binding in zip(offline["journal"], offline["auditBindings"]):
                op = entry["operation"]
                rows.append({"operationId": op["id"], "actorId": "d12-state-admin", "kind": op["kind"], "state": entry["state"],
                    "outcome": entry["outcome"], "acknowledged": True, "policyId": op["data"].get("policyId", ""),
                    "grantId": entry["grantID"], "generation": entry["generation"], "catalogueSHA256": entry["catalogueSHA256"],
                    "preparedAuditHash": op["preparedAuditHash"], "resultAuditHash": entry["resultAuditHash"],
                    "preparedAtUnix": check.lifecycle.event_time(binding["prepared"]["occurredAt"]),
                    "resultAtUnix": check.lifecycle.event_time(binding["result"]["occurredAt"])})
            history = {"boundary": "ADVISORY_TRUST_OPERATION_HISTORY", "authorization": "BLOCKED", "deviceActionsExecuted": False,
                "observedAtUnix": NOW + 100, "sequence": offline["inspection"]["sequence"], "total": len(rows), "offset": 0, "limit": 50, "entries": rows}
            report.update(status=status, history=history, auditLog=offline["auditLog"], checkpoint=offline["checkpoint"])
        else: report["offline"] = offline_fixture(info, lane, scenario, action, sdk)
        reports[action] = report
    return reports


def runtime_fixture(graph, lane, scenario, kind, index=0):
    key = (graph["localImageID"], kind)
    if key not in RUNTIME_TEMPLATES:
        RUNTIME_TEMPLATES[key] = crash_fixture.runtime_fixture(graph, "prepared", kind)
    original, processes, _ = copy.deepcopy(RUNTIME_TEMPLATES[key])
    container = h(lane + "/" + scenario + "/" + kind)
    for label, value in original.items():
        offset = 0 if label in ("running", "killed") else 1 if label.startswith("recovered") else 2
        value["containerID"] = container
        value["pid"] = 100 + index * 10 + offset if label.endswith("running") else 0
    for label, value in processes.items():
        offset = 0 if label == "running" else 1 if label.startswith("recovered") else 2
        value.update(containerID=container, hostPID=100 + index * 10 + offset, startTime=200 + index * 10 + offset)
    healthy = scenario in check.BOUNDARIES
    projections, pids, startups = {}, {}, {}
    for attempt, old_label in (("first", "running"), ("second", "recovered-running")):
        if healthy:
            for suffix, old in (("running", old_label), ("exited", "recovered-exited" if attempt == "first" else "idempotent-exited")):
                value = copy.deepcopy(original[old]); value.pop("plannedSIGKILL"); value["startupRejected"] = False
                projections[attempt + "-" + suffix] = value
            pids[attempt] = copy.deepcopy(processes[old_label])
        else:
            value = copy.deepcopy(original["killed"]); value.pop("plannedSIGKILL"); value.update(startupRejected=True, exitCode=1)
            projections[attempt + "-rejected"] = value
            offset = index * 100_000_000_000 + (0 if attempt == "first" else 10_000_000_000)
            startups[attempt] = {"schema": "chengwang.product-state-startup/v1", "sourceCommit": SOURCE,
                "localImageID": graph["localImageID"], "lane": lane, "scenario": scenario, "kind": kind, "caseKind": "rejected",
                "attempt": attempt, "containerID": value["containerID"], "startedAt": events_fixture.stamp(NOW + index * 20 + (0 if attempt == "first" else 10)),
                "finishedAt": events_fixture.stamp(NOW + index * 20 + (1 if attempt == "first" else 11)),
                "observationStartMonotonicNS": offset + 1, "observationEndMonotonicNS": offset + 1_000_000_000,
                "probes": [{"ordinal": n, "monotonicNS": offset + n * 100_000_000, "transport": "CONNECTION_REFUSED", "httpStatus": 0} for n in (1, 2, 3)],
                "finalNamespaceAPINotListening": True, "exitCode": 1, "oomKilled": False, "pid": 0, "naturalExit": True,
                "cliDiagnostic": {"code": "CANDIDATE_CONFIGURATION_REJECTED", "count": 1}, "pid1SampleCaptured": False, **check.BOUNDARY}
    return projections, pids, startups


def traffic_fixture(graph):
    counters, rows, seeded = {}, [], {}
    for lane, scenario, kind in check.cells():
        cell = (lane, scenario, kind)
        consume = lane == "verify-consumed" and (scenario in check.FAULTS or check.BOUNDARIES.index(scenario) >= 2)
        seeded[cell] = consume
        for window in ("prepare", "seed", "first", "second"):
            for position in ("before", "after"):
                if position == "after" and window == "prepare":
                    change = {("GET", graph["registryManifestDigest"], 200): 1, ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                              ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
                    for layer in (graph["configDescriptor"], *graph["layerDescriptors"]): change[("GET", layer["digest"], 200)] = 1
                elif position == "after" and window == "seed" and consume: change = check.crash.sdk_budget(graph)
                else: change = {}
                for key, amount in change.items(): counters[key] = counters.get(key, 0) + amount
                digest_records, other_records = [], []
                for (method, digest, status), count in sorted(counters.items()):
                    row = {"method": method, "status": status, "count": count}
                    if digest: row["digest"] = digest; digest_records.append(row)
                    else: other_records.append(row)
                rows.append({"ordinal": len(rows) + 1, "lane": lane, "scenario": scenario, "kind": kind,
                    "caseKind": "healthy" if scenario in check.BOUNDARIES else "rejected", "window": window, "position": position,
                    "digestRequests": digest_records, "otherRequests": other_records})
    return {"schema": "chengwang.product-state-observations/v1", "sourceCommit": SOURCE, "localImageID": graph["localImageID"],
        "registryContainerID": "c" * 64, "pinnedRegistryImage": check.registry.REGISTRY_IMAGE, "snapshots": rows, **check.BOUNDARY}, seeded


def cleanup_fixture(graph, products):
    return {"schema": "chengwang.product-state-cleanup/v1", "sourceCommit": SOURCE, "localImageID": graph["localImageID"],
        "outcome": "PASS", "ownedContainersRemoved": 85, "removedContainers": [
            {"containerID": products[cell], "role": "product", "lane": cell[0], "scenario": cell[1], "kind": cell[2]} for cell in check.cells()]
            + [{"containerID": "c" * 64, "role": "registry", "lane": "", "scenario": "", "kind": ""}],
        "healthyNormalStops": 72, "rejectedNaturalExits": 96, "maximumConcurrentOwnedContainers": 2, "noOwnedContainersRemain": True,
        "ownedHelpersJoined": 0, "privateFixtureRemoved": True, "outerProductImagePreserved": True, "registryImagePreserved": True,
        "registryStop": {"exitCode": 0, "oomKilled": False, "pid": 0, "signal": "SIGTERM"}, **check.BOUNDARY}


def final_fixture(root):
    args, old = graph_fixture.synthetic_final_evidence(root)
    graph = old["product-registry-message-signature-graph.json"]
    values = {name: value for name, value in old.items() if name.startswith("product-image-")}
    for label in ("isolation", "network"): values["product-state-" + label + ".json"] = old["product-registry-" + label + ".json"]
    values["product-state-observations.json"], _ = traffic_fixture(graph)
    values["product-state-harness.json"] = {"schema": "chengwang.product-state-harness/v1", "sourceCommit": SOURCE,
        "files": {name: check.image.sha(pathlib.Path(check.__file__).with_name(pathlib.PurePosixPath(name).name).read_bytes()) for name in check.HARNESS_PATHS},
        "checkoutBytesMatched": True, "permissionReadOnly": True, **check.BOUNDARY}
    products = {}
    for index, cell in enumerate(check.cells()):
        for action, report in report_fixture(*cell, graph).items(): values[check.report_name(*cell, action)] = report
        values[check.report_name(*cell, "graph")] = graph
        projections, pids, startups = runtime_fixture(graph, *cell, index)
        products[cell] = next(iter(projections.values()))["containerID"]
        for label, report in projections.items(): values[check.report_name(*cell, label + "-inspect")] = report
        for label, report in pids.items(): values[check.report_name(*cell, label + "-running-pid1")] = report
        for label, report in startups.items(): values[check.report_name(*cell, label + "-startup")] = report
    values["product-state-runtime-cleanup.json"] = cleanup_fixture(graph, products)
    for label, test, marker in (
        ("profile", "test_state_image_profile.py", "D12_STATE_IMAGE_PROFILE_TESTS=PASS tests=8 skipped=0 synthetic_only=true"),
        ("verifier", "test_check_product_state.py", "PRODUCT_STATE_VERIFIER_TESTS=PASS synthetic_only=true tests=32 skipped=0")):
        values["product-state-" + label + "-tests.log"] = crash_fixture.transcript(pathlib.Path(check.__file__).with_name(test).read_bytes(), marker)
    for name, value in values.items(): graph_fixture.put(args.evidence_dir / name, value if isinstance(value, bytes) else raw(value))
    return args, values


class GraphCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        args, _, _ = graph_fixture.fixture(pathlib.Path(self.temp.name)); self.graph = check.registry.graph(args)

    def verify_flow(self, reports, lane="update", scenario="after-journal-prepare", kind="message-signature"):
        return check.action_sequence(reports, lane, scenario, kind, SOURCE, self.graph["localImageID"], self.graph)

    def rejected_edit(self, scenario, edit, lane="verify-consumed"):
        reports = report_fixture(lane, scenario, "message-signature", self.graph); edit(reports)
        with self.assertRaises((check.CheckError, KeyError, ValueError, TypeError)):
            self.verify_flow(reports, lane, scenario)


class FlowTests(GraphCase):
    def test_all_36_healthy_boundary_lane_signature_cells(self):
        for lane in ("update", "verify-reserved", "verify-consumed"):
            for scenario in check.BOUNDARIES:
                for kind in ("message-signature", "dsse"):
                    self.verify_flow(report_fixture(lane, scenario, kind, self.graph), lane, scenario, kind)

    def test_all_48_injected_rejection_cells_are_specific_and_unchanged(self):
        for lane in ("update", "verify-reserved", "verify-consumed"):
            for scenario in check.FAULTS:
                for kind in ("message-signature", "dsse"):
                    self.verify_flow(report_fixture(lane, scenario, kind, self.graph), lane, scenario, kind)

    def test_after_prepared_audit_is_seq2_and_still_unbound(self):
        reports = report_fixture("update", "after-prepared-audit", "message-signature", self.graph)
        seed = reports["seed"]["offline"]
        self.assertEqual(seed["inspection"]["sequence"], 2); self.assertEqual(seed["journal"][0]["operation"]["preparedAuditHash"], "")
        seed["inspection"]["sequence"] = 3
        with self.assertRaises(check.CheckError): self.verify_flow(reports, "update", "after-prepared-audit")

    def test_missing_material_action_or_unknown_protocol_field(self):
        for edit in (lambda r: r.pop("seed"), lambda r: r["seed"].update(secret="SENTINEL"),
                     lambda r: r["prepare"].update(catalogue1SHA256=d("other"))):
            self.rejected_edit("after-journal-prepare", edit)

    def test_sdk_evidence_hash_is_original_go_struct_order(self):
        self.rejected_edit("before-result-audit", lambda r: r["seed"]["sdk"].update(evidenceSHA256=d("fake")))

    def test_sdk_graph_binds_actual_layers_reference_and_config(self):
        for key in ("Graph", "Reference", "Config"):
            self.rejected_edit("before-result-audit", lambda r, key=key: r["seed"]["sdk"]["projection"].update({key: d("fake")}))

    def test_consumed_requires_sdk_and_early_intent_cannot_claim_it(self):
        self.rejected_edit("before-result-audit", lambda r: r["seed"].pop("sdk"))
        self.rejected_edit("after-journal-prepare", lambda r: r["seed"].update(sdk={"verified": True}))

    def test_wrong_scope_requires_frozen_other_site_only(self):
        self.rejected_edit("wrong-scope", lambda r: r["seed"].update(configuredScope=r["seed"]["canonicalScope"]))

    def test_wrong_prefix_requires_real_nonzero_original_chain(self):
        self.rejected_edit("wrong-prefix", lambda r: r["seed"]["offline"]["journal"][0]["operation"].update(auditBaseCount=0))

    def test_prepared_key_conflict_cannot_be_generic_corruption(self):
        self.rejected_edit("prepared-key-conflict", lambda r: r["seed"]["offline"]["journal"][0]["operation"].update(preparedAuditHash=""))

    def test_result_key_conflict_cannot_be_acknowledged_success(self):
        self.rejected_edit("result-key-conflict", lambda r: r["seed"]["offline"]["journal"][0].update(acknowledged=True))

    def test_missing_audit_still_retains_original_bound_hashes(self):
        self.rejected_edit("acked-audit-missing", lambda r: r["seed"]["offline"]["journal"][0].update(resultAuditHash=""))

    def test_later_invalid_must_follow_unacknowledged_first_intent(self):
        self.rejected_edit("later-invalid-acked", lambda r: r["seed"]["offline"]["journal"].reverse())

    def test_later_invalid_must_not_repair_first_operation(self):
        self.rejected_edit("later-invalid-acked", lambda r: r["reopen-first"]["offline"]["journal"][0].update(outcome="INTERRUPTED"))

    def test_audit_bytes_hash_timestamp_and_semantics_tampering(self):
        for edit in (lambda r: r["seed"]["offline"]["auditLog"].update(sha256=h("bad")),
                     lambda r: r["seed"]["offline"]["auditEvents"][0].update(occurredAt="unsafe"),
                     lambda r: r["seed"]["offline"]["auditEvents"][0].update(hash="0" * 64)):
            self.rejected_edit("prepared-key-conflict", edit)

    def test_bad_checkpoint_exact_bytes_cannot_be_silently_rebuilt(self):
        self.rejected_edit("bad-checkpoint", lambda r: r["reopen-first"]["offline"]["checkpoint"].update(bytes=0, sha256=h("")))

    def test_private_logical_record_digest_must_survive_failed_start(self):
        self.rejected_edit("wrong-scope", lambda r: r["reopen-second"]["offline"].update(trustRecordSHA256=h("mutated")))

    def test_reserved_and_consumed_ledgers_cannot_be_recycled(self):
        for lane in ("verify-reserved", "verify-consumed"):
            self.rejected_edit("wrong-scope", lambda r: r["reopen-first"]["offline"]["inspection"].update(ledgerUsed=0, consumptions=[]), lane)

    def test_second_start_recovery_count_must_be_zero(self):
        self.rejected_edit("before-result-audit", lambda r: r["second-read"]["status"].update(recoveryCompleted=1))

    def test_private_key_token_raw_config_and_fake_crash_fields_rejected(self):
        for key in ("privateKey", "token", "rawConfig", "actualCrash"):
            self.rejected_edit("wrong-scope", lambda r, key=key: r["seed"].update({key: "SECRET_SENTINEL"}))


class RuntimeTests(GraphCase):
    def verify_runtime(self, values, lane="update", scenario="after-journal-prepare"):
        return check.runtime(*values, lane, scenario, "message-signature", SOURCE, self.graph["localImageID"],
            "c" * 64, h("synthetic-executable-not-run"))

    def test_healthy_actual_two_starts_pid1_security_and_normal_exit(self):
        values = runtime_fixture(self.graph, "update", "after-journal-prepare", "message-signature")
        self.verify_runtime(values)
        values[1]["second"]["capabilities"] = "CAP_SYS_ADMIN"
        with self.assertRaises(check.CheckError): self.verify_runtime(values)

    def test_rejected_must_be_natural_one_not_137_or_oom(self):
        for edit in (lambda v: v[0]["first-rejected"].update(exitCode=137),
                     lambda v: v[2]["first"].update(oomKilled=True), lambda v: v[2]["first"].update(naturalExit=False)):
            values = runtime_fixture(self.graph, "update", "bad-checkpoint", "message-signature")
            edit(values)
            with self.assertRaises(check.CheckError): self.verify_runtime(values, scenario="bad-checkpoint")

    def test_tls_identity_timeout_http_or_boolean_only_probe_fails(self):
        for transport in ("TIMEOUT", "TLS_HTTP", "TLS_IDENTITY_ERROR", "NO_API"):
            values = runtime_fixture(self.graph, "update", "bad-checkpoint", "message-signature")
            values[2]["first"]["probes"][0]["transport"] = transport
            with self.assertRaises(check.CheckError): self.verify_runtime(values, scenario="bad-checkpoint")

    def test_restart_container_process_identity_and_bounds_required(self):
        for edit in (lambda v: v[1]["second"].update(startTime=v[1]["first"]["startTime"], hostPID=v[1]["first"]["hostPID"]),
                     lambda v: v[0]["second-exited"].update(containerID="e" * 64)):
            values = runtime_fixture(self.graph, "update", "after-journal-prepare", "message-signature"); edit(values)
            with self.assertRaises(check.CheckError): self.verify_runtime(values)

    def test_cleanup_requires_85_exact_owned_ids_and_normal_registry(self):
        products = {cell: h(str(cell)) for cell in check.cells()}; value = cleanup_fixture(self.graph, products)
        check.cleanup(value, SOURCE, self.graph["localImageID"], "c" * 64, products)
        for edit in (lambda x: x["removedContainers"].pop(), lambda x: x["removedContainers"][0].update(containerID="c" * 64),
                     lambda x: x["registryStop"].update(exitCode=137), lambda x: x.update(rejectedNaturalExits=95)):
            current = copy.deepcopy(value); edit(current)
            with self.assertRaises(check.CheckError): check.cleanup(current, SOURCE, self.graph["localImageID"], "c" * 64, products)


class TrafficTests(GraphCase):
    def validate(self, value, seeded):
        return check.observation_projection(value, SOURCE, self.graph["localImageID"], {cell: self.graph for cell in check.cells()}, seeded)

    def test_all_672_snapshots_and_168_startup_zero_windows(self):
        value, seeded = traffic_fixture(self.graph)
        self.assertEqual(len(value["snapshots"]), 672); self.assertEqual(sum(seeded.values()), 24)
        self.assertEqual(self.validate(value, seeded), "c" * 64)

    def test_hidden_requests_gaps_decreasing_counts_or_missing_window(self):
        valid, seeded = traffic_fixture(self.graph)
        for edit in (lambda x: x["snapshots"].pop(), lambda x: x["snapshots"][2]["digestRequests"][0].update(count=999),
                     lambda x: x["snapshots"][1].update(ordinal=True)):
            value = copy.deepcopy(valid); edit(value)
            with self.assertRaises(check.CheckError): self.validate(value, seeded)

    def test_seed_sdk_budget_is_not_recovery_or_synthetic_hash_only(self):
        valid, seeded = traffic_fixture(self.graph)
        # Claiming an SDK result without its one real read is rejected, as is
        # treating an early intent as a completed consumption.
        first = next(iter(seeded)); seeded[first] = True
        with self.assertRaises(check.CheckError): self.validate(valid, seeded)


class TranscriptTests(unittest.TestCase):
    def test_complete_named_source_tests_zero_skip_not_marker_only(self):
        source = b'import unittest\nclass Shape(unittest.TestCase):\n def test_one(self): pass\n'
        marker = "SYNTHETIC=PASS tests=1 skipped=0"
        valid = crash_fixture.transcript(source, marker)
        self.assertEqual(check.crash.test_transcript(valid, source, marker, 1)["tests"], 1)
        for data in (marker.encode(), valid.replace(b'... ok', b'... skipped'), valid + marker.encode() + b'\n'):
            with self.assertRaises(check.CheckError): check.crash.test_transcript(data, source, marker, 1)


class FullGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.args, self.values = final_fixture(pathlib.Path(self.temp.name))

    def test_entire_906_own_909_relation_canonical_synthetic_gate(self):
        result = check.verify(self.args)
        self.assertEqual(len(check.own_names()), 906); self.assertEqual(len(result["evidenceSHA256"]), 909)
        self.assertEqual((result["healthyCases"], result["rejectedCases"]), (36, 48))
        self.assertFalse(result["actualCrashProvenByThisGate"]); self.assertFalse(result["recoveryAuthorized"])
        graph_fixture.put(self.args.evidence_dir / "product-state-outcome.json", raw(result))
        self.assertEqual(check.verify(self.args), result)

    def test_missing_input_unknown_prefix_and_tampered_outcome_fail_closed(self):
        name = check.report_name("update", "after-journal-prepare", "message-signature", "seed")
        path = self.args.evidence_dir / name; original = path.read_bytes(); path.unlink()
        with self.assertRaises(check.CheckError): check.verify(self.args)
        graph_fixture.put(path, original)
        bad = self.args.evidence_dir / "product-state-secret.private.json"; graph_fixture.put(bad, b'{"secret":"SENTINEL"}')
        with self.assertRaises(check.CheckError): check.verify(self.args)
        bad.unlink(); result = check.verify(self.args); result["actualCrashProvenByThisGate"] = True
        graph_fixture.put(self.args.evidence_dir / "product-state-outcome.json", raw(result))
        with self.assertRaises(check.CheckError): check.verify(self.args)


class CLITests(GraphCase):
    def test_exclusive_report_and_safe_failure_without_raw_errors(self):
        root = pathlib.Path(self.temp.name); args, _, _ = graph_fixture.fixture(root / "cli")
        command = ["graph", "--graph-dir", str(args.graph_dir), "--packaged-report", str(args.packaged_report),
            "--source-commit", SOURCE, "--manifest-digest", args.manifest_digest, "--report", str(root / "result.json")]
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(check.main(command), 0)
        original = (root / "result.json").read_bytes(); output = io.StringIO()
        with contextlib.redirect_stderr(output): self.assertEqual(check.main(command), 1)
        self.assertEqual((root / "result.json").read_bytes(), original)
        self.assertEqual(output.getvalue(), "PRODUCT_STATE_CHECK=FAIL rejected=true raw_input_suppressed=true\n")
        graph_fixture.put(args.graph_dir / "manifest.json", b'{"SECRET_SENTINEL":NaN}')
        command[-1] = str(root / "new.json"); output = io.StringIO()
        with contextlib.redirect_stderr(output): self.assertEqual(check.main(command), 1)
        self.assertNotIn("SENTINEL", output.getvalue()); self.assertFalse((root / "new.json").exists())


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    success = result.wasSuccessful() and not result.skipped and result.testsRun == 32
    if success: print("PRODUCT_STATE_VERIFIER_TESTS=PASS synthetic_only=true tests=32 skipped=0")
    raise SystemExit(0 if success else 1)
