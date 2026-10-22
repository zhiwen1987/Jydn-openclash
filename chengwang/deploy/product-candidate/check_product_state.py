#!/usr/bin/env python3
"""Independent safe projections of pre-seeded constructor states, never crashes.

The graph command runs against private bytes inside CI. Reviewer verification
uses only the exported safe projections and never confers recovery authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
import check_product_image as image
import check_product_registry as registry
import check_product_lifecycle as lifecycle
import check_product_crash as crash

CheckError = image.CheckError
require, exact, integer = image.require, registry.exact, registry.integer
digest, bare_hash, public_id = registry.digest, registry.bare_hash, registry.public_id
encoded = lifecycle.encoded
BOUNDARY, KINDS = registry.BOUNDARY, registry.KINDS
LANES = ("update", "verify-reserved", "verify-consumed")
BOUNDARIES = ("after-journal-prepare", "after-prepared-audit", "before-result-audit",
              "after-journal-outcome", "after-result-audit", "after-journal-ack")
FAULTS = ("acked-audit-missing", "prepared-audit-missing", "wrong-prefix",
          "prepared-key-conflict", "result-key-conflict", "wrong-scope",
          "bad-checkpoint", "later-invalid-acked")
ACTOR, FOREIGN_ACTOR = "d12-state-admin", "d12-state-foreign"
ZERO = "0" * 64
CUT_SEQUENCE = {"update": (2, 2, 4, 4, 4, 5),
                "verify-reserved": (2, 2, 4, 5, 5, 6),
                "verify-consumed": (2, 2, 5, 5, 5, 6)}
WINDOWS = ("prepare", "seed", "first", "second")
VERIFIER_TEST_COUNT = 32
RUNTIME_PATHS = tuple("chengwang/deploy/product-candidate/" + name for name in (
    "check_product_state.py", "check_product_image.py", "check_product_registry.py",
    "check_product_lifecycle.py", "check_product_crash.py"))
HARNESS_PATHS = (*RUNTIME_PATHS, *("chengwang/deploy/product-candidate/" + name for name in (
    "test_state_image_profile.py", "test_check_product_state.py")))
SUPPORT_NAMES = frozenset(("product-state-profile-tests.log", "product-state-verifier-tests.log"))


def case_kind(scenario):
    require(scenario in (*BOUNDARIES, *FAULTS), "unknown state scenario")
    return "healthy" if scenario in BOUNDARIES else "rejected"


def cells():
    return tuple((lane, scenario, kind) for lane in LANES
                 for scenario in (*BOUNDARIES, *FAULTS) for kind in KINDS)


def actions(scenario):
    return ("prepare", "seed", "first-read", "reopen-first", "second-read", "reopen-second") \
        if case_kind(scenario) == "healthy" else ("prepare", "seed", "reopen-first", "reopen-second")


def report_name(lane, scenario, kind, label):
    require(lane in LANES and kind in KINDS, "state cell identity rejected")
    case_kind(scenario)
    return "product-state-" + lane + "-" + scenario + "-" + kind + "-" + label + ".json"


def own_names():
    names = set()
    for lane, scenario, kind in cells():
        labels = (*actions(scenario), "graph")
        if case_kind(scenario) == "healthy":
            labels += tuple(start + suffix for start in ("first", "second")
                            for suffix in ("-running-inspect", "-exited-inspect", "-running-pid1"))
        else:
            labels += tuple(start + suffix for start in ("first", "second")
                            for suffix in ("-rejected-inspect", "-startup"))
        names.update(report_name(lane, scenario, kind, label) for label in labels)
    names.update("product-state-" + name + ".json" for name in (
        "harness", "network", "isolation", "observations", "runtime-cleanup", "outcome"))
    require(len(names) == 906, "state file protocol changed")
    return names


def scope(store, *, configured=False, scenario=""):
    return {"tenantId": "d12-tenant", "siteId": "other-site" if configured and scenario == "wrong-scope" else "d12-site",
            "objectType": "image-trust", "objectId": store, "environment": "candidate"}


def typed_equal(actual, wanted, message):
    require(type(actual) is type(wanted) and actual == wanted, message)


def delta(before, after):
    require(all(after.get(key, 0) >= value for key, value in before.items()), "counter decreased")
    return {key: value - before.get(key, 0) for key, value in after.items() if value != before.get(key, 0)}


def observation_projection(value, source, local_id, graphs, seeded_consumption):
    exact(value, ("schema", "sourceCommit", "localImageID", "registryContainerID", "pinnedRegistryImage", *BOUNDARY, "snapshots"))
    registry.boundary(value)
    require(value["schema"] == "chengwang.product-state-observations/v1" and value["sourceCommit"] == source
            and value["localImageID"] == local_id and value["pinnedRegistryImage"] == registry.REGISTRY_IMAGE,
            "state Registry identity rejected")
    identity = bare_hash(value["registryContainerID"])
    expected = [(lane, scenario, kind, window, position) for lane, scenario, kind in cells()
                for window in WINDOWS for position in ("before", "after")]
    rows = value["snapshots"]
    require(isinstance(rows, list) and len(rows) == len(expected) == 672, "state windows incomplete")
    previous, counters = {}, {}
    for ordinal, (row, step) in enumerate(zip(rows, expected), 1):
        exact(row, ("ordinal", "lane", "scenario", "kind", "caseKind", "window", "position", "digestRequests", "otherRequests"))
        typed_equal(row["ordinal"], ordinal, "state counter ordinal rejected")
        require((row["lane"], row["scenario"], row["kind"], row["window"], row["position"]) == step
                and row["caseKind"] == case_kind(step[1]), "state counter order rejected")
        current = crash.traffic_counts(row)
        graph = graphs[step[:3]]
        allowed = {graph["registryManifestDigest"], graph["configDescriptor"]["digest"], *(x["digest"] for x in graph["layerDescriptors"])}
        require(all(not key[1] or key[1] in allowed for key in current), "unbound Registry object")
        delta(previous, current)
        require((not current if ordinal == 1 else current == previous) if step[4] == "before" else True,
                "unobserved state Registry traffic gap")
        counters[step] = current
        previous = current
    for lane, scenario, kind in cells():
        graph = graphs[(lane, scenario, kind)]
        for window in WINDOWS:
            change = delta(counters[(lane, scenario, kind, window, "before")], counters[(lane, scenario, kind, window, "after")])
            if window == "prepare":
                wanted = {("GET", graph["registryManifestDigest"], 200): 1,
                          ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                          ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
                for desc in (graph["configDescriptor"], *graph["layerDescriptors"]):
                    wanted[("GET", desc["digest"], 200)] = 1
                require(change == wanted, "state preparation upload/readback budget changed")
            elif window == "seed" and seeded_consumption[(lane, scenario, kind)]:
                require(change == crash.sdk_budget(graph), "seed consumption not exactly one real SDK read")
            else:
                require(not change, "state startup/recovery repeated Registry access")
    return identity


MATERIAL_FIELDS = ("kind", "sourceCommit", "localImageID", "manifestSHA256", "configSHA256",
                   "layerSHA256s", "diffIDs", "catalogue1SHA256", "catalogue2SHA256", "storeID", "policies")
COMMON = ("schema", "action", "lane", "scenario", "caseKind", *MATERIAL_FIELDS,
          "boundary", "authority", "graphOrigin", *BOUNDARY, "canonicalScope", "configuredScope")
OFFLINE_FIELDS = ("inspection", "journal", "auditOpen", "audit", "auditEvents", "auditBindings", "auditLog", "checkpoint", "trustRecordSHA256")
JOURNAL_FIELDS = ("operation", "state", "outcome", "outcomeData", "acknowledged", "resultAuditHash", "grantID",
                  "generation", "catalogueSHA256", "manifestSHA256", "evidenceSHA256")
OP_FIELDS = ("id", "actorID", "scopeSHA256", "kind", "data", "auditBaseCount", "auditBaseHash", "preparedAuditHash")
SDK_PROJECTION_FIELDS = ("Schema", "Grant", "Catalogue", "Generation", "Reference", "Approval", "Manifest",
                         "Config", "Graph", "Bundle", "Root", "ObservedAtUnixNano", "ValidUntilUnix")


def material(value, lane, scenario, kind, source, local_id, graph):
    require(value["kind"] == kind and value["sourceCommit"] == source and value["localImageID"] == value["configSHA256"] == local_id
            and value["manifestSHA256"] == graph["registryManifestDigest"]
            and value["layerSHA256s"] == [x["digest"] for x in graph["layerDescriptors"]]
            and value["diffIDs"] == [x["diffID"] for x in graph["layerDescriptors"]], "state graph binding rejected")
    require(isinstance(value["storeID"], str) and re.fullmatch(r"[a-f0-9]{32}", value["storeID"]), "state store identity rejected")
    digest(value["catalogue1SHA256"]); digest(value["catalogue2SHA256"])
    require(value["catalogue1SHA256"] != value["catalogue2SHA256"], "catalogue generations conflated")
    require(isinstance(value["policies"], list) and len(value["policies"]) == 1, "single state grant required")
    policy = value["policies"][0]; exact(policy, crash.POLICY_FIELDS)
    require(policy["name"] == "original" and policy["policyID"] == "d12-state-" + lane,
            "state policy role rejected")
    public_id(policy["grantID"])
    for key in crash.POLICY_FIELDS:
        if key not in {"name", "policyID", "grantID"}: digest(policy[key])
    require(policy["bundleArtifactSHA256"] == value["manifestSHA256"], "signature not actual image manifest")
    require(value["canonicalScope"] == scope(value["storeID"])
            and value["configuredScope"] == scope(value["storeID"], configured=True, scenario=scenario), "state scope profile rejected")
    return {key: value[key] for key in MATERIAL_FIELDS}


def sdk_projection(value, info, graph):
    exact(value, ("boundary", "authorization", "verified", "policyID", "policyRevision", "evidenceSHA256", "projection"))
    policy = info["policies"][0]
    require(value["boundary"] == "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND" and value["authorization"] == "BLOCKED"
            and value["verified"] is True and value["policyID"] == policy["policyID"], "seed SDK authority rejected")
    typed_equal(value["policyRevision"], 1, "seed SDK policy revision rejected")
    digest(value["evidenceSHA256"])
    projection = value["projection"]; exact(projection, SDK_PROJECTION_FIELDS)
    expected = {"Schema": "chengwang.managed-binding-evidence/v1", "Grant": policy["grantID"],
                "Catalogue": info["catalogue1SHA256"], "Generation": 1,
                "Reference": "registry.fixture.invalid:5443/chengwang/product-candidate@" + info["manifestSHA256"],
                "Approval": policy["approvalSHA256"], "Manifest": info["manifestSHA256"], "Config": info["configSHA256"],
                "Bundle": policy["bundleSHA256"], "Root": policy["trustedRootSHA256"]}
    for key, wanted in expected.items(): typed_equal(projection[key], wanted, "seed SDK material getter differs")
    digest(projection["Graph"])
    graph_bytes = ("chengwang.local-oci-digest-graph/v1\x00" + expected["Reference"] + "\x00" + info["configSHA256"] + "\x00").encode()
    for layer in graph["layerDescriptors"]:
        graph_bytes += (layer["digest"] + "\x00" + layer["diffID"] + "\x00" + str(layer["size"]) + "\x00"
                        + str(layer["uncompressedBytes"]) + "\x00").encode()
    require(projection["Graph"] == "sha256:" + image.sha(graph_bytes), "SDK graph getter differs from actual archived graph")
    now = integer(projection["ObservedAtUnixNano"], 1)
    integer(projection["ValidUntilUnix"], now // 1_000_000_000 + 1)
    ordered = {key: projection[key] for key in SDK_PROJECTION_FIELDS}
    require("sha256:" + image.sha(encoded(ordered, ordered=True)) == value["evidenceSHA256"],
            "actual managed evidence Go-struct hash mismatch")
    return value["evidenceSHA256"]


def event_chain(events):
    require(isinstance(events, list) and len(events) <= 3, "unexpected state audit event count")
    previous, identifiers, keys = ZERO, set(), set()
    for event in events:
        exact(event, (*lifecycle.EVENT_FIELDS, *(("data",) if event.get("data") else ())))
        for name in ("id", "idempotencyKey", "traceId", "actorId", "action", "target", "result"):
            public_id(event[name])
        require(event["id"] not in identifiers and event["idempotencyKey"] not in keys
                and event["previousHash"] == previous, "duplicate or disconnected audit event")
        identifiers.add(event["id"]); keys.add(event["idempotencyKey"])
        bare_hash(event["previousHash"]); bare_hash(event["hash"]); lifecycle.event_time(event["occurredAt"])
        copy = dict(event); copy["hash"] = ""
        require(image.sha(crash.event_bytes(copy)[:-1]) == event["hash"], "state audit raw Go hash mismatch")
        previous = event["hash"]
    return {event["idempotencyKey"]: event for event in events}


def domain_shape(lane, scenario, *, recovered=False):
    healthy = scenario in BOUNDARIES
    early = healthy and BOUNDARIES.index(scenario) < 2
    state = "PREPARED" if early else "COMMITTED" if lane == "update" else "RESERVED" if lane == "verify-reserved" else "CONSUMED"
    outcome = ("INTERRUPTED" if recovered else "") if early else (
        "CATALOGUE_COMMITTED" if lane == "update" else "VERIFICATION_CONSUMED" if lane == "verify-consumed"
        else "" if healthy and scenario == "before-result-audit" and not recovered else "VERIFICATION_RESERVED_NOT_COMPLETED")
    generation = 2 if state == "COMMITTED" else 1
    ledger = state if state in {"RESERVED", "CONSUMED"} else "AVAILABLE"
    return state, outcome, generation, ledger


def expected_sequence(lane, scenario, phase):
    if phase == "prepare": return 1
    if scenario in BOUNDARIES:
        if phase == "seed": return CUT_SEQUENCE[lane][BOUNDARIES.index(scenario)]
        return 5 if BOUNDARIES.index(scenario) < 2 or lane == "update" else 6
    base = 5 if lane == "update" else 6
    if scenario in {"prepared-audit-missing", "result-key-conflict"}: base -= 1
    if scenario == "later-invalid-acked": base += 1
    return base


def expected_consumption(lane, scenario):
    return lane == "verify-consumed" and (scenario in FAULTS or BOUNDARIES.index(scenario) >= 2)


def inspection(value, info, sequence, generation, ledger, evidence):
    modified = dict(info); modified["catalogueSHA256"] = info["catalogue%dSHA256" % generation]
    # Reuse strict field-level validation, changing only the explicitly allowed
    # catalogue generation. D11/crash acceptance logic remains unchanged.
    copy = json.loads(encoded(value))
    require(copy["catalogue"]["generation"] == generation and type(copy["catalogue"]["generation"]) is int,
            "state catalogue generation rejected")
    copy["catalogue"]["generation"] = 1
    crash.inspection(copy, modified, sequence, ledger, evidence)


def offline(value, info, lane, scenario, phase, sdk_evidence):
    exact(value, OFFLINE_FIELDS)
    bare_hash(value["trustRecordSHA256"])
    initial = phase == "prepare"; healthy = scenario in BOUNDARIES
    recovered = healthy and phase != "seed" and not initial
    sequence = expected_sequence(lane, scenario, phase)
    state, outcome, generation, ledger = ("PREPARED", "", 1, "AVAILABLE") if initial else domain_shape(lane, scenario, recovered=recovered)
    events = value["auditEvents"]; event_map = event_chain(events)
    entries, bindings = value["journal"], value["auditBindings"]
    count = 0 if initial else 2 if scenario == "later-invalid-acked" else 1
    require(isinstance(entries, list) and isinstance(bindings, list) and len(entries) == len(bindings) == count,
            "state journal/binding count rejected")
    expected_audit = 0 if initial else (2 if recovered else (0, 1, 1, 1, 2, 2)[BOUNDARIES.index(scenario)]) if healthy else (
        0 if scenario in {"acked-audit-missing", "prepared-audit-missing"} else 3 if scenario == "wrong-prefix" else 2)
    require(len(events) == expected_audit, "state actual audit count rejected")
    expected_ack = not initial and (recovered or scenario == "after-journal-ack" or scenario in FAULTS and scenario not in {"prepared-audit-missing", "result-key-conflict"})
    used_events, op_ids = set(), set()
    evidence = sdk_evidence if ledger == "CONSUMED" else ""
    for index, (entry, binding) in enumerate(zip(entries, bindings)):
        exact(entry, JOURNAL_FIELDS); op = entry["operation"]; exact(op, OP_FIELDS)
        op_id = public_id(op["id"])
        require(re.fullmatch(r"[a-f0-9]{32}", op_id) and op_id not in op_ids, "state operation ID duplicate or unsafe")
        op_ids.add(op_id)
        first_later = scenario == "later-invalid-acked" and index == 0
        desired_state, desired_outcome = ("PREPARED", "") if first_later else (state, outcome)
        desired_ack = False if first_later else expected_ack
        data = {"catalogueSHA256": info["catalogue2SHA256"]} if lane == "update" else {
            "policyId": info["policies"][0]["policyID"], "approvalSHA256": info["policies"][0]["approvalEnvelopeSHA256"],
            "bundleSHA256": info["policies"][0]["bundleSHA256"], "rootSHA256": info["policies"][0]["trustedRootSHA256"]}
        require(op["actorID"] == ACTOR and op["kind"] == ("update" if lane == "update" else "verify")
                and op["data"] == data and op["scopeSHA256"] == "sha256:" + image.sha(encoded(scope(info["storeID"]), ordered=True)),
                "state operation provenance mismatch")
        base_count = 1 if scenario == "wrong-prefix" else 0
        typed_equal(op["auditBaseCount"], base_count, "audit base count rejected")
        base_hash = events[0]["hash"] if base_count else ZERO
        bare_hash(op["auditBaseHash"])
        require(op["auditBaseHash"] != base_hash if scenario == "wrong-prefix" else op["auditBaseHash"] == base_hash,
                "wrong-prefix injection absent or extra prefix contradiction")
        has_domain = desired_state in {"RESERVED", "CONSUMED"}
        domain_cat = info["catalogue2SHA256"] if desired_state == "COMMITTED" else info["catalogue1SHA256"]
        wanted_data = {"catalogueSHA256": domain_cat} if desired_state == "COMMITTED" else ({
            "grantId": info["policies"][0]["grantID"], "manifestSHA256": info["manifestSHA256"], "catalogueSHA256": domain_cat}
            if has_domain and desired_outcome else {})
        if desired_state == "CONSUMED": wanted_data["evidenceSHA256"] = evidence
        wanted_fields = {"state": desired_state, "outcome": desired_outcome, "outcomeData": wanted_data,
            "acknowledged": desired_ack, "grantID": info["policies"][0]["grantID"] if has_domain else "",
            "generation": 2 if desired_state == "COMMITTED" else int(has_domain),
            "catalogueSHA256": domain_cat if has_domain or desired_state == "COMMITTED" else "",
            "manifestSHA256": info["manifestSHA256"] if has_domain else "",
            "evidenceSHA256": evidence if desired_state == "CONSUMED" else ""}
        for key, wanted in wanted_fields.items(): typed_equal(entry[key], wanted, "state domain/outcome/ACK rejected")
        exact(binding, ("operationID", "prepared", "result"))
        require(binding["operationID"] == op_id, "state binding operation rejected")
        for which in ("prepared", "result"):
            key = "image-trust/" + op_id + "/" + which
            actual = event_map.get(key)
            require(binding[which] == actual, "audit binding not actual event Lookup result")
            if actual is not None:
                used_events.add(key)
                expected_actor = FOREIGN_ACTOR if (which == "prepared" and scenario in {"prepared-key-conflict", "later-invalid-acked"}
                    or which == "result" and scenario == "result-key-conflict") else ACTOR
                expected_result = "prepared" if which == "prepared" else (
                    "completed" if desired_outcome == "CATALOGUE_COMMITTED" else "verification_consumed"
                    if desired_outcome == "VERIFICATION_CONSUMED" else "interrupted" if desired_outcome == "INTERRUPTED" else "rejected")
                require(actual["traceId"] == op_id and actual["actorId"] == expected_actor
                        and actual["action"] == "image_trust." + op["kind"] and actual["target"] == "image-trust/" + info["storeID"]
                        and actual["result"] == expected_result and actual.get("data", {}) == (data if which == "prepared" else wanted_data),
                        "state event semantic mismatch or negative injection absent")
            recorded = op["preparedAuditHash"] if which == "prepared" else entry["resultAuditHash"]
            must_record = (not first_later and (recovered or not healthy or BOUNDARIES.index(scenario) >= 2)) if which == "prepared" else desired_ack
            if must_record:
                bare_hash(recorded)
                if actual is not None: require(recorded == actual["hash"], "state prepared/result hash not actual persisted event")
                else: require(scenario in {"acked-audit-missing", "prepared-audit-missing"}, "unexpected missing bound event")
            else: require(recorded == "", "state falsely bound uncommitted audit event")
        if first_later:
            require(binding["prepared"] is None and binding["result"] is None, "first later-invalid operation already repaired")
    if scenario == "wrong-prefix" and not initial:
        base = events[0]
        require(base["actorId"] == ACTOR and base["action"] == "image_trust.read" and base["target"] == "image-trust/" + info["storeID"]
                and base["result"] == "observed" and base["idempotencyKey"] == "state-matrix/base"
                and base["traceId"] == "d12-state-base" and not base.get("data"), "wrong-prefix original base event rejected")
        used_events.add(base["idempotencyKey"])
    require(used_events == set(event_map), "unrelated audit data exposed")
    inspection(value["inspection"], info, sequence, generation, ledger, evidence)
    payload = b"".join(crash.event_bytes(event) for event in events)
    crash.raw_hash(value["auditLog"], payload)
    bad_cp = scenario == "bad-checkpoint" and not initial
    checkpoint = b"{}\n" if bad_cp else encoded({"count": len(events), "lastHash": events[-1]["hash"] if events else ZERO}, ordered=True)
    crash.raw_hash(value["checkpoint"], checkpoint)
    require(value["auditOpen"] == ("rejected-checkpoint" if bad_cp else "verified"), "audit open result rejected")
    if bad_cp: require(value["audit"] is None, "bad checkpoint falsely verified")
    else:
        audit = value["audit"]; exact(audit, ("valid", "count", "expectedCount", "lastHash", "expectedLastHash", "verifiedAt"))
        require(audit["valid"] is True and type(audit["count"]) is int and type(audit["expectedCount"]) is int
                and audit["count"] == audit["expectedCount"] == len(events)
                and audit["lastHash"] == audit["expectedLastHash"] == (events[-1]["hash"] if events else ZERO), "audit verification summary mismatch")
        lifecycle.event_time(audit["verifiedAt"])
    return {"sequence": sequence, "generation": generation, "ledger": ledger, "evidence": evidence,
            "journal": entries, "bindings": bindings, "events": events, "inspection": value["inspection"], "raw": value}


def stable_offline(value):
    result = json.loads(encoded(value))
    if result["audit"] is not None: result["audit"].pop("verifiedAt")
    return result


def live_read(value, info, snapshot, recovery):
    status = value["status"]
    typed_equal(status["generation"], snapshot["generation"], "live state generation rejected")
    adapted_info = dict(info); adapted_info["catalogueSHA256"] = info["catalogue%dSHA256" % snapshot["generation"]]
    adapted = json.loads(encoded(status)); adapted["generation"] = 1
    crash.status(adapted, adapted_info, snapshot["sequence"], snapshot["ledger"], len(snapshot["journal"]), recovery)
    history = value["history"]; exact(history, registry.HISTORY_FIELDS)
    require(history["boundary"] == "ADVISORY_TRUST_OPERATION_HISTORY" and history["authorization"] == "BLOCKED"
            and history["deviceActionsExecuted"] is False and type(history["sequence"]) is int
            and history["sequence"] == snapshot["sequence"] and type(history["total"]) is int
            and history["total"] == len(snapshot["journal"]) and type(history["offset"]) is int and history["offset"] == 0
            and type(history["limit"]) is int and history["limit"] == 50
            and isinstance(history["entries"], list) and len(history["entries"]) == len(snapshot["journal"]), "live history tally rejected")
    integer(history["observedAtUnix"], 1)
    by_id = {}
    for row in history["entries"]:
        exact(row, registry.ENTRY_FIELDS); identifier = public_id(row["operationId"])
        require(identifier not in by_id, "duplicate live history operation"); by_id[identifier] = row
    for entry, binding in zip(snapshot["journal"], snapshot["bindings"]):
        op = entry["operation"]; row = by_id.get(op["id"])
        require(row is not None, "actual live history operation absent")
        wanted = {"operationId": op["id"], "actorId": ACTOR, "kind": op["kind"], "state": entry["state"],
            "outcome": entry["outcome"], "acknowledged": True, "policyId": op["data"].get("policyId", ""),
            "grantId": entry["grantID"], "generation": entry["generation"], "catalogueSHA256": entry["catalogueSHA256"],
            "preparedAuditHash": op["preparedAuditHash"], "resultAuditHash": entry["resultAuditHash"],
            "preparedAtUnix": lifecycle.event_time(binding["prepared"]["occurredAt"]),
            "resultAtUnix": lifecycle.event_time(binding["result"]["occurredAt"])}
        for key, desired in wanted.items(): typed_equal(row[key], desired, "live history differs from actual recovered events")
    require(value["auditLog"] == snapshot["raw"]["auditLog"] and value["checkpoint"] == snapshot["raw"]["checkpoint"],
            "live audit observations disconnected from exact offline bytes")


def action_sequence(reports, lane, scenario, kind, source, local_id, graph):
    require(set(reports) == set(actions(scenario)), "state action set incomplete")
    info, sdk, sdk_evidence = None, None, ""
    consumption = expected_consumption(lane, scenario)
    for action in actions(scenario):
        value = reports[action]
        is_read = action in {"first-read", "second-read"}
        has_sdk = consumption and action != "prepare"
        exact(value, (*COMMON, *(("status", "history", "auditLog", "checkpoint") if is_read else ("offline",)),
                      *(("sdk",) if has_sdk else ())))
        registry.boundary(value)
        require(value["schema"] == "chengwang.product-state-action/v1" and value["action"] == action
                and value["lane"] == lane and value["scenario"] == scenario and value["caseKind"] == case_kind(scenario)
                and value["boundary"] == "ADVISORY_PRODUCT_STATE_FIXTURE" and value["authority"] == "EPHEMERAL_TEST_ONLY"
                and value["graphOrigin"] == registry.GRAPH_ORIGIN, "state action protocol rejected")
        actual = material(value, lane, scenario, kind, source, local_id, graph)
        require(info is None or actual == info, "state material changed across actions"); info = actual
        if has_sdk:
            sdk_evidence = sdk_projection(value["sdk"], info, graph)
            require(sdk is None or sdk == value["sdk"], "actual seed SDK evidence replaced after restart"); sdk = value["sdk"]
    snapshots = {action: offline(reports[action]["offline"], info, lane, scenario, action, sdk_evidence)
                 for action in ("prepare", "seed", "reopen-first", "reopen-second")}
    seed, first, second = (snapshots[name] for name in ("seed", "reopen-first", "reopen-second"))
    if scenario in FAULTS:
        require(stable_offline(seed["raw"]) == stable_offline(first["raw"]) == stable_offline(second["raw"]),
                "rejected startup repaired checkpoint/audit/outbox or unburned grant")
    else:
        require(first["events"][:len(seed["events"])] == seed["events"]
                and first["inspection"]["catalogue"] == seed["inspection"]["catalogue"]
                and first["inspection"]["consumptions"] == seed["inspection"]["consumptions"]
                and first["evidence"] == seed["evidence"], "healthy constructor redid a domain mutation or replaced evidence")
        before_op, after_op = seed["journal"][0]["operation"], first["journal"][0]["operation"]
        require({k: v for k, v in before_op.items() if k != "preparedAuditHash"}
                == {k: v for k, v in after_op.items() if k != "preparedAuditHash"}, "constructor replaced original intent")
        require(stable_offline(first["raw"]) == stable_offline(second["raw"]), "second startup not fully idempotent")
        live_read(reports["first-read"], info, first, int(scenario != "after-journal-ack"))
        live_read(reports["second-read"], info, second, 0)
    return info, consumption


def runtime(projections, processes, startups, lane, scenario, kind, source, local_id, registry_id, binary_hash):
    healthy = scenario in BOUNDARIES
    expected = {"boundary": "ISOLATED_PRODUCT_CANDIDATE", **BOUNDARY,
        "sourceCommit": source, "localImageID": local_id,
        "imageIdentityKind": "LOCAL_DOCKER_CONFIG_ID_NOT_REGISTRY_MANIFEST", "entrypoint": ["/app/image-trust-api"],
        "user": "10001:10001", "workdir": "/app", "readOnlyRootfs": True, "capabilitiesDropped": "ALL",
        "noNewPrivileges": True, "networkIsolation": "shared_isolated_fixture", "networkPeerContainerID": registry_id,
        "hostPorts": 0, "bindMounts": {"privateReadOnly": True, "trustStateReadWrite": True, "productDataReadWrite": True},
        "memoryBytes": 268435456, "memorySwapBytes": 268435456, "nanoCPUs": 1000000000, "pidsLimit": 128,
        "nofile": 1024, "restartPolicy": "no", "stopTimeoutSeconds": 15, "rawEnvironmentIncluded": False,
        "rawMountSourcesIncluded": False}
    labels = tuple(start + suffix for start in ("first", "second") for suffix in (("-running", "-exited") if healthy else ("-rejected",)))
    require(set(projections) == set(labels) and set(processes) == ({"first", "second"} if healthy else set())
            and set(startups) == (set() if healthy else {"first", "second"}), "actual state runtime starts incomplete")
    identities, starts = set(), []
    for label in labels:
        value = projections[label]; running = label.endswith("-running")
        exact(value, (*expected, "containerID", "state", "pid", "cleanExit", "startupRejected", "exitCode"))
        for key, wanted in expected.items(): typed_equal(value[key], wanted, "state runtime security rejected")
        require(all(type(x) is bool and x for x in value["bindMounts"].values()), "mount authority types rejected")
        identity = bare_hash(value["containerID"]); identities.add(identity)
        require(value["state"] == ("running" if running else "exited") and value["cleanExit"] is (healthy and not running)
                and value["startupRejected"] is (not healthy), "startup rejection confused with normal exit")
        typed_equal(value["exitCode"], 0 if healthy else 1, "startup exit code must be natural1 or normal0")
        integer(value["pid"], 1 if running else 0)
        if not running: typed_equal(value["pid"], 0, "exited state container retains PID"); continue
        p = processes[label.split("-", 1)[0]]
        exact(p, ("schema", *BOUNDARY, "sourceCommit", "localImageID", "containerID", "hostPID", "namespacePID", "startTime",
                  "uid", "gid", "capabilities", "noNewPrivileges", "defaultProductEntrypoint", "expectedConfigurationArguments", "actualExecutableSHA256"))
        wanted = {"schema": "chengwang.product-image-pid1/v1", **BOUNDARY, "sourceCommit": source, "localImageID": local_id,
            "containerID": identity, "hostPID": value["pid"], "namespacePID": 1, "uid": 10001, "gid": 10001,
            "capabilities": "none", "noNewPrivileges": True, "defaultProductEntrypoint": True,
            "expectedConfigurationArguments": True, "actualExecutableSHA256": binary_hash}
        for key, desired in wanted.items(): typed_equal(p[key], desired, "actual state PID1 identity rejected")
        starts.append((p["hostPID"], integer(p["startTime"], 1)))
    require(len(identities) == 1 and (not healthy or len(set(starts)) == 2), "state restart replaced container/process identity")
    identity = next(iter(identities))
    if not healthy:
        intervals = [startup(startups[start], lane, scenario, kind, start, source, local_id, identity) for start in ("first", "second")]
        require(intervals[0][1] <= intervals[1][0] and startups["first"]["startedAt"] != startups["second"]["startedAt"],
                "two natural startup exits not separately observed")
    return identity


def startup(value, lane, scenario, kind, attempt, source, local_id, container_id):
    expected = {"schema": "chengwang.product-state-startup/v1", "sourceCommit": source, "localImageID": local_id,
        "lane": lane, "scenario": scenario, "kind": kind, "caseKind": "rejected", "attempt": attempt, "containerID": container_id,
        "finalNamespaceAPINotListening": True, "exitCode": 1, "oomKilled": False, "pid": 0, "naturalExit": True,
        "cliDiagnostic": {"code": "CANDIDATE_CONFIGURATION_REJECTED", "count": 1}, "pid1SampleCaptured": False, **BOUNDARY}
    exact(value, (*expected, "startedAt", "finishedAt", "observationStartMonotonicNS", "observationEndMonotonicNS", "probes"))
    for key, wanted in expected.items(): typed_equal(value[key], wanted, "state startup rejection observation rejected")
    typed_equal(value["cliDiagnostic"]["count"], 1, "CLI diagnostic count type rejected")
    start_time, finish_time = lifecycle.event_time(value["startedAt"]), lifecycle.event_time(value["finishedAt"])
    require(start_time <= finish_time and finish_time - start_time <= 30, "natural failure duration not bounded")
    start = integer(value["observationStartMonotonicNS"], 1)
    end = integer(value["observationEndMonotonicNS"], start + 1, start + 30_000_000_000)
    require(isinstance(value["probes"], list) and 2 <= len(value["probes"]) <= 32, "startup probes absent or unbounded")
    previous = start
    for ordinal, probe in enumerate(value["probes"], 1):
        exact(probe, ("ordinal", "monotonicNS", "transport", "httpStatus"))
        typed_equal(probe["ordinal"], ordinal, "startup probe order rejected")
        previous = integer(probe["monotonicNS"], previous, end)
        require(probe["transport"] in {"CONNECTION_REFUSED", "CONNECTION_RESET", "CONNECTION_CLOSED"},
                "HTTP service, timeout or TLS identity failure is not startup refusal")
        typed_equal(probe["httpStatus"], 0, "startup unexpectedly served HTTP")
    return start, end


def cleanup(value, source, local_id, registry_id, products):
    expected = {"schema": "chengwang.product-state-cleanup/v1", "sourceCommit": source, "localImageID": local_id,
        "outcome": "PASS", "ownedContainersRemoved": 85, "healthyNormalStops": 72, "rejectedNaturalExits": 96,
        "maximumConcurrentOwnedContainers": 2, "noOwnedContainersRemain": True, "ownedHelpersJoined": 0,
        "privateFixtureRemoved": True, "outerProductImagePreserved": True, "registryImagePreserved": True,
        "registryStop": {"exitCode": 0, "oomKilled": False, "pid": 0, "signal": "SIGTERM"}, **BOUNDARY}
    exact(value, (*expected, "removedContainers"))
    for key, wanted in expected.items(): typed_equal(value[key], wanted, "exact state owned cleanup rejected")
    for key, wanted in expected["registryStop"].items(): typed_equal(value["registryStop"][key], wanted, "Registry normal exit rejected")
    rows = value["removedContainers"]
    require(isinstance(rows, list) and len(rows) == 85, "owned container deletion count changed")
    identities = set()
    for row, cell in zip(rows, (*cells(), None)):
        exact(row, ("containerID", "role", "lane", "scenario", "kind"))
        identity = bare_hash(row["containerID"])
        require(identity not in identities, "cleanup reused container identity"); identities.add(identity)
        wanted = {"containerID": registry_id, "role": "registry", "lane": "", "scenario": "", "kind": ""} if cell is None else {
            "containerID": products[cell], "role": "product", "lane": cell[0], "scenario": cell[1], "kind": cell[2]}
        require(row == wanted, "cleanup removed non-owned/wrong-cell container")


def verify(args):
    source = args.source_commit
    require(isinstance(source, str) and registry.COMMIT.fullmatch(source), "state source commit rejected")
    directory = image.checked_path(args.evidence_dir, directory=True)
    expected_names = own_names()
    present_names = {path.name for path in directory.iterdir() if path.name.startswith("product-state-")}
    require(expected_names - {"product-state-outcome.json"} <= present_names <= expected_names | SUPPORT_NAMES
            and SUPPORT_NAMES <= present_names, "missing, unknown or stale state evidence")
    hashes = {}
    def load(name, *, binary=False):
        raw = registry.read_file(directory / name, 4 << 20)
        hashes[name] = image.sha(raw)
        if binary: return raw
        value = image.decode(raw)
        require(isinstance(value, dict), "state report object required")
        return value
    staging, packaged = load("product-image-staging.json"), load("product-image-packaged-contents.json")
    require(staging.get("sourceCommit") == source and staging.get("authorization") == "BLOCKED"
            and staging.get("deviceActionsExecuted") is False and staging.get("imageBuilt") is False
            and staging.get("imageExecuted") is False and isinstance(staging.get("binary"), dict), "state outer staging boundary rejected")
    binary_hash = bare_hash(staging["binary"].get("sha256")); local_id = digest(packaged.get("localImageID"))
    require(staging["binary"].get("sourceCommit") == source and staging["binary"].get("sourceModified") is False,
            "state binary not bound to unmodified source")
    require(packaged.get("schema") == "chengwang.product-image-packaged-content/v1" and packaged.get("sourceCommit") == source
            and packaged.get("authorization") == "BLOCKED" and packaged.get("production") is False
            and packaged.get("registryManifestDigestVerified") is False and packaged.get("configDigestMatched") is True
            and packaged.get("secretsPackaged") is False and packaged.get("rawArchivePublished") is False, "state packaged boundary rejected")
    files, contexts = packaged.get("files"), staging.get("contextFiles")
    require(isinstance(files, dict) and files.get("app/image-trust-api", {}).get("sha256") == binary_hash
            and files["app/image-trust-api"].get("bytes") == staging["binary"].get("bytes") and isinstance(contexts, dict)
            and "Dockerfile" in contexts and {name.removeprefix("rootfs/"): value for name, value in contexts.items() if name != "Dockerfile"}
            == {name: value["sha256"] for name, value in files.items()}, "state binary/content bytes not independently bound")
    harness = load("product-state-harness.json")
    exact(harness, ("schema", "sourceCommit", "files", "checkoutBytesMatched", "permissionReadOnly", *BOUNDARY)); registry.boundary(harness)
    require(harness["schema"] == "chengwang.product-state-harness/v1" and harness["sourceCommit"] == source
            and harness["checkoutBytesMatched"] is True and harness["permissionReadOnly"] is True
            and isinstance(harness["files"], dict) and set(harness["files"]) == set(HARNESS_PATHS), "state helper/test source set rejected")
    for path, wanted in harness["files"].items():
        bare_hash(wanted)
        require(image.sha(registry.read_file(pathlib.Path(__file__).with_name(pathlib.PurePosixPath(path).name), 256 << 10)) == wanted,
                "state running helper/test not exact bound source")
    suites = {}
    for label, test_file, count, marker in (
        ("profile", "test_state_image_profile.py", 8, "D12_STATE_IMAGE_PROFILE_TESTS=PASS tests=8 skipped=0 synthetic_only=true"),
        ("verifier", "test_check_product_state.py", VERIFIER_TEST_COUNT,
         "PRODUCT_STATE_VERIFIER_TESTS=PASS synthetic_only=true tests=32 skipped=0")):
        suites[label] = crash.test_transcript(load("product-state-" + label + "-tests.log", binary=True),
            registry.read_file(pathlib.Path(__file__).with_name(test_file), 256 << 10), marker, count)
    graphs = {}
    packaged_raw = registry.read_file(directory / "product-image-packaged-contents.json", 4 << 20)
    for cell in cells():
        graph = load(report_name(*cell, "graph")); registry.graph_projection(graph, source, local_id, packaged_raw)
        require([x["diffID"] for x in graph["layerDescriptors"]] == packaged["layerDiffIDs"]
                and graph["packagedFileCount"] == packaged["packagedFileCount"]
                and binary_hash not in {local_id[7:], graph["registryManifestDigest"][7:]}, "binary/config/manifest identities conflated")
        graphs[cell] = graph
    require(all(graph == next(iter(graphs.values())) for graph in graphs.values()), "84 cells did not verify same real image graph")
    infos, seeded = {}, {}
    for cell in cells():
        reports = {action: load(report_name(*cell, action)) for action in actions(cell[1])}
        infos[cell], seeded[cell] = action_sequence(reports, *cell, source, local_id, graphs[cell])
    registry_id = observation_projection(load("product-state-observations.json"), source, local_id, graphs, seeded)
    isolation = load("product-state-isolation.json")
    registry.registry_isolation(isolation, load("product-state-network.json"), source, registry_id)
    require(isolation["actualImageID"] != local_id, "state product and Registry image identities reused")
    products = {}
    for cell in cells():
        lane, scenario, kind = cell; healthy = scenario in BOUNDARIES
        labels = tuple(start + suffix for start in ("first", "second") for suffix in
                       (("-running", "-exited") if healthy else ("-rejected",)))
        projections = {label: load(report_name(*cell, label + "-inspect")) for label in labels}
        processes = {start: load(report_name(*cell, start + "-running-pid1")) for start in ("first", "second")} if healthy else {}
        startups = {start: load(report_name(*cell, start + "-startup")) for start in ("first", "second")} if not healthy else {}
        products[cell] = runtime(projections, processes, startups, *cell, source, local_id, registry_id, binary_hash)
    require(len(set(products.values())) == 84 and registry_id not in products.values()
            and len({info["storeID"] for info in infos.values()}) == 84
            and len({info["policies"][0]["grantID"] for info in infos.values()}) == 84
            and len({info["policies"][0]["trustedRootSHA256"] for info in infos.values()}) == 84,
            "independent state stores/grants/authorities/containers not proven")
    cleanup(load("product-state-runtime-cleanup.json"), source, local_id, registry_id, products)
    names = own_names(); present = {path.name for path in directory.iterdir() if path.name.startswith("product-state-")}
    require(names - {"product-state-outcome.json"} <= present <= names | SUPPORT_NAMES, "missing, unknown or stale state evidence")
    require(set(hashes) == names - {"product-state-outcome.json"} | SUPPORT_NAMES | {"product-image-staging.json", "product-image-packaged-contents.json"}
            and len(hashes) == 909, "state input relation set changed")
    result = {"schema": "chengwang.product-state-gate/v1", "outcome": "PASS", **BOUNDARY, "sourceCommit": source,
        "localImageID": local_id, "registryManifestDigest": next(iter(graphs.values()))["registryManifestDigest"], "binarySHA256": binary_hash,
        "authority": "EPHEMERAL_TEST_ONLY", "graphBytesOrigin": registry.GRAPH_ORIGIN,
        "actualProductPreseededStateMatrixProven": True, "healthyCases": 36, "rejectedCases": 48,
        "lanes": list(LANES), "healthyBoundaries": list(BOUNDARIES), "faults": list(FAULTS), "signatureKinds": list(KINDS),
        "normalProductStops": 72, "naturalStartupRejections": 96, "sameContainerTwoStarts": True,
        "registryCounterSnapshots": 672, "startupRegistryZeroWindows": 168, "seedSDKConsumptions": sum(seeded.values()),
        "auditHashChainsAndScopesVerified": True, "negativeLogicalRecordsUnchanged": True,
        "invalidCheckpointsNotRepaired": True, "laterInvalidPreventsEarlierRepair": True,
        "testSuites": suites, "cleanupVerified": True, "actualCrashProvenByThisGate": False,
        "completeCrashMatrixProven": False, "physicalPowerLossProven": False, "diskFailureRecoveryProven": False,
        "recoveryAuthorized": False, "releaseAuthorized": False, "privateGraphDownloadedByReviewer": False,
        "productImagePublishedOutsideIsolatedRegistry": False, "evidenceSHA256": dict(sorted(hashes.items()))}
    existing = directory / "product-state-outcome.json"
    if existing.exists() or existing.is_symlink():
        current, _ = registry.json_file(existing)
        require(encoded(current) == encoded(result), "existing state outcome differs from independent replay")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="command", required=True)
    graph = sub.add_parser("graph")
    for name in ("graph-dir", "packaged-report", "report"): graph.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("source-commit", "manifest-digest"): graph.add_argument("--" + name, required=True)
    inspect = sub.add_parser("inspect")
    for name in ("image-inspect", "container-inspect", "report"): inspect.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("image-id", "source-commit", "expected-private-source", "expected-state-source", "expected-network-mode"):
        inspect.add_argument("--" + name, required=True)
    inspect.add_argument("--container-status", choices=("running", "exited"), required=True)
    inspect.add_argument("--startup-rejected", action="store_true")
    verify_parser = sub.add_parser("verify")
    for name in ("evidence-dir", "report"): verify_parser.add_argument("--" + name, type=pathlib.Path, required=True)
    verify_parser.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "graph": result = registry.graph(args)
        elif args.command == "inspect":
            require(re.fullmatch(r"container:[a-f0-9]{64}", args.expected_network_mode), "state namespace rejected")
            image_value = image.one_inspect(registry.read_file(args.image_inspect, 8 << 20))
            container = image.one_inspect(registry.read_file(args.container_inspect, 8 << 20))
            result = image.inspect_projection(image_value, container, image_id=args.image_id, source=args.source_commit,
                private=args.expected_private_source, state=args.expected_state_source, network=args.expected_network_mode,
                status=args.container_status, fixture_kind="product-state", startup_rejected=args.startup_rejected)
            result.update(production=False, networkPeerContainerID=args.expected_network_mode.removeprefix("container:"),
                          startupRejected=args.startup_rejected, exitCode=container["State"]["ExitCode"])
        else: result = verify(args)
        image.write_exclusive(args.report, encoded(result) + b"\n")
    except (OSError, CheckError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        print("PRODUCT_STATE_CHECK=FAIL rejected=true raw_input_suppressed=true", file=sys.stderr); return 1
    print("PRODUCT_STATE_CHECK=PASS mode=" + args.command + " authorization=BLOCKED production=false"); return 0


if __name__ == "__main__": raise SystemExit(main())
