#!/usr/bin/env python3
"""Bounded D12 automatic-refresh evidence checks, never release authority.

The graph command verifies private bytes in CI. Reviewer-side verify checks
archived safe projections; it neither fetches Registry bytes nor runs a product.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
import check_product_image as image
import check_product_registry as registry

CheckError = image.CheckError
require = image.require
exact = registry.exact
integer = registry.integer
digest = registry.digest
bare_hash = registry.bare_hash
public_id = registry.public_id
BOUNDARY = registry.BOUNDARY
KINDS = registry.KINDS
FEED_URL = "https://feed.fixture.invalid:5444/feed"
PLAN_SCHEMA = "chengwang.product-lifecycle-feed-plan/v1"
STAGES = (("prepare", 0), *(("exercise", n) for n in range(1, 10)),
          ("reopen-first", 0), *(("resume", n) for n in range(1, 7)), ("reopen-final", 0))
MATERIAL_FIELDS = (*registry.MATERIAL_FIELDS, "feedURL", "feedSPKI", "feedCASHA256",
                   "refreshIntervalSeconds", "refreshMaxAgeSeconds", "refreshTimeoutSeconds")
ACTION_FIELDS = ("schema", "action", "case", *MATERIAL_FIELDS, "authority", "graphOrigin",
                 *BOUNDARY, "cases", "observations", "feedPlans", "journalAuditBindingsVerified")
EVENT_FIELDS = ("id", "idempotencyKey", "traceId", "actorId", "action", "target", "result",
                "occurredAt", "previousHash", "hash")
SOURCE_EVENT_FIELDS = ("schema", "ordinal", "epoch", "pathClass", "generation", "status",
                       "bodySHA256", "bytes", "tls", "authPresent", "reason", "sentComplete")
ERROR_BODY = b'{"code":"fixture_feed_unavailable"}\n'
# (sequence, generation, ledger/consumed, history). There are no reservations.
INITIAL = (1, 1, 0, 0)
AUTO = (5, 2, 0, 1)
FIRST_SUCCESS = (10, 2, 1, 2)
FIRST_REPLAY = (14, 2, 1, 3)
FIRST_FINAL = (18, 2, 1, 4)
RESTART_REPLAY = (22, 2, 1, 5)
SECOND_SUCCESS = (27, 2, 2, 6)
FINAL = (31, 2, 2, 7)
AFTER = {
    ("exercise", 1): INITIAL, ("exercise", 2): AUTO, ("exercise", 3): AUTO,
    ("exercise", 4): FIRST_SUCCESS, ("exercise", 5): FIRST_REPLAY,
    **{("exercise", n): FIRST_FINAL for n in range(6, 10)},
    ("resume", 1): FIRST_FINAL, ("resume", 2): FIRST_FINAL,
    ("resume", 3): RESTART_REPLAY, ("resume", 4): SECOND_SUCCESS,
    ("resume", 5): FINAL, ("resume", 6): FINAL,
}
POSTS = {("exercise", 1): ("unconfirmed", "a", 503),
    ("exercise", 4): ("a-success", "a", 200), ("exercise", 5): ("a-replay", "a", 400),
    ("exercise", 6): ("b-revoked", "b", 400), ("exercise", 7): ("stale", "c", 503),
    ("resume", 1): ("cold-unconfirmed", "c", 503),
    ("resume", 3): ("a-replay-after-restart", "a", 400),
    ("resume", 4): ("c-success", "c", 200), ("resume", 5): ("c-replay", "c", 400)}
PLAN_STAGES = {("prepare", 0): (1, 503), ("exercise", 2): (2, 200),
    ("exercise", 7): (3, 503), ("exercise", 8): (4, 200), ("exercise", 9): (5, 503),
    ("resume", 2): (6, 200), ("resume", 6): (7, 503)}


def encoded(value, *, ordered=False):
    return json.dumps(value, sort_keys=not ordered, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def json_file(path, limit=4 << 20):
    return registry.json_file(path, limit)


def report_name(kind, action, number=0):
    suffix = "-" + str(number) if action in {"exercise", "resume"} else ""
    return "product-lifecycle-" + kind + "-" + action + suffix + ".json"


def material(value, kind, source, local_id, graph):
    require(value["kind"] == kind and value["sourceCommit"] == source
            and value["localImageID"] == value["configSHA256"] == local_id
            and value["manifestSHA256"] == graph["registryManifestDigest"]
            and value["layerSHA256s"] == [v["digest"] for v in graph["layerDescriptors"]]
            and value["diffIDs"] == [v["diffID"] for v in graph["layerDescriptors"]],
            "lifecycle material graph mismatch")
    require(isinstance(value["storeID"], str) and re.fullmatch(r"[a-f0-9]{32}", value["storeID"]),
            "lifecycle store identity rejected")
    for field in ("catalogue1SHA256", "catalogue2SHA256", "feedSPKI", "feedCASHA256"):
        digest(value[field])
    require(value["catalogue1SHA256"] != value["catalogue2SHA256"] and value["feedURL"] == FEED_URL,
            "catalogue or fixed source mismatch")
    for field, expected in (("refreshIntervalSeconds", 2), ("refreshMaxAgeSeconds", 15),
                            ("refreshTimeoutSeconds", 2)):
        require(type(value[field]) is int and value[field] == expected, "refresh configuration changed")
    policies = value["policies"]
    require(isinstance(policies, list) and len(policies) == 3, "three lifecycle grants required")
    for policy, name in zip(policies, ("a", "b", "c")):
        exact(policy, ("name", "policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256",
                       "bundleSHA256", "bundleArtifactSHA256", "trustedRootSHA256", "registrySPKI"))
        require(policy["name"] == name and policy["policyID"] == "d12-" + name,
                "lifecycle policy identity changed")
        public_id(policy["grantID"])
        for field in ("approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256",
                      "bundleArtifactSHA256", "trustedRootSHA256", "registrySPKI"):
            digest(policy[field])
        require(policy["bundleArtifactSHA256"] == value["manifestSHA256"], "signature artifact mismatch")
    for field in ("grantID", "approvalSHA256", "approvalEnvelopeSHA256"):
        require(len({p[field] for p in policies}) == 3, "lifecycle grant or approval reused")
    for field in ("bundleSHA256", "trustedRootSHA256", "registrySPKI"):
        require(len({p[field] for p in policies}) == 1, "lifecycle authority corpus changed")
    require(value["feedSPKI"] != policies[0]["registrySPKI"], "source and Registry TLS identities reused")
    return {field: value[field] for field in MATERIAL_FIELDS}


def status(value, wanted, info):
    exact(value, registry.STATUS_FIELDS)
    seq, generation, consumed, total = wanted
    require(value["boundary"] == "ADVISORY_TRUST_POLICY_STATE" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and value["healthy"] is True and value["fresh"] is True
            and value["storeId"] == info["storeID"]
            and value["catalogueSHA256"] == info["catalogue%dSHA256" % generation]
            and value["refreshRequired"] is True and type(value["refreshFresh"]) is bool,
            "lifecycle status boundary rejected")
    expected = {"sequence": seq, "generation": generation, "ledgerEntries": consumed, "reserved": 0,
                "consumed": consumed, "revokedKeys": 0, "revokedApprovals": int(generation == 2),
                "revokedManifests": 0, "recoveryCompleted": 0}
    for name, target in expected.items():
        require(type(value[name]) is int and value[name] == target, "lifecycle durable state rejected")
    integer(value["ledgerCapacity"], consumed, 1 << 20)
    integer(value["observedAtUnix"], 1)
    integer(value["auditVerifiedAtUnix"], 1, value["observedAtUnix"])
    integer(value["notAfterUnix"], value["observedAtUnix"] + 1)
    last = integer(value["refreshLastSuccessUnix"], 0, value["observedAtUnix"])
    until = integer(value["refreshUntilUnix"], 0)
    if last:
        require(until == min(last + 15, value["notAfterUnix"]), "freshness lifetime mismatch")
    else:
        require(until == 0 and value["refreshFresh"] is False, "unconfirmed source marked fresh")
    if value["refreshFresh"]:
        require(last > 0 and value["observedAtUnix"] <= until, "fresh source deadline rejected")
    wanted_policies = []
    for policy in info["policies"]:
        name = policy["name"]
        if generation == 2 and name == "b":
            continue
        state = "CONSUMED" if name == "a" and consumed >= 1 or name == "c" and consumed >= 2 else "AVAILABLE"
        wanted_policies.append({"policyId": policy["policyID"], "grantId": policy["grantID"], "revision": 1,
                                "manifestSHA256": info["manifestSHA256"], "state": state})
    require(value["policies"] == wanted_policies, "revoked or consumed policy state mismatch")
    for policy in value["policies"]:
        require(type(policy["revision"]) is int, "policy revision type rejected")


def history(value, wanted):
    seq, _, _, total = wanted
    exact(value, registry.HISTORY_FIELDS)
    require(value["boundary"] == "ADVISORY_TRUST_OPERATION_HISTORY" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and type(value["sequence"]) is int
            and value["sequence"] == seq and type(value["total"]) is int and value["total"] == total
            and type(value["offset"]) is int and value["offset"] == 0
            and type(value["limit"]) is int and value["limit"] == 50
            and isinstance(value["entries"], list) and len(value["entries"]) == total,
            "lifecycle history tally rejected")
    integer(value["observedAtUnix"], 1)
    entries = {}
    for row in value["entries"]:
        exact(row, registry.ENTRY_FIELDS)
        identifier = public_id(row["operationId"])
        require(identifier not in entries and row["acknowledged"] is True, "history duplicate or missing ACK")
        require(row["actorId"] in {"d12-admin", "image-trust-refresh"}, "unexpected operation actor")
        bare_hash(row["preparedAuditHash"])
        bare_hash(row["resultAuditHash"])
        integer(row["preparedAtUnix"], 1)
        integer(row["resultAtUnix"], row["preparedAtUnix"])
        integer(row["generation"], 0, 2)
        entries[identifier] = row
    return entries


def snapshot(value, wanted, info, epoch, name):
    exact(value, ("name", "feedEpoch", "status", "history"))
    require(value["name"] == name and type(value["feedEpoch"]) is int and value["feedEpoch"] == epoch,
            "observation name or plan epoch mismatch")
    status(value["status"], wanted, info)
    return history(value["history"], wanted)


def plan_record(value, epoch, http_status, info):
    exact(value, ("epoch", "status", "bodySHA256", "sha256"))
    require(type(value["epoch"]) is int and value["epoch"] == epoch
            and type(value["status"]) is int and value["status"] == http_status,
            "source plan stage mismatch")
    expected_body = info["catalogue2SHA256"][7:] if http_status == 200 else ""
    require(value["bodySHA256"] == expected_body, "source plan catalogue mismatch")
    bare_hash(value["sha256"])
    raw = encoded({"schema": PLAN_SCHEMA, "epoch": epoch,
                   "responses": {"latest.json": {"status": http_status, "bodySHA256": expected_body}}})
    require(image.sha(raw) == value["sha256"], "source plan original bytes mismatch")


def post_case(value, definition, before, after, info, old_history, new_history):
    name, policy_name, code = definition
    exact(value, (*registry.CASE_FIELDS, *(("receipt",) if code == 200 else ())))
    require(value["name"] == name and value["method"] == "POST"
            and value["path"] == "/api/v1/image-trust/verifications"
            and type(value["httpStatus"]) is int and value["httpStatus"] == code
            and value["errorCode"] == ("" if code == 200 else "image_trust_invalid" if code == 400 else "image_trust_unavailable")
            and value["stateMayHaveChanged"] is (code == 400), "actual lifecycle API result rejected")
    policy = next(p for p in info["policies"] if p["name"] == policy_name)
    for field in ("policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256", "trustedRootSHA256"):
        require(value[field] == policy[field], "POST signed material mismatch")
    digest(value["requestSHA256"])
    status(value["statusBefore"], before, info)
    status(value["statusAfter"], after, info)
    require(history(value["historyBefore"], before) == old_history
            and history(value["historyAfter"], after) == new_history, "POST versus observation history mismatch")
    if code == 503:
        for side in ("statusBefore", "statusAfter"):
            require(value[side]["refreshFresh"] is False, "unconfirmed or stale API reached verifier")
        require(old_history == new_history, "source-unavailable request mutated history")
    else:
        require(value["statusBefore"]["refreshFresh"] is True
                and value["statusAfter"]["refreshFresh"] is True, "verification lacked confirmed source")
    if code == 200:
        receipt = value["receipt"]
        exact(receipt, ("boundary", "authorization", "deviceActionsExecuted", "verified", "grantId",
                        "catalogueSHA256", "generation", "manifestSHA256", "evidenceSHA256"))
        require(receipt["boundary"] == "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND"
                and receipt["authorization"] == "BLOCKED" and receipt["deviceActionsExecuted"] is False
                and receipt["verified"] is True and receipt["grantId"] == policy["grantID"]
                and receipt["catalogueSHA256"] == info["catalogue2SHA256"]
                and type(receipt["generation"]) is int and receipt["generation"] == 2
                and receipt["manifestSHA256"] == info["manifestSHA256"], "lifecycle receipt rejected")
        digest(receipt["evidenceSHA256"])


def action_sequence(reports, kind, source, local_id, graph):
    require(set(reports) == set(STAGES), "lifecycle stage set incomplete")
    info = None
    state, epoch, prior_history = INITIAL, 0, {}
    plans, all_cases, last_snapshot = {}, [], None
    for action, number in STAGES:
        report = reports[(action, number)]
        reopening = action in {"reopen-first", "reopen-final"}
        exact(report, (*ACTION_FIELDS, *(("inspection", "journal", "audit", "auditBindings") if reopening else ())))
        registry.boundary(report)
        require(report["schema"] == "chengwang.product-lifecycle-action/v1"
                and report["action"] == action and type(report["case"]) is int and report["case"] == number
                and report["authority"] == "EPHEMERAL_TEST_ONLY" and report["graphOrigin"] == registry.GRAPH_ORIGIN
                and report["journalAuditBindingsVerified"] is reopening, "lifecycle action protocol rejected")
        actual = material(report, kind, source, local_id, graph)
        require(info is None or info == actual, "lifecycle signed material changed")
        info = actual
        require(isinstance(report["feedPlans"], list) and isinstance(report["observations"], list)
                and isinstance(report["cases"], list), "lifecycle arrays required")
        planned = PLAN_STAGES.get((action, number))
        require(len(report["feedPlans"]) == int(planned is not None), "source plan publication missing or extra")
        next_epoch = planned[0] if planned else epoch
        if planned:
            plan_record(report["feedPlans"][0], *planned, info)
            require(next_epoch == epoch + 1, "source plan epochs incomplete")
            plans[next_epoch] = report["feedPlans"][0]
        if action == "prepare":
            require(report["observations"] == report["cases"] == [], "prepare issued product API")
        elif reopening:
            require(report["observations"] == report["cases"] == [], "offline reopen issued product API")
            require(last_snapshot is not None, "reopen before actual product observations")
            reopened(report, last_snapshot, all_cases, info)
        else:
            require(len(report["observations"]) == 2, "before/after actual observations required")
            before, after = report["observations"]
            old = snapshot(before, state, info, epoch, "before")
            require(old == prior_history, "history changed in unobserved stage gap")
            target = AFTER[(action, number)]
            current = snapshot(after, target, info, next_epoch, "after")
            require(all(current.get(key) == value for key, value in old.items()), "acknowledged history changed")
            require(len(current) - len(old) == target[3] - state[3], "unexpected operation count")
            definition = POSTS.get((action, number))
            require(len(report["cases"]) == int(definition is not None), "actual POST evidence missing or extra")
            if definition:
                case = report["cases"][0]
                post_case(case, definition, state, target, info, old, current)
                require(case["statusAfter"] == after["status"], "POST result differs from actual after observation")
                if (action, number) != ("exercise", 7):
                    require(case["statusBefore"] == before["status"], "POST input differs from actual before observation")
                else:
                    durable = set(registry.STATUS_FIELDS) - {"refreshFresh", "refreshLastSuccessUnix",
                        "refreshUntilUnix", "observedAtUnix", "auditVerifiedAtUnix"}
                    require(all(case["statusBefore"][key] == before["status"][key] for key in durable),
                            "stale precondition changed durable domain")
                    require(case["statusBefore"]["observedAtUnix"] >= case["statusBefore"]["refreshUntilUnix"] > 0,
                            "stale precondition not naturally expired")
                all_cases.append(case)
            if (action, number) in {("exercise", 1), ("resume", 1)}:
                for value in (before["status"], after["status"]):
                    require(value["refreshFresh"] is False and value["refreshLastSuccessUnix"] == 0
                            and value["refreshUntilUnix"] == 0, "process inherited source freshness")
            elif (action, number) in {("exercise", 2), ("exercise", 3), ("exercise", 8), ("resume", 2)}:
                require(after["status"]["refreshFresh"] is True
                        and after["status"]["refreshLastSuccessUnix"] > before["status"]["refreshLastSuccessUnix"],
                        "automatic refresh or exact no-op not observed")
            elif (action, number) == ("exercise", 7):
                value = after["status"]
                require(value["refreshFresh"] is False and value["refreshLastSuccessUnix"] > 0
                        and value["observedAtUnix"] >= value["refreshUntilUnix"], "source did not naturally become stale")
            state, prior_history, last_snapshot = target, current, after
        epoch = next_epoch
    require(len(plans) == 7, "source plan matrix incomplete")
    # Replays use the original exact signed request, including across restart.
    by_name = {case["name"]: case for case in all_cases}
    require(len(by_name) == len(all_cases), "duplicate lifecycle POST name")
    require(len({by_name[n]["requestSHA256"] for n in ("unconfirmed", "a-success", "a-replay", "a-replay-after-restart")}) == 1,
            "A request changed across replay or restart")
    require(len({by_name[n]["requestSHA256"] for n in ("stale", "cold-unconfirmed", "c-success", "c-replay")}) == 1,
            "C request changed across stale or restart")
    first, final = reports[("reopen-first", 0)], reports[("reopen-final", 0)]
    require(first["journal"] == final["journal"][:4]
            and first["auditBindings"] == final["auditBindings"][:4]
            and first["inspection"]["consumptions"] == final["inspection"]["consumptions"][:1],
            "restart replaced acknowledged history or consumption")
    return info, plans


def event_time(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value),
            "audit timestamp rejected")
    try:
        return int(datetime.datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
                   .replace(tzinfo=datetime.timezone.utc).timestamp())
    except (ValueError, OverflowError) as error:
        raise CheckError("audit timestamp rejected") from error


def audit_event(value, operation, phase, previous, data, outcome):
    exact(value, (*EVENT_FIELDS, *(("data",) if data else ())))
    public_id(value["id"])
    require(value["idempotencyKey"] == "image-trust/" + operation["id"] + "/" + phase
            and value["traceId"] == operation["id"] and value["actorId"] == operation["actorID"]
            and value["action"] == "image_trust." + operation["kind"]
            and value["target"] == outcome["target"] and value["result"] == outcome["result"]
            and value.get("data", {}) == data and value["previousHash"] == previous,
            "actual audit actor, payload or prefix mismatch")
    bare_hash(value["previousHash"])
    bare_hash(value["hash"])
    occurred = event_time(value["occurredAt"])
    # Match EvidenceEvent's Go struct order and omitempty; maps use Go's sorted
    # string-key order. Every accepted string is a closed ASCII label/digest.
    ordered = {name: value[name] for name in
               ("id", "idempotencyKey", "traceId", "actorId", "action", "target", "result", "occurredAt")}
    if data:
        ordered["data"] = dict(sorted(data.items()))
    ordered["previousHash"] = value["previousHash"]
    ordered["hash"] = ""
    require(image.sha(encoded(ordered, ordered=True)) == value["hash"], "actual audit event bytes hash mismatch")
    return occurred


def reopened(report, last, all_cases, info):
    inspection, journal, audit = report["inspection"], report["journal"], report["audit"]
    current, historical = last["status"], last["history"]
    exact(inspection, ("authorization", "catalogue", "catalogueValid", "sequence", "ledgerCapacity",
                       "ledgerUsed", "ledgerRemaining", "consumptions"))
    require(inspection["authorization"] == "BLOCKED" and inspection["catalogueValid"] is True,
            "reopened lifecycle store rejected")
    for name, target in {"sequence": current["sequence"], "ledgerCapacity": current["ledgerCapacity"],
                         "ledgerUsed": current["ledgerEntries"],
                         "ledgerRemaining": current["ledgerCapacity"] - current["ledgerEntries"]}.items():
        require(type(inspection[name]) is int and inspection[name] == target, "reopened lifecycle tally mismatch")
    catalogue = inspection["catalogue"]
    exact(catalogue, ("storeID", "generation", "sha256", "notBeforeUnix", "notAfterUnix", "rootKeyCount", "rootThreshold",
                      "approverCount", "grants", "policyFloors", "revokedKeyCount", "revokedApprovalCount", "revokedManifestCount"))
    require(catalogue["storeID"] == info["storeID"] and catalogue["sha256"] == info["catalogue2SHA256"]
            and catalogue["notAfterUnix"] == current["notAfterUnix"], "reopened source catalogue mismatch")
    for name, target in {"generation": 2, "rootKeyCount": 1, "rootThreshold": 1, "approverCount": 3,
                         "revokedKeyCount": 0, "revokedApprovalCount": 1, "revokedManifestCount": 0}.items():
        require(type(catalogue[name]) is int and catalogue[name] == target, "reopened catalogue counters mismatch")
    integer(catalogue["notBeforeUnix"], 1, catalogue["notAfterUnix"] - 1)
    require(catalogue["policyFloors"] == {p["policyID"]: 1 for p in info["policies"]}
            and all(type(v) is int for v in catalogue["policyFloors"].values()), "policy floor rollback detected")
    active = [p for p in info["policies"] if p["name"] != "b"]
    require(isinstance(catalogue["grants"], list) and len(catalogue["grants"]) == 2, "revoked grant was retained")
    for grant, policy in zip(catalogue["grants"], active):
        exact(grant, ("id", "policyID", "approvalSHA256", "approverKeyID", "manifestSHA256", "revision"))
        public_id(grant["approverKeyID"])
        require(grant["id"] == policy["grantID"] and grant["policyID"] == policy["policyID"]
                and grant["approvalSHA256"] == policy["approvalSHA256"] and grant["manifestSHA256"] == info["manifestSHA256"]
                and type(grant["revision"]) is int and grant["revision"] == 1, "reopened active grant mismatch")
    successful = [case for case in all_cases if case["httpStatus"] == 200]
    expected_consumed = []
    for case in successful:
        expected_consumed.append({"grantID": case["grantID"], "policyID": case["policyID"],
            "approvalSHA256": case["approvalSHA256"], "manifestSHA256": info["manifestSHA256"],
            "generation": 2, "catalogueSHA256": info["catalogue2SHA256"], "status": "CONSUMED",
            "evidenceSHA256": case["receipt"]["evidenceSHA256"]})
    require(inspection["consumptions"] == expected_consumed, "consumption lost, forged or recreated")
    for row in inspection["consumptions"]:
        require(type(row["generation"]) is int, "consumption generation type rejected")
    exact(audit, ("valid", "count", "expectedCount", "lastHash", "expectedLastHash", "verifiedAt"))
    total = historical["total"]
    require(audit["valid"] is True and type(audit["count"]) is int and type(audit["expectedCount"]) is int
            and audit["count"] == audit["expectedCount"] == total * 2,
            "reopened audit checkpoint tally rejected")
    require(bare_hash(audit["lastHash"]) == bare_hash(audit["expectedLastHash"]), "audit checkpoint tail rejected")
    event_time(audit["verifiedAt"])
    operations = [None] + [case for case in all_cases if case["httpStatus"] != 503]
    require(isinstance(journal, list) and isinstance(report["auditBindings"], list)
            and len(journal) == len(report["auditBindings"]) == total == len(operations), "reopened operation matrix incomplete")
    by_id = {entry["operationId"]: entry for entry in historical["entries"]}
    previous, event_ids = "0" * 64, set()
    scope = {"tenantId": "d12-tenant", "siteId": "d12-site", "objectType": "image-trust",
             "objectId": info["storeID"], "environment": "candidate"}
    scope_hash = "sha256:" + image.sha(encoded(scope, ordered=True))
    for index, (entry, binding, case) in enumerate(zip(journal, report["auditBindings"], operations)):
        exact(entry, ("operation", "state", "outcome", "outcomeData", "acknowledged", "resultAuditHash", "grantID",
                      "generation", "catalogueSHA256", "manifestSHA256", "evidenceSHA256"))
        op = entry["operation"]
        exact(op, ("id", "actorID", "scopeSHA256", "kind", "data", "auditBaseCount", "auditBaseHash", "preparedAuditHash"))
        op_id = public_id(op["id"])
        require(op_id in by_id and op["actorID"] == ("image-trust-refresh" if index == 0 else "d12-admin")
                and op["kind"] == ("update" if index == 0 else "verify") and op["scopeSHA256"] == scope_hash
                and type(op["auditBaseCount"]) is int and op["auditBaseCount"] == index * 2
                and op["auditBaseHash"] == previous and entry["acknowledged"] is True,
                "automatic actor, original scope or audit prefix rejected")
        data = ({"catalogueSHA256": info["catalogue2SHA256"]} if case is None else {
            "policyId": case["policyID"], "approvalSHA256": case["approvalEnvelopeSHA256"],
            "bundleSHA256": case["bundleSHA256"], "rootSHA256": case["trustedRootSHA256"]})
        require(op["data"] == data, "journal request payload binding mismatch")
        consumed = case is not None and case["httpStatus"] == 200
        expected_state = "COMMITTED" if case is None else "CONSUMED" if consumed else "PREPARED"
        expected_outcome = "CATALOGUE_COMMITTED" if case is None else "VERIFICATION_CONSUMED" if consumed else "REJECTED"
        outcome_data = ({"catalogueSHA256": info["catalogue2SHA256"]} if case is None else {
            "grantId": case["grantID"], "manifestSHA256": info["manifestSHA256"],
            "catalogueSHA256": info["catalogue2SHA256"], "evidenceSHA256": case["receipt"]["evidenceSHA256"]} if consumed else {})
        require(entry["state"] == expected_state and entry["outcome"] == expected_outcome
                and entry["outcomeData"] == outcome_data, "journal outcome changed or forged")
        require(type(entry["generation"]) is int and entry["generation"] == (2 if case is None or consumed else 0)
                and entry["catalogueSHA256"] == (info["catalogue2SHA256"] if case is None or consumed else "")
                and entry["grantID"] == (case["grantID"] if consumed else "")
                and entry["manifestSHA256"] == (info["manifestSHA256"] if consumed else "")
                and entry["evidenceSHA256"] == (case["receipt"]["evidenceSHA256"] if consumed else ""),
                "rejected operation acquired domain state")
        old = by_id[op_id]
        for field, old_field in (("state", "state"), ("outcome", "outcome"), ("grantID", "grantId"),
                                 ("generation", "generation"), ("catalogueSHA256", "catalogueSHA256"),
                                 ("resultAuditHash", "resultAuditHash")):
            require(entry[field] == old[old_field], "journal versus HTTP history mismatch")
        require(old["actorId"] == op["actorID"] and old["kind"] == op["kind"]
                and old["policyId"] == ("" if case is None else case["policyID"])
                and old["preparedAuditHash"] == op["preparedAuditHash"], "history actor or prepared binding rejected")
        exact(binding, ("operationID", "prepared", "result"))
        require(binding["operationID"] == op_id, "actual audit binding operation mismatch")
        target = "image-trust/" + info["storeID"]
        prepared_at = audit_event(binding["prepared"], op, "prepared", previous, data,
                                  {"target": target, "result": "prepared"})
        require(binding["prepared"]["hash"] == op["preparedAuditHash"], "prepared hash missing in actual audit")
        result_at = audit_event(binding["result"], op, "result", op["preparedAuditHash"], outcome_data,
                                {"target": target, "result": "completed" if case is None else "verification_consumed" if consumed else "rejected"})
        require(binding["result"]["hash"] == entry["resultAuditHash"] and result_at >= prepared_at
                and old["preparedAtUnix"] == prepared_at and old["resultAtUnix"] == result_at,
                "result audit time or ACK binding rejected")
        for value in (binding["prepared"], binding["result"]):
            require(value["id"] not in event_ids, "actual audit event identity reused")
            event_ids.add(value["id"])
        previous = entry["resultAuditHash"]
    require(previous == audit["lastHash"], "actual audit chain differs from checkpoint")


def source_events(raw, plans, info, windows):
    require(0 < len(raw) <= 4 << 20 and raw.endswith(b"\n"), "source log missing, truncated or oversized")
    rows = raw.splitlines()
    require(1 <= len(rows) <= 8192 and all(rows), "source log framing rejected")
    require(isinstance(windows, list) and len(windows) == 2, "product stop windows missing")
    allowed_incomplete, previous_end = set(), 0
    # Prefix hashes cover original bytes, including each original line terminator.
    raw_lines = raw.splitlines(keepends=True)
    for window, label in zip(windows, ("first", "final")):
        exact(window, ("label", "before", "after"))
        require(window["label"] == label, "product stop window order rejected")
        endpoints = []
        for position in ("before", "after"):
            endpoint = window[position]
            exact(endpoint, ("eventCount", "sha256"))
            count = integer(endpoint["eventCount"], 0, len(rows))
            bare_hash(endpoint["sha256"])
            require(endpoint["sha256"] == image.sha(b"".join(raw_lines[:count])),
                    "product stop window prefix hash mismatch")
            endpoints.append(count)
        start, end = endpoints
        require(previous_end <= start <= end, "product stop windows overlap or move backwards")
        allowed_incomplete.update(range(start + 1, end + 1))
        previous_end = end
    require(previous_end == len(rows), "final product stop omitted source log suffix")
    counts, incomplete = {}, 0
    for ordinal, line in enumerate(rows, 1):
        event = image.decode(line)
        exact(event, SOURCE_EVENT_FIELDS)
        require(event["schema"] == "chengwang.product-lifecycle-feed-event/v1"
                and type(event["ordinal"]) is int and event["ordinal"] == ordinal
                and type(event["epoch"]) is int and event["epoch"] in plans
                and event["pathClass"] == "latest" and type(event["generation"]) is int and event["generation"] == 0
                and event["tls"] is True and event["authPresent"] is False
                and type(event["sentComplete"]) is bool, "source access was not a fixed-target TLS GET")
        plan = plans[event["epoch"]]
        wanted_body = info["catalogue2SHA256"][7:] if plan["status"] == 200 else image.sha(ERROR_BODY)
        wanted_reason = "ok" if plan["status"] == 200 else "planned-unavailable"
        require(type(event["status"]) is int and event["status"] == plan["status"]
                and event["reason"] == wanted_reason and event["bodySHA256"] == wanted_body,
                "source event is not bound to the published exact catalogue")
        if event["sentComplete"]:
            integer(event["bytes"], 1, 256 << 10)
            if event["status"] == 503:
                require(event["bytes"] == len(ERROR_BODY), "source refusal body mismatch")
            counts[event["epoch"]] = counts.get(event["epoch"], 0) + 1
        else:
            require(ordinal in allowed_incomplete and type(event["bytes"]) is int and event["bytes"] == 0,
                    "incomplete source response outside measured product stop window")
            incomplete += 1
    # e5/e7 source-off publication does not assert a request instantly occurs.
    # e5 is nevertheless required by the subsequent cold-unconfirmed case.
    for epoch in (1, 2, 3, 4, 5, 6):
        require(counts.get(epoch, 0) > 0, "actual required source GET absent")
    require(counts[2] >= 2, "exact no-op lacks a second independent source read")
    return {"completedRequests": len(rows) - incomplete, "incompleteResponsesDuringStop": incomplete,
            "epochRequests": {str(k): counts[k] for k in sorted(counts)}}


def observations(value, source, local_id, graphs):
    exact(value, ("schema", "sourceCommit", "localImageID", "registryContainerID", "pinnedRegistryImage", *BOUNDARY, "snapshots"))
    registry.boundary(value)
    require(value["schema"] == "chengwang.product-lifecycle-observations/v1" and value["sourceCommit"] == source
            and value["localImageID"] == local_id and value["pinnedRegistryImage"] == registry.REGISTRY_IMAGE,
            "lifecycle Registry observation identity rejected")
    registry_id = bare_hash(value["registryContainerID"])
    expected = [(kind, action, number, position) for kind in KINDS for action, number in STAGES for position in ("before", "after")]
    snapshots = value["snapshots"]
    require(isinstance(snapshots, list) and len(snapshots) == 72, "lifecycle Registry windows incomplete")
    allowed = {g["registryManifestDigest"] for g in graphs.values()}
    allowed.update(g["configDescriptor"]["digest"] for g in graphs.values())
    allowed.update(layer["digest"] for g in graphs.values() for layer in g["layerDescriptors"])
    previous, counters = {}, []
    for ordinal, (snapshot_value, step) in enumerate(zip(snapshots, expected), 1):
        exact(snapshot_value, ("ordinal", "kind", "action", "case", "position", "digestRequests", "otherRequests"))
        require(type(snapshot_value["ordinal"]) is int and snapshot_value["ordinal"] == ordinal
                and type(snapshot_value["case"]) is int
                and (snapshot_value["kind"], snapshot_value["action"], snapshot_value["case"], snapshot_value["position"]) == step,
                "lifecycle Registry snapshot order mismatch")
        current = registry.traffic_counts(snapshot_value)
        if ordinal == 1:
            require(not current, "lifecycle Registry had unobserved initial requests")
        require(all(not key[1] or key[1] in allowed for key in current), "Registry read unbound product object")
        require(all(current.get(key, 0) >= count for key, count in previous.items()), "Registry counter moved backwards")
        if ordinal > 1 and snapshot_value["position"] == "before":
            require(current == previous, "unobserved lifecycle Registry traffic gap")
        counters.append(current)
        previous = current
    successes = zero_windows = 0
    for index in range(0, len(snapshots), 2):
        row = snapshots[index]
        old, new = counters[index:index + 2]
        delta = {key: new.get(key, 0) - old.get(key, 0) for key in new if new.get(key, 0) != old.get(key, 0)}
        graph = graphs[row["kind"]]
        if row["action"] == "prepare":
            wanted = {("GET", graph["registryManifestDigest"], 200): 1,
                      ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                      ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
            for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                wanted[("GET", desc["digest"], 200)] = 1
            require(delta == wanted, "lifecycle preparation upload or byte readback budget rejected")
        elif (row["action"], row["case"]) in {("exercise", 4), ("resume", 4)}:
            wanted = {("GET", graph["registryManifestDigest"], 200): 2, ("HEAD", graph["registryManifestDigest"], 200): 4}
            for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                wanted[("GET", desc["digest"], 200)] = 1
                wanted[("HEAD", desc["digest"], 200)] = 2
            require(delta == wanted, "actual product Registry SDK budget rejected")
            successes += 1
        else:
            require(not delta, "unconfirmed, stale, revoked, replay or read-only step reached Registry")
            zero_windows += 1
    return {"registryContainerID": registry_id, "snapshotCount": 72,
            "successfulImageReads": successes, "zeroRequestWindows": zero_windows}


SOURCE_LIMITS = {"cpuSeconds": 60, "addressSpaceBytes": 536870912, "fileBytes": 16777216,
                 "openFiles": 128, "processes": 128, "coreBytes": 0}
SUPPORT_NAMES = frozenset("product-lifecycle-" + name for name in (
    "preflight.json", "lease-tests.log", "feed-tests.log", "checker-tests.log", "cleanup.json",
    "profile-tests.log", "verifier-tests.log"))
HARNESS_PATHS = tuple("chengwang/deploy/product-candidate/" + name for name in (
    "fixture_feed.py", "check_product_image.py", "check_product_registry.py", "check_product_lifecycle.py"))


def source_process(process, stopped, ready, source, kind, helper_sha):
    expected = {"schema": "chengwang.product-lifecycle-source/v1", "sourceCommit": source, "kind": kind,
                "sourceCase": "source", "uid": 10001, "gid": 10001, "capabilities": "none",
                "noNewPrivileges": True, "registryNetworkNamespaceMatched": True, "privateMountNamespace": True,
                "gitBoundSourceMatched": True, "sourceSHA256": helper_sha,
                "sourceLimitsVerified": True, "sourceLimits": SOURCE_LIMITS, **BOUNDARY}
    exact(process, (*expected, "hostPID", "pythonExecutableSHA256"))
    require(all(type(process[key]) is type(value) and process[key] == value for key, value in expected.items()),
            "source actual process profile rejected")
    exact(process["sourceLimits"], SOURCE_LIMITS)
    require(all(type(process["sourceLimits"][key]) is int for key in SOURCE_LIMITS), "source resource types rejected")
    pid = integer(process["hostPID"], 1)
    bare_hash(process["pythonExecutableSHA256"])
    expected_stop = {"schema": "chengwang.product-lifecycle-source-stop/v1", "sourceCommit": source, "kind": kind,
                     "hostPID": pid, "signal": "SIGTERM", "exitCode": 0, "joined": True, **BOUNDARY}
    exact(stopped, (*expected_stop, "productStopWindows"))
    require(all(type(stopped[key]) is type(value) and stopped[key] == value for key, value in expected_stop.items()),
            "source did not join with an actual clean exit")
    exact(ready, ("schema", "port", "pid", "uid", "gid", "tls", "listenLoopback", "deadlineSeconds"))
    expected_ready = {"schema": "chengwang.product-lifecycle-feed-ready/v1", "port": 5444, "pid": pid,
                      "uid": 10001, "gid": 10001, "tls": True, "listenLoopback": True}
    require(all(type(ready[key]) is type(value) and ready[key] == value for key, value in expected_ready.items()),
            "source listener is not the measured helper")
    integer(ready["deadlineSeconds"], 1, 600)
    return pid


def own_names():
    names = {"product-lifecycle-" + name + ".json" for name in
             ("harness", "network", "isolation", "observations", "runtime-cleanup", "outcome")}
    for kind in KINDS:
        names.update(report_name(kind, action, number) for action, number in STAGES)
        names.update("product-lifecycle-" + kind + "-" + suffix for suffix in (
            "graph.json", "source.json", "source-stop.json", "feed-ready.json", "feed-events.jsonl",
            "running-inspect.json", "exited-inspect.json", "restarted-running-inspect.json",
            "restarted-exited-inspect.json", "running-pid1.json", "restarted-running-pid1.json"))
    require(len(names) == 64, "internal lifecycle file set mismatch")
    return names


def verify(args):
    require(registry.COMMIT.fullmatch(args.source_commit) is not None, "source commit rejected")
    directory = image.checked_path(args.evidence_dir, directory=True)
    loaded, hashes = {}, {}

    def load(name, *, lines=False):
        raw = registry.read_file(directory / name, 4 << 20)
        hashes[name] = image.sha(raw)
        if lines:
            loaded[name] = raw
            return raw
        value = image.decode(raw)
        require(isinstance(value, dict), "lifecycle evidence object required")
        loaded[name] = value
        return value

    source = args.source_commit
    staging = load("product-image-staging.json")
    packaged = load("product-image-packaged-contents.json")
    packaged_raw = registry.read_file(directory / "product-image-packaged-contents.json", 4 << 20)
    require(staging.get("sourceCommit") == source and staging.get("authorization") == "BLOCKED"
            and staging.get("deviceActionsExecuted") is False and staging.get("imageBuilt") is False
            and staging.get("imageExecuted") is False and isinstance(staging.get("binary"), dict),
            "outer candidate staging boundary rejected")
    binary_hash = bare_hash(staging["binary"].get("sha256"))
    require(staging["binary"].get("sourceCommit") == source and staging["binary"].get("sourceModified") is False,
            "actual binary source identity rejected")
    local_id = digest(packaged.get("localImageID"))
    require(packaged.get("schema") == "chengwang.product-image-packaged-content/v1"
            and packaged.get("sourceCommit") == source and packaged.get("authorization") == "BLOCKED"
            and packaged.get("production") is False and packaged.get("registryManifestDigestVerified") is False
            and packaged.get("configDigestMatched") is True and packaged.get("secretsPackaged") is False
            and packaged.get("rawArchivePublished") is False, "outer packaged image boundary rejected")
    files, contexts = packaged.get("files"), staging.get("contextFiles")
    require(isinstance(files, dict) and files.get("app/image-trust-api", {}).get("sha256") == binary_hash
            and files["app/image-trust-api"].get("bytes") == staging["binary"].get("bytes")
            and isinstance(contexts, dict) and "Dockerfile" in contexts
            and {name.removeprefix("rootfs/"): value for name, value in contexts.items() if name != "Dockerfile"}
            == {name: value["sha256"] for name, value in files.items()}, "staging and packaged image bytes mismatch")
    harness = load("product-lifecycle-harness.json")
    exact(harness, ("schema", "sourceCommit", "files", "checkoutBytesMatched", "permissionReadOnly", *BOUNDARY))
    registry.boundary(harness)
    require(harness["schema"] == "chengwang.product-lifecycle-harness/v1" and harness["sourceCommit"] == source
            and harness["checkoutBytesMatched"] is True and harness["permissionReadOnly"] is True
            and isinstance(harness["files"], dict) and set(harness["files"]) == set(HARNESS_PATHS),
            "lifecycle read-only helper source binding rejected")
    for name, expected_hash in harness["files"].items():
        bare_hash(expected_hash)
        actual = registry.read_file(pathlib.Path(__file__).with_name(pathlib.PurePosixPath(name).name), 256 << 10)
        require(image.sha(actual) == expected_hash, "running lifecycle helper differs from bound source")
    graphs = {}
    for kind in KINDS:
        graph = load("product-lifecycle-" + kind + "-graph.json")
        registry.graph_projection(graph, source, local_id, packaged_raw)
        require([layer["diffID"] for layer in graph["layerDescriptors"]] == packaged["layerDiffIDs"]
                and graph["packagedFileCount"] == packaged["packagedFileCount"]
                and binary_hash not in {local_id[7:], graph["registryManifestDigest"][7:]},
                "binary, config and Registry manifest roles conflated")
        graphs[kind] = graph
    require(graphs[KINDS[0]] == graphs[KINDS[1]], "signature kinds did not verify the same product graph")
    traffic = observations(load("product-lifecycle-observations.json"), source, local_id, graphs)
    registry_id = traffic["registryContainerID"]
    isolation, network = load("product-lifecycle-isolation.json"), load("product-lifecycle-network.json")
    registry.registry_isolation(isolation, network, source, registry_id)
    require(isolation["actualImageID"] != local_id, "Registry and product image identity conflated")
    materials, product_ids, source_ids, source_counts = [], set(), set(), {}
    for kind in KINDS:
        reports = {(action, number): load(report_name(kind, action, number)) for action, number in STAGES}
        info, plans = action_sequence(reports, kind, source, local_id, graphs[kind])
        materials.append(info)
        prefix = "product-lifecycle-" + kind + "-"
        stopped = load(prefix + "source-stop.json")
        source_counts[kind] = source_events(load(prefix + "feed-events.jsonl", lines=True), plans, info,
                                          stopped.get("productStopWindows"))
        source_ids.add(source_process(load(prefix + "source.json"), stopped,
                       load(prefix + "feed-ready.json"), source, kind,
                       harness["files"]["chengwang/deploy/product-candidate/fixture_feed.py"]))
        projections, processes = {}, {}
        for name in ("running", "exited", "restarted-running", "restarted-exited"):
            projections[name] = load(prefix + name + "-inspect.json")
            if name in {"running", "restarted-running"}:
                processes[name] = load(prefix + name + "-pid1.json")
        product_ids.add(registry.runtime_projections(projections, processes, source, local_id, registry_id, binary_hash))
    require(len(source_ids) == len(product_ids) == 2 and registry_id not in product_ids
            and len({info["storeID"] for info in materials}) == 2
            and len({info["policies"][0]["trustedRootSHA256"] for info in materials}) == 2
            and len({policy["grantID"] for info in materials for policy in info["policies"]}) == 6,
            "independent source, product, store or authority reused")
    cleanup = load("product-lifecycle-runtime-cleanup.json")
    expected_cleanup = {"schema": "chengwang.product-lifecycle-cleanup/v1", "sourceCommit": source, "localImageID": local_id,
        "ownedContainersRemoved": 3, "privateFixtureRemoved": True, "outerProductImagePreserved": True,
        "registryImagePreserved": True, "ownedSourcesJoined": 2, "sourceExitCodes": [0, 0], "outcome": "PASS", **BOUNDARY}
    exact(cleanup, expected_cleanup)
    require(all(type(cleanup[key]) is type(value) and cleanup[key] == value for key, value in expected_cleanup.items())
            and all(type(code) is int for code in cleanup["sourceExitCodes"]), "exact owned runtime cleanup not proven")
    expected_names = own_names()
    present = {path.name for path in directory.iterdir() if path.name.startswith("product-lifecycle-")}
    require(present <= expected_names | SUPPORT_NAMES
            and expected_names - {"product-lifecycle-outcome.json"} <= present,
            "unknown, stale or missing lifecycle evidence")
    require({name for name in loaded if name.startswith("product-lifecycle-")}
            == expected_names - {"product-lifecycle-outcome.json"} and len(hashes) == 65,
            "lifecycle evidence association set changed")
    result = {"schema": "chengwang.product-lifecycle-gate/v1", "outcome": "PASS", **BOUNDARY,
        "sourceCommit": source, "localImageID": local_id, "registryManifestDigest": graphs[KINDS[0]]["registryManifestDigest"],
        "binarySHA256": binary_hash, "signatureKinds": list(KINDS), "authority": "EPHEMERAL_TEST_ONLY",
        "graphBytesOrigin": registry.GRAPH_ORIGIN, "actualAutomaticRefreshProven": True,
        "automaticCatalogueUpdates": 2, "sameCatalogueNoopProven": True, "naturalStalenessRejectionProven": True,
        "sourceRestorationProven": True, "restartRequiresSourceConfirmation": True,
        "actualProductAPIRegistryReads": traffic["successfulImageReads"],
        "perCaseZeroRequestWindows": traffic["zeroRequestWindows"], "registryCounterSnapshots": traffic["snapshotCount"],
        "sourceObservations": source_counts, "sameContainerRestart": True, "productGracefulStops": 4,
        "sourceGracefulStops": 2, "cleanupVerified": True,
        "firstReopen": {"sequence": 18, "generation": 2, "journalEntries": 4, "auditEntries": 8, "ledgerEntries": 1},
        "finalReopen": {"sequence": 31, "generation": 2, "journalEntries": 7, "auditEntries": 14, "ledgerEntries": 2},
        "completeCrashMatrixProven": False, "physicalPowerLossProven": False, "trustedBuilderAttestation": False,
        "releaseAuthorized": False, "productImagePublishedOutsideIsolatedRegistry": False,
        "privateGraphDownloadedByReviewer": False, "evidenceSHA256": dict(sorted(hashes.items()))}
    existing = directory / "product-lifecycle-outcome.json"
    if existing.exists() or existing.is_symlink():
        previous, _ = json_file(existing)
        require(encoded(previous) == encoded(result), "existing lifecycle outcome differs from independently recomputed evidence")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    graph_parser = commands.add_parser("graph")
    for name in ("graph-dir", "packaged-report", "report"):
        graph_parser.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("source-commit", "manifest-digest"):
        graph_parser.add_argument("--" + name, required=True)
    inspection = commands.add_parser("inspect")
    for name in ("image-inspect", "container-inspect", "report"):
        inspection.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("image-id", "source-commit", "expected-private-source", "expected-state-source", "expected-network-mode"):
        inspection.add_argument("--" + name, required=True)
    inspection.add_argument("--container-status", choices=("running", "exited"), required=True)
    verification = commands.add_parser("verify")
    for name in ("evidence-dir", "report"):
        verification.add_argument("--" + name, type=pathlib.Path, required=True)
    verification.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "graph":
            result = registry.graph(args)
        elif args.command == "inspect":
            require(re.fullmatch(r"container:[a-f0-9]{64}", args.expected_network_mode),
                    "lifecycle product must share the isolated Registry namespace")
            result = image.inspect_projection(image.one_inspect(registry.read_file(args.image_inspect, 8 << 20)),
                image.one_inspect(registry.read_file(args.container_inspect, 8 << 20)), image_id=args.image_id,
                source=args.source_commit, private=args.expected_private_source, state=args.expected_state_source,
                network=args.expected_network_mode, status=args.container_status, fixture_kind="product-lifecycle")
            result["production"] = False
            result["networkPeerContainerID"] = args.expected_network_mode.removeprefix("container:")
        else:
            result = verify(args)
        image.write_exclusive(args.report, encoded(result) + b"\n")
    except (OSError, CheckError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        print("PRODUCT_LIFECYCLE_CHECK=FAIL rejected=true raw_input_suppressed=true", file=sys.stderr)
        return 1
    print("PRODUCT_LIFECYCLE_CHECK=PASS mode=" + args.command + " authorization=BLOCKED production=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
