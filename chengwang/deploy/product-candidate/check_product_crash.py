#!/usr/bin/env python3
"""Strict safe-evidence replay of the isolated three-cut product crash gate.

Reviewer-side replay does not download private image graphs or databases and
does not establish production recovery authority or physical power-loss safety.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
import check_product_image as image
import check_product_registry as registry
import check_product_lifecycle as lifecycle

CheckError = image.CheckError
require, exact, integer = image.require, registry.exact, registry.integer
digest, bare_hash, public_id = registry.digest, registry.bare_hash, registry.public_id
BOUNDARY, KINDS = registry.BOUNDARY, registry.KINDS
STAGES = ("prepared", "reserved", "consumed")
ACTIONS = ("prepare", "ready", "send", "blocked", "cut", "recovered", "reopen-first",
           "idempotent", "probe", "reopen-final")
MATERIAL_FIELDS = ("kind", "sourceCommit", "localImageID", "manifestSHA256", "configSHA256",
                   "layerSHA256s", "diffIDs", "catalogueSHA256", "storeID", "policies")
COMMON = ("schema", "action", "stage", *MATERIAL_FIELDS, "boundary", "authority", "graphOrigin", *BOUNDARY, "cases")
OFFLINE_FIELDS = ("inspection", "journal", "audit", "auditBindings", "auditLog", "checkpoint")
REQUEST_FIELDS = ("method", "path", "policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256",
                  "bundleSHA256", "trustedRootSHA256", "requestSHA256", "attempts", "httpStatus", "transportOutcome")
POLICY_FIELDS = ("name", "policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256",
                 "bundleSHA256", "bundleArtifactSHA256", "trustedRootSHA256", "registrySPKI")
CUT_SEQUENCE = {"prepared": 2, "reserved": 4, "consumed": 5}
RECOVERED_SEQUENCE = {"prepared": 5, "reserved": 6, "consumed": 6}
ACTOR = "d12-crash-admin"
ZERO = "0" * 64


def encoded(value, *, ordered=False):
    return lifecycle.encoded(value, ordered=ordered)


def actions(stage):
    require(stage in STAGES, "crash stage rejected")
    return (*ACTIONS[:3], "reserved", *ACTIONS[3:]) if stage == "consumed" else ACTIONS


def report_name(stage, kind, action):
    return "product-crash-" + stage + "-" + kind + "-" + action + ".json"


def material(value, stage, kind, source, local_id, graph):
    require(value["kind"] == kind and value["sourceCommit"] == source
            and value["localImageID"] == value["configSHA256"] == local_id
            and value["manifestSHA256"] == graph["registryManifestDigest"]
            and value["layerSHA256s"] == [row["digest"] for row in graph["layerDescriptors"]]
            and value["diffIDs"] == [row["diffID"] for row in graph["layerDescriptors"]],
            "crash material does not bind actual image graph")
    require(isinstance(value["storeID"], str) and re.fullmatch(r"[a-f0-9]{32}", value["storeID"]), "crash store rejected")
    digest(value["catalogueSHA256"])
    require(isinstance(value["policies"], list) and len(value["policies"]) == 1, "single original grant required")
    policy = value["policies"][0]
    exact(policy, POLICY_FIELDS)
    require(policy["name"] == "original" and policy["policyID"] == "d12-crash-" + stage, "crash grant role rejected")
    public_id(policy["grantID"])
    for key in POLICY_FIELDS:
        if key not in {"name", "policyID", "grantID"}:
            digest(policy[key])
    require(policy["bundleArtifactSHA256"] == value["manifestSHA256"], "signature artifact not actual manifest")
    return {key: value[key] for key in MATERIAL_FIELDS}


def status(value, info, sequence, ledger, operation_count, recovery):
    exact(value, registry.STATUS_FIELDS)
    require(value["boundary"] == "ADVISORY_TRUST_POLICY_STATE" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and value["healthy"] is True and value["fresh"] is True
            and value["storeId"] == info["storeID"] and value["catalogueSHA256"] == info["catalogueSHA256"]
            and value["refreshRequired"] is False and value["refreshFresh"] is False,
            "crash status authority or source profile rejected")
    counts = {"generation": 1, "sequence": sequence, "ledgerEntries": int(ledger != "AVAILABLE"),
              "reserved": int(ledger == "RESERVED"), "consumed": int(ledger == "CONSUMED"),
              "revokedKeys": 0, "revokedApprovals": 0, "revokedManifests": 0, "recoveryCompleted": recovery,
              "refreshLastSuccessUnix": 0, "refreshUntilUnix": 0}
    for key, wanted in counts.items():
        require(type(value[key]) is int and value[key] == wanted, "crash durable state or recovery tally rejected")
    integer(value["ledgerCapacity"], max(counts["ledgerEntries"], 1), 1 << 20)
    integer(value["observedAtUnix"], 1)
    integer(value["auditVerifiedAtUnix"], 1, value["observedAtUnix"])
    integer(value["notAfterUnix"], value["observedAtUnix"] + 1)
    policy = info["policies"][0]
    require(value["policies"] == [{"policyId": policy["policyID"], "grantId": policy["grantID"],
            "revision": 1, "manifestSHA256": info["manifestSHA256"], "state": ledger}]
            and type(value["policies"][0]["revision"]) is int, "crash grant burn state changed")


def history(value, sequence, count):
    exact(value, registry.HISTORY_FIELDS)
    require(value["boundary"] == "ADVISORY_TRUST_OPERATION_HISTORY" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and type(value["sequence"]) is int and value["sequence"] == sequence
            and type(value["total"]) is int and value["total"] == count
            and type(value["offset"]) is int and value["offset"] == 0
            and type(value["limit"]) is int and value["limit"] == 50
            and isinstance(value["entries"], list) and len(value["entries"]) == count, "crash history count rejected")
    integer(value["observedAtUnix"], 1)
    by_id = {}
    for row in value["entries"]:
        exact(row, registry.ENTRY_FIELDS)
        identifier = public_id(row["operationId"])
        require(identifier not in by_id and row["actorId"] == ACTOR and row["kind"] == "verify"
                and row["acknowledged"] is True, "crash actual history actor or ACK rejected")
        bare_hash(row["preparedAuditHash"]); bare_hash(row["resultAuditHash"])
        integer(row["preparedAtUnix"], 1); integer(row["resultAtUnix"], row["preparedAtUnix"])
        integer(row["generation"], 0, 1)
        by_id[identifier] = row
    return by_id


def raw_hash(value, raw):
    exact(value, ("bytes", "sha256"))
    require(type(value["bytes"]) is int and value["bytes"] == len(raw)
            and value["sha256"] == image.sha(raw), "actual original byte prefix mismatch")


def event_bytes(event):
    # All accepted strings are closed labels/digests/IDs and UTC timestamps.
    fields = ("id", "idempotencyKey", "traceId", "actorId", "action", "target", "result", "occurredAt")
    value = {name: event[name] for name in fields}
    if event.get("data"):
        value["data"] = dict(sorted(event["data"].items()))
    value.update(previousHash=event["previousHash"], hash=event["hash"])
    return encoded(value, ordered=True) + b"\n"


def audit_prefix(value, events):
    payload = b"".join(event_bytes(event) for event in events)
    raw_hash(value["auditLog"], payload)
    tail = events[-1]["hash"] if events else ZERO
    cp = encoded({"count": len(events), "lastHash": tail}, ordered=True)
    raw_hash(value["checkpoint"], cp)
    return payload


def request(value, info, *, interrupted):
    if interrupted:
        exact(value, REQUEST_FIELDS)
        require(type(value["attempts"]) is int and value["attempts"] == 1
                and type(value["httpStatus"]) is int and value["httpStatus"] == 0
                and value["transportOutcome"] == "connection_closed", "interrupted request returned HTTP or was retried")
    require(value["method"] == "POST" and value["path"] == "/api/v1/image-trust/verifications", "crash target changed")
    policy = info["policies"][0]
    for key in ("policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256", "trustedRootSHA256"):
        require(value[key] == policy[key], "crash original request material changed")
    digest(value["requestSHA256"])


def inspection(value, info, sequence, ledger, evidence):
    exact(value, ("authorization", "catalogue", "catalogueValid", "sequence", "ledgerCapacity", "ledgerUsed",
                  "ledgerRemaining", "consumptions"))
    require(value["authorization"] == "BLOCKED" and value["catalogueValid"] is True
            and type(value["sequence"]) is int and value["sequence"] == sequence, "offline crash sequence rejected")
    capacity = integer(value["ledgerCapacity"], 1, 1 << 20)
    used = int(ledger != "AVAILABLE")
    require(type(value["ledgerUsed"]) is int and value["ledgerUsed"] == used
            and type(value["ledgerRemaining"]) is int and value["ledgerRemaining"] == capacity - used,
            "offline ledger tally rejected")
    catalogue = value["catalogue"]
    exact(catalogue, ("storeID", "generation", "sha256", "notBeforeUnix", "notAfterUnix", "rootKeyCount", "rootThreshold",
                      "approverCount", "grants", "policyFloors", "revokedKeyCount", "revokedApprovalCount", "revokedManifestCount"))
    require(catalogue["storeID"] == info["storeID"] and catalogue["sha256"] == info["catalogueSHA256"], "offline catalogue changed")
    for key,wanted in {"generation":1,"rootKeyCount":1,"rootThreshold":1,"approverCount":1,
                       "revokedKeyCount":0,"revokedApprovalCount":0,"revokedManifestCount":0}.items():
        require(type(catalogue[key]) is int and catalogue[key] == wanted, "offline catalogue counters rejected")
    integer(catalogue["notBeforeUnix"], 1); integer(catalogue["notAfterUnix"], catalogue["notBeforeUnix"] + 1)
    policy = info["policies"][0]
    require(catalogue["policyFloors"] == {policy["policyID"]:1}
            and type(catalogue["policyFloors"][policy["policyID"]]) is int
            and isinstance(catalogue["grants"], list) and len(catalogue["grants"]) == 1, "original catalogue grant missing")
    grant = catalogue["grants"][0]
    exact(grant, ("id", "policyID", "approvalSHA256", "approverKeyID", "manifestSHA256", "revision"))
    require(grant["id"] == policy["grantID"] and grant["policyID"] == policy["policyID"]
            and grant["approvalSHA256"] == policy["approvalSHA256"] and grant["manifestSHA256"] == info["manifestSHA256"]
            and type(grant["revision"]) is int and grant["revision"] == 1, "offline grant payload changed")
    public_id(grant["approverKeyID"])
    consumed = [] if not used else [{"grantID": policy["grantID"], "policyID": policy["policyID"],
        "approvalSHA256": policy["approvalSHA256"], "manifestSHA256": info["manifestSHA256"], "generation":1,
        "catalogueSHA256":info["catalogueSHA256"], "status":ledger, "evidenceSHA256":evidence}]
    require(value["consumptions"] == consumed, "offline grant unburned, duplicated or evidence replaced")
    if used:
        require(type(value["consumptions"][0]["generation"]) is int, "offline generation type rejected")


def offline(value, info, stage, phase, original, probe=None):
    cut = phase == "cut"
    final = phase == "reopen-final"
    sequence = CUT_SEQUENCE[stage] if cut else 10 if final else RECOVERED_SEQUENCE[stage]
    ledger = ("AVAILABLE" if stage == "prepared" and not final else "RESERVED" if stage == "reserved" else "CONSUMED")
    expected_count = 2 if final else 1
    journal, bindings = value["journal"], value["auditBindings"]
    require(isinstance(journal, list) and isinstance(bindings, list)
            and len(journal) == len(bindings) == expected_count, "crash outbox matrix incomplete")
    audit = value["audit"]
    exact(audit, ("valid", "count", "expectedCount", "lastHash", "expectedLastHash", "verifiedAt"))
    scope = {"tenantId":"d12-tenant", "siteId":"d12-site", "objectType":"image-trust",
             "objectId":info["storeID"], "environment":"candidate"}
    scope_hash = "sha256:" + image.sha(encoded(scope, ordered=True))
    previous, events, identifiers, event_ids = ZERO, [], set(), set()
    evidence = ""
    for index,(entry,binding) in enumerate(zip(journal,bindings)):
        exact(entry, ("operation", "state", "outcome", "outcomeData", "acknowledged", "resultAuditHash", "grantID",
                      "generation", "catalogueSHA256", "manifestSHA256", "evidenceSHA256"))
        op = entry["operation"]
        exact(op, ("id", "actorID", "scopeSHA256", "kind", "data", "auditBaseCount", "auditBaseHash", "preparedAuditHash"))
        op_id = public_id(op["id"])
        request_value = original if index == 0 else probe
        require(request_value is not None and op_id not in identifiers and op["actorID"] == ACTOR
                and op["scopeSHA256"] == scope_hash and op["kind"] == "verify"
                and type(op["auditBaseCount"]) is int and op["auditBaseCount"] == index * 2
                and op["auditBaseHash"] == previous, "crash actual scope actor or audit prefix rejected")
        identifiers.add(op_id)
        data = {"policyId": request_value["policyID"], "approvalSHA256": request_value["approvalEnvelopeSHA256"],
                "bundleSHA256": request_value["bundleSHA256"], "rootSHA256": request_value["trustedRootSHA256"]}
        require(op["data"] == data, "crash journal original request mismatch")
        first = index == 0
        state = ("PREPARED" if stage == "prepared" else "RESERVED" if stage == "reserved" else "CONSUMED") if first else ("CONSUMED" if stage == "prepared" else "PREPARED")
        outcome = ("" if cut and stage != "consumed" else "INTERRUPTED" if stage == "prepared"
                   else "VERIFICATION_RESERVED_NOT_COMPLETED" if stage == "reserved" else "VERIFICATION_CONSUMED") if first else ("VERIFICATION_CONSUMED" if stage == "prepared" else "REJECTED")
        has_domain = state in {"RESERVED", "CONSUMED"}
        consumed = state == "CONSUMED"
        if consumed:
            digest(entry["evidenceSHA256"])
            evidence = entry["evidenceSHA256"]
        expected_data = {"grantId": info["policies"][0]["grantID"], "manifestSHA256": info["manifestSHA256"],
                         "catalogueSHA256": info["catalogueSHA256"]} if has_domain and outcome else {}
        if consumed:
            expected_data["evidenceSHA256"] = evidence
        expected_fields = {"state":state,"outcome":outcome,"outcomeData":expected_data,"acknowledged":not cut,
            "grantID":info["policies"][0]["grantID"] if has_domain else "", "generation":int(has_domain),
            "catalogueSHA256":info["catalogueSHA256"] if has_domain else "",
            "manifestSHA256":info["manifestSHA256"] if has_domain else "",
            "evidenceSHA256":evidence if consumed else ""}
        require(all(type(entry[key]) is type(wanted) and entry[key] == wanted for key,wanted in expected_fields.items()),
                "crash cut/recovery outcome acquired unjustified domain state")
        exact(binding, ("operationID", "prepared", "result"))
        require(binding["operationID"] == op_id, "crash audit binding operation mismatch")
        prepared_missing = cut and stage == "prepared"
        result_missing = cut
        target = "image-trust/" + info["storeID"]
        for phase_name,missing,event_data,result in (("prepared",prepared_missing,data,"prepared"),
            ("result",result_missing,expected_data,"interrupted" if outcome == "INTERRUPTED" else "verification_consumed" if consumed else "rejected")):
            event = binding[phase_name]
            if missing:
                require(event is None and (op["preparedAuditHash"] if phase_name == "prepared" else entry["resultAuditHash"]) == "",
                        "cut falsely claims missing audit append or ACK")
                continue
            lifecycle.audit_event(event, op, phase_name, previous, event_data, {"target":target,"result":result})
            require(event["id"] not in event_ids, "crash audit event ID reused")
            event_ids.add(event["id"])
            require(event["hash"] == (op["preparedAuditHash"] if phase_name == "prepared" else entry["resultAuditHash"]),
                    "crash actual audit hashes not bound to journal ACK")
            events.append(event); previous = event["hash"]
    inspection(value["inspection"], info, sequence, ledger, evidence)
    require(audit["valid"] is True and type(audit["count"]) is int and type(audit["expectedCount"]) is int
            and audit["count"] == audit["expectedCount"] == len(events)
            and audit["lastHash"] == audit["expectedLastHash"] == previous, "crash actual audit checkpoint rejected")
    lifecycle.event_time(audit["verifiedAt"])
    audit_prefix(value,events)
    return {"journal":journal,"bindings":bindings,"events":events,"evidence":evidence,
            "ledger":ledger,"sequence":sequence,"inspection":value["inspection"]}


def history_bindings(value, snapshot):
    by_id = history(value, snapshot["sequence"], len(snapshot["journal"]))
    for entry,binding in zip(snapshot["journal"],snapshot["bindings"]):
        op=entry["operation"]; row=by_id.get(op["id"])
        require(row is not None, "HTTP history lost recovered operation")
        expected={"state":entry["state"],"outcome":entry["outcome"],"grantId":entry["grantID"],
            "generation":entry["generation"],"catalogueSHA256":entry["catalogueSHA256"],
            "preparedAuditHash":op["preparedAuditHash"],"resultAuditHash":entry["resultAuditHash"],
            "policyId":op["data"]["policyId"],"preparedAtUnix":lifecycle.event_time(binding["prepared"]["occurredAt"]),
            "resultAtUnix":lifecycle.event_time(binding["result"]["occurredAt"])}
        require(all(type(row[key]) is type(wanted) and row[key]==wanted for key,wanted in expected.items()),
                "HTTP history differs from actual journal/audit event")
    return by_id


def action_sequence(reports, stage, kind, source, local_id, graph):
    require(set(reports)==set(actions(stage)), "crash action set incomplete")
    info=None
    for action in actions(stage):
        value=reports[action]
        extra=(OFFLINE_FIELDS if action in {"cut","reopen-first","reopen-final"} else
            ("status","history","auditLog","checkpoint") if action in {"ready","recovered","idempotent"} else
            ("status",) if action in {"blocked","reserved"} else ("request",) if action=="send" else ())
        exact(value,(*COMMON,*extra)); registry.boundary(value)
        require(value["schema"]=="chengwang.product-crash-action/v1" and value["action"]==action and value["stage"]==stage
                and value["boundary"]=="ADVISORY_PRODUCT_CRASH_FIXTURE" and value["authority"]=="EPHEMERAL_TEST_ONLY"
                and value["graphOrigin"]==registry.GRAPH_ORIGIN, "crash action protocol rejected")
        actual=material(value,stage,kind,source,local_id,graph)
        require(info is None or info==actual,"crash original material changed"); info=actual
        require(isinstance(value["cases"],list) and len(value["cases"])==int(action=="probe"),"unexpected crash business writes")
    original=reports["send"]["request"]; request(original,info,interrupted=True)
    probe=reports["probe"]["cases"][0]; wanted=200 if stage=="prepared" else 400
    exact(probe,(*registry.CASE_FIELDS,*(("receipt",) if wanted==200 else ())))
    request(probe,info,interrupted=False)
    require(probe["name"]=="probe-original" and type(probe["httpStatus"]) is int and probe["httpStatus"]==wanted
            and probe["errorCode"]==("" if wanted==200 else "image_trust_invalid")
            and probe["stateMayHaveChanged"] is (wanted==400)
            and probe["requestSHA256"]==original["requestSHA256"],"probe was not exact original request or acquired false success")
    cut=offline(reports["cut"],info,stage,"cut",original)
    first=offline(reports["reopen-first"],info,stage,"reopen-first",original)
    final=offline(reports["reopen-final"],info,stage,"reopen-final",original,probe)
    before_op=cut["journal"][0]["operation"]; after_op=first["journal"][0]["operation"]
    require({key:val for key,val in before_op.items() if key!="preparedAuditHash"}
            =={key:val for key,val in after_op.items() if key!="preparedAuditHash"},"recovery replaced interrupted intent")
    require(first["events"][:len(cut["events"])]==cut["events"]
            and final["journal"][:1]==first["journal"] and final["bindings"][:1]==first["bindings"],
            "recovery or probe rewrote original audit/outbox prefix")
    require(cut["evidence"]==first["evidence"],"recovery regenerated consumed evidence")
    require(first["inspection"]["catalogue"]==cut["inspection"]["catalogue"]==final["inspection"]["catalogue"]
            and first["inspection"]["consumptions"]==cut["inspection"]["consumptions"],
            "recovery replayed domain mutation or unburned grant")
    status(reports["ready"]["status"],info,1,"AVAILABLE",0,0)
    history(reports["ready"]["history"],1,0); audit_prefix(reports["ready"],[])
    blocked_ledger="AVAILABLE" if stage=="prepared" else "RESERVED" if stage=="reserved" else "CONSUMED"
    status(reports["blocked"]["status"],info,CUT_SEQUENCE[stage],blocked_ledger,1,0)
    if stage=="consumed": status(reports["reserved"]["status"],info,4,"RESERVED",1,0)
    for action,recovery in (("recovered",1),("idempotent",0)):
        value=reports[action]
        status(value["status"],info,RECOVERED_SEQUENCE[stage],first["ledger"],1,recovery)
        history_bindings(value["history"],first); audit_prefix(value,first["events"])
    status(probe["statusBefore"],info,RECOVERED_SEQUENCE[stage],first["ledger"],1,0)
    history_bindings(probe["historyBefore"],first)
    status(probe["statusAfter"],info,10,final["ledger"],2,0)
    history_bindings(probe["historyAfter"],final)
    if wanted==200:
        receipt=probe["receipt"]
        exact(receipt,("boundary","authorization","deviceActionsExecuted","verified","grantId","catalogueSHA256",
                       "generation","manifestSHA256","evidenceSHA256"))
        require(receipt=={"boundary":"ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND","authorization":"BLOCKED",
            "deviceActionsExecuted":False,"verified":True,"grantId":info["policies"][0]["grantID"],
            "catalogueSHA256":info["catalogueSHA256"],"generation":1,"manifestSHA256":info["manifestSHA256"],
            "evidenceSHA256":final["evidence"]} and type(receipt["generation"]) is int,"probe receipt not actual consumed fact")
    return info, {"cut":cut,"recovered":first,"final":final}


def parse_lock_line(value, *, waiter):
    require(isinstance(value,str) and len(value)<=512 and value.isascii(),"unsafe kernel lock record")
    # Preserve the kernel's arrow relationship instead of a reported boolean.
    pattern=r"\s*([1-9][0-9]*):\s+"+(r"->\s+" if waiter else "")+r"LEASE\s+(BREAKER|BREAKING|ACTIVE)\s+(READ|WRITE|UNLCK)\s+([1-9][0-9]*)\s+(<none>:0|[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9]+)\s+0\s+EOF\s*"
    match=re.fullmatch(pattern,value)
    require(match is not None,"kernel lease relationship record malformed")
    lock_id,state,target,pid,inode=match.groups()
    dev=None
    if inode!="<none>:0":
        major,minor,number=inode.split(":"); dev=(int(major,16),int(minor,16),int(number))
    return {"lockID":int(lock_id),"state":state,"target":target,"pid":int(pid),"device":dev}


LIMITS={"cpuSeconds":10,"addressSpaceBytes":268435456,"fileBytes":1048576,"openFiles":64,"processes":64,"coreBytes":0}
RUNTIME_PATHS=tuple("chengwang/deploy/product-candidate/"+name for name in (
    "check_product_crash.py","check_product_image.py","check_product_registry.py","check_product_lifecycle.py",
    "fixture_lease.py","fixture_blob_lease.py"))
HARNESS_PATHS=(*RUNTIME_PATHS,*("chengwang/deploy/product-candidate/"+name for name in (
    "test_fixture_blob_lease.py","test_crash_image_profile.py","test_check_product_crash.py")))
SUPPORT_NAMES=frozenset("product-crash-"+name+"-tests.log" for name in ("blob-lease","profile","verifier"))


def barriers(value, stage, kind, source, graph, cut, product_pid, registry_pid, harness):
    exact(value,("schema","sourceCommit","stage","kind","holders","waitRelations",*BOUNDARY)); registry.boundary(value)
    require(value["schema"]=="chengwang.product-crash-barriers/v1" and value["sourceCommit"]==source
            and value["stage"]==stage and value["kind"]==kind,"crash barrier origin rejected")
    types={"audit"} if stage=="prepared" else {"blob"} if stage=="reserved" else {"audit","blob"}
    holders,relations=value["holders"],value["waitRelations"]
    require(isinstance(holders,list) and isinstance(relations,list) and len(holders)==len(relations)==len(types),
            "crash barriers missing or duplicated")
    by_type={}; seen_pids=set()
    for holder in holders:
        exact(holder,("type","ready","blocked","released","process","releaseMonotonicNS"))
        role=holder["type"]
        require(role in types and role not in by_type,"crash helper role rejected")
        process=holder["process"]
        expected={"uid":10001,"gid":10001,"capabilities":"none","noNewPrivileges":True,"privateMountNamespace":True,
            "registryNetworkNamespaceMatched":True,"sourceLimits":LIMITS,"sourceLimitsVerified":True,"exitCode":0,"joined":True}
        exact(process,(*expected,"hostPID","startTime","sourceSHA256","pythonExecutableSHA256"))
        require(all(type(process[key]) is type(want) and process[key]==want for key,want in expected.items()),
                "crash helper actual sandbox or exit rejected")
        exact(process["sourceLimits"],LIMITS)
        require(all(type(process["sourceLimits"][key]) is int for key in LIMITS),"helper limits type rejected")
        pid=integer(process["hostPID"],1); start=integer(process["startTime"],1)
        integer(holder["releaseMonotonicNS"],1)
        require(pid not in seen_pids and pid not in {product_pid,registry_pid},"barrier actor identities conflated")
        seen_pids.add(pid)
        filename="fixture_lease.py" if role=="audit" else "fixture_blob_lease.py"
        require(process["sourceSHA256"]==harness["chengwang/deploy/product-candidate/"+filename],"lease helper not exact source")
        bare_hash(process["pythonExecutableSHA256"])
        baseline=None
        for label,event_name in (("ready","READY"),("blocked","BLOCKED"),("released","RELEASED")):
            event=holder[label]
            fields=("schema","event","case","kind","leaseBreakSeconds","deadlineSeconds","uid","gid","capNone",
                    "blockedObserved",*BOUNDARY)
            if role=="blob": fields=(*fields,"digest","leaseType","readOnlyBind","holderPID","holderStartTime",
                                    "deviceMajor","deviceMinor","inode","size")
            exact(event,fields); registry.boundary(event)
            require(event["schema"]==("chengwang.product-lifecycle-lease/v1" if role=="audit" else "chengwang.product-crash-blob-lease/v1")
                    and event["event"]==event_name and event["case"]==stage and event["kind"]==kind
                    and type(event["uid"]) is int and event["uid"]==10001 and type(event["gid"]) is int and event["gid"]==10001
                    and event["capNone"] is True and event["blockedObserved"] is (label!="ready"),"lease lifecycle not actually blocked/released")
            kernel=integer(event["leaseBreakSeconds"],10,3600)
            integer(event["deadlineSeconds"],1,min(kernel-2,120 if role=="audit" else 30))
            fixed={key:val for key,val in event.items() if key not in {"event","blockedObserved"}}
            require(baseline is None or baseline==fixed,"lease target or deadline changed"); baseline=fixed
            if role=="blob":
                require(event["leaseType"]=="WRITE" and event["readOnlyBind"] is True
                        and type(event["holderPID"]) is int and event["holderPID"]==pid
                        and type(event["holderStartTime"]) is int and event["holderStartTime"]==start
                        and event["digest"]==graph["configDescriptor"]["digest"]
                        and type(event["size"]) is int and event["size"]==graph["configDescriptor"]["size"],"blob alias not real config object")
                for key in ("deviceMajor","deviceMinor","inode"): integer(event[key],0 if key!="inode" else 1)
        by_type[role]=holder
    seen=set()
    for relation in relations:
        exact(relation,("type","target","holderPID","holderStartTime","waiterTGID","waiterStartTime","expectedAccess","samples"))
        role=relation["type"]; require(role in types and role not in seen,"wait relation role duplicate or wrong"); seen.add(role)
        holder=by_type[role]; process=holder["process"]; target=relation["target"]
        exact(target,("deviceMajor","deviceMinor","inode","size","digest"))
        for key in ("deviceMajor","deviceMinor","inode","size"): integer(target[key],1 if key=="inode" else 0)
        access="WRITE" if role=="audit" else "READ"
        require(type(relation["holderPID"]) is int and relation["holderPID"]==process["hostPID"]
                and type(relation["holderStartTime"]) is int and relation["holderStartTime"]==process["startTime"]
                and type(relation["waiterTGID"]) is int and relation["waiterTGID"]==(product_pid if role=="audit" else registry_pid)
                and relation["expectedAccess"]==access,"kernel wait actual actors mismatched")
        integer(relation["waiterStartTime"],1)
        expected_digest="sha256:"+cut["auditLog"]["sha256"] if role=="audit" else graph["configDescriptor"]["digest"]
        expected_size=cut["auditLog"]["bytes"] if role=="audit" else graph["configDescriptor"]["size"]
        require(target["digest"]==expected_digest and target["size"]==expected_size,"kernel wait target content not exact")
        if role=="blob":
            require(all(target[key]==holder["ready"][key] for key in ("deviceMajor","deviceMinor","inode","size")),"blob lease and kernel inode disagree")
        samples=relation["samples"]
        require(isinstance(samples,list) and len(samples)==2,"two stable kernel observations required")
        previous_ns=None
        for sample in samples:
            exact(sample,("lockID","holderState","holderTarget","waiterPID","waiterTarget","waiterHasInode","waiterTID",
                "syscallNumber","syscallName","openFlags","wchan","sameTargetPath","holderInodeMatched","waiterTGIDMatched",
                "monotonicNS","holderLockLine","waiterLockLine"))
            held=parse_lock_line(sample["holderLockLine"],waiter=False)
            waiting=parse_lock_line(sample["waiterLockLine"],waiter=True)
            require(type(sample["lockID"]) is int and held["lockID"]==waiting["lockID"]==sample["lockID"]
                    and held["state"]==sample["holderState"]=="BREAKING"
                    and held["target"]==sample["holderTarget"]==("UNLCK" if role=="audit" else "READ")
                    and waiting["state"]=="BREAKER" and waiting["target"]==sample["waiterTarget"]==access
                    and held["pid"]==relation["holderPID"]
                    and held["device"]==(target["deviceMajor"],target["deviceMinor"],target["inode"]),
                    "raw kernel lease holder/waiter edge not exact target")
            tid=integer(sample["waiterTID"],1); waiter=integer(sample["waiterPID"],1)
            require(waiting["pid"]==waiter and waiter in {relation["waiterTGID"],tid}
                    and type(sample["waiterHasInode"]) is bool and sample["waiterHasInode"] is (waiting["device"] is not None)
                    and (waiting["device"] is None or waiting["device"]==held["device"]),"kernel waiter not actual task or object")
            require(type(sample["syscallNumber"]) is int and sample["syscallNumber"]==257 and sample["syscallName"]=="openat"
                    and sample["sameTargetPath"] is True and sample["holderInodeMatched"] is True
                    and sample["waiterTGIDMatched"] is True,"blocked syscall path/identity not measured")
            flags=integer(sample["openFlags"],0,(1<<32)-1)
            require(flags&3==(1 if role=="audit" else 0) and not flags&(64|512|2048)
                    and (role!="audit" or flags&1024),"blocked open was nonblocking or wrong access")
            require(isinstance(sample["wchan"],str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,95}",sample["wchan"])
                    and sample["wchan"] not in {"running","0"},"no sleeping kernel wait channel")
            now=integer(sample["monotonicNS"],1)
            require(previous_ns is None or 5_000_000<=now-previous_ns<min(holder["ready"]["deadlineSeconds"],10)*1_000_000_000,
                    "kernel observations not stable bounded samples")
            previous_ns=now
        release=by_type[role]["releaseMonotonicNS"]
        require(release>previous_ns and release-previous_ns<by_type[role]["ready"]["deadlineSeconds"]*1_000_000_000,
                "lease released outside measured short barrier lifetime")
        if stage=="consumed" and role=="blob":
            require(release-previous_ns<3_000_000_000,"consumed handoff missed Registry response-header deadline")
    if stage=="consumed":
        audit_relation=next(x for x in relations if x["type"]=="audit")
        require(by_type["blob"]["releaseMonotonicNS"]<audit_relation["samples"][0]["monotonicNS"],
                "result audit barrier did not follow actual Registry release")
    return seen_pids


def runtime(projections, processes, killed, stage, kind, source, local_id, registry_id, binary_hash):
    labels=("running","killed","recovered-running","recovered-exited","idempotent-running","idempotent-exited")
    require(set(projections)==set(labels) and set(processes)=={"running","recovered-running","idempotent-running"},
            "three actual product starts or exits absent")
    expected={"boundary":"ISOLATED_PRODUCT_CANDIDATE","authorization":"BLOCKED","deviceActionsExecuted":False,
        "production":False,"sourceCommit":source,"localImageID":local_id,
        "imageIdentityKind":"LOCAL_DOCKER_CONFIG_ID_NOT_REGISTRY_MANIFEST","entrypoint":["/app/image-trust-api"],
        "user":"10001:10001","workdir":"/app","readOnlyRootfs":True,"capabilitiesDropped":"ALL",
        "noNewPrivileges":True,"networkIsolation":"shared_isolated_fixture","networkPeerContainerID":registry_id,
        "hostPorts":0,"bindMounts":{"privateReadOnly":True,"trustStateReadWrite":True,"productDataReadWrite":True},
        "memoryBytes":268435456,"memorySwapBytes":268435456,"nanoCPUs":1000000000,"pidsLimit":128,
        "nofile":1024,"restartPolicy":"no","stopTimeoutSeconds":15,"rawEnvironmentIncluded":False,"rawMountSourcesIncluded":False}
    ids=set(); starts=[]
    for label in labels:
        value=projections[label]; running=label in processes; abnormal=label=="killed"
        exact(value,(*expected,"containerID","state","pid","cleanExit","plannedSIGKILL","exitCode"))
        require(all(type(value[key]) is type(wanted) and value[key]==wanted for key,wanted in expected.items()),
                "crash runtime security projection rejected")
        exact(value["bindMounts"],expected["bindMounts"])
        require(all(v is True for v in value["bindMounts"].values()),"runtime mount types rejected")
        identifier=bare_hash(value["containerID"]); ids.add(identifier)
        require(value["state"]==("running" if running else "exited") and value["cleanExit"] is (not running and not abnormal)
                and value["plannedSIGKILL"] is abnormal and type(value["exitCode"]) is int
                and value["exitCode"]==(137 if abnormal else 0),"planned137 confused with normal exit0")
        integer(value["pid"],1 if running else 0)
        if not running:
            require(value["pid"]==0,"exited product retains PID"); continue
        p=processes[label]
        exact(p,("schema",*BOUNDARY,"sourceCommit","localImageID","containerID","hostPID","namespacePID","startTime",
            "uid","gid","capabilities","noNewPrivileges","defaultProductEntrypoint","expectedConfigurationArguments","actualExecutableSHA256"))
        registry.boundary(p)
        require(p["schema"]=="chengwang.product-image-pid1/v1" and p["sourceCommit"]==source and p["localImageID"]==local_id
                and p["containerID"]==identifier and type(p["hostPID"]) is int and p["hostPID"]==value["pid"]
                and type(p["namespacePID"]) is int and p["namespacePID"]==1 and type(p["uid"]) is int and p["uid"]==10001
                and type(p["gid"]) is int and p["gid"]==10001 and p["capabilities"]=="none" and p["noNewPrivileges"] is True
                and p["defaultProductEntrypoint"] is True and p["expectedConfigurationArguments"] is True
                and p["actualExecutableSHA256"]==binary_hash,"actual three-start PID1 executable identity rejected")
        starts.append((p["hostPID"],integer(p["startTime"],1)))
    require(len(ids)==1 and len(set(starts))==3,"product restart replaced container or reused process identity")
    initial=processes["running"]; identifier=next(iter(ids))
    expected_kill={"schema":"chengwang.product-crash-kill/v1","sourceCommit":source,"localImageID":local_id,
        "containerID":identifier,"stage":stage,"kind":kind,"hostPID":initial["hostPID"],"startTime":initial["startTime"],
        "signal":"SIGKILL","signalNumber":9,"pidfd":True,"identityVerified":True,"clientPendingBeforeSignal":True,
        "exitCode":137,"oomKilled":False,"pid":0,**BOUNDARY}
    exact(killed,(*expected_kill,"lastBlockMonotonicNS","signalMonotonicNS"))
    require(all(type(killed[key]) is type(wanted) and killed[key]==wanted for key,wanted in expected_kill.items()),
            "actual planned kill identity, HTTP pending or state rejected")
    before=integer(killed["lastBlockMonotonicNS"],1); after=integer(killed["signalMonotonicNS"],before)
    require(after-before<=2_000_000_000,"kill missed short in-flight deadline")
    return identifier


WINDOWS=("prepare","drain","recover","idempotent","probe")


def traffic_counts(row):
    # Unlike the older success-only gate, an interrupted config response may
    # complete with one non-200 server status. Its exact budget is checked below.
    require(isinstance(row["digestRequests"],list) and len(row["digestRequests"])<=256
            and isinstance(row["otherRequests"],list) and len(row["otherRequests"])<=64,"crash counter budget exceeded")
    result={}
    for records,is_digest in ((row["digestRequests"],True),(row["otherRequests"],False)):
        for value in records:
            exact(value,("method","digest","status","count") if is_digest else ("method","status","count"))
            require(value["method"] in ({"GET","HEAD"} if is_digest else {"GET","HEAD","POST","PATCH","PUT","DELETE","OPTIONS"}),
                    "crash counter method rejected")
            integer(value["status"],100,599); integer(value["count"],1,10000)
            if is_digest: digest(value["digest"])
            key=(value["method"],value.get("digest",""),value["status"])
            require(key not in result,"duplicate crash counter"); result[key]=value["count"]
    return result


def sdk_budget(graph):
    wanted={("GET",graph["registryManifestDigest"],200):2,("HEAD",graph["registryManifestDigest"],200):4}
    for desc in [graph["configDescriptor"],*graph["layerDescriptors"]]:
        wanted[("GET",desc["digest"],200)]=1; wanted[("HEAD",desc["digest"],200)]=2
    return wanted


def original_budget(stage,graph,before,after):
    delta={key:after.get(key,0)-before.get(key,0) for key in after if after.get(key,0)!=before.get(key,0)}
    if stage=="prepared": require(not delta,"prepared interruption reached Registry"); return
    if stage=="consumed": require(delta==sdk_budget(graph),"consumed interruption did not perform exactly one SDK read"); return
    manifest=graph["registryManifestDigest"]; config=graph["configDescriptor"]["digest"]
    required={("GET",manifest,200):1,("HEAD",manifest,200):2}
    require(all(delta.get(key)==count for key,count in required.items()),"reserved original manifest budget changed")
    tail={key:count for key,count in delta.items() if key not in required}
    require(all(key[1]==config and key[0] in {"GET","HEAD"} for key in tail),"reserved request read layer/unbound object or wrote Registry")
    for method in ("GET","HEAD"):
        require(sum(count for key,count in tail.items() if key[0]==method)<=1,"reserved config method repeated")
    require(sum(count for key,count in tail.items() if key[2]!=200)<=1,"multiple interrupted config errors")
    if any(key[0]=="GET" for key in tail): require(tail.get(("HEAD",config,200))==1,"config GET lacked completed successful HEAD")


def observations(value, source, local_id, graphs):
    exact(value,("schema","sourceCommit","localImageID","registryContainerID","pinnedRegistryImage",*BOUNDARY,"snapshots"))
    registry.boundary(value)
    require(value["schema"]=="chengwang.product-crash-observations/v1" and value["sourceCommit"]==source
            and value["localImageID"]==local_id and value["pinnedRegistryImage"]==registry.REGISTRY_IMAGE,"crash Registry identity rejected")
    registry_id=bare_hash(value["registryContainerID"])
    rows=value["snapshots"]; expected=[(stage,kind,window,position) for stage in STAGES for kind in KINDS
                                     for window in WINDOWS for position in ("before","after")]
    require(isinstance(rows,list) and len(rows)==len(expected)==60,"crash Registry windows incomplete")
    previous={}; counters={}; previous_step=None
    for ordinal,(row,step) in enumerate(zip(rows,expected),1):
        exact(row,("ordinal","stage","kind","window","position","digestRequests","otherRequests"))
        require(type(row["ordinal"]) is int and row["ordinal"]==ordinal
                and (row["stage"],row["kind"],row["window"],row["position"])==step,"crash Registry observation order rejected")
        current=traffic_counts(row)
        graph=graphs[(step[0],step[1])]
        allowed={graph["registryManifestDigest"],graph["configDescriptor"]["digest"],*(x["digest"] for x in graph["layerDescriptors"])}
        require(all(not key[1] or key[1] in allowed for key in current)
                and all(current.get(key,0)>=count for key,count in previous.items()),"unbound object or decreasing counter")
        if ordinal==1: require(not current,"crash Registry initial traffic hidden")
        # prepare->drain includes the original request, including its unfinished
        # callback. All other gaps must be exactly quiescent.
        if step[3]=="before" and ordinal>1 and not(step[2]=="drain" and previous_step[2]=="prepare"):
            require(current==previous,"unobserved crash Registry traffic gap")
        counters[step]=current; previous=current; previous_step=step
    zeros=successes=0
    for stage in STAGES:
        for kind in KINDS:
            graph=graphs[(stage,kind)]
            original_budget(stage,graph,counters[(stage,kind,"prepare","after")],counters[(stage,kind,"drain","after")])
            for window in WINDOWS:
                before=counters[(stage,kind,window,"before")]; after=counters[(stage,kind,window,"after")]
                delta={key:after.get(key,0)-before.get(key,0) for key in after if after.get(key,0)!=before.get(key,0)}
                if window=="prepare":
                    wanted={("GET",graph["registryManifestDigest"],200):1,("POST","",202):len(graph["layerDescriptors"])+1,
                            ("PUT","",201):len(graph["layerDescriptors"])+2}
                    for desc in [graph["configDescriptor"],*graph["layerDescriptors"]]: wanted[("GET",desc["digest"],200)]=1
                    require(delta==wanted,"crash preparation upload/readback budget changed")
                elif window in {"recover","idempotent"} or window=="probe" and stage!="prepared":
                    require(not delta,"recovery repeated SDK or burned-grant probe reached Registry"); zeros+=1
                elif window=="probe":
                    require(delta==sdk_budget(graph),"prepared probe not actual one-time SDK consumption"); successes+=1
                # drain records the original in-flight request tail. It is not
                # a recovery zero-window nor successful API receipt.
    return registry_id,counters,{"snapshotCount":60,"zeroRequestWindows":zeros,"successfulPreparedProbes":successes}


def drain(value, stage, kind, source, row, counters):
    exact(value,("schema","sourceCommit","stage","kind","samples",*BOUNDARY)); registry.boundary(value)
    require(value["schema"]=="chengwang.product-crash-drain/v1" and value["sourceCommit"]==source
            and value["stage"]==stage and value["kind"]==kind and isinstance(value["samples"],list)
            and len(value["samples"])==2,"Registry drain observation missing")
    expected_hash=image.sha(encoded({"digestRequests":row["digestRequests"],"otherRequests":row["otherRequests"]}))
    previous_ns=None
    for ordinal,sample in enumerate(value["samples"],1):
        exact(sample,("ordinal","activeConnections","targetOpenFDs","pendingLeases","completedRequests","countersSHA256","monotonicNS"))
        require(type(sample["ordinal"]) is int and sample["ordinal"]==ordinal
                and all(type(sample[key]) is int and sample[key]==0 for key in ("activeConnections","targetOpenFDs","pendingLeases"))
                and type(sample["completedRequests"]) is int and sample["completedRequests"]==sum(counters.values())
                and sample["countersSHA256"]==expected_hash,"old Registry request not drained or counter baseline disconnected")
        now=integer(sample["monotonicNS"],1)
        require(previous_ns is None or 150_000_000<=now-previous_ns<=5_000_000_000,"drain observations not bounded/stable")
        previous_ns=now


def expected_tests(raw):
    tree=ast.parse(raw.decode("utf-8")); classes={node.name:node for node in tree.body if isinstance(node,ast.ClassDef)}
    derived=set(); methods={}
    for _ in range(len(classes)+1):
        for name,node in classes.items():
            parents=[base.id for base in node.bases if isinstance(base,ast.Name) and base.id in derived]
            direct=any(isinstance(base,ast.Attribute) and isinstance(base.value,ast.Name)
                and base.value.id=="unittest" and base.attr=="TestCase" for base in node.bases)
            if direct or parents:
                derived.add(name)
                methods[name]=set().union(*(methods.get(parent,set()) for parent in parents))|{
                    child.name for child in node.body if isinstance(child,ast.FunctionDef) and child.name.startswith("test_")}
    return {name+"."+method for name in derived for method in methods[name]}


def test_transcript(raw, source, marker, count):
    require(0<len(raw)<=1<<20 and b"\x1b" not in raw,"unsafe test transcript")
    wanted=expected_tests(source)
    require(len(wanted)==count,"crash test source count changed")
    found=set(); summary=[]; successes=markers=0
    for line in raw.decode("utf-8").splitlines():
        if not line.strip() or re.fullmatch(r"-{5,}",line): continue
        match=re.fullmatch(r"(test_[A-Za-z0-9_]+) \(__main__\.([A-Za-z0-9_]+)\.(test_[A-Za-z0-9_]+)\) \.\.\. ok",line)
        if match:
            first,cls,method=match.groups(); name=cls+"."+method
            require(first==method and name in wanted and name not in found,"unexpected or repeated named test")
            found.add(name)
        elif match:=re.fullmatch(r"Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s",line): summary.append(int(match.group(1)))
        elif line=="OK": successes+=1
        elif line==marker: markers+=1
        else: raise CheckError("crash suite contains skipped, failed or unexpected output")
    require(found==wanted and summary==[count] and successes==markers==1,"crash named test transcript incomplete")
    return {"tests":count,"passed":count,"skipped":0,"transcriptSHA256":image.sha(raw),
            "testSourceSHA256":image.sha(source),"namedTestsSHA256":image.sha(("\n".join(sorted(found))+"\n").encode())}


def own_names():
    result={"product-crash-"+name+".json" for name in (
        "harness","network","isolation","registry-process","observations","runtime-cleanup","outcome")}
    for stage in STAGES:
        for kind in KINDS:
            result.update(report_name(stage,kind,action) for action in actions(stage))
            prefix="product-crash-"+stage+"-"+kind+"-"
            result.update(prefix+label+".json" for label in ("graph","barriers","kill","drain"))
            result.update(prefix+label+"-inspect.json" for label in ("running","killed","recovered-running","recovered-exited","idempotent-running","idempotent-exited"))
            result.update(prefix+label+"-pid1.json" for label in ("running","recovered-running","idempotent-running"))
    require(len(result)==147,"internal crash expected set changed")
    return result


def registry_process(value, source, registry_id):
    expected={"schema":"chengwang.product-crash-registry-process/v1","sourceCommit":source,
        "registryContainerID":registry_id,"namespacePID":1,"uid":10001,"gid":10001,"capabilities":"none",
        "noNewPrivileges":True,**BOUNDARY}
    exact(value,(*expected,"hostPID","startTime","actualExecutableSHA256"))
    require(all(type(value[key]) is type(want) and value[key]==want for key,want in expected.items()),"Registry actual PID1 identity rejected")
    integer(value["hostPID"],1); integer(value["startTime"],1); bare_hash(value["actualExecutableSHA256"])
    return value["hostPID"],value["startTime"]


VERIFIER_TEST_COUNT=27


def verify(args):
    require(registry.COMMIT.fullmatch(args.source_commit) is not None,"crash source commit rejected")
    directory=image.checked_path(args.evidence_dir,directory=True); source=args.source_commit
    loaded={}; hashes={}
    def load(name, *, binary=False):
        value=registry.read_file(directory/name,4<<20); hashes[name]=image.sha(value)
        if binary: loaded[name]=value; return value
        decoded=image.decode(value); require(isinstance(decoded,dict),"crash evidence object required")
        loaded[name]=decoded; return decoded
    staging=load("product-image-staging.json"); packaged=load("product-image-packaged-contents.json")
    require(staging.get("sourceCommit")==source and staging.get("authorization")=="BLOCKED"
            and staging.get("deviceActionsExecuted") is False and staging.get("imageBuilt") is False
            and staging.get("imageExecuted") is False and isinstance(staging.get("binary"),dict),"outer product source boundary changed")
    binary_hash=bare_hash(staging["binary"].get("sha256")); local_id=digest(packaged.get("localImageID"))
    require(staging["binary"].get("sourceCommit")==source and staging["binary"].get("sourceModified") is False,
            "actual static binary source not bound")
    require(packaged.get("schema")=="chengwang.product-image-packaged-content/v1" and packaged.get("sourceCommit")==source
            and packaged.get("authorization")=="BLOCKED" and packaged.get("production") is False
            and packaged.get("registryManifestDigestVerified") is False and packaged.get("configDigestMatched") is True
            and packaged.get("secretsPackaged") is False and packaged.get("rawArchivePublished") is False,"packaged image roles rejected")
    files,contexts=packaged.get("files"),staging.get("contextFiles")
    require(isinstance(files,dict) and files.get("app/image-trust-api",{}).get("sha256")==binary_hash
            and files["app/image-trust-api"].get("bytes")==staging["binary"].get("bytes")
            and isinstance(contexts,dict) and "Dockerfile" in contexts
            and {name.removeprefix("rootfs/"):value for name,value in contexts.items() if name!="Dockerfile"}
            =={name:value["sha256"] for name,value in files.items()},"static binary or packaged source bytes changed")
    harness=load("product-crash-harness.json")
    exact(harness,("schema","sourceCommit","files","checkoutBytesMatched","permissionReadOnly",*BOUNDARY)); registry.boundary(harness)
    require(harness["schema"]=="chengwang.product-crash-harness/v1" and harness["sourceCommit"]==source
            and harness["checkoutBytesMatched"] is True and harness["permissionReadOnly"] is True
            and isinstance(harness["files"],dict) and set(harness["files"])==set(HARNESS_PATHS),"crash helper/test source set rejected")
    for name,wanted in harness["files"].items():
        bare_hash(wanted)
        require(image.sha(registry.read_file(pathlib.Path(__file__).with_name(pathlib.PurePosixPath(name).name),256<<10))==wanted,
                "running crash helper/test differs from exact bound source")
    suites={}
    for label,test_name,count,marker in (
        ("blob-lease","test_fixture_blob_lease.py",14,"D12_BLOB_LEASE_TESTS=PASS tests=14 passed=14 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none readonly_file_bind=true"),
        ("profile","test_crash_image_profile.py",6,"D12_CRASH_IMAGE_PROFILE_TESTS=PASS tests=6 skipped=0 synthetic_only=true"),
        ("verifier","test_check_product_crash.py",VERIFIER_TEST_COUNT,"PRODUCT_CRASH_VERIFIER_TESTS=PASS synthetic_only=true tests="+str(VERIFIER_TEST_COUNT)+" skipped=0")):
        suites[label]=test_transcript(load("product-crash-"+label+"-tests.log",binary=True),
            registry.read_file(pathlib.Path(__file__).with_name(test_name),256<<10),marker,count)
    graphs={}; packaged_raw=registry.read_file(directory/"product-image-packaged-contents.json",4<<20)
    for stage in STAGES:
        for kind in KINDS:
            graph=load(report_name(stage,kind,"graph")); registry.graph_projection(graph,source,local_id,packaged_raw)
            require([x["diffID"] for x in graph["layerDescriptors"]]==packaged["layerDiffIDs"]
                    and graph["packagedFileCount"]==packaged["packagedFileCount"]
                    and binary_hash not in {local_id[7:],graph["registryManifestDigest"][7:]},"binary/config/manifest identities conflated")
            graphs[(stage,kind)]=graph
    require(all(value==next(iter(graphs.values())) for value in graphs.values()),"six cells did not verify identical image graph")
    observed=load("product-crash-observations.json"); registry_id,counters,traffic=observations(observed,source,local_id,graphs)
    isolation=load("product-crash-isolation.json"); network=load("product-crash-network.json")
    registry.registry_isolation(isolation,network,source,registry_id)
    require(isolation["actualImageID"]!=local_id,"Registry and product identities reused")
    registry_pid,registry_start=registry_process(load("product-crash-registry-process.json"),source,registry_id)
    products=set(); helper_ids=set(); infos=[]; cells={}
    for stage in STAGES:
        for kind in KINDS:
            reports={action:load(report_name(stage,kind,action)) for action in actions(stage)}
            info,facts=action_sequence(reports,stage,kind,source,local_id,graphs[(stage,kind)]); infos.append(info)
            projection={label:load(report_name(stage,kind,label+"-inspect")) for label in
                ("running","killed","recovered-running","recovered-exited","idempotent-running","idempotent-exited")}
            processes={label:load(report_name(stage,kind,label+"-pid1")) for label in ("running","recovered-running","idempotent-running")}
            killed=load(report_name(stage,kind,"kill"))
            products.add(runtime(projection,processes,killed,stage,kind,source,local_id,registry_id,binary_hash))
            barriers_value=load(report_name(stage,kind,"barriers"))
            helper_ids.update(barriers(barriers_value,stage,kind,source,graphs[(stage,kind)],reports["cut"],
                processes["running"]["hostPID"],registry_pid,harness["files"]))
            max_block=max(sample["monotonicNS"] for relation in barriers_value["waitRelations"] for sample in relation["samples"])
            require(max_block==killed["lastBlockMonotonicNS"],"kill not bound to last actual kernel wait")
            for relation in barriers_value["waitRelations"]:
                require(relation["waiterStartTime"]==(processes["running"]["startTime"] if relation["type"]=="audit" else registry_start),
                        "kernel waiter PID reused with different start time")
            for holder in barriers_value["holders"]:
                if not(stage=="consumed" and holder["type"]=="blob"):
                    require(holder["releaseMonotonicNS"]>killed["signalMonotonicNS"],"barrier released before actual cut")
            drain_row=next(row for row in observed["snapshots"] if (row["stage"],row["kind"],row["window"],row["position"])==(stage,kind,"drain","after"))
            drain(load(report_name(stage,kind,"drain")),stage,kind,source,drain_row,counters[(stage,kind,"drain","after")])
            cells[stage+"/"+kind]={"cutSequence":facts["cut"]["sequence"],"recoveredSequence":facts["recovered"]["sequence"],
                "finalSequence":10,"finalJournalEntries":2,"finalAuditEntries":4,"finalLedgerState":facts["final"]["ledger"],
                "originalPOSTSucceeded":False,"probeHTTPStatus":200 if stage=="prepared" else 400}
    require(len(products)==6 and registry_id not in products and len(helper_ids)==8
            and len({info["storeID"] for info in infos})==6 and len({info["policies"][0]["grantID"] for info in infos})==6
            and len({info["policies"][0]["trustedRootSHA256"] for info in infos})==6,"independent six-cell stores/authorities/containers not proven")
    cleanup=load("product-crash-runtime-cleanup.json")
    # Exact cleanup schema is kept separate from all earlier gate cleanups.
    expected_cleanup={"schema":"chengwang.product-crash-cleanup/v1","sourceCommit":source,"localImageID":local_id,
        "ownedContainersRemoved":7,"ownedHelpersJoined":8,"helperExitCodes":[0]*8,"ownedSendersJoined":6,
        "senderExitCodes":[0]*6,"privateFixtureRemoved":True,
        "outerProductImagePreserved":True,"registryImagePreserved":True,"outcome":"PASS",**BOUNDARY}
    exact(cleanup,expected_cleanup)
    require(all(type(cleanup[key]) is type(wanted) and cleanup[key]==wanted for key,wanted in expected_cleanup.items())
            and all(type(code) is int for code in [*cleanup["helperExitCodes"],*cleanup["senderExitCodes"]]),"exact owned crash cleanup not proven")
    expected=own_names(); present={p.name for p in directory.iterdir() if p.name.startswith("product-crash-")}
    require(expected-{"product-crash-outcome.json"}<=present and present<=expected|SUPPORT_NAMES,"unknown/stale/missing crash evidence")
    require(set(loaded)==expected-{"product-crash-outcome.json"}|SUPPORT_NAMES|{"product-image-staging.json","product-image-packaged-contents.json"}
            and len(hashes)==151,"crash evidence relation set changed")
    result={"schema":"chengwang.product-crash-gate/v1","outcome":"PASS",**BOUNDARY,"sourceCommit":source,"localImageID":local_id,
        "registryManifestDigest":next(iter(graphs.values()))["registryManifestDigest"],"binarySHA256":binary_hash,
        "authority":"EPHEMERAL_TEST_ONLY","graphBytesOrigin":registry.GRAPH_ORIGIN,"signatureKinds":list(KINDS),"stages":list(STAGES),
        "actualProductInterruptionRecoveryProven":True,"plannedSIGKILLs":6,"normalProductStops":12,"sameContainerThreeStarts":True,
        "recoveryCompletedFirstStart":1,"recoveryCompletedSecondStart":0,"recoveryRegistryZeroWindows":12,
        "registryCounterSnapshots":traffic["snapshotCount"],"successfulPreparedProbes":traffic["successfulPreparedProbes"],
        "originalRequestRegistryBudgetsVerified":True,
        "totalZeroRequestWindows":traffic["zeroRequestWindows"],"cells":cells,"testSuites":suites,"cleanupVerified":True,
        "completeCrashMatrixProven":False,"physicalPowerLossProven":False,"diskFailureRecoveryProven":False,
        "recoveryAuthorized":False,"releaseAuthorized":False,"privateGraphDownloadedByReviewer":False,
        "productImagePublishedOutsideIsolatedRegistry":False,"evidenceSHA256":dict(sorted(hashes.items()))}
    existing=directory/"product-crash-outcome.json"
    if existing.exists() or existing.is_symlink():
        value,_=registry.json_file(existing)
        require(encoded(value)==encoded(result),"existing crash outcome differs from independent replay")
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest="command",required=True)
    graph=sub.add_parser("graph")
    for name in ("graph-dir","packaged-report","report"): graph.add_argument("--"+name,type=pathlib.Path,required=True)
    for name in ("source-commit","manifest-digest"): graph.add_argument("--"+name,required=True)
    inspect=sub.add_parser("inspect")
    for name in ("image-inspect","container-inspect","report"): inspect.add_argument("--"+name,type=pathlib.Path,required=True)
    for name in ("image-id","source-commit","expected-private-source","expected-state-source","expected-network-mode"):
        inspect.add_argument("--"+name,required=True)
    inspect.add_argument("--container-status",choices=("running","exited"),required=True)
    inspect.add_argument("--planned-sigkill",action="store_true")
    verify_parser=sub.add_parser("verify")
    for name in ("evidence-dir","report"): verify_parser.add_argument("--"+name,type=pathlib.Path,required=True)
    verify_parser.add_argument("--source-commit",required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=="graph": result=registry.graph(args)
        elif args.command=="inspect":
            require(re.fullmatch(r"container:[a-f0-9]{64}",args.expected_network_mode),"crash product namespace rejected")
            image_value=image.one_inspect(registry.read_file(args.image_inspect,8<<20))
            container=image.one_inspect(registry.read_file(args.container_inspect,8<<20))
            result=image.inspect_projection(image_value,container,image_id=args.image_id,source=args.source_commit,
                private=args.expected_private_source,state=args.expected_state_source,network=args.expected_network_mode,
                status=args.container_status,fixture_kind="product-crash",planned_sigkill=args.planned_sigkill)
            result.update(production=False,networkPeerContainerID=args.expected_network_mode.removeprefix("container:"),
                          plannedSIGKILL=args.planned_sigkill,exitCode=container["State"]["ExitCode"])
        else: result=verify(args)
        image.write_exclusive(args.report,encoded(result)+b"\n")
    except (OSError,CheckError,ValueError,TypeError,KeyError,AttributeError,OverflowError):
        print("PRODUCT_CRASH_CHECK=FAIL rejected=true raw_input_suppressed=true",file=sys.stderr); return 1
    print("PRODUCT_CRASH_CHECK=PASS mode="+args.command+" authorization=BLOCKED production=false"); return 0


if __name__=="__main__": raise SystemExit(main())
