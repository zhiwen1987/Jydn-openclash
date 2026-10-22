"""Synthetic D12 evidence rejection tests, never real image/TLS acceptance."""
from __future__ import annotations

import argparse
import contextlib
import copy
import datetime
import hashlib
import io
import json
import pathlib
import tempfile
import unittest

import check_product_lifecycle as check
import test_check_product_registry as graph_fixture

SOURCE = "a" * 40
NOW = 1700000000


def raw(value, *, ordered=False):
    return json.dumps(value, sort_keys=not ordered, separators=(",", ":"), ensure_ascii=False).encode()


def h(label):
    return hashlib.sha256(label.encode()).hexdigest()


def d(label):
    return "sha256:" + h(label)


def stamp(second):
    return datetime.datetime.fromtimestamp(second, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def material(kind, graph):
    return {"kind": kind, "sourceCommit": SOURCE, "localImageID": graph["localImageID"],
        "manifestSHA256": graph["registryManifestDigest"], "configSHA256": graph["localImageID"],
        "layerSHA256s": [v["digest"] for v in graph["layerDescriptors"]],
        "diffIDs": [v["diffID"] for v in graph["layerDescriptors"]],
        "catalogue1SHA256": d(kind + "-catalogue1"), "catalogue2SHA256": d(kind + "-catalogue2"),
        "storeID": h(kind + "-store")[:32], "feedURL": "https://feed.fixture.invalid:5444/feed",
        "feedSPKI": d("source-spki"), "feedCASHA256": d("source-ca"),
        "refreshIntervalSeconds": 2, "refreshMaxAgeSeconds": 15, "refreshTimeoutSeconds": 2,
        "policies": [{"name": name, "policyID": "d12-" + name, "grantID": kind + "-grant-" + name,
            "approvalSHA256": d(kind + "-approval-" + name),
            "approvalEnvelopeSHA256": d(kind + "-envelope-" + name),
            "bundleSHA256": d(kind + "-bundle"), "bundleArtifactSHA256": graph["registryManifestDigest"],
            "trustedRootSHA256": d(kind + "-root"), "registrySPKI": d("registry-spki")}
            for name in ("a", "b", "c")]}


def event(op, phase, previous, data, result, store_id, index):
    value = {"id": "evt-1700000000000-" + format(index, "024x"),
        "idempotencyKey": "image-trust/" + op["id"] + "/" + phase,
        "traceId": op["id"], "actorId": op["actorID"], "action": "image_trust." + op["kind"],
        "target": "image-trust/" + store_id, "result": result, "occurredAt": stamp(NOW + index)}
    if data:
        value["data"] = dict(sorted(data.items()))
    value["previousHash"] = previous
    value["hash"] = ""
    value["hash"] = hashlib.sha256(raw(value, ordered=True)).hexdigest()
    return value


def operation_corpus(info):
    """The seven expected durable facts, independent of checker stage tables."""
    scope = {"tenantId": "d12-tenant", "siteId": "d12-site", "objectType": "image-trust",
             "objectId": info["storeID"], "environment": "candidate"}
    scope_hash = "sha256:" + hashlib.sha256(raw(scope, ordered=True)).hexdigest()
    definitions = [(None, None), ("a", True), ("a", False), ("b", False),
                   ("a", False), ("c", True), ("c", False)]
    journal, bindings, history = [], [], []
    previous = "0" * 64
    for index, (name, success) in enumerate(definitions):
        policy = next((p for p in info["policies"] if p["name"] == name), None)
        data = ({"catalogueSHA256": info["catalogue2SHA256"]} if policy is None else {
            "policyId": policy["policyID"], "approvalSHA256": policy["approvalEnvelopeSHA256"],
            "bundleSHA256": policy["bundleSHA256"], "rootSHA256": policy["trustedRootSHA256"]})
        op = {"id": format(index + 1, "032x"), "actorID": "image-trust-refresh" if index == 0 else "d12-admin",
            "scopeSHA256": scope_hash, "kind": "update" if index == 0 else "verify", "data": data,
            "auditBaseCount": index * 2, "auditBaseHash": previous, "preparedAuditHash": ""}
        prepared = event(op, "prepared", previous, data, "prepared", info["storeID"], index * 2 + 1)
        op["preparedAuditHash"] = prepared["hash"]
        evidence = d(info["kind"] + "-receipt-" + name) if success else ""
        outcome_data = ({"catalogueSHA256": info["catalogue2SHA256"]} if name is None else {
            "grantId": policy["grantID"], "manifestSHA256": info["manifestSHA256"],
            "catalogueSHA256": info["catalogue2SHA256"], "evidenceSHA256": evidence} if success else {})
        result = event(op, "result", prepared["hash"], outcome_data,
                       "completed" if name is None else "verification_consumed" if success else "rejected",
                       info["storeID"], index * 2 + 2)
        entry = {"operation": op, "state": "COMMITTED" if name is None else "CONSUMED" if success else "PREPARED",
            "outcome": "CATALOGUE_COMMITTED" if name is None else "VERIFICATION_CONSUMED" if success else "REJECTED",
            "outcomeData": outcome_data, "acknowledged": True, "resultAuditHash": result["hash"],
            "grantID": policy["grantID"] if success else "", "generation": 2 if name is None or success else 0,
            "catalogueSHA256": info["catalogue2SHA256"] if name is None or success else "",
            "manifestSHA256": info["manifestSHA256"] if success else "", "evidenceSHA256": evidence}
        journal.append(entry)
        bindings.append({"operationID": op["id"], "prepared": prepared, "result": result})
        history.append({"operationId": op["id"], "actorId": op["actorID"], "kind": op["kind"],
            "state": entry["state"], "outcome": entry["outcome"], "acknowledged": True,
            "policyId": policy["policyID"] if policy else "", "grantId": entry["grantID"],
            "generation": entry["generation"], "catalogueSHA256": entry["catalogueSHA256"],
            "preparedAuditHash": prepared["hash"], "resultAuditHash": result["hash"],
            "preparedAtUnix": NOW + index * 2 + 1, "resultAtUnix": NOW + index * 2 + 2})
        previous = result["hash"]
    return journal, bindings, history


def snapshot(info, history_rows, state, epoch, label, observed, last=0):
    seq, generation, consumed, count = state
    policies = [{"policyId": p["policyID"], "grantId": p["grantID"], "revision": 1,
                 "manifestSHA256": info["manifestSHA256"],
                 "state": "CONSUMED" if p["name"] == "a" and consumed >= 1 or p["name"] == "c" and consumed >= 2 else "AVAILABLE"}
                for p in info["policies"] if generation == 1 or p["name"] != "b"]
    status = {"boundary": "ADVISORY_TRUST_POLICY_STATE", "authorization": "BLOCKED", "deviceActionsExecuted": False,
        "healthy": True, "fresh": True, "storeId": info["storeID"], "generation": generation,
        "catalogueSHA256": info["catalogue%dSHA256" % generation], "notAfterUnix": NOW + 10000,
        "sequence": seq, "ledgerEntries": consumed, "ledgerCapacity": 100, "reserved": 0, "consumed": consumed,
        "revokedKeys": 0, "revokedApprovals": int(generation == 2), "revokedManifests": 0, "policies": policies,
        "refreshRequired": True, "refreshFresh": bool(last and observed < last + 15),
        "refreshLastSuccessUnix": last, "refreshUntilUnix": last + 15 if last else 0,
        "recoveryCompleted": 0, "observedAtUnix": observed, "auditVerifiedAtUnix": observed}
    history = {"boundary": "ADVISORY_TRUST_OPERATION_HISTORY", "authorization": "BLOCKED", "deviceActionsExecuted": False,
        "observedAtUnix": observed, "sequence": seq, "total": count, "offset": 0, "limit": 50,
        "entries": copy.deepcopy(history_rows[:count])}
    return {"name": label, "feedEpoch": epoch, "status": status, "history": history}


def action_fixture(info):
    journal, bindings, histories = operation_corpus(info)
    # action, number, before state, after state, before epoch, after epoch,
    # observation time, confirmed-source time, POST name/policy/status.
    flow = [
        ("exercise",1,(1,1,0,0),(1,1,0,0),1,1,0,0,("unconfirmed","a",503)),
        ("exercise",2,(1,1,0,0),(5,2,0,1),1,2,1,1,None),
        ("exercise",3,(5,2,0,1),(5,2,0,1),2,2,3,3,None),
        ("exercise",4,(5,2,0,1),(10,2,1,2),2,2,4,3,("a-success","a",200)),
        ("exercise",5,(10,2,1,2),(14,2,1,3),2,2,5,3,("a-replay","a",400)),
        ("exercise",6,(14,2,1,3),(18,2,1,4),2,2,6,3,("b-revoked","b",400)),
        ("exercise",7,(18,2,1,4),(18,2,1,4),2,3,19,3,("stale","c",503)),
        ("exercise",8,(18,2,1,4),(18,2,1,4),3,4,21,21,None),
        ("exercise",9,(18,2,1,4),(18,2,1,4),4,5,22,21,None),
        ("resume",1,(18,2,1,4),(18,2,1,4),5,5,23,0,("cold-unconfirmed","c",503)),
        ("resume",2,(18,2,1,4),(18,2,1,4),5,6,24,24,None),
        ("resume",3,(18,2,1,4),(22,2,1,5),6,6,25,24,("a-replay-after-restart","a",400)),
        ("resume",4,(22,2,1,5),(27,2,2,6),6,6,26,24,("c-success","c",200)),
        ("resume",5,(27,2,2,6),(31,2,2,7),6,6,27,24,("c-replay","c",400)),
        ("resume",6,(31,2,2,7),(31,2,2,7),6,7,28,24,None),
    ]

    def report(action, number):
        return {"schema": "chengwang.product-lifecycle-action/v1", "action": action, "case": number,
            **copy.deepcopy(info), "authority": "EPHEMERAL_TEST_ONLY", "graphOrigin": "NORMAL_TLS_REGISTRY_READBACK_MATCHED_UPLOAD",
            "authorization": "BLOCKED", "production": False, "deviceActionsExecuted": False,
            "cases": [], "observations": [], "feedPlans": [], "journalAuditBindingsVerified": False}

    def plan(epoch, code):
        body = info["catalogue2SHA256"][7:] if code == 200 else ""
        contents = {"schema": "chengwang.product-lifecycle-feed-plan/v1", "epoch": epoch,
                    "responses": {"latest.json": {"status": code, "bodySHA256": body}}}
        return {"epoch": epoch, "status": code, "bodySHA256": body, "sha256": hashlib.sha256(raw(contents)).hexdigest()}

    reports = {("prepare", 0): report("prepare", 0)}
    reports[("prepare", 0)]["feedPlans"] = [plan(1, 503)]
    previous_time, previous_last = NOW, 0
    for action, number, before, after, old_epoch, new_epoch, observed, last, post in flow:
        r = report(action, number)
        if (action, number) == ("resume", 1):
            previous_last = 0
        b = snapshot(info, histories, before, old_epoch, "before", previous_time, previous_last)
        a = snapshot(info, histories, after, new_epoch, "after", NOW + observed, NOW + last if last else 0)
        r["observations"] = [b, a]
        if old_epoch != new_epoch:
            r["feedPlans"] = [plan(new_epoch, 200 if new_epoch in (2,4,6) else 503)]
        if post:
            name, policy_name, code = post
            p = next(p for p in info["policies"] if p["name"] == policy_name)
            pb = a if name == "stale" else b
            case = {"name": name, "method": "POST", "path": "/api/v1/image-trust/verifications",
                "httpStatus": code, "errorCode": "" if code == 200 else "image_trust_invalid" if code == 400 else "image_trust_unavailable",
                "stateMayHaveChanged": code == 400, "policyID": p["policyID"], "grantID": p["grantID"],
                **{field: p[field] for field in ("approvalSHA256","approvalEnvelopeSHA256","bundleSHA256","trustedRootSHA256")},
                "requestSHA256": d(info["kind"] + "-request-" + policy_name),
                "statusBefore": copy.deepcopy(pb["status"]), "statusAfter": copy.deepcopy(a["status"]),
                "historyBefore": copy.deepcopy(pb["history"]), "historyAfter": copy.deepcopy(a["history"])}
            if code == 200:
                case["receipt"] = {"boundary": "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND", "authorization": "BLOCKED",
                    "deviceActionsExecuted": False, "verified": True, "grantId": p["grantID"],
                    "catalogueSHA256": info["catalogue2SHA256"], "generation": 2,
                    "manifestSHA256": info["manifestSHA256"], "evidenceSHA256": d(info["kind"] + "-receipt-" + policy_name)}
            r["cases"] = [case]
        reports[(action, number)] = r
        previous_time, previous_last = NOW + observed, NOW + last if last else 0
    for phase, state, count, names in (("first", (18,2,1,4),4,("a",)), ("final", (31,2,2,7),7,("a","c"))):
        r = report("reopen-" + phase, 0)
        r["journalAuditBindingsVerified"] = True
        r["journal"], r["auditBindings"] = copy.deepcopy(journal[:count]), copy.deepcopy(bindings[:count])
        r["audit"] = {"valid": True, "count": count * 2, "expectedCount": count * 2,
            "lastHash": bindings[count-1]["result"]["hash"], "expectedLastHash": bindings[count-1]["result"]["hash"],
            "verifiedAt": stamp(NOW + 100)}
        catalogue = {"storeID": info["storeID"], "generation": 2, "sha256": info["catalogue2SHA256"],
            "notBeforeUnix": NOW - 100, "notAfterUnix": NOW + 10000, "rootKeyCount": 1, "rootThreshold": 1,
            "approverCount": 3, "policyFloors": {"d12-a":1,"d12-b":1,"d12-c":1},
            "revokedKeyCount":0,"revokedApprovalCount":1,"revokedManifestCount":0,
            "grants": [{"id":p["grantID"],"policyID":p["policyID"],"approvalSHA256":p["approvalSHA256"],
                "approverKeyID":"approver-"+p["name"],"manifestSHA256":info["manifestSHA256"],"revision":1}
                for p in info["policies"] if p["name"] != "b"]}
        consumptions = [{"grantID":p["grantID"],"policyID":p["policyID"],"approvalSHA256":p["approvalSHA256"],
            "manifestSHA256":info["manifestSHA256"],"generation":2,"catalogueSHA256":info["catalogue2SHA256"],
            "status":"CONSUMED","evidenceSHA256":d(info["kind"]+"-receipt-"+p["name"])}
            for p in info["policies"] if p["name"] in names]
        r["inspection"] = {"authorization":"BLOCKED","catalogue":catalogue,"catalogueValid":True,
            "sequence":state[0],"ledgerCapacity":100,"ledgerUsed":state[2],"ledgerRemaining":100-state[2],
            "consumptions":consumptions}
        reports[("reopen-"+phase,0)] = r
    return reports


class GraphCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        args, _, _ = graph_fixture.fixture(pathlib.Path(self.temp.name))
        self.graph = check.registry.graph(args)
        self.info = material("message-signature", self.graph)
        self.reports = action_fixture(self.info)

    def verify(self, reports=None):
        return check.action_sequence(self.reports if reports is None else reports, "message-signature", SOURCE,
                                     self.graph["localImageID"], self.graph)


class FlowTests(GraphCase):
    def test_complete_synthetic_flow_and_actual_audit_hashes(self):
        info, plans = self.verify()
        self.assertEqual(info, self.info)
        self.assertEqual(set(plans), set(range(1,8)))

    def test_missing_stage_and_unknown_report_field_are_rejected(self):
        for mutate in (lambda r: r.pop(("exercise",3)),
                       lambda r: r[("exercise",3)].update(manualConfirmation=True)):
            r = copy.deepcopy(self.reports); mutate(r)
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_manual_actor_cannot_replace_automatic_update(self):
        r = copy.deepcopy(self.reports)
        r[("exercise",2)]["observations"][1]["history"]["entries"][0]["actorId"] = "d12-admin"
        with self.assertRaises(check.CheckError): self.verify(r)

    def test_same_catalogue_noop_must_advance_real_freshness(self):
        r = copy.deepcopy(self.reports)
        r[("exercise",3)]["observations"][1]["status"]["refreshLastSuccessUnix"] = NOW+1
        r[("exercise",3)]["observations"][1]["status"]["refreshUntilUnix"] = NOW+16
        with self.assertRaises(check.CheckError): self.verify(r)

    def test_stale_can_have_a_later_last_success_but_must_expire(self):
        r = copy.deepcopy(self.reports)
        after = r[("exercise",7)]["observations"][1]["status"]
        after.update(refreshLastSuccessUnix=NOW+4,refreshUntilUnix=NOW+19)
        r[("exercise",7)]["cases"][0]["statusBefore"] = copy.deepcopy(after)
        r[("exercise",7)]["cases"][0]["statusAfter"] = copy.deepcopy(after)
        self.verify(r)

    def test_restart_cannot_inherit_confirmation(self):
        r = copy.deepcopy(self.reports)
        r[("resume",1)]["observations"][0]["status"].update(refreshLastSuccessUnix=NOW+21,refreshUntilUnix=NOW+36,refreshFresh=True)
        with self.assertRaises(check.CheckError): self.verify(r)

    def test_unknown_plan_bytes_and_bool_epoch_are_rejected(self):
        for field,value in (("sha256",h("wrong bytes")),("epoch",True)):
            r = copy.deepcopy(self.reports)
            r[("prepare",0)]["feedPlans"][0][field] = value
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_actual_audit_actor_payload_hash_and_prefix_tamper_are_rejected(self):
        for field,value in (("actorId","d12-admin"),("hash",h("fake")),("previousHash",h("fake"))):
            r = copy.deepcopy(self.reports)
            r[("reopen-final",0)]["auditBindings"][0]["prepared"][field] = value
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_replay_request_and_burned_grant_cannot_change(self):
        for mutate in (lambda r:r[("resume",3)]["cases"][0].update(requestSHA256=d("new request")),
                       lambda r:r[("reopen-final",0)]["inspection"]["consumptions"].clear()):
            r = copy.deepcopy(self.reports); mutate(r)
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_actual_post_snapshots_cannot_disagree_with_independent_observations(self):
        for side in ("statusBefore","statusAfter"):
            r=copy.deepcopy(self.reports)
            r[("exercise",4)]["cases"][0][side]["observedAtUnix"] += 1
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_source_tls_identity_cannot_be_registry_identity(self):
        r=copy.deepcopy(self.reports)
        for value in r.values(): value["feedSPKI"]=value["policies"][0]["registrySPKI"]
        with self.assertRaises(check.CheckError): self.verify(r)

    def test_nanosecond_audit_timestamp_preserves_go_original_hash_bytes(self):
        r=copy.deepcopy(self.reports)
        op=r[("reopen-final",0)]["journal"][0]["operation"]
        value=copy.deepcopy(r[("reopen-final",0)]["auditBindings"][0]["prepared"])
        value["occurredAt"]=value["occurredAt"].removesuffix("Z")+".123456789Z"
        ordered={key:value[key] for key in ("id","idempotencyKey","traceId","actorId","action","target","result","occurredAt")}
        ordered.update(data=dict(sorted(value["data"].items())),previousHash=value["previousHash"],hash="")
        value["hash"]=check.image.sha(raw(ordered,ordered=True))
        self.assertEqual(check.audit_event(value,op,"prepared","0"*64,op["data"],
            {"target":"image-trust/"+self.info["storeID"],"result":"prepared"}),NOW+1)


def source_fixture(info):
    plans = {p["epoch"]: p for report in action_fixture(info).values() for p in report["feedPlans"]}
    events = []
    # Deliberately non-monotonic epochs: callbacks complete, not begin, in this order.
    for epoch in (1,2,2,4,3,5,6,7):
        ok = plans[epoch]["status"] == 200
        events.append({"schema":"chengwang.product-lifecycle-feed-event/v1", "ordinal":len(events)+1,
            "epoch":epoch,"pathClass":"latest","generation":0,"status":200 if ok else 503,
            "bodySHA256":info["catalogue2SHA256"][7:] if ok else check.image.sha(check.ERROR_BODY),
            "bytes":500 if ok else len(check.ERROR_BODY),"tls":True,"authPresent":False,
            "reason":"ok" if ok else "planned-unavailable","sentComplete":True})
    return plans, events


def log_bytes(events):
    return b"".join(raw(row)+b"\n" for row in events)


def stop_windows(events, first=(5,5), final=None):
    payloads = [raw(row)+b"\n" for row in events]
    def endpoint(count):
        return {"eventCount":count,"sha256":check.image.sha(b"".join(payloads[:count]))}
    final = final if final is not None else (len(events),len(events))
    return [{"label":name,"before":endpoint(start),"after":endpoint(end)}
            for name,(start,end) in (("first",first),("final",final))]


def traffic_fixture(graph):
    counters, snapshots = {}, []
    def row(kind,action,number,position):
        snapshots.append({"ordinal":len(snapshots)+1,"kind":kind,"action":action,"case":number,"position":position,
            "digestRequests":[{"method":m,"digest":d,"status":s,"count":n} for (m,d,s),n in sorted(counters.items()) if d],
            "otherRequests":[{"method":m,"status":s,"count":n} for (m,d,s),n in sorted(counters.items()) if not d]})
    for kind in check.KINDS:
        for action,number in check.STAGES:
            row(kind,action,number,"before")
            delta = {}
            if action == "prepare":
                delta = {("GET",graph["registryManifestDigest"],200):1,("POST","",202):len(graph["layerDescriptors"])+1,
                         ("PUT","",201):len(graph["layerDescriptors"])+2}
                for desc in [graph["configDescriptor"],*graph["layerDescriptors"]]: delta[("GET",desc["digest"],200)] = 1
            elif (action,number) in (("exercise",4),("resume",4)):
                delta = {("GET",graph["registryManifestDigest"],200):2,("HEAD",graph["registryManifestDigest"],200):4}
                for desc in [graph["configDescriptor"],*graph["layerDescriptors"]]:
                    delta[("GET",desc["digest"],200)] = 1; delta[("HEAD",desc["digest"],200)] = 2
            for key,count in delta.items(): counters[key] = counters.get(key,0)+count
            row(kind,action,number,"after")
    return {"schema":"chengwang.product-lifecycle-observations/v1","sourceCommit":SOURCE,
        "localImageID":graph["localImageID"],"registryContainerID":"f"*64,
        "pinnedRegistryImage":check.registry.REGISTRY_IMAGE,**check.BOUNDARY,"snapshots":snapshots}


class SourceTests(GraphCase):
    def setUp(self):
        super().setUp()
        self.plans,self.events = source_fixture(self.info)

    def source(self,events=None,windows=None):
        events = self.events if events is None else events
        return check.source_events(log_bytes(events),self.plans,self.info,
                                   stop_windows(events) if windows is None else windows)

    def test_complete_source_gets_allow_completion_epoch_reordering(self):
        result = self.source()
        self.assertEqual(result["completedRequests"],8)
        self.assertEqual(result["incompleteResponsesDuringStop"],0)

    def test_incomplete_only_within_measured_stop_windows_and_never_positive_evidence(self):
        events = copy.deepcopy(self.events)
        events.append({**events[-1],"ordinal":9,"sentComplete":False,"bytes":0})
        result = self.source(events,stop_windows(events,final=(8,9)))
        self.assertEqual(result["completedRequests"],8)
        self.assertEqual(result["incompleteResponsesDuringStop"],1)
        events[0].update(sentComplete=False,bytes=0)
        with self.assertRaises(check.CheckError): self.source(events,stop_windows(events,first=(0,1),final=(8,9)))

    def test_incomplete_outside_window_and_nonzero_bytes_are_rejected(self):
        for change in ({"sentComplete":False,"bytes":0},{"sentComplete":False,"bytes":1}):
            events=copy.deepcopy(self.events); events[-1].update(change)
            with self.assertRaises(check.CheckError): self.source(events)
        events=copy.deepcopy(self.events); events[-1].update(sentComplete=False,bytes=1)
        with self.assertRaises(check.CheckError): self.source(events,stop_windows(events,final=(7,8)))

    def test_stop_prefix_hash_count_overlap_and_suffix_omission_are_rejected(self):
        variants=[]
        for edit in (lambda w:w[0]["before"].update(sha256="0"*64),
                     lambda w:w[0]["before"].update(eventCount=True),
                     lambda w:w[0]["before"].update(eventCount=0),
                     lambda w:w[0]["after"].update(eventCount=99),
                     lambda w:w[1].update(before=copy.deepcopy(w[0]["before"]))):
            windows=stop_windows(self.events,first=(4,6)); edit(windows); variants.append(windows)
        variants.append(stop_windows(self.events,final=(7,7)))
        for windows in variants:
            with self.assertRaises(check.CheckError): self.source(windows=windows)

    def test_source_missing_get_wrong_body_auth_tls_ordinal_and_truncation_are_rejected(self):
        for key,value in (("bodySHA256","0"*64),("authPresent",True),("tls",False),("ordinal",2),
                          ("reason","plan-invalid"),("status",200),("bytes",0)):
            events=copy.deepcopy(self.events); events[0][key]=value
            with self.assertRaises(check.CheckError): self.source(events)
        events=[{**e,"ordinal":n} for n,e in enumerate(self.events[1:],1)]
        with self.assertRaises(check.CheckError): self.source(events)
        with self.assertRaises(check.CheckError): check.source_events(log_bytes(self.events)[:-1],self.plans,self.info,[])

    def test_source_profile_actual_limits_identity_and_clean_join_required(self):
        helper=h("helper"); pid=200
        process={"schema":"chengwang.product-lifecycle-source/v1","sourceCommit":SOURCE,"kind":"message-signature",
            "sourceCase":"source","hostPID":pid,"uid":10001,"gid":10001,"capabilities":"none",
            "noNewPrivileges":True,"registryNetworkNamespaceMatched":True,"privateMountNamespace":True,
            "sourceSHA256":helper,"pythonExecutableSHA256":h("python"),"gitBoundSourceMatched":True,
            "sourceLimitsVerified":True,"sourceLimits":copy.deepcopy(check.SOURCE_LIMITS),**check.BOUNDARY}
        stopped={"schema":"chengwang.product-lifecycle-source-stop/v1","sourceCommit":SOURCE,"kind":"message-signature",
            "hostPID":pid,"signal":"SIGTERM","exitCode":0,"joined":True,**check.BOUNDARY,
            "productStopWindows":stop_windows(self.events)}
        ready={"schema":"chengwang.product-lifecycle-feed-ready/v1","port":5444,"pid":pid,"uid":10001,"gid":10001,
            "tls":True,"listenLoopback":True,"deadlineSeconds":300}
        self.assertEqual(check.source_process(process,stopped,ready,SOURCE,"message-signature",helper),pid)
        for target,key,value in ((process,"uid",0),(process,"capabilities","cap_net_admin"),
                                 (process,"sourceCase","refresh"),(process,"noNewPrivileges",False),
                                 (stopped,"exitCode",143),(ready,"tls",False)):
            modified=copy.deepcopy(target); modified[key]=value
            args=[process,stopped,ready]; args[[process,stopped,ready].index(target)]=modified
            with self.assertRaises(check.CheckError): check.source_process(*args,SOURCE,"message-signature",helper)


class TrafficTests(GraphCase):
    def test_independent_registry_72_snapshots_four_success_thirty_zero_windows(self):
        result=check.observations(traffic_fixture(self.graph),SOURCE,self.graph["localImageID"],dict.fromkeys(check.KINDS,self.graph))
        self.assertEqual((result["snapshotCount"],result["successfulImageReads"],result["zeroRequestWindows"]),(72,4,30))

    def test_registry_unconfirmed_reads_counter_gaps_missing_and_bool_case_rejected(self):
        for edit in (lambda v:v["snapshots"].pop(), lambda v:v["snapshots"][1].update(case=True),
                     lambda v:v["snapshots"][3]["otherRequests"].append({"method":"GET","status":200,"count":1}),
                     lambda v:v["snapshots"][2]["digestRequests"].clear()):
            value=traffic_fixture(self.graph); edit(value)
            with self.assertRaises(check.CheckError):
                check.observations(value,SOURCE,self.graph["localImageID"],dict.fromkeys(check.KINDS,self.graph))

    def test_registry_initial_unobserved_traffic_is_rejected(self):
        value=traffic_fixture(self.graph)
        # Add a constant pre-existing request to every sample: all deltas still
        # match, but the initial boundary must reject this hidden traffic.
        for snapshot in value["snapshots"]:
            snapshot["otherRequests"].append({"method":"GET","status":200,"count":1})
        with self.assertRaises(check.CheckError):
            check.observations(value,SOURCE,self.graph["localImageID"],dict.fromkeys(check.KINDS,self.graph))


def final_fixture(root):
    args, old = graph_fixture.synthetic_final_evidence(root)
    graph = old["product-registry-message-signature-graph.json"]
    values = {name:value for name,value in old.items() if name.startswith("product-image-")}
    for label in ("isolation","network"):
        values["product-lifecycle-"+label+".json"] = old["product-registry-"+label+".json"]
    values["product-lifecycle-observations.json"] = traffic_fixture(graph)
    values["product-lifecycle-observations.json"]["registryContainerID"] = old["product-registry-observations.json"]["registryContainerID"]
    values["product-lifecycle-harness.json"] = {"schema":"chengwang.product-lifecycle-harness/v1",
        "sourceCommit":SOURCE,"files":{name:check.image.sha(pathlib.Path(check.__file__).with_name(
            pathlib.PurePosixPath(name).name).read_bytes()) for name in check.HARNESS_PATHS},
        "checkoutBytesMatched":True,"permissionReadOnly":True,**check.BOUNDARY}
    for index,kind in enumerate(check.KINDS):
        prefix="product-lifecycle-"+kind+"-"
        info=material(kind,graph)
        values[prefix+"graph.json"]=graph
        for (action,number),report in action_fixture(info).items(): values[check.report_name(kind,action,number)]=report
        for label in ("running-inspect","exited-inspect","restarted-running-inspect","restarted-exited-inspect",
                      "running-pid1","restarted-running-pid1"):
            values[prefix+label+".json"]=old["product-registry-"+kind+"-"+label+".json"]
        _,events=source_fixture(info)
        values[prefix+"feed-events.jsonl"]=log_bytes(events)
        pid=200+index
        values[prefix+"source.json"]={"schema":"chengwang.product-lifecycle-source/v1","sourceCommit":SOURCE,
            "kind":kind,"sourceCase":"source","hostPID":pid,"uid":10001,"gid":10001,"capabilities":"none",
            "noNewPrivileges":True,"registryNetworkNamespaceMatched":True,"privateMountNamespace":True,
            "sourceSHA256":values["product-lifecycle-harness.json"]["files"][check.HARNESS_PATHS[0]],
            "pythonExecutableSHA256":h("python"),"gitBoundSourceMatched":True,"sourceLimitsVerified":True,
            "sourceLimits":copy.deepcopy(check.SOURCE_LIMITS),**check.BOUNDARY}
        values[prefix+"source-stop.json"]={"schema":"chengwang.product-lifecycle-source-stop/v1",
            "sourceCommit":SOURCE,"kind":kind,"hostPID":pid,"signal":"SIGTERM","exitCode":0,"joined":True,
            "productStopWindows":stop_windows(events),**check.BOUNDARY}
        values[prefix+"feed-ready.json"]={"schema":"chengwang.product-lifecycle-feed-ready/v1","port":5444,
            "pid":pid,"uid":10001,"gid":10001,"tls":True,"listenLoopback":True,"deadlineSeconds":300}
    values["product-lifecycle-runtime-cleanup.json"]={"schema":"chengwang.product-lifecycle-cleanup/v1",
        "sourceCommit":SOURCE,"localImageID":graph["localImageID"],"ownedContainersRemoved":3,
        "privateFixtureRemoved":True,"outerProductImagePreserved":True,"registryImagePreserved":True,
        "ownedSourcesJoined":2,"sourceExitCodes":[0,0],"outcome":"PASS",**check.BOUNDARY}
    for name,value in values.items(): graph_fixture.put(args.evidence_dir/name,value if isinstance(value,bytes) else raw(value))
    return args,values


class FullGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.args,self.values=final_fixture(pathlib.Path(self.temp.name))

    def mutate(self,name,edit):
        value=copy.deepcopy(self.values[name]); edit(value)
        graph_fixture.put(self.args.evidence_dir/name,raw(value))

    def test_complete_synthetic_64_file_gate_65_relations_and_existing_outcome_replay(self):
        result=check.verify(self.args)
        self.assertEqual(len(check.own_names()),64)
        self.assertEqual(len(result["evidenceSHA256"]),65)
        self.assertEqual(result["perCaseZeroRequestWindows"],30)
        self.assertFalse(result["completeCrashMatrixProven"])
        graph_fixture.put(self.args.evidence_dir/"product-lifecycle-outcome.json",raw(result))
        self.assertEqual(check.verify(self.args),result)
        self.mutate("product-lifecycle-runtime-cleanup.json",lambda v:v.update(sourceExitCodes=[0,143]))
        with self.assertRaises(check.CheckError): check.verify(self.args)

    def test_each_missing_own_input_is_rejected_even_with_preflight_cleanup(self):
        graph_fixture.put(self.args.evidence_dir/"product-lifecycle-cleanup.json",b'{"cleanup":true}')
        for name in sorted(check.own_names()-{"product-lifecycle-outcome.json"}):
            path=self.args.evidence_dir/name; data=path.read_bytes(); path.unlink()
            try:
                with self.subTest(name=name), self.assertRaises((check.CheckError,OSError)):
                    check.verify(self.args)
            finally: graph_fixture.put(path,data)

    def test_cleanup_exact_owned_container_source_count_and_exit_types_are_required(self):
        name="product-lifecycle-runtime-cleanup.json"
        for key,value in (("ownedContainersRemoved",4),("ownedSourcesJoined",1),("privateFixtureRemoved",False),
                          ("sourceExitCodes",[False,0]),("outerProductImagePreserved",False)):
            self.mutate(name,lambda v:v.update({key:value}))
            with self.subTest(key=key),self.assertRaises(check.CheckError): check.verify(self.args)

    def test_source_harness_pid1_restart_and_unknown_own_prefix_are_required(self):
        changes=(("product-lifecycle-harness.json",lambda v:v["files"].update({check.HARNESS_PATHS[0]:"0"*64})),
            ("product-lifecycle-message-signature-restarted-running-pid1.json",lambda v:v.update(actualExecutableSHA256="0"*64)),
            ("product-lifecycle-message-signature-restarted-exited-inspect.json",lambda v:v.update(containerID="0"*64)))
        for name,edit in changes:
            self.mutate(name,edit)
            try:
                with self.assertRaises(check.CheckError): check.verify(self.args)
            finally: graph_fixture.put(self.args.evidence_dir/name,raw(self.values[name]))
        graph_fixture.put(self.args.evidence_dir/"product-lifecycle-unknown.json",b"{}")
        with self.assertRaises(check.CheckError): check.verify(self.args)

    def test_cli_failure_suppresses_raw_input_and_never_writes_report(self):
        self.mutate("product-lifecycle-runtime-cleanup.json",lambda v:v.update(outcome="PRIVATE_SENTINEL"))
        error=io.StringIO(); output=io.StringIO()
        with contextlib.redirect_stderr(error),contextlib.redirect_stdout(output):
            code=check.main(["verify","--evidence-dir",str(self.args.evidence_dir),"--source-commit",SOURCE,
                             "--report",str(self.args.report)])
        self.assertEqual(code,1); self.assertFalse(self.args.report.exists())
        self.assertNotIn("PRIVATE_SENTINEL",error.getvalue()); self.assertNotIn("PASS",output.getvalue())

    def test_cli_success_only_writes_exclusive_safe_recomputed_report(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code=check.main(["verify","--evidence-dir",str(self.args.evidence_dir),"--source-commit",SOURCE,
                             "--report",str(self.args.report)])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(self.args.report.read_bytes())["outcome"],"PASS")
        with contextlib.redirect_stderr(io.StringIO()),contextlib.redirect_stdout(io.StringIO()):
            code=check.main(["verify","--evidence-dir",str(self.args.evidence_dir),"--source-commit",SOURCE,
                             "--report",str(self.args.report)])
        self.assertEqual(code,1)


if __name__ == "__main__":
    program=unittest.main(verbosity=2,exit=False)
    accepted=program.result.wasSuccessful() and not program.result.skipped and program.result.testsRun==27
    if accepted:
        print("PRODUCT_LIFECYCLE_VERIFIER_TESTS=PASS synthetic_only=true tests="+str(program.result.testsRun)+" skipped=0")
    raise SystemExit(0 if accepted else 1)
