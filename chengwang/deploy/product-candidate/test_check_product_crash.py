"""Synthetic crash evidence rejection tests; never actual product acceptance."""
from __future__ import annotations

import argparse
import copy
import contextlib
import io
import json
import pathlib
import tempfile
import unittest

import check_product_crash as check
import test_check_product_registry as graph_fixture
import test_check_product_lifecycle as event_fixture

SOURCE="a"*40
NOW=1700000000
raw=event_fixture.raw
h=event_fixture.h
d=event_fixture.d


def material(stage,kind,graph):
    label=stage+"-"+kind
    return {"kind":kind,"sourceCommit":SOURCE,"localImageID":graph["localImageID"],"configSHA256":graph["localImageID"],
        "manifestSHA256":graph["registryManifestDigest"],"layerSHA256s":[x["digest"] for x in graph["layerDescriptors"]],
        "diffIDs":[x["diffID"] for x in graph["layerDescriptors"]],"catalogueSHA256":d(label+"-catalogue"),"storeID":h(label)[:32],
        "policies":[{"name":"original","policyID":"d12-crash-"+stage,"grantID":h(label+"-grant")[:32],
            "approvalSHA256":d(label+"-approval"),"approvalEnvelopeSHA256":d(label+"-envelope"),
            "bundleSHA256":d(label+"-bundle"),"bundleArtifactSHA256":graph["registryManifestDigest"],
            "trustedRootSHA256":d(label+"-root"),"registrySPKI":d("registry")}]}


def snapshot(info,sequence,ledger,recovery=0):
    policy=info["policies"][0]
    return {"boundary":"ADVISORY_TRUST_POLICY_STATE","authorization":"BLOCKED","deviceActionsExecuted":False,
        "healthy":True,"fresh":True,"storeId":info["storeID"],"generation":1,"catalogueSHA256":info["catalogueSHA256"],
        "notAfterUnix":NOW+10000,"sequence":sequence,"ledgerEntries":int(ledger!="AVAILABLE"),"ledgerCapacity":4096,
        "reserved":int(ledger=="RESERVED"),"consumed":int(ledger=="CONSUMED"),"revokedKeys":0,"revokedApprovals":0,
        "revokedManifests":0,"policies":[{"policyId":policy["policyID"],"grantId":policy["grantID"],"revision":1,
            "manifestSHA256":info["manifestSHA256"],"state":ledger}],"refreshRequired":False,"refreshFresh":False,
        "refreshLastSuccessUnix":0,"refreshUntilUnix":0,"recoveryCompleted":recovery,"observedAtUnix":NOW+100,"auditVerifiedAtUnix":NOW+99}


def operation(info,index,previous,phase_state,outcome,ack,events_count):
    policy=info["policies"][0]; scope={"tenantId":"d12-tenant","siteId":"d12-site","objectType":"image-trust",
        "objectId":info["storeID"],"environment":"candidate"}
    data={"policyId":policy["policyID"],"approvalSHA256":policy["approvalEnvelopeSHA256"],
          "bundleSHA256":policy["bundleSHA256"],"rootSHA256":policy["trustedRootSHA256"]}
    op={"id":h(info["storeID"]+str(index))[:32],"actorID":"d12-crash-admin","scopeSHA256":"sha256:"+check.image.sha(raw(scope,ordered=True)),
        "kind":"verify","data":data,"auditBaseCount":index*2,"auditBaseHash":previous,"preparedAuditHash":""}
    domain=phase_state in {"RESERVED","CONSUMED"}; consumed=phase_state=="CONSUMED"
    evidence=d(info["storeID"]+"-evidence") if consumed else ""
    outcome_data={"grantId":policy["grantID"],"manifestSHA256":info["manifestSHA256"],"catalogueSHA256":info["catalogueSHA256"]} if domain and outcome else {}
    if consumed: outcome_data["evidenceSHA256"]=evidence
    prepared=event_fixture.event(op,"prepared",previous,data,"prepared",info["storeID"],index*2+1) if events_count else None
    if prepared: op["preparedAuditHash"]=prepared["hash"]
    result=event_fixture.event(op,"result",prepared["hash"],outcome_data,
        "interrupted" if outcome=="INTERRUPTED" else "verification_consumed" if consumed else "rejected",info["storeID"],index*2+2) if events_count==2 else None
    entry={"operation":op,"state":phase_state,"outcome":outcome,"outcomeData":outcome_data,"acknowledged":ack,
        "resultAuditHash":result["hash"] if ack else "","grantID":policy["grantID"] if domain else "","generation":int(domain),
        "catalogueSHA256":info["catalogueSHA256"] if domain else "","manifestSHA256":info["manifestSHA256"] if domain else "",
        "evidenceSHA256":evidence}
    binding={"operationID":op["id"],"prepared":prepared,"result":result}
    return entry,binding


def history(sequence,entries,bindings):
    rows=[]
    for entry,binding in zip(entries,bindings):
        op=entry["operation"]
        rows.append({"operationId":op["id"],"actorId":op["actorID"],"kind":"verify","state":entry["state"],
            "outcome":entry["outcome"],"acknowledged":True,"policyId":op["data"]["policyId"],"grantId":entry["grantID"],
            "generation":entry["generation"],"catalogueSHA256":entry["catalogueSHA256"],"preparedAuditHash":op["preparedAuditHash"],
            "resultAuditHash":entry["resultAuditHash"],"preparedAtUnix":check.lifecycle.event_time(binding["prepared"]["occurredAt"]),
            "resultAtUnix":check.lifecycle.event_time(binding["result"]["occurredAt"])})
    return {"boundary":"ADVISORY_TRUST_OPERATION_HISTORY","authorization":"BLOCKED","deviceActionsExecuted":False,
        "observedAtUnix":NOW+100,"sequence":sequence,"total":len(rows),"offset":0,"limit":50,"entries":rows}


def hashes(events):
    body=b"".join(check.event_bytes(event) for event in events)
    cp=raw({"count":len(events),"lastHash":events[-1]["hash"] if events else "0"*64},ordered=True)
    return {"auditLog":{"bytes":len(body),"sha256":check.image.sha(body)},
            "checkpoint":{"bytes":len(cp),"sha256":check.image.sha(cp)}}


def offline_fields(info,sequence,ledger,entries,bindings):
    policy=info["policies"][0]
    consumed=next((entry["evidenceSHA256"] for entry in entries if entry["state"]=="CONSUMED"),"")
    catalogue={"storeID":info["storeID"],"generation":1,"sha256":info["catalogueSHA256"],"notBeforeUnix":NOW-100,"notAfterUnix":NOW+10000,
        "rootKeyCount":1,"rootThreshold":1,"approverCount":1,"grants":[{"id":policy["grantID"],"policyID":policy["policyID"],
            "approvalSHA256":policy["approvalSHA256"],"approverKeyID":"approver","manifestSHA256":info["manifestSHA256"],"revision":1}],
        "policyFloors":{policy["policyID"]:1},"revokedKeyCount":0,"revokedApprovalCount":0,"revokedManifestCount":0}
    usage=[] if ledger=="AVAILABLE" else [{"grantID":policy["grantID"],"policyID":policy["policyID"],"approvalSHA256":policy["approvalSHA256"],
        "manifestSHA256":info["manifestSHA256"],"generation":1,"catalogueSHA256":info["catalogueSHA256"],"status":ledger,"evidenceSHA256":consumed}]
    events=[event for binding in bindings for event in (binding["prepared"],binding["result"]) if event is not None]
    tail=events[-1]["hash"] if events else "0"*64
    return {"inspection":{"authorization":"BLOCKED","catalogue":catalogue,"catalogueValid":True,"sequence":sequence,
            "ledgerCapacity":4096,"ledgerUsed":len(usage),"ledgerRemaining":4096-len(usage),"consumptions":usage},
        "journal":copy.deepcopy(entries),"auditBindings":copy.deepcopy(bindings),"audit":{"valid":True,"count":len(events),
            "expectedCount":len(events),"lastHash":tail,"expectedLastHash":tail,"verifiedAt":event_fixture.stamp(NOW+100)},**hashes(events)}


def action_fixture(stage,kind,graph):
    info=material(stage,kind,graph)
    reports={action:{"schema":"chengwang.product-crash-action/v1","action":action,"stage":stage,**copy.deepcopy(info),
        "boundary":"ADVISORY_PRODUCT_CRASH_FIXTURE","authority":"EPHEMERAL_TEST_ONLY","graphOrigin":check.registry.GRAPH_ORIGIN,
        **check.BOUNDARY,"cases":[]} for action in check.actions(stage)}
    policy=info["policies"][0]
    original={"method":"POST","path":"/api/v1/image-trust/verifications",**{key:policy[key] for key in (
        "policyID","grantID","approvalSHA256","approvalEnvelopeSHA256","bundleSHA256","trustedRootSHA256")},
        "requestSHA256":d(info["storeID"]+"request"),"attempts":1,"httpStatus":0,"transportOutcome":"connection_closed"}
    reports["send"]["request"]=original
    reports["ready"].update(status=snapshot(info,1,"AVAILABLE"),history=history(1,[],[]),**hashes([]))
    state="PREPARED" if stage=="prepared" else "RESERVED" if stage=="reserved" else "CONSUMED"
    cut_outcome="VERIFICATION_CONSUMED" if stage=="consumed" else ""
    cut_entry,cut_binding=operation(info,0,"0"*64,state,cut_outcome,False,0 if stage=="prepared" else 1)
    ledger="AVAILABLE" if stage=="prepared" else state
    reports["blocked"]["status"]=snapshot(info,check.CUT_SEQUENCE[stage],ledger)
    if stage=="consumed": reports["reserved"]["status"]=snapshot(info,4,"RESERVED")
    reports["cut"].update(offline_fields(info,check.CUT_SEQUENCE[stage],ledger,[cut_entry],[cut_binding]))
    outcome="INTERRUPTED" if stage=="prepared" else "VERIFICATION_RESERVED_NOT_COMPLETED" if stage=="reserved" else "VERIFICATION_CONSUMED"
    entry,binding=operation(info,0,"0"*64,state,outcome,True,2)
    reports["reopen-first"].update(offline_fields(info,check.RECOVERED_SEQUENCE[stage],ledger,[entry],[binding]))
    for action,recovery in (("recovered",1),("idempotent",0)):
        reports[action].update(status=snapshot(info,check.RECOVERED_SEQUENCE[stage],ledger,recovery),
            history=history(check.RECOVERED_SEQUENCE[stage],[entry],[binding]),**hashes([binding["prepared"],binding["result"]]))
    probe_entry,probe_binding=operation(info,1,binding["result"]["hash"],"CONSUMED" if stage=="prepared" else "PREPARED",
        "VERIFICATION_CONSUMED" if stage=="prepared" else "REJECTED",True,2)
    final_ledger="RESERVED" if stage=="reserved" else "CONSUMED"
    reports["reopen-final"].update(offline_fields(info,10,final_ledger,[entry,probe_entry],[binding,probe_binding]))
    probe={key:original[key] for key in original if key not in ("attempts","httpStatus","transportOutcome")}
    probe.update(name="probe-original",httpStatus=200 if stage=="prepared" else 400,errorCode="" if stage=="prepared" else "image_trust_invalid",
        stateMayHaveChanged=stage!="prepared",statusBefore=copy.deepcopy(reports["idempotent"]["status"]),
        historyBefore=copy.deepcopy(reports["idempotent"]["history"]),statusAfter=snapshot(info,10,final_ledger),
        historyAfter=history(10,[entry,probe_entry],[binding,probe_binding]))
    if stage=="prepared": probe["receipt"]={"boundary":"ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND","authorization":"BLOCKED",
        "deviceActionsExecuted":False,"verified":True,"grantId":policy["grantID"],"catalogueSHA256":info["catalogueSHA256"],
        "generation":1,"manifestSHA256":info["manifestSHA256"],"evidenceSHA256":probe_entry["evidenceSHA256"]}
    reports["probe"]["cases"]=[probe]
    return reports


class GraphCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        args,_,_=graph_fixture.fixture(pathlib.Path(self.temp.name)); self.graph=check.registry.graph(args)

    def verify(self,reports,stage="prepared",kind="message-signature"):
        return check.action_sequence(reports,stage,kind,SOURCE,self.graph["localImageID"],self.graph)


class FlowTests(GraphCase):
    def test_six_synthetic_cells_exact_cut_recovery_second_start_and_probe(self):
        for stage in check.STAGES:
            for kind in check.KINDS:
                _,facts=self.verify(action_fixture(stage,kind,self.graph),stage,kind)
                self.assertEqual(facts["final"]["sequence"],10)
                self.assertEqual(len(facts["final"]["events"]),4)

    def test_missing_action_unknown_fields_or_fake_success_are_rejected(self):
        for edit in (lambda r:r.pop("blocked"),lambda r:r["cut"].update(fake=True),
                     lambda r:r["send"]["request"].update(httpStatus=200),lambda r:r["send"]["request"].update(attempts=2)):
            r=action_fixture("prepared","message-signature",self.graph); edit(r)
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_recovery_must_not_inherit_completion_count_on_second_start(self):
        r=action_fixture("prepared","message-signature",self.graph); r["idempotent"]["status"]["recoveryCompleted"]=1
        with self.assertRaises(check.CheckError): self.verify(r)

    def test_wrong_cut_boundary_or_recovery_burn_is_rejected(self):
        for stage in check.STAGES:
            r=action_fixture(stage,"message-signature",self.graph)
            r["cut"]["inspection"]["sequence"]+=1
            with self.assertRaises(check.CheckError): self.verify(r,stage)
        r=action_fixture("reserved","message-signature",self.graph)
        r["reopen-first"]["inspection"]["consumptions"][0]["status"]="CONSUMED"
        with self.assertRaises(check.CheckError): self.verify(r,"reserved")

    def test_actual_audit_hash_actor_scope_and_request_binding_are_mandatory(self):
        for edit in (lambda r:r["reopen-first"]["auditBindings"][0]["prepared"].update(actorId="other"),
                     lambda r:r["reopen-first"]["auditBindings"][0]["result"].update(hash="0"*64),
                     lambda r:r["reopen-first"]["journal"][0]["operation"].update(scopeSHA256=d("wrong")),
                     lambda r:r["probe"]["cases"][0].update(requestSHA256=d("newrequest"))):
            r=action_fixture("prepared","message-signature",self.graph); edit(r)
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_raw_prefix_and_checkpoint_are_recomputed_not_boolean_claims(self):
        for action,field in (("ready","auditLog"),("cut","checkpoint"),("idempotent","auditLog"),("reopen-final","auditLog")):
            r=action_fixture("prepared","message-signature",self.graph); r[action][field]["sha256"]="0"*64
            with self.assertRaises(check.CheckError): self.verify(r)

    def test_consumed_evidence_must_not_be_regenerated_or_unburned(self):
        r=action_fixture("consumed","message-signature",self.graph)
        r["reopen-first"]["inspection"]["consumptions"][0]["evidenceSHA256"]=d("forged")
        with self.assertRaises(check.CheckError): self.verify(r,"consumed")

    def test_reserved_or_consumed_probe_cannot_return_success(self):
        for stage in ("reserved","consumed"):
            r=action_fixture(stage,"message-signature",self.graph); r["probe"]["cases"][0]["httpStatus"]=200
            with self.assertRaises(check.CheckError): self.verify(r,stage)


def barrier_fixture(stage,kind,graph,reports,index=0):
    holders=[]; relations=[]; base=1_000_000_000
    roles=["audit"] if stage=="prepared" else ["blob"] if stage=="reserved" else ["blob","audit"]
    product_pid=100+index*10; registry_pid=90
    harness={name:check.image.sha(pathlib.Path(check.__file__).with_name(pathlib.PurePosixPath(name).name).read_bytes()) for name in check.HARNESS_PATHS}
    for ordinal,role in enumerate(roles):
        holder_pid=500+index*10+ordinal; start=300+index*10+ordinal
        first_ns=base+ordinal*500_000_000
        target={"deviceMajor":8,"deviceMinor":1,"inode":1000+index*10+ordinal,
            "size":reports["cut"]["auditLog"]["bytes"] if role=="audit" else graph["configDescriptor"]["size"],
            "digest":"sha256:"+reports["cut"]["auditLog"]["sha256"] if role=="audit" else graph["configDescriptor"]["digest"]}
        helper={"schema":"chengwang.product-lifecycle-lease/v1" if role=="audit" else "chengwang.product-crash-blob-lease/v1",
            "event":"READY","case":stage,"kind":kind,"leaseBreakSeconds":45,"deadlineSeconds":8,"uid":10001,"gid":10001,
            "capNone":True,"blockedObserved":False,**check.BOUNDARY}
        if role=="blob": helper.update(digest=target["digest"],leaseType="WRITE",readOnlyBind=True,holderPID=holder_pid,
            holderStartTime=start,**{key:target[key] for key in ("deviceMajor","deviceMinor","inode","size")})
        process={"hostPID":holder_pid,"startTime":start,"uid":10001,"gid":10001,"capabilities":"none","noNewPrivileges":True,
            "privateMountNamespace":True,"registryNetworkNamespaceMatched":True,"sourceLimits":copy.deepcopy(check.LIMITS),
            "sourceLimitsVerified":True,"sourceSHA256":harness["chengwang/deploy/product-candidate/"+("fixture_lease.py" if role=="audit" else "fixture_blob_lease.py")],
            "pythonExecutableSHA256":h("python"),"exitCode":0,"joined":True}
        holders.append({"type":role,"ready":helper,"blocked":{**helper,"event":"BLOCKED","blockedObserved":True},
            "released":{**helper,"event":"RELEASED","blockedObserved":True},"process":process,
            "releaseMonotonicNS":first_ns+(100_000_000 if stage=="consumed" and role=="blob" else 2_000_000_000)})
        waiter=product_pid if role=="audit" else registry_pid; tid=waiter+2000
        access="WRITE" if role=="audit" else "READ"; target_mode="UNLCK" if role=="audit" else "READ"
        sample={"lockID":123,"holderState":"BREAKING","holderTarget":target_mode,"waiterPID":waiter,"waiterTarget":access,
            "waiterHasInode":False,"waiterTID":tid,"syscallNumber":257,"syscallName":"openat","openFlags":525313 if role=="audit" else 524288,
            "wchan":"break_lease","sameTargetPath":True,"holderInodeMatched":True,"waiterTGIDMatched":True,
            "holderLockLine":f'123: LEASE BREAKING {target_mode} {holder_pid} 08:01:{target["inode"]} 0 EOF',
            "waiterLockLine":f'123: -> LEASE BREAKER {access} {waiter} <none>:0 0 EOF',"monotonicNS":first_ns}
        relations.append({"type":role,"target":target,"holderPID":holder_pid,"holderStartTime":start,
            "waiterTGID":waiter,"waiterStartTime":200+index*10 if role=="audit" else 190,"expectedAccess":access,
            "samples":[sample,{**sample,"monotonicNS":first_ns+5_000_000}]})
    return {"schema":"chengwang.product-crash-barriers/v1","sourceCommit":SOURCE,"stage":stage,"kind":kind,
            "holders":holders,"waitRelations":relations,**check.BOUNDARY},harness


class KernelTests(GraphCase):
    def setUp(self):
        super().setUp(); self.stage="consumed"; self.kind="message-signature"
        self.reports=action_fixture(self.stage,self.kind,self.graph)
        self.value,self.harness=barrier_fixture(self.stage,self.kind,self.graph,self.reports)

    def kernel(self,value=None):
        return check.barriers(self.value if value is None else value,self.stage,self.kind,SOURCE,self.graph,self.reports["cut"],100,90,self.harness)

    def test_real_kernel_edge_projection_accepts_waiter_without_inode(self):
        self.assertEqual(len(self.kernel()),2)

    def test_blocked_marker_or_boolean_without_raw_kernel_relation_is_rejected(self):
        value=copy.deepcopy(self.value)
        for relation in value["waitRelations"]:
            for sample in relation["samples"]: sample.pop("waiterLockLine")
        with self.assertRaises(check.CheckError): self.kernel(value)

    def test_wrong_actor_inode_lockid_or_missing_arrow_is_rejected(self):
        for key,value in (("holderLockLine","123: LEASE BREAKING READ 500 08:01:9999 0 EOF"),
                          ("waiterLockLine","124: -> LEASE BREAKER READ 90 <none>:0 0 EOF"),
                          ("waiterLockLine","123: LEASE BREAKER READ 90 <none>:0 0 EOF"),("waiterPID",91)):
            changed=copy.deepcopy(self.value); changed["waitRelations"][0]["samples"][0][key]=value
            with self.assertRaises(check.CheckError): self.kernel(changed)

    def test_nonblocking_wrong_access_or_unstable_samples_are_rejected(self):
        for key,value in (("openFlags",524288|2048),("openFlags",524289),("syscallNumber",0),("wchan","running"),("monotonicNS",1)):
            changed=copy.deepcopy(self.value); changed["waitRelations"][0]["samples"][1][key]=value
            with self.assertRaises(check.CheckError): self.kernel(changed)

    def test_unsafe_helper_fake_release_or_consumed_handoff_order_is_rejected(self):
        for edit in (lambda v:v["holders"][0]["process"].update(capabilities="CAP_LEASE"),
                     lambda v:v["holders"][0]["process"].update(exitCode=137),
                     lambda v:v["holders"][0]["ready"].update(readOnlyBind=False),
                     lambda v:v["holders"][0].update(releaseMonotonicNS=4_000_000_000)):
            value=copy.deepcopy(self.value); edit(value)
            with self.assertRaises(check.CheckError): self.kernel(value)


def runtime_fixture(graph,stage,kind,index=0):
    # Reuse only a synthetic valid D11 security DTO, not any runtime evidence.
    with tempfile.TemporaryDirectory() as temporary:
        _,old=graph_fixture.synthetic_final_evidence(pathlib.Path(temporary))
    projections={}; processes={}; container=h(stage+kind)
    for label in ("running","killed","recovered-running","recovered-exited","idempotent-running","idempotent-exited"):
        running=label.endswith("running") or label=="running"
        source_label="running" if running else "exited"
        v=copy.deepcopy(old["product-registry-"+kind+"-"+source_label+"-inspect.json"])
        p=copy.deepcopy(old["product-registry-"+kind+"-running-pid1.json"])
        offset=0 if label in ("running","killed") else 1 if label.startswith("recovered") else 2
        pid=100+index*10+offset; start=200+index*10+offset
        v.update(containerID=container,pid=pid if running else 0,plannedSIGKILL=label=="killed",exitCode=137 if label=="killed" else 0,
            cleanExit=not running and label!="killed")
        projections[label]=v
        if running:
            p.update(containerID=container,hostPID=pid,startTime=start); processes[label]=p
    kill={"schema":"chengwang.product-crash-kill/v1","sourceCommit":SOURCE,"localImageID":graph["localImageID"],
        "containerID":container,"stage":stage,"kind":kind,"hostPID":100+index*10,"startTime":200+index*10,"signal":"SIGKILL",
        "signalNumber":9,"pidfd":True,"identityVerified":True,"clientPendingBeforeSignal":True,"lastBlockMonotonicNS":1_505_000_000 if stage=="consumed" else 1_005_000_000,
        "signalMonotonicNS":1_600_000_000,"exitCode":137,"oomKilled":False,"pid":0,**check.BOUNDARY}
    return projections,processes,kill


class RuntimeTests(GraphCase):
    def setUp(self):
        super().setUp(); self.projections,self.processes,self.kill=runtime_fixture(self.graph,"prepared","message-signature")
        self.registry_id=self.projections["running"]["networkPeerContainerID"]
        self.binary=self.processes["running"]["actualExecutableSHA256"]

    def runtime(self,projections=None,processes=None,kill=None):
        return check.runtime(self.projections if projections is None else projections,self.processes if processes is None else processes,
            self.kill if kill is None else kill,"prepared","message-signature",SOURCE,self.graph["localImageID"],self.registry_id,self.binary)

    def test_three_actual_starts_same_container_only_planned_kill_137(self): self.assertEqual(self.runtime(),h("preparedmessage-signature"))

    def test_wrong_container_process_identity_or_security_profile_rejected(self):
        for label,key,value in (("idempotent-running","containerID","0"*64),("running","readOnlyRootfs",False),
                              ("killed","exitCode",0),("recovered-exited","exitCode",137)):
            v=copy.deepcopy(self.projections); v[label][key]=value
            with self.assertRaises(check.CheckError): self.runtime(projections=v)
        p=copy.deepcopy(self.processes); p["running"]["startTime"]+=1
        with self.assertRaises(check.CheckError): self.runtime(processes=p)

    def test_kill_requires_pending_client_pidfd_nooom_and_short_deadline(self):
        for key,value in (("clientPendingBeforeSignal",False),("pidfd",False),("oomKilled",True),("signalMonotonicNS",9_000_000_000)):
            kill=copy.deepcopy(self.kill); kill[key]=value
            with self.assertRaises(check.CheckError): self.runtime(kill=kill)


def traffic_fixture(graph):
    rows=[]; counts={}
    for stage in check.STAGES:
        for kind in check.KINDS:
            for window in check.WINDOWS:
                for position in ("before","after"):
                    if position=="after":
                        delta={}
                        if window=="prepare":
                            delta={("GET",graph["registryManifestDigest"],200):1,("POST","",202):len(graph["layerDescriptors"])+1,
                                ("PUT","",201):len(graph["layerDescriptors"])+2}
                            for desc in [graph["configDescriptor"],*graph["layerDescriptors"]]: delta[("GET",desc["digest"],200)]=1
                        elif window=="probe" and stage=="prepared":
                            delta={("GET",graph["registryManifestDigest"],200):2,("HEAD",graph["registryManifestDigest"],200):4}
                            for desc in [graph["configDescriptor"],*graph["layerDescriptors"]]:
                                delta[("GET",desc["digest"],200)]=1; delta[("HEAD",desc["digest"],200)]=2
                        elif window=="drain" and stage=="reserved":
                            delta={("GET",graph["registryManifestDigest"],200):1,("HEAD",graph["registryManifestDigest"],200):2}
                        elif window=="drain" and stage=="consumed": delta=check.sdk_budget(graph)
                        for key,count in delta.items(): counts[key]=counts.get(key,0)+count
                    rows.append({"ordinal":len(rows)+1,"stage":stage,"kind":kind,"window":window,"position":position,
                        "digestRequests":[{"method":m,"digest":d,"status":s,"count":n} for (m,d,s),n in sorted(counts.items()) if d],
                        "otherRequests":[{"method":m,"status":s,"count":n} for (m,d,s),n in sorted(counts.items()) if not d]})
    with tempfile.TemporaryDirectory() as temporary:
        _,old=graph_fixture.synthetic_final_evidence(pathlib.Path(temporary))
    return {"schema":"chengwang.product-crash-observations/v1","sourceCommit":SOURCE,"localImageID":graph["localImageID"],
        "registryContainerID":old["product-registry-observations.json"]["registryContainerID"],
        "pinnedRegistryImage":check.registry.REGISTRY_IMAGE,"snapshots":rows,**check.BOUNDARY}


def drain_fixture(row):
    value={"schema":"chengwang.product-crash-drain/v1","sourceCommit":SOURCE,"stage":row["stage"],"kind":row["kind"],**check.BOUNDARY}
    count=sum(check.registry.traffic_counts(row).values()); digest=check.image.sha(raw({"digestRequests":row["digestRequests"],"otherRequests":row["otherRequests"]}))
    sample={"ordinal":1,"activeConnections":0,"targetOpenFDs":0,"pendingLeases":0,"completedRequests":count,
        "countersSHA256":digest,"monotonicNS":4_000_000_000}
    value["samples"]=[sample,{**sample,"ordinal":2,"monotonicNS":4_150_000_000}]
    return value


class TrafficTests(GraphCase):
    def setUp(self):
        super().setUp(); self.value=traffic_fixture(self.graph); self.graphs={(s,k):self.graph for s in check.STAGES for k in check.KINDS}

    def test_sixty_windows_twelve_recovery_zero_and_two_prepared_successes(self):
        _,_,result=check.observations(self.value,SOURCE,self.graph["localImageID"],self.graphs)
        self.assertEqual(result,{"snapshotCount":60,"zeroRequestWindows":16,"successfulPreparedProbes":2})

    def test_recovery_reads_hidden_counter_gap_or_missing_snapshot_rejected(self):
        for edit in (lambda v:v["snapshots"].pop(),lambda v:v["snapshots"][5]["otherRequests"].append({"method":"GET","status":200,"count":1}),
                     lambda v:v["snapshots"][2]["digestRequests"].clear()):
            value=copy.deepcopy(self.value); edit(value)
            with self.assertRaises(check.CheckError): check.observations(value,SOURCE,self.graph["localImageID"],self.graphs)
        reserved={("GET",self.graph["registryManifestDigest"],200):1,("HEAD",self.graph["registryManifestDigest"],200):2}
        check.original_budget("reserved",self.graph,{},reserved)
        config=self.graph["configDescriptor"]["digest"]
        check.original_budget("reserved",self.graph,{},dict(reserved,**{})|{("HEAD",config,200):1,("GET",config,499):1})
        for bad in (reserved|{("GET",self.graph["layerDescriptors"][0]["digest"],200):1},
                    reserved|{("GET",config,499):1},reserved|{("HEAD",config,500):2}):
            with self.assertRaises(check.CheckError): check.original_budget("reserved",self.graph,{},bad)
        with self.assertRaises(check.CheckError): check.original_budget("prepared",self.graph,{},reserved)
        with self.assertRaises(check.CheckError): check.original_budget("consumed",self.graph,{},reserved)

    def test_drain_requires_network_fd_lease_and_actual_counter_quiescence(self):
        row=self.value["snapshots"][3]; value=drain_fixture(row); count=check.registry.traffic_counts(row)
        check.drain(value,row["stage"],row["kind"],SOURCE,row,count)
        for key,target in (("activeConnections",1),("targetOpenFDs",1),("pendingLeases",1),("countersSHA256","0"*64),("monotonicNS",4_000_000_001)):
            changed=copy.deepcopy(value); changed["samples"][1][key]=target
            with self.assertRaises(check.CheckError): check.drain(changed,row["stage"],row["kind"],SOURCE,row,count)


def transcript(source,marker):
    names=sorted(check.expected_tests(source)); lines=[]
    for name in names:
        cls,method=name.split(".",1); lines.append(f'{method} (__main__.{cls}.{method}) ... ok')
    return ("\n".join(lines)+"\n\n----------------------------------------------------------------------\nRan "+str(len(names))+" tests in 0.001s\n\nOK\n"+marker+"\n").encode()


class TranscriptTests(unittest.TestCase):
    def setUp(self):
        self.source=b'import unittest\nclass Native(unittest.TestCase):\n def test_one(self): pass\n def test_two(self): pass\n'
        self.marker="SYNTHETIC_MARKER=PASS tests=2 skipped=0"

    def test_exact_named_tests_source_and_marker_are_required(self):
        self.assertEqual(check.test_transcript(transcript(self.source,self.marker),self.source,self.marker,2)["tests"],2)

    def test_skipped_failed_duplicate_or_marker_only_transcript_is_rejected(self):
        valid=transcript(self.source,self.marker)
        for value in (valid.replace(b'... ok',b'... skipped',1),valid.replace(b'OK\n',b'FAILED\n'),valid+self.marker.encode()+b'\n',self.marker.encode()):
            with self.assertRaises(check.CheckError): check.test_transcript(value,self.source,self.marker,2)

    def test_new_source_test_cannot_be_omitted(self):
        source=self.source+b' def test_three(self): pass\n'
        with self.assertRaises(check.CheckError): check.test_transcript(transcript(self.source,self.marker),source,self.marker,3)


def final_fixture(root):
    args,old=graph_fixture.synthetic_final_evidence(root)
    graph=old["product-registry-message-signature-graph.json"]
    values={name:value for name,value in old.items() if name.startswith("product-image-")}
    for name in ("isolation","network"):
        values["product-crash-"+name+".json"]=old["product-registry-"+name+".json"]
    values["product-crash-observations.json"]=traffic_fixture(graph)
    values["product-crash-harness.json"]={"schema":"chengwang.product-crash-harness/v1","sourceCommit":SOURCE,
        "files":{name:check.image.sha(pathlib.Path(check.__file__).with_name(pathlib.PurePosixPath(name).name).read_bytes()) for name in check.HARNESS_PATHS},
        "checkoutBytesMatched":True,"permissionReadOnly":True,**check.BOUNDARY}
    values["product-crash-registry-process.json"]={"schema":"chengwang.product-crash-registry-process/v1","sourceCommit":SOURCE,
        "registryContainerID":values["product-crash-observations.json"]["registryContainerID"],"hostPID":90,"startTime":190,"namespacePID":1,
        "uid":10001,"gid":10001,"capabilities":"none","noNewPrivileges":True,"actualExecutableSHA256":h("registrybinary"),**check.BOUNDARY}
    for index,(stage,kind) in enumerate((s,k) for s in check.STAGES for k in check.KINDS):
        reports=action_fixture(stage,kind,graph)
        for action,value in reports.items(): values[check.report_name(stage,kind,action)]=value
        values[check.report_name(stage,kind,"graph")]=graph
        projections,processes,kill=runtime_fixture(graph,stage,kind,index)
        for label,value in projections.items(): values[check.report_name(stage,kind,label+"-inspect")]=value
        for label,value in processes.items(): values[check.report_name(stage,kind,label+"-pid1")]=value
        values[check.report_name(stage,kind,"kill")]=kill
        barriers,_=barrier_fixture(stage,kind,graph,reports,index)
        values[check.report_name(stage,kind,"barriers")]=barriers
        row=next(row for row in values["product-crash-observations.json"]["snapshots"] if
            (row["stage"],row["kind"],row["window"],row["position"])==(stage,kind,"drain","after"))
        values[check.report_name(stage,kind,"drain")]=drain_fixture(row)
    values["product-crash-runtime-cleanup.json"]={"schema":"chengwang.product-crash-cleanup/v1","sourceCommit":SOURCE,
        "localImageID":graph["localImageID"],"ownedContainersRemoved":7,"ownedHelpersJoined":8,"helperExitCodes":[0]*8,
        "ownedSendersJoined":6,"senderExitCodes":[0]*6,"privateFixtureRemoved":True,"outerProductImagePreserved":True,
        "registryImagePreserved":True,"outcome":"PASS",**check.BOUNDARY}
    for label,test_file,marker in (
        ("blob-lease","test_fixture_blob_lease.py","D12_BLOB_LEASE_TESTS=PASS tests=13 passed=13 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none readonly_file_bind=true"),
        ("profile","test_crash_image_profile.py","D12_CRASH_IMAGE_PROFILE_TESTS=PASS tests=6 skipped=0 synthetic_only=true"),
        ("verifier","test_check_product_crash.py","PRODUCT_CRASH_VERIFIER_TESTS=PASS synthetic_only=true tests=27 skipped=0")):
        source=pathlib.Path(check.__file__).with_name(test_file).read_bytes()
        values["product-crash-"+label+"-tests.log"]=transcript(source,marker)
    for name,value in values.items(): graph_fixture.put(args.evidence_dir/name,value if isinstance(value,bytes) else raw(value))
    return args,values


class FullGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.args,self.values=final_fixture(pathlib.Path(self.temp.name))

    def mutate(self,name,edit):
        value=copy.deepcopy(self.values[name]); edit(value); graph_fixture.put(self.args.evidence_dir/name,raw(value))

    def test_entire_147_file_151_relations_synthetic_gate_and_canonical_replay(self):
        result=check.verify(self.args)
        self.assertEqual(len(check.own_names()),147); self.assertEqual(len(result["evidenceSHA256"]),151)
        self.assertEqual(result["plannedSIGKILLs"],6); self.assertEqual(result["normalProductStops"],12)
        self.assertFalse(result["physicalPowerLossProven"]); self.assertFalse(result["privateGraphDownloadedByReviewer"])
        graph_fixture.put(self.args.evidence_dir/"product-crash-outcome.json",raw(result))
        self.assertEqual(check.verify(self.args),result)

    def test_each_missing_own_input_or_required_native_log_rejected(self):
        for name in sorted(check.own_names()-{"product-crash-outcome.json"}|check.SUPPORT_NAMES):
            path=self.args.evidence_dir/name; original=path.read_bytes(); path.unlink()
            try:
                with self.subTest(name=name),self.assertRaises((OSError,check.CheckError)): check.verify(self.args)
            finally: graph_fixture.put(path,original)

    def test_cleanup_requires_separate_container_helper_sender_joins(self):
        for key,value in (("ownedContainersRemoved",6),("ownedHelpersJoined",7),("ownedSendersJoined",5),
                          ("helperExitCodes",[0]*7+[137]),("senderExitCodes",[False]*6),("privateFixtureRemoved",False)):
            self.mutate("product-crash-runtime-cleanup.json",lambda v:v.update({key:value}))
            with self.assertRaises(check.CheckError): check.verify(self.args)

    def test_cli_writes_only_exclusive_safe_success_and_failure_never_pass(self):
        argv=["verify","--evidence-dir",str(self.args.evidence_dir),"--source-commit",SOURCE,"--report",str(self.args.report)]
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(check.main(argv),0)
        self.assertEqual(json.loads(self.args.report.read_bytes())["outcome"],"PASS")
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()): self.assertEqual(check.main(argv),1)
        self.args.report.unlink()
        self.mutate("product-crash-runtime-cleanup.json",lambda v:v.update(outcome="DO_NOT_ECHO_PRIVATE_SENTINEL"))
        out=io.StringIO(); error=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(error): self.assertEqual(check.main(argv),1)
        self.assertFalse(self.args.report.exists()); self.assertNotIn("PASS",out.getvalue()); self.assertNotIn("DO_NOT_ECHO_PRIVATE_SENTINEL",error.getvalue())

    def test_source_harness_unknown_prefix_and_existing_outcome_tampering_rejected(self):
        name="product-crash-harness.json"
        self.mutate(name,lambda v:v["files"].update({check.HARNESS_PATHS[-1]:"0"*64}))
        with self.assertRaises(check.CheckError): check.verify(self.args)
        graph_fixture.put(self.args.evidence_dir/name,raw(self.values[name]))
        unknown=self.args.evidence_dir/"product-crash-stale.json"; graph_fixture.put(unknown,b"{}")
        with self.assertRaises(check.CheckError): check.verify(self.args)
        unknown.unlink(); result=check.verify(self.args); result["recoveryAuthorized"]=True
        graph_fixture.put(self.args.evidence_dir/"product-crash-outcome.json",raw(result))
        with self.assertRaises(check.CheckError): check.verify(self.args)


if __name__=="__main__":
    program=unittest.main(verbosity=2,exit=False)
    accepted=program.result.wasSuccessful() and not program.result.skipped and program.result.testsRun==27
    if accepted: print("PRODUCT_CRASH_VERIFIER_TESTS=PASS synthetic_only=true tests="+str(program.result.testsRun)+" skipped=0")
    raise SystemExit(0 if accepted else 1)
