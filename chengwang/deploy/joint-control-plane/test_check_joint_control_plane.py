from __future__ import annotations
import base64, copy, datetime, importlib.util, json, pathlib, tempfile, unittest
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
C=load("joint_checker_test_contract","contract.py");K=load("joint_checker_test_target","check_joint_control_plane.py")

def refresh(state="idle"):
    value={"scope":dict(C.SCOPE),"binding":{"sourceId":"src_"+"1"*32,"referenceId":"success","policyRevision":1,"approvalId":"cmd_"+"2"*32,"approvalSourceRevision":3,"intervalSeconds":60,"approvalTtlSeconds":600,"maxStaleSeconds":300,"maxBackoffSeconds":600},"bindingSeal":"hmac-sha256:"+"3"*64,"bindingGeneration":1,"state":state,"attemptCount":0,"consecutiveFailures":0,"stale":False,"clockState":"normal","auditRecorded":False,"stateMayHaveChanged":False}
    return value
def full_evidence(root):
    commit="a"*40;fixture="joint-"+"b"*32;base=1_799_000_000_000_000_000
    wire=[]
    for case in C.SOURCE_HOSTS:
        for response in ("dns_answer","dns_nodata"):
            wire.append({"schema":C.WIRE_SCHEMA,"ordinal":len(wire)+1,"service":"dot","event":"response","reference":C.SOURCE_HOSTS[case],"method":"","path":"","status":200,"bytes":10,"fixturePid":90,"connection":"dot-bootstrap-"+case+"-"+response,"sourceHost":"","tlsClass":"server_tls","authClass":"not_applicable","responseClass":response,"receivedUnixNano":str(base-7_000_000_000)})
        wire.append({"schema":C.WIRE_SCHEMA,"ordinal":len(wire)+1,"service":"source","event":"response","reference":case,"method":"GET","path":"/subscription","status":200,"bytes":10,"fixturePid":90,"connection":"bootstrap-"+case,"sourceHost":C.SOURCE_HOSTS[case],"tlsClass":"server_tls","authClass":"source_secret_accepted","responseClass":"success","receivedUnixNano":str(base-7_000_000_000)})
    for case,status in (("success",200),("failure",503)):
        for response in ("dns_answer","dns_nodata"):
            wire.append({"schema":C.WIRE_SCHEMA,"ordinal":len(wire)+1,"service":"dot","event":"response","reference":C.SOURCE_HOSTS[case],"method":"","path":"","status":200,"bytes":10,"fixturePid":90,"connection":"dot-refresh-"+case+"-"+response,"sourceHost":"","tlsClass":"server_tls","authClass":"not_applicable","responseClass":response,"receivedUnixNano":str(base+1_000_000)})
        wire.append({"schema":C.WIRE_SCHEMA,"ordinal":len(wire)+1,"service":"source","event":"response","reference":case,"method":"GET","path":"/subscription","status":status,"bytes":10,"fixturePid":90,"connection":"refresh-"+case,"sourceHost":C.SOURCE_HOSTS[case],"tlsClass":"server_tls","authClass":"source_secret_accepted","responseClass":"success" if status==200 else "upstream_failure","receivedUnixNano":str(base+2_000_000)})
    for path in ("/version","/configs","/proxies","/rules"):
        wire.append({"schema":C.WIRE_SCHEMA,"ordinal":len(wire)+1,"service":"mihomo","event":"response","reference":"","method":"GET","path":path,"status":200,"bytes":10,"fixturePid":90,"connection":"mihomo-"+str(len(wire)),"sourceHost":C.SOURCE_IP,"tlsClass":"server_tls","authClass":"readonly_bearer_accepted","responseClass":"success","receivedUnixNano":str(base+2_000_000)})
    wire_raw=b"".join(C.canonical(x) for x in wire);wire_lines=wire_raw.splitlines(keepends=True)
    def fence(count):return {"events":count,"sha256":C.sha(b"".join(wire_lines[:count]))}
    processes=[]
    for epoch,pid,start,stop in (("B0",10,base-10_000_000_000,base-5_000_000_000),("J1",11,base-4_000_000_000,base+4_000_000_000),("R2",12,base+5_000_000_000,base+10_000_000_000)):
        processes.append({"epoch":epoch,"pid":pid,"startTicks":pid*10,"exeSHA256":"1"*64,"argvSHA256":"2"*64,"netNamespace":"net:[1]","mountNamespace":"mnt:[1]","pidNamespace":"pid:[1]","uid":10001,"gid":10001,"capabilities":"0000000000000000","noNewPrivileges":1,"startedUnixNano":str(start),"stoppedUnixNano":str(stop),"normalStop":True,"listener":{"fd":3,"inode":str(100+pid),"procFdTarget":"socket:["+str(100+pid)+"]","port":17871,"localAddress":"127.0.0.1","procNet":{"localHex":"0100007F:45CF","remoteHex":"00000000:0000","stateHex":"0A"},"ownerPID":pid,"ownerStartTicks":pid*10}})
    fixture_process={"pid":90,"startTicks":900,"netNamespace":"net:[1]","mountNamespace":"mnt:[1]","pidNamespace":"pid:[1]","uid":10001,"gid":10001,"capabilities":"0000000000000000","noNewPrivileges":1,"startedUnixNano":str(base-20_000_000_000),"stoppedUnixNano":str(base+20_000_000_000),"normalStop":True}
    runtime={"schema":C.RUNTIME_SCHEMA,"sourceCommit":commit,"fixtureId":fixture,"serverBinarySHA256":"1"*64,"fixtureProcess":fixture_process,"processes":processes,"sameBinaryAllEpochs":True}
    captures=[];bootstrap_wire=[0]
    def add(name,epoch,role,path,result,status=200,method="GET",body=None,key=""):
        if path.startswith("/api/v1/subscriptions"):
            value={"boundary":C.BOUNDARY,"authorization":"BLOCKED","deviceActionsExecuted":False,"stateMayHaveChanged":False}
            if result is not None:value["result"]=result
            if status!=200:value["code"]="subscription_forbidden"
        elif status!=200:value={"code":"unauthorized" if status==401 else "forbidden","message":"access denied"}
        else:value=result
        raw=C.canonical(value);before=bootstrap_wire[0] if epoch=="B0" else len(wire)
        if epoch=="B0" and name.endswith("-fetch-r1"):bootstrap_wire[0]+=3
        after=bootstrap_wire[0] if epoch=="B0" else len(wire);received={"B0":base-7_000_000_000,"J1":base+2_000_000,"R2":base+7_000_000_000}[epoch]
        captures.append({"schema":C.CAPTURE_SCHEMA,"ordinal":len(captures)+1,"name":name,"epoch":epoch,"role":role,"method":method,"path":path,"status":status,"request":{"body":body,"idempotencyKey":key},"responseBase64":base64.b64encode(raw).decode(),"responseSHA256":C.sha(raw),"tlsPeerSHA256":"f"*64,"commandIdHeader":None,"wireBefore":fence(before),"wireAfter":fence(after),"receivedUnixNano":str(received)})
    source_ids={"success":"src_"+"1"*32,"failure":"src_"+"2"*32};accepted={"success":"cand_"+"1"*32,"failure":"cand_"+"2"*32};latest={"success":"cand_"+"3"*32,"failure":accepted["failure"]}
    updated=datetime.datetime.fromtimestamp((base-2_000_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")
    def source_view(case,revision,latest_id):return {"id":source_ids[case],"scope":dict(C.SCOPE),"label":case,"revision":revision,"acceptedCandidateId":accepted[case],"latestCandidateId":latest_id,"updatedAt":updated}
    def mutation_receipt(command,kind,source,revision,state,candidate="",digest="",reference=""):
        value={"commandId":command,"kind":kind,"sourceId":source,"revision":revision,"state":state,"replayed":False,"stateMayHaveChanged":False,"auditRecorded":True,"preparedAuditHash":"6"*64,"resultAuditHash":"7"*64,"completedAt":updated}
        if candidate:value.update(candidateId=candidate,candidateDigest=digest)
        if state=="committed":value["localAuditHash"]="8"*64
        else:value.update(referenceId=reference,policyRevision=1,policyDigest="hmac-sha256:"+"b"*64,approvalId=command)
        return value
    add("anonymous-list","B0","anonymous","/api/v1/subscriptions/sources",None,401);add("foreign-list","B0","foreign","/api/v1/subscriptions/sources",None,403)
    finals={};worker_receipts={}
    for i,case in enumerate(C.SOURCE_HOSTS):
        sid=source_ids[case];approve1="cmd_"+str(3+i)*32;approve3="cmd_"+str(5+i)*32;worker="cmd_"+str(7+i)*32
        digest="hmac-sha256:"+str(i+5)*64
        create_command="cmd_"+str(1+i)*32;fetch_command="cmd_"+("9" if case=="success" else "a")*32;decision_command="cmd_"+("b" if case=="success" else "c")*32
        ops=(("viewer-create-neg","viewer","/api/v1/subscriptions/sources","viewer_create_neg",403,{"label":case},None),("create","operator","/api/v1/subscriptions/sources","create_source",200,{"label":case},mutation_receipt(create_command,"create",sid,1,"committed")),("operator-approve-neg","operator",f"/api/v1/subscriptions/sources/{sid}/approvals","operator_approve_r1_neg",403,{"referenceId":case,"policyRevision":1,"expectedRevision":1},None),("approve-r1","approver",f"/api/v1/subscriptions/sources/{sid}/approvals","approve_r1",200,{"referenceId":case,"policyRevision":1,"expectedRevision":1},mutation_receipt(approve1,"approve",sid,1,"approved",reference=case)),("fetch-r1","operator",f"/api/v1/subscriptions/sources/{sid}/fetches","fetch_r1",200,{"approvalId":approve1,"policyRevision":1,"expectedRevision":1},mutation_receipt(fetch_command,"fetch",sid,2,"committed",accepted[case],digest)),("admit-r2","approver",f"/api/v1/subscriptions/sources/{sid}/decisions","admit_r2",200,{"candidateId":accepted[case],"expectedRevision":2,"expectedDigest":digest,"decision":"admitted_local"},mutation_receipt(decision_command,"decide",sid,3,"committed",accepted[case],digest)),("approve-r3","approver",f"/api/v1/subscriptions/sources/{sid}/approvals","approve_r3",200,{"referenceId":case,"policyRevision":1,"expectedRevision":3},mutation_receipt(approve3,"approve",sid,3,"approved",reference=case)))
        for suffix,role,path,op,status,body,result in ops:add(case+"-"+suffix,"B0",role,path,result,status,"POST",body,C.idempotency(case,op))
        baseline_cases=("success",) if case=="success" else ("success","failure");baseline_sources={"sources":[source_view(name,3,accepted[name]) for name in baseline_cases],"total":len(baseline_cases)};add(case+"-baseline-source","B0","viewer","/api/v1/subscriptions/sources",baseline_sources)
        created=datetime.datetime.fromtimestamp((base-2_000_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")
        accepted_summary={"id":accepted[case],"sourceId":sid,"digest":digest,"format":"mihomo-provider-yaml","state":"admitted_local","baseRevision":2,"nodeCount":1,"duplicateCount":0,"createdAt":created}
        baseline={"candidates":[accepted_summary],"total":1,"revision":3};add(case+"-baseline-candidates","B0","viewer",f"/api/v1/subscriptions/sources/{sid}/candidates?limit=100&offset=0&revision=3",baseline)
        add(case+"-approval-receipt","B0","auditor","/api/v1/subscriptions/commands/"+approve3,{"commandId":approve3,"kind":"approve","sourceId":sid,"revision":3,"state":"approved","replayed":False,"stateMayHaveChanged":False,"auditRecorded":True,"preparedAuditHash":"6"*64,"resultAuditHash":"7"*64,"referenceId":case,"policyRevision":1,"policyDigest":"hmac-sha256:"+"b"*64,"approvalId":approve3,"completedAt":datetime.datetime.fromtimestamp((base-2_000_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")})
        final=refresh("candidate_quarantined" if case=="success" else "failed");final.update({"attemptCount":1,"attemptSequence":i+1,"attemptKey":"refresh_"+str(i+1)*32,"fence":str(i+1)*64,"commandId":worker,"commandOwnerId":C.MACHINE_ID,"commandEpoch":"e"*64,"startedAt":datetime.datetime.fromtimestamp((base-1_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z"),"completedAt":datetime.datetime.fromtimestamp((base+3_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z"),"auditRecorded":True});final["binding"].update(sourceId=sid,referenceId=case,approvalId=approve3,approvalSourceRevision=3)
        failure_retry=datetime.datetime.fromtimestamp((base+60_003_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")
        success_fresh=datetime.datetime.fromtimestamp((base+300_003_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")
        if case=="success":final.update(candidateId=latest[case],candidateDigest="hmac-sha256:"+"4"*64,resultRevision=4,lastSuccessAt=final["completedAt"],freshUntil=success_fresh)
        else:final.update(failure="http",consecutiveFailures=1,nextAttemptAt=failure_retry)
        finals[case]=final;add(case+"-refresh-poll","J1","viewer",f"/api/v1/subscriptions/sources/{sid}/refresh",final)
        receipt={"commandId":worker,"kind":"fetch","sourceId":sid,"revision":4 if case=="success" else 3,"state":"committed" if case=="success" else "failed","replayed":False,"stateMayHaveChanged":False,"auditRecorded":True,"preparedAuditHash":"8"*64,"resultAuditHash":"9"*64,"completedAt":final["completedAt"]}
        if case=="success":receipt.update(candidateId=latest[case],candidateDigest=final["candidateDigest"],localAuditHash="a"*64)
        else:receipt["code"]="subscription_fetch_http_rejected"
        worker_receipts[case]=receipt
        for suffix,role,status in (("worker-receipt-auditor","auditor",200),("worker-receipt-viewer-denied","viewer",403),("worker-receipt-operator-denied","operator",403)):add(case+"-"+suffix,"J1",role,"/api/v1/subscriptions/commands/"+worker,receipt if status==200 else None,status)
        add(case+"-r2-worker-receipt","R2","auditor","/api/v1/subscriptions/commands/"+worker,receipt)
        r2={"candidates":[accepted_summary],"total":1,"revision":3}
        if case=="success":
            latest_summary={"id":latest[case],"sourceId":sid,"digest":final["candidateDigest"],"format":"mihomo-provider-yaml","state":"quarantined","baseRevision":4,"nodeCount":1,"duplicateCount":0,"createdAt":final["completedAt"]}
            r2={"candidates":[accepted_summary,latest_summary],"total":2,"revision":4}
        add(case+"-r2-candidates","R2","viewer",f"/api/v1/subscriptions/sources/{sid}/candidates?limit=100&offset=0&revision="+("4" if case=="success" else "3"),r2)
    observed=datetime.datetime.fromtimestamp((base+2_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z");expires=datetime.datetime.fromtimestamp((base+60_002_000_000)/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z");layer={"state":"available","reason":"cache_current","observedAt":observed,"expiresAt":expires}
    overview={"schema":"chengwang.overview-snapshot/v1","dataSource":"live","generatedAt":observed,"mode":"candidate","readOnly":True,"advisoryOnly":True,"coverage":{"state":"partial","missing":["probe"]},"observation":{"configured":True,"running":True,"fresh":True,"stale":False,"lastAttemptAt":observed,"lastSuccessAt":observed,"consecutiveFailures":0,"controller":dict(layer),"storage":dict(layer),"clock":dict(layer)},"probe":{"configured":False,"running":False,"state":"disabled","reason":"disabled","clockHealthy":False,"storageHealthy":False,"cachedAt":None,"expiresAt":None,"coverageState":"unavailable","coverage":None},"subscription":{"configured":True,"inventoryState":"protected_not_read","sourceCount":None,"nodeCount":None},"unsupported":{"businesses":True,"nodePools":True,"endToEndDNS":True,"deviceInventory":True,"trafficTopology":True}}
    mihomo_status={"configured":True,"reachable":True,"fresh":True,"stale":False,"observedAt":observed};mihomo_runtime={"observedAt":observed,"version":{"version":"joint-fixture","meta":False,"premium":False},"config":{"mode":"rule","allowLan":False,"bindAddress":"","ipv6":False,"port":0,"socksPort":0,"mixedPort":0,"redirPort":0,"tproxyPort":0,"externalController":""},"proxies":[],"rules":[]}
    add("overview-anonymous","J1","anonymous","/api/v1/overview",overview);add("mihomo-status-anonymous","J1","anonymous","/api/v1/kernels/mihomo/status",mihomo_status);add("mihomo-runtime-viewer","J1","viewer","/api/v1/kernels/mihomo/runtime",mihomo_runtime);add("mihomo-runtime-anonymous-denied","J1","anonymous","/api/v1/kernels/mihomo/runtime",None,401);add("mihomo-runtime-foreign-denied","J1","foreign","/api/v1/kernels/mihomo/runtime",None,403)
    sources={"sources":[source_view("success",4,latest["success"]),source_view("failure",3,latest["failure"])],"total":2};add("r2-sources","R2","viewer","/api/v1/subscriptions/sources",sources)
    bindings=[]
    for case in sorted(C.SOURCE_HOSTS):bindings.append({"referenceId":case,"changedKeys":["refresh"],"sourceId":source_ids[case],"approvalId":"cmd_"+("6" if case=="failure" else "5")*32,"approvalSourceRevision":3,"intervalSeconds":60,"approvalTtlSeconds":600,"maxStaleSeconds":300,"maxBackoffSeconds":600})
    files={"build.json":{"schema":"chengwang.joint-control-plane-build/v2","sourceCommit":commit,"goVersion":"go1.23.12","moduleMode":"vendor","dependencyDownloads":False,"production":False,"authorization":"BLOCKED","server":{"bytes":2048,"sha256":"1"*64}},"source-before.json":[],"source-after.json":[],"isolation.json":{"interfaces":["lo"],"ipv4Addresses":["127.0.0.1/8","8.8.4.4/32"],"ipv4DefaultRoutes":[],"ipv6DefaultRoutes":[],"unprivilegedPortStart":0,"capabilities":"0000000000000000","noNewPrivileges":1,"netNamespace":"net:[1]","mountNamespace":"mnt:[1]","pidNamespace":"pid:[1]"},"runtime.json":runtime,"readback.json":{"schema":C.READBACK_SCHEMA,"sourceCommit":commit,"fixtureId":fixture,"sources":sources,"workerReceipts":worker_receipts,"sidecarUnchanged":True,"refreshRestartPersistenceProven":False,"bootstrapCounts":{"commands":1,"audit":1},"jointCounts":{"commands":3,"audit":3}},"private-checks.json":{"schema":"chengwang.joint-control-plane-private-checks/v2","policyTransition":{"baseEqualAfterRemovingRefresh":True,"bindings":bindings},"identityTransition":{"humanIdentitiesUnchanged":True,"bootstrapMachineOmitted":True,"refreshMachineExact":True,"humanCount":5,"machineScopeCount":2},"sidecar":{"unchanged":True},"publicationScan":{"result":"PASS"},"privateMaterialPublished":False},"transport-negatives.json":{"schema":"chengwang.joint-control-plane-transport-negatives/v2","cases":[{"case":"wrong_ca","result":"tls_verification_rejected"},{"case":"plaintext_http","result":"no_http_response"},{"case":"duplicate_authorization","result":"401"}]},"outcome.json":C.outcome(commit,fixture,"CAPTURED")}
    for name,value in files.items():(root/name).write_bytes(C.canonical(value))
    (root/"captures.jsonl").write_bytes(b"".join(C.canonical(x) for x in captures));(root/"wire-events.jsonl").write_bytes(wire_raw)
    for name in ("api-ca.pem","api-leaf.pem","resolver-ca.pem","resolver-leaf.pem","source-ca.pem","source-leaf.pem","mihomo-ca.pem","mihomo-leaf.pem"):(root/name).write_bytes(b"PUBLIC CERT\n")
    scan_names=sorted(set(C.PUBLIC_FILES)-{"private-checks.json","source-after.json"});manifest=[]
    for name in scan_names:
        data=(root/name).read_bytes();manifest.append({"path":name,"bytes":len(data),"sha256":C.sha(data)})
    private=json.loads((root/"private-checks.json").read_text());private["publicationScan"]={"filesScanned":len(manifest),"bytesScanned":sum(x["bytes"] for x in manifest),"secretVariants":7,"publicFiles":manifest,"sourceAfterBinding":"byte_equal_to_source-before.json","result":"PASS"};(root/"private-checks.json").write_bytes(C.canonical(private))
    return commit
def rebind_public_manifest(root):
    private=K.decode((root/"private-checks.json").read_bytes());rows=[]
    for name in sorted(set(C.PUBLIC_FILES)-{"private-checks.json","source-after.json"}):
        data=(root/name).read_bytes();rows.append({"path":name,"bytes":len(data),"sha256":C.sha(data)})
    private["publicationScan"].update(filesScanned=len(rows),bytesScanned=sum(x["bytes"] for x in rows),publicFiles=rows);(root/"private-checks.json").write_bytes(C.canonical(private))
def rebind_wire_fences(root):
    wire=(root/"wire-events.jsonl").read_bytes().splitlines(keepends=True);captures=[K.decode(x) for x in (root/"captures.jsonl").read_bytes().splitlines()]
    for capture in captures:
        for fence in (capture["wireBefore"],capture["wireAfter"]):fence["sha256"]=C.sha(b"".join(wire[:fence["events"]]))
    (root/"captures.jsonl").write_bytes(b"".join(C.canonical(x) for x in captures));rebind_public_manifest(root)
def write_wire_mutation(root,rows,removed_ordinal=None):
    for ordinal,row in enumerate(rows,1):row["ordinal"]=ordinal
    (root/"wire-events.jsonl").write_bytes(b"".join(C.canonical(x) for x in rows));captures=[K.decode(x) for x in (root/"captures.jsonl").read_bytes().splitlines()]
    if removed_ordinal is not None:
        for capture in captures:
            for fence in (capture["wireBefore"],capture["wireAfter"]):
                if fence["events"]>=removed_ordinal:fence["events"]-=1
        (root/"captures.jsonl").write_bytes(b"".join(C.canonical(x) for x in captures))
    rebind_wire_fences(root)

class CheckerContracts(unittest.TestCase):
    def checked(self,root,commit):
        with mock.patch.object(K,"source_contract",return_value={"baseCommit":"736bfdd1f8182e958cea26987f85683e2c6aee39"}),mock.patch.object(K,"source_snapshot",return_value=[]),mock.patch.object(K,"cert_validate",return_value=None),mock.patch.object(K,"cert_der_sha",return_value="f"*64):return K.check(root,root,root/"unused",commit)
    def test_complete_checker_positive_and_mutation_space(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root)
            self.assertEqual(self.checked(root,commit)["status"],"PASS")
            original=(root/"captures.jsonl").read_bytes();lines=original.splitlines(keepends=True);(root/"captures.jsonl").write_bytes(lines[1]+lines[0]+b"".join(lines[2:]))
            with self.assertRaises(ValueError):self.checked(root,commit)
            (root/"captures.jsonl").write_bytes(original);wire=(root/"wire-events.jsonl").read_bytes();(root/"wire-events.jsonl").write_bytes(wire.replace(b'"status":200',b'"status":201',1))
            with self.assertRaises(ValueError):self.checked(root,commit)
            (root/"wire-events.jsonl").write_bytes(wire);(root/"api-leaf.pem").write_bytes(b"PUBLIC CERT\nPRIVATE KEY\n")
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_capture_omission_and_duplication(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);path=root/"captures.jsonl";lines=path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:-1]))
            with self.assertRaises(ValueError):self.checked(root,commit)
            path.write_bytes(b"".join(lines)+lines[0])
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_source_cross_file_substitution(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);(root/"source-after.json").write_bytes(C.canonical([{"path":"substituted"}]))
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_wire_fence_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);path=root/"captures.jsonl";rows=[K.decode(x) for x in path.read_bytes().splitlines()];rows[-1]["wireBefore"]["sha256"]="0"*64;path.write_bytes(b"".join(C.canonical(x) for x in rows))
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_short_candidate_dto(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);path=root/"captures.jsonl";rows=[K.decode(x) for x in path.read_bytes().splitlines()];target=next(x for x in rows if x["name"]=="success-baseline-candidates");body=K.decode(base64.b64decode(target["responseBase64"]));body["result"]["candidates"][0].pop("sourceId");raw=C.canonical(body);target["responseBase64"]=base64.b64encode(raw).decode();target["responseSHA256"]=C.sha(raw);path.write_bytes(b"".join(C.canonical(x) for x in rows));rebind_public_manifest(root)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_non_get_source_wire(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);path=root/"wire-events.jsonl";rows=[K.decode(x) for x in path.read_bytes().splitlines()];target=next(x for x in rows if x["service"]=="source");target["method"]="POST";path.write_bytes(b"".join(C.canonical(x) for x in rows));rebind_wire_fences(root)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_stale_candidate_base_revisions(self):
        for capture_name,candidate_index,stale in (("success-baseline-candidates",0,1),("success-r2-candidates",1,3)):
            with self.subTest(capture=capture_name),tempfile.TemporaryDirectory() as d:
                root=pathlib.Path(d);commit=full_evidence(root);path=root/"captures.jsonl";rows=[K.decode(x) for x in path.read_bytes().splitlines()];target=next(x for x in rows if x["name"]==capture_name);body=K.decode(base64.b64decode(target["responseBase64"]));body["result"]["candidates"][candidate_index]["baseRevision"]=stale;raw=C.canonical(body);target["responseBase64"]=base64.b64encode(raw).decode();target["responseSHA256"]=C.sha(raw);path.write_bytes(b"".join(C.canonical(x) for x in rows));rebind_public_manifest(root)
                with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_bootstrap_dot_pair_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);rows=[K.decode(x) for x in (root/"wire-events.jsonl").read_bytes().splitlines()];target=next(x for x in rows if x["connection"]=="dot-bootstrap-success-dns_nodata");rows.remove(target);write_wire_mutation(root,rows,target["ordinal"])
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_bootstrap_dot_pair_reordering(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);rows=[K.decode(x) for x in (root/"wire-events.jsonl").read_bytes().splitlines()];left=next(i for i,x in enumerate(rows) if x["connection"]=="dot-bootstrap-success-dns_answer");right=next(i for i,x in enumerate(rows) if x["connection"]=="dot-bootstrap-success-dns_nodata");rows[left],rows[right]=rows[right],rows[left];write_wire_mutation(root,rows)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_refresh_dot_after_source(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);rows=[K.decode(x) for x in (root/"wire-events.jsonl").read_bytes().splitlines()];nodata=next(i for i,x in enumerate(rows) if x["connection"]=="dot-refresh-success-dns_nodata");source=next(i for i,x in enumerate(rows) if x["connection"]=="refresh-success");rows[nodata],rows[source]=rows[source],rows[nodata];write_wire_mutation(root,rows)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_bootstrap_wire_before_server_pid(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);runtime=K.decode((root/"runtime.json").read_bytes());before=int(runtime["processes"][0]["startedUnixNano"])-1_000_000_000;rows=[K.decode(x) for x in (root/"wire-events.jsonl").read_bytes().splitlines()]
            for row in rows:
                if row["connection"] in ("dot-bootstrap-success-dns_answer","dot-bootstrap-success-dns_nodata","bootstrap-success"):row["receivedUnixNano"]=str(before)
            write_wire_mutation(root,rows)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_refresh_interval_before_server_pid(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);runtime=K.decode((root/"runtime.json").read_bytes());start=int(runtime["processes"][1]["startedUnixNano"]);started=start-2_000_000_000;completed=start-500_000_000
            stamp=lambda value:datetime.datetime.fromtimestamp(value/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")
            path=root/"captures.jsonl";captures=[K.decode(x) for x in path.read_bytes().splitlines()];target=next(x for x in captures if x["name"]=="success-refresh-poll");body=K.decode(base64.b64decode(target["responseBase64"]));final=body["result"];final["startedAt"]=stamp(started);final["completedAt"]=stamp(completed);final["lastSuccessAt"]=final["completedAt"];final["freshUntil"]=stamp(completed+300_000_000_000);raw=C.canonical(body);target["responseBase64"]=base64.b64encode(raw).decode();target["responseSHA256"]=C.sha(raw);path.write_bytes(b"".join(C.canonical(x) for x in captures))
            rows=[K.decode(x) for x in (root/"wire-events.jsonl").read_bytes().splitlines()]
            for row in rows:
                if row["connection"] in ("dot-refresh-success-dns_answer","dot-refresh-success-dns_nodata","refresh-success"):row["receivedUnixNano"]=str(start-1_000_000_000)
            write_wire_mutation(root,rows)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_refresh_completion_after_server_pid(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);runtime=K.decode((root/"runtime.json").read_bytes());completed=int(runtime["processes"][1]["stoppedUnixNano"])+1_000_000_000;stamp=lambda value:datetime.datetime.fromtimestamp(value/1e9,datetime.timezone.utc).isoformat().replace("+00:00","Z")
            path=root/"captures.jsonl";captures=[K.decode(x) for x in path.read_bytes().splitlines()];target=next(x for x in captures if x["name"]=="success-refresh-poll");body=K.decode(base64.b64decode(target["responseBase64"]));final=body["result"];final["completedAt"]=stamp(completed);final["lastSuccessAt"]=final["completedAt"];final["freshUntil"]=stamp(completed+300_000_000_000);raw=C.canonical(body);target["responseBase64"]=base64.b64encode(raw).decode();target["responseSHA256"]=C.sha(raw);path.write_bytes(b"".join(C.canonical(x) for x in captures));rebind_public_manifest(root)
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_complete_checker_rejects_receipt_and_tls_cross_binding(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);commit=full_evidence(root);path=root/"captures.jsonl";rows=[K.decode(x) for x in path.read_bytes().splitlines()];target=next(x for x in rows if x["name"]=="success-worker-receipt-auditor");body=K.decode(base64.b64decode(target["responseBase64"]));body["result"]["state"]="failed";raw=C.canonical(body);target["responseBase64"]=base64.b64encode(raw).decode();target["responseSHA256"]=C.sha(raw);path.write_bytes(b"".join(C.canonical(x) for x in rows))
            with self.assertRaises(ValueError):self.checked(root,commit)
            root=pathlib.Path(d)/"second";root.mkdir();full_evidence(root);rows=[K.decode(x) for x in (root/"captures.jsonl").read_bytes().splitlines()];rows[0]["tlsPeerSHA256"]="e"*64;(root/"captures.jsonl").write_bytes(b"".join(C.canonical(x) for x in rows))
            with self.assertRaises(ValueError):self.checked(root,commit)
    def test_refresh_required_optional_contract(self):
        value=refresh();self.assertIs(C.refresh_keys(value),value)
        value["storageNextRetryAt"]="0001-01-01T00:00:00Z";self.assertIs(C.refresh_keys(value),value)
        for key in C.REFRESH_REQUIRED:
            broken=copy.deepcopy(value);broken.pop(key)
            with self.assertRaises(ValueError):C.refresh_keys(broken)
    def test_running_requires_exact_reservation(self):
        value=refresh("running")
        with self.assertRaises(ValueError):C.refresh_keys(value)
        value["reservation"]={"attemptSequence":1,"attemptKey":"refresh_"+"1"*32,"fence":"2"*64,"commandSlots":1,"candidateSlots":1,"domainAuditSlots":1,"bytes":1024};C.refresh_keys(value)
        value["reservation"]["invented"]=1
        with self.assertRaises(ValueError):C.refresh_keys(value)
    def test_lease_never_serializes(self):
        value=refresh();value["lease"]={}
        with self.assertRaises(ValueError):C.refresh_keys(value)
    def test_outcome_preserves_unknown_and_r2_boundary(self):
        value=C.outcome("a"*40,"joint-"+"b"*32,"CAPTURED");self.assertEqual(value["actualSKUObservation"],"UNKNOWN");self.assertTrue(value["refreshWorkerProven"]);self.assertTrue(value["mainStoreRestartPersistenceProven"]);self.assertFalse(value["refreshRestartPersistenceProven"]);self.assertFalse(value["production"]);self.assertEqual(value["authorization"],"BLOCKED")
    def test_duplicate_json_is_rejected(self):
        with self.assertRaises(ValueError):K.decode(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):K.decode(b'{"a":NaN}')
    def test_source_contract_checks_each_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);(root/"a").write_bytes(b"one\n");contract=root/"source_contract.json";inventory={"scope":"tracked-chengwang-nondeploy-nondocs-plus-joint-scene","excluded":[".github/workflows/chengwang-joint-control-plane.yml","chengwang/deploy/joint-control-plane/source_contract.json"],"pathCount":1};contract.write_bytes(C.canonical({"schema":"chengwang.joint-control-plane-source-contract/v1","baseCommit":"a"*40,"inventory":inventory,"paths":[{"path":"a","sha256":C.sha(b"one\n")}]}))
            with mock.patch.object(K,"contract_paths",return_value={"a"}):K.source_contract(root,contract)
            (root/"a").write_bytes(b"two\n")
            with mock.patch.object(K,"contract_paths",return_value={"a"}):
                with self.assertRaises(ValueError):K.source_contract(root,contract)
            (root/"b").write_bytes(b"new\n")
            with mock.patch.object(K,"contract_paths",return_value={"a","b"}):
                with self.assertRaises(ValueError):K.source_contract(root,contract)
    def test_public_file_contract_has_no_private_inputs(self):
        self.assertNotIn("fixture-input.private.json",C.PUBLIC_FILES);self.assertNotIn("policy1.json",C.PUBLIC_FILES);self.assertNotIn("identities1.json",C.PUBLIC_FILES)

if __name__=="__main__":unittest.main()
