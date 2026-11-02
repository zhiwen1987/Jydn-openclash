"""Independent fail-closed reconstruction of joint-control-plane public evidence."""
from __future__ import annotations
import argparse, base64, calendar, datetime, hashlib, importlib.util, json, os, pathlib, re, ssl, subprocess, sys
HERE=pathlib.Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("joint_checker_contract",HERE/"contract.py");C=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(C)

def need(ok,label="evidence"):
    if not ok: raise ValueError("joint-control-plane-"+label+"-rejected")
def read(path,maximum=C.MAX_ARTIFACT):
    p=pathlib.Path(path);raw=p.read_bytes();need(not p.is_symlink() and p.is_file() and len(raw)<=maximum,"file");return raw
def decode(raw):return json.loads(raw,object_pairs_hook=lambda pairs: _object(pairs),parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
def _object(pairs):
    value={}
    for k,v in pairs:need(k not in value,"json");value[k]=v
    return value
def envelope(capture):
    raw=base64.b64decode(capture["responseBase64"],validate=True);need(C.sha(raw)==capture["responseSHA256"],"capture");value=decode(raw)
    if capture["path"].startswith("/api/v1/subscriptions"):
        need(set(value)<={"boundary","authorization","deviceActionsExecuted","stateMayHaveChanged","code","result"} and {"boundary","authorization","deviceActionsExecuted","stateMayHaveChanged"}<=set(value),"envelope")
        need(value["boundary"]==C.BOUNDARY and value["authorization"]=="BLOCKED" and value["deviceActionsExecuted"] is False and type(value["stateMayHaveChanged"])is bool,"envelope");return value.get("result")
    return value
def cert_validate(ca, path, expected):
    verified=subprocess.run(["openssl","verify","-CAfile",str(ca),"-purpose","sslserver",str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,text=True)
    need(verified.returncode==0 and verified.stdout.strip().endswith(": OK"),"certificate")
    result=subprocess.run(["openssl","x509","-in",str(path),"-noout","-ext","subjectAltName"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=True,text=True)
    actual=sorted(re.findall(r"(?:DNS|IP Address):[^,\s]+",result.stdout))
    need(actual==sorted(expected),"certificate")
    text=subprocess.check_output(["openssl","x509","-in",str(path),"-noout","-text"],stderr=subprocess.DEVNULL,timeout=5,text=True)
    need("CA:FALSE" in text and "Digital Signature" in text and "TLS Web Server Authentication" in text,"certificate")
    need(subprocess.run(["openssl","x509","-in",str(path),"-noout","-checkend","0"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode==0,"certificate")
    ca_text=subprocess.check_output(["openssl","x509","-in",str(ca),"-noout","-text"],stderr=subprocess.DEVNULL,timeout=5,text=True)
    need("CA:TRUE" in ca_text and "Certificate Sign" in ca_text,"certificate")
def cert_der_sha(path):
    return C.sha(ssl.PEM_cert_to_DER_cert(read(path,65536).decode("ascii")))
def nano(value):
    match=re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z",value or "");need(match is not None,"time")
    year,month,day,hour,minute,second=map(int,match.groups()[:6]);instant=datetime.datetime(year,month,day,hour,minute,second,tzinfo=datetime.timezone.utc)
    return calendar.timegm(instant.utctimetuple())*1_000_000_000+int((match.group(7) or "").ljust(9,"0"))
def zero_or_absent(value,key):
    return key not in value or value[key]=="0001-01-01T00:00:00Z"
def candidate_summary(value,source,state,base_revision,candidate_id,digest):
    keys={"id","sourceId","digest","format","state","baseRevision","nodeCount","duplicateCount","createdAt"}
    need(type(value)is dict and set(value)==keys,"candidate")
    need(value["id"]==candidate_id and C.CANDIDATE_ID.fullmatch(value["id"] or "") and value["sourceId"]==source and value["digest"]==digest and C.DIGEST.fullmatch(value["digest"] or ""),"candidate")
    need(value["format"]=="mihomo-provider-yaml" and value["state"]==state and value["baseRevision"]==base_revision and value["nodeCount"]==1 and value["duplicateCount"]==0,"candidate")
    nano(value["createdAt"])
    return value
def candidate_page(value):
    need(type(value)is dict and {"candidates","total","revision"}<=set(value)<={"candidates","total","revision","nextOffset"} and type(value["candidates"])is list and type(value["total"])is int and type(value["revision"])is int,"candidates")
    if "nextOffset" in value:need(type(value["nextOffset"])is int and value["nextOffset"]>=0,"candidates")
    return value
def source_page(value):
    need(type(value)is dict and set(value)=={"sources","total"} and type(value["sources"])is list and value["total"]==len(value["sources"]) and value["total"]<=32,"sources")
    for source in value["sources"]:
        need(type(source)is dict and {"id","scope","label","revision","updatedAt"}<=set(source)<={"id","scope","label","revision","acceptedCandidateId","latestCandidateId","updatedAt"} and C.SOURCE_ID.fullmatch(source["id"] or "") and source["scope"]==C.SCOPE and type(source["label"])is str and source["label"] and type(source["revision"])is int and source["revision"]>0,"sources")
        nano(source["updatedAt"])
    return value
def receipt_validate(value,case,command,source,final):
    required={"commandId","kind","sourceId","revision","state","replayed","stateMayHaveChanged","auditRecorded","preparedAuditHash","resultAuditHash","completedAt"}
    allowed=required|{"candidateId","candidateDigest","code","localAuditHash","referenceId","policyRevision","policyDigest","approvalId"}
    need(type(value)is dict and required<=set(value)<=allowed,"receipt")
    need(value["commandId"]==command and value["kind"]=="fetch" and value["sourceId"]==source and value["replayed"]is False and value["stateMayHaveChanged"]is False and value["auditRecorded"]is True,"receipt")
    need(all(re.fullmatch(r"[a-f0-9]{64}",value[k] or "") for k in ("preparedAuditHash","resultAuditHash")) and nano(value["completedAt"])>=nano(final["startedAt"]),"receipt")
    if case=="success":
        need(value["state"]=="committed" and value["revision"]==4 and value.get("candidateId")==final["candidateId"] and value.get("candidateDigest")==final["candidateDigest"] and re.fullmatch(r"[a-f0-9]{64}",value.get("localAuditHash","") or "") and "code" not in value,"receipt")
    else:
        need(value["state"]=="failed" and value["revision"]==3 and value.get("code")=="subscription_fetch_http_rejected" and not ({"candidateId","candidateDigest","localAuditHash"}&set(value)),"receipt")
    return value
def mutation_receipt_validate(value,kind,source,revision,state,candidate="",digest="",reference=""):
    allowed={"commandId","kind","sourceId","candidateId","revision","candidateDigest","state","code","replayed","stateMayHaveChanged","auditRecorded","preparedAuditHash","resultAuditHash","localAuditHash","referenceId","policyRevision","policyDigest","approvalId","completedAt"}
    required={"commandId","kind","sourceId","revision","state","replayed","stateMayHaveChanged","auditRecorded","preparedAuditHash","resultAuditHash","completedAt"}
    need(type(value)is dict and required<=set(value)<=allowed and C.COMMAND.fullmatch(value["commandId"] or "") and value["kind"]==kind and value["sourceId"]==source and value["revision"]==revision and value["state"]==state and value["replayed"]is False and value["stateMayHaveChanged"]is False and value["auditRecorded"]is True and all(re.fullmatch(r"[a-f0-9]{64}",value[k] or "") for k in ("preparedAuditHash","resultAuditHash")),"mutation-receipt")
    nano(value["completedAt"]);need("code" not in value,"mutation-receipt")
    if candidate:need(value.get("candidateId")==candidate and value.get("candidateDigest")==digest and C.DIGEST.fullmatch(digest or ""),"mutation-receipt")
    else:need(not ({"candidateId","candidateDigest"}&set(value)),"mutation-receipt")
    if state=="committed":need(re.fullmatch(r"[a-f0-9]{64}",value.get("localAuditHash","") or "") and not ({"referenceId","policyRevision","policyDigest","approvalId"}&set(value)),"mutation-receipt")
    else:need(state=="approved" and value.get("referenceId")==reference and value.get("policyRevision")==1 and C.DIGEST.fullmatch(value.get("policyDigest","") or "") and value.get("approvalId")==value["commandId"] and "localAuditHash" not in value,"mutation-receipt")
    return value
def approval_receipt_validate(value,case,command,source):
    required={"commandId","kind","sourceId","revision","state","replayed","stateMayHaveChanged","auditRecorded","preparedAuditHash","resultAuditHash","referenceId","policyRevision","policyDigest","approvalId","completedAt"}
    allowed=required|{"candidateId","candidateDigest","code","localAuditHash"}
    need(type(value)is dict and required<=set(value)<=allowed and value["commandId"]==command and value["approvalId"]==command and value["kind"]=="approve" and value["sourceId"]==source and value["revision"]==3 and value["state"]=="approved" and value["referenceId"]==case and value["policyRevision"]==1 and C.DIGEST.fullmatch(value["policyDigest"]) and value["replayed"]is False and value["stateMayHaveChanged"]is False and value["auditRecorded"]is True and not ({"candidateId","candidateDigest","code","localAuditHash"}&set(value)),"approval-receipt")
    need(all(re.fullmatch(r"[a-f0-9]{64}",value[k] or "") for k in ("preparedAuditHash","resultAuditHash")),"approval-receipt");return value
def contract_paths(repo):
    raw=subprocess.check_output(["git","-c","safe.directory="+str(repo),"-c","core.fsmonitor=false","-C",str(repo),"ls-tree","-r","--name-only","HEAD"],stderr=subprocess.DEVNULL,timeout=30)
    tracked={line.decode("utf-8","strict") for line in raw.splitlines()}
    conservative={name for name in tracked if name.startswith("chengwang/") and not name.startswith(("chengwang/deploy/","chengwang/docs/"))}
    return conservative|set(C.SOURCE_CONTRACT_SCENE)
def source_contract(repo, path):
    value=decode(read(path,1<<20));need(set(value)=={"schema","baseCommit","inventory","paths"} and value.get("schema")=="chengwang.joint-control-plane-source-contract/v1" and re.fullmatch(r"[a-f0-9]{40}",value.get("baseCommit","")) and value.get("paths"),"source-contract")
    expected=contract_paths(repo);inventory=value["inventory"];need(inventory=={"scope":"tracked-chengwang-nondeploy-nondocs-plus-joint-scene","excluded":[".github/workflows/chengwang-joint-control-plane.yml","chengwang/deploy/joint-control-plane/source_contract.json"],"pathCount":len(expected)},"source-contract")
    need([row.get("path") for row in value["paths"]]==sorted(expected),"source-contract")
    for row in value["paths"]:
        need(set(row)=={"path","sha256"} and re.fullmatch(r"[a-f0-9]{64}",row["sha256"]),"source-contract")
        need(C.sha(read(repo/row["path"],4<<20))==row["sha256"],"source-contract")
    return value
def source_snapshot(repo,commit):
    repo=pathlib.Path(repo).resolve()
    def git(*args):return subprocess.check_output(["git","-c","safe.directory="+str(repo),"-c","core.fsmonitor=false","-C",str(repo),*args],stderr=subprocess.DEVNULL,timeout=30)
    need(git("rev-parse","HEAD").decode().strip()==commit and not git("status","--porcelain","--untracked-files=all"),"source-snapshot")
    entries=git("ls-tree","-rz","--full-tree",commit).split(b"\0");rows=[]
    for item in sorted(x for x in entries if x):
        meta,name_raw=item.split(b"\t",1);mode,kind,oid=meta.decode().split();name=name_raw.decode("utf-8","strict");need(kind=="blob" and mode in ("100644","100755"),"source-snapshot")
        data=read(repo/name,4<<20);need(data==git("cat-file","blob",oid),"source-snapshot");rows.append({"path":name,"mode":mode,"blobOID":oid,"bytes":len(data),"sha256":C.sha(data)})
    need(rows and len(rows)==len(entries)-1,"source-snapshot");return rows
def check(directory,repo,contract_path,source_commit):
    directory=pathlib.Path(directory);repo=pathlib.Path(repo);need({p.name for p in directory.iterdir()}==set(C.PUBLIC_FILES),"files")
    contract=source_contract(repo,contract_path);need(contract.get("baseCommit")=="736bfdd1f8182e958cea26987f85683e2c6aee39","source-contract")
    expected=source_snapshot(repo,source_commit)
    for name in ("source-before.json","source-after.json"):need(decode(read(directory/name))==expected,"source-snapshot")
    need(read(directory/"source-before.json")==read(directory/"source-after.json"),"source-mutation")
    build=decode(read(directory/"build.json"));need(set(build)=={"schema","sourceCommit","goVersion","moduleMode","dependencyDownloads","production","authorization","server"} and build["sourceCommit"]==source_commit and build["goVersion"]=="go1.23.12" and build["moduleMode"]=="vendor" and build["dependencyDownloads"]is False and build["production"]is False and build["authorization"]=="BLOCKED","build")
    isolation=decode(read(directory/"isolation.json"));need(isolation.get("interfaces")==["lo"] and isolation.get("ipv4Addresses")==["127.0.0.1/8","8.8.4.4/32"] and not isolation.get("ipv4DefaultRoutes") and not isolation.get("ipv6DefaultRoutes") and isolation.get("unprivilegedPortStart")==0 and isolation.get("capabilities")=="0000000000000000" and isolation.get("noNewPrivileges")==1,"isolation")
    runtime=decode(read(directory/"runtime.json"));need(runtime.get("schema")==C.RUNTIME_SCHEMA and runtime.get("sourceCommit")==source_commit and re.fullmatch(r"joint-[a-f0-9]{32}",runtime.get("fixtureId","") or "") and runtime.get("sameBinaryAllEpochs")is True,"runtime")
    need(set(build["server"])=={"bytes","sha256"} and build["server"]["bytes"]>1024 and build["server"]["sha256"]==runtime.get("serverBinarySHA256") and re.fullmatch(r"[a-f0-9]{64}",runtime.get("serverBinarySHA256","") or ""),"build")
    processes=runtime.get("processes");need(type(processes)is list and [p.get("epoch") for p in processes]==["B0","J1","R2"] and len({p["pid"] for p in processes})==3,"epochs")
    for p in processes:
        need(p.get("exeSHA256")==runtime["serverBinarySHA256"] and re.fullmatch(r"[a-f0-9]{64}",p.get("argvSHA256","") or "") and p.get("normalStop")is True and p.get("uid")==C.UID and p.get("gid")==C.GID and p.get("capabilities")=="0000000000000000" and p.get("noNewPrivileges")==1 and int(p["startedUnixNano"])<int(p["stoppedUnixNano"]),"process")
        listener=p.get("listener",{});need(set(listener)=={"fd","inode","procFdTarget","port","localAddress","procNet","ownerPID","ownerStartTicks"} and listener["fd"]>=0 and str(listener["inode"]).isdigit() and listener["procFdTarget"]=="socket:["+listener["inode"]+"]" and listener["port"]==C.API[1] and listener["localAddress"]==C.API[0] and listener["procNet"]=={"localHex":"0100007F:45CF","remoteHex":"00000000:0000","stateHex":"0A"} and listener["ownerPID"]==p["pid"] and listener["ownerStartTicks"]==p["startTicks"],"listener")
    need(len({p["startTicks"] for p in processes})==3 and len({p["argvSHA256"] for p in processes})==1,"process")
    fixture=runtime["fixtureProcess"]
    need(fixture.get("normalStop")is True and fixture.get("uid")==C.UID and fixture.get("gid")==C.GID and fixture.get("capabilities")=="0000000000000000" and fixture.get("noNewPrivileges")==1 and int(fixture["startedUnixNano"])<int(fixture["stoppedUnixNano"]),"fixture-process")
    for key,iso_key in (("netNamespace","netNamespace"),("mountNamespace","mountNamespace"),("pidNamespace","pidNamespace")):
        need(all(p[key]==fixture[key]==isolation[iso_key] for p in processes),"namespace")
    api_peer=cert_der_sha(directory/"api-leaf.pem")
    rows=[decode(line) for line in read(directory/"captures.jsonl").splitlines()];need(rows and all(r.get("ordinal")==i and r.get("schema")==C.CAPTURE_SCHEMA and r.get("tlsPeerSHA256")==api_peer for i,r in enumerate(rows,1)),"captures")
    wire_raw=read(directory/"wire-events.jsonl");wire_lines=wire_raw.splitlines(keepends=True);wire=[decode(x) for x in wire_lines]
    wire_keys={"schema","ordinal","service","event","reference","method","path","status","bytes","fixturePid","connection","sourceHost","tlsClass","authClass","responseClass","receivedUnixNano"}
    need(wire and all(set(v)==wire_keys and v["ordinal"]==i and v["schema"]==C.WIRE_SCHEMA and v["fixturePid"]==fixture["pid"] and v["connection"] and v["tlsClass"]=="server_tls" and int(fixture["startedUnixNano"])<=int(v["receivedUnixNano"])<=int(fixture["stoppedUnixNano"]) for i,v in enumerate(wire,1)),"wire")
    named={}
    for r in rows:
        named.setdefault(r["name"],[]).append(r);need(0<=r["wireBefore"]["events"]<=r["wireAfter"]["events"]<=len(wire),"fence")
        for fence in (r["wireBefore"],r["wireAfter"]):need(C.sha(b"".join(wire_lines[:fence["events"]]))==fence["sha256"],"fence")
        if r["wireAfter"]["events"]:need(int(wire[r["wireAfter"]["events"]-1]["receivedUnixNano"])<=int(r["receivedUnixNano"]),"fence-time")
        process=next(p for p in processes if p["epoch"]==r["epoch"]);need(int(process["startedUnixNano"])<=int(r["receivedUnixNano"])<=int(process["stoppedUnixNano"]),"capture-lifetime")
        need(r["commandIdHeader"] is None or C.COMMAND.fullmatch(r["commandIdHeader"]),"command-header")
        result=envelope(r)
        if r["commandIdHeader"] is not None:need(type(result)is dict and result.get("commandId")==r["commandIdHeader"],"command-header")
        if r["name"].endswith("-refresh-poll") and r["status"]==200:C.refresh_keys(result)
    need(set(named)==C.CAPTURE_NAMES and all(len(v)==1 or k.endswith("-refresh-poll") for k,v in named.items()),"capture-plan")
    global_plan={
        "anonymous-list":("B0","anonymous","/api/v1/subscriptions/sources",401),"foreign-list":("B0","foreign","/api/v1/subscriptions/sources",403),
        "overview-anonymous":("J1","anonymous","/api/v1/overview",200),"mihomo-status-anonymous":("J1","anonymous","/api/v1/kernels/mihomo/status",200),
        "mihomo-runtime-viewer":("J1","viewer","/api/v1/kernels/mihomo/runtime",200),"mihomo-runtime-anonymous-denied":("J1","anonymous","/api/v1/kernels/mihomo/runtime",401),
        "mihomo-runtime-foreign-denied":("J1","foreign","/api/v1/kernels/mihomo/runtime",403),"r2-sources":("R2","viewer","/api/v1/subscriptions/sources",200),}
    for name,(epoch,role,path,status) in global_plan.items():
        row=named[name][0];need((row["epoch"],row["role"],row["method"],row["path"],row["status"],row["request"])==(epoch,role,"GET",path,status,{"body":None,"idempotencyKey":""}),"capture-plan")
    terminals={}
    for case in C.SOURCE_HOSTS:
        def one(suffix):need(len(named.get(case+suffix,[]))==1,"capture-plan");return named[case+suffix][0]
        create_result=envelope(one("-create"));sid=create_result["sourceId"]
        expected=[("-viewer-create-neg","viewer","POST","/api/v1/subscriptions/sources","viewer_create_neg",403),("-create","operator","POST","/api/v1/subscriptions/sources","create_source",200),("-operator-approve-neg","operator","POST",f"/api/v1/subscriptions/sources/{sid}/approvals","operator_approve_r1_neg",403),("-approve-r1","approver","POST",f"/api/v1/subscriptions/sources/{sid}/approvals","approve_r1",200),("-fetch-r1","operator","POST",f"/api/v1/subscriptions/sources/{sid}/fetches","fetch_r1",200),("-admit-r2","approver","POST",f"/api/v1/subscriptions/sources/{sid}/decisions","admit_r2",200),("-approve-r3","approver","POST",f"/api/v1/subscriptions/sources/{sid}/approvals","approve_r3",200)]
        for suffix,role,method,path,op,status in expected:
            row=one(suffix);need((row["role"],row["method"],row["path"],row["request"]["idempotencyKey"],row["status"])==(role,method,path,C.idempotency(case,op),status),"capture-plan")
        approve1=envelope(one("-approve-r1"));fetch1=envelope(one("-fetch-r1"));decision=envelope(one("-admit-r2"));approve3=envelope(one("-approve-r3"))
        mutation_receipt_validate(create_result,"create",sid,1,"committed")
        mutation_receipt_validate(approve1,"approve",sid,1,"approved",reference=case)
        mutation_receipt_validate(fetch1,"fetch",sid,2,"committed",fetch1.get("candidateId",""),fetch1.get("candidateDigest",""))
        mutation_receipt_validate(decision,"decide",sid,3,"committed",fetch1.get("candidateId",""),fetch1.get("candidateDigest",""))
        mutation_receipt_validate(approve3,"approve",sid,3,"approved",reference=case)
        fetch_capture=one("-fetch-r1");fetch_wire=wire[fetch_capture["wireBefore"]["events"]:fetch_capture["wireAfter"]["events"]]
        need(len(fetch_wire)==3 and [(v["service"],v["responseClass"]) for v in fetch_wire]==[("dot","dns_answer"),("dot","dns_nodata"),("source","success")],"bootstrap-wire-sequence")
        b0=processes[0];need(all(int(b0["startedUnixNano"])<=int(v["receivedUnixNano"])<=int(fetch_capture["receivedUnixNano"]) for v in fetch_wire),"bootstrap-wire-lifetime")
        need(all(v["reference"]==C.SOURCE_HOSTS[case] and v["status"]==200 and v["authClass"]=="not_applicable" for v in fetch_wire[:2]),"bootstrap-dot-wire")
        need(fetch_wire[2]["reference"]==case and fetch_wire[2]["sourceHost"]==C.SOURCE_HOSTS[case] and fetch_wire[2]["method"]=="GET" and fetch_wire[2]["path"]=="/subscription" and fetch_wire[2]["status"]==200 and fetch_wire[2]["authClass"]=="source_secret_accepted","bootstrap-source-wire")
        need(C.COMMAND.fullmatch(approve1.get("commandId","") or "") and C.COMMAND.fullmatch(approve3.get("commandId","") or "") and C.CANDIDATE_ID.fullmatch(fetch1.get("candidateId","") or "") and C.DIGEST.fullmatch(fetch1.get("candidateDigest","") or ""),"mutation-result")
        need(one("-viewer-create-neg")["request"]["body"]==one("-create")["request"]["body"]=={"label":case},"capture-body")
        need(one("-operator-approve-neg")["request"]["body"]==one("-approve-r1")["request"]["body"]=={"referenceId":case,"policyRevision":1,"expectedRevision":1},"capture-body")
        need(one("-fetch-r1")["request"]["body"]=={"approvalId":approve1["commandId"],"policyRevision":1,"expectedRevision":1},"capture-body")
        need(one("-admit-r2")["request"]["body"]=={"candidateId":fetch1["candidateId"],"expectedRevision":2,"expectedDigest":fetch1["candidateDigest"],"decision":"admitted_local"},"capture-body")
        need(one("-approve-r3")["request"]["body"]=={"referenceId":case,"policyRevision":1,"expectedRevision":3},"capture-body")
        need(named[case+"-viewer-create-neg"][0]["status"]==403 and named[case+"-operator-approve-neg"][0]["status"]==403,"rbac")
        read_plan=(("-baseline-source","B0","viewer","/api/v1/subscriptions/sources"),("-baseline-candidates","B0","viewer",f"/api/v1/subscriptions/sources/{sid}/candidates?limit=100&offset=0&revision=3"),("-approval-receipt","B0","auditor","/api/v1/subscriptions/commands/"+approve3["commandId"]),("-worker-receipt-auditor","J1","auditor",None),("-worker-receipt-viewer-denied","J1","viewer",None),("-worker-receipt-operator-denied","J1","operator",None),("-r2-worker-receipt","R2","auditor",None),("-r2-candidates","R2","viewer",f"/api/v1/subscriptions/sources/{sid}/candidates?limit=100&offset=0&revision="+("4" if case=="success" else "3")))
        for suffix,epoch,role,path in read_plan:
            row=one(suffix);expected_status=403 if suffix.endswith("denied") else 200
            if path is not None:need((row["epoch"],row["role"],row["method"],row["path"],row["status"],row["request"])==(epoch,role,"GET",path,expected_status,{"body":None,"idempotencyKey":""}),"capture-plan")
            else:need((row["epoch"],row["role"],row["method"],row["status"],row["request"])==(epoch,role,"GET",expected_status,{"body":None,"idempotencyKey":""}),"capture-plan")
        finals=[envelope(r) for r in named[case+"-refresh-poll"]]
        need(all((r["epoch"],r["role"],r["method"],r["path"],r["status"],r["request"])==("J1","viewer","GET",f"/api/v1/subscriptions/sources/{sid}/refresh",200,{"body":None,"idempotencyKey":""}) for r in named[case+"-refresh-poll"]),"capture-plan")
        final=finals[-1];terminals[case]=final;state="candidate_quarantined" if case=="success" else "failed";need(final["state"]==state,"refresh-terminal")
        need(final["scope"]==C.SCOPE and final["bindingGeneration"]==1 and final["clockState"]=="normal" and not final.get("clockReason") and final["stale"]is False and final.get("storagePending",False)is False and final.get("storageRetryCount",0)==0 and zero_or_absent(final,"storageNextRetryAt") and nano(final["completedAt"])>=nano(final["startedAt"]),"refresh-terminal")
        if case=="success":need(final["lastSuccessAt"]==final["completedAt"] and nano(final["freshUntil"])==nano(final["completedAt"])+300_000_000_000 and zero_or_absent(final,"nextAttemptAt"),"refresh-terminal")
        else:need(zero_or_absent(final,"lastSuccessAt") and zero_or_absent(final,"freshUntil") and nano(final["nextAttemptAt"])==nano(final["completedAt"])+60_000_000_000,"refresh-terminal")
        binding=final["binding"];need(binding=={"sourceId":envelope(named[case+"-create"][0])["sourceId"],"referenceId":case,"policyRevision":1,"approvalId":envelope(named[case+"-approve-r3"][0])["commandId"],"approvalSourceRevision":3,"intervalSeconds":60,"approvalTtlSeconds":600,"maxStaleSeconds":300,"maxBackoffSeconds":600},"binding")
        poll=named[case+"-refresh-poll"][-1]
        j1_process=processes[1];need(int(j1_process["startedUnixNano"])<=nano(final["startedAt"])<=nano(final["completedAt"])<=int(j1_process["stoppedUnixNano"]),"refresh-process-lifetime")
        refresh_wire=[v for v in wire if nano(final["startedAt"])<=int(v["receivedUnixNano"])<=nano(final["completedAt"]) and ((v["service"]=="dot" and v["reference"]==C.SOURCE_HOSTS[case]) or (v["service"]=="source" and v["reference"]==case and v["sourceHost"]==C.SOURCE_HOSTS[case]))]
        need(len(refresh_wire)==3 and [(v["service"],v["responseClass"]) for v in refresh_wire]==[("dot","dns_answer"),("dot","dns_nodata"),("source","success" if case=="success" else "upstream_failure")],"refresh-wire-sequence")
        dot=refresh_wire[:2];relevant=refresh_wire[2]
        need(all(v["status"]==200 and v["method"]=="" and v["path"]=="" and v["sourceHost"]=="" and v["authClass"]=="not_applicable" for v in dot),"dot-wire")
        need(relevant["status"]==(200 if case=="success" else 503) and relevant["method"]=="GET" and relevant["path"]=="/subscription" and relevant["authClass"]=="source_secret_accepted" and all(v["ordinal"]<=poll["wireBefore"]["events"] for v in refresh_wire),"wire-command")
        command=finals[-1].get("commandId");need(C.COMMAND.fullmatch(command or "") and finals[-1].get("commandOwnerId")==C.MACHINE_ID and finals[-1].get("commandEpoch"),"worker-command")
        for suffix in ("-worker-receipt-auditor","-worker-receipt-viewer-denied","-worker-receipt-operator-denied","-r2-worker-receipt"):
            row=one(suffix);need(row["path"]=="/api/v1/subscriptions/commands/"+command,"capture-plan")
        receipt=receipt_validate(envelope(named[case+"-worker-receipt-auditor"][0]),case,command,sid,final);r2receipt=receipt_validate(envelope(named[case+"-r2-worker-receipt"][0]),case,command,sid,final);need(named[case+"-worker-receipt-auditor"][0]["status"]==200 and receipt==r2receipt and named[case+"-worker-receipt-viewer-denied"][0]["status"]==403 and named[case+"-worker-receipt-operator-denied"][0]["status"]==403,"receipt-rbac")
        approval_receipt_validate(envelope(one("-approval-receipt")),case,approve3["commandId"],sid)
        baseline_sources=source_page(envelope(one("-baseline-source")));need(baseline_sources["total"]==(1 if case=="success" else 2) and any(x["id"]==sid and x["label"]==case and x["revision"]==3 and x["acceptedCandidateId"]==fetch1["candidateId"] and x["latestCandidateId"]==fetch1["candidateId"] for x in baseline_sources["sources"]),"baseline-source")
        baseline=candidate_page(envelope(named[case+"-baseline-candidates"][0]));r2=candidate_page(envelope(named[case+"-r2-candidates"][0]));need(baseline["total"]==1 and baseline["revision"]==3 and len(baseline["candidates"])==1,"candidates")
        candidate_summary(baseline["candidates"][0],sid,"admitted_local",fetch1["revision"],fetch1["candidateId"],fetch1["candidateDigest"])
        if case=="success":
            need(r2["total"]==2 and r2["revision"]==4 and len(r2["candidates"])==2,"candidates")
            by_id={x.get("id"):x for x in r2["candidates"]};need(len(by_id)==2 and set(by_id)=={fetch1["candidateId"],final["candidateId"]},"candidates")
            candidate_summary(by_id[fetch1["candidateId"]],sid,"admitted_local",fetch1["revision"],fetch1["candidateId"],fetch1["candidateDigest"])
            need(final["resultRevision"]==receipt["revision"],"candidates")
            candidate_summary(by_id[final["candidateId"]],sid,"quarantined",final["resultRevision"],final["candidateId"],final["candidateDigest"])
        else:need(r2==baseline,"candidates")
    need(len({v["attemptSequence"] for v in terminals.values()})==2 and len({v["attemptKey"] for v in terminals.values()})==2 and len({v["fence"] for v in terminals.values()})==2 and len({v["commandId"] for v in terminals.values()})==2 and len({v["commandEpoch"] for v in terminals.values()})==1,"worker-command")
    need(named["anonymous-list"][0]["status"]==401 and named["foreign-list"][0]["status"]==403 and named["overview-anonymous"][0]["status"]==200,"rbac")
    overview=envelope(named["overview-anonymous"][0]);need(set(overview)=={"schema","dataSource","generatedAt","mode","readOnly","advisoryOnly","coverage","observation","probe","subscription","unsupported"} and overview.get("schema")=="chengwang.overview-snapshot/v1" and overview.get("dataSource")=="live" and type(overview.get("mode"))is str and overview["mode"] and overview.get("readOnly")is True and overview.get("advisoryOnly")is True,"overview");nano(overview["generatedAt"])
    need(set(overview["coverage"])=={"state","missing"} and overview["coverage"]["state"] in ("none","partial") and type(overview["coverage"]["missing"])is list,"overview")
    observation=overview["observation"];need(set(observation)=={"configured","running","fresh","stale","lastAttemptAt","lastSuccessAt","consecutiveFailures","controller","storage","clock"},"overview")
    for layer in (observation["controller"],observation["storage"],observation["clock"]):need(set(layer)=={"state","reason","observedAt","expiresAt"} and layer["state"] in ("unknown","available","degraded","unavailable") and (layer["observedAt"]is None or nano(layer["observedAt"])) and (layer["expiresAt"]is None or nano(layer["expiresAt"])),"overview")
    probe=overview["probe"];need(set(probe)=={"configured","running","state","reason","clockHealthy","storageHealthy","cachedAt","expiresAt","coverageState","coverage"} and probe["state"] in ("disabled","pending","unknown","partial","ready") and probe["coverageState"] in ("current","unavailable"),"overview")
    need(set(overview["subscription"])=={"configured","inventoryState","sourceCount","nodeCount"} and set(overview["unsupported"])=={"businesses","nodePools","endToEndDNS","deviceInventory","trafficTopology"} and all(overview["unsupported"].values()),"overview")
    need(overview.get("subscription",{}).get("configured")is True and overview.get("subscription",{}).get("inventoryState")=="protected_not_read" and overview.get("subscription",{}).get("sourceCount")is None and overview.get("subscription",{}).get("nodeCount")is None,"overview")
    need(overview.get("observation",{}).get("configured")is True and overview.get("observation",{}).get("running")is True and overview.get("observation",{}).get("fresh")is True and overview.get("observation",{}).get("stale")is False,"overview")
    need(named["mihomo-status-anonymous"][0]["status"]==200 and named["mihomo-runtime-viewer"][0]["status"]==200 and named["mihomo-runtime-anonymous-denied"][0]["status"]==401 and named["mihomo-runtime-foreign-denied"][0]["status"]==403,"mihomo-rbac")
    status=envelope(named["mihomo-status-anonymous"][0]);need(set(status)=={"configured","reachable","fresh","stale","observedAt"} and status["configured"]is True and type(status["reachable"])is bool and type(status["fresh"])is bool and type(status["stale"])is bool,"mihomo-status");nano(status["observedAt"])
    runtime_view=envelope(named["mihomo-runtime-viewer"][0]);need(set(runtime_view)=={"observedAt","version","config","proxies","rules"} and set(runtime_view["version"])=={"version","meta","premium"} and set(runtime_view["config"])=={"mode","allowLan","bindAddress","ipv6","port","socksPort","mixedPort","redirPort","tproxyPort","externalController"} and type(runtime_view["proxies"])is list and type(runtime_view["rules"])is list,"mihomo-runtime");nano(runtime_view["observedAt"])
    for name,code in (("mihomo-runtime-anonymous-denied","unauthorized"),("mihomo-runtime-foreign-denied","forbidden")):
        error=envelope(named[name][0]);need(set(error)=={"code","message"} and error["code"]==code and type(error["message"])is str and error["message"],"mihomo-rbac")
    j1=processes[1];mihomo=[v for v in wire if v["service"]=="mihomo" and int(j1["startedUnixNano"])<=int(v["receivedUnixNano"])<=int(j1["stoppedUnixNano"])]
    need({v["path"] for v in mihomo}=={"/version","/configs","/proxies","/rules"} and all(v["method"]=="GET" and v["status"]==200 and v["sourceHost"]==C.SOURCE_IP and v["authClass"]=="readonly_bearer_accepted" and v["responseClass"]=="success" for v in mihomo),"mihomo-wire")
    source_wire=[v for v in wire if v["service"]=="source"]
    need(len(source_wire)==4 and all(v["method"]=="GET" and v["path"]=="/subscription" and v["reference"] in C.SOURCE_HOSTS and v["sourceHost"]==C.SOURCE_HOSTS[v["reference"]] and v["status"] in (200,503) and v["authClass"]=="source_secret_accepted" for v in source_wire),"source-wire")
    need([v["status"] for v in source_wire if v["reference"]=="success"]==[200,200] and [v["status"] for v in source_wire if v["reference"]=="failure"]==[200,503],"source-wire")
    need(all(v["service"] in ("source","mihomo","dot") and (v["service"]!="dot" or (v["authClass"]=="not_applicable" and v["method"]=="" and v["path"]=="" and v["sourceHost"]=="" and v["status"]==200 and v["responseClass"] in ("dns_answer","dns_nodata"))) for v in wire),"wire")
    private=decode(read(directory/"private-checks.json"));need(private.get("schema")=="chengwang.joint-control-plane-private-checks/v2" and private["policyTransition"]["baseEqualAfterRemovingRefresh"]is True and private["identityTransition"]=={"humanIdentitiesUnchanged":True,"bootstrapMachineOmitted":True,"refreshMachineExact":True,"humanCount":5,"machineScopeCount":2} and private["sidecar"]["unchanged"]is True and private["publicationScan"]["result"]=="PASS" and private["privateMaterialPublished"]is False,"private-checks")
    scan=private["publicationScan"];manifest=[{"path":name,"bytes":len(read(directory/name)),"sha256":C.sha(read(directory/name))} for name in sorted(set(C.PUBLIC_FILES)-{"private-checks.json","source-after.json"})]
    need(scan.get("publicFiles")==manifest and scan.get("filesScanned")==len(manifest) and scan.get("bytesScanned")==sum(x["bytes"] for x in manifest) and scan.get("sourceAfterBinding")=="byte_equal_to_source-before.json","private-checks")
    need([x["referenceId"] for x in private["policyTransition"]["bindings"]]==["failure","success"] and all(x["changedKeys"]==["refresh"] for x in private["policyTransition"]["bindings"]),"private-checks")
    transitions={x["referenceId"]:x for x in private["policyTransition"]["bindings"]}
    for case in C.SOURCE_HOSTS:
        need(transitions[case]=={"referenceId":case,"changedKeys":["refresh"],"sourceId":envelope(named[case+"-create"][0])["sourceId"],"approvalId":envelope(named[case+"-approve-r3"][0])["commandId"],"approvalSourceRevision":3,"intervalSeconds":60,"approvalTtlSeconds":600,"maxStaleSeconds":300,"maxBackoffSeconds":600},"private-checks")
    readback=decode(read(directory/"readback.json"));need(readback.get("schema")==C.READBACK_SCHEMA and readback.get("sourceCommit")==source_commit and readback.get("fixtureId")==runtime["fixtureId"] and readback.get("sidecarUnchanged")is True and readback.get("refreshRestartPersistenceProven")is False,"readback")
    need(readback["jointCounts"]["commands"]>=readback["bootstrapCounts"]["commands"]+2 and readback["jointCounts"]["audit"]>readback["bootstrapCounts"]["audit"],"worker-delta")
    need(readback.get("workerReceipts")=={case:envelope(named[case+"-r2-worker-receipt"][0]) for case in C.SOURCE_HOSTS},"readback")
    source_rows=source_page(readback["sources"])["sources"];sources={s["id"]:s for s in source_rows};need(len(source_rows)==len(sources)==2,"readback")
    success=next(s for s in sources.values() if s["id"]==envelope(named["success-create"][0])["sourceId"]);failure=next(s for s in sources.values() if s["id"]==envelope(named["failure-create"][0])["sourceId"])
    need(success["revision"]==4 and success["acceptedCandidateId"]!=success["latestCandidateId"],"accepted-preservation")
    need(failure["revision"]==3 and failure["acceptedCandidateId"]==failure["latestCandidateId"],"failure-preservation")
    need(any(v["service"]=="source" and v["reference"]=="success" and v["status"]==200 for v in wire) and any(v["service"]=="source" and v["reference"]=="failure" and v["status"]==503 for v in wire) and all(v.get("path","").find("token=")<0 for v in wire),"wire-business")
    negatives=decode(read(directory/"transport-negatives.json"));need(negatives=={"schema":"chengwang.joint-control-plane-transport-negatives/v2","cases":[{"case":"wrong_ca","result":"tls_verification_rejected"},{"case":"plaintext_http","result":"no_http_response"},{"case":"duplicate_authorization","result":"401"}]},"transport-negatives")
    cert_validate(directory/"api-ca.pem",directory/"api-leaf.pem",["IP Address:127.0.0.1"]);cert_validate(directory/"resolver-ca.pem",directory/"resolver-leaf.pem",["DNS:"+C.DOT_NAME]);cert_validate(directory/"source-ca.pem",directory/"source-leaf.pem",["DNS:"+x for x in C.SOURCE_HOSTS.values()]);cert_validate(directory/"mihomo-ca.pem",directory/"mihomo-leaf.pem",["IP Address:8.8.4.4"])
    outcome=decode(read(directory/"outcome.json"));need(outcome==C.outcome(source_commit,runtime["fixtureId"],"CAPTURED"),"outcome")
    for p in directory.iterdir():
        raw=read(p);need(b"PRIVATE KEY" not in raw and b"Bearer " not in raw and b"?token=" not in raw,"secret")
    return {"schema":"chengwang.joint-control-plane-verification/v2","sourceCommit":source_commit,"fixtureId":runtime["fixtureId"],"status":"PASS","production":False,"actualSKU":"UNKNOWN","authorization":"BLOCKED","runtimeAcceptanceProven":True,"refreshRestartPersistenceProven":False}
def main():
    p=argparse.ArgumentParser();p.add_argument("--evidence",required=True);p.add_argument("--repo",required=True);p.add_argument("--contract",required=True);p.add_argument("--source-commit",required=True);p.add_argument("--output",required=True);a=p.parse_args();value=check(a.evidence,a.repo,a.contract,a.source_commit);path=pathlib.Path(a.output);need(not path.exists(),"output");path.write_bytes(C.canonical(value))
if __name__=="__main__":
    try:main()
    except Exception:print("JOINT_CONTROL_PLANE_CHECK=REJECTED",file=sys.stderr);raise SystemExit(1) from None
