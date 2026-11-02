"""Independent private/public publication boundary; never uploads raw diagnostics."""
from __future__ import annotations
import argparse, base64, hashlib, importlib.util, json, os, pathlib, re, shutil, sys, tempfile, urllib.parse

HERE=pathlib.Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("joint_publication_contract",HERE/"contract.py");C=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(C)

MAX_FILE=16<<20; MAX_TOTAL=64<<20
PUBLIC={"build.json","source-before.json","source-after.json","isolation.json","runtime.json","captures.jsonl","wire-events.jsonl","readback.json","outcome.json","api-ca.pem","api-leaf.pem","resolver-ca.pem","resolver-leaf.pem","source-ca.pem","source-leaf.pem","mihomo-ca.pem","mihomo-leaf.pem","private-checks.json","transport-negatives.json"}
CPU_DIAGNOSTIC={"schema":"chengwang.joint-control-plane-cpu-diagnostic/v1","failureCode":"CPU_DIAGNOSTIC_UNAVAILABLE","status":"FAIL","production":False,"authorization":"BLOCKED","actualSKU":"UNKNOWN","privateEvidencePublished":False,"runtimeAcceptanceProven":False}
def need(ok):
    if not ok:raise ValueError("joint-publication-rejected")
def raw(path,maximum=MAX_FILE):
    p=pathlib.Path(path);before=p.lstat();need(p.is_file() and not p.is_symlink() and before.st_nlink==1 and 0<before.st_size<=maximum)
    fd=os.open(p,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(fd);need((opened.st_dev,opened.st_ino,opened.st_size)==(before.st_dev,before.st_ino,before.st_size) and opened.st_nlink==1)
        chunks=[];seen=0
        while True:
            chunk=os.read(fd,min(1<<20,maximum-seen+1))
            if not chunk:break
            chunks.append(chunk);seen+=len(chunk);need(seen<=maximum)
        after=os.fstat(fd);need((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns) and seen==opened.st_size)
        return b"".join(chunks)
    finally:os.close(fd)
def decode_bytes(data):return json.loads(data,object_pairs_hook=lambda p:_pairs(p),parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
def decode(path):return decode_bytes(raw(path))
def _pairs(pairs):
    out={}
    for k,v in pairs:need(k not in out);out[k]=v
    return out
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def write(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as f:f.write(data);f.flush();os.fsync(f.fileno())
def fsync_dir(path):
    if os.name!="posix":return
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
    try:os.fsync(fd)
    finally:os.close(fd)
def file_sha(path):
    h=hashlib.sha256();seen=0
    with open(path,"rb") as f:
        while True:
            chunk=f.read(1<<20)
            if not chunk:break
            seen+=len(chunk);need(seen<=256<<20);h.update(chunk)
    return h.hexdigest()
def failure_files(root):
    root=pathlib.Path(root);out=[];total=0
    if not root.is_dir():return out
    for current,dirs,names in os.walk(root,followlinks=False):
        base=pathlib.Path(current);need(all(not (base/d).is_symlink() for d in dirs));dirs[:]=sorted(dirs)
        for name in sorted(names):
            p=base/name;s=p.lstat();need(p.is_file() and not p.is_symlink() and s.st_nlink==1 and s.st_size<=256<<20)
            total+=s.st_size;need(total<=512<<20 and len(out)<8192);out.append(p)
    return out
def secret_variants(values):
    out=[]
    for value in values:
        b=value.encode() if isinstance(value,str) else value
        if len(b)>=8:out.extend((b,base64.b64encode(b),base64.urlsafe_b64encode(b),base64.b64encode(b).rstrip(b"="),urllib.parse.quote_from_bytes(b,safe="").encode(),hashlib.sha256(b).hexdigest().encode(),b.hex().encode()))
    return out
def private_check(root,input_dir,output):
    root=pathlib.Path(root);inp=pathlib.Path(input_dir)
    p0=decode(root/"policy0.json");p1=decode(root/"policy1.json");stripped=json.loads(json.dumps(p1))
    projections=[]
    for item in stripped["sources"]:
        refresh=item.pop("refresh",None);need(type(refresh)is dict and set(refresh)=={"sourceId","approvalId","approvalSourceRevision","intervalSeconds","approvalTtlSeconds","maxStaleSeconds","maxBackoffSeconds"})
        need(refresh["approvalSourceRevision"]==3 and refresh["intervalSeconds"]==60 and refresh["approvalTtlSeconds"]==600 and refresh["maxStaleSeconds"]==300 and refresh["maxBackoffSeconds"]==600)
        projections.append({"referenceId":item["referenceId"],"changedKeys":["refresh"],**refresh})
    need(stripped==p0 and {x["referenceId"] for x in projections}=={"success","failure"})
    i0=decode(root/"identities0.json");i1=decode(root/"identities1.json");need(i0.get("version")==i1.get("version")==1)
    humans0={x["tokenId"]:x for x in i0["identities"]};humans1={x["tokenId"]:x for x in i1["identities"] if x["tokenId"]!="refresh-machine"};need(humans0==humans1 and "refresh-machine" not in humans0 and len(humans0)==len(i0["identities"]))
    machines=[x for x in i1["identities"] if x["tokenId"]=="refresh-machine"];need(len(machines)==1 and len(i1["identities"])==len(i0["identities"])+1)
    principal=machines[0]["principal"];need(principal.get("id")=="refresh-machine" and principal.get("tenantId")=="joint-control-plane" and principal.get("roles")==["subscription_refresher"] and principal.get("breakGlassEligible",False)is False)
    grants=principal.get("allowedScopes");expected={x["sourceId"] for x in projections};need(type(grants)is list and len(grants)==len(expected) and {x["objectId"] for x in grants}==expected and all(x=={"tenantId":"joint-control-plane","siteId":"isolated","environment":"candidate","objectType":"subscription-source","objectId":x["objectId"]} for x in grants))
    before=decode(root/"sidecar-before.private.json");after=decode(root/"sidecar-after.private.json");need(before==after and type(before)is dict and before)
    side=root/"data/subscription-refresh-v3";current={str(p.relative_to(side)).replace("\\","/"):file_sha(p) for p in side.rglob("*") if p.is_file() and not p.is_symlink()};need(current==before)
    fixture=decode(root/"fixture-input.private.json");need(set(fixture)=={"sourceTokens","mihomoToken","bearerTokens","contentSecrets"})
    secrets=list(fixture["sourceTokens"].values())+[fixture["mihomoToken"]]+list(fixture["bearerTokens"].values())+fixture["contentSecrets"]
    secrets += [s["url"] for s in p0["sources"]]
    variants=secret_variants(secrets);total=0;cached={}
    expected=PUBLIC-{"private-checks.json","source-after.json"};need({p.name for p in inp.iterdir()}==expected)
    for name in sorted(expected):
        data=raw(inp/name);cached[name]=data;total+=len(data);need(total<=MAX_TOTAL and b"PRIVATE KEY" not in data and b"Bearer " not in data and b"?token=" not in data and not any(v in data for v in variants))
    manifest=[{"path":name,"bytes":len(cached[name]),"sha256":hashlib.sha256(cached[name]).hexdigest()} for name in sorted(cached)]
    value={"schema":"chengwang.joint-control-plane-private-checks/v2","policyTransition":{"baseEqualAfterRemovingRefresh":True,"bindings":sorted(projections,key=lambda x:x["referenceId"])},"identityTransition":{"humanIdentitiesUnchanged":True,"bootstrapMachineOmitted":True,"refreshMachineExact":True,"humanCount":len(humans0),"machineScopeCount":len(grants)},"sidecar":{"unchanged":True,"fileCount":len(before),"totalBytes":sum((side/k).stat().st_size for k in before)},"publicationScan":{"filesScanned":len(cached),"bytesScanned":total,"secretVariants":len(variants),"publicFiles":manifest,"sourceAfterBinding":"byte_equal_to_source-before.json","result":"PASS"},"privateMaterialPublished":False}
    write(output,canonical(value))
def publish(inp,out,verification):
    inp=pathlib.Path(inp);out=pathlib.Path(out);need(not out.exists() and out.parent.is_dir());names={p.name for p in inp.iterdir()};need(names==PUBLIC)
    cached={name:raw(inp/name) for name in sorted(PUBLIC)};verification_bytes=raw(verification,1<<20)
    total=sum(map(len,cached.values()))+len(verification_bytes);need(total<=MAX_TOTAL)
    need(all(b"PRIVATE KEY" not in data and b"Bearer " not in data and b"?token=" not in data for data in [*cached.values(),verification_bytes]))
    report=decode_bytes(verification_bytes);need(set(report)=={"schema","sourceCommit","fixtureId","status","production","actualSKU","authorization","runtimeAcceptanceProven","refreshRestartPersistenceProven"} and report.get("status")=="PASS" and report.get("runtimeAcceptanceProven")is True and report.get("refreshRestartPersistenceProven")is False and report.get("production")is False and report.get("actualSKU")=="UNKNOWN" and report.get("authorization")=="BLOCKED")
    checks=decode_bytes(cached["private-checks.json"]);scan=checks.get("publicationScan",{});manifest=scan.get("publicFiles")
    expected=[{"path":name,"bytes":len(cached[name]),"sha256":hashlib.sha256(cached[name]).hexdigest()} for name in sorted(PUBLIC-{"private-checks.json","source-after.json"})]
    need(scan.get("result")=="PASS" and manifest==expected and scan.get("filesScanned")==len(expected) and scan.get("bytesScanned")==sum(x["bytes"] for x in expected) and scan.get("sourceAfterBinding")=="byte_equal_to_source-before.json")
    need(cached["source-after.json"]==cached["source-before.json"])
    pending=pathlib.Path(tempfile.mkdtemp(prefix="."+out.name+".pending-",dir=out.parent))
    try:
        lab=pending/"lab";lab.mkdir(mode=0o700)
        for name in sorted(PUBLIC):write(lab/name,cached[name])
        write(pending/"verification.json",verification_bytes)
        fsync_dir(lab);fsync_dir(pending);fsync_dir(out.parent);need(not out.exists());os.replace(pending,out);fsync_dir(out.parent)
    except BaseException:
        if pending.exists():shutil.rmtree(pending)
        raise
def failure(inp,out,code,progress_root=None,source_commit=None,bootstrap_record=None,
            bootstrap_step_id=None,bootstrap_step_outcome=None,bootstrap_step_source=None):
    need(re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}",code)!=None);inp=pathlib.Path(inp);files=failure_files(inp)
    identities=sorted(({"bytes":p.stat().st_size,"sha256":file_sha(p)} for p in files),key=lambda x:(x["sha256"],x["bytes"]))
    scene=code in ("SCENE_FAILED","PRIVATE_SCENE_FAILED")
    value={"schema":"chengwang.joint-control-plane-safe-failure/v5" if scene else "chengwang.joint-control-plane-safe-failure/v2","failureCode":code,"status":"FAIL","production":False,"authorization":"BLOCKED","actualSKU":"UNKNOWN","privateEvidencePublished":False,"retainedPrivateFileCount":len(files),"retainedPrivateBytes":sum(p.stat().st_size for p in files),"privateAggregateSHA256":hashlib.sha256(canonical(identities)).hexdigest()}
    if scene:
        value["provenanceAuthority"]="NON_AUTHORITATIVE_STANDALONE"
        value["failureClassification"]=C.failure_classification(progress_root,source_commit)
        value["localizationEvidence"]=C.localization_evidence(
            progress_root,bootstrap_record,source_commit,bootstrap_step_id,
            bootstrap_step_outcome,bootstrap_step_source)
    nested=inp/"private-failure-identity.json"
    if nested.is_file():
        private=decode(nested);keys={"schema","failureCode","status","production","authorization","actualSKU","privateEvidencePublished","retainedPrivateFileCount","retainedPrivateBytes","privateAggregateSHA256","provenanceAuthority","failureClassification","localizationEvidence"}
        need(set(private)==keys and private["schema"]=="chengwang.joint-control-plane-safe-failure/v5" and private["failureCode"]=="PRIVATE_SCENE_FAILED" and private["status"]=="FAIL" and private["production"]is False and private["authorization"]=="BLOCKED" and private["actualSKU"]=="UNKNOWN" and private["privateEvidencePublished"]is False and private["provenanceAuthority"]=="NON_AUTHORITATIVE_STANDALONE" and re.fullmatch(r"[a-f0-9]{64}",private["privateAggregateSHA256"])!=None and private["failureClassification"]==value["failureClassification"] and private["localizationEvidence"]==value["localizationEvidence"])
        value["privateDiagnostics"]={k:private[k] for k in ("retainedPrivateFileCount","retainedPrivateBytes","privateAggregateSHA256")}
    data=canonical(value);need(len(data)<=4096);pathlib.Path(out).parent.mkdir(mode=0o700,parents=True,exist_ok=True);write(out,data)
def cpu(units,go_exit,out):
    value=decode(units);need(value.get("schema")=="chengwang.joint-control-plane-units/v2" and type(value.get("testsRun"))is int and value["testsRun"]>0 and value.get("syntheticOnly")is True)
    code=int(pathlib.Path(go_exit).read_text().strip());need(code==0)
    pathlib.Path(out).parent.mkdir(mode=0o700,parents=True,exist_ok=True);write(out,canonical({"schema":"chengwang.joint-control-plane-cpu-summary/v2","pythonTests":value["testsRun"],"pythonStatus":"PASS","goStatus":"PASS","rawLogsPublished":False,"runtimeAcceptanceProven":False}))
def cpu_fallback(out):
    out=pathlib.Path(out);out.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write(out,canonical(CPU_DIAGNOSTIC))
def cpu_public_entry(root):
    root=pathlib.Path(root);need(root.is_dir() and not root.is_symlink());entries=list(root.iterdir());need(len(entries)==1)
    p=entries[0];data=raw(p,1<<16);value=decode_bytes(data);need(data==canonical(value))
    if p.name=="cpu-summary.json":
        need(set(value)=={"schema","pythonTests","pythonStatus","goStatus","rawLogsPublished","runtimeAcceptanceProven"} and value["schema"]=="chengwang.joint-control-plane-cpu-summary/v2" and type(value["pythonTests"])is int and value["pythonTests"]>0 and value["pythonStatus"]==value["goStatus"]=="PASS" and value["rawLogsPublished"]is False and value["runtimeAcceptanceProven"]is False)
    elif p.name=="cpu-failure.json":
        keys={"schema","failureCode","status","production","authorization","actualSKU","privateEvidencePublished","retainedPrivateFileCount","retainedPrivateBytes","privateAggregateSHA256"};need(set(value)==keys and value["schema"]=="chengwang.joint-control-plane-safe-failure/v2" and value["failureCode"]=="CPU_FAILED" and value["status"]=="FAIL" and value["production"]is False and value["authorization"]=="BLOCKED" and value["actualSKU"]=="UNKNOWN" and value["privateEvidencePublished"]is False and type(value["retainedPrivateFileCount"])is int and value["retainedPrivateFileCount"]>=0 and type(value["retainedPrivateBytes"])is int and value["retainedPrivateBytes"]>=0 and re.fullmatch(r"[a-f0-9]{64}",value["privateAggregateSHA256"])!=None)
    else:
        need(p.name=="cpu-diagnostic-unavailable.json" and value==CPU_DIAGNOSTIC)
    return p.name,data
def cpu_publish(inp,out):
    name,data=cpu_public_entry(inp);out=pathlib.Path(out);need(not out.exists() and out.parent.is_dir())
    pending=pathlib.Path(tempfile.mkdtemp(prefix="."+out.name+".pending-",dir=out.parent))
    try:
        write(pending/name,data);fsync_dir(pending);fsync_dir(out.parent);need(not out.exists());os.replace(pending,out);fsync_dir(out.parent)
    except BaseException:
        if pending.exists():shutil.rmtree(pending)
        raise
def main():
    p=argparse.ArgumentParser();p.add_argument("action",choices=("private","publish","failure","cpu","cpu-fallback","cpu-publish"));p.add_argument("--private-root");p.add_argument("--input");p.add_argument("--output",required=True);p.add_argument("--verification");p.add_argument("--code",default="SCENE_FAILED");p.add_argument("--units");p.add_argument("--go-exit");p.add_argument("--progress-root");p.add_argument("--bootstrap-record");p.add_argument("--source-commit");p.add_argument("--bootstrap-step-id");p.add_argument("--bootstrap-step-outcome");p.add_argument("--bootstrap-step-source");a=p.parse_args()
    if a.action=="private":
        try:private_check(a.private_root,a.input,a.output)
        except Exception as error:
            if a.progress_root and a.source_commit:
                try:C.record_failure_detail(a.progress_root,a.source_commit,error)
                except Exception:pass
            raise
    elif a.action=="publish":publish(a.input,a.output,a.verification)
    elif a.action=="failure":failure(a.input,a.output,a.code,a.progress_root,a.source_commit,a.bootstrap_record,a.bootstrap_step_id,a.bootstrap_step_outcome,a.bootstrap_step_source)
    elif a.action=="cpu":cpu(a.units,a.go_exit,a.output)
    elif a.action=="cpu-fallback":cpu_fallback(a.output)
    else:cpu_publish(a.input,a.output)
if __name__=="__main__":
    try:main()
    except Exception as error:print("JOINT_PUBLICATION=REJECTED category="+C.exception_type(error),file=sys.stderr);raise SystemExit(1) from None
