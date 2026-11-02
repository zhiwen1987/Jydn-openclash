"""Run the real cmd/server B0 -> J1 -> R2 joint-control-plane experiment in CI."""
from __future__ import annotations

import argparse, base64, copy, hashlib, http.client, importlib.util, json, os, pathlib, re, secrets, signal, socket, ssl, subprocess, sys, time, urllib.parse
HERE=pathlib.Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("joint_runner_contract",HERE/"contract.py");C=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(C)

class Failure(Exception): pass
def need(ok, label):
    if not ok: raise Failure(label)
def read(path, maximum=C.MAX_ARTIFACT):
    p=pathlib.Path(path); raw=p.read_bytes(); need(not p.is_symlink() and len(raw)<=maximum,"READ"); return raw
def decode(raw): return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
def exclusive(path, raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
def token(): return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
def stable(path):
    first=read(path); time.sleep(.01); second=read(path); need(first==second and (not first or first.endswith(b"\n")),"STABLE"); return first
def wire_fence(path):
    raw=stable(path); rows=[decode(x) for x in raw.splitlines()]; need(len(rows)<=C.MAX_EVENTS and all(r.get("ordinal")==i for i,r in enumerate(rows,1)),"WIRE"); return {"events":len(rows),"sha256":C.sha(raw)}

def proc(pid, binary_sha, epoch):
    root=pathlib.Path("/proc")/str(pid); stat=(root/"stat").read_text(); fields=stat[stat.rfind(") ")+2:].split()
    status=dict(line.split(":",1) for line in (root/"status").read_text().splitlines() if ":" in line)
    exe=(root/"exe").read_bytes() if False else pathlib.Path(os.readlink(root/"exe")).read_bytes()
    cmd=(root/"cmdline").read_bytes()
    value={"epoch":epoch,"pid":pid,"startTicks":int(fields[19]),"exeSHA256":C.sha(exe),"argvSHA256":C.sha(cmd),
           "netNamespace":os.readlink(root/"ns/net"),"mountNamespace":os.readlink(root/"ns/mnt"),"pidNamespace":os.readlink(root/"ns/pid"),
           "uid":int(status["Uid"].split()[0]),"gid":int(status["Gid"].split()[0]),"capabilities":status["CapEff"].strip(),"noNewPrivileges":int(status["NoNewPrivs"]),"startedUnixNano":str(time.time_ns())}
    need(value["exeSHA256"]==binary_sha and value["uid"]==C.UID and value["gid"]==C.GID and value["capabilities"]=="0000000000000000" and value["noNewPrivileges"]==1,"PROFILE")
    return value

def listener_owner(pid, port):
    target=f"{port:04X}"; rows={}
    for name in ("tcp","tcp6"):
        for line in pathlib.Path("/proc/net/"+name).read_text().splitlines()[1:]:
            cols=line.split()
            if cols[1].split(":")[-1]==target and cols[3]=="0A":rows[cols[9]]={"localHex":cols[1],"remoteHex":cols[2],"stateHex":cols[3]}
    fds=[]
    for fd in (pathlib.Path("/proc")/str(pid)/"fd").iterdir():
        try: link=os.readlink(fd)
        except OSError: continue
        m=re.fullmatch(r"socket:\[(\d+)\]",link)
        if m and m.group(1) in rows:fds.append({"fd":int(fd.name),"inode":m.group(1),"procFdTarget":link,"port":port,"localAddress":"127.0.0.1","procNet":rows[m.group(1)]})
    need(len(fds)==1,"LISTENER")
    return fds[0]

def identity(tokens, source_ids=None):
    identities=[]
    for role in C.ROLES:
        tenant=C.FOREIGN_TENANT if role=="foreign" else C.SCOPE["tenantId"]
        identities.append({"tokenId":"joint-"+role,"tokenHash":C.sha(tokens[role].encode()),"principal":{"id":role+"@joint.test","tenantId":tenant,"roles":["viewer" if role=="foreign" else role],"allowedScopes":[C.human_grant(tenant)]}})
    if source_ids:
        identities.append({"tokenId":C.MACHINE_ID,"tokenHash":C.sha(tokens[C.MACHINE_ID].encode()),"principal":{"id":C.MACHINE_ID,"tenantId":C.SCOPE["tenantId"],"roles":[C.MACHINE_ROLE],"allowedScopes":C.machine_grants(source_ids)}})
    return {"version":1,"identities":identities}

def policy(ca, resolver_ca, source_tokens):
    return {"version":1,"scope":dict(C.SCOPE),"resolver":{"upstream":"127.0.0.1:1853","serverName":C.DOT_NAME,"caPEM":resolver_ca},"sources":[
        {"referenceId":case,"revision":1,"secretVersion":"v1","url":"https://"+host+"/subscription?token="+source_tokens[case],"allowedCnames":[],"caPEM":ca}
        for case,host in C.SOURCE_HOSTS.items()]}

def certs(root):
    specs={"api":"IP:127.0.0.1","resolver":"DNS:"+C.DOT_NAME,"source":",".join("DNS:"+x for x in C.SOURCE_HOSTS.values()),"mihomo":"IP:8.8.4.4"}
    for index,(stem,san) in enumerate(specs.items(),11):
        for args in (("genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",str(root/(stem+"-ca-key.private.pem"))),
                     ("req","-new","-x509","-sha256","-days","2","-key",str(root/(stem+"-ca-key.private.pem")),"-subj","/CN=Joint-"+stem+"-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-out",str(root/(stem+"-ca.pem"))),
                     ("genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",str(root/(stem+"-key.private.pem"))),
                     ("req","-new","-sha256","-key",str(root/(stem+"-key.private.pem")),"-subj","/CN=Joint-"+stem,"-out",str(root/(stem+".csr")))):
            subprocess.run(["/usr/bin/openssl",*args],check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        ext=root/(stem+"-ext.private.txt"); exclusive(ext,("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName="+san+"\n").encode())
        subprocess.run(["/usr/bin/openssl","x509","-req","-sha256","-days","2","-in",str(root/(stem+".csr")),"-CA",str(root/(stem+"-ca.pem")),"-CAkey",str(root/(stem+"-ca-key.private.pem")),"-set_serial",str(index),"-extfile",str(ext),"-out",str(root/(stem+"-cert.pem"))],check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)

class Lab:
    def __init__(self,a):
        self.a=a;self.root=pathlib.Path(a.private_root).resolve();self.out=pathlib.Path(a.evidence_dir).resolve();self.binary=pathlib.Path(a.server_binary).resolve();self.fixture=pathlib.Path(a.fixture_script).resolve()
        self.binary_raw=read(self.binary,128<<20);self.binary_sha=C.sha(self.binary_raw);self.fixture_id="joint-"+secrets.token_hex(16);self.captures=[];self.processes=[];self.active=[]
    def prepare(self):
        need(sys.platform=="linux" and os.getuid()==C.UID and os.getgid()==C.GID,"PLATFORM")
        need(self.root.is_dir() and not any(self.root.iterdir()),"ROOT")
        need(self.out.is_dir() and {p.name for p in self.out.iterdir()}=={"build.json","source-before.json","isolation.json"},"EVIDENCE")
        for d in (self.root/"data",self.root/"tmp"):d.mkdir(mode=0o700)
        certs(self.root);self.tokens={r:token() for r in (*C.ROLES,C.MACHINE_ID)};self.source_tokens={k:secrets.token_hex(32) for k in C.SOURCE_HOSTS};self.mihomo_token=token()
        body_a=b"proxies:\n  - {name: accepted-A, type: trojan, server: node-a.example, port: 443, password: fixture-a}\n";body_b=b"proxies:\n  - {name: quarantined-B, type: trojan, server: node-b.example, port: 443, password: fixture-b}\n"
        exclusive(self.root/"phase.private.json",C.canonical({"successBody":base64.b64encode(body_a).decode(),"failureStatus":200}))
        exclusive(self.root/"fixture-input.private.json",C.canonical({"sourceTokens":self.source_tokens,"mihomoToken":self.mihomo_token,"bearerTokens":self.tokens,"contentSecrets":["fixture-a","fixture-b"]}))
        ca=read(self.root/"source-ca.pem",65536).decode();rca=read(self.root/"resolver-ca.pem",65536).decode();self.p0=policy(ca,rca,self.source_tokens)
        exclusive(self.root/"policy0.json",C.canonical(self.p0));exclusive(self.root/"identities0.json",C.canonical(identity(self.tokens)))
        self.ctx=ssl.create_default_context(cafile=str(self.root/"api-ca.pem"));self.ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        self.api_peer=ssl.PEM_cert_to_DER_cert(read(self.root/"api-cert.pem",65536).decode())
        self.body_b=body_b
    def launch(self,argv,env,epoch):
        logs=self.root/"process-logs.private";logs.mkdir(mode=0o700,exist_ok=True)
        stdout=open(logs/(str(epoch)+".stdout"),"xb",buffering=0);stderr=open(logs/(str(epoch)+".stderr"),"xb",buffering=0)
        try:p=subprocess.Popen(argv,cwd=self.root,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        finally:stdout.close();stderr.close()
        self.active.append(p)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            need(p.poll() is None,"START")
            try: record=proc(p.pid,self.binary_sha if epoch!="fixture" else C.sha(read(pathlib.Path(sys.executable).resolve(),128<<20)),epoch);break
            except (OSError,Failure):time.sleep(.02)
        else:raise Failure("START")
        return p,record
    def environment(self,policy,identities,refresh,overview):
        return {"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","TZ":"UTC","TMPDIR":str(self.root/"tmp"),"SSL_CERT_FILE":str(self.root/"mihomo-ca.pem"),
         "CHENGWANG_ADDR":"127.0.0.1:17871","CHENGWANG_DATA_DIR":str(self.root/"data"),"CHENGWANG_IDENTITIES_FILE":str(identities),"CHENGWANG_TLS_CERT_FILE":str(self.root/"api-cert.pem"),"CHENGWANG_TLS_KEY_FILE":str(self.root/"api-key.private.pem"),
         "CHENGWANG_MANAGEMENT_TENANT_ID":C.SCOPE["tenantId"],"CHENGWANG_MANAGEMENT_SITE_ID":C.SCOPE["siteId"],"CHENGWANG_MANAGEMENT_OBJECT_ID":C.MANAGEMENT_OBJECT,"CHENGWANG_MODE":C.SCOPE["environment"],
         "CHENGWANG_SUBSCRIPTIONS_ENABLED":"true","CHENGWANG_SUBSCRIPTION_WRITES_ENABLED":"true","CHENGWANG_SUBSCRIPTION_REFRESH_ENABLED":"true" if refresh else "false","CHENGWANG_SUBSCRIPTION_REFRESH_IDENTITY_ID":C.MACHINE_ID if refresh else "","CHENGWANG_SUBSCRIPTION_POLICY_FILE":str(policy),
         "CHENGWANG_LIVE_OVERVIEW_ENABLED":"true" if overview else "false","CHENGWANG_MIHOMO_URL":"https://8.8.4.4:9443","CHENGWANG_MIHOMO_TOKEN":self.mihomo_token,"CHENGWANG_MIHOMO_ALLOWED_HOSTS":"8.8.4.4","CHENGWANG_MIHOMO_LAB_ENABLED":"false"}
    def wait_api(self,p):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            need(p.poll() is None,"START")
            try:
                s=socket.create_connection(C.API,.3);t=self.ctx.wrap_socket(s,server_hostname="127.0.0.1");need(t.getpeercert(binary_form=True)==self.api_peer,"TLS");t.close();return
            except OSError:time.sleep(.02)
        raise Failure("START")
    def start_server(self,epoch,env):
        self.server,record=self.launch([str(self.binary)],env,epoch);self.wait_api(self.server);record["listener"]=listener_owner(self.server.pid,C.API[1]);record["listener"].update(ownerPID=record["pid"],ownerStartTicks=record["startTicks"]);self.processes.append(record)
    def stop(self,p,record=None):
        began=time.monotonic();p.send_signal(signal.SIGTERM)
        try:code=p.wait(C.HARNESS_STOP_SECONDS)
        except subprocess.TimeoutExpired:p.kill();p.wait();raise Failure("STOP")
        need(code==0,"STOP");self.active.remove(p)
        if record is not None:record["stoppedUnixNano"]=str(time.time_ns());record["normalStop"]=True
        deadline=began+C.HARNESS_STOP_SECONDS
        while time.monotonic()<deadline:
            try:socket.create_connection(C.API,.1).close();time.sleep(.02)
            except OSError:return
        raise Failure("STOP")
    def abort(self):
        live=[p for p in self.active if p.poll() is None]
        for p in live:
            try:p.send_signal(signal.SIGTERM)
            except ProcessLookupError:pass
        deadline=time.monotonic()+C.HARNESS_STOP_SECONDS
        for p in live:
            remaining=max(0,deadline-time.monotonic())
            try:p.wait(remaining)
            except subprocess.TimeoutExpired:
                try:p.kill()
                except ProcessLookupError:pass
                p.wait()
        self.active.clear()
    def call(self,name,epoch,role="viewer",method="GET",path="/api/v1/subscriptions/sources",body=None,key="",expected=200):
        before=wire_fence(self.root/"wire-events.jsonl")
        headers={"Connection":"close"};payload=None
        if role!="anonymous":headers["Authorization"]="Bearer "+self.tokens[role]
        if body is not None:payload=C.canonical(body);headers.update({"Content-Type":"application/json","Idempotency-Key":key})
        c=http.client.HTTPSConnection(*C.API,context=self.ctx,timeout=25);c.connect();peer=c.sock.getpeercert(binary_form=True);c.request(method,path,payload,headers);r=c.getresponse();raw=r.read(C.MAX_CAPTURE+1);header=r.getheader("X-Chengwang-Command-ID");c.close()
        need(r.status==expected and len(raw)<=C.MAX_CAPTURE and peer==self.api_peer,"HTTP")
        value=decode(raw);after=wire_fence(self.root/"wire-events.jsonl")
        public_body=body
        self.captures.append({"schema":C.CAPTURE_SCHEMA,"ordinal":len(self.captures)+1,"name":name,"epoch":epoch,"role":role,"method":method,"path":path,"status":r.status,"request":{"body":public_body,"idempotencyKey":key},"responseBase64":base64.b64encode(raw).decode(),"responseSHA256":C.sha(raw),"tlsPeerSHA256":C.sha(peer),"commandIdHeader":header,"wireBefore":before,"wireAfter":after,"receivedUnixNano":str(time.time_ns())})
        fd=os.open(self.out/"captures.partial.jsonl",os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,"O_NOFOLLOW",0),0o600)
        try:os.write(fd,C.canonical(self.captures[-1]));os.fsync(fd)
        finally:os.close(fd)
        if path.startswith("/api/v1/subscriptions"):
            need(value.get("authorization")=="BLOCKED" and value.get("deviceActionsExecuted") is False,"ENVELOPE")
            return value.get("result")
        return value
    def mutate(self,name,epoch,case,op,source,suffix,body,role="operator",expected=200):return self.call(name,epoch,role,"POST","/api/v1/subscriptions/sources"+("/"+source if source else "")+suffix,body,C.idempotency(case,op),expected)
    def bootstrap(self):
        self.start_server("B0",self.environment(self.root/"policy0.json",self.root/"identities0.json",False,False))
        self.call("anonymous-list","B0","anonymous",expected=401);self.call("foreign-list","B0","foreign",expected=403)
        self.sources={};self.candidates={};self.approvals={};self.baseline={}
        for case in C.SOURCE_HOSTS:
            self.mutate(case+"-viewer-create-neg","B0",case,"viewer_create_neg","","",{"label":case},"viewer",403)
            create=self.mutate(case+"-create","B0",case,"create_source","","",{"label":case});sid=create["sourceId"];need(C.SOURCE_ID.fullmatch(sid),"SOURCE");self.sources[case]=sid
            self.mutate(case+"-operator-approve-neg","B0",case,"operator_approve_r1_neg",sid,"/approvals",{"referenceId":case,"policyRevision":1,"expectedRevision":1},"operator",403)
            approval=self.mutate(case+"-approve-r1","B0",case,"approve_r1",sid,"/approvals",{"referenceId":case,"policyRevision":1,"expectedRevision":1},"approver");aid=approval["commandId"]
            fetch=self.mutate(case+"-fetch-r1","B0",case,"fetch_r1",sid,"/fetches",{"approvalId":aid,"policyRevision":1,"expectedRevision":1});cid=fetch["candidateId"];self.candidates[case]=cid
            self.mutate(case+"-admit-r2","B0",case,"admit_r2",sid,"/decisions",{"candidateId":cid,"expectedRevision":2,"expectedDigest":fetch["candidateDigest"],"decision":"admitted_local"},"approver")
            approval3=self.mutate(case+"-approve-r3","B0",case,"approve_r3",sid,"/approvals",{"referenceId":case,"policyRevision":1,"expectedRevision":3},"approver");self.approvals[case]=approval3["commandId"]
            self.baseline[case]=self.call(case+"-baseline-source","B0","viewer",path="/api/v1/subscriptions/sources")
            self.call(case+"-baseline-candidates","B0","viewer",path=f"/api/v1/subscriptions/sources/{sid}/candidates?limit=100&offset=0&revision=3")
            self.call(case+"-approval-receipt","B0","auditor",path="/api/v1/subscriptions/commands/"+self.approvals[case])
        self.stop(self.server,self.processes[-1])
        private=decode(read(self.root/"data/subscriptions/store.json"));self.bootstrap_counts={"commands":len(private.get("commands",[])),"audit":len(private.get("audit",[]))}
    def joint(self):
        p1=C.append_refresh(self.p0,self.sources,self.approvals);exclusive(self.root/"policy1.json",C.canonical(p1));exclusive(self.root/"identities1.json",C.canonical(identity(self.tokens,self.sources)))
        os.unlink(self.root/"phase.private.json");exclusive(self.root/"phase.private.json",C.canonical({"successBody":base64.b64encode(self.body_b).decode(),"failureStatus":503}))
        self.start_server("J1",self.environment(self.root/"policy1.json",self.root/"identities1.json",True,True));j=self.processes[-1]
        deadline=time.monotonic()+C.EXPERIMENT_DEADLINE;last={}
        while time.monotonic()<deadline:
            for case,sid in self.sources.items():last[case]=self.call(case+"-refresh-poll","J1","viewer",path=f"/api/v1/subscriptions/sources/{sid}/refresh")
            if last.get("success",{}).get("state")=="candidate_quarantined" and last.get("failure",{}).get("state")=="failed":break
            time.sleep(C.POLL_SECONDS)
        else:raise Failure("SLO")
        for case,value in last.items():C.refresh_keys(value);cid=value.get("commandId");need(C.COMMAND.fullmatch(cid or ""),"WORKER-RECEIPT");self.call(case+"-worker-receipt-auditor","J1","auditor",path="/api/v1/subscriptions/commands/"+cid);self.call(case+"-worker-receipt-viewer-denied","J1","viewer",path="/api/v1/subscriptions/commands/"+cid,expected=403);self.call(case+"-worker-receipt-operator-denied","J1","operator",path="/api/v1/subscriptions/commands/"+cid,expected=403)
        overview=self.call("overview-anonymous","J1","anonymous",path="/api/v1/overview");need(overview.get("schema")=="chengwang.overview-snapshot/v1" and overview.get("readOnly") is True and overview.get("advisoryOnly") is True,"OVERVIEW")
        self.call("mihomo-status-anonymous","J1","anonymous",path="/api/v1/kernels/mihomo/status")
        self.call("mihomo-runtime-viewer","J1","viewer",path="/api/v1/kernels/mihomo/runtime")
        self.call("mihomo-runtime-anonymous-denied","J1","anonymous",path="/api/v1/kernels/mihomo/runtime",expected=401)
        self.call("mihomo-runtime-foreign-denied","J1","foreign",path="/api/v1/kernels/mihomo/runtime",expected=403)
        self.transport_negatives=self.transport_negative_cases()
        self.joint_refresh=last;self.stop(self.server,j)
        private=decode(read(self.root/"data/subscriptions/store.json"));self.joint_counts={"commands":len(private.get("commands",[])),"audit":len(private.get("audit",[]))}
        need(self.joint_counts["commands"]>=self.bootstrap_counts["commands"]+2 and self.joint_counts["audit"]>self.bootstrap_counts["audit"],"WORKER-DELTA")
    def readback(self):
        side=self.root/"data/subscription-refresh-v3";before={str(p.relative_to(side)):C.sha(read(p)) for p in side.rglob("*") if p.is_file()}
        exclusive(self.root/"sidecar-before.private.json",C.canonical(before))
        self.start_server("R2",self.environment(self.root/"policy0.json",self.root/"identities0.json",False,True));r=self.processes[-1]
        sources=self.call("r2-sources","R2","viewer");receipts={}
        for case,v in self.joint_refresh.items():receipts[case]=self.call(case+"-r2-worker-receipt","R2","auditor",path="/api/v1/subscriptions/commands/"+v["commandId"])
        for case,sid in self.sources.items():self.call(case+"-r2-candidates","R2","viewer",path=f"/api/v1/subscriptions/sources/{sid}/candidates?limit=100&offset=0&revision="+("4" if case=="success" else "3"))
        self.stop(self.server,r);after={str(p.relative_to(side)):C.sha(read(p)) for p in side.rglob("*") if p.is_file()};need(before==after,"SIDECAR")
        exclusive(self.root/"sidecar-after.private.json",C.canonical(after))
        return {"schema":C.READBACK_SCHEMA,"sourceCommit":self.a.source_commit,"fixtureId":self.fixture_id,"sources":sources,"workerReceipts":receipts,"bootstrapCounts":self.bootstrap_counts,"jointCounts":self.joint_counts,"sidecarUnchanged":True,"refreshRestartPersistenceProven":False}
    def transport_negative_cases(self):
        results=[];bad=ssl.create_default_context()
        try:
            c=http.client.HTTPSConnection(*C.API,context=bad,timeout=2);c.request("GET","/api/v1/subscriptions/sources");c.getresponse();raise Failure("WRONG-CA")
        except ssl.SSLCertVerificationError:results.append({"case":"wrong_ca","result":"tls_verification_rejected"})
        raw=socket.create_connection(C.API,2);raw.sendall(b"GET /api/v1/subscriptions/sources HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        try:reply=raw.recv(32)
        except (ConnectionResetError,TimeoutError,OSError):reply=b""
        finally:raw.close()
        need(not reply.startswith(b"HTTP/"),"PLAINTEXT");results.append({"case":"plaintext_http","result":"no_http_response"})
        raw=socket.create_connection(C.API,2);tls=self.ctx.wrap_socket(raw,server_hostname="127.0.0.1");auth=("Bearer "+self.tokens["viewer"]).encode();tls.sendall(b"GET /api/v1/subscriptions/sources HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: "+auth+b"\r\nAuthorization: "+auth+b"\r\nConnection: close\r\n\r\n");response=b""
        while len(response)<C.MAX_CAPTURE:
            part=tls.recv(4096)
            if not part:break
            response+=part
        tls.close();match=re.match(br"HTTP/1\.1 ([0-9]{3}) ",response);need(match and int(match.group(1))==401,"DUPLICATE-AUTH");results.append({"case":"duplicate_authorization","result":"401"})
        return results
    def run(self):
        self.prepare();env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","TZ":"UTC","PYTHONDONTWRITEBYTECODE":"1"};self.wire,wr=self.launch([sys.executable,"-I","-B",str(self.fixture),"serve","--root",str(self.root),"--deadline-seconds","180"],env,"fixture")
        deadline=time.monotonic()+10
        while time.monotonic()<deadline and not (self.root/"fixture-ready.json").exists():need(self.wire.poll() is None,"FIXTURE");time.sleep(.02)
        wire_fence(self.root/"wire-events.jsonl");self.bootstrap();self.joint();readback=self.readback();self.stop(self.wire,wr)
        stopped=decode(read(self.root/"fixture-stopped.json"));need(stopped["normalStop"] and stopped["workerThreadsAlive"]==0 and stopped["listenersClosed"],"FIXTURE-STOP")
        runtime={"schema":C.RUNTIME_SCHEMA,"sourceCommit":self.a.source_commit,"fixtureId":self.fixture_id,"serverBinarySHA256":self.binary_sha,"fixtureProcess":wr,"processes":self.processes,"sameBinaryAllEpochs":len({p["exeSHA256"] for p in self.processes})==1}
        os.replace(self.out/"captures.partial.jsonl",self.out/"captures.jsonl")
        files={"runtime.json":C.canonical(runtime),"wire-events.jsonl":read(self.root/"wire-events.jsonl"),"readback.json":C.canonical(readback),"transport-negatives.json":C.canonical({"schema":"chengwang.joint-control-plane-transport-negatives/v2","cases":self.transport_negatives}),"outcome.json":C.canonical(C.outcome(self.a.source_commit,self.fixture_id,"CAPTURED"))}
        for public,private in (("api-ca.pem","api-ca.pem"),("api-leaf.pem","api-cert.pem"),("resolver-ca.pem","resolver-ca.pem"),("resolver-leaf.pem","resolver-cert.pem"),("source-ca.pem","source-ca.pem"),("source-leaf.pem","source-cert.pem"),("mihomo-ca.pem","mihomo-ca.pem"),("mihomo-leaf.pem","mihomo-cert.pem")):files[public]=read(self.root/private,65536)
        for name,raw in files.items():exclusive(self.out/name,raw)
        need(not self.active,"RESIDUE")
def main():
    p=argparse.ArgumentParser();p.add_argument("--server-binary",required=True);p.add_argument("--fixture-script",required=True);p.add_argument("--private-root",required=True);p.add_argument("--evidence-dir",required=True);p.add_argument("--source-commit",required=True);a=p.parse_args();need(re.fullmatch(r"[a-f0-9]{40}",a.source_commit)!=None,"COMMIT")
    lab=Lab(a)
    try:lab.run()
    except Exception:
        lab.abort()
        out=pathlib.Path(a.evidence_dir)
        try:
            if (pathlib.Path(a.private_root)/"wire-events.jsonl").is_file():exclusive(out/"wire-events.failure.jsonl",read(pathlib.Path(a.private_root)/"wire-events.jsonl"))
            exclusive(out/"failure.json",C.canonical({"schema":"chengwang.joint-control-plane-failure/v2","sourceCommit":a.source_commit,"stage":"runtime","status":"FAIL","production":False,"actualSKU":"UNKNOWN","authorization":"BLOCKED"}))
        except Exception:pass
        raise
if __name__=="__main__":
    try:main()
    except Exception as e: print("JOINT_CONTROL_PLANE=REJECTED "+type(e).__name__,file=sys.stderr);raise SystemExit(1) from None
