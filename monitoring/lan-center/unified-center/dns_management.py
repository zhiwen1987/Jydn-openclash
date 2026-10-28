"""Fail-closed CoreDNS draft manager used by the unified center extension."""
from __future__ import annotations
import contextlib, hashlib, ipaddress, json, os, re, tempfile, time, urllib.parse, uuid
from pathlib import Path
try: import fcntl
except ImportError: fcntl=None
if fcntl is None: import msvcrt

SCHEMA=1; BEGIN="# BEGIN JYDN CLASH CENTER DNS"; END="# END JYDN CLASH CENTER DNS"
IDENT=re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
DOMAIN=re.compile(r"(?:\*\.)?(?=.{1,253}\.?\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?\Z")

class DnsConfigError(ValueError):
 def __init__(self,code,status=400,recovery_required=None):super().__init__(code);self.code,self.status,self.recovery_required=code,status,recovery_required

def _dump(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))
def _hash(v):return hashlib.sha256(v if isinstance(v,bytes) else v.encode()).hexdigest()
def _atomic(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.NamedTemporaryFile("wb",dir=path.parent,delete=False) as f:
  f.write(value if isinstance(value,bytes) else value.encode());f.flush();os.fsync(f.fileno());tmp=Path(f.name)
 os.chmod(tmp,0o600);os.replace(tmp,path)
def _domain(v,wild=True):
 v=str(v).strip().lower().rstrip(".")
 if (not wild and v.startswith("*.")) or not DOMAIN.fullmatch(v):raise DnsConfigError("invalid_domain")
 return v
def _target(v,inherited=False):
 v=str(v).strip()
 if inherited and re.fullmatch(r"/[A-Za-z0-9_./-]{1,255}",v):return v
 try:
  if v.startswith("["):
   end=v.index("]");ipaddress.ip_address(v[1:end]);rest=v[end+1:]
   if rest:
    if not rest.startswith(":") or not 1<=int(rest[1:])<=65535:raise ValueError
   return v
  try:ipaddress.ip_address(v);return v
  except ValueError:pass
  if v.count(":")==1:
   raw,port=v.rsplit(":",1);ipaddress.ip_address(raw)
   if not 1<=int(port)<=65535:raise ValueError
   return v
 except (ValueError,IndexError):pass
 p=urllib.parse.urlsplit(v)
 if p.scheme not in {"tls","https"} or p.username or p.password or p.query or p.fragment or not p.hostname or p.path not in {"","/"}:raise DnsConfigError("invalid_upstream")
 try:port=p.port
 except ValueError:raise DnsConfigError("invalid_upstream") from None
 if port and not 1<=port<=65535:raise DnsConfigError("invalid_upstream")
 return v
def empty_model():return {"schema":1,"upstreams":[],"hosts":[],"rewrites":[],"forward_options":[]}
def validate_model(m):
 if not isinstance(m,dict) or m.get("schema")!=1:raise DnsConfigError("invalid_model")
 for k,limit in (("upstreams",15),("hosts",1024),("rewrites",256),("forward_options",64)):
  if not isinstance(m.get(k),list) or len(m[k])>limit:raise DnsConfigError("invalid_model")
 for key in ("upstreams","hosts","rewrites"):
  ids=[str(x.get("id","")) for x in m[key] if isinstance(x,dict)]
  if len(ids)!=len(m[key]) or len(ids)!=len(set(ids)) or not all(IDENT.fullmatch(x) for x in ids):raise DnsConfigError("invalid_id")
 for x in m["upstreams"]:x["target"]=_target(x.get("target"),bool(x.get("inherited")));x["enabled"]=bool(x.get("enabled",True))
 for x in m["hosts"]:x["name"]=_domain(x.get("name"),False);x["address"]=str(ipaddress.ip_address(x.get("address")));x["enabled"]=bool(x.get("enabled",True))
 for x in m["rewrites"]:
  x["match"]=str(x.get("match","exact"));x["enabled"]=bool(x.get("enabled",True))
  if x["match"] not in {"exact","suffix","prefix"}:raise DnsConfigError("invalid_rewrite")
  x["from"]=_domain(x.get("from"),x["match"]!="exact");x["to"]=_domain(x.get("to"),False)
 if not all(isinstance(v,str) and len(v)<=200 and "\n" not in v and "\r" not in v for v in m["forward_options"]):raise DnsConfigError("invalid_forward_option")
 active=[x for x in m["upstreams"] if x["enabled"]]
 if not active:raise DnsConfigError("last_upstream_required")
 sni=any(v.strip().startswith("tls_servername ") for v in m["forward_options"])
 if any(x["target"].startswith("tls://") and "%" not in x["target"] and not sni for x in active):raise DnsConfigError("tls_servername_required")
 return m

def extract_forward(raw):
 lines=raw.splitlines(keepends=True);hits=[]
 for i,line in enumerate(lines):
  s=line.split("#",1)[0].strip()
  if not s.startswith("forward . "):continue
  tokens=s.replace("{"," {").split();end=i;opts=[]
  if "{" in tokens:
   depth=line.count("{")-line.count("}")
   while depth and end+1<len(lines):
    end+=1;depth+=lines[end].count("{")-lines[end].count("}")
    if depth>0:opts.append(lines[end].strip())
   if depth:raise DnsConfigError("unsupported_corefile")
   targets=tokens[2:tokens.index("{")]
  else:targets=tokens[2:]
  hits.append((i,end,line[:len(line)-len(line.lstrip())],targets,opts))
 if len(hits)!=1:raise DnsConfigError("unsupported_corefile")
 return lines,hits[0]

def render_fragment(m,hosts_path):
 lines=[]
 if any(x["enabled"] for x in m["hosts"]):lines += [f"hosts {hosts_path} {{","  fallthrough","}"]
 lines += [f"rewrite stop name {x['match']} {x['from']} {x['to']} answer auto" for x in m["rewrites"] if x["enabled"]]
 targets=" ".join(x["target"] for x in m["upstreams"] if x["enabled"])
 if m["forward_options"]:lines += [f"forward . {targets} {{"]+["  "+v.strip() for v in m["forward_options"] if v.strip() not in {"{","}"}]+["}"]
 else:lines += [f"forward . {targets}"]
 return "\n".join(lines)+"\n"
def render_hosts(m):return "".join(f"{x['address']} {x['name']}\n" for x in m["hosts"] if x["enabled"])

class DnsManager:
 def __init__(self,state_dir,corefile,fragment,hosts_file,validator=None,reloader=None,probe=None,routing_lock=None,external_lock=False):
  self.root=Path(state_dir);self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
  try:os.chmod(self.root,0o700)
  except OSError:pass
  self.corefile=Path(corefile);self.fragment=Path(fragment);self.hosts=Path(hosts_file)
  self.validator,self.reloader,self.probe=validator,reloader,probe;self.lock=Path(routing_lock or self.root/"routing-owner.lock");self.external_lock=bool(external_lock)
 def _read(self,path):
  try:return json.loads(Path(path).read_text(encoding="utf-8"))
  except (OSError,ValueError):return None
 def active(self):
  v=self._read(self.root/"active.json");return validate_model(v) if v else None
 def revision(self):return _hash(b"\0".join(p.read_bytes() if p.is_file() else b"" for p in (self.corefile,self.fragment,self.hosts,self.root/"active.json")))
 def status(self):
  raw=self.corefile.read_text(encoding="utf-8");managed=raw.count(BEGIN)==raw.count(END)==1;m=self.active()
  return {"state":"ready" if managed and m else "unmanaged","revision":self.revision(),"managed":managed,"config":m or empty_model(),"last_apply":self._read(self.root/"last-apply.json")}
 def migrate(self):
  raw=self.corefile.read_text(encoding="utf-8")
  if BEGIN in raw or END in raw:raise DnsConfigError("managed_block_inconsistent")
  lines,(start,end,indent,targets,opts)=extract_forward(raw);m=empty_model();m["upstreams"]=[{"id":f"upstream-{i+1}","target":_target(v,True),"enabled":True,"inherited":True} for i,v in enumerate(targets)];m["forward_options"]=opts;validate_model(m)
  marker=[indent+BEGIN+"\n",indent+f"import {self.fragment}\n",indent+END+"\n"]
  return "".join(lines[:start]+marker+lines[end+1:]),m
 def create_draft(self,expected,operations):
  if expected!=self.revision():raise DnsConfigError("revision_conflict",409)
  if not isinstance(operations,list) or not 1<=len(operations)<=256:raise DnsConfigError("invalid_operations")
  s=self.status();migration=None
  if s["managed"]:m=json.loads(_dump(self.active()))
  else:
   if operations[0]!={"kind":"migration","action":"adopt"}:raise DnsConfigError("migration_required",409)
   migration,m=self.migrate();operations=operations[1:]
  before=json.loads(_dump(self.active() or empty_model()))
  for op in operations:self.operate(m,op)
  validate_model(m);ident="dns-"+uuid.uuid4().hex;v={"schema":1,"id":ident,"created_at":time.time(),"base_revision":expected,"model":m,"migration_core":migration,"state":"draft","impact":self.impact(before,m)};_atomic(self.root/"drafts"/(ident+".json"),_dump(v));return v
 @staticmethod
 def operate(m,op):
  if not isinstance(op,dict):raise DnsConfigError("invalid_operation")
  key={"upstream":"upstreams","host":"hosts","rewrite":"rewrites"}.get(op.get("kind"));action=op.get("action")
  if not key or action not in {"add","update","delete","enable","disable"}:raise DnsConfigError("invalid_operation")
  rows=m[key];found=next((x for x in rows if x.get("id")==op.get("id")),None)
  if action=="add":
   if found:raise DnsConfigError("duplicate_id")
   rows.append({k:v for k,v in op.items() if k not in {"kind","action"}})
  elif not found:raise DnsConfigError("object_not_found",404)
  elif action=="delete":rows.remove(found)
  elif action in {"enable","disable"}:found["enabled"]=action=="enable"
  else:
   for k,v in op.items():
    if k not in {"kind","action","id"}:found[k]=v
 @staticmethod
 def impact(a,b):
  out={}
  for key in ("upstreams","hosts","rewrites"):
   x={v["id"]:v for v in a[key]};y={v["id"]:v for v in b[key]};out[key]={"added":sorted(y.keys()-x.keys()),"removed":sorted(x.keys()-y.keys()),"changed":sorted(k for k in x.keys()&y.keys() if x[k]!=y[k])}
  return out
 def draft(self,ident):
  if not IDENT.fullmatch(str(ident)):raise DnsConfigError("invalid_draft_id")
  path=self.root/"drafts"/(ident+".json");v=self._read(path)
  if not v:raise DnsConfigError("draft_not_found",404)
  return v,path
 def preview(self,ident):
  v,path=self.draft(ident);core=v.get("migration_core") or self.corefile.read_text(encoding="utf-8");fragment=render_fragment(v["model"],self.hosts);hosts=render_hosts(v["model"]);external={"state":"unknown","detail":"validator_unavailable"}
  if self.validator:
   result=self.validator(core,fragment,hosts)
   if result is False or isinstance(result,dict) and result.get("state") not in {"ok","pass"}:raise DnsConfigError("external_validation_failed")
   external=result if isinstance(result,dict) else {"state":"ok"}
  v.update(state="validated",validated_at=time.time(),candidate={"core_sha256":_hash(core),"fragment_sha256":_hash(fragment),"hosts_sha256":_hash(hosts)},external=external);_atomic(path,_dump(v));return {k:v[k] for k in ("id","state","impact","candidate","external")}
 @contextlib.contextmanager
 def exclusive(self):
  if self.external_lock:
   yield;return
  self.lock.parent.mkdir(parents=True,exist_ok=True)
  with self.lock.open("a") as lock:
   if fcntl is not None:
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise DnsConfigError("configuration_busy",409) from None
    yield
   else:
    if lock.tell()==0:lock.write("0");lock.flush()
    lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:raise DnsConfigError("configuration_busy",409) from None
    try:yield
    finally:lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1)
 def _reload_and_probe(self,request_id,core_bytes,fragment_bytes,purpose,recovery_of=None):
  if purpose not in {"apply","rollback","recovery"} or purpose=="recovery" and not isinstance(recovery_of,str):raise DnsConfigError("invalid_reload_purpose",500,False)
  expected_core,expected_fragment=_hash(core_bytes),_hash(fragment_bytes)
  if not self.corefile.is_file() or _hash(self.corefile.read_bytes())!=expected_core or _hash(self.fragment.read_bytes() if self.fragment.is_file() else b"")!=expected_fragment:raise DnsConfigError("runtime_input_readback_failed",503,False)
  reload_proof=self.reloader(request_id=request_id,expected_core_sha256=expected_core,expected_fragment_sha256=expected_fragment,purpose=purpose,recovery_of=recovery_of)
  if reload_proof is False or isinstance(reload_proof,dict) and reload_proof.get("state") not in {"ok","pass","completed"}:
   required=reload_proof.get("recovery_required") if isinstance(reload_proof,dict) and type(reload_proof.get("recovery_required")) is bool else True
   raise DnsConfigError("runtime_reload_failed",503,required)
  if not isinstance(reload_proof,dict) or reload_proof.get("request_id")!=request_id or reload_proof.get("loaded_core_sha256")!=expected_core or reload_proof.get("loaded_fragment_sha256",expected_fragment)!=expected_fragment or reload_proof.get("purpose")!=purpose or reload_proof.get("recovery_of")!=recovery_of:raise DnsConfigError("runtime_reload_ack_mismatch",503)
  runtime=self.probe()
  if not isinstance(runtime,dict) or runtime.get("state") not in {"ok","pass"}:raise DnsConfigError("runtime_readback_failed",503)
  proof=dict(runtime);proof["reload"]=reload_proof if isinstance(reload_proof,dict) else {"state":"completed"};return proof
 def apply(self,ident,expected):
  v,path=self.draft(ident)
  if v.get("state")!="validated":raise DnsConfigError("draft_not_validated",409)
  if expected!=v.get("base_revision"):raise DnsConfigError("revision_conflict",409)
  if not all((self.validator,self.reloader,self.probe)):raise DnsConfigError("runtime_verification_unavailable",503)
  with self.exclusive():
   if self.revision()!=expected:raise DnsConfigError("revision_conflict",409)
   aid="apply-"+uuid.uuid4().hex;backup=self.root/"backups"/aid;backup.mkdir(parents=True,mode=0o700);targets={"Corefile":self.corefile,"fragment":self.fragment,"hosts":self.hosts,"active":self.root/"active.json"};old={}
   for name,target in targets.items():
    old[name]=target.read_bytes() if target.is_file() else None
    if old[name] is not None:_atomic(backup/name,old[name])
   core=v.get("migration_core") or self.corefile.read_text(encoding="utf-8");fragment=render_fragment(v["model"],self.hosts);hosts=render_hosts(v["model"])
   try:
    _atomic(self.fragment,fragment);_atomic(self.hosts,hosts);_atomic(self.corefile,core);_atomic(self.root/"active.json",_dump(v["model"]));proof=self._reload_and_probe(aid,core.encode(),fragment.encode(),"apply")
   except Exception as original:
    for name,target in targets.items():
     if old[name] is None:target.unlink(missing_ok=True)
     else:_atomic(target,old[name])
    if isinstance(original,DnsConfigError) and original.recovery_required is False:
     recovery=self.probe()
     if isinstance(recovery,dict) and recovery.get("state") in {"ok","pass"}:raise original
     raise DnsConfigError("apply_recovery_failed",503) from original
    try:
     recovery_id="recover-"+uuid.uuid4().hex;self._reload_and_probe(recovery_id,old["Corefile"] or b"",old["fragment"] or b"","recovery",aid)
    except Exception as recovery_error:
     raise DnsConfigError("apply_recovery_failed",503) from recovery_error
    raise original
   receipt={"schema":1,"id":aid,"draft_id":ident,"applied_at":time.time(),"previous_revision":expected,"revision":self.revision(),"proof":proof};_atomic(self.root/"last-apply.json",_dump(receipt));v.update(state="applied",apply_id=aid);_atomic(path,_dump(v));return receipt
 def rollback(self,aid,expected):
  if not IDENT.fullmatch(str(aid)):raise DnsConfigError("invalid_apply_id")
  if not all((self.reloader,self.probe)):raise DnsConfigError("runtime_verification_unavailable",503)
  backup=self.root/"backups"/aid
  with self.exclusive():
   if self.revision()!=expected:raise DnsConfigError("revision_conflict",409)
   if not backup.is_dir():raise DnsConfigError("backup_not_found",404)
   targets={"Corefile":self.corefile,"fragment":self.fragment,"hosts":self.hosts,"active":self.root/"active.json"};current={name:target.read_bytes() if target.is_file() else None for name,target in targets.items()}
   try:
    for name,target in targets.items():
     source=backup/name
     if source.is_file():_atomic(target,source.read_bytes())
     else:target.unlink(missing_ok=True)
    rollback_id="rollback-"+uuid.uuid4().hex;proof=self._reload_and_probe(rollback_id,self.corefile.read_bytes(),self.fragment.read_bytes() if self.fragment.is_file() else b"","rollback")
   except Exception as original:
    for name,target in targets.items():
     if current[name] is None:target.unlink(missing_ok=True)
     else:_atomic(target,current[name])
    if isinstance(original,DnsConfigError) and original.recovery_required is False:
     recovery=self.probe()
     if isinstance(recovery,dict) and recovery.get("state") in {"ok","pass"}:raise DnsConfigError("rollback_readback_failed",503) from original
     raise DnsConfigError("rollback_recovery_failed",503) from original
    try:
     recovery_id="recover-"+uuid.uuid4().hex;self._reload_and_probe(recovery_id,current["Corefile"] or b"",current["fragment"] or b"","recovery",rollback_id)
    except Exception as recovery_error:raise DnsConfigError("rollback_recovery_failed",503) from recovery_error
    raise DnsConfigError("rollback_readback_failed",503) from original
   result={"state":"rolled_back","apply_id":aid,"rolled_back_at":time.time(),"revision":self.revision(),"proof":proof};_atomic(self.root/"last-apply.json",_dump(result));return result

class DnsExtension:
 def __init__(self,context):
  def get(name,default=None):return context.get(name,default) if isinstance(context,dict) else getattr(context,name,default)
  namespace=get("namespace",{}) or {};data=Path(get("data_root",namespace.get("DATA","/data")));center=Path(get("center_root",data/"center"));state=Path(os.getenv("CENTER_DNS_MANAGED_DIR",str(center/"dns-management")))
  core=Path(os.getenv("CENTER_COREFILE",str(get("corefile","/etc/coredns/Corefile"))));fragment=Path(get("dns_fragment",state/"Corefile.managed"));hosts=Path(get("dns_hosts",state/"hosts"))
  callback=lambda name:get(name,namespace.get(name) if isinstance(namespace,dict) else None);bounded=bool(get("dns_runtime_deadline_enforced",False))
  # Do not infer mount writability from mode bits alone: os.access() can report
  # writable for root even when the file lives on a read-only bind mount.  The
  # deployment adapter sets this only after a real write/replace probe of the
  # managed CoreDNS directory has succeeded.
  self.runtime_writable_verified=bool(get("dns_runtime_writable_verified",False))
  self.manager=DnsManager(state,core,fragment,hosts,callback("dns_validator") if bounded else None,callback("dns_reloader") if bounded else None,callback("dns_probe") if bounded else None,get("routing_lock",getattr(get("manager",None),"routing_lock",None)),get("write_lock_managed",False))
  from dns_diagnostics import DnsDiagnostics
  self.diagnostics=DnsDiagnostics(get("opener"),timeout=get("remote_timeout",2.5))
 def actions(self):
  runtime=self.runtime_writable_verified and all((self.manager.validator,self.manager.reloader,self.manager.probe)) and os.access(self.manager.corefile,os.W_OK)
  return {"dns.draft_update":{"write":True,"scope":"control_only","supported":True,"timeout_seconds":10,"deadline_enforced":True},"dns.preview":{"write":True,"scope":"control_only","supported":True,"timeout_seconds":20,"deadline_enforced":True},"dns.apply":{"write":True,"scope":"runtime","supported":runtime,"timeout_seconds":90,"deadline_enforced":True},"dns.rollback":{"write":True,"scope":"runtime","supported":runtime,"timeout_seconds":90,"deadline_enforced":True},"dns.query":{"write":False,"supported":True,"timeout_seconds":10},"dns.diagnose":{"write":False,"supported":True,"timeout_seconds":60},"dns.leak_test":{"write":False,"supported":True,"timeout_seconds":60}}
 def snapshot(self):
  try:s=self.manager.status();state=s["state"]
  except (OSError,UnicodeError,ValueError):s={"revision":None,"config":empty_model(),"last_apply":None};state="error"
  draft=None;folder=self.manager.root/"drafts"
  for path in sorted(folder.glob("dns-*.json"),key=lambda p:p.stat().st_mtime,reverse=True)[:1] if folder.is_dir() else []:
   try:
    v=json.loads(path.read_text(encoding="utf-8"));draft={k:v.get(k) for k in ("id","state","base_revision","created_at","impact","external")}
   except (OSError,ValueError):pass
  action=self.actions();return {"state":state,"revision":s.get("revision"),"capabilities":{"actions":[k for k,v in action.items() if v["supported"]],"management":"ready" if state=="ready" else "migration_required" if state=="unmanaged" else "unsupported","runtime_apply":action["dns.apply"]["supported"],"runtime_requirements":{"writable_verified":self.runtime_writable_verified,"validator":bool(self.manager.validator),"reloader":bool(self.manager.reloader),"probe":bool(self.manager.probe)},"diagnostic_presets":[{"id":"current_coredns","perspective":"resolver","resolver":"127.0.0.1:53"},{"id":"container_system","perspective":"container"},{"id":"browser","perspective":"browser"}],"browser_probe":{"supported":True,"automatic_site":"dnsleak.dev","required_csp_connect_src":["https://*.t.dnsleak.dev"]},"leak_sites":[{"id":"dnsleak.dev","mode":"automatic"},{"id":"ipleak","mode":"browser"},{"id":"browserleaks","mode":"manual_external"},{"id":"dnsleaktest","mode":"manual_external"}]},"config":s.get("config",empty_model()),"draft":draft,"last_apply":s.get("last_apply")}
 def execute(self,action,params,progress=lambda *args,**kwargs:None):
  params=params or {}
  if action=="dns.draft_update":return self.manager.create_draft(params.get("expected_revision"),params.get("operations"))
  if action=="dns.preview":return self.manager.preview(params.get("draft_id"))
  if action=="dns.apply":return self.manager.apply(params.get("draft_id"),params.get("expected_revision"))
  if action=="dns.rollback":return self.manager.rollback(params.get("apply_id"),params.get("expected_revision"))
  if action=="dns.query":return self.diagnostics.query(params)
  if action=="dns.diagnose":return self.diagnostics.diagnose(params,progress)
  if action=="dns.leak_test":return self.diagnostics.leak_test(params,progress)
  raise DnsConfigError("unknown_action",404)

def create_extension(context):return DnsExtension(context)
