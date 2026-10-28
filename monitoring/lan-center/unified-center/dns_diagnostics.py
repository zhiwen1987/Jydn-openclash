"""Bounded DNS path diagnostics.  Evidence is scoped; unknown is never a pass."""
from __future__ import annotations
import concurrent.futures, ipaddress, json, os, random, secrets, socket, ssl, struct, threading, time, urllib.error, urllib.parse, urllib.request

QTYPE={"A":1,"CNAME":5,"AAAA":28,"RRSIG":46}; RCODE={0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",5:"REFUSED"}

class DiagnosticError(ValueError):
 def __init__(self,code,status=400):super().__init__(code);self.code,self.status=code,status

def _name(value):
 if not isinstance(value,str) or any(ord(char)<33 or ord(char)==127 for char in value):raise DiagnosticError("invalid_domain")
 value=value.strip().rstrip(".")
 try:value=".".join(part.encode("idna").decode("ascii") for part in value.split(".")).lower()
 except (UnicodeError,ValueError):raise DiagnosticError("invalid_domain") from None
 if not value or len(value)>253 or any(not part or len(part)>63 or part.startswith("-") or part.endswith("-") for part in value.split(".")):raise DiagnosticError("invalid_domain")
 return value
def _server(value):
 value=str(value or "").strip();host,port=value,53
 if value.startswith("["):host=value[1:value.index("]")];rest=value[value.index("]")+1:];port=int(rest[1:]) if rest.startswith(":") else 53
 elif value.count(":")==1:host,raw=value.rsplit(":",1);port=int(raw)
 try:ipaddress.ip_address(host)
 except ValueError:raise DiagnosticError("resolver_ip_required") from None
 if not 1<=port<=65535:raise DiagnosticError("invalid_resolver_port")
 return host,port
def _encode(name):return b"".join(bytes([len(p)])+p.encode("ascii") for p in name.split("."))+b"\0"
def _decode(raw,offset,visited=None):
 labels=[];visited=set() if visited is None else visited;end=None
 while True:
  if offset>=len(raw) or offset in visited:raise DiagnosticError("invalid_dns_packet")
  visited.add(offset);n=raw[offset]
  if n==0:offset+=1;break
  if n&0xc0==0xc0:
   if offset+1>=len(raw):raise DiagnosticError("invalid_dns_packet")
   pointer=((n&0x3f)<<8)|raw[offset+1];end=offset+2 if end is None else end;part,_=_decode(raw,pointer,visited);labels.append(part);offset=end;break
  if n>63 or offset+1+n>len(raw):raise DiagnosticError("invalid_dns_packet")
  labels.append(raw[offset+1:offset+1+n].decode("ascii"));offset+=1+n
 return ".".join(x for x in labels if x),offset
def _packet(domain,qtype,ident):
 # recursion desired + EDNS DO bit so AD/RRSIG evidence can be observed.
 return struct.pack("!HHHHHH",ident,0x0100,1,0,0,1)+_encode(domain)+struct.pack("!HH",QTYPE[qtype],1)+b"\0"+struct.pack("!HHIH",41,1232,0x8000,0)
def parse_response(raw,ident):
 if len(raw)<12:raise DiagnosticError("invalid_dns_packet")
 rid,flags,qd,an,ns,ar=struct.unpack("!HHHHHH",raw[:12])
 if rid!=ident or not flags&0x8000:raise DiagnosticError("dns_transaction_mismatch")
 offset=12
 questions=[]
 for _ in range(qd):
  qname,offset=_decode(raw,offset)
  if offset+4>len(raw):raise DiagnosticError("invalid_dns_packet")
  qtype,qclass=struct.unpack("!HH",raw[offset:offset+4]);offset+=4;questions.append((qname.lower().rstrip("."),qtype,qclass))
 records=[]
 for section,count in (("answer",an),("authority",ns),("additional",ar)):
  for _ in range(count):
   name,offset=_decode(raw,offset)
   if offset+10>len(raw):raise DiagnosticError("invalid_dns_packet")
   typ,klass,ttl,length=struct.unpack("!HHIH",raw[offset:offset+10]);offset+=10;start=offset;offset+=length
   if offset>len(raw):raise DiagnosticError("invalid_dns_packet")
   value=None
   if typ==1 and length==4:value=socket.inet_ntop(socket.AF_INET,raw[start:offset])
   elif typ==28 and length==16:value=socket.inet_ntop(socket.AF_INET6,raw[start:offset])
   elif typ==5:value,_=_decode(raw,start)
   if value is not None:records.append({"section":section,"name":name,"type":{1:"A",5:"CNAME",28:"AAAA"}.get(typ,str(typ)),"ttl":ttl,"value":value})
   elif typ==46:records.append({"section":section,"name":name,"type":"RRSIG","ttl":ttl,"value":"present"})
 return {"rcode":RCODE.get(flags&15,str(flags&15)),"truncated":bool(flags&0x0200),"authenticated_data":bool(flags&0x0020),"dnssec":"resolver_asserted_validated" if flags&0x0020 else "unknown","questions":questions,"records":records}

def _read_exact(sock,length):
 parts=[]
 while length:
  part=sock.recv(length)
  if not part:raise DiagnosticError("dns_tcp_short_read")
  parts.append(part);length-=len(part)
 return b"".join(parts)

def query_wire(domain,qtype,resolver,transport="udp",timeout=2.0):
 domain=_name(domain);qtype=str(qtype).upper()
 if qtype not in QTYPE:raise DiagnosticError("unsupported_qtype")
 host,port=_server(resolver);family=socket.AF_INET6 if ":" in host else socket.AF_INET;ident=random.SystemRandom().randrange(1,65536);payload=_packet(domain,qtype,ident);started=time.monotonic()
 with socket.socket(family,socket.SOCK_DGRAM if transport=="udp" else socket.SOCK_STREAM) as sock:
  sock.settimeout(timeout);sock.connect((host,port))
  if transport=="udp":sock.send(payload);raw=sock.recv(65535)
  elif transport=="tcp":
   sock.sendall(struct.pack("!H",len(payload))+payload);header=_read_exact(sock,2);raw=_read_exact(sock,struct.unpack("!H",header)[0])
  else:raise DiagnosticError("invalid_transport")
 result=parse_response(raw,ident)
 if result.get("questions")!=[(domain,QTYPE[qtype],1)]:raise DiagnosticError("dns_question_mismatch")
 result.update(domain=domain,qtype=qtype,resolver=f"{host}:{port}",transport=transport,elapsed_ms=round((time.monotonic()-started)*1000,1));return result

def _resolv_conf_resolver():
 try:lines=open("/etc/resolv.conf",encoding="utf-8").read().splitlines()
 except OSError:raise DiagnosticError("system_resolver_unavailable",503) from None
 for line in lines:
  fields=line.split("#",1)[0].split()
  if len(fields)==2 and fields[0]=="nameserver":
   try:_server(fields[1]);return fields[1]
   except (ValueError,DiagnosticError):continue
 raise DiagnosticError("system_resolver_unavailable",503)

def system_query(domain,qtype,timeout=2.0):
 if qtype not in {"A","AAAA"}:raise DiagnosticError("resolver_required_for_qtype")
 result=query_wire(domain,qtype,_resolv_conf_resolver(),"udp",timeout);result["resolver_view"]="container_system";return result

def _connect(domain,addresses,timeout,deadline=None):
 attempts=[]
 for address in addresses[:4]:
  remaining=timeout if deadline is None else min(timeout,max(0,deadline-time.monotonic()))
  if remaining<=0:break
  started=time.monotonic();row={"address":address,"tcp":False,"tls":False,"certificate_name":False}
  try:
   with socket.create_connection((address,443),timeout=remaining) as raw:
    row["tcp"]=True
    raw.settimeout(max(.05,min(remaining,deadline-time.monotonic())) if deadline is not None else remaining)
    with ssl.create_default_context().wrap_socket(raw,server_hostname=domain) as secure:
     row["tls"]=True;row["certificate_name"]=True;row["tls_version"]=secure.version()
  except (OSError,ssl.SSLError) as e:row["error"]=type(e).__name__
  row["elapsed_ms"]=round((time.monotonic()-started)*1000,1);attempts.append(row)
 return attempts

class DnsDiagnostics:
 def __init__(self,opener=None,max_workers=4,timeout=2.5,clock=time.time):
  self.opener=opener or urllib.request.build_opener();self.max_workers=max(1,min(int(max_workers),6));self.timeout=max(.5,min(float(timeout),8));self.clock=clock;self.lock=threading.Lock();self.last_leak=0;self.browser_plans={}
 def query(self,request):
  domain=_name(request.get("domain"));qtype=str(request.get("qtype","A")).upper();resolver=request.get("resolver")
  return query_wire(domain,qtype,resolver,request.get("transport","udp"),self.timeout) if resolver else system_query(domain,qtype)
 def diagnose(self,request,progress=lambda *args,**kwargs:None):
  mode=request.get("mode","quick");perspective=request.get("perspective","container");domains=request.get("domains",[])
  if mode not in {"quick","deep"} or perspective not in {"container","resolver"} or not isinstance(domains,list) or not 1<=len(domains)<=32:raise DiagnosticError("invalid_diagnostic_request")
  budget=request.get("deadline_seconds",12 if mode=="quick" else 45)
  if type(budget) not in (int,float) or not 1<=budget<=50:raise DiagnosticError("invalid_diagnostic_deadline")
  deadline=time.monotonic()+float(budget);domains=[_name(v) for v in domains]
  resolver=request.get("resolver");references=request.get("reference_resolvers",[]) if mode=="deep" else []
  if perspective=="resolver" and not resolver:raise DiagnosticError("resolver_required")
  expected=request.get("expected_policy",{});overrides=expected.get("overrides",{}) if isinstance(expected,dict) else {};fake=[]
  for raw in expected.get("fake_ip_cidrs",[]) if isinstance(expected,dict) else []:
   try:fake.append(ipaddress.ip_network(raw))
   except ValueError:raise DiagnosticError("invalid_expected_policy") from None
  rows=[];untested=[]
  for index,domain in enumerate(domains):
   if time.monotonic()>=deadline:untested.extend(domains[index:]);break
   answers=[];expired=False
   for qtype in ("A","AAAA"):
    transports=("udp","tcp") if resolver and mode=="deep" else ("udp",)
    for transport in transports:
     remaining=deadline-time.monotonic()
     if remaining<=0:expired=True;break
     try:answers.append(query_wire(domain,qtype,resolver,transport,min(self.timeout,remaining)) if resolver else system_query(domain,qtype,min(self.timeout,remaining)))
     except (OSError,DiagnosticError) as e:answers.append({"domain":domain,"qtype":qtype,"transport":transport if resolver else "system","state":"error","error":"timeout" if isinstance(e,(TimeoutError,socket.timeout)) else getattr(e,"code",type(e).__name__)})
    if expired:break
   refs=[]
   for reference in references[:3]:
    remaining=deadline-time.monotonic()
    if remaining<=0:expired=True;break
    try:refs.append(query_wire(domain,"A",reference,"udp",min(self.timeout,remaining)))
    except (OSError,DiagnosticError) as e:refs.append({"resolver":str(reference),"state":"error","error":"timeout" if isinstance(e,(TimeoutError,socket.timeout)) else getattr(e,"code",type(e).__name__)})
   values={r["value"] for a in answers for r in a.get("records",[]) if r.get("type") in {"A","AAAA"}}
   reference_values={r["value"] for a in refs for r in a.get("records",[]) if r.get("type") in {"A","AAAA"}}
   expected_values=set(overrides.get(domain,[]));expected_match=bool(expected_values) and values<=expected_values
   fake_match=bool(values) and all(any(ipaddress.ip_address(v) in net for net in fake) for v in values)
   suspected_fake=bool(values) and all(ipaddress.ip_address(v) in ipaddress.ip_network("198.18.0.0/15") for v in values)
   difference=bool(values and reference_values and values.isdisjoint(reference_values))
   connect=_connect(domain,sorted(values),self.timeout,deadline) if mode=="deep" and values and not expected_match and not fake_match and not suspected_fake and not expired else []
   if mode=="deep" and values and not expected_match and not fake_match and not suspected_fake and not connect and time.monotonic()>=deadline:expired=True
   tls_any=any(v.get("tls") for v in connect);state="ok"
   reason="consistent_or_reachable"
   if expired:state="unknown";reason="deadline_exhausted"
   elif expected_match or fake_match:reason="expected_local_or_fake_ip"
   elif suspected_fake:state="unknown";reason="possible_fake_ip_requires_policy"
   elif difference and not connect:state="unknown";reason="resolver_difference_requires_connection_evidence"
   elif difference and not tls_any:state="anomaly";reason="resolver_difference_and_tls_failure"
   elif all(a.get("state")=="error" or a.get("rcode","").startswith("ERROR") for a in answers):state="error";reason="dns_failed"
   elif mode=="deep" and values and connect and not tls_any:state="unknown";reason="connection_or_tls_failed"
   elif not values:state="unknown";reason="dns_no_address_answer"
   rows.append({"domain":domain,"state":state,"reason":reason,"answers":answers,"references":refs,"connection":connect,"expected_match":expected_match or fake_match})
   progress("domain",domain=domain,state=state)
  states=[v["state"] for v in rows];overall="error" if "error" in states else "anomaly" if "anomaly" in states else "unknown" if "unknown" in states else "ok"
  if untested:overall="unknown"
  stages={"dns":{"state":overall,"queries":sum(len(v["answers"])+len(v["references"]) for v in rows)},"connection":{"state":"checked" if any(v["connection"] for v in rows) else "not_run"},"tls":{"state":"ok" if any(any(a.get("tls") for a in v["connection"]) for v in rows) else "not_verified"}}
  return {"state":overall,"checked_at":self.clock(),"evidence_scope":perspective,"confidence":"high" if mode=="deep" and overall in {"ok","anomaly"} and not untested else "limited","partial":bool(untested) or any(v["reason"]=="deadline_exhausted" for v in rows),"untested":untested,"stages":stages,"domains":rows}
 def leak_test(self,request,progress=lambda *args,**kwargs:None):
  mode=request.get("mode","quick");perspective=request.get("perspective","container");sites=request.get("sites",["dnsleak.dev","ipleak","browserleaks","dnsleaktest"])
  if mode not in {"quick","deep"} or perspective not in {"container","browser"} or not isinstance(sites,list) or not 1<=len(sites)<=4 or len(sites)!=len(set(sites)):raise DiagnosticError("invalid_leak_request")
  catalog={
   "dnsleak.dev":{"mode":"automatic","url":"https://dnsleak.dev/api"},
   "ipleak":{"mode":"browser","url":"https://ipleak.net/"},
   "browserleaks":{"mode":"manual_external","url":"https://browserleaks.com/dns"},
   "dnsleaktest":{"mode":"manual_external","url":"https://www.dnsleaktest.com/"}}
  if any(v not in catalog for v in sites):raise DiagnosticError("unknown_leak_site")
  if perspective=="browser":
   phase=request.get("phase","status")
   if phase=="plan":return self._browser_plan(sites,catalog)
   if phase=="readout":return self._browser_readout(request.get("plan_id"),catalog)
   if phase!="status":raise DiagnosticError("invalid_leak_phase")
   return {"state":"unknown","checked_at":self.clock(),"evidence_scope":"browser","confidence":"unknown","stages":{"probe":{"state":"not_run"},"readout":{"state":"manual_required"}},"sites":[{"id":v,"state":"pending","detail":"browser_or_manual_evidence_required",**catalog[v]} for v in sites],"browser_plan":{"privacy":"third_party_sites_observe_test_ip_and_random_dns_queries","no_real_history_uploaded":True,"server_generated_probe_hosts":False}}
  results=[]
  for site in sites:
   if site=="dnsleak.dev":
    try:row=self._dnsleak_dev()
    except urllib.error.HTTPError as e:row={"id":site,"mode":"automatic","state":"unknown" if e.code==429 else "error","detail":"rate_limited" if e.code==429 else "site_http_error","status":e.code}
    except DiagnosticError as e:row={"id":site,"mode":"automatic","state":"unknown" if e.code in {"rate_limited","system_resolver_unavailable","site_protocol_changed"} else "error","detail":e.code}
    except Exception as e:row={"id":site,"mode":"automatic","state":"error","detail":"site_unavailable","error":type(e).__name__}
   else:row={"id":site,"state":"unknown","detail":"browser_or_manual_evidence_required",**catalog[site]}
   row["checked_at"]=self.clock();results.append(row);progress("site",site=site,state=row["state"])
  automatic=[v for v in results if v["mode"]=="automatic"];overall="anomaly" if any(v["state"]=="anomaly" for v in automatic) else "error" if automatic and all(v["state"]=="error" for v in automatic) else "ok" if automatic and all(v["state"]=="ok" for v in automatic) else "unknown"
  return {"state":overall,"checked_at":self.clock(),"evidence_scope":"container","confidence":"limited","stages":{"probe":{"state":"complete" if automatic else "not_run"},"readout":{"state":overall}},"sites":results,"privacy":{"no_real_history_uploaded":True,"third_party_observes_test_ip_and_random_queries":True}}
 def _begin_dnsleak(self):
  with self.lock:
   now=time.monotonic()
   if now-self.last_leak<2:raise DiagnosticError("rate_limited",429)
   self.last_leak=now
  start=self._get("https://dnsleak.dev/api/new");ident=start.get("testId");hosts=start.get("hostnames")
  if not isinstance(ident,str) or not 1<=len(ident)<=128 or not isinstance(hosts,list) or not 1<=len(hosts)<=64:raise DiagnosticError("site_protocol_changed")
  clean=[]
  for host in hosts:
   try:value=_name(host)
   except DiagnosticError:raise DiagnosticError("site_protocol_changed") from None
   if not value.endswith(".t.dnsleak.dev") or value=="t.dnsleak.dev":raise DiagnosticError("site_protocol_changed")
   clean.append(value)
  if len(clean)!=len(set(clean)):raise DiagnosticError("site_protocol_changed")
  return ident,clean
 def _read_dnsleak(self,ident):
  report=self._get("https://dnsleak.dev/api/result/"+urllib.parse.quote(ident,safe=""));verdict=report.get("verdict",{});status=verdict.get("status")
  state={"no_leak":"ok","split":"anomaly","leak":"anomaly","inconclusive":"unknown"}.get(status,"unknown")
  return {"id":"dnsleak.dev","mode":"automatic","state":state,"detail":str(verdict.get("detail",""))[:300],"verdict":status,"lookups":report.get("lookups"),"resolver_groups":len(report.get("groups",[])) if isinstance(report.get("groups"),list) else None,"dnssec_note":"dnssecOk only indicates DO-bit awareness, not signature validation"}
 def _browser_plan(self,sites,catalog):
  rows=[];plan=None
  if "dnsleak.dev" in sites:
   ident,hosts=self._begin_dnsleak();now=self.clock();local_id=secrets.token_urlsafe(24);expires=now+540
   with self.lock:
    self.browser_plans={key:value for key,value in self.browser_plans.items() if value["expires_at"]>now}
    self.browser_plans[local_id]={"remote_id":ident,"hosts":hosts,"sites":tuple(sites),"expires_at":expires}
   while len(self.browser_plans)>32:self.browser_plans.pop(next(iter(self.browser_plans)))
   plan={"plan_id":local_id,"expires_at":expires,"probe_urls":[{"url":"https://"+host+"/","qtype":"AAAA" if "-q" in host else "A"} for host in hosts],"fetch_options":{"mode":"no-cors","credentials":"omit","referrerPolicy":"no-referrer","cache":"no-store"},"required_csp_connect_src":["https://*.t.dnsleak.dev"],"readout_after_ms":2000,"server_must_not_resolve_probe_hosts":True}
   rows.append({"id":"dnsleak.dev","mode":"automatic","state":"pending","detail":"awaiting_browser_probe", "url":catalog["dnsleak.dev"]["url"]})
  rows.extend({"id":site,"state":"pending","detail":"manual_evidence_required",**catalog[site]} for site in sites if site!="dnsleak.dev")
  return {"state":"unknown","checked_at":self.clock(),"evidence_scope":"browser","confidence":"unknown","stages":{"probe":{"state":"pending" if plan else "not_run"},"readout":{"state":"pending" if plan else "manual_required"}},"sites":rows,"browser_plan":plan,"privacy":{"no_real_history_uploaded":True,"third_party_observes_test_ip_and_random_queries":bool(plan)}}
 def _browser_readout(self,plan_id,catalog):
  if not isinstance(plan_id,str) or len(plan_id)>128:raise DiagnosticError("invalid_browser_plan")
  with self.lock:plan=self.browser_plans.get(plan_id)
  if not plan or plan["expires_at"]<=self.clock():raise DiagnosticError("browser_plan_expired",410)
  try:auto=self._read_dnsleak(plan["remote_id"])
  except urllib.error.HTTPError as e:
   auto={"id":"dnsleak.dev","mode":"automatic","state":"unknown" if e.code==429 else "error","detail":"rate_limited" if e.code==429 else "site_http_error","status":e.code}
  auto["checked_at"]=self.clock();rows=[auto]+[{"id":site,"state":"unknown","detail":"manual_evidence_required",**catalog[site]} for site in plan["sites"] if site!="dnsleak.dev"]
  overall="anomaly" if auto["state"]=="anomaly" else "ok" if auto["state"]=="ok" else "error" if auto["state"]=="error" else "unknown"
  return {"state":overall,"checked_at":self.clock(),"evidence_scope":"browser","confidence":"high" if overall in {"ok","anomaly"} else "limited","stages":{"probe":{"state":"reported_by_browser"},"readout":{"state":overall}},"sites":rows,"browser_plan":{"plan_id":plan_id,"expires_at":plan["expires_at"],"server_resolved_probe_hosts":False},"privacy":{"no_real_history_uploaded":True,"third_party_observes_test_ip_and_random_queries":True}}
 def _system_resolver(self):
  return _resolv_conf_resolver()
 def _get(self,url):
  req=urllib.request.Request(url,headers={"Accept":"application/json","User-Agent":"Jydn-Clash-Center-DNS-Diagnostics/1"})
  with self.opener.open(req,timeout=min(8,self.timeout*2)) as response:
   if int(response.headers.get("Content-Length","0") or 0)>1024*1024:raise DiagnosticError("site_response_too_large")
   raw=response.read(1024*1024+1)
   if len(raw)>1024*1024:raise DiagnosticError("site_response_too_large")
   value=json.loads(raw)
   if not isinstance(value,dict):raise DiagnosticError("site_protocol_changed")
   return value
 def _dnsleak_dev(self):
  ident,hosts=self._begin_dnsleak()
  resolver=self._system_resolver()
  def resolve(host):
   if not isinstance(host,str) or not host.endswith(".t.dnsleak.dev"):raise DiagnosticError("site_protocol_changed")
   try:query_wire(host,"AAAA" if "-q" in host else "A",resolver,"udp",min(self.timeout,2.5))
   except (OSError,DiagnosticError):pass
  with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:list(pool.map(resolve,hosts))
  time.sleep(1);return self._read_dnsleak(ident)
