import importlib.util,json,os,struct,sys,tempfile,unittest
from pathlib import Path
from unittest import mock

HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
def load(name):
 spec=importlib.util.spec_from_file_location(name,HERE/(name+".py"));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
M=load("dns_management");D=load("dns_diagnostics")

CORE=""".:53 {
    health 127.0.0.1:18080
    cache 300
    forward . 10.88.0.254:7874 {
        policy sequential
        health_check 5s domain .
    }
}
"""

class ManagementTests(unittest.TestCase):
 def setup(self,runtime=True):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name);core=root/"Corefile";core.write_text(CORE)
  calls=[]
  validator=lambda core,fragment,hosts:{"state":"ok","isolated":True}
  def reloader(**kwargs):calls.append("reload");return {"state":"completed","request_id":kwargs.get("request_id"),"loaded_core_sha256":kwargs.get("expected_core_sha256"),"loaded_fragment_sha256":kwargs.get("expected_fragment_sha256"),"purpose":kwargs.get("purpose"),"recovery_of":kwargs.get("recovery_of")}
  probe=lambda:{"state":"ok","udp":True,"tcp":True}
  manager=M.DnsManager(root/"state",core,root/"state/Corefile.managed",root/"state/hosts",validator if runtime else None,reloader if runtime else None,probe if runtime else None)
  return manager,core,calls
 def migrate_draft(self,manager,extra=None):
  operations=[{"kind":"migration","action":"adopt"}]+(extra or [])
  draft=manager.create_draft(manager.revision(),operations);manager.preview(draft["id"]);return draft
 def test_read_only_status_does_not_migrate(self):
  manager,core,_=self.setup();before=core.read_bytes();status=manager.status();self.assertEqual(status["state"],"unmanaged");self.assertEqual(core.read_bytes(),before);self.assertFalse((manager.root/"active.json").exists())
 def test_migration_preserves_unmanaged_bytes_and_adopts_forward(self):
  manager,core,_=self.setup();draft=self.migrate_draft(manager,[{"kind":"host","action":"add","id":"lan","name":"router.example","address":"10.88.0.254"}]);value,_=manager.draft(draft["id"])
  self.assertIn("health 127.0.0.1:18080",value["migration_core"]);self.assertIn(M.BEGIN,value["migration_core"]);self.assertNotIn("forward . 10.88.0.254",value["migration_core"])
  self.assertIn("policy sequential",M.render_fragment(value["model"],manager.hosts));self.assertEqual(core.read_text(),CORE)
 def test_apply_and_rollback_are_cas_guarded(self):
  manager,core,calls=self.setup();before=manager.revision();draft=self.migrate_draft(manager);receipt=manager.apply(draft["id"],before)
  self.assertEqual(calls,["reload"]);self.assertIn(M.BEGIN,core.read_text());self.assertEqual(manager.status()["state"],"ready")
  with self.assertRaisesRegex(M.DnsConfigError,"revision_conflict"):manager.rollback(receipt["id"],"bad")
  result=manager.rollback(receipt["id"],receipt["revision"]);self.assertEqual(result["state"],"rolled_back");self.assertEqual(core.read_text(),CORE);self.assertEqual(manager.status()["last_apply"]["state"],"rolled_back")
 def test_failed_readback_restores_every_file(self):
  manager,core,calls=self.setup();states=iter([{"state":"error"},{"state":"ok"}]);manager.probe=lambda:next(states);before=manager.revision();draft=self.migrate_draft(manager)
  with self.assertRaisesRegex(M.DnsConfigError,"runtime_readback_failed"):manager.apply(draft["id"],before)
  self.assertEqual(core.read_text(),CORE);self.assertFalse(manager.fragment.exists());self.assertFalse((manager.root/"active.json").exists());self.assertEqual(calls,["reload","reload"])
 def test_apply_recovery_failure_is_explicit(self):
  manager,_,_=self.setup();manager.probe=lambda:{"state":"error"};before=manager.revision();draft=self.migrate_draft(manager)
  with self.assertRaisesRegex(M.DnsConfigError,"apply_recovery_failed"):manager.apply(draft["id"],before)
 def test_reload_ack_must_match_request_and_loaded_hash(self):
  manager,core,_=self.setup();manager.reloader=lambda **kwargs:{"state":"completed","request_id":"stale","loaded_core_sha256":kwargs["expected_core_sha256"]}
  with self.assertRaisesRegex(M.DnsConfigError,"runtime_reload_ack_mismatch"):manager._reload_and_probe("fresh",core.read_bytes(),b"","apply")
 def test_recovery_is_linked_to_failed_request(self):
  manager,_,_=self.setup();seen=[]
  def reloader(**kwargs):seen.append(kwargs);return {"state":"completed","request_id":kwargs["request_id"],"loaded_core_sha256":kwargs["expected_core_sha256"],"loaded_fragment_sha256":kwargs["expected_fragment_sha256"],"purpose":kwargs["purpose"],"recovery_of":kwargs["recovery_of"]}
  manager.reloader=reloader;states=iter([{"state":"error"},{"state":"ok"}]);manager.probe=lambda:next(states);before=manager.revision();draft=self.migrate_draft(manager)
  with self.assertRaisesRegex(M.DnsConfigError,"runtime_readback_failed"):manager.apply(draft["id"],before)
  self.assertEqual([row["purpose"] for row in seen],["apply","recovery"]);self.assertEqual(seen[1]["recovery_of"],seen[0]["request_id"])
 def test_pre_restart_refusal_restores_files_without_minting_recovery(self):
  manager,core,_=self.setup();seen=[]
  def refused(**kwargs):seen.append(kwargs);return {"state":"error","error_code":"restart_budget_refused","recovery_required":False}
  manager.reloader=refused;before=manager.revision();draft=self.migrate_draft(manager)
  with self.assertRaisesRegex(M.DnsConfigError,"runtime_reload_failed"):manager.apply(draft["id"],before)
  self.assertEqual(len(seen),1);self.assertEqual(seen[0]["purpose"],"apply");self.assertEqual(core.read_text(),CORE);self.assertFalse(manager.fragment.exists())
 def test_failed_rollback_restores_newer_working_configuration(self):
  manager,core,calls=self.setup();before=manager.revision();draft=self.migrate_draft(manager);receipt=manager.apply(draft["id"],before);applied=core.read_bytes();states=iter([{"state":"error"},{"state":"ok"}]);manager.probe=lambda:next(states)
  with self.assertRaisesRegex(M.DnsConfigError,"rollback_readback_failed"):manager.rollback(receipt["id"],receipt["revision"])
  self.assertEqual(core.read_bytes(),applied);self.assertEqual(manager.status()["state"],"ready")
 def test_no_runtime_callbacks_means_preview_only(self):
  manager,_,_=self.setup(False);draft=self.migrate_draft(manager)
  with self.assertRaisesRegex(M.DnsConfigError,"runtime_verification_unavailable"):manager.apply(draft["id"],manager.revision())
 def test_last_upstream_and_tls_sni_fail_closed(self):
  manager,_,_=self.setup();base=manager.revision()
  with self.assertRaisesRegex(M.DnsConfigError,"last_upstream_required"):manager.create_draft(base,[{"kind":"migration","action":"adopt"},{"kind":"upstream","action":"disable","id":"upstream-1"}])
  with self.assertRaisesRegex(M.DnsConfigError,"tls_servername_required"):manager.create_draft(base,[{"kind":"migration","action":"adopt"},{"kind":"upstream","action":"add","id":"dot","target":"tls://9.9.9.9"}])
  with self.assertRaisesRegex(M.DnsConfigError,"invalid_domain"):manager.create_draft(base,[{"kind":"migration","action":"adopt"},{"kind":"host","action":"add","id":"wild","name":"*.example.com","address":"10.0.0.1"}])
  for target in ("[2001:db8::1]:99999","tls://9.9.9.9/unexpected"):
   with self.assertRaisesRegex(M.DnsConfigError,"invalid_upstream"):manager.create_draft(base,[{"kind":"migration","action":"adopt"},{"kind":"upstream","action":"add","id":"bad","target":target}])
 def test_extension_runtime_actions_require_explicit_write_probe(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name);core=root/"Corefile";core.write_text(CORE)
  old_state=os.environ.get("CENTER_DNS_MANAGED_DIR");old_core=os.environ.get("CENTER_COREFILE");os.environ["CENTER_DNS_MANAGED_DIR"]=str(root/"state");os.environ["CENTER_COREFILE"]=str(core)
  self.addCleanup(lambda:os.environ.__setitem__("CENTER_DNS_MANAGED_DIR",old_state) if old_state is not None else os.environ.pop("CENTER_DNS_MANAGED_DIR",None));self.addCleanup(lambda:os.environ.__setitem__("CENTER_COREFILE",old_core) if old_core is not None else os.environ.pop("CENTER_COREFILE",None))
  callbacks={"dns_runtime_deadline_enforced":True,"dns_validator":lambda *args:{"state":"ok"},"dns_reloader":lambda **kwargs:{"state":"completed","request_id":kwargs["request_id"],"loaded_core_sha256":kwargs["expected_core_sha256"],"loaded_fragment_sha256":kwargs["expected_fragment_sha256"],"purpose":kwargs["purpose"],"recovery_of":kwargs["recovery_of"]},"dns_probe":lambda:{"state":"ok"},"write_lock_managed":True}
  extension=M.create_extension(callbacks);self.assertFalse(extension.actions()["dns.apply"]["supported"]);self.assertTrue(extension.manager.external_lock)
  callbacks["dns_runtime_writable_verified"]=True;extension=M.create_extension(callbacks);self.assertTrue(extension.actions()["dns.apply"]["supported"])

class DiagnosticTests(unittest.TestCase):
 class Response:
  def __init__(self,value):self.value=json.dumps(value).encode();self.headers={"Content-Length":str(len(self.value))}
  def __enter__(self):return self
  def __exit__(self,*args):return False
  def read(self,*args):return self.value
 def answer(self,ident,address="1.2.3.4",ad=False):
  flags=0x8180|(0x20 if ad else 0);question=b"\x07example\x03com\0"+struct.pack("!HH",1,1);record=b"\xc0\x0c"+struct.pack("!HHIH",1,1,60,4)+bytes(map(int,address.split(".")));return struct.pack("!HHHHHH",ident,flags,1,1,0,0)+question+record
 def test_dnssec_is_unknown_without_ad_and_asserted_with_ad(self):
  one=D.parse_response(self.answer(7),7);two=D.parse_response(self.answer(8,ad=True),8);self.assertEqual(one["dnssec"],"unknown");self.assertEqual(two["dnssec"],"resolver_asserted_validated")
 def test_rcode_and_cname_are_preserved_as_evidence(self):
  ident=9;question=b"\x07example\x03com\0"+struct.pack("!HH",5,1);target=b"\x03www\x07example\x03com\0";answer=b"\xc0\x0c"+struct.pack("!HHIH",5,1,60,len(target))+target
  parsed=D.parse_response(struct.pack("!HHHHHH",ident,0x8180,1,1,0,0)+question+answer,ident);self.assertEqual(parsed["rcode"],"NOERROR");self.assertEqual(parsed["records"][0]["type"],"CNAME");self.assertEqual(parsed["records"][0]["value"],"www.example.com")
  nx=D.parse_response(struct.pack("!HHHHHH",10,0x8183,0,0,0,0),10);sf=D.parse_response(struct.pack("!HHHHHH",11,0x8182,0,0,0,0),11);self.assertEqual(nx["rcode"],"NXDOMAIN");self.assertEqual(sf["rcode"],"SERVFAIL")
 def test_system_cname_refuses_to_invent_evidence(self):
  with self.assertRaisesRegex(D.DiagnosticError,"resolver_required_for_qtype"):D.DnsDiagnostics().query({"domain":"example.com","qtype":"CNAME"})
 def test_expected_fake_ip_avoids_pollution_false_positive(self):
  diagnostic=D.DnsDiagnostics()
  def system(domain,qtype,*args):return {"domain":domain,"qtype":qtype,"rcode":"NOERROR","records":[{"type":qtype,"value":"198.18.0.1"}] if qtype=="A" else []}
  with mock.patch.object(D,"system_query",side_effect=system):
   result=diagnostic.diagnose({"mode":"deep","perspective":"container","domains":["example.com"],"expected_policy":{"fake_ip_cidrs":["198.18.0.0/16"]}})
  self.assertEqual(result["state"],"ok");self.assertEqual(result["domains"][0]["reason"],"expected_local_or_fake_ip")
 def test_unannounced_fake_ip_is_unknown_not_safe_or_polluted(self):
  diagnostic=D.DnsDiagnostics()
  with mock.patch.object(D,"system_query",side_effect=lambda domain,qtype,*args:{"domain":domain,"qtype":qtype,"rcode":"NOERROR","records":[{"type":qtype,"value":"198.18.0.9"}] if qtype=="A" else []}):result=diagnostic.diagnose({"mode":"deep","perspective":"container","domains":["example.com"]})
  self.assertEqual(result["state"],"unknown");self.assertEqual(result["domains"][0]["reason"],"possible_fake_ip_requires_policy")
 def test_difference_without_connection_evidence_is_unknown(self):
  diagnostic=D.DnsDiagnostics()
  def system(domain,qtype,*args):return {"domain":domain,"qtype":qtype,"rcode":"NOERROR","records":[{"type":qtype,"value":"1.1.1.1"}] if qtype=="A" else []}
  def wire(domain,qtype,*args,**kwargs):return {"domain":domain,"qtype":qtype,"rcode":"NOERROR","records":[{"type":qtype,"value":"2.2.2.2"}] if qtype=="A" else []}
  with mock.patch.object(D,"system_query",side_effect=system),mock.patch.object(D,"query_wire",side_effect=wire),mock.patch.object(D,"_connect",return_value=[]):result=diagnostic.diagnose({"mode":"deep","perspective":"container","domains":["example.com"],"reference_resolvers":["9.9.9.9"]})
  self.assertEqual(result["state"],"unknown");self.assertEqual(result["domains"][0]["reason"],"resolver_difference_requires_connection_evidence")
 def test_diagnostic_deadline_returns_partial_unknown(self):
  diagnostic=D.DnsDiagnostics();ticks=iter([0,0,2,2,2,2,2,2,2,2])
  with mock.patch.object(D.time,"monotonic",side_effect=lambda:next(ticks)),mock.patch.object(D,"system_query",return_value={"rcode":"NOERROR","records":[]}):
   result=diagnostic.diagnose({"mode":"quick","perspective":"container","domains":["one.example","two.example"],"deadline_seconds":1})
  self.assertEqual(result["state"],"unknown");self.assertTrue(result["partial"]);self.assertIn("two.example",result["untested"])
 def test_name_rejects_missing_control_and_accepts_idna(self):
  for value in (None,"bad\n.example","bad..example","-bad.example"):
   with self.assertRaisesRegex(D.DiagnosticError,"invalid_domain"):D._name(value)
  self.assertEqual(D._name("例子.测试"),"xn--fsqu00a.xn--0zwm56d")
 def test_tcp_read_exact_accepts_fragmented_header(self):
  sock=mock.Mock();sock.recv.side_effect=[b"\x00",b"\x05",b"ab",b"cde"];self.assertEqual(D._read_exact(sock,2),b"\x00\x05");self.assertEqual(D._read_exact(sock,5),b"abcde")
 def test_browser_and_manual_sites_are_not_reported_as_passed(self):
  result=D.DnsDiagnostics().leak_test({"perspective":"browser","mode":"quick"});self.assertEqual(result["state"],"unknown");self.assertTrue(all(v["state"]=="pending" for v in result["sites"]));self.assertFalse(result["browser_plan"]["server_generated_probe_hosts"])
 def test_browser_plan_and_readout_never_resolve_probe_on_server(self):
  opener=mock.Mock();opener.open.side_effect=[self.Response({"testId":"remote","hostnames":["remote-a.t.dnsleak.dev","remote-q.t.dnsleak.dev"]}),self.Response({"verdict":{"status":"no_leak","detail":"expected resolver"},"lookups":2,"groups":[{}]})];diagnostic=D.DnsDiagnostics(opener=opener)
  with mock.patch.object(D,"query_wire") as wire:
   plan=diagnostic.leak_test({"perspective":"browser","mode":"quick","phase":"plan","sites":["dnsleak.dev","ipleak"]});result=diagnostic.leak_test({"perspective":"browser","mode":"quick","phase":"readout","plan_id":plan["browser_plan"]["plan_id"]})
  wire.assert_not_called();self.assertEqual(result["state"],"ok");self.assertFalse(result["browser_plan"]["server_resolved_probe_hosts"]);self.assertEqual(plan["browser_plan"]["required_csp_connect_src"],["https://*.t.dnsleak.dev"]);self.assertTrue(all(v["url"].endswith(".t.dnsleak.dev/") for v in plan["browser_plan"]["probe_urls"]))
 def test_single_automatic_site_failure_is_isolated(self):
  diagnostic=D.DnsDiagnostics();diagnostic._dnsleak_dev=lambda:(_ for _ in ()).throw(OSError("offline"));result=diagnostic.leak_test({"perspective":"container","mode":"quick"})
  self.assertEqual(result["state"],"error");self.assertEqual(result["sites"][0]["state"],"error");self.assertTrue(all(v["state"]=="unknown" for v in result["sites"][1:]))
 def test_dnsleak_protocol_uses_bounded_wire_queries_and_preserves_unknown(self):
  opener=mock.Mock();opener.open.side_effect=[self.Response({"testId":"abc","hostnames":["abc-a.t.dnsleak.dev","abc-q.t.dnsleak.dev"]}),self.Response({"verdict":{"status":"inconclusive","detail":"not enough evidence"},"lookups":0,"groups":[]})];diagnostic=D.DnsDiagnostics(opener=opener)
  with mock.patch.object(diagnostic,"_system_resolver",return_value="127.0.0.53"),mock.patch.object(D,"query_wire",return_value={"state":"ok"}) as wire,mock.patch.object(D.time,"sleep"):
   result=diagnostic._dnsleak_dev()
  self.assertEqual(result["state"],"unknown");self.assertEqual(result["verdict"],"inconclusive");self.assertEqual({call.args[1] for call in wire.call_args_list},{"A","AAAA"});self.assertTrue(all(call.args[2]=="127.0.0.53" for call in wire.call_args_list))

if __name__=="__main__":unittest.main()
