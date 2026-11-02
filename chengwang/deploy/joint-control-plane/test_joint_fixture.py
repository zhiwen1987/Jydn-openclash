from __future__ import annotations
import base64, importlib.util, json, pathlib, struct, tempfile, unittest
HERE=pathlib.Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
C=load("joint_fixture_test_contract","contract.py");F=load("joint_fixture_test_target","joint_fixture.py")

class JointFixtureContracts(unittest.TestCase):
    def test_known_aaaa_is_noerror_nodata_not_nxdomain(self):
        def query(host,qtype,qclass=1):
            labels=b"".join(bytes((len(x),))+x.encode() for x in host.split("."))+b"\0";return struct.pack("!HHHHHH",7,0x0100,1,0,0,0)+labels+struct.pack("!HH",qtype,qclass)
        a,_,known,answers,rcode=F.dns_response(query(C.SOURCE_HOSTS["success"],1));self.assertTrue(known);self.assertEqual((answers,rcode),(1,0));self.assertEqual(struct.unpack("!H",a[2:4])[0]&15,0);self.assertEqual(struct.unpack("!H",a[6:8])[0],1)
        aaaa,_,known,answers,rcode=F.dns_response(query(C.SOURCE_HOSTS["success"],28));self.assertTrue(known);self.assertEqual((answers,rcode),(0,0));self.assertEqual(struct.unpack("!H",aaaa[2:4])[0]&15,0);self.assertEqual(struct.unpack("!H",aaaa[6:8])[0],0)
        missing,_,known,_,rcode=F.dns_response(query("missing.subscription.example",28));self.assertFalse(known);self.assertEqual(rcode,3);self.assertEqual(struct.unpack("!H",missing[2:4])[0]&15,3)
        invalid,_,known,answers,rcode=F.dns_response(query(C.SOURCE_HOSTS["success"],15));self.assertTrue(known);self.assertEqual((answers,rcode),(0,5));self.assertEqual(struct.unpack("!H",invalid[2:4])[0]&15,5)
        wrong_class,_,known,answers,rcode=F.dns_response(query(C.SOURCE_HOSTS["success"],1,3));self.assertTrue(known);self.assertEqual((answers,rcode),(0,5));self.assertEqual(struct.unpack("!H",wrong_class[2:4])[0]&15,5)
    def test_phase_switch_is_bounded_and_exact(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d); body=b"proxies:\n  - {name: A, type: direct}\n"
            (root/"phase.private.json").write_bytes(C.canonical({"successBody":base64.b64encode(body).decode(),"failureStatus":503}))
            state=type("S",(),{"root":root})(); self.assertEqual(F.phase(state),(body,503))
            (root/"phase.private.json").write_bytes(C.canonical({"successBody":base64.b64encode(body).decode(),"failureStatus":302}))
            with self.assertRaises(F.Rejected):F.phase(state)
    def test_dns_name_parser_rejects_compression_and_truncation(self):
        packet=b"\0"*12+b"\7success\x0csubscription\7example\0"
        self.assertEqual(F.decode_name(packet,12)[0],C.SOURCE_HOSTS["success"])
        with self.assertRaises(F.Rejected):F.decode_name(b"\0"*12+b"\xc0\x0c",12)
    def test_event_projection_never_contains_tokens_or_headers(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);s=F.State(root,{"sourceTokens":{"success":"PRIVATE"}});s.event("source","response",reference="success",path="/subscription",status=200,bytes=12)
            value=json.loads((root/"wire-events.jsonl").read_bytes())
            self.assertEqual(set(value),{"schema","ordinal","service","event","reference","method","path","status","bytes","fixturePid","connection","sourceHost","tlsClass","authClass","responseClass","receivedUnixNano"})
            self.assertNotIn("PRIVATE",json.dumps(value));self.assertEqual(value["ordinal"],1)
    def test_tls_public_san_sets_are_exact(self):
        self.assertEqual(set(C.SOURCE_HOSTS.values()),{"success.subscription.example","failure.subscription.example"})
        self.assertEqual(C.SOURCE_IP,"8.8.4.4");self.assertNotIn("*",C.DOT_NAME+"".join(C.SOURCE_HOSTS.values()))
    def test_fixture_has_no_public_egress_address(self):
        self.assertEqual(C.DOT,("127.0.0.1",1853));self.assertEqual(C.SOURCE,("8.8.4.4",443));self.assertEqual(C.MIHOMO,("8.8.4.4",9443))
    def test_every_non_get_method_is_logged_and_rejected(self):
        for method in ("HEAD","POST","PUT","PATCH","DELETE","OPTIONS","CONNECT","TRACE"):
            self.assertIs(getattr(F.Handler,"do_"+method),F.Handler.reject_non_get)

if __name__=="__main__":unittest.main()
