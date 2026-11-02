from __future__ import annotations
import importlib.util,json,pathlib,tempfile,unittest
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("joint_sanitizer_test",HERE/"sanitize_publication.py");S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
def put(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(S.canonical(value) if not isinstance(value,bytes) else value)
def private_tree(root,stage):
    token="source-token-0123456789";mihomo="mihomo-token-0123456789"
    source=lambda ref:{"referenceId":ref,"revision":1,"secretVersion":"v1","url":"https://"+ref+".subscription.example/subscription?token="+token+ref,"allowedCnames":[],"caPEM":"PUBLIC-CA"}
    p0={"version":1,"scope":{"tenantId":"joint-control-plane","siteId":"isolated","environment":"candidate"},"resolver":{"upstream":"127.0.0.1:1853","serverName":"resolver.joint.example","caPEM":"PUBLIC-CA"},"sources":[source("success"),source("failure")]};p1=json.loads(json.dumps(p0))
    for i,item in enumerate(p1["sources"]):item["refresh"]={"sourceId":"src_"+str(i+1)*32,"approvalId":"cmd_"+str(i+3)*32,"approvalSourceRevision":3,"intervalSeconds":60,"approvalTtlSeconds":600,"maxStaleSeconds":300,"maxBackoffSeconds":600}
    human={"tokenId":"viewer","tokenHash":"a"*64,"principal":{"id":"viewer@joint.test","tenantId":"joint-control-plane","roles":["viewer"],"allowedScopes":[{"tenantId":"joint-control-plane","siteId":"isolated","environment":"candidate"}]}}
    machine={"tokenId":"refresh-machine","tokenHash":"b"*64,"principal":{"id":"refresh-machine","tenantId":"joint-control-plane","roles":["subscription_refresher"],"allowedScopes":[{"tenantId":"joint-control-plane","siteId":"isolated","environment":"candidate","objectType":"subscription-source","objectId":"src_"+str(i+1)*32} for i in range(2)]}}
    put(root/"policy0.json",p0);put(root/"policy1.json",p1);put(root/"identities0.json",{"version":1,"identities":[human]});put(root/"identities1.json",{"version":1,"identities":[human,machine]});put(root/"fixture-input.private.json",{"sourceTokens":{"success":token+"success","failure":token+"failure"},"mihomoToken":mihomo,"bearerTokens":{"viewer":"viewer-token-0123456789"},"contentSecrets":["fixture-a","fixture-b"]})
    data=root/"data/subscription-refresh-v3/state";put(data,b"private-state\n");manifest={"state":S.hashlib.sha256(data.read_bytes()).hexdigest()};put(root/"sidecar-before.private.json",manifest);put(root/"sidecar-after.private.json",manifest);put(stage/"safe.json",{"status":"safe"})
def publication_tree(root):
    inp=root/"in";inp.mkdir();put(inp/"safe",b"safe\n");put(inp/"source-before.json",b"[]\n");put(inp/"source-after.json",b"[]\n")
    names=("safe","source-before.json");rows=[{"path":name,"bytes":len((inp/name).read_bytes()),"sha256":S.hashlib.sha256((inp/name).read_bytes()).hexdigest()} for name in names]
    put(inp/"private-checks.json",{"publicationScan":{"result":"PASS","filesScanned":2,"bytesScanned":sum(x["bytes"] for x in rows),"publicFiles":rows,"sourceAfterBinding":"byte_equal_to_source-before.json"}})
    report=root/"report";put(report,{"schema":"chengwang.joint-control-plane-verification/v2","sourceCommit":"a"*40,"fixtureId":"joint-"+"b"*32,"status":"PASS","production":False,"actualSKU":"UNKNOWN","authorization":"BLOCKED","runtimeAcceptanceProven":True,"refreshRestartPersistenceProven":False})
    return inp,report
class SanitizerContracts(unittest.TestCase):
    def test_private_projection_checks_policy_sidecar_and_secret_scan(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)/"private";stage=pathlib.Path(d)/"stage";root.mkdir();stage.mkdir();private_tree(root,stage);out=stage/"private-checks.json";old=S.PUBLIC
            try:S.PUBLIC={"safe.json","private-checks.json","source-after.json"};S.private_check(root,stage,out)
            finally:S.PUBLIC=old
            value=S.decode(out)
            self.assertTrue(value["policyTransition"]["baseEqualAfterRemovingRefresh"]);self.assertTrue(value["sidecar"]["unchanged"]);self.assertFalse(value["privateMaterialPublished"])
    def test_private_projection_rejects_material_change_and_secret_publication(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)/"private";stage=pathlib.Path(d)/"stage";root.mkdir();stage.mkdir();private_tree(root,stage);p1=S.decode(root/"policy1.json");p1["sources"][0]["secretVersion"]="v2";(root/"policy1.json").write_bytes(S.canonical(p1))
            old=S.PUBLIC
            try:
                S.PUBLIC={"safe.json","private-checks.json","source-after.json"}
                with self.assertRaises(ValueError):S.private_check(root,stage,stage/"private-checks.json")
            finally:S.PUBLIC=old
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)/"private";stage=pathlib.Path(d)/"stage";root.mkdir();stage.mkdir();private_tree(root,stage);put(stage/"safe.json",b"Bearer private\n");old=S.PUBLIC
            try:
                S.PUBLIC={"safe.json","private-checks.json","source-after.json"}
                with self.assertRaises(ValueError):S.private_check(root,stage,stage/"private-checks.json")
            finally:S.PUBLIC=old
    def test_publish_copies_only_allowlist_after_independent_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);inp,report=publication_tree(root);out=root/"out";old=S.PUBLIC
            try:S.PUBLIC={"safe","source-before.json","source-after.json","private-checks.json"};S.publish(inp,out,report)
            finally:S.PUBLIC=old
            self.assertEqual((out/"lab/safe").read_bytes(),b"safe\n");self.assertTrue((out/"verification.json").is_file())
    def test_publish_preflight_and_mid_copy_fault_leave_no_partial_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);inp,report=publication_tree(root);out=root/"out";put(inp/"safe",b"Bearer changed-after-scan\n");old=S.PUBLIC
            try:
                S.PUBLIC={"safe","source-before.json","source-after.json","private-checks.json"}
                with self.assertRaises(ValueError):S.publish(inp,out,report)
            finally:S.PUBLIC=old
            self.assertFalse(out.exists());self.assertEqual(list(root.glob(".out.pending-*")),[])
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);inp,report=publication_tree(root);out=root/"out";old=S.PUBLIC;real=S.write;calls=[]
            def fail_late(path,data):
                calls.append(path)
                if len(calls)==3:raise OSError("injected-copy-failure")
                return real(path,data)
            try:
                S.PUBLIC={"safe","source-before.json","source-after.json","private-checks.json"}
                with mock.patch.object(S,"write",side_effect=fail_late):
                    with self.assertRaises(OSError):S.publish(inp,out,report)
            finally:S.PUBLIC=old
            self.assertFalse(out.exists());self.assertEqual(list(root.glob(".out.pending-*")),[])
    def test_failure_projection_never_copies_private_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);inp=root/"in";inp.mkdir();put(inp/"raw",b"PRIVATE SECRET MATERIAL");out=root/"public/failure.json";S.failure(inp,out,"SCENE_FAILED");value=S.decode(out)
            self.assertEqual(value["retainedPrivateFileCount"],1);self.assertNotIn("SECRET",out.read_text())
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";staging=root/"staging";private.mkdir();staging.mkdir();put(private/"server.stderr",b"PRIVATE SERVER DIAGNOSTIC")
            S.failure(private,staging/"private-failure-identity.json","PRIVATE_SCENE_FAILED");S.failure(staging,root/"public/failure.json","SCENE_FAILED");value=S.decode(root/"public/failure.json")
            self.assertEqual(value["privateDiagnostics"]["retainedPrivateFileCount"],1);self.assertNotIn("DIAGNOSTIC",(root/"public/failure.json").read_text())
if __name__=="__main__":unittest.main()
