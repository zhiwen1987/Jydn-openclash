from __future__ import annotations
import ast, copy, importlib.util, pathlib, tempfile, unittest
HERE=pathlib.Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
C=load("joint_runner_test_contract","contract.py");R=load("joint_runner_test_target","run_joint_control_plane.py")

def base_policy():
    return {"version":1,"scope":dict(C.SCOPE),"resolver":{"upstream":"127.0.0.1:1853","serverName":C.DOT_NAME,"caPEM":"CA"},"sources":[{"referenceId":case,"revision":1,"secretVersion":"v1","url":"https://"+host+"/subscription?token=PRIVATE","allowedCnames":[],"caPEM":"CA"} for case,host in C.SOURCE_HOSTS.items()]}

class RunnerContracts(unittest.TestCase):
    def test_policy_transition_changes_only_refresh(self):
        p0=base_policy();ids={k:"src_"+("1" if k=="success" else "2")*32 for k in C.SOURCE_HOSTS};approvals={k:"cmd_"+("3" if k=="success" else "4")*32 for k in C.SOURCE_HOSTS}
        p1=C.append_refresh(p0,ids,approvals);self.assertEqual(p0,base_policy());self.assertNotIn("refresh",p0["sources"][0]);self.assertEqual(p1["sources"][0]["refresh"]["intervalSeconds"],60)
        broken=copy.deepcopy(p1);broken["sources"][0]["secretVersion"]="v2"
        with self.assertRaises(ValueError):C.validate_policy_transition(p0,broken)
    def test_human_grants_are_tenant_site_environment_wildcards_only(self):
        grant=C.human_grant(C.SCOPE["tenantId"]);self.assertEqual(set(grant),{"tenantId","siteId","environment"});self.assertNotIn("objectType",grant);self.assertNotIn("objectId",grant)
    def test_machine_grants_are_exact_source_objects(self):
        ids={"success":"src_"+"1"*32,"failure":"src_"+"2"*32};grants=C.machine_grants(ids);self.assertEqual({g["objectId"] for g in grants},set(ids.values()));self.assertTrue(all(g["objectType"]=="subscription-source" for g in grants))
    def test_bootstrap_omits_machine_and_joint_adds_it(self):
        tokens={r:"x"*43 for r in (*C.ROLES,C.MACHINE_ID)};b=R.identity(tokens);self.assertNotIn(C.MACHINE_ID,{i["tokenId"] for i in b["identities"]})
        j=R.identity(tokens,{"success":"src_"+"1"*32,"failure":"src_"+"2"*32});machine=next(i for i in j["identities"] if i["tokenId"]==C.MACHINE_ID);self.assertEqual(machine["principal"]["roles"],[C.MACHINE_ROLE]);self.assertEqual(len(machine["principal"]["allowedScopes"]),2)
    def test_idempotency_map_is_unique_and_retry_stable(self):
        values=[v for row in C.IDEMPOTENCY.values() for v in row.values()];self.assertEqual(len(values),len(set(values)));self.assertEqual(C.idempotency("success","fetch_r1"),C.idempotency("success","fetch_r1"))
    def test_healthy_deadline_is_experiment_slo_not_timeout_recovery(self):
        self.assertEqual((C.EXPERIMENT_DEADLINE,C.POLL_SECONDS,C.REFRESH_INTERVAL),(50,5,60));text=pathlib.Path(R.__file__).read_text();self.assertIn('raise Failure("SLO")',text);self.assertNotIn("runtimeAcceptanceProven=True",text)
    def test_r2_explicitly_disables_refresh_identity(self):
        lab=R.Lab.__new__(R.Lab);lab.root=pathlib.Path("/private");lab.mihomo_token="secret"
        env=lab.environment(pathlib.Path("/policy0.json"),pathlib.Path("/identities0.json"),False,True)
        self.assertEqual(env["CHENGWANG_SUBSCRIPTION_REFRESH_ENABLED"],"false");self.assertEqual(env["CHENGWANG_SUBSCRIPTION_REFRESH_IDENTITY_ID"],"")
        source=ast.unparse(ast.parse(pathlib.Path(R.__file__).read_text()));self.assertIn("'refreshRestartPersistenceProven': False",source)

if __name__=="__main__":unittest.main()
