from __future__ import annotations
import ast, copy, importlib.util, json, os, pathlib, ssl, subprocess, tempfile, types, unittest
from unittest import mock
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
    def test_failure_codes_and_capture_names_have_one_static_source_of_truth(self):
        tree=ast.parse(pathlib.Path(R.__file__).read_text());labels=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                if node.func.id=="need" and len(node.args)>=2 and isinstance(node.args[1],ast.Constant):labels.append(node.args[1].value)
                if node.func.id=="Failure" and node.args and isinstance(node.args[0],ast.Constant):labels.append(node.args[0].value)
        self.assertEqual(set(labels),C.FAILURE_REASON_CODES-{"UNKNOWN"});self.assertEqual(len(C.CAPTURE_NAMES),40)
        checker=(HERE/"check_joint_control_plane.py").read_text();self.assertIn("set(named)==C.CAPTURE_NAMES",checker);self.assertNotIn("expected_names=",checker)
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in ("need","Failure"):
                args=node.args[1:2] if node.func.id=="need" else node.args[:1]
                if node.func.id=="Failure" and args and isinstance(args[0],ast.Name) and args[0].id=="label":continue
                self.assertTrue(args and isinstance(args[0],ast.Constant) and args[0].value in C.FAILURE_REASON_CODES)
    def test_ordered_exception_categories_never_copy_messages(self):
        cases=[
            (R.Failure("HTTP"),"HARNESS_FAILURE"),
            (subprocess.CalledProcessError(7,["private-command"]),"COMMAND_NONZERO"),
            (subprocess.TimeoutExpired(["private-command"],1),"TIMEOUT"),
            (subprocess.SubprocessError("private-command"),"SUBPROCESS_ERROR"),
            (PermissionError("Bearer TOKEN /private/path"),"PERMISSION_ERROR"),
            (FileNotFoundError("https://private.invalid"),"FILE_NOT_FOUND"),
            (FileExistsError("request-body-private"),"FILE_EXISTS"),
            (json.JSONDecodeError("response-body-private","x",0),"JSON_ERROR"),
            (ssl.SSLError("TLS private"),"TLS_ERROR"),
            (OSError("Authorization: secret"),"OS_ERROR"),
            (ValueError("token-private"),"VALUE_ERROR"),
            (TypeError("path-private"),"TYPE_ERROR"),
            (KeyError("url-private"),"KEY_ERROR"),
            (RuntimeError("unknown-private"),"UNKNOWN"),
        ]
        for error,expected in cases:
            with self.subTest(expected=expected):self.assertEqual(C.exception_type(error),expected)
        self.assertEqual(str(R.Failure("SLO")),"")
    def test_progress_chain_localizes_phase_and_static_capture_without_raw_data(self):
        commit="a"*40
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            C.record_progress(root,commit,"NAMESPACE_SETUP","ENTERED");C.record_progress(root,commit,"NAMESPACE_SETUP","COMPLETED");C.record_progress(root,commit,"ISOLATION_CHECK","ENTERED")
            C.record_failure_detail(root,commit,R.Failure("HTTP"),"success-create",None)
            value=C.failure_classification(root,commit)
            self.assertEqual(value,{"failurePhase":"ISOLATION_CHECK","lastCompletedPhase":"NAMESPACE_SETUP","exceptionType":"HARNESS_FAILURE","failureReasonCode":"HTTP","failedCaptureName":"success-create","lastCompletedCaptureName":"NONE"})
            joined=b"".join(p.read_bytes() for p in root.iterdir());self.assertNotIn(b"Bearer TOKEN",joined);self.assertNotIn(b"/private/path",joined);self.assertNotIn(b"https://",joined)
            with self.assertRaises(ValueError):C.record_progress(root,commit,"ISOLATION_CHECK","ENTERED")
    def test_every_operational_phase_has_exact_last_completed_pair(self):
        commit="d"*40
        for index,target in enumerate(C.FAILURE_PHASES):
            with self.subTest(phase=target),tempfile.TemporaryDirectory() as d:
                root=pathlib.Path(d)
                for phase in C.FAILURE_PHASES[:index]:
                    C.record_progress(root,commit,phase,"ENTERED");C.record_progress(root,commit,phase,"COMPLETED")
                C.record_progress(root,commit,target,"ENTERED")
                try:raise R.Failure("ROOT")
                except R.Failure as error:C.record_failure_detail(root,commit,error);exit_code=1
                value=C.failure_classification(root,commit)
                self.assertEqual(value["failurePhase"],target);self.assertEqual(value["lastCompletedPhase"],"NONE" if index==0 else C.FAILURE_PHASES[index-1])
                self.assertEqual((exit_code,value["exceptionType"],value["failureReasonCode"],value["failedCaptureName"]),(1,"HARNESS_FAILURE","ROOT","NONE"))
    def test_progress_chain_tampering_maps_to_bounded_unknown(self):
        commit="b"*40;default=C.unknown_failure_classification()
        def record(phase="NAMESPACE_SETUP",source=commit,extra=None,raw=None,name=None):
            temp=tempfile.TemporaryDirectory();root=pathlib.Path(temp.name);filename=name or C.progress_name(0,"NAMESPACE_SETUP","ENTERED")
            value={"schema":C.PROGRESS_SCHEMA,"sourceCommit":source,"ordinal":1,"phase":phase,"state":"ENTERED"}
            if extra:value.update(extra)
            (root/filename).write_bytes(raw if raw is not None else C.canonical(value));return temp,root
        cases=[]
        cases.append(record(phase="DYNAMIC_PRIVATE_PHASE"));cases.append(record(source="c"*40));cases.append(record(extra={"raw":"Bearer secret"}));cases.append(record(raw=b"\xff\xfe"));cases.append(record(raw=b"X"*4097));cases.append(record(name=C.progress_name(1,"NAMESPACE_SETUP","COMPLETED")))
        for temp,root in cases:
            try:self.assertEqual(C.failure_classification(root,commit),default)
            finally:temp.cleanup()
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);C.record_progress(root,commit,"NAMESPACE_SETUP","ENTERED");source=next(root.iterdir());os.link(source,root.parent/(root.name+"-hardlink"))
            try:self.assertEqual(C.failure_classification(root,commit),default)
            finally:(root.parent/(root.name+"-hardlink")).unlink()
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);C.record_progress(root,commit,"NAMESPACE_SETUP","ENTERED")
            with mock.patch.object(pathlib.Path,"is_symlink",return_value=True):self.assertEqual(C.failure_classification(root,commit),default)
    def test_private_read_accepts_short_reads_and_rejects_named_replacement(self):
        commit="e"*40
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);C.record_progress(root,commit,"NAMESPACE_SETUP","ENTERED");path=next(root.iterdir());expected=path.read_bytes();real_read=C.os.read
            with mock.patch.object(C.os,"read",side_effect=lambda fd,size:real_read(fd,min(size,1))):self.assertEqual(C._private_read(path),expected)
            before=path.lstat();named_after=types.SimpleNamespace(**{key:getattr(before,key) for key in ("st_dev","st_ino","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns")});named_after.st_ino+=1
            with mock.patch.object(pathlib.Path,"is_symlink",return_value=False),mock.patch.object(pathlib.Path,"lstat",side_effect=(before,named_after)):
                with self.assertRaises(ValueError):C._private_read(path)
    def test_call_failure_keeps_only_allowlisted_active_capture(self):
        with tempfile.TemporaryDirectory() as d:
            lab=R.Lab.__new__(R.Lab);lab.root=pathlib.Path(d);lab.active_capture=None;lab.last_completed_capture=None
            with mock.patch.object(R,"wire_fence",side_effect=R.Failure("WIRE")):
                with self.assertRaises(R.Failure):lab.call("success-create","B0")
            self.assertEqual(lab.active_capture,"success-create");self.assertIsNone(lab.last_completed_capture)
            with self.assertRaises(ValueError):lab.call("dynamic-private-capture","B0")
    def test_workflow_and_namespace_cover_every_phase_without_logs(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text();namespace=(HERE/"ci_namespace.sh").read_text();runner=pathlib.Path(R.__file__).read_text()
        self.assertLess(workflow.index("--phase NAMESPACE_SETUP --state ENTERED"),workflow.index(" unshare "))
        self.assertIn('--progress-root "$root/evidence/staging/failure-localization.private"',workflow)
        for phase in C.FAILURE_PHASES:
            self.assertIn(phase,workflow+namespace+runner)
        self.assertNotIn("runner.stderr",workflow);self.assertNotIn("runner.stdout",workflow)

if __name__=="__main__":unittest.main()
