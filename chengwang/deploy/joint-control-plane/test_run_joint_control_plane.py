from __future__ import annotations
import ast, contextlib, copy, importlib.util, io, json, os, pathlib, shutil, ssl, subprocess, sys, tempfile, types, unittest
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
C=load("joint_runner_test_contract","contract.py");R=load("joint_runner_test_target","run_joint_control_plane.py");CI=load("joint_runner_test_ci","ci_joint_control_plane.py")

def base_policy():
    return {"version":1,"scope":dict(C.SCOPE),"resolver":{"upstream":"127.0.0.1:1853","serverName":C.DOT_NAME,"caPEM":"CA"},"sources":[{"referenceId":case,"revision":1,"secretVersion":"v1","url":"https://"+host+"/subscription?token=PRIVATE","allowedCnames":[],"caPEM":"CA"} for case,host in C.SOURCE_HOSTS.items()]}

def _probe_fixture_owner_view(probe):
    probe=pathlib.Path(probe);real_lstat=pathlib.Path.lstat
    class OwnerView:
        def __init__(self,base,uid,gid):self._base=base;self.st_uid=uid;self.st_gid=gid
        def __getattr__(self,name):return getattr(self._base,name)
    def lstat(path):
        meta=real_lstat(path);candidate=pathlib.Path(path)
        try:relative=candidate.relative_to(probe)
        except ValueError:return meta
        parts=relative.parts
        uid,gid=(0,0)
        if parts and parts[0]=="staging" and (len(parts)==1 or parts[1]=="untrusted-replacement"):
            uid,gid=C.UID,C.GID
        return OwnerView(meta,uid,gid)
    return mock.patch.object(pathlib.Path,"lstat",autospec=True,side_effect=lstat)

def _probe_fixture_cleanup_calls(probe):
    probe=pathlib.Path(probe);real_chmod=CI.os.chmod;real_unlink=CI.os.unlink;real_rmdir=CI.os.rmdir
    def inside(path):
        candidate=pathlib.Path(path);return candidate==probe or probe in candidate.parents
    def unlink(path):
        candidate=pathlib.Path(path)
        if not inside(candidate) or not inside(candidate.parent):raise AssertionError("fixture cleanup escaped probe")
        real_chmod(candidate.parent,0o700);real_chmod(candidate,0o600);return real_unlink(candidate)
    def rmdir(path):
        candidate=pathlib.Path(path)
        if not inside(candidate):raise AssertionError("fixture cleanup escaped probe")
        real_chmod(candidate,0o700)
        if inside(candidate.parent):real_chmod(candidate.parent,0o700)
        return real_rmdir(candidate)
    return unlink,rmdir

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
    def test_model_outcome_callbacks_expose_only_allowlisted_parent_ids_and_fixed_outcomes(self):
        class Cases(unittest.TestCase):
            def test_pass(self):pass
            def test_failure(self):self.fail("Bearer SECRET /private/path")
            def test_error(self):raise RuntimeError("https://private.invalid?token=SECRET")
            @unittest.skip("Authorization: SECRET")
            def test_skip(self):pass
            def test_subtest(self):
                with self.subTest(private="token=SECRET"):self.fail("response body SECRET")
        tests=[Cases(name) for name in ("test_pass","test_failure","test_error","test_skip","test_subtest")]
        expected=tuple(sorted(test.id() for test in tests));holder=[]
        def result_class(*args,**kwargs):
            result=CI.ModelOutcomeResult(*args,expected=expected,**kwargs);holder.append(result);return result
        unittest.TextTestRunner(stream=io.StringIO(),verbosity=2,resultclass=result_class).run(unittest.TestSuite(tests));result=holder[0]
        value=CI._model_value("a"*40,expected,CI.hashlib.sha256("\n".join(expected).encode()).hexdigest(),"b"*64,result)
        raw=CI._bounded_model_bytes(value);decoded=json.loads(raw)
        self.assertEqual(set(row["outcome"] for row in decoded["outcomes"]),{"PASS","FAIL","ERROR","SKIP"})
        self.assertEqual(decoded["counts"],{"PASS":1,"FAIL":2,"ERROR":1,"SKIP":1,"UNKNOWN":0})
        self.assertEqual(decoded["unknownEventCount"],0)
        for secret in (b"SECRET",b"/private/path",b"https://",b"Authorization",b"response body",b"private"):
            self.assertNotIn(secret,raw)
    def test_model_outcome_inventory_is_exact_four_source_top_level_ast(self):
        names,names_sha,source_sha=CI._model_inventory();independent=[]
        self.assertEqual(CI.MODEL_TEST_SOURCES,("test_joint_fixture.py","test_run_joint_control_plane.py","test_check_joint_control_plane.py","test_sanitize_publication.py","test_uid_probe_diagnostic.py","test_check_uid_probe_diagnostic.py"))
        for filename in CI.MODEL_TEST_SOURCES:
            tree=ast.parse((HERE/filename).read_bytes());module=filename[:-3]
            independent.extend(module+"."+cls.name+"."+method.name for cls in tree.body if isinstance(cls,ast.ClassDef)
                for method in cls.body if isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)) and method.name.startswith("test_"))
        independent=tuple(sorted(independent));self.assertEqual(names,independent);self.assertGreaterEqual(len(names),83)
        self.assertEqual(names_sha,CI.hashlib.sha256("\n".join(names).encode()).hexdigest());self.assertRegex(source_sha,r"^[0-9a-f]{64}$")
    def test_model_outcome_validator_rejects_noncanonical_extra_cross_source_and_row_mutants(self):
        expected,names_sha,source_sha=CI._model_inventory();result=types.SimpleNamespace(outcomes={name:"PASS" for name in expected},started=set(expected),unknownEvents=0)
        raw=CI._bounded_model_bytes(CI._model_value("c"*40,expected,names_sha,source_sha,result));self.assertEqual(CI.validate_model_diagnostic(raw,"c"*40)["counts"]["PASS"],len(expected))
        values=[];extra=json.loads(raw);extra["traceback"]="SECRET";values.append(C.canonical(extra))
        row=json.loads(raw);row["outcomes"][0]["id"]="dynamic.private.test";values.append(C.canonical(row))
        count=json.loads(raw);count["counts"]["PASS"]-=1;count["counts"]["UNKNOWN"]+=1;values.append(C.canonical(count))
        values.extend((raw.replace(b'"accepted":false',b'"accepted":true'),b" "+raw,
                       raw.replace(b'{"accepted":false',b'{"accepted":false,"accepted":false',1),b"{"+b" "*CI.MODEL_DIAGNOSTIC_MAXIMUM+b"}"))
        for mutant in values:
            with self.subTest(mutant=CI.hashlib.sha256(mutant).hexdigest()),self.assertRaises(ValueError):CI.validate_model_diagnostic(mutant,"c"*40)
        with self.assertRaises(ValueError):CI.validate_model_diagnostic(raw,"d"*40)
    def test_model_outcome_failure_still_writes_valid_source_bound_diagnostic_and_keeps_unit_failure(self):
        expected=CI._model_inventory()[0]
        def fail_run(runner,suite):
            class Fake(unittest.TestCase):
                def runTest(self):pass
                def id(self):return expected[0]
            result=runner._makeResult();test=Fake()
            result.startTest(test);result.addFailure(test,(AssertionError,AssertionError("SECRET /private"),None));result.stopTest(test);return result
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/"model.json"
            with mock.patch.object(CI.unittest.TextTestRunner,"run",fail_run),self.assertRaises(ValueError):CI.units(path,"e"*40)
            raw=path.read_bytes();value=CI.validate_model_diagnostic(raw,"e"*40)
            self.assertEqual((value["accepted"],value["syntheticOnly"],value["counts"]["FAIL"]),(False,True,1));self.assertNotIn(b"SECRET",raw);self.assertLessEqual(len(raw),CI.MODEL_DIAGNOSTIC_MAXIMUM)
            with self.assertRaises(FileExistsError):CI._emit_raw(path,b"{}\n",CI.MODEL_DIAGNOSTIC_MAXIMUM)
        with self.assertRaises(ValueError):CI.units(None,"e"*40)
    def test_units_strict_gate_rejects_expected_failure_unknown_no_callback_and_incomplete_inventory(self):
        expected=CI._model_inventory()[0]
        class Fake(unittest.TestCase):
            def runTest(self):pass
            def __init__(self,identity):super().__init__();self.identity=identity
            def id(self):return self.identity
        def result_for(runner,kind):
            result=runner._makeResult();test=Fake(expected[0] if kind!="unknown-identity" else "dynamic.private.test")
            result.startTest(test)
            if kind=="expected-failure":result.addExpectedFailure(test,(AssertionError,AssertionError("SECRET /private"),None))
            elif kind in ("unknown-identity","incomplete-inventory"):result.addSuccess(test)
            elif kind!="no-callback":raise AssertionError(kind)
            result.stopTest(test);return result
        for kind in ("expected-failure","unknown-identity","no-callback","incomplete-inventory"):
            with self.subTest(kind=kind):
                def controlled_run(runner,suite,kind=kind):return result_for(runner,kind)
                with mock.patch.object(CI.unittest.TextTestRunner,"run",controlled_run),self.assertRaises(ValueError):CI.units()
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/"model.json";captured=[]
            def expected_failure_run(runner,suite):
                result=result_for(runner,"expected-failure");captured.append(result);return result
            with mock.patch.object(CI.unittest.TextTestRunner,"run",expected_failure_run),self.assertRaises(ValueError):CI.units(path,"b"*40)
            raw=path.read_bytes();value=CI.validate_model_diagnostic(raw,"b"*40)
            self.assertTrue(captured[0].wasSuccessful());self.assertEqual(len(captured[0].expectedFailures),1);self.assertFalse(CI._model_all_pass(captured[0],expected))
            self.assertEqual(value["counts"]["UNKNOWN"],len(expected));self.assertNotIn(b"SECRET",raw);self.assertNotIn(b"/private",raw)
    def test_model_outcome_fixed_fallback_is_bounded_counts_only(self):
        expected,names_sha,source_sha=CI._model_inventory();result=types.SimpleNamespace(outcomes={name:"PASS" for name in expected},started=set(expected),unknownEvents=0)
        full=CI._model_value("f"*40,expected,names_sha,source_sha,result);raw=CI._bounded_model_bytes(full,1024);value=json.loads(raw)
        self.assertEqual((value["projection"],value["outcomes"]),("FALLBACK",[]));self.assertEqual(value["counts"]["PASS"],len(expected));self.assertLessEqual(len(raw),1024)
        self.assertEqual(CI.validate_model_diagnostic(raw,"f"*40),value)
    def test_model_outcome_workflow_is_independent_single_file_and_does_not_change_go_budget(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text();self.assertTrue(CI.workflow_contract(workflow.encode()))
        self.assertEqual(workflow.count("go test -count=1 -timeout=300s ./..."),1)
        self.assertIn("joint-control-plane-cpu-public/",workflow);self.assertNotIn("model-outcome",workflow.split("path: ${{ runner.temp }}/joint-control-plane-cpu-public/",1)[1].split("retention-days: 14",1)[0])
        self.assertIn("path: ${{ runner.temp }}/joint-control-plane-model-outcome-public/model-outcome.json",workflow)
        self.assertIn("always() && steps.cpu.outputs.model_diagnostic_ready == 'true'",workflow)
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
    def test_empty_progress_valid_detail_preserves_legacy_fields_and_adds_independent_state(self):
        commit="9"*40
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);C.record_failure_detail(root,commit,PermissionError("PRIVATE"),"success-fetch-r1","success-approve-r1")
            baseline=C.failure_classification(root,commit)
            self.assertEqual(baseline,{"failurePhase":"UNKNOWN","lastCompletedPhase":"NONE","exceptionType":"PERMISSION_ERROR","failureReasonCode":"UNKNOWN","failedCaptureName":"success-fetch-r1","lastCompletedCaptureName":"success-approve-r1"})
            with mock.patch.object(C,"_owned_mode",return_value=True):evidence=C.localization_evidence(root,None,commit)
            self.assertEqual(evidence,{"progressRootState":"EMPTY","failureDetailState":"ACCEPTED","bootstrapStepOutcome":"MISSING","bootstrapRecordState":"ABSENT","bootstrapChildState":"UNKNOWN"})
            (root/C.FAILURE_DETAIL_NAME).write_bytes(b"{}\n")
            rejected=C.failure_classification(root,commit)
            with mock.patch.object(C,"_owned_mode",return_value=True):rejected_evidence=C.localization_evidence(root,None,commit)
            self.assertEqual(rejected,C.unknown_failure_classification());self.assertEqual(rejected_evidence["progressRootState"],"EMPTY");self.assertEqual(rejected_evidence["failureDetailState"],"INVALID")
    def test_bootstrap_record_current_read_rejects_absence_mismatch_and_replacement(self):
        commit="8"*40
        with tempfile.TemporaryDirectory() as d:
            staging=pathlib.Path(d)/"staging";staging.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE
            self.assertEqual(C.bootstrap_record_state(record,commit),("ABSENT","UNKNOWN"))
            record.parent.mkdir();record.write_bytes(C.canonical({"schema":C.BOOTSTRAP_SCHEMA,"sourceCommit":commit,"bootstrapChildState":"PASS"}))
            directory_identity=C._identity(record.parent.lstat());file_identity=C._identity(record.lstat());parent_identity=C._identity(staging.lstat())
            with mock.patch.object(C,"_owned_mode",return_value=True):
                self.assertEqual(C.bootstrap_record_state(record,commit),("ACCEPTED","PASS"))
                self.assertEqual(C.bootstrap_record_state(record,"7"*40),("SOURCE_MISMATCH","UNKNOWN"))
            moved=staging/(C.BOOTSTRAP_DIRECTORY+".moved");record.parent.rename(moved);record.parent.mkdir();record.write_bytes(C.canonical({"schema":C.BOOTSTRAP_SCHEMA,"sourceCommit":commit,"bootstrapChildState":"PASS"}))
            with mock.patch.object(C,"_owned_mode",return_value=True):
                state=C.bootstrap_record_state(record,commit,parent_identity,directory_identity,file_identity)
            self.assertEqual(state,("INVALID","UNKNOWN"))
            with mock.patch.object(C,"_localized_read",return_value=("READ_FAILED",None,None)),mock.patch.object(C,"_owned_mode",return_value=True):
                self.assertEqual(C.bootstrap_record_state(record,commit),("READ_FAILED","UNKNOWN"))
    def test_bootstrap_step_projection_is_closed_and_never_claims_local_authority(self):
        commit="8"*40
        self.assertEqual(C.bootstrap_step_outcome("bootstrap_progress","success",commit,commit),"SUCCESS")
        self.assertEqual(C.bootstrap_step_outcome("bootstrap_progress","failure",commit,commit),"FAILURE")
        self.assertEqual(C.bootstrap_step_outcome("bootstrap_progress","cancelled",commit,commit),"CANCELLED")
        self.assertEqual(C.bootstrap_step_outcome("bootstrap_progress","skipped",commit,commit),"SKIPPED")
        for values in ((None,None,None),("", "success",commit),("bootstrap_progress","",commit)):
            self.assertEqual(C.bootstrap_step_outcome(*values,commit),"MISSING")
        for values in (("other","success",commit),("bootstrap_progress","other",commit),("bootstrap_progress","success","7"*40),("bootstrap_progress","success","private")):
            self.assertEqual(C.bootstrap_step_outcome(*values,commit),"UNKNOWN")
        function=next(node for node in ast.parse(pathlib.Path(C.__file__).read_text()).body if isinstance(node,ast.FunctionDef) and node.name=="bootstrap_step_outcome")
        self.assertNotIn("AUTHORITATIVE",ast.unparse(function))
    def test_every_non_success_projection_suppresses_later_residual_pass(self):
        commit="4"*40
        with tempfile.TemporaryDirectory() as d:
            staging=pathlib.Path(d)/"staging";staging.mkdir();progress=staging/"progress";progress.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE;record.parent.mkdir();record.write_bytes(C.canonical({"schema":C.BOOTSTRAP_SCHEMA,"sourceCommit":commit,"bootstrapChildState":"PASS"}))
            with mock.patch.object(C,"_owned_mode",return_value=True):
                for raw,expected in (("failure","FAILURE"),("cancelled","CANCELLED"),("skipped","SKIPPED"),(None,"MISSING"),("other","UNKNOWN")):
                    value=C.localization_evidence(progress,record,commit,"bootstrap_progress",raw,commit)
                    self.assertEqual((value["bootstrapStepOutcome"],value["bootstrapRecordState"],value["bootstrapChildState"]),(expected,"INVALID","UNKNOWN"))
                accepted=C.localization_evidence(progress,record,commit,"bootstrap_progress","success",commit)
            self.assertEqual((accepted["bootstrapStepOutcome"],accepted["bootstrapRecordState"],accepted["bootstrapChildState"]),("SUCCESS","ACCEPTED","PASS"))
    def test_bootstrap_writer_second_fsync_and_final_named_validation_fail_closed(self):
        commit="5"*40
        def exercise(root,fail_second=False,final=("ACCEPTED","PASS")):
            staging=root/"staging";staging.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE;events=[];fsync_count=0
            def fsync(fd):
                nonlocal fsync_count
                fsync_count+=1;events.append("file-fsync-"+str(fsync_count))
                if fail_second and fsync_count==2:raise OSError("PRIVATE SECOND FSYNC")
            def fchmod(fd,mode):events.append("fchmod-"+oct(mode))
            def fsync_dir(path):events.append("dir-fsync-"+pathlib.Path(path).name)
            def validate(*args,**kwargs):events.append("final-named-validation");return final
            patches=(mock.patch.object(C,"_root_writer",return_value=True),mock.patch.object(C,"_owned_mode",return_value=True),mock.patch.object(C.os,"fsync",side_effect=fsync),mock.patch.object(C.os,"fchmod",side_effect=fchmod,create=True),mock.patch.object(C,"_fsync_dir",side_effect=fsync_dir),mock.patch.object(C,"bootstrap_record_state",side_effect=validate))
            with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5]:
                C.record_bootstrap_status(record,commit,"PASS")
            return events
        with tempfile.TemporaryDirectory() as d:
            events=exercise(pathlib.Path(d));self.assertLess(events.index("file-fsync-1"),events.index("fchmod-0o444"));self.assertLess(events.index("fchmod-0o444"),events.index("file-fsync-2"));self.assertLess(events.index("dir-fsync-staging"),events.index("final-named-validation"))
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OSError):exercise(pathlib.Path(d),fail_second=True)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):exercise(pathlib.Path(d),final=("INVALID","UNKNOWN"))
    def test_record_publication_fault_matrix_never_survives_failure_projection(self):
        commit="3"*40
        real={name:getattr(C.os,name) for name in ("mkdir","chmod","open","write","fsync","lseek","read","fstat","close")}
        cases=[]
        def fail(name,nth=1,after=False):
            count=0
            def wrapped(*args,**kwargs):
                nonlocal count
                count+=1
                if count==nth:
                    if after:real[name](*args,**kwargs)
                    raise OSError("PRIVATE "+name)
                return real[name](*args,**kwargs)
            return mock.patch.object(C.os,name,side_effect=wrapped)
        cases.extend((label,patcher) for label,patcher in (
            ("mkdir",fail("mkdir")),("initial-directory-chmod",fail("chmod",1)),
            ("exclusive-open",fail("open")),("write",fail("write")),
            ("first-file-fsync",fail("fsync",1)),("seek",fail("lseek")),
            ("readback",fail("read")),("fstat",fail("fstat")),
            ("fchmod",mock.patch.object(C.os,"fchmod",side_effect=OSError("PRIVATE fchmod"),create=True)),("second-file-fsync",fail("fsync",2)),
            ("descriptor-close",fail("close",1,after=True)),("final-directory-chmod",fail("chmod",2)),
        ))
        for label,patcher in cases:
            with self.subTest(operation=label),tempfile.TemporaryDirectory() as d:
                staging=pathlib.Path(d)/"staging";staging.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE
                fchmod=(mock.patch.object(C.os,"fchmod",side_effect=lambda fd,mode:None,create=True) if label!="fchmod" else mock.patch.object(C.os,"fchmod",create=True))
                with mock.patch.object(C,"_root_writer",return_value=True),mock.patch.object(C,"_owned_mode",return_value=True),fchmod,patcher:
                    with self.assertRaises(OSError):C.record_bootstrap_status(record,commit,"PASS")
                with mock.patch.object(C,"_owned_mode",return_value=True):value=C.localization_evidence(None,record,commit,"bootstrap_progress","failure",commit)
                self.assertNotEqual(value["bootstrapRecordState"],"ACCEPTED");self.assertEqual(value["bootstrapChildState"],"UNKNOWN")
        for label,which in (("directory-fsync",1),("parent-fsync",2)):
            with self.subTest(operation=label),tempfile.TemporaryDirectory() as d:
                staging=pathlib.Path(d)/"staging";staging.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE;count=0;real_sync=C._fsync_dir
                def sync(path):
                    nonlocal count
                    count+=1
                    if count==which:raise OSError("PRIVATE DIR FSYNC")
                    return real_sync(path)
                with mock.patch.object(C,"_root_writer",return_value=True),mock.patch.object(C,"_owned_mode",return_value=True),mock.patch.object(C.os,"fchmod",side_effect=lambda fd,mode:None,create=True),mock.patch.object(C,"_fsync_dir",side_effect=sync):
                    with self.assertRaises(OSError):C.record_bootstrap_status(record,commit,"PASS")
                with mock.patch.object(C,"_owned_mode",return_value=True):value=C.localization_evidence(None,record,commit,"bootstrap_progress","failure",commit)
                self.assertNotEqual(value["bootstrapRecordState"],"ACCEPTED");self.assertEqual(value["bootstrapChildState"],"UNKNOWN")
        with tempfile.TemporaryDirectory() as d:
            staging=pathlib.Path(d)/"staging";staging.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE
            with mock.patch.object(C,"_root_writer",return_value=True),mock.patch.object(C,"_owned_mode",return_value=True),mock.patch.object(C.os,"fchmod",side_effect=lambda fd,mode:None,create=True),mock.patch.object(C,"bootstrap_record_state",return_value=("READ_FAILED","UNKNOWN")):
                with self.assertRaises(ValueError):C.record_bootstrap_status(record,commit,"PASS")
            with mock.patch.object(C,"_owned_mode",return_value=True):value=C.localization_evidence(None,record,commit,"bootstrap_progress","failure",commit)
            self.assertNotEqual(value["bootstrapRecordState"],"ACCEPTED");self.assertEqual(value["bootstrapChildState"],"UNKNOWN")
    def test_localization_cross_product_preserves_progress_detail_and_record_specificity(self):
        commit="2"*40
        for progress_state in C.PROGRESS_STATES:
            details=C.DETAIL_STATES-{"NOT_EVALUATED"} if progress_state in ("EMPTY","ACCEPTED") else {"NOT_EVALUATED"}
            for detail_state in details:
                for record_state in C.BOOTSTRAP_RECORD_STATES:
                    recorded="PASS" if record_state=="ACCEPTED" else "UNKNOWN"
                    with self.subTest(progress=progress_state,detail=detail_state,record=record_state),mock.patch.object(C,"_progress_localization",return_value=(progress_state,pathlib.Path("/fixed"))),mock.patch.object(C,"_detail_localization",return_value=detail_state),mock.patch.object(C,"bootstrap_record_state",return_value=(record_state,recorded)):
                        value=C.localization_evidence("/fixed","/fixed/status.json",commit,"bootstrap_progress","success",commit)
                    self.assertEqual(value["progressRootState"],progress_state);self.assertEqual(value["failureDetailState"],detail_state);self.assertEqual(value["bootstrapRecordState"],record_state);self.assertEqual(value["bootstrapChildState"],recorded)
    def test_bounded_child_models_all_closed_outcomes_without_stderr(self):
        expected=b'{"status":"PASS"}\n'
        def run(code,timeout=2):return CI._bounded_child([sys.executable,"-I","-B","-c",code],expected,timeout=timeout)
        self.assertEqual(run("import os;os.write(1,"+repr(expected)+")"),"PASS")
        self.assertEqual(run("import os,sys;os.write(2,b'PRIVATE STDERR');sys.exit(7)"),"COMMAND_NONZERO")
        class Stream:
            def __init__(self):self.closed=False
            def fileno(self):return 17
            def close(self):self.closed=True
        class Process:
            def __init__(self):self.stdout=Stream();self.calls=[];self.code=0
            def poll(self):return self.code
            def wait(self,timeout):self.calls.append(("wait",timeout));return self.code
            def terminate(self):self.calls.append(("terminate",None))
            def kill(self):self.calls.append(("kill",None))
        class Selector:
            def __init__(self):self.registered=[];self.select_calls=[];self.closed=False
            def register(self,*args):self.registered.append(args)
            def select(self,timeout):self.select_calls.append(timeout);return [(object(),1)]
            def close(self):self.closed=True
        process=Process();selector=Selector();chunks=[b"bad",b""];read_sizes=[];blocking=[]
        def read_fd(fd,size):read_sizes.append((fd,size));return chunks.pop(0)
        state=CI._bounded_child(["fixed"],expected,popen=lambda *a,**k:process,platform="posix",
            selector_factory=lambda:selector,set_blocking=lambda *a:blocking.append(a),read_fd=read_fd)
        self.assertEqual(state,"STDOUT_INVALID");self.assertEqual(chunks,[])
        self.assertEqual(read_sizes,[(17,1025),(17,1022)]);self.assertEqual(blocking,[(17,False)])
        self.assertEqual(selector.registered,[(17,CI.selectors.EVENT_READ)]);self.assertEqual(len(selector.select_calls),2);self.assertTrue(selector.closed)
        self.assertTrue(process.stdout.closed);self.assertEqual(len(process.calls),1);self.assertEqual(process.calls[0][0],"wait")
        self.assertEqual(run("import os,time;os.write(1,b'X'*1025);time.sleep(2)"),"STDOUT_OVERSIZE")
        self.assertEqual(run("import time;time.sleep(2)",timeout=0.1),"TIMEOUT")
        def spawn_error(*args,**kwargs):raise OSError("PRIVATE SPAWN")
        self.assertEqual(CI._bounded_child(["/not-used"],expected,popen=spawn_error),"SPAWN_ERROR")
    def test_bootstrap_argv_is_fixed_and_cleanup_terminates_kills_reaps(self):
        argv=CI.bootstrap_argv("/progress","/stage/bootstrap-localization.private/status.json","a"*40)
        self.assertEqual(argv[:9],["/usr/bin/setpriv","--reuid=10001","--regid=10001","--clear-groups","--bounding-set=-all","--inh-caps=-all","--ambient-caps=-all","--no-new-privs","/usr/bin/env"])
        self.assertIn("-i",argv);self.assertIn("--receipt",argv);self.assertNotIn("/stage/bootstrap-localization.private/status.json",argv)
        class Process:
            def __init__(self):self.calls=[];self.count=0
            def terminate(self):self.calls.append("terminate")
            def kill(self):self.calls.append("kill")
            def wait(self,timeout):
                self.calls.append("wait");self.count+=1
                if self.count==1:raise subprocess.TimeoutExpired(["fixed"],timeout)
                return -9
        process=Process();CI._stop_child(process);self.assertEqual(process.calls,["terminate","wait","kill","wait"])
    def test_supervisor_setup_read_close_and_reap_faults_never_pass_or_leak(self):
        expected=b"PASS\n"
        class Stream:
            def __init__(self,close_error=False):self.closed=False;self.close_error=close_error
            def fileno(self):return 17
            def close(self):
                self.closed=True
                if self.close_error:raise OSError("PRIVATE CLOSE")
        class Process:
            def __init__(self,code=None,close_error=False,unreapable=False):self.code=code;self.stdout=Stream(close_error);self.calls=[];self.unreapable=unreapable
            def poll(self):return self.code
            def terminate(self):self.calls.append("terminate");self.code=None if self.unreapable else -15
            def kill(self):self.calls.append("kill");self.code=None if self.unreapable else -9
            def wait(self,timeout):
                self.calls.append("wait")
                if self.code is None:raise subprocess.TimeoutExpired(["fixed"],timeout)
                return self.code
        class Selector:
            def __init__(self,events=None,error=None):self.events=events;self.error=error
            def register(self,*args):pass
            def select(self,*args):
                if self.error:raise self.error
                return self.events
            def close(self):pass
        cases=[]
        setup=Process();cases.append((setup,lambda:(_ for _ in ()).throw(OSError("PRIVATE SETUP")),os.read))
        reading=Process();cases.append((reading,lambda:Selector(events=[(1,1)]),lambda *_:(_ for _ in ()).throw(OSError("PRIVATE READ"))))
        closing=Process(code=0,close_error=True);cases.append((closing,lambda:Selector(events=[(1,1)]),lambda *_:b""))
        unreaped=Process(unreapable=True);cases.append((unreaped,lambda:(_ for _ in ()).throw(OSError("PRIVATE SELECTOR")),os.read))
        for process,factory,reader in cases:
            with self.subTest(calls=process.calls):
                with self.assertRaisesRegex(ValueError,"^joint-ci-child-custody-rejected$"):
                    CI._bounded_child(["fixed"],expected,popen=lambda *a,**k:process,platform="posix",selector_factory=factory,set_blocking=lambda *a:None,read_fd=reader)
                self.assertTrue(process.stdout.closed);self.assertNotIn("PRIVATE",str(process.calls))
        self.assertIn("kill",unreaped.calls)
        capped=Process(code=0);sizes=[]
        state=CI._bounded_child(["fixed"],expected,popen=lambda *a,**k:capped,platform="posix",selector_factory=lambda:Selector(events=[]),set_blocking=lambda *a:None,read_fd=lambda fd,size:(sizes.append(size) or b"X"*2048))
        self.assertEqual(state,"STDOUT_OVERSIZE");self.assertEqual(sizes,[1025]);self.assertTrue(capped.stdout.closed)
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
        self.assertLess(workflow.index(" bootstrap-progress "),workflow.index(" unshare "))
        self.assertIn('--progress-root "$root/evidence/staging/failure-localization.private"',workflow)
        self.assertIn('--bootstrap-record "$bootstrap"',workflow);self.assertIn('/mnt/joint-control-plane/evidence/staging/bootstrap-localization.private/status.json',workflow);self.assertIn('--bootstrap-record "$bootstrap"',namespace)
        for phase in C.FAILURE_PHASES:
            self.assertIn(phase,workflow+namespace+runner)
        self.assertNotIn("runner.stderr",workflow);self.assertNotIn("runner.stdout",workflow)
        bash=shutil.which("bash") or (r"C:\Program Files\Git\bin\bash.exe" if pathlib.Path(r"C:\Program Files\Git\bin\bash.exe").is_file() else None);self.assertIsNotNone(bash)
        result=subprocess.run([str(bash),"-n",str(HERE/"ci_namespace.sh")],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False);self.assertEqual(result.returncode,0,result.stderr.decode(errors="replace"))
    def test_workflow_engine_witness_is_exact_gated_and_standalone_only(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text();namespace=(HERE/"ci_namespace.sh").read_text();sanitizer=(HERE/"sanitize_publication.py").read_text()
        self.assertTrue(CI.workflow_contract(workflow.encode()))
        dedicated=workflow.split("      - name: Bootstrap bounded namespace progress",1)[1].split("      - name: Real B0 J1 R2 same-binary scene",1)[0]
        scene=workflow.split("      - name: Real B0 J1 R2 same-binary scene",1)[1].split("      - name: Reacquire source after every attempt",1)[0]
        failure=workflow.split("      - name: Publish only bounded failure classification",1)[1].split("      - if: always()",1)[0]
        self.assertIn("id: bootstrap_progress",dedicated);self.assertNotIn("continue-on-error",dedicated)
        self.assertIn("steps.bootstrap_progress.outcome == 'success'",scene);self.assertNotIn(".conclusion",scene+failure)
        for text in (scene,failure,namespace):
            self.assertIn("bootstrap_progress",text);self.assertIn("bootstrap-step",text.replace("_","-").lower())
        self.assertIn('value["provenanceAuthority"]="NON_AUTHORITATIVE_STANDALONE"',sanitizer)
        self.assertNotIn("AUTHORITATIVE_MATCH",sanitizer);self.assertNotIn("artifact",sanitizer.lower())
    def test_workflow_composition_validator_rejects_every_required_mutant(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text()
        def once(old,new="",occurrence=1):
            start=0
            for _ in range(occurrence):
                index=workflow.find(old,start);self.assertGreaterEqual(index,0);start=index+len(old)
            return workflow[:index]+new+workflow[index+len(old):]
        uid_block=workflow.split("      - name: Probe isolated Linux UID custody\n",1)[1].split("      - name: Independently validate UID probe diagnostic\n",1)[0]
        contract_pin=next(line for line in workflow.splitlines() if line.startswith("  CONTRACT_SHA256: "))
        outcome='          BOOTSTRAP_STEP_OUTCOME: ${{ steps.bootstrap_progress.outcome }}'
        mutants={
            "hardcoded-outer-success":once(outcome,'          BOOTSTRAP_STEP_OUTCOME: success',2),
            "conclusion-substitution":workflow.replace('steps.bootstrap_progress.outcome','steps.bootstrap_progress.conclusion'),
            "continue-on-error":once('        id: bootstrap_progress\n','        id: bootstrap_progress\n        continue-on-error: true\n'),
            "missing-id":once('        id: bootstrap_progress\n'),
            "duplicate-id":once('      - name: Real B0 J1 R2 same-binary scene\n','      - name: Real B0 J1 R2 same-binary scene\n        id: bootstrap_progress\n'),
            "missing-gate":once("        if: ${{ steps.bootstrap_progress.outcome == 'success' }}\n"),
            "gate-bypass":once("        if: ${{ steps.bootstrap_progress.outcome == 'success' }}","        if: always()"),
            "wrong-step":once('--bootstrap-step-id bootstrap_progress','--bootstrap-step-id other_step'),
            "missing-step-arg":once(' --bootstrap-step-id bootstrap_progress'),
            "missing-outcome-arg":once(' --bootstrap-step-outcome "$BOOTSTRAP_STEP_OUTCOME"'),
            "missing-source-arg":once(' --bootstrap-step-source "$GITHUB_SHA"'),
            "cross-source":once('--bootstrap-step-source "$GITHUB_SHA"','--bootstrap-step-source "0000000000000000000000000000000000000000"'),
            "namespace-missing-step":once(' bootstrap_progress "$BOOTSTRAP_STEP_OUTCOME" "$GITHUB_SHA"',' "$BOOTSTRAP_STEP_OUTCOME" "$GITHUB_SHA"'),
            "namespace-missing-outcome":once(' bootstrap_progress "$BOOTSTRAP_STEP_OUTCOME" "$GITHUB_SHA"',' bootstrap_progress "$GITHUB_SHA"'),
            "namespace-cross-source":once(' bootstrap_progress "$BOOTSTRAP_STEP_OUTCOME" "$GITHUB_SHA"',' bootstrap_progress "$BOOTSTRAP_STEP_OUTCOME" "0000000000000000000000000000000000000000"'),
            "dedicated-outcome-wrong-step":once(outcome,'          BOOTSTRAP_STEP_OUTCOME: ${{ steps.cpu.outcome }}',2),
            "model-upload-gate-bypass":once("        if: ${{ always() && steps.cpu.outputs.model_diagnostic_ready == 'true' }}","        if: always()"),
            "model-upload-cross-directory":once("path: ${{ runner.temp }}/joint-control-plane-model-outcome-public/model-outcome.json","path: ${{ runner.temp }}/joint-control-plane-cpu-public/model-outcome.json"),
            "model-units-source-binding-removed":once('ci_joint_control_plane.py units --output "$private/units.json" --model-diagnostic "$private/model-outcome.json" --source-commit "$GITHUB_SHA"','ci_joint_control_plane.py units --output "$private/units.json" --model-diagnostic "$private/model-outcome.json"'),
            "model-independent-validator-removed":once('          if python3 -I -B chengwang/deploy/joint-control-plane/ci_joint_control_plane.py model-diagnostic --input "$private/model-outcome.json" --source-commit "$GITHUB_SHA" --output "$model_public/model-outcome.json"; then\n'),
            "uid-diagnostic-upload-bypass":once("        if: ${{ always() && steps.uid_probe_diagnostic.outputs.ready == 'true' }}","        if: always()"),
            "uid-diagnostic-ready-write-unchecked":once("if echo 'ready=true' >> \"$GITHUB_OUTPUT\"; then exit 0; else exit 1; fi","echo 'ready=true' >> \"$GITHUB_OUTPUT\""),
            "uid-diagnostic-preflight-failure-green":once('          test "$host_preflight" != PREFLIGHT_EXECUTION_FAILED || diagnostic_failed=true\n'),
            "uid-bridge-setup-removed":once('          if sudo --non-interactive /usr/bin/python3 -I -B "$source_script" "${bridge[@]}" --bridge-mode setup >/dev/null 2>/dev/null; then bridge_setup_status=0; bridge_active=true; else bridge_setup_status=$?; bridge_active=false; fi\n'),
            "uid-bridge-preflight-removed":once('            if "${diagnostic[@]}" bridge-preflight --classification "$bridge_preflight" --exit-status "$bridge_preflight_status"; then :; else diagnostic_failed=true; fi\n'),
            "uid-bridge-cleanup-removed":once('              if sudo --non-interactive /usr/bin/python3 -I -B "$source_script" "${bridge[@]}" --bridge-mode cleanup >/dev/null 2>/dev/null; then cleanup_status=0; else cleanup_status=$?; fi\n'),
            "uid-bridge-absence-removed":once('            if sudo --non-interactive /usr/bin/python3 -I -B "$source_script" "${bridge[@]}" --bridge-mode final-absence >/dev/null 2>/dev/null; then absence_status=0; else absence_status=$?; fi\n'),
            "uid-diagnostic-cleanup-missing":once('if run_root root-cleanup; then cleanup_status=0; else cleanup_status=$?; fi','cleanup_status=0'),
            "uid-diagnostic-final-absence-missing":once('if run_root root-final-absence; then absence_status=0; else absence_status=$?; fi','absence_status=0'),
            "uid-diagnostic-independent-replay-removed":once('  uid-probe-independent-replay:\n','  removed-uid-probe-independent-replay:\n'),
            "uid-diagnostic-producer-pin-drift":once("98982bd151c9289534fa7421a1520ba51ff67ceb0fd930065e227321e419052d","0"*64),
            "uid-root-escalation":once("--reuid=10001","--reuid=0"),
            "uid-clear-groups-removed":once("--clear-groups "),
            "main-timeout-expanded":once("    timeout-minutes: 18","    timeout-minutes: 180"),
            "uid-install-call-removed":once('          if test "$probe_active" = true && test "$original_code" = 0; then if run_uid uid-install-replacement; then :; else original_code=$?; fi; fi\n'),
            "exact-ref-drift":once("  EXACT_REF: refs/heads/codex/chengwang-unified-20261102","  EXACT_REF: refs/heads/main"),
            "source-contract-pin-drift":once(contract_pin,"  CONTRACT_SHA256: "+"0"*64),
            "head-source-binding-removed":once('          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"\n'),
            "uid-step-duplicated":once("      - name: Independently validate UID probe diagnostic\n","      - name: Probe isolated Linux UID custody\n"+uid_block+"      - name: Independently validate UID probe diagnostic\n"),
            "uid-replay-truncated":once('          cmp "$input" "$output"\n'),
            "uid-install-comment-spoof":once('          if test "$probe_active" = true && test "$original_code" = 0; then if run_uid uid-install-replacement; then :; else original_code=$?; fi; fi\n','          # if run_uid uid-install-replacement; then :; else original_code=$?; fi\n'),
        }
        for name,mutant in mutants.items():
            with self.subTest(name=name),self.assertRaises(ValueError):CI.workflow_contract(mutant.encode())
    def test_uid_probe_inventory_order_and_model_boundary_are_source_closed(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text();source=pathlib.Path(CI.__file__).read_text();tree=ast.parse(source)
        self.assertEqual(CI.PROBE_MODES,{"root-setup","uid-prepublish-denials","root-finalize","uid-final-read-and-rename","uid-install-replacement","root-reject-replacement","root-cleanup","root-final-absence"})
        probe=workflow.split("      - name: Probe isolated Linux UID custody",1)[1].split("      - name: Build once",1)[0]
        self.assertLess(workflow.index("Prepare immutable source and staging"),workflow.index("Probe isolated Linux UID custody"));self.assertLess(workflow.index("Probe isolated Linux UID custody"),workflow.index("Bootstrap bounded namespace progress"))
        for forbidden in ('private="$RUNNER_TEMP/joint-control-plane"','root="$RUNNER_TEMP/joint-control-plane"',' go ','unshare','curl','wget','systemctl','docker'):
            self.assertNotIn(forbidden,probe)
        for mode in CI.PROBE_MODES:self.assertIn(mode,probe+source)
        self.assertIn("trap 'finish_probe \"$?\"' EXIT",probe);self.assertIn("probe_active=true",probe);self.assertIn("if run_root root-setup; then :; else original_code=$?; fi",probe);self.assertIn("root-final-absence",probe);self.assertNotIn("rmtree",ast.unparse(tree))
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="bootstrap_permission_probe")
        constants={node.value for node in ast.walk(function) if isinstance(node,ast.Constant) and isinstance(node.value,str)}
        self.assertTrue(CI.PROBE_MODES-{"root-final-absence"}<=constants);self.assertTrue(all(mode in source for mode in CI.PROBE_MODES));self.assertNotIn("ACTUAL_UID_PERMISSION_MICROPROBE_PASS",workflow+source)
    def test_uid_probe_bash_preserves_cleanup_absence_and_outer_exit_status(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text()
        block=workflow.split("      - name: Probe isolated Linux UID custody\n",1)[1].split("      - name: Independently validate UID probe diagnostic\n",1)[0]
        probe=block.split("        run: |\n",1)[1]
        probe="\n".join(line[10:] if line.startswith("          ") else line for line in probe.splitlines())+"\n"
        probe=probe.replace('diagnostic=(/usr/bin/python3 -I -B "$producer"','diagnostic=(diagnostic_stub')
        probe=probe.replace('bridge_nonce="$(/usr/bin/python3 -I -B -c \'import secrets;print(secrets.token_hex(16))\')" || exit 1','bridge_nonce=0123456789abcdef0123456789abcdef')
        probe=probe.replace('if cleanup_probe; then :; else cleanup_status=$?; test "$original_code" != 0 || original_code="$cleanup_status"; fi','test "$INJECT_OUTER_EXIT" != true || exit 17\nif cleanup_probe; then :; else cleanup_status=$?; test "$original_code" != 0 || original_code="$cleanup_status"; fi')
        bash=shutil.which("bash")
        if bash is None:
            candidate=pathlib.Path(os.environ.get("ProgramFiles",r"C:\Program Files"))/"Git/bin/bash.exe"
            self.assertTrue(candidate.is_file());bash=str(candidate)
        source=str(HERE.parents[2]).replace("\\","/");producer_hash=CI.hashlib.sha256((HERE/"uid_probe_diagnostic.py").read_bytes()).hexdigest()
        modes=("root-setup","uid-prepublish-denials","root-finalize","uid-final-read-and-rename","uid-install-replacement","root-reject-replacement","root-cleanup","root-final-absence")
        cases=(("cleanup31","root-cleanup","",31,0,False,31,modes),("absence32","root-final-absence","",32,0,False,32,modes),("outer17","","",0,0,True,17,modes),("bridge-cleanup35","","cleanup",35,0,False,35,modes),("bridge-absence36","","final-absence",36,0,False,36,modes),("bridge-setup33","","setup",33,0,False,33,()),("host-inaccessible-bridge-pass","","",0,43,False,0,modes))
        for name,fail_mode,fail_bridge_mode,fail_status,host_preflight_status,inject,want,expected_modes in cases:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);runner=root/"runner";runner.mkdir();trace=root/"trace";candidate=root/"candidate"
                runner_text=str(runner).replace("\\","/");trace_text=str(trace).replace("\\","/")
                harness=f'''set +e
export GITHUB_WORKSPACE={json.dumps(source)} RUNNER_TEMP={json.dumps(runner_text)} GITHUB_SHA={'1'*40} GITHUB_RUN_ID=71 GITHUB_RUN_ATTEMPT=8 UID_PROBE_PRODUCER_SHA256={producer_hash}
export FAIL_MODE={json.dumps(fail_mode)} FAIL_BRIDGE_MODE={json.dumps(fail_bridge_mode)} FAIL_STATUS={fail_status} HOST_PREFLIGHT_STATUS={host_preflight_status} INJECT_OUTER_EXIT={'true' if inject else 'false'} TRACE={json.dumps(trace_text)}
PREFLIGHT_CALLS=0
install() {{ local target="${{@: -1}}"; mkdir "$target"; }}
sudo() {{
  local mode="" bridge_mode="" nonce="" run_id="" run_attempt="" previous="" argument bridge_root="" bridge_status=0
  for argument in "$@"; do
    case "$previous" in --probe-mode) mode="$argument";; --bridge-mode) bridge_mode="$argument";; --bridge-nonce) nonce="$argument";; --run-id) run_id="$argument";; --run-attempt) run_attempt="$argument";; esac
    previous="$argument"
  done
  if printf '%s\\n' "$*" | grep -q 'bridge-payload-digest'; then printf '%064d\\n' 0; return 0; fi
  if test -n "$bridge_mode"; then
    bridge_root="/tmp/chengwang-joint-uid-bridge-$run_id-$run_attempt-$nonce"
    case "$bridge_mode" in
      setup) mkdir -p "$bridge_root/payload" "$bridge_root/runner"; printf 'fixture\\n' >"$bridge_root/payload/ci_joint_control_plane.py"; printf 'fixture\\n' >"$bridge_root/payload/contract.py";;
      cleanup) rm -rf "$bridge_root";;
      final-absence) test ! -e "$bridge_root";;
      *) return 90;;
    esac
    bridge_status=$?
    if test "$bridge_mode" = "$FAIL_BRIDGE_MODE"; then test "$bridge_mode" != setup || rm -rf "$bridge_root"; return "$FAIL_STATUS"; fi
    return "$bridge_status"
  fi
  if test -n "$mode"; then printf 'call:%s\\n' "$mode" >> "$TRACE"; if test "$mode" = "$FAIL_MODE"; then return "$FAIL_STATUS"; fi; return 0; fi
  if printf '%s\\n' "$*" | grep -q -- '--reuid=10001'; then PREFLIGHT_CALLS=$((PREFLIGHT_CALLS+1)); test "$PREFLIGHT_CALLS" != 1 || return "$HOST_PREFLIGHT_STATUS"; fi
  return 0
}}
diagnostic_stub() {{
  local command="" mode="" status="" previous="" argument
  for argument in "$@"; do case "$argument" in init|host-preflight|bridge-setup|bridge-preflight|event|bridge-cleanup|bridge-final-absence|finalize) command="$argument";; esac; case "$previous" in --mode) mode="$argument";; --exit-status) status="$argument";; esac; previous="$argument"; done
  printf 'diagnostic:%s:%s:%s\\n' "$command" "$mode" "$status" >> "$TRACE"
  if test "$command" = finalize && test "$INJECT_OUTER_EXIT" = true; then printf 'reject-finalize:%s\\n' "$status" >> "$TRACE"; return 1; fi
  return 0
}}
'''+probe
                completed=subprocess.run([bash],input=harness.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
                self.assertEqual(completed.returncode,want,(completed.stderr,trace.read_text() if trace.exists() else "NO_TRACE"));self.assertEqual(completed.stdout,b"");self.assertNotIn(b"PRIVATE",completed.stderr)
                rows=trace.read_text().splitlines();calls=[row.split(":",1)[1] for row in rows if row.startswith("call:")]
                self.assertEqual(calls,list(expected_modes));self.assertIn(f"diagnostic:finalize::{want}",rows);self.assertFalse(candidate.exists())
                if inject:self.assertIn("reject-finalize:17",rows)
    def test_uid_probe_root_derivation_rejects_bad_identity_and_is_never_product_staging(self):
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat()
            _,probe,staging,_=CI._probe_paths(runner,"123","4",str(meta.st_dev),str(meta.st_ino),platform="posix")
            self.assertEqual(probe,runner/"chengwang-joint-bootstrap-custody-probe-123-4");self.assertEqual(staging,probe/"staging");self.assertNotEqual(probe,runner/"joint-control-plane")
            for args in (("0","4",str(meta.st_dev),str(meta.st_ino)),("123","0",str(meta.st_dev),str(meta.st_ino)),("123","4","999999",str(meta.st_ino))):
                with self.assertRaises(ValueError):CI._probe_paths(runner,*args,platform="posix")
    def test_uid_probe_fixed_sequence_model_rejects_replacement_and_leaves_no_residue(self):
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();args=(runner,"321","7",str(meta.st_dev),str(meta.st_ino));probe=runner/"chengwang-joint-bootstrap-custody-probe-321-7"
            def owned(path,*unused,**kwargs):return pathlib.Path(path).lstat()
            model_unlink,model_rmdir=_probe_fixture_cleanup_calls(probe)
            common=(mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_probe_owned",side_effect=owned),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None),mock.patch.object(CI,"_probe_denied",side_effect=lambda *a:None),mock.patch.object(CI,"_probe_open_denied",side_effect=lambda *a:None),mock.patch.object(CI,"_probe_rename_denied",side_effect=lambda *a:None),mock.patch.object(CI.C,"_owned_mode",return_value=True),mock.patch.object(CI.C,"bootstrap_record_state",side_effect=(("ACCEPTED","PASS"),("INVALID","UNKNOWN"))),mock.patch.object(CI.stat,"S_IMODE",return_value=0o711),mock.patch.object(CI.os,"unlink",side_effect=model_unlink),mock.patch.object(CI.os,"rmdir",side_effect=model_rmdir),_probe_fixture_owner_view(probe))
            with common[0],common[1],common[2],common[3],common[4],common[5],common[6],common[7],common[8],common[9],common[10],common[11]:
                for mode,identity in (("root-setup",(0,0)),("uid-prepublish-denials",(C.UID,C.GID)),("root-finalize",(0,0)),("uid-final-read-and-rename",(C.UID,C.GID)),("uid-install-replacement",(C.UID,C.GID)),("root-reject-replacement",(0,0)),("root-cleanup",(0,0)),("root-final-absence",(0,0))):
                    with mock.patch.object(CI.os,"geteuid",return_value=identity[0],create=True),mock.patch.object(CI.os,"getegid",return_value=identity[1],create=True):CI.bootstrap_permission_probe(*args,mode,platform="posix")
            self.assertFalse(probe.exists())
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();probe=runner/"chengwang-joint-bootstrap-custody-probe-321-7";probe.write_bytes(b"PREEXISTING")
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True):
                with self.assertRaises(ValueError):CI.bootstrap_permission_probe(runner,"321","7",str(meta.st_dev),str(meta.st_ino),"root-setup",platform="posix")
            self.assertEqual(probe.read_bytes(),b"PREEXISTING")
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();probe=runner/"chengwang-joint-bootstrap-custody-probe-321-7"
            def owned(path,*unused,**kwargs):return pathlib.Path(path).lstat()
            real_final=CI._probe_final_absence;final_calls=[]
            def final(*args,**kwargs):final_calls.append(True);return real_final(*args,**kwargs)
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_probe_owned",side_effect=owned),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None),mock.patch.object(CI,"_probe_write",side_effect=OSError("PRIVATE PARTIAL SETUP")),mock.patch.object(CI,"_probe_final_absence",side_effect=final),mock.patch.object(CI.stat,"S_IMODE",return_value=0o711),_probe_fixture_owner_view(probe):
                with self.assertRaises(OSError):CI.bootstrap_permission_probe(runner,"321","7",str(meta.st_dev),str(meta.st_ino),"root-setup",platform="posix")
            self.assertFalse(probe.exists());self.assertEqual(final_calls,[True])
    def test_uid_probe_preexisting_file_directory_symlink_and_ancestor_models_are_preserved(self):
        for kind in ("file","directory"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                runner=pathlib.Path(d).resolve();meta=runner.lstat();probe=runner/"chengwang-joint-bootstrap-custody-probe-91-2"
                if kind=="file":probe.write_bytes(b"PREEXISTING")
                else:probe.mkdir();(probe/"sentinel").write_bytes(b"PREEXISTING")
                before=(probe.lstat().st_dev,probe.lstat().st_ino)
                with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI,"_probe_cleanup_tree") as cleanup,mock.patch.object(CI,"_probe_final_absence") as final:
                    with self.assertRaises(ValueError):CI.bootstrap_permission_probe(runner,"91","2",str(meta.st_dev),str(meta.st_ino),"root-setup",platform="posix")
                self.assertEqual((probe.lstat().st_dev,probe.lstat().st_ino),before);cleanup.assert_not_called();final.assert_not_called()
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();probe=runner/"chengwang-joint-bootstrap-custody-probe-91-2";probe.write_bytes(b"SYMLINK-SENTINEL");real_absent=CI._probe_absent
            def symlink_collision(path):return False if pathlib.Path(path)==probe else real_absent(path)
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI,"_probe_absent",side_effect=symlink_collision),mock.patch.object(CI,"_probe_cleanup_tree") as cleanup,mock.patch.object(CI,"_probe_final_absence") as final:
                with self.assertRaises(ValueError):CI.bootstrap_permission_probe(runner,"91","2",str(meta.st_dev),str(meta.st_ino),"root-setup",platform="posix")
            self.assertEqual(probe.read_bytes(),b"SYMLINK-SENTINEL");cleanup.assert_not_called();final.assert_not_called()
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();sentinel=runner/"ancestor-sentinel";sentinel.write_bytes(b"UNCHANGED")
            real_symlink=pathlib.Path.is_symlink
            with mock.patch.object(pathlib.Path,"is_symlink",autospec=True,side_effect=lambda path:path==runner or real_symlink(path)),mock.patch.object(CI.os,"mkdir") as mkdir:
                with self.assertRaises(ValueError):CI._probe_paths(runner,"91","2",str(meta.st_dev),str(meta.st_ino),platform="posix")
            mkdir.assert_not_called();self.assertEqual(sentinel.read_bytes(),b"UNCHANGED")
    def test_bootstrap_reader_rejects_extra_symlink_hardlink_owner_mode_and_copied_bytes(self):
        commit="1"*40
        with tempfile.TemporaryDirectory() as d:
            staging=pathlib.Path(d)/"staging";staging.mkdir();record=staging/C.BOOTSTRAP_DIRECTORY/C.BOOTSTRAP_FILE;record.parent.mkdir();record.write_bytes(C.canonical({"schema":C.BOOTSTRAP_SCHEMA,"sourceCommit":commit,"bootstrapChildState":"PASS"}))
            with mock.patch.object(C,"_owned_mode",return_value=True):self.assertEqual(C.bootstrap_record_state(record,commit),("ACCEPTED","PASS"))
            extra=record.parent/"extra";extra.write_bytes(b"X")
            with mock.patch.object(C,"_owned_mode",return_value=True):self.assertEqual(C.bootstrap_record_state(record,commit),("INVALID","UNKNOWN"))
            extra.unlink();hard=record.parent/"hard";os.link(record,hard)
            with mock.patch.object(C,"_owned_mode",return_value=True):self.assertEqual(C.bootstrap_record_state(record,commit),("INVALID","UNKNOWN"))
            hard.unlink();real_symlink=pathlib.Path.is_symlink
            with mock.patch.object(pathlib.Path,"is_symlink",autospec=True,side_effect=lambda path:path==record or real_symlink(path)),mock.patch.object(C,"_owned_mode",return_value=True):self.assertEqual(C.bootstrap_record_state(record,commit),("INVALID","UNKNOWN"))
            for custody in ("wrong-owner","wrong-mode"):
                with self.subTest(custody=custody),mock.patch.object(C,"_owned_mode",return_value=False):self.assertEqual(C.bootstrap_record_state(record,commit),("INVALID","UNKNOWN"))
            parent_identity=C._identity(staging.lstat());directory_identity=C._identity(record.parent.lstat());file_identity=C._identity(record.lstat());moved=staging/"moved";record.parent.rename(moved);record.parent.mkdir();record.write_bytes((moved/C.BOOTSTRAP_FILE).read_bytes())
            with mock.patch.object(C,"_owned_mode",return_value=True):self.assertEqual(C.bootstrap_record_state(record,commit,parent_identity,directory_identity,file_identity),("INVALID","UNKNOWN"))
            record.parent.rename(staging/"replacement");self.assertEqual(C.bootstrap_record_state(record,commit),("ABSENT","UNKNOWN"))
    def test_uid_probe_wrong_uid_and_mode_order_reject_before_untrusted_operations(self):
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();args=(runner,"82","3",str(meta.st_dev),str(meta.st_ino));probe=runner/"chengwang-joint-bootstrap-custody-probe-82-3"
            with mock.patch.object(CI.os,"geteuid",return_value=C.UID,create=True),mock.patch.object(CI.os,"getegid",return_value=C.GID,create=True),mock.patch.object(CI.os,"mkdir") as mkdir:
                with self.assertRaises(ValueError):CI.bootstrap_permission_probe(*args,"root-setup",platform="posix")
            mkdir.assert_not_called();self.assertFalse(probe.exists())
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"rename") as rename:
                with self.assertRaises(ValueError):CI.bootstrap_permission_probe(*args,"uid-final-read-and-rename",platform="posix")
            rename.assert_not_called();self.assertFalse(probe.exists())
            for mode in ("root-finalize","root-reject-replacement","root-cleanup"):
                with self.subTest(mode=mode),mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True):
                    if mode=="root-cleanup":CI.bootstrap_permission_probe(*args,mode,platform="posix")
                    else:
                        with self.assertRaises((FileNotFoundError,ValueError)):CI.bootstrap_permission_probe(*args,mode,platform="posix")
    def test_uid_probe_partial_setup_operation_fault_matrix_runs_cleanup_and_final_absence(self):
        cases=[("mkdir",2),("mkdir",3),("chown",1),("chown",2),("chown",3),("chmod",1),("chmod",2),("chmod",3),("probe-write",1),("probe-owned",1),("probe-owned",2),("probe-owned",3),("probe-owned",4),("dir-fsync",1),("dir-fsync",2),("dir-fsync",3),("dir-fsync",4),("write",1),("file-fsync",1)]
        for operation,nth in cases:
            with self.subTest(operation=operation,nth=nth),tempfile.TemporaryDirectory() as d:
                runner=pathlib.Path(d).resolve();meta=runner.lstat();args=(runner,"73","6",str(meta.st_dev),str(meta.st_ino));probe=runner/"chengwang-joint-bootstrap-custody-probe-73-6";counts={};final_calls=[]
                real={"mkdir":CI.os.mkdir,"chmod":CI.os.chmod,"write":CI.os.write,"file-fsync":CI.os.fsync,"probe-write":CI._probe_write};model_unlink,model_rmdir=_probe_fixture_cleanup_calls(probe)
                def fault(name,normal):
                    def call(*a,**k):
                        counts[name]=counts.get(name,0)+1
                        if name==operation and counts[name]==nth:raise OSError("PRIVATE "+name)
                        return normal(*a,**k)
                    return call
                def owned(path,*unused,**kwargs):return pathlib.Path(path).lstat()
                real_final=CI._probe_final_absence
                def final(*a,**k):final_calls.append(True);return real_final(*a,**k)
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(CI.os,"geteuid",return_value=0,create=True));stack.enter_context(mock.patch.object(CI.os,"getegid",return_value=0,create=True));stack.enter_context(mock.patch.object(CI.stat,"S_IMODE",return_value=0o711));stack.enter_context(mock.patch.object(CI.os,"rmdir",side_effect=model_rmdir));stack.enter_context(mock.patch.object(CI.os,"unlink",side_effect=model_unlink));stack.enter_context(mock.patch.object(CI,"_probe_final_absence",side_effect=final));stack.enter_context(_probe_fixture_owner_view(probe))
                    stack.enter_context(mock.patch.object(CI.os,"mkdir",side_effect=fault("mkdir",real["mkdir"])))
                    stack.enter_context(mock.patch.object(CI.os,"chmod",side_effect=fault("chmod",real["chmod"])))
                    stack.enter_context(mock.patch.object(CI.os,"chown",side_effect=fault("chown",lambda *a:None),create=True))
                    stack.enter_context(mock.patch.object(CI.os,"write",side_effect=fault("write",real["write"])))
                    stack.enter_context(mock.patch.object(CI.os,"fsync",side_effect=fault("file-fsync",real["file-fsync"])))
                    stack.enter_context(mock.patch.object(CI,"_probe_write",side_effect=fault("probe-write",real["probe-write"])))
                    stack.enter_context(mock.patch.object(CI,"_probe_owned",side_effect=fault("probe-owned",owned)))
                    stack.enter_context(mock.patch.object(CI,"_probe_dir_fsync",side_effect=fault("dir-fsync",lambda *a:None)))
                    with self.assertRaises(OSError):CI.bootstrap_permission_probe(*args,"root-setup",platform="posix")
                self.assertFalse(probe.exists());self.assertEqual(final_calls,[True])
    def test_uid_probe_partial_setup_cleanup_and_final_gate_faults_are_both_observed(self):
        for target in ("cleanup","final-absence"):
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                runner=pathlib.Path(d).resolve();meta=runner.lstat();args=(runner,"71","8",str(meta.st_dev),str(meta.st_ino));probe=runner/"chengwang-joint-bootstrap-custody-probe-71-8";final_calls=[];real_final=CI._probe_final_absence
                def final(*a,**k):
                    final_calls.append(True)
                    if target=="final-absence":raise OSError("PRIVATE FINAL ABSENCE")
                    return real_final(*a,**k)
                cleanup=(mock.patch.object(CI,"_probe_cleanup_tree",side_effect=OSError("PRIVATE CLEANUP")) if target=="cleanup" else mock.patch.object(CI,"_probe_cleanup_tree",wraps=CI._probe_cleanup_tree))
                with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_probe_owned",side_effect=lambda path,*a,**k:pathlib.Path(path).lstat()),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None),mock.patch.object(CI,"_probe_write",side_effect=OSError("PRIVATE SETUP")),mock.patch.object(CI,"_probe_final_absence",side_effect=final),mock.patch.object(CI.stat,"S_IMODE",return_value=0o711),_probe_fixture_owner_view(probe),cleanup:
                    with self.assertRaises(ValueError):CI.bootstrap_permission_probe(*args,"root-setup",platform="posix")
                self.assertEqual(final_calls,[True]);self.assertEqual(probe.exists(),target=="cleanup")
    def test_uid_probe_cleanup_custody_and_final_absence_faults_fail_closed(self):
        def setup(root,run_id):
            runner=pathlib.Path(root).resolve();meta=runner.lstat();args=(runner,run_id,"5",str(meta.st_dev),str(meta.st_ino));probe=runner/(CI.PROBE_PREFIX+run_id+"-5")
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_probe_owned",side_effect=lambda path,*a,**k:pathlib.Path(path).lstat()),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None):CI.bootstrap_permission_probe(*args,"root-setup",platform="posix")
            return args,probe
        def cleanup(args,probe,patches=()):
            unlink,rmdir=_probe_fixture_cleanup_calls(probe)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(CI.os,"geteuid",return_value=0,create=True));stack.enter_context(mock.patch.object(CI.os,"getegid",return_value=0,create=True));stack.enter_context(mock.patch.object(CI.stat,"S_IMODE",return_value=0o711));stack.enter_context(mock.patch.object(CI.os,"unlink",side_effect=unlink));stack.enter_context(mock.patch.object(CI.os,"rmdir",side_effect=rmdir));stack.enter_context(mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None));stack.enter_context(_probe_fixture_owner_view(probe))
                for patcher in patches:stack.enter_context(patcher)
                return CI.bootstrap_permission_probe(*args,"root-cleanup",platform="posix")
        with tempfile.TemporaryDirectory() as d:
            args,probe=setup(d,"61");extra=probe/"staging/extra";extra.write_bytes(b"UNTRUSTED")
            with self.assertRaises(ValueError):cleanup(args,probe)
            self.assertEqual(extra.read_bytes(),b"UNTRUSTED");extra.unlink();cleanup(args,probe);self.assertFalse(probe.exists())
        with tempfile.TemporaryDirectory() as d:
            args,probe=setup(d,"62");record=probe/"staging/protected-original/status.json";outside=pathlib.Path(d)/"outside-hardlink";os.link(record,outside)
            with self.assertRaises(ValueError):cleanup(args,probe)
            self.assertTrue(probe.exists());outside.unlink();cleanup(args,probe);self.assertFalse(probe.exists())
        with tempfile.TemporaryDirectory() as d:
            args,probe=setup(d,"63");child=probe/"staging/protected-original";real_symlink=pathlib.Path.is_symlink
            symlink=mock.patch.object(pathlib.Path,"is_symlink",autospec=True,side_effect=lambda path:path==child or real_symlink(path))
            with self.assertRaises(ValueError):cleanup(args,probe,(symlink,))
            self.assertTrue(probe.exists());cleanup(args,probe);self.assertFalse(probe.exists())
        for run_id,target in (("64","unlink"),("65","rmdir"),("66","dir-fsync")):
            with self.subTest(cleanup=target),tempfile.TemporaryDirectory() as d:
                args,probe=setup(d,run_id);patcher={"unlink":mock.patch.object(CI.os,"unlink",side_effect=OSError("PRIVATE CLEANUP")),"rmdir":mock.patch.object(CI.os,"rmdir",side_effect=OSError("PRIVATE CLEANUP")),"dir-fsync":mock.patch.object(CI,"_probe_dir_fsync",side_effect=OSError("PRIVATE CLEANUP"))}[target]
                with self.assertRaises(OSError):cleanup(args,probe,(patcher,))
                if probe.exists():cleanup(args,probe)
                self.assertFalse(probe.exists())
                with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True):CI.bootstrap_permission_probe(*args,"root-final-absence",platform="posix")
                bad=(args[0],args[1],args[2],"999999",args[4])
                with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True):
                    with self.assertRaises(ValueError):CI.bootstrap_permission_probe(*bad,"root-final-absence",platform="posix")
    def test_uid_probe_rename_faults_remain_nonzero_and_scoped_cleanup_removes_only_probe(self):
        with tempfile.TemporaryDirectory() as d:
            runner=pathlib.Path(d).resolve();meta=runner.lstat();args=(runner,"55","4",str(meta.st_dev),str(meta.st_ino));probe=runner/"chengwang-joint-bootstrap-custody-probe-55-4";sentinel=runner/"outside-sentinel";sentinel.write_bytes(b"UNCHANGED")
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_probe_owned",side_effect=lambda path,*a,**k:pathlib.Path(path).lstat()),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None):CI.bootstrap_permission_probe(*args,"root-setup",platform="posix")
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI,"_probe_owned",side_effect=lambda path,*a,**k:pathlib.Path(path).lstat()),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None),mock.patch.object(CI.C,"bootstrap_record_state",return_value=("ACCEPTED","PASS")):CI.bootstrap_permission_probe(*args,"root-finalize",platform="posix")
            uid=(mock.patch.object(CI.os,"geteuid",return_value=C.UID,create=True),mock.patch.object(CI.os,"getegid",return_value=C.GID,create=True),mock.patch.object(CI,"_probe_denied",side_effect=lambda *a:None),mock.patch.object(CI,"_probe_open_denied",side_effect=lambda *a:None))
            with uid[0],uid[1],uid[2],uid[3],mock.patch.object(CI.os,"rename",side_effect=OSError("PRIVATE RENAME")):
                with self.assertRaises(OSError):CI.bootstrap_permission_probe(*args,"uid-final-read-and-rename",platform="posix")
            with uid[0],uid[1],uid[2],uid[3]:CI.bootstrap_permission_probe(*args,"uid-final-read-and-rename",platform="posix")
            with uid[0],uid[1],mock.patch.object(CI.os,"rename",side_effect=OSError("PRIVATE INSTALL RENAME")):
                with self.assertRaises(OSError):CI.bootstrap_permission_probe(*args,"uid-install-replacement",platform="posix")
            unlink,rmdir=_probe_fixture_cleanup_calls(probe)
            with mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.stat,"S_IMODE",return_value=0o711),mock.patch.object(CI.os,"unlink",side_effect=unlink),mock.patch.object(CI.os,"rmdir",side_effect=rmdir),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None),_probe_fixture_owner_view(probe):CI.bootstrap_permission_probe(*args,"root-cleanup",platform="posix")
            self.assertFalse(probe.exists());self.assertEqual(sentinel.read_bytes(),b"UNCHANGED")
    def test_uid_bridge_exact_two_file_payload_rejects_extra_hardlink_and_preserves_sentinel(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d).resolve();repo=root/"repo";parent=root/"parent";parent.mkdir();sentinel=parent/"outside-sentinel";sentinel.write_bytes(b"UNCHANGED")
            rows=[]
            for relative,basename in CI.BRIDGE_FILES:
                path=repo/relative;path.parent.mkdir(parents=True,exist_ok=True);raw=(basename+"\n").encode();path.write_bytes(raw);rows.append({"path":relative,"sha256":CI.hashlib.sha256(raw).hexdigest()})
            contract=repo/"chengwang/deploy/joint-control-plane/source_contract.json";contract.write_text(json.dumps({"schema":"test","paths":rows})+"\n",encoding="utf-8")
            meta=parent.lstat();arguments=(repo,contract,parent,str(meta.st_dev),str(meta.st_ino),"321","7","a"*32)
            owned=lambda path,*a,**k:pathlib.Path(path).lstat()
            patches=(mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI.os,"fchown",side_effect=lambda *a:None,create=True),mock.patch.object(CI.os,"fchmod",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_bridge_parent",side_effect=lambda path,*a,**k:pathlib.Path(path)),mock.patch.object(CI,"_bridge_owned",side_effect=owned),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None))
            with contextlib.ExitStack() as stack:
                for patcher in patches:stack.enter_context(patcher)
                bridge,digest=CI.bridge_setup(*arguments,platform="posix");self.assertEqual(digest,CI.bridge_payload_digest(repo,contract));self.assertEqual({p.name for p in (bridge/"payload").iterdir()},{"ci_joint_control_plane.py","contract.py"});self.assertFalse(any((bridge/"runner").iterdir()))
                extra=bridge/"payload/extra";extra.write_bytes(b"UNTRUSTED")
                with self.assertRaises(ValueError):CI.bridge_cleanup(*arguments,platform="posix")
                self.assertEqual(extra.read_bytes(),b"UNTRUSTED");extra.unlink()
                outside=root/"outside-hardlink";os.link(bridge/"payload/contract.py",outside)
                with self.assertRaises(ValueError):CI.bridge_cleanup(*arguments,platform="posix")
                outside.unlink()
                changed=bridge/"payload/contract.py";expected=changed.read_bytes();changed.write_bytes(b"CHANGED")
                with self.assertRaises(ValueError):CI.bridge_cleanup(*arguments,platform="posix")
                changed.write_bytes(expected)
                moved=root/"moved-contract";os.rename(bridge/"payload/contract.py",moved)
                with self.assertRaises(ValueError):CI.bridge_cleanup(*arguments,platform="posix")
                os.rename(moved,bridge/"payload/contract.py")
                with mock.patch.object(CI.os,"unlink",side_effect=OSError("PRIVATE UNLINK")):
                    with self.assertRaises(OSError):CI.bridge_cleanup(*arguments,platform="posix")
                os.chmod(bridge/"payload",0o700);os.chmod(bridge,0o700);CI.bridge_cleanup(*arguments,platform="posix");CI.bridge_final_absence(*arguments[2:],platform="posix")
                source=pathlib.Path(CI.__file__).read_text(encoding="utf-8")
                for guard in ("os.fchmod(fd,0o444)","os.chmod(payload,0o555)","os.mkdir(runner,0o711)","meta.st_uid==0 and meta.st_gid==0","meta.st_nlink==1"):
                    self.assertIn(guard,source)
            self.assertEqual(sentinel.read_bytes(),b"UNCHANGED")
    def test_uid_bridge_wrong_contract_preexisting_scope_and_partial_copy_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d).resolve();repo=root/"repo";parent=root/"parent";parent.mkdir();rows=[]
            for relative,basename in CI.BRIDGE_FILES:
                path=repo/relative;path.parent.mkdir(parents=True,exist_ok=True);raw=(basename+"\n").encode();path.write_bytes(raw);rows.append({"path":relative,"sha256":CI.hashlib.sha256(raw).hexdigest()})
            contract=repo/"chengwang/deploy/joint-control-plane/source_contract.json";contract.write_text(json.dumps({"paths":rows})+"\n",encoding="utf-8");meta=parent.lstat();arguments=(repo,contract,parent,str(meta.st_dev),str(meta.st_ino),"322","8","b"*32);bridge=parent/(CI.BRIDGE_PREFIX+"322-8-"+"b"*32)
            owned=lambda path,*a,**k:pathlib.Path(path).lstat()
            patches=(mock.patch.object(CI.os,"geteuid",return_value=0,create=True),mock.patch.object(CI.os,"getegid",return_value=0,create=True),mock.patch.object(CI.os,"chown",side_effect=lambda *a:None,create=True),mock.patch.object(CI.os,"fchown",side_effect=lambda *a:None,create=True),mock.patch.object(CI,"_bridge_parent",side_effect=lambda path,*a,**k:pathlib.Path(path)),mock.patch.object(CI,"_bridge_owned",side_effect=owned),mock.patch.object(CI,"_probe_dir_fsync",side_effect=lambda *a:None))
            with contextlib.ExitStack() as stack:
                for patcher in patches:stack.enter_context(patcher)
                def partial(path,raw):pathlib.Path(path).write_bytes(raw[:2]);os.chmod(path,0o600);raise OSError("PRIVATE COPY")
                with mock.patch.object(CI,"_bridge_write",side_effect=partial):
                    with self.assertRaises(OSError):CI.bridge_setup(*arguments,platform="posix")
                self.assertFalse(bridge.exists())
                def wrong_completed(path,raw):pathlib.Path(path).write_bytes(b"WRONG-COMPLETED");os.chmod(path,0o444);raise OSError("PRIVATE POST-SEAL")
                with mock.patch.object(CI,"_bridge_write",side_effect=wrong_completed):
                    with self.assertRaises(ValueError):CI.bridge_setup(*arguments,platform="posix")
                wrong=bridge/"payload/ci_joint_control_plane.py";self.assertTrue(wrong.is_file());self.assertEqual(wrong.read_bytes(),b"WRONG-COMPLETED")
                rows_value,_=CI._bridge_rows(repo,contract);os.chmod(wrong,0o600);CI._bridge_cleanup(bridge,rows_value,partial=True);self.assertFalse(bridge.exists())
                with mock.patch.object(CI.os,"fsync",side_effect=OSError("PRIVATE FILE FSYNC")):
                    with self.assertRaises(OSError):CI.bridge_setup(*arguments,platform="posix")
                self.assertFalse(bridge.exists())
                calls=[]
                def fsync_fault(path):
                    calls.append(path)
                    if len(calls)==1:raise OSError("PRIVATE FSYNC")
                with mock.patch.object(CI,"_probe_dir_fsync",side_effect=fsync_fault):
                    with self.assertRaises(OSError):CI.bridge_setup(*arguments,platform="posix")
                self.assertFalse(bridge.exists())
                bridge.mkdir();sentinel=bridge/"collision";sentinel.write_bytes(b"PRESERVE")
                with self.assertRaises(ValueError):CI.bridge_setup(*arguments,platform="posix")
                self.assertEqual(sentinel.read_bytes(),b"PRESERVE");sentinel.unlink();bridge.rmdir()
                bad=json.loads(contract.read_text());bad["paths"][0]["sha256"]="0"*64;contract.write_text(json.dumps(bad)+"\n")
                with self.assertRaises(ValueError):CI.bridge_payload_digest(repo,contract)
                contract.write_text(json.dumps({"paths":rows})+"\n",encoding="utf-8")
                linked=root/"linked-source";os.link(repo/CI.BRIDGE_FILES[0][0],linked)
                with self.assertRaises(ValueError):CI.bridge_payload_digest(repo,contract)
                linked.unlink()
            with self.assertRaises(ValueError):CI._bridge_parent(parent,str(meta.st_dev+1),str(meta.st_ino),platform="posix")

if __name__=="__main__":unittest.main()
