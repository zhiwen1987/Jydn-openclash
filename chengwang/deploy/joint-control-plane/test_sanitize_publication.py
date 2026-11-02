from __future__ import annotations
import importlib.util,json,os,pathlib,shutil,subprocess,tempfile,unittest
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
            self.assertEqual(value["retainedPrivateFileCount"],1);self.assertEqual(value["failureClassification"],S.C.unknown_failure_classification());self.assertEqual(value["schema"],"chengwang.joint-control-plane-safe-failure/v3");self.assertNotIn("SECRET",out.read_text())
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";staging=root/"staging";private.mkdir();staging.mkdir();put(private/"server.stderr",b"PRIVATE SERVER DIAGNOSTIC")
            S.failure(private,staging/"private-failure-identity.json","PRIVATE_SCENE_FAILED");S.failure(staging,root/"public/failure.json","SCENE_FAILED");value=S.decode(root/"public/failure.json")
            self.assertEqual(value["privateDiagnostics"]["retainedPrivateFileCount"],1);self.assertNotIn("DIAGNOSTIC",(root/"public/failure.json").read_text())
    def test_scene_failure_publishes_only_closed_phase_reason_and_capture(self):
        commit="a"*40
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";private.mkdir();put(private/"runner.stderr",b"Bearer TOKEN https://private.invalid /private/path request-body response-body")
            progress=root/"progress";progress.mkdir()
            for phase in ("NAMESPACE_SETUP","ISOLATION_CHECK","RUNNER_PREPARE","FIXTURE_START"):
                S.C.record_progress(progress,commit,phase,"ENTERED");S.C.record_progress(progress,commit,phase,"COMPLETED")
            S.C.record_progress(progress,commit,"B0","ENTERED")
            error=PermissionError("Bearer TOKEN https://private.invalid /private/path request-body response-body")
            S.C.record_failure_detail(progress,commit,error,"success-fetch-r1","success-approve-r1")
            out=root/"public/failure.json";S.failure(private,out,"SCENE_FAILED",progress,commit);raw=out.read_bytes();value=S.decode(out)
            self.assertLessEqual(len(raw),4096);self.assertEqual(set(value["failureClassification"]),S.C.FAILURE_CLASSIFICATION_KEYS)
            self.assertEqual(value["failureClassification"],{"failurePhase":"B0","lastCompletedPhase":"FIXTURE_START","exceptionType":"PERMISSION_ERROR","failureReasonCode":"UNKNOWN","failedCaptureName":"success-fetch-r1","lastCompletedCaptureName":"success-approve-r1"})
            for secret in (b"Bearer",b"TOKEN",b"private.invalid",b"/private/path",b"request-body",b"response-body"):self.assertNotIn(secret,raw)
            self.assertFalse(value["privateEvidencePublished"]);self.assertEqual(value["status"],"FAIL")
    def test_nested_scene_classification_is_independently_equal_or_rejected(self):
        commit="b"*40
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";staging=root/"staging";progress=staging/"failure-localization.private";private.mkdir();staging.mkdir();progress.mkdir();put(private/"runner.stderr",b"PRIVATE")
            S.C.record_progress(progress,commit,"NAMESPACE_SETUP","ENTERED");S.C.record_progress(progress,commit,"NAMESPACE_SETUP","COMPLETED");S.C.record_progress(progress,commit,"ISOLATION_CHECK","ENTERED")
            nested=staging/"private-failure-identity.json";S.failure(private,nested,"PRIVATE_SCENE_FAILED",progress,commit);value=S.decode(nested);value["failureClassification"]["failurePhase"]="R2";nested.write_bytes(S.canonical(value))
            with self.assertRaises(ValueError):S.failure(staging,root/"public/failure.json","SCENE_FAILED",progress,commit)
            self.assertFalse((root/"public/failure.json").exists())
    def test_invalid_or_missing_progress_never_guesses_from_private_counts(self):
        commit="c"*40
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";progress=root/"progress";private.mkdir();progress.mkdir();put(private/"many-private-files",b"X"*7000);put(progress/"unexpected-private-marker",b"Bearer SECRET")
            out=root/"public/failure.json";S.failure(private,out,"SCENE_FAILED",progress,commit);value=S.decode(out)
            self.assertEqual(value["failureClassification"],S.C.unknown_failure_classification());self.assertNotIn("SECRET",out.read_text());self.assertEqual(value["status"],"FAIL")
    def test_cpu_detailed_failure_is_exactly_one_safe_public_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";stage=root/"stage";private.mkdir();stage.mkdir();secret=b"PRIVATE CPU SECRET MATERIAL";put(private/"go.log",secret)
            S.failure(private,stage/"cpu-failure.json","CPU_FAILED");S.cpu_publish(stage,root/"cpu-public");published=root/"cpu-public/cpu-failure.json"
            self.assertTrue(published.is_file());self.assertEqual([p.name for p in (root/"cpu-public").iterdir()],["cpu-failure.json"]);self.assertNotIn(secret,published.read_bytes())
    def test_cpu_cap_rejection_has_constant_fallback_without_private_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";stage=root/"stage";private.mkdir();stage.mkdir();oversized=private/"go.log"
            secret=b"PRIVATE OVERSIZED CPU SECRET"
            with oversized.open("wb") as f:f.write(secret);f.seek(256<<20);f.write(b"X")
            with self.assertRaises(ValueError):S.failure(private,stage/"cpu-failure.json","CPU_FAILED")
            S.cpu_fallback(stage/"cpu-diagnostic-unavailable.json");S.cpu_publish(stage,root/"cpu-public");data=(root/"cpu-public/cpu-diagnostic-unavailable.json").read_bytes();value=S.decode_bytes(data)
            self.assertEqual(value,S.CPU_DIAGNOSTIC);self.assertNotIn(secret,data);self.assertNotIn("retainedPrivate",data.decode());self.assertNotIn("sha",data.decode().lower());self.assertEqual(len(data),len(S.canonical(S.CPU_DIAGNOSTIC)))
    def test_cpu_fallback_io_and_preexisting_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);private=root/"private";stage=root/"stage";private.mkdir();stage.mkdir();put(private/"go.log",b"PRIVATE")
            def partial_then_fail(path,data):pathlib.Path(path).write_bytes(b"PARTIAL");raise OSError("injected-detailed-write")
            with mock.patch.object(S,"write",side_effect=partial_then_fail):
                with self.assertRaises(OSError):S.failure(private,stage/"cpu-failure.json","CPU_FAILED")
            S.cpu_fallback(stage/"cpu-diagnostic-unavailable.json")
            with self.assertRaises(ValueError):S.cpu_publish(stage,root/"cpu-public")
            self.assertFalse((root/"cpu-public").exists())
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);stage=root/"stage";stage.mkdir();out=stage/"cpu-diagnostic-unavailable.json"
            with mock.patch.object(S,"write",side_effect=OSError("injected")):
                with self.assertRaises(OSError):S.cpu_fallback(out)
            self.assertFalse(out.exists())
            put(out,b"PREEXISTING PRIVATE CONFLICT")
            with self.assertRaises(FileExistsError):S.cpu_fallback(out)
            with self.assertRaises((ValueError,json.JSONDecodeError)):S.cpu_publish(stage,root/"cpu-public")
            self.assertFalse((root/"cpu-public").exists())
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);stage=root/"stage";stage.mkdir();S.cpu_fallback(stage/"cpu-diagnostic-unavailable.json")
            with mock.patch.object(S,"write",side_effect=OSError("injected-publish-write")):
                with self.assertRaises(OSError):S.cpu_publish(stage,root/"cpu-public")
            self.assertFalse((root/"cpu-public").exists());self.assertEqual(list(root.glob(".cpu-public.pending-*")),[])
            conflict=root/"preexisting-public";conflict.mkdir();put(conflict/"sentinel",b"UNCHANGED")
            with self.assertRaises(ValueError):S.cpu_publish(stage,conflict)
            self.assertEqual((conflict/"sentinel").read_bytes(),b"UNCHANGED")
    def test_cpu_publication_rejects_missing_extra_and_unallowlisted_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);stage=root/"stage";stage.mkdir()
            with self.assertRaises(ValueError):S.cpu_publish(stage,root/"missing-public")
            put(stage/"unexpected.json",{"status":"FAIL"})
            with self.assertRaises(ValueError):S.cpu_publish(stage,root/"unexpected-public")
            (stage/"unexpected.json").unlink();S.cpu_fallback(stage/"cpu-diagnostic-unavailable.json");put(stage/"extra.json",{"status":"FAIL"})
            with self.assertRaises(ValueError):S.cpu_publish(stage,root/"extra-public")
            self.assertFalse((root/"missing-public").exists());self.assertFalse((root/"unexpected-public").exists());self.assertFalse((root/"extra-public").exists())
    def test_workflow_stages_then_publishes_and_missing_artifact_is_error(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text()
        block=workflow.split("      - name: CPU contracts and Go suite",1)[1].split("      - name: Build once and acquire immutable source",1)[0]
        self.assertIn('--output "$stage/cpu-failure.json"',block);self.assertIn("cpu-fallback --output",block);self.assertIn('cpu-publish --input "$stage" --output "$public"',block)
        self.assertIn("if-no-files-found: error",block);self.assertNotIn("if-no-files-found: warn",block);self.assertNotIn('--output "$public/cpu-',block);self.assertIn("steps.cpu.outputs.publication_ready == 'true'",block)
    def test_workflow_shell_preexisting_paths_stop_before_units_or_go_and_disable_upload(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text();section=workflow.split("      - name: CPU contracts and Go suite",1)[1].split("      - name: Preserve bounded CPU publication only",1)[0]
        run=section.split("        run: |\n",1)[1];shell="\n".join(line[10:] if line.startswith("          ") else line for line in run.splitlines())+"\n"
        bash=shutil.which("bash") or (r"C:\Program Files\Git\bin\bash.exe" if pathlib.Path(r"C:\Program Files\Git\bin\bash.exe").is_file() else None)
        self.assertIsNotNone(bash)
        probe='python3(){ printf "python3\\n" >>"$CALL_MARKER"; return 99; }; go(){ printf "go\\n" >>"$CALL_MARKER"; return 99; };\n'
        for kind in ("private","stage","public"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                root=pathlib.Path(d);runner=root/"runner";runner.mkdir();conflict=runner/("joint-control-plane-cpu-"+kind);conflict.mkdir();sentinel=conflict/"sentinel";sentinel.write_bytes(b"UNVALIDATED PREEXISTING BYTES")
                output=root/"github-output";marker=root/"commands-called";env=os.environ.copy();env.update({"RUNNER_TEMP":runner.as_posix(),"GITHUB_OUTPUT":output.as_posix(),"CALL_MARKER":marker.as_posix()})
                result=subprocess.run([str(bash),"-c",probe+shell],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
                self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists());self.assertFalse(output.exists());self.assertEqual(sentinel.read_bytes(),b"UNVALIDATED PREEXISTING BYTES")
    def test_workflow_shell_critical_io_failures_are_nonzero_and_not_ready(self):
        workflow=(HERE.parents[2]/".github/workflows/chengwang-joint-control-plane.yml").read_text();section=workflow.split("      - name: CPU contracts and Go suite",1)[1].split("      - name: Preserve bounded CPU publication only",1)[0]
        run=section.split("        run: |\n",1)[1];shell="\n".join(line[10:] if line.startswith("          ") else line for line in run.splitlines())+"\n"
        bash=shutil.which("bash") or (r"C:\Program Files\Git\bin\bash.exe" if pathlib.Path(r"C:\Program Files\Git\bin\bash.exe").is_file() else None);self.assertIsNotNone(bash)
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);runner=root/"runner";runner.mkdir();marker=root/"commands-called";output=root/"github-output";env=os.environ.copy();env.update({"RUNNER_TEMP":runner.as_posix(),"GITHUB_OUTPUT":output.as_posix(),"CALL_MARKER":marker.as_posix()})
            probe='install(){ command printf "install\\n" >>"$CALL_MARKER"; return 73; }; python3(){ command printf "python3\\n" >>"$CALL_MARKER"; return 0; }; go(){ command printf "go\\n" >>"$CALL_MARKER"; return 0; };\n'
            result=subprocess.run([str(bash),"-c",probe+shell],cwd=HERE.parents[2],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertNotEqual(result.returncode,0);self.assertEqual(marker.read_text().splitlines(),["install"]);self.assertFalse(output.exists())
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);runner=root/"runner";runner.mkdir();marker=root/"commands-called";output=root/"github-output";env=os.environ.copy();env.update({"RUNNER_TEMP":runner.as_posix(),"GITHUB_OUTPUT":output.as_posix(),"CALL_MARKER":marker.as_posix()})
            probe='install(){ mkdir -p "$4" "$5"; }; python3(){ command printf "python3 %s\\n" "$*" >>"$CALL_MARKER"; return 0; }; go(){ command printf "go\\n" >>"$CALL_MARKER"; return 0; }; printf(){ builtin printf "$@"; rc=$?; if test "$#" -ge 2 && test "$2" = 0; then return 74; fi; return "$rc"; };\n'
            result=subprocess.run([str(bash),"-c",probe+shell],cwd=HERE.parents[2],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False);calls=marker.read_text()
            self.assertNotEqual(result.returncode,0);self.assertIn("ci_joint_control_plane.py units",calls);self.assertIn("go",calls);self.assertNotIn("sanitize_publication.py",calls);self.assertFalse(output.exists())
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);runner=root/"runner";runner.mkdir();marker=root/"commands-called";output=root/"github-output";output.mkdir();env=os.environ.copy();env.update({"RUNNER_TEMP":runner.as_posix(),"GITHUB_OUTPUT":output.as_posix(),"CALL_MARKER":marker.as_posix()})
            probe=r'''install(){ mkdir -p "$4" "$5"; }
            python3(){
              command printf 'python3 %s\n' "$*" >>"$CALL_MARKER"
              args="$*"; out=''; while test "$#" -gt 0; do if test "$1" = --output; then out="$2"; break; fi; shift; done
              case "$args" in
                *ci_joint_control_plane.py*units*) mkdir -p "${out%/*}"; command printf '{}\n' >"$out" ;;
                *sanitize_publication.py*cpu-publish*) mkdir -p "$out"; command printf 'SAFE\n' >"$out/safe.json" ;;
                *sanitize_publication.py*cpu*) mkdir -p "${out%/*}"; command printf 'SAFE\n' >"$out" ;;
                *) return 75 ;;
              esac
              return 0
            }
            go(){ command printf 'go\n' >>"$CALL_MARKER"; return 0; }
            '''
            result=subprocess.run([str(bash),"-c",probe+shell],cwd=HERE.parents[2],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False);calls=marker.read_text()
            self.assertNotEqual(result.returncode,0);self.assertIn("cpu-publish",calls);self.assertTrue((runner/"joint-control-plane-cpu-public/safe.json").is_file());self.assertEqual(list(output.iterdir()),[])
if __name__=="__main__":unittest.main()
