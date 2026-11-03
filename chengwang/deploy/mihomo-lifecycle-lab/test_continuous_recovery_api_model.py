import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
_REAL_FSTAT=os.fstat
EXPECTED_CASE_CONTRACT=(
  ('INITIAL_HEAD','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/head',200),
  ('FIRST_CANDIDATES','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/candidates',200),
  ('FIRST_UNKNOWN_CREATE','Admin','CASE_ACTOR_ADMIN','POST','/api/v1/lab/mihomo/deployments',201),
  ('FIRST_UNKNOWN_APPROVE','Approver','CASE_ACTOR_APPROVER','POST',None,200),
  ('FIRST_UNKNOWN_EXECUTE','Admin','CASE_ACTOR_ADMIN','POST',None,200),
  ('FIRST_UNKNOWN_INSPECT','Viewer','CASE_ACTOR_VIEWER','GET',None,200),
  ('FIRST_UNKNOWN_HEAD','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/head',200),
  ('FIRST_RECOVERY_CREATE','Admin','CASE_ACTOR_ADMIN','POST','/api/v1/lab/mihomo/recoveries',201),
  ('FIRST_RECOVERY_INSPECT_PLANNED','Auditor','CASE_ACTOR_AUDITOR','GET',None,200),
  ('FIRST_RECOVERY_APPROVE','Approver','CASE_ACTOR_APPROVER','POST',None,200),
  ('FIRST_RECOVERY_EXECUTE','Admin','CASE_ACTOR_ADMIN','POST',None,200),
  ('FIRST_RECOVERY_INSPECT_COMPLETED','Auditor','CASE_ACTOR_AUDITOR','GET',None,200),
  ('FIRST_RECOVERED_HEAD','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/head',200),
  ('ACK_CANDIDATES','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/candidates',200),
  ('ORDINARY_ACK_CREATE','Admin','CASE_ACTOR_ADMIN','POST','/api/v1/lab/mihomo/deployments',201),
  ('ORDINARY_ACK_APPROVE','Approver','CASE_ACTOR_APPROVER','POST',None,200),
  ('ORDINARY_ACK_EXECUTE','Admin','CASE_ACTOR_ADMIN','POST',None,200),
  ('ORDINARY_ACK_INSPECT','Viewer','CASE_ACTOR_VIEWER','GET',None,200),
  ('ORDINARY_ACK_HEAD','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/head',200),
  ('SECOND_CANDIDATES','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/candidates',200),
  ('SECOND_UNKNOWN_CREATE','Admin','CASE_ACTOR_ADMIN','POST','/api/v1/lab/mihomo/deployments',201),
  ('SECOND_UNKNOWN_APPROVE','Approver','CASE_ACTOR_APPROVER','POST',None,200),
  ('SECOND_UNKNOWN_EXECUTE','Admin','CASE_ACTOR_ADMIN','POST',None,200),
  ('SECOND_UNKNOWN_INSPECT','Viewer','CASE_ACTOR_VIEWER','GET',None,200),
  ('SECOND_UNKNOWN_HEAD','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/head',200),
  ('SECOND_RECOVERY_CREATE','Admin','CASE_ACTOR_ADMIN','POST','/api/v1/lab/mihomo/recoveries',201),
  ('SECOND_RECOVERY_INSPECT_PLANNED','Auditor','CASE_ACTOR_AUDITOR','GET',None,200),
  ('SECOND_RECOVERY_APPROVE','Approver','CASE_ACTOR_APPROVER','POST',None,200),
  ('SECOND_RECOVERY_EXECUTE','Admin','CASE_ACTOR_ADMIN','POST',None,200),
  ('SECOND_RECOVERY_INSPECT_COMPLETED','Auditor','CASE_ACTOR_AUDITOR','GET',None,200),
  ('SECOND_RECOVERED_HEAD','Viewer','CASE_ACTOR_VIEWER','GET','/api/v1/lab/mihomo/head',200))

class StatView:
    def __init__(self,value,uid,gid): self.value=value; self.st_uid=uid; self.st_gid=gid
    def __getattr__(self,name): return getattr(self.value,name)

def root_fstat(fd): return StatView(_REAL_FSTAT(fd),0,0)
def nonroot_fstat(fd): return StatView(_REAL_FSTAT(fd),10001,10001)

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class Shared:
    ROOT_ENV={}
    def __init__(self): self.writes=[]
    def unprivileged(self,argv,environment): return list(argv)
    def namespace_values(self): return {'networkNamespace':'net:[2]','mountNamespace':'mnt:[2]','pidNamespace':'pid:[2]'}
    def custody(self,consumed): return consumed['before'],None,consumed['directory']
    def write_new(self,path,body,mode): self.writes.append((path,body,mode))

class Adapter:
    def __init__(self,root):
        self.ROOT_PRIVATE=Path(root); self.PATHS={'module':'/tmp/mihomo-apply-source','goRoot':'/tmp/mihomo-apply-go'}
        self._shared=Shared()
    def shared(self): return self._shared
    def prepare_namespace(self,*args):
        return {'commit':'a'*40,'environment':{},'pending':[],'inputBefore':b'before','originalDirectory':'directory',
          'consumed':{'before':b'before','directory':'directory'}}
    def unchanged_public(self,state): pass
    def sync_output(self,state): pass

class Process:
    def __init__(self,timeout=False): self.pid=4242; self.returncode=None; self.timeout=timeout; self.waits=0
    def wait(self,timeout):
        self.waits+=1
        if self.timeout and self.waits==1: raise subprocess.TimeoutExpired(['model'],timeout)
        self.returncode=-9 if self.timeout else 0; return self.returncode

class ContinuousRecoveryAPIModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader=load('continuous_reader','check_continuous_recovery_api.py')
        cls.verifier_failure=load('continuous_verifier_failure','check_continuous_recovery_verifier_failure.py')
        cls.worker=load('continuous_worker','continuous_recovery_api_worker.py')
        cls.model_outcomes=load('continuous_model_outcomes','continuous_recovery_model_outcomes.py')

    def test_fresh_readback_requires_successful_api_producer(self):
        workflow=(HERE.parents[2]/'.github/workflows/chengwang-mihomo-continuous-recovery-api.yml').read_text(encoding='utf8')
        marker='\n  continuous-recovery-fresh:\n';self.assertEqual(workflow.count(marker),1);fresh=workflow.split(marker,1)[1]
        needs='    needs: [development-only, continuous-recovery-api]\n'
        gate="    if: ${{ !cancelled() && needs.development-only.result == 'success' && needs.continuous-recovery-api.result == 'success' }}\n"
        old="    if: ${{ !cancelled() && needs.development-only.result == 'success' }}\n"
        producer='          name: mihomo-continuous-recovery-api-safe-${{ github.run_id }}-${{ github.run_attempt }}\n'
        mixed='          name: mihomo-continuous-recovery-api-originals-${{ github.run_id }}-${{ github.run_attempt }}\n'
        self.assertEqual(fresh.count(needs),1);self.assertEqual(fresh.count(gate),1);self.assertNotIn(old,fresh)
        self.assertEqual(fresh.count(producer),1);self.assertNotIn(mixed,fresh)
        self.assertIn('--verify-safe',fresh);self.assertNotIn('verification.stderr',fresh);self.assertNotIn('acquisition',fresh)
        self.assertLess(fresh.index(needs),fresh.index(gate));self.assertLess(fresh.index(gate),fresh.index(producer))

    def test_contract_excludes_old_fault_tags_and_has_independent_capture(self):
        contract=json.loads((HERE/'continuous_recovery_api_contract.json').read_bytes())
        self.assertEqual(contract['schema'],'chengwang.mihomo-continuous-recovery-contract/v2')
        self.assertEqual(contract['reportSchema'],'chengwang.mihomo-continuous-recovery-http-experiment/v3')
        self.assertEqual(contract['faultObservationSchema'],'chengwang.mihomo-continuous-recovery-response-loss/v2')
        self.assertEqual(contract['goTimeoutSeconds'],210); self.assertEqual(contract['outerGoTimeoutSeconds'],240)
        self.assertFalse(set(contract['exactTags']) & set(contract['forbiddenTags']))
        self.assertEqual(contract['safeArtifactSchema'],self.reader.SAFE_SCHEMA)
        self.assertEqual(contract['safeEvidenceFiles'],list(self.reader.SAFE_EVIDENCE))
        self.assertEqual((contract['safeEvidenceFileCount'],contract['safeVerificationMaxBytes'],contract['safeArtifactMaxBytes']),(42,16<<10,16<<20))
        lifecycle=(HERE.parents[1]/'internal/mihomodeploy/lifecycle.go').read_text(encoding='utf8')
        actual=re.search(r'^const lifecycleSchemaV2 = "([^"]+)"$',lifecycle,re.M)
        self.assertIsNotNone(actual); self.assertEqual(actual.group(1),self.reader.WAL_SCHEMA)
        harness=(HERE.parents[1]/'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go').read_text(encoding='utf8')
        fault_source=(HERE.parents[1]/'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go').read_text(encoding='utf8')
        self.assertEqual(set(re.findall(r'chengwang\.mihomo-continuous-recovery-http-experiment/v\d+',harness)),{contract['reportSchema']})
        self.assertIn('const labContinuousRecoveryFaultSchema = "'+contract['faultObservationSchema']+'"',fault_source)
        self.assertIn('initial.WALSchema != "'+self.reader.WAL_SCHEMA+'"',harness)
        self.assertNotIn('chengwang.mihomo-lifecycle/v2',harness)

        self.assertIn('h.call(stage+"_INSPECT", http.MethodGet',harness)
        kernel=(HERE.parents[1]/'internal/mihomodeploy/lab_kernel_linux.go').read_text(encoding='utf8')
        observer=(HERE.parents[1]/'internal/mihomodeploy/lab_native_recovery_observer_linux.go').read_text(encoding='utf8')
        observer_default=(HERE.parents[1]/'internal/mihomodeploy/lab_native_recovery_observer_default.go').read_text(encoding='utf8')
        for origin,line in (('Cancel','e := p.Kill()'),('Identity','killErr := c.process.Kill()'),('Stop','e = proc.Kill()')):
            attempt='labNativeRecoveryObserve'+origin+'KillAttempt(c)'; returned='labNativeRecoveryObserve'+origin+'KillReturn(c)'
            self.assertEqual(kernel.count(attempt),1); self.assertEqual(kernel.count(returned),1)
            self.assertLess(kernel.index(attempt),kernel.index(line)); self.assertLess(kernel.index(line),kernel.index(returned))
            self.assertIn('func labNativeRecoveryObserve'+origin+'KillAttempt(core *ownedLabKernelCore)',observer)
            self.assertIn('func labNativeRecoveryObserve'+origin+'KillReturn(core *ownedLabKernelCore)',observer)
            self.assertIn('func labNativeRecoveryObserve'+origin+'KillAttempt(*ownedLabKernelCore)',observer_default)
            self.assertIn('func labNativeRecoveryObserve'+origin+'KillReturn(*ownedLabKernelCore)',observer_default)
        self.assertNotIn('labNativeRecoveryObserve(c, "KERNEL_OS_KILL_',kernel)
        self.assertNotIn('labNativeRecoveryObserveRaw',kernel)
        self.assertEqual(observer.count('labNativeRecoveryObserveRaw('),8)
        self.assertIn('events := make([]labNativeRecoveryCall, len(c.events))',observer)
        self.assertIn('func labNativeRecoveryReadContinuousCalls() ([]labNativeRecoveryCall, bool)',observer)
        self.assertNotRegex(observer,r'type labNativeRecoveryCall struct \{[^}]*[Oo]rigin')
        self.assertIn('labNativeRecoveryReadContinuousCalls()',
          fault_source)
        for path in ('internal/mihomodeploy/lab_kernel_linux.go','internal/mihomodeploy/lab_native_recovery_observer_default.go',
                     'internal/mihomodeploy/lab_native_recovery_observer_linux.go'):
            self.assertIn(path,self.reader.FMT); self.assertIn(path,self.worker.FMT)
            full='chengwang/'+path; self.assertIn(full,self.reader.DELIVERY); self.assertIn(full,self.worker.DELIVERY)
        self.assertEqual(self.reader.FMT,self.worker.FMT); self.assertEqual(len(self.reader.FMT),19)
        self.assertEqual(self.reader.DELIVERY,self.worker.DELIVERY); self.assertEqual(len(self.reader.DELIVERY),33)
        self.assertNotRegex(harness,r'h\.call\([^\n]*"(?:viewer|operator|approver|auditor|admin)"')
        self.assertEqual(len(re.findall(r'h\.call\(',harness)),11)
        deployment_inspects=[row for row in self.reader.HTTP_CASES if row[0] in
          ('FIRST_UNKNOWN_INSPECT','ORDINARY_ACK_INSPECT','SECOND_UNKNOWN_INSPECT')]
        recovery_inspects=[row for row in self.reader.HTTP_CASES if '_RECOVERY_INSPECT_' in row[0]]
        self.assertEqual(len(deployment_inspects),3); self.assertTrue(all(row[1]=='CASE_ACTOR_VIEWER' for row in deployment_inspects))
        self.assertEqual(len(recovery_inspects),4); self.assertTrue(all(row[1]=='CASE_ACTOR_AUDITOR' for row in recovery_inspects))
        expected_public=tuple((case,actor,method,path,status) for case,_,actor,method,path,status in EXPECTED_CASE_CONTRACT)
        self.assertEqual(self.reader.HTTP_CASES,expected_public)
        self.assertEqual(self.worker.HTTP_PUBLIC_CASES,expected_public)
        self.assertEqual(self.worker.BOUNDARY,self.reader.BOUNDARY)
        self.assertEqual(frozenset(row[0] for row in expected_public),self.worker.HTTP_DIAGNOSTIC_CASES)
        coordinated=list(expected_public)
        coordinated[2]=(coordinated[2][0],*expected_public[3][1:])
        coordinated[3]=(coordinated[3][0],*expected_public[2][1:])
        self.assertNotEqual(tuple(coordinated),expected_public)
        self.assertEqual({actor:sum(row[1]==actor for row in self.reader.HTTP_CASES) for actor in
          ('CASE_ACTOR_VIEWER','CASE_ACTOR_ADMIN','CASE_ACTOR_APPROVER','CASE_ACTOR_AUDITOR')},
          {'CASE_ACTOR_VIEWER':12,'CASE_ACTOR_ADMIN':10,'CASE_ACTOR_APPROVER':5,'CASE_ACTOR_AUDITOR':4})
        self.assertEqual(sum(row[4]==201 for row in self.reader.HTTP_CASES),5)
        self.assertEqual(sum(row[4]==200 for row in self.reader.HTTP_CASES),26)
        authz=(HERE.parents[1]/'internal/authz/model.go').read_text(encoding='utf8')
        role_pairs=re.findall(r'Role(Viewer|Operator|Approver|Auditor|Admin)\s+Role\s*=\s*"([^"]+)"',authz)
        self.assertEqual({value.encode():name.upper() for name,value in role_pairs},self.worker.PUBLIC_IDENTITY_ROLE_LABELS)
        roles={name:value for name,value in role_pairs}
        actor_roles={'CASE_ACTOR_VIEWER':'Viewer','CASE_ACTOR_ADMIN':'Admin',
          'CASE_ACTOR_APPROVER':'Approver','CASE_ACTOR_AUDITOR':'Auditor'}
        def case_identity(source):
            identity=re.search(r'func continuousRecoveryCaseIdentity\(name string\).*?\n}',source,re.S)
            self.assertIsNotNone(identity); observed={}
            for cases,role,actor in re.findall(r'case (.*?):\n\s*return authz\.Role(\w+), continuousRecoveryCaseActor(\w+), true',identity.group(0),re.S):
                for case in re.findall(r'"([A-Z0-9_]+)"',cases): observed[case]=(role,'CASE_ACTOR_'+actor.upper())
            return identity.group(0),observed
        identity,observed=case_identity(harness)
        expected={case:(role,actor) for case,role,actor,_,_,_ in EXPECTED_CASE_CONTRACT}
        self.assertEqual(observed,expected)
        coordinated_selector=dict(expected)
        coordinated_selector['FIRST_UNKNOWN_CREATE'],coordinated_selector['FIRST_UNKNOWN_APPROVE']=(
          coordinated_selector['FIRST_UNKNOWN_APPROVE'],coordinated_selector['FIRST_UNKNOWN_CREATE'])
        self.assertNotEqual(coordinated_selector,expected)
        drift=harness.replace('return authz.RoleViewer, continuousRecoveryCaseActorViewer, true',
          'return authz.RoleAdmin, continuousRecoveryCaseActorViewer, true',1)
        self.assertNotEqual(case_identity(drift)[1],expected)
        self.assertEqual({role:roles[role] for role in set(actor_roles.values())},
          {'Viewer':'viewer','Admin':'admin','Approver':'approver','Auditor':'auditor'})
        self.assertIn('role, actor, ok := continuousRecoveryCaseIdentity(name)',harness)
        self.assertLess(harness.index('role, actor, ok := continuousRecoveryCaseIdentity(name)'),harness.index('token := h.tokens[string(role)]'))
        self.assertNotRegex(identity,r'(?i)(toupper|tolower|equalfold|sprintf|format|encode)')
        self.assertNotIn('json:"role"',harness); self.assertIn('json:"caseActor"',harness)
        policy_test=(HERE.parents[1]/'internal/authz/policy_test.go').read_text(encoding='utf8')
        viewer=re.search(r'RoleViewer:\s*\{([^}]*)\}',policy_test,re.S); auditor=re.search(r'RoleAuditor:\s*\{([^}]*)\}',policy_test,re.S)
        self.assertIsNotNone(viewer); self.assertIsNotNone(auditor)
        self.assertIn('ActionReadResource: true',viewer.group(1)); self.assertNotIn('ActionReadResource',auditor.group(1))
        policy=(HERE.parents[1]/'internal/authz/policy.go').read_text(encoding='utf8')
        self.assertIn('case RoleViewer:\n\t\t\tif action == ActionReadResource',policy)
        self.assertIn('case RoleApprover:\n\t\t\tif action == ActionReadResource || action == ActionReadEvidence || action == ActionApproveOperation',policy)
        self.assertIn('case RoleAdmin:\n\t\t\tswitch action {\n\t\t\tcase ActionReadResource, ActionReadEvidence, ActionCreateDraft,\n\t\t\t\tActionCreateOperation, ActionExecuteOperation',policy)
        auditor_source=re.search(r'case RoleAuditor:(.*?)case RoleAdmin:',policy,re.S)
        self.assertIsNotNone(auditor_source); self.assertNotIn('ActionReadResource',auditor_source.group(1))
        recovery_policy=(HERE.parents[1]/'internal/authz/lab_recovery.go').read_text(encoding='utf8')
        recovery_read=re.search(r'case ActionReadLabRecovery:(.*?)case ActionPrepareLabRecovery',recovery_policy,re.S)
        self.assertIsNotNone(recovery_read); self.assertIn('RoleAuditor',recovery_read.group(1))
        lifecycle=(HERE.parents[1]/'internal/mihomodeploy/lab_bootstrap_state.go').read_text(encoding='utf8')
        service=(HERE.parents[1]/'internal/mihomodeploy/lab_service.go').read_text(encoding='utf8')
        self.assertIn('n := next.wire.Active\n\tn.Phase = lifecycleCompletedPhase',lifecycle)
        self.assertIn('if w.Active != nil {\n\t\tx := w.Active.Plan.OperationID\n\t\tv.ActiveOperationID = &x',service)
        self.assertIn('ackHead.ActiveOperationID == nil || *ackHead.ActiveOperationID != acknowledged.OperationID',harness)
        self.assertNotIn('ackHead.ActiveOperationID != nil {',harness)
        plan=(HERE.parents[1]/'internal/mihomodeploy/plan.go').read_text(encoding='utf8')
        runtime=(HERE.parents[1]/'internal/serverruntime/runtime.go').read_text(encoding='utf8')
        environment=re.search(r'LabEnvironment\s*=\s*"([^"]+)"',plan)
        self.assertIsNotNone(environment); self.assertEqual(self.worker.PUBLIC_LAB_ENVIRONMENT,environment.group(1))
        self.assertIn('log.Printf("chengwang listening (mode=%s)", c.Mode)',runtime)
        bound=(HERE.parents[1]/'internal/authn/continuous_bound_credentials_linux.go').read_text(encoding='utf8')
        bound_test=(HERE.parents[1]/'internal/authn/continuous_bound_credentials_linux_test.go').read_text(encoding='utf8')
        store=(HERE.parents[1]/'internal/authn/store.go').read_text(encoding='utf8')
        lab_runtime=(HERE.parents[1]/'internal/serverruntime/mihomo_lab_runtime.go').read_text(encoding='utf8')
        exact_hook=(HERE.parents[1]/'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go').read_text(encoding='utf8')
        default_hook=(HERE.parents[1]/'internal/serverruntime/mihomo_continuous_recovery_hook_default.go').read_text(encoding='utf8')
        credential_test=(HERE.parents[1]/'internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go').read_text(encoding='utf8')
        exact_tag='linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native'
        self.assertEqual(bound.splitlines()[0],'//go:build '+exact_tag)
        self.assertEqual(bound_test.splitlines()[0],'//go:build '+exact_tag)
        self.assertEqual(exact_hook.splitlines()[0],'//go:build '+exact_tag)
        self.assertEqual(credential_test.splitlines()[0],'//go:build '+exact_tag)
        self.assertEqual(harness.splitlines()[0],'//go:build '+exact_tag)
        self.assertIn('!linux || !chengwang_mihomo_service || !chengwang_mihomo_recovery_native || !chengwang_mihomo_recovery_continuous_fault || chengwang_mihomo_faults || chengwang_mihomo_completion_native',default_hook.splitlines()[0])
        self.assertIn('chengwang.mihomo-continuous-recovery-bound-credentials/v2',bound)
        credential_struct=re.search(r'type ContinuousRecoveryBoundCredential struct \{(.*?)\n\}',bound,re.S)
        self.assertIsNotNone(credential_struct)
        self.assertEqual(set(re.findall(r'json:"([A-Za-z]+)',credential_struct.group(1))),
          {'tokenId','tokenHash','binding','disabled','notBefore','expiresAt'})
        self.assertFalse({'principal','tenantId','siteId','objectType','objectId','environment','roles'} &
          set(re.findall(r'json:"([A-Za-z]+)',credential_struct.group(1))))
        rows=re.findall(r'\{tokenID: "([^"]+)", selector: "([^"]+)", principalID: "([^"]+)", role: authz\.Role(\w+)\}',bound)
        self.assertEqual(rows,[
          ('continuous-credential-01','binding-01','continuous-principal-viewer','Viewer'),
          ('continuous-credential-02','binding-02','continuous-principal-operator','Operator'),
          ('continuous-credential-03','binding-03','continuous-principal-approver','Approver'),
          ('continuous-credential-04','binding-04','continuous-principal-auditor','Auditor'),
          ('continuous-credential-05','binding-05','continuous-principal-admin','Admin')])
        self.assertEqual(len({row[0] for row in rows}),5); self.assertEqual(len({row[1] for row in rows}),5)
        self.assertIn('func continuousRecoveryBindings() [5]continuousRecoveryBinding',bound)
        self.assertNotIn('var continuousRecoveryBindings',bound)
        self.assertIn('TenantID: "sub-tenant", SiteID: "sub-site", ObjectType: "mihomo-lab", ObjectID: "local", Environment: "isolated-lab"',bound)
        self.assertEqual(re.search(r'LabObjectType\s*=\s*"([^"]+)"',plan).group(1),'mihomo-lab')
        self.assertIn('return readCredentialSnapshotWithParser(path, strict, afterRead, parseCredentialPayload)',store)
        self.assertIn('initial, err := readCredentialSnapshotWithParser(path, true, nil, parseContinuousRecoveryCredentialPayload)',bound)
        self.assertIn('return readCredentialSnapshotWithParser(candidate, true, nil, parseContinuousRecoveryCredentialPayload)',bound)
        self.assertIn('managerCore.store != initial.store || managerCore.digest != initial.digest',bound)
        self.assertIn('identity, boundManager, boundCredentials, err := claimLabContinuousRecoveryCredentials(c, time.Now().UTC())',runtime)
        self.assertLess(runtime.index('claimLabContinuousRecoveryCredentials(c, time.Now().UTC())'),runtime.index('OpenIdentityStore(c.IdentitiesFile)'))
        self.assertIn('openMihomoLabRuntime(ctx, c, boundManager)',runtime)
        self.assertIn('bindLabContinuousRecoveryHarness(mihomoLab, identity)',runtime)
        self.assertIn('manager: manager, boundCredentials: boundCredentials',lab_runtime)
        self.assertIn('expectedStore, expectedManager := i.credentialStore, i.credentialManager',exact_hook)
        self.assertIn('identity != expectedStore',exact_hook)
        self.assertIn('c.manager == expectedManager && c.boundCredentials',exact_hook)
        self.assertLess(exact_hook.index('validateMihomoLabConfig(c)'),exact_hook.index('authn.OpenContinuousRecoveryCredentialBundle'))
        self.assertIn('!c.MihomoLabEnabled || validateMihomoLabConfig(c) != nil || c.IdentitiesFile != MihomoLabIdentityFile || configured != expected',exact_hook)
        self.assertIn('scope != expected',exact_hook)
        profile_source=re.search(r'profile := authn\.ContinuousRecoveryBoundCredentialFile.*?rawProfile, err := json\.Marshal\(profile\)',harness,re.S)
        self.assertIsNotNone(profile_source)
        self.assertNotIn('authn.Principal',profile_source.group(0)); self.assertNotIn('authn.Identity',profile_source.group(0))
        for path in ('chengwang/internal/authn/continuous_bound_credentials_linux.go',
                     'chengwang/internal/authn/continuous_bound_credentials_linux_test.go','chengwang/internal/authn/store.go',
                     'chengwang/internal/serverruntime/mihomo_lab_runtime.go',
                     'chengwang/internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go'):
            self.assertIn(path,self.reader.DELIVERY); self.assertIn(path,self.worker.DELIVERY)
        source=(HERE/'continuous_recovery_api_worker.py').read_text(encoding='utf8')
        self.assertIn('def capture(',source); self.assertNotIn('a.capture(',source); self.assertNotIn('apply_worker.capture',source)
        self.assertIn("cwd='/tmp/mihomo-apply-source'",source)
        self.assertIn('return outputs,report,forbidden',source)
        self.assertIn("fence_outputs(outputs,forbidden,'REPORT_AND_HTTP_OUTPUTS'",source)
        self.assertIn("fence_outputs(outputs,forbidden,'ALL_GENERIC_AND_REPORT_OUTPUTS'",source)
        self.assertNotIn("row.get('role')",source); self.assertIn("row.get('caseActor')",source)
        self.assertIn("'chengwang.mihomo-continuous-recovery-http-originals/v2'",source)
        self.assertNotIn("'chengwang.mihomo-continuous-recovery-http-originals/v1'",source)
        source_lines=source.splitlines(keepends=True); source_tree=ast.parse(source)
        expected_function_hashes={'encoded_secret_variants':'51a8652f2fc2c1e10f14f53289eb0cf290bd45d1f6dc0d400532fe6b87958192',
          'build_forbidden':'05bea73608b1eb872da922a3465756198001fcebe4f0c8a4c5fb1f916fc5741c',
          'fence_outputs':'91b4a1d6db867001a7cb7e7272f3cec42c200ee64b0dce15182aa850026182a5'}
        actual_function_hashes={node.name:hashlib.sha256(''.join(source_lines[node.lineno-1:node.end_lineno]).encode()).hexdigest()
          for node in source_tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in expected_function_hashes}
        self.assertEqual(actual_function_hashes,expected_function_hashes)
        classes=('IDENTITY_PROFILE','HTTP_TOKENS','TLS_KEY','SERVICE_SECRET','CONFIG_A','CONFIG_B')
        self.assertEqual(self.worker.SECRET_INPUT_CLASSES,frozenset(classes))
        self.assertEqual(self.worker.SECRET_ENCODING_VARIANTS,frozenset(('RAW','B64','B64URL','HEX','JSON_QUOTED')))
        self.assertEqual(self.worker.SECRET_ELEMENT_CLASSES,
          frozenset(('WHOLE_FILE','JSON_SCHEMA','JSON_SCOPE_ENVIRONMENT','JSON_IDENTITY_ROLE','JSON_OTHER_SCALAR')))
        for input_class in classes:
            raw=('model-'+input_class.lower()+'-private-value').encode()
            variants=self.worker.encoded_secret_variants(raw,input_class,'JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE')
            self.assertEqual(len(variants),8)
            for secret,actual_class,element_class,variant,matches_environment,matches_role,public_role in variants:
                for phase in ('REPORT_AND_HTTP_OUTPUTS','ALL_GENERIC_AND_REPORT_OUTPUTS'):
                    with self.subTest(input_class=input_class,variant=variant,phase=phase),self.assertRaises(ValueError) as caught:
                        self.worker.fence_outputs({'clean.json':b'clean','collision.json':b'x'+secret+b'y'},
                          ((secret,actual_class,element_class,variant,matches_environment,matches_role,public_role),),
                          phase,0,0,True,31,'NONE',True)
                    message=str(caught.exception)
                    self.assertNotIn(raw.decode(),message)
                    detail=json.loads(message[message.index('{'):])
                    self.assertEqual(detail,{'phase':phase,'formatExit':0,'goExit':0,
                      'reportObserved':True,'httpCount':31,'reportFailureCode':'NONE','reportOutcomePass':True,
                      'outputLogicalName':'collision.json','secretInputClass':input_class,
                      'secretElementClass':'JSON_OTHER_SCALAR','matchesPublicLabEnvironment':False,
                      'matchesPublicIdentityRole':False,'publicIdentityRole':'NOT_APPLICABLE',
                      'lastHTTPCase':None,'lastHTTPStatusObserved':False,
                      'lastHTTPStatusCode':None,'lastHTTPErrorClass':None,
                      'lastHTTPStateMayHaveChangedObserved':False,'lastHTTPStateMayHaveChanged':None,
                      'recoveryCreateTraceObserved':False,'recoveryCreateTraceBounded':False,
                      'recoveryCreateCount':0,'lastRecoveryCreateStage':None,
                      'encodingVariant':variant})
        for actor in ('CASE_ACTOR_VIEWER','CASE_ACTOR_ADMIN','CASE_ACTOR_APPROVER','CASE_ACTOR_AUDITOR'):
            variants=self.worker.encoded_secret_variants(actor.encode(),'CONFIG_A','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE')
            self.assertEqual(len(variants),8)
            for entry in variants:
                with self.subTest(private_actor=actor,variant=entry[3]),self.assertRaises(ValueError):
                    self.worker.fence_outputs({'continuous-recovery-report.json':b'x'+entry[0]+b'y'},(entry,),
                      'REPORT_AND_HTTP_OUTPUTS',0,0,True,31,'NONE',True)
        public_schema=b'chengwang.mihomo-lab-head-view/v1'
        for entry in self.worker.encoded_secret_variants(public_schema,'IDENTITY_PROFILE','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE'):
            for phase in ('REPORT_AND_HTTP_OUTPUTS','ALL_GENERIC_AND_REPORT_OUTPUTS'):
                with self.subTest(public_constant_secret=entry[3],phase=phase),self.assertRaises(ValueError):
                    self.worker.fence_outputs({'continuous-recovery-report.json':b'x'+entry[0]+b'y'},(entry,),
                      phase,0,0,True,31,'NONE',True)
        self.assertIsNone(self.worker.fence_outputs({'clean.json':b'clean'},
          ((b'model-private-value','CONFIG_A','WHOLE_FILE','RAW',False,False,'NOT_APPLICABLE'),),
          'ALL_GENERIC_AND_REPORT_OUTPUTS',0,0,False,0,'UNKNOWN',False))
        with tempfile.TemporaryDirectory() as td:
            profile=Path(td)/'credentials.json'
            tokens=Path(td)/'http-secrets.private.json'
            object_identities=Path(td)/'object-identities.json'
            object_scopes=Path(td)/'object-scopes.json'
            profile.write_text(json.dumps({'schema':'profile/v1','identities':[
              {'principal':{'roles':['viewer','model-unknown-role'],'allowedScopes':[
                {'environment':self.worker.PUBLIC_LAB_ENVIRONMENT,'role':'approver'},
                {'environment':'different-lab'}]}},
              {'metadata':{'environment':'unknown-nested-environment','schema':'nested/schema','roles':['viewer']}}]}),encoding='utf8')
            tokens.write_text(json.dumps({'environment':self.worker.PUBLIC_LAB_ENVIRONMENT,'roles':['viewer']}),encoding='utf8')
            object_identities.write_text(json.dumps({'identities':{'*':{'principal':{'allowedScopes':[
              {'environment':self.worker.PUBLIC_LAB_ENVIRONMENT}]}}}}),encoding='utf8')
            object_scopes.write_text(json.dumps({'identities':[{'principal':{'allowedScopes':{'*':
              {'environment':self.worker.PUBLIC_LAB_ENVIRONMENT}}}}]}),encoding='utf8')
            with mock.patch.object(self.worker,'SECRET_INPUTS',
              (('IDENTITY_PROFILE',profile),('HTTP_TOKENS',tokens),
               ('IDENTITY_PROFILE',object_identities),('IDENTITY_PROFILE',object_scopes))):
                classified=self.worker.build_forbidden()
            self.assertEqual(len(classified),136)
            raw_entries={(secret,input_class,element,matches_environment,matches_role,public_role)
              for secret,input_class,element,variant,matches_environment,matches_role,public_role in classified if variant=='RAW'}
            self.assertIn((b'profile/v1','IDENTITY_PROFILE','JSON_SCHEMA',False,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((self.worker.PUBLIC_LAB_ENVIRONMENT.encode(),'IDENTITY_PROFILE','JSON_SCOPE_ENVIRONMENT',True,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((b'different-lab','IDENTITY_PROFILE','JSON_SCOPE_ENVIRONMENT',False,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((b'viewer','IDENTITY_PROFILE','JSON_IDENTITY_ROLE',False,True,'VIEWER'),raw_entries)
            self.assertIn((b'model-unknown-role','IDENTITY_PROFILE','JSON_IDENTITY_ROLE',False,False,'UNKNOWN'),raw_entries)
            self.assertIn((b'unknown-nested-environment','IDENTITY_PROFILE','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((b'nested/schema','IDENTITY_PROFILE','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((self.worker.PUBLIC_LAB_ENVIRONMENT.encode(),'HTTP_TOKENS','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((b'viewer','HTTP_TOKENS','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE'),raw_entries)
            self.assertIn((b'approver','IDENTITY_PROFILE','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE'),raw_entries)
            object_marker_decoys=[entry for entry in classified if entry==(
              self.worker.PUBLIC_LAB_ENVIRONMENT.encode(),'IDENTITY_PROFILE','JSON_OTHER_SCALAR','RAW',False,False,'NOT_APPLICABLE')]
            self.assertEqual(len(object_marker_decoys),2)
            role_path_decoys=[entry for entry in classified if entry==(
              b'viewer','IDENTITY_PROFILE','JSON_OTHER_SCALAR','RAW',False,False,'NOT_APPLICABLE')]
            self.assertEqual(len(role_path_decoys),1)
            for phase in ('REPORT_AND_HTTP_OUTPUTS','ALL_GENERIC_AND_REPORT_OUTPUTS'):
                with self.subTest(public_environment_phase=phase),self.assertRaises(ValueError) as caught:
                    self.worker.fence_outputs({'continuous.json':b'mode='+self.worker.PUBLIC_LAB_ENVIRONMENT.encode()},
                      ((self.worker.PUBLIC_LAB_ENVIRONMENT.encode(),'IDENTITY_PROFILE','JSON_SCOPE_ENVIRONMENT','RAW',
                        True,False,'NOT_APPLICABLE'),),
                      phase,0,1,True,0,'INITIAL_STATE',False)
                detail=json.loads(str(caught.exception)[str(caught.exception).index('{'):])
                self.assertEqual(detail['secretElementClass'],'JSON_SCOPE_ENVIRONMENT')
                self.assertIs(detail['matchesPublicLabEnvironment'],True)
            role_variant=[entry for entry in classified if entry[0]==b'"viewer"' and entry[1]=='IDENTITY_PROFILE' and
              entry[2]=='JSON_IDENTITY_ROLE' and entry[3]=='JSON_QUOTED'][0]
            with self.assertRaises(ValueError) as caught:
                self.worker.fence_outputs({'continuous-recovery-report.json':b'role='+role_variant[0]},(role_variant,),
                  'REPORT_AND_HTTP_OUTPUTS',0,1,True,6,'HTTP_RESULT',False,'FIRST_UNKNOWN_INSPECT',True,403,'NONE')
            detail=json.loads(str(caught.exception)[str(caught.exception).index('{'):])
            self.assertEqual(detail['secretElementClass'],'JSON_IDENTITY_ROLE')
            self.assertIs(detail['matchesPublicIdentityRole'],True); self.assertEqual(detail['publicIdentityRole'],'VIEWER')
            self.assertEqual(detail['lastHTTPCase'],'FIRST_UNKNOWN_INSPECT'); self.assertIs(detail['lastHTTPStatusObserved'],True)
            self.assertEqual(detail['lastHTTPStatusCode'],403); self.assertEqual(detail['lastHTTPErrorClass'],'NONE')
        diagnostic_secret=b'CONFIG_B'
        with self.assertRaisesRegex(ValueError,r'^isolated continuous Recovery capture rejected$'):
            self.worker.fence_outputs({'collision.json':diagnostic_secret},
              ((diagnostic_secret,'CONFIG_B','JSON_OTHER_SCALAR','RAW',False,False,'NOT_APPLICABLE'),),
              'ALL_GENERIC_AND_REPORT_OUTPUTS',1,1,True,31,'NONE',False)
        unknown_code='model-private-unknown-code'
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':unknown_code,'outcome':'FAIL'}),
          ('UNKNOWN',False,None,False,None,None,False,None,False,False,0,None))
        self.assertNotIn(unknown_code,str(self.worker.report_diagnostic_status({'failureCode':unknown_code,'outcome':'FAIL'})))
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL',
          'http':[{'case':'FIRST_UNKNOWN_INSPECT','statusCode':403,'errorClass':'NONE'}]}),
          ('HTTP_RESULT',False,'FIRST_UNKNOWN_INSPECT',True,403,'NONE',False,None,False,False,0,None))
        for invalid in (True,403.0,99,600):
            with self.subTest(invalid_status=invalid):
                self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL',
                  'http':[{'case':'model-unknown-case','statusCode':invalid,'errorClass':'model-unknown-error'}]}),
                  ('HTTP_RESULT',False,'UNKNOWN',False,None,'UNKNOWN',False,None,False,False,0,None))
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL','http':{}}),
          ('HTTP_RESULT',False,'UNKNOWN',False,None,'UNKNOWN',False,None,False,False,0,None))
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL','http':[]}),
          ('HTTP_RESULT',False,None,False,None,None,False,None,False,False,0,None))
        error_body=base64.b64encode(json.dumps({'stateMayHaveChanged':True},separators=(',',':')).encode()).decode()
        traced={'failureCode':'HTTP_RESULT','outcome':'FAIL','http':[{'case':'SECOND_RECOVERY_CREATE','statusCode':503,
          'errorClass':'NONE','responseBodyB64':error_body}],
          'faultAfterCleanup':{'recoveryCreatesBounded':True,'recoveryCreates':[
            {'sequence':1,'stage':'ENTERED'},{'sequence':2,'stage':'ACCEPTED'},
            {'sequence':3,'stage':'ENTERED'},{'sequence':4,'stage':'REJECTED_PLAN'}]}}
        self.assertEqual(self.worker.report_diagnostic_status(traced),
          ('HTTP_RESULT',False,'SECOND_RECOVERY_CREATE',True,503,'NONE',True,True,True,True,4,'REJECTED_PLAN'))
        mutant=copy.deepcopy(traced); mutant['http'][-1]['responseBodyB64']=base64.b64encode(b'{"stateMayHaveChanged":1}').decode()
        mutant['faultAfterCleanup']['recoveryCreates'][-1]['stage']='dynamic-private-error'
        self.assertEqual(self.worker.report_diagnostic_status(mutant),
          ('HTTP_RESULT',False,'SECOND_RECOVERY_CREATE',True,503,'NONE',False,None,True,True,4,'UNKNOWN'))
        known_code=b'HOOK_ARM'
        with self.assertRaisesRegex(ValueError,r'^isolated continuous Recovery capture rejected$'):
            self.worker.fence_outputs({'collision.json':known_code},
              ((known_code,'CONFIG_A','JSON_OTHER_SCALAR','RAW',False,False,'NOT_APPLICABLE'),),
              'ALL_GENERIC_AND_REPORT_OUTPUTS',0,1,True,4,'HOOK_ARM',False)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/'private.json'; secret=b'model-report-absent-private-value'; private.write_bytes(secret)
            adapter=Adapter(root); adapter.EXPORT_ALIAS=root/'export'; adapter.EXPORT_ALIAS.mkdir()
            original_source_file=self.worker.source_file
            def source_file(path,*args,**kwargs):
                if Path(path)==private: return original_source_file(path,*args,**kwargs)
                if Path(path).name=='continuous.stderr': return b'generic-prefix '+secret+b' generic-suffix'
                return b''
            with mock.patch.object(self.worker,'adapter',return_value=adapter), \
                 mock.patch.object(self.worker,'SECRET_INPUTS',(('CONFIG_A',private),)), \
                 mock.patch.object(self.worker,'REPORT',root/'report-does-not-exist.json'), \
                 mock.patch.object(self.worker,'git_source',return_value=('a'*40,{'schema':'binding'},b'manifest')), \
                 mock.patch.object(self.worker,'contract',return_value={'maxPublicBytes':1<<20}), \
                 mock.patch.object(self.worker,'private_bases'),mock.patch.object(self.worker,'write_private'), \
                 mock.patch.object(self.worker,'command_argv',return_value=('model',)), \
                 mock.patch.object(self.worker,'capture',return_value=0),mock.patch.object(self.worker,'source_file',side_effect=source_file):
                with self.assertRaises(ValueError) as caught:
                    self.worker.main((str(root),str(adapter.EXPORT_ALIAS),'unused','unused','a'*40))
            self.assertIn('"reportObserved":false',str(caught.exception)); self.assertIn('"httpCount":0',str(caught.exception))
            self.assertNotIn(secret.decode(),str(caught.exception)); self.assertEqual(adapter.shared().writes,[])

    def test_safe_upload_is_success_only_and_excludes_mixed_diagnostics(self):
        workflow=(HERE.parents[2]/'.github/workflows/chengwang-mihomo-continuous-recovery-api.yml').read_text(encoding='utf8')
        safe='          name: mihomo-continuous-recovery-api-safe-${{ github.run_id }}-${{ github.run_attempt }}\n'
        self.assertEqual(workflow.count(safe),2)
        producer=workflow.split('      - name: Project and independently re-read the bounded safe artifact\n',1)[1].split('      - uses: actions/upload-artifact@',1)[0]
        self.assertIn('test ! -s "$RUNNER_TEMP/mihomo-continuous-recovery-verification.stderr"',producer)
        self.assertIn('--project-safe',producer); self.assertIn('--verify-safe',producer)
        upload=workflow.split(safe,1)[1].split('      - uses: actions/upload-artifact@',1)[0]
        self.assertIn('path: ${{ runner.temp }}/mihomo-continuous-recovery-safe/',upload)
        self.assertNotIn('if: ${{ always() }}',upload)
        for forbidden in ('*.stdout','*.stderr','continuous.json','kernel.stdout','kernel.stderr','candidate.gz'):
            self.assertNotIn(forbidden,upload)
        diagnostic_name='          name: mihomo-continuous-recovery-api-verifier-failure-${{ github.run_id }}-${{ github.run_attempt }}\n'
        self.assertEqual(workflow.count(diagnostic_name),1)
        diagnostic=workflow.split('      - name: Independently validate the bounded verifier rejection summary\n',1)[1].split('      - name: Project and independently re-read the bounded safe artifact\n',1)[0]
        self.assertIn("if: ${{ failure() }}",diagnostic)
        self.assertIn('check_continuous_recovery_verifier_failure.py',diagnostic)
        self.assertIn("if: ${{ always() && steps.verifier_failure_diagnostic.outcome == 'success' }}",diagnostic)
        self.assertIn('path: ${{ runner.temp }}/mihomo-continuous-recovery-verifier-failure-public/verification-failure.json',diagnostic)
        for forbidden in ('verification.stderr','verification.txt','*.stdout','*.stderr','kernel.stdout','kernel.stderr','private.json'):
            self.assertNotIn(forbidden,diagnostic.split('      - uses: actions/upload-artifact@',1)[1])
        helper_failure=self.verifier_failure
        commit='a'*40; tree='b'*40; run_id=41581266977; attempt=1
        def summary(proven=False,phase='SOURCE_BINDING',failure_class='SOURCE_MISMATCH',field='SOURCE_MANIFEST'):
            return {'schema':helper_failure.SCHEMA,'status':'FAIL','accepted':False,'authorization':'BLOCKED',
              'runtimeAccepted':False,'phase':phase,'failureClass':failure_class,'fieldCode':field,
              'runId':run_id,'runAttempt':attempt,'sourceCommit':commit,'sourceTree':tree if proven else None,
              'sourceProof':{'proven':proven,'bindingSHA256':'1'*64 if proven else None,
                'sourceCount':34 if proven else None,'deliveryCount':33 if proven else None},
              'rawEvidenceIncluded':False,'production':False}
        private_value=summary(); private_raw=helper_failure.canonical(private_value)+b'\n'
        self.assertEqual(helper_failure.validate(private_raw,commit,tree,run_id,attempt),private_value)
        bound_value=summary(True,'HTTP_SHAPES','SCHEMA_INVALID','HTTP_RESPONSES')
        helper_failure.validate(helper_failure.canonical(bound_value)+b'\n',commit,tree,run_id,attempt)
        mutants=[]
        def changed(path,value):
            mutant=copy.deepcopy(private_value); target=mutant
            for item in path[:-1]: target=target[item]
            target[path[-1]]=value; mutants.append(mutant)
        changed(('runId',),run_id+1); changed(('runAttempt',),attempt+1); changed(('sourceCommit',),'c'*40)
        changed(('sourceTree',),'c'*40); changed(('phase',),'PRIVATE_MESSAGE'); changed(('failureClass',),'RAW_EXCEPTION')
        changed(('fieldCode',),'filesystem/path'); changed(('accepted',),True); changed(('runtimeAccepted',),True)
        changed(('sourceProof','bindingSHA256'),'1'*64); changed(('sourceProof','sourceCount'),34)
        extra=copy.deepcopy(private_value);extra['message']='PRIVATE_CANARY';mutants.append(extra)
        for index,mutant in enumerate(mutants):
            with self.subTest(verifier_failure_mutant=index),self.assertRaises((ValueError,TypeError,KeyError)):
                helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,run_id,attempt)
        scalar_base=summary();scalar_base['runId']=1;scalar_base['runAttempt']=1
        scalar_raw=helper_failure.canonical(scalar_base)+b'\n'
        self.assertEqual(helper_failure.validate(scalar_raw,commit,tree,1,1),scalar_base)
        for key in ('runId','runAttempt'):
            for bad in (True,False,1.0,'1',None):
                mutant=copy.deepcopy(scalar_base);mutant[key]=bad
                with self.subTest(integer_identity=key,bad_type=type(bad).__name__,bad=bad),self.assertRaises((ValueError,TypeError)):
                    helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,1,1)
        for key in ('accepted','runtimeAccepted','rawEvidenceIncluded','production'):
            for bad in (0,0.0,'false',None):
                mutant=copy.deepcopy(scalar_base);mutant[key]=bad
                with self.subTest(boolean_literal=key,bad_type=type(bad).__name__),self.assertRaises((ValueError,TypeError)):
                    helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,1,1)
        for bad in (0,0.0,'false',None):
            mutant=copy.deepcopy(scalar_base);mutant['sourceProof']['proven']=bad
            with self.subTest(source_proof_boolean=type(bad).__name__),self.assertRaises((ValueError,TypeError)):
                helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,1,1)
        for bad in (False,0,0.0,'',tree):
            mutant=copy.deepcopy(scalar_base);mutant['sourceTree']=bad
            with self.subTest(nullable_source_tree=repr(bad)),self.assertRaises((ValueError,TypeError)):
                helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,1,1)
        for proof_key in ('bindingSHA256','sourceCount','deliveryCount'):
            for bad in (False,0,0.0,''):
                mutant=copy.deepcopy(scalar_base);mutant['sourceProof'][proof_key]=bad
                with self.subTest(nullable_source_proof=proof_key,bad_type=type(bad).__name__),self.assertRaises((ValueError,TypeError)):
                    helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,1,1)
        typed_strings=('schema','status','authorization','phase','failureClass','fieldCode','sourceCommit')
        for key in typed_strings:
            for bad in (True,1,1.0,None):
                mutant=copy.deepcopy(scalar_base);mutant[key]=bad
                with self.subTest(closed_string=key,bad_type=type(bad).__name__),self.assertRaises((ValueError,TypeError)):
                    helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,1,1)
        for key in ('sourceCount','deliveryCount'):
            for bad in (True,1.0,'34',None):
                mutant=copy.deepcopy(bound_value);mutant['sourceProof'][key]=bad
                with self.subTest(bound_count=key,bad_type=type(bad).__name__),self.assertRaises((ValueError,TypeError)):
                    helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,run_id,attempt)
        for bad in (True,1,1.0,None,'c'*40):
            mutant=copy.deepcopy(bound_value);mutant['sourceTree']=bad
            with self.subTest(bound_source_tree=repr(bad)),self.assertRaises((ValueError,TypeError)):
                helper_failure.validate(helper_failure.canonical(mutant)+b'\n',commit,tree,run_id,attempt)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/'failure.private.json'; output=root/'public'
            helper_failure.write_new(private,private_raw,0o600)
            linked=root/'linked.private.json';os.link(private,linked)
            with self.assertRaises(ValueError):helper_failure.read_stable(private)
            linked.unlink()
            with mock.patch.object(helper_failure,'bind_source',return_value=(root,tree)):
                published=helper_failure.publish(root,private,commit,str(run_id),str(attempt),output)
            self.assertFalse(published['accepted']);self.assertEqual(tuple(x.name for x in output.iterdir()),('verification-failure.json',))
            self.assertEqual((output/'verification-failure.json').read_bytes(),private_raw)
            with mock.patch.object(helper_failure,'bind_source',return_value=(root,tree)),self.assertRaises(ValueError):
                helper_failure.publish(root,private,commit,str(run_id),str(attempt),output)
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/'repo';repo.mkdir();subprocess.run(['git','init','-q',str(repo)],check=True)
            subprocess.run(['git','-C',str(repo),'config','core.autocrlf','false'],check=True)
            for relative in helper_failure.BOUND_SOURCES:
                destination=repo/relative;destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes((HERE.parents[2]/relative).read_bytes())
            subprocess.run(['git','-C',str(repo),'add','--all'],check=True)
            subprocess.run(['git','-C',str(repo),'-c','user.name=model','-c','user.email=model@example.invalid','commit','-qm','model'],check=True)
            actual_commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
            actual_tree=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD^{tree}'],text=True).strip()
            actual_value=copy.deepcopy(private_value);actual_value['sourceCommit']=actual_commit
            private=Path(td)/'actual.private.json';output=Path(td)/'actual-public'
            helper_failure.write_new(private,helper_failure.canonical(actual_value)+b'\n',0o600)
            helper_failure.publish(repo,private,actual_commit,str(run_id),str(attempt),output)
            self.assertEqual(helper_failure.bind_source(repo,actual_commit)[1],actual_tree)
            (repo/helper_failure.BOUND_SOURCES[-1]).write_bytes(b'tamper\n')
            with self.assertRaises(ValueError):helper_failure.bind_source(repo,actual_commit)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/'early.private.json'
            with mock.patch.object(self.reader,'git_manifest',side_effect=ValueError('private detail')):
                self.assertEqual(self.reader.verify_with_failure_summary(root,root,commit,tree,str(run_id),str(attempt),private),1)
            early=helper_failure.strict_json(private.read_bytes())
            self.assertEqual((early['phase'],early['failureClass'],early['fieldCode']),('SOURCE_BINDING','SOURCE_MISMATCH','SOURCE_MANIFEST'))
            self.assertIsNone(early['sourceTree'])
            self.assertEqual(early['sourceProof'],{'proven':False,'bindingSHA256':None,'sourceCount':None,'deliveryCount':None})
            self.assertNotIn('private detail',private.read_text(encoding='ascii'))
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/'writer.private.json'; private.write_bytes(b'preserve')
            with self.assertRaises(ValueError):
                self.reader.verify_with_failure_summary(root,root,commit,tree,str(run_id),str(attempt),private)
            self.assertEqual(private.read_bytes(),b'preserve')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/'writer-fault.private.json'
            with mock.patch.object(self.reader,'verify',side_effect=ValueError('private verifier detail')), \
                 mock.patch.object(self.reader,'write_new',side_effect=OSError('private writer detail')), \
                 self.assertRaises(OSError):
                self.reader.verify_with_failure_summary(root,root,commit,tree,str(run_id),str(attempt),private)
            self.assertFalse(private.exists());self.assertIsNone(self.reader._ACTIVE_DIAGNOSTIC)
        helper=self.model_outcomes
        source=(HERE/'test_continuous_recovery_api_model.py').read_bytes()
        expected,source_sha=helper.inventory(source)
        self.assertEqual((len(expected),helper.sha('\n'.join(expected).encode())),(12,helper.EXPECTED_IDS_SHA256))
        commit='a'*40; tree='b'*40; run_id='41568557617'; attempt='1'
        accepted=helper.make_value(commit,tree,run_id,attempt,source_sha,expected,expected,expected,(), 'NONE')
        accepted_raw=helper.canonical(accepted)
        self.assertTrue(helper.validate(accepted_raw,commit,tree,run_id,attempt,source_sha)['suiteAccepted'])
        failed_id=expected[0]; passed=tuple(name for name in expected if name!=failed_id)
        rejected=helper.make_value(commit,tree,run_id,attempt,source_sha,expected,expected,passed,
          ((failed_id,'ASSERTION_FAILURE'),),'NONE')
        rejected_raw=helper.canonical(rejected)
        self.assertFalse(helper.validate(rejected_raw,commit,tree,run_id,attempt,source_sha)['suiteAccepted'])
        load_error=helper.make_value(commit,tree,run_id,attempt,source_sha,(),(),(),(), 'MODULE_LOAD_ERROR')
        self.assertFalse(helper.validate(helper.canonical(load_error),commit,tree,run_id,attempt,source_sha)['suiteAccepted'])
        secret='MODEL_PRIVATE_CANARY_7f2e54b910'
        self.assertNotIn(secret,accepted_raw.decode());self.assertNotIn(secret,rejected_raw.decode())
        mutants=[]
        def changed(key,value):
            mutant=copy.deepcopy(rejected);mutant[key]=value;mutants.append(mutant)
        extra=copy.deepcopy(rejected);extra['traceback']=secret;mutants.append(extra)
        changed('sourceCommit','c'*40);changed('sourceTree','c'*40);changed('runId','2');changed('runAttempt','2')
        changed('expectedCount',True);changed('expectedIdsSHA256','0'*64);changed('modelSourceSHA256','0'*64)
        changed('loadedIds',list(expected[:-1]));changed('runIds',list(expected)+[expected[0]])
        changed('passedIds',list(expected));changed('failedIds',[]);changed('notRunIds',[expected[0]])
        wrong_class=copy.deepcopy(rejected);wrong_class['failureClasses'][0]['class']='PRIVATE_EXCEPTION';mutants.append(wrong_class)
        extra_row=copy.deepcopy(rejected);extra_row['failureClasses'][0]['message']=secret;mutants.append(extra_row)
        changed('runnerFailureClass',False);changed('suiteAccepted',True);changed('sourceCleanBefore',False)
        changed('sourceCleanAfter',False);changed('production',True)
        for index,mutant in enumerate(mutants):
            with self.subTest(model_outcome_mutant=index),self.assertRaises((ValueError,TypeError,KeyError,AssertionError)):
                helper.validate(helper.canonical(mutant),commit,tree,run_id,attempt,source_sha)
        with self.assertRaises(ValueError):helper.validate(rejected_raw.replace(b':',b': ',1),commit,tree,run_id,attempt,source_sha)
        with self.assertRaises(ValueError):helper.validate(rejected_raw+b' '*(helper.MAXIMUM+1),commit,tree,run_id,attempt,source_sha)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);private=root/'model-outcome.json';helper.write_new(private,rejected_raw,0o600)
            with self.assertRaises(FileExistsError):helper.write_new(private,rejected_raw,0o600)
            linked=root/'linked.json';os.link(private,linked)
            with self.assertRaises(ValueError):helper.read_stable(private)
            with self.assertRaises(ValueError):helper.exact_directory(root,(private.name,))
        helper_source=(HERE/'continuous_recovery_model_outcomes.py').read_text(encoding='utf8')
        self.assertIn('O_NOFOLLOW',helper_source)
        model_upload='          name: mihomo-continuous-source-model-outcomes-${{ github.run_id }}-${{ github.run_attempt }}\n'
        self.assertEqual(workflow.count(model_upload),1)
        model_block=workflow.split('      - name: Run bounded producer and independent-reader models only\n',1)[1].split('      - name: Preserve independently checked source-model outcomes only\n',1)[0]
        self.assertEqual(model_block.count('helper=chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_model_outcomes.py'),1)
        self.assertEqual(model_block.count('python3 -I -B "$helper" run'),1)
        self.assertEqual(model_block.count('python3 -I -B "$helper" check'),1)
        self.assertIn('model_outcome_ready=true',model_block)
        self.assertLess(model_block.index('exit "$model_code"'),model_block.index('exit "$check_code"'))
        model_upload_block=workflow.split('      - name: Preserve independently checked source-model outcomes only\n',1)[1].split('\n  continuous-fault-model:',1)[0]
        self.assertIn("if: ${{ always() && steps.source_models.outputs.model_outcome_ready == 'true' }}",model_upload_block)
        self.assertIn('path: ${{ runner.temp }}/mihomo-continuous-source-model-public/model-outcome.json',model_upload_block)
        for forbidden in ('*.stdout','*.stderr','continuous.json','kernel.stdout','kernel.stderr','private/'):
            self.assertNotIn(forbidden,model_upload_block)

    def test_producer_and_reader_independently_bind_full_tracked_git_set(self):
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)
            subprocess.run(['git','init','-q',str(repo)],check=True)
            subprocess.run(['git','-C',str(repo),'config','core.autocrlf','false'],check=True)
            for rel in self.reader.DELIVERY:
                path=repo/rel; path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((HERE/'continuous_recovery_api_source_policy.json').read_bytes() if rel==self.reader.MANIFEST_REL else (rel+'\n').encode())
            subprocess.run(['git','-C',str(repo),'add','--all'],check=True)
            subprocess.run(['git','-C',str(repo),'-c','user.name=model','-c','user.email=model@example.invalid','commit','-qm','model'],check=True)
            commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
            _,producer,producer_raw=self.worker.git_source(repo,commit); reader,reader_raw=self.reader.git_manifest(repo,commit)
            self.assertEqual(producer,reader); self.assertEqual(producer_raw,reader_raw)
            (repo/'untracked').write_bytes(b'tamper')
            with self.assertRaises(ValueError): self.worker.git_source(repo,commit)
            with self.assertRaises(ValueError): self.reader.git_manifest(repo,commit)

    def state(self):
        return {'sourceBinding':{'schema':'binding'},'commit':'a'*40,'commandSequence':0,'eventSequence':0,
                'environment':{},'pending':[]}

    def test_capture_dispatch_positive_and_rejects_closed_tuple(self):
        with tempfile.TemporaryDirectory() as td:
            adapter=Adapter(td); state=self.state(); argv=('python3','model')
            with mock.patch.object(self.worker,'adapter',return_value=adapter), mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True), mock.patch.object(self.worker.os,'fchmod',return_value=None,create=True), mock.patch.object(self.worker.os,'fstat',side_effect=root_fstat), \
                 mock.patch.object(self.worker,'command_argv',return_value=argv), \
                 mock.patch.object(self.worker.subprocess,'Popen',return_value=Process()), \
                 mock.patch.object(self.worker.os,'pidfd_open',return_value=os.open(os.devnull,os.O_RDONLY),create=True):
                self.assertEqual(self.worker.capture(state,argv,'continuous-sandbox.private.json','continuous-sandbox.private.stderr',30,'SANDBOX'),0)
            self.assertEqual(state['commandSequence'],1); self.assertEqual(state['eventSequence'],4); self.assertEqual(state['pending'],[])
            for args in ((argv,'wrong','continuous-sandbox.private.stderr',30,'SANDBOX'),
                         (argv,'continuous-sandbox.private.json','wrong',30,'SANDBOX'),
                         (argv,'continuous-sandbox.private.json','continuous-sandbox.private.stderr',31,'SANDBOX'),
                         (argv,'continuous-sandbox.private.json','continuous-sandbox.private.stderr',30,'GO_TEST')):
                with self.subTest(args=args),mock.patch.object(self.worker,'adapter',return_value=adapter),mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True):
                    with self.assertRaises(ValueError): self.worker.capture(self.state(),*args)
            source=(HERE/'continuous_recovery_api_worker.py').read_text(encoding='utf8')
            self.assertIn('info.st_uid==info.st_gid==0',source)
            path=adapter.ROOT_PRIVATE/'nonroot-model.jsonl'
            row={'schema':'model','sequence':1}
            nonroot_state=self.state()
            with mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True),mock.patch.object(self.worker.os,'fstat',side_effect=nonroot_fstat):
                with self.assertRaises(ValueError): self.worker.append_jsonl(path,row,nonroot_state,'eventSequence')
            self.assertEqual(nonroot_state['eventSequence'],0); self.assertEqual(path.read_bytes(),b'')

    def test_capture_pidfd_failure_and_timeout_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            adapter=Adapter(td); argv=('python3','model'); state=self.state()
            with mock.patch.object(self.worker,'adapter',return_value=adapter),mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True),mock.patch.object(self.worker.os,'fchmod',return_value=None,create=True),mock.patch.object(self.worker.os,'fstat',side_effect=root_fstat),mock.patch.object(self.worker,'command_argv',return_value=argv), \
                 mock.patch.object(self.worker.subprocess,'Popen',return_value=Process()),mock.patch.object(self.worker.os,'pidfd_open',side_effect=OSError('model'),create=True):
                with self.assertRaises(OSError): self.worker.capture(state,argv,'continuous-sandbox.private.json','continuous-sandbox.private.stderr',30,'SANDBOX')
            self.assertEqual(state['commandSequence'],1); self.assertEqual(len(state['pending']),1)
        with tempfile.TemporaryDirectory() as td:
            adapter=Adapter(td); state=self.state(); process=Process(timeout=True); sent=[]; fd=os.open(os.devnull,os.O_RDONLY)
            with mock.patch.object(self.worker,'adapter',return_value=adapter),mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True),mock.patch.object(self.worker.os,'fchmod',return_value=None,create=True),mock.patch.object(self.worker.os,'fstat',side_effect=root_fstat),mock.patch.object(self.worker,'command_argv',return_value=argv), \
                 mock.patch.object(self.worker.subprocess,'Popen',return_value=process),mock.patch.object(self.worker.os,'pidfd_open',return_value=fd,create=True), \
                 mock.patch.object(self.worker.signal,'SIGKILL',9,create=True), \
                 mock.patch.object(self.worker.signal,'pidfd_send_signal',side_effect=lambda f,s:sent.append((f,s)),create=True):
                self.assertEqual(self.worker.capture(state,argv,'continuous-sandbox.private.json','continuous-sandbox.private.stderr',30,'SANDBOX'),-9)
            self.assertEqual(len(sent),1); self.assertEqual(state['pending'],[])

    def proof(self): return {'fullPayloadProven':False,'internetBusinessProven':False,'production':False}
    def head(self,generation,head,record,config,blocked,active=None,previous=None):
        return {'schema':'chengwang.mihomo-lab-head-view/v1','boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF',
          'revision':generation,'generation':generation,'headSHA256':head,'previousHeadSHA256':previous,'artifactRecordSHA256':record,
          'configSHA256':config,'verificationSHA256':format(generation+8,'x')*64,'verifiedAt':'2026-10-26T00:00:00Z',
          'activeOperationId':active,'writeBlocked':blocked,'proof':self.proof()}
    def op(self,oid,phase,generation,old,new,record,config,blocked,advanced,revision=None):
        state,status=('unknown',0) if phase=='UNKNOWN' else ('acknowledged',204)
        return {'schema':'chengwang.mihomo-lab-deployment-view/v1','boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF',
          'operationId':oid,'phase':phase,'revision':revision if revision is not None else generation,'planSHA256':'1'*64,'candidateRecordSHA256':record,'candidateConfigSHA256':config,
          'previousHeadSHA256':old,'headSHA256':new,'headGeneration':generation,'expiresAt':'2026-10-26T00:05:00Z',
          'transport':{'result':{'state':state,'dispatched':True,'statusCode':status},'recordedAt':'2026-10-26T00:00:00Z','origin':'ADAPTER','gateReason':None},
          'observation':{'conclusion':'STABLE_NEW_PROJECTION','observedProjectionSHA256':'9'*64,'evidenceSHA256':'8'*64,'observedAt':'2026-10-26T00:00:00Z','localRouteVerified':True},
          'writeBlocked':blocked,'replayed':False,'headAdvanced':advanced,'proof':self.proof()}
    def recovery(self,rid,oid,generation,old,new,record,config,revision=None,phase='COMPLETED'):
        return {'schema':'chengwang.mihomo-lab-recovery-view/v2','boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF',
          'recoveryId':rid,'phase':phase,'revision':revision if revision is not None else generation,'planSHA256':'4'*64,'unknownOperationId':oid,'originalPlanSHA256':'1'*64,
          'previousHeadSHA256':old,'headSHA256':new,'headGeneration':generation,'targetArtifactRecordSHA256':record,'targetConfigSHA256':config,
          'expiresAt':'2026-10-26T00:05:00Z','writeBlocked':False,'replayed':False,'headAdvanced':True,'proof':self.proof()}
    def observe(self,state,calls):
        steps=[]
        for i in range(1,4):
            loss=i!=2; steps.append({'sequence':i,'action':'LOSS' if loss else 'PASS','state':'INJECTED' if loss else 'PASSTHROUGH',
              'underlyingRoundTrips':1,'statusCode':204,'bodyBytes':0 if loss else None,'eofObserved':True if loss else None,
              'closeSucceeded':True if loss else None,'injected':loss,'failureCode':None})
        return {'schema':'chengwang.mihomo-continuous-recovery-response-loss/v2','state':state,'boundOperations':3,'observedResults':3,
          'initialCore':1,'recoveredCore':2,'nativeCallsBounded':True,'nativeCalls':calls,
          'recoveryCreatesBounded':True,'recoveryCreates':[{'sequence':1,'stage':'ENTERED'},{'sequence':2,'stage':'ACCEPTED'},
            {'sequence':3,'stage':'ENTERED'},{'sequence':4,'stage':'ACCEPTED'}],
          'transport':{'schema':'chengwang.mihomo-reload-response-loss-schedule/v1','state':'CLOSED' if state=='CLOSED' else 'TERMINAL',
            'boundChildren':3,'underlyingRoundTrips':3,'injected':2,'steps':steps}}
    def candidates(self,current,record_a,config_a,record_b,config_b):
        return {'schema':'chengwang.mihomo-lab-candidates-view/v1','boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF',
          'candidates':[{'name':'local-a','recordSHA256':record_a,'configSHA256':config_a,'sourceSpecSHA256':'e'*64,'isCurrent':current=='a'},
                        {'name':'local-b','recordSHA256':record_b,'configSHA256':config_b,'sourceSpecSHA256':'f'*64,'isCurrent':current=='b'}],
          'writeBlocked':False,'proof':self.proof()}
    def call(self,sequence,case,actor,method,path,status,result):
        body=json.dumps({'boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF','code':'mihomo_lab_ok',
          'stateMayHaveChanged':method=='POST','result':result},separators=(',',':')).encode()+b'\n'
        return {'sequence':sequence,'case':case,'caseActor':actor,'method':method,'path':path,'requestBodySHA256':self.reader.sha(b'' if method=='GET' else b'model'),
          'statusCode':status,'responseBodySHA256':self.reader.sha(body),'responseBodyB64':base64.b64encode(body).decode(),'errorClass':'NONE'},body
    def rewrite_case(self,report,root,case,mutate):
        row=next(item for item in report['http'] if item['case']==case)
        envelope=json.loads(base64.b64decode(row['responseBodyB64'],validate=True)); mutate(envelope['result'])
        body=json.dumps(envelope,separators=(',',':')).encode()+b'\n'; row['responseBodySHA256']=self.reader.sha(body); row['responseBodyB64']=base64.b64encode(body).decode()
        (root/f"http-{row['sequence']:03d}.response.json").write_bytes(body)
    def fixture(self,root):
        h0='a'*64; h1='b'*64; h2='c'*64; h3='d'*64
        record_a='2'*64; config_a='3'*64; record_b='5'*64; config_b='6'*64
        op1='labop_'+'1'*32; op2='labop_'+'2'*32; op3='labop_'+'3'*32
        rec1='labrec_'+'1'*32; rec2='labrec_'+'2'*32
        heads=[self.head(1,h0,record_a,config_a,False),self.head(1,h0,record_a,config_a,True,op1),
          self.head(2,h1,record_b,config_b,False,None,h0),self.head(3,h2,record_a,config_a,False,op2,h1),
          self.head(3,h2,record_a,config_a,True,op3,h1),self.head(4,h3,record_b,config_b,False,None,h2)]
        ops=[self.op(op1,'UNKNOWN',1,h0,h0,record_b,config_b,True,False,4),self.op(op2,'COMPLETED',3,h1,h2,record_a,config_a,False,True,10),self.op(op3,'UNKNOWN',3,h2,h2,record_b,config_b,True,False,14)]
        rec=[self.recovery(rec1,op1,2,h0,h1,record_b,config_b,7),self.recovery(rec2,op3,4,h2,h3,record_b,config_b,17)]
        result={}
        head_map=dict(zip(['INITIAL','FIRST_UNKNOWN','FIRST_RECOVERED','ORDINARY_ACK','SECOND_UNKNOWN','SECOND_RECOVERED'],heads))
        for prefix,op in zip(('FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'),ops):
            created=copy.deepcopy(op); created.update(phase='PLANNED',revision=op['revision']-2,headSHA256=op['previousHeadSHA256'],headGeneration=op['headGeneration']-(1 if op['headAdvanced'] else 0),transport=None,observation=None,writeBlocked=False,headAdvanced=False)
            approved=copy.deepcopy(created); approved.update(phase='APPROVED',revision=op['revision']-1)
            result[prefix+'_CREATE']=created; result[prefix+'_APPROVE']=approved; result[prefix+'_EXECUTE']=op; result[prefix+'_INSPECT']=copy.deepcopy(op)
        for prefix,item in zip(('FIRST_RECOVERY','SECOND_RECOVERY'),rec):
            planned=copy.deepcopy(item); planned.update(phase='PLANNED',revision=item['revision']-2,headSHA256=item['previousHeadSHA256'],headGeneration=item['headGeneration']-1,writeBlocked=True,headAdvanced=False)
            approved=copy.deepcopy(planned); approved.update(phase='APPROVED',revision=item['revision']-1)
            result[prefix+'_CREATE']=planned; result[prefix+'_INSPECT_PLANNED']=copy.deepcopy(planned); result[prefix+'_APPROVE']=approved; result[prefix+'_EXECUTE']=item; result[prefix+'_INSPECT_COMPLETED']=copy.deepcopy(item)
        for stage,head in head_map.items(): result[stage+'_HEAD']=head
        result['FIRST_CANDIDATES']=self.candidates('a',record_a,config_a,record_b,config_b)
        result['ACK_CANDIDATES']=self.candidates('b',record_a,config_a,record_b,config_b)
        result['SECOND_CANDIDATES']=self.candidates('a',record_a,config_a,record_b,config_b)
        dynamic={}
        for prefix,op in zip(('FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'),ops):
            base='/api/v1/lab/mihomo/deployments/'+op['operationId']; dynamic[prefix+'_APPROVE']=base+'/approvals'; dynamic[prefix+'_EXECUTE']=base+'/execute'; dynamic[prefix+'_INSPECT']=base
        for prefix,item in zip(('FIRST_RECOVERY','SECOND_RECOVERY'),rec):
            base='/api/v1/lab/mihomo/recoveries/'+item['recoveryId']; dynamic[prefix+'_INSPECT_PLANNED']=base; dynamic[prefix+'_APPROVE']=base+'/approvals'; dynamic[prefix+'_EXECUTE']=base+'/execute'; dynamic[prefix+'_INSPECT_COMPLETED']=base
        http=[]
        for i,want in enumerate(self.reader.HTTP_CASES,1):
            case,actor,method,path,status=want; row,body=self.call(i,case,actor,method,path or dynamic[case],status,result[case]); http.append(row); (root/f'http-{i:03d}.response.json').write_bytes(body)
        native=(
          ('RECOVERY_STOP_DISPATCH',1),('OWNED_STOP_HELPER_ENTER',1),('KERNEL_OS_TERM_ATTEMPT',1),
          ('KERNEL_OS_TERM_RETURN',1),('KERNEL_OS_WAIT_RETURN',1),('RECOVERY_START_DISPATCH',0),
          ('KERNEL_OS_START_ATTEMPT',2),('KERNEL_OS_START_RETURN',2),('KERNEL_OS_WAIT_ENTER',2),
          ('RECOVERY_STOP_DISPATCH',2),('OWNED_STOP_HELPER_ENTER',2),('KERNEL_OS_TERM_ATTEMPT',2),
          ('KERNEL_OS_TERM_RETURN',2),('KERNEL_OS_WAIT_RETURN',2),('RECOVERY_START_DISPATCH',0),
          ('KERNEL_OS_START_ATTEMPT',3),('KERNEL_OS_START_RETURN',3),('KERNEL_OS_WAIT_ENTER',3))
        pre=[{'sequence':100+i,'kind':kind,'core':core,'at':'2026-10-26T00:00:00Z'} for i,(kind,core) in enumerate(native,1)]
        post=pre+[{'sequence':100+i+len(pre),'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate(('OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_WAIT_RETURN'),1)]
        initial={'schema':'chengwang.mihomo-lab-acceptance-state/v1','sourceCommit':'a'*40,'walSchema':self.reader.WAL_SCHEMA,'controlSHA256':'7'*64,'recordSHA256':'8'*64,
          'head':copy.deepcopy(heads[0]),'activeOperationId':None,'activePhase':None,'activeIntentSHA256':None,'completed':[],'terminated':[],'unknownObservationCount':0,
          'privateWALValidated':True,'fullPrivateWALIndependentlyProven':False,'observedProcessMatchesHead':True,'production':False}
        return {'schema':'chengwang.mihomo-continuous-recovery-http-experiment/v3','scope':self.reader.SCOPE,'sourceCommit':'a'*40,'outcome':'PASS','failureCode':'NONE','http':http,'initial':initial,
          'heads':[{'stage':s,'view':v} for s,v in zip(('INITIAL','FIRST_UNKNOWN','FIRST_RECOVERED','ORDINARY_ACK','SECOND_UNKNOWN','SECOND_RECOVERED'),heads)],
          'operations':[{'stage':s,'view':v} for s,v in zip(('FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'),ops)],
          'recoveries':[{'stage':s,'view':v} for s,v in zip(('FIRST_RECOVERY','SECOND_RECOVERY'),rec)],
          'callsBefore':{'reloadInvocations':0,'doInvocations':0},'callsAfter':{'reloadInvocations':3,'doInvocations':3},
          'faultBeforeCleanup':self.observe('TERMINAL',pre),'faultAfterCleanup':self.observe('TERMINAL',post),'faultClosed':self.observe('CLOSED',post),
          'closedPorts':[{'port':p,'connectAttempted':True,'accepted':False,'errorClass':'CONNECTION_REFUSED'} for p in (28411,28412,28413,28414,28415,30000)],
          'runtimeReturned':True,'runtimeErrorClass':'NONE','privateWALDecodedByTest':False,'production':False,'fullPayloadProven':False,'internetBusinessProven':False}

    def source_binding(self):
        return {'schema':'chengwang.mihomo-continuous-recovery-source-binding/v1','sourceCommit':'a'*40,
          'sourceTree':'b'*40,'indexTree':'b'*40,'sourceManifestSHA256':'c'*64,'sourceSetSHA256':'d'*64,
          'deliverySetSHA256':'e'*64,'policySHA256':'f'*64,'sourceCount':100,'deliveryCount':35}

    def write_json(self,path,value): path.write_bytes(self.reader.canonical(value)+b'\n')

    def safe_evidence_fixture(self,root):
        root.mkdir(parents=True); binding=self.source_binding(); report=self.fixture(root); commit='a'*40
        self.write_json(root/'continuous-recovery-report.json',report)
        index=self.reader.validate_report(report,commit,root,binding)
        self.write_json(root/'http-originals-index.json',{'schema':'chengwang.mihomo-continuous-recovery-http-originals/v2',
          'scope':self.reader.SCOPE,'sourceCommit':commit,'sourceBinding':binding,'entries':index,'production':False})
        self.write_json(root/'execution.json',{'schema':'chengwang.mihomo-continuous-recovery-execution/v1','scope':self.reader.SCOPE,
          'sourceCommit':commit,'sourceBinding':binding,'formatExit':0,'goExit':0,'outcome':'PASS',
          'fullPrivateWALIndependentlyProven':False,'production':False})
        namespace={'networkNamespace':'net:[2]','mountNamespace':'mnt:[2]','pidNamespace':'pid:[2]'}
        argvs=(
          ['python3','-B','/tmp/mihomo-apply-source/deploy/mihomo-lifecycle-lab/continuous_recovery_api_worker.py','--sandbox',commit,
           binding['sourceTree'],binding['indexTree'],binding['sourceManifestSHA256'],binding['sourceSetSHA256'],binding['deliverySetSHA256'],binding['policySHA256'],str(binding['sourceCount']),str(binding['deliveryCount'])],
          ['/tmp/mihomo-apply-go/bin/go','version'],
          ['/tmp/mihomo-apply-go/bin/gofmt','-d',*self.reader.FMT],
          ['/tmp/mihomo-apply-go/bin/go','test','-json','-count=1','-shuffle=off','-p=1','-tags='+','.join(self.reader.TAGS),'-run=^'+self.reader.TOP+'$','-timeout=210s','./internal/serverruntime'])
        commands=[]; events=[]; sequence=0
        for i,(kind,timeout,argv) in enumerate(zip(self.reader.COMMANDS,self.reader.TIMEOUTS,argvs),1):
            commands.append({'schema':'chengwang.mihomo-continuous-recovery-command-receipt/v1','sequence':i,
              'sourceCommit':commit,'commandClass':kind,'argv':argv,'cwd':'/tmp/mihomo-apply-source','timeoutSeconds':timeout,
              'exitCode':0,'observed':True,'namespace':namespace,'sourceBinding':binding})
            pid=4200+i
            for event,acquired,exit_code in (('START_INTENT',None,None),('SPAWNED',False,None),('PIDFD_ACQUIRED',True,None),('WAIT_RETURNED',True,0)):
                sequence+=1; events.append({'schema':'chengwang.mihomo-continuous-recovery-process-event/v1','sequence':sequence,
                  'commandClass':kind,'kind':event,'pid':None if event=='START_INTENT' else pid,
                  'pidfdAcquired':acquired,'exitCode':exit_code})
        (root/'commands.jsonl').write_bytes(b''.join(self.reader.canonical(row)+b'\n' for row in commands))
        (root/'process-events.jsonl').write_bytes(b''.join(self.reader.canonical(row)+b'\n' for row in events))
        self.write_json(root/'sandbox.json',{'sourceCommit':commit,'uid':10001,'gid':10001,'effectiveCaps':'0000000000000000',
          'noNewPrivileges':True,'environmentKeys':list(self.reader.SANDBOX_ENVIRONMENT_KEYS),'interfaceNames':['lo'],
          'defaultV4Routes':[],'defaultV6Routes':[],'sourceModuleSHA256':'2'*64,'sourceReadOnly':True,'goReadOnly':True,
          'kernelCopy':{'sha256':'3'*64,'bytes':123456,'mode':'0500','readOnly':True,'executable':True},
          'schema':'chengwang.mihomo-continuous-recovery-sandbox/v1','sourceBinding':binding,'exactTags':list(self.reader.TAGS),
          'forbiddenTags':list(self.reader.FORBIDDEN),'production':False,**namespace})
        host={'networkNamespace':'net:[1]','mountNamespace':'mnt:[1]','pidNamespace':'pid:[1]','resolvSHA256':'1'*64}
        self.write_json(root/'host-before.json',host); self.write_json(root/'host-after.json',host)
        source_files=[{'path':path,'bytes':100+i,'sha256':str(i+4)*64} for i,path in enumerate(self.reader.CONSUMPTION_SOURCES)]
        consumption={'schema':'chengwang.mihomo-candidate-consumption/v1','state':'PINNED_GZIP_EXPANDED_NOT_EXECUTED',
          'source':{'projectSourceCommit':commit,'sourceFiles':source_files,'pinSHA256':source_files[0]['sha256']},
          'component':'MetaCubeX/mihomo','version':'v1.19.32','upstreamSourceCommit':self.reader.CONSUMPTION_UPSTREAM,
          'archive':{'name':self.reader.CONSUMPTION_ASSET,'bytes':65432,'sha256':self.reader.CONSUMPTION_ARCHIVE_SHA256,
            'pinBasis':'PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL'},
          'gzip':{'singleMember':True,'complete':True,'trailerCRC32':'1234abcd','trailerISIZE':123456},
          'elf':{'bytes':123456,'sha256':'a'*64,'byteOrder':'little','elfClass':'ELF64','machine':'AMD64','type':'DYN',
            'entryPoint':4096,'programHeaderCount':12,'loadSegments':4,'sectionHeaderCount':30,'executableEntryMapped':True},
          'output':{'path':'mihomo','mode':'0500','receiptMode':'0400','directoryMode':'0700'},
          'runtimeExecuted':False,'runtimeCompatibilityProven':False,'businessAvailabilityProven':False,
          'publisherSignatureProven':False,'productionApproved':False,'production':False}
        self.write_json(root/'consumption.json',consumption); self.write_json(root/'consumption-independent.json',consumption)
        (root/'go-version.txt').write_bytes(b'go version go1.23.12 linux/amd64\n')
        return binding,report

    def full_public_fixture(self,root):
        binding,report=self.safe_evidence_fixture(root)
        (root/'gofmt.patch').write_bytes(b''); (root/'gofmt.stderr').write_bytes(b''); (root/'continuous.stderr').write_bytes(b'')
        rows=({'Action':'run','Package':'chengwang/internal/serverruntime','Test':self.reader.TOP},
              {'Action':'pass','Package':'chengwang/internal/serverruntime','Test':self.reader.TOP},
              {'Action':'pass','Package':'chengwang/internal/serverruntime'})
        (root/'continuous.json').write_bytes(b''.join(self.reader.canonical(row)+b'\n' for row in rows))
        (root/'kernel.stdout').write_bytes(b''); (root/'kernel.stderr').write_bytes(b'')
        receipts=[]
        for private,public in (('continuous-recovery-report.private.json','continuous-recovery-report.json'),('kernel.stdout','kernel.stdout'),('kernel.stderr','kernel.stderr')):
            body=(root/public).read_bytes(); receipts.append({'name':private,'bytes':len(body),'sha256':self.reader.sha(body),
              'mode':'0600','uid':10001,'gid':10001,'fsyncObserved':True})
        self.write_json(root/'private-fsync-receipts.json',{'schema':'chengwang.mihomo-continuous-recovery-private-fsync/v1',
          'sourceCommit':'a'*40,'sourceBinding':binding,'entries':receipts,'directoryFsyncObserved':True,'production':False})
        return binding,report

    def test_safe_projection_and_independent_readback_positive(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); public=root/'public'; safe=root/'safe'; binding,_=self.full_public_fixture(public)
            self.assertEqual(self.reader.strict_json(b'{"z":"\\u003c\\u0026\\u003e","a":1}'),{'z':'<&>','a':1})
            source_report=json.loads((public/'continuous-recovery-report.json').read_bytes())
            source_index=json.loads((public/'http-originals-index.json').read_bytes())
            original=json.loads((public/'http-001.response.json').read_bytes())
            reordered=(b'{ "result" : '+self.reader.canonical(original['result'])+b', "stateMayHaveChanged" : false, '
              b'"code" : "mihomo_lab_ok", "boundary" : "'+self.reader.BOUNDARY.encode()+b'" }\n')
            (public/'http-001.response.json').write_bytes(reordered)
            source_report['http'][0]['responseBodySHA256']=self.reader.sha(reordered)
            source_report['http'][0]['responseBodyB64']=base64.b64encode(reordered).decode()
            source_index['entries'][0]['bytes']=len(reordered); source_index['entries'][0]['sha256']=self.reader.sha(reordered)
            self.write_json(public/'continuous-recovery-report.json',source_report)
            self.write_json(public/'http-originals-index.json',source_index)
            private_receipts=json.loads((public/'private-fsync-receipts.json').read_bytes())
            report_raw=(public/'continuous-recovery-report.json').read_bytes(); private_receipts['entries'][0]['bytes']=len(report_raw)
            private_receipts['entries'][0]['sha256']=self.reader.sha(report_raw); self.write_json(public/'private-fsync-receipts.json',private_receipts)
            with mock.patch.object(self.reader,'git_manifest',return_value=(binding,b'manifest')):
                report=self.reader.project_safe(HERE.parents[2],public,'a'*40,'41560358243','1',safe)
                self.assertEqual(self.reader.safe_root(HERE.parents[2],safe,'a'*40,'41560358243','1'),report)
            self.assertEqual(set(x.name for x in safe.iterdir()),{'verification.json','evidence'})
            evidence_names=tuple(x.name for x in (safe/'evidence').iterdir())
            self.assertEqual(len(evidence_names),len(self.reader.SAFE_EVIDENCE))
            self.assertEqual(set(evidence_names),set(self.reader.SAFE_EVIDENCE))
            self.assertEqual(tuple(row['name'] for row in report['files']),self.reader.SAFE_EVIDENCE)
            self.assertEqual((report['httpResponses'],report['recoveries'],report['closedPorts'],report['commands'],report['processEvents']),(31,2,6,4,16))
            self.assertEqual(len(report['files']),42)
            self.assertEqual((safe/'evidence/http-001.response.json').read_bytes(),reordered)
            names='\n'.join(row['name'] for row in report['files'])
            for forbidden in ('.stdout','.stderr','continuous.json','kernel.stdout','kernel.stderr','.private'):
                self.assertNotIn(forbidden,names)
        for label,mutate in (
          ('sandbox-request-body',lambda value: value.__setitem__('requestBody','SCHEMA_CANARY_9e6b4c2d1a70')),
          ('consumption-authorization',lambda value: value.__setitem__('authorization','SCHEMA_CANARY_9e6b4c2d1a70'))):
            with self.subTest(no_partial_safe_output=label),tempfile.TemporaryDirectory() as td:
                root=Path(td); public=root/'public'; safe=root/'safe'; binding,_=self.full_public_fixture(public)
                names=('sandbox.json',) if label.startswith('sandbox') else ('consumption.json','consumption-independent.json')
                for name in names:
                    value=json.loads((public/name).read_bytes()); mutate(value); self.write_json(public/name,value)
                with mock.patch.object(self.reader,'git_manifest',return_value=(binding,b'manifest')),self.assertRaises((ValueError,TypeError)):
                    self.reader.project_safe(HERE.parents[2],public,'a'*40,'41560358243','1',safe)
                self.assertFalse(safe.exists())

    def test_safe_projection_accepts_reversed_filesystem_enumeration_but_keeps_canonical_report(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); public=root/'public'; safe=root/'safe'; binding,_=self.full_public_fixture(public)
            original_iterdir=Path.iterdir
            def reversed_evidence_iterdir(path):
                rows=tuple(original_iterdir(path))
                return iter(reversed(rows)) if path==safe/'evidence' else iter(rows)
            with mock.patch.object(Path,'iterdir',new=reversed_evidence_iterdir),\
                 mock.patch.object(self.reader,'git_manifest',return_value=(binding,b'manifest')):
                report=self.reader.project_safe(HERE.parents[2],public,'a'*40,'41560358243','1',safe)
                observed=tuple(path.name for path in (safe/'evidence').iterdir())
                readback=self.reader.safe_root(HERE.parents[2],safe,'a'*40,'41560358243','1')
            self.assertEqual(len(observed),len(self.reader.SAFE_EVIDENCE))
            self.assertEqual(set(observed),set(self.reader.SAFE_EVIDENCE))
            self.assertNotEqual(observed,self.reader.SAFE_EVIDENCE)
            self.assertEqual(tuple(row['name'] for row in report['files']),self.reader.SAFE_EVIDENCE)
            self.assertEqual(readback,report)

    def test_safe_evidence_rejects_file_identity_and_semantic_mutants(self):
        marker='SCHEMA_CANARY_9e6b4c2d1a70'
        def descend(value,path):
            for item in path: value=value[item]
            return value
        def inject_json(name,path=()):
            def mutate(root):
                value=json.loads((root/name).read_bytes()); descend(value,path)['authorization']=marker; self.write_json(root/name,value)
            return mutate
        def inject_both(names,path=()):
            def mutate(root):
                for name in names:
                    value=json.loads((root/name).read_bytes()); descend(value,path)['authorization']=marker; self.write_json(root/name,value)
            return mutate
        def replace_json(name,path,value):
            def mutate(root):
                body=json.loads((root/name).read_bytes()); parent=descend(body,path[:-1]); parent[path[-1]]=value; self.write_json(root/name,body)
            return mutate
        def replace_both(names,path,value):
            def mutate(root):
                for name in names:
                    body=json.loads((root/name).read_bytes()); parent=descend(body,path[:-1]); parent[path[-1]]=value; self.write_json(root/name,body)
            return mutate
        def duplicate_key_json(name,key,value):
            def mutate(root):
                raw=(root/name).read_bytes(); need=b'{'; self.assertTrue(raw.startswith(need))
                injected=self.reader.canonical(key)+b':'+self.reader.canonical(value)+b','
                (root/name).write_bytes(need+injected+raw[1:])
            return mutate
        def inject_jsonl(name,row,path=()):
            def mutate(root):
                rows=(root/name).read_bytes().splitlines(); value=json.loads(rows[row]); descend(value,path)['authorization']=marker; rows[row]=self.reader.canonical(value)
                (root/name).write_bytes(b'\n'.join(rows)+b'\n')
            return mutate
        def replace_jsonl(name,row,path,value):
            def mutate(root):
                rows=(root/name).read_bytes().splitlines(); body=json.loads(rows[row]); parent=descend(body,path[:-1]); parent[path[-1]]=value; rows[row]=self.reader.canonical(body)
                (root/name).write_bytes(b'\n'.join(rows)+b'\n')
            return mutate
        def inject_http(case,path=()):
            def mutate(root):
                report=json.loads((root/'continuous-recovery-report.json').read_bytes())
                index=[x[0] for x in self.reader.HTTP_CASES].index(case); row=report['http'][index]
                name=f'http-{index+1:03d}.response.json'; body=json.loads((root/name).read_bytes()); descend(body,path)['authorization']=marker
                raw=self.reader.canonical(body); (root/name).write_bytes(raw); row['responseBodySHA256']=self.reader.sha(raw); row['responseBodyB64']=base64.b64encode(raw).decode()
                self.write_json(root/'continuous-recovery-report.json',report)
            return mutate
        def mutate_extra(root): (root/'extra.json').write_bytes(b'{}\n')
        def mutate_missing(root): (root/'http-031.response.json').unlink()
        def mutate_version(root): (root/'go-version.txt').write_bytes(b'go version go1.24.0 linux/amd64\n')
        def mutate_consumption(root): (root/'consumption-independent.json').write_bytes(b'{}\n')
        def mutate_response(root): (root/'http-001.response.json').write_bytes(b'{}\n')
        def mutate_commands(root): (root/'commands.jsonl').write_bytes((root/'commands.jsonl').read_bytes().splitlines(keepends=True)[0])
        def mutate_events(root):
            rows=(root/'process-events.jsonl').read_bytes().splitlines(); value=json.loads(rows[-1]); value['exitCode']=1; rows[-1]=self.reader.canonical(value)
            (root/'process-events.jsonl').write_bytes(b'\n'.join(rows)+b'\n')
        def mutate_host(root):
            value=json.loads((root/'host-after.json').read_bytes()); value['networkNamespace']='net:[9]'; self.write_json(root/'host-after.json',value)
        def mutate_execution(root):
            value=json.loads((root/'execution.json').read_bytes()); value['goExit']=1; self.write_json(root/'execution.json',value)
        def mutate_index(root):
            value=json.loads((root/'http-originals-index.json').read_bytes()); value['sourceCommit']='9'*40; self.write_json(root/'http-originals-index.json',value)
        def mutate_hardlink(root):
            target=root/'http-031.response.json'; target.unlink(); os.link(root/'http-030.response.json',target)
        closed_schema_cases=(
          ('sandbox-top',inject_json('sandbox.json')),('sandbox-binding',inject_json('sandbox.json',('sourceBinding',))),
          ('sandbox-kernel',inject_json('sandbox.json',('kernelCopy',))),
          ('consumption-top',inject_both(('consumption.json','consumption-independent.json'))),
          ('consumption-source',inject_both(('consumption.json','consumption-independent.json'),('source',))),
          ('consumption-source-row',inject_both(('consumption.json','consumption-independent.json'),('source','sourceFiles',0))),
          ('consumption-archive',inject_both(('consumption.json','consumption-independent.json'),('archive',))),
          ('consumption-gzip',inject_both(('consumption.json','consumption-independent.json'),('gzip',))),
          ('consumption-elf',inject_both(('consumption.json','consumption-independent.json'),('elf',))),
          ('consumption-output',inject_both(('consumption.json','consumption-independent.json'),('output',))),
          ('report-top',inject_json('continuous-recovery-report.json')),
          ('report-initial',inject_json('continuous-recovery-report.json',('initial',))),
          ('report-initial-head',inject_json('continuous-recovery-report.json',('initial','head'))),
          ('report-proof',inject_json('continuous-recovery-report.json',('initial','head','proof'))),
          ('report-http-row',inject_json('continuous-recovery-report.json',('http',0))),
          ('report-head-item',inject_json('continuous-recovery-report.json',('heads',0))),
          ('report-head-view',inject_json('continuous-recovery-report.json',('heads',0,'view'))),
          ('report-operation-item',inject_json('continuous-recovery-report.json',('operations',0))),
          ('report-deployment-view',inject_json('continuous-recovery-report.json',('operations',0,'view'))),
          ('report-deployment-transport',inject_json('continuous-recovery-report.json',('operations',0,'view','transport'))),
          ('report-transport-result',inject_json('continuous-recovery-report.json',('operations',0,'view','transport','result'))),
          ('report-observation',inject_json('continuous-recovery-report.json',('operations',0,'view','observation'))),
          ('report-recovery-item',inject_json('continuous-recovery-report.json',('recoveries',0))),
          ('report-recovery-view',inject_json('continuous-recovery-report.json',('recoveries',0,'view'))),
          ('report-calls',inject_json('continuous-recovery-report.json',('callsBefore',))),
          ('report-fault',inject_json('continuous-recovery-report.json',('faultBeforeCleanup',))),
          ('report-native-call',inject_json('continuous-recovery-report.json',('faultBeforeCleanup','nativeCalls',0))),
          ('report-recovery-create',inject_json('continuous-recovery-report.json',('faultBeforeCleanup','recoveryCreates',0))),
          ('report-fault-transport',inject_json('continuous-recovery-report.json',('faultBeforeCleanup','transport'))),
          ('report-fault-step',inject_json('continuous-recovery-report.json',('faultBeforeCleanup','transport','steps',0))),
          ('report-closed-port',inject_json('continuous-recovery-report.json',('closedPorts',0))),
          ('index-top',inject_json('http-originals-index.json')),('index-binding',inject_json('http-originals-index.json',('sourceBinding',))),
          ('index-entry',inject_json('http-originals-index.json',('entries',0))),('execution-top',inject_json('execution.json')),
          ('execution-binding',inject_json('execution.json',('sourceBinding',))),
          ('command-row',inject_jsonl('commands.jsonl',0)),('command-binding',inject_jsonl('commands.jsonl',0,('sourceBinding',))),
          ('command-namespace',inject_jsonl('commands.jsonl',0,('namespace',))),('process-row',inject_jsonl('process-events.jsonl',0)),
          ('host-top',inject_both(('host-before.json','host-after.json'))),
          ('http-envelope',inject_http('INITIAL_HEAD')),('http-head-result',inject_http('INITIAL_HEAD',('result',))),
          ('http-candidates-result',inject_http('FIRST_CANDIDATES',('result',))),
          ('http-candidate-row',inject_http('FIRST_CANDIDATES',('result','candidates',0))),
          ('http-deployment-result',inject_http('FIRST_UNKNOWN_INSPECT',('result',))),
          ('http-deployment-transport',inject_http('FIRST_UNKNOWN_INSPECT',('result','transport'))),
          ('http-deployment-transport-result',inject_http('FIRST_UNKNOWN_INSPECT',('result','transport','result'))),
          ('http-deployment-observation',inject_http('FIRST_UNKNOWN_INSPECT',('result','observation'))),
          ('http-recovery-result',inject_http('FIRST_RECOVERY_INSPECT_COMPLETED',('result',))),
          ('report-operation-id-alias',replace_json('continuous-recovery-report.json',('operations',0,'view','operationId'),'SCHEMA_CANARY_9e6b4c2d1a70')),
          ('report-recovery-id-alias',replace_json('continuous-recovery-report.json',('recoveries',0,'view','recoveryId'),'SCHEMA_CANARY_9e6b4c2d1a70')),
          ('report-observation-alias',replace_json('continuous-recovery-report.json',('operations',0,'view','observation','conclusion'),'SCHEMA_CANARY_9e6b4c2d1a70')),
          ('sandbox-schema',replace_json('sandbox.json',('schema',),'unknown')),
          ('sandbox-bool-alias',replace_json('sandbox.json',('noNewPrivileges',),1)),
          ('sandbox-missing-kernel-key',lambda root: (lambda value: (value['kernelCopy'].pop('mode'),self.write_json(root/'sandbox.json',value)))(json.loads((root/'sandbox.json').read_bytes()))),
          ('consumption-schema',lambda root: [self.write_json(root/name,{**json.loads((root/name).read_bytes()),'schema':'unknown'}) for name in ('consumption.json','consumption-independent.json')]),
          ('consumption-bool-alias',lambda root: [self.write_json(root/name,{**json.loads((root/name).read_bytes()),'runtimeExecuted':0}) for name in ('consumption.json','consumption-independent.json')]),
          ('consumption-list-type',replace_both(('consumption.json','consumption-independent.json'),('source','sourceFiles'),{})),
          ('consumption-duplicate-key',lambda root: [duplicate_key_json(name,'runtimeExecuted','SCHEMA_CANARY_9e6b4c2d1a70')(root) for name in ('consumption.json','consumption-independent.json')]),
          ('host-duplicate-key',duplicate_key_json('host-before.json','networkNamespace','SCHEMA_CANARY_9e6b4c2d1a70')),
          ('http-duplicate-key',lambda root: (lambda report,name,body,raw: ( (root/name).write_bytes(raw), report['http'][0].__setitem__('responseBodySHA256',self.reader.sha(raw)), report['http'][0].__setitem__('responseBodyB64',base64.b64encode(raw).decode()), self.write_json(root/'continuous-recovery-report.json',report) ))(
              json.loads((root/'continuous-recovery-report.json').read_bytes()),'http-001.response.json',json.loads((root/'http-001.response.json').read_bytes()),b'{'+self.reader.canonical('boundary')+b':'+self.reader.canonical('SCHEMA_CANARY_9e6b4c2d1a70')+b','+(root/'http-001.response.json').read_bytes()[1:])),
          ('report-deep-bool-alias',replace_json('continuous-recovery-report.json',('initial','head','proof','production'),0)),
          ('execution-bool-alias',replace_json('execution.json',('production',),0)),
          ('command-bool-int-alias',replace_jsonl('commands.jsonl',0,('exitCode',),False)),
          ('process-bool-int-alias',replace_jsonl('process-events.jsonl',1,('pid',),True)))
        for label,mutate in (('extra',mutate_extra),('missing',mutate_missing),('go-version',mutate_version),('consumption',mutate_consumption),
          ('response',mutate_response),('commands',mutate_commands),('events',mutate_events),('host',mutate_host),('execution',mutate_execution),('index',mutate_index),
          ('hardlink',mutate_hardlink),*closed_schema_cases):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as td:
                root=Path(td)/'evidence'; binding,_=self.safe_evidence_fixture(root); mutate(root)
                with mock.patch.object(self.reader,'git_manifest',return_value=(binding,b'manifest')),self.assertRaises((ValueError,TypeError,FileNotFoundError)):
                    self.reader.safe_verification(HERE.parents[2],root,'a'*40,'41560358243','1')

    def test_safe_root_rejects_ten_identity_shape_and_digest_mutants(self):
        cases=('extra-root','missing-verification','extra-field','bad-schema','bad-run','bad-attempt','wrong-commit','bad-digest','bad-count','raw-member',
          'sandbox-recomputed-digest','consumption-recomputed-digests')
        for label in cases:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as td:
                base=Path(td); evidence=base/'evidence'; binding,_=self.safe_evidence_fixture(evidence)
                with mock.patch.object(self.reader,'git_manifest',return_value=(binding,b'manifest')):
                    report=self.reader.safe_verification(HERE.parents[2],evidence,'a'*40,'41560358243','1')
                self.write_json(base/'verification.json',report)
                args=['a'*40,'41560358243','1']
                if label=='extra-root': (base/'extra').write_bytes(b'x')
                elif label=='missing-verification': (base/'verification.json').unlink()
                elif label in ('extra-field','bad-schema','bad-digest','bad-count'):
                    value=json.loads((base/'verification.json').read_bytes())
                    if label=='extra-field': value['unknown']=True
                    elif label=='bad-schema': value['schema']='wrong'
                    elif label=='bad-digest': value['files'][0]['sha256']='0'*64
                    else: value['httpResponses']=30
                    self.write_json(base/'verification.json',value)
                elif label=='bad-run': args[1]='01'
                elif label=='bad-attempt': args[2]='0'
                elif label=='wrong-commit': args[0]='9'*40
                elif label=='raw-member': (evidence/'continuous.json').write_bytes(b'raw\n')
                else:
                    names=('sandbox.json',) if label.startswith('sandbox') else ('consumption.json','consumption-independent.json')
                    for name in names:
                        value=json.loads((evidence/name).read_bytes()); value['authorization']='SCHEMA_CANARY_9e6b4c2d1a70'; self.write_json(evidence/name,value)
                    value=json.loads((base/'verification.json').read_bytes())
                    for item in value['files']:
                        if item['name'] in names:
                            raw=(evidence/item['name']).read_bytes(); item['bytes']=len(raw); item['sha256']=self.reader.sha(raw)
                    value['evidenceSetSHA256']=self.reader.set_digest('chengwang.mihomo-continuous-recovery-safe-evidence-set/v1',value['files'])
                    self.write_json(base/'verification.json',value)
                with mock.patch.object(self.reader,'git_manifest',return_value=(binding,b'manifest')),self.assertRaises((ValueError,TypeError,FileNotFoundError)):
                    self.reader.safe_root(HERE.parents[2],base,*args)

    def worker_outputs(self,report,forbidden):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); service=root/'service'; service.mkdir()
            report_path=service/'continuous-recovery-report.private.json'
            report_path.write_bytes(self.worker.canonical(report)+b'\n')
            (service/'kernel.stdout').write_bytes(b''); (service/'kernel.stderr').write_bytes(b'')
            binding={'sourceCommit':'a'*40}
            with mock.patch.object(self.worker,'REPORT',report_path),mock.patch.object(self.worker,'SERVICE',service), \
                 mock.patch.object(self.worker,'adapter',return_value=Adapter(root)),mock.patch.object(self.worker.os,'fsync'), \
                 mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True):
                return self.worker.safe_report_outputs(binding,list(forbidden),0,1)

    def test_reader_accepts_complete_synthetic_shape_and_rejects_material_mutants(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); report=self.fixture(root); binding={'schema':'binding'}
            self.assertEqual(len(self.reader.validate_report(report,'a'*40,root,binding)),31)
            stop_before_wait=copy.deepcopy(report); pre=stop_before_wait['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN',
              'KERNEL_OS_STOP_KILL_ATTEMPT','KERNEL_OS_STOP_KILL_RETURN','KERNEL_OS_WAIT_RETURN'),1)]
            stop_before_wait['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            stop_before_wait['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
            self.assertEqual(len(self.reader.validate_report(stop_before_wait,'a'*40,root,binding)),31)
            wait_before_term_return=copy.deepcopy(report); pre=wait_before_term_return['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_WAIT_RETURN','KERNEL_OS_TERM_RETURN'),1)]
            wait_before_term_return['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            wait_before_term_return['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
            self.assertEqual(len(self.reader.validate_report(wait_before_term_return,'a'*40,root,binding)),31)
            cancel_then_stop=copy.deepcopy(report); pre=cancel_then_stop['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'KERNEL_OS_CANCEL_KILL_ATTEMPT','OWNED_STOP_HELPER_ENTER','KERNEL_OS_CANCEL_KILL_RETURN',
              'KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_WAIT_RETURN'),1)]
            cancel_then_stop['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            cancel_then_stop['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
            self.assertEqual(len(self.reader.validate_report(cancel_then_stop,'a'*40,root,binding)),31)
            wait_inside_stop=copy.deepcopy(report); pre=wait_inside_stop['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_STOP_KILL_ATTEMPT',
              'KERNEL_OS_WAIT_RETURN','KERNEL_OS_STOP_KILL_RETURN'),1)]
            wait_inside_stop['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            wait_inside_stop['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
            self.assertEqual(len(self.reader.validate_report(wait_inside_stop,'a'*40,root,binding)),31)
            settled_before_helper=copy.deepcopy(report); pre=settled_before_helper['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'KERNEL_OS_WAIT_RETURN','OWNED_STOP_HELPER_ENTER'),1)]
            settled_before_helper['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            settled_before_helper['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
            self.assertEqual(len(self.reader.validate_report(settled_before_helper,'a'*40,root,binding)),31)
            cancel_without_term=copy.deepcopy(report); pre=cancel_without_term['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'KERNEL_OS_CANCEL_KILL_ATTEMPT','OWNED_STOP_HELPER_ENTER','KERNEL_OS_CANCEL_KILL_RETURN','KERNEL_OS_WAIT_RETURN'),1)]
            cancel_without_term['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            cancel_without_term['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
            self.assertEqual(len(self.reader.validate_report(cancel_without_term,'a'*40,root,binding)),31)
            for snapshot in ('faultBeforeCleanup','faultAfterCleanup','faultClosed'):
                passthrough=report[snapshot]['transport']['steps'][1]
                self.assertIsNone(passthrough['bodyBytes']); self.assertIsNone(passthrough['eofObserved']); self.assertIsNone(passthrough['closeSucceeded'])
            outputs,worker_report,_=self.worker_outputs(report,[])
            self.assertEqual(worker_report['outcome'],'PASS')
            self.assertEqual(json.loads(outputs['http-originals-index.json'])['entries'][-1]['caseActor'],'CASE_ACTOR_VIEWER')
            partial=copy.deepcopy(report); partial['outcome']='FAIL'; partial['failureCode']='HTTP_RESULT'; partial['http']=partial['http'][:26]
            partial['http'][-1]['statusCode']=503
            outputs,worker_report,_=self.worker_outputs(partial,[])
            self.assertEqual(worker_report['outcome'],'FAIL'); self.assertEqual(len(json.loads(outputs['http-originals-index.json'])['entries']),26)
            self.assertEqual(outputs['http-026.response.json'],base64.b64decode(partial['http'][-1]['responseBodyB64']))
            with self.assertRaises((ValueError,TypeError)):
                self.reader.validate_report(partial,'a'*40,root,binding)
            actor_forbidden=self.worker.encoded_secret_variants(
              b'CASE_ACTOR_ADMIN','CONFIG_A','JSON_OTHER_SCALAR',False,False,'NOT_APPLICABLE')
            with self.assertRaises(ValueError): self.worker_outputs(partial,actor_forbidden)
            unobserved=copy.deepcopy(partial); unobserved['http']=unobserved['http'][:6]
            unobserved['http'][-1].update(statusCode=None,responseBodySHA256='',responseBodyB64=None,errorClass='RESPONSE_NOT_OBSERVED')
            outputs,_,_=self.worker_outputs(unobserved,[]); last=json.loads(outputs['http-originals-index.json'])['entries'][-1]
            self.assertEqual((last['name'],last['bytes'],last['sha256']),(None,0,'')); self.assertNotIn('http-006.response.json',outputs)
            empty_prefix=copy.deepcopy(partial); empty_prefix['http']=[]
            outputs,_,_=self.worker_outputs(empty_prefix,[])
            self.assertEqual(json.loads(outputs['http-originals-index.json'])['entries'],[])
            full_failure=copy.deepcopy(report); full_failure['outcome']='FAIL'; full_failure['failureCode']='CLEANUP'
            outputs,_,_=self.worker_outputs(full_failure,[])
            self.assertEqual(len(json.loads(outputs['http-originals-index.json'])['entries']),31)
            bounded_body=copy.deepcopy(partial); raw=b'x'*((16<<10)+1)
            bounded_body['http'][-1].update(statusCode=503,responseBodySHA256=self.reader.sha(raw),
              responseBodyB64=base64.b64encode(raw).decode(),errorClass='BODY')
            outputs,_,_=self.worker_outputs(bounded_body,[]); self.assertEqual(outputs['http-026.response.json'],raw)
            def envelope_mutant(key,value):
                result=copy.deepcopy(partial); row=result['http'][0]
                envelope=json.loads(base64.b64decode(row['responseBodyB64'],validate=True)); envelope[key]=value
                raw=json.dumps(envelope,separators=(',',':')).encode()+b'\n'
                row['responseBodySHA256']=self.reader.sha(raw); row['responseBodyB64']=base64.b64encode(raw).decode()
                return result
            capture_mutants=[]
            value=copy.deepcopy(partial); value['schema']='chengwang.mihomo-continuous-recovery-http-experiment/v2'; capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][0]['caseActor']='CASE_ACTOR_ADMIN'; capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][0]['role']=value['http'][0].pop('caseActor'); capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][0]['sequence']=True; capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][0]['statusCode']=503; capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][0]['errorClass']='BODY'; capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][0].update(
              statusCode=None,responseBodySHA256='',responseBodyB64=None,errorClass='RESPONSE_NOT_OBSERVED'); capture_mutants.append(value)
            capture_mutants.extend((envelope_mutant('boundary','WRONG'),envelope_mutant('code','wrong'),
              envelope_mutant('stateMayHaveChanged',True),envelope_mutant('result','not-an-object')))
            value=copy.deepcopy(partial); value['http'][-1]['statusCode']=True; capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'][-1]['errorClass']='UNKNOWN'; capture_mutants.append(value)
            value=copy.deepcopy(bounded_body); raw=b'x'*((16<<10)+2); value['http'][-1].update(
              responseBodySHA256=self.reader.sha(raw),responseBodyB64=base64.b64encode(raw).decode()); capture_mutants.append(value)
            value=copy.deepcopy(partial); value['http'].append(copy.deepcopy(report['http'][25])); capture_mutants.append(value)
            value=copy.deepcopy(partial); value['outcome']='PASS'; value['failureCode']='NONE'; capture_mutants.append(value)
            for index,value in enumerate(capture_mutants):
                with self.subTest(capture_mutant=index),self.assertRaises((ValueError,TypeError)): self.worker_outputs(value,[])
            mutants=[]
            for mutate in (
              lambda x:x.__setitem__('schema','chengwang.mihomo-continuous-recovery-http-experiment/v2'),
              lambda x:x['faultBeforeCleanup'].__setitem__('schema','chengwang.mihomo-continuous-recovery-response-loss/v1'),
              lambda x:(x['http'][0].__setitem__('role','viewer'),x['http'][0].pop('caseActor')),
              lambda x:x['http'][0].__setitem__('case','UNKNOWN_CASE'),
              lambda x:x['http'][0].__setitem__('caseActor','CASE_ACTOR_ADMIN'),
              lambda x:x['http'][0].__setitem__('sequence',True),
              lambda x:x['http'][0].__setitem__('statusCode',200.0),
              lambda x:x['http'][0].__setitem__('responseBodySHA256','0'*64),
              lambda x:x['callsAfter'].__setitem__('doInvocations',True),
              lambda x:x['initial'].__setitem__('walSchema','chengwang.mihomo-lifecycle/v2'),
              lambda x:x.__setitem__('privateWALDecodedByTest',True),
              lambda x:x['heads'][5]['view'].__setitem__('headSHA256',x['heads'][3]['view']['headSHA256']),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('action','PASS'),
              lambda x:x['faultClosed']['transport']['steps'][1].__setitem__('bodyBytes',0),
              lambda x:x['faultClosed']['transport']['steps'][1].__setitem__('eofObserved',True),
              lambda x:x['faultClosed']['transport']['steps'][1].__setitem__('closeSucceeded',True),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('bodyBytes',None),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('bodyBytes',False),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('bodyBytes',0.0),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('eofObserved',None),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('eofObserved',False),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('closeSucceeded',None),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('closeSucceeded',False),
              lambda x:x['faultClosed'].__setitem__('recoveryCreatesBounded',False),
              lambda x:x['faultClosed']['recoveryCreates'][3].__setitem__('stage','REJECTED_PLAN'),
              lambda x:x['closedPorts'][0].__setitem__('accepted',True)):
                value=copy.deepcopy(report); mutate(value); mutants.append(value)
            for value in mutants:
                with self.subTest(mutant=mutants.index(value)),self.assertRaises((ValueError,TypeError)): self.reader.validate_report(value,'a'*40,root,binding)

    def test_reader_rejects_consistently_rewritten_nested_and_native_mutants(self):
        def http(case,mutate): return lambda report,root:self.rewrite_case(report,root,case,mutate)
        def retained_head(index,field,value):
            def mutate(report,root):
                report['heads'][index]['view'][field]=value
                self.rewrite_case(report,root,report['heads'][index]['stage']+'_HEAD',lambda view:view.__setitem__(field,value))
            return mutate
        def recovery_target(report,root):
            value='7'*64
            for case in ('FIRST_RECOVERY_CREATE','FIRST_RECOVERY_INSPECT_PLANNED','FIRST_RECOVERY_APPROVE','FIRST_RECOVERY_EXECUTE','FIRST_RECOVERY_INSPECT_COMPLETED'):
                self.rewrite_case(report,root,case,lambda view:view.__setitem__('targetArtifactRecordSHA256',value))
            report['recoveries'][0]['view']['targetArtifactRecordSHA256']=value
            report['heads'][2]['view']['artifactRecordSHA256']=value
            self.rewrite_case(report,root,'FIRST_RECOVERED_HEAD',lambda view:view.__setitem__('artifactRecordSHA256',value))
        def reverse_native(report,root):
            calls=report['faultBeforeCleanup']['nativeCalls']; calls[0],calls[1]=calls[1],calls[0]
        def cleanup_wrong_core(report,root):
            prefix=len(report['faultBeforeCleanup']['nativeCalls'])
            for name in ('faultAfterCleanup','faultClosed'):
                for call in report[name]['nativeCalls'][prefix:]: call['core']=2
        def cleanup_wrong_order(report,root):
            prefix=len(report['faultBeforeCleanup']['nativeCalls'])
            suffix=report['faultAfterCleanup']['nativeCalls'][prefix:]
            suffix[1]['kind'],suffix[2]['kind']=suffix[2]['kind'],suffix[1]['kind']
            report['faultClosed']['nativeCalls']=copy.deepcopy(report['faultAfterCleanup']['nativeCalls'])
        def final_start_reuses_first_core(report,root):
            for name in ('faultBeforeCleanup','faultAfterCleanup','faultClosed'):
                starts=[call for call in report[name]['nativeCalls'] if call['kind'] in ('KERNEL_OS_START_ATTEMPT','KERNEL_OS_START_RETURN')]
                starts[-2]['core']=starts[-1]['core']=2
        def cleanup_kill_before_term_return(report,root):
            pre=report['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_STOP_KILL_ATTEMPT',
              'KERNEL_OS_TERM_RETURN','KERNEL_OS_STOP_KILL_RETURN','KERNEL_OS_WAIT_RETURN'),1)]
            report['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            report['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
        def cleanup_kill_return_before_attempt(report,root):
            pre=report['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate((
              'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN',
              'KERNEL_OS_STOP_KILL_RETURN','KERNEL_OS_STOP_KILL_ATTEMPT','KERNEL_OS_WAIT_RETURN'),1)]
            report['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            report['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
        def cleanup_fixed_suffix(report,kinds):
            pre=report['faultBeforeCleanup']['nativeCalls']; sequence=pre[-1]['sequence']
            suffix=[{'sequence':sequence+i,'kind':kind,'core':3,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate(kinds,1)]
            report['faultAfterCleanup']['nativeCalls']=copy.deepcopy(pre+suffix)
            report['faultClosed']['nativeCalls']=copy.deepcopy(pre+suffix)
        mutants=(
          ('deployment-boundary',http('FIRST_UNKNOWN_CREATE',lambda view:view.__setitem__('boundary','WRONG'))),
          ('deployment-replayed',http('FIRST_UNKNOWN_CREATE',lambda view:view.__setitem__('replayed',True))),
          ('deployment-planned-flags',http('FIRST_UNKNOWN_CREATE',lambda view:view.__setitem__('writeBlocked',True))),
          ('recovery-boundary',http('FIRST_RECOVERY_CREATE',lambda view:view.__setitem__('boundary','WRONG'))),
          ('recovery-planned-flags',http('FIRST_RECOVERY_CREATE',lambda view:view.__setitem__('writeBlocked',False))),
          ('candidate-schema',http('FIRST_CANDIDATES',lambda view:view.__setitem__('schema','WRONG'))),
          ('candidate-boundary',http('FIRST_CANDIDATES',lambda view:view.__setitem__('boundary','WRONG'))),
          ('candidate-proof',http('FIRST_CANDIDATES',lambda view:view['proof'].__setitem__('production',True))),
          ('candidate-count',http('FIRST_CANDIDATES',lambda view:view.__setitem__('candidates',view['candidates'][:1]))),
          ('candidate-current',http('FIRST_CANDIDATES',lambda view:[row.__setitem__('isCurrent',False) for row in view['candidates']])),
          ('candidate-current-stable-record',http('FIRST_CANDIDATES',lambda view:view['candidates'][0].__setitem__('recordSHA256','7'*64))),
          ('candidate-current-stable-config',http('ACK_CANDIDATES',lambda view:view['candidates'][1].__setitem__('configSHA256','7'*64))),
          ('candidate-record-create-binding',http('FIRST_CANDIDATES',lambda view:view['candidates'][1].__setitem__('recordSHA256','7'*64))),
          ('candidate-config-create-binding',http('FIRST_CANDIDATES',lambda view:view['candidates'][1].__setitem__('configSHA256','7'*64))),
          ('transport-state',lambda report,root:report['faultBeforeCleanup']['transport'].__setitem__('state','CLOSED')),
          ('native-gap',lambda report,root:report['faultBeforeCleanup']['nativeCalls'][1].__setitem__('sequence',103)),
          ('native-reverse',reverse_native),
          ('native-positive-kind-core-zero',lambda report,root:report['faultBeforeCleanup']['nativeCalls'][0].__setitem__('core',0)),
          ('native-zero-kind-core-positive',lambda report,root:report['faultBeforeCleanup']['nativeCalls'][5].__setitem__('core',1)),
          ('cleanup-wrong-final-core',cleanup_wrong_core),
          ('cleanup-wrong-order',cleanup_wrong_order),
          ('final-start-reuses-first-core',final_start_reuses_first_core),
          ('cleanup-kill-before-term-return',cleanup_kill_before_term_return),
          ('cleanup-kill-return-before-attempt',cleanup_kill_return_before_attempt),
          ('cleanup-generic-kill',lambda report,root:cleanup_fixed_suffix(report,(
            'OWNED_STOP_HELPER_ENTER','KERNEL_OS_KILL_ATTEMPT','KERNEL_OS_KILL_RETURN','KERNEL_OS_WAIT_RETURN'))),
          ('cleanup-identity-kill',lambda report,root:cleanup_fixed_suffix(report,(
            'OWNED_STOP_HELPER_ENTER','KERNEL_OS_IDENTITY_KILL_ATTEMPT','KERNEL_OS_IDENTITY_KILL_RETURN','KERNEL_OS_WAIT_RETURN'))),
          ('cleanup-origin-mismatch',lambda report,root:cleanup_fixed_suffix(report,(
            'OWNED_STOP_HELPER_ENTER','KERNEL_OS_CANCEL_KILL_ATTEMPT','KERNEL_OS_STOP_KILL_RETURN','KERNEL_OS_WAIT_RETURN'))),
          ('cleanup-crossed-pairs',lambda report,root:cleanup_fixed_suffix(report,(
            'OWNED_STOP_HELPER_ENTER','KERNEL_OS_CANCEL_KILL_ATTEMPT','KERNEL_OS_TERM_ATTEMPT',
            'KERNEL_OS_CANCEL_KILL_RETURN','KERNEL_OS_TERM_RETURN','KERNEL_OS_WAIT_RETURN'))),
          ('cleanup-repeat-cancel',lambda report,root:cleanup_fixed_suffix(report,(
            'KERNEL_OS_CANCEL_KILL_ATTEMPT','KERNEL_OS_CANCEL_KILL_RETURN','KERNEL_OS_CANCEL_KILL_ATTEMPT',
            'KERNEL_OS_CANCEL_KILL_RETURN','OWNED_STOP_HELPER_ENTER','KERNEL_OS_WAIT_RETURN'))),
          ('cleanup-stop-without-term',lambda report,root:cleanup_fixed_suffix(report,(
            'OWNED_STOP_HELPER_ENTER','KERNEL_OS_STOP_KILL_ATTEMPT','KERNEL_OS_STOP_KILL_RETURN','KERNEL_OS_WAIT_RETURN'))),
          ('cleanup-cancel-return-after-wait',lambda report,root:cleanup_fixed_suffix(report,(
            'KERNEL_OS_CANCEL_KILL_ATTEMPT','OWNED_STOP_HELPER_ENTER','KERNEL_OS_WAIT_RETURN','KERNEL_OS_CANCEL_KILL_RETURN'))),
          ('cleanup-wait-enter-after-return',lambda report,root:cleanup_fixed_suffix(report,(
            'OWNED_STOP_HELPER_ENTER','KERNEL_OS_WAIT_RETURN','KERNEL_OS_WAIT_ENTER'))),
          ('head-previous',retained_head(2,'previousHeadSHA256','7'*64)),
          ('head-artifact',retained_head(2,'artifactRecordSHA256','7'*64)),
          ('head-config',retained_head(3,'configSHA256','7'*64)),
          ('published-head-unchanged',retained_head(2,'headSHA256','a'*64)),
          ('ack-head-active-cleared',retained_head(3,'activeOperationId',None)),
          ('ack-head-active-foreign',retained_head(3,'activeOperationId','foreign-op')),
          ('deployment-approved-head-generation',http('ORDINARY_ACK_APPROVE',lambda view:view.__setitem__('headGeneration',99))),
          ('deployment-approved-head-sha',http('ORDINARY_ACK_APPROVE',lambda view:view.__setitem__('headSHA256','7'*64))),
          ('recovery-approved-head-generation',http('FIRST_RECOVERY_APPROVE',lambda view:view.__setitem__('headGeneration',99))),
          ('recovery-approved-head-sha',http('FIRST_RECOVERY_APPROVE',lambda view:view.__setitem__('headSHA256','7'*64))),
          ('recovery-approved-unknown-operation',http('FIRST_RECOVERY_APPROVE',lambda view:view.__setitem__('unknownOperationId','foreign-op'))),
          ('recovery-approved-original-plan',http('FIRST_RECOVERY_APPROVE',lambda view:view.__setitem__('originalPlanSHA256','7'*64))),
          ('recovery-target-operation-binding',recovery_target))
        for label,mutate in mutants:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as td:
                root=Path(td); report=self.fixture(root); mutate(report,root)
                with self.assertRaises((ValueError,TypeError)): self.reader.validate_report(report,'a'*40,root,{'schema':'binding'})

if __name__=='__main__': unittest.main()
