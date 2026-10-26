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
    def setUpClass(cls): cls.reader=load('continuous_reader', 'check_continuous_recovery_api.py'); cls.worker=load('continuous_worker','continuous_recovery_api_worker.py')

    def test_contract_excludes_old_fault_tags_and_has_independent_capture(self):
        contract=json.loads((HERE/'continuous_recovery_api_contract.json').read_bytes())
        self.assertEqual(contract['schema'],'chengwang.mihomo-continuous-recovery-contract/v2')
        self.assertEqual(contract['reportSchema'],'chengwang.mihomo-continuous-recovery-http-experiment/v3')
        self.assertEqual(contract['faultObservationSchema'],'chengwang.mihomo-continuous-recovery-response-loss/v2')
        self.assertEqual(contract['goTimeoutSeconds'],210); self.assertEqual(contract['outerGoTimeoutSeconds'],240)
        self.assertFalse(set(contract['exactTags']) & set(contract['forbiddenTags']))
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
        heads=[self.head(1,h0,record_a,config_a,False),self.head(1,h0,record_a,config_a,True,'op1'),
          self.head(2,h1,record_b,config_b,False,None,h0),self.head(3,h2,record_a,config_a,False,'op2',h1),
          self.head(3,h2,record_a,config_a,True,'op3',h1),self.head(4,h3,record_b,config_b,False,None,h2)]
        ops=[self.op('op1','UNKNOWN',1,h0,h0,record_b,config_b,True,False,4),self.op('op2','COMPLETED',3,h1,h2,record_a,config_a,False,True,10),self.op('op3','UNKNOWN',3,h2,h2,record_b,config_b,True,False,14)]
        rec=[self.recovery('rec1','op1',2,h0,h1,record_b,config_b,7),self.recovery('rec2','op3',4,h2,h3,record_b,config_b,17)]
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
