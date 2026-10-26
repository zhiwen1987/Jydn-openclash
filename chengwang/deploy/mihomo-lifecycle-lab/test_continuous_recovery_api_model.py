import base64
import copy
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
        self.assertEqual(contract['goTimeoutSeconds'],210); self.assertEqual(contract['outerGoTimeoutSeconds'],240)
        self.assertFalse(set(contract['exactTags']) & set(contract['forbiddenTags']))
        lifecycle=(HERE.parents[1]/'internal/mihomodeploy/lifecycle.go').read_text(encoding='utf8')
        actual=re.search(r'^const lifecycleSchemaV2 = "([^"]+)"$',lifecycle,re.M)
        self.assertIsNotNone(actual); self.assertEqual(actual.group(1),self.reader.WAL_SCHEMA)
        harness=(HERE.parents[1]/'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go').read_text(encoding='utf8')
        self.assertIn('initial.WALSchema != "'+self.reader.WAL_SCHEMA+'"',harness)
        self.assertNotIn('chengwang.mihomo-lifecycle/v2',harness)
        self.assertIn('h.call(stage+"_INSPECT", "viewer", http.MethodGet',harness)
        self.assertNotIn('h.call(stage+"_INSPECT", "auditor", http.MethodGet',harness)
        deployment_inspects=[row for row in self.reader.HTTP_CASES if row[0] in
          ('FIRST_UNKNOWN_INSPECT','ORDINARY_ACK_INSPECT','SECOND_UNKNOWN_INSPECT')]
        recovery_inspects=[row for row in self.reader.HTTP_CASES if '_RECOVERY_INSPECT_' in row[0]]
        self.assertEqual(len(deployment_inspects),3); self.assertTrue(all(row[1]=='viewer' for row in deployment_inspects))
        self.assertEqual(len(recovery_inspects),4); self.assertTrue(all(row[1]=='auditor' for row in recovery_inspects))
        self.assertEqual(frozenset(row[0] for row in self.reader.HTTP_CASES),self.worker.HTTP_DIAGNOSTIC_CASES)
        authz=(HERE.parents[1]/'internal/authz/model.go').read_text(encoding='utf8')
        role_pairs=re.findall(r'Role(Viewer|Operator|Approver|Auditor|Admin)\s+Role\s*=\s*"([^"]+)"',authz)
        self.assertEqual({value.encode():name.upper() for name,value in role_pairs},self.worker.PUBLIC_IDENTITY_ROLE_LABELS)
        policy_test=(HERE.parents[1]/'internal/authz/policy_test.go').read_text(encoding='utf8')
        viewer=re.search(r'RoleViewer:\s*\{([^}]*)\}',policy_test,re.S); auditor=re.search(r'RoleAuditor:\s*\{([^}]*)\}',policy_test,re.S)
        self.assertIsNotNone(viewer); self.assertIsNotNone(auditor)
        self.assertIn('ActionReadResource: true',viewer.group(1)); self.assertNotIn('ActionReadResource',auditor.group(1))
        recovery_policy=(HERE.parents[1]/'internal/authz/lab_recovery.go').read_text(encoding='utf8')
        recovery_read=re.search(r'case ActionReadLabRecovery:(.*?)case ActionPrepareLabRecovery',recovery_policy,re.S)
        self.assertIsNotNone(recovery_read); self.assertIn('RoleAuditor',recovery_read.group(1))
        plan=(HERE.parents[1]/'internal/mihomodeploy/plan.go').read_text(encoding='utf8')
        runtime=(HERE.parents[1]/'internal/serverruntime/runtime.go').read_text(encoding='utf8')
        environment=re.search(r'LabEnvironment\s*=\s*"([^"]+)"',plan)
        self.assertIsNotNone(environment); self.assertEqual(self.worker.PUBLIC_LAB_ENVIRONMENT,environment.group(1))
        self.assertIn('log.Printf("chengwang listening (mode=%s)", c.Mode)',runtime)
        source=(HERE/'continuous_recovery_api_worker.py').read_text(encoding='utf8')
        self.assertIn('def capture(',source); self.assertNotIn('a.capture(',source); self.assertNotIn('apply_worker.capture',source)
        self.assertIn("cwd='/tmp/mihomo-apply-source'",source)
        self.assertIn('return outputs,report,forbidden',source)
        self.assertIn("fence_outputs(outputs,forbidden,'REPORT_AND_HTTP_OUTPUTS'",source)
        self.assertIn("fence_outputs(outputs,forbidden,'ALL_GENERIC_AND_REPORT_OUTPUTS'",source)
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
                      'encodingVariant':variant})
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
          ('UNKNOWN',False,None,False,None,None))
        self.assertNotIn(unknown_code,str(self.worker.report_diagnostic_status({'failureCode':unknown_code,'outcome':'FAIL'})))
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL',
          'http':[{'case':'FIRST_UNKNOWN_INSPECT','statusCode':403,'errorClass':'NONE'}]}),
          ('HTTP_RESULT',False,'FIRST_UNKNOWN_INSPECT',True,403,'NONE'))
        for invalid in (True,403.0,99,600):
            with self.subTest(invalid_status=invalid):
                self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL',
                  'http':[{'case':'model-unknown-case','statusCode':invalid,'errorClass':'model-unknown-error'}]}),
                  ('HTTP_RESULT',False,'UNKNOWN',False,None,'UNKNOWN'))
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL','http':{}}),
          ('HTTP_RESULT',False,'UNKNOWN',False,None,'UNKNOWN'))
        self.assertEqual(self.worker.report_diagnostic_status({'failureCode':'HTTP_RESULT','outcome':'FAIL','http':[]}),
          ('HTTP_RESULT',False,None,False,None,None))
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
              'underlyingRoundTrips':1,'statusCode':204,'bodyBytes':0,'eofObserved':True,'closeSucceeded':True,'injected':loss,'failureCode':None})
        return {'schema':'chengwang.mihomo-continuous-recovery-response-loss/v1','state':state,'boundOperations':3,'observedResults':3,
          'initialCore':1,'recoveredCore':2,'nativeCallsBounded':True,'nativeCalls':calls,
          'transport':{'schema':'chengwang.mihomo-reload-response-loss-schedule/v1','state':'CLOSED' if state=='CLOSED' else 'TERMINAL',
            'boundChildren':3,'underlyingRoundTrips':3,'injected':2,'steps':steps}}
    def candidates(self,current,record_a,config_a,record_b,config_b):
        return {'schema':'chengwang.mihomo-lab-candidates-view/v1','boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF',
          'candidates':[{'name':'local-a','recordSHA256':record_a,'configSHA256':config_a,'sourceSpecSHA256':'e'*64,'isCurrent':current=='a'},
                        {'name':'local-b','recordSHA256':record_b,'configSHA256':config_b,'sourceSpecSHA256':'f'*64,'isCurrent':current=='b'}],
          'writeBlocked':False,'proof':self.proof()}
    def call(self,sequence,case,role,method,path,status,result):
        body=json.dumps({'boundary':'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF','code':'mihomo_lab_ok',
          'stateMayHaveChanged':method=='POST','result':result},separators=(',',':')).encode()+b'\n'
        return {'sequence':sequence,'case':case,'role':role,'method':method,'path':path,'requestBodySHA256':self.reader.sha(b'' if method=='GET' else b'model'),
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
          self.head(2,h1,record_b,config_b,False,None,h0),self.head(3,h2,record_a,config_a,False,None,h1),
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
            case,role,method,path,status=want; row,body=self.call(i,case,role,method,path or dynamic[case],status,result[case]); http.append(row); (root/f'http-{i:03d}.response.json').write_bytes(body)
        native=(('KERNEL_OS_START_ATTEMPT',1),('KERNEL_OS_START_RETURN',1),('RECOVERY_STOP_DISPATCH',1),('RECOVERY_START_DISPATCH',0),('SYNTAX_OS_START_ATTEMPT',0),('SYNTAX_OS_START_RETURN',0))
        pre=[{'sequence':100+i,'kind':kind,'core':core,'at':'2026-10-26T00:00:00Z'} for i,(kind,core) in enumerate(native,1)]
        post=pre+[{'sequence':100+i+len(pre),'kind':kind,'core':2,'at':'2026-10-26T00:00:01Z'} for i,kind in enumerate(('OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_WAIT_RETURN'),1)]
        initial={'schema':'chengwang.mihomo-lab-acceptance-state/v1','sourceCommit':'a'*40,'walSchema':self.reader.WAL_SCHEMA,'controlSHA256':'7'*64,'recordSHA256':'8'*64,
          'head':copy.deepcopy(heads[0]),'activeOperationId':None,'activePhase':None,'activeIntentSHA256':None,'completed':[],'terminated':[],'unknownObservationCount':0,
          'privateWALValidated':True,'fullPrivateWALIndependentlyProven':False,'observedProcessMatchesHead':True,'production':False}
        return {'schema':'chengwang.mihomo-continuous-recovery-http-experiment/v1','scope':self.reader.SCOPE,'sourceCommit':'a'*40,'outcome':'PASS','failureCode':'NONE','http':http,'initial':initial,
          'heads':[{'stage':s,'view':v} for s,v in zip(('INITIAL','FIRST_UNKNOWN','FIRST_RECOVERED','ORDINARY_ACK','SECOND_UNKNOWN','SECOND_RECOVERED'),heads)],
          'operations':[{'stage':s,'view':v} for s,v in zip(('FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'),ops)],
          'recoveries':[{'stage':s,'view':v} for s,v in zip(('FIRST_RECOVERY','SECOND_RECOVERY'),rec)],
          'callsBefore':{'reloadInvocations':0,'doInvocations':0},'callsAfter':{'reloadInvocations':3,'doInvocations':3},
          'faultBeforeCleanup':self.observe('TERMINAL',pre),'faultAfterCleanup':self.observe('TERMINAL',post),'faultClosed':self.observe('CLOSED',post),
          'closedPorts':[{'port':p,'connectAttempted':True,'accepted':False,'errorClass':'CONNECTION_REFUSED'} for p in (28411,28412,28413,28414,28415,30000)],
          'runtimeReturned':True,'runtimeErrorClass':'NONE','privateWALDecodedByTest':False,'production':False,'fullPayloadProven':False,'internetBusinessProven':False}

    def test_reader_accepts_complete_synthetic_shape_and_rejects_material_mutants(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); report=self.fixture(root); binding={'schema':'binding'}
            self.assertEqual(len(self.reader.validate_report(report,'a'*40,root,binding)),31)
            mutants=[]
            for mutate in (
              lambda x:x['http'][0].__setitem__('sequence',True),
              lambda x:x['http'][0].__setitem__('statusCode',200.0),
              lambda x:x['http'][0].__setitem__('responseBodySHA256','0'*64),
              lambda x:x['callsAfter'].__setitem__('doInvocations',True),
              lambda x:x['initial'].__setitem__('walSchema','chengwang.mihomo-lifecycle/v2'),
              lambda x:x.__setitem__('privateWALDecodedByTest',True),
              lambda x:x['heads'][5]['view'].__setitem__('headSHA256',x['heads'][3]['view']['headSHA256']),
              lambda x:x['faultClosed']['transport']['steps'][0].__setitem__('action','PASS'),
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
          ('native-zero-kind-core-positive',lambda report,root:report['faultBeforeCleanup']['nativeCalls'][3].__setitem__('core',1)),
          ('head-previous',retained_head(2,'previousHeadSHA256','7'*64)),
          ('head-artifact',retained_head(2,'artifactRecordSHA256','7'*64)),
          ('head-config',retained_head(3,'configSHA256','7'*64)),
          ('published-head-unchanged',retained_head(2,'headSHA256','a'*64)),
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
