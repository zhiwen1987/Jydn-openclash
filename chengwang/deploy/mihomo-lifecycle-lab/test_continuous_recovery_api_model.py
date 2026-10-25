import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class Shared:
    ROOT_ENV={}
    def unprivileged(self,argv,environment): return list(argv)
    def namespace_values(self): return {'networkNamespace':'net:[2]','mountNamespace':'mnt:[2]','pidNamespace':'pid:[2]'}

class Adapter:
    def __init__(self,root):
        self.ROOT_PRIVATE=Path(root); self.PATHS={'module':'/tmp/mihomo-apply-source','goRoot':'/tmp/mihomo-apply-go'}
        self._shared=Shared()
    def shared(self): return self._shared

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
        source=(HERE/'continuous_recovery_api_worker.py').read_text(encoding='utf8')
        self.assertIn('def capture(',source); self.assertNotIn('a.capture(',source); self.assertNotIn('apply_worker.capture',source)
        self.assertIn("cwd='/tmp/mihomo-apply-source'",source)
        self.assertIn('return outputs,report,forbidden',source)
        self.assertIn('for body in outputs.values(): need(all(secret not in body',source)

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
            with mock.patch.object(self.worker,'adapter',return_value=adapter), mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True), mock.patch.object(self.worker.os,'fchmod',return_value=None,create=True), \
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

    def test_capture_pidfd_failure_and_timeout_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            adapter=Adapter(td); argv=('python3','model'); state=self.state()
            with mock.patch.object(self.worker,'adapter',return_value=adapter),mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True),mock.patch.object(self.worker.os,'fchmod',return_value=None,create=True),mock.patch.object(self.worker,'command_argv',return_value=argv), \
                 mock.patch.object(self.worker.subprocess,'Popen',return_value=Process()),mock.patch.object(self.worker.os,'pidfd_open',side_effect=OSError('model'),create=True):
                with self.assertRaises(OSError): self.worker.capture(state,argv,'continuous-sandbox.private.json','continuous-sandbox.private.stderr',30,'SANDBOX')
            self.assertEqual(state['commandSequence'],1); self.assertEqual(len(state['pending']),1)
        with tempfile.TemporaryDirectory() as td:
            adapter=Adapter(td); state=self.state(); process=Process(timeout=True); sent=[]; fd=os.open(os.devnull,os.O_RDONLY)
            with mock.patch.object(self.worker,'adapter',return_value=adapter),mock.patch.object(self.worker.os,'O_NOFOLLOW',0,create=True),mock.patch.object(self.worker.os,'fchmod',return_value=None,create=True),mock.patch.object(self.worker,'command_argv',return_value=argv), \
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
        initial={'schema':'chengwang.mihomo-lab-acceptance-state/v1','sourceCommit':'a'*40,'walSchema':'chengwang.mihomo-lifecycle/v2','controlSHA256':'7'*64,'recordSHA256':'8'*64,
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
