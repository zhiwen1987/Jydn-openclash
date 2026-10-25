"""SYNTHETIC service-original models: no Go, HTTPS, worker or kernel execution.

Invented PIDs/namespaces/identity labels/control hashes are not real custody or
authentication. Original independent model helpers supply raw supported GETs;
no producer is imported and no fixture executes a process/network/service.
"""
import base64
import copy
import json
from pathlib import Path
import unittest

import check_service as S
import test_check_apply as Prior


COMMIT='1'*40
OP='labop_'+'1'*32
PLAN='b'*64
INTENT='c'*64


def wire(v): return Prior.wire(v)
def hashed(v): return Prior.hashed(v)
def b64(v): return base64.b64encode(v).decode('ascii')
def when(n): return f'2026-10-25T00:00:{n:02d}Z'


def model_artifact(payload,role):
    cfg=dict(schema='chengwang.mihomo-lab-config/v1',scope='ISOLATED_LOOPBACK_MIHOMO_STATIC_SUBSET_NOT_PRODUCTION',
        sha256=payload['sha256'],bytes=payload['bytes'],draftSHA256=hashed(('MODEL draft '+role).encode()),
        requirementsSHA256=hashed(b'MODEL requirements'),capabilities=['static_domain_suffix_rules','explicit_selectors',
        'loopback_http_nodes','private_loopback_controller','built_in_dns_disabled'],requirements=[],admissible=True,blockers=[])
    source=hashed(('MODEL private source '+role).encode())
    record=dict(schema='chengwang.mihomo-artifact-record/v1',config=cfg,sourceSpecSHA256=source,sourceSpecBytes=100,controllerPort=28412,mixedPort=28411)
    return dict(schema='chengwang.mihomo-artifact/v1',recordSHA256=hashed(S.go_bytes(record)),config=cfg,
        sourceSpecSHA256=source,sourceSpecBytes=100,controllerPort=28412,mixedPort=28411)


def model_route(index):
    a,b,o=(index,0,index) if index<3 else (3,0,3)
    after=(a+1,b,o+1) if index<3 else (3,1,4)
    role='A' if index<3 else 'B';nonce=str(index+1)*64
    marker=('chengwang-local-service-marker/v1:'+role+':'+nonce+'\n').encode()
    return dict(phase='BOOTSTRAP' if index==0 else 'ACKNOWLEDGED_COMPLETION' if index==3 else 'BASELINE',
        nonceSHA256=hashed(nonce.encode()),clientResponse=Prior.model_body(marker),proxyResponse=Prior.model_body(marker),
        originResponse=Prior.model_body(marker),countersBefore=Prior.model_counters(a,b,o),countersAfter=Prior.model_counters(*after),matched=True)


def model_head(capture,generation,previous,revision,active):
    o=capture['Observation'];i=o['StartupIdentity']
    # Independently construct the source's private fixed hash DTO, not an
    # arbitrary advertised head digest or a call to the checker's head routine.
    material=dict(schema='chengwang.mihomo-lifecycle-head/v1',deviceRef=o['DeviceRef'],scope=o['Scope'],generation=generation,
        artifact=o['Artifact'],kernelSHA256=i['elfSHA256'],pid=i['pid'],startTicks=i['startTicks'],netNSInode=i['netNSInode'],
        controllerPort=28412,mixedPort=28411,verificationSHA256=hashed(S.go_bytes(capture)),verifiedAt=o['ObservedAt'],previousHeadSHA256=previous)
    return dict(schema='chengwang.mihomo-lab-head-view/v1',boundary=S.BOUNDARY,revision=revision,generation=generation,
        headSHA256=hashed(S.go_bytes(material)),previousHeadSHA256=previous,artifactRecordSHA256=o['Artifact']['recordSHA256'],
        configSHA256=o['Artifact']['config']['sha256'],verificationSHA256=material['verificationSHA256'],verifiedAt=o['ObservedAt'],
        activeOperationId=active,writeBlocked=False,proof=dict(fullPayloadProven=False,internetBusinessProven=False,production=False))


def fixture():
    """Complete invented58 originals. This is NOT a successful actual run."""
    legacy,sources=Prior.fixture();r=json.loads(legacy['apply-report.json'])
    sources={p:sources.get(p,b'SYNTHETIC_SOURCE_NOT_ACTUAL_GIT_OR_EXECUTION\n') for p in S.FILES}
    for p in (S.PREFIX+'service_contract.json',S.GO,S.TLS):
        sources[p]=(Path(__file__).parents[2]/p.removeprefix('chengwang/')).read_bytes()
    raw={p:b'' for p in S.PUBLIC}
    for name in ('consumption.json','consumption-independent.json','host-before.json','host-after.json','go-version.txt'):
        raw[name]=legacy[name]
    box=json.loads(legacy['sandbox.json']);box['schema']='chengwang.mihomo-service-sandbox/v1';box['serviceBases']=S.BASES
    raw['sandbox.json']=wire(box)
    raw['execution.json']=wire(dict(schema='chengwang.mihomo-service-execution/v1',sourceCommit=COMMIT,
        formatExit=0,goExit=0,realMihomoExecutionObserved=True,production=False))
    raw['service.json']=Prior.model_go_events([dict(Action='start',Package=S.PACKAGE),dict(Action='run',Package=S.PACKAGE,Test=S.TOP),
        dict(Action='pass',Package=S.PACKAGE,Test=S.TOP),dict(Action='pass',Package=S.PACKAGE)])
    old,new=model_artifact(r['baseInput'],'A'),model_artifact(r['candidateInput'],'B')
    identity={k:r['ownedBefore'][k] for k in S.A.IDENTITY_KEYS}
    scope=dict(tenantId='sub-tenant',siteId='sub-site',objectType='mihomo-lab',objectId='local',environment='isolated-lab')
    captures=[]
    for i,stage in enumerate(S.STAGES):
        phase='candidate' if i==3 else 'baseline'
        transcript=legacy[phase+'-get-evidence.json'];raw[stage+'-transcript.json']=transcript
        bodies=[]
        for n in range(1,9):
            body=legacy[phase+'-get-'+str(n).zfill(2)+'.body'];raw[stage+f'-body-{n}.json']=body;bodies.append(hashed(body))
        observation=dict(Phase='BOOTSTRAP' if i==0 else 'ACKNOWLEDGED_COMPLETION' if i==3 else 'BASELINE',
            Scope=scope,DeviceRef='local',Artifact=new if i==3 else old,StartupIdentity=identity,
            OperationID='' if i==0 else OP,PlanSHA256=PLAN if i>=2 else '',IntentSHA256=INTENT if i==3 else '',VerificationSHA256='',ObservedAt=when(i+1))
        rb={k:r['readbacks'][phase][k] for k in S.A.READBACK_KEYS}
        receipt=dict(Observation=observation,Readback=rb,Transcript=hashed(transcript),Bodies=bodies,Route=model_route(i))
        raw[stage+'-verification.json']=S.go_bytes(receipt);captures.append(receipt)
    h0=model_head(captures[0],1,None,2,None)
    h1=model_head(captures[3],2,h0['headSHA256'],9,OP)
    ack=dict(result=dict(state='acknowledged',dispatched=True,statusCode=204),recordedAt=when(3),origin='ADAPTER',gateReason=None)
    planned=dict(schema='chengwang.mihomo-lab-deployment-view/v1',boundary=S.BOUNDARY,operationId=OP,phase='PLANNED',revision=4,
        planSHA256=PLAN,candidateRecordSHA256=new['recordSHA256'],candidateConfigSHA256=new['config']['sha256'],
        previousHeadSHA256=h0['headSHA256'],headSHA256=h0['headSHA256'],headGeneration=1,expiresAt='2026-10-25T00:05:00Z',
        transport=None,observation=None,writeBlocked=False,replayed=False,headAdvanced=False,proof=copy.deepcopy(h0['proof']))
    approved=copy.deepcopy(planned);approved.update(phase='APPROVED',revision=5)
    completed=copy.deepcopy(planned);completed.update(phase='COMPLETED',revision=9,headSHA256=h1['headSHA256'],headGeneration=2,
        transport=ack,observation=dict(conclusion='STABLE_NEW_PROJECTION',observedProjectionSHA256=r['readbacks']['candidate']['observedProjectionSHA256'],
        evidenceSHA256=hashed(raw[S.STAGES[3]+'-verification.json']),observedAt=when(4),localRouteVerified=True),headAdvanced=True)
    replayed=copy.deepcopy(completed);replayed['replayed']=True
    discovery=copy.deepcopy(h0);discovery.update(revision=4,activeOperationId=OP)
    candidates=dict(schema='chengwang.mihomo-lab-candidates-view/v1',boundary=S.BOUNDARY,candidates=[
        dict(name='local-a',recordSHA256=old['recordSHA256'],configSHA256=old['config']['sha256'],sourceSpecSHA256=old['sourceSpecSHA256'],isCurrent=True),
        dict(name='local-b',recordSHA256=new['recordSHA256'],configSHA256=new['config']['sha256'],sourceSpecSHA256=new['sourceSpecSHA256'],isCurrent=False)],writeBlocked=False,proof=copy.deepcopy(h0['proof']))
    def state(h,done):
        archive=dict(operationId=OP,planSHA256=PLAN,intentSHA256=INTENT,phase='ACKNOWLEDGED_SUPPORTED_POSTCONDITION',headSHA256=h['headSHA256'],
            generation=2,commitRevision=9,committedAt=when(5),transport=ack)
        return dict(schema='chengwang.mihomo-lab-acceptance-state/v1',sourceCommit=COMMIT,walSchema='chengwang.mihomo-lifecycle-record/v2',
            controlSHA256=hashed(b'MODEL WAL after' if done else b'MODEL WAL before'),recordSHA256=hashed(b'MODEL record after' if done else b'MODEL record before'),
            head=copy.deepcopy(h),activeOperationId=OP if done else None,activePhase='ACKNOWLEDGED_SUPPORTED_POSTCONDITION' if done else None,
            activeIntentSHA256=INTENT if done else None,completed=[archive] if done else [],terminated=[],unknownObservationCount=0,
            privateWALValidated=True,fullPrivateWALIndependentlyProven=False,observedProcessMatchesHead=True,production=False)
    before,after=state(h0,False),state(h1,True)
    create=dict(candidateRecordSHA256=new['recordSHA256'],ttlSeconds=300)
    approval=dict(planSHA256=PLAN,revision=4);execute=dict(planSHA256=PLAN,revision=5)
    prefix='/api/v1/lab/mihomo'
    rowspec=[('anonymous','GET','/candidates',None,401,None),('viewer','GET','/candidates',None,200,candidates),
        ('viewer','POST','/deployments',create,403,None),('wrong-scope','POST','/deployments',create,403,None),
        ('admin','POST','/deployments',create,None,None),('admin','GET','/head',None,200,discovery),
        ('admin','GET','/deployments/'+OP,None,200,planned),('admin','POST','/deployments/'+OP+'/approvals',approval,403,None),
        ('approver','POST','/deployments/'+OP+'/approvals',approval,200,approved),('admin','POST','/deployments/'+OP+'/execute',execute,200,completed),
        ('admin','POST','/deployments/'+OP+'/execute',execute,200,replayed)]
    def envelope(status,value,changed=False):
        return S.go_bytes(dict(boundary=S.BOUNDARY,code='mihomo_lab_ok' if status in (200,201) else 'mihomo_lab_unauthenticated' if status==401 else 'mihomo_lab_forbidden',stateMayHaveChanged=changed,result=value))+b'\n'
    rows=[]
    for n,(role,method,path,body,status,response) in enumerate(rowspec,1):
        payload=b'' if body is None else S.go_bytes(body)
        rows.append(dict(sequence=n,case=S.HTTP_CASES[n-1],role=role,method=method,path=prefix+path,requestBody=b64(payload),statusCode=status,
            responseBody=None if status is None else b64(envelope(status,response,status==200 and method=='POST')),
            errorClass='RESPONSE_NOT_OBSERVED' if status is None else 'NONE'))
    report=dict(schema='chengwang.mihomo-service-http-experiment/v1',scope=S.SCOPE,sourceCommit=COMMIT,outcome='PASS',failureCode='NONE',http=rows,
        dropped=dict(handlerCompleted=True,generatedStatus=201,generatedBody=b64(envelope(201,planned,True)),connectionClosed=True),
        before=before,after=after,replay=copy.deepcopy(after),callsBefore=dict(reloadInvocations=0,doInvocations=0),
        callsAfter=dict(reloadInvocations=1,doInvocations=1),callsReplay=dict(reloadInvocations=1,doInvocations=1),
        controllerReceivedCount=None,closedPorts=[dict(port=n,connectAttempted=True,accepted=False,errorClass='CONNECTION_REFUSED') for n in range(28411,28416)],
        runtimeReturned=True,runtimeErrorClass='NONE',production=False,fullPayloadProven=False,internetBusinessProven=False)
    raw['e2e-report.json']=wire(report)
    raw['op-01-syntax.stdout']=legacy['syntax.stdout'];raw['op-01-syntax.stderr']=b''
    raw['op-01-syntax.json']=wire(dict(schema='chengwang.mihomo-lab-service-syntax/v1',inputSHA256=new['config']['sha256'],inputBytes=new['config']['bytes'],
        observation=Prior.model_observation(502,None,raw['op-01-syntax.stdout'])))
    journal=[]
    stages=['STARTUP','HEAD_READY','PLANNED','APPROVED','PREPARED','DISPATCH_ARMED','RELOAD_CALL_INTENT','RELOAD_RETURNED','RESULT_RECORDED','COMPLETED']
    for stage in stages:
        row=dict(stage=stage,operationId='' if stage in ('STARTUP','HEAD_READY') else OP,
            intentSHA256=INTENT if stage in ('DISPATCH_ARMED','RELOAD_CALL_INTENT','RELOAD_RETURNED','RESULT_RECORDED','COMPLETED') else '')
        if stage=='RELOAD_RETURNED':row.update(result=ack['result'],walRecorded=True)
        journal.append(row)
    kernel=dict(started=True,waitReturned=True,waitErrorClass='EXIT_STATUS',exitCode=None,signal=15,termSent=True,killSent=False,
        groupAbsent=True,stdout=Prior.model_stream(b''),stderr=Prior.model_stream(b''))
    fixtures=[dict(role=role,shutdownReturned=True,serveReturned=True,forcedConnectionsClosed=0,errorClass='NONE') for role in ('origin','A','B')]
    journal += [dict(stage='CLEANUP_OBSERVED',kernel=kernel,fixtures=fixtures),dict(stage='CLOSED',operationId='',intentSHA256='')]
    raw['service-journal.jsonl']=b''.join(wire(row) for row in journal)
    return raw,sources


class SyntheticServiceEvidenceModels(unittest.TestCase):
    def reject(self,mutate):
        raw,sources=fixture();mutate(raw,sources)
        with self.assertRaises(ValueError):S.verify_raw(raw,sources,COMMIT)

    def report_reject(self,mutate):
        def change(raw,sources):
            v=json.loads(raw['e2e-report.json']);mutate(v);raw['e2e-report.json']=wire(v)
        self.reject(change)

    def test_complete_synthetic_originals_validate_only_bounded_public_claims(self):
        raw,sources=fixture();v=S.verify_raw(raw,sources,COMMIT)
        self.assertEqual(len(raw),58);self.assertEqual(len(sources),141);self.assertEqual(v['outcome'],'PASS')
        for key in ('sourceGitVerified','currentCredentialContentsIndependentlyProven','privateExpectedSourceIndependentlyProven',
            'fullPrivateWALIndependentlyProven','privateDisclosureFenceIndependentlyProven','fullPayloadProven','internetBusinessProven','production'):self.assertIs(v[key],False)
        self.assertIsNone(v['controllerReceivedCount'])

    def test_missing_or_extra_or_private_member_rejects(self):
        self.reject(lambda r,s:r.pop('bootstrap-body-1.json'))
        self.reject(lambda r,s:r.__setitem__('private.yaml',b'MODEL'))

    def test_missing_source_or_source_module_mismatch_rejects(self):
        self.reject(lambda r,s:s.pop(S.TLS))
        self.reject(lambda r,s:s.__setitem__('chengwang/go.mod',b'MODEL changed source'))

    def test_source_tag_and_real_top_declaration_are_mandatory(self):
        self.reject(lambda r,s:s.__setitem__(S.GO,b'package serverruntime\n'))

    def test_wrong_commit_and_signature_or_production_escalation_rejects(self):
        raw,sources=fixture()
        with self.assertRaises(ValueError):S.verify_raw(raw,sources,'2'*40)
        self.report_reject(lambda v:v.__setitem__('production',True))
        def signature(r,s):v=json.loads(r['consumption.json']);v['publisherSignatureProven']=True;r['consumption.json']=r['consumption-independent.json']=wire(v)
        self.reject(signature)

    def test_format_diff_and_nonzero_execution_exit_reject(self):
        self.reject(lambda r,s:r.__setitem__('gofmt.patch',b'MODEL diff\n'))
        def change(r,s):v=json.loads(r['execution.json']);v['goExit']=1;r['execution.json']=wire(v)
        self.reject(change)

    def test_skipped_failed_or_missing_go_events_reject(self):
        for action in ('skip','fail','pause'):
            self.reject(lambda r,s,a=action:r.__setitem__('service.json',r['service.json'].replace(b'"Action":"run"',('"Action":"'+a+'"').encode(),1)))
        self.reject(lambda r,s:r.__setitem__('service.json',b''))

    def test_unexpected_go_output_cannot_export_private_log(self):
        def change(r,s):
            events=[json.loads(x) for x in r['service.json'].splitlines()];events.insert(2,dict(Time=events[1]['Time'],Action='output',Package=S.PACKAGE,Test=S.TOP,Output='MODEL_PRIVATE_LOG\n'));r['service.json']=b''.join(wire(x) for x in events)
        self.reject(change)

    def test_sandbox_host_namespace_and_nonloopback_routes_reject(self):
        for key,value in [('networkNamespace','net:[1]'),('defaultV4Routes',['MODEL route']),('noNewPrivileges',1)]:
            def change(r,s,k=key,v=value):x=json.loads(r['sandbox.json']);x[k]=v;r['sandbox.json']=wire(x)
            self.reject(change)

    def test_custody_equal_float_and_bool_aliases_reject(self):
        for side in ('before','after'):
            for key in ('bytes','uid','gid'):
                def change(r,s,side=side,key=key):
                    v=json.loads(r['sandbox.json']);v['inputCustody'][side]['elf'][key]=float(v['inputCustody'][side]['elf'][key]);r['sandbox.json']=wire(v)
                self.reject(change)

    def test_receipt_copy_or_published_pin_mismatch_reject(self):
        self.reject(lambda r,s:r.__setitem__('consumption-independent.json',b'{}'))
        def change(r,s):v=json.loads(r['consumption.json']);v['archive']['sha256']='a'*64;r['consumption.json']=r['consumption-independent.json']=wire(v)
        self.reject(change)

    def test_http_request_method_role_scope_and_path_are_fixed(self):
        for index,key,value in [(0,'role','admin'),(3,'role','admin'),(8,'role','admin'),(9,'method','GET'),(5,'path','/MODEL')]:
            self.report_reject(lambda v,i=index,k=key,x=value:v['http'][i].__setitem__(k,x))

    def test_anonymous_viewer_wrong_scope_and_self_approval_cannot_succeed(self):
        for index in (0,2,3,7):self.report_reject(lambda v,i=index:v['http'][i].__setitem__('statusCode',200))

    def test_base64_aliases_and_invalid_response_json_reject(self):
        self.report_reject(lambda v:v['http'][0].__setitem__('responseBody',v['http'][0]['responseBody']+'\n'))
        self.report_reject(lambda v:v['http'][1].__setitem__('responseBody',b64(b'{}')))

    def test_drop_requires_actual_generated201_and_client_absence(self):
        for key,value in [('handlerCompleted',False),('connectionClosed',False),('generatedStatus',200)]:self.report_reject(lambda v,k=key,x=value:v['dropped'].__setitem__(k,x))
        self.report_reject(lambda v:v['http'][4].__setitem__('statusCode',201))

    def test_head_discovery_cannot_be_replaced_by_dropped_body_id(self):
        def change(v):
            e=json.loads(base64.b64decode(v['http'][5]['responseBody']));e['result']['activeOperationId']=None;v['http'][5]['responseBody']=b64(S.go_bytes(e)+b'\n')
        self.report_reject(change)

    def test_request_revision_float_and_stale_cas_reject(self):
        for revision in (4.0,True,3):
            self.report_reject(lambda v,x=revision:v['http'][8].__setitem__('requestBody',b64(S.go_bytes(dict(planSHA256=PLAN,revision=x)) if type(x) is not float else b'{"planSHA256":"'+PLAN.encode()+b'","revision":4.0}')))

    def test_missing204_or_adapter_result_rejects(self):
        def change(v):
            e=json.loads(base64.b64decode(v['http'][9]['responseBody']));e['result']['transport']['result']['statusCode']=200;v['http'][9]['responseBody']=b64(S.go_bytes(e)+b'\n')
        self.report_reject(change)

    def test_no_extra_reload_or_do_counter_is_inferred_from_wal(self):
        for phase,key in [('callsAfter','reloadInvocations'),('callsAfter','doInvocations'),('callsReplay','doInvocations')]:self.report_reject(lambda v,p=phase,k=key:v[p].__setitem__(k,2))

    def test_cumulative_counter_offset_is_not_claimed_as_absolute_zero(self):
        raw,sources=fixture();v=json.loads(raw['e2e-report.json'])
        for phase in ('callsBefore','callsAfter','callsReplay'):
            for key in v[phase]:v[phase][key]+=7
        raw['e2e-report.json']=wire(v);self.assertEqual(S.verify_raw(raw,sources,COMMIT)['outcome'],'PASS')

    def test_counter_bool_alias_and_fabricated_server_received_count_reject(self):
        self.report_reject(lambda v:v['callsAfter'].__setitem__('doInvocations',True))
        self.report_reject(lambda v:v.__setitem__('controllerReceivedCount',1))

    def test_old_wal_or_changed_replay_originals_reject(self):
        self.report_reject(lambda v:v.__setitem__('after',copy.deepcopy(v['before'])))
        self.report_reject(lambda v:v['replay'].__setitem__('controlSHA256','e'*64))

    def test_full_private_wal_or_internet_proof_cannot_be_escalated(self):
        self.report_reject(lambda v:v['after'].__setitem__('fullPrivateWALIndependentlyProven',True))
        self.report_reject(lambda v:v.__setitem__('internetBusinessProven',True))

    def test_empty_capture_and_bound_body_tamper_reject(self):
        self.reject(lambda r,s:r.__setitem__('bootstrap-body-1.json',b''))
        self.reject(lambda r,s:r.__setitem__('op-01-post-dispatch-body-3.json',b'{}'))

    def test_transcript_metadata_and_eof_close_are_recomputed(self):
        def change(r,s):
            stage='bootstrap';v=json.loads(r[stage+'-transcript.json']);v['records'][0]['naturalEOF']=False;r[stage+'-transcript.json']=Prior.CapturedModels.wire(v)
            cap=json.loads(r[stage+'-verification.json']);cap['Transcript']=hashed(r[stage+'-transcript.json']);r[stage+'-verification.json']=S.go_bytes(cap)
        self.reject(change)

    def test_duplicate_json_keys_and_struct_order_alias_reject(self):
        self.reject(lambda r,s:r.__setitem__('bootstrap-verification.json',r['bootstrap-verification.json'].replace(b'"Observation":',b'"Observation":{},"Observation":',1)))
        self.reject(lambda r,s:r.__setitem__('bootstrap-verification.json',r['bootstrap-verification.json']+b'\n'))

    def test_projection_semantics_cannot_be_replaced_by_boolean(self):
        def change(r,s):
            stage='op-01-post-dispatch';v=json.loads(r[stage+'-verification.json']);v['Readback']['observedProjectionSHA256']='d'*64;r[stage+'-verification.json']=S.go_bytes(v)
        self.reject(change)
        # Rebind all entity hashes after a semantically meaningful General
        # drift, then directly test the capture gate. A stale outer head hash
        # cannot mask a missing actual projection recomputation in this check.
        raw,sources=fixture();stage='bootstrap'
        transcript=json.loads(raw[stage+'-transcript.json'])
        receipt=json.loads(raw[stage+'-verification.json'])
        for ordinal in (2,6):
            name=stage+f'-body-{ordinal}.json';body=json.loads(raw[name]);body['mixed-port']=28412;raw[name]=Prior.CapturedModels.wire(body)
            row=transcript['records'][ordinal-1];row['retainedBytes']=row['contentLength']=len(raw[name]);row['retainedSHA256']=hashed(raw[name]);receipt['Bodies'][ordinal-1]=hashed(raw[name])
        transcript['retainedBytes']=sum(row['retainedBytes'] for row in transcript['records'])
        raw[stage+'-transcript.json']=Prior.CapturedModels.wire(transcript);receipt['Transcript']=hashed(raw[stage+'-transcript.json']);raw[stage+'-verification.json']=S.go_bytes(receipt)
        elf=json.loads(raw['consumption.json'])['elf'];ns=int(json.loads(raw['sandbox.json'])['networkNamespace'][5:-1])
        with self.assertRaises(ValueError):S.capture(raw,stage,0,COMMIT,elf,ns)

    def test_wrong_epoch_source_or_startup_artifact_binding_reject(self):
        for key,value in [('sourceCommit','2'*40),('netNSInode',999),('artifactSHA256','d'*64)]:
            def change(r,s,k=key,x=value):
                p='op-01-post-dispatch-verification.json';v=json.loads(r[p]);v['Observation']['StartupIdentity'][k]=x;r[p]=S.go_bytes(v)
            self.reject(change)

    def test_verification_digest_must_bind_actual_head_and_http_observation(self):
        self.report_reject(lambda v:v['after']['head'].__setitem__('verificationSHA256','e'*64))

    def test_route_three_hashes_and_selected_counter_deltas_are_required(self):
        for field in ('clientResponse','originResponse'):
            def change(r,s,k=field):
                p='op-01-pre-dispatch-verification.json';v=json.loads(r[p]);v['Route'][k]['sha256']='d'*64;r[p]=S.go_bytes(v)
            self.reject(change)

    def test_route_nonce_and_counter_chain_are_not_independent_resets(self):
        def change(r,s):
            p='op-01-create-verification.json';v=json.loads(r[p]);v['Route']['countersBefore']=Prior.model_counters();r[p]=S.go_bytes(v)
        self.reject(change)

    def test_syntax_actual_input_exit_and_raw_stdio_are_bound(self):
        self.reject(lambda r,s:r.__setitem__('op-01-syntax.stderr',b'MODEL private error'))
        def change(r,s):v=json.loads(r['op-01-syntax.json']);v['inputBytes']+=1;r['op-01-syntax.json']=wire(v)
        self.reject(change)

    def test_journal_requires_exactly_one_claim_and_actual_return(self):
        self.reject(lambda r,s:r.__setitem__('service-journal.jsonl',r['service-journal.jsonl'].replace(b'"RELOAD_CALL_INTENT"',b'"PREPARED"',1)))

    def test_cleanup_requires_actual_wait_and_preserves_fixture_order(self):
        def change(r,s):
            rows=[json.loads(x) for x in r['service-journal.jsonl'].splitlines()];rows[-2]['kernel']['waitReturned']=False;r['service-journal.jsonl']=b''.join(wire(x) for x in rows)
        self.reject(change)

    def test_cleanup_signal_requires_matching_sent_observation(self):
        def change(r,s):
            rows=[json.loads(x) for x in r['service-journal.jsonl'].splitlines()];rows[-2]['kernel']['termSent']=False;r['service-journal.jsonl']=b''.join(wire(x) for x in rows)
        self.reject(change)

    def test_closed_ports_need_refused_connection_not_arbitrary_error(self):
        self.report_reject(lambda v:v['closedPorts'][0].__setitem__('errorClass','TIMEOUT'))

    def test_runtime_returned_boolean_does_not_replace_cleanup_originals(self):
        self.reject(lambda r,s:r.__setitem__('service-journal.jsonl',b'\n'.join(r['service-journal.jsonl'].splitlines()[:-2])+b'\n'))

    def test_report_unknown_key_or_failure_summary_cannot_pass(self):
        self.report_reject(lambda v:v.__setitem__('privatePayload',True))
        self.report_reject(lambda v:v.__setitem__('outcome','FAIL'))


if __name__=='__main__': unittest.main()
