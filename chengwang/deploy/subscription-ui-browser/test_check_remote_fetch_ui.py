"""Independent pure-CPU counterexamples; no browser/Go/TLS server is run."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_remote_fetch_ui as C

COMMIT = 'a'*40
FIXTURE = 'b'*32
SOURCE = 'src_'+'1'*32
CANDIDATE = 'cand_'+'2'*32
NODE_IDS = ['node_'+'3'*32,'node_'+'4'*32]
STAMP = '2026-10-24T01:02:03Z'
ACTORS = {'operator':'act_'+'5'*60,'approver':'act_'+'6'*60}


def packed(value):
    return (json.dumps(value,ensure_ascii=False,separators=(',',':'))+'\n').encode()


def capture(ordinal, kind, role, path, result, public=None, start=None):
    raw = packed(dict(boundary='LOCAL_SUBSCRIPTION_ADMISSION_ONLY',authorization='BLOCKED',deviceActionsExecuted=False,stateMayHaveChanged=False,result=result))
    start = ordinal*100 if start is None else start
    return dict(schema=C.CONTRACT['captureSchema'],ordinal=ordinal,requestOrdinal=ordinal,requestId=str(ordinal),method='POST' if public is not None else 'GET',path=path,kind=kind,status=200,authorizationPresent=True,actorRole=role,requestPublic=public,responseBase64=base64.b64encode(raw).decode(),responseSHA256=C.sha(raw),responseBytes=len(raw),startedWallTimeUs=1792800000000000+start,startTimeUs=start,headerTimeUs=start+10,endTimeUs=start+20,terminal=dict(event='FINISH',encodedDataLength=len(raw)))


def fixture():
    receipts = []; rows = []
    for i,(kind,role,revision) in enumerate((('create','operator',1),('approve','approver',1),('fetch','operator',2),('decide','approver',3)),1):
        rc = dict(commandId='cmd_'+str(i)*32,kind=kind,sourceId=SOURCE,revision=revision,state='approved' if kind=='approve' else 'committed',replayed=False,stateMayHaveChanged=False,auditRecorded=True,preparedAuditHash='0'*64,resultAuditHash='0'*64,completedAt=STAMP)
        if kind == 'approve': rc.update(referenceId='good-b',policyRevision=1,policyDigest='hmac-sha256:'+'a'*64,approvalId=rc['commandId'])
        else: rc['localAuditHash'] = str(i)*64
        if kind in ('fetch','decide'): rc.update(candidateId=CANDIDATE,candidateDigest='hmac-sha256:'+'b'*64)
        public = dict(idempotencyKey='sub_'+str(i)*32)
        if kind == 'create': public.update(label=C.CONTRACT['label']); path = C.BASE+'/sources'
        else:
            public.update(sourceId=SOURCE,expectedRevision=C.ACTIONS[i-1]['fromRevision']); path = C.BASE+'/sources/'+SOURCE+{'approve':'/approvals','fetch':'/fetches','decide':'/decisions'}[kind]
            if kind == 'approve': public.update(referenceId='good-b',policyRevision=1)
            elif kind == 'fetch': public.update(approvalId=receipts[1]['commandId'],policyRevision=1)
            else: public.update(candidateId=CANDIDATE,expectedDigest=rc['candidateDigest'],decision='admitted_local')
        receipts.append(rc); rows.append(capture(i,kind.upper(),role,path,rc,public))
    audit = []; previous = '0'*64
    for i,(rc,row,action) in enumerate(zip(receipts,rows,C.ACTIONS)):
        stable = dict(**C.SCOPE,managementObject='local',kind=rc['kind'],commandDigest='hmac-sha256:'+'c'*64)
        for stage in ('prepared','result'):
            data = dict(stable)
            if stage == 'result':
                data.update(state=rc['state'],code='',sourceId=SOURCE,candidateId=rc.get('candidateId',''),revision=str(rc['revision']),candidateDigest=rc.get('candidateDigest',''),localAuditHash=rc.get('localAuditHash',''),approvalId=rc.get('approvalId',''),policyDigest=rc.get('policyDigest',''),policyRevision=str(rc.get('policyRevision',0)),stateMayHaveChanged='false')
            event = dict(id='event-'+str(len(audit)+1),idempotencyKey='subscription/'+rc['commandId']+'/'+stage,traceId=rc['commandId'],actorId=ACTORS[action['role']],action='subscription.command.'+stage,target='subscription/'+('local' if rc['kind']=='create' else SOURCE),result=stage,occurredAt=STAMP,data=data,previousHash=previous,hash='')
            event['hash'] = C.sha(C.H.go_event_bytes(event)); previous = event['hash']; audit.append(event); rc[stage+'AuditHash'] = event['hash']
        raw = packed(dict(boundary='LOCAL_SUBSCRIPTION_ADMISSION_ONLY',authorization='BLOCKED',deviceActionsExecuted=False,stateMayHaveChanged=False,result=rc))
        row.update(responseBase64=base64.b64encode(raw).decode(),responseBytes=len(raw),responseSHA256=C.sha(raw))
    decoded = {r['ordinal']:C.envelope(C.unbase64(r['responseBase64'],65536)) for r in rows}
    facts = C.reconstruct(rows,decoded)
    nodes = [dict(id=n,label='节点-'+n[-8:],protocol=protocol,credentialConfigured=True,state='unknown') for n,protocol in zip(NODE_IDS,('http','socks5'))]
    facts.update(nodeViews=nodes,candidateCreatedAt=STAMP)
    private = dict(schema=C.CONTRACT['readbackSchema'],sourceCommit=COMMIT,fixtureId=FIXTURE,scope=C.SCOPE,sources=list(facts['states'][-1]['sources'].values()),candidates=[dict(**facts['states'][-1]['candidates'][CANDIDATE],scope=C.SCOPE,nodes=nodes,createdAt=STAMP)],localAuditCount=3,commandCount=4,approvalCount=1,commands=[],approvals=[dict(commandId=receipts[1]['commandId'],scope=C.SCOPE,sourceId=SOURCE,referenceId='good-b',policyRevision=1,policyDigest=receipts[1]['policyDigest'],sourceRevision=1,approvedAt=STAMP)])
    for rc,action in zip(receipts,C.ACTIONS):
        row = dict(id=rc['commandId'],scope=C.SCOPE,actorId=ACTORS[action['role']],kind=rc['kind'],expectedRevision=action['fromRevision'],preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True)
        if rc['kind'] != 'create': row['sourceId'] = SOURCE
        row['result'] = {k:rc[k] for k in ('sourceId','candidateId','revision','state','stateMayHaveChanged','localAuditHash','completedAt','referenceId','policyRevision','policyDigest','approvalId') if k in rc}
        if 'candidateDigest' in rc: row['result']['digest'] = rc['candidateDigest']
        private['commands'].append(row)
    return rows,decoded,facts,audit,dict(count=8,lastHash=previous),private


def wire_fixture():
    events = []
    for connection,(service,query,status) in enumerate((('dot','A',0),('dot','AAAA',0),('https','',200)),1):
        for kind in ('connect','tls','dns' if service=='dot' else 'http','close'):
            payload = kind in ('dns','http'); size = 0
            if payload:
                question = sum(len(v)+1 for v in 'good-b.subscription.example'.split('.'))+1+4
                size = 2+12+question+(16 if query=='A' else 0) if service=='dot' else 1024
            events.append(dict(schema='chengwang.subscription-wire-event/v1',ordinal=len(events)+1,connection=connection,service=service,event=kind,reference='good-b' if payload else '',queryType=query if payload else '',status=status if payload else 0,bytes=size,tls=kind!='connect',reason='closed' if kind=='close' else 'ok',receivedUnixNano='1792800000000000000' if payload else ''))
    raw = b''.join(C.canonical(e)+b'\n' for e in events)
    ready = dict(schema='chengwang.subscription-wire-ready/v1',pid=44,uid=10001,gid=10001,dotAddress='127.0.0.1',dotPort=1853,httpsAddress='8.8.4.4',httpsPort=443,tls=True,deadlineSeconds=180)
    stopped = dict(schema='chengwang.subscription-wire-stopped/v1',pid=44,termination='term',accepted=3,closed=3,events=12,workerThreadsAlive=0,listenersClosed=True,normalStop=True)
    return raw,ready,stopped,events


def api_rows_fixture():
    posts,_,_,_,_,_=fixture(); rows=[]; dist=[]
    for kind,path,raw in (('DOCUMENT','/',b'<html></html>'),('ASSET','/assets/app.js',b'const prefix="Bearer ";'),('SNAPSHOT','/api/v1/snapshot',b'{"load":0.125}\n')):
        row=capture(len(rows)+1,kind,'anonymous',path,{})
        row.update(authorizationPresent=False,responseBase64=base64.b64encode(raw).decode(),responseBytes=len(raw),responseSHA256=C.sha(raw)); rows.append(row)
        if kind!='SNAPSHOT': dist.append(dict(path='index.html' if kind=='DOCUMENT' else path[1:],bytes=len(raw),sha256=C.sha(raw)))
    for post in posts:
        post.update(ordinal=len(rows)+1,requestOrdinal=len(rows)+1,requestId=str(len(rows)+1)); rows.append(post)
    rc=C.envelope(C.unbase64(posts[-1]['responseBase64'],65536)); rows.append(capture(len(rows)+1,'RECEIPT','approver',C.BASE+'/commands/'+rc['commandId'],rc))
    return rows,dict(distFiles=dist)


def supervisor_fixture():
    root=C.CONTRACT['rootPrefix']+FIXTURE; bundle=C.CONTRACT['bundlePrefix']+FIXTURE
    own='chengwang/deploy/subscription-ui-browser/check_remote_fetch_ui.py'
    required=(C.CONTRACT_PATH,'chengwang/deploy/subscription-ui-browser/remote_fetch_fixture.py','chengwang/deploy/subscription-readback/wire_fixture.py','chengwang/deploy/subscription-readback/lab_contract.py','chengwang/tools/subscription-ui-browser/remote-fetch-cli.mjs')
    blobs={name:b'pure synthetic source, never executed\n' for name in required}; blobs[own]=Path(C.__file__).read_bytes()
    source_rows=[dict(path=p,bytes=len(raw),sha256=C.sha(raw)) for p,raw in sorted(blobs.items())]
    namespaces=dict(net='net:[201]',mnt='mnt:[202]',pid='pid:[203]',user='user:[104]')
    host=dict(netNamespace='net:[101]',mountNamespace='mnt:[102]',pidNamespace='pid:[103]',userNamespace='user:[104]',portStart=1024,systemCASHA256='a'*64,sourceSHA256=C.sha(C.canonical(source_rows)))
    common=dict(schema='chengwang.subscription-ui-supervisor/v1',sourceCommit=COMMIT,fixtureId=FIXTURE,engine='chrome-cdp',production=False)
    iso=dict(**common,hostBefore=host,hostAfter=copy.deepcopy(host),sourceFilesBefore=source_rows,sourceFilesAfter=copy.deepcopy(source_rows),lab=dict(namespaces=namespaces,defaultIPv4Routes=0,defaultIPv6Routes=0,interfaces=['lo'],sourceMount=['ro','nosuid','nodev'],bundleMount=['ro','nosuid','nodev'],tmpMount=['rw','nosuid','nodev','noexec'],ipv4Addresses=['127.0.0.1/8','8.8.4.4/32'],unprivilegedPortStart=0),authorization='BLOCKED',deviceActionsExecuted=False,pythonBinaryProvenanceProven=False)
    build=dict(server=dict(name='server',bytes=1,sha256='b'*64),distFiles=[dict(path='index.html',bytes=1,sha256='c'*64)])
    copied=copy.deepcopy(source_rows)+[dict(path='chrome/chrome',bytes=305061192,sha256=C.ELF_SHA),dict(path='toolchain/node',bytes=1,sha256='d'*64),dict(path='toolchain/server',bytes=1,sha256='b'*64),dict(path='npm/playwright-core/package.json',bytes=1,sha256='e'*64),dict(path='dist/index.html',bytes=1,sha256='c'*64)]
    inputs=dict(**common,copiedInputs=copied,inputTrustScope='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    argvs={'server':[bundle+'/server'],'controller':[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/remote-fetch-cli.mjs','--root',root,'--bundle',bundle,'--engine','chrome-cdp','--source-commit',COMMIT],'chrome':[bundle+'/chrome/chrome','--no-sandbox','--user-data-dir='+root+'/chrome-profile'],'wire':['/usr/bin/python3.12','-I','-B',bundle+'/source/chengwang/deploy/subscription-readback/wire_fixture.py','serve','--root',C.CONTRACT['wireRootPrefix']+FIXTURE,'--deadline-seconds','180']}
    records=[]
    for index,(role,argv) in enumerate(argvs.items()):
        records.append(dict(pid=20+index,startTime=str(100+index),exeSHA256={'server':'b'*64,'controller':'d'*64,'chrome':C.ELF_SHA,'wire':'f'*64}[role],argvSHA256=C.sha(b''.join(v.encode()+b'\0' for v in argv)),uid=[10001]*4,gid=[10001]*4,groups=[],capabilities={k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},noNewPrivs=1,namespaces=copy.deepcopy(namespaces),limits=dict(cpuSeconds=[180,180],fileBytes=[32<<20]*2,openFiles=[1024]*2,processes=[1024]*2,coreBytes=[0,0]),role=role,argv=argv))
    p=dict(**common,records=records,serverExitCode=0,controllerExitCode=0,wireExitCode=0,noLiveOwnedProcesses=True,forcedSignals=0,processScope='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION')
    chrome=records[2]; driver=dict(chrome=dict(pid=chrome['pid'],startTicks=102,uid=10001,profile=root+'/chrome-profile',argvSHA256=chrome['argvSHA256'],exeSHA256=C.ELF_SHA,exeBytes=305061192),close=dict(normalCloseCommandCompleted=True,chromeExit=dict(schema='chengwang.subscription-ui-chrome-exit/v1',engine='chrome-cdp',fixtureId=FIXTURE,pid=chrome['pid'],startTicks=102,exitCode=0,joined=True,forced=False),launcherExit=dict(code=0,signal=None),noLiveOwnedProcesses=True,processScope='CHROME_SESSION_AND_LAUNCHER_ONLY'))
    pin=dict(schema='chengwang.pinned-browser-consumption-verification/v1',sourceCommit=COMMIT,state='PIN_ENFORCED_EXPANDED_NOT_EXECUTED',pinSHA256=C.PIN_SHA,pinEnforced=True,allMemberCRCsVerified=True,actualExpandedFileHashesVerified=True,zip=dict(bytes=202676171,sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853',md5Base64='5qChIL/Gh+8hZv73vzEakQ=='),elf=dict(bytes=305061192,sha256=C.ELF_SHA),**{k:False for k in ('browserExecuted','runtimeVersionProven','projectFixProven','publisherSignatureProven','production')})
    return [p,iso,inputs,build,driver,pin,Path('.'),COMMIT,'chrome-cdp',FIXTURE],blobs


def dom_fixture():
    posts,decoded,facts,_,_,_ = fixture(); raw = wire_fixture()[0]
    captures = []; rows = []; count = 0; receipt = None
    for ordinal,step in enumerate(C.STEPS,1):
        if step in C.POST_STEPS:
            count = C.POST_STEPS[step]; posted = copy.deepcopy(posts[count-1]); posted['ordinal'] = len(captures)+1; captures.append(posted); decoded[posted['ordinal']] = C.envelope(C.unbase64(posted['responseBase64'],65536)); receipt = decoded[posted['ordinal']]
        if step in ('anonymous','operator_connected','approver_source','operator_source','approver_candidate','cleared'): receipt = None
        role = C.role_for_step(step); source = facts['states'][count]['sources'].get(SOURCE) if count and step!='cleared' else None
        candidate = facts['states'][count]['candidates'].get(CANDIDATE) if source else None; selected = step in C.SELECTED
        if source:
            fake = dict(ordinal=len(captures)+1,method='GET',actorRole=role,kind='CANDIDATES'); captures.append(fake); facts['candidatePages'][fake['ordinal']] = dict(revision=source['revision'])
            if selected:
                fake = dict(ordinal=len(captures)+1,method='GET',actorRole=role,kind='NODES'); captures.append(fake); facts['nodePages'][fake['ordinal']] = dict(revision=source['revision'])
        if step == 'receipt': captures.append(dict(ordinal=len(captures)+1,method='GET',actorRole=role,kind='RECEIPT'))
        controls = [dict(key=k,present=True,visible=True,enabled=False,inViewport=True,unobstructed=True,rect=dict(x=0,y=0,width=10,height=10)) for k in C.CONTROLS]; ctl = {v['key']:v for v in controls}
        ctl['prepare_create']['enabled'] = role=='operator'; ctl['prepare_import']['enabled'] = role=='operator' and bool(source); ctl['prepare_approve']['enabled'] = role=='approver' and bool(source)
        for k in ('prepare_admit','prepare_reject'): ctl[k]['enabled'] = role=='approver' and selected and count==3
        ctl['prepare_rollback']['enabled'] = role=='approver' and selected and count==4
        ctl['prepare_fetch']['enabled'] = role=='operator' and step in C.HANDOFF and step!='handoff_empty'
        confirmation = None
        if step in C.PREPARED:
            kind = C.PREPARED[step]; confirmation = dict(kind=kind,binding=dict(sourceId=SOURCE,expectedRevision=1,approvalId=facts['approval']['approvalId'],policyRevision=1) if kind=='fetch_handoff' else None,unverifiedReference=kind=='fetch_handoff',rollbackRequired=False,rollbackChecked=False)
            ctl['confirm']['enabled'] = ctl['cancel']['enabled'] = True
        handoff = None
        if step in C.HANDOFF:
            empty = step=='handoff_empty'; handoff=dict(approvalValid=not empty,approvalId=None if empty else facts['approval']['approvalId'],revisionValid=not empty,policyRevision=None if empty else 2 if step=='handoff_edited' else 1,unverifiedReferenceNotice=True)
        ref_b = step in ('approve_b_prepared','approve_b_cancelled','approve_b_prepared_again','approved_b','approval_refreshed')
        width = 375 if step in ('final_mobile','receipt','hidden','returned','cleared') else 1440
        d = dict(schema='chengwang.subscription-browser-dom/v1',pageMounted=True,pageVisible=step!='hidden',https=True,viewport=dict(width=width,height=900,scrollX=0,scrollY=0,clientWidth=width,scrollWidth=width),session=dict(tokenMounted=True,tokenType='password',tokenEmpty=True,fileMounted=True,fileEmpty=True,storageEmpty=True,cookiesEmpty=True),controls=controls,sources=[dict(id=SOURCE,revision=source['revision'],selected=True,accepted=count==4,disabled=False)] if source else [],candidates=[dict(id=CANDIDATE,state=candidate['state'],nodeCount=2,format='mihomo-provider-yaml',baseRevision=2,selected=selected)] if candidate else [],nodes=[{k:v for k,v in n.items() if k!='label'} for n in facts['nodeViews']] if selected else [],paging=dict(candidates=dict(page=1,revision=source['revision']) if source else None,nodes=dict(page=1,revision=source['revision']) if selected else None),mode='handoff' if step in C.HANDOFF else 'session',directory=dict(present=True,disabled=not bool(source),references=[dict(**v,selected=v['referenceId']==('good-b' if ref_b else 'good-a')) for v in C.CONTRACT['references']] if source else []),sessionApproval=dict(approvalId=facts['approval']['approvalId'],referenceId='good-b',policyRevision=1) if step in ('approved_b','approval_refreshed') else None,handoff=handoff,confirmation=confirmation,receipt=None if receipt is None else {k:receipt[k] for k in ('commandId','revision','state','replayed','auditRecorded')},stale=dict(sources=False,candidates=False,nodes=False),alertVisible=False,boundaryVisible=step!='hidden')
        rows.append(dict(schema=C.CONTRACT['domSchema'],ordinal=ordinal,step=step,captureCount=len(captures),mutationCount=count,actorRole=role,wireFence=dict(eventCount=12 if count>=3 else 0,bytes=len(raw) if count>=3 else 0,sha256=C.sha(raw if count>=3 else b'')),dom=d))
    return rows,captures,decoded,facts,raw


class RemoteFetchVerifierContracts(unittest.TestCase):
    def setUp(self):
        self.guard = mock.patch.object(C.subprocess,'run',side_effect=AssertionError('runtime forbidden in pure test')); self.guard.start(); self.addCleanup(self.guard.stop)

    def test_01_frozen_partial_contract_and_old_scenarios_unchanged(self):
        self.assertEqual(len(C.PUBLIC),21); self.assertEqual(len(C.STEPS),33); self.assertEqual(len(C.ACTIONS),4)
        self.assertFalse(C.CONTRACT['fullSubscriptionE2EProven']); self.assertFalse(C.CONTRACT['production'])
        self.assertEqual(C.CONTRACT['references'],[dict(referenceId='good-a',revision=1),dict(referenceId='good-b',revision=1)])
        self.assertEqual(C.H.STEPS,('anonymous','connected','prepared','cancelled','prepared_again','created_desktop','created_mobile','receipt','hidden','returned','cleared'))

    def test_02_reconstruct_four_real_command_shapes_and_revisions(self):
        _,_,facts,_,_,_ = fixture(); self.assertEqual([list(s['sources'].values())[0]['revision'] if s['sources'] else 0 for s in facts['states']],[0,1,1,2,3])
        self.assertEqual(facts['states'][3]['candidates'][CANDIDATE]['state'],'quarantined'); self.assertEqual(facts['states'][4]['candidates'][CANDIDATE]['state'],'admitted_local')

    def test_03_approval_is_not_import_and_has_no_local_audit(self):
        _,decoded,_,_,_,_ = fixture(); rc=decoded[2]; self.assertEqual(rc['state'],'approved'); self.assertNotIn('localAuditHash',rc)
        for field,val in [('revision',2),('localAuditHash','1'*64),('candidateId',CANDIDATE),('approvalId','cmd_'+'f'*32)]:
            rows,decoded,_,_,_,_=fixture(); decoded[2][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.reconstruct(rows,decoded)

    def test_04_handoff_b_cannot_use_dropdown_a_as_authority(self):
        for index,field,val in ((1,'referenceId','good-a'),(2,'approvalId','cmd_'+'f'*32),(2,'policyRevision',2)):
            rows,decoded,_,_,_,_=fixture(); rows[index]['requestPublic'][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.reconstruct(rows,decoded)

    def test_05_actor_cas_and_source_route_binding_are_required(self):
        for index,field,val in ((1,'actorRole','operator'),(2,'path',C.BASE+'/sources/'+SOURCE+'/imports')):
            rows,decoded,_,_,_,_=fixture(); rows[index][field]=val
            with self.assertRaises(ValueError): C.reconstruct(rows,decoded)
        rows,decoded,_,_,_,_=fixture(); rows[2]['requestPublic']['expectedRevision']=2
        with self.assertRaises(ValueError): C.reconstruct(rows,decoded)
        captures,build=api_rows_fixture(); C.validate_rows(captures,build)
        # FINISH before HEADERS dispatch is legal; both are after START.
        captures[0]['headerTimeUs']=captures[0]['endTimeUs']+1; C.validate_rows(captures,build)
        for field,val in [('status',False),('responseSHA256','0'*64),('responseBase64','YQ=='),('authorizationPresent',True),('requestOrdinal',True)]:
            captures,build=api_rows_fixture(); captures[0][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_rows(captures,build)

    def test_06_unique_idempotency_command_and_explicit_candidate_admission(self):
        for mode in ('key','command','decision','digest'):
            rows,decoded,_,_,_,_=fixture()
            if mode=='key': rows[2]['requestPublic']['idempotencyKey']=rows[0]['requestPublic']['idempotencyKey']
            elif mode=='command': decoded[3]['commandId']=decoded[1]['commandId']
            elif mode=='decision': rows[3]['requestPublic']['decision']='rejected'
            else: rows[3]['requestPublic']['expectedDigest']='hmac-sha256:'+'f'*64
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.reconstruct(rows,decoded)

    def test_07_own_final_receipt_only_no_cross_owner_shortcut(self):
        rows,decoded,facts,_,_,_=fixture(); rc=decoded[4]
        row=capture(5,'RECEIPT','operator',C.BASE+'/commands/'+rc['commandId'],rc); rows.append(row); decoded[5]=rc
        with self.assertRaises(ValueError): C.validate_gets(rows,decoded,facts)

    def test_08_capability_metadata_has_catalog_but_is_not_approval(self):
        access=C.expected_access('operator',SOURCE); self.assertEqual(access['policyState'],'ready'); self.assertNotIn('subscription.source.approve',access['actions'])
        access=C.expected_access('approver',SOURCE); self.assertNotIn('subscription.fetch',access['actions'])
        self.assertEqual([v['referenceId'] for v in access['references']],['good-a','good-b'])

    def test_09_cdp_intervals_allow_overlap_without_cross_clock_arithmetic(self):
        _,_,facts,_,_,_=fixture(); self.assertEqual(len(C.possible_states(dict(startTimeUs=190,endTimeUs=230),facts)),2)
        self.assertEqual(C.possible_states(dict(startTimeUs=421,endTimeUs=430),facts),facts['states'][4:])

    def test_10_audit_hash_chain_checkpoint_and_role_binding(self):
        _,_,facts,audit,checkpoint,_=fixture(); self.assertEqual(C.validate_audit(audit,checkpoint,facts),ACTORS)
        for mode in ('hash','checkpoint','missing','extra'):
            _,_,facts,audit,checkpoint,_=fixture()
            if mode=='hash': audit[1]['hash']='0'*64
            elif mode=='checkpoint': checkpoint['count']=7
            elif mode=='missing': audit.pop()
            else: audit.append(copy.deepcopy(audit[-1]))
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_audit(audit,checkpoint,facts)

    def test_11_private_projection_matches_four_commands_and_one_approval(self):
        _,_,facts,_,_,private=fixture(); C.validate_private(private,facts,ACTORS,COMMIT,FIXTURE)
        self.assertEqual(private['localAuditCount'],3); self.assertEqual(private['approvalCount'],1)

    def test_12_private_seal_owner_and_unknown_fields_never_public(self):
        for mode in ('seal','owner','approvalCount','reference','sourceRevision'):
            _,_,facts,_,_,private=fixture()
            if mode=='seal': private['approvals'][0]['seal']='private'
            elif mode=='owner': private['commands'][0]['ownerId']='private'
            elif mode=='approvalCount': private['approvalCount']=0
            elif mode=='reference': private['approvals'][0]['referenceId']='good-a'
            else: private['approvals'][0]['sourceRevision']=2
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_private(private,facts,ACTORS,COMMIT,FIXTURE)

    def test_13_nodes_stay_unknown_credentials_are_not_exported(self):
        nodes=fixture()[2]['nodeViews']; C.safe_nodes(nodes)
        for field,val in [('state','healthy'),('credentialConfigured',False),('password','private'),('label','upstream-name')]:
            bad=copy.deepcopy(nodes); bad[0][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.safe_nodes(bad)

    def test_14_wire_has_three_closed_connections_and_b_only(self):
        raw,ready,stopped,_=wire_fixture(); self.assertEqual(len(C.validate_wire(raw,ready,stopped,44)),12)
        self.assertEqual({v['reference'] for v in C.json_lines(raw) if v['reference']},{'good-b'})
        args,blobs=supervisor_fixture()
        with mock.patch.object(C,'git_bytes',side_effect=lambda repo,commit,path:blobs[path]),mock.patch.object(C.subprocess,'check_output',return_value=b'\0'.join(p.encode() for p in blobs)+b'\0'):
            self.assertEqual(C.validate_supervisor(*args),(len(blobs),23))
            for field,val in [('wireExitCode',1),('wireExitCode',False),('forcedSignals',1),('noLiveOwnedProcesses',False)]:
                bad=copy.deepcopy(args); bad[0][field]=val
                with self.subTest(field=field),self.assertRaises(ValueError): C.validate_supervisor(*bad)
            for field,val in [('unprivilegedPortStart',1),('defaultIPv4Routes',1),('ipv4Addresses',['127.0.0.1/8'])]:
                bad=copy.deepcopy(args); bad[1]['lab'][field]=val
                with self.subTest(field=field),self.assertRaises(ValueError): C.validate_supervisor(*bad)
            bad=copy.deepcopy(args); bad[0]['records'][-1]['noNewPrivs']=False
            with self.assertRaises(ValueError): C.validate_supervisor(*bad)

    def test_15_wire_a_wrong_tls_or_unclosed_chain_rejected(self):
        for mode in ('reference','tls','close','extra'):
            _,ready,stopped,events=wire_fixture()
            if mode=='reference': events[2]['reference']='good-a'
            elif mode=='tls': events[1]['tls']=False
            elif mode=='close': events[-1]['event']='http'
            else: events.append(copy.deepcopy(events[-1]))
            raw=b''.join(C.canonical(e)+b'\n' for e in events)
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_wire(raw,ready,stopped,44)

    def test_16_wire_dns_pair_bytes_status_and_identity_are_bound(self):
        for index,field,val in ((6,'queryType','A'),(2,'bytes',1),(10,'status',302),(0,'connection',True)):
            _,ready,stopped,events=wire_fixture(); events[index][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_wire(b''.join(C.canonical(e)+b'\n' for e in events),ready,stopped,44)

    def test_17_wire_stop_cannot_hide_kill_threads_or_residue(self):
        for field,val in [('normalStop',False),('listenersClosed',False),('workerThreadsAlive',1),('termination','kill'),('accepted',4)]:
            raw,ready,stopped,_=wire_fixture(); stopped[field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_wire(raw,ready,stopped,44)

    def test_18_dom_wire_prefix_hash_and_empty_prefix_are_independent(self):
        raw=wire_fixture()[0]; C.validate_fence(dict(eventCount=0,bytes=0,sha256=C.sha(b'')),raw,False)
        C.validate_fence(dict(eventCount=12,bytes=len(raw),sha256=C.sha(raw)),raw,True)
        for field,val in [('eventCount',11),('eventCount',True),('bytes',0),('sha256','0'*64)]:
            fence=dict(eventCount=12,bytes=len(raw),sha256=C.sha(raw)); fence[field]=val
            with self.assertRaises(ValueError): C.validate_fence(fence,raw,True)

    def test_19_full_fixed_dom_projection_is_partial_not_business_mock(self):
        C.validate_dom(*dom_fixture())

    def test_20_dom_preserves_same_source_approval_then_clears_changed_reference(self):
        rows,captures,decoded,facts,raw=dom_fixture()
        for step in ('approved_b','approval_refreshed'): self.assertEqual(next(r for r in rows if r['step']==step)['dom']['sessionApproval']['referenceId'],'good-b')
        row=next(r for r in rows if r['step']=='reference_a_cleared'); row['dom']['sessionApproval']=copy.deepcopy(next(r for r in rows if r['step']=='approved_b')['dom']['sessionApproval'])
        with self.assertRaises(ValueError): C.validate_dom(rows,captures,decoded,facts,raw)

    def test_21_dom_prepare_cancel_edit_and_mode_switch_are_not_writes(self):
        for step in ('approve_b_cancelled','fetch_cancelled','handoff_edited','session_mode_cleared'):
            rows,captures,decoded,facts,raw=dom_fixture(); row=next(r for r in rows if r['step']==step); self.assertIsNone(row['dom']['confirmation'])
            row['mutationCount']+=1
            with self.subTest(step=step),self.assertRaises(ValueError): C.validate_dom(rows,captures,decoded,facts,raw)

    def test_22_dom_handoff_binding_does_not_claim_dropdown_a_verified(self):
        for mode in ('notice','approval','revision','ref','confirm'):
            rows,captures,decoded,facts,raw=dom_fixture(); row=next(r for r in rows if r['step']=='fetch_prepared_final'); d=row['dom']
            if mode=='notice': d['handoff']['unverifiedReferenceNotice']=False
            elif mode=='approval': d['handoff']['approvalId']='cmd_'+'f'*32
            elif mode=='revision': d['handoff']['policyRevision']=2
            elif mode=='ref': d['directory']['references'][0]['selected']=False; d['directory']['references'][1]['selected']=True
            else: d['confirmation']['binding']['sourceId']='src_'+'f'*32
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_dom(rows,captures,decoded,facts,raw)

    def test_23_dom_quarantine_requires_explicit_admit_and_unknown_nodes(self):
        for step,key in (('fetched_quarantined','accepted'),('final_desktop','state')):
            rows,captures,decoded,facts,raw=dom_fixture(); d=next(r for r in rows if r['step']==step)['dom']
            if key=='accepted': d['sources'][0]['accepted']=True
            else: d['nodes'][0]['state']='healthy'
            with self.assertRaises(ValueError): C.validate_dom(rows,captures,decoded,facts,raw)

    def test_24_hidden_returns_preserved_data_and_clear_removes_private_view(self):
        rows,captures,decoded,facts,raw=dom_fixture(); self.assertFalse(next(r for r in rows if r['step']=='hidden')['dom']['pageVisible'])
        row=next(r for r in rows if r['step']=='cleared'); row['dom']['sources']=copy.deepcopy(rows[-2]['dom']['sources'])
        with self.assertRaises(ValueError): C.validate_dom(rows,captures,decoded,facts,raw)

    def test_25_json_types_canonical_base64_and_png_crc_fail_closed(self):
        with self.assertRaises(ValueError): C.decode(b'{"a":1,"a":1}')
        with self.assertRaises(ValueError): C.integer(True)
        with self.assertRaises(ValueError): C.unbase64('YQ',4)
        with self.assertRaises(ValueError): C.png(b'not a PNG',1440,900)

    def test_26_cli_report_must_be_exclusive_and_outside_evidence_and_repo(self):
        with tempfile.TemporaryDirectory(prefix='remote-fetch-contract-') as root:
            root=Path(root); evidence=root/'evidence'; repo=root/'repo'; evidence.mkdir(); repo.mkdir()
            for output in (evidence/'bad.json',repo/'bad.json'):
                argv=['checker','--evidence',str(evidence),'--repo',str(repo),'--source-commit',COMMIT,'--engine','chrome-cdp','--report',str(output)]
                with mock.patch('sys.argv',argv),mock.patch.object(C,'verify',side_effect=AssertionError('must reject before verify')),self.assertRaises(ValueError): C.main()


if __name__ == '__main__': unittest.main()
