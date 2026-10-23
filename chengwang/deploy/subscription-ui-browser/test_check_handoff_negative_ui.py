"""Pure CPU contract counterexamples, never browser/API execution evidence."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_handoff_negative_ui as C

COMMIT='a'*40
FIXTURE='b'*32
SOURCES={'a':'src_'+'1'*32,'b':'src_'+'2'*32}
CANDIDATE='cand_'+'3'*32
STAMP='2026-10-24T01:02:03Z'
ACTORS={'operator':'act_'+'5'*60,'approver':'act_'+'6'*60}
LEAF=b'CPU-only invalid certificate placeholder; never OpenSSL verified.'*3
CERTIFICATES=dict(caPEM='unused',leafPEM='-----BEGIN CERTIFICATE-----\n'+base64.b64encode(LEAF).decode()+'\n-----END CERTIFICATE-----\n')


def packed(value): return C.canonical(value)+b'\n'


def body(result,status=200):
    return packed(dict(boundary='LOCAL_SUBSCRIPTION_ADMISSION_ONLY',authorization='BLOCKED',deviceActionsExecuted=False,stateMayHaveChanged=False,**({'result':result} if status == 200 else {'code':result})))


def capture(kind,role,path,result,case=None,public=None,status=200,command=None):
    raw=body(result,status)
    return dict(schema=C.CONTRACT['captureSchema'],ordinal=1,requestOrdinal=1,requestId='1',method='POST' if public is not None else 'GET',path=path,kind=kind,status=status,authorizationPresent=role != 'anonymous',actorRole=role,caseKey=case,requestPublic=public,commandIdHeader=command,denialAuditHeader=None,responseBase64=base64.b64encode(raw).decode(),responseSHA256=C.sha(raw),responseBytes=len(raw),startedWallTimeUs=1792800000000000,startTimeUs=100,headerTimeUs=110,endTimeUs=120,terminal=dict(event='FINISH',encodedDataLength=len(raw)))


def resequence(rows):
    for i,row in enumerate(rows,1):
        row.update(ordinal=i,requestOrdinal=i,requestId=str(i),startTimeUs=i*100,headerTimeUs=i*100+10,endTimeUs=i*100+20,startedWallTimeUs=1792800000000000+i*100)
    return rows


def make_fixture():
    receipts={}; templates={}; sampler=[]; commands=[]; states=[dict(sources={},candidates={})]
    for n,action in enumerate(C.ACTIONS,1):
        key=action['key']; kind=action['kind']; sid=SOURCES[action['source']]; public=dict(idempotencyKey='sub_'+format(n,'032x'))
        if kind == 'create': public['label']=C.CONTRACT['labels'][action['source']]; path=C.BASE+'/sources'
        else:
            public.update(sourceId=sid,expectedRevision=1); path=C.BASE+'/sources/'+sid+('/approvals' if kind == 'approve' else '/fetches')
            if kind == 'approve': public.update(referenceId=action['referenceId'],policyRevision=1)
            else: public.update(approvalId=C.CONTRACT['unknownApprovalId'] if action['approvalKey'] == 'unknown' else receipts[action['approvalKey']]['commandId'],policyRevision=action['policyRevision'])
        failed=action['status'] != 200; rc=None
        if key != 'api_approve_denied':
            rc=dict(commandId='cmd_'+format(n,'032x'),kind=kind,sourceId=sid,revision=action['revision'],state='failed' if failed else 'approved' if kind == 'approve' else 'committed',replayed=False,stateMayHaveChanged=False,auditRecorded=True,preparedAuditHash='0'*64,resultAuditHash='0'*64,completedAt=STAMP)
            if failed: rc['code']=action['code']
            elif kind == 'approve': rc.update(referenceId=action['referenceId'],policyRevision=1,policyDigest='hmac-sha256:'+format(n,'064x'),approvalId=rc['commandId'])
            else:
                rc['localAuditHash']=format(n,'064x')
                if kind == 'fetch': rc.update(candidateId=CANDIDATE,candidateDigest='hmac-sha256:'+'d'*64)
            receipts[key]=rc; commands.append((action,rc)); state=copy.deepcopy(states[-1])
            if kind == 'create': state['sources'][sid]=dict(id=sid,scope=C.SCOPE,label=public['label'],revision=1,updatedAt=STAMP)
            elif kind == 'fetch' and not failed:
                state['sources'][sid].update(revision=2,updatedAt=STAMP,latestCandidateId=CANDIDATE)
                state['candidates'][CANDIDATE]=dict(id=CANDIDATE,sourceId=sid,digest=rc['candidateDigest'],format='mihomo-provider-yaml',state='quarantined',baseRevision=2,nodeCount=2,duplicateCount=0)
            states.append(state)
        if action['origin'] == 'browser': templates[key]=capture(kind.upper(),action['actorRole'],path,action['code'] if failed else rc,key,public,action['status'],rc['commandId'] if failed else None)
        else:
            raw=body(action['code'],action['status'])
            sampler.append(dict(schema=C.CONTRACT['samplerSchema'],ordinal=len(sampler)+1,caseKey=key,method='POST',path=path,actorRole='operator',requestPublic=public,status=action['status'],commandIdHeader=rc['commandId'] if rc else None,denialAuditHeader='recorded' if rc is None else None,responseBase64=base64.b64encode(raw).decode(),responseBytes=len(raw),responseSHA256=C.sha(raw),tls=dict(authorized=True,leafDERBase64=base64.b64encode(LEAF).decode(),leafSHA256=C.sha(LEAF),protocol='TLSv1.3'),startedWallTimeUs=1792800000000000,headerWallTimeUs=1792800000000010,endWallTimeUs=1792800000000020,terminal=copy.deepcopy(C.CONTRACT['samplerTerminal'])))
    audit=[]; previous='0'*64
    def add(event):
        nonlocal previous
        event.update(id='event-'+str(len(audit)+1),occurredAt=STAMP,previousHash=previous,hash=''); event['hash']=C.sha(C.H.go_event_bytes(event)); previous=event['hash']; audit.append(event); return event
    for action,rc in commands:
        stable=dict(**C.SCOPE,managementObject='local',kind=action['kind'],commandDigest='hmac-sha256:'+'e'*64)
        for stage in ('prepared','result'):
            data=dict(stable)
            if stage == 'result': data.update(state=rc['state'],code=rc.get('code',''),sourceId=rc['sourceId'],candidateId=rc.get('candidateId',''),revision=str(rc['revision']),candidateDigest=rc.get('candidateDigest',''),localAuditHash=rc.get('localAuditHash',''),approvalId=rc.get('approvalId',''),policyDigest=rc.get('policyDigest',''),policyRevision=str(rc.get('policyRevision',0)),stateMayHaveChanged='false')
            event=add(dict(idempotencyKey='subscription/'+rc['commandId']+'/'+stage,traceId=rc['commandId'],actorId=ACTORS[action['actorRole']],action='subscription.command.'+stage,target='subscription/'+('local' if action['kind'] == 'create' else rc['sourceId']),result=stage,data=data))
            rc[stage+'AuditHash']=event['hash']
        if action['key'] == 'superseded_fetch': add(dict(idempotencyKey='subscription/denied_'+'f'*32,traceId='denied_'+'f'*32,actorId=ACTORS['operator'],action='subscription.command.denied',target='subscription/local',result='denied',data=dict(category='approve',classification=C.FORBIDDEN_CODE)))
    for key,row in templates.items():
        if row['status'] == 200:
            raw=body(receipts[key]); row.update(responseBase64=base64.b64encode(raw).decode(),responseBytes=len(raw),responseSHA256=C.sha(raw))
    rows=list(templates.values())
    for case in C.CONTRACT['receiptCases']:
        rc=receipts[case['commandKey']]; rows.append(capture('RECEIPT','operator',C.BASE+'/commands/'+rc['commandId'],rc if case['status'] == 200 else C.FORBIDDEN_CODE,case['key'],status=case['status']))
    resequence(rows); sampler[1].update(startedWallTimeUs=1792800000001100,headerWallTimeUs=1792800000001110,endWallTimeUs=1792800000001120)
    decoded={r['ordinal']:C.response(C.unbase64(r['responseBase64'],65536),r['status']) for r in rows}
    facts=C.reconstruct(rows,decoded,sampler)
    nodes=[dict(id='node_'+format(i,'032x'),label='节点-'+format(i,'032x')[-8:],protocol=p,credentialConfigured=True,state='unknown') for i,p in ((10,'http'),(11,'socks5'))]
    facts.update(nodeViews=nodes,candidateCreatedAt=STAMP)
    private=dict(schema=C.CONTRACT['readbackSchema'],sourceCommit=COMMIT,fixtureId=FIXTURE,scope=C.SCOPE,sources=[states[-1]['sources'][SOURCES[k]] for k in ('a','b')],candidates=[dict(**states[-1]['candidates'][CANDIDATE],scope=C.SCOPE,nodes=nodes,createdAt=STAMP)],localAuditCount=3,commandCount=11,approvalCount=3,commands=[],approvals=[])
    for action,rc in commands:
        item=dict(id=rc['commandId'],scope=C.SCOPE,actorId=ACTORS[action['actorRole']],kind=action['kind'],expectedRevision=action['expectedRevision'],preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True)
        if action['kind'] != 'create': item['sourceId']=rc['sourceId']
        item['result']={k:rc[k] for k in ('sourceId','candidateId','revision','state','code','stateMayHaveChanged','localAuditHash','completedAt','referenceId','policyRevision','policyDigest','approvalId') if k in rc}
        if 'candidateDigest' in rc: item['result']['digest']=rc['candidateDigest']
        private['commands'].append(item)
        if action['kind'] == 'approve': private['approvals'].append(dict(commandId=rc['commandId'],scope=C.SCOPE,sourceId=rc['sourceId'],referenceId=rc['referenceId'],policyRevision=1,policyDigest=rc['policyDigest'],sourceRevision=1,approvedAt=STAMP))
    return rows,decoded,sampler,facts,audit,dict(count=23,lastHash=previous),private,templates


def browser_fixture():
    rows,_,sampler,*_=make_fixture(); dist=[]; static=[]
    for kind,path,raw in (('DOCUMENT','/',b'<html></html>'),('ASSET','/assets/app.js',b'const p="Bearer ";'),('SNAPSHOT','/api/v1/snapshot',b'{"load":0.125}\n')):
        row=capture(kind,'anonymous',path,{})
        row.update(responseBase64=base64.b64encode(raw).decode(),responseBytes=len(raw),responseSHA256=C.sha(raw)); static.append(row)
        if kind != 'SNAPSHOT': dist.append(dict(path='index.html' if kind == 'DOCUMENT' else path[1:],bytes=len(raw),sha256=C.sha(raw)))
    rows=resequence(static+rows); decoded,_=C.validate_browser(rows,dict(distFiles=dist)); return rows,decoded,sampler,dict(distFiles=dist)


def wire_fixture():
    events=[]
    for connection,(service,query,status) in enumerate((('dot','A',0),('dot','AAAA',0),('https','',200)),1):
        for event in ('connect','tls','dns' if service == 'dot' else 'http','close'):
            payload=event in ('dns','http'); question=sum(len(x)+1 for x in 'good-b.subscription.example'.split('.'))+5
            size=2+12+question+(16 if query == 'A' else 0) if service == 'dot' else 1024
            events.append(dict(schema='chengwang.subscription-wire-event/v1',ordinal=len(events)+1,connection=connection,service=service,event=event,reference='good-b' if payload else '',queryType=query if payload else '',status=status if payload else 0,bytes=size if payload else 0,tls=event != 'connect',reason='closed' if event == 'close' else 'ok',receivedUnixNano='1792800000000000000' if payload else ''))
    raw=b''.join(packed(e) for e in events); ready=dict(schema='chengwang.subscription-wire-ready/v1',pid=44,uid=10001,gid=10001,dotAddress='127.0.0.1',dotPort=1853,httpsAddress='8.8.4.4',httpsPort=443,tls=True,deadlineSeconds=180)
    stopped=dict(schema='chengwang.subscription-wire-stopped/v1',pid=44,termination='term',accepted=3,closed=3,events=12,workerThreadsAlive=0,listenersClosed=True,normalStop=True)
    return raw,ready,stopped,events


def dom_fixture():
    _,_,sampler,facts,_,_,_,templates=make_fixture(); captures=copy.deepcopy(browser_fixture()[0][:3]); steps=[]; posts=0
    command_rows=[(i,a,rc) for i,(a,_,rc) in enumerate(facts['commands'],1) if a['origin'] == 'browser']
    wire_raw=wire_fixture()[0]; sampler_raw=b''.join(packed(r) for r in sampler)
    for ordinal,step in enumerate(C.STEPS,1):
        s=dict(zip(C.CONTRACT['stateColumns'],C.CONTRACT['stepStates'][step])); role=s['actorRole']; selected=s['selectedSource']
        while posts < s['browserPosts']:
            captures.append(copy.deepcopy(templates[command_rows[posts][1]['key']])); posts+=1
        receipt_case=step if step in C.RECEIPT_CASES else 'cross_owner_receipt' if step == 'cross_owner_denied' else 'stale_receipt' if step == 'stale_receipt_failed' else None
        if receipt_case:
            case=C.RECEIPT_CASES[receipt_case]; rc=facts['receipts'][case['commandKey']]
            captures.append(capture('RECEIPT','operator',C.BASE+'/commands/'+rc['commandId'],rc if case['status'] == 200 else C.FORBIDDEN_CODE,receipt_case,status=case['status']))
        inventory=facts['states'][0 if posts == 0 else command_rows[posts-1][0]]; source=inventory['sources'].get(SOURCES.get(selected)) if selected else None
        if role != 'anonymous':
            captures.append(capture('COLLECTION_ACCESS',role,C.BASE+'/access',C.expected_access(role)))
            sources=sorted(inventory['sources'].values(),key=lambda v:v['id']); captures.append(capture('SOURCES',role,C.BASE+'/sources',dict(sources=sources,total=len(sources))))
            if source:
                captures.append(capture('SOURCE_ACCESS',role,C.BASE+'/sources/'+source['id']+'/access',C.expected_access(role,source['id'])))
                candidates=[dict(**c,createdAt=STAMP) for c in inventory['candidates'].values() if c['sourceId'] == source['id']]
                captures.append(capture('CANDIDATES',role,C.BASE+'/sources/'+source['id']+'/candidates?limit=20&offset=0&revision='+str(source['revision']),dict(candidates=candidates,total=len(candidates),revision=source['revision'])))
                if s['candidateSelected']: captures.append(capture('NODES',role,C.BASE+'/sources/'+source['id']+'/candidates/'+CANDIDATE+'/nodes?limit=20&offset=0&revision=2',dict(nodes=facts['nodeViews'],total=2,revision=2)))
        hidden=step == 'hidden'; fresh=not s['staleSources'] and not s['staleCandidates']; enabled={key:False for key in C.CONTROLS}
        enabled.update(prepare_create=role == 'operator' and fresh,prepare_import=role == 'operator' and bool(source) and fresh,prepare_approve=role == 'approver' and bool(source) and fresh,prepare_fetch=role == 'operator' and bool(source) and fresh and s['mode'] == 'handoff',confirm=bool(s['dialog']),cancel=bool(s['dialog']),connect=True,clear=True,refresh_sources=role != 'anonymous',read_receipt=role != 'anonymous',refresh_source=bool(source))
        controls=[]
        for k in C.CONTROLS:
            present=bool(s['dialog']) if k in ('confirm','cancel') else bool(source) if k in ('refresh_source','candidate_previous','candidate_next') else s['candidateSelected'] if k in ('node_previous','node_next') else True
            controls.append(dict(key=k,present=present,visible=present and not hidden,enabled=enabled[k],inViewport=present and not hidden,unobstructed=present and not hidden,rect=dict(x=0,y=0,width=10,height=10) if present and not hidden else None))
        width=375 if C.STEPS.index(step) >= C.STEPS.index('final_mobile') else 1440
        views=[] if step == 'cleared' else [dict(id=v['id'],revision=v['revision'],selected=bool(source and source['id'] == v['id']),accepted=False,disabled=False) for v in sorted(inventory['sources'].values(),key=lambda v:v['id'])]
        candidate=inventory['candidates'].get(CANDIDATE) if selected == 'a' else None
        aid=C.CONTRACT['unknownApprovalId'] if s['handoffKey'] == 'unknown' else facts['receipts'][s['handoffKey']]['commandId'] if s['handoffKey'] else None
        rc=facts['receipts'].get(s['receiptKey']); approval=facts['receipts'].get(s['approvalKey']); dialog=s['dialog']
        d=dict(schema='chengwang.subscription-browser-dom/v1',pageMounted=True,pageVisible=not hidden,https=True,viewport=dict(width=width,height=900,scrollX=0,scrollY=0,clientWidth=width,scrollWidth=width),session=dict(tokenMounted=True,tokenType='password',tokenEmpty=True,fileMounted=True,fileEmpty=True,storageEmpty=True,cookiesEmpty=True),controls=controls,sources=views,candidates=[dict(id=CANDIDATE,state='quarantined',nodeCount=2,format='mihomo-provider-yaml',baseRevision=2,selected=s['candidateSelected'])] if candidate else [],nodes=[{k:v for k,v in n.items() if k != 'label'} for n in facts['nodeViews']] if s['candidateSelected'] else [],paging=dict(candidates=dict(page=1,revision=source['revision']) if source else None,nodes=dict(page=1,revision=2) if s['candidateSelected'] else None),mode=s['mode'],directory=dict(present=True,disabled=not bool(source),references=[dict(**r,selected=r['referenceId'] == s['reference']) for r in C.CONTRACT['references']] if source else []),sessionApproval={k:approval[k] for k in ('approvalId','referenceId','policyRevision')} if approval else None,handoff=dict(approvalValid=True,approvalId=aid,revisionValid=True,policyRevision=s['handoffPolicy'],unverifiedReferenceNotice=True) if s['mode'] == 'handoff' else None,confirmation=dict(kind=dialog,binding=dict(sourceId=source['id'],expectedRevision=source['revision'],approvalId=aid,policyRevision=s['handoffPolicy']) if dialog == 'fetch_handoff' else None,unverifiedReference=dialog == 'fetch_handoff',rollbackRequired=False,rollbackChecked=False) if dialog else None,receipt={k:rc[k] for k in ('commandId','revision','state','replayed','auditRecorded')} if rc else None,stale=dict(sources=s['staleSources'],candidates=s['staleCandidates'],nodes=False),alertVisible=s['alert'],boundaryVisible=not hidden)
        prefix=b''.join(sampler_raw.splitlines(keepends=True)[:s['samplerRecords']]); wire=wire_raw if s['wireEvents'] else b''
        steps.append(dict(schema=C.CONTRACT['domSchema'],ordinal=ordinal,step=step,captureCount=len(captures),mutationCount=posts,actorRole=role,wireFence=dict(eventCount=s['wireEvents'],bytes=len(wire),sha256=C.sha(wire)),samplerFence=dict(recordCount=s['samplerRecords'],bytes=len(prefix),sha256=C.sha(prefix)),dom=d))
    resequence(captures); valid=next(r for r in captures if r['caseKey'] == 'valid_fetch')['startedWallTimeUs']; sampler[1].update(startedWallTimeUs=valid+30,headerWallTimeUs=valid+40,endWallTimeUs=valid+50)
    sampler_raw=b''.join(packed(r) for r in sampler)
    for row in steps:
        count=dict(zip(C.CONTRACT['stateColumns'],C.CONTRACT['stepStates'][row['step']]))['samplerRecords']; prefix=b''.join(sampler_raw.splitlines(keepends=True)[:count]); row['samplerFence']=dict(recordCount=count,bytes=len(prefix),sha256=C.sha(prefix))
    decoded={r['ordinal']:C.response(C.unbase64(r['responseBase64'],65536),r['status']) for r in captures if r['kind'] not in ('DOCUMENT','ASSET','SNAPSHOT')}
    facts=C.reconstruct(captures,decoded,sampler); C.validate_gets(captures,decoded,facts)
    return steps,captures,decoded,facts,wire_raw,sampler_raw


def supervisor_fixture():
    root=C.CONTRACT['rootPrefix']+FIXTURE; bundle=C.CONTRACT['bundlePrefix']+FIXTURE
    own='chengwang/deploy/subscription-ui-browser/check_handoff_negative_ui.py'
    required=(C.CONTRACT_PATH,'chengwang/deploy/subscription-ui-browser/handoff_negative_fixture.py','chengwang/deploy/subscription-readback/wire_fixture.py','chengwang/deploy/subscription-readback/lab_contract.py','chengwang/tools/subscription-ui-browser/handoff-negative-cli.mjs','chengwang/tools/subscription-ui-browser/handoff-negative-driver.mjs','chengwang/tools/subscription-ui-browser/handoff-negative-contract.mjs','chengwang/tools/subscription-ui-browser/handoff-api-sampler.mjs','chengwang/tools/subscription-ui-browser/ui-contract.mjs','chengwang/tools/subscription-ui-browser/remote-fetch-contract.mjs','chengwang/tools/subscription-browser/collect-subscription-dom.mjs')
    blobs={name:b'pure synthetic source, never executed\n' for name in required}; blobs[own]=Path(C.__file__).read_bytes(); blobs['chengwang/deploy/subscription-ui-browser/check_subscription_ui.py']=Path(C.H.__file__).read_bytes()
    source_rows=[dict(path=p,bytes=len(raw),sha256=C.sha(raw)) for p,raw in sorted(blobs.items())]
    namespaces=dict(net='net:[201]',mnt='mnt:[202]',pid='pid:[203]',user='user:[104]')
    host=dict(netNamespace='net:[101]',mountNamespace='mnt:[102]',pidNamespace='pid:[103]',userNamespace='user:[104]',portStart=1024,systemCASHA256='a'*64,sourceSHA256=C.sha(C.canonical(source_rows)))
    common=dict(schema='chengwang.subscription-ui-supervisor/v1',sourceCommit=COMMIT,fixtureId=FIXTURE,engine='chrome-cdp',production=False)
    iso=dict(**common,hostBefore=host,hostAfter=copy.deepcopy(host),sourceFilesBefore=source_rows,sourceFilesAfter=copy.deepcopy(source_rows),lab=dict(namespaces=namespaces,defaultIPv4Routes=0,defaultIPv6Routes=0,interfaces=['lo'],sourceMount=['ro','nosuid','nodev'],bundleMount=['ro','nosuid','nodev'],tmpMount=['rw','nosuid','nodev','noexec'],ipv4Addresses=['127.0.0.1/8','8.8.4.4/32'],unprivilegedPortStart=0),authorization='BLOCKED',deviceActionsExecuted=False,pythonBinaryProvenanceProven=False)
    build=dict(server=dict(name='server',bytes=1,sha256='b'*64),distFiles=[dict(path='index.html',bytes=1,sha256='c'*64)])
    copied=copy.deepcopy(source_rows)+[dict(path='chrome/chrome',bytes=305061192,sha256=C.ELF_SHA),dict(path='toolchain/node',bytes=1,sha256='d'*64),dict(path='toolchain/server',bytes=1,sha256='b'*64),dict(path='npm/playwright-core/package.json',bytes=1,sha256='e'*64),dict(path='dist/index.html',bytes=1,sha256='c'*64)]
    inputs=dict(**common,copiedInputs=copied,inputTrustScope='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    argvs={'server':[bundle+'/server'],'controller':[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/handoff-negative-cli.mjs','--root',root,'--bundle',bundle,'--engine','chrome-cdp','--source-commit',COMMIT],'chrome':[bundle+'/chrome/chrome','--no-sandbox','--user-data-dir='+root+'/chrome-profile'],'wire':['/usr/bin/python3.12','-I','-B',bundle+'/source/chengwang/deploy/subscription-readback/wire_fixture.py','serve','--root',C.CONTRACT['wireRootPrefix']+FIXTURE,'--deadline-seconds','180']}
    records=[]
    for index,(role,argv) in enumerate(argvs.items()):
        records.append(dict(pid=20+index,startTime=str(100+index),exeSHA256={'server':'b'*64,'controller':'d'*64,'chrome':C.ELF_SHA,'wire':'f'*64}[role],argvSHA256=C.sha(b''.join(v.encode()+b'\0' for v in argv)),uid=[10001]*4,gid=[10001]*4,groups=[],capabilities={k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},noNewPrivs=1,namespaces=copy.deepcopy(namespaces),limits=dict(cpuSeconds=[180,180],fileBytes=[32<<20]*2,openFiles=[1024]*2,processes=[1024]*2,coreBytes=[0,0]),role=role,argv=argv))
    p=dict(**common,records=records,serverExitCode=0,controllerExitCode=0,wireExitCode=0,noLiveOwnedProcesses=True,forcedSignals=0,processScope='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION')
    chrome=records[2]; driver=dict(chrome=dict(pid=chrome['pid'],startTicks=102,uid=10001,profile=root+'/chrome-profile',argvSHA256=chrome['argvSHA256'],exeSHA256=C.ELF_SHA,exeBytes=305061192),close=dict(normalCloseCommandCompleted=True,chromeExit=dict(schema='chengwang.subscription-ui-chrome-exit/v1',engine='chrome-cdp',fixtureId=FIXTURE,pid=chrome['pid'],startTicks=102,exitCode=0,joined=True,forced=False),launcherExit=dict(code=0,signal=None),noLiveOwnedProcesses=True,processScope='CHROME_SESSION_AND_LAUNCHER_ONLY'))
    pin=dict(schema='chengwang.pinned-browser-consumption-verification/v1',sourceCommit=COMMIT,state='PIN_ENFORCED_EXPANDED_NOT_EXECUTED',pinSHA256=C.PIN_SHA,pinEnforced=True,allMemberCRCsVerified=True,actualExpandedFileHashesVerified=True,zip=dict(bytes=202676171,sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853',md5Base64='5qChIL/Gh+8hZv73vzEakQ=='),elf=dict(bytes=305061192,sha256=C.ELF_SHA),**{k:False for k in ('browserExecuted','runtimeVersionProven','projectFixProven','publisherSignatureProven','production')})
    return [p,iso,inputs,build,driver,pin,Path('.'),COMMIT,'chrome-cdp',FIXTURE],blobs



class HandoffNegativeVerifierContracts(unittest.TestCase):
    def setUp(self):
        guard=mock.patch.object(C.subprocess,'run',side_effect=AssertionError('runtime forbidden in pure test')); guard.start(); self.addCleanup(guard.stop)

    def test_01_frozen_scope_counts_and_distinct_origins(self):
        self.assertEqual(len(C.STEPS),49); self.assertEqual(len(C.PUBLIC),22); self.assertEqual(len(C.ACTIONS),12)
        self.assertEqual([a['key'] for a in C.ACTIONS if a['origin'] == 'api-sampler'],['api_approve_denied','api_stale_fetch'])
        self.assertEqual(C.CONTRACT['final']['externalAuditEvents'],23); self.assertFalse(C.CONTRACT['production'])

    def test_02_success_and_failure_envelopes_are_disjoint(self):
        self.assertEqual(C.response(body(C.APPROVAL_CODE,409),409),C.APPROVAL_CODE)
        for raw,status in ((body({},200),409),(body(C.APPROVAL_CODE,409),200),(body({},200)[:-2]+b',"code":"x"}\n',200)):
            with self.assertRaises(ValueError): C.response(raw,status)

    def test_03_complete_independent_command_and_inventory_reconstruction(self):
        _,_,_,facts,audit,checkpoint,private,_=make_fixture(); self.assertEqual(len(facts['commands']),11)
        self.assertEqual(facts['states'][-1]['sources'][SOURCES['a']]['revision'],2); self.assertEqual(facts['states'][-1]['sources'][SOURCES['b']]['revision'],1)
        self.assertEqual(C.validate_audit(audit,checkpoint,facts),ACTORS); C.validate_private(private,facts,ACTORS,COMMIT,FIXTURE)

    def test_04_four_approval_required_failures_are_case_bound(self):
        for key in ('unknown_fetch','wrong_source_fetch','wrong_policy_fetch','superseded_fetch'):
            rows,decoded,sampler,_,_,_,_,_=make_fixture(); row=next(r for r in rows if r['caseKey'] == key); row['requestPublic']['approvalId']='cmd_'+'0'*32
            with self.subTest(key=key),self.assertRaises(ValueError): C.reconstruct(rows,decoded,sampler)

    def test_05_browser_capture_errors_are_not_globally_allowed(self):
        rows,_,_,build=browser_fixture(); C.validate_browser(rows,build)
        for field,value in (('status',403),('caseKey',None),('actorRole','approver'),('commandIdHeader',None),('denialAuditHeader','recorded')):
            bad=copy.deepcopy(rows); row=next(r for r in bad if r['caseKey'] == 'unknown_fetch'); row[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_browser(bad,build)

    def test_06_native_posts_cannot_be_relabelled_browser(self):
        rows,decoded,sampler,_,_,_,_,_=make_fixture(); sampler[0]['caseKey']='valid_fetch'
        with self.assertRaises((ValueError,KeyError)): C.reconstruct(rows,decoded,sampler)
        rows,_,_,build=browser_fixture(); bad=next(r for r in rows if r['caseKey'] == 'unknown_fetch'); bad['caseKey']='api_stale_fetch'
        with self.assertRaises(ValueError): C.validate_browser(rows,build)

    def test_07_five_own_failed_receipts_are_not_post_error_bodies(self):
        rows,decoded,sampler,facts,*_=make_fixture(); self.assertEqual(sum(rc['state'] == 'failed' for rc in facts['receipts'].values()),5)
        for case in ('unknown_receipt','stale_receipt'):
            bad=copy.deepcopy(rows); bad=[r for r in bad if r['caseKey'] != case]
            with self.subTest(case=case),self.assertRaises(ValueError): C.reconstruct(bad,decoded,sampler)

    def test_08_failed_receipt_revision_is_submitted_not_latest(self):
        rows,decoded,sampler,*_=make_fixture(); row=next(r for r in rows if r['caseKey'] == 'stale_receipt'); decoded[row['ordinal']]['revision']=2
        with self.assertRaises(ValueError): C.reconstruct(rows,decoded,sampler)

    def test_09_failed_receipt_cannot_claim_local_audit_or_changed_state(self):
        rc=make_fixture()[3]['receipts']['unknown_fetch']
        for key,value in (('localAuditHash','a'*64),('stateMayHaveChanged',True),('auditRecorded',False),('replayed',True),('code',C.FORBIDDEN_CODE)):
            bad=copy.deepcopy(rc); bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.safe_receipt(bad,'fetch',True)

    def test_10_receipt_handles_source_owner_and_path_are_bound(self):
        rows,decoded,sampler,*_=make_fixture(); row=next(r for r in rows if r['caseKey'] == 'unknown_fetch'); row['commandIdHeader']='cmd_'+'d'*32
        with self.assertRaises(ValueError): C.reconstruct(rows,decoded,sampler)
        rows,decoded,_,facts,*_=make_fixture(); row=next(r for r in rows if r['caseKey'] == 'cross_owner_receipt'); row['path']=C.BASE+'/commands/'+facts['receipts']['approve_b']['commandId']
        with self.assertRaises(ValueError): C.validate_gets(rows,decoded,facts)
        for mode in ('ordinal','completion','monotonic','nativewall'):
            rows,decoded,_,facts,*_=make_fixture(); receipt=next(r for r in rows if r['caseKey'] == ('stale_receipt' if mode == 'nativewall' else 'unknown_receipt'))
            if mode == 'ordinal': receipt['requestOrdinal']=1
            elif mode == 'completion': receipt['ordinal']=1
            elif mode == 'monotonic': receipt['startTimeUs']=1
            else: receipt['startedWallTimeUs']=1
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_gets(rows,decoded,facts)

    def test_11_sampler_strict_two_records_and_normal_tls_leaf(self):
        sampler=make_fixture()[2]; raw=b''.join(packed(r) for r in sampler); self.assertEqual(len(C.validate_sampler(raw,CERTIFICATES)[0]),2)
        for key,value in (('authorized',False),('leafSHA256','0'*64),('leafDERBase64','YQ=='),('protocol','HTTP')):
            bad=copy.deepcopy(sampler); bad[0]['tls'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.validate_sampler(b''.join(packed(r) for r in bad),CERTIFICATES)

    def test_12_sampler_denial_header_and_terminal_are_exact(self):
        original=make_fixture()[2]
        for row,key,value in ((0,'commandIdHeader','cmd_'+'0'*32),(0,'denialAuditHeader',None),(1,'commandIdHeader',None),(1,'terminal',dict(event='END',complete=False,aborted=False)),(1,'status',403)):
            bad=copy.deepcopy(original); bad[row][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.validate_sampler(b''.join(packed(r) for r in bad),CERTIFICATES)

    def test_13_sampler_sha_length_order_and_clock_domain(self):
        for key,value in (('responseSHA256','0'*64),('responseBytes',True),('ordinal',True),('endWallTimeUs',1),('caseKey','api_approve_denied')):
            bad=copy.deepcopy(make_fixture()[2]); bad[1][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.validate_sampler(b''.join(packed(r) for r in bad),CERTIFICATES)
        samples=make_fixture()[2]; samples[1]['startedWallTimeUs']=samples[0]['startedWallTimeUs']
        with self.assertRaises(ValueError): C.validate_sampler(b''.join(packed(r) for r in samples),CERTIFICATES)

    def test_14_stale_cas_does_not_change_inventory_or_wire(self):
        _,_,_,facts,*_=make_fixture(); self.assertEqual(facts['states'][-1],facts['states'][-2]); self.assertEqual(facts['receipts']['api_stale_fetch']['code'],C.CONFLICT_CODE)
        rows,decoded,sampler,*_=make_fixture(); sampler[1]['requestPublic']['expectedRevision']=2
        with self.assertRaises(ValueError): C.reconstruct(rows,decoded,sampler)

    def test_15_idempotency_source_and_policy_bindings_are_unique(self):
        for field,value in (('idempotencyKey','sub_'+format(1,'032x')),('sourceId',SOURCES['b']),('policyRevision',1)):
            rows,decoded,sampler,*_=make_fixture(); row=next(r for r in rows if r['caseKey'] == 'wrong_policy_fetch'); row['requestPublic'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError): C.reconstruct(rows,decoded,sampler)

    def test_16_audit_full_chain_checkpoint_and_exact_denial(self):
        _,_,_,facts,audit,checkpoint,*_=make_fixture(); C.validate_audit(audit,checkpoint,facts)
        for mode in ('hash','missing','extra','checkpoint'):
            bad=copy.deepcopy(audit); cp=copy.deepcopy(checkpoint)
            if mode == 'hash': bad[0]['hash']='0'*64
            elif mode == 'missing': bad.pop()
            elif mode == 'extra': bad.append(copy.deepcopy(bad[-1]))
            else: cp['count']=22
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_audit(bad,cp,facts)
        # Pair by immutable command ID, not positional adjacency.  Insert the
        # single independent denial between a prepared/result pair and reseal
        # the synthetic chain and original receipt hash links independently.
        _,_,_,facts,audit,checkpoint,*_=make_fixture(); denied=next(e for e in audit if e['result'] == 'denied'); audit.remove(denied); audit.insert(1,denied); previous='0'*64
        for event in audit:
            event['previousHash']=previous; event['hash']=C.sha(C.H.go_event_bytes(event)); previous=event['hash']
            if event['traceId'] in facts['commandCases']: facts['receipts'][facts['commandCases'][event['traceId']]][event['result']+'AuditHash']=event['hash']
        checkpoint['lastHash']=previous; self.assertEqual(C.validate_audit(audit,checkpoint,facts),ACTORS)

    def test_17_cross_owner_get_has_no_second_denied_audit(self):
        _,_,_,facts,audit,checkpoint,*_=make_fixture(); event=next(e for e in audit if e['result'] == 'denied'); event['data']['category']='read'
        previous='0'*64
        for e in audit: e['previousHash']=previous; e['hash']=C.sha(C.H.go_event_bytes(e)); previous=e['hash']
        checkpoint['lastHash']=previous
        with self.assertRaises(ValueError): C.validate_audit(audit,checkpoint,facts)

    def test_18_private_projection_cannot_smuggle_owner_seal_or_credentials(self):
        for path,key,value in (('commands','ownerId','secret'),('approvals','seal','secret'),('candidates','raw','secret')):
            _,_,_,facts,_,_,private,*_=make_fixture(); private[path][0][key]=value
            with self.subTest(path=path),self.assertRaises(ValueError): C.validate_private(private,facts,ACTORS,COMMIT,FIXTURE)

    def test_19_private_final_cas_counts_and_approval_associations(self):
        for mode in ('revision','count','approval','failed'):
            _,_,_,facts,_,_,private,*_=make_fixture()
            if mode == 'revision': private['sources'][0]['revision']=1
            elif mode == 'count': private['commandCount']=12
            elif mode == 'approval': private['approvals'][2]['sourceId']=SOURCES['a']
            else: private['commands'][-1]['result']['revision']=2
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_private(private,facts,ACTORS,COMMIT,FIXTURE)

    def test_20_wire_three_closed_connections_only_good_b(self):
        raw,ready,stopped,_=wire_fixture(); self.assertEqual(len(C.validate_wire(raw,ready,stopped,44)),12)
        for key,value in (('reference','good-a'),('bytes',0),('queryType','TXT')):
            _,ready,stopped,events=wire_fixture(); events[2][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.validate_wire(b''.join(packed(e) for e in events),ready,stopped,44)

    def test_21_wire_no_early_connections_kill_or_missing_close(self):
        for key,value in (('accepted',4),('closed',2),('normalStop',False),('workerThreadsAlive',1)):
            raw,ready,stopped,_=wire_fixture(); stopped[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.validate_wire(raw,ready,stopped,44)
        args,blobs=supervisor_fixture()
        with mock.patch.object(C,'git_bytes',side_effect=lambda repo,commit,path:blobs[path]),mock.patch.object(C.subprocess,'check_output',return_value=b'\0'.join(p.encode() for p in blobs)+b'\0'):
            self.assertEqual(C.validate_supervisor(*args),(len(blobs),23))
            for field,value in (('wireExitCode',False),('forcedSignals',1),('noLiveOwnedProcesses',False)):
                bad=copy.deepcopy(args); bad[0][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError): C.validate_supervisor(*bad)
            for field,value in (('defaultIPv4Routes',1),('ipv4Addresses',['127.0.0.1/8']),('unprivilegedPortStart',1)):
                bad=copy.deepcopy(args); bad[1]['lab'][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError): C.validate_supervisor(*bad)
            bad=copy.deepcopy(args); bad[0]['records'][1]['argv'][-1]='0'*40
            with self.assertRaises(ValueError): C.validate_supervisor(*bad)
            original=blobs['chengwang/deploy/subscription-ui-browser/check_subscription_ui.py']; blobs['chengwang/deploy/subscription-ui-browser/check_subscription_ui.py']=b'changed imported neutral bytes'
            with self.assertRaises(ValueError): C.validate_supervisor(*args)
            blobs['chengwang/deploy/subscription-ui-browser/check_subscription_ui.py']=original

    def test_22_both_prefix_fences_use_real_original_bytes(self):
        raw=wire_fixture()[0]; C.validate_fence(dict(eventCount=0,bytes=0,sha256=C.sha(b'')),raw,False); C.validate_fence(dict(eventCount=12,bytes=len(raw),sha256=C.sha(raw)),raw,True)
        samples=b''.join(packed(r) for r in make_fixture()[2]); first=samples.splitlines(keepends=True)[0]; C.sampler_fence(dict(recordCount=1,bytes=len(first),sha256=C.sha(first)),samples,1)
        for bad in (dict(recordCount=2,bytes=len(first),sha256=C.sha(first)),dict(recordCount=1,bytes=0,sha256=C.sha(b''))):
            with self.assertRaises(ValueError): C.sampler_fence(bad,samples,1)

    def test_23_api_metadata_is_not_approval_or_ui_permission(self):
        self.assertNotIn('subscription.source.approve',C.expected_access('operator',SOURCES['a'])['actions'])
        self.assertNotIn('subscription.fetch',C.expected_access('approver',SOURCES['a'])['actions'])
        self.assertEqual(C.expected_access('operator',SOURCES['a'])['references'],[dict(referenceId='good-a',revision=1),dict(referenceId='good-b',revision=1)])

    def test_24_floats_assets_and_finish_before_headers_are_not_false_failures(self):
        rows,_,_,build=browser_fixture(); rows[0]['headerTimeUs']=rows[0]['endTimeUs']+1; C.validate_browser(rows,build)
        for field,value in (('responseSHA256','0'*64),('responseBytes',True),('requestOrdinal',True),('authorizationPresent',True)):
            bad=copy.deepcopy(rows); bad[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_browser(bad,build)

    def test_25_nodes_are_unknown_and_api_dom_fields_differ(self):
        nodes=make_fixture()[3]['nodeViews']; C.safe_nodes(nodes); self.assertEqual(set(nodes[0]),{'id','label','protocol','credentialConfigured','state'})
        for key,value in (('state','healthy'),('credentialConfigured',False),('password','secret')):
            bad=copy.deepcopy(nodes); bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.safe_nodes(bad)

    def test_26_strict_json_types_base64_and_png(self):
        for function,args in ((C.decode,(b'{"x":1,"x":1}',)),(C.integer,(True,)),(C.unbase64,('YQ',4)),(C.png,(b'not png',1440,900))):
            with self.assertRaises(ValueError): function(*args)

    def test_27_cli_report_outside_evidence_and_repository_exclusive(self):
        with tempfile.TemporaryDirectory(prefix='handoff-negative-cpu-') as directory:
            root=Path(directory); evidence=root/'evidence'; repo=root/'repo'; evidence.mkdir(); repo.mkdir(); occupied=root/'existing'; occupied.write_bytes(b'preserve')
            for target in (evidence/'bad',repo/'bad',occupied):
                argv=['checker','--evidence',str(evidence),'--repo',str(repo),'--source-commit',COMMIT,'--engine','chrome-cdp','--report',str(target)]
                with mock.patch('sys.argv',argv),mock.patch.object(C,'verify',side_effect=AssertionError('must reject first')),self.assertRaises(ValueError): C.main()
            self.assertEqual(occupied.read_bytes(),b'preserve')

    def test_28_cdp_state_bounds_do_not_mix_native_wall_clock(self):
        rows,_,sampler,_,_,_,_,_=make_fixture(); decoded={r['ordinal']:C.response(C.unbase64(r['responseBase64'],65536),r['status']) for r in rows}; facts=C.reconstruct(rows,decoded,sampler)
        self.assertEqual(C.possible_states(dict(startTimeUs=100000,endTimeUs=100010),facts),facts['states'][10:])
        self.assertEqual(len(C.possible_states(dict(startTimeUs=190,endTimeUs=230),facts)),2)

    def test_29_complete_dom_49_step_projection(self):
        args=dom_fixture(); C.validate_dom(*args); self.assertLess(len(args[1]),256)
        failed=next(r for r in args[0] if r['step'] == 'unknown_failed'); self.assertIsNone(failed['dom']['receipt']); self.assertTrue(failed['dom']['alertVisible'])
        own=next(r for r in args[0] if r['step'] == 'unknown_receipt'); self.assertEqual(own['dom']['receipt']['state'],'failed'); self.assertTrue(own['dom']['stale']['sources'])

    def test_30_dom_real_capture_and_sampler_fences_not_self_counts(self):
        for mode in ('mutation','capture','wire','sampler'):
            args=list(dom_fixture()); row=next(r for r in args[0] if r['step'] == 'api_approve_denied')
            if mode == 'mutation': row['mutationCount']+=1
            elif mode == 'capture': row['captureCount']=0
            elif mode == 'wire': row['wireFence']=dict(eventCount=12,bytes=len(args[4]),sha256=C.sha(args[4]))
            else: row['samplerFence']=dict(recordCount=0,bytes=0,sha256=C.sha(b''))
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_dom(*args)

    def test_31_dom_real_confirmation_failed_receipt_and_role_controls(self):
        for step,key,value in (('wrong_source_prepared','handoff','bad'),('operator_a_disabled','control','prepare_approve'),('unknown_failed','receipt','bad'),('stale_receipt_failed','revision',2),('wrong_policy_failed','stale',False)):
            args=list(dom_fixture()); d=next(r for r in args[0] if r['step'] == step)['dom']
            if key == 'handoff': d['confirmation']['binding']['approvalId']=C.CONTRACT['unknownApprovalId']
            elif key == 'control': next(v for v in d['controls'] if v['key'] == value)['enabled']=True
            elif key == 'receipt': d['receipt']=copy.deepcopy(next(r for r in args[0] if r['step'] == 'unknown_receipt')['dom']['receipt'])
            elif key == 'revision': d['receipt']['revision']=value
            else: d['stale']['sources']=value
            with self.subTest(step=step),self.assertRaises(ValueError): C.validate_dom(*args)
        for step,key,field,value in (('anonymous','refresh_source','present',True),('operator_connected','read_receipt','enabled',False),('unknown_failed','refresh_source','enabled',False),('unknown_receipt','confirm','enabled',True),('final_mobile','node_next','enabled',True),('hidden','clear','enabled',False)):
            args=list(dom_fixture()); control=next(v for v in next(r for r in args[0] if r['step'] == step)['dom']['controls'] if v['key'] == key); control[field]=value
            with self.subTest(step=step,key=key),self.assertRaises(ValueError): C.validate_dom(*args)

    def test_32_dom_hidden_clear_quarantine_and_node_privacy(self):
        for mode in ('clear','hidden','accept','node','samplerrole'):
            args=list(dom_fixture()); rows=args[0]
            if mode == 'clear': rows[-1]['dom']['sources']=copy.deepcopy(rows[-2]['dom']['sources'])
            elif mode == 'hidden': next(r for r in rows if r['step'] == 'hidden')['dom']['pageVisible']=True
            elif mode == 'accept': next(r for r in rows if r['step'] == 'fetched_quarantined')['dom']['sources'][0]['accepted']=True
            elif mode == 'node': next(r for r in rows if r['step'] == 'nodes_quarantined')['dom']['nodes'][0]['label']='secret'
            else: next(r for r in rows if r['step'] == 'api_stale_conflict')['actorRole']='approver'
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_dom(*args)


if __name__ == '__main__': unittest.main()
