"""Independent raw-observation verifier for the fixed local-admission UI flow.

Only neutral byte/JSON/PNG/TLS tools are shared with the previous checker. Its
business verifier and constants remain unchanged. Private file-to-POST matching
and private database projections remain explicitly trusted CI observations.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess

_spec=importlib.util.spec_from_file_location('admission_neutral_primitives',Path(__file__).with_name('check_subscription_ui.py'))
H=importlib.util.module_from_spec(_spec); _spec.loader.exec_module(H)
need,exact,integer,boolean,same=H.need,H.exact,H.integer,H.boolean,H.same
sha,digest,identifier,canonical,decode,read=H.sha,H.digest,H.identifier,H.canonical,H.decode,H.read
unbase64,timestamp,png,verify_tls,git_bytes=H.unbase64,H.timestamp,H.png,H.verify_tls,H.git_bytes
ELF_SHA='ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
PIN_SHA='404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
TAG='41520584daa68d0040db7746ae562a0ff82187f6'
BASE='/api/v1/subscriptions'
CONTRACT_PATH='chengwang/deploy/subscription-ui-browser/admission-contract.json'
CONTRACT=decode(read(Path(__file__).with_name('admission-contract.json')))
SCOPE=CONTRACT['scopeValue']
PUBLIC=set(CONTRACT['publicFiles'])
ACTIONS=CONTRACT['actions']
STEPS=CONTRACT['steps']
ROLES=('operator','approver','viewer','auditor')
CONTROL_KEYS=('connect','clear','refresh_sources','prepare_create','refresh_source','prepare_import','prepare_approve','prepare_fetch','prepare_admit','prepare_reject','prepare_rollback','confirm','cancel','candidate_previous','candidate_next','node_previous','node_next','read_receipt')
COUNTERS=('runtimeErrors','consoleErrors','consoleWarnings','cspErrors','assetErrors','forbiddenRequests','failedRequests','captureErrors')
POST_STEPS={'created_a':1,'created_b':2,'imported_a':3,'imported_b':4,'admitted_a':5,'imported_a2':6,'admitted_a2':7,'imported_a3':8,'rejected_a3':9,'rolled_back':10}
SELECTED_CANDIDATES={'nodes_a':'a1','nodes_b':'b1','viewer_a':'a1','auditor_b':'b1','approver_a':'a1','admit_a_prepared':'a1','approver_a2':'a2','approver_a3':'a3','rollback_prepared':'a1','rollback_checked':'a1','nodes_restored':'a1','final_desktop':'a1','final_mobile':'a1','receipt':'a1','hidden':'a1','returned':'a1'}
CLEAR_RECEIPT_STEPS={'anonymous','operator_connected','viewer_a','auditor_b','approver_a','admit_a_prepared','operator_a','approver_a2','operator_a3','approver_a3','cleared'}


def json_lines(raw,maximum=256):
    need(type(raw) is bytes and raw.endswith(b'\n') and 0<len(raw.splitlines())<=maximum)
    return [decode(line) for line in raw.splitlines()]


def scope(value): same(value,SCOPE)


def safe_source(value):
    need(type(value) is dict and {'id','scope','label','revision','updatedAt'}<=set(value)<= {'id','scope','label','revision','updatedAt','acceptedCandidateId','latestCandidateId'})
    identifier(value['id'],'src'); scope(value['scope']); integer(value['revision'],1,8); timestamp(value['updatedAt'])
    need(value['label'] in CONTRACT['labels'].values())
    for key in ('acceptedCandidateId','latestCandidateId'):
        if key in value: identifier(value[key],'cand')


def safe_receipt(value,kind):
    keys={'commandId','kind','sourceId','revision','state','replayed','stateMayHaveChanged','auditRecorded','preparedAuditHash','resultAuditHash','localAuditHash','completedAt'}
    if kind!='create': keys|={'candidateId','candidateDigest'}
    exact(value,keys); identifier(value['commandId'],'cmd'); identifier(value['sourceId'],'src'); integer(value['revision'],1,8)
    need(value['kind']==kind and value['state']=='committed' and value['replayed'] is False and value['stateMayHaveChanged'] is False and value['auditRecorded'] is True)
    for key in ('preparedAuditHash','resultAuditHash','localAuditHash'): digest(value[key])
    if kind!='create':
        identifier(value['candidateId'],'cand'); need(type(value['candidateDigest']) is str and re.fullmatch('hmac-sha256:[a-f0-9]{64}',value['candidateDigest']))
    timestamp(value['completedAt'])


def envelope(raw):
    value=decode(raw); exact(value,('boundary','authorization','deviceActionsExecuted','stateMayHaveChanged','result'))
    need(value['boundary']=='LOCAL_SUBSCRIPTION_ADMISSION_ONLY' and value['authorization']=='BLOCKED' and value['deviceActionsExecuted'] is False and value['stateMayHaveChanged'] is False)
    return value['result']


def expected_access(role,sid=None):
    need(role in ROLES)
    actions=['subscription.read']
    if sid is None and role=='operator': actions+=['subscription.source.manage']
    if sid is not None and role=='operator': actions+=['subscription.import','subscription.fetch']
    if sid is not None and role=='approver': actions+=['subscription.admission.decide','subscription.source.approve','subscription.rollback']
    return dict(scope=SCOPE,resource=dict(type='subscription-store' if sid is None else 'subscription-source',id='local' if sid is None else sid),writesEnabled=True,actions=actions,policyState='not_configured',references=[])


def safe_nodes(value):
    need(type(value) is list and len(value)==2)
    ids=[]
    for node in value:
        exact(node,('id','label','protocol','credentialConfigured','state')); identifier(node['id'],'node')
        need(node['label']=='节点-'+node['id'][-8:] and node['state']=='unknown' and node['credentialConfigured'] is True and node['protocol'] in ('http','socks5'))
        ids.append(node['id'])
    need(ids==sorted(set(ids)) and {n['protocol'] for n in value}=={'http','socks5'})


def validate_rows(rows,build):
    need(type(rows) is list and 1<=len(rows)<=256); ids=set(); starts=set(); decoded={}; body_total=0
    dist={f['path']:f for f in build['distFiles']}
    for ordinal,row in enumerate(rows,1):
        exact(row,CONTRACT['captureKeys']); same(row['ordinal'],ordinal); need(row['schema']==CONTRACT['captureSchema'])
        integer(row['requestOrdinal'],1,256); need(row['requestOrdinal'] not in starts); starts.add(row['requestOrdinal'])
        need(type(row['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',row['requestId']) and row['requestId'] not in ids); ids.add(row['requestId'])
        same(row['status'],200); boolean(row['authorizationPresent']); need(row['method'] in ('GET','POST') and row['kind'] in CONTRACT['captureKinds'])
        for k in ('startedWallTimeUs','startTimeUs','headerTimeUs','endTimeUs'): integer(row[k],1)
        need(row['headerTimeUs']>=row['startTimeUs'] and row['endTimeUs']>=row['startTimeUs'])
        exact(row['terminal'],('event','encodedDataLength')); need(row['terminal']['event']=='FINISH'); integer(row['terminal']['encodedDataLength'],0,16<<20)
        static=row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT')
        need(row['actorRole']=='anonymous' if static else row['actorRole'] in ROLES)
        same(row['authorizationPresent'],not static)
        body=unbase64(row['responseBase64'],8<<20 if row['kind'] in ('DOCUMENT','ASSET') else 65536)
        body_total+=len(body); need(body_total<=16<<20); same(row['responseBytes'],len(body)); need(row['responseSHA256']==sha(body))
        need(b'PRIVATE KEY' not in body and (row['kind']=='ASSET' or b'Bearer ' not in body))
        kind,path=row['kind'],row['path']
        if kind in ('DOCUMENT','ASSET'):
            need(row['method']=='GET' and (path=='/' if kind=='DOCUMENT' else type(path) is str and re.fullmatch(r'/assets/[A-Za-z0-9_.-]+',path)))
            rel='index.html' if kind=='DOCUMENT' else path[1:]; need(rel in dist)
            same(dict(bytes=len(body),sha256=sha(body)),{k:dist[rel][k] for k in ('bytes','sha256')})
        elif kind=='SNAPSHOT':
            need(row['method']=='GET' and path=='/api/v1/snapshot'); decode(body,allow_float=True)
        else: decoded[ordinal]=envelope(body)
        if row['method']=='GET': need(row['requestPublic'] is None)
        else: need(kind in ('CREATE','IMPORT','DECIDE','ROLLBACK'))
    need(starts==set(range(1,len(rows)+1)))
    for kind in ('DOCUMENT','SNAPSHOT','RECEIPT'): need(sum(r['kind']==kind for r in rows)==1)
    assets=[r['path'] for r in rows if r['kind']=='ASSET']; need(assets and len(assets)==len(set(assets)))
    need(sum(r['method']=='POST' for r in rows)==10)
    return decoded


def reconstruct(rows,decoded):
    posts=sorted((r for r in rows if r['method']=='POST'),key=lambda r:r['requestOrdinal'])
    need(len(posts)==10 and [a['key'] for a in ACTIONS]==['create_a','create_b','import_a','import_b','admit_a','import_a2','admit_a2','import_a3','reject_a3','rollback_a'])
    sources,candidates={},{}; aliases={'sources':{},'candidates':{}}; states=[dict(sources={},candidates={})]; receipts={}; keys=set()
    for action,row in zip(ACTIONS,posts):
        need(row['actorRole']==action['role'] and row['kind']==action['kind'].upper())
        rc=decoded[row['ordinal']]; safe_receipt(rc,action['kind']); need(rc['commandId'] not in receipts); receipts[rc['commandId']]=rc
        public=row['requestPublic']; kind=action['kind']; alias=action['source']
        if kind=='create':
            exact(public,('label','idempotencyKey')); need(public['label']==CONTRACT['labels'][alias] and row['path']==BASE+'/sources')
            sid=rc['sourceId']; need(sid not in sources); aliases['sources'][alias]=sid
            source=dict(id=sid,scope=SCOPE,label=public['label'],revision=1,updatedAt=rc['completedAt']); sources[sid]=source
        else:
            sid=aliases['sources'][alias]; need(rc['sourceId']==sid and sources[sid]['revision']==action['fromRevision'])
            suffix={'import':'/candidates','decide':'/decisions','rollback':'/rollbacks'}[kind]
            need(row['path']==BASE+'/sources/'+sid+suffix)
            fields={'sourceId','expectedRevision','idempotencyKey'}|({'format','contentBytes'} if kind=='import' else {'candidateId','expectedDigest','decision'} if kind=='decide' else {'candidateId'})
            exact(public,fields); need(public['sourceId']==sid); same(public['expectedRevision'],action['fromRevision'])
            if kind=='import':
                need(public['format']=='mihomo-provider-yaml'); integer(public['contentBytes'],1,1<<20)
                cid=rc['candidateId']; need(cid not in candidates); aliases['candidates'][action['candidate']]=cid
                candidates[cid]=dict(id=cid,sourceId=sid,digest=rc['candidateDigest'],format='mihomo-provider-yaml',state='quarantined',baseRevision=action['toRevision'],nodeCount=2,duplicateCount=0)
                sources[sid]['latestCandidateId']=cid
            else:
                cid=aliases['candidates'][action['candidate']]; need(public['candidateId']==rc['candidateId']==cid and rc['candidateDigest']==candidates[cid]['digest'] and candidates[cid]['sourceId']==sid)
                if kind=='decide':
                    need(candidates[cid]['state']=='quarantined' and candidates[cid]['baseRevision']==action['fromRevision'] and public['expectedDigest']==candidates[cid]['digest'] and public['decision']==action['decision'])
                    candidates[cid]['state']=action['decision']
                    if action['decision']=='admitted_local': sources[sid]['acceptedCandidateId']=cid
                else: need(candidates[cid]['state']=='admitted_local'); sources[sid]['acceptedCandidateId']=cid
            sources[sid].update(revision=action['toRevision'],updatedAt=rc['completedAt'])
        same(rc['revision'],action['toRevision'])
        key=public['idempotencyKey']; need(type(key) is str and re.fullmatch('sub_[a-f0-9]{32}',key) and key not in keys); keys.add(key)
        states.append(copy.deepcopy(dict(sources=sources,candidates=candidates)))
    need(len(set(aliases['sources'].values()))==2 and len(set(aliases['candidates'].values()))==4)
    a,b=aliases['sources']['a'],aliases['sources']['b']; final=states[-1]
    need(final['sources'][a]['revision']==8 and final['sources'][b]['revision']==2 and final['sources'][a]['acceptedCandidateId']==aliases['candidates']['a1'] and final['sources'][a]['latestCandidateId']==aliases['candidates']['a3'] and final['sources'][b]['latestCandidateId']==aliases['candidates']['b1'])
    return dict(posts=posts,states=states,aliases=aliases,receipts=receipts,candidateCreatedAt={},nodeViews={},sourcePages={},candidatePages={},nodePages={})


def possible_states(row,facts):
    # All comparisons remain in CDP's monotonic domain. FINISH may precede
    # HEADERS dispatch; neither browser wallTime nor Go wall time is mixed in.
    lower=max([0]+[i+1 for i,p in enumerate(facts['posts']) if p['endTimeUs']<row['startTimeUs']])
    upper=min([10]+[i for i,p in enumerate(facts['posts']) if p['startTimeUs']>row['endTimeUs']])
    need(lower<=upper)
    return facts['states'][lower:upper+1]


def candidate_summary(value,facts):
    exact(value,('id','sourceId','digest','format','state','baseRevision','nodeCount','duplicateCount','createdAt'))
    identifier(value['id'],'cand'); identifier(value['sourceId'],'src'); timestamp(value['createdAt'])
    cid=value['id']; need(cid in facts['states'][-1]['candidates'])
    if cid in facts['candidateCreatedAt']: need(facts['candidateCreatedAt'][cid]==value['createdAt'])
    else: facts['candidateCreatedAt'][cid]=value['createdAt']
    out={k:v for k,v in value.items() if k!='createdAt'}
    return out


def validate_gets(rows,decoded,facts):
    for row in rows:
        if row['method']!='GET' or row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT'): continue
        kind,path,value,role=row['kind'],row['path'],decoded[row['ordinal']],row['actorRole']
        if kind=='COLLECTION_ACCESS': need(path==BASE+'/access'); same(value,expected_access(role)); continue
        if kind=='SOURCE_ACCESS':
            match=re.fullmatch(re.escape(BASE)+r'/sources/(src_[a-f0-9]{32})/access',path); need(match is not None)
            need(match[1] in facts['states'][-1]['sources']); same(value,expected_access(role,match[1])); continue
        if kind=='RECEIPT':
            rc=decoded[facts['posts'][-1]['ordinal']]; need(role=='approver' and path==BASE+'/commands/'+rc['commandId']); same(value,rc); continue
        allowed=possible_states(row,facts)
        if kind=='SOURCES':
            need(path==BASE+'/sources'); exact(value,('sources','total')); need(type(value['sources']) is list); same(value['total'],len(value['sources']))
            for item in value['sources']: safe_source(item)
            need([s['id'] for s in value['sources']]==sorted({s['id'] for s in value['sources']}))
            need(any(value['sources']==sorted(state['sources'].values(),key=lambda s:s['id']) for state in allowed)); facts['sourcePages'][row['ordinal']]=value
        elif kind in ('CANDIDATES','NODES'):
            pattern=re.escape(BASE)+r'/sources/(src_[a-f0-9]{32})'+(r'/candidates' if kind=='CANDIDATES' else r'/candidates/(cand_[a-f0-9]{32})/nodes')+r'\?limit=20&offset=0&revision=([1-8])'
            match=re.fullmatch(pattern,path); need(match is not None); sid=match[1]; revision=int(match[2 if kind=='CANDIDATES' else 3])
            exact(value,('candidates','total','revision') if kind=='CANDIDATES' else ('nodes','total','revision')); same(value['revision'],revision)
            available=[s for s in allowed if sid in s['sources'] and s['sources'][sid]['revision']==revision]; need(available)
            if kind=='CANDIDATES':
                need(type(value['candidates']) is list); summaries=[candidate_summary(v,facts) for v in value['candidates']]
                same(value['total'],len(summaries)); need([v['id'] for v in summaries]==sorted({v['id'] for v in summaries}))
                need(any(summaries==sorted([c for c in state['candidates'].values() if c['sourceId']==sid],key=lambda c:c['id']) for state in available))
                facts['candidatePages'][row['ordinal']]=dict(sourceId=sid,**value)
            else:
                cid=match[2]; need(cid in facts['states'][-1]['candidates'] and facts['states'][-1]['candidates'][cid]['sourceId']==sid)
                need(any(cid in s['candidates'] for s in available)); safe_nodes(value['nodes']); same(value['total'],2)
                if cid in facts['nodeViews']: same(value['nodes'],facts['nodeViews'][cid])
                else: facts['nodeViews'][cid]=value['nodes']
                facts['nodePages'][row['ordinal']]=dict(sourceId=sid,candidateId=cid,**value)
        else: need(False)
    need(set(facts['nodeViews'])==set(facts['states'][-1]['candidates']))
    sets=[{n['id'] for n in facts['nodeViews'][cid]} for cid in facts['aliases']['candidates'].values()]
    # All three fixture connection sets change, while first is reused across
    # sources; source-scoped identities must still keep all four disjoint.
    need(len(set.union(*sets))==8)


def validate_audit(rows,checkpoint,facts):
    need(type(rows) is list and len(rows)==20); previous='0'*64; pairs={}; event_ids=set()
    for event in rows:
        exact(event,('id','idempotencyKey','traceId','actorId','action','target','result','occurredAt','data','previousHash','hash'))
        need(type(event['id']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',event['id']) and event['id'] not in event_ids); event_ids.add(event['id'])
        need(type(event['actorId']) is str and re.fullmatch('act_[a-f0-9]{60}',event['actorId'])); timestamp(event['occurredAt'])
        need(event['previousHash']==previous and event['hash']==sha(H.go_event_bytes(event))); previous=event['hash']
        cid=identifier(event['traceId'],'cmd'); need(cid in facts['receipts']); stage=event['result']; need(stage in ('prepared','result') and stage not in pairs.setdefault(cid,{}))
        need(event['action']=='subscription.command.'+stage and event['idempotencyKey']=='subscription/'+cid+'/'+stage)
        data=event['data']; base={'tenantId','siteId','environment','managementObject','kind','commandDigest'}
        exact(data,base|({'state','code','sourceId','candidateId','revision','candidateDigest','localAuditHash','approvalId','policyDigest','policyRevision','stateMayHaveChanged'} if stage=='result' else set()))
        need(all(type(v) is str for v in data.values()) and all(data[k]==v for k,v in SCOPE.items()) and data['managementObject']=='local' and re.fullmatch('hmac-sha256:[a-f0-9]{64}',data['commandDigest']))
        pairs[cid][stage]=event
    same(checkpoint,dict(count=20,lastHash=previous)); role_actors={}
    for action,row in zip(ACTIONS,facts['posts']):
        rc=facts['receipts'][envelope(unbase64(row['responseBase64'],65536))['commandId']]; pair=pairs[rc['commandId']]; need(set(pair)=={'prepared','result'})
        a,b=pair['prepared'],pair['result']; need(a['actorId']==b['actorId'] and timestamp(a['occurredAt'])<=timestamp(b['occurredAt']) and a['data']=={k:b['data'][k] for k in a['data']})
        role=action['role']; need(role not in role_actors or role_actors[role]==a['actorId']); role_actors[role]=a['actorId']
        need(a['hash']==rc['preparedAuditHash'] and b['hash']==rc['resultAuditHash'] and b['occurredAt']==rc['completedAt'])
        target='local' if action['kind']=='create' else rc['sourceId']; need(a['target']==b['target']=='subscription/'+target)
        expected=dict(**SCOPE,managementObject='local',kind=action['kind'],commandDigest=a['data']['commandDigest'],state='committed',code='',sourceId=rc['sourceId'],candidateId=rc.get('candidateId',''),revision=str(rc['revision']),candidateDigest=rc.get('candidateDigest',''),localAuditHash=rc['localAuditHash'],approvalId='',policyDigest='',policyRevision='0',stateMayHaveChanged='false')
        same(b['data'],expected)
    need(set(role_actors)=={'operator','approver'} and len(set(role_actors.values()))==2)
    return role_actors


def validate_private(value,facts,actors,commit,fixture):
    exact(value,('schema','sourceCommit','fixtureId','scope','sources','candidates','localAuditCount','commandCount','approvalCount','commands'))
    need(value['schema']==CONTRACT['readbackSchema'] and value['sourceCommit']==commit and value['fixtureId']==fixture); scope(value['scope'])
    same(value['localAuditCount'],10); same(value['commandCount'],10); same(value['approvalCount'],0)
    expected_sources=sorted(facts['states'][-1]['sources'].values(),key=lambda v:v['id'])
    need(type(value['sources']) is list and len(value['sources'])==2)
    need({s['id']:s for s in value['sources']}=={s['id']:s for s in expected_sources})
    for item in value['sources']: safe_source(item)
    need(type(value['candidates']) is list and len(value['candidates'])==4); seen=set()
    for item in value['candidates']:
        exact(item,('id','sourceId','scope','digest','format','state','baseRevision','nodeCount','duplicateCount','nodes','createdAt')); cid=item['id']; need(cid not in seen); seen.add(cid); scope(item['scope']); safe_nodes(item['nodes'])
        expected=dict(**facts['states'][-1]['candidates'][cid],scope=SCOPE,nodes=facts['nodeViews'][cid],createdAt=facts['candidateCreatedAt'][cid]); same(item,expected)
    need(seen==set(facts['states'][-1]['candidates']))
    need(type(value['commands']) is list and len(value['commands'])==10); commands={c['id']:c for c in value['commands']}; need(len(commands)==10 and set(commands)==set(facts['receipts']))
    for action,row in zip(ACTIONS,facts['posts']):
        rc=envelope(unbase64(row['responseBase64'],65536)); expected=dict(id=rc['commandId'],scope=SCOPE,actorId=actors[action['role']],kind=action['kind'],expectedRevision=action['fromRevision'],preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True)
        if action['kind']!='create': expected['sourceId']=rc['sourceId']
        result={k:rc[k] for k in ('sourceId','candidateId','revision','state','stateMayHaveChanged','localAuditHash','completedAt') if k in rc}
        if 'candidateDigest' in rc: result['digest']=rc['candidateDigest']
        expected['result']=result; same(commands[rc['commandId']],expected)


def role_for_step(step):
    if step in ('anonymous','cleared'): return 'anonymous'
    if step=='viewer_a': return 'viewer'
    if step=='auditor_b': return 'auditor'
    if step.startswith('approver') or step.startswith(('admit','reject','rollback','rolled','nodes_restored','final_')) or step in ('receipt','hidden','returned'): return 'approver'
    return 'operator'


def control_projection(value):
    exact(value,('key','present','visible','enabled','inViewport','unobstructed','rect'))
    for k in ('present','visible','enabled','inViewport','unobstructed'): boolean(value[k])
    need(value['present'] or not any(value[k] for k in ('visible','enabled','inViewport','unobstructed')))
    need(value['visible']==(value['rect'] is not None) and (not value['inViewport'] or value['visible']) and (not value['unobstructed'] or value['inViewport']))
    if value['rect'] is not None:
        exact(value['rect'],('x','y','width','height'))
        for k in ('x','y'): integer(value['rect'][k],-100000,100000)
        for k in ('width','height'): integer(value['rect'][k],0,100000)


def validate_decision_controls(controls,role,candidate,current_revision):
    """Stable rendered controls must reflect actual candidate eligibility.

    This never authorizes a write or changes rollback requirements. The API
    metadata and independent state machine still verify role/source/CAS.
    """
    need(role in (*ROLES,'anonymous'))
    eligible=False
    if candidate is not None:
        integer(candidate['baseRevision'],1); integer(current_revision,1)
        need(candidate['state'] in ('quarantined','admitted_local','rejected'))
        eligible=role=='approver' and candidate['state']=='quarantined' and candidate['baseRevision']==current_revision
    for key in ('prepare_admit','prepare_reject'): same(controls[key]['enabled'],eligible)


def validate_dom(rows,captures,decoded,facts):
    need(type(rows) is list and len(rows)==37); count=0; previous_capture=0; last_receipt=None
    for ordinal,(row,step) in enumerate(zip(rows,STEPS),1):
        exact(row,CONTRACT['domStepKeys']); need(row['schema']==CONTRACT['domSchema'] and row['step']==step); same(row['ordinal'],ordinal)
        if step in POST_STEPS: count=POST_STEPS[step]; last_receipt=decoded[facts['posts'][count-1]['ordinal']]
        if step in CLEAR_RECEIPT_STEPS: last_receipt=None
        role=role_for_step(step); need(row['actorRole']==role); same(row['mutationCount'],count); integer(row['captureCount'],previous_capture,len(captures)); previous_capture=row['captureCount']
        seen=captures[:row['captureCount']]; need(sum(c['method']=='POST' for c in seen)==count)
        d=row['dom']; exact(d,('schema','pageMounted','pageVisible','https','viewport','session','controls','sources','candidates','nodes','paging','mode','directory','sessionApproval','handoff','confirmation','receipt','stale','alertVisible','boundaryVisible'))
        need(d['schema']=='chengwang.subscription-browser-dom/v1' and d['pageMounted'] is True and d['https'] is True and d['alertVisible'] is False)
        same(d['pageVisible'],step!='hidden'); same(d['boundaryVisible'],step!='hidden')
        vp=d['viewport']; exact(vp,('width','height','scrollX','scrollY','clientWidth','scrollWidth'))
        for k in ('width','height','clientWidth','scrollWidth'): integer(vp[k],1,100000)
        for k in ('scrollX','scrollY'): integer(vp[k],-100000,100000)
        same(vp['height'],900); same(vp['width'],375 if step in ('final_mobile','receipt','hidden','returned','cleared') else 1440)
        need(vp['scrollWidth']==vp['clientWidth'] and vp['clientWidth']<=vp['width'])
        session=d['session']; exact(session,('tokenMounted','tokenType','tokenEmpty','fileMounted','fileEmpty','storageEmpty','cookiesEmpty'))
        same(session,dict(tokenMounted=True,tokenType='password',tokenEmpty=True,fileMounted=True,fileEmpty=True,storageEmpty=True,cookiesEmpty=True))
        controls=d['controls']; need(type(controls) is list and len(controls)==len(CONTROL_KEYS))
        for ctl,key in zip(controls,CONTROL_KEYS): control_projection(ctl); need(ctl['key']==key)
        ctl={c['key']:c for c in controls}; need(ctl['prepare_create']['enabled']==(role=='operator'))
        same(d['stale'],dict(sources=False,candidates=False,nodes=False)); need(d['sessionApproval'] is None and d['handoff'] is None and d['mode']=='session')
        same(d['directory'],dict(present=True,disabled=True,references=[]))
        need(d['paging']['nodes'] is None if step not in SELECTED_CANDIDATES else d['paging']['nodes'] is not None)
        exact(d['paging'],('candidates','nodes'))
        state=facts['states'][count]; cleared=step=='cleared'; expected_sources=[] if cleared else sorted(state['sources'].values(),key=lambda s:s['id'])
        alias=None if count==0 or cleared else 'b' if step in ('created_b','imported_b','nodes_b','auditor_b') else 'a'
        selected_sid=facts['aliases']['sources'].get(alias)
        expected_dom_sources=[dict(id=s['id'],revision=s['revision'],selected=s['id']==selected_sid,accepted='acceptedCandidateId' in s,disabled=False) for s in expected_sources]
        same(d['sources'],expected_dom_sources)
        cid_alias=SELECTED_CANDIDATES.get(step); selected_cid=facts['aliases']['candidates'].get(cid_alias)
        validate_decision_controls(ctl,role,state['candidates'].get(selected_cid),state['sources'][selected_sid]['revision'] if selected_sid else None)
        expected_candidates=[] if selected_sid is None else sorted([c for c in state['candidates'].values() if c['sourceId']==selected_sid],key=lambda c:c['id'])
        same(d['candidates'],[dict(id=c['id'],state=c['state'],nodeCount=2,format='mihomo-provider-yaml',baseRevision=c['baseRevision'],selected=c['id']==selected_cid) for c in expected_candidates])
        same(d['nodes'],[{k:v for k,v in n.items() if k!='label'} for n in facts['nodeViews'][selected_cid]] if selected_cid else [])
        if selected_sid:
            revision=state['sources'][selected_sid]['revision']; same(d['paging']['candidates'],dict(page=1,revision=revision))
            candidates_seen=[r for r in seen if r['actorRole']==role and r['ordinal'] in facts['candidatePages'] and facts['candidatePages'][r['ordinal']]['sourceId']==selected_sid and facts['candidatePages'][r['ordinal']]['revision']==revision]
            need(candidates_seen)
            if selected_cid:
                same(d['paging']['nodes'],dict(page=1,revision=revision))
                need(any(r['actorRole']==role and r['ordinal'] in facts['nodePages'] and facts['nodePages'][r['ordinal']]['candidateId']==selected_cid and facts['nodePages'][r['ordinal']]['revision']==revision for r in seen))
        else: need(d['paging']['candidates'] is None)
        if last_receipt is None: need(d['receipt'] is None)
        else: same(d['receipt'],{k:last_receipt[k] for k in ('commandId','revision','state','replayed','auditRecorded')})
        prepared=step in ('create_a_prepared','create_a_prepared_again','import_a_prepared','import_a_prepared_again','admit_a_prepared','rollback_prepared','rollback_checked')
        if prepared:
            kind='create' if step.startswith('create') else 'import' if step.startswith('import') else 'admit' if step=='admit_a_prepared' else 'rollback'
            same(d['confirmation'],dict(kind=kind,binding=None,unverifiedReference=False,rollbackRequired=kind=='rollback',rollbackChecked=step=='rollback_checked'))
            need(ctl['cancel']['enabled'] and ctl['confirm']['enabled']==(step!='rollback_prepared'))
        else: need(d['confirmation'] is None)
        if role in ('viewer','auditor'): need(all(not ctl[k]['enabled'] for k in ('prepare_create','prepare_import','prepare_approve','prepare_fetch','prepare_admit','prepare_reject','prepare_rollback')))
        if role=='approver': need(not ctl['prepare_import']['enabled'] and not ctl['prepare_approve']['enabled'] and not ctl['prepare_fetch']['enabled'])
        if role=='operator': need(not ctl['prepare_admit']['enabled'] and not ctl['prepare_reject']['enabled'] and not ctl['prepare_rollback']['enabled'])
        if step=='anonymous': need(not any(r['authorizationPresent'] for r in seen))
        if step=='receipt': need(any(r['kind']=='RECEIPT' for r in seen))
    need(rows[-1]['captureCount']==len(captures))


def validate_supervisor(p,iso,inputs,build,d,receipt_value,repo,commit,engine,fixture):
    prefix='chengwang.subscription-ui-supervisor/v1'
    for value in (p,iso,inputs): need(value['schema']==prefix and value['sourceCommit']==commit and value['fixtureId']==fixture and value['engine']==engine and value['production'] is False)
    exact(p,('schema','sourceCommit','fixtureId','engine','records','serverExitCode','controllerExitCode','noLiveOwnedProcesses','forcedSignals','processScope','production'))
    exact(inputs,('schema','sourceCommit','fixtureId','engine','copiedInputs','inputTrustScope','production'))
    exact(iso,('schema','sourceCommit','fixtureId','engine','hostBefore','hostAfter','sourceFilesBefore','sourceFilesAfter','lab','production','authorization','deviceActionsExecuted','pythonBinaryProvenanceProven'))
    need(p['processScope']=='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION' and inputs['inputTrustScope']=='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    need(iso['authorization']=='BLOCKED' and iso['deviceActionsExecuted'] is False and iso['pythonBinaryProvenanceProven'] is False)
    same(iso['hostBefore'],iso['hostAfter']); same(iso['sourceFilesBefore'],iso['sourceFilesAfter']); host=iso['hostBefore']
    exact(host,('netNamespace','mountNamespace','pidNamespace','userNamespace','portStart','systemCASHA256','sourceSHA256')); integer(host['portStart'],0,65535)
    for name,kind in (('netNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid'),('userNamespace','user')): need(type(host[name]) is str and re.fullmatch(kind+r':\[[0-9]+\]',host[name]))
    digest(host['systemCASHA256']); digest(host['sourceSHA256'])
    sources=iso['sourceFilesBefore']; need(type(sources) is list and 1<=len(sources)<=8192); source_map={}
    for item in sources:
        exact(item,('path','bytes','sha256')); path=item['path']; need(type(path) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+',path) and '..' not in path.split('/') and path not in source_map and path.startswith(('chengwang/','.github/workflows/')))
        original=git_bytes(repo,commit,path); same(item['bytes'],len(original)); need(item['sha256']==sha(original)); source_map[path]=item
    tracked=subprocess.check_output(['git','-c','safe.directory='+str(repo),'-C',str(repo),'ls-tree','-r','-z','--name-only',commit,'--','chengwang','.github/workflows'],stderr=subprocess.DEVNULL)
    need(set(source_map)=={x.decode() for x in tracked.split(b'\0') if x} and sha(canonical(sources))==host['sourceSHA256'])
    own='chengwang/deploy/subscription-ui-browser/check_admission_ui.py'; need(own in source_map and git_bytes(repo,commit,own)==read(Path(__file__)))
    lab=iso['lab']; exact(lab,('namespaces','defaultIPv4Routes','defaultIPv6Routes','interfaces','sourceMount','bundleMount','tmpMount'))
    same(lab['defaultIPv4Routes'],0); same(lab['defaultIPv6Routes'],0); same(lab['interfaces'],['lo']); exact(lab['namespaces'],('net','mnt','pid','user'))
    for key in lab['namespaces']: need(type(lab['namespaces'][key]) is str and re.fullmatch(key+r':\[[0-9]+\]',lab['namespaces'][key]))
    need(lab['namespaces']['user']==host['userNamespace'])
    for key,name in (('net','netNamespace'),('mnt','mountNamespace'),('pid','pidNamespace')): need(lab['namespaces'][key]!=host[name])
    for key in ('sourceMount','bundleMount','tmpMount'):
        need(type(lab[key]) is list and all(type(v) is str for v in lab[key]) and len(set(lab[key]))==len(lab[key]))
    for key in ('sourceMount','bundleMount'): need({'ro','nosuid','nodev'}<=set(lab[key]))
    need({'rw','nosuid','nodev','noexec'}<=set(lab['tmpMount']))
    copied={}
    for item in inputs['copiedInputs']:
        exact(item,('path','bytes','sha256')); path=item['path']; need(type(path) is str and path not in copied and '..' not in path.split('/')); integer(item['bytes'],0,512<<20); digest(item['sha256']); copied[path]=item
        if path.startswith('chengwang/'):
            original=source_map.get(path.removesuffix(':launcher')); need(original is not None)
            same({k:item[k] for k in ('bytes','sha256')},{k:original[k] for k in ('bytes','sha256')})
        else: need(path.startswith(('chrome/','npm/playwright-core/','dist/')) or path in ('toolchain/node','toolchain/server','build/report.json'))
    for path in ('chrome/chrome','toolchain/node','toolchain/server','npm/playwright-core/package.json'): need(path in copied)
    same({k:copied['toolchain/server'][k] for k in ('bytes','sha256')},{k:build['server'][k] for k in ('bytes','sha256')})
    same({k:copied['chrome/chrome'][k] for k in ('bytes','sha256')},dict(bytes=305061192,sha256=ELF_SHA))
    same([{**item,'path':item['path'][5:]} for path,item in sorted(copied.items()) if path.startswith('dist/')],build['distFiles'])
    records=p['records']; need(type(records) is list and len(records)==3); roles={r['role']:r for r in records}; need(set(roles)=={'server','controller','chrome'} and len({r['pid'] for r in records})==3)
    same(p['serverExitCode'],0); same(p['controllerExitCode'],0); same(p['forcedSignals'],0); need(p['noLiveOwnedProcesses'] is True)
    root='/tmp/chengwang-subscription-ui-'+fixture; bundle='/tmp/chengwang-subscription-ui-tools-'+fixture
    for role,r in roles.items():
        exact(r,('pid','startTime','exeSHA256','argvSHA256','uid','gid','groups','capabilities','noNewPrivs','namespaces','limits','role','argv'))
        integer(r['pid'],2); need(type(r['startTime']) is str and re.fullmatch('[1-9][0-9]{0,19}',r['startTime'])); digest(r['exeSHA256']); digest(r['argvSHA256'])
        same(r['uid'],[10001]*4); same(r['gid'],[10001]*4); same(r['groups'],[]); same(r['noNewPrivs'],1)
        same(r['capabilities'],{k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')}); same(r['namespaces'],lab['namespaces'])
        same(r['limits'],dict(cpuSeconds=[180,180],fileBytes=[32<<20]*2,openFiles=[1024]*2,processes=[1024]*2,coreBytes=[0,0]))
        need(type(r['argv']) is list and 1<=len(r['argv'])<=128 and all(type(v) is str and len(v)<=4096 for v in r['argv']))
        need(sha(b''.join(v.encode()+b'\0' for v in r['argv']))==r['argvSHA256'])
    c=d['chrome']; exact(c,('pid','startTicks','uid','profile','argvSHA256','exeSHA256','exeBytes'))
    same(c['pid'],roles['chrome']['pid']); same(c['startTicks'],int(roles['chrome']['startTime'])); same(c['uid'],10001); same(c['exeBytes'],305061192)
    need(c['profile']==root+'/chrome-profile' and c['exeSHA256']==roles['chrome']['exeSHA256']==ELF_SHA and c['argvSHA256']==roles['chrome']['argvSHA256'])
    need(roles['controller']['exeSHA256']==copied['toolchain/node']['sha256'] and roles['server']['exeSHA256']==build['server']['sha256'])
    argv=roles['chrome']['argv']; need(argv[0]==bundle+'/chrome/chrome' and '--no-sandbox' in argv and [v for v in argv if v.startswith('--user-data-dir')]==['--user-data-dir='+root+'/chrome-profile'])
    forbidden=('--ignore-certificate-errors','--ignore-certificate-errors-spki-list','--ignore-ssl-errors','--allow-insecure-localhost','--disable-web-security','--unsafely-treat-insecure-origin-as-secure')
    need(not any(v.split('=',1)[0] in forbidden for v in argv))
    need(roles['server']['argv']==[bundle+'/server'])
    same(roles['controller']['argv'],[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/admission-cli.mjs','--root',root,'--bundle',bundle,'--engine',engine,'--source-commit',commit])
    close=d['close']; exact(close,('normalCloseCommandCompleted','chromeExit','launcherExit','noLiveOwnedProcesses','processScope'))
    need(close['normalCloseCommandCompleted'] is True and close['noLiveOwnedProcesses'] is True and close['processScope']=='CHROME_SESSION_AND_LAUNCHER_ONLY')
    same(close['chromeExit'],dict(schema='chengwang.subscription-ui-chrome-exit/v1',engine=engine,fixtureId=fixture,pid=c['pid'],startTicks=c['startTicks'],exitCode=0,joined=True,forced=False))
    same(close['launcherExit'],dict(code=0,signal=None) if engine=='chrome-cdp' else None)
    need(receipt_value['schema']=='chengwang.pinned-browser-consumption-verification/v1' and receipt_value['sourceCommit']==commit and receipt_value['state']=='PIN_ENFORCED_EXPANDED_NOT_EXECUTED'
         and receipt_value['pinSHA256']==PIN_SHA and receipt_value['pinEnforced'] is True and receipt_value['allMemberCRCsVerified'] is True and receipt_value['actualExpandedFileHashesVerified'] is True)
    same(receipt_value['zip'],dict(bytes=202676171,sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853',md5Base64='5qChIL/Gh+8hZv73vzEakQ=='))
    need(receipt_value['elf']['sha256']==ELF_SHA); same(receipt_value['elf']['bytes'],305061192)
    for k in ('browserExecuted','runtimeVersionProven','projectFixProven','publisherSignatureProven','production'): need(receipt_value[k] is False)
    return len(sources)


def verify(directory,repo,commit,engine):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}',commit) and engine in ('chrome-cdp','playwright'))
    need(not directory.is_symlink() and {p.name for p in directory.iterdir()}==PUBLIC)
    raw={name:read(directory/name,24<<20 if name=='captures.jsonl' else 16<<20) for name in PUBLIC}
    need(all(b'PRIVATE KEY' not in body and b'Bearer ' not in body for body in raw.values()))
    same(decode(git_bytes(repo,commit,CONTRACT_PATH)),CONTRACT)
    d=decode(raw['driver.json']); exact(d,CONTRACT['driverKeys']); fixture=d['fixtureId']; need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}',fixture))
    need(d['schema']==CONTRACT['driverSchema'] and d['scenario']=='local_admission' and d['sourceCommit']==commit and d['engine']==engine and d['origin']==CONTRACT['origin'] and d['scope']==CONTRACT['scope'] and d['runtime'] is True)
    for key in ('mockedResponses','injectedFetch','tlsBypass','production','fullSubscriptionE2EProven'): need(d[key] is False)
    same(d['steps'],STEPS); exact(d['counters'],COUNTERS); need(all(type(v) is int and v==0 for v in d['counters'].values()))
    exact(d['browser'],('product','revision','protocolVersion')); need(d['browser']['product'] in ('Chrome/157.0.8103.6','HeadlessChrome/157.0.8103.6') and d['browser']['revision']=='@'+TAG and d['browser']['protocolVersion']=='1.3')
    build=decode(raw['build.json']); H.validate_build(build,commit)
    captures=json_lines(raw['captures.jsonl']); decoded=validate_rows(captures,build); facts=reconstruct(captures,decoded); validate_gets(captures,decoded,facts)
    same(d['captures'],dict(path='captures.jsonl',bytes=len(raw['captures.jsonl']),sha256=sha(raw['captures.jsonl']),records=len(captures)))
    dom=json_lines(raw['dom.jsonl'],37); validate_dom(dom,captures,decoded,facts)
    actors=validate_audit(json_lines(raw['audit-events.jsonl'],20),decode(raw['audit-checkpoint.json']),facts)
    validate_private(decode(raw['private-readback.json']),facts,actors,commit,fixture)
    shots=d['screenshots']; need(type(shots) is list and len(shots)==2)
    for item,name,step,width in zip(shots,('created-desktop.png','created-mobile.png'),('final_desktop','final_mobile'),(1440,375)):
        exact(item,('path','step','bytes','sha256','viewport','scrollX','scrollY','capturedWallTimeUs'))
        need(item['path']==name and item['step']==step and item['sha256']==sha(raw[name])); same(item['bytes'],len(raw[name])); integer(item['capturedWallTimeUs'],1)
        same(item['viewport'],dict(width=width,height=900)); same(item['scrollX'],0); same(item['scrollY'],0); png(raw[name],width,900)
        projection=next(v['dom'] for v in dom if v['step']==step); same(projection['viewport']['scrollX'],0); same(projection['viewport']['scrollY'],0)
    inputs=decode(raw['inputs.json']); build_rows=[r for r in inputs['copiedInputs'] if r['path']=='build/report.json']; need(len(build_rows)==1)
    same(build_rows[0],dict(path='build/report.json',bytes=len(raw['build.json']),sha256=sha(raw['build.json'])))
    source_count=validate_supervisor(decode(raw['processes.json']),decode(raw['isolation.json']),inputs,build,d,decode(raw['pin-consumption.json']),repo,commit,engine,fixture)
    verify_tls(decode(raw['certificates.json']),d,captures)
    need({name:read(directory/name,24<<20 if name=='captures.jsonl' else 16<<20) for name in PUBLIC}==raw)
    return dict(schema='chengwang.admission-ui-verification/v1',sourceCommit=commit,engine=engine,fixtureId=fixture,outcome='PASS',scope=CONTRACT['scope'],actualBrowser=d['browser'],actualChromeELFSHA256=ELF_SHA,
        steps=37,screenshots=2,requests=len(captures),mutations=10,commands=10,externalAuditEvents=20,sourceGitBlobs=source_count,sources=2,candidates=4,sourceARevision=8,sourceBRevision=2,
        roleMetadataObserved=['operator','approver','viewer','auditor'],normalTLSOfflineVerifiedAtCapture=True,pinConsumed=True,realLocalAdmissionFlowProven=True,fullSubscriptionE2EProven=False,
        fetchDNSWireEvaluated=False,privateDatabaseRawIndependentlyVerified=False,privateRawFilesIndependentlyVerified=False,privateFileObservationTrust=CONTRACT['privateFileObservationTrust'],
        independentReproducibleBuildProven=False,screenshotVisualReviewProven=False,privateReadbackTrustBoundary='TRUSTED_RUNNER_SAFE_PROJECTION_NOT_INDEPENDENT_PRIVATE_DATABASE_VERIFICATION',
        processTrustBoundary='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION',production=False,authorization='BLOCKED',remaining=CONTRACT['remaining'],evidenceSHA256={name:sha(raw[name]) for name in sorted(raw)})


def main():
    p=argparse.ArgumentParser()
    for name in ('evidence','repo','report'): p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--source-commit',required=True); p.add_argument('--engine',required=True,choices=('chrome-cdp','playwright')); a=p.parse_args()
    evidence=a.evidence.resolve(strict=True); report=a.report.absolute()
    need(not a.evidence.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.exists() and not report.is_symlink())
    result=verify(evidence,a.repo.resolve(strict=True),a.source_commit,a.engine)
    with report.open('xb') as handle: handle.write(canonical(result)+b'\n')
    print('ADMISSION_UI_INDEPENDENT=PASS full_subscription_e2e_proven=false production=false')


if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('ADMISSION_UI_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
