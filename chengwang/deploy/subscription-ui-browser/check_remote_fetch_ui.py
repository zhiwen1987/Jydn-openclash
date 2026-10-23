"""Independent reconstruction of the bounded remote-fetch UI experiment.

Never runs a browser/product/network fixture.  Process and private Store facts
are trusted CI projections, not independent private-database attestations.
Only neutral byte/JSON/PNG/build/API-certificate primitives are shared.
"""
import argparse
import base64
import copy
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile

_spec = importlib.util.spec_from_file_location('remote_fetch_neutral', Path(__file__).with_name('check_subscription_ui.py'))
H = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(H)
need, exact, integer, boolean, same = H.need, H.exact, H.integer, H.boolean, H.same
sha, digest, identifier, canonical, decode, read = H.sha, H.digest, H.identifier, H.canonical, H.decode, H.read
unbase64, timestamp, png, git_bytes = H.unbase64, H.timestamp, H.png, H.git_bytes
CONTRACT_PATH = 'chengwang/deploy/subscription-ui-browser/remote-fetch-contract.json'
CONTRACT = decode(read(Path(__file__).with_name('remote-fetch-contract.json')))
BASE = '/api/v1/subscriptions'
SCOPE = CONTRACT['scopeValue']; STEPS = CONTRACT['steps']; ACTIONS = CONTRACT['actions']
PUBLIC = set(CONTRACT['publicFiles'])
TAG = '41520584daa68d0040db7746ae562a0ff82187f6'
ELF_SHA = 'ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
PIN_SHA = '404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
COUNTERS = ('runtimeErrors','consoleErrors','consoleWarnings','cspErrors','assetErrors','forbiddenRequests','failedRequests','captureErrors')
CONTROLS = ('connect','clear','refresh_sources','prepare_create','refresh_source','prepare_import','prepare_approve','prepare_fetch','prepare_admit','prepare_reject','prepare_rollback','confirm','cancel','candidate_previous','candidate_next','node_previous','node_next','read_receipt')
POST_STEPS = {'created':1, 'approved_b':2, 'fetched_quarantined':3, 'admitted':4}
SELECTED = {'approver_candidate','admit_prepared','nodes_admitted','final_desktop','final_mobile','receipt','hidden','returned'}
PREPARED = {'create_prepared':'create','approve_b_prepared':'approve','approve_b_prepared_again':'approve','fetch_prepared':'fetch_handoff','fetch_prepared_before_edit':'fetch_handoff','fetch_prepared_before_mode':'fetch_handoff','fetch_prepared_final':'fetch_handoff','admit_prepared':'admit'}
HANDOFF = {'handoff_empty','handoff_bound','fetch_prepared','fetch_cancelled','fetch_prepared_before_edit','handoff_edited','fetch_prepared_before_mode','handoff_returned','fetch_prepared_final'}


def json_lines(raw, maximum=256):
    need(type(raw) is bytes and raw.endswith(b'\n') and 0 < len(raw.splitlines()) <= maximum)
    return [decode(line) for line in raw.splitlines()]


def safe_source(value):
    need(type(value) is dict and {'id','scope','label','revision','updatedAt'} <= set(value) <= {'id','scope','label','revision','updatedAt','acceptedCandidateId','latestCandidateId'})
    identifier(value['id'],'src'); same(value['scope'],SCOPE); integer(value['revision'],1,3)
    need(value['label'] == CONTRACT['label']); timestamp(value['updatedAt'])
    for k in ('acceptedCandidateId','latestCandidateId'):
        if k in value: identifier(value[k],'cand')


def safe_receipt(value, kind):
    keys = {'commandId','kind','sourceId','revision','state','replayed','stateMayHaveChanged','auditRecorded','preparedAuditHash','resultAuditHash','completedAt'}
    keys |= {'referenceId','policyRevision','policyDigest','approvalId'} if kind == 'approve' else {'localAuditHash'}
    if kind in ('fetch','decide'): keys |= {'candidateId','candidateDigest'}
    exact(value,keys); identifier(value['commandId'],'cmd'); identifier(value['sourceId'],'src'); integer(value['revision'],1,3)
    need(value['kind'] == kind and value['state'] == ('approved' if kind == 'approve' else 'committed'))
    need(value['replayed'] is False and value['stateMayHaveChanged'] is False and value['auditRecorded'] is True)
    for k in ('preparedAuditHash','resultAuditHash'): digest(value[k])
    if kind != 'approve': digest(value['localAuditHash'])
    else:
        need(value['referenceId'] == 'good-b' and type(value['policyRevision']) is int and value['policyRevision'] == 1)
        need(value['approvalId'] == value['commandId'] and re.fullmatch(r'hmac-sha256:[a-f0-9]{64}',value['policyDigest']))
    if kind in ('fetch','decide'):
        identifier(value['candidateId'],'cand'); need(type(value['candidateDigest']) is str and re.fullmatch(r'hmac-sha256:[a-f0-9]{64}',value['candidateDigest']))
    timestamp(value['completedAt'])


def envelope(raw):
    value = decode(raw); exact(value,('boundary','authorization','deviceActionsExecuted','stateMayHaveChanged','result'))
    need(value['boundary'] == 'LOCAL_SUBSCRIPTION_ADMISSION_ONLY' and value['authorization'] == 'BLOCKED' and value['deviceActionsExecuted'] is False and value['stateMayHaveChanged'] is False)
    return value['result']


def expected_access(role, sid=None):
    need(role in ('operator','approver')); actions = ['subscription.read']
    if sid is None and role == 'operator': actions += ['subscription.source.manage']
    if sid is not None and role == 'operator': actions += ['subscription.import','subscription.fetch']
    if sid is not None and role == 'approver': actions += ['subscription.admission.decide','subscription.source.approve','subscription.rollback']
    return dict(scope=SCOPE,resource=dict(type='subscription-store' if sid is None else 'subscription-source',id='local' if sid is None else sid),writesEnabled=True,actions=actions,policyState='ready',references=CONTRACT['references'])


def safe_nodes(value):
    need(type(value) is list and len(value) == 2); ids = []
    for node in value:
        exact(node,('id','label','protocol','credentialConfigured','state')); identifier(node['id'],'node')
        need(node['label'] == '节点-' + node['id'][-8:] and node['credentialConfigured'] is True and node['state'] == 'unknown' and node['protocol'] in ('http','socks5'))
        ids.append(node['id'])
    need(ids == sorted(set(ids)) and {v['protocol'] for v in value} == {'http','socks5'})


def validate_rows(rows, build):
    need(type(rows) is list and 1 <= len(rows) <= 256); starts = set(); ids = set(); decoded = {}; total = 0
    dist = {v['path']:v for v in build['distFiles']}
    for ordinal,row in enumerate(rows,1):
        exact(row,CONTRACT['captureKeys']); same(row['ordinal'],ordinal); need(row['schema'] == CONTRACT['captureSchema'])
        integer(row['requestOrdinal'],1,256); need(row['requestOrdinal'] not in starts); starts.add(row['requestOrdinal'])
        need(type(row['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',row['requestId']) and row['requestId'] not in ids); ids.add(row['requestId'])
        same(row['status'],200); boolean(row['authorizationPresent']); need(row['method'] in ('GET','POST') and row['kind'] in CONTRACT['captureKinds'])
        for k in ('startedWallTimeUs','startTimeUs','headerTimeUs','endTimeUs'): integer(row[k],1)
        need(row['headerTimeUs'] >= row['startTimeUs'] and row['endTimeUs'] >= row['startTimeUs'])
        exact(row['terminal'],('event','encodedDataLength')); need(row['terminal']['event'] == 'FINISH'); integer(row['terminal']['encodedDataLength'],0,16<<20)
        static = row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT')
        need(row['actorRole'] == 'anonymous' if static else row['actorRole'] in ('operator','approver'))
        same(row['authorizationPresent'],not static)
        raw = unbase64(row['responseBase64'],8<<20 if row['kind'] in ('DOCUMENT','ASSET') else 65536)
        total += len(raw); need(total <= 16<<20); same(row['responseBytes'],len(raw)); need(row['responseSHA256'] == sha(raw))
        need(b'PRIVATE KEY' not in raw and (row['kind'] == 'ASSET' or b'Bearer ' not in raw))
        kind,path = row['kind'],row['path']
        if kind in ('DOCUMENT','ASSET'):
            need(row['method'] == 'GET' and (path == '/' if kind == 'DOCUMENT' else type(path) is str and re.fullmatch(r'/assets/[A-Za-z0-9_.-]+',path)))
            rel = 'index.html' if kind == 'DOCUMENT' else path[1:]; need(rel in dist)
            same(dict(bytes=len(raw),sha256=sha(raw)),{k:dist[rel][k] for k in ('bytes','sha256')})
        elif kind == 'SNAPSHOT': need(row['method'] == 'GET' and path == '/api/v1/snapshot'); decode(raw,allow_float=True)
        else: decoded[ordinal] = envelope(raw)
        if row['method'] == 'GET': need(row['requestPublic'] is None)
        else: need(kind in ('CREATE','APPROVE','FETCH','DECIDE'))
    need(starts == set(range(1,len(rows)+1)))
    for kind in ('DOCUMENT','SNAPSHOT','RECEIPT'): same(sum(r['kind'] == kind for r in rows),1)
    assets = [r['path'] for r in rows if r['kind'] == 'ASSET']; need(assets and len(assets) == len(set(assets)))
    same(sum(r['method'] == 'POST' for r in rows),4)
    return decoded


def reconstruct(rows, decoded):
    posts = sorted((r for r in rows if r['method'] == 'POST'),key=lambda r:r['requestOrdinal'])
    same([a['kind'] for a in ACTIONS],['create','approve','fetch','decide']); same(len(posts),4)
    states = [dict(sources={},candidates={})]; receipts = {}; keys = set(); sid = cid = None; approval = None
    for action,row in zip(ACTIONS,posts):
        kind = action['kind']; same(row['kind'],kind.upper()); same(row['actorRole'],action['role'])
        rc = decoded[row['ordinal']]; safe_receipt(rc,kind); need(rc['commandId'] not in receipts); receipts[rc['commandId']] = rc
        same(rc['revision'],action['toRevision']); public = row['requestPublic']; state = copy.deepcopy(states[-1])
        fields = {'idempotencyKey','label'} if kind == 'create' else {'idempotencyKey','sourceId','expectedRevision'} | ({'referenceId','policyRevision'} if kind == 'approve' else {'approvalId','policyRevision'} if kind == 'fetch' else {'candidateId','expectedDigest','decision'})
        exact(public,fields)
        key = public['idempotencyKey']; need(type(key) is str and re.fullmatch(r'sub_[a-f0-9]{32}',key) and key not in keys); keys.add(key)
        if kind == 'create':
            same(public['label'],CONTRACT['label']); same(row['path'],BASE+'/sources'); sid = rc['sourceId']
            state['sources'][sid] = dict(id=sid,scope=SCOPE,label=public['label'],revision=1,updatedAt=rc['completedAt'])
        else:
            same(rc['sourceId'],sid); same(public['sourceId'],sid); same(public['expectedRevision'],action['fromRevision']); same(state['sources'][sid]['revision'],action['fromRevision'])
            same(row['path'],BASE+'/sources/'+sid+{'approve':'/approvals','fetch':'/fetches','decide':'/decisions'}[kind])
            if kind == 'approve':
                same(public['referenceId'],'good-b'); same(public['policyRevision'],1); approval = rc
            elif kind == 'fetch':
                same(public['approvalId'],approval['approvalId']); same(public['policyRevision'],approval['policyRevision']); cid = rc['candidateId']
                state['candidates'][cid] = dict(id=cid,sourceId=sid,digest=rc['candidateDigest'],format='mihomo-provider-yaml',state='quarantined',baseRevision=2,nodeCount=2,duplicateCount=0)
                state['sources'][sid].update(revision=2,updatedAt=rc['completedAt'],latestCandidateId=cid)
            else:
                same(public['candidateId'],cid); same(rc['candidateId'],cid); same(public['expectedDigest'],state['candidates'][cid]['digest']); same(rc['candidateDigest'],public['expectedDigest'])
                same(public['decision'],'admitted_local'); same(state['candidates'][cid]['state'],'quarantined'); same(state['candidates'][cid]['baseRevision'],2)
                state['candidates'][cid]['state'] = 'admitted_local'
                state['sources'][sid].update(revision=3,updatedAt=rc['completedAt'],acceptedCandidateId=cid)
        states.append(state)
    return dict(posts=posts,states=states,receipts=receipts,sourceId=sid,candidateId=cid,approval=approval,candidateCreatedAt=None,nodeViews=None,sourcePages={},candidatePages={},nodePages={})


def possible_states(row, facts):
    # CDP monotonic domain only: dispatch of HEADERS may follow FINISH.  Never
    # synthesize Go/wire wall-clock causality from CDP wallTime + monotonic time.
    lower = max([0]+[i+1 for i,p in enumerate(facts['posts']) if p['endTimeUs'] < row['startTimeUs']])
    upper = min([4]+[i for i,p in enumerate(facts['posts']) if p['startTimeUs'] > row['endTimeUs']])
    need(lower <= upper); return facts['states'][lower:upper+1]


def validate_gets(rows, decoded, facts):
    sid,cid = facts['sourceId'],facts['candidateId']
    for row in rows:
        if row['method'] != 'GET' or row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT'): continue
        kind,path,value,role = row['kind'],row['path'],decoded[row['ordinal']],row['actorRole']
        if kind == 'COLLECTION_ACCESS': same(path,BASE+'/access'); same(value,expected_access(role)); continue
        if kind == 'SOURCE_ACCESS': same(path,BASE+'/sources/'+sid+'/access'); same(value,expected_access(role,sid)); continue
        if kind == 'RECEIPT':
            # No cross-owner shortcut: only the Approver's own final decision.
            need(role == 'approver'); same(path,BASE+'/commands/'+decoded[facts['posts'][-1]['ordinal']]['commandId']); same(value,decoded[facts['posts'][-1]['ordinal']]); continue
        allowed = possible_states(row,facts)
        if kind == 'SOURCES':
            same(path,BASE+'/sources'); exact(value,('sources','total')); need(type(value['sources']) is list); same(value['total'],len(value['sources']))
            for s in value['sources']: safe_source(s)
            need(any(value['sources'] == list(s['sources'].values()) for s in allowed)); facts['sourcePages'][row['ordinal']] = value
        elif kind in ('CANDIDATES','NODES'):
            pattern = re.escape(BASE+'/sources/'+sid+'/candidates') + ('' if kind == 'CANDIDATES' else re.escape('/'+cid+'/nodes')) + r'\?limit=20&offset=0&revision=([1-3])'
            match = re.fullmatch(pattern,path); need(match is not None); revision = int(match[1]); same(value['revision'],revision)
            available = [s for s in allowed if sid in s['sources'] and s['sources'][sid]['revision'] == revision]; need(available)
            exact(value,('candidates','total','revision') if kind == 'CANDIDATES' else ('nodes','total','revision'))
            if kind == 'CANDIDATES':
                need(type(value['candidates']) is list); summaries = []
                for c in value['candidates']:
                    exact(c,('id','sourceId','digest','format','state','baseRevision','nodeCount','duplicateCount','createdAt')); timestamp(c['createdAt']); same(c['id'],cid)
                    if facts['candidateCreatedAt'] is None: facts['candidateCreatedAt'] = c['createdAt']
                    same(c['createdAt'],facts['candidateCreatedAt']); summaries.append({k:v for k,v in c.items() if k != 'createdAt'})
                same(value['total'],len(summaries)); need(any(summaries == list(s['candidates'].values()) for s in available)); facts['candidatePages'][row['ordinal']] = value
            else:
                need(any(cid in s['candidates'] for s in available)); safe_nodes(value['nodes']); same(value['total'],2)
                if facts['nodeViews'] is None: facts['nodeViews'] = value['nodes']
                same(value['nodes'],facts['nodeViews']); facts['nodePages'][row['ordinal']] = value
        else: need(False)
    need(facts['nodeViews'] is not None and facts['candidateCreatedAt'] is not None)


def validate_audit(rows, checkpoint, facts):
    same(len(rows),8); previous = '0'*64; pairs = {}; event_ids = set()
    for event in rows:
        exact(event,('id','idempotencyKey','traceId','actorId','action','target','result','occurredAt','data','previousHash','hash'))
        need(type(event['id']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',event['id']) and event['id'] not in event_ids); event_ids.add(event['id'])
        need(type(event['actorId']) is str and re.fullmatch(r'act_[a-f0-9]{60}',event['actorId'])); timestamp(event['occurredAt'])
        need(event['previousHash'] == previous and event['hash'] == sha(H.go_event_bytes(event))); previous = event['hash']
        command = identifier(event['traceId'],'cmd'); need(command in facts['receipts']); stage = event['result']; need(stage in ('prepared','result') and stage not in pairs.setdefault(command,{}))
        need(event['action'] == 'subscription.command.'+stage and event['idempotencyKey'] == 'subscription/'+command+'/'+stage)
        fields = {'tenantId','siteId','environment','managementObject','kind','commandDigest'}
        if stage == 'result': fields |= {'state','code','sourceId','candidateId','revision','candidateDigest','localAuditHash','approvalId','policyDigest','policyRevision','stateMayHaveChanged'}
        exact(event['data'],fields); need(all(type(v) is str for v in event['data'].values()) and re.fullmatch(r'hmac-sha256:[a-f0-9]{64}',event['data']['commandDigest']))
        pairs[command][stage] = event
    same(checkpoint,dict(count=8,lastHash=previous)); actors = {}
    for action,row in zip(ACTIONS,facts['posts']):
        rc = facts['receipts'][envelope(unbase64(row['responseBase64'],65536))['commandId']]; pair = pairs[rc['commandId']]; exact(pair,('prepared','result'))
        a,b = pair['prepared'],pair['result']; need(a['actorId'] == b['actorId'] and timestamp(a['occurredAt']) <= timestamp(b['occurredAt']) and a['data'] == {k:b['data'][k] for k in a['data']})
        role = action['role']; need(role not in actors or actors[role] == a['actorId']); actors[role] = a['actorId']
        same(a['hash'],rc['preparedAuditHash']); same(b['hash'],rc['resultAuditHash']); same(b['occurredAt'],rc['completedAt'])
        same(a['target'],'subscription/'+('local' if action['kind'] == 'create' else rc['sourceId'])); same(b['target'],a['target'])
        expected = dict(**SCOPE,managementObject='local',kind=action['kind'],commandDigest=a['data']['commandDigest'],state=rc['state'],code='',sourceId=rc['sourceId'],candidateId=rc.get('candidateId',''),revision=str(rc['revision']),candidateDigest=rc.get('candidateDigest',''),localAuditHash=rc.get('localAuditHash',''),approvalId=rc.get('approvalId',''),policyDigest=rc.get('policyDigest',''),policyRevision=str(rc.get('policyRevision',0)),stateMayHaveChanged='false')
        same(b['data'],expected)
    need(set(actors) == {'operator','approver'} and len(set(actors.values())) == 2); return actors


def validate_private(value, facts, actors, commit, fixture):
    exact(value,('schema','sourceCommit','fixtureId','scope','sources','candidates','localAuditCount','commandCount','approvalCount','commands','approvals'))
    need(value['schema'] == CONTRACT['readbackSchema'] and value['sourceCommit'] == commit and value['fixtureId'] == fixture); same(value['scope'],SCOPE)
    same(value['sources'],list(facts['states'][-1]['sources'].values())); same(value['localAuditCount'],3); same(value['commandCount'],4); same(value['approvalCount'],1)
    candidate = dict(**facts['states'][-1]['candidates'][facts['candidateId']],scope=SCOPE,nodes=facts['nodeViews'],createdAt=facts['candidateCreatedAt'])
    same(value['candidates'],[candidate]); need(type(value['commands']) is list and len(value['commands']) == 4)
    commands = {v['id']:v for v in value['commands']}; need(len(commands) == 4 and set(commands) == set(facts['receipts']))
    for action,row in zip(ACTIONS,facts['posts']):
        rc = envelope(unbase64(row['responseBase64'],65536)); expected = dict(id=rc['commandId'],scope=SCOPE,actorId=actors[action['role']],kind=action['kind'],expectedRevision=action['fromRevision'],preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True)
        if action['kind'] != 'create': expected['sourceId'] = rc['sourceId']
        result = {k:rc[k] for k in ('sourceId','candidateId','revision','state','stateMayHaveChanged','localAuditHash','completedAt','referenceId','policyRevision','policyDigest','approvalId') if k in rc}
        if 'candidateDigest' in rc: result['digest'] = rc['candidateDigest']
        expected['result'] = result; same(commands[rc['commandId']],expected)
    rc = facts['approval']
    same(value['approvals'],[dict(commandId=rc['commandId'],scope=SCOPE,sourceId=facts['sourceId'],referenceId='good-b',policyRevision=1,policyDigest=rc['policyDigest'],sourceRevision=1,approvedAt=rc['completedAt'])])


def validate_wire(raw, ready, stopped, wire_pid):
    same(ready,dict(schema='chengwang.subscription-wire-ready/v1',pid=wire_pid,uid=10001,gid=10001,dotAddress='127.0.0.1',dotPort=1853,httpsAddress='8.8.4.4',httpsPort=443,tls=True,deadlineSeconds=180))
    need(len(raw) <= 256<<10); events = json_lines(raw,12); same(len(events),12); chains = {}
    fields = ('schema','ordinal','connection','service','event','reference','queryType','status','bytes','tls','reason','receivedUnixNano')
    for ordinal,event in enumerate(events,1):
        exact(event,fields); same(event['schema'],'chengwang.subscription-wire-event/v1'); same(event['ordinal'],ordinal)
        integer(event['connection'],1,3); integer(event['status'],0,599); integer(event['bytes'],0,(1<<20)+4096); boolean(event['tls'])
        need(event['service'] in ('dot','https')); chain = chains.setdefault(event['connection'],[]); chain.append(event)
        if event['event'] not in ('dns','http'):
            need(event['reference'] == event['queryType'] == event['receivedUnixNano'] == ''); same(event['status'],0); same(event['bytes'],0)
        else:
            need(type(event['receivedUnixNano']) is str and re.fullmatch(r'[1-9][0-9]{15,19}',event['receivedUnixNano']))
    same(sorted(chains),[1,2,3]); payloads = []
    for chain in chains.values():
        same(len(chain),4); payload = chain[2]; service = payload['service']
        same([v['event'] for v in chain],['connect','tls','dns' if service == 'dot' else 'http','close'])
        same([v['reason'] for v in chain],['ok','ok','ok','closed']); same([v['tls'] for v in chain],[False,True,True,True])
        need(all(v['service'] == service for v in chain)); same(payload['reference'],'good-b')
        if service == 'dot':
            need(payload['queryType'] in ('A','AAAA')); same(payload['status'],0)
            question = sum(len(v)+1 for v in 'good-b.subscription.example'.split('.'))+1+4
            same(payload['bytes'],2+12+question+(16 if payload['queryType'] == 'A' else 0))
        else: same(payload['queryType'],''); same(payload['status'],200); integer(payload['bytes'],1,(1<<20)+4096)
        payloads.append((service,payload['queryType'],payload['status']))
    same(sorted(payloads),[('dot','A',0),('dot','AAAA',0),('https','',200)])
    same(stopped,dict(schema='chengwang.subscription-wire-stopped/v1',pid=wire_pid,termination='term',accepted=3,closed=3,events=12,workerThreadsAlive=0,listenersClosed=True,normalStop=True))
    return events


def validate_fence(fence, raw, fetched):
    exact(fence,('eventCount','bytes','sha256')); count = 12 if fetched else 0; prefix = raw if fetched else b''
    same(fence['eventCount'],count); same(fence['bytes'],len(prefix)); same(fence['sha256'],sha(prefix))


def role_for_step(step):
    if step in ('anonymous','cleared'): return 'anonymous'
    if STEPS.index('approver_source') <= STEPS.index(step) <= STEPS.index('reference_a_cleared') or STEPS.index('approver_candidate') <= STEPS.index(step) <= STEPS.index('returned'): return 'approver'
    return 'operator'


def control_projection(value):
    exact(value,('key','present','visible','enabled','inViewport','unobstructed','rect'))
    for k in ('present','visible','enabled','inViewport','unobstructed'): boolean(value[k])
    need(value['present'] or not any(value[k] for k in ('visible','enabled','inViewport','unobstructed')))
    need(value['visible'] == (value['rect'] is not None) and (not value['inViewport'] or value['visible']) and (not value['unobstructed'] or value['inViewport']))
    if value['rect'] is not None:
        exact(value['rect'],('x','y','width','height'))
        for k in ('x','y'): integer(value['rect'][k],-100000,100000)
        for k in ('width','height'): integer(value['rect'][k],0,100000)


def validate_dom(rows, captures, decoded, facts, wire_raw):
    same(len(rows),33); count = 0; previous = 0; last_receipt = None
    for ordinal,(row,step) in enumerate(zip(rows,STEPS),1):
        exact(row,CONTRACT['domStepKeys']); same(row['schema'],CONTRACT['domSchema']); same(row['ordinal'],ordinal); same(row['step'],step)
        if step in POST_STEPS: count = POST_STEPS[step]; last_receipt = decoded[facts['posts'][count-1]['ordinal']]
        if step in ('anonymous','operator_connected','approver_source','operator_source','approver_candidate','cleared'): last_receipt = None
        role = role_for_step(step); same(row['actorRole'],role); same(row['mutationCount'],count); integer(row['captureCount'],previous,len(captures)); previous = row['captureCount']
        seen = captures[:previous]; same(sum(v['method'] == 'POST' for v in seen),count); validate_fence(row['wireFence'],wire_raw,count >= 3)
        d = row['dom']; exact(d,('schema','pageMounted','pageVisible','https','viewport','session','controls','sources','candidates','nodes','paging','mode','directory','sessionApproval','handoff','confirmation','receipt','stale','alertVisible','boundaryVisible'))
        need(d['schema'] == 'chengwang.subscription-browser-dom/v1' and d['pageMounted'] is True and d['https'] is True and d['alertVisible'] is False)
        same(d['pageVisible'],step != 'hidden'); same(d['boundaryVisible'],step != 'hidden')
        vp = d['viewport']; exact(vp,('width','height','scrollX','scrollY','clientWidth','scrollWidth'))
        for k in ('width','height','clientWidth','scrollWidth'): integer(vp[k],1,100000)
        for k in ('scrollX','scrollY'): integer(vp[k],-100000,100000)
        same(vp['height'],900); same(vp['width'],375 if step in ('final_mobile','receipt','hidden','returned','cleared') else 1440); need(vp['scrollWidth'] == vp['clientWidth'] and vp['clientWidth'] <= vp['width'])
        same(d['session'],dict(tokenMounted=True,tokenType='password',tokenEmpty=True,fileMounted=True,fileEmpty=True,storageEmpty=True,cookiesEmpty=True))
        same(d['stale'],dict(sources=False,candidates=False,nodes=False))
        need(type(d['controls']) is list and len(d['controls']) == len(CONTROLS))
        for ctl,key in zip(d['controls'],CONTROLS): control_projection(ctl); same(ctl['key'],key)
        ctl = {v['key']:v for v in d['controls']}; same(ctl['prepare_create']['enabled'],role == 'operator')
        state = facts['states'][count]; selected_source = count > 0 and step != 'cleared'; sid = facts['sourceId']; cid = facts['candidateId']
        source = state['sources'].get(sid) if selected_source else None
        same(d['sources'],[dict(id=sid,revision=source['revision'],selected=True,accepted='acceptedCandidateId' in source,disabled=False)] if source else [])
        selected_candidate = step in SELECTED
        candidate = state['candidates'].get(cid) if source else None
        same(d['candidates'],[dict(id=cid,state=candidate['state'],nodeCount=2,format='mihomo-provider-yaml',baseRevision=2,selected=selected_candidate)] if candidate else [])
        same(d['nodes'],[{k:v for k,v in node.items() if k != 'label'} for node in facts['nodeViews']] if selected_candidate else [])
        same(d['paging'],dict(candidates=dict(page=1,revision=source['revision']) if source else None,nodes=dict(page=1,revision=source['revision']) if selected_candidate else None))
        if source:
            need(any(r['actorRole'] == role and r['ordinal'] in facts['candidatePages'] and facts['candidatePages'][r['ordinal']]['revision'] == source['revision'] for r in seen))
            if selected_candidate: need(any(r['actorRole'] == role and r['ordinal'] in facts['nodePages'] and facts['nodePages'][r['ordinal']]['revision'] == source['revision'] for r in seen))
        reference_b = step in ('approve_b_prepared','approve_b_cancelled','approve_b_prepared_again','approved_b','approval_refreshed')
        same(d['directory'],dict(present=True,disabled=not bool(source),references=[dict(**v,selected=v['referenceId'] == ('good-b' if reference_b else 'good-a')) for v in CONTRACT['references']] if source else []))
        same(d['mode'],'handoff' if step in HANDOFF else 'session')
        approval = facts['approval']
        same(d['sessionApproval'],dict(approvalId=approval['approvalId'],referenceId='good-b',policyRevision=1) if step in ('approved_b','approval_refreshed') else None)
        if step in HANDOFF:
            empty = step == 'handoff_empty'; same(d['handoff'],dict(approvalValid=not empty,approvalId=None if empty else approval['approvalId'],revisionValid=not empty,policyRevision=None if empty else 2 if step == 'handoff_edited' else 1,unverifiedReferenceNotice=True))
        else: need(d['handoff'] is None)
        same(d['receipt'],None if last_receipt is None else {k:last_receipt[k] for k in ('commandId','revision','state','replayed','auditRecorded')})
        confirmation = None
        if step in PREPARED:
            kind = PREPARED[step]; binding = dict(sourceId=sid,expectedRevision=1,approvalId=approval['approvalId'],policyRevision=1) if kind == 'fetch_handoff' else None
            confirmation = dict(kind=kind,binding=binding,unverifiedReference=kind == 'fetch_handoff',rollbackRequired=False,rollbackChecked=False)
            need(ctl['confirm']['enabled'] and ctl['cancel']['enabled'])
        same(d['confirmation'],confirmation)
        for key in ('prepare_admit','prepare_reject'): same(ctl[key]['enabled'],role == 'approver' and selected_candidate and count == 3)
        same(ctl['prepare_import']['enabled'],role == 'operator' and bool(source)); same(ctl['prepare_approve']['enabled'],role == 'approver' and bool(source))
        same(ctl['prepare_rollback']['enabled'],role == 'approver' and selected_candidate and count == 4)
        same(ctl['prepare_fetch']['enabled'],role == 'operator' and step in HANDOFF and step != 'handoff_empty')
        if step == 'anonymous': need(not any(r['authorizationPresent'] for r in seen))
        if step == 'receipt': need(any(r['kind'] == 'RECEIPT' for r in seen))
    same(rows[-1]['captureCount'],len(captures))


def validate_supervisor(p, iso, inputs, build, driver, pin, repo, commit, engine, fixture):
    prefix = 'chengwang.subscription-ui-supervisor/v1'
    for value in (p,iso,inputs):
        need(value['schema'] == prefix and value['sourceCommit'] == commit and value['fixtureId'] == fixture and value['engine'] == engine and value['production'] is False)
    exact(p,('schema','sourceCommit','fixtureId','engine','records','serverExitCode','controllerExitCode','wireExitCode','noLiveOwnedProcesses','forcedSignals','processScope','production'))
    exact(inputs,('schema','sourceCommit','fixtureId','engine','copiedInputs','inputTrustScope','production'))
    exact(iso,('schema','sourceCommit','fixtureId','engine','hostBefore','hostAfter','sourceFilesBefore','sourceFilesAfter','lab','production','authorization','deviceActionsExecuted','pythonBinaryProvenanceProven'))
    need(p['processScope'] == 'TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION' and inputs['inputTrustScope'] == 'SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    need(iso['authorization'] == 'BLOCKED' and iso['deviceActionsExecuted'] is False and iso['pythonBinaryProvenanceProven'] is False)
    same(iso['hostBefore'],iso['hostAfter']); same(iso['sourceFilesBefore'],iso['sourceFilesAfter']); host = iso['hostBefore']
    exact(host,('netNamespace','mountNamespace','pidNamespace','userNamespace','portStart','systemCASHA256','sourceSHA256')); integer(host['portStart'],0,65535)
    for name,kind in (('netNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid'),('userNamespace','user')): need(type(host[name]) is str and re.fullmatch(kind+r':\[[0-9]+\]',host[name]))
    digest(host['systemCASHA256']); digest(host['sourceSHA256']); sources = iso['sourceFilesBefore']
    need(type(sources) is list and 1 <= len(sources) <= 8192); source_map = {}
    for item in sources:
        exact(item,('path','bytes','sha256')); path = item['path']
        need(type(path) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+',path) and '..' not in path.split('/') and path not in source_map and path.startswith(('chengwang/','.github/workflows/')))
        original = git_bytes(repo,commit,path); same(item['bytes'],len(original)); need(item['sha256'] == sha(original)); source_map[path] = item
    tracked = subprocess.check_output(['git','-c','safe.directory='+str(repo),'-C',str(repo),'ls-tree','-r','-z','--name-only',commit,'--','chengwang','.github/workflows'],stderr=subprocess.DEVNULL)
    need(set(source_map) == {x.decode() for x in tracked.split(b'\0') if x} and sha(canonical(sources)) == host['sourceSHA256'])
    own = 'chengwang/deploy/subscription-ui-browser/check_remote_fetch_ui.py'
    need(own in source_map and git_bytes(repo,commit,own) == read(Path(__file__)))
    for path in (CONTRACT_PATH,'chengwang/deploy/subscription-ui-browser/remote_fetch_fixture.py','chengwang/deploy/subscription-readback/wire_fixture.py','chengwang/deploy/subscription-readback/lab_contract.py','chengwang/tools/subscription-ui-browser/remote-fetch-cli.mjs'):
        need(path in source_map)
    lab = iso['lab']; exact(lab,('namespaces','defaultIPv4Routes','defaultIPv6Routes','interfaces','sourceMount','bundleMount','tmpMount','ipv4Addresses','unprivilegedPortStart'))
    same(lab['defaultIPv4Routes'],0); same(lab['defaultIPv6Routes'],0); same(lab['interfaces'],['lo'])
    same(lab['ipv4Addresses'],['127.0.0.1/8','8.8.4.4/32']); same(lab['unprivilegedPortStart'],0)
    exact(lab['namespaces'],('net','mnt','pid','user'))
    for key in lab['namespaces']: need(type(lab['namespaces'][key]) is str and re.fullmatch(key+r':\[[0-9]+\]',lab['namespaces'][key]))
    need(lab['namespaces']['user'] == host['userNamespace'])
    for key,name in (('net','netNamespace'),('mnt','mountNamespace'),('pid','pidNamespace')): need(lab['namespaces'][key] != host[name])
    for key in ('sourceMount','bundleMount','tmpMount'): need(type(lab[key]) is list and all(type(v) is str for v in lab[key]) and len(set(lab[key])) == len(lab[key]))
    for key in ('sourceMount','bundleMount'): need({'ro','nosuid','nodev'} <= set(lab[key]))
    need({'rw','nosuid','nodev','noexec'} <= set(lab['tmpMount']))
    copied = {}; need(type(inputs['copiedInputs']) is list)
    for item in inputs['copiedInputs']:
        exact(item,('path','bytes','sha256')); path = item['path']; need(type(path) is str and path not in copied and '..' not in path.split('/'))
        integer(item['bytes'],0,512<<20); digest(item['sha256']); copied[path] = item
        if path.startswith('chengwang/'):
            original = source_map.get(path.removesuffix(':launcher')); need(original is not None)
            same({k:item[k] for k in ('bytes','sha256')},{k:original[k] for k in ('bytes','sha256')})
        else: need(path.startswith(('chrome/','npm/playwright-core/','dist/')) or path in ('toolchain/node','toolchain/server','build/report.json'))
    for path in ('chrome/chrome','toolchain/node','toolchain/server','npm/playwright-core/package.json','chengwang/deploy/subscription-readback/wire_fixture.py','chengwang/deploy/subscription-readback/lab_contract.py',CONTRACT_PATH): need(path in copied)
    same({k:copied['toolchain/server'][k] for k in ('bytes','sha256')},{k:build['server'][k] for k in ('bytes','sha256')})
    same({k:copied['chrome/chrome'][k] for k in ('bytes','sha256')},dict(bytes=305061192,sha256=ELF_SHA))
    same([{**item,'path':item['path'][5:]} for path,item in sorted(copied.items()) if path.startswith('dist/')],build['distFiles'])
    records = p['records']; need(type(records) is list and len(records) == 4); roles = {r['role']:r for r in records}
    need(set(roles) == {'server','controller','chrome','wire'} and len({r['pid'] for r in records}) == 4)
    for k in ('serverExitCode','controllerExitCode','wireExitCode','forcedSignals'): same(p[k],0)
    need(p['noLiveOwnedProcesses'] is True); root = CONTRACT['rootPrefix']+fixture; bundle = CONTRACT['bundlePrefix']+fixture
    for r in records:
        exact(r,('pid','startTime','exeSHA256','argvSHA256','uid','gid','groups','capabilities','noNewPrivs','namespaces','limits','role','argv'))
        integer(r['pid'],2); need(type(r['startTime']) is str and re.fullmatch(r'[1-9][0-9]{0,19}',r['startTime'])); digest(r['exeSHA256']); digest(r['argvSHA256'])
        same(r['uid'],[10001]*4); same(r['gid'],[10001]*4); same(r['groups'],[]); same(r['noNewPrivs'],1)
        same(r['capabilities'],{k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')}); same(r['namespaces'],lab['namespaces'])
        same(r['limits'],dict(cpuSeconds=[180,180],fileBytes=[32<<20]*2,openFiles=[1024]*2,processes=[1024]*2,coreBytes=[0,0]))
        need(type(r['argv']) is list and 1 <= len(r['argv']) <= 128 and all(type(v) is str and len(v) <= 4096 for v in r['argv']))
        same(sha(b''.join(v.encode()+b'\0' for v in r['argv'])),r['argvSHA256'])
    chrome = driver['chrome']; exact(chrome,('pid','startTicks','uid','profile','argvSHA256','exeSHA256','exeBytes'))
    same(chrome['pid'],roles['chrome']['pid']); same(chrome['startTicks'],int(roles['chrome']['startTime'])); same(chrome['uid'],10001); same(chrome['exeBytes'],305061192)
    need(chrome['profile'] == root+'/chrome-profile' and chrome['exeSHA256'] == roles['chrome']['exeSHA256'] == ELF_SHA and chrome['argvSHA256'] == roles['chrome']['argvSHA256'])
    need(roles['controller']['exeSHA256'] == copied['toolchain/node']['sha256'] and roles['server']['exeSHA256'] == build['server']['sha256'])
    argv = roles['chrome']['argv']; need(argv[0] == bundle+'/chrome/chrome' and '--no-sandbox' in argv and [v for v in argv if v.startswith('--user-data-dir')] == ['--user-data-dir='+root+'/chrome-profile'])
    forbidden = ('--ignore-certificate-errors','--ignore-certificate-errors-spki-list','--ignore-ssl-errors','--allow-insecure-localhost','--disable-web-security','--unsafely-treat-insecure-origin-as-secure')
    need(not any(v.split('=',1)[0] in forbidden for v in argv)); same(roles['server']['argv'],[bundle+'/server'])
    same(roles['controller']['argv'],[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/remote-fetch-cli.mjs','--root',root,'--bundle',bundle,'--engine',engine,'--source-commit',commit])
    wire_argv = roles['wire']['argv']; need(re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,2})?',wire_argv[0]))
    same(wire_argv[1:],['-I','-B',bundle+'/source/chengwang/deploy/subscription-readback/wire_fixture.py','serve','--root',CONTRACT['wireRootPrefix']+fixture,'--deadline-seconds','180'])
    close = driver['close']; exact(close,('normalCloseCommandCompleted','chromeExit','launcherExit','noLiveOwnedProcesses','processScope'))
    need(close['normalCloseCommandCompleted'] is True and close['noLiveOwnedProcesses'] is True and close['processScope'] == 'CHROME_SESSION_AND_LAUNCHER_ONLY')
    same(close['chromeExit'],dict(schema='chengwang.subscription-ui-chrome-exit/v1',engine=engine,fixtureId=fixture,pid=chrome['pid'],startTicks=chrome['startTicks'],exitCode=0,joined=True,forced=False))
    same(close['launcherExit'],dict(code=0,signal=None) if engine == 'chrome-cdp' else None)
    need(pin['schema'] == 'chengwang.pinned-browser-consumption-verification/v1' and pin['sourceCommit'] == commit and pin['state'] == 'PIN_ENFORCED_EXPANDED_NOT_EXECUTED' and pin['pinSHA256'] == PIN_SHA and pin['pinEnforced'] is True and pin['allMemberCRCsVerified'] is True and pin['actualExpandedFileHashesVerified'] is True)
    same(pin['zip'],dict(bytes=202676171,sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853',md5Base64='5qChIL/Gh+8hZv73vzEakQ=='))
    need(pin['elf']['sha256'] == ELF_SHA); same(pin['elf']['bytes'],305061192)
    for key in ('browserExecuted','runtimeVersionProven','projectFixProven','publisherSignatureProven','production'): need(pin[key] is False)
    return len(sources),roles['wire']['pid']


def verify_wire_tls(raws, captures):
    # OpenSSL verifies only provided laboratory roots at the recorded browser
    # capture time.  This starts no server and does not contact the Internet.
    stamp = min(r['startedWallTimeUs'] for r in captures)//1000000
    ders = []
    with tempfile.TemporaryDirectory(prefix='remote-fetch-offline-certs-') as directory:
        root = Path(directory)
        for name in ('source-ca.pem','source-leaf.pem','resolver-ca.pem','resolver-leaf.pem'):
            raw = raws[name]; need(len(raw) <= 65536 and re.fullmatch(rb'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?',raw))
            der = base64.b64decode(b''.join(raw.splitlines()[1:-1]),validate=True); need(der not in ders); ders.append(der)
            with (root/name).open('xb') as output: output.write(raw)
        for role,hostname in (('resolver','resolver.subscription.example'),('source','good-b.subscription.example')):
            result = subprocess.run(['openssl','verify','-trusted',str(root/(role+'-ca.pem')),'-check_ss_sig','-attime',str(stamp),'-purpose','sslserver','-verify_hostname',hostname,str(root/(role+'-leaf.pem'))],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':os.environ.get('PATH',os.defpath),'OPENSSL_CONF':os.devnull})
            need(result.returncode == 0)


def verify(directory, repo, commit, engine):
    need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}',commit) and engine in ('chrome-cdp','playwright'))
    need(not directory.is_symlink() and {p.name for p in directory.iterdir()} == PUBLIC)
    def budget(name): return 24<<20 if name == 'captures.jsonl' else 256<<10 if name == 'wire-events.jsonl' else 1<<20 if name == 'dom.jsonl' else 16<<20
    raw = {name:read(directory/name,budget(name)) for name in PUBLIC}
    need(all(b'PRIVATE KEY' not in body and b'Bearer ' not in body for body in raw.values())); same(decode(git_bytes(repo,commit,CONTRACT_PATH)),CONTRACT)
    driver = decode(raw['driver.json']); exact(driver,CONTRACT['driverKeys']); fixture = driver['fixtureId']; need(type(fixture) is str and re.fullmatch(r'[a-f0-9]{32}',fixture))
    need(driver['schema'] == CONTRACT['driverSchema'] and driver['scenario'] == 'remote_fetch' and driver['sourceCommit'] == commit and driver['engine'] == engine and driver['origin'] == CONTRACT['origin'] and driver['scope'] == CONTRACT['scope'] and driver['runtime'] is True)
    for key in ('mockedResponses','injectedFetch','tlsBypass','production','fullSubscriptionE2EProven'): need(driver[key] is False)
    same(driver['steps'],STEPS); exact(driver['counters'],COUNTERS); need(all(type(v) is int and v == 0 for v in driver['counters'].values()))
    exact(driver['browser'],('product','revision','protocolVersion')); need(driver['browser']['product'] in ('Chrome/157.0.8103.6','HeadlessChrome/157.0.8103.6') and driver['browser']['revision'] == '@'+TAG and driver['browser']['protocolVersion'] == '1.3')
    build = decode(raw['build.json']); H.validate_build(build,commit)
    captures = json_lines(raw['captures.jsonl']); decoded = validate_rows(captures,build); facts = reconstruct(captures,decoded); validate_gets(captures,decoded,facts)
    same(driver['captures'],dict(path='captures.jsonl',bytes=len(raw['captures.jsonl']),sha256=sha(raw['captures.jsonl']),records=len(captures)))
    dom = json_lines(raw['dom.jsonl'],33); validate_dom(dom,captures,decoded,facts,raw['wire-events.jsonl'])
    actors = validate_audit(json_lines(raw['audit-events.jsonl'],8),decode(raw['audit-checkpoint.json']),facts)
    validate_private(decode(raw['private-readback.json']),facts,actors,commit,fixture)
    shots = driver['screenshots']; need(type(shots) is list and len(shots) == 2)
    for item,name,step,width in zip(shots,('created-desktop.png','created-mobile.png'),('final_desktop','final_mobile'),(1440,375)):
        exact(item,('path','step','bytes','sha256','viewport','scrollX','scrollY','capturedWallTimeUs'))
        need(item['path'] == name and item['step'] == step and item['sha256'] == sha(raw[name])); same(item['bytes'],len(raw[name])); integer(item['capturedWallTimeUs'],1)
        same(item['viewport'],dict(width=width,height=900)); same(item['scrollX'],0); same(item['scrollY'],0); png(raw[name],width,900)
        projection = next(v['dom'] for v in dom if v['step'] == step); same(projection['viewport']['scrollX'],0); same(projection['viewport']['scrollY'],0)
    inputs = decode(raw['inputs.json']); build_rows = [v for v in inputs['copiedInputs'] if v['path'] == 'build/report.json']; same(len(build_rows),1)
    same(build_rows[0],dict(path='build/report.json',bytes=len(raw['build.json']),sha256=sha(raw['build.json'])))
    source_count,wire_pid = validate_supervisor(decode(raw['processes.json']),decode(raw['isolation.json']),inputs,build,driver,decode(raw['pin-consumption.json']),repo,commit,engine,fixture)
    validate_wire(raw['wire-events.jsonl'],decode(raw['wire-ready.json']),decode(raw['wire-stopped.json']),wire_pid)
    H.verify_tls(decode(raw['certificates.json']),driver,captures); verify_wire_tls(raw,captures)
    need({name:read(directory/name,budget(name)) for name in PUBLIC} == raw)
    return dict(schema='chengwang.remote-fetch-ui-verification/v1',sourceCommit=commit,engine=engine,fixtureId=fixture,outcome='PASS',scope=CONTRACT['scope'],actualBrowser=driver['browser'],actualChromeELFSHA256=ELF_SHA,
        steps=33,screenshots=2,requests=len(captures),mutations=4,commands=4,approvals=1,localAuditCount=3,externalAuditEvents=8,sourceGitBlobs=source_count,sources=1,candidates=1,sourceRevision=3,wireConnections=3,wireEvents=12,
        normalTLSOfflineVerifiedAtCapture=True,sourceAndResolverTLSOfflineVerifiedAtCapture=True,pinConsumed=True,realRemoteFetchApprovalHandoffFlowProven=True,fullSubscriptionE2EProven=False,fetchDNSWireEvaluated=True,
        perHTTPWireFencesProven=False,wireFenceTrust=CONTRACT['wireFenceTrust'],externalInternetProven=False,privateDatabaseRawIndependentlyVerified=False,privateRawFilesIndependentlyVerified=False,
        independentReproducibleBuildProven=False,screenshotVisualReviewProven=False,privateReadbackTrustBoundary='TRUSTED_RUNNER_SAFE_PROJECTION_NOT_INDEPENDENT_PRIVATE_DATABASE_VERIFICATION',processTrustBoundary='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION',production=False,authorization='BLOCKED',remaining=CONTRACT['remaining'],evidenceSHA256={name:sha(raw[name]) for name in sorted(raw)})


def main():
    parser = argparse.ArgumentParser()
    for name in ('evidence','repo','report'): parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--source-commit',required=True); parser.add_argument('--engine',required=True,choices=('chrome-cdp','playwright')); args = parser.parse_args()
    evidence = args.evidence.resolve(strict=True); repo = args.repo.resolve(strict=True); report = args.report.absolute()
    need(not args.evidence.is_symlink() and not args.repo.is_symlink() and not report.exists() and not report.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.resolve().is_relative_to(repo))
    result = verify(evidence,repo,args.source_commit,args.engine)
    with report.open('xb') as output: output.write(canonical(result)+b'\n')
    print('REMOTE_FETCH_UI_INDEPENDENT=PASS full_subscription_e2e_proven=false production=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('REMOTE_FETCH_UI_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
