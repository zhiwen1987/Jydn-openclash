"""Independent, bounded B09 handoff-rejection evidence verifier.

No browser, product server or Internet is executed. Native API sampler records
are distinct from CDP browser observations. Safe private/process projections
remain trusted CI observations, not independent database or execution proofs.
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
CONTRACT_PATH = 'chengwang/tools/subscription-ui-browser/handoff-negative-contract.json'
CONTRACT = decode(read(Path(__file__).parents[2] / 'tools/subscription-ui-browser/handoff-negative-contract.json'))
BASE = '/api/v1/subscriptions'
SCOPE = CONTRACT['scopeValue']
STEPS = CONTRACT['steps']
PUBLIC = set(CONTRACT['publicFiles'])
SCENARIO = 'remote_handoff_negative'
APPROVAL_CODE = 'subscription_approval_required'
CONFLICT_CODE = 'subscription_command_conflict'
FORBIDDEN_CODE = 'subscription_forbidden'
TAG = '41520584daa68d0040db7746ae562a0ff82187f6'
ELF_SHA = 'ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
PIN_SHA = '404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
COUNTERS = ('runtimeErrors','consoleErrors','consoleWarnings','cspErrors','assetErrors','forbiddenRequests','failedRequests','captureErrors')
CONTROLS = ('connect','clear','refresh_sources','prepare_create','refresh_source','prepare_import','prepare_approve','prepare_fetch','prepare_admit','prepare_reject','prepare_rollback','confirm','cancel','candidate_previous','candidate_next','node_previous','node_next','read_receipt')
ACTIONS = CONTRACT['actions']
ACTION_MAP = {a['key']:a for a in ACTIONS}
RECEIPT_CASES = {a['key']:a for a in CONTRACT['receiptCases']}


def response(raw, status):
    value = decode(raw)
    exact(value,('boundary','authorization','deviceActionsExecuted','stateMayHaveChanged','result' if status == 200 else 'code'))
    need(value['boundary'] == 'LOCAL_SUBSCRIPTION_ADMISSION_ONLY' and value['authorization'] == 'BLOCKED' and value['deviceActionsExecuted'] is False and value['stateMayHaveChanged'] is False)
    return value['result'] if status == 200 else value['code']


def safe_receipt(value, kind, failed=False):
    fields = {'commandId','kind','sourceId','revision','state','replayed','stateMayHaveChanged','auditRecorded','preparedAuditHash','resultAuditHash','completedAt'}
    fields |= {'code'} if failed else {'referenceId','policyRevision','policyDigest','approvalId'} if kind == 'approve' else {'localAuditHash'}
    if kind == 'fetch' and not failed: fields |= {'candidateId','candidateDigest'}
    exact(value,fields); identifier(value['commandId'],'cmd'); identifier(value['sourceId'],'src'); integer(value['revision'],1,2)
    same(value['kind'],kind); same(value['state'],'failed' if failed else 'approved' if kind == 'approve' else 'committed')
    need(value['replayed'] is False and value['stateMayHaveChanged'] is False and value['auditRecorded'] is True)
    for k in ('preparedAuditHash','resultAuditHash'): digest(value[k])
    timestamp(value['completedAt'])
    if failed: need(value['code'] in (APPROVAL_CODE,CONFLICT_CODE)); same(value['revision'],1)
    elif kind == 'approve':
        need(value['referenceId'] in ('good-a','good-b')); same(value['policyRevision'],1); same(value['approvalId'],value['commandId']); hmac_digest(value['policyDigest'])
    else:
        digest(value['localAuditHash'])
        if kind == 'fetch': identifier(value['candidateId'],'cand'); hmac_digest(value['candidateDigest']); same(value['revision'],2)


def hmac_digest(value):
    need(type(value) is str and re.fullmatch(r'hmac-sha256:[a-f0-9]{64}',value))


def same_value(left, right):
    try: same(left,right)
    except ValueError: return False
    return True


def headers(row, expected_command, expected_denial=None):
    same(row['commandIdHeader'],expected_command); same(row['denialAuditHeader'],expected_denial)
    if expected_command is not None: identifier(expected_command,'cmd')


def validate_browser(rows, build):
    need(type(rows) is list and 1 <= len(rows) <= 256); starts=set(); ids=set(); decoded={}; total=0
    dist={v['path']:v for v in build['distFiles']}; cases={}
    for ordinal,row in enumerate(rows,1):
        exact(row,CONTRACT['captureKeys']); same(row['schema'],CONTRACT['captureSchema']); same(row['ordinal'],ordinal)
        integer(row['requestOrdinal'],1,256); need(row['requestOrdinal'] not in starts); starts.add(row['requestOrdinal'])
        need(type(row['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',row['requestId']) and row['requestId'] not in ids); ids.add(row['requestId'])
        need(row['kind'] in CONTRACT['captureKinds'] and row['method'] in ('GET','POST')); integer(row['status'],200,409)
        boolean(row['authorizationPresent'])
        for k in ('startedWallTimeUs','startTimeUs','headerTimeUs','endTimeUs'): integer(row[k],1)
        need(row['headerTimeUs'] >= row['startTimeUs'] and row['endTimeUs'] >= row['startTimeUs'])
        exact(row['terminal'],('event','encodedDataLength')); same(row['terminal']['event'],'FINISH'); integer(row['terminal']['encodedDataLength'],0,16<<20)
        static=row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT'); same(row['authorizationPresent'],not static)
        need(row['actorRole'] == 'anonymous' if static else row['actorRole'] in ('operator','approver'))
        raw=unbase64(row['responseBase64'],8<<20 if row['kind'] in ('DOCUMENT','ASSET') else 65536)
        total+=len(raw); need(total <= 16<<20); same(row['responseBytes'],len(raw)); same(row['responseSHA256'],sha(raw))
        need(b'PRIVATE KEY' not in raw and (row['kind'] == 'ASSET' or b'Bearer ' not in raw))
        case=row['caseKey']; kind=row['kind']; path=row['path']
        if row['method'] == 'POST':
            need(case in ACTION_MAP and ACTION_MAP[case]['origin'] == 'browser' and case not in cases); cases[case]=row
            action=ACTION_MAP[case]; same(kind,action['kind'].upper()); same(row['status'],action['status']); same(row['actorRole'],action['actorRole'])
            value=response(raw,row['status']); decoded[ordinal]=value
            if row['status'] != 200: same(value,action['code']); identifier(row['commandIdHeader'],'cmd'); headers(row,row['commandIdHeader'])
            else: safe_receipt(value,action['kind']); headers(row,None)
        elif kind == 'RECEIPT':
            need(case in RECEIPT_CASES and case not in cases); cases[case]=row; action=RECEIPT_CASES[case]
            same(row['status'],action['status']); same(row['actorRole'],action['actorRole']); same(row['requestPublic'],None); headers(row,None)
            decoded[ordinal]=response(raw,row['status'])
            if row['status'] != 200: same(decoded[ordinal],action['code'])
            else: safe_receipt(decoded[ordinal],'fetch',True)
        else:
            same(case,None); same(row['status'],200); same(row['method'],'GET'); same(row['requestPublic'],None); headers(row,None)
            if kind in ('DOCUMENT','ASSET'):
                need(path == '/' if kind == 'DOCUMENT' else type(path) is str and re.fullmatch(r'/assets/[A-Za-z0-9_.-]+',path))
                rel='index.html' if kind == 'DOCUMENT' else path[1:]; need(rel in dist); same({k:dist[rel][k] for k in ('bytes','sha256')},dict(bytes=len(raw),sha256=sha(raw)))
            elif kind == 'SNAPSHOT': same(path,'/api/v1/snapshot'); decode(raw,allow_float=True)
            else: decoded[ordinal]=response(raw,200)
    same(starts,set(range(1,len(rows)+1)))
    same(set(cases),{a['key'] for a in ACTIONS if a['origin'] == 'browser'} | set(RECEIPT_CASES))
    for kind,count in (('DOCUMENT',1),('SNAPSHOT',1),('RECEIPT',6)): same(sum(r['kind'] == kind for r in rows),count)
    assets=[r['path'] for r in rows if r['kind'] == 'ASSET']; need(assets and len(assets) == len(set(assets)))
    same([r['caseKey'] for r in sorted((r for r in rows if r['method'] == 'POST'),key=lambda r:r['requestOrdinal'])],[a['key'] for a in ACTIONS if a['origin'] == 'browser'])
    return decoded,cases


def validate_sampler(raw, certificates):
    need(len(raw) <= CONTRACT['maxSamplerFileBytes']); rows=json_lines(raw,2); same(len(rows),2); decoded={}; total=0
    leaf=unbase64(certificates['leafDERBase64'],65536) if 'leafDERBase64' in certificates else None
    if leaf is None:
        pem=certificates['leafPEM']; need(type(pem) is str); leaf=base64.b64decode(''.join(pem.splitlines()[1:-1]),validate=True)
    for ordinal,(row,action) in enumerate(zip(rows,[a for a in ACTIONS if a['origin'] == 'api-sampler']),1):
        exact(row,CONTRACT['samplerKeys']); same(row['schema'],CONTRACT['samplerSchema']); same(row['ordinal'],ordinal)
        same(row['caseKey'],action['key']); same(row['method'],'POST'); same(row['actorRole'],'operator'); same(row['status'],action['status'])
        for key in ('startedWallTimeUs','headerWallTimeUs','endWallTimeUs'): integer(row[key],1)
        need(row['headerWallTimeUs'] >= row['startedWallTimeUs'] and row['endWallTimeUs'] >= row['headerWallTimeUs'])
        same(row['terminal'],CONTRACT['samplerTerminal']); tls=row['tls']; exact(tls,CONTRACT['samplerTLSKeys'])
        need(tls['authorized'] is True and tls['protocol'] in ('TLSv1.2','TLSv1.3') and 128 <= len(leaf) <= 16384); same(unbase64(tls['leafDERBase64'],16384),leaf); same(tls['leafSHA256'],sha(leaf))
        body=unbase64(row['responseBase64'],65536); total+=len(body); need(total <= 131072); same(row['responseBytes'],len(body)); same(row['responseSHA256'],sha(body)); need(b'Bearer ' not in body and b'PRIVATE KEY' not in body)
        decoded[action['key']]=response(body,row['status']); same(decoded[action['key']],action['code'])
        if ordinal == 1: headers(row,None,'recorded')
        else: identifier(row['commandIdHeader'],'cmd'); headers(row,row['commandIdHeader'])
    need(rows[1]['startedWallTimeUs'] >= rows[0]['endWallTimeUs'])
    return rows,decoded


def reconstruct(rows, decoded, sampler):
    by_case={r['caseKey']:r for r in rows if r['method'] == 'POST'}
    samples={r['caseKey']:r for r in sampler}; by_case.update(samples)
    need(len(by_case) == 12)
    receipts={}; command_cases={}; source_ids={}; keys=set(); states=[dict(sources={},candidates={})]; commands=[]; latest={}; approvals={}; cid=None
    for action in ACTIONS:
        key=action['key']; row=by_case[key]; public=row['requestPublic']; kind=action['kind']; alias=action['source']
        fields={'label','idempotencyKey'} if kind == 'create' else {'sourceId','expectedRevision','idempotencyKey'} | ({'referenceId','policyRevision'} if kind == 'approve' else {'approvalId','policyRevision'})
        exact(public,fields); ikey=public['idempotencyKey']; need(type(ikey) is str and re.fullmatch(r'sub_[a-f0-9]{32}',ikey) and ikey not in keys); keys.add(ikey)
        if kind == 'create': same(public['label'],CONTRACT['labels'][alias]); same(row['path'],BASE+'/sources')
        else:
            same(public['sourceId'],source_ids[alias]); same(public['expectedRevision'],action['expectedRevision']); same(row['path'],BASE+'/sources/'+source_ids[alias]+('/approvals' if kind == 'approve' else '/fetches'))
            if kind == 'approve': same(public['referenceId'],action['referenceId']); same(public['policyRevision'],1)
            else:
                approval_key=action['approvalKey']; aid=CONTRACT['unknownApprovalId'] if approval_key == 'unknown' else receipts[approval_key]['commandId']
                same(public['approvalId'],aid); same(public['policyRevision'],action['policyRevision'])
        if key == 'api_approve_denied': continue
        if action['status'] == 200: rc=decoded[row['ordinal']]
        else:
            matching=[r for r in rows if r['kind'] == 'RECEIPT' and RECEIPT_CASES[r['caseKey']]['commandKey'] == key and r['status'] == 200]
            same(len(matching),1); rc=decoded[matching[0]['ordinal']]; same(rc['commandId'],row['commandIdHeader']); same(rc['code'],action['code'])
        safe_receipt(rc,kind,action['status'] != 200); same(rc['revision'],action['revision']); need(rc['commandId'] not in command_cases)
        receipts[key]=rc; command_cases[rc['commandId']]=key; commands.append((action,row,rc)); state=copy.deepcopy(states[-1])
        if kind == 'create':
            sid=rc['sourceId']; need(sid not in source_ids.values()); source_ids[alias]=sid
            state['sources'][sid]=dict(id=sid,scope=SCOPE,label=CONTRACT['labels'][alias],revision=1,updatedAt=rc['completedAt'])
        else:
            same(rc['sourceId'],source_ids[alias]); current=state['sources'][source_ids[alias]]
            if kind == 'approve':
                same(current['revision'],1); same(rc['referenceId'],action['referenceId']); latest[alias]=key; approvals[key]=rc
            elif action['status'] == 200:
                same(current['revision'],1); same(latest[alias],action['approvalKey']); same(public['policyRevision'],receipts[latest[alias]]['policyRevision'])
                cid=rc['candidateId']; state['candidates'][cid]=dict(id=cid,sourceId=source_ids[alias],digest=rc['candidateDigest'],format='mihomo-provider-yaml',state='quarantined',baseRevision=2,nodeCount=2,duplicateCount=0)
                current.update(revision=2,updatedAt=rc['completedAt'],latestCandidateId=cid)
            elif key == 'api_stale_fetch': same(current['revision'],2); same(public['expectedRevision'],1)
            else: same(current['revision'],1)
        states.append(state)
    same(len(commands),11); need(CONTRACT['unknownApprovalId'] not in command_cases)
    # Native observations and CDP wallTime are compared only as their recorded
    # real-time values. No monotonic delta is added to fabricate a wall end.
    valid=by_case['valid_fetch']; need(samples['api_approve_denied']['endWallTimeUs'] <= valid['startedWallTimeUs'] <= samples['api_stale_fetch']['startedWallTimeUs'])
    return dict(commands=commands,receipts=receipts,commandCases=command_cases,sourceIds=source_ids,approvals=approvals,states=states,candidateId=cid,candidateCreatedAt=None,nodeViews=None,sourcePages={},candidatePages={},nodePages={})


def expected_access(role, sid=None):
    need(role in ('operator','approver')); actions=['subscription.read']
    if sid is None and role == 'operator': actions+=['subscription.source.manage']
    if sid is not None and role == 'operator': actions+=['subscription.import','subscription.fetch']
    if sid is not None and role == 'approver': actions+=['subscription.admission.decide','subscription.source.approve','subscription.rollback']
    return dict(scope=SCOPE,resource=dict(type='subscription-store' if sid is None else 'subscription-source',id='local' if sid is None else sid),writesEnabled=True,actions=actions,policyState='ready',references=CONTRACT['references'])


def possible_states(row, facts):
    # Only same CDP-monotonic-domain browser writes constrain browser GETs.
    # Sampler native wall clock cannot be mixed into this calculation. Its sole
    # state-changing attempt is a failed stale CAS, so it changes no inventory.
    posts=[(i,r) for i,(_,r,_) in enumerate(facts['commands'],1) if 'requestOrdinal' in r]
    lower=max([0]+[i for i,r in posts if r['endTimeUs'] < row['startTimeUs']])
    upper=min([len(facts['commands'])]+[i-1 for i,r in posts if r['startTimeUs'] > row['endTimeUs']])
    need(lower <= upper); return facts['states'][lower:upper+1]


def validate_gets(rows, decoded, facts):
    for row in rows:
        if row['method'] != 'GET' or row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT'): continue
        kind,path,role=row['kind'],row['path'],row['actorRole']; value=decoded[row['ordinal']]
        if kind == 'COLLECTION_ACCESS': same(path,BASE+'/access'); same(value,expected_access(role)); continue
        if kind == 'RECEIPT':
            case=RECEIPT_CASES[row['caseKey']]; rc=facts['receipts'][case['commandKey']]; same(path,BASE+'/commands/'+rc['commandId'])
            command_row=next(r for a,r,_ in facts['commands'] if a['key'] == case['commandKey'])
            if 'requestOrdinal' in command_row:
                need(command_row['ordinal'] < row['ordinal'] and command_row['requestOrdinal'] < row['requestOrdinal'] and command_row['endTimeUs'] <= row['startTimeUs'])
            else: need(command_row['endWallTimeUs'] <= row['startedWallTimeUs'])
            if row['status'] == 200: same(value,rc)
            else: same(row['caseKey'],'cross_owner_receipt'); same(value,FORBIDDEN_CODE); need(rc['kind'] == 'approve')
            continue
        if kind == 'SOURCE_ACCESS':
            sid=next((v for v in facts['sourceIds'].values() if path == BASE+'/sources/'+v+'/access'),None); need(sid is not None); same(value,expected_access(role,sid)); continue
        available=possible_states(row,facts)
        if kind == 'SOURCES':
            same(path,BASE+'/sources'); exact(value,('sources','total')); need(type(value['sources']) is list); same(value['total'],len(value['sources']))
            need(any(same_value(value['sources'],sorted(s['sources'].values(),key=lambda v:v['id'])) for s in available)); facts['sourcePages'][row['ordinal']]=value
        elif kind in ('CANDIDATES','NODES'):
            pattern=re.escape(BASE+'/sources/')+r'(src_[a-f0-9]{32})/candidates'+('' if kind == 'CANDIDATES' else '/'+re.escape(facts['candidateId'])+'/nodes')+r'\?limit=20&offset=0&revision=([12])'
            match=re.fullmatch(pattern,path); need(match is not None); sid,rev=match[1],int(match[2]); need(sid in facts['sourceIds'].values())
            exact(value,('candidates','total','revision') if kind == 'CANDIDATES' else ('nodes','total','revision')); same(value['revision'],rev)
            allowed=[s for s in available if sid in s['sources'] and s['sources'][sid]['revision'] == rev]; need(allowed)
            if kind == 'CANDIDATES':
                need(type(value['candidates']) is list); summaries=[]
                for c in value['candidates']:
                    exact(c,('id','sourceId','digest','format','state','baseRevision','nodeCount','duplicateCount','createdAt')); timestamp(c['createdAt']); same(c['id'],facts['candidateId'])
                    if facts['candidateCreatedAt'] is None: facts['candidateCreatedAt']=c['createdAt']
                    same(c['createdAt'],facts['candidateCreatedAt']); summaries.append({k:v for k,v in c.items() if k != 'createdAt'})
                same(value['total'],len(summaries)); need(any(same_value(summaries,[c for c in s['candidates'].values() if c['sourceId'] == sid]) for s in allowed)); facts['candidatePages'][row['ordinal']]=(sid,value)
            else:
                need(sid == facts['sourceIds']['a'] and any(facts['candidateId'] in s['candidates'] for s in allowed)); safe_nodes(value['nodes']); same(value['total'],2)
                if facts['nodeViews'] is None: facts['nodeViews']=value['nodes']
                same(value['nodes'],facts['nodeViews']); facts['nodePages'][row['ordinal']]=(sid,value)
        else: need(False)
    need(facts['nodeViews'] is not None and facts['candidateCreatedAt'] is not None)


def validate_audit(events, checkpoint, facts):
    same(len(events),23); previous='0'*64; ids=set(); pairs={}; denied=[]
    for index,event in enumerate(events):
        exact(event,('id','idempotencyKey','traceId','actorId','action','target','result','occurredAt','data','previousHash','hash'))
        need(type(event['id']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',event['id']) and event['id'] not in ids); ids.add(event['id'])
        need(type(event['actorId']) is str and re.fullmatch(r'act_[a-f0-9]{60}',event['actorId'])); timestamp(event['occurredAt'])
        same(event['previousHash'],previous); same(event['hash'],sha(H.go_event_bytes(event))); previous=event['hash']
        if event['result'] == 'denied':
            need(type(event['traceId']) is str and re.fullmatch(r'denied_[a-f0-9]{32}',event['traceId']))
            same(event['idempotencyKey'],'subscription/'+event['traceId']); same(event['action'],'subscription.command.denied'); same(event['target'],'subscription/local')
            same(event['data'],dict(category='approve',classification=FORBIDDEN_CODE)); denied.append(event); continue
        command=identifier(event['traceId'],'cmd'); need(command in facts['commandCases']); stage=event['result']; need(stage in ('prepared','result') and stage not in pairs.setdefault(command,{}))
        same(event['action'],'subscription.command.'+stage); same(event['idempotencyKey'],'subscription/'+command+'/'+stage)
        fields={'tenantId','siteId','environment','managementObject','kind','commandDigest'}
        if stage == 'result': fields|={'state','code','sourceId','candidateId','revision','candidateDigest','localAuditHash','approvalId','policyDigest','policyRevision','stateMayHaveChanged'}
        exact(event['data'],fields); need(all(type(v) is str for v in event['data'].values())); hmac_digest(event['data']['commandDigest'])
        pairs[command][stage]=(index,event)
    same(checkpoint,dict(count=23,lastHash=previous)); same(len(denied),1); same(set(pairs),set(facts['commandCases'])); actors={}
    for action,row,rc in facts['commands']:
        pair=pairs[rc['commandId']]; exact(pair,('prepared','result')); (ai,a),(bi,b)=pair['prepared'],pair['result']
        need(ai < bi and timestamp(a['occurredAt']) <= timestamp(b['occurredAt'])); same(a['actorId'],b['actorId']); same(a['data'],{k:b['data'][k] for k in a['data']})
        role=action['actorRole']; need(role not in actors or actors[role] == a['actorId']); actors[role]=a['actorId']
        same(a['hash'],rc['preparedAuditHash']); same(b['hash'],rc['resultAuditHash']); same(b['occurredAt'],rc['completedAt'])
        same(a['target'],'subscription/'+('local' if action['kind'] == 'create' else rc['sourceId'])); same(b['target'],a['target'])
        expected=dict(**SCOPE,managementObject='local',kind=action['kind'],commandDigest=a['data']['commandDigest'],state=rc['state'],code=rc.get('code',''),sourceId=rc['sourceId'],candidateId=rc.get('candidateId',''),revision=str(rc['revision']),candidateDigest=rc.get('candidateDigest',''),localAuditHash=rc.get('localAuditHash',''),approvalId=rc.get('approvalId',''),policyDigest=rc.get('policyDigest',''),policyRevision=str(rc.get('policyRevision',0)),stateMayHaveChanged='false')
        same(b['data'],expected)
    same(set(actors),{'operator','approver'}); same(len(set(actors.values())),2); same(denied[0]['actorId'],actors['operator'])
    return actors


def validate_private(value, facts, actors, commit, fixture):
    exact(value,('schema','sourceCommit','fixtureId','scope','sources','candidates','localAuditCount','commandCount','approvalCount','commands','approvals'))
    same(value['schema'],CONTRACT['readbackSchema']); same(value['sourceCommit'],commit); same(value['fixtureId'],fixture); same(value['scope'],SCOPE)
    last=facts['states'][-1]; same(value['sources'],[last['sources'][facts['sourceIds'][key]] for key in ('a','b')])
    same(value['localAuditCount'],3); same(value['commandCount'],11); same(value['approvalCount'],3)
    same(value['candidates'],[dict(**last['candidates'][facts['candidateId']],scope=SCOPE,nodes=facts['nodeViews'],createdAt=facts['candidateCreatedAt'])])
    need(type(value['commands']) is list and len(value['commands']) == 11); commands={v['id']:v for v in value['commands']}; same(set(commands),set(facts['commandCases']))
    for action,row,rc in facts['commands']:
        expected=dict(id=rc['commandId'],scope=SCOPE,actorId=actors[action['actorRole']],kind=action['kind'],expectedRevision=action['expectedRevision'],preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True)
        if action['kind'] != 'create': expected['sourceId']=rc['sourceId']
        result={k:rc[k] for k in ('sourceId','candidateId','revision','state','code','stateMayHaveChanged','localAuditHash','completedAt','referenceId','policyRevision','policyDigest','approvalId') if k in rc}
        if 'candidateDigest' in rc: result['digest']=rc['candidateDigest']
        expected['result']=result; same(commands[rc['commandId']],expected)
    need(type(value['approvals']) is list and len(value['approvals']) == 3)
    approvals={v['commandId']:v for v in value['approvals']}; same(set(approvals),{rc['commandId'] for rc in facts['approvals'].values()})
    for rc in facts['approvals'].values():
        same(approvals[rc['commandId']],dict(commandId=rc['commandId'],scope=SCOPE,sourceId=rc['sourceId'],referenceId=rc['referenceId'],policyRevision=1,policyDigest=rc['policyDigest'],sourceRevision=1,approvedAt=rc['completedAt']))


def sampler_fence(value, raw, count):
    exact(value,CONTRACT['samplerFenceKeys']); integer(count,0,2); lines=raw.splitlines(keepends=True); same(len(lines),2)
    prefix=b''.join(lines[:count]); same(value,dict(recordCount=count,bytes=len(prefix),sha256=sha(prefix)))


def validate_dom(rows, captures, decoded, facts, wire_raw, sampler_raw):
    same(len(rows),len(STEPS)); previous=0; last_state=None; seen_cases=set()
    browser_commands=[(i,a,r,rc) for i,(a,r,rc) in enumerate(facts['commands'],1) if a['origin'] == 'browser']
    for ordinal,(row,step) in enumerate(zip(rows,STEPS),1):
        exact(row,CONTRACT['domStepKeys']); same(row['schema'],CONTRACT['domSchema']); same(row['ordinal'],ordinal); same(row['step'],step)
        state=dict(zip(CONTRACT['stateColumns'],CONTRACT['stepStates'][step])); role=state['actorRole']; posts=state['browserPosts']; selected=state['selectedSource']
        same(row['actorRole'],role); same(row['mutationCount'],posts); integer(row['captureCount'],previous,len(captures)); previous=row['captureCount']; seen=captures[:previous]
        same(sum(r['method'] == 'POST' for r in seen),posts)
        # Complete ordered browser prefix, not merely a self-reported counter.
        same([r['caseKey'] for r in sorted((r for r in seen if r['method'] == 'POST'),key=lambda r:r['requestOrdinal'])],[a['key'] for _,a,_,_ in browser_commands[:posts]])
        validate_fence(row['wireFence'],wire_raw,state['wireEvents'] == 12); sampler_fence(row['samplerFence'],sampler_raw,state['samplerRecords'])
        seen_cases={r['caseKey'] for r in seen if r['caseKey'] is not None}
        if step in RECEIPT_CASES: need(step in seen_cases)
        if step == 'cross_owner_denied': need('cross_owner_receipt' in seen_cases)
        if step == 'stale_receipt_failed': need('stale_receipt' in seen_cases)
        state_index=0 if posts == 0 else browser_commands[posts-1][0]; inventory=facts['states'][state_index]
        d=row['dom']; exact(d,('schema','pageMounted','pageVisible','https','viewport','session','controls','sources','candidates','nodes','paging','mode','directory','sessionApproval','handoff','confirmation','receipt','stale','alertVisible','boundaryVisible'))
        need(d['schema'] == 'chengwang.subscription-browser-dom/v1' and d['pageMounted'] is True and d['https'] is True)
        same(d['pageVisible'],step != 'hidden'); same(d['boundaryVisible'],step != 'hidden'); same(d['alertVisible'],state['alert'])
        vp=d['viewport']; exact(vp,('width','height','scrollX','scrollY','clientWidth','scrollWidth'))
        for k in ('width','height','clientWidth','scrollWidth'): integer(vp[k],1,100000)
        for k in ('scrollX','scrollY'): integer(vp[k],-100000,100000)
        same(vp['height'],900); same(vp['width'],375 if STEPS.index(step) >= STEPS.index('final_mobile') else 1440); need(vp['scrollWidth'] == vp['clientWidth'] and vp['clientWidth'] <= vp['width'])
        same(d['session'],dict(tokenMounted=True,tokenType='password',tokenEmpty=True,fileMounted=True,fileEmpty=True,storageEmpty=True,cookiesEmpty=True))
        same(d['stale'],dict(sources=state['staleSources'],candidates=state['staleCandidates'],nodes=False))
        need(type(d['controls']) is list and len(d['controls']) == len(CONTROLS))
        for ctl,key in zip(d['controls'],CONTROLS): control_projection(ctl); same(ctl['key'],key)
        controls={v['key']:v for v in d['controls']}; fresh=not state['staleSources'] and not state['staleCandidates']; source=inventory['sources'].get(facts['sourceIds'].get(selected)) if selected else None
        source_views=[] if step == 'cleared' else [dict(id=s['id'],revision=s['revision'],selected=bool(source and source['id'] == s['id']),accepted=False,disabled=False) for s in sorted(inventory['sources'].values(),key=lambda v:v['id'])]
        same(d['sources'],source_views)
        same(state['revisionA'],inventory['sources'].get(facts['sourceIds']['a'],{}).get('revision',0)); same(state['revisionB'],inventory['sources'].get(facts['sourceIds']['b'],{}).get('revision',0))
        candidate=inventory['candidates'].get(facts['candidateId']) if selected == 'a' else None
        same(d['candidates'],[dict(id=candidate['id'],state='quarantined',nodeCount=2,format='mihomo-provider-yaml',baseRevision=2,selected=state['candidateSelected'])] if candidate else [])
        same(d['nodes'],[{k:v for k,v in n.items() if k != 'label'} for n in facts['nodeViews']] if state['candidateSelected'] else [])
        same(d['paging'],dict(candidates=dict(page=1,revision=source['revision']) if source else None,nodes=dict(page=1,revision=2) if state['candidateSelected'] else None))
        if source:
            need(any(r['actorRole'] == role and r['ordinal'] in facts['candidatePages'] and facts['candidatePages'][r['ordinal']][0] == source['id'] and facts['candidatePages'][r['ordinal']][1]['revision'] == source['revision'] for r in seen))
        if state['candidateSelected']: need(any(r['actorRole'] == role and r['ordinal'] in facts['nodePages'] and facts['nodePages'][r['ordinal']][1]['revision'] == 2 for r in seen))
        same(d['directory'],dict(present=True,disabled=not bool(source),references=[dict(**r,selected=r['referenceId'] == state['reference']) for r in CONTRACT['references']] if source else []))
        same(d['mode'],state['mode'])
        approval=facts['receipts'].get(state['approvalKey']); same(d['sessionApproval'],{k:approval[k] for k in ('approvalId','referenceId','policyRevision')} if approval else None)
        aid=CONTRACT['unknownApprovalId'] if state['handoffKey'] == 'unknown' else facts['receipts'][state['handoffKey']]['commandId'] if state['handoffKey'] else None
        same(d['handoff'],dict(approvalValid=True,approvalId=aid,revisionValid=True,policyRevision=state['handoffPolicy'],unverifiedReferenceNotice=True) if state['mode'] == 'handoff' else None)
        receipt=facts['receipts'].get(state['receiptKey']); same(d['receipt'],{k:receipt[k] for k in ('commandId','revision','state','replayed','auditRecorded')} if receipt else None)
        # Failed POST envelopes do not themselves contain receipts.  A displayed
        # failed receipt must already have a real owner GET in the CDP prefix.
        if receipt and receipt['state'] == 'failed': need(any(r['kind'] == 'RECEIPT' and r['status'] == 200 and decoded[r['ordinal']]['commandId'] == receipt['commandId'] for r in seen))
        dialog=state['dialog']; expected=None
        if dialog:
            expected=dict(kind=dialog,binding=dict(sourceId=source['id'],expectedRevision=source['revision'],approvalId=aid,policyRevision=state['handoffPolicy']) if dialog == 'fetch_handoff' else None,unverifiedReference=dialog == 'fetch_handoff',rollbackRequired=False,rollbackChecked=False)
            need(controls['confirm']['enabled'] is True and controls['cancel']['enabled'] is True)
        same(d['confirmation'],expected)
        same(controls['prepare_create']['enabled'],role == 'operator' and fresh)
        same(controls['prepare_import']['enabled'],role == 'operator' and bool(source) and fresh)
        same(controls['prepare_approve']['enabled'],role == 'approver' and bool(source) and fresh)
        same(controls['prepare_fetch']['enabled'],role == 'operator' and bool(source) and fresh and state['mode'] == 'handoff')
        for key in ('prepare_admit','prepare_reject','prepare_rollback'): same(controls[key]['enabled'],False)
        for key in ('connect','clear'): same(controls[key]['enabled'],True)
        for key in ('refresh_sources','read_receipt'): same(controls[key]['enabled'],role != 'anonymous')
        same(controls['refresh_source']['enabled'],bool(source))
        for key in ('candidate_previous','candidate_next','node_previous','node_next'): same(controls[key]['enabled'],False)
        for key in ('confirm','cancel'): same(controls[key]['enabled'],bool(dialog))
        for key in CONTROLS:
            present=bool(dialog) if key in ('confirm','cancel') else bool(source) if key in ('refresh_source','candidate_previous','candidate_next') else state['candidateSelected'] if key in ('node_previous','node_next') else True
            same(controls[key]['present'],present); same(controls[key]['visible'],present and step != 'hidden')
        if step == 'anonymous': need(not any(r['authorizationPresent'] for r in seen))
        if step in ('hidden','returned'):
            stable={k:v for k,v in d.items() if k not in ('pageVisible','boundaryVisible','controls','viewport')}
            if step == 'hidden': last_state=stable
            else: same(stable,last_state)
    same(rows[-1]['captureCount'],len(captures))


def json_lines(raw, maximum=256):
    need(type(raw) is bytes and raw.endswith(b'\n') and 0 < len(raw.splitlines()) <= maximum)
    return [decode(line) for line in raw.splitlines()]


def safe_nodes(value):
    need(type(value) is list and len(value) == 2); ids = []
    for node in value:
        exact(node,('id','label','protocol','credentialConfigured','state')); identifier(node['id'],'node')
        need(node['label'] == '节点-' + node['id'][-8:] and node['credentialConfigured'] is True and node['state'] == 'unknown' and node['protocol'] in ('http','socks5'))
        ids.append(node['id'])
    need(ids == sorted(set(ids)) and {v['protocol'] for v in value} == {'http','socks5'})


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


def control_projection(value):
    exact(value,('key','present','visible','enabled','inViewport','unobstructed','rect'))
    for k in ('present','visible','enabled','inViewport','unobstructed'): boolean(value[k])
    need(value['present'] or not any(value[k] for k in ('visible','enabled','inViewport','unobstructed')))
    need(value['visible'] == (value['rect'] is not None) and (not value['inViewport'] or value['visible']) and (not value['unobstructed'] or value['inViewport']))
    if value['rect'] is not None:
        exact(value['rect'],('x','y','width','height'))
        for k in ('x','y'): integer(value['rect'][k],-100000,100000)
        for k in ('width','height'): integer(value['rect'][k],0,100000)


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
    own = 'chengwang/deploy/subscription-ui-browser/check_handoff_negative_ui.py'
    need(own in source_map and git_bytes(repo,commit,own) == read(Path(__file__)))
    need(git_bytes(repo,commit,'chengwang/deploy/subscription-ui-browser/check_subscription_ui.py') == read(Path(H.__file__)))
    for path in (CONTRACT_PATH,'chengwang/deploy/subscription-ui-browser/handoff_negative_fixture.py','chengwang/deploy/subscription-readback/wire_fixture.py','chengwang/deploy/subscription-readback/lab_contract.py','chengwang/tools/subscription-ui-browser/handoff-negative-cli.mjs'):
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
    required=('chrome/chrome','toolchain/node','toolchain/server','npm/playwright-core/package.json','chengwang/deploy/subscription-readback/wire_fixture.py','chengwang/deploy/subscription-readback/lab_contract.py',CONTRACT_PATH,
        'chengwang/deploy/subscription-ui-browser/handoff_negative_fixture.py','chengwang/tools/subscription-ui-browser/handoff-negative-cli.mjs','chengwang/tools/subscription-ui-browser/handoff-negative-driver.mjs','chengwang/tools/subscription-ui-browser/handoff-negative-contract.mjs','chengwang/tools/subscription-ui-browser/handoff-api-sampler.mjs','chengwang/tools/subscription-ui-browser/ui-contract.mjs','chengwang/tools/subscription-ui-browser/remote-fetch-contract.mjs','chengwang/tools/subscription-browser/collect-subscription-dom.mjs')
    for path in required: need(path in copied)
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
    same(roles['controller']['argv'],[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/handoff-negative-cli.mjs','--root',root,'--bundle',bundle,'--engine',engine,'--source-commit',commit])
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
    def budget(name):
        return 24<<20 if name == 'captures.jsonl' else 256<<10 if name in ('wire-events.jsonl','api-sampler.jsonl') else 1<<20 if name == 'dom.jsonl' else 16<<20
    raw={name:read(directory/name,budget(name)) for name in PUBLIC}
    need(all(b'PRIVATE KEY' not in v and b'Bearer ' not in v for v in raw.values())); same(decode(git_bytes(repo,commit,CONTRACT_PATH)),CONTRACT)
    driver=decode(raw['driver.json']); exact(driver,CONTRACT['driverKeys']); fixture=driver['fixtureId']; need(type(fixture) is str and re.fullmatch(r'[a-f0-9]{32}',fixture))
    same(driver['schema'],CONTRACT['driverSchema']); same(driver['scenario'],SCENARIO); same(driver['sourceCommit'],commit); same(driver['engine'],engine); same(driver['origin'],CONTRACT['origin']); same(driver['scope'],CONTRACT['scope']); same(driver['runtime'],True)
    for key in ('mockedResponses','injectedFetch','tlsBypass','production','fullSubscriptionE2EProven'): same(driver[key],False)
    same(driver['steps'],STEPS); exact(driver['counters'],COUNTERS)
    need(all(type(v) is int and v == 0 for v in driver['counters'].values()))
    exact(driver['browser'],('product','revision','protocolVersion')); need(driver['browser']['product'] in ('Chrome/157.0.8103.6','HeadlessChrome/157.0.8103.6')); same(driver['browser']['revision'],'@'+TAG); same(driver['browser']['protocolVersion'],'1.3')
    build=decode(raw['build.json']); H.validate_build(build,commit)
    captures=json_lines(raw['captures.jsonl']); decoded,_=validate_browser(captures,build)
    certificates=decode(raw['certificates.json']); sampler,_=validate_sampler(raw['api-sampler.jsonl'],certificates)
    facts=reconstruct(captures,decoded,sampler); validate_gets(captures,decoded,facts)
    same(driver['captures'],dict(path='captures.jsonl',bytes=len(raw['captures.jsonl']),sha256=sha(raw['captures.jsonl']),records=len(captures)))
    exact(driver['apiSampler'],CONTRACT['apiSamplerKeys']); same(driver['apiSampler'],dict(path='api-sampler.jsonl',bytes=len(raw['api-sampler.jsonl']),sha256=sha(raw['api-sampler.jsonl']),records=2,source=CONTRACT['apiSamplerSource']))
    dom=json_lines(raw['dom.jsonl'],len(STEPS)); validate_dom(dom,captures,decoded,facts,raw['wire-events.jsonl'],raw['api-sampler.jsonl'])
    actors=validate_audit(json_lines(raw['audit-events.jsonl'],23),decode(raw['audit-checkpoint.json']),facts)
    validate_private(decode(raw['private-readback.json']),facts,actors,commit,fixture)
    shots=driver['screenshots']; need(type(shots) is list and len(shots) == 2)
    for item,expected in zip(shots,CONTRACT['screenshots']):
        exact(item,('path','step','bytes','sha256','viewport','scrollX','scrollY','capturedWallTimeUs')); name=expected['path']; same(item['path'],name); same(item['step'],expected['step']); same(item['viewport'],expected['viewport']); same(item['sha256'],sha(raw[name])); same(item['bytes'],len(raw[name]))
        integer(item['capturedWallTimeUs'],1); same(item['scrollX'],0); same(item['scrollY'],0); png(raw[name],expected['viewport']['width'],900)
        projection=next(v['dom'] for v in dom if v['step'] == expected['step']); same(projection['viewport']['scrollX'],0); same(projection['viewport']['scrollY'],0)
    inputs=decode(raw['inputs.json']); build_rows=[v for v in inputs['copiedInputs'] if v['path'] == 'build/report.json']; same(len(build_rows),1)
    same(build_rows[0],dict(path='build/report.json',bytes=len(raw['build.json']),sha256=sha(raw['build.json'])))
    source_count,wire_pid=validate_supervisor(decode(raw['processes.json']),decode(raw['isolation.json']),inputs,build,driver,decode(raw['pin-consumption.json']),repo,commit,engine,fixture)
    validate_wire(raw['wire-events.jsonl'],decode(raw['wire-ready.json']),decode(raw['wire-stopped.json']),wire_pid)
    H.verify_tls(certificates,driver,captures); verify_wire_tls(raw,captures)
    for sample in sampler: H.verify_tls(certificates,driver,[dict(startedWallTimeUs=sample['startedWallTimeUs'])])
    need({name:read(directory/name,budget(name)) for name in PUBLIC} == raw)
    return dict(schema='chengwang.handoff-negative-ui-verification/v1',sourceCommit=commit,engine=engine,fixtureId=fixture,outcome='PASS',scope=CONTRACT['scope'],actualBrowser=driver['browser'],actualChromeELFSHA256=ELF_SHA,
        steps=len(STEPS),screenshots=2,requests=len(captures),browserPosts=10,nativeAPIPosts=2,commands=11,approvals=3,localAuditCount=3,externalAuditEvents=23,deniedEvents=1,ownFailedReceiptGETs=5,crossOwnerReceiptGETs=1,sourceGitBlobs=source_count,sources=2,candidates=1,sourceRevisions=dict(a=2,b=1),candidateState='quarantined',wireConnections=3,wireEvents=12,
        normalTLSOfflineVerifiedAtCapture=True,nativeAPITLSLeafBoundAndOfflineVerifiedAtSample=True,sourceAndResolverTLSOfflineVerifiedAtCapture=True,pinConsumed=True,realBrowserHandoffNegativeCasesProven=True,separateNativeAPIRejectionsProven=True,
        browserPerformedNativeAPIPosts=False,fullSubscriptionE2EProven=False,timeTTLProven=False,policyReloadProven=False,postNetworkCASProven=False,trueConcurrentSessionsProven=False,
        perHTTPFencesProven=False,fenceTrust=CONTRACT['fenceTrust'],externalInternetProven=False,privateDatabaseRawIndependentlyVerified=False,privateRawFilesIndependentlyVerified=False,independentReproducibleBuildProven=False,screenshotVisualReviewProven=False,newNavigationFailureDiagnosticsProven=False,
        privateReadbackTrustBoundary='TRUSTED_RUNNER_SAFE_PROJECTION_NOT_INDEPENDENT_PRIVATE_DATABASE_VERIFICATION',processTrustBoundary='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION',production=False,authorization='BLOCKED',remaining=CONTRACT['remaining'],evidenceSHA256={name:sha(raw[name]) for name in sorted(raw)})


def main():
    parser=argparse.ArgumentParser()
    for name in ('evidence','repo','report'): parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--source-commit',required=True); parser.add_argument('--engine',required=True,choices=('chrome-cdp','playwright')); args=parser.parse_args()
    evidence=args.evidence.resolve(strict=True); repo=args.repo.resolve(strict=True); report=args.report.absolute()
    need(not args.evidence.is_symlink() and not args.repo.is_symlink() and not report.exists() and not report.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.resolve().is_relative_to(repo))
    result=verify(evidence,repo,args.source_commit,args.engine)
    with report.open('xb') as output: output.write(canonical(result)+b'\n')
    print('HANDOFF_NEGATIVE_UI_INDEPENDENT=PASS full_subscription_e2e_proven=false production=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('HANDOFF_NEGATIVE_UI_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
