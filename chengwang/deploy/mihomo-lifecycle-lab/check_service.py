"""Independent public-original checker for the isolated product HTTP experiment.

Imports only prior independent verifiers, never a worker/producer. In-memory
models do not prove Git, custody, credentials, private YAML or an actual run.
"""
import argparse
import base64
import importlib.util
import math
import os
from pathlib import Path
import re
import stat
import subprocess


def need(ok):
    if not ok:
        raise ValueError('isolated service evidence rejected')


def _independent():
    path = Path(__file__).absolute().with_name('check_apply.py')
    for part in (*reversed(path.parents),path):
        info=part.lstat(); need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&1024)
    info=path.lstat(); need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=1<<20)
    spec = importlib.util.spec_from_file_location('_service_independent_apply', path)
    need(spec is not None and spec.loader is not None)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


try:
    A = _independent()
except Exception:
    raise SystemExit('MIHOMO_SERVICE=REJECTED independent_source_unavailable=true') from None
C, G = A.C, A.G
PREFIX = 'chengwang/deploy/mihomo-lifecycle-lab/'
GO = 'chengwang/internal/serverruntime/mihomo_service_e2e_linux_test.go'
TLS = 'chengwang/internal/serverruntime/subscription_runtime_linux_test.go'
FILES = tuple(A.FILES) + tuple(PREFIX + n for n in ('check_service.py', 'test_check_service.py',
    'service_worker.py', 'service_contract.json', 'run_service.sh', 'test_service_worker.py')) + (TLS,)
STAGES = ('bootstrap', 'op-01-create', 'op-01-pre-dispatch', 'op-01-post-dispatch')
CAPTURE = ('transcript.json', *(f'body-{i}.json' for i in range(1, 9)), 'verification.json')
PUBLIC = tuple(stage + '-' + name for stage in STAGES for name in CAPTURE) + (
    'op-01-syntax.json', 'op-01-syntax.stdout', 'op-01-syntax.stderr', 'e2e-report.json',
    'service-journal.jsonl', 'kernel.stdout', 'kernel.stderr', 'sandbox.json', 'execution.json',
    'go-version.txt', 'gofmt.patch', 'gofmt.stderr', 'service.json', 'service.stderr',
    'host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json')
SCOPE = 'ACTUAL_ISOLATED_PRODUCT_HTTP_AND_LOCAL_POSTCONDITION_NOT_FULL_SYSTEM_OR_PRODUCTION'
BOUNDARY = 'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF'
TOP = 'TestMihomoServiceHTTPApprovalReloadReadbackAndReplay'
PACKAGE = 'chengwang/internal/serverruntime'
ID = re.compile(r'labop_[a-f0-9]{32}')
BASES = ['/tmp/chengwang-mihomo-service-private', '/tmp/chengwang-mihomo-service-identities', '/tmp/chengwang-mihomo-service-state']
REPORT_KEYS = ('schema','scope','sourceCommit','outcome','failureCode','http','dropped','before','after','replay',
    'callsBefore','callsAfter','callsReplay','controllerReceivedCount','closedPorts','runtimeReturned','runtimeErrorClass',
    'production','fullPayloadProven','internetBusinessProven')
VIEW_KEYS = ('schema','boundary','operationId','phase','revision','planSHA256','candidateRecordSHA256','candidateConfigSHA256',
    'previousHeadSHA256','headSHA256','headGeneration','expiresAt','transport','observation','writeBlocked','replayed','headAdvanced','proof')
HEAD_KEYS = ('schema','boundary','revision','generation','headSHA256','previousHeadSHA256','artifactRecordSHA256','configSHA256',
    'verificationSHA256','verifiedAt','activeOperationId','writeBlocked','proof')
STATE_KEYS = ('schema','sourceCommit','walSchema','controlSHA256','recordSHA256','head','activeOperationId','activePhase',
    'activeIntentSHA256','completed','terminated','unknownObservationCount','privateWALValidated',
    'fullPrivateWALIndependentlyProven','observedProcessMatchesHead','production')
OBS_KEYS = ('Phase','Scope','DeviceRef','Artifact','StartupIdentity','OperationID','PlanSHA256','IntentSHA256','VerificationSHA256','ObservedAt')
ARTIFACT_KEYS = ('schema','recordSHA256','config','sourceSpecSHA256','sourceSpecBytes','controllerPort','mixedPort')
CONFIG_KEYS = ('schema','scope','sha256','bytes','draftSHA256','requirementsSHA256','capabilities','requirements','admissible','blockers')
SCOPE_KEYS = ('tenantId','siteId','objectType','objectId','environment')
TRANSPORT_KEYS = ('result','recordedAt','origin','gateReason')
HTTP_CASES = ('ANONYMOUS_CANDIDATES','ACTUAL_CANDIDATES','VIEWER_CREATE_DENIED','SCOPE_CREATE_DENIED',
    'CREATE_RESPONSE_DROPPED_AFTER_HANDLER','FIND_OPERATION_AFTER_DROP','INSPECT_CREATED_OPERATION','SELF_APPROVAL_DENIED',
    'CURRENT_INDEPENDENT_APPROVAL','ACTUAL_EXECUTE','REPLAY_EXECUTE_NO_NEW_SEND')
sha, decode, integer, timestamp = A.sha, A.decode, A.integer, A.timestamp
exact, same = A.exact, A.same


def digest(value):
    A.digest(value); need(value != '0'*64); return value


def ordered(value, keys):
    exact(value, keys); need(list(value) == list(keys)); return value


def struct(value):
    if type(value) is dict:
        return G._Struct([(k, struct(v)) for k, v in value.items()])
    if type(value) is list:
        return [struct(v) for v in value]
    return value


def go_bytes(value):
    return G.go_codec(struct(value))


def b64(value, *, empty=False, missing=False):
    if value is None:
        need(missing); return None
    need(type(value) is str and len(value) <= 22000)
    result = base64.b64decode(value, validate=True)
    need(base64.b64encode(result).decode('ascii') == value and (0 if empty else 1) <= len(result) <= 16 << 10)
    return result


def proof(value):
    exact(value, ('fullPayloadProven','internetBusinessProven','production'))
    need(all(v is False for v in value.values()))


def artifact(value):
    ordered(value, ARTIFACT_KEYS); cfg = ordered(value['config'], CONFIG_KEYS)
    need(value['schema'] == 'chengwang.mihomo-artifact/v1' and cfg['schema'] == 'chengwang.mihomo-lab-config/v1'
         and cfg['scope'] == 'ISOLATED_LOOPBACK_MIHOMO_STATIC_SUBSET_NOT_PRODUCTION')
    for v in (value['recordSHA256'], value['sourceSpecSHA256'], cfg['sha256'], cfg['draftSHA256'], cfg['requirementsSHA256']): digest(v)
    integer(value['sourceSpecBytes'], 1, 2 << 20); integer(cfg['bytes'], 1, 1 << 20)
    integer(value['controllerPort'], 28412, 28412); integer(value['mixedPort'], 28411, 28411)
    need(cfg['admissible'] is True); same(cfg['requirements'], []); same(cfg['blockers'], [])
    same(cfg['capabilities'], ['static_domain_suffix_rules','explicit_selectors','loopback_http_nodes','private_loopback_controller','built_in_dns_disabled'])
    record = dict(schema='chengwang.mihomo-artifact-record/v1', config=cfg,
                  sourceSpecSHA256=value['sourceSpecSHA256'], sourceSpecBytes=value['sourceSpecBytes'],
                  controllerPort=28412, mixedPort=28411)
    need(sha(go_bytes(record)) == value['recordSHA256'])
    return value


def contract(sources):
    expected = dict(schema='chengwang.mihomo-service-experiment-contract/v1',scope=SCOPE,tag='chengwang_mihomo_service',
        goPackage='./internal/serverruntime',topTest=TOP,goTimeoutSeconds=75,outerGoTimeoutSeconds=90,
        privateRoot=BASES[0],identityRoot=BASES[1],stateRoot=BASES[2],
        captureStages=['bootstrap','op-01/create','op-01/pre-dispatch','op-01/post-dispatch'],captureFiles=list(CAPTURE),
        maxPublicBytes=16 << 20,maxCaptureBodyBytes=256 << 10,maxVerificationBytes=64 << 10,production=False)
    same(decode(sources[PREFIX+'service_contract.json']), expected)
    source = sources[GO].decode('utf8')
    need(source.startswith('//go:build linux && chengwang_mihomo_service\n') and
         re.findall(r'^func (Test\w+)\(t \*testing.T\)',source,re.M) == [TOP])


def sandbox(raw, sources, commit, elf, receipt):
    v = exact(decode(raw['sandbox.json']), (*A.SANDBOX_KEYS, 'serviceBases'))
    need(v['schema'] == 'chengwang.mihomo-service-sandbox/v1' and v['sourceCommit'] == commit)
    integer(v['uid'],10001,10001); integer(v['gid'],10001,10001)
    need(v['effectiveCaps'] == '0000000000000000' and v['noNewPrivileges'] is True)
    same(v['environmentKeys'],list(A.ENV)); same(v['interfaceNames'],['lo']); same(v['serviceBases'],BASES)
    same(v['defaultV4Routes'],[]); same(v['defaultV6Routes'],[])
    need(v['sourceModuleSHA256'] == sha(sources['chengwang/go.mod']) and v['sourceReadOnly'] is True and v['goReadOnly'] is True)
    same(v['kernelCopy'],dict(sha256=elf['sha256'],bytes=elf['bytes'],mode='0500',readOnly=True,executable=True))
    before,after=decode(raw['host-before.json']),decode(raw['host-after.json'])
    exact(before,('networkNamespace','mountNamespace','pidNamespace','resolvSHA256')); same(before,after); digest(before['resolvSHA256'])
    for key,prefix in [('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')]:
        for item in (before[key],v[key]): need(type(item) is str and re.fullmatch(prefix+r':\[[1-9][0-9]{0,19}\]',item) is not None)
        need(before[key] != v[key])
    custody=exact(v['inputCustody'],('before','after')); same(custody['before'],custody['after'])
    for side in ('before','after'):
        exact(custody[side],('elf','receipt'))
        for name,hashed,size,mode in [('elf',elf['sha256'],elf['bytes'],'0500'),('receipt',sha(receipt),len(receipt),'0400')]:
            item=exact(custody[side][name],('sha256','bytes','mode','uid','gid'))
            need(item['sha256']==hashed and item['mode']==mode); integer(item['bytes'],size,size)
            integer(item['uid'],0,(1<<32)-1); integer(item['gid'],0,(1<<32)-1)
    return v


def events(raw):
    started=run=passed=ended=False; last=None
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20 and not ended)
        row=decode(line,elapsed=True); need(type(row) is dict and set(row)<= {'Time','Action','Package','Test','Elapsed','Output'})
        need(row.get('Package')==PACKAGE); when=timestamp(row.get('Time')); need(last is None or when>=last); last=when
        if 'Elapsed' in row: need(type(row['Elapsed']) in (int,float) and math.isfinite(row['Elapsed']) and row['Elapsed']>=0)
        action,name=row.get('Action'),row.get('Test')
        if 'Test' in row: need(name==TOP)
        if action=='start': need(not started and name is None and 'Elapsed' not in row); started=True
        elif action=='run': need(started and name==TOP and not run and not passed and 'Elapsed' not in row); run=True
        elif action=='pass':
            need(started and run)
            if name==TOP: need(not passed); passed=True
            else: need(name is None and passed); ended=True
        elif action=='output':
            need(started and (name is None or (name==TOP and run and not passed)) and 'Elapsed' not in row)
            output=row.get('Output'); need(type(output) is str and len(output)<=4096)
            need(re.fullmatch(r'(?:=== RUN   '+TOP+r'|[ ]*--- PASS: '+TOP+r' \([0-9.]+s\)|PASS|ok\s+'+PACKAGE+r'\s+[0-9.]+s|[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} chengwang listening \(mode=isolated-lab\))\n',output) is not None)
        else: need(False)
        if action!='output': need('Output' not in row)
    need(started and run and passed and ended)
    return dict(topLevel=1,passingSemanticTests=1,skips=0)


def capture(raw,stage,index,commit,elf,netns):
    original=raw[stage+'-verification.json']; need(0<len(original)<=64<<10)
    v=ordered(decode(original),('Observation','Readback','Transcript','Bodies','Route')); need(go_bytes(v)==original)
    ordered(v['Readback'],A.READBACK_KEYS)
    o=ordered(v['Observation'],OBS_KEYS); scope=ordered(o['Scope'],SCOPE_KEYS)
    need(all(type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',x) for x in scope.values()))
    need(scope['objectType']=='mihomo-lab' and scope['environment']=='isolated-lab' and o['DeviceRef']==scope['objectId'])
    need(o['Phase']==('BOOTSTRAP' if index==0 else 'ACKNOWLEDGED_COMPLETION' if index==3 else 'BASELINE'))
    need(o['VerificationSHA256']==''); timestamp(o['ObservedAt']); artifact(o['Artifact'])
    ident=ordered(o['StartupIdentity'],A.IDENTITY_KEYS)
    A.identity(ident,commit,elf,dict(sha256=ident['artifactSHA256'])); integer(ident['netNSInode'],netns,netns)
    transcript=raw[stage+'-transcript.json']; digest(v['Transcript']); need(v['Transcript']==sha(transcript))
    need(type(v['Bodies']) is list and len(v['Bodies'])==8)
    phase='candidate' if index==3 else 'baseline'
    originals={G.TRANSCRIPT_NAMES[phase]:transcript}
    for ordinal,name in enumerate(G.BODY_NAMES[phase],1):
        body=raw[stage+f'-body-{ordinal}.json']; need(0<len(body)<=256<<10)
        need(v['Bodies'][ordinal-1]==sha(body)); originals[name]=body
    # Only the prior independent single-capture parser is reused: actual
    # receipt fields and actual originals, no legacy36/full report/PASS label.
    context=dict(getEvidence={phase:dict(sha256=sha(transcript),bytes=len(transcript))},readbacks={phase:v['Readback']})
    recomputed=G._capture(originals,phase,context)
    need(sum(len(raw[stage+'-'+name]) for name in CAPTURE)<=2<<20)
    return dict(receipt=v,observation=o,projection=recomputed,sha256=sha(original),bytes=len(original))


def route_chain(captures):
    prior=None; nonces=set(); hashes=set()
    for i,capture_ in enumerate(captures):
        r=ordered(capture_['receipt']['Route'],A.ROUTE_KEYS)
        role='B' if i==3 else 'A'
        need(r['phase']==('BOOTSTRAP' if i==0 else 'ACKNOWLEDGED_COMPLETION' if i==3 else 'BASELINE') and r['matched'] is True)
        digest(r['nonceSHA256']); need(r['nonceSHA256'] not in nonces); nonces.add(r['nonceSHA256'])
        values=[A.body(r[k]) for k in ('clientResponse','proxyResponse','originResponse')]
        for value in values: ordered(value,A.BODY_KEYS)
        same(values[0],values[1]); same(values[0],values[2])
        need(values[0]['bytes']==len('chengwang-local-service-marker/v1:A:')+65)
        need(values[0]['sha256'] not in hashes); hashes.add(values[0]['sha256'])
        before,after=A.counters(r['countersBefore']),A.counters(r['countersAfter'])
        for row in before+after: ordered(row,A.COUNTER_KEYS)
        if prior is None: need(all(v[k]==0 for v in before for k in A.COUNTER_KEYS[1:]))
        else: same(before,prior)
        for b,a in zip(before,after):
            for k in A.COUNTER_KEYS[1:]:
                delta=1 if (b['role']==role and k in ('connectIngress','tunnelRequests','forwardInvocations','originRequests')) or (b['role']=='origin' and k=='originRequests') else 0
                integer(a[k],b[k]+delta,b[k]+delta)
        prior=after


def ack(value):
    exact(value,TRANSPORT_KEYS); exact(value['result'],('state','dispatched','statusCode'))
    need(value['origin']=='ADAPTER' and value['gateReason'] is None and value['result']['state']=='acknowledged' and value['result']['dispatched'] is True)
    integer(value['result']['statusCode'],204,204); timestamp(value['recordedAt']); return value


def head(value):
    exact(value,HEAD_KEYS); need(value['schema']=='chengwang.mihomo-lab-head-view/v1' and value['boundary']==BOUNDARY)
    for key in ('revision','generation'): integer(value[key],1)
    for key in ('headSHA256','artifactRecordSHA256','configSHA256','verificationSHA256'): digest(value[key])
    timestamp(value['verifiedAt']); need(type(value['writeBlocked']) is bool); proof(value['proof'])
    need(value['activeOperationId'] is None or (type(value['activeOperationId']) is str and ID.fullmatch(value['activeOperationId'])))
    if value['generation']==1: need(value['previousHeadSHA256'] is None)
    else: digest(value['previousHeadSHA256']); need(value['previousHeadSHA256']!=value['headSHA256'])
    return value


def view(value):
    exact(value,VIEW_KEYS); need(value['schema']=='chengwang.mihomo-lab-deployment-view/v1' and value['boundary']==BOUNDARY)
    need(type(value['operationId']) is str and ID.fullmatch(value['operationId']) is not None)
    for key in ('revision','headGeneration'): integer(value[key],1)
    for key in ('planSHA256','candidateRecordSHA256','candidateConfigSHA256','previousHeadSHA256','headSHA256'): digest(value[key])
    timestamp(value['expiresAt']); proof(value['proof'])
    for key in ('writeBlocked','replayed','headAdvanced'): need(type(value[key]) is bool)
    need(value['writeBlocked'] is False)
    if value['phase'] in ('PLANNED','APPROVED'): need(value['transport'] is None and value['observation'] is None and value['headAdvanced'] is False)
    elif value['phase']=='COMPLETED':
        ack(value['transport']); o=exact(value['observation'],('conclusion','observedProjectionSHA256','evidenceSHA256','observedAt','localRouteVerified'))
        need(o['conclusion']=='STABLE_NEW_PROJECTION' and o['localRouteVerified'] is True and value['headAdvanced'] is True)
        digest(o['observedProjectionSHA256']); digest(o['evidenceSHA256']); timestamp(o['observedAt']); integer(value['headGeneration'],2,2)
    else: need(False)
    return value


def envelope(raw,status,changed=False):
    v=ordered(decode(raw),('boundary','code','stateMayHaveChanged','result'))
    need(go_bytes(v)+b'\n'==raw and v['boundary']==BOUNDARY and v['stateMayHaveChanged'] is changed)
    need(v['code']==('mihomo_lab_ok' if status in (200,201) else 'mihomo_lab_unauthenticated' if status==401 else 'mihomo_lab_forbidden'))
    if status not in (200,201): need(v['result'] is None)
    return v['result']


def http(report):
    rows=report['http']; need(type(rows) is list and len(rows)==11)
    roles=('anonymous','viewer','viewer','wrong-scope','admin','admin','admin','admin','approver','admin','admin')
    methods=('GET','GET','POST','POST','POST','GET','GET','POST','POST','POST','POST')
    statuses=(401,200,403,403,None,200,200,403,200,200,200)
    bodies=[]; responses=[]
    for i,row in enumerate(rows):
        exact(row,('sequence','case','role','method','path','requestBody','statusCode','responseBody','errorClass'))
        integer(row['sequence'],i+1,i+1); need((row['case'],row['role'],row['method'])==(HTTP_CASES[i],roles[i],methods[i]))
        req=b64(row['requestBody'],empty=True); bodies.append(decode(req) if req else None)
        if req: need(go_bytes(bodies[-1])==req)
        if i==4:
            need(row['statusCode'] is None and row['responseBody'] is None and row['errorClass']=='RESPONSE_NOT_OBSERVED'); responses.append(None)
        else:
            integer(row['statusCode'],statuses[i],statuses[i]); need(row['errorClass']=='NONE')
            responses.append(envelope(b64(row['responseBody']),statuses[i],statuses[i] in (200,201) and methods[i]=='POST'))
    discovery=head(responses[5]); planned=view(responses[6]); approved=view(responses[8]); completed=view(responses[9]); replayed=view(responses[10])
    operation=planned['operationId']; need(discovery['activeOperationId']==operation and discovery['revision']==planned['revision'])
    need(planned['phase']=='PLANNED' and approved['phase']=='APPROVED' and completed['phase']=='COMPLETED' and replayed['phase']=='COMPLETED')
    need(planned['replayed'] is approved['replayed'] is completed['replayed'] is False and replayed['replayed'] is True)
    for v in (approved,completed,replayed):
        for key in ('operationId','planSHA256','candidateRecordSHA256','candidateConfigSHA256','previousHeadSHA256','expiresAt'): same(v[key],planned[key])
    integer(approved['revision'],planned['revision']+1,planned['revision']+1)
    same([approved['headSHA256'],approved['headGeneration']],[planned['headSHA256'],planned['headGeneration']])
    integer(completed['revision'],approved['revision']+4,approved['revision']+4)
    expected=dict(completed); expected['replayed']=True; same(replayed,expected)
    prefix='/api/v1/lab/mihomo'; paths=('/candidates','/candidates','/deployments','/deployments','/deployments','/head',
        '/deployments/'+operation,'/deployments/'+operation+'/approvals','/deployments/'+operation+'/approvals',
        '/deployments/'+operation+'/execute','/deployments/'+operation+'/execute')
    for row,path in zip(rows,paths): need(row['path']==prefix+path)
    for i in (0,1,5,6): need(bodies[i] is None)
    create=exact(bodies[4],('candidateRecordSHA256','ttlSeconds')); same(create,dict(candidateRecordSHA256=planned['candidateRecordSHA256'],ttlSeconds=300))
    same(bodies[2],create); same(bodies[3],create)
    for i in (7,8): same(bodies[i],dict(planSHA256=planned['planSHA256'],revision=planned['revision']))
    for i in (9,10): same(bodies[i],dict(planSHA256=approved['planSHA256'],revision=approved['revision']))
    candidates=exact(responses[1],('schema','boundary','candidates','writeBlocked','proof'))
    need(candidates['schema']=='chengwang.mihomo-lab-candidates-view/v1' and candidates['boundary']==BOUNDARY and candidates['writeBlocked'] is False); proof(candidates['proof'])
    need(type(candidates['candidates']) is list and len(candidates['candidates'])==2)
    for i,v in enumerate(candidates['candidates']):
        exact(v,('name','recordSHA256','configSHA256','sourceSpecSHA256','isCurrent'))
        need(v['name']==('local-a' if i==0 else 'local-b') and v['isCurrent'] is (i==0))
        for key in ('recordSHA256','configSHA256','sourceSpecSHA256'): digest(v[key])
    need(candidates['candidates'][1]['recordSHA256']==planned['candidateRecordSHA256'])
    drop=exact(report['dropped'],('handlerCompleted','generatedStatus','generatedBody','connectionClosed'))
    need(drop['handlerCompleted'] is True and drop['connectionClosed'] is True); integer(drop['generatedStatus'],201,201)
    same(envelope(b64(drop['generatedBody']),201,True),planned)
    return operation,planned,approved,completed,candidates,discovery


def expected_head(capture_,generation,previous):
    o=capture_['observation']; i=o['StartupIdentity']
    v=dict(schema='chengwang.mihomo-lifecycle-head/v1',deviceRef=o['DeviceRef'],scope=o['Scope'],generation=generation,
        artifact=o['Artifact'],kernelSHA256=i['elfSHA256'],pid=i['pid'],startTicks=i['startTicks'],netNSInode=i['netNSInode'],
        controllerPort=28412,mixedPort=28411,verificationSHA256=capture_['sha256'],verifiedAt=o['ObservedAt'],previousHeadSHA256=previous)
    return sha(go_bytes(v))


def states(report,captures,commit,operation,planned,completed,discovery):
    old_head=expected_head(captures[0],1,None); new_head=expected_head(captures[3],2,old_head)
    for index,key in enumerate(('before','after','replay')):
        v=exact(report[key],STATE_KEYS); need(v['schema']=='chengwang.mihomo-lab-acceptance-state/v1' and v['sourceCommit']==commit and v['walSchema']=='chengwang.mihomo-lifecycle-record/v2')
        digest(v['controlSHA256']); digest(v['recordSHA256']); h=head(v['head'])
        need(v['privateWALValidated'] is True and v['observedProcessMatchesHead'] is True and v['fullPrivateWALIndependentlyProven'] is False and v['production'] is False)
        integer(v['unknownObservationCount'],0,0); same(v['terminated'],[]); need(h['writeBlocked'] is False)
        c=captures[0 if index==0 else 3]; a=c['observation']['Artifact']
        same([h['artifactRecordSHA256'],h['configSHA256'],h['verificationSHA256'],h['verifiedAt']], [a['recordSHA256'],a['config']['sha256'],c['sha256'],c['observation']['ObservedAt']])
        integer(h['generation'],1 if index==0 else 2,1 if index==0 else 2)
        need(h['headSHA256']==(old_head if index==0 else new_head))
        need(h['previousHeadSHA256']==(None if index==0 else old_head))
        if index==0:
            need(v['activeOperationId'] is v['activePhase'] is v['activeIntentSHA256'] is h['activeOperationId'] is None); same(v['completed'],[])
        else:
            need(v['activeOperationId']==h['activeOperationId']==operation and v['activePhase']=='ACKNOWLEDGED_SUPPORTED_POSTCONDITION')
            digest(v['activeIntentSHA256']); need(type(v['completed']) is list and len(v['completed'])==1)
            a=exact(v['completed'][0],('operationId','planSHA256','intentSHA256','phase','headSHA256','generation','commitRevision','committedAt','transport'))
            same([a['operationId'],a['planSHA256'],a['intentSHA256'],a['phase'],a['headSHA256'],a['generation'],a['commitRevision']],
                 [operation,planned['planSHA256'],v['activeIntentSHA256'],v['activePhase'],new_head,2,h['revision']])
            need(timestamp(a['committedAt'])>=timestamp(c['observation']['ObservedAt']))
            same(a['transport'],completed['transport']); integer(h['revision'],completed['revision'],completed['revision'])
    need(planned['previousHeadSHA256']==old_head and completed['headSHA256']==new_head)
    need(planned['headSHA256']==old_head); integer(planned['headGeneration'],1,1)
    expected_discovery=dict(report['before']['head']); expected_discovery.update(revision=planned['revision'],activeOperationId=operation)
    same(discovery,expected_discovery)
    same(report['after'],report['replay'])
    need(report['before']['controlSHA256']!=report['after']['controlSHA256'] and report['before']['recordSHA256']!=report['after']['recordSHA256'])
    return report['after']['activeIntentSHA256']


def journal(raw,report,captures,operation,intent):
    rows=[decode(line) for line in raw['service-journal.jsonl'].splitlines()]
    names=['STARTUP','HEAD_READY','PLANNED','APPROVED','PREPARED','DISPATCH_ARMED','RELOAD_CALL_INTENT','RELOAD_RETURNED','RESULT_RECORDED','COMPLETED','CLEANUP_OBSERVED','CLOSED']
    need(len(rows)==len(names))
    for row,name in zip(rows,names):
        need(row['stage']==name)
        if name=='CLEANUP_OBSERVED':
            exact(row,('stage','kernel','fixtures')); kernel=exact(row['kernel'],('started','waitReturned','waitErrorClass','exitCode','signal','termSent','killSent','groupAbsent','stdout','stderr'))
            need(kernel['started'] is True and kernel['waitReturned'] is True and kernel['groupAbsent'] is True)
            need(type(kernel['termSent']) is bool and type(kernel['killSent']) is bool)
            if kernel['waitErrorClass']=='NONE': integer(kernel['exitCode'],0,0); need(kernel['signal'] is None)
            else:
                need(kernel['waitErrorClass']=='EXIT_STATUS' and kernel['exitCode'] is None)
                need((type(kernel['signal']) is int and kernel['signal']==15 and kernel['termSent'] is True) or (type(kernel['signal']) is int and kernel['signal']==9 and kernel['killSent'] is True))
            A.stream(kernel['stdout'],raw['kernel.stdout']); A.stream(kernel['stderr'],raw['kernel.stderr'])
            fixtures=row['fixtures']; need(type(fixtures) is list and len(fixtures)==3)
            counters={r['role']:r for r in captures[-1]['receipt']['Route']['countersAfter']}
            for role,fixture in zip(('origin','A','B'),fixtures):
                exact(fixture,A.CLEANUP_KEYS); need(fixture['role']==role and fixture['shutdownReturned'] is True and fixture['serveReturned'] is True and fixture['errorClass']=='NONE')
                integer(fixture['forcedConnectionsClosed'],0,0 if role=='origin' else counters[role]['connectIngress'])
        else:
            exact(row,('stage','operationId','intentSHA256','result','walRecorded') if name=='RELOAD_RETURNED' else ('stage','operationId','intentSHA256'))
            need(row['operationId']==('' if name in ('STARTUP','HEAD_READY','CLOSED') else operation))
            need(row['intentSHA256']==(intent if name in ('DISPATCH_ARMED','RELOAD_CALL_INTENT','RELOAD_RETURNED','RESULT_RECORDED','COMPLETED') else ''))
            if name=='RELOAD_RETURNED': same(row['result'],report['after']['completed'][0]['transport']['result']); need(row['walRecorded'] is True)


def verify_raw(raw,sources,commit):
    try:
        need(type(raw) is dict and set(raw)==set(PUBLIC) and len(PUBLIC)==len(set(PUBLIC))==58)
        need(type(sources) is dict and set(sources)==set(FILES) and len(FILES)==len(set(FILES))==154)
        need(type(commit) is str and re.fullmatch('[a-f0-9]{40}',commit) is not None)
        need(all(type(v) is bytes and 0<len(v)<=1<<20 for v in sources.values()))
        need(all(type(v) is bytes for v in raw.values()) and sum(map(len,raw.values()))<=16<<20)
        for name,data in raw.items():
            limit=8<<20 if name=='service.json' else 512<<10 if name=='e2e-report.json' else 64<<10 if name.endswith('verification.json') else 256<<10 if name.endswith(('.json','.jsonl')) else 1<<20
            need(len(data)<=limit)
        need(G.unicodedata.unidata_version==G.UNICODE_VERSION); contract(sources)
        for name in ('gofmt.patch','gofmt.stderr','service.stderr'): need(raw[name]==b'')
        need(raw['go-version.txt']==b'go version go1.23.12 linux/amd64\n')
        e=exact(decode(raw['execution.json']),A.EXECUTION_KEYS)
        need(e['schema']=='chengwang.mihomo-service-execution/v1' and e['sourceCommit']==commit and e['realMihomoExecutionObserved'] is True and e['production'] is False)
        integer(e['formatExit'],0,0); integer(e['goExit'],0,0)
        receipt=raw['consumption.json']; need(receipt==raw['consumption-independent.json']); elf=C.consumption(receipt,sources,commit)
        box=sandbox(raw,sources,commit,elf,receipt); test=events(raw['service.json'])
        report=exact(decode(raw['e2e-report.json']),REPORT_KEYS)
        need(report['schema']=='chengwang.mihomo-service-http-experiment/v1' and report['scope']==SCOPE and report['sourceCommit']==commit and report['outcome']=='PASS' and report['failureCode']=='NONE')
        need(all(report[k] is False for k in ('production','fullPayloadProven','internetBusinessProven')) and report['controllerReceivedCount'] is None)
        need(report['runtimeReturned'] is True and report['runtimeErrorClass']=='NONE')
        caps=[capture(raw,s,i,commit,elf,int(box['networkNamespace'][5:-1])) for i,s in enumerate(STAGES)]
        route_chain(caps); operation,planned,approved,completed,candidates,discovery=http(report)
        old=caps[0]['observation']['Artifact']; new=caps[-1]['observation']['Artifact']
        need(old['recordSHA256']!=new['recordSHA256'] and old['config']['sha256']!=new['config']['sha256'])
        for i,c in enumerate(caps):
            o=c['observation']; same(o['StartupIdentity'],caps[0]['observation']['StartupIdentity']); same(o['Scope'],caps[0]['observation']['Scope'])
            same(o['Artifact'],new if i==3 else old); need(o['StartupIdentity']['artifactSHA256']==old['config']['sha256'])
            need(o['OperationID']==('' if i==0 else operation) and o['PlanSHA256']==(planned['planSHA256'] if i>=2 else ''))
            r=c['receipt']['Readback']; first=caps[0]['receipt']['Readback']
            same([r['previousProjectionSHA256'],r['candidateProjectionSHA256']],[first['previousProjectionSHA256'],first['candidateProjectionSHA256']])
            if i: need(timestamp(o['ObservedAt'])>=timestamp(caps[i-1]['observation']['ObservedAt']))
        for row,a in zip(candidates['candidates'],(old,new)):
            same([row['recordSHA256'],row['configSHA256'],row['sourceSpecSHA256']],[a['recordSHA256'],a['config']['sha256'],a['sourceSpecSHA256']])
        same([planned['candidateRecordSHA256'],planned['candidateConfigSHA256']],[new['recordSHA256'],new['config']['sha256']])
        intent=states(report,caps,commit,operation,planned,completed,discovery)
        need(timestamp(completed['transport']['recordedAt'])<=timestamp(caps[3]['observation']['ObservedAt']))
        for i,c in enumerate(caps): need(c['observation']['IntentSHA256']==(intent if i==3 else ''))
        same(completed['observation'],dict(conclusion='STABLE_NEW_PROJECTION',observedProjectionSHA256=caps[3]['projection']['observedProjectionSHA256'],evidenceSHA256=caps[3]['sha256'],observedAt=caps[3]['observation']['ObservedAt'],localRouteVerified=True))
        for key in ('callsBefore','callsAfter','callsReplay'):
            exact(report[key],('reloadInvocations','doInvocations'))
            for v in report[key].values(): integer(v,0,(1<<64)-2)
        for key in ('reloadInvocations','doInvocations'): need(report['callsAfter'][key]==report['callsBefore'][key]+1)
        same(report['callsReplay'],report['callsAfter'])
        syntax=exact(decode(raw['op-01-syntax.json']),('schema','inputSHA256','inputBytes','observation'))
        need(syntax['schema']=='chengwang.mihomo-lab-service-syntax/v1' and syntax['inputSHA256']==new['config']['sha256']); integer(syntax['inputBytes'],new['config']['bytes'],new['config']['bytes'])
        A.observation(syntax['observation'],raw['op-01-syntax.stdout'],raw['op-01-syntax.stderr'],syntax=True)
        C.safe_stdio('candidate',raw['op-01-syntax.stdout'],raw['op-01-syntax.stderr']); A._kernel_stdio(raw['kernel.stdout'],raw['kernel.stderr'])
        journal(raw,report,caps,operation,intent)
        need(type(report['closedPorts']) is list and len(report['closedPorts'])==5)
        for port,row in zip(range(28411,28416),report['closedPorts']):
            exact(row,('port','connectAttempted','accepted','errorClass')); integer(row['port'],port,port)
            need(row['connectAttempted'] is True and row['accepted'] is False and row['errorClass']=='CONNECTION_REFUSED')
        return dict(schema='chengwang.mihomo-service-verification/v1',sourceCommit=commit,outcome='PASS',scope=SCOPE,tests=test,
            sourceSHA256={p:sha(sources[p]) for p in FILES},inputSHA256={p:sha(raw[p]) for p in PUBLIC},
            captures={s:dict(verificationSHA256=c['sha256'],projection=c['projection']) for s,c in zip(STAGES,caps)},
            publicHTTPResponsesValidated=True,supportedProjectionRecomputeProven=True,oneReloadOneDoDeltaObserved=True,controllerReceivedCount=None,
            currentCredentialContentsIndependentlyProven=False,privateExpectedSourceIndependentlyProven=False,fullPrivateWALIndependentlyProven=False,
            privateDisclosureFenceIndependentlyProven=False,fullPayloadProven=False,internetBusinessProven=False,production=False,sourceGitVerified=False)
    except Exception:
        raise ValueError('isolated service evidence rejected') from None


def source_bindings(repo,commit):
    repo=C.plain(repo); need(type(commit) is str and re.fullmatch('[a-f0-9]{40}',commit))
    def git(*args):
        result=subprocess.run(['git','-c','safe.directory='+str(repo),'-C',str(repo),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        need(result.returncode==0 and len(result.stdout)<=1<<20); return result.stdout
    need(git('rev-parse','HEAD').strip().decode('ascii')==commit and Path(os.fsdecode(git('rev-parse','--show-toplevel').strip())).resolve()==repo)
    need(len(FILES)==len(set(FILES))==154)
    sources={}
    for p in FILES:
        raw=C.read(repo/p,1<<20,False); need(raw==git('show',commit+':'+p)); sources[p]=raw
    for path,name in [(Path(__file__).absolute(),'check_service.py'),(Path(A.__file__).absolute(),'check_apply.py'),(Path(C.__file__).absolute(),'check_compat.py'),(Path(G.__file__).absolute(),'get_projection.py')]:
        need(C.read(path,1<<20,False)==sources[PREFIX+name])
    return sources


def main():
    p=argparse.ArgumentParser()
    for name in ('repo','source-commit','evidence','report'): p.add_argument('--'+name,required=True,type=str if name=='source-commit' else Path)
    a=p.parse_args(); a.repo=C.plain(a.repo); a.evidence=C.plain(a.evidence); a.report=C.plain(a.report,True)
    need(a.report.parent.is_dir() and not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.evidence))
    signature=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink)
    evidence_before=a.evidence.lstat(); need(stat.S_ISDIR(evidence_before.st_mode))
    need({x.name for x in a.evidence.iterdir()}==set(PUBLIC)); sources=source_bindings(a.repo,a.source_commit)
    raw={n:C.read(a.evidence/n,8<<20,True) for n in PUBLIC}; value=verify_raw(raw,sources,a.source_commit)
    need(all(C.read(a.evidence/n,8<<20,True)==b for n,b in raw.items()) and {x.name for x in a.evidence.iterdir()}==set(PUBLIC))
    again=source_bindings(a.repo,a.source_commit); need(all(again[p]==sources[p] for p in FILES))
    need(signature(a.evidence.lstat())==signature(evidence_before))
    value['sourceGitVerified']=True
    need(os.name=='posix' and os.open in os.supports_dir_fd)
    parent_before=a.report.parent.lstat()
    fd=os.open(a.report.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        need(signature(os.fstat(fd))==signature(parent_before)==signature(a.report.parent.lstat()))
        output=os.open(a.report.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        encoded=C.canonical(value)
        with os.fdopen(output,'wb') as handle:
            need(handle.write(encoded)==len(encoded)); handle.flush(); os.fsync(handle.fileno())
        os.fsync(fd)
    finally: os.close(fd)
    print('MIHOMO_SERVICE=PASS public_semantics_recomputed=true private_wal_proof=false production=false')


if __name__=='__main__':
    try:
        main()
    except Exception:
        raise SystemExit('MIHOMO_SERVICE=REJECTED evidence_rejected=true production=false') from None
