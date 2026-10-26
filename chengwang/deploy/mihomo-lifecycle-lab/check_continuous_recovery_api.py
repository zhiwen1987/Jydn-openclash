#!/usr/bin/env python3
"""Fresh verifier for continuous Recovery API originals; executes no Go or kernel."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unicodedata

SCOPE='ACTUAL_ISOLATED_HTTPS_UNKNOWN_RECOVERY_ACK_UNKNOWN_RECOVERY_NOT_PRODUCTION'
BOUNDARY='OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF'
WAL_SCHEMA='chengwang.mihomo-lifecycle-record/v2'
TOP='TestMihomoContinuousRecoveryHTTPSUnknownRecoveryAckUnknownRecovery'
TAGS=('linux','chengwang_mihomo_service','chengwang_mihomo_recovery_native','chengwang_mihomo_recovery_continuous_fault')
FORBIDDEN=('chengwang_mihomo_faults','chengwang_mihomo_completion_native')
COMMANDS=('SANDBOX','GO_VERSION','GOFMT','GO_TEST')
TIMEOUTS=(30,15,45,240)
FMT=(
 'internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
 'internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
 'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
 'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
 'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
 'internal/mihomodeploy/lab_recovery_backend.go','internal/mihomodeploy/lab_service.go','internal/serverruntime/runtime.go',
 'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
 'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
 'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go')
MANIFEST_REL='chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_api_source_policy.json'
MAX_TRACKED=64<<20
COMMIT=re.compile(r'[0-9a-f]{40}'); OID=re.compile(r'[0-9a-f]{40}'); DIGEST=re.compile(r'[0-9a-f]{64}')
DELIVERY=(
 '.github/workflows/chengwang-mihomo-continuous-recovery-api.yml',
 'chengwang/deploy/mihomo-lifecycle-lab/apply_worker.py',
 'chengwang/deploy/mihomo-lifecycle-lab/check_continuous_recovery_api.py',
 'chengwang/deploy/mihomo-lifecycle-lab/compat_worker.py',
 'chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_api_contract.json',MANIFEST_REL,
 'chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_api_worker.py',
 'chengwang/deploy/mihomo-lifecycle-lab/run_continuous_recovery_api.sh',
 'chengwang/deploy/mihomo-lifecycle-lab/test_continuous_recovery_api_model.py',
 'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
 'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
 'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
 'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
 'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
 'chengwang/internal/mihomodeploy/lab_recovery_backend.go',
 'chengwang/internal/mihomodeploy/lab_service.go',
 'chengwang/internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
 'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
 'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
 'chengwang/internal/serverruntime/runtime.go',
 'chengwang/tools/mihomo-runtime-candidate/README.md',
 'chengwang/tools/mihomo-runtime-candidate/check_consumption.py',
 'chengwang/tools/mihomo-runtime-candidate/consume_pin.py',
 'chengwang/tools/mihomo-runtime-candidate/pin.json',
 'chengwang/tools/mihomo-runtime-candidate/test_consume_pin.py')
HTTP_CASES=(
 ('INITIAL_HEAD','viewer','GET','/api/v1/lab/mihomo/head',200),
 ('FIRST_CANDIDATES','viewer','GET','/api/v1/lab/mihomo/candidates',200),
 ('FIRST_UNKNOWN_CREATE','admin','POST','/api/v1/lab/mihomo/deployments',201),
 ('FIRST_UNKNOWN_APPROVE','approver','POST',None,200),('FIRST_UNKNOWN_EXECUTE','admin','POST',None,200),
 ('FIRST_UNKNOWN_INSPECT','viewer','GET',None,200),('FIRST_UNKNOWN_HEAD','viewer','GET','/api/v1/lab/mihomo/head',200),
 ('FIRST_RECOVERY_CREATE','admin','POST','/api/v1/lab/mihomo/recoveries',201),
 ('FIRST_RECOVERY_INSPECT_PLANNED','auditor','GET',None,200),('FIRST_RECOVERY_APPROVE','approver','POST',None,200),
 ('FIRST_RECOVERY_EXECUTE','admin','POST',None,200),('FIRST_RECOVERY_INSPECT_COMPLETED','auditor','GET',None,200),
 ('FIRST_RECOVERED_HEAD','viewer','GET','/api/v1/lab/mihomo/head',200),
 ('ACK_CANDIDATES','viewer','GET','/api/v1/lab/mihomo/candidates',200),
 ('ORDINARY_ACK_CREATE','admin','POST','/api/v1/lab/mihomo/deployments',201),
 ('ORDINARY_ACK_APPROVE','approver','POST',None,200),('ORDINARY_ACK_EXECUTE','admin','POST',None,200),
 ('ORDINARY_ACK_INSPECT','viewer','GET',None,200),('ORDINARY_ACK_HEAD','viewer','GET','/api/v1/lab/mihomo/head',200),
 ('SECOND_CANDIDATES','viewer','GET','/api/v1/lab/mihomo/candidates',200),
 ('SECOND_UNKNOWN_CREATE','admin','POST','/api/v1/lab/mihomo/deployments',201),
 ('SECOND_UNKNOWN_APPROVE','approver','POST',None,200),('SECOND_UNKNOWN_EXECUTE','admin','POST',None,200),
 ('SECOND_UNKNOWN_INSPECT','viewer','GET',None,200),('SECOND_UNKNOWN_HEAD','viewer','GET','/api/v1/lab/mihomo/head',200),
 ('SECOND_RECOVERY_CREATE','admin','POST','/api/v1/lab/mihomo/recoveries',201),
 ('SECOND_RECOVERY_INSPECT_PLANNED','auditor','GET',None,200),('SECOND_RECOVERY_APPROVE','approver','POST',None,200),
 ('SECOND_RECOVERY_EXECUTE','admin','POST',None,200),('SECOND_RECOVERY_INSPECT_COMPLETED','auditor','GET',None,200),
 ('SECOND_RECOVERED_HEAD','viewer','GET','/api/v1/lab/mihomo/head',200))

def need(value):
    if not value: raise ValueError('continuous Recovery independent verification rejected')
def canonical(value): return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def integer(value,minimum=0,maximum=(1<<63)-1): need(type(value) is int and minimum<=value<=maximum); return value
def boolean(value): need(type(value) is bool); return value
def text(value,pattern=None,limit=4096):
    need(type(value) is str and len(value)<=limit and (pattern is None or re.fullmatch(pattern,value))); return value
def keys(value,names): need(type(value) is dict and set(value)==set(names)); return value
def exact(a,b):
    need(type(a) is type(b))
    if type(b) is dict:
        need(set(a)==set(b))
        for k in b: exact(a[k],b[k])
    elif type(b) in (list,tuple):
        need(len(a)==len(b))
        for x,y in zip(a,b): exact(x,y)
    else: need(a==b)
    return a
def source_file(path,limit=2<<20,empty=False):
    path=Path(path).absolute()
    for item in (*reversed(path.parents),path):
        info=item.lstat(); need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&1024)
    before=path.lstat(); need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit and (empty or before.st_size>0))
    raw=path.read_bytes(); after=path.lstat(); sig=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns)
    need(sig(before)==sig(after) and len(raw)==before.st_size); return raw
def set_digest(schema,entries): return sha(canonical({'schema':schema,'entries':entries}))

def policy(repo):
    raw=source_file(Path(repo)/MANIFEST_REL,64<<10); value=json.loads(raw); need(canonical(value)+b'\n'==raw)
    need(value['schema']=='chengwang.mihomo-continuous-recovery-source-policy/v1' and value['deliveryPaths']==list(DELIVERY) and
         value['trackedSet']=='ALL_GIT_HEAD_BLOBS' and value['maxTrackedFileBytes']==MAX_TRACKED and
         all(value[key] is True for key in ('generatedManifestIsPrivate','rejectCaseFoldCollisions','rejectDirtyIndexOrWorktree','rejectHardlinks','rejectSymlinks')))
    return raw

def git_manifest(repo,supplied):
    repo=Path(repo).resolve(strict=True); need(COMMIT.fullmatch(supplied))
    def git(*args,limit=8<<20):
        r=subprocess.run(['git','-C',str(repo),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        need(r.returncode==0 and len(r.stdout)<=limit and len(r.stderr)<=1<<20); return r.stdout
    head=git('rev-parse','HEAD').strip().decode(); treeoid=git('rev-parse','HEAD^{tree}').strip().decode(); indexoid=git('write-tree').strip().decode()
    need(head==supplied and treeoid==indexoid and Path(os.fsdecode(git('rev-parse','--show-toplevel').strip())).resolve()==repo and git('status','--porcelain=v1','--untracked-files=all')==b'')
    tree={}; folded=set()
    for row in git('ls-tree','-r','-z','--full-tree',head).split(b'\0'):
        if not row: continue
        meta,name=row.split(b'\t',1); mode,kind,oid=meta.split(); path=name.decode(); fold=unicodedata.normalize('NFC',path).casefold()
        need(path not in tree and fold not in folded and mode in (b'100644',b'100755') and kind==b'blob' and OID.fullmatch(oid.decode()))
        need(not path.startswith('/') and '\\' not in path and '..' not in Path(path).parts); tree[path]=(mode.decode(),oid.decode()); folded.add(fold)
    index={}
    for row in git('ls-files','--stage','-z').split(b'\0'):
        if not row: continue
        meta,name=row.split(b'\t',1); mode,oid,stage=meta.split(); path=name.decode(); need(stage==b'0' and path in tree and path not in index); index[path]=(mode.decode(),oid.decode())
    need(tree==index and set(DELIVERY).issubset(tree)); entries=[]
    for path,(mode,oid) in tree.items():
        raw=source_file(repo/path,MAX_TRACKED); need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==oid)
        if os.name=='posix': need(bool((repo/path).lstat().st_mode&0o111)==(mode=='100755'))
        entries.append({'path':path,'mode':mode,'gitBlob':oid,'bytes':len(raw),'sha256':sha(raw)})
    by={r['path']:r for r in entries}; deliveries=[by[p] for p in DELIVERY]; pr=policy(repo)
    value={'schema':'chengwang.mihomo-continuous-recovery-fulltracked-manifest/v1','sourceCommit':head,'sourceTree':treeoid,'indexTree':indexoid,
      'policySHA256':sha(pr),'entryCount':len(entries),'entries':entries,'deliveries':deliveries,
      'sourceSetSHA256':set_digest('chengwang.mihomo-continuous-recovery-fulltracked-set/v1',entries),
      'deliverySetSHA256':set_digest('chengwang.mihomo-continuous-recovery-delivery-set/v1',deliveries)}
    raw=canonical(value)+b'\n'; binding={'schema':'chengwang.mihomo-continuous-recovery-source-binding/v1','sourceCommit':head,
      'sourceTree':treeoid,'indexTree':indexoid,'sourceManifestSHA256':sha(raw),'sourceSetSHA256':value['sourceSetSHA256'],
      'deliverySetSHA256':value['deliverySetSHA256'],'policySHA256':value['policySHA256'],'sourceCount':len(entries),'deliveryCount':len(deliveries)}
    return binding,raw

def json_file(path,limit=2<<20):
    raw=source_file(path,limit); value=json.loads(raw); need(canonical(value)+b'\n'==raw); return value,raw
def json_lines(path,limit=2<<20):
    raw=source_file(path,limit); need(raw.endswith(b'\n')); rows=[]
    for line in raw.splitlines(): value=json.loads(line); need(canonical(value)==line); rows.append(value)
    return rows,raw
def digest(value): text(value,r'[0-9a-f]{64}',64); return value
def timestamp(value): text(value,r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z',64); return value
def proof(value): keys(value,('fullPayloadProven','internetBusinessProven','production')); need(all(boolean(x) is False for x in value.values()))

def view_head(value):
    keys(value,('schema','boundary','revision','generation','headSHA256','previousHeadSHA256','artifactRecordSHA256','configSHA256','verificationSHA256','verifiedAt','activeOperationId','writeBlocked','proof'))
    need(value['schema']=='chengwang.mihomo-lab-head-view/v1' and value['boundary']==BOUNDARY)
    integer(value['revision'],1); integer(value['generation'],1); digest(value['headSHA256']); digest(value['artifactRecordSHA256']); digest(value['configSHA256']); digest(value['verificationSHA256']); timestamp(value['verifiedAt']); boolean(value['writeBlocked']); proof(value['proof'])
    need(value['previousHeadSHA256'] is None or DIGEST.fullmatch(value['previousHeadSHA256'])); need(value['activeOperationId'] is None or type(value['activeOperationId']) is str)
def deployment(value):
    keys(value,('schema','boundary','operationId','phase','revision','planSHA256','candidateRecordSHA256','candidateConfigSHA256','previousHeadSHA256','headSHA256','headGeneration','expiresAt','transport','observation','writeBlocked','replayed','headAdvanced','proof'))
    need(value['schema']=='chengwang.mihomo-lab-deployment-view/v1' and value['boundary']==BOUNDARY and value['replayed'] is False)
    text(value['operationId'],limit=128); digest(value['planSHA256']); digest(value['candidateRecordSHA256']); digest(value['candidateConfigSHA256']); digest(value['previousHeadSHA256']); digest(value['headSHA256']); integer(value['revision'],1); integer(value['headGeneration'],1); timestamp(value['expiresAt'])
    for k in ('writeBlocked','replayed','headAdvanced'): boolean(value[k])
    proof(value['proof'])
    if value['transport'] is not None:
        transport=keys(value['transport'],('result','recordedAt','origin','gateReason')); timestamp(transport['recordedAt']); need(transport['origin']=='ADAPTER' and transport['gateReason'] is None)
        result=keys(transport['result'],('state','dispatched','statusCode')); need(result['state'] in ('acknowledged','unknown') and result['dispatched'] is True); integer(result['statusCode'],0,599)
    if value['observation'] is not None:
        observation=keys(value['observation'],('conclusion','observedProjectionSHA256','evidenceSHA256','observedAt','localRouteVerified'))
        text(observation['conclusion'],limit=128); need(observation['observedProjectionSHA256'] is None or DIGEST.fullmatch(observation['observedProjectionSHA256'])); digest(observation['evidenceSHA256']); timestamp(observation['observedAt']); need(observation['localRouteVerified'] is True)
    if value['phase'] in ('PLANNED','APPROVED'):
        need(value['transport'] is None and value['observation'] is None and value['writeBlocked'] is False and value['headAdvanced'] is False and value['headSHA256']==value['previousHeadSHA256'])
    elif value['phase']=='UNKNOWN':
        need(value['transport'] is not None and value['observation'] is not None and value['writeBlocked'] is True and value['headAdvanced'] is False and value['headSHA256']==value['previousHeadSHA256'])
    elif value['phase']=='COMPLETED':
        need(value['transport'] is not None and value['observation'] is not None and value['writeBlocked'] is False and value['headAdvanced'] is True and value['headSHA256']!=value['previousHeadSHA256'])
    else: need(False)
def recovery(value, phase=None):
    keys(value,('schema','boundary','recoveryId','phase','revision','planSHA256','unknownOperationId','originalPlanSHA256','previousHeadSHA256','headSHA256','headGeneration','targetArtifactRecordSHA256','targetConfigSHA256','expiresAt','writeBlocked','replayed','headAdvanced','proof'))
    need(value['schema']=='chengwang.mihomo-lab-recovery-view/v2' and value['boundary']==BOUNDARY and value['replayed'] is False)
    if phase is not None: need(value['phase']==phase)
    for k in ('planSHA256','originalPlanSHA256','previousHeadSHA256','headSHA256','targetArtifactRecordSHA256','targetConfigSHA256'): digest(value[k])
    integer(value['revision'],1); integer(value['headGeneration'],1); timestamp(value['expiresAt']); boolean(value['writeBlocked']); boolean(value['headAdvanced']); proof(value['proof'])
    text(value['recoveryId'],limit=128); text(value['unknownOperationId'],limit=128)
    if value['phase'] in ('PLANNED','APPROVED'):
        need(value['writeBlocked'] is True and value['headAdvanced'] is False and value['headSHA256']==value['previousHeadSHA256'])
    elif value['phase']=='COMPLETED':
        need(value['writeBlocked'] is False and value['headAdvanced'] is True and value['headSHA256']!=value['previousHeadSHA256'])
    else: need(False)

def candidate_list(value):
    keys(value,('schema','boundary','candidates','writeBlocked','proof'))
    need(value['schema']=='chengwang.mihomo-lab-candidates-view/v1' and value['boundary']==BOUNDARY and value['writeBlocked'] is False)
    boolean(value['writeBlocked']); proof(value['proof']); rows=value['candidates']
    need(type(rows) is list and len(rows)==2); current=[]
    for index,row in enumerate(rows):
        keys(row,('name','recordSHA256','configSHA256','sourceSpecSHA256','isCurrent'))
        need(row['name']==('local-a' if index==0 else 'local-b')); digest(row['recordSHA256']); digest(row['configSHA256']); digest(row['sourceSpecSHA256']); boolean(row['isCurrent'])
        if row['isCurrent']: current.append(index)
    need(len(current)==1 and rows[0]['recordSHA256']!=rows[1]['recordSHA256'] and rows[0]['configSHA256']!=rows[1]['configSHA256'])
    return rows[current[0]],rows[1-current[0]]

def initial_acceptance(value,commit):
    keys(value,('schema','sourceCommit','walSchema','controlSHA256','recordSHA256','head','activeOperationId','activePhase','activeIntentSHA256','completed','terminated','unknownObservationCount','privateWALValidated','fullPrivateWALIndependentlyProven','observedProcessMatchesHead','production'))
    need(value['schema']=='chengwang.mihomo-lab-acceptance-state/v1' and value['sourceCommit']==commit and value['walSchema']==WAL_SCHEMA)
    digest(value['controlSHA256']); digest(value['recordSHA256']); view_head(value['head']); integer(value['unknownObservationCount'])
    need(value['activeOperationId'] is None and value['activePhase'] is None and value['activeIntentSHA256'] is None and value['completed']==[] and value['terminated']==[])
    need(value['privateWALValidated'] is True and value['fullPrivateWALIndependentlyProven'] is False and value['observedProcessMatchesHead'] is True and value['production'] is False)

def envelope(raw,method):
    value=json.loads(raw); keys(value,('boundary','code','stateMayHaveChanged','result'))
    need(value['boundary']==BOUNDARY and value['code']=='mihomo_lab_ok' and value['stateMayHaveChanged'] is (method=='POST') and type(value['result']) is dict)
    return value['result']

def validate_http(report,public):
    rows=report['http']; need(type(rows) is list and len(rows)==len(HTTP_CASES)==31); results={}; index=[]
    for i,(row,want) in enumerate(zip(rows,HTTP_CASES),1):
        keys(row,('sequence','case','role','method','path','requestBodySHA256','statusCode','responseBodySHA256','responseBodyB64','errorClass'))
        case,role,method,path,status=want
        integer(row['sequence'],1,31); integer(row['statusCode'],100,599)
        need(row['sequence']==i and row['case']==case and row['role']==role and row['method']==method and row['statusCode']==status and row['errorClass']=='NONE')
        if path is not None: need(row['path']==path)
        text(row['path'],r'/api/v1/lab/mihomo/[A-Za-z0-9_./-]+',512); digest(row['requestBodySHA256']); digest(row['responseBodySHA256'])
        if method=='GET': need(row['requestBodySHA256']==sha(b''))
        body=base64.b64decode(text(row['responseBodyB64'],limit=1<<16),validate=True); need(body and len(body)<=16<<10 and sha(body)==row['responseBodySHA256'])
        name=f'http-{i:03d}.response.json'; need(source_file(public/name,16<<10)==body); results[case]=envelope(body,method)
        index.append({'sequence':i,'case':case,'role':role,'method':method,'path':row['path'],'statusCode':status,'bytes':len(body),'sha256':sha(body),'name':name})
    # Dynamic paths are derived from the actual IDs returned by earlier responses.
    for prefix in ('FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'):
        op=results[prefix+'_CREATE']['operationId']; base='/api/v1/lab/mihomo/deployments/'+op
        need(rows[[x[0] for x in HTTP_CASES].index(prefix+'_APPROVE')]['path']==base+'/approvals' and rows[[x[0] for x in HTTP_CASES].index(prefix+'_EXECUTE')]['path']==base+'/execute' and rows[[x[0] for x in HTTP_CASES].index(prefix+'_INSPECT')]['path']==base)
    for prefix in ('FIRST_RECOVERY','SECOND_RECOVERY'):
        rid=results[prefix+'_CREATE']['recoveryId']; base='/api/v1/lab/mihomo/recoveries/'+rid
        need(rows[[x[0] for x in HTTP_CASES].index(prefix+'_INSPECT_PLANNED')]['path']==base and rows[[x[0] for x in HTTP_CASES].index(prefix+'_APPROVE')]['path']==base+'/approvals' and rows[[x[0] for x in HTTP_CASES].index(prefix+'_EXECUTE')]['path']==base+'/execute' and rows[[x[0] for x in HTTP_CASES].index(prefix+'_INSPECT_COMPLETED')]['path']==base)
    return results,index

def fault(value,state):
    keys(value,('schema','state','boundOperations','observedResults','initialCore','recoveredCore','nativeCallsBounded','nativeCalls','recoveryCreatesBounded','recoveryCreates','transport'))
    need(value['schema']=='chengwang.mihomo-continuous-recovery-response-loss/v1' and value['state']==state and value['boundOperations']==value['observedResults']==3 and value['nativeCallsBounded'] is True and value['recoveryCreatesBounded'] is True)
    integer(value['initialCore'],1); integer(value['recoveredCore'],1); need(value['initialCore']!=value['recoveredCore'])
    calls=value['nativeCalls']; need(type(calls) is list and calls)
    zero={'RECOVERY_START_DISPATCH','SYNTAX_OS_START_ATTEMPT','SYNTAX_OS_START_RETURN'}
    positive={'KERNEL_OS_START_ATTEMPT','KERNEL_OS_START_RETURN','KERNEL_OS_WAIT_ENTER','KERNEL_OS_WAIT_RETURN','OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_KILL_ATTEMPT','KERNEL_OS_KILL_RETURN','RECOVERY_STOP_DISPATCH'}
    first=None
    for offset,call in enumerate(calls):
        keys(call,('sequence','kind','core','at')); sequence=integer(call['sequence'],1); need(call['kind'] in zero|positive)
        if first is None: first=sequence
        need(sequence==first+offset); integer(call['core'],0,0) if call['kind'] in zero else integer(call['core'],1); timestamp(call['at'])
    creates=value['recoveryCreates']; need(type(creates) is list and len(creates)==4)
    for i,create in enumerate(creates,1):
        keys(create,('sequence','stage')); need(create['sequence']==i and create['stage']==('ENTERED' if i in (1,3) else 'ACCEPTED'))
    transport=value['transport']; keys(transport,('schema','state','boundChildren','underlyingRoundTrips','injected','steps'))
    need(transport['schema']=='chengwang.mihomo-reload-response-loss-schedule/v1' and transport['state']==state and transport['boundChildren']==transport['underlyingRoundTrips']==3 and transport['injected']==2 and len(transport['steps'])==3)
    for i,step in enumerate(transport['steps'],1):
        keys(step,('sequence','action','state','underlyingRoundTrips','statusCode','bodyBytes','eofObserved','closeSucceeded','injected','failureCode'))
        loss=i!=2; need(step['sequence']==i and step['action']==('LOSS' if loss else 'PASS') and step['state']==('INJECTED' if loss else 'PASSTHROUGH') and step['underlyingRoundTrips']==1 and step['statusCode']==204 and step['bodyBytes']==0 and step['eofObserved'] is True and step['closeSucceeded'] is True and step['injected'] is loss and step['failureCode'] is None)
    return calls

def validate_report(report,commit,public,binding):
    keys(report,('schema','scope','sourceCommit','outcome','failureCode','http','initial','heads','operations','recoveries','callsBefore','callsAfter','faultBeforeCleanup','faultAfterCleanup','faultClosed','closedPorts','runtimeReturned','runtimeErrorClass','privateWALDecodedByTest','production','fullPayloadProven','internetBusinessProven'))
    need(report['schema']=='chengwang.mihomo-continuous-recovery-http-experiment/v1' and report['scope']==SCOPE and report['sourceCommit']==commit and report['outcome']=='PASS' and report['failureCode']=='NONE')
    need(report['runtimeReturned'] is True and report['runtimeErrorClass']=='NONE' and all(report[k] is False for k in ('privateWALDecodedByTest','production','fullPayloadProven','internetBusinessProven')))
    initial_acceptance(report['initial'],commit)
    results,index=validate_http(report,public)
    candidates={candidate: candidate_list(results[candidate+'_CANDIDATES']) for candidate in ('FIRST','ACK','SECOND')}
    for candidate,prefix in (('FIRST','FIRST_UNKNOWN'),('ACK','ORDINARY_ACK'),('SECOND','SECOND_UNKNOWN')):
        target=candidates[candidate][1]
        need(results[prefix+'_CREATE']['candidateRecordSHA256']==target['recordSHA256'] and results[prefix+'_CREATE']['candidateConfigSHA256']==target['configSHA256'])
    heads=report['heads']; need([x.get('stage') for x in heads]==['INITIAL','FIRST_UNKNOWN','FIRST_RECOVERED','ORDINARY_ACK','SECOND_UNKNOWN','SECOND_RECOVERED'])
    for item in heads: keys(item,('stage','view')); view_head(item['view'])
    hv=[x['view'] for x in heads]
    for candidate,stable in (('FIRST',hv[0]),('ACK',hv[2]),('SECOND',hv[3])):
        current=candidates[candidate][0]
        need(current['recordSHA256']==stable['artifactRecordSHA256'] and current['configSHA256']==stable['configSHA256'])
    ops=report['operations']; need([x.get('stage') for x in ops]==['FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'])
    for item in ops: keys(item,('stage','view')); deployment(item['view'])
    need([x['view']['phase'] for x in ops]==['UNKNOWN','COMPLETED','UNKNOWN'] and [x['view']['writeBlocked'] for x in ops]==[True,False,True] and [x['view']['headAdvanced'] for x in ops]==[False,True,False])
    for item,state,status in zip(ops,('unknown','acknowledged','unknown'),(0,204,0)):
        need(item['view']['transport'] is not None and item['view']['transport']['result']=={'state':state,'dispatched':True,'statusCode':status} and item['view']['observation'] is not None)
    rec=report['recoveries']; need([x.get('stage') for x in rec]==['FIRST_RECOVERY','SECOND_RECOVERY'])
    for item in rec: keys(item,('stage','view')); recovery(item['view'],'COMPLETED'); need(item['view']['writeBlocked'] is False and item['view']['headAdvanced'] is True)
    # HTTP originals, retained report views, and generation/head chain must agree.
    for stage in ('FIRST_UNKNOWN','ORDINARY_ACK','SECOND_UNKNOWN'): exact(next(x['view'] for x in ops if x['stage']==stage),results[stage+'_INSPECT'])
    for stage in ('FIRST_RECOVERY','SECOND_RECOVERY'): exact(next(x['view'] for x in rec if x['stage']==stage),results[stage+'_INSPECT_COMPLETED'])
    for item in heads: exact(item['view'],results[item['stage']+'_HEAD'])
    exact(report['initial']['head'],heads[0]['view'])
    for prefix,final_phase,stable,final in (('FIRST_UNKNOWN','UNKNOWN',hv[0],hv[0]),('ORDINARY_ACK','COMPLETED',hv[2],hv[3]),('SECOND_UNKNOWN','UNKNOWN',hv[3],hv[3])):
        created,approved,executed,inspected=(results[prefix+'_'+suffix] for suffix in ('CREATE','APPROVE','EXECUTE','INSPECT'))
        deployment(created); deployment(approved); deployment(executed); deployment(inspected)
        need(created['phase']=='PLANNED' and approved['phase']=='APPROVED' and executed['phase']==final_phase and
             created['operationId']==approved['operationId']==executed['operationId']==inspected['operationId'] and
             created['planSHA256']==approved['planSHA256']==executed['planSHA256']==inspected['planSHA256'] and
             created['candidateRecordSHA256']==approved['candidateRecordSHA256']==executed['candidateRecordSHA256']==inspected['candidateRecordSHA256'] and
             created['candidateConfigSHA256']==approved['candidateConfigSHA256']==executed['candidateConfigSHA256']==inspected['candidateConfigSHA256'] and
             created['previousHeadSHA256']==approved['previousHeadSHA256']==executed['previousHeadSHA256']==inspected['previousHeadSHA256'] and
             created['previousHeadSHA256']==stable['headSHA256'] and
             created['headSHA256']==approved['headSHA256']==stable['headSHA256'] and
             created['headGeneration']==approved['headGeneration']==stable['generation'] and
             executed['headSHA256']==inspected['headSHA256']==final['headSHA256'] and
             executed['headGeneration']==inspected['headGeneration']==final['generation'] and
             created['revision']<approved['revision']<executed['revision'] and inspected['revision']==executed['revision'])
        exact(executed,inspected)
    for prefix,unknown_prefix,stable,final in (('FIRST_RECOVERY','FIRST_UNKNOWN',hv[0],hv[2]),('SECOND_RECOVERY','SECOND_UNKNOWN',hv[3],hv[5])):
        planned,planned_read,approved,completed,completed_read=(results[prefix+'_'+suffix] for suffix in ('CREATE','INSPECT_PLANNED','APPROVE','EXECUTE','INSPECT_COMPLETED'))
        recovery(planned,'PLANNED'); recovery(planned_read,'PLANNED'); recovery(approved,'APPROVED'); recovery(completed,'COMPLETED'); recovery(completed_read,'COMPLETED')
        need(planned['recoveryId']==planned_read['recoveryId']==approved['recoveryId']==completed['recoveryId']==completed_read['recoveryId'] and
             planned['planSHA256']==planned_read['planSHA256']==approved['planSHA256']==completed['planSHA256']==completed_read['planSHA256'] and
             planned['unknownOperationId']==planned_read['unknownOperationId']==approved['unknownOperationId']==completed['unknownOperationId']==completed_read['unknownOperationId']==results[unknown_prefix+'_INSPECT']['operationId'] and
             planned['originalPlanSHA256']==planned_read['originalPlanSHA256']==approved['originalPlanSHA256']==completed['originalPlanSHA256']==completed_read['originalPlanSHA256']==results[unknown_prefix+'_INSPECT']['planSHA256'] and
             planned['previousHeadSHA256']==planned_read['previousHeadSHA256']==approved['previousHeadSHA256']==completed['previousHeadSHA256']==completed_read['previousHeadSHA256'] and
             planned['previousHeadSHA256']==stable['headSHA256'] and
             planned['headSHA256']==planned_read['headSHA256']==approved['headSHA256']==stable['headSHA256'] and
             planned['headGeneration']==planned_read['headGeneration']==approved['headGeneration']==stable['generation'] and
             completed['headSHA256']==completed_read['headSHA256']==final['headSHA256'] and
             completed['headGeneration']==completed_read['headGeneration']==final['generation'] and
             planned['targetArtifactRecordSHA256']==planned_read['targetArtifactRecordSHA256']==approved['targetArtifactRecordSHA256']==completed['targetArtifactRecordSHA256']==completed_read['targetArtifactRecordSHA256'] and
             planned['targetConfigSHA256']==planned_read['targetConfigSHA256']==approved['targetConfigSHA256']==completed['targetConfigSHA256']==completed_read['targetConfigSHA256'] and
             planned_read['revision']==planned['revision'] and planned['revision']<approved['revision']<completed['revision'] and completed_read['revision']==completed['revision'])
        exact(planned,planned_read); exact(completed,completed_read)
    need(hv[0]['activeOperationId'] is None and hv[1]['activeOperationId']==ops[0]['view']['operationId'] and hv[2]['activeOperationId'] is None and hv[3]['activeOperationId']==ops[1]['view']['operationId'] and hv[4]['activeOperationId']==ops[2]['view']['operationId'] and hv[5]['activeOperationId'] is None)
    for blocked,stable in ((hv[1],hv[0]),(hv[4],hv[3])):
        need(blocked['generation']==stable['generation'] and blocked['headSHA256']==stable['headSHA256'] and blocked['previousHeadSHA256']==stable['previousHeadSHA256'] and blocked['artifactRecordSHA256']==stable['artifactRecordSHA256'] and blocked['configSHA256']==stable['configSHA256'] and blocked['verificationSHA256']==stable['verificationSHA256'] and blocked['verifiedAt']==stable['verifiedAt'] and blocked['writeBlocked'] is True)
    for published,previous,artifact,config,source in ((hv[2],hv[0],rec[0]['view']['targetArtifactRecordSHA256'],rec[0]['view']['targetConfigSHA256'],rec[0]['view']),
                                                      (hv[3],hv[2],ops[1]['view']['candidateRecordSHA256'],ops[1]['view']['candidateConfigSHA256'],ops[1]['view']),
                                                      (hv[5],hv[3],rec[1]['view']['targetArtifactRecordSHA256'],rec[1]['view']['targetConfigSHA256'],rec[1]['view'])):
        need(published['generation']==previous['generation']+1 and published['previousHeadSHA256']==previous['headSHA256'] and published['headSHA256']==source['headSHA256'] and published['headSHA256']!=previous['headSHA256'] and published['artifactRecordSHA256']==artifact and published['configSHA256']==config and published['writeBlocked'] is False)
    need(ops[0]['view']['previousHeadSHA256']==hv[0]['headSHA256'] and ops[0]['view']['headSHA256']==hv[0]['headSHA256'] and ops[0]['view']['headGeneration']==hv[0]['generation'])
    need(rec[0]['view']['previousHeadSHA256']==hv[0]['headSHA256'] and rec[0]['view']['headGeneration']==hv[2]['generation'])
    need(rec[0]['view']['targetArtifactRecordSHA256']==ops[0]['view']['candidateRecordSHA256'] and rec[0]['view']['targetConfigSHA256']==ops[0]['view']['candidateConfigSHA256'])
    need(ops[1]['view']['previousHeadSHA256']==hv[2]['headSHA256'] and ops[1]['view']['headGeneration']==hv[3]['generation'])
    need(ops[2]['view']['previousHeadSHA256']==hv[3]['headSHA256'] and ops[2]['view']['headSHA256']==hv[3]['headSHA256'] and ops[2]['view']['headGeneration']==hv[3]['generation'])
    need(rec[1]['view']['previousHeadSHA256']==hv[3]['headSHA256'] and rec[1]['view']['headGeneration']==hv[5]['generation'])
    need(rec[1]['view']['targetArtifactRecordSHA256']==ops[2]['view']['candidateRecordSHA256'] and rec[1]['view']['targetConfigSHA256']==ops[2]['view']['candidateConfigSHA256'])
    before=keys(report['callsBefore'],('reloadInvocations','doInvocations')); after=keys(report['callsAfter'],('reloadInvocations','doInvocations'))
    for k in before: integer(before[k]); integer(after[k]); need(after[k]==before[k]+3)
    pre=fault(report['faultBeforeCleanup'],'TERMINAL'); post=fault(report['faultAfterCleanup'],'TERMINAL'); closed=fault(report['faultClosed'],'CLOSED')
    need(post[:len(pre)]==pre and closed==post and len(post)>len(pre)); tail={x['kind'] for x in post[len(pre):]}
    need({'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_WAIT_RETURN'}<=tail)
    ports=report['closedPorts']; need(type(ports) is list and len(ports)==6)
    for row in ports:
        keys(row,('port','connectAttempted','accepted','errorClass')); integer(row['port'],1,65535); need(row['connectAttempted'] is True and row['accepted'] is False and row['errorClass']=='CONNECTION_REFUSED')
    need([row['port'] for row in ports[:5]]==[28411,28412,28413,28414,28415] and ports[5]['port'] not in {28411,28412,28413,28414,28415})
    return index

def command_argv(row,index,binding,commit):
    argv=row['argv']; need(type(argv) is list and all(type(x) is str for x in argv))
    if index==0:
        need(Path(argv[0]).name=='python3')
        exact(argv[1:],['-B','/tmp/mihomo-apply-source/deploy/mihomo-lifecycle-lab/continuous_recovery_api_worker.py','--sandbox',commit,
          binding['sourceTree'],binding['indexTree'],binding['sourceManifestSHA256'],binding['sourceSetSHA256'],binding['deliverySetSHA256'],binding['policySHA256'],str(binding['sourceCount']),str(binding['deliveryCount'])])
    elif index==1: exact(argv,['/tmp/mihomo-apply-go/bin/go','version'])
    elif index==2: exact(argv,['/tmp/mihomo-apply-go/bin/gofmt','-d',*FMT])
    else: exact(argv,['/tmp/mihomo-apply-go/bin/go','test','-json','-count=1','-shuffle=off','-p=1','-tags='+','.join(TAGS),'-run=^'+TOP+'$','-timeout=210s','./internal/serverruntime'])

def verify(repo,public,commit):
    binding,_=git_manifest(repo,commit); public=Path(public).resolve(strict=True)
    contract,contract_raw=json_file(Path(repo)/'chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_api_contract.json',64<<10)
    need(contract['schema']=='chengwang.mihomo-continuous-recovery-contract/v1' and contract['scope']==SCOPE and contract['exactTags']==list(TAGS) and contract['forbiddenTags']==list(FORBIDDEN) and contract['goPackage']=='./internal/serverruntime' and contract['topTest']==TOP and contract['goTimeoutSeconds']==210 and contract['outerGoTimeoutSeconds']==240 and contract['httpOriginalBytesRequired'] is True and contract['fullPrivateWALIndependentlyProven'] is False and contract['internetBusinessProven'] is False and contract['production'] is False)
    build=b'//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native\n'
    default=b'//go:build !linux || !chengwang_mihomo_service || !chengwang_mihomo_recovery_native || !chengwang_mihomo_recovery_continuous_fault || chengwang_mihomo_faults || chengwang_mihomo_completion_native\n'
    for rel in ('chengwang/internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go','chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_linux.go'):
        need(source_file(Path(repo)/rel,2<<20).startswith(build))
    need(source_file(Path(repo)/'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_default.go',64<<10).startswith(default))
    fixed={'host-before.json','host-after.json','consumption.json','consumption-independent.json','sandbox.json','go-version.txt','gofmt.patch','gofmt.stderr','continuous.json','continuous.stderr','commands.jsonl','process-events.jsonl','execution.json','continuous-recovery-report.json','http-originals-index.json','private-fsync-receipts.json','kernel.stdout','kernel.stderr'}
    expected=fixed|{f'http-{i:03d}.response.json' for i in range(1,32)}; need({p.name for p in public.iterdir()}==expected)
    report,raw=json_file(public/'continuous-recovery-report.json'); index=validate_report(report,commit,public,binding)
    actual_index,_=json_file(public/'http-originals-index.json'); keys(actual_index,('schema','scope','sourceCommit','sourceBinding','entries','production'))
    need(actual_index['schema']=='chengwang.mihomo-continuous-recovery-http-originals/v1' and actual_index['scope']==SCOPE and actual_index['sourceCommit']==commit and actual_index['production'] is False); exact(actual_index['sourceBinding'],binding); exact(actual_index['entries'],index)
    execution,_=json_file(public/'execution.json'); keys(execution,('schema','scope','sourceCommit','sourceBinding','formatExit','goExit','outcome','fullPrivateWALIndependentlyProven','production'))
    need(execution['schema']=='chengwang.mihomo-continuous-recovery-execution/v1' and execution['scope']==SCOPE and execution['sourceCommit']==commit and execution['formatExit']==execution['goExit']==0 and execution['outcome']=='PASS' and execution['fullPrivateWALIndependentlyProven'] is False and execution['production'] is False); exact(execution['sourceBinding'],binding)
    need(source_file(public/'gofmt.patch',8<<20,empty=True)==b'' and source_file(public/'gofmt.stderr',8<<20,empty=True)==b'' and source_file(public/'continuous.stderr',8<<20,empty=True)==b'')
    commands,_=json_lines(public/'commands.jsonl'); need(len(commands)==4)
    for i,(row,kind,timeout) in enumerate(zip(commands,COMMANDS,TIMEOUTS)):
        keys(row,('schema','sequence','sourceCommit','commandClass','argv','cwd','timeoutSeconds','exitCode','observed','namespace','sourceBinding'))
        integer(row['sequence'],1,4); integer(row['timeoutSeconds'],1,240); integer(row['exitCode'],0,0)
        need(row['schema']=='chengwang.mihomo-continuous-recovery-command-receipt/v1' and row['sequence']==i+1 and row['sourceCommit']==commit and row['commandClass']==kind and row['cwd']=='/tmp/mihomo-apply-source' and row['timeoutSeconds']==timeout and row['exitCode']==0 and row['observed'] is True); exact(row['sourceBinding'],binding); command_argv(row,i,binding,commit)
    events,_=json_lines(public/'process-events.jsonl'); need(events and [x['sequence'] for x in events]==list(range(1,len(events)+1)))
    for row in events:
        keys(row,('schema','sequence','commandClass','kind','pid','pidfdAcquired','exitCode')); integer(row['sequence'],1,64)
        need(row['schema']=='chengwang.mihomo-continuous-recovery-process-event/v1' and row['commandClass'] in COMMANDS and row['kind'] in ('START_INTENT','SPAWNED','PIDFD_ACQUIRED','WAIT_RETURNED'))
        need(row['pid'] is None or (type(row['pid']) is int and row['pid']>0)); need(row['pidfdAcquired'] is None or type(row['pidfdAcquired']) is bool); need(row['exitCode'] is None or type(row['exitCode']) is int)
    for command in COMMANDS:
        subset=[x for x in events if x.get('commandClass')==command]; need([x['kind'] for x in subset]==['START_INTENT','SPAWNED','PIDFD_ACQUIRED','WAIT_RETURNED'])
        need(subset[-1]['exitCode']==0 and subset[-1]['pidfdAcquired'] is True)
    rows=[json.loads(x) for x in source_file(public/'continuous.json',8<<20).splitlines() if x]
    relevant=[x for x in rows if x.get('Test')==TOP]; packages=[x for x in rows if 'Test' not in x and x.get('Action')=='pass']
    need(sum(x.get('Action')=='run' for x in relevant)==1 and sum(x.get('Action')=='pass' for x in relevant)==1 and not any(x.get('Action') in ('fail','skip') for x in rows) and len(packages)==1 and packages[0].get('Package')=='chengwang/internal/serverruntime' and all(x.get('Test',TOP).split('/')[0]==TOP for x in rows))
    sandbox,_=json_file(public/'sandbox.json'); need(sandbox['sourceBinding']==binding and sandbox['exactTags']==list(TAGS) and sandbox['forbiddenTags']==list(FORBIDDEN) and sandbox['production'] is False and sandbox['sourceReadOnly'] is True and sandbox['goReadOnly'] is True and sandbox['interfaceNames']==['lo'] and sandbox['defaultV4Routes']==sandbox['defaultV6Routes']==[])
    host_before=json.loads(source_file(public/'host-before.json',64<<10)); host_after=json.loads(source_file(public/'host-after.json',64<<10))
    need(host_before==host_after and set(host_before)=={'networkNamespace','mountNamespace','pidNamespace','resolvSHA256'} and DIGEST.fullmatch(host_before['resolvSHA256']))
    namespace={key:sandbox[key] for key in ('networkNamespace','mountNamespace','pidNamespace')}
    need(all(namespace[key]!=host_before[key] for key in namespace))
    for row in commands: exact(row['namespace'],namespace)
    need(source_file(public/'go-version.txt',4096).startswith(b'go version go1.23.12 linux/amd64\n'))
    receipt,_=json_file(public/'private-fsync-receipts.json'); need(receipt['schema']=='chengwang.mihomo-continuous-recovery-private-fsync/v1' and receipt['sourceCommit']==commit and receipt['directoryFsyncObserved'] is True and receipt['production'] is False); exact(receipt['sourceBinding'],binding)
    need([row.get('name') for row in receipt['entries']]==['continuous-recovery-report.private.json','kernel.stdout','kernel.stderr'])
    public_receipts={'continuous-recovery-report.private.json':'continuous-recovery-report.json','kernel.stdout':'kernel.stdout','kernel.stderr':'kernel.stderr'}
    for row in receipt['entries']:
        keys(row,('name','bytes','sha256','mode','uid','gid','fsyncObserved')); body=source_file(public/public_receipts[row['name']],2<<20,empty=True)
        need(row['mode']=='0600' and row['uid']==row['gid']==10001 and row['fsyncObserved'] is True and row['bytes']==len(body) and row['sha256']==sha(body))
    consumption_raw=source_file(public/'consumption.json',1<<20); need(consumption_raw==source_file(public/'consumption-independent.json',1<<20))
    consumption=json.loads(consumption_raw); need(consumption['source']['projectSourceCommit']==commit)
    for key in ('runtimeExecuted','runtimeCompatibilityProven','businessAvailabilityProven','publisherSignatureProven','productionApproved','production'): need(consumption[key] is False)
    return {'schema':'chengwang.mihomo-continuous-recovery-independent-verification/v1','sourceCommit':commit,'sourceBinding':binding,'httpResponses':31,'goTestPassed':True,'fullPrivateWALIndependentlyProven':False,'production':False}

def main(args):
    if len(args)==4 and args[0]=='--source-manifest':
        binding,raw=git_manifest(args[1],args[2]); out=Path(args[3]); need(not out.exists())
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),0o600)
        try:
            view=memoryview(raw)
            while view:
                written=os.write(fd,view); need(written>0); view=view[written:]
            os.fsync(fd)
        finally: os.close(fd)
        try: directory=os.open(out.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
        except PermissionError:
            need(os.name=='nt'); directory=None
        if directory is not None:
            try: os.fsync(directory)
            finally: os.close(directory)
        print(canonical(binding).decode()); return 0
    need(len(args)==3); result=verify(Path(args[0]),Path(args[1]),args[2]); print(canonical(result).decode()); return 0
if __name__=='__main__': raise SystemExit(main(sys.argv[1:]))
