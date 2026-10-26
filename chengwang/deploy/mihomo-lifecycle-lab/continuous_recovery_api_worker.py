#!/usr/bin/env python3
"""Capture one actual continuous Recovery HTTPS experiment; import starts nothing."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import unicodedata

SCOPE = 'ACTUAL_ISOLATED_HTTPS_UNKNOWN_RECOVERY_ACK_UNKNOWN_RECOVERY_NOT_PRODUCTION'
TOP = 'TestMihomoContinuousRecoveryHTTPSUnknownRecoveryAckUnknownRecovery'
TAGS = ('linux','chengwang_mihomo_service','chengwang_mihomo_recovery_native',
        'chengwang_mihomo_recovery_continuous_fault')
FORBIDDEN_TAGS = ('chengwang_mihomo_faults','chengwang_mihomo_completion_native')
COMMANDS = ('SANDBOX','GO_VERSION','GOFMT','GO_TEST')
CAPTURE = {
    'continuous-sandbox.private.json':('continuous-sandbox.private.stderr','SANDBOX',30),
    'go-version.txt':('go-version.private.stderr','GO_VERSION',15),
    'continuous-gofmt.patch':('continuous-gofmt.stderr','GOFMT',45),
    'continuous.json':('continuous.stderr','GO_TEST',240),
}
PRIVATE = Path('/tmp/chengwang-mihomo-continuous-private')
SERVICE = Path('/tmp/chengwang-mihomo-service-private')
IDENTITIES = Path('/tmp/chengwang-mihomo-service-identities')
STATE = Path('/tmp/chengwang-mihomo-service-state')
RECOVERY = Path('/tmp/chengwang-mihomo-recovery-private')
REPORT = SERVICE/'continuous-recovery-report.private.json'
SECRET_INPUTS = (
    ('IDENTITY_PROFILE',IDENTITIES/'credentials.json'),
    ('HTTP_TOKENS',IDENTITIES/'http-secrets.private.json'),
    ('TLS_KEY',IDENTITIES/'tls-key.private.pem'),
    ('SERVICE_SECRET',SERVICE/'.secrets.private.json'),
    ('CONFIG_A',SERVICE/'local-a.config.private.yaml'),
    ('CONFIG_B',SERVICE/'local-b.config.private.yaml'))
SECRET_INPUT_CLASSES = frozenset(name for name,_ in SECRET_INPUTS)
SECRET_ENCODING_VARIANTS = frozenset(('RAW','B64','B64URL','HEX','JSON_QUOTED'))
SECRET_ELEMENT_CLASSES = frozenset(('WHOLE_FILE','JSON_SCHEMA','JSON_SCOPE_ENVIRONMENT','JSON_IDENTITY_ROLE','JSON_OTHER_SCALAR'))
PUBLIC_LAB_ENVIRONMENT = 'isolated-lab'
PUBLIC_IDENTITY_ROLE_LABELS = {
    b'viewer':'VIEWER',b'operator':'OPERATOR',b'approver':'APPROVER',b'auditor':'AUDITOR',b'admin':'ADMIN'}
PUBLIC_IDENTITY_ROLE_ENUMS = frozenset((*PUBLIC_IDENTITY_ROLE_LABELS.values(),'UNKNOWN','NOT_APPLICABLE'))
HTTP_ERROR_CLASSES = frozenset(('NONE','RESPONSE_NOT_OBSERVED','BODY'))
HTTP_DIAGNOSTIC_ERROR_CLASSES = HTTP_ERROR_CLASSES|{'UNKNOWN'}
HTTP_DIAGNOSTIC_CASES = frozenset((
  'INITIAL_HEAD','FIRST_CANDIDATES','FIRST_UNKNOWN_CREATE','FIRST_UNKNOWN_APPROVE','FIRST_UNKNOWN_EXECUTE',
  'FIRST_UNKNOWN_INSPECT','FIRST_UNKNOWN_HEAD','FIRST_RECOVERY_CREATE','FIRST_RECOVERY_INSPECT_PLANNED',
  'FIRST_RECOVERY_APPROVE','FIRST_RECOVERY_EXECUTE','FIRST_RECOVERY_INSPECT_COMPLETED','FIRST_RECOVERED_HEAD',
  'ACK_CANDIDATES','ORDINARY_ACK_CREATE','ORDINARY_ACK_APPROVE','ORDINARY_ACK_EXECUTE','ORDINARY_ACK_INSPECT',
  'ORDINARY_ACK_HEAD','SECOND_CANDIDATES','SECOND_UNKNOWN_CREATE','SECOND_UNKNOWN_APPROVE','SECOND_UNKNOWN_EXECUTE',
  'SECOND_UNKNOWN_INSPECT','SECOND_UNKNOWN_HEAD','SECOND_RECOVERY_CREATE','SECOND_RECOVERY_INSPECT_PLANNED',
  'SECOND_RECOVERY_APPROVE','SECOND_RECOVERY_EXECUTE','SECOND_RECOVERY_INSPECT_COMPLETED','SECOND_RECOVERED_HEAD'))
FENCE_PHASES = frozenset(('REPORT_AND_HTTP_OUTPUTS','ALL_GENERIC_AND_REPORT_OUTPUTS'))
REPORT_FAILURE_CODES = frozenset(('ACK_HEAD','CANDIDATES','CLEANUP','CLEANUP_CALLS','CLEANUP_PORT',
  'DEPLOY_ACK','DEPLOY_APPROVAL','DEPLOY_EXECUTE','DEPLOY_INSPECT','DEPLOY_PLAN','DEPLOY_STATE','DEPLOY_UNKNOWN',
  'DISPATCH_COUNT','ENVELOPE','FAULT_CLOSE','FAULT_OBSERVATION','FIRST_RECOVERED_HEAD','FIRST_UNKNOWN_HEAD',
  'HOOK_ARM','HOOK_BIND','HTTP_BODY','HTTP_RESULT','HTTP_TRANSPORT','IDENTITY_INPUT','INITIAL_HEAD','INITIAL_STATE',
  'NONE','NOT_COMPLETED','RECOVERY_APPROVAL','RECOVERY_COMPLETE','RECOVERY_INSPECT','RECOVERY_PLAN',
  'RECOVERY_READBACK','REPORT_CONTRACT','REQUEST_BUILD','REQUEST_ENCODING','RUNTIME_START','SECOND_RECOVERED_HEAD',
  'SECOND_UNKNOWN_HEAD'))
RECOVERY_CREATE_STAGES = frozenset(('ENTERED','REJECTED_COORDINATOR','REJECTED_INVALID','REJECTED_CONFLICT',
  'REJECTED_AUTHORIZATION','REJECTED_ID','REJECTED_SNAPSHOT','REJECTED_OWNER','REJECTED_TARGET','REJECTED_PLAN',
  'REJECTED_EVOLVE','REJECTED_SOURCE_REFRESH','REJECTED_BEGIN','REJECTED_BIND','REJECTED_VIEW','ACCEPTED'))
MANIFEST_REL = 'chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_api_source_policy.json'
MAX_TRACKED = 64 << 20
COMMIT = re.compile(r'[0-9a-f]{40}')
OID = re.compile(r'[0-9a-f]{40}')
SHA = re.compile(r'[0-9a-f]{64}')
FMT = (
 'internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
 'internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
 'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
 'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
 'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
 'internal/mihomodeploy/lab_recovery_backend.go',
 'internal/mihomodeploy/lab_service.go',
 'internal/serverruntime/runtime.go',
 'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
 'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
 'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go')
DELIVERY = (
 '.github/workflows/chengwang-mihomo-continuous-recovery-api.yml',
 'chengwang/deploy/mihomo-lifecycle-lab/apply_worker.py',
 'chengwang/deploy/mihomo-lifecycle-lab/check_continuous_recovery_api.py',
 'chengwang/deploy/mihomo-lifecycle-lab/compat_worker.py',
 'chengwang/deploy/mihomo-lifecycle-lab/continuous_recovery_api_contract.json',
 MANIFEST_REL,
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
_ADAPTER = None

def need(value):
    if not value:
        raise ValueError('isolated continuous Recovery capture rejected')

def canonical(value):
    return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')

def sha(raw): return hashlib.sha256(raw).hexdigest()

def exact(actual, expected):
    need(type(actual) is type(expected))
    if type(expected) is dict:
        need(set(actual) == set(expected))
        for key in expected: exact(actual[key],expected[key])
    elif type(expected) in (list,tuple):
        need(len(actual) == len(expected))
        for left,right in zip(actual,expected): exact(left,right)
    else: need(actual == expected)
    return actual

def source_file(path, limit=2 << 20, empty=False):
    path = Path(path).absolute()
    for item in (*reversed(path.parents),path):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0) & 1024)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit and (empty or before.st_size > 0))
    raw = path.read_bytes(); after = path.lstat()
    sig = lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns)
    need(sig(before) == sig(after) and len(raw) == before.st_size)
    return raw

def adapter():
    global _ADAPTER
    if _ADAPTER is None:
        path = Path(__file__).absolute().with_name('apply_worker.py')
        info = path.lstat(); need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        spec = importlib.util.spec_from_file_location('_continuous_recovery_envelope',path)
        need(spec is not None and spec.loader is not None)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); _ADAPTER = module
    return _ADAPTER

def policy(root, module=False):
    rel = MANIFEST_REL[len('chengwang/'):] if module else MANIFEST_REL
    raw = source_file(Path(root)/rel,64 << 10); value = json.loads(raw)
    need(canonical(value)+b'\n' == raw)
    exact(value,{'allowedGitModes':['100644','100755'],
      'bindingSchema':'chengwang.mihomo-continuous-recovery-source-binding/v1',
      'deliveryPaths':list(DELIVERY),'generatedManifestIsPrivate':True,
      'generatedManifestSchema':'chengwang.mihomo-continuous-recovery-fulltracked-manifest/v1',
      'maxTrackedFileBytes':MAX_TRACKED,'rejectCaseFoldCollisions':True,
      'rejectDirtyIndexOrWorktree':True,'rejectHardlinks':True,'rejectSymlinks':True,
      'schema':'chengwang.mihomo-continuous-recovery-source-policy/v1','trackedSet':'ALL_GIT_HEAD_BLOBS'})
    return raw

def set_digest(schema, entries): return sha(canonical({'schema':schema,'entries':entries}))

def bind(raw, value):
    return {'schema':'chengwang.mihomo-continuous-recovery-source-binding/v1',
      'sourceCommit':value['sourceCommit'],'sourceTree':value['sourceTree'],'indexTree':value['indexTree'],
      'sourceManifestSHA256':sha(raw),'sourceSetSHA256':value['sourceSetSHA256'],
      'deliverySetSHA256':value['deliverySetSHA256'],'policySHA256':value['policySHA256'],
      'sourceCount':value['entryCount'],'deliveryCount':len(value['deliveries'])}

def git_source(repo, supplied):
    repo = Path(repo).resolve(strict=True); need(COMMIT.fullmatch(supplied) is not None)
    def git(*args, limit=8 << 20):
        result = subprocess.run(['git','-C',str(repo),*args],stdin=subprocess.DEVNULL,
          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        need(result.returncode == 0 and len(result.stdout) <= limit and len(result.stderr) <= 1 << 20)
        return result.stdout
    head=git('rev-parse','HEAD').strip().decode('ascii'); treeoid=git('rev-parse','HEAD^{tree}').strip().decode('ascii')
    indexoid=git('write-tree').strip().decode('ascii')
    need(head == supplied and OID.fullmatch(treeoid) and treeoid == indexoid and
         Path(os.fsdecode(git('rev-parse','--show-toplevel').strip())).resolve() == repo and
         git('status','--porcelain=v1','--untracked-files=all') == b'')
    tree={}; folded=set()
    for row in git('ls-tree','-r','-z','--full-tree',head).split(b'\0'):
        if not row: continue
        meta,name=row.split(b'\t',1); mode,kind,oid=meta.split(); path=name.decode('utf8'); key=unicodedata.normalize('NFC',path).casefold()
        need(path not in tree and key not in folded and not path.startswith('/') and '\\' not in path and '..' not in Path(path).parts and
             mode in (b'100644',b'100755') and kind == b'blob' and OID.fullmatch(oid.decode('ascii')))
        tree[path]=(mode.decode('ascii'),oid.decode('ascii')); folded.add(key)
    index={}
    for row in git('ls-files','--stage','-z').split(b'\0'):
        if not row: continue
        meta,name=row.split(b'\t',1); mode,oid,stage=meta.split(); path=name.decode('utf8')
        need(path in tree and path not in index and stage == b'0'); index[path]=(mode.decode('ascii'),oid.decode('ascii'))
    need(index == tree and set(DELIVERY).issubset(tree))
    entries=[]
    for path,(mode,oid) in tree.items():
        raw=source_file(repo/path,MAX_TRACKED)
        need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == oid)
        if os.name == 'posix': need(bool((repo/path).lstat().st_mode & 0o111) == (mode == '100755'))
        entries.append({'path':path,'mode':mode,'gitBlob':oid,'bytes':len(raw),'sha256':sha(raw)})
    by={row['path']:row for row in entries}; deliveries=[by[path] for path in DELIVERY]; policy_raw=policy(repo)
    value={'schema':'chengwang.mihomo-continuous-recovery-fulltracked-manifest/v1','sourceCommit':head,
      'sourceTree':treeoid,'indexTree':indexoid,'policySHA256':sha(policy_raw),'entryCount':len(entries),
      'entries':entries,'deliveries':deliveries,
      'sourceSetSHA256':set_digest('chengwang.mihomo-continuous-recovery-fulltracked-set/v1',entries),
      'deliverySetSHA256':set_digest('chengwang.mihomo-continuous-recovery-delivery-set/v1',deliveries)}
    raw=canonical(value)+b'\n'; return head,bind(raw,value),raw

def verify_manifest(root, raw, expected, module=False):
    value=json.loads(raw); need(canonical(value)+b'\n' == raw)
    need(set(value)=={'schema','sourceCommit','sourceTree','indexTree','policySHA256','entryCount','entries','deliveries','sourceSetSHA256','deliverySetSHA256'} and
         value['schema']=='chengwang.mihomo-continuous-recovery-fulltracked-manifest/v1')
    exact(bind(raw,value),expected); need(value['sourceTree']==value['indexTree'] and value['entryCount']==len(value['entries']))
    paths=set(); folded=set(); by={}
    for row in value['entries']:
        need(type(row) is dict and set(row)=={'path','mode','gitBlob','bytes','sha256'} and row['mode'] in ('100644','100755') and
             OID.fullmatch(row['gitBlob']) and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_TRACKED and SHA.fullmatch(row['sha256']))
        key=unicodedata.normalize('NFC',row['path']).casefold(); need(row['path'] not in paths and key not in folded)
        paths.add(row['path']); folded.add(key); by[row['path']]=row
        if module and not row['path'].startswith('chengwang/'): continue
        rel=row['path'][len('chengwang/'):] if module else row['path']; body=source_file(Path(root)/rel,MAX_TRACKED)
        need(len(body)==row['bytes'] and sha(body)==row['sha256'] and hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==row['gitBlob'])
    exact(value['deliveries'],[by.get(path) for path in DELIVERY]); policy_raw=policy(root,module)
    need(value['policySHA256']==sha(policy_raw) and set(DELIVERY).issubset(paths) and
         value['sourceSetSHA256']==set_digest('chengwang.mihomo-continuous-recovery-fulltracked-set/v1',value['entries']) and
         value['deliverySetSHA256']==set_digest('chengwang.mihomo-continuous-recovery-delivery-set/v1',value['deliveries']))
    return bind(raw,value)

def contract():
    raw=source_file(Path(__file__).with_name('continuous_recovery_api_contract.json'),64 << 10); value=json.loads(raw)
    need(canonical(value)+b'\n' == raw and value['schema']=='chengwang.mihomo-continuous-recovery-contract/v1' and value['scope']==SCOPE and
         tuple(value['exactTags'])==TAGS and tuple(value['forbiddenTags'])==FORBIDDEN_TAGS and value['topTest']==TOP and
         value['goTimeoutSeconds']==210 and value['outerGoTimeoutSeconds']==240 and value['fullPrivateWALIndependentlyProven'] is False and
         value['production'] is False and value['httpOriginalBytesRequired'] is True)
    need(not set(value['exactTags']) & set(value['forbiddenTags']))
    return value

def private_bases(create):
    for path in (PRIVATE,SERVICE,IDENTITIES,STATE,RECOVERY):
        if create:
            path.mkdir(mode=0o700); os.chown(path,10001,10001)
        info=path.lstat(); need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==info.st_gid==10001)
    if create: need(all(not any(path.iterdir()) for path in (PRIVATE,SERVICE,IDENTITIES,STATE,RECOVERY)))

def write_private(path, raw, uid=10001):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|getattr(os,'O_BINARY',0),0o600)
    try:
        os.fchown(fd,uid,uid); view=memoryview(raw)
        while view:
            n=os.write(fd,view); need(n>0); view=view[n:]
        os.fsync(fd); info=os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==uid and info.st_size==len(raw))
    finally: os.close(fd)
    directory=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)

def command_argv(state, command):
    a=adapter(); w=a.shared(); b=state['sourceBinding']; worker=a.PATHS['module']+'/deploy/mihomo-lifecycle-lab/continuous_recovery_api_worker.py'
    commands={
      'SANDBOX':[w.tool('python3'),'-B',worker,'--sandbox',state['commit'],b['sourceTree'],b['indexTree'],b['sourceManifestSHA256'],b['sourceSetSHA256'],b['deliverySetSHA256'],b['policySHA256'],str(b['sourceCount']),str(b['deliveryCount'])],
      'GO_VERSION':[a.PATHS['goRoot']+'/bin/go','version'],
      'GOFMT':[a.PATHS['goRoot']+'/bin/gofmt','-d',*FMT],
      'GO_TEST':[a.PATHS['goRoot']+'/bin/go','test','-json','-count=1','-shuffle=off','-p=1','-tags='+','.join(TAGS),'-run=^'+TOP+'$','-timeout=210s','./internal/serverruntime']}
    return tuple(commands[command])

def append_jsonl(path, row, state, key):
    sequence=state.get(key,0)+1; need(row['sequence']==sequence)
    raw=canonical(row)+b'\n'; flags=os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW
    if sequence==1: flags|=os.O_CREAT|os.O_EXCL
    fd=os.open(path,flags|getattr(os,'O_BINARY',0),0o600)
    try:
        info=os.fstat(fd); need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and info.st_size+len(raw)<=128<<10)
        view=memoryview(raw)
        while view:
            n=os.write(fd,view); need(n>0); view=view[n:]
        os.fsync(fd)
    finally: os.close(fd)
    state[key]=sequence

def encoded_secret_variants(body, input_class, element_class='WHOLE_FILE', matches_public_lab_environment=False,
                            matches_public_identity_role=False, public_identity_role='NOT_APPLICABLE'):
    need(type(body) is bytes and body and input_class in SECRET_INPUT_CLASSES and
         element_class in SECRET_ELEMENT_CLASSES and type(matches_public_lab_environment) is bool and
         type(matches_public_identity_role) is bool and public_identity_role in PUBLIC_IDENTITY_ROLE_ENUMS)
    metadata=(matches_public_lab_environment,matches_public_identity_role,public_identity_role)
    return ((body,input_class,element_class,'RAW',*metadata),
      (base64.b64encode(body),input_class,element_class,'B64',*metadata),
      (base64.b64encode(body).rstrip(b'='),input_class,element_class,'B64',*metadata),
      (base64.urlsafe_b64encode(body),input_class,element_class,'B64URL',*metadata),
      (base64.urlsafe_b64encode(body).rstrip(b'='),input_class,element_class,'B64URL',*metadata),
      (body.hex().encode(),input_class,element_class,'HEX',*metadata),
      (body.hex().upper().encode(),input_class,element_class,'HEX',*metadata),
      (json.dumps(body.decode('utf8','ignore')).encode(),input_class,element_class,'JSON_QUOTED',*metadata))

def build_forbidden():
    secrets=[]
    scope_environment_path=('identities',None,'principal','allowedScopes',None,'environment')
    identity_role_path=('identities',None,'principal','roles',None)
    def scalar_values(value, input_class, path=()):
        if type(value) is dict:
            for item_key,item in value.items(): yield from scalar_values(item,input_class,path+(item_key,))
        elif type(value) is list:
            for item in value: yield from scalar_values(item,input_class,path+(None,))
        elif type(value) in (str,int,float,bool):
            body=str(value).encode()
            element_class='JSON_SCHEMA' if path==('schema',) else (
              'JSON_SCOPE_ENVIRONMENT' if input_class=='IDENTITY_PROFILE' and path==scope_environment_path else (
              'JSON_IDENTITY_ROLE' if input_class=='IDENTITY_PROFILE' and path==identity_role_path else 'JSON_OTHER_SCALAR'))
            public_role=PUBLIC_IDENTITY_ROLE_LABELS.get(body,'UNKNOWN') if element_class=='JSON_IDENTITY_ROLE' else 'NOT_APPLICABLE'
            yield (body,element_class,element_class=='JSON_SCOPE_ENVIRONMENT' and body==PUBLIC_LAB_ENVIRONMENT.encode(),
              element_class=='JSON_IDENTITY_ROLE' and body in PUBLIC_IDENTITY_ROLE_LABELS,public_role)
    for input_class,path in SECRET_INPUTS:
        if not path.exists(): continue
        body=source_file(path,1<<20); secrets.append((input_class,body,'WHOLE_FILE',False,False,'NOT_APPLICABLE'))
        try:
            value=json.loads(body)
            secrets.extend((input_class,scalar,element_class,matches_environment,matches_role,public_role)
              for scalar,element_class,matches_environment,matches_role,public_role in scalar_values(value,input_class))
        except Exception: pass
    forbidden=[]
    for input_class,body,element_class,matches_environment,matches_role,public_role in secrets:
        if body: forbidden.extend(encoded_secret_variants(
          body,input_class,element_class,matches_environment,matches_role,public_role))
    return forbidden

def report_diagnostic_status(report):
    if type(report) is not dict: return 'UNKNOWN',False,None,False,None,None,False,None,False,False,0,None
    code=report.get('failureCode'); outcome=report.get('outcome')
    last_case=status=error_class=state_changed=None; status_observed=state_changed_observed=False
    rows=report.get('http')
    if rows is not None and (type(rows) is not list or rows):
        last_case=error_class='UNKNOWN'
        if type(rows) is list and type(rows[-1]) is dict:
            candidate=rows[-1].get('case')
            if type(candidate) is str and candidate in HTTP_DIAGNOSTIC_CASES: last_case=candidate
            candidate=rows[-1].get('statusCode')
            if type(candidate) is int and 100<=candidate<=599: status=candidate; status_observed=True
            candidate=rows[-1].get('errorClass')
            if type(candidate) is str and candidate in HTTP_ERROR_CLASSES: error_class=candidate
            encoded=rows[-1].get('responseBodyB64')
            if type(encoded) is str:
                try:
                    envelope=json.loads(base64.b64decode(encoded,validate=True))
                    candidate=envelope.get('stateMayHaveChanged') if type(envelope) is dict else None
                    if type(candidate) is bool: state_changed=candidate; state_changed_observed=True
                except Exception: pass
    trace_observed=trace_bounded=False; create_count=0; last_create_stage=None
    for name in ('faultAfterCleanup','faultClosed','faultBeforeCleanup'):
        observation=report.get(name)
        if observation is None: continue
        trace_observed=True; last_create_stage='UNKNOWN'
        if type(observation) is dict and type(observation.get('recoveryCreatesBounded')) is bool:
            trace_bounded=observation['recoveryCreatesBounded']
            creates=observation.get('recoveryCreates')
            if type(creates) is list and len(creates)<=4:
                create_count=len(creates)
                if creates and type(creates[-1]) is dict and creates[-1].get('sequence')==len(creates):
                    candidate=creates[-1].get('stage')
                    if type(candidate) is str and candidate in RECOVERY_CREATE_STAGES: last_create_stage=candidate
                elif not creates: last_create_stage=None
        break
    return (code if type(code) is str and code in REPORT_FAILURE_CODES else 'UNKNOWN',
      type(outcome) is str and outcome=='PASS',last_case,status_observed,status,error_class,
      state_changed_observed,state_changed,trace_observed,trace_bounded,create_count,last_create_stage)

def fence_outputs(outputs, forbidden, phase, format_exit, go_exit, report_observed, http_count,
                  report_failure_code, report_outcome_pass, last_http_case=None, last_http_status_observed=False,
                  last_http_status_code=None, last_http_error_class=None, last_http_state_changed_observed=False,
                  last_http_state_changed=None, recovery_create_trace_observed=False,
                  recovery_create_trace_bounded=False, recovery_create_count=0, last_recovery_create_stage=None):
    need(type(outputs) is dict and phase in FENCE_PHASES and
         type(format_exit) is int and type(go_exit) is int and type(report_observed) is bool and
         type(http_count) is int and 0 <= http_count <= 4096 and
         report_failure_code in REPORT_FAILURE_CODES|{'UNKNOWN'} and type(report_outcome_pass) is bool and
         (last_http_case is None or last_http_case in HTTP_DIAGNOSTIC_CASES|{'UNKNOWN'}) and
         type(last_http_status_observed) is bool and last_http_status_observed is (last_http_status_code is not None) and
         (last_http_status_code is None or type(last_http_status_code) is int and 100<=last_http_status_code<=599) and
         (last_http_error_class is None or last_http_error_class in HTTP_DIAGNOSTIC_ERROR_CLASSES) and
         type(last_http_state_changed_observed) is bool and
         last_http_state_changed_observed is (type(last_http_state_changed) is bool) and
         type(recovery_create_trace_observed) is bool and type(recovery_create_trace_bounded) is bool and
         type(recovery_create_count) is int and 0<=recovery_create_count<=4 and
         (last_recovery_create_stage is None or last_recovery_create_stage in RECOVERY_CREATE_STAGES|{'UNKNOWN'}))
    for name,body in outputs.items():
        need(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,127}',name) is not None and type(body) is bytes)
        for secret,input_class,element_class,variant,matches_environment,matches_role,public_role in forbidden:
            need(type(secret) is bytes and input_class in SECRET_INPUT_CLASSES and variant in SECRET_ENCODING_VARIANTS and
                 element_class in SECRET_ELEMENT_CLASSES and type(matches_environment) is bool and
                 type(matches_role) is bool and public_role in PUBLIC_IDENTITY_ROLE_ENUMS)
            if len(secret) >= 8 and secret in body:
                diagnostic=canonical({'phase':phase,'formatExit':format_exit,'goExit':go_exit,
                  'reportObserved':report_observed,'httpCount':http_count,'reportFailureCode':report_failure_code,
                  'reportOutcomePass':report_outcome_pass,'lastHTTPCase':last_http_case,
                  'lastHTTPStatusObserved':last_http_status_observed,'lastHTTPStatusCode':last_http_status_code,
                  'lastHTTPErrorClass':last_http_error_class,
                  'lastHTTPStateMayHaveChangedObserved':last_http_state_changed_observed,
                  'lastHTTPStateMayHaveChanged':last_http_state_changed,
                  'recoveryCreateTraceObserved':recovery_create_trace_observed,
                  'recoveryCreateTraceBounded':recovery_create_trace_bounded,
                  'recoveryCreateCount':recovery_create_count,'lastRecoveryCreateStage':last_recovery_create_stage,
                  'outputLogicalName':name,
                  'secretInputClass':input_class,'secretElementClass':element_class,
                  'matchesPublicLabEnvironment':matches_environment,'matchesPublicIdentityRole':matches_role,
                  'publicIdentityRole':public_role,'encodingVariant':variant})
                message=b'isolated continuous Recovery capture rejected '+diagnostic
                if any(len(value)>=8 and value in message for value,_,_,_,_,_,_ in forbidden):
                    raise ValueError('isolated continuous Recovery capture rejected')
                raise ValueError(message.decode('ascii'))

def event(state, command, kind, pid=None, acquired=None, exit_code=None):
    append_jsonl(adapter().ROOT_PRIVATE/'continuous-process-events.private.jsonl',{
      'schema':'chengwang.mihomo-continuous-recovery-process-event/v1','sequence':state.get('eventSequence',0)+1,
      'commandClass':command,'kind':kind,'pid':pid,'pidfdAcquired':acquired,'exitCode':exit_code},state,'eventSequence')

def capture(state, argv, name, err_name, timeout, command):
    a=adapter(); w=a.shared(); actual=tuple(argv)
    need(name in CAPTURE and CAPTURE[name]==(err_name,command,timeout) and command==COMMANDS[state.get('commandSequence',0)] and
         actual==command_argv(state,command) and type(timeout) is int and 0<timeout<=240)
    observed=False; code=None
    try:
        event(state,command,'START_INTENT')
        with (a.ROOT_PRIVATE/name).open('xb') as stdout,(a.ROOT_PRIVATE/err_name).open('xb') as stderr:
            os.fchmod(stdout.fileno(),0o600); os.fchmod(stderr.fileno(),0o600)
            process=subprocess.Popen(w.unprivileged(actual,state['environment']),env=w.ROOT_ENV,cwd='/tmp/mihomo-apply-source',
              stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
            entry={'process':process,'pidfd':None}; state['pending'].append(entry); event(state,command,'SPAWNED',process.pid,False)
            try:
                fd=os.pidfd_open(process.pid,0); entry['pidfd']=fd; event(state,command,'PIDFD_ACQUIRED',process.pid,True)
                try: code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    event(state,command,'TIMEOUT',process.pid,True)
                    signal.pidfd_send_signal(fd,signal.SIGKILL); event(state,command,'SIGKILL_SENT',process.pid,True)
                    try: code=process.wait(timeout=5)
                    except subprocess.TimeoutExpired: event(state,command,'WAIT_UNOBSERVED',process.pid,True); raise ValueError('owned continuous process wait unobserved')
                event(state,command,'WAIT_RETURNED',process.pid,True,code); stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
            finally:
                if process.returncode is not None and entry['pidfd'] is not None:
                    os.close(entry['pidfd']); entry['pidfd']=None; state['pending'].remove(entry)
        observed=True; return code
    finally:
        row={'schema':'chengwang.mihomo-continuous-recovery-command-receipt/v1','sequence':state.get('commandSequence',0)+1,
          'sourceCommit':state['commit'],'commandClass':command,'argv':list(actual),'cwd':'/tmp/mihomo-apply-source',
          'timeoutSeconds':timeout,'exitCode':code if observed else None,'observed':observed,'namespace':w.namespace_values(),
          'sourceBinding':copy.deepcopy(state['sourceBinding'])}
        append_jsonl(a.ROOT_PRIVATE/'continuous-commands.private.jsonl',row,state,'commandSequence')

def safe_report_outputs(binding, forbidden, format_exit, go_exit):
    a=adapter(); w=a.shared(); raw=source_file(REPORT,2<<20); report=json.loads(raw)
    need(canonical(report)+b'\n'==raw and report['schema']=='chengwang.mihomo-continuous-recovery-http-experiment/v1' and
         report['scope']==SCOPE and report['sourceCommit']==binding['sourceCommit'])
    need(type(forbidden) is list)
    outputs={'continuous-recovery-report.json':raw}; index=[]
    for i,row in enumerate(report.get('http',[]),1):
        need(type(row) is dict and row.get('sequence')==i and type(row.get('responseBodyB64')) is str)
        body=base64.b64decode(row['responseBodyB64'],validate=True); need(0<len(body)<=16<<10 and sha(body)==row.get('responseBodySHA256'))
        name=f'http-{i:03d}.response.json'; outputs[name]=body
        index.append({'sequence':i,'case':row.get('case'),'role':row.get('role'),'method':row.get('method'),'path':row.get('path'),
          'statusCode':row.get('statusCode'),'bytes':len(body),'sha256':sha(body),'name':name})
    outputs['http-originals-index.json']=canonical({'schema':'chengwang.mihomo-continuous-recovery-http-originals/v1',
      'scope':SCOPE,'sourceCommit':binding['sourceCommit'],'sourceBinding':binding,'entries':index,'production':False})+b'\n'
    for public,private in (('kernel.stdout',SERVICE/'kernel.stdout'),('kernel.stderr',SERVICE/'kernel.stderr')):
        outputs[public]=source_file(private,256<<10,empty=True)
    diagnostic=report_diagnostic_status(report)
    fence_outputs(outputs,forbidden,'REPORT_AND_HTTP_OUTPUTS',format_exit,go_exit,True,len(report.get('http',[])),
      *diagnostic)
    receipts=[]
    for path in (REPORT,SERVICE/'kernel.stdout',SERVICE/'kernel.stderr'):
        info=path.lstat(); body=source_file(path,2<<20,empty=True); fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        receipts.append({'name':path.name,'bytes':len(body),'sha256':sha(body),'mode':format(stat.S_IMODE(info.st_mode),'04o'),
          'uid':info.st_uid,'gid':info.st_gid,'fsyncObserved':True})
    outputs['private-fsync-receipts.json']=canonical({'schema':'chengwang.mihomo-continuous-recovery-private-fsync/v1',
      'sourceCommit':binding['sourceCommit'],'sourceBinding':binding,'entries':receipts,'directoryFsyncObserved':True,'production':False})+b'\n'
    return outputs,report,forbidden

def go_terminal(raw):
    rows=[json.loads(line) for line in raw.splitlines() if line]; relevant=[row for row in rows if row.get('Test')==TOP]
    need(sum(row.get('Action')=='run' for row in relevant)==1 and sum(row.get('Action')=='pass' for row in relevant)==1 and
         not any(row.get('Action') in ('fail','skip') for row in rows))
    packages=[row for row in rows if 'Test' not in row and row.get('Action')=='pass']
    need(len(packages)==1 and packages[0].get('Package')=='chengwang/internal/serverruntime' and all(row.get('Test',TOP).split('/')[0]==TOP for row in rows))

def main(args):
    if len(args)==10 and args[0]=='--sandbox':
        module=Path('/tmp/mihomo-apply-source'); need(Path(__file__).resolve()==(module/'deploy/mihomo-lifecycle-lab/continuous_recovery_api_worker.py').resolve())
        manifest=source_file(PRIVATE/'continuous-source.private.json',8<<20)
        expected={'schema':'chengwang.mihomo-continuous-recovery-source-binding/v1','sourceCommit':args[1],'sourceTree':args[2],
          'indexTree':args[3],'sourceManifestSHA256':args[4],'sourceSetSHA256':args[5],'deliverySetSHA256':args[6],
          'policySHA256':args[7],'sourceCount':int(args[8]),'deliveryCount':int(args[9])}
        binding=verify_manifest(module,manifest,expected,module=True); a=adapter(); facts=a.sandbox(args[1],sha(source_file(module/'go.mod',64<<10)))
        facts.update(schema='chengwang.mihomo-continuous-recovery-sandbox/v1',sourceBinding=binding,
          exactTags=list(TAGS),forbiddenTags=list(FORBIDDEN_TAGS),production=False)
        print(canonical(facts).decode('ascii')); return 0
    need(len(args)==5); repo=Path(args[0]).absolute(); out=Path(args[1]).absolute(); actual,binding,manifest=git_source(repo,args[4])
    a=adapter(); w=a.shared(); c=contract(); state=a.prepare_namespace(*args); state['sourceBinding']=binding
    private_bases(True); write_private(PRIVATE/'continuous-source.private.json',manifest)
    code=capture(state,command_argv(state,'SANDBOX'),'continuous-sandbox.private.json','continuous-sandbox.private.stderr',30,'SANDBOX')
    need(code==0 and source_file(a.ROOT_PRIVATE/'continuous-sandbox.private.stderr',4096,empty=True)==b'')
    need(capture(state,command_argv(state,'GO_VERSION'),'go-version.txt','go-version.private.stderr',15,'GO_VERSION')==0)
    state['formatExit']=capture(state,command_argv(state,'GOFMT'),'continuous-gofmt.patch','continuous-gofmt.stderr',45,'GOFMT')
    state['goExit']=capture(state,command_argv(state,'GO_TEST'),'continuous.json','continuous.stderr',240,'GO_TEST')
    after,_,directory=w.custody(state['consumed']); need(after==state['inputBefore'] and directory==state['originalDirectory'])
    forbidden=build_forbidden()
    outputs={}
    for public,private in (('sandbox.json','continuous-sandbox.private.json'),('go-version.txt','go-version.txt'),
      ('gofmt.patch','continuous-gofmt.patch'),('gofmt.stderr','continuous-gofmt.stderr'),('continuous.json','continuous.json'),
      ('continuous.stderr','continuous.stderr'),('commands.jsonl','continuous-commands.private.jsonl'),
      ('process-events.jsonl','continuous-process-events.private.jsonl')):
        outputs[public]=source_file(a.ROOT_PRIVATE/private,8<<20,empty=True)
    outcome='NO_REPORT'
    report=None
    if REPORT.exists():
        public,report,_=safe_report_outputs(binding,forbidden,state['formatExit'],state['goExit']); outputs.update(public); outcome=report.get('outcome')
    outputs['execution.json']=canonical({'schema':'chengwang.mihomo-continuous-recovery-execution/v1','scope':SCOPE,
      'sourceCommit':actual,'sourceBinding':binding,'formatExit':state['formatExit'],'goExit':state['goExit'],
      'outcome':outcome,'fullPrivateWALIndependentlyProven':False,'production':False})+b'\n'
    diagnostic=report_diagnostic_status(report)
    fence_outputs(outputs,forbidden,'ALL_GENERIC_AND_REPORT_OUTPUTS',state['formatExit'],state['goExit'],
      report is not None,len(report.get('http',[])) if report is not None else 0,*diagnostic)
    need(sum(map(len,outputs.values()))<=c['maxPublicBytes']); a.unchanged_public(state)
    for name,body in outputs.items(): w.write_new(a.EXPORT_ALIAS/name,body,0o644)
    a.sync_output(state); a.unchanged_public(state); need(not state['pending'])
    if state['formatExit']!=0 or state['goExit']!=0 or outputs['gofmt.patch'] or outputs['gofmt.stderr'] or outcome!='PASS': return 1
    go_terminal(outputs['continuous.json'])
    print('CONTINUOUS_RECOVERY_API_ORIGINALS=CAPTURED private_wal_independent=false production=false'); return 0

if __name__=='__main__':
    try: raise SystemExit(main(sys.argv[1:]))
    except Exception:
        print('continuous Recovery capture rejected',file=sys.stderr); raise
