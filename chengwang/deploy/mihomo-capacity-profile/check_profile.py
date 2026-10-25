"""Independent fixed-profile bytes/source/event reader; never executes Go."""
import argparse
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import zlib

TOP='TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop'
PACKAGE='chengwang/internal/mihomodeploy'
PRIVATE='/tmp/chengwang-capacity-profile-private'
TAG='chengwang_capacity_profile'
GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags',TAG,'-run','^'+TOP+'$','./internal/mihomodeploy']
PUBLIC=('host-before.json','host-after.json','source-before.json','source-after.json','sandbox.json','go-version.txt',
    'gofmt.patch','gofmt.stderr','capacity.json','capacity.stderr','commands.jsonl','execution.json',
    'profile-state.json','cpu-profile.json','pprof-top.txt','pprof-top.stderr','pprof-cum.txt','pprof-cum.stderr')
ENV=sorted(['PATH','GOROOT','HOME','TMPDIR','GOCACHE','GOMODCACHE','GOPROXY','GOSUMDB','GOENV','GOTOOLCHAIN',
    'GOFLAGS','CGO_ENABLED','LANG','LC_ALL','TZ','CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT'])
ORIGINAL_SOURCE_PINS={
    'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go':'ea0a3ec623691b161680727378e1feb638157322df230b60d0f7e09534a2b7d6',
    'chengwang/internal/mihomodeploy/lifecycle.go':'15491b8f671d6b5bc2e948abbbdb56100753cb951176dd8c85167efa9e9f3fe4',
    'chengwang/internal/mihomodeploy/lab_bootstrap_state.go':'4b11dfbbf1e521933ff57be60cab3dd9d44c36e034b68d9529b353a837ca817e',
}

def need(v):
    if not v:raise ValueError('capacity profile evidence rejected')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def decode(raw):
    def pairs(items):
        result={}
        for k,v in items:need(k not in result);result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False))
def exact(value,keys):return type(value) is dict and set(value)==set(keys)
def integer(n,low=0,high=(1<<63)-1):return type(n) is int and low<=n<=high
def read(path,limit):
    need(path.is_absolute() and '..' not in path.parts)
    for part in (*reversed(path.parents),path):need(not part.is_symlink())
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit)
    with path.open('rb') as f:opened=os.fstat(f.fileno());raw=f.read(limit+1);after=os.fstat(f.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_mode,s.st_nlink)
    need(identity(before)==identity(opened)==identity(after)==identity(path.lstat()) and len(raw)==before.st_size)
    return raw
def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as f:need(f.write(raw)==len(raw));f.flush();os.fsync(f.fileno())

def source_snapshot(repo,commit):
    need(re.fullmatch('[a-f0-9]{40}',commit) is not None)
    need(os.path.samefile(Path(__file__),repo/'chengwang/deploy/mihomo-capacity-profile/check_profile.py'))
    need(subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD']).strip().decode()==commit)
    need(subprocess.check_output(['git','-C',str(repo),'status','--porcelain','--untracked-files=all'])==b'')
    index=subprocess.check_output(['git','-C',str(repo),'ls-tree','-r','-z','--full-tree',commit])
    rows=[];total=0
    for entry in index.split(b'\0'):
        if not entry:continue
        meta,path=entry.split(b'\t',1);mode,kind,oid=meta.split(b' ');name=path.decode('utf8')
        need(mode in (b'100644',b'100755') and kind==b'blob' and not name.startswith('/') and '..' not in Path(name).parts)
        raw=read(repo/name,16<<20);total+=len(raw);need(total<=128<<20)
        need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==oid.decode())
        rows.append({'path':name,'bytes':len(raw),'sha256':sha(raw),'gitBlobSHA1':oid.decode()})
    need(1<=len(rows)<=4096 and len({r['path'] for r in rows})==len(rows))
    pinned={r['path']:r['sha256'] for r in rows}
    need(all(pinned.get(p)==value for p,value in ORIGINAL_SOURCE_PINS.items()))
    return {'schema':'chengwang.capacity-profile-source/v1','sourceCommit':commit,'sourceGitVerified':True,
        'originalCaseSourcePins':ORIGINAL_SOURCE_PINS,'files':rows}

def host():
    return {**{k:os.readlink('/proc/self/ns/'+v) for k,v in [('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')]},
        'resolvSHA256':sha(Path('/etc/resolv.conf').read_bytes())}

def protobuf_fields(raw):
    # Bounded protobuf wire reader, not a producer import or a protobuf dependency.
    pos=0;count=0
    def varint():
        nonlocal pos
        n=0
        for shift in range(0,70,7):
            need(pos<len(raw));v=raw[pos];pos+=1;n|=(v&127)<<shift
            if not v&128:need(n<(1<<64));return n
        need(False)
    while pos<len(raw):
        count+=1;need(count<=1000000)
        key=varint();number,wire=key>>3,key&7;need(number>0)
        if wire==0:value=varint()
        elif wire==2:
            size=varint();need(size<=len(raw)-pos);value=raw[pos:pos+size];pos+=size
        elif wire in (1,5):
            size=8 if wire==1 else 4;need(size<=len(raw)-pos);value=raw[pos:pos+size];pos+=size
        else:need(False)
        yield number,wire,value

def profile_shape(raw):
    need(0<len(raw)<=8<<20)
    decoder=zlib.decompressobj(31);proto=decoder.decompress(raw,(64<<20)+1)
    need(len(proto)<=64<<20 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
    strings=[];samples=0;function_names=[];duration=None
    for field,wire,value in protobuf_fields(proto):
        if field==6:need(wire==2);strings.append(value.decode('utf8','strict'))
        elif field==2:
            need(wire==2);samples+=1
            for tag,kind,item in protobuf_fields(value):need(tag!=3) # no profile labels
        elif field==5:
            need(wire==2);names=[item for tag,kind,item in protobuf_fields(value) if tag==2 and kind==0]
            need(len(names)==1);function_names.append(names[0])
        elif field==10:need(wire==0 and duration is None);duration=value
    need(samples>0 and function_names and integer(duration,1,180000000000))
    need(all(integer(i,0,len(strings)-1) for i in function_names))
    need(PACKAGE+'.'+TOP in [strings[i] for i in function_names])
    return {'sampleRecords':samples,'functions':len(function_names),'durationNanoseconds':duration,'profileLabelsPresent':False}

def verify_raw(raw,commit):
    need(set(raw)==set(PUBLIC) and sum(map(len,raw.values()))<=64<<20)
    e=decode(raw['execution.json']);need(exact(e,['schema','sourceCommit','versionExit','formatExit','goExit','topExit','cumExit','profileCaptureComplete','production']))
    need(e['schema']=='chengwang.capacity-profile-execution/v1' and e['sourceCommit']==commit and e['production'] is False)
    need(all(integer(e[k],-128,255) for k in ('versionExit','formatExit','goExit','topExit','cumExit')) and e['versionExit']==e['topExit']==e['cumExit']==0)
    need(e['profileCaptureComplete'] is True and raw['go-version.txt']==b'go version go1.23.12 linux/amd64\n')
    before,after=decode(raw['host-before.json']),decode(raw['host-after.json']);need(before==after and exact(before,['networkNamespace','mountNamespace','pidNamespace','resolvSHA256']))
    box=decode(raw['sandbox.json']);need(exact(box,['schema','uid','gid','effectiveCaps','noNewPrivileges','interfaces','defaultRoutes','environmentKeys',
        'sourceAliasReadOnly','goRootReadOnly','goRoot','networkNamespace','mountNamespace','pidNamespace','production']))
    need(box['schema']=='chengwang.capacity-profile-sandbox/v1' and type(box['uid']) is type(box['gid']) is int and box['uid']==box['gid']==10001)
    need(box['effectiveCaps']=='0000000000000000' and box['noNewPrivileges'] is True and box['interfaces']==['lo'] and box['defaultRoutes']=={'ipv4':[],'ipv6':[]})
    need(box['environmentKeys']==ENV and box['sourceAliasReadOnly'] is box['goRootReadOnly'] is True and box['production'] is False)
    for key,kind in [('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')]:
        need(re.fullmatch(kind+r':\[[0-9]+\]',box[key]) is not None and re.fullmatch(kind+r':\[[0-9]+\]',before[key]) is not None and box[key]!=before[key])
    need(re.fullmatch('[a-f0-9]{64}',before['resolvSHA256']) is not None)
    need(type(box['goRoot']) is str and Path(box['goRoot']).is_absolute() and '..' not in Path(box['goRoot']).parts)
    state=decode(raw['profile-state.json']);need(exact(state,['schema','sourceCommit','stopReason','startedAt','stoppedAt','durationNanoseconds','profileBytes','profileSHA256',
        'writerFailed','limitReached','syncSucceeded','closeSucceeded','complete','timerSeconds','testTimeoutSeconds']))
    need(state['schema']=='chengwang.capacity-cpu-profile-state/v1' and state['sourceCommit']==commit and state['stopReason'] in ('TIMER_60_SECONDS','M_RUN_RETURNED'))
    need(state['writerFailed'] is state['limitReached'] is False and state['syncSucceeded'] is state['closeSucceeded'] is state['complete'] is True)
    need(type(state['timerSeconds']) is type(state['testTimeoutSeconds']) is int and state['timerSeconds']==60 and state['testTimeoutSeconds']==180)
    need(integer(state['durationNanoseconds'],1,180000000000))
    if state['stopReason']=='TIMER_60_SECONDS':need(state['durationNanoseconds']>=60000000000)
    for key in ('startedAt','stoppedAt'):need(type(state[key]) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state[key]) is not None)
    need(datetime.datetime.fromisoformat(state['stoppedAt'].replace('Z','+00:00'))>=datetime.datetime.fromisoformat(state['startedAt'].replace('Z','+00:00')))
    profile=decode(raw['cpu-profile.json']);need(exact(profile,['schema','sourceCommit','bytes','sha256','dataBase64','profileStateSHA256']))
    need(profile['schema']=='chengwang.capacity-cpu-profile-bytes/v1' and profile['sourceCommit']==commit and type(profile['dataBase64']) is str)
    binary=base64.b64decode(profile['dataBase64'],validate=True)
    need(base64.b64encode(binary).decode()==profile['dataBase64'] and integer(profile['bytes'],1,8<<20) and integer(state['profileBytes'],1,8<<20) and len(binary)==profile['bytes']==state['profileBytes'])
    need(profile['sha256']==state['profileSHA256']==sha(binary) and profile['profileStateSHA256']==sha(raw['profile-state.json']))
    shape=profile_shape(binary)
    rows=[decode(line) for line in raw['commands.jsonl'].splitlines()];need(len(rows)==15)
    go=str(Path(box['goRoot'])/'bin/go')
    expected=[('VERSION',[go,'version'],'versionExit'),('FORMAT',[str(Path(box['goRoot'])/'bin/gofmt'),'-d','internal/mihomodeploy/lifecycle_capacity_profile_linux_test.go'],'formatExit'),
        ('GO_TEST',[go,*GO_ARGS],'goExit'),('PPROF_TOP',[go,'tool','pprof','-symbolize=local','-top',PRIVATE+'/cpu.pprof'],'topExit'),
        ('PPROF_CUM',[go,'tool','pprof','-symbolize=local','-top','-cum',PRIVATE+'/cpu.pprof'],'cumExit')]
    previous=0
    for i,(kind,argv,exitkey) in enumerate(expected):
        group=rows[3*i:3*i+3]
        for j,row in enumerate(group):
            need(exact(row,['seq','event','class','argv','pid','exitCode','monotonicNs']) and type(row['seq']) is int and row['seq']==3*i+j+1)
            need(row['class']==kind and row['argv']==argv and integer(row['monotonicNs'],previous));previous=row['monotonicNs']
        need([r['event'] for r in group]==['START_INTENT','STARTED','WAIT_RETURNED'])
        need(group[0]['pid'] is group[0]['exitCode'] is None and integer(group[1]['pid'],2) and group[1]['exitCode'] is None)
        need(integer(group[2]['pid'],2,(1<<31)-1) and group[2]['pid']==group[1]['pid'] and type(group[2]['exitCode']) is int and group[2]['exitCode']==e[exitkey])
    events=[decode(line) for line in raw['capacity.json'].splitlines()]
    need(events and all(type(v) is dict and set(v)<={'Time','Action','Package','Test','Elapsed','Output'} and v.get('Package')==PACKAGE and v.get('Action') in ('start','run','pass','fail','output') for v in events))
    begun=False;ended=False;test_state=None
    for row in events:
        need(not ended and type(row.get('Time')) is str and row['Time'].endswith('Z'))
        datetime.datetime.fromisoformat(row['Time'].replace('Z','+00:00'))
        if 'Elapsed' in row:need(type(row['Elapsed']) in (int,float) and math.isfinite(row['Elapsed']) and row['Elapsed']>=0)
        action=row['Action'];name=row.get('Test')
        if action=='start':need(not begun and name is None);begun=True;continue
        need(begun)
        if name is not None:
            need(name==TOP)
            if action=='run':need(test_state is None);test_state='run'
            elif action in ('pass','fail'):need(test_state=='run');test_state=action
            else:need(action=='output' and test_state is not None and type(row.get('Output')) is str)
        elif action in ('pass','fail'):
            if action=='pass':need(test_state=='pass')
            ended=True
        else:need(action=='output' and type(row.get('Output')) is str)
    need(ended)
    test_events=[v for v in events if v.get('Test') is not None];need(all(v['Test']==TOP for v in test_events))
    need(sum(v['Action']=='run' for v in test_events)==1 and not any(v['Action']=='skip' for v in events))
    terminal=[v['Action'] for v in events if v.get('Test') is None and v['Action'] in ('pass','fail')];need(len(terminal)==1)
    passed=sum(v['Action']=='pass' for v in test_events);failed=sum(v['Action']=='fail' for v in test_events);need(passed<=1 and failed<=1 and not(passed and failed))
    case_pass=e['goExit']==0 and passed==1 and terminal==['pass'] and failed==0
    need((e['goExit']==0)==case_pass)
    text=''.join(v.get('Output','') for v in events)
    for name in ('pprof-top.txt','pprof-cum.txt'):
        value=raw[name].decode('utf8','strict');need(value.strip() and 'flat' in value and 'cum' in value)
    return {'schema':'chengwang.capacity-profile-verification/v1','scope':'CPU_DIAGNOSIS_OF_ORIGINAL_STRUCTURAL_CAPACITY_TEST_NOT_RECOVERY_OR_PRODUCTION',
        'sourceCommit':commit,'captureVerified':True,'originalCasePassed':case_pass,'originalGoExit':e['goExit'],
        'testRun':1,'testPass':passed,'testFailureEvents':failed,'packageTerminal':terminal[0],
        'packageTimeoutObserved':'panic: test timed out after 3m0s' in text,'dataRaceWarningObserved':'WARNING: DATA RACE' in text,
        'formatClean':e['formatExit']==0 and raw['gofmt.patch']==raw['gofmt.stderr']==b'',
        'profile':shape,'profileSHA256':sha(binary),'inputSHA256':{p:sha(v) for p,v in raw.items()},
        'pprofNumericRecomputeProven':False,
        'nativeKernelExecuted':False,'wholeCIPass':False,'production':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['host','source','verify']);p.add_argument('--out',type=Path);p.add_argument('--repo',type=Path);p.add_argument('--source-commit');p.add_argument('--evidence',type=Path);p.add_argument('--report',type=Path);a=p.parse_args()
    need(os.name=='posix')
    if a.mode=='host':write(a.out,encoded(host()));return
    if a.mode=='source':write(a.out,encoded(source_snapshot(a.repo,a.source_commit)));return
    need(set(v.name for v in a.evidence.iterdir())==set(PUBLIC))
    need(a.report.is_absolute() and not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.evidence))
    raw={name:read(a.evidence/name,12<<20 if name=='cpu-profile.json' else 64<<20 if name=='capacity.json' else 2<<20) for name in PUBLIC}
    sources=source_snapshot(a.repo,a.source_commit)
    need(raw['source-before.json']==raw['source-after.json']==encoded(sources))
    report=verify_raw(raw,a.source_commit)
    need(all(read(a.evidence/name,len(value))==value for name,value in raw.items()) and source_snapshot(a.repo,a.source_commit)==sources)
    report['sourceManifestSHA256']=sha(encoded(sources));report['sourceGitVerified']=True
    write(a.report,encoded(report));print('CAPACITY_PROFILE_EVIDENCE=VERIFIED original_case_passed='+str(report['originalCasePassed']).lower()+' not_whole_ci=true')
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('CAPACITY_PROFILE_EVIDENCE=REJECTED raw_error_suppressed=true') from None
