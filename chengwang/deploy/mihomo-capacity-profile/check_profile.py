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
import types
import zlib

TOP='TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop'
PACKAGE='chengwang/internal/mihomodeploy'
PRIVATE='/tmp/chengwang-capacity-profile-private'
TAG='chengwang_capacity_profile'
GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags',TAG,'-run','^'+TOP+'$','./internal/mihomodeploy']
FULL_PACKAGES=['./internal/adapter/mihomo','./internal/mihomodeploy','./internal/authn','./internal/api','./internal/serverruntime','./internal/authz']
FULL_GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags',TAG,'-run','^Test',*FULL_PACKAGES]
FULL_REQUIRED_PIN='8319dfde365203ae1ae268b1a5d0a3938719bcd0671586bc66840ce2a20863c3'
NORMAL_CHECKER='chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py'
PUBLIC=('host-before.json','host-after.json','source-before.json','source-after.json','sandbox.json','go-version.txt',
    'gofmt.patch','gofmt.stderr','capacity.json','capacity.stderr','commands.jsonl','execution.json',
    'profile-state.json','cpu-profile.json','pprof-top.txt','pprof-top.stderr','pprof-cum.txt','pprof-cum.stderr')
RESOURCE_NAMES=('resource-before.json','resource-after.json')
RESOURCE_SCOPES={'cpuCount':'CAPTURE_PROCESS_OS_LOGICAL_CPU_COUNT','affinityCPUs':'CAPTURE_PROCESS_AFFINITY_NOT_MEASURED_GO_PID',
    'procStatCPU':'KERNEL_EXPOSED_AGGREGATE_CPU_TICKS_NOT_PROCESS','cgroupCPUMax':'CURRENT_CGROUP_FAIR_BANDWIDTH_NOT_EFFECTIVE_ANCESTOR_LIMIT',
    'cgroupCPUStat':'CURRENT_CGROUP_USAGE_AND_OWN_BANDWIDTH_COUNTERS_NOT_PER_TEST'}
CPU_STAT_FIELDS=('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')
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

def profile_shape(raw,diagnostic_mode='SINGLE_CASE'):
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
    names=[strings[i] for i in function_names]
    if diagnostic_mode=='SINGLE_CASE':need(PACKAGE+'.'+TOP in names)
    else:need(any(name.startswith(PACKAGE+'.')for name in names))
    result={'sampleRecords':samples,'functions':len(function_names),'durationNanoseconds':duration,'profileLabelsPresent':False}
    if diagnostic_mode=='FULL_CONTRACTS':result.update({'capacityFunctionInProfile':PACKAGE+'.'+TOP in names,'sampledProcessPackage':PACKAGE})
    return result

def load_normal_checker(sources=None):
    # Execute only this fixed repository-owned checker, never Python supplied
    # in an uploaded evidence/source dictionary. CLI binds it to actual Git.
    path=Path(__file__).resolve().parents[1]/'mihomo-lifecycle-lab/check_contracts.py'
    code=read(path,1<<20)
    if sources is not None:need(type(sources)is dict and sources.get(NORMAL_CHECKER)==code)
    module=types.ModuleType('_actual_bound_normal_contract_checker');module.__file__=str(path)
    exec(compile(code,str(path),'exec'),module.__dict__)
    need(module.PACKAGES=={'chengwang'+p[1:]for p in FULL_PACKAGES} and len(module.FILES)==len(set(module.FILES))==112)
    return module

def full_source_contract(sources,manifest):
    checker=load_normal_checker(sources);need(set(sources)==set(checker.FILES))
    need(type(manifest)is dict and type(manifest.get('files'))is list)
    files={row['path']:row for row in manifest['files']};need(len(files)==len(manifest['files']))
    need(all(path in files and files[path]['sha256']==sha(raw) and files[path]['bytes']==len(raw)for path,raw in sources.items()))
    required=checker.required_names(sources)
    names=sorted(package+'::'+name for package,items in required.items()for name in items)
    need(set(required)==checker.PACKAGES and len(names)==585 and sha('\n'.join(names).encode())==FULL_REQUIRED_PIN)
    # -run '^Test' is equivalent to the current normal test selection only
    # because none of the six packages declares Example/Fuzz entry points.
    # Audit ALL package test files bound by the complete Git manifest, not
    # only the 40 mandatory files. A future new entry point fails closed and
    # needs an explicit diagnostic-contract upgrade instead of silent omission.
    package_dirs={'chengwang'+p[1:]for p in FULL_PACKAGES};suite_test_sources={}
    repo=Path(__file__).resolve().parents[3]
    for path,row in files.items():
        if path.rsplit('/',1)[0]not in package_dirs or not path.endswith('_test.go'):continue
        need(not Path(path).is_absolute()and '..'not in Path(path).parts)
        data=read(repo/path,1<<20);need(row['sha256']==sha(data)and row['bytes']==len(data))
        text=data.decode('utf8')
        masked=re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'',lambda m:''.join('\n'if c=='\n'else' 'for c in m[0]),text)
        need(re.search(r'\bfunc\s+(?:Example|Fuzz)\w*\s*\(',masked)is None)
        suite_test_sources[path]=sha(data)
    need(suite_test_sources and all(any(p.rsplit('/',1)[0]==directory for p in suite_test_sources)for directory in package_dirs))
    # Bind the diagnosis's six-package command to the unchanged normal race
    # command, allowing only the fixed diagnostic tag and test filter.
    normal='"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s '+' '.join(FULL_PACKAGES)+' > "$out/race.json" 2> "$out/race.stderr"'
    need(sources['chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh'].decode().splitlines().count(normal)==1)
    return checker,required,{'sourceCount':len(sources),'mandatoryTopLevelCount':585,'mandatoryNamesSHA256':FULL_REQUIRED_PIN,
        'normalCheckerSHA256':sha(sources[NORMAL_CHECKER]),'normalRunContractsSHA256':sha(sources['chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh']),
        'completePackageTestSourceCount':len(suite_test_sources),'completePackageTestSourceSHA256':suite_test_sources,
        'noExampleOrFuzzDeclarationInBoundSixPackageTestSources':True}

def full_events(raw,required,checker,go_exit,stderr=b''):
    # Diagnostic partial-reader: accept coherent failed/unfinished originals,
    # never translate them into C.events acceptance. Extra legitimate top or
    # subtests are allowed just as in the original checker; 585 is a subset.
    need(type(raw)is bytes and 0<len(raw)<=64<<20 and type(stderr)is bytes and integer(go_exit,-128,255))
    packages=checker.PACKAGES;begun=set();terminals={};states={};outputs={p:[]for p in packages}
    for line in raw.splitlines():
        need(0<len(line)<=1<<20);row=decode(line)
        need(type(row)is dict and set(row)<={'Time','Action','Package','Test','Elapsed','Output'} and row.get('Package')in packages)
        package=row['Package'];action=row.get('Action');name=row.get('Test')
        need(action in ('start','run','pause','cont','pass','fail','skip','output'))
        need(type(row.get('Time'))is str and row['Time'].endswith('Z'));datetime.datetime.fromisoformat(row['Time'].replace('Z','+00:00'))
        if 'Elapsed'in row:need(type(row['Elapsed'])in(int,float)and math.isfinite(row['Elapsed'])and row['Elapsed']>=0)
        if action=='start':need(name is None and package not in begun);begun.add(package);continue
        need(package in begun and package not in terminals)
        if name is not None:
            need(type(name)is str and 0<len(name)<=512);key=(package,name)
            if action=='run':need(key not in states and len(states)<65536);states[key]='run'
            elif action=='pause':need(states.get(key)=='run');states[key]='pause'
            elif action=='cont':need(states.get(key)=='pause');states[key]='run'
            elif action in ('pass','fail','skip'):need(states.get(key)=='run');states[key]=action
            else:need(action=='output'and key in states and type(row.get('Output'))is str)
        elif action in ('pass','fail','skip'):
            if action=='pass':need(all(v in ('pass','skip')for k,v in states.items()if k[0]==package))
            if action=='skip':need(not any(k[0]==package for k in states))
            terminals[package]=action
        else:need(action=='output'and type(row.get('Output'))is str)
        if action=='output':outputs[package].append(row['Output'])
    need(PACKAGE in begun)
    required_sets={key:[]for key in ('passed','failed','skipped','unfinished','notStarted')}
    for package,items in required.items():
        for name in items:
            state=states.get((package,name));bucket={'pass':'passed','fail':'failed','skip':'skipped','run':'unfinished','pause':'unfinished',None:'notStarted'}[state]
            required_sets[bucket].append(package+'::'+name)
    need(sum(map(len,required_sets.values()))==585)
    for items in required_sets.values():items.sort()
    unfinished=sorted(p+'::'+n for (p,n),state in states.items()if state in ('run','pause'));need(len(unfinished)<=4096)
    failed=sorted(p+'::'+n for (p,n),state in states.items()if state=='fail');need(len(failed)<=4096)
    skipped=sorted(p+'::'+n for (p,n),state in states.items()if state=='skip');need(len(skipped)<=4096)
    structurally_complete=begun==packages and set(terminals)==packages and all(v=='pass'for v in terminals.values()) and all(v=='pass'for v in states.values()) and len(required_sets['passed'])==585
    strict=None
    if structurally_complete:strict=checker.events(raw,required) # actual original strict gate, no exception-to-pass adapter
    if go_exit==0:need(begun==packages and set(terminals)==packages and all(v in ('pass','skip')for v in terminals.values()) and all(v in ('pass','skip')for v in states.values()))
    text_by_package={p:''.join(parts)for p,parts in outputs.items()};stderr_text=stderr.decode('utf8','strict')
    race_warning=any('WARNING: DATA RACE'in text for text in text_by_package.values())or'WARNING: DATA RACE'in stderr_text
    accepted=go_exit==0 and strict is not None and stderr==b'' and not race_warning
    return {'fullGoAccepted':accepted,'normalStrictEventsAccepted':strict is not None,'normalStrictEventsReport':strict,
        'requiredCounts':{key:len(items)for key,items in required_sets.items()},'requiredNames':required_sets,
        'observedSemanticStates':len(states),'allUnfinishedNames':unfinished,'allFailedNames':failed,'allSkippedNames':skipped,
        'packageStates':{p:terminals.get(p,'UNFINISHED'if p in begun else'NOT_STARTED')for p in sorted(packages)},
        'capacityCaseState':states.get((PACKAGE,TOP),'NOT_STARTED'),'packageTimeoutObserved':{p:'panic: test timed out after 3m0s'in text_by_package[p]for p in sorted(packages)},
        'dataRaceWarningObserved':race_warning,'originalGoExit':go_exit,'nonRequiredStatesRetainedInOriginalJSON':True}

def verify_resource(raw):
    need(type(raw)is bytes and 0<len(raw)<=65536);v=decode(raw)
    need(exact(v,['schema','diagnosticMode','scope','startedMonotonicNs','finishedMonotonicNs','observations']))
    need(v['schema']=='chengwang.capacity-profile-resources/v1'and v['diagnosticMode']=='FULL_CONTRACTS'and v['scope']=='CAPTURE_PROCESS_AND_KERNEL_CGROUP_AGGREGATES_NOT_PER_TEST_NOT_ATOMIC')
    need(integer(v['startedMonotonicNs'])and integer(v['finishedMonotonicNs'],v['startedMonotonicNs']))
    need(exact(v['observations'],RESOURCE_SCOPES))
    unavailable=('CGROUP_V2_UNAVAILABLE','CGROUP_V2_NOT_MAPPED','CGROUP_READ_UNAVAILABLE','CGROUP_FILE_UNAVAILABLE')
    for name,row in v['observations'].items():
        need(exact(row,['scope','value','reason'])and row['scope']==RESOURCE_SCOPES[name]);data=row['value'];reason=row['reason']
        if data is None:need(reason in (('VALUE_UNAVAILABLE',)if name in ('cpuCount','affinityCPUs')else('KERNEL_VALUE_UNAVAILABLE',)if name=='procStatCPU'else unavailable));continue
        if name=='cpuCount':need(reason=='NONE'and integer(data,1,1<<20))
        elif name=='affinityCPUs':need(reason=='NONE'and type(data)is list and 1<=len(data)<=4096 and all(integer(n,0,1<<20)for n in data)and data==sorted(set(data)))
        elif name=='procStatCPU':need(reason=='NONE'and exact(data,['user','system','idle','iowait','steal'])and all(integer(n)for n in data.values()))
        elif name=='cgroupCPUMax':
            need(reason=='NONE'and exact(data,['quotaMicros','periodMicros','unlimited'])and type(data['unlimited'])is bool and integer(data['periodMicros'],1))
            need((data['quotaMicros']is None)==data['unlimited']and(data['quotaMicros']is None or integer(data['quotaMicros'],1)))
        else:
            need(exact(data,CPU_STAT_FIELDS)and any(n is not None for n in data.values())and all(n is None or integer(n)for n in data.values()))
            need(reason==('NONE'if all(n is not None for n in data.values())else'PARTIAL_FIELDS'))
    return v

def verify_raw(raw,commit,diagnostic_mode='SINGLE_CASE',sources=None):
    need(diagnostic_mode in ('SINGLE_CASE','FULL_CONTRACTS'));full=diagnostic_mode=='FULL_CONTRACTS'
    public=PUBLIC+(RESOURCE_NAMES if full else())
    need(set(raw)==set(public) and sum(map(len,raw.values()))<=64<<20)
    e=decode(raw['execution.json']);need(exact(e,['schema','sourceCommit','versionExit','formatExit','goExit','topExit','cumExit','profileCaptureComplete','production']+(['diagnosticMode']if full else[])))
    need(e['schema']==('chengwang.capacity-profile-execution/v2'if full else'chengwang.capacity-profile-execution/v1') and e['sourceCommit']==commit and e['production'] is False)
    if full:need(e['diagnosticMode']=='FULL_CONTRACTS')
    need(all(integer(e[k],-128,255) for k in ('versionExit','formatExit','goExit','topExit','cumExit')) and e['versionExit']==e['topExit']==e['cumExit']==0)
    need(e['profileCaptureComplete'] is True and raw['go-version.txt']==b'go version go1.23.12 linux/amd64\n')
    before,after=decode(raw['host-before.json']),decode(raw['host-after.json']);need(before==after and exact(before,['networkNamespace','mountNamespace','pidNamespace','resolvSHA256']))
    box=decode(raw['sandbox.json']);need(exact(box,['schema','uid','gid','effectiveCaps','noNewPrivileges','interfaces','defaultRoutes','environmentKeys',
        'sourceAliasReadOnly','goRootReadOnly','goRoot','networkNamespace','mountNamespace','pidNamespace','production']))
    need(box['schema']=='chengwang.capacity-profile-sandbox/v1' and type(box['uid']) is type(box['gid']) is int and box['uid']==box['gid']==10001)
    need(box['effectiveCaps']=='0000000000000000' and box['noNewPrivileges'] is True and box['interfaces']==['lo'] and box['defaultRoutes']=={'ipv4':[],'ipv6':[]})
    need(box['environmentKeys']==sorted(ENV+(['CHENGWANG_CAPACITY_PROFILE_MODE']if full else[])) and box['sourceAliasReadOnly'] is box['goRootReadOnly'] is True and box['production'] is False)
    for key,kind in [('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')]:
        need(re.fullmatch(kind+r':\[[0-9]+\]',box[key]) is not None and re.fullmatch(kind+r':\[[0-9]+\]',before[key]) is not None and box[key]!=before[key])
    need(re.fullmatch('[a-f0-9]{64}',before['resolvSHA256']) is not None)
    need(type(box['goRoot']) is str and Path(box['goRoot']).is_absolute() and '..' not in Path(box['goRoot']).parts)
    state=decode(raw['profile-state.json']);need(exact(state,['schema','sourceCommit','stopReason','startedAt','stoppedAt','durationNanoseconds','profileBytes','profileSHA256',
        'writerFailed','limitReached','syncSucceeded','closeSucceeded','complete','timerSeconds','testTimeoutSeconds']+(['diagnosticMode']if full else[])))
    timer=120 if full else 60
    need(state['schema']==('chengwang.capacity-cpu-profile-state/v2'if full else'chengwang.capacity-cpu-profile-state/v1') and state['sourceCommit']==commit and state['stopReason'] in ('TIMER_'+str(timer)+'_SECONDS','M_RUN_RETURNED'))
    if full:need(state['diagnosticMode']=='FULL_CONTRACTS')
    need(state['writerFailed'] is state['limitReached'] is False and state['syncSucceeded'] is state['closeSucceeded'] is state['complete'] is True)
    need(type(state['timerSeconds']) is type(state['testTimeoutSeconds']) is int and state['timerSeconds']==timer and state['testTimeoutSeconds']==180)
    need(integer(state['durationNanoseconds'],1,180000000000))
    if state['stopReason']=='TIMER_'+str(timer)+'_SECONDS':need(state['durationNanoseconds']>=timer*1000000000)
    for key in ('startedAt','stoppedAt'):need(type(state[key]) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state[key]) is not None)
    need(datetime.datetime.fromisoformat(state['stoppedAt'].replace('Z','+00:00'))>=datetime.datetime.fromisoformat(state['startedAt'].replace('Z','+00:00')))
    profile=decode(raw['cpu-profile.json']);need(exact(profile,['schema','sourceCommit','bytes','sha256','dataBase64','profileStateSHA256']))
    need(profile['schema']=='chengwang.capacity-cpu-profile-bytes/v1' and profile['sourceCommit']==commit and type(profile['dataBase64']) is str)
    binary=base64.b64decode(profile['dataBase64'],validate=True)
    need(base64.b64encode(binary).decode()==profile['dataBase64'] and integer(profile['bytes'],1,8<<20) and integer(state['profileBytes'],1,8<<20) and len(binary)==profile['bytes']==state['profileBytes'])
    need(profile['sha256']==state['profileSHA256']==sha(binary) and profile['profileStateSHA256']==sha(raw['profile-state.json']))
    shape=profile_shape(binary,diagnostic_mode)
    rows=[decode(line) for line in raw['commands.jsonl'].splitlines()];need(len(rows)==15)
    go=str(Path(box['goRoot'])/'bin/go')
    expected=[('VERSION',[go,'version'],'versionExit'),('FORMAT',[str(Path(box['goRoot'])/'bin/gofmt'),'-d','internal/mihomodeploy/lifecycle_capacity_profile_linux_test.go'],'formatExit'),
        ('GO_TEST',[go,*(FULL_GO_ARGS if full else GO_ARGS)],'goExit'),('PPROF_TOP',[go,'tool','pprof','-symbolize=local','-top',PRIVATE+'/cpu.pprof'],'topExit'),
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
    for name in ('pprof-top.txt','pprof-cum.txt'):
        value=raw[name].decode('utf8','strict');need(value.strip() and 'flat'in value and 'cum'in value)
    if full:
        checker,required,binding=full_source_contract(sources,decode(raw['source-before.json']))
        summary=full_events(raw['capacity.json'],required,checker,e['goExit'],raw['capacity.stderr'])
        resource_before,resource_after=verify_resource(raw['resource-before.json']),verify_resource(raw['resource-after.json'])
        need(resource_before['finishedMonotonicNs']<=rows[6]['monotonicNs']<=rows[8]['monotonicNs']<=resource_after['startedMonotonicNs'])
        return {'schema':'chengwang.capacity-profile-verification/v2','diagnosticMode':'FULL_CONTRACTS',
            'scope':'FULL_SIX_PACKAGE_RACE_DIAGNOSIS_WITH_MIHOMODEPLOY_ONLY_CPU_WINDOW_NOT_PRODUCT_ACCEPTANCE',
            'sourceCommit':commit,'captureVerified':True,**summary,'normalSourceBinding':binding,
            'formatClean':e['formatExit']==0 and raw['gofmt.patch']==raw['gofmt.stderr']==b'',
            'profile':shape,'profileSHA256':sha(binary),'profileProcessPackage':PACKAGE,'profileTimerSeconds':120,
            'profileStopReason':state['stopReason'],'profileMeasuredDurationNanoseconds':state['durationNanoseconds'],
            'wholeSixPackageCPUProfileProven':False,'wholeTestDurationProfileProven':False,
            'resources':{'before':resource_before,'after':resource_after,'window':'BEFORE_AFTER_GO_CLI_INCLUDING_COMPILATION_AND_SIX_PACKAGES_NOT_PROFILE_WINDOW',
                'sameCgroupAcrossObservationsIndependentlyProven':False,'resourceCauseProven':False},
            'inputSHA256':{p:sha(v)for p,v in raw.items()},'pprofNumericRecomputeProven':False,
            'nativeKernelExecuted':False,'normal13WorkflowAccepted':False,'wholeCIPass':False,'production':False}
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
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['host','source','verify']);p.add_argument('--out',type=Path);p.add_argument('--repo',type=Path);p.add_argument('--source-commit');p.add_argument('--evidence',type=Path);p.add_argument('--report',type=Path);p.add_argument('--diagnostic-mode',choices=['SINGLE_CASE','FULL_CONTRACTS'],default='SINGLE_CASE');a=p.parse_args()
    need(os.name=='posix')
    if a.mode=='host':write(a.out,encoded(host()));return
    if a.mode=='source':write(a.out,encoded(source_snapshot(a.repo,a.source_commit)));return
    public=PUBLIC+(RESOURCE_NAMES if a.diagnostic_mode=='FULL_CONTRACTS'else())
    need(set(v.name for v in a.evidence.iterdir())==set(public))
    need(a.report.is_absolute() and not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.evidence))
    raw={name:read(a.evidence/name,12<<20 if name=='cpu-profile.json' else 64<<20 if name=='capacity.json' else 2<<20) for name in public}
    sources=source_snapshot(a.repo,a.source_commit)
    need(raw['source-before.json']==raw['source-after.json']==encoded(sources))
    normal_sources=None
    if a.diagnostic_mode=='FULL_CONTRACTS':
        checker=load_normal_checker();normal_sources={p:read(a.repo/p,1<<20)for p in checker.FILES}
    report=verify_raw(raw,a.source_commit,a.diagnostic_mode,normal_sources)
    need(all(read(a.evidence/name,len(value))==value for name,value in raw.items()) and source_snapshot(a.repo,a.source_commit)==sources)
    report['sourceManifestSHA256']=sha(encoded(sources));report['sourceGitVerified']=True
    write(a.report,encoded(report))
    if a.diagnostic_mode=='FULL_CONTRACTS':print('CAPACITY_PROFILE_EVIDENCE=VERIFIED diagnostic_mode=FULL_CONTRACTS full_go_accepted='+str(report['fullGoAccepted']).lower()+' not_whole_ci=true')
    else:print('CAPACITY_PROFILE_EVIDENCE=VERIFIED original_case_passed='+str(report['originalCasePassed']).lower()+' not_whole_ci=true')
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('CAPACITY_PROFILE_EVIDENCE=REJECTED raw_error_suppressed=true') from None
