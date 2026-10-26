"""CI-only fixed CPU diagnosis capture. No producer/config/WAL upload."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

PRIVATE=Path('/tmp/chengwang-capacity-profile-private')
SOURCE=Path('/tmp/chengwang-capacity-profile-source')
TOP='TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop'
GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags','chengwang_capacity_profile','-run','^'+TOP+'$','./internal/mihomodeploy']
FULL_PACKAGES=['./internal/adapter/mihomo','./internal/mihomodeploy','./internal/authn','./internal/api','./internal/serverruntime','./internal/authz']
FULL_GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags','chengwang_capacity_profile','-run','^Test',*FULL_PACKAGES]
CAPACITY_FMT=['internal/mihomodeploy/lifecycle_capacity_profile_linux_test.go']
FULL_FMT=[*CAPACITY_FMT,
    'internal/authn/continuous_bound_credentials_linux.go',
    'internal/authn/continuous_bound_credentials_linux_test.go',
    'internal/authn/store.go',
    'internal/mihomodeploy/lifecycle_recovery_checkpoint.go',
    'internal/mihomodeploy/lifecycle_recovery_completion.go',
    'internal/mihomodeploy/lifecycle_recovery_completion_test.go',
    'internal/mihomodeploy/lifecycle_completion_shape_diagnostic_test.go',
    'internal/mihomodeploy/lifecycle_v3_decode_scope_test.go',
    'internal/mihomodeploy/lifecycle_current_epoch.go',
    'internal/mihomodeploy/lifecycle_current_epoch_test.go',
    'internal/mihomodeploy/lab_current_epoch_runtime.go',
    'internal/mihomodeploy/lab_current_epoch_runtime_test.go',
    'internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
    'internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
    'internal/mihomodeploy/lab_service.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'internal/serverruntime/runtime.go',
    'internal/serverruntime/mihomo_lab_runtime.go',
    'internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go']
RAW_NAMES=('go-version.txt','gofmt.patch','gofmt.stderr','capacity.json','capacity.stderr',
    'commands.jsonl','execution.json','profile-state.json','pprof-top.txt','pprof-top.stderr','pprof-cum.txt','pprof-cum.stderr')
RESOURCE_NAMES=('resource-before.json','resource-after.json')
RESOURCE_SCOPES={'cpuCount':'CAPTURE_PROCESS_OS_LOGICAL_CPU_COUNT','affinityCPUs':'CAPTURE_PROCESS_AFFINITY_NOT_MEASURED_GO_PID',
    'procStatCPU':'KERNEL_EXPOSED_AGGREGATE_CPU_TICKS_NOT_PROCESS','cgroupCPUMax':'CURRENT_CGROUP_FAIR_BANDWIDTH_NOT_EFFECTIVE_ANCESTOR_LIMIT',
    'cgroupCPUStat':'CURRENT_CGROUP_USAGE_AND_OWN_BANDWIDTH_COUNTERS_NOT_PER_TEST'}
CPU_STAT_FIELDS=('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')

def need(ok):
    if not ok:raise ValueError('capacity profile capture rejected')
def digest(raw):return hashlib.sha256(raw).hexdigest()
def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as f:need(f.write(raw)==len(raw));f.flush();os.fsync(f.fileno())
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def private_read(path,limit):
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==10001 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=limit)
    with path.open('rb') as f:opened=os.fstat(f.fileno());raw=f.read(limit+1);after=os.fstat(f.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_gid,s.st_mode,s.st_nlink)
    need(identity(before)==identity(opened)==identity(after)==identity(path.lstat()) and len(raw)==before.st_size)
    return raw

def kernel_text(path,limit):
    with Path(path).open('rb') as f:raw=f.read(limit+1)
    need(len(raw)<=limit);return raw.decode('utf8','strict')

def current_cgroup_v2():
    # Resolve the actual membership relative to the actual cgroup2 mount root.
    # An unmappable cgroup namespace is unavailable, never guessed as host '/'.
    memberships=[line.split(':',2)[2] for line in kernel_text('/proc/self/cgroup',65536).splitlines() if line.startswith('0::')]
    if len(memberships)!=1:return None,'CGROUP_V2_UNAVAILABLE'
    member=PurePosixPath(memberships[0]);need(member.is_absolute() and '..'not in member.parts)
    candidates=[]
    def unescape(value):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)
    for line in kernel_text('/proc/self/mountinfo',4<<20).splitlines():
        parts=line.split(' - ',1)
        if len(parts)!=2:continue
        tail=parts[1].split()
        if not tail or tail[0]!='cgroup2':continue
        fields=parts[0].split();need(len(fields)>=6)
        root=PurePosixPath(unescape(fields[3]));mount=Path(unescape(fields[4]))
        need(root.is_absolute() and '..'not in root.parts and mount.is_absolute() and '..'not in mount.parts)
        if not member.is_relative_to(root):continue
        candidate=mount.joinpath(*member.relative_to(root).parts)
        if candidate.is_dir() and not candidate.is_symlink() and candidate.resolve().is_relative_to(mount.resolve()):candidates.append((len(root.parts),candidate))
    if not candidates:return None,'CGROUP_V2_NOT_MAPPED'
    deepest=max(n for n,_ in candidates);paths={p for n,p in candidates if n==deepest}
    if len(paths)!=1:return None,'CGROUP_V2_NOT_MAPPED'
    return paths.pop(),'NONE'

def resource_observation():
    started=time.monotonic_ns();fields={}
    def value(name,data,reason='NONE'):fields[name]={'scope':RESOURCE_SCOPES[name],'value':data,'reason':reason}
    def counter(text):need(re.fullmatch('[0-9]{1,20}',text) is not None);n=int(text);need(n<1<<63);return n
    count=os.cpu_count()
    value('cpuCount',count if type(count)is int and 1<=count<=1<<20 else None,'NONE' if type(count)is int and 1<=count<=1<<20 else 'VALUE_UNAVAILABLE')
    try:
        affinity=sorted(os.sched_getaffinity(0));need(1<=len(affinity)<=4096 and all(type(n)is int and 0<=n<=1<<20 for n in affinity))
        value('affinityCPUs',affinity)
    except (OSError,ValueError,AttributeError):value('affinityCPUs',None,'VALUE_UNAVAILABLE')
    try:
        rows=[line.split()for line in kernel_text('/proc/stat',1<<20).splitlines()if line.startswith('cpu ')]
        need(len(rows)==1 and len(rows[0])>=9)
        value('procStatCPU',{name:counter(rows[0][index+1])for name,index in [('user',0),('system',2),('idle',3),('iowait',4),('steal',7)]})
    except (OSError,ValueError,UnicodeError):value('procStatCPU',None,'KERNEL_VALUE_UNAVAILABLE')
    try:group,reason=current_cgroup_v2()
    except (OSError,ValueError,UnicodeError):group,reason=None,'CGROUP_READ_UNAVAILABLE'
    if group is None:
        value('cgroupCPUMax',None,reason);value('cgroupCPUStat',None,reason)
    else:
        try:
            parts=kernel_text(group/'cpu.max',4096).split();need(len(parts)==2)
            quota=None if parts[0]=='max'else counter(parts[0]);period=counter(parts[1]);need(period>0 and (quota is None or quota>0))
            value('cgroupCPUMax',{'quotaMicros':quota,'periodMicros':period,'unlimited':quota is None})
        except (OSError,ValueError,UnicodeError):value('cgroupCPUMax',None,'CGROUP_FILE_UNAVAILABLE')
        try:
            data={}
            for row in kernel_text(group/'cpu.stat',65536).splitlines():
                parts=row.split();need(len(parts)==2 and parts[0]not in data);data[parts[0]]=counter(parts[1])
            counters={name:data.get(name)for name in CPU_STAT_FIELDS};need(any(v is not None for v in counters.values()))
            value('cgroupCPUStat',counters,'NONE'if all(v is not None for v in counters.values())else'PARTIAL_FIELDS')
        except (OSError,ValueError,UnicodeError):value('cgroupCPUStat',None,'CGROUP_FILE_UNAVAILABLE')
    return {'schema':'chengwang.capacity-profile-resources/v1','diagnosticMode':'FULL_CONTRACTS',
        'scope':'CAPTURE_PROCESS_AND_KERNEL_CGROUP_AGGREGATES_NOT_PER_TEST_NOT_ATOMIC',
        'startedMonotonicNs':started,'finishedMonotonicNs':time.monotonic_ns(),'observations':fields}

def commands(goroot,diagnostic_mode='SINGLE_CASE'):
    seq=0
    def journal(kind,argv,event,pid=None,code=None):
        nonlocal seq
        seq+=1
        value={'seq':seq,'event':event,'class':kind,'argv':argv,'pid':pid,'exitCode':code,'monotonicNs':time.monotonic_ns()}
        with (PRIVATE/'commands.jsonl').open('ab') as f:f.write(encoded(value));f.flush();os.fsync(f.fileno())
    def run(kind,argv,out,err):
        journal(kind,argv,'START_INTENT')
        with (PRIVATE/out).open('xb') as stdout,(PRIVATE/err).open('xb') as stderr:
            # The normal Go suite observes0022. Keep this capture parent077
            # (and its original streams0600), changing only the full GO_TEST
            # child before exec via CPython's POSIX-only umask keyword.
            child_options={'umask':0o022}if diagnostic_mode=='FULL_CONTRACTS'and kind=='GO_TEST'else{}
            p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,**child_options)
            journal(kind,argv,'STARTED',p.pid)
            code=p.wait()
            stdout.flush();os.fsync(stdout.fileno());stderr.flush();os.fsync(stderr.fileno())
        journal(kind,argv,'WAIT_RETURNED',p.pid,code)
        return code
    need(sys.platform=='linux' and os.getuid()==os.getgid()==10001 and Path.cwd()==SOURCE)
    need(os.environ.get('CHENGWANG_CAPACITY_PROFILE_MODE')==('FULL_CONTRACTS'if diagnostic_mode=='FULL_CONTRACTS'else None))
    need(sorted(os.listdir(PRIVATE))==[])
    os.umask(0o077)
    go=str(Path(goroot)/'bin/go')
    version=run('VERSION',[go,'version'],'go-version.txt','version.stderr.private')
    full=diagnostic_mode=='FULL_CONTRACTS'
    fmt=run('FORMAT',[str(Path(goroot)/'bin/gofmt'),'-d',*(FULL_FMT if full else CAPACITY_FMT)],'gofmt.patch','gofmt.stderr')
    if full:
        write(PRIVATE/'resource-before.json',encoded(resource_observation()));os.chmod(PRIVATE/'resource-before.json',0o600)
    code=run('GO_TEST',[go,*(FULL_GO_ARGS if full else GO_ARGS)],'capacity.json','capacity.stderr')
    if full:
        write(PRIVATE/'resource-after.json',encoded(resource_observation()));os.chmod(PRIVATE/'resource-after.json',0o600)
    top=run('PPROF_TOP',[go,'tool','pprof','-symbolize=local','-top',str(PRIVATE/'cpu.pprof')],'pprof-top.txt','pprof-top.stderr')
    cum=run('PPROF_CUM',[go,'tool','pprof','-symbolize=local','-top','-cum',str(PRIVATE/'cpu.pprof')],'pprof-cum.txt','pprof-cum.stderr')
    # Profile completeness is observed independently from the test's exit code.
    complete=None
    if (PRIVATE/'profile-state.json').is_file():
        value=json.loads(private_read(PRIVATE/'profile-state.json',16384));complete=value.get('complete')
        need(type(complete) is bool)
    execution={'schema':'chengwang.capacity-profile-execution/v2'if full else'chengwang.capacity-profile-execution/v1',
        'sourceCommit':os.environ['CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT'],'versionExit':version,
        'formatExit':fmt,'goExit':code,'topExit':top,'cumExit':cum,'profileCaptureComplete':complete,'production':False}
    if full:execution['diagnosticMode']='FULL_CONTRACTS'
    write(PRIVATE/'execution.json',encoded(execution))
    # write() is public-mode; correct only this new private file, not host inputs.
    os.chmod(PRIVATE/'execution.json',0o600)

def export(out,diagnostic_mode='SINGLE_CASE'):
    need(sys.platform=='linux' and os.getuid()==0 and out.is_dir())
    # Preserve actual created files, including failures. Never fill missing
    # streams or profiles with empty replacements or fixed status summaries.
    for name in RAW_NAMES+(RESOURCE_NAMES if diagnostic_mode=='FULL_CONTRACTS'else()):
        path=PRIVATE/name
        if path.exists():
            limit=64<<20 if name=='capacity.json' else 1<<20
            raw=private_read(path,limit);raw.decode('utf-8','strict');write(out/name,raw)
    state=PRIVATE/'profile-state.json';profile=PRIVATE/'cpu.pprof'
    if state.exists() and profile.exists():
        state_raw=private_read(state,16384);raw=private_read(profile,8<<20)
        value={'schema':'chengwang.capacity-cpu-profile-bytes/v1','sourceCommit':os.environ['CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT'],
            'bytes':len(raw),'sha256':digest(raw),'dataBase64':base64.b64encode(raw).decode('ascii'),'profileStateSHA256':digest(state_raw)}
        write(out/'cpu-profile.json',encoded(value))

def sandbox(out,goroot,diagnostic_mode='SINGLE_CASE'):
    need(sys.platform=='linux' and os.getuid()==os.getgid()==10001 and Path.cwd()==SOURCE)
    need(os.environ.get('CHENGWANG_CAPACITY_PROFILE_MODE')==('FULL_CONTRACTS'if diagnostic_mode=='FULL_CONTRACTS'else None))
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    interfaces=sorted(name for _,name in socket.if_nameindex())
    ip=shutil.which('ip',path='/usr/sbin:/usr/bin:/sbin:/bin');need(ip is not None)
    defaults={key:json.loads(subprocess.check_output([ip,flag,'-j','route','show','default'])) for key,flag in [('ipv4','-4'),('ipv6','-6')]}
    need(interfaces==['lo'] and defaults=={'ipv4':[],'ipv6':[]} and int(status['CapEff'].strip(),16)==0 and status['NoNewPrivs'].strip()=='1')
    value={'schema':'chengwang.capacity-profile-sandbox/v1','uid':os.getuid(),'gid':os.getgid(),'effectiveCaps':status['CapEff'].strip(),
        'noNewPrivileges':True,'interfaces':interfaces,'defaultRoutes':defaults,'environmentKeys':sorted(os.environ),
        'sourceAliasReadOnly':bool(os.statvfs(SOURCE).f_flag&os.ST_RDONLY),'goRootReadOnly':bool(os.statvfs(goroot).f_flag&os.ST_RDONLY),
        'goRoot':str(goroot),'networkNamespace':os.readlink('/proc/self/ns/net'),'mountNamespace':os.readlink('/proc/self/ns/mnt'),
        'pidNamespace':os.readlink('/proc/self/ns/pid'),'production':False}
    need(value['sourceAliasReadOnly'] and value['goRootReadOnly'])
    sys.stdout.buffer.write(encoded(value))

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['commands','export','sandbox']);p.add_argument('--goroot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--diagnostic-mode',choices=['SINGLE_CASE','FULL_CONTRACTS'],default='SINGLE_CASE');a=p.parse_args()
    if a.mode=='commands':commands(a.goroot,a.diagnostic_mode)
    elif a.mode=='export':export(a.out,a.diagnostic_mode)
    else:sandbox(a.out,a.goroot,a.diagnostic_mode)
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('CAPACITY_PROFILE_CAPTURE=REJECTED raw_error_suppressed=true') from None
