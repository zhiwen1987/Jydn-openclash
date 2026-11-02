#!/usr/bin/env python3
"""Independent current-custody and semantic checker for safe timelines."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import go_timeline_capture as capture

SOURCE_PATHS=(
    '.github/workflows/chengwang-mihomo-capacity-profile.yml',
    '.github/workflows/chengwang-mihomo-lifecycle.yml',
    'chengwang/deploy/mihomo-capacity-profile/check_profile.py',
    'chengwang/deploy/mihomo-capacity-profile/profile_evidence.py',
    'chengwang/deploy/mihomo-capacity-profile/test_profile_contract.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_go_timeline.py',
    'chengwang/deploy/mihomo-lifecycle-lab/go_timeline_capture.py',
    'chengwang/deploy/mihomo-lifecycle-lab/go_timeline_required_tops.json',
    'chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_contracts.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_go_timeline.py',
)
FORBIDDEN_FRAGMENTS=('origin','absolute','monotonicns','boottime','uptime','pid','argv','commandssha','executionsha',
    'publication','published','custody','checker','upload','directoryfsync')
EXACT_MEMBERS={
    'FOUNDATION':(
        capture.FINAL_NAMES['FOUNDATION_ORDINARY'],
        capture.FINAL_NAMES['FOUNDATION_RACE'],
    ),
    'CAPACITY':(capture.FINAL_NAMES['CAPACITY_FULL_RACE'],),
}

def need(value):
    if not value: raise ValueError('timeline rejected')

def read_fd(fd,limit):
    parts=[];total=0
    while True:
        chunk=os.read(fd,min(65536,limit+1-total))
        if not chunk:return b''.join(parts)
        parts.append(chunk);total+=len(chunk);need(total<=limit)

class RawGit:
    def __init__(self, repo): self.repo=Path(repo)
    def run(self,*args,limit=2<<20):
        env=os.environ.copy();env['GIT_NO_REPLACE_OBJECTS']='1'
        result=subprocess.run(['git','--no-replace-objects','-C',str(self.repo),*args],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            shell=False,env=env,timeout=30)
        need(result.returncode==0 and len(result.stdout)<=limit and len(result.stderr)<=1<<20)
        return result.stdout
    def identity(self,commit):
        need(re.fullmatch('[a-f0-9]{40}',commit) is not None)
        actual=self.run('rev-parse','--verify',commit+'^{commit}').decode().strip()
        need(actual==commit)
        tree=self.run('rev-parse',commit+'^{tree}').decode().strip()
        need(re.fullmatch('[a-f0-9]{40}',tree) is not None)
        return tree
    def source(self,commit,path):
        row=self.run('ls-tree',commit,'--',path).decode().strip().split()
        need(len(row)>=4 and row[1]=='blob' and re.fullmatch('[a-f0-9]{40}',row[2]))
        raw=self.run('cat-file','blob',row[2],limit=2<<20)
        need((self.repo/path).read_bytes()==raw)
        return raw

def _dir_signature(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)

def _require_same_dir(left,right):
    need(_dir_signature(left)==_dir_signature(right))

def _require_exact_members(observed,expected):
    need(expected in EXACT_MEMBERS.values())
    need(type(observed)is list and all(type(name)is str for name in observed))
    need(len(observed)==len(set(observed)) and set(observed)==set(expected))

def _member_names(dirfd):
    with os.scandir(dirfd) as entries:
        return [entry.name for entry in entries]

def _require_final_stat(value,parent,size):
    need(stat.S_ISREG(value.st_mode) and stat.S_IMODE(value.st_mode)==0o644
         and value.st_uid==os.geteuid() and value.st_gid==os.getegid()
         and value.st_nlink==1 and value.st_dev==parent.st_dev and value.st_size==size)

def stable_read_set(parent,names,limit=capture.MAX_PUBLIC):
    need(names in EXACT_MEMBERS.values())
    parent=Path(parent);need(parent.is_absolute())
    for item in reversed((parent,*parent.parents)):
        need(not stat.S_ISLNK(item.lstat().st_mode))
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
    dirfd=os.open(parent,flags)
    try:
        before=os.fstat(dirfd); need(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode)==0o755
            and before.st_uid==os.geteuid() and before.st_gid==os.getegid())
        named_parent=os.open(parent,flags)
        try:_require_same_dir(os.fstat(named_parent),before)
        finally:os.close(named_parent)
        _require_exact_members(_member_names(dirfd),names)
        result={}
        for name in names:
            fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
            try:
                opened=os.fstat(fd);raw=read_fd(fd,limit);after=os.fstat(fd)
                named=os.stat(name,dir_fd=dirfd,follow_symlinks=False)
                sig=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,
                              s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
                need(sig(opened)==sig(after)==sig(named) and 1<=len(raw)<=limit)
                _require_final_stat(opened,before,len(raw))
                fd2=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
                try:need(sig(os.fstat(fd2))==sig(opened) and read_fd(fd2,limit)==raw)
                finally:os.close(fd2)
                result[name]=raw
            finally:os.close(fd)
        _require_exact_members(_member_names(dirfd),names)
        _require_same_dir(os.fstat(dirfd),before)
        named_parent=os.open(Path(parent),flags)
        try:_require_same_dir(os.fstat(named_parent),before)
        finally: os.close(named_parent)
        return result
    finally: os.close(dirfd)

def _forbidden_keys(value):
    if isinstance(value,dict):
        for key,item in value.items():
            low=key.lower()
            # Source identity and the explicit instrumented monotonic-effect
            # label are allowed; runtime absolute monotonic fields are not.
            if key not in ('sourceCommit','sourceTree','instrumentationEffect','prepublicationFinalizationDeltaNs'):
                need(not any(part in low for part in FORBIDDEN_FRAGMENTS))
            _forbidden_keys(item)
    elif isinstance(value,list):
        for item in value:_forbidden_keys(item)

def check_payload(raw,lane,commit,tree):
    value=capture.decode(raw); need(capture.canonical(value)==raw)
    expected={'schema','sourceCommit','sourceTree','lane','manifestCount','manifestNamesSHA256',
        'instrumentationEffect','evidenceScope','priorRunTimingEquivalence','acceptanceAuthority',
        'causalInference','profileTimerSeconds','testTimeoutSeconds','boundaryDeltas',
        'childReturnCodeSigned','childShellStatus','childOutcome','rawOutcome','semanticOutcome',
        'streamClosure','topCoverage','fixedFailure','secondaryFailureFlags','discardCounters',
        'discardCounterSaturated','packages','requiredTops','requiredTransitionTail'}
    need(type(value)is dict and set(value)==expected and value.get('schema')=='chengwang.go-top-observation-timeline/v1')
    need(value.get('sourceCommit')==commit and value.get('sourceTree')==tree and value.get('lane')==lane)
    need(value.get('manifestCount')==689 and value.get('manifestNamesSHA256')==
         '2ffac806dc10c8019b0342e1e0e0c56a4712a02172bdaee8a29429e5c78fa68f')
    need(value.get('instrumentationEffect')=='PIPE_READER_MAY_PERTURB_SCHEDULING_AND_DURATION')
    need(value.get('evidenceScope')=='THIS_INSTRUMENTED_RUN_ONLY' and
         value.get('priorRunTimingEquivalence') is False and value.get('acceptanceAuthority') is False and
         value.get('causalInference')=='NOT_MADE' and value.get('testTimeoutSeconds')==180)
    need(value.get('profileTimerSeconds')==(120 if lane=='CAPACITY_FULL_RACE' else None))
    need(value.get('fixedFailure') in capture.FAILURES)
    rows=value.get('requiredTops'); registry=capture.load_registry()
    need(type(rows)is list and len(rows)==689 and [r.get('name') for r in rows]==registry['names'])
    rowkeys={'name','state','terminalAction','runDeltaNs','terminalDeltaNs','observedSpanNs','goActiveElapsedSeconds','pauseCount','continueCount'}
    for row in rows:
        need(set(row)==rowkeys and row['state']in('ABSENT','RUNNING','PAUSED','TERMINAL'))
        need(row['terminalAction']in(None,'pass','fail','skip'))
        need((row['state']=='TERMINAL')==(row['terminalAction']is not None))
        need(type(row['pauseCount'])is int and type(row['continueCount'])is int and row['pauseCount']>=0 and row['continueCount']>=0)
        for key in ('runDeltaNs','terminalDeltaNs','observedSpanNs'):
            need(row[key]is None or type(row[key])is int and 0<=row[key]<=capture.MAX_I63)
        need(row['goActiveElapsedSeconds']is None or type(row['goActiveElapsedSeconds'])in(int,float)
             and not isinstance(row['goActiveElapsedSeconds'],bool) and math.isfinite(row['goActiveElapsedSeconds'])
             and row['goActiveElapsedSeconds']>=0)
        need((row['state']=='TERMINAL')==(row['terminalDeltaNs']is not None))
        if row['terminalDeltaNs']is not None:
            need(row['runDeltaNs']is not None and row['observedSpanNs']==row['terminalDeltaNs']-row['runDeltaNs'])
    packages=value.get('packages');need(type(packages)is list and len(packages)==6)
    need([p.get('name')for p in packages]==list(capture.PACKAGES)
         and all(set(p)=={'name','state','terminalAction'} for p in packages))
    need(all(p['state']in('ABSENT','STARTED','TERMINAL') and
             p['terminalAction']in(None,'pass','fail','skip') and
             ((p['state']=='TERMINAL')==(p['terminalAction']is not None)) for p in packages))
    tail=value.get('requiredTransitionTail');need(type(tail)is list and len(tail)<=20)
    required=set(registry['names'])
    for item in tail:
        need(set(item)=={'name','action','deltaNs'}and item['name']in required
             and item['action']in('run','pause','cont','pass','fail','skip')
             and type(item['deltaNs'])is int and 0<=item['deltaNs']<=capture.MAX_I63)
    need(value['streamClosure']in('COMPLETE_EOF','TRUNCATED_CAP','REJECTED_IO','CANCELLED_CLEANED_REAPED'))
    need(value['topCoverage']in('COMPLETE_TERMINAL','PARTIAL_TERMINAL','REJECTED_SEMANTICS','UNAVAILABLE_COLLECTOR_FAILURE'))
    need(value['childOutcome']in('EXITED','SIGNALED','COLLECTOR_KILLED_AND_REAPED'))
    need(type(value['secondaryFailureFlags'])is list and value['secondaryFailureFlags']==sorted(set(value['secondaryFailureFlags'])))
    need(set(value['secondaryFailureFlags'])<={'KILLPG_ESRCH','KILLPG_FAILED','CLOSE_FAILED'})
    need(value['rawOutcome']in('COMPLETE','RAW_CAP','RAW_WRITE_FAILED','RAW_FSYNC_FAILED'))
    need(value['semanticOutcome']=='COMPLETE' or value['semanticOutcome']in capture.FAILURES-{'NONE'})
    need(set(value['discardCounters'])=={'requiredSubtest','nonRequiredTop','nonRequiredSubtest','output'})
    need(all(type(n)is int and 0<=n<=capture.MAX_EVENTS for n in value['discardCounters'].values()))
    need(type(value['discardCounterSaturated'])is bool)
    if value['topCoverage']=='COMPLETE_TERMINAL':
        need(value['childReturnCodeSigned']==0 and value['rawOutcome']=='COMPLETE'
             and value['semanticOutcome']=='COMPLETE' and value['fixedFailure']=='NONE'
             and all(row['state']=='TERMINAL' and row['terminalAction']=='pass' for row in rows)
             and all(p['state']=='TERMINAL' and p['terminalAction']=='pass' for p in packages))
    boundaries=value.get('boundaryDeltas'); need(type(boundaries)is dict)
    need(set(boundaries)=={'firstLineReadDeltaNs','eofObservedDeltaNs','waitReturnedDeltaNs',
        'rawFsyncReturnedDeltaNs','stderrFsyncReturnedDeltaNs','prepublicationFinalizationDeltaNs'})
    chain=[boundaries[key] for key in ('firstLineReadDeltaNs','eofObservedDeltaNs',
        'waitReturnedDeltaNs','rawFsyncReturnedDeltaNs','stderrFsyncReturnedDeltaNs',
        'prepublicationFinalizationDeltaNs') if boundaries[key] is not None]
    need(all(type(v)is int and 0<=v<=capture.MAX_I63 for v in chain) and chain==sorted(chain))
    need(type(value.get('childReturnCodeSigned'))is int and value.get('childShellStatus')>=0)
    _forbidden_keys(value)
    return value

def stable_file(path,limit):
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=limit)
    with path.open('rb')as f:opened=os.fstat(f.fileno());raw=f.read(limit+1);after=os.fstat(f.fileno())
    sig=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_nlink)
    need(sig(before)==sig(opened)==sig(after)==sig(path.lstat())and len(raw)==before.st_size)
    return raw

def read_commands(path):
    return [capture.decode(line)for line in stable_file(path,1<<20).splitlines()]

def check_capacity_commands(rows,value):
    selected=[r for r in rows if r.get('class')=='GO_TEST']
    need(len(selected)==4 and [r.get('event')for r in selected]==
         ['START_INTENT','STARTED','COLLECTOR_HANDOFF','WAIT_RETURNED'])
    need([r['seq']for r in selected]==list(range(selected[0]['seq'],selected[0]['seq']+4)))
    a,b,c,d=selected;need(a.get('pid')is None and a.get('exitCode')is None)
    need(type(b.get('pid'))is int and b.get('pid')>0 and b.get('exitCode')is None)
    need(c.get('pid')==d.get('pid')==b['pid']and c.get('exitCode')is None)
    need(d.get('exitCode')==value['childReturnCodeSigned'])
    need(a.get('argv')==b.get('argv')==c.get('argv')==d.get('argv'))
    argv=a['argv'];need(type(argv)is list and len(argv)>1 and type(argv[0])is str and Path(argv[0]).is_absolute())
    need(argv[1:]==['test','-race','-json','-count=1','-timeout=180s','-tags','chengwang_capacity_profile','-run','^Test',
        './internal/adapter/mihomo','./internal/mihomodeploy','./internal/authn','./internal/api','./internal/serverruntime','./internal/authz'])
    need(set(c)=={'seq','event','class','argv','pid','exitCode','monotonicDeltaFromStartedNs'})
    need(set(a)==set(b)==set(d)=={'seq','event','class','argv','pid','exitCode','monotonicNs'})
    need(type(a['monotonicNs'])is int and type(b['monotonicNs'])is int and type(d['monotonicNs'])is int)
    delta=c['monotonicDeltaFromStartedNs'];need(type(delta)is int and 0<=delta<=capture.MAX_I63)
    origin=b['monotonicNs']+delta;need(origin<=capture.MAX_I63 and a['monotonicNs']<=b['monotonicNs']<=origin)
    boundary=[value['boundaryDeltas'][key] for key in ('firstLineReadDeltaNs','eofObservedDeltaNs',
        'waitReturnedDeltaNs','rawFsyncReturnedDeltaNs','stderrFsyncReturnedDeltaNs',
        'prepublicationFinalizationDeltaNs') if value['boundaryDeltas'][key] is not None]
    need(all(origin+v<=capture.MAX_I63 for v in boundary)and origin+max(boundary)<=d['monotonicNs'])
    return d['monotonicNs']-b['monotonicNs']

def check(repo,commit,evidence,lane):
    git=RawGit(repo);tree=git.identity(commit)
    need(git.run('rev-parse','HEAD').decode().strip()==commit)
    need(git.run('status','--porcelain','--untracked-files=all')==b'')
    sources={p:hashlib.sha256(git.source(commit,p)).hexdigest() for p in SOURCE_PATHS}
    import check_contracts as normal
    declared=normal.required_names({p:git.source(commit,p) for p,_ in normal.TEST_FILES})
    names=sorted(package+'::'+name for package,items in declared.items()for name in items)
    need(len(names)==689 and names==capture.load_registry()['names'])
    evidence=Path(evidence)
    if lane=='FOUNDATION':lanes=('FOUNDATION_ORDINARY','FOUNDATION_RACE')
    else:lanes=('CAPACITY_FULL_RACE',)
    values={}
    publication=evidence/capture.PUBLICATION_DIR
    need(publication.parent==evidence and publication.name==capture.PUBLICATION_DIR)
    members=stable_read_set(publication,EXACT_MEMBERS[lane])
    for item in lanes:
        name=capture.FINAL_NAMES[item]
        values[item]=check_payload(members[name],item,commit,tree)
    derived={}
    if lane=='FOUNDATION':
        execution=capture.decode(stable_file(evidence/'execution.json',16384))
        need(values['FOUNDATION_ORDINARY']['childReturnCodeSigned']==execution['ordinaryExit'])
        need(values['FOUNDATION_RACE']['childReturnCodeSigned']==execution['raceExit'])
    else:
        rows=read_commands(evidence/'commands.jsonl')
        derived['journalObservationSpanNs']=check_capacity_commands(rows,values['CAPACITY_FULL_RACE'])
        execution=capture.decode(stable_file(evidence/'execution.json',16384))
        need(execution.get('goExit')==values['CAPACITY_FULL_RACE']['childReturnCodeSigned'])
        need(execution.get('timelineFailure') in {'NONE','SIGNAL_HANDLER_RESTORE_FAILED_AFTER_REAP',
            'WAIT_JOURNAL_WRITE_FAILED','COLLECTOR_FAILED_AND_REAPED','SIGNAL_DEFERRAL_INSTALL_FAILED',
            'DEFERRED_CANCELLATION_NO_CHILD','DEFERRED_CANCELLATION_REAPED','POPEN_FAILED','PGID_REJECTED'})
    return {'schema':'chengwang.go-top-timeline-verification/v1','sourceCommit':commit,
        'sourceTree':tree,'laneGroup':lane,'timelineCount':len(values),
        'custody':'CUSTODY_VALIDATED_AT_CHECK_TIME','acceptanceAuthority':False,
        'causalInference':'NOT_MADE','sourceSHA256':sources,'derived':derived}

def write_report(path,value):
    raw=capture.canonical(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:])
        os.fsync(fd)
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True)
    p.add_argument('--source-commit',required=True);p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--lane',choices=['FOUNDATION','CAPACITY'],required=True);p.add_argument('--report',type=Path)
    a=p.parse_args();value=check(a.repo,a.source_commit,a.evidence,a.lane)
    if a.report:write_report(a.report,value)
    print('GO_TIMELINE_CHECK=PASS custody=current acceptance_authority=false')

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('GO_TIMELINE_CHECK=REJECTED safe=true')from None
