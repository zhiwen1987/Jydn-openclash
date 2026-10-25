"""CI-only fixed CPU diagnosis capture. No producer/config/WAL upload."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
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
RAW_NAMES=('go-version.txt','gofmt.patch','gofmt.stderr','capacity.json','capacity.stderr',
    'commands.jsonl','execution.json','profile-state.json','pprof-top.txt','pprof-top.stderr','pprof-cum.txt','pprof-cum.stderr')

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

def commands(goroot):
    seq=0
    def journal(kind,argv,event,pid=None,code=None):
        nonlocal seq
        seq+=1
        value={'seq':seq,'event':event,'class':kind,'argv':argv,'pid':pid,'exitCode':code,'monotonicNs':time.monotonic_ns()}
        with (PRIVATE/'commands.jsonl').open('ab') as f:f.write(encoded(value));f.flush();os.fsync(f.fileno())
    def run(kind,argv,out,err):
        journal(kind,argv,'START_INTENT')
        with (PRIVATE/out).open('xb') as stdout,(PRIVATE/err).open('xb') as stderr:
            p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
            journal(kind,argv,'STARTED',p.pid)
            code=p.wait()
            stdout.flush();os.fsync(stdout.fileno());stderr.flush();os.fsync(stderr.fileno())
        journal(kind,argv,'WAIT_RETURNED',p.pid,code)
        return code
    need(sys.platform=='linux' and os.getuid()==os.getgid()==10001 and Path.cwd()==SOURCE)
    need(sorted(os.listdir(PRIVATE))==[])
    os.umask(0o077)
    go=str(Path(goroot)/'bin/go')
    version=run('VERSION',[go,'version'],'go-version.txt','version.stderr.private')
    fmt=run('FORMAT',[str(Path(goroot)/'bin/gofmt'),'-d','internal/mihomodeploy/lifecycle_capacity_profile_linux_test.go'],'gofmt.patch','gofmt.stderr')
    code=run('GO_TEST',[go,*GO_ARGS],'capacity.json','capacity.stderr')
    top=run('PPROF_TOP',[go,'tool','pprof','-symbolize=local','-top',str(PRIVATE/'cpu.pprof')],'pprof-top.txt','pprof-top.stderr')
    cum=run('PPROF_CUM',[go,'tool','pprof','-symbolize=local','-top','-cum',str(PRIVATE/'cpu.pprof')],'pprof-cum.txt','pprof-cum.stderr')
    # Profile completeness is observed independently from the test's exit code.
    complete=None
    if (PRIVATE/'profile-state.json').is_file():
        value=json.loads(private_read(PRIVATE/'profile-state.json',16384));complete=value.get('complete')
        need(type(complete) is bool)
    write(PRIVATE/'execution.json',encoded({'schema':'chengwang.capacity-profile-execution/v1',
        'sourceCommit':os.environ['CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT'],'versionExit':version,
        'formatExit':fmt,'goExit':code,'topExit':top,'cumExit':cum,'profileCaptureComplete':complete,'production':False}))
    # write() is public-mode; correct only this new private file, not host inputs.
    os.chmod(PRIVATE/'execution.json',0o600)

def export(out):
    need(sys.platform=='linux' and os.getuid()==0 and out.is_dir())
    # Preserve actual created files, including failures. Never fill missing
    # streams or profiles with empty replacements or fixed status summaries.
    for name in RAW_NAMES:
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

def sandbox(out,goroot):
    need(sys.platform=='linux' and os.getuid()==os.getgid()==10001 and Path.cwd()==SOURCE)
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
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['commands','export','sandbox']);p.add_argument('--goroot',type=Path);p.add_argument('--out',type=Path);a=p.parse_args()
    if a.mode=='commands':commands(a.goroot)
    elif a.mode=='export':export(a.out)
    else:sandbox(a.out,a.goroot)
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('CAPACITY_PROFILE_CAPTURE=REJECTED raw_error_suppressed=true') from None
