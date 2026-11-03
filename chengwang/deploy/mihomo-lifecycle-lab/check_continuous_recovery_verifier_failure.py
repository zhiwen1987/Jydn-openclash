#!/usr/bin/env python3
"""Independently publish one bounded Continuous31 verifier-failure summary."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SCHEMA='chengwang.mihomo-continuous-recovery-verifier-failure/v2'
COMMIT=re.compile(r'[0-9a-f]{40}')
DIGEST=re.compile(r'[0-9a-f]{64}')
MAXIMUM=4096
PHASES=(
 'SOURCE_BINDING','PUBLIC_INVENTORY','REPORT_SHAPE','HTTP_SHAPES','STATE_CROSS_LINKS',
 'COMMANDS','PROCESS_EVENTS','NAMESPACE_TOOLCHAIN','PRIVATE_CUSTODY','CONSUMPTION','UNKNOWN')
CLASSES=(
 'SCHEMA_INVALID','SOURCE_MISMATCH','IDENTITY_MISMATCH','COUNT_MISMATCH','STATE_MISMATCH',
 'SEQUENCE_MISMATCH','CUSTODY_INVALID','MISSING_EVIDENCE','DUPLICATE_EVIDENCE','UNKNOWN')
FIELD_CODES=(
 'SOURCE_MANIFEST','SOURCE_FILES','PUBLIC_FILE_SET','REPORT','HTTP_RESPONSES','STATE_RELATIONSHIPS',
 'COMMAND_RECEIPTS','PROCESS_RECEIPTS','GO_RESULT','SANDBOX','HOST_NAMESPACE','GO_TOOLCHAIN',
 'HOST_NAMESPACE_STABILITY_PID','HOST_NAMESPACE_STABILITY_MNT','HOST_NAMESPACE_STABILITY_NET',
 'HOST_NAMESPACE_STABILITY_RESOLV','HOST_NAMESPACE_STABILITY_OTHER','HOST_NAMESPACE_SCHEMA',
 'HOST_NAMESPACE_FORMAT','HOST_RESOLV_FORMAT','SANDBOX_HOST_SEPARATION','COMMAND_NAMESPACE_CONSISTENCY',
 'PRIVATE_RECEIPTS','CONSUMPTION_RECEIPTS','UNKNOWN')
PHASE_FIELDS={
 'SOURCE_BINDING':('SOURCE_MANIFEST','SOURCE_FILES'),
 'PUBLIC_INVENTORY':('PUBLIC_FILE_SET',),
 'REPORT_SHAPE':('REPORT','GO_RESULT'),
 'HTTP_SHAPES':('HTTP_RESPONSES',),
 'STATE_CROSS_LINKS':('STATE_RELATIONSHIPS',),
 'COMMANDS':('COMMAND_RECEIPTS',),
 'PROCESS_EVENTS':('PROCESS_RECEIPTS',),
 'NAMESPACE_TOOLCHAIN':(
   'SANDBOX','HOST_NAMESPACE','HOST_NAMESPACE_STABILITY_PID','HOST_NAMESPACE_STABILITY_MNT',
   'HOST_NAMESPACE_STABILITY_NET','HOST_NAMESPACE_STABILITY_RESOLV','HOST_NAMESPACE_STABILITY_OTHER',
   'HOST_NAMESPACE_SCHEMA','HOST_NAMESPACE_FORMAT','HOST_RESOLV_FORMAT','SANDBOX_HOST_SEPARATION',
   'COMMAND_NAMESPACE_CONSISTENCY','GO_TOOLCHAIN'),
 'PRIVATE_CUSTODY':('PRIVATE_RECEIPTS',),
 'CONSUMPTION':('CONSUMPTION_RECEIPTS',),
 'UNKNOWN':('UNKNOWN',)}
BOUND_SOURCES=(
 '.github/workflows/chengwang-mihomo-continuous-recovery-api.yml',
 'chengwang/deploy/mihomo-lifecycle-lab/check_continuous_recovery_api.py',
 'chengwang/deploy/mihomo-lifecycle-lab/check_continuous_recovery_verifier_failure.py',
 'chengwang/deploy/mihomo-lifecycle-lab/test_continuous_recovery_api_model.py')

def need(value):
    if not value: raise ValueError('continuous Recovery verifier-failure summary rejected')
def canonical(value): return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def positive(value,maximum=(1<<63)-1):
    need(type(value) is str and re.fullmatch(r'[1-9][0-9]{0,18}',value)); result=int(value); need(result<=maximum); return result
def exact_keys(value,names): need(type(value) is dict and set(value)==set(names)); return value

def read_stable(path,maximum=MAXIMUM,mode=None):
    path=Path(path).absolute(); need(path.parent.resolve(strict=True)==path.parent)
    before=path.lstat(); need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=maximum)
    if mode is not None and os.name!='nt': need(stat.S_IMODE(before.st_mode)==mode)
    signature=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
    try:
        opened=os.fstat(fd); need(signature(opened)==signature(before)); chunks=[]; seen=0
        while True:
            chunk=os.read(fd,min(65536,maximum-seen+1))
            if not chunk: break
            chunks.append(chunk); seen+=len(chunk); need(seen<=maximum)
        after_fd=os.fstat(fd)
    finally: os.close(fd)
    after=path.lstat(); raw=b''.join(chunks); need(signature(before)==signature(after_fd)==signature(after) and len(raw)==before.st_size)
    return raw

def strict_json(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAXIMUM and raw.endswith(b'\n'))
    def pairs(rows):
        need(len({key for key,_ in rows})==len(rows)); return dict(rows)
    def no_constant(_): need(False)
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=no_constant)
    need(canonical(value)+b'\n'==raw)
    return value

def git(repo,*args):
    environment=os.environ.copy(); environment['GIT_NO_REPLACE_OBJECTS']='1'
    result=subprocess.run(['git','-C',str(repo),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,timeout=30,env=environment)
    need(result.returncode==0 and len(result.stdout)<=8<<20 and len(result.stderr)<=64<<10)
    return result.stdout

def bind_source(repo,commit):
    repo=Path(repo).resolve(strict=True); need(COMMIT.fullmatch(commit))
    head=git(repo,'rev-parse','HEAD').decode('ascii').strip(); tree=git(repo,'rev-parse',commit+'^{tree}').decode('ascii').strip()
    need(head==commit and COMMIT.fullmatch(tree)); need(git(repo,'status','--porcelain=v1','--untracked-files=all')==b'')
    for relative in BOUND_SOURCES:
        disk=read_stable(repo/relative,2<<20)
        blob=git(repo,'show',commit+':'+relative)
        need(disk==blob)
    return repo,tree

def validate(raw,commit,tree,run_id,run_attempt):
    value=strict_json(raw)
    exact_keys(value,('schema','status','accepted','authorization','runtimeAccepted','phase','failureClass','fieldCode',
      'runId','runAttempt','sourceCommit','sourceTree','sourceProof','rawEvidenceIncluded','production'))
    need(type(run_id) is int and 0<run_id<=(1<<63)-1 and type(run_attempt) is int and 0<run_attempt<=1<<31)
    need(type(value['schema']) is str and value['schema']==SCHEMA and
      type(value['status']) is str and value['status']=='FAIL' and type(value['accepted']) is bool and value['accepted'] is False and
      value['authorization']=='BLOCKED' and value['runtimeAccepted'] is False and value['rawEvidenceIncluded'] is False and value['production'] is False)
    need(type(value['authorization']) is str and type(value['runtimeAccepted']) is bool and
      type(value['rawEvidenceIncluded']) is bool and type(value['production']) is bool)
    need(type(value['runId']) is int and 0<value['runId']<=(1<<63)-1 and value['runId']==run_id)
    need(type(value['runAttempt']) is int and 0<value['runAttempt']<=1<<31 and value['runAttempt']==run_attempt)
    need(type(value['sourceCommit']) is str and COMMIT.fullmatch(value['sourceCommit']) and value['sourceCommit']==commit)
    phase=value['phase']; failure_class=value['failureClass']; field=value['fieldCode']
    need(type(phase) is str and type(failure_class) is str and type(field) is str)
    need(phase in PHASES and failure_class in CLASSES and field in FIELD_CODES and field in PHASE_FIELDS[phase])
    proof=exact_keys(value['sourceProof'],('proven','bindingSHA256','sourceCount','deliveryCount'))
    need(type(proof['proven']) is bool)
    if proof['proven']:
        need(type(value['sourceTree']) is str and COMMIT.fullmatch(value['sourceTree']) and value['sourceTree']==tree)
        need(type(proof['bindingSHA256']) is str and DIGEST.fullmatch(proof['bindingSHA256']))
        need(type(proof['sourceCount']) is int and proof['sourceCount']>0 and type(proof['deliveryCount']) is int and proof['deliveryCount']>0)
        need(phase!='SOURCE_BINDING' or field=='SOURCE_FILES')
    else:
        need(value['sourceTree'] is None)
        need(proof['bindingSHA256'] is None and proof['sourceCount'] is None and proof['deliveryCount'] is None)
        need((phase=='SOURCE_BINDING' and field=='SOURCE_MANIFEST') or (phase=='UNKNOWN' and field=='UNKNOWN'))
    return value

def sync_directory(path):
    try: fd=os.open(path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
    except PermissionError:
        need(os.name=='nt'); return
    try:
        try: os.fsync(fd)
        except OSError: need(os.name=='nt')
    finally: os.close(fd)

def write_new(path,raw,mode):
    path=Path(path).absolute(); need(path.parent.resolve(strict=True)==path.parent and not path.exists())
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),mode)
    try:
        view=memoryview(raw)
        while view:
            count=os.write(fd,view); need(count>0); view=view[count:]
        os.fsync(fd)
    finally: os.close(fd)
    need(read_stable(path,MAXIMUM,mode)==raw)

def publish(repo,private,commit,run_id,run_attempt,output):
    repo,tree=bind_source(repo,commit); run_id=positive(run_id); run_attempt=positive(run_attempt,1<<31)
    private=Path(private).absolute(); raw=read_stable(private,MAXIMUM,0o600); validate(raw,commit,tree,run_id,run_attempt)
    output=Path(output).absolute(); need(not output.exists() and output.parent.resolve(strict=True)==output.parent)
    os.mkdir(output,0o700); write_new(output/'verification-failure.json',raw,0o400); sync_directory(output)
    need(tuple(path.name for path in output.iterdir())==('verification-failure.json',))
    need(read_stable(private,MAXIMUM,0o600)==read_stable(output/'verification-failure.json',MAXIMUM,0o400)==raw)
    return value_without_private(validate(raw,commit,tree,run_id,run_attempt))

def value_without_private(value):
    return {'schema':value['schema'],'status':value['status'],'phase':value['phase'],'failureClass':value['failureClass'],
      'fieldCode':value['fieldCode'],'sourceCommit':value['sourceCommit'],'sourceTree':value['sourceTree'],
      'runId':value['runId'],'runAttempt':value['runAttempt'],'accepted':False,'production':False}

def main(args):
    need(len(args)==6)
    result=publish(Path(args[0]),Path(args[1]),args[2],args[3],args[4],Path(args[5]))
    print(canonical(result).decode())
    return 0

if __name__=='__main__': raise SystemExit(main(sys.argv[1:]))
