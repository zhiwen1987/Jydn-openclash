#!/usr/bin/env python3
"""Bounded source-model outcome producer and independent structural checker."""
import argparse
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent
TEST_MODULE='test_continuous_recovery_api_model'
TEST_SOURCE_REL='chengwang/deploy/mihomo-lifecycle-lab/'+TEST_MODULE+'.py'
SCHEMA='chengwang.mihomo-continuous-recovery-model-outcomes/v1'
MAXIMUM=32768
EXPECTED_IDS=(
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_capture_dispatch_positive_and_rejects_closed_tuple',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_capture_pidfd_failure_and_timeout_are_fail_closed',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_contract_excludes_old_fault_tags_and_has_independent_capture',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_fresh_readback_requires_successful_api_producer',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_producer_and_reader_independently_bind_full_tracked_git_set',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_reader_accepts_complete_synthetic_shape_and_rejects_material_mutants',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_reader_rejects_consistently_rewritten_nested_and_native_mutants',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_safe_evidence_rejects_file_identity_and_semantic_mutants',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_safe_projection_accepts_reversed_filesystem_enumeration_but_keeps_canonical_report',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_safe_projection_and_independent_readback_positive',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_safe_root_rejects_ten_identity_shape_and_digest_mutants',
    TEST_MODULE+'.ContinuousRecoveryAPIModel.test_safe_upload_is_success_only_and_excludes_mixed_diagnostics',
)
EXPECTED_IDS_SHA256='22ef759e03c29c7e063f3bb5d0770f1710044f3661bf5fe96013dc49f03dcd61'
FAILURE_CLASSES=frozenset(('ASSERTION_FAILURE','TEST_ERROR','SKIPPED','EXPECTED_FAILURE','UNEXPECTED_SUCCESS','RUNNER_INTERNAL_ERROR'))
RUNNER_CLASSES=frozenset(('NONE','MODULE_LOAD_ERROR','SUITE_BUILD_ERROR','RUNNER_INTERNAL_ERROR'))
KEYS=('schema','sourceCommit','sourceTree','runId','runAttempt','expectedCount','expectedIdsSHA256','modelSourceSHA256',
    'loadedIds','runIds','passedIds','failedIds','notRunIds','failureClasses','runnerFailureClass','suiteAccepted',
    'sourceCleanBefore','sourceCleanAfter','production')

def need(value):
    if not value:raise ValueError('continuous source-model outcome rejected')
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def positive(value,maximum=(1<<63)-1):
    need(type(value)is str and re.fullmatch(r'[1-9][0-9]{0,18}',value)is not None)
    need(int(value)<=maximum);return value
def hex40(value):return type(value)is str and re.fullmatch(r'[a-f0-9]{40}',value)is not None
def exact(value,names):return type(value)is dict and tuple(sorted(value))==tuple(sorted(names))

def git(repo,*args,limit=4<<20):
    env=os.environ.copy();env['GIT_NO_REPLACE_OBJECTS']='1'
    result=subprocess.run(['git','--no-replace-objects','-c','core.fsmonitor=false','-C',str(repo),*args],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,env=env,timeout=30)
    need(result.returncode==0 and len(result.stdout)<=limit and len(result.stderr)<=1<<20)
    return result.stdout

def source_binding(repo,commit,tree):
    repo=Path(repo).resolve(strict=True);need(repo.is_dir()and hex40(commit)and hex40(tree))
    need(git(repo,'rev-parse','HEAD').strip().decode()==commit)
    need(git(repo,'rev-parse',commit+'^{tree}').strip().decode()==tree)
    need(git(repo,'status','--porcelain=v1','--untracked-files=all')==b'')
    path=repo/TEST_SOURCE_REL;meta=path.lstat();need(stat.S_ISREG(meta.st_mode)and not path.is_symlink()and meta.st_nlink==1)
    raw=path.read_bytes();need(raw==git(repo,'cat-file','blob',commit+':'+TEST_SOURCE_REL,limit=2<<20))
    return repo,raw

def inventory(raw):
    tree=ast.parse(raw.decode('utf8','strict'),filename=TEST_MODULE+'.py');names=[]
    for item in tree.body:
        if not isinstance(item,ast.ClassDef):continue
        for method in item.body:
            if isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef))and method.name.startswith('test_'):
                names.append(TEST_MODULE+'.'+item.name+'.'+method.name)
    names=tuple(sorted(names));need(names==EXPECTED_IDS and len(names)==len(set(names))==12)
    need(sha('\n'.join(names).encode())==EXPECTED_IDS_SHA256)
    return names,sha(raw)

def flatten(suite):
    values=[]
    for item in suite:
        if isinstance(item,unittest.TestSuite):values.extend(flatten(item))
        else:
            try:identity=item.id()
            except Exception:identity=None
            need(type(identity)is str);values.append(identity)
    return tuple(sorted(values))

class ClosedResult(unittest.TestResult):
    _rank={'PASS':0,'SKIPPED':1,'EXPECTED_FAILURE':2,'ASSERTION_FAILURE':3,'TEST_ERROR':4,'UNEXPECTED_SUCCESS':5,'RUNNER_INTERNAL_ERROR':6}
    def __init__(self,expected):
        super().__init__();self.expected=frozenset(expected);self.started=set();self.outcomes={};self.unknown=False
    def identity(self,test):
        try:value=test.id()
        except Exception:self.unknown=True;return None
        if type(value)is not str or value not in self.expected:self.unknown=True;return None
        return value
    def mark(self,test,outcome):
        identity=self.identity(test)
        if identity is None:return
        previous=self.outcomes.get(identity)
        if previous is None or self._rank[outcome]>=self._rank[previous]:self.outcomes[identity]=outcome
    def startTest(self,test):
        identity=self.identity(test)
        if identity is not None:self.started.add(identity)
        super().startTest(test)
    def addSuccess(self,test):super().addSuccess(test);self.mark(test,'PASS')
    def addFailure(self,test,err):super().addFailure(test,err);self.mark(test,'ASSERTION_FAILURE')
    def addError(self,test,err):super().addError(test,err);self.mark(test,'TEST_ERROR')
    def addSkip(self,test,reason):super().addSkip(test,reason);self.mark(test,'SKIPPED')
    def addExpectedFailure(self,test,err):super().addExpectedFailure(test,err);self.mark(test,'EXPECTED_FAILURE')
    def addUnexpectedSuccess(self,test):super().addUnexpectedSuccess(test);self.mark(test,'UNEXPECTED_SUCCESS')
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err)
        if err is not None:self.mark(test,'ASSERTION_FAILURE'if issubclass(err[0],AssertionError)else'TEST_ERROR')

def make_value(commit,tree,run_id,run_attempt,source_sha,loaded=(),run=(),passed=(),failures=(),runner='NONE'):
    expected=EXPECTED_IDS;loaded=tuple(sorted(loaded));run=tuple(sorted(run));passed=tuple(sorted(passed));failures=tuple(sorted(failures))
    failed=tuple(row[0]for row in failures);not_run=tuple(name for name in expected if name not in set(run))
    value={'schema':SCHEMA,'sourceCommit':commit,'sourceTree':tree,'runId':run_id,'runAttempt':run_attempt,
        'expectedCount':len(expected),'expectedIdsSHA256':EXPECTED_IDS_SHA256,'modelSourceSHA256':source_sha,
        'loadedIds':list(loaded),'runIds':list(run),'passedIds':list(passed),'failedIds':list(failed),'notRunIds':list(not_run),
        'failureClasses':[{'id':identity,'class':kind}for identity,kind in failures],
        'runnerFailureClass':runner,'suiteAccepted':runner=='NONE'and passed==expected and not failures,
        'sourceCleanBefore':True,'sourceCleanAfter':True,'production':False}
    validate(canonical(value),commit,tree,run_id,run_attempt,source_sha)
    return value

def validate(raw,commit,tree,run_id,run_attempt,source_sha):
    need(type(raw)is bytes and 0<len(raw)<=MAXIMUM and raw.endswith(b'\n')and b'\r'not in raw)
    value=json.loads(raw);need(canonical(value)==raw and exact(value,KEYS))
    need(value['schema']==SCHEMA and value['sourceCommit']==commit and value['sourceTree']==tree)
    need(value['runId']==positive(run_id)and value['runAttempt']==positive(run_attempt,1<<31))
    need(value['expectedCount']==12 and type(value['expectedCount'])is int and value['expectedIdsSHA256']==EXPECTED_IDS_SHA256)
    need(value['modelSourceSHA256']==source_sha and re.fullmatch(r'[a-f0-9]{64}',source_sha)is not None)
    expected=EXPECTED_IDS;expected_set=set(expected)
    collections=[]
    for key in ('loadedIds','runIds','passedIds','failedIds','notRunIds'):
        item=value[key];need(type(item)is list and item==sorted(set(item))and set(item)<=expected_set);collections.append(item)
    loaded,run,passed,failed,not_run=map(tuple,collections)
    need(set(run)<=set(loaded)and set(passed).isdisjoint(failed)and set(passed)|set(failed)==set(run))
    need(not_run==tuple(name for name in expected if name not in set(run)))
    rows=value['failureClasses'];need(type(rows)is list and len(rows)==len(failed))
    need(all(exact(row,('id','class'))and row['id']==failed[index]and row['class']in FAILURE_CLASSES for index,row in enumerate(rows)))
    runner=value['runnerFailureClass'];need(runner in RUNNER_CLASSES)
    if runner in ('MODULE_LOAD_ERROR','SUITE_BUILD_ERROR'):
        need(not loaded and not run and not passed and not failed and not rows)
    else:need(loaded==expected)
    accepted=runner=='NONE'and loaded==run==passed==expected and not failed
    need(type(value['suiteAccepted'])is bool and value['suiteAccepted']is accepted)
    need(value['sourceCleanBefore']is value['sourceCleanAfter']is True and value['production']is False)
    return value

def write_new(path,raw,mode):
    path=Path(path);need(path.is_absolute()and'..'not in path.parts and path.parent.is_dir()and not path.parent.is_symlink())
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0)
    fd=os.open(path,flags,mode)
    try:
        view=memoryview(raw)
        while view:
            count=os.write(fd,view);need(count>0);view=view[count:]
        os.fsync(fd);meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode)and meta.st_nlink==1 and meta.st_size==len(raw))
    finally:os.close(fd)

def read_stable(path):
    path=Path(path);need(path.is_absolute()and'..'not in path.parts and not path.is_symlink())
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=MAXIMUM)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
    try:
        opened=os.fstat(fd);parts=[];total=0
        while True:
            chunk=os.read(fd,min(65536,MAXIMUM+1-total))
            if not chunk:break
            parts.append(chunk);total+=len(chunk);need(total<=MAXIMUM)
        raw=b''.join(parts);after=os.fstat(fd)
    finally:os.close(fd)
    identity=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_nlink,item.st_size,item.st_mtime_ns)
    need(identity(before)==identity(opened)==identity(after)==identity(path.lstat())and len(raw)==before.st_size)
    return raw

def exact_directory(path,names):
    path=Path(path);info=path.lstat();need(stat.S_ISDIR(info.st_mode)and not path.is_symlink())
    observed={item.name for item in path.iterdir()};need(observed==set(names)and len(observed)==len(names))

def load_module(path):
    spec=importlib.util.spec_from_file_location(TEST_MODULE,path);need(spec is not None and spec.loader is not None)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def produce(repo,commit,tree,run_id,run_attempt,output):
    repo,source_raw=source_binding(repo,commit,tree);expected,source_sha=inventory(source_raw)
    exact_directory(Path(output).parent,())
    loaded=();result=None;runner='NONE';code=1
    try:module=load_module(repo/TEST_SOURCE_REL)
    except Exception:runner='MODULE_LOAD_ERROR'
    else:
        try:
            suite=unittest.defaultTestLoader.loadTestsFromModule(module);loaded=flatten(suite);need(loaded==expected)
        except Exception:runner='SUITE_BUILD_ERROR';loaded=()
        else:
            result=ClosedResult(expected)
            try:
                with open(os.devnull,'w')as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):suite.run(result)
            except Exception:runner='RUNNER_INTERNAL_ERROR'
            if result.unknown:runner='RUNNER_INTERNAL_ERROR'
    run=tuple(sorted(result.started))if result is not None else()
    outcomes=dict(result.outcomes)if result is not None else{}
    if runner=='RUNNER_INTERNAL_ERROR':
        for identity in run:outcomes.setdefault(identity,'RUNNER_INTERNAL_ERROR')
    passed=tuple(sorted(identity for identity,outcome in outcomes.items()if outcome=='PASS'))
    failures=tuple(sorted((identity,outcome)for identity,outcome in outcomes.items()if outcome!='PASS'))
    source_binding(repo,commit,tree)
    value=make_value(commit,tree,run_id,run_attempt,source_sha,loaded,run,passed,failures,runner)
    write_new(output,canonical(value),0o600);exact_directory(Path(output).parent,(Path(output).name,))
    accepted=value['suiteAccepted'];code=0 if accepted else 1
    return code

def check(repo,commit,tree,run_id,run_attempt,input_path,output):
    _,source_raw=source_binding(repo,commit,tree);_,source_sha=inventory(source_raw)
    exact_directory(Path(input_path).parent,(Path(input_path).name,));exact_directory(Path(output).parent,())
    raw=read_stable(input_path);validate(raw,commit,tree,run_id,run_attempt,source_sha)
    write_new(output,raw,0o644);exact_directory(Path(output).parent,(Path(output).name,));return 0

def main(argv=None):
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='mode',required=True)
    for mode in ('run','check'):
        item=sub.add_parser(mode);item.add_argument('--repo',type=Path,required=True);item.add_argument('--source-commit',required=True)
        item.add_argument('--source-tree',required=True);item.add_argument('--run-id',required=True);item.add_argument('--run-attempt',required=True)
        item.add_argument('--output',type=Path,required=True)
        if mode=='check':item.add_argument('--input',type=Path,required=True)
    args=parser.parse_args(argv)
    if args.mode=='run':return produce(args.repo,args.source_commit,args.source_tree,args.run_id,args.run_attempt,args.output)
    return check(args.repo,args.source_commit,args.source_tree,args.run_id,args.run_attempt,args.input,args.output)

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('CONTINUOUS_SOURCE_MODEL_OUTCOME=REJECTED',file=sys.stderr)
        raise SystemExit(2) from None
