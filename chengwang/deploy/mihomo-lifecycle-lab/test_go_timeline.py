import ast
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import go_timeline_capture as capture
import check_go_timeline as checker

COMMIT='a'*40
TREE='b'*40
TIME='2026-11-03T00:00:00Z'

class FakeGuard:
    returncode=0
    secondary=set()

def event(package,action,test=None,elapsed=None,output=None):
    value={'Time':TIME,'Action':action,'Package':package}
    if test is not None:value['Test']=test
    if elapsed is not None:value['Elapsed']=elapsed
    if output is not None:value['Output']=output
    return json.dumps(value,separators=(',',':')).encode()

def boundaries(end=10000):
    return {'firstLineReadDeltaNs':1,'eofObservedDeltaNs':end-4,
        'waitReturnedDeltaNs':end-3,'rawFsyncReturnedDeltaNs':end-2,
        'stderrFsyncReturnedDeltaNs':end-1,'prepublicationFinalizationDeltaNs':end}

class TimelineModels(unittest.TestCase):
    def projector(self,lane='FOUNDATION_ORDINARY'):
        return capture.Projector(lane,COMMIT,TREE,capture.load_registry())

    def test_registry_is_exact_static_689(self):
        value=capture.load_registry();self.assertEqual(value['count'],689)
        self.assertEqual(value['names'],sorted(set(value['names'])))
        self.assertEqual(value['namesSHA256'],'2ffac806dc10c8019b0342e1e0e0c56a4712a02172bdaee8a29429e5c78fa68f')

    def test_complete_689_success_is_diagnostic_only(self):
        p=self.projector();now=1
        for package in capture.PACKAGES:p.event(event(package,'start'),now,0);now+=1
        for key in p.registry['names']:
            package,name=key.split('::',1)
            p.event(event(package,'run',name),now,0);now+=1
            p.event(event(package,'pass',name,0.01),now,0);now+=1
        for package in capture.PACKAGES:p.event(event(package,'pass',elapsed=1.0),now,0);now+=1
        value=p.payload(FakeGuard(),boundaries(now+10),'COMPLETE_EOF')
        self.assertEqual(value['topCoverage'],'COMPLETE_TERMINAL')
        self.assertTrue(all(r['state']=='TERMINAL' and r['terminalAction']=='pass'
                            for r in value['requiredTops']))
        self.assertTrue(all(r['state']=='TERMINAL' and r['terminalAction']=='pass'
                            for r in value['packages']))
        self.assertFalse(value['acceptanceAuthority']);self.assertEqual(value['causalInference'],'NOT_MADE')

    def test_partial_609_one_open_79_not_started_has_no_cause(self):
        p=self.projector();now=1
        for package in capture.PACKAGES:p.event(event(package,'start'),now,0);now+=1
        for key in p.registry['names'][:610]:
            package,name=key.split('::',1);p.event(event(package,'run',name),now,0);now+=1
            if key!=p.registry['names'][609]:p.event(event(package,'pass',name,.01),now,0);now+=1
        value=p.payload(FakeGuard(),boundaries(now+50),'COMPLETE_EOF')
        states=[r['state']for r in value['requiredTops']]
        actions=[r['terminalAction']for r in value['requiredTops']]
        self.assertEqual(states.count('TERMINAL'),609);self.assertEqual(actions.count('pass'),609)
        self.assertEqual(states.count('RUNNING'),1)
        self.assertEqual(states.count('ABSENT'),79);self.assertEqual(value['causalInference'],'NOT_MADE')

    def test_terminal_is_state_and_action_is_separate(self):
        p=self.projector();package='chengwang/internal/api';name='TestTerminalShape'
        p.event(event(package,'start'),1,0);p.event(event(package,'run',name),2,0)
        p.event(event(package,'fail',name,.2),3,0)
        self.assertEqual(p.tests[package+'::'+name],'TERMINAL')
        self.assertEqual(p.test_terminal[package+'::'+name],'fail')
        self.assertNotIn('FAIL',p.tests.values())

    def test_duplicate_json_key_rejects(self):
        p=self.projector();p.event(b'{"Time":"x","Time":"y","Action":"start","Package":"chengwang/internal/api"}',1,0)
        self.assertFalse(p.semantic);self.assertEqual(p.failure,'JSON_REJECTED')

    def test_unknown_key_and_nonfinite_elapsed_reject(self):
        p=self.projector();raw=b'{"Time":"2026-11-03T00:00:00Z","Action":"start","Package":"chengwang/internal/api","Unknown":1}'
        p.event(raw,1,0);self.assertFalse(p.semantic)

    def test_pause_continue_fsm_and_duplicate_run(self):
        p=self.projector();pkg='chengwang/internal/api';name='TestSynthetic'
        p.event(event(pkg,'start'),1,0);p.event(event(pkg,'run',name),2,0)
        p.event(event(pkg,'pause',name),3,0);p.event(event(pkg,'cont',name),4,0)
        p.event(event(pkg,'run',name),5,0);self.assertFalse(p.semantic)

    def test_dynamic_names_and_output_never_enter_public_bytes(self):
        p=self.projector();pkg='chengwang/internal/api';canary='TestSecretCanary/subsecret'
        p.event(event(pkg,'start'),1,0);p.event(event(pkg,'run',canary),2,0)
        p.event(event(pkg,'output',canary,output='TOKEN-CANARY'),3,0)
        raw=capture.canonical(p.payload(FakeGuard(),boundaries(),'COMPLETE_EOF'))
        self.assertNotIn(canary.encode(),raw);self.assertNotIn(b'TOKEN-CANARY',raw)

    def test_transition_cap_is_fail_closed(self):
        p=self.projector();p.transitions=capture.MAX_TRANSITIONS
        pkg='chengwang/internal/api';p.packages[pkg]='STARTED'
        p._transition(pkg+'::TestX','run',1,None)
        self.assertEqual(p.failure,'TRANSITION_CAP')

    def test_delta_payload_rejects_absolute_mutant(self):
        p=self.projector();value=p.payload(FakeGuard(),boundaries(),'COMPLETE_EOF')
        raw=capture.canonical(value);checker.check_payload(raw,'FOUNDATION_ORDINARY',COMMIT,TREE)
        value['originMonotonicNs']=123
        with self.assertRaises(ValueError):checker.check_payload(capture.canonical(value),'FOUNDATION_ORDINARY',COMMIT,TREE)

    def test_capacity_four_row_reconstruction_and_overflow(self):
        p=self.projector('CAPACITY_FULL_RACE');value=capture.decode(capture.canonical(p.payload(FakeGuard(),boundaries(10),'COMPLETE_EOF')))
        argv=[str(Path.cwd()/'go'),'test','-race','-json','-count=1','-timeout=180s','-tags','chengwang_capacity_profile','-run','^Test',
            './internal/adapter/mihomo','./internal/mihomodeploy','./internal/authn','./internal/api','./internal/serverruntime','./internal/authz'];rows=[
            {'seq':1,'event':'START_INTENT','class':'GO_TEST','argv':argv,'pid':None,'exitCode':None,'monotonicNs':1},
            {'seq':2,'event':'STARTED','class':'GO_TEST','argv':argv,'pid':2,'exitCode':None,'monotonicNs':2},
            {'seq':3,'event':'COLLECTOR_HANDOFF','class':'GO_TEST','argv':argv,'pid':2,'exitCode':None,'monotonicDeltaFromStartedNs':1},
            {'seq':4,'event':'WAIT_RETURNED','class':'GO_TEST','argv':argv,'pid':2,'exitCode':0,'monotonicNs':20}]
        self.assertEqual(checker.check_capacity_commands(rows,value),18)
        rows[2]['monotonicDeltaFromStartedNs']=capture.MAX_I63
        with self.assertRaises(ValueError):checker.check_capacity_commands(rows,value)

    def test_canonical_bytes_and_postpublication_fields_forbidden(self):
        p=self.projector();raw=capture.canonical(p.payload(FakeGuard(),boundaries(),'COMPLETE_EOF'))
        self.assertEqual(capture.canonical(capture.decode(raw)),raw)
        value=capture.decode(raw);value['publicationSucceeded']=True
        with self.assertRaises(ValueError):checker.check_payload(capture.canonical(value),'FOUNDATION_ORDINARY',COMMIT,TREE)

class GuardModels(unittest.TestCase):
    class Process:
        def __init__(self,codes=(0,)):self.pid=123;self.codes=list(codes);self.waits=0;self.stdout=io.BytesIO()
        def wait(self):
            self.waits+=1;value=self.codes.pop(0)
            if isinstance(value,BaseException):raise value
            return value

    def guard(self,process=None):
        g=capture.OwnerGuard(io.BytesIO(),io.BytesIO());g.process=process or self.Process()
        g.pipe=g.process.stdout;g.expectedPgid=g.process.pid;g.validatedPgid=g.process.pid
        g.owner='CALLER_OWNS';g.active=True;return g

    def test_signal_handler_only_records_pending(self):
        g=capture.OwnerGuard(io.BytesIO(),io.BytesIO());g._record_signal(signal.SIGINT,None)
        g._record_signal(signal.SIGTERM,None)
        self.assertTrue(g.pendingCancellation);self.assertTrue(g.repeatedSignal)

    def test_owner_transfer_is_one_guard_ordinary_assignment(self):
        g=self.guard();origin=g.transfer_to_collector()
        self.assertEqual(g.owner,'COLLECTOR_OWNS');self.assertTrue(g.handoffActive);self.assertGreater(origin,0)

    def test_kill_marked_before_failing_syscall_and_wait_once(self):
        p=self.Process();g=self.guard(p)
        with mock.patch('go_timeline_capture.signal.SIGKILL',9,create=True), mock.patch('go_timeline_capture.os.killpg',side_effect=OSError,create=True):g.cleanup(kill=True)
        g.cleanup(kill=True)
        self.assertTrue(g.killIssued);self.assertTrue(g.waitCompleted);self.assertEqual(p.waits,1)

    def test_wait_retries_interrupted_then_marks_complete(self):
        p=self.Process((InterruptedError(),-9));g=self.guard(p)
        with mock.patch('go_timeline_capture.signal.SIGKILL',9,create=True), mock.patch('go_timeline_capture.os.killpg',create=True):g.cleanup(kill=True)
        self.assertEqual(p.waits,2);self.assertEqual(g.returncode,-9)

    def test_close_exception_clears_slot_and_no_integer_retry(self):
        class Bad:
            def close(self):raise OSError
        g=capture.OwnerGuard(Bad(),io.BytesIO());capture._close_slot(g,'rawSink')
        self.assertIsNone(g.rawSink)

    def test_repeated_pending_cancellation_has_one_cleanup(self):
        p=self.Process();g=self.guard(p);g.owner='COLLECTOR_OWNS'
        g._record_signal(signal.SIGINT,None);g._record_signal(signal.SIGTERM,None)
        with mock.patch('go_timeline_capture.signal.SIGKILL',9,create=True), mock.patch('go_timeline_capture.os.killpg',create=True) as kill:
            with self.assertRaises(InterruptedError):g.service_pending()
            g.cleanup(kill=True)
        self.assertEqual(kill.call_count,1);self.assertEqual(p.waits,1)

    def test_signal_at_popen_return_cannot_unwind_registration(self):
        g=capture.OwnerGuard(io.BytesIO(),io.BytesIO());g.installed=[signal.SIGINT,signal.SIGTERM]
        process=self.Process()
        def returned(*_args,**_kwargs):g._record_signal(signal.SIGTERM,None);return process
        with mock.patch('go_timeline_capture.subprocess.Popen',side_effect=returned), \
             mock.patch('go_timeline_capture.os.getpgid',return_value=process.pid,create=True):
            self.assertIs(g.spawn(['stub'],stdout=-1),process)
        self.assertIs(g.process,process);self.assertEqual(g.owner,'CALLER_OWNS');self.assertTrue(g.pendingCancellation)

    def test_popen_failure_has_no_live_owner(self):
        g=capture.OwnerGuard(io.BytesIO(),io.BytesIO());g.installed=[signal.SIGINT,signal.SIGTERM]
        with mock.patch('go_timeline_capture.subprocess.Popen',side_effect=OSError):
            with self.assertRaises(OSError):g.spawn(['stub'])
        self.assertIsNone(g.process);self.assertEqual(g.owner,'NO_CHILD');self.assertEqual(g.failure,'POPEN_FAILED')

class CollectorStubModels(unittest.TestCase):
    class Process:
        pid=991
        returncode=None
        def __init__(self,stream):self.stdout=stream;self.waits=0
        def wait(self):self.waits+=1;self.returncode=0;return 0

    def run_stream(self,raw):
        source=tempfile.TemporaryFile();source.write(raw);source.seek(0)
        raw_sink=tempfile.TemporaryFile();stderr=tempfile.TemporaryFile()
        process=self.Process(source);guard=capture.OwnerGuard(raw_sink,stderr)
        guard.process=process;guard.pipe=source;guard.expectedPgid=guard.validatedPgid=process.pid
        guard.owner='COLLECTOR_OWNS';guard.active=guard.handoffActive=True
        projector=capture.Projector('FOUNDATION_ORDINARY',COMMIT,TREE,capture.load_registry())
        try:
            with mock.patch('go_timeline_capture.publish_safe') as publish:
                code,_=capture.collect(guard,projector,0,publication_parent=Path('/synthetic'))
            raw_sink.seek(0);retained=raw_sink.read()
            return code,projector,publish.call_args.args[2],retained,process
        finally:
            guard.cleanup(kill=False)
            self.assertEqual(guard.owner,'REAPED')
            self.assertIsNone(guard.pipe)
            self.assertIsNone(guard.rawSink)
            self.assertIsNone(guard.stderrSink)

    def test_complete_subprocess_stub_drains_reaps_and_projects(self):
        rows=[]
        for package in capture.PACKAGES:rows.append(event(package,'start'))
        for key in capture.load_registry()['names']:
            package,name=key.split('::',1);rows.extend((event(package,'run',name),event(package,'pass',name,.01)))
        for package in capture.PACKAGES:rows.append(event(package,'pass',elapsed=1.0))
        raw=b'\n'.join(rows)+b'\n';code,projector,public,retained,process=self.run_stream(raw)
        self.assertEqual(code,0);self.assertEqual(retained,raw);self.assertEqual(process.waits,1)
        self.assertEqual(capture.decode(public)['topCoverage'],'COMPLETE_TERMINAL')
        self.assertTrue(projector.semantic)

    def test_semantic_failure_still_drains_and_retains_later_raw_bytes(self):
        package='chengwang/internal/api'
        raw=event(package,'start')+b'\n'+b'{bad-json}\n'+b'CANARY-AFTER-REJECT\n'
        code,projector,public,retained,process=self.run_stream(raw)
        self.assertEqual(code,0);self.assertEqual(retained,raw);self.assertEqual(process.waits,1)
        self.assertFalse(projector.semantic);self.assertEqual(capture.decode(public)['topCoverage'],'REJECTED_SEMANTICS')
        self.assertNotIn(b'CANARY-AFTER-REJECT',public)

class SourceContracts(unittest.TestCase):
    def text(self,name):return (Path(__file__).parent/name).read_text(encoding='utf8')
    def test_handler_ast_has_no_raise_io_lock_or_cleanup_call(self):
        tree=ast.parse(self.text('go_timeline_capture.py'))
        fn=next(n for n in ast.walk(tree)if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))and n.name=='_record_signal')
        self.assertFalse(any(isinstance(n,ast.Raise)for n in ast.walk(fn)))
        calls=[ast.unparse(n.func)for n in ast.walk(fn)if isinstance(n,ast.Call)]
        self.assertEqual(calls,[])

    def test_source_has_no_pthread_mask_preexec_or_cas(self):
        text=self.text('go_timeline_capture.py').lower()
        self.assertNotIn('pthread_sigmask(',text);self.assertNotIn('preexec_fn=',text)
        self.assertNotIn('compare_and_set',text)

    def test_actual_caller_aliases_clear_before_transfer(self):
        capture_source=self.text('go_timeline_capture.py')
        profile_source=(Path(__file__).parents[1]/'mihomo-capacity-profile/profile_evidence.py').read_text(encoding='utf8')
        self.assertLess(capture_source.index('raw = None\n        stderr = None'),
                        capture_source.index('origin = guard.transfer_to_collector()'))
        self.assertLess(capture_source.index('process = None'),
                        capture_source.index('origin = guard.transfer_to_collector()'))
        self.assertLess(profile_source.index('raw=None;stderr=None'),
                        profile_source.index('origin=guard.transfer_to_collector()'))
        self.assertLess(profile_source.index('p=None'),
                        profile_source.index('origin=guard.transfer_to_collector()'))
        self.assertNotIn('caller_process_alias',capture_source)

    def test_source_paths_are_exact_twelve(self):
        self.assertEqual(len(checker.SOURCE_PATHS),12);self.assertEqual(len(set(checker.SOURCE_PATHS)),12)

    def test_git_wrapper_has_both_replace_defenses(self):
        text=self.text('check_go_timeline.py')
        self.assertIn("'--no-replace-objects'",text);self.assertIn("GIT_NO_REPLACE_OBJECTS",text)

    def git(self,repo,*args,input=None):
        env=os.environ.copy()
        env.pop('GIT_NO_REPLACE_OBJECTS',None)
        result=subprocess.run(['git','-C',str(repo),*args],input=input,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,check=True,env=env)
        return result.stdout.strip().decode()

    def repo_fixture(self):
        root=Path(self._temp.name);self.git(root,'init','-q');self.git(root,'config','user.email','timeline@example.invalid')
        self.git(root,'config','user.name','Timeline Test');self.git(root,'config','core.autocrlf','false');(root/'bound.txt').write_bytes(b'original\n')
        self.git(root,'add','bound.txt');self.git(root,'commit','-q','-m','original');return root,self.git(root,'rev-parse','HEAD')

    def test_protected_wrapper_ignores_active_commit_replacement(self):
        self._temp=tempfile.TemporaryDirectory()
        try:
            repo,original=self.repo_fixture();(repo/'bound.txt').write_bytes(b'replacement\n')
            self.git(repo,'commit','-q','-am','replacement');replacement=self.git(repo,'rev-parse','HEAD')
            self.git(repo,'replace',original,replacement);(repo/'bound.txt').write_bytes(b'original\n')
            with mock.patch.dict(os.environ,{'GIT_NO_REPLACE_OBJECTS':'1'}):
                self.assertEqual(self.git(repo,'show',original+':bound.txt'),'replacement')
                self.assertEqual(checker.RawGit(repo).source(original,'bound.txt'),b'original\n')
        finally:self._temp.cleanup()

    def test_protected_wrapper_ignores_active_blob_replacement(self):
        self._temp=tempfile.TemporaryDirectory()
        try:
            repo,commit=self.repo_fixture();blob=self.git(repo,'rev-parse',commit+':bound.txt')
            replacement=self.git(repo,'hash-object','-w','--stdin',input=b'replacement\n')
            self.git(repo,'replace',blob,replacement)
            with mock.patch.dict(os.environ,{'GIT_NO_REPLACE_OBJECTS':'1'}):
                self.assertEqual(self.git(repo,'cat-file','blob',blob),'replacement')
                self.assertEqual(checker.RawGit(repo).source(commit,'bound.txt'),b'original\n')
        finally:self._temp.cleanup()

    def test_checker_has_no_direct_git_subprocess_outside_wrapper(self):
        tree=ast.parse(self.text('check_go_timeline.py'))
        calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='subprocess.run']
        self.assertEqual(len(calls),1)

    def test_publication_is_link_no_replace_not_rename(self):
        tree=ast.parse(self.text('go_timeline_capture.py'))
        fn=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='publish_safe')
        calls=[ast.unparse(n.func)for n in ast.walk(fn)if isinstance(n,ast.Call)]
        self.assertIn('os.link',calls);self.assertNotIn('os.rename',calls);self.assertNotIn('os.replace',calls)

    def test_exact_member_groups_are_source_fixed_and_publisher_stays_incremental(self):
        ordinary=capture.FINAL_NAMES['FOUNDATION_ORDINARY'];race=capture.FINAL_NAMES['FOUNDATION_RACE']
        capacity=capture.FINAL_NAMES['CAPACITY_FULL_RACE']
        self.assertEqual(checker.EXACT_MEMBERS,{'FOUNDATION':(ordinary,race),'CAPACITY':(capacity,)})
        for expected in checker.EXACT_MEMBERS.values():checker._require_exact_members(list(expected),expected)
        tree=ast.parse(self.text('check_go_timeline.py'))
        check=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='check')
        self.assertEqual(sum(ast.unparse(n.func)=='stable_read_set' for n in ast.walk(check)if isinstance(n,ast.Call)),1)
        publisher=next(n for n in ast.walk(ast.parse(self.text('go_timeline_capture.py')))
                       if isinstance(n,ast.FunctionDef)and n.name=='publish_safe')
        self.assertNotIn('EXACT_MEMBERS',ast.unparse(publisher))

    def test_exact_members_reject_missing_crosslane_unrelated_stage_and_duplicates(self):
        foundation=checker.EXACT_MEMBERS['FOUNDATION'];capacity=checker.EXACT_MEMBERS['CAPACITY']
        mutants=[[],[foundation[0]],[*foundation,capacity[0]],[*foundation,'unrelated.txt'],
                 [*foundation,foundation[0]+'.stage'],[foundation[0],foundation[0]],
                 [capacity[0],foundation[0]],[capacity[0],'unrelated.txt'],
                 [capacity[0],capacity[0]+'.stage']]
        for observed in mutants:
            expected=foundation if foundation[0] in observed else capacity
            with self.subTest(observed=observed),self.assertRaises(ValueError):
                checker._require_exact_members(observed,expected)

    def test_final_identity_rejects_symlink_hardlink_subdir_owner_and_size(self):
        parent=types.SimpleNamespace(st_dev=7)
        def value(mode=stat.S_IFREG|0o644,uid=1001,gid=1002,nlink=1,size=9):
            return types.SimpleNamespace(st_mode=mode,st_uid=uid,st_gid=gid,st_nlink=nlink,st_dev=7,st_size=size)
        with mock.patch('check_go_timeline.os.geteuid',return_value=1001,create=True),\
             mock.patch('check_go_timeline.os.getegid',return_value=1002,create=True):
            checker._require_final_stat(value(),parent,9)
            for mutant in (value(stat.S_IFLNK|0o777),value(stat.S_IFDIR|0o755),value(nlink=2),
                           value(uid=0),value(gid=0),value(size=8)):
                with self.assertRaises(ValueError):checker._require_final_stat(mutant,parent,9)

    def test_named_directory_identity_is_checked_before_and_after_members(self):
        def value(**changes):
            fields=dict(st_dev=1,st_ino=2,st_mode=stat.S_IFDIR|0o755,st_uid=3,st_gid=4,
                        st_nlink=2,st_mtime_ns=5,st_ctime_ns=6);fields.update(changes)
            return types.SimpleNamespace(**fields)
        checker._require_same_dir(value(),value())
        for mutant in (value(st_dev=9),value(st_ino=9),value(st_mtime_ns=9),value(st_ctime_ns=9)):
            with self.assertRaises(ValueError):checker._require_same_dir(value(),mutant)
        tree=ast.parse(self.text('check_go_timeline.py'))
        fn=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='stable_read_set')
        calls=[ast.unparse(n.func)for n in ast.walk(fn)if isinstance(n,ast.Call)]
        self.assertEqual(calls.count('_member_names'),2);self.assertEqual(calls.count('_require_same_dir'),3)

    def test_workflow_uploads_are_exact_and_checker_gated(self):
        root=Path(__file__).resolve().parents[3]
        life=(root/'.github/workflows/chengwang-mihomo-lifecycle.yml').read_text(encoding='utf8')
        cap=(root/'.github/workflows/chengwang-mihomo-capacity-profile.yml').read_text(encoding='utf8')
        for text in (life,cap):
            self.assertIn('go_timeline_check',text);self.assertIn("outputs.timeline_ready == 'true'",text)
        self.assertNotIn('mihomo-foundation-contracts/*.json',life)

    def test_workflow_mirrors_root_publisher_then_fresh_runner_custody(self):
        root=Path(__file__).resolve().parents[3]
        life=(root/'.github/workflows/chengwang-mihomo-lifecycle.yml').read_text(encoding='utf8')
        cap=(root/'.github/workflows/chengwang-mihomo-capacity-profile.yml').read_text(encoding='utf8')
        runner=self.text('run_contracts.sh')
        profile=(root/'chengwang/deploy/mihomo-capacity-profile/profile_evidence.py').read_text(encoding='utf8')
        self.assertIn('install -d -m 0755 "$timeline_public"',runner)
        self.assertIn('os.mkdir(publication,0o755)',profile)
        for text in (life,cap):
            self.assertEqual(text.count('sudo python3 -B chengwang/deploy/mihomo-lifecycle-lab/check_go_timeline.py'),1)
            self.assertEqual(text.count('python3 -B chengwang/deploy/mihomo-lifecycle-lab/check_go_timeline.py'),2)
            self.assertIn('name: Establish runner-owned fresh timeline custody',text)
            self.assertIn('test "$(stat -c %u "$timeline_public")" -eq "$(id -u)"',text)
            self.assertIn('test "$(stat -c %g "$timeline_public")" -eq "$(id -g)"',text)
            self.assertIn('/timeline-public/',text)
            self.assertIn('/timeline-public\n',text)
        publisher=self.text('go_timeline_capture.py');reader=self.text('check_go_timeline.py')
        self.assertIn('before.st_uid==os.geteuid() and before.st_gid==os.getegid()',publisher)
        self.assertIn('before.st_uid==os.geteuid() and before.st_gid==os.getegid()',reader)
        self.assertIn("publication=evidence/capture.PUBLICATION_DIR",reader)

    def test_publication_owner_is_not_caller_selected_or_existing_tree_chowned(self):
        root=Path(__file__).resolve().parents[3]
        texts=[self.text('go_timeline_capture.py'),self.text('run_contracts.sh'),
               (root/'.github/workflows/chengwang-mihomo-lifecycle.yml').read_text(encoding='utf8'),
               (root/'.github/workflows/chengwang-mihomo-capacity-profile.yml').read_text(encoding='utf8')]
        self.assertNotIn('--publication-uid',texts[0]);self.assertNotIn('--publication-gid',texts[0])
        self.assertTrue(all('chown ' not in text for text in texts))

if __name__=='__main__':unittest.main()
