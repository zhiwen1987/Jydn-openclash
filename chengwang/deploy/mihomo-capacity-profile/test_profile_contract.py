import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


EXPECTED_FULL_FMT = (
    'internal/mihomodeploy/lifecycle_capacity_profile_linux_test.go',
    'internal/mihomodeploy/lab_kernel_linux.go',
    'internal/mihomodeploy/lab_native_recovery_observer_default.go',
    'internal/mihomodeploy/lab_native_recovery_observer_linux.go',
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
    'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
    'internal/api/server.go',
    'internal/api/subscriptions.go',
    'internal/api/subscriptions_test.go',
    'internal/authn/snapshot_manager.go',
    'internal/authn/snapshot_manager_linux_test.go',
    'internal/authz/model.go',
    'internal/authz/policy.go',
    'internal/authz/subscription.go',
    'internal/authz/subscription_refresh_test.go',
    'internal/serverruntime/subscription_config.go',
    'internal/serverruntime/subscription_config_test.go',
    'internal/subscription/control.go',
    'internal/subscription/refresh.go',
    'internal/subscription/refresh_test.go',
    'internal/subscription/store.go',
    'internal/subscriptionctl/contract.go',
    'internal/subscriptionctl/refresh.go',
    'internal/subscriptionctl/service.go',
    'internal/subscriptionctl/service_linux_test.go',
    'internal/subscriptionpolicy/catalog.go',
    'internal/subscriptionpolicy/catalog_access.go',
    'internal/subscriptionpolicy/refresh_test.go',
)
BOUND_CREDENTIALS_V2_ADDED_FMT = (
    'internal/authn/continuous_bound_credentials_linux.go',
    'internal/authn/continuous_bound_credentials_linux_test.go',
    'internal/authn/store.go',
    'internal/serverruntime/mihomo_lab_runtime.go',
    'internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go',
)
SOURCE_ORIGIN_ADDED_FMT = (
    'internal/mihomodeploy/lab_kernel_linux.go',
    'internal/mihomodeploy/lab_native_recovery_observer_default.go',
    'internal/mihomodeploy/lab_native_recovery_observer_linux.go',
)
P207A_V3_ADDED_FMT = EXPECTED_FULL_FMT[28:]


def load(name):
    path = Path(__file__).absolute().with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('capacity_' + name, path)
    if spec is None or spec.loader is None:
        raise ValueError('capacity profile source unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path.read_text(encoding='utf-8')


def varint(value):
    result=bytearray()
    while value>=0x80:result.append((value&0x7f)|0x80);value>>=7
    result.append(value);return bytes(result)


def protobuf_field(number,wire,value):
    key=varint((number<<3)|wire)
    return key+varint(value)if wire==0 else key+varint(len(value))+value


def synthetic_profile(reader):
    name=(reader.PACKAGE+'.'+reader.TOP).encode();function=protobuf_field(2,0,0)
    return gzip.compress(b''.join((protobuf_field(6,2,name),protobuf_field(5,2,function),
        protobuf_field(2,2,b''),protobuf_field(10,0,1_000_000_000))),mtime=0)


def single_rows(reader,outcomes=None,parent=None,package=None,limit=None):
    outcomes=list(outcomes or ('pass',)*len(reader.SINGLE_CHILDREN));limit=len(outcomes)if limit is None else limit
    parent=parent or ('pass'if all(value=='pass'for value in outcomes[:limit])and limit==len(reader.SINGLE_CHILDREN)else'fail')
    package=package or parent;time='2026-11-03T00:00:00Z'
    rows=[{'Time':time,'Action':'start','Package':reader.PACKAGE},
        {'Time':time,'Action':'run','Package':reader.PACKAGE,'Test':reader.TOP}]
    for name,outcome in zip(reader.SINGLE_CHILDREN[:limit],outcomes[:limit]):
        rows.extend(({'Time':time,'Action':'run','Package':reader.PACKAGE,'Test':name},
            {'Time':time,'Action':outcome,'Package':reader.PACKAGE,'Test':name,'Elapsed':0.01}))
    rows.extend(({'Time':time,'Action':parent,'Package':reader.PACKAGE,'Test':reader.TOP,'Elapsed':0.05},
        {'Time':time,'Action':package,'Package':reader.PACKAGE,'Elapsed':0.05}))
    return rows


def event_wire(reader,rows):return b''.join(reader.encoded(row)for row in rows)


def synthetic_commands(reader,go_root,go_exit):
    go=str(go_root/'bin/go');commands=(
        ('VERSION',[go,'version'],0),
        ('FORMAT',[str(go_root/'bin/gofmt'),'-d',*reader.CAPACITY_FMT],0),
        ('GO_TEST',[go,*reader.GO_ARGS],go_exit),
        ('PPROF_TOP',[go,'tool','pprof','-symbolize=local','-top',reader.PRIVATE+'/cpu.pprof'],0),
        ('PPROF_CUM',[go,'tool','pprof','-symbolize=local','-top','-cum',reader.PRIVATE+'/cpu.pprof'],0))
    rows=[];seq=0;observed=10
    for kind,argv,code in commands:
        pid=4000+len(rows)
        for event,event_pid,event_code in(('START_INTENT',None,None),('STARTED',pid,None),('WAIT_RETURNED',pid,code)):
            seq+=1;rows.append({'seq':seq,'event':event,'class':kind,'argv':argv,'pid':event_pid,
                'exitCode':event_code,'monotonicNs':observed});observed+=10
    return b''.join(reader.encoded(row)for row in rows)


def synthetic_single_evidence(reader,rows,go_exit=0):
    commit='3'*40;go_root=Path('//fixed/go-root');profile=synthetic_profile(reader);profile_sha=reader.sha(profile)
    host={'networkNamespace':'net:[1]','mountNamespace':'mnt:[1]','pidNamespace':'pid:[1]','resolvSHA256':'a'*64}
    sandbox={'schema':'chengwang.capacity-profile-sandbox/v1','uid':10001,'gid':10001,'effectiveCaps':'0000000000000000',
        'noNewPrivileges':True,'interfaces':['lo'],'defaultRoutes':{'ipv4':[],'ipv6':[]},'environmentKeys':reader.ENV,
        'sourceAliasReadOnly':True,'goRootReadOnly':True,'goRoot':str(go_root),'networkNamespace':'net:[2]',
        'mountNamespace':'mnt:[2]','pidNamespace':'pid:[2]','production':False}
    state={'schema':'chengwang.capacity-cpu-profile-state/v1','sourceCommit':commit,'stopReason':'M_RUN_RETURNED',
        'startedAt':'2026-11-03T00:00:00Z','stoppedAt':'2026-11-03T00:00:01Z','durationNanoseconds':1_000_000_000,
        'profileBytes':len(profile),'profileSHA256':profile_sha,'writerFailed':False,'limitReached':False,
        'syncSucceeded':True,'closeSucceeded':True,'complete':True,'timerSeconds':60,'testTimeoutSeconds':180}
    state_raw=reader.encoded(state)
    wrapped={'schema':'chengwang.capacity-cpu-profile-bytes/v1','sourceCommit':commit,'bytes':len(profile),
        'sha256':profile_sha,'dataBase64':base64.b64encode(profile).decode(),
        'profileStateSHA256':hashlib.sha256(state_raw).hexdigest()}
    execution={'schema':'chengwang.capacity-profile-execution/v1','sourceCommit':commit,'versionExit':0,'formatExit':0,
        'goExit':go_exit,'topExit':0,'cumExit':0,'profileCaptureComplete':True,'production':False}
    raw={'host-before.json':reader.encoded(host),'host-after.json':reader.encoded(host),'source-before.json':b'{}\n',
        'source-after.json':b'{}\n','sandbox.json':reader.encoded(sandbox),'go-version.txt':b'go version go1.23.12 linux/amd64\n',
        'gofmt.patch':b'','gofmt.stderr':b'','capacity.json':event_wire(reader,rows),'capacity.stderr':b'',
        'commands.jsonl':synthetic_commands(reader,go_root,go_exit),'execution.json':reader.encoded(execution),
        'profile-state.json':state_raw,'cpu-profile.json':reader.encoded(wrapped),'pprof-top.txt':b'flat cum\n',
        'pprof-top.stderr':b'','pprof-cum.txt':b'flat cum\n','pprof-cum.stderr':b''}
    assert set(raw)==set(reader.PUBLIC);return raw,commit


class CapacityProfileSourceContractModels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.producer, cls.producer_source = load('profile_evidence')
        cls.reader, cls.reader_source = load('check_profile')

    def capture_commands(self, mode):
        observed = []

        class Process:
            pid = 4242

            def __init__(self, argv, **_):
                observed.append(list(argv))

            def wait(self):
                return 0

        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            environment = dict(os.environ)
            environment.update(CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT='1'*40)
            if mode == 'FULL_CONTRACTS':
                environment['CHENGWANG_CAPACITY_PROFILE_MODE'] = mode
            else:
                environment.pop('CHENGWANG_CAPACITY_PROFILE_MODE', None)
            with mock.patch.object(self.producer, 'PRIVATE', private), \
                 mock.patch.object(self.producer, 'SOURCE', Path.cwd()), \
                 mock.patch.object(self.producer.sys, 'platform', 'linux'), \
                 mock.patch.object(self.producer.os, 'getuid', return_value=10001, create=True), \
                 mock.patch.object(self.producer.os, 'getgid', return_value=10001, create=True), \
                 mock.patch.object(self.producer.os, 'O_NOFOLLOW', 0, create=True), \
                 mock.patch.object(self.producer.os, 'umask', return_value=0o022), \
                 mock.patch.object(self.producer, 'resource_observation', return_value={'bounded':True}), \
                 mock.patch.object(self.producer.subprocess, 'Popen', Process), \
                 mock.patch.dict(self.producer.os.environ, environment, clear=True):
                self.producer.commands(Path('/fixed-go-root'), mode)
            rows = [json.loads(line) for line in (private/'commands.jsonl').read_text(encoding='utf-8').splitlines()]
        return observed, rows

    def test_full_formatter_argv_uses_the_independent_exact_50_path_contract(self):
        self.assertEqual(tuple(self.producer.FULL_FMT), EXPECTED_FULL_FMT)
        self.assertEqual(tuple(self.reader.FULL_FMT), EXPECTED_FULL_FMT)
        self.assertEqual(tuple(self.producer.CAPACITY_FMT), EXPECTED_FULL_FMT[:4])
        self.assertEqual(tuple(self.reader.CAPACITY_FMT), EXPECTED_FULL_FMT[:4])
        self.assertEqual(self.producer.GO_ARGS,self.reader.GO_ARGS)
        self.assertEqual(self.producer.FULL_GO_ARGS,self.reader.FULL_GO_ARGS)
        self.assertEqual(self.producer.GO_ARGS,
                         ['test','-race','-json','-count=1','-timeout=180s','-tags','chengwang_capacity_profile',
                          '-run','^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$',
                          './internal/mihomodeploy'])
        self.assertEqual(self.producer.FULL_GO_ARGS,
                         ['test','-race','-json','-count=1','-timeout=180s','-tags','chengwang_capacity_profile',
                          '-run','^Test','./internal/adapter/mihomo','./internal/mihomodeploy','./internal/authn',
                          './internal/api','./internal/serverruntime','./internal/authz'])
        observed, rows = self.capture_commands('FULL_CONTRACTS')
        go = str(Path('/fixed-go-root')/'bin/go')
        self.assertEqual(observed[1],[str(Path('/fixed-go-root')/'bin/gofmt'),'-d',*EXPECTED_FULL_FMT])
        self.assertEqual(observed[2],[go,*self.reader.FULL_GO_ARGS])
        started = [row for row in rows if row['event'] == 'START_INTENT']
        self.assertEqual([row['class'] for row in started],['VERSION','FORMAT','GO_TEST','PPROF_TOP','PPROF_CUM'])
        self.assertEqual(started[1]['argv'],observed[1])
        observed, rows = self.capture_commands('SINGLE_CASE')
        self.assertEqual(observed[1],[str(Path('/fixed-go-root')/'bin/gofmt'),'-d',*EXPECTED_FULL_FMT[:4]])
        self.assertEqual(observed[2],[go,*self.reader.GO_ARGS])
        started = [row for row in rows if row['event'] == 'START_INTENT']
        self.assertEqual([row['class'] for row in started],['VERSION','FORMAT','GO_TEST','PPROF_TOP','PPROF_CUM'])
        self.assertEqual(started[1]['argv'],observed[1])

    def test_bound_credentials_v2_five_path_delta_cannot_be_dropped_or_aliased(self):
        self.assertEqual(tuple(path for path in EXPECTED_FULL_FMT if path in BOUND_CREDENTIALS_V2_ADDED_FMT),
                         BOUND_CREDENTIALS_V2_ADDED_FMT)
        for path in BOUND_CREDENTIALS_V2_ADDED_FMT:
            with self.subTest(path=path):
                shortened = tuple(item for item in EXPECTED_FULL_FMT if item != path)
                self.assertNotEqual(shortened,tuple(self.producer.FULL_FMT))
                self.assertNotEqual(shortened,tuple(self.reader.FULL_FMT))
        aliased = list(EXPECTED_FULL_FMT)
        aliased[aliased.index(BOUND_CREDENTIALS_V2_ADDED_FMT[0])] = BOUND_CREDENTIALS_V2_ADDED_FMT[1]
        self.assertNotEqual(tuple(aliased),tuple(self.producer.FULL_FMT))
        reordered = list(EXPECTED_FULL_FMT)
        first = reordered.index(BOUND_CREDENTIALS_V2_ADDED_FMT[0])
        second = reordered.index(BOUND_CREDENTIALS_V2_ADDED_FMT[1])
        reordered[first], reordered[second] = reordered[second], reordered[first]
        self.assertNotEqual(tuple(reordered),tuple(self.producer.FULL_FMT))
        self.assertNotEqual(tuple(reordered),tuple(self.reader.FULL_FMT))
        self.assertEqual(tuple(path for path in EXPECTED_FULL_FMT if path in SOURCE_ORIGIN_ADDED_FMT),
                         SOURCE_ORIGIN_ADDED_FMT)
        for path in SOURCE_ORIGIN_ADDED_FMT:
            with self.subTest(origin_path=path):
                shortened = tuple(item for item in EXPECTED_FULL_FMT if item != path)
                self.assertNotEqual(shortened,tuple(self.producer.FULL_FMT))
                self.assertNotEqual(shortened,tuple(self.reader.FULL_FMT))
        origin_reordered = list(EXPECTED_FULL_FMT)
        first = origin_reordered.index(SOURCE_ORIGIN_ADDED_FMT[0])
        second = origin_reordered.index(SOURCE_ORIGIN_ADDED_FMT[1])
        origin_reordered[first], origin_reordered[second] = origin_reordered[second], origin_reordered[first]
        self.assertNotEqual(tuple(origin_reordered),tuple(self.producer.FULL_FMT))
        self.assertNotEqual(tuple(origin_reordered),tuple(self.reader.FULL_FMT))
        self.assertEqual(len(P207A_V3_ADDED_FMT),22)
        for path in P207A_V3_ADDED_FMT:
            with self.subTest(p207a_path=path):
                shortened = tuple(item for item in EXPECTED_FULL_FMT if item != path)
                self.assertNotEqual(shortened,tuple(self.producer.FULL_FMT))
                self.assertNotEqual(shortened,tuple(self.reader.FULL_FMT))
        p207a_reordered = list(EXPECTED_FULL_FMT)
        first = p207a_reordered.index(P207A_V3_ADDED_FMT[0])
        second = p207a_reordered.index(P207A_V3_ADDED_FMT[-1])
        p207a_reordered[first], p207a_reordered[second] = p207a_reordered[second], p207a_reordered[first]
        self.assertNotEqual(tuple(p207a_reordered),tuple(self.producer.FULL_FMT))
        self.assertNotEqual(tuple(p207a_reordered),tuple(self.reader.FULL_FMT))
        self.assertEqual(len(EXPECTED_FULL_FMT),len(set(EXPECTED_FULL_FMT)),50)

    def test_full_mode_adds_only_one_safe_timeline_and_four_row_go_group(self):
        self.assertEqual(self.reader.TIMELINE_NAME,'capacity-go-top-observation-timeline.json')
        self.assertEqual(self.reader.TIMELINE_DIR,'timeline-public')
        source=Path(self.producer.__file__).read_text(encoding='utf8')
        self.assertIn("journal(kind,argv,'COLLECTOR_HANDOFF'",source)
        self.assertIn("timeline.publish_safe(publication,",source)
        self.assertNotIn(self.reader.TIMELINE_NAME,self.reader.PUBLIC)

    def test_root_exporter_creates_only_dedicated_publication_directory(self):
        source=Path(self.producer.__file__).read_text(encoding='utf8')
        runner=Path(self.producer.__file__).with_name('run_profile.sh').read_text(encoding='utf8')
        self.assertIn('publication=out/timeline.PUBLICATION_DIR',source)
        self.assertIn('os.mkdir(publication,0o755)',source)
        self.assertIn('info.st_uid==os.geteuid()==0',source)
        self.assertIn('env -i PATH=/usr/bin:/bin',runner)
        self.assertNotIn('chown ',source+runner)

    def test_capacity_source_snapshot_uses_raw_git_and_records_tree(self):
        text=Path(self.reader.__file__).read_text(encoding='utf8')
        self.assertIn("'--no-replace-objects'",text)
        self.assertIn("GIT_NO_REPLACE_OBJECTS",text)
        self.assertIn("'sourceTree':tree",text)
        target='chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go'
        current='fab19f1ca714105f5002d31e2e37ca4cdb0296c5133431951ac81a1576056bc4'
        preformat='dee61e1330b0dd8e658ad19cea90404a49e23e87855bf8955303714d5c65dbc1'
        historical='ea0a3ec623691b161680727378e1feb638157322df230b60d0f7e09534a2b7d6'
        self.assertEqual(self.reader.CURRENT_FIXTURE_SOURCE_PINS[target],current)
        self.assertEqual(self.reader.CASE_IDENTITY,{
            'schema':'chengwang.capacity-profile-case-identity/v1',
            'caseName':self.reader.TOP,
            'version':'CURRENT_FIXTURE_OFFICIAL_GOFMT_V1',
            'currentFixtureSHA256':current,
            'preformatFixtureSHA256':preformat,
            'historicalBaselineReferenceSHA256':historical,
            'historicalBaselineRole':'HISTORICAL_REFERENCE_ONLY',
            'historicalBaselineMeasured':False,
            'performanceComparisonAuthorized':False,
        })
        self.reader.validate_current_source_pins(dict(self.reader.CURRENT_FIXTURE_SOURCE_PINS))
        self.reader.validate_case_identity(self.reader.case_identity())

        for name,digest in [('wrong_hash','0'*64),('preformat_source',preformat),('historical_source',historical)]:
            with self.subTest(rejected_source_pin=name):
                pins=dict(self.reader.CURRENT_FIXTURE_SOURCE_PINS);pins[target]=digest
                with self.assertRaises(ValueError):self.reader.validate_current_source_pins(pins)
        for name,key,value in (
                ('identity_schema','schema','chengwang.capacity-profile-case-identity/v0'),
                ('identity_version','version','HISTORICAL_BASELINE'),
                ('identity_current_hash','currentFixtureSHA256',historical),
                ('identity_historical_role','historicalBaselineRole','CURRENT_FIXTURE'),
                ('historical_claim','historicalBaselineMeasured',True),
                ('comparison_claim','performanceComparisonAuthorized',True)):
            with self.subTest(rejected_case_identity=name):
                identity=self.reader.case_identity();identity[key]=value
                with self.assertRaises(ValueError):self.reader.validate_case_identity(identity)

        single={'schema':self.reader.SINGLE_REPORT_SCHEMA,'scope':self.reader.SINGLE_REPORT_SCOPE,
                'caseIdentity':self.reader.case_identity(),'currentFixtureSourcePins':dict(self.reader.CURRENT_FIXTURE_SOURCE_PINS),
                'currentFixturePassed':False,'currentFixtureGoExit':1,'wholeCIPass':False,'production':False}
        full={'schema':self.reader.FULL_REPORT_SCHEMA,'scope':self.reader.FULL_REPORT_SCOPE,
              'caseIdentity':self.reader.case_identity(),'currentFixtureSourcePins':dict(self.reader.CURRENT_FIXTURE_SOURCE_PINS),
              'currentFixtureGoExit':1,'wholeCIPass':False,'production':False}
        self.assertIs(self.reader.validate_report_case_identity(single,'SINGLE_CASE'),single)
        self.assertIs(self.reader.validate_report_case_identity(full,'FULL_CONTRACTS'),full)
        self.assertEqual(self.reader.FULL_REPORT_SCHEMA,'chengwang.capacity-profile-verification/v2')
        for name,template,key,value,mode in (
                ('single_schema',single,'schema','chengwang.capacity-profile-verification/v1','SINGLE_CASE'),
                ('single_scope',single,'scope','CPU_DIAGNOSIS_OF_ORIGINAL_STRUCTURAL_CAPACITY_TEST_NOT_RECOVERY_OR_PRODUCTION','SINGLE_CASE'),
                ('full_schema',full,'schema','chengwang.capacity-profile-verification/v3','FULL_CONTRACTS'),
                ('full_scope',full,'scope','CURRENT_FIXTURE','FULL_CONTRACTS')):
            with self.subTest(rejected_report_label=name):
                changed=dict(template);changed[key]=value
                with self.assertRaises(ValueError):self.reader.validate_report_case_identity(changed,mode)
        legacy=dict(single);legacy['originalCasePassed']=False
        with self.assertRaises(ValueError):self.reader.validate_report_case_identity(legacy,'SINGLE_CASE')

    def test_single_current_fixture_requires_exact_five_child_fsm_and_keeps_failures_false(self):
        expected=tuple(self.reader.TOP+'/'+name for name in (
            'fixture-equivalence-1','fixture-equivalence-2','fixture-equivalence-8',
            'fixture-tamper-negatives','fixture-capacity-256'))
        self.assertEqual(self.reader.SINGLE_CHILDREN,expected)
        self.assertEqual(self.reader.SINGLE_REPORT_SCHEMA,'chengwang.capacity-profile-verification/v4')
        passing=single_rows(self.reader)
        raw,commit=synthetic_single_evidence(self.reader,passing)
        report=self.reader.verify_raw(copy.deepcopy(raw),commit)
        self.assertTrue(report['currentFixturePassed'])
        self.assertEqual((report['testRun'],report['testPass'],report['testFailureEvents']),(6,6,0))
        self.assertEqual(report['requiredCounts'],{'passed':6,'failed':0,'skipped':0,'unfinished':0,'notStarted':0})
        self.assertEqual((report['expectedDirectSubtestCount'],report['observedDirectSubtestRun'],report['notStartedDirectSubtestCount']),(5,5,0))

        parent_only=[passing[0],passing[1],passing[-2],passing[-1]]
        parent_raw,_=synthetic_single_evidence(self.reader,parent_only)
        with self.assertRaises(ValueError):self.reader.verify_raw(parent_raw,commit)

        continued_failure=single_rows(self.reader,('pass','fail','pass','pass','pass'),parent='fail',package='fail')
        failed_raw,_=synthetic_single_evidence(self.reader,continued_failure,1)
        failed_report=self.reader.verify_raw(failed_raw,commit)
        self.assertFalse(failed_report['currentFixturePassed'])
        self.assertEqual((failed_report['testRun'],failed_report['testPass'],failed_report['testFailureEvents']),(6,4,2))
        self.assertEqual(failed_report['requiredCounts'],{'passed':4,'failed':2,'skipped':0,'unfinished':0,'notStarted':0})

        prefix_failure=single_rows(self.reader,('pass','fail','pass'),parent='fail',package='fail',limit=3)
        prefix_raw,_=synthetic_single_evidence(self.reader,prefix_failure,1)
        prefix_report=self.reader.verify_raw(prefix_raw,commit)
        self.assertFalse(prefix_report['currentFixturePassed'])
        self.assertEqual(prefix_report['requiredCounts'],{'passed':2,'failed':2,'skipped':0,'unfinished':0,'notStarted':2})

        def changed(rows,index,key,value):
            result=copy.deepcopy(rows);result[index][key]=value;return result
        mutations={
            'missing_last_child_exit_zero':single_rows(self.reader,limit=4,parent='pass',package='pass'),
            'unknown_child':changed(passing,2,'Test',self.reader.TOP+'/unknown'),
            'nested_grandchild':changed(passing,2,'Test',expected[0]+'/nested'),
            'duplicate_run':passing[:3]+[copy.deepcopy(passing[2])]+passing[3:],
            'duplicate_pass':passing[:4]+[copy.deepcopy(passing[3])]+passing[4:],
            'pass_before_run':passing[:2]+[copy.deepcopy(passing[3]),copy.deepcopy(passing[2])]+passing[4:],
            'wrong_child_order':changed(changed(passing,2,'Test',expected[1]),3,'Test',expected[1]),
            'skip_child':changed(passing,3,'Action','skip'),
            'parent_terminal_early':passing[:-4]+[copy.deepcopy(passing[-2])]+passing[-4:-2]+[copy.deepcopy(passing[-1])],
            'package_terminal_early':passing[:-2]+[copy.deepcopy(passing[-1]),copy.deepcopy(passing[-2])],
            'parent_package_mismatch':changed(passing,-1,'Action','fail'),
            'missing_interior_then_later_child':passing[:2]+passing[4:],
        }
        for name,rows in mutations.items():
            with self.subTest(rejected_sequence=name):
                with self.assertRaises(ValueError):self.reader.single_events(event_wire(self.reader,rows),0)
        child_fail_zero=single_rows(self.reader,('pass','fail','pass','pass','pass'),parent='fail',package='fail')
        all_pass_nonzero=single_rows(self.reader)
        for name,rows,exit_code in(('child_fail_with_zero_exit',child_fail_zero,0),('all_pass_with_nonzero_exit',all_pass_nonzero,1)):
            with self.subTest(rejected_exit_binding=name):
                with self.assertRaises(ValueError):self.reader.single_events(event_wire(self.reader,rows),exit_code)

    def test_safe_rejection_summary_is_closed_bound_and_cannot_green(self):
        commit='3'*40;tree='4'*40;progress=self.reader.new_safe_progress('SINGLE_CASE')
        for phase in self.reader.SAFE_PHASES['SINGLE_CASE']:
            self.reader.safe_phase_begin(progress,phase)
            if phase=='EXECUTION_CONTRACT':
                progress['exitCodes']={key:0 for key in self.reader.SAFE_EXIT_KEYS};progress['profileCaptureComplete']=True
            if phase=='GO_EVENT_SEMANTICS':break
            self.reader.safe_phase_pass(progress,phase)
        value=self.reader.safe_rejection_value(progress,commit,tree,41560358147,1,'STRICT_PREDICATE_REJECTED')
        raw=self.reader.encoded(value)
        self.assertEqual(self.reader.validate_safe_rejection(raw,commit,tree,41560358147,1,'SINGLE_CASE'),value)
        self.assertIsNone(value['requiredCounts']['passed'])
        self.assertFalse(value['strictVerificationAccepted']or value['wholeCIPass']or value['production'])
        for secret in ('capacity.json','stderr','pprof','/tmp/','Traceback','https://','argv','Output'):
            with self.subTest(secret=secret):self.assertNotIn(secret,raw.decode())

        source_failed=self.reader.new_safe_progress('SINGLE_CASE')
        self.reader.safe_phase_begin(source_failed,'SOURCE_BINDING')
        source_failed_value=self.reader.safe_rejection_value(
            source_failed,commit,None,41560358147,1,'STRICT_PREDICATE_REJECTED')
        source_failed_raw=self.reader.encoded(source_failed_value)
        self.assertEqual(
            self.reader.validate_safe_rejection(
                source_failed_raw,commit,None,41560358147,1,'SINGLE_CASE'),
            source_failed_value)
        self.assertIs(source_failed_value['sourceGitVerified'],False)
        self.assertIsNone(source_failed_value['sourceTree'])
        self.assertEqual(source_failed_value['passedPhases'],[])
        self.assertEqual(source_failed_value['firstFailedPhase'],'SOURCE_BINDING')
        self.assertTrue(all(item is None for item in source_failed_value['exitCodes'].values()))
        self.assertTrue(all(item is None for item in source_failed_value['requiredCounts'].values()))
        for name,key,replacement in (
                ('invented_tree','sourceTree','6'*40),
                ('invented_source_green','sourceGitVerified',True),
                ('invented_exit','exitCodes',dict(source_failed_value['exitCodes'],go=1)),
                ('invented_count','requiredCounts',dict(source_failed_value['requiredCounts'],failed=1))):
            with self.subTest(rejected_unverified_source=name):
                changed=copy.deepcopy(source_failed_value);changed[key]=replacement
                with self.assertRaises(ValueError):
                    self.reader.validate_safe_rejection(
                        self.reader.encoded(changed),commit,None,41560358147,1,'SINGLE_CASE')
        with self.assertRaises(ValueError):
            self.reader.validate_safe_rejection(
                source_failed_raw,commit,tree,41560358147,1,'SINGLE_CASE')
        class PosixOS:
            name='posix'
            O_NOFOLLOW=0
            def __getattr__(self,name):return getattr(os,name)
        def prepare(path,_lane):
            path.parent.mkdir()
            return path
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);evidence=root/'evidence';evidence.mkdir()
            safe_path=root/'safe'/self.reader.SAFE_REJECTION_BASENAMES['SINGLE_CASE']
            report=root/'report.json'
            argv=['check_profile.py','verify','--repo',str(root),'--source-commit',commit,
                '--evidence',str(evidence),'--report',str(report),'--safe-rejection-report',str(safe_path),
                '--run-id','41560358147','--run-attempt','1']
            with mock.patch.object(self.reader,'os',PosixOS()),mock.patch.object(
                    self.reader,'prepare_safe_rejection_path',side_effect=prepare),mock.patch.object(
                    self.reader,'source_snapshot',side_effect=ValueError('bounded')),mock.patch.object(sys,'argv',argv):
                with self.assertRaises(ValueError):self.reader.main()
            early_raw=safe_path.read_bytes()
            self.assertEqual(
                self.reader.validate_safe_rejection(
                    early_raw,commit,None,41560358147,1,'SINGLE_CASE')['firstFailedPhase'],
                'SOURCE_BINDING')
            check_argv=['check_profile.py','safe-rejection-check','--repo',str(root),
                '--source-commit',commit,'--safe-rejection-report',str(safe_path),
                '--run-id','41560358147','--run-attempt','1','--lane','SINGLE_CASE']
            with (mock.patch.object(self.reader,'os',PosixOS()),mock.patch.object(
                    self.reader,'safe_rejection_path',return_value=safe_path),mock.patch.object(
                    self.reader,'read',return_value=early_raw),mock.patch.object(
                    self.reader,'source_snapshot',side_effect=AssertionError('must-not-claim-source')),
                    mock.patch('builtins.print'),mock.patch.object(sys,'argv',check_argv)):
                self.reader.main()
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);evidence=root/'evidence';evidence.mkdir()
            safe_path=root/'safe'/self.reader.SAFE_REJECTION_BASENAMES['SINGLE_CASE']
            argv=['check_profile.py','verify','--repo',str(root),'--source-commit',commit,
                '--evidence',str(evidence),'--report',str(root/'report.json'),
                '--safe-rejection-report',str(safe_path),'--run-id','41560358147','--run-attempt','1']
            with mock.patch.object(self.reader,'os',PosixOS()),mock.patch.object(
                    self.reader,'prepare_safe_rejection_path',side_effect=prepare),mock.patch.object(
                    self.reader,'source_snapshot',side_effect=ValueError('bounded')),mock.patch.object(
                    self.reader,'write',side_effect=OSError('bounded')),mock.patch.object(sys,'argv',argv):
                with self.assertRaises(self.reader.SafeRejectionWriteFailed):self.reader.main()

        mutations={
            'schema':('schema','chengwang.capacity-profile-safe-rejection/v0'),
            'source':('sourceCommit','5'*40),
            'tree':('sourceTree','6'*40),
            'run':('runId',1),
            'attempt':('runAttempt',2),
            'lane':('lane','FULL_CONTRACTS'),
            'phase':('firstFailedPhase','/tmp/private'),
            'class':('failureClass','raw stderr'),
            'source_verified':('sourceGitVerified',False),
            'strict_green':('strictVerificationAccepted',True),
            'whole_ci_green':('wholeCIPass',True),
            'production':('production',True),
        }
        for name,(key,replacement) in mutations.items():
            with self.subTest(rejected_binding=name):
                changed=copy.deepcopy(value);changed[key]=replacement
                with self.assertRaises(ValueError):self.reader.validate_safe_rejection(self.reader.encoded(changed),commit,tree,41560358147,1,'SINGLE_CASE')
        extra=copy.deepcopy(value);extra['message']='secret'
        bad_prefix=copy.deepcopy(value);bad_prefix['passedPhases']=bad_prefix['passedPhases'][:-1]
        missing_exit=copy.deepcopy(value);missing_exit['exitCodes']['go']=None
        invented_count=copy.deepcopy(value);invented_count['requiredCounts']['passed']=0
        for name,changed in(('unknown_field',extra),('non_prefix_phases',bad_prefix),('missing_validated_exit',missing_exit),('invented_unvalidated_count',invented_count)):
            with self.subTest(rejected_shape=name):
                with self.assertRaises(ValueError):self.reader.validate_safe_rejection(self.reader.encoded(changed),commit,tree,41560358147,1,'SINGLE_CASE')
        with self.assertRaises(ValueError):self.reader.validate_safe_rejection(raw+b' '*65536,commit,tree,41560358147,1,'SINGLE_CASE')

        full_progress=self.reader.new_safe_progress('FULL_CONTRACTS')
        for phase in self.reader.SAFE_PHASES['FULL_CONTRACTS']:
            self.reader.safe_phase_begin(full_progress,phase)
            if phase=='EXECUTION_CONTRACT':
                full_progress['exitCodes']={key:0 for key in self.reader.SAFE_EXIT_KEYS};full_progress['profileCaptureComplete']=True
            if phase=='TIMELINE':full_progress['timelineValidated']=True
            if phase=='GO_EVENT_SEMANTICS':full_progress['requiredCounts']={'passed':689,'failed':0,'skipped':0,'unfinished':0,'notStarted':0}
            if phase=='RESOURCE_WINDOW':break
            self.reader.safe_phase_pass(full_progress,phase)
        full_value=self.reader.safe_rejection_value(full_progress,commit,tree,41560358147,1,'STRICT_PREDICATE_REJECTED')
        self.assertTrue(full_value['timelineValidated'])
        self.assertEqual(sum(full_value['requiredCounts'].values()),689)
        self.assertEqual(self.reader.validate_safe_rejection(self.reader.encoded(full_value),commit,tree,41560358147,1,'FULL_CONTRACTS'),full_value)

        completed=self.reader.new_safe_progress('SINGLE_CASE')
        for phase in self.reader.SAFE_PHASES['SINGLE_CASE']:
            self.reader.safe_phase_begin(completed,phase)
            if phase=='EXECUTION_CONTRACT':
                completed['exitCodes']={key:0 for key in self.reader.SAFE_EXIT_KEYS};completed['profileCaptureComplete']=True
            if phase=='GO_EVENT_SEMANTICS':completed['requiredCounts']={'passed':6,'failed':0,'skipped':0,'unfinished':0,'notStarted':0}
            self.reader.safe_phase_pass(completed,phase)
        with self.assertRaises(ValueError):self.reader.safe_rejection_value(completed,commit,tree,1,1,'STRICT_PREDICATE_REJECTED')

        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/self.reader.SAFE_REJECTION_BASENAMES['SINGLE_CASE']
            with mock.patch.object(self.reader.os,'O_NOFOLLOW',0,create=True):
                self.reader.write(path,raw)
                with self.assertRaises(OSError):self.reader.write(path,raw)
            linked=path.with_name('linked.json');os.link(path,linked)
            with self.assertRaises(ValueError):self.reader.read(path,65536)
        with tempfile.TemporaryDirectory()as directory:
            evidence=Path(directory)/'evidence';timeline_dir=evidence/self.reader.TIMELINE_DIR
            timeline_dir.mkdir(parents=True);payload=b'controlled-timeline\n'
            timeline=timeline_dir/self.reader.TIMELINE_NAME;timeline.write_bytes(payload)
            self.assertEqual(
                self.reader.post_readback_path(evidence,self.reader.TIMELINE_NAME,True),timeline)
            self.assertEqual(self.reader.read(
                self.reader.post_readback_path(evidence,self.reader.TIMELINE_NAME,True),len(payload)),payload)
            self.assertEqual(
                self.reader.post_readback_path(evidence,'capacity.json',True),evidence/'capacity.json')
            self.assertEqual(
                self.reader.post_readback_path(evidence,self.reader.TIMELINE_NAME,False),
                evidence/self.reader.TIMELINE_NAME)
            timeline.write_bytes(b'controlled-tamper\n')
            with self.assertRaises(ValueError):
                self.reader.need(self.reader.read(timeline,len(payload))==payload)
            timeline.write_bytes(payload);linked=timeline.with_name('timeline-linked.json');os.link(timeline,linked)
            with self.assertRaises(ValueError):self.reader.read(timeline,len(payload))
            linked.unlink()
            for name in self.reader.PUBLIC+self.reader.RESOURCE_NAMES:(evidence/name).write_bytes(b'')
            (evidence/self.reader.TIMELINE_NAME).write_bytes(payload)
            expected=set(self.reader.PUBLIC)|set(self.reader.RESOURCE_NAMES)|{self.reader.TIMELINE_DIR}
            with self.assertRaises(ValueError):
                self.reader.need(set(item.name for item in evidence.iterdir())==expected)
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);repo=root/'repo';repo.mkdir();evidence=root/'evidence';evidence.mkdir()
            sources={'sourceTree':tree};source_raw=self.reader.encoded(sources)
            for name in self.reader.PUBLIC+self.reader.RESOURCE_NAMES:
                (evidence/name).write_bytes(source_raw if name in ('source-before.json','source-after.json')else b'x')
            timeline_dir=evidence/self.reader.TIMELINE_DIR;timeline_dir.mkdir()
            (timeline_dir/self.reader.TIMELINE_NAME).write_bytes(b'timeline\n')
            safe_path=root/'safe'/self.reader.SAFE_REJECTION_BASENAMES['FULL_CONTRACTS']
            report=root/'report'/'full.json';report.parent.mkdir()
            argv=['check_profile.py','verify','--diagnostic-mode','FULL_CONTRACTS','--repo',str(repo),
                '--source-commit',commit,'--evidence',str(evidence),'--report',str(report),
                '--safe-rejection-report',str(safe_path),'--run-id','41586779373','--run-attempt','1']
            def verified(_raw,_commit,_mode,progress):
                for phase in self.reader.SAFE_PHASES['FULL_CONTRACTS']:
                    if phase in progress['passedPhases']:continue
                    if phase=='POST_READBACK':break
                    self.reader.safe_phase_begin(progress,phase);self.reader.safe_phase_pass(progress,phase)
                return {'fullGoAccepted':False,'wholeCIPass':False,'production':False}
            with mock.patch.object(self.reader,'os',PosixOS()),mock.patch.object(
                    self.reader,'prepare_safe_rejection_path',side_effect=prepare),mock.patch.object(
                    self.reader,'source_snapshot',return_value=sources),mock.patch.object(
                    self.reader,'verify_raw',side_effect=verified),mock.patch('builtins.print'),mock.patch.object(
                    sys,'argv',argv):
                self.reader.main()
            published=self.reader.decode(report.read_bytes())
            self.assertTrue(published['sourceGitVerified']);self.assertFalse(published['fullGoAccepted'])
            self.assertFalse(safe_path.exists())
        with tempfile.TemporaryDirectory()as directory:
            staged=Path(directory)/'safe'/self.reader.SAFE_REJECTION_BASENAMES['SINGLE_CASE']
            with mock.patch.object(self.reader,'safe_rejection_path',return_value=staged),mock.patch.object(
                    self.reader.os,'chmod'):
                self.assertEqual(
                    self.reader.prepare_safe_rejection_path(staged,'SINGLE_CASE'),staged)
            self.assertTrue(staged.parent.is_dir())
            with self.assertRaises(self.reader.SafeCustodyRejected):
                self.reader.prepare_safe_rejection_path(staged,'SINGLE_CASE')
        with tempfile.TemporaryDirectory()as directory:
            collision=Path(directory)/'safe'/self.reader.SAFE_REJECTION_BASENAMES['SINGLE_CASE']
            collision.parent.mkdir()
            collision.write_bytes(b'preexisting')
            with self.assertRaises(self.reader.SafeCustodyRejected):
                self.reader.prepare_safe_rejection_path(collision,'SINGLE_CASE')
            self.assertEqual(collision.read_bytes(),b'preexisting')
        source=Path(self.reader.__file__).read_text(encoding='utf8')
        self.assertIn('os.O_EXCL|os.O_NOFOLLOW',source)
        self.assertNotIn('validate_safe_rejection(raw,commit,tree,run_id,run_attempt,lane):\n    return safe_rejection_value',source)
        self.assertNotIn('except Exception:pass',source)
        self.assertIn('raise SafeRejectionWriteFailed()from None',source)
        self.assertIn('bounded_state=SAFE_CUSTODY_REJECTED',source)
        self.assertIn('bounded_state=SAFE_REJECTION_WRITER_FAILED',source)
        workflow=Path(self.reader.__file__).resolve().parents[3]/'.github/workflows/chengwang-mihomo-capacity-profile.yml'
        workflow_text=workflow.read_text(encoding='utf8')
        self.assertEqual(workflow_text.count('safe_rejection_ready=true'),4)
        self.assertEqual(workflow_text.count('exit "$verify_code"'),4)
        self.assertEqual(workflow_text.count('|| safe_check_code=$?'),4)
        self.assertEqual(workflow_text.count('if test "$safe_check_code" -eq 0; then'),4)
        self.assertEqual(workflow_text.count('--capture-after'),2)
        self.assertEqual(workflow_text.count('safe_state=SAFE_CUSTODY_REJECTED'),4)
        self.assertEqual(workflow_text.count('safe_state=SAFE_REJECTION_WRITER_FAILED'),4)
        self.assertEqual(workflow_text.count('safe_state=SAFE_REPORT_READER_REJECTED'),4)
        self.assertIn('steps.single_fresh_verify.outputs.safe_rejection_ready',workflow_text)
        self.assertIn('steps.full_fresh_verify.outputs.safe_rejection_ready',workflow_text)
        self.assertIn('mihomo-capacity-safe-rejection-single-fresh-',workflow_text)
        self.assertIn('mihomo-capacity-safe-rejection-full-fresh-',workflow_text)
        self.assertNotIn('continue-on-error:',workflow_text)

    def test_full_source_contract_binds_the_exact_normal_race_timeline_wrapper(self):
        repo=Path(__file__).resolve().parents[3]
        normal=self.reader.load_normal_checker()
        sources={path:(repo/path).read_bytes() for path in normal.FILES}
        manifest_paths=set(sources)
        for package in self.reader.FULL_PACKAGES:
            directory='chengwang/'+package.removeprefix('./')
            manifest_paths.update(path.relative_to(repo).as_posix()
                                  for path in (repo/directory).glob('*_test.go'))
        manifest={'files':[{'path':path,'bytes':len(raw),'sha256':self.reader.sha(raw)}
                           for path in sorted(manifest_paths)
                           for raw in [(repo/path).read_bytes()]]}
        _checker,required,binding=self.reader.full_source_contract(sources,manifest)
        self.assertEqual(sum(len(names) for names in required.values()),689)
        self.assertEqual(binding['mandatoryNamesSHA256'],self.reader.FULL_REQUIRED_PIN)

        runner=sources['chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh']
        self.assertEqual(self.reader.sha(runner),self.reader.NORMAL_RUN_CONTRACTS_SHA256)
        self.assertTrue(runner.endswith(b'\n'));self.assertNotIn(b'\r',runner)
        text=runner.decode('utf8').replace('\r\n','\n')
        wrapper='\n'.join((
            'python3 -B "$repo/chengwang/deploy/mihomo-lifecycle-lab/go_timeline_capture.py" spawn \\',
            '  --lane FOUNDATION_RACE --raw "$out/race.json" --stderr "$out/race.stderr" \\',
            '  --publication-parent "$timeline_public" --source-commit "$source_commit" --source-tree "$source_tree" -- \\',
            '  "${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s ./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api ./internal/serverruntime ./internal/authz',
            'race_code=$?'))
        privilege='\n'.join((
            'common=(setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all',
            '  env -i "PATH=$goroot/bin:/usr/bin:/bin" "GOROOT=$goroot" HOME=/tmp/contracts-home TMPDIR=/tmp/contracts-home',
            '  GOCACHE=/tmp/contracts-cache GOMODCACHE=/tmp/contracts-mod GOPROXY=off GOSUMDB=off',
            '  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC)'))
        legacy='"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s ./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api ./internal/serverruntime ./internal/authz > "$out/race.json" 2> "$out/race.stderr"'
        self.assertEqual(text.count(wrapper),1)
        self.assertEqual(text.count(privilege),1)
        def mutate_wrapper(old,new):
            changed=wrapper.replace(old,new,1)
            self.assertNotEqual(changed,wrapper)
            return text.replace(wrapper,changed,1)
        mutations={
            'old_and_new_coexist':text+'\n'+legacy+'\n',
            'duplicate_wrapper':text+'\n'+wrapper+'\n',
            'comment_spoof':text.replace(wrapper,'\n'.join('# '+line for line in wrapper.splitlines())),
            'truncated_privilege_prefix':text.replace(privilege,privilege.replace(' --ambient-caps=-all','',1),1),
            'changed_capture_path':mutate_wrapper('/go_timeline_capture.py" spawn','/changed_capture.py" spawn'),
            'changed_lane':mutate_wrapper('--lane FOUNDATION_RACE','--lane CHANGED_RACE'),
            'changed_raw_path':mutate_wrapper('--raw "$out/race.json"','--raw "$out/changed.json"'),
            'changed_stderr_path':mutate_wrapper('--stderr "$out/race.stderr"','--stderr "$out/changed.stderr"'),
            'changed_publication_path':mutate_wrapper('--publication-parent "$timeline_public"','--publication-parent "$out"'),
            'changed_source_commit':mutate_wrapper('--source-commit "$source_commit"','--source-commit "0"'),
            'changed_source_tree':mutate_wrapper('--source-tree "$source_tree"','--source-tree "0"'),
            'missing_separator':mutate_wrapper('--source-tree "$source_tree" -- \\','--source-tree "$source_tree" \\'),
            'changed_privilege_use':mutate_wrapper('  "${common[@]}" "$goroot/bin/go" test -race','  "$goroot/bin/go" test -race'),
            'changed_go_path':mutate_wrapper('"$goroot/bin/go" test -race','"/usr/bin/go" test -race'),
            'changed_go_option':mutate_wrapper('-timeout=180s ./internal/adapter','-timeout=179s ./internal/adapter'),
            'changed_package_order':mutate_wrapper('./internal/adapter/mihomo ./internal/mihomodeploy','./internal/mihomodeploy ./internal/adapter/mihomo'),
            'legacy_with_leading_space':text+'\n  '+legacy+'\n',
            'legacy_with_equivalent_stderr_spacing':text+'\n'+legacy.replace(' 2> ',' 2 > ')+'\n',
            'second_race_timeout_179':text+'\n'+legacy.replace('-timeout=180s','-timeout=179s')+'\n',
            'changed_output_flag_form':mutate_wrapper('--raw "$out/race.json"','--raw="$out/race.json"'),
            'privilege_moved_after_wrapper':text.replace(privilege+'\n','',1).replace(wrapper,wrapper+'\n'+privilege,1),
            'extra_privilege_after_wrapper':text.replace(wrapper,wrapper+'\n'+privilege,1),
            'commented_extra_race':text+'\n# '+legacy+'\n',
            'heredoc_wrapper_spoof':text.replace(wrapper,"cat <<'RACE_SPOOF'\n"+wrapper+'\nRACE_SPOOF',1),
            'capture_alias_refactor':mutate_wrapper('python3 -B "$repo/chengwang/deploy/mihomo-lifecycle-lab/go_timeline_capture.py"','capture_python "$repo/chengwang/deploy/mihomo-lifecycle-lab/go_timeline_capture.py"'),
            'extra_race_alias':text+'\nrace_runner "$goroot/bin/go" test -race -json -count=1 -timeout=180s '+' '.join(self.reader.FULL_PACKAGES)+'\n',
        }
        for name,mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutated,text)
                with self.assertRaises(ValueError):
                    self.reader.normal_race_wrapper_contract(mutated.encode())


if __name__ == '__main__':
    unittest.main()
