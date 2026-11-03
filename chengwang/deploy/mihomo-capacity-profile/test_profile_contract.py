import importlib.util
import json
import os
from pathlib import Path
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
