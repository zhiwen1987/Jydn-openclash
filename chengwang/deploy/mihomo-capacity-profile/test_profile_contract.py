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

    def test_full_formatter_argv_uses_the_independent_exact_28_path_contract(self):
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
        self.assertEqual(len(EXPECTED_FULL_FMT),len(set(EXPECTED_FULL_FMT)),28)


if __name__ == '__main__':
    unittest.main()
