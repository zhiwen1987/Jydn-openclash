"""Bounded synthetic checker models, never Go, kernel, sandbox or Git execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


_SPEC = importlib.util.spec_from_file_location(
    'mihomo_contract_checker', Path(__file__).with_name('check_contracts.py'))
S = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(S)


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def event_rows(required=None):
    required = REQUIRED if required is None else required
    rows = []
    for package in sorted(S.PACKAGES):
        rows.append(dict(Action='start', Package=package))
        for name in required[package]:
            rows.extend([
                dict(Action='run', Package=package, Test=name),
                dict(Action='output', Package=package, Test=name, Output='synthetic\n'),
                dict(Action='pause', Package=package, Test=name),
                dict(Action='cont', Package=package, Test=name),
                dict(Action='pass', Package=package, Test=name, Elapsed=0.001),
            ])
        rows.append(dict(Action='pass', Package=package, Elapsed=0.002))
    return rows


def transcript(rows):
    return b'\n'.join(encoded(row) for row in rows) + b'\n'


REQUIRED = {package: ['TestSynthetic'] for package in S.PACKAGES}
ADDITIONAL_MODEL_TESTS = {
    'lab_target_readback_test.go': 'TestSyntheticSelectedTargetProjection',
    'lifecycle_recovery_started_linux_test.go': 'TestSyntheticRecoveryStartedPersistence',
    'lifecycle_trusted_clone_properties_test.go': 'TestSyntheticTrustedCloneProperties',
    'lab_recovery_authority_test.go': 'TestSyntheticLabRecoveryAuthority',
    'lab_recovery_start_test.go': 'TestSyntheticLabRecoveryStarted',
    'lab_recovery_start_linux_test.go': 'TestSyntheticLabRecoveryStartedLinux',
    'policy_test.go': 'TestSyntheticRecovery_policytest',
    'image_trust_test.go': 'TestSyntheticRecovery_imagetrusttest',
    'image_trust_history_d8_test.go': 'TestSyntheticRecovery_imagetrusthistoryd8test',
    'subscription_test.go': 'TestSyntheticRecovery_subscriptiontest',
    'lab_recovery_test.go': 'TestSyntheticRecovery_labrecoverytest',
    'lab_quiescence_test.go': 'TestSyntheticRecovery_labquiescencetest',
    'lab_quiescence_linux_test.go': 'TestSyntheticRecovery_labquiescencelinuxtest',
    'lab_recovery_plan_test.go': 'TestSyntheticRecovery_labrecoveryplantest',
    'lifecycle_v3_test.go': 'TestSyntheticRecovery_lifecyclev3test',
    'lifecycle_recovery_store_test.go': 'TestSyntheticRecovery_lifecyclerecoverystoretest',
    'lifecycle_recovery_transitions_test.go': 'TestSyntheticRecovery_lifecyclerecoverytransitionstest',
    'artifact_test.go': 'TestSyntheticArtifact',
    'artifact_linux_test.go': 'TestSyntheticArtifactLinux',
    'plan_test.go': 'TestSyntheticPlan',
    'prepare_test.go': 'TestSyntheticPrepare',
    'lifecycle_test.go': 'TestSyntheticLifecycle',
    'lifecycle_linux_test.go': 'TestSyntheticLifecycleLinux',
    'snapshot_manager_test.go': 'TestSyntheticSnapshotManager',
    'snapshot_manager_linux_test.go': 'TestSyntheticSnapshotLinux',
    'lab_readback_test.go': 'TestSyntheticLabReadback',
    'lab_evidence_test.go': 'TestSyntheticLabEvidence',
    'lab_authority_test.go': 'TestSyntheticLabAuthority',
    'lab_expectation_test.go': 'TestSyntheticLabExpectation',
    'lab_kernel_linux_test.go': 'TestSyntheticLabKernelLinux',
    'lab_bootstrap_linux_test.go': 'TestSyntheticLabBootstrapLinux',
    'lab_bootstrap_test.go': 'TestSyntheticLabBootstrap',
    'lab_collector_linux_test.go': 'TestSyntheticLabCollectorLinux',
    'lab_collector_test.go': 'TestSyntheticLabCollector',
    'lab_local_route_test.go': 'TestSyntheticLabLocalRoute',
    'lab_service_diagnostics_test.go': 'TestSyntheticLabServiceDiagnostics',
    'lab_service_test.go': 'TestSyntheticLabService',
    'lab_syntax_linux_test.go': 'TestSyntheticLabSyntaxLinux',
    'mihomo_lab_test.go': 'TestSyntheticMihomoLabAPI',
    'mihomo_lab_config_test.go': 'TestSyntheticMihomoLabComposition',
}


class ContractEvidenceModels(unittest.TestCase):
    """Models assert rejection boundaries; a positive is not a Go-run receipt."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.evidence = self.root / 'evidence'
        self.repo.mkdir()
        self.evidence.mkdir()
        self.sources = {}
        self.required = {package: [] for package in S.PACKAGES}
        for path in S.FILES:
            value = b'synthetic source\n'
            if path.endswith('check_contracts.py'):
                value = Path(S.__file__).read_bytes()
            elif path.endswith('_test.go'):
                name = ADDITIONAL_MODEL_TESTS.get(Path(path).name, 'TestSynthetic')
                value = ('func ' + name + '(t *testing.T) {\n}\n').encode()
                if path in dict(S.TEST_FILES):
                    self.required[dict(S.TEST_FILES)[path]].append(name)
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            self.sources[path] = value
        self.payloads = {name: b'' for name in S.INPUTS}
        for name in ('ordinary.json', 'race.json'):
            self.payloads[name] = transcript(event_rows(self.required))
        self.set_json('execution.json', dict(
            schema='chengwang.mihomo-contract-execution/v1', formatExit=0,
            ordinaryExit=0, raceExit=0, realMihomoExecuted=False, production=False))
        self.set_json('sandbox.json', dict(
            uid=10001, gid=10001, effectiveCaps='0000000000000000',
            noNewPrivileges=True, networkNamespace='net:[21]', mountNamespace='mnt:[22]',
            pidNamespace='pid:[23]', sourceModuleSHA256=S.sha(self.sources['chengwang/go.mod']),
            sourceAliasReadOnly=True, temporaryRootPrivate=True, environmentKeys=sorted([
                'PATH', 'GOROOT', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE', 'GOPROXY',
                'GOSUMDB', 'GOENV', 'GOTOOLCHAIN', 'GOFLAGS', 'CGO_ENABLED',
                'LANG', 'LC_ALL', 'TZ'])))
        host = dict(networkNamespace='net:[11]', mountNamespace='mnt:[12]',
                    pidNamespace='pid:[13]', resolvSHA256='a' * 64)
        self.set_json('host-before.json', host)
        self.set_json('host-after.json', host)
        self.payloads['go-version.txt'] = b'go version go1.23.12 linux/amd64\n'
        self.flush()

    def set_json(self, name, value):
        self.payloads[name] = encoded(value)

    def mutate_json(self, name, **updates):
        value = json.loads(self.payloads[name])
        value.update(updates)
        self.set_json(name, value)
        self.flush()

    def flush(self):
        for name, value in self.payloads.items():
            (self.evidence / name).write_bytes(value)

    def verify_model(self):
        # Deliberately modeled Git lookup: this test does not attest any commit.
        with mock.patch.object(S, 'source', side_effect=lambda repo, commit, path: self.sources[path]):
            return S.verify(self.evidence, self.repo, 'a' * 40)

    def reject_rows(self, rows):
        with self.assertRaises(ValueError):
            S.events(transcript(rows), REQUIRED)

    def test_synthetic_ordered_events_include_parallel_controls(self):
        result = S.events(transcript(event_rows()), REQUIRED)
        self.assertEqual(result['allPassingSemanticTests'], len(S.PACKAGES))
        self.assertEqual(result['skips'], 0)

    def test_event_package_start_is_required(self):
        self.reject_rows([row for row in event_rows() if row['Action'] != 'start'])

    def test_event_package_success_is_required(self):
        self.reject_rows([row for row in event_rows() if 'Test' in row or row['Action'] != 'pass'])

    def test_event_pass_cannot_precede_its_run(self):
        rows = event_rows()
        rows[1], rows[5] = rows[5], rows[1]
        self.reject_rows(rows)

    def test_duplicate_test_or_package_terminals_are_rejected(self):
        for index in (1, 5, 6):
            with self.subTest(index=index):
                rows = event_rows()
                rows.insert(index + 1, dict(rows[index]))
                self.reject_rows(rows)

    def test_skip_or_fail_is_rejected_even_with_later_pass(self):
        for action in ('skip', 'fail'):
            with self.subTest(action=action):
                rows = event_rows()
                rows.insert(2, dict(Action=action, Package=rows[1]['Package'], Test='TestSynthetic'))
                self.reject_rows(rows)

    def test_unknown_action_is_not_silently_ignored(self):
        rows = event_rows()
        rows.insert(2, dict(Action='unrecognized', Package=rows[1]['Package']))
        self.reject_rows(rows)

    def test_missing_mandatory_test_is_rejected(self):
        self.reject_rows([row for row in event_rows() if row.get('Test') != 'TestSynthetic'])

    def test_authentication_package_cannot_be_omitted_or_fabricated_as_package_pass(self):
        rows = event_rows(self.required)
        for package in sorted(S.PACKAGES):
            for altered in (
                [row for row in rows if row['Package'] != package],
                [row for row in rows if row['Package'] != package or 'Test' not in row],
            ):
                with self.assertRaises(ValueError):
                    S.events(transcript(altered), self.required)

    def test_lifecycle_and_snapshot_source_tests_are_individually_mandatory(self):
        required = S.required_names(self.sources)
        self.assertEqual(required, self.required)
        wanted = ('TestSyntheticLifecycle', 'TestSyntheticLifecycleLinux',
                  'TestSyntheticSnapshotManager', 'TestSyntheticSnapshotLinux')
        for missing in wanted:
            with self.assertRaises(ValueError):
                S.events(transcript([row for row in event_rows(required) if row.get('Test') != missing]), required)

    def test_elapsed_requires_finite_nonnegative_real_number(self):
        for value in (True, -1, float('inf'), float('nan'), '0'):
            with self.subTest(value=repr(value)):
                rows = event_rows()
                rows[5]['Elapsed'] = value
                self.reject_rows(rows)

    def test_unexpected_package_is_rejected(self):
        rows = event_rows()
        rows[0]['Package'] = 'synthetic/unexpected'
        self.reject_rows(rows)

    def test_duplicate_json_keys_and_nonobjects_are_rejected(self):
        for raw in (b'{"Action":"run","Action":"pass"}\n', b'[]\n', b'null\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    S.events(raw, REQUIRED)

    def test_new_required_names_come_from_both_source_test_files(self):
        self.assertEqual(S.required_names(self.sources), self.required)
        for name in ADDITIONAL_MODEL_TESTS.values():
            with self.subTest(missing=name):
                self.payloads['ordinary.json'] = transcript([
                    row for row in event_rows(self.required) if row.get('Test') != name])
                self.flush()
                with self.assertRaises(ValueError):
                    self.verify_model()
        duplicates = dict(self.sources)
        duplicates['chengwang/internal/mihomodeploy/artifact_test.go'] = b'func TestSynthetic(t *testing.T) {\n}\n'
        with self.assertRaises(ValueError):
            S.required_names(duplicates)

    def test_synthetic_complete_ordinary_and_race_remain_distinct(self):
        self.assertEqual(len(self.sources), 121)
        self.assertEqual(len(S.PACKAGES), 6)
        result = self.verify_model()
        self.assertEqual(set(result['suites']), {'ordinary.json', 'race.json'})
        self.assertEqual(result['scope'], 'SOURCE_CONTRACTS_ONLY_NOT_LIFECYCLE_OR_DEPLOYMENT_ACCEPTANCE')
        self.assertIs(result['realMihomoExecuted'], False)
        self.assertIs(result['production'], False)
        version = self.payloads['go-version.txt']
        for changed in (b'prefix\n' + version, version + b'extra\n', version.rstrip(b'\n')):
            with self.subTest(version=changed):
                self.payloads['go-version.txt'] = changed
                self.flush()
                with self.assertRaises(ValueError):
                    self.verify_model()
        self.payloads['go-version.txt'] = version
        self.flush()

    def test_missing_race_cannot_be_replaced_by_ordinary_success(self):
        self.payloads['race.json'] = b''
        self.flush()
        with self.assertRaises(ValueError):
            self.verify_model()

    def test_format_patch_or_stderr_prevents_acceptance(self):
        for name in ('gofmt.patch', 'gofmt.stderr', 'ordinary.stderr', 'race.stderr'):
            with self.subTest(name=name):
                self.payloads[name] = b'synthetic nonempty evidence\n'
                self.flush()
                with self.assertRaises(ValueError):
                    self.verify_model()
                self.payloads[name] = b''
                self.flush()

    def test_exit_status_cannot_use_boolean_zero(self):
        for key in ('formatExit', 'ordinaryExit', 'raceExit'):
            with self.subTest(key=key):
                self.mutate_json('execution.json', **{key: False})
                with self.assertRaises(ValueError):
                    self.verify_model()
                self.mutate_json('execution.json', **{key: 0})

    def test_execution_boolean_fields_cannot_use_numeric_zero(self):
        for key in ('realMihomoExecuted', 'production'):
            with self.subTest(key=key):
                self.mutate_json('execution.json', **{key: 0})
                with self.assertRaises(ValueError):
                    self.verify_model()
                self.mutate_json('execution.json', **{key: False})

    def test_sandbox_gid_requires_integer_not_equal_float(self):
        self.mutate_json('sandbox.json', gid=10001.0)
        with self.assertRaises(ValueError):
            self.verify_model()

    def test_host_child_namespace_and_host_stability_are_checked(self):
        initial = json.loads(self.payloads['sandbox.json'])
        for field, invalid in [('sourceModuleSHA256', '0' * 64),
                               ('sourceAliasReadOnly', False), ('sourceAliasReadOnly', 1),
                               ('temporaryRootPrivate', False), ('temporaryRootPrivate', 1),
                               ('environmentKeys', [key for key in initial['environmentKeys'] if key != 'TMPDIR'])]:
            with self.subTest(field=field, invalid=invalid):
                self.mutate_json('sandbox.json', **{field: invalid})
                with self.assertRaises(ValueError):
                    self.verify_model()
                self.set_json('sandbox.json', initial)
                self.flush()
        for field in ('networkNamespace', 'mountNamespace', 'pidNamespace'):
            with self.subTest(field=field):
                original = json.loads(self.payloads['sandbox.json'])
                same = json.loads(self.payloads['host-before.json'])[field]
                self.mutate_json('sandbox.json', **{field: same})
                with self.assertRaises(ValueError):
                    self.verify_model()
                self.set_json('sandbox.json', original)
                self.flush()
        host = json.loads(self.payloads['host-before.json'])
        for field in ('networkNamespace', 'mountNamespace', 'pidNamespace'):
            for invalid in (None, False, 123, 'wrong:[123]'):
                with self.subTest(field=field, invalid=invalid):
                    changed = dict(host, **{field: invalid})
                    self.set_json('host-before.json', changed)
                    self.set_json('host-after.json', changed)
                    self.flush()
                    with self.assertRaises(ValueError):
                        self.verify_model()
        self.set_json('host-before.json', host)
        self.set_json('host-after.json', host)
        self.flush()
        self.mutate_json('host-after.json', resolvSHA256='b' * 64)
        with self.assertRaises(ValueError):
            self.verify_model()

    def test_public_input_closed_set_rejects_extra_file(self):
        (self.evidence / 'unexpected.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):
            self.verify_model()

    def test_report_dotdot_cannot_escape_into_repo_or_evidence(self):
        outside = self.root / 'outside'
        outside.mkdir()
        for name in ('repo', 'evidence'):
            with self.subTest(name=name):
                report = outside / '..' / name / 'modeled-report.json'
                args = ['checker', '--evidence', str(self.evidence), '--repo', str(self.repo),
                        '--source-commit', 'a' * 40, '--report', str(report)]
                with mock.patch('sys.argv', args), mock.patch.object(S, 'verify', return_value={'synthetic': True}):
                    with self.assertRaises(ValueError):
                        S.main()
                self.assertFalse((self.root / name / 'modeled-report.json').exists())

    def test_source_bytes_must_remain_stable_after_event_validation(self):
        original = S.events
        def changed(raw, required):
            result = original(raw, required)
            path = self.repo / S.FILES[0]
            path.write_bytes(path.read_bytes() + b'changed\n')
            return result
        with mock.patch.object(S, 'events', side_effect=changed):
            with self.assertRaises(ValueError):
                self.verify_model()

    def test_input_bytes_must_remain_stable_after_event_validation(self):
        original = S.events
        def changed(raw, required):
            result = original(raw, required)
            (self.evidence / 'go-version.txt').write_bytes(b'changed\n')
            return result
        with mock.patch.object(S, 'events', side_effect=changed):
            with self.assertRaises(ValueError):
                self.verify_model()


if __name__ == '__main__':
    unittest.main(verbosity=2)
