"""CPU contracts for closed profiles/private projections, not runtime evidence."""
import base64
import importlib.util
import json
import pathlib
import re
import types
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('capability_truth_scene_contract_subject', BASE / 'capability_truth_scene.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
DEFAULT = 'capability_truth:default'
CONFIGURED = 'capability_truth:backend_configured'
ROOT = pathlib.Path('/synthetic/private'); BUNDLE = pathlib.Path('/synthetic/bundle')


def build_fixture():
    manifest = b'{}'; server = b'\x7fELFsynthetic-only'
    files = [dict(path=p, bytes=len(raw), sha256=C.shared().sha(raw)) for p, raw in
        [('.vite/manifest.json', manifest), ('assets/entry.js', b'xxx'), ('index.html', b'xxx'), ('trust.html', b'xxx')]]
    value = dict(schema='chengwang.capability-truth-build/v1', sourceCommit='a' * 40, goVersion='go1.23.12', nodeVersion='v22.23.3',
        moduleMode='vendor', goDependencyDownloads=False, server=dict(name='server', bytes=len(server), sha256=C.shared().sha(server)),
        distFiles=files, manifestBase64=base64.b64encode(manifest).decode(), production=False, authorization='BLOCKED')
    return value, server, files, manifest


def native(values):
    def read(path, *args): return json.dumps(values[path.name]).encode(), None
    return types.SimpleNamespace(canonical=lambda v: json.dumps(v).encode(), decode=json.loads, stable_read=mock.Mock(side_effect=read))


def failure_fixture(**changes):
    value = dict(schema='chengwang.capability-truth-driver-failure/v2', stage='CAPABILITIES', production=False,
        normalCloseCompleted=False, events=7, captures=3, failed=True, operation='DOM_READ', firstFailure=None, counters=None)
    value.update(changes)
    return value


class CapabilitySceneContracts(unittest.TestCase):
    def _failure_native(self, failure, *, missing=False, unknown_secret=False):
        secret = dict(schema='chengwang.capability-truth-secrets/v1', profile='default', fenceCanary='a' * 64, identityToken=None)
        secret_raw = json.dumps(secret).encode()
        failure_raw = failure if isinstance(failure, bytes) else json.dumps(failure).encode()
        def read(path, *args):
            if path.name == 'supervisor-secret.private.json':
                if unknown_secret: raise ValueError('synthetic secret state unavailable')
                return secret_raw, None
            if path.name == 'capability-failure.private.json':
                if missing: raise FileNotFoundError('synthetic observation missing')
                return failure_raw, None
            raise AssertionError('unexpected private read')
        return types.SimpleNamespace(stable_read=mock.Mock(side_effect=read), decode=mock.Mock(side_effect=json.loads)), secret_raw, failure_raw

    def test_failure_diagnostic_projects_only_the_actual_closed_safe_record(self):
        value = failure_fixture()
        N, _, _ = self._failure_native(value)
        observed = C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)
        self.assertEqual(observed, dict(driverCheckpoints=[], driverDiagnostics=value))
        self.assertIn(mock.call(ROOT / 'capability-failure.private.json', 4096, 10001, 0o600), N.stable_read.call_args_list)
        self.assertEqual(C.scene_public_files(DEFAULT), C.PUBLIC)

    def test_missing_failure_observation_is_unknown_instead_of_invented_zeroes(self):
        N, _, _ = self._failure_native({}, missing=True)
        self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])

    def test_unknown_secret_state_suppresses_failure_without_reading_it(self):
        N, _, _ = self._failure_native({}, unknown_secret=True)
        self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])
        self.assertEqual([call.args[0].name for call in N.stable_read.call_args_list], ['supervisor-secret.private.json'])

    def test_malformed_failure_types_ranges_and_stages_are_suppressed(self):
        good = failure_fixture(stage='CLOSE', operation='NORMAL_CLOSE', normalCloseCompleted=True)
        patches = [dict(extra='unapproved'), dict(stage='UNKNOWN'), dict(events=True), dict(events=513), dict(captures=69),
            dict(events=-1), dict(normalCloseCompleted=1), dict(production=0), dict(failed=False), dict(schema='legacy/v1')]
        for patch in patches:
            with self.subTest(patch=patch):
                N, _, _ = self._failure_native({**good, **patch})
                self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])
        N, _, _ = self._failure_native(b'{invalid')
        self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])

    def test_leaking_failure_is_fenced_before_the_failure_json_decoder(self):
        value = failure_fixture(stage='a' * 64)
        N, secret_raw, failure_raw = self._failure_native(value)
        self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])
        self.assertEqual(N.decode.call_args_list, [mock.call(secret_raw)])
        self.assertNotIn(mock.call(failure_raw), N.decode.call_args_list)

    def test_failure_v2_operation_literals_match_the_driver_without_import_or_eval(self):
        path = BASE.parents[1] / 'tools/capability-truth-browser/ui-driver.mjs'
        source = path.read_text(encoding='utf-8')
        matches = re.findall(r'export const FAILURE_OPERATIONS\s*=\s*Object\.freeze\(\s*(\[[\s\S]*?\])\s*\)', source)
        self.assertEqual(len(matches), 1)
        operations = json.loads(matches[0])
        expected = {'ENVIRONMENT', 'LAUNCH', 'READY_WAIT', 'VIEWPORT', 'GOTO', 'DOCUMENT_READY', 'SNAPSHOT_WAIT',
            'CHECKPOINT_SETTLE', 'PAGE_IDENTITY', 'DOM_READ', 'DOM_VALIDATE', 'PNG_CAPTURE', 'PNG_PUBLISH',
            'CLICK_TARGET', 'CLICK_DISPATCH', 'PAGE_WAIT', 'TLS_CERTIFICATE', 'NORMAL_CLOSE', 'CHROME_EXIT_WAIT',
            'LAUNCHER_EXIT_WAIT', 'PROCESS_EXIT_WAIT', 'JOURNAL_FINALIZE', 'PUBLIC_EXPORT', 'DRIVER_PUBLISH',
            'COMPLETE', 'EVENT_REQUEST', 'EVENT_HEADERS', 'EVENT_FINISH', 'EVENT_FAILURE', 'RUNTIME_EVENT',
            'TRANSPORT_EVENT', 'BODY_READ', 'BODY_DECODE', 'BODY_FENCE', 'BODY_BUILD_BINDING', 'CAPTURE_ROW',
            'CAPTURE_EVENT', 'UNCLASSIFIED', 'EVENT_REQUEST_TIME', 'EVENT_HEADERS_TIME', 'EVENT_FINISH_TIME'}
        self.assertEqual(len(operations), 41)
        self.assertEqual(len(set(operations)), 41)
        self.assertEqual(set(operations), expected)
        self.assertEqual(tuple(operations), C.FAILURE_OPERATIONS)

    def test_failure_v2_all_operation_and_error_counter_codes_are_readable(self):
        for operation in C.FAILURE_OPERATIONS:
            value = failure_fixture(operation=operation)
            N, _, _ = self._failure_native(value)
            self.assertEqual(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'], value)
        for code, counter in C.FAILURE_COUNTERS.items():
            counters = dict.fromkeys(C.contract()['eightZero'], 0); counters[counter] = 1
            value = failure_fixture(firstFailure=dict(operation='EVENT_FINISH_TIME', code=code, requestId='r68', kind='CAPABILITIES'), counters=counters)
            N, _, _ = self._failure_native(value)
            self.assertEqual(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'], value)

    def test_failure_v2_nullable_observations_are_not_zero_filled(self):
        first = dict(operation='BODY_READ', code='capture_error', requestId=None, kind='ASSET')
        for first_failure, counters in [(None, None), (first, None), (None, dict.fromkeys(C.contract()['eightZero'], 0))]:
            value = failure_fixture(firstFailure=first_failure, counters=counters)
            N, _, _ = self._failure_native(value)
            observed = C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics']
            self.assertEqual(observed, value)
            if counters is None: self.assertIsNone(observed['counters'])
            if first_failure is None: self.assertIsNone(observed['firstFailure'])

    def test_failure_v2_first_failure_keys_aliases_kinds_and_types_are_closed(self):
        good = dict(operation='EVENT_REQUEST_TIME', code='capture_error', requestId='r1', kind='DOCUMENT')
        patches = [dict(extra='unapproved'), dict(operation='PRIVATE_OPERATION'), dict(code='PRIVATE_ERROR'),
            dict(requestId='raw.123'), dict(requestId='r0'), dict(requestId='r01'), dict(requestId='r69'),
            dict(requestId='/private/path'), dict(requestId=True), dict(kind='PRIVATE_KIND'), dict(kind=1)]
        for patch in patches:
            N, _, _ = self._failure_native(failure_fixture(firstFailure={**good, **patch}))
            self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])
        for first in [True, [], {}, {key: value for key, value in good.items() if key != 'kind'}]:
            N, _, _ = self._failure_native(failure_fixture(firstFailure=first))
            self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])

    def test_failure_v2_counters_are_exact_bounded_integers(self):
        good = dict.fromkeys(C.contract()['eightZero'], 0)
        for counters in [{**good, 'extra': 0}, {key: count for key, count in good.items() if key != 'failedRequests'},
                *[{**good, 'captureErrors': count} for count in [True, -1, 513, 1.5, '1']], [], False]:
            N, _, _ = self._failure_native(failure_fixture(counters=counters))
            self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])
        N, _, _ = self._failure_native(failure_fixture(counters={**good, 'captureErrors': 512}))
        self.assertIsNotNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])

    def test_failure_v2_first_failure_requires_its_own_observed_counter(self):
        first = dict(operation='EVENT_FAILURE', code='net_fail', requestId=None, kind=None)
        counters = dict.fromkeys(C.contract()['eightZero'], 0); counters['captureErrors'] = 1
        N, _, _ = self._failure_native(failure_fixture(firstFailure=first, counters=counters))
        self.assertIsNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])
        counters['failedRequests'] = 1
        N, _, _ = self._failure_native(failure_fixture(firstFailure=first, counters=counters))
        self.assertIsNotNone(C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics'])

    def test_failure_v2_keeps_async_first_operation_independent_of_main_operation(self):
        first = dict(operation='BODY_BUILD_BINDING', code='capture_error', requestId='r2', kind=None)
        counters = dict.fromkeys(C.contract()['eightZero'], 0); counters['captureErrors'] = 1
        value = failure_fixture(operation='SNAPSHOT_WAIT', firstFailure=first, counters=counters)
        N, _, _ = self._failure_native(value)
        observed = C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)['driverDiagnostics']
        self.assertEqual(observed, value)
        self.assertNotEqual(observed['operation'], observed['firstFailure']['operation'])

    def test_failure_v2_rejects_legacy_or_missing_operation_without_exposing_text(self):
        values = [failure_fixture(schema='chengwang.capability-truth-driver-failure/v1'),
            failure_fixture(operation='https://private.invalid/?token=sentinel'), failure_fixture(operation=True),
            {key: value for key, value in failure_fixture().items() if key != 'firstFailure'}]
        for value in values:
            N, _, _ = self._failure_native(value)
            observed = C.scene_failure_diagnostics(None, None, ROOT, 'b' * 32, DEFAULT, N)
            self.assertEqual(observed, dict(driverCheckpoints=[], driverDiagnostics=None))

    def test_profiles_are_closed_and_do_not_accept_legacy_scenarios(self):
        self.assertEqual(C.profile(DEFAULT), 'default'); self.assertEqual(C.profile(CONFIGURED), 'backend_configured')
        for key in ['subscription:create_receipt', 'capability_truth:custom', '../default']:
            with self.subTest(key=key), self.assertRaises(ValueError): C.profile(key)

    def test_default_environment_has_no_identity_upstream_policy_or_write_authority(self):
        with mock.patch.dict(C.os.environ, {'CHENGWANG_ADMIN_TOKEN': 'inherited-secret', 'HTTPS_PROXY': 'http://unexpected'}):
            value = C.scene_child_environment(ROOT, BUNDLE, DEFAULT)
        self.assertNotIn('CHENGWANG_IDENTITIES_FILE', value); self.assertNotIn('CHENGWANG_MIHOMO_URL', value)
        self.assertNotIn('CHENGWANG_SUBSCRIPTION_POLICY_FILE', value); self.assertNotIn('HTTPS_PROXY', value); self.assertNotIn('CHENGWANG_ADMIN_TOKEN', value)
        self.assertEqual(value['CHENGWANG_SUBSCRIPTIONS_ENABLED'], 'false')
        for name in ['CHENGWANG_ALLOW_PUBLISH', 'CHENGWANG_OPERATION_WRITES_ENABLED', 'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED']:
            self.assertEqual(value[name], 'false')

    def test_configured_environment_retains_all_write_locks_and_only_fixed_loopback(self):
        value = C.scene_child_environment(ROOT, BUNDLE, CONFIGURED)
        self.assertEqual(value['CHENGWANG_MIHOMO_URL'], 'http://127.0.0.1:17892'); self.assertEqual(value['CHENGWANG_ADDR'], '127.0.0.1:17891')
        self.assertEqual(value['CHENGWANG_OBSERVATION_INTERVAL'], '30s'); self.assertEqual(value['CHENGWANG_OBSERVATION_TTL'], '2m')
        self.assertEqual(value['CHENGWANG_SUBSCRIPTIONS_ENABLED'], 'true'); self.assertEqual(value['CHENGWANG_SUBSCRIPTION_WRITES_ENABLED'], 'false')
        self.assertEqual(value['CHENGWANG_OPERATION_WRITES_ENABLED'], 'false'); self.assertEqual(value['CHENGWANG_ALLOW_PUBLISH'], 'false')
        self.assertNotIn('CHENGWANG_MIHOMO_TOKEN', value); self.assertNotIn('CHENGWANG_PROBE_READ_ENABLED', value)

    def test_identity_contains_only_a_viewer_hash_and_subscription_scope(self):
        token = 'a' * 64; value = C.identity(token); row = value['identities'][0]
        self.assertNotIn(token, json.dumps(value)); self.assertEqual(row['tokenHash'], C.shared().sha(token.encode()))
        self.assertEqual(row['principal']['roles'], ['viewer']); self.assertEqual(row['principal']['allowedScopes'], [C.scope(True, subscription=True)])
        self.assertEqual(C.scope(False)['tenantId'], ''); self.assertEqual(C.scope(True)['objectType'], 'control-plane')

    def test_initialize_never_passes_the_real_identity_token_or_hash_to_driver_input(self):
        writes = {}; N = types.SimpleNamespace(canonical=lambda v: json.dumps(v).encode(), exclusive=lambda p, raw, mode: writes.__setitem__(p.name, json.loads(raw)))
        options = types.SimpleNamespace(source_commit='a' * 40, engine='chrome-cdp')
        with mock.patch.object(C.secrets, 'token_hex', side_effect=['b' * 64, 'c' * 64]), mock.patch.object(C.os, 'chown', create=True) as chown:
            forbidden = C.scene_initialize(options, ROOT, 'd' * 32, CONFIGURED, N)
        driver = writes['capability-input.private.json']
        self.assertEqual(set(driver), {'schema', 'scenario', 'profile', 'fixtureId', 'sourceCommit', 'engine', 'fenceCanary'})
        self.assertNotIn('c' * 64, json.dumps(driver)); self.assertNotIn(C.shared().sha(('c' * 64).encode()), json.dumps(driver))
        self.assertIn(('c' * 64).encode(), forbidden); self.assertEqual(writes['supervisor-secret.private.json']['identityToken'], 'c' * 64)
        self.assertFalse(any(call.args[0].name == 'supervisor-secret.private.json' for call in chown.call_args_list))

    def test_initialize_default_does_not_create_any_identity_file(self):
        writes = {}; N = types.SimpleNamespace(canonical=lambda v: json.dumps(v).encode(), exclusive=lambda p, raw, mode: writes.__setitem__(p.name, json.loads(raw)))
        with mock.patch.object(C.secrets, 'token_hex', return_value='b' * 64) as random, mock.patch.object(C.os, 'chown', create=True):
            C.scene_initialize(types.SimpleNamespace(source_commit='a' * 40, engine='playwright'), ROOT, 'd' * 32, DEFAULT, N)
        self.assertEqual(random.call_count, 1); self.assertNotIn('identities.json', writes)
        self.assertIsNone(writes['supervisor-secret.private.json']['identityToken'])

    def test_build_binds_the_actual_manifest_and_real_server_bytes(self):
        value, server, files, manifest = build_fixture(); C.scene_validate_build(value, 'a' * 40, server, files, manifest)
        value['manifestBase64'] = base64.b64encode(b'changed').decode()
        with self.assertRaises(ValueError): C.scene_validate_build(value, 'a' * 40, server, files, manifest)

    def test_build_rejects_wrong_schema_extra_authority_and_oversized_manifest(self):
        for field, replacement in [('schema', 'chengwang.subscription-ui-build/v1'), ('production', True), ('authorization', 'APPROVED')]:
            value, server, files, manifest = build_fixture(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): C.scene_validate_build(value, 'a' * 40, server, files, manifest)
        value, server, files, _ = build_fixture()
        with self.assertRaises(ValueError): C.scene_validate_build(value, 'a' * 40, server, files, b'x' * ((256 << 10) + 1))

    def test_ready_and_run_bind_profile_without_expanding_launcher_or_cli_options(self):
        ready = C.scene_ready_message('a' * 32, 'chrome-cdp', CONFIGURED, 20, 21)
        run = C.scene_run_message('a' * 32, 'chrome-cdp', CONFIGURED)
        self.assertEqual(set(ready), {'schema', 'scenario', 'profile', 'fixtureId', 'engine', 'pid', 'chromePid'})
        self.assertEqual(set(run), {'schema', 'scenario', 'profile', 'fixtureId', 'engine'}); self.assertEqual(ready['profile'], run['profile'])
        self.assertEqual(C.scene_driver_entry(DEFAULT), 'chengwang/tools/capability-truth-browser/ui-cli.mjs')

    def test_public_file_set_has_exactly_seventeen_originals(self):
        self.assertEqual(len(C.scene_public_files(DEFAULT)), 17)
        self.assertEqual(C.scene_public_files(DEFAULT), C.scene_public_files(CONFIGURED))
        self.assertNotIn('supervisor-secret.private.json', C.PUBLIC); self.assertNotIn('identities.json', C.PUBLIC)

    def test_listener_probe_uses_passive_proc_facts_and_rejects_a_fixed_port_listener(self):
        header = b' sl local_address rem_address st\n'
        listening = header + b' 0: 0100007F:45E4 00000000:0000 0A\n'
        with mock.patch.object(C, 'proc_bytes', side_effect=[listening]): self.assertTrue(C.listener_present())
        with mock.patch.object(C, 'proc_bytes', side_effect=[header, header]): self.assertFalse(C.listener_present())
        with mock.patch.object(C, 'proc_bytes', return_value=b'invalid'):
            with self.assertRaises(ValueError): C.listener_present()

    def test_environment_projection_replaces_private_paths_but_preserves_actual_settings(self):
        env = C.scene_child_environment(ROOT, BUNDLE, CONFIGURED); rows = C.environment_projection(env, ROOT, BUNDLE)
        projected = {row['name']: row['value'] for row in rows}
        self.assertEqual(projected['CHENGWANG_IDENTITIES_FILE'], '${PRIVATE_ROOT}/identities.json')
        self.assertEqual(projected['CHENGWANG_WEB_DIR'], '${READONLY_BUNDLE}/source/chengwang/web/dist')
        self.assertEqual(projected['CHENGWANG_MIHOMO_URL'], 'http://127.0.0.1:17892')
        self.assertNotIn(str(ROOT), json.dumps(projected))

    def test_runtime_rejects_foreign_proc_environment_before_publishing_a_claim(self):
        expected = C.scene_child_environment(ROOT, BUNDLE, DEFAULT)
        state = types.SimpleNamespace(server_env=expected, server=types.SimpleNamespace(pid=20))
        raw = b'HTTP_PROXY=http://unexpected\0'
        with mock.patch.object(C, 'proc_bytes', return_value=raw), self.assertRaises(ValueError):
            C.scene_before_run(state, types.SimpleNamespace(), ROOT, BUNDLE, 'a' * 32, DEFAULT, mock.Mock())

    def test_runtime_and_storage_frames_use_the_frozen_schemas_after_environment_binding(self):
        env = C.scene_child_environment(ROOT, BUNDLE, DEFAULT)
        record = dict(role='server', pid=20, startTime='123', exeSHA256='a' * 64, argvSHA256='b' * 64)
        state = types.SimpleNamespace(server_env=env, server=types.SimpleNamespace(pid=20, poll=lambda: 0), records=[record], upstream_before=False)
        options = types.SimpleNamespace(source_commit='a' * 40, engine='chrome-cdp', output_dir=ROOT)
        N = native({'operations.json': dict(version=2, operations=[], idempotency=[])}); output = {}
        N.exclusive = lambda p, raw: output.__setitem__(p.name, json.loads(raw))
        raw = b''.join(name.encode() + b'=' + value.encode() + b'\0' for name, value in env.items())
        with mock.patch.object(C, 'proc_bytes', return_value=raw), mock.patch.object(C, 'private_directory'), \
                mock.patch.object(pathlib.Path, 'exists', return_value=False):
            C.scene_before_run(state, options, ROOT, BUNDLE, 'd' * 32, DEFAULT, N)
            with mock.patch.object(C, 'listener_present', return_value=False), mock.patch.object(C, 'scene_export_policy', return_value=([], [b'canary'])):
                C.scene_post_stop(state, options, ROOT, 'd' * 32, DEFAULT, N)
        definition = C.contract()
        for name in ['runtime-facts.json', 'storage-readback.json']:
            self.assertEqual(set(output[name]), set(definition['exactKeySchemas'][name]))
        self.assertEqual(output['runtime-facts.json']['schema'], definition['schemaNames']['runtime'])
        self.assertEqual(output['storage-readback.json']['schema'], definition['schemaNames']['storage'])
        self.assertFalse(output['runtime-facts.json']['upstreamListener']['afterListening'])
        self.assertIsNone(output['runtime-facts.json']['mihomo']['endpointClass'])
        self.assertEqual(output['runtime-facts.json']['upstreamListener']['endpointClass'], C.ENDPOINT)
        self.assertEqual(output['runtime-facts.json']['serverIdentity']['startTicks'], 123)

    def test_runtime_rejects_a_reenabled_write_gate_before_reading_proc(self):
        env = C.scene_child_environment(ROOT, BUNDLE, DEFAULT); env['CHENGWANG_ALLOW_PUBLISH'] = 'true'
        with mock.patch.object(C, 'proc_bytes') as proc, self.assertRaises(ValueError):
            C.scene_before_run(types.SimpleNamespace(server_env=env), types.SimpleNamespace(), ROOT, BUNDLE, 'a' * 32, DEFAULT, mock.Mock())
        proc.assert_not_called()

    def test_configured_runtime_observes_identity_permissions_before_using_frozen_leaf_values(self):
        env = C.scene_child_environment(ROOT, BUNDLE, CONFIGURED); token = 'b' * 64
        state = types.SimpleNamespace(server_env=env, server=types.SimpleNamespace(pid=20), upstream_before=False,
            records=[dict(role='server', pid=20, startTime='123', exeSHA256='a' * 64, argvSHA256='c' * 64)])
        secret = dict(identityToken=token)
        def read(path, *args):
            value = C.identity(token) if path.name == 'identities.json' else secret
            return json.dumps(value).encode(), types.SimpleNamespace(st_gid=10001)
        N = types.SimpleNamespace(stable_read=mock.Mock(side_effect=read), decode=json.loads)
        raw = b''.join(name.encode() + b'=' + value.encode() + b'\0' for name, value in env.items())
        with mock.patch.object(C, 'proc_bytes', return_value=raw), mock.patch.object(C, 'private_directory'), \
                mock.patch.object(pathlib.Path, 'is_symlink', return_value=False):
            C.scene_before_run(state, types.SimpleNamespace(source_commit='a' * 40, engine='playwright'), ROOT, BUNDLE, 'd' * 32, CONFIGURED, N)
        self.assertEqual(state.runtime['identities'], C.contract()['leafValues']['identitiesConfigured'])
        self.assertEqual(state.runtime['observer'], C.contract()['leafValues']['observerConfigured'])
        self.assertEqual(state.runtime['mihomo']['endpointClass'], C.contract()['leafValues']['endpointClass'])
        self.assertNotIn(token, json.dumps(state.runtime)); self.assertNotIn(C.shared().sha(token.encode()), json.dumps(state.runtime))

    def test_default_storage_rejects_a_dangling_symlink_in_an_unconstructed_path(self):
        N = native({'operations.json': dict(version=2, operations=[], idempotency=[])})
        with mock.patch.object(C, 'private_directory'), mock.patch.object(pathlib.Path, 'exists', return_value=False), \
                mock.patch.object(pathlib.Path, 'is_symlink', return_value=True), self.assertRaises(ValueError):
            C.storage_projection(ROOT, DEFAULT, N)

    def test_export_budgets_come_from_the_frozen_contract_without_identity_export(self):
        secret = dict(schema='chengwang.capability-truth-secrets/v1', profile='default', fenceCanary='a' * 64, identityToken=None)
        rows, forbidden = C.scene_export_policy(ROOT, DEFAULT, native({'supervisor-secret.private.json': secret}), False)
        budgets = {public: budget for private, public, budget in rows}; definition = C.contract(); bounds = definition['captureRules']['bounds']
        self.assertEqual(budgets['driver.json'], bounds['driverFileBytes']); self.assertEqual(budgets['dom.jsonl'], bounds['domFileBytes'])
        self.assertEqual(budgets['captures.jsonl'], bounds['captureFile']); self.assertEqual(budgets['overview-desktop.png'], definition['pngFileBytesMax'])
        self.assertNotIn('supervisor-secret.private.json', budgets); self.assertIn(b'a' * 64, forbidden)

    def test_default_storage_accepts_only_absent_subscription_and_empty_operations(self):
        N = native({'operations.json': dict(version=2, operations=[], idempotency=[])})
        with mock.patch.object(C, 'private_directory'), mock.patch.object(pathlib.Path, 'exists', return_value=False):
            value = C.storage_projection(ROOT, DEFAULT, N)
        self.assertFalse(value['subscriptionStore']['constructed']); self.assertIsNone(value['subscriptionStore']['scope'])
        self.assertEqual(value['operationStore']['commandCount'], 0); self.assertFalse(value['observationStore']['constructed'])

    def test_configured_storage_projects_zero_counts_without_private_keys_or_nodes(self):
        store = dict(schema='chengwang.subscription-store/v1', identityKey=base64.b64encode(b'k' * 32).decode(), sources=[], candidates=[], requests=[], audit=[])
        N = native({'store.json': store, 'operations.json': dict(version=2, operations=[], idempotency=[])})
        with mock.patch.object(C, 'private_directory'): value = C.storage_projection(ROOT, CONFIGURED, N)
        self.assertEqual(value['subscriptionStore']['scope']['objectType'], 'subscription-store')
        self.assertEqual(value['scope']['objectType'], 'control-plane'); self.assertNotIn('identityKey', json.dumps(value))
        self.assertEqual(value['subscriptionStore']['privateNodesCount'], 0)

    def test_storage_rejects_nonempty_commands_and_does_not_invent_zero_readback(self):
        store = dict(schema='chengwang.subscription-store/v1', identityKey=base64.b64encode(b'k' * 32).decode(), sources=[], candidates=[], requests=[], audit=[], commands=[{}])
        with mock.patch.object(C, 'private_directory'), self.assertRaises(ValueError): C.storage_projection(ROOT, CONFIGURED, native({'store.json': store}))
        with mock.patch.object(C, 'private_directory'), mock.patch.object(pathlib.Path, 'exists', return_value=False), self.assertRaises(ValueError):
            C.storage_projection(ROOT, DEFAULT, native({'operations.json': dict(version=2, operations=[{}], idempotency=[])}))

    def test_partial_export_with_unknown_secret_state_publishes_nothing(self):
        N = types.SimpleNamespace(decode=json.loads, stable_read=mock.Mock(side_effect=ValueError('synthetic unsafe secret state')))
        self.assertIsNone(C.scene_export_policy(ROOT, DEFAULT, N, True))
        with self.assertRaises(ValueError): C.scene_export_policy(ROOT, DEFAULT, N, False)

    def test_public_fence_scans_decoded_api_bodies_and_enforces_api_and_dom_budgets(self):
        N = types.SimpleNamespace(decode=json.loads); forbidden = [b'private-canary']
        row = dict(kind='CAPABILITIES', responseBase64=base64.b64encode(b'prefix-private-canary').decode())
        with self.assertRaises(ValueError): C.scene_fence_public(json.dumps(row).encode(), 'captures.jsonl', forbidden, DEFAULT, N, False)
        row['responseBase64'] = base64.b64encode(b'x' * 65537).decode()
        with self.assertRaises(ValueError): C.scene_fence_public(json.dumps(row).encode(), 'captures.jsonl', forbidden, DEFAULT, N, False)
        with self.assertRaises(ValueError): C.scene_fence_public(b'{}\n' * 8, 'dom.jsonl', forbidden, DEFAULT, N, False)


if __name__ == '__main__': unittest.main(verbosity=2)
