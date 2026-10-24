"""CPU-only fixtures and mocks; no product/browser/process execution evidence."""
import base64
import copy
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parent
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
S = load(BASE.parent / 'browser-scene-supervisor/supervisor.py', 'overview_supervisor_cpu')
A = load(BASE / 'overview_ui_scene.py', 'overview_adapter_cpu')


def fixture_contract():
    # Synthetic adapter-input shape, not a measurement from a browser or server.
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TMPDIR': '/var/tmp',
        'CHENGWANG_ADDR': '127.0.0.1:17891', 'CHENGWANG_DATA_DIR': '${PRIVATE_ROOT}/data',
        'CHENGWANG_WEB_DIR': '${READONLY_BUNDLE}/source/chengwang/web/dist',
        'CHENGWANG_TLS_CERT_FILE': '${PRIVATE_ROOT}/api-leaf.pem', 'CHENGWANG_TLS_KEY_FILE': '${PRIVATE_ROOT}/api-leaf.key',
        'CHENGWANG_MODE': 'candidate', 'CHENGWANG_ALLOW_PUBLISH': 'false', 'CHENGWANG_OPERATION_WRITES_ENABLED': 'false',
        'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED': 'false', 'CHENGWANG_SUBSCRIPTIONS_ENABLED': 'false'}
    return dict(schemaNames=dict(input='chengwang.overview-ui-input/v1', ready='chengwang.overview-ui-driver-ready/v1',
        run='chengwang.overview-ui-run/v1', runtime='chengwang.overview-ui-runtime-facts/v1', storage='chengwang.overview-ui-storage-readback/v1'),
        profilePolicies={name: dict(env=dict(env, CHENGWANG_LIVE_OVERVIEW_ENABLED='true' if name == 'evidence_enabled_unknown' else 'false'),
            mustOmit=['CHENGWANG_IDENTITIES_FILE', 'CHENGWANG_MIHOMO_URL']) for name in A.PROFILES},
        captureRules=dict(kindEnum=['DOCUMENT', 'ASSET', 'OVERVIEW'], bounds=dict(manifestBytes=262144,
            driverFileBytes=1048576, captureFile=25165824, domFileBytes=4194304, domRowBytes=262144,
            bodyAPI=65536, bodyDocument=1048576, bodyAsset=16777216, decodedTotal=25165824)), pngFileBytesMax=8388608,
        profileFacts={'evidence_disabled': dict(requestsMax=72, domCheckpoints=11),
                      'evidence_enabled_unknown': dict(requestsMax=77, domCheckpoints=17)})


class OverviewSceneContracts(unittest.TestCase):
    def test_old_six_keys_and_public_selectors_remain_closed(self):
        self.assertEqual(len(S.KEYS), 6)
        for profile in A.PROFILES:
            key = S.select_overview_key(profile); self.assertNotIn(key, S.KEYS)
            with self.assertRaises(ValueError): S.select_key('overview_ui', profile=profile)
            with self.assertRaises(ValueError): S.identity('a'*40, 'b'*32, 'chrome-cdp', key)
        for profile in ('../user.py', '', 'default', None):
            with self.assertRaises(ValueError): S.select_overview_key(profile)

    def test_new_dispatch_uses_only_fixed_source_module(self):
        for key in S.OVERVIEW_KEYS:
            loader = mock.Mock(); module = object(); spec = types.SimpleNamespace(loader=loader)
            with mock.patch.object(S.importlib.util, 'spec_from_file_location', return_value=spec) as resolve, \
                    mock.patch.object(S.importlib.util, 'module_from_spec', return_value=module):
                self.assertIs(S.scene_adapter(pathlib.Path('/trusted'), key), module)
            self.assertEqual(resolve.call_args.args[1], pathlib.Path('/trusted') / S.OVERVIEW_PATH)
            loader.exec_module.assert_called_once_with(module)

    def test_old_dispatch_really_delegates_at_call_time(self):
        for key in S.KEYS:
            marker = object()
            with mock.patch.object(S, 'load_scene_adapter', return_value=marker) as old:
                self.assertIs(S.scene_adapter(pathlib.Path('/trusted'), key), marker)
            old.assert_called_once_with(pathlib.Path('/trusted'), key)
            self.assertEqual(S.scene_identity('a'*40, 'b'*32, 'playwright', key), S.identity('a'*40, 'b'*32, 'playwright', key))

    def test_unknown_dispatch_and_entry_reject_before_import(self):
        with mock.patch.object(S.importlib.util, 'spec_from_file_location') as load_spec:
            for key in ('overview_ui:default', 'overview_ui:../evil', 'user:module', ''):
                with self.subTest(key=key), self.assertRaises(ValueError): S.scene_adapter(pathlib.Path('/trusted'), key)
                with self.assertRaises(ValueError): S.scene_entry(key)
                with self.assertRaises(ValueError): S.scene_identity('a'*40, 'b'*32, 'chrome-cdp', key)
        load_spec.assert_not_called()

    def test_fixed_entries_and_new_identity_do_not_claim_health(self):
        for key in S.OVERVIEW_KEYS:
            self.assertEqual(S.scene_entry(key), S.OVERVIEW_ENTRY)
            self.assertEqual(set(S.scene_identity('a'*40, 'b'*32, 'chrome-cdp', key)),
                {'schema', 'sourceCommit', 'fixtureId', 'engine', 'production', 'scenario', 'profile'})
            self.assertFalse(S.scene_identity('a'*40, 'b'*32, 'chrome-cdp', key)['production'])
        self.assertEqual(S.scene_entry('subscription:remote_fetch'), S.LEGACY_PATH)
        self.assertEqual(S.scene_entry('capability_truth:default'), S.CAPABILITY_ENTRY)

    def test_environments_are_exact_and_only_switch_overview(self):
        with mock.patch.object(A, 'contract', side_effect=fixture_contract):
            before, after = [A.scene_child_environment(pathlib.Path('/private'), pathlib.Path('/bundle'), key) for key in S.OVERVIEW_KEYS]
        self.assertEqual(before.pop('CHENGWANG_LIVE_OVERVIEW_ENABLED'), 'false')
        self.assertEqual(after.pop('CHENGWANG_LIVE_OVERVIEW_ENABLED'), 'true'); self.assertEqual(before, after)
        self.assertNotIn('CHENGWANG_IDENTITIES_FILE', before); self.assertNotIn('CHENGWANG_MIHOMO_URL', before)
        for name in ('CHENGWANG_ALLOW_PUBLISH', 'CHENGWANG_OPERATION_WRITES_ENABLED', 'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED'):
            self.assertEqual(before[name], 'false')

    def test_environment_policy_drift_is_not_silently_accepted(self):
        value = fixture_contract(); value['profilePolicies']['evidence_disabled']['env']['CHENGWANG_ALLOW_PUBLISH'] = 'true'
        with mock.patch.object(A, 'contract', return_value=value), self.assertRaises(ValueError):
            A.scene_child_environment(pathlib.Path('/private'), pathlib.Path('/bundle'), S.OVERVIEW_KEYS[0])

    def test_private_input_has_canary_but_no_identity_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); writes = {}
            N = types.SimpleNamespace(canonical=lambda v: json.dumps(v).encode(), exclusive=lambda p, b, mode: writes.__setitem__(p.name, (json.loads(b), mode)))
            options = types.SimpleNamespace(source_commit='a'*40, engine='playwright')
            with mock.patch.object(A, 'contract', side_effect=fixture_contract), mock.patch.object(A.os, 'chown', create=True):
                fence = A.scene_initialize(options, root, 'b'*32, S.OVERVIEW_KEYS[0], N)
            browser, mode = writes['overview-input.private.json']; self.assertEqual(mode, 0o600)
            self.assertEqual(set(browser), {'schema', 'scenario', 'profile', 'fixtureId', 'sourceCommit', 'engine', 'fenceCanary'})
            self.assertEqual(set(writes['supervisor-secret.private.json'][0]), {'schema', 'profile', 'fenceCanary'})
            self.assertNotIn('identities.json', writes); self.assertIn(browser['fenceCanary'].encode(), fence)
            (root / 'identities.json').write_bytes(b'forbidden synthetic identity')
            with mock.patch.object(A, 'contract', side_effect=fixture_contract), self.assertRaises(ValueError):
                A.scene_initialize(options, root, 'b'*32, S.OVERVIEW_KEYS[0], N)

    def test_ready_and_run_are_exact_and_profile_bound(self):
        with mock.patch.object(A, 'contract', side_effect=fixture_contract):
            ready = A.scene_ready_message('b'*32, 'chrome-cdp', S.OVERVIEW_KEYS[1], 11, 12)
            run = A.scene_run_message('b'*32, 'chrome-cdp', S.OVERVIEW_KEYS[1])
        self.assertEqual(set(ready), {'schema', 'scenario', 'profile', 'fixtureId', 'engine', 'pid', 'chromePid'})
        self.assertEqual(set(run), {'schema', 'scenario', 'profile', 'fixtureId', 'engine'})
        self.assertEqual(run['profile'], 'evidence_enabled_unknown'); self.assertEqual(ready['chromePid'], 12)

    def test_build_binds_server_manifest_and_original_toolchain(self):
        server = b'\x7fELFsynthetic-not-executable'; manifest = b'{"synthetic":true}'
        files = [dict(path=name, bytes=len(manifest) if name == '.vite/manifest.json' else 1,
            sha256=S.sha(manifest) if name == '.vite/manifest.json' else 'a'*64)
            for name in ('.vite/manifest.json', 'assets/index.js', 'index.html', 'trust.html')]
        build = dict(schema='chengwang.overview-ui-build/v1', sourceCommit='a'*40, goVersion='go1.23.12', nodeVersion='v22.23.3',
            moduleMode='vendor', goDependencyDownloads=False, server=dict(name='server', bytes=len(server), sha256=S.sha(server)),
            distFiles=files, manifestBase64=base64.b64encode(manifest).decode(), production=False, authorization='BLOCKED')
        with mock.patch.object(A, 'contract', side_effect=fixture_contract):
            A.scene_validate_build(build, 'a'*40, server, files, manifest)
            for patch in (dict(production=True), dict(schema='chengwang.capability-truth-build/v1'),
                          dict(goDependencyDownloads=True), dict(manifestBase64=base64.b64encode(b'wrong').decode())):
                with self.subTest(patch=patch), self.assertRaises(ValueError): A.scene_validate_build(dict(build, **patch), 'a'*40, server, files, manifest)

    def test_unavailable_body_is_only_exact_expected_503_and_remains_null(self):
        value = dict(kind='OVERVIEW', path='/api/v1/overview', method='GET', status=503, bodyState='unavailable',
            bodyUnavailableReason='BODY_RPC_REJECTED_AFTER_EXPECTED_503', bodyRPC=dict(attempted=True, outcome='rejected'),
            responseBase64=None, responseBytes=None, responseSHA256=None)
        N = types.SimpleNamespace(decode=json.loads)
        with mock.patch.object(A, 'contract', side_effect=fixture_contract):
            A.scene_fence_public(json.dumps(value).encode(), 'captures.jsonl', [], S.OVERVIEW_KEYS[0], N, False)
            variants = [dict(value, **patch) for patch in (dict(status=200), dict(method='POST'), dict(path='/api/v1/probes/status'),
                dict(responseSHA256='a'*64), dict(bodyRPC=dict(attempted=True, outcome='fulfilled')), dict(bodyState='present'))]
            for row in variants:
                with self.subTest(row=row), self.assertRaises(ValueError): A.scene_fence_public(json.dumps(row).encode(), 'captures.jsonl', [], S.OVERVIEW_KEYS[0], N, False)
            with self.assertRaises(ValueError): A.scene_fence_public(json.dumps(value).encode(), 'captures.jsonl', [], S.OVERVIEW_KEYS[1], N, False)

    def test_encoded_secret_and_missing_full_body_are_rejected(self):
        N = types.SimpleNamespace(decode=json.loads)
        row = dict(kind='OVERVIEW', bodyState='present', responseBase64=base64.b64encode(b'FENCE-CANARY').decode())
        with mock.patch.object(A, 'contract', side_effect=fixture_contract):
            with self.assertRaises(ValueError): A.scene_fence_public(json.dumps(row).encode(), 'captures.jsonl', [b'FENCE-CANARY'], S.OVERVIEW_KEYS[1], N, False)
            row['responseBase64'] = None
            with self.assertRaises(ValueError): A.scene_fence_public(json.dumps(row).encode(), 'captures.jsonl', [], S.OVERVIEW_KEYS[1], N, False)

    def test_storage_projection_rejects_nonempty_commands_and_configured_stores(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); (root / 'data').mkdir()
            operation = dict(version=2, operations=[], idempotency=[])
            N = types.SimpleNamespace(stable_read=lambda *a: (json.dumps(operation).encode(), None), decode=json.loads)
            with mock.patch.object(A, 'private_directory'):
                result = A.storage_projection(root, S.OVERVIEW_KEYS[0], N)
                self.assertFalse(result['subscriptionStore']['constructed']); self.assertEqual(result['operationStore']['commandCount'], 0)
                operation['operations'] = [dict(synthetic=True)]
                with self.assertRaises(ValueError): A.storage_projection(root, S.OVERVIEW_KEYS[0], N)
                operation['operations'] = []; (root / 'data/subscriptions').mkdir()
                with self.assertRaises(ValueError): A.storage_projection(root, S.OVERVIEW_KEYS[0], N)

    def test_missing_driver_diagnostics_are_unknown_not_success(self):
        result = A.scene_failure_diagnostics(None, None, None, None, S.OVERVIEW_KEYS[0], None)
        self.assertEqual(result, dict(driverCheckpoints=[], driverDiagnostics=None))
        self.assertNotIn('normalCloseCompleted', result)

    def test_actual_source_contract_matches_environment_and_public_closed_set(self):
        contract = A.contract(); self.assertEqual(len(contract['publicFiles']), 19)
        self.assertEqual(A.PUBLIC, set(contract['publicFiles']))
        for key in S.OVERVIEW_KEYS:
            A.scene_child_environment(pathlib.Path('/private'), pathlib.Path('/bundle'), key)
            ready = A.scene_ready_message('b'*32, 'chrome-cdp', key, 11, 12)
            run = A.scene_run_message('b'*32, 'chrome-cdp', key)
            self.assertEqual(set(ready), set(contract['exactKeySchemas']['ready']))
            self.assertEqual(set(run), set(contract['exactKeySchemas']['run']))

    def test_missing_driver_dependency_is_rejected_before_any_launch(self):
        self.assertEqual(A.scene_tool_directories(S.OVERVIEW_KEYS[0]), (
            'chengwang/tools/subscription-ui-browser', 'chengwang/tools/subscription-browser',
            'chengwang/tools/overview-ui-browser', 'chengwang/tools/browser-scene-driver', 'chengwang/tools/capability-truth-browser'))
        with mock.patch.object(pathlib.Path, 'is_file', return_value=False):
            with self.assertRaises(ValueError): A.scene_source_files(S.OVERVIEW_KEYS[0])


if __name__ == '__main__': unittest.main()
