"""Shared orchestration CPU contracts; every process and OS action is fake."""
import contextlib
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scene_supervisor_contract_subject', BASE / 'supervisor.py')
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)


class FakeChild:
    def __init__(self, pid, code=0): self.pid = pid; self.code = code; self.returncode = None; self.signals = []
    def wait(self, *, timeout): self.returncode = self.code; return self.code
    def poll(self): return self.returncode
    def send_signal(self, value): self.signals.append(value)


class SupervisorContracts(unittest.TestCase):
    def test_selection_accepts_only_the_six_source_owned_scene_keys(self):
        keys = [S.select_key('subscription', scenario=name) for name in ('create_receipt', 'local_admission', 'remote_fetch', 'remote_handoff_negative')]
        keys += [S.select_key('capability_truth', profile=name) for name in ('default', 'backend_configured')]
        self.assertEqual(tuple(keys), S.KEYS)

    def test_selection_rejects_cross_family_profiles_and_arbitrary_module_names(self):
        for args in [('subscription', 'create_receipt', 'default'), ('capability_truth', 'create_receipt', 'default'),
                     ('subscription', 'capability_truth', None), ('capability_truth', None, '../module'), ('other', None, 'default')]:
            with self.subTest(args=args), self.assertRaises(ValueError): S.select_key(*args)

    def test_registry_rejects_unknown_keys_before_attempting_any_import(self):
        with mock.patch.object(S.importlib.util, 'spec_from_file_location') as loader:
            with self.assertRaises(ValueError): S.load_scene_adapter(pathlib.Path('/trusted'), 'user:module')
        loader.assert_not_called()

    def test_registry_uses_only_the_two_fixed_repository_modules(self):
        for key, relative in [('subscription:create_receipt', S.LEGACY_PATH), ('capability_truth:default', S.CAPABILITY_PATH)]:
            loader = mock.Mock(); module = object(); spec_value = types.SimpleNamespace(loader=loader)
            with mock.patch.object(S.importlib.util, 'spec_from_file_location', return_value=spec_value) as resolve, \
                    mock.patch.object(S.importlib.util, 'module_from_spec', return_value=module):
                self.assertIs(S.load_scene_adapter(pathlib.Path('/trusted'), key), module)
            self.assertEqual(resolve.call_args.args[1], pathlib.Path('/trusted') / relative); loader.exec_module.assert_called_once_with(module)

    def test_only_capability_identity_adds_scenario_and_profile(self):
        old = S.identity('a' * 40, 'b' * 32, 'chrome-cdp', 'subscription:create_receipt')
        new = S.identity('a' * 40, 'b' * 32, 'chrome-cdp', 'capability_truth:default')
        self.assertNotIn('profile', old); self.assertNotIn('scenario', old)
        self.assertEqual(new['profile'], 'default'); self.assertEqual(new['scenario'], 'capability_truth')
        self.assertFalse(new['production'])

    def _run_inner(self, *, key='capability_truth:default', fail=None, node_code=0, server_code=0):
        with tempfile.TemporaryDirectory(prefix='scene-supervisor-cpu-') as temp:
            root = pathlib.Path(temp) / 'private'; root.mkdir(); bundle = pathlib.Path(temp) / 'bundle'; bundle.mkdir()
            output = pathlib.Path(temp) / 'out'; output.mkdir(); server = FakeChild(20, server_code); node = FakeChild(21, node_code)
            options = types.SimpleNamespace(repo=pathlib.Path(temp), source_commit='a' * 40, engine='chrome-cdp', output_dir=output)
            published = {}; run_gates = []; captured = []
            native = types.SimpleNamespace(BASE_ENV={}, command=lambda argv: b'lo' if argv == ['ip', '-o', 'link', 'show'] else b'',
                mount_bind=mock.Mock(), exclusive=lambda p, raw, *args: published.__setitem__(p.name, json.loads(raw)),
                canonical=lambda v: json.dumps(v).encode(), decode=json.loads,
                stable_read=lambda p, *args: (json.dumps(dict(pid=22, uid=10001)).encode(), None),
                publish_atomic=lambda p, raw, mode: run_gates.append(json.loads(raw)), ns=lambda: {}, mount_flags=lambda *a: [])
            adapter = mock.Mock()
            adapter.scene_namespace_extra.return_value = {}; adapter.scene_initialize.return_value = [b'canary']
            adapter.scene_stop_auxiliary.return_value = {}
            adapter.scene_child_environment.return_value = {'EXPLICIT': 'only'}; adapter.scene_driver_entry.return_value = 'fixed/ui-cli.mjs'
            ready = dict(schema='synthetic-ready', fixtureId='b' * 32, engine='chrome-cdp', pid=21, chromePid=22)
            adapter.scene_ready_message.return_value = ready; adapter.scene_run_message.return_value = {'synthetic': 'gate'}
            adapter.scene_failure_diagnostics.return_value = {'driverCheckpoints': [], 'driverDiagnostics': None}
            adapter.scene_before_run.side_effect = lambda state, *args: captured.append(state)
            observed = {'pid': 20, 'role': 'server'}
            def append(tasks, records, dependency):
                records.append(observed)
                if fail == 'records': raise RuntimeError('synthetic partial observation')
            def stop(children, forced):
                for child in children:
                    if child is not None and child.returncode is None: child.returncode = -15; forced += 1
                return forced
            leaf = types.SimpleNamespace(append_process_records=mock.Mock(side_effect=append), terminate_children=mock.Mock(side_effect=stop))
            barrier = dict(ready)
            if fail == 'barrier': barrier['fixtureId'] = 'wrong'
            matrix = types.SimpleNamespace(certificates=lambda *a: {'caPEM': 'synthetic', 'leafPEM': 'synthetic'}, child_limits=mock.Mock(),
                wait_file=lambda *a: barrier, no_owned_processes=lambda: True)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(S, 'load_scene_adapter', return_value=adapter))
                stack.enter_context(mock.patch.object(S.os, 'geteuid', return_value=0, create=True))
                stack.enter_context(mock.patch.object(S.os, 'getpid', return_value=1))
                stack.enter_context(mock.patch.object(S.os, 'chown', create=True))
                stack.enter_context(mock.patch.object(S.subprocess, 'Popen', side_effect=[server, node]))
                stack.enter_context(mock.patch.object(S, 'wait_server'))
                stack.enter_context(mock.patch.object(S, 'export_scene_evidence', return_value=[]))
                if fail or node_code or server_code:
                    with self.assertRaises((ValueError, RuntimeError)): S.supervise_scene(options, pathlib.Path(temp), root, bundle, 'b' * 32, key, native, matrix, leaf)
                else: S.supervise_scene(options, pathlib.Path(temp), root, bundle, 'b' * 32, key, native, matrix, leaf)
            return published, run_gates, captured, observed, adapter, leaf

    def test_shared_normal_path_preserves_real_wait_ownership_and_profile_identity(self):
        published, gates, states, observed, adapter, leaf = self._run_inner()
        self.assertEqual(published['processes.json']['profile'], 'default'); self.assertEqual(published['processes.json']['forcedSignals'], 0)
        self.assertIs(states[0].records[0], observed); self.assertTrue(states[0].succeeded)
        self.assertEqual(len(gates), 1); adapter.scene_post_stop.assert_called_once(); leaf.terminate_children.assert_called_once()

    def test_shared_legacy_path_does_not_add_capability_fields_to_old_outputs(self):
        published, _, _, _, _, _ = self._run_inner(key='subscription:create_receipt')
        self.assertNotIn('profile', published['processes.json']); self.assertNotIn('scenario', published['processes.json'])

    def test_partial_process_records_survive_failure_and_do_not_open_run_gate(self):
        published, gates, _, observed, adapter, _ = self._run_inner(fail='records')
        self.assertEqual(published['failure.json']['records'], [observed]); self.assertEqual(published['failure.json']['stage'], 'DRIVER_BARRIER')
        self.assertNotIn('processes.json', published); self.assertEqual(gates, []); adapter.scene_post_stop.assert_not_called()

    def test_wrong_barrier_rejects_before_recording_or_releasing_browser(self):
        published, gates, _, _, adapter, leaf = self._run_inner(fail='barrier')
        self.assertEqual(gates, []); leaf.append_process_records.assert_not_called(); adapter.scene_before_run.assert_not_called()
        self.assertEqual(published['failure.json']['stage'], 'DRIVER_BARRIER')

    def test_nonzero_node_exit_does_not_export_success_processes(self):
        published, gates, _, _, adapter, _ = self._run_inner(node_code=9)
        self.assertEqual(published['failure.json']['stage'], 'UI_RUN'); self.assertEqual(len(gates), 1)
        self.assertNotIn('processes.json', published); adapter.scene_post_stop.assert_not_called()

    def test_nonzero_server_exit_does_not_authorize_private_readback(self):
        published, _, _, _, adapter, _ = self._run_inner(server_code=9)
        self.assertEqual(published['failure.json']['stage'], 'SERVER_STOP'); adapter.scene_post_stop.assert_not_called()
        self.assertNotIn('processes.json', published)

    def test_unknown_partial_export_canaries_never_authorize_a_file_read(self):
        adapter = mock.Mock(); adapter.scene_export_policy.return_value = None
        options = types.SimpleNamespace(repo=BASE, output_dir=BASE)
        with mock.patch.object(S, 'load_scene_adapter', return_value=adapter):
            native = mock.Mock(); self.assertEqual(S.export_scene_evidence(options, BASE, 'capability_truth:default', native, partial=True), [])
        native.stable_read.assert_not_called(); native.exclusive.assert_not_called()

    def test_prepare_copies_actual_inputs_once_and_binds_the_manifest_before_sealing(self):
        with tempfile.TemporaryDirectory(prefix='scene-inputs-cpu-') as temp:
            base = pathlib.Path(temp); repo = base / 'repo'; repo.mkdir(); output = base / 'out'; output.mkdir()
            original = base / 'consumed/chrome-linux64'; original.mkdir(parents=True); chrome = b'\x7fELFsynthetic-chrome'
            (original / 'chrome').write_bytes(chrome)
            package = repo / 'chengwang/tools/subscription-ui-browser/node_modules/playwright-core'; package.mkdir(parents=True)
            (package / 'package.json').write_bytes(b'{}'); (repo / 'source.py').write_bytes(b'# trusted synthetic source\n')
            tools = repo / 'tools'; tools.mkdir(); (tools / 'ui.mjs').write_bytes(b'// synthetic\n')
            launcher = repo / 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py'; launcher.parent.mkdir(parents=True)
            launcher.write_bytes(b'# synthetic launcher, never executed\n')
            dist = base / 'dist'; (dist / '.vite').mkdir(parents=True)
            for name, raw in [('index.html', b'index'), ('trust.html', b'trust'), ('.vite/manifest.json', b'{}')]: (dist / name).write_bytes(raw)
            node = base / 'node'; node.write_bytes(b'\x7fELFsynthetic-node'); server = base / 'server'; server.write_bytes(b'\x7fELFsynthetic-server')
            receipt = base / 'pin.json'; receipt.write_text(json.dumps(dict(sourceCommit='a' * 40, pinEnforced=True, browserExecuted=False,
                state='PIN_ENFORCED_EXPANDED_NOT_EXECUTED', elf=dict(path='chrome-linux64/chrome', bytes=len(chrome), sha256=S.sha(chrome)))), encoding='utf-8')
            build = base / 'build.json'; build.write_bytes(b'{"synthetic":true}')
            options = types.SimpleNamespace(consumption_root=original.parent, consumption_report=receipt, node=node, server=server,
                build_report=build, dist=dist, source_commit='a' * 40, output_dir=output, engine='chrome-cdp')
            def exclusive(path, raw, *args):
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as handle: handle.write(raw)
            N = types.SimpleNamespace(stable_read=lambda p, *a: (p.read_bytes(), None), decode=json.loads,
                canonical=lambda v: json.dumps(v).encode(), exclusive=exclusive)
            def copy(source, target, label, records, native, executable=False):
                raw = source.read_bytes(); exclusive(target, raw)
                records.append(dict(path=label, bytes=len(raw), sha256=S.sha(raw)))
            adapter = mock.Mock(); adapter.scene_source_files.return_value = ['source.py']; adapter.scene_tool_directories.return_value = ['tools']
            root = base / 'private'; bundle = base / 'bundle'
            with mock.patch.object(S, 'load_scene_adapter', return_value=adapter), mock.patch.object(S.os, 'chown', create=True), \
                    mock.patch.object(pathlib.Path, 'chmod'):
                S.prepare_scene_inputs(options, repo, root, bundle, 'b' * 32, 'capability_truth:default', N, types.SimpleNamespace(copy_input=copy))
            inputs = json.loads((output / 'inputs.json').read_bytes()); copied = inputs['copiedInputs']
            self.assertEqual(inputs['profile'], 'default'); self.assertEqual(len(copied), len({row['path'] for row in copied}))
            self.assertIn(dict(path='source.py', bytes=len((repo / 'source.py').read_bytes()), sha256=S.sha((repo / 'source.py').read_bytes())), copied)
            self.assertEqual((bundle / 'source/chengwang/web/dist/.vite/manifest.json').read_bytes(), b'{}')
            self.assertEqual(adapter.scene_validate_build.call_args.args[-1], b'{}')
            self.assertEqual((output / 'pin-consumption.json').read_bytes(), receipt.read_bytes())

    def test_outer_timeout_rejects_even_a_zero_exit_and_retains_host_failure_evidence(self):
        with tempfile.TemporaryDirectory(prefix='scene-timeout-cpu-') as temp:
            base = pathlib.Path(temp); bundle = base / 'bundle'; bundle.mkdir(); root = base / 'private'; root.mkdir()
            options = types.SimpleNamespace(repo=base, source_commit='a' * 40, engine='chrome-cdp', fixture=None, output_dir=base / 'out',
                consumption_root=base, consumption_report=base, node=base, server=base, dist=base, build_report=base)
            emitted = {}; native = types.SimpleNamespace(BASE_ENV={}, host_observation=lambda *a: ({'host': 1}, []),
                canonical=lambda v: json.dumps(v).encode(), exclusive=lambda p, raw: emitted.__setitem__(p.name, json.loads(raw)))
            adapter = mock.Mock(); child = FakeChild(30); child.returncode = 0
            with mock.patch.dict(S.os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}), \
                    mock.patch.object(S, 'load_scene_adapter', return_value=adapter), mock.patch.object(S, 'prepare_scene_inputs'), \
                    mock.patch.object(S.subprocess, 'Popen', return_value=child), mock.patch.object(S, 'clean_owned'), \
                    mock.patch.object(S, 'export_scene_evidence', return_value=[]):
                with self.assertRaises(ValueError): S.run_scene_outer(options, base, root, bundle, 'b' * 32, 'capability_truth:default', native,
                    mock.Mock(), types.SimpleNamespace(wait_namespace=lambda *a, **kw: True))
            self.assertTrue(emitted['failed-host-readback.json']['innerTimedOut']); self.assertEqual(emitted['failed-host-readback.json']['innerExitCode'], 0)
            self.assertEqual(emitted['failed-host-readback.json']['acceptance'], 'REJECTED_DIAGNOSTIC_ONLY'); adapter.scene_outer_success.assert_not_called()

    def test_outer_host_change_is_failure_and_always_runs_owned_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='scene-outer-cpu-') as temp:
            base = pathlib.Path(temp); bundle = base / 'bundle'; bundle.mkdir(); root = base / 'private'; root.mkdir()
            options = types.SimpleNamespace(repo=base, source_commit='a' * 40, engine='chrome-cdp', fixture=None, output_dir=base / 'out',
                consumption_root=base, consumption_report=base, node=base, server=base, dist=base, build_report=base)
            native = types.SimpleNamespace(BASE_ENV={}, host_observation=mock.Mock(side_effect=[({'host': 1}, []), ({'host': 2}, [])]))
            adapter = mock.Mock(); child = FakeChild(30); child.returncode = 0
            leaf = types.SimpleNamespace(wait_namespace=mock.Mock(return_value=False))
            with mock.patch.dict(S.os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}), \
                    mock.patch.object(S, 'load_scene_adapter', return_value=adapter), mock.patch.object(S, 'prepare_scene_inputs'), \
                    mock.patch.object(S.subprocess, 'Popen', return_value=child), mock.patch.object(S, 'clean_owned') as cleanup:
                with self.assertRaises(ValueError): S.run_scene_outer(options, base, root, bundle, 'b' * 32, 'capability_truth:default', native, mock.Mock(), leaf)
            self.assertEqual(cleanup.call_args_list, [mock.call(root, 'b' * 32), mock.call(bundle, 'b' * 32)])
            adapter.scene_outer_success.assert_not_called(); adapter.scene_cleanup.assert_called_once()
            leaf.wait_namespace.assert_called_once_with(child, wait_seconds=225, terminate_seconds=5, kill_seconds=3)


if __name__ == '__main__': unittest.main(verbosity=2)
