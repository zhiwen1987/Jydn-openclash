"""CPU-only lifecycle contracts with fake processes; no live /proc or signals."""
import ast
import builtins
import hashlib
import importlib.util
import os
import pathlib
import subprocess
import types
import unittest
from unittest import mock


BASE = pathlib.Path(__file__).resolve().parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


L = load(BASE / 'lifecycle.py', 'browser_scene_lifecycle_contract_subject')


class FakeProcess:
    def __init__(self, name, trace, waits=(), poll=None, terminate_error=None, kill_error=None):
        self.name = name; self.trace = trace; self.waits = list(waits); self.poll_value = poll
        self.terminate_error = terminate_error; self.kill_error = kill_error; self.returncode = poll

    def poll(self):
        self.trace.append((self.name, 'poll')); return self.poll_value

    def terminate(self):
        self.trace.append((self.name, 'terminate'))
        if self.terminate_error is not None: raise self.terminate_error

    def kill(self):
        self.trace.append((self.name, 'kill'))
        if self.kill_error is not None: raise self.kill_error

    def wait(self, *, timeout):
        self.trace.append((self.name, 'wait', timeout))
        if not self.waits: raise AssertionError('unexpected fake wait')
        value = self.waits.pop(0)
        if isinstance(value, BaseException): raise value
        self.returncode = value; return value


class LifecycleContracts(unittest.TestCase):
    def test_append_records_keeps_task_order_hash_limits_and_observed_argv(self):
        tasks = [('server', 10, pathlib.Path('/synthetic/server'), 128), ('controller', 11, pathlib.Path('/synthetic/node'), 256)]
        native = types.SimpleNamespace(stable_read=mock.Mock(side_effect=[(b'server', None), (b'node', None)]),
            task_profile=mock.Mock(side_effect=[{'pid': 10}, {'pid': 11}]))
        records = []
        with mock.patch.object(pathlib.Path, 'read_bytes', autospec=True, side_effect=[b'/synthetic/server\0', b'/synthetic/node\0driver\0']) as read:
            self.assertIsNone(L.append_process_records(tasks, records, native))
        self.assertEqual(records, [{'pid': 10, 'role': 'server', 'argv': ['/synthetic/server']},
            {'pid': 11, 'role': 'controller', 'argv': ['/synthetic/node', 'driver']}])
        self.assertEqual(native.stable_read.call_args_list, [mock.call(tasks[0][2], 128), mock.call(tasks[1][2], 256)])
        self.assertEqual(native.task_profile.call_args_list, [mock.call(10, hashlib.sha256(b'server').hexdigest(), executable_limit=128),
            mock.call(11, hashlib.sha256(b'node').hexdigest(), executable_limit=256)])
        self.assertEqual(read.call_args_list, [mock.call(pathlib.Path('/proc/10/cmdline')), mock.call(pathlib.Path('/proc/11/cmdline'))])

    def test_append_retains_partial_records_when_later_profile_fails(self):
        failure = RuntimeError('synthetic profile failure')
        native = types.SimpleNamespace(stable_read=mock.Mock(return_value=(b'elf', None)),
            task_profile=mock.Mock(side_effect=[{'pid': 10}, failure]))
        records = []
        with mock.patch.object(pathlib.Path, 'read_bytes', return_value=b'server\0'), self.assertRaises(RuntimeError) as raised:
            L.append_process_records([('server', 10, pathlib.Path('/a'), 128), ('controller', 11, pathlib.Path('/b'), 256)], records, native)
        self.assertIs(raised.exception, failure)
        self.assertEqual(records, [{'pid': 10, 'role': 'server', 'argv': ['server']}])

    def test_append_retains_partial_records_when_later_cmdline_read_fails(self):
        failure = FileNotFoundError('synthetic process disappeared')
        native = types.SimpleNamespace(stable_read=mock.Mock(return_value=(b'elf', None)),
            task_profile=mock.Mock(side_effect=[{'pid': 10}, {'pid': 11}]))
        records = []
        with mock.patch.object(pathlib.Path, 'read_bytes', side_effect=[b'server\0', failure]), self.assertRaises(FileNotFoundError) as raised:
            L.append_process_records([('server', 10, pathlib.Path('/a'), 128), ('controller', 11, pathlib.Path('/b'), 256)], records, native)
        self.assertIs(raised.exception, failure)
        self.assertEqual(records, [{'pid': 10, 'role': 'server', 'argv': ['server']}])

    def test_append_does_not_publish_an_incompletely_decoded_record(self):
        native = types.SimpleNamespace(stable_read=mock.Mock(return_value=(b'elf', None)),
            task_profile=mock.Mock(side_effect=[{'pid': 10}, {'pid': 11}]))
        records = []
        with mock.patch.object(pathlib.Path, 'read_bytes', side_effect=[b'server\0', b'\xff\0']), self.assertRaises(UnicodeDecodeError):
            L.append_process_records([('server', 10, pathlib.Path('/a'), 128), ('controller', 11, pathlib.Path('/b'), 256)], records, native)
        self.assertEqual(records, [{'pid': 10, 'role': 'server', 'argv': ['server']}])

    def test_append_empty_preserves_existing_records_without_observations(self):
        records = [{'existing': True}]; native = mock.Mock()
        with mock.patch.object(pathlib.Path, 'read_bytes') as read:
            self.assertIsNone(L.append_process_records([], records, native))
        self.assertEqual(records, [{'existing': True}]); self.assertEqual(native.mock_calls, []); read.assert_not_called()

    def test_terminate_skips_absent_and_exited_children_without_resetting_count(self):
        trace = []; child = FakeProcess('done', trace, poll=7)
        self.assertEqual(L.terminate_children((None, child), 4), 4)
        self.assertEqual(trace, [('done', 'poll')]); self.assertEqual(child.returncode, 7)

    def test_terminate_preserves_caller_order_and_counts_each_termination(self):
        trace = []; node = FakeProcess('node', trace, waits=[0]); server = FakeProcess('server', trace, waits=[0])
        self.assertEqual(L.terminate_children((node, server, None), 2), 4)
        self.assertEqual(trace, [('node', 'poll'), ('node', 'terminate'), ('node', 'wait', 5),
            ('server', 'poll'), ('server', 'terminate'), ('server', 'wait', 5)])

    def test_terminate_counts_timeout_kill_and_keeps_final_wait_budget(self):
        trace = []; child = FakeProcess('node', trace, waits=[subprocess.TimeoutExpired('synthetic', 5), -9])
        self.assertEqual(L.terminate_children((child,)), 2)
        self.assertEqual(trace, [('node', 'poll'), ('node', 'terminate'), ('node', 'wait', 5), ('node', 'kill'), ('node', 'wait', 3)])
        self.assertEqual(child.returncode, -9)

    def test_terminate_propagates_unexpected_wait_without_killing_or_visiting_next(self):
        trace = []; failure = RuntimeError('synthetic wait failure')
        child = FakeProcess('node', trace, waits=[failure]); later = FakeProcess('server', trace, waits=[0])
        with self.assertRaises(RuntimeError) as raised: L.terminate_children((child, later))
        self.assertIs(raised.exception, failure)
        self.assertEqual(trace, [('node', 'poll'), ('node', 'terminate'), ('node', 'wait', 5)])

    def test_terminate_propagates_final_wait_timeout_without_reporting_a_count(self):
        trace = []; failure = subprocess.TimeoutExpired('synthetic', 3)
        child = FakeProcess('node', trace, waits=[subprocess.TimeoutExpired('synthetic', 5), failure])
        with self.assertRaises(subprocess.TimeoutExpired) as raised: L.terminate_children((child,))
        self.assertIs(raised.exception, failure)
        self.assertEqual(trace[-2:], [('node', 'kill'), ('node', 'wait', 3)])

    def test_terminate_propagates_signal_failure_without_waiting_or_visiting_next(self):
        trace = []; failure = ProcessLookupError('synthetic signal failure')
        child = FakeProcess('node', trace, terminate_error=failure); later = FakeProcess('server', trace)
        with self.assertRaises(ProcessLookupError) as raised: L.terminate_children((child, later))
        self.assertIs(raised.exception, failure); self.assertEqual(trace, [('node', 'poll'), ('node', 'terminate')])

    def test_namespace_does_not_translate_nonzero_exit_into_timeout_or_success(self):
        trace = []; child = FakeProcess('namespace', trace, waits=[9], poll=9)
        self.assertFalse(L.wait_namespace(child)); self.assertEqual(child.returncode, 9)
        self.assertEqual(trace, [('namespace', 'wait', 225), ('namespace', 'poll')])

    def test_namespace_retains_timeout_even_if_child_exits_before_finally_poll(self):
        trace = []; child = FakeProcess('namespace', trace, waits=[subprocess.TimeoutExpired('synthetic', 225)], poll=0)
        self.assertTrue(L.wait_namespace(child))
        self.assertEqual(trace, [('namespace', 'wait', 225), ('namespace', 'poll')])

    def test_namespace_timeout_runs_graceful_cleanup_in_original_order(self):
        trace = []; child = FakeProcess('namespace', trace, waits=[subprocess.TimeoutExpired('synthetic', 225), 0])
        self.assertTrue(L.wait_namespace(child, wait_seconds=225, terminate_seconds=5, kill_seconds=3))
        self.assertEqual(trace, [('namespace', 'wait', 225), ('namespace', 'poll'), ('namespace', 'terminate'), ('namespace', 'wait', 5)])

    def test_namespace_timeout_escalates_only_after_terminate_wait_timeout(self):
        trace = []; child = FakeProcess('namespace', trace,
            waits=[subprocess.TimeoutExpired('synthetic', 225), subprocess.TimeoutExpired('synthetic', 5), -9])
        self.assertTrue(L.wait_namespace(child))
        self.assertEqual(trace, [('namespace', 'wait', 225), ('namespace', 'poll'), ('namespace', 'terminate'),
            ('namespace', 'wait', 5), ('namespace', 'kill'), ('namespace', 'wait', 3)])

    def test_namespace_unexpected_wait_still_cleans_up_then_propagates_original(self):
        trace = []; failure = RuntimeError('synthetic namespace wait failure')
        child = FakeProcess('namespace', trace, waits=[failure, 0])
        with self.assertRaises(RuntimeError) as raised: L.wait_namespace(child)
        self.assertIs(raised.exception, failure)
        self.assertEqual(trace, [('namespace', 'wait', 225), ('namespace', 'poll'), ('namespace', 'terminate'), ('namespace', 'wait', 5)])

    def test_namespace_finally_failure_propagates_instead_of_returning_timeout(self):
        trace = []; failure = ProcessLookupError('synthetic cleanup failure')
        child = FakeProcess('namespace', trace, waits=[subprocess.TimeoutExpired('synthetic', 225)], terminate_error=failure)
        with self.assertRaises(ProcessLookupError) as raised: L.wait_namespace(child)
        self.assertIs(raised.exception, failure)
        self.assertEqual(trace, [('namespace', 'wait', 225), ('namespace', 'poll'), ('namespace', 'terminate')])

    def test_import_has_only_declarations_and_starts_no_io_or_processes(self):
        # Python's loader/stdlib may read files. This forbids application I/O
        # and process launch while executing the already-read module body.
        raw = (BASE / 'lifecycle.py').read_bytes(); tree = ast.parse(raw); code = compile(tree, 'synthetic-lifecycle-import', 'exec')
        self.assertTrue(all(isinstance(node, (ast.Import, ast.FunctionDef)) or
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) for node in tree.body))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self.assertEqual(node.decorator_list, [])
                self.assertTrue(all(isinstance(value, ast.Constant) for value in [*node.args.defaults, *node.args.kw_defaults] if value is not None))
        modules = {'hashlib': hashlib, 'pathlib': pathlib, 'subprocess': subprocess}; imported = []
        def cached_import(name, *args, **kwargs):
            self.assertIn(name, modules); imported.append(name); return modules[name]
        scope = {'__builtins__': {**vars(builtins), '__import__': cached_import}}
        with mock.patch.object(builtins, 'open', side_effect=AssertionError('import I/O')), \
                mock.patch.object(os, 'open', side_effect=AssertionError('import I/O')), \
                mock.patch.object(pathlib.Path, 'read_bytes', side_effect=AssertionError('import I/O')), \
                mock.patch.object(pathlib.Path, 'read_text', side_effect=AssertionError('import I/O')), \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('import process')):
            exec(code, scope)
        self.assertEqual(imported, ['hashlib', 'pathlib', 'subprocess'])

    def test_runner_loader_uses_only_the_explicit_trusted_repository_path(self):
        runner = load(BASE.parent / 'subscription-ui-browser/run_subscription_ui.py', 'lifecycle_runner_loader_contract_subject')
        repo = pathlib.PurePosixPath('/trusted/source'); sentinel = object()
        with mock.patch.object(runner, 'load_module', return_value=sentinel) as loader:
            self.assertIs(runner.lifecycle(repo), sentinel)
        loader.assert_called_once_with(repo / 'chengwang/deploy/browser-scene-supervisor/lifecycle.py', 'subscription_ui_lifecycle_primitives')


if __name__ == '__main__': unittest.main(verbosity=2)
