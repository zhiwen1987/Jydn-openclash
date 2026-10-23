"""Eight frozen synthetic runner contracts: no server, Node or Chrome starts.

The in-memory protocol-shaped byte fixtures are custody models, not accepted
browser matrix evidence or substitutes for the independent full gate.
"""
import ast
import contextlib
import importlib.util
import io
import json
import pathlib
import types
import unittest
from unittest import mock


BASE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('stream_matrix_runner_contract_subject', BASE / 'run_matrix.py')
R = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(R)


class MemoryNative:
    BASE_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}

    def __init__(self, records):
        self.records = dict(records); self.reads = []; self.writes = []
        self.mount_bind = mock.Mock()

    @staticmethod
    def canonical(value): return json.dumps(value, separators=(',', ':')).encode()

    @staticmethod
    def decode(raw):
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError('duplicate synthetic JSON key')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=pairs)

    def stable_read(self, path, limit=1 << 20, owner=None, mode=None):
        self.reads.append((path, limit, owner, mode))
        raw = self.records[path]
        if isinstance(raw, BaseException): raise raw
        if len(raw) > limit: raise ValueError('synthetic bounded read failed')
        return raw, None

    def exclusive(self, path, raw, *_):
        if path in self.records: raise FileExistsError('synthetic no overwrite')
        self.records[path] = raw; self.writes.append((path, raw))

    @staticmethod
    def command(arguments):
        return b'1: lo\n' if arguments == ['ip', '-o', 'link', 'show'] else b''


class TestMatrixRunnerContracts(unittest.TestCase):
    def fixture(self):
        root = pathlib.Path('/SYNTHETIC/private'); output = pathlib.Path('/SYNTHETIC/public')
        options = types.SimpleNamespace(output_dir=output, source_commit='a' * 40, engine='chrome-cdp')
        raw = {
            'matrix-driver.private.json': b'{ "schema": "chengwang.stream-matrix-driver/v1", "production": false }\n',
            'network.private.jsonl': b'{"v":1,"event":"START","case":"split-success"}\n',
            'server-events.private.jsonl': b'{"schema":"chengwang.stream-matrix-server-event/v1","ordinal":1,"event":"REQUEST","caseId":"split-success","bodyBytes":0,"framedBytes":0,"reason":"OK"}\n',
        }
        native = MemoryNative({root / name: value for name, value in raw.items()})
        return root, options, native, raw

    @contextlib.contextmanager
    def paths(self, native):
        with mock.patch.object(pathlib.Path, 'exists', lambda path: path in native.records):
            yield

    def test_original_observation_bytes_are_kept_without_reserialization_or_pass_claim(self):
        root, options, native, raw = self.fixture()
        with self.paths(native): result = R.export_observations(options, root, native)
        self.assertEqual(result, ['driver.json', 'network.jsonl', 'server-events.jsonl'])
        for private, public in zip(raw, result): self.assertEqual(native.records[options.output_dir / public], raw[private])
        self.assertEqual(len(native.reads), 3)
        self.assertTrue(all((limit, owner, mode) == (1 << 20, 10001, 0o600) for _, limit, owner, mode in native.reads))
        self.assertFalse(any(b'PASS' in value for _, value in native.writes))

    def test_partial_missing_and_rejected_input_does_not_destroy_other_originals(self):
        for change in ('missing', 'truncated', 'bad-custody'):
            root, options, native, raw = self.fixture(); source = root / 'matrix-driver.private.json'
            if change == 'missing': del native.records[source]
            elif change == 'truncated': native.records[source] = b'{"schema":'
            else: native.records[source] = PermissionError('SYNTHETIC_PRIVATE_CUSTODY_FAILURE')
            with self.paths(native): result = R.export_observations(options, root, native, partial=True)
            self.assertEqual(result, ['network.jsonl', 'server-events.jsonl'])
            self.assertEqual(native.records[options.output_dir / 'network.jsonl'], raw['network.private.jsonl'])
            self.assertEqual(native.records[options.output_dir / 'server-events.jsonl'], raw['server-events.private.jsonl'])
            self.assertNotIn(options.output_dir / 'driver.json', native.records)

    def test_private_keys_bearers_and_nested_token_fields_never_cross_public_boundary(self):
        values = [b'{"schema":"x","value":"-----BEGIN PRIVATE KEY-----"}\n',
                  b'{"schema":"x","value":"Bearer SYNTHETIC"}\n']
        for key in ('token', 'privateKey', 'private_key', 'authorization', 'cookie', 'password', 'secret'):
            values.append(json.dumps({'schema': 'x', 'nested': [{key: 'SYNTHETIC_PRIVATE_MATERIAL'}]}).encode())
        for raw in values:
            root, options, native, _ = self.fixture(); native.records[root / 'matrix-driver.private.json'] = raw
            with self.paths(native), self.assertRaises(ValueError): R.export_observations(options, root, native)
            self.assertNotIn(options.output_dir / 'driver.json', native.records)

    def test_existing_originals_are_never_overwritten_in_full_or_partial_mode(self):
        for partial in (False, True):
            root, options, native, _ = self.fixture(); target = options.output_dir / 'driver.json'
            native.records[target] = b'SYNTHETIC_EXISTING_ORIGINAL\n'
            with self.paths(native):
                if partial:
                    exported = R.export_observations(options, root, native, partial=True)
                    self.assertEqual(exported, ['network.jsonl', 'server-events.jsonl'])
                else:
                    with self.assertRaises(FileExistsError): R.export_observations(options, root, native)
            self.assertEqual(native.records[target], b'SYNTHETIC_EXISTING_ORIGINAL\n')

    def test_export_names_are_fixed_and_raw_logs_profiles_keys_are_not_read(self):
        root, options, native, _ = self.fixture()
        forbidden = ['api-leaf.key', 'ca.key', 'server.private.log', 'driver.private.log', 'chrome-profile', 'arbitrary.json']
        for name in forbidden: native.records[root / name] = b'SYNTHETIC_PRIVATE_MATERIAL'
        with self.paths(native): R.export_observations(options, root, native)
        self.assertEqual({path.name for path, *_ in native.reads},
            {'matrix-driver.private.json', 'network.private.jsonl', 'server-events.private.jsonl'})
        self.assertEqual({path.name for path, _ in native.writes}, {'driver.json', 'network.jsonl', 'server-events.jsonl'})

    def test_malformed_nonobjects_duplicate_keys_and_oversized_complete_capture_rejected(self):
        for raw in (b'[]\n', b'null\n', b'1\n', b'{"x":1,"x":2}\n', b'{"x":', b'S' * ((1 << 20) + 1)):
            root, options, native, _ = self.fixture(); native.records[root / 'matrix-driver.private.json'] = raw
            with self.paths(native), self.assertRaises((ValueError, json.JSONDecodeError)):
                R.export_observations(options, root, native)
            self.assertNotIn(options.output_dir / 'driver.json', native.records)

    def test_failed_child_keeps_actual_exit_codes_fixed_stages_and_diagnostic_originals(self):
        root, options, native, raw = self.fixture(); fixture = 'b' * 32
        repo, bundle = pathlib.Path('/SYNTHETIC/repo'), pathlib.Path('/SYNTHETIC/tools')
        native.records[root / 'driver.private.log'] = (b'STREAM_MATRIX_STAGE=LAUNCH\nSYNTHETIC_PRIVATE_ERROR\n'
            b'STREAM_MATRIX_STAGE=SYNTHETIC_PRIVATE_STAGE\n')
        server = mock.Mock(pid=12); server.poll.return_value = None; server.wait.return_value = 0
        server.terminate.side_effect = lambda: setattr(server.poll, 'return_value', 0)
        node = mock.Mock(pid=13); node.poll.return_value = 1
        ready = dict(schema='chengwang.stream-matrix-ready/v1', fixtureId=fixture,
                     origin='https://127.0.0.1:17881', pid=server.pid, uid=10001)
        with mock.patch.object(R.os, 'geteuid', return_value=0, create=True), \
             mock.patch.object(R.os, 'getpid', return_value=1), \
             mock.patch.object(R, 'certificates', return_value={'caPEM': 'SYNTHETIC', 'leafPEM': 'SYNTHETIC'}), \
             mock.patch.object(pathlib.Path, 'open', side_effect=lambda *_, **__: io.BytesIO()), \
             mock.patch.object(R.subprocess, 'Popen', side_effect=[server, node]), \
             mock.patch.object(R, 'wait_file', side_effect=[ready, ValueError('SYNTHETIC_PRIVATE_ERROR')]), \
             mock.patch.object(R, 'no_owned_processes', return_value=True), self.paths(native):
            with self.assertRaises(ValueError): R.inner(options, repo, root, bundle, fixture, native)
        failure = native.decode(native.records[options.output_dir / 'failure.json'])
        self.assertEqual(failure['acceptance'], 'REJECTED_DIAGNOSTIC_ONLY')
        self.assertEqual(failure['stage'], 'DRIVER_BARRIER'); self.assertEqual(failure['driverCheckpoints'], ['LAUNCH'])
        self.assertEqual((failure['serverExitCode'], failure['controllerExitCode']), (0, 1))
        self.assertEqual(failure['forcedSignals'], 0); self.assertTrue(failure['noLiveOwnedProcesses'])
        self.assertEqual(failure['capturedOriginals'], ['driver.json', 'network.jsonl', 'server-events.jsonl'])
        self.assertNotIn(b'SYNTHETIC_PRIVATE_ERROR', native.records[options.output_dir / 'failure.json'])
        self.assertNotIn(b'SYNTHETIC_PRIVATE_STAGE', native.records[options.output_dir / 'failure.json'])
        for private, public in zip(raw, failure['capturedOriginals']):
            self.assertEqual(native.records[options.output_dir / public], raw[private])

    def test_finally_custody_reap_and_outer_failed_host_record_remain_rejected_not_pass(self):
        source = (BASE / 'run_matrix.py').read_text(encoding='utf-8'); tree = ast.parse(source)
        inner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inner')
        cleanup = next(node for node in inner.body if isinstance(node, ast.Try) and node.finalbody)
        calls = [node for statement in cleanup.finalbody for node in ast.walk(statement) if isinstance(node, ast.Call)]
        self.assertTrue(any(isinstance(call.func, ast.Name) and call.func.id == 'export_observations'
            and any(k.arg == 'partial' and isinstance(k.value, ast.Constant) and k.value.value is True for k in call.keywords)
            for call in calls))
        self.assertTrue(any(isinstance(call.func, ast.Name) and call.func.id == 'no_owned_processes' for call in calls))
        self.assertIn('waitpid(-1, os.WNOHANG)', source)
        acceptance = [keyword.value for node in ast.walk(tree) if isinstance(node, ast.Call)
                      for keyword in node.keywords if keyword.arg == 'acceptance']
        self.assertGreaterEqual(len(acceptance), 2)
        self.assertTrue(all(isinstance(value, ast.Constant) and value.value == 'REJECTED_DIAGNOSTIC_ONLY'
                            for value in acceptance))
        self.assertIn("'failure.json'", source); self.assertIn("'failed-host-readback.json'", source)
        self.assertNotIn('failure.json', R.PUBLIC); self.assertNotIn('failed-host-readback.json', R.PUBLIC)
        self.assertLess(source.index("'failed-host-readback.json'"), source.index("        isolation = N.decode"))
        self.assertIn("'--kill-child=SIGKILL'", source)
        self.assertNotIn("'--kill-child=SIGTERM'", source)
        self.assertIn('child.wait(timeout=190)', source)
        self.assertIn('timed_out = False', source)
        self.assertIn('except subprocess.TimeoutExpired:\n                timed_out = True', source)
        self.assertIn('child.terminate()', source)
        self.assertIn('except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)', source)
        self.assertIn('inner_code = child.returncode', source)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        exit_assignments = [node.value for node in ast.walk(main) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'inner_code' for target in node.targets)]
        self.assertEqual(len(exit_assignments), 2)
        self.assertTrue(all(isinstance(value, ast.Call) or
            (isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
             and value.value.id == 'child' and value.attr == 'returncode') for value in exit_assignments))
        failure_start = source.index('if inner_code != 0 or timed_out:')
        failure_branch = source[failure_start:source.index('        isolation = N.decode')]
        self.assertIn('export_observations(options, root, N, partial=True)', failure_branch)
        self.assertIn('innerExitCode=inner_code, innerTimedOut=timed_out', failure_branch)
        self.assertIn("acceptance='REJECTED_DIAGNOSTIC_ONLY'", failure_branch)
        self.assertIn('need(False)', failure_branch)


if __name__ == '__main__': unittest.main()
