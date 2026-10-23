"""Pure mock/AST contracts; no process, browser, network or system writes."""
import ast
import importlib.util
import json
from pathlib import Path, PurePosixPath
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[2]
FIXTURE = 'a' * 32
COMMIT = 'b' * 40
ROOT = PurePosixPath('/tmp/chengwang-subscription-ui-' + FIXTURE)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = load(BASE / 'navigation_diagnostics.py', 'navigation_diagnostics_test_subject')
R = load(BASE / 'run_subscription_ui.py', 'navigation_diagnostics_runner_subject')
NATIVE = load(BASE.parent / 'probe-readback/run_probe_readback.py', 'navigation_diagnostics_native_decoder')


def observation(engine='chrome-cdp', scenario='remote_fetch'):
    return dict(schema=D.SCHEMA, sourceCommit=COMMIT, fixtureId=FIXTURE, engine=engine,
        scenario=scenario, scope=D.SCOPE, phases=[dict(phase=phase, entered=True, completed=True)
            for phase in D.PHASES[engine]], cause='UNCLASSIFIED',
        input=dict(kind='CDP_ACK_MASK', mask=7) if engine == 'chrome-cdp' else dict(kind='PW_CLICK_RETURN', returned=True),
        journal=dict(available=True, failure=False, counters={key: 0 for key in D.COUNTERS},
                     requests=6, terminal=6, pending=0, captures=6, tasks=0, mutations=0))


def reader(value=None, raw=None):
    if raw is None:
        raw = json.dumps(observation() if value is None else value).encode('ascii')
    return types.SimpleNamespace(stable_read=mock.Mock(return_value=(raw, object())), decode=NATIVE.decode)


def read(value=None, raw=None, **bindings):
    return D.read(bindings.get('root', ROOT), bindings.get('fixture', FIXTURE),
        bindings.get('engine', 'chrome-cdp'), bindings.get('scenario', 'remote_fetch'),
        bindings.get('source_commit', COMMIT), reader(value, raw))


class NavigationDiagnosticsContracts(unittest.TestCase):
    def test_complete_cdp_observation_is_available(self):
        for scenario in D.SCENARIOS:
            value = observation(scenario=scenario)
            self.assertEqual(read(value, scenario=scenario), dict(available=True, observation=value))

    def test_partial_pw_and_missing_journal_are_observed_not_zero_filled(self):
        value = observation('playwright')
        value['phases'] = value['phases'][:4]
        value['phases'][-1]['completed'] = False
        value['cause'] = 'PW_CLICK_REJECTED'
        value['input']['returned'] = False
        value['journal'] = dict(available=False)
        self.assertEqual(read(value, engine='playwright'), dict(available=True, observation=value))
        value.update(phases=[], cause='UNCLASSIFIED', input=None)
        self.assertEqual(read(value, engine='playwright')['observation']['journal'], dict(available=False))

    def test_missing_or_unsafe_private_file_is_unavailable(self):
        for error in (FileNotFoundError('private'), PermissionError('private'), ValueError('unsafe'), OSError('race')):
            native = reader()
            native.stable_read.side_effect = error
            with self.subTest(kind=type(error).__name__):
                self.assertEqual(D.read(ROOT, FIXTURE, 'chrome-cdp', 'remote_fetch', COMMIT, native), dict(available=False))

    def test_reader_uses_only_derived_bounded_owner_mode_path(self):
        native = reader()
        self.assertTrue(D.read(ROOT, FIXTURE, 'chrome-cdp', 'remote_fetch', COMMIT, native)['available'])
        native.stable_read.assert_called_once_with(ROOT / D.PRIVATE_FILE, 8192, 10001, 0o600)
        for root in (PurePosixPath('/tmp/other'), PurePosixPath(str(ROOT) + '/../other')):
            native.stable_read.reset_mock()
            self.assertEqual(D.read(root, FIXTURE, 'chrome-cdp', 'remote_fetch', COMMIT, native), dict(available=False))
            native.stable_read.assert_not_called()
        for raw in (b'', b'x' * 8193, 'not-bytes'):
            self.assertEqual(read(raw=raw), dict(available=False))

    def test_all_identity_and_scope_fields_are_bound(self):
        for key, replacement in [('schema', 'unknown'), ('scope', 'ACCEPTED'), ('fixtureId', 'c' * 32),
                ('sourceCommit', 'c' * 40), ('engine', 'playwright'), ('scenario', 'create_receipt')]:
            value = observation(); value[key] = replacement
            with self.subTest(field=key): self.assertEqual(read(value), dict(available=False))
        for binding in (dict(fixture='../secret'), dict(source_commit='HEAD'), dict(engine='unknown'),
                        dict(scenario='local_admission')):
            self.assertEqual(read(**binding), dict(available=False))

    def test_unknown_and_missing_fields_are_not_projected(self):
        for container in ('root', 'phase', 'input', 'journal', 'counter'):
            value = observation()
            target = {'root': value, 'phase': value['phases'][0], 'input': value['input'],
                      'journal': value['journal'], 'counter': value['journal']['counters']}[container]
            target['unknown'] = 'PRIVATE-CANARY'
            self.assertEqual(read(value), dict(available=False))
        for key in D.OBSERVATION_KEYS:
            value = observation(); del value[key]
            self.assertEqual(read(value), dict(available=False))
        for value in (None, [], 0, True):
            self.assertEqual(read(raw=json.dumps(value).encode()), dict(available=False))

    def test_invalid_duplicate_and_nonfinite_json_are_unavailable(self):
        for raw in (b'{', b'\xff', b'{"schema":1,"schema":2}', b'{"value":NaN}', b'{"value":Infinity}'):
            self.assertEqual(read(raw=raw), dict(available=False))

    def test_phases_must_be_an_exact_engine_entered_prefix(self):
        variants = []
        value = observation(); value['phases'][0]['phase'] = 'READY'; variants.append(value)
        value = observation(); value['phases'][1]['phase'] = 'NAVIGATE_RETURN'; variants.append(value)
        value = observation(); value['phases'][0]['entered'] = False; variants.append(value)
        value = observation(); value['phases'][0]['entered'] = 1; variants.append(value)
        value = observation(); value['phases'][0]['completed'] = 1; variants.append(value)
        value = observation(); value['phases'].append(dict(value['phases'][-1])); variants.append(value)
        value = observation(); value['phases'] = {}; variants.append(value)
        for value in variants: self.assertEqual(read(value), dict(available=False))

    def test_only_last_phase_can_fail_and_cause_belongs_to_it(self):
        for phase in D.PHASES['chrome-cdp']:
            if phase == 'INPUT_DISPATCHED': continue
            value = observation(); index = D.PHASES['chrome-cdp'].index(phase)
            value['phases'] = value['phases'][:index + 1]
            value['phases'][-1]['completed'] = False
            value['cause'] = D.CAUSES[phase][0]
            if index < D.PHASES['chrome-cdp'].index('INPUT_DISPATCHED'): value['input'] = None
            self.assertTrue(read(value)['available'])
            value['cause'] = 'UNCLASSIFIED'; self.assertEqual(read(value), dict(available=False))
        value = observation(); value['phases'][0]['completed'] = False
        self.assertEqual(read(value), dict(available=False))
        value = observation(); value['cause'] = 'TLS_PROOF_REJECTED'
        self.assertEqual(read(value), dict(available=False))

    def test_input_acknowledgements_and_engine_cause_are_exact(self):
        for cause, mask in [('INPUT_MOVE_REJECTED', 0), ('INPUT_PRESS_REJECTED', 1), ('INPUT_RELEASE_REJECTED', 3)]:
            value = observation(); value['phases'] = value['phases'][:5]
            value['phases'][-1]['completed'] = False; value['cause'] = cause; value['input']['mask'] = mask
            self.assertTrue(read(value)['available'])
            value['input']['mask'] = 7; self.assertEqual(read(value), dict(available=False))
        for input_value in (None, dict(kind='CDP_ACK_MASK', mask=True), dict(kind='CDP_ACK_MASK', mask=2),
                            dict(kind='CDP_ACK_MASK', mask=3), dict(kind='PW_CLICK_RETURN', returned=True)):
            value = observation(); value['input'] = input_value
            self.assertEqual(read(value), dict(available=False))
        value = observation(); value['phases'] = value['phases'][:2]; value['input'] = dict(kind='CDP_ACK_MASK', mask=0)
        self.assertEqual(read(value), dict(available=False))
        value = observation('playwright'); value['input']['returned'] = False
        self.assertEqual(read(value, engine='playwright'), dict(available=False))
        value = observation(); value['phases'] = value['phases'][:5]; value['phases'][-1]['completed'] = False
        value.update(cause='PW_CLICK_REJECTED', input=dict(kind='CDP_ACK_MASK', mask=0))
        self.assertEqual(read(value), dict(available=False))

    def test_journal_counter_shape_types_and_bounds_are_closed(self):
        for invalid in (False, -1, 2147483648, 1.0, None, 'private'):
            value = observation(); value['journal']['counters']['captureErrors'] = invalid
            self.assertEqual(read(value), dict(available=False))
        for field in ('available', 'failure'):
            value = observation(); value['journal'][field] = 1
            self.assertEqual(read(value), dict(available=False))
        value = observation(); value['journal'] = dict(available=False, counters={})
        self.assertEqual(read(value), dict(available=False))
        value = observation(); value['journal']['counters'] = []
        self.assertEqual(read(value), dict(available=False))

    def test_journal_request_bounds_and_instant_relations_are_exact(self):
        for key in ('requests', 'terminal', 'pending', 'captures', 'tasks', 'mutations'):
            for invalid in (True, -1, 257, 0.5):
                value = observation(); value['journal'][key] = invalid
                self.assertEqual(read(value), dict(available=False))
        for patch in (dict(requests=7), dict(captures=7), dict(mutations=5), dict(requests=0, terminal=0, captures=0, mutations=1)):
            value = observation(); value['journal'].update(patch)
            self.assertEqual(read(value), dict(available=False))
        value = observation(scenario='create_receipt'); value['journal'].update(requests=65, terminal=65, captures=65)
        self.assertEqual(read(value, scenario='create_receipt'), dict(available=False))
        value = observation(); value['journal'].update(requests=256, terminal=250, pending=6, captures=240, tasks=256, mutations=4)
        value['journal']['counters']['captureErrors'] = 2147483647
        self.assertTrue(read(value)['available'])

    def test_private_canaries_and_exception_text_never_escape_unavailable(self):
        secret = 'PRIVATE-CANARY-TOKEN-HEADER-DOM-EXCEPTION'
        native = reader(); native.stable_read.side_effect = ValueError(secret)
        result = D.read(ROOT, FIXTURE, 'chrome-cdp', 'remote_fetch', COMMIT, native)
        self.assertEqual(result, dict(available=False)); self.assertNotIn(secret, json.dumps(result))
        for key in ('cause', 'scope', 'sourceCommit'):
            value = observation(); value[key] = secret
            self.assertEqual(read(value), dict(available=False))

    def test_constants_match_the_frozen_browser_contract(self):
        contract = json.loads((REPO / 'chengwang/tools/subscription-ui-browser/navigation-diagnostics-contract.json').read_bytes())
        self.assertEqual((contract['observationSchema'], contract['scope'], contract['privateFile'], contract['maxBytes'],
                          contract['uid'], contract['mode']), (D.SCHEMA, D.SCOPE, D.PRIVATE_FILE, D.MAX_BYTES, D.UID, D.MODE))
        self.assertEqual(tuple(contract['scenarios']), D.SCENARIOS)
        self.assertEqual(set(contract['observationKeys']), D.OBSERVATION_KEYS)
        self.assertEqual(set(contract['phaseKeys']), D.PHASE_KEYS)
        self.assertEqual({key: tuple(value) for key, value in contract['phasesByEngine'].items()}, D.PHASES)
        self.assertEqual({key: tuple(value) for key, value in contract['causesByPhase'].items()}, D.CAUSES)
        self.assertEqual(tuple(contract['counterNames']), D.COUNTERS)
        self.assertEqual(set(contract['journalAvailableKeys']), D.JOURNAL_KEYS)
        self.assertEqual(contract['maxCounter'], D.MAX_COUNTER)
        self.assertEqual(contract['maxRequestsByScenario'], D.MAX_REQUESTS)
        self.assertEqual(contract['maxMutationsByScenario'], D.MAX_MUTATIONS)

    def test_runner_copies_helper_and_projects_only_inside_failure_finally(self):
        self.assertIn('chengwang/deploy/subscription-ui-browser/navigation_diagnostics.py', R.SOURCE_FILES)
        tree = ast.parse((BASE / 'run_subscription_ui.py').read_text(encoding='utf-8'))
        inner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inner')
        diagnostic_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                            and any(key.arg == 'driverDiagnostics' for key in node.keywords)]
        self.assertEqual(len(diagnostic_calls), 1)
        final = next(node.finalbody for node in ast.walk(inner) if isinstance(node, ast.Try) and node.finalbody)
        failure = next(node for node in final if isinstance(node, ast.If)
                       and isinstance(node.test, ast.UnaryOp) and isinstance(node.test.operand, ast.Name)
                       and node.test.operand.id == 'succeeded')
        self.assertIn(diagnostic_calls[0], list(ast.walk(failure)))
        self.assertIn("options.output_dir / 'failure.json'", ast.get_source_segment(
            (BASE / 'run_subscription_ui.py').read_text(encoding='utf-8'), failure))
        # The original directory is root-owned 0700 until the final artifact
        # ownership step. A plain test/python would silently skip diagnosis.
        workflow = (BASE.parents[2] / '.github/workflows/chengwang-subscription-ui-browser.yml').read_text(encoding='utf-8')
        self.assertIn('if sudo --non-interactive test -f "$reports/originals/failure.json"; then', workflow)
        self.assertIn('sudo --non-interactive /usr/bin/python3 -I -B chengwang/deploy/subscription-ui-browser/check_navigation_diagnostics.py', workflow)
        self.assertNotIn('if test -f "$reports/originals/failure.json"; then', workflow)

    def test_success_public_sets_remain_exact_and_diagnostics_are_not_acceptance(self):
        expected = {'driver.json', 'captures.jsonl', 'dom.jsonl', 'created-desktop.png', 'created-mobile.png',
            'processes.json', 'isolation.json', 'inputs.json', 'certificates.json', 'pin-consumption.json',
            'private-readback.json', 'audit-events.jsonl', 'audit-checkpoint.json', 'build.json'}
        self.assertEqual(R.PUBLIC, expected)
        self.assertEqual(R.REMOTE_PUBLIC, expected | {'wire-ready.json', 'wire-events.jsonl', 'wire-stopped.json',
            'resolver-ca.pem', 'resolver-leaf.pem', 'source-ca.pem', 'source-leaf.pem'})
        self.assertNotIn(D.PRIVATE_FILE, R.PUBLIC | R.REMOTE_PUBLIC)
        self.assertEqual(D.SCOPE, 'FAILURE_ONLY_PRE_CLEANUP_INSTANT_NOT_ACCEPTANCE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
