"""CPU mocks only: no browser, server, process launch or network."""
import ast
import copy
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
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


D = load(BASE/'handoff_navigation_diagnostics.py', 'handoff_nav_reader_test_subject')
OLD = load(BASE/'navigation_diagnostics.py', 'handoff_nav_old_reader_guard')
R = load(BASE/'run_subscription_ui.py', 'handoff_nav_runner_test_subject')
NATIVE = load(BASE.parent/'probe-readback/run_probe_readback.py', 'handoff_nav_native_decoder')


def observation(engine='chrome-cdp'):
    return dict(schema=D.SCHEMA, sourceCommit=COMMIT, fixtureId=FIXTURE, engine=engine,
        scenario='remote_handoff_negative', scope=D.SCOPE,
        phases=[dict(phase=phase, entered=True, completed=True) for phase in D.PHASES[engine]],
        cause='UNCLASSIFIED', input=dict(kind='CDP_ACK_MASK', mask=7) if engine == 'chrome-cdp'
        else dict(kind='PW_CLICK_RETURN', returned=True),
        journal=dict(available=True, failure=False, counters={key: 0 for key in D.COUNTERS},
                     requests=6, terminal=6, pending=0, captures=6, tasks=0, mutations=0))


def reader(value=None, raw=None):
    if raw is None: raw=json.dumps(observation() if value is None else value).encode('ascii')
    return types.SimpleNamespace(stable_read=mock.Mock(return_value=(raw, object())), decode=NATIVE.decode)


def read(value=None, raw=None, **binding):
    return D.read(binding.get('root',ROOT), binding.get('fixture',FIXTURE),
        binding.get('engine','chrome-cdp'), binding.get('scenario','remote_handoff_negative'),
        binding.get('source_commit',COMMIT), reader(value,raw))


class HandoffNavigationReaderContracts(unittest.TestCase):
    def test_01_schema_is_separate_and_old_reader_remains_closed(self):
        value=observation()
        self.assertEqual(OLD.read(ROOT,FIXTURE,'chrome-cdp','remote_handoff_negative',COMMIT,reader(value)),dict(available=False))
        value['schema']=OLD.SCHEMA
        self.assertEqual(read(value),dict(available=False))
        for scenario in ('create_receipt','remote_fetch','local_admission'):
            self.assertEqual(read(scenario=scenario),dict(available=False))

    def test_02_complete_observations_are_not_acceptance(self):
        for engine in D.PHASES:
            value=observation(engine)
            self.assertEqual(read(value,engine=engine),dict(available=True,observation=value))
            self.assertEqual(value['scope'],'FAILURE_ONLY_PRE_CLEANUP_INSTANT_NOT_ACCEPTANCE')
            self.assertNotIn('productAcceptanceProven',value)

    def test_03_only_derived_private_path_and_original_native_safe_reader(self):
        native=reader(); self.assertTrue(D.read(ROOT,FIXTURE,'chrome-cdp','remote_handoff_negative',COMMIT,native)['available'])
        native.stable_read.assert_called_once_with(ROOT/D.PRIVATE_FILE,8192,10001,0o600)
        for root in (ROOT/'child',PurePosixPath('/tmp/other'),str(ROOT)+'x'):
            self.assertEqual(read(root=root),dict(available=False))
        native=reader(); native.stable_read.side_effect=OSError('PRIVATE_IO_ERROR')
        self.assertEqual(D.read(ROOT,FIXTURE,'chrome-cdp','remote_handoff_negative',COMMIT,native),dict(available=False))

    def test_04_bad_bindings_unknown_fields_and_raw_errors_never_escape(self):
        for field,value in [('fixtureId','c'*32),('sourceCommit','c'*40),('engine','playwright'),('scenario','remote_fetch'),('scope','production'),('schema',OLD.SCHEMA)]:
            item=observation(); item[field]=value
            with self.subTest(field=field): self.assertEqual(read(item),dict(available=False))
        for target in ('root','phase','input','journal','counter'):
            item=observation(); where={'root':item,'phase':item['phases'][0],'input':item['input'],
                'journal':item['journal'],'counter':item['journal']['counters']}[target]
            where['PRIVATE_TOKEN']='PRIVATE_ERROR_STACK'
            self.assertEqual(read(item),dict(available=False))

    def test_05_duplicate_invalid_nonfinite_oversize_bytes_are_unavailable(self):
        for raw in (b'{', b'{}', b'\xff', b'{"schema":"x","schema":"x"}',
                    b'{"value":NaN}', b' '*8193):
            self.assertEqual(read(raw=raw),dict(available=False))

    def test_06_viewport_and_anonymous_rejections_have_exact_prefix(self):
        for index,phase in enumerate(D.PHASES['chrome-cdp']):
            for cause in D.CAUSES[phase]:
                if phase=='INPUT_DISPATCHED' and cause=='PW_CLICK_REJECTED': continue
                value=observation(); value['phases']=value['phases'][:index+1]
                value['phases'][-1]['completed']=False; value['cause']=cause
                if index<D.PHASES['chrome-cdp'].index('INPUT_DISPATCHED'): value['input']=None
                elif phase=='INPUT_DISPATCHED': value['input']['mask']={'INPUT_MOVE_REJECTED':0,'INPUT_PRESS_REJECTED':1,'INPUT_RELEASE_REJECTED':3}[cause]
                with self.subTest(phase=phase,cause=cause): self.assertTrue(read(value)['available'])
                value['cause']='UNCLASSIFIED'; self.assertEqual(read(value),dict(available=False))
        for change in ('skip','two_incomplete','numeric_entered','numeric_complete'):
            value=observation()
            if change=='skip': value['phases'].pop(0)
            elif change=='two_incomplete': value['phases'][0]['completed']=False
            elif change=='numeric_entered': value['phases'][0]['entered']=1
            else: value['phases'][0]['completed']=1
            self.assertEqual(read(value),dict(available=False))

    def test_07_input_acknowledgements_never_imply_missing_actions(self):
        for cause,mask in [('INPUT_MOVE_REJECTED',0),('INPUT_PRESS_REJECTED',1),('INPUT_RELEASE_REJECTED',3)]:
            value=observation(); at=D.PHASES['chrome-cdp'].index('INPUT_DISPATCHED')
            value['phases']=value['phases'][:at+1]; value['phases'][-1]['completed']=False
            value['cause']=cause; value['input']['mask']=mask
            self.assertTrue(read(value)['available'])
            for wrong in (True,2,7):
                bad=copy.deepcopy(value); bad['input']['mask']=wrong; self.assertEqual(read(bad),dict(available=False))
        value=observation('playwright'); at=D.PHASES['playwright'].index('INPUT_DISPATCHED')
        value['phases']=value['phases'][:at+1]; value['phases'][-1]['completed']=False
        value['cause']='PW_CLICK_REJECTED'; value['input']['returned']=False
        self.assertTrue(read(value,engine='playwright')['available'])
        value['input']=dict(kind='CDP_ACK_MASK',mask=7)
        self.assertEqual(read(value,engine='playwright'),dict(available=False))

    def test_08_real_counter_types_request_and_mutation_limits_are_closed(self):
        for name in D.COUNTERS:
            for val in (True,-1,2147483648,'0'):
                value=observation(); value['journal']['counters'][name]=val
                self.assertEqual(read(value),dict(available=False))
        for key,val in [('requests',257),('pending',1),('captures',7),('mutations',11),('tasks',True)]:
            value=observation(); value['journal'][key]=val
            self.assertEqual(read(value),dict(available=False))
        value=observation(); value['journal'].update(requests=256,terminal=250,pending=6,captures=240,tasks=256,mutations=10)
        self.assertTrue(read(value)['available'])
        value['journal']=dict(available=False); self.assertTrue(read(value)['available'])
        value['journal']['counters']={key:0 for key in D.COUNTERS}
        self.assertEqual(read(value),dict(available=False))

    def test_09_json_python_contracts_agree_exactly(self):
        c=json.loads((REPO/'chengwang/tools/subscription-ui-browser/handoff-navigation-diagnostics-contract.json').read_bytes())
        self.assertEqual(c['observationSchema'],D.SCHEMA); self.assertEqual(c['scope'],D.SCOPE)
        self.assertEqual(c['privateFile'],D.PRIVATE_FILE); self.assertEqual(c['maxBytes'],D.MAX_BYTES)
        self.assertEqual(tuple(c['scenarios']),D.SCENARIOS)
        self.assertEqual({k:tuple(v) for k,v in c['phasesByEngine'].items()},D.PHASES)
        self.assertEqual({k:tuple(v) for k,v in c['causesByPhase'].items()},D.CAUSES)
        self.assertEqual(c['maxRequestsByScenario'],D.MAX_REQUESTS); self.assertEqual(c['maxMutationsByScenario'],D.MAX_MUTATIONS)
        self.assertEqual(tuple(c['counterNames']),D.COUNTERS)

    def test_10_runner_projects_only_negative_failure_and_keeps_success_public_sets(self):
        text=(BASE/'run_subscription_ui.py').read_text(encoding='utf-8'); tree=ast.parse(text)
        core_text=(REPO/'chengwang/deploy/browser-scene-supervisor/supervisor.py').read_text(encoding='utf-8')
        core=ast.parse(core_text)

        def expression(value):
            return ast.dump(ast.parse(value,mode='eval').body,include_attributes=False)

        def function(module,name):
            found=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name==name]
            self.assertEqual(len(found),1)
            return found[0]

        def check_flow(runner,shared_tree):
            inner=function(runner,'inner')
            self.assertEqual(len(inner.body),1); self.assertIsInstance(inner.body[0],ast.Return)
            self.assertEqual(ast.dump(inner.body[0].value,include_attributes=False),expression(
                "supervisor(repo).supervise_scene(options, repo, root, bundle, fixture, "
                "'subscription:' + selected_scenario(options), N, M, lifecycle(repo))"))
            loader=function(runner,'supervisor')
            self.assertEqual(len(loader.body),1); self.assertIsInstance(loader.body[0],ast.Return)
            self.assertEqual(ast.dump(loader.body[0].value,include_attributes=False),expression(
                "load_module(repo / 'chengwang/deploy/browser-scene-supervisor/supervisor.py', "
                "'subscription_ui_shared_supervisor')"))
            shared=function(shared_tree,'supervise_scene')
            adapter_loads=[n for n in shared.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='A' for t in n.targets)]
            self.assertEqual(len(adapter_loads),1)
            self.assertEqual(ast.dump(adapter_loads[0].value,include_attributes=False),expression('load_scene_adapter(repo, key)'))
            load_adapter=function(shared_tree,'load_scene_adapter')
            selected=[n.value for n in load_adapter.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='relative' for t in n.targets)]
            self.assertEqual([ast.dump(n,include_attributes=False) for n in selected],
                [expression("LEGACY_PATH if key.startswith('subscription:') else CAPABILITY_PATH")])
            legacy=[n.value.value for n in shared_tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='LEGACY_PATH' for t in n.targets)
                and isinstance(n.value,ast.Constant)]
            self.assertEqual(legacy,['chengwang/deploy/subscription-ui-browser/run_subscription_ui.py'])
            tries=[n for n in shared.body if isinstance(n,ast.Try) and n.finalbody]
            self.assertEqual(len(tries),1)
            failures=[n for n in tries[0].finalbody if isinstance(n,ast.If)
                and ast.dump(n.test,include_attributes=False)==expression('not state.succeeded')]
            self.assertEqual(len(failures),1); failure=failures[0]
            hooks=[n for n in ast.walk(shared_tree) if isinstance(n,ast.Call)
                and ast.dump(n.func,include_attributes=False)==expression('A.scene_failure_diagnostics')]
            self.assertEqual(len(hooks),1)
            assignments=[n for n in failure.body if isinstance(n,ast.Assign) and n.value is hooks[0]]
            self.assertEqual(len(assignments),1)
            self.assertEqual([ast.dump(t,include_attributes=False) for t in assignments[0].targets],
                [ast.dump(ast.Name(id='details',ctx=ast.Store()),include_attributes=False)])
            self.assertEqual(ast.dump(hooks[0],include_attributes=False),
                expression('A.scene_failure_diagnostics(state, options, root, fixture, key, N)'))
            writes=[n.value for n in failure.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
                and ast.dump(n.value.func,include_attributes=False)==expression('N.exclusive')
                and n.value.args and ast.dump(n.value.args[0],include_attributes=False)==expression("options.output_dir / 'failure.json'")]
            self.assertEqual(len(writes),1)
            payloads=[n for n in ast.walk(writes[0].args[1]) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Name) and n.func.id=='dict']
            self.assertEqual(len(payloads),1)
            self.assertEqual([ast.dump(k.value,include_attributes=False) for k in payloads[0].keywords if k.arg is None],[expression('details')])
            self.assertEqual([ast.literal_eval(k.value) for k in payloads[0].keywords if k.arg=='acceptance'],['REJECTED_DIAGNOSTIC_ONLY'])

            adapter=function(runner,'scene_failure_diagnostics')
            calls=[n for n in ast.walk(runner) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                and n.func.attr=='read' and isinstance(n.func.value,ast.Call) and isinstance(n.func.value.func,ast.Name)
                and n.func.value.func.id=='handoff_navigation_diagnostics']
            self.assertEqual(len(calls),1); self.assertIn(calls[0],list(ast.walk(adapter)))
            results=[n for n in adapter.body if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call)
                and any(k.arg=='driverDiagnostics' for k in n.value.keywords)]
            self.assertEqual(len(results),1)
            self.assertEqual([ast.dump(t,include_attributes=False) for t in results[0].targets],
                [ast.dump(ast.Name(id='result',ctx=ast.Store()),include_attributes=False)])
            projection=next(k.value for k in results[0].value.keywords if k.arg=='driverDiagnostics')
            self.assertIsInstance(projection,ast.IfExp)
            self.assertEqual(ast.dump(projection.test,include_attributes=False),expression("scenario == 'remote_handoff_negative'"))
            self.assertIs(projection.body,calls[0])
            self.assertEqual(ast.dump(projection.body,include_attributes=False),expression(
                'handoff_navigation_diagnostics().read(root, fixture, options.engine, scenario, options.source_commit, N)'))
            self.assertEqual(ast.dump(projection.orelse,include_attributes=False),expression(
                'navigation_diagnostics().read(root, fixture, options.engine, scenario, options.source_commit, N)'))
            returns=[n for n in adapter.body if isinstance(n,ast.Return)]
            self.assertEqual(len(returns),1)
            self.assertEqual(ast.dump(returns[0].value,include_attributes=False),expression('result'))
            # Preserve the original lifecycle assertions at their real source:
            # normal node exit and zero forced signals belong to success only.
            waits=[n for n in tries[0].body if isinstance(n,ast.Expr)
                and ast.dump(n.value,include_attributes=False)==expression('need(state.node.wait(timeout=125) == 0)')]
            self.assertEqual(len(waits),1)
            success_writes=[n.value for n in tries[0].body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
                and ast.dump(n.value.func,include_attributes=False)==expression('N.exclusive')
                and n.value.args and ast.dump(n.value.args[0],include_attributes=False)==expression("options.output_dir / 'processes.json'")]
            self.assertEqual(len(success_writes),1)
            self.assertEqual([ast.literal_eval(n.value) for n in ast.walk(success_writes[0])
                if isinstance(n,ast.keyword) and n.arg=='forcedSignals'],[0])
            return shared,failure,assignments[0],projection,payloads[0]

        check_flow(tree,core)
        # Real AST counterexamples remain within this original named case.
        moved=ast.parse(core_text); shared,failure,assignment,_,_=check_flow(tree,moved)
        failure.body.remove(assignment); shared.body.insert(0,assignment)
        with self.assertRaises(AssertionError): check_flow(tree,moved)
        wrong=ast.parse(text); _,_,_,projection,_=check_flow(wrong,core)
        projection.test=ast.Constant(value=True)
        with self.assertRaises(AssertionError): check_flow(wrong,core)
        dropped=ast.parse(core_text); _,_,_,_,payload=check_flow(tree,dropped)
        next(k for k in payload.keywords if k.arg is None).value=ast.Dict(keys=[],values=[])
        with self.assertRaises(AssertionError): check_flow(tree,dropped)
        self.assertIn('chengwang/deploy/subscription-ui-browser/handoff_navigation_diagnostics.py',R.HANDOFF_SOURCE_FILES)
        expected={'driver.json','captures.jsonl','dom.jsonl','created-desktop.png','created-mobile.png','processes.json',
            'isolation.json','inputs.json','certificates.json','pin-consumption.json','private-readback.json',
            'audit-events.jsonl','audit-checkpoint.json','build.json'}
        self.assertEqual(R.PUBLIC,expected); self.assertEqual(R.HANDOFF_PUBLIC,R.REMOTE_PUBLIC|{'api-sampler.jsonl'})
        self.assertNotIn(D.PRIVATE_FILE,R.HANDOFF_PUBLIC)


if __name__=='__main__': unittest.main(verbosity=2)
