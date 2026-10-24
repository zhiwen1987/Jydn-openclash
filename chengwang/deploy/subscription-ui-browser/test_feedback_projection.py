"""Pure CPU forged projection counterexamples, not runtime feedback evidence."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest

import feedback_projection as P


def packed(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')


def fixture():
    observations = []; dom = []
    for ordinal, step in enumerate(P.CONTRACT['steps'], 1):
        expected = copy.deepcopy(P.CONTRACT['expected'][step])
        row = dict(schema='chengwang.handoff-negative-ui-dom-capture/v1',ordinal=ordinal,step=step,
            dom=dict(pageVisible=step != 'hidden',alertVisible=expected['alertVisible']))
        raw = packed(row) + b'\n'; dom.append(raw)
        observations.append(dict(schema=P.CONTRACT['observationSchema'],ordinal=ordinal,step=step,
            domRowSHA256=hashlib.sha256(raw).hexdigest(),**expected))
    return observations, dom


def evidence(observations=None, dom=None):
    original, original_dom = fixture()
    values = original if observations is None else observations
    rows = original_dom if dom is None else dom
    return b''.join(P.PREFIX + packed(value) + b'\n' for value in values), b''.join(rows)


class FeedbackProjectionContracts(unittest.TestCase):
    def test_01_complete_exact_projection_is_unchanged(self):
        raw, dom = evidence(); self.assertEqual(P.project(raw,dom),raw)

    def test_02_private_noise_is_not_exported(self):
        raw, dom = evidence(); private = b'PRIVATE-CANARY-DO-NOT-EXPORT\n' + raw + b'UNSAFE-END\n'
        self.assertEqual(P.project(private,dom,allow_noise=True),raw)
        with self.assertRaises(ValueError): P.project(private,dom)

    def test_03_partial_duplicate_and_extra_stages_rejected(self):
        rows, dom = fixture()
        for values in (rows[:-1], rows + rows[:1], rows[:20] + rows[19:]):
            with self.subTest(count=len(values)), self.assertRaises(ValueError): P.project(*evidence(values,dom))

    def test_04_reordered_stage_and_ordinal_rejected(self):
        rows, dom = fixture(); rows[1],rows[2] = rows[2],rows[1]
        with self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_05_boolean_ordinal_and_visibility_not_integers(self):
        for field in ('ordinal','statusVisible','alertVisible'):
            rows, dom = fixture(); rows[0][field] = True if field == 'ordinal' else 0
            with self.subTest(field=field), self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_06_unknown_status_alert_and_private_fields_rejected(self):
        for patch in (dict(status='PRIVATE-STATUS'),dict(alert='PRIVATE-ALERT'),dict(rawText='PRIVATE-CANARY')):
            rows,dom=fixture(); rows[0].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_07_known_rejection_cannot_remain_waiting(self):
        rows,dom=fixture()
        for index,row in enumerate(rows):
            if row['step'].endswith('_failed') and row['alert'] == 'CONFLICT':
                wrong=copy.deepcopy(rows); wrong[index].update(status='WAITING',statusVisible=True)
                with self.subTest(step=row['step']), self.assertRaises(ValueError): P.project(*evidence(wrong,dom))

    def test_08_conflict_and_forbidden_are_not_interchangeable(self):
        rows,dom=fixture(); row=next(value for value in rows if value['step']=='cross_owner_denied'); row['alert']='CONFLICT'
        with self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_09_hash_binds_exact_dom_row_including_lf(self):
        rows,dom=fixture(); rows[0]['domRowSHA256']=hashlib.sha256(dom[0][:-1]).hexdigest()
        with self.assertRaises(ValueError): P.project(*evidence(rows,dom))
        rows,dom=fixture(); dom[0]=dom[0][:-1]+b' \n'
        with self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_10_dom_stage_order_and_schema_are_bound(self):
        for patch in (dict(ordinal=True),dict(step='other'),dict(schema='other')):
            rows,dom=fixture(); value=json.loads(dom[0]); value.update(patch); dom[0]=packed(value)+b'\n'
            rows[0]['domRowSHA256']=hashlib.sha256(dom[0]).hexdigest()
            with self.subTest(patch=patch), self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_11_dom_alert_and_hidden_visibility_are_cross_bound(self):
        for field in ('alertVisible','pageVisible'):
            rows,dom=fixture(); index=46 if field=='pageVisible' else 17; value=json.loads(dom[index])
            value['dom'][field]=not value['dom'][field]; dom[index]=packed(value)+b'\n'
            rows[index]['domRowSHA256']=hashlib.sha256(dom[index]).hexdigest()
            with self.subTest(field=field), self.assertRaises(ValueError): P.project(*evidence(rows,dom))

    def test_12_duplicate_json_key_noncanonical_escape_and_crlf_rejected(self):
        raw,dom=evidence(); prefix=P.PREFIX
        variants=(raw.replace(b'{"schema":',b'{"ordinal":1,"schema":',1),
            raw.replace(b'"ordinal":',b'"ord\\u0069nal":',1),raw.replace(b'\n',b'\r\n',1))
        for wrong in variants:
            with self.subTest(raw=wrong[:30]), self.assertRaises(ValueError): P.project(wrong,dom)
        self.assertTrue(raw.startswith(prefix))

    def test_13_embedded_marker_cannot_be_silently_ignored(self):
        raw,dom=evidence()
        for extra in (b'PRIVATE '+P.PREFIX+b'{}\n',P.PREFIX+b'{}\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError): P.project(extra+raw,dom,allow_noise=True)

    def test_14_limits_types_and_terminated_lines_are_required(self):
        raw,dom=evidence()
        for wrong,rows in ((b'',dom),(raw,b''),(raw[:-1],dom),(raw,dom[:-1]),(b'x'*(65537)+b'\n',dom)):
            with self.subTest(length=len(wrong)), self.assertRaises(ValueError): P.project(wrong,rows)
        with self.assertRaises(ValueError): P.project(raw,dom,allow_noise=1)
        with self.assertRaises(ValueError): P.project(raw.decode(),dom)

    def test_15_raw_rendered_text_and_failure_markers_are_never_returned(self):
        raw,dom=evidence(); value=P.project(b'PRIVATE NOTICE\nFAILURE DIAGNOSTIC\n'+raw,dom,allow_noise=True)
        self.assertNotIn(b'PRIVATE',value); self.assertNotIn(b'FAILURE',value)
        self.assertEqual(len(value.splitlines()),49)
        with self.assertRaises(ValueError): P.project(b'FAILURE ONLY\n',dom,allow_noise=True)

    def test_16_runner_publishes_only_after_success_and_old_file_set_closes(self):
        # Follow the fixed wrapper -> common supervisor -> legacy hooks. Merely
        # finding safety strings in unrelated/dead functions cannot satisfy the
        # order assertions or either hook's complete source-only AST contract.
        source=Path(__file__).with_name('run_subscription_ui.py').read_text(encoding='utf-8')
        common=(Path(__file__).parents[1]/'browser-scene-supervisor/supervisor.py').read_text(encoding='utf-8')
        tree, core=ast.parse(source), ast.parse(common)
        def shape(node): return ast.dump(node,include_attributes=False)
        def expression(value): return ast.parse(value,mode='eval').body
        def statement(value): return ast.parse(value).body[0]
        def one(values):
            values=list(values); self.assertEqual(len(values),1); return values[0]
        def function(module,name):
            return one(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name==name)
        def matching(values,expected):
            return one(node for node in values if shape(node)==shape(expected))
        def call_statement(values,value): return matching(values,statement(value))
        def assert_architecture(legacy,shared):
            inner,main=function(legacy,'inner'),function(legacy,'main')
            self.assertEqual(shape(inner.body[0]),shape(statement(
                "return supervisor(repo).supervise_scene(options, repo, root, bundle, fixture, 'subscription:' + selected_scenario(options), N, M, lifecycle(repo))")))
            self.assertEqual(len(inner.body),1)
            self.assertEqual(shape(main.body[-1]),shape(statement(
                "return supervisor(repo).run_scene_outer(options, repo, root, bundle, fixture, 'subscription:' + selected_scenario(options), N, M, L)")))
            matching(main.body,statement('if options.inner: inner(options, repo, root, bundle, fixture, N, M); return'))
            self.assertEqual(shape(function(legacy,'supervisor').body[0]),shape(statement(
                "return load_module(repo / 'chengwang/deploy/browser-scene-supervisor/supervisor.py', 'subscription_ui_shared_supervisor')")))
            matching(shared.body,statement("LEGACY_PATH = 'chengwang/deploy/subscription-ui-browser/run_subscription_ui.py'"))
            loader=function(shared,'load_scene_adapter')
            matching(loader.body,statement("relative = LEGACY_PATH if key.startswith('subscription:') else CAPABILITY_PATH"))
            inner_core,outer_core=function(shared,'supervise_scene'),function(shared,'run_scene_outer')
            for body in (inner_core.body,outer_core.body):
                matching(body,statement('A = load_scene_adapter(repo, key)'))
            inner_try=one(node for node in inner_core.body if isinstance(node,ast.Try))
            outer_try=one(node for node in outer_core.body if isinstance(node,ast.Try))
            export_stage=matching(inner_try.body,statement("state.stage = 'EXPORT'"))
            export=call_statement(inner_try.body,'export_scene_evidence(options, root, key, N)')
            inner_hook=call_statement(inner_try.body,'A.scene_inner_success(state, options, root, fixture, key, N)')
            succeeded=matching(inner_try.body,statement('state.succeeded = True'))
            self.assertLess(inner_try.body.index(export_stage),inner_try.body.index(export))
            self.assertLess(inner_try.body.index(export),inner_try.body.index(inner_hook))
            self.assertLess(inner_try.body.index(inner_hook),inner_try.body.index(succeeded))
            for value in ('need(state.node.wait(timeout=125) == 0)',
                          'need(M.no_owned_processes() and all(not pathlib.Path("/proc", str(row["pid"])).exists() for row in state.records))'):
                self.assertLess(inner_try.body.index(call_statement(inner_try.body,value)),inner_try.body.index(export))
            before=matching(outer_core.body,statement('before, source_before = N.host_observation(repo, options.source_commit)'))
            self.assertLess(outer_core.body.index(before),outer_core.body.index(outer_try))
            after=matching(outer_try.body,statement('after, source_after = N.host_observation(repo, options.source_commit)'))
            stable=call_statement(outer_try.body,'need(before == after and source_before == source_after)')
            closed=call_statement(outer_try.body,'need({path.name for path in options.output_dir.iterdir()} == A.scene_public_files(key, options))')
            outer_hook=call_statement(outer_try.body,'A.scene_outer_success(options, root, bundle, fixture, key, N)')
            failure=one(node for node in outer_try.body if isinstance(node,ast.If) and
                        shape(node.test)==shape(expression('child.returncode != 0 or timed_out')))
            self.assertEqual(shape(failure.body[-1]),shape(statement('need(False)')))
            self.assertLess(outer_try.body.index(after),outer_try.body.index(stable))
            self.assertLess(outer_try.body.index(stable),outer_try.body.index(failure))
            self.assertLess(outer_try.body.index(failure),outer_try.body.index(closed))
            self.assertLess(outer_try.body.index(closed),outer_try.body.index(outer_hook))
            matching(outer_try.body,statement("entry = LEGACY_PATH if key.startswith('subscription:') else CAPABILITY_ENTRY"))
            public=function(legacy,'scene_public_files')
            self.assertEqual(shape(public.body[-1]),shape(statement(
                "return set(HANDOFF_PUBLIC if options.scenario == 'remote_handoff_negative' else REMOTE_PUBLIC if options.scenario == 'remote_fetch' else PUBLIC)")))
            self.assertEqual(shape(function(legacy,'feedback_projection').body[0]),shape(statement(
                "return load_module(pathlib.Path(__file__).with_name('feedback_projection.py'), 'subscription_ui_feedback_projection')")))
            expected_inner=ast.parse('''def expected():
    if _scene_scenario(key) != 'remote_handoff_negative': return
    state.stage = 'FEEDBACK_PROJECTION'
    safe_feedback = feedback_projection().project(N.stable_read(root / 'driver.private.log', 32 << 20, 0, 0o600)[0], N.stable_read(options.output_dir / 'dom.jsonl', 1 << 20, 0, 0o644)[0], allow_noise=True)
    print(safe_feedback.decode('ascii'), end='', flush=True)
''').body[0]
            expected_outer=ast.parse('''def expected():
    if _scene_scenario(key) == 'remote_handoff_negative':
        safe_feedback = feedback_projection().project(N.stable_read(bundle / 'supervisor.private.log', 65536, 0, 0o600)[0], N.stable_read(options.output_dir / 'dom.jsonl', 1 << 20, 0, 0o644)[0], allow_noise=False)
        print(safe_feedback.decode('ascii'), end='', flush=True)
    print('SUBSCRIPTION_UI=CAPTURED independent_verification=pending production=false full_subscription_e2e=false')
''').body[0]
            for name,expected in (('scene_inner_success',expected_inner),('scene_outer_success',expected_outer)):
                self.assertEqual([shape(n) for n in function(legacy,name).body],[shape(n) for n in expected.body])
            logs=[]
            for body,path,spawn_target in ((inner_try.body,"(root / 'driver.private.log').open('xb')",'state.node'),
                                           (outer_try.body,"(bundle / 'supervisor.private.log').open('xb')",'child')):
                log=one(n for n in body if isinstance(n,ast.With) and len(n.items)==1 and shape(n.items[0].context_expr)==shape(expression(path)))
                self.assertEqual(shape(log.items[0].optional_vars),shape(ast.Name(id='log',ctx=ast.Store())))
                chmod=one(n for n in log.body if isinstance(n,ast.If) and shape(n.test)==shape(expression("key == 'subscription:remote_handoff_negative'")))
                self.assertEqual([shape(n) for n in chmod.body],[shape(statement('os.fchmod(log.fileno(), 0o600)'))])
                spawn=one(n for n in log.body if isinstance(n,ast.Assign) and len(n.targets)==1 and shape(n.targets[0])==shape(ast.parse(spawn_target+' = None').body[0].targets[0]))
                self.assertLess(log.body.index(chmod),log.body.index(spawn)); logs.append(chmod)
                self.assertIsInstance(spawn.value,ast.Call)
                self.assertEqual(shape(spawn.value.func),shape(expression('subprocess.Popen')))
                keywords={k.arg:k.value for k in spawn.value.keywords}
                for key in ('stdout','stderr'): self.assertEqual(shape(keywords[key]),shape(expression('log')))
            exporter=function(shared,'export_scene_evidence')
            self.assertEqual([n.arg for n in exporter.args.kwonlyargs],['partial'])
            self.assertEqual([ast.literal_eval(n) for n in exporter.args.kw_defaults],[False])
            loop=one(n for n in exporter.body if isinstance(n,ast.For))
            checked=one(n for n in loop.body if isinstance(n,ast.Try))
            fence=call_statement(checked.body,'A.scene_fence_public(raw, public, forbidden, key, N, partial)')
            publish=call_statement(checked.body,'N.exclusive(target, raw)')
            self.assertLess(checked.body.index(fence),checked.body.index(publish))
            self.assertEqual(shape(function(legacy,'scene_fence_public').body[0]),shape(statement(
                "public_fence(raw, forbidden, captures=(public_name == 'captures.jsonl'), N=N, scenario=_scene_scenario(key))")))
            self.assertEqual(shape(function(legacy,'public_fence').body[0]),shape(statement(
                "need(type(raw) is bytes and raw and b'PRIVATE KEY' not in raw and not any(secret in raw for secret in forbidden))")))
            self.assertNotIn('feedback-observations.json',ast.unparse(legacy))
            self.assertNotIn('feedback-observations.json',ast.unparse(shared))
            return inner_try,outer_try,inner_hook,outer_hook,export,closed,stable,failure,logs,checked,fence

        assert_architecture(tree,core)
        # Mutation counterexamples exercise this guard itself without executing
        # any supervisor, production API, process launcher or browser.
        for mutation in ('early_inner','early_outer','missing_closed_set','missing_host_check','ignored_timeout',
                         'public_driver_log','unfenced_export','partial_export','inner_noise','outer_noise','dom_mode','raw_print','wrong_wrapper'):
            wrong_legacy,wrong_core=copy.deepcopy(tree),copy.deepcopy(core)
            inside,outside,inner_hook,outer_hook,export,closed,stable,failure,logs,checked,fence=assert_architecture(wrong_legacy,wrong_core)
            if mutation=='early_inner': inside.body.remove(inner_hook); inside.body.insert(inside.body.index(export),inner_hook)
            elif mutation=='early_outer': outside.body.remove(outer_hook); outside.body.insert(outside.body.index(stable),outer_hook)
            elif mutation=='missing_closed_set': outside.body.remove(closed)
            elif mutation=='missing_host_check': outside.body.remove(stable)
            elif mutation=='ignored_timeout': failure.test=expression('child.returncode != 0')
            elif mutation=='public_driver_log': logs[0].body[0].value.args[-1]=ast.Constant(value=0o644)
            elif mutation=='unfenced_export': checked.body.remove(fence)
            elif mutation=='partial_export': function(wrong_core,'export_scene_evidence').args.kw_defaults[0]=ast.Constant(value=True)
            elif mutation in ('inner_noise','outer_noise','dom_mode','raw_print'):
                hook=function(wrong_legacy,'scene_inner_success' if mutation=='inner_noise' else 'scene_outer_success')
                if mutation=='raw_print': hook.body.insert(0,statement("print('PRIVATE LOG')"))
                else:
                    projection=one(n for n in ast.walk(hook) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='project')
                    if mutation=='dom_mode': projection.args[1].value.args[-1]=ast.Constant(value=0o600)
                    else: projection.keywords[0].value=ast.Constant(value=mutation!='inner_noise')
            else: function(wrong_legacy,'inner').body[0].value.func.attr='run_scene_outer'
            with self.subTest(mutation=mutation),self.assertRaises(AssertionError): assert_architecture(wrong_legacy,wrong_core)
        native=Path(__file__).parents[1]/'probe-readback/run_probe_readback.py'
        native_tree=ast.parse(native.read_bytes())
        exclusive=next(node for node in native_tree.body if isinstance(node,ast.FunctionDef) and node.name=='exclusive')
        self.assertEqual(ast.literal_eval(exclusive.args.defaults[-1]),0o644)
        matching(ast.walk(exclusive),expression('os.fchmod(fd, mode)'))


if __name__ == '__main__': unittest.main()
