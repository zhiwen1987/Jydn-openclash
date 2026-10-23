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
        source=Path(__file__).with_name('run_subscription_ui.py').read_text(encoding='utf-8'); tree=ast.parse(source)
        inner=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='inner')
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        inner_text=ast.get_source_segment(source,inner); main_text=ast.get_source_segment(source,main)
        self.assertLess(inner_text.index("stage = 'EXPORT'"),inner_text.index('allow_noise=True'))
        self.assertLess(main_text.index('before == after and source_before == source_after'),main_text.index('allow_noise=False'))
        self.assertLess(main_text.index('HANDOFF_PUBLIC if options.scenario'),main_text.index('allow_noise=False'))
        self.assertLess(main_text.index('allow_noise=False'),main_text.index('SUBSCRIPTION_UI=CAPTURED'))
        self.assertIn('child.returncode != 0 or timed_out',main_text)
        self.assertIn("N.stable_read(root / 'driver.private.log', 32 << 20, 0, 0o600)",inner_text)
        self.assertIn("N.stable_read(bundle / 'supervisor.private.log', 65536, 0, 0o600)",main_text)
        self.assertIn('os.fchmod(log.fileno(), 0o600)',inner_text)
        self.assertIn('os.fchmod(log.fileno(), 0o600)',main_text)
        for text in (inner_text,main_text):
            self.assertIn("N.stable_read(options.output_dir / 'dom.jsonl', 1 << 20, 0, 0o644)",text)
        native=Path(__file__).parents[1]/'probe-readback/run_probe_readback.py'
        native_tree=ast.parse(native.read_bytes())
        exclusive=next(node for node in native_tree.body if isinstance(node,ast.FunctionDef) and node.name=='exclusive')
        self.assertEqual(ast.literal_eval(exclusive.args.defaults[-1]),0o644)
        self.assertIn('os.fchmod(fd, mode)',ast.get_source_segment(native.read_text(encoding='utf-8'),exclusive))
        self.assertNotIn('feedback-observations.json',source)


if __name__ == '__main__': unittest.main()
