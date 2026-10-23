"""Frozen regressions for observed native records, never browser acceptance."""
import ast
import copy
import hashlib
import pathlib
import unittest

import check_matrix as M
from test_check_matrix import network_fixture, case_fixtures


class TestNativeObservationRegressions(unittest.TestCase):
    def test_01_finish_occurrence_may_precede_header_dispatch_without_event_reordering(self):
        rows = network_fixture()
        # First Linux PW originals recorded these native microsecond times.
        # This synthetic replay is not a browser rerun or acceptance artifact.
        for indices, times in [((0,1,2), (62746256,62794278,62793624)),
                               ((3,4,5), (62817809,62861753,62861394))]:
            for index, stamp in zip(indices, times): rows[index]['timeUs'] = stamp
        original = copy.deepcopy(rows)
        self.assertIsNone(M.validate_network(rows, case_fixtures())); self.assertEqual(rows, original)

    def test_02_finish_cannot_precede_request_start(self):
        rows = network_fixture(); rows[2]['timeUs'] = rows[0]['timeUs'] - 1
        with self.assertRaises(ValueError): M.validate_network(rows, case_fixtures())

    def test_03_header_dispatch_cannot_precede_request_start(self):
        rows = network_fixture(); rows[1]['timeUs'] = rows[0]['timeUs'] - 1
        with self.assertRaises(ValueError): M.validate_network(rows, case_fixtures())

    def test_04_failed_terminal_dispatch_cannot_precede_its_header(self):
        rows = network_fixture(); rows[14]['timeUs'] = rows[13]['timeUs'] - 1
        with self.assertRaises(ValueError): M.validate_network(rows, case_fixtures())

    def test_05_arrival_sequence_and_start_header_terminal_order_remain_strict(self):
        for mode in ('swapped', 'duplicate', 'missing'):
            rows = network_fixture()
            if mode == 'swapped': rows[1], rows[2] = rows[2], rows[1]
            elif mode == 'duplicate': rows[2]['seq'] = rows[1]['seq']
            else: del rows[1]
            with self.assertRaises(ValueError): M.validate_network(rows, case_fixtures())

    def test_06_clock_domain_and_safe_integer_checks_are_not_removed(self):
        for index, field, value in [(0,'clock','WALL'), (1,'timeUs',True), (2,'timeUs',float('nan'))]:
            rows = network_fixture(); rows[index][field] = value
            with self.assertRaises(ValueError): M.validate_network(rows, case_fixtures())

    def test_07_native_cmdline_separator_is_ast_nul_not_printable_backslash_zero(self):
        # An escaped tool-JSON display is not source-byte evidence. Preserve
        # the already-correct NUL join rather than fixing an imagined defect.
        tree = ast.parse(pathlib.Path(M.__file__).read_bytes())
        verify = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == 'verify')
        joins = [n for n in ast.walk(verify) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr == 'join']
        self.assertEqual(len(joins), 1)
        constants = [n.value for n in ast.walk(joins[0]) if isinstance(n,ast.Constant) and isinstance(n.value,bytes)]
        self.assertIn(bytes([0]), constants); self.assertNotIn(bytes([92,48]), constants)

    def test_08_native_argument_sha_matches_literal_nul_terminated_bytes(self):
        tree = ast.parse(pathlib.Path(M.__file__).read_bytes())
        verify = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == 'verify')
        digest = next(n for n in ast.walk(verify) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
                      and n.func.id == 'sha' and any(isinstance(x,ast.Name) and x.id == 'a' for x in ast.walk(n)))
        record = {'argv':['/synthetic/node','driver.mjs','--root','/fixture']}
        actual = eval(compile(ast.Expression(digest),'<synthetic-native-argv>','eval'),{'sha':M.sha,'record':record})
        literal = bytes([0]).join(a.encode() for a in record['argv']) + bytes([0])
        self.assertEqual(actual,hashlib.sha256(literal).hexdigest())


if __name__ == '__main__': unittest.main(verbosity=2)
