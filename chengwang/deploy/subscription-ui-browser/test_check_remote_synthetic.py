"""CPU-only negative transcript fixtures; no real test execution is fabricated."""
import unittest
import check_remote_synthetic as C


def python_text(names=('test_first', 'test_second')):
    return ''.join(n + ' (test_fixture.Contracts.' + n + ') ... ok\n' for n in names) + '\nRan ' + str(len(names)) + ' tests in 0.001s\n\nOK\n'


def node_text(names=('first case', 'second case')):
    text = 'TAP version 13\n'
    for i, n in enumerate(names, 1): text += '# Subtest: ' + n + '\nok ' + str(i) + ' - ' + n + '\n'
    return text + '1..2\n# tests 2\n# suites 0\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n'


class RemoteSyntheticContracts(unittest.TestCase):
    def check_python(self, text):
        return C.python_events(text, 'test_fixture', 'Contracts', ['test_first', 'test_second'], 2,
                               C.names_sha(['test_first', 'test_second']))

    def check_node(self, text): return C.node_events(text, 2, C.names_sha(['first case', 'second case']))

    def test_01_exact_python_named_pass_events(self):
        self.assertEqual(self.check_python(python_text()), ['test_first', 'test_second'])

    def test_02_python_skip_failure_and_expected_failure_rejected(self):
        for outcome in ('skipped reason', 'FAIL', 'ERROR', 'expected failure', 'unexpected success'):
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                self.check_python(python_text().replace('... ok', '... ' + outcome, 1))

    def test_03_python_unknown_duplicate_or_missing_name_rejected(self):
        for text in (python_text(('test_first', 'test_other')), python_text(('test_first', 'test_first')),
                     python_text(('test_first',))):
            with self.subTest(text=text), self.assertRaises(ValueError): self.check_python(text)

    def test_04_python_class_module_and_method_binding_rejected(self):
        for text in (python_text().replace('test_fixture.Contracts', 'other.Contracts'),
                     python_text().replace('Contracts.test_first', 'Contracts.test_second', 1)):
            with self.subTest(text=text), self.assertRaises(ValueError): self.check_python(text)

    def test_05_python_summary_failure_or_extra_ok_rejected(self):
        for text in (python_text().replace('Ran 2', 'Ran 3'), python_text() + 'OK\n',
                     python_text().replace('\nOK\n', '\nOK (skipped=1)\n'), python_text() + 'FAILED\n'):
            with self.subTest(text=text), self.assertRaises(ValueError): self.check_python(text)

    def test_06_python_declaration_pin_count_and_duplicates_rejected(self):
        for names, count, pin in ((['test_first', 'test_second'], 0, '0'*64),
                                  (['test_first', 'test_first'], 2, C.names_sha(['test_first', 'test_first'])),
                                  (['test_first', 'test_second'], 2, '0'*64)):
            with self.subTest(names=names), self.assertRaises(ValueError):
                C.python_events(python_text(), 'test_fixture', 'Contracts', names, count, pin)

    def test_07_exact_node_named_pass_events(self):
        self.assertEqual(self.check_node(node_text()), ['first case', 'second case'])

    def test_08_node_unknown_duplicate_missing_and_wrong_sequence_rejected(self):
        for text in (node_text(('first case', 'unknown')), node_text(('first case', 'first case')),
                     node_text().replace('ok 2 - second case\n', ''), node_text().replace('ok 2 -', 'ok 3 -')):
            with self.subTest(text=text), self.assertRaises(ValueError): self.check_node(text)

    def test_09_node_skip_todo_bailout_and_failure_rejected(self):
        for extra in ('not ok 3 - failure\n', 'Bail out!\n', '# SKIP ignored\n', '# TODO missing\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError): self.check_node(node_text() + extra)

    def test_10_node_each_summary_counter_is_required_exactly_once(self):
        for field in ('tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
            line = next(s for s in node_text().splitlines() if s.startswith('# ' + field + ' '))
            for text in (node_text().replace(line+'\n', ''), node_text()+line+'\n',
                         node_text().replace(line, '# ' + field + ' 99')):
                with self.subTest(field=field), self.assertRaises(ValueError): self.check_node(text)

    def test_11_node_plan_and_name_pin_are_not_optional(self):
        for text in (node_text().replace('1..2', '1..3'), node_text()+'1..2\n'):
            with self.subTest(text=text), self.assertRaises(ValueError): self.check_node(text)
        with self.assertRaises(ValueError): C.node_events(node_text(), 2, '0'*64)

    def test_12_zero_declared_test_count_cannot_pass(self):
        with self.assertRaises(ValueError): C.node_events('', 0, C.names_sha([]))
        with self.assertRaises(ValueError): C.python_events('\nRan 0 tests in 0.0s\n\nOK\n', 'm', 'C', [], 0, C.names_sha([]))


if __name__ == '__main__': unittest.main()
