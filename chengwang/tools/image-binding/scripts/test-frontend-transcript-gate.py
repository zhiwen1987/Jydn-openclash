"""Pure CPU mutation checks of the actual embedded frontend JSON gate.

The positive input combines historical names with synthetic passed observations
for new source declarations. It is not a Vitest transcript or product evidence.
No TypeScript, frontend tests, browser, server or build is executed here.
"""
import argparse
import ast
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


GATE = Path(__file__).with_name('run-offline-gate.sh')


def read_fixture(path):
    data = path.read_bytes()
    if len(data) > 4 * 1024 * 1024:
        raise ValueError('CPU fixture exceeds budget')
    return json.loads(data.decode('utf-8', errors='strict'))


def embedded_gate():
    lines = GATE.read_text(encoding='utf-8').splitlines()
    marker = '/usr/bin/python3 -B - "$RUN_ROOT/evidence/frontend-vitest.json" <<\'PY\''
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise ValueError('Unique frontend JSON gate not found')
    start = starts[0] + 1
    end = next(index for index in range(start, len(lines)) if lines[index] == 'PY')
    code = '\n'.join(lines[start:end]) + '\n'
    ast.parse(code)
    return code


class FrontendTranscriptCPU(unittest.TestCase):
    fixture = None
    code = None
    scratch = None

    def report(self):
        return copy.deepcopy(self.fixture)

    def run_gate(self, report):
        with tempfile.TemporaryDirectory(prefix='frontend-transcript-cpu-', dir=self.scratch) as directory:
            path = Path(directory) / 'synthetic-transcript.json'
            path.write_text(json.dumps(report), encoding='utf-8')
            return subprocess.run([sys.executable, '-B', '-c', self.code, str(path)],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, encoding='utf-8', errors='strict', timeout=15)

    def rejected(self, report):
        result = self.run_gate(report)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('D8_FRONTEND_UNIT_GATE=PASS', result.stdout)

    @staticmethod
    def suite(report, name):
        return next(item for item in report['testResults'] if Path(item['name']).name == name)

    def test_01_accepts_only_the_synthetic_complete_fixture(self):
        result = self.run_gate(self.report())
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('files=18 tests=345', result.stdout)
        self.assertIn('retained_names=306 live_overview_unit=39', result.stdout)
        self.assertIn('mocks=unit_tests_only', result.stdout)

    def test_02_rejects_the_old_306_without_the_new_increment(self):
        value = self.report()
        value['testResults'] = [item for item in value['testResults'] if Path(item['name']).name not in NEW_FILES]
        value['numTotalTests'] = value['numPassedTests'] = 306
        self.rejected(value)

    def test_03_rejects_coherently_renamed_old_case_at_same_count(self):
        value = self.report()
        case = self.suite(value, 'App.test.tsx')['assertionResults'][0]
        case['title'] += ' changed'
        case['fullName'] = ' '.join(case['ancestorTitles'] + [case['title']])
        self.rejected(value)

    def test_04_rejects_coherently_renamed_new_case_at_same_count(self):
        value = self.report()
        case = self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0]
        case['title'] += ' changed'
        case['fullName'] = ' '.join(case['ancestorTitles'] + [case['title']])
        self.rejected(value)

    def test_05_rejects_missing_assertion_behind_passed_aggregate(self):
        value = self.report()
        self.suite(value, 'OverviewReport.test.ts')['assertionResults'].pop()
        self.rejected(value)

    def test_06_rejects_replacement_with_an_unknown_file(self):
        value = self.report()
        self.suite(value, 'OverviewRouting.test.tsx')['name'] = '/synthetic/Other.test.tsx'
        self.rejected(value)

    def test_07_rejects_duplicate_file_observations(self):
        value = self.report()
        self.suite(value, 'OverviewRouting.test.tsx')['name'] = self.suite(value, 'OverviewReport.test.ts')['name']
        self.rejected(value)

    def test_08_rejects_duplicate_case_even_across_files(self):
        value = self.report()
        self.suite(value, 'OverviewRouting.test.tsx')['assertionResults'][0] = copy.deepcopy(self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0])
        self.rejected(value)

    def test_09_rejects_skipped_todo_and_failed_assertions(self):
        for status in ('pending', 'skipped', 'todo', 'failed'):
            with self.subTest(status=status):
                value = self.report()
                self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0]['status'] = status
                self.rejected(value)

    def test_10_rejects_noninteger_or_boolean_counters(self):
        for key, replacement in (('numTotalTests', 345.0), ('numPendingTests', False), ('numTodoTests', '0')):
            with self.subTest(key=key):
                value = self.report(); value[key] = replacement
                self.rejected(value)

    def test_11_rejects_nonzero_failed_or_pending_suites(self):
        for key in ('numFailedTestSuites', 'numPendingTestSuites'):
            with self.subTest(key=key):
                value = self.report(); value[key] = 1
                self.rejected(value)

    def test_12_rejects_failure_messages_on_an_apparently_passed_case(self):
        value = self.report()
        self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0]['failureMessages'] = ['synthetic failure']
        self.rejected(value)

    def test_13_rejects_missing_or_wrong_typed_case_fields(self):
        for key, replacement in (('fullName', None), ('title', 1), ('ancestorTitles', {}), ('failureMessages', None)):
            with self.subTest(key=key):
                value = self.report()
                self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0][key] = replacement
                self.rejected(value)

    def test_14_requires_explicit_zero_todo_and_suite_counters(self):
        for key in ('numTodoTests', 'numFailedTestSuites', 'numPendingTestSuites'):
            with self.subTest(key=key):
                value = self.report(); value.pop(key)
                self.rejected(value)

    def test_15_rejects_forged_total_or_passed_counters(self):
        for key in ('numTotalTests', 'numPassedTests'):
            with self.subTest(key=key):
                value = self.report(); value[key] = 344
                self.rejected(value)

    def test_16_rejects_declaration_list_arrow_framing(self):
        value = self.report()
        case = self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0]
        case['fullName'] = ' > '.join(case['ancestorTitles'] + [case['title']])
        self.rejected(value)

    def test_17_rejects_a_nonpassing_file_even_with_passed_cases(self):
        value = self.report()
        self.suite(value, 'OverviewReport.test.ts')['status'] = 'failed'
        self.rejected(value)

    def test_18_accepts_reordered_files_and_cases_with_identical_names(self):
        value = self.report()
        value['testResults'].reverse()
        for suite in value['testResults']:
            suite['assertionResults'].reverse()
        result = self.run_gate(value)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_19_rejects_inconsistent_ancestor_and_fullname(self):
        value = self.report()
        self.suite(value, 'OverviewReport.test.ts')['assertionResults'][0]['ancestorTitles'] = ['Changed']
        self.rejected(value)

    def test_20_rejects_a_file_without_actual_assertion_observations(self):
        value = self.report()
        self.suite(value, 'OverviewReport.test.ts')['assertionResults'] = []
        self.rejected(value)


NEW_FILES = frozenset(('OverviewReport.test.ts', 'OverviewTransport.test.ts', 'EvidenceOverview.test.tsx', 'OverviewRouting.test.tsx'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--historical-report', type=Path, required=True)
    parser.add_argument('--new-declarations', type=Path, required=True)
    parser.add_argument('--scratch-root', type=Path, required=True)
    args = parser.parse_args()
    source_root = GATE.parents[4].resolve()
    scratch = args.scratch_root.resolve(strict=True)
    if not scratch.is_dir() or scratch.is_relative_to(source_root):
        raise SystemExit('CPU scratch must be an existing directory outside the source tree')
    value = read_fixture(args.historical_report)
    declarations = read_fixture(args.new_declarations)
    files = declarations['files']
    if len(value['testResults']) != 14 or value['numTotalTests'] != 306 or {item['filename'] for item in files} != NEW_FILES or sum(len(item['declarations']) for item in files) != 39:
        raise SystemExit('CPU fixture shapes rejected')
    for item in files:
        cases = [{'ancestorTitles': case['ancestorTitles'], 'title': case['title'], 'fullName': case['fullName'], 'status': 'passed', 'failureMessages': []} for case in item['declarations']]
        value['testResults'].append({'name': '/synthetic/' + item['filename'], 'status': 'passed', 'assertionResults': cases})
    value['numTotalTests'] = value['numPassedTests'] = 345
    value['numTotalTestSuites'] += 8
    value['numPassedTestSuites'] += 8
    value['transcriptCPUFixture'] = 'SYNTHETIC_NEW_PASSED_STATUSES_NOT_VITEST_EXECUTION'
    FrontendTranscriptCPU.fixture = value
    FrontendTranscriptCPU.code = embedded_gate()
    FrontendTranscriptCPU.scratch = str(scratch)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FrontendTranscriptCPU))
    if not result.wasSuccessful() or result.skipped or result.testsRun != 20:
        raise SystemExit(1)
    print('FRONTEND_TRANSCRIPT_CPU=PASS tests=20 skips=0 synthetic_only=true vitest_executed=false product_runtime=false')


if __name__ == '__main__':
    main()
