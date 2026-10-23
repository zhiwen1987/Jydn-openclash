"""Independent frozen synthetic gates; never runs a browser or product server."""
import argparse
import ast
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import subprocess
import sys
import unittest

PINS = {
    'collector': (12, '525077090b05dae125d8f3cdc21ba8f8c998b27d88ad50c78ea2c1ed65c2f693'),
    'subscriptionDOM': (36, 'ad5fe9a1b5cc63e0cf38e50d537d815369313041347cb721eca5327cc3b61f82'),
    'frontend': (12, 'f631cf66f1842329b466bf0139c930409b9fb2d2d4ab9fe2a589050b0dfe1b03'),
    'pythonProjection': (12, 'ce6bbc4cf5dff4e6f047a465bbe94282b11e787c30b9e62d8dc2a81e6b939f11'),
    'artifactChecker': (8, 'da6a8fb45b108e2fbf605d3ac469ed40f69515ecafae376fe44a1b87b3db0622'),
}


def need(value):
    if not value:
        raise ValueError('diagnostic synthetic gate rejected')


def fingerprint(names):
    need(type(names) is list and names and all(type(n) is str and 0 < len(n) <= 256 for n in names))
    need(len(names) == len(set(names)))
    return len(names), hashlib.sha256('\n'.join(sorted(names)).encode()).hexdigest()


def execute(args):
    value = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, check=False)
    need(value.returncode == 0 and 0 < len(value.stdout) <= 1 << 20)
    return value.stdout


def tap(raw, pin):
    text = raw.decode('utf-8', errors='strict')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    need(fingerprint(names) == PINS[pin])
    need(re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M) == [(str(i + 1), n) for i, n in enumerate(names)])
    need(not re.search(r'^\s*(?:not ok\b|Bail out!)|# (?:SKIP|TODO)\b', text, re.M))
    count = PINS[pin][0]
    for key, value in dict(tests=count, suites=0, pass_=count, fail=0, cancelled=0, skipped=0, todo=0).items():
        need(re.findall(r'^# ' + key.rstrip('_') + r' ([0-9]+)$', text, re.M) == [str(value)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(count)])
    return dict(testsRun=count, testsPassed=count, names=sorted(names), namesSHA256=PINS[pin][1],
                originalOutputSHA256=hashlib.sha256(raw).hexdigest(), syntheticOnly=True, browserE2EProven=False)


class Recorded(unittest.TextTestResult):
    def __init__(self, *args):
        super().__init__(*args); self.runs = []; self.passes = []

    def startTest(self, test):
        self.runs.append(test.id()); super().startTest(test)

    def addSuccess(self, test):
        self.passes.append(test.id()); super().addSuccess(test)


def python_tests(base, name, pin):
    source = base / (name + '.py')
    tree = ast.parse(source.read_bytes())
    names = sorted(name + '.' + cls.name + '.' + method.name for cls in tree.body if isinstance(cls, ast.ClassDef)
                   for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'))
    need(fingerprint(names) == PINS[pin])
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Recorded).run(
        unittest.defaultTestLoader.loadTestsFromModule(module))
    need(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)
    need(sorted(result.runs) == names and sorted(result.passes) == names)
    return dict(testsRun=result.testsRun, testsPassed=len(result.passes), names=names,
                namesSHA256=PINS[pin][1], syntheticOnly=True, browserE2EProven=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', required=True); parser.add_argument('--web-build', type=pathlib.Path, required=True)
    parser.add_argument('--report', type=pathlib.Path, required=True)
    args = parser.parse_args()
    base = pathlib.Path(__file__).resolve().parent
    source = base.parents[2]
    reports = {}
    reports['collector'] = tap(execute([args.node, '--test', '--test-reporter=tap',
        str(source / 'chengwang/tools/probe-browser/test-probe-status-diagnostics.mjs')]), 'collector')
    reports['subscriptionDOM'] = tap(execute([args.node, '--test', '--test-reporter=tap',
        str(source / 'chengwang/tools/subscription-browser/test-collect-subscription-dom.mjs')]), 'subscriptionDOM')
    raw = execute([args.node, str(args.web_build / 'tools/check-probe-status-observation.mjs')])
    front = json.loads(raw)
    need(set(front) == {'schema', 'syntheticOnly', 'realBrowserProof', 'passed', 'failed', 'names'})
    need(front['schema'] == 'chengwang.probe-status-observation-synthetic/v1'
         and front['syntheticOnly'] is True and front['realBrowserProof'] is False)
    need(type(front['passed']) is int and front['passed'] == 12 and type(front['failed']) is int and front['failed'] == 0)
    need(fingerprint(front['names']) == PINS['frontend'])
    reports['frontend'] = dict(testsRun=12, testsPassed=12, names=sorted(front['names']),
        namesSHA256=PINS['frontend'][1], originalOutputSHA256=hashlib.sha256(raw).hexdigest(),
        syntheticOnly=True, browserE2EProven=False)
    reports['pythonProjection'] = python_tests(base, 'test_probe_status_diagnostics', 'pythonProjection')
    reports['artifactChecker'] = python_tests(base, 'test_check_status_diagnostic', 'artifactChecker')
    report = dict(schema='chengwang.status-diagnostic-contracts/v1', outcome='PASS', testsRun=80,
        testsPassed=80, skipped=0, syntheticOnly=True, browserE2EProven=False, production=False, reports=reports)
    need(sum(r['testsRun'] for r in reports.values()) == 80)
    with args.report.open('xb') as output:
        output.write((json.dumps(report, separators=(',', ':')) + '\n').encode())
    print('STATUS_DIAGNOSTIC_CONTRACTS=PASS tests=80 skips=0 synthetic_only=true browser_e2e_proven=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('STATUS_DIAGNOSTIC_CONTRACTS=FAIL raw_input_suppressed=true') from None
