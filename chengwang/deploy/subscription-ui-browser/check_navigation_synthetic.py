"""Frozen navigation diagnostic helper events; never product acceptance."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location('navigation_test_event_primitives',
    Path(__file__).with_name('check_remote_synthetic.py'))
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

# Pre-CI declarations; an unset pin is deliberately a hard rejection.
PYTHON = {
    'navigation-reader': ('test_navigation_diagnostics', 'NavigationDiagnosticsContracts', 16,
                          '65d982b98a0f0e7a74a8e663593e75bb1e2e1def1eefad1cd432480483c29c72'),
    'navigation-checker': ('test_check_navigation_diagnostics', 'NavigationDiagnosticVerifierContracts', 18,
                           '29b19637d19136ec767cae3a1283f098433491311edd745cc402f141d7dfcdd4'),
}
NODE_COUNT = 24
NODE_NAMES_SHA = '21b66dd221501d40a0e41f9f6eb13bb4de999a5c2feffff78ec3d16cc347bb13'


def verify(evidence):
    suites = {}
    for filename, (module, classname, count, pin) in PYTHON.items():
        raw, text = H.original(evidence, filename + '.log')
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [c for c in tree.body if isinstance(c, ast.ClassDef)
                   and any(isinstance(b, ast.Attribute) and b.attr == 'TestCase' for b in c.bases)]
        H.need(len(classes) == 1 and classes[0].name == classname)
        names = sorted(m.name for m in classes[0].body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and m.name.startswith('test_'))
        H.python_events(text, module, classname, names, count, pin)
        suites[filename] = dict(tests=count, passed=count, skipped=0,
                               namesSHA256=pin, originalSHA256=H.sha(raw))
    raw, text = H.original(evidence, 'navigation-node.tap')
    H.node_events(text, NODE_COUNT, NODE_NAMES_SHA)
    suites['navigation-node'] = dict(tests=NODE_COUNT, passed=NODE_COUNT, skipped=0,
                                    namesSHA256=NODE_NAMES_SHA, originalSHA256=H.sha(raw))
    return suites


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=Path)
    options = parser.parse_args()
    H.need(re.fullmatch('[a-f0-9]{40}', options.source_commit))
    suites = verify(options.evidence)
    value = dict(schema='chengwang.navigation-diagnostics-synthetic/v1',
        sourceCommit=options.source_commit, suites=suites,
        tests=sum(suite['tests'] for suite in suites.values()), skipped=0,
        previous84Replaced=False, previous76Replaced=False, remote86Replaced=False,
        browserStarted=False, runtime=False, production=False,
        scope='SYNTHETIC_DIAGNOSTIC_CONTRACTS_NOT_REAL_FAILURE_OR_PRODUCT_ACCEPTANCE')
    with options.report.open('xb') as target:
        target.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('NAVIGATION_DIAGNOSTIC_SYNTHETIC=PASS tests=' + str(value['tests'])
          + ' skips=0 browser_started=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('NAVIGATION_DIAGNOSTIC_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
