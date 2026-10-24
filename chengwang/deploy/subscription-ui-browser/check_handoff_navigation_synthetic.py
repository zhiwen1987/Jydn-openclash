"""Frozen negative-handoff diagnostic unit events, never browser acceptance."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location('handoff_navigation_event_primitives', Path(__file__).with_name('check_remote_synthetic.py'))
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)
PYTHON = {
    'handoff-navigation-reader': ('test_handoff_navigation_diagnostics', 'HandoffNavigationReaderContracts', 10, '72489416d5aaef2e46bbce15ad96fe25628f9b3470b2a1ce75e6355c4d15c27d'),
    'handoff-navigation-checker': ('test_check_handoff_navigation_diagnostics', 'HandoffNavigationDiagnosticVerifierContracts', 20, '4d9203eb68b897637a10e197cff393b6c14fc663d9b820d11e82e5680e5f0a60'),
}

def verify(evidence):
    suites = {}
    for filename, (module, classname, count, pin) in PYTHON.items():
        raw, text = H.original(evidence, filename + '.log')
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [c for c in tree.body if isinstance(c, ast.ClassDef) and any(isinstance(b, ast.Attribute) and b.attr == 'TestCase' for b in c.bases)]
        H.need(len(classes) == 1 and classes[0].name == classname)
        names = sorted(m.name for m in classes[0].body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name.startswith('test_'))
        H.python_events(text, module, classname, names, count, pin)
        suites[filename] = dict(tests=count, passed=count, skipped=0, namesSHA256=pin, originalSHA256=H.sha(raw))
    raw, text = H.original(evidence, 'handoff-navigation-node.tap')
    H.node_events(text, 27, '7d2f8c4d2386cb54a68a2914ecdf52471823c1797fbf3903954f83d7c62626eb')
    suites['handoff-navigation-node'] = dict(tests=27, passed=27, skipped=0, originalSHA256=H.sha(raw))
    return suites

def main():
    parser = argparse.ArgumentParser()
    for name in ('evidence', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    H.need(re.fullmatch('[a-f0-9]{40}', args.source_commit))
    suites = verify(args.evidence)
    value = dict(schema='chengwang.handoff-navigation-synthetic/v1', sourceCommit=args.source_commit, suites=suites, tests=57, skipped=0,
                 previousNavigation58Replaced=False, previousProductGatesRelaxed=False, browserStarted=False, runtime=False, production=False,
                 scope='SYNTHETIC_CONTRACTS_NOT_REAL_FAILURE_OR_PRODUCT_ACCEPTANCE')
    with args.report.open('xb') as target:
        target.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('HANDOFF_NAVIGATION_SYNTHETIC=PASS tests=57 skips=0 browser_started=false')

if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('HANDOFF_NAVIGATION_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
