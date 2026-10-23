"""Frozen actual admission-helper events, not real UI or node availability."""
import argparse
import ast
import importlib.util
from pathlib import Path
import json
import re

_spec = importlib.util.spec_from_file_location('admission_event_primitives', Path(__file__).with_name('check_ui_synthetic.py'))
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)
PYTHON = {
    'admission-fixture': ('test_admission_fixture', 'AdmissionFixtureContracts', 16,
                         'b0b143abd996f0cfdf4ab568068f557783eda55cc96eb4d187710afd152eec70'),
    'admission-checker': ('test_check_admission_ui', 'AdmissionVerifierContracts', 28,
                         'b99859cd83e9b2689c468f8c3552fa6f6ff613cc97fb01ee6497b7e9fd7f00bf'),
}
NODE_NAMES_SHA = 'b2e9fc4705056c7dd07f4f80caeb41316ccc8138989891d3cf8f394d23bdec81'


def verify(evidence):
    suites = {}
    for filename, (module, classname, count, expected) in PYTHON.items():
        raw, text = H.original(evidence, filename + '.log')
        pattern = (r'^(test_[A-Za-z0-9_]+) \(' + re.escape(module + '.' + classname)
                   + r'\.(test_[A-Za-z0-9_]+)\) \.\.\. ok$')
        events = re.findall(pattern, text, re.M)
        names = [outer for outer, _ in events]
        H.need(len(events) == len(set(names)) == count
               and all(outer == inner for outer, inner in events)
               and H.names_sha(names) == expected)
        H.need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == count
               and re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$', text, re.M) == [str(count)]
               and re.findall(r'^OK$', text, re.M) == ['OK']
               and not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef)
                   and any(isinstance(b, ast.Attribute) and b.attr == 'TestCase' for b in n.bases)]
        H.need(len(classes) == 1 and classes[0].name == classname)
        declared = sorted(n.name for n in classes[0].body
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_'))
        H.need(declared == sorted(names))
        suites[filename] = dict(tests=count, passed=count, skipped=0,
                               namesSHA256=expected, originalSHA256=H.sha(raw))
    raw, text = H.original(evidence, 'admission-node.tap')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    passed = re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M)
    H.need(len(names) == len(set(names)) == 32 and H.names_sha(names) == NODE_NAMES_SHA
           and passed == [(str(i + 1), name) for i, name in enumerate(names)]
           and not re.search(r'^\s*(?:not ok\b|Bail out!)|# (?:SKIP|TODO)\b', text, re.M))
    for key, count in dict(tests=32, suites=0, **{'pass': 32}, fail=0, cancelled=0, skipped=0, todo=0).items():
        H.need(re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.M) == [str(count)])
    H.need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == ['32'])
    suites['admission-node'] = dict(tests=32, passed=32, skipped=0,
                                    namesSHA256=NODE_NAMES_SHA, originalSHA256=H.sha(raw))
    return suites


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    H.need(re.fullmatch(r'[a-f0-9]{40}', args.source_commit))
    report = dict(schema='chengwang.admission-ui-synthetic/v1', sourceCommit=args.source_commit,
                  suites=verify(args.evidence), tests=76, skipped=0, previous84Replaced=False,
                  runtime=False, browserStarted=False, production=False,
                  scope='SYNTHETIC_CONTRACTS_NOT_REAL_PRODUCT_LOCAL_ADMISSION_ACCEPTANCE')
    with args.report.open('xb') as handle:
        handle.write((json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('ADMISSION_UI_SYNTHETIC=PASS node=32 python=44 skips=0 browser_started=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('ADMISSION_UI_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
