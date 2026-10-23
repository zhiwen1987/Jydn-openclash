"""Verify frozen actual test events; never substitute them for product UI evidence."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

PYTHON = {
    'runner': ('test_run_subscription_ui', 'TestSubscriptionUIRunnerContracts', 16,
               '733eb86a78f3c50b6422c5ec771f266813d3020c1630250760b5e64391688f27'),
    'checker': ('test_check_subscription_ui', 'CheckerContracts', 36,
                'd6df952277974ad9ca14910039ab5c3faace25ee4190dcea6ab003353cf10c7b'),
}
NODE_COUNT = 32
NODE_NAMES_SHA = '4785e3a43d51027cbf6be3dc41671d74d767e36c883ab541f06679e56175ee44'


def need(value):
    if not value:
        raise ValueError('synthetic original rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def names_sha(names):
    return sha('\n'.join(sorted(names)).encode('ascii'))


def original(evidence, filename):
    raw = (evidence / filename).read_bytes()
    need(0 < len(raw) <= 2 << 20)
    return raw, raw.decode('utf-8', errors='strict').replace('\r\n', '\n')


def verify(evidence):
    suites = {}
    for filename, (module, classname, count, expected) in PYTHON.items():
        raw, text = original(evidence, filename + '.log')
        pattern = (r'^(test_[A-Za-z0-9_]+) \(' + re.escape(module + '.' + classname)
                   + r'\.(test_[A-Za-z0-9_]+)\) \.\.\. ok$')
        events = re.findall(pattern, text, re.M)
        names = [outer for outer, _ in events]
        need(len(events) == len(set(names)) == count
             and all(outer == inner for outer, inner in events)
             and names_sha(names) == expected)
        need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == count
             and re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$', text, re.M) == [str(count)]
             and re.findall(r'^OK$', text, re.M) == ['OK']
             and not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef)
                   and any(isinstance(b, ast.Attribute) and b.attr == 'TestCase' for b in n.bases)]
        need(len(classes) == 1 and classes[0].name == classname)
        declared = sorted(n.name for n in classes[0].body
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                          and n.name.startswith('test_'))
        need(declared == sorted(names))
        suites[filename] = dict(tests=count, passed=count, skipped=0,
                               namesSHA256=expected, originalSHA256=sha(raw))
    raw, text = original(evidence, 'node.tap')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    passed = re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M)
    need(len(names) == len(set(names)) == NODE_COUNT and names_sha(names) == NODE_NAMES_SHA
         and passed == [(str(i + 1), name) for i, name in enumerate(names)]
         and not re.search(r'^\s*(?:not ok\b|Bail out!)|# (?:SKIP|TODO)\b', text, re.M))
    for key, count in dict(tests=32, suites=0, **{'pass': 32}, fail=0,
                           cancelled=0, skipped=0, todo=0).items():
        need(re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.M) == [str(count)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(NODE_COUNT)])
    suites['node'] = dict(tests=32, passed=32, skipped=0,
                          namesSHA256=NODE_NAMES_SHA, originalSHA256=sha(raw))
    return suites


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    need(re.fullmatch(r'[a-f0-9]{40}', args.source_commit))
    report = dict(schema='chengwang.subscription-ui-synthetic/v1', sourceCommit=args.source_commit,
                  suites=verify(args.evidence), tests=84, skipped=0,
                  runtime=False, browserStarted=False, production=False,
                  scope='SYNTHETIC_CONTRACTS_NOT_REAL_PRODUCT_UI_ACCEPTANCE')
    with args.report.open('xb') as handle:
        handle.write((json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('SUBSCRIPTION_UI_SYNTHETIC=PASS node=32 python=52 skips=0 browser_started=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('SUBSCRIPTION_UI_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
