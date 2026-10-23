"""Frozen remote helper events only; not a browser, wire or product verdict."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

# Filled from reviewed, pre-CI declarations, never learned from a passing run.
PYTHON = {
    'remote-fixture': ('test_remote_fetch_fixture', 'RemoteFetchFixtureContracts', 16,
                       'fe31cbd21ffe8e761cdb83e9ec308835b04230cb99dfa5af8a88254acb6a6608'),
    'remote-checker': ('test_check_remote_fetch_ui', 'RemoteFetchVerifierContracts', 26,
                       '41369356d5e04ff9042f85747725ac42e52fc77ed6b5baa9ad1e26355fe03121'),
    'remote-synthetic-checker': ('test_check_remote_synthetic', 'RemoteSyntheticContracts', 12,
                                 'b77cdb57750796c3e9bfc68d16d8ec8bcfc4bc4b9907a4a69658a5582f5e3f32'),
}
NODE_COUNT = 32
NODE_NAMES_SHA = '789f5e6ab7cebdfb39e7032db3abb3faec66a3173c31653db2633cc2bc0f2b4e'


def need(value):
    if not value: raise ValueError('remote synthetic evidence rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()
def names_sha(names): return sha('\n'.join(sorted(names)).encode('ascii'))


def original(evidence, name):
    raw = (evidence / name).read_bytes()
    need(0 < len(raw) <= 2 << 20)
    return raw, raw.decode('utf-8', errors='strict').replace('\r\n', '\n')


def python_events(text, module, classname, declared, count, pin):
    need(type(count) is int and count > 0 and len(declared) == count
         and len(set(declared)) == count and names_sha(declared) == pin)
    pattern = (r'^(test_[A-Za-z0-9_]+) \(' + re.escape(module + '.' + classname)
               + r'\.(test_[A-Za-z0-9_]+)\) \.\.\. ok$')
    events = re.findall(pattern, text, re.M)
    names = [outer for outer, _ in events]
    need(sorted(names) == sorted(declared) and len(events) == count
         and all(outer == inner for outer, inner in events))
    need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == count
         and re.findall(r'^Ran ([0-9]+) tests? in [0-9.]+s$', text, re.M) == [str(count)]
         and re.findall(r'^OK$', text, re.M) == ['OK']
         and not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
    return names


def node_events(text, count, pin):
    need(type(count) is int and count > 0)
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    passed = re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M)
    need(len(names) == len(set(names)) == count and names_sha(names) == pin
         and passed == [(str(i + 1), name) for i, name in enumerate(names)]
         and not re.search(r'^\s*(?:not ok\b|Bail out!)|# (?:SKIP|TODO)\b', text, re.M))
    for key, number in dict(tests=count, suites=0, **{'pass': count}, fail=0, cancelled=0, skipped=0, todo=0).items():
        need(re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.M) == [str(number)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(count)])
    return names


def verify(evidence):
    suites = {}
    for filename, (module, classname, count, pin) in PYTHON.items():
        raw, text = original(evidence, filename + '.log')
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [c for c in tree.body if isinstance(c, ast.ClassDef)
                   and any(isinstance(b, ast.Attribute) and b.attr == 'TestCase' for b in c.bases)]
        need(len(classes) == 1 and classes[0].name == classname)
        names = sorted(m.name for m in classes[0].body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and m.name.startswith('test_'))
        python_events(text, module, classname, names, count, pin)
        suites[filename] = dict(tests=count, passed=count, skipped=0, namesSHA256=pin, originalSHA256=sha(raw))
    raw, text = original(evidence, 'remote-node.tap')
    node_events(text, NODE_COUNT, NODE_NAMES_SHA)
    suites['remote-node'] = dict(tests=NODE_COUNT, passed=NODE_COUNT, skipped=0,
                                namesSHA256=NODE_NAMES_SHA, originalSHA256=sha(raw))
    return suites


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--report', required=True, type=Path)
    a = p.parse_args(); need(re.fullmatch('[a-f0-9]{40}', a.source_commit))
    suites = verify(a.evidence)
    value = dict(schema='chengwang.remote-fetch-ui-synthetic/v1', sourceCommit=a.source_commit,
                 suites=suites, tests=sum(v['tests'] for v in suites.values()), skipped=0,
                 previous84Replaced=False, previous76Replaced=False, runtime=False,
                 browserStarted=False, wireStarted=False, production=False,
                 scope='SYNTHETIC_CONTRACTS_NOT_REAL_REMOTE_FETCH_ACCEPTANCE')
    with a.report.open('xb') as out:
        out.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('REMOTE_FETCH_SYNTHETIC=PASS tests=' + str(value['tests']) + ' skips=0 browser_started=false wire_started=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('REMOTE_FETCH_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
