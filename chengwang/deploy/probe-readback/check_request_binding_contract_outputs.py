"""Frozen original synthetic transcripts; never real browser acceptance."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

BASE = Path(__file__).resolve().parent
MAX_BYTES = 1 << 20


def need(value):
    if not value:
        raise ValueError('request binding synthetic originals rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(names):
    need(type(names) is list and names and all(type(n) is str and n.isascii() for n in names)
         and len(names) == len(set(names)))
    return sha('\n'.join(sorted(names)).encode('ascii'))


def read(path):
    before = path.lstat()
    need(not path.is_symlink() and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and 0 < before.st_size <= MAX_BYTES)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    # Keep complete path and descriptor observations independently stable.
    # Windows may give lstat/fstat different ctime meanings; never equate those
    # two clocks, while still requiring inode/device/size/mtime identity.
    common = tuple(k for k in fields if k != 'st_ctime_ns')
    need(len(raw) == before.st_size
         and all(getattr(before, k) == getattr(final, k) for k in fields)
         and all(getattr(opened, k) == getattr(after, k) for k in fields)
         and all(getattr(before, k) == getattr(opened, k) for k in common))
    return raw


def verify(evidence):
    contract = json.loads((BASE / 'request-binding-contract.json').read_bytes())
    pins = contract['syntheticPins']
    reports = {}
    raw = read(evidence / 'request-binding-node.tap')
    text = raw.decode('utf-8').replace('\r\n', '\n')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    passed = re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M)
    need(len(names) == 24 and fingerprint(names) == pins['nodeCollector']
         and passed == [(str(i + 1), name) for i, name in enumerate(names)]
         and not re.search(r'^\s*(?:not ok\b|Bail out!)|# (?:SKIP|TODO)\b', text, re.M))
    for key, count in dict(tests=24, suites=0, **{'pass': 24}, fail=0, cancelled=0, skipped=0, todo=0).items():
        need(re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.M) == [str(count)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == ['24'])
    reports['nodeCollector'] = dict(tests=24, namesSHA256=pins['nodeCollector'], originalSHA256=sha(raw))
    raw = read(evidence / 'request-binding-frontend.json')
    need(raw.count(b'\n') == 1 and raw.endswith(b'\n'))
    front = json.loads(raw)
    need(set(front) == {'schema', 'passed', 'failed', 'names', 'namesSHA256',
                        'syntheticOnly', 'realBrowserProof', 'runtimeStarted'})
    need(front['schema'] == 'chengwang.probe-request-binding-synthetic/v1'
         and type(front['passed']) is int and front['passed'] == 16
         and type(front['failed']) is int and front['failed'] == 0
         and front['syntheticOnly'] is True and front['realBrowserProof'] is False and front['runtimeStarted'] is False
         and len(front['names']) == 16 and fingerprint(front['names']) == front['namesSHA256'] == pins['frontend'])
    reports['frontend'] = dict(tests=16, namesSHA256=pins['frontend'], originalSHA256=sha(raw))
    raw = read(evidence / 'request-binding-python.log')
    text = raw.decode('utf-8').replace('\r\n', '\n')
    events = re.findall(r'^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok$', text, re.M)
    names = [full for outer, full in events]
    need(len(names) == len(set(names)) == 48 and all(outer == full.rsplit('.', 1)[1] for outer, full in events))
    need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == 48
         and re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$', text, re.M) == ['48']
         and re.findall(r'^OK$', text, re.M) == ['OK']
         and not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
    for module, count in [('test_probe_request_binding', 16), ('test_check_request_binding', 24), ('test_run_request_binding', 8)]:
        selected = [name for name in names if name.startswith(module + '.')]
        tree = ast.parse((BASE / (module + '.py')).read_bytes())
        declared = sorted(module + '.' + c.name + '.' + m.name for c in tree.body if isinstance(c, ast.ClassDef)
            for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_'))
        need(len(selected) == count and sorted(selected) == declared and fingerprint(selected) == pins[module])
        reports[module] = dict(tests=count, namesSHA256=pins[module], originalSHA256=sha(raw))
    return reports


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    need(re.fullmatch(r'[a-f0-9]{40}', args.source_commit))
    result = dict(schema='chengwang.probe-request-binding-contract-originals/v1', sourceCommit=args.source_commit,
        scope='SYNTHETIC_NOT_BROWSER_OR_CANCELLATION_CAUSE', suites=verify(args.evidence), tests=88,
        skipped=0, old80Replaced=False, old193Replaced=False, runtimeStarted=False, production=False)
    with args.report.open('xb') as output:
        output.write((json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('REQUEST_BINDING_CONTRACT_ORIGINALS=PASS tests=88 skips=0 browser_started=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('REQUEST_BINDING_CONTRACT_ORIGINALS=REJECTED raw_input_suppressed=true') from None
