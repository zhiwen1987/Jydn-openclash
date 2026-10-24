"""Verify actual frozen CPU transcripts; never prove a real capability UI run."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

HERE = Path(__file__).parent
SELF = 'chengwang/deploy/capability-truth-browser/check_capability_synthetic.py'
PYTHON = {
    'supervisor-unit.log': ('chengwang/deploy/browser-scene-supervisor/test_supervisor.py', 'SupervisorContracts', 16,
        '55a5b1f94d354448556388c29a1a6d90b7367df1320d66170acc66f687c288bb'),
    'capability-scene-unit.log': ('chengwang/deploy/capability-truth-browser/test_capability_truth_scene.py', 'CapabilitySceneContracts', 36,
        '994351e2bfa2755621cd700b6a0817cbd60d946ef2cf71432d70e0f9ea2c951d'),
    'capability-checker-unit.log': ('chengwang/deploy/capability-truth-browser/test_check_capability_truth.py', 'CapabilityCheckerContracts', 50,
        '2a364ac25ecc8528b3a913692d4860cb85dc6c73b2ecc1733f24a4c47c1fbf36'),
}
NODE_COUNT = 86
NODE_PIN = 'a3bb73077a17c6cbb049010d82656cce86cf43239950e12f17f01e721b69a731'
SOURCES = [SELF, 'chengwang/deploy/capability-truth-browser/contract.json',
    'chengwang/deploy/capability-truth-browser/check_capability_truth.py',
    'chengwang/deploy/capability-truth-browser/capability_truth_scene.py',
    'chengwang/deploy/capability-truth-browser/run_capability_truth.py',
    'chengwang/deploy/browser-scene-supervisor/supervisor.py',
    'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
    *[r[0] for r in PYTHON.values()],
    *['chengwang/tools/capability-truth-browser/' + n for n in ('ui-contract.mjs', 'ui-dom.mjs', 'ui-driver.mjs', 'ui-cli.mjs',
        'test-ui-contract.mjs', 'test-ui-dom.mjs', 'test-ui-driver.mjs')]]


def need(value):
    if not value:
        raise ValueError('capability CPU transcript rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def names_sha(names):
    return sha('\n'.join(sorted(names)).encode('utf-8'))


def read(path):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)))
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 2 << 20)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as h:
            raw = h.read((2 << 20) + 1)
        after, named = os.fstat(fd), path.lstat()
        ident = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_size, v.st_mtime_ns, v.st_nlink)
        need(ident(before) == ident(opened) == ident(after) == ident(named) and before.st_ctime_ns == named.st_ctime_ns
             and opened.st_ctime_ns == after.st_ctime_ns and len(raw) == before.st_size)
        return raw
    finally:
        os.close(fd)


def verify_python(raw, source, classname, count, pin, module_name=None):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    module = re.escape(module_name) if module_name else r'[A-Za-z0-9_.]+'
    pattern = r'^(test_[A-Za-z0-9_]+) \((?:__main__|' + module + r')\.' + re.escape(classname) + r'\.(test_[A-Za-z0-9_]+)\) \.\.\. ok$'
    events = re.findall(pattern, text, re.M)
    names = [a for a, _ in events]
    need(len(names) == len(set(names)) == count and all(a == b for a, b in events) and names_sha(names) == pin)
    need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == count)
    need(re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$', text, re.M) == [str(count)] and re.findall(r'^OK$', text, re.M) == ['OK'])
    need(not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
    classes = [n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == classname]
    need(len(classes) == 1)
    declared = sorted(n.name for n in classes[0].body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_'))
    need(declared == sorted(names))
    return dict(tests=count, passed=count, skipped=0, namesSHA256=pin, originalSHA256=sha(raw), sourceSHA256=sha(source))


def verify_node(raw):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    passed = re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M)
    need(len(names) == len(set(names)) == len(passed) == NODE_COUNT and names_sha(names) == NODE_PIN)
    need([int(i) for i, _ in passed] == list(range(1, NODE_COUNT + 1)) and [n for _, n in passed] == names)
    # TAP's valid zero summaries are '# skipped 0' and '# todo 0'. Only test
    # directives, not those summaries, signal a skipped or todo test.
    need(not re.search(r'^\s*(?:not ok\b|Bail out!)|^ok .+#\s*(?:SKIP|TODO)\b', text, re.M | re.I))
    for key, value in [('tests', NODE_COUNT), ('suites', 0), ('pass', NODE_COUNT), ('fail', 0), ('cancelled', 0), ('skipped', 0), ('todo', 0)]:
        need(re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.M) == [str(value)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(NODE_COUNT)])
    return dict(tests=NODE_COUNT, passed=NODE_COUNT, skipped=0, namesSHA256=NODE_PIN, originalSHA256=sha(raw))


def verify(evidence, repo, commit):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    source = {}
    for path in SOURCES:
        actual = read(repo / path)
        p = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), 'show', commit + ':' + path],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        need(p.returncode == 0 and p.stdout == actual)
        source[path] = actual
    need(read(Path(__file__)) == source[SELF])
    originals, suites = {}, {}
    for filename, (path, cls, count, pin) in PYTHON.items():
        originals[filename] = read(evidence / filename)
        suites[filename] = verify_python(originals[filename], source[path], cls, count, pin, Path(path).stem)
    originals['capability-node.tap'] = read(evidence / 'capability-node.tap')
    suites['capability-node.tap'] = verify_node(originals['capability-node.tap'])
    need(all(read(evidence / p) == raw for p, raw in originals.items()))
    need(all(read(repo / p) == raw for p, raw in source.items()) and read(Path(__file__)) == source[SELF])
    return dict(schema='chengwang.capability-truth-synthetic-verification/v1', sourceCommit=commit, outcome='PASS',
        scope='CPU_CONTRACTS_ONLY_NOT_REAL_BROWSER_ACCEPTANCE', suites=suites, totalTests=sum(r[2] for r in PYTHON.values()) + NODE_COUNT, skipped=0,
        sourceSHA256={p: sha(b) for p, b in sorted(source.items())}, realBrowserProven=False, realProductServerProven=False,
        businessAvailabilityProven=False, production=False, authorization='BLOCKED')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence', 'repo', 'report'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--source-commit', required=True)
    a = p.parse_args()
    evidence, repo, report = a.evidence.absolute(), a.repo.absolute(), a.report.absolute()
    need(not any(path.is_symlink() for path in (evidence, repo, report, *report.parents)) and not report.exists()
         and not report.is_relative_to(evidence) and not report.is_relative_to(repo))
    result = verify(evidence, repo, a.source_commit)
    with report.open('xb') as handle:
        handle.write(canonical(result) + b'\n')
        handle.flush()
        os.fsync(handle.fileno())
    print('CAPABILITY_TRUTH_SYNTHETIC=PASS tests=' + str(result['totalTests']) + ' skipped=0 real_browser_proven=false production=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CAPABILITY_TRUTH_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
