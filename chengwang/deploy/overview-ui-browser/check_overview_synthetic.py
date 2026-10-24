"""Reconstruct nine frozen CPU transcripts; never assert browser acceptance."""
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
SELF = 'chengwang/deploy/overview-ui-browser/check_overview_synthetic.py'
PYTHON = {
    'overview-contract-original.log': ('chengwang/deploy/overview-ui-browser/test_overview_contract.py', 'OverviewContractTests', 33, '62917cb1f1e48c1e8ae1b09129bda56a8ac71c19a1450285ebfb8ef4991a70ce'),
    'overview-scene-original.log': ('chengwang/deploy/overview-ui-browser/test_overview_scene.py', 'OverviewSceneContracts', 16, '825021e664340b9f628556b049e28f71c2965fa08df25711abf35b801c25e376'),
    'overview-checker-original.log': ('chengwang/deploy/overview-ui-browser/test_check_overview_ui.py', 'OverviewCheckerContracts', 52, '2433256aa59ee8e04e8cb840eb6e9df8e2e9859c3181e5d74205e3e6fb461fb7'),
}
NODE = {
    'native-session.tap': ('chengwang/tools/browser-scene-driver/test-native-session.mjs', 37, '1a2a7c1fde1f4fa45732b55eb7ee6a6ce9e5f035c455260c8d9cae6577b3e571'),
    'wire-contract.tap': ('chengwang/tools/overview-ui-browser/test-wire-contract.mjs', 19, 'd73bf86a1bf88e1699f2753fe03a3837f89b516acb42ead37b8fbd9733170547'),
    'overview-journal.tap': ('chengwang/tools/overview-ui-browser/test-overview-journal.mjs', 20, '833984573d4f04f1d049bed8845d305a3ca4697069f47be2b61f3fb6645114e7'),
    'overview-dom.tap': ('chengwang/tools/overview-ui-browser/test-ui-dom.mjs', 34, '319952126719d7ad7082909c4d8ff169bf2a2d77e0c9ec0ea422020c639b2b2b'),
    'overview-contract.tap': ('chengwang/tools/overview-ui-browser/test-ui-contract.mjs', 12, 'c8fefab2eb584670880bbd30ab611f250727043d3ef77699396d8309103bee3f'),
    'overview-driver.tap': ('chengwang/tools/overview-ui-browser/test-ui-driver.mjs', 13, 'b64e7905e6e28f6c529ae5e32139ba49e00f83a9ad02bcc1d65342b95dc5a339'),
}
SOURCES = [SELF, 'chengwang/deploy/overview-ui-browser/contract.json',
    'chengwang/deploy/overview-ui-browser/check_overview_ui.py',
    'chengwang/deploy/overview-ui-browser/overview_ui_scene.py',
    'chengwang/deploy/overview-ui-browser/run_overview_ui.py',
    'chengwang/deploy/capability-truth-browser/check_capability_truth.py',
    'chengwang/deploy/browser-scene-supervisor/supervisor.py',
    'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
    'chengwang/tools/browser-scene-driver/native-session.mjs',
    *['chengwang/tools/overview-ui-browser/' + name for name in ('wire-contract.mjs', 'overview-journal.mjs', 'ui-dom.mjs', 'ui-contract.mjs', 'ui-driver.mjs', 'ui-cli.mjs')],
    *[row[0] for row in PYTHON.values()], *[row[0] for row in NODE.values()]]


def need(value):
    if not value:
        raise ValueError('overview CPU transcript rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def names_sha(names):
    return sha('\n'.join(sorted(names)).encode('utf-8'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def safe_path(path):
    path = Path(os.path.abspath(path))
    need(not any(part.is_symlink() for part in (path, *path.parents)))
    return path


def read(path):
    path = safe_path(path); before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 2 << 20)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read((2 << 20) + 1)
        after, named = os.fstat(fd), path.lstat()
        # Windows path/descriptor ctime have different meanings; retain both
        # channels' own before/after ctime and every shared identity field.
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_nlink)
        need(identity(before) == identity(opened) == identity(after) == identity(named)
             and before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns and len(raw) == before.st_size)
        if os.name != 'nt': need(before.st_ctime_ns == opened.st_ctime_ns)
        return raw
    finally:
        os.close(fd)


def python_names(source, classname):
    tree = ast.parse(source); classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == classname]
    need(len(classes) == 1)
    names = [node.name for node in classes[0].body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')]
    need(len(names) == len(set(names)))
    return sorted(names)


def verify_python(raw, source, classname, count, pin, module):
    body = raw.decode('utf-8').replace('\r\n', '\n')
    events = re.findall(r'^(test_[A-Za-z0-9_]+) \((?:__main__|' + re.escape(module) + r')\.' + re.escape(classname) + r'\.(test_[A-Za-z0-9_]+)\) \.\.\. ok$', body, re.M)
    names = [first for first, _ in events]
    need(len(names) == len(set(names)) == count and all(first == second for first, second in events) and names_sha(names) == pin)
    need(python_names(source, classname) == sorted(names))
    need(re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$', body, re.M) == [str(count)] and re.findall(r'^OK$', body, re.M) == ['OK'])
    allowed = re.compile(r'^(?:test_[A-Za-z0-9_]+ \((?:__main__|' + re.escape(module) + r')\.' + re.escape(classname) + r'\.test_[A-Za-z0-9_]+\) \.\.\. ok|-{20,}|Ran [0-9]+ tests in [0-9.]+s|OK)?$')
    need(all(allowed.fullmatch(line) for line in body.splitlines()))
    return dict(tests=count, passed=count, skipped=0, namesSHA256=pin, originalSHA256=sha(raw), sourceSHA256=sha(source))


def node_names(source):
    body = source.decode('utf-8')
    # These frozen suites use static single-quoted top-level declarations.
    # Unknown declaration syntax fails closed; no JavaScript is evaluated.
    names = re.findall(r"^test\('([^'\r\n]+)'\s*,", body, re.M)
    need(len(names) == len(set(names)) and len(re.findall(r'^test\(', body, re.M)) == len(names))
    return names


def verify_node(raw, source, count, pin):
    body = raw.decode('utf-8').replace('\r\n', '\n')
    names = re.findall(r'^# Subtest: (.+)$', body, re.M)
    events = re.findall(r'^ok ([0-9]+) - (.+)$', body, re.M)
    need(len(names) == len(set(names)) == len(events) == count and names_sha(names) == pin)
    need([int(number) for number, _ in events] == list(range(1, count + 1)) and [name for _, name in events] == names)
    need(sorted(node_names(source)) == sorted(names))
    need(re.findall(r'^TAP version ([0-9]+)$', body, re.M) == ['13'] and re.findall(r'^1\.\.([0-9]+)$', body, re.M) == [str(count)])
    need(not re.search(r'^\s*(?:not ok\b|Bail out!)|^ok .+#\s*(?:SKIP|TODO)\b', body, re.M | re.I))
    for key, value in [('tests', count), ('suites', 0), ('pass', count), ('fail', 0), ('cancelled', 0), ('skipped', 0), ('todo', 0)]:
        need(re.findall(r'^# ' + key + r' ([0-9]+)$', body, re.M) == [str(value)])
    allowed = re.compile(r'^(?:TAP version 13|# Subtest: .+|ok [0-9]+ - .+|1\.\.[0-9]+|# (?:tests|suites|pass|fail|cancelled|skipped|todo) [0-9]+|# duration_ms [0-9.]+|  (?:---|\.\.\.|duration_ms: [0-9.]+|type: (?:test|\x27test\x27)))?$')
    need(all(allowed.fullmatch(line) for line in body.splitlines()))
    return dict(tests=count, passed=count, skipped=0, namesSHA256=pin, originalSHA256=sha(raw), sourceSHA256=sha(source))


def git_source(repo, commit, path):
    result = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), 'show', commit + ':' + path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    need(result.returncode == 0)
    return result.stdout


def verify(evidence, repo, commit):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    evidence, repo = safe_path(evidence), safe_path(repo)
    need(evidence.is_dir() and repo.is_dir() and set(path.name for path in evidence.iterdir()) == set(PYTHON) | set(NODE))
    source = {path: read(repo / path) for path in SOURCES}
    need(all(git_source(repo, commit, path) == raw for path, raw in source.items()) and read(__file__) == source[SELF])
    originals = {name: read(evidence / name) for name in (*PYTHON, *NODE)}; suites = {}
    for name, (path, cls, count, pin) in PYTHON.items(): suites[name] = verify_python(originals[name], source[path], cls, count, pin, Path(path).stem)
    for name, (path, count, pin) in NODE.items(): suites[name] = verify_node(originals[name], source[path], count, pin)
    need(set(path.name for path in evidence.iterdir()) == set(originals))
    need(all(read(evidence / path) == raw for path, raw in originals.items()) and all(read(repo / path) == raw for path, raw in source.items()) and read(__file__) == source[SELF])
    return dict(schema='chengwang.overview-ui-synthetic-verification/v1', sourceCommit=commit, outcome='PASS', scope='CPU_CONTRACTS_ONLY_NOT_REAL_BROWSER_ACCEPTANCE',
        suites=suites, totalTests=sum(row[2] for row in PYTHON.values()) + sum(row[1] for row in NODE.values()), skipped=0,
        sourceSHA256={path: sha(raw) for path, raw in sorted(source.items())}, realBrowserProven=False, realProductServerProven=False, businessAvailabilityProven=False, production=False, authorization='BLOCKED')


def main(argv=None):
    class ClosedParser(argparse.ArgumentParser):
        def error(self, message): raise ValueError('overview CPU transcript rejected')
    parser = ClosedParser(add_help=False)
    for name in ('evidence', 'repo', 'report'): parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--source-commit', required=True); args = parser.parse_args(argv)
    evidence, repo, output = safe_path(args.evidence), safe_path(args.repo), safe_path(args.report)
    need(output.parent.is_dir() and not output.exists() and not output.is_relative_to(evidence) and not output.is_relative_to(repo))
    report = verify(evidence, repo, args.source_commit)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as handle: handle.write(canonical(report) + b'\n'); handle.flush(); os.fsync(handle.fileno())
    finally: os.close(fd)
    print('OVERVIEW_UI_SYNTHETIC=PASS tests=' + str(report['totalTests']) + ' skipped=0 real_browser_proven=false production=false')
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception: raise SystemExit('OVERVIEW_UI_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
