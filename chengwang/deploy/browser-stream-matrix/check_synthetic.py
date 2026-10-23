"""Count frozen actual test events, not AST counts or declared summaries."""
import argparse
import ast
import hashlib
import json
import pathlib
import re

PYTHON = {
    'test_server_contract': ('TestStreamServerContracts', 24, 'd2b68e565dc9dc8d1a906e0b9f560914cf60ccd00bd56eab3ef00c42532b553d'),
    'test_check_matrix': ('TestMatrixContracts', 24, 'ffeca5e08c45508e80018b869fb5a16428b2c772e45811d5dc76a7c9b2d06b55'),
    'test_check_matrix_full': ('TestMatrixFullHelpers', 8, '2cff899bb14b0df8a53949c8a4ea7deded555f144e1317f898a380c2d39b7902'),
    'test_run_matrix': ('TestMatrixRunnerContracts', 8, '1f62c75187d2bdc5e0f0188ab172c776a69741794e878c7b57af89df9f0bcded'),
}


def need(value):
    if not value: raise ValueError('synthetic originals rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def verify(evidence):
    result = {}
    for module, (classname, count, expected) in PYTHON.items():
        original = (evidence / (module + '.log')).read_bytes()
        need(0 < len(original) <= 2 << 20)
        text = original.decode('utf-8', errors='strict').replace('\r\n', '\n')
        pattern = r'^(test_[A-Za-z0-9_]+) \(' + re.escape(module + '.' + classname) + r'\.(test_[A-Za-z0-9_]+)\) \.\.\. ok$'
        rows = re.findall(pattern, text, re.M)
        names = [outer for outer, _ in rows]
        digest = sha('\n'.join(sorted(names)).encode())
        need(len(rows) == len(set(names)) == count and all(outer == inner for outer, inner in rows) and digest == expected)
        need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == count
             and re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$', text, re.M) == [str(count)]
             and re.findall(r'^OK$', text, re.M) == ['OK']
             and not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
        tree = ast.parse((pathlib.Path(__file__).parent / (module + '.py')).read_bytes())
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name.startswith('Test')]
        need(len(classes) == 1 and classes[0].name == classname)
        declared = sorted(node.name for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        need(declared == sorted(names))
        result[module] = dict(tests=count, passed=count, skipped=0, namesSHA256=digest, originalSHA256=sha(original))
    original = (evidence / 'node.tap').read_bytes(); need(0 < len(original) <= 2 << 20)
    text = original.decode('utf-8', errors='strict').replace('\r\n', '\n')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    passed = re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M)
    digest = sha(('\n'.join(sorted(names)) + '\n').encode())
    need(len(names) == len(set(names)) == 32 and digest == 'f431b2b6b833b57ca39cb0e30ad0eb93d224ae20b32dd91500b1cb49a0404abb'
         and passed == [(str(index+1), name) for index, name in enumerate(names)]
         and not re.search(r'^\s*(?:not ok\b|Bail out!)|# (?:SKIP|TODO)\b', text, re.M))
    for key, count in dict(tests=32,suites=0,**{'pass':32},fail=0,cancelled=0,skipped=0,todo=0).items():
        need(re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.M) == [str(count)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == ['32'])
    result['node'] = dict(tests=32,passed=32,skipped=0,namesSHA256=digest,originalSHA256=sha(original))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=pathlib.Path)
    args = parser.parse_args()
    need(re.fullmatch(r'[a-f0-9]{40}', args.source_commit))
    results = verify(args.evidence)
    report = dict(schema='chengwang.stream-matrix-synthetic/v1', sourceCommit=args.source_commit,
        suites=results, tests=96, skipped=0, runtime=False, browserStarted=False, production=False,
        scope='SYNTHETIC_CONTRACTS_NOT_REAL_BROWSER_OR_PRODUCT_ACCEPTANCE')
    with args.report.open('xb') as handle:
        handle.write((json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode())
    print('STREAM_MATRIX_SYNTHETIC=PASS node=32 python=64 skips=0 browser_started=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('STREAM_MATRIX_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
