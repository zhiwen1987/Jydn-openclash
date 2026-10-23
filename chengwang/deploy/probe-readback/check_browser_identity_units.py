"""Independent checks of new synthetic raw outputs; not browser acceptance."""
import argparse
import hashlib
import json
import pathlib
import re

NODE_PIN = (20, '82236781b9611eae26fad42ac96071512a0a64a3d79a36591e200a0f9dbe0092')
PY_PINS = {
    'browser-identity-python-unit.log': ('test_probe_browser_identity', 12, '729cebad3da418b771a873385aeccaee736b39abf399f9134481bb720b2279ea'),
    'status-contract-originals-unit.log': ('test_check_status_contract_outputs', 24, '38f61a9a2b69749dfb12b5ddc17902b51622e0663eedd66f44c0a342cdff282b'),
}


def need(value):
    if not value: raise ValueError('identity synthetic outputs rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def python_names(text, module, count, fingerprint):
    rows = re.findall(r'^(test_[A-Za-z0-9_]+) \((' + re.escape(module)
        + r'\.[A-Za-z0-9_]+\.test_[A-Za-z0-9_]+)\) \.\.\. ok\r?$', text, re.M)
    need(all(outer == inner.rsplit('.', 1)[1] for outer, inner in rows))
    tests = [inner for _, inner in rows]
    need(len(tests) == len(set(tests)) == count and sha('\n'.join(sorted(tests)).encode()) == fingerprint)
    return tests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-root', required=True, type=pathlib.Path)
    parser.add_argument('--report', required=True, type=pathlib.Path)
    args = parser.parse_args()
    import check_probe_readback as B
    root = args.evidence_root.resolve(strict=True)
    report_path = args.report.resolve()
    names = ['browser-identity-unit.tap', *PY_PINS]
    need(report_path not in [root / name for name in names])
    raw = B.read_file(root / names[0], 1 << 20); text = raw.decode('utf-8', errors='strict')
    tests = re.findall(r'^# Subtest: (.+)$', text, re.M)
    need(len(tests) == len(set(tests)) == NODE_PIN[0]
         and sha(('\n'.join(sorted(tests)) + '\n').encode()) == NODE_PIN[1])
    need(re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M) == [(str(i + 1), n) for i, n in enumerate(tests)])
    need(len(re.findall(r'^\s*ok\b', text, re.M)) == NODE_PIN[0])
    need(not re.search(r'^\s*(?:not ok\b|Bail out!)', text, re.M | re.I))
    need(not re.search(r'^\s*ok\b[^\n]*#\s*(?:skip|todo)\b', text, re.M | re.I))
    need(re.findall(r'^TAP version ([0-9]+)$', text, re.M) == ['13'])
    for key, expected in dict(tests=20, suites=0, pass_=20, fail=0, cancelled=0, skipped=0, todo=0).items():
        need(re.findall(r'^# ' + key.rstrip('_') + r' ([0-9]+)$', text, re.M) == [str(expected)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == ['20'])
    need(len(re.findall(r'^\s*1\.\.[0-9]+', text, re.M)) == 1)
    reports = [dict(file=names[0], testsRun=20, testsPassed=20, originalSHA256=sha(raw), namesSHA256=NODE_PIN[1])]
    for filename, (module, count, fingerprint) in PY_PINS.items():
        raw = B.read_file(root / filename, 1 << 20); text = raw.decode('utf-8', errors='strict')
        tests = python_names(text, module, count, fingerprint)
        need(len(re.findall(r'^test_.*\.\.\. ', text, re.M)) == count)
        need(re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s\r?$', text, re.M) == [str(count)])
        need(re.findall(r'^OK\r?$', text, re.M) == ['OK'] or re.findall(r'^OK\r?$', text, re.M) == ['OK\r'])
        need(not re.search(r'^(?:FAILED|ERROR:|FAIL:|OK \()', text, re.M))
        reports.append(dict(file=filename, testsRun=count, testsPassed=count,
            originalSHA256=sha(raw), namesSHA256=fingerprint))
    result = dict(schema='chengwang.browser-identity-synthetic/v1', testsRun=56, testsPassed=56,
                  skipped=0, reports=reports, syntheticOnly=True, browserAcceptanceProven=False)
    with report_path.open('xb') as out: out.write((json.dumps(result, separators=(',', ':')) + '\n').encode())
    print('BROWSER_IDENTITY_SYNTHETIC=PASS tests=56 skips=0 browser_acceptance_proven=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('BROWSER_IDENTITY_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
