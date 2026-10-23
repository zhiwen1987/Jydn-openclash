"""Recompute the original 80 synthetic contracts from bounded original outputs.

No browser, product server, old decoder, or runner is imported here.  A derived
PASS document is not an execution transcript and cannot replace these inputs.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat

MAX_BYTES = 1 << 20
PINS = {
    'collector': (12, '525077090b05dae125d8f3cdc21ba8f8c998b27d88ad50c78ea2c1ed65c2f693'),
    'subscriptionDOM': (36, 'ad5fe9a1b5cc63e0cf38e50d537d815369313041347cb721eca5327cc3b61f82'),
    'frontend': (12, 'f631cf66f1842329b466bf0139c930409b9fb2d2d4ab9fe2a589050b0dfe1b03'),
    'pythonProjection': (12, 'ce6bbc4cf5dff4e6f047a465bbe94282b11e787c30b9e62d8dc2a81e6b939f11'),
    'artifactChecker': (8, 'da6a8fb45b108e2fbf605d3ac469ed40f69515ecafae376fe44a1b87b3db0622'),
}
OUTPUTS = {
    'collector': ('collector.tap',),
    'subscriptionDOM': ('subscription-dom.tap',),
    'frontend': ('frontend.json',),
    'pythonProjection': ('python-projection.events.jsonl', 'python-projection.log'),
    'artifactChecker': ('artifact-checker.events.jsonl', 'artifact-checker.log'),
}
RAW_NAMES = frozenset(name for names in OUTPUTS.values() for name in names) | {'execution.json'}
SUMMARY_FIELDS = ('testsRun', 'testsPassed', 'failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')


def need(value):
    if not value:
        raise ValueError('status contract original outputs rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result)
        result[key] = value
    return result


def decoded(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False))


def fingerprint(names):
    need(type(names) is list and names and all(type(n) is str and 0 < len(n) <= 256 for n in names))
    need(len(names) == len(set(names)))
    return len(names), sha('\n'.join(sorted(names)).encode())


def summary(pin, names, raw=None):
    need(fingerprint(names) == PINS[pin])
    result = dict(testsRun=PINS[pin][0], testsPassed=PINS[pin][0], names=sorted(names),
                  namesSHA256=PINS[pin][1], syntheticOnly=True, browserE2EProven=False)
    if raw is not None:
        result['originalOutputSHA256'] = sha(raw)
    return result


def tap(raw, pin):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    text = raw.decode('utf-8', errors='strict')
    names = re.findall(r'^# Subtest: (.+)$', text, re.M)
    result = summary(pin, names, raw)
    need(re.findall(r'^ok ([0-9]+) - (.+)$', text, re.M) == [(str(i + 1), n) for i, n in enumerate(names)])
    # Do not overlook nested/extra result lines, plans, or lower-case directives.
    need(len(re.findall(r'^\s*ok\b', text, re.M)) == len(names))
    need(not re.search(r'^\s*(?:not ok\b|Bail out!)', text, re.M | re.I))
    need(not re.search(r'#\s*(?:SKIP|TODO)\b', text))
    need(not re.search(r'^\s*ok\b[^\n]*#\s*(?:skip|todo)\b|^#\s*skip\b', text, re.M | re.I))
    need(re.findall(r'^TAP version ([0-9]+)$', text, re.M) == ['13'])
    count = PINS[pin][0]
    for key, value in dict(tests=count, suites=0, pass_=count, fail=0, cancelled=0, skipped=0, todo=0).items():
        need(re.findall(r'^# ' + key.rstrip('_') + r' ([0-9]+)$', text, re.M) == [str(value)])
    need(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(count)])
    need(len(re.findall(r'^\s*1\.\.[0-9]+', text, re.M)) == 1)
    return result


def frontend(raw):
    value = decoded(raw)
    need(type(value) is dict and set(value) == {'schema', 'syntheticOnly', 'realBrowserProof', 'passed', 'failed', 'names'})
    need(value['schema'] == 'chengwang.probe-status-observation-synthetic/v1'
         and value['syntheticOnly'] is True and value['realBrowserProof'] is False)
    need(type(value['passed']) is int and value['passed'] == 12
         and type(value['failed']) is int and value['failed'] == 0)
    return summary('frontend', value['names'], raw)


def python_output(events_raw, log_raw, pin):
    need(type(events_raw) is bytes and 0 < len(events_raw) <= MAX_BYTES
         and type(log_raw) is bytes and 0 < len(log_raw) <= MAX_BYTES)
    need(events_raw.endswith(b'\n') and b'\r' not in events_raw)
    events = [decoded(line) for line in events_raw.splitlines()]
    need(events and all(type(row) is dict for row in events))
    final = events[-1]
    need(set(final) == {'event', *SUMMARY_FIELDS} and final['event'] == 'SUMMARY')
    count = PINS[pin][0]
    need(all(type(final[field]) is int for field in SUMMARY_FIELDS))
    need(final == dict(event='SUMMARY', testsRun=count, testsPassed=count, failures=0, errors=0,
                       skipped=0, expectedFailures=0, unexpectedSuccesses=0))
    need(len(events) == count * 2 + 1)
    names = []
    for index in range(count):
        start, end = events[index * 2:index * 2 + 2]
        need(set(start) == {'event', 'name'} and set(end) == {'event', 'name'})
        need(start['event'] == 'RUN' and end['event'] == 'PASS' and start['name'] == end['name'])
        names.append(start['name'])
    result = summary(pin, names)
    # The independent text transcript must agree with every recorded success.
    prefix = ''.join(name.rsplit('.', 1)[1] + ' (' + name + ') ... ok\n' for name in names)
    text = log_raw.decode('utf-8', errors='strict')
    need(re.fullmatch(re.escape(prefix + '\n' + '-' * 70 + '\nRan ' + str(count) + ' tests in ')
                      + r'[0-9]+\.[0-9]{3}s\n\nOK\n', text) is not None)
    return result


def recompute(files):
    need(type(files) is dict and set(files) == RAW_NAMES)
    need(all(type(raw) is bytes and len(raw) <= MAX_BYTES for raw in files.values()))
    execution = decoded(files['execution.json'])
    need(type(execution) is dict and set(execution) == {'schema', 'groups'})
    need(execution['schema'] == 'chengwang.status-contract-execution/v1')
    need(type(execution['groups']) is dict and set(execution['groups']) == set(PINS))
    for pin, row in execution['groups'].items():
        mode = 'SUBPROCESS' if pin in {'collector', 'subscriptionDOM', 'frontend'} else 'IN_PROCESS_UNITTEST'
        keys = {'mode', 'captureComplete', 'outcome'} | ({'exitCode'} if mode == 'SUBPROCESS' else set())
        need(type(row) is dict and set(row) == keys and row['mode'] == mode
             and row['captureComplete'] is True and row['outcome'] == 'RETURNED')
        if mode == 'SUBPROCESS':
            need(type(row['exitCode']) is int and row['exitCode'] == 0)
    reports = {
        'collector': tap(files['collector.tap'], 'collector'),
        'subscriptionDOM': tap(files['subscription-dom.tap'], 'subscriptionDOM'),
        'frontend': frontend(files['frontend.json']),
        'pythonProjection': python_output(files['python-projection.events.jsonl'], files['python-projection.log'], 'pythonProjection'),
        'artifactChecker': python_output(files['artifact-checker.events.jsonl'], files['artifact-checker.log'], 'artifactChecker'),
    }
    return dict(schema='chengwang.status-diagnostic-contracts/v1', outcome='PASS', testsRun=80,
                testsPassed=80, skipped=0, syntheticOnly=True, browserE2EProven=False, production=False, reports=reports)


def read_file(path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_BYTES)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size) == (opened.st_dev, opened.st_ino, opened.st_size))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        after, linked = os.fstat(fd), path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink, s.st_mode)
        # Compare ctime within each stat API: Windows lstat/fstat can expose
        # distinct creation/change-time semantics. Neither API may change
        # during the read; cross-API file identity, size, links and mtime agree.
        cross = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink, s.st_mode)
        need(identity(before) == identity(linked) and identity(opened) == identity(after)
             and cross(before) == cross(opened) and len(raw) == before.st_size)
        return raw
    finally:
        os.close(fd)


def verify_tree(root, contracts_raw):
    need(not root.is_symlink() and stat.S_ISDIR(root.lstat().st_mode))
    root_before = root.lstat()
    manifest_raw = read_file(root / 'manifest.json')
    manifest = decoded(manifest_raw)
    need(type(manifest) is dict and set(manifest) == {'schema', 'files'})
    need(manifest['schema'] == 'chengwang.status-contract-originals/v1'
         and type(manifest['files']) is list and len(manifest['files']) == len(RAW_NAMES))
    entries = {}
    for row in manifest['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'stored'})
        need(type(row['path']) is str and row['path'] in RAW_NAMES and row['path'] not in entries)
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_BYTES and type(row['stored']) is bool)
        need(type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None)
        need(row['stored'] is bool(row['bytes']))
        entries[row['path']] = row
    need(set(entries) == RAW_NAMES)
    expected = {name for name, row in entries.items() if row['stored']} | {'manifest.json'}
    need({path.name for path in root.iterdir()} == expected)
    files = {}
    for name, row in entries.items():
        raw = read_file(root / name) if row['stored'] else b''
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'])
        files[name] = raw
    root_after = root.lstat()
    directory_identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
    need(directory_identity(root_before) == directory_identity(root_after)
         and {p.name for p in root.iterdir()} == expected)
    need(read_file(root / 'manifest.json') == manifest_raw)
    derived = recompute(files)
    claimed = decoded(contracts_raw)
    # Python's True == 1 must not permit a substituted summary field.
    need(json.dumps(claimed, sort_keys=True, separators=(',', ':'))
         == json.dumps(derived, sort_keys=True, separators=(',', ':')))
    return dict(schema='chengwang.status-contract-original-verification/v1', outcome='PASS', testsRun=80,
                testsPassed=80, skipped=0, originalFiles=len(expected), originalBytes=sum(len(v) for v in files.values()),
                originalManifestSHA256=sha(manifest_raw), originalContractsReportSHA256=sha(contracts_raw),
                syntheticOnly=True, browserE2EProven=False, production=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--raw-root', type=pathlib.Path, required=True)
    parser.add_argument('--contracts-report', type=pathlib.Path, required=True)
    parser.add_argument('--report', type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = args.raw_root.resolve(strict=True)
    # Check the supplied path before resolve as well: resolving is not symlink rejection.
    need(not args.raw_root.is_symlink() and not args.contracts_report.is_symlink())
    output = args.report.absolute()
    need(not output.resolve().is_relative_to(root) and not output.exists() and not output.is_symlink())
    need(not args.contracts_report.resolve(strict=True).is_relative_to(root))
    result = verify_tree(root, read_file(args.contracts_report))
    encoded = (json.dumps(result, separators=(',', ':')) + '\n').encode()
    with output.open('xb') as stream:
        stream.write(encoded)
    print('STATUS_CONTRACT_ORIGINAL_OUTPUTS=VERIFIED tests=80 skips=0 synthetic_only=true browser_e2e_proven=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('STATUS_CONTRACT_ORIGINAL_OUTPUTS=REJECTED raw_input_suppressed=true') from None
