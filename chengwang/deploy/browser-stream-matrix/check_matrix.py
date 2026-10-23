"""Recompute closed original stream observations; does not launch a browser."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile

CASES = ('split-success', 'boundary-success', 'oversize', 'truncated', 'abort')
PUBLIC = {'driver.json', 'network.jsonl', 'server-events.jsonl', 'processes.json',
          'isolation.json', 'certificates.json', 'inputs.json', 'pin-consumption.json'}
ORIGIN = 'https://127.0.0.1:17881'
BODY_LIMIT = 1048576
HTML_BYTES = 199
PIN_SHA = '404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
ZIP_SHA = '7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853'
TAG = '41520584daa68d0040db7746ae562a0ff82187f6'


def need(value):
    if not value: raise ValueError('stream matrix rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def exact(value, fields): need(type(value) is dict and set(value) == set(fields))


def integer(value, low=0, high=9007199254740991): need(type(value) is int and low <= value <= high)


def strict_same(actual, expected):
    """JSON equality must not treat false as zero or one as true."""
    need(type(actual) is type(expected))
    if type(expected) is dict:
        exact(actual, expected)
        for key in expected: strict_same(actual[key], expected[key])
    elif type(expected) is list:
        need(len(actual) == len(expected))
        for left, right in zip(actual, expected): strict_same(left, right)
    else: need(actual == expected)


def verify_tls(certs, driver, network):
    """Offline signature/IP/validity check at the recorded observation time.

    OpenSSL -trusted disables default trust stores; -attime validates the
    captured time, not an arbitrary future report replay date. See official
    openssl-verification-options. No network, server or TLS bypass is involved.
    """
    exact(certs, ('caPEM', 'leafPEM'))
    def der(pem):
        need(type(pem) is str and len(pem) <= 65536 and re.fullmatch(
            r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?', pem))
        return base64.b64decode(''.join(pem.splitlines()[1:-1]), validate=True)
    ca, leaf = der(certs['caPEM']), der(certs['leafPEM'])
    strict_same(driver['normalTrust'], dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,',
        caSHA256=sha(ca), leafSHA256=sha(leaf), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True))
    tls = driver['tls']; exact(tls, ('securityState', 'protocol', 'cipher', 'leafSHA256', 'caSHA256',
        'serverChainLength', 'leafSignatureVerified', 'ipSANVerified'))
    need(tls['securityState'] == 'secure' and tls['protocol'] in ('TLS 1.2', 'TLS 1.3')
         and type(tls['cipher']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', tls['cipher'])
         and tls['leafSHA256'] == sha(leaf) and tls['caSHA256'] == sha(ca)
         and tls['leafSignatureVerified'] is True and tls['ipSANVerified'] is True)
    chain = driver['certificateChain']; need(type(chain) is list and 1 <= len(chain) <= 2)
    integer(tls['serverChainLength'], 1, 2); need(tls['serverChainLength'] == len(chain))
    decoded = []
    for encoded in chain:
        need(type(encoded) is str and len(encoded) <= 65536)
        value = base64.b64decode(encoded, validate=True)
        need(base64.b64encode(value).decode('ascii') == encoded); decoded.append(value)
    need(decoded == ([leaf] if len(chain) == 1 else [leaf, ca]))
    need(type(network) is list and network and network[0]['event'] == 'START' and network[0]['case'] == 'DOCUMENT')
    stamp = network[0]['wallTimeUs']; integer(stamp, 1, 9007199254740991)
    with tempfile.TemporaryDirectory(prefix='chengwang-offline-certificate-') as temporary:
        paths = [pathlib.Path(temporary) / name for name in ('ca.pem', 'leaf.pem')]
        for path, pem in zip(paths, (certs['caPEM'], certs['leafPEM'])):
            with path.open('xb') as handle: handle.write(pem.encode('ascii'))
        try:
            result = subprocess.run(['openssl', 'verify', '-trusted', str(paths[0]), '-check_ss_sig',
                '-attime', str(stamp // 1000000), '-purpose', 'sslserver', '-verify_ip', '127.0.0.1', str(paths[1])],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                env={'PATH': os.environ.get('PATH', os.defpath), 'OPENSSL_CONF': os.devnull})
        except (OSError, subprocess.SubprocessError):
            raise ValueError('stream matrix rejected') from None
        need(result.returncode == 0)


def expected_body(case):
    need(case in CASES)
    if case in ('split-success', 'truncated', 'abort'): return b'{"ok":true}'
    size = BODY_LIMIT + (case == 'oversize')
    return b'{"data":"' + b'a' * (size - 11) + b'"}'


def validate_case(value, expected_case):
    exact(value, ('case', 'js', 'networkOrdinal', 'requestId', 'terminal', 'hostBody'))
    need(value['case'] == expected_case and expected_case in CASES)
    integer(value['networkOrdinal'], 2, 6)
    need(value['networkOrdinal'] == CASES.index(expected_case) + 2)
    need(type(value['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', value['requestId']))
    j, t = value['js'], value['terminal']
    exact(j, ('bytes', 'eof', 'readEnd', 'signalAborted', 'abortRequested', 'abortError', 'cancelAttempted',
              'cancelCompleted', 'parsed', 'sha256', 'elapsedMs', 'chunks'))
    integer(j['bytes'], 0, BODY_LIMIT + 1); integer(j['elapsedMs'], 0, 30000); integer(j['chunks'], 1, 8192)
    need(all(type(j[k]) is bool for k in ('eof', 'signalAborted', 'abortRequested', 'abortError',
                                         'cancelAttempted', 'cancelCompleted', 'parsed')))
    exact(t, ('event', 'canceled', 'errorCode'))
    need(type(t['event']) is str and t['event'] in ('FINISH', 'FAIL')
         and t['canceled'] in ('YES', 'NO', 'UNSPECIFIED')
         and t['errorCode'] in ('NONE', 'ABORTED', 'CONTENT_LENGTH_MISMATCH', 'OTHER'))
    if expected_case.endswith('-success'):
        body = expected_body(expected_case); digest = sha(body)
        need(j['bytes'] == len(body) and j['eof'] and j['readEnd'] == 'EOF_OK' and j['parsed'] and j['sha256'] == digest
             and not any(j[k] for k in ('signalAborted', 'abortRequested', 'abortError', 'cancelAttempted', 'cancelCompleted')))
        need(t == dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE'))
        exact(value['hostBody'], ('bytes', 'sha256')); integer(value['hostBody']['bytes'], 1, BODY_LIMIT)
        need(value['hostBody'] == dict(bytes=len(body), sha256=digest))
    else:
        need(value['hostBody'] is None and not j['eof'] and not j['parsed'] and j['sha256'] is None and j['cancelAttempted'])
        if expected_case == 'oversize':
            need(j['bytes'] == BODY_LIMIT + 1 and j['readEnd'] == 'SIZE_REJECT' and j['cancelCompleted']
                 and not any(j[k] for k in ('signalAborted', 'abortRequested', 'abortError')))
            need(t == dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE')
                 or t['event'] == 'FAIL' and t['errorCode'] == 'ABORTED')
        elif expected_case == 'truncated':
            need(j['bytes'] == 6 and j['readEnd'] == 'READ_ERROR'
                 and not any(j[k] for k in ('signalAborted', 'abortRequested', 'abortError')))
            need(t['event'] == 'FAIL' and t['errorCode'] in ('CONTENT_LENGTH_MISMATCH', 'OTHER'))
        else:
            need(j['bytes'] == 6 and j['readEnd'] == 'ABORT_ERROR' and j['signalAborted'] and j['abortRequested'] and j['abortError'])
            need(t['event'] == 'FAIL' and t['errorCode'] == 'ABORTED')


def validate_network(rows, cases):
    need(type(rows) is list and len(rows) == 18 and type(cases) is list and len(cases) == 5)
    for index, value in enumerate(cases): validate_case(value, CASES[index])
    groups, ids = {}, {}
    base = {'v', 'seq', 'event', 'ordinal', 'requestId', 'case', 'clock', 'timeUs'}
    extra = {'START': {'wallTimeUs'}, 'HEADERS': {'status', 'mimeType', 'noStore', 'contentLength'},
             'FINISH': {'encodedDataLength'}, 'FAIL': {'canceled', 'errorCode'}}
    for index, row in enumerate(rows):
        need(type(row) is dict and type(row.get('event')) is str and row['event'] in extra)
        exact(row, base | extra[row['event']])
        need(type(row['v']) is int and row['v'] == 1 and type(row['seq']) is int and row['seq'] == index + 1)
        integer(row['ordinal'], 1, 6); integer(row['timeUs'])
        need(row['case'] == ('DOCUMENT', *CASES)[row['ordinal'] - 1] and row['clock'] == 'CDP_MONOTONIC_US')
        need(type(row['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', row['requestId']))
        groups.setdefault(row['ordinal'], []).append(row)
        if row['event'] == 'START':
            need(row['requestId'] not in ids); ids[row['requestId']] = row['ordinal']; integer(row['wallTimeUs'], 1)
        need(ids.get(row['requestId']) == row['ordinal'])
    need(set(groups) == set(range(1, 7)) and len(ids) == 6)
    for ordinal, group in groups.items():
        need(len(group) == 3 and [r['event'] for r in group[:2]] == ['START', 'HEADERS'])
        start, header, end = group
        # Chromium tag 41520584: responseReceived is stamped at dispatch Now(),
        # loadingFinished carries saved monotonic_finish_time. A successful
        # completion timestamp may precede HEADERS dispatch despite seq order.
        # loadingFailed instead uses dispatch Now(); retain its stronger bound.
        need(start['timeUs'] <= header['timeUs'] and start['timeUs'] <= end['timeUs'] and end['event'] in ('FINISH', 'FAIL'))
        if end['event'] == 'FAIL': need(header['timeUs'] <= end['timeUs'])
        need(type(header['status']) is int and header['status'] == 200 and header['noStore'] is True)
        case = start['case']
        expected_length = HTML_BYTES if case == 'DOCUMENT' else BODY_LIMIT if case == 'boundary-success' else None if case == 'oversize' else 11
        need(header['mimeType'] == ('text/html' if case == 'DOCUMENT' else 'application/json'))
        need(header['contentLength'] is None if expected_length is None else type(header['contentLength']) is int and header['contentLength'] == expected_length)
        if end['event'] == 'FINISH':
            integer(end['encodedDataLength'], 0, 2 << 20)
            terminal = dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE')
        else:
            terminal = {k: end[k] for k in ('event', 'canceled', 'errorCode')}
        if case == 'DOCUMENT': need(terminal == dict(event='FINISH', canceled='UNSPECIFIED', errorCode='NONE'))
        else:
            value = cases[ordinal - 2]
            need(value['networkOrdinal'] == ordinal and value['requestId'] == start['requestId'] and value['terminal'] == terminal)


def validate_server(rows):
    need(type(rows) is list and len(rows) == 24)
    groups, requests = {}, []
    for index, row in enumerate(rows):
        exact(row, ('schema', 'ordinal', 'event', 'caseId', 'bodyBytes', 'framedBytes', 'reason'))
        need(row['schema'] == 'chengwang.stream-matrix-server-event/v1' and type(row['ordinal']) is int and row['ordinal'] == index + 1)
        need(type(row['event']) is str and row['event'] in ('REQUEST', 'WRITE_RETURNED', 'COMPLETE', 'PEER_CLOSED', 'SERVER_STOPPED'))
        need(row['caseId'] in (*CASES, 'none') and row['reason'] == ('PEER_CLOSED' if row['event'] == 'PEER_CLOSED' else 'OK'))
        integer(row['bodyBytes'], 0, BODY_LIMIT + 1); integer(row['framedBytes'], row['bodyBytes'], BODY_LIMIT + 64)
        if row['event'] == 'SERVER_STOPPED':
            need(index == 23 and row['caseId'] == 'none' and row['bodyBytes'] == row['framedBytes'] == 0); continue
        groups.setdefault(row['caseId'], []).append(row)
        if row['event'] == 'REQUEST':
            need(row['bodyBytes'] == row['framedBytes'] == 0); requests.append(row['caseId'])
    need(requests == ['none', *CASES] and set(groups) == {'none', *CASES})
    for case, group in groups.items():
        writes = [(r['bodyBytes'], r['framedBytes']) for r in group if r['event'] == 'WRITE_RETURNED']
        expected = [(199, 199)] if case == 'none' else [(6, 6), (5, 5)] if case == 'split-success' else [
            (524288, 524288), (524288, 524288)] if case == 'boundary-success' else [
            (524288, 524297), (524289, 524298), (0, 5)] if case == 'oversize' else [(6, 6)]
        need(writes == expected)
        events = ['REQUEST', *['WRITE_RETURNED'] * len(expected), *(['PEER_CLOSED'] if case == 'abort' else []), 'COMPLETE']
        need([r['event'] for r in group] == events)
        total = dict(bodyBytes=sum(b for b, _ in writes), framedBytes=sum(f for _, f in writes))
        need(all(group[-1][k] == v for k, v in total.items()))
        if case == 'abort': need(all(group[-2][k] == v for k, v in total.items()))


def decode(raw):
    def unique(rows):
        out = {}
        for key, value in rows: need(key not in out); out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))


def read(path, maximum=1 << 20):
    import os
    import stat
    before = path.lstat(); need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as handle: raw = handle.read(maximum + 1)
        after, named = os.fstat(fd), path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_nlink)
        need(identity(before) == identity(opened) == identity(after) == identity(named) and len(raw) == before.st_size
             and before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns)
        return raw
    finally: os.close(fd)


def git_bytes(repo, commit, relative):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), 'show', commit + ':' + relative], stderr=subprocess.DEVNULL)


def verify(directory, repo, commit, engine):
    need(re.fullmatch(r'[a-f0-9]{40}', commit) and engine in ('chrome-cdp', 'playwright'))
    need(not directory.is_symlink() and {p.name for p in directory.iterdir()} == PUBLIC)
    raw = {name: read(directory / name) for name in PUBLIC}
    need(all(b'PRIVATE KEY' not in body and b'Bearer ' not in body for body in raw.values()))
    d, p, iso, inputs, receipt, certs = [decode(raw[name]) for name in (
        'driver.json', 'processes.json', 'isolation.json', 'inputs.json', 'pin-consumption.json', 'certificates.json')]
    fixture = d['fixtureId']; need(type(fixture) is str and re.fullmatch(r'[a-f0-9]{32}', fixture))
    root, bundle = '/tmp/chengwang-stream-matrix-' + fixture, '/tmp/chengwang-stream-tools-' + fixture
    for value in (d, p, iso, inputs):
        need(value['sourceCommit'] == commit and value['engine'] == engine and value['fixtureId'] == fixture and value['production'] is False)
    need(iso['schema'] == p['schema'] == inputs['schema'] == 'chengwang.stream-matrix-supervisor/v1')
    exact(p, ('schema', 'sourceCommit', 'fixtureId', 'engine', 'records', 'serverExitCode', 'controllerExitCode',
              'noLiveOwnedProcesses', 'forcedSignals', 'processScope', 'production'))
    exact(inputs, ('schema', 'sourceCommit', 'fixtureId', 'engine', 'copiedInputs', 'inputTrustScope', 'production'))
    exact(iso, ('schema', 'sourceCommit', 'fixtureId', 'engine', 'hostBefore', 'hostAfter', 'sourceFilesBefore',
               'sourceFilesAfter', 'lab', 'production', 'authorization', 'deviceActionsExecuted', 'pythonBinaryProvenanceProven'))
    need(p['processScope'] == 'TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION'
         and inputs['inputTrustScope'] == 'SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    need(iso['authorization'] == 'BLOCKED' and iso['deviceActionsExecuted'] is False and iso['pythonBinaryProvenanceProven'] is False)
    strict_same(iso['hostBefore'], iso['hostAfter']); strict_same(iso['sourceFilesBefore'], iso['sourceFilesAfter'])
    host = iso['hostBefore']
    exact(host, ('netNamespace', 'mountNamespace', 'pidNamespace', 'userNamespace', 'portStart', 'systemCASHA256', 'sourceSHA256'))
    integer(host['portStart'], 0, 65535)
    for k, prefix in [('netNamespace','net'), ('mountNamespace','mnt'), ('pidNamespace','pid'), ('userNamespace','user')]:
        need(type(host[k]) is str and re.fullmatch(prefix + r':\[[0-9]+\]', host[k]))
    for k in ('systemCASHA256', 'sourceSHA256'): need(type(host[k]) is str and re.fullmatch(r'[a-f0-9]{64}', host[k]))
    sources = iso['sourceFilesBefore']; need(type(sources) is list and 1 <= len(sources) <= 8192)
    seen = set()
    for entry in sources:
        exact(entry, ('path', 'bytes', 'sha256')); relative = entry['path']
        need(type(relative) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+', relative) and relative not in seen
             and relative.startswith(('chengwang/', '.github/workflows/')) and '..' not in relative.split('/'))
        original = git_bytes(repo, commit, relative)
        integer(entry['bytes'], 0, 64 << 20); need(len(original) == entry['bytes'] and sha(original) == entry['sha256']); seen.add(relative)
    git_sources = subprocess.check_output(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo),
        'ls-tree', '-r', '-z', '--name-only', commit, '--', 'chengwang', '.github/workflows'], stderr=subprocess.DEVNULL)
    need(seen == {name.decode('utf-8') for name in git_sources.split(b'\0') if name})
    need(host['sourceSHA256'] == sha(json.dumps(sources,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')))
    for relative in ('chengwang/deploy/browser-stream-matrix/check_matrix.py', 'chengwang/deploy/browser-stream-matrix/run_matrix.py',
        'chengwang/tools/browser-runtime-candidate/pin.json', 'chengwang/tools/browser-stream-matrix/matrix-driver.mjs'):
        need(relative in seen)
    need(git_bytes(repo, commit, 'chengwang/deploy/browser-stream-matrix/check_matrix.py') == read(pathlib.Path(__file__)))
    lab = iso['lab']; exact(lab, ('namespaces', 'defaultIPv4Routes', 'defaultIPv6Routes', 'interfaces', 'sourceMount', 'bundleMount', 'tmpMount'))
    strict_same(lab['defaultIPv4Routes'], 0); strict_same(lab['defaultIPv6Routes'], 0); strict_same(lab['interfaces'], ['lo'])
    exact(lab['namespaces'], ('net', 'mnt', 'pid', 'user'))
    for k in ('net','mnt','pid','user'): need(type(lab['namespaces'][k]) is str and re.fullmatch(k + r':\[[0-9]+\]', lab['namespaces'][k]))
    need(lab['namespaces']['user'] == host['userNamespace'])
    for k in ('net', 'mnt', 'pid'): need(lab['namespaces'][k] != iso['hostBefore'][{'net':'netNamespace','mnt':'mountNamespace','pid':'pidNamespace'}[k]])
    for k in ('sourceMount', 'bundleMount'): need({'ro', 'nosuid', 'nodev'} <= set(lab[k]))
    need({'rw', 'nosuid', 'nodev', 'noexec'} <= set(lab['tmpMount']))
    need(receipt['sourceCommit'] == commit and receipt['state'] == 'PIN_ENFORCED_EXPANDED_NOT_EXECUTED'
         and receipt['pinSHA256'] == PIN_SHA and receipt['zip']['sha256'] == ZIP_SHA and receipt['zip']['bytes'] == 202676171
         and receipt['sourceFilesVerified'] == 5 and receipt['pinEnforced'] is True and receipt['allMemberCRCsVerified'] is True
         and receipt['actualExpandedFileHashesVerified'] is True and all(receipt[k] is False for k in ('browserExecuted', 'runtimeVersionProven', 'projectFixProven', 'publisherSignatureProven', 'production')))
    exact(receipt, ('schema', 'sourceCommit', 'state', 'pinSHA256', 'sourceFilesVerified', 'mode', 'zip',
        'expandedMemberCount', 'expandedBytes', 'expandedMembersSHA256', 'elf', 'pinEnforced', 'allMemberCRCsVerified',
        'actualExpandedFileHashesVerified', 'browserExecuted', 'runtimeVersionProven', 'projectFixProven',
        'publisherSignatureProven', 'production', 'limitations'))
    need(receipt['schema'] == 'chengwang.pinned-browser-consumption-verification/v1'
         and receipt['mode'] in ('PUBLIC_HTTPS_PINNED_ARCHIVE', 'EXISTING_PINNED_ARCHIVE'))
    strict_same(receipt['sourceFilesVerified'], 5)
    strict_same(receipt['zip'], dict(bytes=202676171, sha256=ZIP_SHA, md5Base64='5qChIL/Gh+8hZv73vzEakQ=='))
    strict_same(receipt['expandedMemberCount'], 309); strict_same(receipt['expandedBytes'], 425547397)
    need(receipt['expandedMembersSHA256'] == '527a3556f1a2db2d89dc0449c77594f2974d46eb54f50ab96d84d8d00ac3e171')
    strict_same(receipt['elf'], dict(path='chrome-linux64/chrome', bytes=305061192,
        sha256='ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444',
        byteOrder='little', **{'class':'ELF64'}, machine='x86_64', type='DYN', entryPoint=124443728,
        programHeaderCount=12, loadSegments=4))
    exact(d, ('schema', 'sourceCommit', 'engine', 'fixtureId', 'origin', 'runtime', 'mockedResponses', 'injectedFetch', 'tlsBypass',
              'limits', 'browser', 'chrome', 'normalTrust', 'tls', 'certificateChain', 'cases', 'counters', 'close', 'networkFile', 'production'))
    need(d['schema'] == 'chengwang.stream-matrix-driver/v1' and d['origin'] == ORIGIN and d['runtime'] is True
         and all(d[k] is False for k in ('mockedResponses', 'injectedFetch', 'tlsBypass')))
    strict_same(d['limits'], dict(bodyBytes=BODY_LIMIT, cases=5, requests=6))
    exact(d['browser'], ('product', 'revision', 'protocolVersion'))
    need(d['browser']['product'] in ('Chrome/157.0.8103.6', 'HeadlessChrome/157.0.8103.6')
         and d['browser']['revision'] == '@' + TAG and d['browser']['protocolVersion'] == '1.3')
    counter_names = ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'forbiddenRequests', 'unexpectedFailedRequests', 'captureErrors')
    exact(d['counters'], counter_names); need(all(type(v) is int and v == 0 for v in d['counters'].values()))
    cases = d['cases']; need(type(cases) is list and len(cases) == 5)
    network = [decode(line) for line in raw['network.jsonl'].splitlines()]
    validate_network(network, cases); validate_server([decode(line) for line in raw['server-events.jsonl'].splitlines()])
    need(d['networkFile'] == dict(path='network.private.jsonl', bytes=len(raw['network.jsonl']), sha256=sha(raw['network.jsonl']), records=18))
    copied = {e['path']: e for e in inputs['copiedInputs']}; need(len(copied) == len(inputs['copiedInputs']))
    source_map = {entry['path']: entry for entry in sources}
    for name, entry in copied.items():
        exact(entry, ('path', 'bytes', 'sha256')); integer(entry['bytes'], 0, 512 << 20)
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./@+:-]+', name) and '..' not in name.split('/'))
        need(type(entry['sha256']) is str and re.fullmatch(r'[a-f0-9]{64}', entry['sha256']))
        if name.startswith('chengwang/'):
            normalized = name.removesuffix(':launcher'); original = source_map.get(normalized)
            need(original is not None and all(entry[k] == original[k] for k in ('bytes', 'sha256')))
        else: need(name.startswith(('chrome/', 'npm/playwright-core/')) or name == 'toolchain/node')
    need({'chrome/chrome', 'toolchain/node', 'npm/playwright-core/package.json'} <= set(copied))
    need(copied['chrome/chrome']['sha256'] == receipt['elf']['sha256'] and copied['chrome/chrome']['bytes'] == receipt['elf']['bytes'])
    records = p['records']; need(type(records) is list and len(records) == 3)
    roles = {r['role']: r for r in records}; need(set(roles) == {'server', 'controller', 'chrome'})
    need(len({r['pid'] for r in records}) == 3 and p['serverExitCode'] == p['controllerExitCode'] == 0
         and type(p['forcedSignals']) is int and p['forcedSignals'] == 0 and p['noLiveOwnedProcesses'] is True)
    strict_same(p['serverExitCode'], 0); strict_same(p['controllerExitCode'], 0)
    for role, record in roles.items():
        exact(record, ('pid', 'startTime', 'exeSHA256', 'argvSHA256', 'uid', 'gid', 'groups', 'capabilities',
            'noNewPrivs', 'namespaces', 'limits', 'role', 'argv'))
        integer(record['pid'], 2); need(type(record['startTime']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', record['startTime']))
        need(record['uid'] == record['gid'] == [10001]*4 and record['groups'] == []
             and type(record['noNewPrivs']) is int and record['noNewPrivs'] == 1
             and all(value == '0000000000000000' for value in record['capabilities'].values())
             and record['namespaces'] == lab['namespaces'])
        strict_same(record['uid'], [10001]*4); strict_same(record['gid'], [10001]*4)
        strict_same(record['capabilities'], {k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')})
        strict_same(record['limits'], dict(cpuSeconds=[180,180],fileBytes=[32<<20]*2,openFiles=[1024]*2,processes=[1024]*2,coreBytes=[0,0]))
        need(type(record['argv']) is list and 1 <= len(record['argv']) <= 128 and all(type(a) is str and len(a) <= 4096 for a in record['argv']))
        need(sha(b''.join(a.encode() + b'\0' for a in record['argv'])) == record['argvSHA256'])
    c = d['chrome']; exact(c, ('pid', 'startTicks', 'uid', 'profile', 'argvSHA256', 'exeSHA256', 'exeBytes'))
    chrome, controller = roles['chrome'], roles['controller']
    strict_same(c['uid'], 10001); integer(c['pid'], 2); integer(c['exeBytes'], 1, 512 << 20)
    need(c['pid'] == chrome['pid'] and type(c['startTicks']) is int and c['startTicks'] == int(chrome['startTime'])
         and c['uid'] == 10001 and c['profile'] == root + '/chrome-profile'
         and c['argvSHA256'] == chrome['argvSHA256'] and c['exeSHA256'] == chrome['exeSHA256'] == receipt['elf']['sha256']
         and c['exeBytes'] == receipt['elf']['bytes'] and controller['exeSHA256'] == copied['toolchain/node']['sha256'])
    argv = chrome['argv']; need(argv[0] == bundle + '/chrome/chrome' and '--no-sandbox' in argv
        and [a for a in argv if a.startswith('--user-data-dir')] == ['--user-data-dir=' + root + '/chrome-profile'])
    forbidden = ('--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors', '--allow-insecure-localhost', '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure')
    need(not any(a.split('=',1)[0] in forbidden for a in argv))
    strict_same(controller['argv'], [bundle + '/node', bundle + '/source/chengwang/tools/browser-stream-matrix/matrix-cli.mjs',
        '--root', root, '--bundle', bundle, '--engine', engine, '--source-commit', commit])
    strict_same(roles['server']['argv'][1:], ['-I', '-B', bundle + '/source/chengwang/deploy/browser-stream-matrix/server.py', '--root', root])
    close = d['close']; exact(close, ('normalCloseCommandCompleted', 'chromeExit', 'launcherExit', 'noLiveOwnedProcesses', 'processScope'))
    need(close['normalCloseCommandCompleted'] is True and close['noLiveOwnedProcesses'] is True
         and close['processScope'] == 'CHROME_SESSION_AND_LAUNCHER_ONLY')
    strict_same(close['chromeExit'], dict(schema='chengwang.stream-matrix-chrome-exit/v1', engine=engine, fixtureId=fixture,
        pid=c['pid'], startTicks=c['startTicks'], exitCode=0, joined=True, forced=False))
    strict_same(close['launcherExit'], dict(code=0, signal=None) if engine == 'chrome-cdp' else None)
    verify_tls(certs, d, network)
    need({name: read(directory / name) for name in PUBLIC} == raw)
    return dict(schema='chengwang.stream-matrix-verification/v1', sourceCommit=commit, engine=engine, fixtureId=fixture,
        outcome='PASS', scope='SYNTHETIC_NORMAL_TLS_BROWSER_PROTOCOL_MATRIX_NOT_PRODUCT_UI_OR_PRODUCTION',
        pinConsumed=True, actualBrowser=d['browser'], actualELF=receipt['elf'], cases=5, requests=6, networkEvents=18,
        serverEvents=24, normalChromeExitCode=0, normalControllerExitCode=0, normalServerExitCode=0,
        allExpectedNegativeCasesObserved=True, sourceGitBlobs=len(sources), historicalCancellationRootCauseProven=False,
        patchAncestryProven=False, productE2EProven=False, newSubscriptionPageE2EProven=False,
        publisherSignatureProven=False, production=False, authorization='BLOCKED', evidenceSHA256={n:sha(raw[n]) for n in sorted(raw)})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=pathlib.Path)
    parser.add_argument('--repo', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp','playwright'))
    parser.add_argument('--report', required=True, type=pathlib.Path)
    args = parser.parse_args()
    evidence, report = args.evidence.resolve(strict=True), args.report.absolute()
    need(not args.evidence.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.exists() and not report.is_symlink())
    result = verify(evidence, args.repo.resolve(strict=True), args.source_commit, args.engine)
    with report.open('xb') as out: out.write((json.dumps(result,sort_keys=True,separators=(',',':'))+'\n').encode())
    print('STREAM_MATRIX_INDEPENDENT=PASS product_e2e_proven=false production=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('STREAM_MATRIX_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
