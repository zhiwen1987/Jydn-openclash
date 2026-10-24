"""Independent, backend-only probe laboratory evidence verifier.

It reads exported public bytes only. It never opens a live product database,
contacts an endpoint, runs Go, or treats a helper's success boolean as proof.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
SCHEMA = 'chengwang.probe-readback-gate/v1'
DRIVER_SCHEMA = 'chengwang.probe-readback-driver/v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
IDS = ('limited', 'pass', 'restricted')
HOSTS = {i: i + '.probe.example' for i in IDS}
BODIES = {i: ('chengwang-probe-' + i + '-v1\n').encode() for i in IDS}
CODES = {'pass': 200, 'restricted': 403, 'limited': 429}
STATES = {'pass': 'available', 'restricted': 'restricted', 'limited': 'rate_limited'}
COMMON = {'schema', 'sourceCommit', 'fixtureId', 'action', 'phase', 'authorization',
          'production', 'deviceActionsExecuted'}
COLLECT = {'observedAt', 'spoolSegments', 'ledgerSnapshots', 'sourceFiles', 'sourceTreeSHA256'}
VERIFY = {'observedAt', 'status', 'details', 'requests', 'offline', 'sourceFiles', 'sourceTreeSHA256'}
PHASES = ('fresh', 'restarted', 'expired')
REPORT_NAMES = ('prepare', 'collect-first', 'collect-final', 'verify-fresh',
                'verify-restarted', 'verify-expired')
STATUS_KEYS = {'schema', 'configured', 'running', 'advisoryOnly', 'state', 'reason',
               'clockHealthy', 'storageHealthy', 'coverage'}
COVERAGE_KEYS = {'declaredTargets', 'targetsWithSamples', 'targetsMissing', 'retainedSamples',
                 'validTotal', 'expiredTotal', 'eligibleTotal', 'rejectedTotal', 'truncated', 'partial'}
LAYER_FIELDS = ('state', 'observedAt', 'expiresAt', 'latencyMillis', 'retryAfterSeconds', 'reason')
LAYER_NAMES = ('dns', 'connect', 'tls', 'http', 'business')
RESULT_FIELDS = ('schemaVersion', 'runId', 'probeId', 'catalogDigest', 'agentId', 'independence',
                 'pathId', 'attemptedAt', 'completedAt', 'expiresAt', 'conclusion', 'outcome',
                 'stageTimings', 'httpStatus', 'responseBytes', 'contentDigest', 'errorClass',
                 'evidenceRef', 'advisoryOnly', 'layers')
RESULT_OPTIONAL = {'httpStatus', 'contentDigest', 'errorClass', 'evidenceRef'}
SAMPLE_FIELDS = ('runId', 'probeId', 'pathId', 'attemptedAt', 'completedAt', 'expiresAt',
                 'conclusion', 'outcome', 'httpStatus', 'responseBytes', 'errorClass', 'layers')
SAMPLE_OPTIONAL = {'httpStatus', 'responseBytes', 'errorClass'}
EVIDENCE_REASONS = frozenset(('access_restricted', 'canceled', 'catalog_digest_mismatch',
    'connect_failure', 'contract_matched', 'contract_mismatch', 'dns_failure', 'dns_timeout',
    'http_response_received', 'http_transport_failure', 'invalid_catalog', 'invalid_probe_id',
    'invalid_probe_input', 'invalid_resolved_target', 'not_observed', 'probe_canceled',
    'rate_limited', 'redirect_blocked', 'resolved_and_pinned', 'response_read_failed',
    'response_too_large', 'response_unusable', 'restricted', 'run_id_unavailable',
    'service_failure', 'target_not_allowlisted', 'tcp_connected', 'timeout', 'tls_failure',
    'tls_verified', 'transport_unavailable', 'unexpected_http_status'))


class Rejected(ValueError):
    """All diagnostics leaving the CLI are fixed and contain no input text."""


def require(condition):
    if not condition:
        raise Rejected('evidence-rejected')


def identical(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict:
        return set(actual) == set(expected) and all(identical(actual[key], expected[key]) for key in actual)
    if type(actual) is list:
        return len(actual) == len(expected) and all(identical(a, b) for a, b in zip(actual, expected))
    return actual == expected


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    # All laboratory scalar strings are ASCII. The explicit projections below
    # reproduce Go struct order and omitempty, never a caller's object order.
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def object_keys(value, required, optional=()):
    require(type(value) is dict and required <= set(value) <= required | set(optional))
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decoded(raw, *, source_manifest=False):
    require(type(raw) is bytes and 0 < len(raw) <= 2 << 20)
    require(type(source_manifest) is bool)
    try:
        value = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(Rejected()))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected('evidence-rejected') from None
    def bounded(item, depth=0, path=()):
        require(depth <= 24)
        if isinstance(item, dict):
            require(len(item) <= 512)
            for key, child in item.items():
                require(type(key) is str and len(key) <= 128)
                bounded(child, depth + 1, path + (key,))
        elif isinstance(item, list):
            # Only verify's exact isolation document opts into the existing
            # source_list budget. Nested/lookalike keys and every child keep
            # all ordinary depth, dictionary, string and list limits.
            maximum = 2000 if source_manifest and path in (('sourceFilesBefore',), ('sourceFilesAfter',)) else 1024
            require(len(item) <= maximum)
            for index, child in enumerate(item):
                bounded(child, depth + 1, path + (index,))
        elif isinstance(item, str):
            require(len(item) <= 1 << 20)
        else:
            require(item is None or type(item) in (int, bool) or type(item) is float and math.isfinite(item))
    bounded(value)
    return value


def base64_bytes(value, maximum):
    require(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3))
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Rejected('evidence-rejected') from None
    require(base64.b64encode(raw).decode() == value and len(raw) <= maximum)
    return raw


def integer(value, minimum=0, maximum=(1 << 63) - 1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def nanoseconds(value):
    require(type(value) is str)
    match = re.fullmatch(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z', value)
    require(match is not None)
    parts = list(map(int, match.groups()[:6]))
    try:
        dt = datetime.datetime(*parts, tzinfo=datetime.timezone.utc)
    except ValueError:
        raise Rejected('evidence-rejected') from None
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    delta = dt - epoch
    result = (delta.days * 86400 + delta.seconds) * 10**9 + int((match[7] or '').ljust(9, '0') or '0')
    require(0 < result < 1 << 63)
    return result


def read_file(path, maximum=2 << 20):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum)
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        require(os.path.samestat(before, opened))
        chunks, size = [], 0
        while True:
            part = os.read(fd, min(65536, maximum + 1 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
            require(size <= maximum)
        after = os.fstat(fd)
        named = path.lstat()
        require(os.path.samestat(before, after) and os.path.samestat(after, named))
        require((before.st_size, before.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns) ==
                (after.st_size, after.st_mtime_ns) == (named.st_size, named.st_mtime_ns))
        require(before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns)
        # Windows path stat and CRT descriptor stat expose different ctime
        # semantics. Each observation channel must still remain unchanged.
        # Native Linux evidence retains the strict cross-channel check too.
        if os.name != 'nt':
            require(before.st_ctime_ns == opened.st_ctime_ns)
        require(size == before.st_size)
        return b''.join(chunks)
    finally:
        os.close(fd)


def fixed_catalog():
    probes = []
    for name in IDS:
        target = dict(id=name, pathId='direct', kind='https', host=HOSTS[name], port=443,
                      requestPath='/health', method='GET', expectedStatus=[200])
        if name == 'pass':
            target['requiredMarker'] = 'chengwang-probe-pass-v1'
        target.update(intervalSeconds=60, timeoutSeconds=2, ttlSeconds=120, maxBodyBytes=4096)
        probes.append(target)
    return dict(schema='chengwang.probe-catalog/v1', revision='probe-readback-lab-v1',
                agent=dict(id='probe-readback-agent', independence='P1', advisoryOnly=True),
                paths=[dict(id='direct', kind='direct')], probes=probes)


def catalog(raw):
    value = decoded(raw)
    object_keys(value, {'schema', 'revision', 'agent', 'paths', 'probes'})
    require(type(value['probes']) is list and len(value['probes']) == 3)
    # The actual prepare file need not be sorted; its digest must canonicalize.
    canonical = dict(value)
    canonical['probes'] = sorted(value['probes'], key=lambda x: x.get('id', '') if isinstance(x, dict) else '')
    require(identical(canonical, fixed_catalog()))
    return 'sha256:' + sha(encoded(fixed_catalog()))


def layer(value):
    object_keys(value, set(LAYER_FIELDS) - {'retryAfterSeconds'}, {'retryAfterSeconds'})
    require(value['state'] in ('unknown', 'available', 'degraded', 'restricted', 'unavailable', 'rate_limited'))
    require(value['reason'] in EVIDENCE_REASONS)
    nanoseconds(value['observedAt']); nanoseconds(value['expiresAt'])
    integer(value['latencyMillis'], 0, 3000)
    if 'retryAfterSeconds' in value:
        integer(value['retryAfterSeconds'], 1, 3600)
    return {key: value[key] for key in LAYER_FIELDS if key in value}


def ordered_result(value):
    object_keys(value, set(RESULT_FIELDS) - RESULT_OPTIONAL, RESULT_OPTIONAL)
    require(value['probeId'] in IDS and value['pathId'] == 'direct' and
            value['agentId'] == 'probe-readback-agent' and value['independence'] == 'P1' and
            value['schemaVersion'] == 'chengwang.probe-result/v1' and value['advisoryOnly'] is True)
    require(type(value['runId']) is str and IDENTITY.fullmatch(value['runId']) is not None)
    require(type(value.get('evidenceRef')) is str and IDENTITY.fullmatch(value['evidenceRef']) is not None)
    object_keys(value['stageTimings'], {'dnsMillis', 'connectMillis', 'tlsMillis', 'httpMillis', 'totalMillis'})
    for number in value['stageTimings'].values(): integer(number, 0, 3000)
    object_keys(value['layers'], set(LAYER_NAMES))
    result = {key: value[key] for key in RESULT_FIELDS if key in value}
    result['stageTimings'] = {key: value['stageTimings'][key] for key in ('dnsMillis', 'connectMillis', 'tlsMillis', 'httpMillis', 'totalMillis')}
    result['layers'] = {key: layer(value['layers'][key]) for key in LAYER_NAMES}
    return result


def spool(raw, name, digest, observed):
    value = decoded(raw)
    object_keys(value, {'schema', 'catalogDigest', 'result', 'digest'})
    require(value['schema'] == 'chengwang.probe-spool/v1' and value['catalogDigest'] == digest)
    result = ordered_result(value['result'])
    require(result['catalogDigest'] == digest)
    actual = 'sha256:' + sha(encoded(dict(schema=value['schema'], catalogDigest=digest, result=result)))
    require(value['digest'] == actual)
    start, end, expiry = (nanoseconds(result[k]) for k in ('attemptedAt', 'completedAt', 'expiresAt'))
    require(start <= end <= observed and end - start <= 3 * 10**9 and expiry == end + 120 * 10**9)
    require(name == f'{end:020d}-{actual[7:23]}.json')
    probe_id = result['probeId']
    require(result['httpStatus'] == CODES[probe_id] and result['conclusion'] == STATES[probe_id])
    require(result['outcome'] == ('pass' if probe_id == 'pass' else 'indeterminate'))
    require(result['responseBytes'] == len(BODIES[probe_id]) and result['contentDigest'] == 'sha256:' + sha(BODIES[probe_id]))
    require(result.get('errorClass', '') == ('' if probe_id == 'pass' else STATES[probe_id]))
    require('errorClass' not in result if probe_id == 'pass' else True)
    for key, item in result['layers'].items():
        require(item['state'] == (STATES[probe_id] if key == 'business' else 'available'))
        when, until = nanoseconds(item['observedAt']), nanoseconds(item['expiresAt'])
        require(start <= when <= end and expiry - 3 * 10**9 <= until <= expiry)
        require(item.get('retryAfterSeconds', 0) == (30 if key == 'business' and probe_id == 'limited' else 0))
        expected_reason = {'dns': 'resolved_and_pinned', 'connect': 'tcp_connected', 'tls': 'tls_verified',
                           'http': 'http_response_received', 'business': {'pass': 'contract_matched',
                           'restricted': 'access_restricted', 'limited': 'rate_limited'}[probe_id]}[key]
        require(item['reason'] == expected_reason)
        if key != 'dns':
            require(item['observedAt'] == result['completedAt'] and item['expiresAt'] == result['expiresAt'])
        else:
            require(until >= when + 120 * 10**9)
    require(result['stageTimings']['totalMillis'] == (end - start) // 10**6 and
            result['stageTimings']['dnsMillis'] == (nanoseconds(result['layers']['dns']['observedAt']) - start) // 10**6)
    require(all(result['layers'][key]['latencyMillis'] == result['stageTimings'][key + 'Millis'] for key in ('dns', 'connect', 'tls', 'http')))
    require(result['layers']['business']['latencyMillis'] == 0)
    return result


def raw_entries(entries):
    require(type(entries) is list and 1 <= len(entries) <= 6)
    result = {}
    for item in entries:
        object_keys(item, {'name', 'raw', 'sha256'})
        require(type(item['name']) is str and re.fullmatch(r'[0-9]{20}-[a-f0-9]{16}\.json', item['name']))
        require(item['name'] not in result and type(item['sha256']) is str and HEX.fullmatch(item['sha256']))
        raw = base64_bytes(item['raw'], 64 << 10)
        require(sha(raw) == item['sha256'])
        result[item['name']] = raw
    require(list(result) == sorted(result))
    return result


def ledger(raw, name, digest, root, observed, sequence, results):
    value = decoded(raw)
    fields = ('schema', 'catalogDigest', 'directoryDigest', 'agentId', 'sequence', 'lastClock', 'starts', 'rateLimits')
    object_keys(value, set(fields) - {'rateLimits'} | {'digest'}, {'rateLimits'})
    require(value['schema'] == 'chengwang.probe-start-ledger/v2' and value['catalogDigest'] == digest and
            value['directoryDigest'] == 'sha256:' + sha((root + '/ledger').encode()) and value['agentId'] == 'probe-readback-agent')
    require(type(value['sequence']) is int and value['sequence'] == sequence)
    last = nanoseconds(value['lastClock']); require(last <= observed)
    require(type(value['starts']) is list and 1 <= len(value['starts']) <= 6)
    starts, joined = [], set()
    by_start = {r['evidenceRef']: r for r in results.values()}
    for item in value['starts']:
        object_keys(item, {'startId', 'probeId', 'startedAt', 'settledAt', 'resultRunId'})
        require(item['startId'] in by_start and item['startId'] not in joined)
        result = by_start[item['startId']]
        require(item['probeId'] == result['probeId'] and item['resultRunId'] == result['runId'] and item['settledAt'] == result['completedAt'])
        require(nanoseconds(item['startedAt']) <= nanoseconds(result['attemptedAt']) <= nanoseconds(item['settledAt']) <= last)
        joined.add(item['startId'])
        starts.append({key: item[key] for key in ('startId', 'probeId', 'startedAt', 'settledAt', 'resultRunId')})
    payload = {key: value[key] for key in fields if key in value}
    payload['starts'] = starts
    if 'rateLimits' in value:
        require(type(value['rateLimits']) is list and len(value['rateLimits']) == 1)
        rates = []
        for rate in value['rateLimits']:
            object_keys(rate, {'probeId', 'sourceRunId', 'observedAt', 'notBefore'})
            require(rate['probeId'] == 'limited' and rate['sourceRunId'] in results)
            match = results[rate['sourceRunId']]
            require(match['probeId'] == 'limited' and rate['observedAt'] == match['completedAt'] and
                    nanoseconds(rate['notBefore']) == nanoseconds(rate['observedAt']) + 30 * 10**9 and nanoseconds(rate['observedAt']) <= last)
            rates.append({key: rate[key] for key in ('probeId', 'sourceRunId', 'observedAt', 'notBefore')})
        payload['rateLimits'] = rates
    actual = 'sha256:' + sha(encoded(payload))
    require(value['digest'] == actual and name == f'{sequence:020d}-{actual[7:23]}.json')
    return value, joined


def source_files(value, expected):
    require(type(value) is list and len(value) == len(expected))
    seen = set()
    for item in value:
        object_keys(item, {'path', 'bytes', 'sha256'})
        name = item['path']
        require(type(name) is str and name in expected and name not in seen)
        raw = expected[name]
        require(type(item['bytes']) is int and item['bytes'] == len(raw) and item['sha256'] == sha(raw))
        seen.add(name)
    require([item['path'] for item in value] == sorted(expected))
    return sha(''.join(name + '\t' + str(len(expected[name])) + '\t' + sha(expected[name]) + '\n' for name in sorted(expected)).encode())


def sample_projection(result):
    return {key: result[key] for key in SAMPLE_FIELDS if key in result and
            (key not in SAMPLE_OPTIONAL or result[key] not in ('', 0, None))}


def status(value, expired):
    object_keys(value, STATUS_KEYS | {'cachedAt', 'expiresAt'})
    require(value['schema'] == 'chengwang.probe-view-status/v1')
    require(all(value[key] is True for key in ('configured', 'running', 'advisoryOnly', 'clockHealthy', 'storageHealthy')))
    require(value['state'] == ('partial' if expired else 'ready') and value['reason'] == ('evidence_expired' if expired else 'ok'))
    cached, expiry = nanoseconds(value['cachedAt']), nanoseconds(value['expiresAt'])
    require(cached < expiry <= cached + 30 * 10**9)
    c = object_keys(value['coverage'], COVERAGE_KEYS)
    wanted = dict(declaredTargets=3, targetsWithSamples=0 if expired else 3, targetsMissing=3 if expired else 0,
                  retainedSamples=0 if expired else 6, validTotal=6, expiredTotal=6 if expired else 0,
                  eligibleTotal=0 if expired else 6, rejectedTotal=0, truncated=False, partial=expired)
    require(identical(c, wanted))
    return cached


def api_details(value, status_value, results, expired):
    object_keys(value, {'schema', 'status', 'catalogDigest', 'agentId', 'independence', 'advisoryOnly', 'targets', 'samples', 'rejections'})
    require(value['schema'] == 'chengwang.probe-view-details/v1' and value['status'] == status_value and
            value['catalogDigest'] == next(iter(results.values()))['catalogDigest'] and value['agentId'] == 'probe-readback-agent' and
            value['independence'] == 'P1' and value['advisoryOnly'] is True)
    require(identical(value['rejections'], dict(format=0, integrity=0, catalog=0, future=0, duplicate=0, semantic=0)))
    require(type(value['targets']) is list and len(value['targets']) == 3 and [t.get('probeId') for t in value['targets']] == list(IDS))
    for target in value['targets']:
        fields = {'probeId', 'pathId', 'state', 'reason', 'consecutiveSuccess', 'consecutiveFailure', 'retainedSamples'}
        object_keys(target, fields, {'observedAt', 'expiresAt'})
        name = target['probeId']
        require(target['pathId'] == 'direct' and target['state'] == ('unknown' if expired else STATES[name]))
        reason = 'no_current_evidence' if expired else {'pass': 'two_consecutive_contract_matches', 'restricted': 'restricted', 'limited': 'rate_limited'}[name]
        require(target['reason'] == reason and type(target['consecutiveSuccess']) is int and type(target['consecutiveFailure']) is int and
                target['consecutiveSuccess'] == (2 if name == 'pass' and not expired else 0) and target['consecutiveFailure'] == 0 and
                type(target['retainedSamples']) is int and target['retainedSamples'] == (0 if expired else 2))
        latest = max((r for r in results.values() if r['probeId'] == name), key=lambda r: nanoseconds(r['completedAt']))
        if not expired:
            require(target.get('observedAt') == latest['completedAt'] and target.get('expiresAt') == latest['expiresAt'])
        else:
            require('observedAt' not in target and 'expiresAt' not in target)
    require(type(value['samples']) is list and len(value['samples']) == (0 if expired else 6))
    seen = set()
    for sample in value['samples']:
        object_keys(sample, set(SAMPLE_FIELDS) - SAMPLE_OPTIONAL, SAMPLE_OPTIONAL)
        name = sample['runId']
        require(name in results and name not in seen and identical(sample, sample_projection(results[name])))
        seen.add(name)


def dns_wire(host, kind, identifier):
    question = b''.join(bytes((len(label),)) + label.encode() for label in host.split('.')) + b'\0'
    question += struct.pack('!HH', 1 if kind == 'A' else 28, 1)
    query = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + question
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x08\x08\x04\x04' if kind == 'A' else b''
    response = struct.pack('!6H', identifier, 0x8180, 1, int(kind == 'A'), 0, 0) + question + answer
    return query, response


def http_wire(name):
    code = CODES[name]
    phrase = {200: 'OK', 403: 'Forbidden', 429: 'Too Many Requests'}[code]
    header = f'HTTP/1.1 {code} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {len(BODIES[name])}\r\n'
    if code == 429:
        header += 'Retry-After: 30\r\n'
    return (header + 'Cache-Control: no-store\r\nConnection: close\r\n\r\n').encode() + BODIES[name]


WIRE_KEYS = {'schema', 'ordinal', 'monotonicNS', 'connection', 'service', 'event', 'reason', 'tls', 'host',
             'queryType', 'queryID', 'queryBytes', 'querySHA256', 'requestBytes', 'requestSHA256', 'status',
             'responseBytes', 'responseSHA256', 'framedResponseBytes', 'writtenBytes', 'complete', 'receivedUnixNano'}


def wire_log(raw, ready, stopped, results):
    require(type(raw) is bytes and 0 < len(raw) <= 1 << 20 and raw.endswith(b'\n'))
    events = [decoded(line) for line in raw.splitlines()]
    require(len(events) == 72)
    object_keys(ready, {'schema', 'pid', 'uid', 'gid', 'dotAddress', 'dotPort', 'httpsAddress', 'httpsPort', 'tls', 'deadlineSeconds'})
    require(ready['schema'] == 'chengwang.probe-wire-ready/v1' and ready['uid'] == ready['gid'] == 10001 and
            ready['dotAddress'] == '127.0.0.1' and ready['dotPort'] == 1853 and ready['httpsAddress'] == '8.8.4.4' and
            ready['httpsPort'] == 443 and ready['tls'] is True and 10 <= integer(ready['deadlineSeconds']) <= 360)
    object_keys(stopped, {'schema', 'pid', 'termination', 'accepted', 'closed', 'events', 'workerThreadsAlive', 'listenersClosed', 'normalStop'})
    require(identical(stopped, dict(schema='chengwang.probe-wire-stopped/v1', pid=ready['pid'], termination='term', accepted=18,
                                  closed=18, events=72, workerThreadsAlive=0, listenersClosed=True, normalStop=True)))
    connections, last = {}, 0
    associations = {run: {} for run in results}
    default = dict(host='', queryType='', queryID=0, queryBytes=0, querySHA256='', requestBytes=0,
                   requestSHA256='', status=0, responseBytes=0, responseSHA256='', framedResponseBytes=0,
                   writtenBytes=0, complete=False, receivedUnixNano='')
    for ordinal, event in enumerate(events, 1):
        object_keys(event, WIRE_KEYS)
        require(event['schema'] == 'chengwang.probe-wire-event/v1' and type(event['ordinal']) is int and event['ordinal'] == ordinal)
        monotonic = integer(event['monotonicNS'], 1)
        require(monotonic >= last); last = monotonic
        number = integer(event['connection'], 1, 18)
        require(event['service'] in ('dot', 'https') and type(event['tls']) is bool and type(event['complete']) is bool)
        connections.setdefault(number, []).append(event)
        if event['event'] not in ('dns', 'http'):
            require(all(event[key] == value and type(event[key]) is type(value) for key, value in default.items()))
            continue
        require(event['tls'] is True and event['reason'] == 'ok' and event['complete'] is True)
        require(type(event['receivedUnixNano']) is str and re.fullmatch(r'[1-9][0-9]{18}', event['receivedUnixNano']))
        received = int(event['receivedUnixNano'])
        require(event['host'] in HOSTS.values())
        name = next(key for key, host in HOSTS.items() if host == event['host'])
        matches = [r for r in results.values() if r['probeId'] == name and nanoseconds(r['attemptedAt']) <= received <= nanoseconds(r['completedAt'])]
        require(len(matches) == 1)
        result = matches[0]
        label = 'http'
        if event['event'] == 'dns':
            require(event['service'] == 'dot' and event['queryType'] in ('A', 'AAAA') and received <= nanoseconds(result['layers']['dns']['observedAt']))
            identifier = integer(event['queryID'], 0, 65535)
            query, response = dns_wire(event['host'], event['queryType'], identifier)
            require(event['queryBytes'] == len(query) and event['querySHA256'] == sha(query) and event['requestBytes'] == 0 and event['requestSHA256'] == '' and event['status'] == 0)
            framed = len(response) + 2
            label = event['queryType']
        else:
            require(event['service'] == 'https' and received >= nanoseconds(result['layers']['dns']['observedAt']) and event['status'] == CODES[name])
            require(event['queryType'] == '' and event['queryID'] == event['queryBytes'] == 0 and event['querySHA256'] == '')
            # The only two allowed Host serializations differ by the explicit
            # default port. No arbitrary headers, path, body or token is trusted.
            requests = [(f'GET /health HTTP/1.1\r\nHost: {event["host"]}{port}\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n').encode() for port in ('', ':443')]
            require(any(event['requestBytes'] == len(request) and event['requestSHA256'] == sha(request) for request in requests))
            response = http_wire(name); framed = len(response)
        require(event['responseBytes'] == len(response) and event['responseSHA256'] == sha(response) and
                event['framedResponseBytes'] == framed and event['writtenBytes'] == framed)
        require(label not in associations[result['runId']])
        associations[result['runId']][label] = received
    require(set(connections) == set(range(1, 19)))
    for chain in connections.values():
        service = chain[0]['service']
        require([e['event'] for e in chain] == ['connect', 'tls', 'dns' if service == 'dot' else 'http', 'close'])
        require(all(e['service'] == service for e in chain))
        require(chain[0]['reason'] == 'ok' and chain[0]['tls'] is False and chain[1]['reason'] == 'ok' and chain[1]['tls'] is True and chain[-1]['reason'] == 'closed' and chain[-1]['tls'] is True)
    require(all(set(items) == {'A', 'AAAA', 'http'} and items['A'] <= items['AAAA'] <= items['http'] for items in associations.values()))
    return associations


def openssl_path():
    executable = shutil.which('openssl')
    if executable:
        return executable
    git = shutil.which('git')
    if git:
        candidate = pathlib.Path(git).parent.parent / 'usr' / 'bin' / 'openssl.exe'
        if candidate.is_file():
            return str(candidate)
    raise Rejected('crypto-unavailable')


def openssl(arguments, raw=None):
    try:
        result = subprocess.run([openssl_path(), *arguments], input=raw, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Rejected('crypto-unavailable') from None
    require(result.returncode == 0 and len(result.stdout) <= 65536 and len(result.stderr) <= 65536)
    return result.stdout


def certificates(corpus, first, final):
    keys = {'dotCARaw', 'targetCARaw', 'apiCARaw', 'dotLeafRaw', 'targetLeafRaw', 'apiLeafRaw'}
    object_keys(corpus, keys)
    raw = {key: base64_bytes(value, 16384) for key, value in corpus.items()}
    ders, public = {}, {}
    with tempfile.TemporaryDirectory(prefix='probe-readback-cert-check-') as directory:
        directory = pathlib.Path(directory)
        for key, pem in raw.items():
            require(re.fullmatch(rb'-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END CERTIFICATE-----\n', pem))
            ders[key] = openssl(['x509', '-inform', 'PEM', '-outform', 'DER'], pem)
            pub = openssl(['x509', '-pubkey', '-noout'], pem)
            public[key] = sha(openssl(['pkey', '-pubin', '-outform', 'DER'], pub))
            (directory / key).write_bytes(pem)
            basic = openssl(['x509', '-noout', '-ext', 'basicConstraints'], pem)
            require((b'CA:TRUE' if key.endswith('CARaw') else b'CA:FALSE') in basic)
        require(len({sha(ders[key]) for key in keys}) == 6 and len(set(public.values())) == 6)
        for service, names in (('dot', ('dot.probe.example',)), ('target', tuple(HOSTS.values())), ('api', ('127.0.0.1',))):
            authority, leaf = str(directory / (service + 'CARaw')), str(directory / (service + 'LeafRaw'))
            for when in (first, final):
                options = ['verify', '-no-CAfile', '-no-CApath', '-no-CAstore', '-trusted', authority, '-attime', str(when // 10**9)]
                openssl([*options, '-check_ss_sig', authority])
                for name in names:
                    openssl([*options, '-purpose', 'sslserver', '-verify_ip' if service == 'api' else '-verify_hostname', name, leaf])
    return {key: sha(value) for key, value in raw.items()}


RUNNER_COMMON = {'schema', 'sourceCommit', 'fixtureId', 'acceptanceScope', 'browserE2EProven',
                 'authorization', 'production', 'deviceActionsExecuted'}
META_FIELDS = {'path', 'kind', 'modeGo', 'uid', 'gid', 'nlink', 'bytes', 'sha256', 'deviceMajor', 'deviceMinor', 'inode'}
NAMESPACE_KEYS = {'net', 'mnt', 'pid', 'user'}


def common(value, schema, commit, fixture_id, extra):
    object_keys(value, RUNNER_COMMON | set(extra))
    require(value['schema'] == 'chengwang.probe-readback-' + schema + '/v1' and value['sourceCommit'] == commit and
            value['fixtureId'] == fixture_id and value['acceptanceScope'] == 'NATIVE_BACKEND_ONLY' and
            value['browserE2EProven'] is False and value['authorization'] == 'BLOCKED' and value['production'] is False and
            value['deviceActionsExecuted'] is False)


def metadata(value, phase, commit, fixture_id, files):
    common(value, 'source-metadata', commit, fixture_id, {'phase', 'snapshotDigest', 'catalog', 'entries'})
    require(value['phase'] == phase and type(value['entries']) is list)
    directories = {'spool/.', 'spool/segments', 'ledger/.', 'ledger/snapshots'}
    expected = set(files) - {'catalog.json'} | directories
    entries = value['entries']
    require(len(entries) == len(expected) and [entry.get('path') for entry in entries] == sorted(expected))
    for entry in [value['catalog'], *entries]:
        object_keys(entry, META_FIELDS)
        name = entry['path']
        require(name in expected or name == 'catalog.json')
        require(type(entry['uid']) is int and type(entry['gid']) is int and entry['uid'] == entry['gid'] == 10001)
        for key in ('deviceMajor', 'deviceMinor', 'inode'): integer(entry[key], 0 if key != 'inode' else 1)
        if name in directories:
            require(entry['kind'] == 'directory' and type(entry['modeGo']) is int and entry['modeGo'] == (1 << 31) | 0o700 and
                    entry['bytes'] == 0 and entry['sha256'] == 'directory')
            integer(entry['nlink'], 2, 32)
        else:
            require(entry['kind'] == 'file' and type(entry['modeGo']) is int and entry['modeGo'] == 0o600 and
                    type(entry['nlink']) is int and entry['nlink'] == 1 and type(entry['bytes']) is int and
                    entry['bytes'] == len(files[name]) and entry['sha256'] == sha(files[name]))
    require(value['catalog']['path'] == 'catalog.json')
    payload = ''.join('\0'.join(str(entry[key]) for key in ('path', 'bytes', 'modeGo', 'uid', 'gid', 'nlink', 'sha256')) + '\0' for entry in entries).encode()
    actual = 'sha256:' + sha(payload)
    require(value['snapshotDigest'] == actual)
    return actual


def namespaces(value):
    object_keys(value, NAMESPACE_KEYS)
    require(all(type(item) is str and re.fullmatch(r'(net|mnt|pid|user):\[[1-9][0-9]*\]', item) and item.startswith(key + ':') for key, item in value.items()))


def ro_mount(value):
    object_keys(value, {'readOnly', 'mountFlags'})
    require(value['readOnly'] is True)
    flags = value['mountFlags']
    if type(flags) is str:
        flags = flags.split(',')
    require(type(flags) is list and 1 <= len(flags) <= 32 and len(set(flags)) == len(flags) and
            all(type(flag) is str and re.fullmatch(r'[a-z0-9_=.-]{1,64}', flag) for flag in flags) and 'ro' in flags and 'rw' not in flags)


def source_list(value):
    require(type(value) is list and 1 <= len(value) <= 2000)
    previous = ''
    for entry in value:
        object_keys(entry, {'path', 'bytes', 'sha256'})
        name = entry['path']
        require(type(name) is str and previous < name and re.fullmatch(r'[A-Za-z0-9_.\-/]+', name) and
                all(part not in ('', '.', '..') for part in name.split('/')) and
                (name.startswith('chengwang/') or name.startswith('.github/workflows/')) and HEX.fullmatch(entry['sha256']))
        integer(entry['bytes'], 0, 16 << 20)
        previous = name


def isolation(value, commit, fixture_id, cert_hashes):
    extra = {'hostBefore', 'hostAfter', 'sourceFilesBefore', 'sourceFilesAfter', 'lab', 'sourceMount', 'tools', 'agentCA', 'apiReadOnlyMounts', 'pythonExecutable'}
    common(value, 'isolation', commit, fixture_id, extra)
    for host in (value['hostBefore'], value['hostAfter']):
        object_keys(host, {'netNamespace', 'mountNamespace', 'portStart', 'systemCASHA256', 'sourceSHA256', 'pidNamespace', 'userNamespace'})
        require(type(host['netNamespace']) is str and re.fullmatch(r'net:\[[1-9][0-9]*\]', host['netNamespace']) and
                type(host['mountNamespace']) is str and re.fullmatch(r'mnt:\[[1-9][0-9]*\]', host['mountNamespace']))
        integer(host['portStart'], 0, 65535)
        require(HEX.fullmatch(host['systemCASHA256']) and HEX.fullmatch(host['sourceSHA256']))
    require(value['hostBefore'] == value['hostAfter'])
    require(type(value['pythonExecutable']) is str and re.fullmatch(r'/[A-Za-z0-9_./-]{1,200}', value['pythonExecutable']) and
            all(part not in ('.', '..') for part in value['pythonExecutable'].split('/')))
    source_list(value['sourceFilesBefore']); source_list(value['sourceFilesAfter'])
    require(value['sourceFilesBefore'] == value['sourceFilesAfter'])
    require(sha(json.dumps(value['sourceFilesBefore'], sort_keys=True, separators=(',', ':')).encode('ascii')) == value['hostBefore']['sourceSHA256'])
    lab = object_keys(value['lab'], {'namespaces', 'interfaces', 'routes4', 'routes6', 'portStart'})
    namespaces(lab['namespaces'])
    require(lab['namespaces']['net'] != value['hostBefore']['netNamespace'] and lab['namespaces']['mnt'] != value['hostBefore']['mountNamespace'] and lab['portStart'] == 0)
    if 'pidNamespace' in value['hostBefore']:
        require(lab['namespaces']['pid'] != value['hostBefore']['pidNamespace'])
    if 'userNamespace' in value['hostBefore']:
        require(lab['namespaces']['user'] == value['hostBefore']['userNamespace'])
    require(type(lab['interfaces']) is list and len(lab['interfaces']) == 1)
    interface = object_keys(lab['interfaces'][0], {'name', 'flags', 'addresses'})
    require(interface['name'] == 'lo' and type(interface['flags']) is list and set(interface['flags']) == {'LOOPBACK', 'UP', 'LOWER_UP'})
    addresses = set()
    require(type(interface['addresses']) is list)
    for address in interface['addresses']:
        object_keys(address, {'family', 'local', 'prefixlen'})
        pair = (address['family'], address['local'], address['prefixlen'])
        require(pair in {('inet', '127.0.0.1', 8), ('inet', '8.8.4.4', 32), ('inet6', '::1', 128)} and pair not in addresses)
        addresses.add(pair)
    require({('inet', '127.0.0.1', 8), ('inet', '8.8.4.4', 32)} <= addresses)
    for family in ('routes4', 'routes6'):
        require(type(lab[family]) is list and len(lab[family]) <= 16)
        seen = set()
        for route in lab[family]:
            object_keys(route, {'type', 'dst', 'dev', 'table', 'scope', 'gateway'})
            require(route['dev'] == 'lo' and route['gateway'] == '' and route['type'] in ('local', 'broadcast', 'multicast', 'unicast'))
            require(type(route['dst']) is str and route['dst'] not in ('default', '0.0.0.0/0', '::/0'))
            require(re.fullmatch(r'127\.[0-9./]+', route['dst']) or route['dst'] in ('8.8.4.4', '8.8.4.4/32', '::1', '::1/128', 'ff00::/8'))
            require(route['table'] in ('local', 'main', 255, 254, '') and route['scope'] in ('host', 'link', 'global', ''))
            key = encoded(route); require(key not in seen); seen.add(key)
    ro_mount(value['sourceMount'])
    require(type(value['tools']) is list and len(value['tools']) == 5)
    tools = {}
    for tool in value['tools']:
        object_keys(tool, {'role', 'inputSHA256', 'actualSHA256'})
        require(tool['role'] in ('agent', 'server', 'driver', 'runner', 'wire') and tool['role'] not in tools and
                HEX.fullmatch(tool['inputSHA256']) and tool['inputSHA256'] == tool['actualSHA256'])
        tools[tool['role']] = tool['actualSHA256']
    source_hashes = {entry['path']: entry['sha256'] for entry in value['sourceFilesBefore']}
    for role, filename in (('runner', 'run_probe_readback.py'), ('wire', 'fixture_probe_wire.py')):
        require(tools[role] == source_hashes.get('chengwang/deploy/probe-readback/' + filename))
    ca = object_keys(value['agentCA'], {'targetPath', 'sha256', 'readOnly', 'hostUnchanged'})
    require(identical(ca, dict(targetPath='/etc/ssl/certs/ca-certificates.crt', sha256=cert_hashes['targetCARaw'], readOnly=True, hostUnchanged=True)))
    require(type(value['apiReadOnlyMounts']) is list and len(value['apiReadOnlyMounts']) == 2)
    seen = set()
    for process in value['apiReadOnlyMounts']:
        object_keys(process, {'role', 'mounts'})
        require(process['role'] in ('api-first', 'api-second') and process['role'] not in seen)
        seen.add(process['role'])
        require(type(process['mounts']) is list and len(process['mounts']) == 3)
        labels = set()
        for mount in process['mounts']:
            object_keys(mount, {'label', 'readOnly', 'mountFlags'})
            require(mount['label'] in ('catalog', 'spool', 'ledger') and mount['label'] not in labels)
            labels.add(mount['label'])
            ro_mount({key: mount[key] for key in ('readOnly', 'mountFlags')})
    return tools


def processes(value, commit, fixture_id, isolated, tools, wire_pid):
    common(value, 'processes', commit, fixture_id, {'processes', 'exits'})
    require(type(value['processes']) is list and len(value['processes']) == 4 and type(value['exits']) is list and len(value['exits']) == 4)
    role_order = ('wire', 'agent', 'api-first', 'api-second')
    require([item.get('role') for item in value['processes']] == list(role_order))
    require([item.get('role') for item in value['exits']] == ['agent', 'wire', 'api-first', 'api-second'])
    seen, pids, previous_start = {}, set(), 0
    for item in value['processes']:
        object_keys(item, {'role', 'pid', 'startTime', 'exeSHA256', 'argvSHA256', 'uid', 'gid', 'groups', 'capabilities', 'noNewPrivs', 'namespaces', 'limits'})
        role = item['role']
        require(role in ('wire', 'agent', 'api-first', 'api-second') and role not in seen)
        pid = integer(item['pid'], 2)
        require(pid not in pids); pids.add(pid)
        require(type(item['startTime']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', item['startTime']) and HEX.fullmatch(item['exeSHA256']) and HEX.fullmatch(item['argvSHA256']))
        # /proc starttime is measured in ticks, so distinct ordered launches
        # can legitimately have the same value within a scheduler tick.
        require(int(item['startTime']) >= previous_start)
        previous_start = int(item['startTime'])
        require(item['uid'] == item['gid'] == [10001] * 4 and item['groups'] == [] and type(item['noNewPrivs']) is int and item['noNewPrivs'] == 1)
        caps = object_keys(item['capabilities'], {'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'})
        require(all(value == '0000000000000000' for value in caps.values()))
        namespaces(item['namespaces'])
        require(all(item['namespaces'][key] == isolated['lab']['namespaces'][key] for key in ('net', 'pid', 'user')))
        require(item['namespaces']['mnt'] not in
                (isolated['lab']['namespaces']['mnt'], isolated['hostBefore']['mountNamespace']))
        if role != 'wire':
            require(item['exeSHA256'] == tools['agent' if role == 'agent' else 'server'])
        else:
            require(item['pid'] == wire_pid)
        root = '/tmp/chengwang-probe-readback-' + fixture_id
        bundle = '/tmp/chengwang-probe-harness-' + fixture_id
        if role == 'agent':
            argv = [bundle + '/agent', '--catalog', root + '/catalog.json', '--spool-dir', root + '/spool',
                    '--ledger-dir', root + '/ledger', '--dot-upstream', '127.0.0.1:1853', '--dot-server-name',
                    'dot.probe.example', '--dot-ca', root + '/dot-ca.pem', '--resolver-timeout', '2s',
                    '--runner-timeout', '2s', '--concurrency', '1', '--queue-size', '3', '--starts-per-minute', '6']
        elif role == 'wire':
            argv = [isolated['pythonExecutable'], '-I', '-B', bundle + '/wire', 'serve', '--fixture-root', root, '--deadline-seconds', '360']
        else:
            argv = [bundle + '/server']
        require(item['argvSHA256'] == sha(b''.join(argument.encode() + b'\0' for argument in argv)))
        limits = object_keys(item['limits'], {'cpuSeconds', 'fileBytes', 'openFiles', 'processes', 'coreBytes'})
        for key, maximum in (('cpuSeconds', 3600), ('fileBytes', 128 << 20), ('openFiles', 1024), ('processes', 1024), ('coreBytes', 0)):
            pair = limits[key]
            require(type(pair) is list and len(pair) == 2)
            low = integer(pair[0], 0 if key == 'coreBytes' else 1, maximum)
            integer(pair[1], low, maximum)
        seen[role] = item
    require(seen['api-first']['exeSHA256'] == seen['api-second']['exeSHA256'] and seen['api-first']['argvSHA256'] == seen['api-second']['argvSHA256'])
    # These two roles overlap. API roles instead start only after their
    # predecessors have joined; destroyed namespace inode numbers may be reused.
    # Ordered runner join records are lifecycle evidence, not independent exit
    # timestamps (the public schema deliberately contains no such timestamp).
    require(seen['wire']['namespaces']['mnt'] != seen['agent']['namespaces']['mnt'])
    exits = set()
    for item in value['exits']:
        object_keys(item, {'role', 'pid', 'startTime', 'signal', 'exitCode', 'joined', 'forced'})
        require(item['role'] in seen and item['role'] not in exits)
        original = seen[item['role']]
        require(identical(item, dict(role=item['role'], pid=original['pid'], startTime=original['startTime'], signal='SIGTERM', exitCode=0, joined=True, forced=False)))
        exits.add(item['role'])
    return seen


def decimal_ns(value):
    require(type(value) is str and re.fullmatch(r'[1-9][0-9]{18}', value))
    return int(value)


def runtime(value, commit, fixture_id, results):
    fields = {'startedUnixNano', 'finishedUnixNano', 'minExpiryUnixNano', 'maxExpiryUnixNano', 'phases',
              'agentRunSeconds', 'labRunSeconds', 'wireConnections', 'wireEvents', 'sourceAssociation'}
    common(value, 'runtime', commit, fixture_id, fields)
    first, final = decimal_ns(value['startedUnixNano']), decimal_ns(value['finishedUnixNano'])
    expiry = [nanoseconds(r['expiresAt']) for r in results.values()] + [nanoseconds(layer['expiresAt']) for r in results.values() for layer in r['layers'].values()]
    require(decimal_ns(value['minExpiryUnixNano']) == min(expiry) and decimal_ns(value['maxExpiryUnixNano']) == max(expiry))
    require(first < final and final - first <= 360 * 10**9)
    for key, maximum in (('agentRunSeconds', 150), ('labRunSeconds', 360)):
        number = value[key]
        require(type(number) in (int, float) and math.isfinite(number) and 0 < number <= maximum)
    require(abs(value['labRunSeconds'] - (final - first) / 10**9) < 0.01)
    require(value['wireConnections'] == 18 and value['wireEvents'] == 72 and value['sourceAssociation'] == 'UNIQUE_TARGET_AND_ATTEMPT_TIME_WINDOW')
    require(type(value['phases']) is list and len(value['phases']) == 3 and [p.get('name') for p in value['phases']] == list(PHASES))
    previous = first
    for phase in value['phases']:
        object_keys(phase, {'name', 'startedUnixNano', 'finishedUnixNano'})
        start, end = decimal_ns(phase['startedUnixNano']), decimal_ns(phase['finishedUnixNano'])
        require(previous <= start <= end <= final)
        require(start >= max(expiry) if phase['name'] == 'expired' else end < min(expiry))
        previous = end
    return first, final


def offline(value, root, snapshot_digest, last_ledger):
    fields = {'schema', 'catalogDigest', 'snapshotDigest', 'readPathDigest', 'ledgerWriterPathDigest', 'relationshipScope',
              'spoolResults', 'ledgerSnapshots', 'latestSequence', 'latestStarts', 'latestInFlight', 'latestSettled', 'latestRateLimits',
              'advisoryOnly', 'readOnlyValidation', 'securityMetadataVerified', 'ownerUid', 'ownerGid', 'expectedOwnerUid',
              'expectedOwnerGid', 'missingRetainedEvidence', 'relationshipComplete'}
    object_keys(value, fields)
    expected = dict(schema='chengwang.probe-state-validation/v1', catalogDigest=last_ledger['catalogDigest'], snapshotDigest=snapshot_digest,
                    readPathDigest='sha256:' + sha((root + '/spool\0' + root + '/ledger').encode()), ledgerWriterPathDigest=last_ledger['directoryDigest'],
                    relationshipScope='latest-ledger-vs-retained-spool', spoolResults=6, ledgerSnapshots=1, latestSequence=13,
                    latestStarts=len(last_ledger['starts']), latestInFlight=0, latestSettled=len(last_ledger['starts']),
                    latestRateLimits=len(last_ledger.get('rateLimits', [])), advisoryOnly=True, readOnlyValidation=True,
                    securityMetadataVerified=True, ownerUid=10001, ownerGid=10001, expectedOwnerUid=10001, expectedOwnerGid=10001,
                    missingRetainedEvidence=0, relationshipComplete=True)
    require(identical(value, expected))


PREFIX = 'product-probe-readback-'
INPUT_FILES = frozenset([PREFIX + name + '.json' for name in REPORT_NAMES] +
    [PREFIX + 'api-' + phase + '-' + kind + '.json' for phase in PHASES for kind in ('status', 'details')] +
    [PREFIX + 'wire-' + name for name in ('ready.json', 'events.jsonl', 'stopped.json')] +
    [PREFIX + name + '.json' for name in ('source-metadata-before', 'source-metadata-after', 'isolation', 'processes', 'runtime', 'cleanup', 'outcome')])


def verify(evidence_dir, source_commit):
    require(type(source_commit) is str and COMMIT.fullmatch(source_commit))
    evidence_dir = pathlib.Path(evidence_dir)
    require(evidence_dir.is_dir() and not evidence_dir.is_symlink())
    require(set(item.name for item in evidence_dir.iterdir()) == INPUT_FILES and len(INPUT_FILES) == 22)
    raw = {name: read_file(evidence_dir / name) for name in INPUT_FILES}
    data = {name: decoded(value, source_manifest=(name == PREFIX + 'isolation.json'))
            for name, value in raw.items() if name.endswith('.json')}
    reports = {name: data[PREFIX + name + '.json'] for name in REPORT_NAMES}
    prepare = reports['prepare']
    object_keys(prepare, COMMON | {'catalogRaw', 'catalogDigest', 'certificates'})
    fixture_id = prepare['fixtureId']
    require(type(fixture_id) is str and re.fullmatch(r'[a-f0-9]{32}', fixture_id))
    root = '/tmp/chengwang-probe-readback-' + fixture_id
    for name, report in reports.items():
        extension = {'catalogRaw', 'catalogDigest', 'certificates'} if name == 'prepare' else COLLECT if name.startswith('collect-') else VERIFY
        object_keys(report, COMMON | extension)
        action, phase = ('prepare', '') if name == 'prepare' else name.split('-', 1)
        require(report['schema'] == DRIVER_SCHEMA and report['sourceCommit'] == source_commit and report['fixtureId'] == fixture_id and
                report['action'] == action and report['phase'] == phase and report['authorization'] == 'BLOCKED' and
                report['production'] is False and report['deviceActionsExecuted'] is False)
    catalog_raw = base64_bytes(prepare['catalogRaw'], 256 << 10)
    catalog_digest = catalog(catalog_raw)
    require(prepare['catalogDigest'] == catalog_digest)
    corpus, ledgers, joins, input_files = {}, {}, {}, {}
    for phase, expected, sequence in (('first', 3, 7), ('final', 6, 13)):
        report = reports['collect-' + phase]
        observed = nanoseconds(report['observedAt'])
        segments, snapshots = raw_entries(report['spoolSegments']), raw_entries(report['ledgerSnapshots'])
        require(len(segments) == expected and len(snapshots) == 1)
        by_run, by_start, counts = {}, set(), {name: 0 for name in IDS}
        for name, body in segments.items():
            result = spool(body, name, catalog_digest, observed)
            require(result['runId'] not in by_run and result['evidenceRef'] not in by_start)
            by_run[result['runId']] = result; by_start.add(result['evidenceRef']); counts[result['probeId']] += 1
        require(set(counts.values()) == {expected // 3})
        ledger_name, ledger_raw = next(iter(snapshots.items()))
        value, joined = ledger(ledger_raw, ledger_name, catalog_digest, root, observed, sequence, by_run)
        require(len(joined) == 3 if phase == 'first' else len(joined) >= 3)
        files = {'catalog.json': catalog_raw, 'spool/.probe-spool.lock': b'', 'ledger/.probe-start-ledger.lock': b''}
        files.update({'spool/segments/' + name: body for name, body in segments.items()})
        files.update({'ledger/snapshots/' + name: body for name, body in snapshots.items()})
        require(report['sourceTreeSHA256'] == source_files(report['sourceFiles'], files))
        corpus[phase], ledgers[phase], joins[phase], input_files[phase] = by_run, value, joined, files
    require(set(corpus['first']) <= set(corpus['final']) and all(corpus['final'][key] == value for key, value in corpus['first'].items()))
    require(all(input_files['final'].get(name) == body for name, body in input_files['first'].items() if name.startswith('spool/')))
    require(len(joins['first'] | joins['final']) == 6)
    for start in joins['first'] & joins['final']:
        first = next(s for s in ledgers['first']['starts'] if s['startId'] == start)
        final = next(s for s in ledgers['final']['starts'] if s['startId'] == start)
        require(first == final)
    require(nanoseconds(ledgers['first']['lastClock']) < nanoseconds(ledgers['final']['lastClock']))
    results = corpus['final']
    # Every target must have distinct, nonoverlapping real attempts. The wire
    # request still does not contain a run ID; the join below is temporal.
    for target in IDS:
        pair = sorted((r for r in results.values() if r['probeId'] == target), key=lambda r: nanoseconds(r['attemptedAt']))
        require(nanoseconds(pair[0]['completedAt']) < nanoseconds(pair[1]['attemptedAt']) and
                nanoseconds(pair[1]['attemptedAt']) - nanoseconds(pair[0]['attemptedAt']) >= 48 * 10**9)
    runtime_value = data[PREFIX + 'runtime.json']
    first_ns, final_ns = runtime(runtime_value, source_commit, fixture_id, results)
    cert_hashes = certificates(prepare['certificates'], first_ns, final_ns)
    before = data[PREFIX + 'source-metadata-before.json']
    after = data[PREFIX + 'source-metadata-after.json']
    before_hash = metadata(before, 'before', source_commit, fixture_id, input_files['final'])
    after_hash = metadata(after, 'after', source_commit, fixture_id, input_files['final'])
    require(before_hash == after_hash and before['catalog'] == after['catalog'] and before['entries'] == after['entries'])
    isolated = data[PREFIX + 'isolation.json']
    tools = isolation(isolated, source_commit, fixture_id, cert_hashes)
    wire_ready, wire_stopped = data[PREFIX + 'wire-ready.json'], data[PREFIX + 'wire-stopped.json']
    wire_log(raw[PREFIX + 'wire-events.jsonl'], wire_ready, wire_stopped, results)
    process_records = processes(data[PREFIX + 'processes.json'], source_commit, fixture_id, isolated, tools, wire_ready['pid'])
    previous_observed = nanoseconds(reports['collect-final']['observedAt'])
    for phase in PHASES:
        report = reports['verify-' + phase]
        observed = nanoseconds(report['observedAt'])
        require(previous_observed <= observed <= final_ns)
        previous_observed = observed
        source_files(report['sourceFiles'], input_files['final'])
        require(report['sourceTreeSHA256'] == reports['collect-final']['sourceTreeSHA256'])
        status_name, details_name = (PREFIX + 'api-' + phase + '-' + key + '.json' for key in ('status', 'details'))
        require(raw[status_name].endswith(b'\n') and raw[details_name].endswith(b'\n') and len(raw[status_name]) <= 1 << 20 and len(raw[details_name]) <= 1 << 20)
        status_value, detail_value = data[status_name], data[details_name]
        require(status_value == report['status'] and detail_value == report['details'])
        cached = status(status_value, phase == 'expired')
        require(cached <= observed)
        expiries = [nanoseconds(r['expiresAt']) for r in results.values()] + [nanoseconds(item['expiresAt']) for r in results.values() for item in r['layers'].values()]
        if phase == 'expired':
            require(cached >= max(expiries))
        else:
            require(observed < min(expiries) and nanoseconds(status_value['expiresAt']) == min(cached + 30 * 10**9, min(expiries)))
        api_details(detail_value, status_value, results, phase == 'expired')
        offline(report['offline'], root, before_hash, ledgers['final'])
        require(type(report['requests']) is list and 4 <= len(report['requests']) <= 128)
        names = []
        for request in report['requests']:
            object_keys(request, {'name', 'httpStatus'})
            require(request['name'] in ('status', 'details', 'unauthenticated-details', 'foreign-scope-details') and
                    type(request['httpStatus']) is int and request['httpStatus'] == {'status': 200, 'details': 200, 'unauthenticated-details': 401, 'foreign-scope-details': 403}[request['name']])
            names.append(request['name'])
        require(names[0] == 'status' and names.count('unauthenticated-details') == names.count('foreign-scope-details') == 1 and
                names.index('unauthenticated-details') < names.index('foreign-scope-details') < names.index('details'))
        time_phase = next(item for item in runtime_value['phases'] if item['name'] == phase)
        require(decimal_ns(time_phase['startedUnixNano']) <= observed <= decimal_ns(time_phase['finishedUnixNano']))
    cleanup = data[PREFIX + 'cleanup.json']
    cleanup_fields = {'ownedProcessesJoined', 'exitCodes', 'forcedKills', 'privateFixtureRemoved', 'privateToolsRemoved',
                      'hostNamespaceUnchanged', 'hostSysctlUnchanged', 'hostCAUnchanged', 'sourceUnchanged', 'outcome'}
    common(cleanup, 'cleanup', source_commit, fixture_id, cleanup_fields)
    require(cleanup['ownedProcessesJoined'] == 4 and identical(cleanup['exitCodes'], [0] * 4) and type(cleanup['forcedKills']) is int and cleanup['forcedKills'] == 0 and cleanup['outcome'] == 'PASS')
    require(all(cleanup[key] is True for key in cleanup_fields - {'ownedProcessesJoined', 'exitCodes', 'forcedKills', 'outcome'}))
    outcome = data[PREFIX + 'outcome.json']
    common(outcome, 'outcome', source_commit, fixture_id, {'outcome', 'inputFileCount', 'processCount', 'agentResults'})
    require(outcome['outcome'] == 'PASS' and outcome['inputFileCount'] == 21 and outcome['processCount'] == 4 and outcome['agentResults'] == 6)
    return dict(schema=SCHEMA, outcome='PASS', sourceCommit=source_commit, fixtureId=fixture_id,
                authorization='BLOCKED', production=False, deviceActionsExecuted=False, advisoryOnly=True,
                acceptanceScope='NATIVE_BACKEND_ONLY', browserE2EProven=False,
                actualInternetReachabilityProven=False, agentIdentitySignatureProven=False,
                buildProvenanceScope='TRUSTED_CI_BUILD_INPUTS_NOT_INDEPENDENT_REBUILD',
                deniedAPIBodiesIndependentlyWitnessed=False, pythonBinaryProvenanceProven=False,
                processLifecycleScope='TRUSTED_RUNNER_ORDERED_JOINS_NOT_INDEPENDENT_EXIT_TIME_ATTESTATION',
                wireAssociation='UNIQUE_TARGET_AND_ATTEMPT_TIME_WINDOW', driverReports=6, spoolResults=6,
                firstLedgerSequence=7, finalLedgerSequence=13, settledUnion=6, dotQueries=12, httpsResponses=6,
                wireConnections=18, wireEvents=72, apiPhases=list(PHASES), sameInputBytesAfterReadback=True,
                normalStops=dict(agent=1, server=2, wire=1), sourceSnapshotDigest=before_hash,
                evidenceSHA256={name: sha(raw[name]) for name in sorted(raw)})


def write_exclusive(path, raw):
    path = pathlib.Path(path)
    require(path.parent.is_dir() and not path.parent.is_symlink())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def main(argv=None):
    class ClosedParser(argparse.ArgumentParser):
        def error(self, _message):
            raise Rejected('arguments-rejected')
    parser = ClosedParser(add_help=False)
    parser.add_argument('command', choices=('verify',))
    parser.add_argument('--evidence-dir', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=pathlib.Path)
    try:
        options = parser.parse_args(argv)
        require(options.report.parent.resolve() != options.evidence_dir.resolve())
        result = verify(options.evidence_dir, options.source_commit)
        write_exclusive(options.report, encoded(result) + b'\n')
    except (Rejected, OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        print('PROBE_READBACK_CHECK=FAIL rejected=true raw_input_suppressed=true', file=sys.stderr)
        return 1
    print('PROBE_READBACK_CHECK=PASS acceptance_scope=NATIVE_BACKEND_ONLY browser_e2e_proven=false authorization=BLOCKED production=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
