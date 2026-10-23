"""Synthetic unit-only checker fixtures; not native backend acceptance."""
from __future__ import annotations

import base64
import contextlib
import copy
import datetime
import functools
import hashlib
import io
import json
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import check_probe_readback as gate


HEAD = 'a' * 40
FIXTURE_ID = 'b' * 32
ROOT = '/tmp/chengwang-probe-readback-' + FIXTURE_ID
BUNDLE = '/tmp/chengwang-probe-harness-' + FIXTURE_ID
PREFIX = 'product-probe-readback-'
NAMES = ('limited', 'pass', 'restricted')
CODE = {'pass': 200, 'restricted': 403, 'limited': 429}
STATE = {'pass': 'available', 'restricted': 'restricted', 'limited': 'rate_limited'}


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode()


def instant(ns):
    seconds, fraction = divmod(ns, 10**9)
    base = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    return base + ('.' + str(fraction).rjust(9, '0').rstrip('0') if fraction else '') + 'Z'


def runner(schema, **extra):
    return dict(schema='chengwang.probe-readback-' + schema + '/v1', sourceCommit=HEAD, fixtureId=FIXTURE_ID,
                acceptanceScope='NATIVE_BACKEND_ONLY', browserE2EProven=False, authorization='BLOCKED',
                production=False, deviceActionsExecuted=False, **extra)


def driver(action, phase, **extra):
    return dict(schema='chengwang.probe-readback-driver/v1', sourceCommit=HEAD, fixtureId=FIXTURE_ID,
                action=action, phase=phase, authorization='BLOCKED', production=False,
                deviceActionsExecuted=False, **extra)


def make_certificates(directory):
    executable = shutil.which('openssl')
    if executable is None:
        git = shutil.which('git')
        if git:
            candidate = pathlib.Path(git).parent.parent / 'usr/bin/openssl.exe'
            if candidate.is_file(): executable = str(candidate)
    if executable is None:
        raise AssertionError('unit certificate tool missing; never skip')
    def run(*args):
        result = subprocess.run([executable, *args], cwd=directory, capture_output=True, timeout=10)
        if result.returncode: raise AssertionError('unit certificate generation failed')
    corpus = {}
    for service in ('dot', 'target', 'api'):
        run('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1', '-subj', '/CN=unit-' + service,
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', service + '-ca.key', '-out', service + '-ca.pem')
        run('req', '-new', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=unit-leaf-' + service,
            '-keyout', service + '-key.pem', '-out', service + '.csr')
        san = {'dot': 'DNS:dot.probe.example', 'target': ','.join('DNS:' + i + '.probe.example' for i in NAMES), 'api': 'IP:127.0.0.1'}[service]
        (directory / (service + '.ext')).write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=' + san + '\n')
        run('x509', '-req', '-in', service + '.csr', '-CA', service + '-ca.pem', '-CAkey', service + '-ca.key',
            '-set_serial', '20', '-days', '1', '-extfile', service + '.ext', '-out', service + '-leaf.pem')
        corpus[service + 'CARaw'] = b64((directory / (service + '-ca.pem')).read_bytes())
        corpus[service + 'LeafRaw'] = b64((directory / (service + '-leaf.pem')).read_bytes())
    return corpus


def synthetic_fixture(certificates):
    """Build independent synthetic bytes in product Go struct order."""
    base = (int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 10) * 10**9
    catalog = dict(schema='chengwang.probe-catalog/v1', revision='probe-readback-lab-v1',
                   agent=dict(id='probe-readback-agent', independence='P1', advisoryOnly=True),
                   paths=[dict(id='direct', kind='direct')], probes=[])
    for name in NAMES:
        target = dict(id=name, pathId='direct', kind='https', host=name + '.probe.example', port=443,
                      requestPath='/health', method='GET', expectedStatus=[200])
        if name == 'pass': target['requiredMarker'] = 'chengwang-probe-pass-v1'
        target.update(intervalSeconds=60, timeoutSeconds=2, ttlSeconds=120, maxBodyBytes=4096)
        catalog['probes'].append(target)
    catalog_raw = compact(catalog)
    catalog_digest = 'sha256:' + digest(catalog_raw)
    fixture, results, segment_bytes = {}, {}, {}
    prepared = driver('prepare', '', catalogRaw=b64(catalog_raw), catalogDigest=catalog_digest, certificates=certificates)
    fixture[PREFIX + 'prepare.json'] = compact(prepared) + b'\n'
    attempt_schedule = [('restricted', 48), ('limited', 58), ('pass', 65), ('restricted', 114), ('pass', 123), ('limited', 129)]
    starts = []
    for number, (name, seconds) in enumerate(attempt_schedule, 1):
        attempted = base + seconds * 10**9
        completed, dns_at = attempted + 4_000_000, attempted + 2_000_000
        expiry = completed + 120 * 10**9
        layers = {}
        for key in ('dns', 'connect', 'tls', 'http', 'business'):
            reason = {'dns': 'resolved_and_pinned', 'connect': 'tcp_connected', 'tls': 'tls_verified',
                      'http': 'http_response_received', 'business': {'pass': 'contract_matched', 'restricted': 'access_restricted', 'limited': 'rate_limited'}[name]}[key]
            item = dict(state=STATE[name] if key == 'business' else 'available',
                        observedAt=instant(dns_at if key == 'dns' else completed),
                        expiresAt=instant(dns_at + 120 * 10**9 if key == 'dns' else expiry),
                        latencyMillis=2 if key in ('dns', 'http') else 0)
            if key == 'business' and name == 'limited': item['retryAfterSeconds'] = 30
            item['reason'] = reason
            layers[key] = item
        body = ('chengwang-probe-' + name + '-v1\n').encode()
        result = dict(schemaVersion='chengwang.probe-result/v1', runId=f'unit-run-{number}', probeId=name,
                      catalogDigest=catalog_digest, agentId='probe-readback-agent', independence='P1', pathId='direct',
                      attemptedAt=instant(attempted), completedAt=instant(completed), expiresAt=instant(expiry),
                      conclusion=STATE[name], outcome='pass' if name == 'pass' else 'indeterminate',
                      stageTimings=dict(dnsMillis=2, connectMillis=0, tlsMillis=0, httpMillis=2, totalMillis=4),
                      httpStatus=CODE[name], responseBytes=len(body), contentDigest='sha256:' + digest(body))
        if name != 'pass': result['errorClass'] = STATE[name]
        result.update(evidenceRef=f'unit-start-{number}', advisoryOnly=True, layers=layers)
        results[result['runId']] = result
        payload = dict(schema='chengwang.probe-spool/v1', catalogDigest=catalog_digest, result=result)
        value = 'sha256:' + digest(compact(payload))
        name_on_disk = f'{completed:020d}-{value[7:23]}.json'
        segment_bytes[name_on_disk] = compact(dict(**payload, digest=value))
        starts.append(dict(startId=result['evidenceRef'], probeId=name, startedAt=instant(attempted - 1_000_000),
                           settledAt=result['completedAt'], resultRunId=result['runId']))
    manifests, latest_ledgers, snapshot_names = {}, {}, {}
    for phase, count, seq, observed in (('first', 3, 7, 66), ('final', 6, 13, 130)):
        selected = dict(list(segment_bytes.items())[:count])
        selected_results = dict(list(results.items())[:count])
        kept_starts = starts[:3] if phase == 'first' else starts[2:]
        rate = list(selected_results.values())[1 if phase == 'first' else -1]
        rate_ns = base + (58 if phase == 'first' else 129) * 10**9 + 4_000_000
        ledger = dict(schema='chengwang.probe-start-ledger/v2', catalogDigest=catalog_digest,
                      directoryDigest='sha256:' + digest((ROOT + '/ledger').encode()), agentId='probe-readback-agent',
                      sequence=seq, lastClock=instant(base + (65 if phase == 'first' else 129) * 10**9 + 5_000_000),
                      starts=kept_starts, rateLimits=[dict(probeId='limited', sourceRunId=rate['runId'],
                      observedAt=rate['completedAt'], notBefore=instant(rate_ns + 30 * 10**9))])
        ledger_sha = 'sha256:' + digest(compact(ledger))
        ledger_raw = compact(dict(**ledger, digest=ledger_sha))
        ledger_name = f'{seq:020d}-{ledger_sha[7:23]}.json'
        files = {'catalog.json': catalog_raw, 'spool/.probe-spool.lock': b'', 'ledger/.probe-start-ledger.lock': b''}
        files.update({'spool/segments/' + name: raw for name, raw in selected.items()})
        files['ledger/snapshots/' + ledger_name] = ledger_raw
        source = [dict(path=name, bytes=len(files[name]), sha256=digest(files[name])) for name in sorted(files)]
        tree_sha = digest(''.join(x['path'] + '\t' + str(x['bytes']) + '\t' + x['sha256'] + '\n' for x in source).encode())
        report = driver('collect', phase, observedAt=instant(base + observed * 10**9),
                        spoolSegments=[dict(name=name, raw=b64(raw), sha256=digest(raw)) for name, raw in sorted(selected.items())],
                        ledgerSnapshots=[dict(name=ledger_name, raw=b64(ledger_raw), sha256=digest(ledger_raw))],
                        sourceFiles=source, sourceTreeSHA256=tree_sha)
        fixture[PREFIX + 'collect-' + phase + '.json'] = compact(report) + b'\n'
        manifests[phase], latest_ledgers[phase], snapshot_names[phase] = (files, source, tree_sha), ledger, ledger_name
    final_files, final_source, final_tree = manifests['final']
    entries = []
    directories = {'spool/.': 3, 'spool/segments': 2, 'ledger/.': 3, 'ledger/snapshots': 2}
    for index, name in enumerate(sorted((set(final_files) - {'catalog.json'}) | set(directories)), 10):
        is_dir = name in directories
        entries.append(dict(path=name, kind='directory' if is_dir else 'file', modeGo=(1 << 31) | 0o700 if is_dir else 0o600,
                            uid=10001, gid=10001, nlink=directories[name] if is_dir else 1, bytes=0 if is_dir else len(final_files[name]),
                            sha256='directory' if is_dir else digest(final_files[name]), deviceMajor=1, deviceMinor=0, inode=index))
    snapshot_digest = 'sha256:' + digest(''.join('\0'.join(str(entry[key]) for key in ('path', 'bytes', 'modeGo', 'uid', 'gid', 'nlink', 'sha256')) + '\0' for entry in entries).encode())
    catalog_metadata = dict(path='catalog.json', kind='file', modeGo=0o600, uid=10001, gid=10001, nlink=1,
                            bytes=len(catalog_raw), sha256=digest(catalog_raw), deviceMajor=1, deviceMinor=0, inode=1)
    for phase in ('before', 'after'):
        fixture[PREFIX + 'source-metadata-' + phase + '.json'] = compact(runner('source-metadata', phase=phase, snapshotDigest=snapshot_digest,
                catalog=catalog_metadata, entries=entries)) + b'\n'
    for phase, cache_seconds, observed_seconds in (('fresh', 132, 133), ('restarted', 140, 141), ('expired', 250, 251)):
        expired = phase == 'expired'
        cached = base + cache_seconds * 10**9
        min_expiry = base + 168 * 10**9 + 2_000_000
        coverage = dict(declaredTargets=3, targetsWithSamples=0 if expired else 3, targetsMissing=3 if expired else 0,
                        retainedSamples=0 if expired else 6, validTotal=6, expiredTotal=6 if expired else 0,
                        eligibleTotal=0 if expired else 6, rejectedTotal=0, truncated=False, partial=expired)
        status = dict(schema='chengwang.probe-view-status/v1', configured=True, running=True, advisoryOnly=True,
                      state='partial' if expired else 'ready', reason='evidence_expired' if expired else 'ok',
                      clockHealthy=True, storageHealthy=True, cachedAt=instant(cached),
                      expiresAt=instant(cached + 30 * 10**9 if expired else min(cached + 30 * 10**9, min_expiry)), coverage=coverage)
        targets = []
        for name in NAMES:
            latest = [r for r in results.values() if r['probeId'] == name][-1]
            target = dict(probeId=name, pathId='direct', state='unknown' if expired else STATE[name],
                          reason='no_current_evidence' if expired else {'pass': 'two_consecutive_contract_matches', 'limited': 'rate_limited', 'restricted': 'restricted'}[name])
            if not expired: target.update(observedAt=latest['completedAt'], expiresAt=latest['expiresAt'])
            target.update(consecutiveSuccess=2 if name == 'pass' and not expired else 0, consecutiveFailure=0, retainedSamples=0 if expired else 2)
            targets.append(target)
        samples = []
        if not expired:
            for result in results.values():
                samples.append({key: result[key] for key in ('runId', 'probeId', 'pathId', 'attemptedAt', 'completedAt', 'expiresAt',
                                'conclusion', 'outcome', 'httpStatus', 'responseBytes', 'errorClass', 'layers') if key in result})
        details = dict(schema='chengwang.probe-view-details/v1', status=status, catalogDigest=catalog_digest,
                       agentId='probe-readback-agent', independence='P1', advisoryOnly=True, targets=targets, samples=samples,
                       rejections=dict(format=0, integrity=0, catalog=0, future=0, duplicate=0, semantic=0))
        offline = dict(schema='chengwang.probe-state-validation/v1', catalogDigest=catalog_digest, snapshotDigest=snapshot_digest,
                       readPathDigest='sha256:' + digest((ROOT + '/spool\0' + ROOT + '/ledger').encode()),
                       ledgerWriterPathDigest=latest_ledgers['final']['directoryDigest'], relationshipScope='latest-ledger-vs-retained-spool',
                       spoolResults=6, ledgerSnapshots=1, latestSequence=13, latestStarts=4, latestInFlight=0, latestSettled=4,
                       latestRateLimits=1, advisoryOnly=True, readOnlyValidation=True, securityMetadataVerified=True,
                       ownerUid=10001, ownerGid=10001, expectedOwnerUid=10001, expectedOwnerGid=10001,
                       missingRetainedEvidence=0, relationshipComplete=True)
        requests = [dict(name=name, httpStatus=code) for name, code in (('status', 200), ('unauthenticated-details', 401), ('foreign-scope-details', 403), ('details', 200))]
        report = driver('verify', phase, observedAt=instant(base + observed_seconds * 10**9), status=status, details=details,
                        requests=requests, offline=offline, sourceFiles=final_source, sourceTreeSHA256=final_tree)
        fixture[PREFIX + 'verify-' + phase + '.json'] = compact(report) + b'\n'
        fixture[PREFIX + 'api-' + phase + '-status.json'] = compact(status) + b'\n'
        fixture[PREFIX + 'api-' + phase + '-details.json'] = compact(details) + b'\n'
    events = []
    def event(number, service, name, **extras):
        value = dict(schema='chengwang.probe-wire-event/v1', ordinal=len(events) + 1, monotonicNS=(len(events) + 1) * 100000,
                     connection=number, service=service, event=name, reason='ok' if name != 'close' else 'closed',
                     tls=name != 'connect', host='', queryType='', queryID=0, queryBytes=0, querySHA256='', requestBytes=0,
                     requestSHA256='', status=0, responseBytes=0, responseSHA256='', framedResponseBytes=0,
                     writtenBytes=0, complete=False, receivedUnixNano='')
        value.update(extras); events.append(value)
    connection_number = 0
    for result in results.values():
        name = result['probeId']; host = name + '.probe.example'
        attempt_ns = base + attempt_schedule[int(result['runId'].rsplit('-', 1)[1]) - 1][1] * 10**9
        for kind, delta in (('A', 500_000), ('AAAA', 1_500_000), ('http', 3_000_000)):
            connection_number += 1; service = 'https' if kind == 'http' else 'dot'
            event(connection_number, service, 'connect'); event(connection_number, service, 'tls')
            extras = dict(host=host, complete=True, receivedUnixNano=str(attempt_ns + delta))
            if kind == 'http':
                body = ('chengwang-probe-' + name + '-v1\n').encode()
                phrase = {200: 'OK', 403: 'Forbidden', 429: 'Too Many Requests'}[CODE[name]]
                response = (f'HTTP/1.1 {CODE[name]} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n' +
                            ('Retry-After: 30\r\n' if name == 'limited' else '') + 'Cache-Control: no-store\r\nConnection: close\r\n\r\n').encode() + body
                request = f'GET /health HTTP/1.1\r\nHost: {host}:443\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n'.encode()
                extras.update(status=CODE[name], requestBytes=len(request), requestSHA256=digest(request))
                framed = len(response)
            else:
                qid = 100 + connection_number
                question = b''.join(bytes((len(label),)) + label.encode() for label in host.split('.')) + b'\0' + struct.pack('!HH', 1 if kind == 'A' else 28, 1)
                query = struct.pack('!6H', qid, 0x0100, 1, 0, 0, 0) + question
                answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x08\x08\x04\x04' if kind == 'A' else b''
                response = struct.pack('!6H', qid, 0x8180, 1, int(kind == 'A'), 0, 0) + question + answer
                extras.update(queryType=kind, queryID=qid, queryBytes=len(query), querySHA256=digest(query))
                framed = len(response) + 2
            extras.update(responseBytes=len(response), responseSHA256=digest(response), framedResponseBytes=framed, writtenBytes=framed)
            event(connection_number, service, 'http' if kind == 'http' else 'dns', **extras)
            event(connection_number, service, 'close')
    fixture[PREFIX + 'wire-events.jsonl'] = b''.join(compact(e) + b'\n' for e in events)
    fixture[PREFIX + 'wire-ready.json'] = compact(dict(schema='chengwang.probe-wire-ready/v1', pid=10, uid=10001, gid=10001,
             dotAddress='127.0.0.1', dotPort=1853, httpsAddress='8.8.4.4', httpsPort=443, tls=True, deadlineSeconds=360)) + b'\n'
    fixture[PREFIX + 'wire-stopped.json'] = compact(dict(schema='chengwang.probe-wire-stopped/v1', pid=10, termination='term', accepted=18,
             closed=18, events=72, workerThreadsAlive=0, listenersClosed=True, normalStop=True)) + b'\n'
    source_files = sorted([dict(path='chengwang/cmd/probe-agent/main.go', bytes=1, sha256=digest(b'x'))] +
        [dict(path='chengwang/deploy/probe-readback/' + filename, bytes=len(role), sha256=digest(role.encode()))
         for role, filename in (('runner', 'run_probe_readback.py'), ('wire', 'fixture_probe_wire.py'))], key=lambda item: item['path'])
    source_sha = digest(json.dumps(source_files, sort_keys=True, separators=(',', ':')).encode())
    host = dict(netNamespace='net:[1]', mountNamespace='mnt:[2]', pidNamespace='pid:[3]', userNamespace='user:[401]', portStart=1024,
                systemCASHA256=digest(b'host-system-ca'), sourceSHA256=source_sha)
    namespace = dict(net='net:[101]', mnt='mnt:[201]', pid='pid:[301]', user='user:[401]')
    tools = [dict(role=role, inputSHA256=digest(role.encode()), actualSHA256=digest(role.encode())) for role in ('agent', 'server', 'driver', 'runner', 'wire')]
    isolation = runner('isolation', hostBefore=host, hostAfter=host, sourceFilesBefore=source_files, sourceFilesAfter=source_files,
        lab=dict(namespaces=namespace, interfaces=[dict(name='lo', flags=['LOOPBACK', 'LOWER_UP', 'UP'], addresses=[dict(family='inet', local='127.0.0.1', prefixlen=8), dict(family='inet', local='8.8.4.4', prefixlen=32)])],
                 routes4=[dict(type='local', dst='8.8.4.4', dev='lo', table='local', scope='host', gateway='')], routes6=[], portStart=0),
        sourceMount=dict(readOnly=True, mountFlags=['ro', 'nosuid', 'nodev']), tools=tools, pythonExecutable='/usr/bin/python3',
        agentCA=dict(targetPath='/etc/ssl/certs/ca-certificates.crt', sha256=digest(base64.b64decode(certificates['targetCARaw'])), readOnly=True, hostUnchanged=True),
        apiReadOnlyMounts=[dict(role=role, mounts=[dict(label=label, readOnly=True, mountFlags=['ro']) for label in ('catalog', 'spool', 'ledger')]) for role in ('api-first', 'api-second')])
    fixture[PREFIX + 'isolation.json'] = compact(isolation) + b'\n'
    process_records, exits = [], []
    for index, role in enumerate(('wire', 'agent', 'api-first', 'api-second')):
        ns = dict(namespace); ns['mnt'] = f'mnt:[{501 + index}]'
        if role == 'agent':
            argv = [BUNDLE + '/agent', '--catalog', ROOT + '/catalog.json', '--spool-dir', ROOT + '/spool', '--ledger-dir', ROOT + '/ledger', '--dot-upstream', '127.0.0.1:1853', '--dot-server-name', 'dot.probe.example', '--dot-ca', ROOT + '/dot-ca.pem', '--resolver-timeout', '2s', '--runner-timeout', '2s', '--concurrency', '1', '--queue-size', '3', '--starts-per-minute', '6']
        elif role == 'wire': argv = ['/usr/bin/python3', '-I', '-B', BUNDLE + '/wire', 'serve', '--fixture-root', ROOT, '--deadline-seconds', '360']
        else: argv = [BUNDLE + '/server']
        record = dict(role=role, pid=10 + index, startTime=str(100 + index), exeSHA256=digest(('python' if role == 'wire' else 'agent' if role == 'agent' else 'server').encode()),
                      argvSHA256=digest(b''.join(s.encode() + b'\0' for s in argv)), uid=[10001] * 4, gid=[10001] * 4, groups=[],
                      capabilities={key: '0' * 16 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}, noNewPrivs=1, namespaces=ns,
                      limits=dict(cpuSeconds=[120, 120], fileBytes=[32 << 20] * 2, openFiles=[256] * 2, processes=[256] * 2, coreBytes=[0, 0]))
        process_records.append(record)
        exits.append(dict(role=role, pid=record['pid'], startTime=record['startTime'], signal='SIGTERM', exitCode=0, joined=True, forced=False))
    fixture[PREFIX + 'processes.json'] = compact(runner('processes', processes=process_records, exits=exits)) + b'\n'
    phases = [dict(name=name, startedUnixNano=str(base + start * 10**9), finishedUnixNano=str(base + end * 10**9)) for name, start, end in (('fresh', 131, 134), ('restarted', 139, 142), ('expired', 250, 252))]
    fixture[PREFIX + 'runtime.json'] = compact(runner('runtime', startedUnixNano=str(base), finishedUnixNano=str(base + 252 * 10**9),
              minExpiryUnixNano=str(base + 168 * 10**9 + 2_000_000), maxExpiryUnixNano=str(base + 249 * 10**9 + 4_000_000), phases=phases,
              agentRunSeconds=130.0, labRunSeconds=252.0, wireConnections=18, wireEvents=72, sourceAssociation='UNIQUE_TARGET_AND_ATTEMPT_TIME_WINDOW')) + b'\n'
    fixture[PREFIX + 'cleanup.json'] = compact(runner('cleanup', ownedProcessesJoined=4, exitCodes=[0] * 4, forcedKills=0,
              privateFixtureRemoved=True, privateToolsRemoved=True, hostNamespaceUnchanged=True, hostSysctlUnchanged=True, hostCAUnchanged=True, sourceUnchanged=True, outcome='PASS')) + b'\n'
    fixture[PREFIX + 'outcome.json'] = compact(runner('outcome', outcome='PASS', inputFileCount=21, processCount=4, agentResults=6)) + b'\n'
    return fixture


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = tempfile.TemporaryDirectory(prefix='probe-readback-unit-ca-')
        cls.addClassCleanup(cls.authority.cleanup)
        cls.certificates = make_certificates(pathlib.Path(cls.authority.name))
        cls.original = synthetic_fixture(cls.certificates)
        actual_certificates = gate.certificates
        @functools.lru_cache(maxsize=16)
        def checked_certificates(items, first, final):
            return actual_certificates(dict(items), first, final)
        # Reuse only the exact real OpenSSL verification result for identical
        # public bytes AND validation times. A mutated corpus is a new key.
        patch = mock.patch.object(gate, 'certificates', side_effect=lambda corpus, first, final:
            checked_certificates(tuple(sorted(corpus.items())), first, final))
        patch.start(); cls.addClassCleanup(patch.stop)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='probe-readback-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.evidence = self.root / 'backend'; self.evidence.mkdir()
        for name, raw in self.original.items(): (self.evidence / name).write_bytes(raw)
        # Every negative starts from a complete independently accepted corpus;
        # rejection at an unrelated reader/crypto entrance cannot make it pass.
        self.assertEqual(gate.verify(self.evidence, HEAD)['outcome'], 'PASS')

    def json(self, name): return json.loads((self.evidence / (PREFIX + name + '.json')).read_bytes())

    def save(self, name, value): (self.evidence / (PREFIX + name + '.json')).write_bytes(compact(value) + b'\n')

    def mutate(self, name, change):
        value = self.json(name); change(value); self.save(name, value)

    def reject(self):
        with self.assertRaises(gate.Rejected): gate.verify(self.evidence, HEAD)

    def wire_mutate(self, change):
        path = self.evidence / (PREFIX + 'wire-events.jsonl')
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        change(events); path.write_bytes(b''.join(compact(e) + b'\n' for e in events))

    def test_synthetic_positive_is_backend_only_not_native_execution(self):
        result = gate.verify(self.evidence, HEAD)
        self.assertEqual(result['outcome'], 'PASS'); self.assertFalse(result['browserE2EProven'])
        self.assertFalse(result['actualInternetReachabilityProven']); self.assertFalse(result['agentIdentitySignatureProven'])
        self.assertEqual(len(result['evidenceSHA256']), 22)

    def test_cli_writes_new_report_outside_evidence(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = gate.main(['verify', '--evidence-dir', str(self.evidence), '--source-commit', HEAD, '--report', str(self.root / 'verification.json')])
        self.assertEqual(result, 0); self.assertIn('NATIVE_BACKEND_ONLY', stdout.getvalue())
        self.assertEqual(json.loads((self.root / 'verification.json').read_bytes())['schema'], gate.SCHEMA)

    def test_extra_or_missing_input_is_rejected(self):
        (self.evidence / 'secret.private').write_bytes(b'PRIVATE')
        self.reject(); (self.evidence / 'secret.private').unlink()
        (self.evidence / (PREFIX + 'wire-ready.json')).unlink(); self.reject()

    def test_duplicate_json_field_is_rejected(self):
        path = self.evidence / (PREFIX + 'prepare.json')
        path.write_bytes(path.read_bytes().replace(b'{', b'{"schema":"duplicate",', 1)); self.reject()

    def test_unknown_secret_field_is_rejected_and_suppressed(self):
        self.mutate('api-fresh-status', lambda r: r.update(token='PRIVATE-SENTINEL'))
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = gate.main(['verify', '--evidence-dir', str(self.evidence), '--source-commit', HEAD, '--report', str(self.root / 'reject.json')])
        self.assertEqual(result, 1); self.assertNotIn('SENTINEL', stderr.getvalue()); self.assertNotIn(str(self.root), stderr.getvalue())

    def test_wrong_source_commit_or_fixture_is_rejected(self):
        with self.assertRaises(gate.Rejected): gate.verify(self.evidence, 'c' * 40)
        self.mutate('collect-final', lambda r: r.update(fixtureId='c' * 32)); self.reject()

    def test_noncanonical_base64_is_rejected(self):
        self.mutate('prepare', lambda r: r.update(catalogRaw=r['catalogRaw'] + '\n')); self.reject()

    def test_catalog_target_or_digest_mutation_is_rejected(self):
        def change(r):
            raw = json.loads(base64.b64decode(r['catalogRaw'])); raw['probes'][0]['port'] = 8443
            r['catalogRaw'] = b64(compact(raw))
        self.mutate('prepare', change); self.reject()

    def test_raw_spool_sha_mutation_is_rejected(self):
        self.mutate('collect-final', lambda r: r['spoolSegments'][0].update(sha256='0' * 64)); self.reject()

    def test_spool_content_digest_with_rehashed_raw_is_rejected(self):
        def change(r):
            item = r['spoolSegments'][0]; value = json.loads(base64.b64decode(item['raw']))
            value['result']['contentDigest'] = 'sha256:' + '0' * 64
            raw = compact(value); item.update(raw=b64(raw), sha256=digest(raw))
        self.mutate('collect-final', change); self.reject()

    def test_spool_filename_or_traversal_is_rejected(self):
        self.mutate('collect-final', lambda r: r['spoolSegments'][0].update(name='../secret.json')); self.reject()

    def test_duplicate_run_or_start_binding_is_rejected(self):
        def change(r): r['spoolSegments'][1] = copy.deepcopy(r['spoolSegments'][0])
        self.mutate('collect-final', change); self.reject()

    def test_ledger_sequence_and_directory_binding_are_rejected(self):
        def change(r):
            item = r['ledgerSnapshots'][0]; value = json.loads(base64.b64decode(item['raw'])); value['directoryDigest'] = 'sha256:' + '0' * 64
            raw = compact(value); item.update(raw=b64(raw), sha256=digest(raw))
        self.mutate('collect-final', change); self.reject()

    def test_first_final_union_cannot_be_replaced_by_final_only(self):
        self.mutate('collect-first', lambda r: r.update(ledgerSnapshots=self.json('collect-final')['ledgerSnapshots'])); self.reject()

    def test_source_manifest_count_or_hash_mutation_is_rejected(self):
        self.mutate('collect-final', lambda r: r['sourceFiles'][0].update(bytes=0)); self.reject()

    def test_metadata_cannot_self_attest_wrong_mode(self):
        self.mutate('source-metadata-before', lambda r: r['entries'][0].update(modeGo=0o755)); self.reject()

    def test_metadata_inode_change_after_readback_is_rejected(self):
        self.mutate('source-metadata-after', lambda r: r['entries'][0].update(inode=r['entries'][0]['inode'] + 999)); self.reject()

    def test_offline_snapshot_hash_cannot_be_self_reported(self):
        self.mutate('verify-fresh', lambda r: r['offline'].update(snapshotDigest='sha256:' + '0' * 64)); self.reject()

    def test_api_raw_body_and_driver_projection_must_match(self):
        self.mutate('api-fresh-details', lambda r: r['samples'][0].update(responseBytes=999)); self.reject()

    def test_api_sample_green_after_expiry_is_rejected(self):
        details = self.json('api-fresh-details')
        self.mutate('verify-expired', lambda r: r['details'].update(samples=details['samples'])); self.reject()

    def test_expiry_window_cannot_be_widened(self):
        self.mutate('runtime', lambda r: r.update(maxExpiryUnixNano=str(int(r['maxExpiryUnixNano']) - 10**9))); self.reject()

    def test_denied_request_cannot_claim_success(self):
        self.mutate('verify-fresh', lambda r: r['requests'][1].update(httpStatus=200)); self.reject()

    def test_wire_truncated_eof_is_rejected(self):
        path = self.evidence / (PREFIX + 'wire-events.jsonl'); path.write_bytes(path.read_bytes()[:-1]); self.reject()

    def test_wire_missing_close_or_duplicate_ordinal_is_rejected(self):
        self.wire_mutate(lambda events: events[-1].update(ordinal=1)); self.reject()

    def test_wire_dns_digest_and_answer_binding_are_rejected(self):
        self.wire_mutate(lambda events: next(e for e in events if e['event'] == 'dns').update(responseSHA256='0' * 64)); self.reject()

    def test_wire_http_complete_send_is_required(self):
        self.wire_mutate(lambda events: next(e for e in events if e['event'] == 'http').update(writtenBytes=1, complete=False)); self.reject()

    def test_wire_received_time_must_uniquely_match_attempt(self):
        self.wire_mutate(lambda events: next(e for e in events if e['event'] == 'http').update(receivedUnixNano='1999999999999999999')); self.reject()

    def test_wire_has_no_invented_run_id_or_arbitrary_header(self):
        self.wire_mutate(lambda events: events[2].update(runId='invented')); self.reject()

    def test_ca_reuse_and_wrong_trust_are_rejected(self):
        self.mutate('prepare', lambda r: r['certificates'].update(apiCARaw=r['certificates']['targetCARaw'])); self.reject()

    def test_process_caps_argv_pid_or_namespace_cannot_be_faked(self):
        self.mutate('processes', lambda r: r['processes'][1]['capabilities'].update(CapEff='0000000000000001')); self.reject()

    def test_external_route_or_host_ca_change_is_rejected(self):
        self.mutate('isolation', lambda r: r['lab']['routes4'].append(dict(type='unicast', dst='default', dev='eth0', table='main', scope='global', gateway='1.1.1.1'))); self.reject()

    def test_forced_cleanup_and_boolean_exit_code_are_rejected(self):
        self.mutate('processes', lambda r: r['exits'][0].update(exitCode=False)); self.reject()


if __name__ == '__main__':
    names = sorted(unittest.defaultTestLoader.getTestCaseNames(CheckerTests))
    names_sha256 = digest(('\n'.join(names) + '\n').encode('ascii'))
    expected_sha256 = '772f67d373fd79722dcf5ede8cf553b5ab483d9fbef77c68deead5805d242d31'
    if len(names) != 32 or names_sha256 != expected_sha256:
        print('PROBE_READBACK_CHECKER_TESTS=FAIL fixed_names_mismatch=true', file=sys.stderr)
        raise SystemExit(1)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CheckerTests))
    accepted = result.wasSuccessful() and result.testsRun == 32 and not result.skipped
    if accepted:
        print('PROBE_READBACK_CHECKER_TESTS=PASS tests=32 passed=32 skipped=0 namesSHA256=' + names_sha256 +
              ' synthetic_only=true native_backend_not_proven=true')
    raise SystemExit(0 if accepted else 1)
