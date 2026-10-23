"""Synthetic offline contract tests; these never execute the actual lab."""
from __future__ import annotations

import base64
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

_spec = importlib.util.spec_from_file_location('subscription_independent_checker', Path(__file__).with_name('check_subscription_lab.py'))
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)
C = checker.contract
HEAD = 'a' * 40
FIXTURE = 'b' * 32
BINARY = hashlib.sha256(b'synthetic-server').hexdigest()
SOURCE_BLOBS = {'chengwang/synthetic.txt': b'synthetic-source', checker.WORKFLOW: b'synthetic-workflow'}
BASE_TIME = 1730000000000000000


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(nanos):
    seconds, fraction = divmod(nanos, 1000000000)
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.' + f'{fraction:09d}' + 'Z'


def identity(prefix, number):
    return prefix + f'{number:032x}'


def api_raw(capture, value):
    raw = encoded(value)
    capture['responseBase64'] = base64.b64encode(raw).decode()
    capture['responseSHA256'] = sha(raw)


def response(capture):
    return json.loads(base64.b64decode(capture['responseBase64']))


def change_response(capture, change):
    value = response(capture)
    change(value)
    api_raw(capture, value)


def captures(files):
    return [json.loads(x) for x in files['captures.jsonl'].splitlines()]


def set_captures(files, items):
    files['captures.jsonl'] = b''.join(encoded(x) for x in items)


def alter_capture(files, name, change):
    items = captures(files)
    item = next(x for x in items if x['name'] == name)
    change(item)
    set_captures(files, items)


def alter_object(files, name, change):
    value = json.loads(files[name])
    change(value)
    files[name] = encoded(value)


def alter_wire(files, change):
    events = [json.loads(x) for x in files['wire-events.jsonl'].splitlines()]
    change(events)
    files['wire-events.jsonl'] = b''.join(encoded(x) for x in events)
    items = captures(files)
    lines = files['wire-events.jsonl'].splitlines(keepends=True)
    for item in items:
        for key in ('wireBefore', 'wireAfter'):
            item[key]['sha256'] = sha(b''.join(lines[:item[key]['eventCount']]))
    set_captures(files, items)


def rewrite_audit(files, change):
    """Make semantic forgeries hash-consistent, including public receipts."""
    events = [json.loads(x) for x in files['audit-events.jsonl'].splitlines()]
    old_hashes = [event['hash'] for event in events]
    change(events)
    previous, replacements = '0' * 64, {}
    order = ('id', 'idempotencyKey', 'traceId', 'actorId', 'action', 'target', 'result',
             'occurredAt', 'data', 'previousHash', 'hash')
    for old, event in zip(old_hashes, events):
        event['previousHash'], event['hash'] = previous, ''
        ordered = {key: dict(sorted(event[key].items())) if key == 'data' else event[key] for key in order}
        event['hash'] = previous = sha(json.dumps(ordered, ensure_ascii=False, separators=(',', ':')).encode())
        replacements[old] = previous
    files['audit-events.jsonl'] = b''.join(encoded(event) for event in events)
    files['audit-checkpoint.json'] = encoded({'count': len(events), 'lastHash': previous})
    items = captures(files)
    for item in items:
        value = response(item)
        result = value.get('result')
        if type(result) is dict and 'commandId' in result:
            for key in ('preparedAuditHash', 'resultAuditHash'):
                result[key] = replacements[result[key]]
            api_raw(item, value)
    set_captures(files, items)


def synthetic_lab():
    """Fixed synthetic producer, not a runner/fixture import or real network."""
    sources = {'a': identity('src_', 1), 'b': identity('src_', 2)}
    candidates = {'a': identity('cand_', 1), 'b': identity('cand_', 2)}
    digests = {k: 'hmac-sha256:' + sha(k.encode()) for k in sources}
    baseline = [{'id': sources[k], 'scope': dict(C.SCOPE), 'label': 'source-' + k, 'revision': 3,
                 'acceptedCandidateId': candidates[k], 'latestCandidateId': candidates[k],
                 'updatedAt': stamp(BASE_TIME + (10 if k == 'a' else 11) * 1000000)} for k in ('a', 'b')]
    profile = {'pid': 1, 'startTicks': 100, 'uid': 10001, 'gid': 10001, 'capabilities': 'none',
               'noNewPrivileges': True, 'netNamespace': 'net:[2]', 'mountNamespace': 'mnt:[3]', 'pidNamespace': 'pid:[4]'}
    processes = []
    for epoch in range(4):
        processes.append({'epoch': epoch, 'pid': 10 + epoch, 'startTicks': 200 + epoch,
            'uid': 10001, 'gid': 10001, 'capabilities': 'none', 'noNewPrivileges': True,
            'netNamespace': 'net:[2]', 'executableSHA256': BINARY, 'argvSHA256': sha(b'/synthetic/server\0'),
            'startedUnixNano': str(BASE_TIME + epoch * 1000000000 - 1000000),
            'stoppedUnixNano': str(BASE_TIME + epoch * 1000000000 + 500000000),
            'stopSignal': 'SIGTERM', 'exitCode': 0, 'joined': True, 'forced': False})
    wire_process = dict(processes[0], pid=2, startTicks=101, executableSHA256=sha(b'python'),
        argvSHA256=sha(b'/synthetic/python\0'), startedUnixNano=str(BASE_TIME - 1000000000),
        stoppedUnixNano=str(BASE_TIME + 5000000000))
    wire_process.pop('epoch')
    rt = {'schema': 'chengwang.subscription-runtime/v1', 'sourceCommit': HEAD, 'fixtureId': FIXTURE,
          'serverBinarySHA256': BINARY, 'runnerProfile': profile, 'wireProcess': wire_process, 'processes': processes}
    audit_events, wire_events, items, success = [], [], [], {}
    approvals = {}
    previous = '0' * 64

    def append_audit(event):
        nonlocal previous
        event = dict(event, id=identity('evt_', len(audit_events) + 1), previousHash=previous, hash='')
        # Independently reproduce Go's declared struct order and sorted map.
        order = ('id', 'idempotencyKey', 'traceId', 'actorId', 'action', 'target', 'result',
                 'occurredAt', 'data', 'previousHash', 'hash')
        ordered = {k: dict(sorted(event[k].items())) if k == 'data' else event[k] for k in order}
        event['hash'] = previous = sha(json.dumps(ordered, ensure_ascii=False, separators=(',', ':')).encode())
        audit_events.append(event)
        return event['hash']

    def command_audit(name, command_id, kind, source, result, at, role):
        actor = 'act_' + ('a' if role == 'operator' else 'b') * 60
        target = 'subscription/' + (source if kind != 'create' else 'local')
        data = dict(C.SCOPE, managementObject='local', kind=kind,
                    commandDigest='hmac-sha256:' + sha(name.encode()))
        common = dict(traceId=command_id, actorId=actor, target=target)
        prepared = append_audit(dict(common, idempotencyKey='subscription/' + command_id + '/prepared',
            action='subscription.command.prepared', result='prepared', occurredAt=stamp(at - 500000), data=data))
        result_data = dict(data, state=result['state'], code=result.get('code', ''), sourceId=source,
            candidateId=result.get('candidateId', ''), revision=str(result['revision']),
            candidateDigest=result.get('candidateDigest', ''), localAuditHash=result.get('localAuditHash', ''),
            approvalId=result.get('approvalId', ''), policyDigest=result.get('policyDigest', ''),
            policyRevision=str(result.get('policyRevision', 0)), stateMayHaveChanged='false')
        result_hash = append_audit(dict(common, idempotencyKey='subscription/' + command_id + '/result',
            action='subscription.command.result', result='result', occurredAt=stamp(at - 100000), data=result_data))
        return prepared, result_hash

    def wire_emit(connection, service, kind, ref='', query='', status=0, count=0, tls=False, reason='ok', at=''):
        wire_events.append(dict(schema=C.EVENT_SCHEMA, ordinal=len(wire_events) + 1,
            connection=connection, service=service, event=kind, reference=ref, queryType=query,
            status=status, bytes=count, tls=tls, reason=reason, receivedUnixNano=at))

    connection_id = 0
    for ordinal, (name, epoch, status) in enumerate(C.CAPTURES, 1):
        at = BASE_TIME + epoch * 1000000000 + ordinal * 1000000
        role = ('anonymous' if name == 'anonymous_list' else 'foreign' if name == 'foreign_list' else
                'viewer' if name.startswith(('sources_', 'nodes_')) or name == 'viewer_create' else
                'other-operator' if name == 'other_actor_receipt' else
                'approver' if name.startswith(('approve_', 'admit_')) else 'operator')
        is_get = name.startswith(('sources_', 'nodes_')) or name in ('anonymous_list', 'foreign_list', 'other_actor_receipt', 'receipt_after_restart')
        method, body, key, path, header = 'GET', None, '', checker.BASE + '/sources', ''
        suffix = 'b' if name in ('create_b', 'approve_b', 'fetch_b', 'admit_b', 'nodes_b') else 'a'
        source = sources[suffix]
        if not is_get:
            method = 'POST'
            key = 'subscription-lab-' + ('fetch_a' if name in ('replay_fetch_a', 'replay_after_restart') else name)
            if name in ('create_a', 'create_b', 'viewer_create'):
                kind, body = 'create', {'label': 'source-' + suffix}
            elif name.startswith('approve_') or name == 'operator_approve_denied':
                kind = 'approve'
                ref = ('good-b' if name == 'approve_b' else 'good-a' if name in ('approve_a', 'approve_good_a', 'operator_approve_denied') else name[8:-2])
                body = {'referenceId': ref, 'policyRevision': 1, 'expectedRevision': 1 if name in ('approve_a', 'approve_b', 'operator_approve_denied') else 3}
                path += '/' + source + '/approvals'
            elif name.startswith('admit_'):
                kind = 'decide'
                body = {'candidateId': candidates[suffix], 'expectedRevision': 2, 'expectedDigest': digests[suffix], 'decision': 'admitted_local'}
                path += '/' + source + '/decisions'
            else:
                kind = 'fetch'
                approval = ('cmd_' + '0' * 32 if name == 'unapproved_fetch' else approvals['approve_a'] if name in
                    ('fetch_a', 'replay_fetch_a', 'replay_after_restart') else approvals['approve_b'] if name == 'fetch_b' else
                    approvals['approve_good_a'] if name in ('fetch_noop_after_restart', 'fetch_changed_policy', 'writes_locked') else approvals['approve_' + name[6:]])
                body = {'approvalId': approval, 'policyRevision': 1,
                        'expectedRevision': 1 if name in ('unapproved_fetch', 'fetch_a', 'fetch_b', 'replay_fetch_a', 'replay_after_restart') else 3}
                path += '/' + source + '/fetches'
        elif name.startswith('nodes_'):
            path += '/' + source + '/candidates/' + candidates[suffix] + '/nodes?limit=100&offset=0&revision=3'
        elif name in ('other_actor_receipt', 'receipt_after_restart'):
            path = checker.BASE + '/commands/' + success['fetch_a']['commandId']
        before = len(wire_events)
        if name in checker.FETCH_REFS:
            ref = checker.FETCH_REFS[name]
            services = [('dot', 'A'), ('dot', 'AAAA')] + ([] if ref == 'private' else [('https', '')])
            for service, query in services:
                connection_id += 1
                wire_emit(connection_id, service, 'connect')
                rejected = service == 'https' and ref in ('wrongca', 'wrongname')
                wire_emit(connection_id, service, 'tls', tls=not rejected, reason='failed' if rejected else 'ok')
                if not rejected:
                    if service == 'dot':
                        host = C.SOURCE_HOSTS[ref]
                        size = 2 + 12 + sum(len(x) + 1 for x in host.split('.')) + 1 + 4 + (16 if query == 'A' else 0)
                        wire_emit(connection_id, service, 'dns', ref, query, count=size, tls=True, at=str(at - 750000))
                    else:
                        body_length = len(b'proxies: [\n') if ref == 'bad' else 0 if ref == 'redirect' else 321
                        http_status = 302 if ref == 'redirect' else 200
                        header_raw = ('HTTP/1.1 ' + ('302 Found' if ref == 'redirect' else '200 OK') + '\r\nContent-Type: application/yaml\r\nContent-Length: ' + str(body_length) + '\r\n' +
                            ('Location: https://good-a.subscription.example/subscription\r\n' if ref == 'redirect' else '') + 'Cache-Control: no-store\r\nConnection: close\r\n\r\n').encode()
                        wire_emit(connection_id, service, 'http', ref, status=http_status,
                            count=64000 if ref == 'oversize' else len(header_raw) + body_length,
                            tls=True, reason='partial' if ref == 'oversize' else 'ok', at=str(at - 500000))
                wire_emit(connection_id, service, 'close', tls=not rejected, reason='failed' if rejected else 'closed')
        result = None
        if status == 200:
            if name.startswith('sources_'):
                result = {'sources': copy.deepcopy(baseline), 'total': 2}
            elif name.startswith('nodes_'):
                numbers = (1, 2) if suffix == 'a' else (3, 4)
                nodes = [dict(id=identity('node_', n), label='节点-' + identity('node_', n)[-8:], protocol='trojan', credentialConfigured=True, state='unknown') for n in numbers]
                result = {'nodes': nodes, 'total': 2, 'revision': 3}
            elif name in ('replay_fetch_a', 'receipt_after_restart', 'replay_after_restart'):
                result = copy.deepcopy(success['fetch_a'])
                result['replayed'] = name != 'receipt_after_restart'
            else:
                command_id = identity('cmd_', ordinal)
                state = 'approved' if kind == 'approve' else 'noop' if name == 'fetch_noop_after_restart' else 'committed'
                result = dict(commandId=command_id, kind=kind, sourceId=source,
                    revision=1 if kind == 'create' or kind == 'approve' and body['expectedRevision'] == 1 else 2 if name in ('fetch_a', 'fetch_b') else 3,
                    state=state, replayed=False, stateMayHaveChanged=False, auditRecorded=True, completedAt=stamp(at - 100000))
                if kind in ('fetch', 'decide'):
                    result.update(candidateId=candidates[suffix], candidateDigest=digests[suffix])
                if state == 'committed':
                    result['localAuditHash'] = sha(('local-' + name).encode())
                if state == 'approved':
                    result.update(referenceId=body['referenceId'], policyRevision=1,
                                  policyDigest='hmac-sha256:' + sha(('policy-' + name).encode()), approvalId=command_id)
                    approvals[name] = command_id
                prepared, result_hash = command_audit(name, command_id, kind, source, result, at, role)
                result.update(preparedAuditHash=prepared, resultAuditHash=result_hash)
                success[name] = copy.deepcopy(result)
        elif name in ('unapproved_fetch', 'fetch_changed_policy') or name in checker.FETCH_REFS:
            header = identity('cmd_', ordinal)
            failed = {'state': 'failed', 'revision': body['expectedRevision'], 'code': checker.ERRORS[name]}
            command_audit(name, header, 'fetch', source, failed, at, role)
        elif name != 'other_actor_receipt':
            category = 'read' if name in ('anonymous_list', 'foreign_list') else 'create' if name == 'viewer_create' else 'fetch' if name == 'writes_locked' else 'approve'
            trace = identity('denied_', ordinal)
            append_audit(dict(traceId=trace, actorId='act_' + 'c' * 60,
                idempotencyKey='subscription/' + trace, action='subscription.command.denied', target='subscription/local',
                result='denied', occurredAt=stamp(at - 100000), data={'category': category, 'classification': checker.ERRORS[name]}))
        envelope = dict(boundary=C.BOUNDARY, authorization='BLOCKED', deviceActionsExecuted=False, stateMayHaveChanged=False)
        envelope.update({'result': result} if status == 200 else {'code': checker.ERRORS[name]})
        item = dict(schema=C.CAPTURE_SCHEMA, ordinal=ordinal, name=name, epoch=epoch, method=method, path=path, status=status,
            requestPublic={'actorRole': role, 'body': body, 'idempotencyKey': key},
            tlsPeerDERBase64=base64.b64encode(b'synthetic-api-peer').decode(),
            wireBefore={'eventCount': before, 'sha256': sha(b''.join(encoded(e) for e in wire_events[:before]))},
            wireAfter={'eventCount': len(wire_events), 'sha256': sha(b''.join(encoded(e) for e in wire_events))},
            receivedUnixNano=str(at), commandIdHeader=header)
        api_raw(item, envelope)
        items.append(item)
    manifest = [{'path': path, 'bytes': len(raw), 'sha256': sha(raw)} for path, raw in sorted(SOURCE_BLOBS.items())]
    files = {'build.json': encoded(dict(schema='chengwang.subscription-build/v1', sourceCommit=HEAD,
        goVersion='go1.23.12', moduleMode='vendor', dependencyDownloads=False, authorization='BLOCKED', production=False,
        server={'name': 'server', 'bytes': len(b'synthetic-server'), 'sha256': BINARY})),
        'source-before.json': encoded(manifest), 'source-after.json': encoded(manifest),
        'runtime.json': encoded(rt), 'isolation.json': encoded(dict(schema='chengwang.subscription-isolation/v1',
        outerNetNamespace='net:[1]', netNamespace='net:[2]', mountNamespace='mnt:[3]', pidNamespace='pid:[4]',
        uid=10001, gid=10001, capabilities='0000000000000000', noNewPrivileges=1, interfaces=['lo'],
        ipv4Addresses=['127.0.0.1/8', '8.8.4.4/32'], ipv4DefaultRoutes=[], ipv6DefaultRoutes=[], unprivilegedPortStart=0)),
        'captures.jsonl': b''.join(encoded(x) for x in items), 'wire-events.jsonl': b''.join(encoded(x) for x in wire_events),
        'audit-events.jsonl': b''.join(encoded(x) for x in audit_events), 'audit-checkpoint.json': encoded({'count': len(audit_events), 'lastHash': previous}),
        'wire-ready.json': encoded(dict(schema=C.READY_SCHEMA, pid=2, uid=10001, gid=10001, dotAddress=C.DOT_HOST,
        dotPort=C.DOT_PORT, httpsAddress=C.SOURCE_IP, httpsPort=C.SOURCE_PORT, tls=True, deadlineSeconds=300)),
        'wire-stopped.json': encoded(dict(schema=C.STOPPED_SCHEMA, pid=2, termination='term', accepted=connection_id,
        closed=connection_id, events=len(wire_events), workerThreadsAlive=0, listenersClosed=True, normalStop=True)),
        'private-readback.json': encoded(dict(schema='chengwang.subscription-private-readback/v1', sourceCommit=HEAD,
        fixtureId=FIXTURE, sources=baseline, candidates=[dict(id=candidates[k], sourceId=sources[k], digest=digests[k],
        format='mihomo-provider-yaml', state='admitted_local', baseRevision=2, nodeCount=2) for k in ('a', 'b')],
        localAuditCount=6, commandCount=24, approvalCount=9)),
        'outcome.json': encoded(dict(schema=C.SCHEMA, sourceCommit=HEAD, fixtureId=FIXTURE, status='CAPTURED',
        runtimeAcceptanceProven=False, authorization='BLOCKED', production=False, deviceActionsExecuted=False, boundary=C.BOUNDARY))}
    for name in C.PUBLIC_FILES:
        if name.endswith('.pem'):
            files[name] = b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(name.encode()) + b'\n-----END CERTIFICATE-----\n'
    return files


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.files = synthetic_lab()

    def run_check(self, files=None, commit=HEAD):
        with tempfile.TemporaryDirectory(prefix='subscription-checker-unit-') as name:
            directory = Path(name)
            for filename, raw in (files or self.files).items():
                (directory / filename).write_bytes(raw)
            native_fstat = os.fstat

            def fixture_fstat(fd):
                info = native_fstat(fd)
                if os.name != 'nt':
                    return info
                # Synthetic POSIX held metadata for Windows auxiliary tests.
                # No production identity comparison is weakened or bypassed.
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                          'st_size', 'st_mtime_ns', 'st_ctime_ns')
                values = {key: getattr(info, key) for key in fields}
                values['st_ctime_ns'] = info.st_birthtime_ns
                return types.SimpleNamespace(**values)

            with mock.patch.object(checker, 'git_blobs', return_value=SOURCE_BLOBS), mock.patch.object(checker, 'certificates'), mock.patch.object(checker.os, 'fstat', side_effect=fixture_fstat):
                return checker.verify(directory, commit, directory)

    def rejects(self, change):
        files = copy.deepcopy(self.files)
        change(files)
        with self.assertRaises(checker.Rejected):
            self.run_check(files)

    def test_valid_complete_lab(self):
        report = self.run_check()
        self.assertEqual((report['captureCount'], report['serverEpochs'], report['wireConnections'], report['wireEvents']), (46, 4, 26, 102))
        self.assertFalse(report['privateDatabaseRawIndependentlyVerified'])
        self.assertFalse(report['externalInternetProven'])
        self.assertEqual(set(report['inputSHA256']), C.PUBLIC_FILES)

    def test_exact_public_file_set(self):
        self.rejects(lambda f: f.pop('api-ca.pem'))
        self.rejects(lambda f: f.update({'secret.private': b'never-export'}))

    def test_file_custody_and_budgets(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            evidence = root / 'evidence'
            evidence.mkdir()
            for filename, raw in self.files.items():
                (evidence / filename).write_bytes(raw)
            os.link(evidence / 'build.json', root / 'hardlink')
            with self.assertRaises(checker.Rejected):
                checker.read_inputs(evidence)
            (root / 'hardlink').unlink()
            native_fstat = os.fstat

            def changed_metadata(fd):
                info = native_fstat(fd)
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                          'st_size', 'st_mtime_ns', 'st_ctime_ns')
                values = {key: getattr(info, key) for key in fields}
                values['st_ctime_ns'] += 123456789
                return types.SimpleNamespace(**values)

            with mock.patch.object(checker.os, 'fstat', side_effect=changed_metadata), self.assertRaises(checker.Rejected):
                checker.read_inputs(evidence)
        self.rejects(lambda f: f.update({'captures.jsonl': b'x' * (C.MAX_ARTIFACT_BYTES + 1)}))

    def test_json_duplicates_nan_and_trailing(self):
        for raw in (b'{"a":1,"a":2}', b'{"n":NaN}', b'{"n":Infinity}', b'{} {}', b'"\xff"', b'{"n":1.0}', b'"\\ud800"'):
            with self.assertRaises(checker.Rejected):
                checker.strict_json(raw)

    def test_source_commit_binding(self):
        with self.assertRaises(checker.Rejected):
            self.run_check(commit='Z' * 40)
        self.rejects(lambda f: alter_object(f, 'runtime.json', lambda v: v.update(sourceCommit='f' * 40)))

    def test_source_manifests_and_raw_git_blobs(self):
        self.rejects(lambda f: alter_object(f, 'source-after.json', lambda v: v.pop()))
        def corrupt(f):
            value = json.loads(f['source-before.json']); value[0]['sha256'] = '0' * 64
            f['source-before.json'] = f['source-after.json'] = encoded(value)
        self.rejects(corrupt)
        with mock.patch.object(checker.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'chengwang/other\n', b'')):
            with self.assertRaises(checker.Rejected):
                checker.git_blobs('.', HEAD, list(SOURCE_BLOBS))

    def test_build_and_binary_binding(self):
        self.rejects(lambda f: alter_object(f, 'build.json', lambda v: v.update(dependencyDownloads=True)))
        self.rejects(lambda f: alter_object(f, 'runtime.json', lambda v: v['processes'][0].update(executableSHA256='0' * 64)))

    def test_isolation_no_egress_profile(self):
        self.rejects(lambda f: alter_object(f, 'isolation.json', lambda v: v.update(interfaces=['lo', 'eth0'])))
        self.rejects(lambda f: alter_object(f, 'isolation.json', lambda v: v.update(ipv4DefaultRoutes=['default'])))
        self.rejects(lambda f: alter_object(f, 'isolation.json', lambda v: v.update(netNamespace=v['outerNetNamespace'])))

    def test_four_actual_server_epochs(self):
        self.rejects(lambda f: alter_object(f, 'runtime.json', lambda v: v['processes'].pop()))
        self.rejects(lambda f: alter_object(f, 'runtime.json', lambda v: v['processes'][1].update(pid=v['processes'][0]['pid'])))
        self.rejects(lambda f: alter_object(f, 'runtime.json', lambda v: v['processes'][1].update(argvSHA256='0' * 64)))

    def test_normal_shutdown_and_no_residue(self):
        for key, value in (('joined', False), ('forced', True), ('exitCode', 137), ('stopSignal', 'SIGKILL')):
            self.rejects(lambda f, k=key, x=value: alter_object(f, 'runtime.json', lambda v: v['processes'][0].update({k: x})))
        self.rejects(lambda f: alter_object(f, 'wire-stopped.json', lambda v: v.update(workerThreadsAlive=1)))

    def test_api_certificate_peers_and_normal_tls(self):
        self.assertEqual(checker.pem_der(self.files['api-leaf.pem']), b'api-leaf.pem')
        items = captures(self.files)
        def fake_run(argv, **_):
            if argv[1] == 'x509':
                name = Path(argv[3]).name
                text = 'IP Address:127.0.0.1' if name == 'api-leaf.pem' else 'DNS:' + C.DOT_NAME if name == 'resolver-leaf.pem' else ', '.join('DNS:' + x for x in C.SOURCE_CERT_NAMES)
                return subprocess.CompletedProcess(argv, 0, text.encode(), b'')
            failed = any('wrong-ca.pem' in arg for arg in argv) or C.SOURCE_HOSTS['wrongname'] in argv
            return subprocess.CompletedProcess(argv, 1 if failed else 0, b'', b'')
        for item in items:
            item['tlsPeerDERBase64'] = base64.b64encode(b'api-leaf.pem').decode()
        with mock.patch.object(checker, 'openssl_command', return_value='synthetic-openssl'), mock.patch.object(checker.subprocess, 'run', side_effect=fake_run):
            checker.certificates(self.files, items)
            items[-1]['tlsPeerDERBase64'] = base64.b64encode(b'wrong-peer').decode()
            with self.assertRaises(checker.Rejected):
                checker.certificates(self.files, items)

    def test_certificate_identities_and_roots(self):
        for raw in (b'PRIVATE KEY sentinel', self.files['api-ca.pem'] + self.files['api-ca.pem'], b'-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----'):
            with self.assertRaises(checker.Rejected):
                checker.pem_der(raw)
        files = dict(self.files); files['wrong-ca.pem'] = files['source-ca.pem']
        with self.assertRaises(checker.Rejected):
            checker.certificates(files, captures(files))

    def test_capture_exact_order_and_status(self):
        self.rejects(lambda f: alter_capture(f, 'anonymous_list', lambda v: v.update(status=200)))
        self.rejects(lambda f: alter_capture(f, 'fetch_changed_policy', lambda v: v.update(epoch=1)))
        self.rejects(lambda f: f.update({'captures.jsonl': f['captures.jsonl'][:-1]}))

    def test_capture_raw_base64_and_sha(self):
        self.rejects(lambda f: alter_capture(f, 'create_a', lambda v: v.update(responseSHA256='0' * 64)))
        self.rejects(lambda f: alter_capture(f, 'create_a', lambda v: v.update(responseBase64=v['responseBase64'] + '\n')))
        self.rejects(lambda f: alter_capture(f, 'create_a', lambda v: v.update(responseBase64='eA==')))

    def test_capture_request_whitelist(self):
        self.rejects(lambda f: alter_capture(f, 'fetch_a', lambda v: v['requestPublic']['body'].update(url='secret-sentinel')))
        self.rejects(lambda f: alter_capture(f, 'fetch_a', lambda v: v['requestPublic'].update(authorization='secret-sentinel')))
        self.rejects(lambda f: alter_capture(f, 'nodes_a', lambda v: v.update(path=v['path'] + '&unknown=1')))
        self.rejects(lambda f: alter_capture(f, 'fetch_a', lambda v: v['requestPublic'].update(idempotencyKey='subscription-lab-unknown')))

    def test_capture_response_closed_dtos(self):
        self.rejects(lambda f: alter_capture(f, 'nodes_a', lambda v: change_response(v, lambda x: x['result']['nodes'][0].update(password='secret-sentinel'))))
        self.rejects(lambda f: alter_capture(f, 'create_a', lambda v: change_response(v, lambda x: x.update(extra='unknown'))))
        self.rejects(lambda f: alter_capture(f, 'approve_a', lambda v: change_response(v, lambda x: x['result'].update(localAuditHash='0' * 64))))

    def test_role_401_403_boundaries(self):
        self.rejects(lambda f: alter_capture(f, 'viewer_create', lambda v: v['requestPublic'].update(actorRole='operator')))
        self.rejects(lambda f: alter_capture(f, 'foreign_list', lambda v: change_response(v, lambda x: x.update(code='subscription_unavailable'))))
        self.rejects(lambda f: alter_capture(f, 'other_actor_receipt', lambda v: v.update(commandIdHeader=identity('cmd_', 1))))

    def test_sources_revisions_and_lkg(self):
        self.rejects(lambda f: alter_capture(f, 'sources_admitted', lambda v: change_response(v, lambda x: x['result']['sources'][0].update(revision=4))))
        self.rejects(lambda f: alter_capture(f, 'sources_admitted', lambda v: change_response(v, lambda x: x['result']['sources'][0]['scope'].update(siteId='foreign'))))

    def test_opaque_nodes_cross_source(self):
        node = response(next(x for x in captures(self.files) if x['name'] == 'nodes_a'))['result']['nodes'][1]
        self.rejects(lambda f: alter_capture(f, 'nodes_b', lambda v: change_response(v, lambda x: x['result']['nodes'].__setitem__(1, copy.deepcopy(node)))))
        self.rejects(lambda f: alter_capture(f, 'nodes_a', lambda v: change_response(v, lambda x: x['result']['nodes'][0].update(state='healthy'))))

    def test_failed_fetch_preserves_lkg(self):
        for name in ('sources_after_bad', 'sources_after_redirect', 'sources_after_private', 'sources_after_wrongca', 'sources_after_wrongname', 'sources_after_oversize'):
            self.rejects(lambda f, name=name: alter_capture(f, name, lambda v: change_response(v, lambda x: x['result']['sources'][0].update(latestCandidateId=identity('cand_', 999)))))

    def test_receipt_restart_immutable(self):
        self.rejects(lambda f: alter_capture(f, 'receipt_after_restart', lambda v: change_response(v, lambda x: x['result'].update(replayed=True))))
        self.rejects(lambda f: alter_capture(f, 'replay_after_restart', lambda v: change_response(v, lambda x: x['result'].update(completedAt=stamp(BASE_TIME + 1000000000)))))

    def test_replay_has_no_wire(self):
        self.rejects(lambda f: alter_capture(f, 'replay_fetch_a', lambda v: v['wireAfter'].update(eventCount=v['wireAfter']['eventCount'] + 1)))
        self.rejects(lambda f: alter_capture(f, 'replay_after_restart', lambda v: v['requestPublic'].update(idempotencyKey='subscription-lab-new_replay')))

    def test_new_key_noop(self):
        self.rejects(lambda f: alter_capture(f, 'fetch_noop_after_restart', lambda v: change_response(v, lambda x: x['result'].update(commandId=identity('cmd_', 10)))))
        self.rejects(lambda f: alter_capture(f, 'fetch_noop_after_restart', lambda v: change_response(v, lambda x: x['result'].update(candidateId=identity('cand_', 100)))))

    def test_changed_policy_unapproved_no_wire(self):
        self.rejects(lambda f: alter_capture(f, 'fetch_changed_policy', lambda v: change_response(v, lambda x: x.update(code='subscription_command_conflict'))))
        self.rejects(lambda f: alter_capture(f, 'fetch_changed_policy', lambda v: v['requestPublic']['body'].update(policyRevision=2)))

    def test_writes_locked_423(self):
        self.rejects(lambda f: alter_capture(f, 'writes_locked', lambda v: v.update(status=503)))
        self.rejects(lambda f: alter_capture(f, 'writes_locked', lambda v: change_response(v, lambda x: x.update(stateMayHaveChanged=True))))

    def test_wire_event_closed_sequence(self):
        self.rejects(lambda f: alter_wire(f, lambda es: es[0].update(ordinal=2)))
        self.rejects(lambda f: alter_wire(f, lambda es: es[2].update(event='unknown')))

    def test_wire_connection_closure(self):
        self.rejects(lambda f: alter_wire(f, lambda es: es[-1].update(event='tls')))
        self.rejects(lambda f: alter_object(f, 'wire-stopped.json', lambda v: v.update(normalStop=False)))

    def test_wire_capture_fences(self):
        self.rejects(lambda f: alter_capture(f, 'fetch_a', lambda v: v['wireAfter'].update(sha256='0' * 64)))
        self.rejects(lambda f: alter_capture(f, 'fetch_a', lambda v: v['wireBefore'].update(eventCount=1)))

    def test_wire_fixed_dns_and_https_budget(self):
        self.rejects(lambda f: alter_wire(f, lambda es: next(x for x in es if x['event'] == 'dns').update(bytes=1)))
        self.rejects(lambda f: alter_wire(f, lambda es: next(x for x in es if x['event'] == 'http' and x['reference'] == 'bad').update(bytes=1)))
        self.rejects(lambda f: alter_wire(f, lambda es: next(x for x in es if x['event'] == 'http' and x['reference'] == 'good-a').update(reason='partial')))

    def test_external_audit_hash_chain(self):
        self.rejects(lambda f: f.update({'audit-events.jsonl': f['audit-events.jsonl'].replace(b'"result":"prepared"', b'"result":"forged"', 1)}))
        self.rejects(lambda f: f.update({'audit-events.jsonl': f['audit-events.jsonl'].split(b'\n', 1)[1]}))

    def test_audit_checkpoint_and_command_bindings(self):
        self.rejects(lambda f: alter_object(f, 'audit-checkpoint.json', lambda v: v.update(lastHash='0' * 64)))
        self.rejects(lambda f: alter_capture(f, 'fetch_bad_a', lambda v: v.update(commandIdHeader=identity('cmd_', 99))))
        self.rejects(lambda f: alter_capture(f, 'fetch_a', lambda v: change_response(v, lambda x: x['result'].update(preparedAuditHash='0' * 64))))
        def wrong_target(events):
            command = next(event['traceId'] for event in events if event['action'].endswith('prepared'))
            for event in events:
                if event['traceId'] == command:
                    event['target'] = 'subscription/' + identity('src_', 999)
        self.rejects(lambda f: rewrite_audit(f, wrong_target))
        def different_stable_data(events):
            event = next(event for event in events if event['action'].endswith('prepared'))
            event['data']['commandDigest'] = 'hmac-sha256:' + 'e' * 64
        self.rejects(lambda f: rewrite_audit(f, different_stable_data))

    def test_private_projection_and_outcome_not_authority(self):
        reordered = copy.deepcopy(self.files)
        alter_object(reordered, 'private-readback.json', lambda v: v['sources'].reverse())
        self.assertEqual(self.run_check(reordered)['outcome'], 'PASS')
        self.rejects(lambda f: alter_object(f, 'private-readback.json', lambda v: v.update(commandCount=25)))
        self.rejects(lambda f: alter_object(f, 'private-readback.json', lambda v: v.update(identityKey='secret-sentinel')))
        self.rejects(lambda f: alter_object(f, 'outcome.json', lambda v: v.update(status='PASS', runtimeAcceptanceProven=True)))
        self.rejects(lambda f: alter_object(f, 'outcome.json', lambda v: v.update(production=True)))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CheckerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful() and result.testsRun == 32 and not result.skipped:
        print('SUBSCRIPTION_LAB_CHECKER_TESTS=PASS tests=32 skipped=0 synthetic_only=true')
        raise SystemExit(0)
    raise SystemExit(1)
