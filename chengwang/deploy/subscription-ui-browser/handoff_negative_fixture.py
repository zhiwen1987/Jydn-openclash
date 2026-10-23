"""Isolated B09 handoff denials; import is pure, no TTL claim is made.

Wire/certificate generation is the unchanged no-egress remote fixture. Only
safe local views and immutable command results leave the private namespace.
"""
import base64
import importlib.util
import os
import pathlib
import re

SCENARIO = 'remote_handoff_negative'
SCOPE = dict(tenantId='subscription-ui-lab', siteId='isolated', environment='candidate')
LABELS = dict(a='browser-handoff-source-a', b='browser-handoff-source-b')
ROLES = ('operator', 'approver')
INPUT_SCHEMA = 'chengwang.handoff-negative-ui-input/v1'
PRIVATE_SCHEMA = 'chengwang.handoff-negative-ui-private-readback/v1'
INPUT_KEYS = {'schema', 'scenario', 'tokens', 'labels', 'canaries'}
CODE_APPROVAL = 'subscription_approval_required'
CODE_CONFLICT = 'subscription_command_conflict'


def need(value):
    if not value: raise ValueError('handoff negative fixture rejected')


def remote():
    spec = importlib.util.spec_from_file_location('handoff_negative_neutral_remote',
        pathlib.Path(__file__).with_name('remote_fetch_fixture.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def forbidden(value):
    need(type(value) is dict and set(value) == INPUT_KEYS and value['schema'] == INPUT_SCHEMA
         and value['scenario'] == SCENARIO and value['labels'] == LABELS
         and type(value['tokens']) is dict and set(value['tokens']) == set(ROLES)
         and type(value['canaries']) is list and len(value['canaries']) == 22
         and all(type(item) is str for item in value['canaries']) and len(set(value['canaries'])) == 22)
    values = list(value['tokens'].values())
    need(all(type(token) is str and re.fullmatch('[a-f0-9]{64}', token) for token in values)
         and len(set(values)) == 2)
    result = set(); neutral = remote()
    for text in values + value['canaries']: result.update(neutral.variants(text))
    return sorted(result)


def generate(resolver_ca, source_ca):
    original, identities, policy, wire = remote().generate(resolver_ca, source_ca)
    browser = dict(schema=INPUT_SCHEMA, scenario=SCENARIO, tokens=dict(original['tokens']),
                   labels=dict(LABELS), canaries=list(original['canaries']))
    forbidden(browser)
    return browser, identities, policy, wire


def initialize(root, fixture, N):
    neutral = remote(); private = neutral.wire_root(fixture)
    need(str(root) == '/tmp/chengwang-subscription-ui-' + fixture)
    private.mkdir(mode=0o700); os.chown(private, 10001, 10001)
    for extension, raw, commands in neutral.certificate_commands(private):
        N.exclusive(extension, raw, 0o600); os.chown(extension, 10001, 10001)
        for args in commands:
            target = pathlib.Path(args[args.index('-out') + 1])
            N.exclusive(target, b'', 0o600); N.command(['/usr/bin/openssl', *args])
            target.chmod(0o600); os.chown(target, 10001, 10001)
            need(N.stable_read(target, 65536, 10001, 0o600)[0])
    browser, identities, policy, wire = generate(
        N.stable_read(private / 'resolver-ca.pem', 65536, 10001, 0o600)[0].decode('ascii'),
        N.stable_read(private / 'source-ca.pem', 65536, 10001, 0o600)[0].decode('ascii'))
    for path, value in [(root / 'identities.json', identities), (root / 'browser-input.private.json', browser),
                        (root / 'policy.remote.private.json', policy), (private / 'wire-input.json', wire)]:
        N.exclusive(path, N.canonical(value), 0o600); os.chown(path, 10001, 10001)
    return forbidden(browser)


def identifier(value, stem):
    need(type(value) is str and re.fullmatch(stem + '_[a-f0-9]{32}', value))


def digest(value, hmac=False):
    need(type(value) is str and re.fullmatch(('hmac-sha256:' if hmac else '') + '[a-f0-9]{64}', value))


def timestamp(value):
    need(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', value))


def project(private, commit, fixture):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit)
         and type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture))
    need(type(private) is dict and private['schema'] == 'chengwang.subscription-store/v1'
         and type(private['sources']) is list and len(private['sources']) == 2
         and type(private['candidates']) is list and len(private['candidates']) == 1
         and type(private.get('approvals')) is list and len(private['approvals']) == 3
         and type(private['commands']) is list and len(private['commands']) == 11
         and type(private['audit']) is list and len(private['audit']) == 3)
    source_keys = {'id', 'scope', 'label', 'revision', 'updatedAt'}
    by_label = {}
    for source in private['sources']:
        need(type(source) is dict and source['label'] in LABELS.values() and source['label'] not in by_label
             and source['scope'] == SCOPE)
        alias = next(key for key, label in LABELS.items() if source['label'] == label)
        need(set(source) == source_keys | ({'latestCandidateId'} if alias == 'a' else set())
             and type(source['revision']) is int and source['revision'] == (2 if alias == 'a' else 1))
        identifier(source['id'], 'src'); timestamp(source['updatedAt']); by_label[source['label']] = source
    sources = [dict(by_label[LABELS[alias]]) for alias in ('a', 'b')]
    a, b = sources
    need(a['id'] != b['id'])
    item = private['candidates'][0]
    need(type(item) is dict and set(item) == {'view', 'raw', 'privateNodes'})
    view = item['view']
    candidate_keys = {'id', 'sourceId', 'scope', 'digest', 'format', 'state', 'baseRevision', 'nodeCount', 'duplicateCount', 'nodes', 'createdAt'}
    need(type(view) is dict and set(view) == candidate_keys and view['scope'] == SCOPE
         and view['sourceId'] == a['id'] and view['id'] == a['latestCandidateId']
         and view['state'] == 'quarantined' and type(view['baseRevision']) is int and view['baseRevision'] == 2
         and type(view['nodeCount']) is int and view['nodeCount'] == 2
         and type(view['duplicateCount']) is int and view['duplicateCount'] == 0
         and view['format'] == 'mihomo-provider-yaml' and type(view['nodes']) is list and len(view['nodes']) == 2)
    identifier(view['id'], 'cand'); digest(view['digest'], True); timestamp(view['createdAt'])
    for node in view['nodes']:
        need(type(node) is dict and set(node) == {'id', 'label', 'protocol', 'credentialConfigured', 'state'}
             and node['credentialConfigured'] is True and node['state'] == 'unknown'
             and node['protocol'] in ('http', 'socks5'))
        identifier(node['id'], 'node'); need(node['label'] == '节点-' + node['id'][-8:])
    need({node['protocol'] for node in view['nodes']} == {'http', 'socks5'}
         and len({node['id'] for node in view['nodes']}) == 2)
    command_keys = ('id', 'scope', 'actorId', 'kind', 'sourceId', 'expectedRevision',
                    'preparedAuditHash', 'resultAuditHash', 'acknowledged')
    basic_result = {'sourceId', 'revision', 'state', 'stateMayHaveChanged', 'completedAt'}
    pattern = [('create', a, 0, 'committed', ''), ('create', b, 0, 'committed', ''),
        ('approve', a, 1, 'approved', ''), ('approve', a, 1, 'approved', ''), ('approve', b, 1, 'approved', ''),
        *[('fetch', a, 1, 'failed', CODE_APPROVAL) for _ in range(4)],
        ('fetch', a, 1, 'committed', ''), ('fetch', a, 1, 'failed', CODE_CONFLICT)]
    commands = []
    for disk, (kind, source, expected, state, code) in zip(private['commands'], pattern):
        need(type(disk) is dict and type(disk.get('record')) is dict)
        record = disk['record']; result = record['result']
        need(record['scope'] == SCOPE and record['kind'] == kind and record['acknowledged'] is True
             and type(record['expectedRevision']) is int and record['expectedRevision'] == expected
             and record.get('sourceId', '') == ('' if kind == 'create' else source['id'])
             and type(record['actorId']) is str and re.fullmatch('act_[a-f0-9]{60}', record['actorId']))
        identifier(record['id'], 'cmd'); digest(record['preparedAuditHash']); digest(record['resultAuditHash'])
        need(type(result) is dict and result['sourceId'] == source['id'] and result['state'] == state
             and result['stateMayHaveChanged'] is False and type(result['revision']) is int
             and result['revision'] == (2 if kind == 'fetch' and state == 'committed' else 1))
        timestamp(result['completedAt'])
        extra = {'code'} if state == 'failed' else {'referenceId', 'policyRevision', 'policyDigest', 'approvalId'} if kind == 'approve' else {'localAuditHash'}
        if kind == 'fetch' and state == 'committed': extra |= {'candidateId', 'digest'}
        need(set(result) == basic_result | extra)
        if code: need(result['code'] == code)
        elif kind == 'approve':
            need(result['referenceId'] in ('good-a', 'good-b') and type(result['policyRevision']) is int
                 and result['policyRevision'] == 1 and result['approvalId'] == record['id'])
            digest(result['policyDigest'], True)
        else:
            digest(result['localAuditHash'])
            if kind == 'fetch': need(result['candidateId'] == view['id'] and result['digest'] == view['digest'])
        row = {key: record[key] for key in command_keys if key in record}
        row['result'] = dict(result); commands.append(row)
    need(len({row['id'] for row in commands}) == 11)
    approval_keys = {'commandId', 'scope', 'sourceId', 'referenceId', 'policyRevision', 'policyDigest', 'sourceRevision', 'approvedAt'}
    approvals = []
    for approval, command, source, reference in zip(private['approvals'], commands[2:5], (a, a, b), ('good-a', 'good-b', 'good-a')):
        need(type(approval) is dict and set(approval) == approval_keys | {'seal'}
             and approval['scope'] == SCOPE and approval['sourceId'] == source['id']
             and approval['commandId'] == command['id'] and approval['referenceId'] == reference
             and type(approval['policyRevision']) is int and approval['policyRevision'] == 1
             and type(approval['sourceRevision']) is int and approval['sourceRevision'] == 1)
        result = command['result']
        need(approval['policyDigest'] == result['policyDigest'] and reference == result['referenceId']
             and approval['approvedAt'] == result['completedAt'])
        digest(approval['policyDigest'], True); timestamp(approval['approvedAt'])
        approvals.append({key: approval[key] for key in approval_keys})
    return dict(schema=PRIVATE_SCHEMA, sourceCommit=commit, fixtureId=fixture, scope=dict(SCOPE),
        sources=sources, candidates=[dict(view)], localAuditCount=3, commandCount=11,
        approvalCount=3, commands=commands, approvals=approvals)


def checkpoints(raw):
    need(type(raw) is bytes and len(raw) <= 32 << 20)
    return [value.decode('ascii') for value in re.findall(
        rb'^SUBSCRIPTION_UI_STAGE=(ENVIRONMENT|LAUNCH|NAVIGATE|CREATE|APPROVE|HANDOFF|RECEIPT|API_SAMPLER|FETCH|CLOSE|COMPLETE)$', raw, re.M)]


def sampler_fence(raw, forbidden_bytes, N, *, partial=False):
    """Fence the separate real HTTPS sampler, never reinterpret it as UI traffic."""
    need(type(raw) is bytes and 0 < len(raw) <= 262144 and raw.endswith(b'\n'))
    need(b'PRIVATE KEY' not in raw and not any(secret in raw for secret in forbidden_bytes))
    lines = raw.splitlines()
    need(1 <= len(lines) <= 2 if partial else len(lines) == 2)
    keys = {'schema', 'ordinal', 'caseKey', 'method', 'path', 'actorRole', 'requestPublic', 'status',
            'commandIdHeader', 'denialAuditHeader', 'responseBase64', 'responseBytes', 'responseSHA256',
            'tls', 'startedWallTimeUs', 'headerWallTimeUs', 'endWallTimeUs', 'terminal'}
    sources = []; idempotency = []; total = 0
    for ordinal, line in enumerate(lines, 1):
        row = N.decode(line)
        need(type(row) is dict and set(row) == keys and row['schema'] == 'chengwang.handoff-api-sample/v1'
             and type(row['ordinal']) is int and row['ordinal'] == ordinal and row['method'] == 'POST'
             and row['actorRole'] == 'operator' and type(row['path']) is str)
        approve = ordinal == 1
        need(row['caseKey'] == ('api_approve_denied' if approve else 'api_stale_fetch')
             and type(row['status']) is int and row['status'] == (403 if approve else 409))
        path = re.fullmatch(r'/api/v1/subscriptions/sources/(src_[a-f0-9]{32})/' +
                            ('approvals' if approve else 'fetches'), row['path'])
        need(path); sources.append(path[1])
        request = row['requestPublic']
        fields = {'sourceId', 'expectedRevision', 'policyRevision', 'idempotencyKey',
                  'referenceId' if approve else 'approvalId'}
        need(type(request) is dict and set(request) == fields and request['sourceId'] == path[1]
             and type(request['expectedRevision']) is int and request['expectedRevision'] == 1
             and type(request['policyRevision']) is int and request['policyRevision'] == 1
             and type(request['idempotencyKey']) is str
             and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{15,127}', request['idempotencyKey']))
        idempotency.append(request['idempotencyKey'])
        if approve:
            need(request['referenceId'] == 'good-b' and row['commandIdHeader'] is None
                 and row['denialAuditHeader'] == 'recorded')
        else:
            identifier(request['approvalId'], 'cmd'); identifier(row['commandIdHeader'], 'cmd')
            need(row['denialAuditHeader'] is None)
        need(type(row['responseBase64']) is str)
        body = base64.b64decode(row['responseBase64'], validate=True); total += len(body)
        need(0 < len(body) <= 65536 and total <= 131072
             and base64.b64encode(body).decode('ascii') == row['responseBase64']
             and type(row['responseBytes']) is int and row['responseBytes'] == len(body)
             and row['responseSHA256'] == remote().sha(body)
             and b'PRIVATE KEY' not in body and not any(secret in body for secret in forbidden_bytes))
        response = N.decode(body)
        need(type(response) is dict and set(response) == {'boundary', 'authorization', 'deviceActionsExecuted',
                'stateMayHaveChanged', 'code'} and response['boundary'] == 'LOCAL_SUBSCRIPTION_ADMISSION_ONLY'
             and response['authorization'] == 'BLOCKED' and response['deviceActionsExecuted'] is False
             and response['stateMayHaveChanged'] is False
             and response['code'] == ('subscription_forbidden' if approve else CODE_CONFLICT))
        tls = row['tls']
        need(type(tls) is dict and set(tls) == {'authorized', 'leafDERBase64', 'leafSHA256', 'protocol'}
             and tls['authorized'] is True and tls['protocol'] in ('TLSv1.2', 'TLSv1.3')
             and type(tls['leafDERBase64']) is str)
        leaf = base64.b64decode(tls['leafDERBase64'], validate=True)
        need(0 < len(leaf) <= 65536 and base64.b64encode(leaf).decode('ascii') == tls['leafDERBase64']
             and tls['leafSHA256'] == remote().sha(leaf)
             and b'PRIVATE KEY' not in leaf and not any(secret in leaf for secret in forbidden_bytes))
        for key in ('startedWallTimeUs', 'headerWallTimeUs', 'endWallTimeUs'):
            need(type(row[key]) is int and 0 < row[key] <= (1 << 53) - 1)
        need(row['startedWallTimeUs'] <= row['headerWallTimeUs'] <= row['endWallTimeUs'])
        terminal = row['terminal']
        need(type(terminal) is dict and set(terminal) == {'event', 'complete', 'aborted'}
             and terminal['event'] == 'END' and terminal['complete'] is True and terminal['aborted'] is False)
    need(len(set(sources)) == 1 and len(set(idempotency)) == len(lines))
    return raw
