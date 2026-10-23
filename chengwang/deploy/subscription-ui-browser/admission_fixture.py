"""Pure DTO/fixture helpers for CI local admission, never remote node probing.

Generated YAML is deliberately private. The public projection uses only the
product's safe views and immutable command results; private bytes are excluded.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import urllib.parse
import uuid

ROLES = ('operator', 'approver', 'viewer', 'auditor')
SCOPE = dict(tenantId='subscription-ui-lab', siteId='isolated', environment='candidate')
LABELS = dict(a='browser-source-a', b='browser-source-b')
KINDS = ('DOCUMENT', 'ASSET', 'SNAPSHOT', 'COLLECTION_ACCESS', 'SOURCES', 'CREATE',
         'SOURCE_ACCESS', 'CANDIDATES', 'NODES', 'IMPORT', 'DECIDE', 'ROLLBACK', 'RECEIPT')


def need(value):
    if not value: raise ValueError('admission fixture rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def variants(text):
    need(type(text) is str and 24 <= len(text) <= 4096 and re.fullmatch(r'[\x21-\x7e]+', text))
    result = set()
    for value in (text, 'Bearer ' + text):
        raw = value.encode('ascii')
        result.update((raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b'='), raw.hex().encode('ascii'),
            raw.hex().upper().encode('ascii'), urllib.parse.quote(value, safe='').encode('ascii'), sha(raw).encode('ascii')))
    return result


def forbidden(input_value):
    need(type(input_value) is dict and set(input_value) == {'schema', 'scenario', 'tokens', 'labels', 'files', 'canaries'}
         and input_value['schema'] == 'chengwang.admission-ui-input/v1' and input_value['scenario'] == 'local_admission'
         and input_value['labels'] == LABELS and type(input_value['tokens']) is dict
         and set(input_value['tokens']) == set(ROLES) and type(input_value['canaries']) is list
         and len(input_value['canaries']) == 21)
    result = set()
    for token in input_value['tokens'].values():
        need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token)); result.update(variants(token))
    for canary in input_value['canaries']: result.update(variants(canary))
    return sorted(result)


def identity(tokens):
    need(type(tokens) is dict and set(tokens) == set(ROLES) and len(set(tokens.values())) == 4)
    identities = []
    for role in ROLES:
        token = tokens[role]; need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token))
        identities.append(dict(tokenId='ui-' + role, tokenHash=sha(token.encode('ascii')),
            principal=dict(id=role + '@subscription-ui.lab', tenantId=SCOPE['tenantId'], roles=[role], allowedScopes=[dict(SCOPE)])))
    return dict(version=1, identities=identities)


def generate(root):
    """Return private bytes only; the supervisor owns atomic file publication."""
    need(re.fullmatch(r'/tmp/chengwang-subscription-ui-[a-f0-9]{32}', str(root)))
    tokens = {role: secrets.token_hex(32) for role in ROLES}; files = []; canaries = []; payloads = {}
    for offset, key in enumerate(('first', 'second', 'third'), 1):
        basename = 'local-' + uuid.uuid4().hex + '.yaml'; path = root / basename
        nodes = []
        for number, protocol in enumerate(('http', 'socks5')):
            name = 'private-node-' + secrets.token_hex(16)
            username = 'private-user-' + secrets.token_hex(16); password = secrets.token_hex(32)
            canaries.extend((name, username, password))
            nodes.append(dict(name=name, type=protocol, server='198.51.100.' + str(offset * 10 + number),
                              port=18080 + number, username=username, password=password))
        canaries.append(basename)
        # JSON flow mappings are valid YAML; the explicit proxies root selects
        # the real Clash parser, with no PyYAML dependency or private aliases.
        raw = ('proxies:\n' + ''.join('  - ' + json.dumps(node, separators=(',', ':')) + '\n' for node in nodes)).encode('ascii')
        need(0 < len(raw) <= 65536); payloads[path] = raw
        files.append(dict(key=key, path=str(path), bytes=len(raw)))
    value = dict(schema='chengwang.admission-ui-input/v1', scenario='local_admission', tokens=tokens,
                 labels=dict(LABELS), files=files, canaries=canaries)
    forbidden(value)
    return value, identity(tokens), payloads


def initialize(root, N):
    value, identities, payloads = generate(root)
    for path, raw in payloads.items():
        N.exclusive(path, raw, 0o600); os.chown(path, 10001, 10001)
    for name, data in (('identities.json', identities), ('browser-input.private.json', value)):
        N.exclusive(root / name, N.canonical(data), 0o600); os.chown(root / name, 10001, 10001)
    return forbidden(value)


def project(private, commit, fixture):
    need(type(private) is dict and private['schema'] == 'chengwang.subscription-store/v1'
         and len(private['sources']) == 2 and len(private['candidates']) == 4
         and len(private['commands']) == 10 and len(private['audit']) == 10 and private.get('approvals', []) == [])
    source_required = {'id', 'scope', 'label', 'revision', 'updatedAt'}
    source_optional = {'acceptedCandidateId', 'latestCandidateId'}
    sources = []
    for source in private['sources']:
        need(type(source) is dict and source_required <= set(source) <= source_required | source_optional
             and source['scope'] == SCOPE and source['label'] in LABELS.values())
        sources.append({key: value for key, value in source.items() if key in source_required | source_optional})
    need({source['label'] for source in sources} == set(LABELS.values()))
    by_label = {source['label']: source for source in sources}
    a, b = by_label[LABELS['a']], by_label[LABELS['b']]
    need(a['revision'] == 8 and b['revision'] == 2 and 'acceptedCandidateId' not in b)
    candidate_keys = {'id', 'sourceId', 'scope', 'digest', 'format', 'state', 'baseRevision',
                      'nodeCount', 'duplicateCount', 'nodes', 'createdAt'}
    node_keys = {'id', 'label', 'protocol', 'credentialConfigured', 'state'}
    candidates = []
    for item in private['candidates']:
        need(type(item) is dict and set(item) == {'view', 'raw', 'privateNodes'})
        view = item['view']; need(type(view) is dict and set(view) == candidate_keys
             and view['scope'] == SCOPE and view['sourceId'] in (a['id'], b['id']) and view['nodeCount'] == 2
             and view['duplicateCount'] == 0 and view['format'] == 'mihomo-provider-yaml'
             and type(view['nodes']) is list and len(view['nodes']) == 2)
        for node in view['nodes']:
            need(type(node) is dict and set(node) == node_keys and node['state'] == 'unknown'
                 and node['credentialConfigured'] is True and node['protocol'] in ('http', 'socks5'))
        need({node['protocol'] for node in view['nodes']} == {'http', 'socks5'})
        candidates.append({key: value for key, value in view.items() if key in candidate_keys})
    command_keys = ('id', 'scope', 'actorId', 'kind', 'sourceId', 'expectedRevision', 'preparedAuditHash', 'resultAuditHash', 'acknowledged')
    result_keys = {'sourceId', 'candidateId', 'digest', 'revision', 'state', 'code', 'stateMayHaveChanged', 'localAuditHash', 'completedAt'}
    commands = []
    for item in private['commands']:
        record = item['record']; need(type(record) is dict and record['scope'] == SCOPE
             and record['kind'] in ('create', 'import', 'decide', 'rollback') and type(record['result']) is dict
             and set(record['result']) <= result_keys and record['result']['state'] == 'committed'
             and record['acknowledged'] is True)
        result = {key: value for key, value in record['result'].items() if key in result_keys}
        command = {key: record[key] for key in command_keys if key in record}; command['result'] = result; commands.append(command)
    need(len({command['id'] for command in commands}) == 10)
    return dict(schema='chengwang.admission-ui-private-readback/v1', sourceCommit=commit, fixtureId=fixture,
        scope=dict(SCOPE), sources=sources, candidates=candidates, localAuditCount=10, commandCount=10,
        approvalCount=0, commands=commands)


def checkpoints(raw):
    need(type(raw) is bytes and len(raw) <= 32 << 20)
    return [value.decode('ascii') for value in re.findall(
        rb'^SUBSCRIPTION_UI_STAGE=(ENVIRONMENT|LAUNCH|NAVIGATE|CREATE|IMPORT|ROLES|DECIDE|ROLLBACK|RECEIPT|CLOSE|COMPLETE)$', raw, re.M)]
