"""Isolated remote-fetch UI fixture; importing this module starts no process.

The existing wire peer and its protocol are reused without changing either.
Source credentials, upstream YAML and private keys never enter public evidence.
"""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import urllib.parse

SCOPE = dict(tenantId='subscription-ui-lab', siteId='isolated', environment='candidate')
ROLES = ('operator', 'approver')
LABEL = 'browser-remote-source'
REFERENCES = ('good-a', 'good-b')
KINDS = ('DOCUMENT', 'ASSET', 'SNAPSHOT', 'COLLECTION_ACCESS', 'SOURCES', 'CREATE',
         'SOURCE_ACCESS', 'CANDIDATES', 'NODES', 'APPROVE', 'FETCH', 'DECIDE', 'RECEIPT')
WIRE_FILES = ('wire-ready.json', 'wire-events.jsonl', 'wire-stopped.json')
CERT_FILES = (('source-ca.pem', 'source-ca.pem'), ('source-cert.pem', 'source-leaf.pem'),
              ('resolver-ca.pem', 'resolver-ca.pem'), ('resolver-cert.pem', 'resolver-leaf.pem'))
INPUT_KEYS = {'schema', 'scenario', 'tokens', 'label', 'canaries'}


def need(value):
    if not value: raise ValueError('remote fetch fixture rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def wire_contract():
    path = pathlib.Path(__file__).resolve().parents[1] / 'subscription-readback/lab_contract.py'
    spec = importlib.util.spec_from_file_location('remote_ui_original_wire_contract', path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def wire_root(fixture):
    need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture))
    return pathlib.Path('/tmp/chengwang-subscription-private-' + fixture)


def variants(text):
    need(type(text) is str and 24 <= len(text) <= 4096 and re.fullmatch(r'[\x21-\x7e]+', text))
    result = set()
    for value in (text, 'Bearer ' + text):
        raw = value.encode('ascii')
        result.update((raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b'='), raw.hex().encode('ascii'),
            raw.hex().upper().encode('ascii'), urllib.parse.quote(value, safe='').encode('ascii'), sha(raw).encode('ascii')))
    return result


def forbidden(value):
    need(type(value) is dict and set(value) == INPUT_KEYS
         and value['schema'] == 'chengwang.remote-fetch-ui-input/v1' and value['scenario'] == 'remote_fetch'
         and value['label'] == LABEL and type(value['tokens']) is dict and set(value['tokens']) == set(ROLES)
         and len(set(value['tokens'].values())) == 2 and type(value['canaries']) is list
         and len(value['canaries']) == 22 and len(set(value['canaries'])) == 22)
    result = set()
    for token in value['tokens'].values():
        need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token)); result.update(variants(token))
    for canary in value['canaries']: result.update(variants(canary))
    return sorted(result)


def generate(resolver_ca, source_ca):
    contract = wire_contract()
    need(type(resolver_ca) is str and type(source_ca) is str
         and resolver_ca.startswith('-----BEGIN CERTIFICATE-----') and source_ca.startswith('-----BEGIN CERTIFICATE-----'))
    tokens = {role: secrets.token_hex(32) for role in ROLES}
    source_tokens = {ref: secrets.token_hex(32) for ref in contract.REFERENCE_IDS}
    urls = {ref: 'https://' + contract.SOURCE_HOSTS[ref] + '/subscription?token=' + source_tokens[ref]
            for ref in contract.REFERENCE_IDS}
    nodes = []; canaries = [*source_tokens.values(), *urls.values()]
    for index, protocol in enumerate(('http', 'socks5')):
        name = 'private-node-' + secrets.token_hex(16); username = 'private-user-' + secrets.token_hex(16)
        password = secrets.token_hex(32); canaries += [name, username, password]
        nodes.append(dict(name=name, type=protocol, server='198.51.100.' + str(40 + index), port=18080 + index,
                          username=username, password=password))
    body = ('proxies:\n' + ''.join('  - ' + json.dumps(node, separators=(',', ':')) + '\n' for node in nodes)).encode('ascii')
    browser = dict(schema='chengwang.remote-fetch-ui-input/v1', scenario='remote_fetch', tokens=tokens,
                   label=LABEL, canaries=canaries)
    identities = dict(version=1, identities=[dict(tokenId='ui-' + role, tokenHash=sha(tokens[role].encode()),
        principal=dict(id=role + '@subscription-ui.lab', tenantId=SCOPE['tenantId'], roles=[role], allowedScopes=[dict(SCOPE)]))
        for role in ROLES])
    policy = dict(version=1, scope=dict(SCOPE), resolver=dict(upstream='127.0.0.1:1853',
        serverName=contract.DOT_NAME, caPEM=resolver_ca), sources=[dict(referenceId=ref, revision=1, secretVersion='v1',
        url=urls[ref], allowedCnames=[], caPEM=source_ca) for ref in REFERENCES])
    wire = dict(sourceTokensByRef=source_tokens, goodBodyBase64=base64.b64encode(body).decode('ascii'))
    forbidden(browser)
    return browser, identities, policy, wire


def certificate_commands(root):
    contract = wire_contract(); commands = []
    for stem, names, serial in [('resolver', [contract.DOT_NAME], 12), ('source', list(contract.SOURCE_CERT_NAMES), 13)]:
        extension = ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                     'extendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + name for name in names) + '\n').encode('ascii')
        commands.append((root / (stem + '-extensions.private.txt'), extension, [
            ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(root / (stem + '-ca-key.private.pem'))],
            ['req', '-new', '-x509', '-sha256', '-days', '2', '-key', str(root / (stem + '-ca-key.private.pem')),
             '-subj', '/CN=Isolated-' + stem + '-CA', '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', str(root / (stem + '-ca.pem'))],
            ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(root / (stem + '-key.private.pem'))],
            ['req', '-new', '-sha256', '-key', str(root / (stem + '-key.private.pem')), '-subj', '/CN=Isolated-' + stem,
             '-out', str(root / (stem + '.csr'))],
            ['x509', '-req', '-sha256', '-days', '2', '-in', str(root / (stem + '.csr')), '-CA', str(root / (stem + '-ca.pem')),
             '-CAkey', str(root / (stem + '-ca-key.private.pem')), '-set_serial', str(serial), '-extfile',
             str(root / (stem + '-extensions.private.txt')), '-out', str(root / (stem + '-cert.pem'))]]))
    return commands


def initialize(root, fixture, N):
    private = wire_root(fixture)
    need(str(root) == '/tmp/chengwang-subscription-ui-' + fixture)
    private.mkdir(mode=0o700); os.chown(private, 10001, 10001)
    for extension, raw, commands in certificate_commands(private):
        N.exclusive(extension, raw, 0o600); os.chown(extension, 10001, 10001)
        for args in commands:
            target = pathlib.Path(args[args.index('-out') + 1])
            N.exclusive(target, b'', 0o600)
            N.command(['/usr/bin/openssl', *args])
            target.chmod(0o600); os.chown(target, 10001, 10001)
            need(N.stable_read(target, 65536, 10001, 0o600)[0])
    browser, identities, policy, wire = generate(
        N.stable_read(private / 'resolver-ca.pem', 65536, 10001, 0o600)[0].decode('ascii'),
        N.stable_read(private / 'source-ca.pem', 65536, 10001, 0o600)[0].decode('ascii'))
    for path, value in [(root / 'identities.json', identities), (root / 'browser-input.private.json', browser),
                        (root / 'policy.remote.private.json', policy), (private / 'wire-input.json', wire)]:
        N.exclusive(path, N.canonical(value), 0o600); os.chown(path, 10001, 10001)
    return forbidden(browser)


def ipv4_addresses(raw):
    need(type(raw) is str)
    values = []
    for line in raw.splitlines():
        fields = line.split(); need(len(fields) >= 4 and fields[1] == 'lo' and fields[2] == 'inet')
        values.append(fields[3])
    need(values == ['127.0.0.1/8', '8.8.4.4/32'])
    return values


def validate_wire(ready, raw, stopped, pid):
    contract = wire_contract()
    need(set(ready) == contract.READY_KEYS and ready['schema'] == contract.READY_SCHEMA
         and ready['pid'] == pid and ready['uid'] == ready['gid'] == 10001 and ready['tls'] is True
         and ready['dotAddress'] == '127.0.0.1' and ready['dotPort'] == 1853
         and ready['httpsAddress'] == '8.8.4.4' and ready['httpsPort'] == 443 and ready['deadlineSeconds'] == 180)
    need(type(raw) is bytes and len(raw) <= 256 << 10 and raw.endswith(b'\n'))
    events = [json.loads(line) for line in raw.splitlines()]; need(len(events) == 12)
    seen = []
    for index, event in enumerate(events, 1):
        need(type(event) is dict and set(event) == contract.EVENT_KEYS and event['schema'] == contract.EVENT_SCHEMA
             and event['ordinal'] == index and type(event['connection']) is int and 1 <= event['connection'] <= 3)
    for connection in (1, 2, 3):
        group = [e for e in events if e['connection'] == connection]
        need(len(group) == 4 and [e['event'] for e in group] in (['connect', 'tls', 'dns', 'close'], ['connect', 'tls', 'http', 'close']))
        payload = group[2]; service = payload['service']
        need(all(e['service'] == service for e in group) and [e['reason'] for e in group] == ['ok', 'ok', 'ok', 'closed']
             and [e['tls'] for e in group] == [False, True, True, True] and payload['reference'] == 'good-b')
        seen.append((service, payload['queryType'], payload['status']))
    need(sorted(seen) == [('dot', 'A', 0), ('dot', 'AAAA', 0), ('https', '', 200)])
    need(set(stopped) == contract.STOPPED_KEYS and stopped['schema'] == contract.STOPPED_SCHEMA
         and stopped['pid'] == pid and stopped['termination'] == 'term' and stopped['normalStop'] is True
         and stopped['accepted'] == stopped['closed'] == 3 and stopped['events'] == 12
         and stopped['workerThreadsAlive'] == 0 and stopped['listenersClosed'] is True)


def project(private, commit, fixture):
    need(type(private) is dict and private['schema'] == 'chengwang.subscription-store/v1'
         and len(private['sources']) == len(private['candidates']) == len(private.get('approvals', [])) == 1
         and len(private['commands']) == 4 and len(private['audit']) == 3)
    source = private['sources'][0]
    source_keys = {'id', 'scope', 'label', 'revision', 'updatedAt', 'acceptedCandidateId', 'latestCandidateId'}
    need(set(source) == source_keys and source['scope'] == SCOPE and source['label'] == LABEL and source['revision'] == 3)
    item = private['candidates'][0]; need(set(item) == {'view', 'raw', 'privateNodes'})
    view = item['view']; candidate_keys = {'id', 'sourceId', 'scope', 'digest', 'format', 'state', 'baseRevision', 'nodeCount', 'duplicateCount', 'nodes', 'createdAt'}
    need(set(view) == candidate_keys and view['scope'] == SCOPE and view['sourceId'] == source['id']
         and view['id'] == source['acceptedCandidateId'] == source['latestCandidateId']
         and view['state'] == 'admitted_local' and view['baseRevision'] == 2 and view['nodeCount'] == 2
         and view['duplicateCount'] == 0 and view['format'] == 'mihomo-provider-yaml' and len(view['nodes']) == 2)
    for node in view['nodes']:
        need(set(node) == {'id', 'label', 'protocol', 'credentialConfigured', 'state'} and node['credentialConfigured'] is True
             and node['state'] == 'unknown' and node['protocol'] in ('http', 'socks5'))
    need({n['protocol'] for n in view['nodes']} == {'http', 'socks5'})
    command_keys = ('id', 'scope', 'actorId', 'kind', 'sourceId', 'expectedRevision', 'preparedAuditHash', 'resultAuditHash', 'acknowledged')
    result_keys = {'sourceId', 'candidateId', 'digest', 'revision', 'state', 'code', 'stateMayHaveChanged', 'localAuditHash', 'completedAt',
                   'referenceId', 'policyRevision', 'policyDigest', 'approvalId'}
    commands = []
    for item in private['commands']:
        record = item['record']; result = record['result']
        need(record['scope'] == SCOPE and record['kind'] in ('create', 'approve', 'fetch', 'decide') and record['acknowledged'] is True
             and type(result) is dict and set(result) <= result_keys and result['sourceId'] == source['id']
             and result['state'] == ('approved' if record['kind'] == 'approve' else 'committed'))
        row = {key: record[key] for key in command_keys if key in record}; row['result'] = dict(result); commands.append(row)
    need(len({c['id'] for c in commands}) == 4 and {c['kind'] for c in commands} == {'create', 'approve', 'fetch', 'decide'})
    approval = private['approvals'][0]; approval_keys = {'commandId', 'scope', 'sourceId', 'referenceId', 'policyRevision', 'policyDigest', 'sourceRevision', 'approvedAt'}
    need(set(approval) == approval_keys | {'seal'} and approval['scope'] == SCOPE and approval['sourceId'] == source['id']
         and approval['referenceId'] == 'good-b' and approval['policyRevision'] == approval['sourceRevision'] == 1)
    need(approval['commandId'] == next(c['id'] for c in commands if c['kind'] == 'approve'))
    return dict(schema='chengwang.remote-fetch-ui-private-readback/v1', sourceCommit=commit, fixtureId=fixture,
        scope=dict(SCOPE), sources=[dict(source)], candidates=[dict(view)], localAuditCount=3, commandCount=4,
        approvalCount=1, commands=commands, approvals=[{key: approval[key] for key in approval_keys}])


def checkpoints(raw):
    need(type(raw) is bytes and len(raw) <= 32 << 20)
    return [value.decode('ascii') for value in re.findall(
        rb'^SUBSCRIPTION_UI_STAGE=(ENVIRONMENT|LAUNCH|NAVIGATE|CREATE|APPROVE|HANDOFF|FETCH|DECIDE|RECEIPT|CLOSE|COMPLETE)$', raw, re.M)]


def cleanup(fixture):
    import shutil
    root = wire_root(fixture)
    if root.exists():
        need(not root.is_symlink() and root.resolve(strict=True) == root)
        for current, dirs, _ in os.walk(root, followlinks=False):
            need(not pathlib.Path(current).is_symlink())
            for name in dirs: need(not (pathlib.Path(current) / name).is_symlink())
            pathlib.Path(current).chmod(0o700)
        shutil.rmtree(root)
