"""Independent, offline checker for the CI-only subscription laboratory.

Only constants are shared with the producer. Private database contents and CI
process observations remain explicitly trusted projections, not attestations.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location('subscription_checker_contract', Path(__file__).with_name('lab_contract.py'))
contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contract)

REPORT_SCHEMA = 'chengwang.subscription-product-lab-verification/v1'
WORKFLOW = '.github/workflows/chengwang-subscription-readback.yml'
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
FIXTURE = re.compile(r'[0-9a-f]{32}\Z')
PART = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{15,127}\Z')
IDS = {kind: re.compile(prefix + r'[0-9a-f]{32}\Z') for kind, prefix in
       (('source', 'src_'), ('candidate', 'cand_'), ('command', 'cmd_'), ('node', 'node_'))}
HMAC = re.compile(r'hmac-sha256:[0-9a-f]{64}\Z')
BASE = '/api/v1/subscriptions'
PROFILE_KEYS = frozenset(('pid', 'startTicks', 'uid', 'gid', 'capabilities',
                          'noNewPrivileges', 'netNamespace', 'mountNamespace', 'pidNamespace'))
PROCESS_KEYS = frozenset(('pid', 'startTicks', 'executableSHA256', 'argvSHA256', 'uid', 'gid',
                          'capabilities', 'noNewPrivileges', 'netNamespace', 'startedUnixNano',
                          'stoppedUnixNano', 'stopSignal', 'exitCode', 'joined', 'forced'))
SOURCE_KEYS = frozenset(('id', 'scope', 'label', 'revision', 'updatedAt'))
SOURCE_OPTIONAL = frozenset(('acceptedCandidateId', 'latestCandidateId'))
RECEIPT_KEYS = frozenset(('commandId', 'kind', 'revision', 'state', 'replayed',
                         'stateMayHaveChanged', 'auditRecorded'))
RECEIPT_OPTIONAL = frozenset(('sourceId', 'candidateId', 'candidateDigest', 'code',
    'preparedAuditHash', 'resultAuditHash', 'localAuditHash', 'referenceId', 'policyRevision',
    'policyDigest', 'approvalId', 'completedAt'))
FETCH_REFS = {'fetch_a': 'good-a', 'fetch_b': 'good-b', 'fetch_bad_a': 'bad',
             'fetch_redirect_a': 'redirect', 'fetch_private_a': 'private',
             'fetch_wrongca_a': 'wrongca', 'fetch_wrongname_a': 'wrongname',
             'fetch_oversize_a': 'oversize', 'fetch_noop_after_restart': 'good-a'}
ERRORS = {name: 'subscription_forbidden' for name in ('anonymous_list', 'foreign_list',
          'viewer_create', 'operator_approve_denied', 'other_actor_receipt')}
ERRORS.update(unapproved_fetch='subscription_approval_required',
    fetch_changed_policy='subscription_approval_required', fetch_bad_a='subscription_command_invalid',
    writes_locked='subscription_writes_disabled')
ERRORS.update({name: 'subscription_unavailable' for name in FETCH_REFS if name not in
               ('fetch_a', 'fetch_b', 'fetch_bad_a', 'fetch_noop_after_restart')})


class Rejected(ValueError):
    """Messages are fixed checker classifications, never input fragments."""


def need(condition, reason):
    if not condition:
        raise Rejected(reason)


def exact(value, required, optional=()):
    need(type(value) is dict and set(required) <= value.keys() <= set(required) | set(optional),
         'object-shape')


def integer(value, low=0, high=(1 << 63) - 1):
    need(type(value) is int and low <= value <= high, 'integer')
    return value


def digest(value):
    need(type(value) is str and HEX.fullmatch(value), 'digest')
    return value


def ident(value, kind):
    need(type(value) is str and IDS[kind].fullmatch(value), 'identifier')
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def strict_json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= contract.MAX_ARTIFACT_BYTES, 'json-budget')

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'json-duplicate')
            result[key] = value
        return result

    def bad_number(_):
        raise Rejected('json-number')

    try:
        result = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                            parse_float=bad_number, parse_constant=bad_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected('json-invalid') from None
    count = 0

    def walk(item, depth=0):
        nonlocal count
        count += 1
        need(depth <= 32 and count <= 100000, 'json-complexity')
        if type(item) is dict:
            for key, child in item.items():
                need(type(key) is str and len(key) <= 256, 'json-key')
                walk(child, depth + 1)
        elif type(item) is list:
            for child in item:
                walk(child, depth + 1)
        elif type(item) is str:
            need(not any(0xD800 <= ord(c) <= 0xDFFF for c in item), 'json-surrogate')
    walk(result)
    return result


def json_lines(raw, limit=4096):
    need(type(raw) is bytes and raw.endswith(b'\n') and len(raw) <= contract.MAX_ARTIFACT_BYTES,
         'jsonl-framing')
    lines = raw.splitlines(keepends=True)
    need(0 < len(lines) <= limit and all(x.endswith(b'\n') and x.strip() for x in lines),
         'jsonl-budget')
    return [strict_json(x) for x in lines]


def decimal_time(value):
    need(type(value) is str and re.fullmatch(r'[1-9][0-9]{15,19}', value), 'unix-time')
    return int(value)


def timestamp(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z', value),
         'timestamp')
    try:
        base, _, fraction = value[:-1].partition('.')
        seconds = int(datetime.datetime.strptime(base, '%Y-%m-%dT%H:%M:%S').replace(
            tzinfo=datetime.timezone.utc).timestamp())
        return seconds * 1000000000 + int((fraction + '000000000')[:9])
    except ValueError:
        raise Rejected('timestamp') from None


def decode64(value, maximum):
    need(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3), 'base64-budget')
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise Rejected('base64') from None
    need(len(raw) <= maximum and base64.b64encode(raw).decode() == value, 'base64-canonical')
    return raw


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read_inputs(directory):
    directory = Path(directory)
    before = directory.lstat()
    need(stat.S_ISDIR(before.st_mode) and not directory.is_symlink(), 'evidence-directory')
    need({x.name for x in directory.iterdir()} == contract.PUBLIC_FILES, 'public-file-set')
    result = {}
    for name in sorted(contract.PUBLIC_FILES):
        path = directory / name
        named = path.lstat()
        need(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and
             0 < named.st_size <= contract.MAX_ARTIFACT_BYTES, 'public-file-custody')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
        try:
            held = os.fstat(fd)
            need(identity(held) == identity(named), 'public-file-open-race')
            chunks = []
            remaining = named.st_size + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            need(len(raw) == named.st_size and identity(held) == identity(os.fstat(fd)) ==
                 identity(path.lstat()), 'public-file-read-race')
            result[name] = raw
        finally:
            os.close(fd)
    need(sum(map(len, result.values())) <= contract.MAX_ARTIFACT_BYTES, 'artifact-budget')
    need(identity(before) == identity(directory.lstat()), 'evidence-directory-race')
    return result


def git_blobs(source_root, commit, names):
    """Read immutable Git objects, not CRLF-converted worktree bytes."""
    root = str(Path(source_root).resolve())
    command = ['git', '-c', 'safe.directory=' + root, '-c', 'core.fsmonitor=false', '-C', root]
    try:
        listing = subprocess.run(command + ['ls-tree', '-r', '--name-only', commit, '--',
            'chengwang', WORKFLOW], capture_output=True, timeout=30, check=True).stdout
        expected = listing.decode('utf-8', 'strict').splitlines()
        need(set(expected) == set(names) and len(expected) == len(names) and WORKFLOW in expected,
             'source-manifest-coverage')
        request = ''.join(commit + ':' + name + '\n' for name in names).encode()
        raw = subprocess.run(command + ['cat-file', '--batch'], input=request,
                             capture_output=True, timeout=60, check=True).stdout
    except (subprocess.SubprocessError, OSError, UnicodeError):
        raise Rejected('source-git-read') from None
    result, offset = {}, 0
    for name in names:
        end = raw.find(b'\n', offset)
        need(end >= offset, 'git-object-framing')
        fields = raw[offset:end].split()
        need(len(fields) == 3 and fields[1] == b'blob' and fields[2].isdigit(), 'git-object-type')
        length = int(fields[2])
        need(0 <= length <= 16 << 20, 'git-object-budget')
        value = raw[end + 1:end + 1 + length]
        need(len(value) == length and raw[end + 1 + length:end + 2 + length] == b'\n',
             'git-object-framing')
        result[name] = value
        offset = end + length + 2
    need(offset == len(raw), 'git-object-trailing')
    return result


def sources(before, after, commit, source_root):
    need(before == after, 'source-before-after')
    need(type(before) is list and 1 <= len(before) <= 4096, 'source-manifest-budget')
    names = []
    for item in before:
        exact(item, ('path', 'bytes', 'sha256'))
        name = item['path']
        need(type(name) is str and (name.startswith('chengwang/') or name == WORKFLOW) and
             '\\' not in name and ':' not in name and all(x not in ('', '.', '..') for x in name.split('/')),
             'source-path')
        integer(item['bytes'], 0, 16 << 20)
        digest(item['sha256'])
        names.append(name)
    need(names == sorted(set(names)) and sum(x['bytes'] for x in before) <= 128 << 20,
         'source-manifest-order')
    blobs = git_blobs(source_root, commit, names)
    for item in before:
        raw = blobs[item['path']]
        need(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'source-raw-blob')
    return len(names)


def build(value, commit):
    exact(value, ('schema', 'sourceCommit', 'goVersion', 'moduleMode', 'dependencyDownloads',
                  'authorization', 'production', 'server'))
    need(value['schema'] == 'chengwang.subscription-build/v1' and value['sourceCommit'] == commit and
         value['goVersion'] == 'go1.23.12' and value['moduleMode'] == 'vendor' and
         value['dependencyDownloads'] is False and value['authorization'] == 'BLOCKED' and
         value['production'] is False, 'build-profile')
    exact(value['server'], ('name', 'bytes', 'sha256'))
    need(value['server']['name'] == 'server', 'build-binary-name')
    integer(value['server']['bytes'], 1, 128 << 20)
    return digest(value['server']['sha256'])


def namespace(value, kind):
    need(type(value) is str and re.fullmatch(kind + r':\[[1-9][0-9]{0,19}\]', value), 'namespace')


def isolation(value):
    exact(value, ('schema', 'outerNetNamespace', 'netNamespace', 'mountNamespace', 'pidNamespace',
        'uid', 'gid', 'capabilities', 'noNewPrivileges', 'interfaces', 'ipv4Addresses',
        'ipv4DefaultRoutes', 'ipv6DefaultRoutes', 'unprivilegedPortStart'))
    need(value['schema'] == 'chengwang.subscription-isolation/v1' and value['uid'] == contract.UID and
         value['gid'] == contract.GID and value['capabilities'] == '0000000000000000' and
         type(value['noNewPrivileges']) is int and value['noNewPrivileges'] == 1 and
         value['interfaces'] == ['lo'] and value['ipv4Addresses'] == ['127.0.0.1/8', '8.8.4.4/32'] and
         value['ipv4DefaultRoutes'] == value['ipv6DefaultRoutes'] == [] and
         type(value['unprivilegedPortStart']) is int and value['unprivilegedPortStart'] == 0,
         'isolated-network-profile')
    for name, kind in (('outerNetNamespace', 'net'), ('netNamespace', 'net'),
                       ('mountNamespace', 'mnt'), ('pidNamespace', 'pid')):
        namespace(value[name], kind)
    need(value['outerNetNamespace'] != value['netNamespace'], 'network-not-isolated')


def profile(value, iso):
    integer(value['pid'], 1)
    integer(value['startTicks'], 1)
    need(value['uid'] == contract.UID and value['gid'] == contract.GID and
         value['capabilities'] == 'none' and value['noNewPrivileges'] is True and
         value['netNamespace'] == iso['netNamespace'], 'process-profile')


def runtime(value, iso, binary, commit):
    exact(value, ('schema', 'sourceCommit', 'fixtureId', 'serverBinarySHA256',
                  'runnerProfile', 'wireProcess', 'processes'))
    need(value['schema'] == 'chengwang.subscription-runtime/v1' and value['sourceCommit'] == commit and
         FIXTURE.fullmatch(value['fixtureId']) and value['serverBinarySHA256'] == binary,
         'runtime-binding')
    runner = value['runnerProfile']
    exact(runner, PROFILE_KEYS)
    profile(runner, iso)
    need(runner['mountNamespace'] == iso['mountNamespace'] and runner['pidNamespace'] == iso['pidNamespace'],
         'runner-namespaces')
    processes = value['processes']
    need(type(processes) is list and len(processes) == 4, 'four-epochs')
    wire = value['wireProcess']
    exact(wire, PROCESS_KEYS)
    profile(wire, iso)
    digest(wire['executableSHA256'])
    digest(wire['argvSHA256'])
    ids = [runner['pid'], wire['pid']]
    previous_stop = 0
    for number, process in enumerate(processes):
        exact(process, PROCESS_KEYS | {'epoch'})
        profile(process, iso)
        need(type(process['epoch']) is int and process['epoch'] == number and
             process['executableSHA256'] == binary, 'epoch-binary')
        digest(process['argvSHA256'])
        need(process['argvSHA256'] == processes[0]['argvSHA256'], 'epoch-argv-changed')
        start, stop = decimal_time(process['startedUnixNano']), decimal_time(process['stoppedUnixNano'])
        need(previous_stop < start < stop and (stop - start) < 300000000000,
             'epoch-lifecycle-order')
        previous_stop = stop
        if number:
            need(process['startTicks'] >= processes[number - 1]['startTicks'], 'start-ticks-order')
        ids.append(process['pid'])
    need(len(ids) == len(set(ids)), 'process-id-reused')
    need(decimal_time(wire['startedUnixNano']) < decimal_time(processes[0]['startedUnixNano']) and
         decimal_time(wire['stoppedUnixNano']) > previous_stop, 'wire-process-lifetime')
    for process in [wire] + processes:
        need(process['stopSignal'] == 'SIGTERM' and type(process['exitCode']) is int and
             process['exitCode'] == 0 and process['joined'] is True and process['forced'] is False,
             'normal-process-stop')
    return value['fixtureId']


def pem_der(raw):
    need(type(raw) is bytes and len(raw) <= 65536, 'certificate-budget')
    match = re.fullmatch(rb'\s*-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\r\n]+)\s+-----END CERTIFICATE-----\s*', raw)
    need(match is not None, 'certificate-pem')
    return decode64(re.sub(rb'\s', b'', match.group(1)).decode(), 49152)


def openssl_command():
    path = shutil.which('openssl')
    if not path:
        git = shutil.which('git')
        if git:
            candidate = Path(git).resolve().parent.parent / 'usr/bin/openssl.exe'
            if candidate.is_file():
                path = str(candidate)
    need(path is not None, 'openssl-unavailable')
    return path


def certificates(raws, captures):
    cert_names = ('api-ca.pem', 'api-leaf.pem', 'source-ca.pem', 'source-leaf.pem',
                  'resolver-ca.pem', 'resolver-leaf.pem', 'wrong-ca.pem')
    ders = {name: pem_der(raws[name]) for name in cert_names}
    need(len(set(ders.values())) == 7, 'certificate-identities-not-distinct')
    tool = openssl_command()
    with tempfile.TemporaryDirectory(prefix='subscription-cert-check-') as directory:
        directory = Path(directory)
        for name in cert_names:
            (directory / name).write_bytes(raws[name])

        def run(args):
            try:
                return subprocess.run([tool] + args, capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                raise Rejected('certificate-tool') from None

        for role, identity_name, flag in (('api', contract.API_HOST, '-verify_ip'),
                                         ('resolver', contract.DOT_NAME, '-verify_hostname'),
                                         ('source', contract.SOURCE_HOSTS['good-a'], '-verify_hostname')):
            leaf, ca = directory / (role + '-leaf.pem'), directory / (role + '-ca.pem')
            for capture in (captures[0], captures[-1]):
                at = str(decimal_time(capture['receivedUnixNano']) // 1000000000)
                need(run(['verify', '-attime', at, '-purpose', 'sslserver', '-CAfile', str(ca),
                          flag, identity_name, str(leaf)]).returncode == 0, 'certificate-normal-trust')
            need(run(['verify', '-CAfile', str(directory / 'wrong-ca.pem'), str(leaf)]).returncode != 0,
                 'wrong-ca-was-trusted')
        for role, expected in (('api', {'IP Address:' + contract.API_HOST}),
                                ('resolver', {'DNS:' + contract.DOT_NAME}),
                                ('source', {'DNS:' + name for name in contract.SOURCE_CERT_NAMES})):
            output = run(['x509', '-in', str(directory / (role + '-leaf.pem')), '-noout', '-ext', 'subjectAltName'])
            need(output.returncode == 0, 'certificate-san')
            names = re.findall(r'(?:DNS:[A-Za-z0-9.-]+|IP Address:[0-9.:a-fA-F]+)', output.stdout.decode('ascii', 'strict'))
            need(len(names) == len(set(names)) and set(names) == expected, 'certificate-single-purpose-san')
        need(run(['verify', '-CAfile', str(directory / 'source-ca.pem'), '-verify_hostname',
                  contract.SOURCE_HOSTS['wrongname'], str(directory / 'source-leaf.pem')]).returncode != 0,
             'wrong-name-was-trusted')
    for capture in captures:
        need(decode64(capture['tlsPeerDERBase64'], 49152) == ders['api-leaf.pem'], 'api-peer-certificate')


def source_view(value):
    exact(value, SOURCE_KEYS, SOURCE_OPTIONAL)
    ident(value['id'], 'source')
    need(value['scope'] == contract.SCOPE and public_label(value['label']), 'source-public-view')
    integer(value['revision'], 1)
    timestamp(value['updatedAt'])
    for name in SOURCE_OPTIONAL & value.keys():
        ident(value[name], 'candidate')


def public_label(value):
    return type(value) is str and 0 < len(value.encode()) <= 128 and value.strip() == value and all(
        c.isalpha() or c.isdecimal() or c in ' ._-' for c in value)


def receipt(value):
    exact(value, RECEIPT_KEYS, RECEIPT_OPTIONAL)
    ident(value['commandId'], 'command')
    need(value['kind'] in ('create', 'fetch', 'approve', 'decide') and
         value['state'] in ('committed', 'approved', 'noop') and value['auditRecorded'] is True and
         type(value['replayed']) is bool and value['stateMayHaveChanged'] is False and 'code' not in value,
         'receipt-state')
    integer(value['revision'], 1)
    ident(value.get('sourceId'), 'source')
    for key in ('preparedAuditHash', 'resultAuditHash'):
        digest(value.get(key))
    timestamp(value.get('completedAt'))
    required = RECEIPT_KEYS | {'sourceId', 'preparedAuditHash', 'resultAuditHash', 'completedAt'}
    if value['kind'] in ('fetch', 'decide'):
        required |= {'candidateId', 'candidateDigest'}
    if value['state'] == 'committed':
        required |= {'localAuditHash'}
    if value['state'] == 'approved':
        required |= {'referenceId', 'policyRevision', 'policyDigest', 'approvalId'}
    exact(value, required)
    if 'candidateId' in value:
        ident(value['candidateId'], 'candidate')
        need(HMAC.fullmatch(value.get('candidateDigest', '')), 'candidate-digest')
    if value['state'] == 'committed':
        digest(value.get('localAuditHash'))
    else:
        need('localAuditHash' not in value, 'noop-local-audit')
    if value['state'] == 'approved':
        need(value['kind'] == 'approve' and value.get('referenceId') in contract.REFERENCE_IDS and
             value.get('policyRevision') == 1 and HMAC.fullmatch(value.get('policyDigest', '')),
             'approval-receipt')
        need(value.get('approvalId') == value['commandId'], 'approval-id')


def capture_dto(item):
    raw = decode64(item['responseBase64'], contract.MAX_CAPTURE_BYTES)
    need(sha(raw) == digest(item['responseSHA256']) and raw.endswith(b'\n'), 'response-raw-binding')
    value = strict_json(raw)
    exact(value, ('boundary', 'authorization', 'deviceActionsExecuted', 'stateMayHaveChanged'), ('code', 'result'))
    need(value['boundary'] == contract.BOUNDARY and value['authorization'] == 'BLOCKED' and
         value['deviceActionsExecuted'] is False and value['stateMayHaveChanged'] is False, 'response-boundary')
    name = item['name']
    if item['status'] != 200:
        need(set(value) == {'boundary', 'authorization', 'deviceActionsExecuted', 'stateMayHaveChanged', 'code'} and
             value['code'] == ERRORS.get(name), 'response-error-code')
        return value
    need('code' not in value and 'result' in value, 'response-success-envelope')
    result = value['result']
    if name.startswith('sources_'):
        exact(result, ('sources', 'total'))
        need(result['total'] == 2 and type(result['sources']) is list and len(result['sources']) == 2,
             'source-page')
        for source in result['sources']:
            source_view(source)
        need(len({x['id'] for x in result['sources']}) == 2, 'source-page-duplicate')
    elif name.startswith('nodes_'):
        exact(result, ('nodes', 'total', 'revision'))
        need(result['total'] == 2 and result['revision'] == 3 and
             type(result['nodes']) is list and len(result['nodes']) == 2, 'node-page')
        for node in result['nodes']:
            exact(node, ('id', 'label', 'protocol', 'credentialConfigured', 'state'))
            ident(node['id'], 'node')
            need(node['label'] == '节点-' + node['id'][-8:] and node['protocol'] == 'trojan' and
                 node['credentialConfigured'] is True and node['state'] == 'unknown', 'node-safe-view')
        need(len({node['id'] for node in result['nodes']}) == 2, 'node-page-duplicate')
    else:
        receipt(result)
    return value


def validate_captures(items, processes):
    need(type(items) is list and len(items) == len(contract.CAPTURES), 'capture-count')
    decoded, previous_time = {}, 0
    for ordinal, (item, expected) in enumerate(zip(items, contract.CAPTURES), 1):
        exact(item, contract.CAPTURE_KEYS)
        name, epoch, status = expected
        need(item['schema'] == contract.CAPTURE_SCHEMA and type(item['ordinal']) is int and
             item['ordinal'] == ordinal and item['name'] == name and item['epoch'] == epoch and
             type(item['status']) is int and item['status'] == status, 'capture-order')
        at = decimal_time(item['receivedUnixNano'])
        process = processes[epoch]
        need(previous_time <= at and decimal_time(process['startedUnixNano']) <= at <=
             decimal_time(process['stoppedUnixNano']), 'capture-epoch-time')
        previous_time = at
        exact(item['requestPublic'], ('actorRole', 'body', 'idempotencyKey'))
        request = item['requestPublic']
        need(request['actorRole'] in ('anonymous',) + contract.ROLES, 'request-role')
        need(type(item['path']) is str and len(item['path']) <= 256 and
             re.fullmatch(r'/api/v1/subscriptions/[A-Za-z0-9_/?=&-]+', item['path']), 'request-path')
        if item['method'] == 'GET':
            need(request['body'] is None and request['idempotencyKey'] == '', 'get-request-body')
            need(name.startswith(('sources_', 'nodes_')) or name in ('anonymous_list', 'foreign_list',
                 'other_actor_receipt', 'receipt_after_restart'), 'get-case')
        else:
            need(item['method'] == 'POST' and type(request['idempotencyKey']) is str and
                 KEY.fullmatch(request['idempotencyKey']), 'post-idempotency')
            body = request['body']
            if name in ('create_a', 'create_b', 'viewer_create'):
                exact(body, ('label',))
                need(public_label(body['label']), 'create-body')
            elif name.startswith('approve_') or name == 'operator_approve_denied':
                exact(body, ('referenceId', 'policyRevision', 'expectedRevision'))
                need(body['referenceId'] in contract.REFERENCE_IDS and body['policyRevision'] == 1, 'approve-body')
                integer(body['expectedRevision'], 1, 3)
            elif name.startswith('admit_'):
                exact(body, ('candidateId', 'expectedRevision', 'expectedDigest', 'decision'))
                ident(body['candidateId'], 'candidate')
                need(body['expectedRevision'] == 2 and HMAC.fullmatch(body['expectedDigest']) and
                     body['decision'] == 'admitted_local', 'decision-body')
            else:
                exact(body, ('approvalId', 'policyRevision', 'expectedRevision'))
                ident(body['approvalId'], 'command')
                need(body['policyRevision'] == 1, 'fetch-policy-revision')
                integer(body['expectedRevision'], 1, 3)
        value = capture_dto(item)
        has_command = name in ERRORS and (name.startswith('fetch_') or name == 'unapproved_fetch')
        if has_command:
            ident(item['commandIdHeader'], 'command')
        else:
            need(item['commandIdHeader'] == '', 'unexpected-command-header')
        decoded[name] = value
    return decoded


def semantics(items, values):
    lookup = {x['name']: x for x in items}
    result = lambda name: values[name]['result']
    a, b = result('create_a')['sourceId'], result('create_b')['sourceId']
    need(a != b, 'distinct-sources')
    for suffix, source in (('a', a), ('b', b)):
        need(result('create_' + suffix)['revision'] == 1 and result('fetch_' + suffix)['revision'] == 2 and
             result('admit_' + suffix)['revision'] == 3, 'source-revision-progression')
        candidate = result('fetch_' + suffix)['candidateId']
        need(result('admit_' + suffix)['candidateId'] == candidate and
             lookup['admit_' + suffix]['requestPublic']['body']['candidateId'] == candidate,
             'candidate-admission-binding')
        need(result('fetch_' + suffix)['sourceId'] == result('admit_' + suffix)['sourceId'] == source,
             'source-receipt-binding')
    baseline = result('sources_admitted')
    for source in baseline['sources']:
        suffix = 'a' if source['id'] == a else 'b'
        need(source['id'] in (a, b) and source['revision'] == 3 and source.get('acceptedCandidateId') ==
             source.get('latestCandidateId') == result('fetch_' + suffix)['candidateId'], 'source-lkg')
        need(source['label'] == 'source-' + suffix, 'source-label')
    for name in values:
        if name.startswith('sources_'):
            need(result(name) == baseline, 'failed-fetch-or-restart-changed-lkg')
    need({n['id'] for n in result('nodes_a')['nodes']}.isdisjoint(
         n['id'] for n in result('nodes_b')['nodes']), 'cross-source-node-identity')
    original = result('fetch_a')
    for name in ('replay_fetch_a', 'receipt_after_restart', 'replay_after_restart'):
        copy = dict(result(name))
        need(copy.pop('replayed') is (name != 'receipt_after_restart'), 'receipt-replayed-flag')
        expected = dict(original)
        expected.pop('replayed')
        need(copy == expected, 'receipt-restart-immutability')
    for name in ('replay_fetch_a', 'replay_after_restart'):
        need(lookup[name]['requestPublic'] == lookup['fetch_a']['requestPublic'], 'replay-request-changed')
    noop = result('fetch_noop_after_restart')
    need(noop['state'] == 'noop' and noop['commandId'] != original['commandId'] and noop['revision'] == 3 and
         noop['candidateId'] == original['candidateId'] and noop['candidateDigest'] == original['candidateDigest'] and
         lookup['fetch_noop_after_restart']['requestPublic']['idempotencyKey'] !=
         lookup['fetch_a']['requestPublic']['idempotencyKey'], 'new-key-noop')
    need(lookup['anonymous_list']['requestPublic']['actorRole'] == 'anonymous' and
         lookup['foreign_list']['requestPublic']['actorRole'] == 'foreign' and
         lookup['viewer_create']['requestPublic']['actorRole'] == 'viewer' and
         lookup['operator_approve_denied']['requestPublic']['actorRole'] == 'operator' and
         lookup['other_actor_receipt']['requestPublic']['actorRole'] == 'other-operator', 'role-boundaries')
    for item in items:
        name, path = item['name'], item['path']
        role = ('anonymous' if name == 'anonymous_list' else 'foreign' if name == 'foreign_list' else
                'viewer' if name.startswith(('sources_', 'nodes_')) or name == 'viewer_create' else
                'other-operator' if name == 'other_actor_receipt' else
                'approver' if name.startswith(('approve_', 'admit_')) else 'operator')
        need(item['requestPublic']['actorRole'] == role, 'case-role')
        if item['method'] == 'POST':
            expected_key = 'subscription-lab-' + ('fetch_a' if name in ('replay_fetch_a', 'replay_after_restart') else name)
            need(item['requestPublic']['idempotencyKey'] == expected_key, 'case-idempotency-key')
            body = item['requestPublic']['body']
            if name in ('create_a', 'create_b', 'viewer_create'):
                need(body == {'label': 'source-b' if name == 'create_b' else 'source-a'}, 'case-create-body')
            elif name.startswith('approve_') or name == 'operator_approve_denied':
                reference = ('good-b' if name == 'approve_b' else 'good-a' if name in
                             ('approve_a', 'approve_good_a', 'operator_approve_denied') else name[8:-2])
                need(body == {'referenceId': reference, 'policyRevision': 1,
                              'expectedRevision': 1 if name in ('approve_a', 'approve_b', 'operator_approve_denied') else 3},
                     'case-approve-body')
            elif name.startswith('admit_'):
                suffix = name[-1]
                need(body['expectedDigest'] == result('fetch_' + suffix)['candidateDigest'], 'case-decision-digest')
            else:
                approval = ('cmd_' + '0' * 32 if name == 'unapproved_fetch' else
                            result('approve_a')['commandId'] if name in ('fetch_a', 'replay_fetch_a', 'replay_after_restart') else
                            result('approve_b')['commandId'] if name == 'fetch_b' else
                            result('approve_good_a')['commandId'] if name in ('fetch_noop_after_restart', 'fetch_changed_policy', 'writes_locked') else
                            result('approve_' + name[6:])['commandId'])
                need(body == {'approvalId': approval, 'policyRevision': 1,
                              'expectedRevision': 1 if name in ('unapproved_fetch', 'fetch_a', 'fetch_b', 'replay_fetch_a', 'replay_after_restart') else 3},
                     'case-fetch-body')
        if name.startswith('sources_') or name in ('anonymous_list', 'foreign_list', 'create_a', 'create_b', 'viewer_create'):
            need(path == BASE + '/sources', 'case-route')
        elif name.startswith('nodes_'):
            suffix = name[-1]
            source = a if suffix == 'a' else b
            need(path == BASE + '/sources/' + source + '/candidates/' +
                 result('fetch_' + suffix)['candidateId'] + '/nodes?limit=100&offset=0&revision=3', 'case-route')
        elif name in ('other_actor_receipt', 'receipt_after_restart'):
            need(path == BASE + '/commands/' + original['commandId'], 'case-route')
        else:
            source = b if name in ('approve_b', 'fetch_b', 'admit_b') else a
            route = 'approvals' if name.startswith('approve_') or name == 'operator_approve_denied' else 'decisions' if name.startswith('admit_') else 'fetches'
            need(path == BASE + '/sources/' + source + '/' + route, 'case-route')
    return a, b


def wire(raw, ready, stopped, runtime_value, items):
    events = json_lines(raw, contract.MAX_EVENTS)
    exact(ready, ('schema', 'pid', 'uid', 'gid', 'dotAddress', 'dotPort', 'httpsAddress',
                   'httpsPort', 'tls', 'deadlineSeconds'))
    need(ready == {'schema': contract.READY_SCHEMA, 'pid': runtime_value['wireProcess']['pid'],
         'uid': contract.UID, 'gid': contract.GID, 'dotAddress': contract.DOT_HOST,
         'dotPort': contract.DOT_PORT, 'httpsAddress': contract.SOURCE_IP, 'httpsPort': contract.SOURCE_PORT,
         'tls': True, 'deadlineSeconds': 300}, 'wire-ready-profile')
    exact(stopped, ('schema', 'pid', 'termination', 'accepted', 'closed', 'events',
                     'workerThreadsAlive', 'listenersClosed', 'normalStop'))
    connections = {}
    previous_received = 0
    for ordinal, event in enumerate(events, 1):
        exact(event, contract.EVENT_KEYS)
        need(event['schema'] == contract.EVENT_SCHEMA and type(event['ordinal']) is int and
             event['ordinal'] == ordinal and event['service'] in ('dot', 'https'), 'wire-event-order')
        connection = integer(event['connection'], 1, contract.MAX_CONNECTIONS)
        integer(event['bytes'], 0, (1 << 20) + 4096)
        integer(event['status'], 0, 599)
        need(type(event['tls']) is bool, 'wire-tls-type')
        chain = connections.setdefault(connection, [])
        need(not chain or (chain[0]['service'] == event['service'] and chain[-1]['event'] != 'close'),
             'wire-connection-identity')
        kind = event['event']
        if kind == 'connect':
            need(not chain and event['reason'] == 'ok' and event['tls'] is False, 'wire-connect')
        elif kind == 'tls':
            need(len(chain) == 1 and chain[0]['event'] == 'connect' and
                 ((event['tls'] is True and event['reason'] == 'ok') or
                  (event['tls'] is False and event['reason'] in ('failed', 'stopping'))), 'wire-tls')
        elif kind in ('dns', 'http'):
            need(len(chain) == 2 and chain[-1]['event'] == 'tls' and chain[-1]['tls'] is True and
                 event['tls'] is True and event['reference'] in contract.REFERENCE_IDS and
                 event['reason'] in ('ok', 'partial'), 'wire-payload-chain')
            at = decimal_time(event['receivedUnixNano'])
            need(decimal_time(runtime_value['wireProcess']['startedUnixNano']) <= at <=
                 decimal_time(runtime_value['wireProcess']['stoppedUnixNano']), 'wire-payload-time')
            previous_received = max(previous_received, at)
            if kind == 'dns':
                need(event['service'] == 'dot' and event['queryType'] in ('A', 'AAAA') and
                     event['status'] == 0 and event['reason'] == 'ok', 'wire-dns')
                question = sum(len(x) + 1 for x in contract.SOURCE_HOSTS[event['reference']].split('.')) + 1 + 4
                need(event['bytes'] == 2 + 12 + question + (16 if event['queryType'] == 'A' else 0), 'wire-dns-size')
            else:
                need(event['service'] == 'https' and event['queryType'] == '' and
                     event['status'] == (302 if event['reference'] == 'redirect' else 200) and
                     event['reference'] != 'private', 'wire-http')
                need(event['reason'] == 'ok' or event['reference'] == 'oversize', 'unexpected-http-partial')
                need(event['bytes'] > 0, 'wire-http-empty')
                ref = event['reference']
                if ref in ('bad', 'redirect', 'oversize'):
                    length = len(b'proxies: [\n') if ref == 'bad' else 0 if ref == 'redirect' else contract.MAX_INPUT + 1
                    header = ('HTTP/1.1 ' + ('302 Found' if ref == 'redirect' else '200 OK') + '\r\n' +
                              'Content-Type: application/yaml\r\nContent-Length: ' + str(length) + '\r\n' +
                              ('Location: https://good-a.subscription.example/subscription\r\n' if ref == 'redirect' else '') +
                              'Cache-Control: no-store\r\nConnection: close\r\n\r\n').encode()
                    need(event['bytes'] == len(header) + length if event['reason'] == 'ok' else
                         0 < event['bytes'] < len(header) + length, 'wire-http-size')
        elif kind == 'close':
            need(len(chain) in (2, 3) and event['reason'] in ('closed', 'transport-error', 'failed', 'stopping'),
                 'wire-close')
        else:
            raise Rejected('wire-event-enum')
        if kind not in ('dns', 'http'):
            need(event['reference'] == event['queryType'] == event['receivedUnixNano'] == '' and
                 event['status'] == event['bytes'] == 0, 'wire-nonpayload-fields')
        chain.append(event)
    need(set(connections) == set(range(1, len(connections) + 1)) and len(connections) == 26,
         'wire-connection-budget')
    for chain in connections.values():
        need(chain[-1]['event'] == 'close' and chain[0]['event'] == 'connect' and
             [e['event'] for e in chain] in (['connect', 'tls', 'close'],
                 ['connect', 'tls', 'dns', 'close'], ['connect', 'tls', 'http', 'close']), 'wire-closed-chain')
    need(stopped == {'schema': contract.STOPPED_SCHEMA, 'pid': ready['pid'], 'termination': 'term',
         'accepted': 26, 'closed': 26, 'events': len(events), 'workerThreadsAlive': 0,
         'listenersClosed': True, 'normalStop': True}, 'wire-normal-stop')
    lines = raw.splitlines(keepends=True)
    previous_after = 0
    for item in items:
        fences = []
        for name in ('wireBefore', 'wireAfter'):
            fence = item[name]
            exact(fence, ('eventCount', 'sha256'))
            count = integer(fence['eventCount'], 0, len(events))
            need(sha(b''.join(lines[:count])) == digest(fence['sha256']), 'wire-prefix-binding')
            fences.append(count)
        before, after = fences
        need(previous_after <= before <= after, 'wire-fence-order')
        previous_after = after
        window = events[before:after]
        name = item['name']
        if name not in FETCH_REFS:
            need(before == after, 'nonfetch-generated-wire')
            continue
        ref = FETCH_REFS[name]
        need(all(e['reference'] in ('', ref) for e in window), 'wire-reference-window')
        need(all(decimal_time(e['receivedUnixNano']) <= decimal_time(item['receivedUnixNano'])
                 for e in window if e['event'] in ('dns', 'http')), 'wire-after-api-response')
        conns = {e['connection'] for e in window}
        need(len(conns) == (2 if ref == 'private' else 3) and
             all(connections[c][0] in window and connections[c][-1] in window for c in conns),
             'wire-window-not-drained')
        dns = [e for e in window if e['event'] == 'dns']
        need(len(dns) == 2 and {e['queryType'] for e in dns} == {'A', 'AAAA'}, 'wire-fetch-dns-budget')
        http = [e for e in window if e['event'] == 'http']
        need(len(http) == (0 if ref in ('private', 'wrongca', 'wrongname') else 1), 'wire-fetch-http-budget')
        if http:
            need(http[0]['reason'] == 'ok' or name == 'fetch_oversize_a', 'wire-success-completion')
    need(previous_after == len(events), 'wire-unfenced-tail')
    goods = [e['bytes'] for e in events if e['event'] == 'http' and e['reference'] in ('good-a', 'good-b')]
    need(len(goods) == 3 and len(set(goods)) == 1, 'good-content-wire-size')
    return len(connections), len(events)


def go_event_bytes(event):
    order = ('id', 'idempotencyKey', 'traceId', 'actorId', 'action', 'target', 'result',
             'occurredAt', 'data', 'previousHash', 'hash')
    copy = {name: (dict(sorted(event[name].items())) if name == 'data' else event[name])
            for name in order if name in event}
    copy['hash'] = ''
    raw = json.dumps(copy, ensure_ascii=False, separators=(',', ':'))
    return raw.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e').replace(
        '\u2028', '\\u2028').replace('\u2029', '\\u2029').encode()


def audit(raw, checkpoint, values, items):
    events = json_lines(raw, 1024)
    previous = '0' * 64
    by_hash, by_command = {}, {}
    for event in events:
        exact(event, ('id', 'traceId', 'actorId', 'action', 'target', 'result', 'occurredAt',
                      'previousHash', 'hash'), ('idempotencyKey', 'data'))
        need(type(event['id']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', event['id']), 'audit-event-id')
        timestamp(event['occurredAt'])
        need(type(event['actorId']) is str and re.fullmatch(r'act_[0-9a-f]{60}', event['actorId']), 'audit-actor')
        need(event['previousHash'] == previous and sha(go_event_bytes(event)) == digest(event['hash']),
             'audit-hash-chain')
        previous = event['hash']
        need(previous not in by_hash, 'audit-duplicate-hash')
        by_hash[previous] = event
        need(event['action'] in ('subscription.command.prepared', 'subscription.command.result',
                                'subscription.command.denied'), 'audit-action')
        need(type(event.get('data')) is dict and all(type(v) is str for v in event['data'].values()), 'audit-data')
        if event['action'].endswith('denied'):
            exact(event['data'], ('category', 'classification'))
            need(event['result'] == 'denied' and event['target'] == 'subscription/local' and
                 event['data']['category'] in ('read', 'create', 'approve', 'fetch') and
                 event['data']['classification'] in ('subscription_forbidden', 'subscription_writes_disabled'),
                 'audit-denial')
        else:
            command = ident(event['traceId'], 'command')
            stage = event['action'].rsplit('.', 1)[1]
            need(event['result'] == stage and event.get('idempotencyKey') == 'subscription/' + command + '/' + stage,
                 'audit-command-identity')
            need(stage not in by_command.setdefault(command, {}), 'audit-stage-duplicate')
            by_command[command][stage] = event
            data = event['data']
            fields = {'tenantId', 'siteId', 'environment', 'managementObject', 'kind', 'commandDigest'}
            if stage == 'result':
                fields |= {'state', 'code', 'sourceId', 'candidateId', 'revision', 'candidateDigest',
                           'localAuditHash', 'approvalId', 'policyDigest', 'policyRevision', 'stateMayHaveChanged'}
            exact(data, fields)
            need({key: data[key] for key in contract.SCOPE} == contract.SCOPE and data['managementObject'] == 'local' and
                 HMAC.fullmatch(data['commandDigest']) and data['kind'] in ('create', 'approve', 'fetch', 'decide'),
                 'audit-scope')
    exact(checkpoint, ('count', 'lastHash'))
    need(type(checkpoint['count']) is int and checkpoint['count'] == len(events) and checkpoint['lastHash'] == previous,
         'audit-checkpoint')
    for command, pair in by_command.items():
        need(set(pair) == {'prepared', 'result'} and pair['prepared']['actorId'] == pair['result']['actorId'] and
             pair['prepared']['target'] == pair['result']['target'] and
             timestamp(pair['prepared']['occurredAt']) <= timestamp(pair['result']['occurredAt']),
             'audit-paired-command')
        stable = ('tenantId', 'siteId', 'environment', 'managementObject', 'kind', 'commandDigest')
        need(pair['prepared']['data'] == {key: pair['result']['data'][key] for key in stable},
             'audit-paired-stable-data')
    for value in values.values():
        result = value.get('result')
        if type(result) is not dict or 'commandId' not in result:
            continue
        pair = by_command.get(result['commandId'])
        need(pair is not None and pair['prepared']['hash'] == result['preparedAuditHash'] and
             pair['result']['hash'] == result['resultAuditHash'], 'receipt-audit-binding')
        data = pair['result']['data']
        for field, default in (('sourceId', ''), ('candidateId', ''), ('candidateDigest', ''),
                               ('localAuditHash', ''), ('approvalId', ''), ('policyDigest', '')):
            need(data[field] == result.get(field, default), 'receipt-audit-result')
        need(data['kind'] == result['kind'] and data['state'] == result['state'] and
             data['revision'] == str(result['revision']) and data['stateMayHaveChanged'] == 'false' and
             pair['result']['occurredAt'] == result['completedAt'], 'receipt-audit-state')
    referenced, actors = set(), {}
    for item in items:
        value = values[item['name']]
        result = value.get('result')
        command_id = result.get('commandId') if type(result) is dict else item['commandIdHeader']
        if not command_id:
            continue
        referenced.add(command_id)
        need(command_id in by_command, 'capture-command-audit')
        pair = by_command[command_id]
        data = pair['result']['data']
        kind = result['kind'] if type(result) is dict else 'fetch'
        source = result['sourceId'] if item['method'] == 'GET' else item['path'].split('/')[5] if kind != 'create' else ''
        target = 'subscription/' + (source if kind != 'create' else 'local')
        need(pair['prepared']['target'] == pair['result']['target'] == target and
             pair['prepared']['data']['kind'] == data['kind'] == kind, 'audit-capture-target')
        role = item['requestPublic']['actorRole']
        actor = pair['prepared']['actorId']
        need(role not in actors or actors[role] == actor, 'audit-actor-role-binding')
        actors[role] = actor
        need(timestamp(pair['result']['occurredAt']) <= decimal_time(item['receivedUnixNano']), 'audit-after-response')
        if item['status'] != 200:
            need(data['state'] == 'failed' and data['code'] == value['code'] and
                 data['stateMayHaveChanged'] == 'false', 'error-command-audit')
    need(set(by_command) == referenced and len(set(actors.values())) == len(actors), 'unreferenced-audit-command')
    need(len(by_command) == 24 and len(events) == 53, 'audit-command-budget')
    return len(by_command)


def private_readback(value, values, commit, fixture):
    exact(value, ('schema', 'sourceCommit', 'fixtureId', 'sources', 'candidates',
                  'localAuditCount', 'commandCount', 'approvalCount'))
    need(value['schema'] == 'chengwang.subscription-private-readback/v1' and value['sourceCommit'] == commit and
         value['fixtureId'] == fixture, 'private-projection-binding')
    expected = values['sources_locked']['result']['sources']
    need(type(value['sources']) is list and len(value['sources']) == 2, 'private-source-count')
    for source in value['sources']:
        source_view(source)
    need(len({x['id'] for x in value['sources']}) == 2 and
         {x['id']: x for x in value['sources']} == {x['id']: x for x in expected} and
         value['localAuditCount'] == 6 and value['commandCount'] == 24 and
         value['approvalCount'] == 9, 'private-projection-counts')
    need(type(value['candidates']) is list and len(value['candidates']) == 2, 'private-candidate-count')
    expected_candidates = {values['fetch_' + suffix]['result']['candidateId']:
                           values['fetch_' + suffix]['result'] for suffix in ('a', 'b')}
    seen = set()
    for candidate in value['candidates']:
        exact(candidate, ('id', 'sourceId', 'digest', 'format', 'state', 'baseRevision', 'nodeCount'))
        ident(candidate['id'], 'candidate')
        need(candidate['id'] in expected_candidates and candidate['id'] not in seen, 'private-candidate-identity')
        seen.add(candidate['id'])
        expected = expected_candidates[candidate['id']]
        need(candidate['sourceId'] == expected['sourceId'] and candidate['digest'] == expected['candidateDigest'] and
             candidate['format'] == 'mihomo-provider-yaml' and candidate['state'] == 'admitted_local' and
             candidate['baseRevision'] == 2 and candidate['nodeCount'] == 2, 'private-candidate-binding')


def verify(evidence_dir, source_commit, source_root):
    need(type(source_commit) is str and COMMIT.fullmatch(source_commit), 'source-commit')
    raws = read_inputs(evidence_dir)
    need(raws['source-before.json'] == raws['source-after.json'], 'source-manifest-raw-changed')
    objects = {name: strict_json(raw) for name, raw in raws.items() if name.endswith('.json')}
    count = sources(objects['source-before.json'], objects['source-after.json'], source_commit, source_root)
    binary = build(objects['build.json'], source_commit)
    iso = objects['isolation.json']
    isolation(iso)
    rt = objects['runtime.json']
    fixture = runtime(rt, iso, binary, source_commit)
    items = json_lines(raws['captures.jsonl'], 46)
    values = validate_captures(items, rt['processes'])
    semantics(items, values)
    certificates(raws, items)
    connections, event_count = wire(raws['wire-events.jsonl'], objects['wire-ready.json'],
                                     objects['wire-stopped.json'], rt, items)
    audit(raws['audit-events.jsonl'], objects['audit-checkpoint.json'], values, items)
    private_readback(objects['private-readback.json'], values, source_commit, fixture)
    outcome = objects['outcome.json']
    exact(outcome, ('schema', 'sourceCommit', 'fixtureId', 'status', 'runtimeAcceptanceProven',
                    'authorization', 'production', 'deviceActionsExecuted', 'boundary'))
    need(outcome == {'schema': contract.SCHEMA, 'sourceCommit': source_commit, 'fixtureId': fixture,
         'status': 'CAPTURED', 'runtimeAcceptanceProven': False, 'authorization': 'BLOCKED',
         'production': False, 'deviceActionsExecuted': False, 'boundary': contract.BOUNDARY}, 'producer-outcome')
    return {'schema': REPORT_SCHEMA, 'sourceCommit': source_commit, 'outcome': 'PASS',
        'authorization': 'BLOCKED', 'production': False, 'deviceActionsExecuted': False,
        'boundary': contract.BOUNDARY,
        'acceptanceScope': 'ISOLATED_PRIVATE_NETNS_PUBLIC_ADDRESS_FIXTURE_NOT_INTERNET_OR_PRODUCTION',
        'publicFileCount': 20, 'captureCount': 46, 'serverEpochs': 4, 'wireConnections': connections,
        'wireEvents': event_count, 'sourceGitBlobCount': count, 'normalTLSCertificatePeersVerified': True,
        'privateDatabaseRawIndependentlyVerified': False, 'externalInternetProven': False,
        'buildTrustBoundary': 'CI_BUILD_REPORT_AND_HASH_BOUND_NOT_REPRODUCIBLE_BUILD',
        'privateReadbackTrustBoundary': 'TRUSTED_RUNNER_SAFE_PROJECTION_NOT_INDEPENDENT_PRIVATE_DATABASE_VERIFICATION',
        'inputSHA256': {name: sha(raws[name]) for name in sorted(raws)}}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('verify',))
    parser.add_argument('--evidence-dir', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args(argv)
    try:
        output = Path(args.report).absolute()
        evidence = Path(args.evidence_dir).resolve()
        need(output.parent.resolve() != evidence and evidence not in output.parent.resolve().parents,
             'report-inside-artifact')
        report = verify(evidence, args.source_commit, args.source_root)
        raw = canonical(report) + b'\n'
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        print('SUBSCRIPTION_LAB_CHECK=PASS authorization=BLOCKED production=false')
        return 0
    except (Rejected, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, OverflowError):
        print('SUBSCRIPTION_LAB_CHECK=FAIL authorization=BLOCKED production=false', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
