#!/usr/bin/env python3
"""Actual-process subscription laboratory. Networking is isolated Linux CI only.

Imports and the companion unit suite never execute a server or a network helper.
This collector publishes CAPTURED, not independently verified acceptance.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse

_spec = importlib.util.spec_from_file_location('subscription_lab_contract', pathlib.Path(__file__).with_name('lab_contract.py'))
contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contract)

HEX = re.compile(r'^[a-f0-9]{64}$')
COMMIT = re.compile(r'^[a-f0-9]{40}$')
ROOT_NAME = re.compile(r'^chengwang-subscription-private-([a-f0-9]{32})$')
ID = {'source': re.compile(r'^src_[a-f0-9]{32}$'), 'candidate': re.compile(r'^cand_[a-f0-9]{32}$'), 'command': re.compile(r'^cmd_[a-f0-9]{32}$')}
CODES = frozenset(('INPUT', 'CUSTODY', 'BUDGET', 'IDENTITY', 'ISOLATION', 'BUILD', 'CERTIFICATE', 'START', 'PROFILE', 'HTTP', 'CAPTURE', 'STATE', 'WIRE', 'STOP', 'SECRET', 'PUBLICATION', 'INTERNAL'))
ZERO = '0000000000000000'


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code if type(code) is str and code in CODES else 'INTERNAL')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'INPUT')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Failure('INPUT')))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8') + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same_file(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def safe_path(path, directory=False):
    path = pathlib.Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'CUSTODY')
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        require(part not in ('.', '..'), 'CUSTODY')
        current /= part
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'CUSTODY')
        if current != path or directory:
            sticky = str(current) == '/tmp' and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777
            require(stat.S_ISDIR(info.st_mode) and (not info.st_mode & 0o022 or sticky), 'CUSTODY')
    return path


def stable_read(path, limit, owner=contract.UID, mode=0o600, empty=True):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, 'CUSTODY')
        require(empty or before.st_size > 0, 'CUSTODY')
        if owner is not None:
            require((before.st_uid, before.st_gid) == (owner, owner), 'CUSTODY')
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, 'CUSTODY')
        pieces, count = [], 0
        while count <= limit:
            piece = os.read(fd, min(65536, limit + 1 - count))
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
        raw = b''.join(pieces)
        require(len(raw) == before.st_size and same_file(before) == same_file(os.fstat(fd)) == same_file(os.stat(path, follow_symlinks=False)), 'CUSTODY')
        return raw
    finally:
        os.close(fd)


def exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            require(written > 0, 'PUBLICATION')
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def root_and_evidence(private, evidence):
    private, evidence = safe_path(private, True), safe_path(evidence, True)
    match = ROOT_NAME.fullmatch(private.name)
    require(private.parent == pathlib.Path('/tmp') and match is not None, 'CUSTODY')
    require(private != evidence and private not in evidence.parents and evidence not in private.parents, 'CUSTODY')
    for path in (private, evidence):
        info = path.stat()
        require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (contract.UID, contract.GID, 0o700), 'CUSTODY')
    require(not list(private.iterdir()), 'CUSTODY')
    require({p.name for p in evidence.iterdir()} == {'build.json', 'source-before.json', 'isolation.json'}, 'PUBLICATION')
    return private, evidence, match.group(1)


def parse_stat(raw):
    close = raw.rfind(') ')
    require(close > 0, 'PROFILE')
    fields = raw[close + 2:].split()
    require(len(fields) >= 20 and fields[19].isdigit(), 'PROFILE')
    return int(fields[19])


def profile(pid):
    proc = pathlib.Path('/proc') / str(pid)
    lines = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    require(all(lines[k].split() == ['10001'] * 4 for k in ('Uid', 'Gid')), 'PROFILE')
    require(not lines['Groups'].split() and lines['NoNewPrivs'].strip() == '1', 'PROFILE')
    require(all(lines[k].strip() == ZERO for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')), 'PROFILE')
    return {'pid': pid, 'startTicks': parse_stat((proc / 'stat').read_text()), 'uid': contract.UID, 'gid': contract.GID,
            'capabilities': 'none', 'noNewPrivileges': True, 'netNamespace': os.readlink(proc / 'ns/net'),
            'mountNamespace': os.readlink(proc / 'ns/mnt'), 'pidNamespace': os.readlink(proc / 'ns/pid')}


def platform_profile():
    require(sys.platform == 'linux' and os.geteuid() == contract.UID and os.getegid() == contract.GID, 'IDENTITY')
    return profile(os.getpid())


def process_executable(pid):
    # /proc/PID/exe is deliberately a kernel magic link, unlike input paths.
    # Follow only this fixed numeric-PID path; bind the held target's identity
    # and let launch additionally bind process start time, argv and build SHA.
    path = pathlib.Path('/proc') / str(pid) / 'exe'
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 128 << 20, 'PROFILE')
        pieces, count = [], 0
        while count <= 128 << 20:
            piece = os.read(fd, min(65536, (128 << 20) + 1 - count))
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
        raw = b''.join(pieces)
        require(len(raw) == before.st_size and same_file(before) == same_file(os.fstat(fd)) == same_file(path.stat()), 'PROFILE')
        return raw
    finally:
        os.close(fd)


def validate_isolation(value, actual):
    keys = {'schema', 'outerNetNamespace', 'netNamespace', 'mountNamespace', 'pidNamespace', 'uid', 'gid', 'capabilities', 'noNewPrivileges', 'interfaces', 'ipv4Addresses', 'ipv4DefaultRoutes', 'ipv6DefaultRoutes', 'unprivilegedPortStart'}
    require(type(value) is dict and set(value) == keys and value['schema'] == 'chengwang.subscription-isolation/v1', 'ISOLATION')
    for key in ('netNamespace', 'mountNamespace', 'pidNamespace', 'uid', 'gid'):
        require(type(value[key]) is type(actual[key]) and value[key] == actual[key], 'ISOLATION')
    require(value['outerNetNamespace'] != value['netNamespace'] and value['capabilities'] == ZERO and type(value['noNewPrivileges']) is int and value['noNewPrivileges'] == 1, 'ISOLATION')
    require(value['interfaces'] == ['lo'] and value['ipv4Addresses'] == ['127.0.0.1/8', '8.8.4.4/32'] and value['ipv4DefaultRoutes'] == value['ipv6DefaultRoutes'] == [], 'ISOLATION')
    require(type(value['unprivilegedPortStart']) is int and value['unprivilegedPortStart'] == 0, 'ISOLATION')
    require(sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()) == ['lo'], 'ISOLATION')
    require(pathlib.Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text().strip() == '0', 'ISOLATION')
    require(not any(line.split()[1] == '00000000' for line in pathlib.Path('/proc/net/route').read_text().splitlines()[1:] if len(line.split()) > 1), 'ISOLATION')
    # /proc also lists the kernel's unreachable loopback ::/0 sentinel.
    # Match the namespace coordinator's effective-route query instead.
    routes = subprocess.run(['/usr/sbin/ip', '-json', '-6', 'route', 'show', 'default'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3,
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C'})
    require(routes.returncode == 0 and decode(routes.stdout) == [], 'ISOLATION')


def validate_build(value, binary, commit):
    require(type(value) is dict and set(value) == {'schema', 'sourceCommit', 'goVersion', 'moduleMode', 'dependencyDownloads', 'authorization', 'production', 'server'}, 'BUILD')
    require(value['schema'] == 'chengwang.subscription-build/v1' and value['sourceCommit'] == commit and value['goVersion'] == 'go1.23.12' and value['moduleMode'] == 'vendor', 'BUILD')
    require(value['dependencyDownloads'] is False and value['production'] is False and value['authorization'] == 'BLOCKED', 'BUILD')
    record = value['server']
    require(type(record) is dict and set(record) == {'name', 'bytes', 'sha256'} and record['name'] == 'server' and type(record['bytes']) is int and record['bytes'] == len(binary) and record['sha256'] == sha(binary), 'BUILD')


def child_environment(root, epoch=0):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'TMPDIR': str(root / 'tmp'),
            'CHENGWANG_ADDR': '127.0.0.1:17871', 'CHENGWANG_DATA_DIR': str(root / 'data'),
            'CHENGWANG_IDENTITIES_FILE': str(root / 'identities.json'), 'CHENGWANG_TLS_CERT_FILE': str(root / 'api-cert.pem'),
            'CHENGWANG_TLS_KEY_FILE': str(root / 'api-key.private.pem'), 'CHENGWANG_MANAGEMENT_TENANT_ID': contract.SCOPE['tenantId'],
            'CHENGWANG_MANAGEMENT_SITE_ID': contract.SCOPE['siteId'], 'CHENGWANG_MANAGEMENT_OBJECT_ID': contract.OBJECT_ID,
            'CHENGWANG_MODE': contract.SCOPE['environment'], 'CHENGWANG_SUBSCRIPTIONS_ENABLED': 'true',
            'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED': 'false' if epoch == 3 else 'true',
            'CHENGWANG_SUBSCRIPTION_POLICY_FILE': str(root / ('policy2.json' if epoch == 2 else 'policy1.json'))}


def credentials():
    return {role: base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii') for role in contract.ROLES}


def identity_file(tokens):
    identities = []
    for role in contract.ROLES:
        tenant = 'foreign-subscription-lab' if role == 'foreign' else contract.SCOPE['tenantId']
        granted = 'operator' if role in ('other-operator', 'foreign') else role
        identities.append({'tokenId': 'lab-' + role, 'tokenHash': sha(tokens[role].encode()), 'principal': {
            'id': role + '@subscription.lab', 'tenantId': tenant, 'roles': [granted],
            'allowedScopes': [{'tenantId': tenant, 'siteId': contract.SCOPE['siteId'], 'environment': contract.SCOPE['environment']}]}})
    return {'version': 1, 'identities': identities}


def policies(root, source_tokens):
    source_ca = stable_read(root / 'source-ca.pem', 65536).decode('ascii')
    wrong_ca = stable_read(root / 'wrong-ca.pem', 65536).decode('ascii')
    resolver_ca = stable_read(root / 'resolver-ca.pem', 65536).decode('ascii')
    first = {'version': 1, 'scope': dict(contract.SCOPE), 'resolver': {'upstream': '127.0.0.1:1853', 'serverName': contract.DOT_NAME, 'caPEM': resolver_ca}, 'sources': []}
    for reference in contract.REFERENCE_IDS:
        first['sources'].append({'referenceId': reference, 'revision': 1, 'secretVersion': 'v1',
                                 'url': 'https://' + contract.SOURCE_HOSTS[reference] + '/subscription?token=' + source_tokens[reference],
                                 'allowedCnames': [], 'caPEM': wrong_ca if reference == 'wrongca' else source_ca})
    second = copy.deepcopy(first)
    second['sources'][0]['secretVersion'] = 'v2'
    return first, second


def certificate_commands(root):
    commands = []
    for stem in ('api', 'resolver', 'source', 'wrong'):
        commands += [(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(root / (stem + '-ca-key.private.pem'))]),
                     (['req', '-new', '-x509', '-sha256', '-days', '2', '-key', str(root / (stem + '-ca-key.private.pem')), '-subj', '/CN=Isolated-' + stem + '-CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', str(root / (stem + '-ca.pem'))])]
    for stem in ('api', 'resolver', 'source'):
        commands += [(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(root / (stem + '-key.private.pem'))]),
                     (['req', '-new', '-sha256', '-key', str(root / (stem + '-key.private.pem')), '-subj', '/CN=Isolated-' + stem, '-out', str(root / (stem + '.csr'))]),
                     (['x509', '-req', '-sha256', '-days', '2', '-in', str(root / (stem + '.csr')), '-CA', str(root / (stem + '-ca.pem')), '-CAkey', str(root / (stem + '-ca-key.private.pem')), '-set_serial', str({'api': 11, 'resolver': 12, 'source': 13}[stem]), '-extfile', str(root / (stem + '-extensions.private.txt')), '-out', str(root / (stem + '-cert.pem'))])]
    return commands


def generate_certificates(root):
    names = {'api': 'IP:127.0.0.1', 'resolver': 'DNS:' + contract.DOT_NAME,
             'source': ','.join('DNS:' + name for name in contract.SOURCE_CERT_NAMES)}
    for stem, san in names.items():
        exclusive(root / (stem + '-extensions.private.txt'), ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=' + san + '\n').encode('ascii'))
    for args in certificate_commands(root):
        output = pathlib.Path(args[args.index('-out') + 1])
        exclusive(output, b'')  # reserve each destination; OpenSSL never selects an arbitrary path
        result = subprocess.run(['/usr/bin/openssl'] + args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'TZ': 'UTC'}, timeout=10)
        require(result.returncode == 0, 'CERTIFICATE')
        require(stable_read(output, 65536, empty=False), 'CERTIFICATE')


def wire_fence(raw):
    require(type(raw) is bytes and len(raw) <= contract.MAX_ARTIFACT_BYTES and (not raw or raw.endswith(b'\n')), 'WIRE')
    lines = raw.splitlines(keepends=True)
    require(len(lines) <= contract.MAX_EVENTS, 'WIRE')
    for index, line in enumerate(lines, 1):
        event = decode(line)
        require(type(event) is dict and set(event) == contract.EVENT_KEYS and event['schema'] == contract.EVENT_SCHEMA and type(event['ordinal']) is int and event['ordinal'] == index, 'WIRE')
    return {'eventCount': len(lines), 'sha256': sha(raw)}


def public_request(role, method, body, key):
    require(role in contract.ROLES + ('anonymous',) and method in ('GET', 'POST'), 'CAPTURE')
    allowed = {'label', 'referenceId', 'policyRevision', 'expectedRevision', 'approvalId', 'candidateId', 'expectedDigest', 'decision'}
    require((body is None and method == 'GET' and key == '') or (type(body) is dict and set(body) <= allowed and method == 'POST' and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{15,127}', key)), 'CAPTURE')
    return {'actorRole': role, 'body': body, 'idempotencyKey': key}


def validate_response(raw, peer, expected_peer):
    require(type(raw) is bytes and 0 < len(raw) <= contract.MAX_CAPTURE_BYTES and peer == expected_peer and bool(peer), 'HTTP')
    value = decode(raw)
    require(type(value) is dict and set(value) <= {'boundary', 'authorization', 'deviceActionsExecuted', 'stateMayHaveChanged', 'code', 'result'}, 'HTTP')
    require(value.get('boundary') == contract.BOUNDARY and value.get('authorization') == 'BLOCKED' and value.get('deviceActionsExecuted') is False and type(value.get('stateMayHaveChanged')) is bool, 'HTTP')
    return value


def ensure_capture_order(captures):
    require(len(captures) == len(contract.CAPTURES), 'CAPTURE')
    for index, (actual, expected) in enumerate(zip(captures, contract.CAPTURES), 1):
        require(set(actual) == contract.CAPTURE_KEYS and actual['ordinal'] == index and (actual['name'], actual['epoch'], actual['status']) == expected, 'CAPTURE')


def assert_inventory(result, sources, candidates):
    require(type(result) is dict and set(result) == {'sources', 'total'} and result['total'] == 2 and type(result['sources']) is list and len(result['sources']) == 2, 'STATE')
    indexed = {v['id']: v for v in result['sources']}
    require(set(indexed) == set(sources.values()), 'STATE')
    for key in ('a', 'b'):
        source = indexed[sources[key]]
        require(source['revision'] == 3 and source['acceptedCandidateId'] == source['latestCandidateId'] == candidates[key] and source['scope'] == contract.SCOPE, 'STATE')


def assert_receipt(receipt, state, source='', revision=None):
    require(type(receipt) is dict and ID['command'].fullmatch(receipt.get('commandId', '')) and receipt.get('state') == state and receipt.get('auditRecorded') is True and receipt.get('stateMayHaveChanged') is False, 'STATE')
    require(HEX.fullmatch(receipt.get('preparedAuditHash', '')) and HEX.fullmatch(receipt.get('resultAuditHash', '')), 'STATE')
    if source:
        require(receipt.get('sourceId') == source, 'STATE')
    if revision is not None:
        require(receipt.get('revision') == revision, 'STATE')


def secret_variants(values):
    variants = set()
    for value in values:
        raw = value.encode('utf-8') if isinstance(value, str) else value
        require(type(raw) is bytes and len(raw) >= 8, 'SECRET')
        variants.update((raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw), base64.b64encode(raw).rstrip(b'='),
                         urllib.parse.quote_from_bytes(raw, safe='').encode(), sha(raw).encode(), raw.hex().encode()))
    return variants


def scan_public(files, forbidden):
    require(type(files) is dict and all(type(k) is str and k in contract.PUBLIC_FILES for k in files) and sum(len(v) for v in files.values()) <= contract.MAX_ARTIFACT_BYTES, 'PUBLICATION')
    for raw in files.values():
        require(type(raw) is bytes and len(raw) <= 4 << 20 and b'PRIVATE KEY' not in raw and b'Bearer ' not in raw, 'SECRET')
        require(not any(secret in raw for secret in forbidden), 'SECRET')


def owned_session_remains(leader):
    for entry in pathlib.Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / 'stat').read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        close = raw.rfind(') ')
        require(close > 0, 'STOP')
        fields = raw[close + 2:].split()
        require(len(fields) >= 4, 'STOP')
        if int(fields[2]) == leader or int(fields[3]) == leader:
            return True
    return False


def stop_process(process, record, timeout=15):
    require(process.poll() is None and profile(process.pid)['startTicks'] == record['startTicks'], 'STOP')
    process.send_signal(signal.SIGTERM)
    code = process.wait(timeout=timeout)
    require(code == 0 and not pathlib.Path('/proc', str(process.pid)).exists() and not owned_session_remains(process.pid), 'STOP')
    return dict(record, stoppedUnixNano=str(time.time_ns()), stopSignal='SIGTERM', exitCode=code, joined=True, forced=False)


def emergency_stop(process):
    if process is None or process.poll() is not None:
        return False
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=15)
        return False
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        return True


class Lab:
    def __init__(self, args):
        self.args, self.active, self.captures, self.records = args, [], [], []
        self.stage = 'INPUT'
        self.root, self.evidence, self.fixture = root_and_evidence(args.private_root, args.evidence_dir)
        require(COMMIT.fullmatch(args.source_commit), 'INPUT')
        self.runner = platform_profile()
        self.build = decode(stable_read(self.evidence / 'build.json', 65536))
        require(pathlib.Path(args.build_record) == self.evidence / 'build.json', 'BUILD')
        self.binary_path = safe_path(args.server_binary)
        self.binary = stable_read(self.binary_path, 128 << 20, owner=None, mode=None, empty=False)
        info = self.binary_path.stat()
        require(info.st_mode & 0o111 and not info.st_mode & 0o022 and info.st_uid in (0, contract.UID), 'BUILD')
        validate_build(self.build, self.binary, args.source_commit)
        self.wire_path = safe_path(args.wire_script)
        stable_read(self.wire_path, 1 << 20, owner=None, mode=None, empty=False)
        validate_isolation(decode(stable_read(self.evidence / 'isolation.json', 65536)), self.runner)
        source = decode(stable_read(self.evidence / 'source-before.json', 4 << 20))
        require(type(source) is list and 0 < len(source) <= 4096 and all(type(v) is dict and set(v) == {'path', 'bytes', 'sha256'} and type(v['path']) is str and type(v['bytes']) is int and v['bytes'] >= 0 and HEX.fullmatch(v['sha256']) for v in source), 'BUILD')

    def prepare(self):
        self.stage = 'CERTIFICATE'
        for name in ('tmp', 'data'):
            (self.root / name).mkdir(mode=0o700)
        generate_certificates(self.root)
        self.tokens = credentials()
        self.source_tokens = {r: secrets.token_hex(32) for r in contract.REFERENCE_IDS}
        self.names = ['private-node-' + secrets.token_hex(16) for _ in range(2)]
        self.passwords = [secrets.token_hex(32) for _ in range(2)]
        self.body = ('proxies:\n' + ''.join('  - {name: ' + n + ', type: trojan, server: node' + str(i) + '.example, port: 443, password: ' + p + '}\n' for i, (n, p) in enumerate(zip(self.names, self.passwords)))).encode()
        self.secrets = secret_variants(list(self.tokens.values()) + list(self.source_tokens.values()) + self.names + self.passwords)
        first, second = policies(self.root, self.source_tokens)
        self.secrets |= secret_variants([entry['url'] for entry in first['sources']])
        exclusive(self.root / 'identities.json', encoded(identity_file(self.tokens)))
        exclusive(self.root / 'policy1.json', encoded(first))
        exclusive(self.root / 'policy2.json', encoded(second))
        exclusive(self.root / 'wire-input.json', encoded({'sourceTokensByRef': self.source_tokens, 'goodBodyBase64': base64.b64encode(self.body).decode()}))
        self.context = ssl.create_default_context(cafile=str(self.root / 'api-ca.pem'))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.peer = ssl.PEM_cert_to_DER_cert(stable_read(self.root / 'api-cert.pem', 65536).decode('ascii'))

    def launch(self, argv, epoch=None):
        self.stage = 'START'
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   cwd=self.root, env=child_environment(self.root, epoch or 0), start_new_session=True)
        self.active.append(process)
        deadline = time.monotonic() + 5
        record = None
        expected = sha(self.binary) if epoch is not None else None
        while time.monotonic() < deadline:
            require(process.poll() is None, 'START')
            try:
                record = profile(process.pid)
                executable = process_executable(process.pid)
                actual_argv = (pathlib.Path('/proc') / str(process.pid) / 'cmdline').read_bytes()
                if actual_argv == b''.join(os.fsencode(v) + b'\0' for v in argv) and (expected is None or sha(executable) == expected):
                    break
            except (FileNotFoundError, ProcessLookupError):
                pass
            time.sleep(0.01)
        require(record is not None and (expected is None or sha(executable) == expected), 'PROFILE')
        require(record['netNamespace'] == self.runner['netNamespace'], 'ISOLATION')
        require(record['mountNamespace'] == self.runner['mountNamespace'] and record['pidNamespace'] == self.runner['pidNamespace'], 'ISOLATION')
        actual_argv = (pathlib.Path('/proc') / str(process.pid) / 'cmdline').read_bytes()
        require(actual_argv == b''.join(os.fsencode(v) + b'\0' for v in argv), 'PROFILE')
        result = {key: record[key] for key in ('pid', 'startTicks', 'uid', 'gid', 'capabilities', 'noNewPrivileges', 'netNamespace')}
        result.update(executableSHA256=sha(executable), argvSHA256=sha(actual_argv), startedUnixNano=str(time.time_ns()))
        if epoch is not None:
            result['epoch'] = epoch
        return process, result

    def wire_start(self):
        self.wire, self.wire_record = self.launch([sys.executable, '-I', '-B', str(self.wire_path), 'serve', '--root', str(self.root), '--deadline-seconds', '300'])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (self.root / 'wire-ready.json').exists():
            require(self.wire.poll() is None, 'START')
            time.sleep(0.02)
        ready = decode(stable_read(self.root / 'wire-ready.json', 65536))
        require(set(ready) == {'schema', 'pid', 'uid', 'gid', 'dotAddress', 'dotPort', 'httpsAddress', 'httpsPort', 'tls', 'deadlineSeconds'} and ready['schema'] == contract.READY_SCHEMA and ready['pid'] == self.wire.pid and ready['uid'] == ready['gid'] == 10001 and ready['tls'] is True and ready['deadlineSeconds'] == 300, 'WIRE')
        require((ready['dotAddress'], ready['dotPort'], ready['httpsAddress'], ready['httpsPort']) == ('127.0.0.1', 1853, '8.8.4.4', 443), 'WIRE')
        require(self.wire_raw() == b'', 'WIRE')

    def wire_raw(self):
        # An in-progress append is not an empty fence. Retry only the bounded
        # stable-read/complete-LF handoff; never rewrite or discard an event.
        deadline = time.monotonic() + 2
        while True:
            try:
                raw = stable_read(self.root / 'wire-events.jsonl', contract.MAX_ARTIFACT_BYTES)
                wire_fence(raw)
                return raw
            except (Failure, FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise Failure('WIRE')
                time.sleep(0.01)

    def wire_quiescent(self):
        deadline = time.monotonic() + 2
        while True:
            raw = self.wire_raw()
            events = [decode(line) for line in raw.splitlines()]
            connections = {v['connection'] for v in events if v['event'] == 'connect'}
            closed = {v['connection'] for v in events if v['event'] == 'close'}
            if connections == closed:
                return raw
            require(time.monotonic() < deadline, 'WIRE')
            time.sleep(0.01)

    def start_server(self, epoch):
        self.server, self.server_record = self.launch([str(self.binary_path)], epoch)
        self.epoch = epoch
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            require(self.server.poll() is None, 'START')
            try:
                with socket.create_connection(('127.0.0.1', 17871), timeout=0.5) as raw:
                    with self.context.wrap_socket(raw, server_hostname='127.0.0.1') as tls:
                        require(tls.getpeercert(binary_form=True) == self.peer, 'CERTIFICATE')
                        return
            except (ConnectionError, TimeoutError, OSError):
                time.sleep(0.02)
        raise Failure('START')

    def stop_server(self):
        self.stage = 'STOP'
        self.records.append(stop_process(self.server, self.server_record))
        self.active.remove(self.server)

    def call(self, name, role='operator', method='GET', path='/api/v1/subscriptions/sources', body=None, key=''):
        self.stage = 'CAPTURE'
        index = len(self.captures)
        require(index < len(contract.CAPTURES) and contract.CAPTURES[index][:2] == (name, self.epoch), 'CAPTURE')
        request = public_request(role, method, body, key)
        before = wire_fence(self.wire_quiescent())
        connection = http.client.HTTPSConnection('127.0.0.1', 17871, timeout=25, context=self.context)
        headers = {'Connection': 'close'}
        if role != 'anonymous':
            headers['Authorization'] = 'Bearer ' + self.tokens[role]
        payload = None
        if body is not None:
            payload = encoded(body)
            headers.update({'Content-Type': 'application/json', 'Idempotency-Key': key})
        try:
            connection.connect()
            peer = connection.sock.getpeercert(binary_form=True)
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read(contract.MAX_CAPTURE_BYTES + 1)
            received = str(time.time_ns())
            require(response.status == contract.CAPTURES[index][2], 'HTTP')
            # Scan original response bytes before base64 changes alignment.
            # The final public-file scan remains a separate publication gate.
            scan_public({'captures.jsonl': raw}, self.secrets)
            scan_public({'captures.jsonl': encoded(request)}, self.secrets)
            value = validate_response(raw, peer, self.peer)
            command_header = response.getheader('X-Chengwang-Command-ID', '')
            require(not command_header or ID['command'].fullmatch(command_header), 'HTTP')
        finally:
            connection.close()
        # Sources can finish the response before appending the complete log.
        # Every fence is an actual stable full prefix; quiescence at final stop
        # preserves the complete log, without inventing request-start order.
        after = wire_fence(self.wire_quiescent())
        capture = {'schema': contract.CAPTURE_SCHEMA, 'ordinal': index + 1, 'name': name, 'epoch': self.epoch, 'method': method, 'path': path,
                   'status': response.status, 'requestPublic': request, 'responseBase64': base64.b64encode(raw).decode(), 'responseSHA256': sha(raw),
                   'tlsPeerDERBase64': base64.b64encode(peer).decode(), 'wireBefore': before, 'wireAfter': after,
                   'receivedUnixNano': received, 'commandIdHeader': command_header}
        self.captures.append(capture)
        require(value['stateMayHaveChanged'] is False, 'STATE')
        return value.get('result')

    def post(self, name, source, suffix, body, role='operator', key=None):
        return self.call(name, role, 'POST', '/api/v1/subscriptions/sources' + ('/' + source if source else '') + suffix, body, key or 'subscription-lab-' + name)

    def run_steps(self):
        self.sources, self.candidates, self.fetches = {}, {}, {}
        self.start_server(0)
        self.call('anonymous_list', 'anonymous')
        self.call('foreign_list', 'foreign')
        self.post('viewer_create', '', '', {'label': 'source-a'}, 'viewer')
        for letter in ('a', 'b'):
            result = self.post('create_' + letter, '', '', {'label': 'source-' + letter})
            assert_receipt(result, 'committed', revision=1)
            self.sources[letter] = result['sourceId']
        a, b = self.sources['a'], self.sources['b']
        self.post('operator_approve_denied', a, '/approvals', {'referenceId': 'good-a', 'policyRevision': 1, 'expectedRevision': 1})
        self.post('unapproved_fetch', a, '/fetches', {'approvalId': 'cmd_' + '0' * 32, 'policyRevision': 1, 'expectedRevision': 1})
        approvals = {}
        for letter in ('a', 'b'):
            r = self.post('approve_' + letter, self.sources[letter], '/approvals', {'referenceId': 'good-' + letter, 'policyRevision': 1, 'expectedRevision': 1}, 'approver')
            assert_receipt(r, 'approved', self.sources[letter], 1)
            approvals[letter] = r['commandId']
        self.fetch_bodies = {}
        for letter in ('a', 'b'):
            body = {'approvalId': approvals[letter], 'policyRevision': 1, 'expectedRevision': 1}
            self.fetch_bodies[letter] = body
            r = self.post('fetch_' + letter, self.sources[letter], '/fetches', body)
            assert_receipt(r, 'committed', self.sources[letter], 2)
            self.fetches[letter] = r
            self.candidates[letter] = r['candidateId']
        require(a != b and self.candidates['a'] != self.candidates['b'], 'STATE')
        for letter in ('a', 'b'):
            r = self.post('admit_' + letter, self.sources[letter], '/decisions', {'candidateId': self.candidates[letter], 'expectedRevision': 2, 'expectedDigest': self.fetches[letter]['candidateDigest'], 'decision': 'admitted_local'}, 'approver')
            assert_receipt(r, 'committed', self.sources[letter], 3)
        assert_inventory(self.call('sources_admitted', 'viewer'), self.sources, self.candidates)
        for letter in ('a', 'b'):
            nodes = self.call('nodes_' + letter, 'viewer', path='/api/v1/subscriptions/sources/' + self.sources[letter] + '/candidates/' + self.candidates[letter] + '/nodes?limit=100&offset=0&revision=3')
            require(nodes['total'] == 2 and len(nodes['nodes']) == 2 and nodes['revision'] == 3 and all(v['state'] == 'unknown' for v in nodes['nodes']), 'STATE')
        replay = self.post('replay_fetch_a', a, '/fetches', self.fetch_bodies['a'], key='subscription-lab-fetch_a')
        self.compare_replay(replay)
        self.call('other_actor_receipt', 'other-operator', path='/api/v1/subscriptions/commands/' + self.fetches['a']['commandId'])
        for reference in ('bad', 'redirect', 'private', 'wrongca', 'wrongname', 'oversize'):
            approval = self.post('approve_' + reference + '_a', a, '/approvals', {'referenceId': reference, 'policyRevision': 1, 'expectedRevision': 3}, 'approver')
            assert_receipt(approval, 'approved', a, 3)
            self.post('fetch_' + reference + '_a', a, '/fetches', {'approvalId': approval['commandId'], 'policyRevision': 1, 'expectedRevision': 3})
            assert_inventory(self.call('sources_after_' + reference, 'viewer'), self.sources, self.candidates)
        approval = self.post('approve_good_a', a, '/approvals', {'referenceId': 'good-a', 'policyRevision': 1, 'expectedRevision': 3}, 'approver')
        assert_receipt(approval, 'approved', a, 3)
        self.good_approval = approval['commandId']
        assert_inventory(self.call('sources_before_restart', 'viewer'), self.sources, self.candidates)
        self.stop_server()
        self.start_server(1)
        assert_inventory(self.call('sources_after_restart', 'viewer'), self.sources, self.candidates)
        receipt = self.call('receipt_after_restart', path='/api/v1/subscriptions/commands/' + self.fetches['a']['commandId'])
        require(receipt == self.fetches['a'], 'STATE')
        self.compare_replay(self.post('replay_after_restart', a, '/fetches', self.fetch_bodies['a'], key='subscription-lab-fetch_a'))
        noop = self.post('fetch_noop_after_restart', a, '/fetches', {'approvalId': self.good_approval, 'policyRevision': 1, 'expectedRevision': 3})
        assert_receipt(noop, 'noop', a, 3)
        require(noop['candidateId'] == self.candidates['a'] and noop.get('localAuditHash', '') == '', 'STATE')
        self.stop_server()
        self.start_server(2)
        self.post('fetch_changed_policy', a, '/fetches', {'approvalId': self.good_approval, 'policyRevision': 1, 'expectedRevision': 3})
        assert_inventory(self.call('sources_after_policy_change', 'viewer'), self.sources, self.candidates)
        self.stop_server()
        self.start_server(3)
        self.post('writes_locked', a, '/fetches', {'approvalId': self.good_approval, 'policyRevision': 1, 'expectedRevision': 3})
        assert_inventory(self.call('sources_locked', 'viewer'), self.sources, self.candidates)
        self.stop_server()
        ensure_capture_order(self.captures)

    def compare_replay(self, receipt):
        require(receipt.get('replayed') is True, 'STATE')
        copied = dict(receipt, replayed=False)
        require(copied == self.fetches['a'], 'STATE')

    def publish(self):
        self.stage = 'STOP'
        wire_record = stop_process(self.wire, self.wire_record)
        self.active.remove(self.wire)
        stopped = decode(stable_read(self.root / 'wire-stopped.json', 65536))
        require(set(stopped) == {'schema', 'pid', 'termination', 'accepted', 'closed', 'events', 'workerThreadsAlive', 'listenersClosed', 'normalStop'} and stopped['schema'] == contract.STOPPED_SCHEMA and stopped['pid'] == self.wire.pid and stopped['termination'] == 'term' and stopped['normalStop'] is True and stopped['workerThreadsAlive'] == 0 and stopped['listenersClosed'] is True and stopped['accepted'] == stopped['closed'], 'STOP')
        wire_raw = self.wire_raw()
        require(stopped['events'] == wire_fence(wire_raw)['eventCount'] and len(self.records) == 4 and len({v['pid'] for v in self.records}) == 4 and not self.active, 'STOP')
        private = decode(stable_read(self.root / 'data/subscriptions/store.json', 16 << 20))
        sources = private['sources']
        assert_inventory({'sources': sources, 'total': len(sources)}, self.sources, self.candidates)
        candidates = [{k: item['view'][k] for k in ('id', 'sourceId', 'digest', 'format', 'state', 'baseRevision', 'nodeCount')} for item in private['candidates']]
        require(len(candidates) == 2 and all(v['state'] == 'admitted_local' and v['nodeCount'] == 2 for v in candidates), 'STATE')
        readback = {'schema': 'chengwang.subscription-private-readback/v1', 'sourceCommit': self.args.source_commit, 'fixtureId': self.fixture,
                    'sources': sources, 'candidates': candidates, 'localAuditCount': len(private['audit']), 'commandCount': len(private.get('commands', [])), 'approvalCount': len(private.get('approvals', []))}
        runtime = {'schema': 'chengwang.subscription-runtime/v1', 'sourceCommit': self.args.source_commit, 'fixtureId': self.fixture,
                   'serverBinarySHA256': sha(self.binary), 'runnerProfile': self.runner, 'wireProcess': wire_record, 'processes': self.records}
        outcome = {'schema': contract.SCHEMA, 'sourceCommit': self.args.source_commit, 'fixtureId': self.fixture, 'status': 'CAPTURED', 'runtimeAcceptanceProven': False,
                   'authorization': 'BLOCKED', 'production': False, 'deviceActionsExecuted': False, 'boundary': contract.BOUNDARY}
        files = {'captures.jsonl': b''.join(encoded(v) for v in self.captures), 'runtime.json': encoded(runtime), 'private-readback.json': encoded(readback),
                 'audit-events.jsonl': stable_read(self.root / 'data/evidence/events.jsonl', 4 << 20), 'audit-checkpoint.json': stable_read(self.root / 'data/evidence/checkpoint.json', 65536),
                 'wire-ready.json': stable_read(self.root / 'wire-ready.json', 65536), 'wire-events.jsonl': wire_raw, 'wire-stopped.json': stable_read(self.root / 'wire-stopped.json', 65536), 'outcome.json': encoded(outcome)}
        for name, original in [('api-ca.pem', 'api-ca.pem'), ('api-leaf.pem', 'api-cert.pem'), ('source-ca.pem', 'source-ca.pem'), ('source-leaf.pem', 'source-cert.pem'), ('resolver-ca.pem', 'resolver-ca.pem'), ('resolver-leaf.pem', 'resolver-cert.pem'), ('wrong-ca.pem', 'wrong-ca.pem')]:
            files[name] = stable_read(self.root / original, 65536)
        require(set(files) == contract.PUBLIC_FILES - {'build.json', 'source-before.json', 'source-after.json', 'isolation.json'}, 'PUBLICATION')
        scan_public(dict(files, **{name: stable_read(self.evidence / name, 4 << 20) for name in ('build.json', 'source-before.json', 'isolation.json')}), self.secrets)
        self.stage = 'PUBLICATION'
        for name, raw in files.items():
            exclusive(self.evidence / name, raw)
        directory = os.open(self.evidence, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def run(self):
        self.prepare()
        self.wire_start()
        self.run_steps()
        self.publish()


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default embeds unrecognized raw arguments in stderr.
        raise Failure('INPUT')


def arguments(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    for option in ('server-binary', 'wire-script', 'private-root', 'evidence-dir', 'source-commit', 'build-record'):
        parser.add_argument('--' + option, required=True)
    return parser.parse_args(argv)


def failure_observation(lab):
    count = len(lab.captures) if lab is not None and type(lab.captures) is list else 0
    count = count if 0 <= count <= len(contract.CAPTURES) else 0
    expected = contract.CAPTURES[count] if count < len(contract.CAPTURES) else None
    stage = lab.stage if lab is not None and type(lab.stage) is str and lab.stage in CODES else 'INPUT'
    exits = []
    if lab is not None:
        for process in lab.active[:8]:
            try:
                value = process.poll()
            except Exception:
                value = None
            exits.append(value if type(value) is int and -65535 <= value <= 65535 else None)
    return {'stage': stage, 'expectedCapture': expected[0] if expected else None, 'epoch': expected[1] if expected else None,
            'completedCaptures': count, 'activeChildExitCodes': exits}


def main(argv=None):
    lab = None
    try:
        args = arguments(argv)
        os.umask(0o077)
        lab = Lab(args)
        lab.run()
        print('SUBSCRIPTION_PRODUCT_LAB=CAPTURED captures=46 epochs=4 independently_verified=false production=false')
        return 0
    except Exception as error:
        code = error.args[0] if isinstance(error, Failure) and error.args and type(error.args[0]) is str and error.args[0] in CODES else 'INTERNAL'
        print('SUBSCRIPTION_PRODUCT_LAB_DIAGNOSTIC=' + json.dumps(failure_observation(lab), sort_keys=True, separators=(',', ':')), file=sys.stderr)
        print('SUBSCRIPTION_PRODUCT_LAB=FAIL code=' + code + ' raw_input_suppressed=true', file=sys.stderr)
        return 1
    finally:
        if lab is not None:
            for process in reversed(lab.active):
                try:
                    emergency_stop(process)
                except Exception:
                    print('SUBSCRIPTION_PRODUCT_LAB_CLEANUP=FAIL raw_input_suppressed=true', file=sys.stderr)


if __name__ == '__main__':
    raise SystemExit(main())
