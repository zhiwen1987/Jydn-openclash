"""24 frozen prerequisites; Windows shape checks are auxiliary, not native proof."""
from __future__ import annotations
import base64
import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import unittest
import uuid
import zlib

import wire_fixture as wire
contract = wire.contract
LINUX = sys.platform.startswith('linux')
HERE = pathlib.Path(__file__).parent
SOURCES = [('lab_contract', (HERE / 'lab_contract.py').read_bytes()),
           ('wire_fixture', (HERE / 'wire_fixture.py').read_bytes())]
GOOD_BODY = b'proxies:\n  - {name: private-fixture-name, type: trojan, server: private-upstream.example, port: 443, password: private-fixture-password}\n'
TOKENS = {ref: ('%064x' % (index + 1)).encode() for index, ref in enumerate(contract.REFERENCE_IDS)}


def bootstrap():
    records = [(name, base64.b85encode(zlib.compress(raw, 9)), len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in SOURCES]
    if any(not 0 < length <= 131072 for _, _, length, _ in records): raise AssertionError('source-size-invalid')
    code = '''import base64,hashlib,sys,types,zlib
try:
    for name,payload,length,digest in RECORDS:
        decoder=zlib.decompressobj()
        raw=decoder.decompress(base64.b85decode(payload),length+1)
        if (not 0<length<=131072 or len(raw)!=length or not decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail or hashlib.sha256(raw).hexdigest()!=digest):
            raise ValueError('invalid')
        module=types.ModuleType(name)
        module.__file__='<'+name+'.py>'
        sys.modules[name]=module
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
except Exception:
    sys.stderr.write('SUBSCRIPTION_WIRE_ERROR=runtime-failed\\n')
    raise SystemExit(1) from None
raise SystemExit(sys.modules['wire_fixture'].main())
'''.replace('RECORDS', repr(records), 1)
    if len(code.encode()) > 96 << 10: raise AssertionError('bootstrap-size-invalid')
    return code


def diagnostic(raw):
    if type(raw) is not bytes or len(raw) > 65536: return 'UNCLASSIFIED'
    return {('SUBSCRIPTION_WIRE_ERROR=' + name + ending).encode(): name for name in wire.ERRORS
            for ending in ('\n', '\r\n')}.get(raw, 'UNCLASSIFIED')


def input_bytes():
    return json.dumps(dict(sourceTokensByRef={k: v.decode() for k, v in TOKENS.items()},
                           goodBodyBase64=base64.b64encode(GOOD_BODY).decode())).encode()


def query(ref='good-a', kind=1, qid=42, host=None):
    host = host or contract.SOURCE_HOSTS[ref]
    name = b''.join(bytes([len(label)]) + label.encode() for label in host.split('.')) + b'\0'
    return struct.pack('!6H', qid, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', kind, 1)


def expected_dns(ref='good-a', kind=1, qid=42):
    answer = (b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
              + (b'\x7f\x00\x00\x01' if ref == 'private' else b'\x08\x08\x04\x04'))
    return struct.pack('!6H', qid, 0x8180, 1, int(kind == 1), 0, 0) + query(ref, kind, qid)[12:] + (answer if kind == 1 else b'')


def request(ref='good-a', token=None, extra=b'', host=None):
    name = host or contract.SOURCE_HOSTS[ref]
    return (b'GET /subscription?token=' + (TOKENS[ref] if token is None else token)
            + b' HTTP/1.1\r\nHost: ' + name.encode() + b'\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n' + extra + b'\r\n')


def expected_http(ref):
    body = b'proxies: [\n' if ref == 'bad' else b'' if ref == 'redirect' else b'x' * (1048576 + 1) if ref == 'oversize' else GOOD_BODY
    status = b'302 Found' if ref == 'redirect' else b'200 OK'
    return (b'HTTP/1.1 ' + status + b'\r\nContent-Type: application/yaml\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n'
            + (b'Location: https://good-a.subscription.example/subscription\r\n' if ref == 'redirect' else b'')
            + b'Cache-Control: no-store\r\nConnection: close\r\n\r\n' + body)


def wait_for(predicate, seconds=4):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value: return value
        time.sleep(0.01)
    raise AssertionError('bounded-condition-not-observed')


def recv_all(connection):
    pieces, count = [], 0
    while True:
        try: piece = connection.recv(65536)
        except (ssl.SSLError, ConnectionResetError): break
        if not piece: break
        pieces.append(piece); count += len(piece)
        if count > contract.MAX_INPUT + 16384: raise AssertionError('response-budget-exceeded')
    return b''.join(pieces)


def private_write(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(body); stream.flush(); os.fsync(fd)
    finally: os.close(fd)


class Fixture:
    def __init__(self, test, wrong_resolver=False):
        if os.geteuid() != 0 or not shutil.which('setpriv') or not shutil.which('openssl'):
            raise AssertionError('linux-root-orchestrator-required')
        self.test = test
        self.root = pathlib.Path('/tmp/chengwang-subscription-private-' + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700); os.chown(self.root, 10001, 10001)
        self.process = None; self.ready = self.stopped = None
        test.addCleanup(self.cleanup)
        for prefix, names in (('resolver', ('wrong.resolver.example',) if wrong_resolver else (contract.DOT_NAME,)),
                              ('source', contract.SOURCE_CERT_NAMES)):
            self.openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                         '-subj', '/CN=subscription-' + prefix + '-ca', '-addext', 'basicConstraints=critical,CA:TRUE',
                         '-keyout', prefix + '-ca.key', '-out', prefix + '-ca.pem')
            self.openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                         '-subj', '/CN=' + names[0], '-keyout', prefix + '-key.private.pem', '-out', prefix + '.csr')
            private_write(self.root / (prefix + '.ext'), ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                'extendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + n for n in names) + '\n').encode())
            self.openssl('x509', '-req', '-in', prefix + '.csr', '-CA', prefix + '-ca.pem', '-CAkey', prefix + '-ca.key',
                         '-set_serial', '10', '-days', '1', '-extfile', prefix + '.ext', '-out', prefix + '-cert.pem')
        private_write(self.root / 'wire-input.json', input_bytes())
        for path in self.root.iterdir(): os.chmod(path, 0o600); os.chown(path, 10001, 10001)
        self.inputs = {name: (self.root / name).read_bytes() for name in wire.INPUTS}

    def openssl(self, *args):
        result = subprocess.run(['openssl', *args], cwd=self.root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode: raise AssertionError('certificate-provisioning-failed')

    def start(self, deadline=300, rejected=False):
        args = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--bounding-set=-all',
                '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs', sys.executable, '-I', '-B', '-c', bootstrap(),
                'serve', '--root', str(self.root), '--deadline-seconds', str(deadline)]
        self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        if rejected:
            stdout, stderr = self.process.communicate(timeout=5)
            self.test.assertTrue(self.process.returncode == 1 and stdout == b'' and diagnostic(stderr) != 'UNCLASSIFIED', 'startup-rejection-invalid')
            self.test.assertFalse((self.root / 'wire-ready.json').exists())
            return
        def ready():
            p = self.root / 'wire-ready.json'
            if p.exists():
                value = json.loads(p.read_bytes())
                self.test.assertEqual(set(value), {'schema', 'pid', 'uid', 'gid', 'dotAddress', 'dotPort', 'httpsAddress', 'httpsPort', 'tls', 'deadlineSeconds'})
                self.test.assertEqual((value['schema'], value['pid'], value['uid'], value['gid']), (contract.READY_SCHEMA, self.process.pid, 10001, 10001))
                return value
            if self.process.poll() is not None:
                _, stderr = self.process.communicate(); raise AssertionError('startup-' + diagnostic(stderr))
            return None
        self.ready = wait_for(ready)
        self.test.assertEqual(self.events(complete=True), [], 'readiness-created-network-traffic')

    def events(self, complete=False):
        path = self.root / 'wire-events.jsonl'
        if not path.exists(): raise AssertionError('wire-log-missing')
        raw = path.read_bytes()
        if raw and not raw.endswith(b'\n'):
            if complete: raise AssertionError('wire-log-truncated')
            raw = raw[:raw.rfind(b'\n') + 1]
        return [json.loads(line) for line in raw.splitlines()]

    def until(self, predicate): return wait_for(lambda: predicate(self.events()))

    def tls(self, service='dot', host=None, ca=None):
        name = host or (contract.DOT_NAME if service == 'dot' else contract.SOURCE_HOSTS['good-a'])
        prefix = 'resolver' if service == 'dot' else 'source'
        context = ssl.create_default_context(cafile=str(self.root / (ca or prefix + '-ca.pem')))
        address = (contract.DOT_HOST, contract.DOT_PORT) if service == 'dot' else (contract.SOURCE_IP, contract.SOURCE_PORT)
        raw = socket.create_connection(address, timeout=3)
        try:
            connection = context.wrap_socket(raw, server_hostname=name); connection.settimeout(3); return connection
        except BaseException: raw.close(); raise

    def dns(self, ref='good-a', kind=1, qid=42):
        data = query(ref, kind, qid)
        with self.tls() as conn:
            conn.sendall(struct.pack('!H', len(data)) + data); result = recv_all(conn)
        answer = expected_dns(ref, kind, qid)
        self.test.assertTrue(result == struct.pack('!H', len(answer)) + answer, 'dns-wire-or-qid-mismatch')

    def http(self, ref):
        with self.tls('https', contract.SOURCE_HOSTS[ref]) as conn:
            conn.sendall(request(ref)); result = recv_all(conn)
        self.test.assertTrue(result == expected_http(ref), 'private-http-response-mismatch')

    def stop(self, signum=signal.SIGTERM, expected=0):
        if self.process.poll() is None: self.process.send_signal(signum)
        stdout, stderr = self.process.communicate(timeout=5)
        self.test.assertTrue(self.process.returncode == expected and stdout == b'' and stderr == b'', 'helper-stop-invalid')
        value = json.loads((self.root / 'wire-stopped.json').read_bytes()); self.stopped = value
        self.test.assertEqual(set(value), {'schema', 'pid', 'termination', 'accepted', 'closed', 'events', 'workerThreadsAlive', 'listenersClosed', 'normalStop'})
        self.test.assertEqual(value['schema'], contract.STOPPED_SCHEMA)
        self.test.assertEqual(value['accepted'], value['closed']); self.test.assertEqual(value['workerThreadsAlive'], 0)
        self.test.assertIs(value['listenersClosed'], True); self.test.assertEqual(value['normalStop'], expected == 0)
        events = self.events(complete=True)
        self.test.assertEqual([e['ordinal'] for e in events], list(range(1, len(events) + 1)))
        self.test.assertEqual(value['events'], len(events)); self.test.assertLessEqual(len(events), contract.MAX_EVENTS)
        for event in events:
            self.test.assertEqual(set(event), contract.EVENT_KEYS)
            self.test.assertIn(event['reason'], wire.REASONS)
            self.test.assertIn(event['reference'], ('', *contract.REFERENCE_IDS))
            self.test.assertTrue(event['receivedUnixNano'] == '' or type(event['receivedUnixNano']) is str and event['receivedUnixNano'].isdigit())
        for number in range(1, value['accepted'] + 1):
            chain = [e for e in events if e['connection'] == number]
            self.test.assertEqual(chain[0]['event'], 'connect'); self.test.assertEqual(chain[-1]['event'], 'close')
            self.test.assertEqual(sum(e['event'] == 'close' for e in chain), 1)
        log = (self.root / 'wire-events.jsonl').read_bytes()
        for secret in (*TOKENS.values(), b'private-fixture-password', b'private-fixture-name', b'/subscription?', b'Authorization', b'SENTINEL'):
            self.test.assertFalse(secret in log, 'private-wire-input-leaked')
        for name, raw in self.inputs.items(): self.test.assertTrue((self.root / name).read_bytes() == raw, 'private-input-mutated')
        return events

    def cleanup(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try: self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.communicate(timeout=3)
                raise AssertionError('emergency-helper-kill-required')
        if self.root.parent != pathlib.Path('/tmp') or not wire.ROOT.fullmatch(str(self.root)) or self.root.is_symlink():
            raise AssertionError('unsafe-cleanup-target')
        shutil.rmtree(self.root)


class ShapeTests(unittest.TestCase):
    def test_dns_a_aaaa_and_private_wire(self):
        for ref in contract.REFERENCE_IDS:
            for kind in (1, 28):
                r, k, qid, raw = wire.dns_answer(query(ref, kind, 0xaff1))
                self.assertTrue((r, k, qid) == (ref, 'A' if kind == 1 else 'AAAA', 0xaff1) and raw == expected_dns(ref, kind, qid))

    def test_dns_invalid_questions_fail_closed(self):
        raw = query()
        for bad in (b'', raw + b'x', raw[:-1], query(host='unknown.subscription.example'), query(kind=15), raw[:4] + b'\0\2' + raw[6:], raw[:12] + b'\xc0\x0c' + raw[-4:]):
            with self.assertRaises(wire.Rejected): wire.dns_answer(bad)

    def test_http_exact_token_request_and_redaction(self):
        for ref in contract.REFERENCE_IDS:
            self.assertEqual(wire.http_reference(request(ref), contract.SOURCE_HOSTS[ref], TOKENS), ref)
        for raw in (request(token=b'f' * 64), request(extra=b'Authorization: SENTINEL\r\n'), request(extra=b'Host: extra\r\n'), request().replace(b'GET ', b'POST '), request() + b'x', request(host='unknown.subscription.example')):
            with self.assertRaises(wire.Rejected): wire.http_reference(raw, contract.SOURCE_HOSTS['good-a'], TOKENS)

    def test_http_fixed_response_modes_and_oversize(self):
        server = object.__new__(wire.WireServer)
        server.stop, server.abnormal = threading.Event(), False

        class FakeSSL:
            def __init__(self, fail_body=False, timeout=False):
                self.parts, self.calls = [], 0
                self.fail_body, self.timeout = fail_body, timeout

            def send(self, raw):
                if not 0 < len(raw) <= 16384:
                    raise AssertionError('single-send-budget-invalid')
                self.calls += 1
                if self.calls > 1 and self.fail_body:
                    if self.timeout: raise socket.timeout('synthetic')
                    raise ssl.SSLError('synthetic')
                self.parts.append(raw)
                return len(raw)

        for ref in contract.REFERENCE_IDS:
            status, response = wire.http_response(ref, GOOD_BODY)
            self.assertTrue(status == (302 if ref == 'redirect' else 200) and response == expected_http(ref), 'wire-template-mismatch')
            complete = FakeSSL()
            self.assertEqual(server.send_http(complete, response), len(response))
            self.assertTrue(b''.join(complete.parts) == expected_http(ref), 'sent-wire-template-mismatch')
            self.assertTrue(complete.parts[0].endswith(b'\r\n\r\n'), 'headers-not-sent-separately')
        self.assertEqual(len(wire.http_response('oversize', GOOD_BODY)[1].split(b'\r\n\r\n', 1)[1]), contract.MAX_INPUT + 1)
        response = expected_http('oversize')
        header_size = response.index(b'\r\n\r\n') + 4
        failed = FakeSSL(fail_body=True)
        self.assertEqual(server.send_http(failed, response), header_size)
        self.assertEqual(failed.calls, 2, 'tls-error-was-retried')
        self.assertTrue(b''.join(failed.parts) == response[:header_size], 'unconfirmed-bytes-counted')
        self.assertFalse(server.abnormal, 'expected-oversize-client-close-was-timeout')
        timed_out = FakeSSL(fail_body=True, timeout=True)
        self.assertEqual(server.send_http(timed_out, response), header_size)
        self.assertEqual(timed_out.calls, 2)
        self.assertTrue(server.abnormal, 'send-timeout-not-abnormal')

    def test_input_json_and_base64_are_closed(self):
        tokens, body = wire.parse_input(input_bytes())
        self.assertTrue(tokens == TOKENS and body == GOOD_BODY, 'private-input-parser-mismatch')
        good = json.loads(input_bytes())
        cases = [b'{', b'{}', input_bytes()[:-1] + b',"goodBodyBase64":"x"}', b'x' * (2 * contract.MAX_INPUT + 1)]
        for field, value in (('extra', 1), ('goodBodyBase64', True), ('goodBodyBase64', '!!!'), ('sourceTokensByRef', {})):
            altered = dict(good); altered[field] = value; cases.append(json.dumps(altered).encode())
        for bad in cases:
            with self.assertRaises(wire.Rejected): wire.parse_input(bad)

    def test_cli_profile_and_event_shape(self):
        root = '/tmp/chengwang-subscription-private-' + 'a' * 32
        self.assertEqual(wire.arguments(['serve', '--root', root]).deadline_seconds, 300)
        for value in ('0', '9', '361', '+30', '030', 'SENTINEL'):
            with self.assertRaises(wire.Rejected): wire.arguments(['serve', '--root', root, '--deadline-seconds', value])
        with self.assertRaises(wire.Rejected): wire.arguments(['serve', '--root', root, '--dead', '30'])
        self.assertEqual(len(contract.EVENT_KEYS), 12)
        self.assertFalse({'path', 'query', 'body', 'headers', 'hash', 'token'} & contract.EVENT_KEYS)
        with self.assertRaises(wire.Rejected): wire.check_process()

    def test_record_signal_never_touches_event_lock(self):
        class Guard(threading.Event):
            def set(self): raise AssertionError('handler-touched-event')
        for signum, name in ((signal.SIGTERM, 'term'), (signal.SIGINT, 'int')):
            server = wire.WireServer.__new__(wire.WireServer); server.stop = Guard(); server.signal_termination = ''
            with server.stop._cond:
                server.record_signal(signum, None); self.assertEqual(server.signal_termination, name)
                self.assertFalse(server.stop.is_set())

    def test_bootstrap_and_diagnostics_are_bounded(self):
        code = bootstrap(); self.assertLessEqual(len(code.encode()), 96 << 10)
        p = subprocess.run([sys.executable, '-I', '-B', '-c', code, 'serve', '--root', '/tmp/chengwang-subscription-private-' + 'a' * 32], capture_output=True, timeout=10)
        self.assertTrue(p.returncode == 1 and p.stdout == b'' and diagnostic(p.stderr) == 'security-invalid', 'bootstrap-closed-profile-rejection')
        for raw in (b'SENTINEL', b'x' * 65537, None): self.assertEqual(diagnostic(raw), 'UNCLASSIFIED')


@unittest.skipUnless(LINUX, 'auxiliary non-Linux shape checks only')
class LinuxTests(unittest.TestCase):
    def test_normal_dot_ca_and_san(self):
        f = Fixture(self); f.start()
        for index, ref in enumerate(contract.REFERENCE_IDS):
            f.dns(ref, 1, index); f.dns(ref, 28, index + 100)
        self.assertEqual(sum(e['event'] == 'dns' and e['reason'] == 'ok' for e in f.stop()), 16)

    def test_wrong_dot_ca_and_san_rejected(self):
        f = Fixture(self); f.start()
        with self.assertRaises((ssl.SSLError, ConnectionError)): f.tls(ca='source-ca.pem')
        f.until(lambda es: sum(e['event'] == 'close' for e in es) == 1); self.assertFalse(any(e['event'] == 'dns' for e in f.stop()))
        f = Fixture(self, wrong_resolver=True); f.start()
        with self.assertRaises((ssl.SSLError, ConnectionError)): f.tls()
        f.until(lambda es: sum(e['event'] == 'close' for e in es) == 1); self.assertFalse(any(e['event'] == 'dns' for e in f.stop()))

    def test_https_good_sources_same_private_yaml(self):
        f = Fixture(self); f.start(); f.http('good-a'); f.http('good-b')
        events = f.stop(); self.assertEqual([e['reference'] for e in events if e['event'] == 'http'], ['good-a', 'good-b'])

    def test_https_bad_yaml_redirect_and_oversize(self):
        f = Fixture(self); f.start()
        for ref in ('bad', 'redirect', 'oversize'): f.http(ref)
        self.assertEqual([e['status'] for e in f.stop() if e['event'] == 'http'], [200, 302, 200])

    def test_wrong_source_ca_rejected_without_http(self):
        f = Fixture(self); f.start()
        with self.assertRaises((ssl.SSLError, ConnectionError)): f.tls('https', contract.SOURCE_HOSTS['wrongca'], 'resolver-ca.pem')
        f.until(lambda es: sum(e['event'] == 'close' for e in es) == 1); self.assertFalse(any(e['event'] == 'http' for e in f.stop()))

    def test_wrong_source_name_rejected_without_http(self):
        f = Fixture(self); f.start()
        with self.assertRaises((ssl.SSLError, ConnectionError)): f.tls('https', contract.SOURCE_HOSTS['wrongname'])
        f.until(lambda es: sum(e['event'] == 'close' for e in es) == 1); self.assertFalse(any(e['event'] == 'http' for e in f.stop()))

    def test_invalid_token_and_sensitive_headers_redacted(self):
        f = Fixture(self); f.start()
        for data in (request(token=b'f' * 64), request(extra=b'Authorization: SENTINEL\r\n')):
            with f.tls('https') as conn: conn.sendall(data); self.assertTrue(recv_all(conn) == b'', 'invalid-request-received-body')
        self.assertEqual(sum(e['event'] == 'http' and e['reason'] == 'auth-invalid' for e in f.stop()), 2)

    def test_unknown_dns_and_http_fail_closed(self):
        f = Fixture(self); f.start(); data = query(host='unknown.subscription.example')
        with f.tls() as conn: conn.sendall(struct.pack('!H', len(data)) + data); self.assertTrue(recv_all(conn) == b'')
        with f.tls('https') as conn: conn.sendall(request().replace(b'/subscription?', b'/unknown?')); self.assertTrue(recv_all(conn) == b'')
        self.assertTrue(any(e['reason'] == 'query-invalid' for e in f.stop()))

    def test_private_modes_owner_and_extra_inputs_rejected(self):
        for mode in ('directory', 'file', 'owner', 'extra-json'):
            f = Fixture(self); p = f.root / 'wire-input.json'
            if mode == 'directory': os.chmod(f.root, 0o755)
            elif mode == 'file': os.chmod(p, 0o644)
            elif mode == 'owner': os.chown(p, 0, 10001)
            else: p.write_bytes(input_bytes()[:-1] + b',"extra":true}')
            f.start(rejected=True)

    def test_symlink_hardlink_and_fifo_inputs_rejected(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            f = Fixture(self); path = f.root / 'source-key.private.pem'; original = f.root / 'original.private'; path.rename(original)
            if kind == 'symlink': path.symlink_to(original)
            elif kind == 'hardlink': os.link(original, path)
            else: os.mkfifo(path, 0o600); os.chown(path, 10001, 10001)
            f.start(rejected=True)

    def test_input_replacement_and_mutation_fail_closed(self):
        for kind in ('replace', 'mutate'):
            f = Fixture(self); f.start(); f.dns(); p = f.root / 'wire-input.json'
            if kind == 'replace':
                replacement = f.root / 'replacement.private'; private_write(replacement, input_bytes()); os.chown(replacement, 10001, 10001); os.replace(replacement, p)
            else: p.write_bytes(input_bytes() + b' ')
            with socket.create_connection((contract.DOT_HOST, contract.DOT_PORT), timeout=2): pass
            stdout, stderr = f.process.communicate(timeout=5)
            self.assertTrue(f.process.returncode == 1 and stdout == b'' and diagnostic(stderr) != 'UNCLASSIFIED', 'runtime-input-replacement-not-rejected')
            self.assertFalse((f.root / 'wire-stopped.json').exists())

    def test_term_joins_inflight_tls(self):
        f = Fixture(self); f.start()
        with socket.create_connection((contract.DOT_HOST, contract.DOT_PORT), timeout=2):
            f.until(lambda es: len(es) == 1 and es[0]['event'] == 'connect'); f.stop()
        self.assertEqual(f.stopped['termination'], 'term')

    def test_int_joins_partial_request(self):
        f = Fixture(self); f.start()
        with f.tls('https') as conn:
            conn.sendall(b'GET /subscription?'); f.until(lambda es: any(e['event'] == 'tls' for e in es)); f.stop(signal.SIGINT)
        self.assertEqual(f.stopped['termination'], 'int')

    def test_request_timeout_and_deadline_not_normal_stop(self):
        f = Fixture(self); f.start()
        with f.tls('https') as conn: conn.sendall(b'GET /subscription?'); self.assertTrue(recv_all(conn) == b'')
        f.until(lambda es: any(e['reason'] == 'timeout' for e in es)); f.stop(expected=2)
        f = Fixture(self); f.start(deadline=10); f.process.wait(timeout=13); f.stop(expected=2)
        self.assertEqual(f.stopped['termination'], 'deadline')

    def test_worker_capacity_and_connection_budget(self):
        f = Fixture(self); f.start(); clients = []
        try:
            for number in range(1, 10):
                clients.append(socket.create_connection((contract.DOT_HOST, contract.DOT_PORT), timeout=2))
                f.until(lambda es: sum(e['event'] == 'connect' for e in es) >= number)
            f.until(lambda es: any(e['connection'] == 9 and e['reason'] == 'capacity' for e in es)
                    and len(list(pathlib.Path('/proc', str(f.process.pid), 'task').iterdir())) >= 10)
            f.stop(expected=2)
        finally:
            for c in clients: c.close()
        f = Fixture(self); f.start()
        for qid in range(contract.MAX_CONNECTIONS): f.dns(kind=28, qid=qid)
        f.process.wait(timeout=5); f.stop(expected=2); self.assertEqual(f.stopped['termination'], 'budget')

    def test_ready_stopped_and_active_listener_are_atomic(self):
        f = Fixture(self); f.start(); ready = (f.root / 'wire-ready.json').read_bytes()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as competing:
            with self.assertRaises(OSError): competing.bind((contract.DOT_HOST, contract.DOT_PORT))
        f.stop(); self.assertTrue((f.root / 'wire-ready.json').read_bytes() == ready, 'ready-was-replaced')
        self.assertFalse(any(p.name.endswith('.pending') for p in f.root.iterdir()))
        other = Fixture(self); other.start(); other.stop()


def main():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    if not result.wasSuccessful() or result.testsRun != 24 or len(result.skipped) != (0 if LINUX else 16): return 1
    print('SUBSCRIPTION_WIRE_TESTS=PASS tests=24 passed=24 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none' if LINUX else
          'SUBSCRIPTION_WIRE_TESTS_AUXILIARY=PASS tests=24 passed=8 skipped=16 real_linux=false')
    return 0


if __name__ == '__main__': raise SystemExit(main())
