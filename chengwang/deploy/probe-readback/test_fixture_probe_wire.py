"""Wire fixture prerequisites: shape on Windows; real low-UID TLS on Linux.

The Linux caller must already provide the isolated GUA/netns and low-port
profile. These tests do not configure interfaces, routes, sysctls or trust.
Passing them is not a real probe-agent/spool/API end-to-end acceptance.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
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

import fixture_probe_wire as wire


SOURCE = pathlib.Path(__file__).with_name('fixture_probe_wire.py').read_bytes()
OBSERVATIONS = []
LINUX = sys.platform.startswith('linux')
PUBLIC_BODIES = (b'chengwang-probe-pass-v1\n', b'chengwang-probe-restricted-v1\n',
                 b'chengwang-probe-limited-v1\n')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap():
    if not 0 < len(SOURCE) <= 131072:
        raise ValueError('source-size-invalid')
    payload = base64.b85encode(zlib.compress(SOURCE, 9))
    code = '''import base64,hashlib,sys,types,zlib
try:
    payload,length,digest=PAYLOAD
    decoder=zlib.decompressobj()
    raw=decoder.decompress(base64.b85decode(payload),length+1)
    if (not 0<length<=131072 or len(raw)!=length or not decoder.eof
        or decoder.unused_data or decoder.unconsumed_tail
        or hashlib.sha256(raw).hexdigest()!=digest):
        raise ValueError('invalid')
    module=types.ModuleType('fixture_probe_wire')
    module.__file__='<fixture_probe_wire.py>'
    sys.modules[module.__name__]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
except Exception:
    sys.stderr.write('PROBE_WIRE_ERROR=runtime-failed\\n')
    raise SystemExit(1) from None
raise SystemExit(module.main())
'''.replace('PAYLOAD', repr((payload, len(SOURCE), sha(SOURCE))), 1)
    if len(code.encode()) > 96 << 10:
        raise ValueError('argument-size-invalid')
    return code


def diagnostic(raw):
    if type(raw) is not bytes or len(raw) > 65536:
        return 'UNCLASSIFIED'
    return {('PROBE_WIRE_ERROR=' + code + ending).encode(): code.upper().replace('-', '_')
            for code in wire.ERROR_CODES for ending in ('\n', '\r\n')}.get(raw, 'UNCLASSIFIED')


def query(host, qtype=1, qid=0x1234):
    name = b''.join(bytes((len(label),)) + label.encode('ascii') for label in host.split('.')) + b'\x00'
    return struct.pack('!6H', qid, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', qtype, 1)


def expected_dns(host, qtype=1, qid=0x1234):
    raw = query(host, qtype, qid)
    answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x08\x08\x04\x04'
    return struct.pack('!6H', qid, 0x8180, 1, int(qtype == 1), 0, 0) + raw[12:] + (answer if qtype == 1 else b'')


def request(host, port=False, extra=b''):
    return (b'GET /health HTTP/1.1\r\nHost: ' + host.encode() + (b':443' if port else b'')
            + b'\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n' + extra + b'\r\n')


def expected_http(index):
    status, phrase = ((200, b'OK'), (403, b'Forbidden'), (429, b'Too Many Requests'))[index]
    body = PUBLIC_BODIES[index]
    return (b'HTTP/1.1 ' + str(status).encode() + b' ' + phrase + b'\r\nContent-Type: text/plain\r\n'
            + b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
            + (b'Retry-After: 30\r\n' if status == 429 else b'')
            + b'Cache-Control: no-store\r\nConnection: close\r\n\r\n' + body)


def recv_all(connection):
    chunks = []
    while True:
        try:
            part = connection.recv(65536)
        except (ssl.SSLError, ConnectionResetError):
            break
        if not part:
            break
        chunks.append(part)
        if sum(map(len, chunks)) > 65536:
            raise AssertionError('response-size-invalid')
    return b''.join(chunks)


def wait_for(predicate, seconds=4):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError('bounded-condition-not-observed')


def private_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


class Fixture:
    def __init__(self, owner_test):
        if os.geteuid() != 0 or shutil.which('setpriv') is None or shutil.which('openssl') is None:
            raise AssertionError('linux-native-orchestrator-required')
        self.test = owner_test
        self.root = pathlib.Path('/tmp/chengwang-probe-readback-' + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        os.chown(self.root, 10001, 10001)
        self.directory = self.root / 'wire'
        self.directory.mkdir(mode=0o700)
        os.chown(self.directory, 10001, 10001)
        self.process = None
        self.ready = self.stopped = None
        self.collected = False
        self.started = False
        self.inputs = {}
        owner_test.addCleanup(self.cleanup)
        self.certificate_files()

    def openssl(self, *arguments):
        result = subprocess.run(['openssl', *arguments], cwd=self.root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode:
            raise AssertionError('certificate-provisioning-failed')

    def certificate_files(self):
        for service, hosts in (('dot', (wire.DOT_NAME,)), ('https', wire.HOSTS)):
            self.openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                         '-nodes', '-days', '1', '-subj', '/CN=probe-wire-' + service + '-ca',
                         '-addext', 'basicConstraints=critical,CA:TRUE',
                         '-keyout', service + '-ca.key', '-out', service + '-ca.pem')
            self.openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                         '-nodes', '-subj', '/CN=' + hosts[0], '-keyout', service + '-leaf.key',
                         '-out', service + '-leaf.csr')
            extension = ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                         'extendedKeyUsage=serverAuth\nsubjectAltName='
                         + ','.join('DNS:' + host for host in hosts) + '\n').encode()
            private_write(self.root / (service + '-leaf.ext'), extension)
            self.openssl('x509', '-req', '-in', service + '-leaf.csr', '-CA', service + '-ca.pem',
                         '-CAkey', service + '-ca.key', '-set_serial', '10', '-days', '1',
                         '-extfile', service + '-leaf.ext', '-out', service + '-leaf.pem')
            for name, source in ((service + '-cert.pem', service + '-leaf.pem'),
                                 (service + '-key.private.pem', service + '-leaf.key')):
                raw = (self.root / source).read_bytes()
                path = self.directory / name
                private_write(path, raw)
                os.chown(path, 10001, 10001)
                self.inputs[name] = sha(raw)

    def start(self, deadline=300, expect_ready=True):
        ready_path = self.directory / 'ready.json'
        prior_ready = sha(ready_path.read_bytes()) if ready_path.is_file() else None
        args = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups',
                '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                sys.executable, '-I', '-B', '-c', bootstrap(), 'serve',
                '--fixture-root', str(self.root), '--deadline-seconds', str(deadline)]
        self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin',
                                        'LANG': 'C', 'LC_ALL': 'C'})
        if not expect_ready:
            stdout, stderr = self.process.communicate(timeout=5)
            self.test.assertEqual(self.process.returncode, 1, 'startup-not-rejected')
            self.test.assertTrue(stdout == b'', 'unexpected-helper-stdout')
            self.test.assertNotEqual(diagnostic(stderr), 'UNCLASSIFIED', 'unsafe-startup-diagnostic')
            if prior_ready is None:
                self.test.assertFalse(ready_path.exists(), 'rejected-startup-ready')
            else:
                self.test.assertEqual(sha(ready_path.read_bytes()), prior_ready, 'existing-ready-was-replaced')
            return

        def ready():
            path = self.directory / 'ready.json'
            if path.exists():
                value = json.loads(path.read_bytes())
                self.test.assertEqual(value['schema'], wire.READY_SCHEMA)
                self.test.assertEqual(value['pid'], self.process.pid)
                self.test.assertEqual((value['uid'], value['gid']), (10001, 10001))
                self.test.assertEqual((value['dotAddress'], value['dotPort']), ('127.0.0.1', 1853))
                self.test.assertEqual((value['httpsAddress'], value['httpsPort']), ('8.8.4.4', 443))
                self.test.assertIs(value['tls'], True)
                return value
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise AssertionError('helper-startup-' + diagnostic(stderr))
            return None
        self.ready = wait_for(ready)
        self.started = True
        self.test.assertEqual(self.events(), [], 'readiness-made-a-network-connection')

    def events(self, complete=False):
        path = self.directory / 'events.jsonl'
        if not path.exists():
            if complete:
                raise AssertionError('final-event-log-missing')
            return []
        raw = path.read_bytes()
        if raw and not raw.endswith(b'\n'):
            if complete:
                raise AssertionError('final-event-log-incomplete')
            # Online polling observes only a completed prefix; never use this
            # permissive view as the stopped/closed log acceptance.
            raw = raw[:raw.rfind(b'\n') + 1]
        return [json.loads(line) for line in raw.splitlines()]

    def until(self, predicate):
        return wait_for(lambda: predicate(self.events()))

    def tls(self, service='dot', host=None, ca=None):
        name = host or (wire.DOT_NAME if service == 'dot' else wire.HOSTS[0])
        context = ssl.create_default_context(cafile=str(self.root / (ca or service + '-ca.pem')))
        if service == 'https':
            context.set_alpn_protocols(['http/1.1'])
        address = (wire.DOT_ADDRESS, wire.DOT_PORT) if service == 'dot' else (wire.HTTPS_ADDRESS, wire.HTTPS_PORT)
        raw = socket.create_connection(address, timeout=3)
        try:
            result = context.wrap_socket(raw, server_hostname=name)
            result.settimeout(3)
            return result
        except BaseException:
            raw.close()
            raise

    def dns(self, host, qtype=1, qid=0x1234):
        raw = query(host, qtype, qid)
        with self.tls() as connection:
            connection.sendall(struct.pack('!H', len(raw)) + raw)
            response = recv_all(connection)
        self.test.assertEqual(response, struct.pack('!H', len(expected_dns(host, qtype, qid)))
                              + expected_dns(host, qtype, qid))

    def http(self, host, port=False):
        with self.tls('https', host) as connection:
            connection.sendall(request(host, port))
            response = recv_all(connection)
        self.test.assertEqual(response, expected_http(wire.HOSTS.index(host)))

    def stop(self, signum=signal.SIGTERM, expected=0):
        if self.process.poll() is None:
            self.process.send_signal(signum)
        stdout, stderr = self.process.communicate(timeout=5)
        self.test.assertEqual(self.process.returncode, expected, 'helper-exit-code-invalid')
        self.test.assertTrue(stdout == b'', 'helper-stdout-not-empty')
        self.test.assertTrue(stderr == b'', 'helper-private-diagnostic-not-empty')
        self.stopped = json.loads((self.directory / 'stopped.json').read_bytes())
        self.test.assertEqual(self.stopped['schema'], wire.STOPPED_SCHEMA)
        self.test.assertEqual(self.stopped['accepted'], self.stopped['closed'])
        self.test.assertEqual(self.stopped['workerThreadsAlive'], 0)
        self.test.assertEqual(self.stopped['normalStop'], expected == 0)
        events = self.events(complete=True)
        self.test.assertEqual([e['ordinal'] for e in events], list(range(1, len(events) + 1)))
        self.test.assertEqual(self.stopped['events'], len(events))
        self.test.assertTrue(all(set(e) == wire.EVENT_KEYS for e in events))
        self.test.assertTrue(all(a['monotonicNS'] <= b['monotonicNS'] for a, b in zip(events, events[1:])))
        for event in events:
            received = event['receivedUnixNano']
            if event['event'] in ('dns', 'http') and event['reason'] == 'ok':
                self.test.assertTrue(type(received) is str and re.fullmatch(r'[1-9][0-9]{0,18}', received)
                                     is not None, 'receive-time-not-bounded-decimal')
            else:
                self.test.assertEqual(received, '')
        for number in range(1, self.stopped['accepted'] + 1):
            chain = [e for e in events if e['connection'] == number]
            self.test.assertEqual(chain[0]['event'], 'connect')
            self.test.assertEqual(chain[-1]['event'], 'close')
            self.test.assertEqual(sum(e['event'] == 'close' for e in chain), 1)
        self.test.assertLessEqual(len(events), wire.MAX_EVENTS)
        for name, digest in self.inputs.items():
            self.test.assertEqual(sha((self.directory / name).read_bytes()), digest,
                                  'private-input-bytes-were-mutated')
        for path in self.directory.iterdir():
            value = path.lstat()
            self.test.assertTrue(stat.S_ISREG(value.st_mode))
            self.test.assertEqual((stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid, value.st_nlink),
                                  (0o600, 10001, 10001, 1))
        return events

    def collect(self, label):
        if self.started and self.stopped is not None and not self.collected:
            OBSERVATIONS.append({'testName': self.test._testMethodName, 'label': label,
                                 'ready': self.ready, 'events': self.events(complete=True), 'stopped': self.stopped})
            self.collected = True

    def cleanup(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=3)
                raise AssertionError('emergency-helper-kill-required')
        if (self.root.parent != pathlib.Path('/tmp') or not wire.FIXTURE_ROOT.fullmatch(str(self.root))
                or self.root.is_symlink()):
            raise AssertionError('unsafe-fixture-cleanup-target')
        shutil.rmtree(self.root)


class ShapeTests(unittest.TestCase):
    def test_dns_a_and_aaaa_are_exact_wire(self):
        for host in wire.HOSTS:
            for qtype in (1, 28):
                parsed = wire.dns_answer(query(host, qtype))
                self.assertEqual(parsed[0], host)
                self.assertEqual(parsed[-1], expected_dns(host, qtype))

    def test_dns_rejects_noncanonical_questions(self):
        good = query(wire.HOSTS[0])
        invalid = (b'', good + b'\0', query('unknown.probe.example'), query(wire.HOSTS[0], 15),
                   good[:2] + b'\0\0' + good[4:], good[:4] + b'\0\2' + good[6:],
                   good[:12] + b'\xc0\x0c' + good[-4:], good[:-1], good + b'x' * 512)
        for raw in invalid:
            with self.assertRaises(wire.Rejected):
                wire.dns_answer(raw)

    def test_http_responses_have_fixed_public_bytes(self):
        for index, host in enumerate(wire.HOSTS):
            self.assertEqual(wire.http_answer(host)[1], expected_http(index))
            for port in (False, True):
                self.assertEqual(wire.http_host(request(host, port), host), host)

    def test_http_parser_rejects_sensitive_and_ambiguous_input(self):
        host = wire.HOSTS[0]
        invalid = (request(host, extra=b'Authorization: SENTINEL\r\n'),
                   request(host, extra=b'Cookie: SENTINEL\r\n'),
                   request(host, extra=b'Host: unknown\r\n'),
                   request(host).replace(b'GET /health', b'POST /health'),
                   request(host).replace(b'/health', b'/health?secret=SENTINEL'),
                   request(host, extra=b'Content-Length: 0\r\n'), request(host) + b'x')
        for raw in invalid:
            with self.assertRaises(wire.Rejected):
                wire.http_host(raw, host)
        with self.assertRaises(wire.Rejected):
            wire.http_host(request(host), wire.HOSTS[1])

    def test_cli_rejects_noncanonical_fixture_and_deadline(self):
        root = '/tmp/chengwang-probe-readback-' + 'a' * 32
        self.assertEqual(wire.arguments(['serve', '--fixture-root', root]).deadline_seconds, 300)
        for value in ('0', '9', '361', '030', '+30', 'SECRET'):
            with self.assertRaises(wire.Rejected):
                wire.arguments(['serve', '--fixture-root', root, '--deadline-seconds', value])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(wire.Rejected):
            wire.arguments(['SECRET'])
        self.assertEqual(stderr.getvalue(), '')

    def test_event_shape_has_no_request_content(self):
        self.assertEqual(len(wire.EVENT_KEYS), 22)
        self.assertFalse({'headers', 'body', 'request', 'key', 'path'} & wire.EVENT_KEYS)
        self.assertEqual((wire.MAX_CONNECTIONS, wire.MAX_WORKERS, wire.MAX_EVENTS), (128, 8, 512))
        self.assertEqual((wire.DOT_ADDRESS, wire.DOT_PORT, wire.HTTPS_ADDRESS, wire.HTTPS_PORT),
                         ('127.0.0.1', 1853, '8.8.4.4', 443))

    def test_profile_and_private_metadata_are_closed(self):
        class Metadata:
            st_mode = stat.S_IFREG | 0o600
            st_uid = st_gid = 10001
            st_nlink = 1
        value = Metadata()
        self.assertTrue(wire.private(value))
        value.st_nlink = 2
        self.assertFalse(wire.private(value))
        value.st_nlink, value.st_uid = 1, 0
        self.assertFalse(wire.private(value))
        with self.assertRaises(wire.Rejected):
            wire.check_process()

    def test_bootstrap_and_diagnostics_are_bounded(self):
        class GuardEvent(threading.Event):
            def set(self):
                raise AssertionError('signal-handler-must-not-set-event')

        # Deterministic synthetic condition-lock interleaving, not a claim to
        # reproduce the unobserved stack of any previous native failure.
        for signum, expected in ((signal.SIGTERM, 'term'), (signal.SIGINT, 'int')):
            server = wire.WireServer.__new__(wire.WireServer)
            server.stop = GuardEvent()
            server.termination = server.signal_termination = ''
            with server.stop._cond:
                server.record_signal(signum, None)
                self.assertEqual(server.signal_termination, expected)
                self.assertEqual(server.termination, '')
                self.assertFalse(server.stop.is_set())
                server.record_signal(signal.SIGINT if signum == signal.SIGTERM else signal.SIGTERM)
                self.assertEqual(server.signal_termination, expected)
        code = bootstrap()
        self.assertLessEqual(len(code.encode()), 96 << 10)
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, 'serve', '--fixture-root',
                                 '/tmp/chengwang-probe-readback-' + 'a' * 32],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(diagnostic(result.stderr), 'SECURITY_INVALID')
        for raw in (b'SECRET', b'PROBE_WIRE_ERROR=SECRET\n', b'x' * 65537, None):
            self.assertEqual(diagnostic(raw), 'UNCLASSIFIED')


@unittest.skipUnless(LINUX, 'auxiliary non-Linux shape checks only')
class LinuxTests(unittest.TestCase):
    def fixture(self):
        result = Fixture(self)
        return result

    def test_dot_a_and_aaaa_actual_tls(self):
        fixture = self.fixture()
        fixture.start()
        for index, host in enumerate(wire.HOSTS):
            fixture.dns(host, 1, 100 + index)
            fixture.dns(host, 28, 200 + index)
        events = fixture.stop()
        self.assertEqual(sum(e['event'] == 'dns' and e['complete'] for e in events), 6)
        fixture.collect('dot-normal')

    def test_https_three_hosts_actual_tls(self):
        fixture = self.fixture()
        fixture.start()
        for index, host in enumerate(wire.HOSTS):
            fixture.http(host, index == 1)
        events = fixture.stop()
        self.assertEqual([e['status'] for e in events if e['event'] == 'http'], [200, 403, 429])
        fixture.collect('https-normal')

    def test_unknown_dns_is_rejected_without_response(self):
        fixture = self.fixture()
        fixture.start()
        raw = query('private-secret.invalid')
        with fixture.tls() as connection:
            connection.sendall(struct.pack('!H', len(raw)) + raw)
            self.assertEqual(recv_all(connection), b'')
        events = fixture.stop()
        self.assertTrue(any(e['event'] == 'dns' and e['reason'] == 'query-invalid' for e in events))
        self.assertNotIn(b'private-secret', (fixture.directory / 'events.jsonl').read_bytes())
        fixture.collect('dns-rejected')

    def test_sensitive_http_is_redacted_and_rejected(self):
        fixture = self.fixture()
        fixture.start()
        with fixture.tls('https') as connection:
            connection.sendall(request(wire.HOSTS[0], extra=b'Authorization: SECRET-CREDENTIAL\r\n'))
            self.assertEqual(recv_all(connection), b'')
        events = fixture.stop()
        self.assertTrue(any(e['event'] == 'http' and e['reason'] == 'auth-present' for e in events))
        self.assertNotIn(b'SECRET-CREDENTIAL', (fixture.directory / 'events.jsonl').read_bytes())
        fixture.collect('http-redacted')

    def test_wrong_ca_and_hostname_fail_normal_tls(self):
        fixture = self.fixture()
        fixture.start()
        for host, ca in ((wire.DOT_NAME, 'https-ca.pem'), ('wrong.probe.example', 'dot-ca.pem')):
            with self.assertRaises((ssl.SSLError, ConnectionError)):
                with fixture.tls(host=host, ca=ca):
                    pass
        fixture.until(lambda es: sum(e['event'] == 'close' for e in es) == 2)
        events = fixture.stop()
        self.assertFalse(any(e['event'] in ('dns', 'http') for e in events))
        fixture.collect('tls-rejected')

    def test_term_joins_inflight_tls(self):
        fixture = self.fixture()
        fixture.start()
        with socket.create_connection((wire.DOT_ADDRESS, wire.DOT_PORT), timeout=2):
            fixture.until(lambda es: len(es) == 1 and es[0]['event'] == 'connect')
            start = time.monotonic()
            events = fixture.stop()
            self.assertLess(time.monotonic() - start, 4)
        self.assertEqual(fixture.stopped['termination'], 'term')
        self.assertTrue(any(e['event'] == 'close' for e in events))
        fixture.collect('term')

    def test_int_joins_incomplete_dns(self):
        fixture = self.fixture()
        fixture.start()
        with fixture.tls() as connection:
            connection.sendall(b'\x00')
            fixture.until(lambda es: any(e['event'] == 'tls' and e['tls'] for e in es))
            fixture.stop(signal.SIGINT)
        self.assertEqual(fixture.stopped['termination'], 'int')
        fixture.collect('int')

    def test_deadline_is_not_normal_stop(self):
        fixture = self.fixture()
        fixture.start(deadline=10)
        fixture.process.wait(timeout=13)
        fixture.stop(expected=2)
        self.assertEqual(fixture.stopped['termination'], 'deadline')
        fixture.collect('deadline')

    def test_private_inputs_reject_symlink_hardlink_fifo(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            fixture = self.fixture()
            path = fixture.directory / 'dot-key.private.pem'
            original = fixture.root / 'original-key.private'
            path.rename(original)
            if kind == 'symlink':
                path.symlink_to(original)
            elif kind == 'hardlink':
                os.link(original, path)
            else:
                os.mkfifo(path, 0o600)
                os.chown(path, 10001, 10001)
            before = sha(original.read_bytes())
            fixture.start(expect_ready=False)
            self.assertEqual(sha(original.read_bytes()), before, 'private-input-was-mutated')

    def test_private_directory_and_file_modes_fail_closed(self):
        for target, mode in (('directory', 0o755), ('key', 0o644), ('owner', 0o600)):
            fixture = self.fixture()
            path = fixture.directory if target == 'directory' else fixture.directory / 'https-key.private.pem'
            if target == 'owner':
                os.chown(path, 0, 10001)
            else:
                os.chmod(path, mode)
            before = path.lstat()
            fixture.start(expect_ready=False)
            self.assertEqual((path.lstat().st_mode, path.lstat().st_uid), (before.st_mode, before.st_uid))

    def test_ready_and_stopped_are_atomic_no_replace(self):
        fixture = self.fixture()
        fixture.start()
        fixture.dns(wire.HOSTS[0])
        fixture.stop()
        before = {p.name: sha(p.read_bytes()) for p in fixture.directory.iterdir()}
        fixture.collect('atomic')
        fixture.start(expect_ready=False)
        self.assertEqual({p.name: sha(p.read_bytes()) for p in fixture.directory.iterdir()}, before)

    def test_fixed_ports_rebind_and_active_listener_rejects(self):
        first, second, rejected = self.fixture(), self.fixture(), self.fixture()
        first.start()
        first.http(wire.HOSTS[0])
        rejected.start(expect_ready=False)
        first.stop()
        first.collect('fixed-port-first')
        second.start()
        second.http(wire.HOSTS[2])
        second.stop()
        second.collect('fixed-port-second')

    def test_worker_capacity_before_stop_is_bounded(self):
        fixture = self.fixture()
        fixture.start()
        connections = []
        try:
            for number in range(1, 10):
                connections.append(socket.create_connection((wire.DOT_ADDRESS, wire.DOT_PORT), timeout=2))
                fixture.until(lambda es: sum(e['event'] == 'connect' for e in es) >= number)
            def capacity(es):
                chain = [e for e in es if e['connection'] == 9]
                return (len(chain) == 2 and chain[-1]['event'] == 'close'
                        and chain[-1]['reason'] == 'capacity'
                        and len(list(pathlib.Path('/proc', str(fixture.process.pid), 'task').iterdir())) >= 10
                        and all([e['event'] for e in es if e['connection'] == n] == ['connect']
                                for n in range(1, 9)))
            fixture.until(capacity)
            fixture.stop()
        finally:
            for connection in connections:
                connection.close()
        fixture.collect('capacity')

    def test_changed_certificate_input_fails_closed(self):
        fixture = self.fixture()
        fixture.start()
        fixture.dns(wire.HOSTS[0])
        path = fixture.directory / 'dot-cert.pem'
        before = path.read_bytes()
        replacement = fixture.root / 'replacement.private'
        private_write(replacement, before)
        os.chown(replacement, 10001, 10001)
        os.replace(replacement, path)
        with socket.create_connection((wire.DOT_ADDRESS, wire.DOT_PORT), timeout=2):
            pass
        stdout, stderr = fixture.process.communicate(timeout=5)
        self.assertEqual(fixture.process.returncode, 1)
        self.assertTrue(stdout == b'', 'unexpected-helper-stdout')
        self.assertIn(diagnostic(stderr), ('INPUT_INVALID', 'RUNTIME_FAILED'))
        self.assertEqual(sha(path.read_bytes()), sha(before))
        self.assertFalse((fixture.directory / 'stopped.json').exists())

    def test_incomplete_http_times_out_and_closes(self):
        fixture = self.fixture()
        fixture.start()
        with fixture.tls('https') as connection:
            connection.sendall(b'GET /health HTTP/1.1\r\nHost: ')
            self.assertEqual(recv_all(connection), b'')
        fixture.until(lambda es: any(e['event'] == 'close' and e['reason'] == 'timeout' for e in es))
        fixture.stop()
        fixture.collect('http-timeout')

    def test_connection_budget_is_fail_closed(self):
        fixture = self.fixture()
        fixture.start()
        for index in range(128):
            fixture.dns(wire.HOSTS[0], 28, index)
        fixture.process.wait(timeout=5)
        fixture.stop(expected=2)
        self.assertEqual(fixture.stopped['termination'], 'budget')
        self.assertEqual(fixture.stopped['accepted'], 128)
        self.assertEqual(fixture.stopped['events'], 512)
        fixture.collect('budget')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-dir')
    options = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    if result.testsRun != 24 or len(result.skipped) != (0 if LINUX else 16):
        return 1
    if options.evidence_dir:
        destination = pathlib.Path(options.evidence_dir)
        if not destination.is_dir() or destination.is_symlink():
            raise SystemExit('evidence-directory-invalid')
        private_write(destination / 'probe-wire-fixture-observations.json',
                      wire.encoded({'schema': 'chengwang.probe-wire-fixture-observations/v1',
                                    'realLinux': LINUX, 'cases': OBSERVATIONS}))
    print(('PROBE_WIRE_TESTS=PASS tests=24 passed=24 skipped=0 real_linux=true '
           'helper_uid=10001 helper_capabilities=none') if LINUX else
          'PROBE_WIRE_TESTS_AUXILIARY=PASS tests=24 passed=8 skipped=16 real_linux=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
