"""Closed source-fixture prerequisite tests, not product source acceptance."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import unittest
import uuid

import fixture_source as source


HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_BODY = b'{"fixture":"source"}\n'
BOUNDARY_BODY = b'x' * 262145
ERROR_BODY = b'{"code":"fixture_source_unavailable"}\n'
FORBIDDEN_BODY = b'{"code":"fixture_source_forbidden"}\n'
REDIRECT_BODY = b'{"code":"fixture_source_redirect"}\n'
MODES = (
    'json', 'forbidden', 'unavailable', 'redirect', 'content-type-missing',
    'content-type-duplicate', 'content-type-wrong', 'content-encoding', 'trailer',
    'chunked', 'length-missing', 'length-zero', 'length-oversize', 'length-short',
    'body-truncated', 'header-oversize', 'stall-headers', 'stall-body',
    'close-before-headers',
)
LABELS_BY_TEST = {
    'test_normal_tls_json_and_generation': ('normal',),
    'test_wrong_ca_and_san_record_failed_tls': ('wrong-ca', 'wrong-san'),
    'test_real_wire_modes': MODES,
    'test_plan_epochs_reject_conflict_rollback_then_recover': ('epoch-sequence',),
    'test_sensitive_request_headers_and_targets_are_redacted': ('sensitive-request',),
    'test_body_bytes_remain_immutable_and_mismatch_is_rejected': ('body-mismatch',),
    'test_private_input_links_and_fifo_rejected': (),
    'test_private_tree_and_certificate_rejections_preserve_bytes': (),
    'test_ready_atomic_and_outputs_never_overwritten': ('ready-atomic',),
    'test_fixed_port_rebind_and_active_listener_exclusivity': ('fixed-port-first', 'fixed-port-second'),
    'test_term_joins_slow_tls_connections': ('stop-term',),
    'test_int_joins_incomplete_http_headers': ('stop-int',),
    'test_deadline_closes_inflight_tls': ('deadline',),
    'test_body_size_boundary_and_oversize_refusal': ('body-boundary',),
    'test_worker_capacity_is_logged_and_joined': ('capacity-stop',),
    'test_missing_or_changed_body_never_reflects_private_bytes': ('missing-body',),
}
EVENT_KEYS = frozenset((
    'schema', 'ordinal', 'connection', 'event', 'reason', 'epoch', 'planSHA256',
    'pathClass', 'generation', 'mode', 'status', 'representationSHA256',
    'representationBytes', 'wireSHA256', 'wireBytes', 'writtenBytes',
    'wireComplete', 'authPresent', 'tls',
))
OBSERVATIONS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def plan(epoch=1, mode='json', body=DEFAULT_BODY, generation=False):
    response = {'mode': mode, 'bodySHA256': '' if mode in source.NO_BODY_MODES else sha(body)}
    responses = {'latest.json': response}
    if generation:
        responses['2.json'] = dict(response)
    return {'schema': 'chengwang.product-source-plan/v1', 'epoch': epoch, 'responses': responses}


def expected_wire(mode, body=DEFAULT_BODY):
    """Independent fixed grammar: do not derive expectations from build_wire."""
    if mode == 'close-before-headers':
        return 0, b'', b''
    status, phrase, representation = 200, b'OK', body
    if mode == 'forbidden':
        status, phrase, representation = 403, b'Forbidden', FORBIDDEN_BODY
    elif mode in ('unavailable', 'stall-headers'):
        status, phrase, representation = 503, b'Service Unavailable', ERROR_BODY
    elif mode == 'redirect':
        status, phrase, representation = 302, b'Found', REDIRECT_BODY
    fields = [b'HTTP/1.1 ' + str(status).encode('ascii') + b' ' + phrase + b'\r\n']
    if mode != 'content-type-missing':
        fields.append(b'Content-Type: ' + (b'text/plain' if mode == 'content-type-wrong'
                                          else b'application/json') + b'\r\n')
        if mode == 'content-type-duplicate':
            fields.append(b'Content-Type: application/json\r\n')
    length = (0 if mode == 'length-zero' else 262145 if mode == 'length-oversize'
              else len(representation) - 1 if mode == 'length-short' else len(representation))
    if mode == 'chunked':
        fields.append(b'Transfer-Encoding: chunked\r\n')
    elif mode != 'length-missing':
        fields.append(b'Content-Length: ' + str(length).encode('ascii') + b'\r\n')
    special = {
        'redirect': b'Location: https://redirect.fixture.invalid/blocked\r\n',
        'content-encoding': b'Content-Encoding: identity\r\n',
        'trailer': b'Trailer: X-Fixture-Trailer\r\n',
        'header-oversize': b'X-Fixture-Padding: ' + b'x' * 17408 + b'\r\n',
    }
    fields.append(special.get(mode, b''))
    fields.append(b'Cache-Control: no-store\r\nConnection: close\r\n\r\n')
    payload = representation
    if mode == 'body-truncated':
        payload = representation[:-1]
    elif mode == 'chunked':
        payload = format(len(representation), 'x').encode('ascii') + b'\r\n' + representation + b'\r\n0\r\n\r\n'
    return status, representation, b''.join(fields) + payload


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('invalid event object')
        result[key] = value
    return result


def decode_events(raw, complete=True):
    if type(raw) is not bytes or len(raw) > 4 << 20 or raw and not raw.endswith(b'\n'):
        raise ValueError('invalid bounded event log')
    events, connections = [], {}
    try:
        for ordinal, line in enumerate(raw.decode('ascii').splitlines(), 1):
            value = json.loads(line, object_pairs_hook=unique_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))
            if (type(value) is not dict or set(value) != EVENT_KEYS
                    or value['schema'] != 'chengwang.product-source-event/v1'
                    or type(value['ordinal']) is not int or value['ordinal'] != ordinal
                    or type(value['connection']) is not int or not 1 <= value['connection'] <= 512):
                raise ValueError('invalid event shape')
            for key in ('tls', 'authPresent', 'wireComplete'):
                if type(value[key]) is not bool:
                    raise ValueError('invalid event type')
            for key in ('epoch', 'generation', 'status', 'representationBytes', 'wireBytes', 'writtenBytes'):
                if type(value[key]) is not int or value[key] < 0:
                    raise ValueError('invalid event number')
            for key in ('reason', 'planSHA256', 'pathClass', 'mode', 'representationSHA256', 'wireSHA256'):
                if type(value[key]) is not str:
                    raise ValueError('invalid event string')
            chain = connections.setdefault(value['connection'], [])
            event = value['event']
            if (event == 'connect' and chain or event == 'tls' and chain != ['connect']
                    or event == 'http' and chain != ['connect', 'tls']
                    or event == 'close' and chain not in (['connect'], ['connect', 'tls'], ['connect', 'tls', 'http'])
                    or event not in ('connect', 'tls', 'http', 'close')):
                raise ValueError('invalid connection chain')
            chain.append(event)
            if event != 'http' and any(value[key] for key in (
                    'epoch', 'planSHA256', 'pathClass', 'generation', 'mode', 'status',
                    'representationSHA256', 'representationBytes', 'wireSHA256',
                    'wireBytes', 'writtenBytes', 'wireComplete', 'authPresent')):
                raise ValueError('invented HTTP evidence')
            events.append(value)
        if len(events) > 4096 or set(connections) != set(range(1, len(connections) + 1)):
            raise ValueError('invalid connection allocation')
        if complete and any(chain[-1] != 'close' for chain in connections.values()):
            raise ValueError('incomplete connection chain')
        return events
    except (UnicodeError, KeyError, TypeError, RecursionError):
        raise ValueError('invalid event log') from None


def observation(test_name, label, events):
    if test_name not in LABELS_BY_TEST or label not in LABELS_BY_TEST[test_name] or not events:
        raise ValueError('invalid observation identity')
    decode_events(b''.join(encoded(value) + b'\n' for value in events))
    return {'testName': test_name, 'label': label, 'events': events}


def remove_fixture_root(root):
    if (root.is_symlink() or root.resolve() != root or root.parent != pathlib.Path('/tmp')
            or not re.fullmatch(r'chengwang-product-lifecycle-[a-f0-9]{32}', root.name)):
        raise RuntimeError('unsafe owned fixture cleanup')
    shutil.rmtree(root)


class ShapeTests(unittest.TestCase):
    def test_plan_exact_fields_and_duplicate_keys(self):
        self.assertEqual(source.parse_plan(encoded(plan())), plan())
        for raw in (encoded(plan()).replace(b'"epoch":1', b'"epoch":1,"epoch":1'),
                    encoded(dict(plan(), extra=True)), encoded({'schema': source.PLAN_SCHEMA}),
                    encoded(plan()).replace(b'"mode":"json"', b'"mode":"json","mode":"json"')):
            with self.assertRaises(source.Rejected):
                source.parse_plan(raw)

    def test_epoch_is_canonical_bounded_integer(self):
        for epoch in (0, -1, True, 1.0, '1', None, 1 << 64):
            with self.assertRaises(source.Rejected):
                source.parse_plan(encoded(plan(epoch)))
        self.assertEqual(source.parse_plan(encoded(plan((1 << 64) - 1)))['epoch'], (1 << 64) - 1)
        self.assertEqual((source.MAX_CONNECTIONS, source.MAX_WORKERS, source.MAX_EVENTS), (512, 8, 4096))
        self.assertEqual((source.SOCKET_TIMEOUT, source.STALL_SECONDS), (2.0, 0.75))

    def test_generation_paths_and_response_count_are_closed(self):
        for name in ('0.json', '01.json', '../1.json', '1.json?secret', '1.json/', str(1 << 64) + '.json'):
            value = plan()
            value['responses'] = {name: value['responses']['latest.json']}
            with self.assertRaises(source.Rejected):
                source.parse_plan(encoded(value))
            self.assertEqual(source.classify_target('/feed/' + name), ('invalid', 0, ''))
        value = plan(generation=True)
        value['responses'] = {str(n) + '.json': value['responses']['latest.json'] for n in range(1, 66)}
        source.parse_plan(encoded(value))
        value['responses']['66.json'] = value['responses']['1.json']
        with self.assertRaises(source.Rejected):
            source.parse_plan(encoded(value))

    def test_wire_modes_and_body_rules_are_closed(self):
        self.assertEqual(source.MODES, MODES)
        for mode in MODES:
            value = plan(mode=mode)
            source.parse_plan(encoded(value))
            actual = source.build_wire(mode, b'' if mode in source.NO_BODY_MODES else DEFAULT_BODY)
            status, representation, wire = expected_wire(mode)
            self.assertTrue((actual.status, actual.representation, actual.wire) == (status, representation, wire),
                            'fixed wire grammar mismatch')
            value['responses']['latest.json']['bodySHA256'] = sha(DEFAULT_BODY) if mode in source.NO_BODY_MODES else ''
            with self.assertRaises(source.Rejected):
                source.parse_plan(encoded(value))
        for mode in ('unknown', 'JSON', '', 'json\n'):
            with self.assertRaises(source.Rejected):
                source.parse_plan(encoded(plan(mode=mode)))

    def test_plan_size_utf8_and_numbers_are_bounded(self):
        for raw in (b'', b' ' * 65537, b'\xff', b'[' * 1100 + b']' * 1100,
                    encoded(plan()).replace(b'"epoch":1', b'"epoch":NaN'),
                    encoded(plan()).replace(b'"epoch":1', b'"epoch":Infinity')):
            with self.assertRaises(source.Rejected):
                source.parse_plan(raw)

    def test_cli_exact_private_paths_and_deadlines(self):
        base = ['serve', '--fixture-root', '/tmp/chengwang-product-lifecycle-' + 'a' * 32,
                '--case', 'real-case', '--kind', 'message-signature', '--port', '15443']
        self.assertEqual(source.arguments(base).deadline_seconds, 300)
        for extra in (['--deadline-seconds', '0'], ['--deadline-seconds', '601'],
                      ['--deadline-seconds', '01'], ['--unknown', 'private']):
            with self.assertRaises(source.Rejected):
                source.arguments(base + extra)
        for index, replacement in ((2, '/tmp/elsewhere'), (4, '../x'), (6, 'unknown'), (8, '1023')):
            args = list(base)
            args[index] = replacement
            with self.assertRaises(source.Rejected):
                source.arguments(args)

    def test_event_json_lines_never_treat_incomplete_as_zero(self):
        self.assertEqual(decode_events(b''), [])
        for raw in (b'{', b'\n', b'[]\n', b'\xff\n', b'{"ordinal":1,"ordinal":2}\n', b'x' * ((4 << 20) + 1)):
            with self.assertRaises(ValueError):
                decode_events(raw)
        # The actual opened FD must be checked, not just an earlier directory stat.
        files = object.__new__(source.PrivateFiles)
        files.immutable = {}
        import threading
        files.identity_lock = threading.Lock()
        class Identity:
            st_dev, st_ino = 1, 2
        files._pin(1, 'body.json', Identity())
        other = Identity()
        other.st_ino = 3
        with self.assertRaises(source.Rejected):
            files._pin(1, 'body.json', other)

    def test_observation_identity_and_labels_are_closed(self):
        self.assertEqual(len(LABELS_BY_TEST), 16)
        self.assertEqual(len({label for labels in LABELS_BY_TEST.values() for label in labels}), 34)
        for name, label in (('unknown', 'normal'), ('test_real_wire_modes', 'unknown'),
                            ('test_private_input_links_and_fifo_rejected', 'normal')):
            with self.assertRaises(ValueError):
                observation(name, label, [])


class Session:
    """One owned root and one actual setpriv helper, never a synthetic log."""
    def __init__(self, test, label=None, body=DEFAULT_BODY, mode='json', generation=False):
        self.test, self.label, self.body, self.process = test, label, body, None
        self.root = pathlib.Path('/tmp/chengwang-product-lifecycle-' + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        os.chown(self.root, 10001, 10001)
        test.addCleanup(self.cleanup)
        self.feed = self.root / 'real-case' / 'message-signature' / 'feed'
        current = self.root
        for name in ('real-case', 'message-signature', 'feed', 'bodies'):
            current = current / name
            current.mkdir(mode=0o700)
            os.chown(current, 10001, 10001)
        self.put(self.feed / 'server.crt', test.leaf.read_bytes())
        self.put(self.feed / 'server.key', test.key.read_bytes())
        self.put(self.feed / 'bodies' / (sha(body) + '.json'), body)
        self.put(self.feed / 'plan.json', encoded(plan(mode=mode, body=body, generation=generation)))

    @staticmethod
    def put(path, raw, replace=False):
        # Runtime body mutation deliberately keeps the pinned inode. Plans alone
        # are atomically replaceable; the helper never repairs test input bytes.
        destination = path.with_name(path.name + '.next') if replace else path
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fchown(fd, 10001, 10001)
            view = memoryview(raw)
            while view:
                size = os.write(fd, view)
                if size <= 0:
                    raise RuntimeError('fixture input write failed')
                view = view[size:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if replace:
            os.replace(destination, path)

    def start(self, port=None, deadline=20, rejected=False):
        if port is None:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
        self.port = port
        launch = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                  'import fixture_source;raise SystemExit(fixture_source.main())')
        command = ['/usr/bin/setpriv', '--reuid=10001', '--regid=10001', '--clear-groups',
                   '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                   sys.executable, '-I', '-B', '-c', launch, str(HERE), 'serve',
                   '--fixture-root', str(self.root), '--case', 'real-case', '--kind', 'message-signature',
                   '--port', str(port), '--deadline-seconds', str(deadline)]
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        if rejected:
            out, err = self.communicate(5)
            self.test.assertTrue(self.process.returncode == 1 and not out, 'startup must naturally reject with exit one')
            self.test.assertTrue(err.startswith(b'D12_SOURCE_ERROR=') and b'PRIVATE_SENTINEL' not in err,
                                 'startup diagnostic must be a fixed safe code')
            return
        ready_path = self.feed / 'ready.json'
        until = time.monotonic() + 5
        while not ready_path.exists() and time.monotonic() < until and self.process.poll() is None:
            time.sleep(0.005)
        self.test.assertTrue(ready_path.exists() and self.process.poll() is None, 'actual helper ready was not published')
        ready_raw = self.private_read(ready_path, 4096)
        try:
            ready = json.loads(ready_raw, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError):
            self.test.fail('ready must be an atomic complete JSON object')
        self.test.assertTrue(ready == {'schema': 'chengwang.product-source-ready/v1', 'port': port,
                            'pid': self.process.pid, 'uid': 10001, 'gid': 10001, 'tls': True,
                            'listenLoopback': True, 'deadlineSeconds': deadline}, 'ready identity differs')
        status_raw = pathlib.Path('/proc/' + str(self.process.pid) + '/status').read_text('ascii')
        status = dict(line.split(':', 1) for line in status_raw.splitlines() if ':' in line)
        self.test.assertTrue(status['Uid'].split() == ['10001'] * 4 and status['Gid'].split() == ['10001'] * 4,
                             'actual helper UID/GID is not restricted')
        self.test.assertTrue(not status['Groups'].strip() and status['NoNewPrivs'].strip() == '1', 'actual helper identity is not restricted')
        self.test.assertTrue(all(status[name].strip() == '0000000000000000' for name in
                                 ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')), 'actual helper capabilities are not empty')

    @staticmethod
    def private_read(path, limit):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                    or (before.st_uid, before.st_gid, before.st_nlink) != (10001, 10001, 1)
                    or not 0 <= before.st_size <= limit):
                raise ValueError('invalid private observation file')
            chunks = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            after, named = os.fstat(fd), os.stat(path, follow_symlinks=False)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                                      value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if identity(before) != identity(after) or identity(before) != identity(named) or len(raw) != before.st_size:
                raise ValueError('unstable private observation file')
            return raw
        finally:
            os.close(fd)

    def events_until(self, predicate, timeout=1):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            try:
                events = decode_events(self.private_read(self.feed / 'events.jsonl', 4 << 20), complete=False)
            except (ValueError, FileNotFoundError):
                time.sleep(0.005)
                continue
            if predicate(events):
                return events
            time.sleep(0.005)
        self.test.fail('bounded actual source event condition was not observed')

    def connect(self, context=None, hostname='feed.fixture.invalid'):
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        try:
            return (self.test.context if context is None else context).wrap_socket(raw, server_hostname=hostname)
        except BaseException:
            raw.close()
            raise

    def request(self, target='/feed/latest.json', method='GET', headers=b''):
        with self.connect() as client:
            client.settimeout(3)
            client.sendall(method.encode('ascii') + b' ' + target.encode('ascii')
                           + b' HTTP/1.1\r\nHost: feed.fixture.invalid\r\n' + headers + b'\r\n')
            parts, length = [], 0
            while True:
                try:
                    chunk = client.recv(65536)
                except (OSError, ValueError):
                    self.test.fail('actual full wire read failed')
                if not chunk:
                    break
                parts.append(chunk)
                length += len(chunk)
                self.test.assertLessEqual(length, 512 << 10, 'wire read exceeded its bound')
            return b''.join(parts)

    def communicate(self, timeout):
        try:
            return self.process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.test.fail('owned helper did not terminate within its bound')

    def finish(self, signum=signal.SIGTERM):
        started = time.monotonic()
        if signum is not None:
            self.test.assertTrue(self.process.poll() is None, 'helper exited before explicit stop')
            self.process.send_signal(signum)
        out, err = self.communicate(4)
        self.test.assertTrue(self.process.returncode == 0 and not out and not err, 'source did not join cleanly with exit zero')
        self.test.assertLess(time.monotonic() - started, 4, 'source stop was not bounded')
        raw = self.private_read(self.feed / 'events.jsonl', 4 << 20)
        events = decode_events(raw)
        self.test.assertTrue(bool(events), 'successful source session has no actual connection evidence')
        OBSERVATIONS.append(observation(self.test._testMethodName, self.label, events))
        with socket.socket() as probe:
            probe.settimeout(0.3)
            self.test.assertNotEqual(probe.connect_ex(('127.0.0.1', self.port)), 0, 'stopped source still listens')
        return events, raw

    def cleanup(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.communicate(timeout=4)
            else:
                self.process.communicate()
        if self.root.exists():
            remove_fixture_root(self.root)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux actual source fixture; auxiliary platform only')
class LinuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError('actual Linux tests require the root orchestrator, never skip')
        for command in ('/usr/bin/openssl', '/usr/bin/setpriv', '/usr/bin/findmnt'):
            if not pathlib.Path(command).is_file():
                raise RuntimeError('required actual Linux tool is absent')
        mounted = subprocess.run(['/usr/bin/findmnt', '-n', '-T', str(HERE), '-o', 'OPTIONS'],
                                 capture_output=True, timeout=5)
        if mounted.returncode or 'ro' not in mounted.stdout.decode('ascii').strip().split(','):
            raise RuntimeError('helper source must reside on the actual read-only source mount')
        cls.authority = pathlib.Path('/tmp/chengwang-product-lifecycle-' + uuid.uuid4().hex)
        cls.authority.mkdir(mode=0o700)
        cls.addClassCleanup(remove_fixture_root, cls.authority)
        cls.ca, cls.leaf, cls.key = cls.certificates('normal')
        cls.other_ca, _, _ = cls.certificates('other')
        cls.context = ssl.create_default_context(cafile=str(cls.ca))
        cls.context.minimum_version = ssl.TLSVersion.TLSv1_2

    @classmethod
    def certificates(cls, label):
        directory = cls.authority / label
        directory.mkdir(mode=0o700)
        ca, cakey = directory / 'ca.pem', directory / 'ca-key.pem'
        leaf, key, csr = directory / 'leaf.pem', directory / 'leaf-key.pem', directory / 'leaf.csr'
        extension = directory / 'extensions.cnf'
        extension.write_bytes(b'subjectAltName=DNS:feed.fixture.invalid\nextendedKeyUsage=serverAuth\n')
        commands = [
            ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
             '-keyout', cakey, '-out', ca, '-days', '1', '-subj', '/CN=Isolated-Source-CA'],
            ['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
             '-keyout', key, '-out', csr, '-subj', '/CN=feed.fixture.invalid'],
            ['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', cakey, '-CAcreateserial',
             '-out', leaf, '-days', '1', '-extfile', extension],
        ]
        for args in commands:
            try:
                result = subprocess.run(['/usr/bin/openssl', *map(str, args)], capture_output=True, timeout=10)
            except subprocess.TimeoutExpired:
                raise RuntimeError('isolated certificate preparation exceeded its bound') from None
            if result.returncode:
                raise RuntimeError('isolated certificate preparation failed')
        return ca, leaf, key

    def assert_wire(self, raw, mode='json', body=DEFAULT_BODY):
        self.assertTrue(raw == expected_wire(mode, body)[2], 'actual wire differs from the independent fixed grammar')

    def assert_http(self, events, modes, reasons=None):
        actual = [value for value in events if value['event'] == 'http']
        self.assertEqual([value['mode'] for value in actual], modes)
        if reasons is not None:
            self.assertEqual([value['reason'] for value in actual], reasons)
        for value in actual:
            body = BOUNDARY_BODY if self._testMethodName == 'test_body_size_boundary_and_oversize_refusal' else DEFAULT_BODY
            status, representation, wire = expected_wire(value['mode'], body)
            self.assertEqual((value['status'], value['representationSHA256'], value['representationBytes'],
                              value['wireSHA256'], value['wireBytes']),
                             (status, sha(representation), len(representation), sha(wire), len(wire)))
        return actual

    def test_normal_tls_json_and_generation(self):
        session = Session(self, 'normal', generation=True)
        session.start()
        self.assert_wire(session.request())
        self.assert_wire(session.request('/feed/2.json'))
        events, _ = session.finish()
        http = self.assert_http(events, ['json', 'json'], ['planned', 'planned'])
        self.assertEqual([(v['pathClass'], v['generation']) for v in http], [('latest', 0), ('generation', 2)])

    def test_wrong_ca_and_san_record_failed_tls(self):
        for label in ('wrong-ca', 'wrong-san'):
            session = Session(self, label)
            session.start()
            context = ssl.create_default_context(cafile=str(self.other_ca if label == 'wrong-ca' else self.ca))
            failed = False
            try:
                client = session.connect(context, 'wrong.fixture.invalid' if label == 'wrong-san' else 'feed.fixture.invalid')
                client.close()
            except ssl.SSLCertVerificationError:
                failed = True
            self.assertTrue(failed, 'single-factor client TLS verification must fail')
            session.events_until(lambda events: any(v['event'] == 'close' for v in events))
            events, _ = session.finish()
            self.assertEqual([v['reason'] for v in events if v['event'] == 'tls'], ['failed'])
            self.assertFalse(any(v['event'] == 'http' for v in events))

    def test_real_wire_modes(self):
        for mode in MODES:
            session = Session(self, mode, mode=mode)
            session.start()
            self.assert_wire(session.request(), mode)
            client = None
            if mode == 'stall-body':
                client = session.connect()
                self.addCleanup(client.close)
                client.sendall(b'GET /feed/latest.json HTTP/1.1\r\nHost: feed.fixture.invalid\r\n\r\n')
                client.settimeout(0.5)
                head = b''
                while not head.endswith(b'\r\n\r\n'):
                    byte = client.recv(1)
                    self.assertTrue(bool(byte) and len(head) < 4096, 'stalled body header was not bounded and complete')
                    head += byte
                self.assertTrue(head == expected_wire(mode)[2].split(b'\r\n\r\n')[0] + b'\r\n\r\n',
                                'actual stalled body header differs')
            events, _ = session.finish()
            http = self.assert_http(events, [mode] * (2 if client else 1), ['planned'] * (2 if client else 1))
            self.assertTrue(http[0]['wireComplete'] and http[0]['writtenBytes'] == http[0]['wireBytes'],
                            'full request must record the actual complete wire write')
            if client:
                partial = http[1]
                expected_written = len(expected_wire(mode)[2].split(b'\r\n\r\n')[0]) + 4
                self.assertTrue(partial['writtenBytes'] == expected_written and not partial['wireComplete'],
                                'stop must interrupt the actual fixed stall write')
                client.close()

    def test_plan_epochs_reject_conflict_rollback_then_recover(self):
        session = Session(self, 'epoch-sequence')
        session.start()
        raws = [encoded(plan(1)), encoded(plan(2)), encoded(plan(2)) + b' ', encoded(plan(1)), encoded(plan(3))]
        reasons = ['planned', 'planned', 'epoch-conflict', 'epoch-rollback', 'planned']
        for raw, reason in zip(raws, reasons):
            session.put(session.feed / 'plan.json', raw, replace=True)
            self.assert_wire(session.request(), 'json' if reason == 'planned' else 'unavailable')
        events, _ = session.finish()
        http = self.assert_http(events, ['json', 'json', 'unavailable', 'unavailable', 'json'], reasons)
        self.assertEqual([(v['epoch'], v['planSHA256']) for v in http], list(zip([1, 2, 2, 1, 3], map(sha, raws))))

    def test_sensitive_request_headers_and_targets_are_redacted(self):
        session = Session(self, 'sensitive-request')
        session.start()
        sentinel = b'PRIVATE_SENTINEL_DO_NOT_ECHO_71a9'
        requests = [('/feed/latest.json', 'GET', b'Authorization: Bearer ' + sentinel + b'\r\nProxy-Authorization: ' + sentinel + b'\r\n'),
                    ('/feed/latest.json?token=' + sentinel.decode('ascii'), 'GET', b''),
                    ('/feed/latest.json', 'POST', b'')]
        for target, method, headers in requests:
            wire = session.request(target, method, headers)
            self.assert_wire(wire, 'unavailable')
            self.assertTrue(sentinel not in wire, 'private request bytes reflected in response')
        events, raw = session.finish()
        http = self.assert_http(events, ['unavailable'] * 3, ['auth-present', 'request-invalid', 'method-invalid'])
        self.assertEqual([v['authPresent'] for v in http], [True, False, False])
        self.assertTrue(sentinel not in raw, 'private request bytes leaked into event log')

    def test_body_bytes_remain_immutable_and_mismatch_is_rejected(self):
        session = Session(self, 'body-mismatch')
        originals = {name: (session.feed / name).read_bytes() for name in ('server.crt', 'server.key', 'plan.json')}
        session.start()
        self.assert_wire(session.request())
        target = session.feed / 'bodies' / (sha(DEFAULT_BODY) + '.json')
        changed = b'changed-private-body\n'
        session.put(target, changed)
        self.assert_wire(session.request(), 'unavailable')
        session.put(target, DEFAULT_BODY, replace=True)
        self.assert_wire(session.request(), 'unavailable')
        events, _ = session.finish()
        http = self.assert_http(events, ['json', 'unavailable', 'unavailable'],
                                ['planned', 'body-mismatch', 'plan-unavailable'])
        self.assertEqual((http[-1]['epoch'], http[-1]['planSHA256']), (0, ''))
        self.assertTrue(target.read_bytes() == DEFAULT_BODY, 'helper repaired or changed the replacement bytes')
        self.assertTrue(all((session.feed / name).read_bytes() == raw for name, raw in originals.items()), 'immutable inputs changed')

    def test_private_input_links_and_fifo_rejected(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'body-symlink', 'body-hardlink', 'body-fifo'):
            session = Session(self)
            target = session.feed / ('bodies/' + sha(DEFAULT_BODY) + '.json' if kind.startswith('body-') else 'plan.json')
            original = target.read_bytes()
            held = session.root / 'held.private'
            target.rename(held)
            if kind.endswith('symlink'):
                target.symlink_to(held)
            elif kind.endswith('hardlink'):
                os.link(held, target)
            else:
                os.mkfifo(target, 0o600)
                os.chown(target, 10001, 10001)
            session.start(rejected=True)
            self.assertFalse((session.feed / 'ready.json').exists())
            self.assertTrue(held.read_bytes() == original, 'unsafe input rejection changed original bytes')

    def test_private_tree_and_certificate_rejections_preserve_bytes(self):
        for kind in ('root-mode', 'directory-owner', 'file-mode', 'file-owner', 'certificate-hardlink', 'certificate-invalid'):
            session = Session(self)
            originals = {name: (session.feed / name).read_bytes() for name in ('server.crt', 'server.key', 'plan.json')}
            if kind == 'root-mode':
                os.chmod(session.root, 0o755)
            elif kind == 'directory-owner':
                os.chown(session.feed, 0, 10001)
            elif kind == 'file-mode':
                os.chmod(session.feed / 'server.key', 0o644)
            elif kind == 'file-owner':
                os.chown(session.feed / 'server.crt', 0, 10001)
            elif kind == 'certificate-hardlink':
                os.link(session.feed / 'server.crt', session.root / 'cert.private')
            else:
                session.put(session.feed / 'server.crt', b'PRIVATE_SENTINEL_INVALID_CERTIFICATE\n')
                originals['server.crt'] = b'PRIVATE_SENTINEL_INVALID_CERTIFICATE\n'
            session.start(rejected=True)
            self.assertFalse((session.feed / 'ready.json').exists())
            self.assertTrue(all((session.feed / name).read_bytes() == raw for name, raw in originals.items()), 'rejection changed original private bytes')

    def test_ready_atomic_and_outputs_never_overwritten(self):
        session = Session(self, 'ready-atomic')
        session.start()
        self.assertFalse((session.feed / 'ready.pending').exists())
        self.assert_wire(session.request())
        session.finish()
        for name in ('ready.json', 'events.jsonl'):
            rejected = Session(self)
            original = b'PRIVATE_SENTINEL_EXISTING_OUTPUT\n'
            rejected.put(rejected.feed / name, original)
            rejected.start(rejected=True)
            self.assertTrue((rejected.feed / name).read_bytes() == original, 'existing output was overwritten')

    def test_fixed_port_rebind_and_active_listener_exclusivity(self):
        first = Session(self, 'fixed-port-first')
        first.start()
        self.assert_wire(first.request())
        with socket.socket() as contender:
            contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            refused = False
            try:
                contender.bind(('127.0.0.1', first.port))
            except OSError as error:
                refused = error.errno == errno.EADDRINUSE
            self.assertTrue(refused, 'active listener must remain exclusive')
        first.finish()
        second = Session(self, 'fixed-port-second')
        second.start(port=first.port)
        self.assert_wire(second.request())
        second.finish()

    def test_term_joins_slow_tls_connections(self):
        session = Session(self, 'stop-term')
        session.start()
        clients = [socket.create_connection(('127.0.0.1', session.port), timeout=2) for _ in range(2)]
        for client in clients:
            self.addCleanup(client.close)
        session.events_until(lambda events: len([v for v in events if v['event'] == 'connect']) == 2)
        events, _ = session.finish()
        self.assertFalse(any(v['event'] == 'http' for v in events))
        self.assertTrue(any(v['reason'] == 'stopping' for v in events), 'stop was not observed')

    def test_int_joins_incomplete_http_headers(self):
        session = Session(self, 'stop-int')
        session.start()
        client = session.connect()
        self.addCleanup(client.close)
        client.sendall(b'GET /feed/latest.json HTTP/1.1\r\nHost: feed.fixture.invalid\r\n')
        session.events_until(lambda events: any(v['event'] == 'tls' and v['reason'] == 'ok' for v in events))
        events, _ = session.finish(signal.SIGINT)
        self.assertTrue(any(v['reason'] == 'stopping' for v in events), 'INT stop was not observed')
        self.assertFalse(any(v['wireComplete'] and v['status'] == 200 for v in events))

    def test_deadline_closes_inflight_tls(self):
        session = Session(self, 'deadline')
        session.start(deadline=1)
        client = socket.create_connection(('127.0.0.1', session.port), timeout=2)
        self.addCleanup(client.close)
        session.events_until(lambda events: any(v['event'] == 'connect' for v in events))
        events, _ = session.finish(None)
        self.assertTrue(any(v['reason'] == 'stopping' for v in events), 'natural deadline was not observed')
        self.assertFalse(any(v['event'] == 'http' for v in events))

    def test_body_size_boundary_and_oversize_refusal(self):
        session = Session(self, 'body-boundary', body=BOUNDARY_BODY)
        session.start()
        self.assert_wire(session.request(), body=BOUNDARY_BODY)
        events, _ = session.finish()
        self.assert_http(events, ['json'], ['planned'])
        rejected = Session(self, body=b'x' * 262146)
        target = rejected.feed / 'bodies' / (sha(b'x' * 262146) + '.json')
        rejected.start(rejected=True)
        self.assertFalse((rejected.feed / 'ready.json').exists())
        self.assertTrue(target.read_bytes() == b'x' * 262146, 'oversize rejection modified the original body')

    def test_worker_capacity_is_logged_and_joined(self):
        session = Session(self, 'capacity-stop')
        session.start()
        clients = []
        for _ in range(9):
            client = socket.create_connection(('127.0.0.1', session.port), timeout=2)
            clients.append(client)
            self.addCleanup(client.close)
        before_stop = session.events_until(lambda events:
            [v['event'] for v in events if v['connection'] == 9] == ['connect', 'close'])
        self.assertTrue(all([v['event'] for v in before_stop if v['connection'] == number] == ['connect']
                            for number in range(1, 9)), 'eight handshake workers were not concurrently pending')
        self.assertEqual([v['reason'] for v in before_stop if v['connection'] == 9], ['accepted', 'closed'])
        tasks = pathlib.Path('/proc/' + str(session.process.pid) + '/task')
        self.assertGreaterEqual(len(list(tasks.iterdir())), 9, 'eight actual worker threads were not live before stop')
        events, _ = session.finish()
        chains = [[v['event'] for v in events if v['connection'] == number] for number in range(1, 10)]
        self.assertEqual(chains[8], ['connect', 'close'], 'worker capacity did not refuse the ninth worker')
        self.assertFalse(any(v['event'] == 'http' for v in events))

    def test_missing_or_changed_body_never_reflects_private_bytes(self):
        session = Session(self, 'missing-body')
        originals = {name: (session.feed / name).read_bytes() for name in ('server.crt', 'server.key', 'plan.json')}
        session.start()
        self.assert_wire(session.request())
        target = session.feed / 'bodies' / (sha(DEFAULT_BODY) + '.json')
        target.unlink()
        self.assert_wire(session.request(), 'unavailable')
        events, _ = session.finish()
        self.assert_http(events, ['json', 'unavailable'], ['planned', 'body-unavailable'])
        self.assertFalse(target.exists(), 'helper recreated a missing source body')
        self.assertTrue(all((session.feed / name).read_bytes() == raw for name, raw in originals.items()), 'missing-body refusal mutated private inputs')


def write_observations(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('unsafe evidence directory')
    expected = {(name, label) for name, labels in LABELS_BY_TEST.items() for label in labels}
    actual = [(case['testName'], case['label']) for case in OBSERVATIONS]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError('incomplete actual observations')
    raw = encoded({'schema': 'chengwang.product-source-observations/v1', 'cases': OBSERVATIONS}) + b'\n'
    path = directory / 'product-source-fixture-observations.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            size = os.write(fd, view)
            if size <= 0:
                raise ValueError('evidence write failed')
            view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--evidence-dir', type=pathlib.Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    linux = sys.platform.startswith('linux')
    if result.wasSuccessful() and result.testsRun == 24 and len(result.skipped) == (0 if linux else 16):
        if linux:
            if args.evidence_dir is None:
                raise ValueError('actual Linux evidence directory is required')
            write_observations(args.evidence_dir)
            print('D12_SOURCE_FIXTURE_TESTS=PASS tests=24 passed=24 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none')
        else:
            print('D12_SOURCE_FIXTURE_AUXILIARY_TESTS=PASS tests=24 passed=8 skipped=16 real_linux=false auxiliary_only=true')
        return 0
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
