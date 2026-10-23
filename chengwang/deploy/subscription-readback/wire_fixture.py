"""CI-only private subscription peer. Never changes networking, CA roots or time."""
from __future__ import annotations

import argparse
import base64
import ctypes
import hmac
import importlib.util
import json
import os
import pathlib
import re
import select
import signal
import socket
import ssl
import stat
import struct
import sys
import threading
import time

try:
    import lab_contract as contract
except ModuleNotFoundError:
    # -I intentionally removes the script directory from sys.path. The CI
    # orchestrator binds these exact two source files read-only together.
    try:
        _path = pathlib.Path(__file__).with_name('lab_contract.py')
        _spec = importlib.util.spec_from_file_location('lab_contract', _path)
        contract = importlib.util.module_from_spec(_spec)
        sys.modules['lab_contract'] = contract
        _spec.loader.exec_module(contract)
    except Exception:
        sys.stderr.write('SUBSCRIPTION_WIRE_ERROR=runtime-failed\n')
        raise SystemExit(1) from None

ROOT = re.compile(r'/tmp/chengwang-subscription-private-[a-f0-9]{32}\Z')
INPUTS = ('wire-input.json', 'resolver-cert.pem', 'resolver-key.private.pem',
          'source-cert.pem', 'source-key.private.pem')
OUTPUTS = ('wire-ready.json', 'wire-events.jsonl', 'wire-stopped.json')
ERRORS = frozenset(('arguments-invalid', 'security-invalid', 'input-invalid', 'bind-failed', 'runtime-failed'))
REASONS = frozenset(('ok', 'closed', 'partial', 'failed', 'timeout', 'stopping', 'capacity',
                     'query-invalid', 'request-invalid', 'auth-invalid', 'transport-error'))
MAX_WORKERS, MAX_DNS, MAX_HTTP, SOCKET_TIMEOUT = 8, 512, 8192, 2.0
BAD_BODY = b'proxies: [\n'
REDIRECT_LOCATION = b'https://good-a.subscription.example/subscription'


class Rejected(Exception):
    """Only fixed classifications may leave the fixture."""


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'


def private(value, directory=False):
    return ((stat.S_ISDIR if directory else stat.S_ISREG)(value.st_mode)
            and stat.S_IMODE(value.st_mode) == (0o700 if directory else 0o600)
            and value.st_uid == contract.UID and value.st_gid == contract.GID
            and (directory or value.st_nlink == 1))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def check_process():
    if (not sys.platform.startswith('linux') or os.getuid() != contract.UID or os.getgid() != contract.GID
            or os.geteuid() != contract.UID or os.getegid() != contract.GID or os.getgroups()):
        raise Rejected('security-invalid')
    with open('/proc/self/status', 'rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise Rejected('security-invalid')
    fields = dict(line.split(':', 1) for line in raw.decode('ascii').splitlines() if ':' in line)
    if (fields.get('NoNewPrivs', '').strip() != '1' or any(
            fields.get(key, '').strip() != '0000000000000000'
            for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))):
        raise Rejected('security-invalid')


def parse_input(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('invalid')
            result[key] = value
        return result
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 2 * contract.MAX_INPUT:
            raise ValueError('invalid')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid')))
        if type(value) is not dict or set(value) != {'sourceTokensByRef', 'goodBodyBase64'}:
            raise ValueError('invalid')
        tokens = value['sourceTokensByRef']
        if (type(tokens) is not dict or set(tokens) != set(contract.REFERENCE_IDS)
                or any(type(v) is not str or not re.fullmatch(r'[a-f0-9]{64}', v) for v in tokens.values())
                or len(set(tokens.values())) != len(tokens)):
            raise ValueError('invalid')
        text = value['goodBodyBase64']
        if type(text) is not str or not text.isascii():
            raise ValueError('invalid')
        body = base64.b64decode(text, validate=True)
        if (not 0 < len(body) <= contract.MAX_INPUT or base64.b64encode(body).decode('ascii') != text
                or b'\x00' in body):
            raise ValueError('invalid')
        body.decode('utf-8')
        return {ref: token.encode('ascii') for ref, token in tokens.items()}, body
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Rejected('input-invalid') from None


def write_all(fd, raw):
    while raw:
        count = os.write(fd, raw)
        if count <= 0:
            raise Rejected('runtime-failed')
        raw = raw[count:]


class PrivateFiles:
    def __init__(self, root):
        self.fds, self.pins = [], {}
        try:
            if type(root) is not str or not ROOT.fullmatch(root):
                raise Rejected('security-invalid')
            parent = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.fds.append(parent)
            info = os.fstat(parent)
            if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o1777
                    or info.st_uid != 0 or info.st_gid != 0):
                raise Rejected('security-invalid')
            self.tmp = parent
            self.name = root.rsplit('/', 1)[1]
            self.directory = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            self.fds.append(self.directory)
            if not private(os.fstat(self.directory), True):
                raise Rejected('security-invalid')
            library = ctypes.CDLL(None, use_errno=True)
            buffer = ctypes.create_string_buffer(256)
            if library.fstatfs(self.directory, buffer) or ctypes.c_long.from_buffer(buffer).value not in (
                    0xEF53, 0x58465342, 0x01021994):
                raise Rejected('security-invalid')
            for name in INPUTS:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=self.directory)
                self.fds.append(fd)
                info = os.fstat(fd)
                limit = 2 * contract.MAX_INPUT if name == 'wire-input.json' else (65536 if 'key' in name else 262144)
                if not private(info) or not 0 < info.st_size <= limit:
                    raise Rejected('input-invalid')
                self.pins[name] = (fd, identity(info))
            for name in OUTPUTS:
                try:
                    os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise Rejected('input-invalid')
            self.check_live()
            self.tokens, self.body = parse_input(self.read('wire-input.json'))
        except (OSError, Rejected):
            self.close()
            raise Rejected('input-invalid') from None

    def check_live(self):
        held = os.fstat(self.tmp)
        named = os.stat('/tmp', follow_symlinks=False)
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
            raise Rejected('security-invalid')
        held = os.fstat(self.directory)
        named = os.stat(self.name, dir_fd=self.tmp, follow_symlinks=False)
        if not private(named, True) or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
            raise Rejected('security-invalid')
        for name, (fd, before) in self.pins.items():
            if (identity(os.fstat(fd)) != before or identity(os.stat(
                    name, dir_fd=self.directory, follow_symlinks=False)) != before):
                raise Rejected('input-invalid')

    def read(self, name):
        self.check_live()
        fd, before = self.pins[name]
        os.lseek(fd, 0, os.SEEK_SET)
        chunks, remaining = [], before[6]
        while remaining:
            piece = os.read(fd, min(remaining, 65536))
            if not piece:
                raise Rejected('input-invalid')
            chunks.append(piece)
            remaining -= len(piece)
        if os.read(fd, 1):
            raise Rejected('input-invalid')
        self.check_live()
        return b''.join(chunks)

    def context(self, service):
        prefix = 'resolver' if service == 'dot' else 'source'
        self.check_live()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain('/proc/self/fd/' + str(self.pins[prefix + '-cert.pem'][0]),
                                '/proc/self/fd/' + str(self.pins[prefix + '-key.private.pem'][0]))
        if service == 'https':
            context.set_alpn_protocols(['http/1.1'])
        def sni(connection, name, _):
            allowed = (contract.DOT_NAME,) if service == 'dot' else tuple(contract.SOURCE_HOSTS.values())
            if name not in allowed:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            connection.fixture_name = name
            return None
        context.set_servername_callback(sni)
        self.check_live()
        return context

    def create(self, name):
        self.check_live()
        if name not in OUTPUTS and name not in ('wire-ready.json.pending', 'wire-stopped.json.pending'):
            raise Rejected('input-invalid')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
        if not private(os.fstat(fd)):
            os.close(fd)
            raise Rejected('security-invalid')
        return fd

    def check_output(self, name, fd):
        self.check_live()
        if not private(os.fstat(fd)) or identity(os.fstat(fd)) != identity(os.stat(
                name, dir_fd=self.directory, follow_symlinks=False)):
            raise Rejected('security-invalid')

    def publish(self, name, value):
        pending = name + '.pending'
        fd = self.create(pending)
        try:
            write_all(fd, encoded(value))
            os.fsync(fd)
            self.check_output(pending, fd)
            rename = ctypes.CDLL(None, use_errno=True).renameat2
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            if rename(self.directory, pending.encode(), self.directory, name.encode(), 1):
                raise Rejected('input-invalid')
            os.fsync(self.directory)
            self.check_output(name, fd)
        finally:
            os.close(fd)

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def dns_answer(query):
    if type(query) is not bytes or not 12 <= len(query) <= MAX_DNS:
        raise Rejected('query-invalid')
    qid, flags, qd, an, ns, ar = struct.unpack('!6H', query[:12])
    if (flags, qd, an, ns, ar) != (0x0100, 1, 0, 0, 0):
        raise Rejected('query-invalid')
    labels, offset = [], 12
    while offset < len(query):
        size = query[offset]; offset += 1
        if size == 0:
            break
        if not 1 <= size <= 63 or offset + size > len(query):
            raise Rejected('query-invalid')
        labels.append(query[offset:offset + size]); offset += size
    else:
        raise Rejected('query-invalid')
    if offset + 4 != len(query):
        raise Rejected('query-invalid')
    try:
        host = b'.'.join(labels).decode('ascii')
    except UnicodeError:
        raise Rejected('query-invalid') from None
    qtype, qclass = struct.unpack('!2H', query[offset:])
    reverse = {host: ref for ref, host in contract.SOURCE_HOSTS.items()}
    if host not in reverse or qtype not in (1, 28) or qclass != 1:
        raise Rejected('query-invalid')
    ref = reverse[host]
    address = '127.0.0.1' if ref == 'private' else contract.SOURCE_IP
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(address) if qtype == 1 else b''
    response = struct.pack('!6H', qid, 0x8180, 1, int(qtype == 1), 0, 0) + query[12:] + answer
    return ref, 'A' if qtype == 1 else 'AAAA', qid, response


def http_reference(raw, server_name, tokens):
    if type(raw) is not bytes or len(raw) > MAX_HTTP or not raw.endswith(b'\r\n\r\n'):
        raise Rejected('request-invalid')
    lines = raw[:-4].split(b'\r\n')
    match = re.fullmatch(rb'GET /subscription\?token=([a-f0-9]{64}) HTTP/1\.1', lines[0])
    if match is None:
        raise Rejected('request-invalid')
    headers = {}
    for line in lines[1:]:
        if not line or line[:1] in (b' ', b'\t') or b':' not in line:
            raise Rejected('request-invalid')
        key, value = line.split(b':', 1); key = key.lower()
        if not re.fullmatch(rb'[a-z0-9-]+', key) or key in headers:
            raise Rejected('request-invalid')
        if key in (b'authorization', b'proxy-authorization', b'cookie', b'proxy-connection'):
            raise Rejected('auth-invalid')
        if key not in (b'host', b'user-agent', b'connection', b'accept', b'accept-encoding'):
            raise Rejected('request-invalid')
        value = value.strip(b' \t')
        if any(c < 32 or c > 126 for c in value):
            raise Rejected('request-invalid')
        headers[key] = value
    for ref, host in contract.SOURCE_HOSTS.items():
        if host == server_name and headers.get(b'host') in (host.encode(), (host + ':443').encode()):
            if not hmac.compare_digest(match[1], tokens[ref]):
                raise Rejected('auth-invalid')
            return ref
    raise Rejected('request-invalid')


def http_response(ref, good_body):
    if ref not in contract.REFERENCE_IDS:
        raise Rejected('request-invalid')
    status, phrase = (302, b'Found') if ref == 'redirect' else (200, b'OK')
    body = BAD_BODY if ref == 'bad' else b'' if ref == 'redirect' else b'x' * (contract.MAX_INPUT + 1) if ref == 'oversize' else good_body
    headers = (b'HTTP/1.1 ' + str(status).encode() + b' ' + phrase + b'\r\nContent-Type: application/yaml\r\n'
               + b'Content-Length: ' + str(len(body)).encode() + b'\r\n')
    if ref == 'redirect':
        headers += b'Location: ' + REDIRECT_LOCATION + b'\r\n'
    return status, headers + b'Cache-Control: no-store\r\nConnection: close\r\n\r\n' + body


class WireServer:
    def __init__(self, files, deadline_seconds):
        self.files, self.deadline_seconds = files, deadline_seconds
        self.stop, self.lock = threading.Event(), threading.RLock()
        self.active, self.workers, self.listeners = {}, [], []
        self.accepted = self.closed = self.ordinal = 0
        self.failure = False
        self.abnormal = False
        self.termination = self.signal_termination = ''
        self.log_fd = files.create('wire-events.jsonl')
        self.contexts = {name: files.context(name) for name in ('dot', 'https')}

    def record_signal(self, signum, _frame=None):
        if not self.signal_termination and signum in (signal.SIGTERM, signal.SIGINT):
            self.signal_termination = 'term' if signum == signal.SIGTERM else 'int'

    def emit(self, number, service, event, reason, tls=False, **extra):
        if reason not in REASONS:
            raise Rejected('runtime-failed')
        value = dict(schema=contract.EVENT_SCHEMA, ordinal=0, connection=number, service=service,
                     event=event, reference='', queryType='', status=0, bytes=0, tls=tls,
                     reason=reason, receivedUnixNano='')
        value.update(extra)
        with self.lock:
            if self.ordinal >= contract.MAX_EVENTS or set(value) != contract.EVENT_KEYS:
                raise Rejected('runtime-failed')
            self.files.check_output('wire-events.jsonl', self.log_fd)
            self.ordinal += 1; value['ordinal'] = self.ordinal
            write_all(self.log_fd, encoded(value)); os.fsync(self.log_fd)
            if reason in ('timeout', 'capacity') or reason == 'partial' and value['reference'] != 'oversize':
                self.abnormal = True

    def read_exact(self, connection, size):
        raw = bytearray()
        while len(raw) < size:
            if self.stop.is_set():
                raise Rejected('stopping')
            remaining = connection.fixture_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            connection.settimeout(remaining)
            piece = connection.recv(size - len(raw))
            if not piece:
                raise Rejected('transport-error')
            connection.fixture_payload_started = True
            raw.extend(piece)
        return bytes(raw)

    def send(self, connection, raw):
        count = 0
        while count < len(raw) and not self.stop.is_set():
            try:
                written = connection.send(raw[count:])
                if written <= 0: break
                count += written
            except (OSError, ssl.SSLError):
                break
        return count

    def worker(self, raw, number, service):
        connection, secured, emitted, payload_emitted, reason = raw, False, False, False, 'closed'
        try:
            raw.settimeout(SOCKET_TIMEOUT)
            connection = self.contexts[service].wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            connection.fixture_deadline = time.monotonic() + SOCKET_TIMEOUT
            with self.lock: self.active[number] = connection
            connection.do_handshake(); secured = True
            self.emit(number, service, 'tls', 'ok', True); emitted = True
            if service == 'dot':
                length = struct.unpack('!H', self.read_exact(connection, 2))[0]
                if not 12 <= length <= MAX_DNS: raise Rejected('query-invalid')
                query = self.read_exact(connection, length)
                try:
                    ref, kind, _, response = dns_answer(query)
                except Rejected:
                    self.emit(number, service, 'dns', 'query-invalid', True)
                    payload_emitted = True
                    raise
                received = str(time.time_ns()); response = struct.pack('!H', len(response)) + response
                written = self.send(connection, response)
                self.emit(number, service, 'dns', 'ok' if written == len(response) else 'partial', True,
                          reference=ref, queryType=kind, bytes=written, receivedUnixNano=received)
                payload_emitted = True
            else:
                request = bytearray()
                while not request.endswith(b'\r\n\r\n'):
                    if len(request) >= MAX_HTTP: raise Rejected('request-invalid')
                    request.extend(self.read_exact(connection, 1))
                try:
                    ref = http_reference(bytes(request), getattr(connection, 'fixture_name', ''), self.files.tokens)
                except Rejected as error:
                    self.emit(number, service, 'http', error.args[0], True)
                    payload_emitted = True
                    raise
                received = str(time.time_ns()); status, response = http_response(ref, self.files.body)
                written = self.send(connection, response)
                self.emit(number, service, 'http', 'ok' if written == len(response) else 'partial', True,
                          reference=ref, status=status, bytes=written, receivedUnixNano=received)
                payload_emitted = True
        except (socket.timeout, TimeoutError):
            reason = 'stopping' if self.stop.is_set() else 'timeout'
        except Rejected as error:
            reason = error.args[0] if error.args and error.args[0] in REASONS else 'failed'
        except (OSError, ssl.SSLError):
            reason = 'stopping' if self.stop.is_set() else 'transport-error'
        except Exception:
            reason = 'failed'; self.failure = True; self.stop.set()
        finally:
            try:
                if not emitted: self.emit(number, service, 'tls', reason if reason in ('timeout', 'stopping') else 'failed')
                if secured and not payload_emitted and getattr(connection, 'fixture_payload_started', False):
                    self.emit(number, service, 'dns' if service == 'dot' else 'http', reason, True)
                try: connection.close()
                finally: raw.close()
                self.emit(number, service, 'close', reason, secured)
            except Exception:
                self.failure = True; self.stop.set()
            finally:
                with self.lock:
                    self.active.pop(number, None); self.closed += 1

    def accept(self):
        try:
            while not self.stop.is_set():
                with self.lock:
                    if self.accepted >= contract.MAX_CONNECTIONS: return
                readable, _, _ = select.select(self.listeners, (), (), 0.1)
                if not readable: continue
                listener = readable[0]; service = 'dot' if listener is self.listeners[0] else 'https'
                try: raw, _ = listener.accept()
                except socket.timeout: continue
                except OSError:
                    if self.stop.is_set(): return
                    raise
                with self.lock:
                    self.accepted += 1; number = self.accepted
                    self.emit(number, service, 'connect', 'ok')
                    if len(self.active) >= MAX_WORKERS:
                        raw.close(); self.emit(number, service, 'close', 'capacity'); self.closed += 1
                        continue
                    self.active[number] = raw
                    thread = threading.Thread(target=self.worker, args=(raw, number, service), daemon=True)
                    self.workers.append(thread); thread.start()
        except Exception:
            if not self.stop.is_set(): self.failure = True; self.stop.set()

    def run(self):
        acceptors = []
        try:
            for address, port in ((contract.DOT_HOST, contract.DOT_PORT), (contract.SOURCE_IP, contract.SOURCE_PORT)):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM); self.listeners.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.settimeout(0.1)
                try: listener.bind((address, port)); listener.listen(MAX_WORKERS + 1)
                except OSError: raise Rejected('bind-failed') from None
            self.files.publish('wire-ready.json', dict(schema=contract.READY_SCHEMA, pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
                dotAddress=contract.DOT_HOST, dotPort=contract.DOT_PORT, httpsAddress=contract.SOURCE_IP,
                httpsPort=contract.SOURCE_PORT, tls=True, deadlineSeconds=self.deadline_seconds))
            thread = threading.Thread(target=self.accept, daemon=True); acceptors.append(thread); thread.start()
            deadline = time.monotonic() + self.deadline_seconds
            while not self.stop.wait(0.02):
                if self.signal_termination:
                    self.termination = self.signal_termination; self.stop.set(); break
                if time.monotonic() >= deadline: self.termination = 'deadline'; self.stop.set()
                with self.lock:
                    if self.accepted >= contract.MAX_CONNECTIONS and not self.active:
                        self.termination = 'budget'; self.stop.set()
        finally:
            self.stop.set()
            for listener in self.listeners: listener.close()
            for thread in acceptors: thread.join(3)
            with self.lock: active = list(self.active.values())
            for connection in active:
                try: connection.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                connection.close()
            for thread in self.workers: thread.join(3)
            if any(t.is_alive() for t in acceptors + self.workers) or self.accepted != self.closed: self.failure = True
            self.files.check_output('wire-events.jsonl', self.log_fd); os.fsync(self.log_fd); os.close(self.log_fd)
        if self.failure or self.termination not in ('term', 'int', 'deadline', 'budget'): raise Rejected('runtime-failed')
        normal = self.termination in ('term', 'int') and not self.abnormal and self.accepted < contract.MAX_CONNECTIONS
        self.files.publish('wire-stopped.json', dict(schema=contract.STOPPED_SCHEMA, pid=os.getpid(), termination=self.termination,
            accepted=self.accepted, closed=self.closed, events=self.ordinal, workerThreadsAlive=0,
            listenersClosed=True, normalStop=normal))
        return 0 if normal else 2


def arguments(argv=None):
    class Closed(argparse.ArgumentParser):
        def error(self, _message): raise Rejected('arguments-invalid')
    parser = Closed(add_help=False, exit_on_error=False, allow_abbrev=False)
    parser.add_argument('command', choices=('serve',)); parser.add_argument('--root', required=True)
    parser.add_argument('--deadline-seconds', default='300')
    try:
        result = parser.parse_args(argv)
        if (not ROOT.fullmatch(result.root) or not re.fullmatch(r'[1-9][0-9]{0,2}', result.deadline_seconds)
                or not 10 <= int(result.deadline_seconds) <= 360): raise ValueError('invalid')
        result.deadline_seconds = int(result.deadline_seconds); return result
    except (argparse.ArgumentError, SystemExit, ValueError, TypeError): raise Rejected('arguments-invalid') from None


def main(argv=None):
    files = None
    try:
        options = arguments(argv); check_process(); files = PrivateFiles(options.root)
        server = WireServer(files, options.deadline_seconds)
        signal.signal(signal.SIGTERM, server.record_signal); signal.signal(signal.SIGINT, server.record_signal)
        return server.run()
    except Rejected as error:
        reason = error.args[0] if error.args and error.args[0] in ERRORS else 'runtime-failed'
        sys.stderr.write('SUBSCRIPTION_WIRE_ERROR=' + reason + '\n'); return 1
    except Exception:
        sys.stderr.write('SUBSCRIPTION_WIRE_ERROR=runtime-failed\n'); return 1
    finally:
        if files is not None: files.close()


if __name__ == '__main__':
    raise SystemExit(main())
