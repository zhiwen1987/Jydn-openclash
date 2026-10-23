"""CI-only fixed DoT/HTTPS laboratory peer; never configures networking or trust.

The caller supplies a private network namespace, the GUA on lo, three independent
CAs and process limits. This peer neither resolves names nor makes outbound calls.
Logs contain closed enums, public identities and digests, never request contents.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
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


READY_SCHEMA = 'chengwang.probe-wire-ready/v1'
EVENT_SCHEMA = 'chengwang.probe-wire-event/v1'
STOPPED_SCHEMA = 'chengwang.probe-wire-stopped/v1'
FIXTURE_ROOT = re.compile(r'/tmp/chengwang-probe-readback-[a-f0-9]{32}\Z')
HOSTS = ('pass.probe.example', 'restricted.probe.example', 'limited.probe.example')
DOT_NAME = 'dot.probe.example'
DOT_ADDRESS, DOT_PORT = '127.0.0.1', 1853
HTTPS_ADDRESS, HTTPS_PORT = '8.8.4.4', 443
MAX_DNS = 512
MAX_HTTP = 8192
MAX_CONNECTIONS = 128
MAX_WORKERS = 8
MAX_EVENTS = 512
SOCKET_TIMEOUT = 2.0
INPUTS = ('dot-cert.pem', 'dot-key.private.pem', 'https-cert.pem', 'https-key.private.pem')
PUBLIC_BODIES = (b'chengwang-probe-pass-v1\n', b'chengwang-probe-restricted-v1\n',
                 b'chengwang-probe-limited-v1\n')
REASONS = frozenset(('ok', 'closed', 'failed', 'timeout', 'stopping', 'capacity',
                     'query-invalid', 'request-invalid', 'auth-present', 'transport-error'))
ERROR_CODES = frozenset(('arguments-invalid', 'security-invalid', 'input-invalid',
                         'bind-failed', 'runtime-failed'))
EVENT_KEYS = frozenset(('schema', 'ordinal', 'monotonicNS', 'connection', 'service',
                        'event', 'reason', 'tls', 'host', 'queryType', 'queryID',
                        'queryBytes', 'querySHA256', 'requestBytes', 'requestSHA256',
                        'status', 'responseBytes', 'responseSHA256', 'framedResponseBytes',
                        'writtenBytes', 'complete', 'receivedUnixNano'))


class Rejected(Exception):
    """Only a member of the fixed error/reason sets may leave main()."""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'


def private(value, directory=False):
    return ((stat.S_ISDIR if directory else stat.S_ISREG)(value.st_mode)
            and stat.S_IMODE(value.st_mode) == (0o700 if directory else 0o600)
            and value.st_uid == 10001 and value.st_gid == 10001
            and (directory or value.st_nlink == 1))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def check_process():
    if (not sys.platform.startswith('linux') or os.getuid() != 10001 or os.getgid() != 10001
            or os.geteuid() != 10001 or os.getegid() != 10001 or os.getgroups()):
        raise Rejected('security-invalid')
    with open('/proc/self/status', 'rb') as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise Rejected('security-invalid')
    values = dict(line.split(':', 1) for line in raw.decode('ascii').splitlines() if ':' in line)
    if (values.get('NoNewPrivs', '').strip() != '1'
            or any(values.get(k, '').strip() != '0000000000000000'
                   for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))):
        raise Rejected('security-invalid')


def write_all(fd, raw):
    while raw:
        size = os.write(fd, raw)
        if size <= 0:
            raise Rejected('runtime-failed')
        raw = raw[size:]


class PrivateFiles:
    def __init__(self, root):
        self.fds, self.links, self.pins = [], [], {}
        if not isinstance(root, str) or not FIXTURE_ROOT.fullmatch(root):
            raise Rejected('security-invalid')
        try:
            parent = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.fds.append(parent)
            value = os.fstat(parent)
            if (not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o1777
                    or value.st_uid != 0 or value.st_gid != 0):
                raise Rejected('security-invalid')
            self.tmp = parent
            for name in (root.rsplit('/', 1)[1], 'wire'):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                self.fds.append(child)
                if not private(os.fstat(child), True):
                    raise Rejected('security-invalid')
                self.links.append((parent, name, child))
                parent = child
            self.directory = parent
            library = ctypes.CDLL(None, use_errno=True)
            buffer = ctypes.create_string_buffer(256)
            if library.fstatfs(parent, buffer) != 0:
                raise Rejected('security-invalid')
            if ctypes.c_long.from_buffer(buffer).value not in (0xEF53, 0x58465342, 0x01021994):
                raise Rejected('security-invalid')
            names = []
            with os.scandir(parent) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > len(INPUTS):
                        raise Rejected('input-invalid')
            if set(names) != set(INPUTS):
                raise Rejected('input-invalid')
            for name in INPUTS:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
                self.fds.append(fd)
                value = os.fstat(fd)
                limit = 65536 if 'key' in name else 262144
                if not private(value) or not 0 < value.st_size <= limit:
                    raise Rejected('input-invalid')
                self.pins[name] = (fd, identity(value))
            self.check_live()
        except (OSError, Rejected):
            self.close()
            raise Rejected('input-invalid') from None

    def check_live(self):
        tmp = os.stat('/tmp', follow_symlinks=False)
        if (tmp.st_dev, tmp.st_ino) != (os.fstat(self.tmp).st_dev, os.fstat(self.tmp).st_ino):
            raise Rejected('security-invalid')
        for parent, name, fd in self.links:
            named, held = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(fd)
            if not private(named, True) or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                raise Rejected('security-invalid')
        for name, (fd, before) in self.pins.items():
            if (identity(os.fstat(fd)) != before or identity(os.stat(
                    name, dir_fd=self.directory, follow_symlinks=False)) != before):
                raise Rejected('input-invalid')

    def context(self, service):
        cert = self.pins[service + '-cert.pem'][0]
        key = self.pins[service + '-key.private.pem'][0]
        self.check_live()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain('/proc/self/fd/' + str(cert), '/proc/self/fd/' + str(key))
        if service == 'https':
            context.set_alpn_protocols(['http/1.1'])

        def sni(connection, name, _):
            allowed = (DOT_NAME,) if service == 'dot' else HOSTS
            if name not in allowed:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            connection.fixture_name = name
            return None

        context.set_servername_callback(sni)
        self.check_live()
        return context

    def create(self, name):
        self.check_live()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
        if not private(os.fstat(fd)):
            os.close(fd)
            raise Rejected('security-invalid')
        return fd

    def check_output(self, name, fd):
        self.check_live()
        held, named = os.fstat(fd), os.stat(name, dir_fd=self.directory, follow_symlinks=False)
        if not private(held) or identity(held) != identity(named):
            raise Rejected('security-invalid')

    def publish(self, name, value):
        pending = name + '.pending'
        fd = self.create(pending)
        try:
            write_all(fd, encoded(value))
            os.fsync(fd)
            self.check_output(pending, fd)
            library = ctypes.CDLL(None, use_errno=True)
            rename = library.renameat2
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            if rename(self.directory, pending.encode('ascii'), self.directory, name.encode('ascii'), 1):
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
    """Canonical single-question DNS only; no compression, EDNS or fallback."""
    if type(query) is not bytes or not 12 <= len(query) <= MAX_DNS:
        raise Rejected('query-invalid')
    query_id, flags, qd, an, ns, ar = struct.unpack('!6H', query[:12])
    if (flags, qd, an, ns, ar) != (0x0100, 1, 0, 0, 0):
        raise Rejected('query-invalid')
    offset, labels = 12, []
    while offset < len(query):
        size = query[offset]
        offset += 1
        if size == 0:
            break
        if not 1 <= size <= 63 or offset + size > len(query):
            raise Rejected('query-invalid')
        labels.append(query[offset:offset + size])
        offset += size
    else:
        raise Rejected('query-invalid')
    if offset + 4 != len(query):
        raise Rejected('query-invalid')
    try:
        host = b'.'.join(labels).decode('ascii')
    except UnicodeError:
        raise Rejected('query-invalid') from None
    qtype, qclass = struct.unpack('!2H', query[offset:])
    if host not in HOSTS or qtype not in (1, 28) or qclass != 1:
        raise Rejected('query-invalid')
    header = struct.pack('!6H', query_id, 0x8180, 1, int(qtype == 1), 0, 0)
    answer = (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4)
              + socket.inet_aton(HTTPS_ADDRESS)) if qtype == 1 else b''
    return host, 'A' if qtype == 1 else 'AAAA', query_id, header + query[12:] + answer


def http_host(raw, server_name):
    if type(raw) is not bytes or len(raw) > MAX_HTTP or not raw.endswith(b'\r\n\r\n'):
        raise Rejected('request-invalid')
    lines = raw[:-4].split(b'\r\n')
    if not lines or lines[0] != b'GET /health HTTP/1.1':
        raise Rejected('request-invalid')
    fields = {}
    for line in lines[1:]:
        if not line or line[:1] in (b' ', b'\t') or b':' not in line:
            raise Rejected('request-invalid')
        key, value = line.split(b':', 1)
        key = key.lower()
        if not re.fullmatch(rb'[a-z0-9-]+', key) or key in fields:
            raise Rejected('request-invalid')
        if key in (b'authorization', b'proxy-authorization', b'cookie', b'proxy-connection'):
            raise Rejected('auth-present')
        if key not in (b'host', b'user-agent', b'connection', b'accept', b'accept-encoding'):
            raise Rejected('request-invalid')
        value = value.strip(b' \t')
        if any(c < 32 or c > 126 for c in value):
            raise Rejected('request-invalid')
        fields[key] = value
    value = fields.get(b'host', b'')
    for host in HOSTS:
        if value in (host.encode(), (host + ':443').encode()) and host == server_name:
            return host
    raise Rejected('request-invalid')


def http_answer(host):
    if host not in HOSTS:
        raise Rejected('request-invalid')
    index = HOSTS.index(host)
    body = PUBLIC_BODIES[index]
    status, phrase = ((200, b'OK'), (403, b'Forbidden'), (429, b'Too Many Requests'))[index]
    headers = (b'HTTP/1.1 ' + str(status).encode() + b' ' + phrase + b'\r\n'
               + b'Content-Type: text/plain\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n')
    if status == 429:
        headers += b'Retry-After: 30\r\n'
    return status, headers + b'Cache-Control: no-store\r\nConnection: close\r\n\r\n' + body


class WireServer:
    def __init__(self, files, deadline_seconds):
        self.files, self.deadline_seconds = files, deadline_seconds
        self.stop = threading.Event()
        self.lock = threading.RLock()
        self.active, self.workers, self.listeners = {}, [], []
        self.accepted = self.closed = self.ordinal = 0
        self.failure = False
        self.termination = ''
        self.signal_termination = ''
        self.log_fd = files.create('events.jsonl')
        self.contexts = {name: files.context(name) for name in ('dot', 'https')}

    def record_signal(self, signum, _frame=None):
        # A Python signal handler can interrupt the main thread while Event.wait
        # holds its non-reentrant condition lock. Record only a closed flag;
        # the normal run loop performs Event.set after wait has released it.
        if not self.signal_termination and signum in (signal.SIGTERM, signal.SIGINT):
            self.signal_termination = 'term' if signum == signal.SIGTERM else 'int'

    def emit(self, connection, service, event, reason, tls=False, **extra):
        if reason not in REASONS:
            raise Rejected('runtime-failed')
        value = dict(schema=EVENT_SCHEMA, ordinal=0, monotonicNS=0, connection=connection,
                     service=service, event=event, reason=reason, tls=tls, host='',
                     queryType='', queryID=0, queryBytes=0, querySHA256='', requestBytes=0,
                     requestSHA256='', status=0, responseBytes=0, responseSHA256='',
                     framedResponseBytes=0, writtenBytes=0, complete=False, receivedUnixNano='')
        value.update(extra)
        with self.lock:
            if self.ordinal >= MAX_EVENTS or set(value) != EVENT_KEYS:
                raise Rejected('runtime-failed')
            self.files.check_output('events.jsonl', self.log_fd)
            self.ordinal += 1
            value['ordinal'], value['monotonicNS'] = self.ordinal, time.monotonic_ns()
            write_all(self.log_fd, encoded(value))
            os.fsync(self.log_fd)

    def read_exact(self, connection, size):
        result = bytearray()
        while len(result) < size:
            if self.stop.is_set():
                raise Rejected('stopping')
            remaining = connection.fixture_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            connection.settimeout(remaining)
            part = connection.recv(size - len(result))
            if not part:
                raise Rejected('transport-error')
            result.extend(part)
        return bytes(result)

    def send(self, connection, raw):
        written = 0
        while written < len(raw):
            if self.stop.is_set():
                break
            try:
                count = connection.send(raw[written:])
                if count <= 0:
                    break
                written += count
            except (OSError, ssl.SSLError):
                break
        return written

    def worker(self, raw, number, service):
        connection, secured, tls_emitted, reason = raw, False, False, 'closed'
        try:
            raw.settimeout(SOCKET_TIMEOUT)
            connection = self.contexts[service].wrap_socket(raw, server_side=True,
                                                           do_handshake_on_connect=False)
            connection.fixture_deadline = time.monotonic() + SOCKET_TIMEOUT
            with self.lock:
                self.active[number] = connection
            connection.do_handshake()
            secured = True
            self.emit(number, service, 'tls', 'ok', True)
            tls_emitted = True
            if service == 'dot':
                length = struct.unpack('!H', self.read_exact(connection, 2))[0]
                if not 12 <= length <= MAX_DNS:
                    raise Rejected('query-invalid')
                query = self.read_exact(connection, length)
                extra = dict(queryBytes=len(query), querySHA256=sha(query))
                try:
                    host, qtype, qid, response = dns_answer(query)
                except Rejected:
                    self.emit(number, service, 'dns', 'query-invalid', True, **extra)
                    raise
                received = str(time.time_ns())
                framed = struct.pack('!H', len(response)) + response
                written = self.send(connection, framed)
                self.emit(number, service, 'dns', 'ok', True, host=host, queryType=qtype,
                          queryID=qid, responseBytes=len(response), responseSHA256=sha(response),
                          framedResponseBytes=len(framed), writtenBytes=written,
                          complete=written == len(framed), receivedUnixNano=received, **extra)
            else:
                request = bytearray()
                while not request.endswith(b'\r\n\r\n'):
                    if len(request) >= MAX_HTTP:
                        raise Rejected('request-invalid')
                    request.extend(self.read_exact(connection, 1))
                request = bytes(request)
                extra = dict(requestBytes=len(request), requestSHA256=sha(request))
                try:
                    host = http_host(request, getattr(connection, 'fixture_name', ''))
                except Rejected as error:
                    self.emit(number, service, 'http', error.args[0], True, **extra)
                    raise
                received = str(time.time_ns())
                status, response = http_answer(host)
                written = self.send(connection, response)
                self.emit(number, service, 'http', 'ok', True, host=host, status=status,
                          responseBytes=len(response), responseSHA256=sha(response),
                          framedResponseBytes=len(response), writtenBytes=written,
                          complete=written == len(response), receivedUnixNano=received, **extra)
        except (socket.timeout, TimeoutError):
            reason = 'stopping' if self.stop.is_set() else 'timeout'
        except Rejected as error:
            reason = error.args[0] if error.args and error.args[0] in REASONS else 'failed'
        except (OSError, ssl.SSLError):
            reason = 'stopping' if self.stop.is_set() else 'transport-error'
        except Exception:
            reason = 'failed'
            self.failure = True
            self.stop.set()
        finally:
            try:
                if not tls_emitted:
                    self.emit(number, service, 'tls', reason if reason in ('timeout', 'stopping')
                              else 'failed', False)
                try:
                    connection.close()
                finally:
                    raw.close()
                self.emit(number, service, 'close', reason, secured)
            except Exception:
                self.failure = True
                self.stop.set()
            finally:
                with self.lock:
                    self.active.pop(number, None)
                    self.closed += 1

    def accept(self):
        try:
            while not self.stop.is_set():
                with self.lock:
                    if self.accepted >= MAX_CONNECTIONS:
                        return
                readable, _, _ = select.select(self.listeners, (), (), 0.1)
                if not readable:
                    continue
                listener = readable[0]
                service = 'dot' if listener is self.listeners[0] else 'https'
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                with self.lock:
                    self.accepted += 1
                    number = self.accepted
                    self.emit(number, service, 'connect', 'ok')
                    if len(self.active) >= MAX_WORKERS:
                        raw.close()
                        self.emit(number, service, 'close', 'capacity')
                        self.closed += 1
                        continue
                    self.active[number] = raw
                    thread = threading.Thread(target=self.worker, args=(raw, number, service), daemon=True)
                    self.workers.append(thread)
                    thread.start()
        except Exception:
            if not self.stop.is_set():
                self.failure = True
                self.stop.set()

    def run(self):
        acceptors = []
        try:
            for service, address, port in (('dot', DOT_ADDRESS, DOT_PORT),
                                           ('https', HTTPS_ADDRESS, HTTPS_PORT)):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.listeners.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.settimeout(0.1)
                try:
                    listener.bind((address, port))
                    listener.listen(MAX_WORKERS + 1)
                except OSError:
                    raise Rejected('bind-failed') from None
            self.files.publish('ready.json', dict(schema=READY_SCHEMA, pid=os.getpid(), uid=os.getuid(),
                               gid=os.getgid(), dotAddress=DOT_ADDRESS, dotPort=DOT_PORT,
                               httpsAddress=HTTPS_ADDRESS, httpsPort=HTTPS_PORT, tls=True,
                               deadlineSeconds=self.deadline_seconds))
            thread = threading.Thread(target=self.accept, daemon=True)
            acceptors.append(thread)
            thread.start()
            deadline = time.monotonic() + self.deadline_seconds
            while not self.stop.wait(0.02):
                if self.signal_termination:
                    if not self.termination:
                        self.termination = self.signal_termination
                    self.stop.set()
                    break
                if time.monotonic() >= deadline:
                    self.termination = 'deadline'
                    self.stop.set()
                with self.lock:
                    if self.accepted >= MAX_CONNECTIONS and not self.active:
                        self.termination = 'budget'
                        self.stop.set()
        finally:
            self.stop.set()
            for listener in self.listeners:
                listener.close()
            for thread in acceptors:
                thread.join(3)
            with self.lock:
                connections = list(self.active.values())
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            for thread in self.workers:
                thread.join(3)
            if any(t.is_alive() for t in acceptors + self.workers) or self.accepted != self.closed:
                self.failure = True
            self.files.check_output('events.jsonl', self.log_fd)
            os.fsync(self.log_fd)
            os.close(self.log_fd)
        if self.failure or self.termination not in ('term', 'int', 'deadline', 'budget'):
            raise Rejected('runtime-failed')
        self.files.publish('stopped.json', dict(schema=STOPPED_SCHEMA, pid=os.getpid(),
                           termination=self.termination, accepted=self.accepted, closed=self.closed,
                           events=self.ordinal, workerThreadsAlive=0, listenersClosed=True,
                           normalStop=self.termination in ('term', 'int')))
        return 0 if self.termination in ('term', 'int') else 2


def arguments(argv=None):
    # Never let argparse echo user-controlled argv or paths in a diagnostic.
    class ClosedParser(argparse.ArgumentParser):
        def error(self, _message):
            raise Rejected('arguments-invalid')
    parser = ClosedParser(add_help=False, exit_on_error=False)
    parser.add_argument('command', choices=('serve',))
    parser.add_argument('--fixture-root', required=True)
    parser.add_argument('--deadline-seconds', default='300')
    try:
        result = parser.parse_args(argv)
        if (not FIXTURE_ROOT.fullmatch(result.fixture_root)
                or not re.fullmatch(r'[1-9][0-9]{0,2}', result.deadline_seconds)
                or not 10 <= int(result.deadline_seconds) <= 360):
            raise ValueError('invalid')
        result.deadline_seconds = int(result.deadline_seconds)
        return result
    except (argparse.ArgumentError, SystemExit, ValueError, TypeError):
        raise Rejected('arguments-invalid') from None


def main(argv=None):
    files = None
    try:
        options = arguments(argv)
        check_process()
        files = PrivateFiles(options.fixture_root)
        server = WireServer(files, options.deadline_seconds)

        signal.signal(signal.SIGTERM, server.record_signal)
        signal.signal(signal.SIGINT, server.record_signal)
        return server.run()
    except Rejected as error:
        code = error.args[0] if error.args and error.args[0] in ERROR_CODES else 'runtime-failed'
        sys.stderr.write('PROBE_WIRE_ERROR=' + code + '\n')
        return 1
    except Exception:
        sys.stderr.write('PROBE_WIRE_ERROR=runtime-failed\n')
        return 1
    finally:
        if files is not None:
            files.close()


if __name__ == '__main__':
    raise SystemExit(main())
