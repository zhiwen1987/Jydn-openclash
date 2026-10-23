#!/usr/bin/python3 -I
"""Five synthetic no-store stream fixtures, never a product/API deployment.

WRITE_RETURNED counts only the application's successful write return, not
acknowledged TLS/network delivery. All real execution belongs to isolated CI.
"""
from __future__ import annotations

import argparse
import ctypes
import http.server
import json
import os
import pathlib
import re
import signal
import socket
import socketserver
import ssl
import stat
import sys
import threading
import time
import uuid

ORIGIN = 'https://127.0.0.1:17881'
HOST, PORT = '127.0.0.1', 17881
CASES = ('split-success', 'boundary-success', 'oversize', 'truncated', 'abort')
EVENTS = frozenset(('REQUEST', 'WRITE_RETURNED', 'COMPLETE', 'PEER_CLOSED', 'ERROR', 'SERVER_STOPPED'))
REASONS = frozenset(('OK', 'PEER_CLOSED', 'DEADLINE', 'INVALID', 'UNEXPECTED'))
EVENT_SCHEMA = 'chengwang.stream-matrix-server-event/v1'
HTML = (b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        b'<link rel="icon" href="data:,"><title>Isolated stream matrix</title>'
        b'</head><body>CI synthetic stream fixture; not product E2E.</body></html>')
MAX_BODY, MAX_FRAMED, MAX_EVENTS = 1048577, 1048640, 128
MAX_PRIVATE_BYTES = 65536


class Rejected(ValueError):
    def __init__(self): super().__init__('stream matrix fixture rejected')


def need(value):
    if not value: raise Rejected()


def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def fixture_root(value):
    need(type(value) is str)
    found = re.fullmatch(r'/tmp/chengwang-stream-matrix-([a-f0-9]{32})', value)
    need(found is not None)
    return pathlib.Path(value), found[1]


def checked_directory(path, owner, mode=None):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid == owner
         and not stat.S_IMODE(info.st_mode) & 0o022)
    if mode is not None: need(stat.S_IMODE(info.st_mode) == mode)
    return info


def private_file(path, maximum=MAX_PRIVATE_BYTES):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 10001
         and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        need(os.path.samestat(before, opened))
        raw = os.read(descriptor, maximum + 1)
        after, named = os.fstat(descriptor), path.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
                                item.st_uid, item.st_gid, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(opened) == identity(after) == identity(named))
        return raw
    finally:
        os.close(descriptor)


def publish(path, value):
    raw = canonical(value) + b'\n'
    need(0 < len(raw) <= MAX_PRIVATE_BYTES)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(descriptor)
        # Same Linux no-replace primitive as
        # deploy/probe-readback/run_probe_readback.py:publish_atomic. Unlike
        # link/unlink it never exposes nlink=2 to strict signal readers.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        need(rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1) == 0)
    finally:
        os.close(descriptor)
        if temporary.exists(): temporary.unlink()


def response_plan(case):
    need(case in CASES)
    body = b'{"ok":true}' if case in ('split-success', 'truncated', 'abort') else (
        b'{"data":"' + b'a' * ((1048576 if case == 'boundary-success' else 1048577) - 11) + b'"}')
    parts = (body[:6], body[6:]) if len(body) == 11 else (body[:524288], body[524288:])
    return dict(body=body, parts=parts, contentLength=None if case == 'oversize' else len(body),
                chunked=case == 'oversize', truncated=case == 'truncated', abort=case == 'abort')


def chunk_frame(body):
    need(type(body) is bytes and 0 < len(body) <= MAX_BODY)
    return format(len(body), 'x').encode('ascii') + b'\r\n' + body + b'\r\n'


def event_record(ordinal, event, case, body=0, framed=0, reason='OK'):
    need(type(ordinal) is int and 1 <= ordinal <= MAX_EVENTS and type(event) is str and event in EVENTS
         and case in (*CASES, 'none') and type(reason) is str and reason in REASONS)
    need(type(body) is int and 0 <= body <= MAX_BODY and type(framed) is int and 0 <= framed <= MAX_FRAMED)
    need(body <= framed)
    if event in ('REQUEST', 'SERVER_STOPPED'): need(body == framed == 0)
    if event == 'SERVER_STOPPED': need(case == 'none')
    return dict(schema=EVENT_SCHEMA, ordinal=ordinal, event=event, caseId=case,
                bodyBytes=body, framedBytes=framed, reason=reason)


class Journal:
    def __init__(self, root):
        self.lock = threading.Lock(); self.ordinal = 0; self.seen = set(); self.failed = False
        descriptor = os.open(root / 'server-events.private.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_APPEND | os.O_CLOEXEC, 0o600)
        self.stream = os.fdopen(descriptor, 'wb', buffering=0)

    def emit(self, event, case, body=0, framed=0, reason='OK'):
        with self.lock:
            record = event_record(self.ordinal + 1, event, case, body, framed, reason)
            raw = canonical(record) + b'\n'
            need(len(raw) <= 512 and self.stream.write(raw) == len(raw))
            self.stream.flush(); self.ordinal += 1
            if event == 'ERROR': self.failed = True

    def claim(self, case):
        with self.lock:
            need(case in CASES and case not in self.seen)
            self.seen.add(case)

    def close(self):
        self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close()


def write_piece(stream, journal, case, body, framed=None):
    data = body if framed is None else framed
    returned = stream.write(data)
    need(type(returned) is int and returned == len(data))
    stream.flush()
    journal.emit('WRITE_RETURNED', case, len(body), returned)
    return len(body), returned


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'IsolatedSyntheticStream/1'
    sys_version = ''
    wbufsize = 0

    def log_message(self, _format, *_arguments):
        pass  # No URL, header, certificate, exception or body text in logs.

    def headers_for(self, length, chunked=False, document=False):
        self.send_response_only(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if document else 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if chunked: self.send_header('Transfer-Encoding', 'chunked')
        else: self.send_header('Content-Length', str(length))
        self.end_headers()

    def do_GET(self):
        journal = self.server.journal
        case, body_total, framed_total = 'none', 0, 0
        try:
            need(self.headers.get('Host') == '127.0.0.1:17881')
            need(self.headers.get('Content-Length') in (None, '0') and self.headers.get('Transfer-Encoding') is None)
            if self.path == '/':
                self.headers_for(len(HTML), document=True)
                journal.emit('REQUEST', 'none')
                body_total, framed_total = write_piece(self.wfile, journal, 'none', HTML)
                journal.emit('COMPLETE', 'none', body_total, framed_total)
                return
            need(self.path.startswith('/case/') and self.path[6:] in CASES)
            case = self.path[6:]; journal.claim(case); journal.emit('REQUEST', case)
            plan = response_plan(case)
            self.headers_for(plan['contentLength'], plan['chunked'])
            first = plan['parts'][0]
            body, framed = write_piece(self.wfile, journal, case, first, chunk_frame(first) if plan['chunked'] else None)
            body_total += body; framed_total += framed
            if plan['truncated']:
                # A fixed fixture-side prefix window, not a client workaround
                # or a guarantee that the browser exposed this queued prefix.
                time.sleep(0.020)
                self.close_connection = True
                journal.emit('COMPLETE', case, body_total, framed_total)
                return
            if plan['abort']:
                self.connection.settimeout(3)
                try:
                    extra = self.connection.recv(1)
                    need(extra == b'')
                except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
                    pass
                self.close_connection = True
                journal.emit('PEER_CLOSED', case, body_total, framed_total, 'PEER_CLOSED')
                journal.emit('COMPLETE', case, body_total, framed_total)
                return
            time.sleep(0.020)
            second = plan['parts'][1]
            body, framed = write_piece(self.wfile, journal, case, second, chunk_frame(second) if plan['chunked'] else None)
            body_total += body; framed_total += framed
            if plan['chunked']:
                _, framed = write_piece(self.wfile, journal, case, b'', b'0\r\n\r\n')
                framed_total += framed
            journal.emit('COMPLETE', case, body_total, framed_total)
        except socket.timeout:
            self.close_connection = True
            journal.emit('ERROR', case, body_total, framed_total, 'DEADLINE')
        except Rejected:
            self.close_connection = True
            journal.emit('ERROR', case, body_total, framed_total, 'INVALID')
        except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True
            journal.emit('ERROR', case, body_total, framed_total, 'PEER_CLOSED')
        except Exception:
            self.close_connection = True
            journal.emit('ERROR', case, body_total, framed_total, 'UNEXPECTED')

    def do_POST(self):
        self.close_connection = True
        self.server.journal.emit('ERROR', 'none', reason='INVALID')

    do_HEAD = do_POST
    do_PUT = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST
    do_CONNECT = do_POST
    do_PATCH = do_POST


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, journal, context):
        self.journal = journal; self.context = context
        self.connections = 0; self.connection_lock = threading.Lock()
        super().__init__((HOST, PORT), Handler)
        self.timeout = 0.2

    def get_request(self):
        connection, peer = super().get_request()
        try:
            with self.connection_lock:
                self.connections += 1; need(self.connections <= 24)
            connection.settimeout(3)
            wrapped = self.context.wrap_socket(connection, server_side=True)
            wrapped.settimeout(3)
            return wrapped, peer
        except Exception:
            connection.close()
            self.journal.emit('ERROR', 'none', reason='UNEXPECTED')
            raise OSError('stream matrix connection rejected') from None

    def handle_error(self, _request, _client_address):
        self.journal.emit('ERROR', 'none', reason='UNEXPECTED')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    args = parser.parse_args(argv)
    server, journal = None, None
    try:
        need(sys.platform.startswith('linux') and os.geteuid() == os.getegid() == 10001)
        root, fixture = fixture_root(args.root)
        directory = checked_directory(root, 10001, 0o700); need(directory.st_gid == 10001)
        for name in ('api-ca.pem', 'api-leaf.pem', 'api-leaf.key'): private_file(root / name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(root / 'api-leaf.pem', root / 'api-leaf.key')
        journal = Journal(root); server = Server(journal, context)
        stopping = threading.Event()
        def stop(_signum, _frame): stopping.set()
        signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
        publish(root / 'ready.private.json', dict(schema='chengwang.stream-matrix-ready/v1',
            fixtureId=fixture, origin=ORIGIN, pid=os.getpid(), uid=os.geteuid()))
        until = time.monotonic() + 120
        while not stopping.is_set():
            need(time.monotonic() < until)
            server.handle_request()
        server.server_close(); server = None
        journal.emit('SERVER_STOPPED', 'none')
        journal.close(); journal = None
        return 0
    except Exception:
        sys.stderr.write('STREAM_MATRIX_SERVER=FAIL raw_input_suppressed=true\n')
        return 1
    finally:
        if server is not None: server.server_close()
        if journal is not None: journal.close()


if __name__ == '__main__': raise SystemExit(main())
