"""Closed anomalous HTTPS source fixture, never a product acceptance claim.

Inputs are private files, not an HTTP control interface. Wire observations say
what this endpoint did; they do not say what a product client accepted.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time

import fixture_feed as feed


PLAN_SCHEMA = "chengwang.product-source-plan/v1"
EVENT_SCHEMA = "chengwang.product-source-event/v1"
READY_SCHEMA = "chengwang.product-source-ready/v1"
MODES = (
    "json", "forbidden", "unavailable", "redirect", "content-type-missing",
    "content-type-duplicate", "content-type-wrong", "content-encoding",
    "trailer", "chunked", "length-missing", "length-zero", "length-oversize",
    "length-short", "body-truncated", "header-oversize", "stall-headers",
    "stall-body", "close-before-headers",
)
NO_BODY_MODES = frozenset((
    "forbidden", "unavailable", "redirect", "stall-headers", "close-before-headers",
))
HTTP_REASONS = frozenset((
    "planned", "request-invalid", "method-invalid", "auth-present",
    "plan-unavailable", "plan-invalid", "epoch-rollback", "epoch-conflict",
    "not-planned", "body-unavailable", "body-mismatch", "stopping",
))
REASONS = HTTP_REASONS
MAX_PLAN = 64 << 10
MAX_BODY = 262145
MAX_BODIES = 128
MAX_RESPONSES = 65
MAX_CONNECTIONS = 512
MAX_EVENTS = 4096
MAX_WORKERS = 8
SOCKET_TIMEOUT = 2.0
STALL_SECONDS = 0.75
HEADER_PADDING = 17 << 10
ERROR_BODY = b'{"code":"fixture_source_unavailable"}\n'
FORBIDDEN_BODY = b'{"code":"fixture_source_forbidden"}\n'
REDIRECT_BODY = b'{"code":"fixture_source_redirect"}\n'
REDIRECT_LOCATION = "https://redirect.fixture.invalid/blocked"
Rejected = feed.Rejected
sha = feed.sha
positive = feed.positive
classify_target = feed.classify_target
arguments = feed.arguments


def parse_plan(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PLAN:
        raise Rejected("plan-invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=feed.unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("number")))
        if type(value) is not dict or set(value) != {"schema", "epoch", "responses"}:
            raise ValueError("shape")
        if value["schema"] != PLAN_SCHEMA or not positive(value["epoch"]):
            raise ValueError("identity")
        responses = value["responses"]
        if type(responses) is not dict or len(responses) > MAX_RESPONSES:
            raise ValueError("responses")
        for name, response in responses.items():
            if name != "latest.json" and not feed.generation_name(name):
                raise ValueError("path")
            if type(response) is not dict or set(response) != {"mode", "bodySHA256"}:
                raise ValueError("response")
            mode, digest = response["mode"], response["bodySHA256"]
            if type(mode) is not str or mode not in MODES or type(digest) is not str:
                raise ValueError("response")
            if (mode in NO_BODY_MODES and digest != ""
                    or mode not in NO_BODY_MODES and not feed.DIGEST.fullmatch(digest)):
                raise ValueError("body")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        raise Rejected("plan-invalid") from None


class PrivateFiles(feed.PrivateFiles):
    """Independent limits; old feed's limits and globals are untouched."""

    def __init__(self, fixture_root, case, kind):
        self.immutable = {}
        self.identity_lock = threading.Lock()
        super().__init__(fixture_root, case, kind)

    def _pin(self, parent, name, value):
        identity = (value.st_dev, value.st_ino)
        with self.identity_lock:
            key = (parent, name)
            if key in self.immutable and self.immutable[key] != identity:
                raise Rejected("security-invalid")
            self.immutable[key] = identity

    def audit_entries(self):
        self.check_live()
        allowed = {"server.crt", "server.key", "plan.json", "bodies", "events.jsonl", "ready.json"}
        names = os.listdir(self.feed)
        if not set(names) <= allowed:
            raise Rejected("security-invalid")
        for name in names:
            value = os.stat(name, dir_fd=self.feed, follow_symlinks=False)
            if not feed.private_stat(value, name == "bodies"):
                raise Rejected("security-invalid")
            # Plans deliberately use atomic replacement. Other objects may not
            # change inode even when their replacement has the right owner.
            if name not in ("plan.json", "bodies"):
                self._pin(self.feed, name, value)
        names = os.listdir(self.bodies)
        if len(names) > MAX_BODIES:
            raise Rejected("security-invalid")
        for name in names:
            value = os.stat(name, dir_fd=self.bodies, follow_symlinks=False)
            if (not re.fullmatch(r"[a-f0-9]{64}\.json", name)
                    or not feed.private_stat(value) or not 0 < value.st_size <= MAX_BODY):
                raise Rejected("security-invalid")
            self._pin(self.bodies, name, value)

    def check_output(self, name, fd):
        super().check_output(name, fd)
        self._pin(self.feed, name, os.fstat(fd))

    def open_read(self, name, limit, body=False):
        fd, before, parent = super().open_read(name, limit, body)
        try:
            # Check the inode actually opened, not only the earlier directory
            # audit. Plans alone are deliberately atomically replaceable.
            if body or name != "plan.json":
                self._pin(parent, name, before)
            return fd, before, parent
        except BaseException:
            os.close(fd)
            raise


@dataclass(frozen=True)
class Selection:
    epoch: int
    planSHA256: str
    reason: str
    mode: str
    body: bytes


class PlanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.epoch = 0
        self.plan_hash = ""

    def choose(self, files, name, request_reason=None):
        if request_reason is not None and request_reason not in HTTP_REASONS - {"planned"}:
            raise Rejected("security-invalid")
        try:
            files.audit_entries()
            raw = files.read("plan.json", MAX_PLAN)
        except (OSError, Rejected):
            return Selection(0, "", "plan-unavailable", "unavailable", b"")
        digest = sha(raw)
        try:
            plan = parse_plan(raw)
        except Rejected:
            return Selection(0, digest, "plan-invalid", "unavailable", b"")
        epoch = plan["epoch"]

        def refusal(reason):
            return Selection(epoch, digest, reason, "unavailable", b"")

        with self.lock:
            if epoch < self.epoch:
                return refusal("epoch-rollback")
            if epoch == self.epoch and digest != self.plan_hash:
                return refusal("epoch-conflict")
            if epoch > self.epoch:
                self.epoch, self.plan_hash = epoch, digest
            if request_reason:
                return refusal(request_reason)
            response = plan["responses"].get(name)
            if response is None:
                return refusal("not-planned")
            mode, body_hash = response["mode"], response["bodySHA256"]
            if mode in NO_BODY_MODES:
                return Selection(epoch, digest, "planned", mode, b"")
            try:
                body = files.read(body_hash + ".json", MAX_BODY, True)
            except (OSError, Rejected):
                return refusal("body-unavailable")
            if sha(body) != body_hash:
                return refusal("body-mismatch")
            return Selection(epoch, digest, "planned", mode, body)


@dataclass(frozen=True)
class Wire:
    status: int
    representation: bytes
    wire: bytes
    headerBytes: int
    stall: str


def build_wire(mode, body):
    """A fixed byte grammar, without HTTP-library normalization or timestamps."""
    if mode not in MODES or type(body) is not bytes:
        raise Rejected("security-invalid")
    if mode in NO_BODY_MODES:
        if body:
            raise Rejected("security-invalid")
    elif not 0 < len(body) <= MAX_BODY:
        raise Rejected("security-invalid")
    if mode == "close-before-headers":
        return Wire(0, b"", b"", 0, "close")
    status, phrase, representation = 200, b"OK", body
    if mode == "forbidden":
        status, phrase, representation = 403, b"Forbidden", FORBIDDEN_BODY
    elif mode in ("unavailable", "stall-headers"):
        status, phrase, representation = 503, b"Service Unavailable", ERROR_BODY
    elif mode == "redirect":
        status, phrase, representation = 302, b"Found", REDIRECT_BODY
    headers = [b"HTTP/1.1 " + str(status).encode("ascii") + b" " + phrase + b"\r\n"]
    if mode != "content-type-missing":
        headers.append(b"Content-Type: " + (b"text/plain" if mode == "content-type-wrong"
                                            else b"application/json") + b"\r\n")
        if mode == "content-type-duplicate":
            headers.append(b"Content-Type: application/json\r\n")
    length = len(representation)
    if mode == "length-zero":
        length = 0
    elif mode == "length-oversize":
        length = MAX_BODY
    elif mode == "length-short":
        length -= 1
    if mode == "chunked":
        headers.append(b"Transfer-Encoding: chunked\r\n")
    elif mode != "length-missing":
        headers.append(b"Content-Length: " + str(length).encode("ascii") + b"\r\n")
    if mode == "redirect":
        headers.append(b"Location: " + REDIRECT_LOCATION.encode("ascii") + b"\r\n")
    elif mode == "content-encoding":
        headers.append(b"Content-Encoding: identity\r\n")
    elif mode == "trailer":
        headers.append(b"Trailer: X-Fixture-Trailer\r\n")
    elif mode == "header-oversize":
        headers.append(b"X-Fixture-Padding: " + b"x" * HEADER_PADDING + b"\r\n")
    headers.append(b"Cache-Control: no-store\r\nConnection: close\r\n\r\n")
    head = b"".join(headers)
    payload = representation
    if mode == "body-truncated":
        payload = representation[:-1]
    elif mode == "chunked":
        payload = (format(len(representation), "x").encode("ascii") + b"\r\n"
                   + representation + b"\r\n0\r\n\r\n")
    stall = "headers" if mode == "stall-headers" else "body" if mode == "stall-body" else ""
    return Wire(status, representation, head + payload, len(head), stall)


class SourceServer(socketserver.TCPServer):
    allow_reuse_address = True  # Never SO_REUSEPORT; a live listener is exclusive.

    def __init__(self, files, port, stop):
        self.files, self.stop = files, stop
        files.audit_entries()
        self.context = files.tls_context()
        self.state = PlanState()
        self.lock = threading.Lock()
        self.event_lock = threading.Lock()
        self.workers, self.active = [], set()
        self.slots = threading.BoundedSemaphore(MAX_WORKERS)
        self.ordinal, self.connections = 0, 0
        self.failed = False
        self._events = []
        self.log_fd = files.create("events.jsonl")
        try:
            super().__init__(("127.0.0.1", port), None)
        except BaseException:
            os.close(self.log_fd)
            raise
        self.timeout = 0.1

    @property
    def events(self):
        with self.event_lock:
            return [dict(value) for value in self._events]

    def fail(self):
        self.failed = True
        self.stop.set()

    def get_request(self):
        # Do not accept an unobservable 513th connection. The listening socket
        # is closed by the owner after this bounded loop sees the stop flag.
        if self.connections >= MAX_CONNECTIONS:
            self.fail()
            raise OSError("connection-limit")
        return super().get_request()

    def emit(self, connection, event, reason, tls=False, selection=None,
             path_class="", generation=0, wire=None, written=0, auth=False):
        if event not in ("connect", "tls", "http", "close"):
            raise Rejected("security-invalid")
        allowed = {"connect": {"accepted"}, "tls": {"ok", "failed", "timeout", "stopping"},
                   "http": HTTP_REASONS, "close": {"closed", "stopping"}}
        if reason not in allowed[event]:
            raise Rejected("security-invalid")
        value = {"schema": EVENT_SCHEMA, "ordinal": 0, "connection": connection,
                 "event": event, "reason": reason, "epoch": 0, "planSHA256": "",
                 "pathClass": "", "generation": 0, "mode": "", "status": 0,
                 "representationSHA256": "", "representationBytes": 0,
                 "wireSHA256": "", "wireBytes": 0, "writtenBytes": 0,
                 "wireComplete": False, "authPresent": False, "tls": bool(tls)}
        if event == "http":
            if selection is None or wire is None or not 0 <= written <= len(wire.wire):
                raise Rejected("security-invalid")
            value.update(epoch=selection.epoch, planSHA256=selection.planSHA256,
                         pathClass=path_class, generation=generation, mode=selection.mode,
                         status=wire.status, representationSHA256=sha(wire.representation),
                         representationBytes=len(wire.representation), wireSHA256=sha(wire.wire),
                         wireBytes=len(wire.wire), writtenBytes=written,
                         wireComplete=written == len(wire.wire), authPresent=bool(auth))
        try:
            with self.event_lock:
                if self.ordinal >= MAX_EVENTS:
                    raise Rejected("runtime-failed")
                self.files.check_output("events.jsonl", self.log_fd)
                value["ordinal"] = self.ordinal + 1
                raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                feed.write_all(self.log_fd, raw)
                os.fsync(self.log_fd)
                self.ordinal += 1
                self._events.append(value)
        except BaseException:
            self.fail()
            raise

    def process_request(self, request, address):
        self.connections += 1
        number = self.connections
        try:
            self.emit(number, "connect", "accepted")
            if not self.slots.acquire(blocking=False):
                self.emit(number, "close", "closed")
                request.close()
                return
            with self.lock:
                for finished in self.workers:
                    if not finished.is_alive():
                        finished.join(0)
                self.workers = [worker for worker in self.workers if worker.is_alive()]
                self.active.add(request)
                worker = threading.Thread(target=self.worker, args=(request, number), daemon=False)
                self.workers.append(worker)
            try:
                worker.start()
            except BaseException:
                with self.lock:
                    self.active.discard(request)
                    self.workers.remove(worker)
                self.slots.release()
                self.emit(number, "close", "stopping")
                raise
        except BaseException:
            request.close()
            self.fail()

    def worker(self, raw, number):
        connection, tls = raw, False
        try:
            if self.stop.is_set():
                return
            try:
                raw.settimeout(SOCKET_TIMEOUT)
                connection = self.context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
                connection.settimeout(SOCKET_TIMEOUT)
                with self.lock:
                    self.active.discard(raw)
                    self.active.add(connection)
                if self.stop.is_set():
                    self.emit(number, "tls", "stopping")
                    return
                connection.do_handshake()
                tls = True
                self.emit(number, "tls", "ok", True)
            except (OSError, ValueError) as error:
                reason = ("stopping" if self.stop.is_set() else "timeout"
                          if isinstance(error, TimeoutError) else "failed")
                self.emit(number, "tls", reason)
                return
            if not self.stop.is_set():
                self.respond(connection, number)
        except (OSError, ValueError):
            # A peer may close after a successful TLS handshake without HTTP.
            # This is observable as connect/tls/close, never an invented pin cause.
            pass
        except Exception:
            self.fail()
        finally:
            try:
                self.emit(number, "close", "stopping" if self.stop.is_set() else "closed", tls)
            except Exception:
                self.fail()
            with self.lock:
                self.active.discard(raw)
                self.active.discard(connection)
            try:
                connection.close()
            finally:
                try:
                    raw.close()
                finally:
                    self.slots.release()

    def read_request(self, connection):
        target, method, auth, forced = "", "", False, None
        with connection.makefile("rb") as reader:
            line = reader.readline(4097)
            if not line:
                return None
            match = re.fullmatch(rb"([A-Z]{1,16}) ([\x21-\x7e]{1,2048}) HTTP/1\.[01]\r\n", line)
            if not match:
                return target, method, auth, "request-invalid"
            method, target = (part.decode("ascii") for part in match.groups())
            total, count, lengths, transfer = 0, 0, [], False
            while True:
                line = reader.readline((16 << 10) + 1)
                total += len(line)
                if not line or total > 16 << 10 or not line.endswith(b"\r\n"):
                    forced = "request-invalid"
                    break
                if line == b"\r\n":
                    break
                count += 1
                field = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):([\t\x20-\x7e]*)\r\n", line)
                if count > 64 or not field:
                    forced = "request-invalid"
                    break
                name, value = field[1].lower(), field[2].strip()
                auth |= name in (b"authorization", b"proxy-authorization")
                if name == b"content-length":
                    lengths.append(value)
                transfer |= name in (b"transfer-encoding", b"expect")
            if transfer or lengths not in ([], [b"0"]):
                forced = "request-invalid"
        return target, method, auth, forced

    def respond(self, connection, number):
        parsed = self.read_request(connection)
        if parsed is None:
            return
        target, method, auth, forced = parsed
        path_class, generation, name = classify_target(target)
        forced = (forced or ("method-invalid" if method != "GET" else "auth-present" if auth
                             else "request-invalid" if path_class == "invalid" else None))
        selected = self.state.choose(self.files, name, forced)
        if self.stop.is_set():
            selected = Selection(selected.epoch, selected.planSHA256, "stopping", "unavailable", b"")
        wire = build_wire(selected.mode, selected.body)
        written = 0
        try:
            if wire.stall == "headers" and self.stop.wait(STALL_SECONDS):
                return
            chunks = ((wire.wire[:wire.headerBytes], wire.wire[wire.headerBytes:])
                      if wire.stall == "body" else (wire.wire,))
            for index, chunk in enumerate(chunks):
                if index and wire.stall == "body" and self.stop.wait(STALL_SECONDS):
                    break
                view = memoryview(chunk)
                while view and not self.stop.is_set():
                    size = connection.send(view)
                    if size <= 0:
                        raise OSError("write-incomplete")
                    written += size
                    view = view[size:]
        except (OSError, ValueError):
            pass
        finally:
            self.emit(number, "http", selected.reason, True, selected,
                      path_class, generation, wire, written, auth)

    def handle_error(self, request, client_address):
        self.fail()  # Never publish socketserver's raw traceback/address.

    def close_join(self):
        self.stop.set()
        self.server_close()
        with self.lock:
            connections, workers = list(self.active), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                self.fail()
        deadline = time.monotonic() + SOCKET_TIMEOUT + 1
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            self.fail()
        os.close(self.log_fd)


def serve(config):
    feed.check_process()
    os.umask(0o077)
    stop = threading.Event()
    files, server, previous = None, None, {}
    try:
        files = PrivateFiles(config.fixture_root, config.case, config.kind)
        files.audit_entries()
        server = SourceServer(files, config.port, stop)
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        files.publish_ready({"schema": READY_SCHEMA, "port": config.port, "pid": os.getpid(),
                             "uid": os.geteuid(), "gid": os.getegid(), "tls": True,
                             "listenLoopback": True, "deadlineSeconds": config.deadline_seconds})
        deadline = time.monotonic() + config.deadline_seconds
        while not stop.is_set() and time.monotonic() < deadline:
            server.handle_request()
    finally:
        if server is not None:
            server.close_join()
        if files is not None:
            files.close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if server.failed:
        raise Rejected("runtime-failed")


def main(argv=None):
    try:
        serve(arguments(sys.argv[1:] if argv is None else argv))
        return 0
    except Rejected as error:
        reason = str(error)
        if reason not in HTTP_REASONS | {"security-invalid", "arguments-invalid", "runtime-failed"}:
            reason = "runtime-failed"
        sys.stderr.write("D12_SOURCE_ERROR=REJECTED reason=" + reason + "\n")
        return 1
    except (OSError, ValueError, ssl.SSLError):
        sys.stderr.write("D12_SOURCE_ERROR=REJECTED reason=filesystem-or-tls-invalid\n")
        return 1
    except Exception:
        sys.stderr.write("D12_SOURCE_ERROR=FAILED\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
