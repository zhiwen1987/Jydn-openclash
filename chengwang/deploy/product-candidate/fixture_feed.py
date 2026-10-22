"""Isolated D12 HTTPS source fixture; not product refresh or Registry acceptance.

The only mutable control is a private local plan file. No HTTP control route,
product hook, trust decision, credential, or raw request is published here.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.server
import json
import os
import re
import signal
import socket
import ssl
import stat
import sys
import threading
import time


PLAN_SCHEMA = "chengwang.product-lifecycle-feed-plan/v1"
EVENT_SCHEMA = "chengwang.product-lifecycle-feed-event/v1"
READY_SCHEMA = "chengwang.product-lifecycle-feed-ready/v1"
FIXTURE_ID = re.compile(r"/tmp/chengwang-product-lifecycle-[a-f0-9]{32}\Z")
CASE_ID = re.compile(r"[a-z0-9-]{1,64}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
GENERATION = re.compile(r"([1-9][0-9]{0,19})\.json\Z")
UINT64 = (1 << 64) - 1
MAX_PLAN = 64 << 10
MAX_BODY = 256 << 10
MAX_EVENTS = 8192
SOCKET_TIMEOUT = 2.0
MAX_WORKERS = 8
ERROR_BODY = b'{"code":"fixture_feed_unavailable"}\n'
REASONS = frozenset((
    "ok", "planned-unavailable", "not-planned", "one-shot-exhausted",
    "plan-unavailable", "plan-invalid", "epoch-rollback", "epoch-conflict",
    "body-unavailable", "body-mismatch", "request-invalid", "auth-present",
    "method-invalid", "shutting-down",
))


class Rejected(Exception):
    """Only fixed reason codes may cross the private diagnostic boundary."""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def positive(value):
    return type(value) is int and 1 <= value <= UINT64


def canonical_decimal(raw, minimum, maximum):
    if not re.fullmatch(r"[1-9][0-9]{0,19}", raw):
        raise argparse.ArgumentTypeError("invalid bounded decimal")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise argparse.ArgumentTypeError("invalid bounded decimal")
    return value


def generation_name(name):
    match = GENERATION.fullmatch(name)
    return int(match[1]) if match and int(match[1]) <= UINT64 else 0


def classify_target(target):
    if target == "/feed/latest.json":
        return "latest", 0, "latest.json"
    if target.startswith("/feed/"):
        name = target[6:]
        generation = generation_name(name)
        if generation:
            return "generation", generation, name
    return "invalid", 0, ""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def parse_plan(raw):
    if not 0 < len(raw) <= MAX_PLAN:
        raise Rejected("plan-invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("number")))
        if type(value) is not dict or set(value) not in (
                {"schema", "epoch", "responses"}, {"schema", "epoch", "responses", "oneShot"}):
            raise ValueError("shape")
        if value["schema"] != PLAN_SCHEMA or not positive(value["epoch"]):
            raise ValueError("identity")
        if "oneShot" in value and type(value["oneShot"]) is not bool:
            raise ValueError("one-shot")
        responses = value["responses"]
        if type(responses) is not dict:
            raise ValueError("responses")
        for name, response in responses.items():
            if name != "latest.json" and not generation_name(name):
                raise ValueError("path")
            if type(response) is not dict or set(response) != {"status", "bodySHA256"}:
                raise ValueError("response")
            status, digest = response["status"], response["bodySHA256"]
            if type(status) is not int or status not in (200, 503) or type(digest) is not str:
                raise ValueError("response")
            if status == 200 and not DIGEST.fullmatch(digest) or status == 503 and digest != "":
                raise ValueError("body")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        raise Rejected("plan-invalid") from None


def check_process():
    if (not sys.platform.startswith("linux") or os.getuid() != 10001 or os.getgid() != 10001
            or os.geteuid() != 10001 or os.getegid() != 10001 or os.getgroups()):
        raise Rejected("security-invalid")
    with open("/proc/self/status", "rb") as handle:
        raw = handle.read(64 << 10).decode("ascii")
    values = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
    if values.get("NoNewPrivs", "").strip() != "1":
        raise Rejected("security-invalid")
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if not re.fullmatch(r"0{16}", values.get(name, "").strip()):
            raise Rejected("security-invalid")


def private_stat(value, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    return (kind(value.st_mode) and stat.S_IMODE(value.st_mode) == (0o700 if directory else 0o600)
            and value.st_uid == 10001 and value.st_gid == 10001
            and (directory or value.st_nlink == 1))


def same_identity(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


class PrivateFiles:
    def __init__(self, fixture_root, case, kind):
        if not FIXTURE_ID.fullmatch(fixture_root) or not CASE_ID.fullmatch(case) or kind not in ("message-signature", "dsse"):
            raise Rejected("security-invalid")
        self.fds = []
        self.links = []
        try:
            tmp = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.fds.append(tmp)
            self.tmp = tmp
            value = os.fstat(tmp)
            if not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o1777 or value.st_uid != 0 or value.st_gid != 0:
                raise Rejected("security-invalid")
            parent = tmp
            for name in (fixture_root.rsplit("/", 1)[1], case, kind, "feed", "bodies"):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                self.fds.append(child)
                if not private_stat(os.fstat(child), True):
                    raise Rejected("security-invalid")
                self.links.append((parent, name, child))
                parent = child
            self.feed, self.bodies = self.fds[-2:]
            self.check_live()
        except (OSError, Rejected):
            self.close()
            raise Rejected("security-invalid") from None

    def check_live(self):
        tmp = os.stat("/tmp", follow_symlinks=False)
        if (not same_identity(tmp, os.fstat(self.tmp)) or not stat.S_ISDIR(tmp.st_mode)
                or stat.S_IMODE(tmp.st_mode) != 0o1777 or tmp.st_uid != 0 or tmp.st_gid != 0):
            raise Rejected("security-invalid")
        for parent, name, child in self.links:
            actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(child)
            if not private_stat(actual, True) or not same_identity(actual, held):
                raise Rejected("security-invalid")

    def audit_entries(self):
        self.check_live()
        allowed = {"server.crt", "server.key", "plan.json", "bodies", "events.jsonl", "ready.json"}
        names = os.listdir(self.feed)
        if not set(names) <= allowed:
            raise Rejected("security-invalid")
        for name in names:
            value = os.stat(name, dir_fd=self.feed, follow_symlinks=False)
            if not private_stat(value, name == "bodies"):
                raise Rejected("security-invalid")
        names = os.listdir(self.bodies)
        if len(names) > 1024:
            raise Rejected("security-invalid")
        for name in names:
            value = os.stat(name, dir_fd=self.bodies, follow_symlinks=False)
            if (not re.fullmatch(r"[a-f0-9]{64}\.json", name) or not private_stat(value)
                    or not 0 < value.st_size <= MAX_BODY):
                raise Rejected("security-invalid")

    def open_read(self, name, limit, body=False):
        self.check_live()
        parent = self.bodies if body else self.feed
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not private_stat(before) or not 0 < before.st_size <= limit:
                raise Rejected("security-invalid")
            return fd, before, parent
        except BaseException:
            os.close(fd)
            raise

    def read(self, name, limit, body=False):
        fd, before, parent = self.open_read(name, limit, body)
        try:
            chunks, remaining = [], limit + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self.check_live()
            if (not private_stat(after) or not private_stat(named) or not same_identity(before, named)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or len(raw) != before.st_size or len(raw) > limit):
                raise Rejected("security-invalid")
            return raw
        finally:
            os.close(fd)

    def create(self, name):
        self.check_live()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.feed)
        if not private_stat(os.fstat(fd)):
            os.close(fd)
            raise Rejected("security-invalid")
        os.fsync(self.feed)
        return fd

    def check_output(self, name, fd):
        self.check_live()
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=self.feed, follow_symlinks=False)
        if not private_stat(held) or not private_stat(named) or not same_identity(held, named):
            raise Rejected("security-invalid")

    def publish_ready(self, value):
        # The final name is never visible with empty/partial contents, and an
        # existing report is never replaced. Pending is private and startup-only.
        fd = self.create("ready.pending")
        try:
            write_all(fd, json.dumps(value, sort_keys=True).encode() + b"\n")
            os.fsync(fd)
            self.check_output("ready.pending", fd)
            library = ctypes.CDLL(None, use_errno=True)
            rename = library.renameat2
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            if rename(self.feed, b"ready.pending", self.feed, b"ready.json", 1) != 0:
                raise Rejected("security-invalid")
            os.fsync(self.feed)
            self.check_output("ready.json", fd)
        finally:
            try:
                pending = os.stat("ready.pending", dir_fd=self.feed, follow_symlinks=False)
                if same_identity(pending, os.fstat(fd)):
                    os.unlink("ready.pending", dir_fd=self.feed)
                    os.fsync(self.feed)
            except FileNotFoundError:
                pass
            os.close(fd)

    def tls_context(self):
        descriptors = []
        try:
            for name, limit in (("server.crt", 256 << 10), ("server.key", 64 << 10)):
                self.read(name, limit)
                fd, _, _ = self.open_read(name, limit)
                descriptors.append(fd)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain("/proc/self/fd/" + str(descriptors[0]),
                                    "/proc/self/fd/" + str(descriptors[1]))
            context.set_alpn_protocols(["http/1.1"])
            return context
        finally:
            for fd in descriptors:
                os.close(fd)

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class PlanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.epoch = 0
        self.plan_hash = ""
        self.used = set()

    def choose(self, files, name, request_reason=None):
        try:
            files.audit_entries()
            raw = files.read("plan.json", MAX_PLAN)
        except (OSError, Rejected):
            return 0, "plan-unavailable", ERROR_BODY
        try:
            plan = parse_plan(raw)
        except Rejected:
            return 0, "plan-invalid", ERROR_BODY
        epoch = plan["epoch"]
        with self.lock:
            if epoch < self.epoch:
                return epoch, "epoch-rollback", ERROR_BODY
            if epoch == self.epoch and sha(raw) != self.plan_hash:
                return epoch, "epoch-conflict", ERROR_BODY
            if epoch > self.epoch:
                self.epoch, self.plan_hash = epoch, sha(raw)
                self.used.clear()
            if request_reason:
                return epoch, request_reason, ERROR_BODY
            response = plan["responses"].get(name)
            if response is None:
                return epoch, "not-planned", ERROR_BODY
            if response["status"] == 503:
                return epoch, "planned-unavailable", ERROR_BODY
            if plan.get("oneShot", False) and name in self.used:
                return epoch, "one-shot-exhausted", ERROR_BODY
            try:
                body = files.read(response["bodySHA256"] + ".json", MAX_BODY, True)
            except (OSError, Rejected):
                return epoch, "body-unavailable", ERROR_BODY
            if sha(body) != response["bodySHA256"]:
                return epoch, "body-mismatch", ERROR_BODY
            if plan.get("oneShot", False):
                self.used.add(name)
            return epoch, "ok", body


def write_all(fd, raw):
    while raw:
        size = os.write(fd, raw)
        if not size:
            raise Rejected("security-invalid")
        raw = raw[size:]


class FeedServer(http.server.HTTPServer):
    # Sequential, explicitly stopped fixtures may reuse the fixed source port
    # despite TIME_WAIT. No SO_REUSEPORT: a live listener must still exclude a
    # second process, and the only bind address remains loopback.
    allow_reuse_address = True

    def __init__(self, files, port, stop):
        self.files, self.stop = files, stop
        self.context = files.tls_context()
        self.state = PlanState()
        self.lock = threading.Lock()
        self.workers = []
        self.active = set()
        self.slots = threading.BoundedSemaphore(MAX_WORKERS)
        self.ordinal = 0
        self.failed = False
        self.log_fd = files.create("events.jsonl")
        try:
            super().__init__(("127.0.0.1", port), FeedHandler)
        except BaseException:
            os.close(self.log_fd)
            raise
        self.timeout = 0.1

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        with self.lock:
            finished = [worker for worker in self.workers if not worker.is_alive()]
            for worker in finished:
                worker.join(0)
            self.workers = [worker for worker in self.workers if worker.is_alive()]
            self.active.add(request)
            worker = threading.Thread(target=self.worker, args=(request, address), daemon=False)
            self.workers.append(worker)
        worker.start()

    def worker(self, raw, address):
        connection = raw
        try:
            raw.settimeout(SOCKET_TIMEOUT)
            connection = self.context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            connection.settimeout(SOCKET_TIMEOUT)
            with self.lock:
                self.active.discard(raw)
                self.active.add(connection)
            if not self.stop.is_set():
                connection.do_handshake()
                self.finish_request(connection, address)
        except (OSError, ValueError):
            pass  # Transport failures contain no completed HTTP response.
        except Exception:
            self.failed = True
            self.stop.set()
        finally:
            with self.lock:
                self.active.discard(raw)
                self.active.discard(connection)
            connection.close()
            raw.close()
            self.slots.release()

    def handle_error(self, request, client_address):
        self.failed = True
        self.stop.set()

    def event(self, epoch, path_class, generation, status, body, auth_present, reason, sent):
        if reason not in REASONS:
            raise Rejected("security-invalid")
        with self.lock:
            if self.ordinal >= MAX_EVENTS:
                raise Rejected("security-invalid")
            self.files.check_output("events.jsonl", self.log_fd)
            self.ordinal += 1
            value = {"schema": EVENT_SCHEMA, "ordinal": self.ordinal, "epoch": epoch,
                     "pathClass": path_class, "generation": generation, "status": status,
                     "bodySHA256": sha(body), "bytes": len(body) if sent else 0,
                     "tls": True, "authPresent": auth_present, "reason": reason,
                     "sentComplete": sent}
            write_all(self.log_fd, json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            os.fsync(self.log_fd)

    def close_join(self):
        self.stop.set()
        self.server_close()
        with self.lock:
            connections = list(self.active)
            workers = list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        deadline = time.monotonic() + SOCKET_TIMEOUT + 1
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            self.failed = True
        os.close(self.log_fd)


class FeedHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def parse_request(self):
        # Parse a deliberately small, closed HTTP/1 request shape. In particular,
        # BaseHTTPRequestHandler's normalization must not bless // or escapes.
        self.command, self.request_version = "", "HTTP/1.1"
        self.close_connection = True
        self.target, self.auth_present = "", False
        match = re.fullmatch(rb"([A-Z]{1,16}) ([\x21-\x7e]{1,2048}) HTTP/1\.[01]\r\n", self.raw_requestline)
        if not match:
            self.respond("request-invalid")
            return False
        self.command, self.target = (part.decode("ascii") for part in match.groups())
        total, count, content_lengths, transfer = 0, 0, [], False
        while True:
            line = self.rfile.readline((16 << 10) + 1)
            total += len(line)
            if not line or total > 16 << 10 or not line.endswith(b"\r\n"):
                self.respond("request-invalid")
                return False
            if line == b"\r\n":
                break
            count += 1
            field = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):([\t\x20-\x7e]*)\r\n", line)
            if count > 64 or not field:
                self.respond("request-invalid")
                return False
            name, value = field[1].lower(), field[2].strip()
            self.auth_present |= name in (b"authorization", b"proxy-authorization")
            if name == b"content-length":
                content_lengths.append(value)
            transfer |= name in (b"transfer-encoding", b"expect")
        if transfer or content_lengths not in ([], [b"0"]):
            self.respond("request-invalid")
            return False
        return True

    def send_error(self, code, message=None, explain=None):
        self.respond("method-invalid" if self.command else "request-invalid")

    def do_GET(self):
        self.respond()

    def respond(self, forced=None):
        path_class, generation, name = classify_target(getattr(self, "target", ""))
        auth_present = getattr(self, "auth_present", False)
        reason = forced
        if reason is None:
            reason = ("method-invalid" if self.command != "GET" else "auth-present" if auth_present
                      else "request-invalid" if path_class == "invalid" else None)
        epoch, reason, body = self.server.state.choose(self.server.files, name, reason)
        if self.server.stop.is_set():
            reason, body = "shutting-down", ERROR_BODY
        status = 200 if reason == "ok" else 503
        # HEAD is rejected with an empty representation, without writing a body
        # that a conforming HEAD client could not observe.
        if self.command == "HEAD":
            body = b""
        sent = False
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            sent = True
        except (OSError, ValueError):
            pass
        self.server.event(epoch, path_class, generation, status, body, auth_present, reason, sent)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise Rejected("arguments-invalid")


def arguments(argv):
    parser = SafeParser(add_help=False, allow_abbrev=False)
    parser.add_argument("action", choices=("serve",))
    parser.add_argument("--fixture-root", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--kind", required=True, choices=("message-signature", "dsse"))
    parser.add_argument("--port", required=True, type=lambda raw: canonical_decimal(raw, 1024, 65535))
    parser.add_argument("--deadline-seconds", default=300, type=lambda raw: canonical_decimal(raw, 1, 600))
    result = parser.parse_args(argv)
    if not FIXTURE_ID.fullmatch(result.fixture_root) or not CASE_ID.fullmatch(result.case):
        raise Rejected("arguments-invalid")
    return result


def serve(config):
    check_process()
    os.umask(0o077)
    stop = threading.Event()
    files, server = None, None
    previous = {}
    try:
        files = PrivateFiles(config.fixture_root, config.case, config.kind)
        server = FeedServer(files, config.port, stop)
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        ready = {"schema": READY_SCHEMA, "port": config.port, "pid": os.getpid(),
                 "uid": os.geteuid(), "gid": os.getegid(), "tls": True,
                 "listenLoopback": True, "deadlineSeconds": config.deadline_seconds}
        files.publish_ready(ready)
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
        if reason not in REASONS | {"security-invalid", "arguments-invalid", "runtime-failed"}:
            reason = "runtime-failed"
        sys.stderr.write("D12_FEED_ERROR=REJECTED reason=" + reason + "\n")
        return 1
    except (OSError, ValueError, ssl.SSLError):
        sys.stderr.write("D12_FEED_ERROR=REJECTED reason=filesystem-or-tls-invalid\n")
        return 1
    except Exception:
        sys.stderr.write("D12_FEED_ERROR=FAILED\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
