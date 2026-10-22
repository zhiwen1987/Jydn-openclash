#!/usr/bin/env python3
"""External Linux read-lease barrier for an isolated D12 fixture only.

This process never writes evidence, changes permissions, signals a product, or
repairs a database. SIGIO proves a conflicting open was attempted; it does not
prove the lease still has F_RDLCK as its F_GETLEASE target while breaking.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import sys
import time
from dataclasses import dataclass

sys.dont_write_bytecode = True

UID = GID = 10001
SCHEMA = "chengwang.product-lifecycle-lease/v1"
KINDS = ("message-signature", "dsse")
ROOT = re.compile(r"/tmp/chengwang-product-lifecycle-([a-f0-9]{32})\Z")
CASE = re.compile(r"[a-z0-9-]{1,64}\Z")
REASONS = frozenset((
    "ARGUMENTS", "UNSUPPORTED", "IDENTITY", "CAPABILITIES",
    "KERNEL_BREAK_TIME", "UNSAFE_DIRECTORY", "UNSAFE_FILE", "PATH_CHANGED",
    "CONTROL_CONTENT", "CONTROL_WRITE", "CONTROL_RELEASE", "LEASE_UNAVAILABLE",
    "LEASE_RELEASE", "DEADLINE", "TERMINATED", "INTERNAL",
))


class LeaseFailure(Exception):
    def __init__(self, reason):
        assert reason in REASONS
        self.reason = reason
        super().__init__(reason)


def require(condition, reason):
    if not condition:
        raise LeaseFailure(reason)


@dataclass(frozen=True)
class Shape:
    fixture_root: str
    case: str
    kind: str
    control_dir: str
    deadline_seconds: int


def validate_shape(fixture_root, case, kind, control_dir, deadline_seconds):
    require(isinstance(fixture_root, str) and ROOT.fullmatch(fixture_root), "ARGUMENTS")
    require(isinstance(case, str) and CASE.fullmatch(case), "ARGUMENTS")
    require(kind in KINDS, "ARGUMENTS")
    require(control_dir == fixture_root + "/control/" + case + "-" + kind, "ARGUMENTS")
    require(isinstance(deadline_seconds, str) and re.fullmatch(r"[1-9][0-9]{0,2}", deadline_seconds), "ARGUMENTS")
    deadline = int(deadline_seconds)
    require(1 <= deadline <= 120, "ARGUMENTS")
    return Shape(fixture_root, case, kind, control_dir, deadline)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise LeaseFailure("ARGUMENTS")


def parse_arguments(arguments):
    parser = SafeParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    hold = sub.add_parser("hold")
    hold.add_argument("--fixture-root", required=True)
    hold.add_argument("--case", required=True)
    hold.add_argument("--kind", required=True)
    hold.add_argument("--control-dir", required=True)
    hold.add_argument("--deadline-seconds", default="8")
    args = parser.parse_args(arguments)
    return validate_shape(args.fixture_root, args.case, args.kind, args.control_dir, args.deadline_seconds)


def check_identity():
    require(os.getuid() == os.geteuid() == UID and os.getgid() == os.getegid() == GID, "IDENTITY")
    require(os.getgroups() == [] or os.getgroups() == [GID], "IDENTITY")
    try:
        with open("/proc/self/status", "rt", encoding="ascii") as handle:
            value = handle.read(16385)
        require(len(value) <= 16384, "CAPABILITIES")
        fields = dict(line.split(":", 1) for line in value.splitlines() if ":" in line)
        for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            require(re.fullmatch(r"[0-9a-fA-F]{16}", fields.get(name, "").strip()) and int(fields[name], 16) == 0, "CAPABILITIES")
        require(fields.get("NoNewPrivs", "").strip() == "1", "CAPABILITIES")
    except OSError:
        raise LeaseFailure("CAPABILITIES") from None


def kernel_break_seconds():
    descriptor = None
    try:
        descriptor = os.open("/proc/sys/fs/lease-break-time", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        raw = os.read(descriptor, 17)
        require(re.fullmatch(rb"[1-9][0-9]{0,3}\n?", raw), "KERNEL_BREAK_TIME")
        value = int(raw)
        require(10 <= value <= 3600, "KERNEL_BREAK_TIME")
        return value
    except OSError:
        raise LeaseFailure("KERNEL_BREAK_TIME") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def identity(info):
    # Directory link counts can change when unrelated /tmp fixtures are added.
    # Regular-file link counts remain part of the exact file binding.
    links = info.st_nlink if stat.S_ISREG(info.st_mode) else 0
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, links)


def regular_file(info, reason="UNSAFE_FILE"):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_uid == UID and info.st_gid == GID and
            stat.S_IMODE(info.st_mode) == 0o600, reason)


class FixtureTree:
    """Retain directory descriptors and recheck each original path binding."""
    def __init__(self, shape):
        self.shape = shape
        self.nodes = []
        self.file = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            self.tmp = os.open("/tmp", flags)
            tmp_info = os.fstat(self.tmp)
            require(stat.S_ISDIR(tmp_info.st_mode) and tmp_info.st_uid == 0 and
                    stat.S_IMODE(tmp_info.st_mode) == 0o1777, "UNSAFE_DIRECTORY")
            self.nodes.append((None, "/tmp", self.tmp, identity(tmp_info)))
            root = self.directory(self.tmp, shape.fixture_root.rsplit("/", 1)[1])
            parent = root
            for name in (shape.case, shape.kind, "data", "evidence"):
                parent = self.directory(parent, name)
            self.evidence = parent
            self.control = self.directory(self.directory(root, "control"), shape.case + "-" + shape.kind)
            require(os.listdir(self.control) == [], "CONTROL_CONTENT")
            self.file = os.open("events.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.evidence)
            info = os.fstat(self.file)
            regular_file(info)
            self.file_identity = identity(info)
            self.file_contents = (info.st_size, info.st_mtime_ns)
            self.verify()
        except OSError:
            self.close()
            raise LeaseFailure("UNSAFE_FILE") from None
        except BaseException:
            self.close()
            raise

    def directory(self, parent, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(descriptor)
        self.nodes.append((parent, name, descriptor, identity(info)))
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == UID and
                info.st_gid == GID and stat.S_IMODE(info.st_mode) == 0o700, "UNSAFE_DIRECTORY")
        return descriptor

    def verify(self):
        try:
            for parent, name, descriptor, original in self.nodes:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(identity(current) == original and identity(os.fstat(descriptor)) == original, "PATH_CHANGED")
            if self.file is not None:
                current = os.stat("events.jsonl", dir_fd=self.evidence, follow_symlinks=False)
                opened = os.fstat(self.file)
                require(identity(current) == self.file_identity == identity(opened) and
                        (opened.st_size, opened.st_mtime_ns) == self.file_contents, "PATH_CHANGED")
        except OSError:
            raise LeaseFailure("PATH_CHANGED") from None

    def release_requested(self):
        descriptor = None
        try:
            before = os.stat("release", dir_fd=self.control, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            raise LeaseFailure("CONTROL_RELEASE") from None
        try:
            regular_file(before, "CONTROL_RELEASE")
            require(before.st_size == 0, "CONTROL_RELEASE")
            descriptor = os.open("release", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.control)
            regular_file(os.fstat(descriptor), "CONTROL_RELEASE")
            require(identity(before) == identity(os.fstat(descriptor)) ==
                    identity(os.stat("release", dir_fd=self.control, follow_symlinks=False)) and
                    os.read(descriptor, 1) == b"", "CONTROL_RELEASE")
            return True
        except OSError:
            raise LeaseFailure("CONTROL_RELEASE") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def publish(self, event, kernel_seconds, blocked):
        self.verify()
        final = event.lower() + ".json"
        pending = "." + final + ".pending"
        descriptor = None
        created = False
        try:
            descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.control)
            created = True
            regular_file(os.fstat(descriptor), "CONTROL_WRITE")
            record = {
                "schema": SCHEMA, "event": event, "case": self.shape.case,
                "kind": self.shape.kind, "leaseBreakSeconds": kernel_seconds,
                "deadlineSeconds": self.shape.deadline_seconds,
                "uid": UID, "gid": GID, "capNone": True,
                "blockedObserved": blocked, "authorization": "BLOCKED",
                "production": False, "deviceActionsExecuted": False,
            }
            raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            require(os.write(descriptor, raw) == len(raw), "CONTROL_WRITE")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            # Linux renameat2(RENAME_NOREPLACE) publishes the complete private
            # file atomically, with no overwrite or transient second hardlink.
            import ctypes
            library = ctypes.CDLL(None, use_errno=True)
            rename = getattr(library, "renameat2", None)
            require(rename is not None, "CONTROL_WRITE")
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            require(rename(self.control, pending.encode("ascii"), self.control,
                           final.encode("ascii"), 1) == 0, "CONTROL_WRITE")
            created = False
            regular_file(os.stat(final, dir_fd=self.control, follow_symlinks=False), "CONTROL_WRITE")
            os.fsync(self.control)
        except OSError:
            raise LeaseFailure("CONTROL_WRITE") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                os.unlink(pending, dir_fd=self.control)

    def close(self):
        if self.file is not None:
            os.close(self.file)
            self.file = None
        for _, _, descriptor, _ in reversed(self.nodes):
            os.close(descriptor)
        self.nodes = []


def hold(shape):
    require(sys.platform == "linux", "UNSUPPORTED")
    import fcntl
    check_identity()
    kernel_seconds = kernel_break_seconds()
    require(shape.deadline_seconds <= kernel_seconds - 2, "KERNEL_BREAK_TIME")
    started = time.monotonic()
    watched = {signal.SIGIO, signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
    tree = None
    leased = False
    blocked = False
    try:
        tree = FixtureTree(shape)
        try:
            fcntl.fcntl(tree.file, fcntl.F_SETOWN, os.getpid())
            fcntl.fcntl(tree.file, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            leased = True
            require(fcntl.fcntl(tree.file, fcntl.F_GETLEASE) == fcntl.F_RDLCK, "LEASE_UNAVAILABLE")
        except OSError:
            raise LeaseFailure("LEASE_UNAVAILABLE") from None
        tree.publish("READY", kernel_seconds, False)
        while True:
            remaining = shape.deadline_seconds - (time.monotonic() - started)
            require(remaining > 0, "DEADLINE")
            require(kernel_break_seconds() == kernel_seconds, "KERNEL_BREAK_TIME")
            tree.verify()
            notification = signal.sigtimedwait(watched, min(remaining, 0.05))
            if notification is not None:
                require(notification.si_signo == signal.SIGIO, "TERMINATED")
                if not blocked:
                    require(time.monotonic() - started < shape.deadline_seconds, "DEADLINE")
                    blocked = True
                    tree.publish("BLOCKED", kernel_seconds, True)
            require(time.monotonic() - started < shape.deadline_seconds, "DEADLINE")
            if tree.release_requested():
                tree.verify()
                try:
                    fcntl.fcntl(tree.file, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                except OSError:
                    raise LeaseFailure("LEASE_RELEASE") from None
                leased = False
                os.close(tree.file)
                tree.file = None
                tree.publish("RELEASED", kernel_seconds, blocked)
                return
    finally:
        try:
            if tree is not None:
                try:
                    if leased and tree.file is not None:
                        fcntl.fcntl(tree.file, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                finally:
                    tree.close()
        finally:
            # A pending default SIGIO must not kill the helper after it has
            # unlocked and before main can emit the fixed failure enum.
            while signal.sigtimedwait(watched, 0) is not None:
                pass
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def main(arguments=None):
    os.umask(0o077)
    try:
        shape = parse_arguments(sys.argv[1:] if arguments is None else arguments)
        hold(shape)
        return 0
    except LeaseFailure as error:
        print("D12_LEASE_FAILURE=" + error.reason, file=sys.stderr)
        return 2 if error.reason == "ARGUMENTS" else 1
    except Exception:
        print("D12_LEASE_FAILURE=INTERNAL", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
