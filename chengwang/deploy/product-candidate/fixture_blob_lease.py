#!/usr/bin/env python3
"""External write lease on one read-only, digest-bound Registry blob alias.

Test fixture only. It never writes a blob, signals a product or accepts an
arbitrary path. SIGIO is not an assertion about a particular breaker process.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from dataclasses import dataclass

sys.dont_write_bytecode = True
import fixture_lease as base

SCHEMA = "chengwang.product-crash-blob-lease/v1"
STAGES = ("reserved", "consumed")


@dataclass(frozen=True)
class Shape:
    fixture_root: str
    case: str
    kind: str
    control_dir: str
    digest: str
    deadline_seconds: int


def shape(root, case, kind, control, digest, seconds):
    base.require(isinstance(root, str) and base.ROOT.fullmatch(root), "ARGUMENTS")
    base.require(case in STAGES and kind in base.KINDS, "ARGUMENTS")
    base.require(control == root + "/control/blob-" + case + "-" + kind, "ARGUMENTS")
    base.require(isinstance(digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", digest), "ARGUMENTS")
    base.require(isinstance(seconds, str) and re.fullmatch(r"[1-9][0-9]?", seconds), "ARGUMENTS")
    seconds = int(seconds)
    base.require(1 <= seconds <= 30, "ARGUMENTS")
    return Shape(root, case, kind, control, digest, seconds)


def arguments(argv):
    parser = base.SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("hold",))
    for name in ("fixture-root", "case", "kind", "control-dir", "digest"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--deadline-seconds", default="8")
    args = parser.parse_args(argv)
    return shape(args.fixture_root, args.case, args.kind, args.control_dir, args.digest, args.deadline_seconds)


def mount_projection(target, device):
    """Require this exact file to be a read-only bind, not a copied fixture."""
    with open("/proc/self/mountinfo", "rt", encoding="ascii") as handle:
        raw = handle.read((1 << 20) + 1)
    base.require(len(raw) <= 1 << 20, "UNSAFE_FILE")
    entries = []
    for line in raw.splitlines():
        fields = line.split()
        base.require(len(fields) >= 10 and "-" in fields, "UNSAFE_FILE")
        if fields[4] == target:
            split = fields.index("-")
            base.require(split >= 6 and len(fields) >= split + 4, "UNSAFE_FILE")
            base.require(fields[2] == f"{os.major(device)}:{os.minor(device)}"
                         and "ro" in fields[5].split(",") and "rw" not in fields[5].split(",")
                         and fields[split + 1] in ("ext4", "xfs", "tmpfs"), "UNSAFE_FILE")
            entries.append((fields[0], fields[2], fields[3], fields[4], fields[5]))
    base.require(len(entries) == 1, "UNSAFE_FILE")
    return entries[0]


class BlobTree:
    def __init__(self, config):
        self.shape, self.nodes, self.file = config, [], None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            tmp = os.open("/tmp", flags)
            info = os.fstat(tmp)
            self.nodes.append((None, "/tmp", tmp, base.identity(info)))
            base.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                         and stat.S_IMODE(info.st_mode) == 0o1777, "UNSAFE_DIRECTORY")
            root = self.directory(tmp, config.fixture_root.rsplit("/", 1)[1])
            parent = self.directory(self.directory(self.directory(root, "blob"), config.case), config.kind)
            self.parent = parent
            self.control = self.directory(self.directory(root, "control"), "blob-" + config.case + "-" + config.kind)
            base.require(os.listdir(self.control) == [], "CONTROL_CONTENT")
            self.target = config.fixture_root + "/blob/" + config.case + "/" + config.kind + "/data"
            self.file = os.open("data", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(self.file)
            self.regular(info)
            self.original = base.identity(info)
            self.contents = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            self.mount = mount_projection(self.target, info.st_dev)
            raw = os.read(self.file, (1 << 20) + 1)
            base.require(len(raw) == info.st_size and "sha256:" + hashlib.sha256(raw).hexdigest() == config.digest,
                         "UNSAFE_FILE")
            self.verify()
        except OSError:
            self.close()
            raise base.LeaseFailure("UNSAFE_FILE") from None
        except BaseException:
            self.close()
            raise

    directory = base.FixtureTree.directory
    release_requested = base.FixtureTree.release_requested

    @staticmethod
    def regular(info):
        base.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) in (0o600, 0o644)
                     and 0 < info.st_size <= 1 << 20, "UNSAFE_FILE")

    def verify(self):
        try:
            for parent, name, fd, original in self.nodes:
                base.require(base.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original
                             and base.identity(os.fstat(fd)) == original, "PATH_CHANGED")
            if self.file is not None:
                before, opened = os.stat("data", dir_fd=self.parent, follow_symlinks=False), os.fstat(self.file)
                self.regular(before)
                self.regular(opened)
                base.require(base.identity(before) == base.identity(opened) == self.original
                             and (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) == self.contents
                             and mount_projection(self.target, opened.st_dev) == self.mount, "PATH_CHANGED")
        except OSError:
            raise base.LeaseFailure("PATH_CHANGED") from None

    def publish(self, event, kernel, blocked):
        self.verify()
        info = os.fstat(self.file) if self.file is not None else self.target_info
        value = {"schema": SCHEMA, "event": event, "case": self.shape.case, "kind": self.shape.kind,
                 "digest": self.shape.digest, "leaseType": "WRITE", "readOnlyBind": True,
                 "leaseBreakSeconds": kernel, "deadlineSeconds": self.shape.deadline_seconds,
                 "uid": 10001, "gid": 10001, "capNone": True, "blockedObserved": blocked,
                 "holderPID": os.getpid(), "holderStartTime": self.start_time,
                 "deviceMajor": os.major(info.st_dev), "deviceMinor": os.minor(info.st_dev),
                 "inode": info.st_ino, "size": info.st_size,
                 "authorization": "BLOCKED", "production": False, "deviceActionsExecuted": False}
        pending, final = "." + event.lower() + ".json.pending", event.lower() + ".json"
        fd, created = None, False
        try:
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=self.control)
            created = True
            base.regular_file(os.fstat(fd), "CONTROL_WRITE")
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
            base.require(os.write(fd, raw) == len(raw), "CONTROL_WRITE")
            os.fsync(fd)
            os.close(fd)
            fd = None
            rename = ctypes.CDLL(None, use_errno=True).renameat2
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            base.require(rename(self.control, pending.encode(), self.control, final.encode(), 1) == 0, "CONTROL_WRITE")
            created = False
            os.fsync(self.control)
        except OSError:
            raise base.LeaseFailure("CONTROL_WRITE") from None
        finally:
            if fd is not None:
                os.close(fd)
            if created:
                os.unlink(pending, dir_fd=self.control)

    def close(self):
        if self.file is not None:
            os.close(self.file)
            self.file = None
        for _, _, fd, _ in reversed(self.nodes):
            os.close(fd)
        self.nodes = []


def bind_readonly_foreign_blob(source_fd, source_mount_ns_fd, target):
    """Root bootstrap only: clone one foreign file into our private namespace.

    Caller-owned FDs are never closed. No namespace is modified while joined to
    the source namespace; only the detached clone gets new mount attributes.
    The low-privilege CLI neither exposes nor calls this function.
    """
    base.require(sys.platform == "linux", "UNSUPPORTED")
    base.require(os.getuid() == os.geteuid() == 0, "IDENTITY")
    import fcntl
    match = re.fullmatch(r"(/tmp/chengwang-product-lifecycle-[a-f0-9]{32})/blob/(reserved|consumed)/(message-signature|dsse)/data", target) if isinstance(target, str) else None
    base.require(match is not None and type(source_fd) is int and source_fd >= 3
                 and type(source_mount_ns_fd) is int and source_mount_ns_fd >= 3
                 and source_fd != source_mount_ns_fd, "ARGUMENTS")
    # Resolve all libc symbols before setns changes our root/cwd. No guessed
    # syscall numbers or subprocess/path lookups occur in the source namespace.
    class MountAttr(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("attr_set", "attr_clr", "propagation", "userns_fd")]
    libc = ctypes.CDLL(None, use_errno=True)
    signatures = {
        "setns": (ctypes.c_int, ctypes.c_int),
        "open_tree": (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint),
        "move_mount": (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint),
        "mount_setattr": (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.POINTER(MountAttr), ctypes.c_size_t),
    }
    calls = {}
    for name, args in signatures.items():
        base.require(hasattr(libc, name), "UNSUPPORTED")
        calls[name] = getattr(libc, name)
        calls[name].argtypes, calls[name].restype = args, ctypes.c_int
    def checked(value):
        if value < 0:
            raise OSError(ctypes.get_errno(), "foreign blob mount operation failed")
        return value
    owned, nodes = [], []
    def retain(fd):
        owned.append(fd)
        return fd
    def opened(name, flags, parent=None):
        return retain(os.open(name, flags, dir_fd=parent))
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        source = retain(os.dup(source_fd))
        source_ns = retain(os.dup(source_mount_ns_fd))
        original = os.fstat(source)
        BlobTree.regular(original)
        base.require(fcntl.fcntl(source, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                     and not fcntl.fcntl(source, fcntl.F_GETFL) & os.O_PATH, "UNSAFE_FILE")
        original_contents = (original.st_size, original.st_mtime_ns, original.st_ctime_ns)
        saved_ns = opened("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        saved_root = opened("/", directory_flags)
        saved_cwd = opened(".", directory_flags)
        ns_identity = lambda fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        base.require(ns_identity(saved_ns) != ns_identity(source_ns), "UNSAFE_FILE")
        base.require(re.fullmatch(r"mnt:\[[0-9]+\]", os.readlink("/proc/self/fd/" + str(source_ns))) is not None, "UNSAFE_FILE")
        parent = opened("/tmp", directory_flags)
        info = os.fstat(parent)
        base.require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777, "UNSAFE_DIRECTORY")
        nodes.append((None, "/tmp", parent, base.identity(info)))
        for name in target.split("/")[2:-1]:
            child = opened(name, directory_flags, parent)
            info = os.fstat(child)
            base.require(info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) == 0o700, "UNSAFE_DIRECTORY")
            nodes.append((parent, name, child, base.identity(info)))
            parent = child
        alias = opened("data", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, parent)
        placeholder = os.fstat(alias)
        base.regular_file(placeholder)
        base.require(placeholder.st_size == 0, "UNSAFE_FILE")
        def verify_paths():
            for directory, name, fd, identity in nodes:
                base.require(base.identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity
                             and base.identity(os.fstat(fd)) == identity, "PATH_CHANGED")
            base.require(base.identity(os.stat("data", dir_fd=parent, follow_symlinks=False)) == base.identity(placeholder)
                         and base.identity(os.fstat(alias)) == base.identity(placeholder), "PATH_CHANGED")
        verify_paths()
        entered = False
        try:
            checked(calls["setns"](source_ns, 0x00020000))  # CLONE_NEWNS
            entered = True
            tree = retain(checked(calls["open_tree"](source, b"", 1 | os.O_CLOEXEC | 0x1000)))
        finally:
            if entered:
                # If restoration fails, raise before any host path operation or
                # attachment. Numeric-FD cleanup below is safe in either namespace.
                checked(calls["setns"](saved_ns, 0x00020000))
                os.fchdir(saved_cwd)
        current_ns = os.stat("/proc/self/ns/mnt")
        base.require((current_ns.st_dev, current_ns.st_ino) == ns_identity(saved_ns)
                     and os.path.samestat(os.stat("/"), os.fstat(saved_root))
                     and os.path.samestat(os.stat("."), os.fstat(saved_cwd)), "PATH_CHANGED")
        verify_paths()
        cloned = os.fstat(tree)
        base.require(base.identity(cloned) == base.identity(original), "PATH_CHANGED")
        # Per-mount flags on the detached clone only; MS_PRIVATE prevents mount
        # propagation. The Registry's original mount/superblock stays writable.
        attrs = MountAttr(0xF, 0, 0x00040000, 0)
        checked(calls["mount_setattr"](tree, b"", 0x1000, ctypes.byref(attrs), ctypes.sizeof(attrs)))
        checked(calls["move_mount"](tree, b"", alias, b"", 0x4 | 0x40))
        current = os.stat("data", dir_fd=parent, follow_symlinks=False)
        base.require(base.identity(current) == base.identity(original)
                     and (current.st_size, current.st_mtime_ns, current.st_ctime_ns) == original_contents, "PATH_CHANGED")
        projection = mount_projection(target, current.st_dev)
        base.require({"ro", "nosuid", "nodev", "noexec"} <= set(projection[4].split(",")), "UNSAFE_FILE")
    finally:
        close_failed = False
        for fd in reversed(owned):
            try:
                os.close(fd)
            except OSError:
                close_failed = True
        base.require(not close_failed, "UNSAFE_FILE")


def hold(config):
    base.require(sys.platform == "linux", "UNSUPPORTED")
    import fcntl
    base.check_identity()
    kernel = base.kernel_break_seconds()
    base.require(config.deadline_seconds <= kernel - 2, "KERNEL_BREAK_TIME")
    watched = {signal.SIGIO, signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
    tree, leased, blocked = None, False, False
    started = time.monotonic()
    try:
        tree = BlobTree(config)
        with open("/proc/self/stat", "rt", encoding="ascii") as handle:
            tree.start_time = int(handle.read().rsplit(")", 1)[1].split()[19])
        tree.target_info = os.fstat(tree.file)
        try:
            fcntl.fcntl(tree.file, fcntl.F_SETOWN, os.getpid())
            fcntl.fcntl(tree.file, fcntl.F_SETLEASE, fcntl.F_WRLCK)
            leased = True
            base.require(fcntl.fcntl(tree.file, fcntl.F_GETLEASE) == fcntl.F_WRLCK, "LEASE_UNAVAILABLE")
        except OSError:
            raise base.LeaseFailure("LEASE_UNAVAILABLE") from None
        tree.publish("READY", kernel, False)
        while True:
            remaining = config.deadline_seconds - (time.monotonic() - started)
            base.require(remaining > 0, "DEADLINE")
            base.require(base.kernel_break_seconds() == kernel, "KERNEL_BREAK_TIME")
            tree.verify()
            event = signal.sigtimedwait(watched, min(remaining, .025))
            if event is not None:
                base.require(event.si_signo == signal.SIGIO, "TERMINATED")
                if not blocked:
                    blocked = True
                    tree.publish("BLOCKED", kernel, True)
            base.require(time.monotonic() - started < config.deadline_seconds, "DEADLINE")
            if tree.release_requested():
                tree.verify()
                try:
                    fcntl.fcntl(tree.file, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                except OSError:
                    raise base.LeaseFailure("LEASE_RELEASE") from None
                leased = False
                os.close(tree.file)
                tree.file = None
                tree.publish("RELEASED", kernel, blocked)
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
            while signal.sigtimedwait(watched, 0) is not None:
                pass
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def main(argv=None):
    os.umask(0o077)
    try:
        hold(arguments(sys.argv[1:] if argv is None else argv))
        return 0
    except base.LeaseFailure as error:
        print("D12_BLOB_LEASE_FAILURE=" + error.reason, file=sys.stderr)
        return 2 if error.reason == "ARGUMENTS" else 1
    except Exception:
        print("D12_BLOB_LEASE_FAILURE=INTERNAL", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
