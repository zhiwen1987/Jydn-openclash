#!/usr/bin/env python3
"""Bounded Linux cleanup for this run's detached browser group only.

This is a CI supervisor, not a Chrome sandbox or a production process manager.
The handoff record is written before the gated wrapper is allowed to exec
Chrome. No process arguments, paths, record contents or credentials are logged.
"""
import json
import os
import posixpath
import signal
import stat
import sys
import time
from dataclasses import dataclass


RECORD = "chrome-process.private.json"
MAX_RECORD = 4096
MAX_PROCESSES = 32768


class Unsafe(Exception):
    pass


@dataclass(frozen=True)
class Process:
    pid: int
    uid: int
    group: int
    session: int
    started: int
    state: str
    argv: tuple


def parse_stat(raw):
    # comm may itself contain spaces and parentheses. Fields are indexed after
    # its final ')', not after a whitespace split of the entire stat record.
    end = raw.rfind(b")")
    fields = raw[end + 1:].split()
    if end < 0 or len(fields) < 20:
        raise Unsafe()
    try:
        return fields[0].decode("ascii"), int(fields[2]), int(fields[3]), int(fields[19])
    except (ValueError, UnicodeError):
        raise Unsafe() from None


def process(pid):
    try:
        directory = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        owner = os.fstat(directory).st_uid
        fd = os.open("stat", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            raw = os.read(fd, 8192)
        finally:
            os.close(fd)
        state, group, session, started = parse_stat(raw)
        fd = os.open("cmdline", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            command = os.read(fd, 262145)
        finally:
            os.close(fd)
        if len(command) > 262144:
            raise Unsafe()
        return Process(pid, owner, group, session, started, state, tuple(command.rstrip(b"\0").split(b"\0")))
    except (FileNotFoundError, ProcessLookupError):
        return None
    finally:
        os.close(directory)


def profile_bound(p, profile):
    value = os.fsencode(profile)
    for index, arg in enumerate(p.argv):
        if arg == b"--user-data-dir=" + value:
            return True
        if arg == b"--user-data-dir" and index + 1 < len(p.argv) and p.argv[index + 1] == value:
            return True
    # Chrome's crashpad handler may use its own session and omit user-data-dir.
    # The trusted launcher puts XDG_CONFIG_HOME/XDG_CACHE_HOME in this private
    # profile. Only this executable basename and canonical descendant paths
    # bind that exception; a similar prefix or '..' never grants membership.
    if not p.argv or posixpath.basename(p.argv[0]) != b"chrome_crashpad_handler":
        return False
    for index, arg in enumerate(p.argv):
        candidate = None
        for flag in (b"--database", b"--metrics-dir"):
            if arg.startswith(flag + b"="):
                candidate = arg[len(flag) + 1:]
            elif arg == flag and index + 1 < len(p.argv):
                candidate = p.argv[index + 1]
        if candidate is not None and candidate.startswith(value + b"/") and b"\\" not in candidate and b"\0" not in candidate and posixpath.isabs(candidate) and posixpath.normpath(candidate) == candidate:
            return True
    return False


def processes():
    ids = [int(name) for name in os.listdir("/proc") if name.isdecimal()]
    if len(ids) > MAX_PROCESSES:
        raise Unsafe()
    result = []
    for pid in ids:
        try:
            p = process(pid)
        except PermissionError:
            # Foreign identities are not cleanup targets. Target members with
            # inaccessible metadata fail below if a complete scan is required.
            try:
                if os.stat(f"/proc/{pid}").st_uid == os.geteuid():
                    raise Unsafe() from None
            except FileNotFoundError:
                pass
            continue
        if p is not None:
            result.append(p)
    return result


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unsafe()
        result[key] = value
    return result


def open_root(path):
    if not os.path.isabs(path) or os.path.normpath(path) != path or path == "/":
        raise Unsafe()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        parts = path[1:].split("/")
        for index, part in enumerate(parts):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            ancestor_sticky = index < len(parts) - 1 and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022 and not ancestor_sticky:
                raise Unsafe()
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise Unsafe()
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_record(root_fd, root):
    try:
        fd = os.open(RECORD, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid() or before.st_gid != os.getegid() or before.st_nlink != 1 or not 0 < before.st_size <= MAX_RECORD:
            raise Unsafe()
        raw = os.read(fd, MAX_RECORD + 1)
        after = os.fstat(fd)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise Unsafe()
        value = json.loads(raw, object_pairs_hook=no_duplicates)
        if not isinstance(value, dict) or set(value) != {"pid", "startTicks", "uid", "profile"}:
            raise Unsafe()
        if any(type(value[key]) is not int for key in ("pid", "startTicks", "uid")):
            raise Unsafe()
        if value["pid"] <= 1 or value["pid"] > 4194304 or value["startTicks"] <= 0 or value["uid"] != os.geteuid() or value["profile"] != os.path.join(root, "chrome-profile"):
            raise Unsafe()
        return value
    finally:
        os.close(fd)


def targets(record, profile):
    snapshot = processes()
    bound = [p for p in snapshot if profile_bound(p, profile)]
    if record is None:
        if bound:
            # The gated wrapper makes an unrecorded live Chrome impossible in
            # a valid run. Do not invent identity when that contract is broken.
            raise Unsafe()
        return []
    leader = next((p for p in snapshot if p.pid == record["pid"]), None)
    if leader is not None and (leader.uid != record["uid"] or leader.started != record["startTicks"] or leader.group != leader.pid or leader.session != leader.pid or leader.state not in ("Z", "X") and not profile_bound(leader, profile)):
        raise Unsafe()
    members = [p for p in snapshot if p.group == record["pid"]]
    # Linux retains a process-group/session PID identifier while members are
    # alive, even after its leader exits. It cannot be reused for a new leader
    # in that interval. Checking every retained member avoids claiming that a
    # vanished leader means its renderers have already exited.
    for p in members:
        if p.uid != record["uid"] or p.session != record["pid"] or p.started < record["startTicks"]:
            raise Unsafe()
    # Crash handlers may leave the original group. Only an exact profile
    # argument or the narrowly validated crashpad paths bind such additional
    # processes. This supervisor is not containment of malicious subprocesses.
    for p in bound:
        if p.uid != record["uid"] or p.started < record["startTicks"]:
            raise Unsafe()
    unique = {p.pid: p for p in members + bound}
    if os.getpid() in unique or os.getppid() in unique:
        raise Unsafe()
    return [p for p in unique.values() if p.state not in ("Z", "X")]


def signal_targets(current, sig):
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise Unsafe()
    # A pidfd pins an individual process. Re-check after opening it, then send
    # through that fd rather than a numeric PID or a racy killpg operation.
    for expected in current:
        try:
            fd = os.pidfd_open(expected.pid, 0)
        except ProcessLookupError:
            continue
        try:
            actual = process(expected.pid)
            if actual is None:
                continue
            if (actual.uid, actual.started, actual.group, actual.session) != (expected.uid, expected.started, expected.group, expected.session):
                raise Unsafe()
            try:
                signal.pidfd_send_signal(fd, sig)
            except ProcessLookupError:
                pass
        finally:
            os.close(fd)


def cleanup(root):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise Unsafe()
    root_fd = open_root(root)
    try:
        try:
            profile_fd = os.open("chrome-profile", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            profile_fd = None
        if profile_fd is not None:
            try:
                info = os.fstat(profile_fd)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise Unsafe()
            finally:
                os.close(profile_fd)
        record = read_record(root_fd, root)
        profile = os.path.join(root, "chrome-profile")
        for sig, allowance in ((signal.SIGTERM, 1.0), (signal.SIGKILL, 2.0)):
            deadline = time.monotonic() + allowance
            while True:
                current = targets(record, profile)
                if not current:
                    return
                signal_targets(current, sig)
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
        if targets(record, profile):
            raise Unsafe()
    finally:
        os.close(root_fd)


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "cleanup":
        args = args[1:]
    try:
        if len(args) != 1:
            raise Unsafe()
        cleanup(args[0])
    except (Unsafe, OSError, ValueError, TypeError, UnicodeError):
        print("D8_BROWSER_PROCESS_GUARD=FAIL cleanup_not_proven=true", file=sys.stderr)
        return 1
    print("D8_BROWSER_PROCESS_GUARD=PASS owned_processes_stopped=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
