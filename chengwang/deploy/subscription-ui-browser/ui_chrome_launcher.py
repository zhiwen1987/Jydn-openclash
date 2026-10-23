#!/usr/bin/python3 -I
"""Independent CI Chrome child identity/normal wait witness; no product code.

The selected ELF is confined to the owned tools bundle and matched by SHA256.
FDs 3/4 remain inherited for Playwright; the child waits on a separate stdin
gate until its PID/start-tick witness has been atomically published.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import uuid

MAX_ELF_BYTES = 512 << 20
MAX_CHILD_SECONDS = 120


class Rejected(ValueError):
    def __init__(self): super().__init__('subscription UI launcher rejected')


def need(value):
    if not value: raise Rejected()


def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value); value[key] = item
    return value


def decode_config(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 8192)
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=unique,
                      parse_constant=lambda _: need(False))


def validate_config(value, bundle):
    need(type(value) is dict and set(value) == {'schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256'})
    found = re.fullmatch(r'/tmp/chengwang-subscription-ui-tools-([a-f0-9]{32})', str(bundle))
    need(found is not None and value['schema'] == 'chengwang.subscription-ui-launch/v1'
         and type(value['engine']) is str and value['engine'] in ('chrome-cdp', 'playwright'))
    fixture = found[1]
    need(value['fixtureId'] == fixture and value['root'] == '/tmp/chengwang-subscription-ui-' + fixture
         and value['chrome'] == str(bundle / 'chrome/chrome'))
    need(type(value['chromeSHA256']) is str and re.fullmatch(r'[a-f0-9]{64}', value['chromeSHA256']) is not None)
    return fixture, pathlib.Path(value['root']), pathlib.Path(value['chrome'])


def validate_arguments(arguments, profile):
    need(type(arguments) is list and 0 < len(arguments) <= 128)
    need(all(type(argument) is str and 0 < len(argument) <= 8192 and
             re.fullmatch(r'[\x20-\x7e]+', argument) is not None for argument in arguments))
    need(sum(map(len, arguments)) <= 65536)
    need([argument for argument in arguments if argument.startswith('--user-data-dir')]
         == ['--user-data-dir=' + str(profile)])
    forbidden = {'--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors',
        '--allow-insecure-localhost', '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure',
        '--allow-running-insecure-content'}
    need(not any(argument.split('=', 1)[0] in forbidden for argument in arguments))
    need('--no-sandbox' in arguments)


def directory(path, owner, exact_mode=None):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid == owner
         and not stat.S_IMODE(info.st_mode) & 0o022)
    if exact_mode is not None: need(stat.S_IMODE(info.st_mode) == exact_mode)
    return info


def stable_file(path, maximum, owner, exact_mode=None):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == owner
         and not stat.S_IMODE(before.st_mode) & 0o022 and 0 < before.st_size <= maximum)
    if exact_mode is not None: need(stat.S_IMODE(before.st_mode) == exact_mode)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor); need(os.path.samestat(before, opened))
        parts, length = [], 0
        while True:
            part = os.read(descriptor, min(65536, maximum + 1 - length))
            if not part: break
            parts.append(part); length += len(part); need(length <= maximum)
        after, named = os.fstat(descriptor), path.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
                                item.st_uid, item.st_gid, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        need(length == before.st_size and identity(before) == identity(opened) == identity(after) == identity(named))
        return b''.join(parts), before
    finally:
        os.close(descriptor)


def publish(path, value):
    raw = canonical(value) + b'\n'; need(0 < len(raw) <= 8192)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(descriptor)
        # Reference: deploy/probe-readback/run_probe_readback.py:publish_atomic.
        # Linux renameat2(RENAME_NOREPLACE) publishes one fsynced inode with
        # nlink=1 throughout, and cannot replace an existing handoff/witness.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        need(rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1) == 0)
    finally:
        os.close(descriptor)
        if temporary.exists(): temporary.unlink()


def start_ticks(pid):
    raw = pathlib.Path('/proc', str(pid), 'stat').read_text(encoding='ascii')
    number = int(raw[raw.rfind(')') + 2:].split()[19]); need(number > 0)
    return number


def environment(root, profile):
    # No inherited HOME, proxy, trust override, NODE_OPTIONS or Python paths.
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': '/var/tmp',
            'XDG_DATA_HOME': str(root / 'home/.local/share'), 'XDG_CONFIG_HOME': str(profile / 'config'),
            'XDG_CACHE_HOME': str(profile / 'cache')}


def gate_command(chrome, arguments):
    return ['/usr/bin/bash', '--noprofile', '--norc', '-c',
            'IFS= read -r launch_gate && test "$launch_gate" = start || exit 78; exec "$@"',
            'chengwang-subscription-ui-chrome', str(chrome), *arguments]


def exit_record(engine, fixture, pid, ticks, code, forced):
    need(engine in ('chrome-cdp', 'playwright') and type(fixture) is str
         and re.fullmatch(r'[a-f0-9]{32}', fixture) is not None)
    need(type(pid) is int and pid >= 2 and type(ticks) is int and ticks >= 1
         and type(code) is int and type(forced) is bool)
    return dict(schema='chengwang.subscription-ui-chrome-exit/v1', engine=engine, fixtureId=fixture,
                pid=pid, startTicks=ticks, exitCode=code, joined=True, forced=forced)


def fixed_failure(kind):
    need(kind in ('LAUNCHER', 'CLEANUP', 'EXIT'))
    try:
        sys.stderr.write('SUBSCRIPTION_UI_CHROME_' + kind + '=FAIL raw_input_suppressed=true\n')
    except BaseException:
        pass  # A closed private stderr cannot justify a raw fallback traceback.


def confirmed_wait(child, timeout):
    code = child.wait(timeout=timeout)
    observed = child.poll()
    need(type(code) is int and type(observed) is int and code == observed)
    return code


def cleanup_child(child, intervention):
    """Confirm an already-exited child, or retain any actual signal attempt.

The mutable flag survives failures after signalling, so a failed cleanup can
never publish a forced=false witness for a child which was intervened upon.
"""
    known = child.poll()
    if known is not None:
        need(type(known) is int)
        return known
    if child.stdin is not None and not child.stdin.closed: child.stdin.close()
    try:
        return confirmed_wait(child, 2)
    except subprocess.TimeoutExpired:
        pass
    try:
        descriptor = os.pidfd_open(child.pid)
    except ProcessLookupError:
        # poll()==None is not a durable process-existence claim. If exit raced
        # with pidfd_open, obtain a real wait result rather than inventing one.
        known = child.poll()
        if known is not None:
            need(type(known) is int)
            return known
        return confirmed_wait(child, 3)
    try:
        for signum, timeout in ((signal.SIGTERM, 8), (signal.SIGKILL, 3)):
            try:
                signal.pidfd_send_signal(descriptor, signum)
                intervention['forced'] = True
            except ProcessLookupError:
                return confirmed_wait(child, 3)
            except BaseException:
                # A non-ESRCH signalling error is inconclusive, not authority
                # to claim that no intervention occurred.
                intervention['forced'] = True
                raise
            try:
                return confirmed_wait(child, timeout)
            except subprocess.TimeoutExpired:
                if signum == signal.SIGKILL: raise
        raise Rejected()
    finally:
        os.close(descriptor)


def main(arguments=None):
    child = None; config = None; root = None; ticks = None; fixture = None
    code = None; intervention = dict(forced=False); exit_published = False
    try:
        need(sys.platform.startswith('linux') and os.geteuid() == os.getegid() == 10001
             and 'HOME' not in os.environ and os.environ.get('TMPDIR') == '/var/tmp')
        bundle = pathlib.Path(__file__).absolute().parent
        directory(bundle, 0); directory(bundle / 'chrome', 0)
        raw, info = stable_file(bundle / 'launch.json', 8192, 0, 0o440)
        need(info.st_gid == 10001)
        config = decode_config(raw); fixture, root, chrome = validate_config(config, bundle)
        need(directory(root, 10001, 0o700).st_gid == 10001)
        profile = root / 'chrome-profile'
        need(directory(profile, 10001, 0o700).st_gid == 10001)
        need(directory(root / 'home', 10001, 0o700).st_gid == 10001)
        arguments = sys.argv[1:] if arguments is None else arguments
        validate_arguments(arguments, profile)
        executable, _ = stable_file(chrome, MAX_ELF_BYTES, 0)
        need(executable.startswith(b'\x7fELF') and hashlib.sha256(executable).hexdigest() == config['chromeSHA256'])

        def interrupted(_signum, _frame): raise Rejected()
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        child = subprocess.Popen(gate_command(chrome, arguments), stdin=subprocess.PIPE,
            close_fds=False, start_new_session=True, env=environment(root, profile))
        ticks = start_ticks(child.pid)
        need(os.getpgid(child.pid) == os.getsid(child.pid) == child.pid)
        publish(root / 'chrome-process.private.json', dict(pid=child.pid, startTicks=ticks,
            uid=os.geteuid(), profile=str(profile)))
        child.stdin.write(b'start\n'); child.stdin.close()
        code = child.wait(timeout=MAX_CHILD_SECONDS)
        publish(root / 'chrome-exit.private.json', exit_record(config['engine'], fixture, child.pid, ticks, code, False))
        exit_published = True
        need(code == 0)
        return 0
    except Exception:
        fixed_failure('LAUNCHER')
        return 1
    finally:
        cleanup_failed = False
        if child is not None:
            try:
                code = cleanup_child(child, intervention)
            except BaseException:
                cleanup_failed = True; fixed_failure('CLEANUP')
        if child is not None and not exit_published and ticks is not None and root is not None:
            try:
                actual = child.poll()
                need(type(actual) is int and (code is None or actual == code))
                publish(root / 'chrome-exit.private.json', exit_record(config['engine'], fixture, child.pid,
                    ticks, actual, intervention['forced']))
            except BaseException:
                cleanup_failed = True; fixed_failure('EXIT')
        if cleanup_failed:
            return 1


if __name__ == '__main__': raise SystemExit(main())
