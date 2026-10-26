"""Capture the unprofiled half of the opt-in A/B measurement.

This is diagnostic evidence only. It does not execute Mihomo, HTTP, or a
production writer, and it deliberately preserves the original Go exit.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import time

PRIVATE = Path('/tmp/chengwang-capacity-profile-private')
SOURCE = Path('/tmp/chengwang-capacity-profile-source')
EXPORT = Path('/tmp/chengwang-capacity-profile-export')
PACKAGES = ['./internal/adapter/mihomo', './internal/mihomodeploy', './internal/authn',
    './internal/api', './internal/serverruntime', './internal/authz']
GO_ARGS = ['test', '-race', '-json', '-count=1', '-timeout=180s', *PACKAGES]
RAW_NAMES = ('go-version.txt', 'capacity.json', 'capacity.stderr', 'commands.jsonl',
    'execution.json', 'resource-before.json', 'resource-after.json')


def need(ok):
    if not ok:
        raise ValueError('capacity pair evidence rejected')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())


def stable(path, limit, owner=None, mode=None):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit)
    if owner is not None:
        need(before.st_uid == before.st_gid == owner)
    if mode is not None:
        need(stat.S_IMODE(before.st_mode) == mode)
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_uid, value.st_gid, value.st_mode, value.st_nlink)
    need(identity(before) == identity(opened) == identity(after) == identity(path.lstat()) and len(raw) == before.st_size)
    return raw


def profile_helper():
    path = SOURCE / 'deploy/mihomo-capacity-profile/profile_evidence.py'
    spec = importlib.util.spec_from_file_location('capacity_profile_pair_dependency', path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resource_observation():
    value = profile_helper().resource_observation()
    need(value['schema'] == 'chengwang.capacity-profile-resources/v1' and value['diagnosticMode'] == 'FULL_CONTRACTS')
    value['schema'] = 'chengwang.capacity-pair-resources/v1'
    value['diagnosticMode'] = 'NO_PROFILE_NORMAL_FLAGS'
    return value


def sandbox(goroot):
    need(sys.platform == 'linux' and os.getuid() == os.getgid() == 10001 and Path.cwd() == SOURCE)
    need(os.environ.get('CHENGWANG_CAPACITY_PROFILE_MODE') is None)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    interfaces = sorted(name for _, name in socket.if_nameindex())
    ip = shutil.which('ip', path='/usr/sbin:/usr/bin:/sbin:/bin')
    need(ip is not None)
    defaults = {key: json.loads(subprocess.check_output([ip, flag, '-j', 'route', 'show', 'default']))
        for key, flag in (('ipv4', '-4'), ('ipv6', '-6'))}
    value = {'schema': 'chengwang.capacity-pair-sandbox/v1', 'mode': 'A_NO_PROFILE',
        'uid': os.getuid(), 'gid': os.getgid(), 'effectiveCaps': status['CapEff'].strip(),
        'noNewPrivileges': True, 'interfaces': interfaces, 'defaultRoutes': defaults,
        'environmentKeys': sorted(os.environ),
        'sourceAliasReadOnly': bool(os.statvfs(SOURCE).f_flag & os.ST_RDONLY),
        'goRootReadOnly': bool(os.statvfs(goroot).f_flag & os.ST_RDONLY), 'goRoot': str(goroot),
        'networkNamespace': os.readlink('/proc/self/ns/net'), 'mountNamespace': os.readlink('/proc/self/ns/mnt'),
        'pidNamespace': os.readlink('/proc/self/ns/pid'), 'production': False}
    need(interfaces == ['lo'] and defaults == {'ipv4': [], 'ipv6': []} and
        int(value['effectiveCaps'], 16) == 0 and status['NoNewPrivs'].strip() == '1' and
        value['sourceAliasReadOnly'] and value['goRootReadOnly'])
    sys.stdout.buffer.write(encoded(value))


def commands(goroot):
    need(sys.platform == 'linux' and os.getuid() == os.getgid() == 10001 and Path.cwd() == SOURCE)
    commit = os.environ.get('CHENGWANG_CAPACITY_PAIR_SOURCE_COMMIT')
    context_sha = os.environ.get('CHENGWANG_CAPACITY_PAIR_CONTEXT_SHA256')
    need(commit is not None and len(commit) == 40 and all(c in '0123456789abcdef' for c in commit))
    need(context_sha is not None and len(context_sha) == 64 and all(c in '0123456789abcdef' for c in context_sha))
    need(os.environ.get('CHENGWANG_CAPACITY_PROFILE_MODE') is None and sorted(PRIVATE.iterdir()) == [])
    os.umask(0o077)
    sequence = 0

    def journal(kind, argv, event, pid=None, code=None):
        nonlocal sequence
        sequence += 1
        row = {'seq': sequence, 'event': event, 'class': kind, 'argv': argv,
            'pid': pid, 'exitCode': code, 'monotonicNs': time.monotonic_ns()}
        with (PRIVATE / 'commands.jsonl').open('ab') as stream:
            stream.write(encoded(row))
            stream.flush()
            os.fsync(stream.fileno())

    def run(kind, argv, stdout_name, stderr_name, child_umask=None):
        journal(kind, argv, 'START_INTENT')
        with (PRIVATE / stdout_name).open('xb') as stdout, (PRIVATE / stderr_name).open('xb') as stderr:
            options = {'umask': child_umask} if child_umask is not None else {}
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, **options)
            journal(kind, argv, 'STARTED', process.pid)
            code = process.wait()
            stdout.flush(); os.fsync(stdout.fileno())
            stderr.flush(); os.fsync(stderr.fileno())
        journal(kind, argv, 'WAIT_RETURNED', process.pid, code)
        return code

    go = str(Path(goroot) / 'bin/go')
    version = run('VERSION', [go, 'version'], 'go-version.txt', 'version.stderr.private')
    write(PRIVATE / 'resource-before.json', encoded(resource_observation()))
    code = run('GO_TEST', [go, *GO_ARGS], 'capacity.json', 'capacity.stderr', 0o022)
    write(PRIVATE / 'resource-after.json', encoded(resource_observation()))
    execution = {'schema': 'chengwang.capacity-pair-execution/v1', 'mode': 'A_NO_PROFILE',
        'sourceCommit': commit, 'contextSHA256': context_sha, 'versionExit': version,
        'goExit': code, 'captureComplete': True, 'realMihomoExecuted': False, 'production': False}
    write(PRIVATE / 'execution.json', encoded(execution))


def export(out):
    need(sys.platform == 'linux' and os.getuid() == 0 and out == EXPORT and out.is_dir())
    for name in RAW_NAMES:
        path = PRIVATE / name
        limit = 64 << 20 if name == 'capacity.json' else 2 << 20
        raw = stable(path, limit, 10001, 0o600)
        raw.decode('utf8', 'strict')
        write(out / name, raw, 0o644)


def bind(out, mode, context):
    need(sys.platform == 'linux' and os.getuid() == 0 and out == EXPORT and out.is_dir())
    context_raw = stable(context, 16384)
    value = json.loads(context_raw)
    need(value['leg'] == mode and value['sourceCommit'] == os.environ.get('CHENGWANG_CAPACITY_PAIR_SOURCE_COMMIT'))
    execution_raw = stable(out / 'execution.json', 16384)
    execution = json.loads(execution_raw)
    expected_schema = 'chengwang.capacity-pair-execution/v1' if mode == 'A' else 'chengwang.capacity-profile-execution/v2'
    need(execution['schema'] == expected_schema and execution['sourceCommit'] == value['sourceCommit'])
    receipt = {'schema': 'chengwang.capacity-pair-leg-receipt/v1', 'leg': mode,
        'sourceCommit': value['sourceCommit'], 'contextSHA256': digest(context_raw),
        'executionSHA256': digest(execution_raw), 'goExit': execution['goExit'],
        'captureOnly': True, 'performanceImprovementProven': False, 'production': False}
    write(out / 'leg-receipt.json', encoded(receipt), 0o644)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('commands', 'export', 'sandbox', 'bind'))
    parser.add_argument('--goroot', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--mode', choices=('A', 'B'))
    parser.add_argument('--context', type=Path)
    args = parser.parse_args()
    if args.action == 'commands':
        commands(args.goroot)
    elif args.action == 'export':
        export(args.out)
    elif args.action == 'sandbox':
        sandbox(args.goroot)
    else:
        bind(args.out, args.mode, args.context)


if __name__ == '__main__':
    main()
