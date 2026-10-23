"""CI-only native backend lab. Never builds Go or changes host networking/trust.

The privileged outer supervisor records unchanged host inputs; one disposable
net/mount/PID namespace runs the real, precompiled agent/server/driver. Every
product process has a further private mount namespace and executes as 10001,
without capabilities. No browser acceptance is claimed by this runner.
"""
from __future__ import annotations

import argparse
import base64
import calendar
import ctypes
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

try:
    import resource
except ImportError:  # Importable for pure auxiliary tests, never a Linux fallback.
    resource = None


PREFIX = 'product-probe-readback-'
ROOT_RE = re.compile(r'/tmp/chengwang-probe-readback-[a-f0-9]{32}\Z')
TOOLS_RE = re.compile(r'/tmp/chengwang-probe-harness-[a-f0-9]{32}\Z')
COMMIT_RE = re.compile(r'[a-f0-9]{40}\Z')
DIGEST_RE = re.compile(r'[a-f0-9]{64}\Z')
DRIVER_ACTIONS = ('prepare', 'collect-first', 'collect-final', 'verify-fresh',
                  'verify-restarted', 'verify-expired')
ROLES = ('wire', 'agent', 'api-first', 'api-second')
EXPECTED = frozenset([PREFIX + a + '.json' for a in DRIVER_ACTIONS]
                    + [PREFIX + 'api-' + p + '-' + k + '.json'
                       for p in ('fresh', 'restarted', 'expired') for k in ('status', 'details')]
                    + [PREFIX + 'wire-' + n for n in ('ready.json', 'events.jsonl', 'stopped.json')]
                    + [PREFIX + n + '.json' for n in ('source-metadata-before', 'source-metadata-after',
                                                     'isolation', 'processes', 'runtime', 'cleanup', 'outcome')])
SYSTEM_CA = '/etc/ssl/certs/ca-certificates.crt'
BASE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
            'GODEBUG': 'x509usefallbackroots=0'}
FLAGS = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
         | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
PHASE = 'ARGUMENTS'
FAILURE_CODES = frozenset((
    'AGENT_ARGUMENTS', 'AGENT_CA_BINDING', 'AGENT_CA_WRITABLE', 'AGENT_DEADLINE',
    'ALTERNATE_ROOT_DIRECTORY', 'API_SOURCE_WRITABLE', 'ARGUMENTS', 'CLEANUP_TARGET',
    'COMMAND_FAILED', 'COMMIT', 'DRIVER_DEADLINE', 'DRIVER_FAILED', 'FILE_CHANGED',
    'FILE_MODE', 'FILE_OWNER', 'FILE_SHAPE', 'FINAL_SEGMENTS', 'FINAL_SEGMENT_DIGEST',
    'FRESHNESS_WINDOW', 'HOST_CHANGED', 'INNER_ARGUMENTS', 'JSON_DUPLICATE', 'JSON_NUMBER',
    'LAB_DEADLINE', 'LAB_FAILED', 'LAB_INIT_IDENTITY', 'LINUX_REQUIRED', 'LINUX_ROOT_REQUIRED',
    'MOUNT_MISSING', 'NAMESPACE_PORT_START', 'NETWORK_INTERFACES', 'NETWORK_ROUTE',
    'OUTER_CLEANUP_TARGET', 'OUTPUT_NOT_EMPTY', 'OUTPUT_SET', 'OUTPUT_WRITE', 'PATH_DIRECTORY',
    'PATH_LINK', 'PATH_SHAPE', 'PATH_WRITABLE', 'PROCESS_ARGUMENTS', 'PROCESS_EXECUTABLE',
    'PROCESS_LIMIT', 'PROCESS_NOT_RUNNING', 'PROCESS_PROFILE_DEADLINE', 'PROCESS_REUSED',
    'PROCESS_SECURITY', 'PROCESS_STARTUP', 'PROCESS_STOP_FAILED', 'PUBLIC_NAME', 'PUBLIC_SECRET',
    'READINESS_DEADLINE', 'ROLE', 'ROLE_ARGUMENTS', 'ROOT_REQUIRED', 'SERVER_ENVIRONMENT',
    'SIGNAL', 'SOURCE_BYTES', 'SOURCE_COUNT', 'SOURCE_HEAD', 'SOURCE_MUTATED', 'SOURCE_PATH',
    'STATE_COUNT', 'STATE_ENTRIES', 'STATE_IDENTITY', 'STATE_MODE', 'STATE_NAME', 'STATE_OWNER',
    'STOP_DEADLINE', 'SUPERVISOR_DEADLINE', 'TIME_FORMAT', 'TOOLS_CLEANUP_TARGET',
    'TOOL_COPY_CHANGED', 'TOOL_WRITABLE', 'WIRE_READY', 'UNEXPECTED'))
PHASES = frozenset(('ARGUMENTS', 'HOST_BEFORE', 'HOST_AFTER', 'LAB_SUPERVISOR', 'WIRE_START',
                    'AGENT_STOP', 'WIRE_STOP', 'API_START', 'NATURAL_EXPIRY', 'INTERNAL',
                    'DRIVER_PREPARE', 'DRIVER_COLLECT_FIRST', 'DRIVER_COLLECT_FINAL',
                    'DRIVER_VERIFY_FRESH', 'DRIVER_VERIFY_RESTARTED', 'DRIVER_VERIFY_EXPIRED'))


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def safe_failure(error, phase):
    code = (error.args[0] if isinstance(error, Failure) and error.args
            and type(error.args[0]) is str and error.args[0] in FAILURE_CODES else 'UNEXPECTED')
    return phase if type(phase) is str and phase in PHASES else 'INTERNAL', code


def private_diagnostic(raw):
    if type(raw) is not bytes or len(raw) > 65536:
        return None
    allowed = {('PROBE_READBACK_RUNNER=FAIL phase=' + phase + ' code=' + code
                + ' raw_input_suppressed=true').encode(): (phase, code)
               for phase in PHASES for code in FAILURE_CODES}
    matches = [allowed[line] for line in raw.splitlines() if line in allowed]
    return matches[0] if len(matches) == 1 else None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'JSON_DUPLICATE')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Failure('JSON_NUMBER')))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def stable_read(path, limit=1 << 20, owner=None, mode=None):
    fd = os.open(path, FLAGS)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= limit, 'FILE_SHAPE')
        if owner is not None:
            require((before.st_uid, before.st_gid) == (owner, owner), 'FILE_OWNER')
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, 'FILE_MODE')
        pieces, count = [], 0
        while count <= limit:
            piece = os.read(fd, min(65536, limit + 1 - count))
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
        raw = b''.join(pieces)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path, follow_symlinks=False)), 'FILE_CHANGED')
        return raw, before
    finally:
        os.close(fd)


def checked_path(value, directory=False):
    p = pathlib.Path(value)
    require(p.is_absolute() and str(p) == value and '..' not in p.parts, 'PATH_SHAPE')
    current = pathlib.Path('/')
    for part in p.parts[1:]:
        current /= part
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'PATH_LINK')
        if current != p or directory:
            require(stat.S_ISDIR(info.st_mode), 'PATH_DIRECTORY')
            sticky_tmp = str(current) == '/tmp' and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777
            require(not info.st_mode & 0o022 or sticky_tmp, 'PATH_WRITABLE')
    return p


def exclusive(path, raw, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
                 | getattr(os, 'O_BINARY', 0), mode)
    try:
        offset = 0
        while offset < len(raw):
            size = os.write(fd, raw[offset:])
            require(size > 0, 'OUTPUT_WRITE')
            offset += size
        os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def publish_atomic(path, raw, mode=0o600):
    """Linux-only complete-file, no-replace publication for lab handoffs.

    Unlike link/unlink, renameat2 never exposes a transient nlink=2 to the
    strict readers. Existing native evidence writers keep their old protocol.
    """
    require(sys.platform.startswith('linux') and type(raw) is bytes, 'OUTPUT_WRITE')
    path = pathlib.Path(path)
    pending = path.with_name(path.name + '.pending')
    exclusive(pending, raw, mode)
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        require(rename(-100, os.fsencode(pending), -100, os.fsencode(path), 1) == 0, 'OUTPUT_WRITE')
    finally:
        if pending.exists():
            pending.unlink()


def command(argv, timeout=15):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=BASE_ENV, timeout=timeout)
    require(p.returncode == 0 and len(p.stdout) <= 8 << 20, 'COMMAND_FAILED')
    return p.stdout


def ns(pid='self'):
    return {name: os.readlink('/proc/' + str(pid) + '/ns/' + name)
            for name in ('net', 'mnt', 'pid', 'user')}


def source_files(root, commit):
    git = ['git', '-c', 'safe.directory=' + str(root), '-C', str(root)]
    require(command(git + ['rev-parse', 'HEAD']).strip().decode() == commit,
            'SOURCE_HEAD')
    paths = command(git + ['ls-files', '-z', '--', 'chengwang', '.github/workflows']).split(b'\0')
    files = []
    for rawpath in paths:
        if not rawpath:
            continue
        rel = rawpath.decode('utf-8')
        require(not pathlib.PurePosixPath(rel).is_absolute() and '..' not in pathlib.PurePosixPath(rel).parts,
                'SOURCE_PATH')
        raw, _ = stable_read(root / rel, 64 << 20)
        original = command(git + ['cat-file', 'blob', commit + ':' + rel])
        require(raw == original, 'SOURCE_BYTES')
        files.append({'path': rel, 'bytes': len(raw), 'sha256': sha(raw)})
    files.sort(key=lambda f: f['path'])
    require(0 < len(files) <= 8192, 'SOURCE_COUNT')
    return files


def host_observation(root, commit):
    files = source_files(root, commit)
    ca, _ = stable_read(SYSTEM_CA, 8 << 20)
    return {'netNamespace': ns()['net'], 'mountNamespace': ns()['mnt'],
            'pidNamespace': ns()['pid'], 'userNamespace': ns()['user'],
            'portStart': int(pathlib.Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text()),
            'systemCASHA256': sha(ca), 'sourceSHA256': sha(canonical(files))}, files


def base(schema, options):
    return {'schema': 'chengwang.probe-readback-' + schema + '/v1',
            'sourceCommit': options.source_commit, 'fixtureId': options.fixture_id,
            'acceptanceScope': 'NATIVE_BACKEND_ONLY', 'browserE2EProven': False,
            'authorization': 'BLOCKED', 'production': False, 'deviceActionsExecuted': False}


def report(options, suffix, schema, **fields):
    value = base(schema, options)
    value.update(fields)
    exclusive(pathlib.Path(options.output_dir) / (PREFIX + suffix + '.json'), canonical(value) + b'\n')


def mount_bind(path, readonly):
    command(['mount', '--bind', str(path), str(path)])
    command(['mount', '-o', 'remount,bind,' + ('ro' if readonly else 'rw') + ',nosuid,nodev', str(path)])


def mount_flags(pid, target):
    raw = pathlib.Path('/proc', str(pid), 'mountinfo').read_text()
    matches = []
    for line in raw.splitlines():
        left, _, _right = line.partition(' - ')
        values = left.split()
        if len(values) >= 6 and values[4].replace('\\040', ' ') == str(target):
            matches.append(values[5].split(','))
    require(matches, 'MOUNT_MISSING')
    return sorted(matches[-1])


def task_profile(pid, expected_sha, *, executable_limit=128 << 20):
    first = pathlib.Path('/proc', str(pid), 'stat').read_text()
    start = first[first.rfind(')') + 2:].split()[19]
    fields = dict(line.split(':', 1) for line in pathlib.Path('/proc', str(pid), 'status').read_text().splitlines() if ':' in line)
    uid, gid = [int(v) for v in fields['Uid'].split()], [int(v) for v in fields['Gid'].split()]
    caps = {k: fields[k].strip() for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}
    require(uid == gid == [10001] * 4 and fields['Groups'].strip() == ''
            and all(v == '0000000000000000' for v in caps.values())
            and fields['NoNewPrivs'].strip() == '1', 'PROCESS_SECURITY')
    # /proc/PID/exe is intentionally followed: it is an owned process witness,
    # unlike a caller-selected filesystem input. Hash the held executable FD.
    with open('/proc/' + str(pid) + '/exe', 'rb') as handle:
        require(type(executable_limit) is int and 0 < executable_limit <= 512 << 20
                and os.fstat(handle.fileno()).st_size <= executable_limit, 'PROCESS_EXECUTABLE')
        actual = sha(handle.read(executable_limit))
    require(actual == expected_sha, 'PROCESS_EXECUTABLE')
    rawargv = pathlib.Path('/proc', str(pid), 'cmdline').read_bytes()
    require(0 < len(rawargv) < 128 << 10, 'PROCESS_ARGUMENTS')
    limits_raw = pathlib.Path('/proc', str(pid), 'limits').read_text()
    limits = {}
    for key, title in (('cpuSeconds', 'Max cpu time'), ('fileBytes', 'Max file size'),
                       ('openFiles', 'Max open files'), ('processes', 'Max processes'),
                       ('coreBytes', 'Max core file size')):
        line = next(line for line in limits_raw.splitlines() if line.startswith(title + ' '))
        values = line[len(title):].split()
        require(values[0].isdigit() and values[1].isdigit(), 'PROCESS_LIMIT')
        limits[key] = [int(values[0]), int(values[1])]
    second = pathlib.Path('/proc', str(pid), 'stat').read_text()
    require(second[second.rfind(')') + 2:].split()[19] == start, 'PROCESS_REUSED')
    return {'pid': pid, 'startTime': start, 'exeSHA256': actual, 'argvSHA256': sha(rawargv),
            'uid': uid, 'gid': gid, 'groups': [], 'capabilities': caps,
            'noNewPrivs': 1, 'namespaces': ns(pid), 'limits': limits}


def state_metadata(root):
    def item(path, rel):
        info = path.lstat()
        require(info.st_uid == info.st_gid == 10001, 'STATE_OWNER')
        directory = stat.S_ISDIR(info.st_mode)
        require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), 'STATE_MODE')
        if directory:
            count, digest, mode = 0, 'directory', 0x80000000 | 0o700
        else:
            raw, actual = stable_read(path, 65536, 10001, 0o600)
            require(identity(actual) == identity(info), 'STATE_IDENTITY')
            count, digest, mode = len(raw), sha(raw), 0o600
        return {'path': rel, 'kind': 'directory' if directory else 'file', 'modeGo': mode,
                'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
                'bytes': count, 'sha256': digest, 'deviceMajor': os.major(info.st_dev),
                'deviceMinor': os.minor(info.st_dev), 'inode': info.st_ino}
    entries = []
    for label, child, lock in (('spool', 'segments', '.probe-spool.lock'),
                                ('ledger', 'snapshots', '.probe-start-ledger.lock')):
        directory = root / label
        require(set(os.listdir(directory)) == {child, lock}, 'STATE_ENTRIES')
        entries.append(item(directory, label + '/.'))
        entries.append(item(directory / lock, label + '/' + lock))
        entries.append(item(directory / child, label + '/' + child))
        names = sorted(os.listdir(directory / child))
        require(len(names) <= 16, 'STATE_COUNT')
        for name in names:
            require(re.fullmatch(r'[0-9]{20}-[a-f0-9]{16}\.json', name), 'STATE_NAME')
            entries.append(item(directory / child / name, label + '/' + child + '/' + name))
    entries.sort(key=lambda e: e['path'])
    return {'snapshotDigest': snapshot_digest(entries), 'catalog': item(root / 'catalog.json', 'catalog.json'),
            'entries': entries}


def snapshot_digest(entries):
    raw = b''.join(('\0'.join(str(e[k]) for k in ('path', 'bytes', 'modeGo', 'uid', 'gid', 'nlink', 'sha256'))
                    + '\0').encode('ascii') for e in sorted(entries, key=lambda e: e['path']))
    return 'sha256:' + sha(raw)


def timestamp_ns(value):
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', value)
    require(match is not None, 'TIME_FORMAT')
    instant = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S')
    return calendar.timegm(instant.timetuple()) * 1000000000 + int((match[2] or '').ljust(9, '0'))


def expiry_bounds(root):
    payload = decode(stable_read(root / (PREFIX + 'collect-final.json'))[0])
    expires = []
    require(len(payload['spoolSegments']) == 6, 'FINAL_SEGMENTS')
    for file in payload['spoolSegments']:
        raw = base64.b64decode(file['raw'], validate=True)
        require(sha(raw) == file['sha256'], 'FINAL_SEGMENT_DIGEST')
        result = decode(raw)['result']
        expires.append(timestamp_ns(result['expiresAt']))
        expires.extend(timestamp_ns(layer['expiresAt']) for layer in result['layers'].values())
    return min(expires), max(expires)


def configure_role(options, *, supervisor_entrypoint='runner', web_dir=None):
    root, bundle = pathlib.Path(options.fixture_root), pathlib.Path(options.bundle)
    require(os.geteuid() == 0 and ROOT_RE.fullmatch(str(root)) and TOOLS_RE.fullmatch(str(bundle)), 'ROLE_ARGUMENTS')
    # Internal roles may only be children of this lab's PID-namespace init,
    # already in a further private mount namespace. A direct --role invocation
    # must never turn mount --make-rprivate into a host-side operation.
    parent_argv = pathlib.Path('/proc/1/cmdline').read_bytes().split(b'\0')
    current_ns, parent_ns = ns(), ns(1)
    require(supervisor_entrypoint in ('runner', 'browser-runner'), 'ROLE_ARGUMENTS')
    require(os.getppid() == 1 and str(bundle / supervisor_entrypoint).encode() in parent_argv
            and b'--inner' in parent_argv and current_ns['pid'] == parent_ns['pid']
            and current_ns['net'] == parent_ns['net'] and current_ns['mnt'] != parent_ns['mnt'],
            'ROLE_ARGUMENTS')
    command(['mount', '--make-rprivate', '/'])
    role = options.role
    # The original CLI exposes neither this keyword nor a static-directory
    # escape. Only the separately witnessed browser wrapper can supply it.
    require(web_dir is None or (supervisor_entrypoint == 'browser-runner'
            and role in ('api-first', 'api-second') and pathlib.Path(web_dir) == bundle / 'web'),
            'ROLE_ARGUMENTS')
    if role in ('agent', 'api-first', 'api-second', 'wire'):
        mount_bind(root, True)
        for name in ({'agent': ('spool', 'ledger'), 'wire': ('wire',),
                      'api-first': ('data',), 'api-second': ('data',)})[role]:
            mount_bind(root / name, False)
        if role in ('api-first', 'api-second'):
            for name in ('catalog.json', 'spool', 'ledger'):
                mount_bind(root / name, True)
    else:
        for name in ('catalog.json', 'spool', 'ledger'):
            if (root / name).exists():
                mount_bind(root / name, True)
    environment = dict(BASE_ENV)
    if role == 'agent':
        require(not pathlib.Path('/etc/pki/tls/certs').exists(), 'ALTERNATE_ROOT_DIRECTORY')
        command(['mount', '-t', 'tmpfs', '-o', 'mode=0755,size=1m,nodev,nosuid,noexec',
                 'probe-lab-agent-ca', '/etc/ssl/certs'])
        pathlib.Path(SYSTEM_CA).touch(mode=0o644)
        command(['mount', '--bind', str(root / 'target-ca.pem'), SYSTEM_CA])
        command(['mount', '-o', 'remount,bind,ro,nosuid,nodev,noexec', SYSTEM_CA])
        command(['mount', '-o', 'remount,ro', '/etc/ssl/certs'])
        arguments = decode(stable_read(root / 'agent-args.private.json', owner=10001, mode=0o600)[0])
        require(type(arguments) is list and all(type(s) is str for s in arguments), 'AGENT_ARGUMENTS')
        executable = [str(bundle / 'agent'), *arguments]
    elif role in ('api-first', 'api-second'):
        server_env = decode(stable_read(root / 'server-env.private.json', owner=10001, mode=0o600)[0])
        allowed = {'CHENGWANG_ADDR', 'CHENGWANG_DATA_DIR', 'CHENGWANG_IDENTITIES_FILE',
                   'CHENGWANG_TLS_CERT_FILE', 'CHENGWANG_TLS_KEY_FILE',
                   'CHENGWANG_MANAGEMENT_TENANT_ID', 'CHENGWANG_MANAGEMENT_SITE_ID',
                   'CHENGWANG_MANAGEMENT_OBJECT_ID', 'CHENGWANG_MODE', 'CHENGWANG_PROBE_READ_ENABLED',
                   'CHENGWANG_PROBE_CATALOG_FILE', 'CHENGWANG_PROBE_SPOOL_DIR',
                   'CHENGWANG_PROBE_POLL_INTERVAL', 'CHENGWANG_PROBE_CACHE_MAX_AGE'}
        require(type(server_env) is dict and set(server_env) == allowed
                and all(type(s) is str for s in server_env.values()), 'SERVER_ENVIRONMENT')
        environment.update(server_env)
        if web_dir is not None:
            mount_bind(pathlib.Path(web_dir), True)
            environment['CHENGWANG_WEB_DIR'] = str(web_dir)
        executable = [str(bundle / 'server')]
    elif role == 'wire':
        executable = [sys.executable, '-I', '-B', str(bundle / 'wire'), 'serve',
                      '--fixture-root', str(root), '--deadline-seconds', '360']
    else:
        environment.update({'CHENGWANG_PROBE_LAB_ROOT': str(root),
                            'CHENGWANG_PROBE_LAB_COMMIT': options.source_commit,
                            'CHENGWANG_PROBE_LAB_ACTION': options.action,
                            'CHENGWANG_PROBE_LAB_PHASE': options.phase})
        executable = [str(bundle / 'driver'), '-test.run=^TestProbeReadbackLabFixture$',
                      '-test.count=1', '-test.timeout=100s', '-test.v']
    for key, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 120),
                       (resource.RLIMIT_FSIZE, 32 << 20), (resource.RLIMIT_NOFILE, 256),
                       (resource.RLIMIT_NPROC, 256)):
        resource.setrlimit(key, (value, value))
    os.umask(0o077)
    prefix = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--bounding-set=-all',
              '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']
    os.execvpe('setpriv', prefix + executable, environment)


class Lab:
    def __init__(self, options):
        self.options = options
        self.root = pathlib.Path(options.fixture_root)
        self.bundle = pathlib.Path(options.bundle)
        self.jobs, self.records, self.exits, self.api_mounts = {}, [], [], []
        self.start_mono, self.started_ns = time.monotonic(), time.time_ns()
        self.agent_start = None
        self.agent_seconds = None
        self.phase_times = []
        self.private_logs = self.bundle / 'logs'

    def role_entrypoint(self):
        return self.bundle / 'runner'

    def after_prepared(self):
        """Optional isolated UI wrapper hook; the native backend is unchanged."""

    def after_restarted(self, minimum, maximum):
        """Called only after the original fresh/restarted timing is recorded."""

    def after_expired(self):
        """The original API-second stays alive until this optional hook joins."""

    def check_budget(self):
        require(time.monotonic() - self.start_mono < 360, 'LAB_DEADLINE')
        if 'agent' in self.jobs and self.agent_start is not None:
            require(time.monotonic() - self.agent_start < 150, 'AGENT_DEADLINE')

    def start(self, role, action='', phase=''):
        self.check_budget()
        log_path = self.private_logs / (role + '-' + action + '-' + phase + '.private')
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        argv = ['unshare', '--mount', sys.executable, '-I', '-B', str(self.role_entrypoint()),
                '--role', role, '--fixture-root', str(self.root), '--bundle', str(self.bundle),
                '--source-commit', self.options.source_commit, '--action', action, '--phase', phase]
        try:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=descriptor, stderr=descriptor,
                                 env=BASE_ENV, close_fds=True)
        finally:
            os.close(descriptor)
        self.jobs[role] = (p, None)
        if role == 'agent':
            self.agent_start = time.monotonic()
        if role == 'driver':
            return p
        if role == 'wire':
            with open('/proc/self/exe', 'rb') as source:
                wanted = sha(source.read(128 << 20))
        else:
            wanted = sha(stable_read(self.bundle / ('agent' if role == 'agent' else 'server'), 128 << 20)[0])
        deadline = time.monotonic() + 5
        while True:
            self.check_budget()
            require(p.poll() is None, 'PROCESS_STARTUP')
            try:
                record = task_profile(p.pid, wanted)
                break
            except (OSError, Failure):
                require(time.monotonic() < deadline, 'PROCESS_PROFILE_DEADLINE')
                time.sleep(0.02)
        record['role'] = role
        self.jobs[role] = (p, record)
        self.records.append(record)
        return p

    def driver(self, action, phase=''):
        global PHASE
        PHASE = ('DRIVER_' + action + '_' + phase).strip('_').upper().replace('-', '_')
        p = self.start('driver', action, phase)
        deadline = time.monotonic() + 100
        while p.poll() is None:
            self.check_budget()
            require(time.monotonic() < deadline, 'DRIVER_DEADLINE')
            time.sleep(0.02)
        require(p.returncode == 0, 'DRIVER_FAILED')
        del self.jobs['driver']

    def wait(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while True:
            self.check_budget()
            if predicate():
                return
            require(time.monotonic() < deadline, 'READINESS_DEADLINE')
            time.sleep(0.02)

    def stop(self, role):
        p, record = self.jobs[role]
        require(record is not None and p.poll() is None, 'PROCESS_NOT_RUNNING')
        pidfd = os.pidfd_open(p.pid)
        try:
            require(task_profile(p.pid, record['exeSHA256'])['startTime'] == record['startTime'], 'PROCESS_REUSED')
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            deadline = time.monotonic() + 12
            while p.poll() is None:
                self.check_budget()
                require(time.monotonic() < deadline, 'STOP_DEADLINE')
                time.sleep(0.02)
            require(p.returncode == 0, 'PROCESS_STOP_FAILED')
            self.exits.append({'role': role, 'pid': p.pid, 'startTime': record['startTime'],
                               'signal': 'SIGTERM', 'exitCode': 0, 'joined': True, 'forced': False})
            del self.jobs[role]
            if role == 'agent':
                self.agent_seconds = time.monotonic() - self.agent_start
                require(self.agent_seconds <= 150, 'AGENT_DEADLINE')
        finally:
            os.close(pidfd)

    def emergency(self):
        for role, (p, _record) in list(self.jobs.items()):
            if p.poll() is None:
                try:
                    fd = os.pidfd_open(p.pid)
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGTERM)
                    finally:
                        os.close(fd)
                    p.wait(timeout=12)
                except (OSError, subprocess.TimeoutExpired):
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=3)
            self.jobs.pop(role, None)

    def api_readonly(self, role):
        pid = self.jobs[role][0].pid
        mounts = []
        for label, name in (('catalog', 'catalog.json'), ('spool', 'spool'), ('ledger', 'ledger')):
            flags = mount_flags(pid, self.root / name)
            require('ro' in flags, 'API_SOURCE_WRITABLE')
            mounts.append({'label': label, 'readOnly': True, 'mountFlags': flags})
        self.api_mounts.append({'role': role, 'mounts': mounts})

    def run(self):
        global PHASE
        require(os.geteuid() == 0 and os.getpid() == 1, 'LAB_INIT_IDENTITY')
        command(['mount', '--make-rprivate', '/'])
        command(['mount', '-t', 'tmpfs', '-o', 'size=64m,mode=0700,uid=10001,gid=10001,nodev,nosuid,noexec',
                 'probe-readback-private', str(self.root)])
        mounted = True
        try:
            source_root = pathlib.Path(self.options.source_root)
            mount_bind(source_root, True)
            mount_bind(self.bundle, True)
            # Logs remain a separate root-only writable mount, never executable.
            mount_bind(self.private_logs, False)
            command(['ip', 'link', 'set', 'lo', 'up'])
            command(['ip', 'address', 'add', '8.8.4.4/32', 'dev', 'lo'])
            pathlib.Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').write_text('0\n')
            network = network_projection()
            self.driver('prepare')
            self.after_prepared()
            PHASE = 'WIRE_START'
            self.start('wire')
            self.wait(lambda: (self.root / 'wire/ready.json').is_file())
            ready = decode(stable_read(self.root / 'wire/ready.json', owner=10001, mode=0o600)[0])
            require(ready['pid'] == self.jobs['wire'][0].pid and ready['httpsPort'] == 443
                    and (self.root / 'wire/events.jsonl').stat().st_size == 0, 'WIRE_READY')
            self.start('agent')
            agent_pid = self.jobs['agent'][0].pid
            ca_raw, _ = stable_read(pathlib.Path('/proc', str(agent_pid), 'root') / SYSTEM_CA.lstrip('/'), 1 << 20)
            target_ca = stable_read(self.root / 'target-ca.pem', owner=10001, mode=0o600)[0]
            require(ca_raw == target_ca and set(os.listdir('/proc/' + str(agent_pid)
                    + '/root/etc/ssl/certs')) == {'ca-certificates.crt'}, 'AGENT_CA_BINDING')
            ca_flags = mount_flags(agent_pid, SYSTEM_CA)
            require('ro' in ca_flags, 'AGENT_CA_WRITABLE')
            self.driver('collect', 'first')
            self.driver('collect', 'final')
            PHASE = 'AGENT_STOP'
            self.stop('agent')
            minimum, maximum = expiry_bounds(self.root)
            before = state_metadata(self.root)
            report(self.options, 'source-metadata-before', 'source-metadata', phase='before', **before)
            PHASE = 'WIRE_STOP'
            self.stop('wire')
            wire_stop = decode(stable_read(self.root / 'wire/stopped.json', owner=10001, mode=0o600)[0])
            for role, phase in (('api-first', 'fresh'), ('api-second', 'restarted')):
                PHASE = 'API_START'
                self.start(role)
                self.api_readonly(role)
                self.wait(lambda: listening(self.jobs[role][0].pid, 17861))
                started = time.time_ns()
                self.driver('verify', phase)
                finished = time.time_ns()
                require(finished < minimum, 'FRESHNESS_WINDOW')
                self.phase_times.append({'name': phase, 'startedUnixNano': str(started),
                                         'finishedUnixNano': str(finished)})
                if role == 'api-first':
                    self.stop(role)
            self.after_restarted(minimum, maximum)
            PHASE = 'NATURAL_EXPIRY'
            while time.time_ns() < maximum + 100000000:
                self.check_budget()
                time.sleep(0.1)
            started = time.time_ns()
            self.driver('verify', 'expired')
            self.phase_times.append({'name': 'expired', 'startedUnixNano': str(started),
                                     'finishedUnixNano': str(time.time_ns())})
            self.after_expired()
            self.stop('api-second')
            after = state_metadata(self.root)
            require(before == after, 'SOURCE_MUTATED')
            report(self.options, 'source-metadata-after', 'source-metadata', phase='after', **after)
            for action in DRIVER_ACTIONS:
                copy_public(self.options, self.root / (PREFIX + action + '.json'), PREFIX + action + '.json')
            for phase in ('fresh', 'restarted', 'expired'):
                for kind in ('status', 'details'):
                    name = PREFIX + 'api-' + phase + '-' + kind + '.json'
                    copy_public(self.options, self.root / name, name)
            for name in ('ready.json', 'events.jsonl', 'stopped.json'):
                copy_public(self.options, self.root / 'wire' / name, PREFIX + 'wire-' + name)
            report(self.options, 'processes', 'processes', processes=self.records, exits=self.exits)
            self.check_budget()
            report(self.options, 'runtime', 'runtime', startedUnixNano=str(self.started_ns),
                   finishedUnixNano=str(time.time_ns()), minExpiryUnixNano=str(minimum),
                   maxExpiryUnixNano=str(maximum), phases=self.phase_times,
                   agentRunSeconds=self.agent_seconds, labRunSeconds=time.monotonic() - self.start_mono,
                   wireConnections=wire_stop['accepted'], wireEvents=wire_stop['events'],
                   sourceAssociation='UNIQUE_TARGET_AND_ATTEMPT_TIME_WINDOW')
            partial = {'lab': network, 'sourceMount': {'readOnly': True, 'mountFlags': mount_flags('self', source_root)},
                       'agentCA': {'targetPath': SYSTEM_CA, 'sha256': sha(target_ca), 'readOnly': True,
                                   'hostUnchanged': True}, 'apiReadOnlyMounts': self.api_mounts}
            exclusive(self.private_logs / 'isolation.private.json', canonical(partial), 0o600)
        finally:
            self.emergency()
            if mounted:
                command(['umount', str(self.root)])
            require(ROOT_RE.fullmatch(str(self.root)) and self.root.parent == pathlib.Path('/tmp'), 'CLEANUP_TARGET')
            self.root.rmdir()


def network_projection():
    interfaces = []
    for item in decode(command(['ip', '-j', 'address', 'show'])):
        interfaces.append({'name': item['ifname'], 'flags': sorted(item['flags']),
                           'addresses': sorted([{'family': a['family'], 'local': a['local'], 'prefixlen': a['prefixlen']}
                                                for a in item.get('addr_info', [])], key=lambda a: (a['family'], a['local']))})
    require(len(interfaces) == 1 and interfaces[0]['name'] == 'lo'
            and {'family': 'inet', 'local': '8.8.4.4', 'prefixlen': 32} in interfaces[0]['addresses'], 'NETWORK_INTERFACES')
    output = {'namespaces': ns(), 'interfaces': interfaces, 'portStart': int(pathlib.Path(
        '/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text())}
    require(output['portStart'] == 0, 'NAMESPACE_PORT_START')
    for family, key in (('-4', 'routes4'), ('-6', 'routes6')):
        routes = []
        for row in decode(command(['ip', family, '-j', 'route', 'show', 'table', 'all'])):
            record = {k: row.get(k, default) for k, default in (('type', 'unicast'), ('dst', 'default'),
                      ('dev', ''), ('table', 'main'), ('scope', 'global'), ('gateway', ''))}
            require(record['dst'] != 'default' and record['dev'] == 'lo' and not record['gateway'], 'NETWORK_ROUTE')
            routes.append(record)
        output[key] = sorted(routes, key=lambda r: canonical(r))
    return output


def listening(pid, port):
    # /proc/PID/net is namespace-wide, not an ownership witness. Intersect the
    # exact IPv4 loopback LISTEN inode with this live process's actual socket FDs.
    owners = set()
    for path in pathlib.Path('/proc', str(pid), 'fd').iterdir():
        try:
            match = re.fullmatch(r'socket:\[([0-9]+)\]', os.readlink(path))
        except FileNotFoundError:
            continue  # A concurrently closed FD is not a positive witness.
        if match:
            owners.add(match[1])
    for line in pathlib.Path('/proc', str(pid), 'net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if (fields[3] == '0A' and fields[1] == '0100007F:' + format(port, '04X')
                and fields[9] in owners):
            return True
    return False


def copy_public(options, source, name):
    require(name in EXPECTED, 'PUBLIC_NAME')
    raw, _ = stable_read(source, 4 << 20, 10001, 0o600)
    require(b'PRIVATE KEY' not in raw and b'Bearer ' not in raw, 'PUBLIC_SECRET')
    if source.suffix == '.json':
        decode(raw)
    exclusive(pathlib.Path(options.output_dir) / name, raw)


def prepare_bundle(options, source_root):
    bundle = pathlib.Path('/tmp/chengwang-probe-harness-' + options.fixture_id)
    # mkdir is outside the cleanup try: a pre-existing UUID path is never ours.
    bundle.mkdir(mode=0o750)
    os.chown(bundle, 0, 10001)
    try:
        (bundle / 'logs').mkdir(mode=0o700)
        tools = []
        for role, path in (('agent', options.agent), ('server', options.server), ('driver', options.driver),
                           ('runner', __file__), ('wire', source_root / 'chengwang/deploy/probe-readback/fixture_probe_wire.py')):
            raw, before = stable_read(path, 128 << 20)
            require(not before.st_mode & 0o022, 'TOOL_WRITABLE')
            exclusive(bundle / role, raw, 0o550)
            os.chown(bundle / role, 0, 10001)
            copied = stable_read(bundle / role, 128 << 20)[0]
            require(raw == copied, 'TOOL_COPY_CHANGED')
            tools.append({'role': role, 'inputSHA256': sha(raw), 'actualSHA256': sha(copied)})
        return bundle, tools
    except BaseException:
        cleanup_bundle(bundle)
        raise


def cleanup_bundle(bundle):
    require(TOOLS_RE.fullmatch(str(bundle)) and bundle.parent == pathlib.Path('/tmp')
            and not bundle.is_symlink(), 'TOOLS_CLEANUP_TARGET')
    info = bundle.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 10001
            and stat.S_IMODE(info.st_mode) == 0o750, 'TOOLS_CLEANUP_TARGET')
    shutil.rmtree(bundle)


def outer(options):
    global PHASE
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'LINUX_ROOT_REQUIRED')
    source_root = pathlib.Path(__file__).resolve().parents[3]
    output = checked_path(options.output_dir, True)
    require(not list(output.iterdir()), 'OUTPUT_NOT_EMPTY')
    options.fixture_id = uuid.uuid4().hex
    root = pathlib.Path('/tmp/chengwang-probe-readback-' + options.fixture_id)
    root.mkdir(mode=0o700)
    os.chown(root, 10001, 10001)
    bundle, supervisor = None, None
    try:
        PHASE = 'HOST_BEFORE'
        before, files_before = host_observation(source_root, options.source_commit)
        bundle, tools = prepare_bundle(options, source_root)
        argv = ['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGTERM', '--mount-proc',
                sys.executable, '-I', '-B', str(bundle / 'runner'), '--inner', '--fixture-root', str(root),
                '--bundle', str(bundle), '--source-root', str(source_root), '--fixture-id', options.fixture_id,
                '--source-commit', options.source_commit, '--output-dir', str(output)]
        PHASE = 'LAB_SUPERVISOR'
        log = os.open(bundle / 'supervisor.private', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            supervisor = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=BASE_ENV)
        finally:
            os.close(log)
        started = time.monotonic()
        while supervisor.poll() is None:
            require(time.monotonic() - started < 370, 'SUPERVISOR_DEADLINE')
            time.sleep(0.1)
        if supervisor.returncode != 0:
            observed = private_diagnostic(stable_read(bundle / 'supervisor.private', 65536)[0])
            if observed is not None:
                PHASE = observed[0]
                raise Failure(observed[1])
            raise Failure('LAB_FAILED')
        PHASE = 'HOST_AFTER'
        after, files_after = host_observation(source_root, options.source_commit)
        require(before == after and files_before == files_after and not root.exists(), 'HOST_CHANGED')
        isolation = decode(stable_read(bundle / 'logs/isolation.private.json')[0])
        report(options, 'isolation', 'isolation', hostBefore=before, hostAfter=after,
               sourceFilesBefore=files_before, sourceFilesAfter=files_after, tools=tools,
               pythonExecutable=sys.executable, **isolation)
        cleanup_bundle(bundle)
        bundle = None
        report(options, 'cleanup', 'cleanup', ownedProcessesJoined=4, exitCodes=[0] * 4, forcedKills=0,
               privateFixtureRemoved=True, privateToolsRemoved=True, hostNamespaceUnchanged=True,
               hostSysctlUnchanged=True, hostCAUnchanged=True, sourceUnchanged=True, outcome='PASS')
        require(set(p.name for p in output.iterdir()) == EXPECTED - {PREFIX + 'outcome.json'}, 'OUTPUT_SET')
        report(options, 'outcome', 'outcome', outcome='PASS', inputFileCount=21, processCount=4, agentResults=6)
        print('PROBE_READBACK_RUNNER=PASS acceptanceScope=NATIVE_BACKEND_ONLY browserE2EProven=false authorization=BLOCKED production=false')
        return 0
    finally:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.terminate()
            try:
                supervisor.wait(timeout=20)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait(timeout=5)
        if root.exists():
            require(ROOT_RE.fullmatch(str(root)) and root.parent == pathlib.Path('/tmp')
                    and not root.is_symlink(), 'OUTER_CLEANUP_TARGET')
            # The underlying host directory was empty before the tmpfs mount.
            # Never recursively delete it or an unresolved mountpoint.
            root.rmdir()
        if bundle is not None:
            cleanup_bundle(bundle)


def arguments(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, _message):
            raise Failure('ARGUMENTS')
    p = Parser(add_help=False)
    for flag in ('agent', 'server', 'driver', 'source-commit', 'output-dir', 'fixture-root',
                 'bundle', 'source-root', 'fixture-id', 'role', 'action', 'phase'):
        p.add_argument('--' + flag, default='')
    p.add_argument('--inner', action='store_true')
    options = p.parse_args(argv)
    require(COMMIT_RE.fullmatch(options.source_commit), 'COMMIT')
    if options.role:
        require(options.role in (*ROLES, 'driver'), 'ROLE')
    elif options.inner:
        require(ROOT_RE.fullmatch(options.fixture_root) and TOOLS_RE.fullmatch(options.bundle)
                and options.fixture_root.endswith(options.fixture_id), 'INNER_ARGUMENTS')
    else:
        require(all((options.agent, options.server, options.driver, options.output_dir)), 'ARGUMENTS')
        for path in (options.agent, options.server, options.driver):
            checked_path(path)
    return options


def main(argv=None):
    global PHASE
    options = None
    try:
        options = arguments(argv)
        if not sys.platform.startswith('linux'):
            raise Failure('LINUX_REQUIRED')
        if os.geteuid() != 0:
            require(not options.inner and not options.role, 'ROOT_REQUIRED')
            # No inherited CHENGWANG/proxy/SSL environment crosses privilege.
            os.execvpe('sudo', ['sudo', '-n', sys.executable, '-I', '-B', str(pathlib.Path(__file__).resolve()),
                               *(sys.argv[1:] if argv is None else argv)], BASE_ENV)

        def interrupted(_signum, _frame):
            raise Failure('SIGNAL')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        if options.role:
            configure_role(options)
        elif options.inner:
            Lab(options).run()
        else:
            return outer(options)
        return 0
    except Exception as error:
        # The only diagnostic is a closed code/phase, never str(raw exception)
        # or a regex-accepted, attacker-chosen class/identifier.
        phase, code = safe_failure(error, PHASE)
        sys.stderr.write('PROBE_READBACK_RUNNER=FAIL phase=' + phase + ' code=' + code + ' raw_input_suppressed=true\n')
        if options is not None and not options.inner and not options.role and options.output_dir:
            try:
                report(options, 'failure', 'failure', phase=phase, code=code, outcome='FAIL')
            except Exception:
                pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
