"""Bounded CI-only dependency acquisition; importing this module executes nothing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import subprocess
import tempfile
import time

SCHEMA = 'chengwang.ci-ui-dependencies/v2'
SCOPE = 'TRUSTED_CI_DEPENDENCY_READBACK_NOT_REPRODUCIBLE_PACKAGE_PROVENANCE'
PACKAGES = ['libnss3-tools', 'fonts-noto-cjk']
FONTS = [('Regular', '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc'),
         ('Bold', '/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc')]
LOG_NAMES = ['ci-dependency-update.log', 'ci-dependency-install.log', 'ci-dependency-readback.log',
             'ci-dependency-toolchain.log']
MAX_LOG = 4194304
MAX_FONT = 67108864
MAX_TOOLCHAIN = 16384
HOST_SOURCE = '/etc/apt/sources.list.d/ubuntu.sources'
HOST_SOURCE_SIZE = 2995
HOST_SOURCE_SHA = '4508181e0dd5578c33d1247db48ab4847910b25da85e0789c8e7b3140d1fb289'
HOST_MIRROR = '/etc/apt/apt-mirrors.txt'
HOST_MIRROR_URI = 'mirror+file:' + HOST_MIRROR
HOST_MIRROR_SIZE = 144
HOST_MIRROR_SHA = 'e0d6b0af979e4662d16357a27ae456cc6f21e26da031540f4df8706ebed1d583'
KEYRING = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
DIRECTORY_PATTERN = r'/tmp/chengwang-ci-apt-[a-z0-9_]{8}'
MIRRORS = ['https://archive.ubuntu.com/ubuntu/', 'https://security.ubuntu.com/ubuntu/',
           'http://azure.archive.ubuntu.com/ubuntu/']
SECURITY_OPTIONS = ['APT::Get::AllowUnauthenticated=false', 'Acquire::AllowInsecureRepositories=false',
                    'Acquire::AllowDowngradeToInsecureRepositories=false', 'Acquire::Check-Date=true',
                    'Acquire::Check-Valid-Until=true', 'Acquire::https::Verify-Peer=true',
                    'Acquire::https::Verify-Host=true', 'Acquire::https::archive.ubuntu.com::Verify-Peer=true',
                    'Acquire::https::archive.ubuntu.com::Verify-Host=true',
                    'Acquire::https::security.ubuntu.com::Verify-Peer=true',
                    'Acquire::https::security.ubuntu.com::Verify-Host=true',
                    'Acquire::https::azure.archive.ubuntu.com::Verify-Peer=true',
                    'Acquire::https::azure.archive.ubuntu.com::Verify-Host=true']
INPUTS = ['chengwang/deploy/subscription-ui-browser/prepare_ci_dependencies.py',
          'chengwang/deploy/subscription-ui-browser/ci-dependencies-contract.json']
PRIVATE_REASONS = frozenset(('FORMAT', 'STRUCTURE', 'TYPES', 'URIS', 'SIGNED_BY', 'COMPONENTS',
    'ARCHITECTURES', 'SUITES', 'SUITE_COVERAGE', 'HOST_SOURCE_READ', 'HOST_SOURCE_DIGEST',
    'HOST_MIRROR_READ', 'HOST_MIRROR_DIGEST', 'KEYRING_READ', 'KEYRING_PERMISSION',
    'DIRECTORY', 'FILES', 'READBACK', 'KEYRING_STAT', 'KEYRING_SYMLINK', 'KEYRING_TYPE',
    'KEYRING_LINK_COUNT', 'KEYRING_SIZE', 'KEYRING_OWNER', 'KEYRING_MODE', 'KEYRING_OPEN',
    'KEYRING_FD_STAT', 'KEYRING_FINAL_STAT', 'KEYRING_STABILITY', 'KEYRING_LENGTH'))


class PrivateSourceRejected(ValueError):
    def __init__(self, reason):
        if type(reason) is not str or reason not in PRIVATE_REASONS:
            raise ValueError('private source diagnostic code rejected')
        self.reason = reason
        super().__init__('private source rejected')


def private_need(value, reason):
    if not value:
        raise PrivateSourceRejected(reason)


def private_operation(reason, operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except PrivateSourceRejected:
        raise
    except Exception:
        raise PrivateSourceRejected(reason) from None


def private_failure_stage(error):
    # Even a mutated exception object cannot export an arbitrary diagnostic.
    reason = error.reason
    return 'PRIVATE_' + reason if type(reason) is str and reason in PRIVATE_REASONS else 'PRIVATE_SOURCES'


def need(value):
    if not value:
        raise ValueError('CI dependency input or readback rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def apt_options(private_directory):
    need(type(private_directory) is str and re.fullmatch(DIRECTORY_PATTERN, private_directory))
    argv = []
    for option in ('Acquire::Retries=1', 'Acquire::http::Timeout=15', 'Acquire::https::Timeout=15'):
        argv += ['-o', option]
    for option in ['Dir::Etc::sourcelist=' + private_directory + '/ubuntu.sources',
                   'Dir::Etc::sourceparts=' + private_directory + '/sourceparts', *SECURITY_OPTIONS]:
        argv += ['-o', option]
    return argv


def phase_argv(stage, private_directory):
    need(stage in ('UPDATE', 'INSTALL'))
    argv = ['/usr/bin/sudo', '--non-interactive', '/usr/bin/timeout', '--signal=TERM',
            '--kill-after=15s', '120s' if stage == 'UPDATE' else '240s', '/usr/bin/env',
            '-u', 'APT_CONFIG', 'DEBIAN_FRONTEND=noninteractive', 'LC_ALL=C', '/usr/bin/apt-get']
    argv += apt_options(private_directory)
    return argv + (['-o', 'APT::Update::Error-Mode=any', 'update'] if stage == 'UPDATE'
                   else ['install', '-y', '--no-install-recommends', *PACKAGES])


def policy_argv(private_directory):
    return ['/usr/bin/sudo', '--non-interactive', '/usr/bin/env', '-u', 'APT_CONFIG',
            'DEBIAN_FRONTEND=noninteractive', 'LC_ALL=C', '/usr/bin/apt-config',
            *apt_options(private_directory), '-o', 'APT::Config::Dump::EmptyValue=false',
            'dump', 'APT::Sources::With', 'Binary::apt-get::APT::Sources::With']


def parse_apt_version(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_TOOLCHAIN)
    text = raw.decode('ascii')
    match = re.match(r'apt ([0-9][A-Za-z0-9.+:~_-]{0,127}) \(amd64\)\n', text)
    need(match is not None)
    return dict(version=match[1], architecture='amd64')


def parse_ubuntu_sources(raw):
    """Accept only the frozen host deb822 policy; never guess continuations."""
    text = private_operation('FORMAT', raw.decode, 'ascii')
    stanzas, current = [], {}
    allowed = {'Types', 'URIs', 'Suites', 'Components', 'Signed-By', 'Architectures'}
    for line in [*text.split('\n'), '']:
        private_need('\r' not in line, 'FORMAT')
        if line.lstrip().startswith('#'):
            continue
        if not line.strip():
            if current:
                stanzas.append(current)
                current = {}
            continue
        private_need(not line[0].isspace() and ':' in line, 'FORMAT')
        key, value = line.split(':', 1)
        private_need(key in allowed and key not in current and value.startswith(' ') and value.strip(), 'FORMAT')
        current[key] = value.strip().split()
    private_need(stanzas and len(stanzas) <= 16, 'STRUCTURE')
    suites = []
    for stanza in stanzas:
        private_need(set(stanza) in ({'Types', 'URIs', 'Suites', 'Components', 'Signed-By'}, allowed), 'STRUCTURE')
        private_need(stanza['Types'] == ['deb'], 'TYPES')
        private_need(stanza['URIs'] == [HOST_MIRROR_URI], 'URIS')
        private_need(stanza['Signed-By'] == [KEYRING], 'SIGNED_BY')
        private_need(len(stanza['Components']) == len(set(stanza['Components'])) == 4
                     and set(stanza['Components']) == {'main', 'restricted', 'universe', 'multiverse'}, 'COMPONENTS')
        private_need('Architectures' not in stanza or stanza['Architectures'] == ['amd64'], 'ARCHITECTURES')
        values = stanza['Suites']
        private_need(values and len(values) == len(set(values))
                     and set(values) <= {'noble', 'noble-updates', 'noble-backports', 'noble-security'}, 'SUITES')
        suites += values
    private_need(set(suites) == {'noble', 'noble-updates', 'noble-backports', 'noble-security'}, 'SUITE_COVERAGE')
    return len(stanzas)


def mirror_bytes():
    return ''.join(uri + '\tpriority:' + str(index) + '\n'
                   for index, uri in enumerate(MIRRORS, 1)).encode('ascii')


def directory_metadata(path, owner=None, empty=False):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISDIR(before.st_mode) and not path.is_symlink() and stat.S_IMODE(before.st_mode) == 0o755)
    if owner is not None:
        need((before.st_uid, before.st_gid) == owner)
    if empty:
        need(not list(path.iterdir()))
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns')
    need(all(getattr(before, field) == getattr(after, field) for field in fields))
    return dict(path=str(path), uid=before.st_uid, gid=before.st_gid, mode=stat.S_IMODE(before.st_mode))


def make_private_directory():
    need(platform.system() == 'Linux')
    directory = Path(tempfile.mkdtemp(prefix='chengwang-ci-apt-', dir='/tmp'))
    need(re.fullmatch(DIRECTORY_PATTERN, str(directory)) and directory.resolve(strict=True) == directory)
    directory.chmod(0o755)
    directory_metadata(directory, (os.geteuid(), os.getegid()))
    return directory


def private_files(directory, host_source):
    """Only a newly allocated directory is passed here by the real producer."""
    directory = Path(directory)
    parse_ubuntu_sources(host_source)
    old = HOST_MIRROR_URI.encode('ascii')
    replacement = ('mirror+file:' + str(directory / 'mirrors.txt')).encode('ascii')
    count = host_source.count(old)
    need(1 <= count <= 16)
    content = host_source.replace(old, replacement)
    for name, raw in [('ubuntu.sources', content), ('mirrors.txt', mirror_bytes())]:
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
        (directory / name).chmod(0o644)
    parts = directory / 'sourceparts'
    parts.mkdir(mode=0o755)
    parts.chmod(0o755)
    return count


def private_readback(directory):
    directory = Path(directory)
    need(re.fullmatch(DIRECTORY_PATTERN, str(directory)))
    parent = directory_metadata(directory)
    owner = (parent['uid'], parent['gid'])
    raw, source = read_file(directory / 'ubuntu.sources', 32768)
    mirrors_raw, mirrors = read_file(directory / 'mirrors.txt', 4096)
    for row in (source, mirrors):
        need((row['uid'], row['gid']) == owner and row['mode'] == 0o644)
    replacement = ('mirror+file:' + str(directory / 'mirrors.txt')).encode('ascii')
    count = raw.count(replacement)
    normalized = raw.replace(replacement, HOST_MIRROR_URI.encode('ascii'))
    need(1 <= count <= 16 and len(normalized) == HOST_SOURCE_SIZE and sha(normalized) == HOST_SOURCE_SHA
         and mirrors_raw == mirror_bytes())
    parse_ubuntu_sources(normalized)
    source.update(normalizedHostSHA256=sha(normalized), replacedURIs=count)
    parts = directory_metadata(directory / 'sourceparts', owner, empty=True)
    parts['empty'] = True
    _, keyring = read_file(KEYRING, 2 << 20, system_owned=True, diagnostic='KEYRING')
    private_need(keyring['mode'] & 0o004, 'KEYRING_PERMISSION')
    return dict(directory=parent, source=source, mirrors=mirrors, parts=parts,
                keyring=keyring, effectiveConfigurationChanged=True)


def create_private_sources():
    source, _ = private_operation('HOST_SOURCE_READ', read_file, HOST_SOURCE, HOST_SOURCE_SIZE, system_owned=True)
    private_need(len(source) == HOST_SOURCE_SIZE and sha(source) == HOST_SOURCE_SHA, 'HOST_SOURCE_DIGEST')
    mirrors, _ = private_operation('HOST_MIRROR_READ', read_file, HOST_MIRROR, HOST_MIRROR_SIZE, system_owned=True)
    private_need(len(mirrors) == HOST_MIRROR_SIZE and sha(mirrors) == HOST_MIRROR_SHA, 'HOST_MIRROR_DIGEST')
    parse_ubuntu_sources(source)
    _, keyring = private_operation('KEYRING_READ', read_file, KEYRING, 2 << 20,
                                  system_owned=True, diagnostic='KEYRING')
    private_need(keyring['mode'] & 0o004, 'KEYRING_PERMISSION')
    directory = private_operation('DIRECTORY', make_private_directory)
    private_operation('FILES', private_files, directory, source)
    return private_operation('READBACK', private_readback, directory)


def read_keyring_file(path, maximum, executable, empty_allowed):
    """Same fail-closed reader, with only closed, non-secret keyring diagnoses."""
    before = private_operation('KEYRING_STAT', path.lstat)
    private_need(not stat.S_ISLNK(before.st_mode), 'KEYRING_SYMLINK')
    private_need(stat.S_ISREG(before.st_mode), 'KEYRING_TYPE')
    private_need(before.st_nlink == 1, 'KEYRING_LINK_COUNT')
    private_need((0 if empty_allowed else 1) <= before.st_size <= maximum, 'KEYRING_SIZE')
    private_need(before.st_uid == before.st_gid == 0, 'KEYRING_OWNER')
    private_need(not stat.S_IMODE(before.st_mode) & 0o022, 'KEYRING_MODE')
    if executable:
        private_need(stat.S_IMODE(before.st_mode) & 0o001
                     and stat.S_IMODE(before.st_mode) & 0o004, 'KEYRING_MODE')
    descriptor = private_operation('KEYRING_OPEN', os.open, path,
        os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        stream = private_operation('KEYRING_OPEN', os.fdopen, descriptor, 'rb')
    except PrivateSourceRejected:
        # fdopen did not take ownership. Cleanup errors must not mask diagnosis.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    with stream:
        opened = private_operation('KEYRING_FD_STAT', os.fstat, stream.fileno())
        raw = private_operation('KEYRING_READ', stream.read, maximum + 1)
        after = private_operation('KEYRING_FD_STAT', os.fstat, stream.fileno())
    final = private_operation('KEYRING_FINAL_STAT', path.lstat)
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_uid', 'st_gid')
    private_need(all(getattr(before, field) == getattr(opened, field)
                     == getattr(after, field) == getattr(final, field) for field in fields), 'KEYRING_STABILITY')
    private_need(len(raw) == before.st_size, 'KEYRING_LENGTH')
    return raw, dict(path=str(path), bytes=len(raw), sha256=sha(raw), uid=before.st_uid,
                    gid=before.st_gid, mode=stat.S_IMODE(before.st_mode))


def read_file(path, maximum, system_owned=False, executable=False, empty_allowed=False, *, diagnostic=None):
    if diagnostic is not None:
        need(diagnostic == 'KEYRING' and Path(path) == Path(KEYRING) and system_owned is True)
        return read_keyring_file(Path(path), maximum, executable, empty_allowed)
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink() and before.st_nlink == 1
         and (0 if empty_allowed else 1) <= before.st_size <= maximum)
    if system_owned:
        need(before.st_uid == before.st_gid == 0 and not stat.S_IMODE(before.st_mode) & 0o022)
    if executable:
        need(stat.S_IMODE(before.st_mode) & 0o001 and stat.S_IMODE(before.st_mode) & 0o004)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns')
    need(len(raw) == before.st_size and all(getattr(before, field) == getattr(opened, field)
         == getattr(after, field) == getattr(final, field) for field in fields))
    return raw, dict(path=str(path), bytes=len(raw), sha256=sha(raw), uid=before.st_uid,
                     gid=before.st_gid, mode=stat.S_IMODE(before.st_mode))


def source_inputs():
    root = Path(__file__).resolve().parents[3]
    rows = []
    for relative in INPUTS:
        raw, _ = read_file(root / relative, 2 << 20)
        rows.append(dict(path=relative, bytes=len(raw), sha256=sha(raw)))
    return rows


def sources_snapshot():
    paths = [Path('/etc/apt') / name for name in
             ('sources.list', 'apt-mirrors.txt', 'apt-mirrors-security.txt', 'apt.conf')]
    for directory in ('sources.list.d', 'apt.conf.d'):
        parent = Path('/etc/apt') / directory
        if parent.exists():
            need(parent.is_dir() and not parent.is_symlink())
            paths += sorted(child for child in parent.iterdir() if not child.is_dir())
    rows = []
    for path in sorted(set(paths)):
        if path.exists() or path.is_symlink():
            raw, _ = read_file(path, 1 << 20, system_owned=True, empty_allowed=True)
            rows.append(dict(path=str(path), bytes=len(raw), sha256=sha(raw)))
    need(rows and len(rows) <= 128)
    return rows


def platform_readback():
    release = {}
    for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = value.strip('"')
    return dict(githubActions=os.environ.get('GITHUB_ACTIONS') == 'true',
                runnerOS='Linux' if os.environ.get('RUNNER_OS') == 'Linux' else 'OTHER',
                system='Linux' if platform.system() == 'Linux' else 'OTHER',
                ubuntu='24.04' if release.get('ID') == 'ubuntu' and release.get('VERSION_ID') == '24.04' else 'OTHER',
                architecture='amd64' if platform.machine() == 'x86_64' else 'OTHER')


def invoke(argv, timeout_seconds):
    """Drain stdout with bounded retained bytes; never install/retry on overflow."""
    start = time.monotonic()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=0)
    output = bytearray()
    maximum = 4096 if '/usr/bin/apt-config' in argv else MAX_TOOLCHAIN if argv == ['/usr/bin/apt-get', '--version'] else MAX_LOG
    truncated = timed_out = False
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        # A child can close stdout before exiting. EOF is not process completion.
        while selector.get_map() or process.poll() is None:
            if time.monotonic() - start >= timeout_seconds:
                timed_out = True
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                break
            if not selector.get_map():
                time.sleep(0.01)
                continue
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                remaining = maximum - len(output)
                output.extend(chunk[:remaining])
                truncated |= len(chunk) > remaining
    process.stdout.close()
    code = process.wait(timeout=2)
    return code, bytes(output), timed_out or code in (124, 137), max(0, int((time.monotonic() - start) * 1000)), truncated


def parse_packages(raw):
    rows = {}
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t')
        need(len(fields) == 3)
        name, status_text, version = fields
        if name == 'libnss3-tools:amd64':
            name = 'libnss3-tools'
        need(name in PACKAGES and name not in rows and status_text == 'install ok installed'
             and re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', version))
        rows[name] = dict(name=name, status=status_text, version=version)
    need(set(rows) == set(PACKAGES))
    return [rows[name] for name in PACKAGES]


def checked_font(raw, style, path):
    need(raw == ('Noto Sans CJK SC\t' + style + '\t' + path + '\n').encode('ascii'))


def prepare(reports, commit, *, execute=invoke):
    reports = Path(reports)
    need(re.fullmatch('[a-f0-9]{40}', commit) and reports.is_absolute()
         and reports.resolve(strict=True) == reports and not reports.is_symlink())
    info = reports.stat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
    if hasattr(os, 'geteuid'):
        need(info.st_uid == os.geteuid())
    targets = [reports / name for name in [*LOG_NAMES, 'ci-dependencies.json']]
    need(all(not path.exists() and not path.is_symlink() for path in targets))
    handles = []
    report = dict(schema=SCHEMA, scope=SCOPE, sourceCommit=commit, outcome='FAIL', failureStage='PLATFORM',
                  platform=dict(githubActions=False, runnerOS='OTHER', system='OTHER', ubuntu='OTHER', architecture='OTHER'),
                  commands=[dict(stage=stage, argv=[], executed=False, exitCode=None,
                                 timedOut=False, elapsedMilliseconds=None) for stage in ('UPDATE', 'INSTALL')],
                  logs=[], sourcesBefore=[], sourcesAfter=None, sourceConfigurationModified=None,
                  packages=[], certutil=None, fonts=[], readbackComplete=False, sourceInputs=[],
                  production=False, authorization='BLOCKED', aptVersion=None, privateSources=None)
    log_bytes = [bytearray() for _ in LOG_NAMES]
    truncated = [False for _ in LOG_NAMES]

    def log(index, raw, overflow=False):
        maximum = MAX_TOOLCHAIN if index == 3 else MAX_LOG
        remaining = maximum - len(log_bytes[index])
        log_bytes[index].extend(raw[:remaining])
        truncated[index] |= overflow or len(raw) > remaining
        need(not truncated[index])

    def readback(argv):
        code, raw, timeout, _, overflow = execute(argv, 5)
        log(2, raw, overflow)
        need(code == 0 and not timeout)
        return raw

    try:
        for path in targets[:len(LOG_NAMES)]:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            handles.append(os.fdopen(descriptor, 'wb'))
        report['platform'] = platform_readback()
        need(report['platform'] == dict(githubActions=True, runnerOS='Linux', system='Linux', ubuntu='24.04', architecture='amd64'))
        report['failureStage'] = 'SOURCES'
        report['sourceInputs'] = source_inputs()
        report['sourcesBefore'] = sources_snapshot()
        report['failureStage'] = 'APT_VERSION'
        code, raw, timeout, _, overflow = execute(['/usr/bin/apt-get', '--version'], 5)
        log(3, raw, overflow)
        need(code == 0 and not timeout)
        report['aptVersion'] = parse_apt_version(raw)
        report['failureStage'] = 'PRIVATE_SOURCES'
        report['privateSources'] = create_private_sources()
        private_directory = report['privateSources']['directory']['path']
        need(private_readback(private_directory) == report['privateSources'])
        report['failureStage'] = 'APT_POLICY'
        probe = dict(argv=policy_argv(private_directory), exitCode=None, timedOut=False,
                     elapsedMilliseconds=None, emptyOutput=False)
        report['privateSources']['extraSourcesProbe'] = probe
        code, raw, timeout, elapsed, overflow = execute(probe['argv'], 5)
        # This output can name private paths. Never put it in any public log.
        probe.update(exitCode=code, timedOut=timeout, elapsedMilliseconds=elapsed,
                     emptyOutput=raw == b'' and not overflow)
        need(code == 0 and not timeout and not overflow and len(raw) <= 4096 and raw == b''
             and type(elapsed) is int and 0 <= elapsed <= 5000)
        for row in report['commands']:
            row['argv'] = phase_argv(row['stage'], private_directory)
        for index, row in enumerate(report['commands']):
            report['failureStage'] = row['stage']
            # Records an invocation attempt, not an OS execution attestation.
            # An unexpected collector error must not relabel it as unattempted.
            row['executed'] = True
            code, raw, timeout, elapsed, overflow = execute(row['argv'], (120 if index == 0 else 240) + 20)
            row.update(exitCode=code, timedOut=timeout, elapsedMilliseconds=elapsed)
            log(index, raw, overflow)
            need(code == 0 and not timeout)
        report['failureStage'] = 'PRIVATE_SOURCES_AFTER'
        need(private_readback(private_directory) == {key: value for key, value in report['privateSources'].items()
                                                     if key != 'extraSourcesProbe'})
        report['failureStage'] = 'PACKAGES'
        report['packages'] = parse_packages(readback(['/usr/bin/dpkg-query', '-W',
            '-f=${binary:Package}\t${Status}\t${Version}\n', *PACKAGES]))
        report['failureStage'] = 'CERTUTIL'
        _, report['certutil'] = read_file('/usr/bin/certutil', 16 << 20, system_owned=True, executable=True)
        for style, path in FONTS:
            report['failureStage'] = 'FONT_' + style.upper()
            raw = readback(['/usr/bin/fc-match', '-f', '%{family}\t%{style}\t%{file}\n',
                            'Noto Sans CJK SC:style=' + style + ':lang=zh-cn'])
            checked_font(raw, style, path)
            _, metadata = read_file(path, MAX_FONT, system_owned=True)
            need(metadata['mode'] & 0o004)
            report['failureStage'] = 'OWNER_' + style.upper()
            need(readback(['/usr/bin/dpkg-query', '-S', path]) == ('fonts-noto-cjk: ' + path + '\n').encode('ascii'))
            report['fonts'].append(dict(**metadata, family='Noto Sans CJK SC', style=style, ownerPackage='fonts-noto-cjk'))
        report['readbackComplete'] = True
        report['failureStage'] = 'SOURCES_AFTER'
        report['sourcesAfter'] = sources_snapshot()
        report['sourceConfigurationModified'] = report['sourcesAfter'] != report['sourcesBefore']
        need(not report['sourceConfigurationModified'])
        report.update(outcome='PASS', failureStage='NONE')
    except PrivateSourceRejected as error:
        report['failureStage'] = private_failure_stage(error)
    except Exception:
        pass  # No raw exception, environment, proxy or source contents are exported.
    finally:
        if report['privateSources'] is not None and report['outcome'] != 'PASS':
            try:
                need(private_readback(report['privateSources']['directory']['path']) ==
                     {key: value for key, value in report['privateSources'].items() if key != 'extraSourcesProbe'})
            except PrivateSourceRejected as error:
                report['failureStage'] = private_failure_stage(error)
            except Exception:
                if report['failureStage'] not in {'PRIVATE_' + reason for reason in PRIVATE_REASONS}:
                    report['failureStage'] = 'PRIVATE_SOURCES_AFTER'
        if report['sourcesBefore'] and report['sourcesAfter'] is None:
            try:
                report['sourcesAfter'] = sources_snapshot()
                report['sourceConfigurationModified'] = report['sourcesAfter'] != report['sourcesBefore']
            except Exception:
                pass
        for index, handle in enumerate(handles):
            raw = bytes(log_bytes[index])
            handle.write(raw)
            handle.close()
            report['logs'].append(dict(path=LOG_NAMES[index], bytes=len(raw), sha256=sha(raw), truncated=truncated[index]))
    need(len(report['logs']) == len(LOG_NAMES))
    descriptor = os.open(targets[len(LOG_NAMES)], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write((json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reports', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    report = prepare(args.reports, args.source_commit)
    print('CI_UI_DEPENDENCIES=' + report['outcome'] + ' production=false provenance_proven=false')
    return 0 if report['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('CI_UI_DEPENDENCIES=FAIL raw_input_suppressed=true') from None
