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
import time

SCHEMA = 'chengwang.ci-ui-dependencies/v1'
SCOPE = 'TRUSTED_CI_DEPENDENCY_READBACK_NOT_REPRODUCIBLE_PACKAGE_PROVENANCE'
PACKAGES = ['libnss3-tools', 'fonts-noto-cjk']
FONTS = [('Regular', '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc'),
         ('Bold', '/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc')]
LOG_NAMES = ['ci-dependency-update.log', 'ci-dependency-install.log', 'ci-dependency-readback.log']
MAX_LOG = 4194304
MAX_FONT = 67108864
INPUTS = ['chengwang/deploy/subscription-ui-browser/prepare_ci_dependencies.py',
          'chengwang/deploy/subscription-ui-browser/ci-dependencies-contract.json']


def need(value):
    if not value:
        raise ValueError('CI dependency input or readback rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def phase_argv(stage):
    need(stage in ('UPDATE', 'INSTALL'))
    argv = ['/usr/bin/sudo', '--non-interactive', '/usr/bin/timeout', '--signal=TERM',
            '--kill-after=15s', '120s' if stage == 'UPDATE' else '240s', '/usr/bin/env',
            'DEBIAN_FRONTEND=noninteractive', 'LC_ALL=C', '/usr/bin/apt-get']
    for option in ('Acquire::Retries=1', 'Acquire::http::Timeout=15', 'Acquire::https::Timeout=15'):
        argv += ['-o', option]
    return argv + (['-o', 'APT::Update::Error-Mode=any', 'update'] if stage == 'UPDATE'
                   else ['install', '-y', '--no-install-recommends', *PACKAGES])


def read_file(path, maximum, system_owned=False, executable=False, empty_allowed=False):
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
                remaining = MAX_LOG - len(output)
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
                  commands=[dict(stage=stage, argv=phase_argv(stage), executed=False, exitCode=None,
                                 timedOut=False, elapsedMilliseconds=None) for stage in ('UPDATE', 'INSTALL')],
                  logs=[], sourcesBefore=[], sourcesAfter=None, sourceConfigurationModified=None,
                  packages=[], certutil=None, fonts=[], readbackComplete=False, sourceInputs=[],
                  production=False, authorization='BLOCKED')
    log_bytes = [bytearray(), bytearray(), bytearray()]
    truncated = [False, False, False]

    def log(index, raw, overflow=False):
        remaining = MAX_LOG - len(log_bytes[index])
        log_bytes[index].extend(raw[:remaining])
        truncated[index] |= overflow or len(raw) > remaining
        need(not truncated[index])

    def readback(argv):
        code, raw, timeout, _, overflow = execute(argv, 5)
        log(2, raw, overflow)
        need(code == 0 and not timeout)
        return raw

    try:
        for path in targets[:3]:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            handles.append(os.fdopen(descriptor, 'wb'))
        report['platform'] = platform_readback()
        need(report['platform'] == dict(githubActions=True, runnerOS='Linux', system='Linux', ubuntu='24.04', architecture='amd64'))
        report['failureStage'] = 'SOURCES'
        report['sourceInputs'] = source_inputs()
        report['sourcesBefore'] = sources_snapshot()
        for index, row in enumerate(report['commands']):
            report['failureStage'] = row['stage']
            # Records an invocation attempt, not an OS execution attestation.
            # An unexpected collector error must not relabel it as unattempted.
            row['executed'] = True
            code, raw, timeout, elapsed, overflow = execute(row['argv'], (120 if index == 0 else 240) + 20)
            row.update(exitCode=code, timedOut=timeout, elapsedMilliseconds=elapsed)
            log(index, raw, overflow)
            need(code == 0 and not timeout)
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
    except Exception:
        pass  # No raw exception, environment, proxy or source contents are exported.
    finally:
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
    need(len(report['logs']) == 3)
    descriptor = os.open(targets[3], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
