"""Verify bounded CI dependency readback; never execute apt or product code.

Installed/font facts are trusted producer projections, not independent local
font-byte verification, a package signature attestation, or browser acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

BASE = 'chengwang/deploy/subscription-ui-browser/'
HELPER = BASE + 'prepare_ci_dependencies.py'
CONTRACT = BASE + 'ci-dependencies-contract.json'
CHECKER = BASE + 'check_ci_dependencies.py'
SOURCE_PATHS = {HELPER, CONTRACT}
SCOPE = 'TRUSTED_CI_DEPENDENCY_READBACK_NOT_REPRODUCIBLE_PACKAGE_PROVENANCE'
MAX_LOG_BYTES = 4 << 20
LOG_NAMES = ('ci-dependency-update.log', 'ci-dependency-install.log', 'ci-dependency-readback.log')
FONTS = [dict(style='Regular', path='/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc'),
         dict(style='Bold', path='/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc')]
PACKAGES = ['libnss3-tools', 'fonts-noto-cjk']
FROZEN_CONTRACT = dict(schema='chengwang.ci-ui-dependencies-contract/v1', scope=SCOPE,
    reportSchema='chengwang.ci-ui-dependencies/v1', reportFile='ci-dependencies.json',
    platform=dict(system='Linux', runner='Linux', ubuntu='24.04', architecture='amd64'),
    packages=PACKAGES, acquireOptions=['Acquire::Retries=1', 'Acquire::http::Timeout=15', 'Acquire::https::Timeout=15'],
    updateStrictOption='APT::Update::Error-Mode=any', updateTimeoutSeconds=120, installTimeoutSeconds=240,
    killAfterSeconds=15, readbackCommandTimeoutSeconds=5, updateInvocations=1, installInvocations=1,
    sourceConfigurationModified=False, fontFamily='Noto Sans CJK SC', fonts=FONTS,
    certutilPath='/usr/bin/certutil', maxLogBytes=MAX_LOG_BYTES, maxFontBytes=64 << 20, production=False)


class Rejected(ValueError):
    def __init__(self): super().__init__('CI dependency evidence rejected')


def need(value):
    if not value: raise Rejected()


def exact(value, fields): need(type(value) is dict and set(value) == set(fields))
def integer(value, low=0, high=9007199254740991): need(type(value) is int and low <= value <= high)
def digest(value): need(type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value))
def sha(raw): return hashlib.sha256(raw).hexdigest()
def same(left, right): return json.dumps(left, sort_keys=True, separators=(',', ':')) == json.dumps(right, sort_keys=True, separators=(',', ':'))


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out); out[key] = value
    return out


def decoded(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536)
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Rejected()))
    except (ValueError, UnicodeError, RecursionError): raise Rejected() from None
    def bounded(item, depth=0):
        need(depth <= 12)
        if type(item) is dict:
            need(len(item) <= 128)
            for key, child in item.items():
                need(type(key) is str and key.isascii() and len(key) <= 128); bounded(child, depth + 1)
        elif type(item) is list:
            need(len(item) <= 128)
            for child in item: bounded(child, depth + 1)
        elif type(item) is str: need(item.isascii() and len(item) <= 4096)
        else: need(item is None or type(item) in (int, bool))
    bounded(value)
    return value


def read(path, maximum):
    """No links, hard links, devices, growth, replacement or partial reads."""
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno()); raw = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    named = path.lstat()
    # On Windows, path stat and descriptor fstat expose different ctime meanings
    # (CPython issue 157671). Keep each API's ctime stable, not interchangeable.
    common = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns')
    own = (*common, 'st_ctime_ns')
    need(len(raw) == before.st_size
         and all(getattr(before, k) == getattr(named, k) for k in own)
         and all(getattr(opened, k) == getattr(after, k) for k in own)
         and all(getattr(before, k) == getattr(opened, k) for k in common))
    return raw


def write_report(path, evidence, repo, value):
    path = path.absolute()
    need(not path.is_symlink() and not path.resolve().is_relative_to(evidence.resolve())
         and not path.resolve().is_relative_to(repo.resolve()))
    with path.open('xb') as out: out.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())


def argv(stage):
    need(stage in ('UPDATE', 'INSTALL'))
    args = ['/usr/bin/sudo', '--non-interactive', '/usr/bin/timeout', '--signal=TERM', '--kill-after=15s',
            '120s' if stage == 'UPDATE' else '240s', '/usr/bin/env', 'DEBIAN_FRONTEND=noninteractive',
            'LC_ALL=C', '/usr/bin/apt-get']
    for item in FROZEN_CONTRACT['acquireOptions']: args += ['-o', item]
    return args + (['-o', 'APT::Update::Error-Mode=any', 'update'] if stage == 'UPDATE'
                   else ['install', '-y', '--no-install-recommends', *PACKAGES])


def source_configuration(rows):
    need(type(rows) is list and 1 <= len(rows) <= 128)
    names = []
    for row in rows:
        exact(row, ('path', 'bytes', 'sha256')); name = row['path']
        need(type(name) is str and re.fullmatch(r'/etc/apt/[A-Za-z0-9_./+-]{1,220}', name)
             and all(part not in ('', '.', '..') for part in name.split('/')[1:]))
        integer(row['bytes'], 0, MAX_LOG_BYTES); digest(row['sha256']); names.append(name)
    need(names == sorted(set(names)))


def projected_file(row, path, maximum, executable=False):
    need(row['path'] == path); integer(row['bytes'], 1, maximum); digest(row['sha256'])
    integer(row['uid'], 0, 0); integer(row['gid'], 0, 0); integer(row['mode'], 0, 0o777)
    need(not row['mode'] & 0o022)
    need(bool(row['mode'] & (0o001 if executable else 0o004)))


def readback(raw, packages, fonts):
    """Bind safe projections to the six original readback stdout lines."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_LOG_BYTES)
    try: lines = raw.decode('ascii').splitlines(keepends=True)
    except UnicodeError: raise Rejected() from None
    need(len(lines) == 6 and all(line.endswith('\n') and '\r' not in line for line in lines))
    observed = {}
    for line in lines[:2]:
        match = re.fullmatch(r'(libnss3-tools(?::amd64)?|fonts-noto-cjk)\tinstall ok installed\t([0-9][A-Za-z0-9.+:~_-]{0,127})\n', line)
        need(match is not None); name = match[1].removesuffix(':amd64')
        need(name not in observed); observed[name] = match[2]
    need(set(observed) == set(PACKAGES))
    for row in packages: need(observed[row['name']] == row['version'])
    for i, font in enumerate(fonts):
        need(lines[2 + 2 * i] == font['family'] + '\t' + font['style'] + '\t' + font['path'] + '\n')
        need(lines[3 + 2 * i] == 'fonts-noto-cjk: ' + font['path'] + '\n')


def verify(value, logs, source_blobs, commit):
    need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}', commit))
    exact(value, ('schema', 'scope', 'sourceCommit', 'outcome', 'failureStage', 'platform', 'commands', 'logs',
                  'sourcesBefore', 'sourcesAfter', 'sourceConfigurationModified', 'packages', 'certutil', 'fonts',
                  'readbackComplete', 'production', 'authorization', 'sourceInputs'))
    need(value['schema'] == 'chengwang.ci-ui-dependencies/v1' and value['scope'] == SCOPE
         and value['sourceCommit'] == commit and value['outcome'] == 'PASS' and value['failureStage'] == 'NONE'
         and value['sourceConfigurationModified'] is False and value['readbackComplete'] is True
         and value['production'] is False and value['authorization'] == 'BLOCKED')
    exact(value['platform'], ('githubActions', 'runnerOS', 'system', 'ubuntu', 'architecture'))
    need(same(value['platform'], dict(githubActions=True, runnerOS='Linux', system='Linux', ubuntu='24.04', architecture='amd64')))
    exact(source_blobs, SOURCE_PATHS)
    need(all(type(raw) is bytes and 0 < len(raw) <= 1 << 20 for raw in source_blobs.values()))
    need(same(decoded(source_blobs[CONTRACT]), FROZEN_CONTRACT))
    need(type(value['sourceInputs']) is list and len(value['sourceInputs']) == 2)
    bindings = {}
    for row in value['sourceInputs']:
        exact(row, ('path', 'bytes', 'sha256')); need(type(row['path']) is str and row['path'] in SOURCE_PATHS and row['path'] not in bindings)
        integer(row['bytes'], 1, 1 << 20); digest(row['sha256']); raw = source_blobs[row['path']]
        need(row['bytes'] == len(raw) and row['sha256'] == sha(raw)); bindings[row['path']] = row
    need(set(bindings) == SOURCE_PATHS)
    need(type(value['commands']) is list and len(value['commands']) == 2)
    for row, stage, seconds in zip(value['commands'], ('UPDATE', 'INSTALL'), (120, 240)):
        exact(row, ('stage', 'argv', 'executed', 'exitCode', 'timedOut', 'elapsedMilliseconds'))
        need(row['stage'] == stage and same(row['argv'], argv(stage)) and row['executed'] is True and row['timedOut'] is False)
        integer(row['exitCode'], 0, 0); integer(row['elapsedMilliseconds'], 0, (seconds + 15) * 1000)
    exact(logs, LOG_NAMES); need(type(value['logs']) is list and len(value['logs']) == 3)
    for row, name in zip(value['logs'], LOG_NAMES):
        exact(row, ('path', 'bytes', 'sha256', 'truncated'))
        need(row['path'] == name and row['truncated'] is False)
        integer(row['bytes'], 0, MAX_LOG_BYTES); digest(row['sha256']); raw = logs[name]
        need(type(raw) is bytes and len(raw) == row['bytes'] and sha(raw) == row['sha256'])
    source_configuration(value['sourcesBefore']); source_configuration(value['sourcesAfter'])
    need(same(value['sourcesBefore'], value['sourcesAfter']))
    packages = value['packages']; need(type(packages) is list and len(packages) == 2)
    for row, name in zip(packages, PACKAGES):
        exact(row, ('name', 'status', 'version'))
        need(row['name'] == name and row['status'] == 'install ok installed' and type(row['version']) is str
             and re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', row['version']))
    tool = value['certutil']; exact(tool, ('path', 'bytes', 'sha256', 'uid', 'gid', 'mode'))
    projected_file(tool, '/usr/bin/certutil', 16 << 20, True)
    fonts = value['fonts']; need(type(fonts) is list and len(fonts) == 2)
    for row, expected in zip(fonts, FONTS):
        exact(row, ('path', 'family', 'style', 'bytes', 'sha256', 'uid', 'gid', 'mode', 'ownerPackage'))
        need(row['family'] == 'Noto Sans CJK SC' and row['style'] == expected['style'] and row['ownerPackage'] == 'fonts-noto-cjk')
        projected_file(row, expected['path'], 64 << 20)
    need(fonts[0]['sha256'] != fonts[1]['sha256'])
    readback(logs[LOG_NAMES[2]], packages, fonts)
    return dict(schema='chengwang.ci-ui-dependencies-verification/v1', sourceCommit=commit, outcome='PASS',
        scope=SCOPE, sourceInputBindings=[bindings[name] for name in sorted(bindings)],
        logSHA256={name: sha(logs[name]) for name in LOG_NAMES}, packageNames=PACKAGES,
        fontStyles=['Regular', 'Bold'], sourceConfigurationModified=False,
        executionAttestationProven=False, independentLocalFontBytesVerified=False,
        reproduciblePackageProvenanceProven=False, browserAcceptanceProven=False, production=False, authorization='BLOCKED')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    need(type(args.source_commit) is str and re.fullmatch(r'[a-f0-9]{40}', args.source_commit))
    need(not args.evidence.is_symlink() and not args.repo.is_symlink())
    root, repo = args.evidence.resolve(strict=True), args.repo.resolve(strict=True)
    need(root.is_dir() and repo.is_dir())
    paths = {'ci-dependencies.json': root / 'ci-dependencies.json', **{name: root / name for name in LOG_NAMES}}
    raw = {name: read(path, 65536 if name == 'ci-dependencies.json' else MAX_LOG_BYTES) for name, path in paths.items()}
    blobs = {}
    for name in sorted(SOURCE_PATHS):
        blob = subprocess.check_output(['git', '-C', str(repo), 'show', args.source_commit + ':' + name], stderr=subprocess.DEVNULL)
        need(blob == read(repo / name, 1 << 20)); blobs[name] = blob
    result = verify(decoded(raw['ci-dependencies.json']), {name: raw[name] for name in LOG_NAMES}, blobs, args.source_commit)
    result.update(requiredGitBlobsVerified=2, originalReportSHA256=sha(raw['ci-dependencies.json']))
    need(all(read(paths[name], 65536 if name == 'ci-dependencies.json' else MAX_LOG_BYTES) == data for name, data in raw.items()))
    write_report(args.report, root, repo, result)
    print('CI_UI_DEPENDENCIES=VERIFIED trusted_ci_readback=true browser_acceptance_proven=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('CI_UI_DEPENDENCIES=REJECTED raw_input_suppressed=true') from None
