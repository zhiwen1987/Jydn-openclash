"""Bind reviewed pinned Chrome to actual probe custody, never forgive browser errors."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
HOST = HERE.parents[2]
BASE = 'chengwang/deploy/probe-readback/'
SOURCES = (
    BASE + 'check_pinned157.py', BASE + 'prepare_pinned157.py', BASE + 'test_pinned157.py',
    '.github/workflows/chengwang-probe-browser.yml', '.github/workflows/chengwang-probe-pinned157.yml',
    'chengwang/tools/probe-browser/package.json', 'chengwang/tools/probe-browser/package-lock.json',
    'chengwang/tools/probe-browser/check-toolchain.mjs', BASE + 'run_probe_browser.py',
    BASE + 'probe_browser_identity.py', 'chengwang/tools/probe-browser/browser-driver.mjs',
    'chengwang/tools/browser-runtime-candidate/pin.json',
    'chengwang/tools/browser-runtime-candidate/consume_pin.py',
    'chengwang/tools/browser-runtime-candidate/check_consumption.py',
    'chengwang/tools/browser-acquisition/check_acquisition.py',
    'chengwang/tools/browser-acquisition/candidate.json',
)
TAG = '41520584daa68d0040db7746ae562a0ff82187f6'
ELF_SHA = 'ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
ELF_BYTES = 305061192
COUNTERS = ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors',
            'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors')
INPUTS = {'pinned157-consumption.json': 1 << 20, 'pinned157-copy.json': 1 << 20,
          'toolchain.json': 16384, 'lab/browser/browser-build.json': 4 << 20,
          'lab/browser/browser-processes.json': 4 << 20, 'lab/browser/browser-driver.json': 1 << 20,
          'lab/browser-identity.json': 16384}


def need(value):
    if not value:
        raise ValueError('pinned157 evidence rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')) + '\n').encode()


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def integer(value, minimum=0, maximum=1 << 40):
    need(type(value) is int and minimum <= value <= maximum)


def unaliased(path, missing_leaf=False):
    need(path.is_absolute() and '..' not in path.parts)
    for item in reversed((path, *path.parents)):
        if missing_leaf and item == path:
            need(not item.exists() and not item.is_symlink()); continue
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    return path


def identity(info, cross=False):
    keys = ['st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns']
    if cross and os.name == 'nt':
        keys.remove('st_ctime_ns')  # CPython3.12 Windows stat/fstat differ; same-channel checks retain it.
    return tuple(getattr(info, key) for key in keys)


def read_file(path, maximum, allow_empty=False):
    unaliased(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (0 if allow_empty else 1) <= before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(fd); need(identity(before, True) == identity(opened, True))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd); named = path.lstat()
        need(identity(opened) == identity(after) and identity(before) == identity(named)
             and identity(after, True) == identity(named, True) and len(raw) == before.st_size)
        return raw
    finally:
        os.close(fd)


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value); value[key] = item
        return value
    def constant(_):
        raise ValueError('nonfinite JSON')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    need(type(value) is dict)
    return value


def records(rows):
    need(type(rows) is list and len(rows) <= 16384)
    values = {}
    for row in rows:
        exact(row, ('path', 'bytes', 'sha256'))
        name = row['path']
        need(type(name) is str and re.fullmatch('[A-Za-z0-9_./@+-]+', name)
             and not any(p in ('', '.', '..') for p in name.split('/')) and name not in values)
        integer(row['bytes'], 0, 512 << 20)
        need(type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']))
        values[name] = row
    return values


def bind_sources(repo, commit, captured=None):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    unaliased(repo); need(repo.is_dir())
    output = {}
    for name in SOURCES:
        proc = subprocess.run(['git', '-C', str(repo), 'show', commit + ':' + name],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        need(proc.returncode == 0 and 0 < len(proc.stdout) <= 1 << 20)
        need(read_file(repo / name, 1 << 20) == proc.stdout == read_file(HOST / name, 1 << 20))
        row = dict(path=name, bytes=len(proc.stdout), sha256=sha(proc.stdout))
        if captured is not None:
            need(captured.get(name) == row)
        output[name] = row
    return output


def consumption_checker(repo):
    path = repo / 'chengwang/tools/browser-runtime-candidate/check_consumption.py'
    spec = importlib.util.spec_from_file_location('probe_independent_pinned_consumption', path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def copy_files(manifest):
    files = []
    need(type(manifest) is dict and type(manifest.get('expanded')) is dict)
    for row in manifest['expanded']['members']:
        name = row['path']
        need(type(name) is str and name.startswith('chrome-linux64/') and row.get('type') in ('file', 'directory'))
        if row.get('type') == 'directory':
            continue
        # Expansion members are regular files, not arbitrary filesystem walks.
        if name.endswith('/'):
            continue
        relative = name[len('chrome-linux64/'):]
        need(relative and all(p not in ('', '.', '..') for p in relative.split('/')))
        integer(row['bytes'], 0, 512 << 20)
        files.append(dict(path=relative, bytes=row['bytes'], sha256=row['sha256']))
    need(0 < len(files) <= 4096)
    return sorted(files, key=lambda row: row['path'])


def verify_binding(data, fresh_receipt, expanded_files, installed, commit, engine):
    need(engine in ('chrome-cdp', 'playwright'))
    receipt, copy = data['pinned157-consumption.json'], data['pinned157-copy.json']
    need(canonical(receipt) == canonical(fresh_receipt) and receipt['sourceCommit'] == commit
         and receipt['schema'] == 'chengwang.pinned-browser-consumption-verification/v1'
         and receipt['pinEnforced'] is True and receipt['browserExecuted'] is False)
    need(receipt['elf']['bytes'] == ELF_BYTES and receipt['elf']['sha256'] == ELF_SHA)
    exact(copy, ('schema', 'sourceCommit', 'browserVersion', 'actualAcquisition', 'receiptSHA256', 'files', 'sourceUnchanged',
                 'rootOwnedReadOnlyDistribution', 'browserExecuted', 'production'))
    need(copy['schema'] == 'chengwang.probe-pinned157-copy/v1' and copy['sourceCommit'] == commit
         and copy['browserVersion'] == '157.0.8103.6' and copy['actualAcquisition'] == 'FIXED_CFT_ARCHIVE_NOT_HOST_CHROME'
         and copy['receiptSHA256'] == sha(canonical(receipt))
         and copy['sourceUnchanged'] is True and copy['rootOwnedReadOnlyDistribution'] is True
         and copy['browserExecuted'] is False and copy['production'] is False)
    need(canonical(copy['files']) == canonical(expanded_files))
    build = data['lab/browser/browser-build.json']
    need(build['sourceCommit'] == commit and build['engine'] == engine and build['production'] is False
         and build['sourceFilesBefore'] == build['sourceFilesAfter'])
    copies = records(build['copiedInputs'])
    observed = sorted([dict(path=k[len('toolchain/chrome/'):], bytes=v['bytes'], sha256=v['sha256'])
                       for k, v in copies.items() if k.startswith('toolchain/chrome/')], key=lambda row: row['path'])
    need(observed == expanded_files)
    need(copies['toolchain/chrome/chrome']['bytes'] == ELF_BYTES and copies['toolchain/chrome/chrome']['sha256'] == ELF_SHA)
    proc = data['lab/browser/browser-processes.json']; driver = data['lab/browser/browser-driver.json']
    ident = data['lab/browser-identity.json']; tool = data['toolchain.json']
    fixture = build['fixtureId']; need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture))
    need(proc['sourceCommit'] == commit and type(proc['controllerExitCode']) is int and proc['controllerExitCode'] == 0 and proc['production'] is False)
    identities = proc['records']; need(type(identities) is list)
    chrome = [r for r in identities if r.get('role') == 'chrome']; controller = [r for r in identities if r.get('role') == 'controller']
    need(len(chrome) == len(controller) == 1); chrome = chrome[0]; controller = controller[0]
    exe = proc['chromeExecutable']
    need(exe['bytes'] == ELF_BYTES and exe['sha256'] == ELF_SHA == chrome['exeSHA256']
         and exe['sourceScope'] == 'TRUSTED_CI_SYSTEM_TOOL_NOT_INDEPENDENT_SUPPLY_CHAIN'
         and controller['exeSHA256'] == copies['toolchain/node']['sha256'])
    need(driver['fixtureId'] == fixture and driver['engine'] == engine and driver['runtime'] is True
         and driver['realBrowser'] in ('Chrome/157.0.8103.6', 'HeadlessChrome/157.0.8103.6'))
    need(all(type(driver[k]) is int and driver[k] == 0 for k in COUNTERS))
    need(all(driver[k] is False for k in ('mockedResponses', 'injectedFetch', 'tlsBypass')))
    need(ident['sourceCommit'] == commit and ident['fixtureId'] == fixture and ident['engine'] == engine
         and ident['state'] == 'observed' and ident['rawIdentityLines'] == 1
         and ident['executable'] == dict(bytes=ELF_BYTES, sha256=ELF_SHA))
    obs = ident['observation']; need(obs['fixtureId'] == fixture and obs['engine'] == engine)
    need(obs['browser']['product'] == driver['realBrowser'] and obs['browser']['revision'] == '@' + TAG
         and obs['browser']['protocolVersion'] == '1.3')
    need(obs['chrome'] == dict(pid=chrome['pid'], startTicks=int(chrome['startTime']), argvSHA256=chrome['argvSHA256']))
    need(all(driver['chrome'][k] == obs['chrome'][k] for k in ('pid', 'startTicks', 'argvSHA256')))
    exact(tool, ('schema', 'outcome', 'acceptanceScope', 'runtime', 'browserStarted', 'nodeVersion', 'playwrightVersion', 'chromiumLaunchAvailable'))
    need(canonical(tool) == canonical(dict(schema='chengwang.probe-browser-toolchain/v1', outcome='PASS', acceptanceScope='TOOLCHAIN_ONLY',
                      runtime=False, browserStarted=False, nodeVersion='v22.23.3', playwrightVersion='1.64.1', chromiumLaunchAvailable=True)))
    package = decode(installed)
    need(package['name'] == 'playwright-core' and package['version'] == '1.64.1')
    need(copies['npm/playwright-core/package.json'] == dict(path='npm/playwright-core/package.json', bytes=len(installed), sha256=sha(installed)))
    return dict(schema='chengwang.probe-pinned157-verification/v1', sourceCommit=commit, engine=engine,
                fixtureId=fixture, actualBrowser=obs['browser'], copiedChromeFiles=len(expanded_files),
                actualChromeELFSHA256=ELF_SHA, pinnedConsumptionIndependentlyReplayed=True,
                copiedDistributionMatched=True, actualProcessAndVersionBound=True,
                playwrightVersion='1.64.1', nodeVersion='v22.23.3', oldEightZeroCountersRelaxed=False,
                originalBrowserGateReplaced=False, uniqueCancellationRootCauseProven=False,
                actualAcquisition='FIXED_CFT_ARCHIVE_NOT_HOST_CHROME',
                legacySourceScopeMeaning='TRUST_CLASS_NOT_HOST_INSTALLATION_OR_ACQUISITION_PATH',
                browserAcceptanceProven=False, production=False, authorization='BLOCKED')


def write_new(path, raw, mode=0o600):
    unaliased(path, True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(raw); output.flush(); os.fsync(fd)
        if os.name != 'nt':
            os.fchmod(fd, mode)
    finally:
        os.close(fd)
    need(read_file(path, len(raw), allow_empty=True) == raw)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError('pinned157 arguments rejected')


def main(argv=None):
    p = Parser()
    p.add_argument('--repo', required=True, type=Path); p.add_argument('--source-commit', required=True)
    p.add_argument('--evidence-root', required=True, type=Path); p.add_argument('--consumption-root', required=True, type=Path)
    p.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright')); p.add_argument('--report', required=True, type=Path)
    a = p.parse_args(argv)
    for path in (a.repo, a.evidence_root, a.consumption_root):
        unaliased(path); need(path.is_dir())
    unaliased(a.report, True)
    need(not any(a.report.is_relative_to(root) for root in (a.repo, a.evidence_root, a.consumption_root)))
    host = bind_sources(a.repo, a.source_commit)
    raw = {name: read_file(a.evidence_root / name, limit) for name, limit in INPUTS.items()}
    data = {name: decode(value) for name, value in raw.items()}
    captured = records(data['lab/browser/browser-build.json']['sourceFilesBefore'])
    need(bind_sources(a.repo, a.source_commit, captured) == host)
    independent = consumption_checker(a.repo)
    independent.require_linux_ci(sys.platform, os.environ)
    fresh = independent.verify_consumption(a.repo, a.consumption_root, a.source_commit)
    manifest = decode(read_file(a.consumption_root / 'consumption.json', 2 << 20))
    installed = read_file(a.repo / 'chengwang/tools/probe-browser/node_modules/playwright-core/package.json', 1 << 20)
    result = verify_binding(data, fresh, copy_files(manifest), installed, a.source_commit, a.engine)
    need(bind_sources(a.repo, a.source_commit, captured) == host)
    need(all(read_file(a.evidence_root / name, INPUTS[name]) == value for name, value in raw.items()))
    result.update(sourceFiles=list(host.values()), inputSHA256={name: sha(value) for name, value in raw.items()})
    write_new(a.report, canonical(result))
    print('PROBE_PINNED157=BOUND old_eight_zero_relaxed=false production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('PROBE_PINNED157=REJECTED raw_input_suppressed=true') from None
