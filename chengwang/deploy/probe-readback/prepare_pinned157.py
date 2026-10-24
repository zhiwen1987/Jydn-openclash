"""Verify the fixed consumption and copy its distribution; never launch Chrome."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

import check_pinned157 as V


def validate_copy_info(info, mode):
    V.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
           and stat.S_IMODE(info.st_mode) == mode)


def validate_locations(options, runner_temp):
    V.unaliased(runner_temp); V.need(runner_temp.is_dir())
    runtime = runner_temp / 'chengwang-probe-browser-runtime'
    V.need(options.destination == runtime / 'chrome'
           and options.consumption_root == runner_temp / 'chengwang-probe-pinned157-consumption'
           and options.receipt == runtime / 'evidence/pinned157-consumption.json'
           and options.report == runtime / 'evidence/pinned157-copy.json')


def copy_distribution(source, destination, files):
    V.unaliased(source); V.need(source.is_dir())
    V.unaliased(destination, True)
    V.need(destination.name == 'chrome' and destination.parent.name == 'chengwang-probe-browser-runtime')
    V.need(sys.platform.startswith('linux') and os.geteuid() == 0)
    destination.mkdir(mode=0o755); destination.chmod(0o755)
    for row in files:
        relative = Path(row['path'])
        V.need(not relative.is_absolute() and not any(p in ('', '.', '..') for p in relative.parts))
        incoming = source / relative; raw = V.read_file(incoming, 512 << 20, allow_empty=True)
        V.need(len(raw) == row['bytes'] and V.sha(raw) == row['sha256'])
        target = destination / relative
        for directory in reversed(target.parent.relative_to(destination).parents):
            (destination / directory).mkdir(mode=0o755, exist_ok=True)
        target.parent.mkdir(mode=0o755, exist_ok=True)
        V.need(not target.exists() and not target.is_symlink())
        mode = 0o755 if incoming.lstat().st_mode & 0o111 else 0o644
        V.write_new(target, raw, mode)
        info = target.lstat()
        validate_copy_info(info, mode)
        V.need(V.read_file(incoming, 512 << 20, allow_empty=True) == raw)
    actual = sorted(p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file())
    V.need(actual == sorted(row['path'] for row in files))


def main(argv=None):
    p = V.Parser()
    p.add_argument('--repo', required=True, type=Path); p.add_argument('--source-commit', required=True)
    p.add_argument('--consumption-root', required=True, type=Path); p.add_argument('--receipt', required=True, type=Path)
    p.add_argument('--destination', required=True, type=Path); p.add_argument('--report', required=True, type=Path)
    a = p.parse_args(argv)
    validate_locations(a, Path(os.environ['RUNNER_TEMP']))
    host = V.bind_sources(a.repo, a.source_commit)
    V.need(not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.consumption_root)
           and not a.report.is_relative_to(a.destination))
    V.unaliased(a.report, True)
    C = V.consumption_checker(a.repo); C.require_linux_ci(sys.platform, os.environ)
    raw = V.read_file(a.receipt, 1 << 20); receipt = V.decode(raw)
    V.need(raw == C.canonical(C.verify_consumption(a.repo, a.consumption_root, a.source_commit)))
    manifest = V.decode(V.read_file(a.consumption_root / 'consumption.json', 2 << 20))
    files = V.copy_files(manifest)
    copy_distribution(a.consumption_root / 'chrome-linux64', a.destination, files)
    V.need(V.read_file(a.receipt, 1 << 20) == raw and V.bind_sources(a.repo, a.source_commit) == host)
    result = dict(schema='chengwang.probe-pinned157-copy/v1', sourceCommit=a.source_commit,
                  browserVersion='157.0.8103.6', actualAcquisition='FIXED_CFT_ARCHIVE_NOT_HOST_CHROME',
                  receiptSHA256=V.sha(raw), files=files,
                  sourceUnchanged=True, rootOwnedReadOnlyDistribution=True, browserExecuted=False, production=False)
    V.write_new(a.report, V.canonical(result), 0o644)
    print('PROBE_PINNED157_COPY=VERIFIED browser_started=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('PROBE_PINNED157_COPY=REJECTED raw_input_suppressed=true') from None
