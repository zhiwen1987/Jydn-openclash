"""Collect remote gofmt bytes without writing source or granting admission."""
import argparse
import difflib
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

SCHEMA = 'chengwang.overview-format-evidence/v1'
FORMATTER = '/opt/hostedtoolcache/go/1.23.12/x64/bin/gofmt'
TIMEOUT_SECONDS = 30
MAX_SOURCE_BYTES = 512 << 10
MAX_SOURCE_TOTAL = 2 << 20
MAX_FORMATTED_BYTES = 2 << 20
MAX_FORMATTED_TOTAL = 4 << 20
MAX_DIFF_BYTES = 16 << 20
FORMAT_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'GOMAXPROCS': '1'}
WINDOWS_METADATA = os.name == 'nt'
GO_PATHS = (
    'chengwang/internal/overview/model.go',
    'chengwang/internal/overview/provider.go',
    'chengwang/internal/overview/provider_test.go',
    'chengwang/internal/api/overview.go',
    'chengwang/internal/api/overview_test.go',
    'chengwang/internal/api/server.go',
    'chengwang/internal/serverruntime/overview_config.go',
    'chengwang/internal/serverruntime/overview_config_test.go',
    'chengwang/internal/serverruntime/overview_runtime_linux_test.go',
    'chengwang/internal/serverruntime/runtime.go',
)


class FormatEvidenceError(Exception):
    """The CLI never exposes the underlying input, exception or formatter stderr."""


def need(condition):
    if not condition:
        raise FormatEvidenceError('format evidence rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute_path(value):
    need(type(value) is str and value and '\x00' not in value)
    path = pathlib.Path(value)
    need(path.is_absolute() and '..' not in path.parts)
    return path


def link_like(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def check_components(path, *, file=False, missing_leaf=False):
    for node in (path, *path.parents):
        try:
            info = node.lstat()
        except FileNotFoundError:
            if node == path and missing_leaf:
                continue
            raise
        need(not link_like(info))
        need(stat.S_ISREG(info.st_mode) if node == path and file else stat.S_ISDIR(info.st_mode))


def identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def cross_identity(info):
    value = identity(info)
    if not WINDOWS_METADATA:
        return value
    # CPython v3.12.10 win32_xstat copies birthtime to path ctime, while
    # _Py_fstat_noraise preserves ChangeTime. Keep both full channel snapshots;
    # only compare their common fields (and optional birthtime) across channels.
    # https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c#L2146
    # https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c#L1117
    return value[:-1] + (getattr(info, 'st_birthtime_ns', None),)


def stable_read(path, maximum):
    check_components(path, file=True)
    before = path.lstat()
    need(0 <= before.st_size <= maximum)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        need(stat.S_ISREG(opened.st_mode) and cross_identity(opened) == cross_identity(before))
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum - size + 1))
            if not chunk:
                break
            size += len(chunk)
            need(size <= maximum)
            chunks.append(chunk)
        descriptor_after = os.fstat(descriptor)
        need(identity(descriptor_after) == identity(opened) and cross_identity(descriptor_after) == cross_identity(opened))
    finally:
        os.close(descriptor)
    check_components(path, file=True)
    path_after = path.lstat()
    need(identity(path_after) == identity(before) and cross_identity(path_after) == cross_identity(before))
    raw = b''.join(chunks)
    need(len(raw) == before.st_size)
    # Preserve descriptor ctime in the collection-wide before/after token too,
    # including same-byte rewrites that restore mtime on Windows.
    return raw, (identity(before), identity(opened), cross_identity(before), cross_identity(opened))


def format_source(raw):
    # No filename, flag, -w, shell command or inherited environment is supplied.
    completed = subprocess.run([FORMATTER], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=TIMEOUT_SECONDS, check=False, shell=False, env=dict(FORMAT_ENV), cwd='/')
    need(completed.returncode == 0 and type(completed.stdout) is bytes and completed.stderr == b'')
    need(len(completed.stdout) <= MAX_FORMATTED_BYTES)
    return completed.stdout


def source_diff(relative, before, after):
    original = before.decode('utf-8').splitlines(keepends=True)
    formatted = after.decode('utf-8').splitlines(keepends=True)
    lines = difflib.unified_diff(original, formatted, fromfile='a/' + relative, tofile='b/' + relative, lineterm='\n')
    result = []
    for line in lines:
        result.append(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n')
    return ''.join(result).encode('utf-8')


def exclusive_write(path, raw):
    check_components(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    observed, _ = stable_read(path, max(1, len(raw)))
    need(observed == raw)


def collect(repo_value, source_commit, output_value):
    need(type(source_commit) is str and re.fullmatch(r'[a-f0-9]{40}', source_commit))
    repo, output = absolute_path(repo_value), absolute_path(output_value)
    check_components(repo)
    need(output != repo and repo not in output.parents)
    check_components(output, missing_leaf=True)
    need(not output.exists())
    output.mkdir(mode=0o700)
    output_identity = identity(output.lstat())[:3]
    originals = {}
    total_before = 0
    for relative in GO_PATHS:
        raw, token = stable_read(repo / relative, MAX_SOURCE_BYTES)
        raw.decode('utf-8')
        total_before += len(raw)
        need(total_before <= MAX_SOURCE_TOTAL)
        originals[relative] = (raw, token)
    rows, diff_parts = [], []
    total_after = diff_size = 0
    for relative in GO_PATHS:
        before, _ = originals[relative]
        after = format_source(before)
        after.decode('utf-8')
        total_after += len(after)
        need(total_after <= MAX_FORMATTED_TOTAL)
        difference = source_diff(relative, before, after)
        diff_size += len(difference)
        need(diff_size <= MAX_DIFF_BYTES)
        diff_parts.append(difference)
        rows.append(dict(path=relative, beforeSHA256=sha(before), afterSHA256=sha(after),
            beforeBytes=len(before), afterBytes=len(after), needsFormatting=before != after))
    # Both bytes and filesystem identity/metadata must survive all formatter calls.
    for relative in GO_PATHS:
        need(stable_read(repo / relative, MAX_SOURCE_BYTES) == originals[relative])
    check_components(output)
    need(identity(output.lstat())[:3] == output_identity)
    difference = b''.join(diff_parts)
    report = dict(schema=SCHEMA, sourceCommit=source_commit,
        commitBinding='CALLER_SUPPLIED_LABEL_SOURCE_BLOBS_CHECKED_BY_PARENT_GATE',
        formatter=dict(path=FORMATTER, arguments=[], input='stdin', perFileTimeoutSeconds=TIMEOUT_SECONDS),
        files=rows, sourceUnchanged=True, needsFormatting=any(row['needsFormatting'] for row in rows),
        beforeTotalBytes=total_before, afterTotalBytes=total_after,
        diff=dict(path='overview-format-diff.txt', bytes=len(difference), sha256=sha(difference)),
        compilationVerified=False, testsVerified=False, runtimeVerified=False, production=False,
        collectionOnly=True, sourceCheck='STABLE_BEFORE_AND_AFTER_NOT_CONTINUOUS_MUTATION_PROOF')
    exclusive_write(output / 'overview-format-diff.txt', difference)
    exclusive_write(output / 'report.json', (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8'))
    return report


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise FormatEvidenceError('format arguments rejected')


def main(argv=None):
    try:
        parser = SafeParser(add_help=False, allow_abbrev=False)
        parser.add_argument('--repo', required=True)
        parser.add_argument('--source-commit', required=True)
        parser.add_argument('--output', required=True)
        options = parser.parse_args(argv)
        collect(options.repo, options.source_commit, options.output)
    except Exception:
        print('OVERVIEW_FORMAT=REJECTED details_suppressed=true', file=sys.stderr)
        return 1
    print('OVERVIEW_FORMAT=COLLECTED format_admission=independent')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
