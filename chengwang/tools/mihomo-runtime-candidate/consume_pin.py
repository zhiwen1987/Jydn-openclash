#!/usr/bin/env python3
"""Offline isolated candidate consumption, not a release or execution tool."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import zlib

RELATIVE = 'chengwang/tools/mihomo-runtime-candidate/'
FILES = ('pin.json', 'consume_pin.py', 'check_consumption.py', 'test_consume_pin.py', 'README.md')
ARCHIVE_LIMIT, ELF_LIMIT = 64 << 20, 128 << 20
PUBLISHED_SHA = '306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc'
UPSTREAM = '88dcbf7f1614a67c3b36b848ee3592dfa92ada36'
NAME = 'mihomo-linux-amd64-v1-v1.19.32.gz'
URL = 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/' + NAME


def need(condition):
    if not condition: raise ValueError('mihomo candidate rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result); result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))
    need(type(value) is dict)
    return value


def plain(path, exists=True):
    path = Path(os.path.abspath(path))
    for ancestor in reversed((path, *path.parents)):
        if ancestor == path and not exists: continue
        need(not ancestor.is_symlink())
        entry = ancestor.lstat()
        # On Windows reject all reparse points, including non-symlink junctions.
        need(not (getattr(entry, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)))
    need(path.resolve(strict=exists) == path)
    return path


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns)


def read_regular(path, maximum, required_mode=None):
    path = plain(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
    if required_mode is not None: need(stat.S_IMODE(before.st_mode) == required_mode)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        need(identity(before) == identity(opened) and stat.S_ISREG(opened.st_mode))
        chunks, size = [], 0
        while True:
            part = os.read(fd, min(65536, maximum - size + 1))
            if not part: break
            size += len(part); need(size <= maximum); chunks.append(part)
        after, named = os.fstat(fd), path.lstat()
        need(identity(before) == identity(opened) == identity(after) == identity(named)
             and before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns
             and size == before.st_size)
        return b''.join(chunks)
    finally: os.close(fd)


def load_pin(raw):
    value = strict_json(raw)
    expected = dict(schema='chengwang.mihomo-runtime-candidate-pin/v1', component='MetaCubeX/mihomo',
        version='v1.19.32', upstreamSourceCommit=UPSTREAM,
        artifact=dict(name=NAME, url=URL, publishedSHA256=PUBLISHED_SHA,
                      exactCompressedBytes=None, elfSHA256=None, elfBytes=None),
        limits=dict(compressedBytes=ARCHIVE_LIMIT, expandedBytes=ELF_LIMIT),
        researchManifestSHA256='76b194ad7183cb661ad2deef164f30f9d8a260ddbc823e53b7760253a71bc7dc',
        publisherSignatureProven=False, productionApproved=False, runtimeExecuted=False)
    # Comparing canonical bytes also distinguishes false from 0 and true from 1.
    need(canonical(value) == canonical(expected))
    return value


def source_bindings(repo, commit, own_name='consume_pin.py'):
    need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}', commit))
    repo = plain(repo); need(repo.is_dir())
    def git(*args):
        run = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        need(run.returncode == 0 and len(run.stdout) <= 1 << 20)
        return run.stdout
    need(Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() == repo
         and git('rev-parse', 'HEAD').strip().decode('ascii') == commit
         and git('rev-parse', '--is-bare-repository').strip() == b'false')
    need(plain(Path(__file__)) == plain(repo / RELATIVE / own_name))
    sources = []
    for name in FILES:
        relative = RELATIVE + name
        actual = read_regular(repo / relative, 256 << 10)
        need(actual == git('show', commit + ':' + relative))
        sources.append(dict(path=relative, bytes=len(actual), sha256=sha(actual)))
    pin = load_pin(read_regular(repo / RELATIVE / 'pin.json', 16 << 10))
    return dict(projectSourceCommit=commit, sourceFiles=sources,
                pinSHA256=next(e['sha256'] for e in sources if e['path'] == RELATIVE + 'pin.json')), pin


def inflate_one(raw, expected_sha, compressed_limit=ARCHIVE_LIMIT, expanded_limit=ELF_LIMIT):
    need(type(raw) is bytes and 18 <= len(raw) <= compressed_limit
         and sha(raw) == expected_sha and raw[:3] == b'\x1f\x8b\x08' and not (raw[3] & 0xe0))
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try: expanded = inflater.decompress(raw, expanded_limit + 1)
    except zlib.error: raise ValueError('mihomo candidate rejected') from None
    need(0 < len(expanded) <= expanded_limit and inflater.eof
         and not inflater.unconsumed_tail and not inflater.unused_data)
    crc, declared = struct.unpack('<II', raw[-8:])
    need(crc == (zlib.crc32(expanded) & 0xffffffff) and declared == len(expanded))
    return expanded, dict(singleMember=True, complete=True, trailerCRC32=f'{crc:08x}', trailerISIZE=declared)


def inspect_elf(raw):
    need(type(raw) is bytes and 64 <= len(raw) <= ELF_LIMIT)
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = h
    need(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3)
         and ident[8:] == b'\0' * 8 and kind in (2, 3) and machine == 62 and version == 1 and flags == 0
         and ehsize == 64 and phsize == 56 and 1 <= phnum <= 1024 and phoff >= 64
         and phoff + phnum * phsize <= len(raw) and entry > 0)
    if shnum:
        need(shsize == 64 and shoff >= 64 and shoff + shnum * shsize <= len(raw) and shstr < shnum)
    else: need(shoff == 0 and shstr == 0)
    loads, executable = 0, False
    for i in range(phnum):
        ptype, pflags, offset, vaddr, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', raw, phoff + i * 56)
        need(offset <= len(raw) and filesz <= len(raw) - offset and vaddr + memsz <= (1 << 64) - 1)
        if ptype == 1:
            loads += 1
            need(filesz <= memsz and (align in (0, 1) or
                (align & (align - 1) == 0 and vaddr % align == offset % align)))
            executable |= bool(pflags & 1 and vaddr <= entry < vaddr + filesz)
    need(loads > 0 and executable)
    return dict(byteOrder='little', elfClass='ELF64', machine='AMD64', type='EXEC' if kind == 2 else 'DYN',
        entryPoint=entry, programHeaderCount=phnum, loadSegments=loads, sectionHeaderCount=shnum,
        executableEntryMapped=True)


def receipt(source, pin, archive, binary, gzip_facts, elf_facts):
    return dict(schema='chengwang.mihomo-candidate-consumption/v1', state='PINNED_GZIP_EXPANDED_NOT_EXECUTED',
        source=source, component=pin['component'], version=pin['version'], upstreamSourceCommit=pin['upstreamSourceCommit'],
        archive=dict(name=pin['artifact']['name'], bytes=len(archive), sha256=sha(archive),
                     pinBasis='PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL'),
        gzip=gzip_facts, elf=dict(bytes=len(binary), sha256=sha(binary), **elf_facts),
        output=dict(path='mihomo', mode='0500', receiptMode='0400', directoryMode='0700'),
        runtimeExecuted=False, runtimeCompatibilityProven=False, businessAvailabilityProven=False,
        publisherSignatureProven=False, productionApproved=False, production=False)


def write_new(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1)
        view = memoryview(raw)
        while view:
            size = os.write(fd, view); need(size > 0); view = view[size:]
        os.fsync(fd)
        os.fchmod(fd, mode)
        need(stat.S_IMODE(os.fstat(fd).st_mode) == mode)
        os.fsync(fd)
    finally: os.close(fd)
    need(read_regular(path, len(raw), mode) == raw)


def consume(archive, repo, commit, output):
    need(os.name == 'posix')  # POSIX permission evidence cannot be manufactured on Windows.
    source, pin = source_bindings(repo, commit)
    original = read_regular(archive, ARCHIVE_LIMIT)
    binary, gz = inflate_one(original, pin['artifact']['publishedSHA256'])
    elf = inspect_elf(binary)
    output = plain(output, exists=False)
    need(not output.exists() and not output.is_symlink())
    output.mkdir(mode=0o700)
    need(stat.S_IMODE(output.lstat().st_mode) == 0o700)
    write_new(output / 'mihomo', binary, 0o500)
    need(source_bindings(repo, commit) == (source, pin))
    record = receipt(source, pin, original, binary, gz, elf)
    write_new(output / 'consumption.json', canonical(record), 0o400)
    need(set(p.name for p in output.iterdir()) == {'mihomo', 'consumption.json'})
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    consume(args.archive, args.repo, args.source_commit, args.output)
    print('MIHOMO_CANDIDATE_CONSUMED=PASS runtime_executed=false production=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('MIHOMO_CANDIDATE_CONSUMED=REJECTED raw_input_suppressed=true') from None
