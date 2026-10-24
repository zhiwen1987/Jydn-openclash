#!/usr/bin/env python3
"""Independent offline original-gzip/output/receipt verification; no producer import."""
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

PREFIX = 'chengwang/tools/mihomo-runtime-candidate/'
SOURCES = ('pin.json', 'consume_pin.py', 'check_consumption.py', 'test_consume_pin.py', 'README.md')
COMPRESSED_MAX, EXPANDED_MAX = 67108864, 134217728
DIGEST = '306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc'
UPSTREAM_COMMIT = '88dcbf7f1614a67c3b36b848ee3592dfa92ada36'
ASSET = 'mihomo-linux-amd64-v1-v1.19.32.gz'


def require(ok):
    if not ok: raise ValueError('independent mihomo verification rejected')


def digest(data): return hashlib.sha256(data).hexdigest()


def encode(value): return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def decode(data):
    def distinct(items):
        value = {}
        for name, item in items:
            require(name not in value); value[name] = item
        return value
    value = json.loads(data, object_pairs_hook=distinct, parse_constant=lambda _: require(False))
    require(type(value) is dict)
    return value


def path_without_links(value, present=True):
    p = Path(os.path.abspath(value))
    for item in [*reversed(p.parents), p]:
        if item == p and not present: continue
        s = item.lstat()
        require(not stat.S_ISLNK(s.st_mode) and not (getattr(s, 'st_file_attributes', 0) & 1024))
    require(p.resolve(strict=present) == p)
    return p


def stable_bytes(value, limit, mode=None):
    p = path_without_links(value)
    first = p.lstat()
    require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and 1 <= first.st_size <= limit)
    if mode is not None: require(stat.S_IMODE(first.st_mode) == mode)
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        def key(s): return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns)
        require(key(first) == key(opened) and stat.S_ISREG(opened.st_mode))
        with os.fdopen(fd, 'rb', closefd=False) as stream: data = stream.read(limit + 1)
        closed, named = os.fstat(fd), p.lstat()
        require(key(first) == key(opened) == key(closed) == key(named) and len(data) == first.st_size
                and first.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == closed.st_ctime_ns)
        return data
    finally: os.close(fd)


def source_identity(repo, revision):
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision))
    repo = path_without_links(repo)
    def git(*args):
        p = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        require(p.returncode == 0 and len(p.stdout) <= 1048576)
        return p.stdout
    require(Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() == repo
            and git('rev-parse', 'HEAD').strip().decode('ascii') == revision
            and git('rev-parse', '--is-bare-repository').strip() == b'false')
    require(path_without_links(__file__) == path_without_links(repo / PREFIX / 'check_consumption.py'))
    rows, pin_bytes = [], None
    for name in SOURCES:
        path = PREFIX + name
        data = stable_bytes(repo / path, 262144)
        require(data == git('show', revision + ':' + path))
        rows.append(dict(path=path, bytes=len(data), sha256=digest(data)))
        if name == 'pin.json': pin_bytes = data
    pin = decode(pin_bytes)
    required_pin = dict(schema='chengwang.mihomo-runtime-candidate-pin/v1',component='MetaCubeX/mihomo',
        version='v1.19.32',upstreamSourceCommit=UPSTREAM_COMMIT,
        artifact=dict(name=ASSET,url='https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/' + ASSET,
            publishedSHA256=DIGEST,exactCompressedBytes=None,elfSHA256=None,elfBytes=None),
        limits=dict(compressedBytes=COMPRESSED_MAX,expandedBytes=EXPANDED_MAX),
        researchManifestSHA256='76b194ad7183cb661ad2deef164f30f9d8a260ddbc823e53b7760253a71bc7dc',
        publisherSignatureProven=False,productionApproved=False,runtimeExecuted=False)
    require(encode(pin) == encode(required_pin))
    return dict(projectSourceCommit=revision,sourceFiles=rows,pinSHA256=digest(pin_bytes))


def original_payload(data, expected_digest=DIGEST, compressed_max=COMPRESSED_MAX, expanded_max=EXPANDED_MAX):
    """Parse one RFC1952 header and raw DEFLATE separately from its sole trailer."""
    require(type(data) is bytes and 18 <= len(data) <= compressed_max and digest(data) == expected_digest)
    require(data[:3] == b'\x1f\x8b\x08' and data[3] & 0xe0 == 0)
    flags, cursor = data[3], 10
    if flags & 4:
        require(cursor + 2 <= len(data) - 8)
        extra = int.from_bytes(data[cursor:cursor+2], 'little'); cursor += 2 + extra
        require(cursor <= len(data) - 8)
    for flag in (8, 16):
        if flags & flag:
            end = data.find(b'\0', cursor, len(data) - 8)
            require(end >= cursor); cursor = end + 1
    if flags & 2:
        require(cursor + 2 <= len(data) - 8)
        require(zlib.crc32(data[:cursor]) & 0xffff == int.from_bytes(data[cursor:cursor+2], 'little'))
        cursor += 2
    require(cursor < len(data) - 8)
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    try: payload = d.decompress(data[cursor:], expanded_max + 1)
    except zlib.error: raise ValueError('independent mihomo verification rejected') from None
    require(d.eof and not d.unconsumed_tail and len(d.unused_data) == 8 and 0 < len(payload) <= expanded_max)
    crc = int.from_bytes(d.unused_data[:4], 'little')
    length = int.from_bytes(d.unused_data[4:], 'little')
    require(crc == zlib.crc32(payload) & 0xffffffff and length == len(payload))
    return payload,dict(singleMember=True,complete=True,trailerCRC32=format(crc,'08x'),trailerISIZE=length)


def elf_identity(data):
    require(type(data) is bytes and 64 <= len(data) <= EXPANDED_MAX)
    require(data[:7] == b'\x7fELF\x02\x01\x01' and data[7] in (0,3) and data[8:16] == bytes(8))
    get = lambda offset, size: int.from_bytes(data[offset:offset+size], 'little')
    kind, machine, version = get(16,2),get(18,2),get(20,4)
    entry, programs, sections = get(24,8),get(32,8),get(40,8)
    phnum, shnum = get(56,2),get(60,2)
    require(kind in (2,3) and machine == 62 and version == 1 and get(48,4) == 0 and entry > 0
            and get(52,2) == 64 and get(54,2) == 56 and 1 <= phnum <= 1024
            and programs >= 64 and programs + phnum * 56 <= len(data))
    if shnum: require(get(58,2) == 64 and sections >= 64 and sections + shnum * 64 <= len(data) and get(62,2) < shnum)
    else: require(sections == 0 and get(62,2) == 0)
    loads, mapped = 0, False
    for offset in range(programs, programs + phnum * 56, 56):
        typ, permissions, file_offset, address, _, size, memory, align = struct.unpack_from('<IIQQQQQQ',data,offset)
        require(file_offset <= len(data) and size <= len(data) - file_offset and address + memory < 1 << 64)
        if typ == 1:
            loads += 1
            require(size <= memory)
            if align not in (0,1): require(align & (align - 1) == 0 and address % align == file_offset % align)
            if permissions & 1 and address <= entry < address + size: mapped = True
    require(loads > 0 and mapped)
    return dict(byteOrder='little',elfClass='ELF64',machine='AMD64',type={2:'EXEC',3:'DYN'}[kind],
        entryPoint=entry,programHeaderCount=phnum,loadSegments=loads,sectionHeaderCount=shnum,executableEntryMapped=True)


def validate_receipt(raw_receipt,source,original,payload,gzip_facts,facts):
    observed_receipt = decode(raw_receipt)
    expected = dict(schema='chengwang.mihomo-candidate-consumption/v1',state='PINNED_GZIP_EXPANDED_NOT_EXECUTED',
        source=source,component='MetaCubeX/mihomo',version='v1.19.32',upstreamSourceCommit=UPSTREAM_COMMIT,
        archive=dict(name=ASSET,bytes=len(original),sha256=digest(original),pinBasis='PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL'),
        gzip=gzip_facts,elf=dict(bytes=len(payload),sha256=digest(payload),**facts),
        output=dict(path='mihomo',mode='0500',receiptMode='0400',directoryMode='0700'),
        runtimeExecuted=False,runtimeCompatibilityProven=False,businessAvailabilityProven=False,
        publisherSignatureProven=False,productionApproved=False,production=False)
    require(raw_receipt == encode(expected) == encode(observed_receipt))
    return raw_receipt


def verify(archive, repo, revision, evidence):
    require(os.name == 'posix')
    source = source_identity(repo, revision)
    original = stable_bytes(archive, COMPRESSED_MAX)
    payload,gzip_facts = original_payload(original)
    facts = elf_identity(payload)
    evidence = path_without_links(evidence)
    require(evidence.is_dir() and stat.S_IMODE(evidence.lstat().st_mode) == 0o700
            and {p.name for p in evidence.iterdir()} == {'mihomo','consumption.json'})
    observed = stable_bytes(evidence / 'mihomo',EXPANDED_MAX,0o500)
    require(observed == payload)
    raw_receipt = stable_bytes(evidence / 'consumption.json',131072,0o400)
    validate_receipt(raw_receipt,source,original,payload,gzip_facts,facts)
    require(source_identity(repo,revision) == source
            and stable_bytes(evidence / 'mihomo',EXPANDED_MAX,0o500) == observed
            and stable_bytes(evidence / 'consumption.json',131072,0o400) == raw_receipt
            and {p.name for p in evidence.iterdir()} == {'mihomo','consumption.json'})
    return raw_receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',required=True,type=Path)
    p.add_argument('--repo',required=True,type=Path)
    p.add_argument('--source-commit',required=True)
    p.add_argument('--evidence',required=True,type=Path)
    p.add_argument('--report',required=True,type=Path)
    args = p.parse_args()
    evidence = path_without_links(args.evidence)
    report = path_without_links(args.report,present=False)
    require(not report.exists() and not report.is_relative_to(evidence))
    raw = verify(args.archive,args.repo,args.source_commit,evidence)
    fd = os.open(report,os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_BINARY',0),0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as out: out.write(raw); out.flush(); os.fsync(fd)
    finally: os.close(fd)
    require(stable_bytes(report,131072) == raw)
    print('MIHOMO_CANDIDATE_VERIFIED=PASS runtime_executed=false production=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('MIHOMO_CANDIDATE_VERIFIED=REJECTED raw_input_suppressed=true') from None
