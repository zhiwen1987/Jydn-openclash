"""Independent, offline capability UI reconstruction, never a producer runtime.

Only Python's standard library and offline git/openssl are used. Safe browser,
process and private-store observations remain source-bound trusted CI evidence;
this is not an independent browser-internal or private-database attestation.
"""
import argparse
import base64
import calendar
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import unicodedata
import zlib

HERE = Path(__file__).parent
CONTRACT_PATH = 'chengwang/deploy/capability-truth-browser/contract.json'
OWN_PATH = 'chengwang/deploy/capability-truth-browser/check_capability_truth.py'
PROCESS_TRUST = 'TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION'
INPUT_TRUST = 'SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD'
COUNTER_TRUST = 'SOURCE_BOUND_SAFE_CDP_EVENT_PROJECTIONS_NOT_BROWSER_INTERNAL_ATTESTATION'
TAG = '41520584daa68d0040db7746ae562a0ff82187f6'
ELF_SHA = 'ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
PIN_SHA = '404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
ELF_BYTES = 305061192
STATES = ('live_readonly', 'implemented_local', 'design_only', 'blocked')


def need(value):
    if not value:
        raise ValueError('capability truth evidence rejected')


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def same(value, expected):
    need(type(value) is type(expected))
    if type(expected) is dict:
        exact(value, expected)
        for key in expected:
            same(value[key], expected[key])
    elif type(expected) is list:
        need(len(value) == len(expected))
        for a, b in zip(value, expected):
            same(a, b)
    else:
        need(value == expected)


def integer(value, low=0, high=9007199254740991):
    need(type(value) is int and low <= value <= high)
    return value


def digest(value):
    need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value))
    return value


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def text(value, maximum=2048, empty=True):
    need(type(value) is str and len(value.encode('utf-16-le')) // 2 <= maximum and (empty or value))
    need(not any(ord(c) <= 31 or 127 <= ord(c) <= 159 or 0x202a <= ord(c) <= 0x202e or
                 0x2066 <= ord(c) <= 0x2069 or 0xd800 <= ord(c) <= 0xdfff for c in value))
    return value


def decode(raw, floats=False):
    need(type(raw) is bytes and 0 < len(raw) <= 32 << 20)
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))
    def walk(v, depth=0):
        need(depth <= 24)
        if type(v) is dict:
            need(len(v) <= 8192)
            for k, child in v.items():
                need(type(k) is str)
                walk(child, depth + 1)
        elif type(v) is list:
            need(len(v) <= 16384)
            for child in v:
                walk(child, depth + 1)
        elif type(v) is str:
            need(len(v) <= 24 << 20 and not any(0xd800 <= ord(c) <= 0xdfff for c in v))
        else:
            need(v is None or type(v) in (bool, int) or floats and type(v) is float and math.isfinite(v))
    walk(value)
    return value


def no_symlinks(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        need(not item.is_symlink())
    return path


def read(path, maximum=16 << 20):
    path = no_symlinks(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after, named = os.fstat(fd), path.lstat()
        # Windows lstat/fstat expose different ctime semantics; compare ctime
        # within each observation channel, as the existing readonly primitive
        # does. All inode/mode/size/mtime identities still match cross-channel.
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_nlink)
        need(identity(before) == identity(opened) == identity(after) == identity(named)
             and before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns
             and len(raw) == before.st_size)
        return bytes(raw)
    finally:
        os.close(fd)


def unbase64(value, maximum):
    need(type(value) is str and 0 < len(value) <= (maximum + 2) // 3 * 4)
    raw = base64.b64decode(value, validate=True)
    need(0 < len(raw) <= maximum and base64.b64encode(raw).decode('ascii') == value)
    return raw


def json_lines(raw, count, row_bytes, floats=False):
    need(raw.endswith(b'\n'))
    rows = raw.splitlines()
    need(0 < len(rows) <= count and all(0 < len(r) <= row_bytes for r in rows))
    return [decode(r, floats) for r in rows]


def safe_path(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+', value) and
         not value.startswith('/') and all(p not in ('', '.', '..') for p in value.split('/')))
    return value


def timestamp(value, seconds=False):
    text(value, 35, False)
    pattern = r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)'
    match = re.fullmatch(pattern + (r'Z' if seconds else r'(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)'), value)
    need(match)
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    need(1 <= month <= 12 and 1 <= day <= days[month - 1] and hour <= 23 and minute <= 59 and second <= 59)
    if not seconds and match[8] != 'Z':
        need(int(match[8][1:3]) <= 23 and int(match[8][4:]) <= 59)
    return year, month, day, hour, minute, second


def png(raw, width, height):
    need(raw.startswith(b'\x89PNG\r\n\x1a\n'))
    at, kinds, compressed, header = 8, [], bytearray(), None
    while at < len(raw):
        need(at + 12 <= len(raw))
        n = struct.unpack('>I', raw[at:at + 4])[0]
        need(n <= 4 << 20 and at + n + 12 <= len(raw))
        kind, body = raw[at + 4:at + 8], raw[at + 8:at + n + 8]
        need(zlib.crc32(kind + body) & 0xffffffff == struct.unpack('>I', raw[at + n + 8:at + n + 12])[0])
        kinds.append(kind)
        at += n + 12
        if kind == b'IHDR':
            need(header is None and len(kinds) == 1 and n == 13)
            header = struct.unpack('>IIBBBBB', body)
        elif kind == b'IDAT':
            compressed.extend(body)
        elif kind == b'IEND':
            need(n == 0 and at == len(raw))
        else:
            need(kind in (b'sRGB', b'gAMA', b'cHRM', b'pHYs', b'tEXt', b'iTXt'))
    need(header is not None and kinds[-1:] == [b'IEND'] and kinds.count(b'IEND') == 1 and b'IDAT' in kinds)
    need(all(k == b'IDAT' for k in kinds[kinds.index(b'IDAT'):-1]))
    w, h, depth, color, compression, filtering, interlace = header
    need((w, h) == (width, height) and depth == 8 and color in (2, 6) and compression == filtering == interlace == 0)
    stride = width * (3 if color == 2 else 4) + 1
    z = zlib.decompressobj()
    pixels = z.decompress(bytes(compressed), stride * height + 1)
    need(z.eof and not z.unused_data and not z.unconsumed_tail and len(pixels) == stride * height)
    need(all(pixels[i * stride] <= 4 for i in range(height)))


def keys(c, value, name, nested=False):
    exact(value, c['nestedExactKeys' if nested else 'exactKeySchemas'][name])


def scope(profile, subscription=False):
    configured = profile == 'backend_configured'
    return dict(tenantId='capability-truth-lab' if configured else '', siteId='isolated' if configured else '',
                environment='candidate', objectType='subscription-store' if subscription else 'control-plane', objectId='local')


def identity(c, value, name, commit, engine, profile, fixture):
    keys(c, value, name)
    schema = 'supervisor' if name in ('inputs.json', 'isolation.json', 'processes.json') else {
        'driver.json': 'driver', 'runtime-facts.json': 'runtime', 'storage-readback.json': 'storage'}[name]
    for k, v in dict(schema=c['schemaNames'][schema], sourceCommit=commit, engine=engine, profile=profile,
                     fixtureId=fixture, scenario=c['scenario'], production=False).items():
        same(value[k], v)


def validate_build(c, build, commit):
    keys(c, build, 'build.json')
    same(build['schema'], c['schemaNames']['build'])
    same(build['sourceCommit'], commit)
    same(build['production'], False)
    same(build['authorization'], 'BLOCKED')
    same(build['goVersion'], 'go1.23.12')
    same(build['nodeVersion'], 'v22.23.3')
    same(build['moduleMode'], 'vendor')
    same(build['goDependencyDownloads'], False)
    keys(c, build['server'], 'build.server', True)
    same(build['server']['name'], 'server')
    integer(build['server']['bytes'], 1, 128 << 20)
    digest(build['server']['sha256'])
    rows = build['distFiles']
    need(type(rows) is list and 4 <= len(rows) <= 512)
    files = {}
    for row in rows:
        keys(c, row, 'byteRecord', True)
        p = safe_path(row['path'])
        need(p not in files and (p in ('index.html', 'trust.html', '.vite/manifest.json') or p.startswith('assets/')))
        integer(row['bytes'], 1, 16 << 20)
        digest(row['sha256'])
        files[p] = row
    need(list(files) == sorted(files) and {'index.html', 'trust.html', '.vite/manifest.json'} <= set(files))
    raw = unbase64(build['manifestBase64'], c['captureRules']['bounds']['manifestBytes'])
    same(dict(bytes=len(raw), sha256=sha(raw)), {k: files['.vite/manifest.json'][k] for k in ('bytes', 'sha256')})
    manifest = decode(raw)
    need(type(manifest) is dict and 'index.html' in manifest)
    fields = {'file', 'src', 'isEntry', 'isDynamicEntry', 'imports', 'dynamicImports', 'css', 'assets', 'name', 'names'}
    for name, row in manifest.items():
        text(name, 512, False)
        need(type(row) is dict and set(row) <= fields and 'file' in row and row['file'] in files)
        for flag in ('isEntry', 'isDynamicEntry'):
            if flag in row:
                need(type(row[flag]) is bool)
        for field in ('src', 'name'):
            if field in row:
                text(row[field], 512)
        if 'names' in row:
            need(type(row['names']) is list and len(row['names']) <= 512)
            for n in row['names']:
                text(n, 512)
        for field in ('imports', 'dynamicImports', 'css', 'assets'):
            if field in row:
                need(type(row[field]) is list and len(row[field]) <= 512 and len(set(row[field])) == len(row[field]))
                need(all(type(v) is str and v in (manifest if field.endswith('Imports') or field == 'imports' else files) for v in row[field]))
    need(manifest['index.html'].get('isEntry') is True)
    def closure(dynamic):
        found, seen, todo = set(), set(), ['index.html']
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            seen.add(key)
            row = manifest[key]
            found.update([row['file'], *row.get('css', [])])
            if dynamic:
                found.update(row.get('assets', []))
            todo.extend(row.get('imports', []))
            if dynamic:
                todo.extend(row.get('dynamicImports', []))
        need(all(p.startswith('assets/') and re.fullmatch(r'assets/[A-Za-z0-9_.-]+', p) for p in found))
        return {'/' + p for p in found}
    return files, closure(False), closure(True)


CONFIGURED_IDENTITY_PUBLIC_TEXTS = {
    ('evidence', 0): '受保护的 /api/v1/operations 接口使用严格 Bearer 身份文件',
    ('limitations', 0): '仅为本地高熵静态 Bearer 凭据哈希，不是密码登录、会话、MFA、SSO 或令牌轮换服务',
}


def configured_identity_source_texts(registry_raw):
    """Recognize this reviewed source subset, never a general Go evaluator."""
    need(type(registry_raw) is bytes and 0 < len(registry_raw) <= 1 << 20)
    registry = registry_raw.decode('utf-8')
    literal = r'("(?:[^"\\\r\n]|\\.)*")'
    pattern = (r'if facts\.IdentityConfigured \{\s*identityState = StateImplementedLocal\s*'
               r'identityEvidence = \[\]string\{' + literal + r'\}\s*'
               r'identityLimitations = \[\]string\{\s*' + literal + r',\s*' + literal + r',\s*\}\s*\}')
    matches = list(re.finditer(pattern, registry))
    need(len(matches) == 1)
    need(len(re.findall(r'\bidentityEvidence\s*=\s*\[\]string', registry)) == 1
         and len(re.findall(r'\bidentityLimitations\s*=\s*\[\]string', registry)) == 1)
    values = [json.loads(value) for value in matches[0].groups()]
    need(all(type(value) is str for value in values))
    result = {('evidence', 0): values[0], ('limitations', 0): values[1]}
    same(result, CONFIGURED_IDENTITY_PUBLIC_TEXTS)
    # The remaining literal is not a Bearer exception and must not introduce
    # another credential-shaped string into the recognized source block.
    need('Bearer ' not in values[2] and 'PRIVATE KEY' not in values[2])
    return result


def read_configured_identity_source(repo, commit):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    return configured_identity_source_texts(git_file(repo, commit, 'chengwang/internal/capability/registry.go'))


def public_body_fence(c, raw, kind, profile, source_texts=None):
    """Only two complete, source-checked documentation strings are exempt."""
    need(type(raw) is bytes and kind in c['captureRules']['kindEnum'] and profile in c['profiles'])
    if source_texts is not None:
        need(type(source_texts) is dict and all(type(key) is tuple and len(key) == 2
             and type(key[0]) is str and type(key[1]) is int and key[1] == 0 for key in source_texts))
        same(source_texts, CONFIGURED_IDENTITY_PUBLIC_TEXTS)
    need(b'PRIVATE KEY' not in raw)
    if kind == 'ASSET':
        return
    if kind != 'CAPABILITIES':
        need(b'Bearer ' not in raw)
        return
    value = capability(c, raw, profile)
    def strings(item, path=()):
        if type(item) is dict:
            for key, child in item.items():
                yield path + (key,), key
                yield from strings(child, path + (key,))
        elif type(item) is list:
            for index, child in enumerate(item):
                yield from strings(child, path + (index,))
        elif type(item) is str:
            yield path, item
    for path, line in strings(value):
        need('PRIVATE KEY' not in line)
        if 'Bearer ' not in line:
            continue
        need(profile == 'backend_configured' and source_texts is not None)
        need(len(path) == 4 and path[0] == 'capabilities' and type(path[1]) is int
             and path[2:] in CONFIGURED_IDENTITY_PUBLIC_TEXTS)
        need(value['capabilities'][path[1]]['id'] == 'real_authentication')
        same(line, source_texts[path[2:]])


def validate_captures(c, rows, files, required, allowed, *, profile='default', source_texts=None):
    bounds = c['captureRules']['bounds']
    need(type(rows) is list and 4 <= len(rows) <= bounds['requests'])
    ids, starts, kinds, total = {}, set(), {}, 0
    for i, row in enumerate(rows, 1):
        keys(c, row, 'captures.jsonl[]')
        same(row['schema'], c['schemaNames']['capture'])
        same(row['ordinal'], i)
        n = integer(row['requestOrdinal'], 1, bounds['requests'])
        same(row['requestId'], 'r' + str(n))
        need(n not in starts)
        starts.add(n)
        same(row['method'], 'GET')
        same(row['status'], 200)
        same(row['authorizationPresent'], False)
        same(row['requestPublic'], None)
        need(row['kind'] in c['captureRules']['kindEnum'])
        kind, path = row['kind'], row['path']
        if kind == 'DOCUMENT':
            same(path, '/')
            relative = 'index.html'
        elif kind == 'ASSET':
            need(path in allowed)
            relative = path[1:]
        else:
            same(path, '/api/v1/' + ('snapshot' if kind == 'SNAPSHOT' else 'capabilities'))
            relative = None
        raw = unbase64(row['responseBase64'], bounds['bodyAsset'] if relative else bounds['bodyAPI'])
        total += len(raw)
        need(total <= bounds['decodedTotal'])
        same(row['responseBytes'], len(raw))
        same(row['responseSHA256'], sha(raw))
        public_body_fence(c, raw, kind, profile, source_texts)
        if relative:
            same(dict(bytes=len(raw), sha256=sha(raw)), {k: files[relative][k] for k in ('bytes', 'sha256')})
        for name in ('startedWallTimeUs', 'startTimeUs', 'headerTimeUs', 'endTimeUs'):
            integer(row[name], 1)
        need(row['headerTimeUs'] >= row['startTimeUs'] and row['endTimeUs'] >= row['startTimeUs'])
        keys(c, row['terminal'], 'capture.terminal', True)
        same(row['terminal']['event'], 'FINISH')
        integer(row['terminal']['encodedDataLength'], 0, 16 << 20)
        ids[row['requestId']] = row
        kinds.setdefault(kind, []).append(row)
    need(starts == set(range(1, len(rows) + 1)))
    need(len(kinds.get('DOCUMENT', [])) == len(kinds.get('SNAPSHOT', [])) == 1 and len(kinds.get('CAPABILITIES', [])) == 2)
    assets = [r['path'] for r in kinds.get('ASSET', [])]
    need(len(assets) <= bounds['assets'] and len(set(assets)) == len(assets) and required <= set(assets))
    return ids, kinds


def validate_events(c, driver, captures):
    events = driver['events']
    bound = c['captureRules']['bounds']
    need(type(events) is list and 1 <= len(events) <= bound['events'])
    counts = {k: 0 for k in c['eightZero']}
    codes = dict(zip(c['eventContract']['errors'], ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'assetErrors', 'forbiddenRequests', 'captureErrors')))
    requests, headers, finished, captured = {}, set(), {}, set()
    failures = set()
    meta = None
    for seq, e in enumerate(events, 1):
        need(type(e) is dict and e.get('type') in c['eventContract']['tags'] and len(canonical(e)) <= bound['eventRowBytes'])
        keys(c, e, 'driver.events.' + e['type'], True)
        same(e['seq'], seq)
        t = e['type']
        need(meta is None)
        if t == 'META':
            meta = e
            continue
        rid = e.get('requestId')
        if t == 'ERROR':
            need(rid is None or rid in requests)
            need(e['code'] in codes)
            counts[codes[e['code']]] += 1
            continue
        if t == 'REQUEST':
            same(e['requestOrdinal'], len(requests) + 1)
            same(rid, 'r' + str(e['requestOrdinal']))
            need(rid not in requests and len(requests) < bound['requests'])
            same(e['method'], 'GET')
            same(e['sameOrigin'], True)
            for k in ('queryPresent', 'fragmentPresent', 'userInfoPresent', 'authorizationPresent', 'cookiePresent', 'bodyPresent'):
                same(e[k], False)
            need(rid in captures)
            for k in ('kind', 'path', 'method', 'requestOrdinal'):
                same(e[k], captures[rid][k])
            requests[rid] = e
            continue
        need(rid in requests)
        if t == 'HEADERS':
            need(rid not in headers and rid not in finished and rid not in failures)
            same(e['status'], 200)
            for k in ('setCookiePresent', 'redirected', 'diskCache', 'serviceWorker'):
                same(e[k], False)
            r = captures[rid]
            expected = 'HTML' if r['kind'] == 'DOCUMENT' else 'JSON' if r['kind'] != 'ASSET' else {
                '.js': 'JS', '.css': 'CSS', '.svg': 'SVG', '.png': 'PNG', '.woff': 'FONT', '.woff2': 'FONT', '.ttf': 'FONT'} .get(Path(r['path']).suffix)
            need(expected is not None)
            same(e['mimeClass'], expected)
            headers.add(rid)
        elif t == 'FINISH':
            need(rid in headers and rid not in finished and rid not in failures)
            same(e['encodedDataLength'], captures[rid]['terminal']['encodedDataLength'])
            finished[rid] = len(finished) + 1
            same(captures[rid]['ordinal'], finished[rid])
        elif t == 'CAPTURE':
            need(rid in finished and rid not in captured)
            same(e['captureOrdinal'], finished[rid])
            for k in ('responseBytes', 'responseSHA256'):
                same(e[k], captures[rid][k])
            captured.add(rid)
        elif t == 'NET_FAIL':
            need(rid not in finished and rid not in failures)
            counts['failedRequests'] += 1
            failures.add(rid)
    need(meta is not None)
    for k, v in dict(requests=len(requests), headers=len(headers), finished=len(finished), failed=len(failures),
                     captured=len(captured), pending=0, tasks=0, mutations=0, overflow=False).items():
        same(meta[k], v)
    integer(meta['ignoredFavicon'], 0, 4)
    need(set(requests) == headers == set(finished) == captured == set(captures) and not failures)
    exact(driver['counters'], c['eightZero'])
    same(driver['counters'], counts)
    need(all(v == 0 for v in counts.values()))
    return counts


def capability(c, raw, profile):
    value = decode(raw)
    exact(value, ('generatedAt', 'productionControlEnabled', 'overallState', 'capabilities'))
    timestamp(value['generatedAt'], True)
    same(value['productionControlEnabled'], False)
    same(value['overallState'], 'foundation')
    items = value['capabilities']
    need(type(items) is list and len(items) == len(c['frozenRegistrySourceProjection']) == 18)
    ids = set()
    for item, frozen in zip(items, c['frozenRegistrySourceProjection']):
        exact(item, ('id', 'domain', 'name', 'state', 'readOnly', 'evidence', 'limitations'))
        need(type(item['id']) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,127}', item['id']) and item['id'] not in ids)
        ids.add(item['id'])
        for k in ('id', 'domain', 'name', 'readOnly'):
            same(item[k], frozen[k])
        text(item['domain'], 64, False)
        text(item['name'], 160, False)
        need(item['state'] in STATES)
        for field in ('evidence', 'limitations'):
            need(type(item[field]) is list and len(item[field]) <= 32 and (field == 'evidence' or item[field]))
            for line in item[field]:
                text(line, 2048, False)
        source = frozen['stateSource']
        if source in ('StateImplementedLocal', 'StateDesignOnly'):
            same(item['state'], 'implemented_local' if source == 'StateImplementedLocal' else 'design_only')
        for field in ('evidence', 'limitations'):
            if field in frozen:
                same(item[field], frozen[field])
    by_id = {i['id']: i for i in items}
    for key, state in c['profilePolicies'][profile]['selectedStates'].items():
        same(by_id[key]['state'], state)
    need(by_id['local_evidence_chain']['state'] in ('blocked', 'implemented_local'))
    if profile == 'backend_configured':
        same(by_id['durable_operation_control']['state'], by_id['local_evidence_chain']['state'])
    return value


class Snapshot:
    """Independent Python implementation of the current bounded wire subset."""
    def __init__(self):
        self.characters, self.items = 0, 0

    def txt(self, v, maximum=256):
        text(v, maximum)
        self.characters += len(v.encode('utf-16-le')) // 2
        need(self.characters <= 1 << 20)
        return v


    def arr(self, v, fn, maximum=1024, optional=False):
        if v is None and not optional:
            return []
        need(type(v) is list and len(v) <= maximum)
        self.items += len(v)
        need(self.items <= 16384)
        return [fn(x) for x in v]

    def strings(self, v, maximum=1024, width=256, optional=False):
        return self.arr(v, lambda x: self.txt(x, width), maximum, optional)

    def ident(self, v, proxy=False):
        self.txt(v, 48 if proxy else 128)
        if proxy:
            need(re.fullmatch('[a-z][a-z0-9_-]{1,47}', v))
        else:
            need(1 <= len(v) <= 64 and unicodedata.category(v[0])[0] in ('L', 'N') and
                 all(unicodedata.category(ch)[0] in ('L', 'N') or ch in '._ -' for ch in v))
        return v

    @staticmethod
    def obj(v, required, optional=()):
        need(type(v) is dict and set(required) <= set(v) <= set(required) | set(optional))
        return v

    def row(self, v, kind):
        definitions = {
            'business': ('id name strategy activeRoute status', ''),
            'pool': ('name region latencyMs lossRate available total status', ''),
            'event': ('at type reason result', ''),
            'policy': ('id name domains strategy candidates fallback skipEmptyPools failuresToSwitch probeIntervalSec sessionStickyMin switchCooldownSec', 'requireCapabilities'),
            'node': ('id name members', 'capabilities'),
            'interface': ('id name type core listen port udp lanAccess authMode tls accessScope maxConnections idleTimeoutSec rateLimitMbps auditEnabled enabled status routingProfile', 'authReference tlsReference allowedCidrs description')}
        required, optional = definitions[kind]
        self.obj(v, required.split(), optional.split())
        if 'id' in v:
            self.ident(v['id'], kind == 'interface')
        strings = {'name': 160, 'strategy': 256, 'activeRoute': 256, 'status': 256, 'region': 160,
                   'reason': 2048, 'result': 2048, 'fallback': 256, 'core': 64, 'listen': 256,
                   'routingProfile': 256, 'authReference': 256, 'tlsReference': 256, 'description': 2048}
        for k, width in strings.items():
            if k in v:
                self.txt(v[k], width)
        for k in ('skipEmptyPools', 'udp', 'lanAccess', 'tls', 'auditEnabled', 'enabled'):
            if k in v:
                need(type(v[k]) is bool)
        for k in ('latencyMs', 'available', 'total', 'port', 'maxConnections', 'idleTimeoutSec', 'rateLimitMbps'):
            if k in v:
                integer(v[k], 0, {'port': 65535, 'maxConnections': 1000000, 'idleTimeoutSec': 86400, 'rateLimitMbps': 100000}.get(k, 9007199254740991))
        for k in ('failuresToSwitch', 'probeIntervalSec', 'sessionStickyMin', 'switchCooldownSec'):
            if k in v:
                integer(v[k], -9007199254740991)
        if kind == 'pool':
            need(type(v['lossRate']) in (int, float) and math.isfinite(v['lossRate']) and 0 <= v['lossRate'] <= 100 and v['available'] <= v['total'])
        if kind == 'event':
            timestamp(v['at'])
            self.txt(v['type'])
        if kind == 'interface':
            k = self.txt(v['type'], 32)
            need('\ufeff' not in k and k.strip().lower() in ('http', 'socks5', 'mixed', 'tun', 'tproxy', 'redirect', 'api'))
            need(v['authMode'] in ('none', 'password', 'token', 'mtls') and v['accessScope'] in ('local', 'lan', 'vpn', 'custom'))
            if 'allowedCidrs' in v:
                self.strings(v['allowedCidrs'], 1024, 128, True)
        for k, maximum, width in [('domains', 1024, 253), ('candidates', 1024, 256), ('members', 4096, 256),
                                  ('requireCapabilities', 1024, 256), ('capabilities', 1024, 256)]:
            if k in v:
                self.strings(v[k], maximum, width, k in ('capabilities', 'requireCapabilities'))
        return v

    def rows(self, value, kind, key=None, maximum=1024):
        rows = self.arr(value, lambda x: self.row(x, kind), maximum)
        if key:
            ids = [key(r) for r in rows]
            need(len(ids) == len(set(ids)))
        return rows

    def parse(self, raw):
        v = decode(raw, True)
        exact(v, 'product version mode status dataSource publishLocked businesses pools interfaces events draft'.split())
        for key in ('product', 'version', 'mode', 'status'):
            self.txt(v[key], 64 if key == 'mode' else 256)
        same(v['dataSource'], 'demo')
        need(type(v['publishLocked']) is bool)
        self.rows(v['businesses'], 'business', lambda r: r['id'])
        self.rows(v['pools'], 'pool', lambda r: (r['name'], r['region']))
        self.rows(v['interfaces'], 'interface', lambda r: r['id'])
        self.rows(v['events'], 'event', maximum=4096)
        d = v['draft']
        exact(d, 'name baseVersion businesses pools dns'.split())
        self.txt(d['name'], 160)
        self.txt(d['baseVersion'])
        self.rows(d['businesses'], 'policy', lambda r: r['id'])
        self.rows(d['pools'], 'node', lambda r: r['id'])
        dns = d['dns']
        exact(dns, 'domesticResolvers overseasResolvers hijackPort53 leakProtection'.split())
        for k in ('domesticResolvers', 'overseasResolvers'):
            self.strings(dns[k], 1024, 2048)
        need(type(dns['hijackPort53']) is bool and type(dns['leakProtection']) is bool)
        return v


def git(repo, *args, input_bytes=None):
    p = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args], input=input_bytes,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    need(p.returncode == 0)
    return p.stdout


def git_file(repo, commit, path):
    safe_path(path)
    return git(repo, 'show', commit + ':' + path)


def source_bindings(c, iso, inputs, build, repo, commit):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    no_symlinks(repo)
    same(iso['sourceFilesBefore'], iso['sourceFilesAfter'])
    same(iso['hostBefore'], iso['hostAfter'])
    rows = iso['sourceFilesBefore']
    need(type(rows) is list and 1 <= len(rows) <= 8192)
    listed = [p.decode('utf-8') for p in git(repo, 'ls-tree', '-r', '-z', '--name-only', commit, '--', 'chengwang', '.github/workflows').split(b'\0') if p]
    source = {}
    for row in rows:
        keys(c, row, 'byteRecord', True)
        path = safe_path(row['path'])
        need(path not in source and path.startswith(('chengwang/', '.github/workflows/')))
        integer(row['bytes'], 0, 128 << 20)
        digest(row['sha256'])
        source[path] = row
    need(set(source) == set(listed))
    request = ''.join(commit + ':' + path + '\n' for path in source).encode('utf-8')
    raw = git(repo, 'cat-file', '--batch', input_bytes=request)
    at = 0
    blobs = {}
    for path, row in source.items():
        end = raw.index(b'\n', at)
        header = raw[at:end].decode('ascii').split()
        need(len(header) == 3 and header[1] == 'blob')
        n = int(header[2])
        need(0 <= n <= 128 << 20)
        blob = raw[end + 1:end + 1 + n]
        need(len(blob) == n and raw[end + 1 + n:end + 2 + n] == b'\n')
        need(hashlib.sha1(b'blob ' + str(n).encode() + b'\0' + blob).hexdigest() == header[0])
        same(dict(bytes=n, sha256=sha(blob)), {k: row[k] for k in ('bytes', 'sha256')})
        blobs[path] = blob
        at = end + n + 2
    same(at, len(raw))
    same(iso['hostBefore']['sourceSHA256'], sha(canonical(rows)))
    # Validate the executable checker and contract themselves, not only captured source claims.
    same(read(Path(__file__)), blobs[OWN_PATH])
    same(read(HERE / 'contract.json'), blobs[CONTRACT_PATH])
    same(decode(blobs[CONTRACT_PATH]), c)
    copied = {}
    need(type(inputs['copiedInputs']) is list and len(inputs['copiedInputs']) <= 8192)
    for row in inputs['copiedInputs']:
        keys(c, row, 'byteRecord', True)
        p = row['path']
        need(type(p) is str and p not in copied)
        safe_path(p.removesuffix(':launcher'))
        integer(row['bytes'], 0, 512 << 20)
        digest(row['sha256'])
        copied[p] = row
        if p.startswith('chengwang/'):
            original = source.get(p.removesuffix(':launcher'))
            need(original is not None)
            same({k: row[k] for k in ('bytes', 'sha256')}, {k: original[k] for k in ('bytes', 'sha256')})
        else:
            need(p.startswith(('chrome/', 'npm/playwright-core/', 'dist/')) or p in ('toolchain/node', 'toolchain/server', 'build/report.json'))
    required = {
        CONTRACT_PATH, 'chengwang/deploy/browser-scene-supervisor/supervisor.py',
        'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
        'chengwang/deploy/capability-truth-browser/capability_truth_scene.py',
        'chengwang/deploy/capability-truth-browser/run_capability_truth.py',
        'chengwang/tools/capability-truth-browser/ui-cli.mjs',
        'chengwang/tools/capability-truth-browser/ui-driver.mjs',
        'chengwang/tools/capability-truth-browser/ui-dom.mjs',
        'chengwang/tools/capability-truth-browser/ui-contract.mjs',
        'chengwang/tools/subscription-ui-browser/ui-driver.mjs',
        'chengwang/tools/subscription-ui-browser/ui-contract.mjs',
        'chengwang/tools/subscription-ui-browser/navigation-diagnostics.mjs',
        'chengwang/tools/subscription-ui-browser/navigation-diagnostics-contract.json',
        'chengwang/web/scripts/trust-browser-tls.mjs',
        'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py',
        'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py:launcher',
        'chrome/chrome', 'toolchain/node', 'toolchain/server', 'npm/playwright-core/package.json', 'build/report.json'}
    need(required <= set(copied))
    for k in ('bytes', 'sha256'):
        same(copied['toolchain/server'][k], build['server'][k])
    same({k: copied['chrome/chrome'][k] for k in ('bytes', 'sha256')}, dict(bytes=ELF_BYTES, sha256=ELF_SHA))
    same([dict(path=p[5:], bytes=r['bytes'], sha256=r['sha256']) for p, r in sorted(copied.items()) if p.startswith('dist/')], build['distFiles'])
    # Registry literals must be tied to this Git source, not just an editable contract.
    registry = blobs['chengwang/internal/capability/registry.go'].decode('utf-8')
    projection = []
    for m in re.finditer(r'ID: "([^"]+)", Domain: "([^"]+)", Name: "([^"]+)",\s*State: ([A-Za-z]+), ReadOnly: (true|false)', registry):
        projection.append(dict(id=m[1], domain=m[2], name=m[3], stateSource=m[4], readOnly=m[5] == 'true'))
    for m in re.finditer(r'designOnly\("([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)"\)', registry):
        projection.append(dict(id=m[1], domain=m[2], name=m[3], stateSource='StateDesignOnly', readOnly=True, evidence=[], limitations=[m[4]]))
    same(projection, c['frozenRegistrySourceProjection'])
    return source, copied, blobs


def validate_processes(c, p, iso, inputs, build, driver, pin, commit, engine, profile, fixture):
    for name, value in [('processes.json', p), ('isolation.json', iso), ('inputs.json', inputs)]:
        identity(c, value, name, commit, engine, profile, fixture)
    same(p['processScope'], PROCESS_TRUST)
    same(inputs['inputTrustScope'], INPUT_TRUST)
    same(iso['authorization'], 'BLOCKED')
    same(iso['deviceActionsExecuted'], False)
    same(iso['pythonBinaryProvenanceProven'], False)
    host = iso['hostBefore']
    keys(c, host, 'isolation.hostBefore/After', True)
    keys(c, iso['hostAfter'], 'isolation.hostBefore/After', True)
    for name, kind in [('netNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid'), ('userNamespace', 'user')]:
        need(type(host[name]) is str and re.fullmatch(kind + r':\[[0-9]+\]', host[name]))
    integer(host['portStart'], 0, 65535)
    digest(host['systemCASHA256'])
    digest(host['sourceSHA256'])
    same(iso['hostBefore'], iso['hostAfter'])
    lab = iso['lab']
    keys(c, lab, 'isolation.lab', True)
    keys(c, lab['namespaces'], 'record.namespaces', True)
    for k, value in lab['namespaces'].items():
        need(type(value) is str and re.fullmatch(k + r':\[[0-9]+\]', value))
    same(lab['namespaces']['user'], host['userNamespace'])
    for k, h in [('net', 'netNamespace'), ('mnt', 'mountNamespace'), ('pid', 'pidNamespace')]:
        need(lab['namespaces'][k] != host[h])
    same(lab['defaultIPv4Routes'], 0)
    same(lab['defaultIPv6Routes'], 0)
    same(lab['interfaces'], ['lo'])
    for k, required in [('sourceMount', {'ro', 'nosuid', 'nodev'}), ('bundleMount', {'ro', 'nosuid', 'nodev'}), ('tmpMount', {'rw', 'nosuid', 'nodev', 'noexec'})]:
        flags = lab[k]
        need(type(flags) is list and all(type(v) is str for v in flags) and len(flags) == len(set(flags)) and required <= set(flags))
    need(type(p['records']) is list and len(p['records']) == 3)
    records = {}
    for r in p['records']:
        keys(c, r, 'processes.records[]', True)
        need(r['role'] in ('server', 'controller', 'chrome') and r['role'] not in records)
        records[r['role']] = r
        integer(r['pid'], 2)
        need(type(r['startTime']) is str and re.fullmatch('[1-9][0-9]{0,19}', r['startTime']))
        digest(r['exeSHA256'])
        digest(r['argvSHA256'])
        same(r['uid'], [10001] * 4)
        same(r['gid'], [10001] * 4)
        same(r['groups'], [])
        same(r['noNewPrivs'], 1)
        same(r['namespaces'], lab['namespaces'])
        same(r['capabilities'], {k: '0000000000000000' for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')})
        same(r['limits'], dict(cpuSeconds=[180, 180], fileBytes=[32 << 20] * 2, openFiles=[1024] * 2, processes=[1024] * 2, coreBytes=[0, 0]))
        need(type(r['argv']) is list and 1 <= len(r['argv']) <= 128 and all(type(s) is str and len(s) <= 4096 for s in r['argv']))
        same(r['argvSHA256'], sha(b''.join(s.encode() + b'\0' for s in r['argv'])))
    need(len({r['pid'] for r in records.values()}) == 3)
    for k, v in dict(serverExitCode=0, controllerExitCode=0, forcedSignals=0, noLiveOwnedProcesses=True).items():
        same(p[k], v)
    chrome = driver['chrome']
    keys(c, chrome, 'driver.chrome', True)
    for k, v in dict(pid=records['chrome']['pid'], startTicks=int(records['chrome']['startTime']), uid=10001, exeBytes=ELF_BYTES,
                     exeSHA256=ELF_SHA, argvSHA256=records['chrome']['argvSHA256']).items():
        same(chrome[k], v)
    root = '/tmp/chengwang-subscription-ui-' + fixture
    bundle = '/tmp/chengwang-subscription-ui-tools-' + fixture
    same(chrome['profile'], root + '/chrome-profile')
    same(records['chrome']['exeSHA256'], ELF_SHA)
    same(records['server']['exeSHA256'], build['server']['sha256'])
    copied = {r['path']: r for r in inputs['copiedInputs']}
    same(records['controller']['exeSHA256'], copied['toolchain/node']['sha256'])
    same(records['server']['argv'], [bundle + '/server'])
    same(records['controller']['argv'], [bundle + '/node', bundle + '/source/chengwang/tools/capability-truth-browser/ui-cli.mjs',
         '--root', root, '--bundle', bundle, '--engine', engine, '--source-commit', commit])
    argv = records['chrome']['argv']
    same(argv[0], bundle + '/chrome/chrome')
    need('--no-sandbox' in argv and [v for v in argv if v.startswith('--user-data-dir')] == ['--user-data-dir=' + root + '/chrome-profile'])
    forbidden = {'--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors', '--allow-insecure-localhost', '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure'}
    need(not any(v.split('=', 1)[0] in forbidden for v in argv))
    close = driver['close']
    keys(c, close, 'driver.close', True)
    same(close['normalCloseCommandCompleted'], True)
    same(close['noLiveOwnedProcesses'], True)
    same(close['processScope'], 'CHROME_SESSION_AND_LAUNCHER_ONLY')
    same(close['chromeExit'], dict(schema='chengwang.subscription-ui-chrome-exit/v1', engine=engine, fixtureId=fixture,
         pid=chrome['pid'], startTicks=chrome['startTicks'], exitCode=0, joined=True, forced=False))
    same(close['launcherExit'], dict(code=0, signal=None) if engine == 'chrome-cdp' else None)
    validate_pin(c, pin, commit)
    return records


def validate_pin(c, pin, commit):
    keys(c, pin, 'pin-consumption.json')
    same(pin['schema'], 'chengwang.pinned-browser-consumption-verification/v1')
    same(pin['sourceCommit'], commit)
    same(pin['state'], 'PIN_ENFORCED_EXPANDED_NOT_EXECUTED')
    same(pin['pinSHA256'], PIN_SHA)
    for k in ('pinEnforced', 'allMemberCRCsVerified', 'actualExpandedFileHashesVerified'):
        same(pin[k], True)
    for k in ('browserExecuted', 'runtimeVersionProven', 'projectFixProven', 'publisherSignatureProven', 'production'):
        same(pin[k], False)
    same(pin['zip'], dict(bytes=202676171, sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853', md5Base64='5qChIL/Gh+8hZv73vzEakQ=='))
    keys(c, pin['elf'], 'pin.elf', True)
    same(pin['elf'], dict(path='chrome-linux64/chrome', bytes=ELF_BYTES, sha256=ELF_SHA, byteOrder='little',
         entryPoint=124443728, loadSegments=4, machine='x86_64', programHeaderCount=12, type='DYN', **{'class': 'ELF64'}))
    for k in ('sourceFilesVerified', 'expandedMemberCount', 'expandedBytes'):
        integer(pin[k], 1)
    digest(pin['expandedMembersSHA256'])
    text(pin['mode'], 128, False)
    need(type(pin['limitations']) is list and 1 <= len(pin['limitations']) <= 32)
    for s in pin['limitations']:
        text(s)


def runtime_facts(c, runtime, storage, records, commit, engine, profile, fixture):
    identity(c, runtime, 'runtime-facts.json', commit, engine, profile, fixture)
    identity(c, storage, 'storage-readback.json', commit, engine, profile, fixture)
    configured = profile == 'backend_configured'
    leaf = c['leafValues']
    same(runtime['scope'], scope(profile))
    same(storage['scope'], scope(profile))
    r = records['server']
    same(runtime['serverIdentity'], dict(pid=r['pid'], startTicks=int(r['startTime']), exeSHA256=r['exeSHA256'], argvSHA256=r['argvSHA256']))
    same(runtime['environment'], [dict(name=k, value=v) for k, v in sorted(c['profilePolicies'][profile]['env'].items())])
    same(runtime['identities'], leaf['identitiesConfigured' if configured else 'identitiesUnconfigured'])
    same(runtime['mihomo'], dict(configured=configured, endpointClass=leaf['endpointClass'] if configured else None))
    same(runtime['observer'], leaf['observerConfigured' if configured else 'observerUnconfigured'])
    same(runtime['probe'], dict(configured=False))
    same(runtime['subscription'], dict(configured=configured, writesEnabled=False, policyConfigured=False))
    same(runtime['writeGates'], dict(publish=False, operation=False, subscription=False))
    same(runtime['policyCatalog'], dict(configured=False))
    same(runtime['upstreamListener'], leaf['upstreamListener'])
    same(runtime['snapshotsProvider'], leaf['snapshotsProvider'])
    same(runtime['trustBoundary'], leaf['trustBoundary'])
    same(storage['trustBoundary'], leaf['trustBoundary'])
    counts = dict(constructed=configured, scope=scope(profile, True) if configured else None,
                  **{k: 0 for k in ('sourceCount', 'candidateCount', 'requestCount', 'auditCount', 'commandCount', 'approvalCount', 'privateNodesCount')})
    same(storage['subscriptionStore'], counts)
    same(storage['observationStore'], dict(constructed=configured))
    same(storage['operationStore'], dict(constructed=True, commandCount=0))
    same(storage['evidenceStore'], dict(constructed=True))


def verify_tls(c, certs, driver, captures):
    keys(c, certs, 'certificates.json')
    def der(pem):
        need(type(pem) is str and len(pem) <= 65536 and re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?', pem))
        return base64.b64decode(''.join(pem.splitlines()[1:-1]), validate=True)
    ca, leaf = der(certs['caPEM']), der(certs['leafPEM'])
    same(driver['normalTrust'], dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,', caSHA256=sha(ca), leafSHA256=sha(leaf), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True))
    tls = driver['tls']
    keys(c, tls, 'driver.tls', True)
    same(tls['securityState'], 'secure')
    need(tls['protocol'] in ('TLS 1.2', 'TLS 1.3') and type(tls['cipher']) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', tls['cipher']))
    for k, v in dict(caSHA256=sha(ca), leafSHA256=sha(leaf), leafSignatureVerified=True, ipSANVerified=True).items():
        same(tls[k], v)
    chain = driver['certificateChain']
    need(type(chain) is list and 1 <= len(chain) <= 2)
    same(tls['serverChainLength'], len(chain))
    same([unbase64(v, 65536) for v in chain], [leaf] if len(chain) == 1 else [leaf, ca])
    stamp = min(r['startedWallTimeUs'] for r in captures) // 1000000
    with tempfile.TemporaryDirectory(prefix='capability-offline-cert-') as temp:
        paths = [Path(temp) / n for n in ('ca.pem', 'leaf.pem')]
        for path, pem in zip(paths, (certs['caPEM'], certs['leafPEM'])):
            path.write_text(pem, encoding='ascii')
        p = subprocess.run(['openssl', 'verify', '-trusted', str(paths[0]), '-check_ss_sig', '-attime', str(stamp), '-purpose', 'sslserver',
                            '-verify_ip', '127.0.0.1', str(paths[1])], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=10, env={'PATH': os.environ.get('PATH', os.defpath), 'OPENSSL_CONF': os.devnull})
        need(p.returncode == 0)


def rect(c, value):
    keys(c, value, 'dom.controls[].rect', True)
    for v in value.values():
        need(type(v) in (int, float) and math.isfinite(v) and abs(v) <= 10000000)
    need(value['width'] >= 0 and value['height'] >= 0)


def check_text_tree(value):
    if type(value) is str:
        text(value)
    elif type(value) is list:
        need(len(value) <= 256)
        for item in value:
            check_text_tree(item)
    elif type(value) is dict:
        for item in value.values():
            check_text_tree(item)


def capability_dom(c, value, api):
    keys(c, value, 'dom.capabilities', True)
    same(value['heading'], '系统闭环')
    same(value['boundary'], dict(title='生产写入保持关闭', text='当前页面只展示能力证据，不会发布配置、切换节点或重启网络服务。', writeEnabled=False))
    expected_summary = []
    for state in STATES:
        label, description = c['statePresentation'][state]
        expected_summary.append(dict(stateClass='', label=label, count=str(sum(i['state'] == state for i in api['capabilities'])), description=description))
    same(value['summary'], expected_summary)
    meta = value['meta']
    keys(c, meta, 'dom.capabilities.meta', True)
    for k, v in dict(overallState=api['overallState'], generatedAtLabel='清单生成时间', capabilityCount=str(len(api['capabilities'])), productionLabel='未启用').items():
        same(meta[k], v)
    m = re.fullmatch(r'(\d{4})[/-](\d{1,2})[/-](\d{1,2}) (\d{1,2}):(\d\d):(\d\d)', meta['generatedAtText'])
    need(m is not None and tuple(map(int, m.groups())) == timestamp(api['generatedAt'], True))
    groups = {}
    for item in api['capabilities']:
        groups.setdefault(item['domain'], []).append(dict(id=item['id'], name=item['name'], stateClass='readiness-state ' + item['state'],
            stateLabel=c['statePresentation'][item['state']][0], readOnlyLabel='只读' if item['readOnly'] else '包含写入能力',
            evidenceLabel='可核验入口与实现依据', evidence=item['evidence'], emptyEvidenceLabel='' if item['evidence'] else '暂无可核验入口',
            limitationsLabel='当前限制', limitations=item['limitations']))
    same(value['groups'], [dict(domain=k, count=str(len(v)) + ' 项能力，每项分别展示证据与限制', rows=v) for k, v in groups.items()])


def overview_dom(c, value, snapshot):
    keys(c, value, 'dom.overview', True)
    expected = dict(status=snapshot['status'], mode=snapshot['mode'], badge='总览只读',
        boundaryText='总览仅展示数据边界；执行权限以服务端授权为准', demoAlertTitle='当前总览没有接入真实运行数据',
        demoAlertText='为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。',
        evidenceStrip=[dict(label=a, value=b, status=d, statusClass='status neutral') for a, b, d in [
            ('控制面模式', snapshot['mode'], '总览只读'), ('真实设备证据', '设备读回', '可查看'), ('业务评估', '未接入', '未知'), ('DNS 评估', '未接入', '未知')]],
        boundaryRows=[dict(domain=a, evidence=b, handling=d) for a, b, d in [
            ('Mihomo 运行状态', '已提供独立只读接口', '前往“设备读回”查看实时证据'),
            ('业务分流状态', '尚未接入实际数据', '不显示模拟正常或模拟故障'),
            ('节点能力评估', '尚未接入实际探测器', '不生成虚构延迟、丢包和可用率'),
            ('DNS 健康状态', '尚未接入实际探测器', '不生成虚构解析耗时和泄漏结论'),
            ('自动化与拓扑', '当前仅有产品设计', '不冒充已执行动作或实时流量路径')]],
        **{k: False for k in ('businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent')})
    same(value, expected)


def kernels_dom(c, value):
    keys(c, value, 'dom.kernels', True)
    kernel_rows = [('Mihomo', '未核验', '只读适配', '未核验', '实际状态请显式进入设备读回'),
        ('sing-box', '未核验', '适配目标', '尚未实现', '现代多协议与独立 DNS（规划）'),
        ('Xray', '未核验', '适配目标', '尚未实现', 'VMess / VLESS / Reality（规划）'),
        ('Hysteria', '未核验', '适配目标', '尚未实现', 'Hysteria2 / QUIC（规划）')]
    matrix = [('Shadowsocks', '原生', '原生', '适配'), ('VMess', '适配', '适配', '原生'), ('VLESS', '原生', '原生', '原生'),
        ('Trojan', '原生', '原生', '原生'), ('Hysteria2', '适配', '原生', '不支持'), ('TUIC', '适配', '原生', '不支持'),
        ('AnyTLS', '适配', '原生', '不支持'), ('WireGuard', '适配', '原生', '适配'), ('TUN / TProxy', '原生', '原生', '适配'),
        ('Rule Provider', '原生', '适配', '适配'), ('DNS 分流', '原生', '原生', '适配'), ('链式代理', '原生', '原生', '原生')]
    same(value, dict(heading='内核与协议', description='适配规划；尚无主机安装库存或实例运行证据。下列操作未接执行器，保持禁用。',
        rows=[dict(zip(('name', 'versionEvidence', 'scope', 'instanceState', 'boundary', 'statusClass'), [*r, 'status neutral'])) for r in kernel_rows],
        matrixHeading='能力矩阵', matrixDescription='参考规划，目标版本尚未逐项实测；不表示已安装或当前可用。',
        matrixRows=[dict(feature=r[0], cells=[dict(text='待核验（参考：' + cell + '）', className='support pending') for cell in r[1:]]) for r in matrix],
        evidenceHeading='Mihomo 实例证据', evidenceStatus='未核验', evidenceFields=[dict(label=a, value=b) for a, b in [
            ('可执行文件', '未核验，发现适配器尚未接入'), ('完整性校验', '尚未执行'), ('配置绑定', '未接入'),
            ('监听接口', '未核验'), ('重启与回滚', '执行器尚未实现'), ('业务健康', '需独立业务探测，不由控制器配置推导')]]))


def validate_dom(c, rows, captures, snapshot, reports):
    need(len(rows) == len(c['stepFences']) == 7)
    capture_by_ordinal = {r['ordinal']: r for r in captures}
    previous = 0
    clicked = {0: 'nav_kernels', 1: 'nav_capabilities', 2: 'refresh_capabilities', 4: 'nav_kernels', 5: 'nav_overview'}
    for ordinal, (row, step) in enumerate(zip(rows, c['stepFences']), 1):
        keys(c, row, 'dom.jsonl[]')
        same(row['schema'], c['schemaNames']['domRow'])
        same(row['ordinal'], ordinal)
        same(row['step'], step[0])
        same(row['mutationCount'], 0)
        count = integer(row['captureCount'], previous, len(captures))
        previous = count
        prefix = [capture_by_ordinal[i] for i in range(1, count + 1)]
        snapshots = [r for r in prefix if r['kind'] == 'SNAPSHOT']
        caps = [r for r in prefix if r['kind'] == 'CAPABILITIES']
        same(len(snapshots), step[3])
        same(len(caps), step[4])
        d = row['dom']
        keys(c, d, 'dom.dom', True)
        same(d['schema'], c['schemaNames']['dom'])
        page = '运行总览' if step[0].startswith('overview') else '内核与协议' if step[0].startswith('kernels') else '系统闭环'
        same(d['page'], page)
        for k in ('pageMounted', 'pageVisible', 'https'):
            same(d[k], True)
        same(d['environment'], dict(language='zh-CN', timeZone='UTC'))
        same(d['browserStorage'], dict(localEmpty=True, sessionEmpty=True, cookiesEmpty=True))
        check_text_tree(d)
        vp = d['viewport']
        keys(c, vp, 'dom.viewport', True)
        same(vp['width'], step[1])
        same(vp['height'], step[2])
        for k in ('scrollX', 'scrollY', 'clientWidth', 'scrollWidth'):
            integer(vp[k], 0, 1000000)
        need(vp['scrollWidth'] == vp['clientWidth'] <= vp['width'] and vp['clientWidth'] > 0 and vp['scrollX'] == vp['scrollY'] == 0)
        same(d['apiFence'], dict(snapshotCaptureOrdinal=snapshots[0]['ordinal'], capabilitiesCaptureOrdinals=[r['ordinal'] for r in caps]))
        keys(c, d['topbar'], 'dom.topbar', True)
        for k, expected in dict(product=snapshot['product'], sourceLabel='演示草稿', mode=snapshot['mode'], kernel='未核验').items():
            node = d['topbar'][k]
            keys(c, node, 'dom.topbar.node', True)
            same(node['text'], expected)
            need(type(node['visible']) is bool)
            if node['visible']:
                rect(c, node['rect'])
                need(node['rect']['width'] > 0 and node['rect']['height'] > 0)
            else:
                same(node['rect'], None)
        controls = d['controls']
        need(type(controls) is list and len(controls) == len(c['controlSlots']) == 11)
        by_key = {}
        for control, (key, label) in zip(controls, c['controlSlots']):
            keys(c, control, 'dom.controls[]', True)
            same(control['key'], key)
            present = key.startswith('nav_') or key == 'refresh_capabilities' and page == '系统闭环' or key.startswith('kernel_') and page == '内核与协议'
            same(control['present'], present)
            for k in ('visible', 'enabled', 'inViewport', 'unobstructed'):
                need(type(control[k]) is bool)
            if not present:
                same(control, dict(key=key, label=None, labelSource=None, present=False, visible=False, enabled=False, inViewport=False, unobstructed=False, rect=None))
            else:
                same(control['label'], label)
                same(control['labelSource'], 'ARIA_LABEL' if key.startswith('nav_') else 'VISIBLE_TEXT')
                same(control['enabled'], not key.startswith('kernel_'))
                if control['visible']:
                    rect(c, control['rect'])
                    need(control['rect']['width'] > 0 and control['rect']['height'] > 0)
                    r = control['rect']
                    same(control['inViewport'], r['x'] < vp['width'] and r['y'] < vp['height'] and r['x'] + r['width'] > 0 and r['y'] + r['height'] > 0)
                    if control['unobstructed']:
                        need(0 <= r['x'] + r['width'] / 2 < vp['width'] and 0 <= r['y'] + r['height'] / 2 < vp['height'])
                else:
                    same(control['rect'], None)
                    same(control['inViewport'], False)
                    same(control['unobstructed'], False)
                if key.startswith('nav_'):
                    same(control['visible'], True)
            by_key[key] = control
        if ordinal - 1 in clicked:
            ctl = by_key[clicked[ordinal - 1]]
            for k in ('present', 'visible', 'enabled', 'inViewport', 'unobstructed'):
                same(ctl[k], True)
        for field, active in [('overview', page == '运行总览'), ('kernels', page == '内核与协议'), ('capabilities', page == '系统闭环')]:
            if not active:
                same(d[field], None)
        if page == '运行总览':
            overview_dom(c, d['overview'], snapshot)
        elif page == '内核与协议':
            kernels_dom(c, d['kernels'])
        else:
            capability_dom(c, d['capabilities'], reports[caps[-1]['ordinal']])
    same(previous, len(captures))


def verify(directory, repo, commit, engine, profile):
    directory, repo = no_symlinks(directory), no_symlinks(repo)
    contract_raw = read(HERE / 'contract.json', 1 << 20)
    c = decode(contract_raw)
    need(c['schema'] == 'chengwang.capability-truth-browser-contract/v1' and engine in c['engines'] and profile in c['profiles'])
    need(set(p.name for p in directory.iterdir()) == set(c['publicFiles']))
    bounds = c['captureRules']['bounds']
    def limit(name):
        return bounds['driverFileBytes'] if name == 'driver.json' else bounds['domFileBytes'] if name == 'dom.jsonl' else bounds['captureFile'] if name == 'captures.jsonl' else c['pngFileBytesMax'] if name.endswith('.png') else c['buildFileBytesMax'] if name == 'build.json' else 16 << 20
    raw = {n: read(directory / n, limit(n)) for n in c['publicFiles']}
    need(all(b'PRIVATE KEY' not in b for b in raw.values()))
    driver = decode(raw['driver.json'], True)
    fixture = driver.get('fixtureId')
    need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture))
    identity(c, driver, 'driver.json', commit, engine, profile, fixture)
    same(driver['origin'], c['origin'])
    same(driver['scope'], scope(profile))
    same(driver['runtime'], True)
    for k in ('mockedResponses', 'injectedFetch', 'tlsBypass'):
        same(driver[k], False)
    keys(c, driver['browser'], 'driver.browser', True)
    need(driver['browser']['product'] in ('Chrome/157.0.8103.6', 'HeadlessChrome/157.0.8103.6'))
    same(driver['browser']['revision'], '@' + TAG)
    same(driver['browser']['protocolVersion'], '1.3')
    same(driver['steps'], [r[0] for r in c['stepFences']])
    build = decode(raw['build.json'])
    files, required, allowed = validate_build(c, build, commit)
    captures = json_lines(raw['captures.jsonl'], bounds['requests'], 12 << 20)
    public_texts = read_configured_identity_source(repo, commit) if profile == 'backend_configured' else None
    capture_ids, kinds = validate_captures(c, captures, files, required, allowed, profile=profile, source_texts=public_texts)
    validate_events(c, driver, capture_ids)
    same(driver['captures'], dict(path='captures.jsonl', bytes=len(raw['captures.jsonl']), sha256=sha(raw['captures.jsonl']), records=len(captures)))
    snapshot = Snapshot().parse(unbase64(kinds['SNAPSHOT'][0]['responseBase64'], bounds['bodyAPI']))
    same(snapshot['mode'], 'candidate')
    same(snapshot['publishLocked'], True)
    reports = {r['ordinal']: capability(c, unbase64(r['responseBase64'], bounds['bodyAPI']), profile) for r in kinds['CAPABILITIES']}
    dom = json_lines(raw['dom.jsonl'], 7, bounds['domRowBytes'], True)
    validate_dom(c, dom, captures, snapshot, reports)
    screenshots = driver['screenshots']
    expected_shots = [s for s in c['stepFences'] if s[5]]
    need(type(screenshots) is list and len(screenshots) == len(expected_shots) == 6)
    for item, step in zip(screenshots, expected_shots):
        keys(c, item, 'driver.screenshots[]', True)
        same(item['path'], step[5])
        same(item['step'], step[0])
        same(item['bytes'], len(raw[step[5]]))
        same(item['sha256'], sha(raw[step[5]]))
        same(item['viewport'], dict(width=step[1], height=step[2]))
        row = next(r for r in dom if r['step'] == step[0])
        for k in ('scrollX', 'scrollY'):
            same(item[k], row['dom']['viewport'][k])
        integer(item['capturedWallTimeUs'], min(r['startedWallTimeUs'] for r in captures))
        png(raw[step[5]], step[1], step[2])
    processes, iso, inputs = [decode(raw[n]) for n in ('processes.json', 'isolation.json', 'inputs.json')]
    records = validate_processes(c, processes, iso, inputs, build, driver, decode(raw['pin-consumption.json']), commit, engine, profile, fixture)
    source, copied, blobs = source_bindings(c, iso, inputs, build, repo, commit)
    same({k: copied['build/report.json'][k] for k in ('bytes', 'sha256')}, dict(bytes=len(raw['build.json']), sha256=sha(raw['build.json'])))
    runtime_facts(c, decode(raw['runtime-facts.json']), decode(raw['storage-readback.json']), records, commit, engine, profile, fixture)
    verify_tls(c, decode(raw['certificates.json']), driver, captures)
    need(raw == {n: read(directory / n, limit(n)) for n in c['publicFiles']} and read(HERE / 'contract.json') == contract_raw and read(Path(__file__)) == blobs[OWN_PATH])
    report = dict(schema=c['schemaNames']['report'], sourceCommit=commit, fixtureId=fixture, engine=engine, scenario=c['scenario'], profile=profile,
        outcome='PASS', scope=scope(profile), actualBrowser=driver['browser'], actualChromeELFSHA256=ELF_SHA, steps=7, screenshots=6,
        requests=len(captures), mutations=0, sourceGitBlobs=len(source), normalTLSOfflineVerifiedAtCapture=True, pinConsumed=True,
        rawCapabilitiesMatchedDOM=True, normalRefreshObserved=True, demoSeedSuppressionObserved=True,
        productionControlProven=False, businessAvailabilityProven=False, liveOverviewProven=False, liveProviderProven=False,
        deadlineFaultFlowProven=False, rbacCurrentSubjectProven=False, privateDatabaseRawIndependentlyVerified=False,
        screenshotVisualReviewProven=False, independentReproducibleBuildProven=False, processTrustBoundary=PROCESS_TRUST,
        storageTrustBoundary=c['leafValues']['trustBoundary'], counterTrustBoundary=COUNTER_TRUST,
        remaining=['live SnapshotProvider', 'real upstream and end-to-end business', 'deadline and fault browser paths',
                   'current-subject authentication and RBAC', 'independent private storage attestation', 'visual review', 'production'],
        evidenceSHA256={n: sha(raw[n]) for n in sorted(raw)}, production=False, authorization='BLOCKED')
    exact(report, c['reportExactKeys'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence', 'repo', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    parser.add_argument('--profile', required=True, choices=('default', 'backend_configured'))
    a = parser.parse_args()
    evidence, repo, output = no_symlinks(a.evidence), no_symlinks(a.repo), no_symlinks(a.report)
    need(not output.exists() and not output.is_relative_to(evidence) and not output.is_relative_to(repo))
    result = verify(evidence, repo, a.source_commit, a.engine, a.profile)
    with output.open('xb') as handle:
        handle.write(canonical(result) + b'\n')
        handle.flush()
        os.fsync(handle.fileno())
    print('CAPABILITY_TRUTH_INDEPENDENT=PASS scope=demo_configured_ui_only production=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CAPABILITY_TRUTH_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
