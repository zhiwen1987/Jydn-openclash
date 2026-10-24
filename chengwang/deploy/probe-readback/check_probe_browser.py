"""Independent verifier for public browser captures; never launches a browser."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import tempfile
import zlib

sys.dont_write_bytecode = True
import check_probe_readback as backend

SCHEMA = 'chengwang.probe-browser-runtime-gate/v1'
ENGINES = {'chrome-cdp': 'cdp', 'playwright': 'playwright'}
STAGES = ('fresh', 'cleared', 'withdrawn', 'expired')
IDS = ('limited', 'pass', 'restricted')
LAYERS = ('dns', 'connect', 'tls', 'http', 'business')
LABELS = {'unknown': '未评估', 'available': '可用', 'restricted': '业务受限', 'rate_limited': '限流'}
ORIGIN = 'https://127.0.0.1:17861'
need = backend.require
keys = backend.object_keys
integer = backend.integer
ns = backend.nanoseconds
sha = backend.sha
same = backend.identical


def capture_names(engine):
    need(engine in ENGINES)
    prefix = 'probe-browser-' + ENGINES[engine] + '-'
    names = {prefix + stage + '-' + kind + '.json' for stage in ('fresh', 'withdrawn', 'expired')
             for kind in ('status', 'details')}
    names |= {prefix + stage + '-dom.json' for stage in STAGES}
    names |= {prefix + stage + '-network.jsonl' for stage in STAGES}
    names |= {prefix + suffix + '.png' for suffix in
              ('fresh-desktop', 'fresh-mobile', 'withdrawn-desktop', 'expired-mobile')}
    need(len(names) == 18)
    return prefix, frozenset(names)


def png_dimensions(raw):
    """Validate complete non-interlaced 8-bit Chromium PNG framing and pixels.

    This is integrity/decodability, not OCR or an independent rendering witness.
    """
    need(type(raw) is bytes and 57 <= len(raw) <= 8 << 20 and raw[:8] == b'\x89PNG\r\n\x1a\n')
    at, parts, width, height, channels, ended = 8, [], 0, 0, 0, False
    seen_idat, ended_idat = False, False
    while at < len(raw):
        need(at + 12 <= len(raw))
        length = struct.unpack_from('>I', raw, at)[0]
        tag = raw[at + 4:at + 8]
        need(length <= 8 << 20 and re.fullmatch(rb'[A-Za-z]{4}', tag) is not None)
        end = at + 12 + length
        need(end <= len(raw))
        data = raw[at + 8:end - 4]
        need(zlib.crc32(tag + data) & 0xffffffff == struct.unpack_from('>I', raw, end - 4)[0])
        if at == 8:
            need(tag == b'IHDR' and length == 13)
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', data)
            integer(width, 320, 1600); integer(height, 1, 12000)
            need(depth == 8 and color in (2, 6) and compression == filtering == interlace == 0)
            channels = 3 if color == 2 else 4
        elif tag == b'IDAT':
            need(not ended_idat); seen_idat = True; parts.append(data)
        elif tag == b'IEND':
            need(length == 0 and seen_idat and end == len(raw)); ended = True
        else:
            need(tag != b'IHDR' and tag[0] & 32)
            if seen_idat: ended_idat = True
        at = end
        if ended: break
    need(ended)
    expected = height * (width * channels + 1)
    need(expected <= 80 << 20)
    decoder = zlib.decompressobj()
    try:
        pixels = decoder.decompress(b''.join(parts), expected + 1)
    except zlib.error:
        raise backend.Rejected('evidence-rejected') from None
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and len(pixels) == expected)
    stride = width * channels + 1
    need(all(pixels[row * stride] <= 4 for row in range(height)))
    return width, height


def raw_reference(ref, raw, name, timed=False):
    keys(ref, {'name', 'bytes', 'sha256'} | ({'capturedAt'} if timed else set()))
    need(ref['name'] == name and type(ref['bytes']) is int and ref['bytes'] == len(raw)
         and ref['sha256'] == sha(raw))
    if timed: ns(ref['capturedAt'])


def dom_projection(value, stage, detail, observed, deadline):
    keys(value, {'url', 'title', 'heading', 'viewport', 'scrollWidth', 'clientWidth', 'inputType',
                 'tokenEmpty', 'storageEmpty', 'cookiesEmpty', 'detailMounted', 'catalogText', 'targets', 'overlayCount'})
    need(value['url'] == ORIGIN + '/' and value['title'] == '澄网 · 网络代理与路由平台'
         and value['heading'] == '代理节点观测' and value['inputType'] == 'password')
    keys(value['viewport'], {'width', 'height'})
    integer(value['viewport']['width'], 320, 1600); integer(value['viewport']['height'], 320, 1200)
    need(type(value['clientWidth']) is int and value['clientWidth'] == value['viewport']['width'])
    integer(value['scrollWidth'], 1, value['clientWidth']); integer(value['overlayCount'], 0, 0)
    need(type(value['tokenEmpty']) is bool and value['storageEmpty'] is True and value['cookiesEmpty'] is True)
    need(type(value['targets']) is list)
    if stage == 'cleared':
        need(value['tokenEmpty'] is True and value['detailMounted'] is False and value['catalogText'] == '' and value['targets'] == [])
        need(observed < deadline)
        return
    need(value['detailMounted'] is True and value['catalogText'] == detail['catalogDigest'] and len(value['targets']) == 3)
    if stage == 'fresh': need(observed < deadline)
    if stage == 'withdrawn': need(observed >= deadline)
    latest = {}
    for sample in detail['samples']:
        old = latest.get(sample['probeId'])
        if old is None or (ns(sample['completedAt']), sample['runId']) > (ns(old['completedAt']), old['runId']):
            latest[sample['probeId']] = sample
    for ident, actual in zip(IDS, value['targets']):
        keys(actual, {'probeId', 'pathId', 'stateLabel', 'runId', 'httpStatus', 'layers'})
        need(actual['probeId'] == ident and actual['pathId'] == 'direct')
        if stage == 'fresh':
            sample = latest[ident]
            need(actual['stateLabel'] == LABELS[sample['conclusion']] and actual['runId'] == sample['runId']
                 and type(actual['httpStatus']) is int and actual['httpStatus'] == sample['httpStatus'])
            need(same(actual['layers'], {name: LABELS[sample['layers'][name]['state']] for name in LAYERS}))
        else:
            need(actual['stateLabel'] == LABELS['unknown'] and actual['runId'] == ''
                 and type(actual['httpStatus']) is int and actual['httpStatus'] == 0 and same(actual['layers'], {}))


def validate_captures(raw, results, engine):
    """Bind the 18 capture files to the actual six independently verified runs."""
    prefix, expected_names = capture_names(engine)
    need(expected_names <= set(raw) and type(results) is dict and len(results) == 6)
    extrema = [ns(result['expiresAt']) for result in results.values()] + [ns(layer['expiresAt'])
               for result in results.values() for layer in result['layers'].values()]
    minimum, maximum = min(extrema), max(extrema)
    bodies, models, captures, events = {}, {}, {}, []
    for stage in ('fresh', 'withdrawn', 'expired'):
        summary = backend.decoded(raw[prefix + stage + '-status.json'])
        detail = backend.decoded(raw[prefix + stage + '-details.json'])
        cached = backend.status(summary, stage == 'expired')
        backend.api_details(detail, summary, results, stage == 'expired')
        need(same(detail['status'], summary))
        if stage == 'expired': need(cached >= maximum)
        else: need(cached < minimum)
        deadline = ns(summary['expiresAt'])
        need(deadline == min(cached + 30 * 10**9, minimum) if stage != 'expired' else deadline == cached + 30 * 10**9)
        bodies[stage] = (summary, detail)
        models[stage] = {'cached': cached, 'deadline': deadline,
                         'deadlineKind': 'EVIDENCE_TTL' if stage != 'expired' and deadline == minimum else 'CACHE_OR_EVIDENCE_DEADLINE'}
    for stage in STAGES:
        content = raw[prefix + stage + '-network.jsonl']
        need(content.endswith(b'\n') and 0 < len(content) <= 2 << 20)
        local = [backend.decoded(line) for line in content.splitlines()]
        need(0 < len(local) <= 128)
        for event in local:
            keys(event, {'stage', 'ordinal', 'receivedUnixNano', 'method', 'path', 'status',
                         'authorizationPresent', 'resourceType', 'bodyBytes', 'bodySHA256'})
            need(event['stage'] == stage and type(event['ordinal']) is int and event['ordinal'] == len(events) + 1)
            need(event['method'] == 'GET' and event['path'] in ('/api/v1/probes/status', '/api/v1/probes/details'))
            need(type(event['status']) is int and event['status'] == 200 and event['resourceType'] in ('fetch', 'xhr'))
            need(event['authorizationPresent'] is (event['path'] == '/api/v1/probes/details'))
            integer(event['bodyBytes'], 1, 1 << 20); need(type(event['bodySHA256']) is str and backend.HEX.fullmatch(event['bodySHA256']))
            received = backend.decimal_ns(event['receivedUnixNano'])
            need(received % 1_000_000 == 0 and (not events or received >= int(events[-1]['receivedUnixNano'])))
            events.append(event)
    need(len(events) <= 128)
    need(any(e['stage'] == 'cleared' and e['path'] == '/api/v1/probes/status' and e['authorizationPresent'] is False for e in events))
    previous = 0
    for stage in STAGES:
        capture = backend.decoded(raw[prefix + stage + '-dom.json'])
        keys(capture, {'schema', 'outcome', 'runtimeProven', 'browserE2EProven', 'engine', 'stage', 'source', 'observations', 'screenshots'})
        need(capture['schema'] == 'chengwang.probe-browser-capture/v1' and capture['outcome'] == 'API_CAPTURE_UNBOUND'
             and capture['runtimeProven'] is False and capture['browserE2EProven'] is False
             and capture['engine'] == engine and capture['stage'] == stage)
        source = keys(capture['source'], {'sourcePhase', 'status', 'details', 'statusOrdinal', 'detailsOrdinal', 'cachedAt', 'deadline', 'deadlineKind'})
        source_stage = 'fresh' if stage == 'cleared' else stage
        model = models[source_stage]; summary, detail = bodies[source_stage]
        need(source['sourcePhase'] == ('expired' if stage == 'expired' else 'fresh') and source['cachedAt'] == summary['cachedAt']
             and source['deadline'] == summary['expiresAt'] and source['deadlineKind'] == model['deadlineKind'])
        for kind in ('status', 'details'):
            name = prefix + source_stage + '-' + kind + '.json'
            raw_reference(source[kind], raw[name], name)
            ordinal = integer(source[kind + 'Ordinal'], 1, len(events)); event = events[ordinal - 1]
            need(event['stage'] == source_stage and event['path'] == '/api/v1/probes/' + kind
                 and event['bodyBytes'] == len(raw[name]) and event['bodySHA256'] == sha(raw[name]))
            # Date.now() is the lower bound of a one-millisecond interval,
            # whereas the Go API cachedAt preserves nanosecond precision.
            need(int(event['receivedUnixNano']) + 999_999 >= model['cached'])
        need(source['statusOrdinal'] < source['detailsOrdinal'])
        observations = capture['observations']; need(type(observations) is list and len(observations) == (2 if stage == 'fresh' else 1))
        widths = []
        for observation in observations:
            keys(observation, {'observedAt', 'dom'}); observed = ns(observation['observedAt'])
            need(observed % 1_000_000 == 0 and observed >= previous and observed + 999_999 >= model['cached']
                 and all(observed + 999_999 >= int(events[source[kind + 'Ordinal'] - 1]['receivedUnixNano'])
                         for kind in ('status', 'details')))
            if stage == 'expired': need(observed >= maximum)
            dom_projection(observation['dom'], stage, detail, observed, model['deadline'])
            widths.append(observation['dom']['viewport']['width']); previous = observed
        need(widths == ([1440, 375] if stage == 'fresh' else [375] if stage == 'expired' else [1440]))
        screenshots = capture['screenshots']; need(type(screenshots) is list and len(screenshots) == (0 if stage == 'cleared' else len(observations)))
        for observation, screenshot in zip(observations, screenshots):
            suffix = 'mobile' if observation['dom']['viewport']['width'] == 375 else 'desktop'
            name = prefix + stage + '-' + suffix + '.png'; raw_reference(screenshot, raw[name], name, True)
            when = ns(screenshot['capturedAt']); need(when >= ns(observation['observedAt']))
            need(when < model['deadline'] if stage == 'fresh' else when >= model['deadline'] if stage == 'withdrawn' else when >= maximum)
            width, height = png_dimensions(raw[name]); need(width == observation['dom']['viewport']['width'] and height >= observation['dom']['viewport']['height'])
        captures[stage] = capture
    need(captures['cleared']['source'] == captures['fresh']['source'])
    cleared_at = ns(captures['cleared']['observations'][0]['observedAt'])
    need(any(e['stage'] == 'cleared' and e['path'] == '/api/v1/probes/status'
             and e['authorizationPresent'] is False and int(e['receivedUnixNano']) >= cleared_at for e in events))
    return {'captures': captures, 'network': events, 'minimumExpiryUnixNano': minimum,
            'maximumExpiryUnixNano': maximum, 'deadlineKind': models['withdrawn']['deadlineKind']}


def verify(backend_dir, browser_dir, source_commit, engine):
    need(type(source_commit) is str and backend.COMMIT.fullmatch(source_commit) and engine in ENGINES)
    backend_dir, browser_dir = pathlib.Path(backend_dir), pathlib.Path(browser_dir)
    need(backend_dir.resolve() != browser_dir.resolve() and browser_dir.is_dir() and not browser_dir.is_symlink())
    # Never replace the old verifier with a success flag or consume its stored
    # outcome as proof: recompute all 22 original inputs first.
    native = backend.verify(backend_dir, source_commit)
    native_bytes = backend.encoded(native) + b'\n'
    prefix, captures_set = capture_names(engine)
    own_names = captures_set | {'browser-captures.json', 'browser-driver.json', 'browser-build.json', 'browser-processes.json'}
    need({p.name for p in browser_dir.iterdir()} == own_names | {'web'})
    raw = {name: backend.read_file(browser_dir / name, 8 << 20) for name in own_names}
    need(all(b'PRIVATE KEY' not in value and b'Bearer ' not in value for name, value in raw.items() if not name.endswith('.png')))
    collect = backend.decoded(backend.read_file(backend_dir / (backend.PREFIX + 'collect-final.json')))
    prepare = backend.decoded(backend.read_file(backend_dir / (backend.PREFIX + 'prepare.json')))
    results = {}
    for entry in collect['spoolSegments']:
        body = backend.base64_bytes(entry['raw'], 64 << 10)
        value = backend.spool(body, entry['name'], prepare['catalogDigest'], ns(collect['observedAt']))
        need(value['runId'] not in results); results[value['runId']] = value
    model = validate_captures(raw, results, engine)
    native_runtime = backend.decoded(backend.read_file(backend_dir / (backend.PREFIX + 'runtime.json')))
    restart_end = int(next(p for p in native_runtime['phases'] if p['name'] == 'restarted')['finishedUnixNano'])
    for capture in model['captures'].values():
        for observation in capture['observations']:
            when = ns(observation['observedAt'])
            need(when + 999_999 >= restart_end and when <= int(native_runtime['finishedUnixNano']))
    need(all(int(e['receivedUnixNano']) + 999_999 >= restart_end
             and int(e['receivedUnixNano']) <= int(native_runtime['finishedUnixNano']) for e in model['network']))
    flow = backend.decoded(raw['browser-captures.json'])
    keys(flow, {'schema', 'outcome', 'runtimeProven', 'browserE2EProven', 'authorization', 'production',
                'deviceActionsExecuted', 'engine', 'captures', 'network', 'files', 'deadlineKind'})
    need(flow['schema'] == 'chengwang.probe-browser-flow/v1' and flow['outcome'] == 'API_CAPTURE_UNBOUND'
         and flow['engine'] == engine and flow['authorization'] == 'BLOCKED')
    need(all(flow[k] is False for k in ('runtimeProven', 'browserE2EProven', 'production', 'deviceActionsExecuted')))
    need(same(flow['files'], sorted(captures_set)) and same(flow['network'], model['network'])
         and flow['deadlineKind'] == model['deadlineKind'])
    need(type(flow['captures']) is list and len(flow['captures']) == 4)
    for stage, value in zip(STAGES, flow['captures']):
        need(type(value) is dict and same({k: v for k, v in value.items() if k != 'artifact'}, model['captures'][stage]))
        raw_reference(value['artifact'], raw[prefix + stage + '-dom.json'], prefix + stage + '-dom.json')
    build = backend.decoded(raw['browser-build.json'], source_manifest=True)
    isolation = backend.decoded(backend.read_file(backend_dir / (backend.PREFIX + 'isolation.json')), source_manifest=True)
    web = validate_build(browser_dir, build, isolation, source_commit, native['fixtureId'], engine)
    driver = backend.decoded(raw['browser-driver.json'])
    processes = backend.decoded(raw['browser-processes.json'])
    validate_processes(processes, driver, build, isolation, raw, source_commit, native['fixtureId'], engine)
    validate_driver(driver, prepare['certificates'], model, web, native['fixtureId'], engine)
    hashes = {name: sha(value) for name, value in raw.items()}
    hashes.update({'web/' + name: sha(value) for name, value in web.items()})
    return {'schema': SCHEMA, 'outcome': 'PASS', 'sourceCommit': source_commit, 'fixtureId': native['fixtureId'],
            'engine': engine, 'authorization': 'BLOCKED', 'production': False, 'deviceActionsExecuted': False,
            'advisoryOnly': True, 'acceptanceScope': 'ISOLATED_REAL_BROWSER_READ_ONLY_NOT_PRODUCTION',
            'browserE2EProven': True, 'actualInternetReachabilityProven': False, 'agentIdentitySignatureProven': False,
            'browserPluginUsed': False, 'responseBodyScope': 'CDP_DECODED_RESPONSE_BODY_NOT_RAW_TLS_WIRE',
            'buildProvenanceScope': 'TRUSTED_CI_INPUTS_NOT_INDEPENDENT_REBUILD',
            'processLifecycleScope': 'TRUSTED_RUNNER_AND_LAUNCHER_WAIT_NOT_INDEPENDENT_SIGNAL_AUDIT',
            'pngScope': 'FULL_PNG_FRAMING_AND_DECOMPRESSION_NOT_OCR_OR_INDEPENDENT_RENDER_ATTESTATION',
            'backendVerificationSHA256': sha(native_bytes), 'backendEvidenceSHA256': native['evidenceSHA256'],
            'apiSamples': 6, 'latestVisibleTargets': 3, 'latestVisibleLayers': 15,
            'withdrawalDeadlineKind': model['deadlineKind'], 'normalChromeExitCode': 0,
            'evidenceSHA256': dict(sorted(hashes.items()))}


def validate_build(directory, value, isolated, commit, fixture, engine):
    keys(value, {'schema', 'sourceCommit', 'fixtureId', 'engine', 'copiedInputs', 'sourceFilesBefore',
                 'sourceFilesAfter', 'hostBefore', 'hostAfter', 'buildScope', 'backendSupervisorMode', 'production'})
    need(value['schema'] == 'chengwang.probe-browser-build/v1' and value['sourceCommit'] == commit
         and value['fixtureId'] == fixture and value['engine'] == engine and value['production'] is False
         and value['buildScope'] == 'TRUSTED_CI_INPUTS_NOT_INDEPENDENT_REBUILD'
         and value['backendSupervisorMode'] == 'WRAPPER_IMPORTS_NATIVE_HELPERS')
    for name in ('sourceFilesBefore', 'sourceFilesAfter', 'hostBefore', 'hostAfter'):
        need(same(value[name], isolated[name]))
    entries = value['copiedInputs']; need(type(entries) is list and 1 <= len(entries) <= 8192)
    sources = {entry['path']: entry for entry in value['sourceFilesBefore']}
    seen, manifest = set(), {}
    for entry in entries:
        keys(entry, {'path', 'bytes', 'sha256'}); name = entry['path']
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+', name)
             and all(part not in ('', '.', '..') for part in name.split('/')) and name not in seen)
        seen.add(name); integer(entry['bytes'], 1, 512 << 20); need(backend.HEX.fullmatch(entry['sha256']))
        if name.startswith('chengwang/'):
            need(name in sources and sources[name]['bytes'] == entry['bytes'] and sources[name]['sha256'] == entry['sha256'])
        else: need(name.startswith(('built-web/', 'npm/playwright-core/', 'fonts/', 'toolchain/chrome/')) or name == 'toolchain/node')
        if name.startswith('built-web/'):
            manifest[name[len('built-web/'):]] = entry
    mandatory = {'chengwang/deploy/probe-readback/run_probe_browser.py', 'chengwang/deploy/probe-readback/probe_chrome_launcher.py',
                 'chengwang/tools/probe-browser/package.json', 'chengwang/tools/probe-browser/package-lock.json',
                 'chengwang/tools/probe-browser/probe-browser-contract.mjs', 'chengwang/tools/probe-browser/run-browser.mjs',
                 'chengwang/tools/probe-browser/browser-driver.mjs', 'chengwang/tools/probe-browser/browser-cli.mjs',
                 'chengwang/web/scripts/trust-browser-tls.mjs', 'chengwang/tools/image-binding/scripts/browser-process-guard.py',
                 'toolchain/node', 'toolchain/chrome/chrome', 'npm/playwright-core/package.json',
                 'fonts/NotoSansCJKsc-Regular.otf', 'fonts/NotoSansCJKsc-Bold.otf', 'fonts/LICENSE'}
    need(mandatory <= seen and sum(entry['bytes'] for entry in entries) <= 1536 << 20)
    webdir = directory / 'web'; need(webdir.is_dir() and not webdir.is_symlink())
    actual, web = set(), {}
    for child in webdir.rglob('*'):
        need(not child.is_symlink())
        name = child.relative_to(webdir).as_posix()
        if child.is_dir(): need(name in ('assets', '.vite')); continue
        need(name in ('index.html', 'trust.html', '.vite/manifest.json')
             or re.fullmatch(r'assets/[A-Za-z0-9_-]{1,100}\.[A-Za-z0-9]{1,8}', name))
        need(name in manifest); body = backend.read_file(child, 8 << 20); entry = manifest[name]
        need(entry['bytes'] == len(body) and entry['sha256'] == sha(body)); actual.add(name); web[name] = body
    need(actual == set(manifest) and 'index.html' in web and 2 <= len(web) <= 128)
    html = web['index.html'].decode('utf-8')
    refs = re.findall(r'(?:src|href)="(/assets/[^"<>]+)"', html)
    need(refs and all(ref[1:] in web for ref in refs) and any(ref.endswith('.js') for ref in refs))
    need(not re.search(r'(?:src|href)="https?://', html))
    return web


def validate_processes(value, driver, build, isolated, raw, commit, fixture, engine):
    keys(value, {'schema', 'sourceCommit', 'records', 'chromeArgv', 'chromeExecutable', 'controllerExitCode',
                 'chromeExit', 'webReadOnlyMounts', 'files', 'production'})
    need(value['schema'] == 'chengwang.probe-browser-processes/v1' and value['sourceCommit'] == commit and value['production'] is False)
    need(type(value['controllerExitCode']) is int and value['controllerExitCode'] == 0)
    records = value['records']; need(type(records) is list and len(records) == 2)
    by_role = {}
    for record in records:
        keys(record, {'role', 'pid', 'startTime', 'exeSHA256', 'argvSHA256', 'uid', 'gid', 'groups', 'capabilities', 'noNewPrivs', 'namespaces', 'limits'})
        need(record['role'] in ('controller', 'chrome') and record['role'] not in by_role)
        integer(record['pid'], 2); need(type(record['startTime']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', record['startTime']))
        need(backend.HEX.fullmatch(record['exeSHA256']) and backend.HEX.fullmatch(record['argvSHA256']))
        need(same(record['uid'], [10001] * 4) and same(record['gid'], [10001] * 4) and same(record['groups'], [])
             and type(record['noNewPrivs']) is int and record['noNewPrivs'] == 1)
        need(same(record['capabilities'], {name: '0000000000000000' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}))
        backend.namespaces(record['namespaces'])
        need(all(record['namespaces'][name] == isolated['lab']['namespaces'][name] for name in ('net', 'pid', 'user'))
             and record['namespaces']['mnt'] != isolated['lab']['namespaces']['mnt'])
        need(same(record['limits'], {'cpuSeconds': [180, 180], 'fileBytes': [32 << 20] * 2,
                                    'openFiles': [1024, 1024], 'processes': [1024, 1024], 'coreBytes': [0, 0]}))
        by_role[record['role']] = record
    chrome, controller = by_role['chrome'], by_role['controller']
    need(chrome['pid'] != controller['pid'] and chrome['namespaces'] == controller['namespaces'])
    copies = {entry['path']: entry for entry in build['copiedInputs']}
    need(controller['exeSHA256'] == copies['toolchain/node']['sha256'])
    bundle = '/tmp/chengwang-probe-harness-' + fixture; root = '/tmp/chengwang-probe-readback-' + fixture
    executable = keys(value['chromeExecutable'], {'path', 'bytes', 'sha256', 'sourceScope'})
    need(executable['sourceScope'] == 'TRUSTED_CI_SYSTEM_TOOL_NOT_INDEPENDENT_SUPPLY_CHAIN'
         and executable['path'] == bundle + '/chrome/chrome'
         and executable['sha256'] == chrome['exeSHA256'] == copies['toolchain/chrome/chrome']['sha256']
         and type(executable['bytes']) is int and executable['bytes'] == copies['toolchain/chrome/chrome']['bytes'])
    integer(executable['bytes'], 1, 512 << 20)
    argv = value['chromeArgv']; need(type(argv) is list and 1 <= len(argv) <= 128)
    need(all(type(arg) is str and 0 < len(arg) <= 8192 and re.fullmatch(r'[\x20-\x7e]+', arg) for arg in argv))
    need(argv[0] == executable['path'] and sha(b''.join(arg.encode() + b'\0' for arg in argv)) == chrome['argvSHA256'])
    need([arg for arg in argv if arg.startswith('--user-data-dir')] == ['--user-data-dir=' + root + '/browser/chrome-profile'])
    forbidden = {'--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors', '--allow-insecure-localhost',
                 '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure'}
    need(not any(arg.split('=', 1)[0] in forbidden for arg in argv) and '--no-sandbox' in argv)
    controller_argv = [bundle + '/browser-node', bundle + '/source/chengwang/tools/probe-browser/browser-cli.mjs',
                       '--root', root, '--engine', engine, '--chrome', executable['path'], '--launcher', bundle + '/chrome-launcher',
                       '--source-root', bundle + '/source', '--source-commit', commit]
    need(controller['argvSHA256'] == sha(b''.join(arg.encode() + b'\0' for arg in controller_argv)))
    chrome_record = driver['chrome']; keys(chrome_record, {'pid', 'startTicks', 'uid', 'profile', 'argvSHA256'})
    need(same(chrome_record, {'pid': chrome['pid'], 'startTicks': int(chrome['startTime']), 'uid': 10001,
                             'profile': root + '/browser/chrome-profile', 'argvSHA256': chrome['argvSHA256']}))
    exit_record = {'schema': 'chengwang.probe-chrome-exit/v1', 'engine': engine, 'fixtureId': fixture,
                   'pid': chrome['pid'], 'startTicks': int(chrome['startTime']), 'exitCode': 0, 'joined': True, 'forced': False}
    need(same(value['chromeExit'], exit_record))
    close = {'normalCloseCommandCompleted': True, 'chromeExit': exit_record, 'guardExitCode': 0,
             'noLiveOwnedProcessesBeforeGuard': True, 'noLiveOwnedProcessesAfterGuard': True, 'guardSignalIntervention': False}
    need(same(driver['close'], close))
    mounts = value['webReadOnlyMounts']; need(type(mounts) is list and len(mounts) == 1)
    keys(mounts[0], {'role', 'flags'}); need(mounts[0]['role'] == 'api-second')
    backend.ro_mount({'readOnly': True, 'mountFlags': mounts[0]['flags']})
    expected_files = set(raw) - {'browser-build.json', 'browser-processes.json'}
    need(type(value['files']) is list and len(value['files']) == len(expected_files))
    seen = set()
    for entry in value['files']:
        keys(entry, {'path', 'bytes', 'sha256'}); name = entry['path']
        need(name in expected_files and name not in seen and type(entry['bytes']) is int
             and entry['bytes'] == len(raw[name]) and entry['sha256'] == sha(raw[name])); seen.add(name)
    need(seen == expected_files)


def validate_driver(value, certificates, captures, web, fixture, engine):
    counters = {'runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors'}
    keys(value, {'schema', 'engine', 'fixtureId', 'runtime', 'browserPluginUsed', 'mockedResponses', 'injectedFetch', 'tlsBypass',
                 'chromeSandbox', 'realBrowser', 'responseBodyScope', 'receivedClockResolution', 'normalTrust', 'chrome', 'tls',
                 'certificateChain', 'screenshotCount', 'network', 'close'} | counters)
    need(value['schema'] == 'chengwang.probe-browser-driver/v1' and value['engine'] == engine and value['fixtureId'] == fixture
         and value['runtime'] is True and value['chromeSandbox'] == 'DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED'
         and value['responseBodyScope'] == 'CDP_DECODED_RESPONSE_BODY_NOT_RAW_TLS_WIRE'
         and value['receivedClockResolution'] == 'UNIX_MILLISECONDS')
    need(all(value[k] is False for k in ('browserPluginUsed', 'mockedResponses', 'injectedFetch', 'tlsBypass')))
    need(type(value['realBrowser']) is str and re.fullmatch(r'(?:Chrome|HeadlessChrome)/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', value['realBrowser']))
    need(all(type(value[k]) is int and value[k] == 0 for k in counters) and type(value['screenshotCount']) is int and value['screenshotCount'] == 4)
    ca = backend.base64_bytes(certificates['apiCARaw'], 16384); leaf = backend.base64_bytes(certificates['apiLeafRaw'], 16384)
    ca_der = backend.openssl(['x509', '-outform', 'DER'], ca); leaf_der = backend.openssl(['x509', '-outform', 'DER'], leaf)
    chain = value['certificateChain']; need(type(chain) is list and 1 <= len(chain) <= 2)
    chain_raw = [backend.base64_bytes(item, 65536) for item in chain]
    need(chain_raw[0] == leaf_der and (len(chain_raw) == 1 or chain_raw[1] == ca_der))
    trust = {'method': 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', 'trustFlags': 'C,,', 'caSHA256': sha(ca_der), 'leafSHA256': sha(leaf_der),
             'homeEnvironmentAbsent': True, 'legacyDatabaseAbsent': True}
    need(same(value['normalTrust'], trust))
    proof = keys(value['tls'], {'securityState', 'protocol', 'cipher', 'leafSHA256', 'caSHA256', 'serverChainLength', 'leafSignatureVerified', 'ipSANVerified'})
    need(proof['securityState'] == 'secure' and proof['protocol'] in ('TLS 1.2', 'TLS 1.3')
         and type(proof['cipher']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', proof['cipher'])
         and proof['leafSHA256'] == sha(leaf_der) and proof['caSHA256'] == sha(ca_der)
         and type(proof['serverChainLength']) is int and proof['serverChainLength'] == len(chain)
         and proof['leafSignatureVerified'] is True and proof['ipSANVerified'] is True)
    with tempfile.TemporaryDirectory(prefix='probe-browser-cert-check-') as directory:
        ca_path, leaf_path = pathlib.Path(directory) / 'ca.pem', pathlib.Path(directory) / 'leaf.pem'
        backend.write_exclusive(ca_path, ca); backend.write_exclusive(leaf_path, backend.openssl(['x509', '-inform', 'DER', '-outform', 'PEM'], chain_raw[0]))
        for when in (captures['captures']['fresh']['observations'][0]['observedAt'], captures['captures']['expired']['observations'][0]['observedAt']):
            backend.openssl(['verify', '-no-CAfile', '-no-CApath', '-no-CAstore', '-trusted', str(ca_path), '-attime', str(ns(when) // 10**9),
                             '-purpose', 'sslserver', '-verify_ip', '127.0.0.1', str(leaf_path)])
    network = value['network']; need(type(network) is list and 1 <= len(network) <= 128)
    probe_events, served = [], set()
    for ordinal, event in enumerate(network, 1):
        keys(event, {'ordinal', 'url', 'method', 'status', 'authorizationPresent', 'resourceType', 'bodyBytes', 'bodySHA256', 'receivedUnixNano'})
        need(type(event['ordinal']) is int and event['ordinal'] == ordinal and event['method'] == 'GET'
             and type(event['status']) is int and event['status'] == 200)
        need(type(event['url']) is str and event['url'].startswith(ORIGIN + '/'))
        path = event['url'][len(ORIGIN):]
        need(path in ('/', '/api/v1/snapshot', '/api/v1/observations/status', '/api/v1/probes/status', '/api/v1/probes/details')
             or path.startswith('/assets/') and path[1:] in web)
        need(event['authorizationPresent'] is (path == '/api/v1/probes/details'))
        need(event['resourceType'] in ('document', 'script', 'stylesheet', 'font', 'image', 'fetch', 'xhr', 'other'))
        integer(event['bodyBytes'], 1, 16 << 20); need(backend.HEX.fullmatch(event['bodySHA256'])); backend.decimal_ns(event['receivedUnixNano'])
        if path == '/' or path[1:] in web:
            expected = web['index.html' if path == '/' else path[1:]]
            need(event['bodyBytes'] == len(expected) and event['bodySHA256'] == sha(expected)); served.add('index.html' if path == '/' else path[1:])
        if path in ('/api/v1/probes/status', '/api/v1/probes/details'):
            projection = {k: v for k, v in event.items() if k not in ('ordinal', 'url')}
            projection['path'] = path; projection['ordinal'] = len(probe_events) + 1; probe_events.append(projection)
    main_refs = {name[1:] for name in re.findall(r'(?:src|href)="(/assets/[^"<>]+)"', web['index.html'].decode('utf-8'))}
    need({'index.html'} | main_refs <= served)
    need(len(probe_events) == len(captures['network']))
    for full, capture in zip(probe_events, captures['network']):
        need(same(full, {k: v for k, v in capture.items() if k != 'stage'}))


def main(argv=None):
    class ClosedParser(argparse.ArgumentParser):
        def error(self, _message): raise backend.Rejected('arguments-rejected')
    parser = ClosedParser(add_help=False)
    parser.add_argument('command', choices=('verify',))
    parser.add_argument('--backend-dir', required=True, type=pathlib.Path)
    parser.add_argument('--browser-dir', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=tuple(ENGINES))
    parser.add_argument('--report', required=True, type=pathlib.Path)
    try:
        options = parser.parse_args(argv)
        report_path = options.report.resolve()
        need(not any(report_path.is_relative_to(folder.resolve()) for folder in (options.backend_dir, options.browser_dir)))
        result = verify(options.backend_dir, options.browser_dir, options.source_commit, options.engine)
        backend.write_exclusive(options.report, backend.encoded(result) + b'\n')
    except (backend.Rejected, OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, zlib.error):
        print('PROBE_BROWSER_CHECK=FAIL rejected=true raw_input_suppressed=true', file=sys.stderr)
        return 1
    print('PROBE_BROWSER_CHECK=PASS authorization=BLOCKED production=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
