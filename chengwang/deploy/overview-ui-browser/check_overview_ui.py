"""Independent offline reconstruction of the closed overview UI laboratory.

No producer, JavaScript or product decoder is imported. The only reused module
is an independent checker, through an explicit low-level primitive whitelist;
its bytes are also bound to the verified Git commit. Nothing runs on import.
"""
import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unicodedata

HERE = Path(__file__).parent
OWN_PATH = 'chengwang/deploy/overview-ui-browser/check_overview_ui.py'
CONTRACT_PATH = 'chengwang/deploy/overview-ui-browser/contract.json'
PRIMITIVES_PATH = 'chengwang/deploy/capability-truth-browser/check_capability_truth.py'
_spec = importlib.util.spec_from_file_location('overview_offline_primitives', HERE.parents[0] / 'capability-truth-browser/check_capability_truth.py')
_primitive_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_primitive_module)
for _name in ('read', 'no_symlinks', 'decode', 'digest', 'sha', 'integer', 'exact', 'same', 'text', 'canonical', 'git', 'git_file', 'png'):
    globals()[_name] = getattr(_primitive_module, _name)

PROFILES = ('evidence_disabled', 'evidence_enabled_unknown')
COUNTERS = ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors')
STRICT_ZERO = ('runtimeErrors', 'consoleWarnings', 'cspErrors', 'assetErrors', 'forbiddenRequests')
RPC_GAP = 'BODY_RPC_REJECTED_AFTER_EXPECTED_503'
CHROME_TAG = '41520584daa68d0040db7746ae562a0ff82187f6'
CHROME_SHA = 'ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
CHROME_BYTES = 305061192
PIN_SHA = '404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
PROCESS_TRUST = 'TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION'
INPUT_TRUST = 'SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD'
PATHS = {'SNAPSHOT': '/api/v1/snapshot', 'OVERVIEW': '/api/v1/overview', 'OBSERVATION_STATUS': '/api/v1/observations/status', 'PROBE_STATUS': '/api/v1/probes/status'}
# Independent reviewed closure of the executed overview entry's static imports,
# including the JSON module loaded by NavigationDiagnostics on module import.
# It is deliberately not obtained from a producer adapter or its copied list.
BROWSER_SOURCE_FILES = (
    'chengwang/tools/overview-ui-browser/ui-cli.mjs',
    'chengwang/tools/overview-ui-browser/ui-driver.mjs',
    'chengwang/tools/overview-ui-browser/ui-contract.mjs',
    'chengwang/tools/overview-ui-browser/ui-dom.mjs',
    'chengwang/tools/overview-ui-browser/overview-journal.mjs',
    'chengwang/tools/overview-ui-browser/wire-contract.mjs',
    'chengwang/tools/browser-scene-driver/native-session.mjs',
    'chengwang/tools/capability-truth-browser/ui-driver.mjs',
    'chengwang/tools/capability-truth-browser/ui-contract.mjs',
    'chengwang/tools/capability-truth-browser/ui-dom.mjs',
    'chengwang/tools/subscription-ui-browser/ui-driver.mjs',
    'chengwang/tools/subscription-ui-browser/ui-contract.mjs',
    'chengwang/tools/subscription-ui-browser/navigation-diagnostics.mjs',
    'chengwang/tools/subscription-ui-browser/navigation-diagnostics-contract.json',
    'chengwang/web/scripts/trust-browser-tls.mjs',
)
SUPERVISOR_SOURCE_FILES = (
    CONTRACT_PATH,
    'chengwang/deploy/overview-ui-browser/overview_ui_scene.py',
    'chengwang/deploy/overview-ui-browser/run_overview_ui.py',
    'chengwang/deploy/browser-scene-supervisor/supervisor.py',
    'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
    'chengwang/deploy/browser-stream-matrix/run_matrix.py',
    'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py',
    'chengwang/web/scripts/trust-browser-tls.mjs',
)


def need(condition):
    if not condition:
        raise ValueError('overview evidence rejected')


def keys(c, value, name, nested=False):
    exact(value, c['nestedExactKeys' if nested else 'exactKeySchemas'][name])


def relative(value):
    need(type(value) is str and 0 < len(value) <= 512 and re.fullmatch(r'[A-Za-z0-9_./-]+', value))
    need(not value.startswith('/') and all(part not in ('', '.', '..') for part in value.split('/')))
    return value


def unbase64(value, maximum):
    need(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3))
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('overview evidence rejected') from None
    need(0 < len(raw) <= maximum and base64.b64encode(raw).decode() == value)
    return raw


def timestamp(value):
    """Go UTC RFC3339Nano, including year 0000; no client-clock inference."""
    need(type(value) is str)
    match = re.fullmatch(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z', value)
    need(match is not None)
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    need(1 <= month <= 12 and 1 <= day <= days[month - 1] and hour < 24 and minute < 60 and second < 60)
    fraction = (match[7] or '').ljust(9, '0')
    need((year, month, day, hour, minute, second, fraction) != (1, 1, 1, 0, 0, 0, '000000000'))
    return value


def unknown_overview():
    layer = lambda: dict(state='unknown', reason='not_configured', observedAt=None, expiresAt=None)
    return dict(schema='chengwang.overview-snapshot/v1', dataSource='live', mode='candidate', readOnly=True, advisoryOnly=True,
        coverage=dict(state='none', missing=['controller_observation', 'probe_readback', 'businesses', 'node_pools', 'end_to_end_dns', 'device_inventory', 'traffic_topology']),
        observation=dict(configured=False, running=False, fresh=False, stale=False, lastAttemptAt=None, lastSuccessAt=None, consecutiveFailures=0,
                         controller=layer(), storage=layer(), clock=layer()),
        probe=dict(configured=False, running=False, state='disabled', reason='disabled', clockHealthy=False, storageHealthy=False,
                   cachedAt=None, expiresAt=None, coverageState='unavailable', coverage=None),
        subscription=dict(configured=False, inventoryState='protected_not_read', sourceCount=None, nodeCount=None),
        unsupported=dict(businesses=True, nodePools=True, endToEndDNS=True, deviceInventory=True, trafficTopology=True))


class Snapshot:
    """Independent bounded snapshot wire shape, not policy validity or health."""
    def __init__(self):
        self.items = self.characters = 0

    def txt(self, value, maximum=256):
        text(value, maximum)
        self.characters += len(value.encode('utf-16-le')) // 2
        need(self.characters <= 1 << 20)
        return value

    def array(self, value, fn, maximum=1024, nullable=True):
        if value is None and nullable:
            return []
        need(type(value) is list and len(value) <= maximum)
        self.items += len(value); need(self.items <= 16384)
        return [fn(item) for item in value]

    def strings(self, value, maximum=1024, width=256, nullable=True):
        return self.array(value, lambda item: self.txt(item, width), maximum, nullable)

    def row(self, value, kind):
        definitions = {
            'business': ('id name strategy activeRoute status', ''),
            'pool': ('name region latencyMs lossRate available total status', ''),
            'event': ('at type reason result', ''),
            'policy': ('id name domains strategy candidates fallback skipEmptyPools failuresToSwitch probeIntervalSec sessionStickyMin switchCooldownSec', 'requireCapabilities'),
            'node': ('id name members', 'capabilities'),
            'interface': ('id name type core listen port udp lanAccess authMode tls accessScope maxConnections idleTimeoutSec rateLimitMbps auditEnabled enabled status routingProfile', 'authReference tlsReference allowedCidrs description')}
        required, optional = [set(s.split()) for s in definitions[kind]]
        need(type(value) is dict and required <= set(value) <= required | optional)
        widths = dict(name=160, strategy=256, activeRoute=256, status=256, region=160, reason=2048, result=2048,
                      fallback=256, core=64, listen=256, routingProfile=256, authReference=256, tlsReference=256, description=2048)
        for key, width in widths.items():
            if key in value: self.txt(value[key], width)
        if 'id' in value:
            identifier = self.txt(value['id'], 128)
            if kind == 'interface': need(re.fullmatch(r'[a-z][a-z0-9_-]{1,47}', identifier))
            else: need(1 <= len(identifier) <= 64 and unicodedata.category(identifier[0])[0] in ('L', 'N') and all(unicodedata.category(c)[0] in ('L', 'N') or c in '._ -' for c in identifier))
        for key in ('skipEmptyPools', 'udp', 'lanAccess', 'tls', 'auditEnabled', 'enabled'):
            if key in value: need(type(value[key]) is bool)
        for key in ('latencyMs', 'available', 'total', 'port', 'maxConnections', 'idleTimeoutSec', 'rateLimitMbps'):
            if key in value: integer(value[key], 0, dict(port=65535, maxConnections=1000000, idleTimeoutSec=86400, rateLimitMbps=100000).get(key, 9007199254740991))
        for key in ('failuresToSwitch', 'probeIntervalSec', 'sessionStickyMin', 'switchCooldownSec'):
            if key in value: integer(value[key], -9007199254740991)
        if kind == 'pool':
            need(type(value['lossRate']) in (int, float) and math.isfinite(value['lossRate']) and 0 <= value['lossRate'] <= 100 and value['available'] <= value['total'])
        if kind == 'event': timestamp(value['at']); self.txt(value['type'])
        if kind == 'interface':
            protocol = self.txt(value['type'], 32)
            need('\ufeff' not in protocol and protocol.strip().lower() in ('http', 'socks5', 'mixed', 'tun', 'tproxy', 'redirect', 'api'))
            need(value['authMode'] in ('none', 'password', 'token', 'mtls') and value['accessScope'] in ('local', 'lan', 'vpn', 'custom'))
            if 'allowedCidrs' in value: self.strings(value['allowedCidrs'], 1024, 128, False)
        for key, limit, width in [('domains', 1024, 253), ('candidates', 1024, 256), ('members', 4096, 256), ('requireCapabilities', 1024, 256), ('capabilities', 1024, 256)]:
            if key in value: self.strings(value[key], limit, width, key not in ('requireCapabilities', 'capabilities'))
        return value

    def rows(self, value, kind, identity=None, maximum=1024):
        result = self.array(value, lambda row: self.row(row, kind), maximum)
        if identity:
            identifiers = [identity(row) for row in result]
            need(len(identifiers) == len(set(identifiers)))
        return result

    def parse(self, value):
        exact(value, 'product version mode status dataSource publishLocked businesses pools interfaces events draft'.split())
        for key in ('product', 'version', 'mode', 'status'): self.txt(value[key], 64 if key == 'mode' else 256)
        same(value['dataSource'], 'demo'); same(value['mode'], 'candidate'); same(value['publishLocked'], True)
        self.rows(value['businesses'], 'business', lambda row: row['id'])
        self.rows(value['pools'], 'pool', lambda row: (row['name'], row['region']))
        self.rows(value['interfaces'], 'interface', lambda row: row['id'])
        self.rows(value['events'], 'event', maximum=4096)
        draft = value['draft']; exact(draft, 'name baseVersion businesses pools dns'.split())
        self.txt(draft['name'], 160); self.txt(draft['baseVersion'])
        self.rows(draft['businesses'], 'policy', lambda row: row['id']); self.rows(draft['pools'], 'node', lambda row: row['id'])
        exact(draft['dns'], 'domesticResolvers overseasResolvers hijackPort53 leakProtection'.split())
        for key in ('domesticResolvers', 'overseasResolvers'): self.strings(draft['dns'][key], 1024, 2048)
        for key in ('hijackPort53', 'leakProtection'): need(type(draft['dns'][key]) is bool)
        return value


def body_value(c, raw, kind, profile):
    value = decode(raw, True)
    if kind == 'SNAPSHOT': return Snapshot().parse(value)
    if kind == 'OVERVIEW':
        if profile == 'evidence_disabled':
            same(value, dict(code='overview_not_configured', message='实际证据汇总尚未启用'))
        else:
            exact(value, list(unknown_overview()) + ['generatedAt'])
            timestamp(value['generatedAt'])
            same({k: v for k, v in value.items() if k != 'generatedAt'}, unknown_overview())
    else:
        same(value, c['apiExpected']['observationStatusDisabled' if kind == 'OBSERVATION_STATUS' else 'probeStatusDisabled'])
    return value


def manifest_graph(c, manifest):
    need(type(manifest) is dict and 1 <= len(manifest) <= 256 and manifest.get('index.html', {}).get('isEntry') is True)
    path_ok = lambda p: type(p) is str and re.fullmatch(r'assets/[A-Za-z0-9][A-Za-z0-9_.-]{0,160}\.(?:js|css|woff2?|ttf|svg|png)', p)
    for entry in manifest.values():
        need(type(entry) is dict and set(entry) <= set(c['manifestAlgorithm']['keys']) and path_ok(entry.get('file')))
        for field in ('src', 'name'):
            if field in entry: text(entry[field], 1024)
        for field in ('isEntry', 'isDynamicEntry'):
            if field in entry: need(type(entry[field]) is bool)
        for field in ('css', 'assets', 'imports', 'dynamicImports', 'names'):
            if field not in entry: continue
            items = entry[field]; need(type(items) is list and len(items) <= 64 and all(type(s) is str and len(s) <= 1024 for s in items) and len(items) == len(set(items)))
        for field in ('imports', 'dynamicImports'):
            need(all(key in manifest for key in entry.get(field, [])))
    allowed, required, visited, static_visited = set(), set(), set(), set()
    def visit(key, mandatory):
        seen = static_visited if mandatory else visited
        if key in seen: return
        seen.add(key); entry = manifest[key]
        for path in [entry['file'], *entry.get('css', []), *entry.get('assets', [])]:
            need(path_ok(path)); allowed.add('/' + path)
        if mandatory:
            required.update('/' + path for path in [entry['file'], *entry.get('css', [])])
        for child in entry.get('imports', []): visit(child, mandatory)
        for child in entry.get('dynamicImports', []): visit(child, False)
    visit('index.html', True)
    need(0 < len(allowed) <= c['captureRules']['bounds']['assets'])
    return required, allowed


def validate_build(c, value, commit):
    keys(c, value, 'build.json')
    for key, expected in dict(schema=c['schemaNames']['build'], sourceCommit=commit, goVersion='go1.23.12', nodeVersion='v22.23.3', moduleMode='vendor', goDependencyDownloads=False, production=False, authorization='BLOCKED').items(): same(value[key], expected)
    keys(c, value['server'], 'build.server', True); same(value['server']['name'], 'server')
    integer(value['server']['bytes'], 1, 128 << 20); digest(value['server']['sha256'])
    rows = value['distFiles']; need(type(rows) is list and 4 <= len(rows) <= 512)
    files = {}
    for row in rows:
        keys(c, row, 'byteRecord', True); path = relative(row['path']); need(path not in files)
        integer(row['bytes'], 1, 16 << 20); digest(row['sha256']); files[path] = row
    same(list(files), sorted(files)); need({'index.html', 'trust.html', '.vite/manifest.json'} <= set(files))
    manifest_raw = unbase64(value['manifestBase64'], c['captureRules']['bounds']['manifestBytes'])
    same({k: files['.vite/manifest.json'][k] for k in ('bytes', 'sha256')}, dict(bytes=len(manifest_raw), sha256=sha(manifest_raw)))
    required, allowed = manifest_graph(c, decode(manifest_raw))
    need(all(path[1:] in files for path in allowed))
    return files, required, allowed


def json_lines(raw, maximum, row_maximum, floats=False):
    need(raw.endswith(b'\n'))
    lines = raw.splitlines(); need(0 < len(lines) <= maximum)
    need(all(0 < len(line) <= row_maximum for line in lines))
    return [decode(line, floats) for line in lines]


def validate_captures(c, rows, files, required, allowed, profile):
    policy, bounds = c['profileFacts'][profile], c['captureRules']['bounds']
    need(type(rows) is list and 4 <= len(rows) <= policy['requestsMax'])
    by_alias, kinds, bodies, request_ordinals = {}, {}, {}, set()
    total = 0
    for ordinal, row in enumerate(rows, 1):
        keys(c, row, 'captures.jsonl[]'); same(row['schema'], c['schemaNames']['capture']); same(row['ordinal'], ordinal)
        request_ordinal = integer(row['requestOrdinal'], 1, policy['requestsMax']); same(row['requestId'], 'r' + str(request_ordinal))
        need(request_ordinal not in request_ordinals and row['requestId'] not in by_alias); request_ordinals.add(request_ordinal)
        same(row['method'], 'GET'); same(row['authorizationPresent'], False); same(row['requestPublic'], None)
        kind, path = row['kind'], row['path']; need(kind in c['captureRules']['kindEnum'])
        if kind == 'DOCUMENT': same(path, '/'); file = files['index.html']
        elif kind == 'ASSET': need(path in allowed); file = files[path[1:]]
        else: same(path, PATHS[kind]); file = None
        expected_status = 503 if kind == 'OVERVIEW' and profile == 'evidence_disabled' else 200
        same(row['status'], expected_status)
        expected503 = profile == 'evidence_disabled' and kind == 'OVERVIEW'
        for key in ('startedWallTimeUs', 'startTimeUs', 'headerTimeUs', 'endTimeUs'): integer(row[key], 1)
        need(row['headerTimeUs'] >= row['startTimeUs'] and row['endTimeUs'] >= row['startTimeUs'])
        terminal = row['terminal']; keys(c, terminal, 'capture.terminal', True)
        if terminal['event'] == 'FINISH':
            integer(terminal['encodedDataLength'], 0, 9007199254740991)
            for key in ('canceled', 'blockedReasonPresent', 'corsErrorPresent'): same(terminal[key], None)
        else:
            need(expected503); same(terminal, dict(event='NET_FAIL', encodedDataLength=None, canceled=True, blockedReasonPresent=False, corsErrorPresent=False))
        keys(c, row['bodyRPC'], 'capture.bodyRPC', True); same(row['bodyRPC']['attempted'], True)
        if row['bodyState'] == 'unavailable':
            need(expected503); same(row['bodyRPC']['outcome'], 'rejected'); same(row['bodyUnavailableReason'], RPC_GAP)
            for key in ('responseBase64', 'responseSHA256', 'responseBytes', 'errorCodeObserved'): same(row[key], None)
        else:
            same(row['bodyState'], 'present'); same(row['bodyRPC']['outcome'], 'fulfilled'); same(row['bodyUnavailableReason'], None)
            maximum = bounds['bodyDocument'] if kind == 'DOCUMENT' else bounds['bodyAsset'] if kind == 'ASSET' else bounds['bodyAPI']
            raw = unbase64(row['responseBase64'], maximum); total += len(raw); need(total <= bounds['decodedTotal'])
            same(row['responseBytes'], len(raw)); same(row['responseSHA256'], sha(raw)); need(b'PRIVATE KEY' not in raw)
            if file:
                same({k: file[k] for k in ('bytes', 'sha256')}, dict(bytes=len(raw), sha256=sha(raw))); same(row['errorCodeObserved'], None)
            else:
                need(b'Bearer ' not in raw); bodies[ordinal] = body_value(c, raw, kind, profile)
                same(row['errorCodeObserved'], 'overview_not_configured' if expected503 else None)
        by_alias[row['requestId']] = row; kinds.setdefault(kind, []).append(row)
    same(request_ordinals, set(range(1, len(rows) + 1)))
    same(len(kinds.get('DOCUMENT', [])), 1)
    for kind, name in [('SNAPSHOT', 'snapshot'), ('OVERVIEW', 'overview'), ('OBSERVATION_STATUS', 'observationStatus'), ('PROBE_STATUS', 'probeStatus')]: same(len(kinds.get(kind, [])), policy['apiCounts'][name])
    assets = [row['path'] for row in kinds.get('ASSET', [])]
    need(0 < len(assets) <= bounds['assets'] and len(assets) == len(set(assets)) and required <= set(assets))
    return by_alias, kinds, bodies


def validate_events(c, driver, captures, profile):
    events = driver['events']; bounds = c['captureRules']['bounds']
    need(type(events) is list and 1 <= len(events) <= bounds['events'])
    observed, raw_counters, capture_events, rpc_errors = {}, {key: 0 for key in COUNTERS}, {}, {}
    network_logs = []
    terminal_count = finished = 0
    for seq, event in enumerate(events, 1):
        need(type(event) is dict and event.get('type') in c['driverEvents']); exact(event, c['driverEvents'][event['type']]); same(event['seq'], seq)
        need(len(canonical(event)) <= bounds['eventRowBytes'])
        tag = event['type']
        if tag == 'REQUEST':
            alias = event['requestId']; need(alias in captures and alias not in observed); row = captures[alias]
            same(event['requestOrdinal'], len(observed) + 1); same(event['requestOrdinal'], row['requestOrdinal'])
            for key in ('kind', 'method', 'path'): same(event[key], row[key])
            same(event['sameOrigin'], True)
            for key in ('queryPresent', 'fragmentPresent', 'userInfoPresent', 'authorizationPresent', 'cookiePresent', 'bodyPresent'): same(event[key], False)
            observed[alias] = dict(headers=False, terminal=False, captured=False)
        elif tag == 'HEADERS':
            alias = event['requestId']; need(alias in observed and not observed[alias]['headers'] and not observed[alias]['terminal']); row = captures[alias]
            same(event['status'], row['status'])
            mime = 'HTML' if row['kind'] == 'DOCUMENT' else ('JS' if row['path'].endswith('.js') else 'CSS' if row['path'].endswith('.css') else 'SVG' if row['path'].endswith('.svg') else 'PNG' if row['path'].endswith('.png') else 'FONT') if row['kind'] == 'ASSET' else 'JSON'
            same(event['mimeClass'], mime)
            for key in ('setCookiePresent', 'redirected', 'diskCache', 'serviceWorker'): same(event[key], False)
            observed[alias]['headers'] = True
        elif tag == 'LOG_NETWORK_ERROR':
            alias = event['requestId']
            need(alias in observed and observed[alias]['headers'] and alias not in network_logs)
            row = captures[alias]
            need(profile == 'evidence_disabled' and row['kind'] == 'OVERVIEW' and row['method'] == 'GET' and row['path'] == PATHS['OVERVIEW'] and row['status'] == 503)
            for key, expected in dict(source='network', level='error', urlSameRequest=True, workerIdPresent=False, categoryPresent=False, beforeClose=True).items(): same(event[key], expected)
            # Event position supplies the order; association with this safe 503
            # is not proof of a causal console message or of absent leakage.
            raw_counters['consoleErrors'] += 1; network_logs.append(alias)
        elif tag in ('FINISH', 'NET_FAIL'):
            alias = event['requestId']; need(alias in observed and observed[alias]['headers'] and not observed[alias]['terminal']); row = captures[alias]
            same(tag, row['terminal']['event']); terminal_count += 1; same(row['ordinal'], terminal_count)
            if tag == 'FINISH': same(event['encodedDataLength'], row['terminal']['encodedDataLength']); finished += 1
            else:
                need(profile == 'evidence_disabled' and row['kind'] == 'OVERVIEW' and row['status'] == 503)
                for key in ('canceled', 'blockedReasonPresent', 'corsErrorPresent'): same(event[key], row['terminal'][key])
                raw_counters['failedRequests'] += 1
            observed[alias]['terminal'] = True
        elif tag == 'ERROR':
            need(event['code'] in c['counterRules']['errorCodeToCounter']); counter = c['counterRules']['errorCodeToCounter'][event['code']]; raw_counters[counter] += 1
            need(event['code'] == 'capture_error' and event['reason'] == RPC_GAP)
            alias = event['requestId']; need(alias in captures and alias in observed and observed[alias]['terminal'] and not observed[alias]['captured'])
            row = captures[alias]
            need(profile == 'evidence_disabled' and row['kind'] == 'OVERVIEW' and row['status'] == 503 and row['bodyState'] == 'unavailable')
            same(event['kind'], row['kind']); need(alias not in rpc_errors); rpc_errors[alias] = event
        elif tag == 'CAPTURE':
            alias = event['requestId']; need(alias in observed and observed[alias]['terminal'] and not observed[alias]['captured']); row = captures[alias]
            for a, b in [('captureOrdinal', 'ordinal'), ('responseBytes', 'responseBytes'), ('responseSHA256', 'responseSHA256'), ('bodyState', 'bodyState'), ('bodyUnavailableReason', 'bodyUnavailableReason')]: same(event[a], row[b])
            same(event['bodyRPCOutcome'], row['bodyRPC']['outcome'])
            need((alias in rpc_errors) == (row['bodyState'] == 'unavailable'))
            observed[alias]['captured'] = True; capture_events[alias] = event
        else:
            same(seq, len(events)); same(event, dict(seq=seq, type='META', requests=len(captures), headers=len(captures), finished=finished,
                failed=raw_counters['failedRequests'], captured=len(captures), pending=0, tasks=0, ignoredFavicon=integer(event['ignoredFavicon'], 0, 4), mutations=0, overflow=False))
    need(events[-1]['type'] == 'META' and set(observed) == set(captures) and set(capture_events) == set(captures))
    need(all(all(state.values()) for state in observed.values()))
    exact(driver['counters'], COUNTERS)
    for key in COUNTERS: integer(driver['counters'][key], 0, bounds['events']); same(driver['counters'][key], raw_counters[key])
    need(all(raw_counters[key] == 0 for key in STRICT_ZERO))
    canceled = sorted((row for row in captures.values() if row['terminal']['event'] == 'NET_FAIL'), key=lambda row: row['ordinal'])
    gaps = sorted((row for row in captures.values() if row['bodyState'] == 'unavailable'), key=lambda row: row['ordinal'])
    same(raw_counters['failedRequests'], len(canceled)); same(raw_counters['captureErrors'], len(gaps))
    same(raw_counters['consoleErrors'], len(network_logs))
    return dict(rawCounters=raw_counters, qualifiedExpected503ReportedCanceled=[row['requestId'] for row in canceled],
        qualifiedExpected503BodyUnavailable=[row['requestId'] for row in gaps], qualifiedExpected503NetworkLogs=network_logs,
        unexpectedFailedRequests=0, unexpectedCaptureErrors=0, unexpectedConsoleErrors=raw_counters['consoleErrors'] - len(network_logs),
        errorBodyCompleteness=(len(gaps) == 0) if profile == 'evidence_disabled' else None,
        coverageGaps=[dict(requestId=row['requestId'], kind='OVERVIEW', reason=RPC_GAP) for row in gaps], claimOriginalEightZero=False)


def geometry(c, value, viewport):
    for key in ('present', 'rendered', 'inViewport'): need(type(value[key]) is bool)
    if not value['present']: need(not value['rendered'] and not value['inViewport'])
    if not value['rendered']:
        same(value['rect'], None); same(value['inViewport'], False); return
    same(value['present'], True); rect = value['rect']; keys(c, rect, 'rect', True)
    need(all(type(number) in (int, float) and math.isfinite(number) and abs(number) <= 10000000 for number in rect.values()))
    need(rect['width'] > 0 and rect['height'] > 0)
    intersects = rect['x'] < viewport['width'] and rect['y'] < viewport['height'] and rect['x'] + rect['width'] > 0 and rect['y'] + rect['height'] > 0
    same(value['inViewport'], intersects)


def text_tree(value, depth=0):
    need(depth <= 24)
    if type(value) is str: text(value, 2048)
    elif type(value) is list:
        need(len(value) <= 256)
        for item in value: text_tree(item, depth + 1)
    elif type(value) is dict:
        need(len(value) <= 128)
        for key, item in value.items(): text(key, 128); text_tree(item, depth + 1)
    else: need(value is None or type(value) in (bool, int) or type(value) is float and math.isfinite(value))


def validate_dom(c, rows, captures, bodies, profile):
    fences = c['stepFences'][profile]
    need(type(rows) is list and len(rows) == len(fences) == c['profileFacts'][profile]['domCheckpoints'])
    previous = 0
    for ordinal, (row, fence) in enumerate(zip(rows, fences), 1):
        keys(c, row, 'dom.jsonl[]'); same(row['schema'], c['schemaNames']['domRow']); same(row['ordinal'], ordinal)
        same(row['step'], fence[0]); integer(row['captureCount'], previous, len(captures)); same(row['mutationCount'], 0)
        previous = row['captureCount']; prefix = captures[:previous]
        d = row['dom']; keys(c, d, 'dom', True); text_tree(d)
        same(d['schema'], c['schemaNames']['dom']); same(d['navigationPage'], fence[2]); same(d['viewKind'], fence[3]); same(d['heading'], fence[4])
        for key in ('pageMounted', 'pageVisible', 'https'): same(d[key], True)
        viewport = d['viewport']; keys(c, viewport, 'dom.viewport', True)
        same(viewport['width'], fence[5]); same(viewport['height'], fence[6])
        integer(viewport['clientWidth'], 1, viewport['width']); same(viewport['scrollWidth'], viewport['clientWidth'])
        for key in ('scrollX', 'scrollY'): need(type(viewport[key]) in (int, float)); same(float(viewport[key]), 0.0)
        same(d['environment'], dict(language='zh-CN', timeZone='UTC'))
        same(d['browserStorage'], dict(localEmpty=True, sessionEmpty=True, cookiesEmpty=True))
        keys(c, d['apiFence'], 'dom.apiFence', True)
        grouped = {kind: [r for r in prefix if r['kind'] == kind] for kind in PATHS}
        same(len(grouped['SNAPSHOT']), 1)
        for kind, number in [('OVERVIEW', fence[7]), ('OBSERVATION_STATUS', fence[8]), ('PROBE_STATUS', fence[9])]: same(len(grouped[kind]), number)
        same(d['apiFence'], dict(snapshotCaptureOrdinal=grouped['SNAPSHOT'][0]['ordinal'], overviewCaptureOrdinals=[r['ordinal'] for r in grouped['OVERVIEW']],
            observationStatusCaptureOrdinals=[r['ordinal'] for r in grouped['OBSERVATION_STATUS']], probeStatusCaptureOrdinals=[r['ordinal'] for r in grouped['PROBE_STATUS']]))
        snapshot = bodies[grouped['SNAPSHOT'][0]['ordinal']]
        keys(c, d['topbar'], 'dom.topbar', True)
        for node in d['topbar'].values():
            keys(c, node, 'dom.topbar.node', True); geometry(c, node, viewport); same(node['present'], True)
            same(node['rendered'], viewport['width'] > 900); same(node['inViewport'], viewport['width'] > 900)
        same(d['topbar']['product']['text'], snapshot['product']); same(d['topbar']['kernel']['text'], '未核验')
        need(type(d['controls']) is list and len(d['controls']) == len(c['controlSlots']))
        controls = {}
        for control, slot in zip(d['controls'], c['controlSlots']):
            keys(c, control, 'dom.controls[]', True); same(control['key'], slot['key']); geometry(c, control, viewport)
            need(type(control['enabled']) is bool and type(control['unobstructed']) is bool)
            need(control['ariaPressed'] is None or type(control['ariaPressed']) is str and control['ariaPressed'] in ('true', 'false'))
            if control['present']:
                same(control['label'], slot['label']); same(control['labelSource'], slot['labelSource'])
            else:
                for key in ('label', 'labelSource', 'ariaPressed'): same(control[key], None)
                same(control['enabled'], False); same(control['unobstructed'], False)
            if control['unobstructed']:
                need(control['rendered'] and control['inViewport']); r = control['rect']
                need(0 <= r['x'] + r['width'] / 2 < viewport['width'] and 0 <= r['y'] + r['height'] / 2 < viewport['height'])
            name, view = slot['key'], d['viewKind']
            present = name.startswith('nav_') or name.startswith('source_') and view in ('demo', 'actual') or name == 'actual_refresh' and view == 'actual' or name.startswith('cta_') and view == 'actual' and profile == 'evidence_enabled_unknown'
            same(control['present'], present); same(control['rendered'], present); same(control['enabled'], present)
            if name.startswith('source_') and present:
                same(control['ariaPressed'], 'true' if (name == 'source_demo') == (view == 'demo') else 'false'); same(control['inViewport'], True)
            else: same(control['ariaPressed'], None)
            if name == 'actual_refresh' and present: same(control['inViewport'], True)
            controls[name] = control
        view = d['viewKind']
        need((d['actual'] is not None) == (view == 'actual') and (d['demo'] is not None) == (view == 'demo'))
        need((d['detail'] is not None) == (view in ('kernels', 'device_readback', 'proxy_observation', 'subscriptions')))
        if view == 'actual':
            a = d['actual']; keys(c, a, 'dom.actual', True)
            expected = c['domSemantics']['disabled' if profile == 'evidence_disabled' else 'enabled']
            same(a['state'], expected['state']); same(a['alert'], expected['alert']); same(a['pendingText'], None); same(a['healthMetricsPresent'], False)
            same(a['boundaryText'], c['domSemantics']['actualBoundary'] + ' ' + c['domSemantics']['asOfNotice'])
            same(d['topbar']['sourceLabel']['text'], expected['sourceBadge']); same(d['topbar']['mode']['text'], expected['modeBadge'])
            need(grouped['OVERVIEW']); latest = grouped['OVERVIEW'][-1]
            if profile == 'evidence_disabled':
                same(a['summary'], []); same(a['sourceCards'], []); same(a['timeElements'], []); same(a['unsupported'], None)
            else:
                body = bodies[latest['ordinal']]
                same(a['summary'], [s.replace('{generatedAt}', body['generatedAt']) for s in c['domSemantics']['summaryText']])
                same(a['timeElements'], [dict(dateTime=body['generatedAt'], text=body['generatedAt'])]); same(a['unsupported'], c['domSemantics']['unsupported'])
                need(type(a['sourceCards']) is list and len(a['sourceCards']) == 3)
                sections = [c['domSemantics']['controllerSections'], [dict(heading=None, facts=c['domSemantics']['probeFacts'])], [dict(heading=None, facts=c['domSemantics']['subscriptionFacts'])]]
                for index, card in enumerate(a['sourceCards']):
                    keys(c, card, 'dom.actual.sourceCards[]', True); same(card['heading'], c['domSemantics']['cardHeadings'][index]); same(card['badgeCurrent'], False)
                    same(card['badge'], expected['controllerBadge'] if index == 0 else expected['probeBadge'] if index == 1 else '')
                    same(card['buttonLabel'], controls[['cta_device', 'cta_nodes', 'cta_subscriptions'][index]]['label'])
                    same(card['sections'], [dict(heading=section['heading'], facts=[dict(label=label, text=label_text, dateTime=None) for label, label_text in section['facts']]) for section in sections[index]])
        else:
            same(d['topbar']['sourceLabel']['text'], '演示草稿'); same(d['topbar']['mode']['text'], snapshot['mode'])
            if view == 'demo':
                demo = d['demo']; keys(c, demo, 'dom.demo', True)
                same(demo, dict(status=snapshot['status'], mode=snapshot['mode'], badge='总览只读', boundaryText='总览仅展示数据边界；执行权限以服务端授权为准',
                    demoAlertTitle='当前总览没有接入真实运行数据', demoAlertText='为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。',
                    **{key: False for key in ('businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent')}))
            else:
                keys(c, d['detail'], 'dom.detail', True)
                same(d['detail'], dict(kind=view, heading=fence[4], tokenInputsEmpty=True, authenticatedResultVisible=False,
                                      observationStatusVisible=view == 'proxy_observation', probeStatusVisible=view == 'proxy_observation'))
    same(previous, len(captures))


def identity(c, value, filename, commit, engine, profile, fixture):
    keys(c, value, filename)
    schema = c['schemaNames']['driver'] if filename == 'driver.json' else c['schemaNames']['runtime'] if filename == 'runtime-facts.json' else c['schemaNames']['storage'] if filename == 'storage-readback.json' else c['schemaNames']['supervisor']
    for key, expected in dict(schema=schema, sourceCommit=commit, fixtureId=fixture, engine=engine, scenario='overview_ui', profile=profile, production=False).items(): same(value[key], expected)


def source_bindings(c, iso, inputs, build, repo, commit):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    same(iso['sourceFilesBefore'], iso['sourceFilesAfter']); same(iso['hostBefore'], iso['hostAfter'])
    rows = iso['sourceFilesBefore']; need(type(rows) is list and 1 <= len(rows) <= c['captureRules']['bounds']['sourceManifestEntries'])
    listed = [p.decode('utf-8') for p in git(repo, 'ls-tree', '-r', '-z', '--name-only', commit, '--', 'chengwang', '.github/workflows').split(b'\0') if p]
    source = {}
    for row in rows:
        keys(c, row, 'byteRecord', True); name = relative(row['path']); need(name not in source and name.startswith(('chengwang/', '.github/workflows/')))
        integer(row['bytes'], 0, 128 << 20); digest(row['sha256']); source[name] = row
    same(list(source), sorted(source)); same(set(source), set(listed))
    raw = git(repo, 'cat-file', '--batch', input_bytes=''.join(commit + ':' + name + '\n' for name in source).encode())
    at, blobs = 0, {}
    for name, row in source.items():
        end = raw.index(b'\n', at); header = raw[at:end].decode('ascii').split(); need(len(header) == 3 and header[1] == 'blob')
        size = int(header[2]); need(0 <= size <= 128 << 20)
        blob = raw[end + 1:end + 1 + size]; need(len(blob) == size and raw[end + 1 + size:end + 2 + size] == b'\n')
        need(hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + blob).hexdigest() == header[0])
        same(dict(bytes=size, sha256=sha(blob)), {key: row[key] for key in ('bytes', 'sha256')})
        blobs[name] = blob; at = end + size + 2
    same(at, len(raw)); same(iso['hostBefore']['sourceSHA256'], sha(canonical(rows)))
    for name, path in [(OWN_PATH, Path(__file__)), (CONTRACT_PATH, HERE / 'contract.json'), (PRIMITIVES_PATH, Path(_spec.origin))]: same(read(path), blobs[name])
    same(decode(blobs[CONTRACT_PATH]), c)
    copies = {}; need(type(inputs['copiedInputs']) is list and len(inputs['copiedInputs']) <= 8192)
    for row in inputs['copiedInputs']:
        keys(c, row, 'byteRecord', True); name = relative(row['path'].removesuffix(':launcher')); need(row['path'] not in copies)
        integer(row['bytes'], 0, 512 << 20); digest(row['sha256']); copies[row['path']] = row
        if name.startswith('chengwang/'):
            need(name in source); same({k: row[k] for k in ('bytes', 'sha256')}, {k: source[name][k] for k in ('bytes', 'sha256')})
        else: need(name.startswith(('chrome/', 'npm/playwright-core/', 'dist/')) or name in ('toolchain/node', 'toolchain/server', 'build/report.json'))
    required = {*BROWSER_SOURCE_FILES, *SUPERVISOR_SOURCE_FILES,
        'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py:launcher',
        'chrome/chrome', 'toolchain/node', 'toolchain/server', 'npm/playwright-core/package.json', 'build/report.json'}
    need(required <= set(copies))
    same({k: copies['toolchain/server'][k] for k in ('bytes', 'sha256')}, {k: build['server'][k] for k in ('bytes', 'sha256')})
    same({k: copies['chrome/chrome'][k] for k in ('bytes', 'sha256')}, dict(bytes=CHROME_BYTES, sha256=CHROME_SHA))
    same([dict(path=name[5:], bytes=row['bytes'], sha256=row['sha256']) for name, row in sorted(copies.items()) if name.startswith('dist/')], build['distFiles'])
    return source, copies, blobs


def validate_processes(c, p, iso, inputs, build, driver, commit, engine, profile, fixture):
    for filename, value in [('processes.json', p), ('isolation.json', iso), ('inputs.json', inputs)]: identity(c, value, filename, commit, engine, profile, fixture)
    same(p['processScope'], PROCESS_TRUST); same(inputs['inputTrustScope'], INPUT_TRUST)
    same(iso['authorization'], 'BLOCKED'); same(iso['deviceActionsExecuted'], False); same(iso['pythonBinaryProvenanceProven'], False)
    host = iso['hostBefore']; keys(c, host, 'hostObservation', True); keys(c, iso['hostAfter'], 'hostObservation', True); same(host, iso['hostAfter'])
    for key, kind in [('netNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid'), ('userNamespace', 'user')]: need(type(host[key]) is str and re.fullmatch(kind + r':\[[1-9][0-9]*\]', host[key]))
    integer(host['portStart'], 0, 65535); digest(host['systemCASHA256']); digest(host['sourceSHA256'])
    lab = iso['lab']; keys(c, lab, 'isolation.lab', True); keys(c, lab['namespaces'], 'record.namespaces', True)
    for key, value in lab['namespaces'].items(): need(type(value) is str and re.fullmatch(key + r':\[[1-9][0-9]*\]', value))
    same(lab['namespaces']['user'], host['userNamespace'])
    for key, other in [('net', 'netNamespace'), ('mnt', 'mountNamespace'), ('pid', 'pidNamespace')]: need(lab['namespaces'][key] != host[other])
    same(lab['defaultIPv4Routes'], 0); same(lab['defaultIPv6Routes'], 0); same(lab['interfaces'], ['lo'])
    for key, required, forbidden in [('sourceMount', {'ro', 'nosuid', 'nodev'}, {'rw'}), ('bundleMount', {'ro', 'nosuid', 'nodev'}, {'rw'}), ('tmpMount', {'rw', 'nosuid', 'nodev', 'noexec'}, {'ro'})]:
        flags = lab[key]; need(type(flags) is list and len(flags) <= 32 and all(type(flag) is str and re.fullmatch('[a-z0-9_=.-]{1,64}', flag) for flag in flags))
        need(len(flags) == len(set(flags)) and required <= set(flags) and not forbidden & set(flags))
    records = {}; need(type(p['records']) is list and len(p['records']) == 3)
    for record in p['records']:
        keys(c, record, 'processes.records[]', True); role = record['role']; need(role in ('server', 'controller', 'chrome') and role not in records)
        integer(record['pid'], 2); need(type(record['startTime']) is str and re.fullmatch('[1-9][0-9]{0,19}', record['startTime']))
        digest(record['exeSHA256']); digest(record['argvSHA256'])
        same(record['uid'], [10001] * 4); same(record['gid'], [10001] * 4); same(record['groups'], []); same(record['noNewPrivs'], 1)
        same(record['namespaces'], lab['namespaces']); same(record['capabilities'], {name: '0000000000000000' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')})
        same(record['limits'], dict(cpuSeconds=[180, 180], fileBytes=[32 << 20] * 2, openFiles=[1024] * 2, processes=[1024] * 2, coreBytes=[0, 0]))
        argv = record['argv']; need(type(argv) is list and 1 <= len(argv) <= 128)
        for argument in argv: text(argument, 4096)
        same(record['argvSHA256'], sha(b''.join(argument.encode() + b'\0' for argument in argv))); records[role] = record
    need(len({r['pid'] for r in records.values()}) == 3)
    for key, expected in dict(serverExitCode=0, controllerExitCode=0, forcedSignals=0, noLiveOwnedProcesses=True).items(): same(p[key], expected)
    root, bundle = '/tmp/chengwang-subscription-ui-' + fixture, '/tmp/chengwang-subscription-ui-tools-' + fixture
    copies = {row['path']: row for row in inputs['copiedInputs']}; chrome = driver['chrome']; keys(c, chrome, 'driver.chrome', True)
    same(chrome, dict(pid=records['chrome']['pid'], startTicks=int(records['chrome']['startTime']), uid=10001, profile=root + '/chrome-profile',
        argvSHA256=records['chrome']['argvSHA256'], exeSHA256=CHROME_SHA, exeBytes=CHROME_BYTES))
    same(records['chrome']['exeSHA256'], CHROME_SHA); same(records['server']['exeSHA256'], build['server']['sha256']); same(records['controller']['exeSHA256'], copies['toolchain/node']['sha256'])
    same(records['server']['argv'], [bundle + '/server'])
    same(records['controller']['argv'], [bundle + '/node', bundle + '/source/chengwang/tools/overview-ui-browser/ui-cli.mjs', '--root', root, '--bundle', bundle, '--engine', engine, '--source-commit', commit])
    argv = records['chrome']['argv']; same(argv[0], bundle + '/chrome/chrome')
    need('--no-sandbox' in argv and [v for v in argv if v.startswith('--user-data-dir')] == ['--user-data-dir=' + root + '/chrome-profile'])
    forbidden = {'--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors', '--allow-insecure-localhost', '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure'}
    need(not any(argument.split('=', 1)[0] in forbidden for argument in argv))
    close = driver['close']; keys(c, close, 'driver.close', True)
    same(close['normalCloseCommandCompleted'], True); same(close['noLiveOwnedProcesses'], True); same(close['processScope'], 'CHROME_SESSION_AND_LAUNCHER_ONLY')
    same(close['chromeExit'], dict(schema='chengwang.subscription-ui-chrome-exit/v1', engine=engine, fixtureId=fixture, pid=chrome['pid'], startTicks=chrome['startTicks'], exitCode=0, joined=True, forced=False))
    same(close['launcherExit'], dict(code=0, signal=None) if engine == 'chrome-cdp' else None)
    return records


def runtime_facts(c, runtime, storage, records, commit, engine, profile, fixture):
    identity(c, runtime, 'runtime-facts.json', commit, engine, profile, fixture)
    identity(c, storage, 'storage-readback.json', commit, engine, profile, fixture)
    expected_scope = dict(tenantId='', siteId='', environment='candidate', objectType='control-plane', objectId='local')
    same(runtime['scope'], expected_scope); same(storage['scope'], expected_scope)
    server = records['server']
    same(runtime['serverIdentity'], dict(pid=server['pid'], startTicks=int(server['startTime']), exeSHA256=server['exeSHA256'], argvSHA256=server['argvSHA256']))
    same(runtime['environment'], [dict(name=name, value=value) for name, value in sorted(c['profilePolicies'][profile]['env'].items())])
    same(runtime['identities'], dict(configured=False, regularFile=False, directoryMode=None, fileMode=None, symlinkComponents=False, ownershipVerified=False))
    same(runtime['mihomo'], dict(configured=False, endpointClass=None)); same(runtime['observer'], dict(configured=False, interval=None, ttl=None))
    same(runtime['probe'], dict(configured=False)); same(runtime['subscription'], dict(configured=False, writesEnabled=False, policyConfigured=False))
    same(runtime['writeGates'], dict(publish=False, operation=False, subscription=False)); same(runtime['policyCatalog'], dict(configured=False))
    same(runtime['upstreamListener'], dict(endpointClass='ISOLATED_LOOPBACK_17892', beforeListening=False, afterListening=False, reachabilityObserved=False))
    same(runtime['snapshotsProvider'], 'seed_demo'); same(runtime['liveOverview'], dict(enabled=profile == 'evidence_enabled_unknown'))
    trust = 'SOURCE_BOUND_TRUSTED_CI_NOT_INDEPENDENT_PRIVATE_STORAGE_ATTESTATION'
    same(runtime['trustBoundary'], trust); same(storage['trustBoundary'], trust)
    same(storage['subscriptionStore'], dict(constructed=False, scope=None, **{key: 0 for key in ('sourceCount', 'candidateCount', 'requestCount', 'auditCount', 'commandCount', 'approvalCount', 'privateNodesCount')}))
    same(storage['observationStore'], dict(constructed=False)); same(storage['operationStore'], dict(constructed=True, commandCount=0)); same(storage['evidenceStore'], dict(constructed=True))


def validate_pin(c, value, commit):
    keys(c, value, 'pin-consumption.json')
    for key, expected in dict(schema='chengwang.pinned-browser-consumption-verification/v1', sourceCommit=commit,
                              state='PIN_ENFORCED_EXPANDED_NOT_EXECUTED', pinSHA256=PIN_SHA).items(): same(value[key], expected)
    for key in ('pinEnforced', 'allMemberCRCsVerified', 'actualExpandedFileHashesVerified'): same(value[key], True)
    for key in ('browserExecuted', 'runtimeVersionProven', 'projectFixProven', 'publisherSignatureProven', 'production'): same(value[key], False)
    same(value['zip'], dict(bytes=202676171, sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853', md5Base64='5qChIL/Gh+8hZv73vzEakQ=='))
    same(value['elf'], dict(path='chrome-linux64/chrome', bytes=CHROME_BYTES, sha256=CHROME_SHA, byteOrder='little',
                          entryPoint=124443728, loadSegments=4, machine='x86_64', programHeaderCount=12, type='DYN', **{'class': 'ELF64'}))
    for key in ('sourceFilesVerified', 'expandedMemberCount', 'expandedBytes'): integer(value[key], 1)
    digest(value['expandedMembersSHA256']); text(value['mode'], 128, False)
    need(type(value['limitations']) is list and 1 <= len(value['limitations']) <= 32)
    for limitation in value['limitations']: text(limitation)


def action_timings(c, driver, profile):
    value = driver['actionTimings']; keys(c, value, 'driver.actionTimings', True)
    if profile == 'evidence_disabled':
        same(value['nodeVisit'], None); return
    visit = value['nodeVisit']; keys(c, visit, 'driver.actionTimings.nodeVisit', True)
    entered = integer(visit['enteredMonotonicUs']); returned = integer(visit['returnedMonotonicUs'], entered)
    need(returned - entered <= 10000000)


def openssl_verify(arguments):
    """Offline public-certificate operation; no sockets, raw errors or bypass."""
    result = subprocess.run(['openssl', *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=10, env={'PATH': os.environ.get('PATH', os.defpath), 'OPENSSL_CONF': os.devnull})
    need(result.returncode == 0 and len(result.stdout) <= 65536 and len(result.stderr) <= 65536)


def verify_tls(c, certs, driver, captures):
    keys(c, certs, 'certificates.json')
    def der(value):
        need(type(value) is str and len(value) <= 65536 and re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?', value))
        result = base64.b64decode(''.join(value.splitlines()[1:-1]), validate=True); need(result); return result
    ca, leaf = der(certs['caPEM']), der(certs['leafPEM'])
    same(driver['normalTrust'], dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,', caSHA256=sha(ca), leafSHA256=sha(leaf), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True))
    tls = driver['tls']; keys(c, tls, 'driver.tls', True)
    same(tls['securityState'], 'secure'); need(tls['protocol'] in ('TLS 1.2', 'TLS 1.3')); need(type(tls['cipher']) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', tls['cipher']))
    for key, expected in dict(caSHA256=sha(ca), leafSHA256=sha(leaf), leafSignatureVerified=True, ipSANVerified=True).items(): same(tls[key], expected)
    chain = driver['certificateChain']; need(type(chain) is list and 1 <= len(chain) <= 2)
    same(tls['serverChainLength'], len(chain)); same([unbase64(item, 65536) for item in chain], [leaf] if len(chain) == 1 else [leaf, ca])
    stamp = min(row['startedWallTimeUs'] for row in captures) // 1000000
    with tempfile.TemporaryDirectory(prefix='overview-offline-public-cert-') as directory:
        root = Path(directory); ca_path, leaf_path = root / 'ca.pem', root / 'leaf.pem'
        ca_path.write_text(certs['caPEM'], encoding='ascii'); leaf_path.write_text(certs['leafPEM'], encoding='ascii')
        openssl_verify(['verify', '-trusted', str(ca_path), '-check_ss_sig', '-attime', str(stamp), '-purpose', 'sslserver', '-verify_ip', '127.0.0.1', str(leaf_path)])


def load_contract():
    raw = read(HERE / 'contract.json', 131072); c = decode(raw)
    same(c['schema'], 'chengwang.overview-ui-browser-contract/v1'); same(c['scenario'], 'overview_ui')
    same(c['profiles'], list(PROFILES)); same(c['engines'], ['chrome-cdp', 'playwright']); same(c['origin'], 'https://127.0.0.1:17891')
    need(len(c['publicFiles']) == len(set(c['publicFiles'])) == 19)
    same(c['counterRules']['rawKeys'], list(COUNTERS)); same(c['counterRules']['strictZeroKeys'], list(STRICT_ZERO))
    same(c['apiExpected']['overviewEnabled'], unknown_overview())
    for profile, count, points, maximum in [(PROFILES[0], 6, 11, 72), (PROFILES[1], 9, 17, 77)]:
        p = c['profileFacts'][profile]
        same(p['apiCounts'], dict(snapshot=1, overview=count, observationStatus=int(profile == PROFILES[1]), probeStatus=int(profile == PROFILES[1])))
        same(p['domCheckpoints'], points); same(len(c['stepFences'][profile]), points); same(p['requestsMax'], maximum)
        same(c['profilePolicies'][profile]['env']['CHENGWANG_LIVE_OVERVIEW_ENABLED'], 'true' if profile == PROFILES[1] else 'false')
    return c, raw


def verify(directory, repo, commit, engine, profile):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit) and engine in ('chrome-cdp', 'playwright') and profile in PROFILES)
    directory, repo = no_symlinks(directory), no_symlinks(repo)
    c, contract_raw = load_contract(); same(set(path.name for path in directory.iterdir()), set(c['publicFiles']))
    bounds = c['captureRules']['bounds']
    def limit(name):
        return bounds['driverFileBytes'] if name == 'driver.json' else bounds['captureFile'] if name == 'captures.jsonl' else bounds['domFileBytes'] if name == 'dom.jsonl' else c['pngFileBytesMax'] if name.endswith('.png') else c['buildFileBytesMax'] if name == 'build.json' else 16 << 20
    raw = {name: read(directory / name, limit(name)) for name in c['publicFiles']}
    need(all(b'PRIVATE KEY' not in value for value in raw.values()))
    driver = decode(raw['driver.json'], True); fixture = driver.get('fixtureId')
    need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture)); identity(c, driver, 'driver.json', commit, engine, profile, fixture)
    same(driver['origin'], c['origin']); same(driver['scope'], dict(tenantId='', siteId='', environment='candidate', objectType='control-plane', objectId='local'))
    same(driver['runtime'], True)
    for key in ('mockedResponses', 'injectedFetch', 'tlsBypass'): same(driver[key], False)
    keys(c, driver['browser'], 'driver.browser', True)
    need(driver['browser']['product'] in ('Chrome/157.0.8103.6', 'HeadlessChrome/157.0.8103.6'))
    same(driver['browser']['revision'], '@' + CHROME_TAG); same(driver['browser']['protocolVersion'], '1.3')
    same(driver['steps'], [row[0] for row in c['stepFences'][profile]])
    action_timings(c, driver, profile)
    build = decode(raw['build.json']); files, required, allowed = validate_build(c, build, commit)
    captures = json_lines(raw['captures.jsonl'], c['profileFacts'][profile]['requestsMax'], 12 << 20)
    aliases, kinds, bodies = validate_captures(c, captures, files, required, allowed, profile)
    qualification = validate_events(c, driver, aliases, profile)
    same(driver['captures'], dict(path='captures.jsonl', bytes=len(raw['captures.jsonl']), sha256=sha(raw['captures.jsonl']), records=len(captures)))
    dom = json_lines(raw['dom.jsonl'], c['profileFacts'][profile]['domCheckpoints'], bounds['domRowBytes'], True)
    validate_dom(c, dom, captures, bodies, profile)
    shots = driver['screenshots']; fences = [row for row in c['stepFences'][profile] if row[10] is not None]
    need(type(shots) is list and len(shots) == len(fences) == 8)
    for shot, fence in zip(shots, fences):
        keys(c, shot, 'driver.screenshots[]', True); same(shot['path'], fence[10]); same(shot['step'], fence[0])
        same(shot['bytes'], len(raw[fence[10]])); same(shot['sha256'], sha(raw[fence[10]])); same(shot['viewport'], dict(width=fence[5], height=fence[6]))
        row = next(row for row in dom if row['step'] == fence[0])
        for key in ('scrollX', 'scrollY'): same(shot[key], row['dom']['viewport'][key])
        integer(shot['capturedWallTimeUs'], min(row['startedWallTimeUs'] for row in captures))
        png(raw[fence[10]], fence[5], fence[6])
    iso, processes, inputs = [decode(raw[name]) for name in ('isolation.json', 'processes.json', 'inputs.json')]
    records = validate_processes(c, processes, iso, inputs, build, driver, commit, engine, profile, fixture)
    validate_pin(c, decode(raw['pin-consumption.json']), commit)
    source, copies, blobs = source_bindings(c, iso, inputs, build, repo, commit)
    same({key: copies['build/report.json'][key] for key in ('bytes', 'sha256')}, dict(bytes=len(raw['build.json']), sha256=sha(raw['build.json'])))
    runtime_facts(c, decode(raw['runtime-facts.json']), decode(raw['storage-readback.json']), records, commit, engine, profile, fixture)
    verify_tls(c, decode(raw['certificates.json']), driver, captures)
    same(set(path.name for path in directory.iterdir()), set(raw)); same(raw, {name: read(directory / name, limit(name)) for name in raw})
    same(read(HERE / 'contract.json'), contract_raw)
    for name, path in [(OWN_PATH, Path(__file__)), (PRIMITIVES_PATH, Path(_spec.origin))]: same(read(path), blobs[name])
    limitations = ['SOURCE_BOUND_TRUSTED_CI_NOT_BROWSER_INTERNAL_OR_PRIVATE_STORAGE_ATTESTATION',
        'QUALIFIED_NETWORK_ERROR_LOG_IS_HTTP_503_ASSOCIATION_NOT_CAUSALITY_OR_NO_LEAK_PROOF_BEFORE_CLOSE_IS_SOURCE_BOUND_CI_PROJECTION',
        'ERROR_BODY_BYTES_CODE_AND_ABSENCE_OF_LEAKAGE_UNPROVEN_WHEN_UNAVAILABLE',
        'DOM_AUTHENTICATED_RESULT_VISIBILITY_IS_NOT_NETWORK_AUTHORIZATION_PROOF',
        'PER_CHECKPOINT_QUIESCENCE_SOURCE_BOUND_AND_RECORDED_NODE_VISIT_MONOTONIC_TIMER_QUANTIZED_1US_NOT_EXTERNAL_TIME_ATTESTATION',
        'NO_FORCED_TIMEOUT_LATE_RESPONSE_OR_HEALTHY_TO_STALE_FAULT_FLOW',
        'NO_BUSINESS_INTERNET_DNS_RBAC_PRODUCTION_OR_REPRODUCIBLE_BUILD_PROOF']
    report = dict(schema=c['schemaNames']['report'], sourceCommit=commit, fixtureId=fixture, engine=engine, scenario='overview_ui', profile=profile,
        production=False, outcome='PASS', authorization='BLOCKED', acceptanceScope='OVERVIEW_READONLY_ERROR_UNKNOWN_UI_FLOW',
        **qualification, evidenceSHA256={name: sha(raw[name]) for name in sorted(raw)}, limitations=limitations)
    keys(c, report, 'report'); return report


def main(argv=None):
    class ClosedParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('overview evidence rejected')
    parser = ClosedParser(add_help=False)
    for name in ('evidence', 'repo', 'report'): parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--source-commit', required=True); parser.add_argument('--engine', required=True); parser.add_argument('--profile', required=True)
    args = parser.parse_args(argv)
    directory, repo, output = no_symlinks(args.evidence), no_symlinks(args.repo), no_symlinks(args.report)
    need(output.parent.is_dir() and not output.exists() and not output.is_relative_to(directory) and not output.is_relative_to(repo))
    result = verify(directory, repo, args.source_commit, args.engine, args.profile)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(canonical(result) + b'\n'); handle.flush(); os.fsync(handle.fileno())
    finally: os.close(fd)
    print('OVERVIEW_UI_INDEPENDENT=PASS scope=readonly_error_unknown_ui production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('OVERVIEW_UI_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
