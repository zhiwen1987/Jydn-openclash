"""Complete synthetic protocol fixtures, never actual browser/build evidence.

Only Git object responses and the offline OpenSSL invocation are modelled.
The actual new verifier, real temporary evidence files, PNG parser, every wire/
DOM/process/source rule and report exclusivity run without producer imports.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import re
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('overview_independent_test_target', HERE / 'check_overview_ui.py')
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)
SYN_SPEC = importlib.util.spec_from_file_location('overview_synthetic_test_target', HERE / 'check_overview_synthetic.py')
S = importlib.util.module_from_spec(SYN_SPEC); SYN_SPEC.loader.exec_module(S)
ROOT = HERE.parents[2]
COMMIT = '1' * 40
FIXTURE = '2' * 32
SCOPE = dict(tenantId='', siteId='', environment='candidate', objectType='control-plane', objectId='local')
CONTRACT = C.decode((HERE / 'contract.json').read_bytes())


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def png(width, height):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress((b'\0' * (width * 3 + 1)) * height)) + chunk(b'IEND', b'')


def snapshot():
    return dict(product='Synthetic protocol fixture only', version='unit', mode='candidate', status='not real runtime evidence',
        dataSource='demo', publishLocked=True, businesses=None, pools=None, interfaces=None, events=None,
        draft=dict(name='synthetic', baseVersion='', businesses=None, pools=None,
                   dns=dict(domesticResolvers=None, overseasResolvers=None, hijackPort53=False, leakProtection=False)))


def build_fixture(profile='evidence_disabled', engine='chrome-cdp', gap=False, canceled=False):
    c = CONTRACT; bounds = c['captureRules']['bounds']; files = {}
    def json_file(name, value): files[name] = encoded(value) + b'\n'
    def identity(schema): return dict(schema=schema, sourceCommit=COMMIT, fixtureId=FIXTURE, engine=engine, scenario='overview_ui', profile=profile, production=False)
    base = '/tmp/chengwang-subscription-ui-' + FIXTURE; bundle = '/tmp/chengwang-subscription-ui-tools-' + FIXTURE
    dist = {'index.html': b'<html>CPU fixture, not a product build</html>', 'trust.html': b'<html>unused trust</html>', 'assets/main.js': b'/* CPU asset */'}
    manifest = {'index.html': dict(file='assets/main.js', src='index.html', isEntry=True, names=['main'])}
    dist['.vite/manifest.json'] = encoded(manifest)
    build = dict(schema=c['schemaNames']['build'], sourceCommit=COMMIT, goVersion='go1.23.12', nodeVersion='v22.23.3', moduleMode='vendor',
        goDependencyDownloads=False, server=dict(name='server', bytes=12, sha256='a' * 64),
        distFiles=[dict(path=name, bytes=len(raw), sha256=C.sha(raw)) for name, raw in sorted(dist.items())],
        manifestBase64=base64.b64encode(dist['.vite/manifest.json']).decode(), production=False, authorization='BLOCKED')
    json_file('build.json', build)
    captures, dom_rows, kind_counts = [], [], {key: 0 for key in C.PATHS}
    def capture(kind, path, value, unavailable=False, failure=False):
        ordinal = len(captures) + 1; raw = value if isinstance(value, bytes) else encoded(value)
        status = 503 if kind == 'OVERVIEW' and profile == 'evidence_disabled' else 200
        terminal = dict(event='NET_FAIL', encodedDataLength=None, canceled=True, blockedReasonPresent=False, corsErrorPresent=False) if failure else dict(event='FINISH', encodedDataLength=len(raw), canceled=None, blockedReasonPresent=None, corsErrorPresent=None)
        row = dict(schema=c['schemaNames']['capture'], ordinal=ordinal, requestOrdinal=ordinal, requestId='r' + str(ordinal), method='GET', path=path,
            kind=kind, status=status, authorizationPresent=False, requestPublic=None,
            responseBase64=None if unavailable else base64.b64encode(raw).decode(), responseSHA256=None if unavailable else C.sha(raw), responseBytes=None if unavailable else len(raw),
            startedWallTimeUs=1792800000000000 + ordinal, startTimeUs=1000 + ordinal, headerTimeUs=3000 + ordinal, endTimeUs=2000 + ordinal,
            terminal=terminal, bodyState='unavailable' if unavailable else 'present', bodyUnavailableReason=C.RPC_GAP if unavailable else None,
            errorCodeObserved=None if unavailable or status != 503 else 'overview_not_configured', bodyRPC=dict(attempted=True, outcome='rejected' if unavailable else 'fulfilled'))
        captures.append(row)
        if kind in kind_counts: kind_counts[kind] += 1
        return row
    capture('DOCUMENT', '/', dist['index.html']); capture('ASSET', '/assets/main.js', dist['assets/main.js']); capture('SNAPSHOT', C.PATHS['SNAPSHOT'], snapshot())
    generated = '2026-10-24T03:04:05.123456789Z'
    def geometry(present=True, rendered=True):
        return dict(present=present, rendered=present and rendered, inViewport=present and rendered,
                    rect=dict(x=1, y=1, width=20, height=20) if present and rendered else None)
    for ordinal, fence in enumerate(c['stepFences'][profile], 1):
        while kind_counts['OVERVIEW'] < fence[7]:
            value = c['expected503Union']['present']['body'] if profile == 'evidence_disabled' else {**C.unknown_overview(), 'generatedAt': generated}
            capture('OVERVIEW', C.PATHS['OVERVIEW'], value, gap and kind_counts['OVERVIEW'] == 0, canceled and kind_counts['OVERVIEW'] == 0)
        for kind, target in [('OBSERVATION_STATUS', fence[8]), ('PROBE_STATUS', fence[9])]:
            while kind_counts[kind] < target: capture(kind, C.PATHS[kind], c['apiExpected']['observationStatusDisabled' if kind == 'OBSERVATION_STATUS' else 'probeStatusDisabled'])
        view = fence[3]; actual = demo = detail = None
        if view == 'actual':
            expected = c['domSemantics']['disabled' if profile == 'evidence_disabled' else 'enabled']
            actual = dict(state=expected['state'], alert=expected['alert'], pendingText=None, boundaryText=c['domSemantics']['actualBoundary'] + ' ' + c['domSemantics']['asOfNotice'],
                summary=[], sourceCards=[], unsupported=None, timeElements=[], healthMetricsPresent=False)
            if profile == 'evidence_enabled_unknown':
                actual.update(summary=[s.replace('{generatedAt}', generated) for s in c['domSemantics']['summaryText']],
                              unsupported=copy.deepcopy(c['domSemantics']['unsupported']), timeElements=[dict(dateTime=generated, text=generated)])
                sections = [c['domSemantics']['controllerSections'], [dict(heading=None, facts=c['domSemantics']['probeFacts'])], [dict(heading=None, facts=c['domSemantics']['subscriptionFacts'])]]
                for index in range(3):
                    actual['sourceCards'].append(dict(heading=c['domSemantics']['cardHeadings'][index], badge=expected['controllerBadge'] if index == 0 else expected['probeBadge'] if index == 1 else '', badgeCurrent=False,
                        sections=[dict(heading=s['heading'], facts=[dict(label=label, text=text, dateTime=None) for label, text in s['facts']]) for s in sections[index]],
                        buttonLabel=next(s['label'] for s in c['controlSlots'] if s['key'] == ['cta_device', 'cta_nodes', 'cta_subscriptions'][index])))
        elif view == 'demo':
            demo = dict(status=snapshot()['status'], mode='candidate', badge='总览只读', boundaryText='总览仅展示数据边界；执行权限以服务端授权为准',
                demoAlertTitle='当前总览没有接入真实运行数据', demoAlertText='为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。',
                **{key: False for key in ('businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent')})
        else:
            detail = dict(kind=view, heading=fence[4], tokenInputsEmpty=True, authenticatedResultVisible=False, observationStatusVisible=view == 'proxy_observation', probeStatusVisible=view == 'proxy_observation')
        controls = []
        for slot in c['controlSlots']:
            key = slot['key']; present = key.startswith('nav_') or key.startswith('source_') and view in ('demo', 'actual') or key == 'actual_refresh' and view == 'actual' or key.startswith('cta_') and view == 'actual' and profile == 'evidence_enabled_unknown'
            controls.append(dict(key=key, label=slot['label'] if present else None, labelSource=slot['labelSource'] if present else None,
                **geometry(present), enabled=present, unobstructed=present,
                ariaPressed=('true' if (key == 'source_demo') == (view == 'demo') else 'false') if key.startswith('source_') and present else None))
        topbar = {}
        label = c['domSemantics']['disabled' if profile == 'evidence_disabled' else 'enabled']['sourceBadge'] if view == 'actual' else '演示草稿'
        mode = c['domSemantics']['disabled' if profile == 'evidence_disabled' else 'enabled']['modeBadge'] if view == 'actual' else 'candidate'
        for key, text in dict(product=snapshot()['product'], sourceLabel=label, mode=mode, kernel='未核验').items(): topbar[key] = dict(text=text, **geometry(True, fence[5] > 900))
        api = dict(snapshotCaptureOrdinal=3, overviewCaptureOrdinals=[r['ordinal'] for r in captures if r['kind'] == 'OVERVIEW'],
            observationStatusCaptureOrdinals=[r['ordinal'] for r in captures if r['kind'] == 'OBSERVATION_STATUS'], probeStatusCaptureOrdinals=[r['ordinal'] for r in captures if r['kind'] == 'PROBE_STATUS'])
        d = dict(schema=c['schemaNames']['dom'], navigationPage=fence[2], viewKind=view, heading=fence[4], pageMounted=True, pageVisible=True, https=True,
            viewport=dict(width=fence[5], height=fence[6], scrollX=0, scrollY=0, clientWidth=fence[5], scrollWidth=fence[5]), environment=dict(language='zh-CN', timeZone='UTC'),
            browserStorage=dict(localEmpty=True, sessionEmpty=True, cookiesEmpty=True), topbar=topbar, controls=controls, apiFence=api, actual=actual, demo=demo, detail=detail)
        dom_rows.append(dict(schema=c['schemaNames']['domRow'], ordinal=ordinal, step=fence[0], captureCount=len(captures), mutationCount=0, dom=d))
    events, counters = [], {key: 0 for key in C.COUNTERS}
    def emit(tag, **fields): events.append(dict(seq=len(events) + 1, type=tag, **fields))
    finished = 0
    for row in captures:
        alias = row['requestId']; kind = row['kind']
        emit('REQUEST', requestId=alias, requestOrdinal=row['requestOrdinal'], kind=kind, method='GET', path=row['path'], sameOrigin=True,
             queryPresent=False, fragmentPresent=False, userInfoPresent=False, authorizationPresent=False, cookiePresent=False, bodyPresent=False)
        emit('HEADERS', requestId=alias, status=row['status'], mimeClass='HTML' if kind == 'DOCUMENT' else 'JS' if kind == 'ASSET' else 'JSON', setCookiePresent=False, redirected=False, diskCache=False, serviceWorker=False)
        if row['terminal']['event'] == 'NET_FAIL':
            emit('NET_FAIL', requestId=alias, canceled=True, blockedReasonPresent=False, corsErrorPresent=False); counters['failedRequests'] += 1
        else: emit('FINISH', requestId=alias, encodedDataLength=row['terminal']['encodedDataLength']); finished += 1
        if row['bodyState'] == 'unavailable': emit('ERROR', requestId=alias, kind=kind, code='capture_error', reason=C.RPC_GAP); counters['captureErrors'] += 1
        emit('CAPTURE', requestId=alias, captureOrdinal=row['ordinal'], responseBytes=row['responseBytes'], responseSHA256=row['responseSHA256'], bodyState=row['bodyState'], bodyUnavailableReason=row['bodyUnavailableReason'], bodyRPCOutcome=row['bodyRPC']['outcome'])
    emit('META', requests=len(captures), headers=len(captures), finished=finished, failed=counters['failedRequests'], captured=len(captures), pending=0, tasks=0, ignoredFavicon=0, mutations=0, overflow=False)
    captures_raw = b''.join(encoded(row) + b'\n' for row in captures); files['captures.jsonl'] = captures_raw; files['dom.jsonl'] = b''.join(encoded(row) + b'\n' for row in dom_rows)
    screenshots = []
    for fence in c['stepFences'][profile]:
        if fence[10] is None: continue
        raw = png(fence[5], fence[6]); files[fence[10]] = raw
        screenshots.append(dict(path=fence[10], step=fence[0], bytes=len(raw), sha256=C.sha(raw), viewport=dict(width=fence[5], height=fence[6]), scrollX=0, scrollY=0, capturedWallTimeUs=1792800001000000))
    caps = {key: '0000000000000000' for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}
    namespaces = dict(net='net:[11]', mnt='mnt:[12]', pid='pid:[13]', user='user:[4]')
    records = []
    argvs = dict(server=[bundle + '/server'], controller=[bundle + '/node', bundle + '/source/chengwang/tools/overview-ui-browser/ui-cli.mjs', '--root', base, '--bundle', bundle, '--engine', engine, '--source-commit', COMMIT],
                 chrome=[bundle + '/chrome/chrome', '--no-sandbox', '--user-data-dir=' + base + '/chrome-profile'])
    for index, role in enumerate(('server', 'controller', 'chrome'), 101):
        records.append(dict(pid=index, startTime=str(index), exeSHA256=build['server']['sha256'] if role == 'server' else C.CHROME_SHA if role == 'chrome' else 'b' * 64,
            argvSHA256=C.sha(b''.join(s.encode() + b'\0' for s in argvs[role])), uid=[10001] * 4, gid=[10001] * 4, groups=[], capabilities=copy.deepcopy(caps), noNewPrivs=1, namespaces=copy.deepcopy(namespaces),
            limits=dict(cpuSeconds=[180, 180], fileBytes=[32 << 20] * 2, openFiles=[1024] * 2, processes=[1024] * 2, coreBytes=[0, 0]), role=role, argv=argvs[role]))
    chrome = dict(pid=103, startTicks=103, uid=10001, profile=base + '/chrome-profile', argvSHA256=records[2]['argvSHA256'], exeSHA256=C.CHROME_SHA, exeBytes=C.CHROME_BYTES)
    ca, leaf = b'PUBLIC_SYNTHETIC_CA_NOT_CRYPTO_PROOF', b'PUBLIC_SYNTHETIC_LEAF_NOT_CRYPTO_PROOF'
    pem = lambda raw: '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(raw).decode() + '\n-----END CERTIFICATE-----\n'
    json_file('certificates.json', dict(caPEM=pem(ca), leafPEM=pem(leaf)))
    driver = dict(identity(c['schemaNames']['driver']), origin=c['origin'], scope=copy.deepcopy(SCOPE), runtime=True, mockedResponses=False, injectedFetch=False, tlsBypass=False,
        browser=dict(product='Chrome/157.0.8103.6', revision='@' + C.CHROME_TAG, protocolVersion='1.3'), chrome=chrome,
        normalTrust=dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,', caSHA256=C.sha(ca), leafSHA256=C.sha(leaf), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True),
        tls=dict(securityState='secure', protocol='TLS 1.3', cipher='AES_256_GCM', leafSHA256=C.sha(leaf), caSHA256=C.sha(ca), serverChainLength=2, leafSignatureVerified=True, ipSANVerified=True),
        certificateChain=[base64.b64encode(leaf).decode(), base64.b64encode(ca).decode()], counters=counters, events=events,
        close=dict(normalCloseCommandCompleted=True, chromeExit=dict(schema='chengwang.subscription-ui-chrome-exit/v1', engine=engine, fixtureId=FIXTURE, pid=103, startTicks=103, exitCode=0, joined=True, forced=False),
                   launcherExit=dict(code=0, signal=None) if engine == 'chrome-cdp' else None, noLiveOwnedProcesses=True, processScope='CHROME_SESSION_AND_LAUNCHER_ONLY'),
        steps=[fence[0] for fence in c['stepFences'][profile]], actionTimings=dict(nodeVisit=None if profile == 'evidence_disabled' else dict(enteredMonotonicUs=100, returnedMonotonicUs=1000100)),
        captures=dict(path='captures.jsonl', bytes=len(captures_raw), sha256=C.sha(captures_raw), records=len(captures)), screenshots=screenshots)
    json_file('driver.json', driver)
    pin = dict(schema='chengwang.pinned-browser-consumption-verification/v1', sourceCommit=COMMIT, state='PIN_ENFORCED_EXPANDED_NOT_EXECUTED', pinSHA256=C.PIN_SHA,
        sourceFilesVerified=1, mode='synthetic CPU only', zip=dict(bytes=202676171, sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853', md5Base64='5qChIL/Gh+8hZv73vzEakQ=='),
        expandedMemberCount=1, expandedBytes=C.CHROME_BYTES, expandedMembersSHA256='c' * 64,
        elf=dict(path='chrome-linux64/chrome', bytes=C.CHROME_BYTES, sha256=C.CHROME_SHA, byteOrder='little', entryPoint=124443728, loadSegments=4, machine='x86_64', programHeaderCount=12, type='DYN', **{'class': 'ELF64'}),
        pinEnforced=True, allMemberCRCsVerified=True, actualExpandedFileHashesVerified=True, browserExecuted=False, runtimeVersionProven=False, projectFixProven=False, publisherSignatureProven=False, production=False, limitations=['Synthetic CPU metadata, never execution proof'])
    json_file('pin-consumption.json', pin)
    blobs = {name: (ROOT / name).read_bytes() for name in [C.OWN_PATH, C.CONTRACT_PATH, C.PRIMITIVES_PATH]}
    wanted = ['chengwang/deploy/overview-ui-browser/overview_ui_scene.py', 'chengwang/deploy/overview-ui-browser/run_overview_ui.py',
        'chengwang/deploy/browser-scene-supervisor/supervisor.py', 'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
        'chengwang/deploy/browser-stream-matrix/run_matrix.py',
        'chengwang/tools/overview-ui-browser/ui-cli.mjs', 'chengwang/tools/overview-ui-browser/ui-driver.mjs', 'chengwang/tools/overview-ui-browser/ui-dom.mjs',
        'chengwang/tools/overview-ui-browser/overview-journal.mjs', 'chengwang/tools/overview-ui-browser/wire-contract.mjs', 'chengwang/tools/overview-ui-browser/ui-contract.mjs',
        'chengwang/tools/browser-scene-driver/native-session.mjs', 'chengwang/tools/capability-truth-browser/ui-driver.mjs', 'chengwang/tools/capability-truth-browser/ui-contract.mjs',
        'chengwang/tools/capability-truth-browser/ui-dom.mjs', 'chengwang/tools/subscription-ui-browser/ui-driver.mjs',
        'chengwang/tools/subscription-ui-browser/navigation-diagnostics.mjs', 'chengwang/tools/subscription-ui-browser/navigation-diagnostics-contract.json',
        'chengwang/tools/subscription-ui-browser/ui-contract.mjs', 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py', 'chengwang/web/scripts/trust-browser-tls.mjs']
    for name in wanted: blobs[name] = (ROOT / name).read_bytes()
    source = [dict(path=name, bytes=len(raw), sha256=C.sha(raw)) for name, raw in sorted(blobs.items())]
    copies = copy.deepcopy(source)
    copies.append(dict(copies[next(index for index, row in enumerate(copies) if row['path'] == 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py')], path='chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py:launcher'))
    copies += [dict(path='chrome/chrome', bytes=C.CHROME_BYTES, sha256=C.CHROME_SHA), dict(path='toolchain/node', bytes=1, sha256='b' * 64),
        dict(path='toolchain/server', bytes=build['server']['bytes'], sha256=build['server']['sha256']), dict(path='npm/playwright-core/package.json', bytes=1, sha256='d' * 64),
        dict(path='build/report.json', bytes=len(files['build.json']), sha256=C.sha(files['build.json']))]
    copies += [dict(path='dist/' + name, bytes=len(raw), sha256=C.sha(raw)) for name, raw in dist.items()]
    copies.sort(key=lambda row: row['path'])
    json_file('inputs.json', dict(identity(c['schemaNames']['supervisor']), copiedInputs=copies, inputTrustScope=C.INPUT_TRUST))
    host = dict(netNamespace='net:[1]', mountNamespace='mnt:[2]', pidNamespace='pid:[3]', userNamespace='user:[4]', portStart=32768, systemCASHA256='e' * 64, sourceSHA256=C.sha(C.canonical(source)))
    json_file('isolation.json', dict(identity(c['schemaNames']['supervisor']), hostBefore=host, hostAfter=copy.deepcopy(host), sourceFilesBefore=source, sourceFilesAfter=copy.deepcopy(source),
        lab=dict(namespaces=namespaces, defaultIPv4Routes=0, defaultIPv6Routes=0, interfaces=['lo'], sourceMount=['ro', 'nosuid', 'nodev'], bundleMount=['ro', 'nosuid', 'nodev'], tmpMount=['rw', 'nosuid', 'nodev', 'noexec']),
        authorization='BLOCKED', deviceActionsExecuted=False, pythonBinaryProvenanceProven=False))
    json_file('processes.json', dict(identity(c['schemaNames']['supervisor']), records=records, serverExitCode=0, controllerExitCode=0, noLiveOwnedProcesses=True, forcedSignals=0, processScope=C.PROCESS_TRUST))
    server = records[0]
    runtime = dict(identity(c['schemaNames']['runtime']), scope=copy.deepcopy(SCOPE), serverIdentity=dict(pid=101, startTicks=101, exeSHA256=server['exeSHA256'], argvSHA256=server['argvSHA256']),
        environment=[dict(name=name, value=value) for name, value in sorted(c['profilePolicies'][profile]['env'].items())],
        **{key: copy.deepcopy(c['runtimeLeafValues'][key]) for key in ('identities', 'mihomo', 'observer', 'probe', 'subscription', 'writeGates', 'policyCatalog', 'upstreamListener', 'snapshotsProvider', 'trustBoundary')},
        liveOverview=dict(enabled=profile == 'evidence_enabled_unknown'))
    json_file('runtime-facts.json', runtime)
    json_file('storage-readback.json', dict(identity(c['schemaNames']['storage']), scope=copy.deepcopy(SCOPE),
        **{key: copy.deepcopy(c['storageLeafValues'][key]) for key in ('subscriptionStore', 'observationStore', 'operationStore', 'evidenceStore')}, trustBoundary=c['runtimeLeafValues']['trustBoundary']))
    if set(files) != set(c['publicFiles']): raise AssertionError('synthetic public closure differs')
    return files, blobs


class OverviewCheckerContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = {(p, e): build_fixture(p, e) for p in C.PROFILES for e in ('chrome-cdp', 'playwright')}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='overview-verifier-cpu-')
        self.addCleanup(self.temporary.cleanup); self.base = Path(self.temporary.name)
        self.evidence = self.base / 'evidence'; self.repo = self.base / 'repository'; self.evidence.mkdir(); self.repo.mkdir()
        self.profile = 'evidence_disabled'; self.engine = 'chrome-cdp'
        self.install()
        self.git_patch = patch.object(C, 'git', side_effect=self.fake_git); self.git_patch.start(); self.addCleanup(self.git_patch.stop)
        self.crypto_patch = patch.object(C, 'openssl_verify', side_effect=self.fake_crypto); self.crypto_patch.start(); self.addCleanup(self.crypto_patch.stop)
        # Every negative first proves this complete real-file fixture can pass.
        self.assertEqual(self.verify()['outcome'], 'PASS')

    def install(self, profile=None, engine=None, *, gap=False, canceled=False):
        self.profile = profile or self.profile; self.engine = engine or self.engine
        files, self.blobs = build_fixture(self.profile, self.engine, gap, canceled) if gap or canceled else copy.deepcopy(self.fixtures[(self.profile, self.engine)])
        for path in self.evidence.iterdir(): path.unlink()
        for name, raw in files.items(): (self.evidence / name).write_bytes(raw)

    def fake_git(self, repo, *args, input_bytes=None):
        self.assertEqual(repo, self.repo)
        if args == ('ls-tree', '-r', '-z', '--name-only', COMMIT, '--', 'chengwang', '.github/workflows'):
            return b''.join(name.encode() + b'\0' for name in sorted(self.blobs))
        self.assertEqual(args, ('cat-file', '--batch'))
        output = bytearray()
        for request in input_bytes.decode().splitlines():
            self.assertTrue(request.startswith(COMMIT + ':')); raw = self.blobs[request[len(COMMIT) + 1:]]
            digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            output.extend((digest + ' blob ' + str(len(raw)) + '\n').encode() + raw + b'\n')
        return bytes(output)

    def fake_crypto(self, arguments):
        self.assertEqual(arguments[0], 'verify'); self.assertIn('-check_ss_sig', arguments)
        self.assertEqual(arguments[arguments.index('-attime') + 1], '1792800000')
        self.assertEqual(arguments[arguments.index('-verify_ip') + 1], '127.0.0.1')
        self.assertNotIn('-no_check_time', arguments)

    def verify(self): return C.verify(self.evidence, self.repo, COMMIT, self.engine, self.profile)
    def json(self, name): return json.loads((self.evidence / name).read_bytes())
    def save(self, name, value): (self.evidence / name).write_bytes(encoded(value) + b'\n')
    def mutate(self, name, fn): value = self.json(name); fn(value); self.save(name, value)
    def rejects(self):
        with self.assertRaises((ValueError, TypeError, KeyError, OSError, AssertionError)): self.verify()
    def rows(self, name): return [json.loads(line) for line in (self.evidence / name).read_bytes().splitlines()]
    def save_rows(self, name, rows):
        raw = b''.join(encoded(row) + b'\n' for row in rows); (self.evidence / name).write_bytes(raw)
        if name == 'captures.jsonl': self.mutate('driver.json', lambda v: v['captures'].update(bytes=len(raw), sha256=C.sha(raw), records=len(rows)))

    def test_complete_nineteen_file_fixtures_cover_both_profiles_and_engines(self):
        for profile in C.PROFILES:
            for engine in ('chrome-cdp', 'playwright'):
                self.install(profile, engine); result = self.verify()
                self.assertEqual(result['outcome'], 'PASS'); self.assertFalse(result['production'])
                self.assertEqual(result['acceptanceScope'], 'OVERVIEW_READONLY_ERROR_UNKNOWN_UI_FLOW')

    def test_rpc_gap_preserves_actual_counter_and_body_privacy_gap(self):
        self.install(gap=True); result = self.verify()
        self.assertEqual(result['rawCounters']['captureErrors'], 1); self.assertFalse(result['errorBodyCompleteness'])
        self.assertEqual(len(result['coverageGaps']), 1); self.assertFalse(result['claimOriginalEightZero'])

    def test_canceled_rpc_gap_keeps_both_actual_raw_counters(self):
        self.install(gap=True, canceled=True); result = self.verify()
        self.assertEqual(result['rawCounters']['failedRequests'], 1); self.assertEqual(result['rawCounters']['captureErrors'], 1)

    def test_canceled_terminal_may_still_have_a_complete_error_body(self):
        self.install(canceled=True); result = self.verify()
        self.assertTrue(result['errorBodyCompleteness']); self.assertEqual(result['rawCounters']['captureErrors'], 0)

    def test_exact_public_closure_rejects_extra_and_missing_files(self):
        (self.evidence / 'passed.json').write_bytes(b'{"passed":true}'); self.rejects()
        (self.evidence / 'passed.json').unlink(); (self.evidence / 'actual-mobile.png').unlink(); self.rejects()

    def test_source_commit_engine_profile_or_fixture_cannot_be_relabelled(self):
        for key, wrong in [('sourceCommit', '3' * 40), ('engine', 'playwright'), ('profile', 'evidence_enabled_unknown'), ('fixtureId', '3' * 32)]:
            self.install('evidence_disabled', 'chrome-cdp'); self.mutate('driver.json', lambda v: v.update({key: wrong})); self.rejects()

    def test_build_manifest_cannot_be_replaced_without_raw_hash_binding(self):
        self.mutate('build.json', lambda v: v.update(manifestBase64=base64.b64encode(b'{}').decode())); self.rejects()

    def test_manifest_static_and_dynamic_graphs_keep_independent_visited_sets(self):
        manifest = {'index.html': dict(file='assets/main.js', isEntry=True, dynamicImports=['shared'], imports=['static']),
                    'static': dict(file='assets/static.js', imports=['shared']), 'shared': dict(file='assets/shared.js', css=['assets/shared.css'])}
        required, allowed = C.manifest_graph(CONTRACT, manifest)
        self.assertTrue({'/assets/shared.js', '/assets/shared.css'} <= required <= allowed)

    def test_document_or_asset_bytes_must_equal_source_bound_build(self):
        rows = self.rows('captures.jsonl'); raw = b'changed document'
        rows[0].update(responseBase64=base64.b64encode(raw).decode(), responseBytes=len(raw), responseSHA256=C.sha(raw)); self.save_rows('captures.jsonl', rows); self.rejects()

    def test_missing_200_body_can_never_borrow_the_503_exception(self):
        self.install('evidence_enabled_unknown'); rows = self.rows('captures.jsonl'); row = next(r for r in rows if r['kind'] == 'OVERVIEW')
        row.update(bodyState='unavailable', bodyUnavailableReason=C.RPC_GAP, responseBase64=None, responseSHA256=None, responseBytes=None, errorCodeObserved=None, bodyRPC=dict(attempted=True, outcome='rejected'))
        self.save_rows('captures.jsonl', rows); self.rejects()

    def test_503_missing_body_must_have_rejected_rpc_and_all_four_nulls(self):
        for key, bad in [('errorCodeObserved', 'overview_not_configured'), ('responseBytes', 0), ('bodyRPC', dict(attempted=True, outcome='fulfilled'))]:
            self.install(gap=True); rows = self.rows('captures.jsonl'); next(r for r in rows if r['bodyState'] == 'unavailable')[key] = bad; self.save_rows('captures.jsonl', rows); self.rejects()

    def test_wrong_error_json_is_not_reinterpreted_as_an_rpc_gap(self):
        rows = self.rows('captures.jsonl'); row = next(r for r in rows if r['kind'] == 'OVERVIEW'); raw = encoded(dict(code='wrong', message='synthetic'))
        row.update(responseBase64=base64.b64encode(raw).decode(), responseBytes=len(raw), responseSHA256=C.sha(raw)); self.save_rows('captures.jsonl', rows); self.rejects()

    def test_fake_cancel_and_blocked_or_cors_terminal_flags_are_rejected(self):
        for key, bad in [('canceled', False), ('blockedReasonPresent', True), ('corsErrorPresent', True)]:
            self.install(canceled=True); rows = self.rows('captures.jsonl'); next(r for r in rows if r['terminal']['event'] == 'NET_FAIL')['terminal'][key] = bad; self.save_rows('captures.jsonl', rows); self.rejects()

    def test_finish_unreported_failure_flags_must_be_null(self):
        rows = self.rows('captures.jsonl'); rows[0]['terminal']['canceled'] = False; self.save_rows('captures.jsonl', rows); self.rejects()

    def test_duplicate_alias_request_or_terminal_cannot_be_a_retry(self):
        self.mutate('driver.json', lambda v: v['events'][4].update(requestId='r1')); self.rejects()

    def test_private_auth_query_or_body_request_projection_is_rejected(self):
        for key in ('authorizationPresent', 'cookiePresent', 'queryPresent', 'bodyPresent'):
            self.install(); self.mutate('driver.json', lambda v: v['events'][0].update({key: True})); self.rejects()

    def test_raw_failed_and_capture_counters_are_independently_recomputed(self):
        self.install(gap=True); self.mutate('driver.json', lambda v: v['counters'].update(captureErrors=0)); self.rejects()
        # Expected HTTP 503 network logs remain visible in the actual raw
        # console counter. No producer qualification array is consulted.
        def insert(alias=None, position='headers', changes=None, counter=1):
            driver = self.json('driver.json')
            alias = alias or next(row['requestId'] for row in self.rows('captures.jsonl') if row['kind'] == 'OVERVIEW')
            event = dict(type='LOG_NETWORK_ERROR', requestId=alias, source='network', level='error', urlSameRequest=True, workerIdPresent=False, categoryPresent=False, beforeClose=True)
            if changes: event.update(changes)
            if position == 'last': at = len(driver['events']) - 1
            elif position == 'after_meta': at = len(driver['events'])
            else:
                tag = {'headers': 'HEADERS', 'request': 'REQUEST', 'capture': 'CAPTURE'}[position]
                at = next(i for i, row in enumerate(driver['events']) if row['type'] == tag and row.get('requestId') == alias) + 1
            driver['events'].insert(at, event)
            for seq, row in enumerate(driver['events'], 1): row['seq'] = seq
            driver['counters']['consoleErrors'] += counter
            self.save('driver.json', driver); return alias
        for position in ('headers', 'capture'):
            with self.subTest(qualifiedPosition=position):
                self.install(); alias = insert(position=position); result = self.verify()
                self.assertEqual(result['rawCounters']['consoleErrors'], 1)
                self.assertEqual(result['qualifiedExpected503NetworkLogs'], [alias]); self.assertEqual(result['unexpectedConsoleErrors'], 0)
        # Distinct aliases must be reported by actual event order, not sorted
        # request order, and combining cancellation/body gaps never zero-fills.
        self.install(gap=True, canceled=True)
        aliases = [row['requestId'] for row in self.rows('captures.jsonl') if row['kind'] == 'OVERVIEW']
        insert(aliases[1], 'last'); insert(aliases[0], 'last'); result = self.verify()
        self.assertEqual(result['qualifiedExpected503NetworkLogs'], [aliases[1], aliases[0]])
        self.assertEqual(result['rawCounters']['consoleErrors'], 2)
        self.assertGreater(result['rawCounters']['failedRequests'], 0); self.assertGreater(result['rawCounters']['captureErrors'], 0)
        for key, value in [('source', 'javascript'), ('level', 'warning'), ('urlSameRequest', False), ('workerIdPresent', True), ('categoryPresent', True), ('categoryPresent', None), ('beforeClose', False), ('rawText', 'forbidden')]:
            with self.subTest(rejectedLogField=key, value=value):
                self.install(); insert(changes={key: value}); self.rejects()
        for position in ('request', 'after_meta'):
            with self.subTest(rejectedPosition=position): self.install(); insert(position=position); self.rejects()
        self.install(); alias = insert(); insert(alias); self.rejects()
        self.install(); insert('r1', 'headers'); self.rejects()
        self.install('evidence_enabled_unknown'); insert(); self.rejects()
        self.install('evidence_disabled'); insert(changes={'requestId': 'r68'}); self.rejects()
        self.install(); insert(counter=0); self.rejects()
        self.install(); self.mutate('driver.json', lambda v: v['counters'].update(consoleErrors=1)); self.rejects()
        self.install(); insert(); driver = self.json('driver.json')
        driver['events'] = [event for event in driver['events'] if event['type'] != 'LOG_NETWORK_ERROR']
        for seq, event in enumerate(driver['events'], 1): event['seq'] = seq
        self.save('driver.json', driver); self.rejects()
        # An old console ERROR is still fatal even if it names the same 503.
        self.install(); alias = insert(); driver = self.json('driver.json')
        event = next(row for row in driver['events'] if row['type'] == 'LOG_NETWORK_ERROR')
        seq = event['seq']; event.clear(); event.update(seq=seq, type='ERROR', requestId=alias, kind='OVERVIEW', code='console_error', reason='UNQUALIFIED_CAPTURE_FAILURE')
        self.save('driver.json', driver); self.rejects()

    def test_rpc_error_requires_exact_alias_kind_and_closed_reason(self):
        for key, bad in [('reason', 'UNQUALIFIED_CAPTURE_FAILURE'), ('kind', 'SNAPSHOT'), ('requestId', 'r1')]:
            self.install(gap=True); self.mutate('driver.json', lambda v: next(e for e in v['events'] if e['type'] == 'ERROR').update({key: bad})); self.rejects()

    def test_runtime_warning_cannot_be_zero_filled(self):
        self.mutate('driver.json', lambda v: v['counters'].update(consoleWarnings=1)); self.rejects()

    def test_unknown_api_shape_never_invents_coverage_or_subscription_counts(self):
        self.install('evidence_enabled_unknown'); rows = self.rows('captures.jsonl'); row = next(r for r in rows if r['kind'] == 'OVERVIEW'); value = json.loads(base64.b64decode(row['responseBase64']))
        value['subscription']['nodeCount'] = 0; raw = encoded(value); row.update(responseBase64=base64.b64encode(raw).decode(), responseBytes=len(raw), responseSHA256=C.sha(raw))
        self.save_rows('captures.jsonl', rows); self.rejects()

    def test_snapshot_nested_types_and_required_dns_fields_are_checked(self):
        value = snapshot(); value['draft']['dns'].pop('hijackPort53')
        with self.assertRaises(ValueError): C.Snapshot().parse(value)
        value = snapshot(); value['publishLocked'] = 1
        with self.assertRaises(ValueError): C.Snapshot().parse(value)

    def test_nanoseconds_year_zero_and_go_zero_are_not_confused(self):
        self.assertEqual(C.timestamp('0000-02-29T01:02:03.123456789Z'), '0000-02-29T01:02:03.123456789Z')
        for value in ('0001-01-01T00:00:00Z', '2026-02-29T00:00:00Z', '2026-01-01T00:00:00+00:00'):
            with self.assertRaises(ValueError): C.timestamp(value)

    def test_stale_dom_cannot_bind_an_old_overview_or_capture_count(self):
        rows = self.rows('dom.jsonl'); rows[2]['dom']['apiFence']['overviewCaptureOrdinals'] = rows[1]['dom']['apiFence']['overviewCaptureOrdinals']; self.save_rows('dom.jsonl', rows); self.rejects()

    def test_generated_at_dom_time_must_equal_the_current_response(self):
        self.install('evidence_enabled_unknown'); rows = self.rows('dom.jsonl'); rows[1]['dom']['actual']['timeElements'][0]['dateTime'] = '2026-10-23T00:00:00Z'; self.save_rows('dom.jsonl', rows); self.rejects()

    def test_unknown_badges_and_privileged_result_visibility_are_not_inferred(self):
        self.install('evidence_enabled_unknown'); rows = self.rows('dom.jsonl'); row = next(r for r in rows if r['dom']['viewKind'] == 'device_readback'); row['dom']['detail']['authenticatedResultVisible'] = True; self.save_rows('dom.jsonl', rows); self.rejects()

    def test_mobile_hidden_badge_cannot_be_claimed_rendered(self):
        rows = self.rows('dom.jsonl'); row = next(r for r in rows if r['dom']['viewport']['width'] == 375); row['dom']['topbar']['sourceLabel']['rendered'] = True; self.save_rows('dom.jsonl', rows); self.rejects()

    def test_nonempty_browser_storage_or_token_input_is_rejected(self):
        rows = self.rows('dom.jsonl'); rows[0]['dom']['browserStorage']['cookiesEmpty'] = False; self.save_rows('dom.jsonl', rows); self.rejects()

    def test_nodes_actual_timer_is_required_ordered_and_bounded(self):
        for value in (None, dict(enteredMonotonicUs=1, returnedMonotonicUs=10000002), dict(enteredMonotonicUs=True, returnedMonotonicUs=2)):
            self.install('evidence_enabled_unknown'); self.mutate('driver.json', lambda v: v['actionTimings'].update(nodeVisit=value)); self.rejects()

    def test_default_profile_cannot_invent_a_nodes_timer_or_status_reads(self):
        self.mutate('driver.json', lambda v: v['actionTimings'].update(nodeVisit=dict(enteredMonotonicUs=0, returnedMonotonicUs=1))); self.rejects()

    def test_source_blob_hash_and_complete_source_manifest_are_required(self):
        self.blobs[C.OWN_PATH] += b'\n# changed source\n'; self.rejects()

    def test_executing_checker_and_primitive_dependency_match_actual_git_blobs(self):
        self.blobs[C.PRIMITIVES_PATH] = b'not the executing primitive'; self.rejects()

    def test_copied_inputs_do_not_accept_mutated_build_or_unbound_code(self):
        self.mutate('inputs.json', lambda v: next(r for r in v['copiedInputs'] if r['path'] == 'toolchain/server').update(sha256='0' * 64)); self.rejects()
        # Independently walk literal relative static imports without evaluating
        # JavaScript or calling the producer. This also follows the fixed JSON
        # import in navigation-diagnostics.mjs; dormant dynamic business entry
        # functions are not claimed to have executed.
        pending, closure = ['chengwang/tools/overview-ui-browser/ui-cli.mjs'], set()
        while pending:
            name = pending.pop()
            if name in closure: continue
            closure.add(name)
            for relative in re.findall(r'\bfrom\s+[\x27\x22]([^\x27\x22]+)[\x27\x22]', (ROOT / name).read_text(encoding='utf-8')):
                if relative.startswith('.'):
                    pending.append(posixpath.normpath(posixpath.join(posixpath.dirname(name), relative)))
        self.assertEqual(len(closure), 15)
        self.assertEqual(closure, set(C.BROWSER_SOURCE_FILES))
        for name in sorted(closure | set(C.SUPERVISOR_SOURCE_FILES)):
            for operation in ('delete', 'tamper'):
                with self.subTest(dependency=name, operation=operation):
                    self.install(); self.assertEqual(self.verify()['outcome'], 'PASS')
                    def changed(value):
                        if operation == 'delete': value['copiedInputs'] = [row for row in value['copiedInputs'] if row['path'] != name]
                        else: next(row for row in value['copiedInputs'] if row['path'] == name)['sha256'] = '0' * 64
                    self.mutate('inputs.json', changed); self.rejects()

    def test_source_before_after_and_host_namespace_are_stable(self):
        self.mutate('isolation.json', lambda v: v['hostAfter'].update(netNamespace='net:[99]')); self.rejects()

    def test_uid_caps_and_readonly_mount_permissions_cannot_be_self_excused(self):
        self.mutate('processes.json', lambda v: v['records'][0].update(uid=[0] * 4)); self.rejects()
        self.install(); self.mutate('isolation.json', lambda v: v['lab'].update(sourceMount=['rw', 'nosuid', 'nodev'])); self.rejects()

    def test_parent_processes_must_join_zero_without_forced_signals(self):
        self.mutate('processes.json', lambda v: v.update(forcedSignals=1)); self.rejects()

    def test_normal_browser_close_cannot_cover_unjoined_or_forced_chrome(self):
        self.mutate('driver.json', lambda v: v['close']['chromeExit'].update(forced=True)); self.rejects()

    def test_chrome_pin_consumption_and_elf_identity_are_exact(self):
        self.mutate('pin-consumption.json', lambda v: v['elf'].update(sha256='0' * 64)); self.rejects()

    def test_tls_chain_identity_and_capture_time_are_verified_offline(self):
        self.mutate('driver.json', lambda v: v['tls'].update(ipSANVerified=False)); self.rejects()
        self.install(); self.crypto_patch.stop()
        with patch.object(C, 'openssl_verify', side_effect=ValueError('synthetic crypto rejection')): self.rejects()

    def test_tls_bypass_chrome_arguments_are_rejected_even_when_rehashed(self):
        value = self.json('processes.json'); record = next(r for r in value['records'] if r['role'] == 'chrome'); record['argv'].append('--ignore-certificate-errors')
        record['argvSHA256'] = C.sha(b''.join(s.encode() + b'\0' for s in record['argv'])); self.save('processes.json', value)
        self.mutate('driver.json', lambda v: v['chrome'].update(argvSHA256=record['argvSHA256'])); self.rejects()

    def test_runtime_environment_write_gates_and_live_flag_are_observed_facts(self):
        self.mutate('runtime-facts.json', lambda v: v['writeGates'].update(publish=True)); self.rejects()

    def test_private_storage_counts_do_not_become_production_inventory(self):
        self.mutate('storage-readback.json', lambda v: v['subscriptionStore'].update(constructed=True)); self.rejects()

    def test_png_crc_viewport_and_screenshot_hash_bindings_are_enforced(self):
        path = self.evidence / 'demo-desktop.png'; raw = path.read_bytes(); path.write_bytes(raw[:-1] + b'X'); self.rejects()

    def test_report_is_exclusive_outside_evidence_and_source(self):
        output = self.base / 'report.json'
        args = ['--evidence', str(self.evidence), '--repo', str(self.repo), '--source-commit', COMMIT, '--engine', self.engine, '--profile', self.profile, '--report', str(output)]
        with patch('builtins.print'): self.assertEqual(C.main(args), 0)
        before = output.read_bytes()
        with self.assertRaises(ValueError): C.main(args)
        self.assertEqual(output.read_bytes(), before)
        for path in (self.evidence / 'report.json', self.repo / 'report.json'):
            with self.assertRaises(ValueError): C.main(args[:-1] + [str(path)])

    def test_original_input_mutation_during_verification_cannot_pass(self):
        original_crypto = self.fake_crypto
        def changed(arguments):
            original_crypto(arguments); path = self.evidence / 'runtime-facts.json'; path.write_bytes(path.read_bytes() + b' ')
        with patch.object(C, 'openssl_verify', side_effect=changed): self.rejects()

    def synthetic_logs(self):
        """Explicit parser fixtures, never retained as actual execution logs."""
        originals = {}
        for name, (path, cls, count, _) in S.PYTHON.items():
            names = S.python_names((ROOT / path).read_bytes(), cls)
            self.assertEqual(len(names), count)
            originals[name] = ('\n'.join(f'{test} ({Path(path).stem}.{cls}.{test}) ... ok' for test in names) + f'\n\n----------------------------------------------------------------------\nRan {count} tests in 0.001s\n\nOK\n').encode()
        for name, (path, count, _) in S.NODE.items():
            names = S.node_names((ROOT / path).read_bytes()); self.assertEqual(len(names), count)
            body = ['TAP version 13']
            for number, test in enumerate(names, 1): body += ['# Subtest: ' + test, 'ok ' + str(number) + ' - ' + test, '  ---', '  duration_ms: 0.001', "  type: 'test'", '  ...']
            body += ['1..' + str(count)] + ['# ' + key + ' ' + str(value) for key, value in [('tests', count), ('suites', 0), ('pass', count), ('fail', 0), ('cancelled', 0), ('skipped', 0), ('todo', 0)]] + ['# duration_ms 0.001']
            originals[name] = ('\n'.join(body) + '\n').encode()
        return originals

    def synthetic_evidence(self):
        path = self.base / 'synthetic-parser-fixtures'; path.mkdir(exist_ok=True)
        for name, raw in self.synthetic_logs().items(): (path / name).write_bytes(raw)
        return path

    def test_synthetic_nine_log_parser_accepts_only_all_frozen_source_names(self):
        directory = self.synthetic_evidence()
        with patch.object(S, 'git_source', side_effect=lambda repo, commit, path: (repo / path).read_bytes() if commit == COMMIT else b''):
            report = S.verify(directory, ROOT, COMMIT)
        self.assertEqual(report['totalTests'], 236)
        self.assertEqual(set(report['suites']), set(S.PYTHON) | set(S.NODE))
        self.assertFalse(report['realBrowserProven']); self.assertFalse(report['realProductServerProven'])

    def test_synthetic_python_duplicate_skip_or_declaration_drift_is_rejected(self):
        name = 'overview-contract-original.log'; path, cls, count, pin = S.PYTHON[name]; raw = self.synthetic_logs()[name]; source = (ROOT / path).read_bytes()
        S.verify_python(raw, source, cls, count, pin, Path(path).stem)
        for changed in (raw + raw.splitlines()[0] + b'\n', raw.replace(b'... ok', b'... skipped', 1), raw.replace(b'OK\n', b'OK (skipped=1)\n')):
            with self.assertRaises(ValueError): S.verify_python(changed, source, cls, count, pin, Path(path).stem)
        with self.assertRaises(ValueError): S.verify_python(raw, source.replace(b'def test_', b'def changed_', 1), cls, count, pin, Path(path).stem)

    def test_synthetic_node_duplicate_skip_todo_and_false_summary_are_rejected(self):
        name = 'overview-driver.tap'; path, count, pin = S.NODE[name]; raw = self.synthetic_logs()[name]; source = (ROOT / path).read_bytes()
        S.verify_node(raw, source, count, pin)
        for changed in (raw + raw.splitlines()[1] + b'\n', raw.replace(b'\n1..13\n', b'\n1..12\n'), raw.replace(b'# skipped 0', b'# skipped 1'), raw.replace(b'# todo 0', b'# todo 1'), raw.replace(b'\nok 1 - ', b'\nnot ok 1 - ', 1), raw.replace(b'\n  ---', b' # SKIP\n  ---', 1)):
            with self.assertRaises(ValueError): S.verify_node(changed, source, count, pin)
        with self.assertRaises(ValueError): S.verify_node(raw, source.replace(b"test('d01", b"test('changed01", 1), count, pin)

    def test_synthetic_exact_nine_closure_rejects_missing_and_extra_transcripts(self):
        directory = self.synthetic_evidence()
        with patch.object(S, 'git_source', side_effect=lambda repo, commit, path: (repo / path).read_bytes()):
            S.verify(directory, ROOT, COMMIT)
            (directory / 'extra.log').write_bytes(b'not allowed')
            with self.assertRaises(ValueError): S.verify(directory, ROOT, COMMIT)
            (directory / 'extra.log').unlink(); (directory / 'native-session.tap').unlink()
            with self.assertRaises(ValueError): S.verify(directory, ROOT, COMMIT)

    def test_synthetic_source_commit_self_and_dependency_binding_are_required(self):
        directory = self.synthetic_evidence()
        with patch.object(S, 'git_source', return_value=b'not the checked-out source'):
            with self.assertRaises(ValueError): S.verify(directory, ROOT, COMMIT)
        for commit in ('main', COMMIT + '0', True):
            with self.assertRaises(ValueError): S.verify(directory, ROOT, commit)
        original = S.read
        def wrong_self(path): return b'changed executing helper' if Path(path).absolute() == Path(S.__file__).absolute() else original(path)
        with patch.object(S, 'git_source', side_effect=lambda repo, commit, path: (repo / path).read_bytes()), patch.object(S, 'read', side_effect=wrong_self):
            with self.assertRaises(ValueError): S.verify(directory, ROOT, COMMIT)

    def test_synthetic_inputs_must_remain_byte_stable_after_validation(self):
        directory = self.synthetic_evidence(); original = S.read; observed = 0
        def changing(path):
            nonlocal observed
            raw = original(path)
            if Path(path) == directory / 'overview-driver.tap':
                observed += 1
                if observed > 1: return raw + b'\n'
            return raw
        with patch.object(S, 'git_source', side_effect=lambda repo, commit, path: (repo / path).read_bytes()), patch.object(S, 'read', side_effect=changing):
            with self.assertRaises(ValueError): S.verify(directory, ROOT, COMMIT)
        self.assertGreaterEqual(observed, 2)

    def test_synthetic_report_is_exclusive_outside_source_and_logs(self):
        directory = self.synthetic_evidence(); target = self.base / 'synthetic-report.json'
        args = ['--evidence', str(directory), '--repo', str(ROOT), '--source-commit', COMMIT, '--report', str(target)]
        with patch.object(S, 'git_source', side_effect=lambda repo, commit, path: (repo / path).read_bytes()):
            with patch('builtins.print'): self.assertEqual(S.main(args), 0)
            with self.assertRaises(ValueError): S.main(args)
            for path in (directory / 'output.json', ROOT / 'output.json'):
                with self.assertRaises(ValueError): S.main(args[:-1] + [str(path)])

    def test_synthetic_parser_rejects_unframed_text_and_unknown_test_syntax(self):
        originals = self.synthetic_logs()
        for name, (path, cls, count, pin) in S.PYTHON.items():
            with self.assertRaises(ValueError): S.verify_python(originals[name] + b'WARNING hidden failure\n', (ROOT / path).read_bytes(), cls, count, pin, Path(path).stem)
        for name, (path, count, pin) in S.NODE.items():
            with self.assertRaises(ValueError): S.verify_node(originals[name] + b'UNCLASSIFIED output\n', (ROOT / path).read_bytes(), count, pin)
        with self.assertRaises(ValueError): S.node_names(b'test(computedName, () => {});')


if __name__ == '__main__':
    unittest.main(verbosity=2)
