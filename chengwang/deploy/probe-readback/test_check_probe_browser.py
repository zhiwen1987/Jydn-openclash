"""Pure synthetic verifier contracts; no browser, Go, namespace or API calls."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
import struct
import tempfile
import unittest
import zlib
from unittest import mock

import check_probe_browser as gate
import check_probe_readback as native
import test_check_probe_readback as fixtures


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode() + b'\n'


def png(width, height):
    def chunk(tag, body):
        return struct.pack('>I', len(body)) + tag + body + struct.pack('>I', zlib.crc32(tag + body) & 0xffffffff)
    pixels = (b'\0' + b'\xff\xff\xff' * width) * height
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))


def captures_fixture(native_raw, engine='chrome-cdp'):
    collect = json.loads(native_raw[native.PREFIX + 'collect-final.json'])
    results = {value['runId']: value for item in collect['spoolSegments']
               for value in [json.loads(base64.b64decode(item['raw']))['result']]}
    first = min(native.nanoseconds(r['attemptedAt']) for r in results.values())
    base = (first // 10**9 - 48) * 10**9
    at = lambda seconds: fixtures.instant(base + int(seconds * 10**9))
    prefix, _ = gate.capture_names(engine)
    raw, sources, network, objects = {}, {}, [], {}
    def event(stage, kind, body, seconds):
        item = dict(stage=stage, ordinal=len(network) + 1, receivedUnixNano=str(base + int(seconds * 1000) * 1_000_000),
                    method='GET', path='/api/v1/probes/' + kind, status=200, authorizationPresent=kind == 'details',
                    resourceType='fetch', bodyBytes=len(body), bodySHA256=gate.sha(body))
        network.append(item); return item['ordinal']
    for stage in ('fresh', 'withdrawn', 'expired'):
        phase = 'expired' if stage == 'expired' else 'restarted'
        summary = json.loads(native_raw[native.PREFIX + 'api-' + phase + '-status.json'])
        details = json.loads(native_raw[native.PREFIX + 'api-' + phase + '-details.json'])
        if stage == 'withdrawn':
            summary['cachedAt'] = at(146)
            summary['expiresAt'] = at(168.002)
            details['status'] = copy.deepcopy(summary)
        for kind, value in (('status', summary), ('details', details)):
            raw[prefix + stage + '-' + kind + '.json'] = encoded(value)
        objects[stage] = (summary, details)
    # Completion order is gapless across the four output log partitions.
    for stage in gate.STAGES:
        if stage == 'cleared':
            event(stage, 'status', raw[prefix + 'fresh-status.json'], 145.010)
            continue
        summary, details = objects[stage]
        received = {'fresh': 143.010, 'withdrawn': 146.010, 'expired': 250.010}[stage]
        ordinals = {kind: event(stage, kind, raw[prefix + stage + '-' + kind + '.json'], received + index * .010)
                    for index, kind in enumerate(('status', 'details'))}
        sources[stage] = dict(sourcePhase='expired' if stage == 'expired' else 'fresh',
            **{kind: dict(name=prefix + stage + '-' + kind + '.json', bytes=len(raw[prefix + stage + '-' + kind + '.json']),
                          sha256=gate.sha(raw[prefix + stage + '-' + kind + '.json'])) for kind in ('status', 'details')},
            statusOrdinal=ordinals['status'], detailsOrdinal=ordinals['details'], cachedAt=summary['cachedAt'],
            deadline=summary['expiresAt'], deadlineKind='EVIDENCE_TTL' if stage != 'expired' else 'CACHE_OR_EVIDENCE_DEADLINE')
    latest = {ident: max((r for r in results.values() if r['probeId'] == ident), key=lambda r: native.nanoseconds(r['completedAt'])) for ident in gate.IDS}
    captures = {}
    for stage in gate.STAGES:
        source_stage = 'fresh' if stage == 'cleared' else stage
        summary, details = objects[source_stage]
        widths = [1440, 375] if stage == 'fresh' else [375] if stage == 'expired' else [1440]
        times = {'fresh': 144, 'cleared': 145, 'withdrawn': 169, 'expired': 251}
        observations, screenshots = [], []
        for index, width in enumerate(widths):
            observed = times[stage] + index * .100
            targets = []
            if stage != 'cleared':
                for ident in gate.IDS:
                    sample = latest[ident]; current = stage == 'fresh'
                    targets.append(dict(probeId=ident, pathId='direct', stateLabel=gate.LABELS[sample['conclusion'] if current else 'unknown'],
                                        runId=sample['runId'] if current else '', httpStatus=sample['httpStatus'] if current else 0,
                                        layers={name: gate.LABELS[sample['layers'][name]['state']] for name in gate.LAYERS} if current else {}))
            dom = dict(url=gate.ORIGIN + '/', title='澄网 · 网络代理与路由平台', heading='代理节点观测',
                       viewport=dict(width=width, height=812 if width == 375 else 1000), scrollWidth=width, clientWidth=width,
                       inputType='password', tokenEmpty=stage == 'cleared', storageEmpty=True, cookiesEmpty=True,
                       detailMounted=stage != 'cleared', catalogText='' if stage == 'cleared' else details['catalogDigest'],
                       targets=targets, overlayCount=0)
            observations.append(dict(observedAt=at(observed), dom=dom))
            if stage != 'cleared':
                suffix = 'mobile' if width == 375 else 'desktop'; name = prefix + stage + '-' + suffix + '.png'
                raw[name] = png(width, dom['viewport']['height'])
                screenshots.append(dict(name=name, bytes=len(raw[name]), sha256=gate.sha(raw[name]), capturedAt=at(observed + .001)))
        captures[stage] = dict(schema='chengwang.probe-browser-capture/v1', outcome='API_CAPTURE_UNBOUND', runtimeProven=False,
                              browserE2EProven=False, engine=engine, stage=stage, source=copy.deepcopy(sources[source_stage]),
                              observations=observations, screenshots=screenshots)
        raw[prefix + stage + '-dom.json'] = encoded(captures[stage])
        raw[prefix + stage + '-network.jsonl'] = b''.join(encoded(item) for item in network if item['stage'] == stage)
    return raw, results


def runtime_fixture(certificates, engine='chrome-cdp'):
    native_raw = fixtures.synthetic_fixture(certificates)
    raw, results = captures_fixture(native_raw, engine)
    prefix, capture_set = gate.capture_names(engine)
    model = gate.validate_captures(raw, results, engine)
    root, bundle = fixtures.ROOT, fixtures.BUNDLE
    commit, fixture = fixtures.HEAD, fixtures.FIXTURE_ID
    isolated = json.loads(native_raw[native.PREFIX + 'isolation.json'])
    source_root = pathlib.Path(__file__).resolve().parents[3]
    paths = ('chengwang/deploy/probe-readback/run_probe_browser.py', 'chengwang/deploy/probe-readback/probe_chrome_launcher.py',
             'chengwang/tools/probe-browser/package.json', 'chengwang/tools/probe-browser/package-lock.json',
             'chengwang/tools/probe-browser/probe-browser-contract.mjs', 'chengwang/tools/probe-browser/run-browser.mjs',
             'chengwang/tools/probe-browser/browser-driver.mjs', 'chengwang/tools/probe-browser/browser-cli.mjs',
             'chengwang/web/scripts/trust-browser-tls.mjs', 'chengwang/tools/image-binding/scripts/browser-process-guard.py')
    sources = {entry['path']: entry for entry in isolated['sourceFilesBefore']}
    copied = []
    for path in paths:
        body = (source_root / path).read_bytes()
        entry = dict(path=path, bytes=len(body), sha256=gate.sha(body)); sources[path] = entry; copied.append(entry)
    sources = sorted(sources.values(), key=lambda item: item['path'])
    isolated['sourceFilesBefore'] = copy.deepcopy(sources); isolated['sourceFilesAfter'] = copy.deepcopy(sources)
    for host in ('hostBefore', 'hostAfter'):
        isolated[host]['sourceSHA256'] = gate.sha(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())
    native_raw[native.PREFIX + 'isolation.json'] = encoded(isolated)
    web = {'index.html': b'<script type="module" src="/assets/main.js"></script><link href="/assets/main.css">',
           'trust.html': b'<script type="module" src="/assets/trust.js"></script>',
           '.vite/manifest.json': b'{"main":{"file":"assets/main.js"},"trust":{"file":"assets/trust.js"}}',
           'assets/main.js': b'export const isolatedSynthetic=true;', 'assets/main.css': b'body{margin:0}',
           'assets/trust.js': b'export const deliberatelyNotBrowsed=true;'}
    for name, body in web.items(): copied.append(dict(path='built-web/' + name, bytes=len(body), sha256=gate.sha(body)))
    for path, body in [('toolchain/node', b'synthetic-node'), ('npm/playwright-core/package.json', b'{}'),
                       ('fonts/NotoSansCJKsc-Regular.otf', b'font'), ('fonts/NotoSansCJKsc-Bold.otf', b'bold'), ('fonts/LICENSE', b'license')]:
        copied.append(dict(path=path, bytes=len(body), sha256=gate.sha(body)))
    build = dict(schema='chengwang.probe-browser-build/v1', sourceCommit=commit, fixtureId=fixture, engine=engine,
                 copiedInputs=copied, sourceFilesBefore=sources, sourceFilesAfter=copy.deepcopy(sources),
                 hostBefore=isolated['hostBefore'], hostAfter=isolated['hostAfter'], buildScope='TRUSTED_CI_INPUTS_NOT_INDEPENDENT_REBUILD',
                 backendSupervisorMode='WRAPPER_IMPORTS_NATIVE_HELPERS', production=False)
    flow_captures = []
    for stage in gate.STAGES:
        name = prefix + stage + '-dom.json'; value = copy.deepcopy(model['captures'][stage])
        value['artifact'] = dict(name=name, bytes=len(raw[name]), sha256=gate.sha(raw[name])); flow_captures.append(value)
    raw['browser-captures.json'] = encoded(dict(schema='chengwang.probe-browser-flow/v1', outcome='API_CAPTURE_UNBOUND',
        runtimeProven=False, browserE2EProven=False, authorization='BLOCKED', production=False, deviceActionsExecuted=False,
        engine=engine, captures=flow_captures, network=model['network'], files=sorted(capture_set), deadlineKind=model['deadlineKind']))
    argv = ['/opt/google/chrome/chrome', '--no-sandbox', '--headless=new', '--user-data-dir=' + root + '/browser/chrome-profile']
    controller_args = [bundle + '/browser-node', bundle + '/source/chengwang/tools/probe-browser/browser-cli.mjs',
                       '--root', root, '--engine', engine, '--chrome', argv[0], '--launcher', bundle + '/chrome-launcher',
                       '--source-root', bundle + '/source', '--source-commit', commit]
    records = []
    for role, pid, args, exe in [('controller', 100, controller_args, gate.sha(b'synthetic-node')), ('chrome', 101, argv, gate.sha(b'synthetic-chrome'))]:
        records.append(dict(role=role, pid=pid, startTime=str(pid * 100), exeSHA256=exe,
            argvSHA256=gate.sha(b''.join(arg.encode() + b'\0' for arg in args)), uid=[10001] * 4, gid=[10001] * 4, groups=[],
            capabilities={name: '0000000000000000' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}, noNewPrivs=1,
            namespaces={**isolated['lab']['namespaces'], 'mnt': 'mnt:[900]'},
            limits=dict(cpuSeconds=[180, 180], fileBytes=[32 << 20] * 2, openFiles=[1024] * 2, processes=[1024] * 2, coreBytes=[0, 0])))
    chrome_record = dict(pid=101, startTicks=10100, uid=10001, profile=root + '/browser/chrome-profile', argvSHA256=records[1]['argvSHA256'])
    exit_record = dict(schema='chengwang.probe-chrome-exit/v1', engine=engine, fixtureId=fixture, pid=101, startTicks=10100, exitCode=0, joined=True, forced=False)
    ca_der = native.openssl(['x509', '-outform', 'DER'], base64.b64decode(certificates['apiCARaw']))
    leaf_der = native.openssl(['x509', '-outform', 'DER'], base64.b64decode(certificates['apiLeafRaw']))
    trust = dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,', caSHA256=gate.sha(ca_der), leafSHA256=gate.sha(leaf_der), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True)
    first_received = int(model['network'][0]['receivedUnixNano']) - 1_000_000
    network = [dict(ordinal=i + 1, url=gate.ORIGIN + path, method='GET', status=200, authorizationPresent=False,
                    resourceType='document' if path == '/' else 'script' if path.endswith('.js') else 'stylesheet',
                    bodyBytes=len(web['index.html' if path == '/' else path[1:]]),
                    bodySHA256=gate.sha(web['index.html' if path == '/' else path[1:]]), receivedUnixNano=str(first_received))
               for i, path in enumerate(('/', '/assets/main.js', '/assets/main.css'))]
    for event in model['network']:
        network.append({**{key: value for key, value in event.items() if key not in ('stage', 'path', 'ordinal')},
                        'ordinal': len(network) + 1, 'url': gate.ORIGIN + event['path']})
    driver = dict(schema='chengwang.probe-browser-driver/v1', engine=engine, fixtureId=fixture, runtime=True,
                  browserPluginUsed=False, mockedResponses=False, injectedFetch=False, tlsBypass=False,
                  chromeSandbox='DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED', realBrowser='Chrome/130.0.0.0',
                  responseBodyScope='CDP_DECODED_RESPONSE_BODY_NOT_RAW_TLS_WIRE', receivedClockResolution='UNIX_MILLISECONDS',
                  normalTrust=trust, chrome=chrome_record, tls=dict(securityState='secure', protocol='TLS 1.3', cipher='AES_256_GCM',
                  leafSHA256=trust['leafSHA256'], caSHA256=trust['caSHA256'], serverChainLength=1, leafSignatureVerified=True, ipSANVerified=True),
                  certificateChain=[base64.b64encode(leaf_der).decode()], screenshotCount=4, network=network,
                  close=dict(normalCloseCommandCompleted=True, chromeExit=exit_record, guardExitCode=0,
                             noLiveOwnedProcessesBeforeGuard=True, noLiveOwnedProcessesAfterGuard=True, guardSignalIntervention=False),
                  **{name: 0 for name in ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors')})
    raw['browser-driver.json'] = encoded(driver)
    files = [dict(path=name, bytes=len(body), sha256=gate.sha(body)) for name, body in sorted(raw.items())]
    raw['browser-processes.json'] = encoded(dict(schema='chengwang.probe-browser-processes/v1', sourceCommit=commit,
        records=records, chromeArgv=argv, chromeExecutable=dict(path=argv[0], bytes=len(b'synthetic-chrome'), sha256=records[1]['exeSHA256'],
        sourceScope='TRUSTED_CI_SYSTEM_TOOL_NOT_INDEPENDENT_SUPPLY_CHAIN'), controllerExitCode=0, chromeExit=exit_record,
        webReadOnlyMounts=[dict(role='api-second', flags=['ro', 'nosuid', 'nodev'])], files=files, production=False))
    raw['browser-build.json'] = encoded(build)
    return native_raw, raw, web


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = tempfile.TemporaryDirectory(prefix='probe-browser-unit-ca-'); cls.addClassCleanup(cls.authority.cleanup)
        cls.certificates = fixtures.make_certificates(pathlib.Path(cls.authority.name))
        cls.native_raw, cls.browser_raw, cls.web = runtime_fixture(cls.certificates)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='probe-browser-unit-runtime-'); self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name); self.backend = self.root / 'backend'; self.browser = self.root / 'browser'
        self.backend.mkdir(); self.browser.mkdir()
        for name, body in self.native_raw.items(): (self.backend / name).write_bytes(body)
        for name, body in self.browser_raw.items(): (self.browser / name).write_bytes(body)
        for name, body in self.web.items():
            path = self.browser / 'web' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        self.assertEqual(gate.verify(self.backend, self.browser, fixtures.HEAD, 'chrome-cdp')['outcome'], 'PASS')

    def mutate(self, name, change):
        path = self.browser / name; value = json.loads(path.read_bytes()); change(value); path.write_bytes(encoded(value))
        if name not in ('browser-processes.json', 'browser-build.json'):
            manifest_path = self.browser / 'browser-processes.json'; manifest = json.loads(manifest_path.read_bytes())
            entry = next(item for item in manifest['files'] if item['path'] == name)
            body = path.read_bytes(); entry.update(bytes=len(body), sha256=gate.sha(body)); manifest_path.write_bytes(encoded(manifest))

    def reject(self):
        with self.assertRaises((native.Rejected, ValueError, KeyError)):
            gate.verify(self.backend, self.browser, fixtures.HEAD, 'chrome-cdp')

    def test_full_twenty_two_backend_and_browser_gate(self):
        result = gate.verify(self.backend, self.browser, fixtures.HEAD, 'chrome-cdp')
        self.assertTrue(result['browserE2EProven']); self.assertEqual(result['apiSamples'], 6)
        self.assertEqual(result['latestVisibleTargets'], 3); self.assertFalse(result['actualInternetReachabilityProven'])
        native_raw, browser_raw, web = runtime_fixture(self.certificates, 'playwright')
        for name, body in native_raw.items(): (self.backend / name).write_bytes(body)
        for path in self.browser.iterdir():
            if path.is_file(): path.unlink()
        for name, body in browser_raw.items(): (self.browser / name).write_bytes(body)
        self.assertEqual(gate.verify(self.backend, self.browser, fixtures.HEAD, 'playwright')['engine'], 'playwright')

    def test_dual_entry_dist_does_not_require_browsing_trust(self):
        self.assertTrue((self.browser / 'web/trust.html').exists()); self.assertTrue((self.browser / 'web/.vite/manifest.json').exists())

    def test_backend_original_bytes_are_reverified(self):
        path = self.backend / (native.PREFIX + 'collect-final.json'); path.write_bytes(path.read_bytes() + b'bad'); self.reject()

    def test_unknown_browser_input_rejected(self):
        (self.browser / 'unreviewed.json').write_bytes(b'{}'); self.reject()

    def test_built_asset_original_bytes_must_match(self):
        (self.browser / 'web/assets/main.js').write_bytes(b'changed'); self.reject()

    def test_foreign_source_commit_rejected(self):
        self.mutate('browser-build.json', lambda value: value.update(sourceCommit='b' * 40)); self.reject()

    def test_insecure_chrome_args_cannot_hide_behind_normal_tls_true(self):
        self.mutate('browser-processes.json', lambda value: value['chromeArgv'].append('--ignore-certificate-errors')); self.reject()

    def test_capability_and_namespace_escalation_rejected(self):
        self.mutate('browser-processes.json', lambda value: value['records'][0]['capabilities'].update(CapEff='0000000000000001')); self.reject()
        (self.browser / 'browser-processes.json').write_bytes(self.browser_raw['browser-processes.json'])
        self.mutate('browser-processes.json', lambda value: value['records'][0]['namespaces'].update(net='net:[999999]')); self.reject()

    def test_wait_137_or_forced_exit_not_normal(self):
        self.mutate('browser-processes.json', lambda value: value['chromeExit'].update(exitCode=137, forced=True)); self.reject()

    def test_source_copy_hash_self_consistency_not_git_binding(self):
        self.mutate('browser-build.json', lambda value: value['copiedInputs'][0].update(sha256='0' * 64)); self.reject()

    def test_actual_chain_cannot_be_replaced_by_boolean(self):
        self.mutate('browser-driver.json', lambda value: value.update(certificateChain=[])); self.reject()

    def test_chrome_identity_pid_and_tick_must_match(self):
        self.mutate('browser-processes.json', lambda value: value['records'][1].update(startTime='999')); self.reject()


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = fixtures.synthetic_fixture({'targetCARaw': base64.b64encode(b'synthetic-capture-only').decode()})
        cls.template, cls.results = captures_fixture(cls.native)

    def setUp(self):
        self.raw = copy.deepcopy(self.template)
        gate.validate_captures(self.raw, self.results, 'chrome-cdp')

    def mutate(self, stage, change):
        name = 'probe-browser-cdp-' + stage + '-dom.json'
        value = json.loads(self.raw[name]); change(value); self.raw[name] = encoded(value)

    def reject(self):
        with self.assertRaises((native.Rejected, ValueError, KeyError)):
            gate.validate_captures(self.raw, self.results, 'chrome-cdp')

    def test_both_engine_closed_sets_and_real_png_pixels(self):
        for engine in gate.ENGINES:
            raw, results = captures_fixture(self.native, engine)
            self.assertEqual(len(raw), 18)
            self.assertEqual(gate.validate_captures(raw, results, engine)['deadlineKind'], 'EVIDENCE_TTL')

    def test_missing_public_api_file_rejected(self):
        del self.raw['probe-browser-cdp-fresh-details.json']; self.reject()

    def test_raw_body_digest_substitution_rejected(self):
        self.raw['probe-browser-cdp-fresh-status.json'] += b' '; self.reject()

    def test_original_six_samples_cannot_be_replaced(self):
        name = 'probe-browser-cdp-fresh-details.json'; value = json.loads(self.raw[name])
        value['samples'][0]['runId'] = 'unrelated-run'; self.raw[name] = encoded(value); self.reject()

    def test_three_visible_targets_are_not_six_or_wrong_latest(self):
        self.mutate('fresh', lambda v: v['observations'][0]['dom']['targets'][0].update(runId='old-or-other-run')); self.reject()

    def test_layer_label_relabelling_rejected(self):
        self.mutate('fresh', lambda v: v['observations'][0]['dom']['targets'][0]['layers'].update(business='可用')); self.reject()

    def test_unknown_secret_fields_rejected(self):
        self.mutate('fresh', lambda v: v['observations'][0]['dom'].update(token='PRIVATE_SENTINEL')); self.reject()

    def test_clear_must_remove_input_and_details(self):
        self.mutate('cleared', lambda v: v['observations'][0]['dom'].update(tokenEmpty=False)); self.reject()

    def test_clear_anonymous_response_must_be_after_dom(self):
        name = 'probe-browser-cdp-cleared-network.jsonl'; value = json.loads(self.raw[name])
        value['receivedUnixNano'] = str(native.nanoseconds(json.loads(self.raw['probe-browser-cdp-cleared-dom.json'])['observations'][0]['observedAt']) - 1_000_000)
        self.raw[name] = encoded(value); self.reject()

    def test_completion_timestamp_cannot_go_backwards(self):
        name = 'probe-browser-cdp-fresh-network.jsonl'; rows = [json.loads(line) for line in self.raw[name].splitlines()]
        rows[0]['receivedUnixNano'] = str(int(rows[1]['receivedUnixNano']) + 1_000_000)
        self.raw[name] = b''.join(encoded(row) for row in rows); self.reject()

    def test_millisecond_precision_is_not_arbitrary_nanosecond_claim(self):
        name = 'probe-browser-cdp-fresh-network.jsonl'; rows = [json.loads(line) for line in self.raw[name].splitlines()]
        rows[0]['receivedUnixNano'] = str(int(rows[0]['receivedUnixNano']) + 1)
        self.raw[name] = b''.join(encoded(row) for row in rows); self.reject()

    def test_natural_withdrawal_cannot_happen_before_deadline(self):
        self.mutate('withdrawn', lambda v: v['observations'][0].update(observedAt=v['source']['cachedAt'])); self.reject()

    def test_cache_expiry_cannot_be_relabelled_evidence_ttl(self):
        self.mutate('fresh', lambda v: v['source'].update(deadlineKind='CACHE_OR_EVIDENCE_DEADLINE')); self.reject()

    def test_expired_api_must_be_past_original_maximum_ttl(self):
        name = 'probe-browser-cdp-expired-status.json'; value = json.loads(self.raw[name]); value['cachedAt'] = json.loads(self.raw['probe-browser-cdp-fresh-status.json'])['cachedAt']
        self.raw[name] = encoded(value); self.reject()

    def test_green_samples_after_withdrawal_rejected(self):
        self.mutate('withdrawn', lambda v: v['observations'][0]['dom']['targets'][0].update(runId='still-visible')); self.reject()

    def test_authorization_on_anonymous_status_rejected(self):
        name = 'probe-browser-cdp-cleared-network.jsonl'; value = json.loads(self.raw[name]); value['authorizationPresent'] = True
        self.raw[name] = encoded(value); self.reject()

    def test_source_response_ordinal_wrong_body_rejected(self):
        self.mutate('fresh', lambda v: v['source'].update(detailsOrdinal=v['source']['statusOrdinal'])); self.reject()

    def test_png_crc_and_trailing_bytes_rejected(self):
        for raw in (self.raw['probe-browser-cdp-fresh-desktop.png'] + b'bad', self.raw['probe-browser-cdp-fresh-desktop.png'][:-8]):
            with self.assertRaises(native.Rejected): gate.png_dimensions(raw)

    def test_png_inflate_budget_and_truncated_stream_rejected(self):
        raw = bytearray(self.raw['probe-browser-cdp-fresh-desktop.png']); raw[30] ^= 1
        with self.assertRaises(native.Rejected): gate.png_dimensions(bytes(raw))

    def test_png_width_must_match_actual_viewport(self):
        self.mutate('fresh', lambda v: v['observations'][0]['dom']['viewport'].update(width=375)); self.reject()

    def test_success_bools_cannot_replace_original_captures(self):
        self.mutate('fresh', lambda v: v.update(runtimeProven=True, browserE2EProven=True)); self.reject()

    def test_catalogue_hash_must_match_real_backend(self):
        self.mutate('fresh', lambda v: v['observations'][0]['dom'].update(catalogText='sha256:' + '0' * 64)); self.reject()

    def test_public_output_is_exclusive_and_failure_suppresses_input(self):
        with tempfile.TemporaryDirectory() as folder:
            target = pathlib.Path(folder) / 'report.json'; native.write_exclusive(target, b'original')
            with self.assertRaises(FileExistsError): native.write_exclusive(target, b'replacement')
            self.assertEqual(target.read_bytes(), b'original')
            evidence = pathlib.Path(folder) / 'browser'; (evidence / 'web').mkdir(parents=True)
            with mock.patch('sys.stderr'), mock.patch.object(gate, 'verify') as verify:
                self.assertEqual(gate.main(['verify', '--backend-dir', str(pathlib.Path(folder) / 'backend'),
                    '--browser-dir', str(evidence), '--source-commit', 'a' * 40, '--engine', 'chrome-cdp',
                    '--report', str(evidence / 'web/report.json')]), 1)
                verify.assert_not_called()
        with mock.patch('sys.stderr') as error:
            self.assertEqual(gate.main(['--PRIVATE_SENTINEL']), 1)
            self.assertNotIn('PRIVATE_SENTINEL', str(error.write.call_args_list))


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__)))
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print('PROBE_BROWSER_VERIFIER_TESTS=PASS tests=' + str(result.testsRun) + ' skipped=0 synthetic_only=true')
