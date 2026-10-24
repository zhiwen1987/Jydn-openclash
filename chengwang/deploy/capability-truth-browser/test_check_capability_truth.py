"""CPU-only adversarial unit fixtures; never evidence of a real browser run."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zlib

SPEC = importlib.util.spec_from_file_location('capability_independent_checker', Path(__file__).with_name('check_capability_truth.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
SYN_SPEC = importlib.util.spec_from_file_location('capability_synthetic_checker', Path(__file__).with_name('check_capability_synthetic.py'))
S = importlib.util.module_from_spec(SYN_SPEC)
SYN_SPEC.loader.exec_module(S)
CONTRACT = C.decode(Path(__file__).with_name('contract.json').read_bytes())
COMMIT = '1' * 40


def body(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def snapshot():
    return dict(product='Synthetic CPU only', version='', mode='candidate', status='not real evidence', dataSource='demo', publishLocked=True,
        businesses=None, pools=None, interfaces=None, events=None,
        draft=dict(name='draft', baseVersion='', businesses=None, pools=None,
                   dns=dict(domesticResolvers=None, overseasResolvers=None, hijackPort53=False, leakProtection=False)))


def report(profile='default'):
    items = []
    for f in CONTRACT['frozenRegistrySourceProjection']:
        state = 'implemented_local' if f['stateSource'] == 'StateImplementedLocal' else 'design_only' if f['stateSource'] == 'StateDesignOnly' else 'blocked'
        state = CONTRACT['profilePolicies'][profile]['selectedStates'].get(f['id'], state)
        items.append(dict(id=f['id'], domain=f['domain'], name=f['name'], readOnly=f['readOnly'], state=state,
                          evidence=f.get('evidence', []), limitations=f.get('limitations', ['Synthetic CPU limitation'])))
    return dict(generatedAt='2026-10-24T03:04:05Z', productionControlEnabled=False, overallState='foundation', capabilities=items)


def built():
    contents = {'index.html': b'<html>synthetic</html>', 'trust.html': b'<html>unused</html>', 'assets/main.js': b'/* synthetic */',
                'assets/main.css': b'body{}', 'assets/later.js': b'/* optional */'}
    manifest = {'index.html': dict(file='assets/main.js', src='index.html', isEntry=True, css=['assets/main.css'], dynamicImports=['later'], names=['main']),
                'later': dict(file='assets/later.js', isDynamicEntry=True)}
    contents['.vite/manifest.json'] = body(manifest)
    value = dict(schema=CONTRACT['schemaNames']['build'], sourceCommit=COMMIT, goVersion='go1.23.12', nodeVersion='v22.23.3',
        moduleMode='vendor', goDependencyDownloads=False, server=dict(name='server', bytes=1, sha256='a' * 64),
        distFiles=[dict(path=p, bytes=len(b), sha256=C.sha(b)) for p, b in sorted(contents.items())],
        manifestBase64=base64.b64encode(contents['.vite/manifest.json']).decode(), production=False, authorization='BLOCKED')
    return value, contents


def capture_rows():
    build, contents = built()
    files, required, allowed = C.validate_build(CONTRACT, build, COMMIT)
    rows = []
    for i, (kind, path, raw) in enumerate([
        ('DOCUMENT', '/', contents['index.html']), ('ASSET', '/assets/main.js', contents['assets/main.js']),
        ('ASSET', '/assets/main.css', contents['assets/main.css']), ('SNAPSHOT', '/api/v1/snapshot', body(snapshot())),
        ('CAPABILITIES', '/api/v1/capabilities', body(report())), ('CAPABILITIES', '/api/v1/capabilities', body(report()))], 1):
        rows.append(dict(schema=CONTRACT['schemaNames']['capture'], ordinal=i, requestOrdinal=i, requestId='r' + str(i), method='GET',
            path=path, kind=kind, status=200, authorizationPresent=False, requestPublic=None,
            responseBase64=base64.b64encode(raw).decode(), responseSHA256=C.sha(raw), responseBytes=len(raw),
            startedWallTimeUs=1792800000000000 + i, startTimeUs=i, headerTimeUs=i + 1, endTimeUs=i + 2,
            terminal=dict(event='FINISH', encodedDataLength=len(raw))))
    return rows, files, required, allowed


def event_driver(rows):
    events = []
    for r in rows:
        def emit(t, **fields):
            events.append(dict(seq=len(events) + 1, type=t, **fields))
        emit('REQUEST', requestId=r['requestId'], requestOrdinal=r['requestOrdinal'], kind=r['kind'], method='GET', path=r['path'],
             sameOrigin=True, queryPresent=False, fragmentPresent=False, userInfoPresent=False, authorizationPresent=False, cookiePresent=False, bodyPresent=False)
        mime = 'HTML' if r['kind'] == 'DOCUMENT' else 'JS' if r['path'].endswith('.js') else 'CSS' if r['path'].endswith('.css') else 'JSON'
        emit('HEADERS', requestId=r['requestId'], status=200, mimeClass=mime, setCookiePresent=False, redirected=False, diskCache=False, serviceWorker=False)
        emit('FINISH', requestId=r['requestId'], encodedDataLength=r['terminal']['encodedDataLength'])
        emit('CAPTURE', requestId=r['requestId'], captureOrdinal=r['ordinal'], responseBytes=r['responseBytes'], responseSHA256=r['responseSHA256'])
    events.append(dict(seq=len(events) + 1, type='META', requests=len(rows), headers=len(rows), finished=len(rows), failed=0,
        captured=len(rows), pending=0, tasks=0, ignoredFavicon=0, mutations=0, overflow=False))
    return dict(events=events, counters={k: 0 for k in CONTRACT['eightZero']})


def observed_capabilities(api):
    groups = {}
    for item in api['capabilities']:
        groups.setdefault(item['domain'], []).append(dict(id=item['id'], name=item['name'], stateClass='readiness-state ' + item['state'],
            stateLabel=CONTRACT['statePresentation'][item['state']][0], readOnlyLabel='只读' if item['readOnly'] else '包含写入能力',
            evidenceLabel='可核验入口与实现依据', evidence=list(item['evidence']), emptyEvidenceLabel='' if item['evidence'] else '暂无可核验入口',
            limitationsLabel='当前限制', limitations=list(item['limitations'])))
    return dict(heading='系统闭环', boundary=dict(title='生产写入保持关闭', text='当前页面只展示能力证据，不会发布配置、切换节点或重启网络服务。', writeEnabled=False),
        summary=[dict(stateClass='', label=CONTRACT['statePresentation'][s][0], count=str(sum(i['state'] == s for i in api['capabilities'])), description=CONTRACT['statePresentation'][s][1]) for s in C.STATES],
        meta=dict(overallState='foundation', generatedAtLabel='清单生成时间', generatedAtText='2026/10/24 3:04:05', capabilityCount='18', productionLabel='未启用'),
        groups=[dict(domain=k, count=str(len(v)) + ' 项能力，每项分别展示证据与限制', rows=v) for k, v in groups.items()])


def metadata(profile):
    configured = profile == 'backend_configured'
    common = dict(sourceCommit=COMMIT, fixtureId='f' * 32, engine='chrome-cdp', profile=profile, scenario='capability_truth', production=False)
    server = dict(pid=2, startTime='100', exeSHA256='a' * 64, argvSHA256='b' * 64)
    runtime = dict(common, schema=CONTRACT['schemaNames']['runtime'], scope=C.scope(profile),
        serverIdentity=dict(pid=2, startTicks=100, exeSHA256='a' * 64, argvSHA256='b' * 64),
        environment=[dict(name=k, value=v) for k, v in sorted(CONTRACT['profilePolicies'][profile]['env'].items())],
        identities=copy.deepcopy(CONTRACT['leafValues']['identitiesConfigured' if configured else 'identitiesUnconfigured']),
        mihomo=dict(configured=configured, endpointClass=CONTRACT['leafValues']['endpointClass'] if configured else None),
        observer=copy.deepcopy(CONTRACT['leafValues']['observerConfigured' if configured else 'observerUnconfigured']),
        probe=dict(configured=False), subscription=dict(configured=configured, writesEnabled=False, policyConfigured=False),
        writeGates=dict(publish=False, operation=False, subscription=False), policyCatalog=dict(configured=False),
        upstreamListener=copy.deepcopy(CONTRACT['leafValues']['upstreamListener']), snapshotsProvider='seed_demo', trustBoundary=CONTRACT['leafValues']['trustBoundary'])
    storage = dict(common, schema=CONTRACT['schemaNames']['storage'], scope=C.scope(profile), trustBoundary=CONTRACT['leafValues']['trustBoundary'],
        subscriptionStore=dict(constructed=configured, scope=C.scope(profile, True) if configured else None,
            sourceCount=0, candidateCount=0, requestCount=0, auditCount=0, commandCount=0, approvalCount=0, privateNodesCount=0),
        observationStore=dict(constructed=configured), operationStore=dict(constructed=True, commandCount=0), evidenceStore=dict(constructed=True))
    return runtime, storage, dict(server=server)


def source_fixture():
    root = Path(__file__).resolve().parents[3]
    paths = [C.OWN_PATH, C.CONTRACT_PATH, 'chengwang/internal/capability/registry.go',
        'chengwang/deploy/browser-scene-supervisor/supervisor.py', 'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
        'chengwang/deploy/capability-truth-browser/capability_truth_scene.py', 'chengwang/deploy/capability-truth-browser/run_capability_truth.py',
        *['chengwang/tools/capability-truth-browser/' + n for n in ('ui-cli.mjs', 'ui-driver.mjs', 'ui-dom.mjs', 'ui-contract.mjs')],
        *['chengwang/tools/subscription-ui-browser/' + n for n in ('ui-driver.mjs', 'ui-contract.mjs', 'navigation-diagnostics.mjs', 'navigation-diagnostics-contract.json')],
        'chengwang/web/scripts/trust-browser-tls.mjs', 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py']
    blobs = {p: (root / p).read_bytes() for p in sorted(paths)}
    rows = [dict(path=p, bytes=len(b), sha256=C.sha(b)) for p, b in blobs.items()]
    b, _ = built()
    copied = [r.copy() for r in rows]
    launcher = next(r for r in rows if r['path'] == 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py')
    copied.append(dict(launcher, path=launcher['path'] + ':launcher'))
    copied.extend(dict(path='dist/' + r['path'], bytes=r['bytes'], sha256=r['sha256']) for r in b['distFiles'])
    copied.extend([dict(path='chrome/chrome', bytes=C.ELF_BYTES, sha256=C.ELF_SHA), dict(path='toolchain/node', bytes=1, sha256='c' * 64),
        dict(path='toolchain/server', bytes=b['server']['bytes'], sha256=b['server']['sha256']), dict(path='npm/playwright-core/package.json', bytes=1, sha256='d' * 64),
        dict(path='build/report.json', bytes=len(body(b)), sha256=C.sha(body(b)))])
    iso = dict(sourceFilesBefore=rows, sourceFilesAfter=copy.deepcopy(rows), hostBefore=dict(sourceSHA256=C.sha(C.canonical(rows))))
    iso['hostAfter'] = copy.deepcopy(iso['hostBefore'])
    def fake_git(repo, *args, input_bytes=None):
        if args[0] == 'ls-tree':
            return b'\0'.join(p.encode() for p in blobs) + b'\0'
        result = bytearray()
        for spec in input_bytes.decode().splitlines():
            p = spec.split(':', 1)[1]
            raw = blobs[p]
            oid = C.hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            result.extend(oid.encode() + b' blob ' + str(len(raw)).encode() + b'\n' + raw + b'\n')
        return bytes(result)
    return root, iso, dict(copiedInputs=copied), b, fake_git


def observed_pages():
    """Handwritten mounted-DOM CPU projections, never browser originals."""
    snap = snapshot()
    overview = dict(status=snap['status'], mode='candidate', badge='总览只读', boundaryText='总览仅展示数据边界；执行权限以服务端授权为准',
        demoAlertTitle='当前总览没有接入真实运行数据', demoAlertText='为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。',
        evidenceStrip=[dict(label=a, value=b, status=s, statusClass='status neutral') for a, b, s in [
            ('控制面模式', 'candidate', '总览只读'), ('真实设备证据', '设备读回', '可查看'), ('业务评估', '未接入', '未知'), ('DNS 评估', '未接入', '未知')]],
        boundaryRows=[dict(domain=a, evidence=b, handling=s) for a, b, s in [
            ('Mihomo 运行状态', '已提供独立只读接口', '前往“设备读回”查看实时证据'), ('业务分流状态', '尚未接入实际数据', '不显示模拟正常或模拟故障'),
            ('节点能力评估', '尚未接入实际探测器', '不生成虚构延迟、丢包和可用率'), ('DNS 健康状态', '尚未接入实际探测器', '不生成虚构解析耗时和泄漏结论'),
            ('自动化与拓扑', '当前仅有产品设计', '不冒充已执行动作或实时流量路径')]],
        businessTablePresent=False, poolTablePresent=False, eventsTablePresent=False, metricCardsPresent=False, simulatedTopologyPresent=False, dnsHealthObservedPresent=False)
    kr = [('Mihomo', '未核验', '只读适配', '未核验', '实际状态请显式进入设备读回'), ('sing-box', '未核验', '适配目标', '尚未实现', '现代多协议与独立 DNS（规划）'),
          ('Xray', '未核验', '适配目标', '尚未实现', 'VMess / VLESS / Reality（规划）'), ('Hysteria', '未核验', '适配目标', '尚未实现', 'Hysteria2 / QUIC（规划）')]
    matrix = [('Shadowsocks', '原生', '原生', '适配'), ('VMess', '适配', '适配', '原生'), ('VLESS', '原生', '原生', '原生'), ('Trojan', '原生', '原生', '原生'),
        ('Hysteria2', '适配', '原生', '不支持'), ('TUIC', '适配', '原生', '不支持'), ('AnyTLS', '适配', '原生', '不支持'), ('WireGuard', '适配', '原生', '适配'),
        ('TUN / TProxy', '原生', '原生', '适配'), ('Rule Provider', '原生', '适配', '适配'), ('DNS 分流', '原生', '原生', '适配'), ('链式代理', '原生', '原生', '原生')]
    kernels = dict(heading='内核与协议', description='适配规划；尚无主机安装库存或实例运行证据。下列操作未接执行器，保持禁用。',
        rows=[dict(zip(['name', 'versionEvidence', 'scope', 'instanceState', 'boundary', 'statusClass'], [*r, 'status neutral'])) for r in kr],
        matrixHeading='能力矩阵', matrixDescription='参考规划，目标版本尚未逐项实测；不表示已安装或当前可用。',
        matrixRows=[dict(feature=r[0], cells=[dict(text='待核验（参考：' + s + '）', className='support pending') for s in r[1:]]) for r in matrix],
        evidenceHeading='Mihomo 实例证据', evidenceStatus='未核验', evidenceFields=[dict(label=a, value=b) for a, b in [
            ('可执行文件', '未核验，发现适配器尚未接入'), ('完整性校验', '尚未执行'), ('配置绑定', '未接入'), ('监听接口', '未核验'), ('重启与回滚', '执行器尚未实现'), ('业务健康', '需独立业务探测，不由控制器配置推导')]])
    captures, *_ = capture_rows()
    rows = []
    for ordinal, step in enumerate(CONTRACT['stepFences'], 1):
        page = '运行总览' if step[0].startswith('overview') else '内核与协议' if step[0].startswith('kernels') else '系统闭环'
        bbox = dict(x=1, y=1, width=10, height=10)
        controls = []
        for key, label in CONTRACT['controlSlots']:
            present = key.startswith('nav_') or key == 'refresh_capabilities' and page == '系统闭环' or key.startswith('kernel_') and page == '内核与协议'
            controls.append(dict(key=key, label=label if present else None, labelSource=('ARIA_LABEL' if key.startswith('nav_') else 'VISIBLE_TEXT') if present else None,
                present=present, visible=present, enabled=present and not key.startswith('kernel_'), inViewport=present, unobstructed=present, rect=copy.deepcopy(bbox) if present else None))
        d = dict(schema=CONTRACT['schemaNames']['dom'], page=page, pageMounted=True, pageVisible=True, https=True,
            viewport=dict(width=step[1], height=step[2], scrollX=0, scrollY=0, clientWidth=step[1], scrollWidth=step[1]),
            environment=dict(language='zh-CN', timeZone='UTC'), browserStorage=dict(localEmpty=True, sessionEmpty=True, cookiesEmpty=True),
            topbar={k: dict(text=v, visible=True, rect=copy.deepcopy(bbox)) for k, v in dict(product=snap['product'], sourceLabel='演示草稿', mode='candidate', kernel='未核验').items()},
            controls=controls, apiFence=dict(snapshotCaptureOrdinal=4, capabilitiesCaptureOrdinals=list(range(5, 5 + step[4]))),
            overview=copy.deepcopy(overview) if page == '运行总览' else None, kernels=copy.deepcopy(kernels) if page == '内核与协议' else None,
            capabilities=observed_capabilities(report()) if page == '系统闭环' else None)
        rows.append(dict(schema=CONTRACT['schemaNames']['domRow'], ordinal=ordinal, step=step[0], captureCount=4 + step[4], mutationCount=0, dom=d))
    return rows, captures, snap, {5: report(), 6: report()}


def cpu_tap_framing():
    # Generic CPU text isolates transcript framing; the names pin is mocked in
    # these two tests only. Actual B79 names are verified against its real TAP
    # separately, and these strings never become browser evidence or a report.
    rows = [line for i in range(1, 80) for line in ('# Subtest: CPU case ' + str(i), 'ok ' + str(i) + ' - CPU case ' + str(i))]
    return ('\n'.join(rows + ['1..79', '# tests 79', '# suites 0', '# pass 79', '# fail 0', '# cancelled 0', '# skipped 0', '# todo 0']) + '\n').encode()


class CapabilityCheckerContracts(unittest.TestCase):
    def reject(self, fn, *args):
        with self.assertRaises((ValueError, TypeError, KeyError, UnicodeError, OverflowError)):
            fn(*args)

    def test_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            self.reject(C.decode, raw, True)

    def test_security_integer_rejects_bool_and_out_of_safe_range(self):
        for v in (True, 1.0, -1, 9007199254740992):
            self.reject(C.integer, v)

    def test_text_counts_utf16_and_rejects_control_bidi_and_surrogates(self):
        self.assertEqual(C.text('😀', 2), '😀')
        for value in ('😀😀', '\u202ehidden', 'line\nfeed', '\ud800'):
            self.reject(C.text, value, 3)

    def test_base64_rejects_noncanonical_and_overbudget_bodies(self):
        for value in ('YQ', 'YQ==\n', 'YWI='):
            self.reject(C.unbase64, value, 1)

    def test_read_rejects_symlinks_and_detects_oversized_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'file'
            p.write_bytes(b'abc')
            self.reject(C.read, p, 2)
            link = Path(d) / 'link'
            try:
                link.symlink_to(p)
            except OSError:
                with patch.object(Path, 'is_symlink', return_value=True):
                    self.reject(C.read, p)
            else:
                self.reject(C.read, link)

    def test_calendar_rejects_rollover_and_preserves_go_nanoseconds_offsets(self):
        self.assertEqual(C.timestamp('0000-02-29T01:02:03.123456789+23:59'), (0, 2, 29, 1, 2, 3))
        for v in ('2026-02-29T01:02:03Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+24:00'):
            self.reject(C.timestamp, v)

    def test_manifest_accepts_vite_names_and_optional_dynamic_assets(self):
        b, _ = built()
        _, required, allowed = C.validate_build(CONTRACT, b, COMMIT)
        self.assertNotIn('/assets/later.js', required)
        self.assertIn('/assets/later.js', allowed)

    def test_manifest_rejects_hash_drift_and_missing_import(self):
        b, _ = built()
        b['manifestBase64'] = base64.b64encode(b'{}').decode()
        self.reject(C.validate_build, CONTRACT, b, COMMIT)

    def test_manifest_rejects_path_escape_and_unknown_fields(self):
        b, _ = built()
        b['distFiles'][0]['path'] = '../private'
        self.reject(C.validate_build, CONTRACT, b, COMMIT)
        b, _ = built()
        b['unexpected'] = True
        self.reject(C.validate_build, CONTRACT, b, COMMIT)

    def test_capture_graph_accepts_two_identical_normal_refresh_bodies(self):
        rows, files, required, allowed = capture_rows()
        ids, kinds = C.validate_captures(CONTRACT, rows, files, required, allowed)
        self.assertEqual(len(ids), 6)
        self.assertEqual(kinds['CAPABILITIES'][0]['responseSHA256'], kinds['CAPABILITIES'][1]['responseSHA256'])

    def test_capture_rejects_duplicate_alias_and_unapproved_api(self):
        rows, files, required, allowed = capture_rows()
        rows[1]['requestId'] = 'r1'
        self.reject(C.validate_captures, CONTRACT, rows, files, required, allowed)
        rows, files, required, allowed = capture_rows()
        rows[-1]['path'] = '/api/v1/subscriptions/sources'
        self.reject(C.validate_captures, CONTRACT, rows, files, required, allowed)

    def test_capture_rejects_post_authorization_and_body_hash_drift(self):
        for field, value in [('method', 'POST'), ('authorizationPresent', True), ('responseSHA256', '0' * 64)]:
            rows, files, required, allowed = capture_rows()
            rows[-1][field] = value
            self.reject(C.validate_captures, CONTRACT, rows, files, required, allowed)

    def test_capture_rejects_missing_snapshot_or_second_capability(self):
        rows, files, required, allowed = capture_rows()
        self.reject(C.validate_captures, CONTRACT, rows[:-1], files, required, allowed)

    def test_events_reconstruct_zero_counts_from_actual_graph(self):
        rows, *_ = capture_rows()
        counts = C.validate_events(CONTRACT, event_driver(rows), {r['requestId']: r for r in rows})
        self.assertEqual(counts, {k: 0 for k in CONTRACT['eightZero']})

    def test_synthetic_node_rejects_indented_nested_failure(self):
        raw = cpu_tap_framing()
        with patch.object(S, 'names_sha', return_value=S.NODE_PIN):
            S.verify_node(raw)
            self.reject(S.verify_node, raw + b'    not ok 1 - injected nested failure\n')

    def test_synthetic_node_rejects_suite_summary_tampering(self):
        raw = cpu_tap_framing()
        with patch.object(S, 'names_sha', return_value=S.NODE_PIN):
            S.verify_node(raw)
            self.reject(S.verify_node, raw.replace(b'# suites 0', b'# suites 99'))

    def test_events_reject_scalar_zero_when_console_error_exists(self):
        rows, *_ = capture_rows()
        d = event_driver(rows)
        d['events'].insert(-1, dict(seq=0, type='ERROR', requestId=None, code='console_error'))
        for i, e in enumerate(d['events'], 1):
            e['seq'] = i
        self.reject(C.validate_events, CONTRACT, d, {r['requestId']: r for r in rows})

    def test_events_reject_net_fail_instead_of_filtering_completed_payload(self):
        rows, *_ = capture_rows()
        d = event_driver(rows)
        d['events'][2] = dict(seq=3, type='NET_FAIL', requestId='r1')
        self.reject(C.validate_events, CONTRACT, d, {r['requestId']: r for r in rows})

    def test_events_reject_query_userinfo_cookie_and_service_worker(self):
        rows, *_ = capture_rows()
        for index, field in [(0, 'queryPresent'), (0, 'userInfoPresent'), (0, 'cookiePresent'), (1, 'serviceWorker')]:
            d = event_driver(rows)
            d['events'][index][field] = True
            self.reject(C.validate_events, CONTRACT, d, {r['requestId']: r for r in rows})

    def test_events_reject_unknown_tags_duplicate_terminal_and_post_meta(self):
        rows, *_ = capture_rows()
        for mutation in ('unknown', 'duplicate', 'post_meta'):
            d = event_driver(rows)
            if mutation == 'unknown':
                d['events'][0]['type'] = 'PASSED'
            elif mutation == 'duplicate':
                d['events'][3] = dict(d['events'][2], seq=4)
            else:
                d['events'].append(dict(seq=len(d['events']) + 1, type='ERROR', requestId=None, code='runtime_error'))
            self.reject(C.validate_events, CONTRACT, d, {r['requestId']: r for r in rows})

    def test_events_reject_missing_capture_and_wrong_finish_ordinal(self):
        rows, *_ = capture_rows()
        d = event_driver(rows)
        d['events'][3]['captureOrdinal'] = 2
        self.reject(C.validate_events, CONTRACT, d, {r['requestId']: r for r in rows})

    def test_capability_default_and_configured_preserve_conditional_evidence(self):
        for profile in CONTRACT['profiles']:
            v = C.capability(CONTRACT, body(report(profile)), profile)
            self.assertEqual(len(v['capabilities']), 18)

    def test_capability_rejects_green_configured_claim_in_default_profile(self):
        r = report()
        r['capabilities'][5]['state'] = 'live_readonly'
        self.reject(C.capability, CONTRACT, body(r), 'default')

    def test_capability_rejects_duplicate_ids_and_production_enabled(self):
        for mutation in ('duplicate', 'production'):
            r = report()
            if mutation == 'duplicate':
                r['capabilities'][1]['id'] = r['capabilities'][0]['id']
            else:
                r['productionControlEnabled'] = True
            self.reject(C.capability, CONTRACT, body(r), 'default')

    def test_snapshot_accepts_required_nil_and_signed_unapproved_draft(self):
        v = snapshot()
        v['draft']['businesses'] = [dict(id='draft', name='', domains=None, strategy='', candidates=None, fallback='', skipEmptyPools=False,
            failuresToSwitch=-1, probeIntervalSec=-1, sessionStickyMin=-1, switchCooldownSec=-1)]
        self.assertEqual(C.Snapshot().parse(body(v))['draft']['businesses'][0]['failuresToSwitch'], -1)

    def test_snapshot_rejects_missing_dns_fields_and_optional_null(self):
        v = snapshot()
        del v['draft']['dns']['leakProtection']
        self.reject(C.Snapshot().parse, body(v))
        v = snapshot()
        v['draft']['pools'] = [dict(id='pool', name='', members=None, capabilities=None)]
        self.reject(C.Snapshot().parse, body(v))

    def test_snapshot_rejects_live_source_and_invalid_pool_counts(self):
        v = snapshot()
        v['dataSource'] = 'live'
        self.reject(C.Snapshot().parse, body(v))
        v = snapshot()
        v['pools'] = [dict(name='a', region='b', latencyMs=1, lossRate=0, available=2, total=1, status='')]
        self.reject(C.Snapshot().parse, body(v))

    def test_snapshot_distinguishes_pool_regions_and_duplicate_pairs(self):
        v = snapshot()
        p = dict(name='a', region='b', latencyMs=1, lossRate=0.5, available=1, total=1, status='')
        v['pools'] = [p, dict(p, region='c')]
        C.Snapshot().parse(body(v))
        v['pools'][1]['region'] = 'b'
        self.reject(C.Snapshot().parse, body(v))

    def test_runtime_scope_is_management_not_subscription_or_authentication(self):
        self.assertEqual(C.scope('default')['tenantId'], '')
        self.assertEqual(C.scope('backend_configured')['objectType'], 'control-plane')
        self.assertEqual(C.scope('backend_configured', True)['objectType'], 'subscription-store')

    def test_dom_rejects_fabricated_summary_state_class_and_count(self):
        api = report()
        value = dict(heading='系统闭环', boundary=dict(title='生产写入保持关闭', text='当前页面只展示能力证据，不会发布配置、切换节点或重启网络服务。', writeEnabled=False),
                     summary=[dict(stateClass='live_readonly', label='fake', count=18, description='fake')], meta={}, groups=[])
        self.reject(C.capability_dom, CONTRACT, value, api)

    def test_dom_rejects_wrong_generation_time_without_requiring_new_hash(self):
        api = report()
        value = observed_capabilities(api)
        value['meta']['generatedAtText'] = '2026/10/24 4:04:05'
        self.reject(C.capability_dom, CONTRACT, value, api)

    def test_dom_accepts_observed_string_counts_and_empty_hint_text(self):
        api = report()
        api['capabilities'][0]['evidence'] = ['GET /api/v1/health']
        d = observed_capabilities(api)
        C.capability_dom(CONTRACT, d, api)
        self.assertEqual(d['groups'][0]['rows'][0]['emptyEvidenceLabel'], '')

    def test_complete_seven_checkpoint_cpu_projection_checks_every_page(self):
        rows, captures, snap, reports = observed_pages()
        C.validate_dom(CONTRACT, rows, captures, snap, reports)
        for row in rows[4:]:
            for node in row['dom']['topbar'].values():
                node.update(visible=False, rect=None)
        C.validate_dom(CONTRACT, rows, captures, snap, reports)

    def test_seven_checkpoint_rejects_stale_body_fence_hidden_nav_and_fake_kernel(self):
        for mutation in ('stale', 'fence', 'nav', 'kernel'):
            rows, captures, snap, reports = observed_pages()
            if mutation == 'stale':
                reports[6]['capabilities'][0]['limitations'] = ['new second response, old DOM must fail']
            elif mutation == 'fence':
                rows[3]['dom']['apiFence']['capabilitiesCaptureOrdinals'] = [5]
            elif mutation == 'nav':
                rows[4]['dom']['controls'][0].update(visible=False, rect=None, inViewport=False, unobstructed=False)
            else:
                rows[1]['dom']['kernels']['evidenceStatus'] = '正常'
            self.reject(C.validate_dom, CONTRACT, rows, captures, snap, reports)

    def test_seven_checkpoint_rejects_nonzero_scroll_position(self):
        rows, captures, snap, reports = observed_pages()
        rows[6]['dom']['viewport']['scrollY'] = 1
        self.reject(C.validate_dom, CONTRACT, rows, captures, snap, reports)

    def test_seven_checkpoint_rejects_inconsistent_document_width(self):
        rows, captures, snap, reports = observed_pages()
        rows[6]['dom']['viewport']['scrollWidth'] -= 1
        self.reject(C.validate_dom, CONTRACT, rows, captures, snap, reports)

    def test_dom_rejects_domain_reordering_and_removed_limitations(self):
        api = report()
        d = observed_capabilities(api)
        d['groups'].reverse()
        self.reject(C.capability_dom, CONTRACT, d, api)
        d = observed_capabilities(api)
        d['groups'][0]['rows'][0]['limitations'] = []
        self.reject(C.capability_dom, CONTRACT, d, api)

    def test_dom_rejects_integer_count_substitution_for_observed_text(self):
        api = report()
        d = observed_capabilities(api)
        d['summary'][0]['count'] = 0
        self.reject(C.capability_dom, CONTRACT, d, api)

    def test_runtime_accepts_both_explicit_profiles_and_no_health_claim(self):
        for profile in CONTRACT['profiles']:
            r, s, records = metadata(profile)
            C.runtime_facts(CONTRACT, r, s, records, COMMIT, 'chrome-cdp', profile, 'f' * 32)

    def test_runtime_rejects_default_endpoint_fabrication_and_unknown_state(self):
        r, s, records = metadata('default')
        r['mihomo']['endpointClass'] = 'ISOLATED_LOOPBACK_17892'
        self.reject(C.runtime_facts, CONTRACT, r, s, records, COMMIT, 'chrome-cdp', 'default', 'f' * 32)

    def test_runtime_rejects_foreign_env_write_gate_and_subject_scope(self):
        for mutation in ('env', 'write', 'scope'):
            r, s, records = metadata('backend_configured')
            if mutation == 'env':
                r['environment'].append(dict(name='HTTP_PROXY', value='secret'))
            elif mutation == 'write':
                r['writeGates']['operation'] = True
            else:
                r['scope']['objectType'] = 'subscription-store'
            self.reject(C.runtime_facts, CONTRACT, r, s, records, COMMIT, 'chrome-cdp', 'backend_configured', 'f' * 32)

    def test_storage_rejects_nonempty_store_and_listener_unknown(self):
        r, s, records = metadata('backend_configured')
        s['subscriptionStore']['commandCount'] = 1
        self.reject(C.runtime_facts, CONTRACT, r, s, records, COMMIT, 'chrome-cdp', 'backend_configured', 'f' * 32)
        r, s, records = metadata('backend_configured')
        r['upstreamListener']['afterListening'] = None
        self.reject(C.runtime_facts, CONTRACT, r, s, records, COMMIT, 'chrome-cdp', 'backend_configured', 'f' * 32)

    def test_source_binding_mocked_git_checks_host_source_and_required_copies(self):
        root, iso, inputs, build, fake_git = source_fixture()
        with patch.object(C, 'git', side_effect=fake_git):
            C.source_bindings(CONTRACT, iso, inputs, build, root, COMMIT)
        inputs['copiedInputs'] = [r for r in inputs['copiedInputs'] if r['path'] != 'chengwang/tools/capability-truth-browser/ui-dom.mjs']
        with patch.object(C, 'git', side_effect=fake_git):
            self.reject(C.source_bindings, CONTRACT, iso, inputs, build, root, COMMIT)

    def test_source_binding_rejects_copy_drift_and_missing_tracked_source(self):
        root, iso, inputs, build, fake_git = source_fixture()
        inputs['copiedInputs'][0]['sha256'] = '0' * 64
        with patch.object(C, 'git', side_effect=fake_git):
            self.reject(C.source_bindings, CONTRACT, iso, inputs, build, root, COMMIT)
        root, iso, inputs, build, fake_git = source_fixture()
        iso['sourceFilesBefore'] = iso['sourceFilesBefore'][1:]
        iso['sourceFilesAfter'] = copy.deepcopy(iso['sourceFilesBefore'])
        with patch.object(C, 'git', side_effect=fake_git):
            self.reject(C.source_bindings, CONTRACT, iso, inputs, build, root, COMMIT)

    def test_source_binding_rejects_omitted_consumed_neutral_and_tls_sources(self):
        for path in ['chengwang/tools/subscription-ui-browser/ui-driver.mjs', 'chengwang/tools/subscription-ui-browser/ui-contract.mjs',
                     'chengwang/tools/subscription-ui-browser/navigation-diagnostics.mjs', 'chengwang/tools/subscription-ui-browser/navigation-diagnostics-contract.json',
                     'chengwang/web/scripts/trust-browser-tls.mjs', 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py',
                     'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py:launcher']:
            root, iso, inputs, build, fake_git = source_fixture()
            inputs['copiedInputs'] = [r for r in inputs['copiedInputs'] if r['path'] != path]
            with patch.object(C, 'git', side_effect=fake_git):
                self.reject(C.source_bindings, CONTRACT, iso, inputs, build, root, COMMIT)
    def test_source_binding_rejects_actual_host_checker_bytes_drift(self):
        root, iso, inputs, build, fake_git = source_fixture()
        original = C.read
        def changed(path, maximum=16 << 20):
            return b'drift' if Path(path) == Path(C.__file__) else original(path, maximum)
        with patch.object(C, 'git', side_effect=fake_git), patch.object(C, 'read', side_effect=changed):
            self.reject(C.source_bindings, CONTRACT, iso, inputs, build, root, COMMIT)

    def test_tls_mocked_openssl_uses_capture_epoch_and_ip_without_bypass(self):
        ca, leaf = b'cpu-only-ca', b'cpu-only-leaf'
        pem = lambda b: '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(b).decode() + '\n-----END CERTIFICATE-----\n'
        d = dict(normalTrust=dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,', caSHA256=C.sha(ca), leafSHA256=C.sha(leaf), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True),
            tls=dict(securityState='secure', protocol='TLS 1.3', cipher='TEST', leafSHA256=C.sha(leaf), caSHA256=C.sha(ca), serverChainLength=1, leafSignatureVerified=True, ipSANVerified=True), certificateChain=[base64.b64encode(leaf).decode()])
        with patch.object(C.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as mocked:
            C.verify_tls(CONTRACT, dict(caPEM=pem(ca), leafPEM=pem(leaf)), d, [dict(startedWallTimeUs=1792800000123456)])
            args = mocked.call_args.args[0]
            self.assertEqual(args[args.index('-attime') + 1], '1792800000')
            self.assertEqual(args[args.index('-verify_ip') + 1], '127.0.0.1')
            self.assertIn('-check_ss_sig', args)
        d['certificateChain'] = [base64.b64encode(ca).decode()]
        self.reject(C.verify_tls, CONTRACT, dict(caPEM=pem(ca), leafPEM=pem(leaf)), d, [dict(startedWallTimeUs=1)])

    def test_png_rejects_crc_corruption_and_wrong_viewport(self):
        chunk = lambda k, b: struct.pack('>I', len(b)) + k + b + struct.pack('>I', zlib.crc32(k + b) & 0xffffffff)
        p = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\0\0\0\0')) + chunk(b'IEND', b'')
        C.png(p, 1, 1)
        self.reject(C.png, p, 2, 1)
        self.reject(C.png, p[:-1] + b'\1', 1, 1)

    def test_closed_file_set_rejects_missing_originals_without_trusting_passed(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'passed.json').write_text('{"passed":true}')
            self.reject(C.verify, Path(d), Path(d), COMMIT, 'chrome-cdp', 'default')

    def test_output_cli_rejects_existing_report_and_suppresses_raw_errors(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'report'
            p.write_text('already exists')
            with patch('sys.argv', ['checker', '--evidence', d, '--repo', d, '--source-commit', COMMIT, '--engine', 'chrome-cdp', '--profile', 'default', '--report', str(p)]):
                self.reject(C.main)
            self.assertEqual(p.read_text(), 'already exists')


if __name__ == '__main__':
    unittest.main(verbosity=2)
