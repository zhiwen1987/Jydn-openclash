"""Contract/source consistency only. These checks never run a browser or product."""
import copy
import hashlib
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
CONTRACT = pathlib.Path(__file__).with_name('contract.json')
PROFILES = ('evidence_disabled', 'evidence_enabled_unknown')
RAW_COUNTERS = ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors')
PNG = ('demo-desktop.png', 'actual-desktop.png', 'actual-refreshed-desktop.png', 'demo-return-desktop.png', 'actual-remount-desktop.png', 'actual-mobile.png', 'demo-mobile.png', 'actual-reenter-mobile.png')
FRAMEWORK = ('driver.json', 'captures.jsonl', 'dom.jsonl', 'processes.json', 'isolation.json', 'inputs.json', 'certificates.json', 'pin-consumption.json', 'build.json', 'runtime-facts.json', 'storage-readback.json')
KINDS = ('DOCUMENT', 'ASSET', 'SNAPSHOT', 'OVERVIEW', 'OBSERVATION_STATUS', 'PROBE_STATUS')
COMMON_STEPS = ('demo_desktop', 'actual_enter_desktop', 'actual_refresh_desktop', 'demo_return_desktop', 'actual_reenter_desktop', 'kernels_page_desktop', 'actual_return_from_kernels', 'actual_mobile', 'actual_mobile_refresh', 'demo_mobile', 'actual_mobile_reenter')
EXTRA_STEPS = ('device_page_desktop', 'actual_return_from_device', 'nodes_page_desktop', 'actual_return_from_nodes', 'subscriptions_page_desktop', 'actual_return_from_subscriptions')
TOP = set('schema scenario profiles engines sourceBasis origin driverEntrypoint privateInputFilename pngFileBytesMax buildFileBytesMax publicFiles privateFiles schemaNames browserEnvironment profileFacts profilePolicies captureRules apiRoutes exactKeySchemas nestedExactKeys driverEvents counterRules expected503Union wireKeys apiExpected controlSlots stepColumns stepFences stepRules domSemantics runtimeLeafValues storageLeafValues buildAndTrust manifestAlgorithm negativeAcceptanceCases unproven'.split())


class ContractRejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise ContractRejected('overview contract rejected')


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def load(raw=None):
    raw = CONTRACT.read_bytes() if raw is None else raw
    need(type(raw) is bytes and 0 < len(raw) <= 131072)
    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))
    except (ValueError, UnicodeError, RecursionError):
        raise ContractRejected('overview contract rejected') from None
    return result


def validate_terminal(value):
    need(type(value) is dict and set(value) == {'event', 'encodedDataLength', 'canceled', 'blockedReasonPresent', 'corsErrorPresent'})
    if value['event'] == 'FINISH':
        need(type(value['encodedDataLength']) is int and 0 <= value['encodedDataLength'] <= 9007199254740991)
        need(all(value[key] is None for key in ('canceled', 'blockedReasonPresent', 'corsErrorPresent')))
    elif value['event'] == 'NET_FAIL':
        need(value['encodedDataLength'] is None and value['canceled'] is True
             and value['blockedReasonPresent'] is False and value['corsErrorPresent'] is False)
    else:
        need(False)
    return value


def source_favicon():
    html = (ROOT / 'chengwang/web/index.html').read_text(encoding='utf-8')
    helper = (ROOT / 'chengwang/tools/subscription-ui-browser/ui-contract.mjs').read_text(encoding='utf-8')
    html_match = re.search(r'<link rel="icon" href="([^"]+)"', html)
    helper_match = re.search(r'export const FAVICON = "([^"]+)"', helper)
    need(html_match is not None and helper_match is not None and html_match[1] == helper_match[1])
    return html_match[1]


def validate_action_timings(value, profile):
    need(type(value) is dict and set(value) == {'nodeVisit'})
    if profile == PROFILES[0]:
        need(value['nodeVisit'] is None)
    else:
        need(profile == PROFILES[1])
        visit = value['nodeVisit']
        need(type(visit) is dict and set(visit) == {'enteredMonotonicUs', 'returnedMonotonicUs'})
        need(all(type(number) is int and 0 <= number <= 9007199254740991 for number in visit.values()))
        need(0 <= visit['returnedMonotonicUs'] - visit['enteredMonotonicUs'] <= 10000000)


def validate(value):
    need(type(value) is dict and set(value) == TOP)
    need(value['schema'] == 'chengwang.overview-ui-browser-contract/v1' and value['scenario'] == 'overview_ui')
    need(value['profiles'] == list(PROFILES) and value['engines'] == ['chrome-cdp', 'playwright'])
    need(value['origin'] == 'https://127.0.0.1:17891')
    need(value['driverEntrypoint'] == 'chengwang/tools/overview-ui-browser/ui-cli.mjs')
    need(value['privateInputFilename'] == 'overview-input.private.json')
    need(value['publicFiles'] == list(FRAMEWORK + PNG) and len(set(value['publicFiles'])) == 19)
    need(set(value['profileFacts']) == set(PROFILES) == set(value['profilePolicies']) == set(value['stepFences']))
    need(value['browserEnvironment'] == dict(language='zh-CN', timeZone='UTC', deviceScaleFactor=1, physicalTouchDeviceProven=False))
    bounds = value['captureRules']['bounds']
    need(all(type(number) is int and number > 0 for number in bounds.values()))
    need(bounds['assets'] == 64 and bounds['bodyAPI'] == 65536 and bounds['manifestBytes'] == 262144)
    need(bounds['events'] == 512 and bounds['sourceManifestEntries'] == 2000)
    need(bounds['domRowBytes'] == 131072 and bounds['domFileBytes'] == 2097152 and bounds['driverFileBytes'] == 1048576)
    need(value['pngFileBytesMax'] == 4194304 and value['buildFileBytesMax'] == 1048576)
    need(value['captureRules']['kindEnum'] == list(KINDS))
    need(value['captureRules']['method'] == 'GET' and value['captureRules']['anonymous'] is True)
    need(value['captureRules']['requestPublic'] is None)
    old_manifest = json.loads((ROOT / 'chengwang/deploy/capability-truth-browser/contract.json').read_bytes())['manifestAlgorithm']
    need(value['manifestAlgorithm'] == old_manifest)
    need(value['manifestAlgorithm']['mainEntryRequired'] is True)
    icon = value['captureRules']['ignoredFavicon']
    need(icon['url'] == source_favicon() and icon['method'] == 'GET')
    need(all(icon[key] is False for key in ('authorizationPresent', 'cookiePresent', 'bodyPresent', 'redirectPresent', 'networkFaviconException')))
    need(type(icon['requestIdsMax']) is int and icon['requestIdsMax'] == 4)
    terminal_rules = value['captureRules']['terminalScalarRules']
    need(set(terminal_rules) == {'FINISH', 'NET_FAIL'})
    need(terminal_rules['FINISH'] == dict(event='FINISH', encodedDataLength=dict(type='integer', minimum=0, maximum=9007199254740991),
                                        canceled=None, blockedReasonPresent=None, corsErrorPresent=None))
    validate_terminal(terminal_rules['NET_FAIL'])
    expected_paths = {'SNAPSHOT': '/api/v1/snapshot', 'OVERVIEW': '/api/v1/overview', 'OBSERVATION_STATUS': '/api/v1/observations/status', 'PROBE_STATUS': '/api/v1/probes/status'}
    need(set(value['apiRoutes']) == set(expected_paths))
    for kind, route in value['apiRoutes'].items():
        need(route['path'] == expected_paths[kind] and '?' not in route['path'])
        need(route['contentType'] == 'application/json; charset=utf-8')
        if kind != 'OVERVIEW':
            need(type(route['status']) is int and route['status'] == 200 and route['bodyRequired'] is True)
    need(value['stepColumns'] == ['step', 'action', 'navigationPage', 'viewKind', 'heading', 'width', 'height', 'overviewGets', 'observationStatusGets', 'probeStatusGets', 'png'])
    slots = value['controlSlots']
    need(len(slots) == 11 and len({row['key'] for row in slots}) == 11)
    need(all(set(row) == {'key', 'label', 'labelSource', 'selector', 'ariaPressed'} for row in slots))
    slot_keys = {row['key'] for row in slots}
    for index, profile in enumerate(PROFILES):
        facts, steps = value['profileFacts'][profile], value['stepFences'][profile]
        expected_counts = dict(snapshot=1, overview=6 if index == 0 else 9, observationStatus=index, probeStatus=index)
        need(facts['liveOverviewEnabled'] is bool(index) and facts['overviewStatus'] == (503 if index == 0 else 200))
        need(facts['apiCounts'] == expected_counts and all(type(n) is int for n in facts['apiCounts'].values()))
        need(facts['documentRequests'] == 1 and facts['assetRequestsMax'] == 64)
        need(type(facts['requestsMax']) is int and facts['requestsMax'] == 1 + 64 + sum(expected_counts.values()))
        need(len(steps) == facts['domCheckpoints'] == (11 if index == 0 else 17))
        names = [step[0] for step in steps]
        need(len(names) == len(set(names)) and set(names) == set(COMMON_STEPS + (() if index == 0 else EXTRA_STEPS)))
        need([name for name in names if name not in EXTRA_STEPS] == list(COMMON_STEPS))
        need([row[10] for row in steps if row[10] is not None] == list(PNG) and facts['screenshots'] == 8)
        previous, node_reads = 0, 0
        mobile_started = False
        for row in steps:
            need(len(row) == 11)
            step, action, page, view, heading, width, height, count, obs, probe, png = row
            need(action in slot_keys | {'navigate', 'resize'})
            need(all(type(number) is int for number in (width, height, count, obs, probe)))
            if action in ('source_actual', 'actual_refresh', 'nav_overview'):
                previous += 1
            need(count == previous)
            if action == 'cta_nodes':
                node_reads += 1
            need(obs == probe == node_reads)
            need(height == 900 and width in (1440, 375))
            mobile_started = mobile_started or width == 375
            need(width == (375 if mobile_started else 1440))
            if view == 'actual':
                need(page == '运行总览' and heading == '实际证据总览')
            elif view == 'demo':
                need(page == heading == '运行总览')
            else:
                expected = {'device_readback': ('设备读回', '设备读回与差异'), 'proxy_observation': ('代理节点', '代理节点观测'), 'subscriptions': ('订阅与提供者', '订阅资源'), 'kernels': ('内核与协议', '内核与协议')}
                need(view in expected and (page, heading) == expected[view])
        need(previous == expected_counts['overview'] and node_reads == index)
        policy = value['profilePolicies'][profile]
        need(len(policy['env']) == 16 and len(policy['mustOmit']) == len(set(policy['mustOmit'])))
        need(not set(policy['env']) & set(policy['mustOmit']))
        need(policy['env']['CHENGWANG_LIVE_OVERVIEW_ENABLED'] == ('true' if index else 'false'))
        for key in ('CHENGWANG_ALLOW_PUBLISH', 'CHENGWANG_OPERATION_WRITES_ENABLED', 'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED', 'CHENGWANG_SUBSCRIPTIONS_ENABLED'):
            need(policy['env'][key] == 'false')
        need({'CHENGWANG_IDENTITIES_FILE', 'CHENGWANG_MIHOMO_URL', 'CHENGWANG_PROBE_READ_ENABLED'} <= set(policy['mustOmit']))
    first, second = [dict(value['profilePolicies'][profile]['env']) for profile in PROFILES]
    first.pop('CHENGWANG_LIVE_OVERVIEW_ENABLED'); second.pop('CHENGWANG_LIVE_OVERVIEW_ENABLED')
    need(first == second)
    rules = value['stepRules']
    need(rules['snapshotGetsAtEveryCheckpoint'] == 1 and rules['nodesVisitSecondsMax'] == 10)
    need('actionTimings' in value['exactKeySchemas']['driver.json'])
    need(value['nestedExactKeys']['driver.actionTimings'] == ['nodeVisit'])
    need(value['nestedExactKeys']['driver.actionTimings.nodeVisit'] == ['enteredMonotonicUs', 'returnedMonotonicUs'])
    timing = rules['nodeVisitTiming']
    need(timing == dict(disabled=dict(nodeVisit=None), enabledRequired=True, unit='microseconds', maximumDelta=10000000,
        minimum=0, maximum=9007199254740991, enterRounding='floor', returnRounding='ceil',
        interval='BEFORE_NODES_CTA_CLICK_TO_AFTER_RETURNED_ACTUAL_CHECKPOINT_SETTLED_AND_GUARD',
        trustBoundary='SOURCE_BOUND_TRUSTED_CI_MONOTONIC_TIMER_WITH_1US_QUANTIZATION_NOT_EXTERNAL_ATTESTATION'))
    need(rules['productProbePollIntervalSeconds'] == 30 and rules['extraPollAccepted'] is False and rules['pollingProven'] is False)
    need(rules['resizeRequests'] == rules['sameSourceClickRequests'] == 0)
    counters = value['counterRules']
    need(counters['rawKeys'] == list(RAW_COUNTERS) and counters['strictZeroKeys'] == [key for key in RAW_COUNTERS[:6] if key != 'consoleErrors'])
    need(counters['claimOriginalEightZero'] is False and counters['otherProfileExceptions'] is False)
    need(counters['unexpectedFailedRequests'] == counters['unexpectedCaptureErrors'] == counters['unexpectedConsoleErrors'] == 0)
    need(counters['qualifiedNetworkLog'] == dict(event='LOG_NETWORK_ERROR', profile='evidence_disabled', kind='OVERVIEW', method='GET', path='/api/v1/overview', status=503,
        source='network', level='error', urlSameRequest=True, workerIdPresent=False, categoryPresent=False, beforeClose=True,
        requiresObservedRequestAndHeaders=True, maximumPerAlias=1, qualificationOrder='EVENT_SEQ', rawConsoleErrorsIncrement=1))
    need(counters['networkLogBoundary'] == 'HTTP_503_ASSOCIATION_NOT_CAUSALITY_OR_NO_LEAK_PROOF_NO_RAW_TEXT_OR_URL_BEFORE_CLOSE_IS_SOURCE_BOUND_TRUSTED_CI_PROJECTION')
    union = value['expected503Union']
    need((union['profile'], union['kind'], union['method'], union['path'], union['status']) == (PROFILES[0], 'OVERVIEW', 'GET', '/api/v1/overview', 503))
    need(union['anonymous'] is True and union['sameOrigin'] is True and union['queryPresent'] is False)
    need(union['terminalEvents'] == ['FINISH', 'NET_FAIL'])
    need(union['netFailRequired'] == dict(canceled=True, blockedReasonPresent=False, corsErrorPresent=False))
    need(union['bodyRPCAttemptedForBothTerminals'] is True and union['bodyStateEnum'] == ['present', 'unavailable'])
    need(union['present']['bodyRPC'] == dict(attempted=True, outcome='fulfilled'))
    need(union['present']['body'] == dict(code='overview_not_configured', message='实际证据汇总尚未启用'))
    need(union['present']['bodyUnavailableReason'] is None and union['present']['errorCodeObserved'] == 'overview_not_configured')
    unavailable = union['unavailable']
    need(unavailable['bodyRPC'] == dict(attempted=True, outcome='rejected'))
    need(unavailable['bodyUnavailableReason'] == 'BODY_RPC_REJECTED_AFTER_EXPECTED_503')
    need(all(unavailable[key] is None for key in ('responseBase64', 'responseSHA256', 'responseBytes', 'errorCodeObserved')))
    need(type(unavailable['actualCaptureErrorIncrement']) is int and unavailable['actualCaptureErrorIncrement'] == 1)
    need(union['unavailable200Allowed'] is False and union['unavailablePrivacyClaimAllowed'] is False)
    need('coverageGaps' in value['exactKeySchemas']['report'] and 'errorBodyCompleteness' in value['exactKeySchemas']['report'])
    for table in ('exactKeySchemas', 'nestedExactKeys', 'driverEvents', 'wireKeys'):
        need(all(type(keys) is list and keys and len(keys) == len(set(keys)) for keys in value[table].values()))
    need(set(value['driverEvents']) == {'REQUEST', 'HEADERS', 'FINISH', 'NET_FAIL', 'CAPTURE', 'ERROR', 'LOG_NETWORK_ERROR', 'META'})
    need(value['driverEvents']['LOG_NETWORK_ERROR'] == ['seq', 'type', 'requestId', 'source', 'level', 'urlSameRequest', 'workerIdPresent', 'categoryPresent', 'beforeClose'])
    need({'qualifiedExpected503NetworkLogs', 'unexpectedConsoleErrors'} <= set(value['exactKeySchemas']['report']))
    need({'requestId', 'kind', 'code', 'reason'} <= set(value['driverEvents']['ERROR']))
    need({'bodyState', 'bodyUnavailableReason', 'errorCodeObserved', 'bodyRPC'} <= set(value['exactKeySchemas']['captures.jsonl[]']))
    unknown = value['apiExpected']['overviewEnabled']
    need(set(unknown) == set(value['wireKeys']['overview']) - {'generatedAt'})
    need(unknown['dataSource'] == 'live' and unknown['mode'] == 'candidate' and unknown['readOnly'] is True and unknown['advisoryOnly'] is True)
    need(unknown['coverage']['state'] == 'none' and len(unknown['coverage']['missing']) == 7)
    need(unknown['probe']['coverage'] is None and unknown['probe']['coverageState'] == 'unavailable')
    need(unknown['subscription']['sourceCount'] is None and unknown['subscription']['nodeCount'] is None)
    need(all(flag is True for flag in unknown['unsupported'].values()))
    need(all(flag is False for key, flag in value['runtimeLeafValues']['writeGates'].items()))
    need(value['runtimeLeafValues']['identities']['configured'] is False)
    need(value['runtimeLeafValues']['mihomo']['configured'] is False and value['runtimeLeafValues']['probe']['configured'] is False)
    need(value['runtimeLeafValues']['production'] is False)
    need(value['domSemantics']['disabled']['autoDemoFallback'] is False)
    need(value['domSemantics']['mobileVersion'] == dict(present=True, rendered=False, inViewport=False, claimVisibleBadge=False))
    need(value['domSemantics']['enabled']['currentBadges'] == 0 and value['domSemantics']['enabled']['sourceTimePlaceholders'] == 10)
    need('authenticatedResultVisible' in value['nestedExactKeys']['dom.detail'] and 'authenticatedReadPerformed' not in value['nestedExactKeys']['dom.detail'])
    need(value['domSemantics']['detailEvidence'] == dict(authenticatedResultVisible='VISIBLE_AUTH_RESULT_MARKERS_ONLY',
        markers=['.readback-heading .healthy-dot', '.probe-detail', '.subscription-scope'],
        networkProof='NO_AUTHORIZATION_AND_NO_PRIVATE_API_RECONSTRUCTED_FROM_CAPTURES_NOT_THIS_DOM_BOOLEAN', fillFalseFromProfile=False))
    need(value['buildAndTrust']['fetchMocks'] is False and value['buildAndTrust']['stateMocks'] is False)
    need(value['buildAndTrust']['ignoreHTTPSErrors'] is False and value['buildAndTrust']['bypassCSP'] is False)
    need(value['buildAndTrust']['failureIsAcceptance'] is False)
    need(len(value['unproven']) >= 10 and len(value['negativeAcceptanceCases']) >= 20)
    return value


class OverviewContractTests(unittest.TestCase):
    def setUp(self):
        self.value = load()
        validate(self.value)

    def rejects(self, mutate):
        value = copy.deepcopy(self.value)
        mutate(value)
        with self.assertRaises(ContractRejected):
            validate(value)

    def test_contract_is_source_owned_not_runtime_evidence(self):
        self.assertEqual(self.value['sourceBasis']['status'], 'IMPLEMENTATION_CONTRACT_NOT_RUNTIME_EVIDENCE')

    def test_exact_nineteen_files_exclude_private_and_verification(self):
        self.rejects(lambda v: v['publicFiles'].append('verification.json'))
        self.rejects(lambda v: v['publicFiles'].__setitem__(0, 'overview-input.private.json'))

    def test_profiles_and_engines_are_closed(self):
        self.rejects(lambda v: v['profiles'].append('healthy_mock'))
        self.rejects(lambda v: v['engines'].__setitem__(0, 'fake'))

    def test_request_counts_preserve_all_assets_and_snapshot(self):
        self.rejects(lambda v: v['profileFacts'][PROFILES[0]].update(requestsMax=68))
        self.rejects(lambda v: v['profileFacts'][PROFILES[1]]['apiCounts'].update(snapshot=2))
        self.rejects(lambda v: v['manifestAlgorithm']['keys'].remove('names'))
        self.rejects(lambda v: v['manifestAlgorithm']['keys'].append('inventedManifestField'))
        self.rejects(lambda v: v['manifestAlgorithm'].update(entry='trust.html'))
        self.rejects(lambda v: v['manifestAlgorithm'].update(required='All dynamic imports are mandatory'))
        self.rejects(lambda v: v['manifestAlgorithm'].update(mainEntryRequired=1))

    def test_enabled_branch_must_visit_all_three_detail_pages(self):
        self.rejects(lambda v: v['stepFences'][PROFILES[1]].pop(5))

    def test_disabled_branch_has_no_report_only_cta(self):
        self.rejects(lambda v: v['stepFences'][PROFILES[0]][5].__setitem__(1, 'cta_nodes'))

    def test_every_step_requires_current_cumulative_api_fence(self):
        self.rejects(lambda v: v['stepFences'][PROFILES[1]][8].__setitem__(7, 4))

    def test_png_bindings_are_complete_distinct_and_ordered(self):
        self.rejects(lambda v: v['stepFences'][PROFILES[0]][-1].__setitem__(10, 'demo-mobile.png'))

    def test_geometry_and_mobile_source_are_separate_facts(self):
        self.rejects(lambda v: v['domSemantics']['mobileVersion'].update(rendered=True))
        self.rejects(lambda v: v['stepFences'][PROFILES[0]][-1].__setitem__(5, 1440))

    def test_node_visit_budget_does_not_rewrite_or_claim_polling(self):
        self.rejects(lambda v: v['stepRules'].update(productProbePollIntervalSeconds=10))
        self.rejects(lambda v: v['stepRules'].update(extraPollAccepted=True))
        source = (ROOT / 'chengwang/web/src/ProbeReadback.tsx').read_text(encoding='utf-8')
        self.assertRegex(source, r'setInterval\([\s\S]*?30_000')
        validate_action_timings(dict(nodeVisit=None), PROFILES[0])
        validate_action_timings(dict(nodeVisit=dict(enteredMonotonicUs=1, returnedMonotonicUs=10000001)), PROFILES[1])
        for profile, timing in ((PROFILES[0], dict(nodeVisit={})), (PROFILES[1], dict(nodeVisit=None)),
            (PROFILES[1], dict(nodeVisit=dict(enteredMonotonicUs=1, returnedMonotonicUs=10000002))),
            (PROFILES[1], dict(nodeVisit=dict(enteredMonotonicUs=2, returnedMonotonicUs=1))),
            (PROFILES[1], dict(nodeVisit=dict(enteredMonotonicUs=False, returnedMonotonicUs=1)))):
            with self.assertRaises(ContractRejected): validate_action_timings(timing, profile)
        self.rejects(lambda v: v['stepRules']['nodeVisitTiming'].update(maximumDelta=10000001))

    def test_only_overview_enable_env_changes_between_profiles(self):
        self.rejects(lambda v: v['profilePolicies'][PROFILES[1]]['env'].update(CHENGWANG_MIHOMO_URL='http://127.0.0.1:17892'))

    def test_writes_identities_and_upstreams_remain_disabled(self):
        self.rejects(lambda v: v['runtimeLeafValues']['writeGates'].update(publish=True))

    def test_503_exception_is_exact_profile_route_status(self):
        self.rejects(lambda v: v['expected503Union'].update(profile=PROFILES[1]))
        self.rejects(lambda v: v['expected503Union'].update(path='/api/v1/snapshot'))

    def test_canceled_terminal_requires_no_block_or_cors_reason(self):
        self.rejects(lambda v: v['expected503Union']['netFailRequired'].update(canceled=False))
        self.rejects(lambda v: v['expected503Union']['netFailRequired'].update(corsErrorPresent=True))
        self.rejects(lambda v: v['captureRules']['terminalScalarRules']['FINISH'].update(canceled=False))
        self.rejects(lambda v: v['captureRules']['terminalScalarRules']['NET_FAIL'].update(encodedDataLength=0))
        finish = dict(event='FINISH', encodedDataLength=0, canceled=None, blockedReasonPresent=None, corsErrorPresent=None)
        self.assertEqual(validate_terminal(finish), finish)
        for key in ('canceled', 'blockedReasonPresent', 'corsErrorPresent'):
            invalid = dict(finish, **{key: False})
            with self.assertRaises(ContractRejected):
                validate_terminal(invalid)
        net_fail = dict(event='NET_FAIL', encodedDataLength=None, canceled=True, blockedReasonPresent=False, corsErrorPresent=False)
        self.assertEqual(validate_terminal(net_fail), net_fail)
        for changes in (dict(encodedDataLength=0), dict(canceled=None), dict(blockedReasonPresent=None), dict(corsErrorPresent=0)):
            with self.assertRaises(ContractRejected):
                validate_terminal(dict(net_fail, **changes))

    def test_both_terminals_require_actual_body_rpc_attempt(self):
        self.rejects(lambda v: v['expected503Union'].update(bodyRPCAttemptedForBothTerminals=False))

    def test_rpc_rejection_never_fabricates_body_hash_or_error_code(self):
        self.rejects(lambda v: v['expected503Union']['unavailable'].update(errorCodeObserved='overview_not_configured'))
        self.rejects(lambda v: v['expected503Union']['unavailable'].update(responseBytes=0))

    def test_present_error_body_is_fixed_and_full_bytes_required(self):
        self.rejects(lambda v: v['expected503Union']['present']['body'].update(message='successful'))

    def test_no_200_body_exception_or_unobserved_privacy_claim(self):
        self.rejects(lambda v: v['expected503Union'].update(unavailable200Allowed=True))
        self.rejects(lambda v: v['expected503Union'].update(unavailablePrivacyClaimAllowed=True))

    def test_actual_raw_counters_and_qualified_exception_are_distinct(self):
        self.rejects(lambda v: v['counterRules'].update(claimOriginalEightZero=True))
        self.rejects(lambda v: v['counterRules']['strictZeroKeys'].append('failedRequests'))
        self.rejects(lambda v: v['counterRules']['strictZeroKeys'].append('consoleErrors'))
        self.rejects(lambda v: v['counterRules'].update(unexpectedConsoleErrors=1))
        for key, bad in [('source', 'javascript'), ('level', 'warning'), ('workerIdPresent', True), ('categoryPresent', True), ('beforeClose', False), ('maximumPerAlias', 2), ('requiresObservedRequestAndHeaders', False)]:
            with self.subTest(key=key): self.rejects(lambda v: v['counterRules']['qualifiedNetworkLog'].update({key: bad}))

    def test_error_events_have_alias_kind_and_closed_reason(self):
        self.rejects(lambda v: v['driverEvents']['ERROR'].remove('reason'))
        for key in ('requestId', 'source', 'urlSameRequest', 'categoryPresent', 'beforeClose'):
            with self.subTest(key=key): self.rejects(lambda v: v['driverEvents']['LOG_NETWORK_ERROR'].remove(key))
        self.rejects(lambda v: v['driverEvents']['LOG_NETWORK_ERROR'].append('rawText'))

    def test_missing_body_completeness_is_in_independent_report(self):
        self.rejects(lambda v: v['exactKeySchemas']['report'].remove('coverageGaps'))
        self.rejects(lambda v: v['exactKeySchemas']['report'].remove('qualifiedExpected503NetworkLogs'))
        self.rejects(lambda v: v['exactKeySchemas']['report'].remove('unexpectedConsoleErrors'))

    def test_unknown_subscription_counts_stay_null(self):
        self.rejects(lambda v: v['apiExpected']['overviewEnabled']['subscription'].update(nodeCount=0))

    def test_unknown_probe_coverage_never_becomes_numeric_health(self):
        self.rejects(lambda v: v['apiExpected']['overviewEnabled']['probe'].update(coverage={}))

    def test_go_overview_json_fields_match_required_wire_tables(self):
        source = (ROOT / 'chengwang/internal/overview/model.go').read_text(encoding='utf-8')
        for name, key in [('PublicSnapshot', 'overview'), ('Coverage', 'overview.coverage'), ('ObservationSummary', 'overview.observation'), ('Layer', 'overview.layer'), ('ProbeSummary', 'overview.probe'), ('SubscriptionSummary', 'overview.subscription'), ('Unsupported', 'overview.unsupported')]:
            body = re.search(r'type ' + name + r' struct \{([^}]+)\}', source).group(1)
            self.assertEqual(re.findall(r'json:"([^",]+)"', body), self.value['wireKeys'][key])

    def test_page_titles_match_actual_source_not_navigation_labels(self):
        for relative, title in [('MihomoReadback.tsx', '设备读回与差异'), ('ObservationStatus.tsx', '代理节点观测'), ('Subscriptions.tsx', '订阅资源')]:
            source = (ROOT / 'chengwang/web/src' / relative).read_text(encoding='utf-8')
            self.assertIn('<h1>' + title + '</h1>', source)
        self.rejects(lambda v: v['domSemantics']['detailEvidence'].update(networkProof='DOM_FLAG_PROVES_NO_AUTHENTICATED_READ'))
        self.rejects(lambda v: v['nestedExactKeys']['dom.detail'].__setitem__(3, 'authenticatedReadPerformed'))

    def test_as_of_labels_and_nonautomatic_update_notice_match_source(self):
        source = (ROOT / 'chengwang/web/src/EvidenceOverview.tsx').read_text(encoding='utf-8')
        labels = [self.value['domSemantics']['asOfNotice'], self.value['domSemantics']['enabled']['controllerBadge'], self.value['domSemantics']['enabled']['probeBadge'], self.value['domSemantics']['enabled']['generatedAtLabel']]
        self.assertTrue(all(label in source for label in labels))

    def test_frontend_non_ok_cancels_without_reading_error_json(self):
        source = (ROOT / 'chengwang/web/src/overview-api.ts').read_text(encoding='utf-8')
        self.assertIn("if (!response.ok) { cancel(response.body); throw new OverviewReadError('http') }", source)
        self.assertIn('5000)', source)

    def test_disabled_status_wire_obeys_go_omitempty_semantics(self):
        self.assertNotIn('cachedAt', self.value['wireKeys']['probeStatusDisabled'])
        self.assertNotIn('observedAt', self.value['wireKeys']['observationStatusDisabled.layer'])
        self.assertIn('observedAt', self.value['wireKeys']['overview.layer'])

    def test_all_exact_key_arrays_reject_duplicates(self):
        self.rejects(lambda v: v['exactKeySchemas']['build.json'].append('schema'))

    def test_contract_loader_rejects_duplicate_json_and_nonfinite(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"x":NaN}'):
            with self.assertRaises(ContractRejected):
                load(raw)

    def test_contract_budgets_reject_boolean_and_oversize_source_lists(self):
        self.rejects(lambda v: v['captureRules']['bounds'].update(events=True))
        self.rejects(lambda v: v['captureRules']['bounds'].update(sourceManifestEntries=3000))

    def test_ordinary_tls_and_real_product_are_required(self):
        self.rejects(lambda v: v['buildAndTrust'].update(ignoreHTTPSErrors=True))
        self.rejects(lambda v: v['buildAndTrust'].update(fetchMocks=True))
        self.assertEqual(self.value['captureRules']['ignoredFavicon']['url'], source_favicon())
        self.rejects(lambda v: v['captureRules']['ignoredFavicon'].update(url='https://127.0.0.1:17891/favicon.ico'))
        self.rejects(lambda v: v['captureRules']['ignoredFavicon'].update(url='data:image/svg+xml,arbitrary'))
        self.rejects(lambda v: v['captureRules']['ignoredFavicon'].update(networkFaviconException=True))

    def test_unproven_cases_are_not_erased_for_acceptance(self):
        self.rejects(lambda v: v.update(unproven=[]))


if __name__ == '__main__':
    unittest.main(verbosity=2)
