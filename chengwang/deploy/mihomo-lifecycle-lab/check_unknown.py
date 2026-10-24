"""Independent bounded public-original verifier for the opt-in UNKNOWN experiment.

Only independent verifier primitives are imported. A candidate projection is
not an acknowledgement, recovery, private-WAL proof or production approval.
"""
import argparse
import importlib.util
import math
import os
from pathlib import Path
import re
import stat
import subprocess


def need(value):
    if not value:
        raise ValueError('isolated unknown evidence rejected')


def _independent():
    path = Path(__file__).absolute().with_name('check_service.py')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
    spec = importlib.util.spec_from_file_location('_unknown_independent_service', path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    S = _independent()
except Exception:
    raise SystemExit('MIHOMO_UNKNOWN=REJECTED independent_source_unavailable=true') from None
A, C, G = S.A, S.C, S.G
sha, decode, integer, timestamp = S.sha, S.decode, S.integer, S.timestamp
exact, same, digest, ordered, go_bytes, b64 = S.exact, S.same, S.digest, S.ordered, S.go_bytes, S.b64
PREFIX = S.PREFIX
FILES = tuple(S.FILES) + tuple(PREFIX + n for n in ('check_unknown.py', 'test_check_unknown.py',
    'unknown_worker.py', 'unknown_contract.json', 'run_unknown.sh', 'test_unknown_worker.py'))
PUBLIC = tuple({'e2e-report.json': 'unknown-report.json', 'service.json': 'unknown.json',
    'service.stderr': 'unknown.stderr'}.get(n, n) for n in S.PUBLIC)
GO = 'chengwang/internal/serverruntime/mihomo_unknown_e2e_linux_test.go'
FAULT_GO = 'chengwang/internal/adapter/mihomo/lab_reload_fault_linux_test.go'
TOP = 'TestMihomoServiceHTTPUnknownOutcomeBlocksReplayAndNewPlan'
MODEL_TOP = 'TestLabReloadFaultCapsuleModelBoundaries'
PACKAGE = S.PACKAGE
MODEL_PACKAGE = 'chengwang/internal/adapter/mihomo'
SCOPE = 'ACTUAL_FIXED_KERNEL_UNKNOWN_OUTCOME_NO_RESEND_NOT_RECOVERY_OR_PRODUCTION'
REPORT_KEYS = ('schema', 'scope', 'sourceCommit', 'outcome', 'failureCode', 'http', 'before', 'after', 'replay',
    'final', 'fault', 'callsBefore', 'callsAfter', 'callsReplay', 'callsFinal', 'controllerReceivedCount',
    'closedPorts', 'runtimeReturned', 'runtimeErrorClass', 'production', 'fullPayloadProven', 'internetBusinessProven')
WRAPPER_KEYS = ('state', 'activeAttempt', 'activeTransport', 'lastObservation')
DURABLE_KEYS = ('operationId', 'planSHA256', 'intentSHA256', 'conclusion', 'evidenceSHA256', 'observedAt', 'commitRevision')
FAULT_KEYS = ('schema', 'state', 'claimed', 'underlyingRoundTrips', 'statusCode', 'bodyBytes', 'eofObserved',
    'closeSucceeded', 'injected', 'failureCode')
HTTP_CASES = ('ANONYMOUS_CANDIDATES', 'ACTUAL_CANDIDATES', 'VIEWER_CREATE_DENIED', 'SCOPE_CREATE_DENIED',
    'CREATE_ACTUAL_PLAN', 'SELF_APPROVAL_DENIED', 'CURRENT_INDEPENDENT_APPROVAL', 'ACTUAL_EXECUTE_UNKNOWN',
    'INSPECT_UNKNOWN', 'HEAD_REMAINS_OLD', 'CANDIDATES_CURRENT_UNKNOWN', 'REPLAY_UNKNOWN_NO_NEW_DO',
    'CREATE_BLOCKED_BY_UNKNOWN', 'INSPECT_AFTER_BLOCKED_CREATE')
MODEL_GROUPS = (
    'unarmed_global_preserves_original_concrete_transport',
    'actual_wrapper_and_original_reload_unknown_without_second_call',
    'non204_is_original_response_and_original_reload',
    'framing_anomalies_delegate_without_consumption',
    'consumed_anomalies_preserve_observation_and_cannot_pass',
    'cancel_before_dispatch_does_not_claim', 'cancel_after_headers_before_body_is_original_reload',
    'underlying_error_and_nil_response_are_not_injected',
    'response_and_error_are_delegated_by_identity_without_body_read',
    'fixed_request_match_does_not_claim_other_targets', 'concurrent_claims_have_one_underlying_call',
    'spent_issue_attempt_and_foreign_handles_cannot_revive', 'debug_and_json_are_fixed_and_nonce_free')
MODEL_NESTED = {
    MODEL_GROUPS[2]: ('200', '302', '403', '429', '503'),
    MODEL_GROUPS[3]: ('positive_length', 'invalid_length', 'transfer_encoding', 'transfer_header', 'length_header', 'duplicate_length'),
    MODEL_GROUPS[4]: ('read', 'close', 'nonempty', 'limit', 'cancel_during_read'),
    MODEL_GROUPS[7]: ('error', 'nil_response', 'nil_body')}
MODEL_NAMES = (MODEL_TOP,) + tuple(MODEL_TOP + '/' + n for n in MODEL_GROUPS) + tuple(
    MODEL_TOP + '/' + group + '/' + n for group, names in MODEL_NESTED.items() for n in names)


def contract(sources):
    expected = dict(schema='chengwang.mihomo-unknown-experiment-contract/v1', scope=SCOPE,
        tags=['chengwang_mihomo_service', 'chengwang_mihomo_faults'],
        goPackages=['./internal/adapter/mihomo', './internal/serverruntime'], topTests=[MODEL_TOP, TOP],
        goTimeoutSeconds=75, outerGoTimeoutSeconds=90, privateRoot=S.BASES[0], identityRoot=S.BASES[1], stateRoot=S.BASES[2],
        captureStages=['bootstrap', 'op-01/create', 'op-01/pre-dispatch', 'op-01/post-dispatch'],
        captureFiles=list(S.CAPTURE), maxPublicBytes=16 << 20, maxCaptureBodyBytes=256 << 10,
        maxVerificationBytes=64 << 10, production=False)
    same(decode(sources[PREFIX + 'unknown_contract.json']), expected)
    source = sources[GO].decode('utf8')
    need(source.startswith('//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults\n'))
    need(re.findall(r'^func (Test\w+)\(t \*testing.T\)', source, re.M) == [TOP])
    model = sources[FAULT_GO].decode('utf8')
    need(model.startswith('//go:build linux && chengwang_mihomo_faults\n'))
    need(re.findall(r'^func (Test\w+)\(t \*testing.T\)', model, re.M) == [MODEL_TOP])
    need(tuple(re.findall(r't\.Run\("([a-z0-9_]+)"', model)) == MODEL_GROUPS)
    need('[]int{200, 302, 403, 429, 503}' in model)
    for names in list(MODEL_NESTED.values())[1:]:
        need('[]string{' + ', '.join('"' + n + '"' for n in names) + '}' in model)


def sandbox(raw, sources, commit, elf, receipt):
    # Same bounded independent custody primitives, actual UNKNOWN schema.
    v = exact(decode(raw['sandbox.json']), (*A.SANDBOX_KEYS, 'serviceBases'))
    need(v['schema'] == 'chengwang.mihomo-unknown-sandbox/v1' and v['sourceCommit'] == commit)
    integer(v['uid'], 10001, 10001); integer(v['gid'], 10001, 10001)
    need(v['effectiveCaps'] == '0000000000000000' and v['noNewPrivileges'] is True)
    same(v['environmentKeys'], list(A.ENV)); same(v['interfaceNames'], ['lo']); same(v['serviceBases'], S.BASES)
    same(v['defaultV4Routes'], []); same(v['defaultV6Routes'], [])
    need(v['sourceModuleSHA256'] == sha(sources['chengwang/go.mod']) and v['sourceReadOnly'] is True and v['goReadOnly'] is True)
    same(v['kernelCopy'], dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', readOnly=True, executable=True))
    before, after = decode(raw['host-before.json']), decode(raw['host-after.json'])
    exact(before, ('networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256')); same(before, after); digest(before['resolvSHA256'])
    for key, prefix in [('networkNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid')]:
        for item in (before[key], v[key]):
            need(type(item) is str and re.fullmatch(prefix + r':\[[1-9][0-9]{0,19}\]', item) is not None)
        need(before[key] != v[key])
    custody = exact(v['inputCustody'], ('before', 'after')); same(custody['before'], custody['after'])
    for side in ('before', 'after'):
        exact(custody[side], ('elf', 'receipt'))
        for name, hashed, size, mode in [('elf', elf['sha256'], elf['bytes'], '0500'), ('receipt', sha(receipt), len(receipt), '0400')]:
            item = exact(custody[side][name], ('sha256', 'bytes', 'mode', 'uid', 'gid'))
            need(item['sha256'] == hashed and item['mode'] == mode); integer(item['bytes'], size, size)
            integer(item['uid'], 0, (1 << 32) - 1); integer(item['gid'], 0, (1 << 32) - 1)
    return v


def events(raw):
    expected = {MODEL_PACKAGE: set(MODEL_NAMES), PACKAGE: {TOP}}
    state = {p: dict(start=False, ended=False, running=set(), passed=set(), last=None) for p in expected}
    order = []
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20)
        row = decode(line, elapsed=True)
        need(type(row) is dict and set(row) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'})
        package = row.get('Package'); need(package in state)
        s = state[package]; need(not s['ended'])
        when = timestamp(row.get('Time')); need(s['last'] is None or when >= s['last']); s['last'] = when
        if 'Elapsed' in row:
            need(type(row['Elapsed']) in (int, float) and math.isfinite(row['Elapsed']) and row['Elapsed'] >= 0)
        action, name = row.get('Action'), row.get('Test')
        if name is not None: need(type(name) is str and name in expected[package])
        if action == 'start':
            need(not s['start'] and name is None and 'Elapsed' not in row)
            need(not order or state[order[-1]]['ended']); order.append(package); s['start'] = True
        elif action == 'run':
            need(s['start'] and name is not None and name not in s['running'] | s['passed'] and 'Elapsed' not in row)
            if '/' in name: need(name.rsplit('/', 1)[0] in s['running'])
            s['running'].add(name)
        elif action == 'pass':
            need(s['start'])
            if name is not None:
                need(name in s['running'] and not any(n.startswith(name + '/') for n in s['running']))
                s['running'].remove(name); s['passed'].add(name)
            else:
                need(not s['running'] and s['passed'] == expected[package]); s['ended'] = True
        elif action == 'output':
            need(s['start'] and 'Elapsed' not in row and (name is None or name in s['running']))
            output = row.get('Output'); need(type(output) is str and len(output) <= 4096)
            choices = '|'.join(re.escape(n) for n in expected[package])
            grammar = (r'(?:=== RUN   (?:' + choices + r')|[ ]*--- PASS: (?:' + choices +
                r') \([0-9.]+s\)|PASS|ok\s+' + re.escape(package) + r'\s+[0-9.]+s|'
                r'[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} chengwang listening \(mode=isolated-lab\))\n')
            need(re.fullmatch(grammar, output) is not None)
        else: need(False)
        if action != 'output': need('Output' not in row)
    need(order == [MODEL_PACKAGE, PACKAGE] and all(s['ended'] for s in state.values()))
    return dict(topLevel=2, passingSemanticTests=len(MODEL_NAMES) + 1, skips=0,
        modelPackage=dict(package=MODEL_PACKAGE, topLevel=1, passingSemanticTests=len(MODEL_NAMES)),
        actualKernelPackage=dict(package=PACKAGE, topLevel=1, passingSemanticTests=1))


def capture(raw, stage, index, commit, elf, netns):
    original = raw[stage + '-verification.json']; need(0 < len(original) <= 64 << 10)
    v = ordered(decode(original), ('Observation', 'Readback', 'Transcript', 'Bodies', 'Route')); need(go_bytes(v) == original)
    ordered(v['Readback'], A.READBACK_KEYS)
    o = ordered(v['Observation'], S.OBS_KEYS); scope = ordered(o['Scope'], S.SCOPE_KEYS)
    need(all(type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', x) for x in scope.values()))
    need(scope['objectType'] == 'mihomo-lab' and scope['environment'] == 'isolated-lab' and o['DeviceRef'] == scope['objectId'])
    need(o['Phase'] == ('BOOTSTRAP' if index == 0 else 'UNKNOWN_OBSERVATION' if index == 3 else 'BASELINE'))
    need(o['VerificationSHA256'] == ''); timestamp(o['ObservedAt']); S.artifact(o['Artifact'])
    ident = ordered(o['StartupIdentity'], A.IDENTITY_KEYS)
    A.identity(ident, commit, elf, dict(sha256=ident['artifactSHA256'])); integer(ident['netNSInode'], netns, netns)
    transcript = raw[stage + '-transcript.json']; digest(v['Transcript']); need(v['Transcript'] == sha(transcript))
    need(type(v['Bodies']) is list and len(v['Bodies']) == 8)
    phase = 'candidate' if index == 3 else 'baseline'
    originals = {G.TRANSCRIPT_NAMES[phase]: transcript}
    for ordinal, name in enumerate(G.BODY_NAMES[phase], 1):
        body = raw[stage + f'-body-{ordinal}.json']; need(0 < len(body) <= 256 << 10)
        need(v['Bodies'][ordinal - 1] == sha(body)); originals[name] = body
    context = dict(getEvidence={phase: dict(sha256=sha(transcript), bytes=len(transcript))}, readbacks={phase: v['Readback']})
    recomputed = G._capture(originals, phase, context)
    need(sum(len(raw[stage + '-' + n]) for n in S.CAPTURE) <= 2 << 20)
    return dict(receipt=v, observation=o, projection=recomputed, sha256=sha(original), bytes=len(original))


def route_chain(captures):
    prior = None; nonces = set(); hashes = set()
    for i, c in enumerate(captures):
        r = ordered(c['receipt']['Route'], A.ROUTE_KEYS); role = 'B' if i == 3 else 'A'
        need(r['phase'] == ('BOOTSTRAP' if i == 0 else 'UNKNOWN_OBSERVATION' if i == 3 else 'BASELINE') and r['matched'] is True)
        digest(r['nonceSHA256']); need(r['nonceSHA256'] not in nonces); nonces.add(r['nonceSHA256'])
        values = [A.body(r[k]) for k in ('clientResponse', 'proxyResponse', 'originResponse')]
        for v in values: ordered(v, A.BODY_KEYS)
        same(values[0], values[1]); same(values[0], values[2])
        integer(values[0]['bytes'], len('chengwang-local-service-marker/v1:A:') + 65, len('chengwang-local-service-marker/v1:A:') + 65)
        need(values[0]['sha256'] not in hashes); hashes.add(values[0]['sha256'])
        before, after = A.counters(r['countersBefore']), A.counters(r['countersAfter'])
        for row in before + after: ordered(row, A.COUNTER_KEYS)
        if prior is None: need(all(v[k] == 0 for v in before for k in A.COUNTER_KEYS[1:]))
        else: same(before, prior)
        for b, a in zip(before, after):
            for k in A.COUNTER_KEYS[1:]:
                delta = 1 if (b['role'] == role and k in ('connectIngress', 'tunnelRequests', 'forwardInvocations', 'originRequests')) or (b['role'] == 'origin' and k == 'originRequests') else 0
                integer(a[k], b[k] + delta, b[k] + delta)
        prior = after


def unknown(value):
    exact(value, S.TRANSPORT_KEYS); exact(value['result'], ('state', 'dispatched', 'statusCode'))
    need(value['origin'] == 'ADAPTER' and value['gateReason'] is None and value['result']['state'] == 'unknown' and value['result']['dispatched'] is True)
    integer(value['result']['statusCode'], 0, 0); timestamp(value['recordedAt']); return value


def fault(value):
    exact(value, FAULT_KEYS)
    need(value['schema'] == 'chengwang.mihomo-reload-response-loss-observation/v1' and value['state'] == 'INJECTED')
    for key in ('claimed', 'eofObserved', 'closeSucceeded', 'injected'): need(value[key] is True)
    integer(value['underlyingRoundTrips'], 1, 1); integer(value['statusCode'], 204, 204); integer(value['bodyBytes'], 0, 0)
    need(value['failureCode'] is None)


def view(value):
    exact(value, S.VIEW_KEYS)
    need(value['schema'] == 'chengwang.mihomo-lab-deployment-view/v1' and value['boundary'] == S.BOUNDARY)
    need(type(value['operationId']) is str and S.ID.fullmatch(value['operationId']) is not None)
    integer(value['revision'], 1); integer(value['headGeneration'], 1, 1)
    for k in ('planSHA256', 'candidateRecordSHA256', 'candidateConfigSHA256', 'previousHeadSHA256', 'headSHA256'): digest(value[k])
    timestamp(value['expiresAt']); S.proof(value['proof'])
    for k in ('writeBlocked', 'replayed', 'headAdvanced'): need(type(value[k]) is bool)
    need(value['headAdvanced'] is False)
    if value['phase'] in ('PLANNED', 'APPROVED'):
        need(value['transport'] is None and value['observation'] is None and value['writeBlocked'] is False and value['replayed'] is False)
    else:
        need(value['phase'] == 'UNKNOWN' and value['writeBlocked'] is True); unknown(value['transport'])
        o = exact(value['observation'], ('conclusion', 'observedProjectionSHA256', 'evidenceSHA256', 'observedAt', 'localRouteVerified'))
        need(o['conclusion'] == 'STABLE_NEW_PROJECTION' and o['localRouteVerified'] is True)
        digest(o['observedProjectionSHA256']); digest(o['evidenceSHA256']); timestamp(o['observedAt'])
    return value


def envelope(raw, status, changed=False):
    v = ordered(decode(raw), ('boundary', 'code', 'stateMayHaveChanged', 'result'))
    need(go_bytes(v) + b'\n' == raw and v['boundary'] == S.BOUNDARY and v['stateMayHaveChanged'] is changed)
    codes = {200: 'mihomo_lab_ok', 201: 'mihomo_lab_ok', 401: 'mihomo_lab_unauthenticated', 403: 'mihomo_lab_forbidden', 409: 'mihomo_lab_conflict'}
    need(v['code'] == codes[status])
    if status not in (200, 201): need(v['result'] is None)
    return v['result']


def candidates(value, blocked):
    exact(value, ('schema', 'boundary', 'candidates', 'writeBlocked', 'proof'))
    need(value['schema'] == 'chengwang.mihomo-lab-candidates-view/v1' and value['boundary'] == S.BOUNDARY and value['writeBlocked'] is blocked)
    S.proof(value['proof']); need(type(value['candidates']) is list and len(value['candidates']) == 2)
    for i, row in enumerate(value['candidates']):
        exact(row, ('name', 'recordSHA256', 'configSHA256', 'sourceSpecSHA256', 'isCurrent'))
        need(row['name'] == ('local-a' if i == 0 else 'local-b') and row['isCurrent'] is (False if blocked else i == 0))
        for k in ('recordSHA256', 'configSHA256', 'sourceSpecSHA256'): digest(row[k])
    return value


def http(report):
    rows = report['http']; need(type(rows) is list and len(rows) == 14)
    roles = ('anonymous', 'viewer', 'viewer', 'wrong-scope', 'admin', 'admin', 'approver', 'admin', 'admin', 'admin', 'viewer', 'admin', 'admin', 'admin')
    methods = ('GET', 'GET', 'POST', 'POST', 'POST', 'POST', 'POST', 'POST', 'GET', 'GET', 'GET', 'POST', 'POST', 'GET')
    statuses = (401, 200, 403, 403, 201, 403, 200, 200, 200, 200, 200, 200, 409, 200)
    requests = []; responses = []
    for i, row in enumerate(rows):
        exact(row, ('sequence', 'case', 'role', 'method', 'path', 'requestBody', 'statusCode', 'responseBody', 'errorClass'))
        integer(row['sequence'], i + 1, i + 1); integer(row['statusCode'], statuses[i], statuses[i])
        need((row['case'], row['role'], row['method']) == (HTTP_CASES[i], roles[i], methods[i]) and row['errorClass'] == 'NONE')
        req = b64(row['requestBody'], empty=True); requests.append(decode(req) if req else None)
        if req: need(go_bytes(requests[-1]) == req)
        responses.append(envelope(b64(row['responseBody']), statuses[i], methods[i] == 'POST' and statuses[i] in (200, 201)))
    planned, approved, result = view(responses[4]), view(responses[6]), view(responses[7])
    operation = planned['operationId']; need(planned['phase'] == 'PLANNED' and approved['phase'] == 'APPROVED' and result['phase'] == 'UNKNOWN')
    need(result['replayed'] is False)
    integer(approved['revision'], planned['revision'] + 1, planned['revision'] + 1)
    integer(result['revision'], approved['revision'] + 4, approved['revision'] + 4)
    for value in (approved, result, view(responses[8]), view(responses[11]), view(responses[13])):
        for k in ('operationId', 'planSHA256', 'candidateRecordSHA256', 'candidateConfigSHA256', 'previousHeadSHA256', 'headSHA256', 'headGeneration', 'expiresAt'):
            same(value[k], planned[k])
    same(responses[8], result); same(responses[13], result)
    replay = dict(result); replay['replayed'] = True; same(responses[11], replay)
    prefix = '/api/v1/lab/mihomo'
    suffix = ('/candidates', '/candidates', '/deployments', '/deployments', '/deployments', '/deployments/' + operation + '/approvals',
        '/deployments/' + operation + '/approvals', '/deployments/' + operation + '/execute', '/deployments/' + operation,
        '/head', '/candidates', '/deployments/' + operation + '/execute', '/deployments', '/deployments/' + operation)
    for row, ending in zip(rows, suffix): need(row['path'] == prefix + ending)
    for i in (0, 1, 8, 9, 10, 13): need(requests[i] is None)
    create = exact(requests[4], ('candidateRecordSHA256', 'ttlSeconds')); same(create, dict(candidateRecordSHA256=planned['candidateRecordSHA256'], ttlSeconds=300))
    for i in (2, 3, 12): same(requests[i], create)
    for i in (5, 6): same(requests[i], dict(planSHA256=planned['planSHA256'], revision=planned['revision']))
    for i in (7, 11): same(requests[i], dict(planSHA256=approved['planSHA256'], revision=approved['revision']))
    initial, blocked = candidates(responses[1], False), candidates(responses[10], True)
    for a, b in zip(initial['candidates'], blocked['candidates']):
        expected = dict(a); expected['isCurrent'] = False; same(b, expected)
    need(initial['candidates'][1]['recordSHA256'] == planned['candidateRecordSHA256'])
    return operation, planned, approved, result, initial, S.head(responses[9])


def states(report, caps, commit, operation, planned, result, actual_head):
    old = S.expected_head(caps[0], 1, None); first = caps[0]['observation']; last = caps[-1]['observation']
    before = report['before']; snapshots = [before] + [exact(report[k], WRAPPER_KEYS)['state'] for k in ('after', 'replay', 'final')]
    for index, state in enumerate(snapshots):
        exact(state, S.STATE_KEYS)
        need(state['schema'] == 'chengwang.mihomo-lab-acceptance-state/v1' and state['sourceCommit'] == commit and state['walSchema'] == 'chengwang.mihomo-lifecycle-record/v2')
        digest(state['controlSHA256']); digest(state['recordSHA256']); h = S.head(state['head'])
        need(state['privateWALValidated'] is True and state['observedProcessMatchesHead'] is True and state['fullPrivateWALIndependentlyProven'] is False and state['production'] is False)
        same(state['completed'], []); same(state['terminated'], []); integer(h['generation'], 1, 1)
        need(h['headSHA256'] == old and h['previousHeadSHA256'] is None and h['writeBlocked'] is bool(index))
        same([h['artifactRecordSHA256'], h['configSHA256'], h['verificationSHA256'], h['verifiedAt']],
            [first['Artifact']['recordSHA256'], first['Artifact']['config']['sha256'], caps[0]['sha256'], first['ObservedAt']])
        if index == 0:
            integer(state['unknownObservationCount'], 0, 0)
            need(state['activeOperationId'] is state['activePhase'] is state['activeIntentSHA256'] is h['activeOperationId'] is None)
        else:
            integer(state['unknownObservationCount'], 1, 1)
            need(state['activeOperationId'] == h['activeOperationId'] == operation and state['activePhase'] == 'UNKNOWN')
            digest(state['activeIntentSHA256']); integer(h['revision'], result['revision'], result['revision'])
    after = report['after']; same(after, report['replay']); same(after, report['final'])
    state = after['state']; intent = state['activeIntentSHA256']
    integer(after['activeAttempt'], 1, 1); same(unknown(after['activeTransport']), result['transport'])
    observation = exact(after['lastObservation'], DURABLE_KEYS)
    same(observation, dict(operationId=operation, planSHA256=planned['planSHA256'], intentSHA256=intent,
        conclusion='CURRENT_SUPPORTED_POSTCONDITION_OBSERVED', evidenceSHA256=caps[3]['sha256'], observedAt=last['ObservedAt'], commitRevision=result['revision']))
    integer(observation['commitRevision'], result['revision'], result['revision'])
    need(before['controlSHA256'] != state['controlSHA256'] and before['recordSHA256'] != state['recordSHA256'])
    same(actual_head, state['head'])
    need(planned['headSHA256'] == planned['previousHeadSHA256'] == result['headSHA256'] == old)
    need(timestamp(planned['expiresAt']) > timestamp(result['transport']['recordedAt']))
    integer(planned['revision'], before['head']['revision'] + 2, before['head']['revision'] + 2)
    return intent


def journal(raw, report, caps, operation, intent):
    rows = [decode(line) for line in raw['service-journal.jsonl'].splitlines()]
    names = ('STARTUP', 'HEAD_READY', 'PLANNED', 'APPROVED', 'PREPARED', 'DISPATCH_ARMED', 'RELOAD_CALL_INTENT',
        'RELOAD_RETURNED', 'RESULT_RECORDED', 'OBSERVATION_RECORDED', 'CLEANUP_OBSERVED', 'CLOSED')
    need(len(rows) == len(names))
    for row, name in zip(rows, names):
        need(row['stage'] == name)
        if name == 'CLEANUP_OBSERVED':
            exact(row, ('stage', 'kernel', 'fixtures'))
            kernel = exact(row['kernel'], ('started', 'waitReturned', 'waitErrorClass', 'exitCode', 'signal', 'termSent', 'killSent', 'groupAbsent', 'stdout', 'stderr'))
            need(kernel['started'] is True and kernel['waitReturned'] is True and kernel['groupAbsent'] is True)
            need(type(kernel['termSent']) is bool and type(kernel['killSent']) is bool)
            if kernel['waitErrorClass'] == 'NONE': integer(kernel['exitCode'], 0, 0); need(kernel['signal'] is None)
            else:
                need(kernel['waitErrorClass'] == 'EXIT_STATUS' and kernel['exitCode'] is None)
                need((type(kernel['signal']) is int and kernel['signal'] == 15 and kernel['termSent'] is True) or
                     (type(kernel['signal']) is int and kernel['signal'] == 9 and kernel['killSent'] is True))
            A.stream(kernel['stdout'], raw['kernel.stdout']); A.stream(kernel['stderr'], raw['kernel.stderr'])
            fixtures = row['fixtures']; need(type(fixtures) is list and len(fixtures) == 3)
            counters = {r['role']: r for r in caps[-1]['receipt']['Route']['countersAfter']}
            for role, fixture in zip(('origin', 'A', 'B'), fixtures):
                exact(fixture, A.CLEANUP_KEYS)
                need(fixture['role'] == role and fixture['shutdownReturned'] is True and fixture['serveReturned'] is True and fixture['errorClass'] == 'NONE')
                integer(fixture['forcedConnectionsClosed'], 0, 0 if role == 'origin' else counters[role]['connectIngress'])
        else:
            exact(row, ('stage', 'operationId', 'intentSHA256', 'result', 'walRecorded') if name == 'RELOAD_RETURNED' else ('stage', 'operationId', 'intentSHA256'))
            need(row['operationId'] == ('' if name in ('STARTUP', 'HEAD_READY', 'CLOSED') else operation))
            need(row['intentSHA256'] == (intent if name in ('DISPATCH_ARMED', 'RELOAD_CALL_INTENT', 'RELOAD_RETURNED', 'RESULT_RECORDED', 'OBSERVATION_RECORDED') else ''))
            if name == 'RELOAD_RETURNED': same(row['result'], report['after']['activeTransport']['result']); need(row['walRecorded'] is True)


def verify_raw(raw, sources, commit):
    try:
        need(type(raw) is dict and set(raw) == set(PUBLIC) and len(PUBLIC) == len(set(PUBLIC)) == 58)
        need(type(sources) is dict and set(sources) == set(FILES) and len(FILES) == len(set(FILES)) == len(S.FILES) + 6)
        need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit) is not None)
        need(all(type(v) is bytes and 0 < len(v) <= 1 << 20 for v in sources.values()))
        need(all(type(v) is bytes for v in raw.values()) and sum(map(len, raw.values())) <= 16 << 20)
        for name, data in raw.items():
            limit = 8 << 20 if name == 'unknown.json' else 512 << 10 if name == 'unknown-report.json' else 64 << 10 if name.endswith('verification.json') else 256 << 10 if name.endswith(('.json', '.jsonl')) else 1 << 20
            need(len(data) <= limit)
        need(G.unicodedata.unidata_version == G.UNICODE_VERSION); contract(sources)
        for name in ('gofmt.patch', 'gofmt.stderr', 'unknown.stderr'): need(raw[name] == b'')
        need(raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
        e = exact(decode(raw['execution.json']), A.EXECUTION_KEYS)
        need(e['schema'] == 'chengwang.mihomo-unknown-execution/v1' and e['sourceCommit'] == commit and e['realMihomoExecutionObserved'] is True and e['production'] is False)
        integer(e['formatExit'], 0, 0); integer(e['goExit'], 0, 0)
        receipt = raw['consumption.json']; need(receipt == raw['consumption-independent.json']); elf = C.consumption(receipt, sources, commit)
        box = sandbox(raw, sources, commit, elf, receipt); test = events(raw['unknown.json'])
        report = exact(decode(raw['unknown-report.json']), REPORT_KEYS)
        need(report['schema'] == 'chengwang.mihomo-unknown-http-experiment/v1' and report['scope'] == SCOPE and report['sourceCommit'] == commit and report['outcome'] == 'PASS' and report['failureCode'] == 'NONE')
        need(all(report[k] is False for k in ('production', 'fullPayloadProven', 'internetBusinessProven')) and report['controllerReceivedCount'] is None)
        need(report['runtimeReturned'] is True and report['runtimeErrorClass'] == 'NONE'); fault(report['fault'])
        caps = [capture(raw, s, i, commit, elf, int(box['networkNamespace'][5:-1])) for i, s in enumerate(S.STAGES)]
        route_chain(caps); operation, planned, approved, result, initial, actual_head = http(report)
        old, new = caps[0]['observation']['Artifact'], caps[3]['observation']['Artifact']
        need(old['recordSHA256'] != new['recordSHA256'] and old['config']['sha256'] != new['config']['sha256'])
        for i, c in enumerate(caps):
            o = c['observation']; same(o['StartupIdentity'], caps[0]['observation']['StartupIdentity']); same(o['Scope'], caps[0]['observation']['Scope'])
            same(o['Artifact'], new if i == 3 else old); need(o['StartupIdentity']['artifactSHA256'] == old['config']['sha256'])
            need(o['OperationID'] == ('' if i == 0 else operation) and o['PlanSHA256'] == (planned['planSHA256'] if i >= 2 else ''))
            rb, first = c['receipt']['Readback'], caps[0]['receipt']['Readback']
            same([rb['previousProjectionSHA256'], rb['candidateProjectionSHA256']], [first['previousProjectionSHA256'], first['candidateProjectionSHA256']])
            if i: need(timestamp(o['ObservedAt']) >= timestamp(caps[i - 1]['observation']['ObservedAt']))
        for row, artifact in zip(initial['candidates'], (old, new)):
            same([row['recordSHA256'], row['configSHA256'], row['sourceSpecSHA256']], [artifact['recordSHA256'], artifact['config']['sha256'], artifact['sourceSpecSHA256']])
        same([planned['candidateRecordSHA256'], planned['candidateConfigSHA256']], [new['recordSHA256'], new['config']['sha256']])
        intent = states(report, caps, commit, operation, planned, result, actual_head)
        need(timestamp(result['transport']['recordedAt']) <= timestamp(caps[3]['observation']['ObservedAt']))
        for i, c in enumerate(caps): need(c['observation']['IntentSHA256'] == (intent if i == 3 else ''))
        same(result['observation'], dict(conclusion='STABLE_NEW_PROJECTION', observedProjectionSHA256=caps[3]['projection']['observedProjectionSHA256'],
            evidenceSHA256=caps[3]['sha256'], observedAt=caps[3]['observation']['ObservedAt'], localRouteVerified=True))
        for i, key in enumerate(('callsBefore', 'callsAfter', 'callsReplay', 'callsFinal')):
            exact(report[key], ('reloadInvocations', 'doInvocations'))
            for value in report[key].values(): integer(value, 0 if i == 0 else 1, 0 if i == 0 else 1)
        syntax = exact(decode(raw['op-01-syntax.json']), ('schema', 'inputSHA256', 'inputBytes', 'observation'))
        need(syntax['schema'] == 'chengwang.mihomo-lab-service-syntax/v1' and syntax['inputSHA256'] == new['config']['sha256'])
        integer(syntax['inputBytes'], new['config']['bytes'], new['config']['bytes'])
        A.observation(syntax['observation'], raw['op-01-syntax.stdout'], raw['op-01-syntax.stderr'], syntax=True)
        C.safe_stdio('candidate', raw['op-01-syntax.stdout'], raw['op-01-syntax.stderr']); A._kernel_stdio(raw['kernel.stdout'], raw['kernel.stderr'])
        journal(raw, report, caps, operation, intent)
        need(type(report['closedPorts']) is list and len(report['closedPorts']) == 5)
        for port, row in zip(range(28411, 28416), report['closedPorts']):
            exact(row, ('port', 'connectAttempted', 'accepted', 'errorClass')); integer(row['port'], port, port)
            need(row['connectAttempted'] is True and row['accepted'] is False and row['errorClass'] == 'CONNECTION_REFUSED')
        return dict(schema='chengwang.mihomo-unknown-verification/v1', sourceCommit=commit, outcome='PASS', scope=SCOPE, tests=test,
            sourceSHA256={p: sha(sources[p]) for p in FILES}, inputSHA256={p: sha(raw[p]) for p in PUBLIC},
            captures={s: dict(verificationSHA256=c['sha256'], projection=c['projection']) for s, c in zip(S.STAGES, caps)},
            publicHTTPResponsesValidated=True, supportedProjectionRecomputeProven=True, actualClientUnknownPreserved=True,
            unchangedHeadAndNoResendObserved=True, controllerReceivedCount=None,
            currentCredentialContentsIndependentlyProven=False, privateExpectedSourceIndependentlyProven=False,
            fullPrivateWALIndependentlyProven=False, privateDisclosureFenceIndependentlyProven=False,
            fullPayloadProven=False, internetBusinessProven=False, production=False, sourceGitVerified=False)
    except Exception:
        raise ValueError('isolated unknown evidence rejected') from None


def source_bindings(repo, commit):
    repo = C.plain(repo); need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit))
    def git(*args):
        result = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        need(result.returncode == 0 and len(result.stdout) <= 1 << 20); return result.stdout
    need(git('rev-parse', 'HEAD').strip().decode('ascii') == commit and Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() == repo)
    need(len(FILES) == len(set(FILES)) == len(S.FILES) + 6)
    sources = {}
    for p in FILES:
        raw = C.read(repo / p, 1 << 20, False); need(raw == git('show', commit + ':' + p)); sources[p] = raw
    for path, name in [(Path(__file__).absolute(), 'check_unknown.py'), (Path(S.__file__).absolute(), 'check_service.py'),
            (Path(A.__file__).absolute(), 'check_apply.py'), (Path(C.__file__).absolute(), 'check_compat.py'), (Path(G.__file__).absolute(), 'get_projection.py')]:
        need(C.read(path, 1 << 20, False) == sources[PREFIX + name])
    return sources


def main():
    p = argparse.ArgumentParser()
    for name in ('repo', 'source-commit', 'evidence', 'report'):
        p.add_argument('--' + name, required=True, type=str if name == 'source-commit' else Path)
    a = p.parse_args(); a.repo = C.plain(a.repo); a.evidence = C.plain(a.evidence); a.report = C.plain(a.report, True)
    need(a.report.parent.is_dir() and not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.evidence))
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink)
    before = a.evidence.lstat(); need(stat.S_ISDIR(before.st_mode) and {x.name for x in a.evidence.iterdir()} == set(PUBLIC))
    sources = source_bindings(a.repo, a.source_commit)
    raw = {n: C.read(a.evidence / n, 8 << 20, True) for n in PUBLIC}; value = verify_raw(raw, sources, a.source_commit)
    need(all(C.read(a.evidence / n, 8 << 20, True) == b for n, b in raw.items()) and {x.name for x in a.evidence.iterdir()} == set(PUBLIC))
    again = source_bindings(a.repo, a.source_commit); need(all(again[p] == sources[p] for p in FILES))
    need(signature(a.evidence.lstat()) == signature(before)); value['sourceGitVerified'] = True
    need(os.name == 'posix' and os.open in os.supports_dir_fd)
    parent = a.report.parent.lstat(); fd = os.open(a.report.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        need(signature(os.fstat(fd)) == signature(parent) == signature(a.report.parent.lstat()))
        output = os.open(a.report.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        encoded = C.canonical(value)
        with os.fdopen(output, 'wb') as handle:
            need(handle.write(encoded) == len(encoded)); handle.flush(); os.fsync(handle.fileno())
        os.fsync(fd)
    finally: os.close(fd)
    print('MIHOMO_UNKNOWN=PASS public_unknown_semantics_recomputed=true recovery=false production=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('MIHOMO_UNKNOWN=REJECTED evidence_rejected=true production=false') from None
