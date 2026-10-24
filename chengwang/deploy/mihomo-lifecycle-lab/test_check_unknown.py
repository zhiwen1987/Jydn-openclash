"""SYNTHETIC UNKNOWN evidence only; never Go/kernel/HTTP/WAL execution.

The complete invented fixture uses prior independent model materials. PIDs,
namespaces, authentication labels and private-WAL hashes are synthetic, not
actual observations or private source proofs. No producer is imported.
"""
import base64
import copy
import datetime
import json
from pathlib import Path
import unittest

import check_unknown as U
import test_check_service as Prior

COMMIT, OP, PLAN, INTENT = Prior.COMMIT, Prior.OP, Prior.PLAN, Prior.INTENT
wire, hashed, b64 = Prior.wire, Prior.hashed, Prior.b64


def response(row):
    return json.loads(base64.b64decode(row['responseBody']))


def set_response(row, value):
    # Negative lexical-number vectors must reach the verifier. The public Go
    # struct codec deliberately refuses floats and is not their fixture encoder.
    row['responseBody'] = b64(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf8') + b'\n')


def model_events():
    result = []; clock = datetime.datetime(2026, 10, 25, tzinfo=datetime.timezone.utc)
    def add(package, action, name=None):
        row = dict(Time=(clock + datetime.timedelta(milliseconds=len(result))).isoformat(timespec='milliseconds').replace('+00:00', 'Z'), Action=action, Package=package)
        if name is not None: row['Test'] = name
        result.append(row)
    add(U.MODEL_PACKAGE, 'start'); add(U.MODEL_PACKAGE, 'run', U.MODEL_TOP)
    for group in U.MODEL_GROUPS:
        parent = U.MODEL_TOP + '/' + group; add(U.MODEL_PACKAGE, 'run', parent)
        for name in U.MODEL_NESTED.get(group, ()):
            add(U.MODEL_PACKAGE, 'run', parent + '/' + name); add(U.MODEL_PACKAGE, 'pass', parent + '/' + name)
        add(U.MODEL_PACKAGE, 'pass', parent)
    add(U.MODEL_PACKAGE, 'pass', U.MODEL_TOP); add(U.MODEL_PACKAGE, 'pass')
    add(U.PACKAGE, 'start'); add(U.PACKAGE, 'run', U.TOP); add(U.PACKAGE, 'pass', U.TOP); add(U.PACKAGE, 'pass')
    return b''.join(wire(r) for r in result)


def fixture():
    """Complete invented58, NOT an accepted actual UNKNOWN experiment."""
    oldraw, oldsources = Prior.fixture()
    legacy = json.loads(oldraw['e2e-report.json'])
    sources = {p: oldsources.get(p, b'SYNTHETIC_SOURCE_NOT_ACTUAL_GIT_OR_EXECUTION\n') for p in U.FILES}
    root = Path(__file__).parents[2]
    for p in (U.PREFIX + 'unknown_contract.json', U.GO, U.FAULT_GO):
        sources[p] = (root / p.removeprefix('chengwang/')).read_bytes()
    raw = {({'e2e-report.json': 'unknown-report.json', 'service.json': 'unknown.json', 'service.stderr': 'unknown.stderr'}.get(p, p)): v for p, v in oldraw.items()}
    box = json.loads(raw['sandbox.json']); box['schema'] = 'chengwang.mihomo-unknown-sandbox/v1'; raw['sandbox.json'] = wire(box)
    execution = json.loads(raw['execution.json']); execution['schema'] = 'chengwang.mihomo-unknown-execution/v1'; raw['execution.json'] = wire(execution)
    raw['unknown.json'] = model_events()
    stage = U.S.STAGES[-1]; receipt = json.loads(raw[stage + '-verification.json'])
    receipt['Observation']['Phase'] = receipt['Route']['phase'] = 'UNKNOWN_OBSERVATION'
    raw[stage + '-verification.json'] = U.go_bytes(receipt)
    transport = dict(result=dict(state='unknown', dispatched=True, statusCode=0), recordedAt=Prior.when(3), origin='ADAPTER', gateReason=None)
    before = copy.deepcopy(legacy['before'])
    planned = response(legacy['http'][6])['result']; approved = response(legacy['http'][8])['result']
    outcome = copy.deepcopy(planned)
    outcome.update(phase='UNKNOWN', revision=approved['revision'] + 4, transport=transport, writeBlocked=True,
        observation=dict(conclusion='STABLE_NEW_PROJECTION', observedProjectionSHA256=receipt['Readback']['observedProjectionSHA256'],
            evidenceSHA256=hashed(raw[stage + '-verification.json']), observedAt=receipt['Observation']['ObservedAt'], localRouteVerified=True))
    afterstate = copy.deepcopy(before)
    afterstate.update(controlSHA256=hashed(b'MODEL UNKNOWN WAL'), recordSHA256=hashed(b'MODEL UNKNOWN record'),
        activeOperationId=OP, activePhase='UNKNOWN', activeIntentSHA256=INTENT, unknownObservationCount=1)
    afterstate['head'].update(revision=outcome['revision'], activeOperationId=OP, writeBlocked=True)
    after = dict(state=afterstate, activeAttempt=1, activeTransport=transport,
        lastObservation=dict(operationId=OP, planSHA256=PLAN, intentSHA256=INTENT,
            conclusion='CURRENT_SUPPORTED_POSTCONDITION_OBSERVED', evidenceSHA256=hashed(raw[stage + '-verification.json']),
            observedAt=receipt['Observation']['ObservedAt'], commitRevision=outcome['revision']))
    initial = response(legacy['http'][1])['result']
    blocked = copy.deepcopy(initial); blocked['writeBlocked'] = True
    for row in blocked['candidates']: row['isCurrent'] = False
    replayed = copy.deepcopy(outcome); replayed['replayed'] = True
    create = dict(candidateRecordSHA256=planned['candidateRecordSHA256'], ttlSeconds=300)
    approval = dict(planSHA256=PLAN, revision=planned['revision']); execute = dict(planSHA256=PLAN, revision=approved['revision'])
    paths = ('/candidates', '/candidates', '/deployments', '/deployments', '/deployments', '/deployments/' + OP + '/approvals',
        '/deployments/' + OP + '/approvals', '/deployments/' + OP + '/execute', '/deployments/' + OP, '/head', '/candidates',
        '/deployments/' + OP + '/execute', '/deployments', '/deployments/' + OP)
    roles = ('anonymous', 'viewer', 'viewer', 'wrong-scope', 'admin', 'admin', 'approver', 'admin', 'admin', 'admin', 'viewer', 'admin', 'admin', 'admin')
    methods = ('GET', 'GET', 'POST', 'POST', 'POST', 'POST', 'POST', 'POST', 'GET', 'GET', 'GET', 'POST', 'POST', 'GET')
    statuses = (401, 200, 403, 403, 201, 403, 200, 200, 200, 200, 200, 200, 409, 200)
    requests = (None, None, create, create, create, approval, approval, execute, None, None, None, execute, create, None)
    results = (None, initial, None, None, planned, None, approved, outcome, outcome, afterstate['head'], blocked, replayed, None, outcome)
    rows = []
    for i, (role, method, path, request, status, result) in enumerate(zip(roles, methods, paths, requests, statuses, results)):
        envelope = dict(boundary=U.S.BOUNDARY, code={200:'mihomo_lab_ok', 201:'mihomo_lab_ok', 401:'mihomo_lab_unauthenticated', 403:'mihomo_lab_forbidden', 409:'mihomo_lab_conflict'}[status],
            stateMayHaveChanged=status in (200, 201) and method == 'POST', result=result)
        rows.append(dict(sequence=i + 1, case=U.HTTP_CASES[i], role=role, method=method, path='/api/v1/lab/mihomo' + path,
            requestBody=b64(b'' if request is None else U.go_bytes(request)), statusCode=status,
            responseBody=b64(U.go_bytes(envelope) + b'\n'), errorClass='NONE'))
    report = dict(schema='chengwang.mihomo-unknown-http-experiment/v1', scope=U.SCOPE, sourceCommit=COMMIT, outcome='PASS', failureCode='NONE',
        http=rows, before=before, after=after, replay=copy.deepcopy(after), final=copy.deepcopy(after),
        fault=dict(schema='chengwang.mihomo-reload-response-loss-observation/v1', state='INJECTED', claimed=True,
            underlyingRoundTrips=1, statusCode=204, bodyBytes=0, eofObserved=True, closeSucceeded=True, injected=True, failureCode=None),
        callsBefore=dict(reloadInvocations=0, doInvocations=0), callsAfter=dict(reloadInvocations=1, doInvocations=1),
        callsReplay=dict(reloadInvocations=1, doInvocations=1), callsFinal=dict(reloadInvocations=1, doInvocations=1),
        controllerReceivedCount=None, closedPorts=legacy['closedPorts'], runtimeReturned=True, runtimeErrorClass='NONE',
        production=False, fullPayloadProven=False, internetBusinessProven=False)
    raw['unknown-report.json'] = wire(report)
    journal = [json.loads(line) for line in raw['service-journal.jsonl'].splitlines()]
    for row in journal:
        if row['stage'] == 'COMPLETED': row['stage'] = 'OBSERVATION_RECORDED'
        if row['stage'] == 'RELOAD_RETURNED': row['result'] = copy.deepcopy(transport['result'])
    raw['service-journal.jsonl'] = b''.join(wire(r) for r in journal)
    return raw, sources


class SyntheticUnknownEvidenceModels(unittest.TestCase):
    def reject(self, mutate):
        raw, sources = fixture(); mutate(raw, sources)
        with self.assertRaises(ValueError): U.verify_raw(raw, sources, COMMIT)

    def report_reject(self, mutate):
        def change(raw, sources):
            report = json.loads(raw['unknown-report.json']); mutate(report); raw['unknown-report.json'] = wire(report)
        self.reject(change)

    def response_reject(self, index, mutate):
        def change(report):
            row = report['http'][index]; value = response(row); mutate(value); set_response(row, value)
        self.report_reject(change)

    def test_complete_synthetic_unknown_has_bounded_claims_not_execution(self):
        raw, sources = fixture(); value = U.verify_raw(raw, sources, COMMIT)
        self.assertEqual(len(raw), 58); self.assertEqual(len(sources), len(U.FILES))
        self.assertEqual(value['tests']['topLevel'], 2); self.assertEqual(value['tests']['passingSemanticTests'], 34)
        self.assertEqual(value['tests']['modelPackage']['passingSemanticTests'], 33)
        self.assertEqual(value['tests']['actualKernelPackage']['passingSemanticTests'], 1)
        for key in ('sourceGitVerified', 'currentCredentialContentsIndependentlyProven', 'privateExpectedSourceIndependentlyProven',
                'fullPrivateWALIndependentlyProven', 'privateDisclosureFenceIndependentlyProven', 'fullPayloadProven', 'internetBusinessProven', 'production'):
            self.assertIs(value[key], False)
        self.assertIsNone(value['controllerReceivedCount'])

    def test_public_missing_extra_private_or_positive_filename_rejects(self):
        self.reject(lambda r, s: r.pop('op-01-post-dispatch-body-8.json'))
        self.reject(lambda r, s: r.__setitem__('private.yaml', b'MODEL'))
        def positive(r, s): r['e2e-report.json'] = r.pop('unknown-report.json')
        self.reject(positive)

    def test_source_missing_and_source_commit_mismatch_rejects(self):
        self.reject(lambda r, s: s.pop(U.GO))
        self.report_reject(lambda r: r.__setitem__('sourceCommit', '2' * 40))

    def test_contract_wrong_scope_tag_and_real_top_reject(self):
        self.reject(lambda r, s: s.__setitem__(U.GO, b'package serverruntime\n'))
        def contract(r, s):
            v = json.loads(s[U.PREFIX + 'unknown_contract.json']); v['tags'] = ['chengwang_mihomo_service']; s[U.PREFIX + 'unknown_contract.json'] = wire(v)
        self.reject(contract)

    def test_model_name_and_dynamic_leaf_source_binding_reject(self):
        self.reject(lambda r, s: s.__setitem__(U.FAULT_GO, s[U.FAULT_GO].replace(b'"nil_body"', b'"MODEL_renamed"', 1)))

    def test_format_go_exit_and_actual_go_version_are_mandatory(self):
        self.reject(lambda r, s: r.__setitem__('gofmt.patch', b'MODEL format diff\n'))
        self.reject(lambda r, s: r.__setitem__('unknown.stderr', b'MODEL private log'))
        self.reject(lambda r, s: r.__setitem__('go-version.txt', b'go version go1.23.11 linux/amd64\n'))
        def execution(r, s): v=json.loads(r['execution.json']);v['goExit']=1;r['execution.json']=wire(v)
        self.reject(execution)

    def test_both_go_packages_and_all_leaf_events_required(self):
        self.reject(lambda r, s: r.__setitem__('unknown.json', b''.join(x + b'\n' for x in r['unknown.json'].splitlines() if U.PACKAGE.encode() not in x)))
        def missing(r, s):
            leaf=(U.MODEL_TOP+'/'+U.MODEL_GROUPS[2]+'/200').encode()
            r['unknown.json']=b''.join(x+b'\n' for x in r['unknown.json'].splitlines() if leaf not in x)
        self.reject(missing)

    def test_skip_failure_duplicate_or_unowned_go_event_reject(self):
        for action in ('skip', 'fail', 'pause'):
            self.reject(lambda r, s, a=action: r.__setitem__('unknown.json', r['unknown.json'].replace(b'"Action":"run"', ('"Action":"'+a+'"').encode(), 1)))
        self.reject(lambda r, s: r.__setitem__('unknown.json', r['unknown.json'] + r['unknown.json'].splitlines()[-1] + b'\n'))

    def test_go_private_output_and_wrong_package_order_reject(self):
        def output(r, s):
            rows=[json.loads(x) for x in r['unknown.json'].splitlines()];row=dict(rows[1]);row.update(Action='output',Output='MODEL_PRIVATE_LOG\n');rows.insert(2,row);r['unknown.json']=b''.join(wire(x) for x in rows)
        self.reject(output)
        def order(r, s):
            rows=[json.loads(x) for x in r['unknown.json'].splitlines()];r['unknown.json']=b''.join(wire(x) for x in rows if x['Package']==U.PACKAGE)+b''.join(wire(x) for x in rows if x['Package']==U.MODEL_PACKAGE)
        self.reject(order)

    def test_fault_must_be_actual_claimed_injection_not_passthrough_or_failed(self):
        for key, value in [('state','PASSTHROUGH'),('state','FAILED'),('claimed',False),('injected',False),('failureCode','CLOSE_REJECTED')]:
            self.report_reject(lambda r, k=key, v=value: r['fault'].__setitem__(k,v))

    def test_fault_exact_one_original_204_and_zero_body(self):
        for key, values in [('underlyingRoundTrips',(0,2,1.0,True)),('statusCode',(None,200,204.0)),('bodyBytes',(None,1,False,0.0))]:
            for value in values: self.report_reject(lambda r, k=key, v=value:r['fault'].__setitem__(k,v))

    def test_fault_natural_eof_and_successful_close_not_inferred(self):
        for key in ('eofObserved','closeSucceeded'):
            for value in (False,None,1):self.report_reject(lambda r,k=key,v=value:r['fault'].__setitem__(k,v))

    def test_harness_204_cannot_replace_original_unknown_adapter_result(self):
        self.response_reject(7, lambda e: e['result']['transport']['result'].__setitem__('statusCode',204))
        self.response_reject(7, lambda e: e['result']['transport']['result'].__setitem__('state','acknowledged'))
        self.report_reject(lambda r:r['after']['activeTransport']['result'].__setitem__('statusCode',204))

    def test_unknown_transport_origin_dispatched_and_null_gate_are_strict(self):
        for key,value in [('origin','SERVICE_GATE'),('gateReason','MODEL')]:self.response_reject(7,lambda e,k=key,v=value:e['result']['transport'].__setitem__(k,v))
        for value in (False,1):self.response_reject(7,lambda e,v=value:e['result']['transport']['result'].__setitem__('dispatched',v))

    def test_unknown_result_numeric_aliases_reject(self):
        for value in (False,0.0):self.response_reject(7,lambda e,v=value:e['result']['transport']['result'].__setitem__('statusCode',v))

    def test_http_exact_14_roles_methods_paths_and_auth_denials(self):
        self.report_reject(lambda r:r['http'].pop())
        for index,key,value in [(0,'role','admin'),(3,'role','admin'),(6,'role','admin'),(7,'method','GET'),(9,'path','/MODEL')]:
            self.report_reject(lambda r,i=index,k=key,v=value:r['http'][i].__setitem__(k,v))
        for index in (0,2,3,5):self.report_reject(lambda r,i=index:r['http'][i].__setitem__('statusCode',200))

    def test_actual_requests_require_strict_cas_and_independent_approval(self):
        for revision in (4.0,True,3):
            def change(r, v=revision): r['http'][6]['requestBody']=b64(json.dumps(dict(planSHA256=PLAN,revision=v),separators=(',',':')).encode())
            self.report_reject(change)
        self.response_reject(6,lambda e:e['result'].__setitem__('revision',4))

    def test_create_after_unknown_reuses_candidate_not_vacuous_oldbase(self):
        def change(r):
            v=json.loads(base64.b64decode(r['http'][12]['requestBody']));v['candidateRecordSHA256']=r['before']['head']['artifactRecordSHA256'];r['http'][12]['requestBody']=b64(U.go_bytes(v))
        self.report_reject(change)

    def test_blocked_create_requires_conflict_not_unready503_or_changed_state(self):
        self.report_reject(lambda r:r['http'][12].__setitem__('statusCode',503))
        self.response_reject(12,lambda e:e.__setitem__('stateMayHaveChanged',True))
        self.response_reject(12,lambda e:e.__setitem__('result',{}))

    def test_request_or_response_base64_and_duplicate_json_reject(self):
        self.report_reject(lambda r:r['http'][0].__setitem__('responseBody',r['http'][0]['responseBody']+'\n'))
        self.reject(lambda r,s:r.__setitem__('unknown-report.json',r['unknown-report.json'].replace(b'"outcome":',b'"outcome":"PASS","outcome":',1)))

    def test_head_generation_cannot_advance_even_when_candidate_is_observed(self):
        self.response_reject(7,lambda e:e['result'].__setitem__('headGeneration',2))
        self.report_reject(lambda r:r['after']['state']['head'].__setitem__('generation',2))
        self.report_reject(lambda r:r['after']['state']['head'].__setitem__('verificationSHA256',r['after']['lastObservation']['evidenceSHA256']))

    def test_unknown_barrier_and_no_head_advance_are_required(self):
        self.response_reject(7,lambda e:e['result'].__setitem__('writeBlocked',False))
        self.response_reject(7,lambda e:e['result'].__setitem__('headAdvanced',True))
        self.report_reject(lambda r:r['after']['state']['head'].__setitem__('writeBlocked',False))

    def test_blocked_candidates_cannot_claim_either_current_artifact(self):
        for i in (0,1):self.response_reject(10,lambda e,i=i:e['result']['candidates'][i].__setitem__('isCurrent',True))
        self.response_reject(10,lambda e:e['result'].__setitem__('writeBlocked',False))

    def test_old_unknown_wal_and_missing_or_invented_observation_reject(self):
        self.report_reject(lambda r:r['after'].__setitem__('state',copy.deepcopy(r['before'])))
        self.report_reject(lambda r:r['after'].__setitem__('lastObservation',None))
        self.report_reject(lambda r:r['after']['state'].__setitem__('unknownObservationCount',0))
        self.report_reject(lambda r:r['after'].__setitem__('activeAttempt',2))

    def test_durable_unknown_cannot_be_completed_or_lose_original_result(self):
        self.report_reject(lambda r:r['after']['state'].__setitem__('activePhase','ACKNOWLEDGED_SUPPORTED_POSTCONDITION'))
        self.report_reject(lambda r:r['after'].__setitem__('activeTransport',None))
        self.report_reject(lambda r:r['after']['state']['completed'].append({}))

    def test_durable_observation_must_bind_original_intent_revision_and_receipt(self):
        for key,value in [('intentSHA256','d'*64),('evidenceSHA256','e'*64),('conclusion','STABLE_NEW_PROJECTION'),('commitRevision',8),('commitRevision',9.0)]:
            self.report_reject(lambda r,k=key,v=value:r['after']['lastObservation'].__setitem__(k,v))

    def test_replay_requires_exact_original_request_and_only_replayed_flag(self):
        self.response_reject(11,lambda e:e['result'].__setitem__('replayed',False))
        self.response_reject(8,lambda e:e['result'].__setitem__('replayed',True))
        self.report_reject(lambda r:r['http'][11].__setitem__('requestBody',b64(U.go_bytes(dict(planSHA256=PLAN,revision=6)))))

    def test_replay_and_denied_create_keep_actual_control_hash_unchanged(self):
        for phase in ('replay','final'):
            for key in ('controlSHA256','recordSHA256'):
                self.report_reject(lambda r,p=phase,k=key:r[p]['state'].__setitem__(k,'e'*64))

    def test_reload_and_do_counters_exact_zero_one_one_one(self):
        for phase,key,value in [('callsBefore','doInvocations',1),('callsAfter','reloadInvocations',0),('callsReplay','doInvocations',2),('callsFinal','doInvocations',2)]:
            self.report_reject(lambda r,p=phase,k=key,v=value:r[p].__setitem__(k,v))

    def test_counter_bool_float_and_controller_received_fiction_reject(self):
        for value in (True,1.0):self.report_reject(lambda r,v=value:r['callsAfter'].__setitem__('doInvocations',v))
        self.report_reject(lambda r:r.__setitem__('controllerReceivedCount',1))

    def test_capture_last_phase_is_unknown_not_ack_completion(self):
        def change(r,s):
            p=U.S.STAGES[-1]+'-verification.json';v=json.loads(r[p]);v['Observation']['Phase']='ACKNOWLEDGED_COMPLETION';r[p]=U.go_bytes(v)
        self.reject(change)

    def test_raw_32_bodies_and_capture_transcripts_mandatory(self):
        self.reject(lambda r,s:r.__setitem__('bootstrap-body-1.json',b''))
        self.reject(lambda r,s:r.__setitem__('op-01-post-dispatch-body-3.json',b'{}'))
        def change(r,s):
            p='bootstrap-transcript.json';v=json.loads(r[p]);v['records'][0]['naturalEOF']=False;r[p]=Prior.Prior.CapturedModels.wire(v)
            cap=json.loads(r['bootstrap-verification.json']);cap['Transcript']=hashed(r[p]);r['bootstrap-verification.json']=U.go_bytes(cap)
        self.reject(change)

    def test_coherently_rehashed_capture_semantic_drift_still_rejects_directly(self):
        raw,sources=fixture();stage='bootstrap';transcript=json.loads(raw[stage+'-transcript.json']);receipt=json.loads(raw[stage+'-verification.json'])
        for ordinal in (2,6):
            p=stage+f'-body-{ordinal}.json';body=json.loads(raw[p]);body['mixed-port']=28412;raw[p]=Prior.Prior.CapturedModels.wire(body)
            row=transcript['records'][ordinal-1];row['retainedBytes']=row['contentLength']=len(raw[p]);row['retainedSHA256']=hashed(raw[p]);receipt['Bodies'][ordinal-1]=hashed(raw[p])
        transcript['retainedBytes']=sum(r['retainedBytes'] for r in transcript['records']);raw[stage+'-transcript.json']=Prior.Prior.CapturedModels.wire(transcript)
        receipt['Transcript']=hashed(raw[stage+'-transcript.json']);raw[stage+'-verification.json']=U.go_bytes(receipt)
        elf=json.loads(raw['consumption.json'])['elf'];ns=int(json.loads(raw['sandbox.json'])['networkNamespace'][5:-1])
        with self.assertRaises(ValueError):U.capture(raw,stage,0,COMMIT,elf,ns)
        with self.assertRaises(ValueError):U.verify_raw(raw,sources,COMMIT)

    def test_observation_hash_binds_new_raw_without_advancing_old_head(self):
        self.response_reject(7,lambda e:e['result']['observation'].__setitem__('observedProjectionSHA256','e'*64))
        self.report_reject(lambda r:r['after']['state']['head'].__setitem__('headSHA256','e'*64))

    def test_owned_epoch_source_namespace_and_startup_artifact_are_fixed(self):
        for key,value in [('sourceCommit','2'*40),('netNSInode',999),('artifactSHA256','e'*64)]:
            def change(r,s,k=key,v=value):
                p=U.S.STAGES[-1]+'-verification.json';x=json.loads(r[p]);x['Observation']['StartupIdentity'][k]=v;r[p]=U.go_bytes(x)
            self.reject(change)

    def test_local_routes_require_three_hashes_and_actual_counter_chain(self):
        def change(r,s):
            p='op-01-post-dispatch-verification.json';v=json.loads(r[p]);v['Route']['originResponse']['sha256']='e'*64;r[p]=U.go_bytes(v)
        self.reject(change)
        def reset(r,s):
            p='op-01-create-verification.json';v=json.loads(r[p]);v['Route']['countersBefore']=Prior.Prior.model_counters();r[p]=U.go_bytes(v)
        self.reject(reset)

    def test_syntax_input_and_bounded_actual_streams_must_match(self):
        self.reject(lambda r,s:r.__setitem__('op-01-syntax.stderr',b'MODEL private cause'))
        def change(r,s):v=json.loads(r['op-01-syntax.json']);v['inputBytes']+=1;r['op-01-syntax.json']=wire(v)
        self.reject(change)

    def test_journal_one_send_unknown_return_and_observation_not_completion(self):
        self.reject(lambda r,s:r.__setitem__('service-journal.jsonl',r['service-journal.jsonl'].replace(b'"OBSERVATION_RECORDED"',b'"COMPLETED"',1)))
        self.reject(lambda r,s:r.__setitem__('service-journal.jsonl',r['service-journal.jsonl'].replace(b'"RELOAD_CALL_INTENT"',b'"PREPARED"',1)))
        def result(r,s):
            rows=[json.loads(x) for x in r['service-journal.jsonl'].splitlines()];rows[7]['result']['statusCode']=204;r['service-journal.jsonl']=b''.join(wire(x) for x in rows)
        self.reject(result)

    def test_cleanup_real_wait_signal_stream_and_fixture_order_are_required(self):
        for key,value in [('waitReturned',False),('termSent',False),('groupAbsent',1)]:
            def change(r,s,k=key,v=value):
                rows=[json.loads(x) for x in r['service-journal.jsonl'].splitlines()];rows[-2]['kernel'][k]=v;r['service-journal.jsonl']=b''.join(wire(x) for x in rows)
            self.reject(change)
        def order(r,s):
            rows=[json.loads(x) for x in r['service-journal.jsonl'].splitlines()];rows[-2]['fixtures'].reverse();r['service-journal.jsonl']=b''.join(wire(x) for x in rows)
        self.reject(order)

    def test_closed_ports_require_actual_refused_probes(self):
        self.report_reject(lambda r:r['closedPorts'][0].__setitem__('errorClass','TIMEOUT'))
        self.report_reject(lambda r:r['closedPorts'][0].__setitem__('connectAttempted',1))

    def test_namespace_custody_and_module_binding_are_not_self_report_only(self):
        def namespace(r,s):v=json.loads(r['sandbox.json']);v['networkNamespace']='net:[1]';r['sandbox.json']=wire(v)
        self.reject(namespace)
        for side in ('before','after'):
            def alias(r,s,side=side):v=json.loads(r['sandbox.json']);v['inputCustody'][side]['elf']['bytes']=float(v['inputCustody'][side]['elf']['bytes']);r['sandbox.json']=wire(v)
            self.reject(alias)
        self.reject(lambda r,s:s.__setitem__('chengwang/go.mod',b'MODEL another module'))

    def test_consumption_copy_pin_and_signature_claim_cannot_change(self):
        self.reject(lambda r,s:r.__setitem__('consumption-independent.json',b'{}'))
        def pin(r,s):v=json.loads(r['consumption.json']);v['publisherSignatureProven']=True;r['consumption.json']=r['consumption-independent.json']=wire(v)
        self.reject(pin)

    def test_privacy_internet_production_and_unknown_report_fields_cannot_escalate(self):
        self.report_reject(lambda r:r.__setitem__('production',True))
        self.report_reject(lambda r:r['after']['state'].__setitem__('fullPrivateWALIndependentlyProven',True))
        self.report_reject(lambda r:r.__setitem__('internetBusinessProven',True))
        self.report_reject(lambda r:r.__setitem__('dropped',{}))
        self.report_reject(lambda r:r.__setitem__('outcome','FAIL'))


if __name__ == '__main__':
    unittest.main()
