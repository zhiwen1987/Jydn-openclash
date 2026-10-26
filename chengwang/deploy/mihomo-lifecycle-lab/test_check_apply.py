"""SYNTHETIC evidence protocol models; no worker, Go, kernel or service runs.

The invented commit/PIDs/namespaces/body hashes below are not actual custody,
authentication, execution or packet evidence. Only the CLI can bind actual Git
and on-disk originals. Tests import the independent checker, never a producer.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest

import check_apply as C
import test_check_compat as Legacy
import test_get_projection as CapturedModels


COMMIT = '1' * 40
PREFIX = 'chengwang/deploy/mihomo-lifecycle-lab/'
TOP = 'TestMihomoApplyReloadReadbackAndLocalProxy'
PACKAGE = 'chengwang/internal/mihomodeploy'


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def hashed(raw):
    return hashlib.sha256(raw).hexdigest()


def model_binding(raw):
    return dict(sha256=hashed(raw), bytes=len(raw))


def model_stream(raw, complete=True):
    return dict(bytes=len(raw), totalBytes=len(raw), sha256=hashed(raw),
                truncated=False, complete=complete)


def model_body(raw):
    return dict(**model_binding(raw), complete=True)


def model_observation(pid, ticks, stdout=b'', stderr=b'', running=False):
    return dict(attempted=True, started=True, pid=pid, startTicks=ticks,
                waitReturned=not running, waitErrorClass='NOT_WAITED' if running else 'NONE',
                exitCode=None if running else 0, signal=None,
                termSent=False, killSent=False, groupAbsent=None if running else True,
                stdout=model_stream(stdout, not running), stderr=model_stream(stderr, not running))


def model_counters(a=0, b=0, origin=0):
    def row(role, count, received):
        return dict(role=role, connectIngress=count, tunnelRequests=count,
                    forwardInvocations=count, originRequests=received, rejected=0)
    return [row('A', a, a), row('B', b, b), row('origin', 0, origin)]


def model_time(seq):
    return '2026-10-25T00:00:00.' + str(seq).zfill(9) + 'Z'


def model_go_events(events):
    result = []
    for index, event in enumerate(events, 1):
        event = copy.deepcopy(event)
        event['Time'] = model_time(index)
        result.append(wire(event))
    return b''.join(result)


def model_journal(report, syntax, receipt_hash, c):
    """Source-derived event placement from runtime_apply_linux_test.go.

    This reconstructs only an invented fixture; no production fact is inferred.
    BEGIN entries remain distinct from the subsequent observed results.
    """
    rows = []
    running = copy.deepcopy(report['kernelObservation'])
    if type(running) is dict:
        running.update(waitReturned=False, waitErrorClass='NOT_WAITED', exitCode=None,
                       signal=None, termSent=False, killSent=False, groupAbsent=None,
                       stdout=model_stream(b'', False), stderr=model_stream(b'', False))
    def event(stage, **facts):
        fields = {name: None for name in c['journalFactKeys']}
        fields.update(copy.deepcopy(facts))
        seq = len(rows) + 1
        rows.append(dict(schema=c['journalSchema'], seq=seq, stage=stage,
                         observedAtUTC=model_time(seq), facts=fields))
    event('INPUT_OPENED', receiptSHA256=receipt_hash)
    event('ARTIFACTS_BOUND', baseInput=report['baseInput'], candidateInput=report['candidateInput'])
    event('FIXTURES_LISTENING')
    event('KERNEL_START_BEGIN', baseInput=report['baseInput'])
    event('KERNEL_START_RESULT', kernelObservation=running)
    for probe in report['readiness']:
        event('READINESS_PROBE', readinessProbe=probe)
    event('BASELINE_READ_BEGIN', ownedIdentity=report['ownedBefore'])
    event('BASELINE_READ_RESULT', readback=report['readbacks']['baseline'], getEvidence=report['getEvidence']['baseline'])
    event('BASELINE_ROUTE_RESULT', route=report['routes'][0])
    event('SYNTAX_BEGIN', candidateInput=report['candidateInput'])
    event('SYNTAX_RESULT', candidateInput=report['candidateInput'], kernelObservation=syntax['observation'])
    event('RELOAD_BEGIN', reloadPayload=report['candidateInput'])
    event('RELOAD_RESULT', reloadPayload=report['reloadPayload'], reloadResult=report['reloadResult'],
          clientReloadInvocations=report['clientReloadInvocations'])
    event('CANDIDATE_READ_BEGIN')
    event('CANDIDATE_READ_RESULT', readback=report['readbacks']['candidate'], getEvidence=report['getEvidence']['candidate'])
    event('CANDIDATE_ROUTE_RESULT', route=report['routes'][1])
    event('OWNED_FINAL_RESULT', ownedIdentity=report['ownedAfter'])
    event('KERNEL_STOP_RESULT', kernelObservation=report['kernelObservation'])
    event('FIXTURE_STOP_RESULT', fixtureCleanup=report['fixtureCleanup'])
    event('FINAL_RESULT', code=report['failureCode'])
    return b''.join(wire(row) for row in rows)


def refresh(raw, report=None, syntax=None):
    """Keep surrounding checks coherent to exercise the intended semantic gate."""
    c = json.loads((Path(__file__).parent / 'apply_contract.json').read_bytes())
    if report is None:
        report = json.loads(raw['apply-report.json'])
    if syntax is None:
        syntax = json.loads(raw['syntax.exec.json'])
    raw['syntax.exec.json'] = wire(syntax)
    report['syntaxSHA256'] = hashed(raw['syntax.exec.json'])
    raw['apply-report.json'] = wire(report)
    raw['apply-observations.jsonl'] = model_journal(report, syntax, hashed(raw['consumption.json']), c)


def fixture():
    """Complete36 SYNTHETIC public originals, not a real Git/kernel run."""
    legacy, sources = Legacy.fixture()
    sources = {name: sources.get(name, b'SYNTHETIC_SOURCE_NOT_ACTUAL_GIT_OR_EXECUTION\n') for name in C.FILES}
    c = json.loads((Path(__file__).parent / 'apply_contract.json').read_bytes())
    sources[PREFIX + 'apply_contract.json'] = (Path(__file__).parent / 'apply_contract.json').read_bytes()
    sources['chengwang/internal/mihomodeploy/runtime_apply_linux_test.go'] = (
        Path(__file__).parents[2] / 'internal/mihomodeploy/runtime_apply_linux_test.go').read_bytes()
    raw = {name: b'' for name in C.PUBLIC}
    for name in ('consumption.json', 'consumption-independent.json', 'host-before.json', 'host-after.json', 'go-version.txt'):
        raw[name] = legacy[name]
    sandbox = json.loads(legacy['sandbox.json'])
    sandbox.update(schema=c['sandboxSchema'], environmentKeys=c['environmentKeys'])
    raw['sandbox.json'] = wire(sandbox)
    raw['execution.json'] = wire(dict(schema=c['executionSchema'], sourceCommit=COMMIT,
        formatExit=0, goExit=0, realMihomoExecutionObserved=True, production=False))
    raw['apply.json'] = model_go_events([dict(Action='start', Package=PACKAGE),
        dict(Action='run', Package=PACKAGE, Test=TOP), dict(Action='pass', Package=PACKAGE, Test=TOP),
        dict(Action='pass', Package=PACKAGE)])
    # MODEL private inputs are represented solely by digests; no actual secret
    # or YAML is asserted to have been opened by this fixture.
    base = model_binding(b'SYNTHETIC_BASE_COMPLETE_CONFIG_NOT_ACTUAL_STDIN')
    candidate = model_binding(b'SYNTHETIC_CANDIDATE_COMPLETE_CONFIG_NOT_ACTUAL_PUT')
    elf = json.loads(raw['consumption.json'])['elf']
    identity = dict(pid=501, startTicks=12345, netNSInode=int(sandbox['networkNamespace'][5:-1]), elfSHA256=elf['sha256'],
        elfBytes=elf['bytes'], sourceCommit=COMMIT, artifactSHA256=base['sha256'],
        controllerPort=28412, mixedPort=28411)
    kernel = model_observation(identity['pid'], identity['startTicks'])
    kernel['termSent'] = True
    # Reuse the previously source-checked fixed syntax grammar as MODEL raw
    # bytes; this is not a new actual stdout sample or kernel execution.
    raw['syntax.stdout'] = legacy['candidate.stdout']
    syntax = dict(schema=c['syntaxSchema'], sourceCommit=COMMIT,
        binary=dict(sha256=elf['sha256'], bytes=elf['bytes']), receiptSHA256=hashed(raw['consumption.json']),
        input=candidate, argvClass='STDIN_TEST',
        observation=model_observation(502, None, raw['syntax.stdout']))
    prev, new = hashed(b'SYNTHETIC_OLD_HTTP_PROJECTION'), hashed(b'SYNTHETIC_NEW_HTTP_PROJECTION')
    def readback(conclusion, observed):
        return dict(conclusion=conclusion, sampleCount=2, requestsObserved=8,
            previousProjectionSHA256=prev, candidateProjectionSHA256=new, observedProjectionSHA256=observed,
            dataplaneProven=False, fullPayloadProven=False, authorizationProven=False, production=False)
    readiness = [dict(role='VALID', statusCode=200, body=model_body(b'{"version":"v1.19.32","meta":true}'), errorClass='NONE')]
    readiness.extend(dict(role=role, statusCode=401, body=model_body(b'{"message":"Unauthorized"}'), errorClass='NONE') for role in ('NONE', 'WRONG'))
    routes = []
    for phase, role, before, after in [('BASELINE_A', 'A', model_counters(), model_counters(1, 0, 1)),
                                      ('CANDIDATE_B', 'B', model_counters(1, 0, 1), model_counters(1, 1, 2))]:
        nonce = hashed(('SYNTHETIC_NONCE_' + role).encode('ascii'))
        body = model_body(('chengwang-local-apply-marker/v1:' + role + ':' + nonce + '\n').encode('ascii'))
        routes.append(dict(phase=phase, nonceSHA256=hashed(nonce.encode('ascii')), clientResponse=copy.deepcopy(body),
            proxyResponse=copy.deepcopy(body), originResponse=copy.deepcopy(body), countersBefore=before,
            countersAfter=after, matched=True))
    cleanup = [dict(role=role, shutdownReturned=True, serveReturned=True,
                    forcedConnectionsClosed=0, errorClass='NONE') for role in ('origin', 'A', 'B')]
    report = dict(schema=c['reportSchema'], scope=c['scope'], sourceCommit=COMMIT, outcome='PASS', failureCode=None,
        baseInput=base, candidateInput=candidate, syntaxSHA256=None, kernelObservation=kernel,
        ownedBefore=identity, ownedAfter=copy.deepcopy(identity),
        readbacks=dict(baseline=readback('STABLE_OLD_PROJECTION', prev), candidate=readback('STABLE_NEW_PROJECTION', new)),
        readiness=readiness, clientReloadInvocations=1, controllerReceivedCount=None,
        reloadPayload=candidate, reloadResult=dict(state='acknowledged', dispatched=True, statusCode=204),
        reloadErrorClass='NONE', routes=routes, fixtureCleanup=cleanup, flags=copy.deepcopy(c['flags']))
    captured_raw, captured_report = CapturedModels.fixture()
    raw.update(captured_raw)
    report['readbacks'] = captured_report['readbacks']
    report['getEvidence'] = captured_report['getEvidence']
    refresh(raw, report, syntax)
    return raw, sources


class SyntheticApplyEvidenceModels(unittest.TestCase):
    def reject(self, raw, sources):
        with self.assertRaises(ValueError):
            C.verify_raw(raw, sources, COMMIT)

    def reject_report(self, change):
        raw, sources = fixture(); report = json.loads(raw['apply-report.json']); change(report)
        refresh(raw, report)
        self.reject(raw, sources)

    def reject_json(self, name, change):
        raw, sources = fixture(); value = json.loads(raw[name]); change(value); raw[name] = wire(value)
        self.reject(raw, sources)

    def reject_syntax(self, change):
        raw, sources = fixture(); value = json.loads(raw['syntax.exec.json']); change(value)
        refresh(raw, syntax=value)
        self.reject(raw, sources)

    def test_synthetic_complete18_model_is_not_actual_kernel_or_authorization(self):
        # Preserve the historical test ID while checking the version2 set.
        raw, sources = fixture(); report = C.verify_raw(raw, sources, COMMIT)
        self.assertEqual(len(raw), 36); self.assertEqual(len(sources), 194)
        self.assertEqual(report['schema'], 'chengwang.mihomo-runtime-apply-verification/v2')
        self.assertEqual(report['scope'], 'ACTUAL_LOCAL_APPLY_EXPERIMENT_NOT_FULL_PROJECT')
        self.assertIs(report['production'], False)
        self.assertIs(report['independentProjectionRecomputeProven'], True)
        self.assertIs(report['expectedSourceIndependentlyProven'], False)
        self.assertIs(report['privateDisclosureFenceIndependentlyProven'], False)

    def test_missing_extra_or_nonbytes_source_rejects(self):
        for kind in ('missing', 'extra', 'nonbytes', 'empty', 'changed_module'):
            raw, sources = fixture()
            if kind == 'missing': del sources[next(iter(sources))]
            elif kind == 'extra': sources['unexpected'] = b'SYNTHETIC'
            elif kind == 'nonbytes': sources['chengwang/go.mod'] = 'SYNTHETIC'
            elif kind == 'empty': sources['chengwang/go.mod'] = b''
            else: sources['chengwang/go.mod'] += b'changed\n'
            self.reject(raw, sources)

    def test_source_contract_or_actual_tagged_top_declaration_rejects(self):
        for kind in ('schema', 'production', 'tag', 'top'):
            raw, sources = fixture()
            if kind in ('schema', 'production'):
                value=json.loads(sources[PREFIX+'apply_contract.json']);value[kind]='wrong' if kind=='schema' else True
                sources[PREFIX+'apply_contract.json']=wire(value)
            else:
                key='chengwang/internal/mihomodeploy/runtime_apply_linux_test.go'
                sources[key]=sources[key].replace(b'chengwang_mihomo_apply',b'wrong_apply') if kind=='tag' else sources[key].replace(TOP.encode(),b'TestWrongApply')
            self.reject(raw,sources)

    def test_public_missing_extra_private_and_failure_summary_reject(self):
        # Valid-JSON whitespace still changes the actual captured original.
        # Keep its report/journal unchanged to catch a missing verifier call.
        raw,sources=fixture()
        raw['baseline-get-01.body'] += b' '
        self.reject(raw,sources)
        for kind in ('missing','extra','private','summary'):
            raw,sources=fixture()
            if kind=='missing':del raw['kernel.stderr']
            elif kind=='extra':raw['extra.txt']=b'SYNTHETIC'
            elif kind=='private':raw['base.config.private.yaml']=b'SYNTHETIC_PRIVATE'
            else:raw['worker-failure.json']=wire(dict(schema='chengwang.mihomo-apply-worker-failure/v1',sourceCommit=COMMIT,failureCode='WORKER_REJECTED_RAW_OUTPUT_SUPPRESSED',rawOutputSuppressed=True))
            self.reject(raw,sources)

    def test_wrong_project_commit_cannot_be_substituted(self):
        raw,sources=fixture()
        with self.assertRaises(ValueError):C.verify_raw(raw,sources,'2'*40)
        self.reject_report(lambda d:d.__setitem__('sourceCommit','2'*40))

    def test_duplicate_keys_invalid_utf8_nan_or_trailing_json_reject(self):
        for data in (b'{"schema":1,"schema":2}',b'\xff',b'{"x":NaN}',b'{} {}'):
            raw,sources=fixture();raw['apply-report.json']=data;self.reject(raw,sources)

    def test_exact_key_case_alias_unknown_or_missing_report_field_rejects(self):
        for mode in ('alias','unknown','missing'):
            raw,sources=fixture();value=json.loads(raw['apply-report.json'])
            if mode=='alias':value['SourceCommit']=value.pop('sourceCommit')
            elif mode=='unknown':value['authorizationToken']='SYNTHETIC_FORBIDDEN'
            else:del value['controllerReceivedCount']
            raw['apply-report.json']=wire(value);self.reject(raw,sources)

    def test_all_false_scope_flags_are_strict_booleans(self):
        raw,_=fixture();keys=json.loads(raw['apply-report.json'])['flags']
        for key in keys:
            wrong_bool = False if key == 'perGetRawEvidenceAvailable' else True
            for value in (wrong_bool,0,1,None,'false'):
                self.reject_report(lambda d,k=key,v=value:d['flags'].__setitem__(k,v))

    def test_fail_outcome_or_failure_code_cannot_be_accepted(self):
        self.reject_report(lambda d:d.update(outcome='FAIL',failureCode='BASELINE_READBACK'))
        self.reject_report(lambda d:d.__setitem__('failureCode','FIXTURE_STOP'))

    def test_fixed_safe_failure_summary_cannot_replace_original_stderr(self):
        raw,sources=fixture();raw['apply.stderr']=b'MIHOMO_APPLY_WORKER_REJECTED raw_output_suppressed=true\n';self.reject(raw,sources)

    def test_execution_metadata_requires_actual_observed_start_and_zero_exits(self):
        for key,value in [('formatExit',1),('goExit',1),('goExit',False),('realMihomoExecutionObserved',False),('realMihomoExecutionObserved',None),('production',True)]:
            self.reject_json('execution.json',lambda d,k=key,v=value:d.__setitem__(k,v))

    def test_go_version_formatter_and_go_stderr_reject(self):
        for filename,data in [('go-version.txt',b'go version go1.24.0 linux/amd64\n'),('gofmt.patch',b'not formatted\n'),('gofmt.stderr',b'formatter failed\n'),('apply.stderr',b'build failed\n')]:
            raw,sources=fixture();raw[filename]=data;self.reject(raw,sources)

    def test_original_and_independent_receipts_must_be_byte_equal(self):
        raw,sources=fixture();raw['consumption-independent.json']+=b' ';self.reject(raw,sources)

    def test_receipt_cannot_claim_execution_signature_or_production_approval(self):
        for key in ('runtimeExecuted','runtimeCompatibilityProven','businessAvailabilityProven','publisherSignatureProven','productionApproved','production'):
            raw,sources=fixture();value=json.loads(raw['consumption.json']);value[key]=True
            raw['consumption.json']=raw['consumption-independent.json']=wire(value);self.reject(raw,sources)

    def test_published_asset_or_consumption_source_digest_rejects(self):
        for kind in ('asset','source'):
            raw,sources=fixture();value=json.loads(raw['consumption.json'])
            if kind=='asset':value['archive']['sha256']='c'*64
            else:value['source']['sourceFiles'][0]['sha256']='c'*64
            raw['consumption.json']=raw['consumption-independent.json']=wire(value);self.reject(raw,sources)

    def test_sandbox_uid_caps_nnp_and_readonly_guards_reject(self):
        for key,value in [('uid',0),('gid',0),('uid',True),('effectiveCaps','0000000000000001'),('noNewPrivileges',False),('sourceReadOnly',False),('goReadOnly',False)]:
            self.reject_json('sandbox.json',lambda d,k=key,v=value:d.__setitem__(k,v))

    def test_namespace_reuse_host_change_and_egress_routes_reject(self):
        self.reject_json('host-after.json',lambda d:d.__setitem__('resolvSHA256','c'*64))
        for key,value in [('networkNamespace','net:[1]'),('interfaceNames',['lo','eth0']),('defaultV4Routes',['default']),('defaultV6Routes',['::/0'])]:
            self.reject_json('sandbox.json',lambda d,k=key,v=value:d.__setitem__(k,v))

    def test_scrubbed_environment_rejects_missing_extra_or_proxy(self):
        for change in (lambda a:a.append('HTTP_PROXY'),lambda a:a.remove('TMPDIR'),lambda a:a.reverse()):
            self.reject_json('sandbox.json',lambda d:change(d['environmentKeys']))

    def test_original_custody_owner_mode_bytes_and_types_are_checked(self):
        for key,value in [('mode','0700'),('sha256','c'*64),('bytes',True),('uid',True),('gid',0.0)]:
            self.reject_json('sandbox.json',lambda d,k=key,v=value:d['inputCustody']['after']['elf'].__setitem__(k,v))

    def test_kernel_copy_must_match_receipt_and_be_readonly_executable(self):
        for key,value in [('sha256','c'*64),('bytes',1),('mode','0700'),('readOnly',False),('executable',False),('readOnly',1)]:
            self.reject_json('sandbox.json',lambda d,k=key,v=value:d['kernelCopy'].__setitem__(k,v))

    def test_owned_epoch_identity_must_survive_reload_unchanged(self):
        for key,value in [('pid',999),('startTicks',999),('netNSInode',999),('elfSHA256','c'*64),('sourceCommit','2'*40),('controllerPort',28413),('mixedPort',28414)]:
            self.reject_report(lambda d,k=key,v=value:d['ownedAfter'].__setitem__(k,v))
        def coherent_other_namespace(d):
            # Both identities and every journal use agree, but sandbox says
            # net:[4]. This must fail the actual cross-evidence namespace gate,
            # not merely before/after or journal equality.
            d['ownedBefore']['netNSInode']=999
            d['ownedAfter']=copy.deepcopy(d['ownedBefore'])
        self.reject_report(coherent_other_namespace)

    def test_owned_input_artifact_is_base_not_candidate_or_claimed_full_payload(self):
        def candidate_identity(d):
            d['ownedBefore']['artifactSHA256']=d['candidateInput']['sha256'];d['ownedAfter']=copy.deepcopy(d['ownedBefore'])
        self.reject_report(candidate_identity)
        self.reject_report(lambda d:d.__setitem__('baseInput',copy.deepcopy(d['candidateInput'])))

    def test_owned_identity_rejects_zero_null_bool_and_unknown_keys(self):
        for key,value in [('pid',0),('pid',True),('startTicks',0),('startTicks',None),('netNSInode',False),('elfBytes',1.0)]:
            def change(d,k=key,v=value):
                d['ownedBefore'][k]=v;d['ownedAfter']=copy.deepcopy(d['ownedBefore'])
            self.reject_report(change)
        self.reject_report(lambda d:d['ownedBefore'].__setitem__('endpoint','http://127.0.0.1:28412'))

    def test_kernel_start_pid_ticks_and_attempt_are_real_required_observations(self):
        for key,value in [('attempted',False),('started',None),('started',False),('pid',None),('pid',502),('startTicks',0)]:
            self.reject_report(lambda d,k=key,v=value:d['kernelObservation'].__setitem__(k,v))

    def test_kernel_terminal_wait_signal_and_group_absence_are_not_inferred(self):
        for key,value in [('waitReturned',False),('waitErrorClass','WAIT_ERROR'),('exitCode',1),('groupAbsent',None),('groupAbsent',False),('signal',9),('killSent',None)]:
            self.reject_report(lambda d,k=key,v=value:d['kernelObservation'].__setitem__(k,v))

    def test_syntax_binds_candidate_receipt_binary_and_commit(self):
        raw,_=fixture();report=json.loads(raw['apply-report.json'])
        for key,value in [('input',report['baseInput']),('receiptSHA256','c'*64),('sourceCommit','2'*40),('argvClass','VERSION'),('binary',dict(sha256='c'*64,bytes=12345))]:
            self.reject_syntax(lambda d,k=key,v=value:d.__setitem__(k,v))

    def test_short_syntax_pid_may_have_unknown_ticks_without_faking_zero(self):
        raw,sources=fixture();self.assertIs(json.loads(raw['syntax.exec.json'])['observation']['startTicks'],None)
        C.verify_raw(raw,sources,COMMIT)
        self.reject_syntax(lambda d:d['observation'].__setitem__('startTicks',0))

    def test_syntax_requires_distinct_started_pid_and_normal_zero_wait(self):
        for key,value in [('started',False),('pid',501),('pid',None),('waitReturned',False),('exitCode',1),('waitErrorClass','WAIT_ERROR'),('signal',15),('killSent',True),('termSent',True),('groupAbsent',None)]:
            self.reject_syntax(lambda d,k=key,v=value:d['observation'].__setitem__(k,v))

    def test_kernel_original_stream_hash_length_total_complete_and_truncation(self):
        for key,value in [('sha256','c'*64),('bytes',1),('totalBytes',1),('bytes',False),('complete',False),('truncated',True)]:
            self.reject_report(lambda d,k=key,v=value:d['kernelObservation']['stdout'].__setitem__(k,v))
        raw,sources=fixture();raw['kernel.stdout']=b'not the original empty stream\n';self.reject(raw,sources)

    def test_syntax_original_stream_and_record_hash_cannot_be_fabricated(self):
        for key,value in [('sha256','c'*64),('bytes',0),('totalBytes',0),('complete',False),('truncated',True)]:
            self.reject_syntax(lambda d,k=key,v=value:d['observation']['stdout'].__setitem__(k,v))
        raw,sources=fixture();raw['syntax.stdout']+=b'extra';self.reject(raw,sources)
        self.reject_json('apply-report.json',lambda d:d.__setitem__('syntaxSHA256','c'*64))

    def test_go_top_missing_skipped_failed_or_unexpected_subtest_rejects(self):
        for kind in ('missing','skip','fail','subtest'):
            raw,sources=fixture();events=[json.loads(line) for line in raw['apply.json'].splitlines()]
            if kind=='missing':events=[e for e in events if 'Test' not in e]
            elif kind in ('skip','fail'):events[2]['Action']=kind
            else:events.insert(2,dict(Action='pass',Package=PACKAGE,Test=TOP+'/invented'))
            raw['apply.json']=model_go_events(events);self.reject(raw,sources)

    def test_go_event_replay_wrong_package_or_unfinished_test_rejects(self):
        for kind in ('replay','package','unfinished','outoforder'):
            raw,sources=fixture();events=[json.loads(line) for line in raw['apply.json'].splitlines()]
            if kind=='replay':events.insert(3,copy.deepcopy(events[2]))
            elif kind=='package':events[1]['Package']='unexpected/package'
            elif kind=='unfinished':events.pop(2)
            else:events[1],events[2]=events[2],events[1]
            raw['apply.json']=model_go_events(events);self.reject(raw,sources)

    def test_journal_missing_extra_unknown_or_out_of_order_stage_rejects(self):
        for kind in ('missing','extra','unknown','order'):
            raw,sources=fixture();rows=[json.loads(line) for line in raw['apply-observations.jsonl'].splitlines()]
            if kind=='missing':rows.pop(2)
            elif kind=='extra':rows.insert(3,copy.deepcopy(rows[2]))
            elif kind=='unknown':rows[2]['stage']='APPROVED_BY_BODY'
            else:rows[2],rows[3]=rows[3],rows[2]
            for index,row in enumerate(rows,1):row['seq']=index
            raw['apply-observations.jsonl']=b''.join(wire(e) for e in rows);self.reject(raw,sources)

    def test_journal_sequence_zero_replay_alias_or_noninteger_rejects(self):
        for key,value in [('seq',0),('seq',True),('seq',1.0),('schema','wrong')]:
            raw,sources=fixture();rows=[json.loads(line) for line in raw['apply-observations.jsonl'].splitlines()];rows[0][key]=value
            raw['apply-observations.jsonl']=b''.join(wire(e) for e in rows);self.reject(raw,sources)
        raw,sources=fixture();raw['apply-observations.jsonl']+=raw['apply-observations.jsonl'];self.reject(raw,sources)

    def test_journal_facts_bind_receipt_input_readback_reload_and_cleanup(self):
        changes={'INPUT_OPENED':lambda f:f.__setitem__('receiptSHA256','c'*64),
            'ARTIFACTS_BOUND':lambda f:f['baseInput'].__setitem__('sha256','c'*64),
            'BASELINE_READ_RESULT':lambda f:f['readback'].__setitem__('requestsObserved',0),
            'RELOAD_RESULT':lambda f:f.__setitem__('clientReloadInvocations',0),
            'FIXTURE_STOP_RESULT':lambda f:f.__setitem__('fixtureCleanup',[])}
        for stage,change in changes.items():
            raw,sources=fixture();rows=[json.loads(line) for line in raw['apply-observations.jsonl'].splitlines()]
            change(next(row['facts'] for row in rows if row['stage']==stage))
            raw['apply-observations.jsonl']=b''.join(wire(e) for e in rows);self.reject(raw,sources)

    def test_running_observation_cannot_predeclare_wait_or_new_kernel_identity(self):
        for key,value in [('waitReturned',True),('exitCode',0),('groupAbsent',True),('pid',999),('startTicks',999)]:
            raw,sources=fixture();rows=[json.loads(line) for line in raw['apply-observations.jsonl'].splitlines()]
            obs=next(row['facts']['kernelObservation'] for row in rows if row['stage']=='KERNEL_START_RESULT');obs[key]=value
            raw['apply-observations.jsonl']=b''.join(wire(e) for e in rows);self.reject(raw,sources)

    def test_readiness_requires_valid_auth_then_none_and_wrong_401(self):
        for index,key,value in [(0,'statusCode',401),(0,'errorClass','NETWORK'),(1,'statusCode',200),(2,'role','NONE'),(2,'statusCode',True)]:
            self.reject_report(lambda d,i=index,k=key,v=value:d['readiness'][i].__setitem__(k,v))
        self.reject_report(lambda d:d['readiness'].pop())

    def test_readback_null_zero_float_counts_or_incomplete_samples_reject(self):
        self.reject_report(lambda d:d['readbacks'].__setitem__('baseline',None))
        for role in ('baseline','candidate'):
            for key,value in [('sampleCount',0),('sampleCount',2.0),('requestsObserved',0),('requestsObserved',True),('requestsObserved',9)]:
                self.reject_report(lambda d,r=role,k=key,v=value:d['readbacks'][r].__setitem__(k,v))

    def test_readback_old_new_digest_relationships_and_conclusions_reject(self):
        self.reject_report(lambda d:d['readbacks']['candidate'].__setitem__('conclusion','STABLE_OLD_PROJECTION'))
        self.reject_report(lambda d:d['readbacks']['candidate'].__setitem__('observedProjectionSHA256',d['readbacks']['candidate']['previousProjectionSHA256']))
        self.reject_report(lambda d:d['readbacks']['candidate'].__setitem__('candidateProjectionSHA256','c'*64))
        def collapsed(d):
            v=d['readbacks']['baseline']['previousProjectionSHA256']
            for r in d['readbacks'].values():r['candidateProjectionSHA256']=v;r['observedProjectionSHA256']=v
        self.reject_report(collapsed)

    def test_readback_cannot_gain_payload_dataplane_authorization_or_production(self):
        for role in ('baseline','candidate'):
            for key in ('dataplaneProven','fullPayloadProven','authorizationProven','production'):
                self.reject_report(lambda d,r=role,k=key:d['readbacks'][r].__setitem__(k,True))

    def test_multiple_put_claims_or_invented_server_received_count_reject(self):
        for key,value in [('clientReloadInvocations',0),('clientReloadInvocations',2),('clientReloadInvocations',True),('controllerReceivedCount',0),('controllerReceivedCount',1)]:
            self.reject_report(lambda d,k=key,v=value:d.__setitem__(k,v))

    def test_reload_payload_ack_dispatch_and_status_are_exact(self):
        self.reject_report(lambda d:d.__setitem__('reloadPayload',copy.deepcopy(d['baseInput'])))
        self.reject_report(lambda d:d.__setitem__('reloadErrorClass','UNKNOWN'))
        for key,value in [('state','unknown'),('dispatched',False),('dispatched',1),('statusCode',200),('statusCode',204.0)]:
            self.reject_report(lambda d,k=key,v=value:d['reloadResult'].__setitem__(k,v))

    def test_route_phases_and_exact_selected_proxy_counter_deltas(self):
        self.reject_report(lambda d:d['routes'].reverse())
        self.reject_report(lambda d:d['routes'][1].__setitem__('phase','BASELINE_A'))
        def wrong_proxy(d):
            after=d['routes'][1]['countersAfter'];after[0].update(connectIngress=2,tunnelRequests=2,forwardInvocations=2,originRequests=2);after[1].update(connectIngress=0,tunnelRequests=0,forwardInvocations=0,originRequests=0)
        self.reject_report(wrong_proxy)

    def test_route_three_actual_body_hashes_lengths_and_nonce_replay_reject(self):
        for key,value in [('sha256','c'*64),('bytes',1),('complete',False),('bytes',True)]:
            self.reject_report(lambda d,k=key,v=value:d['routes'][1]['originResponse'].__setitem__(k,v))
        self.reject_report(lambda d:d['routes'][1].__setitem__('nonceSHA256',d['routes'][0]['nonceSHA256']))
        self.reject_report(lambda d:d['routes'][0].__setitem__('matched',False))

    def test_route_counter_types_rejections_and_cross_phase_continuity(self):
        for key,value in [('rejected',1),('originRequests',True),('forwardInvocations',-1)]:
            self.reject_report(lambda d,k=key,v=value:d['routes'][0]['countersAfter'][2].__setitem__(k,v))
        self.reject_report(lambda d:d['routes'][1].__setitem__('countersBefore',model_counters()))
        self.reject_report(lambda d:d['routes'][0]['countersAfter'].pop())

    def test_cleanup_observations_require_every_owned_fixture_and_no_failure(self):
        for key,value in [('shutdownReturned',False),('serveReturned',False),('errorClass','SHUTDOWN'),('forcedConnectionsClosed',True)]:
            self.reject_report(lambda d,k=key,v=value:d['fixtureCleanup'][0].__setitem__(k,v))
        # refresh() also changes FIXTURE_STOP_RESULT, keeping the invented
        # journal coherent so these hit real owned-connection budget checks.
        for index,count in ((0,1),(1,2),(2,2)):
            self.reject_report(lambda d,i=index,n=count:d['fixtureCleanup'][i].__setitem__('forcedConnectionsClosed',n))
        self.reject_report(lambda d:d['fixtureCleanup'].pop())
        self.reject_report(lambda d:d['fixtureCleanup'][2].__setitem__('role','A'))

    def test_journal_time_shape_order_and_unrelated_fact_injection_rejects(self):
        for kind in ('time','backward','unknownfact','unusedfact'):
            raw,sources=fixture();rows=[json.loads(line) for line in raw['apply-observations.jsonl'].splitlines()]
            if kind=='time':rows[0]['observedAtUTC']='not-a-timestamp'
            elif kind=='backward':rows[2]['observedAtUTC']='2020-01-01T00:00:00Z'
            elif kind=='unknownfact':rows[2]['facts']['permission']=True
            else:rows[2]['facts']['clientReloadInvocations']=1
            raw['apply-observations.jsonl']=b''.join(wire(e) for e in rows);self.reject(raw,sources)


if __name__ == '__main__':
    unittest.main()
