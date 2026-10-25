"""Synthetic independent-reader tests; they never run Go, HTTP or a worker."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_get_projection as GET

path = Path(__file__).with_name('check_native_recovery.py')
spec = importlib.util.spec_from_file_location('native_reader_under_test', path)
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def events_fixture():
    # MODEL ordering exercises the reader grammar, not original OS evidence.
    pairs = [(1, 'KERNEL_OS_START_ATTEMPT'), (1, 'KERNEL_OS_START_RETURN'),
             (1, 'KERNEL_OS_WAIT_ENTER'), (0, 'SYNTAX_OS_START_ATTEMPT'),
             (0, 'SYNTAX_OS_START_RETURN'), (1, 'RECOVERY_STOP_DISPATCH'),
             (1, 'OWNED_STOP_HELPER_ENTER'), (1, 'KERNEL_OS_TERM_ATTEMPT'),
             (1, 'KERNEL_OS_TERM_RETURN'), (1, 'KERNEL_OS_WAIT_RETURN'),
             (0, 'RECOVERY_START_DISPATCH'), (2, 'KERNEL_OS_START_ATTEMPT'),
             (2, 'KERNEL_OS_START_RETURN'), (2, 'KERNEL_OS_WAIT_ENTER'),
             (2, 'OWNED_STOP_HELPER_ENTER'), (2, 'KERNEL_OS_TERM_ATTEMPT'),
             (2, 'KERNEL_OS_TERM_RETURN'), (2, 'KERNEL_OS_WAIT_RETURN'),
             (1, 'OWNED_STOP_HELPER_ENTER')]
    rows = [{'sequence': i, 'kind': kind, 'core': core,
             'at': '2026-10-25T00:00:%02dZ' % i}
            for i, (core, kind) in enumerate(pairs, 1)]
    window = (C.timestamp('2026-10-25T00:00:00Z'), C.timestamp('2026-10-25T00:01:00Z'))
    counts = [14, 14, 14, 14, 14, 19, 19, 19, 19, 19]
    snapshots = [{'stage': stage, 'count': n, 'lastSequence': n,
                  'eventsSHA256': C.event_prefix_sha(rows, n)}
                 for stage, n in zip(C.EVENT_STAGES, counts)]
    return rows, window, snapshots


def go_fixture():
    return [dict(Time='2026-10-25T00:00:00Z', Package=C.PACKAGE, Action='start'),
            dict(Time='2026-10-25T00:00:01Z', Package=C.PACKAGE, Test=C.TOP, Action='run'),
            dict(Time='2026-10-25T00:00:40Z', Package=C.PACKAGE, Test=C.TOP, Action='pass', Elapsed=39),
            dict(Time='2026-10-25T00:00:41Z', Package=C.PACKAGE, Action='pass', Elapsed=41)]


def wire(rows):
    return b''.join(C.canonical(row) for row in rows)


class SyntheticNativeRecoveryEvidenceModels(unittest.TestCase):
    def test_json_duplicates_aliases_nonfinite_surrogates_and_depth_reject(self):
        self.assertEqual(C.decode(b'{"ok":[1,true,null]}'), {'ok': [1, True, None]})
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.0}', b'"\\ud800"',
                    b'\xef\xbb\xbf{}', b'[' * 26 + b'0' + b']' * 26):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                C.decode(raw)

    def test_exact_go_top_positive_does_not_claim_native_execution(self):
        result = C.go_events(wire(go_fixture()))
        self.assertEqual(result['passingSemanticTests'], 1)
        self.assertEqual(result['skips'], 0)
        self.assertNotIn('nativeExecuted', result)

    def test_go_skip_other_top_duplicate_and_postterminal_reject(self):
        mutations = []
        rows = go_fixture(); rows[2]['Action'] = 'skip'; mutations.append(rows)
        rows = go_fixture(); rows[1]['Test'] += '/extra'; mutations.append(rows)
        rows = go_fixture(); rows.insert(3, copy.deepcopy(rows[2])); mutations.append(rows)
        rows = go_fixture(); rows.append(copy.deepcopy(rows[-1])); mutations.append(rows)
        rows = go_fixture(); rows[2]['Time'] = '2026-10-24T00:00:00Z'; mutations.append(rows)
        rows = go_fixture(); rows[1]['Package'] = 'other/package'; mutations.append(rows)
        for rows in mutations:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                C.go_events(wire(rows))

    def test_source_calls_positive_and_each_core_order_or_count_tamper_rejects(self):
        rows, window, _ = events_fixture()
        positions = C.native_events(rows, 1, 2, window)
        self.assertEqual(len(positions[(1, 'OWNED_STOP_HELPER_ENTER')]), 2)
        # Wait is a different goroutine. Its return observation may precede
        # the signal return, or precede the signal attempt after natural exit.
        # This protocol cannot infer that TERM caused process termination.
        for kinds in (('KERNEL_OS_TERM_ATTEMPT', 'KERNEL_OS_WAIT_RETURN', 'KERNEL_OS_TERM_RETURN'),
                      ('KERNEL_OS_WAIT_RETURN', 'KERNEL_OS_TERM_ATTEMPT', 'KERNEL_OS_TERM_RETURN')):
            interleaved = copy.deepcopy(rows)
            for row, kind in zip(interleaved[7:10], kinds):
                row['kind'] = kind
            C.native_events(interleaved, 1, 2, window)
        for edit in (lambda r: r[7].update(core=2),
                     lambda r: r[7].update(kind='KERNEL_OS_KILL_ATTEMPT'),
                     lambda r: r[13].update(kind='KERNEL_OS_WAIT_RETURN'),
                     lambda r: r[0].update(sequence=2),
                     lambda r: r[0].update(at='2026-10-24T00:00:00Z'),
                     lambda r: r[0].update(kind='CALLER_INVENTED_OS_SUCCESS')):
            bad = copy.deepcopy(rows); edit(bad)
            with self.assertRaises(ValueError):
                C.native_events(bad, 1, 2, window)

    def test_replay_cleanup_and_reopen_prefixes_are_independently_rehashed(self):
        rows, window, snapshots = events_fixture()
        positions = C.native_events(rows, 1, 2, window)
        result = C.event_checkpoints(snapshots, rows, positions, 1, 2)
        self.assertEqual(result['snapshotCount'], 10)
        self.assertEqual(result['reopenAddedCalls'], 0)
        for edit in (lambda r: r[1].update(eventsSHA256='a' * 64),
                     lambda r: r[1].update(count=15, lastSequence=15, eventsSHA256=C.event_prefix_sha(rows, 15)),
                     lambda r: r[8].update(stage='caller-stage'),
                     lambda r: r[9].update(count=18, lastSequence=18, eventsSHA256=C.event_prefix_sha(rows, 18)),
                     lambda r: r[0].update(lastSequence=13)):
            bad = copy.deepcopy(snapshots); edit(bad)
            with self.assertRaises(ValueError):
                C.event_checkpoints(bad, rows, positions, 1, 2)

    def test_stream_prefix_or_closed_flag_cannot_fake_full_retained_stream(self):
        raw = b'MODEL retained stream'
        value = dict(bytes=len(raw), totalBytes=len(raw), sha256=C.sha(raw), truncated=False, complete=True)
        C.stream(value, raw)
        for edit in (lambda r: r.update(bytes=True), lambda r: r.update(totalBytes=len(raw) + 1),
                     lambda r: r.update(sha256='a' * 64), lambda r: r.update(complete=False),
                     lambda r: r.update(truncated=True)):
            bad = dict(value); edit(bad)
            with self.assertRaises(ValueError):
                C.stream(bad, raw)


_SOURCE_FIXTURE = None


def fixture_sources():
    global _SOURCE_FIXTURE
    if _SOURCE_FIXTURE is None:
        repo = Path(__file__).resolve().parents[3]
        _SOURCE_FIXTURE = {p: (repo / p).read_bytes() for p in C.FILES}
    return dict(_SOURCE_FIXTURE)


def stream_meta(raw, complete=True):
    return dict(bytes=len(raw), totalBytes=len(raw), sha256=C.sha(raw), truncated=False, complete=complete)


def recovery_fixture(raw, report, index, hashed):
    # Pure synthetic response entities from the existing independent model
    # helper. They are never claimed to be requests, a real cap or actual WAL.
    original, projection_report = GET.fixture()
    phase = 'candidate'
    raw['recovery-s2-transcript.json'] = original[phase+'-get-evidence.json']
    bodies = []
    for i in range(1, 9):
        name = f'recovery-s2-body-{i}.json'
        raw[name] = original[phase+'-get-'+str(i).zfill(2)+'.body']
        bodies.append(C.sha(raw[name]))
    cfg = dict(schema='chengwang.mihomo-lab-config/v1', scope='ISOLATED_LOOPBACK_MIHOMO_STATIC_SUBSET_NOT_PRODUCTION',
               sha256=report['newIdentity']['artifactSHA256'], bytes=1234, draftSHA256=hashed('draft'),
               requirementsSHA256=hashed('requirements'), capabilities=['static_domain_suffix_rules', 'explicit_selectors',
               'loopback_http_nodes', 'private_loopback_controller', 'built_in_dns_disabled'], requirements=[], admissible=True, blockers=[])
    record = dict(schema='chengwang.mihomo-artifact-record/v1', config=cfg, sourceSpecSHA256=hashed('source spec'),
                  sourceSpecBytes=567, controllerPort=28412, mixedPort=28411)
    artifact = dict(schema='chengwang.mihomo-artifact/v1', recordSHA256=C.sha(C.recovery_go_bytes(record, GET.G)),
                    config=cfg, sourceSpecSHA256=record['sourceSpecSHA256'], sourceSpecBytes=567, controllerPort=28412, mixedPort=28411)
    report['originalUnknown']['candidateRecordSHA256'] = artifact['recordSHA256']
    target = projection_report['readbacks'][phase]['observedProjectionSHA256']
    readback = dict(schema='chengwang.mihomo-selected-target-readback/v1', conclusion='TARGET_PROJECTION_MATCHED',
                    sampleCount=2, requestsObserved=8, targetProjectionSHA256=target, observedProjectionSHA256=target,
                    dataplaneProven=False, fullPayloadProven=False, authorizationProven=False, production=False)
    # These are inert descriptors for protocol models, not route observations
    # or a reconstructed private fixture/receipt. No HTTP is run here.
    nonce = 'c' * 64
    marker_body = ('chengwang-local-service-marker/v1:B:' + nonce + '\n').encode('ascii')
    marker_hash = C.sha(marker_body)
    before = [dict(role=role, connectIngress=0, tunnelRequests=0, forwardInvocations=0, originRequests=0, rejected=0)
              for role in ('A', 'B', 'origin')]
    after = copy.deepcopy(before)
    after[1].update(connectIngress=1, tunnelRequests=1, forwardInvocations=1, originRequests=1)
    after[2]['originRequests'] = 1
    body_meta = dict(sha256=marker_hash, bytes=len(marker_body), complete=True)
    local = dict(schema='chengwang.mihomo-recovery-local-marker/v1',
                 scope='ACTUAL_LOOPBACK_PROXY_MARKER_NOT_INTERNET_BUSINESS_OR_AUTHORIZATION',
                 expectedRole='B', expectedMarkerSHA256=marker_hash, expectedMarkerBytes=len(marker_body),
                 startedAt='2026-10-25T00:00:14.81Z', returnedAt='2026-10-25T00:00:14.9Z',
                 handlerCompleted=True, clientNaturalEOF=True, proxyNaturalEOF=True,
                 originWriteComplete=True, localProxyMarkerProven=True,
                 route=dict(phase='RECOVERY_NEW_EPOCH_MARKER', nonceSHA256=C.sha(nonce.encode('ascii')),
                            clientResponse=copy.deepcopy(body_meta), proxyResponse=copy.deepcopy(body_meta),
                            originResponse=copy.deepcopy(body_meta), countersBefore=before, countersAfter=after, matched=True))
    raw['recovery-s2-local-marker.json'] = C.recovery_go_bytes(local, GET.G)
    observed = dict(schema='chengwang.mihomo-recovery-control-observation/v2', recoveryId='labrec_'+'3'*32,
                    planSHA256=hashed('recovery plan'), startIntentSHA256=hashed('start intent'), startedSHA256=report['startedSHA256'],
                    sourceRevision=report['stages'][5]['revision'], sourceRecordSHA256=report['stages'][5]['recordSHA256'],
                    ownerFence=1, artifact=artifact, startupIdentity=copy.deepcopy(report['newIdentity']),
                    entryAt='2026-10-25T00:00:14.55Z', deadline='2026-10-25T00:00:14.95Z',
                    sampleTimes=[dict(startedAt='2026-10-25T00:00:14.6Z', completedAt='2026-10-25T00:00:14.65Z'),
                                 dict(startedAt='2026-10-25T00:00:14.7Z', completedAt='2026-10-25T00:00:14.75Z')],
                    observedAt='2026-10-25T00:00:14.8Z', readback=readback,
                    transcriptSHA256=C.sha(raw['recovery-s2-transcript.json']), bodySHA256s=bodies, verificationSHA256='',
                    localPath=local, localMarkerSHA256=C.sha(raw['recovery-s2-local-marker.json']))
    verification = C.recovery_go_bytes(observed, GET.G)
    raw['recovery-s2-verification.json'] = verification
    report['controlPlane'] = copy.deepcopy(observed)
    report['controlPlane']['verificationSHA256'] = C.sha(verification)
    report['controlBeforeSHA256'] = report['controlAfterSHA256'] = report['stages'][5]['controlSHA256']
    report['controlProofReplayRejected'] = report['controlRecollectRejected'] = True
    report['controlCopiedStartedRejected'] = report['controlCopiedProofRejected'] = True
    report['localCopiedFixtureRejected'] = True
    report['controlEvents'] = [dict(stage=stage, count=14, lastSequence=14, eventsSHA256=C.event_prefix_sha(report['nativeCalls'],14))
                               for stage in ('before-control-plane','after-control-plane')]


def edit_recovery_value(raw, change):
    value = C.decode(raw['recovery-s2-verification.json'])
    change(value)
    raw['recovery-s2-verification.json'] = C.recovery_go_bytes(value, GET.G)
    report = C.decode(raw['native-report.json'])
    report['controlPlane'] = copy.deepcopy(value)
    report['controlPlane']['verificationSHA256'] = C.sha(raw['recovery-s2-verification.json'])
    if C.RECORD_PUBLIC in raw and raw[C.RECORD_PUBLIC]:
        record = C.decode(raw[C.RECORD_PUBLIC])
        if record['receiptPresent']:
            record['observationSHA256'] = C.sha(C.recovery_go_bytes(report['controlPlane'], GET.G))
        raw[C.RECORD_PUBLIC] = C.recovery_go_bytes(record, GET.G)
        report['verificationRecord'] = record
    raw['native-report.json'] = C.canonical(report)


def edit_marker_value(raw, change):
    marker = C.decode(raw['recovery-s2-local-marker.json'])
    change(marker)
    original = C.recovery_go_bytes(marker, GET.G)
    raw['recovery-s2-local-marker.json'] = original
    def rebind(value):
        value['localPath'] = marker
        value['localMarkerSHA256'] = C.sha(original)
    edit_recovery_value(raw, rebind)


def record_fixture(raw, report, index, hashed, variant):
    # Metadata-only protocol model. No private owner nonce, disk, registered
    # cap, fake WAL writer or live source object is constructed here.
    source, disk = report['stages'][5], report['stages'][6]
    durable, positive = variant != 'not-committed', variant == 'positive'
    current = hashed('unchanged Current')
    value = dict(schema='chengwang.mihomo-native-verification-record/v1',
                 scope='REDACTED_ACTUAL_WAL_FACT_NOT_AUTHORIZATION_OR_COMPLETE_PRIVATE_RECEIPT',
                 mode=variant, attemptedAt='2026-10-25T00:00:14.91Z', returnedAt='2026-10-25T00:00:14.94Z',
                 replaceAttempts=1, forwardedWrites=int(durable), postWriteReads=int(variant in ('positive','readback')),
                 injectedReads=int(variant=='readback'), underlyingCommitted=durable, capKnownBefore=True,
                 capSpent=True, capCopyRejected=True, capReplayRejected=True, recordReturnedError=not positive,
                 storePoisoned=not positive, candidateAdopted=positive, liveOwnerCleared=not positive,
                 transientProofCleared=True, retainedStartedCleared=True, sourceRevision=source['revision'],
                 sourceRecordSHA256=source['recordSHA256'], sourceControlSHA256=source['controlSHA256'],
                 memoryRevision=(disk if positive else source)['revision'],
                 memoryRecordSHA256=(disk if positive else source)['recordSHA256'],
                 diskRevision=disk['revision'], diskRecordSHA256=disk['recordSHA256'], diskControlSHA256=disk['controlSHA256'],
                 executionSchema='chengwang.mihomo-recovery-execution/'+('v2' if durable else 'v1'),
                 receiptPresent=durable, receiptSHA256=hashed('private receipt not disclosed') if durable else None,
                 observationSHA256=C.sha(C.recovery_go_bytes(report['controlPlane'],GET.G)) if durable else None,
                 verificationCommitRevision=source['revision']+1 if durable else None,
                 recordedAt='2026-10-25T00:00:14.91Z' if durable else None,
                 s1PreimageSHA256=source['controlSHA256'] if durable else None,
                 sourceCurrentSHA256=current, diskCurrentSHA256=current, completionAbsent=True,
                 noNewPhysicalCalls=True, fullPrivateReceiptIndependentlyProven=False)
    raw[C.RECORD_PUBLIC] = C.recovery_go_bytes(value,GET.G)
    report['verificationRecord'] = value
    report['verificationEvents'] = [dict(stage=stage,count=14,lastSequence=14,eventsSHA256=C.event_prefix_sha(report['nativeCalls'],14))
                                    for stage in ('before-verification-record','after-verification-record')]
    report['reopenedExecutionPreserved'] = report['reopenedRecordCapabilityAbsent'] = True


def edit_record_projection(raw, change):
    value = C.decode(raw[C.RECORD_PUBLIC]);change(value)
    raw[C.RECORD_PUBLIC] = C.recovery_go_bytes(value,GET.G)
    edit_json(raw,'native-report.json',lambda report:report.update(verificationRecord=value))


def closed_fixture(variant='positive'):
    assert variant in C.VARIANTS
    # Entirely SYNTHETIC. Public strings/counters exercise protocol validation;
    # no process, permit, Start, Wait, socket, credential or WAL is constructed.
    sources = fixture_sources()
    commit = '1' * 40
    hashed = lambda name: C.sha(('MODEL ' + name).encode())
    ns = dict(networkNamespace='net:[101]', mountNamespace='mnt:[201]', pidNamespace='pid:[301]')
    host = dict(networkNamespace='net:[100]', mountNamespace='mnt:[200]', pidNamespace='pid:[300]', resolvSHA256=hashed('resolv'))
    pin_path = 'chengwang/tools/mihomo-runtime-candidate/pin.json'
    pin = C.decode(sources[pin_path])
    elf = dict(sha256=hashed('ELF'), bytes=62054526, elfClass='ELF64', byteOrder='little', machine='AMD64', type='EXEC',
               entryPoint=4795680, programHeaderCount=5, sectionHeaderCount=14, loadSegments=3, executableEntryMapped=True)
    paths = ['chengwang/tools/mihomo-runtime-candidate/' + n for n in
             ('pin.json', 'consume_pin.py', 'check_consumption.py', 'test_consume_pin.py', 'README.md')]
    receipt = dict(schema='chengwang.mihomo-candidate-consumption/v1', state='PINNED_GZIP_EXPANDED_NOT_EXECUTED',
                   component=pin['component'], version=pin['version'], upstreamSourceCommit=pin['upstreamSourceCommit'],
                   archive=dict(name=pin['artifact']['name'], sha256=pin['artifact']['publishedSHA256'], bytes=22877868,
                                pinBasis='PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL'),
                   gzip=dict(complete=True, singleMember=True, trailerCRC32='b50365ef', trailerISIZE=elf['bytes']), elf=elf,
                   source=dict(projectSourceCommit=commit, pinSHA256=C.sha(sources[pin_path]),
                               sourceFiles=[dict(path=p, bytes=len(sources[p]), sha256=C.sha(sources[p])) for p in paths]),
                   output=dict(path='mihomo', mode='0500', receiptMode='0400', directoryMode='0700'),
                   publisherSignatureProven=False, productionApproved=False, runtimeExecuted=False,
                   runtimeCompatibilityProven=False, businessAvailabilityProven=False, production=False)
    receipt_raw = C.canonical(receipt)
    custody = dict(elf=dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', uid=1000, gid=1000),
                   receipt=dict(sha256=C.sha(receipt_raw), bytes=len(receipt_raw), mode='0400', uid=1000, gid=1000))
    sandbox = dict(schema='chengwang.mihomo-native-recovery-sandbox/v2', verificationMode=variant, sourceCommit=commit, uid=10001, gid=10001,
                   effectiveCaps='0000000000000000', noNewPrivileges=True, **ns,
                   environmentKeys=list(C.ENV), interfaceNames=['lo'], defaultV4Routes=[], defaultV6Routes=[],
                   sourceModuleSHA256=C.sha(sources['chengwang/go.mod']), sourceReadOnly=True, goReadOnly=True,
                   kernelCopy=dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', readOnly=True, executable=True),
                   inputCustody=dict(before=custody, after=copy.deepcopy(custody)),
                   serviceBases=['/tmp/chengwang-mihomo-service-private', '/tmp/chengwang-mihomo-service-identities',
                                 '/tmp/chengwang-mihomo-service-state'])
    identity = lambda pid, ticks, artifact: dict(pid=pid, startTicks=ticks, netNSInode=101, elfSHA256=elf['sha256'],
                                               elfBytes=elf['bytes'], sourceCommit=commit, artifactSHA256=artifact,
                                               controllerPort=28412, mixedPort=28411)
    old, new = identity(123, 1001, hashed('old config')), identity(124, 1002, hashed('new config'))
    oldraw, newraw = b'MODEL old retained stream\n', b'MODEL new retained stream\n'

    def started(ident):
        return dict(attempted=True, started=True, pid=ident['pid'], startTicks=ident['startTicks'], waitReturned=False,
                    waitErrorClass='NOT_WAITED', exitCode=None, signal=None, termSent=False, killSent=False,
                    groupAbsent=None, stdout=stream_meta(b'', False), stderr=stream_meta(b'', False))

    def exited(raw):
        return dict(started=True, waitReturned=True, waitErrorClass='NONE', exitCode=0, signal=None,
                    termSent=True, killSent=False, groupAbsent=True, stdout=stream_meta(raw), stderr=stream_meta(b''))

    oldexit, newexit = exited(oldraw), exited(newraw)
    unknown = dict(schema='chengwang.mihomo-lab-deployment-view/v1', boundary=C.BOUNDARY,
                   operationId='labop_' + '2' * 32, phase='UNKNOWN', revision=10, planSHA256=hashed('original plan'),
                   candidateRecordSHA256=hashed('candidate record'), candidateConfigSHA256=new['artifactSHA256'],
                   previousHeadSHA256=hashed('old head'), headSHA256=hashed('old head'), headGeneration=1,
                   expiresAt='2026-10-25T00:02:00Z',
                   transport=dict(result=dict(state='unknown', dispatched=True, statusCode=0),
                                  recordedAt='2026-10-25T00:00:05.1Z', origin='ADAPTER', gateReason=None),
                   observation=dict(conclusion='STABLE_NEW_PROJECTION', observedProjectionSHA256=hashed('old route'),
                                    evidenceSHA256=hashed('original unknown observation'), observedAt='2026-10-25T00:00:05.2Z', localRouteVerified=True),
                   writeBlocked=True, replayed=False, headAdvanced=False,
                   proof=dict(fullPayloadProven=False, internetBusinessProven=False, production=False))
    q = dict(schema='chengwang.mihomo-owned-quiescence-observation/v1', startupIdentity=copy.deepcopy(old),
             stopInvoked=True, stopReturned=True, stopErrorClass='NONE', stop=copy.deepcopy(oldexit), namespaceInode=101,
             controllerProbe=dict(port=28412, attempted=True, result='CONNECTION_REFUSED'),
             mixedProbe=dict(port=28411, attempted=True, result='CONNECTION_REFUSED'),
             startedAt='2026-10-25T00:00:05.5Z', returnedAt='2026-10-25T00:00:10.5Z', outcome='QUIESCED', failureCode='NONE')
    start = dict(schema='chengwang.mihomo-owned-recovery-start-observation/v1', permitConsumed=True, startInvoked=True,
                 startReturned=True, startErrorClass='NONE', startObservation=started(new),
                 startupIdentity=copy.deepcopy(new), verifiedIdentity=copy.deepcopy(new), namespaceInode=101,
                 listenersBefore=True, listenersAfter=True, startedAt='2026-10-25T00:00:10.75Z',
                 returnedAt='2026-10-25T00:00:14.5Z', outcome='STARTED', failureCode='NONE')
    native, _, checkpoints = events_fixture()
    index = []
    for i, stage in enumerate(('legacy', *C.STAGES, 'reopened')):
        row = dict(stage=stage, bytes=1000 + i, controlSHA256=hashed('control ' + stage),
                   schema='chengwang.mihomo-lifecycle-record/v2' if i == 0 else 'chengwang.mihomo-lifecycle-record/v3',
                   revision=10 if i == 0 else 12 + i, recordSHA256=hashed('record ' + stage))
        if i:
            row.update(phase='RECOVERY_UNKNOWN' if stage == 'reopened' else C.PHASES[i - 1], headSHA256=unknown['headSHA256'])
        index.append(row)
    if variant == 'not-committed':
        index[-2] = dict(index[-3], stage='verification-attempted')
        index[-1]['revision'] = index[-2]['revision']+1
    checkpoint = lambda row: {k: row[k] for k in ('stage', 'controlSHA256', 'recordSHA256', 'revision', 'phase')}
    syntax = dict(attempted=True, started=True, pid=125, startTicks=None, waitReturned=True, waitErrorClass='NONE',
                  exitCode=0, signal=None, termSent=False, killSent=False, groupAbsent=True,
                  stdout=stream_meta(b'MODEL unexported syntax output'), stderr=stream_meta(b''))
    fixtures = [dict(role=role, shutdownReturned=True, serveReturned=True,
                     forcedConnectionsClosed=0, errorClass='NONE') for role in ('origin', 'A', 'B')]
    probes = [dict(port=port, attempted=True, result='CONNECTION_REFUSED') for port in (28411, 28412, 28413, 28414, 28415)]
    report = dict(schema='chengwang.mihomo-native-recovery-experiment/v5', verificationMode=variant, scope=C.SCOPE, sourceCommit=commit,
                  outcome='PASS', failureCode='NONE', originalUnknown=unknown,
                  fault=dict(schema='chengwang.mihomo-reload-response-loss-observation/v1', state='INJECTED', claimed=True,
                             underlyingRoundTrips=1, statusCode=204, bodyBytes=0, eofObserved=True, closeSucceeded=True,
                             injected=True, failureCode=None), reloadBefore=dict(reloadInvocations=0, doInvocations=0),
                  reloadUnknown=dict(reloadInvocations=1, doInvocations=1), reloadFinal=dict(reloadInvocations=1, doInvocations=1),
                  oldIdentity=old, newIdentity=new, bootstrapStart=started(old), oldCore=1, newCore=2, quiescence=q,
                  start=start, startedSHA256=hashed('started fact'), stages=[checkpoint(row) for row in index[1:-1]],
                  replayRejected=True, recoverySelfApprovalDenied=True, reopened=checkpoint(index[-1]), oldCleanup=oldexit,
                  newCleanup=newexit, syntax=[syntax], nativeCalls=native, eventCheckpoints=checkpoints,
                  dualOwnerCloseRejectedTwice=True, countersBounded=True, closedPorts=[28411, 28412, 28413, 28414, 28415],
                  fixtureCleanup=fixtures, cleanupProbes=probes,
                  runtimeClosed=True, newDiskOwnerClosed=True, cleanupReplayNoOp=True, httpRecoveryProven=False,
                  completionProven=False, fullPrivateWALIndependentlyProven=False, syntaxRawStreamsIndependentlyProven=False,
                  internetBusinessProven=False, production=False)
    commands = []
    cw, gr = '/tmp/mihomo-apply-source', '/tmp/mihomo-apply-go'
    argv = [["/usr/bin/python3", '-B', cw + '/deploy/mihomo-lifecycle-lab/native_recovery_worker.py', '--sandbox', commit, C.sha(sources['chengwang/go.mod']), variant],
            [gr + '/bin/go', 'version'], [gr + '/bin/gofmt', '-d', *C.FMT],
            [gr + '/bin/go', 'test', '-json', '-count=1', '-shuffle=off', '-p=1', '-tags=' + ','.join(C.TAGS), '-run=^' + C.TOP + '$', '-timeout=75s', './internal/mihomodeploy', '-args', '-chengwang-native-verification-mode='+variant]]
    for i, name in enumerate(C.COMMAND_CLASSES):
        commands.append(dict(schema='chengwang.mihomo-native-command-receipt/v1', sequence=i + 1, sourceCommit=commit,
                             commandClass=name, argv=argv[i], cwd=cw, timeoutSeconds=[30, 15, 30, 90][i], exitCode=0,
                             observed=True, namespace=copy.deepcopy(ns)))
    process = []
    for i, name in enumerate(C.COMMAND_CLASSES):
        for event, pid, acquired, code in [('START_INTENT', None, None, None), ('STARTED', 1000 + i, None, None),
                                            ('REFERENCE_ACQUIRED', 1000 + i, True, None), ('WAIT_RETURNED', 1000 + i, True, 0)]:
            process.append(dict(schema='chengwang.mihomo-apply-private-process-event/v1', seq=len(process) + 1,
                                commandClass=name, event=event, pid=pid, pidfdAcquired=acquired, exitCode=code))
    manifest = C.make_source_manifest(sources, commit)
    manifest['sourceGitVerified'] = True  # MODEL input only; output remains false.
    raw = {p: b'' for p in C.PUBLIC}
    raw.update({'host-before.json': C.canonical(host), 'host-after.json': C.canonical(host),
                'consumption.json': receipt_raw, 'consumption-independent.json': receipt_raw,
                'native-report.json': C.canonical(report),
                'wal-readback-index.json': C.canonical(dict(schema='chengwang.mihomo-native-wal-readback-index/v2',
                    scope=C.SCOPE, sourceCommit=commit, stages=index, fullPrivateWALIndependentlyProven=False, production=False)),
                'old-kernel.stdout': oldraw, 'new-kernel.stdout': newraw, 'sandbox.json': C.canonical(sandbox),
                'execution.json': C.canonical(dict(schema='chengwang.mihomo-native-recovery-execution/v2', scope=C.SCOPE, verificationMode=variant,
                    sourceCommit=commit, formatExit=0, goExit=0, captureState='CAPTURED_NOT_INDEPENDENT_ACCEPTANCE', production=False)),
                'go-version.txt': b'go version go1.23.12 linux/amd64\n', 'native.json': wire(go_fixture()),
                'commands.jsonl': wire(commands), 'process-events.jsonl': wire(process),
                'source-before.json': C.canonical(manifest), 'source-after.json': C.canonical(manifest)})
    recovery_fixture(raw, report, index, hashed)
    record_fixture(raw, report, index, hashed, variant)
    raw['native-report.json'] = C.canonical(report)
    return raw, sources, commit


def edit_json(raw, path, change):
    value = C.decode(raw[path])
    change(value)
    raw[path] = C.canonical(value)


class SyntheticNativeRecoveryClosedModels(unittest.TestCase):
    def test_real_git_tree_index_and_worktree_bind_to_the_declared_commit(self):
        # Real disposable Git, not mocked Git output or producer imports. Files
        # are inert MODEL text; this does not execute their Go/Python contents.
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='native-reader-git-', dir=parent)).resolve(strict=True)
        self.assertEqual(root.parent, parent)
        self.assertTrue(root.is_relative_to(parent))
        hooks = root / 'empty-hooks'; hooks.mkdir()
        diagnostic = root / 'git-model-calls'; diagnostic.mkdir()
        sequence = 0

        def record(value):
            with (diagnostic / 'journal.jsonl').open('ab') as f:
                f.write(C.canonical(value)); f.flush(); os.fsync(f.fileno())

        def git(*args):
            nonlocal sequence
            sequence += 1
            command = ['git', '-C', str(root), '-c', 'core.hooksPath=' + str(hooks),
                       '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false',
                       '-c', 'core.attributesFile=' + os.devnull, '-c', 'commit.gpgsign=false',
                       '-c', 'user.name=Native reader model', '-c', 'user.email=fixture@example.invalid', *args]
            record(dict(event='START', sequence=sequence, argv=command, scope='DISPOSABLE_GIT_MODEL_NOT_NATIVE'))
            with (diagnostic / (str(sequence) + '.stdout')).open('xb') as out, \
                    (diagnostic / (str(sequence) + '.stderr')).open('xb') as err:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
                record(dict(event='PID', sequence=sequence, pid=process.pid))
                code = process.wait(timeout=30)
                out.flush(); os.fsync(out.fileno()); err.flush(); os.fsync(err.fileno())
            record(dict(event='EXIT', sequence=sequence, pid=process.pid, exitCode=code))
            self.assertEqual(code, 0, 'isolated Git fixture command rejected')
            return (diagnostic / (str(sequence) + '.stdout')).read_bytes()

        git('init', '--quiet')
        for name, value in [('core.hooksPath', str(hooks)), ('core.fsmonitor', 'false'),
                            ('core.autocrlf', 'false'), ('core.attributesFile', os.devnull)]:
            git('config', name, value)
        values = {}
        for path in C.FILES:
            target = root / path; target.parent.mkdir(parents=True, exist_ok=True)
            value = ('MODEL tracked source ' + path + '\n').encode()
            target.write_bytes(value); values[path] = value
        git('add', '--', *C.FILES)
        git('commit', '--quiet', '-m', 'MODEL exact committed source bytes')
        commit = git('rev-parse', 'HEAD').decode('ascii').strip()
        self.assertEqual(C.source_git(root, commit), values)
        selected = root / C.FILES[0]
        original = values[C.FILES[0]]
        selected.write_bytes(original + b'MODEL unstaged change\n')
        with self.assertRaises(ValueError):
            C.source_git(root, commit)
        selected.write_bytes(original)
        self.assertEqual(C.source_git(root, commit), values)
        selected.write_bytes(original + b'MODEL staged change under same HEAD\n')
        git('add', '--', C.FILES[0])
        self.assertEqual(git('rev-parse', 'HEAD').decode('ascii').strip(), commit)
        with self.assertRaises(ValueError):
            C.source_git(root, commit)
        # Even restoring worktree bytes must not conceal a different index.
        selected.write_bytes(original)
        with self.assertRaises(ValueError):
            C.source_git(root, commit)
        git('reset', '--mixed', '--quiet', 'HEAD')
        self.assertEqual(C.source_git(root, commit), values)
        # Retain the inert disposable fixture for diagnostics. No recursive
        # delete or operation against the real repository is performed.

    def test_complete_synthetic_protocol_is_not_source_git_or_native_acceptance(self):
        raw, sources, commit = closed_fixture()
        value = C.verify_raw(raw, sources, commit)
        self.assertEqual(value['outcome'], 'PASS')
        self.assertEqual(value['nativeObservations']['endpointCleanup'],
                         dict(fixtureCleanupRecords=3, actualEndpointProbeRecords=5))
        # Actual owned hijacked connections may have needed closure; zero is
        # not required. The count remains an integer observation, not a flag.
        changed = dict(raw)
        edit_json(changed, 'native-report.json', lambda v: v['fixtureCleanup'][1].update(forcedConnectionsClosed=1))
        self.assertEqual(C.verify_raw(changed, sources, commit)['outcome'], 'PASS')
        for key in ('sourceGitVerified', 'fullPrivateWALIndependentlyProven', 'syntaxRawStreamsIndependentlyProven',
                    'privateDisclosureFenceIndependentlyProven', 'completeKernelSyscallTracingProven', 'completionProven', 'production'):
            self.assertIs(value[key], False)
        self.assertIsNone(value['controllerReceivedCount'])
        marker = value['nativeObservations']['recoveryControlObservation']['localMarker']
        self.assertEqual(marker['matchedSourceResponseDescriptors'], 3)
        self.assertTrue(marker['sourceLocalMarkerObserved'])
        for key in ('markerBodyIndependentlyProven', 'privateNonceIndependentlyProven', 'internetBusinessProven', 'completionProven'):
            self.assertIs(marker[key], False)
        # Real bootstrap and earlier reads may have nonzero totals. Only the
        # actual marker's deltas are fixed; historical counters need not zero.
        changed = dict(raw)
        def historical_totals(v):
            for side in ('countersBefore', 'countersAfter'):
                for row in v['route'][side]:
                    for field in ('connectIngress', 'tunnelRequests', 'forwardInvocations', 'originRequests', 'rejected'):
                        if row['role'] != 'origin' or field in ('originRequests', 'rejected'):
                            row[field] += 42
        edit_marker_value(changed, historical_totals)
        self.assertEqual(C.verify_raw(changed, sources, commit)['outcome'], 'PASS')

    def test_closed_public_set_commit_and_execution_failures_do_not_pass(self):
        raw, sources, commit = closed_fixture()
        for kind in ('missing', 'private_extra', 'stderr', 'format', 'exit', 'commit', 'incomplete'):
            bad = dict(raw)
            if kind == 'missing': del bad['native-report.json']
            elif kind == 'private_extra': bad['tokens.private.json'] = b'{}'
            elif kind == 'stderr': bad['native.stderr'] = b'MODEL compiler error'
            elif kind == 'format': bad['gofmt.patch'] = b'MODEL actual diff'
            elif kind == 'exit': edit_json(bad, 'execution.json', lambda v: v.update(goExit=1))
            elif kind == 'commit': edit_json(bad, 'execution.json', lambda v: v.update(sourceCommit='2' * 40))
            else: edit_json(bad, 'execution.json', lambda v: v.update(captureState='INCOMPLETE_EMPTY_PRIVATE_RUNTIME_ROOTS_NOT_ACCEPTED'))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_full_source_manifest_requires_all_paths_and_exact_before_after(self):
        raw, sources, commit = closed_fixture()
        for kind in ('missing_source', 'unlisted_source', 'manifest_hash', 'manifest_missing_path', 'after_changed', 'not_git'):
            bad, changed = dict(raw), dict(sources)
            if kind == 'missing_source': del changed[C.FILES[0]]
            elif kind == 'unlisted_source': changed['chengwang/private-invented.go'] = b'MODEL'
            elif kind == 'after_changed': bad['source-after.json'] += b' '
            else:
                def change(v):
                    if kind == 'manifest_hash': v['files'][0]['sha256'] = 'a' * 64
                    elif kind == 'manifest_missing_path': v['files'].pop()
                    else: v['sourceGitVerified'] = False
                edit_json(bad, 'source-before.json', change)
                bad['source-after.json'] = bad['source-before.json']
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, changed, commit)

    def test_old_native_source_closure_selects_defaults_and_rejects_dual_fault_tags(self):
        sources = fixture_sources()
        self.assertEqual(len(C.FILES), 196)
        self.assertEqual(len(C.FMT), 28)
        self.assertEqual(C.contract(sources)['tags'], list(C.TAGS))
        changed = dict(sources)
        path = 'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_default.go'
        changed[path] = changed[path].replace(b' || chengwang_mihomo_faults', b'', 1)
        with self.assertRaises(ValueError):
            C.contract(changed)
        changed = dict(sources)
        contract = C.decode(changed[C.PREFIX + 'native_recovery_contract.json'])
        contract['tags'].append('chengwang_mihomo_recovery_continuous_fault')
        changed[C.PREFIX + 'native_recovery_contract.json'] = C.canonical(contract)
        with self.assertRaises(ValueError):
            C.contract(changed)

    def test_actual_command_projection_rejects_changed_run_tag_timeout_or_namespace(self):
        raw, sources, commit = closed_fixture()
        for kind in ('run', 'tags', 'timeout', 'cwd', 'namespace', 'unobserved'):
            rows = [C.decode(v) for v in raw['commands.jsonl'].splitlines()]
            if kind == 'run': rows[-1]['argv'][-3] = '-run=^AnotherTest$'
            elif kind == 'tags': rows[-1]['argv'][-4] += ',caller_tag'
            elif kind == 'timeout': rows[-1]['timeoutSeconds'] = 91
            elif kind == 'cwd': rows[-1]['cwd'] = '/tmp/caller-source'
            elif kind == 'namespace': rows[-1]['namespace']['networkNamespace'] = 'net:[999]'
            else: rows[-1].update(observed=False, exitCode=None)
            bad = dict(raw); bad['commands.jsonl'] = wire(rows)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_observed_true_does_not_replace_actual_pidfd_wait_originals(self):
        raw, sources, commit = closed_fixture()
        for kind in ('no_reference', 'wrong_pid', 'nonzero_exit', 'extra_signal'):
            rows = [C.decode(v) for v in raw['process-events.jsonl'].splitlines()]
            if kind == 'no_reference': rows[-2]['pidfdAcquired'] = False
            elif kind == 'wrong_pid': rows[-1]['pid'] += 1
            elif kind == 'nonzero_exit': rows[-1]['exitCode'] = 1
            else: rows.insert(-1, dict(rows[-1], event='SIGNAL_SENT'))
            bad = dict(raw); bad['process-events.jsonl'] = wire(rows)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_valid_event_hashes_cannot_hide_replay_or_cleanup_boundary_changes(self):
        raw, sources, commit = closed_fixture()
        for kind in ('permit_replay', 'runner_replay', 'not_yet_wait_entered', 'cleanup_already_began', 'reopen'):
            bad = dict(raw)
            def change(v):
                checkpoints, rows = v['eventCheckpoints'], v['nativeCalls']
                indices, n = ([1], 15) if kind == 'permit_replay' else ([3], 15) if kind == 'runner_replay' else \
                             (list(range(5)), 13) if kind == 'not_yet_wait_entered' else \
                             (list(range(5)), 17) if kind == 'cleanup_already_began' else ([9], 18)
                for index in indices:
                    checkpoints[index].update(count=n, lastSequence=n, eventsSHA256=C.event_prefix_sha(rows, n))
            edit_json(bad, 'native-report.json', change)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_source_call_counts_and_cross_core_identity_are_not_trusted_booleans(self):
        raw, sources, commit = closed_fixture()
        for kind in ('extra_start', 'core_alias', 'identity_alias', 'unsettled', 'false_cleanup',
                     'old_pid_one', 'new_pid_one', 'syntax_pid_one', 'fixture_missing', 'fixture_role',
                     'shutdown_unobserved', 'serve_unjoined', 'fixture_error', 'forced_count_bool', 'forced_count_negative',
                     'probe_missing', 'probe_unattempted', 'probe_connected', 'probe_unsupported', 'probe_alias',
                     'probe_extra_field', 'legacy_report_schema'):
            bad = dict(raw)
            def change(v):
                if kind == 'extra_start': v['nativeCalls'][8]['kind'] = 'KERNEL_OS_START_ATTEMPT'
                elif kind == 'core_alias': v['newCore'] = v['oldCore']
                elif kind == 'identity_alias':
                    v['oldIdentity']['pid'] = v['newIdentity']['pid']
                    v['oldIdentity']['startTicks'] = v['newIdentity']['startTicks']
                elif kind == 'old_pid_one':
                    v['oldIdentity']['pid'] = v['bootstrapStart']['pid'] = 1
                    v['quiescence']['startupIdentity']['pid'] = 1
                elif kind == 'new_pid_one':
                    v['newIdentity']['pid'] = v['start']['startObservation']['pid'] = 1
                    v['start']['startupIdentity']['pid'] = v['start']['verifiedIdentity']['pid'] = 1
                elif kind == 'syntax_pid_one': v['syntax'][0]['pid'] = 1
                elif kind == 'fixture_missing': del v['fixtureCleanup']
                elif kind == 'fixture_role': v['fixtureCleanup'][2]['role'] = 'A'
                elif kind == 'shutdown_unobserved': v['fixtureCleanup'][0]['shutdownReturned'] = False
                elif kind == 'serve_unjoined': v['fixtureCleanup'][1]['serveReturned'] = False
                elif kind == 'fixture_error': v['fixtureCleanup'][2]['errorClass'] = 'SHUTDOWN'
                elif kind == 'forced_count_bool': v['fixtureCleanup'][0]['forcedConnectionsClosed'] = True
                elif kind == 'forced_count_negative': v['fixtureCleanup'][0]['forcedConnectionsClosed'] = -1
                elif kind == 'probe_missing': v['cleanupProbes'].pop()
                elif kind == 'probe_unattempted': v['cleanupProbes'][2]['attempted'] = False
                elif kind == 'probe_connected': v['cleanupProbes'][3]['result'] = 'CONNECTION_ACCEPTED'
                elif kind == 'probe_unsupported': v['cleanupProbes'][2].update(attempted=False, result='OTHER')
                elif kind == 'probe_alias': v['cleanupProbes'][3]['port'] = 28413
                elif kind == 'probe_extra_field': v['cleanupProbes'][0]['unprovedOwner'] = True
                elif kind == 'legacy_report_schema': v['schema'] = 'chengwang.mihomo-native-recovery-experiment/v1'
                elif kind == 'unsettled': v['newCleanup']['groupAbsent'] = False
                else: v['runtimeClosed'] = False
            edit_json(bad, 'native-report.json', change)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_stage_index_and_reopen_relationships_cannot_claim_completion(self):
        raw, sources, commit = closed_fixture()
        for kind in ('completed', 'reopen_phase', 'revision_gap', 'index_hash', 'observation_phase_alias'):
            bad = dict(raw)
            report, index = C.decode(bad['native-report.json']), C.decode(bad['wal-readback-index.json'])
            if kind == 'completed':
                report['stages'][-1]['phase'] = index['stages'][-2]['phase'] = 'COMPLETED'
            elif kind == 'reopen_phase':
                report['reopened']['phase'] = index['stages'][-1]['phase'] = 'START_ARMED'
            elif kind == 'observation_phase_alias':
                report['stages'][3]['phase'] = index['stages'][4]['phase'] = 'QUIESCED'
            elif kind == 'revision_gap':
                report['reopened']['revision'] += 1; index['stages'][-1]['revision'] += 1
            else: index['stages'][-1]['controlSHA256'] = 'a' * 64
            bad['native-report.json'], bad['wal-readback-index.json'] = C.canonical(report), C.canonical(index)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_public_pipe_bytes_and_unsupported_proofs_remain_closed(self):
        raw, sources, commit = closed_fixture()
        for kind in ('stream_bytes', 'full_wal', 'syntax_raw', 'http_completion', 'counter_bool'):
            bad = dict(raw)
            if kind == 'stream_bytes': bad['new-kernel.stdout'] += b'MODEL unexplained byte'
            else:
                def change(v):
                    if kind == 'full_wal': v['fullPrivateWALIndependentlyProven'] = True
                    elif kind == 'syntax_raw': v['syntaxRawStreamsIndependentlyProven'] = True
                    elif kind == 'http_completion': v['completionProven'] = True
                    else: v['reloadFinal']['doInvocations'] = True
                edit_json(bad, 'native-report.json', change)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)
        # Re-sign both the private-summary metadata and its public projection
        # where applicable, so these cases reach semantic/time/source gates
        # rather than only failing a changed outer digest.
        for kind in ('missing_capture', 'body_hash', 'source_revision', 'identity', 'future', 'sample_order',
                     'target_mismatch', 'dataplane', 'proof_replay', 'recollect', 'copied_started', 'copied_proof',
                     'physical_call', 'wal_changed', 'two_round_drift', 'non_eof', 'close_error', 'legacy_v2', 'epoch_age'):
            bad = dict(raw)
            if kind == 'missing_capture': del bad['recovery-s2-body-8.json']
            elif kind == 'body_hash': bad['recovery-s2-body-1.json'] += b' '
            elif kind == 'source_revision': edit_recovery_value(bad, lambda v: v.update(sourceRevision=v['sourceRevision']-1))
            elif kind == 'identity': edit_recovery_value(bad, lambda v: v['startupIdentity'].update(pid=123))
            elif kind == 'future': edit_recovery_value(bad, lambda v: v.update(observedAt='2026-10-25T00:00:14.99Z'))
            elif kind == 'sample_order': edit_recovery_value(bad, lambda v: v['sampleTimes'][1].update(startedAt='2026-10-25T00:00:14.61Z'))
            elif kind == 'target_mismatch': edit_recovery_value(bad, lambda v: v['readback'].update(targetProjectionSHA256='a'*64, observedProjectionSHA256='a'*64))
            elif kind == 'dataplane': edit_recovery_value(bad, lambda v: v['readback'].update(dataplaneProven=True))
            elif kind in ('proof_replay', 'recollect', 'copied_started', 'copied_proof'):
                key = {'proof_replay':'controlProofReplayRejected', 'recollect':'controlRecollectRejected',
                       'copied_started':'controlCopiedStartedRejected', 'copied_proof':'controlCopiedProofRejected'}[kind]
                edit_json(bad, 'native-report.json', lambda v: v.update({key:False}))
            elif kind == 'physical_call':
                edit_json(bad, 'native-report.json', lambda v: v['controlEvents'][1].update(count=15,lastSequence=15,eventsSHA256=C.event_prefix_sha(v['nativeCalls'],15)))
            elif kind == 'wal_changed': edit_json(bad, 'native-report.json', lambda v: v.update(controlAfterSHA256='a'*64))
            elif kind == 'epoch_age':
                # Move every relevant later event/window consistently. Only
                # the absolute Started+30s cap should reject, not a stale
                # prefix hash, cleanup-before-capture or Go-test boundary.
                late = C.decode(bad['native-report.json'])
                for row in late['nativeCalls'][14:]:
                    row['at'] = '2026-10-25T00:00:%02dZ' % (row['sequence']+30)
                for point in late['eventCheckpoints']:
                    point['eventsSHA256'] = C.event_prefix_sha(late['nativeCalls'],point['count'])
                bad['native-report.json'] = C.canonical(late)
                stream = [C.decode(row,elapsed=True)for row in bad['native.json'].splitlines()]
                stream[-2].update(Time='2026-10-25T00:01:10Z',Elapsed=69)
                stream[-1].update(Time='2026-10-25T00:01:11Z',Elapsed=71)
                bad['native.json'] = wire(stream)
                def late_value(v):
                    v.update(entryAt='2026-10-25T00:00:44.1Z',deadline='2026-10-25T00:00:44.95Z',observedAt='2026-10-25T00:00:44.6Z')
                    v['sampleTimes'] = [dict(startedAt='2026-10-25T00:00:44.2Z',completedAt='2026-10-25T00:00:44.3Z'),
                                        dict(startedAt='2026-10-25T00:00:44.4Z',completedAt='2026-10-25T00:00:44.5Z')]
                edit_marker_value(bad, lambda v: v.update(startedAt='2026-10-25T00:00:44.7Z', returnedAt='2026-10-25T00:00:44.8Z'))
                edit_recovery_value(bad, late_value)
            elif kind in ('two_round_drift', 'non_eof', 'close_error'):
                transcript = C.decode(bad['recovery-s2-transcript.json'])
                if kind == 'two_round_drift':
                    body = json.loads(bad['recovery-s2-body-7.json'])
                    body['proxies']['默认策略']['now'] = 'apply-a'
                    bad['recovery-s2-body-7.json'] = GET.wire(body)
                    row = transcript['records'][6]
                    row.update(retainedBytes=len(bad['recovery-s2-body-7.json']), retainedSHA256=C.sha(bad['recovery-s2-body-7.json']),
                               contentLength=len(bad['recovery-s2-body-7.json']))
                    transcript['retainedBytes'] = sum(len(bad[f'recovery-s2-body-{i}.json'])for i in range(1,9))
                elif kind == 'non_eof': transcript['records'][4]['naturalEOF'] = False
                else: transcript['records'][5]['closeErrorClass'] = 'CLOSE_FAILED'
                bad['recovery-s2-transcript.json'] = GET.wire(transcript)
                def rebind(v):
                    v['transcriptSHA256'] = C.sha(bad['recovery-s2-transcript.json'])
                    v['bodySHA256s'] = [C.sha(bad[f'recovery-s2-body-{i}.json'])for i in range(1,9)]
                edit_recovery_value(bad, rebind)
            else: edit_json(bad, 'native-report.json', lambda v: v.update(schema='chengwang.mihomo-native-recovery-experiment/v2'))
            with self.subTest(recovery=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)
        # Bind all changed originals and summary digests before testing the
        # marker's semantic checks; an outer digest mismatch is insufficient.
        mutations = {
            'phase': lambda v: v['route'].update(phase='BASELINE'),
            'role': lambda v: v.update(expectedRole='A'),
            'nonce_zero': lambda v: v['route'].update(nonceSHA256='0'*64),
            'expected_hash': lambda v: v.update(expectedMarkerSHA256='a'*64),
            'expected_bytes': lambda v: v.update(expectedMarkerBytes=v['expectedMarkerBytes']+1),
            'matched_false': lambda v: v['route'].update(matched=False),
            'handler_pending': lambda v: v.update(handlerCompleted=False),
            'client_non_eof': lambda v: v.update(clientNaturalEOF=False),
            'proxy_non_eof': lambda v: v.update(proxyNaturalEOF=False),
            'origin_incomplete': lambda v: v.update(originWriteComplete=False),
            'local_claim_false': lambda v: v.update(localProxyMarkerProven=False),
            'body_partial': lambda v: v['route']['originResponse'].update(complete=False),
            'body_hash': lambda v: v['route']['proxyResponse'].update(sha256='b'*64),
            'body_bytes_bool': lambda v: v['route']['clientResponse'].update(bytes=True),
            'body_field_order': lambda v: v['route'].update(clientResponse=dict(reversed(list(v['route']['clientResponse'].items())))),
            'counter_missing': lambda v: v['route']['countersAfter'].pop(),
            'counter_reordered': lambda v: v['route']['countersAfter'].reverse(),
            'counter_field_order': lambda v: v['route']['countersAfter'].__setitem__(1, dict(reversed(list(v['route']['countersAfter'][1].items())))),
            'counter_bool': lambda v: v['route']['countersBefore'][0].update(rejected=False),
            'counter_rejected': lambda v: v['route']['countersAfter'][1].update(rejected=1),
            'other_role_changed': lambda v: v['route']['countersAfter'][0].update(connectIngress=1),
            'origin_not_observed': lambda v: v['route']['countersAfter'][2].update(originRequests=0),
            'double_tunnel': lambda v: v['route']['countersAfter'][1].update(tunnelRequests=2),
            'counter_negative': lambda v: v['route']['countersBefore'][1].update(originRequests=-1),
            'before_get': lambda v: v.update(startedAt='2026-10-25T00:00:14.79Z'),
            'reversed_time': lambda v: v.update(returnedAt='2026-10-25T00:00:14.8Z'),
            'deadline_equal': lambda v: v.update(returnedAt='2026-10-25T00:00:14.95Z'),
            'future_scope': lambda v: v.update(scope='INTERNET_BUSINESS_PROVEN'),
            'extra_claim': lambda v: v.update(internetBusinessProven=True),
        }
        for name, mutation in mutations.items():
            bad = dict(raw)
            edit_marker_value(bad, mutation)
            with self.subTest(marker=name), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)
        # These four models assert separate closed predicates. They never
        # mint a known cap or claim actual post-write reachability; only the
        # dedicated native CI processes can supply that evidence.
        for mode in C.VARIANTS:
            variant_raw, variant_sources, variant_commit = closed_fixture(mode)
            self.assertEqual(C.verify_raw(variant_raw, variant_sources, variant_commit, mode)['outcome'], 'PASS')
            changes = {
                'replace_front_gate': lambda v:v.update(replaceAttempts=0),
                'replace_twice': lambda v:v.update(replaceAttempts=2),
                'forwarded_write': lambda v:v.update(forwardedWrites=1-v['forwardedWrites']),
                'readback_unreached': lambda v:v.update(postWriteReads=1-v['postWriteReads']),
                'readback_injection': lambda v:v.update(injectedReads=1-v['injectedReads']),
                'delegate_not_committed': lambda v:v.update(underlyingCommitted=not v['underlyingCommitted']),
                'unknown_cap': lambda v:v.update(capKnownBefore=False),
                'unspent_cap': lambda v:v.update(capSpent=False),
                'copy_accepted': lambda v:v.update(capCopyRejected=False),
                'replay_accepted': lambda v:v.update(capReplayRejected=False),
                'wrong_return_status': lambda v:v.update(recordReturnedError=not v['recordReturnedError']),
                'wrong_poison': lambda v:v.update(storePoisoned=not v['storePoisoned']),
                'wrong_adopt': lambda v:v.update(candidateAdopted=not v['candidateAdopted']),
                'wrong_owner_state': lambda v:v.update(liveOwnerCleared=not v['liveOwnerCleared']),
                'transient_restored': lambda v:v.update(transientProofCleared=False),
                'started_restored': lambda v:v.update(retainedStartedCleared=False),
                'source_revision': lambda v:v.update(sourceRevision=v['sourceRevision']+1),
                'memory_revision': lambda v:v.update(memoryRevision=v['memoryRevision']+1),
                'disk_revision': lambda v:v.update(diskRevision=v['diskRevision']+1),
                'wrong_execution_version': lambda v:v.update(executionSchema='chengwang.mihomo-recovery-execution/future'),
                'false_durable_claim': lambda v:v.update(receiptPresent=not v['receiptPresent']),
                'current_advanced': lambda v:v.update(diskCurrentSHA256='a'*64),
                'completion': lambda v:v.update(completionAbsent=False),
                'physical_dispatch': lambda v:v.update(noNewPhysicalCalls=False),
                'full_private_receipt': lambda v:v.update(fullPrivateReceiptIndependentlyProven=True),
                'returned_before_attempt': lambda v:v.update(returnedAt='2026-10-25T00:00:14.9Z'),
                'extra_secret_field': lambda v:v.update(sourceOwner={'ownerNonce':'MODEL_NOT_DISCLOSABLE'}),
            }
            if mode != 'not-committed':
                changes.update(observation_digest=lambda v:v.update(observationSHA256='a'*64),
                               preimage_digest=lambda v:v.update(s1PreimageSHA256='b'*64),
                               receipt_revision=lambda v:v.update(verificationCommitRevision=v['verificationCommitRevision']+1),
                               recorded_time=lambda v:v.update(recordedAt='2026-10-25T00:00:14.92Z'))
            else:
                changes['fabricated_receipt'] = lambda v:v.update(receiptSHA256='a'*64)
            for name, change in changes.items():
                bad = dict(variant_raw);edit_record_projection(bad,change)
                with self.subTest(variant=mode,record=name), self.assertRaises(ValueError):
                    C.verify_raw(bad,variant_sources,variant_commit,mode)
            for name in ('mode_mismatch','missing_original','execution_mode','sandbox_mode','go_mode','reopen_cap','reopen_fact','event_prefix'):
                bad=dict(variant_raw)
                if name=='mode_mismatch':
                    edit_record_projection(bad,lambda v:v.update(mode=next(x for x in C.VARIANTS if x!=mode)))
                elif name=='missing_original':del bad[C.RECORD_PUBLIC]
                elif name=='execution_mode':edit_json(bad,'execution.json',lambda v:v.update(verificationMode='invalid'))
                elif name=='sandbox_mode':edit_json(bad,'sandbox.json',lambda v:v.update(verificationMode='invalid'))
                elif name=='go_mode':
                    rows=[C.decode(line)for line in bad['commands.jsonl'].splitlines()]
                    rows[-1]['argv'][-1]='-chengwang-native-verification-mode=invalid'
                    bad['commands.jsonl']=wire(rows)
                elif name=='reopen_cap':edit_json(bad,'native-report.json',lambda v:v.update(reopenedRecordCapabilityAbsent=False))
                elif name=='reopen_fact':edit_json(bad,'native-report.json',lambda v:v.update(reopenedExecutionPreserved=False))
                else:edit_json(bad,'native-report.json',lambda v:v['verificationEvents'][1].update(count=15,lastSequence=15,eventsSHA256=C.event_prefix_sha(v['nativeCalls'],15)))
                with self.subTest(variant=mode,record=name),self.assertRaises(ValueError):
                    C.verify_raw(bad,variant_sources,variant_commit,mode)
            other=next(x for x in C.VARIANTS if x!=mode)
            with self.subTest(variant=mode,requested=other),self.assertRaises(ValueError):
                C.verify_raw(variant_raw,variant_sources,variant_commit,other)
        for name in ('missing', 'raw_tamper', 'legacy_control_schema', 'summary_marker_hash', 'summary_marker_payload', 'copied_fixture'):
            bad = dict(raw)
            if name == 'missing': del bad['recovery-s2-local-marker.json']
            elif name == 'raw_tamper': bad['recovery-s2-local-marker.json'] += b' '
            elif name == 'legacy_control_schema': edit_recovery_value(bad, lambda v: v.update(schema='chengwang.mihomo-recovery-control-observation/v1'))
            elif name == 'summary_marker_hash': edit_recovery_value(bad, lambda v: v.update(localMarkerSHA256='d'*64))
            elif name == 'copied_fixture': edit_json(bad, 'native-report.json', lambda v: v.update(localCopiedFixtureRejected=False))
            else: edit_recovery_value(bad, lambda v: v['localPath'].update(localProxyMarkerProven=False))
            with self.subTest(marker=name), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)


if __name__ == '__main__':
    unittest.main()
