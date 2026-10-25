"""Synthetic independent-reader tests; they never run Go, HTTP or a worker."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

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


def closed_fixture():
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
    sandbox = dict(schema='chengwang.mihomo-native-recovery-sandbox/v1', sourceCommit=commit, uid=10001, gid=10001,
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
    checkpoint = lambda row: {k: row[k] for k in ('stage', 'controlSHA256', 'recordSHA256', 'revision', 'phase')}
    syntax = dict(attempted=True, started=True, pid=125, startTicks=None, waitReturned=True, waitErrorClass='NONE',
                  exitCode=0, signal=None, termSent=False, killSent=False, groupAbsent=True,
                  stdout=stream_meta(b'MODEL unexported syntax output'), stderr=stream_meta(b''))
    report = dict(schema='chengwang.mihomo-native-recovery-experiment/v1', scope=C.SCOPE, sourceCommit=commit,
                  outcome='PASS', failureCode='NONE', originalUnknown=unknown,
                  fault=dict(schema='chengwang.mihomo-reload-response-loss-observation/v1', state='INJECTED', claimed=True,
                             underlyingRoundTrips=1, statusCode=204, bodyBytes=0, eofObserved=True, closeSucceeded=True,
                             injected=True, failureCode=None), reloadBefore=dict(reloadInvocations=0, doInvocations=0),
                  reloadUnknown=dict(reloadInvocations=1, doInvocations=1), reloadFinal=dict(reloadInvocations=1, doInvocations=1),
                  oldIdentity=old, newIdentity=new, bootstrapStart=started(old), oldCore=1, newCore=2, quiescence=q,
                  start=start, startedSHA256=hashed('started fact'), stages=[checkpoint(row) for row in index[1:7]],
                  replayRejected=True, recoverySelfApprovalDenied=True, reopened=checkpoint(index[-1]), oldCleanup=oldexit,
                  newCleanup=newexit, syntax=[syntax], nativeCalls=native, eventCheckpoints=checkpoints,
                  dualOwnerCloseRejectedTwice=True, countersBounded=True, closedPorts=[28411, 28412, 28413, 28414, 28415],
                  runtimeClosed=True, newDiskOwnerClosed=True, cleanupReplayNoOp=True, httpRecoveryProven=False,
                  completionProven=False, fullPrivateWALIndependentlyProven=False, syntaxRawStreamsIndependentlyProven=False,
                  internetBusinessProven=False, production=False)
    commands = []
    cw, gr = '/tmp/mihomo-apply-source', '/tmp/mihomo-apply-go'
    argv = [["/usr/bin/python3", '-B', cw + '/deploy/mihomo-lifecycle-lab/native_recovery_worker.py', '--sandbox', commit, C.sha(sources['chengwang/go.mod'])],
            [gr + '/bin/go', 'version'], [gr + '/bin/gofmt', '-d', *C.FMT],
            [gr + '/bin/go', 'test', '-json', '-count=1', '-shuffle=off', '-p=1', '-tags=' + ','.join(C.TAGS), '-run=^' + C.TOP + '$', '-timeout=75s', './internal/mihomodeploy']]
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
                'wal-readback-index.json': C.canonical(dict(schema='chengwang.mihomo-native-wal-readback-index/v1',
                    scope=C.SCOPE, sourceCommit=commit, stages=index, fullPrivateWALIndependentlyProven=False, production=False)),
                'old-kernel.stdout': oldraw, 'new-kernel.stdout': newraw, 'sandbox.json': C.canonical(sandbox),
                'execution.json': C.canonical(dict(schema='chengwang.mihomo-native-recovery-execution/v1', scope=C.SCOPE,
                    sourceCommit=commit, formatExit=0, goExit=0, captureState='CAPTURED_NOT_INDEPENDENT_ACCEPTANCE', production=False)),
                'go-version.txt': b'go version go1.23.12 linux/amd64\n', 'native.json': wire(go_fixture()),
                'commands.jsonl': wire(commands), 'process-events.jsonl': wire(process),
                'source-before.json': C.canonical(manifest), 'source-after.json': C.canonical(manifest)})
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
        for key in ('sourceGitVerified', 'fullPrivateWALIndependentlyProven', 'syntaxRawStreamsIndependentlyProven',
                    'privateDisclosureFenceIndependentlyProven', 'completeKernelSyscallTracingProven', 'completionProven', 'production'):
            self.assertIs(value[key], False)
        self.assertIsNone(value['controllerReceivedCount'])

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
                     'old_pid_one', 'new_pid_one', 'syntax_pid_one'):
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
                elif kind == 'unsettled': v['newCleanup']['groupAbsent'] = False
                else: v['runtimeClosed'] = False
            edit_json(bad, 'native-report.json', change)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.verify_raw(bad, sources, commit)

    def test_stage_index_and_reopen_relationships_cannot_claim_completion(self):
        raw, sources, commit = closed_fixture()
        for kind in ('completed', 'reopen_phase', 'revision_gap', 'index_hash'):
            bad = dict(raw)
            report, index = C.decode(bad['native-report.json']), C.decode(bad['wal-readback-index.json'])
            if kind == 'completed':
                report['stages'][-1]['phase'] = index['stages'][-2]['phase'] = 'COMPLETED'
            elif kind == 'reopen_phase':
                report['reopened']['phase'] = index['stages'][-1]['phase'] = 'START_ARMED'
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


if __name__ == '__main__':
    unittest.main()
