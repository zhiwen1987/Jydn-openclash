#!/usr/bin/env python3
"""Capture a distinct actual native Started-record experiment; import starts nothing.

This is a proposed producer, not a checker or CI acceptance. It deliberately
does not rename the existing UNKNOWN acceptance as recovery. Fresh independent
checker/workflow wiring is not supplied by this initial source-only candidate.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

SCOPE = 'ACTUAL_OWNED_KERNEL_RECOVERY_STARTED_RECORD_NOT_HTTP_COMPLETION_OR_PRODUCTION'
ROOT = Path('/tmp/chengwang-mihomo-recovery-private')
TAGS = ('chengwang_mihomo_service', 'chengwang_mihomo_faults', 'chengwang_mihomo_recovery_native')
TOP = 'TestLabRecoveryNativeUnknownStartedReplayReopenAndOwnedCleanup'
STAGES = ('planned', 'approved', 'stop-armed', 'quiesced', 'start-armed', 'started', 'verification-attempted')
VARIANTS = ('positive', 'not-committed', 'unknown', 'readback')
OUTPUT_MODES = {'mihomo-native-recovery-public': 'positive',
                **{'mihomo-native-recovery-'+mode+'-public': mode for mode in VARIANTS[1:]}}
RECORD_PUBLIC = 'recovery-s2-record.json'
RECOVERY_CAPTURE = ('transcript.json', *(f'body-{i}.json' for i in range(1, 9)), 'verification.json', 'local-marker.json')
RECOVERY_PUBLIC = tuple('recovery-s2-'+name for name in RECOVERY_CAPTURE)
FMT = tuple('internal/mihomodeploy/'+name for name in (
    'lab_bootstrap.go', 'lab_kernel_linux.go', 'lab_quiescence_linux.go',
    'lab_recovery_start_linux.go', 'lab_syntax_linux.go',
    'lab_native_recovery_observer_default.go', 'lab_native_recovery_observer_linux.go',
    'lab_native_recovery_linux.go', 'lab_native_recovery_linux_test.go',
    'lifecycle_recovery_checkpoint.go', 'lifecycle_recovery_completion.go',
    'lifecycle_recovery_completion_test.go', 'lifecycle_completion_shape_diagnostic_test.go',
    'lifecycle_v3_decode_scope_test.go',
    'lifecycle_current_epoch.go',
    'lifecycle_current_epoch_test.go', 'lab_current_epoch_runtime.go',
    'lab_current_epoch_runtime_test.go')) + (
    'internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
    'internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
    'internal/mihomodeploy/lab_service.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'internal/serverruntime/runtime.go',
    'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go')
PREEXISTING = ('host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json')
PRODUCED = ('native-report.json', 'wal-readback-index.json', 'old-kernel.stdout', 'old-kernel.stderr',
            'new-kernel.stdout', 'new-kernel.stderr', 'sandbox.json', 'execution.json',
            'go-version.txt', 'gofmt.patch', 'gofmt.stderr', 'native.json', 'native.stderr',
            'commands.jsonl', 'process-events.jsonl', *RECOVERY_PUBLIC, RECORD_PUBLIC)
_ADAPTER = None
_STATE = None

CHECKPOINTS = ('before-permit-cap-replay', 'after-permit-cap-replay', 'before-runner-replay', 'after-runner-replay',
               'before-cleanup', 'after-cleanup', 'before-cleanup-replay', 'after-cleanup-replay', 'before-reopen', 'after-reopen')
COMMAND_CLASSES = ('SANDBOX', 'GO_VERSION', 'GOFMT', 'GO_TEST')
COMMAND_KEYS = ('schema', 'sequence', 'sourceCommit', 'commandClass', 'argv', 'cwd', 'timeoutSeconds', 'exitCode', 'observed', 'namespace')


def need(value):
    if not value:
        raise ValueError('isolated native recovery capture rejected')


def adapter():
    global _ADAPTER
    if _ADAPTER is None:
        # Reuse only fixed source namespace/custody/capture helpers. Do not
        # mutate old module globals, old acceptance result or old contracts.
        path = Path(__file__).absolute().with_name('service_worker.py')
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
        spec = importlib.util.spec_from_file_location('_native_fixed_service_helpers', path)
        need(spec is not None and spec.loader is not None)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _ADAPTER = mod
    return _ADAPTER


def contract():
    s = adapter(); w = s.adapter().shared()
    value = w.decode(w.file_bytes(Path(__file__).absolute().with_name('native_recovery_contract.json'), 64 << 10)[0])
    expected = dict(schema='chengwang.mihomo-native-recovery-contract/v5', scope=SCOPE,
        tags=list(TAGS), goPackage='./internal/mihomodeploy', topTests=[TOP],
        goTimeoutSeconds=75, outerGoTimeoutSeconds=90, privateRoot=str(ROOT),
        identityRoot=str(s.IDENTITIES), servicePrivateRoot=str(s.ROOT), stateRoot=str(s.STATE),
        stages=list(STAGES), reopenStage='reopened', counterEventLimit=256,
        cleanupPorts=[28411, 28412, 28413, 28414, 28415], fixtureRoles=['origin', 'A', 'B'],
        cleanupProbeKeys=['port', 'attempted', 'result'],
        fixtureCleanupKeys=['role', 'shutdownReturned', 'serveReturned', 'forcedConnectionsClosed', 'errorClass'],
        recoveryCaptureStage='recovery-s2', recoveryCaptureFiles=list(RECOVERY_CAPTURE),
        recoveryCaptureMaxBytes=2 << 20, recoveryCaptureBodyBytes=256 << 10, recoveryVerificationBytes=64 << 10,
        recoveryControlOnly=False, recoveryLocalMarkerOnly=True, recoveryLocalMarkerBytes=64 << 10,
        recoveryLocalMarkerSchema='chengwang.mihomo-recovery-local-marker/v1',
        recoveryLocalMarkerPhase='RECOVERY_NEW_EPOCH_MARKER',
        recoveryLocalMarkerScope='ACTUAL_LOOPBACK_PROXY_MARKER_NOT_INTERNET_BUSINESS_OR_AUTHORIZATION',
        localMarkerBodyIndependentlyProven=False,
        verificationModes=list(VARIANTS), verificationRecordPublic=RECORD_PUBLIC,
        verificationRecordSchema='chengwang.mihomo-native-verification-record/v1',
        verificationRecordScope='REDACTED_ACTUAL_WAL_FACT_NOT_AUTHORIZATION_OR_COMPLETE_PRIVATE_RECEIPT',
        verificationRecordMaxBytes=64 << 10,
        eventCheckpoints=list(CHECKPOINTS), eventCheckpointKeys=['stage', 'count', 'lastSequence', 'eventsSHA256'],
        eventPrefixEncoding='Go-json.Marshal([]labNativeRecoveryCall)-sequence-kind-core-at-no-newline',
        commandReceiptSchema='chengwang.mihomo-native-command-receipt/v1', commandReceiptKeys=list(COMMAND_KEYS),
        commandClasses=list(COMMAND_CLASSES), commandReceiptLimit=4,
        processEventsSchema='chengwang.mihomo-apply-private-process-event/v1', processEventLimit=64,
        maxPublicBytes=16 << 20, production=False, httpRecoveryProven=False, completionProven=False,
        syntaxRawStreamsIndependentlyProven=False)
    need(w.canonical(value) == w.canonical(expected))
    return value


def append_command(state, row):
    a = adapter().adapter(); w = a.shared()
    need(type(row) is dict and set(row) == set(COMMAND_KEYS) and row['sequence'] == state.get('nativeCommandSequence', 0)+1 and
         1 <= row['sequence'] <= 4 and row['commandClass'] == COMMAND_CLASSES[row['sequence']-1])
    data = w.canonical(row)
    path = a.ROOT_PRIVATE/'native-commands.private.jsonl'
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    if row['sequence'] == 1:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size+len(data) <= 64 << 10)
        identity = (info.st_dev, info.st_ino)
        if row['sequence'] == 1:
            state['nativeCommandIdentity'] = identity
        need(state['nativeCommandIdentity'] == identity)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            need(written > 0)
            view = view[written:]
        os.fsync(fd)
        named = path.lstat()
        need((named.st_dev, named.st_ino) == identity and named.st_nlink == 1 and
             named.st_uid == named.st_gid == 0 and stat.S_IMODE(named.st_mode) == 0o600)
        state['nativeCommandSequence'] = row['sequence']
    finally:
        os.close(fd)
    if row['sequence'] == 1:
        directory = os.open(a.ROOT_PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def capture_actual(state, argv, name, err_name, timeout):
    # Capture exactly the same tuple actually passed to the existing owned
    # subprocess primitive. Its fixed Popen cwd is a.PATHS['module']; its
    # child wrapper drops credentials/capabilities without unsharing NSes.
    # The unchanged process-event trace independently supplies PID/reference/
    # Wait/exit originals, rather than trusting this receipt's observed bool.
    a = adapter().adapter(); w = a.shared()
    actual = tuple(argv)
    need(actual and len(actual) <= 64 and all(type(arg) is str and 0 < len(arg) <= 4096 for arg in actual))
    classes = {'sandbox.private.json': 'SANDBOX', 'go-version.txt': 'GO_VERSION', 'gofmt.patch': 'GOFMT', 'apply.json': 'GO_TEST'}
    need(name in classes and type(timeout) is int and 0 < timeout <= 90)
    namespaces = w.namespace_values()
    sequence = state.get('nativeCommandSequence', 0)+1
    observed, code = False, None
    try:
        code = a.capture(state, actual, name, err_name, timeout)
        observed = True
        return code
    finally:
        append_command(state, dict(schema='chengwang.mihomo-native-command-receipt/v1', sequence=sequence,
            sourceCommit=state['commit'], commandClass=classes[name], argv=list(actual), cwd=a.PATHS['module'],
            timeoutSeconds=timeout, exitCode=code if observed else None, observed=observed, namespace=namespaces))


def command_outputs():
    a = adapter().adapter(); w = a.shared(); outputs = {}
    for public, original in [('commands.jsonl', 'native-commands.private.jsonl'), ('process-events.jsonl', 'process-events.private.jsonl')]:
        data, info = w.file_bytes(a.ROOT_PRIVATE/original, 64 << 10, 0o600)
        need(info.st_uid == info.st_gid == 0)
        outputs[public] = data
    return outputs


def native_base(create):
    if create:
        ROOT.mkdir(mode=0o700)
        os.chown(ROOT, 10001, 10001)
    info = ROOT.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
         info.st_uid == info.st_gid == 10001 and not any(ROOT.iterdir()))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def disclosure_inputs():
    s = adapter(); a = s.adapter(); w = a.shared()
    tokens = w.decode(s.private_file(ROOT/'tokens.private.json', 16 << 10))
    need(type(tokens) is dict and set(tokens) == {'initiator', 'approver', 'viewer'} and
         all(type(v) is str and 32 <= len(v) <= 512 for v in tokens.values()))
    values = list(tokens.values())
    private_path = s.ROOT/'.secrets.private.json'
    if private_path.exists():
        private = w.decode(s.private_file(private_path, 4096))
        need(set(private) == {'schema', 'controller', 'routeA', 'routeB'} and
             private['schema'] == 'chengwang.mihomo-lab-service-private-secrets/v1')
        values.extend((private['controller'], private['routeA'], private['routeB']))
    configs = [s.private_file(s.ROOT/name, 1 << 20) for name in
               ('local-a.config.private.yaml', 'local-b.config.private.yaml') if (s.ROOT/name).exists()]
    profile = s.private_file(s.IDENTITIES/'credentials.json', 1 << 20)
    return a.safe_variants([v.encode() for v in values], [*configs, profile])


def private_outputs(commit):
    s = adapter(); w = s.adapter().shared(); forbidden = disclosure_inputs()
    raw = s.private_file(ROOT/'native-report.private.json', 1 << 20)
    report = w.decode(raw)
    need(report['schema'] == 'chengwang.mihomo-native-recovery-experiment/v5' and
         report['scope'] == SCOPE and report['sourceCommit'] == commit and
         report['outcome'] in ('PASS', 'FAIL') and type(report['nativeCalls']) is list and len(report['nativeCalls']) <= 256)
    # Public evidence does not include owner nonce/raw WAL. The Go test's
    # original strict decoder already checked it; this index adds bounded
    # byte/relationship observations, not independent complete WAL proof.
    index = []
    for name in ('legacy', *STAGES, 'reopened'):
        path = ROOT/(name+'-control.private.json')
        if not path.exists():
            need(report['outcome'] == 'FAIL')
            index.append(dict(stage=name, present=False))
            continue
        data = s.private_file(path, 2 << 20)
        value = w.decode(data)
        need(type(value) is dict and type(value['revision']) is int and value['revision'] > 0)
        row = dict(stage=name, bytes=len(data), controlSHA256=sha(data),
                   schema=value['schema'], revision=value['revision'], recordSHA256=value['recordSHA256'])
        if name != 'legacy':
            need(value['schema'] == 'chengwang.mihomo-lifecycle-record/v3' and
                 type(value['sourceV2']) is dict)
            source = base64.b64decode(value['sourceV2']['controlBytes'], validate=True)
            legacy = s.private_file(ROOT/'legacy-control.private.json', 2 << 20)
            need(source == legacy and value['sourceV2']['controlSHA256'] == sha(legacy))
            row['phase'] = value['recovery']['phase']
            row['headSHA256'] = value['current']['head']['headSHA256']
        index.append(row)
    outputs = {'native-report.json': raw, 'wal-readback-index.json': w.canonical(dict(
        schema='chengwang.mihomo-native-wal-readback-index/v2', scope=SCOPE, sourceCommit=commit,
        stages=index, fullPrivateWALIndependentlyProven=False, production=False))}
    for public, path in [('old-kernel.stdout', s.ROOT/'kernel.stdout'), ('old-kernel.stderr', s.ROOT/'kernel.stderr'),
                         ('new-kernel.stdout', ROOT/'new-kernel.stdout'), ('new-kernel.stderr', ROOT/'new-kernel.stderr')]:
        if not path.exists():
            need(report['outcome'] == 'FAIL')
            continue
        outputs[public] = s.private_file(path, 64 << 10, empty=True)
    # Fixed originals from this one real bounded capture; never a second GET
    # or a blind directory export. Existing disclosure checks below apply to
    # every retained byte, including captured HTTP entities and transcript.
    capture_bytes = 0
    for name, public in zip(RECOVERY_CAPTURE, RECOVERY_PUBLIC):
        path = s.ROOT/'recovery-s2'/name
        if not path.exists():
            need(report['outcome'] == 'FAIL')
            continue
        limit = 64 << 10 if name in ('verification.json', 'local-marker.json') else 256 << 10 if name.startswith('body-') else 2 << 20
        data = s.private_file(path, limit)
        capture_bytes += len(data)
        need(capture_bytes <= 2 << 20)
        outputs[public] = data
    record_path = ROOT/'verification-record.private.json'
    if record_path.exists():
        data = s.private_file(record_path, 64 << 10)
        need(capture_bytes + len(data) <= 2 << 20)
        outputs[RECORD_PUBLIC] = data
    else:
        need(report['outcome'] == 'FAIL')
    for data in outputs.values():
        s.disclosure(data, forbidden)
    return outputs, forbidden, report


def go_terminal(raw):
    # Capture may only claim a completed selected test when its original Go
    # stream independently contains the exact run/pass and package terminal.
    rows = [json.loads(line) for line in raw.splitlines() if line]
    need(rows and all(type(row) is dict for row in rows))
    relevant = [row for row in rows if row.get('Test') == TOP]
    need(sum(row.get('Action') == 'run' for row in relevant) == 1 and
         sum(row.get('Action') == 'pass' for row in relevant) == 1)
    need(not any(row.get('Action') in ('fail', 'skip') for row in rows))
    packages = [row for row in rows if 'Test' not in row and row.get('Action') == 'pass']
    need(len(packages) == 1 and packages[0].get('Package') == 'chengwang/internal/mihomodeploy')
    need(all(row.get('Test', TOP).split('/')[0] == TOP for row in rows))


def compile_failure_originals(state, facts):
    # No test/profile/bootstrap/private fence has run when all four fixed
    # runtime roots remain empty. Preserve compiler/format originals in that
    # finite case; no report/control/cleanup success is fabricated.
    s = adapter(); a = s.adapter(); w = a.shared()
    need(state['goExit'] != 0 and all(not any(path.iterdir()) for path in (ROOT, s.ROOT, s.IDENTITIES, s.STATE)))
    outputs = command_outputs()
    for public, original in [('go-version.txt', 'go-version.txt'), ('gofmt.patch', 'gofmt.patch'),
                             ('gofmt.stderr', 'gofmt.stderr'), ('native.json', 'apply.json'), ('native.stderr', 'apply.stderr')]:
        outputs[public] = w.file_bytes(a.ROOT_PRIVATE/original, 8 << 20, empty=True)[0]
    outputs['sandbox.json'] = w.canonical(facts)
    outputs['execution.json'] = w.canonical(dict(schema='chengwang.mihomo-native-recovery-execution/v2', scope=SCOPE, verificationMode=state['verificationMode'],
        sourceCommit=state['commit'], formatExit=state['formatExit'], goExit=state['goExit'],
        captureState='INCOMPLETE_EMPTY_PRIVATE_RUNTIME_ROOTS_NOT_ACCEPTED', production=False))
    a.unchanged_public(state)
    for name, data in outputs.items():
        w.write_new(a.EXPORT_ALIAS/name, data, 0o644)
    a.sync_output(state); a.unchanged_public(state)
    need(not state['pending'])
    return 1


def main(args):
    global _STATE
    s = adapter(); a = s.adapter(); w = a.shared(); c = contract()
    if len(args) == 4 and args[0] == '--sandbox':
        need(args[3] in VARIANTS)
        facts = a.sandbox(args[1], args[2])
        s.bases(False); native_base(False)
        facts['serviceBases'] = [str(s.ROOT), str(s.IDENTITIES), str(s.STATE)]
        facts['schema'] = 'chengwang.mihomo-native-recovery-sandbox/v2'
        facts['verificationMode'] = args[3]
        print(w.canonical(facts).decode('ascii'), end='')
        return 0
    need(len(args) == 5)
    mode = OUTPUT_MODES.get(Path(args[1]).name)
    need(mode in VARIANTS)
    state = a.prepare_namespace(*args); _STATE = state
    state['verificationMode'] = mode
    s.bases(True); native_base(True)
    worker = a.PATHS['module']+'/deploy/mihomo-lifecycle-lab/native_recovery_worker.py'
    code = capture_actual(state, [w.tool('python3'), '-B', worker, '--sandbox', state['commit'], state['moduleSHA256'], mode],
                     'sandbox.private.json', 'sandbox.private.stderr', 30)
    need(code == 0 and w.file_bytes(a.ROOT_PRIVATE/'sandbox.private.stderr', 4096, empty=True)[0] == b'')
    facts = w.decode(w.file_bytes(a.ROOT_PRIVATE/'sandbox.private.json', 64 << 10)[0])
    need(facts['schema'] == 'chengwang.mihomo-native-recovery-sandbox/v2' and facts['verificationMode'] == mode)
    need(capture_actual(state, [a.PATHS['goRoot']+'/bin/go', 'version'], 'go-version.txt', 'go-version.private.stderr', 15) == 0)
    need(w.file_bytes(a.ROOT_PRIVATE/'go-version.private.stderr', 4096, empty=True)[0] == b'')
    state['formatExit'] = capture_actual(state, [a.PATHS['goRoot']+'/bin/gofmt', '-d', *FMT], 'gofmt.patch', 'gofmt.stderr', 30)
    argv = [a.PATHS['goRoot']+'/bin/go', 'test', '-json', '-count=1', '-shuffle=off', '-p=1',
            '-tags='+','.join(TAGS), '-run=^'+TOP+'$', '-timeout=75s', './internal/mihomodeploy',
            '-args', '-chengwang-native-verification-mode='+mode]
    state['goExit'] = capture_actual(state, argv, 'apply.json', 'apply.stderr', c['outerGoTimeoutSeconds'])
    after, _, directory = w.custody(state['consumed'])
    need(after == state['inputBefore'] and directory == state['originalDirectory'])
    facts['inputCustody'] = dict(before=state['inputBefore'], after=after)
    if not (ROOT/'native-report.private.json').exists():
        return compile_failure_originals(state, facts)
    outputs, forbidden, report = private_outputs(state['commit'])
    need(report['verificationMode'] == mode)
    commands = command_outputs()
    for raw in commands.values():
        s.disclosure(raw, forbidden)
    outputs.update(commands)
    for public, original in [('go-version.txt', 'go-version.txt'), ('gofmt.patch', 'gofmt.patch'),
                             ('gofmt.stderr', 'gofmt.stderr'), ('native.json', 'apply.json'), ('native.stderr', 'apply.stderr')]:
        data = w.file_bytes(a.ROOT_PRIVATE/original, 8 << 20, empty=True)[0]
        s.disclosure(data, forbidden)
        outputs[public] = data
    outputs['sandbox.json'] = w.canonical(facts)
    outputs['execution.json'] = w.canonical(dict(schema='chengwang.mihomo-native-recovery-execution/v2', scope=SCOPE, verificationMode=mode,
        sourceCommit=state['commit'], formatExit=state['formatExit'], goExit=state['goExit'],
        captureState='CAPTURED_NOT_INDEPENDENT_ACCEPTANCE', production=False))
    need(set(outputs) <= set(PRODUCED) and sum(map(len, outputs.values())) <= c['maxPublicBytes'])
    if report['outcome'] == 'PASS':
        need(set(outputs) == set(PRODUCED))
    a.unchanged_public(state)
    for name, data in outputs.items():
        w.write_new(a.EXPORT_ALIAS/name, data, 0o644)
    a.sync_output(state); a.unchanged_public(state)
    need(not state['pending'])
    if state['formatExit'] != 0 or state['goExit'] != 0 or outputs['gofmt.patch'] or outputs['gofmt.stderr'] or report['outcome'] != 'PASS':
        return 1
    go_terminal(outputs['native.json'])
    print('NATIVE_STARTED_ORIGINALS=CAPTURED independent_acceptance=false production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        # Keep private raw Go outputs and actual owned-process state; never
        # invent a report, exit code, missing control file or cleanup success.
        if _STATE is not None:
            a = adapter().adapter(); w = a.shared()
            if not (a.EXPORT_ALIAS/'native-worker-failure.json').exists():
                w.write_new(a.EXPORT_ALIAS/'native-worker-failure.json', w.canonical(dict(
                    schema='chengwang.mihomo-native-recovery-worker-failure/v1',
                    sourceCommit=_STATE['commit'], failureCode='NATIVE_CAPTURE_REJECTED',
                    independentAcceptance=False, rawOutputSuppressed=True)), 0o644)
        print('NATIVE_STARTED_ORIGINALS=REJECTED raw_output_suppressed=true', file=sys.stderr)
        raise SystemExit(1)
