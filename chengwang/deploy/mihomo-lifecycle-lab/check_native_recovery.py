"""Independent public native-Started data reader; no producer/worker imports.

Fixed source-owned originals are checked independently of the producer.
Component validators never execute native I/O or infer Internet capability.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

SCOPE = 'ACTUAL_OWNED_KERNEL_RECOVERY_STARTED_RECORD_NOT_HTTP_COMPLETION_OR_PRODUCTION'
BOUNDARY = 'OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF'
TOP = 'TestLabRecoveryNativeUnknownStartedReplayReopenAndOwnedCleanup'
PACKAGE = 'chengwang/internal/mihomodeploy'
PREFIX = 'chengwang/deploy/mihomo-lifecycle-lab/'
TAGS = ('chengwang_mihomo_service', 'chengwang_mihomo_faults', 'chengwang_mihomo_recovery_native')
STAGES = ('planned', 'approved', 'stop-armed', 'quiesced', 'start-armed', 'started', 'verification-attempted')
PHASES = ('PLANNED', 'APPROVED', 'STOP_ARMED', 'OLD_EPOCH_QUIESCED', 'START_ARMED', 'START_ARMED', 'START_ARMED')
VARIANTS = ('positive', 'not-committed', 'unknown', 'readback')
RECORD_PUBLIC = 'recovery-s2-record.json'
STREAM_KEYS = ('bytes', 'totalBytes', 'sha256', 'truncated', 'complete')
IDENTITY_KEYS = ('pid', 'startTicks', 'netNSInode', 'elfSHA256', 'elfBytes', 'sourceCommit',
                 'artifactSHA256', 'controllerPort', 'mixedPort')
START_KEYS = ('attempted', 'started', 'pid', 'startTicks', 'waitReturned', 'waitErrorClass',
              'exitCode', 'signal', 'termSent', 'killSent', 'groupAbsent', 'stdout', 'stderr')
EXIT_KEYS = ('started', 'waitReturned', 'waitErrorClass', 'exitCode', 'signal', 'termSent',
             'killSent', 'groupAbsent', 'stdout', 'stderr')
CALL_KINDS = ('KERNEL_OS_START_ATTEMPT', 'KERNEL_OS_START_RETURN', 'KERNEL_OS_WAIT_ENTER',
              'KERNEL_OS_WAIT_RETURN', 'OWNED_STOP_HELPER_ENTER', 'KERNEL_OS_TERM_ATTEMPT',
              'KERNEL_OS_TERM_RETURN', 'KERNEL_OS_KILL_ATTEMPT', 'KERNEL_OS_KILL_RETURN',
              'RECOVERY_STOP_DISPATCH', 'RECOVERY_START_DISPATCH',
              'SYNTAX_OS_START_ATTEMPT', 'SYNTAX_OS_START_RETURN')
EVENT_STAGES = ('before-permit-cap-replay', 'after-permit-cap-replay',
                'before-runner-replay', 'after-runner-replay',
                'before-cleanup', 'after-cleanup',
                'before-cleanup-replay', 'after-cleanup-replay',
                'before-reopen', 'after-reopen')
COMMAND_CLASSES = ('SANDBOX', 'GO_VERSION', 'GOFMT', 'GO_TEST')
COMMAND_KEYS = ('schema', 'sequence', 'sourceCommit', 'commandClass', 'argv', 'cwd',
                'timeoutSeconds', 'exitCode', 'observed', 'namespace')
NS_KEYS = ('networkNamespace', 'mountNamespace', 'pidNamespace')
ENV = ('CGO_ENABLED', 'CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT', 'GOCACHE', 'GOENV', 'GOFLAGS',
       'GOMODCACHE', 'GOPROXY', 'GOROOT', 'GOSUMDB', 'GOTOOLCHAIN', 'HOME', 'LANG', 'LC_ALL',
       'PATH', 'TMPDIR', 'TZ')
FMT = tuple('internal/mihomodeploy/' + name for name in (
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
    'internal/authn/continuous_bound_credentials_linux.go',
    'internal/authn/continuous_bound_credentials_linux_test.go',
    'internal/authn/store.go',
    'internal/mihomodeploy/lab_service.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'internal/serverruntime/runtime.go',
    'internal/serverruntime/mihomo_lab_runtime.go',
    'internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go')
RECOVERY_CAPTURE = ('transcript.json', *(f'body-{i}.json' for i in range(1, 9)), 'verification.json', 'local-marker.json')
RECOVERY_PUBLIC = tuple('recovery-s2-'+name for name in RECOVERY_CAPTURE)
PUBLIC = ('host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json',
          'native-report.json', 'wal-readback-index.json', 'old-kernel.stdout', 'old-kernel.stderr',
          'new-kernel.stdout', 'new-kernel.stderr', 'sandbox.json', 'execution.json', 'go-version.txt',
          'gofmt.patch', 'gofmt.stderr', 'native.json', 'native.stderr', 'commands.jsonl', 'process-events.jsonl',
          'source-before.json', 'source-after.json', *RECOVERY_PUBLIC, RECORD_PUBLIC)
REPORT_KEYS = ('schema', 'verificationMode', 'scope', 'sourceCommit', 'outcome', 'failureCode', 'originalUnknown', 'fault',
               'reloadBefore', 'reloadUnknown', 'reloadFinal', 'oldIdentity', 'newIdentity',
               'bootstrapStart', 'oldCore', 'newCore', 'quiescence', 'start', 'startedSHA256',
               'stages', 'replayRejected', 'recoverySelfApprovalDenied', 'reopened', 'oldCleanup',
               'newCleanup', 'syntax', 'nativeCalls', 'eventCheckpoints', 'dualOwnerCloseRejectedTwice',
               'countersBounded', 'closedPorts', 'fixtureCleanup', 'cleanupProbes',
               'runtimeClosed', 'newDiskOwnerClosed', 'cleanupReplayNoOp', 'controlPlane', 'controlEvents',
               'controlBeforeSHA256', 'controlAfterSHA256', 'controlProofReplayRejected', 'controlRecollectRejected',
               'controlCopiedStartedRejected', 'controlCopiedProofRejected',
               'localCopiedFixtureRejected',
               'verificationRecord', 'verificationEvents', 'reopenedExecutionPreserved', 'reopenedRecordCapabilityAbsent',
               'httpRecoveryProven', 'completionProven', 'fullPrivateWALIndependentlyProven',
               'syntaxRawStreamsIndependentlyProven', 'internetBusinessProven', 'production')
HEX = re.compile(r'[a-f0-9]{64}')
COMMIT = re.compile(r'[a-f0-9]{40}')


def need(value):
    if not value:
        raise ValueError('native recovery public evidence rejected')


def sha(raw):
    need(type(raw) is bytes)
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('ascii')


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))
    return value


def integer(value, low=0, high=(1 << 64) - 1):
    need(type(value) is int and low <= value <= high)
    return value


def digest(value):
    need(type(value) is str and HEX.fullmatch(value) is not None and value != '0' * 64)
    return value


def same(a, b):
    need(canonical(a) == canonical(b))


def decode(raw, *, elapsed=False):
    need(type(raw) is bytes and len(raw) <= 16 << 20)
    text = raw.decode('utf-8', errors='strict')
    need(not text.startswith('\ufeff'))

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result

    def floating(value):
        need(elapsed)
        result = float(value)
        need(math.isfinite(result))
        return result

    value = json.loads(text, object_pairs_hook=pairs, parse_float=floating,
                       parse_constant=lambda _: need(False))

    def visit(item, depth):
        need(depth <= 24)
        if type(item) is dict:
            need(len(item) <= 128)
            for key, child in item.items():
                need(type(key) is str and not any(0xd800 <= ord(c) <= 0xdfff for c in key))
                visit(child, depth + 1)
        elif type(item) is list:
            need(len(item) <= 512)
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str:
            need(len(item) <= 1 << 20 and not any(0xd800 <= ord(c) <= 0xdfff for c in item))
        elif type(item) is int:
            need(-(1 << 63) <= item <= (1 << 64) - 1)
        elif type(item) is float:
            need(elapsed and math.isfinite(item))
        else:
            need(item is None or type(item) is bool)

    visit(value, 0)
    return value


def timestamp(value):
    need(type(value) is str)
    m = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z', value)
    need(m is not None)
    year, month, day, hour, minute, second = map(int, m.groups()[:6])
    need(1 <= year <= 9999 and hour < 24 and minute < 60 and second < 60)
    date = datetime.date(year, month, day)
    return ((date.toordinal() * 24 + hour) * 3600 + minute * 60 + second) * 10**9 + int((m.group(7) or '').ljust(9, '0'))


def go_event_time(value):
    result = timestamp(value)
    # A time.Time field's actual RFC3339Nano JSON cannot retain fractional
    # trailing zeroes. Prefix hashes must describe possible Go Marshal bytes.
    fraction = re.search(r'\.([0-9]+)Z$', value)
    need(fraction is None or not fraction[1].endswith('0'))
    return result


def source_path(value):
    need(type(value) is str and '\\' not in value and ':' not in value and
         (value.startswith('chengwang/') or value.startswith('.github/workflows/')))
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value and '..' not in path.parts and '.' not in path.parts)
    return value


def stream(value, raw, *, complete=True):
    exact(value, STREAM_KEYS)
    integer(value['bytes'], 0, 64 << 10)
    integer(value['totalBytes'], 0, 64 << 10)
    digest(value['sha256'])
    need(value['truncated'] is False and type(value['complete']) is bool)
    need(value['bytes'] == value['totalBytes'])
    if complete:
        need(value['complete'] is True and value['bytes'] == len(raw) and value['sha256'] == sha(raw))
    else:
        need(value['bytes'] <= len(raw) and value['sha256'] == sha(raw[:value['bytes']]))
    return value


def exited(value, stdout, stderr):
    exact(value, EXIT_KEYS)
    need(value['started'] is True and value['waitReturned'] is True and value['groupAbsent'] is True)
    need(type(value['termSent']) is bool and type(value['killSent']) is bool)
    if value['waitErrorClass'] == 'NONE':
        integer(value['exitCode'], 0, 0)
        need(value['signal'] is None)
    else:
        need(value['waitErrorClass'] == 'EXIT_STATUS')
        if value['signal'] is None:
            integer(value['exitCode'], 1, 255)
        else:
            need(value['exitCode'] is None)
            integer(value['signal'], 1, 64)
    stream(value['stdout'], stdout)
    stream(value['stderr'], stderr)
    return value


def identity(value, commit, elf, netns, artifact=None):
    exact(value, IDENTITY_KEYS)
    integer(value['pid'], 2, (1 << 31) - 1)
    integer(value['startTicks'], 1)
    integer(value['netNSInode'], netns, netns)
    need(value['sourceCommit'] == commit and value['elfSHA256'] == elf['sha256'])
    integer(value['elfBytes'], elf['bytes'], elf['bytes'])
    digest(value['artifactSHA256'])
    if artifact is not None:
        need(value['artifactSHA256'] == artifact)
    integer(value['controllerPort'], 28412, 28412)
    integer(value['mixedPort'], 28411, 28411)
    return value


def go_events(raw):
    started = running = passed = ended = False
    last = None
    test_start = test_pass = None
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20 and not ended)
        row = decode(line, elapsed=True)
        need(type(row) is dict and set(row) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'})
        need(row.get('Package') == PACKAGE)
        when = timestamp(row.get('Time'))
        need(last is None or when >= last)
        last = when
        if 'Elapsed' in row:
            need(type(row['Elapsed']) in (int, float) and math.isfinite(row['Elapsed']) and row['Elapsed'] >= 0)
        action, name = row.get('Action'), row.get('Test')
        if 'Test' in row:
            need(name == TOP)
        if action == 'start':
            need(not started and name is None and 'Output' not in row and 'Elapsed' not in row)
            started = True
        elif action == 'run':
            need(started and name == TOP and not running and not passed and 'Output' not in row and 'Elapsed' not in row)
            running = True
            test_start = when
        elif action == 'pass':
            need(started and running and 'Output' not in row)
            if name == TOP:
                need(not passed)
                passed = True
                test_pass = when
            else:
                need(name is None and passed)
                ended = True
        elif action == 'output':
            need(started and (name is None or (name == TOP and running and not passed)) and 'Elapsed' not in row)
            output = row.get('Output')
            need(type(output) is str and len(output) <= 4096)
            need(re.fullmatch(r'(?:=== RUN   ' + TOP + r'|[ ]*--- PASS: ' + TOP + r' \([0-9.]+s\)|PASS|ok\s+' + PACKAGE + r'\s+[0-9.]+s)\n', output) is not None)
        else:
            need(False)
        if action != 'output':
            need('Output' not in row)
    need(started and running and passed and ended and test_start is not None and test_pass is not None)
    return {'topLevel': 1, 'passingSemanticTests': 1, 'skips': 0,
            'testStartedAtNanoseconds': test_start, 'testPassedAtNanoseconds': test_pass}


def native_events(rows, old_core, new_core, go_window):
    need(type(rows) is list and 1 <= len(rows) <= 256)
    integer(old_core, 1, 4)
    integer(new_core, 1, 4)
    need(old_core != new_core)
    positions = {}
    last = None
    for i, row in enumerate(rows, 1):
        exact(row, ('sequence', 'kind', 'core', 'at'))
        integer(row['sequence'], i, i)
        need(row['kind'] in CALL_KINDS)
        core = integer(row['core'], 0, 4)
        need(core in (0, old_core, new_core))
        when = go_event_time(row['at'])
        need((last is None or when >= last) and go_window[0] <= when <= go_window[1])
        last = when
        if row['kind'] in ('SYNTAX_OS_START_ATTEMPT', 'SYNTAX_OS_START_RETURN', 'RECOVERY_START_DISPATCH'):
            need(core == 0)
        elif row['kind'] == 'RECOVERY_STOP_DISPATCH':
            need(core == old_core)
        else:
            need(core in (old_core, new_core))
        positions.setdefault((core, row['kind']), []).append(i)

    def one(core, kind):
        found = positions.get((core, kind), [])
        need(len(found) == 1)
        return found[0]

    for core, helper_count in ((old_core, 2), (new_core, 1)):
        start = one(core, 'KERNEL_OS_START_ATTEMPT')
        returned = one(core, 'KERNEL_OS_START_RETURN')
        entered = one(core, 'KERNEL_OS_WAIT_ENTER')
        waited = one(core, 'KERNEL_OS_WAIT_RETURN')
        need(start < returned < entered < waited)
        need(len(positions.get((core, 'OWNED_STOP_HELPER_ENTER'), [])) == helper_count)
        term = one(core, 'KERNEL_OS_TERM_ATTEMPT')
        term_returned = one(core, 'KERNEL_OS_TERM_RETURN')
        need(entered < term < term_returned)
        kills = positions.get((core, 'KERNEL_OS_KILL_ATTEMPT'), [])
        kill_returns = positions.get((core, 'KERNEL_OS_KILL_RETURN'), [])
        need(len(kills) == len(kill_returns) <= 1)
        if kills:
            need(term < kills[0] < kill_returns[0])
    stop = one(old_core, 'RECOVERY_STOP_DISPATCH')
    start = one(0, 'RECOVERY_START_DISPATCH')
    need(stop < one(old_core, 'KERNEL_OS_TERM_ATTEMPT') < start < one(new_core, 'KERNEL_OS_START_ATTEMPT'))
    need(one(old_core, 'KERNEL_OS_WAIT_RETURN') < start)
    syntax_start = one(0, 'SYNTAX_OS_START_ATTEMPT')
    syntax_return = one(0, 'SYNTAX_OS_START_RETURN')
    need(syntax_start < syntax_return < stop)
    need(positions[(old_core, 'OWNED_STOP_HELPER_ENTER')][0] > stop)
    need(positions[(old_core, 'OWNED_STOP_HELPER_ENTER')][0] < one(old_core, 'KERNEL_OS_TERM_ATTEMPT'))
    need(positions[(old_core, 'OWNED_STOP_HELPER_ENTER')][1] > one(old_core, 'KERNEL_OS_WAIT_RETURN'))
    need(positions[(new_core, 'OWNED_STOP_HELPER_ENTER')][0] > one(new_core, 'KERNEL_OS_START_RETURN'))
    need(positions[(new_core, 'OWNED_STOP_HELPER_ENTER')][0] < one(new_core, 'KERNEL_OS_TERM_ATTEMPT'))
    return positions


def event_prefix_sha(rows, count):
    # Actual Go observer structs marshal in this declaration order. Kinds and
    # RFC3339Nano times are ASCII, so no HTML/Unicode string escape is involved.
    integer(count, 0, len(rows))
    values = [{key: row[key] for key in ('sequence', 'kind', 'core', 'at')}
              for row in rows[:count]]
    return sha(json.dumps(values, ensure_ascii=True, separators=(',', ':'),
                          allow_nan=False).encode('ascii'))


def event_checkpoints(checkpoints, rows, positions, old_core, new_core):
    need(type(checkpoints) is list and len(checkpoints) == len(EVENT_STAGES))
    values = {}
    prior = 0
    for stage, row in zip(EVENT_STAGES, checkpoints):
        exact(row, ('stage', 'count', 'lastSequence', 'eventsSHA256'))
        need(row['stage'] == stage)
        count = integer(row['count'], prior, len(rows))
        integer(row['lastSequence'], count, count)
        need(digest(row['eventsSHA256']) == event_prefix_sha(rows, count))
        values[stage] = (count, row['eventsSHA256'])
        prior = count
    for before, after in ((EVENT_STAGES[0], EVENT_STAGES[1]),
                          (EVENT_STAGES[2], EVENT_STAGES[3]),
                          (EVENT_STAGES[6], EVENT_STAGES[7]),
                          (EVENT_STAGES[8], EVENT_STAGES[9])):
        need(values[before] == values[after])
    need(values[EVENT_STAGES[1]] == values[EVENT_STAGES[2]] == values[EVENT_STAGES[4]])
    need(all(values[stage] == values[EVENT_STAGES[5]] for stage in EVENT_STAGES[6:]))
    need(values[EVENT_STAGES[5]][0] == len(rows))
    boundary = values[EVENT_STAGES[4]][0]
    need(boundary >= positions[(new_core, 'KERNEL_OS_WAIT_ENTER')][0])
    need(boundary >= positions[(old_core, 'KERNEL_OS_WAIT_RETURN')][0])
    need(boundary < positions[(new_core, 'OWNED_STOP_HELPER_ENTER')][0])
    need(boundary < positions[(new_core, 'KERNEL_OS_TERM_ATTEMPT')][0])
    need(boundary < positions[(new_core, 'KERNEL_OS_WAIT_RETURN')][0])
    need(boundary < positions[(old_core, 'OWNED_STOP_HELPER_ENTER')][1])
    return {'snapshotCount': len(checkpoints), 'finalSourceCallCount': len(rows),
            'permitAndCapReplayAddedCalls': 0, 'runnerReplayAddedCalls': 0,
            'cleanupReplayAddedCalls': 0, 'reopenAddedCalls': 0,
            'counterScope': 'SOURCE_CALLSITE_EVENTS_NOT_KERNEL_SYSCALL_TRACE'}


def contract(sources):
    value = decode(sources[PREFIX + 'native_recovery_contract.json'])
    expected = dict(schema='chengwang.mihomo-native-recovery-contract/v5', scope=SCOPE,
                    tags=list(TAGS), goPackage='./internal/mihomodeploy', topTests=[TOP],
                    goTimeoutSeconds=75, outerGoTimeoutSeconds=90,
                    privateRoot='/tmp/chengwang-mihomo-recovery-private',
                    identityRoot='/tmp/chengwang-mihomo-service-identities',
                    servicePrivateRoot='/tmp/chengwang-mihomo-service-private',
                    stateRoot='/tmp/chengwang-mihomo-service-state', stages=list(STAGES),
                    reopenStage='reopened', counterEventLimit=256, eventCheckpoints=list(EVENT_STAGES),
                    eventCheckpointKeys=['stage', 'count', 'lastSequence', 'eventsSHA256'],
                    eventPrefixEncoding='Go-json.Marshal([]labNativeRecoveryCall)-sequence-kind-core-at-no-newline',
                    commandReceiptSchema='chengwang.mihomo-native-command-receipt/v1',
                    commandReceiptKeys=list(COMMAND_KEYS), commandClasses=list(COMMAND_CLASSES),
                    commandReceiptLimit=4, processEventsSchema='chengwang.mihomo-apply-private-process-event/v1',
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
                    processEventLimit=64, maxPublicBytes=16 << 20, production=False,
                    httpRecoveryProven=False, completionProven=False,
                    syntaxRawStreamsIndependentlyProven=False)
    same(value, expected)
    go = sources['chengwang/internal/mihomodeploy/lab_native_recovery_linux_test.go'].decode('utf-8')
    need(go.startswith('//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults && chengwang_mihomo_recovery_native\n'))
    need(re.findall(r'^func (Test\w+)\(t \*testing\.T\)', go, re.M) == [TOP])
    # The old S2 command never enables the continuous fault. Its ordinary
    # build therefore selects both default bridges. The continuous HTTP
    # harness is the only supported owner of the new fault tag, and its
    # server bridge explicitly excludes the old-fault and Completion tags.
    need('chengwang_mihomo_recovery_continuous_fault' not in TAGS)
    need(sources['chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_default.go'].startswith(
        b'//go:build !linux || !chengwang_mihomo_recovery_continuous_fault || !chengwang_mihomo_recovery_native\n'))
    need(sources['chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_default.go'].startswith(
        b'//go:build !linux || !chengwang_mihomo_service || !chengwang_mihomo_recovery_native || !chengwang_mihomo_recovery_continuous_fault || chengwang_mihomo_faults || chengwang_mihomo_completion_native\n'))
    exact_continuous = b'//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native\n'
    for path in (
        'chengwang/internal/authn/continuous_bound_credentials_linux.go',
        'chengwang/internal/authn/continuous_bound_credentials_linux_test.go',
        'chengwang/internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go',
        'chengwang/internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
        'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
    ):
        need(sources[path].startswith(exact_continuous))
    return value


def commands(raw, source_commit, module_sha, namespaces, variant='positive'):
    need(variant in VARIANTS)
    need(0 < len(raw) <= 64 << 10)
    rows = [decode(line) for line in raw.splitlines()]
    need(len(rows) == 4)
    go_root = '/tmp/mihomo-apply-go'
    cwd = '/tmp/mihomo-apply-source'
    expected = {
        'GO_VERSION': ([go_root + '/bin/go', 'version'], 15),
        'GOFMT': ([go_root + '/bin/gofmt', '-d', *FMT], 30),
        'GO_TEST': ([go_root + '/bin/go', 'test', '-json', '-count=1', '-shuffle=off', '-p=1',
                     '-tags=' + ','.join(TAGS), '-run=^' + TOP + '$', '-timeout=75s', './internal/mihomodeploy',
                     '-args', '-chengwang-native-verification-mode='+variant], 90),
    }
    for i, (row, name) in enumerate(zip(rows, COMMAND_CLASSES), 1):
        exact(row, COMMAND_KEYS)
        need(row['schema'] == 'chengwang.mihomo-native-command-receipt/v1' and row['sourceCommit'] == source_commit)
        integer(row['sequence'], i, i)
        need(row['commandClass'] == name and row['cwd'] == cwd and row['observed'] is True)
        integer(row['exitCode'], 0, 0)
        same(row['namespace'], namespaces)
        if name == 'SANDBOX':
            argv = row['argv']
            need(type(argv) is list and len(argv) == 7 and type(argv[0]) is str)
            need(argv[0] in [directory + '/python3' for directory in ('/usr/sbin', '/usr/bin', '/sbin', '/bin')])
            same(argv[1:], ['-B', cwd + '/deploy/mihomo-lifecycle-lab/native_recovery_worker.py',
                            '--sandbox', source_commit, module_sha, variant])
            integer(row['timeoutSeconds'], 30, 30)
        else:
            argv, timeout = expected[name]
            same(row['argv'], argv)
            integer(row['timeoutSeconds'], timeout, timeout)
    return rows


def process_events(raw, command_rows):
    need(0 < len(raw) <= 64 << 10)
    lines = raw.splitlines()
    need(len(lines) == 16)
    rows = [decode(line) for line in lines]
    keys = ('schema', 'seq', 'commandClass', 'event', 'pid', 'pidfdAcquired', 'exitCode')
    for i, row in enumerate(rows, 1):
        exact(row, keys)
        need(row['schema'] == 'chengwang.mihomo-apply-private-process-event/v1')
        integer(row['seq'], i, i)
        need(canonical(row) == lines[i - 1] + b'\n')
    result = {}
    for i, command in enumerate(command_rows):
        name = command['commandClass']
        group = rows[i * 4:i * 4 + 4]
        need(all(row['commandClass'] == name for row in group))
        need([row['event'] for row in group] == ['START_INTENT', 'STARTED', 'REFERENCE_ACQUIRED', 'WAIT_RETURNED'])
        intent, start, reference, returned = group
        need(intent['pid'] is None and intent['pidfdAcquired'] is None and intent['exitCode'] is None)
        pid = integer(start['pid'], 2, (1 << 31) - 1)
        need(start['pidfdAcquired'] is None and start['exitCode'] is None)
        integer(reference['pid'], pid, pid)
        need(reference['pidfdAcquired'] is True and reference['exitCode'] is None)
        integer(returned['pid'], pid, pid)
        need(returned['pidfdAcquired'] is True)
        integer(returned['exitCode'], command['exitCode'], command['exitCode'])
        result[name] = {'startObserved': True, 'ownedReferenceAcquired': True,
                        'waitReturned': True, 'exitCode': returned['exitCode']}
    return result


def sandbox(raw, sources, source_commit, elf, receipt, variant='positive'):
    keys = ('schema', 'sourceCommit', 'uid', 'gid', 'effectiveCaps', 'noNewPrivileges',
            *NS_KEYS, 'environmentKeys', 'interfaceNames', 'defaultV4Routes', 'defaultV6Routes',
            'sourceModuleSHA256', 'sourceReadOnly', 'goReadOnly', 'kernelCopy', 'inputCustody', 'serviceBases')
    value = exact(decode(raw['sandbox.json']), (*keys, 'verificationMode'))
    need(value['schema'] == 'chengwang.mihomo-native-recovery-sandbox/v2' and value['sourceCommit'] == source_commit)
    need(value['verificationMode'] == variant)
    integer(value['uid'], 10001, 10001)
    integer(value['gid'], 10001, 10001)
    need(value['effectiveCaps'] == '0000000000000000' and value['noNewPrivileges'] is True)
    same(value['environmentKeys'], list(ENV))
    same(value['interfaceNames'], ['lo'])
    same(value['defaultV4Routes'], [])
    same(value['defaultV6Routes'], [])
    same(value['serviceBases'], ['/tmp/chengwang-mihomo-service-private',
                                 '/tmp/chengwang-mihomo-service-identities', '/tmp/chengwang-mihomo-service-state'])
    need(value['sourceModuleSHA256'] == sha(sources['chengwang/go.mod']) and value['sourceReadOnly'] is True and value['goReadOnly'] is True)
    same(value['kernelCopy'], dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', readOnly=True, executable=True))
    host_before = exact(decode(raw['host-before.json']), (*NS_KEYS, 'resolvSHA256'))
    host_after = exact(decode(raw['host-after.json']), (*NS_KEYS, 'resolvSHA256'))
    same(host_before, host_after)
    digest(host_before['resolvSHA256'])
    for name, prefix in zip(NS_KEYS, ('net', 'mnt', 'pid')):
        for entry in (host_before[name], value[name]):
            need(type(entry) is str and re.fullmatch(prefix + r':\[[1-9][0-9]{0,19}\]', entry) is not None)
        need(host_before[name] != value[name])
    custody = exact(value['inputCustody'], ('before', 'after'))
    same(custody['before'], custody['after'])
    for side in ('before', 'after'):
        exact(custody[side], ('elf', 'receipt'))
        for name, hashed, size, mode in (('elf', elf['sha256'], elf['bytes'], '0500'),
                                         ('receipt', sha(receipt), len(receipt), '0400')):
            item = exact(custody[side][name], ('sha256', 'bytes', 'mode', 'uid', 'gid'))
            need(item['sha256'] == hashed and item['mode'] == mode)
            integer(item['bytes'], size, size)
            integer(item['uid'], 0, (1 << 32) - 1)
            integer(item['gid'], 0, (1 << 32) - 1)
    return value


def start_observation(value, expected_identity, stdout, stderr):
    exact(value, START_KEYS)
    need(value['attempted'] is True and value['started'] is True and value['waitReturned'] is False)
    integer(value['pid'], expected_identity['pid'], expected_identity['pid'])
    integer(value['startTicks'], expected_identity['startTicks'], expected_identity['startTicks'])
    need(value['waitErrorClass'] == 'NOT_WAITED' and value['exitCode'] is None and value['signal'] is None)
    need(value['termSent'] is False and value['killSent'] is False and value['groupAbsent'] is None)
    stream(value['stdout'], stdout, complete=False)
    stream(value['stderr'], stderr, complete=False)
    return value


def syntax_observation(value):
    exact(value, START_KEYS)
    need(value['attempted'] is True and value['started'] is True and value['waitReturned'] is True)
    need(value['waitErrorClass'] == 'NONE')
    integer(value['exitCode'], 0, 0)
    need(value['signal'] is None and value['groupAbsent'] is True and value['termSent'] is False and value['killSent'] is False)
    # Syntax raw pipes are deliberately not public. Only source-bound settled
    # metadata is checked, and the result never claims independent pipe hashes.
    for name in ('stdout', 'stderr'):
        row = exact(value[name], STREAM_KEYS)
        integer(row['bytes'], 0, 64 << 10)
        integer(row['totalBytes'], row['bytes'], row['bytes'])
        digest(row['sha256'])
        need(row['truncated'] is False and row['complete'] is True)
    integer(value['pid'], 2, (1 << 31) - 1)
    if value['startTicks'] is not None:
        integer(value['startTicks'], 1)
    return value


def consumption(raw, sources, source_commit):
    need(raw['consumption.json'] == raw['consumption-independent.json'])
    receipt_raw = raw['consumption.json']
    value = exact(decode(receipt_raw), ('schema', 'state', 'component', 'version', 'upstreamSourceCommit',
                                       'archive', 'gzip', 'elf', 'source', 'output', 'publisherSignatureProven',
                                       'productionApproved', 'runtimeExecuted', 'runtimeCompatibilityProven',
                                       'businessAvailabilityProven', 'production'))
    pin_path = 'chengwang/tools/mihomo-runtime-candidate/pin.json'
    pin = exact(decode(sources[pin_path]), ('schema', 'component', 'version', 'upstreamSourceCommit', 'artifact',
                                          'limits', 'researchManifestSHA256', 'publisherSignatureProven',
                                          'productionApproved', 'runtimeExecuted'))
    need(pin['schema'] == 'chengwang.mihomo-runtime-candidate-pin/v1' and pin['component'] == 'MetaCubeX/mihomo' and pin['version'] == 'v1.19.32')
    need(pin['upstreamSourceCommit'] == '88dcbf7f1614a67c3b36b848ee3592dfa92ada36')
    digest(pin['researchManifestSHA256'])
    same(pin['limits'], dict(compressedBytes=64 << 20, expandedBytes=128 << 20))
    need(all(pin[k] is False for k in ('publisherSignatureProven', 'productionApproved', 'runtimeExecuted')))
    item = exact(pin['artifact'], ('name', 'url', 'publishedSHA256', 'exactCompressedBytes', 'elfSHA256', 'elfBytes'))
    need(item['name'] == 'mihomo-linux-amd64-v1-v1.19.32.gz' and
         item['url'] == 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/' + item['name'] and
         item['publishedSHA256'] == '306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc')
    need(value['schema'] == 'chengwang.mihomo-candidate-consumption/v1' and value['state'] == 'PINNED_GZIP_EXPANDED_NOT_EXECUTED')
    for key in ('component', 'version', 'upstreamSourceCommit'):
        need(value[key] == pin[key])
    need(all(value[k] is False for k in ('publisherSignatureProven', 'productionApproved', 'runtimeExecuted',
                                         'runtimeCompatibilityProven', 'businessAvailabilityProven', 'production')))
    archive = exact(value['archive'], ('name', 'sha256', 'bytes', 'pinBasis'))
    need(archive['name'] == item['name'] and archive['sha256'] == item['publishedSHA256'] and
         archive['pinBasis'] == 'PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL')
    integer(archive['bytes'], 1, 64 << 20)
    if item['exactCompressedBytes'] is not None:
        integer(item['exactCompressedBytes'], archive['bytes'], archive['bytes'])
    elf = exact(value['elf'], ('sha256', 'bytes', 'elfClass', 'byteOrder', 'machine', 'type', 'entryPoint',
                                'programHeaderCount', 'sectionHeaderCount', 'loadSegments', 'executableEntryMapped'))
    digest(elf['sha256'])
    integer(elf['bytes'], 64, 128 << 20)
    need(elf['elfClass'] == 'ELF64' and elf['byteOrder'] == 'little' and elf['machine'] == 'AMD64' and elf['type'] == 'EXEC')
    need(elf['executableEntryMapped'] is True)
    integer(elf['entryPoint'], 1)
    integer(elf['programHeaderCount'], 1, 1024)
    integer(elf['sectionHeaderCount'], 1, 4096)
    integer(elf['loadSegments'], 1, elf['programHeaderCount'])
    if item['elfSHA256'] is not None:
        need(digest(item['elfSHA256']) == elf['sha256'])
    if item['elfBytes'] is not None:
        integer(item['elfBytes'], elf['bytes'], elf['bytes'])
    gz = exact(value['gzip'], ('complete', 'singleMember', 'trailerCRC32', 'trailerISIZE'))
    need(gz['complete'] is True and gz['singleMember'] is True and type(gz['trailerCRC32']) is str and re.fullmatch('[a-f0-9]{8}', gz['trailerCRC32']) is not None)
    integer(gz['trailerISIZE'], elf['bytes'], elf['bytes'])
    same(value['output'], dict(path='mihomo', mode='0500', receiptMode='0400', directoryMode='0700'))
    src = exact(value['source'], ('projectSourceCommit', 'pinSHA256', 'sourceFiles'))
    need(src['projectSourceCommit'] == source_commit and src['pinSHA256'] == sha(sources[pin_path]))
    wanted = ['chengwang/tools/mihomo-runtime-candidate/' + n for n in
              ('pin.json', 'consume_pin.py', 'check_consumption.py', 'test_consume_pin.py', 'README.md')]
    need(type(src['sourceFiles']) is list and len(src['sourceFiles']) == len(wanted))
    for row, path in zip(src['sourceFiles'], wanted):
        exact(row, ('path', 'bytes', 'sha256'))
        need(row['path'] == path and row['sha256'] == sha(sources[path]))
        integer(row['bytes'], len(sources[path]), len(sources[path]))
    return elf, receipt_raw


def original_unknown(value):
    keys = ('schema', 'boundary', 'operationId', 'phase', 'revision', 'planSHA256',
            'candidateRecordSHA256', 'candidateConfigSHA256', 'previousHeadSHA256', 'headSHA256',
            'headGeneration', 'expiresAt', 'transport', 'observation', 'writeBlocked', 'replayed',
            'headAdvanced', 'proof')
    exact(value, keys)
    need(value['schema'] == 'chengwang.mihomo-lab-deployment-view/v1' and value['boundary'] == BOUNDARY)
    need(type(value['operationId']) is str and re.fullmatch(r'labop_[a-f0-9]{32}', value['operationId']) is not None)
    need(value['phase'] == 'UNKNOWN' and value['writeBlocked'] is True and value['replayed'] is False and value['headAdvanced'] is False)
    integer(value['revision'], 1)
    integer(value['headGeneration'], 1, 1)
    for k in ('planSHA256', 'candidateRecordSHA256', 'candidateConfigSHA256', 'previousHeadSHA256', 'headSHA256'):
        digest(value[k])
    need(value['previousHeadSHA256'] == value['headSHA256'])
    timestamp(value['expiresAt'])
    proof = exact(value['proof'], ('fullPayloadProven', 'internetBusinessProven', 'production'))
    need(all(v is False for v in proof.values()))
    t = exact(value['transport'], ('result', 'recordedAt', 'origin', 'gateReason'))
    result = exact(t['result'], ('state', 'dispatched', 'statusCode'))
    need(result['state'] == 'unknown' and result['dispatched'] is True and t['origin'] == 'ADAPTER' and t['gateReason'] is None)
    integer(result['statusCode'], 0, 0)
    timestamp(t['recordedAt'])
    observation = exact(value['observation'], ('conclusion', 'observedProjectionSHA256', 'evidenceSHA256', 'observedAt', 'localRouteVerified'))
    need(observation['conclusion'] == 'STABLE_NEW_PROJECTION' and observation['localRouteVerified'] is True)
    digest(observation['observedProjectionSHA256'])
    digest(observation['evidenceSHA256'])
    timestamp(observation['observedAt'])
    return value


def wal_index(raw, report, source_commit, variant='positive'):
    index = exact(decode(raw), ('schema', 'scope', 'sourceCommit', 'stages', 'fullPrivateWALIndependentlyProven', 'production'))
    need(index['schema'] == 'chengwang.mihomo-native-wal-readback-index/v2' and index['scope'] == SCOPE and index['sourceCommit'] == source_commit)
    need(index['fullPrivateWALIndependentlyProven'] is False and index['production'] is False)
    rows = index['stages']
    need(type(rows) is list and len(rows) == 9 and type(report['stages']) is list and len(report['stages']) == 7)
    previous_revision = report['originalUnknown']['revision']
    observed_controls = set()
    for i, (stage, row) in enumerate(zip(('legacy', *STAGES, 'reopened'), rows)):
        keys = ('stage', 'bytes', 'controlSHA256', 'schema', 'revision', 'recordSHA256')
        exact(row, keys if stage == 'legacy' else (*keys, 'phase', 'headSHA256'))
        need(row['stage'] == stage)
        integer(row['bytes'], 1, 2 << 20)
        digest(row['controlSHA256'])
        digest(row['recordSHA256'])
        duplicate_s1 = variant == 'not-committed' and stage == 'verification-attempted'
        need(duplicate_s1 or row['controlSHA256'] not in observed_controls)
        observed_controls.add(row['controlSHA256'])
        if stage == 'legacy':
            need(row['schema'] == 'chengwang.mihomo-lifecycle-record/v2')
            integer(row['revision'], previous_revision, previous_revision)
            continue
        need(row['schema'] == 'chengwang.mihomo-lifecycle-record/v3' and row['headSHA256'] == report['originalUnknown']['headSHA256'])
        revision = previous_revision + (3 if stage == 'planned' else 0 if duplicate_s1 else 1)
        integer(row['revision'], revision, revision)
        previous_revision = revision
        checkpoint = report['reopened'] if stage == 'reopened' else report['stages'][i - 1]
        exact(checkpoint, ('stage', 'controlSHA256', 'recordSHA256', 'revision', 'phase'))
        same(checkpoint, {k: row[k] for k in checkpoint})
        if duplicate_s1:
            same({k:v for k,v in row.items()if k!='stage'}, {k:v for k,v in rows[i-1].items()if k!='stage'})
        need(row['phase'] == ('RECOVERY_UNKNOWN' if stage == 'reopened' else PHASES[i - 1]))
    return {'stagesObserved': 9, 'actualReopenPhase': rows[-1]['phase'],
            'publicControlIndexCrossChecked': True, 'fullPrivateWALIndependentlyProven': False}


def recovery_projection_reader():
    # Only the already source-bound independent parser is imported. This is
    # neither the worker nor a constructor for an old/new authorization DTO.
    path = Path(__file__).absolute().with_name('get_projection.py')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
    spec = importlib.util.spec_from_file_location('_native_independent_target_projection', path)
    need(spec is not None and spec.loader is not None)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    need(reader.unicodedata.unidata_version == reader.UNICODE_VERSION)
    return reader


def recovery_go_bytes(value, projection):
    def struct(item):
        if type(item) is dict:
            return projection._Struct([(key, struct(child)) for key, child in item.items()])
        if type(item) is list:
            return [struct(child) for child in item]
        return item
    return projection.go_codec(struct(value))


def recovery_artifact(value, projection):
    keys = ('schema', 'recordSHA256', 'config', 'sourceSpecSHA256', 'sourceSpecBytes', 'controllerPort', 'mixedPort')
    cfg_keys = ('schema', 'scope', 'sha256', 'bytes', 'draftSHA256', 'requirementsSHA256',
                'capabilities', 'requirements', 'admissible', 'blockers')
    exact(value, keys); need(list(value) == list(keys))
    cfg = exact(value['config'], cfg_keys); need(list(cfg) == list(cfg_keys))
    need(value['schema'] == 'chengwang.mihomo-artifact/v1' and cfg['schema'] == 'chengwang.mihomo-lab-config/v1')
    need(cfg['scope'] == 'ISOLATED_LOOPBACK_MIHOMO_STATIC_SUBSET_NOT_PRODUCTION')
    for item in (value['recordSHA256'], value['sourceSpecSHA256'], cfg['sha256'], cfg['draftSHA256'], cfg['requirementsSHA256']):
        digest(item)
    integer(value['sourceSpecBytes'], 1, 2 << 20); integer(cfg['bytes'], 1, 1 << 20)
    integer(value['controllerPort'], 28412, 28412); integer(value['mixedPort'], 28411, 28411)
    need(cfg['admissible'] is True and cfg['requirements'] == [] and cfg['blockers'] == [])
    same(cfg['capabilities'], ['static_domain_suffix_rules', 'explicit_selectors', 'loopback_http_nodes',
                               'private_loopback_controller', 'built_in_dns_disabled'])
    record = dict(schema='chengwang.mihomo-artifact-record/v1', config=cfg,
                  sourceSpecSHA256=value['sourceSpecSHA256'], sourceSpecBytes=value['sourceSpecBytes'],
                  controllerPort=28412, mixedPort=28411)
    need(sha(recovery_go_bytes(record, projection)) == value['recordSHA256'])


def recovery_capture(raw, observation, projection):
    transcript_raw = raw['recovery-s2-transcript.json']
    need(0 < len(transcript_raw) <= 1 << 20 and observation['transcriptSHA256'] == sha(transcript_raw))
    transcript = projection._object(projection._json(transcript_raw, projection.METADATA_LIMIT), projection.TOP_KEYS, True)
    need(transcript['schema'] == 'chengwang.mihomo-lab-get-evidence/v1' and
         transcript['scope'] == 'PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF' and
         transcript['outcome'] == 'COMPLETE' and transcript['failureClass'] is None and
         transcript['limitReached'] is False and transcript['contextState'] == 'ACTIVE')
    schedule, records = transcript['expectedSchedule'], transcript['records']
    need(type(schedule) is list and type(records) is list and len(schedule) == len(records) == 8)
    hashes = observation['bodySHA256s']
    need(type(hashes) is list and len(hashes) == 8)
    bodies, total = [], 0
    for i, expected in enumerate(projection.SCHEDULE):
        projection._object(schedule[i], projection.SCHEDULE_KEYS, True)
        integer(schedule[i]['ordinal'], i + 1, i + 1); integer(schedule[i]['round'], expected['round'], expected['round'])
        need(schedule[i]['endpointKind'] == expected['endpointKind'])
        row = projection._object(records[i], projection.RECORD_KEYS, True)
        integer(row['ordinal'], i + 1, i + 1); integer(row['round'], expected['round'], expected['round'])
        need(row['endpointKind'] == expected['endpointKind'])
        need(all(row[key] is True for key in ('requestBuilt', 'doInvoked', 'responseObserved', 'readAttempted', 'naturalEOF', 'closeAttempted')))
        integer(row['statusCode'], 200, 200)
        headers = projection._headers(row['headers'])
        need(row['uncompressed'] is False and row['limitReached'] is False and
             row['readErrorClass'] == row['closeErrorClass'] == 'NONE' and row['contextState'] == 'ACTIVE' and
             row['parseState'] == 'SHAPE_ACCEPTED' and row['terminalClass'] == 'NONE')
        body = raw[f'recovery-s2-body-{i+1}.json']
        need(0 < len(body) <= 256 << 10)
        integer(row['retainedBytes'], len(body), len(body))
        need(row['retainedSHA256'] == hashes[i] == sha(body))
        length = integer(row['contentLength'], -1, 256 << 10)
        need(length == -1 or length == len(body))
        if headers['transferEncodingValuesB64']:
            need(length == -1)
        total += len(body); bodies.append(body)
    for key in ('slotsEntered', 'doInvocations', 'responsesObserved', 'readAttempts', 'completedBodies'):
        integer(transcript[key], 8, 8)
    integer(transcript['retainedBytes'], total, total)
    digests, witnesses = [], []
    for start in (0, 4):
        hashed, witness = projection.projection_from_bodies(*bodies[start:start+4])
        digests.append(hashed); witnesses.append(witness)
    need(digests[0] == digests[1] and witnesses[0] == witnesses[1])
    readback = observation['readback']
    need(readback['targetProjectionSHA256'] == readback['observedProjectionSHA256'] == digests[0])
    need(sum(len(raw[name]) for name in (*RECOVERY_PUBLIC, RECORD_PUBLIC)) <= 2 << 20)
    return {'actualResponseBodies': 8, 'rounds': 2, 'roundProjectionSHA256': digests,
            'roundUUIDWitnessSHA256': witnesses, 'transcriptSHA256': sha(transcript_raw),
            'independentProjectionRecomputeProven': True, 'expectedPrivateSourceIndependentlyProven': False,
            'controllerReceivedCount': None}


def recovery_local_marker(raw, observation, projection):
    original = raw['recovery-s2-local-marker.json']
    need(0 < len(original) <= 64 << 10)
    keys = ('schema', 'scope', 'expectedRole', 'expectedMarkerSHA256', 'expectedMarkerBytes',
            'startedAt', 'returnedAt', 'handlerCompleted', 'clientNaturalEOF', 'proxyNaturalEOF',
            'originWriteComplete', 'localProxyMarkerProven', 'route')
    marker = exact(decode(original), keys)
    need(list(marker) == list(keys) and recovery_go_bytes(marker, projection) == original)
    digest(observation['localMarkerSHA256'])
    need(observation['localMarkerSHA256'] == sha(original))
    same(marker, observation['localPath'])
    need(marker['schema'] == 'chengwang.mihomo-recovery-local-marker/v1' and
         marker['scope'] == 'ACTUAL_LOOPBACK_PROXY_MARKER_NOT_INTERNET_BUSINESS_OR_AUTHORIZATION' and
         marker['expectedRole'] == 'B')
    # This fixed native program targets service-b. Only the nonce hash is
    # disclosed: matching the source's expected hash does not independently
    # reconstruct the private nonce or any of the three original bodies.
    expected = digest(marker['expectedMarkerSHA256'])
    size = len(b'chengwang-local-service-marker/v1:B:' + b'0' * 64 + b'\n')
    integer(marker['expectedMarkerBytes'], size, size)
    for key in ('handlerCompleted', 'clientNaturalEOF', 'proxyNaturalEOF',
                'originWriteComplete', 'localProxyMarkerProven'):
        need(marker[key] is True)
    begin, end = timestamp(marker['startedAt']), timestamp(marker['returnedAt'])
    need(timestamp(observation['observedAt']) <= begin <= end < timestamp(observation['deadline']))
    route = exact(marker['route'], ('phase', 'nonceSHA256', 'clientResponse', 'proxyResponse',
                                  'originResponse', 'countersBefore', 'countersAfter', 'matched'))
    need(list(route) == ['phase', 'nonceSHA256', 'clientResponse', 'proxyResponse',
                        'originResponse', 'countersBefore', 'countersAfter', 'matched'])
    need(route['phase'] == 'RECOVERY_NEW_EPOCH_MARKER' and route['matched'] is True)
    digest(route['nonceSHA256'])
    for name in ('clientResponse', 'proxyResponse', 'originResponse'):
        body = exact(route[name], ('sha256', 'bytes', 'complete'))
        need(list(body) == ['sha256', 'bytes', 'complete'])
        digest(body['sha256']); need(body['sha256'] == expected and body['complete'] is True)
        integer(body['bytes'], size, size)
    before, after = route['countersBefore'], route['countersAfter']
    need(type(before) is list and type(after) is list and len(before) == len(after) == 3)
    counter_keys = ('role', 'connectIngress', 'tunnelRequests', 'forwardInvocations', 'originRequests', 'rejected')
    for role, old, new in zip(('A', 'B', 'origin'), before, after):
        exact(old, counter_keys); exact(new, counter_keys)
        need(list(old) == list(new) == list(counter_keys))
        need(old['role'] == new['role'] == role)
        for field in counter_keys[1:]:
            low, high = integer(old[field], 0, (1 << 63) - 1), integer(new[field], 0, (1 << 63) - 1)
            wanted = int(role == 'B' and field != 'rejected' or role == 'origin' and field == 'originRequests')
            need(high - low == wanted)
    return {'scope': marker['scope'], 'phase': route['phase'], 'expectedRole': marker['expectedRole'],
            'matchedSourceResponseDescriptors': 3, 'actualSourceCounterRows': 3,
            'privateOriginalSHA256': sha(original), 'sourceLocalMarkerObserved': True,
            'markerBodyIndependentlyProven': False, 'privateNonceIndependentlyProven': False,
            'internetBusinessProven': False, 'completionProven': False}


def recovery_control(raw, report, source_commit, elf, netns):
    projection = recovery_projection_reader()
    keys = ('schema', 'recoveryId', 'planSHA256', 'startIntentSHA256', 'startedSHA256', 'sourceRevision',
            'sourceRecordSHA256', 'ownerFence', 'artifact', 'startupIdentity', 'entryAt', 'deadline',
            'sampleTimes', 'observedAt', 'readback', 'transcriptSHA256', 'bodySHA256s', 'verificationSHA256',
            'localPath', 'localMarkerSHA256')
    verification = raw['recovery-s2-verification.json']
    need(0 < len(verification) <= 64 << 10)
    observed = exact(decode(verification), keys)
    need(list(observed) == list(keys) and observed['verificationSHA256'] == '' and recovery_go_bytes(observed, projection) == verification)
    public = exact(report['controlPlane'], keys)
    digest(public['verificationSHA256']); need(public['verificationSHA256'] == sha(verification))
    comparison = dict(public); comparison['verificationSHA256'] = ''
    same(comparison, observed)
    need(observed['schema'] == 'chengwang.mihomo-recovery-control-observation/v2')
    need(type(observed['recoveryId']) is str and re.fullmatch(r'labrec_[a-f0-9]{32}', observed['recoveryId']) is not None)
    for key in ('planSHA256', 'startIntentSHA256', 'startedSHA256', 'sourceRecordSHA256', 'transcriptSHA256'):
        digest(observed[key])
    need(observed['startedSHA256'] == report['startedSHA256'])
    latest = report['stages'][5]
    integer(observed['sourceRevision'], latest['revision'], latest['revision'])
    need(observed['sourceRecordSHA256'] == latest['recordSHA256'])
    integer(observed['ownerFence'], 1)
    recovery_artifact(observed['artifact'], projection)
    need(observed['artifact']['recordSHA256'] == report['originalUnknown']['candidateRecordSHA256'] and
         observed['artifact']['config']['sha256'] == report['originalUnknown']['candidateConfigSHA256'])
    actual = identity(observed['startupIdentity'], source_commit, elf, netns, observed['artifact']['config']['sha256'])
    same(actual, report['newIdentity'])
    entry, deadline, at = (timestamp(observed[key]) for key in ('entryAt', 'deadline', 'observedAt'))
    started_at = timestamp(report['start']['returnedAt'])
    need(started_at <= entry <= at < deadline <= entry + 10_000_000_000 and deadline <= started_at + 30_000_000_000)
    windows = observed['sampleTimes']; need(type(windows) is list and len(windows) == 2)
    previous = entry
    for window in windows:
        exact(window, ('startedAt', 'completedAt'))
        begin, end = timestamp(window['startedAt']), timestamp(window['completedAt'])
        need(previous <= begin <= end <= at)
        previous = end
    readback = exact(observed['readback'], ('schema', 'conclusion', 'sampleCount', 'requestsObserved',
                     'targetProjectionSHA256', 'observedProjectionSHA256', 'dataplaneProven', 'fullPayloadProven', 'authorizationProven', 'production'))
    need(readback['schema'] == 'chengwang.mihomo-selected-target-readback/v1' and readback['conclusion'] == 'TARGET_PROJECTION_MATCHED')
    integer(readback['sampleCount'], 2, 2); integer(readback['requestsObserved'], 8, 8)
    for key in ('dataplaneProven', 'fullPayloadProven', 'authorizationProven', 'production'):
        need(readback[key] is False)
    digest(readback['targetProjectionSHA256']); digest(readback['observedProjectionSHA256'])
    for key in ('controlProofReplayRejected', 'controlRecollectRejected', 'controlCopiedStartedRejected', 'controlCopiedProofRejected',
                'localCopiedFixtureRejected'):
        need(report[key] is True)
    need(report['controlBeforeSHA256'] == report['controlAfterSHA256'] == latest['controlSHA256'])
    checkpoints = report['controlEvents']; need(type(checkpoints) is list and len(checkpoints) == 2)
    original = report['eventCheckpoints']; boundary = original[3]
    need(boundary['count'] == original[4]['count'] and boundary['eventsSHA256'] == original[4]['eventsSHA256'])
    for stage, point in zip(('before-control-plane', 'after-control-plane'), checkpoints):
        exact(point, ('stage', 'count', 'lastSequence', 'eventsSHA256'))
        need(point['stage'] == stage)
        integer(point['count'], boundary['count'], boundary['count']); integer(point['lastSequence'], point['count'], point['count'])
        need(point['eventsSHA256'] == event_prefix_sha(report['nativeCalls'], point['count']) == boundary['eventsSHA256'])
    calls = report['nativeCalls']
    need(timestamp(calls[checkpoints[0]['count']-1]['at']) <= entry <= at <= timestamp(calls[checkpoints[1]['count']]['at']))
    capture = recovery_capture(raw, observed, projection)
    marker = recovery_local_marker(raw, observed, projection)
    need(timestamp(observed['localPath']['returnedAt']) <= timestamp(calls[checkpoints[1]['count']]['at']))
    return {'capture': capture, 'localMarker': marker, 'sampleWindows': 2, 'sourceRevision': observed['sourceRevision'],
            'sameS1WALBeforeAfter': True, 'physicalCallsAdded': 0,
            'oneUseAndCopyRejectionsObservedBySource': True,
            'authorizationIndependentlyProven': False, 'completionProven': False, 'dataplaneProven': False}


def verification_record(raw, report, variant):
    need(variant in VARIANTS)
    original = raw[RECORD_PUBLIC]
    need(0 < len(original) <= 64 << 10)
    keys = ('schema', 'scope', 'mode', 'attemptedAt', 'returnedAt', 'replaceAttempts', 'forwardedWrites',
            'postWriteReads', 'injectedReads', 'underlyingCommitted', 'capKnownBefore', 'capSpent',
            'capCopyRejected', 'capReplayRejected', 'recordReturnedError', 'storePoisoned', 'candidateAdopted',
            'liveOwnerCleared', 'transientProofCleared', 'retainedStartedCleared', 'sourceRevision',
            'sourceRecordSHA256', 'sourceControlSHA256', 'memoryRevision', 'memoryRecordSHA256',
            'diskRevision', 'diskRecordSHA256', 'diskControlSHA256', 'executionSchema', 'receiptPresent',
            'receiptSHA256', 'observationSHA256', 'verificationCommitRevision', 'recordedAt', 's1PreimageSHA256',
            'sourceCurrentSHA256', 'diskCurrentSHA256', 'completionAbsent', 'noNewPhysicalCalls',
            'fullPrivateReceiptIndependentlyProven')
    value = exact(decode(original), keys)
    need(list(value) == list(keys) and recovery_go_bytes(value, recovery_projection_reader()) == original)
    same(value, report['verificationRecord'])
    need(value['schema'] == 'chengwang.mihomo-native-verification-record/v1' and value['mode'] == variant and
         value['scope'] == 'REDACTED_ACTUAL_WAL_FACT_NOT_AUTHORIZATION_OR_COMPLETE_PRIVATE_RECEIPT')
    for key in ('capKnownBefore', 'capSpent', 'capCopyRejected', 'capReplayRejected', 'transientProofCleared',
                'retainedStartedCleared', 'completionAbsent', 'noNewPhysicalCalls'):
        need(value[key] is True)
    need(value['fullPrivateReceiptIndependentlyProven'] is False)
    need(report['reopenedExecutionPreserved'] is True and report['reopenedRecordCapabilityAbsent'] is True)
    positive = variant == 'positive'; durable = variant != 'not-committed'
    for key, expected in (('recordReturnedError', not positive), ('storePoisoned', not positive),
                          ('candidateAdopted', positive), ('liveOwnerCleared', not positive),
                          ('underlyingCommitted', durable), ('receiptPresent', durable)):
        need(value[key] is expected)
    integer(value['replaceAttempts'], 1, 1)
    integer(value['forwardedWrites'], int(durable), int(durable))
    reads = int(variant in ('positive', 'readback'))
    integer(value['postWriteReads'], reads, reads)
    integer(value['injectedReads'], int(variant == 'readback'), int(variant == 'readback'))
    source, disk = report['stages'][5], report['stages'][6]
    integer(value['sourceRevision'], source['revision'], source['revision'])
    need(value['sourceRecordSHA256'] == source['recordSHA256'] and value['sourceControlSHA256'] == source['controlSHA256'])
    integer(value['diskRevision'], disk['revision'], disk['revision'])
    need(value['diskRecordSHA256'] == disk['recordSHA256'] and value['diskControlSHA256'] == disk['controlSHA256'])
    memory = disk if positive else source
    integer(value['memoryRevision'], memory['revision'], memory['revision'])
    need(value['memoryRecordSHA256'] == memory['recordSHA256'])
    digest(value['sourceCurrentSHA256']); need(value['sourceCurrentSHA256'] == value['diskCurrentSHA256'])
    need(value['executionSchema'] == 'chengwang.mihomo-recovery-execution/' + ('v2' if durable else 'v1'))
    optional = ('receiptSHA256', 'observationSHA256', 'verificationCommitRevision', 'recordedAt', 's1PreimageSHA256')
    if durable:
        digest(value['receiptSHA256']); digest(value['observationSHA256'])
        fact = decode(raw['recovery-s2-verification.json'])
        fact['verificationSHA256'] = sha(raw['recovery-s2-verification.json'])
        observed = recovery_go_bytes(fact, recovery_projection_reader())
        need(value['observationSHA256'] == sha(observed))
        integer(value['verificationCommitRevision'], source['revision']+1, source['revision']+1)
        need(value['s1PreimageSHA256'] == source['controlSHA256'] and value['recordedAt'] == value['attemptedAt'])
    else:
        need(all(value[key] is None for key in optional))
    begin, end = timestamp(value['attemptedAt']), timestamp(value['returnedAt'])
    need(timestamp(report['controlPlane']['localPath']['returnedAt']) <= begin <= end)
    points = report['verificationEvents']; need(type(points) is list and len(points) == 2)
    boundary = report['controlEvents'][1]
    for stage, point in zip(('before-verification-record', 'after-verification-record'), points):
        exact(point, ('stage', 'count', 'lastSequence', 'eventsSHA256'))
        need(point['stage'] == stage)
        integer(point['count'], boundary['count'], boundary['count'])
        integer(point['lastSequence'], boundary['lastSequence'], boundary['lastSequence'])
        need(point['eventsSHA256'] == boundary['eventsSHA256'] == event_prefix_sha(report['nativeCalls'], point['count']))
    need(end <= timestamp(report['nativeCalls'][boundary['count']]['at']))
    return {'variant': variant, 'originalProjectionSHA256': sha(original), 'actualReplaceAttempts': 1,
            'actualUnderlyingWriteCalls': int(durable), 'postWriteReadbackCalls': reads,
            'publicationAccepted': positive, 'actualDurableReceiptPresentAfterAttempt': durable,
            'uncertainCandidateNotAdopted': not positive, 'capSpentAndReplayDeniedObserved': True,
            'coldReopenFactAndAbsencePreserved': True, 'noReopenLiveCapability': True,
            'fullPrivateReceiptIndependentlyProven': False, 'completionProven': False, 'production': False}


def endpoint_cleanup(value):
    # These are source-bound owner observations plus actual TCP probes. They
    # do not establish complete syscall tracing or arbitrary process custody.
    ports = [28411, 28412, 28413, 28414, 28415]
    same(value['closedPorts'], ports)
    fixtures = value['fixtureCleanup']
    need(type(fixtures) is list and len(fixtures) == 3)
    for role, item in zip(('origin', 'A', 'B'), fixtures):
        row = exact(item, ('role', 'shutdownReturned', 'serveReturned', 'forcedConnectionsClosed', 'errorClass'))
        need(row['role'] == role and row['shutdownReturned'] is True and row['serveReturned'] is True)
        need(row['errorClass'] == 'NONE')
        integer(row['forcedConnectionsClosed'], 0)
    probes = value['cleanupProbes']
    need(type(probes) is list and len(probes) == len(ports))
    for port, item in zip(ports, probes):
        row = exact(item, ('port', 'attempted', 'result'))
        integer(row['port'], port, port)
        need(row['attempted'] is True and row['result'] == 'CONNECTION_REFUSED')
    return {'fixtureCleanupRecords': len(fixtures), 'actualEndpointProbeRecords': len(probes)}


def native_report(raw, source_commit, elf, sandbox_value, go_result, variant='positive'):
    value = exact(decode(raw['native-report.json']), REPORT_KEYS)
    need(value['schema'] == 'chengwang.mihomo-native-recovery-experiment/v5' and value['scope'] == SCOPE and value['sourceCommit'] == source_commit and value['verificationMode'] == variant)
    need(value['outcome'] == 'PASS' and value['failureCode'] == 'NONE')
    for key in ('replayRejected', 'recoverySelfApprovalDenied', 'dualOwnerCloseRejectedTwice', 'countersBounded',
                'runtimeClosed', 'newDiskOwnerClosed', 'cleanupReplayNoOp'):
        need(value[key] is True)
    for key in ('httpRecoveryProven', 'completionProven', 'fullPrivateWALIndependentlyProven',
                'syntaxRawStreamsIndependentlyProven', 'internetBusinessProven', 'production'):
        need(value[key] is False)
    cleanup = endpoint_cleanup(value)
    original_unknown(value['originalUnknown'])
    digest(value['startedSHA256'])
    fault = exact(value['fault'], ('schema', 'state', 'claimed', 'underlyingRoundTrips', 'statusCode', 'bodyBytes',
                                  'eofObserved', 'closeSucceeded', 'injected', 'failureCode'))
    need(fault['schema'] == 'chengwang.mihomo-reload-response-loss-observation/v1' and fault['state'] == 'INJECTED')
    need(all(fault[k] is True for k in ('claimed', 'eofObserved', 'closeSucceeded', 'injected')) and fault['failureCode'] is None)
    integer(fault['underlyingRoundTrips'], 1, 1)
    integer(fault['statusCode'], 204, 204)
    integer(fault['bodyBytes'], 0, 0)
    for name, expected in (('reloadBefore', 0), ('reloadUnknown', 1), ('reloadFinal', 1)):
        counters = exact(value[name], ('reloadInvocations', 'doInvocations'))
        for v in counters.values():
            integer(v, expected, expected)
    netns = int(re.fullmatch(r'net:\[([1-9][0-9]*)\]', sandbox_value['networkNamespace'])[1])
    old = identity(value['oldIdentity'], source_commit, elf, netns)
    new = identity(value['newIdentity'], source_commit, elf, netns, value['originalUnknown']['candidateConfigSHA256'])
    need((old['pid'], old['startTicks']) != (new['pid'], new['startTicks']))
    start_observation(value['bootstrapStart'], old, raw['old-kernel.stdout'], raw['old-kernel.stderr'])
    old_exit = exited(value['oldCleanup'], raw['old-kernel.stdout'], raw['old-kernel.stderr'])
    new_exit = exited(value['newCleanup'], raw['new-kernel.stdout'], raw['new-kernel.stderr'])
    q = exact(value['quiescence'], ('schema', 'startupIdentity', 'stopInvoked', 'stopReturned', 'stopErrorClass', 'stop',
                                   'namespaceInode', 'controllerProbe', 'mixedProbe', 'startedAt', 'returnedAt', 'outcome', 'failureCode'))
    need(q['schema'] == 'chengwang.mihomo-owned-quiescence-observation/v1' and q['outcome'] == 'QUIESCED' and q['failureCode'] == 'NONE')
    same(q['startupIdentity'], old)
    same(q['stop'], old_exit)
    need(q['stopInvoked'] is True and q['stopReturned'] is True and q['stopErrorClass'] == 'NONE')
    integer(q['namespaceInode'], netns, netns)
    for key, port in (('controllerProbe', 28412), ('mixedProbe', 28411)):
        probe = exact(q[key], ('port', 'attempted', 'result'))
        integer(probe['port'], port, port)
        need(probe['attempted'] is True and probe['result'] == 'CONNECTION_REFUSED')
    s = exact(value['start'], ('schema', 'permitConsumed', 'startInvoked', 'startReturned', 'startErrorClass',
                              'startObservation', 'startupIdentity', 'verifiedIdentity', 'namespaceInode',
                              'listenersBefore', 'listenersAfter', 'startedAt', 'returnedAt', 'outcome', 'failureCode'))
    need(s['schema'] == 'chengwang.mihomo-owned-recovery-start-observation/v1' and s['outcome'] == 'STARTED' and s['failureCode'] == 'NONE')
    need(all(s[k] is True for k in ('permitConsumed', 'startInvoked', 'startReturned', 'listenersBefore', 'listenersAfter')) and s['startErrorClass'] == 'NONE')
    same(s['startupIdentity'], new)
    same(s['verifiedIdentity'], new)
    integer(s['namespaceInode'], netns, netns)
    start_observation(s['startObservation'], new, raw['new-kernel.stdout'], raw['new-kernel.stderr'])
    qbegin, qend = timestamp(q['startedAt']), timestamp(q['returnedAt'])
    sbegin, send = timestamp(s['startedAt']), timestamp(s['returnedAt'])
    need(go_result['testStartedAtNanoseconds'] <= qbegin <= qend <= sbegin <= send <= go_result['testPassedAtNanoseconds'])
    need(type(value['syntax']) is list and len(value['syntax']) == 1)
    syntax_observation(value['syntax'][0])
    calls = value['nativeCalls']
    positions = native_events(calls, value['oldCore'], value['newCore'],
                              (go_result['testStartedAtNanoseconds'], go_result['testPassedAtNanoseconds']))
    one = lambda core, kind: timestamp(calls[positions[(core, kind)][0] - 1]['at'])
    need(qbegin <= one(value['oldCore'], 'RECOVERY_STOP_DISPATCH') <= qend)
    need(sbegin <= one(0, 'RECOVERY_START_DISPATCH') <= one(value['newCore'], 'KERNEL_OS_START_ATTEMPT') <= one(value['newCore'], 'KERNEL_OS_START_RETURN') <= send)
    for core, exit in ((value['oldCore'], old_exit), (value['newCore'], new_exit)):
        if exit['killSent']:
            need(len(positions.get((core, 'KERNEL_OS_KILL_ATTEMPT'), [])) == 1)
    replay = event_checkpoints(value['eventCheckpoints'], calls, positions, value['oldCore'], value['newCore'])
    index = wal_index(raw['wal-readback-index.json'], value, source_commit, variant)
    control = recovery_control(raw, value, source_commit, elf, netns)
    persisted = verification_record(raw, value, variant)
    return value, {'sourceCallEvents': len(calls), 'replay': replay, 'wal': index,
                   'endpointCleanup': cleanup,
                   'recoveryControlObservation': control, 'verificationRecord': persisted,
                   'ownedKernelStartAttempts': 2, 'ownedKernelWaitReturns': 2,
                   'syntaxStartAttempts': 1, 'syntaxReportedWaitReturns': 1,
                   'oldStopDispatches': 1, 'newStartDispatches': 1,
                   'oldStopHelperEntries': 2, 'newStopHelperEntries': 1,
                   'termAttempts': 2,
                   'killAttempts': sum(len(positions.get((c, 'KERNEL_OS_KILL_ATTEMPT'), [])) for c in (value['oldCore'], value['newCore'])),
                   'syntaxRawStreamsIndependentlyProven': False,
                   'fullPrivateWALIndependentlyProven': False, 'controllerReceivedCount': None}

# Fixed proposed source manifest. Root will explicitly extend it when the
# native CI runner is added; no producer/runtime code is imported to derive it.
FILES = (
    '.github/workflows/chengwang-mihomo-lifecycle.yml',
    'chengwang/deploy/mihomo-lifecycle-lab/apply_contract.json',
    'chengwang/deploy/mihomo-lifecycle-lab/apply_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_apply.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_compat.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_native_recovery.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_service.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_unknown.py',
    'chengwang/deploy/mihomo-lifecycle-lab/compat_contract.json',
    'chengwang/deploy/mihomo-lifecycle-lab/compat_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/get_projection.py',
    'chengwang/deploy/mihomo-lifecycle-lab/legacy_go_tops.json',
    'chengwang/deploy/mihomo-lifecycle-lab/native_recovery_contract.json',
    'chengwang/deploy/mihomo-lifecycle-lab/native_recovery_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/run_apply.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/run_compat.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/run_service.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/run_unknown.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/service_contract.json',
    'chengwang/deploy/mihomo-lifecycle-lab/service_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_apply.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_compat.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_contracts.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_native_recovery.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_service.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_check_unknown.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_get_projection.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_service_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/test_unknown_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/unknown_contract.json',
    'chengwang/deploy/mihomo-lifecycle-lab/unknown_worker.py',
    'chengwang/go.mod',
    'chengwang/internal/adapter/mihomo/lab_evidence.go',
    'chengwang/internal/adapter/mihomo/lab_evidence_test.go',
    'chengwang/internal/adapter/mihomo/lab_readback.go',
    'chengwang/internal/adapter/mihomo/lab_readback_test.go',
    'chengwang/internal/adapter/mihomo/lab_sample_times.go',
    'chengwang/internal/adapter/mihomo/lab_sample_times_test.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_default.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_linux.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_linux_test.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_unsupported.go',
    'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
    'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
    'chengwang/internal/adapter/mihomo/lab_target_readback.go',
    'chengwang/internal/adapter/mihomo/lab_target_readback_test.go',
    'chengwang/internal/adapter/mihomo/write_client.go',
    'chengwang/internal/adapter/mihomo/write_client_test.go',
    'chengwang/internal/api/mihomo_lab.go',
    'chengwang/internal/api/mihomo_lab_test.go',
    'chengwang/internal/api/server.go',
    'chengwang/internal/authn/snapshot_manager.go',
    'chengwang/internal/authn/snapshot_manager_linux.go',
    'chengwang/internal/authn/snapshot_manager_linux_test.go',
    'chengwang/internal/authn/snapshot_manager_test.go',
    'chengwang/internal/authn/snapshot_manager_unsupported.go',
    'chengwang/internal/authn/continuous_bound_credentials_linux.go',
    'chengwang/internal/authn/continuous_bound_credentials_linux_test.go',
    'chengwang/internal/authn/store.go',
    'chengwang/internal/authn/store_test.go',
    'chengwang/internal/authz/image_trust_history_d8_test.go',
    'chengwang/internal/authz/image_trust_test.go',
    'chengwang/internal/authz/lab_recovery.go',
    'chengwang/internal/authz/lab_recovery_test.go',
    'chengwang/internal/authz/model.go',
    'chengwang/internal/authz/policy.go',
    'chengwang/internal/authz/policy_test.go',
    'chengwang/internal/authz/subscription.go',
    'chengwang/internal/authz/subscription_test.go',
    'chengwang/internal/mihomodeploy/artifact.go',
    'chengwang/internal/mihomodeploy/artifact_linux.go',
    'chengwang/internal/mihomodeploy/artifact_linux_test.go',
    'chengwang/internal/mihomodeploy/artifact_test.go',
    'chengwang/internal/mihomodeploy/artifact_unsupported.go',
    'chengwang/internal/mihomodeploy/config.go',
    'chengwang/internal/mihomodeploy/config_test.go',
    'chengwang/internal/mihomodeploy/lab_authority.go',
    'chengwang/internal/mihomodeploy/lab_authority_test.go',
    'chengwang/internal/mihomodeploy/lab_backend.go',
    'chengwang/internal/mihomodeploy/lab_bootstrap.go',
    'chengwang/internal/mihomodeploy/lab_bootstrap_linux.go',
    'chengwang/internal/mihomodeploy/lab_bootstrap_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_bootstrap_state.go',
    'chengwang/internal/mihomodeploy/lab_bootstrap_test.go',
    'chengwang/internal/mihomodeploy/lab_bootstrap_unsupported.go',
    'chengwang/internal/mihomodeploy/lab_collector.go',
    'chengwang/internal/mihomodeploy/lab_collector_linux.go',
    'chengwang/internal/mihomodeploy/lab_collector_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_collector_test.go',
    'chengwang/internal/mihomodeploy/lab_collector_unsupported.go',
    'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_expectation.go',
    'chengwang/internal/mihomodeploy/lab_expectation_test.go',
    'chengwang/internal/mihomodeploy/lab_kernel.go',
    'chengwang/internal/mihomodeploy/lab_kernel_linux.go',
    'chengwang/internal/mihomodeploy/lab_kernel_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_kernel_unsupported.go',
    'chengwang/internal/mihomodeploy/lab_kernel_unsupported_test.go',
    'chengwang/internal/mihomodeploy/lab_local_route.go',
    'chengwang/internal/mihomodeploy/lab_local_route_test.go',
    'chengwang/internal/mihomodeploy/lab_native_recovery_linux.go',
    'chengwang/internal/mihomodeploy/lab_native_recovery_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_native_recovery_observer_default.go',
    'chengwang/internal/mihomodeploy/lab_native_recovery_observer_linux.go',
    'chengwang/internal/mihomodeploy/lab_quiescence.go',
    'chengwang/internal/mihomodeploy/lab_quiescence_linux.go',
    'chengwang/internal/mihomodeploy/lab_quiescence_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_quiescence_test.go',
    'chengwang/internal/mihomodeploy/lab_quiescence_unsupported.go',
    'chengwang/internal/mihomodeploy/lab_recovery_authority.go',
    'chengwang/internal/mihomodeploy/lab_recovery_authority_test.go',
    'chengwang/internal/mihomodeploy/lab_recovery_collector.go',
    'chengwang/internal/mihomodeploy/lab_recovery_collector_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_recovery_plan.go',
    'chengwang/internal/mihomodeploy/lab_recovery_plan_test.go',
    'chengwang/internal/mihomodeploy/lab_recovery_start.go',
    'chengwang/internal/mihomodeploy/lab_recovery_start_linux.go',
    'chengwang/internal/mihomodeploy/lab_recovery_start_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_recovery_start_test.go',
    'chengwang/internal/mihomodeploy/lab_recovery_start_unsupported.go',
    'chengwang/internal/mihomodeploy/lab_service.go',
    'chengwang/internal/mihomodeploy/lab_service_acceptance_linux.go',
    'chengwang/internal/mihomodeploy/lab_service_diagnostics.go',
    'chengwang/internal/mihomodeploy/lab_service_diagnostics_test.go',
    'chengwang/internal/mihomodeploy/lab_service_test.go',
    'chengwang/internal/mihomodeploy/lab_syntax_linux.go',
    'chengwang/internal/mihomodeploy/lab_syntax_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_syntax_unsupported.go',
    'chengwang/internal/mihomodeploy/lab_syntax_unsupported_test.go',
    'chengwang/internal/mihomodeploy/lab_unknown_acceptance_linux.go',
    'chengwang/internal/mihomodeploy/lifecycle.go',
    'chengwang/internal/mihomodeploy/lifecycle_disk.go',
    'chengwang/internal/mihomodeploy/lifecycle_linux.go',
    'chengwang/internal/mihomodeploy/lifecycle_linux_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_recovery_started.go',
    'chengwang/internal/mihomodeploy/lifecycle_recovery_started_linux_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_recovery_store.go',
    'chengwang/internal/mihomodeploy/lifecycle_recovery_store_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions.go',
    'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_trusted_clone_properties_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_unsupported.go',
    'chengwang/internal/mihomodeploy/lifecycle_unsupported_test.go',
    'chengwang/internal/mihomodeploy/lifecycle_v3.go',
    'chengwang/internal/mihomodeploy/lifecycle_v3_test.go',
    'chengwang/internal/mihomodeploy/plan.go',
    'chengwang/internal/mihomodeploy/plan_test.go',
    'chengwang/internal/mihomodeploy/prepare.go',
    'chengwang/internal/mihomodeploy/prepare_test.go',
    'chengwang/internal/mihomodeploy/private_atomic_linux.go',
    'chengwang/internal/mihomodeploy/runtime_apply_linux_test.go',
    'chengwang/internal/mihomodeploy/runtime_compat_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_lab_config_test.go',
    'chengwang/internal/serverruntime/mihomo_lab_runtime.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
    'chengwang/internal/serverruntime/mihomo_service_e2e_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_unknown_e2e_linux_test.go',
    'chengwang/internal/serverruntime/runtime.go',
    'chengwang/internal/serverruntime/subscription_runtime_linux_test.go',
    'chengwang/tools/mihomo-runtime-candidate/README.md',
    'chengwang/tools/mihomo-runtime-candidate/check_consumption.py',
    'chengwang/tools/mihomo-runtime-candidate/consume_pin.py',
    'chengwang/tools/mihomo-runtime-candidate/pin.json',
    'chengwang/tools/mihomo-runtime-candidate/test_consume_pin.py',
)
FILES = tuple(sorted((*FILES, '.github/workflows/chengwang-mihomo-native-recovery.yml',
                      PREFIX + 'run_native_recovery.sh',
                      'chengwang/internal/mihomodeploy/lab_recovery_marker.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_marker_test.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_marker_bounds_test.go')))
FILES = tuple(sorted((*FILES, 'chengwang/internal/mihomodeploy/lifecycle_recovery_verification.go',
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_verification_test.go',
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_verified_bounds_test.go')))
FILES = tuple(sorted((*FILES,
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_checkpoint.go',
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_completion.go',
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_completion_test.go',
                      'chengwang/internal/mihomodeploy/lifecycle_completion_shape_diagnostic_test.go',
                      'chengwang/internal/mihomodeploy/lifecycle_v3_decode_scope_test.go',
                      'chengwang/internal/mihomodeploy/lifecycle_current_epoch.go',
                      'chengwang/internal/mihomodeploy/lifecycle_current_epoch_test.go',
                      'chengwang/internal/mihomodeploy/lab_current_epoch_runtime.go',
                      'chengwang/internal/mihomodeploy/lab_current_epoch_runtime_test.go')))
FILES = tuple(sorted((*FILES,
                      'chengwang/internal/api/mihomo_recovery.go',
                      'chengwang/internal/api/mihomo_recovery_test.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_backend.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_backend_test.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_cleanup_bridge.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_coordinator_linux.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_coordinator_unsupported.go',
                      'chengwang/internal/mihomodeploy/lab_recovery_unstarted_cleanup_linux_test.go',
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_reconcile.go',
                      'chengwang/internal/mihomodeploy/lifecycle_recovery_reconcile_test.go')))


def make_source_manifest(sources, source_commit):
    need(type(sources) is dict and set(sources) == set(FILES) and len(FILES) == len(set(FILES)) == 199)
    need(type(source_commit) is str and COMMIT.fullmatch(source_commit) is not None)
    return {'schema': 'chengwang.mihomo-native-source-manifest/v1',
            'scope': 'FIXED_GIT_SOURCE_BYTES_NOT_NATIVE_EXECUTION',
            'sourceCommit': source_commit, 'sourceCount': len(FILES),
            'sourceGitVerified': False,
            'files': [{'path': p, 'bytes': len(sources[p]), 'sha256': sha(sources[p])} for p in FILES],
            'production': False}


def source_manifests(raw, sources, source_commit):
    need(raw['source-before.json'] == raw['source-after.json'])
    value = exact(decode(raw['source-before.json']),
                  ('schema', 'scope', 'sourceCommit', 'sourceCount', 'sourceGitVerified', 'files', 'production'))
    expected = make_source_manifest(sources, source_commit)
    # This is only an input projection comparison. verify_raw itself retains
    # sourceGitVerified=false; the CLI independently checks the real Git tree.
    expected['sourceGitVerified'] = True
    same(value, expected)
    need(canonical(value) == raw['source-before.json'])
    return {'sourceFiles': len(FILES), 'sourceBeforeAfterByteEqual': True,
            'sourceManifestSHA256': sha(raw['source-before.json'])}


def verify_raw(raw, sources, source_commit, variant='positive'):
    need(variant in VARIANTS)
    need(type(source_commit) is str and COMMIT.fullmatch(source_commit) is not None)
    need(type(raw) is dict and set(raw) == set(PUBLIC) and len(PUBLIC) == len(set(PUBLIC)) == 33)
    need(all(type(v) is bytes and len(v) <= 16 << 20 for v in raw.values()) and sum(map(len, raw.values())) <= 16 << 20)
    need(type(sources) is dict and set(sources) == set(FILES) and len(FILES) == len(set(FILES)) == 199)
    need(all(type(v) is bytes and 0 < len(v) <= 1 << 20 for v in sources.values()))
    for path in FILES:
        source_path(path)
    source_observation = source_manifests(raw, sources, source_commit)
    contract(sources)
    execution = exact(decode(raw['execution.json']), ('schema', 'scope', 'verificationMode', 'sourceCommit', 'formatExit', 'goExit', 'captureState', 'production'))
    need(execution['schema'] == 'chengwang.mihomo-native-recovery-execution/v2' and execution['scope'] == SCOPE and execution['sourceCommit'] == source_commit and execution['verificationMode'] == variant)
    need(execution['captureState'] == 'CAPTURED_NOT_INDEPENDENT_ACCEPTANCE' and execution['production'] is False)
    integer(execution['formatExit'], 0, 0)
    integer(execution['goExit'], 0, 0)
    need(raw['gofmt.patch'] == raw['gofmt.stderr'] == raw['native.stderr'] == b'')
    need(raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
    elf, receipt = consumption(raw, sources, source_commit)
    facts = sandbox(raw, sources, source_commit, elf, receipt, variant)
    commands_value = commands(raw['commands.jsonl'], source_commit, sha(sources['chengwang/go.mod']),
                               {k: facts[k] for k in NS_KEYS}, variant)
    process = process_events(raw['process-events.jsonl'], commands_value)
    go_result = go_events(raw['native.json'])
    report, observed = native_report(raw, source_commit, elf, facts, go_result, variant)
    return {'schema': 'chengwang.mihomo-native-recovery-verification/v1', 'scope': SCOPE,
            'sourceCommit': source_commit, 'outcome': 'PASS', 'verificationMode': variant,
            'tests': {k: go_result[k] for k in ('topLevel', 'passingSemanticTests', 'skips')},
            'sourceSHA256': {p: sha(sources[p]) for p in FILES},
            'originalSHA256': {p: sha(raw[p]) for p in PUBLIC},
            'commandObservations': process, 'nativeObservations': observed,
            'sourceManifestObservation': source_observation,
            'sourceGitVerified': False, 'privateCredentialContentsIndependentlyProven': False,
            'privateDisclosureFenceIndependentlyProven': False,
            'completeKernelSyscallTracingProven': False, 'candidateBinaryReacquiredByChecker': False,
            'syntaxRawStreamsIndependentlyProven': False,
            'fullPrivateWALIndependentlyProven': False, 'controllerReceivedCount': None,
            'httpRecoveryProven': False, 'completionProven': False,
            'internetBusinessProven': False, 'publisherSignatureProven': False, 'production': False}


def file_bytes(path, limit):
    path = Path(path).absolute()
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit)
    raw = path.read_bytes()
    after = path.lstat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns)
    need(signature(before) == signature(after) and len(raw) == before.st_size)
    return raw


def source_git(repo, source_commit):
    repo = Path(repo).resolve(strict=True)
    need(type(source_commit) is str and COMMIT.fullmatch(source_commit) is not None)

    def git(*args):
        result = subprocess.run(['git', '-C', str(repo), *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        need(result.returncode == 0 and len(result.stdout) <= 1 << 20 and len(result.stderr) <= 1 << 20)
        return result.stdout

    need(git('rev-parse', 'HEAD').strip().decode('ascii') == source_commit)
    need(Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() == repo)
    tree_raw = git('ls-tree', '-r', '-z', source_commit, '--', *FILES)
    tree = {}
    for row in tree_raw.split(b'\0'):
        if not row:
            continue
        meta, encoded = row.split(b'\t', 1)
        mode, kind, oid = meta.split()
        path = encoded.decode('utf-8', errors='strict')
        need(path in FILES and path not in tree and mode in (b'100644', b'100755') and kind == b'blob')
        tree[path] = (mode, oid.decode('ascii'))
    need(set(tree) == set(FILES))
    index = git('ls-files', '--stage', '-z', '--', *FILES)
    entries = {}
    for row in index.split(b'\0'):
        if not row:
            continue
        meta, encoded = row.split(b'\t', 1)
        mode, oid, stage = meta.split()
        path = encoded.decode('utf-8', errors='strict')
        need(path in FILES and path not in entries and mode in (b'100644', b'100755') and stage == b'0')
        entries[path] = (mode, oid.decode('ascii'))
    need(set(entries) == set(FILES))
    need(entries == tree)
    sources = {p: file_bytes(repo / p, 1 << 20) for p in FILES}
    for path, raw in sources.items():
        need(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == tree[path][1])
        if os.name == 'posix':
            need(bool((repo / path).lstat().st_mode & 0o111) == (tree[path][0] == b'100755'))
    return sources


def write_report(path, raw):
    need(os.name == 'posix' and os.open in os.supports_dir_fd)
    path = Path(path).absolute()
    for part in (*reversed(path.parent.parents), path.parent):
        need(not stat.S_ISLNK(part.lstat().st_mode))
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            data = memoryview(raw)
            while data:
                written = os.write(fd, data)
                need(written > 0)
                data = data[written:]
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report')
    parser.add_argument('--source-manifest')
    parser.add_argument('--variant', choices=VARIANTS, default='positive')
    args = parser.parse_args()
    repo = Path(args.repo).resolve(strict=True)
    checker = repo / PREFIX / 'check_native_recovery.py'
    need(Path(__file__).resolve(strict=True) == checker.resolve(strict=True))
    if args.source_manifest is not None:
        need(args.evidence is None and args.report is None)
        sources = source_git(args.repo, args.source_commit)
        need(file_bytes(Path(__file__), 1 << 20) == sources[PREFIX + 'check_native_recovery.py'])
        manifest = make_source_manifest(sources, args.source_commit)
        manifest['sourceGitVerified'] = True
        need(source_git(args.repo, args.source_commit) == sources)
        write_report(args.source_manifest, canonical(manifest))
        print('MIHOMO_NATIVE_SOURCE_MANIFEST=PASS source_bytes_only=true production=false')
        return
    need(args.evidence is not None and args.report is not None)
    evidence = Path(args.evidence).resolve(strict=True)
    need(evidence.is_dir() and {p.name for p in evidence.iterdir()} == set(PUBLIC))
    sources = source_git(args.repo, args.source_commit)
    need(file_bytes(Path(__file__), 1 << 20) == sources[PREFIX + 'check_native_recovery.py'])
    raw = {p: file_bytes(evidence / p, 16 << 20) for p in PUBLIC}
    before = {p: sha(v) for p, v in raw.items()}
    value = verify_raw(raw, sources, args.source_commit, args.variant)
    need(source_git(args.repo, args.source_commit) == sources)
    need(before == {p: sha(file_bytes(evidence / p, 16 << 20)) for p in PUBLIC})
    value['sourceGitVerified'] = True
    write_report(args.report, canonical(value))
    print('MIHOMO_NATIVE_RECOVERY=PASS public_started_experiment_only=true full_private_wal=false production=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('MIHOMO_NATIVE_RECOVERY=REJECTED raw_input_suppressed=true') from None
