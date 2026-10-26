"""Independent original-evidence checker; never imports the apply producer.

verify_raw is an in-memory evidence verifier, also usable by explicitly
synthetic unit fixtures. The CLI additionally requires Linux custody and every
source blob to match the requested Git commit. Neither path executes Mihomo.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


PREFIX = 'chengwang/deploy/mihomo-lifecycle-lab/'
RUNTIME = 'chengwang/internal/mihomodeploy/runtime_apply_linux_test.go'
BOUND_CREDENTIAL_SOURCES = (
    'chengwang/internal/authn/continuous_bound_credentials_linux.go',
    'chengwang/internal/authn/continuous_bound_credentials_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_credentials_linux_test.go')


def need(value):
    if not value:
        raise ValueError('Mihomo local apply evidence rejected')


def _independent_compat():
    # Fixed independent sibling only. Its bytes, and all of its dependencies,
    # are in FILES and bound again by the CLI. No producer module is imported.
    path = Path(__file__).absolute().with_name('check_compat.py')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
    spec = importlib.util.spec_from_file_location('_apply_independent_compat', path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = _independent_compat()
def _independent_projection():
    path = Path(__file__).absolute().with_name('get_projection.py')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
    spec = importlib.util.spec_from_file_location('_apply_independent_projection', path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


G = _independent_projection()
FILES = tuple(C.FILES) + tuple(PREFIX + name for name in (
    'apply_contract.json', 'apply_worker.py', 'run_apply.sh', 'check_apply.py', 'test_check_apply.py',
    'get_projection.py', 'test_get_projection.py')) + (RUNTIME,)
TOP = 'TestMihomoApplyReloadReadbackAndLocalProxy'
PACKAGE = 'chengwang/internal/mihomodeploy'
SCOPE = 'ACTUAL_FIXED_KERNEL_LOCAL_APPLY_EXPERIMENT_NOT_API_AUTHORIZATION_HEAD_OR_PRODUCTION'
REPORT_SCOPE = 'ACTUAL_LOCAL_APPLY_EXPERIMENT_NOT_FULL_PROJECT'
TEST_PUBLIC = ('apply-observations.jsonl', 'apply-report.json', 'kernel.stdout', 'kernel.stderr',
               'syntax.exec.json', 'syntax.stdout', 'syntax.stderr')
CAPTURE_PUBLIC = tuple(name for phase in ('baseline', 'candidate')
    for name in (phase + '-get-evidence.json', *[phase + '-get-' + str(i).zfill(2) + '.body' for i in range(1, 9)]))
TEST_PUBLIC += CAPTURE_PUBLIC
WORKER_PUBLIC = ('sandbox.json', 'execution.json', 'go-version.txt', 'gofmt.patch', 'gofmt.stderr', 'apply.json', 'apply.stderr')
PREEXISTING = ('host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json')
PUBLIC = TEST_PUBLIC + WORKER_PUBLIC + PREEXISTING
FLAGS = ('apiExercised', 'authorizationExercised', 'authorizationProven', 'fullPayloadProven', 'headAdvanced',
         'production', 'perGetRawEvidenceAvailable', 'independentProjectionRecomputeProven', 'internetBusinessProven')
ENV = ('CGO_ENABLED', 'CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT', 'GOCACHE', 'GOENV', 'GOFLAGS', 'GOMODCACHE',
       'GOPROXY', 'GOROOT', 'GOSUMDB', 'GOTOOLCHAIN', 'HOME', 'LANG', 'LC_ALL', 'PATH', 'TMPDIR', 'TZ')
BINDING_KEYS = ('sha256', 'bytes')
BODY_KEYS = ('sha256', 'bytes', 'complete')
STREAM_KEYS = ('bytes', 'totalBytes', 'sha256', 'truncated', 'complete')
OBSERVATION_KEYS = ('attempted', 'started', 'pid', 'startTicks', 'waitReturned', 'waitErrorClass', 'exitCode',
                    'signal', 'termSent', 'killSent', 'groupAbsent', 'stdout', 'stderr')
IDENTITY_KEYS = ('pid', 'startTicks', 'netNSInode', 'elfSHA256', 'elfBytes', 'sourceCommit', 'artifactSHA256', 'controllerPort', 'mixedPort')
READBACK_KEYS = ('conclusion', 'sampleCount', 'requestsObserved', 'previousProjectionSHA256', 'candidateProjectionSHA256',
                 'observedProjectionSHA256', 'dataplaneProven', 'fullPayloadProven', 'authorizationProven', 'production')
ROUTE_KEYS = ('phase', 'nonceSHA256', 'clientResponse', 'proxyResponse', 'originResponse', 'countersBefore', 'countersAfter', 'matched')
COUNTER_KEYS = ('role', 'connectIngress', 'tunnelRequests', 'forwardInvocations', 'originRequests', 'rejected')
CLEANUP_KEYS = ('role', 'shutdownReturned', 'serveReturned', 'forcedConnectionsClosed', 'errorClass')
PROBE_KEYS = ('role', 'statusCode', 'body', 'errorClass')
REPORT_KEYS = ('schema', 'scope', 'sourceCommit', 'outcome', 'failureCode', 'baseInput', 'candidateInput', 'syntaxSHA256',
               'kernelObservation', 'ownedBefore', 'ownedAfter', 'readbacks', 'getEvidence', 'readiness', 'clientReloadInvocations',
               'controllerReceivedCount', 'reloadPayload', 'reloadResult', 'reloadErrorClass', 'routes', 'fixtureCleanup', 'flags')
FACT_KEYS = ('code', 'baseInput', 'candidateInput', 'receiptSHA256', 'kernelObservation', 'ownedIdentity', 'readinessProbe',
             'readback', 'getEvidence', 'reloadPayload', 'reloadResult', 'clientReloadInvocations', 'route', 'fixtureCleanup')
JOURNAL_KEYS = ('schema', 'seq', 'stage', 'observedAtUTC', 'facts')
SYNTAX_KEYS = ('schema', 'sourceCommit', 'binary', 'receiptSHA256', 'input', 'argvClass', 'observation')
EXECUTION_KEYS = ('schema', 'sourceCommit', 'formatExit', 'goExit', 'realMihomoExecutionObserved', 'production')
SANDBOX_KEYS = ('schema', 'sourceCommit', 'uid', 'gid', 'effectiveCaps', 'noNewPrivileges', 'networkNamespace', 'mountNamespace',
                'pidNamespace', 'environmentKeys', 'interfaceNames', 'defaultV4Routes', 'defaultV6Routes', 'sourceModuleSHA256',
                'sourceReadOnly', 'goReadOnly', 'kernelCopy', 'inputCustody')
STAGES = ('INPUT_OPENED', 'ARTIFACTS_BOUND', 'FIXTURES_LISTENING', 'KERNEL_START_BEGIN', 'KERNEL_START_RESULT',
          'READINESS_PROBE', 'BASELINE_READ_BEGIN', 'BASELINE_READ_RESULT', 'BASELINE_ROUTE_RESULT', 'SYNTAX_BEGIN',
          'SYNTAX_RESULT', 'RELOAD_BEGIN', 'RELOAD_RESULT', 'CANDIDATE_READ_BEGIN', 'CANDIDATE_READ_RESULT',
          'CANDIDATE_ROUTE_RESULT', 'OWNED_FINAL_RESULT', 'KERNEL_STOP_RESULT', 'FIXTURE_STOP_RESULT', 'FINAL_RESULT')
HEX = re.compile(r'[a-f0-9]{64}')
COMMIT = re.compile(r'[a-f0-9]{40}')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))
    return value


def integer(value, low=0, high=(1 << 63) - 1):
    need(type(value) is int and low <= value <= high)
    return value


def digest(value):
    need(type(value) is str and HEX.fullmatch(value) is not None)
    return value


def same(a, b):
    need(canonical(a) == canonical(b))


def decode(raw, *, elapsed=False):
    need(type(raw) is bytes and len(raw) <= 8 << 20)
    text = raw.decode('utf-8', errors='strict')
    need(not text.startswith('\ufeff'))

    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value

    def floating(text):
        need(elapsed)
        value = float(text)
        need(math.isfinite(value))
        return value

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
            need(len(item) <= 128)
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str:
            need(len(item) <= 1 << 20 and not any(0xd800 <= ord(c) <= 0xdfff for c in item))
    visit(value, 0)
    return value


def timestamp(value):
    # UTC RFC3339Nano; integer nanoseconds avoid float chronology aliases.
    need(type(value) is str)
    m = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z', value)
    need(m is not None)
    year, month, day, hour, minute, second = map(int, m.groups()[:6])
    need(1 <= year <= 9999 and hour < 24 and minute < 60 and second < 60)
    date = datetime.date(year, month, day)
    return ((date.toordinal() * 24 + hour) * 3600 + minute * 60 + second) * 10**9 + int((m.group(7) or '').ljust(9, '0'))


def contract(sources):
    c = decode(sources[PREFIX + 'apply_contract.json'])
    expected = {'schema': 'chengwang.mihomo-runtime-apply-contract/v2',
     'scope': 'ACTUAL_FIXED_KERNEL_LOCAL_APPLY_EXPERIMENT_NOT_API_AUTHORIZATION_HEAD_OR_PRODUCTION',
     'tag': 'chengwang_mihomo_apply',
     'goPackage': './internal/mihomodeploy',
     'topTests': ['TestMihomoApplyReloadReadbackAndLocalProxy'],
     'goTimeoutSeconds': 90,
     'sessionTimeoutSeconds': 60,
     'paths': {'module': '/tmp/mihomo-apply-source',
               'goRoot': '/tmp/mihomo-apply-go',
               'kernelDirectory': '/tmp/mihomo-apply-kernel',
               'kernel': '/tmp/mihomo-apply-kernel/mihomo',
               'receipt': '/tmp/mihomo-apply-kernel/consumption.json',
               'serviceHome': '/tmp/mihomo-apply-home',
               'buildHome': '/tmp/mihomo-apply-build',
               'privateOutput': '/tmp/mihomo-apply-private',
               'exportAlias': '/tmp/mihomo-apply-export'},
     'ports': {'mixed': 28411, 'controller': 28412, 'proxyA': 28413, 'proxyB': 28414, 'origin': 28415},
     'publicTestFiles': ['apply-observations.jsonl',
                         'apply-report.json',
                         'kernel.stdout',
                         'kernel.stderr',
                         'syntax.exec.json',
                         'syntax.stdout',
                         'syntax.stderr',
                         'baseline-get-evidence.json',
                         'baseline-get-01.body',
                         'baseline-get-02.body',
                         'baseline-get-03.body',
                         'baseline-get-04.body',
                         'baseline-get-05.body',
                         'baseline-get-06.body',
                         'baseline-get-07.body',
                         'baseline-get-08.body',
                         'candidate-get-evidence.json',
                         'candidate-get-01.body',
                         'candidate-get-02.body',
                         'candidate-get-03.body',
                         'candidate-get-04.body',
                         'candidate-get-05.body',
                         'candidate-get-06.body',
                         'candidate-get-07.body',
                         'candidate-get-08.body'],
     'privateExtraFiles': ['.secrets.private.json', 'base.config.private.yaml', 'candidate.config.private.yaml'],
     'secretsSchema': 'chengwang.mihomo-apply-private-secrets/v1',
     'secretsKeys': ['schema', 'controller', 'routeA', 'routeB'],
     'bindingKeys': ['sha256', 'bytes'],
     'bodyKeys': ['sha256', 'bytes', 'complete'],
     'streamKeys': ['bytes', 'totalBytes', 'sha256', 'truncated', 'complete'],
     'reportSchema': 'chengwang.mihomo-runtime-apply-report/v2',
     'reportKeys': ['schema',
                    'scope',
                    'sourceCommit',
                    'outcome',
                    'failureCode',
                    'baseInput',
                    'candidateInput',
                    'syntaxSHA256',
                    'kernelObservation',
                    'ownedBefore',
                    'ownedAfter',
                    'readbacks',
                    'getEvidence',
                    'readiness',
                    'clientReloadInvocations',
                    'controllerReceivedCount',
                    'reloadPayload',
                    'reloadResult',
                    'reloadErrorClass',
                    'routes',
                    'fixtureCleanup',
                    'flags'],
     'readbackKeys': ['conclusion',
                      'sampleCount',
                      'requestsObserved',
                      'previousProjectionSHA256',
                      'candidateProjectionSHA256',
                      'observedProjectionSHA256',
                      'dataplaneProven',
                      'fullPayloadProven',
                      'authorizationProven',
                      'production'],
     'readinessKeys': ['role', 'statusCode', 'body', 'errorClass'],
     'routeKeys': ['phase',
                   'nonceSHA256',
                   'clientResponse',
                   'proxyResponse',
                   'originResponse',
                   'countersBefore',
                   'countersAfter',
                   'matched'],
     'counterKeys': ['role',
                     'connectIngress',
                     'tunnelRequests',
                     'forwardInvocations',
                     'originRequests',
                     'rejected'],
     'fixtureCleanupKeys': ['role', 'shutdownReturned', 'serveReturned', 'forcedConnectionsClosed', 'errorClass'],
     'flags': {'apiExercised': False,
               'authorizationExercised': False,
               'authorizationProven': False,
               'fullPayloadProven': False,
               'headAdvanced': False,
               'production': False,
               'perGetRawEvidenceAvailable': True,
               'independentProjectionRecomputeProven': False,
               'internetBusinessProven': False},
     'syntaxSchema': 'chengwang.mihomo-apply-syntax-exec/v1',
     'syntaxKeys': ['schema', 'sourceCommit', 'binary', 'receiptSHA256', 'input', 'argvClass', 'observation'],
     'journalSchema': 'chengwang.mihomo-apply-observation/v1',
     'journalKeys': ['schema', 'seq', 'stage', 'observedAtUTC', 'facts'],
     'journalFactKeys': ['code',
                         'baseInput',
                         'candidateInput',
                         'receiptSHA256',
                         'kernelObservation',
                         'ownedIdentity',
                         'readinessProbe',
                         'readback',
                         'getEvidence',
                         'reloadPayload',
                         'reloadResult',
                         'clientReloadInvocations',
                         'route',
                         'fixtureCleanup'],
     'journalStages': ['INPUT_OPENED',
                       'ARTIFACTS_BOUND',
                       'FIXTURES_LISTENING',
                       'KERNEL_START_BEGIN',
                       'KERNEL_START_RESULT',
                       'READINESS_PROBE',
                       'BASELINE_READ_BEGIN',
                       'BASELINE_READ_RESULT',
                       'BASELINE_ROUTE_RESULT',
                       'SYNTAX_BEGIN',
                       'SYNTAX_RESULT',
                       'RELOAD_BEGIN',
                       'RELOAD_RESULT',
                       'CANDIDATE_READ_BEGIN',
                       'CANDIDATE_READ_RESULT',
                       'CANDIDATE_ROUTE_RESULT',
                       'OWNED_FINAL_RESULT',
                       'KERNEL_STOP_RESULT',
                       'FIXTURE_STOP_RESULT',
                       'FINAL_RESULT'],
     'maxJournalLines': 128,
     'controllerReceivedCount': None,
     'knownGaps': ['expected projection source from private complete YAML remains source-bound, not '
                   'independently proven by public originals',
                   'private disclosure fence remains source-bound, not independently repeatable from public '
                   'originals',
                   'actual API authentication and independent approval',
                   'real durable head bootstrap and advancement',
                   'lost response, timeout, crash and UNKNOWN recovery matrix',
                   'internet business acceptance and production rollout'],
     'production': False,
     'workerPublicFiles': ['sandbox.json',
                           'execution.json',
                           'go-version.txt',
                           'gofmt.patch',
                           'gofmt.stderr',
                           'apply.json',
                           'apply.stderr'],
     'preexistingPublicFiles': ['host-before.json',
                                'host-after.json',
                                'consumption.json',
                                'consumption-independent.json'],
     'publicFiles': ['apply-observations.jsonl',
                     'apply-report.json',
                     'kernel.stdout',
                     'kernel.stderr',
                     'syntax.exec.json',
                     'syntax.stdout',
                     'syntax.stderr',
                     'baseline-get-evidence.json',
                     'baseline-get-01.body',
                     'baseline-get-02.body',
                     'baseline-get-03.body',
                     'baseline-get-04.body',
                     'baseline-get-05.body',
                     'baseline-get-06.body',
                     'baseline-get-07.body',
                     'baseline-get-08.body',
                     'candidate-get-evidence.json',
                     'candidate-get-01.body',
                     'candidate-get-02.body',
                     'candidate-get-03.body',
                     'candidate-get-04.body',
                     'candidate-get-05.body',
                     'candidate-get-06.body',
                     'candidate-get-07.body',
                     'candidate-get-08.body',
                     'sandbox.json',
                     'execution.json',
                     'go-version.txt',
                     'gofmt.patch',
                     'gofmt.stderr',
                     'apply.json',
                     'apply.stderr',
                     'host-before.json',
                     'host-after.json',
                     'consumption.json',
                     'consumption-independent.json'],
     'sandboxSchema': 'chengwang.mihomo-apply-sandbox/v1',
     'sandboxKeys': ['schema',
                     'sourceCommit',
                     'uid',
                     'gid',
                     'effectiveCaps',
                     'noNewPrivileges',
                     'networkNamespace',
                     'mountNamespace',
                     'pidNamespace',
                     'environmentKeys',
                     'interfaceNames',
                     'defaultV4Routes',
                     'defaultV6Routes',
                     'sourceModuleSHA256',
                     'sourceReadOnly',
                     'goReadOnly',
                     'kernelCopy',
                     'inputCustody'],
     'executionSchema': 'chengwang.mihomo-apply-execution/v1',
     'executionKeys': ['schema',
                       'sourceCommit',
                       'formatExit',
                       'goExit',
                       'realMihomoExecutionObserved',
                       'production'],
     'environmentKeys': ['CGO_ENABLED',
                         'CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT',
                         'GOCACHE',
                         'GOENV',
                         'GOFLAGS',
                         'GOMODCACHE',
                         'GOPROXY',
                         'GOROOT',
                         'GOSUMDB',
                         'GOTOOLCHAIN',
                         'HOME',
                         'LANG',
                         'LC_ALL',
                         'PATH',
                         'TMPDIR',
                         'TZ'],
     'maxPublicLogBytes': 8388608,
     'failureFiles': ['worker-failure.json'],
     'workerFailureSchema': 'chengwang.mihomo-apply-worker-failure/v1',
     'workerFailureKeys': ['schema', 'sourceCommit', 'failureCode', 'rawOutputSuppressed'],
     'capturePublicFiles': ['baseline-get-evidence.json',
                            'baseline-get-01.body',
                            'baseline-get-02.body',
                            'baseline-get-03.body',
                            'baseline-get-04.body',
                            'baseline-get-05.body',
                            'baseline-get-06.body',
                            'baseline-get-07.body',
                            'baseline-get-08.body',
                            'candidate-get-evidence.json',
                            'candidate-get-01.body',
                            'candidate-get-02.body',
                            'candidate-get-03.body',
                            'candidate-get-04.body',
                            'candidate-get-05.body',
                            'candidate-get-06.body',
                            'candidate-get-07.body',
                            'candidate-get-08.body'],
     'getEvidenceSchema': 'chengwang.mihomo-lab-get-evidence/v1',
     'getEvidenceScope': 'PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF',
     'getEvidenceTopKeys': ['schema',
                            'scope',
                            'expectedSchedule',
                            'records',
                            'slotsEntered',
                            'doInvocations',
                            'responsesObserved',
                            'readAttempts',
                            'completedBodies',
                            'retainedBytes',
                            'outcome',
                            'failureClass',
                            'limitReached',
                            'contextState'],
     'getEvidenceRecordKeys': ['ordinal',
                               'round',
                               'endpointKind',
                               'requestBuilt',
                               'doInvoked',
                               'responseObserved',
                               'statusCode',
                               'headers',
                               'contentLength',
                               'uncompressed',
                               'readAttempted',
                               'retainedBytes',
                               'retainedSHA256',
                               'naturalEOF',
                               'readErrorClass',
                               'limitReached',
                               'closeAttempted',
                               'closeErrorClass',
                               'contextState',
                               'parseState',
                               'terminalClass'],
     'getEvidenceHeaderKeys': ['contentTypeValuesB64',
                               'contentEncodingValuesB64',
                               'transferEncodingValuesB64',
                               'setCookieCount'],
     'getEvidenceSchedule': [{'ordinal': 1, 'round': 1, 'endpointKind': 'VERSION'},
                             {'ordinal': 2, 'round': 1, 'endpointKind': 'CONFIGS'},
                             {'ordinal': 3, 'round': 1, 'endpointKind': 'PROXIES'},
                             {'ordinal': 4, 'round': 1, 'endpointKind': 'RULES'},
                             {'ordinal': 5, 'round': 2, 'endpointKind': 'VERSION'},
                             {'ordinal': 6, 'round': 2, 'endpointKind': 'CONFIGS'},
                             {'ordinal': 7, 'round': 2, 'endpointKind': 'PROXIES'},
                             {'ordinal': 8, 'round': 2, 'endpointKind': 'RULES'}],
     'captureLimits': {'acceptedBodyBytes': 8388608,
                       'probeBodyBytes': 8388609,
                       'rawArchiveBytes': 67108872,
                       'transcriptBytes': 1048576,
                       'selectedHeaderBytes': 16384,
                       'scheduleTimeoutMilliseconds': 5000},
     'proofBoundaries': {'producerIndependentProjectionRecomputeProven': False,
                         'expectedSourceIndependentlyProven': False,
                         'privateDisclosureFenceIndependentlyProven': False},
     'projectionCodecUnicodeVersion': '15.0.0'}
    same(c, expected)
    need(tuple(G.CAPTURE_FILES) == CAPTURE_PUBLIC)
    source = sources[RUNTIME].decode('utf-8')
    need(source.startswith('//go:build linux && chengwang_mihomo_apply\n'))
    need(re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)\s*\{', source, re.M) == [TOP])
    return c


def binding(value, *, limit=1 << 20):
    exact(value, BINDING_KEYS)
    digest(value['sha256'])
    integer(value['bytes'], 1, limit)
    return value


def body(value):
    exact(value, BODY_KEYS)
    digest(value['sha256'])
    integer(value['bytes'], 1, 4096)
    need(value['complete'] is True)
    return value


def stream(value, raw, *, complete=True):
    exact(value, STREAM_KEYS)
    size = integer(value['bytes'], 0, 65536)
    integer(value['totalBytes'], 0, 65536)
    need(value['bytes'] == value['totalBytes'] and value['truncated'] is False)
    digest(value['sha256'])
    need(type(value['complete']) is bool)
    if complete:
        need(value['complete'] is True and size == len(raw) and value['sha256'] == sha(raw))
    else:
        need(size <= len(raw) and value['sha256'] == sha(raw[:size]))
    return value


def sandbox(raw, sources, commit, elf, receipt):
    value = exact(decode(raw['sandbox.json']), SANDBOX_KEYS)
    need(value['schema'] == 'chengwang.mihomo-apply-sandbox/v1' and value['sourceCommit'] == commit)
    integer(value['uid'], 10001, 10001); integer(value['gid'], 10001, 10001)
    need(value['effectiveCaps'] == '0000000000000000' and value['noNewPrivileges'] is True)
    same(value['environmentKeys'], list(ENV)); same(value['interfaceNames'], ['lo'])
    same(value['defaultV4Routes'], []); same(value['defaultV6Routes'], [])
    need(value['sourceModuleSHA256'] == sha(sources['chengwang/go.mod']) and value['sourceReadOnly'] is True and value['goReadOnly'] is True)
    same(value['kernelCopy'], dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', readOnly=True, executable=True))
    before, after = decode(raw['host-before.json']), decode(raw['host-after.json'])
    exact(before, ('networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256')); same(before, after)
    digest(before['resolvSHA256'])
    for name, prefix in [('networkNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid')]:
        for item in (before[name], value[name]):
            need(type(item) is str and re.fullmatch(prefix + r':\[[1-9][0-9]{0,19}\]', item) is not None)
        need(value[name] != before[name])
    custody = exact(value['inputCustody'], ('before', 'after'))
    same(custody['before'], custody['after']); exact(custody['before'], ('elf', 'receipt'))
    for name, hashed, size, mode in [('elf', elf['sha256'], elf['bytes'], '0500'), ('receipt', sha(receipt), len(receipt), '0400')]:
        item = exact(custody['before'][name], ('sha256', 'bytes', 'mode', 'uid', 'gid'))
        need(item['sha256'] == hashed and item['mode'] == mode)
        integer(item['bytes'], size, size)
        integer(item['uid'], 0, (1 << 32) - 1); integer(item['gid'], 0, (1 << 32) - 1)
    return value


def go_events(raw):
    started = run = passed = ended = False
    last = None
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20 and not ended)
        event = decode(line, elapsed=True)
        need(type(event) is dict and set(event) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'})
        need(event.get('Package') == PACKAGE and type(event.get('Action')) is str)
        when = timestamp(event.get('Time'))
        need(last is None or when >= last); last = when
        if 'Elapsed' in event:
            need(type(event['Elapsed']) in (int, float) and math.isfinite(event['Elapsed']) and event['Elapsed'] >= 0)
        action, name = event['Action'], event.get('Test')
        if 'Test' in event:
            need(type(name) is str and name == TOP)
        if action == 'start':
            need(not started and name is None and 'Output' not in event and 'Elapsed' not in event); started = True
        elif action == 'run':
            need(started and name == TOP and not run and not passed and 'Output' not in event and 'Elapsed' not in event); run = True
        elif action == 'pass':
            need(started and run and 'Output' not in event)
            if name == TOP:
                need(not passed); passed = True
            else:
                need(name is None and passed); ended = True
        elif action == 'output':
            need(started and (name is None or (name == TOP and run and not passed)) and 'Elapsed' not in event)
            text = event.get('Output')
            need(type(text) is str and len(text) <= 4096)
            need(re.fullmatch(r'(?:=== RUN   ' + TOP + r'|[ ]*--- PASS: ' + TOP +
                              r' \([0-9.]+s\)|PASS|ok\s+' + PACKAGE + r'\s+[0-9.]+s)\n', text) is not None)
        else:
            need(False)
    need(started and run and passed and ended)
    return dict(topLevel=1, subtests=0, passingSemanticTests=1, skips=0)


def identity(value, commit, elf, base):
    exact(value, IDENTITY_KEYS)
    integer(value['pid'], 2, (1 << 31) - 1); integer(value['startTicks'], 1); integer(value['netNSInode'], 1)
    integer(value['elfBytes'], elf['bytes'], elf['bytes'])
    need(value['elfSHA256'] == elf['sha256'] and value['sourceCommit'] == commit and value['artifactSHA256'] == base['sha256'])
    integer(value['controllerPort'], 28412, 28412); integer(value['mixedPort'], 28411, 28411)
    return value


def observation(value, raw_out, raw_err, *, running=False, syntax=False):
    exact(value, OBSERVATION_KEYS)
    need(value['attempted'] is True and value['started'] is True)
    integer(value['pid'], 2, (1 << 31) - 1)
    if value['startTicks'] is not None:
        integer(value['startTicks'], 1)
    need(type(value['termSent']) is bool and type(value['killSent']) is bool)
    if running:
        need(value['waitReturned'] is False and value['waitErrorClass'] == 'NOT_WAITED' and
             value['exitCode'] is None and value['signal'] is None and value['groupAbsent'] is None and
             value['termSent'] is False and value['killSent'] is False)
    else:
        need(value['waitReturned'] is True and value['groupAbsent'] is True)
        if value['waitErrorClass'] == 'NONE':
            integer(value['exitCode'], 0, 0); need(value['signal'] is None)
        else:
            need(not syntax and value['waitErrorClass'] == 'EXIT_STATUS' and value['exitCode'] is None)
            need((type(value['signal']) is int and value['signal'] == 15 and value['termSent'] is True) or
                 (type(value['signal']) is int and value['signal'] == 9 and value['killSent'] is True))
        if syntax:
            need(value['waitErrorClass'] == 'NONE' and value['termSent'] is False and value['killSent'] is False)
    stream(value['stdout'], raw_out, complete=not running)
    stream(value['stderr'], raw_err, complete=not running)
    return value


def readbacks(value):
    exact(value, ('baseline', 'candidate'))
    previous = candidate = None
    for name, conclusion in [('baseline', 'STABLE_OLD_PROJECTION'), ('candidate', 'STABLE_NEW_PROJECTION')]:
        row = exact(value[name], READBACK_KEYS)
        need(row['conclusion'] == conclusion)
        integer(row['sampleCount'], 2, 2); integer(row['requestsObserved'], 8, 8)
        for key in ('previousProjectionSHA256', 'candidateProjectionSHA256', 'observedProjectionSHA256'):
            digest(row[key])
        need(row['previousProjectionSHA256'] != row['candidateProjectionSHA256'])
        need(all(row[key] is False for key in ('dataplaneProven', 'fullPayloadProven', 'authorizationProven', 'production')))
        need(row['observedProjectionSHA256'] == row['previousProjectionSHA256' if name == 'baseline' else 'candidateProjectionSHA256'])
        if previous is None:
            previous, candidate = row['previousProjectionSHA256'], row['candidateProjectionSHA256']
        else:
            same([previous, candidate], [row['previousProjectionSHA256'], row['candidateProjectionSHA256']])
    return value


def readiness(value):
    need(type(value) is list and 3 <= len(value) <= 34)
    valid = value[:-2]
    for i, row in enumerate(value):
        exact(row, PROBE_KEYS)
        need(row['role'] == ('VALID' if i < len(valid) else ('NONE' if i == len(valid) else 'WRONG')))
        if row['statusCode'] is not None:
            integer(row['statusCode'], 100, 599)
        if row['body'] is not None:
            body(row['body'])
        if i == len(valid) - 1:
            need(row['errorClass'] == 'NONE' and row['statusCode'] == 200 and row['body'] is not None)
        elif i >= len(valid):
            need(row['errorClass'] == 'NONE' and row['statusCode'] == 401 and row['body'] is not None)
        else:
            need(row['errorClass'] in ('NETWORK', 'BODY', 'NOT_READY'))
            if row['errorClass'] == 'NETWORK':
                need(row['statusCode'] is None and row['body'] is None)
            elif row['errorClass'] == 'BODY':
                need(row['statusCode'] is not None and row['body'] is None)
            else:
                need(row['statusCode'] is not None and row['body'] is not None)
    return value


def counters(value):
    need(type(value) is list and len(value) == 3)
    for role, row in zip(('A', 'B', 'origin'), value):
        exact(row, COUNTER_KEYS); need(row['role'] == role)
        for key in COUNTER_KEYS[1:]:
            integer(row[key], 0, 1024)
    return value


def routes(value):
    need(type(value) is list and len(value) == 2)
    last = None
    nonces = set()
    for phase, role, row in zip(('BASELINE_A', 'CANDIDATE_B'), ('A', 'B'), value):
        exact(row, ROUTE_KEYS)
        need(row['phase'] == phase and row['matched'] is True)
        digest(row['nonceSHA256']); need(row['nonceSHA256'] not in nonces); nonces.add(row['nonceSHA256'])
        observed = [body(row[name]) for name in ('clientResponse', 'proxyResponse', 'originResponse')]
        same(observed[0], observed[1]); same(observed[0], observed[2])
        # The nonce itself is private/not exported: do not pretend its digest
        # allows reconstructing the origin marker bytes. All three observed
        # hashes/lengths and independently recorded counter deltas must agree.
        need(observed[0]['bytes'] == len('chengwang-local-apply-marker/v1:A:') + 64 + 1)
        before, after = counters(row['countersBefore']), counters(row['countersAfter'])
        if last is None:
            need(all(item[key] == 0 for item in before for key in COUNTER_KEYS[1:]))
        else:
            same(before, last)
        for b, a in zip(before, after):
            for key in COUNTER_KEYS[1:]:
                delta = 1 if (b['role'] == role and key in ('connectIngress', 'tunnelRequests', 'forwardInvocations', 'originRequests')) or (b['role'] == 'origin' and key == 'originRequests') else 0
                need(a[key] == b[key] + delta)
        last = after
    need(value[0]['clientResponse']['sha256'] != value[1]['clientResponse']['sha256'])
    return value


def cleanup(value, route_evidence):
    need(type(value) is list and len(value) == 3)
    # Only A/B handlers hijack and register connections. Origin can never
    # report a forced hijacked close; a proxy cannot close more tracked
    # connections than the actual validated ingress counter has observed.
    final_counters = {row['role']: row for row in route_evidence[-1]['countersAfter']}
    for role, row in zip(('origin', 'A', 'B'), value):
        exact(row, CLEANUP_KEYS)
        need(row['role'] == role and row['shutdownReturned'] is True and row['serveReturned'] is True and row['errorClass'] == 'NONE')
        limit = 0 if role == 'origin' else final_counters[role]['connectIngress']
        integer(row['forcedConnectionsClosed'], 0, limit)
    return value


def journal(raw, report, syntax, receipt):
    lines = raw.splitlines(); need(0 < len(lines) <= 128)
    rows = []
    last = None
    for seq, line in enumerate(lines, 1):
        need(0 < len(line) <= 64 << 10)
        row = exact(decode(line), JOURNAL_KEYS)
        need(row['schema'] == 'chengwang.mihomo-apply-observation/v1')
        integer(row['seq'], seq, seq)
        when = timestamp(row['observedAtUTC']); need(last is None or when >= last); last = when
        exact(row['facts'], FACT_KEYS); rows.append(row)
    expected_stages = list(STAGES[:5]) + ['READINESS_PROBE'] * len(report['readiness']) + list(STAGES[6:])
    same([row['stage'] for row in rows], expected_stages)
    ready_i = 0
    start = None
    for row in rows:
        stage = row['stage']; fact = {key: None for key in FACT_KEYS}
        if stage == 'INPUT_OPENED': fact['receiptSHA256'] = sha(receipt)
        elif stage == 'ARTIFACTS_BOUND': fact.update(baseInput=report['baseInput'], candidateInput=report['candidateInput'])
        elif stage == 'KERNEL_START_BEGIN': fact['baseInput'] = report['baseInput']
        elif stage == 'KERNEL_START_RESULT':
            start = row['facts']['kernelObservation']
            observation(start, report['_kernelOut'], report['_kernelErr'], running=True)
            need(start['pid'] == report['ownedBefore']['pid'] and start['startTicks'] == report['ownedBefore']['startTicks'])
            fact['kernelObservation'] = start
        elif stage == 'READINESS_PROBE':
            fact['readinessProbe'] = report['readiness'][ready_i]; ready_i += 1
        elif stage == 'BASELINE_READ_BEGIN': fact['ownedIdentity'] = report['ownedBefore']
        elif stage == 'BASELINE_READ_RESULT': fact.update(readback=report['readbacks']['baseline'], getEvidence=report['getEvidence']['baseline'])
        elif stage == 'BASELINE_ROUTE_RESULT': fact['route'] = report['routes'][0]
        elif stage == 'SYNTAX_BEGIN': fact['candidateInput'] = report['candidateInput']
        elif stage == 'SYNTAX_RESULT': fact.update(candidateInput=report['candidateInput'], kernelObservation=syntax['observation'])
        elif stage == 'RELOAD_BEGIN': fact['reloadPayload'] = report['candidateInput']
        elif stage == 'RELOAD_RESULT': fact.update(reloadPayload=report['reloadPayload'], reloadResult=report['reloadResult'], clientReloadInvocations=1)
        elif stage == 'CANDIDATE_READ_RESULT': fact.update(readback=report['readbacks']['candidate'], getEvidence=report['getEvidence']['candidate'])
        elif stage == 'CANDIDATE_ROUTE_RESULT': fact['route'] = report['routes'][1]
        elif stage == 'OWNED_FINAL_RESULT': fact['ownedIdentity'] = report['ownedAfter']
        elif stage == 'KERNEL_STOP_RESULT': fact['kernelObservation'] = report['kernelObservation']
        elif stage == 'FIXTURE_STOP_RESULT': fact['fixtureCleanup'] = report['fixtureCleanup']
        same(row['facts'], fact)
    need(start is not None)
    return dict(lines=len(rows), readinessProbes=ready_i)


def _kernel_stdio(out, err):
    need(err == b'' and len(out) <= 65536)
    # Kernel config uses silent after initial parsing. Allow no messages or
    # only complete source-known initial-parser groups; unknown logs reject.
    if out:
        C.safe_stdio('candidate', out + b'configuration file config.yaml test is successful\n', err)


def verify_raw(raw, sources, commit):
    need(type(raw) is dict and set(raw) == set(PUBLIC) and type(sources) is dict and set(sources) == set(FILES))
    need(len(FILES) == len(set(FILES)) == 170 and set(BOUND_CREDENTIAL_SOURCES).issubset(FILES) and
         type(commit) is str and COMMIT.fullmatch(commit) is not None)
    need(all(type(v) is bytes and 0 < len(v) <= 1 << 20 for v in sources.values()))
    need(all(type(v) is bytes and len(v) <= 8 << 20 for v in raw.values()))
    contract(sources)
    need(raw['apply.stderr'] == raw['gofmt.patch'] == raw['gofmt.stderr'] == b'')
    need(raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
    execution = exact(decode(raw['execution.json']), EXECUTION_KEYS)
    need(execution['schema'] == 'chengwang.mihomo-apply-execution/v1' and execution['sourceCommit'] == commit)
    integer(execution['formatExit'], 0, 0); integer(execution['goExit'], 0, 0)
    need(execution['realMihomoExecutionObserved'] is True and execution['production'] is False)
    receipt = raw['consumption.json']; need(receipt == raw['consumption-independent.json'])
    elf = C.consumption(receipt, sources, commit)
    environment = sandbox(raw, sources, commit, elf, receipt)
    tests = go_events(raw['apply.json'])
    report = exact(decode(raw['apply-report.json']), REPORT_KEYS)
    need(report['schema'] == 'chengwang.mihomo-runtime-apply-report/v2' and report['scope'] == SCOPE and report['sourceCommit'] == commit)
    need(report['outcome'] == 'PASS' and report['failureCode'] is None)
    exact(report['flags'], FLAGS)
    need(report['flags']['perGetRawEvidenceAvailable'] is True and
         all(v is False for k, v in report['flags'].items() if k != 'perGetRawEvidenceAvailable'))
    base, candidate = binding(report['baseInput']), binding(report['candidateInput'])
    need(base['sha256'] != candidate['sha256'])
    same(report['reloadPayload'], candidate)
    integer(report['clientReloadInvocations'], 1, 1); need(report['controllerReceivedCount'] is None)
    same(report['reloadResult'], dict(state='acknowledged', dispatched=True, statusCode=204))
    need(report['reloadErrorClass'] == 'NONE')
    owned = identity(report['ownedBefore'], commit, elf, base)
    need(owned['netNSInode'] == int(environment['networkNamespace'][5:-1]))
    identity(report['ownedAfter'], commit, elf, base); same(report['ownedBefore'], report['ownedAfter'])
    observation(report['kernelObservation'], raw['kernel.stdout'], raw['kernel.stderr'])
    need(report['kernelObservation']['pid'] == owned['pid'] and report['kernelObservation']['startTicks'] == owned['startTicks'])
    _kernel_stdio(raw['kernel.stdout'], raw['kernel.stderr'])
    syntax = exact(decode(raw['syntax.exec.json']), SYNTAX_KEYS)
    need(syntax['schema'] == 'chengwang.mihomo-apply-syntax-exec/v1' and syntax['sourceCommit'] == commit and syntax['argvClass'] == 'STDIN_TEST')
    same(syntax['binary'], dict(sha256=elf['sha256'], bytes=elf['bytes']))
    need(syntax['receiptSHA256'] == sha(receipt) and report['syntaxSHA256'] == sha(raw['syntax.exec.json']))
    same(syntax['input'], candidate)
    observation(syntax['observation'], raw['syntax.stdout'], raw['syntax.stderr'], syntax=True)
    need(syntax['observation']['pid'] != owned['pid'])
    C.safe_stdio('candidate', raw['syntax.stdout'], raw['syntax.stderr'])
    readbacks(report['readbacks']); readiness(report['readiness']); routes(report['routes'])
    captured = G.verify_captured(raw, report)
    cleanup(report['fixtureCleanup'], report['routes'])
    # Private helper inputs are local only; they are not additional wire keys.
    checked = dict(report, _kernelOut=raw['kernel.stdout'], _kernelErr=raw['kernel.stderr'])
    timeline = journal(raw['apply-observations.jsonl'], checked, syntax, receipt)
    return dict(schema='chengwang.mihomo-runtime-apply-verification/v2', sourceCommit=commit, outcome='PASS', scope=REPORT_SCOPE,
                sourceSHA256={p: sha(sources[p]) for p in FILES}, inputSHA256={p: sha(raw[p]) for p in PUBLIC}, tests=tests,
                journal=timeline, clientReloadInvocations=1, controllerReceivedCount=None,
                sourceBoundLocalRouteEvidenceValidated=True, perGetRawEvidenceAvailable=True,
                independentProjectionRecomputeProven=True, capturedProjection=captured,
                expectedSourceIndependentlyProven=False, privateDisclosureFenceIndependentlyProven=False,
                fullPayloadProven=False, authorizationProven=False,
                headAdvanced=False, internetBusinessProven=False, production=False,
                trustBoundary='TRUSTED_CI_OBSERVATIONS_NOT_EXTERNAL_ATTESTATION',
                disclosureBoundary='PRIVATE_WITNESSES_FENCED_BY_SOURCE_BOUND_WORKER_NOT_REPLAYABLE_FROM_PUBLIC_ARTIFACT')


def source_bindings(repo, commit):
    repo = C.plain(repo)
    need(type(commit) is str and COMMIT.fullmatch(commit) is not None)

    def git(*args):
        process = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        need(process.returncode == 0 and len(process.stdout) <= 1 << 20)
        return process.stdout

    need(git('rev-parse', 'HEAD').strip().decode('ascii') == commit)
    need(Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() == repo)
    need(len(FILES) == len(set(FILES)) == 170 and set(BOUND_CREDENTIAL_SOURCES).issubset(FILES))
    sources = {}
    for path in FILES:
        value = C.read(repo / path, 1 << 20, False)
        need(value == git('show', commit + ':' + path)); sources[path] = value
    need(C.read(Path(__file__).absolute(), 1 << 20, False) == sources[PREFIX + 'check_apply.py'])
    need(C.read(Path(C.__file__).absolute(), 1 << 20, False) == sources[PREFIX + 'check_compat.py'])
    need(C.read(Path(G.__file__).absolute(), 1 << 20, False) == sources[PREFIX + 'get_projection.py'])
    return sources


def verify(evidence, repo, commit):
    need(sys.platform == 'linux')
    evidence = C.plain(evidence)
    before_dir = evidence.stat()
    need(stat.S_ISDIR(before_dir.st_mode) and set(p.name for p in evidence.iterdir()) == set(PUBLIC))
    sources = source_bindings(repo, commit)
    raw = {p: C.read(evidence / p, 8 << 20) for p in PUBLIC}
    report = verify_raw(raw, sources, commit)
    for path, value in raw.items():
        need(C.read(evidence / path, 8 << 20) == value)
    need(set(p.name for p in evidence.iterdir()) == set(PUBLIC))
    after_dir = evidence.stat()
    need((before_dir.st_dev, before_dir.st_ino, before_dir.st_mode) == (after_dir.st_dev, after_dir.st_ino, after_dir.st_mode))
    again = source_bindings(repo, commit)
    need(all(again[p] == sources[p] for p in FILES))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    need(sys.platform == 'linux' and os.open in os.supports_dir_fd)
    args.repo, args.evidence = C.plain(args.repo), C.plain(args.evidence)
    args.report = C.plain(args.report, True)
    need(not args.report.is_relative_to(args.repo) and not args.report.is_relative_to(args.evidence))
    result = verify(args.evidence, args.repo, args.source_commit)
    directory = os.open(args.report.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(args.report.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as handle:
            value = canonical(result)
            need(handle.write(value) == len(value)); handle.flush(); os.fsync(handle.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)
    print('MIHOMO_APPLY=PASS scope=ACTUAL_LOCAL_APPLY_EXPERIMENT_NOT_FULL_PROJECT production=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('MIHOMO_APPLY=REJECTED raw_input_suppressed=true') from None
