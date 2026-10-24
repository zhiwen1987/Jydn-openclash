#!/usr/bin/env python3
"""Source-owned isolated Linux apply laboratory worker; import starts nothing.

This captures a real-kernel experiment. CAPTURED will never mean independent
acceptance, product API/RBAC authorization, production or business availability.
The source-owned apply_contract.json is supplied by the root integrator.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys


CONTRACT_NAME = 'apply_contract.json'
ROOT_PRIVATE = Path('/tmp/mihomo-apply-root')
EXPORT_ALIAS = Path('/tmp/mihomo-apply-export')
PATHS = dict(module='/tmp/mihomo-apply-source', goRoot='/tmp/mihomo-apply-go',
             buildHome='/tmp/mihomo-apply-build', home='/tmp/mihomo-apply-home',
             privateOutput='/tmp/mihomo-apply-private',
             kernelDirectory='/tmp/mihomo-apply-kernel',
             kernel='/tmp/mihomo-apply-kernel/mihomo',
             receipt='/tmp/mihomo-apply-kernel/consumption.json')
LEGACY_CASE_FILES = ('apply-observations.jsonl', 'apply-report.json',
                     'kernel.stdout', 'kernel.stderr', 'syntax.exec.json',
                     'syntax.stdout', 'syntax.stderr')
GET_PHASES = ('baseline', 'candidate')
GET_FILES = tuple(name for phase in GET_PHASES for name in
                  (phase + '-get-evidence.json',
                   *(f'{phase}-get-{n:02d}.body' for n in range(1, 9))))
PUBLIC_CASE_FILES = LEGACY_CASE_FILES + GET_FILES
PRIVATE_FENCE_FILES = ('.secrets.private.json', 'base.config.private.yaml',
                       'candidate.config.private.yaml')
FIXED_TOP = 'TestMihomoApplyReloadReadbackAndLocalProxy'
FIXED_TAG = 'chengwang_mihomo_apply'
MAX_LOG = 8 << 20
MAX_BODY = 1 << 20
GO_TIMEOUT = 90
SECRET = re.compile(r'[a-f0-9]{64}')
COMMIT = re.compile(r'[a-f0-9]{40}')
_SHARED = None
_FAILURE_STATE = None


def need(value):
    if not value:
        raise ValueError('isolated apply worker rejected')


def shared():
    """Reuse the actual old worker's helpers without mutating its globals.

    Loading is deferred until an explicit entrypoint. The module path is a
    fixed source sibling, never an environment variable or caller module name.
    Both sources must be independently bound by the eventual evidence checker.
    """
    global _SHARED
    if _SHARED is None:
        path = Path(__file__).absolute().with_name('compat_worker.py')
        for item in [*reversed(path.parents), path]:
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode))
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
        spec = importlib.util.spec_from_file_location('_mihomo_apply_fixed_shared', path)
        need(spec is not None and spec.loader is not None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SHARED = module
    return _SHARED


def environment(commit):
    need(type(commit) is str and COMMIT.fullmatch(commit))
    build = PATHS['buildHome']
    return dict(CGO_ENABLED='1', CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT=commit,
                GOCACHE=build + '/cache', GOENV='off', GOFLAGS='-mod=vendor',
                GOMODCACHE=build + '/mod', GOPROXY='off', GOROOT=PATHS['goRoot'],
                GOSUMDB='off', GOTOOLCHAIN='local', HOME=build,
                LANG='C.UTF-8', LC_ALL='C.UTF-8',
                PATH=PATHS['goRoot'] + '/bin:/usr/bin:/bin',
                TMPDIR=build + '/tmp', TZ='UTC')


def pidfd_preflight():
    # Feature presence alone is not a measured kernel capability. Open a
    # reference to this original worker before launching any Go subprocess.
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'))
    fd = os.pidfd_open(os.getpid(), 0)
    try:
        need(type(fd) is int and fd >= 0)
    finally:
        os.close(fd)


def process_event(state, command_class, event, pid=None, acquired=None, exit_code=None):
    """Private durable observations, never a public authority/dispatch ticket.

    Record only actual observations and explicitly labelled intents. A missing
    Wait result remains null. Do not persist argv, error text or pidfd number.
    The first record creates the witness exclusively; later records append to
    that same root-owned inode and fsync before execution can continue.
    """
    need(command_class in ('SANDBOX', 'GO_VERSION', 'GOFMT', 'GO_TEST') and
         event in ('START_INTENT', 'STARTED', 'START_UNOBSERVED', 'REFERENCE_ACQUIRED',
                   'REFERENCE_UNAVAILABLE', 'WAIT_TIMEOUT',
                   'SIGNAL_INTENT', 'SIGNAL_SENT', 'SIGNAL_UNCERTAIN',
                   'WAIT_RETURNED', 'WAIT_UNOBSERVED'))
    need((pid is None or type(pid) is int and pid >= 2) and
         (acquired is None or type(acquired) is bool) and
         (exit_code is None or type(exit_code) is int))
    seq = state.get('processEventSeq', 0) + 1
    need(type(seq) is int and 1 <= seq <= 64)
    value = dict(schema='chengwang.mihomo-apply-private-process-event/v1',
                 seq=seq, commandClass=command_class, event=event,
                 pid=pid, pidfdAcquired=acquired, exitCode=exit_code)
    raw = shared().canonical(value)
    path = ROOT_PRIVATE / 'process-events.private.jsonl'
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    if seq == 1:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_size + len(raw) <= 64 << 10)
        identity = (info.st_dev, info.st_ino)
        if seq == 1:
            state['processEventIdentity'] = identity
        need(state['processEventIdentity'] == identity)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            need(written > 0)
            view = view[written:]
        os.fsync(fd)
        named = path.lstat()
        need((named.st_dev, named.st_ino) == identity and named.st_nlink == 1 and
             named.st_uid == named.st_gid == 0 and stat.S_IMODE(named.st_mode) == 0o600)
        state['processEventSeq'] = seq
    finally:
        os.close(fd)
    if seq == 1:
        directory = os.open(ROOT_PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def capture(state, argv, name, err_name, timeout):
    """Private raw capture with an owned pidfd acquired before poll or wait.

    An unbound or unreaped child stays in state['pending']; failure never
    reports a fabricated exit code or falls back to a bare PID/PGID signal.
    The source-owned outer PID namespace remains a separate containment layer.
    """
    w = shared()
    need(type(timeout) is int and 0 < timeout <= GO_TIMEOUT)
    commands = {'sandbox.private.json': ('SANDBOX', 'sandbox.private.stderr'),
                'go-version.txt': ('GO_VERSION', 'go-version.private.stderr'),
                'gofmt.patch': ('GOFMT', 'gofmt.stderr'),
                'apply.json': ('GO_TEST', 'apply.stderr')}
    need(name in commands and err_name == commands[name][1])
    command_class = commands[name][0]
    process_event(state, command_class, 'START_INTENT')
    with (ROOT_PRIVATE / name).open('xb') as stdout, (ROOT_PRIVATE / err_name).open('xb') as stderr:
        os.fchmod(stdout.fileno(), 0o600)
        os.fchmod(stderr.fileno(), 0o600)
        try:
            process = subprocess.Popen(w.unprivileged(argv, state['environment']),
                                       env=w.ROOT_ENV, cwd=PATHS['module'],
                                       stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
        except Exception:
            process_event(state, command_class, 'START_UNOBSERVED')
            raise ValueError('owned process start unobserved') from None
        entry = dict(process=process, pidfd=None)
        state['pending'].append(entry)
        process_event(state, command_class, 'STARTED', pid=process.pid)
        # Do not poll/reap before this reference is obtained. An own child
        # which exits quickly remains unreaped, so its PID cannot be reused.
        try:
            fd = os.pidfd_open(process.pid, 0)
        except Exception:
            process_event(state, command_class, 'REFERENCE_UNAVAILABLE', pid=process.pid, acquired=False)
            raise ValueError('owned process reference unavailable') from None
        entry['pidfd'] = fd
        process_event(state, command_class, 'REFERENCE_ACQUIRED', pid=process.pid, acquired=True)
        try:
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process_event(state, command_class, 'WAIT_TIMEOUT', pid=process.pid, acquired=True)
                process_event(state, command_class, 'SIGNAL_INTENT', pid=process.pid, acquired=True)
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except Exception:
                    process_event(state, command_class, 'SIGNAL_UNCERTAIN', pid=process.pid, acquired=True)
                    raise ValueError('owned process termination unobserved') from None
                process_event(state, command_class, 'SIGNAL_SENT', pid=process.pid, acquired=True)
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # No fake completion and no second numeric termination.
                    process_event(state, command_class, 'WAIT_UNOBSERVED', pid=process.pid, acquired=True)
                    raise ValueError('owned Go process wait unobserved') from None
            except Exception:
                process_event(state, command_class, 'WAIT_UNOBSERVED', pid=process.pid, acquired=True)
                raise ValueError('owned process wait unobserved') from None
            process_event(state, command_class, 'WAIT_RETURNED', pid=process.pid, acquired=True, exit_code=code)
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
            return code
        finally:
            if process.returncode is not None:
                os.close(fd)
                entry['pidfd'] = None
                state['pending'].remove(entry)


def sandbox(commit, module_sha):
    w = shared()
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 10001 and not os.getgroups())
    need(dict(os.environ) == environment(commit))
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text(encoding='utf8').splitlines() if ':' in line)
    need(all(int(status[key].strip(), 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) and status['NoNewPrivs'].strip() == '1')
    interfaces = sorted(name for _, name in socket.if_nameindex())
    v4 = w.decode(w.command([w.tool('ip'), '-j', '-4', 'route', 'show', 'default']))
    v6 = w.decode(w.command([w.tool('ip'), '-j', '-6', 'route', 'show', 'default']))
    need(interfaces == ['lo'] and v4 == v6 == [])
    need(Path.cwd() == Path(PATHS['module']))
    module, _ = w.file_bytes(Path(PATHS['module']) / 'go.mod', 64 << 10)
    need(w.sha(module) == module_sha)
    for key in ('buildHome', 'home', 'privateOutput'):
        info = Path(PATHS[key]).lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) == 0o700)
    # Go build caches live elsewhere; the service parent and producer output
    # remain genuinely empty before the suite creates its own artifacts.
    need(not any(Path(PATHS['home']).iterdir()) and not any(Path(PATHS['privateOutput']).iterdir()))
    kernel, info = w.file_bytes(Path(PATHS['kernel']), w.MAX_ELF, 0o500)
    need(info.st_uid == info.st_gid == 10001)
    source_ro = bool(os.statvfs(PATHS['module']).f_flag & os.ST_RDONLY)
    go_ro = bool(os.statvfs(PATHS['goRoot']).f_flag & os.ST_RDONLY)
    flags = os.statvfs(PATHS['kernel']).f_flag
    kernel_ro = bool(flags & os.ST_RDONLY)
    executable = os.access(PATHS['kernel'], os.X_OK) and not bool(flags & os.ST_NOEXEC)
    need(source_ro and go_ro and kernel_ro and executable)
    return dict(sourceCommit=commit, uid=10001, gid=10001,
                effectiveCaps=status['CapEff'].strip(), noNewPrivileges=True,
                **w.namespace_values(), environmentKeys=sorted(os.environ),
                interfaceNames=interfaces, defaultV4Routes=v4,
                defaultV6Routes=v6, sourceModuleSHA256=module_sha,
                sourceReadOnly=source_ro, goReadOnly=go_ro,
                kernelCopy=dict(sha256=w.sha(kernel), bytes=len(kernel),
                                mode='0500', readOnly=kernel_ro, executable=executable))


def prepare_namespace(repo, out, goroot, consumed, commit):
    global _FAILURE_STATE
    """Only called by the root worker inside already-new net/mnt/pid NSes."""
    w = shared()
    need(os.name == 'posix' and sys.platform == 'linux' and os.geteuid() == 0 and COMMIT.fullmatch(commit))
    repo, out, goroot, consumed = [w.plain(p) for p in (repo, out, goroot, consumed)]
    need(all(not p.is_relative_to(Path('/tmp')) for p in (repo, out, goroot, consumed)))
    need(repo.is_dir() and out.is_dir() and goroot.is_dir() and not out.is_relative_to(repo) and not consumed.is_relative_to(repo) and not out.is_relative_to(consumed))
    initial = {'host-before.json', 'consumption.json', 'consumption-independent.json'}
    need(set(p.name for p in out.iterdir()) == initial)
    public = {n: w.file_bytes(out / n, 1 << 20)[0] for n in initial}
    host = w.decode(public['host-before.json'])
    need(type(host) is dict and set(host) == {'networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256'})
    current = w.namespace_values()
    need(all(current[key] != host[key] for key in current))
    before, original, directory = w.custody(consumed)
    receipt = w.decode(original['receipt'])
    need(receipt['schema'] == 'chengwang.mihomo-candidate-consumption/v1' and receipt['state'] == 'PINNED_GZIP_EXPANDED_NOT_EXECUTED' and
         receipt['source']['projectSourceCommit'] == commit and receipt['elf']['sha256'] == before['elf']['sha256'] and receipt['elf']['bytes'] == before['elf']['bytes'])
    for key in ('runtimeExecuted', 'runtimeCompatibilityProven', 'businessAvailabilityProven', 'publisherSignatureProven', 'productionApproved', 'production'):
        need(receipt[key] is False)
    need(public['consumption.json'] == public['consumption-independent.json'] == original['receipt'])
    state = dict(repo=repo, out=out, goroot=goroot, consumed=consumed,
                 commit=commit, originalPublic=public, inputBefore=before,
                 originalDirectory=directory, environment=environment(commit),
                 pending=[], formatExit=None, goExit=None, observed=None)
    _FAILURE_STATE = state
    module, _ = w.file_bytes(repo / 'chengwang/go.mod', 64 << 10)
    state['moduleSHA256'] = w.sha(module)
    need((repo / 'chengwang/vendor').is_dir() and (goroot / 'bin/go').is_file() and (goroot / 'bin/gofmt').is_file())
    pidfd_preflight()
    w.command([w.tool('mount'), '--make-rprivate', '/'])
    w.command([w.tool('ip'), 'link', 'set', 'lo', 'up'])
    w.mount_readonly(repo, repo)
    w.mount_readonly(goroot, goroot, executable=True)
    w.command([w.tool('mount'), '-t', 'tmpfs', '-o', 'nosuid,nodev,mode=755', 'tmpfs', '/tmp'])
    ROOT_PRIVATE.mkdir(mode=0o700)
    for key in ('module', 'goRoot', 'kernelDirectory'):
        Path(PATHS[key]).mkdir(mode=0o755)
    for key in ('buildHome', 'home', 'privateOutput'):
        Path(PATHS[key]).mkdir(mode=0o700)
        os.chown(PATHS[key], 10001, 10001)
    for name in ('tmp', 'cache', 'mod'):
        path = Path(PATHS['buildHome']) / name
        path.mkdir(mode=0o700)
        os.chown(path, 10001, 10001)
    w.mount_readonly(repo / 'chengwang', Path(PATHS['module']))
    w.mount_readonly(goroot, Path(PATHS['goRoot']), executable=True)
    for key, raw in [('kernel', original['elf']), ('receipt', original['receipt'])]:
        mode = 0o500 if key == 'kernel' else 0o400
        path = Path(PATHS[key])
        w.write_new(path, raw, mode)
        os.chown(path, 10001, 10001)
        need(w.file_bytes(path, len(raw), mode)[0] == raw)
        w.mount_readonly(path, path, executable=key == 'kernel')
    EXPORT_ALIAS.mkdir(mode=0o700)
    w.command([w.tool('mount'), '--bind', str(out), str(EXPORT_ALIAS)])
    return state


def contract():
    """Use the fixed source contract, never a caller-selected JSON path."""
    w = shared()
    raw, _ = w.file_bytes(Path(__file__).absolute().with_name(CONTRACT_NAME), 64 << 10)
    c = w.decode(raw)
    paths = dict(PATHS)
    paths['serviceHome'] = paths.pop('home')
    paths['exportAlias'] = str(EXPORT_ALIAS)
    need(type(c) is dict and c['schema'] == 'chengwang.mihomo-runtime-apply-contract/v2' and
         c['scope'] == 'ACTUAL_FIXED_KERNEL_LOCAL_APPLY_EXPERIMENT_NOT_API_AUTHORIZATION_HEAD_OR_PRODUCTION' and
         c['production'] is False and c['paths'] == paths and
         c['tag'] == FIXED_TAG and c['goPackage'] == './internal/mihomodeploy' and
         c['topTests'] == [FIXED_TOP] and type(c['goTimeoutSeconds']) is int and
         c['goTimeoutSeconds'] == GO_TIMEOUT and type(c['sessionTimeoutSeconds']) is int and
         c['sessionTimeoutSeconds'] == 60 and
         c['publicTestFiles'] == list(PUBLIC_CASE_FILES) and
         c['privateExtraFiles'] == list(PRIVATE_FENCE_FILES) and
         c['controllerReceivedCount'] is None)
    need(c['capturePublicFiles'] == list(GET_FILES) and
         c['getEvidenceSchema'] == 'chengwang.mihomo-lab-get-evidence/v1' and
         c['getEvidenceScope'] == 'PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF' and
         w.canonical(c['captureLimits']) == w.canonical(dict(acceptedBodyBytes=8388608,
             probeBodyBytes=8388609, rawArchiveBytes=67108872, transcriptBytes=1048576,
             selectedHeaderBytes=16384, scheduleTimeoutMilliseconds=5000)))
    need(c['ports'] == dict(mixed=28411, controller=28412, proxyA=28413,
                            proxyB=28414, origin=28415))
    need(type(c['flags']) is dict and set(c['flags']) == {
        'apiExercised', 'authorizationExercised', 'authorizationProven',
        'fullPayloadProven', 'headAdvanced', 'production',
        'perGetRawEvidenceAvailable', 'independentProjectionRecomputeProven',
        'internetBusinessProven'} and
         all(type(value) is bool and value is (key == 'perGetRawEvidenceAvailable')
             for key, value in c['flags'].items()))
    need(c['workerPublicFiles'] == ['sandbox.json', 'execution.json', 'go-version.txt',
         'gofmt.patch', 'gofmt.stderr', 'apply.json', 'apply.stderr'] and
         c['preexistingPublicFiles'] == ['host-before.json', 'host-after.json',
         'consumption.json', 'consumption-independent.json'] and
         len(c['publicFiles']) == len(set(c['publicFiles'])) == 36 and
         set(c['publicFiles']) == set(c['publicTestFiles'] + c['workerPublicFiles'] + c['preexistingPublicFiles']) and
         c['environmentKeys'] == sorted(environment('0' * 40)) and
         type(c['maxPublicLogBytes']) is int and c['maxPublicLogBytes'] == MAX_LOG)
    need(c['failureFiles'] == ['worker-failure.json'] and
         c['workerFailureSchema'] == 'chengwang.mihomo-apply-worker-failure/v1' and
         c['workerFailureKeys'] == ['schema', 'sourceCommit', 'failureCode', 'rawOutputSuppressed'])
    return c


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))
    return value


def binding(raw):
    return dict(sha256=shared().sha(raw), bytes=len(raw))


def check_binding(c, value, raw):
    exact(value, c['bindingKeys'])
    need(type(value['bytes']) is int and value['bytes'] > 0 and value == binding(raw))


def private_file(root, name, limit, empty=False):
    raw, info = shared().file_bytes(root / name, limit, 0o600, empty=empty)
    need(info.st_uid == info.st_gid == 10001)
    return raw


def stream_complete(c, metadata, raw):
    exact(metadata, c['streamKeys'])
    need(type(metadata['bytes']) is int and type(metadata['totalBytes']) is int and
         metadata['bytes'] == metadata['totalBytes'] == len(raw) and
         metadata['sha256'] == shared().sha(raw) and
         metadata['truncated'] is False and metadata['complete'] is True)


def safe_variants(secrets, bodies):
    # Include both quoted encodings, unpadded encodings and upper hex too.
    # This is a bounded disclosure fence, not a claim against arbitrary
    # transformations or covert channels in a malicious producer binary.
    values = shared().forbidden_variants(secrets, bodies)
    for raw in [*secrets, *bodies]:
        values.update((base64.b64encode(raw).rstrip(b'='),
                       base64.urlsafe_b64encode(raw).rstrip(b'='),
                       raw.hex().upper().encode('ascii')))
    need(all(values))
    return values


def get_outputs(c, outputs, report, forbidden):
    """Validate actual staged entity-response bytes, not projection semantics.

    This gate does not infer expected configuration from private YAML. The
    independent projection checker is a different source-owned implementation.
    Decoded selected header bytes participate in the same private-data fence.
    """
    w = shared()
    phase_bindings = exact(report['getEvidence'], GET_PHASES)
    need(set(GET_FILES) <= set(outputs))
    top_keys = ('schema', 'scope', 'expectedSchedule', 'records', 'slotsEntered',
                'doInvocations', 'responsesObserved', 'readAttempts', 'completedBodies',
                'retainedBytes', 'outcome', 'failureClass', 'limitReached', 'contextState')
    record_keys = ('ordinal', 'round', 'endpointKind', 'requestBuilt', 'doInvoked',
                   'responseObserved', 'statusCode', 'headers', 'contentLength',
                   'uncompressed', 'readAttempted', 'retainedBytes', 'retainedSHA256',
                   'naturalEOF', 'readErrorClass', 'limitReached', 'closeAttempted',
                   'closeErrorClass', 'contextState', 'parseState', 'terminalClass')
    header_keys = ('contentTypeValuesB64', 'contentEncodingValuesB64',
                   'transferEncodingValuesB64', 'setCookieCount')
    endpoints = ('VERSION', 'CONFIGS', 'PROXIES', 'RULES') * 2
    need(c['getEvidenceTopKeys'] == list(top_keys) and
         c['getEvidenceRecordKeys'] == list(record_keys) and
         c['getEvidenceHeaderKeys'] == list(header_keys))
    def integer(token):
        need(token != '-0' and re.fullmatch(r'-?(?:0|[1-9][0-9]{0,18})', token))
        return int(token)
    def reject_number(_):
        need(False)
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result
    for phase in GET_PHASES:
        transcript_raw = outputs[phase + '-get-evidence.json']
        check_binding(c, phase_bindings[phase], transcript_raw)
        transcript = exact(json.loads(transcript_raw.decode('utf-8', errors='strict'),
                           object_pairs_hook=unique, parse_int=integer,
                           parse_float=reject_number, parse_constant=reject_number), top_keys)
        need(transcript['schema'] == 'chengwang.mihomo-lab-get-evidence/v1' and
             transcript['scope'] == 'PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF' and
             transcript['outcome'] == 'COMPLETE' and transcript['failureClass'] is None and
             transcript['limitReached'] is False and transcript['contextState'] == 'ACTIVE')
        for key in ('slotsEntered', 'doInvocations', 'responsesObserved', 'readAttempts', 'completedBodies'):
            need(type(transcript[key]) is int and transcript[key] == 8)
        need(type(transcript['retainedBytes']) is int and
             type(transcript['expectedSchedule']) is list and len(transcript['expectedSchedule']) == 8 and
             type(transcript['records']) is list and len(transcript['records']) == 8)
        total = 0
        for ordinal, endpoint in enumerate(endpoints, 1):
            schedule = exact(transcript['expectedSchedule'][ordinal - 1], ('ordinal', 'round', 'endpointKind'))
            record = exact(transcript['records'][ordinal - 1], record_keys)
            for row in (schedule, record):
                need(type(row['ordinal']) is int and row['ordinal'] == ordinal and
                     type(row['round']) is int and row['round'] == (1 if ordinal <= 4 else 2) and
                     row['endpointKind'] == endpoint)
            for key in ('requestBuilt', 'doInvoked', 'responseObserved', 'readAttempted', 'naturalEOF', 'closeAttempted'):
                need(record[key] is True)
            need(type(record['statusCode']) is int and record['statusCode'] == 200 and
                 type(record['contentLength']) is int and -1 <= record['contentLength'] <= 8 << 20 and
                 record['uncompressed'] is False and record['limitReached'] is False and
                 record['readErrorClass'] == 'NONE' and record['closeErrorClass'] == 'NONE' and
                 record['contextState'] == 'ACTIVE' and record['parseState'] == 'SHAPE_ACCEPTED' and
                 record['terminalClass'] == 'NONE')
            raw = outputs[f'{phase}-get-{ordinal:02d}.body']
            need(len(raw) <= 8 << 20 and type(record['retainedBytes']) is int and
                 record['retainedBytes'] == len(raw) and record['retainedSHA256'] == w.sha(raw))
            need(record['contentLength'] == -1 or record['contentLength'] == len(raw))
            total += len(raw)
            headers = exact(record['headers'], header_keys)
            need(type(headers['setCookieCount']) is int and headers['setCookieCount'] == 0)
            selected_bytes = 0
            for key in header_keys[:-1]:
                values = headers[key]
                need(type(values) is list and len(values) <= 16384)
                for encoded in values:
                    need(type(encoded) is str and len(encoded) <= 21848)
                    decoded = base64.b64decode(encoded, validate=True)
                    need(base64.b64encode(decoded).decode('ascii') == encoded)
                    selected_bytes += len(decoded)
                    need(selected_bytes <= 16384 and not any(value in decoded for value in forbidden))
            need(len(headers['contentTypeValuesB64']) == 1 and
                 len(headers['contentEncodingValuesB64']) <= 1)
        need(transcript['retainedBytes'] == total)


def private_outputs(c, state):
    """Validate all candidate bytes before making any public copy.

    Failure may retain only a real producer-created subset. No absent stream,
    partial stream or missing body witness is padded with an empty original.
    This validates export confidentiality and bindings; it is not the
    independent runtime/route/readback acceptance checker.
    """
    w = shared()
    root = Path(PATHS['privateOutput'])
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
         info.st_uid == info.st_gid == 10001)
    names = {path.name for path in root.iterdir()}
    need(set(PRIVATE_FENCE_FILES) <= names <= set(PUBLIC_CASE_FILES + PRIVATE_FENCE_FILES))
    secret = w.decode(private_file(root, '.secrets.private.json', 4096))
    exact(secret, c['secretsKeys'])
    secret_names = ('controller', 'routeA', 'routeB')
    need(secret['schema'] == c['secretsSchema'] and
         all(type(secret[name]) is str and SECRET.fullmatch(secret[name]) for name in secret_names) and
         len({secret[name] for name in secret_names}) == 3)
    bodies = [private_file(root, name, MAX_BODY) for name in PRIVATE_FENCE_FILES[1:]]
    for raw in bodies:
        raw.decode('utf-8', errors='strict')
        need(secret['controller'].encode('ascii') in raw)
    forbidden = safe_variants([secret[name].encode('ascii') for name in secret_names], bodies)
    outputs = {}
    for name in PUBLIC_CASE_FILES:
        if name in names:
            limit = ((8 << 20) + 1 if name.endswith('.body') else
                     1 << 20 if name.endswith('-get-evidence.json') else
                     MAX_LOG if name.endswith(('.stdout', '.stderr')) else 2 << 20)
            outputs[name] = private_file(root, name, limit,
                                         empty=name.endswith(('.stdout', '.stderr', '.body')))
    need('apply-report.json' in outputs)
    report = exact(w.decode(outputs['apply-report.json']), c['reportKeys'])
    need(report['schema'] == c['reportSchema'] and report['scope'] == c['scope'] and
         report['sourceCommit'] == state['commit'] and report['outcome'] in ('PASS', 'FAIL') and
         report['controllerReceivedCount'] is None)
    flags = exact(report['flags'], c['flags'])
    need(all(type(value) is bool and (key == 'perGetRawEvidenceAvailable' or value is False)
             for key, value in flags.items()))
    phase_bindings = exact(report['getEvidence'], GET_PHASES)
    for phase in GET_PHASES:
        if phase_bindings[phase] is not None:
            name = phase + '-get-evidence.json'
            need(name in outputs)
            check_binding(c, phase_bindings[phase], outputs[name])
    if report['outcome'] == 'PASS' or flags['perGetRawEvidenceAvailable']:
        need(flags['perGetRawEvidenceAvailable'] is True)
        get_outputs(c, outputs, report, forbidden)
    check_binding(c, report['baseInput'], bodies[0])
    check_binding(c, report['candidateInput'], bodies[1])
    if report['reloadPayload'] is not None:
        check_binding(c, report['reloadPayload'], bodies[1])
    observation = report['kernelObservation']
    observed = None
    if observation is not None:
        need(type(observation) is dict and type(observation.get('attempted')) is bool and
             (observation.get('started') is None or type(observation['started']) is bool))
        if observation['started'] is True:
            observed = True
        for stream in ('stdout', 'stderr'):
            name = 'kernel.' + stream
            if name in outputs:
                stream_complete(c, observation[stream], outputs[name])
            else:
                need(observation[stream] is None)
    else:
        need('kernel.stdout' not in outputs and 'kernel.stderr' not in outputs)
    if 'syntax.exec.json' in outputs:
        syntax_raw = outputs['syntax.exec.json']
        syntax = exact(w.decode(syntax_raw), c['syntaxKeys'])
        need(syntax['schema'] == c['syntaxSchema'] and syntax['sourceCommit'] == state['commit'] and
             syntax['argvClass'] == 'STDIN_TEST' and
             syntax['receiptSHA256'] == state['inputBefore']['receipt']['sha256'] and
             report['syntaxSHA256'] == w.sha(syntax_raw))
        check_binding(c, syntax['input'], bodies[1])
        exact(syntax['binary'], c['bindingKeys'])
        need(syntax['binary'] == dict(sha256=state['inputBefore']['elf']['sha256'],
                                     bytes=state['inputBefore']['elf']['bytes']))
        need(type(syntax['observation']) is dict)
        for stream in ('stdout', 'stderr'):
            name = 'syntax.' + stream
            if name in outputs:
                stream_complete(c, syntax['observation'][stream], outputs[name])
            else:
                need(syntax['observation'][stream] is None)
    else:
        need(report['syntaxSHA256'] is None and
             'syntax.stdout' not in outputs and 'syntax.stderr' not in outputs)
    if 'apply-observations.jsonl' in outputs:
        rows = outputs['apply-observations.jsonl'].splitlines()
        need(0 < len(rows) <= c['maxJournalLines'])
        for seq, raw in enumerate(rows, 1):
            row = exact(w.decode(raw), c['journalKeys'])
            need(row['schema'] == c['journalSchema'] and type(row['seq']) is int and
                 row['seq'] == seq and row['stage'] in c['journalStages'] and
                 type(row['observedAtUTC']) is str and 0 < len(row['observedAtUTC']) <= 64)
            exact(row['facts'], c['journalFactKeys'])
            phase = {'BASELINE_READ_RESULT': 'baseline', 'CANDIDATE_READ_RESULT': 'candidate'}.get(row['stage'])
            if phase is None:
                need(row['facts']['getEvidence'] is None)
            else:
                phase_binding = report['getEvidence'][phase]
                need(phase_binding is not None and
                     w.canonical(row['facts']['getEvidence']) == w.canonical(phase_binding))
                if report['outcome'] == 'PASS':
                    check_binding(c, row['facts']['getEvidence'], outputs[phase + '-get-evidence.json'])
    for raw in outputs.values():
        need(not any(value in raw for value in forbidden))
    if report['outcome'] != 'PASS':
        # Actual private partials stay private, including empty bodies only if
        # they were really read. Never publish a failed or unknown transcript.
        for name in GET_FILES:
            outputs.pop(name, None)
    need({path.name for path in root.iterdir()} == names)
    # Commit metadata is not a substitute for raw originals or semantic
    # verification. In particular this does not infer server receipt of PUT.
    return outputs, forbidden, observed, report['outcome'] == 'PASS'


def execution(c, state):
    value = dict(schema=c['executionSchema'], sourceCommit=state['commit'],
                 formatExit=state['formatExit'], goExit=state['goExit'],
                 realMihomoExecutionObserved=state['observed'], production=False)
    exact(value, c['executionKeys'])
    return value


def unchanged_public(state):
    w = shared()
    for name, raw in state['originalPublic'].items():
        need(w.file_bytes(state['out'] / name, 1 << 20)[0] == raw)


def sync_output(state):
    # File contents are individually fsynced by write_new; persist the new
    # directory entries without chmod/chown of the caller's host directory.
    fd = os.open(state['out'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def report_failure():
    """Emit only fixed safe diagnostics when the private fence is unavailable.

    Do not overwrite first witnesses or copy any producer/raw Go bytes on this
    path. No observed exit is inferred from a missing process, file or report.
    """
    if _FAILURE_STATE is None:
        return
    try:
        w, state, c = shared(), _FAILURE_STATE, contract()
        unchanged_public(state)
        values = [('execution.json', w.canonical(execution(c, state))),
                  ('worker-failure.json', w.canonical(worker_failure(c, state)))]
        for name, raw in values:
            path = state['out'] / name
            if not path.exists() and not path.is_symlink():
                w.write_new(path, raw, 0o644)
        sync_output(state)
    except Exception:
        # Do not reveal a raw exception, pathname, environment or private body.
        return


def worker_failure(c, state):
    value = dict(schema=c['workerFailureSchema'], sourceCommit=state['commit'],
                 failureCode='WORKER_REJECTED_RAW_OUTPUT_SUPPRESSED',
                 rawOutputSuppressed=True)
    exact(value, c['workerFailureKeys'])
    return value


def main(args):
    c, w = contract(), shared()
    if len(args) == 3 and args[0] == '--sandbox':
        need(type(args[1]) is str and COMMIT.fullmatch(args[1]) and
             type(args[2]) is str and SECRET.fullmatch(args[2]))
        value = sandbox(args[1], args[2])
        value['schema'] = c['sandboxSchema']
        exact(value, set(c['sandboxKeys']) - {'inputCustody'})
        print(w.canonical(value).decode('ascii'), end='')
        return 0
    need(len(args) == 5)
    state = prepare_namespace(*args)
    worker = PATHS['module'] + '/deploy/mihomo-lifecycle-lab/apply_worker.py'
    code = capture(state, [w.tool('python3'), '-B', worker, '--sandbox',
                          state['commit'], state['moduleSHA256']],
                   'sandbox.private.json', 'sandbox.private.stderr', 30)
    need(code == 0 and w.file_bytes(ROOT_PRIVATE / 'sandbox.private.stderr', 4096, empty=True)[0] == b'')
    raw, _ = w.file_bytes(ROOT_PRIVATE / 'sandbox.private.json', 64 << 10)
    facts = exact(w.decode(raw), set(c['sandboxKeys']) - {'inputCustody'})
    need(facts['schema'] == c['sandboxSchema'] and facts['sourceCommit'] == state['commit'] and
         facts['kernelCopy']['sha256'] == state['inputBefore']['elf']['sha256'] and
         facts['kernelCopy']['bytes'] == state['inputBefore']['elf']['bytes'])
    version_exit = capture(state, [PATHS['goRoot'] + '/bin/go', 'version'],
                           'go-version.txt', 'go-version.private.stderr', 15)
    need(version_exit == 0 and
         w.file_bytes(ROOT_PRIVATE / 'go-version.txt', 4096)[0] == b'go version go1.23.12 linux/amd64\n' and
         w.file_bytes(ROOT_PRIVATE / 'go-version.private.stderr', 4096, empty=True)[0] == b'')
    state['formatExit'] = capture(state, [PATHS['goRoot'] + '/bin/gofmt', '-d',
        'internal/mihomodeploy/runtime_apply_linux_test.go'], 'gofmt.patch', 'gofmt.stderr', 30)
    state['goExit'] = capture(state, [PATHS['goRoot'] + '/bin/go', 'test', '-json',
        '-count=1', '-shuffle=off', '-tags=' + FIXED_TAG, '-run=^' + FIXED_TOP + '$',
        '-timeout=' + str(c['goTimeoutSeconds']) + 's', c['goPackage']],
        'apply.json', 'apply.stderr', c['goTimeoutSeconds'])
    after, _, after_directory = w.custody(state['consumed'])
    need(state['inputBefore'] == after and state['originalDirectory'] == after_directory)
    facts['inputCustody'] = dict(before=state['inputBefore'], after=after)
    exact(facts, c['sandboxKeys'])
    outputs, pass_report = {}, False
    raw_suppressed = False
    try:
        outputs, forbidden, observed, pass_report = private_outputs(c, state)
        for name in ('go-version.txt', 'gofmt.patch', 'gofmt.stderr', 'apply.json', 'apply.stderr'):
            raw, _ = w.file_bytes(ROOT_PRIVATE / name, MAX_LOG, empty=True)
            need(not any(value in raw for value in forbidden))
            outputs[name] = raw
        state['observed'] = observed
    except Exception:
        outputs = {}
        raw_suppressed = True
    outputs['sandbox.json'] = w.canonical(facts)
    outputs['execution.json'] = w.canonical(execution(c, state))
    if raw_suppressed:
        outputs['worker-failure.json'] = w.canonical(worker_failure(c, state))
    need(set(outputs) <= (set(c['publicFiles']) | set(c['failureFiles'])) -
         set(state['originalPublic']) - {'host-after.json'})
    unchanged_public(state)
    for name, raw in outputs.items():
        w.write_new(EXPORT_ALIAS / name, raw, 0o644)
    sync_output(state)
    unchanged_public(state)
    exported = {path.name for path in state['out'].iterdir()}
    need(not (set(PRIVATE_FENCE_FILES) & exported))
    if (raw_suppressed or state['formatExit'] != 0 or state['goExit'] != 0 or
            outputs.get('gofmt.patch') or outputs.get('gofmt.stderr') or not pass_report):
        return state['goExit'] if type(state['goExit']) is int and state['goExit'] > 0 else 1
    need(exported == set(c['publicFiles']) - {'host-after.json'} and not state['pending'])
    print('MIHOMO_APPLY_WORKER=CAPTURED independent_verification=pending production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        report_failure()
        raise SystemExit('MIHOMO_APPLY_WORKER=REJECTED raw_input_suppressed=true') from None
