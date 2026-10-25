"""Independent original CLI evidence reader. No kernel execution or producer import."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess

PREFIX = 'chengwang/deploy/mihomo-lifecycle-lab/'
CANDIDATE = 'chengwang/tools/mihomo-runtime-candidate/'
FOUNDATION = [PREFIX + n for n in ('run_contracts.sh', 'check_contracts.py', 'test_check_contracts.py')]
FOUNDATION += ['.github/workflows/chengwang-mihomo-lifecycle.yml', 'chengwang/go.mod']
FOUNDATION += ['chengwang/internal/adapter/mihomo/' + n for n in ('write_client.go', 'write_client_test.go')]
FOUNDATION += ['chengwang/internal/mihomodeploy/' + n for n in ('config.go', 'config_test.go', 'artifact.go',
    'artifact_linux.go', 'artifact_unsupported.go', 'artifact_test.go', 'artifact_linux_test.go',
    'plan.go', 'plan_test.go', 'prepare.go', 'prepare_test.go')]
FOUNDATION += ['chengwang/internal/mihomodeploy/' + n for n in ('lifecycle_disk.go', 'lifecycle.go', 'lifecycle_test.go',
    'lifecycle_linux.go', 'lifecycle_linux_test.go', 'lifecycle_unsupported.go', 'lifecycle_unsupported_test.go', 'private_atomic_linux.go')]
FOUNDATION += ['chengwang/internal/authn/' + n for n in ('store.go', 'store_test.go', 'snapshot_manager.go', 'snapshot_manager_test.go',
    'snapshot_manager_linux.go', 'snapshot_manager_linux_test.go', 'snapshot_manager_unsupported.go')]
LAB_READER_FILES = ('lab_readback.go', 'lab_readback_test.go', 'lab_evidence.go', 'lab_evidence_test.go')
LAB_RUNTIME_FILES = ('lab_authority.go', 'lab_authority_test.go', 'lab_expectation.go', 'lab_expectation_test.go',
    'lab_kernel.go', 'lab_kernel_linux.go', 'lab_kernel_linux_test.go',
    'lab_kernel_unsupported.go', 'lab_kernel_unsupported_test.go')
FOUNDATION += ['chengwang/internal/adapter/mihomo/' + name for name in LAB_READER_FILES]
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RUNTIME_FILES]
LAB_SERVICE_FILES = (
    'lab_backend.go',
    'lab_bootstrap.go',
    'lab_bootstrap_linux.go',
    'lab_bootstrap_linux_test.go',
    'lab_bootstrap_state.go',
    'lab_bootstrap_test.go',
    'lab_bootstrap_unsupported.go',
    'lab_collector.go',
    'lab_collector_linux.go',
    'lab_collector_linux_test.go',
    'lab_collector_test.go',
    'lab_collector_unsupported.go',
    'lab_local_route.go',
    'lab_local_route_test.go',
    'lab_service.go',
    'lab_service_acceptance_linux.go',
    'lab_service_diagnostics.go',
    'lab_service_diagnostics_test.go',
    'lab_service_test.go',
    'lab_syntax_linux.go',
    'lab_syntax_linux_test.go',
    'lab_syntax_unsupported.go',
    'lab_syntax_unsupported_test.go',
)
LAB_API_FILES = (
    'mihomo_lab.go',
    'mihomo_lab_test.go',
    'server.go',
)
LAB_COMPOSITION_FILES = (
    'mihomo_lab_runtime.go',
    'mihomo_lab_config_test.go',
    'mihomo_service_e2e_linux_test.go',
    'runtime.go',
)
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_SERVICE_FILES]
FOUNDATION += ['chengwang/internal/api/' + name for name in LAB_API_FILES]
FOUNDATION += ['chengwang/internal/serverruntime/' + name for name in LAB_COMPOSITION_FILES]
FOUNDATION += [
    'chengwang/internal/adapter/mihomo/lab_reload_fault_default.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_linux.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_unsupported.go',
    'chengwang/internal/adapter/mihomo/lab_reload_fault_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_unknown_acceptance_linux.go',
    'chengwang/internal/serverruntime/mihomo_unknown_e2e_linux_test.go',
]
CONTINUOUS_RECOVERY_COMPAT_FILES = (
    'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
    'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
    'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'chengwang/internal/serverruntime/mihomo_continuous_recovery_hook_linux.go',
)
FOUNDATION += list(CONTINUOUS_RECOVERY_COMPAT_FILES)
FOUNDATION += ['chengwang/internal/authz/model.go', 'chengwang/internal/authz/policy.go', 'chengwang/internal/authz/policy_test.go', 'chengwang/internal/authz/image_trust_test.go', 'chengwang/internal/authz/image_trust_history_d8_test.go', 'chengwang/internal/authz/subscription.go', 'chengwang/internal/authz/subscription_test.go', 'chengwang/internal/authz/lab_recovery.go', 'chengwang/internal/authz/lab_recovery_test.go', 'chengwang/internal/mihomodeploy/lab_quiescence.go', 'chengwang/internal/mihomodeploy/lab_quiescence_linux.go', 'chengwang/internal/mihomodeploy/lab_quiescence_unsupported.go', 'chengwang/internal/mihomodeploy/lab_quiescence_test.go', 'chengwang/internal/mihomodeploy/lab_quiescence_linux_test.go', 'chengwang/internal/mihomodeploy/lab_recovery_plan.go', 'chengwang/internal/mihomodeploy/lab_recovery_plan_test.go', 'chengwang/internal/mihomodeploy/lifecycle_v3.go', 'chengwang/internal/mihomodeploy/lifecycle_v3_test.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_store.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_store_test.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go', 'chengwang/deploy/mihomo-lifecycle-lab/legacy_go_tops.json']
LAB_RECOVERY_EXECUTION_FILES = (
    'lab_recovery_authority.go',
    'lab_recovery_authority_test.go',
    'lab_recovery_start.go',
    'lab_recovery_start_linux.go',
    'lab_recovery_start_unsupported.go',
    'lab_recovery_start_test.go',
    'lab_recovery_start_linux_test.go',
)
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_EXECUTION_FILES]
FOUNDATION += ['chengwang/internal/mihomodeploy/lifecycle_trusted_clone_properties_test.go']
S1_STARTED_FILES = ('lifecycle_recovery_started.go', 'lifecycle_recovery_started_linux_test.go')
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in S1_STARTED_FILES]
LAB_SELECTED_TARGET_FILES = ('lab_target_readback.go', 'lab_target_readback_test.go')
FOUNDATION += ['chengwang/internal/adapter/mihomo/' + name for name in LAB_SELECTED_TARGET_FILES]
LAB_SAMPLE_TIMES_FILES = ('lab_sample_times.go', 'lab_sample_times_test.go')
FOUNDATION += ['chengwang/internal/adapter/mihomo/' + name for name in LAB_SAMPLE_TIMES_FILES]
LAB_RECOVERY_COLLECTOR_FILES = ('lab_recovery_collector.go', 'lab_recovery_collector_linux_test.go')
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_COLLECTOR_FILES]
LAB_RECOVERY_MARKER_FILES = ('lab_recovery_marker.go', 'lab_recovery_marker_test.go', 'lab_recovery_marker_bounds_test.go')
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_MARKER_FILES]
LAB_RECOVERY_VERIFICATION_FILES = ('lifecycle_recovery_verification.go', 'lifecycle_recovery_verification_test.go', 'lifecycle_recovery_verified_bounds_test.go')
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_VERIFICATION_FILES]
LAB_NATIVE_RECOVERY_FILES = ('lab_native_recovery_linux.go', 'lab_native_recovery_linux_test.go',
    'lab_native_recovery_observer_default.go', 'lab_native_recovery_observer_linux.go')
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in LAB_NATIVE_RECOVERY_FILES]
RECOVERY_COMPLETION_CURRENT_SCOPE_FILES = (
    'lifecycle_recovery_checkpoint.go',
    'lifecycle_recovery_completion.go',
    'lifecycle_recovery_completion_test.go',
    'lifecycle_completion_shape_diagnostic_test.go',
    'lifecycle_v3_decode_scope_test.go',
    'lifecycle_current_epoch.go',
    'lifecycle_current_epoch_test.go',
    'lab_current_epoch_runtime.go',
    'lab_current_epoch_runtime_test.go',
)
FOUNDATION += ['chengwang/internal/mihomodeploy/' + name for name in RECOVERY_COMPLETION_CURRENT_SCOPE_FILES]
FILES = FOUNDATION + ['chengwang/internal/mihomodeploy/runtime_compat_linux_test.go']
FILES += [PREFIX + n for n in ('run_compat.sh', 'compat_worker.py', 'compat_contract.json', 'check_compat.py', 'test_check_compat.py')]
CONSUMER_FILES = [CANDIDATE + n for n in ('pin.json', 'consume_pin.py', 'check_consumption.py', 'test_consume_pin.py', 'README.md')]
FILES += CONSUMER_FILES
CASES = ('version', 'base', 'candidate', 'malformed')
TOP = ('TestMihomoCompatVersion', 'TestMihomoCompatGeneratedConfigs', 'TestMihomoCompatMalformedYAML')
SUB = ('TestMihomoCompatGeneratedConfigs/base', 'TestMihomoCompatGeneratedConfigs/candidate')
PUBLIC = ['compat.json', 'compat.stderr', 'execution.json', 'sandbox.json', 'go-version.txt',
    'host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json', 'gofmt.patch', 'gofmt.stderr']
PUBLIC += [case + suffix for case in CASES for suffix in ('.exec.json', '.stdout', '.stderr')]
ENV = sorted(['CGO_ENABLED', 'CHENGWANG_MIHOMO_COMPAT_ELF', 'CHENGWANG_MIHOMO_COMPAT_OUT',
    'CHENGWANG_MIHOMO_COMPAT_RECEIPT', 'CHENGWANG_MIHOMO_COMPAT_SOURCE_COMMIT', 'GOCACHE', 'GOENV',
    'GOFLAGS', 'GOMODCACHE', 'GOPROXY', 'GOROOT', 'GOSUMDB', 'GOTOOLCHAIN', 'HOME', 'LANG', 'LC_ALL', 'PATH', 'TMPDIR', 'TZ'])
SCOPE = 'ACTUAL_FIXED_KERNEL_VERSION_AND_SYNTAX_ONLY_NOT_SERVICE_DATAPLANE_BUSINESS_SIGNATURE_OR_PRODUCTION'
UPSTREAM = '88dcbf7f1614a67c3b36b848ee3592dfa92ada36'
PUBLISHED = '306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc'
ASSET = 'mihomo-linux-amd64-v1-v1.19.32.gz'
MALFORMED = b'mixed-port: [\n'
HEX = re.compile(r'[a-f0-9]{64}')
EXEC_KEYS = ['schema', 'sourceCommit', 'case', 'binarySHA256', 'binaryBytes', 'consumptionSHA256', 'argvClass', 'inputSHA256', 'inputBytes',
    'started', 'pid', 'procStartTicks', 'procObservationState', 'waitReturned', 'waitErrorClass', 'exitCode', 'signal', 'timedOut', 'killSent', 'processGroupAbsent', 'stdout', 'stderr']


def need(ok):
    if not ok: raise ValueError('Mihomo compatibility evidence rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
def exact(value, keys): return type(value) is dict and set(value) == set(keys)
def integer(value, low, high): return type(value) is int and low <= value <= high
def digest(value): return type(value) is str and HEX.fullmatch(value) is not None


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items: need(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))


def plain(path, missing=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts)
    for item in reversed((path, *path.parents)):
        if missing and item == path:
            try: item.lstat()
            except FileNotFoundError: continue
            need(False)
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    return path


def read(path, limit, empty=True):
    path = plain(path); before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (0 if empty else 1) <= before.st_size <= limit)
    if os.name == 'posix': need(stat.S_IMODE(before.st_mode) in (0o400, 0o600, 0o644))
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as handle: raw = handle.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(opened) == identity(after) == identity(path.lstat()) and len(raw) == before.st_size)
        return raw
    finally: os.close(fd)


def source_bindings(repo, commit):
    repo = plain(repo); need(re.fullmatch('[a-f0-9]{40}', commit) is not None)
    def git(*args):
        result = subprocess.run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        need(result.returncode == 0 and len(result.stdout) <= 1 << 20); return result.stdout
    need(git('rev-parse', 'HEAD').strip().decode('ascii') == commit
         and Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() == repo)
    need(len(FILES) == len(set(FILES)) == 159)
    result = {}
    for relative in FILES:
        raw = read(repo / relative, 1 << 20, False); need(raw == git('show', commit + ':' + relative)); result[relative] = raw
    need(read(__file__, 1 << 20, False) == result[PREFIX + 'check_compat.py'])
    return result


def contract(sources):
    value = decode(sources[PREFIX + 'compat_contract.json'])
    need(exact(value, ['schema', 'status', 'buildTag', 'testPackage', 'topLevelTests', 'subtests', 'cases', 'publicFiles', 'privateExtraFiles',
        'privateSecretsSchema', 'privateSecretsKeys', 'environmentKeys', 'paths', 'execSchema', 'execKeys', 'stdioKeys', 'stdioMaxBytes',
        'caseTimeoutSeconds', 'waitDelaySeconds', 'goTimeoutSeconds', 'argvClass', 'waitErrorClasses', 'procObservationStates',
        'executionSchema', 'executionKeys', 'sandboxSchema', 'sandboxKeys', 'kernelCopyKeys', 'inputCustodyKeys', 'inputObjects', 'inputObjectKeys', 'scope', 'production']))
    need(value['schema'] == 'chengwang.mihomo-compat-contract/v1' and value['production'] is False and value['scope'] == SCOPE)
    need(value['cases'] == list(CASES) and value['topLevelTests'] == list(TOP) and value['subtests'] == list(SUB))
    need(value['publicFiles'] == PUBLIC and value['environmentKeys'] == ENV and value['stdioMaxBytes'] == 65536)
    need(value['buildTag'] == 'linux && chengwang_mihomo_compat' and value['testPackage'] == 'chengwang/internal/mihomodeploy')
    need(value['execKeys'] == EXEC_KEYS and value['stdioKeys'] == ['bytes', 'sha256', 'totalBytes', 'truncated'])
    need(value['execSchema'] == 'chengwang.mihomo-compat-exec/v1' and value['executionSchema'] == 'chengwang.mihomo-compat-execution/v1'
         and value['executionKeys'] == ['schema', 'sourceCommit', 'formatExit', 'goExit', 'realMihomoExecutionObserved', 'production'])
    need(value['argvClass'] == dict(version='VERSION', base='STDIN_TEST', candidate='STDIN_TEST', malformed='STDIN_TEST'))
    text = sources['chengwang/internal/mihomodeploy/runtime_compat_linux_test.go'].decode('utf8')
    need(text.startswith('//go:build linux && chengwang_mihomo_compat\n'))
    names = re.findall(r'^func (TestMihomoCompat[A-Za-z0-9_]+)\(t \*testing\.T\)\s*\{', text, re.M)
    need(len(names) == 3 and set(names) == set(TOP) and '"base"' in text and '"candidate"' in text)
    return value


def consumption(raw, sources, commit):
    value = decode(raw); need(canonical(value) == raw)
    need(exact(value, ['schema', 'state', 'source', 'component', 'version', 'upstreamSourceCommit', 'archive', 'gzip', 'elf', 'output',
        'runtimeExecuted', 'runtimeCompatibilityProven', 'businessAvailabilityProven', 'publisherSignatureProven', 'productionApproved', 'production']))
    need(value['schema'] == 'chengwang.mihomo-candidate-consumption/v1' and value['state'] == 'PINNED_GZIP_EXPANDED_NOT_EXECUTED')
    need(value['component'] == 'MetaCubeX/mihomo' and value['version'] == 'v1.19.32' and value['upstreamSourceCommit'] == UPSTREAM)
    need(all(value[k] is False for k in ('runtimeExecuted', 'runtimeCompatibilityProven', 'businessAvailabilityProven', 'publisherSignatureProven', 'productionApproved', 'production')))
    want = dict(projectSourceCommit=commit, sourceFiles=[dict(path=p, bytes=len(sources[p]), sha256=sha(sources[p])) for p in CONSUMER_FILES], pinSHA256=sha(sources[CANDIDATE + 'pin.json']))
    need(canonical(value['source']) == canonical(want))
    pin = decode(sources[CANDIDATE + 'pin.json'])
    expected_pin = dict(schema='chengwang.mihomo-runtime-candidate-pin/v1', component='MetaCubeX/mihomo', version='v1.19.32', upstreamSourceCommit=UPSTREAM,
        artifact=dict(name=ASSET, url='https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/' + ASSET,
            publishedSHA256=PUBLISHED, exactCompressedBytes=None, elfSHA256=None, elfBytes=None),
        limits=dict(compressedBytes=67108864, expandedBytes=134217728),
        researchManifestSHA256='76b194ad7183cb661ad2deef164f30f9d8a260ddbc823e53b7760253a71bc7dc',
        publisherSignatureProven=False, productionApproved=False, runtimeExecuted=False)
    need(canonical(pin) == canonical(expected_pin))
    archive, elf, gz = value['archive'], value['elf'], value['gzip']
    need(exact(archive, ['name', 'bytes', 'sha256', 'pinBasis']) and archive['name'] == ASSET and archive['sha256'] == PUBLISHED
         and integer(archive['bytes'], 1, 64 << 20) and archive['pinBasis'] == 'PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL')
    need(exact(elf, ['bytes', 'sha256', 'byteOrder', 'elfClass', 'machine', 'type', 'entryPoint', 'programHeaderCount', 'loadSegments', 'sectionHeaderCount', 'executableEntryMapped']))
    need(integer(elf['bytes'], 64, 128 << 20) and digest(elf['sha256']) and elf['byteOrder'] == 'little' and elf['elfClass'] == 'ELF64'
         and elf['machine'] == 'AMD64' and elf['type'] in ('EXEC', 'DYN') and integer(elf['entryPoint'], 1, (1 << 64) - 1)
         and integer(elf['programHeaderCount'], 1, 65535) and integer(elf['loadSegments'], 1, elf['programHeaderCount'])
         and integer(elf['sectionHeaderCount'], 0, 65535) and elf['executableEntryMapped'] is True)
    need(exact(gz, ['singleMember', 'complete', 'trailerCRC32', 'trailerISIZE']) and gz['singleMember'] is True and gz['complete'] is True
         and type(gz['trailerCRC32']) is str and re.fullmatch('[a-f0-9]{8}', gz['trailerCRC32']) and type(gz['trailerISIZE']) is int and gz['trailerISIZE'] == elf['bytes'])
    need(value['output'] == dict(path='mihomo', mode='0500', receiptMode='0400', directoryMode='0700'))
    return elf


def sandbox(raw, before_raw, after_raw, sources, commit, elf, receipt):
    value, before, after = decode(raw), decode(before_raw), decode(after_raw)
    keys = ['schema', 'sourceCommit', 'uid', 'gid', 'effectiveCaps', 'noNewPrivileges', 'networkNamespace', 'mountNamespace', 'pidNamespace',
        'environmentKeys', 'interfaceNames', 'defaultV4Routes', 'defaultV6Routes', 'sourceModuleSHA256', 'sourceReadOnly', 'goReadOnly', 'kernelCopy', 'inputCustody']
    need(exact(value, keys) and value['schema'] == 'chengwang.mihomo-compat-sandbox/v1' and value['sourceCommit'] == commit)
    need(type(value['uid']) is type(value['gid']) is int and value['uid'] == value['gid'] == 10001
         and value['effectiveCaps'] == '0000000000000000' and value['noNewPrivileges'] is True)
    need(value['environmentKeys'] == ENV and value['interfaceNames'] == ['lo'] and value['defaultV4Routes'] == value['defaultV6Routes'] == [])
    need(value['sourceModuleSHA256'] == sha(sources['chengwang/go.mod']) and value['sourceReadOnly'] is True and value['goReadOnly'] is True)
    need(value['kernelCopy'] == dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', readOnly=True, executable=True))
    need(value['kernelCopy']['readOnly'] is True and value['kernelCopy']['executable'] is True and type(value['kernelCopy']['bytes']) is int)
    need(exact(before, ['networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256']) and before == after and digest(before['resolvSHA256']))
    for name, kind in [('networkNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid')]:
        pattern = kind + r':\[[0-9]{1,20}\]'
        need(type(before[name]) is str and re.fullmatch(pattern, before[name]) and type(value[name]) is str
             and re.fullmatch(pattern, value[name]) and value[name] != before[name])
    custody = value['inputCustody']; need(exact(custody, ['before', 'after']) and canonical(custody['before']) == canonical(custody['after']))
    need(exact(custody['before'], ['elf', 'receipt']))
    for key, hashed, size, mode in [('elf', elf['sha256'], elf['bytes'], '0500'), ('receipt', sha(receipt), len(receipt), '0400')]:
        item = custody['before'][key]
        need(exact(item, ['sha256', 'bytes', 'mode', 'uid', 'gid']) and item['sha256'] == hashed and type(item['bytes']) is int
             and item['bytes'] == size and item['mode'] == mode and integer(item['uid'], 0, (1 << 32) - 1) and integer(item['gid'], 0, (1 << 32) - 1))
    return value


def safe_stdio(case, out, err):
    """Closed fixed-upstream CLI text, not a claim about a loaded config path.

    Original run 40110160604 (63236a2) observes the literal config.yaml label
    for stdin -t -f -; the old inferred absolute HOME/case path was incorrect.
    Only that exact relative success line is accepted, never arbitrary paths.
    """
    need(err == b'' and len(out) <= 65536 and b'\r' not in out and b'\x1b' not in out and out.endswith(b'\n'))
    text = out.decode('utf8'); need('\x00' not in text)
    if case == 'version':
        lines = text.splitlines()
        need(1 <= len(lines) <= 2 and re.fullmatch(r'Mihomo Meta v1\.19\.32 linux amd64 with go1\.[0-9]{1,2}\.[0-9]{1,2} [0-9A-Za-z:TZ+. ,_-]{1,96}', lines[0]))
        need(not re.search(r'[a-f0-9]{40,}|https?://|secret|payload|127\.0\.0\.1', text, re.I))
        if len(lines) == 2: need(re.fullmatch(r'Use tags: [a-z_]{1,32}(?:, [a-z_]{1,32}){0,15}', lines[1]))
        return
    lines = text.splitlines(); need(1 <= len(lines) <= 8)
    if case in ('base', 'candidate'):
        need(lines[-1] == 'configuration file config.yaml test is successful')
        messages = [r'Start initial configuration in progress', r'Geodata Loader mode: (?:memconservative|standard)',
            r'Geosite Matcher implementation: (?:succinct|mph)', r'Initial configuration complete, total time: [0-9]{1,6}ms']
        need(len(lines) == 5)
        for line, message in zip(lines[:-1], messages):
            need(re.fullmatch(r'time="[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,18}Z" level=info msg="' + message + '"', line))
    else:
        need(case == 'malformed' and len(lines) == 2 and lines[-1] == 'configuration test failed')
        need(re.fullmatch(r'time="[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,18}Z" level=error msg="yaml: line [12]: did not find expected node content"', lines[0]))


def exec_record(raw, case, out, err, c, commit, elf, receipt):
    value = decode(raw); need(exact(value, c['execKeys']))
    need(value['schema'] == c['execSchema'] and value['sourceCommit'] == commit and value['case'] == case
         and value['binarySHA256'] == elf['sha256'] and type(value['binaryBytes']) is int and value['binaryBytes'] == elf['bytes']
         and value['consumptionSHA256'] == sha(receipt) and value['argvClass'] == c['argvClass'][case])
    need(value['started'] is True and integer(value['pid'], 2, (1 << 31) - 1) and value['waitReturned'] is True
         and value['signal'] is None and value['timedOut'] is False and value['killSent'] is False and value['processGroupAbsent'] is True)
    need(value['procObservationState'] in ('OBSERVED', 'NOT_OBSERVED'))
    need(integer(value['procStartTicks'], 1, (1 << 63) - 1) if value['procObservationState'] == 'OBSERVED' else value['procStartTicks'] is None)
    need(integer(value['inputBytes'], 0, 1 << 20))
    if case == 'version': need(value['inputSHA256'] is None and value['inputBytes'] == 0)
    elif case == 'malformed': need(value['inputSHA256'] == sha(MALFORMED) and value['inputBytes'] == len(MALFORMED))
    else: need(digest(value['inputSHA256']) and value['inputBytes'] > 0)
    if case == 'malformed': need(value['waitErrorClass'] == 'EXIT_STATUS' and integer(value['exitCode'], 1, 255))
    else: need(value['waitErrorClass'] == 'NONE' and type(value['exitCode']) is int and value['exitCode'] == 0)
    for key, original in [('stdout', out), ('stderr', err)]:
        item = value[key]
        need(exact(item, c['stdioKeys']) and type(item['bytes']) is type(item['totalBytes']) is int and item['bytes'] == item['totalBytes'] == len(original)
             and len(original) <= 65536 and item['sha256'] == sha(original) and item['truncated'] is False)
    safe_stdio(case, out, err)
    return value


def go_events(raw):
    states = {}; started = ended = False; package = 'chengwang/internal/mihomodeploy'
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20); event = decode(line)
        need(type(event) is dict and set(event) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'} and event.get('Package') == package)
        action, name = event.get('Action'), event.get('Test')
        need(action in ('start', 'run', 'output', 'pass') and not ended)
        if 'Elapsed' in event: need(type(event['Elapsed']) in (int, float) and math.isfinite(event['Elapsed']) and event['Elapsed'] >= 0)
        if action == 'start': need(not started and name is None); started = True; continue
        need(started)
        if name is not None:
            need(name in TOP + SUB)
            if action == 'run': need(name not in states); states[name] = 'run'
            elif action == 'pass': need(states.get(name) == 'run'); states[name] = 'pass'
            else: need(action == 'output' and name in states)
        elif action == 'pass': need(set(states) == set(TOP + SUB) and all(v == 'pass' for v in states.values())); ended = True
        else: need(action == 'output')
        if action == 'output':
            output = event.get('Output'); need(type(output) is str and len(output) <= 4096)
            need(re.fullmatch(r'(?:=== RUN   TestMihomoCompat[A-Za-z0-9_/]+|[ ]*--- PASS: (?:TestMihomoCompat[A-Za-z0-9_/]+|base|candidate) \([0-9.]+s\)|PASS|ok\s+chengwang/internal/mihomodeploy\s+[0-9.]+s)\n', output))
    need(started and ended and len(states) == 5)
    return dict(topLevel=3, subtests=2, passingSemanticTests=5, skips=0)


def verify_raw(raw, sources, commit):
    need(set(raw) == set(PUBLIC) and re.fullmatch('[a-f0-9]{40}', commit))
    c = contract(sources)
    need(raw['compat.stderr'] == raw['gofmt.patch'] == raw['gofmt.stderr'] == b'')
    need(raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
    execution = decode(raw['execution.json'])
    need(exact(execution, c['executionKeys']) and execution['schema'] == c['executionSchema'] and execution['sourceCommit'] == commit
         and type(execution['formatExit']) is type(execution['goExit']) is int and execution['formatExit'] == execution['goExit'] == 0
         and execution['realMihomoExecutionObserved'] is True and execution['production'] is False)
    receipt = raw['consumption.json']; need(receipt == raw['consumption-independent.json'])
    elf = consumption(receipt, sources, commit)
    sandbox(raw['sandbox.json'], raw['host-before.json'], raw['host-after.json'], sources, commit, elf, receipt)
    tests = go_events(raw['compat.json'])
    records = {case: exec_record(raw[case + '.exec.json'], case, raw[case + '.stdout'], raw[case + '.stderr'], c, commit, elf, receipt) for case in CASES}
    need(len({record['pid'] for record in records.values()}) == 4)
    need(records['base']['inputSHA256'] != records['candidate']['inputSHA256'])
    return dict(schema='chengwang.mihomo-compat-verification/v1', sourceCommit=commit, outcome='PASS', scope=SCOPE,
        sourceSHA256={p: sha(value) for p, value in sources.items()}, inputSHA256={p: sha(value) for p, value in raw.items()},
        tests=tests, actualKernelCLIVersionAndSyntaxObserved=True, dataplaneProven=False, businessAvailabilityProven=False,
        publisherSignatureProven=False, productionApproved=False, production=False)


def verify(evidence, repo, commit):
    evidence = plain(evidence); sources = source_bindings(repo, commit)
    need(set(p.name for p in evidence.iterdir()) == set(PUBLIC))
    limits = {p: (16 << 20 if p == 'compat.json' else 65536) for p in PUBLIC}
    raw = {p: read(evidence / p, limits[p]) for p in PUBLIC}
    result = verify_raw(raw, sources, commit)
    need(all(read(evidence / p, limits[p]) == value for p, value in raw.items()))
    need(set(p.name for p in evidence.iterdir()) == set(PUBLIC) and sources == source_bindings(repo, commit))
    return result


def main():
    p = argparse.ArgumentParser(); p.add_argument('--repo', type=Path, required=True); p.add_argument('--source-commit', required=True)
    p.add_argument('--evidence', type=Path, required=True); p.add_argument('--report', type=Path, required=True); a = p.parse_args()
    a.repo, a.evidence, a.report = plain(a.repo), plain(a.evidence), plain(a.report, True)
    need(os.name == 'posix' and os.open in os.supports_dir_fd and not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.evidence))
    value = verify(a.evidence, a.repo, a.source_commit)
    directory = os.open(a.report.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(a.report.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as h: h.write(canonical(value)); h.flush(); os.fsync(h.fileno())
        os.fsync(directory)
    finally: os.close(directory)
    print('MIHOMO_COMPAT=PASS scope=CLI_VERSION_AND_SYNTAX_ONLY production=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('MIHOMO_COMPAT=REJECTED raw_input_suppressed=true') from None
