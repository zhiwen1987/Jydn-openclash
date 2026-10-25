"""Check actual Go event streams; no claim of Mihomo or production execution."""
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
FILES = [PREFIX + 'run_contracts.sh', PREFIX + 'check_contracts.py',
    PREFIX + 'test_check_contracts.py',
    '.github/workflows/chengwang-mihomo-lifecycle.yml',
    'chengwang/internal/adapter/mihomo/write_client.go',
    'chengwang/internal/adapter/mihomo/write_client_test.go',
    'chengwang/internal/mihomodeploy/config.go', 'chengwang/internal/mihomodeploy/config_test.go', 'chengwang/go.mod',
    *['chengwang/internal/mihomodeploy/' + name for name in ('artifact.go', 'artifact_linux.go',
        'artifact_unsupported.go', 'artifact_test.go', 'artifact_linux_test.go', 'plan.go', 'plan_test.go', 'prepare.go', 'prepare_test.go')]]
LIFECYCLE_FILES = ('lifecycle_disk.go', 'lifecycle.go', 'lifecycle_test.go', 'lifecycle_linux.go',
    'lifecycle_linux_test.go', 'lifecycle_unsupported.go', 'lifecycle_unsupported_test.go', 'private_atomic_linux.go')
AUTHN_FILES = ('store.go', 'store_test.go', 'snapshot_manager.go', 'snapshot_manager_test.go',
    'snapshot_manager_linux.go', 'snapshot_manager_linux_test.go', 'snapshot_manager_unsupported.go')
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LIFECYCLE_FILES]
FILES += ['chengwang/internal/authn/' + name for name in AUTHN_FILES]
LAB_READER_FILES = ('lab_readback.go', 'lab_readback_test.go', 'lab_evidence.go', 'lab_evidence_test.go')
LAB_RUNTIME_FILES = ('lab_authority.go', 'lab_authority_test.go', 'lab_expectation.go', 'lab_expectation_test.go',
    'lab_kernel.go', 'lab_kernel_linux.go', 'lab_kernel_linux_test.go',
    'lab_kernel_unsupported.go', 'lab_kernel_unsupported_test.go')
FILES += ['chengwang/internal/adapter/mihomo/' + name for name in LAB_READER_FILES]
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RUNTIME_FILES]
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
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_SERVICE_FILES]
FILES += ['chengwang/internal/api/' + name for name in LAB_API_FILES]
FILES += ['chengwang/internal/serverruntime/' + name for name in LAB_COMPOSITION_FILES]
FILES += [
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
FILES += list(CONTINUOUS_RECOVERY_COMPAT_FILES)
FILES += ['chengwang/internal/authz/model.go', 'chengwang/internal/authz/policy.go', 'chengwang/internal/authz/policy_test.go', 'chengwang/internal/authz/image_trust_test.go', 'chengwang/internal/authz/image_trust_history_d8_test.go', 'chengwang/internal/authz/subscription.go', 'chengwang/internal/authz/subscription_test.go', 'chengwang/internal/authz/lab_recovery.go', 'chengwang/internal/authz/lab_recovery_test.go', 'chengwang/internal/mihomodeploy/lab_quiescence.go', 'chengwang/internal/mihomodeploy/lab_quiescence_linux.go', 'chengwang/internal/mihomodeploy/lab_quiescence_unsupported.go', 'chengwang/internal/mihomodeploy/lab_quiescence_test.go', 'chengwang/internal/mihomodeploy/lab_quiescence_linux_test.go', 'chengwang/internal/mihomodeploy/lab_recovery_plan.go', 'chengwang/internal/mihomodeploy/lab_recovery_plan_test.go', 'chengwang/internal/mihomodeploy/lifecycle_v3.go', 'chengwang/internal/mihomodeploy/lifecycle_v3_test.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_store.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_store_test.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions.go', 'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go', 'chengwang/deploy/mihomo-lifecycle-lab/legacy_go_tops.json']
LAB_RECOVERY_EXECUTION_FILES = (
    'lab_recovery_authority.go',
    'lab_recovery_authority_test.go',
    'lab_recovery_start.go',
    'lab_recovery_start_linux.go',
    'lab_recovery_start_unsupported.go',
    'lab_recovery_start_test.go',
    'lab_recovery_start_linux_test.go',
)
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_EXECUTION_FILES]
FILES += ['chengwang/internal/mihomodeploy/lifecycle_trusted_clone_properties_test.go']
S1_STARTED_FILES = ('lifecycle_recovery_started.go', 'lifecycle_recovery_started_linux_test.go')
FILES += ['chengwang/internal/mihomodeploy/' + name for name in S1_STARTED_FILES]
LAB_SELECTED_TARGET_FILES = ('lab_target_readback.go', 'lab_target_readback_test.go')
FILES += ['chengwang/internal/adapter/mihomo/' + name for name in LAB_SELECTED_TARGET_FILES]
LAB_SAMPLE_TIMES_FILES = ('lab_sample_times.go', 'lab_sample_times_test.go')
FILES += ['chengwang/internal/adapter/mihomo/' + name for name in LAB_SAMPLE_TIMES_FILES]
LAB_RECOVERY_COLLECTOR_FILES = ('lab_recovery_collector.go', 'lab_recovery_collector_linux_test.go')
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_COLLECTOR_FILES]
LAB_RECOVERY_MARKER_FILES = ('lab_recovery_marker.go', 'lab_recovery_marker_test.go', 'lab_recovery_marker_bounds_test.go')
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_MARKER_FILES]
LAB_RECOVERY_VERIFICATION_FILES = ('lifecycle_recovery_verification.go', 'lifecycle_recovery_verification_test.go', 'lifecycle_recovery_verified_bounds_test.go')
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_RECOVERY_VERIFICATION_FILES]
LAB_NATIVE_RECOVERY_FILES = ('lab_native_recovery_linux.go', 'lab_native_recovery_linux_test.go',
    'lab_native_recovery_observer_default.go', 'lab_native_recovery_observer_linux.go')
FILES += ['chengwang/internal/mihomodeploy/' + name for name in LAB_NATIVE_RECOVERY_FILES]
RECOVERY_COMPLETION_CURRENT_FILES = (
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
FILES += ['chengwang/internal/mihomodeploy/' + name for name in RECOVERY_COMPLETION_CURRENT_FILES]
RECOVERY_SERVICE_COORDINATOR_FILES = (
    'lab_recovery_backend.go',
    'lab_recovery_backend_test.go',
    'lab_recovery_cleanup_bridge.go',
    'lab_recovery_coordinator_linux.go',
    'lab_recovery_coordinator_unsupported.go',
    'lab_recovery_unstarted_cleanup_linux_test.go',
    'lifecycle_recovery_reconcile.go',
    'lifecycle_recovery_reconcile_test.go',
)
FILES += ['chengwang/internal/mihomodeploy/' + name for name in RECOVERY_SERVICE_COORDINATOR_FILES]
FILES += ['chengwang/internal/api/mihomo_recovery.go', 'chengwang/internal/api/mihomo_recovery_test.go']
TEST_FILES = [('chengwang/internal/adapter/mihomo/write_client_test.go', 'chengwang/internal/adapter/mihomo'),
    *[('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
      for name in ('config_test.go', 'artifact_test.go', 'artifact_linux_test.go', 'plan_test.go', 'prepare_test.go',
                   'lifecycle_test.go', 'lifecycle_linux_test.go')]]
TEST_FILES += [('chengwang/internal/authn/' + name, 'chengwang/internal/authn')
    for name in ('store_test.go', 'snapshot_manager_test.go', 'snapshot_manager_linux_test.go')]
TEST_FILES += [('chengwang/internal/adapter/mihomo/lab_readback_test.go', 'chengwang/internal/adapter/mihomo')]
TEST_FILES += [('chengwang/internal/adapter/mihomo/lab_evidence_test.go', 'chengwang/internal/adapter/mihomo')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lab_authority_test.go', 'lab_expectation_test.go', 'lab_kernel_linux_test.go')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lab_bootstrap_linux_test.go', 'lab_bootstrap_test.go', 'lab_collector_linux_test.go', 'lab_collector_test.go', 'lab_local_route_test.go', 'lab_service_diagnostics_test.go', 'lab_service_test.go', 'lab_syntax_linux_test.go')]
TEST_FILES += [('chengwang/internal/api/mihomo_lab_test.go', 'chengwang/internal/api'),
    ('chengwang/internal/serverruntime/mihomo_lab_config_test.go', 'chengwang/internal/serverruntime')]
TEST_FILES += [('chengwang/internal/authz/policy_test.go', 'chengwang/internal/authz'), ('chengwang/internal/authz/image_trust_test.go', 'chengwang/internal/authz'), ('chengwang/internal/authz/image_trust_history_d8_test.go', 'chengwang/internal/authz'), ('chengwang/internal/authz/subscription_test.go', 'chengwang/internal/authz'), ('chengwang/internal/authz/lab_recovery_test.go', 'chengwang/internal/authz'), ('chengwang/internal/mihomodeploy/lab_quiescence_test.go', 'chengwang/internal/mihomodeploy'), ('chengwang/internal/mihomodeploy/lab_quiescence_linux_test.go', 'chengwang/internal/mihomodeploy'), ('chengwang/internal/mihomodeploy/lab_recovery_plan_test.go', 'chengwang/internal/mihomodeploy'), ('chengwang/internal/mihomodeploy/lifecycle_v3_test.go', 'chengwang/internal/mihomodeploy'), ('chengwang/internal/mihomodeploy/lifecycle_recovery_store_test.go', 'chengwang/internal/mihomodeploy'), ('chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go', 'chengwang/internal/mihomodeploy')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lab_recovery_authority_test.go', 'lab_recovery_start_test.go', 'lab_recovery_start_linux_test.go')]
TEST_FILES += [('chengwang/internal/mihomodeploy/lifecycle_trusted_clone_properties_test.go', 'chengwang/internal/mihomodeploy')]
TEST_FILES += [('chengwang/internal/mihomodeploy/lifecycle_recovery_started_linux_test.go', 'chengwang/internal/mihomodeploy')]
TEST_FILES += [('chengwang/internal/adapter/mihomo/lab_target_readback_test.go', 'chengwang/internal/adapter/mihomo')]
TEST_FILES += [('chengwang/internal/adapter/mihomo/lab_sample_times_test.go', 'chengwang/internal/adapter/mihomo')]
TEST_FILES += [('chengwang/internal/mihomodeploy/lab_recovery_collector_linux_test.go', 'chengwang/internal/mihomodeploy')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lab_recovery_marker_test.go', 'lab_recovery_marker_bounds_test.go')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lifecycle_recovery_verification_test.go', 'lifecycle_recovery_verified_bounds_test.go')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lifecycle_recovery_completion_test.go', 'lifecycle_completion_shape_diagnostic_test.go',
                 'lifecycle_v3_decode_scope_test.go',
                 'lifecycle_current_epoch_test.go',
                 'lab_current_epoch_runtime_test.go')]
TEST_FILES += [('chengwang/internal/api/mihomo_recovery_test.go', 'chengwang/internal/api')]
TEST_FILES += [('chengwang/internal/mihomodeploy/' + name, 'chengwang/internal/mihomodeploy')
    for name in ('lab_recovery_backend_test.go', 'lab_recovery_unstarted_cleanup_linux_test.go',
                 'lifecycle_recovery_reconcile_test.go')]
PACKAGES = {'chengwang/internal/adapter/mihomo', 'chengwang/internal/mihomodeploy', 'chengwang/internal/authn',
    'chengwang/internal/api', 'chengwang/internal/serverruntime', 'chengwang/internal/authz'}
INPUTS = {'ordinary.json': 64 << 20, 'race.json': 64 << 20, 'ordinary.stderr': 1 << 20,
    'race.stderr': 1 << 20, 'gofmt.patch': 1 << 20, 'gofmt.stderr': 1 << 20,
    'execution.json': 4096, 'sandbox.json': 4096, 'go-version.txt': 4096,
    'host-before.json': 4096, 'host-after.json': 4096}

def need(value):
    if not value: raise ValueError('Mihomo contract evidence rejected')

def sha(raw): return hashlib.sha256(raw).hexdigest()

def plain(path, missing_leaf=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts)
    for item in reversed((path, *path.parents)):
        if item == path and missing_leaf:
            try: item.lstat()
            except FileNotFoundError: continue
            need(False)
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    return path

def read(path, limit, empty=False):
    path = plain(path)
    before = path.lstat(); need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (0 if empty else 1) <= before.st_size <= limit)
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno()); raw = handle.read(limit + 1); after = os.fstat(handle.fileno())
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_nlink, s.st_mtime_ns)
    need(signature(before) == signature(opened) == signature(after) == signature(path.lstat()) and len(raw) == before.st_size)
    return raw

def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items: need(key not in value); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))

def source(repo, commit, path):
    result = subprocess.run(['git', '-C', str(repo), 'show', commit + ':' + path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    need(result.returncode == 0)
    raw = read(repo / path, 1 << 20); need(raw == result.stdout); return raw

def required_names(sources):
    result = {}
    for path, package in TEST_FILES:
        text = sources[path].decode('utf8')
        names = re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)\s*\{', text, re.M)
        need(names and len(names) == len(set(names)))
        combined = result.setdefault(package, [])
        need(not set(combined).intersection(names)); combined.extend(names)
    return result

def events(raw, required):
    starts, passes, packages, begun, states = {}, {}, set(), set(), {}
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20)
        event = decode(line); need(type(event) is dict and event.get('Package') in PACKAGES)
        action, package, test = event.get('Action'), event['Package'], event.get('Test')
        need(action in ('start', 'run', 'pause', 'cont', 'pass', 'output'))
        if 'Elapsed' in event: need(type(event['Elapsed']) in (int, float) and math.isfinite(event['Elapsed']) and event['Elapsed'] >= 0)
        if action == 'start':
            need(test is None and package not in begun); begun.add(package); continue
        need(package in begun and package not in packages)
        if test is not None:
            need(type(test) is str and 0 < len(test) <= 512)
            key = (package, test)
            if action == 'run':
                need(key not in states); starts[key] = 1; states[key] = 'run'
            elif action == 'pause': need(states.get(key) == 'run'); states[key] = 'pause'
            elif action == 'cont': need(states.get(key) == 'pause'); states[key] = 'run'
            elif action == 'pass':
                need(states.get(key) == 'run'); passes[key] = 1; states[key] = 'pass'
            else: need(action == 'output' and key in states)
        elif action == 'pass':
            need(all(state == 'pass' for key, state in states.items() if key[0] == package)); packages.add(package)
        else: need(action == 'output')
    need(begun == packages == PACKAGES and starts == passes and all(v == 1 for v in starts.values()))
    for package, names in required.items():
        for name in names: need(starts.get((package, name)) == passes.get((package, name)) == 1)
    return dict(allPassingSemanticTests=len(passes), mandatoryNewTopLevelTests=sum(map(len, required.values())), skips=0)

def verify(evidence, repo, commit):
    evidence, repo = plain(evidence), plain(repo)
    need(re.fullmatch('[a-f0-9]{40}', commit) is not None)
    sources = {p: source(repo, commit, p) for p in FILES}
    need(read(__file__, 1 << 20) == sources[PREFIX + 'check_contracts.py'])
    need(set(p.name for p in evidence.iterdir()) == set(INPUTS))
    raw = {name: read(evidence / name, limit, empty=True) for name, limit in INPUTS.items()}
    for name in ('ordinary.stderr', 'race.stderr', 'gofmt.patch', 'gofmt.stderr'): need(raw[name] == b'')
    execution = decode(raw['execution.json'])
    need(all(type(execution.get(key)) is int for key in ('formatExit', 'ordinaryExit', 'raceExit')))
    need(execution.get('realMihomoExecuted') is False and execution.get('production') is False)
    need(execution == dict(schema='chengwang.mihomo-contract-execution/v1', formatExit=0, ordinaryExit=0, raceExit=0, realMihomoExecuted=False, production=False))
    sandbox = decode(raw['sandbox.json'])
    need(type(sandbox) is dict and set(sandbox) == {'uid', 'gid', 'effectiveCaps', 'noNewPrivileges', 'networkNamespace', 'mountNamespace', 'pidNamespace', 'environmentKeys', 'sourceModuleSHA256', 'sourceAliasReadOnly', 'temporaryRootPrivate'})
    need(sandbox['uid'] == sandbox['gid'] == 10001 and type(sandbox['uid']) is type(sandbox['gid']) is int and sandbox['effectiveCaps'] == '0000000000000000' and sandbox['noNewPrivileges'] is True)
    need(sandbox['environmentKeys'] == sorted(['PATH', 'GOROOT', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE', 'GOPROXY', 'GOSUMDB', 'GOENV', 'GOTOOLCHAIN', 'GOFLAGS', 'CGO_ENABLED', 'LANG', 'LC_ALL', 'TZ']))
    need(sandbox['sourceModuleSHA256'] == sha(sources['chengwang/go.mod'])
         and sandbox['sourceAliasReadOnly'] is True and sandbox['temporaryRootPrivate'] is True)
    before, after = decode(raw['host-before.json']), decode(raw['host-after.json'])
    need(type(before) is dict and set(before) == {'networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256'} and before == after)
    need(type(before['resolvSHA256']) is str and re.fullmatch('[a-f0-9]{64}', before['resolvSHA256']))
    for name, kind in [('networkNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid')]:
        need(type(before[name]) is str and re.fullmatch(kind + r':\[[0-9]{1,20}\]', before[name]))
        need(type(sandbox[name]) is str and re.fullmatch(kind + r':\[[0-9]{1,20}\]', sandbox[name]) and sandbox[name] != before[name])
    need(raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
    names = required_names(sources)
    suites = {name: events(raw[name], names) for name in ('ordinary.json', 'race.json')}
    need(all(read(evidence / name, INPUTS[name], empty=True) == value for name, value in raw.items()))
    need(set(p.name for p in evidence.iterdir()) == set(INPUTS))
    need(all(read(repo / path, 1 << 20) == value for path, value in sources.items()))
    return dict(schema='chengwang.mihomo-contract-verification/v1', sourceCommit=commit, outcome='PASS', suites=suites,
        sourceSHA256={p: sha(raw) for p, raw in sources.items()}, inputSHA256={p: sha(value) for p, value in raw.items()},
        realMihomoExecuted=False, production=False, scope='SOURCE_CONTRACTS_ONLY_NOT_LIFECYCLE_OR_DEPLOYMENT_ACCEPTANCE')

def main():
    p = argparse.ArgumentParser(); p.add_argument('--evidence', type=Path, required=True); p.add_argument('--repo', type=Path, required=True); p.add_argument('--source-commit', required=True); p.add_argument('--report', type=Path, required=True); a = p.parse_args()
    a.evidence, a.repo, a.report = plain(a.evidence), plain(a.repo), plain(a.report, True)
    need(a.report.parent.is_dir() and not a.report.is_relative_to(a.evidence) and not a.report.is_relative_to(a.repo))
    value = verify(a.evidence, a.repo, a.source_commit)
    # This is a Linux CI writer. Relative-dirfd creation never follows a replaced
    # report leaf or re-resolves a parent after validation.
    need(os.name == 'posix' and os.open in os.supports_dir_fd)
    directory = os.open(a.report.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(a.report.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as h: h.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()); h.flush(); os.fsync(h.fileno())
        os.fsync(directory)
    finally: os.close(directory)
    print('MIHOMO_CONTRACTS=PASS real_kernel_executed=false production=false')

if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('MIHOMO_CONTRACTS=REJECTED raw_input_suppressed=true') from None
