"""Strict reader for fixed-source baseline/candidate measurement."""
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

ORIGINAL_BASELINE_COMMIT = 'fdcdcea3f469670ed0edc08d180f991e150a3a66'
BASELINE_COMMIT = 'a46f1b93ddec3b600fbe46e906795b84c363f848'
CANDIDATE_COMMIT = 'b5b5fa96cadbf35ae833c618555ab82e5d70429b'
SOURCE_COMMITS = {'A': BASELINE_COMMIT, 'B': CANDIDATE_COMMIT}
GO_DIFF = (
    ('chengwang/internal/mihomodeploy/lifecycle_recovery_store.go',
     'e2280919851bd8833395e90f77cf995459f64623', '6db06420f70135fbdda4cf0e3a38948c56b04918'),
)
TEST_FIXTURE_PATH = 'chengwang/internal/mihomodeploy/lifecycle_trusted_clone_properties_test.go'
TEST_FIXTURE_BLOB = 'bb3855e52ce3ef69e607d990793e76b68e02b4ea'
TEST_FIXTURE_SHA256 = '02495da477fa2a77ecdcbe8de649724a2d2e8dfba9b2293f4c535789f1060756'
TRACKED_GO_FILES = 569
TRACKED_TEST_GO_FILES = 233
PACKAGES = ('chengwang/internal/adapter/mihomo', 'chengwang/internal/mihomodeploy',
            'chengwang/internal/authn', 'chengwang/internal/api',
            'chengwang/internal/serverruntime', 'chengwang/internal/authz')
PACKAGE_SET = set(PACKAGES)
TOP = 'TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop'
ORIGINAL_NAMES = {'ordinary.json', 'race.json', 'ordinary.stderr', 'race.stderr',
                  'gofmt.patch', 'gofmt.stderr', 'execution.json', 'sandbox.json',
                  'go-version.txt', 'host-before.json', 'host-after.json'}
META_NAMES = {'pair-context.json', 'source-before.json', 'source-after.json',
              'controller-before.json', 'controller-after.json',
              'parent-resource-before.json', 'parent-resource-after.json',
              'inner-source.json', 'inner-binding.json',
              'inner-resource-before.json', 'inner-resource-after.json',
              'supervision.jsonl', 'runner.json', 'supervisor.stdout',
              'supervisor.stderr', 'originals-fsync.json', 'script-binding.json', 'leg-receipt.json'}
EXPECTED_NAMES = ORIGINAL_NAMES | META_NAMES
PACKAGES_CLI = ['./internal/adapter/mihomo', './internal/mihomodeploy', './internal/authn',
                './internal/api', './internal/serverruntime', './internal/authz']
ORDINARY_ARGS = ['test', '-json', '-count=1', '-timeout=180s', *PACKAGES_CLI]
RACE_ARGS = ['test', '-race', '-json', '-count=1', '-timeout=180s', *PACKAGES_CLI]
RESOURCE_SCOPES = {
    'cpuCount': 'CAPTURE_PROCESS_OS_LOGICAL_CPU_COUNT',
    'affinityCPUs': 'CAPTURE_PROCESS_AFFINITY_NOT_MEASURED_GO_PID',
    'procStatCPU': 'KERNEL_EXPOSED_AGGREGATE_CPU_TICKS_NOT_PROCESS',
    'cgroupCPUMax': 'CURRENT_CGROUP_FAIR_BANDWIDTH_NOT_EFFECTIVE_ANCESTOR_LIMIT',
    'cgroupCPUStat': 'CURRENT_CGROUP_USAGE_AND_OWN_BANDWIDTH_COUNTERS_NOT_PER_TEST',
}
CPU_STAT_FIELDS = ('usage_usec', 'user_usec', 'system_usec', 'nr_periods',
                   'nr_throttled', 'throttled_usec')
ENVIRONMENT_KEYS = sorted(['PATH', 'GOROOT', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE',
                           'GOPROXY', 'GOSUMDB', 'GOENV', 'GOTOOLCHAIN', 'GOFLAGS',
                           'CGO_ENABLED', 'LANG', 'LC_ALL', 'TZ'])


def need(value):
    if not value:
        raise ValueError('source pair evidence rejected')


def exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def integer(value, low=0, high=(1 << 63) - 1):
    return type(value) is int and low <= value <= high


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))


def absolute(path):
    path = Path(os.path.abspath(path))
    need(path.is_absolute() and '..' not in path.parts)
    for part in (*reversed(path.parents), path):
        need(not part.is_symlink())
    return path


def output_path(path):
    path = Path(os.path.abspath(path))
    need(path.is_absolute() and '..' not in path.parts and path.parent.is_dir())
    for part in reversed(path.parents):
        need(not part.is_symlink())
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    need(False)


def read(path, limit, empty=True):
    path = absolute(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         (0 if empty else 1) <= before.st_size <= limit)
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                              value.st_mode, value.st_nlink)
    need(identity(before) == identity(opened) == identity(after) == identity(path.lstat()) and
         len(raw) == before.st_size)
    return raw


def write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, 'wb') as stream:
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60, check=False)
    need(result.returncode == 0)
    return result.stdout


def source_commit(leg):
    need(leg in SOURCE_COMMITS)
    return SOURCE_COMMITS[leg]


def source_heads(baseline_head, candidate_head, baseline_parents):
    need(baseline_head == BASELINE_COMMIT and candidate_head == CANDIDATE_COMMIT and
         baseline_parents == [ORIGINAL_BASELINE_COMMIT])


def normal_script_contract(raw):
    ordinary = (b'"${common[@]}" "$goroot/bin/go" test -json -count=1 -timeout=180s '
                b'./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api '
                b'./internal/serverruntime ./internal/authz > "$out/ordinary.json" 2> "$out/ordinary.stderr"')
    race = (b'"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s '
            b'./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api '
            b'./internal/serverruntime ./internal/authz > "$out/race.json" 2> "$out/race.stderr"')
    need(raw.count(ordinary) == raw.count(race) == 1 and
         b' test -p=' not in raw and b'GOMAXPROCS' not in raw)
    return sha(raw)


def go_diff_contract(rows):
    need(type(rows) is list and rows == [
        {'path': path, 'oldBlobSHA1': old, 'newBlobSHA1': new,
         'oldMode': '100644', 'newMode': '100644', 'status': 'M'}
        for path, old, new in GO_DIFF])
    return rows


def test_go_contract(baseline, candidate):
    baseline_tests = {path: row for path, row in baseline.items() if path.endswith('_test.go')}
    candidate_tests = {path: row for path, row in candidate.items() if path.endswith('_test.go')}
    need(baseline_tests == candidate_tests and TEST_FIXTURE_PATH in baseline_tests and
         baseline_tests[TEST_FIXTURE_PATH] == {'mode': '100644', 'blobSHA1': TEST_FIXTURE_BLOB})
    return {'trackedTestGoFiles': len(baseline_tests),
            'testGoTreeSHA256': sha(encoded(baseline_tests)),
            'fixturePath': TEST_FIXTURE_PATH, 'fixtureGitBlobSHA1': TEST_FIXTURE_BLOB,
            'allTrackedTestGoBytesEqual': True}


def tracked_tree(repo, commit):
    raw = git(repo, 'ls-tree', '-r', '--full-tree', commit)
    pattern = re.compile(rb'^([0-7]{6}) blob ([a-f0-9]{40})\t([^\r\n]+)$')
    rows = {}
    for line in raw.splitlines():
        match = pattern.fullmatch(line)
        need(match is not None)
        mode, blob, path = match.groups()
        name = path.decode('utf8')
        need(name not in rows)
        rows[name] = {'mode': mode.decode(), 'blobSHA1': blob.decode()}
    need(rows)
    return rows


def raw_commit_parents(repo, commit):
    raw = git(repo, 'cat-file', 'commit', commit)
    headers, separator, _ = raw.partition(b'\n\n')
    need(separator == b'\n\n')
    parents = []
    for line in headers.splitlines():
        if line.startswith(b'parent '):
            parent = line.removeprefix(b'parent ').decode()
            need(re.fullmatch('[a-f0-9]{40}', parent) is not None)
            parents.append(parent)
    return parents


def go_tree(repo, commit):
    return {path: row for path, row in tracked_tree(repo, commit).items()
            if path.endswith('.go')}


def non_go_diff_contract(paths):
    need(type(paths) is list and paths and paths == sorted(set(paths)) and
         all(path.startswith('chengwang/docs/') and not path.endswith('.go') for path in paths))
    return paths


def compare_go_trees(baseline, candidate):
    need(set(baseline) == set(candidate))
    changed = []
    for path in sorted(baseline):
        left, right = baseline[path], candidate[path]
        if left != right:
            changed.append({'path': path, 'oldBlobSHA1': left['blobSHA1'],
                            'newBlobSHA1': right['blobSHA1'], 'oldMode': left['mode'],
                            'newMode': right['mode'], 'status': 'M'})
    return go_diff_contract(changed)


def source_pair_contract(baseline, candidate):
    baseline, candidate = absolute(baseline), absolute(candidate)
    need(not os.path.samefile(baseline, candidate))
    baseline_head = git(baseline, 'rev-parse', 'HEAD').strip().decode()
    candidate_head = git(candidate, 'rev-parse', 'HEAD').strip().decode()
    # Read the raw commit object: shallow checkouts may intentionally hide the
    # parent from revision traversal, but cannot alter the signed commit header.
    baseline_parents = raw_commit_parents(baseline, BASELINE_COMMIT)
    source_heads(baseline_head, candidate_head, baseline_parents)
    need(git(baseline, 'status', '--porcelain', '--untracked-files=all') == b'' and
         git(candidate, 'status', '--porcelain', '--untracked-files=all') == b'')
    baseline_tree = go_tree(baseline, BASELINE_COMMIT)
    candidate_tree = go_tree(candidate, CANDIDATE_COMMIT)
    need(len(baseline_tree) == len(candidate_tree) == TRACKED_GO_FILES)
    test_contract = test_go_contract(baseline_tree, candidate_tree)
    need(test_contract['trackedTestGoFiles'] == TRACKED_TEST_GO_FILES)
    rows = compare_go_trees(baseline_tree, candidate_tree)
    baseline_all = tracked_tree(baseline, BASELINE_COMMIT)
    candidate_all = tracked_tree(candidate, CANDIDATE_COMMIT)
    non_go_changed = non_go_diff_contract(sorted(path for path in set(baseline_all) | set(candidate_all)
        if not path.endswith('.go') and baseline_all.get(path) != candidate_all.get(path)))
    script_a = read(baseline / 'chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh', 1 << 20)
    script_b = read(candidate / 'chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh', 1 << 20)
    script_sha = normal_script_contract(script_a)
    need(script_a == script_b and script_sha == normal_script_contract(script_b))
    module_a = read(baseline / 'chengwang/go.mod', 1 << 20)
    module_b = read(candidate / 'chengwang/go.mod', 1 << 20)
    need(module_a == module_b)
    fixture_a = read(baseline / TEST_FIXTURE_PATH, 2 << 20)
    fixture_b = read(candidate / TEST_FIXTURE_PATH, 2 << 20)
    need(fixture_a == fixture_b and sha(fixture_a) == TEST_FIXTURE_SHA256)
    return {'schema': 'chengwang.source-pair-source-contract/v2',
            'originalBaselineCommit': ORIGINAL_BASELINE_COMMIT,
            'baselineCommit': BASELINE_COMMIT, 'candidateCommit': CANDIDATE_COMMIT,
            'baselineParents': baseline_parents, 'baselineIsSingleParentTestEqualDerivative': True,
            'sourceCheckoutsDistinct': True,
            'normalScriptSHA256': script_sha, 'moduleSHA256': sha(module_a),
            'goDiff': rows, 'trackedGoFiles': len(baseline_tree),
            'baselineGoTreeSHA256': sha(encoded(baseline_tree)),
            'candidateGoTreeSHA256': sha(encoded(candidate_tree)),
            'allOtherTrackedGoBytesEqual': True,
            'testGoContract': test_contract, 'testFixtureSHA256': TEST_FIXTURE_SHA256,
            'nonGoChangedPaths': non_go_changed,
            'nonGoDifferencesAllDocumentationOnly': True,
            'normalCommandsAndPFlagsEqual': True, 'runtimeGOMAXPROCSModified': False,
            'onlyProductionGoDifferenceIsStoreCopyImplementation': True,
            'sourceChangeMayBePerformanceCause': True, 'performanceCauseProven': False}


def leg_script_contract(source, leg):
    source = absolute(source)
    commit = source_commit(leg)
    need(git(source, 'rev-parse', 'HEAD').strip().decode() == commit)
    need(git(source, 'status', '--porcelain', '--untracked-files=all') == b'')
    raw = read(source / 'chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh', 1 << 20)
    return {'leg': leg, 'sourceCommit': commit, 'normalSHA256': normal_script_contract(raw)}


def host(raw):
    value = decode(raw)
    need(type(value) is dict and set(value) == {'networkNamespace', 'mountNamespace',
                                                'pidNamespace', 'resolvSHA256'})
    need(re.fullmatch('[a-f0-9]{64}', value['resolvSHA256']) is not None)
    for key, kind in (('networkNamespace', 'net'), ('mountNamespace', 'mnt'),
                      ('pidNamespace', 'pid')):
        need(re.fullmatch(kind + r':\[[0-9]{1,20}\]', value[key]) is not None)
    return value


def resource(raw, scope, phase):
    value = decode(raw)
    need(exact(value, ('schema', 'diagnosticMode', 'scope', 'startedMonotonicNs',
                       'finishedMonotonicNs', 'observations', 'captureScope', 'phase')))
    need(value['schema'] == 'chengwang.source-pair-resource-observation/v1' and
         value['diagnosticMode'] == 'TEST_EQUAL_BASELINE_CANDIDATE_SAME_NORMAL_FLAGS' and
         value['scope'] == 'CAPTURE_PROCESS_AND_KERNEL_CGROUP_AGGREGATES_NOT_PER_TEST_NOT_ATOMIC' and
         value['captureScope'] == scope and value['phase'] == phase)
    need(integer(value['startedMonotonicNs'], 1) and
         integer(value['finishedMonotonicNs'], value['startedMonotonicNs']))
    need(exact(value['observations'], RESOURCE_SCOPES))
    unavailable = ('CGROUP_V2_UNAVAILABLE', 'CGROUP_V2_NOT_MAPPED',
                   'CGROUP_READ_UNAVAILABLE', 'CGROUP_FILE_UNAVAILABLE')
    for name, row in value['observations'].items():
        need(exact(row, ('scope', 'value', 'reason')) and row['scope'] == RESOURCE_SCOPES[name])
        data, reason = row['value'], row['reason']
        if data is None:
            expected = ('VALUE_UNAVAILABLE',) if name in ('cpuCount', 'affinityCPUs') else \
                ('KERNEL_VALUE_UNAVAILABLE',) if name == 'procStatCPU' else unavailable
            need(reason in expected)
        elif name == 'cpuCount':
            need(reason == 'NONE' and integer(data, 1, 1 << 20))
        elif name == 'affinityCPUs':
            need(reason == 'NONE' and type(data) is list and 1 <= len(data) <= 4096 and
                 all(integer(item, 0, 1 << 20) for item in data) and data == sorted(set(data)))
        elif name == 'procStatCPU':
            need(reason == 'NONE' and exact(data, ('user', 'system', 'idle', 'iowait', 'steal')) and
                 all(integer(item) for item in data.values()))
        elif name == 'cgroupCPUMax':
            need(reason == 'NONE' and exact(data, ('quotaMicros', 'periodMicros', 'unlimited')) and
                 type(data['unlimited']) is bool and integer(data['periodMicros'], 1))
            need((data['quotaMicros'] is None) == data['unlimited'] and
                 (data['quotaMicros'] is None or integer(data['quotaMicros'], 1)))
        else:
            need(exact(data, CPU_STAT_FIELDS) and any(item is not None for item in data.values()) and
                 all(item is None or integer(item) for item in data.values()))
            need(reason == ('NONE' if all(item is not None for item in data.values()) else
                            'PARTIAL_FIELDS'))
    return value


def sandbox_contract(value, host_value, module_sha):
    need(exact(value, ('uid', 'gid', 'effectiveCaps', 'noNewPrivileges', 'networkNamespace',
                       'mountNamespace', 'pidNamespace', 'environmentKeys', 'sourceModuleSHA256',
                       'sourceAliasReadOnly', 'temporaryRootPrivate')))
    need(type(value['uid']) is type(value['gid']) is int and value['uid'] == value['gid'] == 10001)
    need(value['effectiveCaps'] == '0000000000000000' and value['noNewPrivileges'] is True and
         value['environmentKeys'] == ENVIRONMENT_KEYS and
         value['sourceModuleSHA256'] == module_sha and value['sourceAliasReadOnly'] is True and
         value['temporaryRootPrivate'] is True)
    for key, kind in (('networkNamespace', 'net'), ('mountNamespace', 'mnt'),
                      ('pidNamespace', 'pid')):
        need(re.fullmatch(kind + r':\[[0-9]{1,20}\]', value[key]) is not None and
             value[key] != host_value[key])
    return value


def raw_go_binding(snapshot):
    rows = snapshot['files']
    go_rows = [{'path': row['path'], 'bytes': row['bytes'], 'sha256': row['sha256'],
                'gitBlobSHA1': row['gitBlobSHA1']} for row in rows if row['path'].endswith('.go')]
    need(go_rows and all(row['path'].startswith('chengwang/') for row in go_rows))
    return {'trackedGoFiles': len(go_rows), 'aggregateSHA256': sha(encoded(go_rows)),
            'allGoBytesFromExactMeasurementSource': True}


def raw_go_pair_binding(baseline_snapshot, candidate_snapshot):
    def rows(snapshot):
        return {row['path']: row for row in snapshot['files'] if row['path'].endswith('.go')}
    baseline, candidate = rows(baseline_snapshot), rows(candidate_snapshot)
    need(set(baseline) == set(candidate))
    baseline_tests = {path: row for path, row in baseline.items() if path.endswith('_test.go')}
    candidate_tests = {path: row for path, row in candidate.items() if path.endswith('_test.go')}
    need(baseline_tests == candidate_tests)
    changed = []
    for path in sorted(baseline):
        left, right = baseline[path], candidate[path]
        if left != right:
            changed.append((path, left['gitBlobSHA1'], right['gitBlobSHA1']))
    need(changed == list(GO_DIFF))
    return {'baseline': raw_go_binding(baseline_snapshot),
            'candidate': raw_go_binding(candidate_snapshot),
            'changedPaths': [path for path, _, _ in changed],
            'allOtherTrackedGoBytesEqual': True,
            'allSnapshotTestGoBytesEqual': True}


def snapshot_sha(snapshot, path):
    matches = [row['sha256'] for row in snapshot['files'] if row['path'] == path]
    need(len(matches) == 1 and re.fullmatch('[a-f0-9]{64}', matches[0]) is not None)
    return matches[0]


def event_summary(raw, required):
    packages = {}
    required_state = {(package, name): 'NOT_STARTED'
                      for package, names in required.items() for name in names}
    test_states = {}
    timeout = False
    data_race = False
    capacity = {'state': 'NOT_STARTED', 'startedAt': None, 'finishedAt': None, 'elapsed': None}
    events = 0
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20)
        row = decode(line + b'\n')
        need(type(row) is dict and set(row) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'})
        package, action, test = row.get('Package'), row.get('Action'), row.get('Test')
        need(package in PACKAGE_SET and action in ('start', 'run', 'pause', 'cont',
                                                   'pass', 'fail', 'skip', 'output'))
        datetime.datetime.fromisoformat(row['Time'].replace('Z', '+00:00'))
        if 'Elapsed' in row:
            need(type(row['Elapsed']) in (int, float) and math.isfinite(row['Elapsed']) and
                 row['Elapsed'] >= 0)
        events += 1
        if test is None and action == 'start':
            need(package not in packages)
            packages[package] = {'startedAt': row['Time'], 'finishedAt': None,
                                 'terminal': 'UNFINISHED', 'elapsed': None}
        elif test is None and action in ('pass', 'fail', 'skip'):
            need(package in packages and packages[package]['finishedAt'] is None)
            packages[package].update(finishedAt=row['Time'], terminal=action,
                                     elapsed=row.get('Elapsed'))
        elif test is not None:
            key = (package, test)
            if action == 'run':
                test_states[key] = 'run'
                if key in required_state:
                    required_state[key] = 'run'
                if package == PACKAGES[1] and test == TOP:
                    capacity.update(state='run', startedAt=row['Time'])
            elif action in ('pass', 'fail', 'skip'):
                test_states[key] = action
                if key in required_state:
                    required_state[key] = action
                if package == PACKAGES[1] and test == TOP:
                    capacity.update(state=action, finishedAt=row['Time'], elapsed=row.get('Elapsed'))
        if action == 'output':
            text = row.get('Output', '')
            need(type(text) is str)
            timeout = timeout or 'panic: test timed out after 3m0s' in text
            data_race = data_race or 'WARNING: DATA RACE' in text
    required_counts = {state: list(required_state.values()).count(state)
                       for state in ('pass', 'fail', 'skip', 'run', 'NOT_STARTED')}
    last_other = None
    mihomo_start = packages.get(PACKAGES[1], {}).get('startedAt')
    for name, value in packages.items():
        if name != PACKAGES[1] and value['finishedAt'] is not None:
            instant = datetime.datetime.fromisoformat(value['finishedAt'].replace('Z', '+00:00'))
            last_other = instant if last_other is None or instant > last_other else last_other
    overlap = None
    if mihomo_start is not None and last_other is not None:
        overlap = (last_other - datetime.datetime.fromisoformat(mihomo_start.replace('Z', '+00:00'))).total_seconds()
    return {'events': events, 'packages': packages, 'capacity': capacity,
            'requiredTopLevelStates': required_counts, 'timeoutObserved': timeout,
            'dataRaceWarningObserved': data_race,
            'lastOtherPackageEndOffsetFromMihomoStartSeconds': overlap}


def supervision(raw, runner):
    rows = [decode(line + b'\n') for line in raw.splitlines()]
    need(len(rows) == 5 and [row['sequence'] for row in rows] == [1, 2, 3, 4, 5])
    need([row['event'] for row in rows] ==
         ['START_INTENT', 'STARTED_GATED', 'PIDFD_ACQUIRED', 'GATE_RELEASED', 'WAIT_RETURNED'])
    previous = 0
    for row in rows:
        need(set(row) == {'schema', 'sequence', 'event', 'pid', 'pidfdAcquired', 'exitCode',
                          'monotonicNs', 'commandClass'} and
             row['schema'] == 'chengwang.source-pair-supervision-event/v1' and
             row['commandClass'] == 'ISOLATED_LEG' and type(row['monotonicNs']) is int and
             row['monotonicNs'] >= previous)
        previous = row['monotonicNs']
    intent, started, acquired, released, returned = rows
    need(intent['pid'] is None and intent['pidfdAcquired'] is None and intent['exitCode'] is None)
    pid = started['pid']
    need(integer(pid, 2, (1 << 31) - 1) and started['pidfdAcquired'] is False and
         started['exitCode'] is None)
    for row in (acquired, released, returned):
        need(row['pid'] == pid and row['pidfdAcquired'] is True)
    need(acquired['exitCode'] is released['exitCode'] is None and
         type(returned['exitCode']) is int and returned['exitCode'] == runner['processExit'])
    need(exact(runner, ('processExit', 'outerTimedOut', 'pidfdAcquired', 'termSent', 'killSent',
                        'captureSupervisorComplete', 'failureClass', 'schema', 'leg',
                        'sourceCommit', 'controllerCommit', 'outerTimeoutSeconds',
                        'termGraceSeconds', 'measurementOnly', 'production',
                        'finishedMonotonicNs', 'startedMonotonicNs')))
    need(type(runner['processExit']) is int and runner['pidfdAcquired'] is True and
         runner['outerTimedOut'] is runner['termSent'] is runner['killSent'] is False and
         runner['captureSupervisorComplete'] is True and runner['failureClass'] == 'NONE' and
         integer(runner['startedMonotonicNs'], 1) and
         integer(runner['finishedMonotonicNs'], runner['startedMonotonicNs']) and
         rows[0]['monotonicNs'] == runner['startedMonotonicNs'] and
         rows[-1]['monotonicNs'] <= runner['finishedMonotonicNs'])
    return rows


def validate_leg(directory, leg, source, controller, source_expected, controller_expected,
                  required, pair_contract, order, controller_commit):
    directory = absolute(directory)
    need(set(path.name for path in directory.iterdir()) == EXPECTED_NAMES)
    raw = {name: read(directory / name, 160 << 20 if name.startswith('source-') else
                      64 << 20 if name in ('ordinary.json', 'race.json') else 4 << 20)
           for name in EXPECTED_NAMES}
    context = decode(raw['pair-context.json'])
    need(context == {'schema': 'chengwang.source-pair-context/v1', 'measurementOnly': True,
        'production': False, 'sourceCommit': source_commit(leg),
        'sourceRole': 'TEST_EQUAL_BASELINE' if leg == 'A' else 'CANDIDATE',
        'controllerCommit': controller_commit,
        'runID': context['runID'], 'runAttempt': context['runAttempt'], 'order': order,
        'position': order.index(leg) + 1, 'leg': leg, 'job': context['job'],
        'pairID': f"{context['runID']}:{context['runAttempt']}:{order}",
        'executionClass': 'EXACT_SOURCE_NORMAL', 'sameRunnerSameLoadProven': False,
        'candidateMayReplaceBaselineAcceptance': False, 'performanceCauseProven': False})
    need(type(context['runID']) is type(context['runAttempt']) is int and
         context['runID'] > 0 and context['runAttempt'] > 0 and
         re.fullmatch('[A-Za-z0-9:._-]{1,128}', context['job']) is not None)
    source_before, source_after = decode(raw['source-before.json']), decode(raw['source-after.json'])
    need(source_before == source_after == source_expected)
    need(decode(raw['inner-source.json']) == source_expected)
    controller_before = decode(raw['controller-before.json'])
    controller_after = decode(raw['controller-after.json'])
    need(controller_before == controller_after == controller_expected)
    binding = decode(raw['script-binding.json'])
    need(exact(binding, ('schema', 'sourceCommit', 'normalSHA256', 'ordinaryCommandExact',
                         'raceCommandExact', 'racePFlagExplicit', 'runtimeGOMAXPROCSModified',
                         'packages', 'goTestTimeoutSeconds', 'historyEntries', 'recordBytes')) and
         binding['schema'] == 'chengwang.source-pair-script-binding/v1' and
         binding['sourceCommit'] == source_commit(leg) and
         binding['normalSHA256'] == pair_contract['normalScriptSHA256'] and
         binding['ordinaryCommandExact'] is binding['raceCommandExact'] is True and
         binding['racePFlagExplicit'] is False and
         binding['runtimeGOMAXPROCSModified'] is False and
         binding['goTestTimeoutSeconds'] == 180 and binding['historyEntries'] == 256 and
         binding['recordBytes'] == 2 << 20 and binding['packages'] == PACKAGES_CLI)
    inner_binding = decode(raw['inner-binding.json'])
    need(inner_binding == {'schema': 'chengwang.source-pair-inner-binding/v1',
        'sourceCommit': source_commit(leg), 'controllerCommit': controller_commit, 'leg': leg,
        'sourceReadOnly': True, 'controllerReadOnly': True, 'goRootReadOnly': True,
        'sourceAndControllerDistinct': True,
        'executedScriptClass': 'EXACT_SOURCE_NORMAL'})
    before_host, after_host = host(raw['host-before.json']), host(raw['host-after.json'])
    need(before_host == after_host)
    parent_before = resource(raw['parent-resource-before.json'],
        'PARENT_CONTROLLER_PROCESS_AND_KERNEL_AGGREGATES', 'BEFORE')
    parent_after = resource(raw['parent-resource-after.json'],
        'PARENT_CONTROLLER_PROCESS_AND_KERNEL_AGGREGATES', 'AFTER')
    inner_before = resource(raw['inner-resource-before.json'],
        'ISOLATED_NAMESPACE_WRAPPER_PROCESS_AND_KERNEL_AGGREGATES_NOT_GO_PID', 'BEFORE')
    inner_after = resource(raw['inner-resource-after.json'],
        'ISOLATED_NAMESPACE_WRAPPER_PROCESS_AND_KERNEL_AGGREGATES_NOT_GO_PID', 'AFTER')
    runner = decode(raw['runner.json'])
    need(runner['schema'] == 'chengwang.source-pair-runner/v1' and runner['leg'] == leg and
         runner['sourceCommit'] == source_commit(leg) and
         runner['controllerCommit'] == controller_commit and
         runner['pidfdAcquired'] is runner['captureSupervisorComplete'] is True and
         runner['outerTimeoutSeconds'] == 420 and runner['termGraceSeconds'] == 5 and
         runner['measurementOnly'] is True and runner['production'] is False and
         runner['failureClass'] == 'NONE' and runner['outerTimedOut'] is False)
    supervision(raw['supervision.jsonl'], runner)
    receipt = decode(raw['leg-receipt.json'])
    need(exact(receipt, ('schema', 'leg', 'sourceCommit', 'controllerCommit',
                         'measurementOnly', 'production', 'captureCandidateComplete',
                         'superviseExit', 'copiedControlFiles', 'goAcceptanceEvaluated',
                         'candidateMayReplaceBaselineAcceptance', 'sameRunnerSameLoadProven')) and
         receipt['schema'] == 'chengwang.source-pair-leg-receipt/v1' and receipt['leg'] == leg and
         receipt['sourceCommit'] == source_commit(leg) and
         receipt['controllerCommit'] == controller_commit and
         receipt['measurementOnly'] is True and receipt['production'] is False and
         receipt['captureCandidateComplete'] is True and receipt['superviseExit'] == 0 and
         receipt['goAcceptanceEvaluated'] is False and
         receipt['candidateMayReplaceBaselineAcceptance'] is False and
         receipt['sameRunnerSameLoadProven'] is False)
    execution = decode(raw['execution.json'])
    need(set(execution) == {'schema', 'formatExit', 'ordinaryExit', 'raceExit',
                            'realMihomoExecuted', 'production'} and
         execution['schema'] == 'chengwang.mihomo-contract-execution/v1' and
         all(type(execution[key]) is int for key in ('formatExit', 'ordinaryExit', 'raceExit')) and
         execution['realMihomoExecuted'] is execution['production'] is False)
    fsync_receipt = decode(raw['originals-fsync.json'])
    fsync_names = ['host-before.json', 'ordinary.json', 'race.json', 'ordinary.stderr', 'race.stderr',
                   'gofmt.patch', 'gofmt.stderr', 'execution.json', 'sandbox.json', 'go-version.txt']
    need(exact(fsync_receipt, ('schema', 'sourceCommit', 'files',
                               'outputDirectoryFsyncSucceeded')) and
         fsync_receipt['schema'] == 'chengwang.source-pair-originals-fsync/v1' and
         fsync_receipt['sourceCommit'] == source_commit(leg) and
         fsync_receipt['outputDirectoryFsyncSucceeded'] is True and
         [row['name'] for row in fsync_receipt['files']] == fsync_names)
    for row in fsync_receipt['files']:
        need(row == {'name': row['name'], 'bytes': len(raw[row['name']]),
                     'sha256': sha(raw[row['name']]), 'fsyncSucceeded': True})
    all_exit_zero = all(execution[key] == 0 for key in ('formatExit', 'ordinaryExit', 'raceExit'))
    need((runner['processExit'] == 0) == all_exit_zero)
    sandbox = sandbox_contract(decode(raw['sandbox.json']), before_host,
                               snapshot_sha(source_expected, 'chengwang/go.mod'))
    need('GOMAXPROCS' not in sandbox['environmentKeys'])
    need(raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
    need(raw['gofmt.stderr'] == b'' and (execution['formatExit'] != 0 or raw['gofmt.patch'] == b''))
    ordinary_shape = event_summary(raw['ordinary.json'], required)
    race_shape = event_summary(raw['race.json'], required)
    normal = load(source / 'chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py',
                  'source_pair_normal_checker_' + leg)
    ordinary_accepted = False
    race_accepted = False
    if execution['ordinaryExit'] == 0 and raw['ordinary.stderr'] == b'':
        normal.events(raw['ordinary.json'], required)
        ordinary_accepted = True
    if execution['raceExit'] == 0 and raw['race.stderr'] == b'':
        normal.events(raw['race.json'], required)
        race_accepted = True
    format_accepted = execution['formatExit'] == 0 and raw['gofmt.patch'] == raw['gofmt.stderr'] == b''
    go_accepted = format_accepted and ordinary_accepted and race_accepted
    return {'context': context, 'captureVerified': True, 'goAccepted': go_accepted,
            'formatAccepted': format_accepted, 'ordinaryAccepted': ordinary_accepted,
            'raceAccepted': race_accepted, 'execution': execution,
            'raceArgs': RACE_ARGS,
            'ordinaryArgs': ORDINARY_ARGS, 'runtimeGOMAXPROCSModified': False,
            'ordinary': ordinary_shape, 'race': race_shape,
            'parentResources': {'before': parent_before, 'after': parent_after},
            'innerResources': {'before': inner_before, 'after': inner_after},
            'hostNamespacesUnchanged': True,
            'inputSHA256': {name: sha(value) for name, value in raw.items()}}


def required_contract(source, leg):
    normal = load(source / 'chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py',
                  'source_pair_required_names_' + leg)
    commit = source_commit(leg)
    sources = {path: normal.source(source, commit, path) for path in normal.FILES}
    required = normal.required_names(sources)
    names = sorted(package + '::' + name for package, tests in required.items() for name in tests)
    need(len(names) == 688 and sha(('\n'.join(names)).encode()) ==
         'b0a464294a9dcaf7bea46ea29c0e7bc4937acc63b16df05387d3652efbbcb280')
    return required


def verify(baseline_source, candidate_source, controller, controller_commit, order, a_dir, b_dir):
    baseline_source, candidate_source, controller = map(
        absolute, (baseline_source, candidate_source, controller))
    need(order in ('AB', 'BA') and re.fullmatch('[a-f0-9]{40}', controller_commit) is not None)
    pair_contract = source_pair_contract(baseline_source, candidate_source)
    producer_a = load(baseline_source / 'chengwang/deploy/mihomo-capacity-profile/check_profile.py',
                      'source_pair_baseline_snapshot_checker')
    producer_b = load(candidate_source / 'chengwang/deploy/mihomo-capacity-profile/check_profile.py',
                      'source_pair_candidate_snapshot_checker')
    source_a = producer_a.source_snapshot(baseline_source, BASELINE_COMMIT)
    source_b = producer_b.source_snapshot(candidate_source, CANDIDATE_COMMIT)
    controller_module = load(controller / 'chengwang/deploy/mihomo-source-pair/pair_controller.py',
                             'source_pair_controller_binding')
    controller_expected = controller_module.controller_snapshot(controller, controller_commit)
    required_a = required_contract(baseline_source, 'A')
    required_b = required_contract(candidate_source, 'B')
    need(required_a == required_b)
    go_binding = raw_go_pair_binding(source_a, source_b)
    a = validate_leg(a_dir, 'A', baseline_source, controller, source_a, controller_expected,
                     required_a, pair_contract, order, controller_commit)
    b = validate_leg(b_dir, 'B', candidate_source, controller, source_b, controller_expected,
                     required_b, pair_contract, order, controller_commit)
    need(a['context']['runID'] == b['context']['runID'] and
         a['context']['runAttempt'] == b['context']['runAttempt'] and
         a['context']['pairID'] == b['context']['pairID'] and
         a['context']['job'] == b['context']['job'] and
         a['context']['position'] != b['context']['position'])
    return {'schema': 'chengwang.source-pair-comparison/v2', 'measurementOnly': True,
            'production': False, 'originalBaselineCommit': ORIGINAL_BASELINE_COMMIT,
            'baselineCommit': BASELINE_COMMIT,
            'candidateCommit': CANDIDATE_COMMIT,
            'controllerCommit': controller_commit, 'order': order,
            'pairID': a['context']['pairID'], 'captureVerified': True,
            'rawGoSourceBinding': go_binding, 'sourceContract': pair_contract,
            'controllerAndMeasurementSourcesSeparated': True,
            'a': a, 'b': b,
            'eachGoAccepted': {'baseline': a['goAccepted'], 'candidate': b['goAccepted']},
            'limits': {'goTestTimeoutSeconds': 180, 'historyEntries': 256,
                       'recordBytes': 2 << 20, 'requiredTopLevelTests':
                            sum(len(names) for names in required_a.values())},
            'sameRunnerSequentialLegs': True, 'sameRunnerSameLoadProven': False,
            'runtimeGOMAXPROCSModified': False,
            'candidateMayReplaceBaselineAcceptance': False,
            'allTrackedTestGoBytesEqual': True,
            'onlyProductionGoDifferenceIsStoreCopyImplementation': True,
            'sourceChangeMayBePerformanceCause': True,
            'performanceCauseProven': False}


def models():
    now = '2026-10-26T00:00:00Z'
    positive_cases = 0
    rejected = []

    def clone(value):
        return decode(encoded(value))

    def expect_reject(name, function):
        try:
            function()
        except ValueError:
            rejected.append(name)
            return
        need(False)

    required = {package: ['TestRequired'] for package in PACKAGES}
    rows = []
    for package in PACKAGES:
        rows.append({'Time': now, 'Action': 'start', 'Package': package})
        rows.append({'Time': now, 'Action': 'run', 'Package': package, 'Test': 'TestRequired'})
        rows.append({'Time': now, 'Action': 'pass', 'Package': package,
                     'Test': 'TestRequired', 'Elapsed': 1})
        if package == PACKAGES[1]:
            rows.append({'Time': now, 'Action': 'run', 'Package': package, 'Test': TOP})
            rows.append({'Time': now, 'Action': 'pass', 'Package': package, 'Test': TOP, 'Elapsed': 2})
        rows.append({'Time': now, 'Action': 'pass', 'Package': package, 'Elapsed': 3})
    summary = event_summary(b''.join(encoded(row) for row in rows), required)
    need(summary['requiredTopLevelStates']['pass'] == 6 and summary['capacity']['state'] == 'pass')
    positive_cases += 1
    timed = list(rows)
    timed.insert(-1, {'Time': now, 'Action': 'output', 'Package': PACKAGES[1],
                      'Test': TOP, 'Output': 'panic: test timed out after 3m0s\n'})
    need(event_summary(b''.join(encoded(row) for row in timed), required)['timeoutObserved'])
    positive_cases += 1
    need(RACE_ARGS[:2] == ['test', '-race'] and ORDINARY_ARGS[0] == 'test' and
         '-p=1' not in RACE_ARGS and RACE_ARGS[2:] == ORDINARY_ARGS[1:])
    for order in ('AB', 'BA'):
        need(order[order.index('A')] == 'A' and order[order.index('B')] == 'B')
    positive_cases += 1

    source_heads(BASELINE_COMMIT, CANDIDATE_COMMIT, [ORIGINAL_BASELINE_COMMIT])
    positive_cases += 1
    go_rows = [{'path': path, 'oldBlobSHA1': old, 'newBlobSHA1': new,
                'oldMode': '100644', 'newMode': '100644', 'status': 'M'}
               for path, old, new in GO_DIFF]
    go_diff_contract(clone(go_rows))
    positive_cases += 1
    test_fixture = {TEST_FIXTURE_PATH: {'mode': '100644', 'blobSHA1': TEST_FIXTURE_BLOB}}
    test_go_contract(clone(test_fixture), clone(test_fixture))
    positive_cases += 1
    non_go_diff_contract(['chengwang/docs/MODEL.md'])
    positive_cases += 1
    ordinary_line = (b'"${common[@]}" "$goroot/bin/go" test -json -count=1 -timeout=180s '
                     b'./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api '
                     b'./internal/serverruntime ./internal/authz > "$out/ordinary.json" 2> "$out/ordinary.stderr"')
    race_line = (b'"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s '
                 b'./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api '
                 b'./internal/serverruntime ./internal/authz > "$out/race.json" 2> "$out/race.stderr"')
    script_fixture = ordinary_line + b'\n' + race_line + b'\n'
    normal_script_contract(script_fixture)
    positive_cases += 1

    host_value = {'networkNamespace': 'net:[1]', 'mountNamespace': 'mnt:[2]',
                  'pidNamespace': 'pid:[3]', 'resolvSHA256': '0' * 64}
    sandbox_value = {'uid': 10001, 'gid': 10001, 'effectiveCaps': '0000000000000000',
        'noNewPrivileges': True, 'networkNamespace': 'net:[11]', 'mountNamespace': 'mnt:[12]',
        'pidNamespace': 'pid:[13]', 'environmentKeys': ENVIRONMENT_KEYS,
        'sourceModuleSHA256': '1' * 64, 'sourceAliasReadOnly': True,
        'temporaryRootPrivate': True}
    sandbox_contract(clone(sandbox_value), host_value, '1' * 64)
    positive_cases += 1
    # Namespace inode numbers may be reused after the earlier sequential leg
    # has exited. Freshness is proved per leg against its concurrently alive
    # host namespaces, not by comparing stale numeric strings across legs.
    later_host = {'networkNamespace': 'net:[4]', 'mountNamespace': 'mnt:[5]',
                  'pidNamespace': 'pid:[6]', 'resolvSHA256': '0' * 64}
    sandbox_contract(clone(sandbox_value), later_host, '1' * 64)
    positive_cases += 1

    observation = {'schema': 'chengwang.source-pair-resource-observation/v1',
        'diagnosticMode': 'TEST_EQUAL_BASELINE_CANDIDATE_SAME_NORMAL_FLAGS',
        'scope': 'CAPTURE_PROCESS_AND_KERNEL_CGROUP_AGGREGATES_NOT_PER_TEST_NOT_ATOMIC',
        'startedMonotonicNs': 1, 'finishedMonotonicNs': 2,
        'captureScope': 'MODEL_SCOPE', 'phase': 'BEFORE', 'observations': {
            'cpuCount': {'scope': RESOURCE_SCOPES['cpuCount'], 'value': 4, 'reason': 'NONE'},
            'affinityCPUs': {'scope': RESOURCE_SCOPES['affinityCPUs'], 'value': [0, 1],
                             'reason': 'NONE'},
            'procStatCPU': {'scope': RESOURCE_SCOPES['procStatCPU'],
                            'value': {'user': 1, 'system': 2, 'idle': 3, 'iowait': 4, 'steal': 5},
                            'reason': 'NONE'},
            'cgroupCPUMax': {'scope': RESOURCE_SCOPES['cgroupCPUMax'],
                             'value': {'quotaMicros': None, 'periodMicros': 100000,
                                       'unlimited': True}, 'reason': 'NONE'},
            'cgroupCPUStat': {'scope': RESOURCE_SCOPES['cgroupCPUStat'],
                              'value': {name: 1 for name in CPU_STAT_FIELDS}, 'reason': 'NONE'}}}
    resource(encoded(observation), 'MODEL_SCOPE', 'BEFORE')
    positive_cases += 1

    runner = {'processExit': 0, 'outerTimedOut': False, 'pidfdAcquired': True,
              'termSent': False, 'killSent': False, 'captureSupervisorComplete': True,
              'failureClass': 'NONE', 'schema': 'chengwang.source-pair-runner/v1', 'leg': 'A',
              'sourceCommit': BASELINE_COMMIT, 'controllerCommit': '2' * 40,
              'outerTimeoutSeconds': 420, 'termGraceSeconds': 5, 'measurementOnly': True,
              'production': False, 'startedMonotonicNs': 10, 'finishedMonotonicNs': 20}
    event_names = ['START_INTENT', 'STARTED_GATED', 'PIDFD_ACQUIRED',
                   'GATE_RELEASED', 'WAIT_RETURNED']
    journal = []
    for sequence, event_name in enumerate(event_names, 1):
        journal.append({'schema': 'chengwang.source-pair-supervision-event/v1',
            'sequence': sequence, 'event': event_name,
            'pid': None if sequence == 1 else 101,
            'pidfdAcquired': None if sequence == 1 else sequence >= 3,
            'exitCode': 0 if sequence == 5 else None, 'monotonicNs': 9 + sequence,
            'commandClass': 'ISOLATED_LEG'})
    supervision(b''.join(encoded(row) for row in journal), clone(runner))
    positive_cases += 1

    same_network = clone(sandbox_value); same_network['networkNamespace'] = host_value['networkNamespace']
    same_mount = clone(sandbox_value); same_mount['mountNamespace'] = host_value['mountNamespace']
    same_pid = clone(sandbox_value); same_pid['pidNamespace'] = host_value['pidNamespace']
    malformed_namespace = clone(sandbox_value); malformed_namespace['networkNamespace'] = 'FORGED'
    wrong_module = clone(sandbox_value); wrong_module['sourceModuleSHA256'] = '3' * 64
    missing_sandbox_field = clone(sandbox_value); del missing_sandbox_field['temporaryRootPrivate']

    bad_resource_schema = clone(observation); bad_resource_schema['schema'] = 'forged'
    bad_scope = clone(observation); bad_scope['observations']['cpuCount']['scope'] = 'FORGED'
    bad_reason = clone(observation); bad_reason['observations']['affinityCPUs']['reason'] = 'FORGED'
    bad_type = clone(observation); bad_type['observations']['cpuCount']['value'] = True
    bad_quota = clone(observation); bad_quota['observations']['cgroupCPUMax']['value']['quotaMicros'] = 1
    all_forged = clone(observation)
    all_forged['observations'] = {name: {'scope': 'FORGED', 'value': 'FORGED', 'reason': 'FORGED'}
                                  for name in RESOURCE_SCOPES}

    wrong_order = clone(journal); wrong_order[2], wrong_order[3] = wrong_order[3], wrong_order[2]
    wrong_order[2]['sequence'], wrong_order[3]['sequence'] = 3, 4
    wrong_pid = clone(journal); wrong_pid[3]['pid'] = 102
    wrong_event_schema = clone(journal); wrong_event_schema[1]['schema'] = 'forged'
    signaled_runner = clone(runner); signaled_runner['termSent'] = True
    wrong_exit = clone(runner); wrong_exit['processExit'] = 1
    wrong_go_path = clone(go_rows); wrong_go_path[0]['path'] = 'chengwang/internal/mihomodeploy/forged.go'
    wrong_test_fixture = clone(test_fixture)
    wrong_test_fixture[TEST_FIXTURE_PATH]['blobSHA1'] = '0' * 40
    wrong_script_flags = script_fixture.replace(b' test -race ', b' test -p=1 -race ')
    mutants = [
        ('source_wrong_commit',
         lambda: source_heads('0' * 40, CANDIDATE_COMMIT, [ORIGINAL_BASELINE_COMMIT])),
        ('source_wrong_baseline_parent',
         lambda: source_heads(BASELINE_COMMIT, CANDIDATE_COMMIT, ['0' * 40])),
        ('source_go_diff_path', lambda: go_diff_contract(wrong_go_path)),
        ('source_test_go_mismatch',
         lambda: test_go_contract(test_fixture, wrong_test_fixture)),
        ('source_non_go_execution_input', lambda: non_go_diff_contract(['chengwang/go.mod'])),
        ('source_script_flags', lambda: normal_script_contract(wrong_script_flags)),
        ('sandbox_network_namespace_not_isolated',
         lambda: sandbox_contract(same_network, host_value, '1' * 64)),
        ('sandbox_mount_namespace_not_isolated',
         lambda: sandbox_contract(same_mount, host_value, '1' * 64)),
        ('sandbox_pid_namespace_not_isolated',
         lambda: sandbox_contract(same_pid, host_value, '1' * 64)),
        ('sandbox_namespace_format',
         lambda: sandbox_contract(malformed_namespace, host_value, '1' * 64)),
        ('sandbox_source_module_digest',
         lambda: sandbox_contract(wrong_module, host_value, '1' * 64)),
        ('sandbox_exact_fields',
         lambda: sandbox_contract(missing_sandbox_field, host_value, '1' * 64)),
        ('resource_schema', lambda: resource(encoded(bad_resource_schema), 'MODEL_SCOPE', 'BEFORE')),
        ('resource_row_scope', lambda: resource(encoded(bad_scope), 'MODEL_SCOPE', 'BEFORE')),
        ('resource_row_reason', lambda: resource(encoded(bad_reason), 'MODEL_SCOPE', 'BEFORE')),
        ('resource_bool_integer_alias', lambda: resource(encoded(bad_type), 'MODEL_SCOPE', 'BEFORE')),
        ('resource_unlimited_quota_pair', lambda: resource(encoded(bad_quota), 'MODEL_SCOPE', 'BEFORE')),
        ('resource_all_rows_forged', lambda: resource(encoded(all_forged), 'MODEL_SCOPE', 'BEFORE')),
        ('supervision_gate_before_pidfd',
         lambda: supervision(b''.join(encoded(row) for row in wrong_order), clone(runner))),
        ('supervision_pid_identity',
         lambda: supervision(b''.join(encoded(row) for row in wrong_pid), clone(runner))),
        ('supervision_event_schema',
         lambda: supervision(b''.join(encoded(row) for row in wrong_event_schema), clone(runner))),
        ('supervision_runner_signal_flags',
         lambda: supervision(b''.join(encoded(row) for row in journal), signaled_runner)),
        ('supervision_runner_exit_mismatch',
         lambda: supervision(b''.join(encoded(row) for row in journal), wrong_exit)),
    ]
    for name, function in mutants:
        expect_reject(name, function)
    need(len(rejected) == len(mutants))
    print(f'SOURCE_PAIR_MODELS=PASS positive_cases={positive_cases} '
          f'negative_mutants={len(mutants)} rejected_classes={",".join(rejected)}')


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    source_parser = sub.add_parser('source-contract')
    source_parser.add_argument('--baseline-source', type=Path, required=True)
    source_parser.add_argument('--candidate-source', type=Path, required=True)
    leg_parser = sub.add_parser('leg-script-contract')
    leg_parser.add_argument('--source', type=Path, required=True)
    leg_parser.add_argument('--leg', choices=('A', 'B'), required=True)
    verify_parser = sub.add_parser('verify')
    for name in ('baseline-source', 'candidate-source', 'controller', 'controller-commit',
                 'order', 'a', 'b', 'report'):
        verify_parser.add_argument('--' + name, required=True)
    sub.add_parser('models')
    args = parser.parse_args()
    if args.action == 'models':
        models()
    elif args.action == 'source-contract':
        value = source_pair_contract(args.baseline_source, args.candidate_source)
        required_a = required_contract(absolute(args.baseline_source), 'A')
        required_b = required_contract(absolute(args.candidate_source), 'B')
        need(required_a == required_b)
        print(f"SOURCE_PAIR_SOURCE_CONTRACT=PASS go_diff_paths={len(value['goDiff'])} "
              'required_tops=688 test_go_equal=true production_go_diff_paths=1 '
              'normal_flags_equal=true performance_cause_proven=false')
    elif args.action == 'leg-script-contract':
        leg_script_contract(args.source, args.leg)
        print(f'SOURCE_PAIR_LEG_SCRIPT=PASS leg={args.leg} exact_source_normal=true')
    else:
        value = verify(Path(args.baseline_source), Path(args.candidate_source),
                       Path(args.controller), args.controller_commit, args.order,
                       Path(args.a), Path(args.b))
        write(output_path(args.report), encoded(value))
        print(f"SOURCE_PAIR_CAPTURE=VERIFIED order={args.order} "
              f"a_go_accepted={str(value['a']['goAccepted']).lower()} "
              f"b_go_accepted={str(value['b']['goAccepted']).lower()} measurement_only=true")
        if not (value['a']['goAccepted'] and value['b']['goAccepted']):
            raise SystemExit(3)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('SOURCE_PAIR=REJECTED raw_input_suppressed=true') from None
