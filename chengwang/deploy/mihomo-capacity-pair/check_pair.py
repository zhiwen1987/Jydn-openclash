"""Strict reader for the opt-in A/B and B/A capacity measurement."""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SCHEMA = 'chengwang.capacity-pair-context/v1'
PACKAGES = {'chengwang/internal/adapter/mihomo', 'chengwang/internal/mihomodeploy',
    'chengwang/internal/authn', 'chengwang/internal/api', 'chengwang/internal/serverruntime',
    'chengwang/internal/authz'}
PACKAGE = 'chengwang/internal/mihomodeploy'
TOP = 'TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop'
JOB_TIMEOUT_MINUTES = 12
A_NAMES = ('sandbox.json', 'go-version.txt', 'capacity.json', 'capacity.stderr', 'commands.jsonl',
    'execution.json', 'resource-before.json', 'resource-after.json')


def need(ok):
    if not ok:
        raise ValueError('capacity pair evidence rejected')


def exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def measurement_limits():
    return {'goTestTimeoutSecondsEach': 180, 'historyEntries': 256,
        'recordBytes': 2 << 20, 'jobTimeoutMinutes': JOB_TIMEOUT_MINUTES}


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())


def absolute(path):
    path = Path(os.path.abspath(path))
    need(path.is_absolute() and '..' not in path.parts)
    for part in (*reversed(path.parents), path):
        need(not part.is_symlink())
    return path


def read(path, limit):
    path = absolute(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit)
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_mode, value.st_nlink)
    need(identity(before) == identity(opened) == identity(after) == identity(path.lstat()) and len(raw) == before.st_size)
    return raw


def decode(raw):
    value = json.loads(raw)
    need(encoded(value) == raw)
    return value


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def context_value(commit, run_id, attempt, order, position, leg, job):
    need(re.fullmatch('[a-f0-9]{40}', commit) is not None and order in ('AB', 'BA') and leg in ('A', 'B'))
    need(type(run_id) is type(attempt) is type(position) is int and run_id > 0 and attempt > 0 and position in (1, 2))
    need(order[position - 1] == leg and re.fullmatch('[A-Za-z0-9:._-]{1,128}', job) is not None)
    return {'schema': SCHEMA, 'sourceCommit': commit, 'runID': run_id, 'runAttempt': attempt,
        'order': order, 'position': position, 'leg': leg, 'job': job,
        'pairID': f'{run_id}:{attempt}:{order}', 'measurementOnly': True, 'production': False}


def validate_context_pair(a, b, commit, order):
    keys = ('schema', 'sourceCommit', 'runID', 'runAttempt', 'order', 'position', 'leg',
        'job', 'pairID', 'measurementOnly', 'production')
    for value, leg in ((a, 'A'), (b, 'B')):
        need(exact(value, keys) and value['schema'] == SCHEMA and value['sourceCommit'] == commit and
            value['order'] == order and value['leg'] == leg and value['measurementOnly'] is True and
            value['production'] is False and type(value['runID']) is type(value['runAttempt']) is type(value['position']) is int)
        need(value['runID'] > 0 and value['runAttempt'] > 0 and value['position'] in (1, 2) and
            order[value['position'] - 1] == leg and re.fullmatch('[A-Za-z0-9:._-]{1,128}', value['job']) is not None)
    need(a['runID'] == b['runID'] and a['runAttempt'] == b['runAttempt'] and a['job'] == b['job'] and
        a['pairID'] == b['pairID'] == f"{a['runID']}:{a['runAttempt']}:{order}" and a['position'] != b['position'])


def bind_source(before, after, expected, commit):
    need(before == after == expected)
    value = decode(before)
    need(value.get('schema') == 'chengwang.capacity-profile-source/v1' and
        value.get('sourceCommit') == commit and value.get('sourceGitVerified') is True and type(value.get('files')) is list)
    return value


def validate_host(raw):
    value = decode(raw)
    need(exact(value, ('networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256')) and
        all(type(value[name]) is str and value[name] for name in ('networkNamespace', 'mountNamespace', 'pidNamespace')) and
        re.fullmatch('[a-f0-9]{64}', value['resolvSHA256']) is not None)
    return value


def validate_resource_a(raw):
    value = decode(raw)
    need(exact(value, ('schema', 'diagnosticMode', 'scope', 'startedMonotonicNs', 'finishedMonotonicNs', 'observations')) and
        value['schema'] == 'chengwang.capacity-pair-resources/v1' and value['diagnosticMode'] == 'NO_PROFILE_NORMAL_FLAGS' and
        value['scope'] == 'CAPTURE_PROCESS_AND_KERNEL_CGROUP_AGGREGATES_NOT_PER_TEST_NOT_ATOMIC' and
        type(value['startedMonotonicNs']) is type(value['finishedMonotonicNs']) is int and
        0 < value['startedMonotonicNs'] <= value['finishedMonotonicNs'] and type(value['observations']) is dict)
    need(set(value['observations']) == {'cpuCount', 'affinityCPUs', 'procStatCPU', 'cgroupCPUMax', 'cgroupCPUStat'})
    return value


def command_rows(raw, expected):
    rows = [decode(line + b'\n') for line in raw.splitlines()]
    need(len(rows) == 3 * len(expected))
    previous = 0
    for index, (kind, argv) in enumerate(expected):
        group = rows[3 * index:3 * index + 3]
        need([row['event'] for row in group] == ['START_INTENT', 'STARTED', 'WAIT_RETURNED'])
        for offset, row in enumerate(group):
            need(exact(row, ('seq', 'event', 'class', 'argv', 'pid', 'exitCode', 'monotonicNs')) and
                row['seq'] == 3 * index + offset + 1 and row['class'] == kind and row['argv'] == argv and
                type(row['monotonicNs']) is int and row['monotonicNs'] >= previous)
            previous = row['monotonicNs']
        need(group[0]['pid'] is group[0]['exitCode'] is None and type(group[1]['pid']) is int and group[1]['pid'] > 1 and
            group[1]['exitCode'] is None and group[2]['pid'] == group[1]['pid'] and type(group[2]['exitCode']) is int)
    go_group = next(rows[3 * index:3 * index + 3] for index, (kind, _) in enumerate(expected) if kind == 'GO_TEST')
    return (rows, go_group[2]['monotonicNs'] - go_group[0]['monotonicNs'], go_group[2]['exitCode'],
        go_group[0]['monotonicNs'], go_group[2]['monotonicNs'])


def event_shape(raw):
    terminals = {}
    states = {}
    timeout = False
    race = False
    package_elapsed = None
    target_elapsed = None
    for line in raw.splitlines():
        need(0 < len(line) <= 1 << 20)
        row = json.loads(line)
        need(type(row) is dict and set(row) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'} and row.get('Package') in PACKAGES)
        datetime.datetime.fromisoformat(row['Time'].replace('Z', '+00:00'))
        if 'Elapsed' in row:
            need(type(row['Elapsed']) in (int, float) and math.isfinite(row['Elapsed']) and row['Elapsed'] >= 0)
        action, package, name = row.get('Action'), row['Package'], row.get('Test')
        if name is not None and action == 'run':
            states[(package, name)] = 'run'
        elif name is not None and action in ('pass', 'fail', 'skip'):
            states[(package, name)] = action
            if package == PACKAGE and name == TOP:
                target_elapsed = row.get('Elapsed')
        elif name is None and action in ('pass', 'fail', 'skip'):
            terminals[package] = action
            if package == PACKAGE:
                package_elapsed = row.get('Elapsed')
        if action == 'output':
            text = row.get('Output', '')
            need(type(text) is str)
            timeout = timeout or 'panic: test timed out after 3m0s' in text
            race = race or 'WARNING: DATA RACE' in text
    return {'packageStates': {name: terminals.get(name, 'UNFINISHED') for name in sorted(PACKAGES)},
        'targetState': states.get((PACKAGE, TOP), 'NOT_STARTED'), 'timeoutObserved': timeout,
        'dataRaceWarningObserved': race, 'packageSeconds': package_elapsed, 'capacitySeconds': target_elapsed}


def accepted(full_accepted, shape):
    return bool(full_accepted and not shape['timeoutObserved'] and not shape['dataRaceWarningObserved'] and
        shape['targetState'] == 'pass' and all(value == 'pass' for value in shape['packageStates'].values()))


def validate_receipt(directory, context_raw, execution_raw, leg):
    value = decode(read(directory / 'leg-receipt.json', 16384))
    need(exact(value, ('schema', 'leg', 'sourceCommit', 'contextSHA256', 'executionSHA256', 'goExit',
        'captureOnly', 'performanceImprovementProven', 'production')) and
        value['schema'] == 'chengwang.capacity-pair-leg-receipt/v1' and value['leg'] == leg and
        value['contextSHA256'] == sha(context_raw) and value['executionSHA256'] == sha(execution_raw) and
        value['captureOnly'] is True and value['performanceImprovementProven'] is value['production'] is False)
    runner = decode(read(directory / 'runner-exit.json', 4096))
    need(exact(runner, ('schema', 'leg', 'exitCode')) and runner == {
        'schema': 'chengwang.capacity-pair-runner-exit/v1', 'leg': leg, 'exitCode': 0})
    return value


def verify(repo, commit, order, a_dir, b_dir):
    need(order in ('AB', 'BA') and re.fullmatch('[a-f0-9]{40}', commit) is not None)
    profile = load('capacity_pair_profile_checker', repo / 'chengwang/deploy/mihomo-capacity-profile/check_profile.py')
    expected_source = profile.encoded(profile.source_snapshot(repo, commit))
    context_raw_a = read(a_dir / 'pair-context.json', 16384)
    context_raw_b = read(b_dir / 'pair-context.json', 16384)
    context_a, context_b = decode(context_raw_a), decode(context_raw_b)
    validate_context_pair(context_a, context_b, commit, order)
    manifests = []
    for directory in (a_dir, b_dir):
        manifests.append(bind_source(read(directory / 'source-before.json', 16 << 20),
            read(directory / 'source-after.json', 16 << 20), expected_source, commit))
        validate_host(read(directory / 'host-before.json', 65536))
        validate_host(read(directory / 'host-after.json', 65536))
    need(manifests[0] == manifests[1])
    normal_checker = load('capacity_pair_normal_checker', repo / 'chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py')
    sources = {path: read(repo / PurePosixPath(path), 1 << 20) for path in normal_checker.FILES}
    bound_checker, required, binding = profile.full_source_contract(sources, manifests[0])

    a_raw = {name: read(a_dir / name, 64 << 20 if name == 'capacity.json' else 2 << 20) for name in A_NAMES}
    a_box = decode(a_raw['sandbox.json'])
    need(exact(a_box, ('schema', 'mode', 'uid', 'gid', 'effectiveCaps', 'noNewPrivileges', 'interfaces',
        'defaultRoutes', 'environmentKeys', 'sourceAliasReadOnly', 'goRootReadOnly', 'goRoot',
        'networkNamespace', 'mountNamespace', 'pidNamespace', 'production')) and
        a_box['schema'] == 'chengwang.capacity-pair-sandbox/v1' and a_box['mode'] == 'A_NO_PROFILE' and
        a_box['uid'] == a_box['gid'] == 10001 and a_box['production'] is False and a_box['interfaces'] == ['lo'] and
        a_box['defaultRoutes'] == {'ipv4': [], 'ipv6': []} and a_box['sourceAliasReadOnly'] is a_box['goRootReadOnly'] is True)
    need(a_box['environmentKeys'] == sorted(('PATH', 'GOROOT', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE',
        'GOPROXY', 'GOSUMDB', 'GOENV', 'GOTOOLCHAIN', 'GOFLAGS', 'CGO_ENABLED', 'LANG', 'LC_ALL', 'TZ',
        'CHENGWANG_CAPACITY_PAIR_SOURCE_COMMIT', 'CHENGWANG_CAPACITY_PAIR_CONTEXT_SHA256')))
    a_execution = decode(a_raw['execution.json'])
    need(exact(a_execution, ('schema', 'mode', 'sourceCommit', 'contextSHA256', 'versionExit', 'goExit',
        'captureComplete', 'realMihomoExecuted', 'production')) and
        a_execution['schema'] == 'chengwang.capacity-pair-execution/v1' and a_execution['mode'] == 'A_NO_PROFILE' and
        a_execution['sourceCommit'] == commit and a_execution['contextSHA256'] == sha(context_raw_a) and
        a_execution['versionExit'] == 0 and type(a_execution['goExit']) is int and
        a_execution['captureComplete'] is True and a_execution['realMihomoExecuted'] is a_execution['production'] is False)
    go = str(Path(a_box['goRoot']) / 'bin/go')
    packages = ['./internal/adapter/mihomo', './internal/mihomodeploy', './internal/authn', './internal/api', './internal/serverruntime', './internal/authz']
    _, a_wall, a_command_exit, a_started, a_finished = command_rows(a_raw['commands.jsonl'], [('VERSION', [go, 'version']),
        ('GO_TEST', [go, 'test', '-race', '-json', '-count=1', '-timeout=180s', *packages])])
    need(a_command_exit == a_execution['goExit'] and a_raw['go-version.txt'] == b'go version go1.23.12 linux/amd64\n')
    resource_a_before, resource_a_after = validate_resource_a(a_raw['resource-before.json']), validate_resource_a(a_raw['resource-after.json'])
    a_summary = profile.full_events(a_raw['capacity.json'], required, bound_checker, a_execution['goExit'], a_raw['capacity.stderr'])
    a_shape = event_shape(a_raw['capacity.json'])
    a_accepted = accepted(a_summary['fullGoAccepted'], a_shape)
    validate_receipt(a_dir, context_raw_a, a_raw['execution.json'], 'A')

    b_names = profile.PUBLIC + profile.RESOURCE_NAMES
    b_raw = {name: read(b_dir / name, 12 << 20 if name == 'cpu-profile.json' else 64 << 20 if name == 'capacity.json' else 2 << 20) for name in b_names}
    b_report = profile.verify_raw(b_raw, commit, 'FULL_CONTRACTS', sources)
    b_execution = decode(b_raw['execution.json'])
    b_box = decode(b_raw['sandbox.json'])
    b_expected = [('VERSION', [str(Path(b_box['goRoot']) / 'bin/go'), 'version']),
        ('FORMAT', [str(Path(b_box['goRoot']) / 'bin/gofmt'), '-d', *profile.FULL_FMT]),
        ('GO_TEST', [str(Path(b_box['goRoot']) / 'bin/go'), *profile.FULL_GO_ARGS]),
        ('PPROF_TOP', [str(Path(b_box['goRoot']) / 'bin/go'), 'tool', 'pprof', '-symbolize=local', '-top', profile.PRIVATE + '/cpu.pprof']),
        ('PPROF_CUM', [str(Path(b_box['goRoot']) / 'bin/go'), 'tool', 'pprof', '-symbolize=local', '-top', '-cum', profile.PRIVATE + '/cpu.pprof'])]
    _, b_wall, b_command_exit, _, _ = command_rows(b_raw['commands.jsonl'], b_expected)
    need(b_command_exit == b_execution['goExit'] and b_raw['go-version.txt'] == a_raw['go-version.txt'])
    b_shape = event_shape(b_raw['capacity.json'])
    b_accepted = accepted(b_report['fullGoAccepted'], b_shape)
    validate_receipt(b_dir, context_raw_b, b_raw['execution.json'], 'B')

    need(resource_a_before['finishedMonotonicNs'] <= a_started <= a_finished <= resource_a_after['startedMonotonicNs'])
    result = {'schema': 'chengwang.capacity-pair-comparison/v1', 'sourceCommit': commit,
        'captureVerified': True, 'order': order, 'pairID': context_a['pairID'], 'runID': context_a['runID'],
        'runAttempt': context_a['runAttempt'], 'normalSourceBinding': binding,
        'a': {'mode': 'NO_PROFILE_NORMAL_FLAGS', 'goExit': a_execution['goExit'], 'goAccepted': a_accepted,
            'goCLIWallNanoseconds': a_wall, 'packageSeconds': a_shape['packageSeconds'],
            'capacitySeconds': a_shape['capacitySeconds'], 'eventSummary': a_summary,
            'resourceBefore': resource_a_before, 'resourceAfter': resource_a_after},
        'b': {'mode': 'TAGGED_FULL_PROFILE', 'goExit': b_execution['goExit'], 'goAccepted': b_accepted,
            'goCLIWallNanoseconds': b_wall, 'packageSeconds': b_shape['packageSeconds'],
            'capacitySeconds': b_shape['capacitySeconds'], 'eventSummary': b_report,
            'profileDurationNanoseconds': b_report['profile']['durationNanoseconds'], 'resources': b_report['resources']},
        'delta': {'bMinusAGoCLIWallNanoseconds': b_wall - a_wall,
            'bMinusAPackageSeconds': None if a_shape['packageSeconds'] is None or b_shape['packageSeconds'] is None else b_shape['packageSeconds'] - a_shape['packageSeconds'],
            'bMinusACapacitySeconds': None if a_shape['capacitySeconds'] is None or b_shape['capacitySeconds'] is None else b_shape['capacitySeconds'] - a_shape['capacitySeconds']},
        'limits': measurement_limits(),
        'freshProcessNamespaceAndPrivateGoCachePerLeg': True, 'sameWorkflowJobRunner': True,
        'identicalSystemLoadProven': False, 'profileOverheadCausalityProven': False,
        'performanceImprovementProven': False, 'productAcceptance': False, 'production': False}
    return result


def synthetic_events(target='pass', timeout=False, missing=False):
    now = '2026-10-26T00:00:00Z'
    rows = []
    for package in sorted(PACKAGES):
        rows.append({'Time': now, 'Action': 'start', 'Package': package})
        if package == PACKAGE and not missing:
            rows.append({'Time': now, 'Action': 'run', 'Package': package, 'Test': TOP})
            if timeout:
                rows.append({'Time': now, 'Action': 'output', 'Package': package, 'Test': TOP,
                    'Output': 'panic: test timed out after 3m0s\n'})
            rows.append({'Time': now, 'Action': target, 'Package': package, 'Test': TOP, 'Elapsed': 1})
        rows.append({'Time': now, 'Action': 'pass', 'Package': package, 'Elapsed': 1})
    return b''.join(encoded(row) for row in rows)


def reject(action):
    try:
        action()
    except (ValueError, AssertionError, KeyError, TypeError):
        return
    raise AssertionError('negative model accepted')


def models():
    workflow = Path(__file__).resolve().parents[3] / '.github/workflows/chengwang-mihomo-capacity-pair.yml'
    timeout_values = re.findall(rb'(?m)^    timeout-minutes: ([0-9]+)\n', read(workflow, 1 << 20))
    need(timeout_values == [str(JOB_TIMEOUT_MINUTES).encode()])
    need(measurement_limits() == {'goTestTimeoutSecondsEach': 180, 'historyEntries': 256,
        'recordBytes': 2 << 20, 'jobTimeoutMinutes': int(timeout_values[0])})
    commit = 'a' * 40
    a = context_value(commit, 7, 1, 'AB', 1, 'A', 'pair-AB')
    b = context_value(commit, 7, 1, 'AB', 2, 'B', 'pair-AB')
    validate_context_pair(a, b, commit, 'AB')
    crossed = copy.deepcopy(a); crossed['leg'] = 'B'
    reject(lambda: validate_context_pair(crossed, b, commit, 'AB'))
    expected = encoded({'schema': 'chengwang.capacity-profile-source/v1', 'sourceCommit': commit,
        'sourceGitVerified': True, 'files': [], 'originalCaseSourcePins': {}})
    bind_source(expected, expected, expected, commit)
    drifted_header = expected.replace(commit.encode(), ('b' * 40).encode())
    reject(lambda: bind_source(drifted_header, drifted_header, expected, commit))
    drifted_body = expected.replace(b'"files":[]', b'"files":[{}]')
    reject(lambda: bind_source(drifted_body, drifted_body, expected, commit))
    good = event_shape(synthetic_events())
    need(accepted(True, good))
    need(not accepted(True, event_shape(synthetic_events(timeout=True))))
    need(not accepted(True, event_shape(synthetic_events(target='skip'))))
    need(not accepted(True, event_shape(synthetic_events(missing=True))))
    print('CAPACITY_PAIR_MODELS=PASS negative_cases=6 cross_source_limits=1')


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    context = sub.add_parser('context')
    for name in ('source-commit', 'order', 'leg', 'job', 'out'):
        context.add_argument('--' + name, required=True)
    context.add_argument('--run-id', type=int, required=True)
    context.add_argument('--run-attempt', type=int, required=True)
    context.add_argument('--position', type=int, required=True)
    runner = sub.add_parser('runner')
    runner.add_argument('--leg', choices=('A', 'B'), required=True)
    runner.add_argument('--exit-code', type=int, required=True)
    runner.add_argument('--out', type=Path, required=True)
    verify_parser = sub.add_parser('verify')
    verify_parser.add_argument('--repo', type=Path, required=True)
    verify_parser.add_argument('--source-commit', required=True)
    verify_parser.add_argument('--order', choices=('AB', 'BA'), required=True)
    verify_parser.add_argument('--a', type=Path, required=True)
    verify_parser.add_argument('--b', type=Path, required=True)
    verify_parser.add_argument('--report', type=Path, required=True)
    sub.add_parser('models')
    args = parser.parse_args()
    if args.action == 'context':
        value = context_value(args.source_commit, args.run_id, args.run_attempt, args.order,
            args.position, args.leg, args.job)
        write(Path(args.out), encoded(value))
    elif args.action == 'runner':
        need(-128 <= args.exit_code <= 255)
        write(args.out, encoded({'schema': 'chengwang.capacity-pair-runner-exit/v1',
            'leg': args.leg, 'exitCode': args.exit_code}))
    elif args.action == 'verify':
        result = verify(absolute(args.repo), args.source_commit, args.order,
            absolute(args.a), absolute(args.b))
        write(args.report, encoded(result))
        print(f"CAPACITY_PAIR=VERIFIED order={args.order} a_accepted={str(result['a']['goAccepted']).lower()} b_accepted={str(result['b']['goAccepted']).lower()} measurement_only=true")
    else:
        models()


if __name__ == '__main__':
    main()
