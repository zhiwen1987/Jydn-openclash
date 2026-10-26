"""Custody and pidfd supervision for the isolated default-p versus -p=1 diagnostic.

This controller never supplies Go package bytes. Every Go command is run by an
exact or mechanically derived 2eb7717 run_contracts.sh against a separate,
read-only checkout of that commit.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

SOURCE_COMMIT = '2eb7717a7a9d32308fbb90c45b2c183c1acb53d8'
# Custody bound only. It must not pre-empt the two unchanged 180 s Go-test
# budgets plus formatting and evidence finalization.
OUTER_TIMEOUT_SECONDS = 420
TERM_GRACE_SECONDS = 5
CONTROLLER_FILES = (
    '.github/workflows/chengwang-mihomo-p1-pair.yml',
    'chengwang/deploy/mihomo-p1-pair/check_pair.py',
    'chengwang/deploy/mihomo-p1-pair/pair_controller.py',
    'chengwang/deploy/mihomo-p1-pair/run_contracts_p1.sh',
    'chengwang/deploy/mihomo-p1-pair/run_leg.sh',
)
CONTROL_FILES = (
    'pair-context.json', 'source-before.json', 'controller-before.json',
    'parent-resource-before.json', 'inner-source.json', 'inner-binding.json', 'inner-resource-before.json',
    'inner-resource-after.json', 'supervision.jsonl', 'runner.json',
    'supervisor.stdout', 'supervisor.stderr', 'originals-fsync.json',
)
ORIGINALS_BEFORE_HOST_AFTER = (
    'host-before.json', 'ordinary.json', 'race.json', 'ordinary.stderr', 'race.stderr',
    'gofmt.patch', 'gofmt.stderr', 'execution.json', 'sandbox.json', 'go-version.txt',
)


def need(value):
    if not value:
        raise ValueError('p1 pair controller rejected')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stable_read(path, limit, empty=True):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts)
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


def fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write(path, raw, mode=0o644):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())


def append(path, value):
    raw = encoded(value)
    with Path(path).open('ab') as stream:
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60, check=False)
    need(result.returncode == 0)
    return result.stdout


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_profile_checker(source):
    return load(source / 'chengwang/deploy/mihomo-capacity-profile/check_profile.py',
                'p1_pair_source_profile_checker')


def source_profile_producer(source):
    return load(source / 'chengwang/deploy/mihomo-capacity-profile/profile_evidence.py',
                'p1_pair_source_profile_producer')


def source_snapshot(source):
    need(git(source, 'rev-parse', 'HEAD').strip().decode() == SOURCE_COMMIT)
    need(git(source, 'status', '--porcelain', '--untracked-files=all') == b'')
    return source_profile_checker(source).source_snapshot(source, SOURCE_COMMIT)


def controller_snapshot(controller, commit):
    need(re.fullmatch('[a-f0-9]{40}', commit) is not None)
    need(git(controller, 'rev-parse', 'HEAD').strip().decode() == commit)
    need(git(controller, 'status', '--porcelain', '--untracked-files=all') == b'')
    rows = []
    for name in CONTROLLER_FILES:
        path = controller / name
        raw = stable_read(path, 2 << 20)
        need(git(controller, 'show', commit + ':' + name) == raw)
        rows.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
    return {'schema': 'chengwang.p1-pair-controller-source/v1', 'controllerCommit': commit,
            'sourceCommit': SOURCE_COMMIT, 'files': rows, 'controllerGitVerified': True,
            'controllerGoFilesUsed': False}


def host_observation():
    value = {key: os.readlink('/proc/self/ns/' + kind)
             for key, kind in (('networkNamespace', 'net'), ('mountNamespace', 'mnt'),
                               ('pidNamespace', 'pid'))}
    value['resolvSHA256'] = sha(Path('/etc/resolv.conf').read_bytes())
    return value


def resource_observation(source, scope, phase):
    value = source_profile_producer(source).resource_observation()
    need(value['schema'] == 'chengwang.capacity-profile-resources/v1')
    value['schema'] = 'chengwang.p1-pair-resource-observation/v1'
    value['diagnosticMode'] = 'NORMAL_FLAGS_P1_DIAGNOSTIC'
    value['captureScope'] = scope
    value['phase'] = phase
    return value


def script_binding(source, controller):
    baseline = stable_read(source / 'chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh', 1 << 20)
    p1 = stable_read(controller / 'chengwang/deploy/mihomo-p1-pair/run_contracts_p1.sh', 1 << 20)
    old = (b'"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s '
           b'./internal/adapter/mihomo ./internal/mihomodeploy ./internal/authn ./internal/api '
           b'./internal/serverruntime ./internal/authz > "$out/race.json" 2> "$out/race.stderr"')
    new = old.replace(b' test -race ', b' test -p=1 -race ')
    need(baseline.count(old) == 1 and old != new and p1 == baseline.replace(old, new))
    return {'schema': 'chengwang.p1-pair-script-binding/v1', 'sourceCommit': SOURCE_COMMIT,
            'baselineSHA256': sha(baseline), 'p1SHA256': sha(p1),
            'onlyRaceP1TokenAdded': True, 'ordinaryPreludeUnchanged': True,
            'normalRaceFlagsUnchanged': True, 'runtimeGOMAXPROCSModified': False,
            'packages': ['./internal/adapter/mihomo', './internal/mihomodeploy', './internal/authn',
                         './internal/api', './internal/serverruntime', './internal/authz'],
            'goTestTimeoutSeconds': 180, 'historyEntries': 256, 'recordBytes': 2 << 20}


def context_value(controller_commit, run_id, attempt, order, position, leg, job):
    need(order in ('AB', 'BA') and leg in ('A', 'B') and order[position - 1] == leg)
    need(type(run_id) is type(attempt) is type(position) is int and run_id > 0 and attempt > 0 and position in (1, 2))
    need(re.fullmatch('[a-f0-9]{40}', controller_commit) is not None and
         re.fullmatch('[A-Za-z0-9:._-]{1,128}', job) is not None)
    return {'schema': 'chengwang.p1-pair-context/v1', 'measurementOnly': True,
            'production': False, 'sourceCommit': SOURCE_COMMIT,
            'controllerCommit': controller_commit, 'runID': run_id,
            'runAttempt': attempt, 'order': order, 'position': position, 'leg': leg,
            'job': job, 'pairID': f'{run_id}:{attempt}:{order}',
            'raceMode': 'ORIGINAL_DEFAULT_P' if leg == 'A' else 'ONLY_P_EQUALS_1_ADDED',
            'sameRunnerSameLoadProven': False, 'bMayReplaceOriginalAcceptance': False}


def prepare(args):
    source, controller, out, control = map(Path, (args.source, args.controller, args.out, args.control))
    need(out.is_dir() and control.is_dir() and not any(out.iterdir()) and not any(control.iterdir()))
    value = context_value(args.controller_commit, args.run_id, args.run_attempt,
                          args.order, args.position, args.leg, args.job)
    write(out / 'host-before.json', encoded(host_observation()))
    write(control / 'pair-context.json', encoded(value))
    write(control / 'source-before.json', encoded(source_snapshot(source)))
    write(control / 'controller-before.json', encoded(controller_snapshot(controller, args.controller_commit)))
    write(control / 'parent-resource-before.json',
          encoded(resource_observation(source, 'PARENT_CONTROLLER_PROCESS_AND_KERNEL_AGGREGATES', 'BEFORE')))
    fsync_dir(out)
    fsync_dir(control)


def inner_resource(args):
    need(sys.platform == 'linux' and os.geteuid() == 0 and args.phase in ('BEFORE', 'AFTER'))
    write(Path(args.out), encoded(resource_observation(Path(args.source),
          'ISOLATED_NAMESPACE_WRAPPER_PROCESS_AND_KERNEL_AGGREGATES_NOT_GO_PID', args.phase)), 0o644)
    fsync_dir(Path(args.out).parent)


def inner_binding(args):
    source, controller, goroot = map(Path, (args.source, args.controller, args.goroot))
    need(sys.platform == 'linux' and os.geteuid() == 0 and args.source_commit == SOURCE_COMMIT and
         re.fullmatch('[a-f0-9]{40}', args.controller_commit) is not None and args.leg in ('A', 'B'))
    readonly = lambda path: bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    value = {'schema': 'chengwang.p1-pair-inner-binding/v1', 'sourceCommit': SOURCE_COMMIT,
             'controllerCommit': args.controller_commit, 'leg': args.leg,
             'sourceReadOnly': readonly(source), 'controllerReadOnly': readonly(controller),
             'goRootReadOnly': readonly(goroot), 'sourceAndControllerDistinct':
                 not os.path.samefile(source, controller),
             'executedScriptClass': 'EXACT_SOURCE_NORMAL' if args.leg == 'A' else
                 'SOURCE_NORMAL_WITH_ONLY_RACE_P_EQUALS_1'}
    need(value['sourceReadOnly'] and value['controllerReadOnly'] and value['goRootReadOnly'] and
         value['sourceAndControllerDistinct'])
    write(Path(args.out), encoded(value), 0o644)
    fsync_dir(Path(args.out).parent)


def fsync_originals(args):
    out = Path(args.out)
    need(sys.platform == 'linux' and os.geteuid() == 0 and out.is_dir() and not out.is_symlink())
    rows = []
    for name in ORIGINALS_BEFORE_HOST_AFTER:
        path = out / name
        raw = stable_read(path, 64 << 20 if name in ('ordinary.json', 'race.json') else 2 << 20)
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        need(stable_read(path, len(raw)) == raw)
        rows.append({'name': name, 'bytes': len(raw), 'sha256': sha(raw), 'fsyncSucceeded': True})
    fsync_dir(out)
    write(Path(args.receipt), encoded({'schema': 'chengwang.p1-pair-originals-fsync/v1',
          'sourceCommit': SOURCE_COMMIT, 'files': rows,
          'outputDirectoryFsyncSucceeded': True}), 0o644)
    fsync_dir(Path(args.receipt).parent)


def supervise(args):
    need(sys.platform == 'linux' and os.geteuid() == 0 and hasattr(os, 'pidfd_open') and
         hasattr(signal, 'pidfd_send_signal'))
    controller, source, out, control, goroot = map(Path, (args.controller, args.source,
                                                          args.out, args.control, args.goroot))
    journal = control / 'supervision.jsonl'
    stdout_path, stderr_path = control / 'supervisor.stdout', control / 'supervisor.stderr'
    write(journal, b'', 0o644)
    started = time.monotonic_ns()
    target = ['/usr/bin/unshare', '--net', '--mount', '--pid', '--fork', '--mount-proc',
              '--kill-child=SIGKILL', '/bin/bash',
              str(controller / 'chengwang/deploy/mihomo-p1-pair/run_leg.sh'),
              str(source), str(controller), str(out), str(control), str(goroot),
              SOURCE_COMMIT, args.controller_commit, args.leg]
    append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': 1,
                     'event': 'START_INTENT', 'pid': None, 'pidfdAcquired': None,
                     'exitCode': None, 'monotonicNs': started, 'commandClass': 'ISOLATED_LEG'})
    process = None
    pidfd = None
    read_fd, write_fd = os.pipe()
    outcome = {'processExit': None, 'outerTimedOut': False, 'pidfdAcquired': False,
               'termSent': False, 'killSent': False, 'captureSupervisorComplete': False,
               'failureClass': 'NONE'}
    sequence = 1
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            gate = ['/bin/bash', '-c',
                    'fd="$1"; shift; IFS= read -r -n 1 gate <&"$fd" && test "$gate" = G && exec "$@"',
                    'p1-pair-gate', str(read_fd), *target]
            process = subprocess.Popen(gate, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       pass_fds=(read_fd,))
            os.close(read_fd); read_fd = -1
            sequence += 1
            append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': sequence,
                             'event': 'STARTED_GATED', 'pid': process.pid, 'pidfdAcquired': False,
                             'exitCode': None, 'monotonicNs': time.monotonic_ns(),
                             'commandClass': 'ISOLATED_LEG'})
            pidfd = os.pidfd_open(process.pid, 0)
            outcome['pidfdAcquired'] = True
            sequence += 1
            append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': sequence,
                             'event': 'PIDFD_ACQUIRED', 'pid': process.pid, 'pidfdAcquired': True,
                             'exitCode': None, 'monotonicNs': time.monotonic_ns(),
                             'commandClass': 'ISOLATED_LEG'})
            need(os.write(write_fd, b'G') == 1)
            os.close(write_fd); write_fd = -1
            sequence += 1
            append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': sequence,
                             'event': 'GATE_RELEASED', 'pid': process.pid, 'pidfdAcquired': True,
                             'exitCode': None, 'monotonicNs': time.monotonic_ns(),
                             'commandClass': 'ISOLATED_LEG'})
            try:
                outcome['processExit'] = process.wait(timeout=OUTER_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                outcome['outerTimedOut'] = True
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                outcome['termSent'] = True
                sequence += 1
                append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': sequence,
                                 'event': 'SIGTERM_SENT', 'pid': process.pid, 'pidfdAcquired': True,
                                 'exitCode': None, 'monotonicNs': time.monotonic_ns(),
                                 'commandClass': 'ISOLATED_LEG'})
                try:
                    outcome['processExit'] = process.wait(timeout=TERM_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    outcome['killSent'] = True
                    sequence += 1
                    append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': sequence,
                                     'event': 'SIGKILL_SENT', 'pid': process.pid, 'pidfdAcquired': True,
                                     'exitCode': None, 'monotonicNs': time.monotonic_ns(),
                                     'commandClass': 'ISOLATED_LEG'})
                    outcome['processExit'] = process.wait(timeout=TERM_GRACE_SECONDS)
            stdout.flush(); os.fsync(stdout.fileno())
            stderr.flush(); os.fsync(stderr.fileno())
        outcome['captureSupervisorComplete'] = True
    except Exception:
        outcome['failureClass'] = 'SUPERVISION_FAILED'
        if write_fd >= 0:
            os.close(write_fd); write_fd = -1
        if process is not None and pidfd is None:
            try:
                outcome['processExit'] = process.wait(timeout=TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                outcome['failureClass'] = 'GATED_CHILD_EXIT_UNCONFIRMED'
        if process is not None and pidfd is not None and process.poll() is None:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            outcome['killSent'] = True
            try:
                outcome['processExit'] = process.wait(timeout=TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                outcome['failureClass'] = 'SUPERVISION_CLEANUP_UNCONFIRMED'
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if pidfd is not None:
            os.close(pidfd)
    sequence += 1
    append(journal, {'schema': 'chengwang.p1-pair-supervision-event/v1', 'sequence': sequence,
                     'event': 'WAIT_RETURNED', 'pid': None if process is None else process.pid,
                     'pidfdAcquired': outcome['pidfdAcquired'], 'exitCode': outcome['processExit'],
                     'monotonicNs': time.monotonic_ns(), 'commandClass': 'ISOLATED_LEG'})
    outcome.update({'schema': 'chengwang.p1-pair-runner/v1', 'leg': args.leg,
                    'sourceCommit': SOURCE_COMMIT, 'controllerCommit': args.controller_commit,
                    'outerTimeoutSeconds': OUTER_TIMEOUT_SECONDS,
                    'termGraceSeconds': TERM_GRACE_SECONDS, 'measurementOnly': True,
                    'production': False, 'finishedMonotonicNs': time.monotonic_ns(),
                    'startedMonotonicNs': started})
    write(control / 'runner.json', encoded(outcome))
    fsync_dir(control)
    return 0 if outcome['captureSupervisorComplete'] else 2


def finish(args):
    source, controller, out, control = map(Path, (args.source, args.controller, args.out, args.control))
    write(out / 'host-after.json', encoded(host_observation()))
    write(control / 'source-after.json', encoded(source_snapshot(source)))
    write(control / 'controller-after.json', encoded(controller_snapshot(controller, args.controller_commit)))
    write(control / 'parent-resource-after.json',
          encoded(resource_observation(source, 'PARENT_CONTROLLER_PROCESS_AND_KERNEL_AGGREGATES', 'AFTER')))
    write(control / 'script-binding.json', encoded(script_binding(source, controller)))
    copied = []
    for name in (*CONTROL_FILES, 'source-after.json', 'controller-after.json',
                 'parent-resource-after.json', 'script-binding.json'):
        path = control / name
        if path.is_file() and not path.is_symlink():
            limit = 160 << 20 if name.startswith('source-') else 4 << 20
            write(out / name, stable_read(path, limit), 0o644)
            copied.append(name)
    runner = json.loads(stable_read(control / 'runner.json', 16384)) if (control / 'runner.json').is_file() else {}
    required = set((*CONTROL_FILES, 'source-after.json', 'controller-after.json',
                    'parent-resource-after.json', 'script-binding.json'))
    receipt = {'schema': 'chengwang.p1-pair-leg-receipt/v1', 'leg': args.leg,
               'sourceCommit': SOURCE_COMMIT, 'controllerCommit': args.controller_commit,
               'measurementOnly': True, 'production': False,
               'captureCandidateComplete': set(copied) == required and args.supervise_exit == 0 and
                   runner.get('captureSupervisorComplete') is True,
               'superviseExit': args.supervise_exit, 'copiedControlFiles': sorted(copied),
               'goAcceptanceEvaluated': False, 'bMayReplaceOriginalAcceptance': False,
               'sameRunnerSameLoadProven': False}
    write(out / 'leg-receipt.json', encoded(receipt))
    fsync_dir(control)
    fsync_dir(out)


def parser():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest='action', required=True)
    prepare_parser = sub.add_parser('prepare')
    for name in ('controller', 'source', 'out', 'control', 'controller-commit', 'order', 'leg', 'job'):
        prepare_parser.add_argument('--' + name, required=True)
    prepare_parser.add_argument('--run-id', type=int, required=True)
    prepare_parser.add_argument('--run-attempt', type=int, required=True)
    prepare_parser.add_argument('--position', type=int, required=True)
    supervise_parser = sub.add_parser('supervise')
    for name in ('controller', 'source', 'out', 'control', 'goroot', 'controller-commit', 'leg'):
        supervise_parser.add_argument('--' + name, required=True)
    finish_parser = sub.add_parser('finish')
    for name in ('controller', 'source', 'out', 'control', 'controller-commit', 'leg'):
        finish_parser.add_argument('--' + name, required=True)
    finish_parser.add_argument('--supervise-exit', type=int, required=True)
    inner = sub.add_parser('inner-resource')
    inner.add_argument('--source', required=True)
    inner.add_argument('--phase', choices=('BEFORE', 'AFTER'), required=True)
    inner.add_argument('--out', required=True)
    binding = sub.add_parser('inner-binding')
    for name in ('source', 'controller', 'goroot', 'source-commit', 'controller-commit', 'leg', 'out'):
        binding.add_argument('--' + name, required=True)
    fsync_parser = sub.add_parser('fsync-originals')
    fsync_parser.add_argument('--out', required=True)
    fsync_parser.add_argument('--receipt', required=True)
    return root


def main():
    args = parser().parse_args()
    if args.action == 'prepare':
        prepare(args)
    elif args.action == 'supervise':
        raise SystemExit(supervise(args))
    elif args.action == 'finish':
        finish(args)
    elif args.action == 'inner-resource':
        inner_resource(args)
    elif args.action == 'inner-binding':
        inner_binding(args)
    else:
        fsync_originals(args)


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        raise SystemExit('P1_PAIR_CONTROLLER=REJECTED raw_input_suppressed=true') from None
