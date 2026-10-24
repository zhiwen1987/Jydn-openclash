"""Trusted CI scene supervision; no application I/O or process launch on import.

The registry is closed source code, not a caller-supplied adapter/command API.
Private projections are trusted CI observations, not database attestations.
"""
import base64
import hashlib
import importlib.util
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.parse

KEYS = ('subscription:create_receipt', 'subscription:local_admission',
        'subscription:remote_fetch', 'subscription:remote_handoff_negative',
        'capability_truth:default', 'capability_truth:backend_configured')
CORE_PATH = 'chengwang/deploy/browser-scene-supervisor/supervisor.py'
LEGACY_PATH = 'chengwang/deploy/subscription-ui-browser/run_subscription_ui.py'
CAPABILITY_PATH = 'chengwang/deploy/capability-truth-browser/capability_truth_scene.py'
CAPABILITY_ENTRY = 'chengwang/deploy/capability-truth-browser/run_capability_truth.py'
OVERVIEW_KEYS = ('overview_ui:evidence_disabled', 'overview_ui:evidence_enabled_unknown')
OVERVIEW_PATH = 'chengwang/deploy/overview-ui-browser/overview_ui_scene.py'
OVERVIEW_ENTRY = 'chengwang/deploy/overview-ui-browser/run_overview_ui.py'
PREFIX = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--bounding-set=-all',
          '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']


def need(value):
    if not value: raise ValueError('browser scene rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def select_key(family, scenario=None, profile=None):
    if family == 'subscription':
        need(profile is None and scenario in ('create_receipt', 'local_admission', 'remote_fetch', 'remote_handoff_negative'))
        return 'subscription:' + scenario
    need(family == 'capability_truth' and scenario is None and profile in ('default', 'backend_configured'))
    return 'capability_truth:' + profile


def load_scene_adapter(repo, key):
    need(key in KEYS and isinstance(repo, pathlib.Path))
    relative = LEGACY_PATH if key.startswith('subscription:') else CAPABILITY_PATH
    spec = importlib.util.spec_from_file_location('trusted_scene_' + key.replace(':', '_'), repo / relative)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def identity(commit, fixture, engine, key):
    need(key in KEYS)
    value = dict(schema='chengwang.subscription-ui-supervisor/v1' if key.startswith('subscription:') else
        'chengwang.capability-truth-supervisor/v1', sourceCommit=commit, fixtureId=fixture, engine=engine, production=False)
    if key.startswith('capability_truth:'): value.update(scenario='capability_truth', profile=key.split(':')[1])
    return value


def select_overview_key(profile):
    need(profile in ('evidence_disabled', 'evidence_enabled_unknown'))
    return 'overview_ui:' + profile


def scene_adapter(repo, key):
    if key in OVERVIEW_KEYS:
        need(isinstance(repo, pathlib.Path))
        spec = importlib.util.spec_from_file_location('trusted_overview_scene', repo / OVERVIEW_PATH)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module
    return load_scene_adapter(repo, key)


def scene_identity(commit, fixture, engine, key):
    if key in OVERVIEW_KEYS:
        return dict(schema='chengwang.overview-ui-supervisor/v1', sourceCommit=commit,
            fixtureId=fixture, engine=engine, production=False, scenario='overview_ui', profile=key.split(':')[1])
    return identity(commit, fixture, engine, key)


def scene_entry(key):
    if key in OVERVIEW_KEYS: return OVERVIEW_ENTRY
    need(key in KEYS)
    return LEGACY_PATH if key.startswith('subscription:') else CAPABILITY_ENTRY


def secret_variants(token):
    need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token))
    values = set()
    for text in (token, 'Bearer ' + token):
        raw = text.encode('ascii')
        values.update((raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b'='), raw.hex().encode('ascii'), raw.hex().upper().encode('ascii'),
            urllib.parse.quote(text, safe='').encode('ascii'), sha(raw).encode('ascii')))
    return sorted(values)


def safe_relative(value):
    need(type(value) is str and 0 < len(value) <= 512 and '\\' not in value and not value.startswith('/')
         and all(part not in ('', '.', '..') for part in value.split('/')))
    return value


def clean_owned(path, fixture):
    need(re.fullmatch('[a-f0-9]{32}', fixture) and path in (
        pathlib.Path('/tmp/chengwang-subscription-ui-' + fixture),
        pathlib.Path('/tmp/chengwang-subscription-ui-tools-' + fixture)))
    if path.exists():
        import shutil
        need(not path.is_symlink() and stat.S_ISDIR(path.lstat().st_mode))
        for current, dirs, _ in os.walk(path, followlinks=False):
            need(not pathlib.Path(current).is_symlink())
            for name in dirs: need(not (pathlib.Path(current) / name).is_symlink())
            pathlib.Path(current).chmod(0o700)
        shutil.rmtree(path)


def prepare_scene_inputs(options, repo, root, bundle, fixture, key, N, M):
    A = scene_adapter(repo, key)
    os.mkdir(root, 0o700); os.chown(root, 10001, 10001)
    os.mkdir(bundle, 0o750); os.chown(bundle, 0, 10001)
    records = []
    copy = lambda source, target, label, executable=False: M.copy_input(source, target, label, records, N, executable)
    receipt_raw = N.stable_read(options.consumption_report, 1 << 20)[0]; receipt = N.decode(receipt_raw)
    need(receipt['sourceCommit'] == options.source_commit and receipt['pinEnforced'] is True
         and receipt['browserExecuted'] is False and receipt['state'] == 'PIN_ENFORCED_EXPANDED_NOT_EXECUTED'
         and receipt['elf']['path'] == 'chrome-linux64/chrome')
    original = options.consumption_root / 'chrome-linux64'; need(original.is_dir() and not original.is_symlink())
    for path in sorted(original.rglob('*')):
        need(not path.is_symlink())
        if path.is_dir(): continue
        need(stat.S_ISREG(path.lstat().st_mode)); relative = path.relative_to(original).as_posix()
        copy(path, bundle / 'chrome' / relative, 'chrome/' + relative, bool(path.stat().st_mode & 0o100))
    chrome = bundle / 'chrome/chrome'; raw = N.stable_read(chrome, 512 << 20)[0]
    need(raw[:4] == b'\x7fELF' and sha(raw) == receipt['elf']['sha256'] and len(raw) == receipt['elf']['bytes'])
    copy(options.node, bundle / 'node', 'toolchain/node', True)
    copy(options.server, bundle / 'server', 'toolchain/server', True)
    server = N.stable_read(bundle / 'server', 128 << 20)[0]
    build_raw = N.stable_read(options.build_report, 1 << 20)[0]; build = N.decode(build_raw)
    files = []; manifest = None
    need(options.dist.is_dir() and not options.dist.is_symlink())
    for path in sorted(options.dist.rglob('*')):
        need(not path.is_symlink())
        if path.is_dir(): continue
        need(stat.S_ISREG(path.lstat().st_mode)); relative = safe_relative(path.relative_to(options.dist).as_posix())
        contents = N.stable_read(path, 16 << 20)[0]
        if relative == '.vite/manifest.json': manifest = contents
        files.append(dict(path=relative, bytes=len(contents), sha256=sha(contents)))
        copy(path, bundle / 'source/chengwang/web/dist' / relative, 'dist/' + relative)
    A.scene_validate_build(build, options.source_commit, server, files, manifest)
    copy(options.build_report, bundle / 'build.json', 'build/report.json')
    for relative in A.scene_source_files(key): copy(repo / relative, bundle / 'source' / relative, relative)
    for directory in A.scene_tool_directories(key):
        tools = repo / directory; need(tools.is_dir())
        for path in sorted(tools.glob('*')):
            if path.is_file() and path.suffix in ('.mjs', '.json'):
                label = path.relative_to(repo).as_posix(); copy(path, bundle / 'source' / label, label)
    package = repo / 'chengwang/tools/subscription-ui-browser/node_modules/playwright-core'
    need(package.is_dir() and not package.is_symlink())
    for path in sorted(package.rglob('*')):
        need(not path.is_symlink())
        if path.is_dir(): continue
        relative = path.relative_to(package).as_posix()
        copy(path, bundle / 'source/chengwang/tools/subscription-ui-browser/node_modules/playwright-core' / relative,
             'npm/playwright-core/' + relative)
    launcher = 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py'
    copy(repo / launcher, bundle / 'ui-chrome-launcher', launcher + ':launcher', True)
    N.exclusive(bundle / 'launch.json', N.canonical(dict(schema='chengwang.subscription-ui-launch/v1',
        engine=options.engine, fixtureId=fixture, root=str(root), chrome=str(chrome), chromeSHA256=receipt['elf']['sha256'])), 0o440)
    passwd = ('root:x:0:0:root:/root:/usr/sbin/nologin\nui:x:10001:10001:ui:' + str(root / 'home') + ':/usr/sbin/nologin\n').encode()
    N.exclusive(bundle / 'passwd', passwd, 0o440); N.exclusive(bundle / 'group', b'root:x:0:\nui:x:10001:\n', 0o440)
    for path in (bundle / 'launch.json', bundle / 'passwd', bundle / 'group'): os.chown(path, 0, 10001)
    for current, dirs, _ in os.walk(bundle):
        for name in dirs:
            path = pathlib.Path(current) / name; os.chown(path, 0, 10001); path.chmod(0o550)
    bundle.chmod(0o550)
    N.exclusive(options.output_dir / 'inputs.json', N.canonical(dict(scene_identity(options.source_commit, fixture, options.engine, key),
        copiedInputs=records, inputTrustScope='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')) + b'\n')
    N.exclusive(options.output_dir / 'pin-consumption.json', receipt_raw)
    N.exclusive(options.output_dir / 'build.json', build_raw)


def export_scene_evidence(options, root, key, N, *, partial=False):
    repo = options.repo.resolve(strict=True); A = scene_adapter(repo, key)
    policy = A.scene_export_policy(root, key, N, partial)
    if policy is None: return []
    names, forbidden = policy; exported = []
    for private, public, budget in names:
        source, target = root / private, options.output_dir / public
        if partial and (not source.exists() or target.exists()): continue
        try:
            raw = N.stable_read(source, budget, 10001, 0o600)[0]
            A.scene_fence_public(raw, public, forbidden, key, N, partial)
            if public.endswith('.png'): need(raw.startswith(b'\x89PNG\r\n\x1a\n'))
            else:
                values = [N.decode(row) for row in raw.splitlines()] if public.endswith('.jsonl') else [N.decode(raw)]
                need(values and all(type(value) is dict for value in values))
            N.exclusive(target, raw); exported.append(public)
        except Exception:
            if not partial: raise
    return exported


def wait_server(root, server, N):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        need(server.poll() is None)
        raw = N.stable_read(root / 'server.private.log', 1 << 20)[0]
        if b'chengwang listening (mode=candidate)' in raw: return
        time.sleep(0.02)
    need(False)


class RunState:
    def __init__(self):
        self.server = self.node = self.wire = None
        self.wire_ready = None; self.records = []; self.stage = 'SERVER_START'
        self.succeeded = False; self.forced = 0; self.forbidden = []; self.server_env = None
        self.upstream_before = None; self.runtime = None


def supervise_scene(options, repo, root, bundle, fixture, key, N, M, L):
    A = scene_adapter(repo, key); state = RunState()
    need(os.geteuid() == 0 and os.getpid() == 1)
    N.command(['mount', '--make-rprivate', '/']); N.mount_bind(repo, True); N.mount_bind(bundle, True)
    N.command(['ip', 'link', 'set', 'lo', 'up'])
    need(len(N.command(['ip', '-o', 'link', 'show']).splitlines()) == 1
         and not N.command(['ip', '-4', 'route', 'show', 'default']) and not N.command(['ip', '-6', 'route', 'show', 'default']))
    extra_isolation = A.scene_namespace_extra(state, root, fixture, key, N)
    N.command(['mount', '-t', 'tmpfs', '-o', 'size=64m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec',
               'chengwang-subscription-ui-short-tmp', '/var/tmp'])
    for source, target in (('passwd', '/etc/passwd'), ('group', '/etc/group')):
        N.command(['mount', '--bind', str(bundle / source), target]); N.command(['mount', '-o', 'remount,bind,ro,nosuid,nodev', target])
    certs = M.certificates(root, N)
    N.exclusive(options.output_dir / 'certificates.json', N.canonical(certs) + b'\n')
    state.forbidden = A.scene_initialize(options, root, fixture, key, N)
    (root / 'data').mkdir(mode=0o700); os.chown(root / 'data', 10001, 10001)
    try:
        A.scene_start_auxiliary(state, options, root, bundle, fixture, key, N, M, PREFIX)
        with (root / 'server.private.log').open('xb') as log:
            state.server_env = A.scene_child_environment(root, bundle, key)
            state.server = subprocess.Popen([*PREFIX, str(bundle / 'server')], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, env=state.server_env, cwd=root, preexec_fn=M.child_limits)
        wait_server(root, state.server, N); state.stage = 'DRIVER_START'
        with (root / 'driver.private.log').open('xb') as log:
            if key == 'subscription:remote_handoff_negative': os.fchmod(log.fileno(), 0o600)
            state.node = subprocess.Popen([*PREFIX, str(bundle / 'node'), str(bundle / 'source' / A.scene_driver_entry(key)),
                '--root', str(root), '--bundle', str(bundle), '--engine', options.engine, '--source-commit', options.source_commit],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=dict(N.BASE_ENV, TMPDIR='/var/tmp'),
                cwd=root, preexec_fn=M.child_limits)
        state.stage = 'DRIVER_BARRIER'; barrier = M.wait_file(root / 'driver-ready.private.json', state.node, N, 45)
        need(barrier == A.scene_ready_message(fixture, options.engine, key, state.node.pid, barrier.get('chromePid')))
        handoff = N.decode(N.stable_read(root / 'chrome-process.private.json', 8192, 10001, 0o600)[0])
        need(type(barrier['chromePid']) is int and handoff['pid'] == barrier['chromePid'] and handoff['uid'] == 10001)
        tasks = [('server', state.server.pid, bundle / 'server', 128 << 20),
            ('controller', state.node.pid, bundle / 'node', 256 << 20), ('chrome', handoff['pid'], bundle / 'chrome/chrome', 512 << 20)]
        if state.wire is not None: tasks.append(('wire', state.wire.pid, pathlib.Path(sys.executable).resolve(strict=True), 128 << 20))
        L.append_process_records(tasks, state.records, N)
        A.scene_before_run(state, options, root, bundle, fixture, key, N)
        state.stage = 'UI_RUN'; N.publish_atomic(root / 'run.go', N.canonical(A.scene_run_message(fixture, options.engine, key)), 0o444)
        need(state.node.wait(timeout=125) == 0)
        state.stage = 'SERVER_STOP'; state.server.send_signal(signal.SIGTERM); need(state.server.wait(timeout=15) == 0)
        extra = A.scene_stop_auxiliary(state, options, root, fixture, key, N)
        state.stage = 'PROCESS_REAP'
        need(M.no_owned_processes() and all(not pathlib.Path('/proc', str(row['pid'])).exists() for row in state.records))
        need(extra == (dict(wireExitCode=0) if state.wire is not None else {}))
        N.exclusive(options.output_dir / 'processes.json', N.canonical(dict(scene_identity(options.source_commit, fixture, options.engine, key),
            records=state.records, serverExitCode=0, controllerExitCode=0, noLiveOwnedProcesses=True, forcedSignals=0,
            processScope='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION', **extra)) + b'\n')
        state.stage = 'READBACK'; A.scene_post_stop(state, options, root, fixture, key, N)
        state.stage = 'EXPORT'; export_scene_evidence(options, root, key, N)
        N.exclusive(options.output_dir / 'inner-isolation.private.json', N.canonical(dict(
            namespaces=N.ns(), defaultIPv4Routes=0, defaultIPv6Routes=0, interfaces=['lo'],
            sourceMount=N.mount_flags('self', repo), bundleMount=N.mount_flags('self', bundle),
            tmpMount=N.mount_flags('self', '/var/tmp'), **extra_isolation)) + b'\n')
        A.scene_inner_success(state, options, root, fixture, key, N)
        state.succeeded = True
    finally:
        state.forced = L.terminate_children((state.node, state.server, state.wire), state.forced)
        if not state.succeeded:
            no_owned = M.no_owned_processes(); exported = export_scene_evidence(options, root, key, N, partial=True)
            details = A.scene_failure_diagnostics(state, options, root, fixture, key, N)
            N.exclusive(options.output_dir / 'failure.json', N.canonical(dict(scene_identity(options.source_commit, fixture, options.engine, key),
                stage=state.stage, serverExitCode=None if state.server is None else state.server.poll(),
                controllerExitCode=None if state.node is None else state.node.poll(), records=state.records,
                forcedSignals=state.forced, noLiveOwnedProcesses=no_owned, capturedOriginals=exported,
                acceptance='REJECTED_DIAGNOSTIC_ONLY', **details)) + b'\n')


def run_scene_outer(options, repo, root, bundle, fixture, key, N, M, L):
    A = scene_adapter(repo, key)
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux' and options.fixture is None)
    options.output_dir = options.output_dir.absolute(); need(not options.output_dir.exists()); options.output_dir.mkdir(mode=0o700)
    before, source_before = N.host_observation(repo, options.source_commit)
    try:
        prepare_scene_inputs(options, repo, root, bundle, fixture, key, N, M)
        entry = scene_entry(key)
        argv = ['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc',
            sys.executable, '-I', '-B', str(repo / entry), '--inner', '--fixture', fixture,
            '--source-commit', options.source_commit, '--engine', options.engine]
        if key.startswith('subscription:'):
            scenario = key.split(':')[1]
            if scenario != 'create_receipt': argv += ['--scenario', scenario]
        else: argv += ['--profile', key.split(':')[1]]
        for name in ('repo', 'consumption-root', 'consumption-report', 'node', 'server', 'dist', 'build-report', 'output-dir'):
            argv += ['--' + name, str(getattr(options, name.replace('-', '_')))]
        with (bundle / 'supervisor.private.log').open('xb') as log:
            if key == 'subscription:remote_handoff_negative': os.fchmod(log.fileno(), 0o600)
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=dict(N.BASE_ENV), cwd='/')
            timed_out = L.wait_namespace(child, wait_seconds=225, terminate_seconds=5, kill_seconds=3)
        after, source_after = N.host_observation(repo, options.source_commit)
        need(before == after and source_before == source_after)
        if child.returncode != 0 or timed_out:
            export_scene_evidence(options, root, key, N, partial=True)
            N.exclusive(options.output_dir / 'failed-host-readback.json', N.canonical(dict(scene_identity(options.source_commit, fixture, options.engine, key),
                hostBefore=before, hostAfter=after, sourceFilesBefore=source_before, sourceFilesAfter=source_after,
                innerExitCode=child.returncode, innerTimedOut=timed_out, acceptance='REJECTED_DIAGNOSTIC_ONLY')) + b'\n'); need(False)
        isolation = N.decode(N.stable_read(options.output_dir / 'inner-isolation.private.json')[0])
        N.exclusive(options.output_dir / 'isolation.json', N.canonical(dict(scene_identity(options.source_commit, fixture, options.engine, key),
            hostBefore=before, hostAfter=after, sourceFilesBefore=source_before, sourceFilesAfter=source_after,
            lab=isolation, authorization='BLOCKED', deviceActionsExecuted=False, pythonBinaryProvenanceProven=False)) + b'\n')
        (options.output_dir / 'inner-isolation.private.json').unlink()
        need({path.name for path in options.output_dir.iterdir()} == A.scene_public_files(key, options))
        A.scene_outer_success(options, root, bundle, fixture, key, N)
    finally:
        clean_owned(root, fixture); clean_owned(bundle, fixture); A.scene_cleanup(fixture, key)
