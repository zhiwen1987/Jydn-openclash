"""Real isolated CI fixture; never a product/browser-UI acceptance shortcut."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

SCHEMA = 'chengwang.stream-matrix-supervisor/v1'
PUBLIC = {'driver.json', 'network.jsonl', 'server-events.jsonl', 'processes.json',
          'isolation.json', 'certificates.json', 'inputs.json', 'pin-consumption.json'}
SOURCE_FILES = [
    'chengwang/deploy/browser-stream-matrix/run_matrix.py',
    'chengwang/deploy/browser-stream-matrix/server.py',
    'chengwang/deploy/browser-stream-matrix/chrome_launcher.py',
    'chengwang/web/scripts/trust-browser-tls.mjs',
]


def need(value):
    if not value: raise ValueError('stream matrix rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def load_native(repo):
    path = repo / 'chengwang/deploy/probe-readback/run_probe_readback.py'
    spec = importlib.util.spec_from_file_location('stream_matrix_native_primitives', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def clean_owned(path, fixture):
    """Only this invocation's two exact CI UUID directories, never a glob/root."""
    need(path in (pathlib.Path('/tmp/chengwang-stream-matrix-' + fixture),
                  pathlib.Path('/tmp/chengwang-stream-tools-' + fixture)))
    need(re.fullmatch(r'[a-f0-9]{32}', fixture))
    if path.exists():
        need(not path.is_symlink() and stat.S_ISDIR(path.lstat().st_mode))
        # These are newly allocated private inputs, not a checkout/user tree.
        for current, dirs, _ in os.walk(path, followlinks=False):
            need(not pathlib.Path(current).is_symlink())
            for name in dirs: need(not (pathlib.Path(current) / name).is_symlink())
            pathlib.Path(current).chmod(0o700)
        shutil.rmtree(path)


def wait_file(path, child, N, seconds=25):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if path.exists():
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and 0 < info.st_size <= 8192)
            # Node publishes a complete fsynced pending file with exclusive
            # link/unlink. Wait only for that observable two-link handoff.
            need(info.st_nlink in (1, 2))
            if info.st_nlink == 1:
                return N.decode(N.stable_read(path, 8192, owner=10001, mode=0o600)[0])
        need(child.poll() is None)
        time.sleep(0.02)
    raise ValueError('stream matrix handshake deadline')


def no_owned_processes():
    """PID1 reaps orphaned grandchildren, then proves this private UID is gone."""
    until = time.monotonic() + 3
    while time.monotonic() < until:
        try:
            while os.waitpid(-1, os.WNOHANG)[0]: pass
        except ChildProcessError: pass
        remaining = []
        for path in pathlib.Path('/proc').iterdir():
            if not path.name.isdigit(): continue
            try:
                status = (path / 'status').read_text()
            except FileNotFoundError: continue
            uid = re.search(r'^Uid:\s+([0-9]+)', status, re.M)
            if uid and int(uid[1]) == 10001: remaining.append(path.name)
        if not remaining: return True
        time.sleep(0.02)
    return False


def copy_input(source, target, label, records, N, executable=False):
    raw, info = N.stable_read(source, 512 << 20)
    need(not info.st_mode & 0o022 and (len(raw) > 0 or not executable))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    N.exclusive(target, raw, 0o550 if executable else 0o440)
    os.chown(target, 0, 10001)
    need(N.stable_read(target, 512 << 20)[0] == raw)
    records.append(dict(path=label, bytes=len(raw), sha256=sha(raw)))


def prepare(options, repo, root, bundle, fixture, N):
    os.mkdir(root, 0o700); os.chown(root, 10001, 10001)
    os.mkdir(bundle, 0o750); os.chown(bundle, 0, 10001)
    records = []
    receipt_raw = N.stable_read(options.consumption_report, 1 << 20)[0]
    receipt = N.decode(receipt_raw)
    need(receipt['sourceCommit'] == options.source_commit and receipt['pinEnforced'] is True
         and receipt['browserExecuted'] is False and receipt['state'] == 'PIN_ENFORCED_EXPANDED_NOT_EXECUTED')
    need(receipt['elf']['path'] == 'chrome-linux64/chrome')
    original = options.consumption_root / 'chrome-linux64'
    need(original.is_dir() and not original.is_symlink())
    for path in sorted(original.rglob('*')):
        need(not path.is_symlink())
        if path.is_dir(): continue
        need(stat.S_ISREG(path.lstat().st_mode))
        relative = path.relative_to(original).as_posix()
        copy_input(path, bundle / 'chrome' / relative, 'chrome/' + relative, records, N,
                   executable=bool(path.stat().st_mode & 0o100))
    chrome = bundle / 'chrome/chrome'
    chrome_raw = N.stable_read(chrome, 512 << 20)[0]
    need(chrome_raw[:4] == b'\x7fELF' and sha(chrome_raw) == receipt['elf']['sha256']
         and len(chrome_raw) == receipt['elf']['bytes'])
    copy_input(options.node, bundle / 'node', 'toolchain/node', records, N, True)
    for relative in SOURCE_FILES:
        copy_input(repo / relative, bundle / 'source' / relative, relative, records, N)
    copy_input(repo / SOURCE_FILES[2], bundle / 'matrix-chrome-launcher', SOURCE_FILES[2] + ':launcher', records, N, True)
    tools = repo / 'chengwang/tools/browser-stream-matrix'
    for path in sorted(tools.glob('*')):
        if path.is_file() and path.suffix in ('.mjs', '.json'):
            label = path.relative_to(repo).as_posix()
            copy_input(path, bundle / 'source' / label, label, records, N)
    package = tools / 'node_modules/playwright-core'
    for path in sorted(package.rglob('*')):
        need(not path.is_symlink())
        if path.is_dir(): continue
        relative = path.relative_to(package).as_posix()
        copy_input(path, bundle / 'source/chengwang/tools/browser-stream-matrix/node_modules/playwright-core' / relative,
                   'npm/playwright-core/' + relative, records, N)
    need(any(row['path'] == 'npm/playwright-core/package.json' for row in records))
    N.exclusive(bundle / 'launch.json', N.canonical(dict(schema='chengwang.stream-matrix-launch/v1',
        engine=options.engine, fixtureId=fixture, root=str(root), chrome=str(chrome),
        chromeSHA256=receipt['elf']['sha256'])), 0o440)
    os.chown(bundle / 'launch.json', 0, 10001)
    passwd = ('root:x:0:0:root:/root:/usr/sbin/nologin\nstream:x:10001:10001:stream:'
              + str(root / 'home') + ':/usr/sbin/nologin\n').encode()
    N.exclusive(bundle / 'passwd', passwd, 0o440)
    N.exclusive(bundle / 'group', b'root:x:0:\nstream:x:10001:\n', 0o440)
    for path in (bundle / 'passwd', bundle / 'group'): os.chown(path, 0, 10001)
    for current, dirs, _ in os.walk(bundle):
        for name in dirs:
            path = pathlib.Path(current) / name; os.chown(path, 0, 10001); path.chmod(0o550)
    bundle.chmod(0o550)
    N.exclusive(options.output_dir / 'inputs.json', N.canonical(dict(schema=SCHEMA,
        sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine, copiedInputs=records,
        inputTrustScope='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD', production=False)) + b'\n')
    N.exclusive(options.output_dir / 'pin-consumption.json', receipt_raw)


def certificates(root, N):
    ca, cert, key = root / 'api-ca.pem', root / 'api-leaf.pem', root / 'api-leaf.key'
    ca_key, csr, ext = root / 'ca.key', root / 'leaf.csr', root / 'leaf.ext'
    N.command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=Chengwang Stream Matrix CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', str(ca_key), '-out', str(ca)])
    N.command(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1',
        '-keyout', str(key), '-out', str(csr)])
    N.exclusive(ext, b'basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', 0o600)
    N.command(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key),
        '-set_serial', '17', '-days', '1', '-extfile', str(ext), '-out', str(cert)])
    for path in root.iterdir():
        if path.is_file(): path.chmod(0o600); os.chown(path, 10001, 10001)
    # The low-privilege driver creates its own exclusive profile and XDG home.
    # Precreating that profile here would incorrectly make its mkdir fail.
    return dict(caPEM=N.stable_read(ca, 65536)[0].decode('ascii'),
                leafPEM=N.stable_read(cert, 65536)[0].decode('ascii'))


def child_limits():
    import resource
    for kind, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 180),
        (resource.RLIMIT_FSIZE, 32 << 20), (resource.RLIMIT_NOFILE, 1024), (resource.RLIMIT_NPROC, 1024)):
        resource.setrlimit(kind, (value, value))
    os.umask(0o077)


def export_observations(options, root, N, *, partial=False):
    """Preserve original bounded protocol records even when acceptance fails.

    No raw stderr, profile, browser archive or private key is exported. These
    trusted CI writers emit structured observations, not arbitrary page text.
    A partial capture is diagnostic only and can never satisfy the closed gate.
    """
    exported = []
    def no_secret_fields(value):
        if type(value) is dict:
            for key, item in value.items():
                need(type(key) is str and key.lower() not in ('token', 'password', 'secret', 'privatekey',
                    'private_key', 'authorization', 'cookie', 'bearer', 'access_token', 'refresh_token'))
                no_secret_fields(item)
        elif type(value) is list:
            for item in value: no_secret_fields(item)
    for private, public in [('matrix-driver.private.json', 'driver.json'),
        ('network.private.jsonl', 'network.jsonl'), ('server-events.private.jsonl', 'server-events.jsonl')]:
        source, target = root / private, options.output_dir / public
        if partial and (not source.exists() or target.exists()): continue
        try:
            raw = N.stable_read(source, 1 << 20, owner=10001, mode=0o600)[0]
            need(raw and b'PRIVATE KEY' not in raw and b'Bearer ' not in raw)
            values = [N.decode(line) for line in raw.splitlines()] if public.endswith('.jsonl') else [N.decode(raw)]
            need(values and all(type(value) is dict for value in values))
            for value in values: no_secret_fields(value)
            N.exclusive(target, raw); exported.append(public)
        except Exception:
            if not partial: raise
            # One malformed original must not destroy the other originals or
            # prevent a fixed failure receipt. Its name is absent from exported.
            continue
    return exported


def inner(options, repo, root, bundle, fixture, N):
    need(os.geteuid() == 0 and os.getpid() == 1)
    N.command(['mount', '--make-rprivate', '/'])
    N.mount_bind(repo, True); N.mount_bind(bundle, True)
    N.command(['ip', 'link', 'set', 'lo', 'up'])
    need(len(N.command(['ip', '-o', 'link', 'show']).splitlines()) == 1
         and not N.command(['ip', '-4', 'route', 'show', 'default'])
         and not N.command(['ip', '-6', 'route', 'show', 'default']))
    N.command(['mount', '-t', 'tmpfs', '-o', 'size=64m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec',
               'chengwang-stream-short-tmp', '/var/tmp'])
    for source, target in (('passwd', '/etc/passwd'), ('group', '/etc/group')):
        N.command(['mount', '--bind', str(bundle / source), target])
        N.command(['mount', '-o', 'remount,bind,ro,nosuid,nodev', target])
    certs = certificates(root, N)
    N.exclusive(options.output_dir / 'certificates.json', N.canonical(certs) + b'\n')
    environment = dict(N.BASE_ENV, TMPDIR='/var/tmp')
    prefix = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--bounding-set=-all',
              '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']
    server = node = None
    records = []
    succeeded = False
    stage = 'SERVER_START'
    forced = 0
    try:
        with (root / 'server.private.log').open('xb') as log:
            server = subprocess.Popen([*prefix, sys.executable, '-I', '-B',
                str(bundle / 'source/chengwang/deploy/browser-stream-matrix/server.py'), '--root', str(root)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment, cwd=root, preexec_fn=child_limits)
        ready = wait_file(root / 'ready.private.json', server, N)
        need(ready == dict(schema='chengwang.stream-matrix-ready/v1', fixtureId=fixture,
                          origin='https://127.0.0.1:17881', pid=server.pid, uid=10001))
        stage = 'DRIVER_START'
        with (root / 'driver.private.log').open('xb') as log:
            node = subprocess.Popen([*prefix, str(bundle / 'node'),
                str(bundle / 'source/chengwang/tools/browser-stream-matrix/matrix-cli.mjs'),
                '--root', str(root), '--bundle', str(bundle), '--engine', options.engine,
                '--source-commit', options.source_commit], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                env=environment, cwd=root, preexec_fn=child_limits)
        stage = 'DRIVER_BARRIER'
        barrier = wait_file(root / 'driver-ready.private.json', node, N, 45)
        need(barrier['schema'] == 'chengwang.stream-matrix-driver-ready/v1' and barrier['fixtureId'] == fixture
             and barrier['engine'] == options.engine and barrier['pid'] == node.pid)
        handoff = N.decode(N.stable_read(root / 'chrome-process.private.json', 8192, 10001, 0o600)[0])
        need(handoff['pid'] == barrier['chromePid'] and handoff['uid'] == 10001)
        for role, pid, executable, limit in [('server', server.pid, pathlib.Path(sys.executable).resolve(), 128 << 20),
            ('controller', node.pid, bundle / 'node', 256 << 20),
            ('chrome', handoff['pid'], bundle / 'chrome/chrome', 512 << 20)]:
            raw = N.stable_read(executable, limit)[0]
            record = N.task_profile(pid, sha(raw), executable_limit=limit)
            record.update(role=role, argv=pathlib.Path('/proc', str(pid), 'cmdline').read_bytes()[:-1].decode().split('\0'))
            records.append(record)
        stage = 'MATRIX_RUN'
        N.publish_atomic(root / 'run.go', N.canonical(dict(schema='chengwang.stream-matrix-run/v1',
                         fixtureId=fixture, engine=options.engine)), 0o444)
        need(node.wait(timeout=100) == 0)
        stage = 'SERVER_STOP'
        server.send_signal(signal.SIGTERM); need(server.wait(timeout=8) == 0)
        stage = 'PROCESS_REAP'
        need(no_owned_processes() and all(not pathlib.Path('/proc', str(row['pid'])).exists() for row in records))
        N.exclusive(options.output_dir / 'processes.json', N.canonical(dict(schema=SCHEMA,
            sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine, records=records,
            serverExitCode=0, controllerExitCode=0, noLiveOwnedProcesses=True, forcedSignals=0,
            processScope='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION', production=False)) + b'\n')
        stage = 'EXPORT'
        export_observations(options, root, N)
        N.exclusive(options.output_dir / 'inner-isolation.private.json', N.canonical(dict(
            namespaces=N.ns(), defaultIPv4Routes=0, defaultIPv6Routes=0, interfaces=['lo'],
            sourceMount=N.mount_flags('self', repo), bundleMount=N.mount_flags('self', bundle),
            tmpMount=N.mount_flags('self', '/var/tmp'))) + b'\n')
        succeeded = True
    finally:
        for child in (node, server):
            if child is not None and child.poll() is None:
                # A termination signal to a still-running controller is a
                # failed-path intervention, not a normal browser shutdown.
                if child is node: forced += 1
                child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    forced += 1; child.kill(); child.wait(timeout=3)
        if not succeeded:
            no_owned = no_owned_processes()
            exported = export_observations(options, root, N, partial=True)
            checkpoints = []
            log = root / 'driver.private.log'
            if log.exists():
                # Only fixed enums survive. Never publish raw private stderr.
                raw = N.stable_read(log, 32 << 20)[0]
                checkpoints = [v.decode('ascii') for v in re.findall(
                    rb'^STREAM_MATRIX_STAGE=(ENVIRONMENT|NSS|LAUNCH|IDENTITY|SUPERVISOR_GATE|NAVIGATE|SPLIT|BOUNDARY|OVERSIZE|TRUNCATED|ABORT|CLOSE|COMPLETE)$', raw, re.M)]
            N.exclusive(options.output_dir / 'failure.json', N.canonical(dict(schema=SCHEMA,
                sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine,
                stage=stage, driverCheckpoints=checkpoints, serverExitCode=None if server is None else server.poll(),
                controllerExitCode=None if node is None else node.poll(), records=records,
                forcedSignals=forced, noLiveOwnedProcesses=no_owned, capturedOriginals=exported,
                acceptance='REJECTED_DIAGNOSTIC_ONLY', production=False)) + b'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--consumption-root', required=True, type=pathlib.Path)
    parser.add_argument('--consumption-report', required=True, type=pathlib.Path)
    parser.add_argument('--node', required=True, type=pathlib.Path)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    parser.add_argument('--output-dir', required=True, type=pathlib.Path)
    parser.add_argument('--fixture', default=None)
    parser.add_argument('--inner', action='store_true')
    options = parser.parse_args()
    need(sys.platform == 'linux' and os.geteuid() == 0)
    repo = options.repo.resolve(strict=True); N = load_native(repo)
    need(re.fullmatch(r'[a-f0-9]{40}', options.source_commit))
    fixture = options.fixture or uuid.uuid4().hex
    need(re.fullmatch(r'[a-f0-9]{32}', fixture))
    root = pathlib.Path('/tmp/chengwang-stream-matrix-' + fixture)
    bundle = pathlib.Path('/tmp/chengwang-stream-tools-' + fixture)
    if options.inner:
        inner(options, repo, root, bundle, fixture, N); return
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'
         and options.fixture is None)
    options.output_dir = options.output_dir.absolute()
    need(not options.output_dir.exists())
    options.output_dir.mkdir(mode=0o700)
    before, source_before = N.host_observation(repo, options.source_commit)
    try:
        prepare(options, repo, root, bundle, fixture, N)
        environment = dict(N.BASE_ENV)
        argv = ['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc',
            sys.executable, '-I', '-B', str(pathlib.Path(__file__).resolve()), '--inner', '--fixture', fixture,
            '--repo', str(repo), '--source-commit', options.source_commit, '--consumption-root', str(options.consumption_root),
            '--consumption-report', str(options.consumption_report), '--node', str(options.node), '--engine', options.engine,
            '--output-dir', str(options.output_dir)]
        with (bundle / 'supervisor.private.log').open('xb') as log:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment, cwd='/')
            timed_out = False
            try: inner_code = child.wait(timeout=190)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
                inner_code = child.returncode
        after, source_after = N.host_observation(repo, options.source_commit)
        need(before == after and source_before == source_after)
        if inner_code != 0 or timed_out:
            # A namespace-init watchdog failure may prevent its own finally.
            # Retain safe published originals from the exact new fixture, but
            # do not claim its process cleanup or normal exits were observed.
            export_observations(options, root, N, partial=True)
            N.exclusive(options.output_dir / 'failed-host-readback.json', N.canonical(dict(schema=SCHEMA,
                sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine,
                hostBefore=before, hostAfter=after, sourceFilesBefore=source_before, sourceFilesAfter=source_after,
                innerExitCode=inner_code, innerTimedOut=timed_out,
                acceptance='REJECTED_DIAGNOSTIC_ONLY', production=False)) + b'\n')
            need(False)
        isolation = N.decode(N.stable_read(options.output_dir / 'inner-isolation.private.json')[0])
        N.exclusive(options.output_dir / 'isolation.json', N.canonical(dict(schema=SCHEMA,
            sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine,
            hostBefore=before, hostAfter=after, sourceFilesBefore=source_before, sourceFilesAfter=source_after,
            lab=isolation, production=False, authorization='BLOCKED', deviceActionsExecuted=False,
            pythonBinaryProvenanceProven=False)) + b'\n')
        (options.output_dir / 'inner-isolation.private.json').unlink()
        need({p.name for p in options.output_dir.iterdir()} == PUBLIC)
        print('STREAM_MATRIX=CAPTURED independent_verification=pending production=false')
    finally:
        clean_owned(root, fixture); clean_owned(bundle, fixture)


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('STREAM_MATRIX=REJECTED raw_input_suppressed=true') from None
