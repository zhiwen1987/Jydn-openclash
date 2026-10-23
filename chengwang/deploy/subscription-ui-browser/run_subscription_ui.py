"""CI-only real product create/receipt UI collector, not full B01-B23 acceptance.

Only the isolated Linux worker executes this module's main. Import/unit tests
are pure. No DNS fixture, source fetch, publication or production action exists.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
import urllib.parse
import uuid

SCHEMA = 'chengwang.subscription-ui-supervisor/v1'
SCOPE = dict(tenantId='subscription-ui-lab', siteId='isolated', environment='candidate')
PUBLIC = {'driver.json', 'captures.jsonl', 'dom.jsonl', 'created-desktop.png', 'created-mobile.png',
          'processes.json', 'isolation.json', 'inputs.json', 'certificates.json', 'pin-consumption.json',
          'private-readback.json', 'audit-events.jsonl', 'audit-checkpoint.json', 'build.json'}
SOURCE_FILES = ['chengwang/deploy/subscription-ui-browser/run_subscription_ui.py',
    'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py',
    'chengwang/deploy/subscription-ui-browser/contract.json',
    'chengwang/deploy/browser-stream-matrix/run_matrix.py',
    'chengwang/web/scripts/trust-browser-tls.mjs']


def need(value):
    if not value: raise ValueError('subscription UI rejected')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def secret_variants(token):
    need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token))
    result = set()
    for text in (token, 'Bearer ' + token):
        raw = text.encode('ascii')
        result.update((raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b'='), raw.hex().encode('ascii'),
            raw.hex().upper().encode('ascii'), urllib.parse.quote(text, safe='').encode('ascii'), sha(raw).encode('ascii')))
    return sorted(result)


def public_fence(raw, forbidden, *, captures=False, N=None):
    need(type(raw) is bytes and raw and b'PRIVATE KEY' not in raw
         and not any(secret in raw for secret in forbidden))
    if captures:
        need(N is not None)
        lines = raw.splitlines(); need(0 < len(lines) <= 64); total = 0
        kinds = ('DOCUMENT', 'ASSET', 'SNAPSHOT', 'COLLECTION_ACCESS', 'SOURCES', 'CREATE', 'SOURCE_ACCESS', 'CANDIDATES', 'RECEIPT')
        for line in lines:
            value = N.decode(line)
            need(type(value) is dict and type(value.get('responseBase64')) is str and value.get('kind') in kinds)
            encoded = value['responseBase64']; body = base64.b64decode(encoded, validate=True)
            total += len(body)
            budget = 8 << 20 if value['kind'] in ('DOCUMENT', 'ASSET') else 65536
            need(len(body) <= budget and total <= 16 << 20 and base64.b64encode(body).decode('ascii') == encoded
                 and b'PRIVATE KEY' not in body and not any(secret in body for secret in forbidden))
    return raw


def driver_checkpoints(raw):
    need(type(raw) is bytes and len(raw) <= 32 << 20)
    return [value.decode('ascii') for value in re.findall(
        rb'^SUBSCRIPTION_UI_STAGE=(ENVIRONMENT|LAUNCH|NAVIGATE|CONNECT|CONFIRM|RECEIPT|CLOSE|COMPLETE)$', raw, re.M)]


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def library(repo):
    return load_module(repo / 'chengwang/deploy/browser-stream-matrix/run_matrix.py', 'subscription_ui_matrix_primitives')


def safe_relative(value):
    need(type(value) is str and 0 < len(value) <= 512 and '\\' not in value
         and not value.startswith('/') and all(v not in ('', '.', '..') for v in value.split('/')))
    return value


def validate_build(build, commit, server, files):
    need(type(build) is dict and set(build) == {'schema', 'sourceCommit', 'goVersion', 'nodeVersion',
        'moduleMode', 'goDependencyDownloads', 'server', 'distFiles', 'production', 'authorization'})
    need(build['schema'] == 'chengwang.subscription-ui-build/v1' and build['sourceCommit'] == commit
         and build['goVersion'] == 'go1.23.12' and build['nodeVersion'] == 'v22.23.3'
         and build['moduleMode'] == 'vendor' and build['goDependencyDownloads'] is False
         and build['production'] is False and build['authorization'] == 'BLOCKED')
    need(server[:4] == b'\x7fELF' and build['server'] == dict(name='server', bytes=len(server), sha256=sha(server)))
    need(type(build['server']['bytes']) is int and type(build['distFiles']) is list and 4 <= len(files) <= 512)
    need(build['distFiles'] == files and [row['path'] for row in files] == sorted(row['path'] for row in files))
    need({'index.html', 'trust.html', '.vite/manifest.json'} <= {row['path'] for row in files})
    for row in files:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and type(row['bytes']) is int and 0 < row['bytes'] <= 16 << 20
             and re.fullmatch('[a-f0-9]{64}', row['sha256']))
        safe_relative(row['path'])


def child_environment(root, bundle):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TMPDIR': '/var/tmp',
        'CHENGWANG_ADDR': '127.0.0.1:17891', 'CHENGWANG_DATA_DIR': str(root / 'data'),
        'CHENGWANG_IDENTITIES_FILE': str(root / 'identities.json'),
        'CHENGWANG_TLS_CERT_FILE': str(root / 'api-leaf.pem'), 'CHENGWANG_TLS_KEY_FILE': str(root / 'api-leaf.key'),
        'CHENGWANG_MANAGEMENT_TENANT_ID': SCOPE['tenantId'], 'CHENGWANG_MANAGEMENT_SITE_ID': SCOPE['siteId'],
        'CHENGWANG_MANAGEMENT_OBJECT_ID': 'local', 'CHENGWANG_MODE': 'candidate',
        'CHENGWANG_SUBSCRIPTIONS_ENABLED': 'true', 'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED': 'true',
        'CHENGWANG_ALLOW_PUBLISH': 'false', 'CHENGWANG_OPERATION_WRITES_ENABLED': 'false',
        'CHENGWANG_WEB_DIR': str(bundle / 'source/chengwang/web/dist')}


def identity(token):
    need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token))
    return dict(version=1, identities=[dict(tokenId='ui-operator', tokenHash=sha(token.encode('ascii')),
        principal=dict(id='operator@subscription-ui.lab', tenantId=SCOPE['tenantId'], roles=['operator'],
                       allowedScopes=[dict(SCOPE)]))])


def private_projection(private, commit, fixture):
    need(type(private) is dict and private['schema'] == 'chengwang.subscription-store/v1'
         and type(private['sources']) is list and len(private['sources']) == 1
         and private['candidates'] == [] and private.get('approvals', []) == []
         and type(private['audit']) is list and type(private.get('commands')) is list and len(private['commands']) == 1)
    allowed_source = {'id', 'scope', 'label', 'revision', 'updatedAt'}
    source = private['sources'][0]
    need(type(source) is dict and set(source) == allowed_source and source['scope'] == SCOPE
         and source['label'] == 'browser-ui-source' and type(source['revision']) is int and source['revision'] == 1
         and re.fullmatch('src_[a-f0-9]{32}', source['id']))
    command = private['commands'][0]['record']
    allowed = ('id', 'scope', 'actorId', 'kind', 'sourceId', 'expectedRevision', 'preparedAuditHash',
               'resultAuditHash', 'acknowledged')
    need(type(command) is dict and command['scope'] == SCOPE and command['kind'] == 'create'
         and type(command['result']) is dict)
    result_allowed = ('sourceId', 'revision', 'state', 'stateMayHaveChanged', 'localAuditHash', 'completedAt')
    result = {key: command['result'][key] for key in result_allowed if key in command['result']}
    need(result.get('sourceId') == source['id'] and result.get('revision') == 1 and result.get('state') == 'committed')
    public_command = {key: command[key] for key in allowed if key in command}
    public_command['result'] = result
    return dict(schema='chengwang.subscription-ui-private-readback/v1', sourceCommit=commit, fixtureId=fixture,
        scope=dict(SCOPE), sources=[{key: source[key] for key in allowed_source}], candidates=[],
        localAuditCount=len(private['audit']), commandCount=1, approvalCount=0, commands=[public_command])


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


def prepare(options, repo, root, bundle, fixture, N, M):
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
    files = []
    need(options.dist.is_dir() and not options.dist.is_symlink())
    for path in sorted(options.dist.rglob('*')):
        need(not path.is_symlink())
        if path.is_dir(): continue
        need(stat.S_ISREG(path.lstat().st_mode)); relative = safe_relative(path.relative_to(options.dist).as_posix())
        contents = N.stable_read(path, 16 << 20)[0]
        files.append(dict(path=relative, bytes=len(contents), sha256=sha(contents)))
        copy(path, bundle / 'source/chengwang/web/dist' / relative, 'dist/' + relative)
    validate_build(build, options.source_commit, server, files)
    copy(options.build_report, bundle / 'build.json', 'build/report.json')
    for relative in SOURCE_FILES: copy(repo / relative, bundle / 'source' / relative, relative)
    # The A driver imports the existing DOM collector; preserve its exact path.
    for directory in ('chengwang/tools/subscription-ui-browser', 'chengwang/tools/subscription-browser'):
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
    copy(repo / SOURCE_FILES[1], bundle / 'ui-chrome-launcher', SOURCE_FILES[1] + ':launcher', True)
    N.exclusive(bundle / 'launch.json', N.canonical(dict(schema='chengwang.subscription-ui-launch/v1',
        engine=options.engine, fixtureId=fixture, root=str(root), chrome=str(chrome), chromeSHA256=receipt['elf']['sha256'])), 0o440)
    passwd = ('root:x:0:0:root:/root:/usr/sbin/nologin\nui:x:10001:10001:ui:' + str(root / 'home') + ':/usr/sbin/nologin\n').encode()
    N.exclusive(bundle / 'passwd', passwd, 0o440); N.exclusive(bundle / 'group', b'root:x:0:\nui:x:10001:\n', 0o440)
    for path in (bundle / 'launch.json', bundle / 'passwd', bundle / 'group'): os.chown(path, 0, 10001)
    for current, dirs, _ in os.walk(bundle):
        for name in dirs:
            path = pathlib.Path(current) / name; os.chown(path, 0, 10001); path.chmod(0o550)
    bundle.chmod(0o550)
    N.exclusive(options.output_dir / 'inputs.json', N.canonical(dict(schema=SCHEMA,
        sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine, copiedInputs=records,
        inputTrustScope='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD', production=False)) + b'\n')
    N.exclusive(options.output_dir / 'pin-consumption.json', receipt_raw)
    N.exclusive(options.output_dir / 'build.json', build_raw)


def export_observations(options, root, N, partial=False):
    names = [('driver.private.json', 'driver.json', 65536), ('captures.private.jsonl', 'captures.jsonl', 24 << 20),
        ('dom.private.jsonl', 'dom.jsonl', 262144), ('created-desktop.private.png', 'created-desktop.png', 16 << 20),
        ('created-mobile.private.png', 'created-mobile.png', 16 << 20)]
    exported = []
    secrets_raw = []
    input_path = root / 'browser-input.private.json'
    if input_path.exists():
        try:
            value = N.decode(N.stable_read(input_path, 8192, 10001, 0o600)[0])
            secrets_raw.extend(secret_variants(value['operatorToken']))
        except Exception:
            if partial: return []  # Unknown canaries cannot authorize publication.
            raise
    else:
        if partial: return []
        need(False)
    for private, public, budget in names:
        source, target = root / private, options.output_dir / public
        if partial and (not source.exists() or target.exists()): continue
        try:
            raw = N.stable_read(source, budget, 10001, 0o600)[0]
            public_fence(raw, secrets_raw, captures=(public == 'captures.jsonl'), N=N)
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


def inner(options, repo, root, bundle, fixture, N, M):
    need(os.geteuid() == 0 and os.getpid() == 1)
    N.command(['mount', '--make-rprivate', '/']); N.mount_bind(repo, True); N.mount_bind(bundle, True)
    N.command(['ip', 'link', 'set', 'lo', 'up'])
    need(len(N.command(['ip', '-o', 'link', 'show']).splitlines()) == 1
         and not N.command(['ip', '-4', 'route', 'show', 'default']) and not N.command(['ip', '-6', 'route', 'show', 'default']))
    N.command(['mount', '-t', 'tmpfs', '-o', 'size=64m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec',
               'chengwang-subscription-ui-short-tmp', '/var/tmp'])
    for source, target in (('passwd', '/etc/passwd'), ('group', '/etc/group')):
        N.command(['mount', '--bind', str(bundle / source), target]); N.command(['mount', '-o', 'remount,bind,ro,nosuid,nodev', target])
    certs = M.certificates(root, N)
    N.exclusive(options.output_dir / 'certificates.json', N.canonical(certs) + b'\n')
    token = secrets.token_hex(32)
    for path, value in [('identities.json', identity(token)), ('browser-input.private.json',
        dict(schema='chengwang.subscription-ui-input/v1', operatorToken=token, label='browser-ui-source'))]:
        N.exclusive(root / path, N.canonical(value), 0o600); os.chown(root / path, 10001, 10001)
    (root / 'data').mkdir(mode=0o700); os.chown(root / 'data', 10001, 10001)
    prefix = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--bounding-set=-all',
              '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']
    server = node = None; records = []; stage = 'SERVER_START'; succeeded = False; forced = 0
    try:
        with (root / 'server.private.log').open('xb') as log:
            server = subprocess.Popen([*prefix, str(bundle / 'server')], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, env=child_environment(root, bundle), cwd=root, preexec_fn=M.child_limits)
        wait_server(root, server, N); stage = 'DRIVER_START'
        with (root / 'driver.private.log').open('xb') as log:
            node = subprocess.Popen([*prefix, str(bundle / 'node'),
                str(bundle / 'source/chengwang/tools/subscription-ui-browser/ui-cli.mjs'), '--root', str(root),
                '--bundle', str(bundle), '--engine', options.engine, '--source-commit', options.source_commit],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=dict(N.BASE_ENV, TMPDIR='/var/tmp'),
                cwd=root, preexec_fn=M.child_limits)
        stage = 'DRIVER_BARRIER'; barrier = M.wait_file(root / 'driver-ready.private.json', node, N, 45)
        need(barrier == dict(schema='chengwang.subscription-ui-driver-ready/v1', fixtureId=fixture,
            engine=options.engine, pid=node.pid, chromePid=barrier.get('chromePid')))
        handoff = N.decode(N.stable_read(root / 'chrome-process.private.json', 8192, 10001, 0o600)[0])
        need(type(barrier['chromePid']) is int and handoff['pid'] == barrier['chromePid'] and handoff['uid'] == 10001)
        for role, pid, executable, limit in [('server', server.pid, bundle / 'server', 128 << 20),
            ('controller', node.pid, bundle / 'node', 256 << 20), ('chrome', handoff['pid'], bundle / 'chrome/chrome', 512 << 20)]:
            record = N.task_profile(pid, sha(N.stable_read(executable, limit)[0]), executable_limit=limit)
            record.update(role=role, argv=pathlib.Path('/proc', str(pid), 'cmdline').read_bytes()[:-1].decode().split('\0'))
            records.append(record)
        stage = 'UI_RUN'; N.publish_atomic(root / 'run.go', N.canonical(dict(
            schema='chengwang.subscription-ui-run/v1', fixtureId=fixture, engine=options.engine)), 0o444)
        need(node.wait(timeout=125) == 0)
        stage = 'SERVER_STOP'; server.send_signal(signal.SIGTERM); need(server.wait(timeout=15) == 0)
        stage = 'PROCESS_REAP'
        need(M.no_owned_processes() and all(not pathlib.Path('/proc', str(row['pid'])).exists() for row in records))
        N.exclusive(options.output_dir / 'processes.json', N.canonical(dict(schema=SCHEMA,
            sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine, records=records,
            serverExitCode=0, controllerExitCode=0, noLiveOwnedProcesses=True, forcedSignals=0,
            processScope='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION', production=False)) + b'\n')
        stage = 'READBACK'
        private = N.decode(N.stable_read(root / 'data/subscriptions/store.json', 16 << 20, 10001, 0o600)[0])
        readback = private_projection(private, options.source_commit, fixture)
        forbidden = secret_variants(token)
        N.exclusive(options.output_dir / 'private-readback.json', public_fence(N.canonical(readback) + b'\n', forbidden))
        for original, public, limit in [('data/evidence/events.jsonl', 'audit-events.jsonl', 4 << 20),
                                       ('data/evidence/checkpoint.json', 'audit-checkpoint.json', 65536)]:
            raw = N.stable_read(root / original, limit, 10001, 0o600)[0]
            N.exclusive(options.output_dir / public, public_fence(raw, forbidden))
        stage = 'EXPORT'; export_observations(options, root, N)
        N.exclusive(options.output_dir / 'inner-isolation.private.json', N.canonical(dict(
            namespaces=N.ns(), defaultIPv4Routes=0, defaultIPv6Routes=0, interfaces=['lo'],
            sourceMount=N.mount_flags('self', repo), bundleMount=N.mount_flags('self', bundle),
            tmpMount=N.mount_flags('self', '/var/tmp'))) + b'\n')
        succeeded = True
    finally:
        for child in (node, server):
            if child is not None and child.poll() is None:
                forced += 1; child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: forced += 1; child.kill(); child.wait(timeout=3)
        if not succeeded:
            no_owned = M.no_owned_processes(); exported = export_observations(options, root, N, partial=True)
            checkpoints = []
            if (root / 'driver.private.log').exists():
                checkpoints = driver_checkpoints(N.stable_read(root / 'driver.private.log', 32 << 20)[0])
            N.exclusive(options.output_dir / 'failure.json', N.canonical(dict(schema=SCHEMA,
                sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine, stage=stage,
                driverCheckpoints=checkpoints,
                serverExitCode=None if server is None else server.poll(), controllerExitCode=None if node is None else node.poll(),
                records=records, forcedSignals=forced, noLiveOwnedProcesses=no_owned, capturedOriginals=exported,
                acceptance='REJECTED_DIAGNOSTIC_ONLY', production=False)) + b'\n')


def main():
    parser = argparse.ArgumentParser()
    for name in ('repo', 'consumption-root', 'consumption-report', 'node', 'server', 'dist', 'build-report', 'output-dir'):
        parser.add_argument('--' + name, required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    parser.add_argument('--fixture', default=None); parser.add_argument('--inner', action='store_true')
    options = parser.parse_args(); need(sys.platform == 'linux' and os.geteuid() == 0)
    repo = options.repo.resolve(strict=True); M = library(repo); N = M.load_native(repo)
    need(re.fullmatch('[a-f0-9]{40}', options.source_commit))
    fixture = options.fixture or uuid.uuid4().hex; need(re.fullmatch('[a-f0-9]{32}', fixture))
    root = pathlib.Path('/tmp/chengwang-subscription-ui-' + fixture)
    bundle = pathlib.Path('/tmp/chengwang-subscription-ui-tools-' + fixture)
    if options.inner: inner(options, repo, root, bundle, fixture, N, M); return
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux' and options.fixture is None)
    options.output_dir = options.output_dir.absolute(); need(not options.output_dir.exists()); options.output_dir.mkdir(mode=0o700)
    before, source_before = N.host_observation(repo, options.source_commit)
    try:
        prepare(options, repo, root, bundle, fixture, N, M)
        argv = ['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc',
            sys.executable, '-I', '-B', str(pathlib.Path(__file__).resolve()), '--inner', '--fixture', fixture,
            '--source-commit', options.source_commit, '--engine', options.engine]
        for name in ('repo', 'consumption-root', 'consumption-report', 'node', 'server', 'dist', 'build-report', 'output-dir'):
            argv += ['--' + name, str(getattr(options, name.replace('-', '_')))]
        with (bundle / 'supervisor.private.log').open('xb') as log:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=dict(N.BASE_ENV), cwd='/')
            timed_out = False
            try: child.wait(timeout=225)
            except subprocess.TimeoutExpired: timed_out = True
            finally:
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
        after, source_after = N.host_observation(repo, options.source_commit)
        need(before == after and source_before == source_after)
        if child.returncode != 0 or timed_out:
            export_observations(options, root, N, partial=True)
            N.exclusive(options.output_dir / 'failed-host-readback.json', N.canonical(dict(schema=SCHEMA,
                sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine,
                hostBefore=before, hostAfter=after, sourceFilesBefore=source_before, sourceFilesAfter=source_after,
                innerExitCode=child.returncode, innerTimedOut=timed_out,
                acceptance='REJECTED_DIAGNOSTIC_ONLY', production=False)) + b'\n'); need(False)
        isolation = N.decode(N.stable_read(options.output_dir / 'inner-isolation.private.json')[0])
        N.exclusive(options.output_dir / 'isolation.json', N.canonical(dict(schema=SCHEMA,
            sourceCommit=options.source_commit, fixtureId=fixture, engine=options.engine,
            hostBefore=before, hostAfter=after, sourceFilesBefore=source_before, sourceFilesAfter=source_after,
            lab=isolation, production=False, authorization='BLOCKED', deviceActionsExecuted=False,
            pythonBinaryProvenanceProven=False)) + b'\n')
        (options.output_dir / 'inner-isolation.private.json').unlink()
        need({path.name for path in options.output_dir.iterdir()} == PUBLIC)
        print('SUBSCRIPTION_UI=CAPTURED independent_verification=pending production=false full_subscription_e2e=false')
    finally: clean_owned(root, fixture); clean_owned(bundle, fixture)


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('SUBSCRIPTION_UI=REJECTED raw_input_suppressed=true') from None
