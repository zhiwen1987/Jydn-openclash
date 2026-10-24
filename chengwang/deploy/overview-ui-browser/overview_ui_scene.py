"""Source-owned overview profiles; configuration/readback is not business health."""
import base64
import importlib.util
import json
import os
import pathlib
import re
import secrets
import stat

TRUST = 'SOURCE_BOUND_TRUSTED_CI_NOT_INDEPENDENT_PRIVATE_STORAGE_ATTESTATION'
PROFILES = ('evidence_disabled', 'evidence_enabled_unknown')
PNG = {'demo-desktop.png', 'actual-desktop.png', 'actual-refreshed-desktop.png', 'demo-return-desktop.png',
       'actual-remount-desktop.png', 'actual-mobile.png', 'demo-mobile.png', 'actual-reenter-mobile.png'}
PUBLIC = {'driver.json', 'captures.jsonl', 'dom.jsonl', 'processes.json', 'isolation.json', 'inputs.json',
          'certificates.json', 'pin-consumption.json', 'build.json', 'runtime-facts.json', 'storage-readback.json'} | PNG
SOURCES = ['chengwang/deploy/browser-scene-supervisor/supervisor.py', 'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
    'chengwang/deploy/overview-ui-browser/overview_ui_scene.py', 'chengwang/deploy/overview-ui-browser/run_overview_ui.py',
    'chengwang/deploy/overview-ui-browser/contract.json', 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py',
    'chengwang/deploy/browser-stream-matrix/run_matrix.py', 'chengwang/web/scripts/trust-browser-tls.mjs']


def need(value):
    if not value: raise ValueError('overview UI scene rejected')


def shared():
    path = pathlib.Path(__file__).resolve().parents[1] / 'browser-scene-supervisor/supervisor.py'
    spec = importlib.util.spec_from_file_location('overview_shared_primitives', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def profile(key):
    need(key in ('overview_ui:evidence_disabled', 'overview_ui:evidence_enabled_unknown'))
    return key.split(':')[1]


def contract():
    path = pathlib.Path(__file__).with_name('contract.json')
    with path.open('rb') as handle: raw = handle.read(131073)
    need(0 < len(raw) <= 131072)
    def unique(pairs):
        value = {}
        for key, child in pairs: need(key not in value); value[key] = child
        return value
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    need(value['schema'] == 'chengwang.overview-ui-browser-contract/v1' and value['scenario'] == 'overview_ui'
         and value['profiles'] == list(PROFILES) and value['privateInputFilename'] == 'overview-input.private.json'
         and set(value['publicFiles']) == PUBLIC and len(value['publicFiles']) == 19)
    return value


def scope():
    return dict(tenantId='', siteId='', environment='candidate', objectType='control-plane', objectId='local')


def environment_projection(actual, root, bundle):
    logical = {str(root / 'data'): '${PRIVATE_ROOT}/data', str(bundle / 'source/chengwang/web/dist'): '${READONLY_BUNDLE}/source/chengwang/web/dist',
        str(root / 'api-leaf.pem'): '${PRIVATE_ROOT}/api-leaf.pem', str(root / 'api-leaf.key'): '${PRIVATE_ROOT}/api-leaf.key'}
    return [dict(name=name, value=logical.get(value, value)) for name, value in sorted(actual.items())]


def scene_child_environment(root, bundle, key):
    selected = profile(key)
    value = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TMPDIR': '/var/tmp',
        'CHENGWANG_ADDR': '127.0.0.1:17891', 'CHENGWANG_DATA_DIR': str(root / 'data'),
        'CHENGWANG_WEB_DIR': str(bundle / 'source/chengwang/web/dist'),
        'CHENGWANG_TLS_CERT_FILE': str(root / 'api-leaf.pem'), 'CHENGWANG_TLS_KEY_FILE': str(root / 'api-leaf.key'),
        'CHENGWANG_MODE': 'candidate', 'CHENGWANG_ALLOW_PUBLISH': 'false', 'CHENGWANG_OPERATION_WRITES_ENABLED': 'false',
        'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED': 'false', 'CHENGWANG_SUBSCRIPTIONS_ENABLED': 'false',
        'CHENGWANG_LIVE_OVERVIEW_ENABLED': 'true' if selected == 'evidence_enabled_unknown' else 'false'}
    policy = contract()['profilePolicies'][selected]
    need({row['name']: row['value'] for row in environment_projection(value, root, bundle)} == policy['env']
         and all(name not in value for name in policy['mustOmit']))
    return value


def scene_initialize(options, root, fixture, key, N):
    selected = profile(key); canary = secrets.token_hex(32)
    need(not (root / 'identities.json').exists() and not (root / 'identities.json').is_symlink())
    N.exclusive(root / 'supervisor-secret.private.json', N.canonical(dict(
        schema='chengwang.overview-ui-secrets/v1', profile=selected, fenceCanary=canary)), 0o600)
    N.exclusive(root / 'overview-input.private.json', N.canonical(dict(schema=contract()['schemaNames']['input'],
        scenario='overview_ui', profile=selected, fixtureId=fixture, sourceCommit=options.source_commit,
        engine=options.engine, fenceCanary=canary)), 0o600)
    os.chown(root / 'overview-input.private.json', 10001, 10001)
    return shared().secret_variants(canary)


def scene_validate_build(build, commit, server, files, manifest):
    need(type(build) is dict and set(build) == {'schema', 'sourceCommit', 'goVersion', 'nodeVersion', 'moduleMode',
        'goDependencyDownloads', 'server', 'distFiles', 'manifestBase64', 'production', 'authorization'})
    need(build['schema'] == 'chengwang.overview-ui-build/v1' and build['sourceCommit'] == commit
         and build['goVersion'] == 'go1.23.12' and build['nodeVersion'] == 'v22.23.3' and build['moduleMode'] == 'vendor'
         and build['goDependencyDownloads'] is False and build['production'] is False and build['authorization'] == 'BLOCKED')
    need(server[:4] == b'\x7fELF' and build['server'] == dict(name='server', bytes=len(server), sha256=shared().sha(server)))
    need(type(build['server']['bytes']) is int and type(files) is list and 4 <= len(files) <= 512
         and build['distFiles'] == files and [row['path'] for row in files] == sorted(row['path'] for row in files))
    need({'index.html', 'trust.html', '.vite/manifest.json'} <= {row['path'] for row in files})
    for row in files:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and type(row['bytes']) is int
             and 0 < row['bytes'] <= 16 << 20 and re.fullmatch('[a-f0-9]{64}', row['sha256']))
        shared().safe_relative(row['path'])
    maximum = contract()['captureRules']['bounds']['manifestBytes']
    need(type(manifest) is bytes and 0 < len(manifest) <= maximum)
    need(type(build['manifestBase64']) is str and len(build['manifestBase64']) <= 4 * (maximum + 2) // 3)
    decoded = base64.b64decode(build['manifestBase64'], validate=True)
    need(decoded == manifest and base64.b64encode(decoded).decode('ascii') == build['manifestBase64'])
    need(next(row for row in files if row['path'] == '.vite/manifest.json') ==
         dict(path='.vite/manifest.json', bytes=len(manifest), sha256=shared().sha(manifest)))


def scene_source_files(key):
    profile(key); contract()
    entry = pathlib.Path(__file__).resolve().parents[2] / 'tools/overview-ui-browser/ui-cli.mjs'
    # Refuse missing implementation before the namespace/server is launched.
    need(entry.is_file() and not entry.is_symlink())
    return list(SOURCES)
def scene_tool_directories(key):
    profile(key); return ('chengwang/tools/subscription-ui-browser', 'chengwang/tools/subscription-browser',
        'chengwang/tools/overview-ui-browser', 'chengwang/tools/browser-scene-driver', 'chengwang/tools/capability-truth-browser')
def scene_public_files(key, options=None): profile(key); contract(); return set(PUBLIC)
def scene_driver_entry(key): profile(key); return 'chengwang/tools/overview-ui-browser/ui-cli.mjs'
def scene_ready_message(fixture, engine, key, node_pid, chrome_pid):
    return dict(schema=contract()['schemaNames']['ready'], scenario='overview_ui', profile=profile(key),
        fixtureId=fixture, engine=engine, pid=node_pid, chromePid=chrome_pid)
def scene_run_message(fixture, engine, key):
    return dict(schema=contract()['schemaNames']['run'], scenario='overview_ui', profile=profile(key), fixtureId=fixture, engine=engine)


def proc_bytes(path, limit=1 << 20):
    with path.open('rb') as handle: raw = handle.read(limit + 1)
    need(len(raw) <= limit); return raw


def listener_present():
    for name in ('tcp', 'tcp6'):
        lines = proc_bytes(pathlib.Path('/proc/net') / name).decode('ascii').splitlines()
        need(lines and 'local_address' in lines[0])
        for line in lines[1:]:
            fields = line.split(); need(len(fields) >= 4)
            if fields[3] == '0A' and int(fields[1].split(':')[1], 16) == 17892: return True
    return False


def scene_namespace_extra(state, root, fixture, key, N):
    profile(key); state.upstream_before = listener_present(); need(state.upstream_before is False); return {}
def scene_start_auxiliary(state, options, root, bundle, fixture, key, N, M, prefix):
    profile(key); need(state.wire is None)
def scene_stop_auxiliary(state, options, root, fixture, key, N):
    profile(key); need(state.wire is None); return {}


def private_directory(path):
    need(not any(part.is_symlink() for part in (path, *path.parents)))
    info = path.lstat(); need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == info.st_gid == 10001)


def scene_before_run(state, options, root, bundle, fixture, key, N):
    expected = scene_child_environment(root, bundle, key); need(state.server_env == expected)
    rows = proc_bytes(pathlib.Path('/proc', str(state.server.pid), 'environ'), 65536).split(b'\0')
    need(rows[-1] == b''); pairs = [row.decode('utf-8').split('=', 1) for row in rows[:-1]]
    need(all(len(row) == 2 for row in pairs) and len({row[0] for row in pairs}) == len(pairs) and dict(pairs) == expected)
    private_directory(root); need(not (root / 'identities.json').exists() and not (root / 'identities.json').is_symlink())
    server = next(row for row in state.records if row['role'] == 'server')
    label = shared().scene_identity(options.source_commit, fixture, options.engine, key); label['schema'] = contract()['schemaNames']['runtime']
    state.runtime = dict(label, scope=scope(),
        serverIdentity=dict(pid=server['pid'], startTicks=int(server['startTime']), exeSHA256=server['exeSHA256'], argvSHA256=server['argvSHA256']),
        environment=environment_projection(expected, root, bundle), identities=dict(configured=False, regularFile=False,
            directoryMode=None, fileMode=None, symlinkComponents=False, ownershipVerified=False),
        mihomo=dict(configured=False, endpointClass=None), observer=dict(configured=False, interval=None, ttl=None),
        probe=dict(configured=False), subscription=dict(configured=False, writesEnabled=False, policyConfigured=False),
        writeGates=dict(publish=False, operation=False, subscription=False), policyCatalog=dict(configured=False),
        upstreamListener=dict(endpointClass='ISOLATED_LOOPBACK_17892', beforeListening=state.upstream_before,
            afterListening=None, reachabilityObserved=False), snapshotsProvider='seed_demo',
        liveOverview=dict(enabled=profile(key) == 'evidence_enabled_unknown'), trustBoundary=TRUST)


def storage_projection(root, key, N):
    profile(key); data = root / 'data'; private_directory(data)
    for name in ('subscriptions', 'observations'):
        need(not (data / name).exists() and not (data / name).is_symlink())
    private_directory(data / 'operations')
    operations = N.decode(N.stable_read(data / 'operations/operations.json', 16 << 20, 10001, 0o600)[0])
    need(type(operations) is dict and set(operations) == {'version', 'operations', 'idempotency'}
         and type(operations['version']) is int and operations['version'] == 2
         and operations['operations'] in ([], None) and operations['idempotency'] in ([], None))
    private_directory(data / 'evidence')
    return dict(scope=scope(), subscriptionStore=dict(constructed=False, scope=None, sourceCount=0, candidateCount=0,
        requestCount=0, auditCount=0, commandCount=0, approvalCount=0, privateNodesCount=0),
        observationStore=dict(constructed=False), operationStore=dict(constructed=True, commandCount=0),
        evidenceStore=dict(constructed=True), trustBoundary=TRUST)


def scene_post_stop(state, options, root, fixture, key, N):
    need(state.runtime is not None and state.server.poll() == 0)
    after = listener_present(); need(after is False); state.runtime['upstreamListener']['afterListening'] = after
    label = shared().scene_identity(options.source_commit, fixture, options.engine, key); label['schema'] = contract()['schemaNames']['storage']
    fence = scene_export_policy(root, key, N, False)[1]
    for name, value in [('runtime-facts.json', state.runtime), ('storage-readback.json', dict(label, **storage_projection(root, key, N)))]:
        raw = N.canonical(value) + b'\n'; scene_fence_public(raw, name, fence, key, N, False); N.exclusive(options.output_dir / name, raw)


def scene_export_policy(root, key, N, partial):
    selected = profile(key)
    try:
        secret = N.decode(N.stable_read(root / 'supervisor-secret.private.json', 8192, 0, 0o600)[0])
        need(set(secret) == {'schema', 'profile', 'fenceCanary'} and secret['schema'] == 'chengwang.overview-ui-secrets/v1'
             and secret['profile'] == selected)
        forbidden = shared().secret_variants(secret['fenceCanary'])
    except Exception:
        if partial: return None
        raise
    bounds = contract()['captureRules']['bounds']
    rows = [('driver.private.json', 'driver.json', bounds['driverFileBytes']),
        ('captures.private.jsonl', 'captures.jsonl', bounds['captureFile']), ('dom.private.jsonl', 'dom.jsonl', bounds['domFileBytes'])]
    rows += [(name.removesuffix('.png') + '.private.png', name, contract()['pngFileBytesMax']) for name in sorted(PNG)]
    return rows, forbidden


def scene_fence_public(raw, public_name, forbidden, key, N, partial):
    selected = profile(key)
    need(type(raw) is bytes and raw and b'PRIVATE KEY' not in raw and not any(secret in raw for secret in forbidden))
    rules = contract()['captureRules']; bounds = rules['bounds']
    if public_name == 'captures.jsonl':
        rows = raw.splitlines(); need(0 < len(rows) <= contract()['profileFacts'][selected]['requestsMax']); total = 0
        for line in rows:
            row = N.decode(line); need(type(row) is dict and row.get('kind') in rules['kindEnum'])
            encoded = row.get('responseBase64')
            if encoded is None:
                # Missing bodies are an explicit coverage gap, never invented bytes.
                need(selected == 'evidence_disabled' and row.get('path') == '/api/v1/overview'
                     and row.get('method') == 'GET' and row.get('status') == 503
                     and row.get('bodyState') == 'unavailable' and row.get('bodyUnavailableReason') == 'BODY_RPC_REJECTED_AFTER_EXPECTED_503'
                     and row.get('responseBytes') is None and row.get('responseSHA256') is None
                     and row.get('bodyRPC') == dict(attempted=True, outcome='rejected'))
                continue
            need(type(encoded) is str and row.get('bodyState') == 'present')
            body = base64.b64decode(encoded, validate=True); total += len(body)
            maximum = bounds['bodyDocument'] if row['kind'] == 'DOCUMENT' else bounds['bodyAsset'] if row['kind'] == 'ASSET' else bounds['bodyAPI']
            need(base64.b64encode(body).decode('ascii') == encoded and len(body) <= maximum
                 and total <= bounds['decodedTotal'] and b'PRIVATE KEY' not in body and not any(secret in body for secret in forbidden))
    if public_name == 'dom.jsonl':
        rows = raw.splitlines(); need(0 < len(rows) <= contract()['profileFacts'][selected]['domCheckpoints']
                                    and all(len(row) <= bounds['domRowBytes'] for row in rows))
    return raw


def scene_failure_diagnostics(state, options, root, fixture, key, N):
    # No absent driver checkpoint or normal-close result is inferred from source.
    profile(key); return dict(driverCheckpoints=[], driverDiagnostics=None)
def scene_inner_success(state, options, root, fixture, key, N): profile(key)
def scene_outer_success(options, root, bundle, fixture, key, N):
    profile(key); print('OVERVIEW_UI=CAPTURED independent_verification=pending production=false business_health_proven=false')
def scene_cleanup(fixture, key): profile(key)
