"""Closed real-Go capability profiles, not mock API producers or health claims."""
import base64
import importlib.util
import json
import os
import pathlib
import re
import secrets
import stat

SCHEMA = 'chengwang.capability-truth-supervisor/v1'
TRUST = 'SOURCE_BOUND_TRUSTED_CI_NOT_INDEPENDENT_PRIVATE_STORAGE_ATTESTATION'
ENDPOINT = 'ISOLATED_LOOPBACK_17892'
FAILURE_STAGES = ('ENVIRONMENT', 'LAUNCH', 'NAVIGATE', 'KERNELS', 'CAPABILITIES', 'REFRESH', 'MOBILE', 'CLOSE', 'COMPLETE')
PUBLIC = {'driver.json', 'captures.jsonl', 'dom.jsonl', 'overview-desktop.png', 'capabilities-desktop.png',
    'kernels-desktop.png', 'overview-mobile.png', 'capabilities-mobile.png', 'kernels-mobile.png',
    'processes.json', 'isolation.json', 'inputs.json', 'certificates.json', 'pin-consumption.json',
    'build.json', 'runtime-facts.json', 'storage-readback.json'}
SOURCES = ['chengwang/deploy/browser-scene-supervisor/supervisor.py', 'chengwang/deploy/browser-scene-supervisor/lifecycle.py',
    'chengwang/deploy/capability-truth-browser/capability_truth_scene.py', 'chengwang/deploy/capability-truth-browser/run_capability_truth.py',
    'chengwang/deploy/capability-truth-browser/contract.json', 'chengwang/deploy/subscription-ui-browser/ui_chrome_launcher.py',
    'chengwang/deploy/browser-stream-matrix/run_matrix.py', 'chengwang/web/scripts/trust-browser-tls.mjs']


def need(value):
    if not value: raise ValueError('capability truth scene rejected')


def contract():
    path = pathlib.Path(__file__).with_name('contract.json')
    with path.open('rb') as handle: raw = handle.read(65537)
    need(0 < len(raw) <= 65536)
    def unique(pairs):
        result = {}
        for key, value in pairs: need(key not in result); result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(value['schema'] == 'chengwang.capability-truth-browser-contract/v1' and value['scenario'] == 'capability_truth'
         and value['profiles'] == ['default', 'backend_configured'] and value['privateInputFilename'] == 'capability-input.private.json')
    return value


def shared():
    path = pathlib.Path(__file__).resolve().parents[1] / 'browser-scene-supervisor/supervisor.py'
    spec = importlib.util.spec_from_file_location('capability_scene_shared_primitives', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def profile(key):
    need(key in ('capability_truth:default', 'capability_truth:backend_configured'))
    return key.split(':')[1]


def scope(configured, *, subscription=False):
    return dict(tenantId='capability-truth-lab' if configured else '', siteId='isolated' if configured else '',
        environment='candidate', objectType='subscription-store' if subscription else 'control-plane', objectId='local')


def scene_child_environment(root, bundle, key):
    value = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TMPDIR': '/var/tmp',
        'CHENGWANG_ADDR': '127.0.0.1:17891', 'CHENGWANG_DATA_DIR': str(root / 'data'),
        'CHENGWANG_WEB_DIR': str(bundle / 'source/chengwang/web/dist'),
        'CHENGWANG_TLS_CERT_FILE': str(root / 'api-leaf.pem'), 'CHENGWANG_TLS_KEY_FILE': str(root / 'api-leaf.key'),
        'CHENGWANG_MODE': 'candidate', 'CHENGWANG_ALLOW_PUBLISH': 'false', 'CHENGWANG_OPERATION_WRITES_ENABLED': 'false',
        'CHENGWANG_SUBSCRIPTION_WRITES_ENABLED': 'false', 'CHENGWANG_SUBSCRIPTIONS_ENABLED': 'false'}
    if profile(key) == 'backend_configured':
        value.update(CHENGWANG_SUBSCRIPTIONS_ENABLED='true', CHENGWANG_IDENTITIES_FILE=str(root / 'identities.json'),
            CHENGWANG_MANAGEMENT_TENANT_ID='capability-truth-lab', CHENGWANG_MANAGEMENT_SITE_ID='isolated',
            CHENGWANG_MANAGEMENT_OBJECT_ID='local', CHENGWANG_MIHOMO_URL='http://127.0.0.1:17892',
            CHENGWANG_OBSERVATION_INTERVAL='30s', CHENGWANG_OBSERVATION_TTL='2m')
    policy = contract()['profilePolicies'][profile(key)]
    logical = environment_projection(value, root, bundle)
    need({row['name']: row['value'] for row in logical} == policy['env'] and all(name not in value for name in policy['mustOmit']))
    return value


def identity(token):
    need(type(token) is str and re.fullmatch('[a-f0-9]{64}', token))
    return dict(version=1, identities=[dict(tokenId='capability-viewer', tokenHash=shared().sha(token.encode('ascii')),
        principal=dict(id='viewer@capability-truth.lab', tenantId='capability-truth-lab', roles=['viewer'],
            allowedScopes=[scope(True, subscription=True)], breakGlassEligible=False))])


def scene_initialize(options, root, fixture, key, N):
    selected = profile(key); canary = secrets.token_hex(32); token = secrets.token_hex(32) if selected == 'backend_configured' else None
    private = dict(schema='chengwang.capability-truth-secrets/v1', profile=selected, fenceCanary=canary, identityToken=token)
    # Raw identity token is root-only and never handed to the Node/browser UID.
    N.exclusive(root / 'supervisor-secret.private.json', N.canonical(private), 0o600)
    browser = dict(schema=contract()['schemaNames']['input'], scenario='capability_truth', profile=selected,
        fixtureId=fixture, sourceCommit=options.source_commit, engine=options.engine, fenceCanary=canary)
    N.exclusive(root / 'capability-input.private.json', N.canonical(browser), 0o600)
    os.chown(root / 'capability-input.private.json', 10001, 10001)
    if token is not None:
        N.exclusive(root / 'identities.json', N.canonical(identity(token)), 0o600); os.chown(root / 'identities.json', 10001, 10001)
    return shared().secret_variants(canary) + ([] if token is None else shared().secret_variants(token))


def scene_validate_build(build, commit, server, files, manifest):
    need(type(build) is dict and set(build) == {'schema', 'sourceCommit', 'goVersion', 'nodeVersion', 'moduleMode',
        'goDependencyDownloads', 'server', 'distFiles', 'manifestBase64', 'production', 'authorization'})
    need(build['schema'] == 'chengwang.capability-truth-build/v1' and build['sourceCommit'] == commit
         and build['goVersion'] == 'go1.23.12' and build['nodeVersion'] == 'v22.23.3' and build['moduleMode'] == 'vendor'
         and build['goDependencyDownloads'] is False and build['production'] is False and build['authorization'] == 'BLOCKED')
    need(server[:4] == b'\x7fELF' and build['server'] == dict(name='server', bytes=len(server), sha256=shared().sha(server)))
    need(type(build['server']['bytes']) is int and type(build['distFiles']) is list and 4 <= len(files) <= 512)
    need(build['distFiles'] == files and [row['path'] for row in files] == sorted(row['path'] for row in files))
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


def scene_source_files(key): profile(key); return list(SOURCES)
def scene_tool_directories(key):
    profile(key); return ('chengwang/tools/subscription-ui-browser', 'chengwang/tools/subscription-browser', 'chengwang/tools/capability-truth-browser')
def scene_public_files(key, options=None):
    profile(key); need(set(contract()['publicFiles']) == PUBLIC); return set(PUBLIC)
def scene_driver_entry(key): profile(key); return 'chengwang/tools/capability-truth-browser/ui-cli.mjs'


def scene_ready_message(fixture, engine, key, node_pid, chrome_pid):
    return dict(schema=contract()['schemaNames']['ready'], scenario='capability_truth', profile=profile(key),
        fixtureId=fixture, engine=engine, pid=node_pid, chromePid=chrome_pid)


def scene_run_message(fixture, engine, key):
    return dict(schema=contract()['schemaNames']['run'], scenario='capability_truth', profile=profile(key), fixtureId=fixture, engine=engine)


def proc_bytes(path, limit=1 << 20):
    # procfs advertises zero sizes; ordinary stable-file st_size equality is not valid here.
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


def environment_projection(actual, root, bundle):
    logical = {str(root / 'data'): '${PRIVATE_ROOT}/data', str(bundle / 'source/chengwang/web/dist'): '${READONLY_BUNDLE}/source/chengwang/web/dist',
        str(root / 'api-leaf.pem'): '${PRIVATE_ROOT}/api-leaf.pem', str(root / 'api-leaf.key'): '${PRIVATE_ROOT}/api-leaf.key',
        str(root / 'identities.json'): '${PRIVATE_ROOT}/identities.json'}
    return [dict(name=name, value=logical.get(value, value)) for name, value in sorted(actual.items())]


def scene_before_run(state, options, root, bundle, fixture, key, N):
    configured = profile(key) == 'backend_configured'; expected = scene_child_environment(root, bundle, key)
    need(state.server_env == expected)
    rows = proc_bytes(pathlib.Path('/proc', str(state.server.pid), 'environ'), 65536).split(b'\0')
    need(rows[-1] == b''); pairs = [row.decode('utf-8').split('=', 1) for row in rows[:-1]]
    need(all(len(row) == 2 for row in pairs) and len({row[0] for row in pairs}) == len(pairs) and dict(pairs) == expected)
    private_directory(root); configured_identity = dict(configured=False, regularFile=False, directoryMode=None,
        fileMode=None, symlinkComponents=False, ownershipVerified=False)
    if configured:
        raw, info = N.stable_read(root / 'identities.json', 65536, 10001, 0o600)
        secret = N.decode(N.stable_read(root / 'supervisor-secret.private.json', 8192, 0, 0o600)[0])
        need(info.st_gid == 10001 and N.decode(raw) == identity(secret['identityToken']) and not (root / 'identities.json').is_symlink())
        configured_identity = dict(configured=True, regularFile=True, directoryMode='0700', fileMode='0600',
            symlinkComponents=False, ownershipVerified=True)
    else: need(not (root / 'identities.json').exists() and not (root / 'identities.json').is_symlink())
    server = next(row for row in state.records if row['role'] == 'server')
    runtime_identity = shared().identity(options.source_commit, fixture, options.engine, key)
    runtime_identity['schema'] = contract()['schemaNames']['runtime']
    state.runtime = dict(runtime_identity, scope=scope(configured),
        serverIdentity=dict(pid=server['pid'], startTicks=int(server['startTime']), exeSHA256=server['exeSHA256'], argvSHA256=server['argvSHA256']),
        environment=environment_projection(expected, root, bundle), identities=configured_identity,
        mihomo=dict(configured=configured, endpointClass=ENDPOINT if configured else None), observer=dict(configured=configured,
            interval='30s' if configured else None, ttl='2m' if configured else None), probe=dict(configured=False),
        subscription=dict(configured=configured, writesEnabled=False, policyConfigured=False),
        writeGates=dict(publish=False, operation=False, subscription=False), policyCatalog=dict(configured=False),
        upstreamListener=dict(endpointClass=ENDPOINT, beforeListening=state.upstream_before, afterListening=None, reachabilityObserved=False),
        snapshotsProvider='seed_demo', trustBoundary=TRUST)


def storage_projection(root, key, N):
    configured = profile(key) == 'backend_configured'; data = root / 'data'; private_directory(data)
    counts = dict(constructed=configured, scope=scope(True, subscription=True) if configured else None,
        sourceCount=0, candidateCount=0, requestCount=0, auditCount=0, commandCount=0, approvalCount=0, privateNodesCount=0)
    if configured:
        private_directory(data / 'subscriptions'); value = N.decode(N.stable_read(data / 'subscriptions/store.json', 16 << 20, 10001, 0o600)[0])
        need(type(value) is dict and set(value) <= {'schema', 'identityKey', 'sources', 'candidates', 'requests', 'audit', 'commands', 'approvals'}
             and {'schema', 'identityKey', 'sources', 'candidates', 'requests', 'audit'} <= set(value) and value['schema'] == 'chengwang.subscription-store/v1')
        need(type(value['identityKey']) is str)
        identity_key = base64.b64decode(value['identityKey'], validate=True)
        need(len(identity_key) == 32 and base64.b64encode(identity_key).decode('ascii') == value['identityKey'])
        for name in ('sources', 'candidates', 'requests', 'audit'): need(type(value[name]) is list and value[name] == [])
        for name in ('commands', 'approvals'): need(name not in value or type(value[name]) is list and value[name] == [])
    else: need(not (data / 'subscriptions').exists() and not (data / 'subscriptions').is_symlink())
    private_directory(data / 'operations')
    operations = N.decode(N.stable_read(data / 'operations/operations.json', 16 << 20, 10001, 0o600)[0])
    need(type(operations) is dict and set(operations) == {'version', 'operations', 'idempotency'} and type(operations['version']) is int
         and operations['version'] == 2 and operations['operations'] in ([], None) and operations['idempotency'] in ([], None))
    private_directory(data / 'evidence')
    if configured: private_directory(data / 'observations')
    else: need(not (data / 'observations').exists() and not (data / 'observations').is_symlink())
    return dict(scope=scope(configured), subscriptionStore=counts, observationStore=dict(constructed=configured),
        operationStore=dict(constructed=True, commandCount=0), evidenceStore=dict(constructed=True), trustBoundary=TRUST)


def scene_post_stop(state, options, root, fixture, key, N):
    need(state.runtime is not None and state.server.poll() == 0)
    after = listener_present(); need(after is False)
    state.runtime['upstreamListener']['afterListening'] = after
    fence = scene_export_policy(root, key, N, False)[1]
    storage_identity = shared().identity(options.source_commit, fixture, options.engine, key)
    storage_identity['schema'] = contract()['schemaNames']['storage']
    for name, value in [('runtime-facts.json', state.runtime), ('storage-readback.json',
        dict(storage_identity, **storage_projection(root, key, N)))]:
        raw = N.canonical(value) + b'\n'; scene_fence_public(raw, name, fence, key, N, False); N.exclusive(options.output_dir / name, raw)


def scene_export_policy(root, key, N, partial):
    selected = profile(key)
    try:
        value = N.decode(N.stable_read(root / 'supervisor-secret.private.json', 8192, 0, 0o600)[0])
        need(set(value) == {'schema', 'profile', 'fenceCanary', 'identityToken'} and value['schema'] == 'chengwang.capability-truth-secrets/v1'
             and value['profile'] == selected and (value['identityToken'] is None) == (selected == 'default'))
        forbidden = shared().secret_variants(value['fenceCanary']) + ([] if value['identityToken'] is None else shared().secret_variants(value['identityToken']))
    except Exception:
        if partial: return None
        raise
    bounds = contract()['captureRules']['bounds']
    rows = [('driver.private.json', 'driver.json', bounds['driverFileBytes']),
        ('captures.private.jsonl', 'captures.jsonl', bounds['captureFile']), ('dom.private.jsonl', 'dom.jsonl', bounds['domFileBytes'])]
    rows += [(name.removesuffix('.png') + '.private.png', name, contract()['pngFileBytesMax']) for name in sorted(PUBLIC) if name.endswith('.png')]
    return rows, forbidden


def scene_fence_public(raw, public_name, forbidden, key, N, partial):
    profile(key); need(type(raw) is bytes and raw and b'PRIVATE KEY' not in raw and not any(secret in raw for secret in forbidden))
    rules = contract()['captureRules']; bounds = rules['bounds']
    if public_name == 'captures.jsonl':
        rows = raw.splitlines(); need(0 < len(rows) <= bounds['requests']); total = 0
        for line in rows:
            row = N.decode(line); need(type(row) is dict and row.get('kind') in rules['kindEnum'])
            encoded = row.get('responseBase64'); need(type(encoded) is str)
            body = base64.b64decode(encoded, validate=True); total += len(body)
            need(base64.b64encode(body).decode('ascii') == encoded and len(body) <= (bounds['bodyAsset'] if row['kind'] in ('DOCUMENT', 'ASSET') else bounds['bodyAPI'])
                 and total <= bounds['decodedTotal'] and b'PRIVATE KEY' not in body and not any(secret in body for secret in forbidden))
    if public_name == 'dom.jsonl':
        rows = raw.splitlines(); need(0 < len(rows) <= 7 and all(len(row) <= bounds['domRowBytes'] for row in rows))
    return raw


def scene_failure_diagnostics(state, options, root, fixture, key, N):
    profile(key); diagnostic = None
    try:
        policy = scene_export_policy(root, key, N, True)
        need(policy is not None)
        raw = N.stable_read(root / 'capability-failure.private.json', 4096, 10001, 0o600)[0]
        scene_fence_public(raw, 'capability-failure.private.json', policy[1], key, N, True)
        value = N.decode(raw)
        keys = {'schema', 'stage', 'production', 'normalCloseCompleted', 'events', 'captures', 'failed'}
        need(type(value) is dict and set(value) == keys and value['schema'] == 'chengwang.capability-truth-driver-failure/v1'
             and value['stage'] in FAILURE_STAGES and value['production'] is False and value['failed'] is True
             and type(value['normalCloseCompleted']) is bool)
        bounds = contract()['captureRules']['bounds']
        need(type(value['events']) is int and 0 <= value['events'] <= bounds['events']
             and type(value['captures']) is int and 0 <= value['captures'] <= bounds['requests'])
        diagnostic = {name: value[name] for name in keys}
    except Exception:
        # Unavailable or unsafe observations stay unknown, never normal zeroes.
        diagnostic = None
    return dict(driverCheckpoints=[], driverDiagnostics=diagnostic)


def scene_inner_success(state, options, root, fixture, key, N): profile(key)
def scene_outer_success(options, root, bundle, fixture, key, N):
    profile(key); print('CAPABILITY_TRUTH=CAPTURED independent_verification=pending production=false')
def scene_cleanup(fixture, key): profile(key)
