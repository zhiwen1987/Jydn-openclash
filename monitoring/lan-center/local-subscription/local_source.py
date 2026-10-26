"""Independent local subscription source; no changes to public-source admission.

The immutable provider pointer is independent of the airport release pointer.
Private data and original proxy credentials remain in the mounted /data volume.
"""
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

import yaml
from node_links import Invalid, parse

PREFIX = '🔐 自建节点 · '
EMPTY = PREFIX + '__EMPTY__'
PROVIDER = 'Local_Custom'
SELECTOR = '🔐 自定义节点'
PROBE = '🧪 节点能力检测'
VALIDATION_LOCK = threading.Lock()


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode() + b'\n'
    tmp = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def locked(path, nonblock=True):
    with open(path, 'a') as f:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblock else 0))
        except BlockingIOError:
            raise Invalid('busy_retry_later') from None
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


class Manager:
    def __init__(self, root, api, validator, capability_db=None):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.api, self.validator = api, validator
        self.capability_db = Path(capability_db) if capability_db else self.root.parent.parent / 'node-capability.db'
        self.routing_lock = self.root.parent.parent / 'routing-owner.lock'
        for key in ('identity-key', 'provider-token', 'admin-token'):
            path = self.root / key
            if not path.exists():
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(secrets.token_urlsafe(36) + '\n'); f.flush(); os.fsync(f.fileno())
            os.chmod(path, 0o600)
        self.identity_key = (self.root / 'identity-key').read_text().strip().encode()
        if not (self.root / 'state.json').exists():
            self.write_release({'version': 0, 'nodes': []})
            atomic(self.root / 'current.json', {'version': 0})
            atomic(self.root / 'state.json', {'version': 0, 'nodes': []})
        elif not (self.root / 'current.json').exists() and not (self.root / 'pending.json').exists():
            state = self.read('state.json')
            if self.read('releases/' + str(state['version']) + '/state.json') != state:
                raise Invalid('committed_state_mismatch')
            atomic(self.root / 'current.json', {'version': state['version']})

    def read(self, name):
        try:
            return json.loads((self.root / name).read_text())
        except Exception:
            raise Invalid('local_state_unreadable') from None

    def credential(self, key):
        return (self.root / key).read_text().strip()

    def canonical(self, text):
        out = {}
        for label, proxy in parse(text):
            raw = json.dumps(proxy, sort_keys=True, separators=(',', ':')).encode()
            ident = hmac.new(self.identity_key, raw, hashlib.sha256).hexdigest()[:20]
            out[ident] = {'id': ident, 'label': label, 'proxy': proxy, 'name': PREFIX + label + ' · ' + ident[:8]}
        return list(out.values())

    def payload(self, nodes):
        proxies = [{**n['proxy'], 'name': n['name']} for n in nodes]
        return yaml.safe_dump({'proxies': proxies or [{'name': EMPTY, 'type': 'reject'}]}, allow_unicode=True, sort_keys=False).encode()

    def write_release(self, state):
        (self.root / 'releases').mkdir(mode=0o700, exist_ok=True)
        directory = self.root / 'releases' / str(state['version'])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = self.payload(state['nodes'])
        for name, raw in [('provider.yaml', payload), ('state.json', json.dumps(state, ensure_ascii=False).encode())]:
            path = directory / name
            if path.exists():
                if path.read_bytes() != raw:
                    raise Invalid('immutable_version_conflict')
            else:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(raw); f.flush(); os.fsync(f.fileno())
        atomic(directory / 'checksum.json', {'sha256': hashlib.sha256(payload).hexdigest()})

    def provider_payload(self):
        version = self.read('current.json')['version']
        if type(version) is not int or version < 0:
            raise Invalid('local_pointer_invalid')
        path = self.root / 'releases' / str(version)
        raw = (path / 'provider.yaml').read_bytes()
        if hashlib.sha256(raw).hexdigest() != json.loads((path / 'checksum.json').read_text())['sha256']:
            raise Invalid('local_provider_checksum_failed')
        return raw

    def runtime_names(self):
        providers = self.api('/providers/proxies').get('providers', {})
        return {p['name'] for p in providers.get(PROVIDER, {}).get('proxies', [])}

    def verify(self, nodes):
        expected = {n['name'] for n in nodes}
        if self.runtime_names() != (expected or {EMPTY}):
            raise Invalid('router_provider_not_loaded')
        menu = set(self.api('/proxies/' + urllib.parse.quote(SELECTOR, safe='')).get('all', []))
        probe = set(self.api('/proxies/' + urllib.parse.quote(PROBE, safe='')).get('all', []))
        if not expected.issubset(menu) or not expected.issubset(probe) or EMPTY in menu or EMPTY in probe:
            raise Invalid('router_membership_not_loaded')
        if menu & {EMPTY, PROVIDER}:
            raise Invalid('router_empty_sentinel_exposed')

    def refresh(self, nodes):
        self.api('/providers/proxies/' + PROVIDER, 'PUT')
        for _ in range(20):
            try:
                self.verify(nodes)
                return
            except Exception:
                time.sleep(.25)
        raise Invalid('router_refresh_readback_failed')

    def fence_removed(self, old, nodes):
        removed = {n['name'] for n in old['nodes']} - {n['name'] for n in nodes}
        if not removed:
            return 0
        path = '/proxies/' + urllib.parse.quote(SELECTOR, safe='')
        current = self.api(path)
        if current.get('now') not in removed:
            return 0
        self.api(path, 'PUT', {'name': 'REJECT'})
        if self.api(path).get('now') != 'REJECT':
            raise Invalid('reject_fence_failed')
        drained = 0
        for c in self.api('/connections').get('connections') or []:
            if SELECTOR in c.get('chains', []):
                self.api('/connections/' + urllib.parse.quote(c['id'], safe=''), 'DELETE')
                drained += 1
        return drained

    def update(self, request):
        with locked(self.root / 'writer.lock'):
            if (self.root / 'pending.json').exists():
                raise Invalid('pending_recovery_retry_later')
            old = self.read('state.json')
            if type(request.get('version')) is not int or request['version'] != old['version']:
                raise Invalid('version_conflict_refresh_page')
            mode = request.get('mode', 'merge')
            if mode in ('merge', 'replace'):
                entries = self.canonical(request.get('text', ''))
                if mode == 'merge':
                    entries = list({n['id']: n for n in old['nodes'] + entries}.values())
            elif mode == 'remove':
                ids = request.get('ids')
                if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                    raise Invalid('remove_ids_invalid')
                entries = [n for n in old['nodes'] if n['id'] not in ids]
            elif mode == 'edit':
                edits = self.canonical(request.get('text', ''))
                ident = request.get('id')
                if len(edits) != 1 or ident not in {n['id'] for n in old['nodes']}:
                    raise Invalid('edit_one_existing_node_required')
                if edits[0]['id'] != ident and edits[0]['id'] in {n['id'] for n in old['nodes']}:
                    raise Invalid('edited_node_duplicate')
                entries = [edits[0] if n['id'] == ident else n for n in old['nodes']]
            else:
                raise Invalid('mode_invalid')
            if len(entries) > 100:
                raise Invalid('node_limit_100')
            if entries == old['nodes']:
                return {'status': 'unchanged', 'version': old['version'], 'count': len(entries)}
            # Native parser runs with no listeners, DNS, providers or remote assets.
            self.validator([{**n['proxy'], 'name': n['name']} for n in entries])
            version = max(int(time.time() * 1000), old['version'] + 1)
            state = {'version': version, 'nodes': entries}
            self.write_release(state)
            with locked(self.routing_lock):
                self.fence_removed(old, entries)
                atomic(self.root / 'pending.json', {'previous': old['version'], 'candidate': version})
                atomic(self.root / 'current.json', {'version': version})
                try:
                    self.refresh(entries)
                    self.signal_discovery()
                    atomic(self.root / 'receipt.json', {'status': 'loaded', 'version': version, 'at': time.time(), 'count': len(entries)})
                    atomic(self.root / 'runtime.json', {'version': version, 'loaded': True, 'at': time.time()})
                    # state.json is the commit marker. Everything before it is
                    # recoverable from pending.previous; after it keep candidate.
                    atomic(self.root / 'state.json', state)
                except Exception:
                    if self.read('state.json')['version'] == version:
                        raise Invalid('publish_committed_recovery_pending') from None
                    atomic(self.root / 'current.json', {'version': old['version']})
                    try:
                        self.refresh(old['nodes'])
                        (self.root / 'pending.json').unlink()
                        atomic(self.root / 'receipt.json', {'status': 'rolled_back', 'version': old['version'], 'at': time.time(), 'count': len(old['nodes'])})
                    except Exception:
                        pass  # durable journal retained; recovery retries only this provider
                    raise Invalid('publish_failed_previous_retained') from None
                try:
                    (self.root / 'pending.json').unlink()
                except OSError:
                    pass  # recovery sees committed candidate; never reverts it
            try:
                self.prune()
            except OSError:
                pass  # retention failure cannot turn a successful commit into rollback
            return {'status': 'loaded', 'version': version, 'count': len(entries)}

    def signal_discovery(self):
        atomic(self.root.parent.parent / 'local-discovery.json', {'generation': time.time_ns()})

    def recover(self):
        with locked(self.root / 'writer.lock'):
            if not (self.root / 'pending.json').exists():
                return
            with locked(self.routing_lock):
                pending = self.read('pending.json')
                state = self.read('state.json')
                version = pending['candidate'] if state['version'] == pending['candidate'] else pending['previous']
                recovered = self.read('releases/' + str(version) + '/state.json')
                atomic(self.root / 'current.json', {'version': version})
                self.refresh(recovered['nodes'])
                atomic(self.root / 'state.json', recovered)
                self.signal_discovery()
                (self.root / 'pending.json').unlink()

    def prune(self):
        # Versions contain credentials: bounded retention, protected current state.
        folders = sorted((self.root / 'releases').iterdir(), key=lambda p: int(p.name), reverse=True)
        for folder in folders[20:]:
            import shutil
            shutil.rmtree(folder)

    def status(self):
        state = self.read('state.json')
        rows = {}
        if state['nodes'] and self.capability_db.exists():
            try:
                with contextlib.closing(sqlite3.connect('file:' + str(self.capability_db) + '?mode=ro', uri=True, timeout=1)) as c:
                    c.row_factory = sqlite3.Row
                    for row in c.execute('SELECT n.name,n.active,h.state,h.updated_at,h.fresh_until,h.score FROM nodes n LEFT JOIN health_scores h ON h.node_id=n.id WHERE n.name LIKE ?', (PREFIX + '%',)):
                        rows[row['name']] = dict(row)
            except sqlite3.Error:
                pass
        out = []
        for n in state['nodes']:
            h = rows.get(n['name'], {})
            health = 'queued' if not h.get('updated_at') or not h.get('active') else ('stale' if h.get('fresh_until', 0) < time.time() else h.get('state', 'unknown'))
            out.append({'id': n['id'], 'label': n['label'], 'name': n['name'], 'type': n['proxy']['type'], 'health': health, 'evaluated_at': h.get('updated_at', 0), 'score': h.get('score')})
        receipt = self.read('receipt.json') if (self.root / 'receipt.json').exists() else {'status': 'ready'}
        runtime = self.read('runtime.json') if (self.root / 'runtime.json').exists() else {}
        return {'version': state['version'], 'nodes': out, 'count': len(out), 'receipt': receipt,
                'router_loaded': runtime.get('version') == state['version'] and runtime.get('loaded') is True and 0 <= time.time() - runtime.get('at', 0) < 90,
                'pending_recovery': (self.root / 'pending.json').exists()}


def native_validator(core, nodes):
    if not VALIDATION_LOCK.acquire(blocking=False):
        raise Invalid('busy_retry_later')
    try:
        return _native_validator(core, nodes)
    finally:
        VALIDATION_LOCK.release()


def _native_validator(core, nodes):
    # An empty source is legal, but validate a reject-only fixture in that case.
    with tempfile.TemporaryDirectory(prefix='local-validate-') as tmp:
        path = Path(tmp) / 'config.yaml'
        data = {'port': 0, 'socks-port': 0, 'mixed-port': 0, 'allow-lan': False, 'mode': 'rule', 'log-level': 'silent', 'dns': {'enable': False}, 'proxies': nodes, 'proxy-groups': [{'name': 'validate', 'type': 'select', 'proxies': ['REJECT'] + [n['name'] for n in nodes]}], 'rules': ['MATCH,REJECT']}
        path.write_text(yaml.safe_dump(data, allow_unicode=True))
        path.chmod(0o600)
        try:
            p = subprocess.run([str(core), '-t', '-d', tmp, '-f', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25, env={**os.environ, 'GOMAXPROCS': '1', 'GOMEMLIMIT': '64MiB'})
        except Exception:
            raise Invalid('native_validation_unavailable') from None
        if p.returncode:
            raise Invalid('native_kernel_rejected_configuration')
