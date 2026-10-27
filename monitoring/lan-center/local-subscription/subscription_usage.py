"""Independent, bounded subscription-account metadata; never publishes nodes."""
import concurrent.futures
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.parse

import yaml

SCHEMA = 1
MAX_SOURCES = 128
MAX_INTEGER = 2**53 - 1
ROOT = Path(__file__).parent


class UsageError(ValueError):
    pass


def atomic(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def source_url(value):
    if not isinstance(value, str) or len(value) > 8192 or re.search(r'[\x00-\x20\x7f]', value):
        raise UsageError('invalid_information_url')
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise UsageError('invalid_information_url')
    return value


def inventory(document):
    entries = document.get('sources') if isinstance(document, dict) else document
    if not isinstance(entries, list) or len(entries) > MAX_SOURCES:
        raise UsageError('invalid_source_inventory')
    result = {}
    for item in entries:
        if not isinstance(item, dict):
            raise UsageError('invalid_source_entry')
        if item.get('enabled', True) is False:
            continue
        sid = item.get('id', '')
        if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', sid) or sid in result:
            raise UsageError('invalid_or_duplicate_source_id')
        # A configured override is explicit. A converter with a single nested
        # origin can be unwrapped; merged origins cannot share invented totals.
        original = item.get('info_url') or item.get('url')
        error = None
        try:
            url = source_url(original)
            if not item.get('info_url'):
                for _ in range(4):
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                    nested = query.get('url') or query.get('sub')
                    if not nested:
                        break
                    if not nested[0].startswith(('http://', 'https://')):
                        break
                    if len(nested) != 1 or '|' in nested[0] or '\n' in nested[0]:
                        raise UsageError('ambiguous_information_origin')
                    url = source_url(nested[0])
        except (UsageError, ValueError):
            error = 'ambiguous_information_origin' if isinstance(original, str) and '|' in original else 'invalid_information_url'
            url = None
        raw_name = str(item.get('name') or sid)
        name = re.sub(r'[\x00-\x1f\x7f<>]', '', raw_name)[:80]
        if '://' in name or re.search(r'[?&](?:token|key|OwO)=', name, re.I):
            name = sid
        result[sid] = {'id': sid, 'name': name or sid, 'url': url, 'configuration_error': error,
                       'identity': hashlib.sha256((url or repr(original)).encode()).hexdigest()}
    return result


def parse_userinfo(headers):
    values = re.findall(r'^subscription-userinfo:\s*([^\r\n]+)', headers, re.I | re.M)
    if not values:
        raise UsageError('information_header_missing')
    fields = {}
    for part in values[-1].split(';'):
        if not part.strip():
            continue
        key, sep, value = part.strip().partition('=')
        key = key.lower().strip()
        if key not in ('upload', 'download', 'total', 'expire'):
            continue
        if not sep or key in fields or not re.fullmatch(r'\d{1,16}', value.strip()):
            raise UsageError('information_header_invalid')
        fields[key] = int(value)
        if fields[key] > MAX_INTEGER:
            raise UsageError('information_header_out_of_range')
    if not all(key in fields for key in ('upload', 'download', 'total')):
        raise UsageError('information_header_incomplete')
    if fields['upload'] + fields['download'] > MAX_INTEGER or fields.get('expire', 0) > 253402300799:
        raise UsageError('information_header_out_of_range')
    return fields


class Fetcher:
    def __init__(self, proxy='', auth='', timeout=8):
        self.proxy, self.auth = proxy, auth
        self.timeout = max(3, min(15, timeout))

    def __call__(self, url):
        routes = [('', ''), (self.proxy, self.auth)] if self.proxy else [('', '')]
        for proxy, auth in routes:
            config = 'url = '+json.dumps(url)+'\nproxy = '+json.dumps(proxy)+'\nuser-agent = "Clash"\n'
            if proxy:
                config += 'proxy-user = '+json.dumps(auth)+'\n'
            args = ['curl', '--silent', '--location', '--max-redirs', '3', '--head', '--request', 'GET',
                    '--proto', '=http,https', '--proto-redir', '=https', '--connect-timeout', '3',
                    '--max-time', str(self.timeout), '--write-out', '\n__JYDN_HTTP__=%{http_code}', '--config', '-']
            try:
                result = subprocess.run(args, input=config, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=self.timeout+2)
            except subprocess.TimeoutExpired:
                result = None
            raw = result.stdout if result else ''
            if len(raw) > 65536:
                return {'error': 'response_headers_too_large'}
            match = re.search(r'\n__JYDN_HTTP__=(\d{3})\s*$', raw)
            status = int(match[1]) if match else 0
            if status == 429:
                retry = re.findall(r'^retry-after:\s*(\d+)\s*$', raw, re.I | re.M)
                return {'error': 'http_429', 'retry_after': min(3600, max(60, int(retry[-1]))) if retry else 900}
            if result and result.returncode == 0 and status == 200:
                try:
                    return {'metrics': parse_userinfo(raw)}
                except UsageError as error:
                    return {'error': str(error)}
            reason = 'http_'+str(status) if status else 'transport_unavailable'
        return {'error': reason}


class Collector:
    def __init__(self, sources, root, fetcher=None, clock=time.time, interval=600, stale_after=1800):
        self.sources, self.root = Path(sources), Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fetcher = fetcher or Fetcher(os.getenv('PROXY', ''), os.getenv('PROXY_AUTH', ''))
        self.clock, self.interval, self.stale_after = clock, interval, stale_after
        self.lock = threading.RLock()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='subscription-usage')
        self.active, self.records, self.pending = {}, {}, {}
        self.registry_state, self.registry_error = 'loading', None
        self.last_tick = 0
        self.stop = threading.Event()
        self._registry_stamp = None
        self._last_registry_read = 0
        try:
            cache = self.root/'cache.json'
            if cache.stat().st_size > 2*1024**2:
                raise ValueError('cache_too_large')
            saved = json.loads(cache.read_text())
            if saved.get('schema') == SCHEMA and isinstance(saved.get('records'), dict):
                for sid, item in list(saved['records'].items())[:MAX_SOURCES]:
                    if not isinstance(item, dict) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', sid):
                        continue
                    if not re.fullmatch(r'[0-9a-f]{64}', str(item.get('identity', ''))):
                        continue
                    clean = {'identity': item['identity']}
                    for key in ('last_success', 'last_attempt', 'next_due', 'failures'):
                        value = item.get(key, 0)
                        clean[key] = value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else 0
                    if clean['next_due'] > self.clock()+3600 or clean['last_success'] > self.clock():
                        clean['next_due'], clean['last_success'] = 0, 0
                    error = item.get('error')
                    clean['error'] = error if isinstance(error, str) and re.fullmatch(r'[a-z0-9_]{1,100}', error) else None
                    metrics = item.get('metrics')
                    if isinstance(metrics, dict):
                        try:
                            clean['metrics'] = parse_userinfo('subscription-userinfo: '+'; '.join(k+'='+str(v) for k,v in metrics.items() if k in ('upload','download','total','expire')))
                        except UsageError:
                            clean['last_success'] = 0
                    self.records[sid] = clean
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        token_path = self.root/'provider-token'
        try:
            self.token = token_path.read_text().strip()
            if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', self.token):
                raise UsageError('metadata_token_invalid')
        except FileNotFoundError:
            self.token = secrets.token_urlsafe(32)
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(self.token)

    def _registry(self):
        now = self.clock()
        try:
            stat = self.sources.stat()
            stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
            if stamp == self._registry_stamp and now-self._last_registry_read < 30:
                return
            self._last_registry_read = now
            if stat.st_size > 2*1024**2:
                raise UsageError('source_inventory_too_large')
            sources = inventory(yaml.safe_load(self.sources.read_text()))
            fresh = {}
            for sid, source in sources.items():
                prior = self.records.get(sid, {})
                if not isinstance(prior, dict) or prior.get('identity') != source['identity']:
                    prior = {'identity': source['identity'], 'failures': 0, 'next_due': 0}
                if source.get('configuration_error'):
                    prior.update(error=source['configuration_error'])
                fresh[sid] = prior
            self.records, self.active = fresh, sources
            self._registry_stamp = stamp
            self.registry_state, self.registry_error = 'ok', None
        except Exception as error:
            self.registry_state = 'error'
            self.registry_error = str(error) if isinstance(error, UsageError) else 'source_inventory_unreadable'

    def tick(self):
        with self.lock:
            self._registry()
            now, dirty = self.clock(), False
            for key, (identity, future) in list(self.pending.items()):
                if not future.done():
                    continue
                del self.pending[key]
                if key not in self.active or self.active[key]['identity'] != identity:
                    continue
                try:
                    result = future.result()
                except Exception:
                    result = {'error': 'metadata_worker_error'}
                if not isinstance(result, dict):
                    result = {'error': 'metadata_worker_invalid_result'}
                record = self.records[key]
                record['last_attempt'] = now
                metrics = result.get('metrics')
                if metrics is not None:
                    try:
                        metrics = parse_userinfo('subscription-userinfo: '+'; '.join(k+'='+str(v) for k, v in metrics.items()))
                    except (UsageError, TypeError, AttributeError):
                        metrics = None
                        result = {'error': 'metadata_worker_invalid_result'}
                if metrics is not None:
                    record.update(metrics=metrics, last_success=now, error=None, failures=0,
                                  next_due=now+self.interval)
                else:
                    error = str(result.get('error', 'metadata_worker_error'))
                    if not re.fullmatch(r'[a-z0-9_]{1,100}', error):
                        error = 'metadata_worker_error'
                    failures = min(8, int(record.get('failures', 0))+1)
                    delay = min(900, 30*2**(failures-1))
                    delay = max(delay, min(3600, max(0, int(result.get('retry_after', 0)))))
                    record.update(error=error, failures=failures, next_due=now+delay)
                dirty = True
            busy = set(self.pending)
            # At most two tasks exist, rather than an unbounded executor queue.
            for sid, source in self.active.items():
                if len(self.pending) >= 2:
                    break
                record = self.records[sid]
                due = record.get('next_due', 0)
                if source['url'] and sid not in busy and isinstance(due, (float, int)) and due <= now:
                    self.pending[sid] = (source['identity'], self.pool.submit(self.fetcher, source['url']))
            self.last_tick = now
            if dirty or self._registry_stamp != getattr(self, '_saved_stamp', None):
                atomic(self.root/'cache.json', {'schema': SCHEMA, 'records': self.records})
                self._saved_stamp = self._registry_stamp

    def snapshot(self):
        with self.lock:
            now = self.clock()
            rows = []
            for sid, source in self.active.items():
                record = self.records.get(sid, {})
                last = record.get('last_success', 0)
                age = now-last if isinstance(last, (int, float)) else -1
                metrics = record.get('metrics')
                valid = isinstance(metrics, dict) and 0 <= age
                status = ('cached' if record.get('error') or age > self.stale_after else 'ok') if valid else ('unavailable' if record.get('error') else 'checking')
                rows.append({'id': sid, 'name': source['name'], 'usage_status': status,
                             'metrics': metrics if valid else None, 'last_success': last if valid else None,
                             'age_seconds': round(age) if valid else None, 'error': record.get('error'),
                             'stale': bool(valid and age > self.stale_after), 'next_due': record.get('next_due')})
            healthy = self.last_tick and 0 <= now-self.last_tick < 20
            return {'schema': SCHEMA, 'auto_mode': True, 'get_time': int(now), 'providers': rows,
                    'registry_state': self.registry_state if healthy else 'worker_unavailable',
                    'registry_error': self.registry_error, 'source_count': len(rows), 'refresh_seconds': 30}

    def start(self):
        def run():
            while not self.stop.is_set():
                try:
                    self.tick()
                except Exception:
                    # No raw exception/URL logging; stale worker time is visible.
                    pass
                self.stop.wait(2)
        threading.Thread(target=run, name='subscription-usage', daemon=True).start()

    def close(self):
        self.stop.set()
        self.pool.shutdown(wait=True, cancel_futures=True)


def install(namespace, collector=None):
    if os.getenv('SUBSCRIPTION_USAGE_ENABLED', '1') != '1':
        return None
    collector = collector or Collector(namespace['SOURCES_FILE'], namespace['DATA'].parent/'subscription-usage')
    previous = namespace['Handler'].do_GET
    page = namespace['dashboard']
    namespace['dashboard'] = lambda: page().replace(b'</main>', (ROOT/'usage.html').read_bytes()+b'</main>')

    def send(handler, status, value):
        raw = json.dumps(value, ensure_ascii=False).encode()
        handler.send(status, 'application/json; charset=utf-8', raw)

    def get(handler):
        parsed = urllib.parse.urlsplit(handler.path)
        if parsed.path == '/subscription-usage.js':
            handler.send(200, 'text/javascript; charset=utf-8', (ROOT/'usage_ui.js').read_bytes())
        elif parsed.path == '/api/subscription-usage':
            send(handler, 200, collector.snapshot())
        elif parsed.path == '/subscription-info':
            auth = handler.headers.get('Authorization', '')
            if (handler.client_address[0] not in namespace['ALLOWED_PROVIDER_CLIENTS']
                    or not hmac.compare_digest(auth, 'Bearer '+collector.token)):
                send(handler, 403, {'error': 'forbidden'})
                return
            send(handler, 200, collector.snapshot())
        else:
            previous(handler)
    namespace['Handler'].do_GET = get
    collector.start()
    return collector
