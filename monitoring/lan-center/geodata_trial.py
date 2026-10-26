"""Bounded geodata collection and native compatibility trial; never changes routing."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.parse

REPO = 'MetaCubeX/meta-rules-dat'
CORE_SHA = '59198acb9b851f59ab328396684bc8c1ec70c432f8f1cd035c27ad2fdf549b08'
FILES = {'geosite.dat': 'GeoSite.dat', 'geoip.dat': 'GeoIP.dat',
         'country.mmdb': 'Country.mmdb', 'GeoLite2-ASN.mmdb': 'ASN.mmdb'}
MAX_DATA = 64 * 1024**2


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while part := stream.read(1024**2):
            h.update(part)
    return h.hexdigest()


def atomic(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False, encoding='utf-8') as stream:
        temporary = Path(stream.name)
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def metadata_assets(value):
    """Pin the exact repository, filenames, expected sizes and asset digests."""
    result = {}
    for item in value.get('assets', []):
        name = item.get('name')
        if name not in FILES:
            continue
        url = item.get('browser_download_url', '')
        parsed = urllib.parse.urlsplit(url)
        expected = '/'+REPO+'/releases/download/latest/'+name
        checksum = item.get('digest', '')
        size = item.get('size')
        if (name in result or parsed.scheme != 'https' or parsed.netloc != 'github.com'
                or parsed.path != expected or parsed.query or parsed.fragment
                or not isinstance(size, int) or not 10240 <= size <= MAX_DATA
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', checksum)):
            raise ValueError('invalid_upstream_asset')
        result[name] = {'url': url, 'sha256': checksum[7:], 'size': size}
    if set(result) != set(FILES):
        raise ValueError('upstream_assets_incomplete')
    return result


class Fetcher:
    def __init__(self, proxy='', proxy_auth=''):
        self.proxy, self.proxy_auth = proxy, proxy_auth
        self.deadline = time.monotonic()+360

    def fetch(self, url, target, limit=MAX_DATA):
        # Secrets travel through stdin, never process arguments or receipts.
        command = ['curl', '--fail', '--silent', '--show-error', '--location',
                   '--proto', '=https', '--proto-redir', '=https',
                   '--connect-timeout', '5', '--max-time', '60', '--limit-rate', '2M',
                   '--max-filesize', str(limit), '--output', str(target), '--write-out', '%{http_code}', '--config', '-']
        routes = [(self.proxy, self.proxy_auth), ('', '')] if self.proxy else [('', '')]
        code, exit_code = '000', 0
        for proxy, auth in routes:
            remaining = int(self.deadline-time.monotonic())
            if remaining < 5:
                raise RuntimeError('upstream_budget_exhausted')
            bounded_command = list(command)
            bounded_command[bounded_command.index('--max-time')+1] = str(min(60, remaining))
            config = 'url = '+json.dumps(url)+'\n'
            config += 'proxy = '+json.dumps(proxy)+'\n'  # An explicit empty proxy avoids inherited proxy variables.
            if proxy:
                config += 'proxy-user = '+json.dumps(auth)+'\n'
            try:
                result = subprocess.run(bounded_command, input=config, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=min(65, remaining+2))
                exit_code = result.returncode
                code = result.stdout.strip() if re.fullmatch(r'\d{3}', result.stdout.strip()) else '000'
            except subprocess.TimeoutExpired:
                exit_code, code = 28, '000'
                continue
            if result.returncode == 0 and target.is_file() and target.stat().st_size <= limit:
                target.chmod(0o600)
                return
        raise RuntimeError('upstream_fetch_failed_curl_'+str(exit_code)+'_http_'+code)


def categories_from_rules(document):
    values = {'cn', 'private', 'geolocation-cn'}
    for rule in document.get('rules', []):
        if rule.get('type') == 'GeoSite':
            value = rule.get('payload', '')
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_!@.:-]{1,160}', value):
                raise ValueError('unsupported_category_name')
            values.add(value)
    if not 1 <= len(values) <= 512:
        raise ValueError('category_count_invalid')
    return sorted(values)


def fixture(categories, dat_mode):
    return {'mode': 'rule', 'log-level': 'error', 'port': 0, 'socks-port': 0,
            'mixed-port': 0, 'external-controller': '', 'dns': {'enable': False},
            'geo-auto-update': False, 'geodata-loader': 'memconservative',
            'geodata-mode': dat_mode,
            'geox-url': {key: 'https://127.0.0.1:9/forbidden' for key in ('geoip', 'geosite', 'asn', 'mmdb')},
            'proxies': [], 'proxy-groups': [],
            'rules': ['GEOSITE,'+name+',REJECT' for name in categories]
                     + ['GEOIP,CN,REJECT', 'IP-ASN,13335,REJECT', 'MATCH,REJECT']}


def memory_headroom():
    root = Path('/sys/fs/cgroup')
    try:
        limit = (root/'memory.max').read_text().strip()
        if limit != 'max':
            return int(limit)-int((root/'memory.current').read_text())
    except (OSError, ValueError):
        pass
    return 2**63


def native_check(core, directory, categories, dat_mode):
    if memory_headroom() < 320 * 1024**2:
        raise RuntimeError('deferred_low_memory')
    config = directory/'native-check.json'
    atomic(config, fixture(categories, dat_mode))
    started = time.monotonic()
    peak = 0
    with open(directory/'native-check.private.log', 'ab') as log:
        child = subprocess.Popen(['nice', '-n', '19', str(core), '-t', '-d', str(directory), '-f', str(config)],
                                 env={**os.environ, 'GOMAXPROCS': '1', 'GOMEMLIMIT': '192MiB'},
                                 stdout=log, stderr=log, start_new_session=True)
        try:
            while child.poll() is None:
                try:
                    text = Path('/proc', str(child.pid), 'status').read_text()
                    match = re.search(r'^VmRSS:\s+(\d+) kB', text, re.M)
                    if match:
                        peak = max(peak, int(match[1]))
                except OSError:
                    pass
                if time.monotonic()-started > 60 or peak > 256*1024 or memory_headroom() < 64*1024**2:
                    raise RuntimeError('native_resource_budget_exceeded')
                time.sleep(.2)
            if child.returncode:
                raise RuntimeError('native_compatibility_failed')
        finally:
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
    return {'dat_mode': dat_mode, 'seconds': round(time.monotonic()-started, 3), 'peak_rss_kib': peak}


def verify_data(path, item):
    size = path.stat().st_size
    if (path.is_symlink() or not 10240 <= size <= MAX_DATA
            or item['size'] is not None and size != item['size'] or digest(path) != item['sha256']):
        raise ValueError('asset_checksum_or_size_failed')


def source_metadata(fetcher, work):
    metadata = work/'release.json'
    try:
        fetcher.fetch('https://api.github.com/repos/'+REPO+'/releases/tags/latest', metadata, 2*1024**2)
    except RuntimeError as error:
        if not str(error).startswith('upstream_fetch_failed'):
            raise
        # An unauthenticated API rate limit must not disable public data updates.
        # Use the same publisher's checksum assets; never guess digests or treat
        # download time as the upstream release timestamp.
        assets = {}
        for name in FILES:
            url = 'https://github.com/'+REPO+'/releases/download/latest/'+name
            checksum = work/(name+'.sha256sum')
            fetcher.fetch(url+'.sha256sum', checksum, 4096)
            match = re.fullmatch(r'([0-9a-f]{64})\s+\*?'+re.escape(name)+r'\s*', checksum.read_text().strip())
            if not match:
                raise ValueError('publisher_checksum_invalid')
            assets[name] = {'url': url, 'sha256': match[1], 'size': None}
        return {'name': 'checksum-pinned rolling latest', 'published_at': None,
                'metadata_mode': 'publisher_checksum_assets'}, assets
    release = json.loads(metadata.read_text())
    release['metadata_mode'] = 'github_release_api'
    return release, metadata_assets(release)


def collect(root, core, fetcher, category_loader):
    """An unchanged artifact avoids downloading it again and rerunning native tests."""
    if digest(core) != CORE_SHA:
        raise RuntimeError('native_core_pin_changed')
    with tempfile.TemporaryDirectory(prefix='.trial-', dir=root) as temporary:
        work = Path(temporary)
        release, assets = source_metadata(fetcher, work)
        categories = category_loader()
        ident = hashlib.sha256(json.dumps({'assets': assets, 'categories': categories, 'core': CORE_SHA}, sort_keys=True).encode()).hexdigest()
        previous_path = root/'candidate.json'
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
        versions = root/'candidates'
        versions.mkdir(mode=0o700, exist_ok=True)
        version = versions/ident
        cached_valid = version.is_dir() and not version.is_symlink()
        if cached_valid:
            try:
                for name, item in assets.items():
                    verify_data(version/FILES[name], item)
            except (OSError, ValueError):
                cached_valid = False
        if previous.get('id') == ident and cached_valid:
            return {**previous, 'unchanged': True}
        for name, item in assets.items():
            target = work/FILES[name]
            cached = version/FILES[name]
            if not cached.is_file() and re.fullmatch(r'[0-9a-f]{64}', previous.get('id', '')):
                cached = versions/previous['id']/FILES[name]
            if cached.is_file() and not cached.is_symlink() and digest(cached) == item['sha256']:
                shutil.copyfile(cached, target)
            else:
                fetcher.fetch(item['url'], target, item['size'] or MAX_DATA)
            verify_data(target, item)
        checks = [native_check(core, work, categories, dat_mode) for dat_mode in (False, True)]
        value = {'id': ident, 'source': REPO, 'release': release.get('name'),
                 'upstream_published_at': release.get('published_at'), 'metadata_mode': release['metadata_mode'],
                 'assets': assets, 'category_count': len(categories), 'native_checks': checks,
                 'production_applied': False, 'route_rehearsal': 'pending', 'validated_at': time.time()}
        # Commit an immutable candidate directory, then atomically switch only
        # its metadata pointer. A failed collection retains the previous one.
        atomic(work/'candidate.json', value)
        if version.exists():
            if version.is_symlink() or version.resolve().parent != versions.resolve():
                raise ValueError('unsafe_candidate_directory')
            shutil.rmtree(version)
        os.replace(work, version)
        atomic(previous_path, value)
        old = sorted((d for d in versions.iterdir() if re.fullmatch(r'[0-9a-f]{64}', d.name)
                      and d.is_dir() and not d.is_symlink() and d != version), key=lambda d: d.stat().st_mtime, reverse=True)
        for obsolete in old[2:]:
            if obsolete.resolve().parent == versions.resolve():
                shutil.rmtree(obsolete)
        return value


def main():
    import urllib.request
    p = argparse.ArgumentParser()
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--core', type=Path, default=Path('/local-subscription/core'))
    args = p.parse_args()
    os.umask(0o077)
    root = args.state.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (root/'operations.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'status': 'busy'}))
            return
        previous = json.loads((root/'status.json').read_text()) if (root/'status.json').exists() else {}
        def categories():
            request = urllib.request.Request(os.environ['OPENCLASH_API'].rstrip('/')+'/rules',
                                            headers={'Authorization': 'Bearer '+os.environ['OPENCLASH_SECRET']})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=10) as response:
                return categories_from_rules(json.load(response))
        try:
            candidate = collect(root, args.core.resolve(), Fetcher(os.getenv('PROXY', ''), os.getenv('PROXY_AUTH', '')), categories)
            status = {'status': 'candidate_ready', 'checked_at': time.time(), 'last_success_at': time.time(),
                      'candidate_id': candidate['id'], 'production_applied': False,
                      'route_rehearsal': candidate['route_rehearsal'], 'unchanged': candidate.get('unchanged', False)}
        except Exception as error:
            reason = str(error) if isinstance(error, (RuntimeError, ValueError)) and re.fullmatch(r'[a-z0-9_]{1,100}', str(error)) else type(error).__name__
            status = {'status': 'blocked', 'checked_at': time.time(), 'last_success_at': previous.get('last_success_at'),
                      'reason': reason, 'production_applied': False}
        atomic(root/'status.json', status)
        print(json.dumps(status))
        if status['status'] != 'candidate_ready':
            raise SystemExit(1)


if __name__ == '__main__':
    main()
