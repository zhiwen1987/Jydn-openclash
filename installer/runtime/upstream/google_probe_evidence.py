"""Google-only GET monitor. No write APIs, selector changes or DNS alterations."""
from __future__ import annotations

import datetime
import fcntl
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

from probe_capture import capture, redact, utc_now

URL = 'https://www.google.com/generate_204'
GROUP = '🔎 谷歌服务（Google）'
MAX_LOG = 8 * 1024 * 1024
BACKUPS = 3


def route_snapshot():
    base = os.environ.get('OPENCLASH_API', 'http://10.88.0.254:9090').rstrip('/')
    headers = {}
    if os.environ.get('OPENCLASH_SECRET'):
        headers['Authorization'] = 'Bearer ' + os.environ['OPENCLASH_SECRET']
    try:
        request = urllib.request.Request(base + '/proxies', headers=headers, method='GET')
        # Do not use HTTP(S)_PROXY from the environment for this LAN control read.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=0.6) as response:
            payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ValueError('oversized control response')
        proxies = json.loads(payload)['proxies']
        chain = []
        name = GROUP
        while name and name not in chain and len(chain) < 12:
            chain.append(name)
            name = proxies.get(name, {}).get('now')
        return {'ok': GROUP in proxies, 'at_utc': utc_now(), 'configured_chain': chain,
                'evidence_type': 'read_only_configuration_snapshot_not_per_request_connection_trace'}
    except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
        return {'ok': False, 'at_utc': utc_now(), 'error_class': type(error).__name__}


def append_evidence(root, record):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / 'google-probe-evidence.jsonl'
    fd = os.open(root / '.google-probe-evidence.lock', os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cutoff = time.time() - 7 * 86400
        for index in range(1, BACKUPS + 1):
            old = Path(str(path) + '.' + str(index))
            if old.exists() and old.stat().st_mtime < cutoff:
                old.unlink()
        if path.exists() and path.stat().st_size >= MAX_LOG:
            last = Path(str(path) + '.' + str(BACKUPS))
            if last.exists():
                last.unlink()
            for index in range(BACKUPS - 1, 0, -1):
                old = Path(str(path) + '.' + str(index))
                if old.exists():
                    os.replace(old, Path(str(path) + '.' + str(index + 1)))
            os.replace(path, Path(str(path) + '.1'))
        fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
            stream.flush()
            os.fsync(stream.fileno())


def legacy_event(root, record, status):
    path = Path(os.environ.get('BUSINESS_PROBE_LOG', str(Path(root) / 'business-probe.log')))
    line = '{} probe=google status={} attempt={} http_code={} curl_code={} latency_ms={} reason={} probe_id={}\n'.format(
        time.strftime('%F %T'), status, record['attempt'], str(record.get('status') or 0).zfill(3),
        record.get('curl_exit') if record.get('curl_exit') is not None else -1,
        int((record.get('seconds') or 0) * 1000), record['kind'], record['probe_id'])
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as stream:
        stream.write(line)


def probe(root='/data', collector=capture, route=route_snapshot, clock=time.monotonic,
          sleeper=time.sleep, writer=append_evidence):
    start = clock()
    deadline = start + 12.5
    route_before = route()
    marker = Path(root) / '.business-probe-google-degraded'
    attempts = []
    for number in range(1, 3):
        remaining = deadline - clock() - 0.8
        if remaining < 0.3:
            break
        result = collector(URL, expected=204, timeout=min(5.0, remaining), connect_timeout=4)
        result.update(attempt=number, probe='google', route_before=route_before)
        result['route_after'] = route()
        result['configured_route_changed'] = (route_before.get('configured_chain') != result['route_after'].get('configured_chain'))
        attempts.append(result)
        writer(root, result)  # First failure is durable BEFORE rechecking.
        if result['kind'] == 'healthy':
            if marker.exists():
                legacy_event(root, result, 'recovered')
                marker.unlink()
            return {'status': 'ok', 'probe': 'google', 'probe_id': result['probe_id'],
                    'attempts': len(attempts), 'first_failure_preserved': len(attempts) > 1}, 0
        marker.touch(mode=0o600, exist_ok=True)
        legacy_event(root, result, 'failed')
        # Restrictions and other valid HTTP responses are not repaired by rapid retries.
        if result['kind'] in ('access_denied', 'rate_limited', 'geo_restricted', 'unexpected_http'):
            break
        if number == 1 and deadline - clock() > 1.4:
            sleeper(1)
    last = attempts[-1] if attempts else {'kind': 'executor_budget', 'status': None, 'curl_exit': None, 'seconds': 0}
    return {'status': 'down', 'probe': 'google', 'reason': last['kind'],
            'http_code': str(last.get('status') or 0).zfill(3), 'curl_code': last.get('curl_exit'),
            'latency_ms': int((last.get('seconds') or 0) * 1000), 'attempts': len(attempts),
            'probe_id': last.get('probe_id'), 'first_failure_preserved': bool(attempts)}, 1


def main():
    os.umask(0o077)
    try:
        result, code = probe(root=os.environ.get('BUSINESS_PROBE_STATE_DIR', '/data'))
    except Exception as error:
        # No tracebacks/configuration/credentials in an HTTP error response.
        result, code = {'status': 'down', 'probe': 'google', 'reason': 'probe_executor_error',
                        'error_class': type(error).__name__}, 2
        print(json.dumps(result), file=__import__('sys').stderr)
    print(json.dumps(result, ensure_ascii=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
