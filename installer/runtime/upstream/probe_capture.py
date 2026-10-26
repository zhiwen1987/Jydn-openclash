"""Credential-safe curl evidence shared by production probes and acceptance tools."""
from __future__ import annotations

import base64
import datetime
import json
import os
import re
import subprocess
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

FIELDS = ('http_code', 'http_connect', 'time_namelookup', 'time_connect',
          'time_appconnect', 'time_pretransfer', 'time_starttransfer', 'time_total',
          'remote_ip', 'remote_port', 'local_ip', 'local_port', 'ssl_verify_result',
          'num_connects', 'http_version', 'proxy_used')


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def safe_url(value):
    """Do not retain userinfo, query strings or fragments in evidence."""
    try:
        u = urlsplit(value)
        host = u.hostname or ''
        if ':' in host:
            host = '[' + host + ']'
        if u.port:
            host += ':' + str(u.port)
        return urlunsplit((u.scheme, host, u.path, '', ''))
    except (ValueError, TypeError):
        return '[invalid URL]'


def redact(text, secrets=()):
    text = str(text or '')
    candidates = []
    for secret in secrets:
        if not secret:
            continue
        candidates.append(str(secret))
        if ':' in str(secret):
            candidates.extend(part for part in str(secret).split(':', 1) if len(part) >= 3)
    for secret in sorted(set(candidates), key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'(https?://)[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)\b(Basic|Bearer)\s+[A-Za-z0-9+/_=.-]+', r'\1 [REDACTED]', text)
    text = re.sub(r'(?i)([?&](?:token|key|secret|password|api_key)=)[^&\s]+', r'\1[REDACTED]', text)
    return text[:800]


def classify(exit_code, status, expected):
    if exit_code == 0 and status == expected:
        return 'healthy'
    if exit_code == 0:
        return {403: 'access_denied', 429: 'rate_limited', 451: 'geo_restricted'}.get(
            status, 'upstream_error' if status >= 500 else 'unexpected_http')
    if exit_code in (5, 6):
        return 'dns_error'
    if exit_code == 28:
        return 'timeout'
    if exit_code == 35:
        return 'tls_connect_error'
    if exit_code in (51, 60, 77, 90, 91):
        return 'tls_trust_error'
    if exit_code in (7, 52, 56):
        return 'connect_error'
    if exit_code in (16, 92):
        return 'http2_error'
    return 'transport_error'


def capture(url, expected=204, timeout=8, connect_timeout=5, curl_bin='curl',
            proxy=None, auth=None, runner=subprocess.run, wall=time.time,
            monotonic=time.monotonic):
    proxy = os.environ.get('PROXY', 'http://10.88.0.254:7893') if proxy is None else proxy
    auth = os.environ.get('PROXY_AUTH', '') if auth is None else auth
    proxy_userinfo = urlsplit(proxy).netloc.rsplit('@', 1)[0] if '@' in urlsplit(proxy).netloc else ''
    secrets = [auth, proxy_userinfo, os.environ.get('OPENCLASH_SECRET', '')]
    if auth:
        secrets.append(base64.b64encode(auth.encode()).decode())
    start = wall()
    mono = monotonic()
    result = {'schema': 1, 'probe_id': uuid.uuid4().hex, 'url': safe_url(url),
              'expected': expected, 'started_utc': datetime.datetime.fromtimestamp(start, datetime.timezone.utc).isoformat(),
              'started_epoch': start, 'timeout_seconds': timeout,
              'status': None, 'exit': None, 'curl_exit': None, 'seconds': None,
              'layer': 'curl', 'metrics': {}, 'stderr': '', 'kind': 'executor_error'}
    cfg = 'proxy = ' + json.dumps(proxy) + '\n'
    if auth:
        cfg += 'proxy-user = ' + json.dumps(auth) + '\n'
    args = [curl_bin, '-sS', '--connect-timeout', str(min(connect_timeout, timeout)),
            '--max-time', str(timeout), '--config', '-', '-o', '/dev/null',
            '-w', '%{json}', '-H', 'User-Agent: Mozilla/5.0 lan-center-business-probe', url]
    try:
        p = runner(args, input=cfg, text=True, capture_output=True, timeout=timeout + 1.5)
        result['exit'] = p.returncode
        result['stderr'] = redact(p.stderr, secrets)
        try:
            data = json.loads(p.stdout)
            if not isinstance(data, dict):
                raise ValueError('curl result is not an object')
            status = int(data['http_code'])
            result['status'] = status
            result['curl_exit'] = p.returncode
            result['metrics'] = {k: data[k] for k in FIELDS if k in data}
            result['seconds'] = data.get('time_total')
            result['curl_error'] = redact(data.get('errormsg'), secrets)
            result['kind'] = classify(p.returncode, status, expected)
        except (ValueError, KeyError, TypeError):
            result['layer'] = 'curl_output'
            result['kind'] = 'invalid_evidence'
            result['error_class'] = 'InvalidCurlEvidence'
    except subprocess.TimeoutExpired as error:
        result.update(layer='probe_executor', kind='executor_timeout', error_class=type(error).__name__)
    except OSError as error:
        result.update(layer='probe_executor', kind='executor_error', error_class=type(error).__name__,
                      stderr=redact(str(error), secrets))
    finally:
        result['finished_utc'] = utc_now()
        result['elapsed_monotonic_seconds'] = max(0, monotonic() - mono)
    return result
