"""Authenticated, same-origin local source editor on the existing 3103 server."""
import hmac
import json
import os
import secrets
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path

from local_source import Invalid, Manager, native_validator

ROOT = Path(__file__).parent
SUBSCRIPTION_USAGE_INTEGRATED = True


class Access:
    def __init__(self, credential):
        self.credential = credential
        self.sessions = {}
        self.attempts = {}
        self.lock = threading.Lock()

    def login(self, client, token):
        with self.lock:
            now = time.monotonic()
            self.attempts = {k: v for k, v in self.attempts.items() if now - v[0] < 60}
            start, count = self.attempts.get(client, (now, 0))
            if count >= 5 or len(self.attempts) > 1024:
                raise Invalid('login_rate_limited')
            self.attempts[client] = (start, count + 1)
            if not isinstance(token, str) or not hmac.compare_digest(token, self.credential('admin-token')):
                raise Invalid('login_failed')
            self.sessions = {k: v for k, v in self.sessions.items() if now - v['at'] < 1800}
            if len(self.sessions) >= 32:
                raise Invalid('session_limit')
            sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[sid] = {'csrf': csrf, 'at': now}
            self.attempts.pop(client, None)
            return sid, csrf

    def session(self, cookie):
        try:
            cookies = SimpleCookie(cookie)
            sid = cookies['local_session'].value
        except Exception:
            return None, None
        with self.lock:
            entry = self.sessions.get(sid)
            if entry and time.monotonic() - entry['at'] < 1800:
                return sid, entry
            self.sessions.pop(sid, None)
        return None, None


def install(namespace, manager=None):
    Handler = namespace['Handler']
    def api(path, method='GET', body=None):
        return namespace['api_request'](method, path, json.dumps(body, ensure_ascii=False).encode() if body is not None else None)
    manager = manager or Manager(namespace['DATA'] / 'local-source', api, lambda nodes: native_validator(os.getenv('LOCAL_SOURCE_CORE', '/local-subscription/core'), nodes))
    access = Access(manager.credential)
    session_cookie_path = '/' if os.getenv('CENTER_UI_ENABLED', '0') == '1' else '/api/local'
    previous_get, previous_post = Handler.do_GET, Handler.do_POST
    dashboard = namespace['dashboard']
    fragment = (ROOT / 'editor.html').read_text()
    namespace['dashboard'] = lambda: dashboard().replace(b'</main>', fragment.encode() + b'</main>')

    def respond(h, code, value, cookie=None):
        raw = json.dumps(value, ensure_ascii=False).encode()
        h.send_response(code)
        h.send_header('Content-Type', 'application/json; charset=utf-8')
        h.send_header('Content-Length', str(len(raw)))
        h.send_header('Cache-Control', 'no-store')
        h.send_header('X-Content-Type-Options', 'nosniff')
        h.send_header('X-Frame-Options', 'DENY')
        if cookie:
            h.send_header('Set-Cookie', cookie)
        h.end_headers(); h.wfile.write(raw)

    def origin_ok(h):
        host = h.headers.get('Host', '')
        allowed = os.getenv('LOCAL_SOURCE_HOSTS', '10.88.0.249:3103,127.0.0.1:8082,localhost:8082').split(',')
        return host in allowed and h.headers.get('Origin') in ('http://' + host, 'https://' + host)

    def get(h):
        path = urllib.parse.urlsplit(h.path).path
        if path == '/local-source.js':
            h.send(200, 'text/javascript; charset=utf-8', (ROOT / 'editor.js').read_bytes())
        elif path == '/api/local/status':
            _, session = access.session(h.headers.get('Cookie', ''))
            if not session:
                respond(h, 401, {'error': 'login_required'})
                return
            try:
                respond(h, 200, {**manager.status(), 'csrf': session['csrf']})
            except Exception:
                respond(h, 503, {'error': 'local_status_unavailable'})
        elif path == '/providers/local-custom.yaml':
            auth = h.headers.get('Authorization', '')
            # This credential never appears in a URL or a LAN dashboard.
            if h.client_address[0] not in namespace['ALLOWED_PROVIDER_CLIENTS'] or not hmac.compare_digest(auth, 'Bearer ' + manager.credential('provider-token')):
                respond(h, 403, {'error': 'forbidden'})
                return
            try:
                h.send(200, 'text/yaml; charset=utf-8', manager.provider_payload())
            except Exception:
                respond(h, 503, {'error': 'local_provider_unavailable'})
        else:
            previous_get(h)

    def post(h):
        path = urllib.parse.urlsplit(h.path).path
        if not path.startswith('/api/local/'):
            return previous_post(h)
        if not origin_ok(h) or h.headers.get('Content-Type', '').split(';')[0] != 'application/json' or h.headers.get('Transfer-Encoding'):
            respond(h, 403, {'error': 'origin_or_content_type_forbidden'})
            return
        try:
            length = int(h.headers.get('Content-Length', '0'))
            if not 0 < length <= 262144:
                raise Invalid('request_size_invalid')
            h.connection.settimeout(15)
            raw = h.rfile.read(length)
            if len(raw) != length:
                raise Invalid('request_incomplete')
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise Invalid('request_object_required')
            if path == '/api/local/login':
                sid, csrf = access.login(h.client_address[0], req.get('token'))
                respond(h, 200, {'csrf': csrf}, 'local_session=' + sid + '; HttpOnly; SameSite=Strict; Path=' + session_cookie_path + '; Max-Age=1800' + ('; Secure' if os.getenv('LOCAL_SOURCE_HTTPS') == '1' else ''))
                return
            sid, session = access.session(h.headers.get('Cookie', ''))
            if not session or not hmac.compare_digest(h.headers.get('X-CSRF-Token', ''), session['csrf']):
                respond(h, 403, {'error': 'session_or_csrf_invalid'})
                return
            if path == '/api/local/logout':
                with access.lock:
                    access.sessions.pop(sid, None)
                respond(h, 200, {'status': 'logged_out'}, 'local_session=; HttpOnly; SameSite=Strict; Path=' + session_cookie_path + '; Max-Age=0')
            elif path == '/api/local/preview':
                nodes = manager.canonical(req.get('text', ''))
                manager.validator([{**n['proxy'], 'name': n['name']} for n in nodes])
                respond(h, 200, {'count': len(nodes), 'nodes': [{'id': n['id'], 'label': n['label'], 'type': n['proxy']['type']} for n in nodes]})
            elif path == '/api/local/publish':
                respond(h, 200, manager.update(req))
            else:
                respond(h, 404, {'error': 'not_found'})
        except Invalid as exc:
            respond(h, 409 if any(s in str(exc) for s in ('conflict', 'busy', 'pending')) else 400, {'error': str(exc)})
        except Exception:
            # Tracebacks and exception text can contain secrets; never reflect them.
            respond(h, 500, {'error': 'local_operation_failed'})

    Handler.do_GET, Handler.do_POST = get, post

    def recovery():
        while True:
            try:
                manager.recover()
                with manager_lock(manager):
                    state = manager.read('state.json')
                    loaded = False
                    try:
                        manager.verify(state['nodes'])
                        loaded = True
                    except Exception:
                        pass
                    from local_source import atomic
                    atomic(manager.root / 'runtime.json', {'version': state['version'], 'loaded': loaded, 'at': time.time()})
            except Exception:
                pass
            time.sleep(30)

    threading.Thread(target=recovery, name='local-source-recovery', daemon=True).start()
    try:
        from subscription_usage import install as install_usage
        install_usage(namespace)
    except Exception as error:
        if callable(namespace.get('log')):
            namespace['log']('subscription_usage_unavailable', type(error).__name__, 'warning')
    if os.getenv('CENTER_UI_ENABLED', '0') == '1':
        try:
            import sys
            if '/unified-center' not in sys.path:
                sys.path.insert(0, '/unified-center')
            from unified_center import install as install_center
            install_center(namespace, manager, access)
        except Exception as error:
            if callable(namespace.get('log')):
                namespace['log']('unified_center_unavailable', type(error).__name__, 'warning')
    return manager


def manager_lock(manager):
    from local_source import locked
    return locked(manager.root / 'writer.lock')
