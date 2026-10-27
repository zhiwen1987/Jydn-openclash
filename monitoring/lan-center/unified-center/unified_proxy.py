"""Small, fixed-target reverse proxy for the unified LAN management entry.

The module deliberately has no generic ``url=`` mode.  Uptime Kuma is always
127.0.0.1:3001; LuCI is derived from the private OPENCLASH_API host or from an
explicit private ROUTER_UI_URL.  Authentication remains at each upstream.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import os
import select
import selectors
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from http.cookies import SimpleCookie


@dataclass(frozen=True)
class _Target:
    name: str
    scheme: str
    host: str
    port: int

    @property
    def authority(self):
        host = "[" + self.host + "]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else "%s:%d" % (host, self.port)


_KUMA_TARGET = _Target("kuma", "http", "127.0.0.1", 3001)
_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}
_REQUEST_LIMIT = min(max(int(os.getenv("UNIFIED_PROXY_MAX_REQUEST_BYTES", "2097152")), 1024), 8 * 1024 * 1024)
_RESPONSE_LIMIT = min(max(int(os.getenv("UNIFIED_PROXY_MAX_RESPONSE_BYTES", "33554432")), 65536), 64 * 1024 * 1024)
_UPSTREAM_TIMEOUT = min(max(float(os.getenv("UNIFIED_PROXY_TIMEOUT", "20")), 1), 60)
_WS_IDLE_TIMEOUT = min(max(float(os.getenv("UNIFIED_PROXY_WS_IDLE_TIMEOUT", "120")), 10), 600)
_WS_MAX_SECONDS = min(max(float(os.getenv("UNIFIED_PROXY_WS_MAX_SECONDS", "3600")), 60), 86400)
_WS_MAX_BYTES = min(max(int(os.getenv("UNIFIED_PROXY_WS_MAX_BYTES", str(64 * 1024 * 1024))), 65536), 1024 * 1024 * 1024)
_WS_SEND_TIMEOUT = min(max(float(os.getenv("UNIFIED_PROXY_WS_SEND_TIMEOUT", "10")), 1), 60)
_SSE_MAX_SECONDS = min(max(float(os.getenv("UNIFIED_PROXY_SSE_MAX_SECONDS", "300")), 10), 1800)

_RESERVED = ("/center-assets", "/api/center", "/api/local", "/classic/subscriptions")
_KUMA_ADMIN = (
    "/dashboard", "/edit", "/clone", "/add", "/list", "/settings",
    "/manage-status-page", "/add-status-page", "/maintenance", "/add-maintenance",
    "/setup", "/setup-database", "/setup-database-info", "/empty", "/socket.io",
    "/metrics", "/api/auth",
)
_KUMA_PUBLIC = ("/status", "/status-page", "/api/status-page", "/api/entry-page", "/api/badge")
_KUMA_PUBLIC_FILES = {
    "/favicon.ico", "/icon.svg", "/manifest.json", "/robots.txt",
    "/apple-touch-icon.png",
}
_ROUTER = ("/cgi-bin/luci", "/luci-static", "/ubus")


class _ProxyError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status = status
        self.code = code


def _path_under(path, roots):
    return any(path == root or path.startswith(root + "/") for root in roots)


def _safe_path(raw_target):
    try:
        split = urllib.parse.urlsplit(raw_target)
    except ValueError:
        raise _ProxyError(400, "invalid_proxy_path")
    if split.scheme or split.netloc or split.fragment or not split.path.startswith("/"):
        raise _ProxyError(400, "invalid_proxy_path")
    probe = split.path
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(probe, errors="strict")
        except (UnicodeDecodeError, ValueError):
            raise _ProxyError(400, "invalid_proxy_path")
        if "\x00" in decoded or "\\" in decoded:
            raise _ProxyError(400, "invalid_proxy_path")
        if any(part in (".", "..") for part in decoded.split("/")):
            raise _ProxyError(400, "invalid_proxy_path")
        if decoded == probe:
            break
        probe = decoded
    return split, urllib.parse.unquote(split.path)


def _route(path):
    if path == "/" or _path_under(path, _RESERVED):
        return None
    if _path_under(path, _ROUTER):
        return "router", True
    if path.startswith("/assets/") or path.startswith("/upload/") or path in _KUMA_PUBLIC_FILES:
        return "kuma", False
    if _path_under(path, _KUMA_PUBLIC):
        return "kuma", False
    if _path_under(path, _KUMA_ADMIN):
        return "kuma", True
    return None


def _private_ip(host):
    try:
        value = ipaddress.ip_address(host)
    except ValueError:
        raise _ProxyError(503, "router_proxy_target_invalid")
    if value.is_unspecified or value.is_multicast or value.is_global:
        raise _ProxyError(503, "router_proxy_target_invalid")
    if not (value.is_private or value.is_loopback or value.is_link_local):
        raise _ProxyError(503, "router_proxy_target_invalid")
    return str(value)


def _parse_router_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise _ProxyError(503, "router_proxy_target_invalid")
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise _ProxyError(503, "router_proxy_target_invalid")
    host = _private_ip(parsed.hostname)
    return _Target("router", parsed.scheme, host, port or (443 if parsed.scheme == "https" else 80))


def _router_target():
    explicit = os.getenv("ROUTER_UI_URL", "").strip()
    if explicit:
        return _parse_router_url(explicit)
    api = os.getenv("OPENCLASH_API", "").strip()
    try:
        parsed = urllib.parse.urlsplit(api)
    except ValueError:
        raise _ProxyError(503, "router_proxy_not_configured")
    # OPENCLASH_API normally is http://private-address:9090.  HTTPS cannot be
    # safely converted to an HTTP UI target; it requires explicit ROUTER_UI_URL.
    if (parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or
            parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise _ProxyError(503, "router_proxy_not_configured")
    return _Target("router", "http", _private_ip(parsed.hostname), 80)


def _allowed_hosts():
    return {item.strip() for item in os.getenv(
        "LOCAL_SOURCE_HOSTS", "10.88.0.249:3103,127.0.0.1:8082,localhost:8082"
    ).split(",") if item.strip()}


def _origin_ok(handler):
    host = handler.headers.get("Host", "")
    origin = handler.headers.get("Origin", "")
    if host not in _allowed_hosts():
        return False
    try:
        value = urllib.parse.urlsplit(origin)
    except ValueError:
        return False
    return (value.scheme in ("http", "https") and value.netloc == host and
            value.username is None and value.password is None and value.path in ("", "/") and
            not value.query and not value.fragment)


def _has_access(access, cookie):
    if access is None or not callable(getattr(access, "session", None)):
        return False
    try:
        result = access.session(cookie or "")
        if isinstance(result, tuple):
            return len(result) > 1 and result[1] is not None
        return bool(result)
    except Exception:
        return False


def _respond(handler, status, code):
    raw = json.dumps({"error": code}, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Connection", "close")
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(raw)
    handler.close_connection = True


def _read_body(handler):
    if handler.headers.get("Transfer-Encoding"):
        raise _ProxyError(400, "chunked_request_not_supported")
    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        return b""
    try:
        length = int(raw_length)
    except ValueError:
        raise _ProxyError(400, "invalid_content_length")
    if length < 0 or length > _REQUEST_LIMIT:
        raise _ProxyError(413, "proxy_request_too_large")
    handler.connection.settimeout(_UPSTREAM_TIMEOUT)
    body = handler.rfile.read(length)
    if len(body) != length:
        raise _ProxyError(400, "incomplete_request_body")
    return body


def _cookie_header(raw, target_name):
    prefix = "__uc_%s_" % target_name
    output = []
    for part in (raw or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name.startswith(prefix) and len(name) > len(prefix):
            output.append(name[len(prefix):] + "=" + value)
    return "; ".join(output)


def _rewrite_set_cookie(value, target_name):
    first, separator, rest = value.partition(";")
    name, equals, cookie_value = first.partition("=")
    if not equals or not name.strip():
        return None
    attributes = []
    for item in rest.split(";") if separator else ():
        item = item.strip()
        if not item or item.lower().startswith("domain=") or item.lower().startswith("path="):
            continue
        attributes.append(item)
    result = "__uc_%s_%s=%s; Path=/" % (target_name, name.strip(), cookie_value)
    if attributes:
        result += "; " + "; ".join(attributes)
    return result


def _request_headers(handler, target, websocket=False):
    headers = {}
    connection_tokens = {part.strip().lower() for part in handler.headers.get("Connection", "").split(",")}
    for name, value in handler.headers.items():
        lower = name.lower()
        if lower in _HOP_HEADERS or lower in connection_tokens or lower in {
            "host", "cookie", "content-length", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"
        }:
            continue
        if lower in ("origin", "referer"):
            continue
        headers[name] = value
    headers["Host"] = target.authority
    cookie = _cookie_header(handler.headers.get("Cookie", ""), target.name)
    if cookie:
        headers["Cookie"] = cookie
    if handler.headers.get("Origin"):
        headers["Origin"] = "%s://%s" % (target.scheme, target.authority)
    if handler.headers.get("Referer"):
        headers["Referer"] = "%s://%s/" % (target.scheme, target.authority)
    headers["X-Forwarded-For"] = handler.client_address[0]
    headers["X-Forwarded-Host"] = handler.headers.get("Host", "")
    headers["X-Forwarded-Proto"] = "https" if os.getenv("LOCAL_SOURCE_HTTPS") == "1" else "http"
    if websocket:
        headers["Connection"] = "Upgrade"
        headers["Upgrade"] = "websocket"
    else:
        headers["Connection"] = "close"
    return headers


def _same_target(parsed, target):
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return parsed.scheme == target.scheme and parsed.hostname == target.host and port == target.port


def _location(value, target):
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        raise _ProxyError(502, "unsafe_upstream_redirect")
    if parsed.scheme or parsed.netloc:
        if parsed.scheme not in ("http", "https") or not _same_target(parsed, target):
            raise _ProxyError(502, "unsafe_upstream_redirect")
        return urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))
    if value.startswith("//") or "\r" in value or "\n" in value:
        raise _ProxyError(502, "unsafe_upstream_redirect")
    return value


def _connection(target):
    if target.scheme == "https":
        return http.client.HTTPSConnection(target.host, target.port, timeout=_UPSTREAM_TIMEOUT,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(target.host, target.port, timeout=_UPSTREAM_TIMEOUT)


def _response_headers(response, target):
    result = []
    connection_tokens = {part.strip().lower() for part in (response.getheader("Connection") or "").split(",")}
    for name, value in response.getheaders():
        lower = name.lower()
        if lower in _HOP_HEADERS or lower in connection_tokens or lower in ("content-length", "set-cookie"):
            continue
        if lower == "location":
            value = _location(value, target)
        result.append((name, value))
    for value in response.headers.get_all("Set-Cookie", []):
        rewritten = _rewrite_set_cookie(value, target.name)
        if rewritten:
            result.append(("Set-Cookie", rewritten))
    return result


def _proxy_sse(handler, response, target, headers):
    handler.send_response(response.status, response.reason)
    for name, value in headers:
        handler.send_header(name, value)
    handler.send_header("Cache-Control", response.getheader("Cache-Control") or "no-cache")
    handler.send_header("Connection", "close")
    handler.end_headers()
    deadline = time.monotonic() + _SSE_MAX_SECONDS
    total = 0
    try:
        while time.monotonic() < deadline and total < _RESPONSE_LIMIT:
            chunk = response.read(min(65536, _RESPONSE_LIMIT - total))
            if not chunk:
                break
            handler.wfile.write(chunk)
            handler.wfile.flush()
            total += len(chunk)
    except (OSError, TimeoutError, http.client.HTTPException):
        # Headers are already committed; terminate the bounded stream cleanly.
        pass
    handler.close_connection = True


def _proxy_http(handler, target, split):
    body = _read_body(handler)
    headers = _request_headers(handler, target)
    if body:
        headers["Content-Length"] = str(len(body))
    path = urllib.parse.urlunsplit(("", "", split.path, split.query, ""))
    connection = _connection(target)
    try:
        connection.request(handler.command, path, body=body or None, headers=headers)
        response = connection.getresponse()
        outgoing = _response_headers(response, target)
        content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        length = response.getheader("Content-Length")
        if length:
            try:
                if int(length) > _RESPONSE_LIMIT:
                    raise _ProxyError(502, "upstream_response_too_large")
            except ValueError:
                raise _ProxyError(502, "invalid_upstream_response")
        if content_type == "text/event-stream":
            _proxy_sse(handler, response, target, outgoing)
            return
        data = response.read(_RESPONSE_LIMIT + 1)
        if len(data) > _RESPONSE_LIMIT:
            raise _ProxyError(502, "upstream_response_too_large")
        handler.send_response(response.status)
        for name, value in outgoing:
            handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        if handler.command != "HEAD":
            try:
                handler.wfile.write(data)
            except OSError:
                handler.close_connection = True
    finally:
        connection.close()


def _open_socket(target):
    raw = socket.create_connection((target.host, target.port), timeout=_UPSTREAM_TIMEOUT)
    if target.scheme == "https":
        return ssl.create_default_context().wrap_socket(raw, server_hostname=target.host)
    return raw


def _read_http_head(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise _ProxyError(502, "upstream_websocket_closed")
        data.extend(chunk)
        if len(data) > 65536:
            raise _ProxyError(502, "upstream_websocket_headers_too_large")
    head, extra = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    try:
        version, status, reason = lines[0].decode("latin-1").split(" ", 2)
        status = int(status)
    except (ValueError, UnicodeDecodeError):
        raise _ProxyError(502, "invalid_upstream_websocket_response")
    headers = []
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            raise _ProxyError(502, "invalid_upstream_websocket_response")
        headers.append((name.decode("latin-1").strip(), value.decode("latin-1").strip()))
    return version, status, reason, headers, extra


def _send_tunnel_bytes(destination, data, hard_deadline, last_activity):
    """Write one bounded tunnel chunk without busy-waiting on backpressure."""
    view = memoryview(data)
    progress_at = time.monotonic()
    while view:
        now = time.monotonic()
        deadline = min(hard_deadline, last_activity + _WS_IDLE_TIMEOUT, progress_at + _WS_SEND_TIMEOUT)
        if now >= deadline:
            return False, last_activity
        try:
            sent = destination.send(view)
            if sent <= 0:
                return False, last_activity
            view = view[sent:]
            progress_at = last_activity = time.monotonic()
            continue
        except (BlockingIOError, ssl.SSLWantWriteError):
            pass
        except ssl.SSLWantReadError:
            readable, _, _ = select.select([destination], [], [], min(0.25, max(0, deadline - now)))
            if not readable and time.monotonic() >= deadline:
                return False, last_activity
            continue
        _, writable, exceptional = select.select([], [destination], [destination], min(0.25, max(0, deadline - now)))
        if exceptional:
            return False, last_activity
        if not writable and time.monotonic() >= deadline:
            return False, last_activity
    return True, last_activity


def _tunnel(client, upstream, initial=b""):
    client.setblocking(False)
    upstream.setblocking(False)
    started = last = time.monotonic()
    hard_deadline = started + _WS_MAX_SECONDS
    total = 0
    if initial:
        if len(initial) > _WS_MAX_BYTES:
            return
        forwarded, last = _send_tunnel_bytes(client, initial, hard_deadline, last)
        if not forwarded:
            return
        total = len(initial)
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, upstream)
    selector.register(upstream, selectors.EVENT_READ, client)
    try:
        while time.monotonic() < hard_deadline and total < _WS_MAX_BYTES:
            remaining = min(hard_deadline - time.monotonic(), last + _WS_IDLE_TIMEOUT - time.monotonic())
            if remaining <= 0:
                break
            events = selector.select(timeout=min(1.0, remaining))
            now = time.monotonic()
            if not events:
                if now - last >= _WS_IDLE_TIMEOUT:
                    break
                continue
            for key, _ in events:
                try:
                    data = key.fileobj.recv(min(65536, _WS_MAX_BYTES - total))
                except (BlockingIOError, ssl.SSLWantReadError):
                    continue
                if not data:
                    return
                destination = key.data
                last = now
                forwarded, last = _send_tunnel_bytes(destination, data, hard_deadline, last)
                if not forwarded:
                    return
                total += len(data)
    finally:
        selector.close()


def _proxy_websocket(handler, target, split):
    if not _origin_ok(handler):
        raise _ProxyError(403, "websocket_origin_forbidden")
    if "upgrade" not in {v.strip().lower() for v in handler.headers.get("Connection", "").split(",")}:
        raise _ProxyError(400, "invalid_websocket_upgrade")
    key = handler.headers.get("Sec-WebSocket-Key", "")
    try:
        if len(base64.b64decode(key, validate=True)) != 16:
            raise ValueError
    except (ValueError, binascii.Error):
        raise _ProxyError(400, "invalid_websocket_key")
    if handler.headers.get("Sec-WebSocket-Version") != "13":
        raise _ProxyError(400, "invalid_websocket_version")
    path = urllib.parse.urlunsplit(("", "", split.path, split.query, ""))
    headers = _request_headers(handler, target, websocket=True)
    request = ["GET %s HTTP/1.1" % path]
    request.extend("%s: %s" % item for item in headers.items())
    upstream = _open_socket(target)
    upgraded = False
    try:
        upstream.sendall(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
        _, status, _reason, response_headers, extra = _read_http_head(upstream)
        if status != 101:
            raise _ProxyError(502, "upstream_websocket_rejected")
        allowed = {"upgrade", "connection", "sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions"}
        received = {name.lower(): value for name, value in response_headers}
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        if (received.get("upgrade", "").lower() != "websocket" or
                "upgrade" not in {item.strip().lower() for item in received.get("connection", "").split(",")} or
                received.get("sec-websocket-accept") != expected):
            raise _ProxyError(502, "invalid_upstream_websocket_response")
        # BaseHTTPRequestHandler defaults to HTTP/1.0.  RFC 6455 upgrades are
        # HTTP/1.1 handshakes, so constrain the override to this one response.
        original_protocol = handler.protocol_version
        handler.protocol_version = "HTTP/1.1"
        try:
            handler.send_response_only(101)
            for name, value in response_headers:
                if name.lower() in allowed:
                    handler.send_header(name, value)
            handler.end_headers()
            handler.wfile.flush()
        finally:
            handler.protocol_version = original_protocol
        upgraded = True
        try:
            _tunnel(handler.connection, upstream, extra)
        except (OSError, TimeoutError, ssl.SSLError):
            # A reset after 101 is a tunnel close, not a second HTTP response.
            pass
        handler.close_connection = True
    finally:
        try:
            upstream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        upstream.close()
        if upgraded:
            handler.close_connection = True


def proxy_request(handler, access=None):
    """Proxy an allowed Kuma/LuCI request, returning whether it was handled.

    The caller should invoke this only after its own unified-center routes have
    had a chance to match.  A ``False`` result means the path is not owned here.
    """
    try:
        split, path = _safe_path(handler.path)
        route = _route(path)
        if route is None:
            return False
        target_name, needs_access = route
        if handler.command not in ("GET", "HEAD", "POST"):
            raise _ProxyError(405, "proxy_method_not_allowed")
        if handler.command == "POST" and not _origin_ok(handler):
            raise _ProxyError(403, "proxy_origin_forbidden")
        if needs_access and not _has_access(access, handler.headers.get("Cookie", "")):
            raise _ProxyError(401, "management_session_required")
        target = _KUMA_TARGET if target_name == "kuma" else _router_target()
        upgrade = handler.headers.get("Upgrade", "").lower()
        if upgrade:
            if upgrade != "websocket" or target_name != "kuma" or not _path_under(path, ("/socket.io",)):
                raise _ProxyError(400, "proxy_upgrade_not_allowed")
            _proxy_websocket(handler, target, split)
        else:
            _proxy_http(handler, target, split)
        return True
    except _ProxyError as error:
        _respond(handler, error.status, error.code)
        return True
    except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError):
        _respond(handler, 502, "proxy_upstream_unavailable")
        return True
