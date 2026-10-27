import base64
import hashlib
import json
import os
import socket
import socketserver
import threading
import time
import unittest
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import unified_proxy as proxy


class Access:
    def session(self, cookie):
        return ("valid", {"csrf": "test"}) if "local_session=valid" in cookie else (None, None)


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/same-redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/dashboard" % self.server.server_port)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/large":
            body = b"x" * 32
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.com/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({
            "path": self.path,
            "host": self.headers.get("Host"),
            "cookie": self.headers.get("Cookie"),
            "origin": self.headers.get("Origin"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "upstream=abc; HttpOnly; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        data = json.dumps({
            "body": body.decode(),
            "origin": self.headers.get("Origin"),
            "cookie": self.headers.get("Cookie"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not proxy.proxy_request(self, Access()):
            body = b"center"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_HEAD(self):
        if not proxy.proxy_request(self, Access()):
            self.send_error(404)

    def do_POST(self):
        if not proxy.proxy_request(self, Access()):
            self.send_error(404)

    def log_message(self, *args):
        pass


class WebSocketUpstream(socketserver.BaseRequestHandler):
    def handle(self):
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            raw.extend(self.request.recv(4096))
        headers = {}
        for line in bytes(raw).split(b"\r\n")[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers[name.decode().lower()] = value.decode().strip()
        accept = base64.b64encode(hashlib.sha1(
            (headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest()).decode()
        self.request.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n" % accept
        ).encode())
        data = self.request.recv(4096)
        if data:
            self.request.sendall(data)


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


class UnifiedProxyTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {
            "LOCAL_SOURCE_HOSTS": "127.0.0.1",
            "OPENCLASH_API": "http://10.88.0.254:9090",
        }, clear=False)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    @contextmanager
    def stack(self):
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        target = proxy._Target("kuma", "http", "127.0.0.1", upstream.server_port)
        front = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        with mock.patch.object(proxy, "_KUMA_TARGET", target), running(upstream), running(front):
            yield front, upstream

    def request(self, front, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", front.server_port, timeout=3)
        base = {"Host": "127.0.0.1"}
        base.update(headers or {})
        connection.request(method, path, body=body, headers=base)
        response = connection.getresponse()
        data = response.read()
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    def test_reserved_center_routes_are_not_swallowed(self):
        with self.stack() as (front, _):
            for path in ("/", "/center-assets/app.js", "/api/center/overview", "/api/local/status"):
                status, _, body = self.request(front, "GET", path)
                self.assertEqual((status, body), (200, b"center"))
            status, _, body = self.request(front, "GET", "/api/not-a-kuma-route")
            self.assertEqual((status, body), (200, b"center"))

    def test_admin_requires_center_session_and_public_status_does_not(self):
        with self.stack() as (front, _):
            status, _, body = self.request(front, "GET", "/dashboard")
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(body)["error"], "management_session_required")
            for path in ("/status/public", "/status-page"):
                status, _, _ = self.request(front, "GET", path)
                self.assertEqual(status, 200)

    def test_service_worker_is_authenticated_local_retirement_response(self):
        with self.stack() as (front, _):
            status, _, body = self.request(front, "GET", "/serviceWorker.js")
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(body)["error"], "management_session_required")

            cookie = {"Cookie": "local_session=valid"}
            with mock.patch.object(proxy, "_connection", side_effect=AssertionError("upstream must not be used")):
                status, headers, body = self.request(front, "GET", "/serviceWorker.js", headers=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], "application/javascript; charset=utf-8")
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(int(headers["Content-Length"]), len(body))
                lowered = body.lower()
                for forbidden in (b"fetch", b"cache", b"upstream", b"/api/center", b"/center-assets", b"location"):
                    self.assertNotIn(forbidden, lowered)
                self.assertIn(b"skipwaiting", lowered)
                self.assertIn(b"registration.unregister", lowered)

                status, headers, body = self.request(front, "HEAD", "/serviceWorker.js", headers=cookie)
                self.assertEqual((status, body), (200, b""))
                self.assertEqual(int(headers["Content-Length"]), len(proxy._RETIRED_SERVICE_WORKER))

            status, _, body = self.request(front, "POST", "/serviceWorker.js", b"", cookie)
            self.assertEqual(status, 405)
            self.assertEqual(json.loads(body)["error"], "proxy_method_not_allowed")

    def test_http_query_cookie_isolation_and_set_cookie_namespace(self):
        with self.stack() as (front, upstream):
            headers = {"Cookie": "local_session=valid; unrelated=drop; __uc_kuma_login=yes"}
            status, response_headers, body = self.request(front, "GET", "/dashboard?x=1", headers=headers)
            self.assertEqual(status, 200)
            value = json.loads(body)
            self.assertEqual(value["path"], "/dashboard?x=1")
            self.assertEqual(value["host"], "127.0.0.1:%d" % upstream.server_port)
            self.assertEqual(value["cookie"], "login=yes")
            self.assertIn("__uc_kuma_upstream=abc", response_headers["Set-Cookie"])
            self.assertNotIn("Domain=", response_headers["Set-Cookie"])

    def test_post_requires_trusted_origin_and_rewrites_it_for_upstream(self):
        with self.stack() as (front, upstream):
            headers = {"Cookie": "local_session=valid", "Content-Type": "application/json"}
            status, _, _ = self.request(front, "POST", "/api/auth/login", b"{}", headers)
            self.assertEqual(status, 403)
            headers["Origin"] = "http://127.0.0.1"
            status, _, body = self.request(front, "POST", "/api/auth/login", b"{}", headers)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["origin"], "http://127.0.0.1:%d" % upstream.server_port)

    def test_request_and_response_limits_fail_closed(self):
        with self.stack() as (front, _):
            headers = {"Cookie": "local_session=valid", "Origin": "http://127.0.0.1"}
            with mock.patch.object(proxy, "_REQUEST_LIMIT", 2):
                status, _, body = self.request(front, "POST", "/api/auth/login", b"123", headers)
                self.assertEqual(status, 413)
                self.assertEqual(json.loads(body)["error"], "proxy_request_too_large")
            with (mock.patch.object(proxy, "_RESPONSE_LIMIT", 16),
                  mock.patch.object(proxy, "_KUMA_ADMIN", proxy._KUMA_ADMIN + ("/large",))):
                status, _, body = self.request(front, "GET", "/large", headers={"Cookie": "local_session=valid"})
                self.assertEqual(status, 502)
                self.assertEqual(json.loads(body)["error"], "upstream_response_too_large")

    def test_path_traversal_is_rejected(self):
        with self.stack() as (front, _):
            status, _, body = self.request(front, "GET", "/dashboard/%252e%252e/secret",
                                           headers={"Cookie": "local_session=valid"})
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body)["error"], "invalid_proxy_path")

    def test_router_target_rejects_public_or_credentialed_urls(self):
        for value in ("https://example.com", "http://user:password@10.0.0.1"):
            with mock.patch.dict(os.environ, {"ROUTER_UI_URL": value}):
                with self.assertRaises(proxy._ProxyError):
                    proxy._router_target()
        with mock.patch.dict(os.environ, {"ROUTER_UI_URL": "https://10.0.0.1:8443"}):
            target = proxy._router_target()
            self.assertEqual((target.scheme, target.host, target.port), ("https", "10.0.0.1", 8443))

    def test_luci_uses_only_explicit_private_fixed_target(self):
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        front = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        value = "http://127.0.0.1:%d" % upstream.server_port
        with mock.patch.dict(os.environ, {"ROUTER_UI_URL": value}), running(upstream), running(front):
            status, _, body = self.request(front, "GET", "/cgi-bin/luci/admin/status",
                                           headers={"Cookie": "local_session=valid; __uc_router_sysauth=router-token"})
            self.assertEqual(status, 200)
            decoded = json.loads(body)
            self.assertEqual(decoded["cookie"], "sysauth=router-token")
            self.assertEqual(decoded["path"], "/cgi-bin/luci/admin/status")

    def test_redirect_only_rewrites_same_fixed_target(self):
        with self.stack() as (front, _):
            cookie = {"Cookie": "local_session=valid"}
            # These paths are patched into the explicit admin allowlist for the focused redirect test.
            with mock.patch.object(proxy, "_KUMA_ADMIN", proxy._KUMA_ADMIN + ("/same-redirect", "/external-redirect")):
                status, headers, _ = self.request(front, "GET", "/same-redirect", headers=cookie)
                self.assertEqual(status, 302)
                self.assertEqual(headers["Location"], "/dashboard")
                status, _, body = self.request(front, "GET", "/external-redirect", headers=cookie)
                self.assertEqual(status, 502)
                self.assertEqual(json.loads(body)["error"], "unsafe_upstream_redirect")

    def test_real_websocket_upgrade_and_bidirectional_bytes(self):
        self.assertEqual(ProxyHandler.protocol_version, "HTTP/1.0")
        websocket = socketserver.ThreadingTCPServer(("127.0.0.1", 0), WebSocketUpstream)
        websocket.daemon_threads = True
        target = proxy._Target("kuma", "http", "127.0.0.1", websocket.server_address[1])
        front = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        with mock.patch.object(proxy, "_KUMA_TARGET", target), running(websocket), running(front):
            client = socket.create_connection(("127.0.0.1", front.server_port), timeout=3)
            key = base64.b64encode(b"0123456789abcdef").decode()
            client.sendall((
                "GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n"
                "Cookie: local_session=valid\r\nConnection: Upgrade\r\n"
                "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: %s\r\n\r\n" % key
            ).encode())
            response = bytearray()
            while b"\r\n\r\n" not in response:
                response.extend(client.recv(4096))
            self.assertEqual(response.split(b"\r\n", 1)[0], b"HTTP/1.1 101 Switching Protocols")
            payload = b"\x81\x82\x01\x02\x03\x04ik"  # a complete masked websocket frame
            client.sendall(payload)
            self.assertEqual(client.recv(len(payload)), payload)
            client.close()

    def test_websocket_backpressure_has_bounded_write_wait(self):
        source_tunnel, source_peer = socket.socketpair()
        destination_tunnel, destination_peer = socket.socketpair()
        sockets = (source_tunnel, source_peer, destination_tunnel, destination_peer)
        try:
            destination_tunnel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            destination_tunnel.setblocking(False)
            filler = b"z" * 65536
            while True:
                try:
                    destination_tunnel.send(filler)
                except BlockingIOError:
                    break
            source_peer.sendall(b"tunnel-data")
            thread = threading.Thread(target=proxy._tunnel, args=(source_tunnel, destination_tunnel), daemon=True)
            started = time.monotonic()
            with (mock.patch.object(proxy, "_WS_SEND_TIMEOUT", 0.15),
                  mock.patch.object(proxy, "_WS_IDLE_TIMEOUT", 1.0),
                  mock.patch.object(proxy, "_WS_MAX_SECONDS", 1.0)):
                thread.start()
                thread.join(0.8)
            self.assertFalse(thread.is_alive(), "backpressured tunnel exceeded its bounded send wait")
            self.assertLess(time.monotonic() - started, 0.8)
        finally:
            for item in sockets:
                item.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
