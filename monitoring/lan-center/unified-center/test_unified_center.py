import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import tarfile
import types
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from datetime import datetime, timedelta, timezone


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "installer" / "runtime" / "upstream"))
SPEC = importlib.util.spec_from_file_location("unified_center_under_test", HERE / "unified_center.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
Center, install = MODULE.Center, MODULE.install


class FakeAccess:
    def __init__(self):
        self.sessions = {"valid": {"csrf": "csrf-token", "at": time.monotonic()}}

    def session(self, cookie):
        if "local_session=valid" in cookie:
            return "valid", self.sessions["valid"]
        return None, None


class FakeManager:
    def __init__(self, root):
        self.root = Path(root) / "local-source"
        self.root.mkdir(parents=True)
        self.routing_lock = Path(root) / "routing-owner.lock"


class FakeClash:
    def __init__(self):
        self.selected = "A"
        self.puts = []
        self.delay = 37

    def __call__(self, method, path, body=None, timeout=None):
        if path == "/proxies" and method == "GET":
            return {"proxies": {"Business": {"type": "Selector", "now": self.selected, "all": ["A", "B"]}}}
        if path == "/proxies/Business" and method == "GET":
            return {"type": "Selector", "now": self.selected, "all": ["A", "B"]}
        if path == "/proxies/Business" and method == "PUT":
            self.selected = json.loads(body)["name"]
            self.puts.append(self.selected)
            return {}
        if path == "/providers/proxies" and method == "GET":
            return {"providers": {
                "provider-a": {"proxies": [{"name": "A"}, {"name": "B"}]},
                "provider-b": {"proxies": [{"name": "C"}]},
            }}
        if path.startswith("/providers/proxies/provider-a/A/healthcheck?") and method == "GET":
            return {"delay": self.delay}
        if path == "/version" and method == "GET":
            return {"version": "test"}
        if path == "/rules" and method == "GET":
            return {"rules": [{"type": "MATCH", "proxy": "Business"}]}
        if path == "/configs" and method == "GET":
            return {"mode": "rule", "allow-lan": True, "secret": "must-not-leak"}
        raise AssertionError((method, path))


def namespace(root, clash=None):
    root = Path(root)
    data = root / "controller"
    data.mkdir(parents=True, exist_ok=True)
    return {
        "DATA": data,
        "DB_PATH": data / "controller.db",
        "SOURCES_FILE": root / "subscription-sources.json",
        "api_request": clash or FakeClash(),
        "latest_status": lambda: {
            "status": "ok", "epoch": int(time.time()), "node_count": 3,
            "release_status": "same_as_current", "sources": [], "releases": [],
        },
    }


def values(now=None):
    now = int(now or time.time())
    return {
        "controller": {"status": "ok", "epoch": now, "node_count": 3, "release_status": "same_as_current"},
        "manifest": {"available": True, "published_at": now - 10, "sources": [
            {"provider_name": "provider-a", "node_count": 2, "names": ["A", "B"]},
            {"provider_name": "provider-b", "node_count": 1, "names": ["C"]},
        ]},
        "nodes": {"generated_at": now, "progress": {"status": "ok", "epoch": now, "last_probe_epoch": now - 5},
                  "business_labels": {"chatgpt": "ChatGPT"}, "nodes": [
            {"id": "n1", "name": "A", "provider": "provider-a", "state": "healthy", "score": 91,
             "latency_ms": 40, "updated_at": now, "fresh_until": now + 300, "fresh": True,
             "confidence": 90, "health_schedule": {"status": "available", "next_due": now + 300},
             "latency_kind": "Clash HTTPS HEAD", "latency_summary": {"samples": 2, "median_ms": 40, "p95_ms": None},
             "egress": {"country": "US", "colo": "SJC", "last_checked": now},
             "capabilities": {"chatgpt": {"status": "available", "last_checked": now, "confidence": 90}}}
        ]},
        "usage": {"schema": 2, "get_time": now, "source_count": 3, "providers": [
            {"id": "one", "name": "One", "usage_status": "ok", "last_success": now, "url": "https://subscription.invalid/URL_CANARY"},
            {"id": "two", "name": "Two", "usage_status": "cached", "last_success": now - 30},
            {"id": "three", "name": "Three", "usage_status": "checking"},
        ], "registry_state": "ok", "source_sync": {"state": "ok", "managed_count": 3, "last_success": now - 20, "token": "TOKEN_CANARY", "path": "/PATH_CANARY"}},
        "clash": {
            "proxies": {"proxies": {
                "ChatGPT": {"type": "Selector", "now": "Gateway", "all": ["Gateway"]},
                "Gateway": {"type": "Selector", "now": "A", "all": ["A", "B"]},
                "A": {"type": "VLESS", "history": []},
                "GLOBAL": {"type": "Selector", "now": "A", "all": ["A"]},
                "🧪 节点能力检测": {"type": "Selector", "now": "A", "all": ["A"]},
                "🔬 节点归属校验": {"type": "Selector", "now": "A", "all": ["A"]},
            }},
            "providers": {"providers": {
                "provider-a": {"proxies": [{"name": "A"}, {"name": "B"}]},
                "provider-b": {"proxies": [{"name": "C"}]},
            }},
            "rules": {"rules": [{"type": "MATCH"}]},
            "configs": {"mode": "rule", "allow-lan": True, "secret": "redact"},
            "errors": [],
        },
        "files": {"controller_health": {"status": "ok", "node_count": 3}},
        "dns": {"upstreams": ["1.1.1.1"], "mtime": now, "config_state": "ok", "health_state": "ok"},
        "kuma": {"health_state": "ok", "database_state": "ok", "http": {"state": "ok", "status": 200},
                 "monitors": [{"id": "1", "name": "Business", "state": "ok", "checked_at": now, "detail": "Heartbeat 正常"}]},
    }


@contextlib.contextmanager
def env(**updates):
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update({key: str(value) for key, value in updates.items()})
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class ComposeTests(unittest.TestCase):
    def test_dns_probe_evidence_reaches_ui_with_only_public_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            evidence = values()
            evidence["dns"]["probes"] = {
                "health": {"state": "ok", "status": 200, "checked_at": 123, "private": "canary"},
                "ready": {"state": "error", "status": 503},
                "private": {"secret": "canary"},
            }
            result = center.compose(evidence, {})["dns"]["probes"]
            self.assertEqual(result, {"health": {"state": "ok", "status": 200, "checked_at": 123}, "ready": {"state": "error", "status": 503}})

    def test_three_information_sources_are_not_node_sources_and_partial_failure_survives(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            with env(CENTER_ENVIRONMENT="isolated"):
                result = center.compose(values(), {"dns": "unavailable"})
            self.assertEqual(result["environment"], "isolated")
            self.assertEqual(center.compose(values(), {})["environment"], "production")
            self.assertEqual(result["sync"]["information_sources"], 3)
            self.assertEqual(result["sync"]["node_sources"], 2)
            self.assertIn("不等于节点来源", result["sync"]["stages"][0]["detail"])
            self.assertEqual(result["dns"]["state"], "error")
            self.assertEqual(result["metrics"]["nodes"], 1)
            self.assertEqual(result["overall"]["state"], "error")
            self.assertTrue(any(issue["id"] == "same-as-current" for issue in result["issues"]))
            self.assertEqual(result["sync"]["stages"][2]["state"], "warning")
            self.assertNotEqual(result["sync"]["state"], "error")
            self.assertEqual(result["sync"]["stages"][0]["last_success"], result["subscriptions"]["source_sync"]["last_success"])
            self.assertNotEqual(result["sync"]["stages"][0]["last_success"], values()["usage"]["get_time"])
            self.assertEqual(result["businesses"][0]["leaf"], "A")
            self.assertEqual(result["businesses"][0]["chain"], ["Gateway", "A"])
            self.assertEqual(result["businesses"][0]["state"], "ok")
            business_ids = {item["id"] for item in result["businesses"]}
            self.assertTrue({"GLOBAL", "🧪 节点能力检测", "🔬 节点归属校验"}.isdisjoint(business_ids))
            self.assertEqual(result["metrics"]["selectors"], 2)
            self.assertIn("health_schedule", result["nodes"][0])
            self.assertIn("capabilities", result["nodes"][0])
            encoded = json.dumps(result, ensure_ascii=False)
            self.assertNotIn("redact", encoded)
            self.assertNotIn("secret", encoded)
            self.assertNotIn("CANARY", encoded)

    def test_runtime_needs_manifest_name_and_count_match_and_selector_membership_is_not_health(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            evidence = values()
            evidence["clash"]["providers"]["providers"]["provider-a"]["proxies"] = [{"name": "X"}, {"name": "Y"}]
            evidence["nodes"]["nodes"][0]["capabilities"] = {}
            result = center.compose(evidence, {})
            runtime = next(item for item in result["sync"]["stages"] if item["id"] == "runtime")
            self.assertEqual(runtime["state"], "warning")
            self.assertNotEqual(result["businesses"][0]["state"], "ok")
            evidence["manifest"] = {"available": False, "sources": []}
            result = center.compose(evidence, {})
            self.assertIsNone(result["sync"]["node_sources"])
            self.assertEqual(next(item for item in result["sync"]["stages"] if item["id"] == "runtime")["state"], "unknown")
            evidence = values()
            evidence["clash"]["errors"] = ["proxies"]
            evidence["clash"]["proxies"] = {}
            result = center.compose(evidence, {})
            self.assertIsNone(result["metrics"]["selectors"])
            self.assertEqual(result["metrics"]["rules"], 1)

    def test_business_reject_stale_nodes_and_dns_probe_prevent_fake_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            evidence = values()
            evidence["controller"]["release_status"] = "published"
            evidence["clash"]["proxies"]["proxies"]["ChatGPT"].update(now="REJECT", all=["REJECT"])
            evidence["dns"]["health_state"] = "error"
            result = center.compose(evidence, {})
            self.assertEqual(next(item for item in result["businesses"] if item["id"] == "ChatGPT")["state"], "warning")
            self.assertEqual(result["overall"]["state"], "error")
            self.assertIn("主动选择 REJECT", next(item for item in result["businesses"] if item["id"] == "ChatGPT")["detail"])
            self.assertNotEqual(next(item for item in result["services"] if item["id"] == "dns")["state"], "ok")

            evidence = values()
            evidence["controller"]["release_status"] = "published"
            for provider in evidence["usage"]["providers"]:
                provider.update(usage_status="ok", stale=False)
            evidence["clash"]["proxies"]["proxies"]["🔐 自定义节点"] = {"type": "Selector", "now": "REJECT", "all": ["REJECT"]}
            result = center.compose(evidence, {})
            custom = next(item for item in result["businesses"] if item["id"] == "🔐 自定义节点")
            self.assertEqual(custom["state"], "warning")
            self.assertEqual(result["overall"]["state"], "ok")

            evidence = values()
            evidence["controller"]["release_status"] = "published"
            for provider in evidence["usage"]["providers"]:
                provider.update(usage_status="ok", stale=False)
            evidence["clash"]["proxies"]["proxies"].update(DIRECT={"type": "Direct"})
            evidence["clash"]["proxies"]["proxies"]["ChatGPT"].update(now="DIRECT", all=["DIRECT"])
            result = center.compose(evidence, {})
            self.assertEqual(next(item for item in result["businesses"] if item["id"] == "ChatGPT")["state"], "unknown")
            self.assertEqual(result["overall"]["state"], "unknown")

            evidence = values()
            evidence["controller"]["release_status"] = "published"
            for node in evidence["nodes"]["nodes"]:
                node["fresh"] = False
            result = center.compose(evidence, {})
            self.assertNotEqual(result["overall"]["state"], "ok")
            self.assertTrue(any(issue["id"] == "all-node-evidence-stale" for issue in result["issues"]))

            evidence = values()
            evidence["controller"].update(release_status="published", epoch=1)
            evidence["nodes"]["progress"].update(epoch=1, last_probe_epoch=1)
            evidence["nodes"]["generated_at"] = int(time.time())  # HTTP serialization time is not worker freshness.
            result = center.compose(evidence, {})
            service_states = {item["id"]: item["state"] for item in result["services"]}
            stage_states = {item["id"]: item["state"] for item in result["sync"]["stages"]}
            self.assertEqual(service_states["controller"], "stale")
            self.assertEqual(service_states["nodes"], "stale")
            self.assertEqual(stage_states["publication"], "stale")
            self.assertEqual(stage_states["evaluation"], "stale")
            self.assertEqual(result["sync"]["state"], "stale")

    def test_relevant_business_warning_and_unknown_prevent_overall_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            evidence = values()
            evidence["controller"]["release_status"] = "published"
            for provider in evidence["usage"]["providers"]:
                provider.update(usage_status="ok", stale=False)
            evidence["clash"]["proxies"]["proxies"]["ChatGPT"]["now"] = "not-a-member"
            result = center.compose(evidence, {})
            self.assertEqual(next(item for item in result["businesses"] if item["id"] == "ChatGPT")["state"], "warning")
            self.assertEqual(result["overall"]["state"], "warning")

            evidence = values()
            evidence["controller"]["release_status"] = "published"
            for provider in evidence["usage"]["providers"]:
                provider.update(usage_status="ok", stale=False)
            evidence["nodes"]["nodes"][0]["capabilities"] = {}
            result = center.compose(evidence, {})
            self.assertEqual(next(item for item in result["businesses"] if item["id"] == "ChatGPT")["state"], "unknown")
            self.assertEqual(result["overall"]["state"], "unknown")

    def test_cached_subscription_metadata_prevents_overall_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            evidence = values()
            evidence["controller"]["release_status"] = "published"
            for provider in evidence["usage"]["providers"]:
                provider.update(usage_status="ok", stale=False)
            evidence["usage"]["providers"][0]["usage_status"] = "cached"
            result = center.compose(evidence, {})
            self.assertEqual(result["overall"]["state"], "warning")
            self.assertTrue(any(issue["id"] == "subscription-metadata-stale" for issue in result["issues"]))

    def test_overview_fanout_has_total_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            center.controller_status = lambda: {}
            center.manifest_status = lambda: {"available": False, "sources": []}
            center.usage_status = lambda: {}
            center.fixed_file_status = lambda: {}
            center.dns_status = lambda: {}
            center.kuma_status = lambda: {}
            center.node_status = lambda: (time.sleep(3), {})[1]
            started = time.monotonic()
            with env(CENTER_OVERVIEW_TIMEOUT=2):
                _, errors = center._collect()
            self.assertLess(time.monotonic() - started, 2.8)
            self.assertEqual(errors["nodes"], "timeout")
            center.pool.shutdown(wait=False, cancel_futures=True)

    def test_cache_coalesces_concurrent_viewers(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            count = 0
            gate = threading.Barrier(3)

            def collect():
                nonlocal count
                count += 1
                time.sleep(.2)
                return values(), {}

            center._collect = collect
            output = []

            def worker():
                gate.wait()
                output.append(center.overview())

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            gate.wait()
            for thread in threads:
                thread.join()
            self.assertEqual(count, 1)
            self.assertEqual(len(output), 2)


class LocalEvidenceTests(unittest.TestCase):
    def test_kuma_http_and_database_stay_ok_when_one_child_monitor_fails(self):
        class HealthyKuma(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

        server = ThreadingHTTPServer(("127.0.0.1", 0), HealthyKuma)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                database = root / "kuma.db"
                stamp = datetime.now(timezone.utc).isoformat()
                with contextlib.closing(sqlite3.connect(database)) as connection:
                    connection.executescript("CREATE TABLE monitor(id INTEGER PRIMARY KEY,name TEXT,active INTEGER,interval INTEGER); CREATE TABLE heartbeat(monitor_id INTEGER,status INTEGER,time TEXT);")
                    connection.execute("INSERT INTO monitor VALUES(1,'failed child',1,20)")
                    connection.execute("INSERT INTO heartbeat VALUES(1,0,?)", (stamp,))
                    connection.commit()
                center = Center(namespace(root), FakeManager(root), FakeAccess())
                with env(CENTER_KUMA_DB=database, CENTER_KUMA_HEALTH_URL=f"http://127.0.0.1:{server.server_port}/"):
                    kuma = center.kuma_status()
                self.assertEqual(kuma["health_state"], "ok")
                self.assertEqual(kuma["database_state"], "ok")
                self.assertEqual(kuma["monitors"][0]["state"], "error")
                evidence = values()
                evidence["controller"]["release_status"] = "published"
                for provider in evidence["usage"]["providers"]:
                    provider.update(usage_status="ok", stale=False)
                evidence["kuma"] = kuma
                result = center.compose(evidence, {})
                self.assertEqual(next(item for item in result["services"] if item["id"] == "kuma")["state"], "ok")
                self.assertEqual(result["overall"]["state"], "warning")
                self.assertTrue(any(issue["id"] == "monitor-heartbeats-abnormal" for issue in result["issues"]))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_corefile_whitelist_and_stale_kuma_heartbeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kuma = root / "uptime-kuma"
            kuma.mkdir()
            corefile = kuma / "Corefile"
            corefile.write_text(". {\n forward . 1.1.1.1 tls://dns.google {\n }\n # token secret\n}\n", encoding="utf-8")
            database = kuma / "kuma.db"
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.executescript("""
                    CREATE TABLE monitor(id INTEGER PRIMARY KEY,name TEXT,active INTEGER,interval INTEGER,url TEXT);
                    CREATE TABLE heartbeat(id INTEGER PRIMARY KEY,monitor_id INTEGER,status INTEGER,time TEXT,ping REAL);
                    INSERT INTO monitor VALUES(1,'DNS monitor',1,20,'https://private.example/token');
                    INSERT INTO heartbeat VALUES(1,1,1,'2000-01-01 00:00:00',12.5);
                """)
            ns = namespace(root)
            center = Center(ns, FakeManager(root), FakeAccess())
            with env(CENTER_COREFILE=corefile, CENTER_KUMA_DB=database):
                dns = center.dns_status()
                monitor = center.kuma_status()["monitors"][0]
            self.assertEqual(dns["upstreams"], ["1.1.1.1", "tls://dns.google"])
            self.assertEqual(monitor["state"], "stale")
            self.assertNotIn("url", monitor)
            self.assertNotIn("private", json.dumps(monitor))

    def test_future_kuma_heartbeat_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "future.db"
            future = datetime.fromtimestamp(time.time() + 3600, tz=timezone.utc).isoformat()
            offset_now = datetime.now(timezone(timedelta(hours=8))).isoformat()
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.executescript("CREATE TABLE monitor(id INTEGER PRIMARY KEY,name TEXT,active INTEGER,interval INTEGER); CREATE TABLE heartbeat(monitor_id INTEGER,status INTEGER,time TEXT);")
                connection.execute("INSERT INTO monitor VALUES(1,'future',1,20)")
                connection.execute("INSERT INTO heartbeat VALUES(1,1,?)", (future,))
                connection.execute("INSERT INTO monitor VALUES(2,'offset',1,20)")
                connection.execute("INSERT INTO heartbeat VALUES(2,1,?)", (offset_now,))
                connection.commit()
            center = Center(namespace(root), FakeManager(root), FakeAccess())
            with env(CENTER_KUMA_DB=database):
                monitors = {item["id"]: item for item in center.kuma_status()["monitors"]}
            self.assertEqual(monitors["1"]["state"], "stale")
            self.assertIn("未来", monitors["1"]["detail"])
            self.assertEqual(monitors["2"]["state"], "ok")

    def test_backup_retention_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            center = Center(namespace(temporary), FakeManager(temporary), FakeAccess())
            for index in range(3):
                backup_id = f"backup-{index}"
                (center.backup_root / f"{backup_id}.tar.gz").write_bytes(b"x" * 20)
                (center.backup_root / f"{backup_id}.json").write_text(json.dumps({"id": backup_id, "state": "ok", "created_at": index, "size": 20}), encoding="utf-8")
            with env(CENTER_BACKUP_RETAIN=2):
                center.prune_backups("backup-2", 1024)
            self.assertTrue((center.backup_root / "backup-2.tar.gz").exists())
            self.assertTrue((center.backup_root / "backup-1.tar.gz").exists())
            self.assertFalse((center.backup_root / "backup-0.tar.gz").exists())

    def test_unsupported_kuma_schema_is_explicit_not_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "bad.db"
            sqlite3.connect(database).close()
            center = Center(namespace(root), FakeManager(root), FakeAccess())
            with env(CENTER_KUMA_DB=database):
                with self.assertRaises(MODULE.CenterError) as caught:
                    center.kuma_status()
            self.assertEqual(caught.exception.code, "monitor_schema_unsupported")


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clash = FakeClash()
        self.access = FakeAccess()
        self.manager = FakeManager(self.root)
        self.ns = namespace(self.root, self.clash)
        self.original_provider_hits = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def send(self, code, content_type, payload):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                if self.path == "/providers/original.yaml":
                    outer.original_provider_hits += 1
                    if self.headers.get("Authorization") != "Bearer original":
                        self.send(403, "application/json", b'{"error":"forbidden"}')
                    else:
                        self.send(200, "text/yaml", b"proxies: []\n")
                else:
                    self.send(404, "application/json", b'{"error":"legacy_not_found"}')

            def do_POST(self):
                self.send(404, "application/json", b'{"error":"legacy_not_found"}')

            def do_HEAD(self):
                if self.path == "/legacy-head":
                    self.send_response(204)
                    self.end_headers()
                else:
                    self.send_error(404)

        self.ns.update({"Handler": Handler, "dashboard": lambda: b"<html>classic</html>"})
        self.env = env(CENTER_UI_ENABLED=1, LOCAL_SOURCE_HOSTS="127.0.0.1")
        self.env.__enter__()
        self.center = install(self.ns, self.manager, self.access)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        # The exact Host including the ephemeral port is mandatory.
        os.environ["LOCAL_SOURCE_HOSTS"] = f"127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.env.__exit__(None, None, None)
        self.temporary.cleanup()

    def request(self, path, method="GET", body=None, authenticated=False, csrf=True, origin=True):
        data = json.dumps(body).encode() if body is not None else None
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers["Cookie"] = "local_session=valid"
        if csrf:
            headers["X-CSRF-Token"] = "csrf-token"
        if origin:
            headers["Origin"] = f"http://127.0.0.1:{self.port}"
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                raw = response.read()
                return response.status, json.loads(raw) if "json" in response.headers.get("Content-Type", "") else raw
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_index_is_uncached_and_assets_have_content_fingerprints(self):
        import hashlib
        import unified_center
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=3) as response:
            self.assertEqual(response.headers.get("Cache-Control"), "no-store")
            html = response.read()
        for name in ("app.js", "app.css", "logo.png"):
            digest = hashlib.sha256((unified_center.ASSETS / name).read_bytes()).hexdigest()[:16]
            self.assertIn(("/center-assets/" + name + "?v=" + digest).encode(), html)
        status, payload = self.request("/center-assets/app.js?v=previous-version")
        self.assertEqual(status, 200)
        self.assertEqual(payload, (unified_center.ASSETS / "app.js").read_bytes())

    def test_head_is_offered_to_proxy_then_legacy_without_get_body(self):
        calls = []

        def proxy_request(handler, access=None):
            calls.append((handler.command, handler.path, access))
            if handler.path == "/serviceWorker.js":
                handler.send_response(200)
                handler.send_header("Content-Type", "application/javascript")
                handler.send_header("Content-Length", "17")
                handler.end_headers()
                return True
            return False

        proxy = types.ModuleType("unified_proxy")
        proxy.proxy_request = proxy_request
        with mock.patch.dict(sys.modules, {"unified_proxy": proxy}):
            request = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/serviceWorker.js", method="HEAD"
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"")

            request = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/legacy-head", method="HEAD"
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(response.status, 204)
                self.assertEqual(response.read(), b"")

            request = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/api/center/overview", method="HEAD"
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(caught.exception.code, 404)
            self.assertEqual(caught.exception.read(), b"")

        self.assertEqual([item[:2] for item in calls], [
            ("HEAD", "/serviceWorker.js"),
            ("HEAD", "/legacy-head"),
            ("HEAD", "/api/center/overview"),
        ])

    def test_session_auth_origin_conflict_and_node_probe_does_not_select(self):
        status, result = self.request("/api/center/session", origin=False, csrf=False)
        self.assertEqual((status, result), (200, {"authenticated": False}))
        status, result = self.request("/api/center/session", authenticated=True, origin=False, csrf=False)
        self.assertEqual(status, 200)
        self.assertEqual(result["csrf"], "csrf-token")

        for group in ("GLOBAL", "🧪 节点能力检测", "🔬 节点归属校验"):
            status, result = self.request(
                "/api/center/select", "POST", {"group": group, "choice": "B", "expected": "A"}, authenticated=True,
            )
            self.assertEqual((status, result["error"]), (403, "technical_group_write_forbidden"))
        self.assertEqual(self.clash.puts, [])

        status, result = self.request("/api/center/select", "POST", {"group": "Business", "choice": "B", "expected": "WRONG"}, authenticated=True)
        self.assertEqual((status, result["error"]), (409, "selection_conflict"))
        self.assertEqual(self.clash.selected, "A")
        status, result = self.request("/api/center/select", "POST", {"group": "Business", "choice": "B", "expected": "A"}, authenticated=True, origin=False)
        self.assertEqual((status, result["error"]), (403, "origin_or_content_type_forbidden"))
        status, result = self.request("/api/center/select", "POST", {"group": "Business", "choice": "B", "expected": "A"}, authenticated=True)
        self.assertEqual(status, 200)
        self.assertEqual(self.clash.selected, "B")

        # Probe A directly.  It must not issue a selector PUT.
        before = list(self.clash.puts)
        import clash_measurement
        clash_measurement._inventory = (0, {})
        status, result = self.request("/api/center/node-test", "POST", {"provider": "provider-a", "name": "A"}, authenticated=True)
        self.assertEqual((status, result["delay_ms"]), (200, 37))
        self.assertEqual(self.clash.puts, before)

        # Same selection is an idempotent no-op, and zero latency is never green.
        status, result = self.request("/api/center/select", "POST", {"group": "Business", "choice": "B", "expected": "B"}, authenticated=True)
        self.assertEqual((status, result["changed"]), (200, False))
        self.assertEqual(self.clash.puts, before)
        self.clash.delay = 0
        clash_measurement._inventory = (0, {})
        status, result = self.request("/api/center/node-test", "POST", {"provider": "provider-a", "name": "A"}, authenticated=True)
        self.assertEqual(status, 503)

    def test_legacy_provider_auth_is_unchanged(self):
        status, result = self.request("/providers/original.yaml", origin=False, csrf=False)
        self.assertEqual(status, 403)
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/providers/original.yaml", headers={"Authorization": "Bearer original"})
        with urllib.request.urlopen(request, timeout=3) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.original_provider_hits, 2)

    def test_backup_job_uses_online_sqlite_backup_and_private_download(self):
        with contextlib.closing(sqlite3.connect(self.ns["DB_PATH"])) as connection:
            connection.execute("CREATE TABLE evidence(value TEXT)")
            connection.execute("INSERT INTO evidence VALUES('real-row')")
            connection.commit()
        self.ns["SOURCES_FILE"].write_text('{"sources":[]}', encoding="utf-8")
        (self.ns["DATA"] / "current.json").write_text('{"release_id":"test","published_at":1}', encoding="utf-8")
        corefile = self.root / "Corefile"
        corefile.write_text(". { forward . 1.1.1.1 }\n", encoding="utf-8")
        kuma = self.root / "kuma.db"
        with contextlib.closing(sqlite3.connect(kuma)) as connection:
            connection.execute("CREATE TABLE heartbeat_evidence(value TEXT)")
            connection.execute("INSERT INTO heartbeat_evidence VALUES('kuma-row')")
            connection.commit()
        with env(CENTER_KUMA_DB=kuma, CENTER_COREFILE=corefile):
            status, result = self.request("/api/center/backup", "POST", {}, authenticated=True)
            self.assertEqual(status, 202)
            job_id = result["job_id"]
            deadline = time.time() + 5
            while time.time() < deadline:
                status, job = self.request(f"/api/center/jobs/{job_id}", authenticated=True, origin=False, csrf=False)
                if job["state"] in {"ok", "error"}:
                    break
                time.sleep(.05)
        self.assertEqual(job["state"], "ok", job)
        self.assertIn("download_url", job)
        status, result = self.request(f"/api/center/backups/{job_id}/download", origin=False, csrf=False)
        self.assertEqual(status, 401)
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/center/backups/{job_id}/download",
            headers={"Cookie": "local_session=valid"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = response.read()
            self.assertEqual(response.status, 200)
            self.assertGreater(len(payload), 50)
        manifest = json.loads((self.center.backup_root / f"{job_id}.json").read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest["sha256"])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as bundle:
            names = set(bundle.getnames())
            self.assertTrue({"controller.db", "kuma.db", "Corefile", "BACKUP-CONTENTS.json", "RESTORE-GUIDE.txt"}.issubset(names))
            self.assertFalse(any("router" in name.lower() for name in names))
            contents = json.load(bundle.extractfile("BACKUP-CONTENTS.json"))
            self.assertIn("router_configuration", contents["excludes"])
            self.assertIn("BACKUP-CONTENTS.json", contents["included"])
            for database_name, query, expected in (
                ("controller.db", "SELECT value FROM evidence", "real-row"),
                ("kuma.db", "SELECT value FROM heartbeat_evidence", "kuma-row"),
            ):
                target = self.root / ("verify-" + database_name)
                target.write_bytes(bundle.extractfile(database_name).read())
                with contextlib.closing(sqlite3.connect(target)) as connection:
                    self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertEqual(connection.execute(query).fetchone()[0], expected)
        (self.center.backup_root / f"{job_id}.tar.gz").unlink()
        self.assertEqual(self.center.job_status(job_id)["state"], "error")
        self.assertFalse(any(item["id"] == job_id for item in self.center.backup_list()))

    def test_node_probe_and_backup_concurrency_are_bounded(self):
        self.assertTrue(self.center.node_test_slots.acquire(blocking=False))
        self.assertTrue(self.center.node_test_slots.acquire(blocking=False))
        try:
            status, result = self.request("/api/center/node-test", "POST", {"provider": "provider-a", "name": "A"}, authenticated=True)
            self.assertEqual((status, result["error"]), (429, "node_test_busy_retry_later"))
        finally:
            self.center.node_test_slots.release()
            self.center.node_test_slots.release()
        self.assertTrue(self.center.backup_slot.acquire(blocking=False))
        try:
            status, result = self.request("/api/center/backup", "POST", {}, authenticated=True)
            self.assertEqual((status, result["error"]), (409, "backup_busy_retry_later"))
        finally:
            self.center.backup_slot.release()

    def test_backup_missing_required_sources_fails_without_download(self):
        status, result = self.request("/api/center/backup", "POST", {}, authenticated=True)
        self.assertEqual(status, 202)
        job_id = result["job_id"]
        deadline = time.time() + 3
        while time.time() < deadline:
            _, job = self.request(f"/api/center/jobs/{job_id}", authenticated=True, origin=False, csrf=False)
            if job["state"] == "error":
                break
            time.sleep(.05)
        self.assertEqual(job["state"], "error")
        self.assertIsNone(job.get("download"))
        self.assertFalse((self.center.backup_root / f"{job_id}.tar.gz").exists())

    def test_two_concurrent_selections_with_same_expected_only_change_once(self):
        gate = threading.Barrier(3)
        results = []

        def select():
            gate.wait()
            results.append(self.request(
                "/api/center/select", "POST",
                {"group": "Business", "choice": "B", "expected": "A"}, authenticated=True,
            ))

        threads = [threading.Thread(target=select) for _ in range(2)]
        for thread in threads:
            thread.start()
        gate.wait()
        for thread in threads:
            thread.join(timeout=3)
        self.assertEqual(sorted(status for status, _ in results), [200, 409])
        success = next(body for status, body in results if status == 200)
        conflict = next(body for status, body in results if status == 409)
        self.assertTrue(success["changed"])
        self.assertEqual(conflict["error"], "selection_conflict")
        self.assertEqual(self.clash.puts, ["B"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
