import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("kuma_management", HERE / "kuma_management.py")
K = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(K)


class FakeTransport:
    def __init__(self, state="ready"):
        self.state = state
        self.calls = []
        self.revision = "a" * 64

    def snapshot(self):
        return {
            "state": self.state,
            "error_code": "kuma_binding_required" if self.state == "unbound" else None,
            "revision": self.revision if self.state == "ready" else None,
            "version": "2.5.6",
            "connection": {"state": self.state, "checked_at": "now", "detail": None},
            "monitors": [{"id": 1, "name": "主页", "type": "http", "active": True, "status": "up"}] if self.state == "ready" else [],
            "groups": [],
            "notifications": [{"id": 1, "name": "通知", "type": "webhook", "has_secret_fields": ["webhookURL"]}] if self.state == "ready" else [],
        }

    def __call__(self, action, params, *, timeout=None, write=False):
        self.calls.append((action, json.loads(json.dumps(params)), timeout, write))
        if action == "kuma.snapshot":
            return self.snapshot()
        if action == "internal.bind":
            if params.get("password") != "correct":
                raise K.KumaError("kuma_auth_failed", 401)
            self.state = "ready"
            return {"state": "bound", "revision": self.revision}
        if action == "kuma.monitor_detail":
            return {"state": "ok", "revision": self.revision, "monitor": {"id": 1, "name": "主页", "has_secret_fields": ["headers"]}}
        if action == "kuma.monitor_history":
            return {"state": "ok", "monitor_id": 1, "hours": 24, "beats": [], "chart": []}
        if action.startswith("kuma.notification_") and action.endswith("detail"):
            return {"state": "ok", "revision": self.revision, "notification": {"id": 1, "has_secret_fields": ["webhookURL"]}}
        if action == "kuma.notification_test":
            return {"state": "ok", "tested": True, "message": "Sent"}
        return {"state": "ok", "revision": self.revision, "readback": {"id": params.get("id", 2), "name": "ok"}}


class ExtensionTests(unittest.TestCase):
    def extension(self, transport):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return K.create_extension({"data_root": temporary.name, "center_root": temporary.name, "kuma_bridge_transport": transport, "write_lock_managed": True})

    def test_snapshot_contract_and_capabilities(self):
        transport = FakeTransport()
        extension = self.extension(transport)
        snapshot = extension.snapshot()
        self.assertEqual(snapshot["state"], "ready")
        self.assertEqual(snapshot["version"], "2.5.6")
        self.assertEqual(snapshot["notifications"][0]["has_secret_fields"], ["webhookURL"])
        self.assertIn("kuma.monitor_create", snapshot["capabilities"]["actions"])
        self.assertFalse(snapshot["capabilities"]["monitor_test"])
        actions = extension.actions()
        self.assertTrue(actions["kuma.monitor_create"]["write"])
        self.assertTrue(actions["kuma.monitor_create"]["deadline_enforced"])
        self.assertTrue(actions["kuma.bind"]["sensitive_input"])
        self.assertFalse(actions["kuma.monitor_detail"]["write"])
        self.assertEqual(actions["kuma.monitor_detail"]["timeout_seconds"], 45)
        self.assertEqual(actions["kuma.monitor_create"]["timeout_seconds"], 60)
        self.assertEqual(actions["kuma.bind"]["timeout_seconds"], 60)

    def test_unbound_is_explicit_and_only_binding_is_advertised(self):
        extension = self.extension(FakeTransport("unbound"))
        snapshot = extension.snapshot()
        self.assertEqual(snapshot["state"], "unbound")
        self.assertEqual(snapshot["error_code"], "kuma_binding_required")
        self.assertEqual(snapshot["capabilities"]["actions"], ["kuma.bind"])
        self.assertRegex(snapshot["revision"], r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(K.KumaError, "kuma_action_unsupported"):
            extension.execute("kuma.monitor_detail", {"id": 1})

    def test_binding_uses_sensitive_path_and_clears_input(self):
        transport = FakeTransport("unbound")
        extension = self.extension(transport)
        extension.snapshot()
        params = {"username": "admin", "password": "correct", "totp": ""}
        result = extension.bind_sensitive(params)
        self.assertEqual(params, {})
        self.assertEqual(result["state"], "bound")
        self.assertNotIn("admin", json.dumps(result))
        self.assertNotIn("correct", json.dumps(result))
        self.assertEqual(transport.calls[-2][0], "internal.bind")
        self.assertTrue(transport.calls[-2][3])
        with self.assertRaisesRegex(K.KumaError, "operation_sensitive_route_required"):
            extension.execute("kuma.bind", {"username": "x", "password": "x"})

    def test_read_and_write_dispatch_with_readback(self):
        transport = FakeTransport()
        extension = self.extension(transport)
        extension.snapshot()
        detail = extension.execute("kuma.monitor_detail", {"id": 1})
        self.assertEqual(detail["monitor"]["id"], 1)
        result = extension.execute("kuma.monitor_pause", {"id": 1})
        self.assertEqual(result["readback"]["id"], 1)
        self.assertFalse(transport.calls[-2][3])
        self.assertTrue(transport.calls[-1][3])

    def test_defensive_redaction(self):
        transport = FakeTransport()
        extension = self.extension(transport)
        transport.__call__ = transport.__call__
        value = K._safe({"password": "p", "nested": {"access_token": "t", "name": "ok"}})
        self.assertEqual(value["password"], "[hidden]")
        self.assertEqual(value["nested"]["access_token"], "[hidden]")
        self.assertEqual(value["nested"]["name"], "ok")


class ProcessTransportTests(unittest.TestCase):
    def test_jsonl_process_round_trip_and_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            script = root / "bridge.py"
            script.write_text(
                "import json,sys,time\n"
                "for line in sys.stdin:\n"
                " r=json.loads(line)\n"
                " if r['action']=='slow': time.sleep(2)\n"
                " print(json.dumps({'id':r['id'],'ok':True,'result':{'state':'ok','echo':r['params']}}),flush=True)\n",
                encoding="utf-8",
            )
            bridge = K.JsonLineBridge(script, root / "token", "http://127.0.0.1", node=sys.executable, request_timeout=2)
            result = bridge.request("read", {"value": 1}, timeout=4)
            self.assertEqual(result["echo"]["value"], 1)
            started = time.monotonic()
            with self.assertRaisesRegex(K.KumaError, "kuma_timeout"):
                bridge.request("slow", {}, timeout=1)
            self.assertLess(time.monotonic() - started, 1.8)
            bridge.close()

    def test_repeated_start_close_releases_pipes_and_reader(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            script = root / "bridge.py"
            script.write_text(
                "import json,sys\n"
                "for line in sys.stdin:\n"
                " r=json.loads(line); print(json.dumps({'id':r['id'],'ok':True,'result':{'state':'ok'}}),flush=True)\n",
                encoding="utf-8",
            )
            bridge = K.JsonLineBridge(script, root / "token", "http://127.0.0.1", node=sys.executable, request_timeout=2)
            baseline = len([t for t in threading.enumerate() if t.name == "kuma-jsonl-reader"])
            for _ in range(5):
                self.assertEqual(bridge.request("read")["state"], "ok")
                process = bridge.process
                bridge.close()
                self.assertIsNone(bridge.process)
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)
            time.sleep(0.1)
            self.assertLessEqual(len([t for t in threading.enumerate() if t.name == "kuma-jsonl-reader"]), baseline)


if __name__ == "__main__":
    unittest.main()
