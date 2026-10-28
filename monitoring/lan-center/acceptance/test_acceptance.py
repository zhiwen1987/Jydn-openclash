import importlib.util
import sys
import unittest
import json
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("integrated_acceptance", HERE / "acceptance.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
PROTECTED_SPEC = importlib.util.spec_from_file_location("protected_state", HERE / "protected_state.py")
PROTECTED = importlib.util.module_from_spec(PROTECTED_SPEC)
sys.modules[PROTECTED_SPEC.name] = PROTECTED
PROTECTED_SPEC.loader.exec_module(PROTECTED)
SURFACE_SPEC = importlib.util.spec_from_file_location("surface_gate", HERE / "surface_gate.py")
SURFACE = importlib.util.module_from_spec(SURFACE_SPEC)
sys.modules[SURFACE_SPEC.name] = SURFACE
SURFACE_SPEC.loader.exec_module(SURFACE)


class AcceptanceHelpersTests(unittest.TestCase):
    def test_percentile_uses_observed_value(self):
        self.assertEqual(MODULE.percentile([1, 2, 3, 4, 100], .95), 100)

    def test_secret_fields_are_rejected_recursively(self):
        with self.assertRaisesRegex(MODULE.GateFailure, "secret_field_exposed"):
            MODULE.public_shape({"modules": {"dns": {"provider_token": "x"}}})
        with self.assertRaisesRegex(MODULE.GateFailure, "secret_field_exposed"):
            MODULE.public_shape({"modules": {"dns": {"provider_token": {"nested": "x"}}}})
        MODULE.public_shape({"modules": {"dns": {"provider_token": "[已隐藏]"}}})

    def test_subscription_snapshot_and_jobs_never_expose_request_urls_or_params(self):
        safe = {
            "state": "ok", "revision": "r", "sources": [
                {"id": "Managed_A", "name": "https://display-name.example/?allowed-as-text=1"},
            ],
        }
        self.assertGreater(MODULE.assert_subscription_public_shape(safe)["objects_checked"], 0)
        with self.assertRaisesRegex(MODULE.GateFailure, "subscription_private_request_exposed"):
            MODULE.assert_subscription_public_shape({"sources": [{"source_url": "https://secret/?token=x"}]})
        with self.assertRaisesRegex(MODULE.GateFailure, "operation_params_exposed"):
            MODULE.assert_public_job_shape({"module": "subscriptions", "params": {"url": "https://secret"}})
        with self.assertRaisesRegex(MODULE.GateFailure, "subscription_private_request_exposed"):
            MODULE.assert_public_job_shape({"module": "subscriptions", "result": {"provider_url": "https://secret"}})
        with self.assertRaisesRegex(MODULE.GateFailure, "subscription_private_url_value_exposed"):
            MODULE.assert_subscription_public_shape({"last_error": "fetch failed at https://secret/?token=x"})

    def test_snapshot_requires_all_real_modules_and_actions(self):
        value = {"schema": 2, "revision": "r1", "updated_at": 1, "modules": {}}
        for name in MODULE.MODULES:
            value["modules"][name] = {"state": "unknown", "revision": name + "-1", "capabilities": {"actions": [], "action_meta": {}}}
        result = MODULE.validate_snapshot(value)
        self.assertEqual(set(result["actions"]), MODULE.MODULES)
        del value["modules"]["dns"]
        with self.assertRaisesRegex(MODULE.GateFailure, "snapshot_modules_missing"):
            MODULE.validate_snapshot(value)

    def test_snapshot_waits_for_background_module_revision(self):
        ready = {"schema": 2, "revision": "root", "updated_at": 1, "modules": {}}
        for name in MODULE.MODULES:
            ready["modules"][name] = {"state": "ok", "revision": name, "capabilities": {"actions": [], "action_meta": {}}}
        pending = json.loads(json.dumps(ready))
        pending["modules"]["monitors"]["state"] = "pending"
        pending["modules"]["monitors"]["revision"] = None

        class FakeClient:
            def __init__(self): self.calls = 0
            def request(self, _path):
                self.calls += 1
                return 200, pending if self.calls == 1 else ready, 1, 1

        snapshot, evidence = MODULE.wait_for_snapshot(FakeClient(), 2)
        self.assertEqual(snapshot["modules"]["monitors"]["revision"], "monitors")
        self.assertEqual(evidence["ready_attempts"], 2)

    def test_performance_gate_allows_small_jitter_and_rejects_regression(self):
        baseline = {"p95_ms": 100, "concurrent_p95_ms": 120, "max_bytes": 20000}
        current = {"p95_ms": 124, "concurrent_p95_ms": 150, "max_bytes": 24000}
        self.assertTrue(all(v["passed"] for v in MODULE.compare_performance(current, baseline).values()))
        current["p95_ms"] = 180
        with self.assertRaisesRegex(MODULE.GateFailure, "performance_regression"):
            MODULE.compare_performance(current, baseline)

    def test_protected_state_reports_drift_without_exposing_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "secret.yaml"
            protected.write_text("top-secret")
            spec = root / "spec.json"
            spec.write_text(json.dumps({"files": [{"name": "config", "path": str(protected)}]}))
            before = PROTECTED.capture(spec)
            self.assertNotIn("top-secret", json.dumps(before))
            protected.write_text("changed")
            after = PROTECTED.capture(spec)
            self.assertFalse(PROTECTED.compare(before, after)["passed"])

    def test_protected_json_values_hash_only_selected_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = root / "runtime.json"
            document.write_text(json.dumps({"selection": {"Google": "DIRECT"}, "token": "never-output"}))
            spec = root / "spec.json"
            spec.write_text(json.dumps({"files": [], "json_values": [{
                "name": "business-selection", "path": str(document.resolve()),
                "pointers": ["/selection"],
            }]}))
            before = PROTECTED.capture(spec)
            self.assertNotIn("DIRECT", json.dumps(before))
            self.assertNotIn("never-output", json.dumps(before))
            document.write_text(json.dumps({"selection": {"Google": "Proxy"}, "token": "never-output"}))
            after = PROTECTED.capture(spec)
            self.assertFalse(PROTECTED.compare(before, after)["passed"])

    def test_required_actions_and_kuma_inventory_are_exact(self):
        snapshot = {"modules": {name: {"capabilities": {"actions": []}} for name in MODULE.MODULES}}
        snapshot["modules"]["monitors"].update({"monitors": [{}, {}], "notifications": [{}]})
        snapshot["modules"]["monitors"]["capabilities"]["actions"] = ["monitor_create"]
        self.assertEqual(
            MODULE.assert_required_actions(snapshot, ["monitors=monitor_create"])["checked"],
            ["monitors=monitor_create"],
        )
        self.assertEqual(MODULE.assert_kuma_inventory(snapshot, 2, 1), {"monitors": 2, "notifications": 1})
        with self.assertRaisesRegex(MODULE.GateFailure, "kuma_monitor_count_mismatch"):
            MODULE.assert_kuma_inventory(snapshot, 3, 1)

    def test_candidate_isolation_contract_is_fail_closed(self):
        snapshot = {"modules": {"subscriptions": {"reconcile": {
            "candidate_provider": None, "candidate_scope": "isolated_admission_queue",
            "active_provider": "Managed_Auto", "candidate_exposed": False,
        }}}}
        self.assertFalse(MODULE.assert_candidate_isolation(snapshot)["candidate_exposed"])
        snapshot["modules"]["subscriptions"]["reconcile"]["candidate_exposed"] = True
        with self.assertRaisesRegex(MODULE.GateFailure, "candidate_isolation_invalid"):
            MODULE.assert_candidate_isolation(snapshot)

    def test_kuma_must_not_have_a_host_mapping_or_iframe(self):
        safe = [{"Name": "/clash-center", "State": {"Running": True},
                 "HostConfig": {"PortBindings": {"3103/tcp": [{"HostPort": "3103"}]}},
                 "NetworkSettings": {"Ports": {"3001/tcp": None, "3103/tcp": [{"HostPort": "3103"}]}}}]
        self.assertFalse(SURFACE.docker_surface(safe)["kuma_external_port_published"])
        unsafe = [{"Name": "/clash-center", "State": {"Running": True},
                   "HostConfig": {"PortBindings": {"3001/tcp": [{"HostPort": "3101"}]}},
                   "NetworkSettings": {"Ports": {"3001/tcp": [{"HostPort": "3101"}]}}}]
        with self.assertRaisesRegex(SURFACE.SurfaceFailure, "kuma_external_port_published"):
            SURFACE.docker_surface(unsafe)
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "app.js"
            asset.write_text("document.createElement('iframe'); frame.src='/kuma/status-page'", encoding="utf-8")
            with self.assertRaisesRegex(SURFACE.SurfaceFailure, "forbidden_kuma_iframe"):
                SURFACE.static_surface([asset])
            asset.write_text("target.innerHTML = userControlledName", encoding="utf-8")
            with self.assertRaisesRegex(SURFACE.SurfaceFailure, "forbidden_unsafe_dom_html_sink"):
                SURFACE.static_surface([asset])


if __name__ == "__main__":
    unittest.main()
