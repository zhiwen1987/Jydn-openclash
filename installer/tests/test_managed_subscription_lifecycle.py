import importlib.util
import json
import os
import sys
import tempfile
import types
from contextlib import contextmanager
import unittest
from pathlib import Path
from unittest import mock


UPSTREAM = Path(__file__).resolve().parents[1] / "runtime" / "upstream"
sys.path.insert(0, str(UPSTREAM))
SPEC = importlib.util.spec_from_file_location("subscription_controller_managed_test", UPSTREAM / "subscription-controller.py")
controller = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = controller
SPEC.loader.exec_module(controller)


def node(name, server):
    return {"name": name, "type": "ss", "server": server, "port": 443, "cipher": "aes-128-gcm", "password": "x"}


class ManagedLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        controller.DATA = root / "subscription-controller"
        controller.DB_PATH = controller.DATA / "controller.db"
        controller.RELEASES = controller.DATA / "releases"
        controller.CACHE = controller.DATA / "cache"
        controller.CURRENT_PATH = controller.DATA / "current.json"
        controller.PENDING_PATH = controller.DATA / "pending.json"
        controller.HEALTH_PATH = controller.DATA / "health.json"
        controller.LOG_PATH = controller.DATA / "controller.log"
        controller.SOURCES_FILE = root / "subscription-sources.json"
        controller.INFORMATION_SOURCES_FILE = root / "information-sources.json"
        controller.SOURCE_OVERRIDES_FILE = root / "source-overrides.json"
        controller.RELEASES.mkdir(parents=True)
        controller.CACHE.mkdir(parents=True)
        explicit = {"sources": [{"id": "Provider_A", "name": "A", "url": "https://a.invalid/sub", "provider_name": "Provider_A"}]}
        controller.SOURCES_FILE.write_text(json.dumps(explicit), encoding="utf-8")
        os.chmod(controller.SOURCES_FILE, 0o600)
        controller.RETAINED_SOURCES.clear()
        controller.SOURCE_RECONCILE.clear()
        admission = types.ModuleType("admission_queue")
        admission.read_cache = lambda path: json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        health = types.ModuleType("health_policy")
        health.eligible = lambda record, _now: record.get("test_eligible") is True
        self.module_patch = mock.patch.dict(sys.modules, {"admission_queue": admission, "health_policy": health})
        self.module_patch.start()

    def tearDown(self):
        self.module_patch.stop()
        self.temporary.cleanup()

    def information(self, *rows):
        document = {"schema": 1, "purpose": "subscription_information_only", "sources": list(rows)}
        controller.INFORMATION_SOURCES_FILE.write_text(json.dumps(document), encoding="utf-8")

    def admit(self, *nodes):
        controller.DATA.mkdir(parents=True, exist_ok=True)
        (controller.DATA / "admission-cache.json").write_text(json.dumps({
            controller.fingerprint(item): {"test_eligible": True} for item in nodes
        }), encoding="utf-8")

    def test_n_sources_are_discovered_and_explicit_url_is_not_duplicated(self):
        self.information(
            {"id": "Info_duplicate", "name": "same", "url": "https://a.invalid/sub", "enabled": True},
            {"id": "Info_B", "name": "B", "url": "https://b.invalid/sub", "enabled": True},
            {"id": "Info_C", "name": "C", "url": "https://c.invalid/sub", "enabled": True},
        )
        with mock.patch.object(controller, "current_manifest", return_value=None):
            sources = controller.load_sources()
        self.assertEqual([s.source_id for s in sources], ["Provider_A", "Info_B", "Info_C"])
        self.assertEqual(controller.SOURCE_RECONCILE["Info_duplicate"]["lifecycle"], "covered_by_explicit")

    def test_removed_source_with_selected_leaf_is_retained(self):
        self.information()
        previous = {"Info_B": {"id": "Info_B", "name": "B", "origin": "managed", "approved_names": ["[Info_B] US"]}}
        with mock.patch.object(controller, "_previous_managed", return_value=previous), mock.patch.object(
            controller, "_selected_leaf_dependencies", return_value=(["Google", "Stable"], True)
        ):
            sources = controller.load_sources()
        retained = next(source for source in sources if source.source_id == "Info_B")
        self.assertTrue(retained.retiring)
        self.assertEqual(retained.dependencies, ("Google", "Stable"))

    def test_removed_source_without_dependencies_is_retired(self):
        self.information()
        previous = {"Info_B": {"id": "Info_B", "name": "B", "origin": "managed", "approved_names": ["[Info_B] US"]}}
        with mock.patch.object(controller, "_previous_managed", return_value=previous), mock.patch.object(
            controller, "_selected_leaf_dependencies", return_value=([], True)
        ):
            sources = controller.load_sources()
        self.assertNotIn("Info_B", [source.source_id for source in sources])
        self.assertEqual(controller.SOURCE_RECONCILE["Info_B"]["lifecycle"], "pending_retirement")

    def test_registry_failure_retains_previous_source_conservatively(self):
        controller.INFORMATION_SOURCES_FILE.write_text("{broken", encoding="utf-8")
        previous = {"Info_B": {"id": "Info_B", "name": "B", "origin": "managed", "approved_names": []}}
        with mock.patch.object(controller, "_previous_managed", return_value=previous):
            sources = controller.load_sources()
        retained = next(source for source in sources if source.source_id == "Info_B")
        self.assertTrue(retained.retiring)
        self.assertIn("information_registry_unavailable", retained.dependencies)

    def test_new_managed_fetch_failure_is_isolated_from_explicit_source(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")

        def load(source, _deadline=None):
            if source.origin == "managed":
                raise controller.ControllerError("source_unavailable")
            return [node("A", "1.1.1.1")], False, "digest"

        with mock.patch.object(controller, "load_or_fetch", side_effect=load), mock.patch.object(controller, "log"):
            ready, nodes, cached = controller.collect_source_nodes([explicit, managed])
        self.assertEqual([source.source_id for source in ready], ["Provider_A"])
        self.assertEqual(list(nodes), ["Provider_A"])
        self.assertEqual(cached, 0)
        self.assertEqual(controller.SOURCE_RECONCILE["Info_B"]["lifecycle"], "error")

    def test_release_has_candidate_and_admitted_aggregate_with_stable_names(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        explicit_node = node("A-US", "1.1.1.1")
        managed_node = controller._managed_names(managed, [node("B-US", "2.2.2.2")])[0]
        self.admit(managed_node)
        sources = [explicit, managed]
        source_nodes = {"Provider_A": [explicit_node], "Info_B": [managed_node]}
        with mock.patch.object(controller, "current_manifest", return_value=None):
            release_id, manifest, *_ = controller.create_release(source_nodes, sources, {}, 0, {})
        providers = {row["id"]: row for row in manifest["sources"]}
        self.assertNotIn(controller.MANAGED_CANDIDATE_ID, providers)
        self.assertIn(controller.MANAGED_AUTO_ID, providers)
        self.assertEqual(manifest["managed"]["candidate_count"], 1)
        self.assertEqual(manifest["managed"]["approved_count"], 1)
        self.assertEqual(manifest["managed"]["candidate_channel"], "isolated_admission_queue")
        self.assertEqual(manifest["source_breakdown"][0]["approved_names"], ["[Info_B] B-US"])
        self.assertIn("approved_file", manifest["source_breakdown"][0])
        self.assertTrue((controller.RELEASES / release_id / providers[controller.MANAGED_AUTO_ID]["file"]).is_file())

    def test_candidate_is_never_a_production_provider(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        source_nodes = {"Provider_A": [node("A", "1.1.1.1")], "Info_B": controller._managed_names(managed, [node("B", "2.2.2.2")])}
        self.admit(*source_nodes["Info_B"])
        with mock.patch.object(controller, "current_manifest", return_value=None):
            release_id, manifest, *_ = controller.create_release(source_nodes, [explicit, managed], {}, 0, {})
        self.assertFalse(manifest["managed"]["candidate_exposed"])
        self.assertNotIn(controller.MANAGED_CANDIDATE_ID, {row["id"] for row in manifest["sources"]})
        breakdown = manifest["source_breakdown"][0]
        parsed = controller.parse_nodes((controller.RELEASES / release_id / breakdown["file"]).read_bytes())
        self.assertEqual(parsed[0]["name"], "[Info_B] B")

    def test_new_managed_node_waits_for_isolated_admission(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        candidate = controller._managed_names(managed, [node("Pending", "2.2.2.2")])[0]
        with mock.patch.object(controller, "current_manifest", return_value=None):
            release_id, manifest, *_ = controller.create_release(
                {"Provider_A": [node("A", "1.1.1.1")], "Info_B": [candidate]}, [explicit, managed], {}, 0, {}
            )
        self.assertEqual(manifest["managed"]["candidate_count"], 1)
        self.assertEqual(manifest["managed"]["approved_count"], 0)
        active = next(row for row in manifest["sources"] if row["id"] == controller.MANAGED_AUTO_ID)
        parsed = controller.parse_nodes((controller.RELEASES / release_id / active["file"]).read_bytes())
        self.assertEqual(parsed[0]["name"], "__STACK_EMPTY_MANAGED_AUTO__")

    def test_private_override_add_and_tombstone_are_applied(self):
        self.information({"id": "Info_B", "name": "B", "url": "https://b.invalid/sub", "enabled": True})
        controller.SOURCE_OVERRIDES_FILE.write_text(json.dumps({
            "schema": 1,
            "sources": [{"id": "Local_C", "name": "C", "url": "https://c.invalid/sub", "enabled": True}],
            "tombstones": ["Info_B"],
        }), encoding="utf-8")
        os.chmod(controller.SOURCE_OVERRIDES_FILE, 0o600)
        with mock.patch.object(controller, "current_manifest", return_value=None):
            sources = controller.load_sources()
        self.assertEqual([source.source_id for source in sources], ["Provider_A", "Local_C"])

    def test_managed_runtime_identity_is_not_only_a_count(self):
        refs = [controller.Source(controller.MANAGED_AUTO_ID, "active", "", controller.MANAGED_AUTO_ID)]
        payload = {"providers": {controller.MANAGED_AUTO_ID: {"proxies": [
            {"name": "[Info_B] B"}, {"name": "__STACK_EMPTY_MANAGED_AUTO__"}
        ]}}}
        with mock.patch.object(controller, "api_request", return_value=payload):
            snapshot = controller.runtime_provider_snapshot(refs)
        self.assertEqual(snapshot, {controller.MANAGED_AUTO_ID: ["[Info_B] B"]})

    def test_reconciliation_uses_private_single_flight_lock(self):
        seen = []

        @contextmanager
        def lock(path):
            seen.append(path)
            yield True

        with mock.patch.object(controller, "exclusive", side_effect=lock), mock.patch.object(controller, "_cycle_locked") as run:
            controller.cycle()
        run.assert_called_once_with()
        self.assertEqual(seen, [controller.DATA / "reconcile.lock"])

    def test_slow_source_collection_never_holds_routing_owner_lock(self):
        held = set()

        @contextmanager
        def lock(path):
            held.add(path)
            try:
                yield True
            finally:
                held.remove(path)

        explicit = controller.Source("Provider_A", "A", "", "Provider_A")

        def load(_source, _deadline=None):
            self.assertNotIn(controller.DATA.parent / "routing-owner.lock", held)
            return [node("A", "1.1.1.1")], False, "digest"

        with mock.patch.object(controller, "exclusive", side_effect=lock), mock.patch.object(
            controller, "load_or_fetch", side_effect=load
        ):
            with controller.exclusive(controller.DATA / "reconcile.lock") as acquired:
                self.assertTrue(acquired)
                ready, batches, _cached = controller.collect_source_nodes(
                    [explicit], deadline=controller.time.monotonic() + 10
                )
        self.assertEqual([row.source_id for row in ready], ["Provider_A"])
        self.assertEqual(list(batches), ["Provider_A"])

    def test_cycle_budget_defers_new_source_without_late_worker(self):
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        with mock.patch.object(controller, "load_or_fetch") as load, mock.patch.object(
            controller, "_remaining", return_value=-1
        ), mock.patch.object(controller, "current_manifest", return_value=None), mock.patch.object(controller, "log"):
            ready, batches, cached = controller.collect_source_nodes([managed], deadline=1)
        load.assert_not_called()
        self.assertEqual((ready, batches, cached), ([], {}, 0))
        self.assertEqual(controller.SOURCE_RECONCILE["Info_B"]["reason"], "cycle_budget_deferred")

    def test_source_budget_round_robin_prevents_cross_class_starvation(self):
        sources = [
            controller.Source("Provider_A", "A", "", "Provider_A"),
            controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed"),
            controller.Source("Info_C", "C", "", controller.MANAGED_AUTO_ID, "managed"),
        ]
        seen = []

        def load(source, _deadline=None):
            seen.append(source.source_id)
            return [node(source.source_id, "1.1.1.1")], False, "digest"

        with mock.patch.object(controller, "load_or_fetch", side_effect=load), mock.patch.object(
            controller, "_remaining", side_effect=[10, -1, -1]
        ), mock.patch.object(controller, "current_manifest", return_value=None), mock.patch.object(controller, "log"):
            controller.collect_source_nodes(sources, deadline=1)
        self.assertEqual(seen, ["Provider_A"])
        seen.clear()
        with mock.patch.object(controller, "load_or_fetch", side_effect=load), mock.patch.object(
            controller, "_remaining", side_effect=[10, -1, -1]
        ), mock.patch.object(controller, "current_manifest", return_value=None), mock.patch.object(controller, "log"):
            controller.collect_source_nodes(sources, deadline=1)
        self.assertEqual(seen, ["Info_B"])

    def test_publish_network_checks_run_outside_global_lock(self):
        held = set()

        @contextmanager
        def lock(path):
            held.add(path)
            try:
                yield True
            finally:
                held.remove(path)

        source = controller.Source("Provider_A", "A", "", "Provider_A")
        previous = {"release_id": "old", "source_breakdown": []}
        manifest = {"release_id": "new", "previous_id": "old", "candidate_hash": "hash",
                    "sources": [{"id": "Provider_A", "provider_name": "Provider_A", "node_count": 1}]}
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": "old", "published_at": 1})

        def refresh(_sources, _deadline=None):
            self.assertNotIn(controller.DATA.parent / "routing-owner.lock", held)

        def smoke(_deadline=None):
            self.assertNotIn(controller.DATA.parent / "routing-owner.lock", held)
            return True, "ok"

        with mock.patch.object(controller, "exclusive", side_effect=lock), mock.patch.object(
            controller, "current_manifest", return_value=previous
        ), mock.patch.object(controller, "_runtime_proxy_snapshot", return_value=({"A": {}}, "rev")), mock.patch.object(
            controller, "_publish_dependencies_safe", return_value=True
        ), mock.patch.object(controller, "refresh_providers", side_effect=refresh), mock.patch.object(
            controller, "runtime_provider_snapshot", return_value={"Provider_A": ["A"]}
        ), mock.patch.object(controller, "production_smoke", side_effect=smoke), mock.patch.object(
            controller, "MODE", "automatic"
        ), mock.patch.object(controller, "POST_PUBLISH_WAIT", 0), mock.patch.object(controller, "MIN_APPROVED", 1):
            ok, reason = controller.publish("new", manifest, [source], controller.time.monotonic() + 10)
        self.assertTrue(ok, reason)
        self.assertFalse(controller.PENDING_PATH.exists())

    def test_publish_dependency_cas_rereads_selection_before_commit(self):
        source = controller.Source("Provider_A", "A", "", "Provider_A")
        previous = {"release_id": "old", "source_breakdown": [{"id": "Info_B", "approved_names": ["old"]}]}
        manifest = {"release_id": "new", "previous_id": "old", "candidate_hash": "hash",
                    "sources": [{"id": "Provider_A", "provider_name": "Provider_A", "node_count": 1}],
                    "source_breakdown": []}
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": "old", "published_at": 1})
        with mock.patch.object(controller, "current_manifest", return_value=previous), mock.patch.object(
            controller, "_runtime_proxy_snapshot", return_value=({"old": {}, "Google": {"now": "old"}}, "rev")
        ), mock.patch.object(controller, "refresh_providers") as refresh, mock.patch.object(
            controller, "MODE", "automatic"
        ):
            ok, reason = controller.publish("new", manifest, [source], controller.time.monotonic() + 10)
        self.assertFalse(ok)
        self.assertEqual(reason, "deferred_selection_dependency_changed")
        refresh.assert_not_called()
        self.assertEqual(json.loads(controller.CURRENT_PATH.read_text())["release_id"], "old")

    def test_pending_recovery_never_overwrites_newer_current(self):
        for release_id in ("previous", "candidate", "newer"):
            directory = controller.RELEASES / release_id
            directory.mkdir(parents=True, exist_ok=True)
            controller.atomic_json(directory / "manifest.json", {"release_id": release_id, "sources": [], "source_breakdown": []})
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": "newer", "published_at": 3})
        controller.atomic_json(controller.PENDING_PATH, {
            "release_id": "candidate", "previous_pointer": {"release_id": "previous", "published_at": 1},
            "started_at": 2,
        })
        self.assertTrue(controller.recover_interrupted_publish())
        self.assertEqual(json.loads(controller.CURRENT_PATH.read_text())["release_id"], "newer")
        self.assertFalse(controller.PENDING_PATH.exists())
        self.assertTrue((controller.DATA / "recovery-refresh.json").exists())

    def test_unselected_removed_leaf_can_publish_after_it_disappears(self):
        source = controller.Source("Provider_A", "A", "", "Provider_A")
        previous = {"release_id": "old", "source_breakdown": [
            {"id": "Info_B", "approved_names": ["old-leaf"]},
        ]}
        manifest = {"release_id": "new", "previous_id": "old", "candidate_hash": "hash",
                    "sources": [{"id": "Provider_A", "provider_name": "Provider_A", "node_count": 1}],
                    "source_breakdown": []}
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": "old", "published_at": 1})
        snapshots = [({"old-leaf": {}}, "before"), ({}, "pre-refresh"), ({}, "after-refresh"),
                     ({}, "before-finalize"), ({}, "after-finalize"), ({}, "post-commit")]
        with mock.patch.object(controller, "current_manifest", return_value=previous), mock.patch.object(
            controller, "_runtime_proxy_snapshot", side_effect=snapshots
        ), mock.patch.object(controller, "refresh_providers"), mock.patch.object(
            controller, "runtime_provider_snapshot", return_value={"Provider_A": ["A"]}
        ), mock.patch.object(controller, "production_smoke", return_value=(True, "ok")), mock.patch.object(
            controller, "MODE", "automatic"
        ), mock.patch.object(controller, "POST_PUBLISH_WAIT", 0), mock.patch.object(controller, "MIN_APPROVED", 1):
            ok, reason = controller.publish("new", manifest, [source], controller.time.monotonic() + 10)
        self.assertTrue(ok, reason)

    def test_selector_race_at_commit_is_detected_and_rolled_back(self):
        source = controller.Source("Provider_A", "A", "", "Provider_A")
        previous = {"release_id": "old", "sources": [], "source_breakdown": [
            {"id": "Info_B", "approved_names": ["old-leaf"]},
        ]}
        old_dir = controller.RELEASES / "old"
        old_dir.mkdir(parents=True, exist_ok=True)
        controller.atomic_json(old_dir / "manifest.json", previous)
        manifest = {"release_id": "new", "previous_id": "old", "candidate_hash": "hash",
                    "sources": [{"id": "Provider_A", "provider_name": "Provider_A", "node_count": 1}],
                    "source_breakdown": []}
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": "old", "published_at": 1})
        snapshots = [({"old-leaf": {}}, "before"), ({}, "pre-refresh"), ({}, "after-refresh"),
                     ({}, "before-finalize"), ({}, "after-finalize"),
                     ({"old-leaf": {}, "Google": {"now": "old-leaf"}}, "commit-race")]
        with mock.patch.object(controller, "current_manifest", return_value=previous), mock.patch.object(
            controller, "_runtime_proxy_snapshot", side_effect=snapshots
        ), mock.patch.object(controller, "refresh_providers"), mock.patch.object(
            controller, "runtime_provider_snapshot", return_value={"Provider_A": ["A"]}
        ), mock.patch.object(controller, "production_smoke", return_value=(True, "ok")), mock.patch.object(
            controller, "MODE", "automatic"
        ), mock.patch.object(controller, "POST_PUBLISH_WAIT", 0), mock.patch.object(controller, "MIN_APPROVED", 1):
            ok, reason = controller.publish("new", manifest, [source], controller.time.monotonic() + 10)
        self.assertFalse(ok)
        self.assertEqual(reason, "selection_dependency_changed_at_commit")
        self.assertEqual(json.loads(controller.CURRENT_PATH.read_text())["release_id"], "old")

    def test_reconcile_trigger_requires_fresh_owned_bounded_document(self):
        path = controller.DATA / "reconcile-request.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(controller, "now", return_value=1000):
            path.write_text(json.dumps({"schema": 1, "owner": "unified-center", "source_id": "Info_B", "requested_at": 900}), encoding="utf-8")
            self.assertTrue(controller.reconcile_requested())
            path.write_text(json.dumps({"schema": 1, "owner": "other", "source_id": "Info_B", "requested_at": 900}), encoding="utf-8")
            self.assertFalse(controller.reconcile_requested())
            path.write_text(json.dumps({"schema": 1, "owner": "admission-queue", "source_id": "Info_B", "requested_at": 900}), encoding="utf-8")
            self.assertTrue(controller.reconcile_requested())
            path.write_text(json.dumps({"schema": 1, "owner": "unified-center", "source_id": "Info_B", "requested_at": 1}), encoding="utf-8")
            self.assertFalse(controller.reconcile_requested())

    def test_error_evidence_redacts_url_userinfo_query_and_secret_canary(self):
        raw = "fetch failed https://user:pass@private.example/path?token=CANARY token=CANARY"
        safe = controller.safe_detail(raw)
        for secret in ("private.example", "user", "pass", "CANARY"):
            self.assertNotIn(secret, safe)
        controller.log("source_failure", raw, "warning")
        controller.source_failure(controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed"), raw)
        public = json.dumps(controller.latest_status(), ensure_ascii=False)
        persisted = controller.LOG_PATH.read_text(encoding="utf-8") + public
        for secret in ("private.example", "user:pass", "CANARY"):
            self.assertNotIn(secret, persisted)
        self.assertIn("URL_REDACTED", persisted)

    def test_release_is_restart_readable_with_managed_breakdown_checksums(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        nodes = {"Provider_A": [node("A", "1.1.1.1")], "Info_B": controller._managed_names(managed, [node("B", "2.2.2.2")])}
        self.admit(*nodes["Info_B"])
        with mock.patch.object(controller, "current_manifest", return_value=None):
            release_id, manifest, *_ = controller.create_release(nodes, [explicit, managed], {}, 0, {})
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": release_id, "published_at": controller.now()})
        self.assertEqual(controller.current_manifest()["candidate_hash"], manifest["candidate_hash"])
        breakdown = manifest["source_breakdown"][0]
        (controller.RELEASES / release_id / breakdown["file"]).write_text("tampered", encoding="utf-8")
        self.assertIsNone(controller.current_manifest())

    def test_new_unapproved_candidate_keeps_old_approved_snapshot_separately(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        old = controller._managed_names(managed, [node("Old", "2.2.2.2")])[0]
        self.admit(old)
        with mock.patch.object(controller, "current_manifest", return_value=None):
            first_id, first, *_ = controller.create_release(
                {"Provider_A": [node("A", "1.1.1.1")], "Info_B": [old]}, [explicit, managed], {}, 0, {}
            )
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": first_id, "published_at": controller.now()})
        new = controller._managed_names(managed, [node("New", "3.3.3.3")])[0]
        second_id, second, *_ = controller.create_release(
            {"Provider_A": [node("A", "1.1.1.1")], "Info_B": [new]}, [explicit, managed], {}, 0, {}
        )
        row = second["source_breakdown"][0]
        candidate_names = [item["name"] for item in controller.parse_nodes(
            (controller.RELEASES / second_id / row["file"]).read_bytes()
        )]
        approved_names = [item["name"] for item in controller.parse_nodes(
            (controller.RELEASES / second_id / row["approved_file"]).read_bytes()
        )]
        self.assertEqual(candidate_names, ["[Info_B] New"])
        self.assertEqual(approved_names, ["[Info_B] Old"])

    def test_source_update_keeps_selected_old_leaf_until_dependency_clears(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        managed = controller.Source("Info_B", "B", "", controller.MANAGED_AUTO_ID, "managed")
        old = controller._managed_names(managed, [node("Old", "2.2.2.2")])[0]
        self.admit(old)
        with mock.patch.object(controller, "current_manifest", return_value=None):
            first_id, _first, *_ = controller.create_release(
                {"Provider_A": [node("A", "1.1.1.1")], "Info_B": [old]}, [explicit, managed], {}, 0, {}
            )
        controller.atomic_json(controller.CURRENT_PATH, {"release_id": first_id, "published_at": controller.now()})
        new = controller._managed_names(managed, [node("New", "3.3.3.3")])[0]
        self.admit(new)
        with mock.patch.object(controller, "_selected_leaf_dependencies", return_value=(["Google"], True)):
            second_id, second, *_ = controller.create_release(
                {"Provider_A": [node("A", "1.1.1.1")], "Info_B": [new]}, [explicit, managed], {}, 0, {}
            )
        row = second["source_breakdown"][0]
        names = [item["name"] for item in controller.parse_nodes(
            (controller.RELEASES / second_id / row["approved_file"]).read_bytes()
        )]
        self.assertEqual(set(names), {"[Info_B] New", "[Info_B] Old"})
        self.assertEqual(controller.SOURCE_RECONCILE["Info_B"]["dependencies"], ["Google"])

    def test_same_endpoint_from_new_and_retiring_sources_keeps_both_name_identities(self):
        explicit = controller.Source("Provider_A", "A", "", "Provider_A")
        first = controller.Source("Info_OLD", "Old", "", controller.MANAGED_AUTO_ID, "managed", True, ("Google",))
        second = controller.Source("Info_NEW", "New", "", controller.MANAGED_AUTO_ID, "managed")
        endpoint = node("Shared", "4.4.4.4")
        old_node = controller._managed_names(first, [endpoint])[0]
        new_node = controller._managed_names(second, [endpoint])[0]
        self.admit(old_node, new_node)
        with mock.patch.object(controller, "current_manifest", return_value=None):
            _release, manifest, *_ = controller.create_release({
                "Provider_A": [node("A", "1.1.1.1")], "Info_OLD": [old_node], "Info_NEW": [new_node],
            }, [explicit, first, second], {}, 0, {})
        self.assertEqual(manifest["managed"]["approved_count"], 2)
        active = next(row for row in manifest["sources"] if row["id"] == controller.MANAGED_AUTO_ID)
        names = [item["name"] for item in controller.parse_nodes(
            (controller.RELEASES / manifest["release_id"] / active["file"]).read_bytes()
        ) if not item["name"].startswith("__STACK_EMPTY_")]
        self.assertEqual(set(names), {"[Info_OLD] Shared", "[Info_NEW] Shared"})

    def test_third_source_enters_private_admission_queue_and_is_retested(self):
        self.information({"id": "Info_THREE", "name": "Third", "url": "https://three.invalid/sub", "enabled": True})
        candidate = node("Third Pending", "5.5.5.5")
        (controller.CACHE / "Info_THREE.yaml").write_bytes(controller.provider_yaml([candidate]))
        fake_fcntl = types.ModuleType("fcntl")
        fake_fcntl.LOCK_EX, fake_fcntl.LOCK_NB = 1, 2
        fake_fcntl.flock = lambda *_args: None
        health_spec = importlib.util.spec_from_file_location("health_policy_real_test", UPSTREAM / "health_policy.py")
        real_health = importlib.util.module_from_spec(health_spec)
        assert health_spec and health_spec.loader
        health_spec.loader.exec_module(real_health)
        spec = importlib.util.spec_from_file_location("admission_queue_real_test", UPSTREAM / "admission_queue.py")
        queue = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        with mock.patch.dict(sys.modules, {"fcntl": fake_fcntl, "health_policy": real_health}):
            spec.loader.exec_module(queue)
        current = {"fingerprints": [], "source_breakdown": []}
        with mock.patch.object(controller, "current_manifest", return_value=current):
            self.assertTrue(queue.tick(controller, validator=lambda _node: (True, "isolated_two_endpoints_passed"), epoch=1000))
            self.assertTrue(queue.tick(controller, validator=lambda _node: (True, "isolated_two_endpoints_passed"), epoch=1031))
        cache = queue.read_cache(controller.DATA / "admission-cache.json")
        record = cache[controller.fingerprint(candidate)]
        self.assertEqual((record["status"], record["success_streak"], record["ok"]), ("available", 2, True))
        self.assertEqual(record["reason"], "isolated_two_endpoints_passed")
        trigger = json.loads((controller.DATA / "reconcile-request.json").read_text(encoding="utf-8"))
        self.assertEqual((trigger["owner"], trigger["source_id"]), ("admission-queue", "Info_THREE"))


if __name__ == "__main__":
    unittest.main()
