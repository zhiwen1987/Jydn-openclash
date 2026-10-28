import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
MODULE = importlib.import_module("extensions.subscription_lifecycle")


class SubscriptionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        controller = self.root / "subscription-controller"
        release = controller / "releases" / "release-1"
        usage = self.root / "subscription-usage"
        node_health = self.root / "node-health"
        release.mkdir(parents=True)
        usage.mkdir(parents=True)
        node_health.mkdir(parents=True)
        (controller / "current.json").write_text(json.dumps({"release_id": "release-1"}), encoding="utf-8")
        active = json.dumps({"proxies": [{"name": "[Info_THREE] US-1", "type": "ss", "server": "x", "port": 1}]}).encode()
        candidate = json.dumps({"proxies": [
            {"name": "[Info_THREE] US-1", "type": "ss", "server": "x", "port": 1},
            {"name": "[Info_THREE] Pending", "type": "ss", "server": "y", "port": 2},
        ]}).encode()
        import hashlib
        (release / "Managed_Auto.yaml").write_bytes(active)
        (release / "managed-Info_THREE.yaml").write_bytes(candidate)
        manifest = {
            "release_id": "release-1", "sources": [
                {"id": "Managed_Auto", "provider_name": "Managed_Auto", "file": "Managed_Auto.yaml",
                 "sha256": hashlib.sha256(active).hexdigest(), "role": "managed_active"},
            ],
            "source_breakdown": [{"id": "Info_THREE", "name": "Third", "origin": "managed",
                                  "candidate_count": 2, "approved_count": 1,
                                  "approved_names": ["[Info_THREE] US-1"], "dependencies": [],
                                  "file": "managed-Info_THREE.yaml", "sha256": hashlib.sha256(candidate).hexdigest()}],
            "managed": {"candidate_provider": None, "candidate_channel": "isolated_admission_queue",
                        "active_provider": "Managed_Auto", "candidate_count": 2,
                        "approved_count": 1, "candidate_exposed": False},
        }
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (controller / "health.json").write_text(json.dumps({"status": "ok", "epoch": 10,
            "release_status": "published", "source_inventory": [{"id": "Info_THREE", "name": "Third",
            "lifecycle": "published", "desired": "present", "actual": "published", "loaded": True}]}), encoding="utf-8")
        (usage / "information-sources.json").write_text(json.dumps({"purpose": "subscription_information_only",
            "sources": [{"id": "Info_THREE", "name": "Third", "url": "https://secret.invalid/?token=SECRET"}]}), encoding="utf-8")
        (node_health / "admission-progress.json").write_text(json.dumps({"schema": 1, "epoch": 10,
            "sources": [{"source_id": "Info_THREE", "parsed_count": 2, "candidate_count": 2,
                         "tested_count": 1, "approved_count": 1, "next_due": 40}]}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def progress(*_args, **_kwargs):
        return None

    def extension(self, mismatch=False, global_candidate=False):
        def clash(path, method="GET", body=None):
            name = "wrong" if mismatch else "[Info_THREE] US-1"
            if path == "/providers/proxies":
                return {"providers": {"Managed_Auto": {"proxies": [{"name": name}]}}}
            if path == "/proxies":
                members = [name] + (["[Info_THREE] Pending"] if global_candidate else [])
                return {"proxies": {name: {"type": "Shadowsocks"}, "GLOBAL": {"now": name, "all": members}}}
            self.fail(path)
        return MODULE.create_extension({"data_root": self.root, "clash": clash, "write_lock_managed": True})

    def test_snapshot_is_n_source_and_secret_free(self):
        extension = self.extension()
        snapshot = extension.snapshot()
        self.assertEqual(snapshot["state"], "ok")
        self.assertEqual(snapshot["sources"][0]["id"], "Info_THREE")
        self.assertEqual(snapshot["sources"][0]["providers"]["active"], "Managed_Auto")
        self.assertEqual(snapshot["sources"][0]["providers"]["candidate_scope"], "isolated_admission_queue")
        self.assertEqual(snapshot["sources"][0]["admission"]["tested_count"], 1)
        self.assertEqual(snapshot["sources"][0]["admission"]["next_due"], 40)
        self.assertNotIn("SECRET", json.dumps(snapshot))
        self.assertNotIn("secret.invalid", json.dumps(snapshot))
        actions = extension.actions()
        self.assertTrue(actions["subscriptions.preview"]["supported"])
        self.assertNotIn("subscriptions.reconcile", actions)
        self.assertTrue(all(actions[action]["supported"] for action in (
            "subscriptions.source.add", "subscriptions.source.update", "subscriptions.source.disable",
            "subscriptions.source.enable", "subscriptions.source.delete",
        )))

    def test_pending_publication_is_visible_and_not_reported_ok(self):
        controller = self.root / "subscription-controller"
        (controller / "publish-pending.json").write_text(json.dumps({
            "release_id": "release-2", "started_at": 123,
            "previous_pointer": {"release_id": "release-1"},
        }), encoding="utf-8")
        snapshot = self.extension().snapshot()
        self.assertEqual(snapshot["state"], "warning")
        self.assertEqual(snapshot["reconcile"]["journal"], {
            "state": "publishing", "release_id": "release-2", "started_at": 123,
        })

    def test_revision_ignores_heartbeat_but_tracks_config_and_pointer(self):
        extension = self.extension()
        revision = extension.snapshot()["revision"]
        controller = self.root / "subscription-controller"
        health = json.loads((controller / "health.json").read_text(encoding="utf-8"))
        health["epoch"] = 999
        (controller / "health.json").write_text(json.dumps(health), encoding="utf-8")
        node_health = self.root / "node-health" / "admission-progress.json"
        progress = json.loads(node_health.read_text(encoding="utf-8")); progress["epoch"] = 999
        node_health.write_text(json.dumps(progress), encoding="utf-8")
        self.assertEqual(extension.snapshot()["revision"], revision)

        overrides = self.root / "subscription-usage" / "source-overrides.json"
        overrides.write_text(json.dumps({"schema": 1, "sources": [], "tombstones": [], "updated_at": 1}), encoding="utf-8")
        config_revision = extension.snapshot()["revision"]
        self.assertNotEqual(config_revision, revision)
        (controller / "current.json").write_text(json.dumps({"release_id": "other-release"}), encoding="utf-8")
        self.assertNotEqual(extension.snapshot()["revision"], config_revision)

    def test_validate_requires_exact_managed_identity(self):
        result = self.extension().execute("subscriptions.validate", {}, self.progress)
        self.assertEqual(result["state"], "ok")
        self.assertTrue(all(row["identity_match"] for row in result["providers"]))
        mismatch = self.extension(mismatch=True).execute("subscriptions.validate", {}, self.progress)
        self.assertEqual(mismatch["state"], "error")
        self.assertEqual({row["code"] for row in mismatch["failures"]}, {"managed_provider_identity_mismatch"})
        global_exposed = self.extension(global_candidate=True).execute("subscriptions.validate", {}, self.progress)
        self.assertEqual(global_exposed["state"], "error")
        self.assertIn("unadmitted_candidate_in_global", {row["code"] for row in global_exposed["failures"]})

    def test_missing_registry_is_warning_not_destructive(self):
        (self.root / "subscription-usage" / "information-sources.json").unlink()
        snapshot = self.extension().snapshot()
        self.assertEqual(snapshot["state"], "warning")
        row = snapshot["sources"][0]
        self.assertEqual(row["desired"], "unknown")
        self.assertEqual(row["stage"], "retained_by_selection")
        self.assertIn("information_registry_unavailable", row["dependencies"])

    def test_n_source_add_and_delete_preview_are_derived_without_writes(self):
        registry = self.root / "subscription-usage" / "information-sources.json"
        document = json.loads(registry.read_text(encoding="utf-8"))
        document["sources"].append({"id": "Info_FOUR", "name": "Fourth",
                                    "url": "https://four.invalid/subscription"})
        registry.write_text(json.dumps(document), encoding="utf-8")
        snapshot = self.extension().snapshot()
        rows = {row["id"]: row for row in snapshot["sources"]}
        self.assertEqual(rows["Info_FOUR"]["stage"], "discovered")
        self.assertEqual(rows["Info_FOUR"]["desired"], "present")

        # A valid registry deletion is a retirement request, unlike a missing
        # registry which must retain the last release conservatively.
        registry.write_text(json.dumps({"purpose": "subscription_information_only", "sources": []}), encoding="utf-8")
        snapshot = self.extension().snapshot()
        row = snapshot["sources"][0]
        self.assertEqual(row["desired"], "absent")
        self.assertEqual(row["stage"], "pending_retirement")

    def test_private_override_write_lifecycle_never_exposes_url(self):
        extension = self.extension()
        result = extension.execute("subscriptions.source.add", {
            "name": "New", "url": "https://new.invalid/sub?token=DO_NOT_EXPOSE"
        }, self.progress)
        source_id = result["source_id"]
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(result))
        override = self.root / "subscription-usage" / "source-overrides.json"
        self.assertIn("DO_NOT_EXPOSE", override.read_text(encoding="utf-8"))
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(extension.snapshot()))

        extension.execute("subscriptions.source.disable", {"source_id": source_id}, self.progress)
        row = next(row for row in extension.snapshot()["sources"] if row["id"] == source_id)
        self.assertEqual((row["desired"], row["stage"]), ("absent", "pending_retirement"))
        extension.execute("subscriptions.source.enable", {"source_id": source_id}, self.progress)
        extension.execute("subscriptions.source.update", {
            "source_id": source_id, "name": "Renamed", "url": "https://new.invalid/changed?token=SECOND"
        }, self.progress)
        row = next(row for row in extension.snapshot()["sources"] if row["id"] == source_id)
        self.assertEqual(row["name"], "Renamed")
        self.assertNotIn("SECOND", json.dumps(row))
        extension.execute("subscriptions.source.delete", {"source_id": source_id}, self.progress)
        self.assertNotIn(source_id, {row["id"] for row in extension.snapshot()["sources"]})

    def test_sync_tombstone_prevents_revival_and_explicit_source_is_protected(self):
        extension = self.extension()
        extension.execute("subscriptions.source.disable", {"source_id": "Info_THREE"}, self.progress)
        self.assertEqual(next(row for row in extension.snapshot()["sources"]
                              if row["id"] == "Info_THREE")["desired"], "absent")

        # Editing metadata/URL is not an implicit enable operation.
        extension.execute("subscriptions.source.update", {
            "source_id": "Info_THREE", "name": "Still Disabled",
            "url": "https://secret.invalid/updated",
        }, self.progress)
        disabled = next(row for row in extension.snapshot()["sources"] if row["id"] == "Info_THREE")
        self.assertEqual(disabled["desired"], "absent")
        registry = self.root / "subscription-usage" / "information-sources.json"
        registry.write_text(json.dumps({"purpose": "subscription_information_only", "sources": [
            {"id": "Info_THREE", "name": "Third Again", "url": "https://secret.invalid/new"}
        ]}), encoding="utf-8")
        self.assertEqual(next(row for row in extension.snapshot()["sources"]
                              if row["id"] == "Info_THREE")["desired"], "absent")

        manifest_path = self.root / "subscription-controller" / "releases" / "release-1" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sources"].append({"id": "Provider_LEGACY", "provider_name": "Provider_LEGACY", "role": "explicit"})
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(MODULE.SubscriptionActionError) as raised:
            extension.execute("subscriptions.source.delete", {"source_id": "Provider_LEGACY"}, self.progress)
        self.assertEqual(raised.exception.code, "protected_legacy_source")


if __name__ == "__main__":
    unittest.main()
