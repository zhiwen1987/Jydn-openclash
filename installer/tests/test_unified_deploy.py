import importlib.util
import json
import hashlib
import gzip
import io
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest import mock
import contextlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "unified_center_deploy", ROOT / "agents/unified_center_deploy.py"
)
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)
BUILD_SPEC = importlib.util.spec_from_file_location(
    "build_unified_image", ROOT / "build_unified_image.py"
)
build = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(build)


COMPOSE = """name: lan-center
services:
  center:
    image: old/image:1
    environment:
      EXISTING: "kept"
    volumes:
      - ./data/failover:/data
      - /release/node-capability.py:/node-capability.py:ro
      - /release/subscription-controller.py:/subscription-controller.py:ro
      - /release/healthcheck.sh:/healthcheck.sh:ro
      - /release/Corefile:/etc/coredns/Corefile:ro
  unrelated:
    image: never/change:1
"""

COMPOSE_JSON_OBJECT = {
    "name": "lan-center",
    "services": {
        "center": {
            "container_name": "clash-center",
            "image": "old/image:1",
            "restart": "unless-stopped",
            "environment": {"EXISTING": "kept", "CENTER_UI_ENABLED": "0"},
            "ports": ["3101:3001", "3102:8081", "3103:8082"],
            "volumes": [
                "/srv/failover:/data",
                "/srv/kuma:/app/data",
                "/release/Corefile:/etc/coredns/Corefile:ro",
                "/release/node-capability.py:/node-capability.py:ro",
                "/release/subscription-controller.py:/subscription-controller.py:ro",
                "/release/healthcheck.sh:/healthcheck.sh:ro",
            ],
            "labels": {"preserve": "exact-value"},
        },
        "unrelated": {
            "container_name": "unrelated-service",
            "image": "never/change:1",
            "environment": {"UNCHANGED": "yes"},
        },
    },
    "networks": {"default": {"name": "lan-center_default", "external": True}},
    "x-private-shape": {"nested": [1, True, None, {"keep": "所有字段"}]},
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def make_oci_archive(path, *, multi_root=False, corrupt_unreferenced=False,
                     duplicate_member=False, traversal=False, legacy_mismatch=False,
                     wrong_platform=False, wrong_root_size=False):
    def encoded(value):
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    expanded = b"one deterministic tar layer\n"
    compressed = gzip.compress(expanded, mtime=0)
    layer_hex = hashlib.sha256(compressed).hexdigest()
    diff_id = "sha256:" + hashlib.sha256(expanded).hexdigest()
    config = encoded({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [diff_id, diff_id]},
        "config": {"Labels": {"fixture": "oci-containerd"}},
    })
    config_hex = hashlib.sha256(config).hexdigest()
    layers = [
        {"mediaType": build.OCI_GZIP_LAYER, "digest": "sha256:" + layer_hex, "size": len(compressed)},
        {"mediaType": build.DOCKER_GZIP_LAYER, "digest": "sha256:" + layer_hex, "size": len(compressed)},
    ]
    manifest = encoded({
        "schemaVersion": 2, "mediaType": build.OCI_MANIFEST,
        "config": {"mediaType": build.OCI_CONFIG, "digest": "sha256:" + config_hex, "size": len(config)},
        "layers": layers,
    })
    manifest_hex = hashlib.sha256(manifest).hexdigest()
    root = {"mediaType": build.OCI_MANIFEST, "digest": "sha256:" + manifest_hex,
            "size": len(manifest) + (1 if wrong_root_size else 0)}
    if wrong_platform:
        root["platform"] = {"os": "linux", "architecture": "arm64"}
    roots = [root]
    if multi_root:
        roots.append({**root, "platform": {"os": "linux", "architecture": "arm64"}})
    index = encoded({"schemaVersion": 2, "mediaType": build.OCI_INDEX, "manifests": roots})
    layer_path = "blobs/sha256/" + layer_hex
    legacy_config = "blobs/sha256/" + (layer_hex if legacy_mismatch else config_hex)
    legacy = encoded([{"Config": legacy_config, "RepoTags": ["fixture:oci"], "Layers": [layer_path, layer_path]}])
    unreferenced = b"valid unreferenced OCI content"
    unreferenced_hex = hashlib.sha256(unreferenced).hexdigest()
    entries = [
        ("oci-layout", encoded({"imageLayoutVersion": "1.0.0"})),
        ("index.json", index), ("manifest.json", legacy),
        ("blobs/sha256/" + manifest_hex, manifest),
        ("blobs/sha256/" + config_hex, config),
        (layer_path, compressed),
        ("blobs/sha256/" + unreferenced_hex, b"corrupt" if corrupt_unreferenced else unreferenced),
    ]
    if duplicate_member:
        entries.append(("index.json", index))
    if traversal:
        entries.append(("../escape", b"not allowed"))
    with tarfile.open(path, "w") as archive:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return "sha256:" + manifest_hex, "sha256:" + config_hex


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, args, timeout=60, data=None):
        self.calls.append(list(args))
        return b""


class ComposePatchTests(unittest.TestCase):
    def test_json_compose_changes_only_owned_center_fields(self):
        original = json.loads(json.dumps(COMPOSE_JSON_OBJECT, ensure_ascii=False))
        patched, removed = deploy.patch_compose(
            json.dumps(original, ensure_ascii=False, separators=(",", ":")),
            "center", "unified@sha256:new",
        )
        actual = json.loads(patched)
        expected = json.loads(json.dumps(original, ensure_ascii=False))
        target = expected["services"]["center"]
        target["image"] = "unified@sha256:new"
        target["environment"]["CENTER_UI_ENABLED"] = "1"
        target["volumes"] = target["volumes"][:3]
        self.assertEqual(actual, expected)
        self.assertEqual(removed, {
            "/node-capability.py": "/release/node-capability.py",
            "/subscription-controller.py": "/release/subscription-controller.py",
            "/healthcheck.sh": "/release/healthcheck.sh",
        })
        self.assertEqual(actual["services"]["unrelated"], original["services"]["unrelated"])
        self.assertEqual(actual["networks"], original["networks"])
        self.assertEqual(actual["x-private-shape"], original["x-private-shape"])

    def test_json_compose_rejects_structured_volume_and_private_override(self):
        structured = json.loads(json.dumps(COMPOSE_JSON_OBJECT))
        structured["services"]["center"]["volumes"][0] = {"type": "bind", "source": "/srv/failover", "target": "/data"}
        with self.assertRaisesRegex(RuntimeError, "structured_or_invalid_mount_requires_review"):
            deploy.patch_compose(json.dumps(structured), "center", "new")
        private = json.loads(json.dumps(COMPOSE_JSON_OBJECT))
        private["services"]["center"]["volumes"].insert(0, "/private/ui:/unified-center:ro")
        with self.assertRaisesRegex(RuntimeError, "private_image_code_override_requires_review"):
            deploy.patch_compose(json.dumps(private), "center", "new")

    def test_only_correct_service_is_patched(self):
        patched, removed = deploy.patch_compose(COMPOSE, "center", "unified@sha256:abc")
        self.assertEqual(set(removed), deploy.MANAGED_CODE_TARGETS)
        self.assertIn("  center:\n    image: unified@sha256:abc\n", patched)
        self.assertIn('CENTER_UI_ENABLED: "1"', patched)
        self.assertIn("./data/failover:/data", patched)
        self.assertIn("/release/Corefile:/etc/coredns/Corefile:ro", patched)
        self.assertIn("  unrelated:\n    image: never/change:1", patched)
        for target in deploy.MANAGED_CODE_TARGETS:
            self.assertNotIn(":" + target + ":ro", patched)

    def test_private_image_override_is_refused(self):
        source = COMPOSE.replace(
            "      - ./data/failover:/data\n",
            "      - ./data/failover:/data\n      - /private/ui:/unified-center:ro\n",
        )
        with self.assertRaisesRegex(RuntimeError, "private_image_code_override_requires_review"):
            deploy.patch_compose(source, "center", "new")

    def test_compose_service_requires_requested_service(self):
        config = {"services": {"center": {"container_name": "clash-center"}}}
        self.assertEqual(deploy.compose_service(config, "center", "clash-center"), config["services"]["center"])
        with self.assertRaisesRegex(RuntimeError, "compose_service_missing"):
            deploy.compose_service(config, "failover", "clash-center")


class BuildContractTests(unittest.TestCase):
    def test_containerd_oci_archive_uses_unique_root_manifest_as_image_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "oci.tar"
            image_id, config_id = make_oci_archive(archive)
            self.assertNotEqual(image_id, config_id)
            build.validate_docker_archive(archive, image_id)

    def test_oci_archive_rejects_multiple_roots_and_hidden_blob_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            multi = root / "multi.tar"
            image_id, _ = make_oci_archive(multi, multi_root=True)
            with self.assertRaisesRegex(RuntimeError, "docker_archive_oci_root_count_invalid"):
                build.validate_docker_archive(multi, image_id)
            corrupt = root / "corrupt.tar"
            image_id, _ = make_oci_archive(corrupt, corrupt_unreferenced=True)
            with self.assertRaisesRegex(RuntimeError, "docker_archive_blob_digest_mismatch"):
                build.validate_docker_archive(corrupt, image_id)
            platform = root / "platform.tar"
            image_id, _ = make_oci_archive(platform, wrong_platform=True)
            with self.assertRaisesRegex(RuntimeError, "docker_archive_oci_platform_invalid"):
                build.validate_docker_archive(platform, image_id)
            size = root / "size.tar"
            image_id, _ = make_oci_archive(size, wrong_root_size=True)
            with self.assertRaisesRegex(RuntimeError, "docker_archive_descriptor_size_mismatch"):
                build.validate_docker_archive(size, image_id)

    def test_oci_archive_rejects_duplicate_traversal_and_legacy_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.tar"
            image_id, _ = make_oci_archive(duplicate, duplicate_member=True)
            with self.assertRaisesRegex(RuntimeError, "duplicate_docker_archive_member"):
                build.validate_docker_archive(duplicate, image_id)
            traversal = root / "traversal.tar"
            image_id, _ = make_oci_archive(traversal, traversal=True)
            with self.assertRaisesRegex(RuntimeError, "unsafe_docker_archive_member"):
                build.validate_docker_archive(traversal, image_id)
            mismatch = root / "legacy-mismatch.tar"
            image_id, _ = make_oci_archive(mismatch, legacy_mismatch=True)
            with self.assertRaisesRegex(RuntimeError, "docker_archive_legacy_config_mismatch"):
                build.validate_docker_archive(mismatch, image_id)

    def test_rootfs_lineage_accepts_complete_audited_base_prefix(self):
        base = {"Id": deploy.BASE_IMAGE_ID, "RootFS": {"Type": "layers", "Layers": ["sha256:a", "sha256:b"]}}
        image = {
            "Config": {"Labels": {
                "io.jydn.clash-center.base-image": deploy.BASE_IMAGE_ID,
                "io.jydn.clash-center.build-method": "docker-build-offline-increment",
            }},
            "RootFS": {"Type": "layers", "Layers": ["sha256:a", "sha256:b", "sha256:new"]},
        }
        deploy.validate_image_lineage(image, base, {"base_image_id": deploy.BASE_IMAGE_ID})

    def test_spoofed_base_label_cannot_replace_rootfs_lineage(self):
        base = {"Id": deploy.BASE_IMAGE_ID, "RootFS": {"Type": "layers", "Layers": ["sha256:a", "sha256:b"]}}
        spoofed = {
            "Config": {"Labels": {
                "io.jydn.clash-center.base-image": deploy.BASE_IMAGE_ID,
                "io.jydn.clash-center.build-method": "docker-build-offline-increment",
            }},
            "RootFS": {"Type": "layers", "Layers": ["sha256:fake", "sha256:b", "sha256:new"]},
        }
        with self.assertRaisesRegex(RuntimeError, "new_image_base_rootfs_prefix_mismatch"):
            deploy.validate_image_lineage(spoofed, base, {"base_image_id": deploy.BASE_IMAGE_ID})

    def test_context_and_bundle_are_manifested_without_source_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = root / "context"
            result = build.build_context(context, "test-version", "test-commit")
            self.assertEqual(result["base_image_id"], build.BASE_IMAGE)
            self.assertFalse(result["contains_production_data"])
            self.assertFalse(any("__pycache__" in path.parts or path.name.startswith("test_") for path in context.rglob("*")))
            self.assertIn("FROM ${BASE_IMAGE}", (context / "Dockerfile").read_text(encoding="utf-8"))
            self.assertNotIn("docker commit", (context / "Dockerfile").read_text(encoding="utf-8").lower())

            config = b'{"architecture":"amd64","os":"linux"}'
            image_hex = hashlib.sha256(config).hexdigest()
            image_archive = root / "image.tar"
            with tarfile.open(image_archive, "w") as archive:
                for name, payload in (
                    (image_hex + ".json", config),
                    ("layer/layer.tar", b"empty-layer"),
                    ("manifest.json", json.dumps([{
                        "Config": image_hex + ".json", "RepoTags": ["unified:test"],
                        "Layers": ["layer/layer.tar"],
                    }]).encode()),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            packaged = build.bundle(context, image_archive, "sha256:" + image_hex, root / "bundle", "test-version")
            self.assertEqual(packaged["manifest"]["image_id"], "sha256:" + image_hex)
            self.assertTrue((root / "bundle/manifest.json").is_file())
            self.assertTrue((root / "bundle.tar.gz").is_file())


class BackupTests(unittest.TestCase):
    def test_online_sqlite_backup_and_private_file_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "live", root / "backup"
            source.mkdir()
            database = source / "kuma.db"
            with contextlib.closing(sqlite3.connect(database)) as db:
                db.execute("create table monitor(id integer primary key, name text)")
                db.execute("insert into monitor(name) values ('real-row')")
                db.commit()
            (source / "private.json").write_text('{"secret":"not printed"}', encoding="utf-8")
            receipt = deploy.snapshot_bind(source, target)
            deploy.verify_snapshot(receipt, target)
            self.assertEqual(receipt["databases"]["kuma.db"]["integrity"], "ok")
            with contextlib.closing(sqlite3.connect(target / "kuma.db")) as db:
                self.assertEqual(db.execute("select name from monitor").fetchone()[0], "real-row")

    def test_corrupt_backup_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "live", root / "backup"
            source.mkdir()
            (source / "private.json").write_text("original", encoding="utf-8")
            receipt = deploy.snapshot_bind(source, target)
            (target / "private.json").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "private_backup_checksum_failed"):
                deploy.verify_snapshot(receipt, target)

    def test_overlay_uses_renamed_subscription_implementation(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            health = data / "node-health/code"
            usage = data / "subscription-usage/code"
            health.mkdir(parents=True)
            usage.mkdir(parents=True)
            implementation = b"accepted implementation\n"
            metadata = b"accepted metadata\n"
            (health / "subscription_impl.py").write_bytes(implementation.replace(b"\n", b"\r\n"))
            (usage / "subscription_usage.py").write_bytes(metadata.replace(b"\n", b"\r\n"))
            manifest = {
                "runtime/upstream/subscription-controller.py": __import__("hashlib").sha256(implementation).hexdigest(),
                "local-subscription/subscription_usage.py": __import__("hashlib").sha256(metadata).hexdigest(),
            }
            result = deploy.verify_overlays(data, manifest)
            self.assertIn("node-health/code/subscription_impl.py", result)
            detail = result["node-health/code/subscription_impl.py"]
            self.assertNotEqual(detail["raw_sha256"], detail["normalized_source_sha256"])


class ApplyRollbackIsolationTests(unittest.TestCase):
    def transaction(self, root):
        compose = root / "docker-compose.yml"
        compose.write_text(COMPOSE, encoding="utf-8")
        backup = root / "backups/tx"
        backup.mkdir(parents=True)
        (backup / "compose.before.yml").write_text(COMPOSE, encoding="utf-8")
        legacy_path = root / "legacy-state.json"
        legacy = {
            "container_name": "clash-center", "container_id": "old-id",
            "manifest": {"image_id": "old-image-id"},
        }
        legacy_bytes = deploy.encoded_json(legacy)
        legacy_path.write_bytes(legacy_bytes)
        (backup / "legacy-state.before.json").write_bytes(legacy_bytes)
        transaction = {
            "schema": 1,
            "id": "tx",
            "phase": "prepared",
            "compose_path": str(compose),
            "compose_before_sha256": deploy.sha256(compose),
            "service": "center",
            "container_name": "clash-center",
            "old_container": {"id": "old-id", "image": "old-image-id"},
            "new_image": "unified:1",
            "new_image_id": "new-image-id",
            "manifest": {"image_id": "new-image-id", "context_files": {}},
            "backup": str(backup),
            "managed_mounts": deploy.normalized_mounts({
                "/node-capability.py": "/release/node-capability.py",
                "/subscription-controller.py": "/release/subscription-controller.py",
                "/healthcheck.sh": "/release/healthcheck.sh",
            }, compose.parent),
            "data_mounts": {},
            "other_containers": {"other": {"id": "other-id"}},
            "guard_timeout_seconds": 900,
            "legacy_state": {
                "path": str(legacy_path),
                "before_sha256": hashlib.sha256(legacy_bytes).hexdigest(),
                "before_container_id": "old-id", "before_image_id": "old-image-id",
            },
            "unified_state_before": {"existed": False, "sha256": None},
        }
        write_json(root / "transaction.json", transaction)
        return transaction, compose, backup

    def accept_fixture(self, root):
        transaction, compose, backup = self.transaction(root)
        patched, _ = deploy.patch_compose(COMPOSE, "center", "unified:1")
        compose.write_text(patched, encoding="utf-8")
        transaction.update(
            phase="verified", compose_after_sha256=deploy.sha256(compose),
            new_container_id="new-id",
        )
        write_json(root / "transaction.json", transaction)
        with mock.patch.object(deploy, "inspect_object", return_value={"Id": "new-id", "Image": "new-image-id"}):
            result = deploy.accept({}, root)
        return result, transaction, compose, backup

    def test_apply_recreates_only_requested_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            runner = FakeRunner()
            old = {"Id": "old-id", "Image": "old-image-id"}
            new = {"Id": "new-id", "Image": "new-image-id"}
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[old, new]), \
                 mock.patch.object(deploy, "start_guard", return_value="guard-tx"):
                result = deploy.apply({}, root)
            self.assertEqual(result["phase"], "applied")
            compose_calls = [call for call in runner.calls if call[:2] == ["docker", "compose"]]
            self.assertEqual(len(compose_calls), 1)
            command = compose_calls[0]
            self.assertEqual(command[-1], "center")
            self.assertIn("--no-deps", command)
            self.assertNotIn("down", command)
            self.assertNotIn("/node-capability.py", compose.read_text(encoding="utf-8"))

    def test_rollback_refuses_concurrent_compose_edit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            transaction.update(phase="applied", compose_after_sha256="owned-after", new_container_id="new-id")
            write_json(root / "transaction.json", transaction)
            compose.write_text(COMPOSE + "# human change\n", encoding="utf-8")
            runner = FakeRunner()
            with mock.patch.object(deploy, "RUNNER", runner):
                with self.assertRaisesRegex(RuntimeError, "concurrent_compose_edit_restore_refused"):
                    deploy.rollback({"transaction": "tx"}, root)
            self.assertEqual(runner.calls, [])
            self.assertTrue((Path(transaction["backup"]) / "rollback-refused.json").is_file())

    def test_rollback_refuses_concurrent_container_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            transaction.update(
                phase="applied", compose_after_sha256=deploy.sha256(compose),
                new_container_id="owned-new-id",
            )
            write_json(root / "transaction.json", transaction)
            with mock.patch.object(deploy, "inspect_object", return_value={"Id": "human-new-id"}):
                with self.assertRaisesRegex(RuntimeError, "concurrent_container_change_restore_refused"):
                    deploy.rollback({"transaction": "tx"}, root)

    def test_rollback_restores_compose_and_old_image_without_database_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, backup = self.transaction(root)
            patched, _ = deploy.patch_compose(COMPOSE, "center", "unified:1")
            compose.write_text(patched, encoding="utf-8")
            transaction.update(
                phase="applied", compose_after_sha256=deploy.sha256(compose),
                new_container_id="new-id", guard_unit="guard-tx",
            )
            write_json(root / "transaction.json", transaction)
            runner = FakeRunner()
            current = {"Id": "new-id", "Image": "new-image-id"}
            restored = {"Id": "restored-id", "Image": "old-image-id"}
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[current, restored]), \
                 mock.patch.object(deploy, "all_container_shapes", return_value={
                     "clash-center": {"id": "restored-id"}, "other": {"id": "other-id"}
                 }):
                result = deploy.rollback({"transaction": "tx"}, root)
            self.assertTrue(result["restored"])
            self.assertFalse(result["data_restored"])
            self.assertEqual(compose.read_text(encoding="utf-8"), COMPOSE)
            command = next(call for call in runner.calls if call[:2] == ["docker", "compose"])
            self.assertEqual(command[-1], "center")
            self.assertNotIn("down", command)
            self.assertFalse((root / "transaction.json").exists())
            self.assertTrue((backup / "rollback-result.json").is_file())

    def test_guard_recovers_when_compose_recreate_was_interrupted_without_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            patched, _ = deploy.patch_compose(COMPOSE, "center", "unified:1")
            compose.write_text(patched, encoding="utf-8")
            transaction.update(phase="applying", compose_after_sha256=deploy.sha256(compose))
            write_json(root / "transaction.json", transaction)
            runner = FakeRunner()
            restored = {"Id": "restored-id", "Image": "old-image-id"}
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[
                     RuntimeError("command_failed:docker:1"), restored
                 ]), \
                 mock.patch.object(deploy, "all_container_shapes", return_value={
                     "clash-center": {"id": "restored-id"}, "other": {"id": "other-id"}
                 }):
                result = deploy.rollback({"transaction": "tx"}, root, guard=True)
            self.assertTrue(result["restored"])
            self.assertEqual(result["trigger"], "guard")

    def test_accept_synchronizes_legacy_watchdog_identity_and_disables_code_overlays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, transaction, _, backup = self.accept_fixture(root)
            self.assertEqual(result["phase"], "accepted")
            legacy = json.loads(Path(transaction["legacy_state"]["path"]).read_text(encoding="utf-8"))
            self.assertEqual(legacy["container_id"], "new-id")
            self.assertEqual(legacy["manifest"]["image_id"], "new-image-id")
            self.assertFalse(legacy["unified_image"]["managed_code_overlays"])
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertTrue(state["legacy_watchdog_identity_synchronized"])
            self.assertFalse(state["managed_code_overlays"])
            saved = json.loads((backup / "transaction.private.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["phase"], "accepted")

    def test_accepted_manual_rollback_restores_old_image_and_live_watchdog_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, transaction, compose, backup = self.accept_fixture(root)
            # A stale guard must never undo an accepted release.
            guard_result = deploy.rollback({"transaction": "tx"}, root, guard=True)
            self.assertEqual(guard_result["reason"], "no_pending_transaction")
            self.assertIn("unified:1", compose.read_text(encoding="utf-8"))

            runner = FakeRunner()
            current = {"Id": "new-id", "Image": "new-image-id"}
            restored = {"Id": "restored-live-id", "Image": "old-image-id"}
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[current, restored]), \
                 mock.patch.object(deploy, "all_container_shapes", return_value={
                     "clash-center": {"id": "restored-live-id"}, "other": {"id": "other-id"}
                 }):
                result = deploy.rollback({"transaction": "tx"}, root)
            self.assertTrue(result["restored"])
            self.assertFalse(result["data_restored"])
            self.assertEqual(compose.read_text(encoding="utf-8"), COMPOSE)
            legacy = json.loads(Path(transaction["legacy_state"]["path"]).read_text(encoding="utf-8"))
            self.assertEqual(legacy["container_id"], "restored-live-id")
            self.assertEqual(legacy["manifest"]["image_id"], "old-image-id")
            self.assertNotIn("unified_image", legacy)
            self.assertFalse((root / "state.json").exists())
            receipt = json.loads((backup / "rollback-result.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["data_policy"], "retained_new_history_and_live_databases")

    def test_accepted_rollback_refuses_concurrent_legacy_state_edit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, transaction, _, _ = self.accept_fixture(root)
            legacy_path = Path(transaction["legacy_state"]["path"])
            legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
            legacy["human_note"] = "must not be overwritten"
            legacy_path.write_bytes(deploy.encoded_json(legacy))
            runner = FakeRunner()
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", return_value={"Id": "new-id", "Image": "new-image-id"}):
                with self.assertRaisesRegex(RuntimeError, "legacy_installer_state_concurrent_edit_refused"):
                    deploy.rollback({"transaction": "tx"}, root)
            self.assertEqual(runner.calls, [])
            self.assertEqual(json.loads(legacy_path.read_text(encoding="utf-8"))["human_note"], "must not be overwritten")


if __name__ == "__main__":
    unittest.main()
