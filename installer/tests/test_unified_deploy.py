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
      ADMISSION_NATIVE_SSH: "1"
    ports:
      - 3101:3001
      - 3102:8081
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
            "environment": {"EXISTING": "kept", "CENTER_UI_ENABLED": "0", "ADMISSION_NATIVE_SSH": "1"},
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
    def test_future_image_upgrade_preserves_already_absent_kuma_port(self):
        source = COMPOSE.replace("      - 3101:3001\n", "")
        patched, removed = deploy.patch_compose(
            source, "center", "unified:next", "/srv/dns-management/coredns",
            remove_kuma_port=False, admission_native_ssh="0",
        )
        self.assertNotIn("3101:3001", patched)
        self.assertIn("3102:8081", patched)
        self.assertIn('ADMISSION_NATIVE_SSH: "0"', patched)
        self.assertEqual(set(removed), deploy.MANAGED_CODE_TARGETS)

    def test_image_upgrade_replaces_dns_directory_and_removes_only_kuma_port(self):
        source = json.loads(json.dumps(COMPOSE_JSON_OBJECT))
        source["services"]["center"]["volumes"] = [
            item for item in source["services"]["center"]["volumes"]
            if deploy.parse_short_mount(item)[1] not in deploy.MANAGED_CODE_TARGETS
        ]
        patched, removed = deploy.patch_compose(
            json.dumps(source), "center", "unified:0.3", "/srv/failover/dns-management/coredns",
            remove_kuma_port=True,
        )
        center = json.loads(patched)["services"]["center"]
        self.assertEqual(removed, {})
        self.assertNotIn("3101:3001", center["ports"])
        self.assertIn("3102:8081", center["ports"])
        self.assertIn("/srv/failover/dns-management/coredns:/etc/coredns:rw", center["volumes"])
        self.assertFalse(any("/etc/coredns/Corefile" in item for item in center["volumes"]))

    def test_partial_legacy_mount_set_is_refused(self):
        source = json.loads(json.dumps(COMPOSE_JSON_OBJECT))
        source["services"]["center"]["volumes"] = [
            item for item in source["services"]["center"]["volumes"]
            if "/healthcheck.sh:" not in item
        ]
        with self.assertRaisesRegex(RuntimeError, "managed_code_mount_set_changed"):
            deploy.patch_compose(json.dumps(source), "center", "new")

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

    def test_yaml_dns_and_port_transition_is_exact(self):
        patched, _ = deploy.patch_compose(
            COMPOSE, "center", "unified:0.3", "/srv/failover/dns-management/coredns",
            remove_kuma_port=True,
        )
        self.assertNotIn("- 3101:3001", patched)
        self.assertIn("- 3102:8081", patched)
        self.assertIn("/srv/failover/dns-management/coredns:/etc/coredns:rw", patched)

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
    def test_context_archive_is_independent_of_output_filename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "runtime.py").write_text("print('fixed')\n", encoding="utf-8")
            first, second = root / "first-name.tar.gz", root / "second-name.tar.gz"
            build.deterministic_tar(source, first)
            build.deterministic_tar(source, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_runtime_contract_excludes_only_explicit_managed_environment(self):
        base = {"Config": {"Env": ["KEEP=1", "CENTER_UI_ENABLED=1"]}, "HostConfig": {}}
        upgraded = {"Config": {"Env": [
            "KEEP=1", "CENTER_UI_ENABLED=1",
            "ADMISSION_CORE=/local-subscription/core",
            "ADMISSION_CORE_PIN=/local-subscription/core.sha256",
        ]}, "HostConfig": {}}
        self.assertEqual(deploy.stable_runtime(base), deploy.stable_runtime(upgraded))
        changed = {"Config": {"Env": upgraded["Config"]["Env"] + ["UNOWNED=changed"]}, "HostConfig": {}}
        self.assertNotEqual(deploy.stable_runtime(base), deploy.stable_runtime(changed))

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
            self.assertTrue((context / "unified-center/extensions/subscription_lifecycle.py").is_file())
            self.assertTrue((context / "unified-center/dns_validator.py").is_file())
            self.assertEqual(result["runtime_code_policy"], "image_only")
            self.assertIn("FROM ${BASE_IMAGE}", (context / "Dockerfile").read_text(encoding="utf-8"))
            dockerfile = (context / "Dockerfile").read_text(encoding="utf-8")
            self.assertNotIn("docker commit", dockerfile.lower())
            self.assertIn("ADMISSION_CORE=/local-subscription/core", dockerfile)
            self.assertIn("ADMISSION_CORE_PIN=/local-subscription/core.sha256", dockerfile)

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
    def test_kuma_native_probe_requires_safe_ready_summary(self):
        class Runner:
            def __init__(self, value): self.value = value
            def run(self, args, timeout=60, data=None):
                self.args, self.timeout = args, timeout
                return json.dumps(self.value).encode()

        ready = {
            "state": "ok", "revision": "a" * 64, "monitors": 3,
            "notifications": 0, "credential_file": "root-0600-regular",
        }
        runner = Runner(ready)
        with mock.patch.object(deploy, "RUNNER", runner):
            self.assertEqual(deploy.verify_kuma_native_runtime("clash-center")["monitors"], 3)
        self.assertEqual(runner.args[:3], ["docker", "exec", "clash-center"])
        self.assertEqual(runner.timeout, 35)

        for invalid in (
            dict(ready, monitors=0), dict(ready, revision="bad"),
            dict(ready, credential_file="unknown"),
        ):
            with mock.patch.object(deploy, "RUNNER", Runner(invalid)):
                with self.assertRaisesRegex(RuntimeError, "kuma_native_runtime_probe_invalid"):
                    deploy.verify_kuma_native_runtime("clash-center")

    def test_overview_probe_requires_production_dns_kuma_and_clash_ok(self):
        class Response:
            status = 200
            def __init__(self, payload): self.payload = payload
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _limit): return json.dumps(self.payload).encode()
        class Opener:
            def __init__(self, payload): self.payload = payload
            def open(self, _url, timeout=8): return Response(self.payload)
        payload = {"schema": 1, "environment": "production", "services": [
            {"id": "kuma", "state": "ok"}, {"id": "dns", "state": "ok"},
            {"id": "clash", "state": "ok"},
        ]}
        url = "http://10.88.0.249:3103/api/center/overview"
        with mock.patch.object(deploy.urllib.request, "build_opener", return_value=Opener(payload)):
            self.assertEqual(deploy.verify_http_probes([url])[0]["status"], "ok")
        payload["services"][0]["state"] = "error"
        with mock.patch.object(deploy.urllib.request, "build_opener", return_value=Opener(payload)):
            with self.assertRaisesRegex(RuntimeError, "unified_overview_critical_service_unhealthy"):
                deploy.verify_http_probes([url])

    def test_dns_mount_transition_requires_absent_managed_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.mkdir()
            corefile = root / "Corefile"
            corefile.write_text(".:53 { reload }\n", encoding="utf-8")
            expected = {"corefile_source": str(corefile), "dns_corefile_sha256": deploy.sha256(corefile)}
            mounts = [{"Type": "bind", "Source": str(corefile),
                       "Destination": deploy.DNS_FILE_TARGET, "RW": False}]
            plan = deploy.dns_mount_plan(data, mounts, expected)
            self.assertEqual(plan["mode"], "readonly_file_to_managed_directory")
            (data / deploy.DNS_MANAGED_RELATIVE).mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "dns_managed_directory_preexists_requires_review"):
                deploy.dns_mount_plan(data, mounts, expected)

    def test_dns_directory_stage_copies_complete_layout_and_preserves_hash(self):
        class CopyRunner:
            def __init__(self, payload):
                self.payload = payload
                self.calls = []

            def run(self, args, timeout=60, data=None):
                self.calls.append(list(args))
                destination = Path(args[-1])
                (destination / "Corefile").write_bytes(self.payload)
                return b""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b".:53 {\n  reload\n}\n"
            digest = hashlib.sha256(payload).hexdigest()
            target = root / "data/dns-management/coredns"
            transaction = {
                "container_name": "clash-center",
                "dns_config": {
                    "mode": "readonly_file_to_managed_directory",
                    "managed_source": str(target), "corefile_sha256": digest,
                    "layout": {"files": {"Corefile": digest}, "total_bytes": len(payload),
                               "corefile_sha256": digest},
                },
            }
            runner = CopyRunner(payload)
            with mock.patch.object(deploy, "RUNNER", runner):
                layout = deploy.stage_dns_directory(transaction)
            self.assertEqual(layout["corefile_sha256"], digest)
            self.assertEqual((target / "Corefile").read_bytes(), payload)
            self.assertEqual(runner.calls[0][:2], ["docker", "cp"])

    def test_unaccepted_owned_dns_stage_is_removed_for_safe_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "data/dns-management/coredns"
            target.mkdir(parents=True)
            (target / "Corefile").write_text(".:53 { reload }\n", encoding="utf-8")
            layout = deploy.validate_dns_directory(target)
            result = deploy.cleanup_unaccepted_dns_stage({"dns_config": {
                "mode": "readonly_file_to_managed_directory",
                "managed_source": str(target), "layout": layout,
            }})
            self.assertTrue(result["removed"])
            self.assertFalse(target.exists())

    def test_private_subscription_override_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source-overrides.json"
            path.write_text('{"schema":1}', encoding="utf-8")
            identity = deploy.optional_private_file_identity(path)
            deploy.verify_optional_private_file_identity(identity)
            path.write_text('{"schema":1,"changed":true}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "subscription_override_changed_during_unaccepted_deployment"):
                deploy.verify_optional_private_file_identity(identity)

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
    @staticmethod
    def restored_container(identifier="restored-id"):
        return {
            "Id": identifier, "Image": "old-image-id", "Mounts": [],
            "Config": {"Env": ["ADMISSION_NATIVE_SSH=1"]},
            "HostConfig": {
                "PortBindings": {"3001/tcp": [{"HostIp": "", "HostPort": "3101"}]},
                "NetworkMode": None, "RestartPolicy": {},
            },
        }

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
        dns_root = root / "data/dns-management/coredns"
        dns_root.mkdir(parents=True)
        (dns_root / "Corefile").write_text(".:53 {\n  reload\n}\n", encoding="utf-8")
        dns_layout = deploy.validate_dns_directory(dns_root)
        planned, _ = deploy.patch_compose(
            COMPOSE, "center", "unified:1", str(dns_root), remove_kuma_port=True,
            admission_native_ssh="0",
        )
        transaction = {
            "schema": 2,
            "id": "tx",
            "phase": "prepared",
            "compose_path": str(compose),
            "compose_before_sha256": deploy.sha256(compose),
            "service": "center",
            "container_name": "clash-center",
            "old_container": {"id": "old-id", "image": "old-image-id"},
            "old_image": "old/image:1",
            "old_admission_native_ssh": "1",
            "old_kuma_port_published": True,
            "new_image": "unified:1",
            "new_image_id": "new-image-id",
            "manifest": {"image_id": "new-image-id", "context_files": {}},
            "backup": str(backup),
            "managed_mounts": deploy.normalized_mounts({
                "/node-capability.py": "/release/node-capability.py",
                "/subscription-controller.py": "/release/subscription-controller.py",
                "/healthcheck.sh": "/release/healthcheck.sh",
            }, compose.parent),
            "old_runtime": {
                "ports": {}, "network_mode": None, "restart_policy": {},
                "environment_without_center_flag": [], "mounts": [],
            },
            "deployment_mode": "legacy_bind_migration",
            "subscription_override": deploy.optional_private_file_identity(
                root / "data/subscription-usage/source-overrides.json"
            ),
            "dns_config": {
                "mode": "managed_directory", "old_source": str(dns_root),
                "old_destination": deploy.DNS_DIRECTORY_TARGET, "old_rw": True,
                "managed_source": str(dns_root),
                "corefile_sha256": dns_layout["corefile_sha256"], "layout": dns_layout,
            },
            "planned_compose_sha256": hashlib.sha256(planned.encode()).hexdigest(),
            "removed_port": {"container": deploy.KUMA_CONTAINER_PORT, "host": deploy.KUMA_HOST_PORT},
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
        patched, _ = deploy.patch_compose(
            COMPOSE, "center", "unified:1", transaction["dns_config"]["managed_source"],
            remove_kuma_port=True, admission_native_ssh="0",
        )
        compose.write_text(patched, encoding="utf-8")
        transaction.update(
            phase="verified", compose_after_sha256=deploy.sha256(compose),
            new_container_id="new-id",
        )
        write_json(root / "transaction.json", transaction)
        with mock.patch.object(deploy, "inspect_object", return_value={"Id": "new-id", "Image": "new-image-id"}), \
             mock.patch.object(deploy, "critical_runtime_gate", return_value={}):
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

    def test_accept_refuses_runtime_drift_before_guard_is_cancelled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            patched, _ = deploy.patch_compose(
                COMPOSE, "center", "unified:1", transaction["dns_config"]["managed_source"],
                remove_kuma_port=True, admission_native_ssh="0",
            )
            compose.write_text(patched, encoding="utf-8")
            transaction.update(phase="verified", compose_after_sha256=deploy.sha256(compose),
                               new_container_id="new-id", verification={"probes": []})
            write_json(root / "transaction.json", transaction)
            with mock.patch.object(deploy, "inspect_object", return_value={"Id": "new-id"}), \
                 mock.patch.object(deploy, "critical_runtime_gate", side_effect=RuntimeError("new_container_not_running")), \
                 mock.patch.object(deploy, "cancel_guard") as cancel:
                with self.assertRaisesRegex(RuntimeError, "new_container_not_running"):
                    deploy.accept({}, root)
            cancel.assert_not_called()
            self.assertTrue((root / "transaction.json").is_file())

    def test_accept_refuses_subscription_override_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            patched, _ = deploy.patch_compose(
                COMPOSE, "center", "unified:1", transaction["dns_config"]["managed_source"],
                remove_kuma_port=True, admission_native_ssh="0",
            )
            compose.write_text(patched, encoding="utf-8")
            transaction.update(phase="verified", compose_after_sha256=deploy.sha256(compose),
                               new_container_id="new-id", verification={"probes": []})
            write_json(root / "transaction.json", transaction)
            override = Path(transaction["subscription_override"]["path"])
            override.parent.mkdir(parents=True, exist_ok=True)
            override.write_text('{"schema":1,"sources":[]}', encoding="utf-8")
            with mock.patch.object(deploy, "inspect_object", return_value={"Id": "new-id"}), \
                 mock.patch.object(deploy, "critical_runtime_gate", return_value={}), \
                 mock.patch.object(deploy, "cancel_guard") as cancel:
                with self.assertRaisesRegex(RuntimeError, "subscription_override_changed_during_unaccepted_deployment"):
                    deploy.accept({}, root)
            cancel.assert_not_called()

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
            override = Path(transaction["subscription_override"]["path"])
            override.parent.mkdir(parents=True, exist_ok=True)
            override.write_text('{"schema":1,"sources":[]}', encoding="utf-8")
            runner = FakeRunner()
            current = {"Id": "new-id", "Image": "new-image-id"}
            restored = self.restored_container()
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[current, restored]), \
                 mock.patch.object(deploy, "all_container_shapes", return_value={
                     "clash-center": {"id": "restored-id"}, "other": {"id": "other-id"}
                 }):
                result = deploy.rollback({"transaction": "tx"}, root)
            self.assertTrue(result["restored"])
            self.assertFalse(result["data_restored"])
            self.assertTrue(result["subscription_override_drift"])
            self.assertTrue(result["live_subscription_override_preserved"])
            self.assertTrue(override.is_file())
            self.assertEqual(compose.read_text(encoding="utf-8"), COMPOSE)
            command = next(call for call in runner.calls if call[:2] == ["docker", "compose"])
            self.assertEqual(command[-1], "center")
            self.assertNotIn("down", command)
            self.assertFalse((root / "transaction.json").exists())
            self.assertTrue((backup / "rollback-result.json").is_file())

    def test_future_upgrade_rollback_preserves_absent_kuma_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, backup = self.transaction(root)
            before = COMPOSE.replace("      - 3101:3001\n", "")
            compose.write_text(before, encoding="utf-8")
            (backup / "compose.before.yml").write_text(before, encoding="utf-8")
            transaction["compose_before_sha256"] = deploy.sha256(compose)
            transaction["old_kuma_port_published"] = False
            after, _ = deploy.patch_compose(
                before, "center", "unified:1", transaction["dns_config"]["managed_source"],
                remove_kuma_port=False, admission_native_ssh="0",
            )
            compose.write_text(after, encoding="utf-8")
            transaction.update(
                phase="applied", compose_after_sha256=deploy.sha256(compose),
                planned_compose_sha256=deploy.sha256(compose), new_container_id="new-id",
            )
            write_json(root / "transaction.json", transaction)
            restored = self.restored_container()
            restored["HostConfig"]["PortBindings"] = {}
            with mock.patch.object(deploy, "RUNNER", FakeRunner()), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[
                     {"Id": "new-id", "Image": "new-image-id"}, restored,
                 ]), \
                 mock.patch.object(deploy, "all_container_shapes", return_value={
                     "clash-center": {"id": "restored-id"}, "other": {"id": "other-id"},
                 }):
                result = deploy.rollback({"transaction": "tx"}, root)
            self.assertTrue(result["restored"])
            self.assertNotIn("3101:3001", compose.read_text(encoding="utf-8"))
            self.assertIn("3102:8081", compose.read_text(encoding="utf-8"))

    def test_guard_recovers_when_compose_recreate_was_interrupted_without_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, _ = self.transaction(root)
            patched, _ = deploy.patch_compose(COMPOSE, "center", "unified:1")
            compose.write_text(patched, encoding="utf-8")
            transaction.update(phase="applying", compose_after_sha256=deploy.sha256(compose))
            write_json(root / "transaction.json", transaction)
            runner = FakeRunner()
            restored = self.restored_container()
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
            restored = self.restored_container("restored-live-id")
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

    def test_accepted_image_upgrade_rollback_preserves_live_managed_dns(self):
        class DigestRunner(FakeRunner):
            def __init__(self, digest):
                super().__init__()
                self.digest = digest

            def run(self, args, timeout=60, data=None):
                self.calls.append(list(args))
                if args[:3] == ["docker", "exec", "clash-center"] and "sha256sum" in args:
                    return (self.digest + "  /etc/coredns/Corefile\n").encode()
                return b""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transaction, compose, backup = self.transaction(root)
            before, removed = deploy.patch_compose(COMPOSE, "center", "old/image:1")
            self.assertEqual(set(removed), deploy.MANAGED_CODE_TARGETS)
            compose.write_text(before, encoding="utf-8")
            (backup / "compose.before.yml").write_text(before, encoding="utf-8")
            transaction["compose_before_sha256"] = deploy.sha256(compose)
            transaction["managed_mounts"] = {}
            transaction["deployment_mode"] = "unified_image_upgrade"
            prior_state = {
                "schema": 1, "kind": "unified-center-installation", "transaction": "prior",
                "container_name": "clash-center", "container_id": "old-id",
                "image": "old/image:1", "image_id": "old-image-id",
                "compose_sha256": transaction["compose_before_sha256"],
            }
            prior_bytes = deploy.encoded_json(prior_state)
            (root / "state.json").write_bytes(prior_bytes)
            (backup / "unified-state.before.json").write_bytes(prior_bytes)
            transaction["unified_state_before"] = {
                "existed": True, "sha256": hashlib.sha256(prior_bytes).hexdigest(),
            }
            after, _ = deploy.patch_compose(
                before, "center", "unified:1", transaction["dns_config"]["managed_source"],
                remove_kuma_port=True, admission_native_ssh="0",
            )
            compose.write_text(after, encoding="utf-8")
            transaction.update(phase="verified", compose_after_sha256=deploy.sha256(compose),
                               new_container_id="new-id")
            write_json(root / "transaction.json", transaction)
            with mock.patch.object(deploy, "inspect_object", return_value={"Id": "new-id", "Image": "new-image-id"}), \
                 mock.patch.object(deploy, "critical_runtime_gate", return_value={}):
                deploy.accept({}, root)

            corefile = Path(transaction["dns_config"]["managed_source"]) / "Corefile"
            corefile.write_text(".:53 {\n  reload 5s\n}\n", encoding="utf-8")
            live_digest = deploy.sha256(corefile)
            current = {"Id": "new-id", "Image": "new-image-id"}
            restored = self.restored_container("restored-live-id")
            restored["Mounts"] = [{
                "Type": "bind", "Source": transaction["dns_config"]["managed_source"],
                "Destination": deploy.DNS_DIRECTORY_TARGET, "RW": True,
            }]
            runner = DigestRunner(live_digest)
            with mock.patch.object(deploy, "RUNNER", runner), \
                 mock.patch.object(deploy, "inspect_object", side_effect=[current, restored]), \
                 mock.patch.object(deploy, "all_container_shapes", return_value={
                     "clash-center": {"id": "restored-live-id"}, "other": {"id": "other-id"}
                 }):
                result = deploy.rollback({"transaction": "tx"}, root)
            self.assertTrue(result["managed_dns_preserved"])
            self.assertEqual(deploy.sha256(corefile), live_digest)
            self.assertIn(transaction["dns_config"]["managed_source"] + ":/etc/coredns:rw",
                          compose.read_text(encoding="utf-8"))
            self.assertIn("3101:3001", compose.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
