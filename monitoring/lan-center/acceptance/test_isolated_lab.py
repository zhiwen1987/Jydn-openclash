import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import yaml

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("isolated_lab", HERE / "isolated_lab.py")
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)


class IsolatedLabTests(unittest.TestCase):
    def fixture(self, root: Path, *, candidate=False) -> Path:
        value = root / "input"
        (value / "control" / "unified").mkdir(parents=True)
        (value / "control" / "local-source").mkdir(parents=True)
        (value / "control" / "subscription-controller").mkdir(parents=True)
        (value / "kuma").mkdir(parents=True)
        (value / "coredns").mkdir()
        (value / "router" / "providers").mkdir(parents=True)
        for relative, payload in {
            "kuma/kuma.db": b"fixture",
            "control/unified/kuma-bridge.jwt": b"fixture-token",
            "control/local-source/admin-token": b"fixture-admin",
            "control/subscription-controller/current.json": b'{"release_id":"fixture"}',
            "coredns/Corefile": b'.:53 {\n forward . 127.0.0.1:1153\n}\n',
            "coredns/Corefile.managed": b'forward . 127.0.0.1:1153\n',
            "coredns/hosts": b'127.0.0.1 fixture.test\n',
        }.items():
            path = value / relative; path.write_bytes(payload); os.chmod(path, 0o600)
        provider = "Managed_Candidate" if candidate else "Provider_A"
        runtime = {
            "proxies": [{"name": "direct-fixture", "type": "direct"}],
            "proxy-providers": {provider: {"type": "http", "url": "https://not-copied.invalid"}},
            "proxy-groups": [{"name": "Auto", "type": "select", "use": [provider]}],
            "profile": {"store-selected": False},
            "rules": ["MATCH,old"],
        }
        (value / "router" / "runtime.yaml").write_text(yaml.safe_dump(runtime), encoding="utf-8")
        (value / "router" / "provider-map.json").write_text(json.dumps({provider: "a.yaml"}), encoding="utf-8")
        (value / "router" / "providers" / "a.yaml").write_text(yaml.safe_dump({"proxies": [{"name": "a", "type": "direct"}]}), encoding="utf-8")
        (value / "private.env").write_text(
            "OPENCLASH_SECRET=" + "a" * 32 + "\n"
            "SUBSCRIPTION_PUBLISH_TOKEN=" + "b" * 32 + "\n"
            "SUBSCRIPTION_HMAC_KEY=" + "c" * 32 + "\n",
            encoding="utf-8",
        )
        if os.name == "posix":
            for path in [value, *value.rglob("*")]: os.chmod(path, 0o700 if path.is_dir() else 0o600)
        return value

    def test_prepare_is_private_direct_only_and_never_reports_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = self.fixture(root); output = root / "bundle"
            args = type("Args", (), {"input": source, "output": output, "image": "fixture@sha256:" + "d" * 64,
                                      "container": "lab", "network": "lab-internal", "keep_failed": False})()
            result = LAB.prepare(args)
            config = yaml.safe_load((output / "lab" / "mihomo.yaml").read_text(encoding="utf-8"))
            self.assertEqual(config["rules"], ["MATCH,DIRECT"])
            self.assertEqual(set(config["proxy-providers"]), {"Provider_A", "Managed_Auto"})
            self.assertNotIn("Managed_Candidate", json.dumps(config))
            encoded = json.dumps(result)
            self.assertNotIn("a" * 32, encoded); self.assertNotIn("b" * 32, encoded)
            self.assertIn("not_production_acceptance", result["scope"])
            self.assertFalse((output / "lab" / "fake_dns.py").exists(), "image passive_control owns the only DNS fixture")

    def test_candidate_in_runtime_is_refused_and_failed_bundle_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = self.fixture(root, candidate=True); output = root / "bundle"
            args = type("Args", (), {"input": source, "output": output, "image": "fixture",
                                      "container": "lab", "network": "lab-internal", "keep_failed": False})()
            with self.assertRaisesRegex(LAB.LabFailure, "candidate"):
                LAB.prepare(args)
            self.assertFalse(output.exists())

    def test_coredns_must_only_forward_to_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.joinpath("Corefile").write_text(". {\n forward . 8.8.8.8\n}\n")
            root.joinpath("Corefile.managed").write_text("forward . 127.0.0.1:1153\n")
            root.joinpath("hosts").write_text("127.0.0.1 fixture.test\n")
            if os.name == "posix":
                os.chmod(root, 0o700)
                for path in root.iterdir(): os.chmod(path, 0o600)
            with self.assertRaisesRegex(LAB.LabFailure, "coredns_not_isolated"):
                LAB._validate_coredns(root)

    def test_layout_has_no_secret_values(self):
        value = LAB.layout()
        self.assertEqual(value["network"], "Docker --internal; no published ports")
        self.assertNotIn("=", json.dumps(value["private_input_tree"]["private.env"]))
        self.assertIn("127.0.0.1:23993", LAB.ISOLATED_ENV["LOCAL_SOURCE_HOSTS"])

    def test_private_environment_refuses_unreviewed_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.env"
            path.write_text(
                "OPENCLASH_SECRET=" + "a" * 32 + "\n"
                "SUBSCRIPTION_PUBLISH_TOKEN=" + "b" * 32 + "\n"
                "SUBSCRIPTION_HMAC_KEY=" + "c" * 32 + "\n"
                "HTTP_PROXY=http://outside.invalid\n",
                encoding="utf-8",
            )
            if os.name == "posix": os.chmod(path, 0o600)
            with self.assertRaisesRegex(LAB.LabFailure, "unknown_or_missing"):
                LAB._read_env(path)

    def test_destroy_refuses_container_without_isolated_scope_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / "manifest.json").write_text(json.dumps({
                "container": "clash-center-lab", "network": "clash-center-lab-internal",
            }), encoding="utf-8")
            args = type("Args", (), {"bundle": bundle, "remove_network": True})()
            with mock.patch.object(LAB, "_run", return_value='[{"Config":{"Labels":{}}}]') as runner:
                with self.assertRaisesRegex(LAB.LabFailure, "refuse_destroy_unlabelled"):
                    LAB.destroy(args)
            self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
