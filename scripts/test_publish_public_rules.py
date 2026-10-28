#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("publish_public_rules.py")
SPEC = importlib.util.spec_from_file_location("publish_public_rules", MODULE_PATH)
PUBLISHER = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(PUBLISHER)


class PublicRulesPublisherTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        source = root / "source"
        (source / "rules").mkdir(parents=True)
        lines = ["[custom]"]
        for name in sorted(PUBLISHER.PUBLIC_TEMPLATE_RULES | PUBLISHER.SITE_LOCAL_TEMPLATE_RULES):
            lines.append(
                "ruleset=DIRECT,clash-domain:"
                f"{PUBLISHER.SOURCE_RAW_PREFIX}rules/{name},86400"
            )
            (source / "rules" / name).write_text(
                "payload:\n  - '+.example.test'\n", encoding="utf-8"
            )
        for name in PUBLISHER.ADDITIONAL_PUBLIC_RULES:
            (source / "rules" / name).write_text(
                "payload:\n  - '+.iot.example.test'\n", encoding="utf-8"
            )
        (source / "metafenliu.ini").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return source

    def test_allowlist_export_is_closed_and_rewrites_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            output = root / "public"
            result = PUBLISHER.publish(source, output)
            actual = {
                p.relative_to(output).as_posix()
                for p in output.rglob("*")
                if p.is_file()
            }
            expected = {"README.md", "metafenliu.ini"} | {
                f"rules/{name}"
                for name in PUBLISHER.PUBLIC_TEMPLATE_RULES
                | PUBLISHER.ADDITIONAL_PUBLIC_RULES
            }
            self.assertEqual(actual, expected)
            template = (output / "metafenliu.ini").read_text(encoding="utf-8")
            self.assertNotIn(PUBLISHER.SOURCE_RAW_PREFIX, template)
            self.assertIn("webrtc-client.yaml", template)
            self.assertEqual(
                (output / "rules" / "webrtc-client.yaml").read_text(encoding="utf-8").splitlines()[-1],
                "payload: []",
            )
            self.assertEqual(result["template_rules"], len(PUBLISHER.PUBLIC_TEMPLATE_RULES))

    def test_missing_source_rule_fails_before_output_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            (source / "rules" / "direct.yaml").unlink()
            output = root / "public"
            with self.assertRaises(PUBLISHER.PublishError):
                PUBLISHER.publish(source, output)
            self.assertFalse(output.exists())

    def test_site_specific_private_address_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            (source / "rules" / "direct.yaml").write_text(
                "payload:\n  - 'IP-CIDR,10.88.0.0/24'\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(PUBLISHER.PublishError, "site-specific private"):
                PUBLISHER.publish(source, root / "public")

    def test_site_local_source_is_replaced_before_private_address_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            (source / "rules" / "webrtc-client.yaml").write_text(
                "payload:\n  - 'SRC-IP-CIDR,10.88.0.0/24'\n", encoding="utf-8"
            )
            PUBLISHER.publish(source, root / "public")
            public_rule = (root / "public" / "rules" / "webrtc-client.yaml").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("10.88", public_rule)

    def test_generic_private_network_rule_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            template = (source / "metafenliu.ini").read_text(encoding="utf-8")
            (source / "metafenliu.ini").write_text(
                template + "ruleset=DIRECT,[]IP-CIDR,10.0.0.0/8,no-resolve\n",
                encoding="utf-8",
            )
            PUBLISHER.publish(source, root / "public")

    def test_credential_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            template = (source / "metafenliu.ini").read_text(encoding="utf-8")
            (source / "metafenliu.ini").write_text(
                template + "; https://user:password@example.test/file\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PUBLISHER.PublishError, "credential URL"):
                PUBLISHER.publish(source, root / "public")

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.fixture(root)
            output = root / "public"
            output.mkdir()
            marker = output / "old.txt"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(PUBLISHER.PublishError, "must not already exist"):
                PUBLISHER.publish(source, output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
