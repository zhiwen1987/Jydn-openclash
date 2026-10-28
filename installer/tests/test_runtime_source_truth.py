"""The unified image, never persistent /data, is the runtime code authority."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WRAPPER_PATH = ROOT / "runtime" / "portable_subscriptions.py"
CAPABILITY_PATH = ROOT / "runtime" / "upstream" / "node-capability.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("portable_subscriptions_source_truth", WRAPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RuntimeSourceTruthTests(unittest.TestCase):
    def test_wrapper_has_no_persistent_code_overlay(self):
        source = WRAPPER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("/data/subscription-usage/code", source)
        self.assertNotIn("/data/node-health/code", source)
        self.assertIn("SUBSCRIPTION_IMPL=Path('/subscription_impl.py')", source)

    def test_capability_has_no_persistent_code_overlay(self):
        source = CAPABILITY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("sys.path.insert(0,\"/data/node-health/code\")", source)
        compile(source, str(CAPABILITY_PATH), "exec")

    def test_load_always_uses_image_implementation(self):
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as directory:
            image_impl = Path(directory) / "subscription_impl.py"
            image_impl.write_text("SOURCE = 'image'\n", encoding="utf-8")
            overlay = Path(directory) / "data" / "node-health" / "code"
            overlay.mkdir(parents=True)
            (overlay / "subscription_impl.py").write_text("SOURCE = 'overlay'\n", encoding="utf-8")
            with patch.object(wrapper, "SUBSCRIPTION_IMPL", image_impl):
                module = wrapper.load()
            self.assertEqual(module.SOURCE, "image")
            self.assertEqual(Path(module.__file__).resolve(), image_impl.resolve())

    def test_import_does_not_add_data_code_to_sys_path(self):
        before = list(sys.path)
        load_wrapper()
        added = [entry for entry in sys.path if entry not in before]
        self.assertFalse(any(entry.startswith("/data/") for entry in added), added)


if __name__ == "__main__":
    unittest.main()
