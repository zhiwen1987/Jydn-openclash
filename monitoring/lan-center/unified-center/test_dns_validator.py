import importlib.util
import errno
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("dns_validator", HERE / "dns_validator.py")
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)

FRAGMENT_PATH = "/data/dns-management/Corefile.managed"
HOSTS_PATH = "/data/dns-management/hosts"
CORE = f""".:53 {{
    bind 0.0.0.0
    errors {{
        consolidate 5s ".* i/o timeout$" warning
    }}
    health 127.0.0.1:18080 {{
        lameduck 5s
    }}
    ready 127.0.0.1:18181 {{
        monitor continuously
    }}
    prometheus 127.0.0.1:19153
    loop
    reload 10s
    acl {{
        allow net 10.88.0.0/24 127.0.0.0/8
        block
    }}
    cache 300 {{
        success 9984 300 5
        denial 9984 60 5
        servfail 0
        prefetch 10 1m 10%
    }}
    import {FRAGMENT_PATH}
}}
"""
FRAGMENT = f"""hosts {HOSTS_PATH} {{
  fallthrough
}}
rewrite stop name exact old.example new.example answer auto
forward . 127.0.0.1:53 {{
  policy sequential
  health_check 5s domain .
  max_fails 2
  failfast_all_unhealthy_upstreams
}}
"""


class ValidatorTests(unittest.TestCase):
    def validator(self):
        return V.IsolatedCoreDnsValidator(FRAGMENT_PATH, HOSTS_PATH, timeout=4)

    def test_rewrite_moves_every_listener_and_managed_path(self):
        validator = self.validator()
        with tempfile.TemporaryDirectory() as temporary:
            core, fragment = validator._rewrite(CORE, FRAGMENT, Path(temporary), 15353, 18081, 18182, 19154)
        self.assertIn(".:15353 {", core)
        self.assertIn("bind 127.0.0.1", core)
        self.assertIn("health 127.0.0.1:18081 {", core)
        self.assertIn("ready 127.0.0.1:18182 {", core)
        self.assertIn("prometheus 127.0.0.1:19154", core)
        self.assertNotIn(FRAGMENT_PATH, core)
        self.assertNotIn(HOSTS_PATH, fragment)

    def test_unknown_plugin_and_listener_are_fail_closed(self):
        validator = self.validator()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(V.ValidatorError, "unsupported_plugin"):
                validator._rewrite(CORE.replace("    loop\n", "    unknown_plugin\n"), FRAGMENT, Path(temporary), 15353, 18081, 18182, 19154)
            with self.assertRaisesRegex(V.ValidatorError, "unsupported_plugin"):
                validator._rewrite(CORE.replace("    loop\n", "    tls://.:853 {\n    }\n"), FRAGMENT, Path(temporary), 15353, 18081, 18182, 19154)

    def test_import_and_hosts_path_must_match_exactly_once(self):
        validator = self.validator()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(V.ValidatorError, "managed_import_mismatch"):
                validator._rewrite(CORE.replace(FRAGMENT_PATH, "/wrong"), FRAGMENT, Path(temporary), 15353, 18081, 18182, 19154)
            with self.assertRaisesRegex(V.ValidatorError, "managed_hosts_mismatch"):
                validator._rewrite(CORE, FRAGMENT + f"# {HOSTS_PATH}\n", Path(temporary), 15353, 18081, 18182, 19154)

    def test_ready_probe_ignores_proxy_environment(self):
        response = mock.MagicMock();response.status = 200
        opener = mock.MagicMock();opener.open.return_value.__enter__.return_value = response
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://198.51.100.1:8080", "HTTPS_PROXY": "http://198.51.100.1:8080"}), mock.patch.object(V.urllib.request, "build_opener", return_value=opener) as build:
            self.assertTrue(V._direct_http_ok("http://127.0.0.1:18181/ready", .2))
        handler = build.call_args.args[0]
        self.assertIsInstance(handler, V.urllib.request.ProxyHandler)
        self.assertEqual(handler.proxies, {})
        self.assertEqual(opener.open.call_args.args[0].full_url, "http://127.0.0.1:18181/ready")

    def test_binary_start_errors_are_classified_without_hiding_capability_denial(self):
        validator = self.validator()
        cases = [
            (FileNotFoundError(errno.ENOENT, "missing"), "coredns_binary_unavailable"),
            (PermissionError(errno.EPERM, "file capability outside bounding set"), "coredns_execution_denied"),
            (PermissionError(errno.EACCES, "permission denied"), "coredns_execution_denied"),
            (OSError(errno.EIO, "exec failed"), "coredns_start_failed"),
        ]
        for error, code in cases:
            with self.subTest(code=code, error=error.errno), mock.patch.object(V.subprocess, "Popen", side_effect=error):
                with self.assertRaisesRegex(V.ValidatorError, code):
                    validator(CORE, FRAGMENT, "10.88.0.254 router.example\n")

    @unittest.skipUnless(
        os.name == "posix" and os.getenv("RUN_COREDNS_VALIDATOR_INTEGRATION") == "1" and shutil.which("coredns"),
        "requires the production-like Linux image and an existing CoreDNS on 127.0.0.1:53",
    )
    def test_real_coredns_udp_tcp_and_cleanup(self):
        result = self.validator()(CORE, FRAGMENT, "10.88.0.254 router.example\n")
        self.assertEqual(result["state"], "ok")
        self.assertTrue(result["isolated"])
        self.assertEqual(result["udp"]["rcode"], result["tcp"]["rcode"])


if __name__ == "__main__":
    unittest.main()
