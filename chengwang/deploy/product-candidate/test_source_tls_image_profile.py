"""Synthetic TLS-source inspection guards, not product TLS acceptance."""
import copy
import unittest

import check_product_image as checker
from test_lifecycle_image_profile import LifecycleProfileTests


class SourceTLSProfileTests(unittest.TestCase):
    def fixture(self, flow="tls-ca", kind="message-signature"):
        private = "/tmp/chengwang-product-lifecycle-" + "e" * 32 + "/refresh/" + flow + "/" + kind
        return LifecycleProfileTests().fixture(private)

    def check(self, image, container, private, **extra):
        return LifecycleProfileTests().check(image, container, private, fixture_kind="product-source-tls", **extra)

    def test_exact_six_paths_preserve_runtime_security(self):
        for flow in ("tls-ca", "tls-san", "tls-spki"):
            for kind in ("message-signature", "dsse"):
                value = self.check(*self.fixture(flow, kind))
                self.assertEqual(value["capabilitiesDropped"], "ALL")
                self.assertEqual(value["hostPorts"], 0)
                self.assertFalse(value["cleanExit"])

    def test_other_profiles_cannot_authorize_tls_source_paths(self):
        image, container, private = self.fixture()
        for family in ("product-image", "product-registry", "product-lifecycle", "product-crash", "product-state", "product-source"):
            with self.subTest(family=family), self.assertRaises(checker.CheckError):
                LifecycleProfileTests().check(image, container, private, fixture_kind=family)

    def test_closed_tls_profile_does_not_accept_other_namespaces(self):
        for flow, kind in (("http-recovery", "dsse"), ("bad-signature", "dsse"),
                           ("tls-other", "dsse"), ("tls-ca/..", "dsse"),
                           ("tls-ca", "unknown"), ("tls-ca", "dsse/"), ("tls-ca", "../dsse")):
            with self.subTest(flow=flow, kind=kind), self.assertRaises(checker.CheckError):
                self.check(*self.fixture(flow, kind))

    def test_tls_runtime_cannot_claim_startup_or_crash_exceptions(self):
        for flags in ({"planned_sigkill": True}, {"startup_rejected": True},
                      {"planned_sigkill": True, "startup_rejected": True}):
            image, container, private = self.fixture()
            container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=137)
            with self.subTest(flags=flags), self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited", **flags)

    def test_normal_stop_requires_integer_zero_without_oom(self):
        image, container, private = self.fixture()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=0)
        self.assertTrue(self.check(image, container, private, status="exited")["cleanExit"])
        for code in (1, 137, 143, False, 0.0):
            container["State"]["ExitCode"] = code
            with self.subTest(code=code), self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited")
        container["State"].update(ExitCode=0, OOMKilled=True)
        with self.assertRaises(checker.CheckError):
            self.check(image, container, private, status="exited")

    def test_all_container_hardening_constraints_remain_required(self):
        for mutate in (lambda c: c["HostConfig"].update(Privileged=True),
                       lambda c: c["HostConfig"].update(CapAdd=["NET_ADMIN"]),
                       lambda c: c["HostConfig"].update(ReadonlyRootfs=False),
                       lambda c: c["HostConfig"].update(Memory=0),
                       lambda c: c["Mounts"].append(copy.deepcopy(c["Mounts"][0])),
                       lambda c: c["Config"].update(Entrypoint=["/bin/sh"])):
            image, container, private = self.fixture()
            mutate(container)
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private)

    def test_peer_namespace_and_image_source_binding_remain_required(self):
        for mutate in (lambda i, c: c["HostConfig"].update(NetworkMode="host"),
                       lambda i, c: c.update(Image="sha256:" + "0" * 64),
                       lambda i, c: i["Config"]["Labels"].update({"org.opencontainers.image.revision": "0" * 40})):
            image, container, private = self.fixture()
            mutate(image, container)
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private)

    def test_flags_and_fixture_kind_require_exact_types_and_names(self):
        image, container, private = self.fixture()
        for flags in ({"planned_sigkill": 0}, {"startup_rejected": 0},
                      {"planned_sigkill": "false"}, {"startup_rejected": None}):
            with self.subTest(flags=flags), self.assertRaises(checker.CheckError):
                self.check(image, container, private, **flags)
        with self.assertRaises(checker.CheckError):
            LifecycleProfileTests().check(image, container, private, fixture_kind="product-source-tls-other")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SourceTLSProfileTests))
    success = result.wasSuccessful() and result.testsRun == 8 and not result.skipped
    if success:
        print("D12_SOURCE_TLS_IMAGE_PROFILE_TESTS=PASS tests=8 skipped=0 synthetic_only=true")
    raise SystemExit(0 if success else 1)
