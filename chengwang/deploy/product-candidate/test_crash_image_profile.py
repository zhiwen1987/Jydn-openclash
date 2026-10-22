"""Closed crash profile tests; synthetic inspect is not real image evidence."""
import copy
import unittest

import check_product_image as checker
from test_lifecycle_image_profile import LifecycleProfileTests


class CrashProfileTests(unittest.TestCase):
    def fixture(self, stage="prepared", kind="message-signature"):
        private = "/tmp/chengwang-product-lifecycle-" + "e" * 32 + "/" + stage + "/" + kind
        return LifecycleProfileTests().fixture(private)

    def check(self, image, container, private, **extra):
        return LifecycleProfileTests().check(image, container, private, fixture_kind="product-crash", **extra)

    def test_exact_six_paths_accept_without_new_authority(self):
        for stage in ("prepared", "reserved", "consumed"):
            for kind in ("message-signature", "dsse"):
                value = self.check(*self.fixture(stage, kind))
                self.assertFalse(value["cleanExit"])
                self.assertEqual(value["capabilitiesDropped"], "ALL")

    def test_planned_kill_requires_exact137_and_never_claims_clean(self):
        image, container, private = self.fixture()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=137)
        value = self.check(image, container, private, status="exited", planned_sigkill=True)
        self.assertFalse(value["cleanExit"])
        for code in (0, 1, 143, True, 137.0):
            container["State"]["ExitCode"] = code
            with self.subTest(code=code), self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited", planned_sigkill=True)

    def test_normal_exit_remains_exact_zero_and_137_rejected(self):
        image, container, private = self.fixture()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=0)
        self.assertTrue(self.check(image, container, private, status="exited")["cleanExit"])
        for code in (137, 1, 143):
            container["State"]["ExitCode"] = code
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited")

    def test_no_old_profile_or_running_can_opt_into_planned_kill(self):
        image, container, private = self.fixture()
        for kind in ("product-image", "product-registry", "product-lifecycle"):
            with self.assertRaises(checker.CheckError):
                checker.inspect_projection(image, container, image_id=image["Id"], source=image["Config"]["Labels"]["org.opencontainers.image.revision"],
                    private=private, state=private + "/trust", network="none", status="running", fixture_kind=kind, planned_sigkill=True)
        for flag in (True, 1, "true", None):
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private, planned_sigkill=flag)

    def test_oom_pid_or_security_cannot_be_hidden_by_kill(self):
        for edit in (lambda c: c["State"].update(OOMKilled=True), lambda c: c["State"].update(Pid=123),
                     lambda c: c["HostConfig"].update(Privileged=True), lambda c: c["HostConfig"].update(Memory=0),
                     lambda c: c["Mounts"].append(copy.deepcopy(c["Mounts"][0]))):
            image, container, private = self.fixture()
            container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=137)
            edit(container)
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited", planned_sigkill=True)

    def test_arbitrary_paths_and_refresh_namespace_are_rejected(self):
        for stage, kind in (("refresh", "dsse"), ("prepared/..", "dsse"), ("prepared", "cross"), ("other", "message-signature")):
            with self.assertRaises(checker.CheckError):
                self.check(*self.fixture(stage, kind))


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CrashProfileTests))
    success = result.wasSuccessful() and result.testsRun == 6 and not result.skipped
    if success:
        print("D12_CRASH_IMAGE_PROFILE_TESTS=PASS tests=6 skipped=0 synthetic_only=true")
    raise SystemExit(0 if success else 1)
