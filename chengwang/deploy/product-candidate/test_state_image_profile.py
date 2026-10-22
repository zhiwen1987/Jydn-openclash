"""Synthetic closed-path inspect checks, not actual product startup evidence."""
import copy
import unittest

import check_product_image as checker
from test_lifecycle_image_profile import LifecycleProfileTests


class StateProfileTests(unittest.TestCase):
    def fixture(self, lane="update", scenario="after-journal-prepare", kind="message-signature"):
        private = "/tmp/chengwang-product-lifecycle-" + "f" * 32 + "/state/" + lane + "/" + scenario + "/" + kind
        return LifecycleProfileTests().fixture(private)

    def check(self, image, container, private, **extra):
        return LifecycleProfileTests().check(image, container, private, fixture_kind="product-state", **extra)

    def rejected(self, lane="update", scenario="bad-checkpoint", kind="message-signature"):
        image, container, private = self.fixture(lane, scenario, kind)
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=1)
        return image, container, private

    def test_all_36_healthy_and_48_rejected_closed_paths(self):
        total = 0
        for lane in checker.STATE_LANES:
            for kind in ("message-signature", "dsse"):
                for scenario in checker.STATE_BOUNDARIES:
                    value = self.check(*self.fixture(lane, scenario, kind))
                    self.assertEqual(value["state"], "running")
                    self.assertFalse(value["cleanExit"])
                    total += 1
                for scenario in checker.STATE_FAULTS:
                    value = self.check(*self.rejected(lane, scenario, kind), status="exited", startup_rejected=True)
                    self.assertEqual(value["state"], "exited")
                    self.assertFalse(value["cleanExit"])
                    total += 1
        self.assertEqual(total, 84)

    def test_rejection_requires_exact_exit_one_not_oom_signal_or_bool(self):
        for code in (0, 137, 143, -1, True, 1.0):
            image, container, private = self.rejected()
            container["State"]["ExitCode"] = code
            with self.subTest(code=code), self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited", startup_rejected=True)

    def test_no_healthy_or_running_can_claim_expected_rejection(self):
        with self.assertRaises(checker.CheckError):
            self.check(*self.fixture(), startup_rejected=True)
        image, container, private = self.fixture()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=1)
        with self.assertRaises(checker.CheckError):
            self.check(image, container, private, status="exited", startup_rejected=True)
        with self.assertRaises(checker.CheckError):
            self.check(*self.rejected(), status="exited")
        with self.assertRaises(checker.CheckError):
            self.check(*self.fixture(scenario="bad-checkpoint"))

    def test_old_profiles_and_sigkill_cannot_acquire_new_rejection_profile(self):
        image, container, private = self.rejected()
        for family in ("product-image", "product-registry", "product-lifecycle", "product-crash"):
            with self.subTest(family=family), self.assertRaises(checker.CheckError):
                LifecycleProfileTests().check(image, container, private, fixture_kind=family, status="exited", startup_rejected=True)
        for flags in ({"planned_sigkill": True}, {"planned_sigkill": True, "startup_rejected": True}):
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited", **flags)

    def test_normal_healthy_exit_remains_exact_zero(self):
        image, container, private = self.fixture()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=0)
        self.assertTrue(self.check(image, container, private, status="exited")["cleanExit"])
        for code in (1, 137, 143, False, 0.0):
            container["State"]["ExitCode"] = code
            with self.subTest(code=code), self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited")

    def test_no_unsafe_process_or_authority_can_hide_as_rejected(self):
        edits = (lambda c: c["State"].update(OOMKilled=True), lambda c: c["State"].update(Pid=123),
                 lambda c: c["State"].update(Running=True), lambda c: c["HostConfig"].update(Privileged=True),
                 lambda c: c["HostConfig"].update(CapAdd=["SYS_ADMIN"]), lambda c: c["HostConfig"].update(ReadonlyRootfs=False),
                 lambda c: c["HostConfig"].update(MemorySwap=-1), lambda c: c["Mounts"].append(copy.deepcopy(c["Mounts"][0])),
                 lambda c: c["Config"].update(Entrypoint=["/bin/sh"]))
        for edit in edits:
            image, container, private = self.rejected()
            edit(container)
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited", startup_rejected=True)

    def test_noncanonical_unknown_or_other_fixture_paths_rejected(self):
        for lane, scenario, kind in (("other", "after-journal-ack", "dsse"), ("update", "other", "dsse"),
                                     ("update", "after-journal-ack", "other"), ("update/..", "after-journal-ack", "dsse")):
            with self.assertRaises(checker.CheckError):
                self.check(*self.fixture(lane, scenario, kind))
        for old in ("/refresh/dsse", "/consumed/dsse", "/state/update/after-journal-ack/dsse/"):
            private = "/tmp/chengwang-product-lifecycle-" + "f" * 32 + old
            with self.assertRaises(checker.CheckError):
                self.check(*LifecycleProfileTests().fixture(private))

    def test_rejection_flag_is_strict_bool_and_old_default_stays_closed(self):
        for flag in (1, "true", None, [], {}):
            with self.assertRaises(checker.CheckError):
                self.check(*self.rejected(), status="exited", startup_rejected=flag)
        image, container, private = self.rejected()
        with self.assertRaises(checker.CheckError):
            LifecycleProfileTests().check(image, container, private, fixture_kind="product-image", status="exited")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StateProfileTests))
    success = result.wasSuccessful() and result.testsRun == 8 and not result.skipped
    if success:
        print("D12_STATE_IMAGE_PROFILE_TESTS=PASS tests=8 skipped=0 synthetic_only=true")
    raise SystemExit(0 if success else 1)
