"""D12 closed-namespace projection tests; these do not execute an image."""
import copy
import unittest

import check_product_image as checker
from test_check_product_image import synthetic_inspect, SOURCE, IMAGE_ID, PRIVATE


class LifecycleProfileTests(unittest.TestCase):
    def fixture(self, private=None):
        private = private or "/tmp/chengwang-product-lifecycle-" + "d" * 32 + "/refresh/message-signature"
        image, container = synthetic_inspect()
        args = ["--config", private + "/trust-config.json", "--product-config", private + "/product-config.json"]
        container["Config"]["Cmd"] = args[:]
        container["Args"] = args[:]
        for mount in container["Mounts"]:
            mount["Source"] = mount["Source"].replace(PRIVATE, private)
            mount["Destination"] = mount["Destination"].replace(PRIVATE, private)
        return image, container, private

    def check(self, image, container, private, **changed):
        values = dict(image_id=IMAGE_ID, source=SOURCE, private=private,
                      state=private + "/trust", network="none", status="running",
                      fixture_kind="product-lifecycle")
        values.update(changed)
        return checker.inspect_projection(image, container, **values)

    def test_two_closed_signature_paths_accept(self):
        for kind in ("message-signature", "dsse"):
            fixture = self.fixture("/tmp/chengwang-product-lifecycle-" + "d" * 32 + "/refresh/" + kind)
            result = self.check(*fixture)
            self.assertEqual(result["user"], "10001:10001")
            self.assertEqual(result["sourceCommit"], SOURCE)

    def test_original_default_and_registry_namespace_reject_lifecycle(self):
        for kind in ("product-image", "product-registry", "arbitrary-prefix"):
            with self.subTest(kind=kind), self.assertRaises(checker.CheckError):
                self.check(*self.fixture(), fixture_kind=kind)

    def test_noncanonical_or_wrong_case_paths_reject(self):
        valid = self.fixture()[2]
        for path in (valid + "/", valid.replace("/refresh/", "/other/"),
                     valid.replace("message-signature", "cross"), valid.replace("/tmp/", "/var/tmp/"),
                     valid.replace("d" * 32, "d" * 31), valid.replace("/refresh/", "/../refresh/")):
            with self.subTest(path=path), self.assertRaises(checker.CheckError):
                self.check(*self.fixture(path))

    def test_security_and_exact_mount_checks_are_not_relaxed(self):
        changes = (
            lambda c: c["HostConfig"].update(CapAdd=["NET_ADMIN"]),
            lambda c: c["HostConfig"].update(ReadonlyRootfs=False),
            lambda c: c["HostConfig"].update(MemorySwap=-1),
            lambda c: c["HostConfig"].update(NetworkMode="host"),
            lambda c: c["Mounts"].append(copy.deepcopy(c["Mounts"][0])),
            lambda c: c["NetworkSettings"].update(Ports={"17821/tcp": [{"HostPort": "17821"}]}),
            lambda c: c["Config"].update(Entrypoint=["/bin/sh"]),
        )
        for change in changes:
            image, container, private = self.fixture()
            change(container)
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private)

    def test_normal_stop_zero_required_not_planned_kill(self):
        image, container, private = self.fixture()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=0)
        self.assertTrue(self.check(image, container, private, status="exited")["cleanExit"])
        for code in (1, 137, 143):
            container["State"]["ExitCode"] = code
            with self.assertRaises(checker.CheckError):
                self.check(image, container, private, status="exited")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LifecycleProfileTests))
    success = result.wasSuccessful() and result.testsRun == 5 and not result.skipped
    if success:
        print("D12_IMAGE_PROFILE_TESTS=PASS tests=5 skipped=0 synthetic_only=true")
    raise SystemExit(0 if success else 1)
