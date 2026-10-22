#!/usr/bin/env python3
"""Native Linux prerequisite tests; no product or Registry is simulated as live."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
import unittest
import uuid

sys.dont_write_bytecode = True
import fixture_blob_lease as blob
import fixture_lease as lease

BASE = pathlib.Path(__file__).resolve().parent
WRAPPER = """
import os,subprocess,sys
source,target,script,*args=sys.argv[1:]
subprocess.run(['/usr/bin/mount','--bind',source,target],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['/usr/bin/mount','-o','remount,bind,ro',target],check=True,stdout=subprocess.DEVNULL)
os.execv('/usr/bin/setpriv',['/usr/bin/setpriv','--reuid=10001','--regid=10001','--clear-groups',
 '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs',
 sys.executable,'-B',script,*args])
"""


class ShapeTests(unittest.TestCase):
    def test_closed_path_digest_and_deadline(self):
        root = "/tmp/chengwang-product-lifecycle-" + "a" * 32
        control = root + "/control/blob-reserved-dsse"
        value = blob.shape(root, "reserved", "dsse", control, "sha256:" + "1" * 64, "8")
        self.assertEqual(value.deadline_seconds, 8)
        baseline = [root, "reserved", "dsse", control, "sha256:" + "1" * 64, "8"]
        for index, wrong in ((0, root + "/.."), (1, "prepared"), (2, "other"),
                             (3, root + "/control/other"), (4, "sha256:" + "A" * 64),
                             (5, "0"), (5, "08"), (5, "31"), (5, 8)):
            args = baseline.copy()
            args[index] = wrong
            with self.subTest(index=index, wrong=wrong), self.assertRaises(lease.LeaseFailure):
                blob.shape(*args)

    def test_argument_errors_never_echo_arbitrary_values(self):
        process = subprocess.run([sys.executable, "-B", str(BASE / "fixture_blob_lease.py"), "hold",
                                  "--unknown", "PRIVATE_SENTINEL"], capture_output=True, timeout=5)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertEqual(process.stderr, ("D12_BLOB_LEASE_FAILURE=ARGUMENTS" + os.linesep).encode())


@unittest.skipUnless(sys.platform == "linux", "real Linux mount and file leases required")
class LinuxBlobLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise AssertionError("root fixture orchestrator required; no skip/fallback")
        for tool in ("/usr/bin/unshare", "/usr/bin/mount", "/usr/bin/setpriv"):
            if not os.access(tool, os.X_OK):
                raise AssertionError("required native tool unavailable")
        if int(pathlib.Path("/proc/sys/fs/lease-break-time").read_text()) < 10:
            raise AssertionError("required native lease deadline unavailable")

    def setUp(self):
        self.root = pathlib.Path("/tmp/chengwang-product-lifecycle-" + uuid.uuid4().hex)
        self.processes = []
        self.directory(self.root)
        for relative in ("bin", "blob/reserved/message-signature", "control/blob-reserved-message-signature"):
            node = self.root
            for part in relative.split("/"):
                node = node / part
                if not node.exists():
                    self.directory(node)
        self.control = self.root / "control/blob-reserved-message-signature"
        self.alias = self.root / "blob/reserved/message-signature/data"
        self.original = b'private fixture bytes never exported\n'
        self.source = self.root / "original-blob.private"
        self.file(self.source, self.original, 0o644)
        self.file(self.alias, b"alias placeholder\n")
        for name in ("fixture_lease.py", "fixture_blob_lease.py"):
            self.file(self.root / "bin" / name, (BASE / name).read_bytes(), 0o444, owner=0)

    def tearDown(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        self.assertRegex(str(self.root), lease.ROOT)
        self.assertEqual(self.root.resolve().parent, pathlib.Path("/tmp"))
        self.assertEqual(self.root.stat().st_uid, 10001)
        shutil.rmtree(self.root)

    def directory(self, path):
        path.mkdir(mode=0o700)
        os.chown(path, 10001, 10001)

    def file(self, path, raw=b"", mode=0o600, owner=10001):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), owner, owner)
            os.fchmod(handle.fileno(), mode)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

    def spawn(self, command, *, input_pipe=False):
        p = subprocess.Popen(command, stdin=subprocess.PIPE if input_pipe else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1"})
        self.processes.append(p)
        return p

    def helper(self, *, deadline="6", digest=None, mounted=True):
        script = self.root / "bin/fixture_blob_lease.py"
        args = ["hold", "--fixture-root", str(self.root), "--case", "reserved", "--kind", "message-signature",
                "--control-dir", str(self.control), "--digest", digest or "sha256:" + hashlib.sha256(self.original).hexdigest(),
                "--deadline-seconds", deadline]
        if mounted:
            cmd = ["/usr/bin/unshare", "--mount", "--propagation", "private", sys.executable, "-B", "-c", WRAPPER,
                   str(self.source), str(self.alias), str(script), *args]
        else:
            cmd = ["/usr/bin/setpriv", "--reuid=10001", "--regid=10001", "--clear-groups", "--bounding-set=-all",
                   "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", sys.executable, "-B", str(script), *args]
        return self.spawn(cmd)

    def event(self, process, name):
        target = self.control / (name.lower() + ".json")
        end = time.monotonic() + 3
        while time.monotonic() < end:
            if target.exists():
                raw = target.read_bytes()
                value = json.loads(raw)
                info = target.stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (10001, 10001, 0o600, 1))
                self.assertEqual(value["schema"], blob.SCHEMA)
                self.assertEqual(value["event"], name)
                self.assertEqual(value["holderPID"], process.pid)
                self.assertEqual(value["uid"], 10001)
                self.assertEqual(value["leaseType"], "WRITE")
                self.assertIs(value["readOnlyBind"], True)
                self.assertIs(value["capNone"], True)
                self.assertIs(value["production"], False)
                original = self.source.stat()
                self.assertEqual((value["deviceMajor"], value["deviceMinor"], value["inode"], value["size"]),
                                 (os.major(original.st_dev), os.minor(original.st_dev), original.st_ino, original.st_size))
                self.assertNotIn(self.original, raw)
                return value
            if process.poll() is not None:
                self.fail("helper terminated before " + name + ": " + repr(process.communicate(timeout=1)))
            time.sleep(.01)
        self.fail("bounded event missing")

    def exit(self, process, code=0, reason=None):
        stdout, stderr = process.communicate(timeout=3)
        self.assertEqual((process.returncode, stdout, stderr),
                         (code, b"", b"" if reason is None else ("D12_BLOB_LEASE_FAILURE=" + reason + "\n").encode()))

    def reader(self, *, held=False):
        code = ("import os,sys; print('START',flush=True); fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); "
                "print('OPENED',flush=True); " + ("sys.stdin.buffer.read(1); " if held else "") + "os.close(fd)")
        process = self.spawn(["/usr/bin/setpriv", "--reuid=10001", "--regid=10001", "--clear-groups",
                              "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
                              sys.executable, "-B", "-c", code, str(self.source)], input_pipe=held)
        self.assertTrue(select.select([process.stdout], [], [], 2)[0])
        self.assertEqual(process.stdout.readline(), b"START\n")
        return process

    def released(self):
        self.file(self.control / ".release.pending")
        os.rename(self.control / ".release.pending", self.control / "release")

    def reader_done(self, process):
        output, error = process.communicate(timeout=3)
        self.assertEqual((process.returncode, output, error), (0, b"OPENED\n", b""))
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_readonly_file_bind_write_lease_blocks_real_reader_until_release(self):
        helper = self.helper()
        self.assertIs(self.event(helper, "READY")["blockedObserved"], False)
        reader = self.reader()
        self.assertIs(self.event(helper, "BLOCKED")["blockedObserved"], True)
        self.assertIsNone(reader.poll())
        self.assertEqual(select.select([reader.stdout], [], [], .1)[0], [])
        self.released()
        self.exit(helper)
        self.assertIs(self.event(helper, "RELEASED")["blockedObserved"], True)
        self.reader_done(reader)

    def test_existing_open_reader_rejects_write_lease(self):
        held = os.open(self.source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            self.exit(self.helper(), 1, "LEASE_UNAVAILABLE")
            self.assertFalse((self.control / "ready.json").exists())
        finally:
            os.close(held)

    def test_release_without_reader_does_not_claim_break(self):
        helper = self.helper()
        self.event(helper, "READY")
        self.released()
        self.exit(helper)
        self.assertIs(self.event(helper, "RELEASED")["blockedObserved"], False)

    def test_sigterm_releases_kernel_lease_but_is_not_success(self):
        helper = self.helper()
        self.event(helper, "READY")
        reader = self.reader()
        self.event(helper, "BLOCKED")
        helper.terminate()
        self.exit(helper, 1, "TERMINATED")
        self.assertFalse((self.control / "released.json").exists())
        self.reader_done(reader)

    def test_holder_sigkill_releases_kernel_lease_without_release_marker(self):
        helper = self.helper()
        self.event(helper, "READY")
        reader = self.reader()
        self.event(helper, "BLOCKED")
        helper.kill()
        self.assertEqual(helper.wait(timeout=3), -signal.SIGKILL)
        self.assertFalse((self.control / "released.json").exists())
        self.reader_done(reader)

    def test_deadline_failure_releases_lease_and_cannot_report_success(self):
        helper = self.helper(deadline="1")
        self.event(helper, "READY")
        reader = self.reader()
        self.event(helper, "BLOCKED")
        self.exit(helper, 1, "DEADLINE")
        self.assertFalse((self.control / "released.json").exists())
        self.reader_done(reader)

    def test_copied_nonmount_target_is_rejected(self):
        self.exit(self.helper(mounted=False), 1, "UNSAFE_FILE")

    def test_digest_mismatch_never_acquires_lease(self):
        self.exit(self.helper(digest="sha256:" + "0" * 64), 1, "UNSAFE_FILE")
        self.assertFalse((self.control / "ready.json").exists())

    def test_unsafe_owner_mode_hardlink_and_symlink_rejected(self):
        for variant in ("owner", "mode", "hardlink", "symlink"):
            with self.subTest(variant=variant):
                if variant == "owner":
                    os.chown(self.source, 0, 0)
                elif variant == "mode":
                    self.source.chmod(0o666)
                elif variant == "hardlink":
                    os.link(self.source, self.root / "extra-link")
                else:
                    # Kernel mount resolves symlinks; fail the helper on an alias
                    # symlink without provisioning a bind on that untrusted name.
                    self.alias.unlink()
                    self.alias.symlink_to(self.source)
                self.exit(self.helper(mounted=variant != "symlink"), 1, "UNSAFE_FILE")
                if variant == "owner":
                    os.chown(self.source, 10001, 10001)
                elif variant == "mode":
                    self.source.chmod(0o644)
                elif variant == "hardlink":
                    (self.root / "extra-link").unlink()

    def test_stale_control_and_nonempty_release_rejected(self):
        self.file(self.control / "unknown")
        self.exit(self.helper(), 1, "CONTROL_CONTENT")
        (self.control / "unknown").unlink()
        helper = self.helper()
        self.event(helper, "READY")
        self.file(self.control / "release", b"not empty")
        self.exit(helper, 1, "CONTROL_RELEASE")


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    success = result.wasSuccessful() and not result.skipped and result.testsRun == 12
    if success:
        print("D12_BLOB_LEASE_TESTS=PASS tests=12 passed=12 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none readonly_file_bind=true")
    elif sys.platform != "linux" and result.wasSuccessful():
        print("D12_BLOB_LEASE_TESTS=AUXILIARY_ONLY real_linux=false")
    raise SystemExit(0 if success or sys.platform != "linux" and result.wasSuccessful() else 1)
