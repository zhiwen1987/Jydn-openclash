"""D12 lease preflight: real Linux processes, no simulated lease fallback.

Run the Linux suite as a root test orchestrator. Every lease helper and open
probe is a distinct UID10001/GID10001 process with all capability sets empty.
Windows runs shape checks only; Linux prerequisites fail rather than skip.
"""
from __future__ import annotations

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

import fixture_lease as lease

SOURCE = pathlib.Path(lease.__file__).read_text(encoding="utf-8")
FIELDS = {"schema", "event", "case", "kind", "leaseBreakSeconds",
          "deadlineSeconds", "uid", "gid", "capNone", "blockedObserved",
          "authorization", "production", "deviceActionsExecuted"}


class ShapeTests(unittest.TestCase):
    def setUp(self):
        self.root = "/tmp/chengwang-product-lifecycle-" + "a" * 32
        self.case = "prepared-before-audit"
        self.kind = "message-signature"
        self.control = self.root + "/control/" + self.case + "-" + self.kind

    def shape(self, **changes):
        values = dict(fixture_root=self.root, case=self.case, kind=self.kind,
                      control_dir=self.control, deadline_seconds="8")
        values.update(changes)
        return lease.validate_shape(**values)

    def test_exact_shape_and_default_cli(self):
        value = self.shape()
        self.assertEqual(value.deadline_seconds, 8)
        parsed = lease.parse_arguments(["hold", "--fixture-root", self.root,
            "--case", self.case, "--kind", self.kind, "--control-dir", self.control])
        self.assertEqual(parsed, value)

    def test_reject_paths_aliases_kinds_and_unbounded_deadlines(self):
        changes = [
            {"fixture_root": self.root + "/"}, {"fixture_root": self.root + "/../x"},
            {"fixture_root": self.root.replace("/tmp/", "/var/tmp/")},
            {"fixture_root": self.root.replace("a", "A")},
            {"case": ".."}, {"case": "a/b"}, {"case": "A"},
            {"case": "a" * 65}, {"case": ""}, {"kind": "cross"},
            {"control_dir": self.control + "/"}, {"control_dir": self.root + "/control"},
            *({"deadline_seconds": value} for value in ("0", "01", "121", "3600", "1.5", "-1", " 8", 8)),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(lease.LeaseFailure) as error:
                self.shape(**change)
            self.assertEqual(error.exception.reason, "ARGUMENTS")

    def test_parser_rejects_without_reflecting_private_arguments(self):
        with self.assertRaises(lease.LeaseFailure) as error:
            lease.parse_arguments(["hold", "--fixture-root", "/private-do-not-print"])
        self.assertEqual(str(error.exception), "ARGUMENTS")


@unittest.skipUnless(sys.platform == "linux", "Linux kernel lease integration required")
class LinuxProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise AssertionError("Linux integration requires a root fixture orchestrator; no skip/fallback")
        if not pathlib.Path("/usr/bin/setpriv").is_file():
            raise AssertionError("Linux integration requires setpriv; no skip/fallback")
        value = lease.kernel_break_seconds()
        if value < 10:
            raise AssertionError("kernel lease break window rejected; no skip/fallback")

    def setUp(self):
        self.root = pathlib.Path("/tmp/chengwang-product-lifecycle-" + uuid.uuid4().hex)
        self.case = "lease-check"
        self.kind = "message-signature"
        self.processes = []
        self._directory(self.root)
        self.evidence = self.root / self.case / self.kind / "data" / "evidence"
        self.control = self.root / "control" / (self.case + "-" + self.kind)
        for target in (self.evidence, self.control):
            current = self.root
            for name in target.relative_to(self.root).parts:
                current = current / name
                if not current.exists():
                    self._directory(current)
        self.log = self.evidence / "events.jsonl"
        self.original = b"private-fixture-bytes-never-published\n"
        self._file(self.log, self.original)

    def tearDown(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        # This fresh, exact UUID fixture is the only recursive cleanup target.
        self.assertRegex(str(self.root), lease.ROOT)
        self.assertEqual(str(self.root.parent), "/tmp")
        if self.root.is_symlink():
            self.root.unlink()
        elif self.root.exists():
            self.assertEqual(self.root.resolve(), self.root)
            shutil.rmtree(self.root)

    def _directory(self, path):
        path.mkdir(mode=0o700)
        os.chown(path, lease.UID, lease.GID)
        path.chmod(0o700)

    def _file(self, path, contents=b""):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(descriptor, lease.UID, lease.GID)
            os.fchmod(descriptor, 0o600)
            self.assertEqual(os.write(descriptor, contents), len(contents))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _spawn(self, source, arguments=(), *, unprivileged=True):
        command = []
        if unprivileged:
            command = ["/usr/bin/setpriv", "--reuid=10001", "--regid=10001", "--clear-groups",
                       "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]
        command += [sys.executable, "-B", "-c", source, *map(str, arguments)]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
                 "PYTHONOPTIMIZE": "0", "PYTHONDONTWRITEBYTECODE": "1"})
        self.processes.append(process)
        return process

    def helper(self, deadline="6", *, extra=(), unprivileged=True):
        arguments = ["hold", "--fixture-root", self.root, "--case", self.case,
            "--kind", self.kind, "--control-dir", self.control,
            "--deadline-seconds", deadline, *extra]
        return self._spawn(SOURCE, arguments, unprivileged=unprivileged)

    def wait_event(self, process, event, timeout=3):
        target = self.control / (event.lower() + ".json")
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if target.exists():
                value = json.loads(target.read_text(encoding="ascii"))
                info = target.stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                                 (lease.UID, lease.GID, 0o600, 1))
                self.assertEqual(set(value), FIELDS)
                self.assertEqual(value["schema"], lease.SCHEMA)
                self.assertEqual(value["event"], event)
                self.assertEqual((value["case"], value["kind"]), (self.case, self.kind))
                self.assertEqual((value["uid"], value["gid"]), (lease.UID, lease.GID))
                self.assertIs(value["capNone"], True)
                self.assertIs(value["production"], False)
                self.assertIs(value["deviceActionsExecuted"], False)
                self.assertEqual(value["authorization"], "BLOCKED")
                self.assertIs(type(value["blockedObserved"]), bool)
                self.assertNotIn(self.original, target.read_bytes())
                return value
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=1)
                self.fail("helper exited before " + event + ": " + str((process.returncode, stdout, stderr)))
            time.sleep(0.01)
        self.fail("missing bounded helper event " + event)

    def release(self):
        pending = self.control / ".orchestrator-release.pending"
        self._file(pending)
        os.rename(pending, self.control / "release")

    def assert_exit(self, process, code, reason=None, timeout=3):
        stdout, stderr = process.communicate(timeout=timeout)
        self.assertEqual(process.returncode, code)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"" if reason is None else ("D12_LEASE_FAILURE=" + reason + "\n").encode())

    def writer(self):
        process = self._spawn(
            "import os,sys; print('START',flush=True); "
            "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC); "
            "os.close(fd); print('OPENED',flush=True)", [self.log])
        self.assertTrue(select.select([process.stdout], [], [], 2)[0])
        self.assertEqual(process.stdout.readline(), b"START\n")
        return process

    def assert_writer_blocked(self, process):
        self.assertIsNone(process.poll())
        self.assertEqual(select.select([process.stdout], [], [], 0.15)[0], [])

    def assert_writer_opened(self, process):
        stdout, stderr = process.communicate(timeout=3)
        self.assertEqual((process.returncode, stdout, stderr), (0, b"OPENED\n", b""))
        self.assertEqual(self.log.read_bytes(), self.original)

    def test_real_read_open_is_allowed_writer_blocks_until_explicit_release(self):
        helper = self.helper()
        self.assertIs(self.wait_event(helper, "READY")["blockedObserved"], False)
        reader = self._spawn("import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); os.close(fd)", [self.log])
        self.assert_exit(reader, 0)
        self.assertFalse((self.control / "blocked.json").exists())
        writer = self.writer()
        self.assertIs(self.wait_event(helper, "BLOCKED")["blockedObserved"], True)
        self.assert_writer_blocked(writer)
        self.release()
        self.assert_exit(helper, 0)
        self.assertIs(self.wait_event(helper, "RELEASED")["blockedObserved"], True)
        self.assert_writer_opened(writer)

    def test_explicit_release_without_writer_does_not_claim_blocked(self):
        helper = self.helper()
        self.wait_event(helper, "READY")
        self.release()
        self.assert_exit(helper, 0)
        self.assertIs(self.wait_event(helper, "RELEASED")["blockedObserved"], False)

    def test_termination_unlocks_without_release_success(self):
        helper = self.helper()
        self.wait_event(helper, "READY")
        writer = self.writer()
        self.wait_event(helper, "BLOCKED")
        self.assert_writer_blocked(writer)
        helper.terminate()
        self.assert_exit(helper, 1, "TERMINATED")
        self.assertFalse((self.control / "released.json").exists())
        self.assert_writer_opened(writer)

    def test_deadline_unlocks_but_never_claims_release_success(self):
        helper = self.helper("1")
        self.wait_event(helper, "READY")
        writer = self.writer()
        self.wait_event(helper, "BLOCKED")
        self.assert_writer_blocked(writer)
        self.assert_exit(helper, 1, "DEADLINE")
        self.assertFalse((self.control / "released.json").exists())
        self.assert_writer_opened(writer)

    def test_sigkill_holder_releases_kernel_lease_without_finally(self):
        helper = self.helper()
        self.wait_event(helper, "READY")
        writer = self.writer()
        self.wait_event(helper, "BLOCKED")
        self.assert_writer_blocked(writer)
        helper.kill()
        self.assert_exit(helper, -signal.SIGKILL)
        self.assertFalse((self.control / "released.json").exists())
        self.assert_writer_opened(writer)

    def test_root_identity_is_rejected(self):
        self.assert_exit(self.helper(unprivileged=False), 1, "IDENTITY")
        self.assertFalse((self.control / "ready.json").exists())

    def test_unsafe_cli_path_is_rejected_without_raw_input(self):
        self.assert_exit(self.helper(extra=("--fixture-root", "/private-do-not-print")), 2, "ARGUMENTS")

    def test_wrong_file_owner_and_gid_are_rejected(self):
        for owner, group in ((0, lease.GID), (lease.UID, 0)):
            with self.subTest(owner=owner, group=group):
                os.chown(self.log, owner, group)
                self.assert_exit(self.helper(), 1, "UNSAFE_FILE")
                self.assertFalse((self.control / "ready.json").exists())
        os.chown(self.log, lease.UID, lease.GID)

    def test_wrong_file_mode_is_rejected(self):
        self.log.chmod(0o640)
        self.assert_exit(self.helper(), 1, "UNSAFE_FILE")
        self.assertFalse((self.control / "ready.json").exists())

    def test_symlink_log_is_rejected(self):
        target = self.evidence / "saved"
        self.log.rename(target)
        self.log.symlink_to(target)
        self.assert_exit(self.helper(), 1, "UNSAFE_FILE")
        self.assertEqual(target.read_bytes(), self.original)

    def test_hardlinked_log_is_rejected(self):
        os.link(self.log, self.evidence / "alias")
        self.assert_exit(self.helper(), 1, "UNSAFE_FILE")
        self.assertEqual(self.log.read_bytes(), self.original)

    def test_fifo_is_rejected_without_blocking(self):
        self.log.unlink()
        os.mkfifo(self.log, 0o600)
        os.chown(self.log, lease.UID, lease.GID)
        self.assert_exit(self.helper(), 1, "UNSAFE_FILE")

    def test_symlink_directory_is_rejected(self):
        saved = self.evidence.with_name("saved-evidence")
        self.evidence.rename(saved)
        self.evidence.symlink_to(saved, target_is_directory=True)
        self.assert_exit(self.helper(), 1, "UNSAFE_DIRECTORY")
        self.assertFalse((self.control / "ready.json").exists())

    def test_control_directory_must_be_private_and_owned(self):
        self.control.chmod(0o750)
        self.assert_exit(self.helper(), 1, "UNSAFE_DIRECTORY")
        self.control.chmod(0o700)
        os.chown(self.control, 0, lease.GID)
        self.assert_exit(self.helper(), 1, "UNSAFE_DIRECTORY")

    def test_stale_control_is_rejected_without_overwrite(self):
        self._file(self.control / "ready.json", b"stale\n")
        self.assert_exit(self.helper(), 1, "CONTROL_CONTENT")
        self.assertEqual((self.control / "ready.json").read_bytes(), b"stale\n")

    def test_release_symlink_is_rejected_and_lease_dropped(self):
        helper = self.helper()
        self.wait_event(helper, "READY")
        writer = self.writer()
        self.wait_event(helper, "BLOCKED")
        (self.control / "release").symlink_to(self.log)
        self.assert_exit(helper, 1, "CONTROL_RELEASE")
        self.assertFalse((self.control / "released.json").exists())
        self.assert_writer_opened(writer)

    def test_replaced_log_inode_is_rejected(self):
        helper = self.helper()
        self.wait_event(helper, "READY")
        substitute = self.evidence / "new-log"
        self._file(substitute, self.original)
        os.replace(substitute, self.log)
        self.assert_exit(helper, 1, "PATH_CHANGED")
        self.assertFalse((self.control / "released.json").exists())


class CountingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = 0

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed += 1


if __name__ == "__main__":
    program = unittest.main(testRunner=unittest.TextTestRunner(
        verbosity=2, resultclass=CountingResult), exit=False)
    result = program.result
    linux = sys.platform == "linux"
    good = result.wasSuccessful() and (not linux or len(result.skipped) == 0)
    marker = "D12_LEASE_TESTS" if linux else "D12_LEASE_AUXILIARY_TESTS"
    message = (f"{marker}={'PASS' if good else 'FAIL'} tests={result.testsRun} "
               f"passed={result.passed} skipped={len(result.skipped)} "
               f"real_linux={str(linux).lower()}")
    if good and linux:
        message += " helper_uid=10001 helper_capabilities=none"
    print(message, flush=True)
    raise SystemExit(0 if good else 1)
