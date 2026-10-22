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

FOREIGN_SOURCE = """
import json,os,pathlib,subprocess,sys
backend=pathlib.Path(sys.argv[1])
subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=1m,mode=0700,uid=10001,gid=10001,nodev,nosuid,noexec','tmpfs',str(backend)],check=True)
fd=os.open(backend/'data',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
os.fchown(fd,10001,10001); os.fchmod(fd,0o644)
os.write(fd,b'private fixture bytes never exported\\n'); os.fsync(fd); os.close(fd)
code=r'''
import os,pathlib,sys
path=pathlib.Path(sys.argv[1])
print('SOURCE_READY',flush=True)
assert sys.stdin.buffer.read(1)==b'W'
fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC); os.close(fd)
assert path.read_bytes()==b'private fixture bytes never exported\\n'
print('SOURCE_RW',flush=True)
assert sys.stdin.buffer.read(1)==b'X'
'''
os.execv('/usr/bin/setpriv',['/usr/bin/setpriv','--reuid=10001','--regid=10001','--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs',sys.executable,'-B','-c',code,str(backend/'data')])
"""

FOREIGN_WRAPPER = """
import os,pathlib,subprocess,sys
pid,root,script,*args=sys.argv[1:]
root=pathlib.Path(root); sys.path.insert(0,str(root/'bin'))
import fixture_blob_lease as blob
target=root/'blob/reserved/message-signature/data'
source=os.open('/proc/'+pid+'/root'+str(root/'foreign-tmpfs/data'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
namespace=os.open('/proc/'+pid+'/ns/mnt',os.O_RDONLY|os.O_CLOEXEC)
try:
    original=os.fstat(source)
    identity=lambda path:(os.stat(path).st_dev,os.stat(path).st_ino)
    before_ns,before_root,before_cwd=identity('/proc/self/ns/mnt'),identity('/'),identity('.')
    assert before_ns!=identity('/proc/'+pid+'/ns/mnt')
    old=subprocess.run(['/usr/bin/mount','--no-canonicalize','--bind','/proc/'+str(os.getpid())+'/fd/'+str(source),str(target)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    assert old.returncode!=0
    before_fds=set(os.listdir('/proc/self/fd'))
    blob.bind_readonly_foreign_blob(source,namespace,str(target))
    assert set(os.listdir('/proc/self/fd'))==before_fds
    assert identity('/proc/self/ns/mnt')==before_ns and identity('/')==before_root and identity('.')==before_cwd
    actual=target.stat()
    assert (actual.st_dev,actual.st_ino,actual.st_size)==(original.st_dev,original.st_ino,original.st_size)
    assert {'ro','nosuid','nodev','noexec'}<=set(blob.mount_projection(str(target),actual.st_dev)[4].split(','))
finally:
    os.close(namespace); os.close(source)
os.execv('/usr/bin/setpriv',['/usr/bin/setpriv','--reuid=10001','--regid=10001','--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs',sys.executable,'-B',script,*args])
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
        self.reap()
        self.assertRegex(str(self.root), lease.ROOT)
        self.assertEqual(self.root.resolve().parent, pathlib.Path("/tmp"))
        self.assertEqual(self.root.stat().st_uid, 10001)
        shutil.rmtree(self.root)

    def reap(self):
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
        self.processes.clear()

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

    def event(self, process, name, source_info=None):
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
                original = self.source.stat() if source_info is None else source_info
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

    def reader(self, *, held=False, namespace_pid=None, source=None):
        code = ("import os,sys; print('START',flush=True); fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); "
                "print('OPENED',flush=True); " + ("sys.stdin.buffer.read(1); " if held else "") + "os.close(fd)")
        command = ["/usr/bin/setpriv", "--reuid=10001", "--regid=10001", "--clear-groups",
                              "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
                              sys.executable, "-B", "-c", code, str(self.source if source is None else source)]
        if namespace_pid is not None:
            command = ["/usr/bin/nsenter", "--mount=/proc/" + str(namespace_pid) + "/ns/mnt", "--", *command]
        process = self.spawn(command, input_pipe=held)
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

    def test_registry_style_tmpfs_blob_with_readonly_alias_blocks_reader(self):
        # The runtime Registry keeps its original private tmpfs profile. Test
        # that filesystem too; an ext4-only lease result is insufficient.
        backend = self.root / "tmpfs-blob"
        self.directory(backend)
        self.assertEqual(backend.resolve().parent, self.root.resolve())
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "size=1m,mode=0700,uid=10001,gid=10001,nodev,nosuid,noexec",
                        "tmpfs", str(backend)], check=True)
        original_source = self.source
        try:
            self.source = backend / "data"
            self.file(self.source, self.original, 0o644)
            helper = self.helper()
            self.event(helper, "READY")
            reader = self.reader()
            self.event(helper, "BLOCKED")
            self.assertEqual(select.select([reader.stdout], [], [], .1)[0], [])
            self.released()
            self.exit(helper)
            self.event(helper, "RELEASED")
            self.reader_done(reader)
        finally:
            self.reap()
            self.source = original_source
            self.assertEqual(backend.resolve().parent, self.root.resolve())
            subprocess.run(["/usr/bin/umount", "--", str(backend)], check=True)

    def test_foreign_tmpfs_detached_clone_restores_namespace_and_blocks_reader(self):
        # This root API accepts only a fresh empty alias placeholder. Preserve
        # the older direct-bind tests' nonempty placeholder fixture unchanged.
        self.alias.unlink()
        self.file(self.alias, b"")
        backend = self.root / "foreign-tmpfs"
        self.directory(backend)
        keeper = self.spawn(["/usr/bin/unshare", "--mount", "--propagation", "private",
                             sys.executable, "-B", "-c", FOREIGN_SOURCE, str(backend)], input_pipe=True)
        try:
            self.assertTrue(select.select([keeper.stdout], [], [], 3)[0])
            self.assertEqual(keeper.stdout.readline(), b"SOURCE_READY\n")
            own_ns = pathlib.Path("/proc/self/ns/mnt").stat().st_ino
            foreign_ns = pathlib.Path("/proc", str(keeper.pid), "ns/mnt").stat().st_ino
            self.assertNotEqual(own_ns, foreign_ns)
            foreign_file = pathlib.Path("/proc", str(keeper.pid), "root") / str(backend / "data").lstrip("/")
            original = foreign_file.stat()
            self.assertEqual(foreign_file.read_bytes(), self.original)
            source_status = dict(line.split(":", 1) for line in pathlib.Path("/proc", str(keeper.pid), "status").read_text().splitlines())
            self.assertEqual(source_status["Uid"].split(), ["10001"] * 4)
            self.assertEqual(source_status["Gid"].split(), ["10001"] * 4)
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                self.assertEqual(int(source_status[name], 16), 0)
            self.assertEqual(source_status["NoNewPrivs"].strip(), "1")
            rows = pathlib.Path("/proc", str(keeper.pid), "mountinfo").read_text().splitlines()
            source_row = [row.split() for row in rows if row.split()[4] == str(backend)]
            self.assertEqual(len(source_row), 1)
            self.assertIn("rw", source_row[0][5].split(","))
            self.assertEqual(source_row[0][source_row[0].index("-") + 1], "tmpfs")
            args = ["hold", "--fixture-root", str(self.root), "--case", "reserved", "--kind", "message-signature",
                    "--control-dir", str(self.control), "--digest", "sha256:" + hashlib.sha256(self.original).hexdigest(),
                    "--deadline-seconds", "6"]
            helper = self.spawn(["/usr/bin/unshare", "--mount", "--propagation", "private", sys.executable, "-B", "-c",
                                 FOREIGN_WRAPPER, str(keeper.pid), str(self.root), str(self.root / "bin/fixture_blob_lease.py"), *args])
            self.event(helper, "READY", original)
            reader = self.reader(namespace_pid=keeper.pid, source=backend / "data")
            self.event(helper, "BLOCKED", original)
            self.assertIsNone(reader.poll())
            self.assertEqual(select.select([reader.stdout], [], [], .1)[0], [])
            self.released()
            self.exit(helper)
            self.event(helper, "RELEASED", original)
            output, error = reader.communicate(timeout=3)
            self.assertEqual((reader.returncode, output, error), (0, b"OPENED\n", b""))
            self.assertEqual(foreign_file.read_bytes(), self.original)
            self.assertEqual(pathlib.Path("/proc", str(keeper.pid), "ns/mnt").stat().st_ino, foreign_ns)
            after_rows = pathlib.Path("/proc", str(keeper.pid), "mountinfo").read_text().splitlines()
            self.assertEqual([row.split() for row in after_rows if row.split()[4] == str(backend)], source_row)
            keeper.stdin.write(b"W"); keeper.stdin.flush()
            self.assertTrue(select.select([keeper.stdout], [], [], 2)[0])
            self.assertEqual(keeper.stdout.readline(), b"SOURCE_RW\n")
            keeper.stdin.write(b"X"); keeper.stdin.flush()
            self.exit(keeper)
            self.assertFalse((backend / "data").exists())
        finally:
            # The tmpfs is private to this exact child namespace. Reap all
            # holders/readers before UUID teardown; never umount a host path.
            self.reap()

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
    success = result.wasSuccessful() and not result.skipped and result.testsRun == 14
    if success:
        print("D12_BLOB_LEASE_TESTS=PASS tests=14 passed=14 skipped=0 real_linux=true helper_uid=10001 helper_capabilities=none readonly_file_bind=true")
    elif sys.platform != "linux" and result.wasSuccessful():
        print("D12_BLOB_LEASE_TESTS=AUXILIARY_ONLY real_linux=false")
    raise SystemExit(0 if success or sys.platform != "linux" and result.wasSuccessful() else 1)
