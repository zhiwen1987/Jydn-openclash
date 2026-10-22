#!/usr/bin/env python3
"""Real inert Linux workers test supervisor death, not real Chrome behavior."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
GUARD = HERE / "browser-process-guard.py"
spec = importlib.util.spec_from_file_location("browser_process_guard", GUARD)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise RuntimeError("inert fixture readiness timeout")


def alive(pid):
    p = guard.process(pid)
    return p is not None and p.state not in ("Z", "X")


def write_record(root, pid):
    p = guard.process(pid)
    value = {"pid": pid, "startTicks": p.started, "uid": os.geteuid(), "profile": str(root / "chrome-profile")}
    fd = os.open(root / guard.RECORD, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream)
    return value


def ready_file(path, value):
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(str(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def worker(mode, root):
    # Deliberately inert workers: no browser, HTTP, signing keys or real token.
    if mode == "supervisor":
        leader = subprocess.Popen([sys.executable, "-B", __file__, "--worker", "leader", str(root), "--user-data-dir=" + str(root / "chrome-profile")], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(lambda: (root / "child.pid").exists())
        write_record(root, leader.pid)
        ready_file(root / "supervisor.ready", leader.pid)
        while True:
            time.sleep(1)
    if mode == "leader":
        child = os.fork()
        if child == 0:
            if (root / "crashpad-child").exists():
                os.setsid()
                # exec changes the inert worker argv to the actual crashpad
                # shape: no --user-data-dir, its own session, private database.
                os.execv(sys.executable, ["chrome_crashpad_handler", "-B", __file__, "--worker", "crashpad", str(root), "--database=" + str(root / "chrome-profile" / "config" / "chromium" / "Crash Reports")])
            if (root / "escape-child").exists():
                os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            ready_file(root / "child.pid", os.getpid())
            while True:
                time.sleep(1)
        # The child ignores TERM, proving that terminating or reaping only the
        # group leader is insufficient. The guard must reach the KILL phase.
        while True:
            if (root / "exit-leader").exists():
                os._exit(0)
            time.sleep(0.02)
    if mode == "unrelated":
        while True:
            time.sleep(1)
    if mode == "crashpad":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        ready_file(root / "child.pid", os.getpid())
        while True:
            time.sleep(1)
    raise RuntimeError("invalid inert worker mode")


class GuardParsingTests(unittest.TestCase):
    def test_stat_comm_spaces_and_parentheses(self):
        fields = ["S", "8", "42", "42"] + ["0"] * 15 + ["123456"]
        self.assertEqual(guard.parse_stat(("42 (a tricky ) process) " + " ".join(fields)).encode()), ("S", 42, 42, 123456))

    def test_profile_argument_is_exact(self):
        p = guard.Process(42, 1000, 42, 42, 123, "S", (b"wrapper", b"--user-data-dir=/private/chrome-profile"))
        self.assertTrue(guard.profile_bound(p, "/private/chrome-profile"))
        self.assertFalse(guard.profile_bound(p, "/private/chrome"))

    def test_crashpad_paths_are_canonical_descendants_and_name_limited(self):
        profile = "/private/chrome-profile"
        for argv in (
            (b"/opt/google/chrome/chrome_crashpad_handler", b"--database=/private/chrome-profile/config/google-chrome/Crash Reports"),
            (b"chrome_crashpad_handler", b"--metrics-dir", b"/private/chrome-profile/cache/metrics"),
        ):
            self.assertTrue(guard.profile_bound(guard.Process(42, 1000, 42, 42, 123, "S", argv), profile))
        for argv in (
            (b"chrome_crashpad_handler", b"--database=/private/chrome-profile-other/config"),
            (b"chrome_crashpad_handler", b"--database=/private/chrome-profile/../outside"),
            (b"chrome_crashpad_handler", b"--database=/private/chrome-profile//config"),
            (b"chrome_crashpad_handler", b"--database=/private/chrome-profile/config/./metrics"),
            (b"chrome_crashpad_handler", b"--metrics-dir=relative/chrome-profile/config"),
            (b"chrome_crashpad_handler", b"--metrics-dir=/private/chrome-profile"),
            (b"unrelated", b"--database=/private/chrome-profile/config"),
            (b"fake_chrome_crashpad_handler", b"--database=/private/chrome-profile/config"),
        ):
            self.assertFalse(guard.profile_bound(guard.Process(42, 1000, 42, 42, 123, "S", argv), profile))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() != 0, "requires isolated non-root Linux")
class GuardRealLinuxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="d8-browser-guard-")
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        (self.root / "chrome-profile").mkdir(mode=0o700)
        self.processes = []
        self.owned_pids = set()
        self.owned_started = {}

    def tearDown(self):
        # Test-owned fallback only, never a process-name/global pkill. This
        # prevents a failed assertion from leaking the intentionally inert
        # workers; the test itself still fails if the guard did not stop them.
        for p in self.processes:
            if p.poll() is None:
                self.owned_pids.add(p.pid)
        for pid in self.owned_pids:
            current = guard.process(pid)
            if current is None or self.owned_started.get(pid) != current.started:
                continue
            try:
                fd = os.pidfd_open(pid, 0)
            except ProcessLookupError:
                continue
            try:
                pinned = guard.process(pid)
                if pinned is not None and pinned.started == self.owned_started[pid]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        for p in self.processes:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.fail("inert worker fallback cleanup failed")
        self.temporary.cleanup()

    def launch(self, mode="leader", profile=True):
        args = [sys.executable, "-B", __file__, "--worker", mode, str(self.root)]
        if profile:
            args.append("--user-data-dir=" + str(self.root / "chrome-profile"))
        p = subprocess.Popen(args, start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(p)
        self.owned_started[p.pid] = guard.process(p.pid).started
        if mode == "leader":
            wait_for(lambda: (self.root / "child.pid").exists())
            child = int((self.root / "child.pid").read_text(encoding="ascii"))
            self.owned_pids.add(child)
            self.owned_started[child] = guard.process(child).started
        return p

    def run_guard(self, success=True):
        result = subprocess.run([sys.executable, "-B", str(GUARD), str(self.root)], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0 if success else 1)
        if success:
            self.assertEqual(result.stdout, "D8_BROWSER_PROCESS_GUARD=PASS owned_processes_stopped=true\n")
            self.assertEqual(result.stderr, "")
        else:
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "D8_BROWSER_PROCESS_GUARD=FAIL cleanup_not_proven=true\n")
        return result

    def assert_workers_stopped(self):
        for pid in self.owned_pids:
            self.assertFalse(alive(pid), "guard left an inert group member alive")
        for p in self.processes:
            p.wait(timeout=3)

    def test_supervisor_sigkill_then_real_group_cleanup(self):
        supervisor = self.launch("supervisor", profile=False)
        wait_for(lambda: (self.root / "supervisor.ready").exists())
        leader = int((self.root / "supervisor.ready").read_text(encoding="ascii"))
        child = int((self.root / "child.pid").read_text(encoding="ascii"))
        self.owned_pids.update((leader, child))
        self.owned_started.update({leader: guard.process(leader).started, child: guard.process(child).started})
        supervisor.kill()
        supervisor.wait(timeout=3)
        self.assertTrue(alive(leader))
        self.assertTrue(alive(child))
        self.run_guard()
        self.assert_workers_stopped()
        self.run_guard()

    def test_leader_exits_but_child_remains_in_original_group(self):
        leader = self.launch()
        write_record(self.root, leader.pid)
        (self.root / "exit-leader").touch(mode=0o600)
        leader.wait(timeout=3)
        child = next(iter(self.owned_pids))
        self.assertTrue(alive(child))
        self.run_guard()
        self.assert_workers_stopped()

    def test_profile_bound_child_escapes_original_group(self):
        (self.root / "escape-child").touch(mode=0o600)
        leader = self.launch()
        write_record(self.root, leader.pid)
        child = next(iter(self.owned_pids))
        self.assertNotEqual(guard.process(child).group, leader.pid)
        self.run_guard()
        self.assert_workers_stopped()

    def test_escaped_crashpad_without_user_data_dir_and_similar_prefix_survives(self):
        (self.root / "crashpad-child").touch(mode=0o600)
        leader = self.launch()
        write_record(self.root, leader.pid)
        child = next(iter(self.owned_pids))
        actual = guard.process(child)
        self.assertNotEqual(actual.group, leader.pid)
        self.assertFalse(any(arg.startswith(b"--user-data-dir") for arg in actual.argv))
        unrelated = subprocess.Popen(["chrome_crashpad_handler", "-B", __file__, "--worker", "unrelated", str(self.root), "--database=" + str(self.root / "chrome-profile-other" / "config")], executable=sys.executable, start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(unrelated)
        self.owned_started[unrelated.pid] = guard.process(unrelated.pid).started
        self.run_guard()
        self.assertFalse(alive(leader.pid))
        self.assertFalse(alive(child))
        self.assertTrue(alive(unrelated.pid), "similar-prefix crashpad must not be a target")
        self.run_guard()

    def test_wrong_start_rejected_without_signalling_any_process(self):
        leader = self.launch()
        record = write_record(self.root, leader.pid)
        record["startTicks"] += 1
        (self.root / guard.RECORD).write_text(json.dumps(record), encoding="utf-8")
        unrelated = self.launch("unrelated", profile=False)
        self.run_guard(success=False)
        self.assertTrue(alive(leader.pid))
        self.assertTrue(alive(unrelated.pid))
        self.assertTrue(all(alive(pid) for pid in self.owned_pids))

    def test_wrong_pid_rejected_without_harming_unrelated_session(self):
        unrelated = self.launch("unrelated", profile=False)
        write_record(self.root, unrelated.pid)
        self.run_guard(success=False)
        self.assertTrue(alive(unrelated.pid))

    def test_private_record_checks_fail_closed(self):
        leader = self.launch()
        record = write_record(self.root, leader.pid)
        path = self.root / guard.RECORD
        for mutation in ("mode", "symlink", "hardlink", "profile", "unknown", "boolean-pid"):
            with self.subTest(mutation=mutation):
                if path.exists() or path.is_symlink():
                    path.unlink()
                path.write_text(json.dumps(record), encoding="utf-8")
                path.chmod(0o600)
                if mutation == "mode":
                    path.chmod(0o640)
                elif mutation == "symlink":
                    target = self.root / "record-target"
                    path.rename(target)
                    path.symlink_to(target)
                elif mutation == "hardlink":
                    os.link(path, self.root / "record-link")
                else:
                    changed = dict(record)
                    if mutation == "profile":
                        changed["profile"] += "-other"
                    elif mutation == "unknown":
                        changed["extra"] = True
                    else:
                        changed["pid"] = True
                    path.write_text(json.dumps(changed), encoding="utf-8")
                self.run_guard(success=False)
                self.assertTrue(alive(leader.pid))

    def test_missing_record_no_process_is_idempotent(self):
        self.run_guard()
        self.run_guard()


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--worker":
        worker(sys.argv[2], Path(sys.argv[3]))
    else:
        suite = unittest.main(exit=False)
        success = suite.result.wasSuccessful() and not suite.result.skipped
        if success and sys.platform == "linux" and suite.result.testsRun >= 9:
            print("D8_BROWSER_PROCESS_GUARD_TESTS=PASS real_linux_processes=true simulated_chrome=true")
        sys.exit(0 if success else 1)
