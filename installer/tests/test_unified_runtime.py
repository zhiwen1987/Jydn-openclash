import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


UPSTREAM = Path(__file__).resolve().parents[1] / "runtime/upstream"
sys.path.insert(0, str(UPSTREAM))
SPEC = importlib.util.spec_from_file_location("unified_runtime", UPSTREAM / "unified_runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class FakeProcess:
    def __init__(self, pid, exit_code=None):
        self.pid = pid
        self.exit_code = exit_code

    def poll(self):
        return self.exit_code


class ReadyResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class SupervisorRequestTests(unittest.TestCase):
    def test_dns_request_ack_is_bound_to_id_pid_and_loaded_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            payload = b".:53 { reload }\n"
            digest = hashlib.sha256(payload).hexdigest()

            def launch(name, recovery=False):
                supervisor.children[name] = FakeProcess(101)
                return True

            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate"), \
                 mock.patch.object(supervisor, "launch", side_effect=launch), \
                 mock.patch.object(runtime.urllib.request, "urlopen", return_value=ReadyResponse()):
                now = time.time()
                self.assertTrue(supervisor.request("dns", "dns-request-0001", digest, None, now, now + 20, "apply"))
            result = supervisor.last_request
            self.assertEqual(result["id"], "dns-request-0001")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["old_pid"], 100)
            self.assertEqual(result["new_pid"], 101)
            self.assertEqual(result["loaded_core_sha256"], digest)

    def test_dns_hash_mismatch_fails_without_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            with mock.patch.object(runtime.Path, "read_bytes", return_value=b"actual"), \
                 mock.patch.object(supervisor, "terminate") as terminate:
                now = time.time()
                self.assertFalse(supervisor.request("dns", "dns-request-0002", "0" * 64, None, now, now + 20, "apply"))
            terminate.assert_not_called()
            self.assertEqual(supervisor.last_request["state"], "failed")
            self.assertEqual(supervisor.last_request["error_code"], "corefile_hash_mismatch")

    def test_expired_dns_request_is_failed_without_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            with mock.patch.object(supervisor, "terminate") as terminate:
                now = time.time()
                self.assertFalse(supervisor.request("dns", "dns-request-0003", "0" * 64,
                                                    None, now - 25, now - 5, "apply"))
            terminate.assert_not_called()
            self.assertEqual(supervisor.last_request["error_code"], "request_expired")

    def test_expiry_crossed_during_terminate_relaunches_but_never_completes(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            payload = b".:53 { reload }\n"
            digest = hashlib.sha256(payload).hexdigest()

            def terminate(_name, _grace=20):
                time.sleep(1.15)

            def launch(name, recovery=False):
                supervisor.children[name] = FakeProcess(101)
                return True

            now = time.time()
            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate", side_effect=terminate), \
                 mock.patch.object(supervisor, "launch", side_effect=launch):
                self.assertFalse(supervisor.request("dns", "dns-request-0004", digest,
                                                    None, now, now + 1.05, "apply"))
            self.assertEqual(supervisor.children["dns"].pid, 101)
            self.assertEqual(supervisor.last_request["state"], "failed")
            self.assertEqual(supervisor.last_request["error_code"], "request_expired")

    def test_one_linked_recovery_can_cross_budget_but_cannot_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            payload = b".:53 { reload }\n"
            digest = hashlib.sha256(payload).hexdigest()
            now = time.time()
            supervisor.state["events"] = [
                {"component": "dns", "at": now - 10}, {"component": "dns", "at": now - 5},
            ]
            # This represents a verified request that already crossed the
            # process stop boundary and then failed its readback.
            supervisor.request_result(
                "dns-failed-parent", "failed", now - 1, 99,
                error="dns_restart_not_verified", purpose="rollback", recoverable=True,
            )

            def launch(name, recovery=False):
                supervisor.children[name] = FakeProcess(101)
                return True

            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate"), \
                 mock.patch.object(supervisor, "launch", side_effect=launch), \
                 mock.patch.object(runtime.urllib.request, "urlopen", return_value=ReadyResponse()):
                started = time.time()
                self.assertTrue(supervisor.request(
                    "dns", "dns-recovery-0001", digest, None, started, started + 20,
                    "recovery", "dns-failed-parent",
                ))
            self.assertTrue(supervisor.last_request["budget_override"])
            self.assertEqual(supervisor.last_request["recovery_of"], "dns-failed-parent")
            self.assertTrue(supervisor.state["events"][-1]["budget_override"])

            # The same failed transaction cannot authorize a second exception.
            supervisor.children["dns"] = FakeProcess(102)
            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate") as terminate:
                started = time.time()
                self.assertFalse(supervisor.request(
                    "dns", "dns-recovery-0002", digest, None, started, started + 20,
                    "recovery", "dns-failed-parent",
                ))
            terminate.assert_not_called()
            self.assertEqual(supervisor.last_request["error_code"], "invalid_recovery_reference")

    def test_budget_denial_cannot_mint_repeatable_recovery_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            payload = b".:53 { reload }\n"
            digest = hashlib.sha256(payload).hexdigest()
            now = time.time()
            supervisor.state["events"] = [
                {"component": "dns", "at": now - 10}, {"component": "dns", "at": now - 5},
            ]
            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate") as terminate:
                for suffix in ("0001", "0002"):
                    started = time.time()
                    parent = "dns-budget-parent-" + suffix
                    self.assertFalse(supervisor.request(
                        "dns", parent, digest, None, started, started + 20, "apply",
                    ))
                    self.assertEqual(supervisor.last_request["error_code"], "restart_budget_refused")
                    self.assertNotIn(parent, supervisor.failed_requests)
                    recovery_at = time.time()
                    self.assertFalse(supervisor.request(
                        "dns", "dns-recovery-" + suffix, digest, None,
                        recovery_at, recovery_at + 20, "recovery", parent,
                    ))
                    self.assertEqual(supervisor.last_request["error_code"], "invalid_recovery_reference")
            terminate.assert_not_called()

    def test_completed_parent_can_authorize_one_probe_failure_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            candidate = b".:53 { reload 2s }\n"
            original = b".:53 { reload }\n"
            current = {"payload": candidate, "pid": 100}

            def read_bytes(_path):
                return current["payload"]

            def launch(name, recovery=False):
                current["pid"] += 1
                supervisor.children[name] = FakeProcess(current["pid"])
                return True

            with mock.patch.object(runtime.Path, "read_bytes", autospec=True, side_effect=read_bytes), \
                 mock.patch.object(supervisor, "terminate"), \
                 mock.patch.object(supervisor, "launch", side_effect=launch), \
                 mock.patch.object(runtime.urllib.request, "urlopen", return_value=ReadyResponse()):
                started = time.time()
                self.assertTrue(supervisor.request(
                    "dns", "dns-apply-completed", hashlib.sha256(candidate).hexdigest(),
                    None, started, started + 20, "apply",
                ))
                self.assertIn("dns-apply-completed", supervisor.failed_requests)
                # The manager has now observed a real post-reload probe failure,
                # atomically restored the old bytes, and asks for one linked reload.
                current["payload"] = original
                supervisor.state["events"].append({"component": "dns", "at": time.time()})
                recovery_at = time.time()
                self.assertTrue(supervisor.request(
                    "dns", "dns-recovery-probe", hashlib.sha256(original).hexdigest(),
                    None, recovery_at, recovery_at + 20,
                    "recovery", "dns-apply-completed",
                ))
                second_at = time.time()
                self.assertFalse(supervisor.request(
                    "dns", "dns-recovery-probe2", hashlib.sha256(original).hexdigest(),
                    None, second_at, second_at + 20,
                    "recovery", "dns-apply-completed",
                ))
            self.assertEqual(supervisor.last_request["error_code"], "invalid_recovery_reference")

    def test_launch_exception_after_stop_preserves_linked_recovery_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            candidate = b".:53 { reload 2s }\n"
            original = b".:53 { reload }\n"
            current = {"payload": candidate}
            launch_calls = {"count": 0}

            def launch(name, recovery=False):
                launch_calls["count"] += 1
                if launch_calls["count"] <= 2:
                    raise OSError("isolated-popen-failure")
                supervisor.children[name] = FakeProcess(103)
                return True

            with mock.patch.object(runtime.Path, "read_bytes", autospec=True,
                                   side_effect=lambda _path: current["payload"]), \
                 mock.patch.object(supervisor, "terminate"), \
                 mock.patch.object(supervisor, "launch", side_effect=launch), \
                 mock.patch.object(runtime.urllib.request, "urlopen", return_value=ReadyResponse()):
                started = time.time()
                self.assertFalse(supervisor.request(
                    "dns", "dns-launch-failed", hashlib.sha256(candidate).hexdigest(),
                    None, started, started + 20, "apply",
                ))
                self.assertEqual(supervisor.last_request["purpose"], "apply")
                self.assertTrue(supervisor.last_request["recoverable"])
                self.assertIn("dns-launch-failed", supervisor.failed_requests)

                # No DNS process is running.  A linked recovery is still
                # allowed to launch the restored configuration from scratch.
                supervisor.children["dns"] = FakeProcess(100, exit_code=1)
                current["payload"] = original
                recovery_at = time.time()
                self.assertTrue(supervisor.request(
                    "dns", "dns-recover-launch", hashlib.sha256(original).hexdigest(),
                    None, recovery_at, recovery_at + 20,
                    "recovery", "dns-launch-failed",
                ))
            self.assertEqual(supervisor.last_request["state"], "completed")
            self.assertEqual(supervisor.children["dns"].pid, 103)

    def test_terminate_exception_only_mints_authority_when_old_pid_is_proven_dead(self):
        payload = b".:53 { reload }\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            old = FakeProcess(100)
            supervisor.children["dns"] = old
            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate", side_effect=OSError("still-running")):
                started = time.time()
                self.assertFalse(supervisor.request(
                    "dns", "dns-terminate-live", digest, None, started, started + 20, "apply",
                ))
                self.assertFalse(supervisor.last_request["recoverable"])
                self.assertNotIn("dns-terminate-live", supervisor.failed_requests)
                recovery_at = time.time()
                self.assertFalse(supervisor.request(
                    "dns", "dns-recovery-live", digest, None, recovery_at, recovery_at + 20,
                    "recovery", "dns-terminate-live",
                ))
                self.assertEqual(supervisor.last_request["error_code"], "invalid_recovery_reference")

        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            old = FakeProcess(200)
            supervisor.children["dns"] = old
            launches = {"pid": 200}

            def terminate_then_raise(_name, _grace=20):
                old.exit_code = 1
                raise OSError("stopped")

            def launch(name, recovery=False):
                launches["pid"] += 1
                supervisor.children[name] = FakeProcess(launches["pid"])
                return True

            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate", side_effect=terminate_then_raise), \
                 mock.patch.object(supervisor, "launch", side_effect=launch):
                started = time.time()
                self.assertFalse(supervisor.request(
                    "dns", "dns-terminate-dead", digest, None, started, started + 20, "rollback",
                ))
            self.assertTrue(supervisor.last_request["recoverable"])
            self.assertIn("dns-terminate-dead", supervisor.failed_requests)
            with mock.patch.object(runtime.Path, "read_bytes", return_value=payload), \
                 mock.patch.object(supervisor, "terminate"), \
                 mock.patch.object(supervisor, "launch", side_effect=launch), \
                 mock.patch.object(runtime.urllib.request, "urlopen", return_value=ReadyResponse()):
                recovery_at = time.time()
                self.assertTrue(supervisor.request(
                    "dns", "dns-recovery-dead", digest, None, recovery_at, recovery_at + 20,
                    "recovery", "dns-terminate-dead",
                ))

    def test_invalid_or_failed_recovery_cannot_mint_recovery_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = runtime.Supervisor(services={"dns": ["unused"]}, root=Path(temporary))
            supervisor.children["dns"] = FakeProcess(100)
            now = time.time()
            self.assertFalse(supervisor.request(
                "dns", "dns-invalid-0001", "0" * 64, None, now, now + 20,
                "recovery", "missing-parent",
            ))
            self.assertNotIn("dns-invalid-0001", supervisor.failed_requests)
            supervisor.request_result(
                "dns-recovery-failed", "failed", now, 100,
                error="dns_restart_not_verified", purpose="recovery",
                recovery_of="dns-prior", recoverable=True,
            )
            self.assertNotIn("dns-recovery-failed", supervisor.failed_requests)


if __name__ == "__main__":
    unittest.main()
