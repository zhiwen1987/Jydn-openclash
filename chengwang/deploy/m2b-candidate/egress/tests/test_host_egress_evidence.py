from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "host_egress_evidence.py"
SPEC = importlib.util.spec_from_file_location("host_egress_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


CONTAINER_ID = "a" * 64
NETWORK_ID = "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
PROJECT = "m2b-probe-test"
BRIDGE = "br-" + NETWORK_ID[:12]
NOW = 2_000_000_000


def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def rule(chain, comment, expressions, packets):
    return {
        "rule": {
            "family": "inet", "table": "cw_probe", "chain": chain, "handle": len(comment),
            "expr": expressions[:-2] + [{"counter": {"packets": packets, "bytes": packets * 100}}, expressions[-1]],
            "comment": comment,
        }
    }


def ruleset(delta=0):
    nf = lambda family: {"meta": {"key": "nfproto"}}
    d4 = {"payload": {"protocol": "ip", "field": "daddr"}}
    d6 = {"payload": {"protocol": "ip6", "field": "daddr"}}
    tcp = {"meta": {"key": "l4proto"}}
    port = {"payload": {"protocol": "tcp", "field": "dport"}}
    return {
        "nftables": [
            {"metainfo": {"version": "1.0.6", "release_name": "fixture"}},
            {"table": {"family": "inet", "name": "cw_probe", "handle": 1}},
            {"chain": {"family": "inet", "table": "cw_probe", "name": "entry", "type": "filter", "hook": "forward", "prio": -5, "policy": "accept"}},
            {"chain": {"family": "inet", "table": "cw_probe", "name": "policy"}},
            rule("entry", "chengwang:v1:entry", [match({"meta": {"key": "iifname"}}, BRIDGE), {}, {"jump": {"target": "policy"}}], 10 + delta),
            rule("policy", "chengwang:v1:allow-dot4", [match(nf("ipv4"), "ipv4"), match(d4, "1.1.1.1"), match(tcp, "tcp"), match(port, 853), {}, {"accept": None}], 3 + delta),
            rule("policy", "chengwang:v1:allow-probe4", [match(nf("ipv4"), "ipv4"), match(d4, "93.184.216.34"), match(tcp, "tcp"), match(port, 443), {}, {"accept": None}], 4 + delta),
            rule("policy", "chengwang:v1:deny4", [match(nf("ipv4"), "ipv4"), {}, {"drop": None}], 5 + delta),
            rule("policy", "chengwang:v1:deny6", [match(nf("ipv6"), "ipv6"), {}, {"drop": None}], 6 + delta),
        ]
    }


def snapshot(captured, delta=0, internal=False):
    return {
        "schema": MODULE.SNAPSHOT_SCHEMA,
        "capturedStartedUnix": captured,
        "capturedFinishedUnix": captured,
        "bootId": BOOT_ID,
        "netns": {"path": "/var/run/docker/netns/fixture", "device": 42, "inode": 4242, "pid": 1234, "processStartTicks": 5678},
        "container": {
            "id": CONTAINER_ID, "imageId": IMAGE_ID, "running": True, "projectName": PROJECT,
            "serviceName": "probe-agent", "networkName": "probe-net", "networkId": NETWORK_ID,
            "ipv4Address": "172.30.0.2", "ipv6Address": "",
        },
        "network": {
            "id": NETWORK_ID, "name": "probe-net", "internal": internal, "attachable": False,
            "bridgeName": BRIDGE, "attachedContainerIds": [CONTAINER_ID],
        },
        "nftRuleset": ruleset(delta),
    }


class EvidenceTests(unittest.TestCase):
    def write_json(self, directory, name, value):
        path = pathlib.Path(directory) / name
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return path

    def inputs(self, directory):
        catalog = {
            "schema": "chengwang.probe-catalog/v1",
            "revision": "fixture-v1",
            "agent": {"id": "fixture-agent", "independence": "P1", "advisoryOnly": True},
            "paths": [{"id": "direct", "kind": "direct"}],
            "probes": [{
                "id": "owned-canary", "pathId": "direct", "kind": "https", "host": "example.com",
                "port": 443, "requestPath": "/healthz", "method": "GET", "expectedStatus": [200],
                "requiredMarker": "fixture", "intervalSeconds": 300, "timeoutSeconds": 5,
                "ttlSeconds": 600, "maxBodyBytes": 4096,
            }],
        }
        catalog_path = self.write_json(directory, "catalog.json", catalog)
        catalog_sha = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
        catalog_digest = MODULE._catalog_probes(catalog)[1]
        plan = {
            "schema": MODULE.PLAN_SCHEMA,
            "revision": "fixture-v1",
            "approval": {"status": "approved", "owner": "fixture-owner", "approvedUnix": NOW - 60},
            "candidateRoot": "/var/lib/chengwang/test",
            "projectName": PROJECT,
            "imageId": IMAGE_ID,
            "catalogSha256": catalog_sha,
            "catalogDigest": catalog_digest,
            "validUntilUnix": NOW + 300,
            "resolver": {"endpoint": "1.1.1.1:853", "serverName": "one.one.one.one"},
            "nft": {"family": "inet", "table": "cw_probe", "entryChain": "entry", "entryPriority": -5, "policyChain": "policy", "bridgeName": BRIDGE},
            "probeResolutions": [{
                "probeId": "owned-canary", "queryName": "example.com", "cnameChain": ["example.com"],
                "addresses": ["93.184.216.34"], "resolvedUnix": NOW - 30, "expiresUnix": NOW + 270,
            }],
        }
        plan_path = self.write_json(directory, "plan.json", plan)
        evidence_id = "evidence:" + hashlib.sha256(plan_path.read_bytes()).hexdigest()
        policy = {
            "schema": "chengwang.probe-egress-policy/v1",
            "revision": "fixture-v1",
            "approval": {"status": "approved", "owner": "fixture-owner", "approvedAt": "2033-05-18T03:32:00Z"},
            "enforcement": {"state": "enforced", "mode": "default-deny", "runtimeEvidence": evidence_id},
            "allowedDestinations": [
                {"schema": "chengwang.probe-egress-destination/v1", "kind": "fixed-dot", "endpoint": "1.1.1.1:853", "serverName": "one.one.one.one"},
                {"schema": "chengwang.probe-egress-destination/v1", "kind": "catalog-probe", "probeId": "owned-canary", "catalogDigest": catalog_digest},
            ],
        }
        return (
            self.write_json(directory, "before.json", snapshot(NOW - 20, 0)),
            self.write_json(directory, "after.json", snapshot(NOW - 10, 1)),
            plan_path,
            catalog_path,
            self.write_json(directory, "policy.json", policy),
            pathlib.Path(directory) / "compose.yaml",
        )

    def invoke(self, directory, paths):
        compose = paths[-1]
        compose.write_text("services: {}\n", encoding="utf-8")
        output = pathlib.Path(directory) / "report.json"
        with self.assertRaises(SystemExit) as raised:
            MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, output, now=NOW)
        self.assertEqual(raised.exception.code, 78)
        return json.loads(output.read_text(encoding="utf-8"))

    def rewrite_plan_and_bind_policy(self, directory, paths, plan):
        plan_path = self.write_json(directory, "plan-updated.json", plan)
        policy = json.loads(paths[4].read_text(encoding="utf-8"))
        policy["enforcement"]["runtimeEvidence"] = "evidence:" + hashlib.sha256(plan_path.read_bytes()).hexdigest()
        paths[2] = plan_path
        paths[4] = self.write_json(directory, "policy-updated.json", policy)

    def test_valid_raw_evidence_is_explicitly_blocked_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.invoke(directory, self.inputs(directory))
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["reason"], "INTEGRATION_CONTRACTS_INCOMPLETE")
            self.assertEqual(report["schema"], MODULE.REPORT_SCHEMA)
            self.assertNotEqual(report["schema"], MODULE.EVIDENCE_SCHEMA)
            self.assertEqual(report["counters"]["resolverAllowedAfter"], 4)
            self.assertEqual(report["counters"]["canaryAllowedAfter"], 5)
            self.assertEqual(report["counters"]["deniedAfter"], 13)

    def test_internal_network_is_rejected_as_non_routable(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            after = snapshot(NOW - 10, 1, internal=True)
            paths[1] = self.write_json(directory, "after-internal.json", after)
            paths[-1].write_text("services: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "non-internal"):
                MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, pathlib.Path(directory) / "report.json", now=NOW)

    def test_undeclared_accept_rule_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            after = snapshot(NOW - 10, 1)
            extra = copy.deepcopy(after["nftRuleset"]["nftables"][5])
            extra["rule"]["comment"] = "chengwang:v1:undeclared"
            after["nftRuleset"]["nftables"].insert(-2, extra)
            paths[1] = self.write_json(directory, "after-extra.json", after)
            paths[-1].write_text("services: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "structure changed"):
                MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, pathlib.Path(directory) / "report.json", now=NOW)

    def test_counter_without_growth_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            paths[1] = self.write_json(directory, "after-flat.json", snapshot(NOW - 10, 0))
            paths[-1].write_text("services: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "counter did not increase"):
                MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, pathlib.Path(directory) / "report.json", now=NOW)

    def test_policy_must_bind_exact_plan_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            policy = json.loads(paths[4].read_text(encoding="utf-8"))
            policy["enforcement"]["runtimeEvidence"] = "evidence:" + "0" * 64
            paths[4] = self.write_json(directory, "policy-wrong.json", policy)
            paths[-1].write_text("services: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "exact egress plan"):
                MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, pathlib.Path(directory) / "report.json", now=NOW)

    def test_duplicate_json_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "duplicate JSON key"):
                MODULE.load_json(path)

    def test_hardlinked_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            first = pathlib.Path(directory) / "first.json"
            second = pathlib.Path(directory) / "second.json"
            first.write_text("{}", encoding="utf-8")
            try:
                second.hardlink_to(first)
            except OSError:
                self.skipTest("hardlinks are unavailable")
            with self.assertRaisesRegex(MODULE.ContractError, "single-link"):
                MODULE.load_json(first)

    def test_oversized_and_relative_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            oversized = pathlib.Path(directory) / "oversized.json"
            oversized.write_bytes(b"x" * 33)
            with self.assertRaisesRegex(MODULE.ContractError, "exceeds"):
                MODULE.load_json(oversized, 32)
        with self.assertRaisesRegex(MODULE.ContractError, "absolute"):
            MODULE.secure_read(pathlib.Path("relative.json"), 32)

    def test_relative_command_is_rejected_before_execution(self):
        with self.assertRaisesRegex(MODULE.ContractError, "absolute executable"):
            MODULE.run_json(["docker", "inspect", CONTAINER_ID])

    @unittest.skipUnless(sys.platform == "linux", "process-group regression requires Linux")
    def test_closed_pipes_then_hang_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = pathlib.Path(directory) / "child.pid"
            script = (
                "import os,pathlib,time;"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()));"
                "os.close(1);os.close(2);time.sleep(60)"
            )
            descriptor = os.open(sys.executable, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(MODULE.ContractError, "timed out"):
                    MODULE._run_bounded_process([sys.executable, "-c", script], descriptor, 0.25, 1024)
            finally:
                os.close(descriptor)
            self.assertLess(time.monotonic() - started, 3)
            pid = int(pid_path.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    @unittest.skipUnless(sys.platform == "linux", "process-group regression requires Linux")
    def test_exited_parent_cannot_leave_pipe_holding_grandchild(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = pathlib.Path(directory) / "grandchild.pid"
            grandchild = (
                "import os,pathlib,time;"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()));"
                "time.sleep(60)"
            )
            parent = (
                "import subprocess,sys;"
                f"subprocess.Popen([sys.executable,'-c',{grandchild!r}])"
            )
            descriptor = os.open(sys.executable, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(MODULE.ContractError, "timed out"):
                    MODULE._run_bounded_process([sys.executable, "-c", parent], descriptor, 0.5, 1024)
            finally:
                os.close(descriptor)
            self.assertLess(time.monotonic() - started, 3)
            self.assertTrue(pid_path.is_file())
            pid = int(pid_path.read_text(encoding="ascii"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("pipe-holding grandchild survived process-group cleanup")

    def test_arbitrary_absolute_executable_is_not_approved(self):
        executable = pathlib.Path(sys.executable).resolve()
        with self.assertRaisesRegex(MODULE.ContractError, "not an approved fixed executable"):
            MODULE._approved_executable(str(executable), "Docker executable", "docker")

    def test_go_public_ip_boundary_is_mirrored(self):
        for address in ("192.0.2.1", "100.64.0.1", "169.254.169.254", "2001:db8::1", "3fff::1", "::ffff:8.8.8.8"):
            with self.subTest(address=address), self.assertRaises(MODULE.ContractError):
                MODULE._public_ip(address)
        for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                self.assertEqual(MODULE._public_ip(address), address)

    def test_cname_loop_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            plan = json.loads(paths[2].read_text(encoding="utf-8"))
            plan["probeResolutions"][0]["cnameChain"] = ["example.com", "example.com"]
            self.rewrite_plan_and_bind_policy(directory, paths, plan)
            paths[-1].write_text("services: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "duplicate or loop"):
                MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, pathlib.Path(directory) / "report.json", now=NOW)

    def test_nft_projection_drops_unrelated_secret_and_rejects_unlabelled_managed_rule(self):
        managed = ruleset(0)["nftables"]
        raw = {"nftables": managed + [
            {"table": {"family": "inet", "name": "other"}},
            {"rule": {"family": "inet", "table": "other", "chain": "x", "comment": "SECRET_TOKEN", "expr": []}},
        ]}
        projected = MODULE._project_nft_ruleset(raw, "inet", "cw_probe")
        self.assertNotIn("SECRET_TOKEN", json.dumps(projected))
        malformed = copy.deepcopy(raw)
        malformed["nftables"].append({"rule": {"family": "inet", "table": "cw_probe", "chain": "policy", "comment": "SECRET_TOKEN", "expr": []}})
        with self.assertRaisesRegex(MODULE.ContractError, "unlabelled"):
            MODULE._project_nft_ruleset(malformed, "inet", "cw_probe")
        flagged = copy.deepcopy(raw)
        flagged["nftables"][1]["table"]["flags"] = ["dormant"]
        with self.assertRaisesRegex(MODULE.ContractError, "unsupported flags"):
            MODULE._project_nft_ruleset(flagged, "inet", "cw_probe")

    def test_docker_projection_never_persists_environment_mounts_or_unrelated_labels(self):
        container = {
            "Id": CONTAINER_ID, "Image": IMAGE_ID, "State": {"Running": True},
            "Config": {
                "Env": ["API_KEY=SUPER_SECRET"],
                "Labels": {
                    "com.docker.compose.project": PROJECT,
                    "com.docker.compose.service": "probe-agent",
                    "secret-label": "SUPER_SECRET",
                },
            },
            "Mounts": [{"Source": "/secret/path", "Destination": "/run/secret"}],
            "NetworkSettings": {"Networks": {"probe-net": {
                "NetworkID": NETWORK_ID, "IPAddress": "172.30.0.2", "GlobalIPv6Address": "",
            }}},
        }
        network = {
            "Id": NETWORK_ID, "Name": "probe-net", "Internal": False, "Attachable": False,
            "Options": {}, "Containers": {CONTAINER_ID: {"Name": "probe-agent", "Secret": "SUPER_SECRET"}},
        }
        projected = MODULE._project_docker(container, network)
        serialized = json.dumps(projected)
        self.assertNotIn("SUPER_SECRET", serialized)
        self.assertNotIn("/secret/path", serialized)
        self.assertNotIn("secret-label", serialized)

    def test_ipv6_dot_and_probe_contract_remains_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            dot6 = "2606:4700:4700::1111"
            probe6 = "2606:2800:220:1:248:1893:25c8:1946"
            plan = json.loads(paths[2].read_text(encoding="utf-8"))
            plan["resolver"]["endpoint"] = f"[{dot6}]:853"
            plan["probeResolutions"][0]["addresses"] = [probe6]
            self.rewrite_plan_and_bind_policy(directory, paths, plan)
            policy = json.loads(paths[4].read_text(encoding="utf-8"))
            policy["allowedDestinations"][0]["endpoint"] = f"[{dot6}]:853"
            paths[4] = self.write_json(directory, "policy-ipv6.json", policy)

            def ipv6_rules(delta):
                value = ruleset(delta)
                for entry in value["nftables"]:
                    item = entry.get("rule") if isinstance(entry, dict) else None
                    if not isinstance(item, dict):
                        continue
                    if item.get("comment") == "chengwang:v1:allow-dot4":
                        item["comment"] = "chengwang:v1:allow-dot6"
                        item["expr"][0]["match"]["right"] = "ipv6"
                        item["expr"][1]["match"]["left"]["payload"]["protocol"] = "ip6"
                        item["expr"][1]["match"]["right"] = dot6
                    if item.get("comment") == "chengwang:v1:allow-probe4":
                        item["comment"] = "chengwang:v1:allow-probe6"
                        item["expr"][0]["match"]["right"] = "ipv6"
                        item["expr"][1]["match"]["left"]["payload"]["protocol"] = "ip6"
                        item["expr"][1]["match"]["right"] = probe6
                return value

            before = snapshot(NOW - 20, 0)
            after = snapshot(NOW - 10, 1)
            before["nftRuleset"] = ipv6_rules(0)
            after["nftRuleset"] = ipv6_rules(1)
            paths[0] = self.write_json(directory, "before-ipv6.json", before)
            paths[1] = self.write_json(directory, "after-ipv6.json", after)
            report = self.invoke(directory, paths)
            self.assertEqual(report["status"], "BLOCKED")

    def test_shared_cdn_ip_across_probes_is_deduplicated_not_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            catalog = json.loads(paths[3].read_text(encoding="utf-8"))
            second = copy.deepcopy(catalog["probes"][0])
            second["id"] = "owned-canary-two"
            catalog["probes"].append(second)
            paths[3] = self.write_json(directory, "catalog-shared.json", catalog)
            catalog_sha = hashlib.sha256(paths[3].read_bytes()).hexdigest()
            catalog_digest = MODULE._catalog_probes(catalog)[1]

            plan = json.loads(paths[2].read_text(encoding="utf-8"))
            plan["catalogSha256"] = catalog_sha
            plan["catalogDigest"] = catalog_digest
            second_resolution = copy.deepcopy(plan["probeResolutions"][0])
            second_resolution["probeId"] = "owned-canary-two"
            plan["probeResolutions"].append(second_resolution)
            self.rewrite_plan_and_bind_policy(directory, paths, plan)
            policy = json.loads(paths[4].read_text(encoding="utf-8"))
            policy["allowedDestinations"][1]["catalogDigest"] = catalog_digest
            policy["allowedDestinations"].append({
                "schema": "chengwang.probe-egress-destination/v1", "kind": "catalog-probe",
                "probeId": "owned-canary-two", "catalogDigest": catalog_digest,
            })
            paths[4] = self.write_json(directory, "policy-shared.json", policy)
            report = self.invoke(directory, paths)
            self.assertEqual(report["status"], "BLOCKED")

    def test_future_policy_approval_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = list(self.inputs(directory))
            policy = json.loads(paths[4].read_text(encoding="utf-8"))
            policy["approval"]["approvedAt"] = "2099-01-01T00:00:00Z"
            paths[4] = self.write_json(directory, "policy-future.json", policy)
            paths[-1].write_text("services: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "in the future"):
                MODULE.verify(*paths, "/var/lib/chengwang/test", PROJECT, IMAGE_ID, CONTAINER_ID, pathlib.Path(directory) / "report.json", now=NOW)


if __name__ == "__main__":
    unittest.main()
