import copy
import importlib.util
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[1] / "compile_egress_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("compile_egress_bootstrap", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def sample_input():
    return {
        "schema": MODULE.INPUT_SCHEMA,
        "revision": "candidate-r1",
        "validationUnix": 2_000_000_100,
        "candidate": {
            "projectName": "chengwang_probe_candidate",
            "serviceName": "probe-agent",
            "imageId": "sha256:" + "1" * 64,
            "composeSha256": "2" * 64,
            "resolverMode": "DIRECT_DOT_ONLY_NO_SYSTEM_RESOLVER",
        },
        "network": {
            "name": "m2b_probe_egress",
            "driver": "bridge",
            "internal": False,
            "attachable": False,
            "bridgeName": "cwprobe0",
            "enableIcc": False,
            "enableIpv6": True,
            "ipv4": {"subnet": "172.31.254.0/29", "gateway": "172.31.254.1", "containerAddress": "172.31.254.2"},
            "ipv6": {"subnet": "fd42:88:2::/64", "gateway": "fd42:88:2::1", "containerAddress": "fd42:88:2::2"},
        },
        "identityBinding": {
            "mode": "pending-runtime", "containerId": None, "containerPid": None,
            "pidStartTime": None, "netnsInode": None, "cgroupId": None,
            "vethHostIfindex": None,
        },
        "firewall": {
            "family": "inet", "table": "cw_probe",
            "forwardEntryChain": "cw_fwd_entry", "forwardPolicyChain": "cw_fwd_policy",
            "inputEntryChain": "cw_in_entry", "inputPolicyChain": "cw_in_policy",
            "forwardPriority": -25, "inputPriority": -25,
            "basePolicy": "accept", "allowPlainDns": False, "allowDhcp": False,
            "allowIpv6NeighborDiscovery": True,
            "globalImpactApproval": "unproven",
        },
        "resolver": {
            "serverName": "dns.example.com", "port": 853, "transport": "tcp-tls",
            "addresses": ["1.1.1.1", "2606:4700:4700::1111"],
            "observedUnix": 2_000_000_000, "expiresUnix": 2_000_003_600,
        },
        "canary": {
            "contractSha256": "3" * 64,
            "observedUnix": 2_000_000_000, "expiresUnix": 2_000_003_600,
            "probes": [
                {"id": "owned-a", "host": "probe-a.example.com", "port": 443, "addresses": ["8.8.8.8", "2001:4860:4860::8888"]},
                {"id": "owned-b", "host": "probe-b.example.com", "port": 443, "addresses": ["8.8.8.8"]},
            ],
        },
    }


def compile_value(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return MODULE.compile_report(value, raw)


class CompilerTests(unittest.TestCase):
    def test_valid_report_is_always_blocked_and_non_executable(self):
        report = compile_value(sample_input())
        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["exitCode"], 78)
        self.assertFalse(report["executionPermitted"])
        self.assertFalse(report["acceptedEvidenceProduced"])
        self.assertEqual(report["planSha256"], MODULE._sha(MODULE._canonical(report["plan"])))

    def test_compilation_is_deterministic(self):
        value = sample_input()
        self.assertEqual(compile_value(value), compile_value(copy.deepcopy(value)))

    def test_rules_cover_order_state_dns_dot_https_ipv4_and_ipv6(self):
        rules = compile_value(sample_input())["plan"]["nft"]["rules"]
        kinds = [rule["kind"] for rule in rules]
        self.assertEqual([rule["ordinal"] for rule in rules], sorted(rule["ordinal"] for rule in rules))
        self.assertEqual(len({rule["counterLabel"] for rule in rules}), len(rules))
        for label in ("return-established", "return-invalid", "ip-invalid", "ip-established", "ip6-invalid", "ip6-established", "ip-plain-dns-udp", "ip-plain-dns-tcp", "ip6-plain-dns-udp", "ip6-plain-dns-tcp", "ip-default", "ip6-default", "ip-source-spoof", "ip6-source-spoof"):
            self.assertIn(label, kinds)
        self.assertTrue(any(item["kind"] == "ip-dot" and item["match"]["destinationPort"] == 853 for item in rules))
        self.assertTrue(any(item["kind"] == "ip6-https" and item["match"]["destinationPort"] == 443 for item in rules))

    def test_every_rule_has_explicit_valid_chain_membership(self):
        nft = compile_value(sample_input())["plan"]["nft"]
        base_names = [item["name"] for item in nft["baseChains"]]
        known = set(base_names + nft["policyChains"])
        self.assertEqual({rule["chain"] for rule in nft["rules"]}, known)
        self.assertEqual([item["hook"] for item in nft["baseChains"]], ["forward", "input"])
        for rule in nft["rules"]:
            self.assertIn(rule["chain"], known)
        self.assertEqual(next(rule for rule in nft["rules"] if rule["kind"] == "scope-out")["verdict"], "jump:cw_fwd_policy")
        self.assertEqual(next(rule for rule in nft["rules"] if rule["kind"] == "host-scope-in")["verdict"], "jump:cw_in_policy")

    def test_new_inbound_to_managed_bridge_is_dropped_after_return_state_rules(self):
        nft = compile_value(sample_input())["plan"]["nft"]
        entry = [rule for rule in nft["rules"] if rule["chain"] == "cw_fwd_entry"]
        self.assertEqual([rule["kind"] for rule in entry], ["scope-out", "return-established", "return-invalid", "inbound-default"])
        self.assertEqual(entry[1]["match"]["ctState"], ["established", "related"])
        self.assertEqual(entry[1]["verdict"], "accept")
        self.assertEqual(entry[2]["verdict"], "drop")
        self.assertEqual(entry[3]["match"], {"oifname": "cwprobe0"})
        self.assertEqual(entry[3]["verdict"], "drop")

    def test_host_input_path_is_default_deny_with_only_strict_nd_allow(self):
        report = compile_value(sample_input())
        nft = report["plan"]["nft"]
        host_rules = [rule for rule in nft["rules"] if rule["chain"] == "cw_in_policy"]
        accepts = [rule for rule in host_rules if rule["verdict"] == "accept"]
        self.assertEqual([rule["kind"] for rule in accepts], ["host-nd-rs", "host-nd-ns", "host-nd-na"])
        self.assertEqual([rule["match"]["icmpv6Type"] for rule in accepts], [[133], [135], [136]])
        self.assertEqual(accepts[1]["match"]["sourceSet"], ["::", "fd42:88:2::2", "fe80::/64"])
        for rule in accepts:
            self.assertEqual(rule["match"]["hopLimit"], 255)
        self.assertEqual(host_rules[-1]["kind"], "host-default")
        self.assertEqual(host_rules[-1]["verdict"], "drop")
        denied = {rule["kind"] for rule in host_rules if rule["verdict"] == "drop"}
        for family in ("ip", "ip6"):
            for suffix in ("dhcp-server", "plain-dns-udp", "plain-dns-tcp", "dot-host-bypass", "https-host-bypass"):
                self.assertIn(f"host-{family}-{suffix}", denied)
        self.assertIn("DOCKER_EMBEDDED_DNS_127_0_0_11_BYPASS_UNPROVEN", report["blockers"])

    def test_rollback_is_bound_to_exact_nft_object_and_all_chains(self):
        plan = compile_value(sample_input())["plan"]
        self.assertEqual(plan["nftObjectSha256"], MODULE._sha(MODULE._canonical(plan["nft"])))
        self.assertEqual(plan["rollback"]["expectedNftObjectSha256"], plan["nftObjectSha256"])
        self.assertEqual(set(plan["rollback"]["managedChains"]), {"cw_fwd_entry", "cw_fwd_policy", "cw_in_entry", "cw_in_policy"})

    def test_shared_ip_is_deduplicated_and_explicitly_blocked(self):
        report = compile_value(sample_input())
        shared = report["plan"]["allowset"]["sharedDestinationAttribution"]
        self.assertEqual(shared, [{"address": "8.8.8.8", "probeIds": ["owned-a", "owned-b"]}])
        self.assertIn("SHARED_DESTINATION_IP_CANNOT_PROVE_PER_PROBE_ATTRIBUTION", report["blockers"])
        rules = [rule for rule in report["plan"]["nft"]["rules"] if rule.get("match", {}).get("destination") == "8.8.8.8"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["owners"], ["canary:owned-a", "canary:owned-b"])

    def test_rollback_and_global_impact_are_non_executable(self):
        plan = compile_value(sample_input())["plan"]
        self.assertFalse(plan["rollback"]["automaticExecutionPermitted"])
        self.assertEqual(plan["rollback"]["operation"], "DELETE_ONLY_EXACT_MANAGED_TABLE")
        self.assertTrue(plan["globalImpact"]["hostBaseChainInventoryRequired"])
        self.assertEqual(plan["globalImpact"]["approval"], "unproven")

    def test_first_start_binding_is_explicitly_unresolved(self):
        report = compile_value(sample_input())
        self.assertEqual(report["plan"]["runtimeBinding"]["status"], "BLOCKED_NO_RUNTIME_IDENTITY_BEFORE_PROCESS_START")
        self.assertEqual(report["plan"]["runtimeBinding"]["bootstrapMechanism"], "INDEPENDENT_NETNS_OR_PAUSED_NO_NETWORK_SHIM_REQUIRED")
        self.assertIn("cgroupId", report["plan"]["runtimeBinding"]["required"])
        self.assertIn("vethHostIfindex", report["plan"]["runtimeBinding"]["required"])
        self.assertIn("containerResolvConfSha256", report["plan"]["runtimeBinding"]["required"])
        self.assertIn("FIRST_START_REQUIRES_INDEPENDENT_NETNS_OR_PAUSED_NO_NETWORK_SHIM", report["blockers"])

    def test_internal_network_is_rejected(self):
        value = sample_input(); value["network"]["internal"] = True
        with self.assertRaises(MODULE.ContractError):
            compile_value(value)

    def test_non_bridge_and_icc_are_rejected(self):
        for field, bad in (("driver", "host"), ("enableIcc", True), ("attachable", True)):
            value = sample_input(); value["network"][field] = bad
            with self.subTest(field=field), self.assertRaises(MODULE.ContractError):
                compile_value(value)

    def test_bad_subnet_gateway_and_family_are_rejected(self):
        mutations = [
            ("ipv4", "subnet", "172.31.254.0/30"),
            ("ipv4", "gateway", "172.31.253.1"),
            ("ipv6", "subnet", "2001:db8::/64"),
            ("ipv6", "containerAddress", "fd42:88:3::2"),
            ("ipv6", "gateway", "fd42:88:2::"),
        ]
        for family, field, bad in mutations:
            value = sample_input(); value["network"][family][field] = bad
            with self.subTest(family=family, field=field), self.assertRaises(MODULE.ContractError):
                compile_value(value)

    def test_runtime_identity_cannot_be_forged_offline(self):
        value = sample_input(); value["identityBinding"]["containerPid"] = 123
        with self.assertRaises(MODULE.ContractError):
            compile_value(value)

    def test_system_or_embedded_dns_mode_is_rejected(self):
        for mode in ("SYSTEM", "DOCKER_EMBEDDED", "direct-dot-only-no-system-resolver"):
            value = sample_input(); value["candidate"]["resolverMode"] = mode
            with self.subTest(mode=mode), self.assertRaises(MODULE.ContractError):
                compile_value(value)

    def test_plain_dns_or_wrong_ports_are_rejected(self):
        variants = []
        value = sample_input(); value["firewall"]["allowPlainDns"] = True; variants.append(value)
        value = sample_input(); value["resolver"]["port"] = 53; variants.append(value)
        value = sample_input(); value["canary"]["probes"][0]["port"] = 8443; variants.append(value)
        value = sample_input(); value["firewall"]["allowDhcp"] = True; variants.append(value)
        value = sample_input(); value["firewall"]["allowIpv6NeighborDiscovery"] = False; variants.append(value)
        for value in variants:
            with self.assertRaises(MODULE.ContractError):
                compile_value(value)

    def test_stale_future_or_excessive_ttl_is_rejected(self):
        variants = []
        value = sample_input(); value["validationUnix"] = value["resolver"]["expiresUnix"]; variants.append(value)
        value = sample_input(); value["canary"]["observedUnix"] = value["validationUnix"] + 1; variants.append(value)
        value = sample_input(); value["resolver"]["expiresUnix"] = value["resolver"]["observedUnix"] + 86401; variants.append(value)
        for value in variants:
            with self.assertRaises(MODULE.ContractError):
                compile_value(value)

    def test_private_nonsorted_or_duplicate_destinations_are_rejected(self):
        variants = []
        value = sample_input(); value["resolver"]["addresses"] = ["192.168.1.1"]; variants.append(value)
        value = sample_input(); value["resolver"]["addresses"] = ["2606:4700:4700::1111", "1.1.1.1"]; variants.append(value)
        value = sample_input(); value["canary"]["probes"][0]["addresses"] = ["8.8.8.8", "8.8.8.8"]; variants.append(value)
        for value in variants:
            with self.assertRaises(MODULE.ContractError):
                compile_value(value)

    def test_unknown_field_and_duplicate_probe_id_are_rejected(self):
        value = sample_input(); value["surprise"] = True
        with self.assertRaises(MODULE.ContractError):
            compile_value(value)

    def test_invalid_unicode_and_total_rule_budget_are_rejected(self):
        value = sample_input(); value["revision"] = "bad\ud800"
        with self.assertRaises(MODULE.ContractError):
            compile_value(value)
        value = sample_input()
        value["canary"]["probes"] = [
            {"id": f"owned-{index}", "host": f"p{index}.example.com", "port": 443, "addresses": [f"8.8.{index}.1", f"9.9.{index}.1"]}
            for index in range(64)
        ]
        with self.assertRaises(MODULE.ContractError):
            compile_value(value)
        value = sample_input(); value["canary"]["probes"][1]["id"] = "owned-a"
        with self.assertRaises(MODULE.ContractError):
            compile_value(value)

    def test_duplicate_json_key_is_rejected(self):
        with self.assertRaises(MODULE.ContractError):
            json.loads('{"schema":"a","schema":"b"}', object_pairs_hook=MODULE._pairs)

    def test_excessive_json_integer_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory).resolve() / "huge.json"
            path.write_text('{"n":' + "9" * 5000 + "}", encoding="utf-8")
            if os.name == "posix":
                if os.geteuid() != 0:
                    self.skipTest("production POSIX path policy requires root ownership")
                os.chmod(directory, 0o700)
                os.chmod(path, 0o600)
            with self.assertRaises(MODULE.ContractError):
                MODULE.load_immutable_json(path)

    def test_schema_documents_parse(self):
        schema_dir = MODULE_PATH.parent / "schemas"
        for name in ("input.schema.json", "plan.schema.json", "report.schema.json"):
            with self.subTest(name=name):
                self.assertIsInstance(json.loads((schema_dir / name).read_text(encoding="utf-8")), dict)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name).resolve()
        self.input = self.root / "input.json"
        self.report = self.root / "report.json"
        self.input.write_text(json.dumps(sample_input(), sort_keys=True), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.root, 0o700)
            os.chmod(self.input, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_compile_then_validate_both_exit_blocked(self):
        if os.name == "posix" and os.geteuid() != 0:
            self.skipTest("production POSIX path policy requires root ownership")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(MODULE.main(["compile", "--input", str(self.input), "--output", str(self.report)]), 78)
        self.assertIn("BOOTSTRAP_PLAN=BLOCKED", stdout.getvalue())
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(MODULE.main(["validate", "--input", str(self.input), "--report", str(self.report)]), 78)
        self.assertIn("BOOTSTRAP_PLAN=VALID_BLOCKED", stdout.getvalue())

    def test_output_is_no_clobber(self):
        if os.name == "posix" and os.geteuid() != 0:
            self.skipTest("production POSIX path policy requires root ownership")
        self.report.write_text("sentinel", encoding="utf-8")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(MODULE.main(["compile", "--input", str(self.input), "--output", str(self.report)]), 2)
        self.assertEqual(self.report.read_text(encoding="utf-8"), "sentinel")

    @unittest.skipUnless(os.name == "posix", "directory fsync is a POSIX publication gate")
    def test_parent_fsync_failure_removes_published_output(self):
        if os.geteuid() != 0:
            self.skipTest("production POSIX path policy requires root ownership")
        real_fsync = os.fsync

        def fail_directory_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("injected directory fsync failure")
            return real_fsync(descriptor)

        stderr = io.StringIO()
        with mock.patch.object(MODULE.os, "fsync", side_effect=fail_directory_fsync), redirect_stderr(stderr):
            self.assertEqual(MODULE.main(["compile", "--input", str(self.input), "--output", str(self.report)]), 2)
        self.assertFalse(self.report.exists())

    def test_tampered_report_fails_validation(self):
        if os.name == "posix" and os.geteuid() != 0:
            self.skipTest("production POSIX path policy requires root ownership")
        self.assertEqual(MODULE.main(["compile", "--input", str(self.input), "--output", str(self.report)]), 78)
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["plan"]["nft"]["rules"][0]["verdict"] = "accept"
        self.report.write_text(json.dumps(report), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.report, 0o600)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(MODULE.main(["validate", "--input", str(self.input), "--report", str(self.report)]), 2)
        self.assertIn("not the exact deterministic compilation", stderr.getvalue())

    def test_tampered_rule_chain_fails_validation(self):
        if os.name == "posix" and os.geteuid() != 0:
            self.skipTest("production POSIX path policy requires root ownership")
        self.assertEqual(MODULE.main(["compile", "--input", str(self.input), "--output", str(self.report)]), 78)
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["plan"]["nft"]["rules"][0]["chain"] = "cw_in_policy"
        self.report.write_text(json.dumps(report), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.report, 0o600)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(MODULE.main(["validate", "--input", str(self.input), "--report", str(self.report)]), 2)
        self.assertIn("not the exact deterministic compilation", stderr.getvalue())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlink_input_is_rejected(self):
        link = self.root / "input-link.json"
        try:
            os.symlink(self.input, link)
        except OSError:
            self.skipTest("symlink creation not permitted")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(MODULE.main(["compile", "--input", str(link), "--output", str(self.report)]), 2)


if __name__ == "__main__":
    unittest.main()
