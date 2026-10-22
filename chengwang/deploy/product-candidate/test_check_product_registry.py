"""D11 synthetic gate rejection tests, not real Registry/image acceptance."""
from __future__ import annotations

import argparse
import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest

import check_product_registry as checker

SOURCE = "a" * 40


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)


def tar_bytes(entries=None, suffix=b""):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, contents, mode, kind in entries or [
            ("app/image-trust-api", b"synthetic-executable-not-run", 0o555, tarfile.REGTYPE),
            ("app/web/trust.html", b"synthetic-page", 0o444, tarfile.REGTYPE),
        ]:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = mode
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
    return output.getvalue() + suffix


def fixture(root, *, gzip_layer=False, layer=None):
    raw_layer = tar_bytes() if layer is None else layer
    layer_payload = gzip.compress(raw_layer, mtime=0) if gzip_layer else raw_layer
    layer_digest = "sha256:" + checker.sha(layer_payload)
    config = {"os": "linux", "architecture": "amd64", "config": {
        "Entrypoint": ["/app/image-trust-api"], "WorkingDir": "/app", "User": "10001:10001",
        "Labels": {"org.opencontainers.image.revision": SOURCE,
                   "org.chengwang.boundary": "ISOLATED_PRODUCT_CANDIDATE"}},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + checker.sha(raw_layer)]}}
    config_raw = encoded(config)
    config_digest = "sha256:" + checker.sha(config_raw)
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": config_digest, "size": len(config_raw)},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if gzip_layer else ""),
                            "digest": layer_digest, "size": len(layer_payload)}]}
    files = {}
    for name, contents in [("app/image-trust-api", b"synthetic-executable-not-run"),
                           ("app/web/trust.html", b"synthetic-page")]:
        files[name] = {"sha256": checker.sha(contents), "bytes": len(contents),
                       "mode": "0555" if name == "app/image-trust-api" else "0444", "uid": 0, "gid": 0}
    packaged = {"schema": "chengwang.product-image-packaged-content/v1", "authorization": "BLOCKED",
                "production": False, "sourceCommit": SOURCE, "localImageID": config_digest,
                "registryManifestDigestVerified": False, "configDigestMatched": True,
                "secretsPackaged": False, "rawArchivePublished": False, "files": files,
                "packagedFileCount": 2, "layerDiffIDs": config["rootfs"]["diff_ids"]}
    graph_dir = root / "graph"
    put(graph_dir / "manifest.json", encoded(manifest))
    put(graph_dir / "blobs" / config_digest[7:], config_raw)
    put(graph_dir / "blobs" / layer_digest[7:], layer_payload)
    put(root / "packaged.json", encoded(packaged))
    return argparse.Namespace(graph_dir=graph_dir, packaged_report=root / "packaged.json",
                              source_commit=SOURCE, manifest_digest="sha256:" + checker.sha(encoded(manifest)),
                              report=root / "report.json"), manifest, packaged


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def test_raw_manifest_config_layer_and_actual_file_bytes_bound(self):
        args, manifest, packaged = fixture(self.root)
        report = checker.graph(args)
        self.assertEqual(report["registryManifestDigest"], args.manifest_digest)
        self.assertEqual(report["localImageID"], packaged["localImageID"])
        self.assertNotEqual(report["localImageID"], report["registryManifestDigest"])
        self.assertEqual(report["layerDescriptors"][0]["diffID"], packaged["layerDiffIDs"][0])
        self.assertEqual(report["packagedReportSHA256"], checker.sha(args.packaged_report.read_bytes()))
        self.assertFalse(report["releaseAuthorized"])
        self.assertFalse(report["deviceActionsExecuted"])

    def test_single_gzip_layer_verified(self):
        args, _, _ = fixture(self.root, gzip_layer=True)
        self.assertTrue(checker.graph(args)["actualGraphBytesVerified"])

    def test_manifest_raw_bytes_not_reencoded_or_tag_identity(self):
        args, manifest, _ = fixture(self.root)
        for mutated in [args.manifest_digest[7:], "latest", "sha256:" + "0" * 64]:
            with self.subTest(mutated=mutated), self.assertRaises(checker.CheckError):
                checker.graph(argparse.Namespace(**{**vars(args), "manifest_digest": mutated}))
        put(args.graph_dir / "manifest.json", encoded(manifest) + b"\n")
        with self.assertRaises(checker.CheckError):
            checker.graph(args)

    def test_duplicate_json_and_nonfinite_rejected(self):
        args, _, _ = fixture(self.root)
        for raw in [b'{"schemaVersion":2,"schemaVersion":2}', b'{"number":NaN}']:
            put(args.graph_dir / "manifest.json", raw)
            args.manifest_digest = "sha256:" + checker.sha(raw)
            with self.subTest(raw=raw), self.assertRaises(checker.CheckError):
                checker.graph(args)

    def test_blob_size_digest_and_bytes_rejected(self):
        args, manifest, _ = fixture(self.root)
        target = args.graph_dir / "blobs" / manifest["layers"][0]["digest"][7:]
        raw = target.read_bytes()
        for bad in [raw[:-1], raw + b"\0", b"x" + raw[1:]]:
            put(target, bad)
            with self.subTest(length=len(bad)), self.assertRaises(checker.CheckError):
                checker.graph(args)

    def test_descriptor_unknown_media_urls_annotations_and_boolean_size_rejected(self):
        args, manifest, _ = fixture(self.root)
        for delta in [{"urls": ["https://external.invalid/blob"]}, {"annotations": {}},
                      {"mediaType": "application/octet-stream"}, {"size": True}]:
            bad = copy.deepcopy(manifest)
            bad["layers"][0].update(delta)
            put(args.graph_dir / "manifest.json", encoded(bad))
            args.manifest_digest = "sha256:" + checker.sha(encoded(bad))
            with self.subTest(delta=delta), self.assertRaises(checker.CheckError):
                checker.graph(args)

    def test_mixed_manifest_descriptor_media_and_oversize_config_rejected(self):
        args, manifest, _ = fixture(self.root)
        variants = []
        bad = copy.deepcopy(manifest)
        bad["config"]["mediaType"] = "application/vnd.docker.container.image.v1+json"
        variants.append(bad)
        bad = copy.deepcopy(manifest)
        bad["layers"][0]["mediaType"] = "application/vnd.docker.image.rootfs.diff.tar.gzip"
        variants.append(bad)
        bad = copy.deepcopy(manifest)
        bad["config"]["size"] = (1 << 20) + 1
        variants.append(bad)
        for bad in variants:
            put(args.graph_dir / "manifest.json", encoded(bad))
            args.manifest_digest = "sha256:" + checker.sha(encoded(bad))
            with self.subTest(bad=bad), self.assertRaises(checker.CheckError):
                checker.graph(args)

    def test_wrong_packaged_source_config_diffid_file_and_boundary_rejected(self):
        args, _, packaged = fixture(self.root)
        variants = []
        for key, value in [("sourceCommit", "b" * 40), ("localImageID", "sha256:" + "c" * 64),
                           ("layerDiffIDs", ["sha256:" + "d" * 64]), ("production", True),
                           ("authorization", "APPROVED"), ("registryManifestDigestVerified", True),
                           ("secretsPackaged", True), ("packagedFileCount", True)]:
            variants.append({**packaged, key: value})
        bad = copy.deepcopy(packaged)
        bad["files"]["app/web/trust.html"]["sha256"] = "f" * 64
        variants.append(bad)
        for bad in variants:
            put(args.packaged_report, encoded(bad))
            with self.subTest(keys=list(bad)), self.assertRaises(checker.CheckError):
                checker.graph(args)

    def test_extra_missing_or_nonregular_blob_rejected(self):
        args, manifest, _ = fixture(self.root)
        extra = args.graph_dir / "blobs" / ("0" * 64)
        put(extra, b"extra")
        with self.assertRaises(checker.CheckError):
            checker.graph(args)
        extra.unlink()
        target = args.graph_dir / "blobs" / manifest["layers"][0]["digest"][7:]
        target.unlink()
        target.mkdir()
        with self.assertRaises(checker.CheckError):
            checker.graph(args)

    def test_tar_extra_duplicate_link_wrongmode_whiteout_and_trailing_rejected(self):
        basic = [("app/image-trust-api", b"synthetic-executable-not-run", 0o555, tarfile.REGTYPE),
                 ("app/web/trust.html", b"synthetic-page", 0o444, tarfile.REGTYPE)]
        variants = [tar_bytes(basic + [("app/secret", b"private", 0o444, tarfile.REGTYPE)]),
                    tar_bytes(basic + [basic[0]]), tar_bytes([(basic[0][0], b"", 0o555, tarfile.SYMTYPE)]),
                    tar_bytes([(basic[0][0], basic[0][1], 0o777, tarfile.REGTYPE)]),
                    tar_bytes([("app/.wh.foo", b"x", 0o444, tarfile.REGTYPE)]),
                    tar_bytes(suffix=b"x" * 512)]
        for index, raw in enumerate(variants):
            case = self.root / str(index)
            args, _, _ = fixture(case, layer=raw)
            with self.subTest(index=index), self.assertRaises(checker.CheckError):
                checker.graph(args)

    def test_gzip_truncation_concatenation_and_bomb_rejected(self):
        data = tar_bytes()
        compressed = gzip.compress(data)
        for raw in [compressed[:-1], compressed + b"junk", compressed + compressed,
                    gzip.compress(b"0" * (2 << 20))]:
            with self.subTest(length=len(raw)), self.assertRaises(checker.CheckError):
                checker.unpack_layer(raw, "application/vnd.oci.image.layer.v1.tar+gzip")

    def test_cli_failure_is_generic_and_does_not_write_success(self):
        args, _, _ = fixture(self.root)
        put(args.graph_dir / "manifest.json", b'{"secret":"must-not-appear"}')
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = checker.main(["graph", "--graph-dir", str(args.graph_dir), "--packaged-report",
                                   str(args.packaged_report), "--source-commit", SOURCE,
                                   "--manifest-digest", args.manifest_digest, "--report", str(args.report)])
        self.assertEqual(result, 1)
        self.assertNotIn("must-not-appear", output.getvalue())
        self.assertFalse(args.report.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics require Linux")
    def test_writable_or_symlink_blob_rejected(self):
        args, manifest, _ = fixture(self.root)
        target = args.graph_dir / "blobs" / manifest["layers"][0]["digest"][7:]
        target.chmod(0o666)
        with self.assertRaises(checker.CheckError):
            checker.graph(args)
        target.chmod(0o600)
        replacement = self.root / "replacement"
        target.rename(replacement)
        target.symlink_to(replacement)
        with self.assertRaises(checker.CheckError):
            checker.graph(args)


def observed_fixture(graphs):
    value = {"schema": "chengwang.product-registry-observations/v1", "sourceCommit": SOURCE,
             "localImageID": graphs[checker.KINDS[0]]["localImageID"],
             "registryContainerID": "c" * 64, "pinnedRegistryImage": checker.REGISTRY_IMAGE,
             **checker.BOUNDARY, "snapshots": []}
    counts = {}
    for kind in checker.KINDS:
        for action, case in checker.STAGES:
            for position in ("before", "after"):
                if position == "after":
                    if action == "prepare":
                        graph = graphs[kind]
                        delta = {("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                                 ("PUT", "", 201): len(graph["layerDescriptors"]) + 2,
                                 ("GET", graph["registryManifestDigest"], 200): 1}
                        for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                            delta[("GET", desc["digest"], 200)] = 1
                        for key, count in delta.items():
                            counts[key] = counts.get(key, 0) + count
                    elif action == "exercise" and case == 1:
                        graph = graphs[kind]
                        delta = {("GET", graph["registryManifestDigest"], 200): 2,
                                 ("HEAD", graph["registryManifestDigest"], 200): 4}
                        for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                            delta[("GET", desc["digest"], 200)] = 1
                            delta[("HEAD", desc["digest"], 200)] = 2
                        for key, count in delta.items():
                            counts[key] = counts.get(key, 0) + count
                rows, other = [], []
                for (method, digest, status), count in sorted(counts.items()):
                    row = {"method": method, "status": status, "count": count}
                    if digest:
                        rows.append({**row, "digest": digest})
                    else:
                        other.append(row)
                value["snapshots"].append({"ordinal": len(value["snapshots"]) + 1,
                    "kind": kind, "action": action, "case": case, "position": position,
                    "digestRequests": rows, "otherRequests": other})
    return value


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        args, _, _ = fixture(pathlib.Path(self.temporary.name))
        self.graph = checker.graph(args)
        self.graphs = {kind: self.graph for kind in checker.KINDS}
        self.value = observed_fixture(self.graphs)

    def check(self, value):
        return checker.observations(value, SOURCE, self.graph["localImageID"], self.graphs)

    def test_exact_per_case_cumulative_descriptor_budget_and_zero_windows(self):
        result = self.check(self.value)
        self.assertEqual(result["snapshotCount"], 44)
        self.assertEqual(result["successfulImageReads"], 2)
        self.assertEqual(result["zeroRequestWindows"], 18)

    def test_missing_duplicate_or_reordered_case_observation_rejected(self):
        variants = []
        bad = copy.deepcopy(self.value)
        bad["snapshots"].pop()
        variants.append(bad)
        bad = copy.deepcopy(self.value)
        bad["snapshots"][3] = copy.deepcopy(bad["snapshots"][2])
        variants.append(bad)
        bad = copy.deepcopy(self.value)
        bad["snapshots"][4]["case"] = True
        variants.append(bad)
        for bad in variants:
            with self.subTest(bad=bad["snapshots"][-1]["ordinal"]), self.assertRaises(checker.CheckError):
                self.check(bad)

    def test_flat_success_boolean_cannot_replace_actual_counter_rows(self):
        bad = {**self.value, "snapshots": [], "allCasesZero": True}
        with self.assertRaises(checker.CheckError):
            self.check(bad)

    def test_wrong_source_authority_image_or_privileged_boundary_rejected(self):
        for key, value in [("sourceCommit", "b" * 40), ("localImageID", "sha256:" + "d" * 64),
                           ("pinnedRegistryImage", "registry:latest"), ("production", True),
                           ("deviceActionsExecuted", 0), ("authorization", "AUTHORIZED")]:
            with self.subTest(key=key), self.assertRaises(checker.CheckError):
                self.check({**self.value, key: value})

    def test_success_wrong_digest_count_or_http_status_rejected(self):
        for delta in [{"count": 99}, {"status": 403}, {"digest": "sha256:" + "f" * 64}, {"count": True}]:
            bad = copy.deepcopy(self.value)
            bad["snapshots"][3]["digestRequests"][0].update(delta)
            with self.subTest(delta=delta), self.assertRaises(checker.CheckError):
                self.check(bad)

    def test_rejected_case_hidden_http_and_unobserved_gap_rejected(self):
        for index in [5, 6, 11, 21]:
            bad = copy.deepcopy(self.value)
            bad["snapshots"][index]["digestRequests"][0]["count"] += 1
            with self.subTest(index=index), self.assertRaises(checker.CheckError):
                self.check(bad)

    def test_counter_reset_duplicate_rows_and_raw_url_fields_rejected(self):
        for kind in ("reset", "duplicate", "url"):
            bad = copy.deepcopy(self.value)
            row = bad["snapshots"][-1]
            if kind == "reset":
                row["digestRequests"] = []
            elif kind == "duplicate":
                row["digestRequests"].append(copy.deepcopy(row["digestRequests"][0]))
            else:
                row["url"] = "https://must-not-appear.invalid?token=private"
            with self.subTest(kind=kind), self.assertRaises(checker.CheckError):
                self.check(bad)


def test_digest(value):
    return "sha256:" + checker.sha(value.encode())


def synthetic_material(kind, graph):
    policies = []
    for name in ("accepted", "cross", "revoked", "spki"):
        policies.append({"name": name, "policyID": "d11-" + name, "grantID": "grant-" + kind + "-" + name,
            "approvalSHA256": test_digest(kind + name + "payload"),
            "approvalEnvelopeSHA256": test_digest(kind + name + "envelope"),
            "bundleSHA256": test_digest(kind + ("cross" if name == "cross" else "good") + "bundle"),
            "bundleArtifactSHA256": test_digest(kind + "crossmanifest") if name == "cross" else graph["registryManifestDigest"],
            "trustedRootSHA256": test_digest(kind + "trustroot"),
            "registrySPKI": test_digest("badspki" if name == "spki" else "registryspki")})
    return {"kind": kind, "sourceCommit": SOURCE, "localImageID": graph["localImageID"],
            "manifestSHA256": graph["registryManifestDigest"], "configSHA256": graph["localImageID"],
            "layerSHA256s": [layer["digest"] for layer in graph["layerDescriptors"]],
            "diffIDs": [layer["diffID"] for layer in graph["layerDescriptors"]],
            "catalogue1SHA256": test_digest(kind + "cat1"), "catalogue2SHA256": test_digest(kind + "cat2"),
            "storeID": checker.sha(kind.encode())[:32], "policies": policies}


def synthetic_status(info, state):
    sequence, generation, ledger, reserved, _ = state
    result = {"boundary": "ADVISORY_TRUST_POLICY_STATE", "authorization": "BLOCKED", "deviceActionsExecuted": False,
              "healthy": True, "fresh": True, "storeId": info["storeID"], "generation": generation,
              "catalogueSHA256": info["catalogue%dSHA256" % generation], "notAfterUnix": 2000000000,
              "sequence": sequence, "ledgerEntries": ledger, "ledgerCapacity": 4096, "reserved": reserved,
              "consumed": int(ledger > 0), "revokedKeys": 0, "revokedApprovals": int(generation == 2), "revokedManifests": 0,
              "policies": [], "refreshRequired": False, "refreshFresh": False, "refreshLastSuccessUnix": 0,
              "refreshUntilUnix": 0, "recoveryCompleted": 0, "observedAtUnix": 1800000000, "auditVerifiedAtUnix": 1800000000}
    for policy in info["policies"]:
        name = policy["name"]
        if generation == 2 and name == "revoked":
            continue
        status = "CONSUMED" if name == "accepted" and ledger else (
            "RESERVED" if name == "cross" and ledger >= 2 or name == "spki" and ledger == 3 else "AVAILABLE")
        result["policies"].append({"policyId": policy["policyID"], "grantId": policy["grantID"], "revision": 1,
                                   "manifestSHA256": info["manifestSHA256"], "state": status})
    return result


def synthetic_history(state, entries):
    return {"boundary": "ADVISORY_TRUST_OPERATION_HISTORY", "authorization": "BLOCKED", "deviceActionsExecuted": False,
            "observedAtUnix": 1800000000, "sequence": state[0], "total": state[4], "offset": 0, "limit": 50,
            "entries": copy.deepcopy(entries)}


def synthetic_action_reports(kind, graph):
    info = synthetic_material(kind, graph)

    def report(action, case=0, cases=None):
        return {"schema": "chengwang.product-registry-action/v1", "action": action, "case": case, **copy.deepcopy(info),
                "authority": "EPHEMERAL_TEST_ONLY", "graphOrigin": checker.GRAPH_ORIGIN, **checker.BOUNDARY,
                "cases": cases or [], "journalAuditBindingsVerified": False}

    reports = {"prepare": report("prepare")}
    journal, entries, cases = [], [], []
    state = (1, 1, 0, 0, 0)
    previous_hash = "0" * 64
    first_journal = None
    for index, row in enumerate(checker.CASE_MATRIX):
        action, number, name, policy_name, http_status, after = row
        policy = next((p for p in info["policies"] if p["name"] == policy_name), None)
        case = {field: "" for field in checker.CASE_FIELDS}
        case.update({"name": name, "method": "PUT" if action == "catalogue" else "POST",
                     "path": "/api/v1/image-trust/catalogue" if action == "catalogue" else "/api/v1/image-trust/verifications",
                     "httpStatus": http_status, "errorCode": "" if http_status == 200 else "image_trust_invalid",
                     "stateMayHaveChanged": http_status == 400,
                     "statusBefore": synthetic_status(info, state), "historyBefore": synthetic_history(state, entries)})
        if policy is not None:
            for field in ("policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256", "trustedRootSHA256"):
                case[field] = policy[field]
            if name == "approval-tamper":
                case["approvalEnvelopeSHA256"] = test_digest(kind + "tampered-envelope")
            case["requestSHA256"] = test_digest(kind + policy_name + ("tampered" if name == "approval-tamper" else "request"))
        else:
            case["requestSHA256"] = info["catalogue%dSHA256" % (2 if name == "revocation-install" else 1)]
        state_name, outcome = ("CONSUMED", "VERIFICATION_CONSUMED") if name == "success" else (
            ("RESERVED", "VERIFICATION_RESERVED_NOT_COMPLETED") if name in {"crossed-bundle", "wrong-spki"} else (
                ("COMMITTED", "CATALOGUE_COMMITTED") if name == "revocation-install" else ("PREPARED", "REJECTED")))
        prepared_hash = checker.sha((kind + str(index) + "prepared").encode())
        result_hash = checker.sha((kind + str(index) + "result").encode())
        bound = state_name in {"CONSUMED", "RESERVED", "COMMITTED"}
        entry = {"operationId": f"operation-{kind}-{index}", "actorId": "d11-admin", "kind": "update" if action == "catalogue" else "verify",
                 "state": state_name, "outcome": outcome, "acknowledged": True, "policyId": case["policyID"],
                 "grantId": case["grantID"] if state_name in {"CONSUMED", "RESERVED"} else "",
                 "generation": after[1] if bound else 0, "catalogueSHA256": info["catalogue%dSHA256" % after[1]] if bound else "",
                 "preparedAuditHash": prepared_hash, "resultAuditHash": result_hash, "preparedAtUnix": 1800000000, "resultAtUnix": 1800000000}
        entries.append(entry)
        case["statusAfter"] = synthetic_status(info, after)
        case["historyAfter"] = synthetic_history(after, entries)
        if name == "success":
            case["receipt"] = {"boundary": "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND", "authorization": "BLOCKED",
                "deviceActionsExecuted": False, "verified": True, "grantId": case["grantID"], "catalogueSHA256": info["catalogue1SHA256"],
                "generation": 1, "manifestSHA256": info["manifestSHA256"], "evidenceSHA256": test_digest(kind + "evidence")}
        data = {"catalogueSHA256": case["requestSHA256"]} if action == "catalogue" else {
            "policyId": case["policyID"], "approvalSHA256": case["approvalEnvelopeSHA256"],
            "bundleSHA256": case["bundleSHA256"], "rootSHA256": case["trustedRootSHA256"]}
        journal_entry = {"operation": {"id": entry["operationId"], "actorID": "d11-admin", "scopeSHA256": test_digest(kind + "scope"),
            "kind": entry["kind"], "data": data, "auditBaseCount": index * 2, "auditBaseHash": previous_hash,
            "preparedAuditHash": prepared_hash}, "state": state_name, "outcome": outcome, "outcomeData": {}, "acknowledged": True,
            "resultAuditHash": result_hash, "grantID": entry["grantId"], "generation": entry["generation"],
            "catalogueSHA256": entry["catalogueSHA256"], "manifestSHA256": info["manifestSHA256"] if state_name in {"CONSUMED", "RESERVED"} else "",
            "evidenceSHA256": case.get("receipt", {}).get("evidenceSHA256", "")}
        if state_name in {"CONSUMED", "RESERVED"}:
            journal_entry["outcomeData"] = {"grantId": case["grantID"], "manifestSHA256": info["manifestSHA256"], "catalogueSHA256": entry["catalogueSHA256"]}
            if state_name == "CONSUMED":
                journal_entry["outcomeData"]["evidenceSHA256"] = case["receipt"]["evidenceSHA256"]
        elif state_name == "COMMITTED":
            journal_entry["outcomeData"] = {"catalogueSHA256": info["catalogue2SHA256"]}
        journal.append(journal_entry)
        previous_hash = result_hash
        cases.append(case)
        if action != "catalogue":
            reports[action + "-" + str(number)] = report(action, number, [case])
        if index == 3:
            first_journal = copy.deepcopy(journal)
        state = after
    reports["exercise"] = report("exercise", cases=cases[:4])
    reports["resume"] = report("resume", cases=[cases[n] for n in (4, 7, 8, 9)])
    reports["catalogue"] = report("catalogue", cases=cases[5:7])
    for phase, count, retained in (("first", 4, first_journal), ("final", 10, journal)):
        last = cases[count - 1]["statusAfter"]
        active = [p for p in info["policies"] if last["generation"] == 1 or p["name"] != "revoked"]
        grants = [{"id": p["grantID"], "policyID": p["policyID"], "approvalSHA256": p["approvalSHA256"],
                   "approverKeyID": "key-" + p["name"], "manifestSHA256": info["manifestSHA256"], "revision": 1} for p in active]
        consumptions = []
        for name in ["accepted", "cross"] + (["spki"] if phase == "final" else []):
            p = next(p for p in info["policies"] if p["name"] == name)
            generation = 2 if name == "spki" else 1
            consumptions.append({"grantID": p["grantID"], "policyID": p["policyID"], "approvalSHA256": p["approvalSHA256"],
                "manifestSHA256": info["manifestSHA256"], "generation": generation, "catalogueSHA256": info["catalogue%dSHA256" % generation],
                "status": "CONSUMED" if name == "accepted" else "RESERVED",
                "evidenceSHA256": cases[0]["receipt"]["evidenceSHA256"] if name == "accepted" else ""})
        summary = {"storeID": info["storeID"], "generation": last["generation"], "sha256": last["catalogueSHA256"],
                   "notBeforeUnix": 1799999900, "notAfterUnix": last["notAfterUnix"], "rootKeyCount": 1, "rootThreshold": 1,
                   "approverCount": 4, "grants": grants, "policyFloors": {p["policyID"]: 1 for p in info["policies"]},
                   "revokedKeyCount": 0, "revokedApprovalCount": int(phase == "final"), "revokedManifestCount": 0}
        final = report("verify-" + phase)
        final.update({"journalAuditBindingsVerified": True,
            "inspection": {"authorization": "BLOCKED", "catalogue": summary, "catalogueValid": True, "sequence": last["sequence"],
                           "ledgerCapacity": 4096, "ledgerUsed": last["ledgerEntries"], "ledgerRemaining": 4096 - last["ledgerEntries"],
                           "consumptions": consumptions}, "journal": retained,
            "audit": {"valid": True, "count": count * 2, "expectedCount": count * 2, "lastHash": retained[-1]["resultAuditHash"],
                      "expectedLastHash": retained[-1]["resultAuditHash"], "verifiedAt": "2026-10-23T01:00:00Z"}})
        reports["verify-" + phase] = final
    return reports


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        args, _, _ = fixture(pathlib.Path(self.temporary.name))
        self.graph = checker.graph(args)
        self.reports = synthetic_action_reports("message-signature", self.graph)

    def check(self, reports):
        return checker.action_sequence(reports, "message-signature", SOURCE, self.graph["localImageID"], self.graph)

    def test_synthetic_api_calls_reopens_burned_grants_and_ack_hashes_match(self):
        self.assertEqual(self.check(self.reports)["storeID"], self.reports["prepare"]["storeID"])

    def test_wrong_or_missing_case_status_error_receipt_and_replay_request_rejected(self):
        for which in ("status", "error", "receipt", "request", "missing", "changeflag"):
            bad = copy.deepcopy(self.reports)
            if which == "missing":
                bad["exercise-2"]["cases"] = []
            elif which == "receipt":
                bad["exercise-1"]["cases"][0]["receipt"]["manifestSHA256"] = test_digest("wrong")
            else:
                case = bad["exercise-2"]["cases"][0]
                key, value = {"status": ("httpStatus", 200), "error": ("errorCode", ""),
                              "request": ("requestSHA256", test_digest("different")), "changeflag": ("stateMayHaveChanged", False)}[which]
                case[key] = value
            with self.subTest(which=which), self.assertRaises(checker.CheckError):
                self.check(bad)

    def test_catalogue_rollback_or_ledger_recreation_rejected(self):
        for which in ("generation", "catalogue", "sequence", "ledger", "policy"):
            bad = copy.deepcopy(self.reports)
            state = bad["resume-4"]["cases"][0]["statusAfter"]
            if which == "policy":
                state["policies"][0]["state"] = "AVAILABLE"
            else:
                key, value = {"generation": ("generation", 1), "catalogue": ("catalogueSHA256", bad["prepare"]["catalogue1SHA256"]),
                              "sequence": ("sequence", 19), "ledger": ("ledgerEntries", 2)}[which]
                state[key] = value
            with self.subTest(which=which), self.assertRaises(checker.CheckError):
                self.check(bad)

    def test_cross_bundle_wrong_root_or_missing_spki_distinction_rejected(self):
        for field, source in (("bundleArtifactSHA256", "manifest"), ("trustedRootSHA256", "new"), ("registrySPKI", "same")):
            bad = copy.deepcopy(self.reports)
            if field == "registrySPKI":
                bad["prepare"]["policies"][3][field] = bad["prepare"]["policies"][0][field]
            else:
                bad["prepare"]["policies"][1][field] = self.graph["registryManifestDigest"] if source == "manifest" else test_digest("otherroot")
            with self.subTest(field=field), self.assertRaises(checker.CheckError):
                self.check(bad)

    def test_reopened_hash_prefix_checkpoint_ack_and_grant_evidence_rejected(self):
        for which in ("ack", "base", "checkpoint", "evidence", "journal", "unknown"):
            bad = copy.deepcopy(self.reports)
            report = bad["verify-final"]
            if which == "ack":
                report["journal"][0]["acknowledged"] = False
            elif which == "base":
                report["journal"][1]["operation"]["auditBaseHash"] = "f" * 64
            elif which == "checkpoint":
                report["audit"]["expectedCount"] = 18
            elif which == "evidence":
                report["inspection"]["consumptions"][0]["evidenceSHA256"] = test_digest("changed")
            elif which == "journal":
                report["journal"].pop()
            else:
                report["anchor"] = {"keys": ["must-not-publish"]}
            with self.subTest(which=which), self.assertRaises(checker.CheckError):
                self.check(bad)


def synthetic_final_evidence(root):
    import test_check_product_image as old_tests
    args, _, packaged = fixture(root)
    graph = checker.graph(args)
    source_files = {name: record["sha256"] for name, record in packaged["files"].items()}
    binary = packaged["files"]["app/image-trust-api"]
    values = {"product-image-staging.json": {"sourceCommit": SOURCE, "authorization": "BLOCKED", "deviceActionsExecuted": False,
        "imageBuilt": False, "imageExecuted": False, "binary": {"sourceCommit": SOURCE, "sourceModified": False,
            "sha256": binary["sha256"], "bytes": binary["bytes"]},
        "contextFiles": {"Dockerfile": "d" * 64, **{"rootfs/" + key: val for key, val in source_files.items()}}},
        "product-image-packaged-contents.json": packaged}
    graphs = {kind: graph for kind in checker.KINDS}
    observed = observed_fixture(graphs)
    registry_id = observed["registryContainerID"]
    values["product-registry-observations.json"] = observed
    tools = ("chengwang/deploy/product-candidate/check_product_image.py", "chengwang/deploy/product-candidate/check_product_registry.py")
    values["product-registry-harness.json"] = {"schema": "chengwang.product-registry-harness/v1", "sourceCommit": SOURCE,
        "files": {name: checker.sha(pathlib.Path(checker.__file__).with_name(pathlib.PurePosixPath(name).name).read_bytes()) for name in tools},
        "checkoutBytesMatched": True, "permissionReadOnly": True, **checker.BOUNDARY}
    values["product-registry-isolation.json"] = {"schema": "chengwang.product-registry-isolation/v1", "sourceCommit": SOURCE,
        "registryContainerID": registry_id, "pinnedImage": checker.REGISTRY_IMAGE, "actualImageID": "sha256:" + "9" * 64,
        "pinnedImageMatched": True, "networkMode": "none", "securityProfileVerified": True, "normalTLSVerified": True,
        "readOnlyRootfs": True, "user": "10001:10001", "capDrop": ["ALL"], "noNewPrivileges": True,
        "memory": 268435456, "memorySwap": 268435456, "nanoCpus": 1000000000, "pidsLimit": 128,
        "tmpfsBytes": 201326592, "tmpBytes": 16777216, "roFileBindCount": 3, "hostPorts": 0, "privileged": False, **checker.BOUNDARY}
    values["product-registry-network.json"] = {"schema": "chengwang.product-registry-network/v1", "sourceCommit": SOURCE,
        "registryContainerID": registry_id, "loopbackOnly": True, "defaultRoutes": 0,
        "externalIPv4Blocked": True, "externalIPv6Blocked": True, **checker.BOUNDARY}
    for kind in checker.KINDS:
        values["product-registry-" + kind + "-graph.json"] = graph
        reports = synthetic_action_reports(kind, graph)
        for action, report in reports.items():
            values["product-registry-" + kind + "-" + action + ".json"] = report
        private = "/tmp/chengwang-product-registry-" + "d" * 32 + "/" + kind
        network = "container:" + registry_id
        container_id = checker.sha(kind.encode())
        for label in ("running", "exited", "restarted-running", "restarted-exited"):
            running = label in {"running", "restarted-running"}
            image, container = old_tests.synthetic_inspect()
            image["Id"] = graph["localImageID"]
            container["Image"] = graph["localImageID"]
            container["Id"] = container_id
            container["HostConfig"]["NetworkMode"] = network
            arguments = ["--config", private + "/trust-config.json", "--product-config", private + "/product-config.json"]
            container["Config"]["Cmd"] = arguments[:]
            container["Args"] = arguments[:]
            for mount in container["Mounts"]:
                mount["Source"] = mount["Source"].replace(old_tests.PRIVATE, private)
                mount["Destination"] = mount["Destination"].replace(old_tests.PRIVATE, private)
            container["State"].update({"Status": "running" if running else "exited", "Running": running,
                                       "Pid": (101 if label == "running" else 102) if running else 0})
            projection = checker.image.inspect_projection(image, container, image_id=graph["localImageID"], source=SOURCE,
                private=private, state=private + "/trust", network=network, status="running" if running else "exited", fixture_kind="product-registry")
            projection.update({"production": False, "networkPeerContainerID": registry_id})
            values["product-registry-" + kind + "-" + label + "-inspect.json"] = projection
            if running:
                process = {"schema": "chengwang.product-image-pid1/v1", **checker.BOUNDARY, "sourceCommit": SOURCE,
                    "localImageID": graph["localImageID"], "containerID": container_id, "hostPID": container["State"]["Pid"],
                    "namespacePID": 1, "uid": 10001, "gid": 10001, "capabilities": "none", "noNewPrivileges": True,
                    "defaultProductEntrypoint": True, "expectedConfigurationArguments": True, "actualExecutableSHA256": binary["sha256"]}
                values["product-registry-" + kind + "-" + label + "-pid1.json"] = process
    values["product-registry-cleanup.json"] = {"schema": "chengwang.product-registry-cleanup/v1", "sourceCommit": SOURCE,
        "localImageID": graph["localImageID"], "ownedContainersRemoved": 3, "privateFixtureRemoved": True,
        "outerProductImagePreserved": True, "registryImagePreserved": True, "outcome": "PASS", **checker.BOUNDARY}
    directory = root / "evidence"
    for name, value in values.items():
        put(directory / name, encoded(value))
    return argparse.Namespace(evidence_dir=directory, source_commit=SOURCE, report=root / "final-report.json"), values


class FullGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.args, self.values = synthetic_final_evidence(self.root)

    def change(self, name, edit):
        value = copy.deepcopy(self.values[name])
        edit(value)
        put(self.args.evidence_dir / name, encoded(value))

    def test_entire_synthetic_cross_artifact_gate_and_report_replay(self):
        result = checker.verify(self.args)
        self.assertEqual(len(result["evidenceSHA256"]), 49)
        self.assertEqual(result["actualProductAPIRegistryReads"], 2)
        self.assertEqual(result["registryCounterSnapshots"], 44)
        self.assertFalse(result["formalSLSAProvenance"])
        self.assertFalse(result["releaseAuthorized"])
        self.assertEqual(result["authority"], "EPHEMERAL_TEST_ONLY")
        put(self.args.evidence_dir / "product-registry-outcome.json", encoded(result))
        self.assertEqual(checker.verify(self.args), result)

    def test_cli_actual_verify_writes_only_safe_recomputed_outcome(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = checker.main(["verify", "--evidence-dir", str(self.args.evidence_dir),
                                   "--source-commit", SOURCE, "--report", str(self.args.report)])
        self.assertEqual(result, 0)
        actual = json.loads(self.args.report.read_bytes())
        self.assertEqual(actual["schema"], "chengwang.product-registry-gate/v1")
        self.assertEqual(actual["outcome"], "PASS")
        self.assertEqual(output.getvalue(), "PRODUCT_REGISTRY_CHECK=PASS mode=verify authorization=BLOCKED production=false\n")

    def test_missing_report_or_extra_private_artifact_rejected(self):
        path = self.args.evidence_dir / "product-registry-dsse-exercise-3.json"
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(OSError):
            checker.verify(self.args)
        put(path, original)
        put(self.args.evidence_dir / "product-registry-secret-config.json", b'{"private":"must-not-publish"}')
        with self.assertRaises(checker.CheckError):
            checker.verify(self.args)

    def test_actual_binary_pid_source_container_restart_and_peer_substitution_rejected(self):
        mutations = [("product-registry-dsse-running-pid1.json", "actualExecutableSHA256", "f" * 64),
                     ("product-registry-dsse-running-pid1.json", "sourceCommit", "b" * 40),
                     ("product-registry-dsse-restarted-exited-inspect.json", "containerID", "f" * 64),
                     ("product-registry-dsse-running-inspect.json", "networkPeerContainerID", "f" * 64),
                     ("product-registry-dsse-restarted-exited-inspect.json", "cleanExit", False)]
        for name, key, value in mutations:
            self.change(name, lambda item: item.update({key: value}))
            with self.subTest(key=key), self.assertRaises(checker.CheckError):
                checker.verify(self.args)
            put(self.args.evidence_dir / name, encoded(self.values[name]))

    def test_nested_mount_bools_numeric_extra_and_missing_rejected(self):
        name = "product-registry-dsse-running-inspect.json"
        for mutation in (1, False, "extra", "missing"):
            def edit(value):
                mounts = value["bindMounts"]
                if mutation == "extra":
                    mounts["unknown"] = True
                elif mutation == "missing":
                    mounts.pop("privateReadOnly")
                else:
                    mounts["privateReadOnly"] = mutation
            self.change(name, edit)
            with self.subTest(mutation=mutation), self.assertRaises(checker.CheckError):
                checker.verify(self.args)

    def test_graph_packaged_hash_wrong_config_or_identity_role_rejected(self):
        name = "product-registry-dsse-graph.json"
        for key, value in (("packagedReportSHA256", "f" * 64), ("localImageID", test_digest("wrong")),
                           ("registryManifestDigest", self.values[name]["localImageID"]),
                           ("packagedFilesSHA256", "f" * 64),
                           ("graphBytesOrigin", "PREPARED_ONLY")):
            for kind in checker.KINDS:
                self.change("product-registry-" + kind + "-graph.json", lambda item: item.update({key: value}))
            with self.subTest(key=key), self.assertRaises(checker.CheckError):
                checker.verify(self.args)
            for kind in checker.KINDS:
                graph_name = "product-registry-" + kind + "-graph.json"
                put(self.args.evidence_dir / graph_name, encoded(self.values[graph_name]))
        for field in ("config", "layer"):
            def edit(item):
                if field == "config":
                    item["configDescriptor"]["mediaType"] = "application/vnd.docker.container.image.v1+json"
                else:
                    item["layerDescriptors"][0]["mediaType"] = "application/vnd.docker.image.rootfs.diff.tar.gzip"
            for kind in checker.KINDS:
                self.change("product-registry-" + kind + "-graph.json", edit)
            with self.subTest(field=field), self.assertRaises(checker.CheckError):
                checker.verify(self.args)
            for kind in checker.KINDS:
                graph_name = "product-registry-" + kind + "-graph.json"
                put(self.args.evidence_dir / graph_name, encoded(self.values[graph_name]))

    def test_registry_network_cleanup_authority_and_pinned_reference_rejected(self):
        mutations = [("product-registry-isolation.json", "pinnedImage", "registry:latest"),
                     ("product-registry-network.json", "externalIPv6Blocked", False),
                     ("product-registry-cleanup.json", "privateFixtureRemoved", False),
                     ("product-registry-cleanup.json", "ownedContainersRemoved", True),
                     ("product-registry-cleanup.json", "authorization", "AUTHORIZED"),
                     ("product-registry-cleanup.json", "deviceActionsExecuted", 0)]
        for name, key, value in mutations:
            self.change(name, lambda item: item.update({key: value}))
            with self.subTest(key=key), self.assertRaises(checker.CheckError):
                checker.verify(self.args)
            put(self.args.evidence_dir / name, encoded(self.values[name]))

    def test_source_copy_mismatch_or_final_report_fabrication_rejected(self):
        name = "product-registry-harness.json"
        self.change(name, lambda value: value["files"].update({next(iter(value["files"])): "0" * 64}))
        with self.assertRaises(checker.CheckError):
            checker.verify(self.args)
        put(self.args.evidence_dir / name, encoded(self.values[name]))
        result = checker.verify(self.args)
        result["production"] = True
        put(self.args.evidence_dir / "product-registry-outcome.json", encoded(result))
        with self.assertRaises(checker.CheckError):
            checker.verify(self.args)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    okay = result.wasSuccessful() and (os.name != "posix" or not result.skipped)
    passed = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
    print("PRODUCT_REGISTRY_CHECK_TESTS=" + ("PASS" if okay else "FAIL")
          + f" tests={result.testsRun} passed={passed} skipped={len(result.skipped)} synthetic_only=true")
    raise SystemExit(0 if okay else 1)
