"""Synthetic TLS evidence tests using real OpenSSL, not product execution."""
from __future__ import annotations

import argparse
import contextlib
import copy
import io
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import check_product_source_tls as check
import test_check_product_source as old
import test_check_product_registry as graph_fixture

SOURCE, NOW = old.SOURCE, int(time.time()) + 120
raw, h, d, b64 = old.raw, old.h, old.d, old.b64


def command(argv):
    result = subprocess.run([check.source.openssl_path(), *argv], capture_output=True, timeout=5, check=True)
    return result.stdout


def certificate_fixture():
    """Public CA/leaf corpus: independently issued, not a mocked verifier."""
    with tempfile.TemporaryDirectory(prefix="source-tls-synthetic-cert-") as directory:
        root = pathlib.Path(directory)
        signers = {name: old.Signer("tls-cert-" + name) for name in ("ca", "alternate", "good", "other")}
        try:
            for name in ("ca", "alternate"):
                cert = command(["req", "-new", "-x509", "-key", str(signers[name].private), "-keyform", "DER", "-days", "2",
                    "-subj", "/CN=TLSFixture" + name, "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
                graph_fixture.put(root / (name + ".pem"), cert)
            def issue(label, key, authority, hostname):
                csr = command(["req", "-new", "-key", str(signers[key].private), "-keyform", "DER", "-subj", "/CN=TLSFixtureLeaf"])
                graph_fixture.put(root / "leaf.csr", csr)
                graph_fixture.put(root / "leaf.ext", ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                    "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:" + hostname + "\n").encode())
                return command(["x509", "-req", "-in", str(root / "leaf.csr"), "-CA", str(root / (authority + ".pem")),
                    "-CAkey", str(signers[authority].private), "-CAkeyform", "DER", "-set_serial", str(int(h(label)[:12], 16)),
                    "-days", "1", "-extfile", str(root / "leaf.ext")])
            good = issue("good", "good", "ca", "feed.fixture.invalid")
            bad = {"ca": issue("ca", "good", "alternate", "feed.fixture.invalid"),
                   "san": issue("san", "good", "ca", "wrong.fixture.invalid"),
                   "spki": issue("spki", "other", "ca", "feed.fixture.invalid")}
            return {fault: {"configuredCARaw": b64((root / "ca.pem").read_bytes()), "goodChainRaw": b64(good),
                "badChainRaw": b64(bad[fault]), "alternateCARaw": b64((root / "alternate.pem").read_bytes()) if fault == "ca" else ""}
                for fault in check.FAULTS}
        finally:
            for signer in signers.values():
                signer.close()


def signed_material(fault, kind, graph, certificates):
    label = "tls-" + fault
    info = old.signed_material(label, kind, graph)
    # Make public catalogue/approval time windows current without changing any
    # old test globals or production fixtures. Re-sign the real raw payloads.
    root, approver = old.Signer(label + kind + "-root"), old.Signer(label + kind + "-approver")
    try:
        approval = check.parse(check.binary(info["approvalRaw"]))
        approval_doc = check.parse(check.binary(approval["payload"]))
        approval_doc.update(notBeforeUnix=NOW - 60, notAfterUnix=NOW + 3600)
        payload = raw(approval_doc)
        approval_raw = raw({"payload": b64(payload), "signature": b64(approver.sign(b"chengwang.image-approval/v1\0" + payload))})
        info["approvalRaw"] = b64(approval_raw)
        info["policies"][0].update(approvalSHA256=check.source.prefixed(payload), approvalEnvelopeSHA256=check.source.prefixed(approval_raw))
        for record in info["catalogues"][:3]:
            doc = check.parse(check.binary(check.parse(check.binary(record["raw"]))["payload"]))
            doc.update(notBeforeUnix=NOW - 60, notAfterUnix=NOW + 3600)
            doc["grants"][0]["approvalSHA256"] = info["policies"][0]["approvalSHA256"]
            payload = raw(doc)
            envelope = {"payload": b64(payload), "signatures": [{"keyID": root.key["id"],
                "signature": b64(root.sign(b"chengwang.trust-catalog/v1\0" + payload))}]}
            content = raw(envelope); record.update(raw=b64(content), sha256=check.source.prefixed(content))
        for index, generation in ((3, 2), (4, 3)):
            envelope = check.parse(check.binary(info["catalogues"][generation - 1]["raw"]))
            signed = bytearray(check.binary(envelope["signatures"][0]["signature"])); signed[0] ^= 1
            envelope["signatures"][0]["signature"] = b64(signed)
            content = raw(envelope); info["catalogues"][index].update(raw=b64(content), sha256=check.source.prefixed(content))
        anchor = check.parse(check.binary(info["anchorRaw"]))
        anchor["initialSHA256"] = info["catalogues"][0]["sha256"]
        info.update(anchorRaw=b64(raw(anchor)), catalogue1SHA256=info["catalogues"][0]["sha256"], catalogue2SHA256=info["catalogues"][1]["sha256"],
            feedSPKI=check.public_spki(check.binary(certificates["goodChainRaw"])), feedCASHA256=check.source.prefixed(check.binary(certificates["configuredCARaw"])))
        return info
    finally:
        root.close(); approver.close()


def event_rows(info, phase):
    plans = old.plans_fixture("bad-signature", info)
    rows, _ = old.events_fixture("bad-signature", info, plans)
    if phase == "good":
        return rows[:4]
    result = []
    for connection in (1, 2):
        for original in rows[:2] + rows[3:4]:
            row = copy.deepcopy(original); row.update(ordinal=len(result) + 1, connection=connection)
            if row["event"] == "tls":
                row.update(reason="failed", tls=False)
            if row["event"] == "close":
                row["tls"] = False
            result.append(row)
    return result


def point(log, count=None):
    lines = log.splitlines(keepends=True)
    count = len(lines) if count is None else count
    return {"eventCount": count, "sha256": check.image.sha(b"".join(lines[:count]))}


def reports_fixture(fault, kind, info, certificates):
    old_reports, _, _ = old.cell_fixture("http-recovery", kind, info)
    baseline = old_reports["reopen"]["offline"]
    plan = old.plans_fixture("bad-signature", info)[0]
    material = {"source": info, "certificates": certificates, "phasePlans": {"bad": plan, "good": copy.deepcopy(plan)},
        "initial": {key: copy.deepcopy(baseline[key]) for key in ("trustRecordSHA256", "auditLog", "checkpoint")}}
    logs = {phase: b"".join(raw(row) + b"\n" for row in event_rows(info, phase)) for phase in check.PHASES}
    reports = {}
    for action in check.ACTIONS:
        reports[action] = {"schema": "chengwang.product-source-tls-driver/v1", "sourceCommit": SOURCE, "localImageID": info["localImageID"],
            "fault": fault, "kind": kind, "action": action, **check.BOUNDARY, "material": material, "observations": [],
            "offline": baseline if action == "reopen" else None}
    for phase, action, index in (("bad", "reject", 0), ("good", "recover", -1)):
        row = copy.deepcopy(old_reports["run"]["observations"][index])
        row.update(name="rejected" if phase == "bad" else "recovered", sourcePhase=phase, sourceFence=point(logs[phase]))
        row["status"].update(notAfterUnix=NOW + 3600, observedAtUnix=NOW + 10 if phase == "bad" else NOW + 20,
            auditVerifiedAtUnix=NOW + 10 if phase == "bad" else NOW + 20,
            refreshLastSuccessUnix=0 if phase == "bad" else NOW + 19, refreshUntilUnix=0 if phase == "bad" else NOW + 34)
        row["history"]["observedAtUnix"] = row["status"]["observedAtUnix"]
        reports[action]["observations"] = [row]
    return reports, logs


def final_fixture(root, graph, old_values, sources, certificate_sets):
    # Existing source test code supplies only synthetic old image projections.
    # No old runtime verdict or checker globals are changed.
    args_old, old_source_values = old.final_fixture(root, graph, old_values,
        {(flow, kind): sources[(check.FAULTS[index], kind)] for index, flow in enumerate(check.source.FLOWS) for kind in check.KINDS})
    del args_old
    values = {name: copy.deepcopy(old_values[name]) for name in ("product-image-staging.json", "product-image-packaged-contents.json")}
    harness = {path: check.image.sha(pathlib.Path(check.__file__).with_name(pathlib.PurePosixPath(path).name).read_bytes()) for path in check.HARNESS_PATHS}
    values["product-tls-harness.json"] = {"schema": "chengwang.product-tls-harness/v1", "sourceCommit": SOURCE, "files": harness,
        "checkoutBytesMatched": True, "permissionReadOnly": True, **check.BOUNDARY}
    registry_id = old_values["product-registry-observations.json"]["registryContainerID"]
    for label in ("network", "isolation"):
        values["product-tls-" + label + ".json"] = copy.deepcopy(old_values["product-registry-" + label + ".json"])
    removed, counters, snapshots = [], {}, []
    for index, (fault, kind) in enumerate((f, k) for f in check.FAULTS for k in check.KINDS):
        prefix = "product-tls-" + fault + "-" + kind + "-"
        source_prefix = "product-source-" + check.source.FLOWS[check.FAULTS.index(fault)] + "-" + kind + "-"
        reports, logs = reports_fixture(fault, kind, sources[(fault, kind)], certificate_sets[fault])
        material = reports["prepare"]["material"]
        values.update({prefix + action + ".json": report for action, report in reports.items()})
        values[prefix + "graph.json"] = graph
        product_id = h(fault + kind + "-tls-product")
        for label in ("running", "exited"):
            value = copy.deepcopy(old_values["product-registry-" + kind + "-" + label + "-inspect.json"])
            value.update(containerID=product_id, pid=5000 + index if label == "running" else 0)
            values[prefix + label + "-inspect.json"] = value
        for label in ("before-reject", "after-reject", "after-recover"):
            process = copy.deepcopy(old_values["product-registry-" + kind + "-running-pid1.json"])
            info = sources[(fault, kind)]
            process.update(schema="chengwang.product-tls-pid1/v1", containerID=product_id, hostPID=5000 + index, hostStartTime=6000 + index,
                trustConfigurationSHA256=h(fault + kind + "trust-config"), productConfigurationSHA256=h(fault + kind + "product-config"),
                refreshConfiguration={"refreshEnabled": True, "refreshURL": check.lifecycle.FEED_URL, "refreshIP": "127.0.0.1",
                    "refreshSPKI": info["feedSPKI"], "refreshCAFile": "/tmp/chengwang-product-lifecycle-" + "f" * 32 + "/refresh/tls-" + fault + "/" + kind + "/source-ca.pem",
                    "refreshCASHA256": info["feedCASHA256"][7:], "refreshIntervalSeconds": 2, "refreshMaxAgeSeconds": 15, "refreshTimeoutSeconds": 2})
            values[prefix + label + "-pid1.json"] = process
        for phase_index, phase in enumerate(check.PHASES):
            process = copy.deepcopy(old_source_values[source_prefix + "source.json"])
            for key in ("flow",):
                process.pop(key)
            cert = check.binary(certificate_sets[fault]["badChainRaw" if phase == "bad" else "goodChainRaw"])
            cert_sha, spki = check.image.sha(cert), check.public_spki(cert)
            metadata = {"deviceMajor": 0, "deviceMinor": 41, "inode": 10000 + index * 2 + phase_index,
                "bytes": len(cert), "mode": "0600", "uid": 10001, "gid": 10001, "nlink": 1, "sha256": cert_sha}
            pid, start = 7000 + index * 2 + phase_index, 8000 + index * 2 + phase_index
            process.update(schema="chengwang.product-tls-process/v1", fault=fault, sourcePhase=phase,
                sourceCase="source-tls-" + fault + "-" + phase, hostPID=pid, hostStartTime=start,
                readyPrefix=point(logs[phase], 0), publicCertificateSHA256=cert_sha, privateKeySPKI=spki,
                certificateInput={key: copy.deepcopy(metadata) for key in ("before", "after", "named")})
            process["sourceSHA256"] = harness[check.BASE + "fixture_source.py"]
            process["dependencySHA256"] = harness[check.BASE + "fixture_feed.py"]
            values[prefix + phase + "-source.json"] = process
            final = point(logs[phase])
            values[prefix + phase + "-source-stop.json"] = {"schema": "chengwang.product-tls-stop/v1", "sourceCommit": SOURCE,
                "fault": fault, "kind": kind, "sourcePhase": phase, "sourceCase": process["sourceCase"], "hostPID": pid, "startTime": start,
                "signal": "SIGTERM", "exitCode": 0, "joined": True, "sourceStopWindow": {"before": final, "after": copy.deepcopy(final)},
                "productStopWindows": [] if phase == "bad" else [{"label": "final", "before": final, "after": copy.deepcopy(final)}],
                "listenerAbsent": True, "listenerObservation": {"port": 5444, "tcpListening": 0, "tcp6Listening": 0, "registryNetworkNamespaceMatched": True}, **check.BOUNDARY}
            values[prefix + phase + "-feed-ready.json"] = {"schema": "chengwang.product-source-ready/v1", "port": 5444, "pid": pid,
                "uid": 10001, "gid": 10001, "tls": True, "listenLoopback": True, "deadlineSeconds": 600}
            values[prefix + phase + "-feed-events.jsonl"] = logs[phase]
        removed.append({"containerID": product_id, "role": "product", "fault": fault, "kind": kind})
        for action in check.ACTIONS:
            for position in ("before", "after"):
                if action == "prepare" and position == "after":
                    delta = {("GET", graph["registryManifestDigest"], 200): 1, ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                        ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
                    for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                        delta[("GET", desc["digest"], 200)] = 1
                    for key, count in delta.items():
                        counters[key] = counters.get(key, 0) + count
                snapshots.append({"ordinal": len(snapshots) + 1, "fault": fault, "kind": kind, "action": action, "position": position,
                    "digestRequests": [{"method": m, "digest": d, "status": s, "count": c} for (m, d, s), c in sorted(counters.items()) if d],
                    "otherRequests": [{"method": m, "status": s, "count": c} for (m, d, s), c in sorted(counters.items()) if not d]})
    removed.append({"containerID": registry_id, "role": "registry", "fault": "", "kind": ""})
    values["product-tls-observations.json"] = {"schema": "chengwang.product-tls-observations/v1", "sourceCommit": SOURCE,
        "localImageID": graph["localImageID"], "registryContainerID": registry_id, "pinnedRegistryImage": check.registry.REGISTRY_IMAGE,
        "snapshots": snapshots, **check.BOUNDARY}
    values["product-tls-runtime-cleanup.json"] = {"schema": "chengwang.product-tls-cleanup/v1", "sourceCommit": SOURCE,
        "localImageID": graph["localImageID"], "ownedContainersRemoved": 7, "ownedSourcesJoined": 12, "sourceExitCodes": [0] * 12,
        "normalProductStops": 6, "maximumConcurrentOwnedContainers": 2, "noOwnedContainersRemain": True, "removedContainers": removed,
        "registryStop": {"signal": "SIGTERM", "exitCode": 0, "oomKilled": False, "pid": 0}, "privateFixtureRemoved": True,
        "outerProductImagePreserved": True, "registryImagePreserved": True, "outcome": "PASS", **check.BOUNDARY}
    for label, suite, name in (("profile", "TLS_IMAGE_PROFILE", "test_source_tls_image_profile.py"), ("verifier", "TLS_VERIFIER", "test_check_product_source_tls.py")):
        values["product-tls-" + label + "-tests.log"] = old.transcript(pathlib.Path(check.__file__).with_name(name).read_bytes(), suite)
    directory = root / "tls-evidence"
    for name, value in values.items():
        graph_fixture.put(directory / name, value if type(value) is bytes else raw(value))
    return argparse.Namespace(evidence_dir=directory, source_commit=SOURCE, report=root / "tls-outcome.json"), values


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.root = pathlib.Path(cls.temporary.name)
        _, cls.old_values = graph_fixture.synthetic_final_evidence(cls.root)
        cls.graph = cls.old_values["product-registry-message-signature-graph.json"]
        cls.certificates = certificate_fixture()
        cls.sources = {(f, k): signed_material(f, k, cls.graph, cls.certificates[f]) for f in check.FAULTS for k in check.KINDS}
        # Only construction of immutable synthetic inputs is shared. Every test
        # writes an independent deepcopy; checker signature/certificate calls
        # are never cached or mocked by this template.
        _, cls.template_values = final_fixture(cls.root / "template", cls.graph, cls.old_values, cls.sources, cls.certificates)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.fault, self.kind = "ca", "message-signature"
        self.info = self.sources[(self.fault, self.kind)]
        self.reports, self.logs = reports_fixture(self.fault, self.kind, self.info, self.certificates[self.fault])

    def reject(self, function, *args):
        with self.assertRaises(check.CheckError):
            function(*args)

    def cert_check(self, value, fault=None, times=None):
        fault = self.fault if fault is None else fault
        return check.certificate_corpus(value, fault, self.sources[(fault, self.kind)], [NOW + 10, NOW + 20] if times is None else times)

    def loaded_fixture(self, root):
        directory = root / "tls-evidence"
        values = copy.deepcopy(self.template_values)
        for name, value in values.items():
            graph_fixture.put(directory / name, value if type(value) is bytes else raw(value))
        return argparse.Namespace(evidence_dir=directory, source_commit=SOURCE, report=root / "tls-outcome.json"), values

    def test_real_openssl_ca_san_spki_single_fault_corpus(self):
        for fault in check.FAULTS:
            self.cert_check(self.certificates[fault], fault)

    def test_unrelated_ca_must_not_reuse_trusted_ca_or_key(self):
        value = copy.deepcopy(self.certificates["ca"]); value["alternateCARaw"] = value["configuredCARaw"]
        self.reject(self.cert_check, value)

    def test_ca_fault_requires_matching_good_spki_and_hostname(self):
        for field in ("badChainRaw",):
            value = copy.deepcopy(self.certificates["ca"]); value[field] = self.certificates["spki"][field]
            self.reject(self.cert_check, value)

    def test_san_fault_requires_trusted_chain_and_exact_wrong_san(self):
        value = copy.deepcopy(self.certificates["san"]); value["badChainRaw"] = self.certificates["ca"]["badChainRaw"]
        self.reject(self.cert_check, value, "san")

    def test_spki_fault_requires_other_key_but_valid_ca_and_hostname(self):
        for replacement in (self.certificates["spki"]["goodChainRaw"], self.certificates["san"]["badChainRaw"]):
            value = copy.deepcopy(self.certificates["spki"]); value["badChainRaw"] = replacement
            self.reject(self.cert_check, value, "spki")

    def test_public_pem_chain_duplicate_private_key_or_trailing_text_rejected(self):
        cert = check.binary(self.certificates["ca"]["goodChainRaw"])
        for content in (cert + cert, cert + b"TOKEN_SENTINEL", b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"):
            if content == cert + cert:
                self.reject(check.pem_certificates, content)
            else:
                self.reject(check.pem_certificates, content)

    def test_certificate_validation_uses_actual_observation_time(self):
        self.cert_check(self.certificates["ca"])
        self.reject(self.cert_check, self.certificates["ca"], None, [NOW + 10 * 86400, NOW + 10 * 86400 + 1])

    def test_tool_failure_cannot_be_classified_tls_rejection(self):
        with mock.patch.object(check.subprocess, "run", return_value=argparse.Namespace(returncode=1, stdout=b"", stderr=b"")):
            self.reject(self.cert_check, self.certificates["ca"])

    def test_same_original_g1_plan_and_public_signature_material(self):
        check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)

    def test_changed_source_plan_epoch_or_raw_bytes_rejected(self):
        for key, value in (("epoch", 2), ("raw", b64(b'{}')), ("sha256", d("foreign"))):
            material = copy.deepcopy(self.reports["prepare"]["material"]); material["phasePlans"]["good"][key] = value
            self.reject(check.material, material, self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)

    def test_initial_checkpoint_and_empty_audit_are_original_bytes(self):
        value = self.reports["prepare"]["material"]["initial"]
        check.initial(value)
        for field in ("auditLog", "checkpoint"):
            changed = copy.deepcopy(value); changed[field]["sha256"] = h("foreign")
            self.reject(check.initial, changed)

    def test_bad_closed_attempts_allow_tls_ok_without_assigning_cause(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            rows = [check.parse(x) for x in self.logs["bad"].splitlines()]
            for row in rows:
                if row["event"] == "tls": row.update(reason="ok", tls=True)
                if row["event"] == "close": row["tls"] = True
            content = b"".join(raw(row) + b"\n" for row in rows)
            stopped = values[prefix + "bad-source-stop.json"]; stopped["sourceStopWindow"] = {"before": point(content), "after": point(content)}
            process = values[prefix + "bad-source.json"]
            corpus, docs, plans = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
            events, lines, complete, _ = check.phase_events(content, "bad", plans, corpus, stopped, process)
            observation = copy.deepcopy(self.reports["reject"]["observations"][0]); observation["sourceFence"] = point(content)
            self.assertEqual(check.observation(observation, "bad", self.info, docs, events, lines, complete, stopped)["closedRejectionAttemptsBeforeObservation"], 2)

    def test_timeout_stopping_or_incomplete_attempts_are_not_rejection_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            corpus, docs, plans = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
            for reason in ("timeout", "stopping"):
                rows = [check.parse(x) for x in self.logs["bad"].splitlines()]; rows[1]["reason"] = reason
                content = b"".join(raw(row) + b"\n" for row in rows); stopped = copy.deepcopy(values[prefix + "bad-source-stop.json"])
                stopped["sourceStopWindow"] = {"before": point(content), "after": point(content)}
                events, lines, complete, _ = check.phase_events(content, "bad", plans, corpus, stopped, values[prefix + "bad-source.json"])
                observation = copy.deepcopy(self.reports["reject"]["observations"][0]); observation["sourceFence"] = point(content)
                self.reject(check.observation, observation, "bad", self.info, docs, events, lines, complete, stopped)

    def test_bad_phase_may_not_emit_any_http(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            corpus, _, plans = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
            self.reject(check.phase_events, self.logs["good"], "bad", plans, corpus, values[prefix + "bad-source-stop.json"], values[prefix + "bad-source.json"])

    def test_rejected_api_must_be_unconfirmed_zero_last_until(self):
        row = copy.deepcopy(self.reports["reject"]["observations"][0]); row["status"].update(refreshLastSuccessUnix=NOW, refreshUntilUnix=NOW + 15)
        corpus, docs, _ = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
        del corpus
        self.reject(check.observation, row, "bad", self.info, docs, [], self.logs["bad"].splitlines(keepends=True), [],
            {"sourceStopWindow": {"before": point(self.logs["bad"])}})

    def test_fence_hash_and_source_stop_boundary_are_exact(self):
        row = copy.deepcopy(self.reports["reject"]["observations"][0]); row["sourceFence"]["sha256"] = h("foreign")
        _, docs, _ = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
        self.reject(check.observation, row, "bad", self.info, docs, [], self.logs["bad"].splitlines(keepends=True), [],
            {"sourceStopWindow": {"before": point(self.logs["bad"])}})

    def test_good_phase_actual_complete_g1_then_fresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            corpus, docs, plans = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
            stopped = values[prefix + "good-source-stop.json"]
            events, lines, complete, _ = check.phase_events(self.logs["good"], "good", plans, corpus, stopped, values[prefix + "good-source.json"])
            self.assertTrue(check.observation(self.reports["recover"]["observations"][0], "good", self.info, docs, events, lines, complete, stopped)["sameGenerationFreshConfirmed"])

    def test_fresh_boolean_without_completed_g1_is_rejected(self):
        _, docs, _ = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
        self.reject(check.observation, self.reports["recover"]["observations"][0], "good", self.info, docs, [],
            self.logs["good"].splitlines(keepends=True), [], {"sourceStopWindow": {"before": point(self.logs["good"])},
            "productStopWindows": [{"before": point(self.logs["good"])}]})

    def test_nonempty_good_ready_prefix_is_legal_product_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            corpus, _, plans = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
            process = copy.deepcopy(values[prefix + "good-source.json"]); process["readyPrefix"] = point(self.logs["good"], 2)
            check.phase_events(self.logs["good"], "good", plans, corpus, values[prefix + "good-source-stop.json"], process)

    def test_bad_ready_prefix_cannot_hide_probe_connections(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            corpus, _, plans = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
            process = copy.deepcopy(values[prefix + "bad-source.json"]); process["readyPrefix"] = point(self.logs["bad"], 1)
            self.reject(check.phase_events, self.logs["bad"], "bad", plans, corpus, values[prefix + "bad-source-stop.json"], process)

    def test_same_product_pid_start_binary_and_configuration_three_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            projections = {n: values[prefix + n + "-inspect.json"] for n in ("running", "exited")}
            processes = {n: values[prefix + n + "-pid1.json"] for n in ("before-reject", "after-reject", "after-recover")}
            rid = values["product-tls-observations.json"]["registryContainerID"]; sha = self.old_values["product-image-staging.json"]["binary"]["sha256"]
            check.product_runtime(projections, processes, SOURCE, self.graph["localImageID"], rid, sha, self.fault, self.kind, self.info)
            for key, value in (("hostPID", 9999), ("hostStartTime", 9999), ("trustConfigurationSHA256", h("foreign")), ("productConfigurationSHA256", h("foreign"))):
                changed = copy.deepcopy(processes); changed["after-recover"][key] = value
                self.reject(check.product_runtime, projections, changed, SOURCE, self.graph["localImageID"], rid, sha, self.fault, self.kind, self.info)

    def test_product_configuration_cannot_adopt_faulty_ca_or_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            projections = {n: values[prefix + n + "-inspect.json"] for n in ("running", "exited")}
            processes = {n: values[prefix + n + "-pid1.json"] for n in ("before-reject", "after-reject", "after-recover")}
            for process in processes.values(): process["refreshConfiguration"]["refreshSPKI"] = d("foreign")
            self.reject(check.product_runtime, projections, processes, SOURCE, self.graph["localImageID"], values["product-tls-observations.json"]["registryContainerID"],
                self.old_values["product-image-staging.json"]["binary"]["sha256"], self.fault, self.kind, self.info)

    def test_loader_bound_public_cert_and_private_public_key_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            cert = self.cert_check(self.certificates["ca"])["bad"]; harness = values["product-tls-harness.json"]["files"]
            process, stopped, ready = [values[prefix + "bad-" + n + ".json"] for n in ("source", "source-stop", "feed-ready")]
            check.source_process(process, stopped, ready, SOURCE, self.fault, self.kind, "bad", harness, cert)
            for key in ("publicCertificateSHA256", "privateKeySPKI"):
                changed = copy.deepcopy(process); changed[key] = h("foreign")
                self.reject(check.source_process, changed, stopped, ready, SOURCE, self.fault, self.kind, "bad", harness, cert)

    def test_certificate_replacement_hardlink_or_permission_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            cert = self.cert_check(self.certificates["ca"])["bad"]; harness = values["product-tls-harness.json"]["files"]
            process, stopped, ready = [values[prefix + "bad-" + n + ".json"] for n in ("source", "source-stop", "feed-ready")]
            for key, value in (("inode", 9999), ("nlink", 2), ("mode", "0644"), ("bytes", 2)):
                changed = copy.deepcopy(process); changed["certificateInput"]["named"][key] = value
                self.reject(check.source_process, changed, stopped, ready, SOURCE, self.fault, self.kind, "bad", harness, cert)

    def test_ready_boolean_deadline_and_listener_handoff_are_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); prefix = "product-tls-ca-message-signature-"
            cert = self.cert_check(self.certificates["ca"])["bad"]; harness = values["product-tls-harness.json"]["files"]
            process, stopped, ready = [values[prefix + "bad-" + n + ".json"] for n in ("source", "source-stop", "feed-ready")]
            for key, value in (("tls", 1), ("listenLoopback", 1), ("deadlineSeconds", 300)):
                changed = copy.deepcopy(ready); changed[key] = value
                self.reject(check.source_process, process, stopped, changed, SOURCE, self.fault, self.kind, "bad", harness, cert)
            changed = copy.deepcopy(stopped); changed["listenerObservation"]["tcpListening"] = 1
            self.reject(check.source_process, process, changed, ready, SOURCE, self.fault, self.kind, "bad", harness, cert)

    def test_final_logical_record_audit_and_checkpoint_unchanged(self):
        corpus, docs, _ = check.material(self.reports["prepare"]["material"], self.fault, self.kind, SOURCE, self.graph["localImageID"], self.graph)
        offline = self.reports["reopen"]["offline"]; initial = self.reports["prepare"]["material"]["initial"]
        last = self.reports["recover"]["observations"][0]
        check.offline(offline, last, initial, self.info, corpus, docs)
        changed = copy.deepcopy(offline); changed["trustRecordSHA256"] = h("foreign")
        self.reject(check.offline, changed, last, initial, self.info, corpus, docs)

    def test_registry_exact_prepare_and_eighteen_zero_request_windows(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); value = values["product-tls-observations.json"]
            graphs = {(f, k): self.graph for f in check.FAULTS for k in check.KINDS}
            check.traffic(value, SOURCE, self.graph["localImageID"], graphs)
            changed = copy.deepcopy(value); changed["snapshots"][3]["otherRequests"].append({"method": "GET", "status": 200, "count": 1})
            self.reject(check.traffic, changed, SOURCE, self.graph["localImageID"], graphs)

    def test_full_one_hundred_seventeen_relations_and_existing_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _ = self.loaded_fixture(pathlib.Path(temporary)); result = check.verify(args)
            self.assertEqual(len(result["evidenceSHA256"]), 117); graph_fixture.put(args.evidence_dir / "product-tls-outcome.json", raw(result))
            self.assertEqual(check.verify(args), result)

    def test_missing_unknown_prefix_or_tampered_outcome_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _ = self.loaded_fixture(pathlib.Path(temporary)); self.assertEqual(len(check.own_names()), 114)
            graph_fixture.put(args.evidence_dir / "product-tls-unknown.json", b'{}'); self.reject(check.verify, args)
            (args.evidence_dir / "product-tls-unknown.json").unlink()
            graph_fixture.put(args.evidence_dir / "product-tls-outcome.json", b'{"outcome":"PASS"}'); self.reject(check.verify, args)
            (args.evidence_dir / "product-tls-outcome.json").unlink()
            (args.evidence_dir / "product-tls-ca-message-signature-prepare.json").unlink(); self.reject(check.verify, args)

    def test_cleanup_requires_all_twelve_sources_and_exact_seven_containers(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, values = self.loaded_fixture(pathlib.Path(temporary)); value = values["product-tls-runtime-cleanup.json"]
            products = {(r["fault"], r["kind"]): r["containerID"] for r in value["removedContainers"] if r["role"] == "product"}
            rid = value["removedContainers"][-1]["containerID"]
            check.cleanup(value, SOURCE, self.graph["localImageID"], products, rid)
            changed = copy.deepcopy(value); changed["ownedSourcesJoined"] = 11
            self.reject(check.cleanup, changed, SOURCE, self.graph["localImageID"], products, rid)

    def test_named_transcript_and_marker_only_skip_rejection(self):
        source = pathlib.Path(__file__).read_bytes(); content = old.transcript(source, "TLS_VERIFIER")
        check.source.transcript(content, source, "TLS_VERIFIER", 32)
        self.reject(check.source.transcript, content.splitlines()[-1], source, "TLS_VERIFIER", 32)
        self.reject(check.source.transcript, content.replace(b'... ok', b'... skipped', 1), source, "TLS_VERIFIER", 32)

    def test_cli_failure_and_exclusive_output_suppress_private_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = pathlib.Path(temporary) / "report.json"
            argv = ["verify", "--evidence-dir", temporary, "--source-commit", SOURCE, "--report", str(report)]
            with contextlib.redirect_stderr(io.StringIO()) as errors, mock.patch.object(check, "verify", side_effect=check.CheckError("TOKEN_SENTINEL")):
                self.assertEqual(check.main(argv), 1)
            self.assertNotIn("TOKEN_SENTINEL", errors.getvalue()); self.assertFalse(report.exists())
            graph_fixture.put(report, b"original")
            with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(check, "verify", return_value={}):
                self.assertEqual(check.main(argv), 1)
            self.assertEqual(report.read_bytes(), b"original")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TLSTests))
    accepted = result.wasSuccessful() and result.testsRun == 32 and not result.skipped
    if accepted:
        print("D12_SOURCE_TLS_VERIFIER_TESTS=PASS tests=32 skipped=0 synthetic_only=true")
    raise SystemExit(0 if accepted else 1)
