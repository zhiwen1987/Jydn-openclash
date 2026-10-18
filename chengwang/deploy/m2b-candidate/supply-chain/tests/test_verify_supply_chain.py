from __future__ import annotations

import base64
import contextlib
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import tarfile
import time
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "verify_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("verify_supply_chain", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

NOW = 2_000_000_000
REPOSITORY = "registry.example.com/chengwang/probe-agent"
ISSUER = "https://token.actions.githubusercontent.com"
SUBJECT = "https://github.com/example/chengwang/.github/workflows/release.yml@refs/heads/main"
BUILDER = "https://github.com/Attestations/GitHubHostedActions@v1"
PREDICATE = "https://slsa.dev/provenance/v1"
ALGORITHM = "ECDSA_P256_SHA256"
RUN_ID = "fixture-run-0001"


def instant(seconds: int) -> str:
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def dump(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        if os.name == "posix" and os.geteuid() != 0:
            self.skipTest("production path security tests require root on POSIX")
        temp_parent = "/root" if os.name == "posix" else None
        self.temp = tempfile.TemporaryDirectory(dir=temp_parent)
        self.root = pathlib.Path(self.temp.name) / "evidence"
        self.root.mkdir(mode=0o700)
        (self.root / "blobs" / "sha256").mkdir(parents=True)
        if os.name == "posix":
            (self.root / "blobs").chmod(0o700)
            (self.root / "blobs" / "sha256").chmod(0o700)
        self.policy_path = pathlib.Path(self.temp.name) / "policy.json"
        self.build_fixture()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path: pathlib.Path, raw: bytes):
        path.write_bytes(raw)
        if os.name == "posix":
            path.chmod(0o600)

    def write_json(self, path: pathlib.Path, value):
        self.write(path, dump(value))

    def build_fixture(self):
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            payload = b"fixture-layer\n"
            member = tarfile.TarInfo("app/fixture.txt")
            member.size = len(payload)
            member.mode = 0o644
            member.mtime = 0
            archive.addfile(member, io.BytesIO(payload))
        uncompressed_layer = tar_buffer.getvalue()
        layer = gzip.compress(uncompressed_layer, mtime=0)
        layer_digest = digest(layer)
        self.write(self.root / "blobs" / "sha256" / layer_digest[7:], layer)
        config = {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [digest(uncompressed_layer)]}}
        config_raw = dump(config)
        self.write(self.root / "config.json", config_raw)
        manifest = {
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config_raw), "size": len(config_raw)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_digest, "size": len(layer)}],
        }
        manifest_raw = dump(manifest)
        self.write(self.root / "manifest.json", manifest_raw)
        self.image_digest = digest(manifest_raw)
        purl = f"pkg:oci/{REPOSITORY}@{self.image_digest}"
        sbom = {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "probe-agent", "documentNamespace": "https://example.com/spdx/fixture",
            "creationInfo": {"created": instant(NOW - 30), "creators": ["Tool: fixture/1.0"]},
            "packages": [{"SPDXID": "SPDXRef-Package", "name": "probe-agent", "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]}],
            "documentDescribes": ["SPDXRef-Package"],
        }
        sbom_raw = dump(sbom)
        self.write(self.root / "sbom.spdx.json", sbom_raw)
        statement = {
            "_type": MODULE.IN_TOTO_STATEMENT,
            "subject": [{"name": REPOSITORY, "digest": {"sha256": self.image_digest[7:]}}],
            "predicateType": PREDICATE,
            "predicate": {"buildType": "https://example.com/build/v1", "builder": {"id": BUILDER},
                          "metadata": {"buildStartedOn": instant(NOW - 90), "buildFinishedOn": instant(NOW - 60), "invocationId": RUN_ID},
                          "materials": [{"uri": "git+https://github.com/example/chengwang", "digest": {"sha256": "2" * 64}}]},
        }
        envelope = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(dump(statement)).decode(),
                    "signatures": [{"keyid": "fixture", "sig": base64.b64encode(b"x" * 64).decode()}]}
        envelope_raw = dump(envelope)
        self.write(self.root / "attestation.dsse.json", envelope_raw)
        policy = {
            "schema": MODULE.POLICY_SCHEMA, "issuedAt": instant(NOW - 120), "expiresAt": instant(NOW + 3600),
            "maxEvidenceAgeSeconds": 600, "maxFutureSkewSeconds": 30, "expectedImageRepository": REPOSITORY,
            "expectedImageDigest": self.image_digest, "expectedIssuer": ISSUER, "expectedSubject": SUBJECT,
            "allowedBuilderIds": [BUILDER], "allowedPredicateTypes": [PREDICATE],
            "allowedSignatureAlgorithms": [ALGORITHM],
            "expectedVerifier": {"name": "fixture-verifier", "version": "test-only", "binaryDigest": "sha256:" + "6" * 64},
            "expectedTrustRootDigest": "sha256:" + "7" * 64, "expectedRunId": RUN_ID, "requireTransparencyLog": True,
        }
        self.write_json(self.policy_path, policy)
        self.policy_digest = digest(self.policy_path.read_bytes())
        certificate_der = b"0" * 256
        certificate_digest = digest(certificate_der)
        bundle = {
            "schema": MODULE.SIGNATURE_BUNDLE_SCHEMA, "runId": RUN_ID, "signedArtifactDigest": self.image_digest,
            "signature": {"algorithm": ALGORITHM, "value": base64.b64encode(b"s" * 64).decode()},
            "certificate": {"der": base64.b64encode(certificate_der).decode(), "sha256": certificate_digest,
                            "issuer": ISSUER, "subject": SUBJECT, "notBefore": instant(NOW - 300), "notAfter": instant(NOW + 300)},
            "transparencyLog": {"logId": "fixture-log", "logIndex": 42, "integratedTime": instant(NOW - 25),
                                "inclusionProof": {"rootHash": "4" * 64, "treeSize": 100, "hashes": ["5" * 64]}},
        }
        bundle_raw = dump(bundle)
        self.write(self.root / "signature.bundle.json", bundle_raw)
        receipt = {
            "schema": MODULE.RECEIPT_SCHEMA, "runId": RUN_ID, "verifiedAt": instant(NOW - 20), "imageRepository": REPOSITORY,
            "imageDigest": self.image_digest, "manifestDigest": self.image_digest, "configDigest": digest(config_raw),
            "layerDigests": [layer_digest], "sbomDigest": digest(sbom_raw), "attestationDigest": digest(envelope_raw),
            "signatureBundleDigest": digest(bundle_raw),
            "issuer": ISSUER, "subject": SUBJECT,
            "certificate": {"sha256": certificate_digest, "notBefore": instant(NOW - 300), "notAfter": instant(NOW + 300)},
            "transparencyLog": {"included": True, "integratedTime": instant(NOW - 25), "logId": "fixture-log", "logIndex": 42},
            "verifier": {"name": "fixture-verifier", "version": "test-only", "binaryDigest": "sha256:" + "6" * 64,
                         "trustRootDigest": "sha256:" + "7" * 64, "offline": True, "policyDigest": self.policy_digest},
            "verification": {name: True for name in ["signatureVerified", "certificateChainVerified", "issuerMatched", "subjectMatched", "manifestDigestMatched", "sbomDigestMatched", "attestationDigestMatched", "transparencyProofVerified"]},
        }
        self.write_json(self.root / "signature-evidence.json", receipt)

    def verify(self):
        return MODULE.verify(self.root.resolve(), self.policy_path.resolve(), NOW)

    def retime_for_cli(self):
        now = int(time.time())
        policy = json.loads(self.policy_path.read_text())
        policy["issuedAt"], policy["expiresAt"] = instant(now - 120), instant(now + 3600)
        self.write_json(self.policy_path, policy)

        sbom_path = self.root / "sbom.spdx.json"
        sbom = json.loads(sbom_path.read_text())
        sbom["creationInfo"]["created"] = instant(now - 30)
        self.write_json(sbom_path, sbom)

        attestation_path = self.root / "attestation.dsse.json"
        envelope = json.loads(attestation_path.read_text())
        statement = json.loads(base64.b64decode(envelope["payload"]))
        statement["predicate"]["metadata"]["buildStartedOn"] = instant(now - 90)
        statement["predicate"]["metadata"]["buildFinishedOn"] = instant(now - 60)
        envelope["payload"] = base64.b64encode(dump(statement)).decode()
        self.write_json(attestation_path, envelope)

        bundle_path = self.root / "signature.bundle.json"
        bundle = json.loads(bundle_path.read_text())
        bundle["certificate"]["notBefore"], bundle["certificate"]["notAfter"] = instant(now - 300), instant(now + 300)
        bundle["transparencyLog"]["integratedTime"] = instant(now - 25)
        self.write_json(bundle_path, bundle)

        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["verifiedAt"] = instant(now - 20)
        receipt["sbomDigest"] = digest(sbom_path.read_bytes())
        receipt["attestationDigest"] = digest(attestation_path.read_bytes())
        receipt["signatureBundleDigest"] = digest(bundle_path.read_bytes())
        receipt["certificate"]["notBefore"], receipt["certificate"]["notAfter"] = instant(now - 300), instant(now + 300)
        receipt["transparencyLog"]["integratedTime"] = instant(now - 25)
        receipt["verifier"]["policyDigest"] = digest(self.policy_path.read_bytes())
        self.write_json(receipt_path, receipt)

    def replace_single_layer(self, uncompressed: bytes, *, compressed: bytes | None = None):
        layer_dir = self.root / "blobs" / "sha256"
        for existing in layer_dir.iterdir():
            existing.unlink()
        layer = gzip.compress(uncompressed, mtime=0) if compressed is None else compressed
        layer_digest = digest(layer)
        self.write(layer_dir / layer_digest[7:], layer)
        config_path = self.root / "config.json"
        config = json.loads(config_path.read_text())
        config["rootfs"]["diff_ids"] = [digest(uncompressed)]
        self.write_json(config_path, config)
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["config"]["digest"] = digest(config_path.read_bytes())
        manifest["config"]["size"] = config_path.stat().st_size
        manifest["layers"][0]["digest"] = layer_digest
        manifest["layers"][0]["size"] = len(layer)
        self.write_json(manifest_path, manifest)
        policy = json.loads(self.policy_path.read_text())
        policy["expectedImageDigest"] = digest(manifest_path.read_bytes())
        self.write_json(self.policy_path, policy)

    def rewrite_config_and_manifest(self, config):
        config_path = self.root / "config.json"
        self.write_json(config_path, config)
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["config"]["digest"] = digest(config_path.read_bytes())
        manifest["config"]["size"] = config_path.stat().st_size
        self.write_json(manifest_path, manifest)
        policy = json.loads(self.policy_path.read_text())
        policy["expectedImageDigest"] = digest(manifest_path.read_bytes())
        self.write_json(self.policy_path, policy)

    def test_complete_fixture_is_still_blocked(self):
        report = self.verify()
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["authorizationGranted"])
        self.assertEqual(report["structuralChecks"], "PASS")
        self.assertEqual(report["cryptographicChecks"], "UNTRUSTED_EXTERNAL_ASSERTIONS_ONLY")
        self.assertEqual(report["replayProtection"], "UNAVAILABLE_OFFLINE")

    def test_manifest_digest_mismatch_rejected(self):
        manifest = json.loads((self.root / "manifest.json").read_text())
        manifest["annotations"] = {"changed": "yes"}
        self.write_json(self.root / "manifest.json", manifest)
        with self.assertRaisesRegex(MODULE.ContractError, "manifest bytes"):
            self.verify()

    def test_manifest_media_type_object_rejected_cleanly(self):
        manifest = json.loads((self.root / "manifest.json").read_text())
        manifest["mediaType"] = {"unexpected": True}
        raw = dump(manifest)
        self.write(self.root / "manifest.json", raw)
        policy = json.loads(self.policy_path.read_text())
        policy["expectedImageDigest"] = digest(raw)
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "manifest.mediaType"):
            self.verify()

    def test_manifest_artifact_type_is_not_silently_accepted(self):
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifactType"] = 123
        self.write_json(manifest_path, manifest)
        policy = json.loads(self.policy_path.read_text())
        policy["expectedImageDigest"] = digest(manifest_path.read_bytes())
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "unknown fields"):
            self.verify()

    def test_layer_content_mismatch_rejected(self):
        layer_path = next((self.root / "blobs" / "sha256").iterdir())
        self.write(layer_path, b"tampered")
        with self.assertRaisesRegex(MODULE.ContractError, "descriptor does not match"):
            self.verify()

    def test_layer_diff_id_mismatch_rejected(self):
        config_path = self.root / "config.json"
        config = json.loads(config_path.read_text())
        config["rootfs"]["diff_ids"] = ["sha256:" + "a" * 64]
        self.write_json(config_path, config)
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["config"]["digest"] = digest(config_path.read_bytes())
        manifest["config"]["size"] = config_path.stat().st_size
        self.write_json(manifest_path, manifest)
        policy = json.loads(self.policy_path.read_text())
        policy["expectedImageDigest"] = digest(manifest_path.read_bytes())
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "diff_id"):
            self.verify()

    def test_layer_must_be_valid_tar(self):
        self.replace_single_layer(b"not-a-tar-archive")
        with self.assertRaisesRegex(MODULE.ContractError, "tar archive"):
            self.verify()

    def test_layer_tar_path_traversal_rejected(self):
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            payload = b"escape"
            member = tarfile.TarInfo("../escape")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        self.replace_single_layer(tar_buffer.getvalue())
        with self.assertRaisesRegex(MODULE.ContractError, "unsafe member path"):
            self.verify()

    def test_layer_expansion_ratio_stops_before_full_decompression(self):
        self.replace_single_layer(b"0" * (2 * 1024 * 1024))
        with self.assertRaisesRegex(MODULE.ContractError, "uncompressed layer exceeds"):
            self.verify()

    def test_config_mismatch_rejected(self):
        config = json.loads((self.root / "config.json").read_text())
        config["architecture"] = "arm64"
        self.write_json(self.root / "config.json", config)
        with self.assertRaisesRegex(MODULE.ContractError, "config descriptor"):
            self.verify()

    def test_config_history_wrong_type_rejected(self):
        config = json.loads((self.root / "config.json").read_text())
        config["history"] = {"unexpected": None}
        self.rewrite_config_and_manifest(config)
        with self.assertRaisesRegex(MODULE.ContractError, "config.history"):
            self.verify()

    def test_config_surrogate_string_rejected(self):
        config = json.loads((self.root / "config.json").read_text())
        config["author"] = "\ud800"
        self.rewrite_config_and_manifest(config)
        with self.assertRaisesRegex(MODULE.ContractError, "Unicode scalar"):
            self.verify()

    def test_config_created_requires_oci_rfc3339_nano(self):
        config = json.loads((self.root / "config.json").read_text())
        config["created"] = "not-rfc3339"
        self.rewrite_config_and_manifest(config)
        with self.assertRaisesRegex(MODULE.ContractError, "RFC3339Nano"):
            self.verify()

    def test_duplicate_json_key_rejected(self):
        self.write(self.policy_path, b'{"schema":"x","schema":"y"}')
        with self.assertRaisesRegex(MODULE.ContractError, "duplicate JSON key"):
            self.verify()

    def test_unknown_policy_field_rejected(self):
        policy = json.loads(self.policy_path.read_text())
        policy["allowUnsigned"] = True
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "unknown fields"):
            self.verify()

    def test_non_finite_json_rejected(self):
        raw = self.policy_path.read_text()
        self.write(self.policy_path, raw[:-1].encode() + b',"extra":NaN}')
        with self.assertRaisesRegex(MODULE.ContractError, "non-finite"):
            self.verify()

    def test_overflowing_json_float_rejected(self):
        sbom_path = self.root / "sbom.spdx.json"
        raw = sbom_path.read_bytes()
        self.write(sbom_path, raw[:-1] + b',"comment":1e400}')
        with self.assertRaisesRegex(MODULE.ContractError, "floating-point"):
            self.verify()

    def test_surrogate_unicode_rejected(self):
        policy = json.loads(self.policy_path.read_text())
        policy["expectedIssuer"] = "\ud800"
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "Unicode scalar"):
            self.verify()

    def test_object_in_allowlist_rejected_cleanly(self):
        policy = json.loads(self.policy_path.read_text())
        policy["allowedBuilderIds"] = [{}]
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "allowlist item"):
            self.verify()

    def test_non_sha256_expected_digest_rejected(self):
        policy = json.loads(self.policy_path.read_text())
        policy["expectedImageDigest"] = "sha512:" + "0" * 128
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "lowercase sha256"):
            self.verify()

    def test_stale_receipt_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["verifiedAt"] = instant(NOW - 601)
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "stale"):
            self.verify()

    def test_signature_integration_cannot_predate_sbom(self):
        sbom_path = self.root / "sbom.spdx.json"
        sbom = json.loads(sbom_path.read_text())
        sbom["creationInfo"]["created"] = instant(NOW - 5)
        self.write_json(sbom_path, sbom)
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["sbomDigest"] = digest(sbom_path.read_bytes())
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "predates SBOM"):
            self.verify()

    def test_receipt_cannot_predate_transparency_integration(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["verifiedAt"] = instant(NOW - 30)
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "receipt predates"):
            self.verify()

    def test_future_receipt_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["verifiedAt"] = instant(NOW + 31)
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "future"):
            self.verify()

    def test_issuer_mismatch_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["issuer"] = "https://evil.example"
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "issuer"):
            self.verify()

    def test_subject_mismatch_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["subject"] = "https://github.com/evil/repo"
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "subject"):
            self.verify()

    def test_predicate_not_allowlisted_rejected(self):
        envelope_path = self.root / "attestation.dsse.json"
        envelope = json.loads(envelope_path.read_text())
        statement = json.loads(base64.b64decode(envelope["payload"]))
        statement["predicateType"] = "https://evil.example/predicate"
        envelope["payload"] = base64.b64encode(dump(statement)).decode()
        self.write_json(envelope_path, envelope)
        with self.assertRaisesRegex(MODULE.ContractError, "predicate type"):
            self.verify()

    def test_signature_algorithm_not_allowlisted_rejected(self):
        bundle_path = self.root / "signature.bundle.json"
        bundle = json.loads(bundle_path.read_text())
        bundle["signature"]["algorithm"] = "RSA_SHA1"
        self.write_json(bundle_path, bundle)
        with self.assertRaisesRegex(MODULE.ContractError, "algorithm"):
            self.verify()

    def test_policy_cannot_allow_unknown_signature_algorithm(self):
        policy = json.loads(self.policy_path.read_text())
        policy["allowedSignatureAlgorithms"].append("RSA_SHA1")
        self.write_json(self.policy_path, policy)
        with self.assertRaisesRegex(MODULE.ContractError, "unsupported algorithm"):
            self.verify()

    def test_signature_bundle_digest_mismatch_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["signatureBundleDigest"] = "sha256:" + "8" * 64
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "signatureBundleDigest"):
            self.verify()

    def test_false_external_verification_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["verification"]["signatureVerified"] = False
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "signatureVerified"):
            self.verify()

    def test_missing_sbom_is_rejected(self):
        (self.root / "sbom.spdx.json").unlink()
        with self.assertRaisesRegex(MODULE.ContractError, "missing=.*sbom"):
            self.verify()

    def test_unsupported_sbom_optional_subtree_rejected(self):
        sbom_path = self.root / "sbom.spdx.json"
        sbom = json.loads(sbom_path.read_text())
        sbom["relationships"] = [{"unknown": "field"}]
        self.write_json(sbom_path, sbom)
        with self.assertRaisesRegex(MODULE.ContractError, "unknown fields"):
            self.verify()

    def test_unknown_evidence_file_rejected(self):
        self.write(self.root / "unsigned-note.txt", b"extra")
        with self.assertRaisesRegex(MODULE.ContractError, "tree shape mismatch"):
            self.verify()

    def test_receipt_policy_digest_mismatch_rejected(self):
        receipt_path = self.root / "signature-evidence.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["verifier"]["policyDigest"] = "sha256:" + "9" * 64
        self.write_json(receipt_path, receipt)
        with self.assertRaisesRegex(MODULE.ContractError, "policyDigest"):
            self.verify()

    def test_symlink_input_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        original = self.root / "manifest.json"
        moved = self.root / "manifest.real.json"
        original.rename(moved)
        try:
            os.symlink(moved, original)
        except OSError:
            self.skipTest("symlink creation not permitted")
        with self.assertRaisesRegex(MODULE.ContractError, "symlink"):
            self.verify()

    def test_hardlink_input_rejected(self):
        original = self.root / "manifest.json"
        linked = self.root / "manifest.link.json"
        try:
            os.link(original, linked)
        except OSError:
            self.skipTest("hardlink creation not permitted")
        with self.assertRaisesRegex(MODULE.ContractError, "one hard link"):
            self.verify()

    def test_cli_writes_blocked_report_and_exit_78(self):
        self.retime_for_cli()
        output = pathlib.Path(self.temp.name) / "blocked.json"
        code = MODULE.main(["verify", "--evidence-root", str(self.root.resolve()), "--policy", str(self.policy_path.resolve()), "--output", str(output.resolve())])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        report = json.loads(output.read_text())
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["authorizationGranted"])
        self.assertEqual(report["reason"], "CRYPTOGRAPHIC_TRUST_GATE_NOT_IMPLEMENTED")
        self.assertEqual(report["structuralChecks"], "PASS")

    def test_cli_malicious_type_writes_contract_blocked_report(self):
        policy = json.loads(self.policy_path.read_text())
        policy["allowedBuilderIds"] = [{}]
        self.write_json(self.policy_path, policy)
        output = pathlib.Path(self.temp.name) / "bad-type.json"
        code = MODULE.main(["verify", "--evidence-root", str(self.root.resolve()), "--policy", str(self.policy_path.resolve()), "--output", str(output.resolve())])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        report = json.loads(output.read_text())
        self.assertEqual(report["reason"], "EVIDENCE_CONTRACT_FAILED")

    def test_cli_contract_error_is_utf8_bounded_to_report_schema_limit(self):
        policy = json.loads(self.policy_path.read_text())
        for index in range(100):
            policy[f"unknown_{index}_" + "x" * 180] = True
        self.write_json(self.policy_path, policy)
        output = pathlib.Path(self.temp.name) / "long-error.json"
        code = MODULE.main(["verify", "--evidence-root", str(self.root.resolve()), "--policy", str(self.policy_path.resolve()), "--output", str(output.resolve())])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        report = json.loads(output.read_text())
        self.assertLessEqual(len(report["error"].encode("utf-8")), 4096)
        self.assertRegex(report["error"], r"\[sha256:[0-9a-f]{64}\]$")

    def test_atomic_report_publish_leaves_no_temporary_file(self):
        self.retime_for_cli()
        output = pathlib.Path(self.temp.name) / "atomic-report.json"
        self.assertEqual(MODULE.main(["verify", "--evidence-root", str(self.root.resolve()), "--policy", str(self.policy_path.resolve()), "--output", str(output.resolve())]), MODULE.BLOCKED_EXIT)
        self.assertTrue(output.is_file())
        self.assertEqual(list(pathlib.Path(self.temp.name).glob(".chengwang-supply-chain-*")), [])

    def test_cli_missing_evidence_root_still_writes_blocked_report(self):
        output = pathlib.Path(self.temp.name) / "missing-root.json"
        missing = pathlib.Path(self.temp.name) / "absent"
        code = MODULE.main(["verify", "--evidence-root", str(missing.resolve()), "--policy", str(self.policy_path.resolve()), "--output", str(output.resolve())])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        report = json.loads(output.read_text())
        self.assertEqual(report["reason"], "EVIDENCE_CONTRACT_FAILED")

    def test_cli_missing_arguments_returns_blocked_json_not_argparse_exit(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = MODULE.main([])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["reason"], "EVIDENCE_CONTRACT_FAILED")
        self.assertFalse(report["authorizationGranted"])

    def test_cli_unknown_argument_returns_blocked_json(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = MODULE.main(["--definitely-unknown"])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "BLOCKED")

    def test_output_no_clobber(self):
        output = pathlib.Path(self.temp.name) / "exists.json"
        output.write_text("do-not-overwrite")
        code = MODULE.main(["verify", "--evidence-root", str(self.root.resolve()), "--policy", str(self.policy_path.resolve()), "--output", str(output.resolve())])
        self.assertEqual(code, MODULE.BLOCKED_EXIT)
        self.assertEqual(output.read_text(), "do-not-overwrite")


if __name__ == "__main__":
    unittest.main()
