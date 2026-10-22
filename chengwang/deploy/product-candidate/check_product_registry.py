#!/usr/bin/env python3
"""Independent bounded D11 artifact consistency gates, never a release authority.

The graph command independently hashes bytes saved by the normal-TLS preparer
after a Registry readback matched the upload. This Python command itself does
not perform a remote read. Actual image API reads have separate Registry logs.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import sys
import tarfile
import zlib

sys.dont_write_bytecode = True
import check_product_image as image

CheckError = image.CheckError
require = image.require
decode = image.decode
sha = image.sha
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BOUNDARY = {"authorization": "BLOCKED", "production": False,
            "deviceActionsExecuted": False}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json",
                "application/vnd.docker.container.image.v1+json"}
TAR_TYPES = {"application/vnd.oci.image.layer.v1.tar",
             "application/vnd.docker.image.rootfs.diff.tar"}
GZIP_TYPES = {"application/vnd.oci.image.layer.v1.tar+gzip",
              "application/vnd.docker.image.rootfs.diff.tar.gzip"}
KINDS = ("message-signature", "dsse")
REGISTRY_IMAGE = "registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151"
STAGES = (("prepare", 0), *(("exercise", n) for n in range(1, 5)),
          ("resume", 1), ("catalogue", 0), *(("resume", n) for n in range(2, 5)), ("final", 0))
GRAPH_ORIGIN = "NORMAL_TLS_REGISTRY_READBACK_MATCHED_UPLOAD"
MATERIAL_FIELDS = ("kind", "sourceCommit", "localImageID", "manifestSHA256", "configSHA256",
                   "layerSHA256s", "diffIDs", "catalogue1SHA256", "catalogue2SHA256", "storeID", "policies")
ACTION_FIELDS = ("schema", "action", "case", *MATERIAL_FIELDS, "authority", "graphOrigin", *BOUNDARY,
                 "cases", "journalAuditBindingsVerified")
STATUS_FIELDS = ("boundary", "authorization", "deviceActionsExecuted", "healthy", "fresh", "storeId", "generation",
                 "catalogueSHA256", "notAfterUnix", "sequence", "ledgerEntries", "ledgerCapacity", "reserved", "consumed",
                 "revokedKeys", "revokedApprovals", "revokedManifests", "policies", "refreshRequired", "refreshFresh",
                 "refreshLastSuccessUnix", "refreshUntilUnix", "recoveryCompleted", "observedAtUnix", "auditVerifiedAtUnix")
HISTORY_FIELDS = ("boundary", "authorization", "deviceActionsExecuted", "observedAtUnix", "sequence", "total", "offset", "limit", "entries")
ENTRY_FIELDS = ("operationId", "actorId", "kind", "state", "outcome", "acknowledged", "policyId", "grantId", "generation",
                "catalogueSHA256", "preparedAuditHash", "resultAuditHash", "preparedAtUnix", "resultAtUnix")
CASE_FIELDS = ("name", "method", "path", "httpStatus", "errorCode", "stateMayHaveChanged", "policyID", "grantID",
               "approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256", "trustedRootSHA256", "requestSHA256",
               "statusBefore", "statusAfter", "historyBefore", "historyAfter")
CASE_MATRIX = (("exercise", 1, "success", "accepted", 200, (6, 1, 1, 0, 1)),
               ("exercise", 2, "replay", "accepted", 400, (10, 1, 1, 0, 2)),
               ("exercise", 3, "approval-tamper", "accepted", 400, (14, 1, 1, 0, 3)),
               ("exercise", 4, "crossed-bundle", "cross", 400, (19, 1, 2, 1, 4)),
               ("resume", 1, "replay-after-restart", "accepted", 400, (23, 1, 2, 1, 5)),
               ("catalogue", 0, "revocation-install", None, 200, (27, 2, 2, 1, 6)),
               ("catalogue", 0, "rollback-rejected", None, 400, (31, 2, 2, 1, 7)),
               ("resume", 2, "revoked-unused", "revoked", 400, (35, 2, 2, 1, 8)),
               ("resume", 3, "wrong-spki", "spki", 400, (40, 2, 3, 2, 9)),
               ("resume", 4, "reserved-replay", "cross", 400, (44, 2, 3, 2, 10)))


def read_file(path, limit):
    if os.name == "posix":
        return image.read_file(path, limit)
    # Windows stat exposes birth-time in st_ctime while fstat may expose change
    # time. Compare like APIs to themselves, retaining every POSIX check above.
    path = image.checked_path(path)
    before = path.stat()
    require(0 < before.st_size <= limit, "input size rejected")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        common = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode, s.st_nlink)
        require(common(before) == common(opened), "input changed while opening")
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        current = path.stat()
        require(common(before) == common(after) == common(current)
                and opened.st_ctime_ns == after.st_ctime_ns
                and before.st_ctime_ns == current.st_ctime_ns
                and len(raw) == before.st_size, "input changed while reading")
        return raw


def exact(value, fields, message="artifact fields rejected"):
    require(isinstance(value, dict) and set(value) == set(fields), message)


def integer(value, minimum=0, maximum=1 << 62):
    require(type(value) is int and minimum <= value <= maximum, "integer rejected")
    return value


def digest(value):
    require(isinstance(value, str) and DIGEST.fullmatch(value), "digest rejected")
    return value


def json_file(path, limit=4 << 20):
    raw = read_file(path, limit)
    value = decode(raw)
    require(isinstance(value, dict), "object required")
    return value, raw


def descriptor(value, allowed):
    exact(value, ("mediaType", "digest", "size"), "descriptor extensions rejected")
    require(value["mediaType"] in allowed, "descriptor media type rejected")
    digest(value["digest"])
    integer(value["size"], 1, 128 << 20)
    return value


def read_blob(directory, desc):
    raw = read_file(directory / "blobs" / desc["digest"][7:], 128 << 20)
    require(len(raw) == desc["size"] and "sha256:" + sha(raw) == desc["digest"], "blob identity mismatch")
    return raw


def unpack_layer(raw, media_type):
    if media_type in TAR_TYPES:
        require(not raw.startswith(b"\x1f\x8b"), "tar media type mismatch")
        return raw
    require(media_type in GZIP_TYPES and raw.startswith(b"\x1f\x8b"), "gzip media type mismatch")
    # One complete gzip member only: no concatenation, ignored bytes or bombs.
    stream = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        result = stream.decompress(raw, (256 << 20) + 1)
    except zlib.error as error:
        raise CheckError("gzip layer rejected") from error
    require(len(result) <= 256 << 20 and stream.eof and not stream.unused_data
            and not stream.unconsumed_tail, "gzip bounds or trailing data rejected")
    require(len(result) <= max(1 << 20, len(raw) * 200), "gzip expansion rejected")
    return result


def tar_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 512 and "\\" not in value
            and "\x00" not in value and not value.startswith("/"), "layer path rejected")
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    require(value not in {"", "."} and pathlib.PurePosixPath(value).as_posix() == value
            and all(part not in {"", ".", ".."} and not part.startswith(".wh.")
                    for part in value.split("/")), "layer path rejected")
    return value


def layer_files(raw, expected, files):
    require(len(raw) % 512 == 0 and len(raw) >= 1024, "tar framing rejected")
    seen = set()
    end = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            require(not archive.pax_headers, "global tar extensions rejected")
            for index, member in enumerate(archive):
                require(index < 4096 and not member.pax_headers and not member.sparse
                        and (member.isdir() or member.isreg()), "tar member rejected")
                name = tar_path(member.name)
                require(name not in seen and member.uid == 0 and member.gid == 0, "tar duplicate or owner rejected")
                seen.add(name)
                end = member.offset_data + ((member.size + 511) // 512) * 512
                if member.isdir():
                    require(member.mode == 0o555 and member.size == 0
                            and any(path.startswith(name + "/") for path in expected), "tar directory rejected")
                    continue
                require(name in expected and name not in files and 0 < member.size <= 128 << 20,
                        "extra or replaced packaged file rejected")
                require(member.mode == (0o555 if name == "app/image-trust-api" else 0o444), "tar file mode rejected")
                stream = archive.extractfile(member)
                require(stream is not None, "tar payload unavailable")
                contents = stream.read((128 << 20) + 1)
                record = {"sha256": sha(contents), "bytes": len(contents),
                          "mode": format(member.mode, "04o"), "uid": 0, "gid": 0}
                require(len(contents) == member.size and record == expected[name], "packaged file bytes mismatch")
                files[name] = record
    except (tarfile.TarError, EOFError) as error:
        raise CheckError("tar layer rejected") from error
    require(len(raw) >= end + 1024 and not any(raw[end:]), "tar termination or trailing bytes rejected")


def graph(args):
    require(COMMIT.fullmatch(args.source_commit) is not None, "source commit rejected")
    digest(args.manifest_digest)
    directory = image.checked_path(args.graph_dir, directory=True)
    blobs = image.checked_path(directory / "blobs", directory=True)
    require({p.name for p in directory.iterdir()} == {"manifest.json", "blobs"}, "graph layout rejected")
    packaged, packaged_raw = json_file(args.packaged_report)
    require(packaged.get("schema") == "chengwang.product-image-packaged-content/v1"
            and packaged.get("authorization") == "BLOCKED" and packaged.get("production") is False
            and packaged.get("sourceCommit") == args.source_commit
            and packaged.get("registryManifestDigestVerified") is False
            and packaged.get("configDigestMatched") is True
            and packaged.get("secretsPackaged") is False and packaged.get("rawArchivePublished") is False,
            "D10 packaged boundary rejected")
    config_id = digest(packaged.get("localImageID"))
    expected = packaged.get("files")
    require(isinstance(expected, dict) and "app/image-trust-api" in expected
            and type(packaged.get("packagedFileCount")) is int
            and packaged["packagedFileCount"] == len(expected) and 2 <= len(expected) <= 65,
            "packaged file set rejected")
    for name, record in expected.items():
        require(tar_path(name) == name and (name == "app/image-trust-api" or name.startswith("app/web/")), "packaged path rejected")
        exact(record, ("sha256", "bytes", "mode", "uid", "gid"))
        require(isinstance(record["sha256"], str) and image.HEX.fullmatch(record["sha256"]), "file digest rejected")
        integer(record["bytes"], 1, 128 << 20)
        require(record["mode"] == ("0555" if name == "app/image-trust-api" else "0444")
                and type(record["uid"]) is int and record["uid"] == 0
                and type(record["gid"]) is int and record["gid"] == 0, "packaged permissions rejected")
    manifest, raw = json_file(directory / "manifest.json", 1 << 20)
    require("sha256:" + sha(raw) == args.manifest_digest, "manifest digest mismatch")
    exact(manifest, ("schemaVersion", "mediaType", "config", "layers"))
    require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2
            and manifest["mediaType"] in MANIFEST_TYPES, "manifest type rejected")
    config_desc = descriptor(manifest["config"], CONFIG_TYPES)
    config_type = ("application/vnd.oci.image.config.v1+json" if manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
                   else "application/vnd.docker.container.image.v1+json")
    allowed_layers = ({"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip"}
                      if manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
                      else {"application/vnd.docker.image.rootfs.diff.tar.gzip"})
    require(config_desc["digest"] == config_id and config_desc["size"] <= 1 << 20
            and config_desc["mediaType"] == config_type, "config versus image identity mismatch")
    layers = manifest["layers"]
    require(isinstance(layers, list) and 1 <= len(layers) <= 8, "layer count rejected")
    for value in layers:
        descriptor(value, allowed_layers)
    require(len({d["digest"] for d in layers}) == len(layers)
            and config_id not in {d["digest"] for d in layers}, "duplicate graph blob rejected")
    names = {config_id[7:], *(d["digest"][7:] for d in layers)}
    require({p.name for p in blobs.iterdir()} == names, "extra or missing graph blobs rejected")
    config = decode(read_blob(directory, config_desc))
    require(isinstance(config, dict) and config.get("os") == "linux" and config.get("architecture") == "amd64", "config platform rejected")
    cfg = config.get("config")
    require(isinstance(cfg, dict) and cfg.get("User") == "10001:10001"
            and cfg.get("Entrypoint") == ["/app/image-trust-api"] and cfg.get("WorkingDir") == "/app"
            and cfg.get("Labels", {}).get("org.opencontainers.image.revision") == args.source_commit
            and cfg.get("Labels", {}).get("org.chengwang.boundary") == "ISOLATED_PRODUCT_CANDIDATE", "config default executable rejected")
    rootfs = config.get("rootfs")
    exact(rootfs, ("type", "diff_ids"))
    diff_ids = rootfs["diff_ids"]
    require(rootfs["type"] == "layers" and isinstance(diff_ids, list)
            and len(diff_ids) == len(layers) and diff_ids == packaged.get("layerDiffIDs"), "ordered diff IDs mismatch")
    files = {}
    output_layers = []
    total = 0
    for desc, diff_id in zip(layers, diff_ids):
        digest(diff_id)
        uncompressed = unpack_layer(read_blob(directory, desc), desc["mediaType"])
        total += len(uncompressed)
        require(total <= 512 << 20 and "sha256:" + sha(uncompressed) == diff_id, "layer diff ID mismatch")
        layer_files(uncompressed, expected, files)
        output_layers.append({**desc, "diffID": diff_id, "uncompressedBytes": len(uncompressed)})
    require(files == expected, "incomplete packaged image graph")
    listing = "".join(name + "\t" + json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                      for name, record in sorted(files.items())).encode()
    return {"schema": "chengwang.product-registry-graph/v1", **BOUNDARY,
            "sourceCommit": args.source_commit, "localImageID": config_id,
            "registryManifestDigest": args.manifest_digest, "manifestBytes": len(raw),
            "manifestMediaType": manifest["mediaType"], "configDescriptor": config_desc,
            "layerDescriptors": output_layers, "packagedReportSHA256": sha(packaged_raw),
            "packagedFilesSHA256": sha(listing), "packagedFileCount": len(files),
            "actualGraphBytesVerified": True, "rawGraphPublished": False,
            "graphBytesOrigin": GRAPH_ORIGIN,
            "trustedBuilderAttestation": False, "releaseAuthorized": False}


def boundary(value):
    require(isinstance(value, dict) and all(value.get(key) is expected if type(expected) is bool
            else value.get(key) == expected for key, expected in BOUNDARY.items()), "D11 boundary rejected")


def graph_projection(value, source, local_id, packaged_raw):
    expected = ("schema", *BOUNDARY, "sourceCommit", "localImageID", "registryManifestDigest",
                "manifestBytes", "manifestMediaType", "configDescriptor", "layerDescriptors",
                "packagedReportSHA256", "packagedFilesSHA256", "packagedFileCount",
                "actualGraphBytesVerified", "rawGraphPublished", "graphBytesOrigin",
                "trustedBuilderAttestation", "releaseAuthorized")
    exact(value, expected)
    boundary(value)
    require(value["schema"] == "chengwang.product-registry-graph/v1" and value["sourceCommit"] == source
            and value["localImageID"] == local_id and value["configDescriptor"]["digest"] == local_id
            and value["packagedReportSHA256"] == sha(packaged_raw)
            and value["actualGraphBytesVerified"] is True and value["rawGraphPublished"] is False
            and value["graphBytesOrigin"] == GRAPH_ORIGIN
            and value["trustedBuilderAttestation"] is False and value["releaseAuthorized"] is False,
            "graph proof identity rejected")
    digest(value["registryManifestDigest"])
    require(value["registryManifestDigest"] != local_id, "manifest and config digest roles conflated")
    integer(value["manifestBytes"], 1, 1 << 20)
    require(value["manifestMediaType"] in MANIFEST_TYPES, "graph proof media type rejected")
    descriptor(value["configDescriptor"], CONFIG_TYPES)
    oci = value["manifestMediaType"] == "application/vnd.oci.image.manifest.v1+json"
    config_type = "application/vnd.oci.image.config.v1+json" if oci else "application/vnd.docker.container.image.v1+json"
    allowed_layers = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip"} if oci else {"application/vnd.docker.image.rootfs.diff.tar.gzip"}
    require(value["configDescriptor"]["size"] <= 1 << 20 and value["configDescriptor"]["mediaType"] == config_type,
            "graph config type or size rejected")
    require(isinstance(value["layerDescriptors"], list) and 1 <= len(value["layerDescriptors"]) <= 8,
            "graph proof layers rejected")
    for layer in value["layerDescriptors"]:
        exact(layer, ("mediaType", "digest", "size", "diffID", "uncompressedBytes"))
        descriptor({key: layer[key] for key in ("mediaType", "digest", "size")}, allowed_layers)
        digest(layer["diffID"])
        integer(layer["uncompressedBytes"], 1024, 256 << 20)
    require(isinstance(value["packagedFilesSHA256"], str) and image.HEX.fullmatch(value["packagedFilesSHA256"]), "graph file-set hash rejected")
    integer(value["packagedFileCount"], 2, 65)
    packaged = decode(packaged_raw)
    files = packaged["files"]
    listing = "".join(name + "\t" + json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                      for name, record in sorted(files.items())).encode()
    require(value["packagedFilesSHA256"] == sha(listing) and value["packagedFileCount"] == len(files), "graph file-set proof mismatch")
    require(len({layer["digest"] for layer in value["layerDescriptors"]}) == len(value["layerDescriptors"])
            and local_id not in {layer["digest"] for layer in value["layerDescriptors"]}, "graph descriptor roles reused")


def traffic_counts(snapshot):
    require(isinstance(snapshot["digestRequests"], list) and len(snapshot["digestRequests"]) <= 256
            and isinstance(snapshot["otherRequests"], list) and len(snapshot["otherRequests"]) <= 64,
            "Registry counter budget rejected")
    result = {}
    for rows, is_digest in ((snapshot["digestRequests"], True), (snapshot["otherRequests"], False)):
        for row in rows:
            exact(row, ("method", "digest", "status", "count") if is_digest else ("method", "status", "count"))
            require(row["method"] in ({"GET", "HEAD"} if is_digest else {"GET", "HEAD", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"}),
                    "Registry method rejected")
            integer(row["status"], 200, 299)
            integer(row["count"], 1, 10000)
            if is_digest:
                digest(row["digest"])
            key = (row["method"], row.get("digest", ""), row["status"])
            require(key not in result, "duplicate Registry counter rejected")
            result[key] = row["count"]
    return result


def observations(value, source, local_id, graphs):
    exact(value, ("schema", "sourceCommit", "localImageID", "registryContainerID",
                  "pinnedRegistryImage", *BOUNDARY, "snapshots"))
    boundary(value)
    require(value["schema"] == "chengwang.product-registry-observations/v1"
            and value["sourceCommit"] == source and value["localImageID"] == local_id
            and value["pinnedRegistryImage"] == REGISTRY_IMAGE
            and isinstance(value["registryContainerID"], str) and image.HEX.fullmatch(value["registryContainerID"]),
            "Registry observation identity rejected")
    expected = [(kind, action, case, position) for kind in KINDS for action, case in STAGES
                for position in ("before", "after")]
    snapshots = value["snapshots"]
    require(isinstance(snapshots, list) and len(snapshots) == len(expected), "Registry observation stages incomplete")
    counts = []
    previous = {}
    allowed_digests = {item["registryManifestDigest"] for item in graphs.values()}
    allowed_digests.update(item["configDescriptor"]["digest"] for item in graphs.values())
    allowed_digests.update(layer["digest"] for item in graphs.values() for layer in item["layerDescriptors"])
    for ordinal, (snapshot, step) in enumerate(zip(snapshots, expected), 1):
        exact(snapshot, ("ordinal", "kind", "action", "case", "position", "digestRequests", "otherRequests"))
        require(type(snapshot["ordinal"]) is int and snapshot["ordinal"] == ordinal
                and (snapshot["kind"], snapshot["action"], snapshot["case"], snapshot["position"]) == step
                and type(snapshot["case"]) is int, "Registry observation order rejected")
        current = traffic_counts(snapshot)
        require(all(not key[1] or key[1] in allowed_digests for key in current), "unbound Registry object observed")
        require(all(current.get(key, 0) >= count for key, count in previous.items()), "Registry counters moved backwards")
        # There are no background Registry readers. Unobserved gaps must not
        # conceal a request outside the individual before/after case windows.
        if ordinal > 1 and snapshot["position"] == "before":
            require(current == previous, "unobserved Registry traffic gap")
        previous = current
        counts.append(current)
    successful_reads = 0
    zero_windows = 0
    for index in range(0, len(snapshots), 2):
        snapshot = snapshots[index]
        before, after = counts[index:index + 2]
        delta = {key: after.get(key, 0) - before.get(key, 0) for key in after
                 if after.get(key, 0) != before.get(key, 0)}
        if snapshot["action"] == "prepare":
            graph_value = graphs[snapshot["kind"]]
            required = {("GET", graph_value["registryManifestDigest"], 200): 1,
                        ("POST", "", 202): len(graph_value["layerDescriptors"]) + 1,
                        ("PUT", "", 201): len(graph_value["layerDescriptors"]) + 2}
            for desc in [graph_value["configDescriptor"], *graph_value["layerDescriptors"]]:
                required[("GET", desc["digest"], 200)] = 1
            require(delta == required, "prepared upload or normal-TLS readback budget rejected")
        elif snapshot["action"] == "exercise" and snapshot["case"] == 1:
            graph_value = graphs[snapshot["kind"]]
            required = {("GET", graph_value["registryManifestDigest"], 200): 2,
                        ("HEAD", graph_value["registryManifestDigest"], 200): 4}
            for desc in [graph_value["configDescriptor"], *graph_value["layerDescriptors"]]:
                required[("GET", desc["digest"], 200)] = 1
                required[("HEAD", desc["digest"], 200)] = 2
            require(delta == required, "successful Registry descriptor budget rejected")
            successful_reads += 1
        else:
            require(not delta, "rejected or read-only case reached Registry HTTP")
            zero_windows += 1
    return {"successfulImageReads": successful_reads, "zeroRequestWindows": zero_windows,
            "snapshotCount": len(snapshots), "registryContainerID": value["registryContainerID"]}


def bare_hash(value):
    require(isinstance(value, str) and image.HEX.fullmatch(value), "bare hash rejected")
    return value


def public_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}", value), "public identifier rejected")
    return value


def material(value, kind, source, local_id, graph_value):
    require(value["kind"] == kind and value["sourceCommit"] == source and value["localImageID"] == local_id
            and value["configSHA256"] == local_id and value["manifestSHA256"] == graph_value["registryManifestDigest"]
            and value["layerSHA256s"] == [layer["digest"] for layer in graph_value["layerDescriptors"]]
            and value["diffIDs"] == [layer["diffID"] for layer in graph_value["layerDescriptors"]], "action graph binding rejected")
    require(isinstance(value["storeID"], str) and re.fullmatch(r"[0-9a-f]{32}", value["storeID"]), "store identity rejected")
    digest(value["catalogue1SHA256"])
    digest(value["catalogue2SHA256"])
    require(value["catalogue1SHA256"] != value["catalogue2SHA256"], "catalogue versions reused")
    policies = value["policies"]
    require(isinstance(policies, list) and len(policies) == 4, "signed policy corpus incomplete")
    for policy, name in zip(policies, ("accepted", "cross", "revoked", "spki")):
        exact(policy, ("name", "policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256",
                       "bundleArtifactSHA256", "trustedRootSHA256", "registrySPKI"))
        require(policy["name"] == name and policy["policyID"] == "d11-" + name, "policy name rejected")
        public_id(policy["grantID"])
        for field in ("approvalSHA256", "approvalEnvelopeSHA256", "bundleSHA256", "bundleArtifactSHA256", "trustedRootSHA256", "registrySPKI"):
            digest(policy[field])
        require((policy["bundleArtifactSHA256"] != value["manifestSHA256"]) if name == "cross"
                else policy["bundleArtifactSHA256"] == value["manifestSHA256"], "cross-artifact corpus binding rejected")
    require(len({policy["grantID"] for policy in policies}) == 4
            and len({policy["approvalSHA256"] for policy in policies}) == 4
            and len({policy["approvalEnvelopeSHA256"] for policy in policies}) == 4,
            "signed policy or grant reused")
    require(len({policy["trustedRootSHA256"] for policy in policies}) == 1
            and len({policy["bundleSHA256"] for policy in (policies[0], policies[2], policies[3])}) == 1
            and policies[1]["bundleSHA256"] != policies[0]["bundleSHA256"]
            and policies[0]["registrySPKI"] == policies[1]["registrySPKI"] == policies[2]["registrySPKI"]
            and policies[3]["registrySPKI"] != policies[0]["registrySPKI"], "same-authority negative corpus rejected")
    return {name: value[name] for name in MATERIAL_FIELDS}


def action_report(value, kind, action, case_number, reference, source, local_id, graph_value):
    verification = action in {"verify-first", "verify-final"}
    exact(value, (*ACTION_FIELDS, *( ("inspection", "journal", "audit") if verification else () )))
    boundary(value)
    require(value["schema"] == "chengwang.product-registry-action/v1" and value["action"] == action
            and type(value["case"]) is int and value["case"] == case_number
            and value["authority"] == "EPHEMERAL_TEST_ONLY" and value["graphOrigin"] == GRAPH_ORIGIN
            and value["journalAuditBindingsVerified"] is verification,
            "action report protocol rejected")
    actual = material(value, kind, source, local_id, graph_value)
    require(reference is None or actual == reference, "action material changed")
    require(isinstance(value["cases"], list), "case array required")
    return actual


def status_snapshot(value, state, info):
    exact(value, STATUS_FIELDS)
    sequence, generation, ledger, reserved, _ = state
    require(value["boundary"] == "ADVISORY_TRUST_POLICY_STATE" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and value["healthy"] is True and value["fresh"] is True
            and value["storeId"] == info["storeID"] and value["catalogueSHA256"] == info["catalogue%dSHA256" % generation],
            "status trust boundary rejected")
    for key, expected in {"sequence": sequence, "generation": generation, "ledgerEntries": ledger, "reserved": reserved,
                          "consumed": int(ledger > 0), "revokedKeys": 0, "revokedApprovals": int(generation == 2),
                          "revokedManifests": 0, "recoveryCompleted": 0, "refreshLastSuccessUnix": 0, "refreshUntilUnix": 0}.items():
        require(type(value[key]) is int and value[key] == expected, "status state transition rejected")
    integer(value["ledgerCapacity"], ledger, 1 << 20)
    require(value["refreshRequired"] is False and value["refreshFresh"] is False, "unexpected source refresh")
    integer(value["observedAtUnix"], 1)
    integer(value["auditVerifiedAtUnix"], 1, value["observedAtUnix"])
    integer(value["notAfterUnix"], value["observedAtUnix"] + 1)
    wanted = []
    for policy in info["policies"]:
        name = policy["name"]
        if generation == 2 and name == "revoked":
            continue
        policy_state = "AVAILABLE"
        if name == "accepted" and ledger:
            policy_state = "CONSUMED"
        elif name == "cross" and ledger >= 2 or name == "spki" and ledger == 3:
            policy_state = "RESERVED"
        wanted.append({"policyId": policy["policyID"], "grantId": policy["grantID"], "revision": 1,
                       "manifestSHA256": info["manifestSHA256"], "state": policy_state})
    require(value["policies"] == wanted, "policy availability or pinned grant state rejected")
    for policy in value["policies"]:
        require(type(policy["revision"]) is int, "policy revision type rejected")


def history_snapshot(value, state):
    exact(value, HISTORY_FIELDS)
    require(value["boundary"] == "ADVISORY_TRUST_OPERATION_HISTORY" and value["authorization"] == "BLOCKED"
            and value["deviceActionsExecuted"] is False and type(value["sequence"]) is int
            and value["sequence"] == state[0] and type(value["total"]) is int and value["total"] == state[4]
            and type(value["offset"]) is int and value["offset"] == 0
            and type(value["limit"]) is int and value["limit"] == 50
            and isinstance(value["entries"], list) and len(value["entries"]) == state[4], "history state rejected")
    integer(value["observedAtUnix"], 1)
    seen = set()
    for entry in value["entries"]:
        exact(entry, ENTRY_FIELDS)
        operation_id = public_id(entry["operationId"])
        require(operation_id not in seen and entry["actorId"] == "d11-admin" and entry["acknowledged"] is True,
                "history operation or ACK rejected")
        seen.add(operation_id)
        bare_hash(entry["preparedAuditHash"])
        bare_hash(entry["resultAuditHash"])
        integer(entry["preparedAtUnix"], 1)
        integer(entry["resultAtUnix"], entry["preparedAtUnix"])
        integer(entry["generation"], 0, 2)
    return {entry["operationId"]: entry for entry in value["entries"]}


def validate_case(value, row, before, info, previous_history):
    action, _, name, policy_name, http_status, after = row
    exact(value, (*CASE_FIELDS, *(("receipt",) if name == "success" else ())))
    require(value["name"] == name and value["method"] == ("PUT" if action == "catalogue" else "POST")
            and value["path"] == ("/api/v1/image-trust/catalogue" if action == "catalogue" else "/api/v1/image-trust/verifications")
            and type(value["httpStatus"]) is int and value["httpStatus"] == http_status
            and value["errorCode"] == ("" if http_status == 200 else "image_trust_invalid")
            and value["stateMayHaveChanged"] is (http_status == 400), "actual API case result rejected")
    digest(value["requestSHA256"])
    if policy_name is not None:
        policy = next(policy for policy in info["policies"] if policy["name"] == policy_name)
        for field in ("policyID", "grantID", "approvalSHA256", "bundleSHA256", "trustedRootSHA256"):
            require(value[field] == policy[field], "case signed material binding rejected")
        digest(value["approvalEnvelopeSHA256"])
        require((value["approvalEnvelopeSHA256"] != policy["approvalEnvelopeSHA256"]) if name == "approval-tamper"
                else value["approvalEnvelopeSHA256"] == policy["approvalEnvelopeSHA256"], "approval tamper distinction rejected")
    else:
        require(all(value[field] == "" for field in ("policyID", "grantID", "approvalSHA256", "approvalEnvelopeSHA256",
                                                       "bundleSHA256", "trustedRootSHA256")), "catalogue case included policy payload")
        require(value["requestSHA256"] == info["catalogue%dSHA256" % (2 if name == "revocation-install" else 1)],
                "catalogue request identity rejected")
    status_snapshot(value["statusBefore"], before, info)
    status_snapshot(value["statusAfter"], after, info)
    old = history_snapshot(value["historyBefore"], before)
    current = history_snapshot(value["historyAfter"], after)
    require(old == previous_history and len(current) == len(old) + 1 and all(current.get(key) == item for key, item in old.items()),
            "history was cleared, changed or replayed")
    latest = next(item for key, item in current.items() if key not in old)
    expected_state, expected_outcome = ("CONSUMED", "VERIFICATION_CONSUMED") if name == "success" else (
        ("RESERVED", "VERIFICATION_RESERVED_NOT_COMPLETED") if name in {"crossed-bundle", "wrong-spki"}
        else (("COMMITTED", "CATALOGUE_COMMITTED") if name == "revocation-install" else ("PREPARED", "REJECTED")))
    require(latest["kind"] == ("update" if action == "catalogue" else "verify")
            and latest["policyId"] == value["policyID"] and latest["state"] == expected_state
            and latest["outcome"] == expected_outcome, "case journal outcome rejected")
    if name == "success":
        receipt = value["receipt"]
        exact(receipt, ("boundary", "authorization", "deviceActionsExecuted", "verified", "grantId", "catalogueSHA256",
                        "generation", "manifestSHA256", "evidenceSHA256"))
        require(receipt["boundary"] == "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND" and receipt["authorization"] == "BLOCKED"
                and receipt["deviceActionsExecuted"] is False and receipt["verified"] is True
                and receipt["grantId"] == value["grantID"] and receipt["catalogueSHA256"] == info["catalogue1SHA256"]
                and type(receipt["generation"]) is int and receipt["generation"] == 1
                and receipt["manifestSHA256"] == info["manifestSHA256"], "real verification receipt rejected")
        digest(receipt["evidenceSHA256"])
    return current


def reopened(value, last_case, all_cases, info, receipt):
    inspection, journal, audit = value["inspection"], value["journal"], value["audit"]
    status, history = last_case["statusAfter"], last_case["historyAfter"]
    exact(inspection, ("authorization", "catalogue", "catalogueValid", "sequence", "ledgerCapacity",
                       "ledgerUsed", "ledgerRemaining", "consumptions"))
    require(inspection["authorization"] == "BLOCKED" and inspection["catalogueValid"] is True, "reopened trust store invalid")
    for key, expected in {"sequence": status["sequence"], "ledgerUsed": status["ledgerEntries"],
                          "ledgerCapacity": status["ledgerCapacity"], "ledgerRemaining": status["ledgerCapacity"] - status["ledgerEntries"]}.items():
        require(type(inspection[key]) is int and inspection[key] == expected, "reopened ledger tally mismatch")
    summary = inspection["catalogue"]
    exact(summary, ("storeID", "generation", "sha256", "notBeforeUnix", "notAfterUnix", "rootKeyCount", "rootThreshold",
                    "approverCount", "grants", "policyFloors", "revokedKeyCount", "revokedApprovalCount", "revokedManifestCount"))
    require(summary["storeID"] == info["storeID"] and summary["sha256"] == status["catalogueSHA256"]
            and summary["notAfterUnix"] == status["notAfterUnix"], "reopened catalogue binding mismatch")
    for key, expected in {"generation": status["generation"], "rootKeyCount": 1, "rootThreshold": 1, "approverCount": 4,
                          "revokedKeyCount": 0, "revokedApprovalCount": status["revokedApprovals"], "revokedManifestCount": 0}.items():
        require(type(summary[key]) is int and summary[key] == expected, "reopened catalogue summary mismatch")
    integer(summary["notBeforeUnix"], 1, summary["notAfterUnix"] - 1)
    require(summary["policyFloors"] == {policy["policyID"]: 1 for policy in info["policies"]}
            and all(type(v) is int for v in summary["policyFloors"].values()), "policy floor rollback detected")
    active = [policy for policy in info["policies"] if status["generation"] == 1 or policy["name"] != "revoked"]
    require(isinstance(summary["grants"], list) and len(summary["grants"]) == len(active), "reopened active grants mismatch")
    for grant, policy in zip(summary["grants"], active):
        exact(grant, ("id", "policyID", "approvalSHA256", "approverKeyID", "manifestSHA256", "revision"))
        public_id(grant["approverKeyID"])
        require(grant["id"] == policy["grantID"] and grant["policyID"] == policy["policyID"]
                and grant["approvalSHA256"] == policy["approvalSHA256"] and grant["manifestSHA256"] == info["manifestSHA256"]
                and type(grant["revision"]) is int and grant["revision"] == 1, "reopened signed grant binding mismatch")
    consumed = inspection["consumptions"]
    expected_names = ["accepted", "cross"] + (["spki"] if status["generation"] == 2 else [])
    require(isinstance(consumed, list) and len(consumed) == len(expected_names), "reopened consumption count rejected")
    for item, name in zip(consumed, expected_names):
        exact(item, ("grantID", "policyID", "approvalSHA256", "manifestSHA256", "generation", "catalogueSHA256", "status", "evidenceSHA256"))
        policy = next(policy for policy in info["policies"] if policy["name"] == name)
        generation = 2 if name == "spki" else 1
        require(item["grantID"] == policy["grantID"] and item["policyID"] == policy["policyID"]
                and item["approvalSHA256"] == policy["approvalSHA256"] and item["manifestSHA256"] == info["manifestSHA256"]
                and type(item["generation"]) is int and item["generation"] == generation
                and item["catalogueSHA256"] == info["catalogue%dSHA256" % generation]
                and item["status"] == ("CONSUMED" if name == "accepted" else "RESERVED")
                and item["evidenceSHA256"] == (receipt["evidenceSHA256"] if name == "accepted" else ""),
                "reopened burned grant changed or recreated")
    exact(audit, ("valid", "count", "expectedCount", "lastHash", "expectedLastHash", "verifiedAt"))
    require(audit["valid"] is True and type(audit["count"]) is int and type(audit["expectedCount"]) is int
            and audit["count"] == audit["expectedCount"] == history["total"] * 2,
            "reopened audit checkpoint count rejected")
    require(bare_hash(audit["lastHash"]) == bare_hash(audit["expectedLastHash"]), "reopened audit checkpoint hash rejected")
    require(isinstance(audit["verifiedAt"], str) and re.fullmatch(r"[0-9TZ:.+-]{20,40}", audit["verifiedAt"]), "audit verification time rejected")
    require(isinstance(journal, list) and len(journal) == history["total"] == len(all_cases), "reopened journal count rejected")
    history_by_id = {entry["operationId"]: entry for entry in history["entries"]}
    previous_hash = "0" * 64
    seen = set()
    for index, (entry, case) in enumerate(zip(journal, all_cases)):
        exact(entry, ("operation", "state", "outcome", "outcomeData", "acknowledged", "resultAuditHash", "grantID", "generation",
                      "catalogueSHA256", "manifestSHA256", "evidenceSHA256"))
        operation = entry["operation"]
        exact(operation, ("id", "actorID", "scopeSHA256", "kind", "data", "auditBaseCount", "auditBaseHash", "preparedAuditHash"))
        operation_id = public_id(operation["id"])
        require(operation_id not in seen and operation_id in history_by_id and operation["actorID"] == "d11-admin"
                and operation["kind"] == ("update" if case["method"] == "PUT" else "verify"), "reopened operation identity rejected")
        seen.add(operation_id)
        digest(operation["scopeSHA256"])
        require(type(operation["auditBaseCount"]) is int and operation["auditBaseCount"] == index * 2
                and operation["auditBaseHash"] == previous_hash and entry["acknowledged"] is True,
                "reopened audit prefix or ACK binding rejected")
        bare_hash(operation["preparedAuditHash"])
        bare_hash(entry["resultAuditHash"])
        integer(entry["generation"], 0, 2)
        expected_data = ({"catalogueSHA256": case["requestSHA256"]} if case["method"] == "PUT" else {
            "policyId": case["policyID"], "approvalSHA256": case["approvalEnvelopeSHA256"],
            "bundleSHA256": case["bundleSHA256"], "rootSHA256": case["trustedRootSHA256"]})
        require(operation["data"] == expected_data, "operation payload digest binding rejected")
        historical = history_by_id[operation_id]
        for key, old_key in (("state", "state"), ("outcome", "outcome"), ("grantID", "grantId"),
                             ("generation", "generation"), ("catalogueSHA256", "catalogueSHA256")):
            require(entry[key] == historical[old_key], "reopened journal versus HTTP history mismatch")
        require(operation["preparedAuditHash"] == historical["preparedAuditHash"]
                and entry["resultAuditHash"] == historical["resultAuditHash"], "reopened journal audit hash mismatch")
        data = {}
        if entry["state"] in {"CONSUMED", "RESERVED"}:
            require(entry["grantID"] == case["grantID"] and entry["manifestSHA256"] == info["manifestSHA256"], "journal grant binding rejected")
            data = {"grantId": entry["grantID"], "manifestSHA256": entry["manifestSHA256"], "catalogueSHA256": entry["catalogueSHA256"]}
            if entry["state"] == "CONSUMED":
                require(entry["evidenceSHA256"] == receipt["evidenceSHA256"], "consumed evidence changed")
                data["evidenceSHA256"] = receipt["evidenceSHA256"]
            else:
                require(entry["evidenceSHA256"] == "", "reserved grant acquired evidence")
        elif entry["state"] == "COMMITTED":
            require(entry["grantID"] == entry["manifestSHA256"] == entry["evidenceSHA256"] == "", "catalogue journal acquired a grant")
            data = {"catalogueSHA256": info["catalogue2SHA256"]}
        else:
            require(entry["state"] == "PREPARED" and entry["grantID"] == entry["catalogueSHA256"]
                    == entry["manifestSHA256"] == entry["evidenceSHA256"] == "" and entry["generation"] == 0,
                    "rejected journal acquired state")
        require(entry["outcomeData"] == data, "unexpected journal outcome payload")
        previous_hash = entry["resultAuditHash"]
    require(previous_hash == audit["lastHash"], "journal tail versus audit head mismatch")


def action_sequence(reports, kind, source, local_id, graph_value):
    reference = action_report(reports["prepare"], kind, "prepare", 0, None, source, local_id, graph_value)
    require(reports["prepare"]["cases"] == [], "prepare executed business calls")
    for action in ("exercise", "resume", "catalogue", "verify-first", "verify-final"):
        action_report(reports[action], kind, action, 0, reference, source, local_id, graph_value)
    all_cases = []
    history = {}
    state = (1, 1, 0, 0, 0)
    catalogue = reports["catalogue"]["cases"]
    require(len(catalogue) == 2, "catalogue case pair incomplete")
    for row in CASE_MATRIX:
        action, number, name, _, _, after = row
        if action == "catalogue":
            case = catalogue[0 if name == "revocation-install" else 1]
        else:
            report = reports[action + "-" + str(number)]
            action_report(report, kind, action, number, reference, source, local_id, graph_value)
            require(len(report["cases"]) == 1, "per-case actual API evidence missing")
            case = report["cases"][0]
        history = validate_case(case, row, state, reference, history)
        state = after
        all_cases.append(case)
    require(reports["exercise"]["cases"] == all_cases[:4]
            and reports["resume"]["cases"] == [all_cases[n] for n in (4, 7, 8, 9)], "aggregate aliases differ from individual calls")
    require(all_cases[0]["requestSHA256"] == all_cases[1]["requestSHA256"] == all_cases[4]["requestSHA256"]
            and all_cases[0]["requestSHA256"] != all_cases[2]["requestSHA256"]
            and all_cases[3]["requestSHA256"] == all_cases[9]["requestSHA256"], "replay or tamper request identity changed")
    receipt = all_cases[0]["receipt"]
    for action, count in (("verify-first", 4), ("verify-final", 10)):
        require(reports[action]["cases"] == [], "offline reopen issued API calls")
        reopened(reports[action], all_cases[count - 1], all_cases[:count], reference, receipt)
    require(reports["verify-first"]["journal"] == reports["verify-final"]["journal"][:4]
            and reports["verify-first"]["inspection"]["consumptions"] == reports["verify-final"]["inspection"]["consumptions"][:2],
            "restart replaced acknowledged history or burned grants")
    return reference


def runtime_projections(projections, processes, source, local_id, registry_id, binary_hash):
    ids = set()
    expected = {"boundary": "ISOLATED_PRODUCT_CANDIDATE", "authorization": "BLOCKED", "deviceActionsExecuted": False,
                "production": False, "sourceCommit": source, "localImageID": local_id,
                "imageIdentityKind": "LOCAL_DOCKER_CONFIG_ID_NOT_REGISTRY_MANIFEST", "entrypoint": ["/app/image-trust-api"],
                "user": "10001:10001", "workdir": "/app", "readOnlyRootfs": True, "capabilitiesDropped": "ALL",
                "noNewPrivileges": True, "networkIsolation": "shared_isolated_fixture", "networkPeerContainerID": registry_id,
                "hostPorts": 0, "bindMounts": {"privateReadOnly": True, "trustStateReadWrite": True, "productDataReadWrite": True},
                "memoryBytes": 268435456, "memorySwapBytes": 268435456, "nanoCPUs": 1000000000, "pidsLimit": 128,
                "nofile": 1024, "restartPolicy": "no", "stopTimeoutSeconds": 15,
                "rawEnvironmentIncluded": False, "rawMountSourcesIncluded": False}
    for name, projection in projections.items():
        exact(projection, (*expected, "containerID", "state", "pid", "cleanExit"))
        exact(projection["bindMounts"], ("privateReadOnly", "trustStateReadWrite", "productDataReadWrite"))
        require(all(item is True for item in projection["bindMounts"].values()), "runtime mount boolean types rejected")
        require(all(type(projection[key]) is type(item) and projection[key] == item for key, item in expected.items()),
                "product runtime security projection rejected")
        bare_hash(projection["containerID"])
        ids.add(projection["containerID"])
        running = name in {"running", "restarted-running"}
        require(projection["state"] == ("running" if running else "exited")
                and projection["cleanExit"] is (not running), "product runtime lifecycle rejected")
        integer(projection["pid"], 1 if running else 0)
        if not running:
            require(projection["pid"] == 0, "stopped process still has a PID")
        else:
            process = processes[name]
            exact(process, ("schema", *BOUNDARY, "sourceCommit", "localImageID", "containerID", "hostPID", "namespacePID",
                            "uid", "gid", "capabilities", "noNewPrivileges", "defaultProductEntrypoint",
                            "expectedConfigurationArguments", "actualExecutableSHA256"))
            boundary(process)
            require(process["schema"] == "chengwang.product-image-pid1/v1" and process["sourceCommit"] == source
                    and process["localImageID"] == local_id and process["containerID"] == projection["containerID"]
                    and type(process["hostPID"]) is int and process["hostPID"] == projection["pid"]
                    and type(process["namespacePID"]) is int and process["namespacePID"] == 1
                    and type(process["uid"]) is int and process["uid"] == 10001
                    and type(process["gid"]) is int and process["gid"] == 10001
                    and process["capabilities"] == "none" and process["noNewPrivileges"] is True
                    and process["defaultProductEntrypoint"] is True and process["expectedConfigurationArguments"] is True
                    and process["actualExecutableSHA256"] == binary_hash, "actual PID1 executable binding rejected")
    require(len(ids) == 1, "restart created another container")
    return next(iter(ids))


def registry_isolation(value, network, source, registry_id):
    expected = {"schema": "chengwang.product-registry-isolation/v1", "sourceCommit": source, "registryContainerID": registry_id,
                "pinnedImage": REGISTRY_IMAGE, "pinnedImageMatched": True, "networkMode": "none", "securityProfileVerified": True,
                "normalTLSVerified": True, "readOnlyRootfs": True, "user": "10001:10001", "capDrop": ["ALL"], "noNewPrivileges": True,
                "memory": 268435456, "memorySwap": 268435456, "nanoCpus": 1000000000, "pidsLimit": 128,
                "tmpfsBytes": 201326592, "tmpBytes": 16777216, "roFileBindCount": 3, "hostPorts": 0, "privileged": False, **BOUNDARY}
    exact(value, (*expected, "actualImageID"))
    require(all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()), "Registry isolation projection rejected")
    digest(value["actualImageID"])
    expected_network = {"schema": "chengwang.product-registry-network/v1", "sourceCommit": source, "registryContainerID": registry_id,
                        "loopbackOnly": True, "defaultRoutes": 0, "externalIPv4Blocked": True, "externalIPv6Blocked": True, **BOUNDARY}
    exact(network, expected_network)
    require(all(type(network[key]) is type(item) and network[key] == item for key, item in expected_network.items()),
            "Registry network namespace evidence rejected")


def verify(args):
    require(COMMIT.fullmatch(args.source_commit) is not None, "source commit rejected")
    directory = image.checked_path(args.evidence_dir, directory=True)
    loaded = {}
    hashes = {}

    def load(name):
        value, raw = json_file(directory / name)
        loaded[name] = value
        hashes[name] = sha(raw)
        return value, raw

    staging, _ = load("product-image-staging.json")
    packaged, packaged_raw = load("product-image-packaged-contents.json")
    require(staging.get("sourceCommit") == args.source_commit and staging.get("authorization") == "BLOCKED"
            and staging.get("deviceActionsExecuted") is False and staging.get("imageBuilt") is False
            and staging.get("imageExecuted") is False and isinstance(staging.get("binary"), dict), "D10 staging boundary changed")
    binary_hash = bare_hash(staging["binary"].get("sha256"))
    require(staging["binary"].get("sourceCommit") == args.source_commit and staging["binary"].get("sourceModified") is False,
            "binary source binding rejected")
    local_id = digest(packaged.get("localImageID"))
    require(packaged.get("schema") == "chengwang.product-image-packaged-content/v1" and packaged.get("authorization") == "BLOCKED"
            and packaged.get("production") is False and packaged.get("sourceCommit") == args.source_commit
            and packaged.get("registryManifestDigestVerified") is False and packaged.get("configDigestMatched") is True
            and packaged.get("secretsPackaged") is False and packaged.get("rawArchivePublished") is False,
            "D10 packaged report changed registry identity roles")
    files = packaged.get("files")
    require(isinstance(files, dict) and files.get("app/image-trust-api", {}).get("sha256") == binary_hash
            and files["app/image-trust-api"].get("bytes") == staging["binary"].get("bytes"), "packaged binary mismatch")
    contexts = staging.get("contextFiles")
    require(isinstance(contexts, dict) and "Dockerfile" in contexts
            and {name.removeprefix("rootfs/"): value for name, value in contexts.items() if name != "Dockerfile"}
            == {name: value["sha256"] for name, value in files.items()}, "staged versus packaged file set mismatch")
    harness, _ = load("product-registry-harness.json")
    exact(harness, ("schema", "sourceCommit", "files", "checkoutBytesMatched", "permissionReadOnly", *BOUNDARY))
    boundary(harness)
    tool_names = {"chengwang/deploy/product-candidate/check_product_image.py", "chengwang/deploy/product-candidate/check_product_registry.py"}
    require(harness["schema"] == "chengwang.product-registry-harness/v1" and harness["sourceCommit"] == args.source_commit
            and harness["checkoutBytesMatched"] is True and harness["permissionReadOnly"] is True
            and isinstance(harness["files"], dict) and set(harness["files"]) == tool_names, "checker source copy binding rejected")
    for name, expected_hash in harness["files"].items():
        require(sha(read_file(pathlib.Path(__file__).with_name(pathlib.PurePosixPath(name).name), 256 << 10)) == bare_hash(expected_hash),
                "running checker differs from source-bound harness")
    graphs = {}
    for kind in KINDS:
        graph_value, _ = load("product-registry-" + kind + "-graph.json")
        graph_projection(graph_value, args.source_commit, local_id, packaged_raw)
        require([layer["diffID"] for layer in graph_value["layerDescriptors"]] == packaged["layerDiffIDs"]
                and graph_value["packagedFileCount"] == packaged["packagedFileCount"], "graph proof versus packaged image mismatch")
        graphs[kind] = graph_value
    require(graphs[KINDS[0]] == graphs[KINDS[1]], "two signature modes verified different product graphs")
    observed, _ = load("product-registry-observations.json")
    traffic = observations(observed, args.source_commit, local_id, graphs)
    registry_id = traffic["registryContainerID"]
    isolation, _ = load("product-registry-isolation.json")
    network, _ = load("product-registry-network.json")
    registry_isolation(isolation, network, args.source_commit, registry_id)
    require(isolation["actualImageID"] != local_id, "Registry image replaced by product image identity")
    materials = []
    container_ids = set()
    for kind in KINDS:
        reports = {}
        for action in ("prepare", "exercise", "resume", "catalogue", "verify-first", "verify-final",
                       *("exercise-" + str(n) for n in range(1, 5)), *("resume-" + str(n) for n in range(1, 5))):
            reports[action], _ = load("product-registry-" + kind + "-" + action + ".json")
        materials.append(action_sequence(reports, kind, args.source_commit, local_id, graphs[kind]))
        projections, processes = {}, {}
        for name in ("running", "exited", "restarted-running", "restarted-exited"):
            projections[name], _ = load("product-registry-" + kind + "-" + name + "-inspect.json")
            if name in {"running", "restarted-running"}:
                processes[name], _ = load("product-registry-" + kind + "-" + name + "-pid1.json")
        container_ids.add(runtime_projections(projections, processes, args.source_commit, local_id, registry_id, binary_hash))
    require(len(container_ids) == 2 and registry_id not in container_ids
            and len({item["storeID"] for item in materials}) == 2
            and len({item["policies"][0]["trustedRootSHA256"] for item in materials}) == 2
            and len({policy["grantID"] for item in materials for policy in item["policies"]}) == 8,
            "independent signature-mode stores or containers reused")
    cleanup, _ = load("product-registry-cleanup.json")
    expected_cleanup = {"schema": "chengwang.product-registry-cleanup/v1", "sourceCommit": args.source_commit, "localImageID": local_id,
                        "ownedContainersRemoved": 3, "privateFixtureRemoved": True, "outerProductImagePreserved": True,
                        "registryImagePreserved": True, "outcome": "PASS", **BOUNDARY}
    exact(cleanup, expected_cleanup)
    require(all(type(cleanup[key]) is type(item) and cleanup[key] == item for key, item in expected_cleanup.items()), "exact owned cleanup not proven")
    own_names = {path.name for path in directory.glob("product-registry-*.json") if path.name != "product-registry-outcome.json"}
    require(own_names == {name for name in loaded if name.startswith("product-registry-")}, "unknown or stale D11 artifact")
    result = {"schema": "chengwang.product-registry-gate/v1", "outcome": "PASS", **BOUNDARY,
            "sourceCommit": args.source_commit, "localImageID": local_id,
            "registryManifestDigest": graphs[KINDS[0]]["registryManifestDigest"],
            "identityRoles": "SOURCE_COMMIT_LOCAL_CONFIG_ID_REGISTRY_MANIFEST_DISTINCT",
            "signatureKinds": list(KINDS), "authority": "EPHEMERAL_TEST_ONLY", "graphBytesOrigin": GRAPH_ORIGIN,
            "localGraphBytesGatePassed": True, "actualProductAPIRegistryReads": traffic["successfulImageReads"],
            "perCaseZeroRequestWindows": traffic["zeroRequestWindows"], "registryCounterSnapshots": traffic["snapshotCount"],
            "normalTLSAndFixedSPKIExercised": True, "approvedConsumptions": 2,
            "firstReopen": {"sequence": 19, "generation": 1, "journalEntries": 4, "auditEntries": 8, "ledgerEntries": 2},
            "finalReopen": {"sequence": 44, "generation": 2, "journalEntries": 10, "auditEntries": 20, "ledgerEntries": 3},
            "sameContainerRestart": True, "gracefulStops": 4, "cleanupVerified": True,
            "productImagePublishedOutsideIsolatedRegistry": False, "trustedBuilderAttestation": False,
            "formalSLSAProvenance": False, "releaseAuthorized": False, "privateGraphDownloadedByReviewer": False,
            "evidenceSHA256": dict(sorted(hashes.items()))}
    existing = directory / "product-registry-outcome.json"
    if existing.exists() or existing.is_symlink():
        previous, _ = json_file(existing)
        require(json.dumps(previous, sort_keys=True, separators=(",", ":")) == json.dumps(result, sort_keys=True, separators=(",", ":")),
                "existing final report differs from independently recomputed evidence")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    graph_parser = commands.add_parser("graph")
    for name in ("graph-dir", "packaged-report", "report"):
        graph_parser.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("source-commit", "manifest-digest"):
        graph_parser.add_argument("--" + name, required=True)
    inspection = commands.add_parser("inspect")
    for option in ("image-inspect", "container-inspect", "report"):
        inspection.add_argument("--" + option, type=pathlib.Path, required=True)
    for option in ("image-id", "source-commit", "expected-private-source", "expected-state-source", "expected-network-mode"):
        inspection.add_argument("--" + option, required=True)
    inspection.add_argument("--container-status", choices=("running", "exited"), required=True)
    verification = commands.add_parser("verify")
    for option in ("evidence-dir", "report"):
        verification.add_argument("--" + option, type=pathlib.Path, required=True)
    verification.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "graph":
            result = graph(args)
        elif args.command == "inspect":
            require(bool(re.fullmatch(r"container:[0-9a-f]{64}", args.expected_network_mode)), "D11 product must share isolated Registry netns")
            result = image.inspect_projection(image.one_inspect(read_file(args.image_inspect, 8 << 20)),
                image.one_inspect(read_file(args.container_inspect, 8 << 20)), image_id=args.image_id,
                source=args.source_commit, private=args.expected_private_source,
                state=args.expected_state_source, network=args.expected_network_mode,
                status=args.container_status, fixture_kind="product-registry")
            result["production"] = False
            result["networkPeerContainerID"] = args.expected_network_mode.removeprefix("container:")
        else:
            result = verify(args)
        image.write_exclusive(args.report, (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode())
    except (OSError, CheckError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        print("PRODUCT_REGISTRY_CHECK=FAIL rejected=true raw_input_suppressed=true", file=sys.stderr)
        return 1
    print("PRODUCT_REGISTRY_CHECK=PASS mode=" + args.command + " authorization=BLOCKED production=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
