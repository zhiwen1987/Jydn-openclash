#!/usr/bin/env python3
"""Independent initial-source TLS rejection/recovery replay, isolated-only.

Public certificate files are loader-bound projections, not a capture of the
product's PeerCertificates. Source TLS enums never establish rejection cause.
"""
from __future__ import annotations

import argparse
import base64
import pathlib
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
import check_product_source as source

image, registry, lifecycle = source.image, source.registry, source.lifecycle
CheckError = source.CheckError
require, exact, integer = source.require, source.exact, source.integer
encoded, parse, binary = source.encoded, source.parse, source.binary
digest, bare_hash, BOUNDARY, KINDS = source.digest, source.bare_hash, source.BOUNDARY, source.KINDS
FAULTS, PHASES, ACTIONS = ("ca", "san", "spki"), ("bad", "good"), ("prepare", "reject", "recover", "reopen")
BASE = source.BASE
HARNESS_PATHS = tuple(BASE + name for name in (
    "check_product_source_tls.py", "check_product_source.py", "check_product_image.py", "check_product_registry.py",
    "check_product_lifecycle.py", "check_source_preflight.py", "check_lifecycle_preflight.py", "fixture_source.py",
    "fixture_feed.py", "test_check_product_source_tls.py", "test_source_tls_image_profile.py"))
REPORT_FIELDS = ("schema", "sourceCommit", "localImageID", "fault", "kind", "action", *BOUNDARY,
                 "material", "observations", "offline")
CERTIFICATE_FIELDS = ("configuredCARaw", "badChainRaw", "goodChainRaw", "alternateCARaw")
EMPTY_AUDIT = {"bytes": 0, "sha256": image.sha(b"")}
GENESIS_CHECKPOINT = encoded({"count": 0, "lastHash": "0" * 64}, ordered=True)


def openssl(argv, raw=None, acceptable=(0,)):
    try:
        result = subprocess.run([source.openssl_path(), *argv], input=raw, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise CheckError("independent certificate tool failed") from error
    require(result.returncode in acceptable and len(result.stdout) <= 512 << 10 and len(result.stderr) <= 8192,
            "independent certificate tool failed")
    return result.returncode, result.stdout


def pem_certificates(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 256 << 10 and b"\0" not in raw, "public certificate bytes rejected")
    pattern = rb"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n"
    matches = list(re.finditer(pattern, raw))
    require(1 <= len(matches) <= 4 and b"".join(m.group(0) for m in matches) == raw, "public PEM chain shape rejected")
    certificates = []
    for match in matches:
        try:
            der = base64.b64decode(re.sub(rb"[\r\n]", b"", match.group(1)), validate=True)
        except ValueError as error:
            raise CheckError("public certificate DER rejected") from error
        require(0 < len(der) <= 64 << 10 and der not in certificates, "duplicate or oversized public certificate")
        _, actual = openssl(["x509", "-inform", "PEM", "-outform", "DER"], match.group(0))
        require(actual == der, "certificate PEM/DER disagreement")
        certificates.append(der)
    return certificates


def public_spki(pem):
    _, public = openssl(["x509", "-pubkey", "-noout"], pem)
    _, der = openssl(["pkey", "-pubin", "-outform", "DER"], public)
    require(0 < len(der) <= 8192, "public certificate SPKI budget rejected")
    return source.prefixed(der)


def certificate_corpus(value, fault, info, times):
    exact(value, CERTIFICATE_FIELDS)
    require(fault in FAULTS and type(times) is list and len(times) >= 2, "certificate verification context rejected")
    for second in times:
        integer(second, 1)
    raw = {name: binary(value[name]) for name in CERTIFICATE_FIELDS}
    require(bool(raw["alternateCARaw"]) is (fault == "ca"), "unrelated CA corpus mismatch")
    certs = {name: pem_certificates(content) for name, content in raw.items() if content}
    require(len(certs["configuredCARaw"]) == len(certs["goodChainRaw"]) == len(certs["badChainRaw"]) == 1,
            "this direct-issuer fixture requires exactly one leaf and one configured CA")
    if fault == "ca":
        require(len(certs["alternateCARaw"]) == 1 and certs["alternateCARaw"] != certs["configuredCARaw"]
                and public_spki(raw["alternateCARaw"]) != public_spki(raw["configuredCARaw"]), "unrelated CA reused trusted identity")
    require(source.prefixed(raw["configuredCARaw"]) == info["feedCASHA256"], "configured CA raw bytes mismatch")
    good_spki, bad_spki = public_spki(raw["goodChainRaw"]), public_spki(raw["badChainRaw"])
    require(good_spki == info["feedSPKI"] and (bad_spki != good_spki if fault == "spki" else bad_spki == good_spki),
            "single-cause certificate pin relationship rejected")
    require(certs["badChainRaw"] != certs["goodChainRaw"], "fault did not change the served certificate")
    for field, hostname in (("goodChainRaw", "feed.fixture.invalid"), ("badChainRaw", "wrong.fixture.invalid" if fault == "san" else "feed.fixture.invalid")):
        _, extension = openssl(["x509", "-noout", "-ext", "subjectAltName"], raw[field])
        require(re.fullmatch(rb"X509v3 Subject Alternative Name:\s*DNS:" + hostname.encode().replace(b".", rb"\.") + rb"\s*", extension),
                "single-cause certificate SAN set rejected")
    for field in ("configuredCARaw", *(("alternateCARaw",) if fault == "ca" else ())):
        _, extension = openssl(["x509", "-noout", "-ext", "basicConstraints"], raw[field])
        require(re.fullmatch(rb"X509v3 Basic Constraints:(?: critical)?\s*CA:TRUE(?:, pathlen:[0-9]+)?\s*", extension),
                "public trust anchor lacks CA constraints")
    with tempfile.TemporaryDirectory(prefix="chengwang-tls-public-") as directory:
        root = pathlib.Path(directory)
        for name, content in raw.items():
            if content:
                image.write_exclusive(root / (name + ".pem"), content)
        def verify(leaf, authority, host, when):
            # Never fall back to a system CA directory/store. Replays use the
            # real API observation time, not today's reviewer wall clock.
            argv = ["verify", "-no-CAfile", "-no-CApath", "-no-CAstore", "-trusted", str(root / (authority + ".pem")),
                    "-purpose", "sslserver", "-verify_hostname", host, "-attime", str(when), str(root / (leaf + ".pem"))]
            code, _ = openssl(argv, acceptable=(0, 2))
            return code == 0
        for when in times:
            for authority in ("configuredCARaw", *(("alternateCARaw",) if fault == "ca" else ())):
                code, _ = openssl(["verify", "-no-CAfile", "-no-CApath", "-no-CAstore", "-trusted",
                    str(root / (authority + ".pem")), "-check_ss_sig", "-attime", str(when), str(root / (authority + ".pem"))], acceptable=(0, 2))
                require(code == 0, "public CA self-signature or validity rejected")
            require(verify("goodChainRaw", "configuredCARaw", "feed.fixture.invalid", when), "normal certificate path is not independently valid")
            if fault == "ca":
                require(verify("badChainRaw", "alternateCARaw", "feed.fixture.invalid", when)
                        and not verify("badChainRaw", "configuredCARaw", "feed.fixture.invalid", when), "CA-only rejection not isolated")
            elif fault == "san":
                require(verify("badChainRaw", "configuredCARaw", "wrong.fixture.invalid", when)
                        and not verify("badChainRaw", "configuredCARaw", "feed.fixture.invalid", when), "SAN-only rejection not isolated")
            else:
                require(verify("badChainRaw", "configuredCARaw", "feed.fixture.invalid", when), "SPKI-only fault has another TLS defect")
    return {"bad": {"publicCertificateSHA256": image.sha(raw["badChainRaw"]), "privateKeySPKI": bad_spki, "_bytes": len(raw["badChainRaw"])},
            "good": {"publicCertificateSHA256": image.sha(raw["goodChainRaw"]), "privateKeySPKI": good_spki, "_bytes": len(raw["goodChainRaw"])}}


def initial(value):
    exact(value, ("trustRecordSHA256", "auditLog", "checkpoint"))
    bare_hash(value["trustRecordSHA256"])
    source.raw_hash(value["auditLog"], b"")
    source.raw_hash(value["checkpoint"], GENESIS_CHECKPOINT)


def material(value, fault, kind, commit, local_id, graph):
    exact(value, ("source", "certificates", "phasePlans", "initial"))
    corpus, docs = source.material(value["source"], kind, commit, local_id, graph)
    initial(value["initial"])
    exact(value["phasePlans"], PHASES)
    expected_plan = {"schema": "chengwang.product-source-plan/v1", "epoch": 1,
                     "responses": {"latest.json": {"mode": "json", "bodySHA256": image.sha(corpus["g1"])}}}
    expected_raw = encoded(expected_plan)
    for plan in value["phasePlans"].values():
        exact(plan, ("epoch", "raw", "sha256"))
        require(type(plan["epoch"]) is int and plan["epoch"] == 1 and binary(plan["raw"]) == expected_raw
                and plan["sha256"] == source.prefixed(expected_raw), "TLS phases did not serve the same original G1 plan")
    require(value["phasePlans"]["bad"] == value["phasePlans"]["good"], "TLS source plan changed beyond certificate")
    return corpus, docs, {1: (expected_plan, image.sha(expected_raw))}


def phase_events(raw, phase, plans, corpus, stopped, process):
    require(type(raw) is bytes and 0 < len(raw) <= 4 << 20 and raw.endswith(b"\n"), "full original TLS source log required")
    lines = raw.splitlines(keepends=True)
    events = [parse(line) for line in lines]
    try:
        summary = source.wirecheck.verify_connections(events)
    except source.wirecheck.Rejected as error:
        raise CheckError("TLS source connection chain rejected") from error
    exact(stopped["sourceStopWindow"], ("before", "after"))
    before = source.fence(stopped["sourceStopWindow"]["before"], lines)
    after = source.fence(stopped["sourceStopWindow"]["after"], lines)
    require(before <= after == len(lines), "owned source stop prefix omits original events")
    ready_count = source.fence(process["readyPrefix"], lines)
    require(ready_count <= before, "source readiness prefix follows stop")
    if phase == "bad":
        require(ready_count == 0 and stopped["productStopWindows"] == []
                and all(event["event"] != "http" for event in events), "faulty source emitted HTTP or was probed before product start")
        complete = []
    else:
        _, _, complete, wire_summary = source.source_events(raw, plans, corpus, stopped["productStopWindows"])
        summary.update(wire_summary)
        require(stopped["productStopWindows"][0]["after"]["eventCount"] <= before,
                "product stop is not closed before source termination")
    return events, lines, complete, summary


def observation(value, phase, info, docs, events, lines, completed, stopped):
    exact(value, ("name", "status", "history", "sourcePhase", "sourceFence"))
    name = "rejected" if phase == "bad" else "recovered"
    require(value["name"] == name and value["sourcePhase"] == phase, "TLS observation phase/name mismatch")
    wanted = (name, 1, 1, 0, phase == "good")
    source.status(value["status"], wanted, info, docs)
    source.history(value["history"], wanted)
    count = source.fence(value["sourceFence"], lines)
    require(count <= stopped["sourceStopWindow"]["before"]["eventCount"], "TLS observation includes source-stop attempts")
    if phase == "bad":
        require(value["status"]["refreshLastSuccessUnix"] == value["status"]["refreshUntilUnix"] == 0,
                "TLS rejection established source confirmation")
        connections = {}
        for event in events[:count]:
            connections.setdefault(event["connection"], []).append(event)
        actual_attempts = [rows for rows in connections.values()
                           if [row["event"] for row in rows] == ["connect", "tls", "close"]
                           and rows[1]["reason"] in ("ok", "failed") and rows[2]["reason"] == "closed"]
        require(len(actual_attempts) >= 2, "TLS rejection lacks two closed non-stop/non-timeout product attempts")
        return {"closedRejectionAttemptsBeforeObservation": len(actual_attempts), "sourceHTTPEvents": 0}
    require(count <= stopped["productStopWindows"][0]["before"]["eventCount"], "recovery observation includes product-stop events")
    good = [event for event in completed if event["ordinal"] <= count and event["status"] == 200
            and event["wireComplete"] and event["representationSHA256"] == image.sha(next(binary(c["raw"]) for c in info["catalogues"] if c["name"] == "g1"))]
    require(bool(good), "recovery Fresh lacks a complete original G1 response before its source fence")
    return {"completeG1ResponsesBeforeObservation": len(good), "sameGenerationFreshConfirmed": True}


def offline(value, last, initial_state, info, corpus, docs):
    result = source.offline(value, last, info, "http-recovery", corpus, docs)
    require(value["trustRecordSHA256"] == initial_state["trustRecordSHA256"]
            and value["auditLog"] == initial_state["auditLog"] and value["checkpoint"] == initial_state["checkpoint"],
            "TLS-only flow changed logical trust record, audit or checkpoint original bytes")
    return result


def own_names():
    names = {"product-tls-" + name + ".json" for name in ("harness", "network", "isolation", "observations", "runtime-cleanup", "outcome")}
    for fault in FAULTS:
        for kind in KINDS:
            prefix = "product-tls-" + fault + "-" + kind + "-"
            names.update(prefix + suffix + ".json" for suffix in (*ACTIONS, "graph", "running-inspect", "exited-inspect",
                "before-reject-pid1", "after-reject-pid1", "after-recover-pid1"))
            for phase in PHASES:
                names.update(prefix + phase + "-" + suffix + ".json" for suffix in ("source", "source-stop", "feed-ready"))
                names.add(prefix + phase + "-feed-events.jsonl")
    return frozenset(names)


def source_process(process, stopped, ready, commit, fault, kind, phase, harness, certificate):
    limits = {"cpuSeconds": 60, "addressSpaceBytes": 536870912, "fileBytes": 16777216,
              "openFiles": 128, "processes": 128, "coreBytes": 0}
    expected = {"schema": "chengwang.product-tls-process/v1", "sourceCommit": commit, "fault": fault, "kind": kind,
        "sourcePhase": phase, "sourceCase": "source-tls-" + fault + "-" + phase, "uid": 10001, "gid": 10001,
        "capabilities": "none", "noNewPrivileges": True, "registryNetworkNamespaceMatched": True, "privateMountNamespace": True,
        "sourceSHA256": harness[BASE + "fixture_source.py"], "dependencySHA256": harness[BASE + "fixture_feed.py"],
        "gitBoundSourceMatched": True, "sourceLimitsVerified": True, "sourceLimits": limits,
        **{k: v for k, v in certificate.items() if not k.startswith("_")}, **BOUNDARY}
    exact(process, (*expected, "hostPID", "hostStartTime", "pythonExecutableSHA256", "certificateInput", "readyPrefix"))
    require(all(type(process[k]) is type(v) and encoded(process[k]) == encoded(v) for k, v in expected.items()), "TLS source loader/profile mismatch")
    pid, start = integer(process["hostPID"], 2), integer(process["hostStartTime"], 1)
    bare_hash(process["pythonExecutableSHA256"])
    bound = process["certificateInput"]
    exact(bound, ("before", "after", "named"))
    for entry in bound.values():
        exact(entry, ("deviceMajor", "deviceMinor", "inode", "bytes", "mode", "uid", "gid", "nlink", "sha256"))
        integer(entry["deviceMajor"]); integer(entry["deviceMinor"]); integer(entry["inode"], 1)
        integer(entry["bytes"], 1, 256 << 10)
        require(type(entry["uid"]) is int and entry["uid"] == 10001 and type(entry["gid"]) is int and entry["gid"] == 10001
                and type(entry["nlink"]) is int and entry["nlink"] == 1 and entry["mode"] == "0600"
                and entry["sha256"] == certificate["publicCertificateSHA256"] and entry["bytes"] == certificate["_bytes"],
                "actual certificate input safety/hash rejected")
    require(bound["before"] == bound["after"] == bound["named"], "certificate replaced during source certificate observation")
    stop_expected = {"schema": "chengwang.product-tls-stop/v1", "sourceCommit": commit, "fault": fault, "kind": kind,
        "sourcePhase": phase, "sourceCase": expected["sourceCase"], "hostPID": pid, "startTime": start, "signal": "SIGTERM",
        "exitCode": 0, "joined": True, "listenerAbsent": True,
        "listenerObservation": {"port": 5444, "tcpListening": 0, "tcp6Listening": 0, "registryNetworkNamespaceMatched": True}, **BOUNDARY}
    exact(stopped, (*stop_expected, "sourceStopWindow", "productStopWindows"))
    require(all(type(stopped[k]) is type(v) and encoded(stopped[k]) == encoded(v) for k, v in stop_expected.items()),
            "TLS source stop, identity, join or listener handoff rejected")
    exact(ready, ("schema", "port", "pid", "uid", "gid", "tls", "listenLoopback", "deadlineSeconds"))
    require(ready == {"schema": "chengwang.product-source-ready/v1", "port": 5444, "pid": pid, "uid": 10001,
        "gid": 10001, "tls": True, "listenLoopback": True, "deadlineSeconds": ready["deadlineSeconds"]}
        and all(type(ready[k]) is int for k in ("port", "pid", "uid", "gid"))
        and ready["tls"] is True and ready["listenLoopback"] is True
        and type(ready["deadlineSeconds"]) is int and ready["deadlineSeconds"] == 600,
        "TLS source actual atomic ready identity rejected")
    return pid, start


def product_runtime(projections, processes, commit, local_id, registry_id, binary_sha, fault, kind, info):
    labels = ("before-reject", "after-reject", "after-recover")
    exact(processes, labels)
    old_keys = ("schema", *BOUNDARY, "sourceCommit", "localImageID", "containerID", "hostPID", "namespacePID", "uid", "gid",
                "capabilities", "noNewPrivileges", "defaultProductEntrypoint", "expectedConfigurationArguments", "actualExecutableSHA256")
    identities = []
    expected_configuration = {"refreshEnabled": True, "refreshURL": lifecycle.FEED_URL, "refreshIP": "127.0.0.1",
        "refreshSPKI": info["feedSPKI"], "refreshCASHA256": info["feedCASHA256"][7:],
        "refreshIntervalSeconds": 2, "refreshMaxAgeSeconds": 15, "refreshTimeoutSeconds": 2}
    for label in labels:
        process = processes[label]
        exact(process, (*old_keys, "hostStartTime", "trustConfigurationSHA256", "productConfigurationSHA256", "refreshConfiguration"))
        require(process["schema"] == "chengwang.product-tls-pid1/v1", "TLS PID1 actual schema rejected")
        integer(process["hostStartTime"], 1)
        bare_hash(process["trustConfigurationSHA256"]); bare_hash(process["productConfigurationSHA256"])
        configuration = process["refreshConfiguration"]
        exact(configuration, (*expected_configuration, "refreshCAFile"))
        require(all(type(configuration[k]) is type(v) and configuration[k] == v for k, v in expected_configuration.items())
                and re.fullmatch(r"/tmp/chengwang-product-lifecycle-[a-f0-9]{32}/refresh/tls-" + fault + "/" + kind + r"/source-ca\.pem",
                                 configuration["refreshCAFile"]), "actual immutable product TLS configuration rejected")
        original = {k: process[k] for k in old_keys}; original["schema"] = "chengwang.product-image-pid1/v1"
        # Reuse only the unchanged image/PID security validator. The new
        # three-sample identity and raw configuration bindings remain explicit.
        registry.runtime_projections(projections, {"running": original}, commit, local_id, registry_id, binary_sha)
        identities.append({k: v for k, v in process.items() if k != "schema"})
    require(identities[0] == identities[1] == identities[2], "source restoration restarted product or changed configuration")
    return processes[labels[0]]["containerID"]


def traffic(value, commit, local_id, graphs):
    exact(value, ("schema", "sourceCommit", "localImageID", "registryContainerID", "pinnedRegistryImage", "snapshots", *BOUNDARY))
    registry.boundary(value)
    require(value["schema"] == "chengwang.product-tls-observations/v1" and value["sourceCommit"] == commit
            and value["localImageID"] == local_id and value["pinnedRegistryImage"] == registry.REGISTRY_IMAGE,
            "TLS Registry counter identity rejected")
    bare_hash(value["registryContainerID"])
    expected = [(f, k, a, p) for f in FAULTS for k in KINDS for a in ACTIONS for p in ("before", "after")]
    require(type(value["snapshots"]) is list and len(value["snapshots"]) == 48, "TLS Registry counter stages incomplete")
    counts, previous = [], {}
    for ordinal, (row, step) in enumerate(zip(value["snapshots"], expected), 1):
        exact(row, ("ordinal", "fault", "kind", "action", "position", "digestRequests", "otherRequests"))
        require(type(row["ordinal"]) is int and row["ordinal"] == ordinal
                and (row["fault"], row["kind"], row["action"], row["position"]) == step, "TLS Registry counter order rejected")
        current = registry.traffic_counts(row)
        require(all(current.get(key, 0) >= count for key, count in previous.items()), "TLS Registry counters regressed")
        if ordinal == 1:
            require(not current, "TLS prepare traffic hidden before first snapshot")
        elif row["position"] == "before":
            require(current == previous, "TLS Registry traffic hidden between windows")
        previous = current; counts.append(current)
    for index in range(0, 48, 2):
        row, before, after = value["snapshots"][index], counts[index], counts[index + 1]
        delta = {key: count - before.get(key, 0) for key, count in after.items() if count != before.get(key, 0)}
        if row["action"] == "prepare":
            graph = graphs[(row["fault"], row["kind"])]
            wanted = {("GET", graph["registryManifestDigest"], 200): 1, ("POST", "", 202): len(graph["layerDescriptors"]) + 1,
                      ("PUT", "", 201): len(graph["layerDescriptors"]) + 2}
            for desc in [graph["configDescriptor"], *graph["layerDescriptors"]]:
                wanted[("GET", desc["digest"], 200)] = 1
            require(delta == wanted, "TLS prepare exact upload/readback budget rejected")
        else:
            require(not delta, "TLS rejection/recovery/reopen read reached Registry HTTP")
    return value["registryContainerID"]


def cleanup(value, commit, local_id, products, registry_id):
    expected = {"schema": "chengwang.product-tls-cleanup/v1", "sourceCommit": commit, "localImageID": local_id,
        "ownedContainersRemoved": 7, "ownedSourcesJoined": 12, "sourceExitCodes": [0] * 12, "normalProductStops": 6,
        "maximumConcurrentOwnedContainers": 2, "noOwnedContainersRemain": True,
        "registryStop": {"signal": "SIGTERM", "exitCode": 0, "oomKilled": False, "pid": 0}, "privateFixtureRemoved": True,
        "outerProductImagePreserved": True, "registryImagePreserved": True, "outcome": "PASS", **BOUNDARY}
    exact(value, (*expected, "removedContainers"))
    require(all(type(value[k]) is type(v) and encoded(value[k]) == encoded(v) for k, v in expected.items()), "TLS exact source/container cleanup rejected")
    require(type(value["removedContainers"]) is list and len(value["removedContainers"]) == 7, "TLS cleanup IDs incomplete")
    seen = set()
    for row in value["removedContainers"]:
        exact(row, ("containerID", "role", "fault", "kind"))
        identifier = bare_hash(row["containerID"])
        require(identifier not in seen, "TLS cleanup duplicate container")
        seen.add(identifier)
        if identifier == registry_id:
            require(row["role"] == "registry" and row["fault"] == row["kind"] == "", "TLS Registry cleanup role rejected")
        else:
            require(row["role"] == "product" and products.get((row["fault"], row["kind"])) == identifier, "TLS foreign cleanup object rejected")
    require(seen == {registry_id, *products.values()}, "TLS cleanup exact owned set mismatch")


SUPPORT_NAMES = frozenset(("product-tls-profile-tests.log", "product-tls-verifier-tests.log"))


def verify(args):
    commit = args.source_commit
    require(registry.COMMIT.fullmatch(commit), "TLS source commit rejected")
    directory = image.checked_path(args.evidence_dir, directory=True)
    expected = own_names()
    present = {p.name for p in directory.iterdir() if p.name.startswith("product-tls-")}
    require(expected - {"product-tls-outcome.json"} <= present and present <= expected | SUPPORT_NAMES,
            "unknown, missing or stale TLS gate artifact")
    hashes = {}
    def load(name, raw=False):
        content = registry.read_file(directory / name, 4 << 20)
        require(name not in hashes, "TLS evidence loaded twice")
        hashes[name] = image.sha(content)
        return content if raw else parse(content)
    staging, packaged = load("product-image-staging.json"), load("product-image-packaged-contents.json")
    packaged_raw = registry.read_file(directory / "product-image-packaged-contents.json", 4 << 20)
    require(staging.get("sourceCommit") == commit and staging.get("authorization") == "BLOCKED"
            and staging.get("deviceActionsExecuted") is False and staging.get("imageBuilt") is False
            and staging.get("imageExecuted") is False and type(staging.get("binary")) is dict, "TLS staging boundary rejected")
    binary_sha = bare_hash(staging["binary"].get("sha256"))
    require(staging["binary"].get("sourceCommit") == commit and staging["binary"].get("sourceModified") is False, "TLS binary source mismatch")
    local_id = digest(packaged.get("localImageID"))
    require(packaged.get("schema") == "chengwang.product-image-packaged-content/v1" and packaged.get("sourceCommit") == commit
            and packaged.get("authorization") == "BLOCKED" and packaged.get("production") is False
            and packaged.get("registryManifestDigestVerified") is False and packaged.get("configDigestMatched") is True
            and packaged.get("secretsPackaged") is False and packaged.get("rawArchivePublished") is False, "TLS packaged image boundary rejected")
    files, contexts = packaged.get("files"), staging.get("contextFiles")
    require(type(files) is dict and type(contexts) is dict and "Dockerfile" in contexts
            and files.get("app/image-trust-api", {}).get("sha256") == binary_sha
            and files["app/image-trust-api"].get("bytes") == staging["binary"].get("bytes")
            and {k.removeprefix("rootfs/"): v for k, v in contexts.items() if k != "Dockerfile"} == {k: v["sha256"] for k, v in files.items()},
            "TLS packaged binary/context bytes mismatch")
    harness = load("product-tls-harness.json")
    exact(harness, ("schema", "sourceCommit", "files", "checkoutBytesMatched", "permissionReadOnly", *BOUNDARY))
    registry.boundary(harness)
    require(harness["schema"] == "chengwang.product-tls-harness/v1" and harness["sourceCommit"] == commit
            and harness["checkoutBytesMatched"] is True and harness["permissionReadOnly"] is True, "TLS read-only harness boundary rejected")
    exact(harness["files"], HARNESS_PATHS)
    for path, wanted in harness["files"].items():
        bare_hash(wanted)
        require(image.sha(registry.read_file(pathlib.Path(__file__).with_name(pathlib.PurePosixPath(path).name), 256 << 10)) == wanted,
                "running TLS checker/helper differs from original Git-bound source")
    suites = {}
    for label, suite, name, count in (("profile", "TLS_IMAGE_PROFILE", "test_source_tls_image_profile.py", 8),
                                      ("verifier", "TLS_VERIFIER", "test_check_product_source_tls.py", 32)):
        suites[label] = source.transcript(load("product-tls-" + label + "-tests.log", True),
            registry.read_file(pathlib.Path(__file__).with_name(name), 256 << 10), suite, count)
    graphs = {}
    for fault in FAULTS:
        for kind in KINDS:
            graph = load("product-tls-" + fault + "-" + kind + "-graph.json")
            registry.graph_projection(graph, commit, local_id, packaged_raw)
            require([row["diffID"] for row in graph["layerDescriptors"]] == packaged["layerDiffIDs"]
                    and graph["packagedFileCount"] == packaged["packagedFileCount"]
                    and binary_sha not in {local_id[7:], graph["registryManifestDigest"][7:]}, "TLS image graph/binary roles conflated")
            graphs[(fault, kind)] = graph
    require(all(graph == next(iter(graphs.values())) for graph in graphs.values()), "TLS six cells used different image bytes")
    registry_id = traffic(load("product-tls-observations.json"), commit, local_id, graphs)
    isolation, network = load("product-tls-isolation.json"), load("product-tls-network.json")
    registry.registry_isolation(isolation, network, commit, registry_id)
    require(isolation["actualImageID"] != local_id, "TLS Registry/product image roles conflated")
    products, source_ids, materials, cells = {}, set(), [], {}
    for fault in FAULTS:
        for kind in KINDS:
            prefix = "product-tls-" + fault + "-" + kind + "-"
            reports = {action: load(prefix + action + ".json") for action in ACTIONS}
            info = reports["prepare"]["material"]
            corpus, docs, plans = material(info, fault, kind, commit, local_id, graphs[(fault, kind)])
            materials.append(info["source"])
            for action, report in reports.items():
                exact(report, REPORT_FIELDS); registry.boundary(report)
                require(report["schema"] == "chengwang.product-source-tls-driver/v1" and report["sourceCommit"] == commit
                        and report["localImageID"] == local_id and report["fault"] == fault and report["kind"] == kind
                        and report["action"] == action and report["material"] == info, "TLS driver report identity/material changed")
                require(type(report["observations"]) is list and len(report["observations"]) == int(action in ("reject", "recover")),
                        "TLS driver actual observation count rejected")
                if action != "reopen":
                    require(report["offline"] is None, "running TLS report fabricated offline state")
            times = [reports[action]["observations"][0]["status"]["observedAtUnix"] for action in ("reject", "recover")]
            require(times[1] >= times[0], "TLS API observation time regressed")
            certificates = certificate_corpus(info["certificates"], fault, info["source"], times)
            phase_results = {}
            phase_processes = {}
            for phase, action in (("bad", "reject"), ("good", "recover")):
                process, stopped, ready = load(prefix + phase + "-source.json"), load(prefix + phase + "-source-stop.json"), load(prefix + phase + "-feed-ready.json")
                identity = source_process(process, stopped, ready, commit, fault, kind, phase, harness["files"], certificates[phase])
                require(identity not in source_ids, "TLS source phase reused process identity")
                source_ids.add(identity); phase_processes[phase] = identity
                events, lines, completed, summary = phase_events(load(prefix + phase + "-feed-events.jsonl", True), phase, plans, corpus, stopped, process)
                proof = observation(reports[action]["observations"][0], phase, info["source"], docs, events, lines, completed, stopped)
                phase_results[phase] = {"source": summary, "observation": proof}
            require(phase_processes["bad"] != phase_processes["good"], "TLS source recovery did not use a separately joined source")
            last = reports["recover"]["observations"][0]
            reopened = offline(reports["reopen"]["offline"], last, info["initial"], info["source"], corpus, docs)
            products[(fault, kind)] = product_runtime(
                {label: load(prefix + label + "-inspect.json") for label in ("running", "exited")},
                {label: load(prefix + label + "-pid1.json") for label in ("before-reject", "after-reject", "after-recover")},
                commit, local_id, registry_id, binary_sha, fault, kind, info["source"])
            cells[fault + "/" + kind] = {"phases": phase_results, "finalReopen": reopened,
                "certificateCauseIndependentlyVerified": fault, "productPeerCertificateArrayCaptured": False}
    require(len(set(products.values())) == 6 and registry_id not in products.values() and len(source_ids) == 12
            and len({m["storeID"] for m in materials}) == len({m["policies"][0]["grantID"] for m in materials})
            == len({m["policies"][0]["trustedRootSHA256"] for m in materials})
            == len({parse(binary(m["anchorRaw"]))["keys"][0]["id"] for m in materials}) == 6,
            "TLS independent product/store/grant/authority/source cells incomplete")
    cleanup(load("product-tls-runtime-cleanup.json"), commit, local_id, products, registry_id)
    require(set(hashes) == expected - {"product-tls-outcome.json"} | SUPPORT_NAMES
            | {"product-image-staging.json", "product-image-packaged-contents.json"} and len(hashes) == 117,
            "TLS 117 original input relation set changed")
    result = {"schema": "chengwang.product-source-tls-gate/v1", "outcome": "PASS", **BOUNDARY, "sourceCommit": commit,
        "localImageID": local_id, "registryManifestDigest": next(iter(graphs.values()))["registryManifestDigest"], "binarySHA256": binary_sha,
        "authority": "EPHEMERAL_TEST_ONLY", "graphBytesOrigin": registry.GRAPH_ORIGIN, "signatureKinds": list(KINDS), "faults": list(FAULTS),
        "cells": cells, "testSuites": suites, "registryCounterSnapshots": 48, "prepareUploadReadbackWindows": 6, "zeroRequestWindows": 18,
        "normalProductStops": 6, "sourceGracefulStops": 12, "sameProductPIDRecovery": True, "initialTLSFaultsOnly": True,
        "independentCertificateVerification": "OPENSSL_EXPLICIT_TRUST_OBSERVATION_TIME_NO_SYSTEM_CA",
        "sourceNetworkReadinessProbes": 0, "productPeerCertificateArrayCaptured": False, "cleanupVerified": True,
        "confirmedThenTLSStalenessProven": False, "certificateOnlineRotationProven": False, "sourceRestartColdConfirmationProven": False,
        "reservedRevocationProven": False, "realNetworkTimeoutProven": False, "completeSourceFaultMatrixProven": False,
        "releaseAuthorized": False, "physicalPowerLossProven": False, "privateGraphDownloadedByReviewer": False,
        "productImagePublishedOutsideIsolatedRegistry": False, "evidenceSHA256": dict(sorted(hashes.items()))}
    existing = directory / "product-tls-outcome.json"
    if existing.exists() or existing.is_symlink():
        require(encoded(parse(registry.read_file(existing, 4 << 20))) == encoded(result), "existing TLS outcome differs from independent replay")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    graph = commands.add_parser("graph")
    for name in ("graph-dir", "packaged-report", "report"):
        graph.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("source-commit", "manifest-digest"):
        graph.add_argument("--" + name, required=True)
    inspect = commands.add_parser("inspect")
    for name in ("image-inspect", "container-inspect", "report"):
        inspect.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in ("image-id", "source-commit", "expected-private-source", "expected-state-source", "expected-network-mode"):
        inspect.add_argument("--" + name, required=True)
    inspect.add_argument("--container-status", choices=("running", "exited"), required=True)
    verification = commands.add_parser("verify")
    for name in ("evidence-dir", "report"):
        verification.add_argument("--" + name, type=pathlib.Path, required=True)
    verification.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "graph":
            result = registry.graph(args)
        elif args.command == "inspect":
            require(re.fullmatch(r"container:[a-f0-9]{64}", args.expected_network_mode), "TLS product namespace rejected")
            result = image.inspect_projection(image.one_inspect(registry.read_file(args.image_inspect, 8 << 20)),
                image.one_inspect(registry.read_file(args.container_inspect, 8 << 20)), image_id=args.image_id,
                source=args.source_commit, private=args.expected_private_source, state=args.expected_state_source,
                network=args.expected_network_mode, status=args.container_status, fixture_kind="product-source-tls")
            result.update(production=False, networkPeerContainerID=args.expected_network_mode.removeprefix("container:"))
        else:
            result = verify(args)
        image.write_exclusive(args.report, encoded(result) + b"\n")
    except (OSError, CheckError, ValueError, TypeError, KeyError, AttributeError, OverflowError, source.preflight.Rejected):
        print("PRODUCT_SOURCE_TLS_CHECK=FAIL rejected=true raw_input_suppressed=true", file=sys.stderr)
        return 1
    print("PRODUCT_SOURCE_TLS_CHECK=PASS mode=" + args.command + " authorization=BLOCKED production=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
