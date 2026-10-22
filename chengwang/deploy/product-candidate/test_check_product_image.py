"""Synthetic parser negatives; actual ELF execution/Docker acceptance is CI-only."""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
import pathlib
import stat
import struct
import tempfile
import unittest

import check_product_image as checker

SOURCE = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64
PRIVATE = "/tmp/chengwang-product-image-" + "d" * 32 + "/trusted"


def put(path: pathlib.Path, raw: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)  # Only this test's disposable fixture may be rewritten.
    path.write_bytes(raw)
    path.chmod(mode)


def encode_var(raw):
    size = len(raw)
    out = bytearray()
    while size > 127:
        out.append((size & 127) | 128)
        size >>= 7
    return bytes(out + bytes([size])) + raw


def synthetic_elf(**changed):
    settings = {"-buildmode": "exe", "-trimpath": "true", "CGO_ENABLED": "0", "GOARCH": "amd64", "GOOS": "linux", "vcs": "git", "vcs.revision": SOURCE, "vcs.modified": "false"}
    settings.update(changed)
    records = "path\tchengwang/image-binding/cmd/image-trust-api\nmod\tchengwang/image-binding\t(devel)\t\n" + "".join("build\t" + key + "=" + value + "\n" for key, value in settings.items())
    body = b"A" * 16 + records.encode() + b"B" * 16
    build = b"\xff Go buildinf:" + bytes([8, 2]) + b"\0" * 16 + encode_var(b"go1.25.8") + encode_var(body)
    raw = bytearray(2048)
    raw[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 62, 1, 0x400100, 64, 1536, 0, 64, 56, 1, 64, 3, 1)
    raw[64:120] = struct.pack("<IIQQQQQQ", 1, 7, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
    names = b"\0.shstrtab\0.go.buildinfo\0"
    raw[448:448 + len(names)] = names
    raw[512:512 + len(build)] = build
    raw[1600:1664] = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 448, len(names), 0, 0, 1, 0)
    raw[1664:1728] = struct.pack("<IIQQQQIIQQ", 11, 1, 3, 0x400200, 512, len(build), 0, 0, 16, 0)
    external = "synthetic-not-executed: go1.25.8\n" + "".join("\t" + line + "\n" for line in records.splitlines())
    return bytes(raw), external.encode()


def synthetic_inspect():
    config = {"Entrypoint": checker.ENTRYPOINT[:], "User": "10001:10001", "WorkingDir": "/app", "Labels": {"org.opencontainers.image.revision": SOURCE, "org.chengwang.boundary": checker.BOUNDARY}, "Cmd": None}
    image = {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64", "Config": copy.deepcopy(config)}
    args = ["--config", PRIVATE + "/trust-config.json", "--product-config", PRIVATE + "/product-config.json"]
    config.update({"Cmd": args[:], "StopTimeout": 15})
    host = {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Memory": 268435456, "MemorySwap": 268435456, "NanoCpus": 1000000000, "PidsLimit": 128, "Ulimits": [{"Name": "nofile", "Hard": 1024, "Soft": 1024}], "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "AutoRemove": False}
    container = {"Id": CONTAINER_ID, "Image": IMAGE_ID, "Config": config, "HostConfig": host, "Path": checker.ENTRYPOINT[0], "Args": args, "NetworkSettings": {"Ports": {}}, "State": {"Status": "running", "Running": True, "Pid": 123, "ExitCode": 0}, "Mounts": [{"Type": "bind", "Source": path, "Destination": path, "RW": writable, "Propagation": "rprivate"} for path, writable in [(PRIVATE, False), (PRIVATE + "/trust", True), (PRIVATE + "/data", True)]]}
    return image, container


class ElfTests(unittest.TestCase):
    def test_synthetic_shape_accepts_matching_embedded_static_metadata(self):
        raw, text = synthetic_elf()
        report = checker.verify_elf(raw, text, SOURCE)
        self.assertFalse(report["cgoEnabled"])
        self.assertEqual(report["sourceCommit"], SOURCE)

    def test_wrong_platform_shape_and_out_of_range_rejected(self):
        raw, text = synthetic_elf()
        mutations = []
        for offset, value in [(4, b"\x01"), (5, b"\x02"), (18, b"\xb7\0"), (40, struct.pack("<Q", 4096)), (56, b"\xff\xff"), (62, b"\xff\xff")]:
            changed = bytearray(raw)
            changed[offset:offset + len(value)] = value
            mutations.append(bytes(changed))
        for changed in [b"", raw[:63], *mutations]:
            with self.subTest(size=len(changed)), self.assertRaises(checker.CheckError):
                checker.verify_elf(changed, text, SOURCE)

    def test_interpreter_and_dynamic_needed_rejected(self):
        raw, text = synthetic_elf()
        for kind in [3, 2]:
            changed = bytearray(raw)
            changed[56:58] = struct.pack("<H", 2)
            changed[120:176] = struct.pack("<IIQQQQQQ", kind, 6, 384, 0x400180, 0x400180, 16, 16, 8)
            changed[384:400] = struct.pack("<qQ", 1, 1)
            with self.subTest(kind=kind), self.assertRaises(checker.CheckError):
                checker.verify_elf(bytes(changed), text, SOURCE)

    def test_wrong_embedded_flags_and_report_forgery_rejected(self):
        for settings in [{"CGO_ENABLED": "1"}, {"vcs.modified": "true"}, {"vcs.revision": "e" * 40}, {"GOOS": "windows"}, {"GOARCH": "arm64"}, {"-trimpath": "false"}]:
            raw, text = synthetic_elf(**settings)
            with self.subTest(settings=settings), self.assertRaises(checker.CheckError):
                checker.verify_elf(raw, text, SOURCE)
        raw, text = synthetic_elf()
        for changed in [text.replace(b"CGO_ENABLED=0", b"CGO_ENABLED=1"), text.replace(b"go1.25.8", b"go1.25.7"), text + b"\tbuild\tCGO_ENABLED=0\n"]:
            with self.assertRaises(checker.CheckError):
                checker.verify_elf(raw, changed, SOURCE)

    def test_inline_build_info_bounds_and_duplicate_sections_rejected(self):
        raw, text = synthetic_elf()
        for offset, value in [(526, b"\x04"), (527, b"\x00"), (528, b"\x01"), (544, b"\xff" * 10), (1664, struct.pack("<I", 0))]:
            changed = bytearray(raw)
            changed[offset:offset + len(value)] = value
            with self.subTest(offset=offset), self.assertRaises(checker.CheckError):
                checker.verify_elf(bytes(changed), text, SOURCE)
        duplicate = bytearray(raw)
        duplicate[1536:1600] = duplicate[1664:1728]
        with self.assertRaises(checker.CheckError):
            checker.verify_elf(bytes(duplicate), text, SOURCE)


@unittest.skipUnless(os.name == "posix", "POSIX staging/descriptor metadata semantics require Linux CI; Windows runs pure ELF/inspect parser tests only")
class WebAndStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.web = self.root / "dist"
        self.data = {
            "trust.html": b'<html><link href="/assets/trust.css"><script src="/assets/trust.js"></script><img src="/assets/logo.svg"></html>',
            "index.html": b"<html>MAIN_DEMO_NOT_TO_BE_COPIED</html>",
            "assets/trust.js": b"export const trust = true;",
            "assets/trust.css": b"body{margin:0}",
            "assets/logo.svg": b"<svg/>",
            "assets/shared.js": b"export const shared = true;",
            "assets/main.js": b"MAIN_DEMO_NOT_TO_BE_COPIED",
        }
        self.manifest = {"trust.html": {"file": "assets/trust.js", "src": "trust.html", "isEntry": True, "imports": ["_shared.js"], "css": ["assets/trust.css"], "assets": ["assets/logo.svg"]}, "_shared.js": {"file": "assets/shared.js"}, "index.html": {"file": "assets/main.js", "src": "index.html", "isEntry": True}}
        self.refresh()

    def refresh(self):
        self.data[".vite/manifest.json"] = json.dumps(self.manifest, separators=(",", ":")).encode()
        for name, raw in self.data.items():
            put(self.web / name, raw)
        self.listing = "".join(checker.sha(raw) + "  ./" + name + "\n" for name, raw in sorted(self.data.items())).encode()

    def test_reachable_graph_preserves_manifest_but_excludes_main(self):
        files, selected = checker.source_web(self.web, self.listing)
        self.assertNotIn("index.html", selected)
        self.assertNotIn("assets/main.js", selected)
        self.assertEqual(selected, {"trust.html", ".vite/manifest.json", "assets/trust.js", "assets/trust.css", "assets/logo.svg", "assets/shared.js"})
        self.assertEqual(files[".vite/manifest.json"], self.data[".vite/manifest.json"])

    def test_hash_drift_missing_and_unlisted_files_rejected(self):
        for listing in [self.listing.replace(b"  ./trust.html", b"  ./missing.html"), self.listing + b"0" * 64 + b"  ./extra.js\n", b"0" * 64 + self.listing[64:]]:
            with self.assertRaises(checker.CheckError):
                checker.source_web(self.web, listing)
        put(self.web / "unknown.txt", b"not allowed")
        with self.assertRaises(checker.CheckError):
            checker.source_web(self.web, self.listing)

    def test_manifest_unsafe_types_paths_main_import_and_html_rejected(self):
        base_manifest, base_data = copy.deepcopy(self.manifest), copy.deepcopy(self.data)
        for field, value in [("file", "../outside.js"), ("file", "assets/privatekey.js"), ("imports", ["index.html"]), ("imports", ["missing"]), ("assets", ["assets/main.js.map"]), ("isEntry", 1), ("css", "assets/trust.css")]:
            original = copy.deepcopy(self.manifest)
            self.manifest["trust.html"][field] = value
            self.refresh()
            with self.subTest(field=field, value=value), self.assertRaises(checker.CheckError):
                checker.source_web(self.web, self.listing)
            self.manifest = original
        self.data["trust.html"] = b'<script src="https://outside.invalid/private"></script>'
        self.refresh()
        with self.assertRaises(checker.CheckError):
            checker.source_web(self.web, self.listing)
        for kind in ("depth", "assets", "bytes", "other-entry"):
            self.web = self.root / kind
            self.manifest, self.data = copy.deepcopy(base_manifest), copy.deepcopy(base_data)
            if kind == "depth":
                self.manifest["trust.html"]["imports"] = ["chain0"]
                for i in range(18):
                    self.data["assets/chain" + str(i) + ".js"] = b"export {};"
                    self.manifest["chain" + str(i)] = {"file": "assets/chain" + str(i) + ".js", "imports": ["chain" + str(i + 1)] if i < 17 else []}
            elif kind in {"assets", "bytes"}:
                extra = ["assets/extra" + str(i) + ".js" for i in range(65 if kind == "assets" else 5)]
                self.manifest["trust.html"]["assets"] = extra
                for name in extra:
                    self.data[name] = b"x" if kind == "assets" else b"x" * (2 << 20)
            else:
                self.manifest["trust.html"]["assets"] = ["assets/main.js"]
            self.refresh()
            with self.subTest(budget=kind), self.assertRaises(checker.CheckError):
                checker.source_web(self.web, self.listing)

    def test_duplicate_json_and_hash_paths_rejected(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b"not json"]:
            with self.assertRaises(checker.CheckError):
                checker.decode(raw)
        for raw in [self.listing + self.listing, b"0" * 64 + b"  ../escape\n", b"0" * 64 + b"  /absolute\n", b"0" * 64 + b"  ./assets//a.js\n"]:
            with self.assertRaises(checker.CheckError):
                checker.hash_listing(raw)

    def test_symlink_or_hardlink_input_rejected(self):
        source = self.web / "assets/trust.js"
        hard = self.root / "hard"
        os.link(source, hard)
        with self.assertRaises(checker.CheckError):
            checker.source_web(self.web, self.listing)
        hard.unlink()
        target = self.root / "target"
        source.rename(target)
        try:
            source.symlink_to(target)
        except OSError:
            self.skipTest("Windows symlink creation not permitted; Linux CI requires zero skips")
        with self.assertRaises(checker.CheckError):
            checker.source_web(self.web, self.listing)

    @unittest.skipUnless(os.name == "posix", "POSIX mode/owner evidence is Linux-only")
    def test_writable_or_executable_web_inputs_rejected(self):
        source = self.web / "assets/trust.js"
        for mode in [0o666, 0o755]:
            source.chmod(mode)
            with self.assertRaises(checker.CheckError):
                checker.source_web(self.web, self.listing)

    def stage_args(self):
        binary, buildinfo = synthetic_elf()
        put(self.root / "image-trust-api", binary, 0o555)
        put(self.root / "binary.sha256", (checker.sha(binary) + "  " + str(self.root / "image-trust-api") + "\n").encode())
        put(self.root / "buildinfo.txt", buildinfo)
        put(self.root / "web.sha256", self.listing)
        return argparse.Namespace(binary=self.root / "image-trust-api", binary_sha256=self.root / "binary.sha256", buildinfo=self.root / "buildinfo.txt", web_dist=self.web, web_sha256=self.root / "web.sha256", source_commit=SOURCE, context=self.root / "context", report=self.root / "report.json")

    def test_stage_exact_allowlist_modes_digest_and_no_overwrite(self):
        args = self.stage_args()
        report = checker.stage(args)
        names = {path.relative_to(args.context).as_posix() for path in args.context.rglob("*") if path.is_file()}
        self.assertEqual(names, set(report["contextFiles"]))
        self.assertEqual(names, {"Dockerfile", "rootfs/app/image-trust-api", "rootfs/app/web/.vite/manifest.json", "rootfs/app/web/trust.html", "rootfs/app/web/assets/trust.js", "rootfs/app/web/assets/trust.css", "rootfs/app/web/assets/shared.js", "rootfs/app/web/assets/logo.svg"})
        self.assertEqual((args.context / "rootfs/app/web/.vite/manifest.json").read_bytes(), self.data[".vite/manifest.json"])
        self.assertFalse(report["imageBuilt"])
        self.assertFalse(report["imageExecuted"])
        for path in args.context.rglob("*"):
            if os.name == "posix":
                want = 0o555 if path.is_dir() or path.name == "image-trust-api" else 0o444
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), want)
        with self.assertRaises(checker.CheckError):
            checker.stage(args)

    def test_bad_binary_digest_and_report_in_context_fail_without_context(self):
        args = self.stage_args()
        put(args.binary_sha256, b"0" * 64 + b"  actual-binary\n")
        with self.assertRaises(checker.CheckError):
            checker.stage(args)
        self.assertFalse(args.context.exists())
        args = self.stage_args()
        args.report = args.context / "secret-report.json"
        with self.assertRaises(checker.CheckError):
            checker.stage(args)
        self.assertFalse(args.context.exists())


class InspectTests(unittest.TestCase):
    def check(self, image=None, container=None, **options):
        base_image, base_container = synthetic_inspect()
        defaults = dict(image_id=IMAGE_ID, source=SOURCE, private=PRIVATE, state=PRIVATE + "/trust", network="none", status="running")
        defaults.update(options)
        return checker.inspect_projection(base_image if image is None else image, base_container if container is None else container, **defaults)

    def test_valid_running_and_clean_stopped_project_only_safe_fields(self):
        report = self.check()
        encoded = json.dumps(report)
        self.assertNotIn(PRIVATE, encoded)
        self.assertNotIn("Env", report)
        self.assertEqual(report["imageIdentityKind"], "LOCAL_DOCKER_CONFIG_ID_NOT_REGISTRY_MANIFEST")
        image, container = synthetic_inspect()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=0)
        self.assertTrue(self.check(image, container, status="exited")["cleanExit"])
        container["HostConfig"]["NetworkMode"] = "container:" + "e" * 64
        self.check(image, container, status="exited", network="container:" + "e" * 64)

    def test_runtime_authority_and_resource_mutations_rejected(self):
        for key, value in [("ReadonlyRootfs", False), ("Privileged", True), ("NetworkMode", "host"), ("CapDrop", []), ("CapAdd", ["NET_ADMIN"]), ("SecurityOpt", ["seccomp=unconfined"]), ("Memory", 0), ("MemorySwap", -1), ("NanoCpus", 0), ("PidsLimit", -1), ("Ulimits", []), ("AutoRemove", True), ("Init", True), ("Devices", [{"PathOnHost": "/dev/kmsg"}]), ("Tmpfs", {"/tmp": "rw"}), ("PortBindings", {"8080/tcp": []}), ("PidMode", "host"), ("Dns", ["8.8.8.8"]), ("IpcMode", "host"), ("IpcMode", "container:" + CONTAINER_ID), ("CgroupnsMode", "host"), ("UsernsMode", "host"), ("Runtime", "unreviewed-custom-runtime")]:
            image, container = synthetic_inspect()
            container["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(checker.CheckError):
                self.check(image, container)

    def test_identity_command_environment_and_mount_override_rejected(self):
        mutations = [lambda i, c: i.update(Id="sha256:" + "e" * 64), lambda i, c: i.update(Architecture="arm64"), lambda i, c: i.update(RepoDigests=["registry.invalid/private@sha256:" + "f" * 64]), lambda i, c: c["Config"].update(User="0"), lambda i, c: c["Config"].update(Entrypoint=["/bin/sh"]), lambda i, c: c["Config"].update(Env=["SECRET=never print this"]), lambda i, c: c["Config"].update(Cmd=["--help"]), lambda i, c: c["Config"].update(StopSignal="SIGKILL"), lambda i, c: c["Config"]["Labels"].update({"org.opencontainers.image.revision": "e" * 40}), lambda i, c: c["Mounts"][0].update(RW=True), lambda i, c: c["Mounts"][1].update(Source="/var/run/docker.sock"), lambda i, c: c["Mounts"][2].update(Destination="/app"), lambda i, c: c["Mounts"][2].update(Propagation="shared"), lambda i, c: c["Mounts"].append(copy.deepcopy(c["Mounts"][0]))]
        for mutate in mutations:
            image, container = synthetic_inspect()
            mutate(image, container)
            with self.assertRaises(checker.CheckError):
                self.check(image, container)

    def test_pid_and_exit_state_rejected(self):
        for mutation in [{"Pid": 0}, {"Pid": True}, {"Paused": True}, {"OOMKilled": True}, {"Error": "private detail"}, {"Running": False}]:
            image, container = synthetic_inspect()
            container["State"].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(checker.CheckError):
                self.check(image, container)
        image, container = synthetic_inspect()
        container["State"].update(Status="exited", Running=False, Pid=0, ExitCode=1)
        with self.assertRaises(checker.CheckError):
            self.check(image, container, status="exited")

    def test_inspect_shape_and_cli_error_do_not_echo_private_data(self):
        for raw in [b"{}", b"[]", b"[{},{}]", b'[null]', b'[{"Env":[],"Env":[]}]']:
            with self.assertRaises(checker.CheckError):
                checker.one_inspect(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            put(root / "bad.json", b'[{"Env":["SECRET=never print this"]}]')
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                result = checker.main(["inspect", "--image-inspect", str(root / "bad.json"), "--container-inspect", str(root / "bad.json"), "--image-id", IMAGE_ID, "--source-commit", SOURCE, "--expected-private-source", PRIVATE, "--expected-state-source", PRIVATE + "/trust", "--expected-network-mode", "none", "--container-status", "running", "--report", str(root / "report.json")])
            self.assertEqual(result, 1)
            self.assertNotIn("SECRET", output.getvalue())
            self.assertFalse((root / "report.json").exists())


if __name__ == "__main__":
    program = unittest.main(exit=False)
    result = program.result
    windows_skips = {
        "__main__.WebAndStagingTests.test_bad_binary_digest_and_report_in_context_fail_without_context",
        "__main__.WebAndStagingTests.test_duplicate_json_and_hash_paths_rejected",
        "__main__.WebAndStagingTests.test_hash_drift_missing_and_unlisted_files_rejected",
        "__main__.WebAndStagingTests.test_manifest_unsafe_types_paths_main_import_and_html_rejected",
        "__main__.WebAndStagingTests.test_reachable_graph_preserves_manifest_but_excludes_main",
        "__main__.WebAndStagingTests.test_stage_exact_allowlist_modes_digest_and_no_overwrite",
        "__main__.WebAndStagingTests.test_symlink_or_hardlink_input_rejected",
        "__main__.WebAndStagingTests.test_writable_or_executable_web_inputs_rejected",
    }
    import sys
    skipped_ids = {case.id() for case, _ in result.skipped}
    accepted_skips = (sys.platform.startswith("linux") and not result.skipped) or (
        sys.platform == "win32" and len(result.skipped) == 8 and skipped_ids == windows_skips
    )
    if result.testsRun != 18 or not result.wasSuccessful() or not accepted_skips:
        print("PRODUCT_IMAGE_CHECKER_TESTS=FAIL unexpected_test_set_or_skip=true", file=sys.stderr)
        raise SystemExit(1)
    print("PRODUCT_IMAGE_CHECKER_TESTS=PASS tests=18 skips=" + str(len(result.skipped)) + " simulated_elf=true actual_image_not_proven=true")
