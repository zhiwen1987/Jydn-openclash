#!/usr/bin/env python3
"""Bounded scratch-candidate staging and safe Docker inspection projection.

No network, compiler, Docker execution, credential output or production changes.
The Go 1.25 inline build-info format is checked inside the actual ELF, not
inferred from a caller's text report. Format reference:
https://github.com/golang/go/blob/go1.25.8/src/debug/buildinfo/buildinfo.go
This is artifact consistency, not a trusted-builder attestation or signature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import sys
import tempfile

sys.dont_write_bytecode = True
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ASSET = re.compile(r"assets/[A-Za-z0-9_-][A-Za-z0-9._-]*\.(?:js|css|svg|woff2)\Z")
ENTRYPOINT = ["/app/image-trust-api"]
BOUNDARY = "ISOLATED_PRODUCT_CANDIDATE"
STATE_LANES = ("update", "verify-reserved", "verify-consumed")
STATE_BOUNDARIES = ("after-journal-prepare", "after-prepared-audit", "before-result-audit",
                    "after-journal-outcome", "after-result-audit", "after-journal-ack")
STATE_FAULTS = ("acked-audit-missing", "prepared-audit-missing", "wrong-prefix",
                "prepared-key-conflict", "result-key-conflict", "wrong-scope",
                "bad-checkpoint", "later-invalid-acked")
DOCKERFILE = """FROM scratch
ARG SOURCE_COMMIT
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT
LABEL org.chengwang.boundary=ISOLATED_PRODUCT_CANDIDATE
COPY --chown=0:0 rootfs/ /
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["/app/image-trust-api"]
"""


class CheckError(ValueError):
    """Only constant, non-secret diagnostics may cross the CLI boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def asset_name(name) -> bool:
    return isinstance(name, str) and bool(ASSET.fullmatch(name)) and len(name.removeprefix("assets/")) <= 160


def pairs_unique(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def decode(raw: bytes):
    try:
        return json.loads(raw, object_pairs_hook=pairs_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(CheckError("non-finite JSON")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("invalid JSON") from error


def checked_path(path: pathlib.Path, *, directory: bool = False) -> pathlib.Path:
    path = pathlib.Path(os.path.abspath(path))
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode), "symlink path rejected")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "unsafe file type")
    if not directory:
        require(info.st_nlink == 1, "hardlinked file rejected")
    if os.name == "posix":
        require(info.st_uid in {0, os.geteuid()}, "unsafe input owner")
        require(not info.st_mode & 0o022, "writable input rejected")
    return path


def read_file(path: pathlib.Path, limit: int, *, nonempty: bool = True) -> bytes:
    path = checked_path(path)
    before = path.stat()
    require((0 < before.st_size if nonempty else 0 <= before.st_size) and before.st_size <= limit, "input size rejected")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino) and opened.st_nlink == 1 and stat.S_ISREG(opened.st_mode), "input changed while opening")
        data = bytearray()
        while len(data) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_nlink)
        require(fields(before) == fields(opened) == fields(after) and len(data) == before.st_size, "input changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def slice_at(raw: bytes, offset: int, size: int) -> bytes:
    require(0 <= offset <= len(raw) and 0 <= size <= len(raw) - offset, "ELF range rejected")
    return raw[offset:offset + size]


def varstring(raw: bytes, offset: int) -> tuple[bytes, int]:
    size = 0
    for shift in range(0, 70, 7):
        require(offset < len(raw), "truncated build info")
        ch = raw[offset]
        offset += 1
        require(shift < 63 or ch <= 1, "build info integer overflow")
        size |= (ch & 127) << shift
        if not ch & 128:
            require(size <= 2 << 20, "build info size rejected")
            return slice_at(raw, offset, size), offset + size
    raise CheckError("invalid build info integer")


def build_records(text: str) -> tuple[str, dict[str, str], list[str]]:
    records = [line.lstrip("\t") for line in text.splitlines() if line.strip()]
    settings = {}
    path = ""
    for line in records:
        if line.startswith("path\t"):
            require(not path, "duplicate build path")
            path = line[5:]
        elif line.startswith("build\t"):
            key, sep, value = line[6:].partition("=")
            require(sep == "=" and key not in settings, "invalid build setting")
            settings[key] = value
    return path, settings, records


def verify_elf(raw: bytes, buildinfo: bytes, source: str) -> dict:
    require(bool(COMMIT.fullmatch(source)), "invalid source commit")
    require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01", "ELF64 little-endian required")
    header = struct.unpack("<16sHHIQQQIHHHHHH", raw[:64])
    _, kind, machine, version, entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, strindex = header
    require(kind == 2 and machine == 62 and version == 1 and ehsize == 64, "Linux amd64 executable required")
    require(phsize == 56 and 1 <= phnum <= 128 and shsize == 64 and 1 <= shnum <= 8192 and 0 < strindex < shnum, "ELF table shape rejected")
    programs = [struct.unpack("<IIQQQQQQ", slice_at(raw, phoff + i * phsize, phsize)) for i in range(phnum)]
    executable_entry = False
    dynamics = []
    for ptype, flags, offset, address, _, filesz, memsz, _ in programs:
        require(filesz <= memsz, "ELF segment size rejected")
        slice_at(raw, offset, filesz)
        require(ptype != 3, "dynamic interpreter rejected")
        if ptype == 2:
            dynamics.append((offset, filesz))
        if ptype == 1 and flags & 1 and address <= entry < address + filesz:
            executable_entry = True
    require(executable_entry, "ELF entry outside executable load")
    sections = [struct.unpack("<IIQQQQIIQQ", slice_at(raw, shoff + i * shsize, shsize)) for i in range(shnum)]
    names_header = sections[strindex]
    require(names_header[1] == 3, "ELF section names rejected")
    names = slice_at(raw, names_header[4], names_header[5])
    infos = []
    for nameoff, stype, _, address, offset, size, _, _, _, _ in sections:
        require(nameoff < len(names), "ELF section name rejected")
        end = names.find(b"\0", nameoff)
        require(end >= 0, "ELF section name unterminated")
        if stype != 8:
            slice_at(raw, offset, size)
        if stype == 6:
            dynamics.append((offset, size))
        if names[nameoff:end] == b".go.buildinfo":
            require(stype == 1 and any(pt == 1 and po <= offset and offset + size <= po + ps and va + offset - po == address for pt, _, po, va, _, ps, _, _ in programs), "build info outside load segment")
            infos.append(slice_at(raw, offset, size))
    for offset, size in dynamics:
        require(size % 16 == 0, "dynamic table shape rejected")
        for i in range(0, size, 16):
            tag, _ = struct.unpack("<qQ", slice_at(raw, offset + i, 16))
            require(tag != 1, "dynamic dependency rejected")
    require(len(infos) == 1, "one Go build info section required")
    info = infos[0]
    require(len(info) >= 32 and info[:14] == b"\xff Go buildinf:" and info[14] == 8 and info[15] == 2 and info[16:32] == b"\0" * 16, "inline Go build info required")
    version_raw, next_offset = varstring(info, 32)
    module_raw, _ = varstring(info, next_offset)
    require(version_raw == b"go1.25.8" and len(module_raw) >= 33 and module_raw[-17] == 10, "Go toolchain or module frame rejected")
    try:
        embedded = module_raw[16:-16].decode("utf-8")
        external_lines = buildinfo.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise CheckError("build info encoding rejected") from error
    require(external_lines and external_lines[0].endswith(": go1.25.8"), "reported Go version rejected")
    path, settings, records = build_records(embedded)
    external_path, external_settings, external_records = build_records("\n".join(external_lines[1:]))
    require(path == "chengwang/image-binding/cmd/image-trust-api" and external_path == path and external_settings == settings and external_records == records, "reported build info differs from ELF")
    for key, value in {"-buildmode": "exe", "-trimpath": "true", "CGO_ENABLED": "0", "GOARCH": "amd64", "GOOS": "linux", "vcs": "git", "vcs.revision": source, "vcs.modified": "false"}.items():
        require(settings.get(key) == value, "required binary build setting rejected")
    return {"format": "ELF64_LSB_AMD64_EXEC", "goVersion": "go1.25.8", "cgoEnabled": False,
            "sourceCommit": source, "sourceModified": False, "trimpath": True,
            "interpreterPresent": False, "dynamicDependencies": 0, "embeddedBuildInfoSHA256": sha(module_raw)}


def hash_listing(raw: bytes) -> dict[str, str]:
    result = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise CheckError("hash list encoding rejected") from error
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([^\r\n\\]+)", line)
        require(match is not None, "hash list record rejected")
        digest, name = match.groups()
        require(name not in result and name not in {".", ".."} and not name.startswith("/") and all(part not in {"", ".", ".."} for part in name.split("/")), "hash list path rejected")
        result[name] = digest
    require(bool(result), "empty hash list")
    return result


def source_web(directory: pathlib.Path, listing_raw: bytes) -> tuple[dict[str, bytes], set[str]]:
    directory = checked_path(directory, directory=True)
    expected = hash_listing(listing_raw)
    actual = {}
    count = total = 0
    for root, dirs, files in os.walk(directory, followlinks=False):
        root_path = pathlib.Path(root)
        checked_path(root_path, directory=True)
        for name in dirs:
            checked_path(root_path / name, directory=True)
        for name in files:
            path = root_path / name
            relative = path.relative_to(directory).as_posix()
            require(relative in {"index.html", "trust.html", ".vite/manifest.json"} or asset_name(relative), "unknown web output path")
            require(not re.search(r"(?:^|[._-])(?:test|spec|secret|credentials?|privatekey)(?:[._-]|$)", relative, re.I), "private or test web output rejected")
            data = read_file(path, 2 << 20)
            if os.name == "posix":
                require(not path.stat().st_mode & 0o111, "executable web file rejected")
            count += 1
            total += len(data)
            require(count <= 256 and total <= 64 << 20, "web output budget rejected")
            actual[relative] = data
    require(set(expected) == set(actual) and all(sha(actual[name]) == digest for name, digest in expected.items()), "original web output digest mismatch")
    require("trust.html" in actual and ".vite/manifest.json" in actual and len(actual["trust.html"]) <= 256 << 10 and len(actual[".vite/manifest.json"]) <= 256 << 10, "web entry or manifest rejected")
    manifest = decode(actual[".vite/manifest.json"])
    fields = {"file", "src", "name", "names", "isEntry", "isDynamicEntry", "imports", "dynamicImports", "css", "assets"}
    require(isinstance(manifest, dict) and 0 < len(manifest) <= 256, "manifest shape rejected")
    for key, value in manifest.items():
        require(isinstance(key, str) and isinstance(value, dict) and not set(value) - fields, "manifest member rejected")
        for name, item in value.items():
            if name in {"imports", "dynamicImports", "css", "assets", "names"}:
                require(isinstance(item, list) and all(isinstance(x, str) for x in item), "manifest array rejected")
            elif name in {"isEntry", "isDynamicEntry"}:
                require(type(item) is bool, "manifest boolean rejected")
            else:
                require(isinstance(item, str), "manifest string rejected")
    require(manifest.get("trust.html", {}).get("isEntry") is True and manifest["trust.html"].get("src") == "trust.html", "trust manifest entry rejected")
    selected = {"trust.html", ".vite/manifest.json"}
    visited = set()
    asset_count = total = 0
    total = len(actual["trust.html"])
    def add(name):
        nonlocal asset_count, total
        require(asset_name(name) and name in actual, "unreachable or invalid asset")
        if name in selected:
            return
        asset_count += 1
        total += len(actual[name])
        require(asset_count <= 64 and total <= 8 << 20, "trust graph budget rejected")
        selected.add(name)
    def visit(key, depth):
        require(isinstance(key, str) and 0 < len(key) <= 256 and depth <= 16, "trust graph depth rejected")
        if key in visited:
            return
        require(key in manifest, "missing manifest dependency")
        visited.add(key)
        item = manifest[key]
        add(item.get("file"))
        for name in item.get("css", []) + item.get("assets", []):
            add(name)
        for dependency in item.get("imports", []) + item.get("dynamicImports", []):
            require(dependency != "index.html", "main application dependency rejected")
            visit(dependency, depth + 1)
    visit("trust.html", 0)
    for key, item in manifest.items():
        if key != "trust.html" and item.get("isEntry") is True:
            require(item.get("file") not in selected, "other application entry copied into trust graph")
    for name in re.findall(rb"(?i)(?:src|href)\s*=\s*[\"']([^\"']+)[\"']", actual["trust.html"]):
        try:
            name = name.decode("utf-8").removeprefix("/")
        except UnicodeError as error:
            raise CheckError("HTML reference encoding rejected") from error
        require(name in selected and name not in {"trust.html", ".vite/manifest.json"}, "HTML reference outside trust graph")
    # The unmodified full manifest is retained, but never its main-only files.
    return actual, selected


def write_exclusive(path: pathlib.Path, raw: bytes, mode: int = 0o600) -> None:
    checked_path(path.parent, directory=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(raw)
        os.fchmod(fd, mode) if hasattr(os, "fchmod") else os.chmod(path, mode)
    finally:
        os.close(fd)


def stage(args) -> dict:
    binary = read_file(args.binary, 128 << 20)
    binary_listing = read_file(args.binary_sha256, 16 << 10).decode("utf-8").splitlines()
    require(len(binary_listing) == 1 and re.fullmatch(r"[0-9a-f]{64}  [^\r\n]+", binary_listing[0]) is not None and binary_listing[0][:64] == sha(binary), "binary digest mismatch")
    result = verify_elf(binary, read_file(args.buildinfo, 2 << 20), args.source_commit)
    listing = read_file(args.web_sha256, 128 << 10)
    web, selected = source_web(args.web_dist, listing)
    dockerfile = read_file(pathlib.Path(__file__).with_name("Dockerfile"), 16 << 10)
    require(dockerfile.decode("utf-8").replace("\r\n", "\n") == DOCKERFILE, "unreviewed Dockerfile rejected")
    context = pathlib.Path(os.path.abspath(args.context))
    checked_path(context.parent, directory=True)
    require(not context.exists() and not context.is_symlink(), "context already exists")
    report = pathlib.Path(os.path.abspath(args.report))
    require(report != context and context not in report.parents, "report must stay outside image context")
    # Only a fresh, generated sibling is ever cleaned up on staging failure.
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=".product-context-", dir=context.parent))
    try:
        outputs = {"Dockerfile": DOCKERFILE.encode(), "rootfs/app/image-trust-api": binary,
                   **{"rootfs/app/web/" + name: web[name] for name in selected}}
        for name, raw in sorted(outputs.items()):
            path = temporary / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_exclusive(path, raw, 0o555 if name == "rootfs/app/image-trust-api" else 0o444)
        for root, dirs, _ in os.walk(temporary, topdown=False):
            for name in dirs:
                os.chmod(pathlib.Path(root) / name, 0o555)
        os.chmod(temporary, 0o555)
        os.rename(temporary, context)
    finally:
        if temporary.exists():
            for root, dirs, files in os.walk(temporary):
                os.chmod(root, 0o700)
                for name in files:
                    os.chmod(pathlib.Path(root) / name, 0o600)
            shutil.rmtree(temporary)
    file_hashes = {name: sha(raw) for name, raw in sorted(outputs.items())}
    return {"boundary": BOUNDARY, "authorization": "BLOCKED", "deviceActionsExecuted": False,
            "sourceCommit": args.source_commit, "binary": {**result, "sha256": sha(binary), "bytes": len(binary)},
            "originalWebListingSHA256": sha(listing), "originalManifestSHA256": sha(web[".vite/manifest.json"]),
            "contextFiles": file_hashes, "contextFileCount": len(file_hashes),
            "contextSHA256": sha("".join(name + "\t" + digest + "\n" for name, digest in file_hashes.items()).encode()),
            "contextPublished": True, "imageBuilt": False, "imageExecuted": False,
            "imageIdentityKind": "NOT_YET_BUILT_NOT_A_REGISTRY_MANIFEST"}


def one_inspect(raw: bytes) -> dict:
    data = decode(raw)
    require(isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict), "one inspect object required")
    return data[0]


def inspect_projection(image: dict, container: dict, *, image_id: str, source: str,
                       private: str, state: str, network: str, status: str,
                       fixture_kind: str = "product-image", planned_sigkill: bool = False,
                       startup_rejected: bool = False) -> dict:
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)) and bool(COMMIT.fullmatch(source)), "image identity rejected")
    require(image.get("Id") == image_id and container.get("Image") == image_id, "actual image identity mismatch")
    require(image.get("Os") == "linux" and image.get("Architecture") == "amd64", "image platform rejected")
    require(not image.get("RepoDigests"), "local image must not claim registry identity")
    ic, cc, host, current = (image.get("Config"), container.get("Config"), container.get("HostConfig"), container.get("State"))
    require(all(isinstance(x, dict) for x in (ic, cc, host, current)), "inspect configuration missing")
    for config in (ic, cc):
        require(config.get("Entrypoint") == ENTRYPOINT and config.get("User") == "10001:10001" and config.get("WorkingDir") == "/app", "default executable or user replaced")
        labels = config.get("Labels", {})
        require(isinstance(labels, dict) and labels.get("org.opencontainers.image.revision") == source and labels.get("org.chengwang.boundary") == BOUNDARY, "source labels mismatch")
        require(not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("Healthcheck") and not config.get("Tty") and not config.get("OpenStdin"), "unexpected image or terminal surface")
        require(config.get("StopSignal") in (None, "", "SIGTERM"), "stop signal override rejected")
        env = config.get("Env")
        require(env in (None, [], ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]), "unexpected environment rejected")
    require(ic.get("Cmd") in (None, []), "image must not bake configuration arguments")
    # The original CLI stays D10-only. Separate lifecycle checkers opt in to
    # their closed namespaces while reusing every runtime security check.
    # No caller-supplied arbitrary prefix, path rewrite or broad /tmp allowance.
    require(fixture_kind in {"product-image", "product-registry", "product-lifecycle", "product-crash", "product-state"}, "fixture kind rejected")
    require(type(planned_sigkill) is bool and (not planned_sigkill or fixture_kind == "product-crash" and status == "exited"), "planned abnormal exit scope rejected")
    require(type(startup_rejected) is bool and (not startup_rejected or fixture_kind == "product-state" and status == "exited" and not planned_sigkill), "startup rejection scope rejected")
    if fixture_kind == "product-registry":
        require(isinstance(private, str) and bool(re.fullmatch(r"/tmp/chengwang-product-registry-[0-9a-f]{32}/(?:message-signature|dsse)", private)), "private registry fixture path rejected")
    elif fixture_kind == "product-lifecycle":
        require(isinstance(private, str) and bool(re.fullmatch(r"/tmp/chengwang-product-lifecycle-[0-9a-f]{32}/refresh/(?:message-signature|dsse)", private)), "private lifecycle fixture path rejected")
    elif fixture_kind == "product-crash":
        require(isinstance(private, str) and bool(re.fullmatch(r"/tmp/chengwang-product-lifecycle-[0-9a-f]{32}/(?:prepared|reserved|consumed)/(?:message-signature|dsse)", private)), "private crash fixture path rejected")
    elif fixture_kind == "product-state":
        pattern = (r"/tmp/chengwang-product-lifecycle-[0-9a-f]{32}/state/(?:"
                   + "|".join(STATE_LANES) + r")/(" + "|".join((*STATE_BOUNDARIES, *STATE_FAULTS))
                   + r")/(?:message-signature|dsse)")
        match = re.fullmatch(pattern, private) if isinstance(private, str) else None
        require(match is not None, "private state fixture path rejected")
        require(startup_rejected is (match[1] in STATE_FAULTS), "state scenario and exit profile disagree")
    else:
        require(isinstance(private, str) and private.startswith("/tmp/chengwang-product-image-") and pathlib.PurePosixPath(private).as_posix() == private and all(x not in {"", ".", ".."} for x in private.split("/")[1:]), "private fixture path rejected")
    require(state == private + "/trust", "state mount binding rejected")
    args = ["--config", private + "/trust-config.json", "--product-config", private + "/product-config.json"]
    require(cc.get("Cmd") == args and container.get("Path") == ENTRYPOINT[0] and container.get("Args") == args, "container default entrypoint arguments rejected")
    require(network == "none" or bool(re.fullmatch(r"container:[0-9a-f]{64}", network)), "network expectation rejected")
    require(host.get("NetworkMode") == network and host.get("ReadonlyRootfs") is True and host.get("Privileged") is False, "runtime isolation rejected")
    require(host.get("IpcMode") in (None, "", "private") and host.get("CgroupnsMode") in (None, "", "private") and not host.get("UsernsMode"), "host namespace sharing rejected")
    require(host.get("Runtime") in (None, "", "runc", "io.containerd.runc.v2"), "runtime override rejected")
    require(host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"), "capability boundary rejected")
    security = host.get("SecurityOpt")
    require(isinstance(security, list) and len(security) == 1 and security[0] in {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}, "no-new-privileges required")
    require(all(type(host.get(key)) is int and host[key] == value for key, value in {"Memory": 268435456, "MemorySwap": 268435456, "NanoCpus": 1000000000, "PidsLimit": 128}.items()), "resource limits rejected")
    require(host.get("Ulimits") == [{"Name": "nofile", "Hard": 1024, "Soft": 1024}], "file descriptor limit rejected")
    require(host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0} and cc.get("StopTimeout") == 15 and host.get("AutoRemove") is False and not host.get("Init"), "lifecycle options rejected")
    for field in ("Devices", "DeviceRequests", "DeviceCgroupRules", "VolumesFrom", "Links", "ExtraHosts", "Dns", "DnsSearch", "DnsOptions", "GroupAdd", "Sysctls", "Tmpfs", "PortBindings", "PublishAllPorts", "PidMode", "UTSMode", "CgroupParent", "OomKillDisable"):
        require(not host.get(field), "extra runtime authority rejected")
    mounts = container.get("Mounts")
    require(isinstance(mounts, list) and len(mounts) == 3, "exact fixture mounts required")
    expected = {private: False, private + "/trust": True, private + "/data": True}
    destinations = set()
    for mount in mounts:
        require(isinstance(mount, dict), "mount record rejected")
        destination = mount.get("Destination")
        require(destination in expected and destination not in destinations and mount.get("Type") == "bind" and mount.get("Source") == destination and mount.get("RW") is expected[destination] and mount.get("Propagation") == "rprivate", "mount boundary rejected")
        destinations.add(destination)
    ns = container.get("NetworkSettings")
    require(isinstance(ns, dict) and not ns.get("Ports") and not host.get("PublishAllPorts"), "host port exposure rejected")
    require(not current.get("Paused") and not current.get("Restarting") and not current.get("Dead") and not current.get("OOMKilled") and not current.get("Error"), "container health state rejected")
    pid = current.get("Pid")
    require(type(pid) is int and current.get("Status") == status, "PID state rejected")
    if status == "running":
        require(pid > 0 and current.get("Running") is True, "running process required")
    else:
        require(status == "exited" and pid == 0 and current.get("Running") is False and type(current.get("ExitCode")) is int and current["ExitCode"] == (137 if planned_sigkill else 1 if startup_rejected else 0), "expected exact exit required")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", container.get("Id", ""))), "container identity rejected")
    return {"boundary": BOUNDARY, "authorization": "BLOCKED", "deviceActionsExecuted": False,
            "sourceCommit": source, "localImageID": image_id, "imageIdentityKind": "LOCAL_DOCKER_CONFIG_ID_NOT_REGISTRY_MANIFEST",
            "containerID": container["Id"], "entrypoint": ENTRYPOINT, "user": "10001:10001", "workdir": "/app",
            "readOnlyRootfs": True, "capabilitiesDropped": "ALL", "noNewPrivileges": True,
            "networkIsolation": "none" if network == "none" else "shared_isolated_fixture",
            "hostPorts": 0, "bindMounts": {"privateReadOnly": True, "trustStateReadWrite": True, "productDataReadWrite": True},
            "memoryBytes": host["Memory"], "memorySwapBytes": host["MemorySwap"], "nanoCPUs": host["NanoCpus"], "pidsLimit": host["PidsLimit"], "nofile": 1024,
            "restartPolicy": "no", "stopTimeoutSeconds": 15, "state": status, "pid": pid,
            "cleanExit": status == "exited" and not planned_sigkill and not startup_rejected, "rawEnvironmentIncluded": False, "rawMountSourcesIncluded": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    staging = sub.add_parser("stage")
    for option in ("binary", "binary-sha256", "buildinfo", "web-dist", "web-sha256", "context", "report"):
        staging.add_argument("--" + option, type=pathlib.Path, required=True)
    staging.add_argument("--source-commit", required=True)
    inspection = sub.add_parser("inspect")
    for option in ("image-inspect", "container-inspect", "report"):
        inspection.add_argument("--" + option, type=pathlib.Path, required=True)
    for option in ("image-id", "source-commit", "expected-private-source", "expected-state-source", "expected-network-mode"):
        inspection.add_argument("--" + option, required=True)
    inspection.add_argument("--container-status", choices=("running", "exited"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            result = stage(args)
        else:
            result = inspect_projection(one_inspect(read_file(args.image_inspect, 8 << 20)), one_inspect(read_file(args.container_inspect, 8 << 20)), image_id=args.image_id, source=args.source_commit, private=args.expected_private_source, state=args.expected_state_source, network=args.expected_network_mode, status=args.container_status)
        write_exclusive(args.report, (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode())
    except (OSError, CheckError, UnicodeError, struct.error, TypeError, KeyError, AttributeError):
        print("PRODUCT_IMAGE_CHECK=FAIL rejected=true raw_input_suppressed=true", file=sys.stderr)
        return 1
    print("PRODUCT_IMAGE_CHECK=PASS mode=" + args.command + " boundary=" + BOUNDARY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
