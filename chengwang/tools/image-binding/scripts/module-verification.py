#!/usr/bin/env python3
"""Verify the unchanged remote graph using two fixed local-only dotted aliases.

Copy the original module, changing only its two local require/replace names
and replacement directories. Never promote remote dependencies to roots or
use a Go workspace. Local source manifests are checked separately, not claimed
to have remote archives. Official Go verifies every pinned remote archive.
"""
import hashlib
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCAL = {"chengwang/image-binding": ROOT, "chengwang": ROOT.parent.parent,
         "chengwang-image-verifier": ROOT.parent / "image-verifier"}
ALIASES = {"chengwang-ci.invalid/local-main": "chengwang",
           "chengwang-ci.invalid/local-verifier": "chengwang-image-verifier"}


def read_objects(path):
    raw = path.read_text(encoding="utf-8")
    decoder, result = json.JSONDecoder(), {}
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip())
        if not isinstance(value, dict) or not isinstance(value.get("Path"), str) or value["Path"] in result or value.get("Error"):
            raise ValueError("invalid, duplicated or failed module evidence")
        result[value["Path"]] = value
        raw = raw.lstrip()[end:]
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def original_pins():
    pins = {}
    for line in (ROOT / "go.sum").read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[2].startswith("h1:"):
            raise ValueError("invalid original go.sum")
        key = tuple(parts[:2])
        if key in pins and pins[key] != parts[2]:
            raise ValueError("conflicting original go.sum pin")
        pins[key] = parts[2]
    combined = dict(pins)
    for directory in LOCAL.values():
        for line in (directory / "go.sum").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) != 3 or not parts[2].startswith("h1:"):
                raise ValueError("invalid local module checksum file")
            key = tuple(parts[:2])
            if key in combined and combined[key] != parts[2]:
                raise ValueError("conflicting checksum pins across local modules")
            combined[key] = parts[2]
    return pins


def expected_remote(run):
    modules = read_objects(run / "evidence/modules.json")
    if not set(LOCAL).issubset(modules):
        raise ValueError("missing local module")
    remote = {}
    pins = original_pins()
    for name, module in modules.items():
        if name in LOCAL:
            continue
        version = module.get("Version", "")
        if "Replace" in module or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~/-]*", name) or not re.fullmatch(r"v[A-Za-z0-9.+_-]+", version):
            raise ValueError("unapproved remote module identity or replacement")
        if (name, version) not in pins or (name, version + "/go.mod") not in pins:
            raise ValueError(f"remote module lacks original archive/go.mod pin: {name}@{version}")
        remote[name] = version
    if not remote:
        raise ValueError("no remote modules to verify")
    return remote, pins


def local_manifest():
    return {name: {file: sha(directory / file) for file in ("go.mod", "go.sum")}
            for name, directory in LOCAL.items()}


def check_alias_cache(cache):
    for alias in ALIASES:
        # No archive, ziphash, extracted directory or download metadata may
        # masquerade as either deliberately local-only verification alias.
        candidates = [cache / "cache/download" / alias,
                      cache / (alias + "@v0.0.0")]
        if any(path.exists() or path.is_symlink() for path in candidates):
            raise ValueError("local-only alias unexpectedly exists in module cache")


def auxiliary_mod():
    raw = (ROOT / "go.mod").read_bytes()
    for alias, original in ALIASES.items():
        token = re.escape(original.encode("ascii"))
        pattern = rb"(?m)^([ \t]+)" + token + rb"([ \t]+)v0\.0\.0(?=[ \t]*(?://[^\r\n]*)?\r?$)"
        raw, count = re.subn(pattern, lambda match: match[1] + alias.encode("ascii") + match[2] + b"v0.0.0", raw)
        if count != 1:
            raise ValueError("expected exactly one original local require")
        pattern = rb"(?m)^replace[ \t]+" + token + rb"[ \t]+=>[ \t]+[^\r\n]+(?=\r?$)"
        replacement = ("replace " + alias + " => " + json.dumps(str(LOCAL[original].resolve()), ensure_ascii=True)).encode("ascii")
        raw, count = re.subn(pattern, lambda match: replacement, raw)
        if count != 1:
            raise ValueError("expected exactly one original local replace")
    return raw


def check_graph(run, actual_path):
    remote, pins = expected_remote(run)
    actual = read_objects(actual_path)
    directory = run / "remote-verification"
    main = actual.pop("chengwang/image-binding", {})
    if main.get("Main") is not True or main.get("Version") or "Replace" in main or pathlib.Path(main.get("Dir", "")).resolve() != directory.resolve() or pathlib.Path(main.get("GoMod", "")).resolve() != (directory / "go.mod").resolve():
        raise ValueError("verification main module does not match its temporary directory")
    for alias, original in ALIASES.items():
        module = actual.pop(alias, {})
        replacement = module.get("Replace", {})
        directory = LOCAL[original].resolve()
        if module.get("Main") or module.get("Version") != "v0.0.0" or replacement.get("Version") or pathlib.Path(replacement.get("Path", "")).resolve() != directory or pathlib.Path(replacement.get("Dir", "")).resolve() != directory or pathlib.Path(replacement.get("GoMod", "")).resolve() != directory / "go.mod" or pathlib.Path(module.get("Dir", "")).resolve() != directory or pathlib.Path(module.get("GoMod", "")).resolve() != directory / "go.mod":
            raise ValueError("verification alias is not the exact approved local replacement")
    if any(value.get("Main") or "Replace" in value for value in actual.values()) or {name: value.get("Version") for name, value in actual.items()} != remote:
        raise ValueError("remote verification graph differs from original exact MVS graph")
    return remote, pins


def prepare(run, cache):
    remote, _ = expected_remote(run)
    check_alias_cache(cache)
    auxiliary = run / "remote-verification"
    auxiliary.mkdir(mode=0o700, exist_ok=False)
    (auxiliary / "go.mod").write_bytes(auxiliary_mod())
    (auxiliary / "go.sum").write_bytes((ROOT / "go.sum").read_bytes())
    manifest = {"local": local_manifest(), "remote": remote,
                "auxiliary": {file: sha(auxiliary / file) for file in ("go.mod", "go.sum")}}
    (run / "evidence/module-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    print(f"IMAGE_BINDING_MODULE_MANIFEST=PASS local_modules=3 remote_modules={len(remote)} local_only_aliases=2 workspace=off")


def check(run, cache, actual_path):
    manifest = json.loads((run / "evidence/module-manifest.json").read_text(encoding="utf-8"))
    remote, pins = expected_remote(run)
    if manifest["local"] != local_manifest() or manifest["remote"] != remote:
        raise ValueError("local manifests or remote pins changed")
    auxiliary = run / "remote-verification"
    if set(path.name for path in auxiliary.iterdir()) != {"go.mod", "go.sum"}:
        raise ValueError("unexpected files in verification module")
    if manifest["auxiliary"] != {file: sha(auxiliary / file) for file in ("go.mod", "go.sum")} or (auxiliary / "go.mod").read_bytes() != auxiliary_mod() or (auxiliary / "go.sum").read_bytes() != (ROOT / "go.sum").read_bytes():
        raise ValueError("verification module or checksum lock changed")
    check_alias_cache(cache)
    check_graph(run, actual_path)
    downloads = read_objects(run / "evidence/remote-downloads.json")
    if set(downloads) != set(remote):
        raise ValueError("remote archive coverage differs from expected modules")
    for name, version in remote.items():
        download = downloads[name]
        if download.get("Version") != version or download.get("Sum") != pins[(name, version)] or download.get("GoModSum") != pins[(name, version + "/go.mod")]:
            raise ValueError("remote downloaded archive does not match original go.sum")
        paths = {field: pathlib.Path(download.get(field, "")).resolve() for field in ("Zip", "Dir", "GoMod")}
        if any(not path.is_relative_to(cache) for path in paths.values()):
            raise ValueError("remote verification path escapes module cache")
        if not paths["Zip"].is_file() or not paths["Dir"].is_dir() or not paths["GoMod"].is_file():
            raise ValueError("remote archive, extracted source or module metadata is missing")
        if pathlib.Path(str(paths["Zip"]) + "hash").read_text(encoding="utf-8").strip() != pins[(name, version)]:
            raise ValueError("remote cache ziphash differs from original go.sum")
    print(f"IMAGE_BINDING_REMOTE_MODULE_CONTRACT=PASS remote_modules={len(remote)} exact_mvs=true original_go_sum=true local_manifests=3")


if __name__ == "__main__":
    operation, run_arg, cache_arg, *rest = sys.argv[1:]
    run = pathlib.Path(run_arg).resolve(strict=True)
    cache = pathlib.Path(cache_arg).resolve(strict=True)
    if run.is_relative_to(ROOT) or cache.is_relative_to(run):
        raise SystemExit("verification temp/cache locations are not isolated")
    if operation == "prepare" and not rest:
        prepare(run, cache)
    elif operation == "graph" and len(rest) == 1:
        remote, _ = check_graph(run, pathlib.Path(rest[0]).resolve(strict=True))
        check_alias_cache(cache)
        print(f"IMAGE_BINDING_EXACT_MVS_GRAPH=PASS remote_modules={len(remote)} local_only_aliases=2 workspace=off final_verification_pending=true")
    elif operation == "check" and len(rest) == 1:
        check(run, cache, pathlib.Path(rest[0]).resolve(strict=True))
    else:
        raise SystemExit("expected prepare RUN CACHE or graph/check RUN CACHE REMOTE_MODULES_JSON")
