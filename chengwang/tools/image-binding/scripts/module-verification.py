#!/usr/bin/env python3
"""Use official Go verification for an exact remote graph; bind local source manifests.

Go 1.25.8 mod verify attempts to find archive hashes for local replace paths.
The auxiliary module excludes ONLY the two reviewed local modules. All remote
MVS versions and original go.sum pins must match before official mod verify runs.
"""
import hashlib
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCAL = {"chengwang/image-binding": ROOT, "chengwang": ROOT.parent.parent,
         "chengwang-image-verifier": ROOT.parent / "image-verifier"}
AUXILIARY = "chengwang-ci.invalid/remote-module-verification"


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


def prepare(run):
    remote, _ = expected_remote(run)
    auxiliary = run / "remote-verification"
    auxiliary.mkdir(mode=0o700, exist_ok=False)
    text = "module " + AUXILIARY + "\n\ngo 1.25.8\n\nrequire (\n"
    text += "".join("\t" + name + " " + version + "\n" for name, version in sorted(remote.items()))
    text += ")\n"
    (auxiliary / "go.mod").write_text(text, encoding="utf-8", newline="\n")
    (auxiliary / "go.sum").write_bytes((ROOT / "go.sum").read_bytes())
    manifest = {"local": local_manifest(), "remote": remote,
                "auxiliary": {file: sha(auxiliary / file) for file in ("go.mod", "go.sum")}}
    (run / "evidence/module-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    print(f"IMAGE_BINDING_MODULE_MANIFEST=PASS local_modules=3 remote_modules={len(remote)}")


def check(run, cache, actual_path):
    manifest = json.loads((run / "evidence/module-manifest.json").read_text(encoding="utf-8"))
    remote, pins = expected_remote(run)
    if manifest["local"] != local_manifest() or manifest["remote"] != remote:
        raise ValueError("local manifests or remote pins changed")
    auxiliary = run / "remote-verification"
    if manifest["auxiliary"] != {file: sha(auxiliary / file) for file in ("go.mod", "go.sum")}:
        raise ValueError("verification auxiliary module changed")
    actual = read_objects(actual_path)
    main = actual.pop(AUXILIARY, {})
    if main.get("Main") is not True or pathlib.Path(main.get("Dir", "")).resolve() != auxiliary:
        raise ValueError("unexpected verification main module")
    if any("Replace" in value for value in actual.values()) or {name: value.get("Version") for name, value in actual.items()} != remote:
        raise ValueError("remote verification graph differs from original exact MVS graph")
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
        prepare(run)
    elif operation == "check" and len(rest) == 1:
        check(run, cache, pathlib.Path(rest[0]).resolve(strict=True))
    else:
        raise SystemExit("expected prepare RUN CACHE or check RUN CACHE REMOTE_MODULES_JSON")
