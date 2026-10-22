#!/usr/bin/env python3
"""Check the exact SDK version and the two explicitly allowed local modules."""
import json
import pathlib
import sys

module_root = pathlib.Path(__file__).resolve().parent.parent
expected_local = {"chengwang": module_root.parent.parent,
                  "chengwang-image-verifier": module_root.parent / "image-verifier"}
raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
decoder = json.JSONDecoder()
modules = {}
while raw.strip():
    value, end = decoder.raw_decode(raw.lstrip())
    if not isinstance(value, dict) or not isinstance(value.get("Path"), str) or value["Path"] in modules:
        raise SystemExit("invalid or duplicated module evidence")
    modules[value["Path"]] = value
    raw = raw.lstrip()[end:]
if modules.get("chengwang/image-binding", {}).get("Main") is not True:
    raise SystemExit("binding must be its own main module")
if pathlib.Path(modules["chengwang/image-binding"].get("Dir", "")).resolve() != module_root:
    raise SystemExit("unexpected binding module directory")
sdk = modules.get("github.com/sigstore/sigstore-go", {})
if sdk.get("Version") != "v1.3.0" or "Replace" in sdk:
    raise SystemExit("Sigstore must be v1.3.0 without replacement")
for name, path in expected_local.items():
    replacement = modules.get(name, {}).get("Replace", {})
    if modules.get(name, {}).get("Version") != "v0.0.0" or pathlib.Path(replacement.get("Dir", "")).resolve() != path.resolve() or replacement.get("Version"):
        raise SystemExit("unexpected local module replacement")
for name, value in modules.items():
    if name not in expected_local and "Replace" in value:
        raise SystemExit("unapproved dependency replacement")
print("IMAGE_BINDING_MODULE_PINS=PASS sigstore-go=v1.3.0 local_modules=2 unexpected_replacements=0")
