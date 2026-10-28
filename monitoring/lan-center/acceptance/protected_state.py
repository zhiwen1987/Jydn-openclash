#!/usr/bin/env python3
"""Capture and compare hashes without copying or printing protected contents."""
import argparse
import hashlib
import json
from pathlib import Path
import time


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def json_pointer(value, pointer: str):
    if pointer == "":
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("json_pointer_invalid")
    current = value
    for raw in pointer[1:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise ValueError("json_pointer_missing")
    return current


def semantic_digest(path: Path, pointers: list[str]) -> tuple[str, int]:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("protected_json_too_large")
    document = json.loads(path.read_text(encoding="utf-8"))
    selected = [json_pointer(document, pointer) for pointer in pointers]
    payload = json.dumps(selected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest(), len(pointers)


def capture(specification: Path) -> dict:
    spec = json.loads(specification.read_text(encoding="utf-8"))
    rows = []
    names = set()
    for item in spec["files"]:
        path = Path(item["path"])
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError("protected_file_invalid:" + item["name"])
        name = str(item["name"])
        if name in names:
            raise ValueError("protected_name_duplicate")
        names.add(name)
        rows.append({"name": name, "bytes": path.stat().st_size, "sha256": digest(path)})
    semantic = []
    for item in spec.get("json_values", []):
        path = Path(item["path"])
        pointers = item.get("pointers")
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or not isinstance(pointers, list) or not pointers
                or not all(isinstance(pointer, str) for pointer in pointers)):
            raise ValueError("protected_json_invalid:" + str(item.get("name", "unknown")))
        name = str(item["name"])
        if name in names:
            raise ValueError("protected_name_duplicate")
        names.add(name)
        sha256, count = semantic_digest(path, pointers)
        semantic.append({"name": name, "value_count": count, "sha256": sha256})
    return {"schema": 2, "captured_at": time.time(), "files": rows, "json_values": semantic}


def compare(before: dict, after: dict) -> dict:
    left = {item["name"]: ("file", item) for item in before["files"]}
    right = {item["name"]: ("file", item) for item in after["files"]}
    left.update({item["name"]: ("json", item) for item in before.get("json_values", [])})
    right.update({item["name"]: ("json", item) for item in after.get("json_values", [])})
    names = sorted(set(left) | set(right))
    rows = []
    for name in names:
        old_pair, new_pair = left.get(name), right.get(name)
        old, new = old_pair[1] if old_pair else None, new_pair[1] if new_pair else None
        rows.append({"name": name, "present_before": old is not None, "present_after": new is not None,
                     "kind": old_pair[0] if old_pair else new_pair[0] if new_pair else "unknown",
                     "unchanged": old is not None and new is not None and old_pair[0] == new_pair[0]
                     and old["sha256"] == new["sha256"]
                     and old.get("bytes", old.get("value_count")) == new.get("bytes", new.get("value_count"))})
    return {"schema": 2, "passed": all(row["unchanged"] for row in rows), "objects": rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    snapshot = sub.add_parser("capture")
    snapshot.add_argument("--spec", type=Path, required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    diff = sub.add_parser("compare")
    diff.add_argument("--before", type=Path, required=True)
    diff.add_argument("--after", type=Path, required=True)
    diff.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "capture":
        result = capture(args.spec)
        code = 0
    else:
        result = compare(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
        code = 0 if result["passed"] else 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result.get("passed", True), "output": str(args.output)}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
