#!/usr/bin/env python3
"""Recompute local rule redundancy and test a hypothetical deletion set.

This tool is deliberately read-only.  It never rewrites rules.  The proposed
after-state exists only as bytes in memory and is used for size and routing
comparisons.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TEMPLATE = ROOT / "metafenliu.ini"
PRIVATE_RULE_FILES = {"webrtc-client.yaml"}
OUTPUT_JSON = ROOT / "docs/reports/rule-redundancy-inventory.json"
OPERATIONS_JSON = ROOT / "docs/reports/rule-redundancy-candidate-operations.json"
EVIDENCE_JSON = ROOT / "reports/rule-redundancy-plan-evidence-20261028.json"


@dataclass(frozen=True)
class Entry:
    path: str
    line: int
    scalar: str | None
    matcher_kind: str
    matcher_value: str | None
    raw_kind: str
    route: str | None = None
    template_line: int | None = None
    provider_order: int | None = None

    @property
    def public_scalar(self) -> str | None:
        if Path(self.path).name in PRIVATE_RULE_FILES:
            return None
        return self.scalar

    @property
    def static_domain(self) -> bool:
        return self.matcher_kind in {"exact", "suffix"}


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def input_commit() -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--",
         "rules", "custom", "metafenliu.ini"],
        text=True,
    ).strip()


def stable_id(entry: Entry) -> str:
    if Path(entry.path).name in PRIVATE_RULE_FILES:
        material = f"{entry.path}\0redacted-line\0{entry.line}"
    else:
        material = f"{entry.path}\0{entry.matcher_kind}\0{entry.scalar}"
    return "rule-" + sha256(material.encode("utf-8"))[:16]


def yaml_scalar(raw: str) -> str | None:
    match = re.match(r"^\s*-\s+(.+?)\s*$", raw)
    if not match:
        return None
    value = match.group(1).split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value.strip()


def parse_matcher(scalar: str) -> tuple[str, str | None, str]:
    value = scalar.strip().lower().rstrip(".")
    if value.startswith("+.") and "," not in value and "*" not in value:
        return "suffix", value[2:], "DOMAIN-SUFFIX"
    parts = [part.strip() for part in value.split(",")]
    if parts[0] in {
        "domain", "domain-suffix", "domain-keyword", "domain-wildcard",
        "domain-regex",
    }:
        if len(parts) != 2 or not parts[1]:
            return "unsupported", None, parts[0].upper()
        kind = {
            "domain": "exact",
            "domain-suffix": "suffix",
            "domain-keyword": "keyword",
            "domain-wildcard": "wildcard",
            "domain-regex": "regex",
        }[parts[0]]
        return kind, parts[1], parts[0].upper()
    # Historical domain providers use a single bare `*` label as a wildcard.
    # Multi-wildcard underscore service-discovery expressions are deliberately
    # left unsupported because their exact Mihomo semantics are not proven here.
    if ("," not in value and value.count("*") == 1
            and re.fullmatch(r"[a-z0-9][a-z0-9._*-]*", value)):
        return "wildcard", value, "DOMAIN-WILDCARD"
    if "," not in value and "*" not in value and re.fullmatch(
        r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", value
    ) and "." in value:
        return "exact", value, "DOMAIN"
    raw_kind = parts[0].upper() if parts and parts[0] else "UNKNOWN"
    return "unsupported", None, raw_kind


def parse_rule_file(path: Path) -> list[Entry]:
    entries: list[Entry] = []
    relative = path.relative_to(ROOT).as_posix()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        scalar = yaml_scalar(raw)
        if scalar is None:
            continue
        matcher_kind, matcher_value, raw_kind = parse_matcher(scalar)
        entries.append(Entry(relative, number, scalar, matcher_kind, matcher_value, raw_kind))
    return entries


def all_rule_entries() -> list[Entry]:
    entries: list[Entry] = []
    for path in sorted(RULES.glob("*.yaml"), key=lambda item: item.name):
        entries.extend(parse_rule_file(path))
    return entries


def inline_sources() -> dict[str, tuple[str, int]]:
    """Map generated inline rules back to reviewed repository sources."""
    result: dict[str, tuple[str, int]] = {}
    for relative in ("custom/rules.ini", "rules/smarthome-direct.yaml"):
        path = ROOT / relative
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if relative.endswith(".ini"):
                match = re.match(r"^ruleset=([^,]+),\[\](DOMAIN|DOMAIN-SUFFIX),(.+)$", raw)
                if not match:
                    continue
                key = f"{match.group(2).lower()}:{match.group(3).lower().rstrip('.')}"
            else:
                scalar = yaml_scalar(raw)
                if scalar is None:
                    continue
                kind, value, _ = parse_matcher(scalar)
                if kind not in {"exact", "suffix"}:
                    continue
                key = f"{'domain-suffix' if kind == 'suffix' else 'domain'}:{value}"
            result.setdefault(key, (relative, number))
    return result


def ordered_repository_entries() -> list[Entry]:
    """Return only statically understood inline/local entries in template order."""
    source_map = inline_sources()
    result: list[Entry] = []
    provider_order = 0
    for template_line, raw in enumerate(TEMPLATE.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.startswith("ruleset="):
            continue
        provider_order += 1
        target, spec = raw[len("ruleset="):].split(",", 1)
        inline = re.match(
            r"\[\](DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-WILDCARD|DOMAIN-REGEX),(.+)$",
            spec,
            re.IGNORECASE,
        )
        if inline:
            scalar = f"{inline.group(1).upper()},{inline.group(2)}"
            kind, value, raw_kind = parse_matcher(scalar)
            key = f"{inline.group(1).lower()}:{inline.group(2).lower().rstrip('.')}"
            path, line = source_map.get(key, ("metafenliu.ini", template_line))
            result.append(Entry(path, line, scalar, kind, value, raw_kind,
                                target, template_line, provider_order))
            continue
        local = re.search(r"/rules/([^,/?]+\.yaml)", spec)
        if not local:
            continue
        path = RULES / local.group(1)
        if not path.is_file():
            continue
        for entry in parse_rule_file(path):
            result.append(Entry(entry.path, entry.line, entry.scalar,
                                entry.matcher_kind, entry.matcher_value,
                                entry.raw_kind, target, template_line,
                                provider_order))
    return result


def covers(earlier: Entry, later: Entry) -> bool:
    if not earlier.static_domain or later.matcher_kind not in {"exact", "suffix", "wildcard"}:
        return False
    if earlier.matcher_kind == "exact":
        return later.matcher_kind == "exact" and earlier.matcher_value == later.matcher_value
    if later.matcher_kind == "exact":
        return later.matcher_value == earlier.matcher_value or bool(
            later.matcher_value and earlier.matcher_value
            and later.matcher_value.endswith("." + earlier.matcher_value)
        )
    if later.matcher_kind == "wildcard":
        # Only the reviewed single-label bare wildcard form reaches here.  A
        # fixed suffix still covers every possible expansion of that label.
        return bool(later.matcher_value and earlier.matcher_value and (
            later.matcher_value == earlier.matcher_value
            or later.matcher_value.endswith("." + earlier.matcher_value)
        ))
    return later.matcher_value == earlier.matcher_value or bool(
        later.matcher_value and earlier.matcher_value
        and later.matcher_value.endswith("." + earlier.matcher_value)
    )


def duplicate_candidates(ordered: list[Entry]) -> list[tuple[Entry, Entry]]:
    """Find exact textual duplicates where the later copy has the same route."""
    first: dict[str, Entry] = {}
    candidates: list[tuple[Entry, Entry]] = []
    for entry in ordered:
        if entry.scalar is None or entry.path == "metafenliu.ini":
            continue
        key = entry.scalar.lower()
        previous = first.get(key)
        if previous is None:
            first[key] = entry
        elif previous.route == entry.route:
            candidates.append((entry, previous))
    return candidates


def shadowed_entries(ordered: list[Entry]) -> list[tuple[Entry, Entry]]:
    shadowed: list[tuple[Entry, Entry]] = []
    earlier: list[Entry] = []
    for entry in ordered:
        if entry.matcher_kind in {"exact", "suffix", "wildcard"}:
            cover = next((item for item in earlier
                          if item.route == entry.route and covers(item, entry)), None)
            if cover is not None and entry.path != "metafenliu.ini":
                shadowed.append((entry, cover))
        if entry.static_domain:
            earlier.append(entry)
    return shadowed


def matcher_identity(entry: Entry) -> str | None:
    if entry.matcher_value is None:
        return None
    prefix = "+." if entry.matcher_kind == "suffix" else ""
    return prefix + entry.matcher_value


def decision_inventory(
    all_entries: list[Entry],
    duplicates: list[tuple[Entry, Entry]],
    shadows: list[tuple[Entry, Entry]],
) -> list[dict]:
    duplicate_keys = {(later.path, later.line) for later, _ in duplicates}
    candidate_map = {(later.path, later.line): earlier for later, earlier in shadows}
    route_map = {(entry.path, entry.line): entry for entry in ordered_repository_entries()
                 if entry.path != "metafenliu.ini"}
    rows: list[dict] = []
    for entry in all_entries:
        key = (entry.path, entry.line)
        ordered = route_map.get(key)
        row = {
            "id": stable_id(entry),
            "path": entry.path,
            "line": entry.line,
            "matcher_kind": entry.matcher_kind,
            "rule_type": entry.raw_kind,
            "route": ordered.route if ordered else None,
        }
        if entry.public_scalar is not None and entry.matcher_value is not None:
            row["entry"] = matcher_identity(entry)
        elif Path(entry.path).name in PRIVATE_RULE_FILES:
            row["entry_redacted"] = True
        if key in candidate_map:
            keep = candidate_map[key]
            exact = key in duplicate_keys
            row.update({
                "decision": "delete_candidate_full_template_only",
                "proof_kind": "exact_duplicate" if exact else "parent_covers_child",
                "reason": (
                    "identical matcher and same target are loaded earlier" if exact else
                    "an earlier same-target parent covers every match of this child"
                ),
                "keep_path": keep.path,
                "keep_line": keep.line,
                "keep_entry": matcher_identity(keep),
                "standalone_impact": (
                    "removal changes this provider's member list when consumed alone; "
                    "it also removes explicit ownership/catalog detail; the fixed "
                    "full-template equivalence does not cover that use"
                ),
            })
        elif entry.matcher_kind == "unsupported":
            row.update({
                "decision": "retain_unsupported_or_non_domain",
                "reason": "no equivalence claim for this rule type or condition",
            })
        else:
            row.update({
                "decision": "retain_nonredundant",
                "reason": "no earlier same-target static cover was proven",
            })
        rows.append(row)
    return rows


def remove_candidate_lines(candidates: list[tuple[Entry, Entry]]) -> tuple[dict[str, bytes], dict[str, bytes]]:
    grouped: dict[str, list[Entry]] = {}
    for later, _ in candidates:
        grouped.setdefault(later.path, []).append(later)
    before_files: dict[str, bytes] = {}
    after_files: dict[str, bytes] = {}
    for relative, file_candidates in grouped.items():
        before = (ROOT / relative).read_bytes()
        lines = before.splitlines(keepends=True)
        target_lines = {entry.line for entry in file_candidates}
        if len(target_lines) != len(file_candidates):
            raise RuntimeError("more than one candidate claims the same source line")
        for entry in file_candidates:
            current = yaml_scalar(lines[entry.line - 1].decode("utf-8"))
            if current != entry.scalar:
                raise RuntimeError(f"candidate precondition failed at {entry.path}:{entry.line}")
        before_files[relative] = before
        after_files[relative] = b"".join(
            line for number, line in enumerate(lines, 1) if number not in target_lines
        )
    return before_files, after_files


def gzip_size(raw: bytes) -> int:
    return len(gzip.compress(raw, compresslevel=9, mtime=0))


def size_evidence(
    after_files: dict[str, bytes], candidates: list[tuple[Entry, Entry]]
) -> dict:
    files = sorted(RULES.glob("*.yaml"), key=lambda item: item.name)
    before_raw = sum(len(path.read_bytes()) for path in files)
    before_gzip = sum(gzip_size(path.read_bytes()) for path in files)
    after_raw = sum(len(after_files.get(path.relative_to(ROOT).as_posix(), path.read_bytes()))
                    for path in files)
    after_gzip = sum(gzip_size(after_files.get(path.relative_to(ROOT).as_posix(), path.read_bytes()))
                     for path in files)
    per_file = {}
    for relative, after in sorted(after_files.items()):
        before = (ROOT / relative).read_bytes()
        per_file[relative] = {
            "before_bytes": len(before), "after_bytes": len(after),
            "saved_bytes": len(before) - len(after),
            "before_gzip_bytes": gzip_size(before),
            "after_gzip_bytes": gzip_size(after),
            "saved_gzip_bytes": gzip_size(before) - gzip_size(after),
        }
    matcher_bytes = sum(len((later.matcher_value or "").encode("utf-8"))
                        for later, _ in candidates)
    labels = sum(len((later.matcher_value or "").replace("*", "probe").split("."))
                 for later, _ in candidates)
    simple_low = matcher_bytes + len(candidates) * 32
    simple_high = matcher_bytes + len(candidates) * 96 + labels * 48
    return {
        "definition": "UTF-8 file bytes and sum of per-file gzip-9 bytes with mtime=0",
        "candidate_files": per_file,
        "all_rule_yaml": {
            "before_bytes": before_raw, "after_bytes": after_raw,
            "saved_bytes": before_raw - after_raw,
            "before_gzip_bytes": before_gzip, "after_gzip_bytes": after_gzip,
            "saved_gzip_bytes": before_gzip - after_gzip,
        },
        "loaded_memory": {
            "measured": False,
            "reason": "no same-version Mihomo binary was supplied; file bytes are not RSS",
            "model_inputs": {
                "candidate_entries": len(candidates),
                "matcher_utf8_bytes": matcher_bytes,
                "domain_labels": labels,
            },
            "illustrative_model": (
                "matcher bytes + entries * (32..96 bytes) + labels * (0..48 bytes)"
            ),
            "illustrative_model_bytes": {"low": simple_low, "high": simple_high},
            "planning_range_bytes": {"low": 0, "high": 96 * 1024},
            "planning_range_caveat": (
                "0 allows parser/provider deduplication or allocator rounding; 96 KiB rounds "
                "the illustrative high scenario upward. This is not a measured Mihomo range."
            ),
        },
    }


def simulator_comparison(after_files: dict[str, bytes], candidates: list[tuple[Entry, Entry]]) -> dict:
    tools = str(ROOT / "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import build_routing_samples as builder
    import simulate_routing as simulator

    rows = [json.loads(line) for line in simulator.CORPUS.read_text(encoding="utf-8").splitlines() if line]
    manifest = json.loads(simulator.MANIFEST.read_text(encoding="utf-8"))
    if sha256(simulator.CORPUS.read_bytes()) != manifest["corpus_sha256"]:
        raise RuntimeError("corpus hash mismatch")
    loaded = simulator.verified_sources(manifest)
    for row in rows:
        calculated = sorted(name for name, rule in loaded.items()
                            if builder.matches(rule, row["domain"]))
        if calculated != row["memberships"]:
            raise RuntimeError("materialized membership mismatch: " + row["domain"])
    rules = simulator.ordered_rules()
    before_cache: dict = {}
    after_cache = {}
    for relative, raw in after_files.items():
        after_rule, unsupported = builder.patterns(raw.decode("utf-8"))
        if unsupported:
            raise RuntimeError("hypothetical provider has unsupported domain entries: " + relative)
        after_cache[("local-domain", Path(relative).name)] = after_rule
    compare_fields = ("actual", "rule_line", "rule_kind", "rule_source")
    changes = {field: 0 for field in compare_fields}
    for row in rows:
        before = simulator.simulate(row, rules, before_cache)
        after = simulator.simulate(row, rules, after_cache)
        for field in compare_fields:
            changes[field] += before[field] != after[field]

    witness_count = 0
    witness_changes = {field: 0 for field in compare_fields}
    for later, keep in candidates:
        value = later.matcher_value
        domains = [value]
        if later.matcher_kind == "suffix":
            domains.append("redundancy-probe." + value)
        elif later.matcher_kind == "wildcard":
            domains = [value.replace("*", "redundancy-probe")]
        for domain in domains:
            row = {"domain": domain, "memberships": []}
            before = simulator.simulate(row, rules, before_cache)
            after = simulator.simulate(row, rules, after_cache)
            for field in compare_fields:
                witness_changes[field] += before[field] != after[field]
            if any(before[field] != after[field] for field in compare_fields):
                raise RuntimeError("candidate witness changed: " + domain)
            witness_count += 1
    return {
        "manifest_pinned_corpus": {
            "samples": len(rows),
            "corpus_sha256": manifest["corpus_sha256"],
            "compared_fields": list(compare_fields),
            "changes_by_field": changes,
        },
        "candidate_witnesses": {
            "samples": witness_count,
            "source": "root plus one synthetic subdomain for every suffix candidate",
            "compared_fields": list(compare_fields),
            "changes_by_field": witness_changes,
        },
        "boundary": (
            "domain stage only; fixed public snapshots plus candidate-derived witnesses; "
            "no IP, IPv6, port, process, DNS, node selection, or live-device behavior"
        ),
    }


def candidate_operations(
    candidates: list[tuple[Entry, Entry]],
    duplicates: list[tuple[Entry, Entry]],
    before_files: dict[str, bytes],
    after_files: dict[str, bytes],
) -> dict:
    duplicate_keys = {(later.path, later.line) for later, _ in duplicates}
    operations = []
    for number, (later, keep) in enumerate(candidates, 1):
        operations.append({
            "sequence": number,
            "id": stable_id(later),
            "operation": "remove_yaml_payload_scalar",
            "path": later.path,
            "expected_line": later.line,
            "expected_scalar": later.scalar,
            "expected_route": later.route,
            "proof_kind": (
                "exact_duplicate" if (later.path, later.line) in duplicate_keys
                else "parent_covers_child"
            ),
            "keep_path": keep.path,
            "keep_line": keep.line,
            "keep_scalar": keep.scalar,
            "proof": (
                "same route; the keep rule precedes and fully covers the delete rule "
                "in fixed template/provider order"
            ),
            "keep_provider_order": keep.provider_order,
            "delete_provider_order": later.provider_order,
        })
    return {
        "schema": 1,
        "proposal_only": True,
        "apply_automatically": False,
        "scope": "full generated metafenliu template only",
        "standalone_consumer_risk": (
            "removing entries changes each affected provider's explicit member list when "
            "consumed alone; inventory consumers before any implementation PR"
        ),
        "precondition": {
            "input_commit": input_commit(),
            "files": {path: sha256(raw) for path, raw in sorted(before_files.items())},
        },
        "hypothetical_after_sha256": {
            path: sha256(raw) for path, raw in sorted(after_files.items())
        },
        "operations": operations,
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")


def previous_counts() -> dict:
    result = {}
    for name, path in {
        "duplicates": ROOT / "docs/audits/rule-quality-duplicates.csv",
        "shadowing": ROOT / "docs/audits/rule-quality-shadowing.csv",
    }.items():
        with path.open(encoding="utf-8", newline="") as stream:
            result[name] = sum(1 for _ in csv.DictReader(stream))
    return result


def run(write: bool, with_simulator: bool) -> dict:
    entries = all_rule_entries()
    ordered = ordered_repository_entries()
    duplicates = duplicate_candidates(ordered)
    shadows = shadowed_entries(ordered)
    candidates = shadows
    inventory = decision_inventory(entries, duplicates, shadows)
    before_files, after_files = remove_candidate_lines(candidates)
    previous = previous_counts()
    decision_counts: dict[str, int] = {}
    for row in inventory:
        decision_counts[row["decision"]] = decision_counts.get(row["decision"], 0) + 1
    evidence = {
        "schema": 1,
        "proposal_only": True,
        "inputs": {
            "input_commit": input_commit(),
            "template_sha256": sha256(TEMPLATE.read_bytes()),
            "rules_tree_files": len(list(RULES.glob("*.yaml"))),
            "rules_tree_sha256": sha256(b"".join(
                path.name.encode("utf-8") + b"\0" + path.read_bytes()
                for path in sorted(RULES.glob("*.yaml"), key=lambda item: item.name)
            )),
        },
        "recomputed": {
            "rule_entries": len(entries),
            "domain_matchers": sum(entry.matcher_kind != "unsupported" for entry in entries),
            "duplicate_copies": len(duplicates),
            "static_shadowed": len(shadows),
            "previous_audit": previous,
            "previous_counts_still_match": (
                previous == {"duplicates": len(duplicates), "shadowing": len(shadows)}
            ),
            "decision_counts": decision_counts,
        },
        "sizes": size_evidence(after_files, candidates),
    }
    if with_simulator:
        evidence["simulation"] = simulator_comparison(after_files, candidates)
    operations = candidate_operations(
        candidates, duplicates, before_files, after_files
    )
    if write:
        write_json(OUTPUT_JSON, {
            "schema": 1,
            "privacy": "private complex rule values are intentionally omitted",
            "counts": evidence["recomputed"],
            "entries": inventory,
        })
        write_json(OPERATIONS_JSON, operations)
        write_json(EVIDENCE_JSON, evidence)
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write proposal evidence only")
    parser.add_argument("--with-simulator", action="store_true",
                        help="verify manifest-pinned before/after routing")
    args = parser.parse_args()
    run(args.write, args.with_simulator)


if __name__ == "__main__":
    main()
