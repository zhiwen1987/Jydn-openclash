#!/usr/bin/env python3
"""Verify named D12 prerequisite tests, not product lifecycle acceptance."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import re
import subprocess


class Rejected(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Rejected(reason)


def expected_tests(raw):
    tree = ast.parse(raw.decode("utf-8"))
    names = set()
    for item in tree.body:
        if not isinstance(item, ast.ClassDef):
            continue
        if not any(isinstance(base, ast.Attribute) and base.attr == "TestCase"
                   and isinstance(base.value, ast.Name) and base.value.id == "unittest"
                   for base in item.bases):
            continue
        for method in item.body:
            if isinstance(method, ast.FunctionDef) and method.name.startswith("test_"):
                name = item.name + "." + method.name
                require(name not in names, "duplicate-source-test")
                names.add(name)
    require(bool(names), "empty-source-tests")
    return names


def verify_transcript(raw, source, suite):
    require(suite in ("lease", "feed"), "suite")
    require(len(raw) <= 1024 * 1024 and b"\x1b" not in raw, "log-size-or-escape")
    expected = expected_tests(source)
    seen = set()
    summaries, success, markers = [], 0, 0
    count = len(expected)
    marker = (f"D12_{suite.upper()}_TESTS=PASS tests={count} passed={count} skipped=0 "
              "real_linux=true helper_uid=10001 helper_capabilities=none")
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line.strip():
            continue
        test = re.fullmatch(r"(test_[a-zA-Z0-9_]+) \(__main__\.([a-zA-Z0-9_]+)\.(test_[a-zA-Z0-9_]+)\) \.\.\. ok", line)
        if test:
            first, cls, method = test.groups()
            name = cls + "." + method
            require(first == method and name in expected and name not in seen, "named-test")
            seen.add(name)
        elif re.fullmatch(r"-{5,}", line):
            continue
        elif (summary := re.fullmatch(r"Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s", line)):
            summaries.append(int(summary.group(1)))
        elif line == "OK":
            success += 1
        elif line == marker:
            markers += 1
        else:
            raise Rejected("unexpected-transcript-line")
    require(seen == expected, "missing-named-test")
    require(summaries == [count] and success == 1 and markers == 1, "summary")
    pairs = "\n".join(sorted(seen)) + "\n"
    return {"suite": suite, "tests": count, "passed": count, "skipped": 0,
            "namedTestsSHA256": hashlib.sha256(pairs.encode()).hexdigest(),
            "transcriptSHA256": hashlib.sha256(raw).hexdigest(),
            "testSourceSHA256": hashlib.sha256(source).hexdigest(), "realLinux": True,
            "helperUID": 10001, "helperCapabilities": "none"}


def verify_cleanup(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-cleanup-field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    expected = {"schema": "chengwang.product-lifecycle-preflight-cleanup/v1",
                "privateTreeRemoved": True, "testExitCode": 0,
                "hostTmpTouched": False, "parentMountNamespaceChanged": False,
                "production": False, "authorization": "BLOCKED", "deviceActionsExecuted": False}
    require(type(value) is dict and set(value) == set(expected), "cleanup-fields")
    require(all(type(value[key]) is type(want) and value[key] == want
                for key, want in expected.items()), "cleanup-value")
    return {"sha256": hashlib.sha256(raw).hexdigest(), **value}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    root, evidence = pathlib.Path(args.source_root), pathlib.Path(args.evidence_dir)
    require(re.fullmatch(r"[a-f0-9]{40}", args.source_commit), "commit")
    require(root.is_absolute() and root.resolve() == root and evidence.is_absolute()
            and evidence.resolve() == evidence, "paths")
    git = ["/usr/bin/git", "-c", "safe.directory=" + str(root), "-C", str(root)]
    actual = subprocess.check_output(git + ["rev-parse", "HEAD"], timeout=5).decode().strip()
    require(actual == args.source_commit, "head")
    base = "chengwang/deploy/product-candidate/"
    paths = [base + name for name in ("fixture_lease.py", "test_fixture_lease.py",
             "fixture_feed.py", "test_fixture_feed.py", "check_lifecycle_preflight.py",
             "test_check_lifecycle_preflight.py")]
    paths += ["chengwang/tools/image-binding/scripts/" + name for name in
              ("run-lifecycle-fixture-preflight.sh", "run-linux-ci.sh")]
    sources = []
    for name in paths:
        path = root / name
        require(path.is_file() and not path.is_symlink(), "source-file")
        raw = path.read_bytes()
        committed = subprocess.check_output(git + ["cat-file", "blob", args.source_commit + ":" + name], timeout=5)
        require(raw == committed, "source-bytes")
        sources.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest()})
    suites = []
    for name in ("lease", "feed"):
        suites.append(verify_transcript((evidence / ("product-lifecycle-" + name + "-tests.log")).read_bytes(),
                      (root / base / ("test_fixture_" + name + ".py")).read_bytes(), name))
    cleanup = verify_cleanup((evidence / "product-lifecycle-cleanup.json").read_bytes())
    report = {"schema": "chengwang.product-lifecycle-preflight/v1", "outcome": "PASS",
              "sourceCommit": args.source_commit, "sources": sources, "suites": suites,
              "cleanup": cleanup,
              "authorization": "BLOCKED", "production": False, "deviceActionsExecuted": False,
              "actualProductLifecycleProven": False, "productImageFaultInjectionProven": False,
              "productAutomaticRefreshProven": False, "fixturePrerequisitesOnly": True}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (Rejected, ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit("D12_PREFLIGHT_CHECK=FAIL") from None
