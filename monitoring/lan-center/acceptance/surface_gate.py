#!/usr/bin/env python3
"""Verify the unified surface without changing Docker or application state.

The Docker input is the JSON emitted by ``docker inspect``.  The report keeps
only public port facts and never copies environment variables or labels.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


class SurfaceFailure(AssertionError):
    pass


def docker_surface(document: object, container_name: str = "") -> dict:
    rows = document if isinstance(document, list) else [document]
    rows = [row for row in rows if isinstance(row, dict)]
    if container_name:
        rows = [row for row in rows if str(row.get("Name", "")).lstrip("/") == container_name]
    if len(rows) != 1:
        raise SurfaceFailure("target_container_not_unique")
    row = rows[0]
    host = row.get("HostConfig") if isinstance(row.get("HostConfig"), dict) else {}
    network = row.get("NetworkSettings") if isinstance(row.get("NetworkSettings"), dict) else {}
    configured = host.get("PortBindings") if isinstance(host.get("PortBindings"), dict) else {}
    effective = network.get("Ports") if isinstance(network.get("Ports"), dict) else {}
    bindings = []
    for source, mapping in (("configured", configured), ("effective", effective)):
        for container_port, targets in mapping.items():
            if not targets:
                continue
            for target in targets if isinstance(targets, list) else [targets]:
                target = target if isinstance(target, dict) else {}
                bindings.append({
                    "source": source,
                    "container_port": str(container_port),
                    "host_ip": str(target.get("HostIp", "")),
                    "host_port": str(target.get("HostPort", "")),
                })
    if any(item["container_port"] == "3001/tcp" or item["host_port"] == "3101" for item in bindings):
        raise SurfaceFailure("kuma_external_port_published")
    return {
        "container": str(row.get("Name", "")).lstrip("/"),
        "running": (row.get("State") or {}).get("Running") is True,
        "published_bindings": bindings,
        "kuma_external_port_published": False,
    }


def static_surface(paths: list[Path]) -> dict:
    checked = []
    patterns = {
        "kuma_iframe": re.compile(
            r"(?:<\s*iframe\b|createElement\s*\(\s*['\"]iframe|h\s*\(\s*['\"]iframe).{0,500}(?:kuma|3101|status-page)",
            re.I | re.S,
        ),
        "kuma_3101": re.compile(r"(?:https?://[^\s'\"]+)?[:/]3101(?:[/\s'\"]|$)", re.I),
        # User-controlled subscription/node/monitor names are rendered by the
        # same application.  Keep the whole surface on text/DOM construction
        # APIs instead of allowing a future feature to reintroduce HTML sinks.
        "unsafe_dom_html_sink": re.compile(
            r"(?:\.\s*(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\s*\.\s*write\s*\()",
            re.I,
        ),
    }
    for path in paths:
        if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
            raise SurfaceFailure("asset_invalid:" + path.name)
        text = path.read_text(encoding="utf-8")
        for label, pattern in patterns.items():
            if pattern.search(text):
                raise SurfaceFailure(f"forbidden_{label}:{path.name}")
        checked.append(path.name)
    return {
        "checked_assets": checked,
        "kuma_iframe": False,
        "kuma_3101_reference": False,
        "unsafe_dom_html_sink": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-inspect", type=Path, required=True)
    parser.add_argument("--container-name", default="")
    parser.add_argument("--asset", action="append", type=Path, default=[])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": 1}
    try:
        report["docker"] = docker_surface(json.loads(args.docker_inspect.read_text(encoding="utf-8")), args.container_name)
        report["static"] = static_surface(args.asset)
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["failure"] = str(error)[:240]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "report": str(args.report), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
