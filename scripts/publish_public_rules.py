#!/usr/bin/env python3
"""Build a deliberately small public rules repository from the private source.

The exporter is fail-closed: it copies an explicit allowlist, rewrites only the
known repository URLs, validates that every exported template reference exists,
and rejects credentials, private keys, symlinks and site-specific RFC1918
addresses.  It never edits the source tree or an existing output directory.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import tempfile
from pathlib import Path


SOURCE_REPOSITORY = "zhiwen1987/Jydn-openclash"
PUBLIC_REPOSITORY = "zhiwen1987/Jydn-openclash-rules"
SOURCE_RAW_PREFIX = (
    "https://raw.githubusercontent.com/"
    f"{SOURCE_REPOSITORY}/refs/heads/main/"
)
PUBLIC_RAW_PREFIX = (
    "https://raw.githubusercontent.com/"
    f"{PUBLIC_REPOSITORY}/refs/heads/main/"
)

# This is the public contract.  Adding a file requires code review and tests.
PUBLIC_TEMPLATE_RULES = frozenset(
    {
        "apple-ip-asn.yaml",
        "bank-cn.yaml",
        "cloud-drive-cn.yaml",
        "connectivity-check.yaml",
        "development.yaml",
        "direct.yaml",
        "google-ip-asn.yaml",
        "government-cn.yaml",
        "meta-ip-asn.yaml",
        "music-cn.yaml",
        "mygw.yaml",
        "netflix-ip-asn.yaml",
        "node-geo-check.yaml",
        "securities-cn.yaml",
        "singapore.yaml",
        "telegram-ip-asn.yaml",
        "webrtc-client.yaml",
    }
)
ADDITIONAL_PUBLIC_RULES = frozenset({"smarthome-direct.yaml"})

# The source embeds the production LAN prefix and router address.  The public
# repository gets an empty placeholder at the same URL; deployments inject the
# real rule through their authenticated local file provider.
SITE_LOCAL_TEMPLATE_RULES = frozenset({"webrtc-client.yaml"})

RULE_URL_RE = re.compile(
    re.escape(SOURCE_RAW_PREFIX) + r"rules/([A-Za-z0-9_.-]+\.yaml)"
)
PUBLIC_RULE_URL_RE = re.compile(
    re.escape(PUBLIC_RAW_PREFIX) + r"rules/([A-Za-z0-9_.-]+\.yaml)"
)
IPV4_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
CREDENTIAL_URL_RE = re.compile(r"https?://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
SENSITIVE_QUERY_RE = re.compile(
    r"https?://[^\s]+[?&](?:access_token|auth|key|password|secret|token)="
    r"[^\s&#;]+",
    re.IGNORECASE,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----", re.IGNORECASE
)
TOKEN_RE = re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}")
ALLOWED_GENERIC_PRIVATE_NETWORKS = {
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
}


class PublishError(RuntimeError):
    pass


def _regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise PublishError(f"required regular file missing: {path}")


def _validate_yaml_rule(path: Path, text: str) -> None:
    if text.count("payload:") != 1:
        raise PublishError(f"rule must have exactly one payload: {path.name}")
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line in {"payload:", "payload: []"} or line.startswith(("  - ", "- ")):
            continue
        raise PublishError(f"non-rule YAML content in {path.name}: {line[:80]}")


def _validate_no_secrets(path: Path, text: str) -> None:
    for label, pattern in (
        ("credential URL", CREDENTIAL_URL_RE),
        ("sensitive URL query", SENSITIVE_QUERY_RE),
        ("private key", PRIVATE_KEY_RE),
        ("GitHub token", TOKEN_RE),
    ):
        if pattern.search(text):
            raise PublishError(f"{label} found in public output: {path.name}")

    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            parsed = (
                ipaddress.ip_network(value, strict=False)
                if "/" in value
                else ipaddress.ip_address(value)
            )
        except ValueError:
            continue
        if not parsed.is_private and not parsed.is_loopback:
            continue
        if isinstance(parsed, ipaddress.IPv4Network) and parsed in ALLOWED_GENERIC_PRIVATE_NETWORKS:
            continue
        raise PublishError(
            f"site-specific private address found in public output: {path.name}"
        )


def _public_readme() -> str:
    return (
        "# Jydn OpenClash Public Rules\n\n"
        "This repository contains only the public OpenClash conversion template "
        "and domain/IP rule payloads exported from the private project. It "
        "contains no subscriptions, proxy nodes, credentials, internal "
        "operational records, or production databases. The public "
        "`webrtc-client.yaml` is deliberately an empty placeholder; each "
        "deployment injects its site-specific LAN rule from a local authenticated "
        "file provider.\n\n"
        "Files are generated by an allowlist publisher. Direct edits may be "
        "replaced by the next verified publication.\n"
    )


def _render_template(source: str) -> tuple[str, set[str]]:
    referenced = set(RULE_URL_RE.findall(source))
    unknown = referenced - PUBLIC_TEMPLATE_RULES
    missing = PUBLIC_TEMPLATE_RULES - referenced
    if unknown:
        raise PublishError("unapproved repository rules in template: " + ", ".join(sorted(unknown)))
    if missing:
        raise PublishError("approved repository rules missing from template: " + ", ".join(sorted(missing)))

    output: list[str] = []
    for line in source.splitlines():
        if "10.88.0." in line:
            output.append(
                "; WebRTC 站点级范围由部署侧本地 provider 注入；公开仓库不包含生产网段。"
            )
            continue
        output.append(line.replace(SOURCE_RAW_PREFIX, PUBLIC_RAW_PREFIX))
    rendered = "\n".join(output) + "\n"
    exported_refs = set(PUBLIC_RULE_URL_RE.findall(rendered))
    if exported_refs != PUBLIC_TEMPLATE_RULES:
        raise PublishError("exported template references do not match the public allowlist")
    if SOURCE_RAW_PREFIX in rendered:
        raise PublishError("private source reference remains in exported template")
    return rendered, exported_refs


def publish(source_root: Path, output: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    output = output.resolve()
    if output.exists():
        raise PublishError(f"output must not already exist: {output}")

    template_path = source_root / "metafenliu.ini"
    _regular_file(template_path)
    template, references = _render_template(template_path.read_text(encoding="utf-8"))

    all_rules = sorted(PUBLIC_TEMPLATE_RULES | ADDITIONAL_PUBLIC_RULES)
    staged_parent = output.parent
    staged_parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="public-rules-", dir=staged_parent))
    try:
        (stage / "rules").mkdir(mode=0o755)
        files: dict[str, str] = {
            "README.md": _public_readme(),
            "metafenliu.ini": template,
        }
        license_path = source_root / "LICENSE"
        if license_path.exists():
            _regular_file(license_path)
            files["LICENSE"] = license_path.read_text(encoding="utf-8")
        for name in all_rules:
            source = source_root / "rules" / name
            _regular_file(source)
            text = (
                "# Site-specific WebRTC matching is injected by a local provider.\n"
                "payload: []\n"
                if name in SITE_LOCAL_TEMPLATE_RULES
                else source.read_text(encoding="utf-8")
            )
            _validate_yaml_rule(source, text)
            files[f"rules/{name}"] = text.rstrip() + "\n"

        for relative, text in files.items():
            target = stage / relative
            _validate_no_secrets(target, text)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")

        actual = {
            path.relative_to(stage).as_posix()
            for path in stage.rglob("*")
            if path.is_file()
        }
        allowed = {"README.md", "metafenliu.ini"} | {
            f"rules/{name}" for name in all_rules
        }
        if "LICENSE" in files:
            allowed.add("LICENSE")
        if actual != allowed:
            raise PublishError("public output differs from its file allowlist")
        for name in references:
            if not (stage / "rules" / name).is_file():
                raise PublishError(f"template target is absent from public output: {name}")
        stage.replace(output)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return {
        "files": len(actual),
        "template_rules": len(references),
        "additional_rules": len(ADDITIONAL_PUBLIC_RULES),
        "site_local_rules_excluded": sorted(SITE_LOCAL_TEMPLATE_RULES),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = publish(args.source_root, args.output)
    print(
        "public rules ready: "
        f"files={result['files']} template_rules={result['template_rules']} "
        f"additional_rules={result['additional_rules']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
