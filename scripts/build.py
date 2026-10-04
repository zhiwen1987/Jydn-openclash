#!/usr/bin/env python3
import json
from pathlib import Path

from group_catalog import (
    BUSINESS_BUILTIN_CHOICES,
    BUSINESS_PROXY_GROUP_CHOICES,
    BUSINESS_STRATEGY_CHOICES,
    BUSINESS_STRATEGY_GROUPS,
    DASHBOARD_PROXY_GROUP_ORDER,
)


ROOT = Path(__file__).resolve().parents[1]
CUSTOM_DIR = ROOT / "custom"
OUTPUT_FILE = ROOT / "metafenliu.ini"
BASE_FILE = ROOT / "upstream" / "metafenliu.ini"
RUNTIME_CATALOG_FILE = ROOT / "modules" / "openclash-business-group-catalog.json"
SMARTHOME_RULE_FILE = ROOT / "rules" / "smarthome-direct.yaml"
DNS_OVERRIDE_FILE = ROOT / "modules" / "openclash-dns-privacy-override.yaml"

RULES_MARKER = "; >>> custom rules injection point <<<"
GROUPS_MARKER = "; >>> custom groups injection point <<<"
SMARTHOME_RULES_MARKER = "; >>> generated smarthome rules start <<<"
SMARTHOME_RULES_END_MARKER = "; <<< generated smarthome rules end >>>"
SMARTHOME_DNS_FILTER_MARKER = "; >>> generated smarthome dns-filter entries start <<<"
SMARTHOME_DNS_FILTER_END_MARKER = "; <<< generated smarthome dns-filter entries end >>>"
SMARTHOME_DNS_POLICY_MARKER = "; >>> generated smarthome dns-policy entries start <<<"
SMARTHOME_DNS_POLICY_END_MARKER = "; <<< generated smarthome dns-policy entries end >>>"

# 中国大陆公共 DoH：智能家居域名级直连解析与 direct-nameserver 保持一致。
DIRECT_DOH_SERVERS = (
    "https://223.5.5.5/dns-query#DIRECT",
    "https://120.53.53.53/dns-query#DIRECT",
)


def read_required(path: Path) -> str:
    if not path.is_file():
        raise RuntimeError(f"缺少必需文件：{path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8").strip()


def load_smarthome_domains() -> list[str]:
    """Parse rules/smarthome-direct.yaml payload into strict '+.domain' entries.

    Raises RuntimeError for empty lists, invalid suffixes, or duplicate domains.
    Returns bare domains such as 'tuya.com'.
    """
    raw = read_required(SMARTHOME_RULE_FILE)
    if raw.count("payload:") != 1:
        raise RuntimeError("智能家居清单必须恰好包含一个 payload 节")

    domains: list[str] = []
    for line in raw.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or entry.startswith("payload:"):
            continue
        if not entry.startswith("- '+."):
            raise RuntimeError(f"智能家居清单仅支持严格 '+.' 后缀：{entry}")
        domain = entry[len("- '+."):].strip().strip("'")
        if not domain or any(ch in domain for ch in "/*?"):
            raise RuntimeError(f"非法智能家居域名：{domain}")
        domains.append(domain)
    # 空清单视为未启用智能家居例外：生成空块，属于默认行为。
    seen: set[str] = set()
    for domain in domains:
        if domain in seen:
            raise RuntimeError(f"智能家居域名重复：{domain}")
        seen.add(domain)
    return domains


def smarthome_rule_block() -> str:
    return "\n".join(
        f"ruleset=DIRECT,[]DOMAIN-SUFFIX,{domain}"
        for domain in load_smarthome_domains()
    )


def smarthome_dns_blocks() -> tuple[str, str]:
    """Return (fake-ip-filter real-ip entries, nameserver-policy entries)."""
    domains = load_smarthome_domains()
    filter_lines = [
        f"    - DOMAIN-SUFFIX,{domain},real-ip"
        for domain in domains
    ]
    policy_lines = [
        f"    \"DOMAIN-SUFFIX,{domain}\": {server}"
        for domain in domains
        for server in DIRECT_DOH_SERVERS
    ]
    return "\n".join(filter_lines), "\n".join(policy_lines)


def insert_between_markers(text: str, start_marker: str, end_marker: str, label: str, block: str) -> str:
    """Replace content between start/end markers, preserving the markers.

    Missing or duplicate markers are fatal so two different copies can never be
    generated from the same domain list.
    """
    start_count = text.count(start_marker)
    end_count = text.count(end_marker)
    if start_count != 1 or end_count != 1:
        raise RuntimeError(f"{label} 标记数量错误：start={start_count} end={end_count}")
    pre, sep = text.split(start_marker, 1)
    _, tail = sep.split(end_marker, 1)
    return pre + start_marker + "\n" + block + "\n" + end_marker + tail


def insert_after_marker(text: str, marker: str, label: str, block: str) -> str:
    count = text.count(marker)
    if count != 1:
        raise RuntimeError(f"{label} 插入标记应出现 1 次，实际为 {count} 次：{marker}")

    insertion = f"\n; >>> generated {label} start <<<\n{block}\n; <<< generated {label} end <<<"
    return text.replace(marker, marker + insertion, 1)


def ordered_unique(values: list[str] | tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys(values))


def order_business_proxy_choices(text: str) -> str:
    """Keep each default first, then apply one consistent local-network order."""
    business_groups = set(BUSINESS_STRATEGY_GROUPS)
    standard_choices = set(BUSINESS_STRATEGY_CHOICES)
    found: set[str] = set()
    output: list[str] = []

    for line in text.splitlines():
        if not line.startswith("custom_proxy_group="):
            output.append(line)
            continue

        key, definition = line.split("=", 1)
        fields = definition.split("`")
        name = fields[0].strip()
        if name not in business_groups:
            output.append(line)
            continue

        found.add(name)
        if len(fields) < 3 or fields[1] != "select":
            raise RuntimeError(f"业务策略组格式错误：{name}")

        existing_choices = [
            field[2:].strip() for field in fields[2:] if field.startswith("[]")
        ]
        non_choice_fields = [field for field in fields[2:] if not field.startswith("[]")]
        if not existing_choices:
            raise RuntimeError(f"业务策略组没有默认选项：{name}")

        default_choice = existing_choices[0]
        related_choices = [
            choice
            for choice in existing_choices[1:]
            if choice not in standard_choices and choice != name
        ]
        ordered_choices = ordered_unique(
            [default_choice]
            + list(BUSINESS_BUILTIN_CHOICES)
            + related_choices
            + list(BUSINESS_PROXY_GROUP_CHOICES)
        )
        rebuilt = "`".join(
            [fields[0], fields[1]]
            + [f"[]{choice}" for choice in ordered_choices]
            + non_choice_fields
        )
        output.append(f"{key}={rebuilt}")

    missing = business_groups - found
    if missing:
        raise RuntimeError("缺少业务策略组：" + ", ".join(sorted(missing)))
    return "\n".join(output)


def build() -> str:
    result = read_required(BASE_FILE)
    result = insert_between_markers(
        result,
        SMARTHOME_RULES_MARKER,
        SMARTHOME_RULES_END_MARKER,
        "智能家居规则",
        smarthome_rule_block(),
    )
    result = insert_after_marker(
        result,
        RULES_MARKER,
        "custom rules",
        read_required(CUSTOM_DIR / "rules.ini"),
    )
    result = insert_after_marker(
        result,
        GROUPS_MARKER,
        "custom groups",
        read_required(CUSTOM_DIR / "groups.ini"),
    )
    result = order_business_proxy_choices(result)
    return result + "\n"


def write_dns_override() -> None:
    if not DNS_OVERRIDE_FILE.is_file():
        raise RuntimeError(f"缺少 DNS 覆写模块：{DNS_OVERRIDE_FILE.relative_to(ROOT)}")
    text = DNS_OVERRIDE_FILE.read_text(encoding="utf-8")
    filter_block, policy_block = smarthome_dns_blocks()
    text = insert_between_markers(
        text,
        SMARTHOME_DNS_FILTER_MARKER,
        SMARTHOME_DNS_FILTER_END_MARKER,
        "智能家居 fake-ip real-ip",
        filter_block,
    )
    text = insert_between_markers(
        text,
        SMARTHOME_DNS_POLICY_MARKER,
        SMARTHOME_DNS_POLICY_END_MARKER,
        "智能家居 nameserver-policy",
        policy_block,
    )
    DNS_OVERRIDE_FILE.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    OUTPUT_FILE.write_text(build(), encoding="utf-8", newline="\n")
    print(f"Generated {OUTPUT_FILE.relative_to(ROOT)}")
    write_dns_override()
    print(f"Updated {DNS_OVERRIDE_FILE.relative_to(ROOT)}")
    runtime_catalog = {
        "business_groups": BUSINESS_STRATEGY_GROUPS,
        "proxy_choices": BUSINESS_PROXY_GROUP_CHOICES,
        "always_choices": BUSINESS_BUILTIN_CHOICES,
        "dashboard_group_order": DASHBOARD_PROXY_GROUP_ORDER,
    }
    RUNTIME_CATALOG_FILE.write_text(
        json.dumps(runtime_catalog, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Generated {RUNTIME_CATALOG_FILE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
