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

RULES_MARKER = "; >>> custom rules injection point <<<"
GROUPS_MARKER = "; >>> custom groups injection point <<<"


def read_required(path: Path) -> str:
    if not path.is_file():
        raise RuntimeError(f"缺少必需文件：{path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8").strip()


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


def main() -> None:
    OUTPUT_FILE.write_text(build(), encoding="utf-8", newline="\n")
    print(f"Generated {OUTPUT_FILE.relative_to(ROOT)}")
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
