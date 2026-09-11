#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "metafenliu.ini"
BASE = ROOT / "upstream" / "metafenliu.ini"
OVERWRITE = ROOT / "modules" / "openclash-dns-privacy-override.yaml"
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
REQUIRED_URL_TEST_GROUPS = {
    "♻️ 自动选择",
    "🛟 稳定自动",
    "🇭🇰 HK",
    "🇹🇼 TW",
    "🇯🇵 JP",
    "🇸🇬 SG",
    "🇺🇸 US",
    "🧊 冷门节点",
}


def active_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]


def validate_config(errors: list[str]) -> None:
    text = CONFIG.read_text(encoding="utf-8")
    lines = active_lines(text)
    group_lines = [line for line in lines if line.startswith("custom_proxy_group=")]
    rule_lines = [line for line in lines if line.startswith("ruleset=")]

    groups: dict[str, str] = {}
    for line in group_lines:
        definition = line.split("=", 1)[1]
        fields = definition.split("`")
        if len(fields) < 2:
            errors.append(f"策略组格式错误：{line}")
            continue
        name, group_type = fields[0].strip(), fields[1].strip()
        if name in groups:
            errors.append(f"策略组重复定义：{name}")
        groups[name] = group_type

    for line in rule_lines:
        target = line.split("=", 1)[1].split(",", 1)[0].strip()
        if target not in BUILTIN_POLICIES and target not in groups:
            errors.append(f"规则引用了不存在的策略组：{target}")

    group_reference = re.compile(r"`\[\]([^`]+)")
    for line in group_lines:
        owner = line.split("=", 1)[1].split("`", 1)[0].strip()
        for target in group_reference.findall(line):
            target = target.strip()
            if target not in BUILTIN_POLICIES and target not in groups:
                errors.append(f"策略组 {owner} 引用了不存在的策略：{target}")

    for name in sorted(REQUIRED_URL_TEST_GROUPS):
        if name not in groups:
            errors.append(f"缺少自动测速组：{name}")
            continue
        if groups[name] != "url-test":
            errors.append(f"{name} 必须是 url-test，当前为 {groups[name]}")
            continue
        line = next(
            item for item in group_lines if item.startswith(f"custom_proxy_group={name}`")
        )
        fields = line.split("`")
        if len(fields) < 5 or "https://cp.cloudflare.com/generate_204" not in fields:
            errors.append(f"{name} 必须使用 Cloudflare HTTPS 测速地址")
        if not fields[-1].endswith("120,,10"):
            errors.append(f"{name} 必须使用 120 秒间隔和 10 ms 容差")

    stable_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🛟 稳定自动`")),
        None,
    )
    if stable_line is not None:
        if "`[]♻️ 自动选择`" not in stable_line:
            errors.append("稳定自动组必须包含自动选择组作为非 DIRECT 兜底")
        if "CUCM|专线.*流媒体" not in stable_line:
            errors.append("稳定自动组缺少稳定线路筛选条件")

    privacy_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🔒 隐私代理`")),
        None,
    )
    if privacy_line is None:
        errors.append("缺少隐私代理策略组")
    else:
        if groups.get("🔒 隐私代理") != "select":
            errors.append("隐私代理必须是 select 策略组")
        if "`[]🛟 稳定自动`[]♻️ 自动选择`" not in privacy_line:
            errors.append("隐私代理必须优先稳定自动组，并保留自动选择组")
        if not privacy_line.endswith("`.*"):
            errors.append("隐私代理必须直接包含全部物理节点")
        if "[]DIRECT" in privacy_line:
            errors.append("隐私代理禁止包含 DIRECT")

    if "ruleset=🌐 Default,[]GEOSITE,geolocation-!cn" not in lines:
        errors.append("缺少 GEOSITE,geolocation-!cn 海外域名规则")
    if "ruleset=DIRECT,[]GEOSITE,cn" not in lines:
        errors.append("缺少 GEOSITE,cn 国内直连规则")
    if "ruleset=DIRECT,[]GEOIP,cn,no-resolve" not in lines:
        errors.append("缺少 GEOIP,cn 国内直连规则")

    overseas = lines.index("ruleset=🌐 Default,[]GEOSITE,geolocation-!cn")
    china = lines.index("ruleset=DIRECT,[]GEOSITE,cn")
    final = lines.index("ruleset=🐟 漏网之鱼,[]FINAL")
    if not overseas < china < final:
        errors.append("规则顺序应为 geolocation-!cn → GEOSITE,cn → FINAL")

    if "zhiwen1987/openclash-rules" in text:
        errors.append("生成配置仍包含旧仓库 openclash-rules 地址")
    if "Bloomberg-zhong/openclash-rules" in text:
        errors.append("生成配置仍包含外部 singapore.yaml 地址")


def validate_base(errors: list[str]) -> None:
    text = BASE.read_text(encoding="utf-8")
    for marker in (
        "; >>> custom rules injection point <<<",
        "; >>> custom groups injection point <<<",
    ):
        count = text.count(marker)
        if count != 1:
            errors.append(f"基础模板标记数量错误（{count}）：{marker}")


def validate_rule_files(errors: list[str]) -> None:
    for path in sorted((ROOT / "rules").glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if not re.search(r"(?m)^payload:\s*$", text):
            errors.append(f"{path.relative_to(ROOT)} 缺少 payload:")
        entries = [
            match.group(1).strip()
            for match in re.finditer(r"(?m)^\s*-\s+(.+?)\s*$", text)
        ]
        duplicates = sorted({entry for entry in entries if entries.count(entry) > 1})
        if duplicates:
            errors.append(
                f"{path.relative_to(ROOT)} 存在重复条目：{', '.join(duplicates)}"
            )


def validate_overwrite(errors: list[str]) -> None:
    text = OVERWRITE.read_text(encoding="utf-8")
    required = (
        "<proxy-groups>*:",
        "type: url-test",
        "interval: 120",
        "tolerance: 10",
        "timeout: 5000",
        "max-failed-times: 2",
        "expected-status: 204",
    )
    for marker in required:
        if marker not in text:
            errors.append(f"覆写模块缺少自动组健康检查设置：{marker}")


def main() -> None:
    errors: list[str] = []
    validate_base(errors)
    validate_config(errors)
    validate_rule_files(errors)
    validate_overwrite(errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)
    print("Validation passed: groups, references, rule order, URL tests, overwrite, and rule files")


if __name__ == "__main__":
    main()
