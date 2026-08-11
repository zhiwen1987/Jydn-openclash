#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUSTOM_DIR = ROOT / "custom"
OUTPUT_FILE = ROOT / "metafenliu.ini"
BASE_FILE = ROOT / "upstream" / "metafenliu.ini"

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
    return result + "\n"


def main() -> None:
    OUTPUT_FILE.write_text(build(), encoding="utf-8", newline="\n")
    print(f"Generated {OUTPUT_FILE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
