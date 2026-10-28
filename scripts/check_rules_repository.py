"""Check the rules/template repository boundary without external dependencies."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {
    "build.py", "validate.py", "group_catalog.py", "strict_catalog.py",
    "publish_public_rules.py", "test_publish_public_rules.py", "check_rules_repository.py",
    "patch_runtime_groups.rb", "test_patch_runtime_groups.rb", "jydn_group_filter_hook.sh",
    "routing_controls.rb", "test_routing_controls.rb", "jydn_routing_controls_hook.sh",
    "strict_custom.rb", "test_strict_custom.rb", "jydn_strict_custom_hook.sh",
}

def main():
    forbidden = ["installer", "monitoring", "AI_HANDOFF.md", "START_HERE.md", "docs/handoff"]
    for name in forbidden:
        if (ROOT / name).exists():
            raise RuntimeError("center content in rules repository: " + name)
    actual = {p.name for p in (ROOT / "scripts").iterdir() if p.is_file()}
    if actual != SCRIPTS:
        raise RuntimeError("unexpected scripts: " + repr(sorted(actual ^ SCRIPTS)))
    workflows = {p.name for p in (ROOT / ".github/workflows").glob("*.yml")}
    if workflows != {"pr-check.yml", "sync.yml", "publish-public-rules.yml"}:
        raise RuntimeError("unexpected workflow ownership")
    for p in (ROOT / ".github/workflows").glob("*.yml"):
        text = p.read_text(encoding="utf-8")
        if "monitoring/" in text or "installer/" in text:
            raise RuntimeError("workflow depends on removed center code: " + p.name)
        for name in re.findall(r"scripts/[A-Za-z0-9_.-]+", text):
            if not (ROOT / name).is_file():
                raise RuntimeError("workflow references missing script: " + name)
    sync = (ROOT / ".github/workflows/sync.yml").read_text(encoding="utf-8")
    publish = (ROOT / ".github/workflows/publish-public-rules.yml").read_text(encoding="utf-8")
    if not sync.startswith("name: Build OpenClash Template\n"):
        raise RuntimeError("automatic publisher event binding changed")
    if 'workflows: ["Build OpenClash Template"]' not in publish:
        raise RuntimeError("publisher no longer listens to template build")
    if "contents: write" not in sync or "RULES_PUBLISH_SSH_KEY" not in publish:
        raise RuntimeError("automatic update capability removed")
    print(json.dumps({"rules_only": True, "scripts": len(actual), "workflows": len(workflows),
        "removed_center_roots_absent": True, "automatic_update_binding_preserved": True}))

if __name__ == "__main__":
    main()
