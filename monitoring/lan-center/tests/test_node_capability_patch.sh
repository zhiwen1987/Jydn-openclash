#!/bin/sh
set -eu

repo_root="$(cd -- "$(dirname "$0")/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

cat > "$work/config.yaml" <<'EOF'
proxy-providers:
  provider-a:
    type: http
    url: https://example.invalid/provider.yaml
proxy-groups:
  - name: Existing
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,Existing
EOF

cat > "$work/auth.yaml" <<'EOF'
username: probe
password: test-only
group: 🧪 节点能力检测
listener: node-capability-probe
listen: 10.88.0.254
port: 7895
EOF

ruby "$repo_root/scripts/patch_node_capability_probe.rb" "$work/config.yaml" "$work/auth.yaml"
ruby "$repo_root/scripts/patch_node_capability_probe.rb" "$work/config.yaml" "$work/auth.yaml"

ruby -ryaml -e '
  config = YAML.unsafe_load_file(ARGV[0])
  groups = config.fetch("proxy-groups").select { |item| item["name"] == "🧪 节点能力检测" }
  listeners = config.fetch("listeners").select { |item| item["name"] == "node-capability-probe" }
  raise "group is not idempotent" unless groups.length == 1
  raise "listener is not idempotent" unless listeners.length == 1
  raise "provider missing" unless groups.first.fetch("use") == ["provider-a"]
  raise "listener is not isolated" unless listeners.first.fetch("proxy") == "🧪 节点能力检测"
  raise "listener auth missing" unless listeners.first.fetch("users").first.fetch("username") == "probe"
' "$work/config.yaml"

echo "node capability OpenClash patch test: OK"
