#!/usr/bin/env ruby
# Inject an isolated, authenticated listener and selector used only by the
# lan-center node-capability evaluator. The listener has a fixed proxy group,
# so probing never changes a production business selector.

require "yaml"

unless (2..3).cover?(ARGV.length)
  warn "usage: patch_node_capability_probe.rb INPUT_YAML AUTH_YAML [OUTPUT_YAML]"
  exit 2
end

input_path, auth_path, output_path = ARGV
output_path ||= input_path

config = YAML.unsafe_load_file(input_path)
auth = YAML.safe_load_file(auth_path, permitted_classes: [], aliases: false)

username = auth.fetch("username").to_s
password = auth.fetch("password").to_s
raise "capability listener username is empty" if username.empty?
raise "capability listener password is empty" if password.empty?

group_name = auth.fetch("group", "🧪 节点能力检测").to_s
listener_name = auth.fetch("listener", "node-capability-probe").to_s
listen_address = auth.fetch("listen", "10.88.0.254").to_s
listen_port = Integer(auth.fetch("port", 7895))
raise "invalid capability listener port" unless (1..65_535).cover?(listen_port)

providers = config.fetch("proxy-providers", {}).keys
raise "runtime config has no proxy providers" if providers.empty?

groups = config.fetch("proxy-groups")
group = {
  "name" => group_name,
  "type" => "select",
  "proxies" => ["REJECT"],
  "use" => providers,
  "filter" => "(?i)^(?!.*(剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|刷新订阅|刷新失败|更新失败|取消订阅时限)).+"
}

existing_group_index = groups.index { |entry| entry["name"] == group_name }
if existing_group_index
  groups[existing_group_index] = group
else
  groups << group
end

listeners = config["listeners"] ||= []
listener = {
  "name" => listener_name,
  "type" => "mixed",
  "port" => listen_port,
  "listen" => listen_address,
  "udp" => false,
  "users" => [{"username" => username, "password" => password}],
  "proxy" => group_name
}

existing_listener_index = listeners.index { |entry| entry["name"] == listener_name }
if existing_listener_index
  listeners[existing_listener_index] = listener
else
  listeners << listener
end

File.open(output_path, "w", 0o600) { |file| file.write(YAML.dump(config)) }

puts "node_capability_probe_group=1"
puts "node_capability_probe_listener=1"
puts "node_capability_probe_providers=#{providers.length}"
