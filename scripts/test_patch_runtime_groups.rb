#!/usr/bin/env ruby

require "yaml"

patch_script = File.expand_path("patch_runtime_groups.rb", __dir__)
prefix = "/tmp/jydn-group-filter-test-#{Process.pid}"
input_path = "#{prefix}-input.yaml"
catalog_path = "#{prefix}-catalog.yaml"
output_path = "#{prefix}-output.yaml"

config = {
  "proxies" => [{"name" => "node-a", "type" => "direct"}],
  "proxy-groups" => [
    {"name" => "business", "type" => "select", "proxies" => ["empty-leaf", "full-region"]},
    {"name" => "full-leaf", "type" => "url-test", "proxies" => ["node-a", "REJECT"]},
    {"name" => "empty-leaf", "type" => "url-test", "proxies" => ["REJECT"]},
    {"name" => "full-region", "type" => "select", "proxies" => ["full-leaf", "empty-leaf"]},
    {"name" => "empty-region", "type" => "select", "proxies" => ["empty-leaf"]},
  ],
}
catalog = {
  "business_groups" => ["business"],
  "proxy_choices" => ["full-leaf", "empty-leaf", "full-region", "empty-region"],
  "always_choices" => ["DIRECT", "REJECT"],
  "dashboard_group_order" => ["full-region", "business", "full-leaf", "empty-leaf", "empty-region"],
}

begin
  File.write(input_path, YAML.dump(config))
  File.write(catalog_path, YAML.dump(catalog))
  raise "patch command failed" unless system("ruby", patch_script, input_path, catalog_path, output_path)

  result = YAML.unsafe_load_file(output_path)
  groups = result.fetch("proxy-groups").to_h { |group| [group.fetch("name"), group] }
  expected = ["full-region", "DIRECT", "REJECT", "full-leaf"]
  raise "business choices mismatch" unless groups.fetch("business").fetch("proxies") == expected
  raise "empty child was not removed" if groups.fetch("full-region").fetch("proxies").include?("empty-leaf")
  raise "empty region lost safe fallback" unless groups.fetch("empty-region").fetch("proxies") == ["REJECT"]
  raise "proxy-group definitions were removed" unless groups.length == 5
  expected_group_order = ["full-region", "business", "full-leaf", "empty-leaf", "empty-region"]
  raise "dashboard group order mismatch" unless result.fetch("proxy-groups").map { |group| group.fetch("name") } == expected_group_order

  puts "Runtime group filter test passed"
ensure
  [input_path, catalog_path, output_path].each do |path|
    File.delete(path) if File.exist?(path)
  end
end
