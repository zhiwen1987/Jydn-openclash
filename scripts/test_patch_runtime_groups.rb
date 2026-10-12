#!/usr/bin/env ruby

require "yaml"

patch_script = File.expand_path("patch_runtime_groups.rb", __dir__)
prefix = "/tmp/jydn-group-filter-test-#{Process.pid}"
config_dir = File.join(prefix, "config")
provider_dir = File.join(prefix, "proxy_provider")
input_path = File.join(config_dir, "input.yaml")
catalog_path = File.join(prefix, "catalog.yaml")
output_path = File.join(config_dir, "output.yaml")
provider_path = File.join(provider_dir, "provider.yaml")

config = {
  "proxies" => [{"name" => "node-a", "type" => "direct"}],
  "proxy-providers" => {
    "provider-a" => {"type" => "file", "path" => "./providers/provider.yaml"},
  },
  "proxy-groups" => [
    {"name" => "business", "type" => "select", "proxies" => ["empty-leaf", "full-region", "full-provider", "empty-provider"]},
    {"name" => "full-leaf", "type" => "url-test", "proxies" => ["node-a", "REJECT"]},
    {"name" => "empty-leaf", "type" => "url-test", "proxies" => ["REJECT"]},
    {"name" => "full-region", "type" => "select", "proxies" => ["full-leaf", "empty-leaf"]},
    {"name" => "empty-region", "type" => "select", "proxies" => ["empty-leaf"]},
    {"name" => "full-provider", "type" => "url-test", "use" => ["provider-a"], "filter" => "Singapore", "proxies" => ["REJECT"]},
    {"name" => "empty-provider", "type" => "url-test", "use" => ["provider-a"], "filter" => "Tokyo", "proxies" => ["REJECT"]},
  ],
}
catalog = {
  "business_groups" => ["business"],
  "proxy_choices" => ["full-leaf", "empty-leaf", "full-region", "empty-region", "full-provider", "empty-provider"],
  "always_choices" => ["DIRECT", "REJECT"],
  "dashboard_group_order" => ["full-region", "business", "full-leaf", "empty-leaf", "empty-region", "full-provider", "empty-provider"],
}
provider = {
  "proxies" => [
    {"name" => "Singapore-01", "type" => "direct"},
    {"name" => "subscription remaining", "type" => "direct"},
  ],
}

begin
  Dir.mkdir(prefix)
  Dir.mkdir(config_dir)
  Dir.mkdir(provider_dir)
  File.write(input_path, YAML.dump(config))
  File.write(catalog_path, YAML.dump(catalog))
  File.write(provider_path, YAML.dump(provider))
  raise "patch command failed" unless system("ruby", patch_script, input_path, catalog_path, output_path)

  result = YAML.unsafe_load_file(output_path)
  groups = result.fetch("proxy-groups").to_h { |group| [group.fetch("name"), group] }
  expected = ["full-region", "full-provider"]
  raise "business choices mismatch" unless groups.fetch("business").fetch("proxies") == expected
  raise "empty child was not removed" if groups.fetch("full-region").fetch("proxies").include?("empty-leaf")
  raise "empty region lost safe fallback" unless groups.fetch("empty-region").fetch("proxies") == ["REJECT"]
  raise "provider filter with a match was removed" unless groups.fetch("business").fetch("proxies").include?("full-provider")
  raise "provider filter without a match was kept" if groups.fetch("business").fetch("proxies").include?("empty-provider")
  raise "proxy-group definitions were removed" unless groups.length == 7
  expected_group_order = ["full-region", "business", "full-leaf", "empty-leaf", "empty-region", "full-provider", "empty-provider"]
  raise "dashboard group order mismatch" unless result.fetch("proxy-groups").map { |group| group.fetch("name") } == expected_group_order

  puts "Runtime group filter test passed"
ensure
  [input_path, catalog_path, output_path, provider_path].each do |path|
    File.delete(path) if File.exist?(path)
  end
  [config_dir, provider_dir, prefix].each do |path|
    Dir.rmdir(path) if Dir.exist?(path)
  end
end
