#!/usr/bin/env ruby
# Build a temporary Mihomo config that forces every provider node to parse.

require "yaml"

abort "usage: build_provider_validation_config.rb PROVIDER OUTPUT" unless ARGV.length == 2
provider_path, output_path = ARGV
abort "input and output must differ" if File.expand_path(provider_path) == File.expand_path(output_path)

provider = YAML.safe_load(File.read(provider_path), aliases: true)
nodes = provider.is_a?(Hash) ? provider["proxies"] : nil
abort "provider proxies missing" unless nodes.is_a?(Array) && !nodes.empty?
abort "provider contains non-mapping node" unless nodes.all? { |node| node.is_a?(Hash) }

names = nodes.map { |node| node["name"].to_s }
abort "provider contains empty node name" if names.any?(&:empty?)
abort "provider contains duplicate node name" unless names.uniq.length == names.length

config = {
  "mode" => "rule",
  "log-level" => "silent",
  "proxies" => nodes,
  "proxy-groups" => [{"name" => "provider-validation", "type" => "select", "proxies" => names}],
  "rules" => ["MATCH,provider-validation"],
}

File.open(output_path, "w", 0o600) { |file| file.write(YAML.dump(config)) }
puts "provider_validation_nodes=#{nodes.length}"
