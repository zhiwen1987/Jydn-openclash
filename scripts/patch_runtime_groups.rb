#!/usr/bin/env ruby
# Apply a generated business-group catalog to an existing Mihomo YAML file.

require "yaml"

unless (2..3).cover?(ARGV.length)
  warn "usage: patch_runtime_groups.rb INPUT_YAML CATALOG_JSON [OUTPUT_YAML]"
  exit 2
end

input_path, catalog_path, output_path = ARGV
output_path ||= input_path
catalog = YAML.unsafe_load_file(catalog_path)
business_groups = catalog.fetch("business_groups")
proxy_choices = catalog.fetch("proxy_choices")
always_choices = catalog.fetch("always_choices", ["DIRECT", "REJECT"])
dashboard_group_order = catalog.fetch("dashboard_group_order", [])

unless business_groups.uniq.length == business_groups.length
  raise "business group catalog contains duplicates"
end
unless proxy_choices.uniq.length == proxy_choices.length
  raise "proxy choice catalog contains duplicates"
end
unless always_choices.uniq.length == always_choices.length
  raise "always choice catalog contains duplicates"
end
unless dashboard_group_order.uniq.length == dashboard_group_order.length
  raise "dashboard group order contains duplicates"
end

config = YAML.unsafe_load_file(input_path)
proxy_groups = config.fetch("proxy-groups")
groups_by_name = proxy_groups.to_h { |group| [group.fetch("name"), group] }

missing_business = business_groups.reject { |name| groups_by_name.key?(name) }
missing_choices = proxy_choices.reject { |name| groups_by_name.key?(name) }
unless missing_business.empty?
  raise "runtime config is missing business groups: #{missing_business.join(', ')}"
end
unless missing_choices.empty?
  raise "runtime config is missing proxy choices: #{missing_choices.join(', ')}"
end
missing_dashboard_groups = dashboard_group_order.reject { |name| groups_by_name.key?(name) }
unless missing_dashboard_groups.empty?
  raise "runtime config is missing dashboard groups: #{missing_dashboard_groups.join(', ')}"
end

raw_proxy_names = Array(config["proxies"]).filter_map do |proxy|
  proxy.is_a?(Hash) ? proxy["name"] : proxy
end.compact.to_h { |name| [name, true] }
group_names = groups_by_name.keys.to_h { |name| [name, true] }
builtin_names = %w[DIRECT REJECT REJECT-DROP PASS COMPATIBLE].to_h do |name|
  [name, true]
end

compile_filter = lambda do |pattern, label|
  next nil if pattern.nil? || pattern.to_s.empty?

  Regexp.new(pattern.to_s)
rescue RegexpError => e
  raise "invalid #{label} regular expression: #{e.message}"
end

# A provider reference alone does not prove that a filtered group has nodes.
# Evaluate the filter against OpenClash's local provider cache. When a cache is
# temporarily unavailable, keep the group visible to avoid a false removal.
config_dir = File.dirname(File.expand_path(input_path))
provider_base_dirs = [config_dir]
provider_base_dirs << File.dirname(config_dir) if File.basename(config_dir) == "config"
provider_base_dirs << ENV.fetch("OPENCLASH_HOME", "/etc/openclash")
provider_base_dirs.uniq!
provider_node_names = {}
provider_cache_missing = []
config.fetch("proxy-providers", {}).each do |provider_name, provider|
  provider_path = provider["path"]
  provider_config = nil
  if provider_path && !provider_path.to_s.empty?
    candidate_paths = if File.absolute_path(provider_path) == provider_path
      [provider_path]
    else
      relative_paths = [provider_path]
      if provider_path.match?(%r{\A(?:\./)?providers/})
        relative_paths << provider_path.sub(
          %r{\A(?:\./)?providers/},
          "./proxy_provider/"
        )
      end
      relative_paths.flat_map do |relative_path|
        provider_base_dirs.map { |base_dir| File.expand_path(relative_path, base_dir) }
      end.uniq
    end
    expanded_path = candidate_paths.find { |path| File.file?(path) } || candidate_paths.first
    begin
      provider_config = YAML.unsafe_load_file(expanded_path)
    rescue Errno::ENOENT, Psych::SyntaxError => e
      provider_cache_missing << "#{provider_name}: #{e.message}"
    end
  end

  if provider_config
    include_pattern = compile_filter.call(provider["filter"], "provider #{provider_name} filter")
    exclude_pattern = compile_filter.call(
      provider["exclude-filter"],
      "provider #{provider_name} exclude-filter"
    )
    exclude_type_pattern = compile_filter.call(
      provider["exclude-type"],
      "provider #{provider_name} exclude-type"
    )
    provider_node_names[provider_name] = Array(provider_config["proxies"]).filter_map do |proxy|
      next unless proxy.is_a?(Hash)

      name = proxy["name"]
      type = proxy["type"]
      next if name.nil? || name.to_s.empty?
      next if include_pattern && !include_pattern.match?(name.to_s)
      next if exclude_pattern&.match?(name.to_s)
      next if exclude_type_pattern&.match?(type.to_s)

      name.to_s
    end
  else
    provider_node_names[provider_name] = nil
  end
end

availability = {}
visiting = {}

group_has_node = lambda do |name|
  return true if raw_proxy_names.include?(name)
  return availability[name] if availability.key?(name)
  return false unless group_names.include?(name)
  return false if visiting.include?(name)

  visiting[name] = true
  group = groups_by_name.fetch(name)
  group_filter = compile_filter.call(group["filter"], "group #{name} filter")
  group_exclude_filter = compile_filter.call(
    group["exclude-filter"],
    "group #{name} exclude-filter"
  )
  provider_result = Array(group["use"]).any? do |provider_name|
    names = provider_node_names[provider_name]
    next true if names.nil?

    names.any? do |node_name|
      (!group_filter || group_filter.match?(node_name)) &&
        !group_exclude_filter&.match?(node_name)
    end
  end
  result = provider_result || group["include-all"] == true ||
    Array(group["proxies"]).any? do |choice|
      next false if builtin_names.include?(choice)

      raw_proxy_names.include?(choice) || group_has_node.call(choice)
    end
  visiting.delete(name)
  availability[name] = result
end

proxy_choice_set = proxy_choices.to_h { |name| [name, true] }
empty_proxy_choices = proxy_choices.reject { |name| group_has_node.call(name) }
empty_proxy_choice_set = empty_proxy_choices.to_h { |name| [name, true] }
removed_choice_count = 0

# Keep every proxy-group object visible, but remove empty node-group references
# from selector menus (including region navigation and the global manual entry).
proxy_groups.each do |group|
  next unless group["proxies"].is_a?(Array)

  before = group["proxies"].length
  group["proxies"] = group["proxies"].reject do |choice|
    proxy_choice_set.include?(choice) && empty_proxy_choice_set.include?(choice)
  end
  removed_choice_count += before - group["proxies"].length
  if group["proxies"].empty? && Array(group["use"]).empty?
    group["proxies"] << "REJECT"
  end
end

business_groups.each do |name|
  group = groups_by_name.fetch(name)
  choices = group.fetch("proxies")
  raise "business group has no available choice: #{name}" if choices.empty?
  raise "self reference detected in #{name}" if choices.include?(name)
end

dashboard_reordered_group_count = 0
unless dashboard_group_order.empty?
  dashboard_index = dashboard_group_order.each_with_index.to_h
  original_group_order = proxy_groups.map { |group| group.fetch("name") }
  original_index = original_group_order.each_with_index.to_h
  proxy_groups.sort_by! do |group|
    name = group.fetch("name")
    [dashboard_index.fetch(name, dashboard_group_order.length + original_index.fetch(name)),
     original_index.fetch(name)]
  end
  dashboard_reordered_group_count = proxy_groups.each_index.count do |index|
    proxy_groups[index].fetch("name") != original_group_order[index]
  end
end

File.open(output_path, "w", 0o600) { |file| file.write(YAML.dump(config)) }

puts "group_count=#{proxy_groups.length}"
puts "business_group_count=#{business_groups.length}"
puts "proxy_choice_count=#{proxy_choices.length}"
puts "available_proxy_choice_count=#{proxy_choices.length - empty_proxy_choices.length}"
puts "empty_proxy_choice_count=#{empty_proxy_choices.length}"
puts "added_choice_count=0"
puts "removed_choice_count=#{removed_choice_count}"
puts "reordered_group_count=0"
puts "dashboard_reordered_group_count=#{dashboard_reordered_group_count}"
puts "provider_cache_missing_count=#{provider_cache_missing.length}"
