#!/usr/bin/env ruby
# Build an R4-HA candidate from an existing R3 OpenClash YAML without
# modifying the source file or exposing subscription/node details.

require "yaml"

unless ARGV.length == 2
  warn "usage: build_r4_candidate.rb INPUT_R3_YAML OUTPUT_R4_YAML"
  exit 2
end

input_path, output_path = ARGV
raise "input and output must be different files" if File.expand_path(input_path) == File.expand_path(output_path)

status_filter = "(?i)^(?!.*(剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|刷新订阅|刷新失败|更新失败|取消订阅时限)).+"
specs = [
  ["🤖 对话助手（ChatGPT）", "🧠 人工智能", "🤖 ChatGPT 专用节点池", "https://chatgpt.com/api/auth/session"],
  ["🟠 对话助手（Claude）", "🧠 人工智能", "🟠 Claude 专用节点池", "https://claude.ai/favicon.ico"],
  ["🔵 对话助手（Gemini）", "🧠 人工智能", "🔵 Gemini 专用节点池", "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta"],
  ["🎥 流媒体（Netflix）", "🎬 流媒体节点", "🎥 Netflix 专用节点池", "https://www.netflix.com/"],
]

config = YAML.unsafe_load_file(input_path)
groups = config.fetch("proxy-groups")
raise "R3 baseline must contain 95 groups, got #{groups.length}" unless groups.length == 95

groups_by_name = groups.to_h { |group| [group.fetch("name"), group] }
raise "duplicate proxy-group names in R3 baseline" unless groups_by_name.length == groups.length

automatic = groups_by_name.fetch("♻️ 自动选择")
provider_names = Array(automatic["use"])
raise "automatic pool has no proxy providers" if provider_names.empty?
missing_providers = provider_names.reject { |name| config.fetch("proxy-providers", {}).key?(name) }
raise "automatic pool references missing providers" unless missing_providers.empty?

new_groups = specs.map do |business_name, old_default, pool_name, url|
  raise "R4 pool already exists: #{pool_name}" if groups_by_name.key?(pool_name)

  business = groups_by_name.fetch(business_name)
  choices = Array(business["proxies"])
  raise "#{business_name} is not a selectable business group" unless business["type"] == "select"
  raise "#{business_name} default drifted from #{old_default}" unless choices.first == old_default

  # Keep the old functional parent immediately after the new service-aware
  # default so the dashboard retains a simple manual escape hatch.
  business["proxies"] = [pool_name, *choices]

  pool = {
    "name" => pool_name,
    "type" => "url-test",
    "proxies" => ["🛟 稳定自动"],
    "use" => provider_names.dup,
    "filter" => status_filter,
    "url" => url,
    "interval" => 900,
    "tolerance" => 100,
  }
  if pool_name == "🤖 ChatGPT 专用节点池"
    pool.delete("url")
    pool.delete("interval")
    pool.delete("tolerance")
    pool["type"] = "select"
    pool["proxies"] = ["🧠 人工智能"]
  end
  pool
end

insert_at = groups.index { |group| group["name"] == "🧭 手动选择" }
raise "cannot locate node-pool insertion point" if insert_at.nil?
groups.insert(insert_at, *new_groups)

raise "R4 candidate must contain 99 groups, got #{groups.length}" unless groups.length == 99
raise "R4 candidate has duplicate group names" unless groups.map { |group| group.fetch("name") }.uniq.length == 99

specs.each do |business_name, old_default, pool_name, url|
  business = groups.find { |group| group["name"] == business_name }
  pool = groups.find { |group| group["name"] == pool_name }
  raise "#{business_name} default was not updated" unless business["proxies"].first(2) == [pool_name, old_default]
  raise "#{pool_name} has an unsafe DIRECT fallback" if pool["proxies"].include?("DIRECT")
  if pool_name == "🤖 ChatGPT 专用节点池"
    raise "#{pool_name} must be controller-selected" unless pool["type"] == "select"
    raise "#{pool_name} lost AI fail-safe" unless pool["proxies"] == ["🧠 人工智能"]
  else
    raise "#{pool_name} lost stable fallback" unless pool["proxies"] == ["🛟 稳定自动"]
    raise "#{pool_name} URL mismatch" unless pool["url"] == url
    raise "#{pool_name} timing mismatch" unless pool["interval"] == 900 && pool["tolerance"] == 100
  end
end

File.open(output_path, "w", 0o600) { |file| file.write(YAML.dump(config)) }
puts "candidate_group_count=99"
puts "capability_pool_count=4"
puts "source_unchanged=true"
