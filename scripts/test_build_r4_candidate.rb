#!/usr/bin/env ruby

require "yaml"

builder = File.expand_path("build_r4_candidate.rb", __dir__)
dir = "/tmp/r4-candidate-test-#{Process.pid}"
input = File.join(dir, "r3.yaml")
output = File.join(dir, "r4.yaml")

begin
  Dir.mkdir(dir, 0o700)
  groups = [
    {"name" => "♻️ 自动选择", "type" => "url-test", "proxies" => ["REJECT"], "use" => ["one", "two"]},
    {"name" => "🛟 稳定自动", "type" => "url-test", "proxies" => ["♻️ 自动选择"]},
    {"name" => "🤖 对话助手（ChatGPT）", "type" => "select", "proxies" => ["🧠 人工智能", "DIRECT"]},
    {"name" => "🟠 对话助手（Claude）", "type" => "select", "proxies" => ["🧠 人工智能", "DIRECT"]},
    {"name" => "🔵 对话助手（Gemini）", "type" => "select", "proxies" => ["🧠 人工智能", "DIRECT"]},
    {"name" => "🎥 流媒体（Netflix）", "type" => "select", "proxies" => ["🎬 流媒体节点", "DIRECT"]},
    {"name" => "🧭 手动选择", "type" => "select", "proxies" => ["🛟 稳定自动"]},
  ]
  88.times do |index|
    groups << {"name" => "fixture-#{index}", "type" => "select", "proxies" => ["DIRECT"]}
  end
  config = {
    "proxy-providers" => {"one" => {}, "two" => {}},
    "proxy-groups" => groups,
  }
  File.write(input, YAML.dump(config))

  raise "candidate builder failed" unless system("ruby", builder, input, output)

  result = YAML.unsafe_load_file(output)
  result_groups = result.fetch("proxy-groups")
  raise "candidate group count mismatch" unless result_groups.length == 99
  by_name = result_groups.to_h { |group| [group.fetch("name"), group] }
  expected = {
    "🤖 对话助手（ChatGPT）" => ["🤖 ChatGPT 专用节点池", "🧠 人工智能"],
    "🟠 对话助手（Claude）" => ["🟠 Claude 专用节点池", "🧠 人工智能"],
    "🔵 对话助手（Gemini）" => ["🔵 Gemini 专用节点池", "🧠 人工智能"],
    "🎥 流媒体（Netflix）" => ["🎥 Netflix 专用节点池", "🎬 流媒体节点"],
  }
  expected.each do |business_name, choices|
    raise "business order mismatch: #{business_name}" unless by_name.fetch(business_name).fetch("proxies").first(2) == choices
    pool = by_name.fetch(choices.first)
    raise "unsafe pool fallback: #{choices.first}" unless pool.fetch("proxies") == ["🛟 稳定自动"]
    raise "provider inheritance mismatch: #{choices.first}" unless pool.fetch("use") == ["one", "two"]
    raise "pool timing mismatch: #{choices.first}" unless pool.fetch("interval") == 900 && pool.fetch("tolerance") == 100
  end

  puts "R4 candidate builder test passed"
ensure
  File.delete(output) if File.exist?(output)
  File.delete(input) if File.exist?(input)
  Dir.rmdir(dir) if Dir.exist?(dir)
end
