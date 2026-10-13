#!/usr/bin/env ruby
# Prove that only provider URL/interval fields changed in a managed candidate.

require "yaml"

abort "usage: verify_subscription_managed_candidate.rb ORIGINAL CANDIDATE BASE" unless ARGV.length == 3
original_path, candidate_path, base = ARGV
abort "invalid provider base" unless base.match?(%r{\Ahttps?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[^\s?#]*)?\z})

load_yaml = lambda do |path|
  value = YAML.safe_load(File.read(path), aliases: true)
  abort "configuration root must be a mapping" unless value.is_a?(Hash)
  value
end

original = load_yaml.call(original_path)
candidate = load_yaml.call(candidate_path)
original_providers = original.fetch("proxy-providers")
candidate_providers = candidate.fetch("proxy-providers")
abort "provider names changed" unless original_providers.keys == candidate_providers.keys

candidate_providers.each do |name, provider|
  expected_prefix = "#{base.sub(%r{/$}, '')}/providers/#{name}.yaml?token="
  abort "provider URL mismatch" unless provider["url"].to_s.start_with?(expected_prefix)
  token = provider["url"].to_s.delete_prefix(expected_prefix)
  abort "provider token invalid" unless token.match?(/\A[A-Za-z0-9_-]{24,128}\z/)
  abort "provider interval mismatch" unless provider["interval"] == 3600
  provider["url"] = original_providers.fetch(name)["url"]
  provider["interval"] = original_providers.fetch(name)["interval"]
end

abort "non-provider structure changed" unless candidate == original
abort "candidate permissions must be 600" unless (File.stat(candidate_path).mode & 0o077).zero?

puts "subscription_candidate_verification=OK"
puts "verified_provider_count=#{candidate_providers.length}"
