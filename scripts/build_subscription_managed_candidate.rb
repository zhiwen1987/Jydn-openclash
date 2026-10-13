#!/usr/bin/env ruby
# Replace only proxy-provider URLs with the local admission controller.
# Rules, DNS, groups, ports and provider names remain unchanged.

require "yaml"

abort "usage: build_subscription_managed_candidate.rb INPUT OUTPUT" unless ARGV.length == 2
input, output = ARGV
abort "input and output must differ" if File.expand_path(input) == File.expand_path(output)

base = ENV.fetch("SUBSCRIPTION_PROVIDER_BASE")
token = ENV.fetch("SUBSCRIPTION_PUBLISH_TOKEN")
abort "publish token must be 24-128 URL-safe characters" unless token.match?(/\A[A-Za-z0-9_-]{24,128}\z/)
abort "invalid provider base" unless base.match?(%r{\Ahttps?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[^\s?#]*)?\z})

config = YAML.safe_load(File.read(input), aliases: true)
abort "candidate root must be a mapping" unless config.is_a?(Hash)
providers = config.fetch("proxy-providers")
abort "proxy-providers must be a mapping" unless providers.is_a?(Hash)
abort "candidate needs at least one proxy provider" if providers.empty?

providers.each do |name, provider|
  abort "unsafe provider name" unless name.match?(/\A[A-Za-z0-9_.-]{1,80}\z/)
  abort "only HTTP providers can be managed" unless provider["type"] == "http"
  provider["url"] = "#{base.sub(%r{/$}, '')}/providers/#{name}.yaml?token=#{token}"
  provider["interval"] = 3600
end

File.open(output, "w", 0o600) { |file| file.write(YAML.dump(config)) }
puts "managed_provider_count=#{providers.length}"
puts "rules_unchanged=#{Array(config['rules']).length}"
puts "groups_unchanged=#{Array(config['proxy-groups']).length}"
