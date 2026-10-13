#!/usr/bin/env ruby
require "yaml"

script = File.expand_path("build_subscription_managed_candidate.rb", __dir__)
verifier = File.expand_path("verify_subscription_managed_candidate.rb", __dir__)
dir = "/tmp/subscription-candidate-test-#{Process.pid}"
Dir.mkdir(dir, 0o700)
begin
  input = File.join(dir, "input.yaml")
  output = File.join(dir, "output.yaml")
  source = {
    "proxy-providers" => {
      "Provider_A" => {"type" => "http", "url" => "https://secret.invalid/a", "interval" => 60}
    },
    "proxy-groups" => [{"name" => "auto", "type" => "url-test", "use" => ["Provider_A"]}],
    "rules" => ["MATCH,auto"],
  }
  File.write(input, YAML.dump(source))
  env = {
    "SUBSCRIPTION_PROVIDER_BASE" => "http://10.88.0.249:3103",
    "SUBSCRIPTION_PUBLISH_TOKEN" => "a" * 32,
  }
  abort "builder failed" unless system(env, "ruby", script, input, output, out: File::NULL)
  result = YAML.load_file(output)
  abort "provider URL not replaced" unless result.dig("proxy-providers", "Provider_A", "url").start_with?(env["SUBSCRIPTION_PROVIDER_BASE"])
  abort "rules changed" unless result["rules"] == source["rules"]
  abort "groups changed" unless result["proxy-groups"] == source["proxy-groups"]
  abort "unsafe mode" unless (File.stat(output).mode & 0o077).zero?
  abort "candidate verification failed" unless system(
    "ruby", verifier, input, output, env["SUBSCRIPTION_PROVIDER_BASE"], out: File::NULL
  )

  malicious = File.join(dir, "malicious.yaml")
  File.write(malicious, "--- !ruby/object:Object {}\n")
  abort "unsafe YAML accepted" if system(env, "ruby", script, malicious, output, out: File::NULL, err: File::NULL)
  bad_env = env.merge("SUBSCRIPTION_PUBLISH_TOKEN" => ("a" * 32 + "\r"))
  abort "control character in token accepted" if system(
    bad_env, "ruby", script, input, output, out: File::NULL, err: File::NULL
  )
ensure
  Dir.children(dir).each { |name| File.delete(File.join(dir, name)) }
  Dir.rmdir(dir)
end
puts "subscription_managed_candidate_test=OK"
