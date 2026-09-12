#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

GROUP_NAME = "🔬 节点归属校验"
STATUS_PATTERN = /(剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|刷新订阅|刷新失败|更新失败|取消订阅时限)/i
BUILTIN_POLICIES = %w[DIRECT REJECT REJECT-DROP PASS COMPATIBLE].freeze
COUNTRY_GROUP_CODES = {
  "🇭🇰 香港" => "HK", "🇹🇼 台湾" => "TW", "🇯🇵 日本" => "JP", "🇸🇬 新加坡" => "SG",
  "🇰🇷 韩国" => "KR", "🇮🇳 印度" => "IN", "🇻🇳 越南" => "VN", "🇹🇭 泰国" => "TH",
  "🇲🇾 马来西亚" => "MY", "🇵🇭 菲律宾" => "PH", "🇮🇩 印度尼西亚" => "ID",
  "🇲🇲 缅甸" => "MM", "🇵🇰 巴基斯坦" => "PK", "🇬🇧 英国" => "GB",
  "🇩🇪 德国" => "DE", "🇫🇷 法国" => "FR", "🇳🇱 荷兰" => "NL",
  "🇪🇸 西班牙" => "ES", "🇨🇭 瑞士" => "CH", "🇸🇪 瑞典" => "SE",
  "🇷🇺 俄罗斯" => "RU", "🇹🇷 土耳其" => "TR", "🇬🇷 希腊" => "GR",
  "🇳🇴 挪威" => "NO", "🇺🇸 美国" => "US", "🇨🇦 加拿大" => "CA",
  "🇲🇽 墨西哥" => "MX", "🇧🇷 巴西" => "BR", "🇨🇱 智利" => "CL",
  "🇨🇴 哥伦比亚" => "CO", "🇦🇪 阿联酋" => "AE", "🇸🇦 沙特阿拉伯" => "SA",
  "🇮🇱 以色列" => "IL", "🇿🇦 南非" => "ZA", "🇳🇬 尼日利亚" => "NG",
  "🇦🇺 澳大利亚" => "AU"
}.freeze
SOURCES = [
  { "name" => "country.is", "url" => "https://api.country.is/", "field" => "country" },
  { "name" => "ipwho.is", "url" => "https://ipwho.is/", "field" => "country_code" },
  { "name" => "ip.sb", "url" => "https://api.ip.sb/geoip", "field" => "country_code" },
  { "name" => "countries.dev", "url" => "https://countries.dev/ip", "field" => "countryCode" },
  { "name" => "cloudflare", "url" => "https://www.cloudflare.com/cdn-cgi/trace", "field" => "loc", "format" => "trace" }
].freeze

def usage
  <<~TEXT
    Usage: ruby scripts/verify_node_geo.rb [options]
      --controller=URL   Mihomo API, default: http://127.0.0.1:<openclash.cn_port>
      --proxy=URL        Mihomo HTTP/mixed proxy, default: http://127.0.0.1:<openclash.mixed_port>
      --proxy-auth=USER:PASS
                         proxy-port authentication; normally auto-read from UCI
      --template=PATH    generated subconverter template used for name fallback
      --timeout=SECONDS  timeout per online source, default: 8
      --limit=COUNT      verify only the first COUNT nodes
      --match=REGEX      verify only matching node names
      --output=PATH      write a YAML report without node credentials or exit IPs
      --self-test        test parsers, voting, and name fallback without network access

    The API secret is read from OPENCLASH_SECRET first, then from
    openclash.config.dashboard_password. Proxy authentication is read from
    OPENCLASH_PROXY_AUTH first, then from the first enabled UCI authentication
    entry. Neither credential is printed or written to reports.
  TEXT
end

def capture(*args)
  output = IO.popen(args, err: [:child, :out], &:read)
  [$?.success?, output]
end

def uci_value(key)
  ok, output = capture("uci", "-q", "get", key)
  ok ? output.strip : nil
rescue StandardError
  nil
end

def url_encode(value)
  value.encode("UTF-8").bytes.map do |byte|
    char = byte.chr
    char.match?(/[A-Za-z0-9_.~-]/) ? char : format("%%%02X", byte)
  end.join
end

def json_string(value)
  escaped = value.gsub("\\", "\\\\").gsub('"', '\\"')
                 .gsub("\n", "\\n").gsub("\r", "\\r").gsub("\t", "\\t")
  %Q{"#{escaped}"}
end

def curl_args(secret, timeout)
  args = ["curl", "-fSs", "--connect-timeout", [timeout / 2, 2].max.to_s,
          "--max-time", timeout.to_s]
  args += ["-H", "Authorization: Bearer #{secret}"] unless secret.empty?
  args
end

def api_get(controller, path, secret, timeout)
  ok, output = capture(*(curl_args(secret, timeout) + ["#{controller}#{path}"]))
  raise "Mihomo API query failed: #{path}: #{output.strip}" unless ok

  YAML.load(output)
end

def api_select(controller, group, node, secret, timeout)
  body = %Q{{"name":#{json_string(node)}}}
  args = curl_args(secret, timeout) + ["-o", "/dev/null", "-X", "PUT",
                                      "-H", "Content-Type: application/json",
                                      "--data-binary", body,
                                      "#{controller}/proxies/#{url_encode(group)}"]
  ok, output = capture(*args)
  raise "Unable to select #{node}: #{output.strip}" unless ok
end

def group_patterns(template)
  lines = File.readlines(template, encoding: "UTF-8")
  COUNTRY_GROUP_CODES.each_with_object({}) do |(group, code), result|
    line = lines.find { |entry| entry.start_with?("custom_proxy_group=#{group}`") }
    raise "Missing country group in template: #{group}" unless line

    pattern = line.strip.split("`")[2..].find do |field|
      !field.empty? && !field.start_with?("[]") && !field.start_with?("http")
    end
    raise "Missing name filter in template: #{group}" unless pattern

    result[code] = Regexp.new(pattern)
  end
end

def name_country(node, patterns)
  matches = patterns.filter_map { |code, pattern| code if pattern.match?(node) }
  matches.length == 1 ? matches.first : nil
end

def parse_country(source, body)
  if source["format"] == "trace"
    code = body.each_line.filter_map do |line|
      key, value = line.strip.split("=", 2)
      value if key == source["field"]
    end.first.to_s.upcase
    return code.match?(/\A[A-Z]{2}\z/) ? code : nil
  end

  payload = YAML.load(body)
  return nil unless payload.is_a?(Hash)
  return nil if source["name"] == "ipwho.is" && payload["success"] == false

  code = payload[source["field"]].to_s.upcase
  code.match?(/\A[A-Z]{2}\z/) ? code : nil
rescue Psych::SyntaxError
  nil
end

def online_query(source, proxy, proxy_auth, timeout)
  args = ["curl", "-fSsL", "--noproxy", "", "--proxy", proxy,
          "--connect-timeout", [timeout / 2, 2].max.to_s, "--max-time", timeout.to_s,
          "-A", "Jydn-OpenClash-GeoCheck/1.0", source["url"]]
  args[1, 0] = ["--proxy-user", proxy_auth] unless proxy_auth.empty?
  ok, output = capture(*args)
  ok ? parse_country(source, output) : nil
end

def consensus(votes)
  valid_votes = votes.compact
  return nil if valid_votes.length < 2

  counts = valid_votes.tally
  winner = counts.max_by { |code, count| [count, code] }
  required = [2, (valid_votes.length / 2) + 1].max
  winner && winner[1] >= required ? winner[0] : nil
end

def self_test(template)
  raise "country.is parser failed" unless parse_country(SOURCES[0], '{"country":"JP"}') == "JP"
  raise "ipwho.is parser failed" unless parse_country(SOURCES[1], '{"success":true,"country_code":"JP"}') == "JP"
  raise "ip.sb parser failed" unless parse_country(SOURCES[2], '{"country_code":"US"}') == "US"
  raise "countries.dev parser failed" unless parse_country(SOURCES[3], '{"countryCode":"SG"}') == "SG"
  raise "Cloudflare parser failed" unless parse_country(SOURCES[4], "ip=192.0.2.1\nloc=JP\n") == "JP"
  raise "consensus failed" unless consensus(%w[JP JP JP US SG]) == "JP"
  raise "non-majority result must not win" unless consensus(%w[JP JP US SG]).nil?
  raise "single-source result must not win" unless consensus(["JP", nil, nil]).nil?

  patterns = group_patterns(template)
  raise "Tokyo fallback failed" unless name_country("Tokyo-01", patterns) == "JP"
  raise "JP code fallback failed" unless name_country("JP-01", patterns) == "JP"
  raise "Indonesia fallback is ambiguous" unless name_country("🇮🇩印度尼西亚 01", patterns) == "ID"
  puts "Self-test passed: parsers, strict-majority consensus, and name fallback"
end

begin
options = {
  "controller" => nil,
  "proxy" => nil,
  "proxy-auth" => nil,
  "template" => File.expand_path("../metafenliu.ini", __dir__),
  "timeout" => 8,
  "limit" => nil,
  "match" => nil,
  "output" => nil,
  "self_test" => false
}

ARGV.each do |arg|
  case arg
  when "--help", "-h" then puts usage; exit 0
  when "--self-test" then options["self_test"] = true
  when /\A--([^=]+)=(.*)\z/ then options[Regexp.last_match(1)] = Regexp.last_match(2)
  else warn "Unknown option: #{arg}\n#{usage}"; exit 64
  end
end

unless File.file?(options["template"])
  warn "Template not found: #{options['template']}"
  exit 66
end

if options["self_test"]
  self_test(options["template"])
  exit 0
end

timeout = Integer(options["timeout"])
limit = options["limit"] ? Integer(options["limit"]) : nil
match_pattern = options["match"] ? Regexp.new(options["match"]) : nil
controller_port = uci_value("openclash.config.cn_port") || "9090"
mixed_port = uci_value("openclash.config.mixed_port") || "7890"
controller = (options["controller"] || "http://127.0.0.1:#{controller_port}").sub(%r{/$}, "")
proxy = options["proxy"] || "http://127.0.0.1:#{mixed_port}"
secret = ENV.fetch("OPENCLASH_SECRET", "")
secret = uci_value("openclash.config.dashboard_password").to_s if secret.empty?
proxy_auth = options["proxy-auth"] || ENV.fetch("OPENCLASH_PROXY_AUTH", "")
if proxy_auth.empty? && uci_value("openclash.@authentication[0].enabled") != "0"
  proxy_user = uci_value("openclash.@authentication[0].username").to_s
  proxy_password = uci_value("openclash.@authentication[0].password").to_s
  proxy_auth = "#{proxy_user}:#{proxy_password}" unless proxy_user.empty?
end
patterns = group_patterns(options["template"])

all_proxies = api_get(controller, "/proxies", secret, timeout).fetch("proxies")
group = all_proxies.fetch(GROUP_NAME) { raise "Missing runtime group: #{GROUP_NAME}" }
original = group["now"]
nodes = Array(group["all"]).select do |name|
  info = all_proxies[name]
  info && !info.key?("all") && !BUILTIN_POLICIES.include?(name) && !STATUS_PATTERN.match?(name)
end
nodes.select! { |name| match_pattern.match?(name) } if match_pattern
nodes = nodes.first(limit) if limit
raise "No terminal nodes found in #{GROUP_NAME}" if nodes.empty?

known_codes = COUNTRY_GROUP_CODES.values.to_h { |code| [code, true] }
results = []
issues = 0

begin
  nodes.each_with_index do |node, index|
    api_select(controller, GROUP_NAME, node, secret, timeout)
    sleep 0.25
    source_votes = SOURCES.to_h do |source|
      [source["name"], online_query(source, proxy, proxy_auth, timeout)]
    end
    online = consensus(source_votes.values)
    fallback = name_country(node, patterns)
    chosen = online || fallback
    method = online ? "online-consensus" : "name-fallback"
    flags = []
    flags << "ONLINE_NAME_MISMATCH" if online && fallback && online != fallback
    flags << "UNMAPPED_ONLINE_COUNTRY" if online && !known_codes[online]
    flags << "UNCLASSIFIED" unless chosen
    issues += 1 unless flags.empty?
    results << {
      "node" => node,
      "country" => chosen,
      "method" => method,
      "votes" => source_votes,
      "name_country" => fallback,
      "flags" => flags
    }
    vote_text = source_votes.map { |name, code| "#{name}=#{code || '-'}" }.join(",")
    puts format("[%d/%d] %s country=%s method=%s votes=%s flags=%s",
                index + 1, nodes.length, node, chosen || "-", method, vote_text,
                flags.empty? ? "OK" : flags.join("+"))
    sleep 0.25
  end
ensure
  api_select(controller, GROUP_NAME, original, secret, timeout) if original && all_proxies[original]
end

if options["output"]
  report = {
    "generated_at" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sources" => SOURCES.map { |source| source["name"] },
    "minimum_agreeing_sources" => 2,
    "strict_majority_of_successful_sources" => true,
    "results" => results
  }
  File.write(options["output"], YAML.dump(report), mode: "w", encoding: "UTF-8")
  puts "Report written: #{options['output']}"
end

online_count = results.count { |result| result["method"] == "online-consensus" }
fallback_count = results.length - online_count
puts "Summary: nodes=#{results.length} online=#{online_count} fallback=#{fallback_count} issues=#{issues}"
exit(issues.zero? ? 0 : 1)
rescue Interrupt
  warn "Interrupted; the original validation-group selection was restored when available"
  exit 130
rescue StandardError => e
  warn "ERROR: #{e.message}"
  exit 1
end
