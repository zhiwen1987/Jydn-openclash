#!/usr/bin/env ruby
# Add selectable controls without changing defaults, node pools or DNS.
require 'yaml'

module RoutingControls
  def self.apply(config, catalog, controls)
    stable = controls.fetch('stable_choice')
    groups = config.fetch('proxy-groups').to_h { |g| [g.fetch('name'), g] }
    raise 'stable_group_missing' unless groups.key?(stable)
    targets = (catalog.fetch('business_groups') + controls.fetch('additional_selectors')).uniq
    # Strict exits and controller-owned pools are not ordinary business menus.
    targets.reject! { |n| n == stable || n.include?('自定义节点') || n.include?('专用节点池') || n == '⚫ Grok 稳定节点池' }
    graph = groups.transform_values { |g| Array(g['proxies']).select { |n| groups.key?(n) } }
    reachable = lambda do |start, target, seen|
      next true if start == target
      next false if seen[start]
      seen[start] = true
      graph.fetch(start, []).any? { |n| reachable.call(n, target, seen) }
    end
    added = []
    targets.each do |name|
      group = groups[name]
      next unless group && group['type'] == 'select'
      choices = group['proxies']
      raise 'selector_choices_missing' unless choices.is_a?(Array) && !choices.empty?
      next if choices.include?(stable)
      raise 'stable_choice_would_cycle' if reachable.call(stable, name, {})
      index = [1, *choices.each_index.select { |i| %w[DIRECT REJECT].include?(choices[i]) }.map { |i| i + 1 }].max
      choices.insert(index, stable)
      graph[name] << stable
      added << name
    end
    domains = controls.fetch('direct_domains')
    raise 'direct_domain_list_invalid' unless domains.is_a?(Array) && domains.length <= 16 && domains.all? { |d| d.is_a?(String) && d.match?(/\A[a-z0-9](?:[a-z0-9.-]*\.)[a-z]{2,63}\z/) }
    forced = domains.uniq.map { |d| 'DOMAIN-SUFFIX,' + d + ',DIRECT' }
    rules = config.fetch('rules')
    config['rules'] = forced + rules.reject { |r| forced.include?(r) }
    {'stable_choices_added' => added.length, 'changed_groups' => added,
     'explicit_direct_domains' => domains.uniq, 'defaults_preserved' => true}
  end
end

if __FILE__ == $0
  abort 'usage: routing_controls.rb INPUT CATALOG CONTROLS [OUTPUT]' unless (3..4).cover?(ARGV.length)
  input, catalog, controls, output = ARGV
  output ||= input
  config = YAML.load_file(input)
  result = RoutingControls.apply(config, YAML.load_file(catalog), YAML.load_file(controls))
  temporary = output + '.routing-controls-' + Process.pid.to_s
  begin
    File.open(temporary, 'w', 0600) { |f| f.write(YAML.dump(config)); f.flush; f.fsync }
    File.rename(temporary, output)
  ensure
    File.unlink(temporary) if File.exist?(temporary)
  end
  puts YAML.dump(result)
end
