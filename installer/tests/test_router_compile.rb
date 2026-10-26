require 'json'
require 'tmpdir'
require 'yaml'
root=File.expand_path('..',__dir__)
Dir.mktmpdir('stack-compile-') do |dir|
 [0,1,2].each do |count|
  settings={'profile'=>{},'ports'=>{'api'=>19090,'proxy'=>17893,'probe'=>17895,'router_dns'=>17874},'material'=>{'api_secret'=>'test-api-key-not-a-real-secret','proxy_auth'=>'test:fixture','probe_auth'=>'test:fixture','publish_token'=>'test-public-not-a-real-secret','local_provider_token'=>'test-local-not-a-real-secret'},'base'=>'/etc/openclash/custom/clash-stack-fixture','release'=>root+'/runtime','server'=>'192.0.2.10','source_count'=>count}
  File.write(dir+'/settings.json',JSON.generate(settings))
  ok=system('ruby',root+'/runtime/router_compile.rb',root+'/runtime/template.json',dir+'/settings.json',dir+'/result.yaml')
  raise 'compile_failed' unless ok
  y=YAML.load_file(dir+'/result.yaml');groups=y.fetch('proxy-groups');names=groups.map{|g|g['name']}
  raise 'duplicate_group' unless names.uniq==names
  custom=groups.select{|g|g['name'].include?('自定义节点')}
  raise 'duplicate_custom_entry' unless custom.length==1 && custom[0]['name']=='🔐 自定义节点'
  raise 'custom_failopen' unless custom[0]['proxies'].first=='REJECT' && custom[0]['empty-fallback']=='REJECT'
  raise 'wrong_provider_count' unless y['proxy-providers'].length==count+1
  raise 'empty_placeholder_visible' unless custom[0]['exclude-filter'].include?('__STACK_EMPTY_')
  raise 'unexpected_system_clock_write' if y.dig('ntp','write-to-system')
  listeners=y.fetch('listeners');raise 'listener_collision' if listeners.any?{|l|l['port']==y['tproxy-port']}
  raise 'incomplete_rules' unless y['rules'].length>=100
  puts "router_compile_sources_#{count}=PASS groups=#{groups.length} rules=#{y['rules'].length}"
 end
end
