require 'tmpdir'
source=File.read(File.expand_path('../agents/router.rb',__dir__)).split(/\r?\nbegin\r?\n guard=/).first
eval(source,TOPLEVEL_BINDING,'router-agent-functions')

def hash_file(path);$fixture_hashes.fetch(path);end
def uci_map(name,dir=nil);$fixture_maps.fetch(name);end
def atomic(*args);$fixture_writes<<args.first;end

Dir.mktmpdir('stack-router-safety-') do |base|
 File.write(base+'/transaction.json','{}')
 original={'dhcp.@dnsmasq[0]'=>'dnsmasq','dhcp.@dnsmasq[0].resolvfile'=>"'/tmp/resolv.conf.d/resolv.conf.auto'",'dhcp.@dnsmasq[0].cachesize'=>"'1000'",'dhcp.@dnsmasq[0].noresolv'=>"'0'",'dhcp.lan.start'=>"'100'"}
 expected={'openclash.config.core_type'=>"'TUN'",'openclash.config.redirect_dns'=>"'0'",'openclash.config.cachesize_dns'=>"'0'",'openclash.config.mixed_port'=>"'17893'"}
 system_changes=expected.merge('openclash.config.core_type'=>"'Meta'",'openclash.config.redirect_dns'=>"'1'",'openclash.config.cachesize_dns'=>"'1'",'openclash.config.dnsmasq_resolvfile'=>original['dhcp.@dnsmasq[0].resolvfile'],'openclash.config.dnsmasq_cachesize'=>"'1000'")
 redirected=original.reject{|k,_|k.end_with?('.resolvfile')}.merge('dhcp.@dnsmasq[0].server'=>"'127.0.0.1#17874'",'dhcp.@dnsmasq[0].noresolv'=>"'1'",'dhcp.@dnsmasq[0].cachesize'=>"'0'",'dhcp.@dnsmasq[0].localuse'=>"'1'")
 make=proc{{'owned_sha256'=>{'/etc/config/openclash'=>'planned'},'expected_uci'=>expected,'dhcp_before'=>original,'routing_applied'=>true,'was_running'=>false,'profile'=>{'ports'=>{'router_dns'=>17874}}}}
 $fixture_hashes={'/etc/config/openclash'=>'runtime','/etc/config/dhcp'=>'redirected'}
 $fixture_maps={'openclash'=>system_changes,'dhcp'=>redirected};$fixture_writes=[]
 t=make.call;reconcile_service_files(t,base)
 assert(t['owned_sha256']['/etc/config/openclash']=='runtime','known_service_flags_not_recognized')
 assert(t['owned_sha256']['/etc/config/dhcp']=='redirected','dns_redirect_not_recognized')
 puts 'known_service_rewrites=PASS'
 [[:uci,'openclash','openclash.config.mixed_port',"'8888'",'router_concurrent_uci_edit_restore_refused'],
  [:dhcp,'dhcp','dhcp.lan.start',"'200'",'router_concurrent_dhcp_edit_restore_refused'],
  [:dns,'dhcp','dhcp.@dnsmasq[0].server',"'9.9.9.9'",'router_concurrent_dhcp_edit_restore_refused']].each do |label,namespace,key,value,error|
  $fixture_maps={'openclash'=>system_changes.dup,'dhcp'=>redirected.dup};$fixture_maps[namespace][key]=value;$fixture_writes=[]
  begin;reconcile_service_files(make.call,base);raise 'unexpected_manual_edit_acceptance'
  rescue RuntimeError=>e;raise unless e.message==error;end
  assert($fixture_writes.empty?,'refusal_wrote_transaction')
  puts "manual_#{label}_change_refused=PASS"
 end
end
assert(private_path?({'business'=>{'now'=>'🔐 自定义节点'}},'business'),'global_private_entry_not_protected')
assert(!private_path?({'A'=>{'now'=>'B'},'B'=>{'now'=>'A'}},'A'),'cycle_detection_failed')
probe='🧪 节点能力检测';private_node='🔐 自建节点 · isolated-fixture'
protect_private_choices({probe=>'public'},{probe=>{'now'=>private_node}})
['business','GLOBAL','🔐 自定义节点'].each do |name|
 begin
  protect_private_choices({name=>'old'},{name=>{'now'=>'🔐 自定义节点'}})
  raise 'business_private_change_was_ignored'
 rescue RuntimeError=>e
  raise unless e.message=='concurrent_private_selection_restore_refused'
 end
end
puts 'probe_rotation_allowed_business_private_choices_protected=PASS'
started=Process.clock_gettime(Process::CLOCK_MONOTONIC)
assert(!bounded(['/bin/sh','-c','sleep 10'],0.1),'timeout_did_not_interrupt_child')
assert(Process.clock_gettime(Process::CLOCK_MONOTONIC)-started<3,'timeout_took_too_long')
puts 'owned_process_timeout=PASS'
