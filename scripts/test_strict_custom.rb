#!/usr/bin/env ruby
require 'yaml'
require_relative 'strict_custom'
def copy(v);Marshal.load(Marshal.dump(v));end
def assert(v,message);raise message unless v;end
def fixture
 {'profile'=>{'store-selected'=>true},'proxies'=>[{'name'=>'public','type'=>'socks5','server'=>'public.invalid','port'=>1080}],
  'proxy-groups'=>[{'name'=>'Google','type'=>'select','proxies'=>['PublicPool','DIRECT']},{'name'=>'Gemini','type'=>'select','proxies'=>['PublicPool']},
   {'name'=>'PublicPool','type'=>'url-test','include-all'=>true,'proxies'=>['public']}],
  'dns'=>{'enhanced-mode'=>'fake-ip','nameserver'=>['https://1.1.1.1/dns-query#PublicPool'],'proxy-server-nameserver'=>['223.5.5.5'],
   'nameserver-policy'=>{'DOMAIN,update.googleapis.com'=>['https://223.5.5.5/dns-query#DIRECT']}},
  'rules'=>['DOMAIN-SUFFIX,google.com,Google','DOMAIN-SUFFIX,gemini.google.com,Gemini','MATCH,DIRECT']}
end
POLICY={'schema'=>1,'business_groups'=>['Google','Gemini'],'bind_business_dns'=>true}
PRIVATE={'schema'=>1,'nodes'=>[{'id'=>'own-a','proxy'=>{'type'=>'socks5','server'=>'127.0.0.1','port'=>19001}}],
 'pools'=>[{'id'=>'mine','mode'=>'fallback','node_ids'=>['own-a']}]}
tests={
 'empty_entries_are_reject'=>lambda do
  y=fixture;r=StrictCustom.apply(y,POLICY);assert(r['private_status']=='empty_closed','empty status')
  y['proxy-groups'].select{|g|StrictCustom.owned?(g['name'])}.each{|g|assert(g['proxies']==['REJECT'],'empty pool escapes')}
 end,
 'defaults_rules_upstreams_preserved'=>lambda do
  y=fixture;before=copy(y);StrictCustom.apply(y,POLICY)
  assert(y['rules']==before['rules'],'rule changes');assert(y['dns']['nameserver']==before['dns']['nameserver'],'upstream changes')
  before['proxy-groups'].first(2).each{|g|now=y['proxy-groups'].find{|x|x['name']==g['name']};assert(now['proxies'].first(g['proxies'].length)==g['proxies'],'existing menu changes')}
 end,
 'shared_entries_independent_business_choices'=>lambda do
  y=fixture;StrictCustom.apply(y,POLICY,PRIVATE);g=y['proxy-groups'].to_h{|v|[v['name'],v]}
  assert(g['Google']['proxies'].include?(StrictCustom::SINGLE),'Google missing');assert(g['Gemini']['proxies'].include?(StrictCustom::SINGLE),'Gemini shared entry missing')
  assert(g.keys.count{|name|name==StrictCustom::SINGLE}==1,'duplicated shared entry')
  assert(g.keys.none?{|name|StrictCustom.legacy_entry?(name)},'legacy entry remains')
 end,
 'only_approved_members'=>lambda do
  y=fixture;StrictCustom.apply(y,POLICY,PRIVATE);StrictCustom.validate(y)
  pool=y['proxy-groups'].find{|g|g['name']==StrictCustom::POOL+'mine'};assert(pool['proxies']==[StrictCustom::NODE+'own-a','REJECT'],'foreign pool member')
 end,
 'invalid_and_missing_private_fail_closed'=>lambda do
  [{'schema'=>1,'nodes'=>[{'id'=>'bad','proxy'=>{'type'=>'direct'}}]},'invalid',nil].each do |v|
   y=fixture;StrictCustom.apply(y,POLICY,v);assert(y['proxy-groups'].select{|g|StrictCustom.owned?(g['name'])}.all?{|g|g['proxies']==['REJECT']},'invalid input leaks')
  end
 end,
 'foreign_pool_reference_rejected'=>lambda do
  v=copy(PRIVATE);v['pools'][0]['node_ids']=['public'];y=fixture;r=StrictCustom.apply(y,POLICY,v);assert(r['private_status']=='invalid_closed','foreign member accepted')
 end,
 'external_dialer_rejected'=>lambda do
  v=copy(PRIVATE);v['nodes'][0]['proxy']['dialer-proxy']='PublicPool';y=fixture;r=StrictCustom.apply(y,POLICY,v);assert(r['private_status']=='invalid_closed','external chain accepted')
 end,
 'idempotent_rewrite_and_removed_nodes'=>lambda do
  y=fixture;StrictCustom.apply(y,POLICY,PRIVATE);first=copy(y);StrictCustom.apply(y,POLICY,PRIVATE);assert(y==first,'not idempotent')
  StrictCustom.apply(y,POLICY,{'schema'=>1,'nodes'=>[],'pools'=>[]});assert(y['proxy-groups'].select{|g|StrictCustom.owned?(g['name'])}.all?{|g|g['proxies']==['REJECT']},'removed node leaks')
 end,
 'private_nodes_excluded_from_public_include_all'=>lambda do
  y=fixture;StrictCustom.apply(y,POLICY,PRIVATE);g=y['proxy-groups'].find{|v|v['name']=='PublicPool'}
  assert(Regexp.new(g['exclude-filter']).match?(StrictCustom::NODE+'own-a'),'public pool includes private')
  assert(!Regexp.new(g['exclude-filter']).match?('public'),'normal node excluded')
 end,
 'dns_follows_each_business_preserves_direct_exception'=>lambda do
  y=fixture;StrictCustom.apply(y,POLICY);p=y['dns']['nameserver-policy']
  assert(p['+.google.com']==['https://1.1.1.1/dns-query#Google'],'Google DNS wrong')
  assert(p['+.gemini.google.com']==['https://1.1.1.1/dns-query#Gemini'],'Gemini DNS coupled')
  assert(p['DOMAIN,update.googleapis.com']==['https://223.5.5.5/dns-query#DIRECT'],'direct exception overridden')
 end,
 'missing_selection_persistence_rejected'=>lambda do
  y=fixture;y['profile']['store-selected']=false
  begin;StrictCustom.apply(y,POLICY);raise 'missing persistence accepted';rescue RuntimeError=>e;raise unless e.message=='private_profile_persistence_required';end
 end,
 'strict_graph_foreign_escape_rejected'=>lambda do
  y=fixture;StrictCustom.apply(y,POLICY);y['proxy-groups'].last['proxies']<<'DIRECT'
  begin;StrictCustom.validate(y);raise 'DIRECT accepted';rescue RuntimeError=>e;raise unless e.message=='strict_foreign_escape';end
 end
}
tests.each{|name,test|test.call;puts 'PASS '+name}
locks={'schema'=>1,'bindings'=>{'Google'=>{'kind'=>'node','target'=>'own-a','original_menu'=>['PublicPool','DIRECT']}}}
y=fixture;StrictCustom.apply(y,POLICY,PRIVATE,locks);g=y['proxy-groups'].to_h{|v|[v['name'],v]}
assert(g['Google']['proxies']==[StrictCustom::SINGLE,'REJECT'],'durable outer escapes')
assert(g[StrictCustom::SINGLE]['proxies'].first=='REJECT' && g[StrictCustom::SINGLE]['proxies'].include?(StrictCustom::NODE+'own-a'),'durable shared target escapes')
assert(g['Gemini']['proxies'].first=='PublicPool','durable lock affects Gemini');puts 'PASS persistent_allowlist_without_cache'
StrictCustom.apply(y,POLICY,nil,locks);g=y['proxy-groups'].to_h{|v|[v['name'],v]}
assert(g['Google']['proxies']==[StrictCustom::SINGLE,'REJECT'] && g[StrictCustom::SINGLE]['proxies']==['REJECT'],'missing durable target escapes')
puts 'PASS persistent_missing_node_rejects'
y=fixture
%w[Google Gemini].each do |name|
 old_single=StrictCustom::LEGACY_SINGLE+name;old_group=StrictCustom::LEGACY_GROUP+name
 y['proxy-groups'].find{|g|g['name']==name}['proxies'] += [old_single,old_group]
 y['proxy-groups'] += [{'name'=>old_single,'type'=>'select','proxies'=>['REJECT']},{'name'=>old_group,'type'=>'select','proxies'=>['REJECT']}]
end
rules=copy(y['rules']);StrictCustom.apply(y,POLICY);assert(y['rules']==rules,'migration changed rules')
assert(y['proxy-groups'].none?{|g|StrictCustom.legacy_entry?(g['name']) || Array(g['proxies']).any?{|n|StrictCustom.legacy_entry?(n)}},'migration retained old entries')
assert(y['proxy-groups'].count{|g|g['name']==StrictCustom::SINGLE}==1,'migration did not keep exactly one')
puts 'PASS remove_legacy_groups_and_references'
puts 'strict_custom_tests='+(tests.length+3).to_s
