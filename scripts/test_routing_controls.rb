require 'yaml'
require_relative 'routing_controls'

def assert(value, message)
  raise message unless value
end

controls = {'stable_choice'=>'stable', 'additional_selectors'=>['default'], 'direct_domains'=>['sysceo.com','drvceo.com']}
catalog = {'business_groups'=>['business','local','strict','missing']}
config = {'proxy-groups'=>[
  {'name'=>'stable','type'=>'url-test','proxies'=>['node-a']},
  {'name'=>'business','type'=>'select','proxies'=>['parent','DIRECT','REJECT','🔐 自定义节点']},
  {'name'=>'local','type'=>'select','proxies'=>['DIRECT','REJECT']},
  {'name'=>'default','type'=>'select','proxies'=>['stable']},
  {'name'=>'🔐 自定义节点','type'=>'select','proxies'=>['REJECT','private-node']},
  {'name'=>'strict','type'=>'fallback','proxies'=>['node-a']}
], 'rules'=>['DOMAIN,test.invalid,DIRECT','MATCH,default'], 'dns'=>{'enable'=>true,'nameserver'=>['127.0.0.1']}}
before = Marshal.load(Marshal.dump(config))
result = RoutingControls.apply(config,catalog,controls)
assert(result['stable_choices_added']==2, 'wrong_changed_count')
assert(config['proxy-groups'][1]['proxies']==['parent','DIRECT','REJECT','stable','🔐 自定义节点'],'business_menu_wrong')
assert(config['proxy-groups'][2]['proxies'].first=='DIRECT','default_changed')
assert(config['proxy-groups'][0]==before['proxy-groups'][0], 'stable_members_changed')
assert(config['proxy-groups'][4]==before['proxy-groups'][4], 'strict_exit_changed')
assert(config['proxy-groups'][5]==before['proxy-groups'][5], 'automatic_pool_changed')
assert(config['dns']==before['dns'], 'dns_changed')
assert(config['rules'].last(2)==before['rules'], 'old_rule_order_changed')
assert(RoutingControls.apply(config,catalog,controls)['stable_choices_added']==0,'not_idempotent')
assert(config['rules'].count('DOMAIN-SUFFIX,sysceo.com,DIRECT')==1,'duplicate_direct_rule')
cycle={'proxy-groups'=>[{'name'=>'stable','type'=>'url-test','proxies'=>['business']}, {'name'=>'business','type'=>'select','proxies'=>['DIRECT']}], 'rules'=>['MATCH,DIRECT']}
begin
  RoutingControls.apply(cycle,catalog,controls)
  raise 'cycle_was_accepted'
rescue RuntimeError=>e
  raise unless e.message=='stable_choice_would_cycle'
end
puts 'routing_controls: defaults, idempotence, strict exit, pool isolation and cycle checks passed'
