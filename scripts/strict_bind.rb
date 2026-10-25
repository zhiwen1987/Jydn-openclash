#!/usr/bin/env ruby
# Persistent, business-only binding. Run locally on the intended OpenWrt router.
require 'yaml'
compiler=File.join(__dir__,'jydn_strict_custom.rb');compiler=File.join(__dir__,'strict_custom.rb') unless File.file?(compiler);require compiler
recovery=File.join(__dir__,'jydn_strict_router_recovery.rb');recovery=File.join(__dir__,'strict_custom_router_recovery.rb') unless File.file?(recovery);require recovery
module StrictBind
  ROOT='/etc/openclash/custom'
  def self.execute(business,kind,target,unlock=false)
    File.open(ROOT+'/.strict-bind.lock',File::RDWR|File::CREAT,0600) do |lock|
      raise 'binding_operation_busy' unless lock.flock(File::LOCK_EX|File::LOCK_NB)
      execute_locked(business,kind,target,unlock)
    end
  end
  def self.execute_locked(business,kind,target,unlock=false)
    raise 'wrong_router_identity' unless File.read('/sys/class/net/br-lan/address').strip=='00:0c:29:2d:96:e8'
    r=StrictRouterRecovery;source=r.sh('uci','-q','get','openclash.config.config_path');raise 'unexpected_source' unless source.start_with?('/etc/openclash/config/') && source.end_with?('.yaml')
    runtime='/etc/openclash/'+File.basename(source);policy=StrictCustom.load(ROOT+'/strict-custom-policy.json')
    raise 'business_not_supported' unless policy['business_groups'].include?(business)
    private_value=StrictCustom.load(ROOT+'/strict-custom-private.yaml');nodes,pools=StrictCustom.private_data(private_value)
    path=ROOT+'/strict-custom-locks.yaml';locks=nil
    [path,path+'.good'].each do |file|
      next unless File.file?(file)
      begin
        value=StrictCustom.load(file)
        if value.is_a?(Hash) && value['schema']==1 && value['bindings'].is_a?(Hash);locks=value;break;end
      rescue StandardError
      end
    end
    locks||={'schema'=>1,'bindings'=>{}} unless File.exist?(path)||File.exist?(path+'.good')
    raise 'lock_registry_invalid' unless locks.is_a?(Hash) && locks['schema']==1 && locks['bindings'].is_a?(Hash)
    old_binding=locks['bindings'][business]
    raise 'no_persistent_binding' if unlock && !old_binding
    raise 'binding_kind_invalid' unless unlock || %w[node group].include?(kind)
    allowed=kind=='node' ? nodes.map{|n|n['name']} : pools.map{|p|p['name']}
    full_target=target=='REJECT' ? 'REJECT' : (kind=='node' ? StrictCustom::NODE : StrictCustom::POOL)+target.to_s
    raise 'private_target_missing' unless unlock || full_target=='REJECT' || allowed.include?(full_target)
    before=r.api('/proxies')['proxies'];outer=before.fetch(business)
    wrapper=(unlock ? (old_binding['kind']=='node' ? StrictCustom::SINGLE : StrictCustom::GROUP) : (kind=='node' ? StrictCustom::SINGLE : StrictCustom::GROUP))+business
    fence=old_binding ? (old_binding['kind']=='node' ? StrictCustom::SINGLE : StrictCustom::GROUP)+business : wrapper
    raise 'strict_entry_not_installed' unless before[wrapper] && before[fence] && outer['all'].include?(fence)
    backup='/root/openclash-backups/strict-bind-'+Time.now.to_i.to_s+'-'+Process.pid.to_s;r.sh('mkdir','-m','700',backup)
    {'source'=>source,'runtime'=>runtime,'private'=>ROOT+'/strict-custom-private.yaml','locks'=>path}.each do |name,file|
      next unless File.file?(file);r.atomic(backup+'/'+name+'.before',File.binread(file))
    end
    original_menu=old_binding ? old_binding.fetch('original_menu') : outer['all']
    previous=old_binding ? old_binding['previous_selected'] : outer['now']
    if unlock;locks['bindings'].delete(business)
    else;locks['bindings'][business]={'kind'=>kind,'target'=>target,'original_menu'=>original_menu,'previous_selected'=>previous}
    end
    # Compile and validate before changing active routing or durable inputs.
    %w[source runtime].each do |label|
      file=label=='source' ? source : runtime;y=StrictCustom.load(file)
      y['proxy-groups'].find{|g|g['name']==business}['proxies']=original_menu if unlock
      local_policy=Marshal.load(Marshal.dump(policy));local_policy['bind_business_dns']=false if label=='source' && y.dig('dns','enhanced-mode')!='fake-ip'
      StrictCustom.apply(y,local_policy,private_value,locks)
      r.atomic(backup+'/'+label+'.candidate',YAML.dump(y))
    end
    validation=StrictCustom.load(backup+'/runtime.candidate')
    %w[external-ui external-ui-url external-ui-name].each{|key|validation.delete(key)}
    r.atomic(backup+'/validation.yaml',YAML.dump(validation))
    ok=system('/etc/openclash/core/clash_meta','-t','-d','/etc/openclash','-f',backup+'/validation.yaml',out:backup+'/validation.log',err:backup+'/validation.log')
    raise 'native_validation_failed_no_routing_changed' unless ok
    # Fence first, then drain this business. Never close unrelated connections.
    r.api('/proxies/'+r.uri(fence),'PUT',{'name'=>'REJECT'});r.api('/proxies/'+r.uri(business),'PUT',{'name'=>fence})
    closed=0
    3.times do
      rows=(r.api('/connections')['connections'] || []).select{|v|v.fetch('chains',[]).include?(business)}
      break if rows.empty?
      rows.each do |v|
        r.api('/connections/'+r.uri(v.fetch('id')),'DELETE');closed+=1
      end
    end
    raise 'old_connections_not_drained_left_closed' unless (r.api('/connections')['connections'] || []).none?{|v|v.fetch('chains',[]).include?(business)}
    r.atomic(path,YAML.dump(locks));r.atomic(path+'.good',YAML.dump(locks))
    %w[source runtime].each do |label|
      file=label=='source' ? source : runtime;r.atomic(file,File.binread(backup+'/'+label+'.candidate'))
    end
    # On an API error, keep the fence and durable lock; never restore public fallback.
    r.api('/configs?force=true','PUT',{'path'=>runtime})
    if unlock
      current=r.api('/proxies/'+r.uri(business));selected=current['all'].include?(previous) ? previous : original_menu.first
      r.api('/proxies/'+r.uri(business),'PUT',{'name'=>selected})
    else
      current=r.api('/proxies/'+r.uri(business));raise 'persistent_allowlist_not_applied' unless current['all'].sort==[wrapper,'REJECT'].sort
      r.api('/proxies/'+r.uri(business),'PUT',{'name'=>wrapper});r.api('/proxies/'+r.uri(wrapper),'PUT',{'name'=>full_target})
    end
    {'business'=>business,'persistent_locked'=>!unlock,'private_target'=>unlock ? nil : full_target,'connections_closed'=>closed,'backup'=>backup}
  end
end
if __FILE__==$0
  raise 'usage: strict_bind.rb BUSINESS node|group TARGET_ID_OR_REJECT / BUSINESS unlock' unless ARGV.length==3 || ARGV.length==2 && ARGV[1]=='unlock'
  business,kind,target=ARGV
  puts YAML.dump(StrictBind.execute(business,kind,target,kind=='unlock'))
end
