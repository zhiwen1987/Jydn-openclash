#!/usr/bin/env ruby
# Pure configuration compiler. Ruby's existing YAML support is sufficient.
require 'yaml'

module StrictCustom
  LOCAL_PROVIDER='Local_Custom'
  LOCAL_EMPTY='🔐 自建节点 · __EMPTY__'
  PROBE='🧪 节点能力检测'
  NODE = '🔐 自建节点 · '
  POOL = '🔐 自建节点池 · '
  LEGACY_SINGLE = '🔐 自定义节点 · '
  LEGACY_GROUP = '🔐 自定义节点组 · '
  SINGLE = '🔐 自定义节点'
  GROUP = SINGLE # legacy command kind; both target the single shared entry
  PREFIXES = [NODE, POOL, LEGACY_SINGLE, LEGACY_GROUP].freeze
  TYPES = %w[ss ssr vmess vless trojan socks5 http snell hysteria hysteria2 tuic wireguard].freeze
  ID = /\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}\z/
  EXCLUDE_TYPES='Direct|Pass|Compatible|Dns|Selector|URLTest|Fallback|LoadBalance|Relay'
  NOTICE_FILTER='(?i)(剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|刷新订阅|刷新失败|更新失败|取消订阅时限)'
  NON_NODE_TYPES=%w[direct reject reject-drop pass compatible dns select selector url-test fallback load-balance relay].freeze
  def self.owned?(name);name.is_a?(String) && (name==SINGLE || PREFIXES.any?{|p|name.start_with?(p)});end
  def self.legacy_entry?(name)
    name.is_a?(String) && (name.start_with?(LEGACY_SINGLE) && name!=SINGLE || name.start_with?(LEGACY_GROUP) && name!=GROUP)
  end
  def self.canonical(name)
    return name unless name.is_a?(String)
    return SINGLE if name.start_with?(LEGACY_SINGLE)
    return GROUP if name.start_with?(LEGACY_GROUP)
    name
  end
  def self.load(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
  end
  def self.private_data(value)
    raise 'private_schema_invalid' unless value.is_a?(Hash) && value['schema']==1
    nodes=value.fetch('nodes',[]);pools=value.fetch('pools',[])
    raise 'private_collections_invalid' unless nodes.is_a?(Array) && pools.is_a?(Array) && nodes.length<=100 && pools.length<=100
    parsed={}
    nodes.each do |item|
      raise 'private_node_invalid' unless item.is_a?(Hash) && ID.match?(item['id'].to_s) && !parsed.key?(item['id'])
      proxy=item['proxy'];raise 'private_protocol_invalid' unless proxy.is_a?(Hash) && TYPES.include?(proxy['type'])
      raise 'private_server_invalid' unless proxy['server'].is_a?(String) && proxy['server'].match?(/\A[a-zA-Z0-9_.:-]{1,253}\z/)
      raise 'private_port_invalid' unless proxy['port'].is_a?(Integer) && proxy['port'].between?(1,65535)
      raise 'private_path_override_forbidden' if (proxy.keys & %w[dialer-proxy routing-mark interface-name name]).any?
      parsed[item['id']]=proxy.merge('name'=>NODE+item['id'])
    end
    seen={}
    compiled=pools.map do |item|
      raise 'private_pool_invalid' unless item.is_a?(Hash) && ID.match?(item['id'].to_s) && !seen[item['id']]
      seen[item['id']]=true;ids=item.fetch('node_ids',[]);mode=item.fetch('mode','select')
      raise 'private_pool_members_invalid' unless ids.is_a?(Array) && ids.uniq==ids && ids.all?{|id|parsed.key?(id)}
      raise 'private_pool_mode_invalid' unless %w[select fallback].include?(mode)
      members=ids.map{|id|NODE+id}
      group={'name'=>POOL+item['id'],'type'=>mode,'hidden'=>true,'proxies'=>mode=='select' ? ['REJECT']+members : members+['REJECT']}
      if mode=='fallback'
        group.merge!('url'=>'https://cp.cloudflare.com/generate_204','interval'=>60,'timeout'=>5000,'lazy'=>true)
      end
      group
    end
    [parsed.values,compiled]
  end
  def self.apply(config,policy,private_value=nil,locks={'schema'=>1,'bindings'=>{}})
    if policy.is_a?(Hash) && policy['local_provider_file']
      policy=Marshal.load(Marshal.dump(policy))
      policy['local_provider']=StrictCustom.load(policy['local_provider_file'])
    end
    raise 'configuration_invalid' unless config.is_a?(Hash) && config['proxy-groups'].is_a?(Array)
    raise 'public_policy_invalid' unless policy.is_a?(Hash) && policy['schema']==1 && policy['business_groups'].is_a?(Array)
    targets=policy['business_groups'];raise 'public_business_invalid' unless targets.all?{|n|n.is_a?(String)} && targets.uniq==targets
    raise 'lock_registry_invalid' unless locks.is_a?(Hash) && locks['schema']==1 && locks['bindings'].is_a?(Hash)
    locks['bindings'].each do |name,binding|
      raise 'lock_binding_invalid' unless targets.include?(name) && binding.is_a?(Hash) && %w[node group existing].include?(binding['kind']) &&
        (binding['target']=='REJECT' || binding['kind']=='existing' && binding['target'].is_a?(String) && binding['target'].length.between?(1,512) && !binding['target'].match?(/[\x00-\x1f]/) || ID.match?(binding['target'].to_s))
    end
    original=config['proxy-groups'];existing=original.to_h{|g|[g.fetch('name'),g]}
    defaults=existing.to_h{|name,g|[name,(locks.dig('bindings',name,'original_menu') || g['proxies'] || []).first]}
    raise 'duplicate_group_name' unless existing.length==original.length
    raise 'private_profile_persistence_required' unless config.dig('profile','store-selected')==true
    status='empty_closed';nodes=[];pools=[]
    unless private_value.nil?
      begin
        nodes,pools=private_data(private_value);status=nodes.empty? ? 'empty_closed' : 'configured'
      rescue StandardError
        nodes=[];pools=[];status='invalid_closed'
      end
    end
    raw=Array(config['proxies']).reject{|n|owned?(n['name'])};config['proxies']=raw+nodes
    if policy['local_provider']
      raise 'local_provider_invalid' unless policy['local_provider'].is_a?(Hash) && policy['local_provider']['type']=='http'
      config['proxy-providers']||={}
      config['proxy-providers'][LOCAL_PROVIDER]=Marshal.load(Marshal.dump(policy['local_provider']))
    end
    config.fetch('proxy-providers',{}).each do |key,provider|
      next if key==LOCAL_PROVIDER && policy['local_provider']
      old=provider['exclude-filter'].to_s
      provider['exclude-filter']=old.empty? ? '^'+NODE : '('+old+')|^'+NODE unless old.include?(NODE)
    end
    groups=original.reject{|g|owned?(g['name'])}
    applied=[];private_names=nodes.map{|n|n['name']}
    generated=[{'name'=>SINGLE,'type'=>'select','proxies'=>['REJECT']+private_names+pools.map{|v|v['name']}}]
    if policy['select_all_nodes']==true
      names=(raw+nodes).reject{|node|NON_NODE_TYPES.include?(node['type'].to_s.downcase) || node['name'].to_s.match?(Regexp.new(NOTICE_FILTER))}.map{|node|node['name']}
      entry=generated.first;entry['proxies']=(['REJECT']+names).uniq
      entry['use']=config.fetch('proxy-providers',{}).keys unless config.fetch('proxy-providers',{}).empty?
      entry['exclude-type']=EXCLUDE_TYPES;entry['exclude-filter']=NOTICE_FILTER+(policy['local_provider'] ? '|^'+Regexp.escape(LOCAL_EMPTY)+'$' : '');entry['empty-fallback']='REJECT'
    end
    groups.each do |g|
      # Private raw nodes never enter public include-all pools.
      if policy['local_provider'] && g['name']==PROBE
        g['use']=(Array(g['use'])+[LOCAL_PROVIDER]).uniq
        old=g['exclude-filter'].to_s
        g['exclude-filter']=[old, '^'+Regexp.escape(LOCAL_EMPTY)+'$'].reject(&:empty?).uniq.join('|') unless old.include?(Regexp.escape(LOCAL_EMPTY))
      elsif policy['local_provider']
        g['use']=Array(g['use'])-[LOCAL_PROVIDER] if g['use']
      end
      if g['name']!=PROBE && (g['include-all']==true || g['include-all-proxies']==true || g['include-all-providers']==true)
        old=g['exclude-filter'].to_s
        unless old.include?(NODE)
          g['exclude-filter']=old.empty? ? '^'+NODE : '('+old+')|^'+NODE
        end
      end
      if g['proxies'].is_a?(Array)
        g['proxies'].map!{|n|n.is_a?(String) && n.start_with?(NODE) && !private_names.include?(n) ? 'REJECT' : canonical(n)}
        g['proxies'].uniq!
      end
      next unless targets.include?(g['name']) && g['type']=='select'
      raise 'business_menu_invalid' unless g['proxies'].is_a?(Array) && !g['proxies'].empty?
      single=SINGLE;pool=GROUP
      # Append; never replace the original default or current public choices.
      g['proxies']=(g['proxies']+[single,pool]).uniq
      if binding=locks['bindings'][g['name']]
        wrapper=binding['kind']=='node' ? single : pool
        # Hard allowlist survives lost cache and cannot be bypassed by auto writers.
        g['proxies']=[wrapper,'REJECT']
      end
      applied<<g['name']
    end
    added=generated+pools;names=added.to_h{|g|[g['name'],true]}
    # A removed source or pool is an explicit rejection tombstone, never DIRECT.
    original.select{|g|owned?(g['name']) && !legacy_entry?(g['name']) && !names[g['name']]}.each do |g|
      added<<{'name'=>g['name'],'type'=>'select','hidden'=>true,'proxies'=>['REJECT']}
    end
    config['proxy-groups']=groups+added
    dns_count=0
    if policy.fetch('bind_business_dns',false)
      dns=config['dns'];raise 'strict_dns_requires_fake_ip' unless dns.is_a?(Hash) && dns['enhanced-mode']=='fake-ip'
      raise 'strict_dns_bootstrap_required' if Array(dns['proxy-server-nameserver']).empty?
      normal=Array(dns['nameserver']).map{|url|url.to_s.split('#',2).first}
      direct=Array(dns['direct-nameserver']).map{|url|url.to_s.split('#',2).first}
      raise 'strict_dns_upstream_invalid' if normal.empty? || normal.any?{|u|u.empty? || u.include?('?')}
      old=dns.fetch('nameserver-policy',{})
      raise 'strict_dns_policy_invalid' unless old.is_a?(Hash)
      entries={}
      Array(config['rules']).each do |rule|
        next unless rule.is_a?(String)
        type,payload,target=rule.split(',',4);next unless applied.include?(target)
        key=case type
            when 'DOMAIN';payload
            when 'DOMAIN-SUFFIX';'+.'+payload
            when 'GEOSITE';'geosite:'+payload
            when 'RULE-SET';'rule-set:'+payload if config.dig('rule-providers',payload,'behavior')=='domain'
            end
        next unless key && !entries.key?(key)
        # Use the existing domestic upstreams for businesses whose original default
        # is DIRECT; preserve upstream servers and bind only the transport selector.
        base=defaults[target]=='DIRECT' && !direct.empty? ? direct : normal
        entries[key]=base.map{|url|url+'#'+target};dns_count+=1
      end
      dns['nameserver-policy']=old.merge(entries){|_,old_value,_|old_value}
    end
    validate(config)
    {'businesses'=>applied,'business_count'=>applied.length,'private_nodes'=>nodes.length,'private_pools'=>pools.length,
     'private_status'=>status,'dns_bindings'=>dns_count,'strict_groups'=>added.length,'persistent_locks'=>locks['bindings'].length}
  end
  def self.validate(config)
    groups=config['proxy-groups'].to_h{|g|[g['name'],g]}
    raise 'strict_duplicate_group' unless groups.length==config['proxy-groups'].length
    groups.each_value do |group|
      next unless owned?(group['name'])
      raise 'strict_type_invalid' unless %w[select fallback].include?(group['type'])
      if group['name']==SINGLE && group['empty-fallback']=='REJECT'
        expected_filter=NOTICE_FILTER+(config.fetch('proxy-providers',{}).key?(LOCAL_PROVIDER) ? '|^'+Regexp.escape(LOCAL_EMPTY)+'$' : '')
        raise 'all_nodes_selector_invalid' unless group['type']=='select' && group['proxies'].first=='REJECT' && group['exclude-type']==EXCLUDE_TYPES && group['exclude-filter']==expected_filter
        raise 'all_nodes_expansion_invalid' if group['include-all'] || group['include-all-proxies'] || group['include-all-providers']
        raise 'all_nodes_provider_invalid' unless Array(group['use']).sort==config.fetch('proxy-providers',{}).keys.sort
        raw=Array(config['proxies']).to_h{|node|[node['name'],node]}
        raise 'all_nodes_group_or_direct_escape' unless group['proxies'].all?{|name|name=='REJECT' || raw[name] && !NON_NODE_TYPES.include?(raw[name]['type'].to_s.downcase)}
        next
      end
      raise 'strict_external_provider_forbidden' if group['use'] || group['include-all'] || group['include-all-proxies'] || group['include-all-providers']
      members=group['proxies'];raise 'strict_members_invalid' unless members.is_a?(Array) && !members.empty?
      raise 'strict_foreign_escape' unless members.all?{|n|n=='REJECT' || owned?(n)}
    end
    valid=(groups.keys+Array(config['proxies']).map{|p|p['name']}+%w[DIRECT REJECT REJECT-DROP PASS COMPATIBLE]).to_h{|n|[n,true]}
    groups.each_value do |g|
      Array(g['proxies']).each{|n|raise 'dangling_proxy_reference' unless valid[n]}
    end
    visit=lambda do |name,path|
      raise 'strict_cycle' if path.include?(name)
      return unless groups[name]
      Array(groups[name]['proxies']).each{|n|visit.call(n,path+[name]) if owned?(n)}
    end
    groups.each_key{|n|visit.call(n,[]) if owned?(n)}
    true
  end
end

if __FILE__==$0
  abort 'usage: strict_custom.rb INPUT POLICY PRIVATE_OR_DASH OUTPUT [LOCKS]' unless [4,5].include?(ARGV.length)
  input,policy_path,private_path,output,locks_path=ARGV
  config=StrictCustom.load(input);policy=StrictCustom.load(policy_path)
  private_value=nil
  if private_path!='-' && File.file?(private_path)
    begin;private_value=StrictCustom.load(private_path);rescue StandardError;private_value={'schema'=>'invalid'};end
  end
  locks={'schema'=>1,'bindings'=>{}}
  if locks_path
    found=false
    [locks_path,locks_path+'.good'].each do |path|
      next unless File.file?(path)
      begin
        candidate=StrictCustom.load(path)
        if candidate.is_a?(Hash) && candidate['schema']==1 && candidate['bindings'].is_a?(Hash)
          locks=candidate;found=true;break
        end
      rescue StandardError
      end
    end
    raise 'lock_registry_unrecoverable' if !found && (File.exist?(locks_path)||File.exist?(locks_path+'.good'))
  end
  result=StrictCustom.apply(config,policy,private_value,locks)
  temp=output+'.strict-'+Process.pid.to_s
  File.open(temp,'w',0600){|f|f.write(YAML.dump(config));f.flush;f.fsync};File.rename(temp,output)
  puts YAML.dump(result)
end
