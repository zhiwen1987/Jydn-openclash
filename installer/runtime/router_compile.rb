# Runs last in OpenClash's overwrite hook. No production credentials in source.
require 'yaml'
require_relative 'strict_custom'

abort 'usage: router_compile.rb INPUT SETTINGS OUTPUT' unless ARGV.length==3
input,settings_path,output=ARGV
settings=YAML.load_file(settings_path);p=settings.fetch('profile');ports=settings.fetch('ports');m=settings.fetch('material')
config=YAML.load_file(input)
base=settings.fetch('base');release=settings.fetch('release')
abort 'managed base invalid' unless base.match?(%r{\A/etc/openclash/custom/clash-stack-[a-z][a-z0-9-]{0,31}\z})
config['profile']||={};config['profile']['store-selected']=true
config['external-controller']='0.0.0.0:'+ports.fetch('api').to_s;config['secret']=m.fetch('api_secret')
config['mixed-port']=ports.fetch('proxy');config['allow-lan']=true;config['bind-address']='*'
config['authentication']=[m.fetch('proxy_auth')]
config['port']=0;config['socks-port']=0
config['ntp']={'enable'=>false}
config['geodata-loader']='memconservative'
config['ipv6']=false;config['mode']='rule'
config['dns']||={};config['dns']['enable']=true;config['dns']['listen']='0.0.0.0:'+ports.fetch('router_dns').to_s
config['dns']['enhanced-mode']='fake-ip';config['dns']['respect-rules']=true
old_public=config.fetch('proxy-providers',{}).keys-['Local_Custom']
providers={}
Integer(settings.fetch('source_count')).times do |index|
 name='Public_'+(index+1).to_s
 providers[name]={'type'=>'http','url'=>'http://'+settings.fetch('server')+':'+ports.fetch('subscription').to_s+'/providers/public'+(index+1).to_s+'.yaml','path'=>base+'/cache/'+name+'.yaml','proxy'=>'DIRECT','interval'=>3600,'header'=>{'Authorization'=>['Bearer '+m.fetch('publish_token')]},'payload'=>[{'name'=>'__STACK_EMPTY_'+name,'type'=>'reject'}],'health-check'=>{'enable'=>true,'url'=>'https://www.gstatic.com/generate_204','interval'=>300,'lazy'=>true}}
end
config['proxy-providers']=providers
group_names=config.fetch('proxy-groups').map{|g|g['name']}
config['proxy-groups'].each do |g|
 if g['use'] && (g['use'] & old_public).any?
  g['use']=((g['use']-old_public-['Local_Custom'])+providers.keys).uniq
 end
 g['proxies']=Array(g['proxies']).select{|name|group_names.include?(name)||%w[DIRECT REJECT REJECT-DROP PASS].include?(name)} if g.key?('proxies')
 g['empty-fallback']='REJECT'
 if g['use'] || g['include-all'] || g['include-all-providers']
  old=g['exclude-filter'].to_s
  g['exclude-filter']=[old,'^__STACK_EMPTY_'].reject(&:empty?).uniq.join('|') unless old.include?('__STACK_EMPTY_')
 end
 if Array(g['proxies']).empty? && Array(g['use']).empty? && !g['include-all']
  g['proxies']=['REJECT']
 end
 if g['name']=='⚫ Grok 稳定节点池'
  g['type']='select';g['proxies']=['REJECT'];g['use']=providers.keys;g['filter']='(?i)(美国|United States|US[ -]|🇺🇸)'
 end
end
probe='🧪 节点能力检测'
group=config['proxy-groups'].find{|g|g['name']==probe}
unless group;group={'name'=>probe,'type'=>'select'};config['proxy-groups']<<group;end
group['proxies']=['REJECT'];group['use']=providers.keys;group['empty-fallback']='REJECT';group['exclude-filter']='^__STACK_EMPTY_'
user,password=m.fetch('probe_auth').split(':',2)
config['listeners']=Array(config['listeners']).reject{|l|l['name']=='node-capability-probe'}
config['listeners']<<{'name'=>'node-capability-probe','type'=>'mixed','listen'=>'0.0.0.0','port'=>ports.fetch('probe'),'udp'=>false,'users'=>[{'username'=>user,'password'=>password}],'proxy'=>probe}
local={'type'=>'http','url'=>'http://'+settings.fetch('server')+':'+ports.fetch('subscription').to_s+'/providers/local-custom.yaml','path'=>base+'/cache/local.yaml','proxy'=>'DIRECT','interval'=>3600,'header'=>{'Authorization'=>['Bearer '+m.fetch('local_provider_token')]},'payload'=>[{'name'=>StrictCustom::LOCAL_EMPTY,'type'=>'reject'}],'health-check'=>{'enable'=>false}}
policy=YAML.load_file(release+'/strict-custom-policy.json');policy['local_provider']=local
locks=File.file?(base+'/locks.json') ? YAML.load_file(base+'/locks.json') : {'schema'=>1,'bindings'=>{}}
private_value=File.file?(base+'/private.yaml') ? YAML.load_file(base+'/private.yaml') : {'schema'=>1,'nodes'=>[],'pools'=>[]}
StrictCustom.apply(config,policy,private_value,locks)
tmp=output+'.stack-'+Process.pid.to_s
File.open(tmp,'w',0600){|f|f.write(YAML.dump(config));f.flush;f.fsync};File.rename(tmp,output)
