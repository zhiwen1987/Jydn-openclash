require 'yaml'
require_relative 'strict_custom'
abort 'usage: strict_fixture_configs.rb OUTPUT_DIR' unless ARGV.length==1
root=ARGV.first;Dir.mkdir(root) unless Dir.exist?(root)
base={
 'allow-lan'=>false,'bind-address'=>'127.0.0.1','mixed-port'=>19445,'external-controller'=>'127.0.0.1:19447','secret'=>'isolated-lab-only','ipv6'=>false,'log-level'=>'error','mode'=>'rule',
 'profile'=>{'store-selected'=>true,'store-fake-ip'=>false},'proxies'=>[],
 'hosts'=>{'google.strict.invalid'=>'127.0.0.1','gemini.strict.invalid'=>'127.0.0.1'},
 'proxy-groups'=>[{'name'=>'Google','type'=>'select','proxies'=>['PublicPool']},{'name'=>'Gemini','type'=>'select','proxies'=>['PublicPool']},{'name'=>'PublicPool','type'=>'select','proxies'=>['DIRECT']}],
 'dns'=>{'enable'=>true,'listen'=>'127.0.0.1:19456','enhanced-mode'=>'fake-ip','fake-ip-range'=>'198.18.0.1/16','fake-ip-filter'=>['+.strict.invalid'],'use-hosts'=>true,'respect-rules'=>true,
  'default-nameserver'=>['127.0.0.1'],'nameserver'=>['tcp://127.0.0.1:19455#PublicPool'],'proxy-server-nameserver'=>['tcp://127.0.0.1:19455']},
 'rules'=>['DOMAIN-SUFFIX,google.strict.invalid,Google','DOMAIN-SUFFIX,gemini.strict.invalid,Gemini','MATCH,REJECT']}
policy={'schema'=>1,'business_groups'=>['Google','Gemini'],'bind_business_dns'=>true}
private_value={'schema'=>1,'nodes'=>[
 {'id'=>'own-good','proxy'=>{'type'=>'socks5','server'=>'127.0.0.1','port'=>19441}},
 {'id'=>'own-bad','proxy'=>{'type'=>'socks5','server'=>'127.0.0.1','port'=>19449}}],
 'pools'=>[{'id'=>'mine','mode'=>'fallback','node_ids'=>['own-bad','own-good']}]}
[['empty',nil],['configured',private_value],['locked',private_value]].each do |name,private_data|
 locks={'schema'=>1,'bindings'=>{}}
 locks['bindings']['Google']={'kind'=>'node','target'=>'own-good','original_menu'=>['PublicPool']} if name=='locked'
 y=Marshal.load(Marshal.dump(base));StrictCustom.apply(y,policy,private_data,locks)
 y['proxy-groups'].select{|g|g['type']=='fallback'}.each{|g|g['url']='http://127.0.0.1:19440/';g['interval']=1;g['timeout']=500}
 File.write(root+'/'+name+'.yaml',YAML.dump(y));File.chmod(0600,root+'/'+name+'.yaml')
end
fixture={
 'allow-lan'=>false,'bind-address'=>'127.0.0.1','mixed-port'=>19441,'external-controller'=>'127.0.0.1:19446','secret'=>'isolated-lab-only','ipv6'=>false,'log-level'=>'error',
 'hosts'=>base['hosts'],'profile'=>{'store-selected'=>false},'rules'=>['MATCH,DIRECT'],
 'dns'=>{'enable'=>true,'listen'=>'127.0.0.1:19455','enhanced-mode'=>'fake-ip','fake-ip-range'=>'198.18.0.1/16','fake-ip-filter'=>[],'nameserver'=>['127.0.0.1']}}
File.write(root+'/fixture.yaml',YAML.dump(fixture));File.chmod(0600,root+'/fixture.yaml')
puts 'fixtures_written=4'
