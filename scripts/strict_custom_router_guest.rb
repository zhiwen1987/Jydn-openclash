require 'yaml'
abort 'Router identity mismatch' unless File.read('/sys/class/net/br-lan/address').strip=='00:0c:29:2d:96:e8'
def sh(*args)
 out=IO.popen(args,err:File::NULL){|io|io.read};raise "Read/operation failed: #{args.first}" unless $?.success?;out.strip
end
def hash_file(path);sh('sha256sum',path).split.first;end
def api(path)
 secret=sh('uci','-q','get','openclash.config.dashboard_password')
 YAML.load(sh('curl','-fsS','--max-time','10','-H','Authorization: Bearer '+secret,'http://127.0.0.1:9090'+path))
end
source=sh('uci','-q','get','openclash.config.config_path')
abort 'Unexpected source' unless source=='/etc/openclash/config/精准稳定-v1-r4-ha-subscription-managed.yaml'
runtime='/etc/openclash/'+File.basename(source)
paths={'source'=>source,'runtime'=>runtime,'uci'=>'/etc/config/openclash','overwrite'=>'/etc/openclash/custom/openclash_custom_overwrite.sh'}
paths['group_filter']='/etc/openclash/custom/jydn_patch_runtime_groups.rb'
paths['catalog']='/etc/openclash/custom/jydn_business_group_catalog.json'
files=paths.transform_values{|p|File.file?(p) ? {'path'=>p,'sha256'=>hash_file(p),'bytes'=>File.size(p)} : {'path'=>p,'missing'=>true}}
case ARGS.fetch('phase')
when 'observe'
 b=ARGS.fetch('router');require b+'/stage/strict_custom_router_recovery';r=StrictRouterRecovery;y=YAML.load_file(runtime)
 port=y['mixed-port'].to_i;port=y['port'].to_i if port==0;raise 'http_proxy_listener_missing' if port==0
 tests={}
 {'google'=>'https://www.google.com/generate_204','github'=>'https://github.com/','domestic'=>'https://www.baidu.com/'}.each do |name,url|
  config='url = '+r.json(url)+"\nproxy = "+r.json('http://127.0.0.1:'+port.to_s)+"\n"
  auth=Array(y['authentication']).first;config+='proxy-user = '+r.json(auth)+"\n" if auth
  output=IO.popen(['curl','-sS','--max-time','12','-o','/dev/null','-w','%{http_code} %{time_total}','--config','-'],'r+',err:File::NULL){|f|f.write(config);f.close_write;f.read}
  tests[name]={'http_code'=>output.split.first,'seconds'=>output.split.last,'curl_ok'=>$?.success?}
 end
 now=r.api('/proxies')['proxies'];result={'identity'=>'00:0c:29:2d:96:e8','probes'=>tests,'rule_count'=>r.api('/rules')['rules'].length,'groups'=>now.values.count{|v|v.key?('all')},'mode'=>r.api('/configs')['mode'],'source_sha256'=>hash_file(source)}
 r.atomic(b+'/observation-'+Time.now.to_i.to_s+'.yaml',YAML.dump(result));puts YAML.dump(result)
when 'preflight'
 if ARGS['router'] && File.file?(ARGS['router']+'/stage/core-validation.log')
  lines=File.readlines(ARGS['router']+'/stage/core-validation.log').last(12).map{|line|line.gsub(/https?:\/\/\S+/,'[URL]').gsub(/(secret|password|token|authentication)\s*[:=]\s*\S+/i,'\\1=[REDACTED]')}
  puts YAML.dump({'identity'=>'00:0c:29:2d:96:e8','stage_diagnostics'=>lines});exit 0
 end
 y=YAML.load_file(runtime);p=api('/proxies')['proxies'];catalog=YAML.load_file(paths['catalog']) rescue {}
 puts YAML.dump({'identity'=>'00:0c:29:2d:96:e8','source'=>source,'files'=>files,'selectors'=>Array(y['proxy-groups']).select{|g|g['type']=='select'}.map{|g|{'name'=>g['name'],'proxies'=>g['proxies'],'use'=>g['use']}},
  'catalog_businesses'=>catalog['business_groups'],'profile'=>y['profile'],'dns'=>{'enable'=>y.dig('dns','enable'),'mode'=>y.dig('dns','enhanced-mode'),'respect_rules'=>y.dig('dns','respect-rules'),'policy_keys'=>y.dig('dns','nameserver-policy')&.keys},
  'ipv6'=>y['ipv6'],'rule_count'=>api('/rules')['rules'].length,'group_count'=>p.values.count{|v|v.key?('all')},'overwrite_hooks'=>File.readlines(paths['overwrite']).grep(/ruby|jydn|grok|CONFIG_FILE/).reject{|line|line.match?(/password|secret|token|auth|https?:/i)}})
when 'backup'
 b='/root/openclash-backups/strict-custom-20261026-'+Time.now.to_i.to_s;abort 'Backup exists' if File.exist?(b)
 sh('mkdir','-m','700',b)
 paths.each{|k,path|next unless File.file?(path);sh('cp',path,b+'/'+k+'.before');File.chmod(0600,b+'/'+k+'.before')}
 manifest={'backup'=>b,'files'=>files,'rules'=>api('/rules')['rules'].map{|r|r.slice('type','payload','proxy')},'groups'=>api('/proxies')['proxies'].select{|_,g|g.key?('all')}.transform_values{|g|g.slice('type','all','now')}}
 File.write(b+'/manifest.yaml',YAML.dump(manifest));File.chmod(0600,b+'/manifest.yaml')
 abort 'Backup checksum failed' unless files.all?{|k,v|v['missing']||hash_file(b+'/'+k+'.before')==v['sha256']}
 puts YAML.dump({'backup'=>b,'files_verified'=>files.values.count{|v|!v['missing']},'production_restarted'=>false})
when 'stage'
 b=ARGS.fetch('router');abort 'Unexpected backup location' unless b.start_with?('/root/openclash-backups/strict-custom-20261026-') && File.directory?(b)
 stage=b+'/stage';sh('mkdir','-p',stage);File.chmod(0700,stage)
 BUNDLE.each{|name,encoded|abort 'Unsafe staged filename' if name.include?('/');File.write(stage+'/'+name,encoded.unpack1('m0'));File.chmod(0600,stage+'/'+name)}
 result=sh('ruby','-E','UTF-8',stage+'/test_strict_custom.rb');File.write(stage+'/unit-tests.log',result)
 require stage+'/strict_custom'
 policy=StrictCustom.load(stage+'/strict-custom-policy.json')
 stats={}
 ['source','runtime'].each do |label|
  y=StrictCustom.load(paths[label]);before=Marshal.load(Marshal.dump(y))
  if label=='source'
   y['profile']||={};y['profile']['store-selected']=true
  end
  local_policy=Marshal.load(Marshal.dump(policy));local_policy['bind_business_dns']=false if label=='source' && y.dig('dns','enhanced-mode')!='fake-ip'
  stats[label]=StrictCustom.apply(y,local_policy)
  abort 'Rules changed by strict compiler' unless y['rules']==before['rules']
  before['proxy-groups'].reject{|g|StrictCustom.owned?(g['name'])}.each do |g|
   next unless g['proxies'].is_a?(Array)
   new_g=y['proxy-groups'].find{|v|v['name']==g['name']};abort 'Existing menu order changed' unless new_g['proxies'].first(g['proxies'].length)==g['proxies']
  end
  File.write(stage+'/'+label+'.yaml',YAML.dump(y));File.chmod(0600,stage+'/'+label+'.yaml')
 end
 sh('ruby','-E','UTF-8',stage+'/strict_fixture_configs.rb',stage+'/fixtures')
 y=StrictCustom.load(stage+'/runtime.yaml');validation=stage+'/validation';sh('mkdir','-p',validation)
 # A parser-only copy has no dashboard. Keep every production path restriction.
 y.delete('external-ui');y.delete('external-ui-url');y.delete('external-ui-name')
 %w[GeoSite.dat GeoIP.dat Country.mmdb ASN.mmdb].each do |name|
  from='/etc/openclash/'+name;to=validation+'/'+name;File.symlink(from,to) if File.file?(from) && !File.exist?(to)
 end
 %w[proxy-providers rule-providers].each do |key|
  y.fetch(key,{}).each do |name,item|
   next unless item['path']
   src=File.expand_path(item['path'],'/etc/openclash');next unless File.file?(src)
   dest=validation+'/'+key+'-'+name.gsub(/[^A-Za-z0-9_.-]/,'_')+'.yaml';sh('cp',src,dest);File.chmod(0600,dest);item['path']=dest
  end
 end
 File.write(validation+'/config.yaml',YAML.dump(y));File.chmod(0600,validation+'/config.yaml')
 ok=system('/etc/openclash/core/clash_meta','-t','-d',validation,'-f',validation+'/config.yaml',out:stage+'/core-validation.log',err:stage+'/core-validation.log')
 abort 'Native core candidate validation failed; inspect private log' unless ok
 puts YAML.dump({'staged'=>true,'unit_test_count'=>result[/strict_custom_tests=(\d+)/,1].to_i,'native_core_test_passed'=>true,'stats'=>stats,'kernel_sha256'=>hash_file('/etc/openclash/core/clash_meta')})
when 'activate_router'
 b=ARGS.fetch('router');stage=b+'/stage';require stage+'/strict_custom_router_recovery'
 recovery=StrictRouterRecovery;m=recovery.verify(b);abort 'Activation already attempted' if File.exist?(b+'/activated_router.yaml')
 %w[source runtime overwrite].each{|k|abort 'Production changed during rehearsal' unless hash_file(paths[k])==m['files'][k]['sha256']}
 abort 'Rule mode required' unless recovery.api('/configs')['mode'].to_s.downcase=='rule'
 before=recovery.api('/proxies')['proxies'];choices=before.select{|name,g|g['type']=='Selector'}.transform_values{|g|g['now']}
 hook=File.read(paths['overwrite']);marker='# BEGIN JYDN STRICT CUSTOM'
 abort 'Strict hook already present' if hook.include?(marker)
 block="\n#{marker}\n/etc/openclash/custom/jydn_strict_custom_hook.sh \"$CONFIG_FILE\" || exit 1\n# END JYDN STRICT CUSTOM\n"
 if hook.match?(/^exit 0\s*$/);hook=hook.sub(/^exit 0\s*$/,block+"\nexit 0\n");else;hook+=block;end
 File.write(stage+'/overwrite.sh',hook);abort 'Overwrite shell syntax failed' unless system('bash','-n',stage+'/overwrite.sh')
 source_bytes=File.binread(stage+'/source.yaml');runtime_bytes=File.binread(stage+'/runtime.yaml')
 owned={'source'=>hash_file(stage+'/source.yaml'),'runtime'=>hash_file(stage+'/runtime.yaml'),'overwrite'=>hash_file(stage+'/overwrite.sh')}
 unit='jydn-strict-'+Time.now.to_i.to_s
 a={'started_at'=>Time.now.to_i,'choices'=>choices,'rules'=>recovery.api('/rules')['rules'].map{|r|r.slice('type','payload','proxy')},
    'owned_sha256'=>owned,'modes'=>%w[source runtime overwrite].to_h{|k|[k,File.stat(paths[k]).mode & 0777]},'guard_service'=>unit,'strict_group_count'=>138}
 recovery.atomic(b+'/activated_router.yaml',YAML.dump(a))
 init="#!/bin/sh /etc/rc.common\nSTART=99\nUSE_PROCD=1\nstart_service() {\n procd_open_instance\n procd_set_param command /usr/bin/ruby #{stage}/strict_custom_router_recovery.rb guardloop #{b}\n procd_set_param stderr 1\n procd_close_instance\n}\n"
 abort 'Guard service already exists' if File.exist?('/etc/init.d/'+unit)
 File.write('/etc/init.d/'+unit,init);File.chmod(0755,'/etc/init.d/'+unit)
 sh('/etc/init.d/'+unit,'enable');sh('/etc/init.d/'+unit,'start')
 recovery.atomic(b+'/PUBLISHING','active')
 begin
  install={'strict_custom.rb'=>'jydn_strict_custom.rb','strict_bind.rb'=>'jydn_strict_bind.rb','strict_custom_router_recovery.rb'=>'jydn_strict_router_recovery.rb','jydn_strict_custom_hook.sh'=>'jydn_strict_custom_hook.sh','strict-custom-policy.json'=>'strict-custom-policy.json'}
  install.each{|from,to|recovery.atomic('/etc/openclash/custom/'+to,File.binread(stage+'/'+from),to.end_with?('.sh') ? 0755 : 0600)}
  private_path='/etc/openclash/custom/strict-custom-private.yaml'
  abort 'Unexpected existing private input' if File.exist?(private_path)
  recovery.atomic(private_path,File.binread(stage+'/strict-custom-private.example.yaml'))
  lock_path='/etc/openclash/custom/strict-custom-locks.yaml'
  abort 'Unexpected existing lock registry' if File.exist?(lock_path) || File.exist?(lock_path+'.good')
  recovery.atomic(lock_path,YAML.dump({'schema'=>1,'bindings'=>{}}));recovery.atomic(lock_path+'.good',File.binread(lock_path))
  recovery.atomic(paths['overwrite'],hook,a['modes']['overwrite']);recovery.atomic(source,source_bytes,a['modes']['source']);recovery.atomic(runtime,runtime_bytes,a['modes']['runtime'])
  recovery.api('/configs?force=true','PUT',{'path'=>runtime})
  skipped=recovery.restore_choices(choices);abort 'Original production choices could not be preserved' unless skipped.empty?
  now=recovery.api('/proxies')['proxies'];count=now.keys.count{|n|n.start_with?('🔐 自定义节点 · ','🔐 自定义节点组 · ')}
  abort 'Strict selector count mismatch' unless count==138
  puts YAML.dump({'router_activated'=>true,'active_source'=>source,'strict_groups'=>count,'original_choices_preserved'=>true,'native_kernel_replaced'=>false,'rollback_guard_armed'=>true})
 rescue Exception
  recovery.restore(b);raise
 ensure
  File.unlink(b+'/PUBLISHING') if File.exist?(b+'/PUBLISHING')
 end
when 'accept'
 b=ARGS.fetch('router');stage=b+'/stage';require stage+'/strict_custom_router_recovery';require stage+'/strict_custom'
 recovery=StrictRouterRecovery;a=YAML.load_file(b+'/activated_router.yaml');now=recovery.api('/proxies')['proxies'];y=StrictCustom.load(runtime)
 strict=now.select{|name,g|name.start_with?('🔐 自定义节点 · ','🔐 自定义节点组 · ')}
 abort 'Private selector missing or not closed' unless strict.length==138 && strict.values.all?{|g|g['type']=='Selector' && g['all']==['REJECT'] && g['now']=='REJECT'}
 rules=recovery.api('/rules')['rules'].map{|r|r.slice('type','payload','proxy')};abort 'Production rules changed' unless rules==a['rules']
 ignored=['GLOBAL','🧪 节点能力检测','🔬 节点归属校验']
 a['choices'].each{|name,selected|next if ignored.include?(name);abort 'Production selection changed' unless now.dig(name,'now')==selected}
 StrictCustom.validate(y);abort 'Persistent private hook missing' unless File.read(paths['overwrite']).include?('# BEGIN JYDN STRICT CUSTOM')
 abort 'UCI source changed unexpectedly' unless sh('uci','-q','get','openclash.config.config_path')==source
 recovery.atomic(b+'/ROUTER_ACCEPTED','accepted');sh('/etc/init.d/'+a['guard_service'],'disable');sh('/etc/init.d/'+a['guard_service'],'stop')
 result={'accepted'=>true,'source'=>source,'business_count'=>69,'strict_group_count'=>138,'all_empty_private_entries_reject'=>true,'rules_unchanged'=>true,'original_choices_preserved'=>true,'subscription_restart_hook_persistent'=>true,'native_kernel_replaced'=>false,'rollback_guard_disarmed'=>true,
  'source_sha256'=>hash_file(source),'runtime_sha256'=>hash_file(runtime)}
 recovery.atomic(b+'/router-acceptance.yaml',YAML.dump(result));puts YAML.dump(result)
when 'rollback'
 b=ARGS.fetch('router');require b+'/stage/strict_custom_router_recovery';puts YAML.dump(StrictRouterRecovery.restore(b))
else;abort 'Unknown router phase'
end
