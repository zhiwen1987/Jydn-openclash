# Usage: ruby deploy_router.rb PRIVATE/router_helpers.rb ACTION PRIVATE_RECEIPT
# Helpers are an exact copy of installer/agents/router.rb's function definitions.
# This patch only manages account-metadata UCI and UI files; never reloads core.
require ARGV.shift
action,b=ARGV
assert(b && b.start_with?('/root/clash-stack-backups/usage-auto-') && File.directory?(b),'private_receipt_required')

def usage_check(j)
 assert(File.read('/sys/class/net/br-lan/address').strip==j['mac'],'router_identity_changed')
 j['targets'].each do |path,item|
  assert(!item['before'] || hash_file(item['backup'])==item['before'],'backup_corrupt')
  current=File.file?(path) ? hash_file(path) : nil
  assert([item['before'],item['after']].include?(current),'later_configuration_edit_manual_review')
 end
end

def usage_rollback(b)
 j=YAML.load_file(b+'/usage-journal.yaml');usage_check(j)
 j['targets'].each do |path,item|
  if item['before']
   atomic(path,File.binread(item['backup']),item['mode'])
  else
   File.unlink(path) if File.file?(path)
  end
 end
 atomic(b+'/USAGE_ROLLED_BACK',Time.now.to_i.to_s)
 {'restored'=>true,'core_restarted'=>false}
end

def usage_protected(j)
 m=YAML.load_file(j['backup']+'/manifest.yaml')
 %w[source runtime].each{|k|i=m['files'][k];assert(hash_file(i['path'])==i['sha256'],'node_configuration_changed')}
 m['protected'].each{|path,h|assert(hash_file(path)==h,'dns_or_protected_configuration_changed')}
 now=api('/proxies')['proxies'];assert(j['choices'].all?{|name,v|now.dig(name,'now')==v},'business_selection_changed')
 rules=api('/rules')['rules'].map{|r|{'index'=>r['index'],'type'=>r['type'],'payload'=>r['payload'],'proxy'=>r['proxy'],'disabled'=>r.dig('extra','disabled')}}
 assert(rules==m['rules'],'runtime_rule_definitions_changed')
 assert(File.directory?('/proc/'+j['core_pid']),'core_restarted')
end

begin
 case action
 when 'prepare'
  assert(!File.exist?(b+'/usage-journal.yaml'),'already_prepared')
  input=YAML.load(STDIN.read);m=YAML.load_file(b+'/manifest.yaml')
  assert(File.read('/sys/class/net/br-lan/address').strip==input['mac'],'router_identity_changed')
  m['files'].each{|key,i|assert(hash_file(i['path'])==i['sha256'],'original_backup_baseline_changed')}
  assert(sh('uci','-q','changes','openclash').empty?,'pending_uci_changes')
  state_path=m['files']['state']['path'];state=YAML.load_file(state_path)
  assert(state.dig('files','/etc/config/openclash','sha256')==hash_file('/etc/config/openclash'),'preexisting_managed_uci_drift')
  base=m['config_base'];section='jydn_subinfo_auto';old='jydn_subinfo_bffc55'
  # Refuse unrelated bindings for this configuration instead of overwriting them.
  sh('uci','show','openclash').lines.each do |line|
   match=line.match(/^openclash\.([^.=]+)=subscribe_info$/);next unless match
   id=match[1];name=IO.popen(['uci','-q','get','openclash.'+id+'.name'],err:File::NULL){|f|f.read}.strip
   assert(![base,base+'.yaml'].include?(name) || id==old,'unowned_metadata_binding')
  end
  token=input['token'];assert(token.is_a?(String)&&token.match?(/\A[A-Za-z0-9_-]{32,128}\z/),'invalid_metadata_token')
  endpoint=input['endpoint'];assert(endpoint=='http://10.88.0.249:3103/subscription-info','unexpected_metadata_endpoint')
  dirs=%w[usage-stage usage-before-normalized usage-after-normalized]
  dirs.each{|d|sh('mkdir','-p','-m','700',b+'/'+d,b+'/'+d+'/delta',b+'/'+d+'/override')}
  dirs.each{|d|atomic(b+'/'+d+'/openclash',File.binread('/etc/config/openclash'))}
  runuci=lambda{|d,*a|sh('uci','-c',b+'/'+d,'-C',b+'/'+d+'/override','-t',b+'/'+d+'/delta',*a)}
  # The only removed binding is the previously accepted one-source feature.
  runuci.call('usage-stage','delete','openclash.'+old)
  runuci.call('usage-before-normalized','delete','openclash.'+old)
  runuci.call('usage-before-normalized','commit','openclash')
  runuci.call('usage-stage','set','openclash.'+section+'=subscribe_info')
  {'name'=>base,'jydn_auto'=>'1','jydn_usage_token'=>token}.each{|k,v|runuci.call('usage-stage','set','openclash.'+section+'.'+k+'='+v)}
  runuci.call('usage-stage','add_list','openclash.'+section+'.url='+endpoint)
  runuci.call('usage-stage','commit','openclash')
  atomic(b+'/usage-after-normalized/openclash',File.binread(b+'/usage-stage/openclash'))
  runuci.call('usage-after-normalized','delete','openclash.'+section);runuci.call('usage-after-normalized','commit','openclash')
  assert(runuci.call('usage-before-normalized','export','openclash')==runuci.call('usage-after-normalized','export','openclash'),'non_metadata_uci_change')
  assert(hash_file('/etc/config/openclash')==m['files']['uci']['sha256'],'private_uci_stage_touched_production')
  allowed=['/usr/lib/lua/luci/controller/openclash.lua','/www/luci-static/resources/openclash/js/status.js',
   '/www/luci-static/resources/openclash/js/config_upload.js','/usr/lib/lua/luci/view/openclash/sub_info_show.htm',
   '/usr/lib/lua/luci/jydn_subscription_usage.lua','/www/luci-static/resources/openclash/js/jydn_subscription_usage.js']
  assert(input['files'].keys.sort==allowed.sort,'unexpected_ui_targets')
  targets={}
  add=lambda do |path,raw,mode|
   n=targets.length.to_s;before=File.file?(path) ? hash_file(path) : nil
   backup=b+'/usage-before-'+n;atomic(backup,File.binread(path)) if before
   stage=b+'/usage-stage-'+n;atomic(stage,raw)
   targets[path]={'before'=>before,'after'=>hash_file(stage),'backup'=>backup,'stage'=>stage,'mode'=>File.file?(path) ? File.stat(path).mode&0777 : mode}
  end
  input['files'].each{|path,encoded|add.call(path,encoded.unpack1('m0'),0644)}
  add.call('/etc/config/openclash',File.binread(b+'/usage-stage/openclash'),0600)
  item=state['files']['/etc/config/openclash'];item['backup_sha256']||=item['sha256'];item['sha256']=hash_file(b+'/usage-stage/openclash')
  state['config_baseline_history']||=[]
  state['config_baseline_history']<<{'reason'=>'authorized_auto_subscription_metadata_only','receipt'=>b,'epoch'=>Time.now.to_i,
   'before'=>m['files']['uci']['sha256'],'after'=>item['sha256'],'provider_pull_urls_unchanged'=>true}
  add.call(state_path,json(state),0600)
  now=api('/proxies')['proxies'];choices=now.select{|name,g|g['type']=='Selector'&&!['GLOBAL','🧪 节点能力检测','🔬 节点归属校验'].include?(name)}.transform_values{|g|g['now']}
  j={'backup'=>b,'mac'=>input['mac'],'targets'=>targets,'choices'=>choices,'core_pid'=>m['core_pid'],'prepared_at'=>Time.now.to_i}
  atomic(b+'/usage-journal.yaml',YAML.dump(j));usage_check(j);usage_protected(j)
  result={'prepared'=>true,'files'=>targets.length,'metadata_only_uci_semantics'=>true,'rollback_precheck'=>true}
 when 'apply'
  j=YAML.load_file(b+'/usage-journal.yaml');usage_check(j);usage_protected(j)
  assert(!File.file?(b+'/USAGE_ACCEPTED'),'already_accepted')
  j['targets'].each{|path,i|assert((File.file?(path) ? hash_file(path) : nil)==i['before'],'apply_requires_original_baseline');assert(hash_file(i['stage'])==i['after'],'staged_file_changed')}
  guard=Process.spawn('ruby',File.realpath(__FILE__),b+'/router_helpers.rb','guard',b,pgroup:true,in:File::NULL,out:b+'/usage-guard.log',err:[:child,:out]);Process.detach(guard)
  begin
   j['targets'].each{|path,i|atomic(path,File.binread(i['stage']),i['mode'])}
   usage_check(j);usage_protected(j)
  rescue Exception;usage_rollback(b);raise;end
  result={'applied'=>true,'core_restarted'=>false,'guard_seconds'=>1200}
 when 'check'
  j=YAML.load_file(b+'/usage-journal.yaml');usage_check(j);usage_protected(j);result={'rollback_precheck'=>true,'protected_state_unchanged'=>true,'business_choices'=>j['choices'].length}
 when 'rollback';result=usage_rollback(b)
 when 'accept'
  j=YAML.load_file(b+'/usage-journal.yaml');usage_check(j);usage_protected(j)
  assert(j['targets'].all?{|path,i|hash_file(path)==i['after']},'installed_files_not_exact')
  atomic(b+'/USAGE_ACCEPTED',Time.now.to_i.to_s);result={'accepted'=>true}
 when 'guard'
  deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+1200
  while Process.clock_gettime(Process::CLOCK_MONOTONIC)<deadline
   exit if File.exist?(b+'/USAGE_ACCEPTED')||File.exist?(b+'/USAGE_ROLLED_BACK')
   sleep 5
  end
  result=usage_rollback(b)
 else;raise 'unknown_action'
 end
 puts json(result)
rescue Exception=>e
 puts json({'ok'=>false,'error_class'=>e.class.name,'reason'=>e.message.match?(/\A[A-Za-z0-9_:.+-]{1,140}\z/) ? e.message : 'redacted'})
 exit 1
end
