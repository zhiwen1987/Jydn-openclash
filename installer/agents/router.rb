require 'yaml'

def assert(value,message);raise message unless value;end
def sh(*args)
 out=IO.popen(args,err:File::NULL){|f|f.read};raise 'command_failed' unless $?.success?;out.strip
end

def bounded(args,seconds,out:File::NULL,err:File::NULL)
 pid=Process.spawn(*args,pgroup:true,out:out,err:err)
 deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+seconds
 loop do
  result=Process.waitpid2(pid,Process::WNOHANG);return result[1].success? if result
  if Process.clock_gettime(Process::CLOCK_MONOTONIC)>=deadline
   begin;Process.kill('TERM',-pid);rescue Errno::ESRCH;end
   sleep 1
   begin;Process.kill('KILL',-pid);rescue Errno::ESRCH;end
   begin;Process.waitpid(pid);rescue Errno::ECHILD;end
   return false
  end
  sleep 0.2
 end
end

def service(path,action)
 assert(bounded([path,action],180),'service_action_failed')
end
def json(v)
 case v
 when Hash;'{'+v.map{|k,x|json(k.to_s)+':'+json(x)}.join(',')+'}'
 when Array;'['+v.map{|x|json(x)}.join(',')+']'
 when String;'"'+v.each_char.map{|c|c=='"' ? '\\"' : c=="\\" ? '\\\\' : c.ord<32 ? ('\\u%04x'%c.ord) : c}.join+'"'
 when Integer,Float;v.to_s
 when TrueClass;'true'
 when FalseClass;'false'
 when NilClass;'null'
 else;raise 'json_type_invalid'
 end
end
def atomic(path,raw,mode=0600)
 sh('mkdir','-p','-m','700',File.dirname(path))
 tmp=path+'.stack-'+Process.pid.to_s
 File.open(tmp,'w',mode){|f|f.write(raw);f.flush;f.fsync};File.chmod(mode,tmp);File.rename(tmp,path)
end
def hash_file(path);sh('sha256sum',path).split.first;end

def with_lock(base)
 sh('mkdir','-p','-m','700',base)
 File.open(base+'/operations.lock','a',0600) do |f|
  assert(f.flock(File::LOCK_EX|File::LOCK_NB),'router_operation_in_progress')
  begin;yield;ensure;f.flock(File::LOCK_UN);end
 end
end
def managed_write(t,base,path,raw,mode=0600)
 current=File.file?(path) ? hash_file(path) : nil
 expected=t['owned_sha256'].key?(path) ? t['owned_sha256'][path] : t['files'].dig(path,'sha256')
 assert(current==expected,'router_concurrent_edit_apply_refused')
 temp=base+'/intent-'+t['owned_sha256'].length.to_s
 atomic(temp,raw,mode);t['owned_sha256'][path]=hash_file(temp)
 atomic(base+'/transaction.json',json(t));atomic(path,raw,mode)
end
def uci(key);IO.popen(['uci','-q','get','openclash.config.'+key],err:File::NULL){|f|f.read}.strip;end

def uci_map(name,dir=nil)
 args=['uci','-q'];args+=['-c',dir] if dir;args+=['show',name]
 IO.popen(args,err:File::NULL){|f|f.read}.lines.map{|line|line.strip.split('=',2)}.to_h
end

def reconcile_service_files(t,base)
 path='/etc/config/openclash'
 if t['owned_sha256'].key?(path) && hash_file(path)!=t['owned_sha256'][path]
  expected=t['expected_uci'] || uci_map('openclash',base+'/uci-stage');actual=uci_map('openclash')
  before=t.fetch('dhcp_before',{})
  permitted={
   'openclash.config.redirect_dns'=>["'0'","'1'"],
   'openclash.config.cachesize_dns'=>["'0'","'1'"],
   'openclash.config.core_type'=>["'Meta'"],
   'openclash.config.filter_aaaa_dns'=>["'0'"],
   'openclash.config.dnsmasq_server'=>[before['dhcp.@dnsmasq[0].server'],nil],
   'openclash.config.dnsmasq_noresolv'=>[before['dhcp.@dnsmasq[0].noresolv']||"''",nil],
   'openclash.config.dnsmasq_cachesize'=>[before['dhcp.@dnsmasq[0].cachesize']||(t.key?('dhcp_before') ? "''" : "'1000'"),nil],
   'openclash.config.dnsmasq_resolvfile'=>[before['dhcp.@dnsmasq[0].resolvfile']||"'/tmp/resolv.conf.d/resolv.conf.auto'",nil],
   'openclash.config.default_resolvfile'=>["'/tmp/resolv.conf.d/resolv.conf.auto'","'/tmp/resolv.conf.auto'"]}
  changed=(expected.keys|actual.keys).select{|key|expected[key]!=actual[key]}
  assert(changed.all?{|key|permitted.fetch(key,[]).include?(actual[key])},'router_concurrent_uci_edit_restore_refused')
  t['owned_sha256'][path]=hash_file(path)
 end
 path='/etc/config/dhcp'
 if t['dhcp_before'] && t['routing_applied'] && !t['was_running']
  original=t['dhcp_before'];actual=uci_map('dhcp');port=t['profile']['ports']['router_dns']
  permitted={
   'dhcp.@dnsmasq[0].server'=>[nil,"'127.0.0.1##{port}'"],
   'dhcp.@dnsmasq[0].noresolv'=>[nil,"'0'","'1'"],
   'dhcp.@dnsmasq[0].localuse'=>[nil,"'1'"],
   'dhcp.@dnsmasq[0].cachesize'=>[nil,"'0'","'1000'"],
   'dhcp.@dnsmasq[0].resolvfile'=>[nil,"'/tmp/resolv.conf.d/resolv.conf.auto'"]}
  changed=(original.keys|actual.keys).select{|key|original[key]!=actual[key]}
  assert(changed.all?{|key|(permitted.fetch(key,[])+[original[key]]).include?(actual[key])},'router_concurrent_dhcp_edit_restore_refused')
  t['owned_sha256'][path]=hash_file(path)
 end
 atomic(base+'/transaction.json',json(t)) if File.file?(base+'/transaction.json')
end
def api(path,method='GET',body=nil,settings=nil)
 port=settings ? settings['ports']['api'] : uci('cn_port').to_i
 port=9090 if port.to_i==0
 secret=settings ? settings['material']['api_secret'] : uci('dashboard_password')
 config='url = '+json('http://127.0.0.1:'+port.to_s+path)+"\nheader = "+json('Authorization: Bearer '+secret)+"\nrequest = "+json(method)+"\n"
 config+='header = "Content-Type: application/json"'+"\ndata-binary = "+json(json(body))+"\n" if body
 out=IO.popen(['curl','-fsS','--max-time','30','--config','-'],'r+',err:File::NULL){|f|f.write(config);f.close_write;f.read}
 raise 'api_request_failed' unless $?.success?
 out.strip.empty? ? {} : YAML.load(out)
end
def active?;system('pidof','clash_meta',out:File::NULL,err:File::NULL);end

def private_path?(proxies,name)
 seen=[]
 while name.is_a?(String) && !seen.include?(name)
  return true if name=='🔐 自定义节点' || name.start_with?('🔐 自建节点 · ','🔐 自建节点池 · ','🔐 自定义节点 · ','🔐 自定义节点组 · ')
  seen<<name;name=proxies.dig(name,'now')
 end
 false
end
def identity(p)
 actual=File.read('/sys/class/net/br-lan/address').strip
 assert(actual==p.fetch('router').fetch('mac'),'router_identity_changed')
end
def doctor(p)
 identity(p)
 assert(File.file?('/etc/init.d/openclash'),'openclash_missing')
 assert(File.file?('/etc/openclash/core/clash_meta'),'mihomo_missing')
 version=sh('opkg','status','luci-app-openclash')[/^Version:\s*(\S+)/,1]
 assert(version=='0.48.002','openclash_version_requires_rehearsal')
 source=uci('config_path');runtime=source.empty? ? '' : '/etc/openclash/'+File.basename(source)
 {'mac'=>p['router']['mac'],'architecture'=>sh('uname','-m'),'source'=>source,'source_sha256'=>File.file?(source) ? hash_file(source) : nil,'runtime_sha256'=>File.file?(runtime) ? hash_file(runtime) : nil,'running'=>active?,'enabled'=>uci('enable'),'kernel_sha256'=>hash_file('/etc/openclash/core/clash_meta'),'uci_sha256'=>hash_file('/etc/config/openclash'),'overwrite_sha256'=>File.file?('/etc/openclash/custom/openclash_custom_overwrite.sh') ? hash_file('/etc/openclash/custom/openclash_custom_overwrite.sh') : nil}
end
def prepare(p,base,args)
 identity(p);assert(!File.file?(base+'/transaction.json'),'unfinished_router_transaction')
 assert(p['mode']=='adopt' || ['', '0'].include?(uci('ipv6_dns')),'ipv6_dns_migration_requires_review')
 state=File.file?(base+'/state.json') ? YAML.load_file(base+'/state.json') : nil
 source=uci('config_path');runtime=source.empty? ? '' : '/etc/openclash/'+File.basename(source)
 if args['expected']
  snapshot=doctor(p)
  %w[mac source source_sha256 runtime_sha256 uci_sha256 overwrite_sha256 kernel_sha256].each{|key|assert(snapshot[key]==args['expected'][key],'router_changed_before_backup')}
 end
 target='/etc/openclash/config/clash-stack-'+p['site']+'.yaml'
 assert(!active? || state || p['mode']=='adopt' || args['allow_router_switch'],'running_router_requires_explicit_switch_approval')
 backup='/root/clash-stack-backups/'+p['site']+'/'+Time.now.to_i.to_s+'-'+Process.pid.to_s
 sh('mkdir','-p','-m','700',backup);File.chmod(0700,backup)
 paths=['/etc/config/openclash','/etc/config/dhcp','/etc/openclash/custom/openclash_custom_overwrite.sh',target,'/etc/openclash/'+File.basename(target)]
 paths+=[source,runtime] unless source.empty?
 files={}
 paths.uniq.each_with_index do |path,index|
  if File.file?(path)
   name=index.to_s+'.before';atomic(backup+'/'+name,File.binread(path))
   files[path]={'file'=>name,'sha256'=>hash_file(path),'mode'=>File.stat(path).mode & 0777}
  else;files[path]={'missing'=>true};end
 end
 choices=active? ? api('/proxies')['proxies'].select{|_,g|g['type']=='Selector'}.transform_values{|g|g['now']} : {}
 t={'schema'=>1,'profile'=>p,'previous'=>state,'backup'=>backup,'files'=>files,'phase'=>'prepared','was_running'=>active?,'was_enabled'=>uci('enable'),'old_api'=>{'ports'=>{'api'=>uci('cn_port').to_i},'material'=>{'api_secret'=>uci('dashboard_password')}},'source'=>source,'runtime'=>runtime,'target'=>target,'choices'=>choices,'material'=>args['material'],'started_at'=>Time.now.to_i,'owned_sha256'=>{}}
 t['dhcp_before']=uci_map('dhcp')
 atomic(base+'/transaction.json',json(t));atomic(backup+'/transaction.json',json(t))
 {'prepared'=>true,'backup'=>backup,'source_preserved'=>p['mode']=='adopt'}
end
def install(p,base,args)
 identity(p);t=YAML.load_file(base+'/transaction.json');assert(t['phase']=='prepared','router_phase_invalid')
 # Adoption leaves the existing routing, DNS, hooks and choices intact.
 if p['mode']=='adopt'
  t['phase']='installed';atomic(base+'/transaction.json',json(t));return {'adopted'=>true,'routing_changed'=>false}
 end
 release=base+'/releases/'+args['version'];settings=YAML.load_file(release+'/settings.json')
 assert(settings['profile']==p && settings['material']==t['material'],'router_staged_settings_changed')
 assert(hash_file(release+'/core')==args['core_sha256'],'router_core_checksum_failed')
 compile=release+'/router_compile.rb'
 assert(bounded(['ruby','-E','UTF-8',compile,release+'/template.json',release+'/settings.json',release+'/candidate.yaml'],90,out:release+'/compile.log',err:release+'/compile.err'),'router_compile_failed')
 unit='clash-stack-rollback-'+p['site']
 request={'action'=>'restore','profile'=>p,'base'=>base,'transaction'=>t['backup']}
 atomic(base+'/guard-request.json',json(request))
 atomic(base+'/guard-agent.rb',ROUTER_AGENT_SOURCE)
 init="#!/bin/sh /etc/rc.common\nSTART=99\nUSE_PROCD=1\nstart_service() {\n procd_open_instance\n procd_set_param command /usr/bin/ruby #{base}/guard-agent.rb #{base}/guard-request.json\n procd_set_param stderr 1\n procd_close_instance\n}\n"
 atomic('/etc/init.d/'+unit,init,0755)
 t['guard_unit']=unit;t['guard_deadline']=Time.now.to_i+600;t['phase']='applying';atomic(base+'/transaction.json',json(t))
 service('/etc/init.d/'+unit,'enable');service('/etc/init.d/'+unit,'start')
 # Geo assets use the core's native home. Snapshot every changed asset before
 # writing it; the independent guard is already armed at this point.
 assets=release+'/rules'
 if Dir.exist?(assets)
  Dir.glob(assets+'/**/*').select{|path|File.file?(path)}.each do |path|
   rel=path.delete_prefix(assets+'/');assert(!rel.split('/').include?('..'),'asset_path_invalid')
   dest='/etc/openclash/'+rel
   unless t['files'].key?(dest)
    if File.file?(dest)
     name='asset-'+t['files'].length.to_s+'.before';atomic(t['backup']+'/'+name,File.binread(dest))
     t['files'][dest]={'file'=>name,'sha256'=>hash_file(dest),'mode'=>File.stat(dest).mode & 0777}
    else;t['files'][dest]={'missing'=>true};end
   end
   t['owned_sha256'][dest]=hash_file(path);atomic(base+'/transaction.json',json(t));atomic(dest,File.binread(path))
  end
 end
 y=YAML.load_file(release+'/candidate.yaml');validation=Marshal.load(Marshal.dump(y));validation.delete('external-ui')
 validation.fetch('proxy-providers',{}).each do |name,provider|
  path=release+'/validate-'+name+'.yaml';atomic(path,YAML.dump({'proxies'=>[{'name'=>'__STACK_EMPTY_'+name,'type'=>'reject'}]}));provider['path']=path
 end
 atomic(release+'/validate.yaml',YAML.dump(validation))
 assert(bounded([release+'/core','-t','-d','/etc/openclash','-f',release+'/validate.yaml'],180,out:release+'/native.log',err:release+'/native.err'),'native_router_validation_failed')
 hook='/etc/openclash/custom/openclash_custom_overwrite.sh'
 old=File.file?(hook) ? File.read(hook) : "#!/bin/sh\n"
 marker='# BEGIN CLASH STACK '+p['site'];ending='# END CLASH STACK '+p['site']
 old=old.gsub(/#{Regexp.escape(marker)}.*?#{Regexp.escape(ending)}\n?/m,'')
 block=marker+"\nruby -E UTF-8 "+compile+" \"$CONFIG_FILE\" "+release+"/settings.json \"$CONFIG_FILE\" || exit 1\n"+ending+"\n"
 if old.match?(/^\s*exit\s+0\s*$/)
  assert(old.scan(/^\s*exit\s+0\s*$/).length==1,'overwrite_exit_ambiguous')
  old=old.sub(/^\s*exit\s+0\s*$/,block+"exit 0")
 else;old+="\n"+block;end
 managed_write(t,base,hook,old,0755);managed_write(t,base,t['target'],File.binread(release+'/candidate.yaml'))
 if hash_file('/etc/openclash/core/clash_meta')!=args['core_sha256']
  assert(!t['was_running'],'running_kernel_replacement_refused')
  atomic(t['backup']+'/kernel.before',File.binread('/etc/openclash/core/clash_meta'))
  t['files']['/etc/openclash/core/clash_meta']={'file'=>'kernel.before','sha256'=>hash_file('/etc/openclash/core/clash_meta'),'mode'=>0755}
  t['kernel_replaced']=true;managed_write(t,base,'/etc/openclash/core/clash_meta',File.binread(release+'/core'),0755)
 end
 # UCI input uses generated URL-safe credentials; no credentials in process args.
 values={'enable'=>'1','config_path'=>t['target'],'cn_port'=>p['ports']['api'].to_s,'dashboard_password'=>t['material']['api_secret'],'mixed_port'=>p['ports']['proxy'].to_s,'dns_port'=>p['ports']['router_dns'].to_s,'enable_custom_dns'=>'0'}
 script=values.map{|key,value|assert(!value.include?("'"),'uci_value_invalid');"set openclash.config.#{key}='#{value}'"}.join("\n")+"\ncommit openclash\n"
 staged_uci=base+'/uci-stage';sh('mkdir','-p','-m','700',staged_uci);atomic(staged_uci+'/openclash',File.binread('/etc/config/openclash'))
 IO.popen(['uci','-c',staged_uci,'batch'],'r+'){|f|f.write(script);f.close_write;f.read};assert($?.success?,'uci_update_failed')
 t['expected_uci']=uci_map('openclash',staged_uci)
 managed_write(t,base,'/etc/config/openclash',File.binread(staged_uci+'/openclash'))
 t['phase']='installed';t['settings']=settings;atomic(base+'/transaction.json',json(t))
 if t['was_running']
  runtime='/etc/openclash/'+File.basename(t['target']);managed_write(t,base,runtime,File.binread(release+'/candidate.yaml'))
  api('/configs?force=true','PUT',{'path'=>runtime},t['old_api'])
 else
  t['routing_applied']=true;atomic(base+'/transaction.json',json(t))
  service('/etc/init.d/openclash','start')
 end
 t['routing_applied']=true;atomic(base+'/transaction.json',json(t))
 {'installed'=>true,'guard_armed'=>true,'configuration'=>t['target'],'kernel_replaced'=>t['kernel_replaced']==true}
end
def verify(p,base,accept=false)
 identity(p);t=YAML.load_file(File.file?(base+'/transaction.json') ? base+'/transaction.json' : base+'/state.json')
 settings=t['settings'];proxies=api('/proxies','GET',nil,settings)['proxies'];rules=api('/rules','GET',nil,settings)['rules']
 if p['mode']=='adopt'
  ignore=['GLOBAL','🧪 节点能力检测','🔬 节点归属校验']
  t['choices'].each{|name,value|assert(ignore.include?(name)||proxies.dig(name,'now')==value,'adopt_business_choice_changed')}
  t['files'].each{|path,item|next if item['missing'];assert(hash_file(path)==item['sha256'],'adopt_router_file_changed')}
 else
  assert(uci('config_path')==t['target'],'router_source_changed')
  assert(proxies.key?('🔐 自定义节点') && proxies.key?('🧪 节点能力检测'),'managed_groups_missing')
  assert(proxies['🔐 自定义节点']['all'].first=='REJECT','custom_default_not_reject')
  assert(rules.length>=100,'routing_rules_incomplete')
  providers=api('/providers/proxies','GET',nil,settings)['providers']
  Integer(settings['source_count']).times do |index|
   nodes=providers.dig('Public_'+(index+1).to_s,'proxies') || []
   assert(nodes.any?{|n|!%w[Reject RejectDrop Direct Pass PassRule].include?(n['type']) && !n['name'].to_s.start_with?('__STACK_EMPTY_')},'public_provider_not_loaded')
  end
  if t['phase']=='installed'
   reconcile_service_files(t,base)
   runtime='/etc/openclash/'+File.basename(t['target']);t['owned_sha256'][runtime]=hash_file(runtime) if File.file?(runtime)
   atomic(base+'/transaction.json',json(t))
  end
 end
 if accept
  assert(t['phase']=='installed','router_accept_phase_invalid')
  t['phase']='accepted';atomic(base+'/state.json',json(t));atomic(t['backup']+'/transaction.json',json(t));File.unlink(base+'/transaction.json')
  if t['guard_unit'];service('/etc/init.d/'+t['guard_unit'],'disable');service('/etc/init.d/'+t['guard_unit'],'stop');end
 end
 {'ready'=>true,'group_count'=>proxies.values.count{|g|g.key?('all')},'rule_count'=>rules.length,'custom_entry_count'=>proxies.count{|n,g|g.key?('all') && n.include?('自定义节点')},'accepted'=>t['phase']=='accepted'}
end
def restore(p,base,manual=false)
 identity(p)
 unless File.file?(base+'/transaction.json')
  return {'restored'=>false,'reason'=>'no_pending_transaction'} unless manual && File.file?(base+'/state.json')
  atomic(base+'/transaction.json',File.binread(base+'/state.json'))
 end
 t=YAML.load_file(base+'/transaction.json')
 if p['mode']=='adopt'
  if t['previous'];atomic(base+'/state.json',json(t['previous']));elsif File.file?(base+'/state.json');File.unlink(base+'/state.json');end
  File.unlink(base+'/transaction.json');return {'restored'=>true,'routing_changed'=>false}
 end
 if t['was_running'] && t['routing_applied']
  fresh=api('/proxies','GET',nil,t['settings'])['proxies']
  t['choices'].each do |name,value|
   next unless fresh[name] && fresh[name]['now']!=value
   assert(!private_path?(fresh,name),'concurrent_private_selection_restore_refused')
  end
 end
 reconcile_service_files(t,base)
 t['owned_sha256'].each{|path,digest|current=File.file?(path) ? hash_file(path) : nil;assert([digest,t['files'].dig(path,'sha256')].include?(current),'router_concurrent_edit_restore_refused')}
 if !t['was_running'] && t['routing_applied'] && active?
  assert(uci('config_path')==t['target'],'foreign_router_service_stop_refused')
  service('/etc/init.d/openclash','stop')
  reconcile_service_files(t,base)
 end
 t['files'].each do |path,item|
  next unless t['owned_sha256'].key?(path)
  if item['missing'];File.unlink(path) if File.file?(path) && t['owned_sha256'].key?(path)
  else;assert(hash_file(t['backup']+'/'+item['file'])==item['sha256'],'router_backup_corrupt');atomic(path,File.binread(t['backup']+'/'+item['file']),item['mode']);end
 end
 if t['was_running'] && t['routing_applied']
  api('/configs?force=true','PUT',{'path'=>t['runtime']},t['settings'])
  groups=api('/proxies')['proxies']
  t['choices'].each do |name,value|
   next if ['GLOBAL','🧪 节点能力检测','🔬 节点归属校验'].include?(name)
   g=groups[name];next unless g && g['type']=='Selector' && g['now']!=value && Array(g['all']).include?(value)
   assert(!private_path?(groups,name),'concurrent_private_selection_restore_refused')
   api('/proxies/'+name.bytes.map{|b|b.chr.match?(/[A-Za-z0-9_.~-]/) ? b.chr : ('%%%02X'%b)}.join,'PUT',{'name'=>value})
  end
 end
 if !t['was_running'] && t['routing_applied'] && t['dhcp_before']
  service('/etc/init.d/dnsmasq','restart')
 end
 if t['previous'];atomic(base+'/state.json',json(t['previous']));elsif File.file?(base+'/state.json');File.unlink(base+'/state.json');end
 atomic(t['backup']+'/restored-transaction.private.json',json(t))
 File.unlink(base+'/transaction.json')
 if t['guard_unit'];service('/etc/init.d/'+t['guard_unit'],'disable');end
 {'restored'=>true,'backup'=>t['backup']}
end

def backup(p,base)
 identity(p);assert(!File.file?(base+'/transaction.json'),'unfinished_router_transaction')
 assert(File.file?(base+'/state.json'),'managed_state_missing')
 state=YAML.load_file(base+'/state.json');dest='/root/clash-stack-backups/'+p['site']+'/manual-'+Time.now.to_i.to_s+'-'+Process.pid.to_s
 sh('mkdir','-p','-m','700',dest);checks={}
 paths=state.fetch('files').keys+[base+'/state.json']+Dir.glob(base+'/releases/*/settings.json')
 paths.uniq.each_with_index{|path,i|next unless File.file?(path);atomic(dest+'/'+i.to_s+'.before',File.binread(path));checks[path]={'file'=>i.to_s+'.before','sha256'=>hash_file(path)}}
 atomic(dest+'/checksums.json',json(checks));{'backup'=>dest,'files'=>checks.length,'routing_changed'=>false}
end
begin
 guard=ARGV.length==1
 if !defined?(ARGS);ARGS=YAML.load_file(ARGV.first);end
 p=ARGS.fetch('profile');assert(p['site'].match?(/\A[a-z][a-z0-9-]{0,31}\z/),'site_invalid')
 base='/etc/openclash/custom/clash-stack-'+p['site'];assert(ARGS.fetch('base',base)==base,'router_base_invalid')
 if guard
  loop do
   break unless File.file?(base+'/transaction.json')
   t=YAML.load_file(base+'/transaction.json');break if ARGS['transaction'] && ARGS['transaction']!=t['backup']
   if Time.now.to_i>=t['guard_deadline'].to_i
    begin;with_lock(base){restore(p,base)};break;rescue StandardError=>e;raise e unless e.message=='router_operation_in_progress';end
   end
   sleep 5
  end
  result={'guard_finished'=>true}
 else
  action=ARGS.fetch('action')
  operation=proc { case action
   when 'doctor';doctor(p)
   when 'prepare';prepare(p,base,ARGS)
   when 'install';install(p,base,ARGS)
   when 'verify';verify(p,base,ARGS['accept']==true)
   when 'restore';restore(p,base,ARGS['manual']==true)
   when 'backup';backup(p,base)
   else;raise 'unsupported_router_action'
  end }
  result=action=='doctor' ? operation.call : with_lock(base){operation.call}
 end
 puts json({'ok'=>true,'result'=>result})
rescue StandardError=>e
 message=e.message.match?(/\A[A-Za-z0-9_:.+-]{1,140}\z/) ? e.message : e.class.to_s
 puts json({'ok'=>false,'error'=>message});exit 1
end
