# Independent OpenWrt recovery; uses only Ruby YAML and existing curl/uci tools.
require 'yaml'
module StrictRouterRecovery
  def self.sh(*args)
    out=IO.popen(args,err:File::NULL){|f|f.read};raise 'recovery_command_failed' unless $?.success?;out.strip
  end
  def self.hash(path);sh('sha256sum',path).split.first;end
  def self.json(v)
    case v
    when Hash;'{'+v.map{|k,x|json(k.to_s)+':'+json(x)}.join(',')+'}'
    when Array;'['+v.map{|x|json(x)}.join(',')+']'
    when String;'"'+v.each_char.map{|c|c=='"' ? '\\"' : c=="\\" ? '\\\\' : c.ord<32 ? ('\\u%04x'%c.ord) : c}.join+'"'
    when Integer;v.to_s
    when TrueClass;'true'
    when FalseClass;'false'
    when NilClass;'null'
    else;raise 'unsupported_json_value'
    end
  end
  def self.uri(v);v.bytes.map{|b|b.chr.match?(/[A-Za-z0-9_.~-]/) ? b.chr : ('%%%02X'%b)}.join;end
  def self.api(path,method='GET',body=nil)
    raise 'unsupported_api_path' unless path.match?(%r{\A/(proxies(?:/[^/?]+)?|providers/proxies(?:/[^/?]+)?|configs(?:\?force=true)?|rules|connections(?:/[^/?]+)?)\z})
    secret=sh('uci','-q','get','openclash.config.dashboard_password')
    config='url = '+json('http://127.0.0.1:9090'+path)+"\nheader = "+json('Authorization: Bearer '+secret)+"\nrequest = "+json(method)+"\n"
    config+='header = "Content-Type: application/json"'+"\ndata-binary = "+json(json(body))+"\n" if body
    out=IO.popen(['curl','-fsS','--max-time',method=='GET' ? '12' : '90','--config','-'],'r+',err:File::NULL){|f|f.write(config);f.close_write;f.read}
    raise 'kernel_api_failed' unless $?.success?;out.strip.empty? ? {} : YAML.load(out)
  end
  def self.atomic(path,bytes,mode=0600)
    temp=path+'.strict-tmp';File.open(temp,'w',mode){|f|f.write(bytes);f.flush;f.fsync};File.chmod(mode,temp);File.rename(temp,path)
  end
  def self.verify(b)
    raise 'unexpected_recovery_directory' unless b.match?(%r{\A/root/openclash-backups/(shared-custom|local-source)-\d{8}-\d+\z}) && File.directory?(b)
    raise 'wrong_router_identity' unless File.read('/sys/class/net/br-lan/address').strip=='00:0c:29:2d:96:e8'
    m=YAML.load_file(b+'/manifest.yaml')
    m['files'].each{|k,item|next if item['missing'];raise 'backup_integrity_failed' unless hash(b+'/'+k+'.before')==item['sha256']}
    m
  end
  def self.restore_choices(choices,migrate=false)
    proxies=api('/proxies')['proxies'];skipped=[]
    choices.each do |name,selected|
      next if ['GLOBAL','🧪 节点能力检测','🔬 节点归属校验'].include?(name)
      if migrate && selected.is_a?(String)
        selected='🔐 自定义节点' if selected.start_with?('🔐 自定义节点 · ','🔐 自定义节点组 · ')
      end
      item=proxies[name];next unless item && item['type']=='Selector'
      if selected && item.fetch('all',[]).include?(selected)
        api('/proxies/'+uri(name),'PUT',{'name'=>selected}) if item['now']!=selected
      else;skipped<<name
      end
    end
    skipped
  end
  def self.restore(b)
    m=verify(b);a=YAML.load_file(b+'/activated_router.yaml')
    # Never overwrite bindings or release a newly selected private business
    # back to an older public choice during a later manual rollback.
    %w[private_input locks locks_good].each do |key|
      item=m['files'][key];next unless item && !item['missing']
      raise 'private_registry_changed_manual_review_required' unless File.file?(item['path']) && hash(item['path'])==item['sha256']
    end
    current=api('/proxies')['proxies']
    raise 'new_private_selection_manual_review_required' if current.any?{|name,g|name!='GLOBAL' && name!='🔐 自定义节点' && g['now']=='🔐 自定义节点' && a['choices'][name]!='🔐 自定义节点'}
    a['owned_sha256'].keys.each do |k|
      item=m['files'][k];current=hash(item['path'])
      raise 'concurrent_configuration_edit' unless [item['sha256'],a['owned_sha256'][k]].include?(current)
    end
    a['owned_sha256'].keys.each do |k|
      item=m['files'][k]
      if item['missing'];File.unlink(item['path']) if File.file?(item['path'])
      else;atomic(item['path'],File.binread(b+'/'+k+'.before'),a['modes'][k]);end
    end
    begin;api('/configs?force=true','PUT',{'path'=>m['files']['runtime']['path']})
    rescue StandardError;sh('/etc/init.d/openclash','restart')
    end
    deadline=Time.now.to_i+90
    loop do
      begin;api('/configs');break;rescue StandardError;raise if Time.now.to_i>deadline;sleep 2;end
    end
    skipped=restore_choices(a['choices'])
    atomic(b+'/ROUTER_ROLLED_BACK',YAML.dump({'completed'=>true,'skipped_choices'=>skipped,'epoch'=>Time.now.to_i}))
    sh('/etc/init.d/'+a['guard_service'],'disable')
    {'rollback_completed'=>true,'skipped_choices'=>skipped,'live_provider_caches_preserved'=>true}
  end
  def self.guardloop(b)
    verify(b);a=YAML.load_file(b+'/activated_router.yaml');failures=0
    loop do
      break if File.file?(b+'/ROUTER_ACCEPTED') || File.file?(b+'/ROUTER_ROLLED_BACK')
      age=Time.now.to_i-a['started_at']
      if age>600;restore(b);break;end
      if File.file?(b+'/PUBLISHING') && age<180;sleep 5;next;end
      begin
        p=api('/proxies')['proxies'];n=p.keys.count{|k|k=='🔐 自定义节点' || k.start_with?('🔐 自定义节点 · ','🔐 自定义节点组 · ')}
        raise 'strict_groups_missing' unless n==a['strict_group_count']
        failures=0
      rescue StandardError;failures+=1
      end
      if age>30 && failures>=3;restore(b);break;end
      sleep 10
    end
  end
end
if __FILE__==$0
  action,b=ARGV
  result=case action
         when 'verify';StrictRouterRecovery.verify(b);{'backup_verified'=>true}
         when 'rollback';StrictRouterRecovery.restore(b)
         when 'guardloop';StrictRouterRecovery.guardloop(b);{'guard_exited'=>true}
         else;raise 'unsupported_recovery_action'
         end
  puts YAML.dump(result)
end
