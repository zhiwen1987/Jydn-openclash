# ruby deploy_exporter.rb PRIVATE_HELPERS ACTION PRIVATE_RECEIPT
# Owns only the dedicated forced key and explicitly staged metadata UI/export files.
require ARGV.shift
action,b=ARGV
assert(b && b.start_with?('/root/clash-stack-backups/info-sync-') && File.directory?(b),'private_receipt_required')
KEYS='/etc/dropbear/authorized_keys'
def verify_exporter(j)
 assert(File.read('/sys/class/net/br-lan/address').strip==j['mac'],'router_changed')
 j['files'].each do |p,i|
  assert(i['before'].nil? || hash_file(i['backup'])==i['before'],'backup_corrupt')
  assert([i['before'],i['after']].include?(File.file?(p) ? hash_file(p) : nil),'later_edit_requires_review')
 end
 lines=File.readlines(KEYS,chomp:true);same=lines.select{|s|s.split.include?(j['public_blob'])}
 assert(same.empty? || same==[j['key_line']],'owned_key_changed')
end
def rollback_exporter(b)
 j=YAML.load_file(b+'/exporter-journal.yaml');verify_exporter(j)
 # Remove exactly our authorization; preserve all subsequent unrelated entries.
 lines=File.readlines(KEYS);lines.reject!{|s|s.chomp==j['key_line']}
 atomic(KEYS,lines.join,0600)
 j['files'].each do |p,i|
  if i['before'];atomic(p,File.binread(i['backup']),i['mode'])
  else;File.unlink(p) if File.file?(p);end
 end
 atomic(b+'/EXPORTER_ROLLED_BACK',Time.now.to_i.to_s)
 {'restored'=>true,'ssh_restarted'=>false,'core_restarted'=>false}
end
begin
 case action
 when 'prepare'
  assert(!File.exist?(b+'/exporter-journal.yaml'),'already_prepared')
  input=YAML.load(STDIN.read);pub=input['public_key'].split
  assert(pub.length==3 && pub[0]=='ssh-ed25519' && pub[1].match?(/\A[A-Za-z0-9+\/=]+\z/),'invalid_public_key')
  assert(!File.read(KEYS).include?(pub[1]),'key_already_present')
  line='restrict,command="/usr/bin/lua /etc/openclash/custom/subscription-info-exporter/export.lua" '+pub.join(' ')
  allowed=%w[/etc/openclash/custom/subscription-info-exporter/export.lua /etc/openclash/custom/subscription-info-exporter/source_export.lua /etc/openclash/custom/subscription-info-exporter/config.json /usr/lib/lua/luci/jydn_subscription_usage.lua /www/luci-static/resources/openclash/js/status.js /www/luci-static/resources/openclash/js/config_upload.js /www/luci-static/resources/openclash/js/jydn_subscription_usage.js]
  assert(input['files'].keys.sort==allowed.sort,'unexpected_targets')
  files={};input['files'].each do |p,encoded|
   raw=encoded.unpack1('m0');n=files.length.to_s;before=File.file?(p) ? hash_file(p) : nil
   backup=b+'/exporter-before-'+n;atomic(backup,File.binread(p)) if before
   stage=b+'/exporter-stage-'+n;atomic(stage,raw)
   files[p]={'before'=>before,'after'=>hash_file(stage),'backup'=>backup,'stage'=>stage,'mode'=>File.file?(p) ? File.stat(p).mode&0777 : (p.include?('/www/') ? 0644 : 0600)}
  end
  j={'mac'=>input['mac'],'files'=>files,'key_line'=>line,'public_blob'=>pub[1]}
  atomic(b+'/exporter-journal.yaml',YAML.dump(j));verify_exporter(j);result={'prepared'=>true,'files'=>files.length}
 when 'apply'
  j=YAML.load_file(b+'/exporter-journal.yaml');verify_exporter(j)
  assert(!File.exist?(b+'/EXPORTER_ACCEPTED'),'already_accepted')
  j['files'].each{|p,i|assert((File.file?(p) ? hash_file(p) : nil)==i['before'],'baseline_changed');assert(hash_file(i['stage'])==i['after'],'stage_changed')}
  pid=Process.spawn('ruby',b+'/deploy_exporter.rb',b+'/helpers.rb','guard',b,in:File::NULL,out:b+'/exporter-guard.log',err:[:child,:out],pgroup:true);Process.detach(pid)
  begin
   j['files'].each{|p,i|sh('mkdir','-p','-m','700',File.dirname(p)) unless File.directory?(File.dirname(p));atomic(p,File.binread(i['stage']),i['mode'])}
   old=File.binread(KEYS);atomic(KEYS,old+(old.end_with?("\n") ? '' : "\n")+j['key_line']+"\n",0600)
   verify_exporter(j)
  rescue;rollback_exporter(b);raise;end
  result={'applied'=>true,'guard_seconds'=>1200,'ssh_restarted'=>false,'core_restarted'=>false}
 when 'check';verify_exporter(YAML.load_file(b+'/exporter-journal.yaml'));result={'rollback_precheck'=>true}
 when 'rollback';result=rollback_exporter(b)
 when 'accept';verify_exporter(YAML.load_file(b+'/exporter-journal.yaml'));atomic(b+'/EXPORTER_ACCEPTED',Time.now.to_i.to_s);result={'accepted'=>true}
 when 'guard'
  deadline=Time.now+1200
  while Time.now<deadline
   exit if File.exist?(b+'/EXPORTER_ACCEPTED') || File.exist?(b+'/EXPORTER_ROLLED_BACK')
   sleep 5
  end
  result=rollback_exporter(b)
 else;raise 'unknown_action'
 end
 puts json(result)
rescue => e
 puts json({'ok'=>false,'error_class'=>e.class.to_s});exit 1
end
