# Usage: ruby node_health_router.rb PRIVATE_HELPERS ACTION PRIVATE_RECEIPT
require ARGV.shift
action,b=ARGV
assert(b && b.start_with?('/root/clash-stack-backups/node-health-') && File.directory?(b),'private_receipt_required')
def health_check(j)
 assert(File.read('/sys/class/net/br-lan/address').strip==j['mac'],'router_identity_changed')
 j['files'].each{|p,i|assert(i['before'].nil?||hash_file(i['backup'])==i['before'],'backup_corrupt');assert([i['before'],i['after']].include?(File.file?(p) ? hash_file(p) : nil),'later_edit_requires_review')}
end
def health_rollback(b)
 j=YAML.load_file(b+'/health-journal.yaml');health_check(j)
 j['files'].each{|p,i|if i['before'];atomic(p,File.binread(i['backup']),i['mode']);else;File.unlink(p) if File.file?(p);end}
 atomic(b+'/ROLLED_BACK',Time.now.to_i.to_s);{'restored'=>true,'main_core_restarted'=>false}
end
begin
 case action
 when 'prepare'
  assert(!File.exist?(b+'/health-journal.yaml'),'already_prepared');input=YAML.load(STDIN.read)
  names=%w[/usr/share/openclash/lan-center-admission.sh /usr/share/openclash/lan-center-admission-supervisor.rb /usr/share/openclash/lan-center-admission-core.sha256]
  assert(input['files'].keys.sort==names.sort,'unexpected_targets');files={}
  input['files'].each do |p,encoded|
   n=files.length.to_s;before=File.file?(p) ? hash_file(p) : nil;backup=b+'/before-'+n;stage=b+'/after-'+n
   atomic(backup,File.binread(p)) if before;atomic(stage,encoded.unpack1('m0'))
   files[p]={'before'=>before,'after'=>hash_file(stage),'backup'=>backup,'stage'=>stage,'mode'=>before ? File.stat(p).mode&0777 : (p.end_with?('.sh') ? 0700 : 0600)}
  end
  j={'files'=>files,'mac'=>input['mac']};atomic(b+'/health-journal.yaml',YAML.dump(j));health_check(j);result={'prepared'=>true,'rollback_precheck'=>true}
 when 'apply'
  j=YAML.load_file(b+'/health-journal.yaml');health_check(j);assert(!File.exist?(b+'/ACCEPTED'),'already_accepted')
  j['files'].each{|p,i|assert((File.file?(p) ? hash_file(p) : nil)==i['before'],'baseline_changed');assert(hash_file(i['stage'])==i['after'],'stage_changed')}
  pid=Process.spawn('ruby',b+'/node_health_router.rb',b+'/helpers.rb','guard',b,in:File::NULL,out:b+'/guard.log',err:[:child,:out],pgroup:true);Process.detach(pid)
  begin;j['files'].each{|p,i|atomic(p,File.binread(i['stage']),i['mode'])};health_check(j);rescue;health_rollback(b);raise;end
  result={'applied'=>true,'guard_seconds'=>1200,'main_core_restarted'=>false}
 when 'check';health_check(YAML.load_file(b+'/health-journal.yaml'));result={'rollback_precheck'=>true}
 when 'rollback';result=health_rollback(b)
 when 'accept';health_check(YAML.load_file(b+'/health-journal.yaml'));atomic(b+'/ACCEPTED',Time.now.to_i.to_s);result={'accepted'=>true}
 when 'guard'
  deadline=Time.now+1200
  while Time.now<deadline
   exit if File.exist?(b+'/ACCEPTED')||File.exist?(b+'/ROLLED_BACK');sleep 5
  end
  result=health_rollback(b)
 else;raise 'unknown_action'
 end
 puts json(result)
rescue => e;puts json({'ok'=>false,'error_class'=>e.class.to_s});exit 1;end
