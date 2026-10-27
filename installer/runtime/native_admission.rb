# Fixed restricted native admission executor. Children never inherit the flock.
module NativeAdmission
 def self.cleanup(work)
  return unless work && work.start_with?('/tmp/oc-admission.') && File.directory?(work) && File.realpath(work)==work
  %w[config.yaml token cache.db cache.db-shm cache.db-wal input.yaml response control.cfg].each{|n|p=work+'/'+n;File.unlink(p) if File.file?(p)}
  begin;Dir.rmdir(work);rescue Errno::ENOTEMPTY,Errno::ENOENT;end
 end
 def self.lease(work,core:'/etc/openclash/core/clash_meta',seconds:50)
  raise 'invalid_lease_directory' unless work.start_with?('/tmp/oc-admission.') && File.realpath(work)==work && File.file?(work+'/config.yaml')
  previous_term=Signal.trap('TERM'){raise Interrupt}
  pid=Process.spawn(core,'-d',work,'-f',work+'/config.yaml',in:File::NULL,out:File::NULL,err:File::NULL,pgroup:true,close_others:true)
  begin
   deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+seconds
   loop do
    break if Process.waitpid(pid,Process::WNOHANG)
    break if Process.clock_gettime(Process::CLOCK_MONOTONIC)>=deadline
    sleep 0.1
   end
  ensure
   begin;Process.kill('TERM',-pid);rescue Errno::ESRCH;end
   sleep 0.1
   begin;Process.kill('KILL',-pid);rescue Errno::ESRCH;end
   begin;Process.waitpid(pid);rescue Errno::ECHILD;end
   cleanup(work)
   Signal.trap('TERM',previous_term)
  end
 end
 def self.bounded(args,seconds,input:nil,out:File::NULL)
  # The watchdog survives an abruptly killed SSH/Ruby parent. Separate process
  # groups permit bounded cleanup without touching the production core.
  pid=Process.spawn('timeout','-s','KILL',seconds.to_s,*args,in:input||File::NULL,out:out,err:File::NULL,pgroup:true,close_others:true)
  deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+seconds+2
  begin
   loop do
    pair=Process.waitpid2(pid,Process::WNOHANG);return pair[1].success? if pair
    raise 'child_deadline' if Process.clock_gettime(Process::CLOCK_MONOTONIC)>=deadline
    sleep 0.05
   end
  ensure
   begin;Process.kill('TERM',-pid);rescue Errno::ESRCH;end
   stop=Process.clock_gettime(Process::CLOCK_MONOTONIC)+1
   loop do
    begin;break if Process.waitpid(pid,Process::WNOHANG);rescue Errno::ECHILD;break;end
    break if Process.clock_gettime(Process::CLOCK_MONOTONIC)>=stop;sleep 0.05
   end
   begin;Process.kill('KILL',-pid);rescue Errno::ESRCH;end
   begin;Process.waitpid(pid);rescue Errno::ECHILD;end
  end
 end
 def self.run
  return [false,'command_not_allowed'] unless ENV['SSH_ORIGINAL_COMMAND']=='validate-v1'
  return [false,'client_not_allowed'] unless ENV.fetch('SSH_CONNECTION','').start_with?('10.88.0.249 ')
  File.open('/tmp/lan-center-admission.lock',File::RDWR|File::CREAT,0600) do |lock|
   return [false,'busy'] unless lock.flock(File::LOCK_EX|File::LOCK_NB)
   core='/etc/openclash/core/clash_meta'
   pin=File.read('/usr/share/openclash/lan-center-admission-core.sha256').strip
   digest=IO.popen(['sha256sum',core],err:File::NULL){|f|f.read}.split.first
   return [false,'core_version_changed'] unless digest==pin
   occupied=%w[/proc/net/tcp /proc/net/tcp6].any?{|p|File.file?(p)&&File.readlines(p).drop(1).any?{|line|v=line.split;v[3]=='0A'&&%w[45E8 45E9].include?(v[1].split(':').last)}}
   return [false,'admission_port_busy'] if occupied
   work='/tmp/oc-admission.'+Process.pid.to_s+'-'+rand(1<<40).to_s;Dir.mkdir(work,0700);raw=STDIN.read(2*1024*1024+1)
   begin
    return [false,'input_rejected'] if raw.bytesize>2*1024*1024
    File.open(work+'/input.yaml','w+',0600) do |input|
     input.write(raw);input.flush;input.rewind
     return [false,'input_rejected'] unless bounded(['ruby','/usr/share/openclash/lan-center-admission-config.rb',work+'/config.yaml',work+'/token'],8,input:input)
    end
    return [false,'core_validation_failed'] unless bounded([core,'-t','-d',work,'-f',work+'/config.yaml'],10)
    # A 50-second independent lease also contains orphaned test cores.
    pid=Process.spawn('ruby',__FILE__,'--lease',work,in:File::NULL,out:File::NULL,err:File::NULL,pgroup:true,close_others:true)
    begin
     token=File.read(work+'/token').strip
     raise 'invalid_control_token' unless token.match?(/\A[0-9a-f]{32}\z/)
     File.open(work+'/control.cfg','w',0600){|f|f.write("url = \"http://127.0.0.1:17897/version\"\nheader = \"Authorization: Bearer #{token}\"\n")}
     ready=false;ready_deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+8
     while Process.clock_gettime(Process::CLOCK_MONOTONIC)<ready_deadline
      if bounded(['curl','-fsS','--max-time','1','--config',work+'/control.cfg','-o','/dev/null'],2);ready=true;break;end
      sleep 0.2
     end
     return [false,'isolated_core_not_ready'] unless ready
     ['https://www.gstatic.com/generate_204','https://cp.cloudflare.com/generate_204'].each do |url|
      File.open(work+'/response','w+',0600) do |output|
       ok=bounded(['curl','-sS','--connect-timeout','5','--max-time','10','-x','http://127.0.0.1:17896','-o','/dev/null','-w','%{http_code}',url],12,out:output)
       output.rewind;return [false,'isolated_transport_failed'] unless ok && output.read.strip=='204'
      end
     end
     [true,'native_exit_two_endpoints_passed']
    ensure
     begin;Process.kill('TERM',-pid);rescue Errno::ESRCH;end
     deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+1
     loop do
      begin;break if Process.waitpid(pid,Process::WNOHANG);rescue Errno::ECHILD;break;end
      break if Process.clock_gettime(Process::CLOCK_MONOTONIC)>=deadline;sleep 0.05
     end
     begin;Process.kill('KILL',-pid);rescue Errno::ESRCH;end
     begin;Process.waitpid(pid);rescue Errno::ECHILD;end
    end
   ensure
    # Only the exact private directory created by this invocation is removed.
    cleanup(work)
   end
  end
 end
end
if __FILE__==$0
 if ARGV.length==2 && ARGV[0]=='--lease';NativeAdmission.lease(ARGV[1]);exit;end
 begin;ok,reason=NativeAdmission.run;puts '{"ok":'+(ok ? 'true' : 'false')+',"reason":"'+reason+'"}'
 rescue;puts '{"ok":false,"reason":"admission_executor_error"}';end
end
