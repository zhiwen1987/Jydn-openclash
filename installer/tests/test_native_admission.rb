require_relative '../runtime/native_admission'
b='/tmp/native-test-'+Process.pid.to_s;Dir.mkdir(b,0700)
begin
 lock=File.open(b+'/lock',File::RDWR|File::CREAT,0600);raise unless lock.flock(File::LOCK_EX|File::LOCK_NB)
 output=b+'/output'
 File.open(output,'w') do |out|
  code="found=Dir.glob('/proc/self/fd/*').any?{|p|(File.readlink(p) rescue '')==ARGV[0]};puts(found ? 'leaked' : 'closed')"
  raise unless NativeAdmission.bounded(['ruby','-e',code,b+'/lock'],2,out:out)
 end
 raise 'flock_inherited' unless File.read(output).strip=='closed'
 start=Process.clock_gettime(Process::CLOCK_MONOTONIC)
 raise 'timeout_failed' if NativeAdmission.bounded(['ruby','-e','sleep 30'],1)
 raise 'timeout_unbounded' if Process.clock_gettime(Process::CLOCK_MONOTONIC)-start>4
 work='/tmp/oc-admission.test-'+Process.pid.to_s;Dir.mkdir(work,0700);File.write(work+'/config.yaml','fixture')
 core=b+'/fake-core';File.write(core,"#!/bin/sh\nsleep 30\n");File.chmod(0700,core)
 NativeAdmission.lease(work,core:core,seconds:0.3)
 raise 'lease_work_leaked' if File.exist?(work)
 # The lease is independent of its SSH parent, including a non-catchable kill.
 work='/tmp/oc-admission.orphan-test-'+Process.pid.to_s;Dir.mkdir(work,0700);File.write(work+'/config.yaml','fixture')
 parent=fork do
  fork{NativeAdmission.lease(work,core:core,seconds:0.7);exit!}
  File.write(b+'/ready','ready');sleep 30
 end
 deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+3
 until File.file?(b+'/ready');raise 'parent_not_ready' if Process.clock_gettime(Process::CLOCK_MONOTONIC)>deadline;sleep 0.05;end
 Process.kill('KILL',parent);Process.waitpid(parent)
 deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+3
 while File.exist?(work);raise 'orphan_lease_unbounded' if Process.clock_gettime(Process::CLOCK_MONOTONIC)>deadline;sleep 0.05;end
 lock.close
ensure
 %w[lock output fake-core ready].each{|n|File.unlink(b+'/'+n) if File.file?(b+'/'+n)};Dir.rmdir(b)
end
puts 'native admission lifecycle: 4 tests passed'
