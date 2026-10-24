//go:build linux

package mihomodeploy

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "runtime"
 "strconv"
 "sync/atomic"
 "syscall"
 "time"
)

func labServiceSyntax(ctx context.Context,in *labKernelInput,a *LabConfigArtifact,d *labServiceDiagnostics,stage string) (*labSyntaxCleanupObservation,error) {
 if artifactContext(ctx)!=nil||in==nil||in.labKernelInputCore==nil||a==nil||a.AdmissionError()!=nil||in.verify()!=nil||d==nil{return nil,errLabKernelInput}
 raw:=a.Bytes();home,e:=labKernelNewHome();if e!=nil{return nil,errLabKernelInput}
 session,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 cmd:=exec.CommandContext(session,labKernelPath,"-t","-d",home,"-f","-");cmd.Dir=home;cmd.Stdin=bytes.NewReader(raw)
 cmd.Env=[]string{"PATH=/usr/bin:/bin","HOME="+home,"TMPDIR="+filepath.Join(home,"tmp"),"LANG=C.UTF-8","LC_ALL=C.UTF-8","TZ=UTC"}
 cmd.SysProcAttr=&syscall.SysProcAttr{Setpgid:true,Pdeathsig:syscall.SIGKILL};cmd.WaitDelay=time.Second
 var killed atomic.Bool;cmd.Cancel=func()error{if cmd.Process==nil{return os.ErrProcessDone};e:=cmd.Process.Kill();if e==nil{killed.Store(true)};return e}
 // Own the actual output pipes. ExitError must not be used to infer either
 // EOF or a stream failure: each Copy records its own observed termination.
 or,ow,e:=os.Pipe();if e!=nil{return nil,errLabKernelStart};defer or.Close()
 er,ew,e:=os.Pipe();if e!=nil{ow.Close();return nil,errLabKernelStart};defer er.Close()
 stdout,stderr:=&labKernelWriter{},&labKernelWriter{};cmd.Stdout=ow;cmd.Stderr=ew
 readers:=make(chan struct{},2)
 for _,pair:=range []struct{file *os.File;writer *labKernelWriter}{{or,stdout},{er,stderr}}{
  go func(file *os.File,writer *labKernelWriter){_,err:=io.Copy(writer,file);writer.finish(err);readers<-struct{}{}}(pair.file,pair.writer)
 }
 observation:=labKernelStartObservation{Attempted:true,WaitErrorClass:"NOT_WAITED"}
 runtime.LockOSThread()
 startErr:=cmd.Start();started:=startErr==nil;observation.Started=&started;_ = ow.Close();_ = ew.Close()
 var waitErr error
 if started {
  pid:=cmd.Process.Pid;observation.PID=&pid
  if stat,e:=labKernelRead("/proc/"+strconv.Itoa(pid)+"/stat",4096);e==nil{if ticks,_,e:=labKernelProcStat(stat,pid);e==nil{observation.StartTicks=&ticks}}
  waitErr=cmd.Wait();waited:=true;observation.WaitReturned=&waited;observation.WaitErrorClass="NONE"
  if waitErr!=nil{var exited *exec.ExitError;observation.WaitErrorClass="WAIT_ERROR";if errors.As(waitErr,&exited){observation.WaitErrorClass="EXIT_STATUS"}}
  if cmd.ProcessState!=nil{if status,ok:=cmd.ProcessState.Sys().(syscall.WaitStatus);ok{if status.Signaled(){signal:=int(status.Signal());observation.Signal=&signal}else{exit:=status.ExitStatus();observation.ExitCode=&exit}}}
  term:=false;kill:=killed.Load();observation.TermSent=&term;observation.KillSent=&kill
  // Read-only existence observation only; never signal a numeric PID/PGID.
  if e:=syscall.Kill(-pid,0);e==syscall.ESRCH{absent:=true;observation.GroupAbsent=&absent}else if e==nil{absent:=false;observation.GroupAbsent=&absent}
 }
 runtime.UnlockOSThread()
 _ = or.SetReadDeadline(time.Now().Add(time.Second));_ = er.SetReadDeadline(time.Now().Add(time.Second))
 <-readers;<-readers
 var outRaw,errRaw []byte
 if started{a,am:=stdout.snapshot();b,bm:=stderr.snapshot();outRaw=a;errRaw=b;observation.Stdout=&am;observation.Stderr=&bm}
 cleanup:=&labSyntaxCleanupObservation{core:&labSyntaxCleanupCore{process:cmd.Process,observation:observation}}
 record:=struct{Schema string `json:"schema"`;InputSHA256 string `json:"inputSHA256"`;InputBytes int `json:"inputBytes"`;Observation labKernelStartObservation `json:"observation"`}{"chengwang.mihomo-lab-service-syntax/v1",labConfigHash(raw),len(raw),observation}
 encoded,e:=json.Marshal(record);if e!=nil||d.write(stage+"/syntax.json",encoded)!=nil{return cleanup,errLabDiagnostics}
 if started{if d.write(stage+"/syntax.stdout",outRaw)!=nil||d.write(stage+"/syntax.stderr",errRaw)!=nil{return cleanup,errLabDiagnostics}}
 if !cleanup.settled()||!started||waitErr!=nil||session.Err()!=nil||observation.ExitCode==nil||*observation.ExitCode!=0||observation.Signal!=nil||observation.KillSent==nil||*observation.KillSent||len(errRaw)!=0||!bytes.HasSuffix(outRaw,[]byte("configuration file config.yaml test is successful\n"))||in.verify()!=nil{return cleanup,errLabKernelStart};return cleanup,nil
}
