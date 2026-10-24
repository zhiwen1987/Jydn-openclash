//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/domain"
	"go.yaml.in/yaml/v3"
)

// All subprocesses below are explicitly the current Go MODEL test binary.
// They never consume or execute a downloaded Mihomo binary. Real Mihomo
// behavior belongs to the future separate chengwang_mihomo_apply tagged suite.
func TestLabKernelModelHelper(t *testing.T) {
	mode:=os.Getenv("CHENGWANG_LAB_KERNEL_MODEL")
	if mode==""{return}
	if mode!="quiet"&&mode!="listen"&&mode!="wildcard"&&mode!="ignore-term"&&mode!="private-output"&&mode!="large-output"{os.Exit(91)}
	raw,e:=io.ReadAll(io.LimitReader(os.Stdin,MaxLabConfigBytes+1));if e!=nil||len(raw)>MaxLabConfigBytes{os.Exit(92)}
	var cfg labRawConfig;if yaml.Unmarshal(raw,&cfg)!=nil{os.Exit(93)}
	if mode=="listen"||mode=="wildcard"{
		host:="127.0.0.1";if mode=="wildcard"{host="0.0.0.0"}
		_,controller,ok:=strings.Cut(cfg.ExternalController,"127.0.0.1:");if !ok{os.Exit(94)}
		for _,p:=range []string{controller,strconv.Itoa(int(cfg.MixedPort))}{l,e:=net.Listen("tcp4",net.JoinHostPort(host,p));if e!=nil{os.Exit(95)};defer l.Close()}
	}
	if mode=="ignore-term"{signal.Ignore(syscall.SIGTERM)}
	sig:=make(chan os.Signal,1);if mode!="ignore-term"{signal.Notify(sig,syscall.SIGTERM,syscall.SIGINT);defer signal.Stop(sig)}
	if mode=="private-output"{_,_=os.Stdout.Write([]byte(cfg.Secret));_,_=os.Stderr.Write(raw)}
	if mode=="large-output"{_,_=fmt.Fprintln(os.Stdout,"MODEL_READY "+labConfigHash(raw));_,_=os.Stdout.Write(bytes.Repeat([]byte("MODEL_PRIVATE_PREFIX_"),8192))}
	_,_=fmt.Fprintln(os.Stdout,"MODEL_READY "+labConfigHash(raw))
	select{case <-sig:case <-time.After(12*time.Second):}
}

func labKernelModelArtifact(t *testing.T)*LabConfigArtifact{
	t.Helper();a,e:=BuildLabConfig(LabConfigSpec{MixedPort:30481,ControllerPort:30482,ControllerSecret:strings.Repeat("MODEL_private_",4),DefaultTarget:"DIRECT",Draft:domain.PolicyDraft{Name:"explicit MODEL laboratory process"}})
	if e!=nil||a.AdmissionError()!=nil{t.Fatal("MODEL artifact construction failed")};return a
}
func labKernelModelFixture(t *testing.T,mode string)(*labKernelInput,labKernelOps){
	t.Helper();path,e:=os.Executable();if e!=nil{t.Fatal("MODEL executable unavailable")};f,e:=os.Open(path);if e!=nil{t.Fatal("MODEL executable not readable")}
	var st syscall.Stat_t;if syscall.Fstat(int(f.Fd()),&st)!=nil{_ = f.Close();t.Fatal("MODEL executable stat failed")};h:=sha256.New();n,e:=io.Copy(h,f);_ = f.Close();if e!=nil{t.Fatal("MODEL executable hashing failed")}
	in:=&labKernelInput{&labKernelInputCore{commit:strings.Repeat("a",40),binaryHash:hex.EncodeToString(h.Sum(nil)),binaryBytes:n,binaryStat:st,receiptHash:strings.Repeat("b",64)}}
	// This seam is test-local and labels its own non-publisher input. Production
	// openLabKernelInput cannot be made to accept this executable/receipt.
	ops:=labKernelOps{verifyInput:func()error{return nil},home:func()(string,error){return t.TempDir(),nil}}
	ops.command=func(ctx context.Context,home string,raw []byte)*exec.Cmd{
		cmd:=exec.CommandContext(ctx,path,"-test.run=^TestLabKernelModelHelper$")
		cmd.Stdin=bytes.NewReader(raw);cmd.Dir=home
		cmd.Env=[]string{"PATH=/usr/bin:/bin","HOME="+home,"TMPDIR="+home,"LANG=C.UTF-8","LC_ALL=C.UTF-8","TZ=UTC","GORACE=atexit_sleep_ms=0","CHENGWANG_LAB_KERNEL_MODEL="+mode}
		return cmd
	}
	ops.observe=func(pid int)(labKernelIdentity,error){return labKernelObserve(pid,in)}
	return in,ops
}
func labKernelModelStart(t *testing.T,mode string)(*ownedLabKernel,*LabConfigArtifact){
	t.Helper();in,ops:=labKernelModelFixture(t,mode);a:=labKernelModelArtifact(t)
	ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
	k,e:=startLabKernelWith(ctx,in,a,ops);if e!=nil{if k!=nil{_,_=k.stop(context.Background())};cancel();t.Fatal("MODEL child start failed")}
	t.Cleanup(func(){_,_=k.stop(context.Background());cancel()})
	deadline:=time.NewTimer(3*time.Second);defer deadline.Stop();tick:=time.NewTicker(5*time.Millisecond);defer tick.Stop()
	for{raw,meta:=k.stdout.snapshot();ready:=bytes.Contains(raw,[]byte("MODEL_READY "+a.Descriptor().SHA256));if mode=="large-output"{ready=ready&&meta.TotalBytes>=int64(len("MODEL_PRIVATE_PREFIX_")*8192+len("MODEL_READY "+a.Descriptor().SHA256)+1)};if ready{return k,a};select{case <-k.done:t.Fatal("MODEL child exited before readiness");case <-deadline.C:t.Fatal("MODEL readiness observation expired");case <-tick.C:}}
}
func labKernelReceiptModel(t *testing.T)[]byte{
	t.Helper();r:=labKernelReceipt{Schema:"chengwang.mihomo-candidate-consumption/v1",State:"PINNED_GZIP_EXPANDED_NOT_EXECUTED",Component:"MetaCubeX/mihomo",Version:"v1.19.32",Upstream:labKernelUpstream}
	r.Source.Commit=strings.Repeat("a",40);r.Source.PinSHA256=strings.Repeat("c",64)
	for _,name:=range []string{"pin.json","consume_pin.py","check_consumption.py","test_consume_pin.py","README.md"}{r.Source.Files=append(r.Source.Files,struct{Path string `json:"path"`;Bytes int64 `json:"bytes"`;SHA256 string `json:"sha256"`}{"chengwang/tools/mihomo-runtime-candidate/"+name,1,strings.Repeat("c",64)})}
	r.Archive.Name="mihomo-linux-amd64-v1-v1.19.32.gz";r.Archive.Bytes=100;r.Archive.SHA256=labKernelPublished;r.Archive.PinBasis="PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL"
	yes,no:=true,false;r.Gzip.Single=&yes;r.Gzip.Complete=&yes;r.Gzip.CRC="12345678";r.Gzip.Size=64
	r.ELF.Bytes=64;r.ELF.SHA256=strings.Repeat("d",64);r.ELF.ByteOrder="little";r.ELF.Class="ELF64";r.ELF.Machine="AMD64";r.ELF.Type="EXEC";r.ELF.Entry=1;r.ELF.Programs=1;r.ELF.Loads=1;r.ELF.ExecutableEntry=&yes
	r.Output.Path="mihomo";r.Output.Mode="0500";r.Output.ReceiptMode="0400";r.Output.DirectoryMode="0700"
	r.RuntimeExecuted=&no;r.Compatibility=&no;r.Business=&no;r.Signature=&no;r.Approved=&no;r.Production=&no
	raw,e:=json.Marshal(r);if e!=nil{t.Fatal("MODEL receipt construction failed")};return raw
}

func TestLabKernelReceiptRequiresFixedHistoryAndPublisherBasis(t *testing.T){
	raw:=labKernelReceiptModel(t);commit:=strings.Repeat("a",40)
	if _,e:=labKernelReceiptValid(raw,commit);e!=nil{t.Fatal("synthetic structural receipt rejected")}
	for _,pair:=range [][2]string{{`"production":false`,`"production":true`},{`"runtimeExecuted":false`,`"runtimeExecuted":true`},{labKernelPublished,strings.Repeat("0",64)},{labKernelUpstream,strings.Repeat("0",40)},{`"version":"v1.19.32"`,`"version":"v1.19.33"`},{`"receiptMode":"0400"`,`"receiptMode":"0600"`},{`"singleMember":true`,`"singleMember":false`}}{
		if bytes.Equal(raw,bytes.Replace(raw,[]byte(pair[0]),[]byte(pair[1]),1)){t.Fatal("MODEL mutation did not apply")}
		if _,e:=labKernelReceiptValid(bytes.Replace(raw,[]byte(pair[0]),[]byte(pair[1]),1),commit);e==nil{t.Fatal("changed receipt accepted")}
	}
	if _,e:=labKernelReceiptValid(raw,strings.Repeat("e",40));e==nil{t.Fatal("wrong project source accepted")}
}
func TestLabKernelReceiptRejectsDuplicateUnknownAndEqualNumericTypes(t *testing.T){
	raw:=labKernelReceiptModel(t)
	for _,bad:=range [][]byte{append([]byte(`{"schema":"duplicate",`),raw[1:]...),append(append([]byte(nil),raw[:len(raw)-1]...),[]byte(`,"unexpected":null}`)...),bytes.Replace(raw,[]byte(`"bytes":1,`),[]byte(`"bytes":1.0,`),1),bytes.Replace(raw,[]byte(`"bytes":1,`),[]byte(`"bytes":true,`),1),bytes.Replace(raw,[]byte(`"production":false`),[]byte(`"production":0`),1),append(append([]byte(nil),raw...),[]byte(` {}`)...)}{
		if _,e:=labKernelReceiptValid(bad,strings.Repeat("a",40));e==nil{t.Fatal("ambiguous receipt accepted")}
	}
	// Derive rejection targets from the actual positive receipt tree, not a
	// second hand-written copy of the implementation's key lists. Each object
	// and each of the five sourceFiles entries is independently mutated.
	var tree any;if json.Unmarshal(raw,&tree)!=nil{t.Fatal("MODEL receipt tree unavailable")}
	var walk func(any,[]string)
	walk=func(node any,path []string){
		switch value:=node.(type){
		case map[string]any:
			for key,child:=range value{
				aliases:=[]string{strings.ToUpper(key[:1])+key[1:],strings.ToUpper(key)}
				if i:=strings.IndexAny(key,"sS");i>=0{aliases=append(aliases,key[:i]+"ſ"+key[i+1:])}
				for _,alias:=range aliases{if alias==key{continue};for _,duplicate:=range []bool{false,true}{
					var cloned any;if json.Unmarshal(raw,&cloned)!=nil{t.Fatal("MODEL receipt clone unavailable")};cursor:=cloned
					for _,part:=range path{switch object:=cursor.(type){case map[string]any:cursor=object[part];case []any:i,e:=strconv.Atoi(part);if e!=nil||i<0||i>=len(object){t.Fatal("MODEL receipt path invalid")};cursor=object[i];default:t.Fatal("MODEL receipt path not composite")}}
					object,ok:=cursor.(map[string]any);if !ok{t.Fatal("MODEL receipt object missing")};original:=object[key];if !duplicate{delete(object,key)};object[alias]=original
					bad,e:=json.Marshal(cloned);if e!=nil{t.Fatal("MODEL alias encoding failed")}
					if _,e:=labKernelReceiptValid(bad,strings.Repeat("a",40));e==nil{t.Fatal("case or Unicode receipt alias accepted")}
				}}
				walk(child,append(append([]string(nil),path...),key))
			}
		case []any:for i,child:=range value{walk(child,append(append([]string(nil),path...),strconv.Itoa(i)))}
		}
	}
	walk(tree,nil)
}
func TestLabKernelOwnedModelStartIdentityAndExactStdin(t *testing.T){
	k,a:=labKernelModelStart(t,"quiet");id,e:=k.identity()
	if e!=nil||id.PID<2||id.StartTicks==0||id.NetNSInode==0||id.ArtifactSHA256!=labConfigHash(a.Bytes())||id.ControllerPort!=30482||id.MixedPort!=30481{t.Fatal("owned MODEL identity missing")}
	if v,e:=k.stop(context.Background());e!=nil||!v.Started||!v.WaitReturned||!v.Stdout.Complete||!v.Stderr.Complete||v.GroupAbsent==nil||!*v.GroupAbsent{t.Fatal("MODEL cleanup not measured")}
}
func TestLabKernelOwnedModelExactLoopbackListeners(t *testing.T){
	k,_:=labKernelModelStart(t,"listen");if e:=k.verifyListeners();e!=nil{t.Fatal("owned MODEL listeners rejected")}
	if k.controllerInode==0||k.mixedInode==0||k.controllerInode==k.mixedInode{t.Fatal("socket ownership proof missing")}
}
func TestLabKernelListenersCannotBeBorrowedFromOtherPID(t *testing.T){
	var listeners []net.Listener
	for _,p:=range []string{"30481","30482"}{l,e:=net.Listen("tcp4","127.0.0.1:"+p);if e!=nil{t.Fatal("MODEL other-owner listener setup failed")};listeners=append(listeners,l);defer l.Close()}
	k,_:=labKernelModelStart(t,"quiet");if e:=k.verifyListeners();e==nil{t.Fatal("another PID listeners granted ownership")}
}
func TestLabKernelOwnedWildcardListenersAreRejected(t *testing.T){
	k,_:=labKernelModelStart(t,"wildcard");if e:=k.verifyListeners();e==nil{t.Fatal("wildcard MODEL listeners accepted")}
}
func TestLabKernelIdentityDriftFailsWithoutChangingActualPID(t *testing.T){
	in,ops:=labKernelModelFixture(t,"quiet");var changed atomic.Bool;actual:=ops.observe
	ops.observe=func(pid int)(labKernelIdentity,error){v,e:=actual(pid);if changed.Load(){v.StartTicks++};return v,e}
	ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second);defer cancel();k,e:=startLabKernelWith(ctx,in,labKernelModelArtifact(t),ops);if e!=nil{t.Fatal("MODEL process setup failed")};defer k.stop(context.Background())
	if _,e:=k.identity();e!=nil{t.Fatal("original identity rejected")};changed.Store(true)
	if _,e:=k.identity();e==nil{t.Fatal("changed start ticks accepted")}
}
func TestLabKernelInputCustodyIsRecheckedForOwnedIdentity(t *testing.T){
	in,ops:=labKernelModelFixture(t,"quiet");var changed atomic.Bool
	ops.verifyInput=func()error{if changed.Load(){return errLabKernelInput};return nil}
	ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second);defer cancel();k,e:=startLabKernelWith(ctx,in,labKernelModelArtifact(t),ops);if e!=nil{t.Fatal("MODEL process setup failed")};defer k.stop(context.Background())
	changed.Store(true);if _,e:=k.identity();e==nil{t.Fatal("changed custody accepted")}
}
func TestLabKernelFailedModelStartReturnsNoCapability(t *testing.T){
	in,ops:=labKernelModelFixture(t,"quiet");ops.command=func(ctx context.Context,home string,raw []byte)*exec.Cmd{return exec.CommandContext(ctx,filepath.Join(home,"does-not-exist"))}
	k,e:=startLabKernelWith(context.Background(),in,labKernelModelArtifact(t),ops);var observed *labKernelStartError
	if e==nil||k!=nil||!errors.As(e,&observed){t.Fatal("failed exec created capability or lost observation")}
	v:=observed.observation();if !v.Attempted||v.Started==nil||*v.Started||v.PID!=nil||v.StartTicks!=nil||v.WaitReturned==nil||*v.WaitReturned{t.Fatal("failed Start was fabricated or erased")}
	raw,je:=json.Marshal(observed);if je!=nil||bytes.Contains(raw,[]byte("does-not-exist")){t.Fatal("private Start error escaped")}
}
func TestLabKernelInitialUnobservedIdentityNeverCreatesCapability(t *testing.T){
	in,ops:=labKernelModelFixture(t,"quiet");var child atomic.Int64;actual:=ops.command
	ops.command=func(ctx context.Context,home string,raw []byte)*exec.Cmd{return actual(ctx,home,raw)}
	ops.observe=func(pid int)(labKernelIdentity,error){child.Store(int64(pid));return labKernelIdentity{},errLabKernelIdentity}
	ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second);defer cancel()
	k,e:=startLabKernelWith(ctx,in,labKernelModelArtifact(t),ops);var observed *labKernelStartError
	if e==nil||k==nil||!errors.As(e,&observed)||observed.owned()!=k{t.Fatal("failed identity erased owned cleanup handle")}
	if _,e:=k.identity();e==nil{t.Fatal("initial identity failure granted authority")}
	if v:=observed.observation();v.Started==nil||!*v.Started||v.PID==nil||v.StartTicks!=nil{t.Fatal("actual Start observation was lost or fabricated")}
	if _,e:=k.stop(context.Background());e!=nil{t.Fatal("failed identity child did not clean up")}
	if v:=observed.observation();v.WaitReturned==nil||!*v.WaitReturned{t.Fatal("actual failure Wait was lost")}
	if child.Load()<2{t.Fatal("MODEL rejection did not follow actual Start")}
	if _,e:=os.Stat("/proc/"+strconv.FormatInt(child.Load(),10));!os.IsNotExist(e){t.Fatal("rejected MODEL child was not waited")}
}
func TestLabKernelUnknownStopRetainsSameOwnedHandleUntilActualWait(t *testing.T){
	in,ops:=labKernelModelFixture(t,"ignore-term");gate:=make(chan struct{});ops.waitGate=gate
	ctx,cancel:=context.WithTimeout(context.Background(),7*time.Second);defer cancel()
	k,e:=startLabKernelWith(ctx,in,labKernelModelArtifact(t),ops);if e!=nil{close(gate);t.Fatal("MODEL gated process setup failed")}
	// Only the MODEL owner goroutine's scheduling is gated. The OS process is
	// real; no test claims this delay is a real Mihomo/OS Wait failure.
	v,e:=k.stop(context.Background());if !errors.Is(e,errLabKernelStop)||v.WaitReturned{close(gate);t.Fatal("unwaited state was falsely completed")}
	observed:=&labKernelStartError{&labKernelStartErrorCore{kernel:k}}
	if observed.owned()!=k{close(gate);t.Fatal("uncertain cleanup lost original handle")}
	before:=observed.observation();if before.PID==nil||before.StartTicks==nil||before.WaitReturned==nil||*before.WaitReturned{close(gate);t.Fatal("unwaited actual process observation missing")}
	close(gate);select{case <-k.done:case <-time.After(3*time.Second):t.Fatal("MODEL owner did not perform actual Wait")}
	if _,e:=observed.owned().stop(context.Background());e!=nil{t.Fatal("retained handle could not observe completed cleanup")}
	after:=observed.observation();if after.WaitReturned==nil||!*after.WaitReturned||after.PID==nil||*after.PID!=*before.PID{t.Fatal("late actual Wait was lost or changed process identity")}
}
func TestLabKernelSessionCancellationRecordsActualWait(t *testing.T){
	in,ops:=labKernelModelFixture(t,"ignore-term");ctx,cancel:=context.WithCancel(context.Background());k,e:=startLabKernelWith(ctx,in,labKernelModelArtifact(t),ops);if e!=nil{cancel();t.Fatal("MODEL process setup failed")}
	cancel();select{case <-k.done:case <-time.After(3*time.Second):t.Fatal("canceled MODEL child was not waited")}
	v,e:=k.stop(context.Background());if e!=nil||!v.KillSent||!v.WaitReturned{t.Fatal("session cancellation was not actually observed")}
}
func TestLabKernelStopEscalationSignalsOnlyOwnedProcess(t *testing.T){
	k,_:=labKernelModelStart(t,"ignore-term");v,e:=k.stop(context.Background())
	if e!=nil||!v.TermSent||!v.KillSent||!v.WaitReturned||v.Signal==nil||*v.Signal!=int(syscall.SIGKILL){t.Fatal("MODEL TERM/KILL/Wait sequence missing")}
}
func TestLabKernelPrivateOutputIsNeverFormattedOrReturned(t *testing.T){
	k,a:=labKernelModelStart(t,"private-output");v,e:=k.stop(context.Background());if e!=nil{t.Fatal("MODEL private stream cleanup failed")}
	privateOut,_:=k.stdout.snapshot();privateErr,_:=k.stderr.snapshot()
	if !bytes.Contains(privateOut,[]byte(strings.Repeat("MODEL_private_",4)))||!bytes.Contains(privateErr,a.Bytes()){t.Fatal("MODEL private stream not actually captured")}
	raw,e:=json.Marshal(v);if e!=nil||bytes.Contains(raw,a.Bytes())||bytes.Contains(raw,[]byte("MODEL_private_")){t.Fatal("exit metadata exposed private body")}
	var nilKernel *ownedLabKernel;var nilInput *labKernelInput;var nilFailure *labKernelStartError
	failure:=&labKernelStartError{&labKernelStartErrorCore{kernel:k}}
	secret:=[]byte(strings.Repeat("MODEL_private_",4));body:=a.Bytes()
	for _,value:=range []any{k,*k,k.input,*k.input,failure,*failure,nilKernel,nilInput,nilFailure}{
		for _,verb:=range []string{"%v","%+v","%#v","%s","%q","%x","%X","%d","%p"}{text:=fmt.Sprintf(verb,value);for _,needle:=range []string{string(secret),string(body),hex.EncodeToString(secret),hex.EncodeToString(body),base64.StdEncoding.EncodeToString(secret),base64.StdEncoding.EncodeToString(body)}{if strings.Contains(text,needle){t.Fatal("opaque handle formatting exposed private stream")}}}
		if raw,e:=json.Marshal(value);e!=nil||bytes.Contains(raw,secret)||bytes.Contains(raw,body){t.Fatal("opaque handle JSON exposed private stream")}
	}
}
func TestLabKernelOversizedPrivateStreamCannotPassCleanup(t *testing.T){
	k,_:=labKernelModelStart(t,"large-output");v,e:=k.stop(context.Background());if !errors.Is(e,errLabKernelStop)||!v.Stdout.Truncated||v.Stdout.Bytes!=labKernelStreamLimit||v.Stdout.TotalBytes<=int64(labKernelStreamLimit){t.Fatal("private stream truncation was silently accepted")}
}
func TestLabKernelNilClosedAndCancelledInputsAreRejected(t *testing.T){
	var k *ownedLabKernel;for _,value:=range []*ownedLabKernel{k,{}, {&ownedLabKernelCore{}}}{if _,e:=value.identity();e==nil{t.Fatal("empty identity accepted")};if _,e:=value.stop(nil);e==nil{t.Fatal("nil stop accepted")}}
	in,ops:=labKernelModelFixture(t,"quiet");ctx,cancel:=context.WithCancel(context.Background());cancel()
	if k,e:=startLabKernelWith(ctx,in,labKernelModelArtifact(t),ops);e==nil||k!=nil{t.Fatal("canceled input started")}
	k,_=labKernelModelStart(t,"quiet");if _,e:=k.stop(context.Background());e!=nil{t.Fatal("MODEL stop failed")};if _,e:=k.identity();!errors.Is(e,errLabKernelClosed){t.Fatal("stopped identity remained available")}
}
func TestLabKernelProcStatHandlesParenthesesAndRejectsReuse(t *testing.T){
	fields:=make([]string,22);for i:=range fields{fields[i]="0"};fields[0]="S";fields[2]="123";fields[19]="98765"
	raw:=[]byte("123 (MODEL name ) with spaces) "+strings.Join(fields," "))
	if n,p,e:=labKernelProcStat(raw,123);e!=nil||n!=98765||p!=123{t.Fatal("proc stat field alignment failed")}
	for _,bad:=range [][]byte{bytes.Replace(raw,[]byte("98765"),[]byte("0"),1),bytes.Replace(raw,[]byte(") S "),[]byte(") Z "),1),bytes.Replace(raw,[]byte("0 123 0"),[]byte("0 124 0"),1)}{if _,_,e:=labKernelProcStat(bad,123);e==nil{t.Fatal("unowned or exited stat accepted")}}
}
func TestLabKernelSocketTableRequiresOwnedExactIPv4AndUniquePort(t *testing.T){
	header:="sl local_address rem_address st tx rx tr timer retr uid timeout inode\n"
	line:="0: 0100007F:7712 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10001 0 12345 1\n"
	good:=[]byte(header+line);owned:=map[uint64]bool{12345:true}
	if got,e:=labKernelTCP(good,owned,30482,30481,false);e!=nil||got[30482]!=12345{t.Fatal("MODEL table not decoded")}
	for _,row:=range []struct{raw []byte;owners map[uint64]bool;v6 bool}{{good,map[uint64]bool{},false},{bytes.Replace(good,[]byte("0100007F"),[]byte("00000000"),1),owned,false},{good,owned,true},{[]byte(header+line+line),owned,false}}{got,e:=labKernelTCP(row.raw,row.owners,30482,30481,row.v6);if e==nil&&got[30482]!=0{t.Fatal("unsafe ownership table accepted")}}
}
func TestLabKernelExitMetadataCopiesCannotMutateObservedResult(t *testing.T){
	k,_:=labKernelModelStart(t,"quiet");v,e:=k.stop(context.Background());if e!=nil||v.ExitCode==nil||v.GroupAbsent==nil{t.Fatal("MODEL normal exit metadata unavailable")}
	*v.ExitCode=999;*v.GroupAbsent=false;again,e:=k.stop(context.Background());if e!=nil||again.ExitCode==nil||*again.ExitCode==999||again.GroupAbsent==nil||!*again.GroupAbsent{t.Fatal("metadata copy mutated owned result")}
}
func TestLabKernelNoSignalsAreIssuedAfterOwnedWait(t *testing.T){
	k,_:=labKernelModelStart(t,"quiet");first,e:=k.stop(context.Background());if e!=nil{t.Fatal("MODEL initial stop failed")};again,e:=k.stop(context.Background());if e!=nil||again.TermSent!=first.TermSent||again.KillSent!=first.KillSent{t.Fatal("completed process was signalled again")}
}
func TestLabKernelFixedInputRejectsMissingWorkerEnvelope(t *testing.T){
	t.Setenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT","")
	if in,e:=openLabKernelInput();e==nil||in!=nil{t.Fatal("fixed worker envelope absent but input opened")}
}
