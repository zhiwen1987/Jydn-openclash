package mihomodeploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"chengwang/internal/adapter/mihomo"
)

const labDiagnosticsPath = "/tmp/chengwang-mihomo-service-private"
const labDiagnosticsTotal = 64 << 20
const labDiagnosticsBody = 256 << 10
const labDiagnosticsCapture = 2 << 20 // Includes the actual transcript, not just bodies.
const labDiagnosticsVerification = 64 << 10
var errLabDiagnostics = errors.New("private laboratory diagnostics unavailable")
var errLabDiagnosticsLimit = errors.New("private laboratory diagnostic budget exceeded")
type labServiceDiagnostics struct { core *labDiagnosticsCore }
type labDiagnosticsCore struct {
	mu sync.Mutex
	platform *labDiagnosticsPlatform
	used int
	journalBytes int
	captureBytes map[string]int
	closed bool
}
func (labServiceDiagnostics) String() string { return "private bounded laboratory diagnostics" }
func (labServiceDiagnostics) GoString() string { return "private bounded laboratory diagnostics" }
func (labServiceDiagnostics) Format(s fmt.State,_ rune) { _,_=io.WriteString(s,"private bounded laboratory diagnostics") }
func (labServiceDiagnostics) MarshalJSON() ([]byte,error) {return []byte(`{"scope":"PRIVATE_DIAGNOSTICS_NOT_PUBLIC_OUTPUT"}`),nil}
func labDiagnosticName(name string) bool {
	if name==".secrets.private.json"||name=="local-a.config.private.yaml"||name=="local-b.config.private.yaml"||name=="kernel.stdout"||name=="kernel.stderr" {return true}
	parts:=strings.Split(name,"/");if len(parts)==2&&parts[0]=="bootstrap" {return labCaptureBase(parts[1])}
	if len(parts)<2||len(parts)>3||len(parts[0])!=5||!strings.HasPrefix(parts[0],"op-") {return false}
	n,err:=strconv.Atoi(parts[0][3:]);if err!=nil||n<1||n>8||parts[0]!=fmt.Sprintf("op-%02d",n){return false}
	if len(parts)==2{return parts[1]=="syntax.json"||parts[1]=="syntax.stdout"||parts[1]=="syntax.stderr"}
	return (parts[1]=="create"||parts[1]=="pre-dispatch"||parts[1]=="post-dispatch")&&labCaptureBase(parts[2])
}
func labCaptureBase(s string) bool {if s=="transcript.json"||s=="verification.json"{return true};for i:=1;i<=8;i++{if s=="body-"+strconv.Itoa(i)+".json"{return true}};return false}
func openLabServiceDiagnostics() (*labServiceDiagnostics,error) {p,err:=openLabDiagnosticsPlatform();if err!=nil{return nil,err};return &labServiceDiagnostics{core:&labDiagnosticsCore{platform:p}},nil}
func (d *labServiceDiagnostics) write(name string,raw []byte) error {
	if d==nil||d.core==nil||!labDiagnosticName(name)||len(raw)>labDiagnosticsCapture{return errLabDiagnostics};c:=d.core;c.mu.Lock();defer c.mu.Unlock()
	if c.closed||len(raw)>labDiagnosticsTotal-c.used{return errLabDiagnostics}
	if err:=c.platform.write(name,raw,false);err!=nil{return err};c.used+=len(raw);return nil
}
func (d *labServiceDiagnostics) capture(stage string,transcript []byte,bodies [8][]byte) error {
	// The transcript and each nonnil original are private, exclusive writes.
	// A failure leaves an honest subset; no absent body is padded with empty data.
	failed:=false;total:=0
	if len(transcript)==0||len(transcript)>labDiagnosticsBody{failed=true}else if d.write(stage+"/transcript.json",transcript)!=nil{failed=true}else{total=len(transcript)}
	for i,b:=range bodies {if b==nil{failed=true;continue};if len(b)>labDiagnosticsBody||len(b)>labDiagnosticsCapture-total{failed=true;continue};if d.write(stage+"/body-"+strconv.Itoa(i+1)+".json",b)!=nil{failed=true}else{total+=len(b)}}
	if failed{_ = d.event("CAPTURE_UNAVAILABLE","","");return errLabDiagnostics}
	d.core.mu.Lock();if d.core.captureBytes==nil{d.core.captureBytes=map[string]int{}};d.core.captureBytes[stage]=total;d.core.mu.Unlock();return nil
}
// The caller supplies the one canonical byte slice used for the issued hash.
// This path neither reserializes it nor fetches any replacement HTTP body.
func(d *labServiceDiagnostics)verification(stage string,raw []byte)(string,error){
	if d==nil||d.core==nil||!labDiagnosticName(stage+"/verification.json")||len(raw)==0{return "",errLabDiagnostics};if len(raw)>labDiagnosticsVerification{return "",errLabDiagnosticsLimit}
	c:=d.core;c.mu.Lock();defer c.mu.Unlock();used,exists:=c.captureBytes[stage]
	if !exists||c.closed{return "",errLabDiagnostics};if len(raw)>labDiagnosticsCapture-used||len(raw)>labDiagnosticsTotal-c.used{return "",errLabDiagnosticsLimit}
	if c.platform.write(stage+"/verification.json",raw,false)!=nil{return "",errLabDiagnostics};c.used+=len(raw);c.captureBytes[stage]+=len(raw);return labConfigHash(raw),nil
}
func (d *labServiceDiagnostics) event(stage,operationID,intentSHA string) error {
	allowed:=map[string]bool{"STARTUP":true,"HEAD_READY":true,"PLANNED":true,"APPROVED":true,"PREPARED":true,"DISPATCH_ARMED":true,"RELOAD_CALL_INTENT":true,"RESULT_RECORDED":true,"SERVICE_GATE_RECORDED":true,"OBSERVATION_RECORDED":true,"COMPLETED":true,"REVOKED":true,"CLOSED":true,"CAPTURE_UNAVAILABLE":true}
	if d==nil||d.core==nil||!allowed[stage]||(operationID!=""&&!planReference.MatchString(operationID))||(intentSHA!=""&&!lifecycleNonzeroHash(intentSHA)){return errLabDiagnostics}
	raw,err:=json.Marshal(struct{Stage string `json:"stage"`;OperationID string `json:"operationId"`;IntentSHA256 string `json:"intentSHA256"`}{stage,operationID,intentSHA});if err!=nil{return errLabDiagnostics};raw=append(raw,'\n')
	c:=d.core;c.mu.Lock();defer c.mu.Unlock();if c.closed||len(raw)>(256<<10)-c.journalBytes||len(raw)>labDiagnosticsTotal-c.used{return errLabDiagnostics}
	if err:=c.platform.write("service-journal.jsonl",raw,true);err!=nil{return err};c.journalBytes+=len(raw);c.used+=len(raw);return nil
}
func (d *labServiceDiagnostics) close() error {if d==nil||d.core==nil{return nil};c:=d.core;c.mu.Lock();defer c.mu.Unlock();if c.closed{return nil};c.closed=true;return c.platform.close()}

func(d *labServiceDiagnostics)cleanupObserved(kernel *labKernelExit,fixtures []labLocalFixtureCleanup)error{
	if d==nil||d.core==nil{return errLabDiagnostics}
	// Original returned metadata only. No additional stop/probe and no
	// invented successful process, stream or fixture observation occurs here.
	raw,err:=labCleanupRaw(kernel,fixtures);if err!=nil{return errLabDiagnostics}
	c:=d.core;c.mu.Lock();defer c.mu.Unlock();if c.closed||len(raw)>(256<<10)-c.journalBytes||len(raw)>labDiagnosticsTotal-c.used{return errLabDiagnostics}
	if c.platform.write("service-journal.jsonl",raw,true)!=nil{return errLabDiagnostics};c.journalBytes+=len(raw);c.used+=len(raw);return nil
}
func labCleanupRaw(kernel *labKernelExit,fixtures []labLocalFixtureCleanup)([]byte,error){
	raw,err:=json.Marshal(struct{Stage string `json:"stage"`;Kernel *labKernelExit `json:"kernel"`;Fixtures []labLocalFixtureCleanup `json:"fixtures"`}{"CLEANUP_OBSERVED",kernel,fixtures});if err!=nil{return nil,errLabDiagnostics};return append(raw,'\n'),nil
}

func (d *labServiceDiagnostics) adapterReturned(id,intent string,result mihomo.ReloadResult,recorded bool)error{
	if d==nil||d.core==nil||!planReference.MatchString(id)||!lifecycleNonzeroHash(intent)||!lifecycleResultValid(result){return errLabDiagnostics}
	raw,err:=json.Marshal(struct{Stage string `json:"stage"`;OperationID string `json:"operationId"`;IntentSHA256 string `json:"intentSHA256"`;Result mihomo.ReloadResult `json:"result"`;WALRecorded bool `json:"walRecorded"`}{"RELOAD_RETURNED",id,intent,result,recorded});if err!=nil{return errLabDiagnostics};raw=append(raw,'\n')
	c:=d.core;c.mu.Lock();defer c.mu.Unlock();if c.closed||len(raw)>(256<<10)-c.journalBytes||len(raw)>labDiagnosticsTotal-c.used{return errLabDiagnostics};if c.platform.write("service-journal.jsonl",raw,true)!=nil{return errLabDiagnostics};c.journalBytes+=len(raw);c.used+=len(raw);return nil
}
