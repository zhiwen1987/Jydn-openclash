package mihomodeploy

import (
	"errors"
	"encoding/json"
	"testing"
)

func TestLabDiagnosticsRejectsTraversalAndUnboundedOperationSlots(t *testing.T){
	for _,s:=range []string{"../secret","op-00/create/body-1.json","op-09/create/body-1.json","op-01/../../body-1.json","op-01/create/body-9.json","op-1/syntax.json","op-01/unknown/body-1.json","credentials.json"}{if labDiagnosticName(s){t.Fatal("unsafe diagnostic name")}}
	for _,s:=range []string{"bootstrap/body-1.json","op-08/post-dispatch/body-8.json","op-01/syntax.json","bootstrap/verification.json","op-08/post-dispatch/verification.json"}{if !labDiagnosticName(s){t.Fatal("fixed name rejected")}}
}
func TestLabDiagnosticsVerificationCountsAgainstExistingCaptureAndGlobalBudgets(t *testing.T){
	// Budget rejection is distinct from the unavailable MODEL sink, so a
	// missing budget check cannot pass merely because a later write fails.
	d:=&labServiceDiagnostics{core:&labDiagnosticsCore{captureBytes:map[string]int{"bootstrap":labDiagnosticsCapture-4}}}
	if _,err:=d.verification("bootstrap",[]byte("12345"));!errors.Is(err,errLabDiagnosticsLimit){t.Fatal("receipt excluded from capture budget")}
	d.core.captureBytes["bootstrap"]=1;d.core.used=labDiagnosticsTotal-4
	if _,err:=d.verification("bootstrap",[]byte("12345"));!errors.Is(err,errLabDiagnosticsLimit){t.Fatal("receipt excluded from total budget")}
	d.core.used=0
	if _,err:=d.verification("bootstrap",make([]byte,labDiagnosticsVerification+1));!errors.Is(err,errLabDiagnosticsLimit){t.Fatal("receipt size cap lost")}
}
func TestLabDiagnosticsCleanupJournalPreservesOriginalObservations(t *testing.T){
	// SYNTHETIC codec case: unobserved values must not become cleanup success.
	raw,err:=labCleanupRaw(nil,nil);if err!=nil{t.Fatal(err)};var fields map[string]json.RawMessage
	if json.Unmarshal(raw,&fields)!=nil||len(fields)!=3||string(fields["kernel"])!="null"||string(fields["fixtures"])!="null"||string(fields["stage"])!=`"CLEANUP_OBSERVED"`{t.Fatal("unobserved cleanup invented observations")}
	kernel:=&labKernelExit{Started:true,WaitReturned:false,WaitErrorClass:"NOT_WAITED"};fixtures:=[]labLocalFixtureCleanup{{Role:"A",ErrorClass:"SHUTDOWN",ForcedConnectionsClosed:1}}
	raw,err=labCleanupRaw(kernel,fixtures);if err!=nil{t.Fatal(err)};var decoded struct{Stage string;Kernel labKernelExit;Fixtures []labLocalFixtureCleanup}
	if json.Unmarshal(raw,&decoded)!=nil||decoded.Kernel.WaitReturned||decoded.Kernel.GroupAbsent!=nil||len(decoded.Fixtures)!=1||decoded.Fixtures[0].ErrorClass!="SHUTDOWN"||decoded.Fixtures[0].ForcedConnectionsClosed!=1{t.Fatal("cleanup payload was rewritten")}
}
func TestLabDiagnosticsMissingPrivateSinkCannotClaimCapturedOriginals(t *testing.T){
	var d *labServiceDiagnostics;var bodies [8][]byte
	if d.capture("bootstrap",[]byte(`{}`),bodies)==nil||d.write("kernel.stdout",nil)==nil{t.Fatal("missing originals claimed successful")}
}
