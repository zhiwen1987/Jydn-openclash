package mihomodeploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"chengwang/internal/adapter/mihomo"
)

func TestLabCollectorNoJSONOrCallerDigestMintsObservation(t *testing.T){
	now:=time.Now().UTC();var nilProof *labObservedEvidence
	for _,e:=range []*labObservedEvidence{nilProof,{}, {core:&labObservedEvidenceCore{sequence:1,value:labObservedLifecycle{Phase:"BOOTSTRAP",VerificationSHA256:strings.Repeat("a",64),ObservedAt:now}}}}{if _,err:=e.consumeLifecycle("BOOTSTRAP",now);err==nil{t.Fatal("unissued proof accepted")}}
	var restored labObservedEvidence;if json.Unmarshal([]byte(`{"verificationSHA256":"`+strings.Repeat("a",64)+`"}`),&restored)==nil{t.Fatal("JSON restored authority")}
}
func TestLabCollectorMissingActualInputsNeverStartsCollection(t *testing.T){
	var c *labCollector
	if _,e:=c.collect(context.Background(),"BOOTSTRAP","","","","","","bootstrap");e==nil{t.Fatal("nil collector accepted")}
	if _,e:=newLabCollector(nil,nil,nil,nil,TargetBinding{}.Scope);e==nil{t.Fatal("missing owned inputs accepted")}
}
func TestLabCollectorOpaqueDebugDoesNotRevealObservationValues(t *testing.T){
	e:=labObservedEvidence{core:&labObservedEvidenceCore{value:labObservedLifecycle{DeviceRef:"sensitive-owned-device",OperationID:"sensitive-operation"},transcriptSHA256:strings.Repeat("e",64)}}
	for _,v:=range []any{e,&e,(*labObservedEvidence)(nil)}{raw,_:=json.Marshal(v);for _,s:=range []string{string(raw),fmt.Sprintf("%v %+v %#v %s %d %x %p",v,v,v,v,v,v,v)}{if strings.Contains(s,"sensitive-")||strings.Contains(s,strings.Repeat("e",64)){t.Fatal("private observation escaped")}}}
}
func TestLabCollectorVerificationBytesKeepAnEmptySelfHash(t *testing.T){
	// SYNTHETIC codec receipt; this does not issue a collector capability.
	value:=labObservedLifecycle{Phase:"BOOTSTRAP",ObservedAt:time.Date(2026,10,25,1,2,3,4,time.UTC)}
	raw,err:=labCollectorVerificationRaw(value,mihomo.LabReadbackReport{},strings.Repeat("a",64),[8]string{},labLocalRoute{});if err!=nil{t.Fatal(err)}
	var fields map[string]json.RawMessage;if json.Unmarshal(raw,&fields)!=nil||len(fields)!=5{t.Fatal("receipt field set")}
	for _,key:=range []string{"Observation","Readback","Transcript","Bodies","Route"}{if _,ok:=fields[key];!ok{t.Fatal("receipt field missing")}}
	var observation map[string]json.RawMessage;if json.Unmarshal(fields["Observation"],&observation)!=nil||string(observation["VerificationSHA256"])!=`""`{t.Fatal("self hash was included")}
	value.VerificationSHA256=labConfigHash(raw);if _,err:=labCollectorVerificationRaw(value,mihomo.LabReadbackReport{},"",[8]string{},labLocalRoute{});err==nil{t.Fatal("recursive self hash accepted")}
	if len(raw)==0||raw[len(raw)-1]=='\n'{t.Fatal("canonical receipt gained newline")}
}
