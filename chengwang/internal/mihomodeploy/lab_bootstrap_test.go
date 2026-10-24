package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

// MODEL ONLY: these records/disks exercise durable structure and guards. They
// are not a real owned process, a collector-issued proof, authentication, or a
// filesystem initialization permit. Real provenance is an isolated CI exit.
type labBootstrapModelDisk struct {
	*lifecycleModelDisk
	binding lifecycleProvisioning
}
func (d *labBootstrapModelDisk) provisioning()(lifecycleProvisioning,error){if d==nil{return lifecycleProvisioning{},errLifecycleUnsafe};return d.binding,d.verifyErr}
func (*labBootstrapModelDisk) artifactDirectory()string{return "/MODEL/private-artifacts"}

func labV2TestRecord(t *testing.T)(lifecycleRecord,Plan,time.Time){
	t.Helper()
	r,p,now:=lifecycleTestRecord(t)
	h:=r.wire.Head
	h.Generation=1;h.PreviousHeadSHA256=nil
	h.HeadSHA256,_=lifecycleHeadHash(*h)
	target:=lifecycleHeadTarget(*h)
	backup,err:=newBackupDescriptor(p.binding.OperationID,h.Artifact,target);if err!=nil{t.Fatal("model backup")}
	p,err=NewPlan(PlanSpec{OperationID:p.binding.OperationID,DeclaredInitiatorRef:p.binding.DeclaredInitiatorRef,Target:target,Artifact:p.binding.Artifact,Backup:backup,ExpiresAt:p.binding.ExpiresAt},now)
	if err!=nil{t.Fatal("model plan")}
	r.wire.Schema=lifecycleSchemaV2
	r.wire.V2=&lifecycleV2Wire{Provisioning:lifecycleProvisioning{Schema:"chengwang.mihomo-lab-provision-binding/v1",RuntimeID:strings.Repeat("a",64),MarkerSHA256:strings.Repeat("b",64)},Completed:[]lifecycleCompletion{},Observations:[]lifecycleObservationRecord{},Terminated:[]lifecycleTerminalArchive{}}
	return lifecycleTestSeal(t,r),p,now
}
func labV2TestPrepared(t *testing.T)(*lifecycleStore,*lifecycleModelDisk,*lifecycleOwnerToken,Plan,time.Time){
	t.Helper()
	r,p,now:=labV2TestRecord(t)
	s,d:=lifecycleTestOpen(t,r)
	owner:=lifecycleTestOwner(t,s,now)
	if s.recordPlan(owner,p,now)!=nil || s.recordApproval(owner,planTestApproval(p,now),now)!=nil || s.recordPrepared(owner,lifecycleTestPrepared(t,p,now),now)!=nil{t.Fatal("model preparation")}
	return s,d,owner,p,now
}
func labV2TestArmed(t *testing.T)(*lifecycleStore,*lifecycleModelDisk,*lifecycleOwnerToken,Plan,time.Time){
	t.Helper();s,d,owner,p,now:=labV2TestPrepared(t)
	if s.recordIntent(owner,p.binding.Target.HeadSHA256,now)!=nil{t.Fatal("model intent")}
	return s,d,owner,p,now
}
func labV2ModelCompleted(t *testing.T,s *lifecycleStore,now time.Time)lifecycleRecord{
	t.Helper()
	next,err:=s.copyRecord();if err!=nil{t.Fatal("model copy")}
	previous:=*next.wire.Head
	head:=previous;head.Generation++;head.Artifact=cloneArtifactDescriptor(next.wire.Active.Plan.Artifact)
	prior:=previous.HeadSHA256;head.PreviousHeadSHA256=&prior
	head.VerificationSHA256=strings.Repeat("e",64);head.VerifiedAt=now
	head.HeadSHA256,_=lifecycleHeadHash(head)
	next.wire.Head=&head
	next.wire.Active.Phase=lifecycleCompletedPhase
	next.wire.Active.Readback=&lifecycleReadback{Conclusion:lifecycleCompletedConclusion,EvidenceSHA256:head.VerificationSHA256,ObservedAt:now}
	next.wire.V2.Completed=append(next.wire.V2.Completed,lifecycleCompletion{PreviousHead:previous,Head:head,Active:*next.wire.Active,Owner:*next.wire.Owner,CommitRevision:next.wire.Revision+1,CommittedAt:now})
	if lifecycleAddTombstone(&next)!=nil{t.Fatal("model tombstone")}
	return next
}
func labV2TestCompleted(t *testing.T)(*lifecycleStore,*lifecycleModelDisk,*lifecycleOwnerToken,Plan,time.Time){
	t.Helper();s,d,owner,p,now:=labV2TestArmed(t)
	if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
	next:=labV2ModelCompleted(t,s,now)
	// This private structural transition is MODEL-only; it does not call or
	// replace the actual registry-bound recordAcknowledgedCompletion path.
	if s.commitTransition(next,now,lifecycleAppendCompletion)!=nil{t.Fatal("model completion")}
	return s,d,owner,p,now
}

func TestLabBootstrapV1CanonicalWireRemainsUnextended(t *testing.T){
	r,_,_:=lifecycleTestRecord(t);raw,err:=encodeLifecycleRecord(r);if err!=nil{t.Fatal(err)}
	if bytes.Contains(raw,[]byte(`"v2"`)) || bytes.Contains(raw,[]byte(`"origin"`)) || bytes.Contains(raw,[]byte(`"serviceGate"`)){t.Fatal("v1 gained fields")}
	r.wire.V2=&lifecycleV2Wire{}
	if _,err:=encodeLifecycleRecord(lifecycleTestSeal(t,r));err==nil{t.Fatal("v1 accepted extension")}
	r.wire.V2=nil;again,err:=encodeLifecycleRecord(lifecycleTestSeal(t,r))
	if err!=nil || !bytes.Equal(raw,again){t.Fatal("v1 bytes changed")}
}
func TestLabBootstrapV2RequiredExtensionAndNonnullLists(t *testing.T){
	for _,mutate:=range []func(*lifecycleWire){func(w *lifecycleWire){w.V2=nil},func(w *lifecycleWire){w.V2.Completed=nil},func(w *lifecycleWire){w.V2.Observations=nil},func(w *lifecycleWire){w.V2.Terminated=nil},func(w *lifecycleWire){w.V2.Provisioning.RuntimeID=strings.Repeat("0",64)},func(w *lifecycleWire){w.Head.Generation=2}}{
		r,_,_:=labV2TestRecord(t);mutate(r.wire);lifecycleTestReject(t,r)
	}
	r,_,_:=labV2TestRecord(t);raw,err:=encodeLifecycleRecord(r)
	if err!=nil || !bytes.Contains(raw,[]byte(`"completed":[],"observations":[]`)){t.Fatal("required v2 arrays absent")}
	for _,bad:=range [][]byte{bytes.Replace(raw,[]byte(`"runtimeID"`),[]byte(`"RuntimeID"`),1),bytes.Replace(raw,[]byte(`"completed":[]`),[]byte(`"completed":null`),1),bytes.Replace(raw,[]byte(`"v2":`),[]byte(`"v2":{},"v2":`),1)}{if _,err:=decodeLifecycleRecord(bad);err==nil{t.Fatal("noncanonical v2 accepted")}}
}
func TestLabBootstrapRuntimeNilTypedNilAndMissingControlFailClosed(t *testing.T){
	var typed *labBootstrapModelDisk
	for _,d:=range []labRuntimeDisk{nil,typed}{if _,_,err:=ownLabLifecycleRuntime(d,true);err==nil{t.Fatal("nil runtime disk accepted")}}
	r,_,_:=labV2TestRecord(t)
	d:=&labBootstrapModelDisk{lifecycleModelDisk:&lifecycleModelDisk{state:lifecycleCommitted},binding:r.wire.V2.Provisioning}
	if _,_,err:=ownLabLifecycleRuntime(d,false);err==nil || d.exists{t.Fatal("ordinary missing control initialized")}
	var runtime *labLifecycleRuntime
	if _,err:=runtime.artifactDirectory();err==nil{t.Fatal("nil directory")}
	if _,err:=runtime.existingStore();err==nil{t.Fatal("nil store")}
	if _,err:=runtime.bootstrap(nil,nil,time.Time{});err==nil{t.Fatal("nil bootstrap")}
	broken:=&labLifecycleRuntime{core:&labLifecycleRuntimeCore{store:&lifecycleStore{}}}
	if _,err:=broken.existingStore();err==nil{t.Fatal("nil store core accepted")}
	if err:=(*lifecycleStore)(nil).reserveLifecycleResultCapacity(time.Time{});err==nil{t.Fatal("nil capacity receiver accepted")}
}
func TestLabBootstrapPermitIsOwnerBoundSingleAttemptAndNoJSONImport(t *testing.T){
	r,_,now:=labV2TestRecord(t)
	newRuntime:=func()(*labLifecycleRuntime,*labFreshPermit){d:=&labBootstrapModelDisk{lifecycleModelDisk:&lifecycleModelDisk{state:lifecycleCommitted},binding:r.wire.V2.Provisioning};runtime,p,err:=ownLabLifecycleRuntime(d,true);if err!=nil{t.Fatal(err)};t.Cleanup(func(){_=runtime.close()});return runtime,p}
	a,p:=newRuntime();b,q:=newRuntime()
	if _,err:=a.bootstrap(q,nil,now);err==nil || p.core.used{t.Fatal("foreign permit changed owner")}
	copyPermit:=*p
	if _,err:=a.bootstrap(&copyPermit,nil,now);err==nil || !p.core.used{t.Fatal("admitted failed attempt not consumed")}
	if _,err:=a.bootstrap(p,nil,now);err==nil{t.Fatal("permit reused")}
	if json.Unmarshal([]byte(`{}`),q)==nil || json.Unmarshal([]byte(`{}`),b)==nil{t.Fatal("JSON imported runtime authority")}
}
func TestLabBootstrapRuntimeReopenBindsMarkerAndRejectsV1Migration(t *testing.T){
	for _,legacy:=range []bool{false,true}{
		r,_,_:=labV2TestRecord(t);binding:=r.wire.V2.Provisioning
		if legacy{r.wire.Schema=lifecycleSchema;r.wire.V2=nil;r=lifecycleTestSeal(t,r)}
		raw,err:=encodeLifecycleRecord(r);if err!=nil{t.Fatal(err)}
		d:=&labBootstrapModelDisk{lifecycleModelDisk:&lifecycleModelDisk{raw:raw,exists:true,state:lifecycleCommitted},binding:binding}
		runtime,p,err:=ownLabLifecycleRuntime(d,false)
		if legacy{if err==nil{t.Fatal("v1 silently migrated")};continue}
		if err!=nil || p!=nil{t.Fatal("model v2 reopen")}
		if _,err:=runtime.existingStore();err!=nil{t.Fatal("existing record not available")}
		_=runtime.close()
	}
	r,_,_:=labV2TestRecord(t);raw,_:=encodeLifecycleRecord(r);binding:=r.wire.V2.Provisioning;binding.MarkerSHA256=strings.Repeat("c",64)
	d:=&labBootstrapModelDisk{lifecycleModelDisk:&lifecycleModelDisk{raw:raw,exists:true,state:lifecycleCommitted},binding:binding}
	if _,_,err:=ownLabLifecycleRuntime(d,false);err==nil{t.Fatal("different marker accepted")}
	for _,legacy:=range []bool{false,true}{for _,ack:=range []bool{false,true}{
		var s *lifecycleStore;var owner *lifecycleOwnerToken;var now time.Time
		if legacy{s,_,owner,_,now=lifecycleTestArmed(t)}else{s,_,owner,_,now=labV2TestArmed(t)}
		if ack && s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
		original:=bytes.Clone(s.raw)
		binding:=lifecycleProvisioning{Schema:"chengwang.mihomo-lab-provision-binding/v1",RuntimeID:strings.Repeat("a",64),MarkerSHA256:strings.Repeat("b",64)}
		if !legacy{binding.MarkerSHA256=strings.Repeat("c",64)}
		d:=&labBootstrapModelDisk{lifecycleModelDisk:&lifecycleModelDisk{raw:bytes.Clone(original),exists:true,state:lifecycleCommitted},binding:binding}
		if runtime,_,err:=ownLabLifecycleRuntime(d,false);err==nil{_=runtime.close();t.Fatal("foreign armed/ack record admitted")}
		if d.writes!=0 || !bytes.Equal(d.raw,original){t.Fatal("rejected schema/marker wrote UNKNOWN before rejection")}
	}}
	for _,ack:=range []bool{false,true}{
		s,_,owner,_,now:=labV2TestArmed(t)
		if ack && s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
		originalResult:=s.record.wire.Active.Result
		d:=&labBootstrapModelDisk{lifecycleModelDisk:&lifecycleModelDisk{raw:bytes.Clone(s.raw),exists:true,state:lifecycleCommitted},binding:s.record.wire.V2.Provisioning}
		runtime,permit,err:=ownLabLifecycleRuntime(d,false)
		if err!=nil || permit!=nil{t.Fatal("matching v2 reopen rejected")}
		store,err:=runtime.existingStore()
		if err!=nil || d.writes!=1 || store.record.wire.Active.Phase!="UNKNOWN" || !reflect.DeepEqual(store.record.wire.Active.Result,originalResult){t.Fatal("matching v2 recovery lost original facts")}
		_=runtime.close()
	}
}
func TestLabBootstrapOpaqueRuntimeAndPermitFormattingProtectValueCopies(t *testing.T){
	secret:="model-private-runtime-nonce-not-a-real-credential"
	r:=labLifecycleRuntime{core:&labLifecycleRuntimeCore{disk:&labBootstrapModelDisk{binding:lifecycleProvisioning{RuntimeID:secret}}}}
	p:=labFreshPermit{core:&labFreshPermitCore{runtime:r.core}}
	for _,v:=range []any{r,&r,p,&p}{for _,verb:=range []string{"%v","%+v","%#v","%d","%x","%p"}{if strings.Contains(fmt.Sprintf(verb,v),secret){t.Fatal("private wrapper reflected core")}};raw,err:=json.Marshal(v);if err!=nil || bytes.Contains(raw,[]byte(secret)){t.Fatal("private wrapper JSON leaked")}}
	var nilRuntime *labLifecycleRuntime;var nilPermit *labFreshPermit
	for _,v:=range []any{nilRuntime,nilPermit}{raw,err:=json.Marshal(v);if err!=nil || string(raw)!="null"{t.Fatal("typed nil JSON")};_=fmt.Sprintf("%#v %p %x",v,v,v)}
}
func TestLabBootstrapV2AdapterOriginCannotBecomeServiceGate(t *testing.T){
	s,_,owner,_,now:=labV2TestArmed(t)
	if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
	if s.record.wire.Active.Result.Origin!="ADAPTER" || s.record.wire.Active.Result.ServiceGate!=nil{t.Fatal("adapter origin lost")}
	for _,origin:=range []string{"","SERVICE_GATE","adapter"}{r,_:=s.copyRecord();r.wire.Active.Result.Origin=origin;lifecycleTestReject(t,r)}
}
func TestLabBootstrapV2ServiceGateExactSourceAndTimeBindings(t *testing.T){
	s,_,_,_,now:=labV2TestArmed(t);r,_:=s.copyRecord();a:=r.wire.Active
	f:=&labServiceGateFact{OperationID:a.Plan.OperationID,PlanSHA256:a.Plan.PlanSHA256,IntentSHA256:a.Intent.IntentSHA256,Reason:"OWNED_IDENTITY_REJECTED",ObservedAt:now}
	a.Result=&lifecycleResult{Reload:mihomo.ReloadResult{State:mihomo.ReloadRejected},ObservedAt:now,Origin:"SERVICE_GATE",ServiceGate:f};a.Phase="UNSENT_REJECTED"
	if lifecycleAddTombstone(&r)!=nil || lifecycleAppendTerminalArchive(&r,now)!=nil{t.Fatal("model tombstone")};r.wire.Revision++;r=lifecycleTestSeal(t,r)
	if _,err:=encodeLifecycleRecord(r);err!=nil{t.Fatal("closed gate fact rejected")}
	for _,mutate:=range []func(*labServiceGateFact){func(v *labServiceGateFact){v.PlanSHA256=strings.Repeat("f",64)},func(v *labServiceGateFact){v.Reason="raw exception"},func(v *labServiceGateFact){v.ObservedAt=now.Add(time.Second)}}{bad,err:=decodeLifecycleRecord(mustLabV2Encode(t,r));if err!=nil{t.Fatal(err)};mutate(bad.wire.Active.Result.ServiceGate);lifecycleTestReject(t,bad)}
}
func mustLabV2Encode(t *testing.T,r lifecycleRecord)[]byte{t.Helper();raw,err:=encodeLifecycleRecord(r);if err!=nil{t.Fatal("model encode")};return raw}
func TestLabBootstrapV2CompletionRequiresTypedEvidenceAndAcknowledgedState(t *testing.T){
	s,d,owner,_,now:=labV2TestArmed(t);writes:=d.writes
	if s.recordAcknowledgedCompletion(owner,nil,now)==nil || s.recordUnknownObservation(owner,nil,now)==nil || s.recordServiceGate(owner,s.record.wire.Active.Intent.IntentSHA256,nil,now)==nil || d.writes!=writes{t.Fatal("nil proof wrote facts")}
	if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
	writes=d.writes
	if s.recordAcknowledgedCompletion(owner,&labObservedEvidence{},now)==nil || d.writes!=writes{t.Fatal("forged collector proof accepted")}
}
func TestLabBootstrapV2GenericCommitCannotAdvanceHeadOrAppendFacts(t *testing.T){
	s,d,owner,_,now:=labV2TestArmed(t)
	if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
	next:=labV2ModelCompleted(t,s,now);writes:=d.writes
	if s.commit(next,now)==nil || d.writes!=writes{t.Fatal("generic commit advanced head")}
}
func TestLabBootstrapV2FullCompletionArchiveCanonicalChain(t *testing.T){
	s,_,owner,oldPlan,now:=labV2TestCompleted(t)
	raw:=mustLabV2Encode(t,s.record);decoded,err:=decodeLifecycleRecord(raw)
	if err!=nil || !reflect.DeepEqual(decoded.wire,s.record.wire){t.Fatal("archive roundtrip")}
	c:=decoded.wire.V2.Completed[0]
	if c.PreviousHead.Generation!=1 || c.Head.Generation!=2 || c.Active.Intent==nil || c.Active.Result==nil || c.Active.Approval==nil || c.Owner.Fence==0 || c.CommitRevision!=decoded.wire.Revision{t.Fatal("full history missing")}
	// A later cancelled plan on the same owner/head cannot resurrect the old
	// successful Active, even after recomputing the entire record digest.
	target:=lifecycleHeadTarget(*s.record.wire.Head)
	backup,err:=newBackupDescriptor("model-later-cancel",s.record.wire.Head.Artifact,target);if err!=nil{t.Fatal("model backup")}
	p,err:=NewPlan(PlanSpec{OperationID:"model-later-cancel",DeclaredInitiatorRef:oldPlan.binding.DeclaredInitiatorRef,Target:target,Artifact:oldPlan.binding.Backup.Artifact,Backup:backup,ExpiresAt:now.Add(time.Minute)},now)
	if err!=nil || s.recordPlan(owner,p,now)!=nil || s.recordRevocation(owner,"EXPLICIT_REVOKED","model-revoker",now)!=nil{t.Fatal("model later cancel")}
	bad,_:=s.copyRecord();oldActive:=bad.wire.V2.Completed[0].Active;bad.wire.Active=&oldActive;lifecycleTestReject(t,bad)
}
func TestLabBootstrapV2ArchivePreviousHeadAndGenerationCannotBeRehashedAway(t *testing.T){
	s,_,_,_,_:=labV2TestCompleted(t)
	t.Run("self-consistent-new-head-digest-still-requires-generation-step",func(t *testing.T){
		r,_:=s.copyRecord();c:=&r.wire.V2.Completed[0]
		c.Head.Generation++
		c.Head.HeadSHA256,_=lifecycleHeadHash(c.Head)
		head:=c.Head;r.wire.Head=&head
		// All affected head/record digests are recomputed; the rejected fact
		// is generation+2, not an unrelated stale SHA.
		lifecycleTestReject(t,r)
	})
	for _,mutate:=range []func(*lifecycleCompletion){func(c *lifecycleCompletion){c.Head.Generation++},func(c *lifecycleCompletion){c.PreviousHead.Artifact=c.Head.Artifact},func(c *lifecycleCompletion){c.Owner.Fence++},func(c *lifecycleCompletion){c.CommittedAt=c.CommittedAt.Add(-time.Second)},func(c *lifecycleCompletion){c.Active.Plan.Target.HeadSHA256=strings.Repeat("f",64)}}{
		r,_:=s.copyRecord();mutate(&r.wire.V2.Completed[0]);lifecycleTestReject(t,r)
	}
}
func TestLabBootstrapV2ArchivePrefixCannotBeDeletedOrRewritten(t *testing.T){
	s,d,_,_,now:=labV2TestCompleted(t)
	for _,mutate:=range []func(*lifecycleWire){func(w *lifecycleWire){w.V2.Completed=[]lifecycleCompletion{}},func(w *lifecycleWire){w.V2.Completed[0].Active.Result.ObservedAt=now.Add(time.Second)},func(w *lifecycleWire){w.V2.Provisioning.RuntimeID=strings.Repeat("c",64)}}{next,_:=s.copyRecord();mutate(next.wire);writes:=d.writes;if s.commit(next,now)==nil || d.writes!=writes{t.Fatal("history prefix changed")}}
}
func TestLabBootstrapV2OwnerReplacementRetainsCompleteOriginalResult(t *testing.T){
	s,_,_,oldPlan,now:=labV2TestCompleted(t);before:=mustLabV2Encode(t,s.record)
	archive:=s.record.wire.V2.Completed[0]
	later:=now.Add(3*time.Minute)
	owner,err:=s.acquireOwner(later,now.Add(4*time.Minute));if err!=nil{t.Fatal("model next owner")}
	if s.record.wire.Active!=nil || !reflect.DeepEqual(archive,s.record.wire.V2.Completed[0]) || bytes.Equal(before,s.raw){t.Fatal("clearing active lost original facts")}
	target:=lifecycleHeadTarget(*s.record.wire.Head)
	backup,err:=newBackupDescriptor("model-next-operation",s.record.wire.Head.Artifact,target);if err!=nil{t.Fatal("model next backup")}
	p,err:=NewPlan(PlanSpec{OperationID:"model-next-operation",DeclaredInitiatorRef:oldPlan.binding.DeclaredInitiatorRef,Target:target,Artifact:oldPlan.binding.Backup.Artifact,Backup:backup,ExpiresAt:later.Add(time.Minute)},later)
	if err!=nil || s.recordPlan(owner,p,later)!=nil || !reflect.DeepEqual(archive,s.record.wire.V2.Completed[0]){t.Fatal("new plan lost previous complete facts")}
	if _,err:=decodeLifecycleRecord(s.raw);err!=nil{t.Fatal("history not durable")}
}
func TestLabBootstrapV2UnknownObservationsRemainBlockingAndAppendOnly(t *testing.T){
	s,d,owner,_,now:=labV2TestArmed(t)
	if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadUnknown,Dispatched:true},now)!=nil{t.Fatal("model unknown")}
	head:=*s.record.wire.Head
	next,_:=s.copyRecord();a:=next.wire.Active
	next.wire.V2.Observations=append(next.wire.V2.Observations,lifecycleObservationRecord{OperationID:a.Plan.OperationID,PlanSHA256:a.Plan.PlanSHA256,IntentSHA256:a.Intent.IntentSHA256,Readback:lifecycleReadback{Conclusion:lifecycleObservationConclusion,EvidenceSHA256:strings.Repeat("d",64),ObservedAt:now},CommitRevision:next.wire.Revision+1})
	if s.commitTransition(next,now,lifecycleAppendObservation)!=nil || s.record.wire.Active.Phase!="UNKNOWN" || !reflect.DeepEqual(head,*s.record.wire.Head){t.Fatal("observation changed authority")}
	writes:=d.writes
	if _,err:=s.acquireOwner(now.Add(3*time.Minute),now.Add(4*time.Minute));err==nil || d.writes!=writes{t.Fatal("observation released unknown barrier")}
	next,_=s.copyRecord();next.wire.V2.Observations=[]lifecycleObservationRecord{}
	if s.commit(next,now)==nil{t.Fatal("observation removed")}
}
func TestLabBootstrapV2ExpiryAndRevocationCannotEraseAcknowledgedArchive(t *testing.T){
	s,_,owner,_,now:=labV2TestArmed(t)
	later:=now.Add(3*time.Minute)
	if s.recordRevocation(owner,"EXPIRED","model-actor",later)!=nil || s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},later)!=nil{t.Fatal("real result lost to expiry")}
	next:=labV2ModelCompleted(t,s,later)
	if s.commitTransition(next,later,lifecycleAppendCompletion)!=nil || s.record.wire.V2.Completed[0].Active.Revocation==nil{t.Fatal("expiry erased archived result")}
}
func TestLabBootstrapV2PrearmReservesActualPayloadAndFixedFutureMetadata(t *testing.T){
	s,d,owner,p,now:=labV2TestPrepared(t)
	if s.reserveLifecycleResultCapacity(now)!=nil{t.Fatal("small model did not fit")}
	oldRaw:=s.raw
	// MODEL resource unit: the input length is measured, not a fabricated Go
	// transcript or real serialized observation. No disk write is performed.
	s.raw=make([]byte,maxLifecycleControlBytes-(64<<10))
	if s.reserveLifecycleResultCapacity(now)==nil{t.Fatal("insufficient result reserve accepted")}
	s.raw=oldRaw
	s.record.wire.Revision=^uint64(0)-3;s.record=lifecycleTestSeal(t,s.record);s.raw=mustLabV2Encode(t,s.record);d.raw=bytes.Clone(s.raw)
	writes:=d.writes
	if s.recordIntent(owner,p.binding.Target.HeadSHA256,now)==nil || d.writes!=writes{t.Fatal("revision reserve missing")}
}
func TestLabBootstrapV2ResourceLimitsNeverGarbageCollectHistory(t *testing.T){
	r,_,_:=labV2TestRecord(t)
	r.wire.V2.Completed=make([]lifecycleCompletion,maxLifecycleHistory+1);lifecycleTestReject(t,r)
	r,_,_=labV2TestRecord(t);r.wire.V2.Observations=make([]lifecycleObservationRecord,maxLifecycleHistory+1);lifecycleTestReject(t,r)
	r,_,_=labV2TestRecord(t);r.wire.V2.Terminated=make([]lifecycleTerminalArchive,maxLifecycleHistory+1);lifecycleTestReject(t,r)
	s,_,_,_,now:=labV2TestPrepared(t);s.record.wire.V2.Completed=make([]lifecycleCompletion,maxLifecycleHistory)
	if s.reserveLifecycleResultCapacity(now)==nil || len(s.record.wire.V2.Completed)!=maxLifecycleHistory{t.Fatal("capacity silently collected history")}
}
func TestLabBootstrapV2RevokedAndUnsentArchivesSurviveSubsequentPlans(t *testing.T){
	for _,kind:=range []string{"prearm-revocation","adapter-unsent","service-gate-unsent"}{t.Run(kind,func(t *testing.T){
		var s *lifecycleStore;var owner *lifecycleOwnerToken;var p Plan;var now time.Time
		if kind=="prearm-revocation"{
			s,_,owner,p,now=labV2TestPrepared(t)
			if s.recordRevocation(owner,"EXPLICIT_REVOKED","model-revoker",now)!=nil{t.Fatal("model revoke")}
		}else{
			s,_,owner,p,now=labV2TestArmed(t)
			if kind=="adapter-unsent"{
				if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadRejected},now)!=nil{t.Fatal("model unsent adapter")}
			}else{
				// MODEL wire transition, not a service-issued gate capability.
				next,_:=s.copyRecord();a:=next.wire.Active
				fact:=&labServiceGateFact{OperationID:a.Plan.OperationID,PlanSHA256:a.Plan.PlanSHA256,IntentSHA256:a.Intent.IntentSHA256,Reason:"FINAL_AUTHORIZATION_REJECTED",ObservedAt:now}
				a.Phase="UNSENT_REJECTED";a.Result=&lifecycleResult{Reload:mihomo.ReloadResult{State:mihomo.ReloadRejected},ObservedAt:now,Origin:"SERVICE_GATE",ServiceGate:fact}
				lifecycleAppendAudit(a,"RESULT_RECORDED")
				if lifecycleAddTombstone(&next)!=nil || lifecycleAppendTerminalArchive(&next,now)!=nil || s.commitTransition(next,now,lifecycleAppendTermination)!=nil{t.Fatal("model gate archive")}
			}
		}
		if len(s.record.wire.V2.Terminated)!=1{t.Fatal("terminal fact not archived atomically")}
		original:=s.record.wire.V2.Terminated[0]
		target:=lifecycleHeadTarget(*s.record.wire.Head)
		backup,err:=newBackupDescriptor("next-after-terminal",s.record.wire.Head.Artifact,target);if err!=nil{t.Fatal("model backup")}
		nextPlan,err:=NewPlan(PlanSpec{OperationID:"next-after-terminal",DeclaredInitiatorRef:p.binding.DeclaredInitiatorRef,Target:target,Artifact:p.binding.Artifact,Backup:backup,ExpiresAt:now.Add(time.Minute)},now)
		if err!=nil || s.recordPlan(owner,nextPlan,now)!=nil || !reflect.DeepEqual(original,s.record.wire.V2.Terminated[0]){t.Fatal("new plan erased terminal history")}
		if original.Active.Plan.OperationID!=p.binding.OperationID || original.Owner.Fence==0 || (kind=="prearm-revocation" && original.Active.Revocation==nil) || (kind!="prearm-revocation" && (original.Active.Intent==nil || original.Active.Result==nil)){t.Fatal("terminal archive incomplete")}
		if kind=="service-gate-unsent" && (original.Active.Result.ServiceGate==nil || original.Active.Result.Origin!="SERVICE_GATE"){t.Fatal("gate provenance lost")}
		for _,mutate:=range []func(*lifecycleWire){func(w *lifecycleWire){w.V2.Terminated=[]lifecycleTerminalArchive{}},func(w *lifecycleWire){w.V2.Terminated[0].Active.Plan.OperationID="rewritten"}}{next,_:=s.copyRecord();mutate(next.wire);if s.commit(next,now)==nil{t.Fatal("terminal prefix changed")}}
		if _,err:=decodeLifecycleRecord(s.raw);err!=nil{t.Fatal("terminal history not canonical")}
	})}
}
func TestLabBootstrapV2ReadbackCommitFailurePreservesUnknownAndPoisons(t *testing.T){
	s,d,owner,_,now:=labV2TestArmed(t)
	if s.recordResult(owner,s.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},now)!=nil{t.Fatal("model ack")}
	next:=labV2ModelCompleted(t,s,now);d.corruptReadback=true
	if err:=s.commitTransition(next,now,lifecycleAppendCompletion);!errors.Is(err,errLifecycleCommitUnknown) || !s.poisoned{t.Fatal("completion uncertainty hidden")}
	if s.recordAcknowledgedCompletion(owner,nil,now)==nil{t.Fatal("poisoned store reused")}
}
