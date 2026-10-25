package mihomodeploy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// SYNTHETIC DATA ONLY. No process is started, no listener is probed and no
// authority is authenticated by this fixture. It cannot issue a production cap.
func labRecoveryStartedModel(t *testing.T) (labRecoveryStartedBinding, labRecoveryStartedFact, time.Time) {
	t.Helper()
	old, _, now := labQuiescenceModel(t)
	spec := labConfigTestSpec(); spec.ControllerPort = 28412; spec.MixedPort = 28411
	a, err := newArtifactDescriptor(labConfigTestBuild(t, spec).Descriptor(), strings.Repeat("d", 64), 512, 28412, 28411)
	if err != nil { t.Fatal("MODEL artifact") }
	b := labRecoveryStartedBinding{RecoveryID: old.RecoveryID, RecoveryPlanSHA256: old.RecoveryPlanSHA256,
		StartIntentSHA256: strings.Repeat("5",64), Revision: 17, RecordSHA256: strings.Repeat("6",64), TargetArtifact: a,
		QuiescenceSHA256: strings.Repeat("7",64), ArmedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		ExpectedOldIdentity: old.ExpectedOldIdentity, StartMillis: 10000}
	id := b.ExpectedOldIdentity; id.PID++; id.StartTicks++; id.ArtifactSHA256 = a.Config.SHA256
	started, waited, no, class, pid, ticks, ns := true, false, false, "NONE", id.PID, id.StartTicks, id.NetNSInode
	stream := labKernelStream{SHA256:labConfigHash(nil)} // MODEL incomplete running stream, not a false EOF claim
	start := labKernelStartObservation{Attempted:true, Started:&started, PID:&pid, StartTicks:&ticks, WaitReturned:&waited,
		WaitErrorClass:"NOT_WAITED", TermSent:&no, KillSent:&no, Stdout:&stream, Stderr:&stream}
	begin := now.Add(-time.Millisecond); yes := true
	f := labRecoveryStartedFact{Schema:labRecoveryStartedFactSchema, Binding:labRecoveryStartedCloneBinding(b), ObservedAt:now,
		Observation:labRecoveryStartObservation{Schema:labRecoveryStartObservationSchema, PermitConsumed:true, StartInvoked:true,
			StartReturned:true, StartErrorClass:&class, StartObservation:&start, StartupIdentity:&id, VerifiedIdentity:&id,
			NamespaceInode:&ns, ListenersBefore:&yes, ListenersAfter:&yes, StartedAt:&begin, ReturnedAt:&now, Outcome:"STARTED", FailureCode:"NONE"}}
	labRecoveryStartedModelReseal(t, &f)
	return b, f, now
}

func labRecoveryStartedModelReseal(t *testing.T, f *labRecoveryStartedFact) {
	t.Helper()
	h, err := labRecoveryStartedFactHash(*f)
	if err != nil { t.Fatal("MODEL digest") }
	f.StartedSHA256 = h
}

func TestLabRecoveryStartedBindingRejectsInvalidSourceAndBudget(t *testing.T) {
	b, _, now := labRecoveryStartedModel(t)
	if !labRecoveryStartedBindingValid(b, now) { t.Fatal("MODEL valid binding") }
	for _, mutate := range []func(*labRecoveryStartedBinding){
		func(v *labRecoveryStartedBinding){v.RecoveryID="labop_"+strings.Repeat("1",32)},
		func(v *labRecoveryStartedBinding){v.RecoveryPlanSHA256=strings.Repeat("0",64)},
		func(v *labRecoveryStartedBinding){v.StartIntentSHA256=""},
		func(v *labRecoveryStartedBinding){v.Revision=0},
		func(v *labRecoveryStartedBinding){v.RecordSHA256=""},
		func(v *labRecoveryStartedBinding){v.QuiescenceSHA256=""},
		func(v *labRecoveryStartedBinding){v.ExpectedOldIdentity.PID=0},
		func(v *labRecoveryStartedBinding){v.TargetArtifact.ControllerPort=28413},
		func(v *labRecoveryStartedBinding){v.TargetArtifact.Config.Admissible=false},
		func(v *labRecoveryStartedBinding){v.TargetArtifact.Config.Capabilities=nil},
		func(v *labRecoveryStartedBinding){v.TargetArtifact.SourceSpecBytes++},
		func(v *labRecoveryStartedBinding){v.StartMillis=10001},
	} {
		bad:=labRecoveryStartedCloneBinding(b); mutate(&bad)
		if labRecoveryStartedBindingValid(bad,now){t.Fatal("MODEL invalid binding")}
	}
}

func TestLabRecoveryStartedBindingRejectsExpiryRollbackAndNonUTC(t *testing.T) {
	b, _, now := labRecoveryStartedModel(t)
	for _, at := range []time.Time{time.Time{},b.ArmedAt.Add(-time.Nanosecond),b.ExpiresAt,b.ArmedAt.Add(10000*time.Millisecond+time.Nanosecond),now.In(time.FixedZone("notUTC",0))} {
		if labRecoveryStartedBindingValid(b,at){t.Fatal("MODEL invalid phase time")}
	}
	bad:=b; bad.ExpiresAt=bad.ArmedAt.Add(5*time.Minute+time.Nanosecond)
	if labRecoveryStartedBindingValid(bad,now){t.Fatal("MODEL excessive material window")}
}

func TestLabRecoveryStartedIdentityRequiresDifferentPhysicalTuple(t *testing.T) {
	b,f,_:=labRecoveryStartedModel(t); id:=*f.Observation.StartupIdentity
	if !labRecoveryStartedIdentityValid(id,b){t.Fatal("MODEL distinct tuple")}
	// PID reuse is legal only with a different real start tick. A different PID
	// need not also have a different tick; the pair, not either scalar, differs.
	for _, pair := range [][2]uint64{{uint64(b.ExpectedOldIdentity.PID),id.StartTicks},{uint64(id.PID),b.ExpectedOldIdentity.StartTicks}} {
		other:=id; other.PID=int(pair[0]); other.StartTicks=pair[1]
		if !labRecoveryStartedIdentityValid(other,b){t.Fatal("MODEL distinct pair rejected")}
	}
	id.PID=b.ExpectedOldIdentity.PID; id.StartTicks=b.ExpectedOldIdentity.StartTicks
	if labRecoveryStartedIdentityValid(id,b){t.Fatal("MODEL old epoch reused")}
}

func TestLabRecoveryStartedIdentityRejectsKernelNamespaceSourceAndArtifactDrift(t *testing.T) {
	b,f,_:=labRecoveryStartedModel(t)
	for _, mutate:=range []func(*labKernelIdentity){
		func(v *labKernelIdentity){v.NetNSInode++},func(v *labKernelIdentity){v.ELFSHA256=strings.Repeat("e",64)},
		func(v *labKernelIdentity){v.ELFBytes++},func(v *labKernelIdentity){v.SourceCommit=strings.Repeat("e",40)},
		func(v *labKernelIdentity){v.ArtifactSHA256=strings.Repeat("e",64)},func(v *labKernelIdentity){v.ControllerPort++},
		func(v *labKernelIdentity){v.MixedPort++},func(v *labKernelIdentity){v.PID=1},
	} { id:=*f.Observation.StartupIdentity;mutate(&id);if labRecoveryStartedIdentityValid(id,b){t.Fatal("MODEL identity drift")}}
}

func TestLabRecoveryStartedFactChecksEveryObservedSuccessBoundary(t *testing.T) {
	b,f,now:=labRecoveryStartedModel(t)
	if !labRecoveryStartedFactValid(f,b,now){t.Fatal("MODEL valid observed fact")}
	for _, mutate:=range []func(*labRecoveryStartedFact){
		func(v *labRecoveryStartedFact){v.Schema="wrong"},func(v *labRecoveryStartedFact){v.Observation.PermitConsumed=false},
		func(v *labRecoveryStartedFact){v.Observation.StartInvoked=false},func(v *labRecoveryStartedFact){v.Observation.StartReturned=false},
		func(v *labRecoveryStartedFact){v.Observation.StartErrorClass=nil},func(v *labRecoveryStartedFact){*v.Observation.StartErrorClass="FAILED"},
		func(v *labRecoveryStartedFact){v.Observation.StartupIdentity=nil},func(v *labRecoveryStartedFact){v.Observation.VerifiedIdentity.PID++},
		func(v *labRecoveryStartedFact){v.Observation.NamespaceInode=nil},func(v *labRecoveryStartedFact){*v.Observation.NamespaceInode++},
		func(v *labRecoveryStartedFact){v.Observation.ListenersBefore=nil},func(v *labRecoveryStartedFact){*v.Observation.ListenersAfter=false},
		func(v *labRecoveryStartedFact){v.Observation.Outcome="START_UNCERTAIN"},func(v *labRecoveryStartedFact){v.Observation.FailureCode="FAILED"},
		func(v *labRecoveryStartedFact){v.Observation.StartedAt=nil},func(v *labRecoveryStartedFact){*v.Observation.ReturnedAt=v.ObservedAt.Add(time.Nanosecond)},
	} { bad:=labRecoveryStartedCloneFact(f);mutate(&bad);labRecoveryStartedModelReseal(t,&bad);if labRecoveryStartedFactValid(bad,b,now){t.Fatal("MODEL bad success boundary")}}
}

func TestLabRecoveryStartedFactNeverInventsWaitOrStartedMetadata(t *testing.T) {
	b,f,now:=labRecoveryStartedModel(t)
	for _,mutate:=range []func(*labKernelStartObservation){
		func(v *labKernelStartObservation){v.Attempted=false},func(v *labKernelStartObservation){v.Started=nil},
		func(v *labKernelStartObservation){*v.Started=false},func(v *labKernelStartObservation){v.PID=nil},
		func(v *labKernelStartObservation){*v.StartTicks++},func(v *labKernelStartObservation){*v.WaitReturned=true},
		func(v *labKernelStartObservation){v.WaitErrorClass="NONE"},func(v *labKernelStartObservation){v.ExitCode=new(int)},
		func(v *labKernelStartObservation){v.GroupAbsent=new(bool)},func(v *labKernelStartObservation){*v.TermSent=true},
		func(v *labKernelStartObservation){*v.KillSent=true},func(v *labKernelStartObservation){v.Stdout=nil},
	} {bad:=labRecoveryStartedCloneFact(f);mutate(bad.Observation.StartObservation);labRecoveryStartedModelReseal(t,&bad);if labRecoveryStartedFactValid(bad,b,now){t.Fatal("MODEL invented running observation")}}
}

func TestLabRecoveryStartedFactRejectsCoherentDigestAndBindingTamper(t *testing.T) {
	b,f,now:=labRecoveryStartedModel(t)
	bad:=labRecoveryStartedCloneFact(f);bad.StartedSHA256=strings.Repeat("e",64)
	if labRecoveryStartedFactValid(bad,b,now){t.Fatal("MODEL forged hash")}
	bad=labRecoveryStartedCloneFact(f);bad.Binding.Revision++;labRecoveryStartedModelReseal(t,&bad)
	if labRecoveryStartedFactValid(bad,b,now){t.Fatal("MODEL cross revision")}
	bad=labRecoveryStartedCloneFact(f);bad.Observation.StartupIdentity.NetNSInode++;bad.Observation.VerifiedIdentity.NetNSInode++
	*bad.Observation.NamespaceInode++;labRecoveryStartedModelReseal(t,&bad)
	if labRecoveryStartedFactValid(bad,b,now){t.Fatal("MODEL coherent namespace drift")}
}

func TestLabRecoveryStartedFactRecordTimeDoesNotRenewOriginalWindow(t *testing.T) {
	b,f,now:=labRecoveryStartedModel(t)
	if !labRecoveryStartedFactValid(f,b,now.Add(24*time.Hour)){t.Fatal("MODEL late record lost original fact")}
	for _,at:=range []time.Time{now.Add(-time.Nanosecond),{},now.In(time.FixedZone("notUTC",0))}{if labRecoveryStartedFactValid(f,b,at){t.Fatal("MODEL record clock")}}
	bad:=labRecoveryStartedCloneFact(f);late:=b.ArmedAt.Add(10000*time.Millisecond+time.Nanosecond)
	bad.ObservedAt=late;bad.Observation.ReturnedAt=&late;labRecoveryStartedModelReseal(t,&bad)
	if labRecoveryStartedFactValid(bad,b,late){t.Fatal("MODEL late native return became timely fact")}
}

func TestLabRecoveryStartedFactAndBindingCopiesAreDetached(t *testing.T) {
	b,f,now:=labRecoveryStartedModel(t)
	copy:=labRecoveryStartedCloneFact(f)
	copy.Binding.TargetArtifact.Config.Capabilities[0]="MODEL_mutation"
	copy.Observation.StartObservation.PID=new(int);copy.Observation.StartupIdentity.PID++
	*copy.Observation.ListenersBefore=false;*copy.Observation.ReturnedAt=now.Add(time.Hour)
	if !labRecoveryStartedFactValid(f,b,now) || reflect.DeepEqual(copy,f){t.Fatal("MODEL aliased copy")}
	other:=labRecoveryStartedCloneBinding(b);other.TargetArtifact.Config.Requirements=nil
	if b.TargetArtifact.Config.Requirements==nil{t.Fatal("MODEL binding alias")}
}

func TestLabRecoveryStartedOpaqueFormattingAndJSONCannotRecreateCapability(t *testing.T) {
	b,f,_:=labRecoveryStartedModel(t)
	q:=labRecoveryStartedEpoch{core:&labRecoveryStartedEpochCore{nonce:[32]byte{1,2,3},fact:f}}
	for _,v:=range []any{q,&q}{
		for _,verb:=range []string{"%v","%+v","%#v","%s","%q","%x","%X","%d","%p"}{
			out:=fmt.Sprintf(verb,v)
			for _,private:=range []string{b.RecoveryID,b.RecordSHA256,b.TargetArtifact.Config.SHA256,"ExpectedOldIdentity","nonce:","fact:"}{if strings.Contains(out,private){t.Fatal("MODEL format exposed private structure")}}
		}
		raw,err:=json.Marshal(v);if err!=nil || string(raw)!=`{"scope":"OBSERVED_START_NOT_AUTHORIZATION_OR_HEAD"}`{t.Fatal("MODEL public JSON metadata")}
		var restored labRecoveryStartedEpoch;if json.Unmarshal(raw,&restored)==nil || restored.core!=nil{t.Fatal("MODEL JSON reconstructed cap")}
	}
	var nilValue *labRecoveryStartedEpoch
	for _,verb:=range []string{"%v","%#v","%d","%x","%p"}{_ = fmt.Sprintf(verb,nilValue)}
	for _,value:=range []*labRecoveryStartedEpoch{nilValue,{}, {core:&labRecoveryStartedEpochCore{fact:f}}}{if _,err:=value.consumeStartedEpochForRecord(b,f.ObservedAt);err==nil{t.Fatal("MODEL DTO acquired provenance")}}
}
