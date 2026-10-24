//go:build linux

package mihomodeploy

import (
	"strings"
	"testing"
	"time"
)

// The child is the existing current Go MODEL executable, not Mihomo. Only
// actual registry/owned-process/listener checks are exercised by this fixture;
// the assembled observation is synthetic and proves no HTTP projection.
func labCollectorModelEvidence(t *testing.T)(*labObservedEvidence,*ownedLabKernel){
	t.Helper();k,a:=labKernelModelStart(t,"listen");identity,err:=k.identity();if err!=nil{t.Fatal("MODEL identity")}
	d,err:=newArtifactDescriptor(a.Descriptor(),strings.Repeat("a",64),128,identity.ControllerPort,identity.MixedPort);if err!=nil{t.Fatal("MODEL artifact")}
	spec,_:=planTestFixture(t);p:=&labCollectorCore{kernel:k,scope:spec.Target.Scope,issued:map[*labObservedEvidenceCore]bool{}}
	x:=&labObservedEvidenceCore{owner:p,sequence:1,value:labObservedLifecycle{Phase:"BOOTSTRAP",Scope:p.scope,DeviceRef:p.scope.ObjectID,Artifact:d,StartupIdentity:identity,VerificationSHA256:strings.Repeat("d",64),ObservedAt:time.Now().UTC()}}
	p.issued[x]=true;return &labObservedEvidence{core:x},k
}
func TestLabCollectorIssuedModelObservationConsumesOnceAndCopiesDescriptor(t *testing.T){
	e,_:=labCollectorModelEvidence(t);original:=e.core.value.Artifact.Config.Capabilities[0]
	v,err:=e.consumeLifecycle("BOOTSTRAP",time.Now().UTC());if err!=nil{t.Fatal("issued MODEL rejected")};v.Artifact.Config.Capabilities[0]="changed"
	if e.core.value.Artifact.Config.Capabilities[0]!=original{t.Fatal("descriptor alias")};if _,err:=e.consumeLifecycle("BOOTSTRAP",time.Now().UTC());err==nil{t.Fatal("proof replay")}
}
func TestLabCollectorFailedConsumeCannotReviveAfterPhaseOrClockRestoration(t *testing.T){
	for _,bad:=range []string{"WRONG_PHASE","FUTURE_TIME","STALE_TIME"}{e,_:=labCollectorModelEvidence(t);now:=time.Now().UTC();phase:="BOOTSTRAP";if bad=="WRONG_PHASE"{phase="ACKNOWLEDGED_COMPLETION"}else if bad=="FUTURE_TIME"{now=e.core.value.ObservedAt.Add(-time.Second)}else{now=e.core.value.ObservedAt.Add(31*time.Second)}
		if _,err:=e.consumeLifecycle(phase,now);err==nil{t.Fatal("invalid consumption")};if _,err:=e.consumeLifecycle("BOOTSTRAP",time.Now().UTC());err==nil{t.Fatal("failed proof revived")}}
}
func TestLabCollectorChangedActualOwnedEpochRejectsWithoutNewCapability(t *testing.T){
	e,k:=labCollectorModelEvidence(t);e.core.value.StartupIdentity.StartTicks++
	if _,err:=e.consumeLifecycle("BOOTSTRAP",time.Now().UTC());err==nil{t.Fatal("foreign epoch accepted")};if _,err:=k.identity();err!=nil{t.Fatal("test changed actual child identity")}
}
