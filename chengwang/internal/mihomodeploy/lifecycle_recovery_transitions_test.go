//go:build linux

package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

// MODEL ONLY: build valid structural records with the source-selected physical
// ports. There is no process/collector capability and no authenticated actor.
func lifecycleRecoveryStopModel(t *testing.T) (*lifecycleRecoveryStore,*lifecycleModelDisk,*lifecycleRecoveryOwnerToken,labRecoveryPlan,labKernelIdentity,time.Time) {
	t.Helper();r,oldPlan,now:=labV2TestRecord(t)
	base:=labConfigTestSpec();base.ControllerPort=28412;base.MixedPort=28411
	candidate:=base;candidate.DefaultTarget="REJECT"
	oldArtifact,err:=newArtifactDescriptor(labConfigTestBuild(t,base).Descriptor(),strings.Repeat("3",64),512,28412,28411);if err!=nil {t.Fatal("MODEL base")}
	newArtifact,err:=newArtifactDescriptor(labConfigTestBuild(t,candidate).Descriptor(),strings.Repeat("4",64),513,28412,28411);if err!=nil {t.Fatal("MODEL candidate")}
	h:=r.wire.Head;h.Artifact=oldArtifact;h.ControllerPort=28412;h.MixedPort=28411;h.HeadSHA256,_=lifecycleHeadHash(*h)
	backup,err:=newBackupDescriptor(oldPlan.Descriptor().OperationID,oldArtifact,lifecycleHeadTarget(*h));if err!=nil {t.Fatal("MODEL backup")}
	p,err:=NewPlan(PlanSpec{OperationID:oldPlan.Descriptor().OperationID,DeclaredInitiatorRef:oldPlan.Descriptor().DeclaredInitiatorRef,Target:lifecycleHeadTarget(*h),Artifact:newArtifact,Backup:backup,ExpiresAt:now.Add(time.Minute)},now);if err!=nil {t.Fatal("MODEL ordinary plan")}
	r=lifecycleTestSeal(t,r);legacy,d:=lifecycleTestOpen(t,r);o:=lifecycleTestOwner(t,legacy,now)
	prepared:=&PreparedReload{preparedReloadCore:&preparedReloadCore{descriptor:ReloadPreparationDescriptor{Schema:ReloadPreparationSchema,Boundary:ReloadPreparationBoundary,Plan:p.Descriptor(),PreparedAt:now},candidate:labConfigTestBuild(t,candidate).Bytes(),backup:labConfigTestBuild(t,base).Bytes()}}
	if legacy.recordPlan(o,p,now)!=nil||legacy.recordApproval(o,planTestApproval(p,now),now)!=nil||legacy.recordPrepared(o,prepared,now)!=nil||legacy.recordIntent(o,p.Descriptor().Target.HeadSHA256,now)!=nil {t.Fatal("MODEL original intent")}
	if legacy.recordResult(o,legacy.record.wire.Active.Intent.IntentSHA256,mihomo.ReloadResult{State:mihomo.ReloadUnknown,Dispatched:true,StatusCode:0},now)!=nil {t.Fatal("MODEL original unknown")}
	recovery,err:=newLabRecoveryPlan(legacy.record,"labrec_"+strings.Repeat("1",32),"MODEL_initiator",newArtifact,now,now.Add(time.Minute));if err!=nil {t.Fatal("MODEL recovery plan")}
	s,err:=evolveLifecycleV2ForRecovery(legacy,&recovery,now);if err!=nil {t.Fatal("MODEL evolve")}
	owner:=lifecycleRecoveryModelOwner(t,s,now)
	if s.beginRecovery(owner,&recovery,s.core.record.core.Revision,s.core.record.core.RecordSHA256,now)!=nil {t.Fatal("MODEL begin")}
	approval,err:=newLifecycleRecoveryApproval(&recovery,"MODEL_independent_approver",now,now.Add(time.Minute));if err!=nil||s.recordRecoveryApproval(owner,approval,now)!=nil {t.Fatal("MODEL approval")}
	identity:=labKernelIdentity{PID:h.PID,StartTicks:h.StartTicks,NetNSInode:h.NetNSInode,ELFSHA256:h.KernelSHA256,ELFBytes:1024,SourceCommit:strings.Repeat("c",40),ArtifactSHA256:oldArtifact.Config.SHA256,ControllerPort:28412,MixedPort:28411}
	return s,d,owner,recovery,identity,now
}
func lifecycleRecoveryModelArmed(t *testing.T) (*lifecycleRecoveryStore,*lifecycleModelDisk,*lifecycleRecoveryOwnerToken,labRecoveryPlan,labQuiescenceBinding,time.Time) {
	t.Helper();s,d,o,p,i,now:=lifecycleRecoveryStopModel(t);b,err:=s.armRecoveryStop(o,i,now);if err!=nil {t.Fatal("MODEL stop arm")};return s,d,o,p,b,now
}
func lifecycleRecoveryModelFact(b labQuiescenceBinding,now time.Time) labQuiescenceFact {
	exit:=0;absent:=true;ns:=b.ExpectedOldIdentity.NetNSInode;i:=b.ExpectedOldIdentity
	stream:=labKernelStream{Bytes:0,TotalBytes:0,SHA256:labConfigHash(nil),Complete:true}
	stop:=labKernelExit{Started:true,WaitReturned:true,WaitErrorClass:"NONE",ExitCode:&exit,GroupAbsent:&absent,Stdout:stream,Stderr:stream}
	controller:=labQuiescenceProbe{28412,true,"CONNECTION_REFUSED"};mixed:=labQuiescenceProbe{28411,true,"CONNECTION_REFUSED"}
	stopClass:="NONE"
	o:=labQuiescenceObservation{Schema:labQuiescenceObservationSchema,StartupIdentity:&i,StopInvoked:true,StopReturned:true,Stop:&stop,StopErrorClass:&stopClass,NamespaceInode:&ns,ControllerProbe:&controller,MixedProbe:&mixed,StartedAt:&now,ReturnedAt:&now,Outcome:"QUIESCED",FailureCode:"NONE"}
	f:=labQuiescenceFact{labQuiescenceFactSchema,b,o,now,""};f.QuiescenceSHA256,_=labQuiescenceFactHash(f);return f
}
// Reuse B's private issued-registry/retained-owner STRUCTURE MODEL. The fake
// os.Process metadata is never stopped/signaled/probed. Consumption itself is
// the actual one-use implementation, not core.commit or a production factory.
func lifecycleRecoveryIssuedModel(t *testing.T,b labQuiescenceBinding,f labQuiescenceFact) *labQuiescedEpoch {
	t.Helper();old,_,_,_:=labQuiescenceOwnedModel(t)
	pid,ticks:=b.ExpectedOldIdentity.PID,b.ExpectedOldIdentity.StartTicks
	old.process.Pid=pid;old.bound=b.ExpectedOldIdentity;old.observedPID=&pid;old.observedTicks=&ticks
	old.input.commit=b.ExpectedOldIdentity.SourceCommit;old.input.binaryHash=b.ExpectedOldIdentity.ELFSHA256;old.input.binaryBytes=b.ExpectedOldIdentity.ELFBytes
	old.exit=labQuiescenceCloneExit(*f.Observation.Stop)
	return labQuiescenceIssueForModel(t,old,b,f)
}
func lifecycleRecoveryModelQuiesced(t *testing.T) (*lifecycleRecoveryStore,*lifecycleModelDisk,*lifecycleRecoveryOwnerToken,time.Time) {
	t.Helper();s,d,o,_,b,now:=lifecycleRecoveryModelArmed(t);fact:=lifecycleRecoveryModelFact(b,now)
	if !labQuiescenceFactValid(fact,b,now) {t.Fatal("MODEL fact structure")}
	if s.recordRecoveryQuiescence(o,lifecycleRecoveryIssuedModel(t,b,fact),now)!=nil {t.Fatal("MODEL actual once consumption/durable fact")}
	return s,d,o,now
}

func TestLifecycleRecoveryApprovalRequiresIndependentMaterialAndExactPlan(t *testing.T) {
	s,d,o,p,now:=lifecycleRecoveryModelPlanned(t);before:=d.writes
	if _,err:=newLifecycleRecoveryApproval(&p,p.descriptor().DeclaredInitiatorRef,now,now.Add(time.Minute));err==nil {t.Fatal("MODEL self approval")}
	a,err:=newLifecycleRecoveryApproval(&p,"MODEL_approver",now,now.Add(time.Minute));if err!=nil {t.Fatal("MODEL approval")}
	a.RecoveryPlanSHA256=strings.Repeat("e",64);a.ApprovalSHA256,_=lifecycleRecoveryApprovalHash(a)
	if s.recordRecoveryApproval(o,a,now)==nil||d.writes!=before {t.Fatal("MODEL approval bound wrong plan")}
	a,_=newLifecycleRecoveryApproval(&p,"MODEL_approver",now,now.Add(time.Minute))
	if s.recordRecoveryApproval(o,a,now)!=nil||s.recordRecoveryApproval(o,a,now)==nil {t.Fatal("MODEL approval not one way")}
}
func TestLifecycleRecoveryStopArmingBindsOldEpochAndCannotRepeat(t *testing.T) {
	s,d,o,_,i,now:=lifecycleRecoveryStopModel(t);before:=d.writes
	bad:=i;bad.StartTicks++
	if _,err:=s.armRecoveryStop(o,bad,now);err==nil||d.writes!=before {t.Fatal("MODEL other epoch armed")}
	b,err:=s.armRecoveryStop(o,i,now)
	if err!=nil||b.ExpectedOldIdentity!=i||b.StopIntentSHA256!=s.core.record.core.Recovery.StopIntent.IntentSHA256||s.core.record.core.Current.Active.Phase!="UNKNOWN" {t.Fatal("MODEL arm binding")}
	if _,err:=s.armRecoveryStop(o,i,now);err==nil||d.writes!=before+1 {t.Fatal("MODEL stop intent repeated")}
}
func TestLifecycleRecoveryActualQuiescenceMethodRejectsNilForgedAndJSONFact(t *testing.T) {
	s,d,o,_,b,now:=lifecycleRecoveryModelArmed(t);before:=d.writes
	fact:=lifecycleRecoveryModelFact(b,now)
	for _,q:=range []*labQuiescedEpoch{nil,{}, {core:&labQuiescedEpochCore{fact:fact}}} {
		if s.recordRecoveryQuiescence(o,q,now)==nil||d.writes!=before||s.core.quiescenceSHA!="" {t.Fatal("MODEL forged fact granted provenance")}
	}
	if _,err:=s.armRecoveryStart(o,now);err==nil {t.Fatal("MODEL JSON fact enabled start")}
}
func TestLifecycleRecoveryQuiescenceHistorySurvivesExpiryWithoutGrantingStart(t *testing.T) {
	s,d,o,now:=lifecycleRecoveryModelQuiesced(t);original:=s.core.record.core.Recovery.Quiescence
	late:=now.Add(2*time.Minute)
	// Durable history validates its reception time, not the later wall clock.
	next,_:=s.core.copyRecord();next.core.Recovery.Phase="RECOVERY_UNKNOWN";next.core.Recovery.Failure=&lifecycleRecoveryFailure{"AUTHORITY_CHANGED",late};next.core.Recovery.UpdatedAt=late
	if s.core.commit(next,late)!=nil {t.Fatal("MODEL expired fact discarded")}
	if _,err:=s.armRecoveryStart(o,late);err==nil {t.Fatal("MODEL expired start")}
	reopened,err:=openLifecycleRecoveryStore(d,late);if err!=nil||!reflect.DeepEqual(reopened.core.record.core.Recovery.Quiescence,original)||reopened.core.permit!=nil||reopened.core.quiescenceSHA!="" {t.Fatal("MODEL expired fact or provenance restored")}
	// Unlike the historical-codec check above, these use actual record-only
	// issued-registry consumption after the TTL and after concurrent revoke.
	for _,revoked:=range []bool{false,true} {
		fresh,_,lease,_,binding,at:=lifecycleRecoveryModelArmed(t);fact:=lifecycleRecoveryModelFact(binding,at)
		q:=lifecycleRecoveryIssuedModel(t,binding,fact)
		if revoked&&fresh.revokeRecovery(lease,"MODEL_revoker","EXPLICIT_REVOKED",at)!=nil {t.Fatal("MODEL concurrent revoke")}
		var firstFailure *lifecycleRecoveryFailure
		if fresh.core.record.core.Recovery.Failure!=nil {copy:=*fresh.core.record.core.Recovery.Failure;firstFailure=&copy}
		if fresh.recordRecoveryQuiescence(lease,q,at.Add(2*time.Minute))!=nil {t.Fatal("MODEL late issued fact not retained")}
		actual:=fresh.core.record.core.Recovery
		if actual.Phase!="RECOVERY_UNKNOWN"||!reflect.DeepEqual(actual.Quiescence,&fact)||fresh.core.quiescenceSHA!=""||firstFailure!=nil&&!reflect.DeepEqual(firstFailure,actual.Failure) {t.Fatal("MODEL late fact changed barrier or original reason")}
		if _,err:=q.consumeQuiescenceForRecord(binding,at.Add(2*time.Minute));err==nil {t.Fatal("MODEL record consumption replay")}
		if _,err:=fresh.armRecoveryStart(lease,at.Add(2*time.Minute));err==nil {t.Fatal("MODEL late fact granted start")}
		strict:=lifecycleRecoveryIssuedModel(t,binding,fact)
		if _,err:=strict.consumeQuiescence(binding,at.Add(2*time.Minute));err==nil {t.Fatal("MODEL strict fresh consume weakened")}
	}
}
func TestLifecycleRecoveryReopenArmedNeverRestoresPermitOrChangesOriginalResult(t *testing.T) {
	for _,stage:=range []string{"stop","start"} {
		s,d,o,now:=lifecycleRecoveryModelQuiesced(t)
		if stage=="start" {if _,err:=s.armRecoveryStart(o,now);err!=nil {t.Fatal("MODEL start arm")}}
		original:=s.core.record.core.Current.Active;before:=d.writes
		beforeRaw:=bytes.Clone(d.raw)
		for _,badNow:=range []time.Time{now.Add(-time.Nanosecond),now.In(time.FixedZone("noncanonical",0)),{}} {
			if _,err:=openLifecycleRecoveryStore(d,badNow);err==nil||d.writes!=before||!bytes.Equal(beforeRaw,d.raw) {t.Fatal("MODEL invalid reopen clock wrote bytes")}
		}
		reopenAt:=now.Add(time.Millisecond)
		fresh,err:=openLifecycleRecoveryStore(d,reopenAt)
		if err!=nil||fresh.core.record.core.Recovery.Phase!="RECOVERY_UNKNOWN"||fresh.core.live!=nil||fresh.core.permit!=nil||fresh.core.quiescenceSHA!=""||d.writes!=before+1||!reflect.DeepEqual(original,fresh.core.record.core.Current.Active) {t.Fatal("MODEL unsafe reopen")}
		if !fresh.core.record.core.LastTrustedAt.Equal(reopenAt)||!fresh.core.record.core.Recovery.UpdatedAt.Equal(reopenAt)||!fresh.core.record.core.Recovery.Failure.At.Equal(reopenAt) {t.Fatal("MODEL reopen observation time invented")}
		if _,err:=fresh.acquireRecoveryOwner(now.Add(2*time.Minute),now.Add(3*time.Minute));err==nil {t.Fatal("MODEL UNKNOWN lease takeover")}
	}
}
func TestLifecycleRecoveryStartPermitCopiesConsumeExactlyOnce(t *testing.T) {
	s,_,o,now:=lifecycleRecoveryModelQuiesced(t);p,err:=s.armRecoveryStart(o,now);if err!=nil {t.Fatal("MODEL permit")};copy:=*p
	var wg sync.WaitGroup;var mu sync.Mutex;success:=0
	for _,v:=range []*labRecoveryStartPermit{p,&copy} {wg.Add(1);go func(v *labRecoveryStartPermit){defer wg.Done();f,err:=v.consumeRecoveryStart(now);if err==nil {mu.Lock();success++;mu.Unlock();if f.Revision==0||f.RecordSHA256=="" {t.Error("MODEL incomplete permit fact")}}}(v)};wg.Wait()
	if success!=1 {t.Fatal("MODEL permit aliases replayed")}
	if _,err:=s.armRecoveryStart(o,now);err==nil {t.Fatal("MODEL start rearmed")}
}
func TestLifecycleRecoveryStartPermitBadAttemptSpendsAndRevocationBlocks(t *testing.T) {
	for _,kind:=range []string{"expired","revoked","forged"} {
		s,_,o,now:=lifecycleRecoveryModelQuiesced(t);p,err:=s.armRecoveryStart(o,now);if err!=nil {t.Fatal("MODEL permit")}
		switch kind {
		case "expired":if _,err:=p.consumeRecoveryStart(now.Add(31*time.Second));err==nil {t.Fatal("MODEL stale permit")}
		case "revoked":if s.revokeRecovery(o,"MODEL_revoker","EXPLICIT_REVOKED",now)!=nil {t.Fatal("MODEL revoke")};if _,err:=p.consumeRecoveryStart(now);err==nil {t.Fatal("MODEL revoked permit")}
		case "forged":f:=*p.core;forged:=&labRecoveryStartPermit{core:&f};if _,err:=forged.consumeRecoveryStart(now);err==nil {t.Fatal("MODEL copied fields minted permit")};if _,err:=p.consumeRecoveryStart(now);err!=nil {t.Fatal("MODEL foreign pointer spent real entry")};continue
		}
		if _,err:=p.consumeRecoveryStart(now);err==nil {t.Fatal("MODEL failed consume revived")}
	}
}
func TestLifecycleRecoveryFailureRetainsPartialFactsAndUnknownBlocksReplay(t *testing.T) {
	s,d,o,p,_,now:=lifecycleRecoveryModelArmed(t)
	failedClass:="FAILED"
	observation:=labQuiescenceObservation{Schema:labQuiescenceObservationSchema,Outcome:"STOP_UNCERTAIN",FailureCode:"STOP_UNCERTAIN",StopInvoked:true,StopReturned:true,StopErrorClass:&failedClass,StartedAt:&now,ReturnedAt:&now,Stop:&labKernelExit{WaitErrorClass:"NOT_WAITED"}}
	if s.recordRecoveryFailure(o,"QUIESCENCE_REJECTED",&observation,now)!=nil {t.Fatal("MODEL partial fact lost")}
	before:=d.writes;a:=s.core.record.core.Recovery
	if a.Phase!="RECOVERY_UNKNOWN"||len(a.FailedQuiescence)!=1||a.FailedQuiescence[0].Stop.GroupAbsent!=nil||s.core.record.core.Current.Active.Result.Reload.State!=mihomo.ReloadUnknown {t.Fatal("MODEL invented partial fields")}
	if s.beginRecovery(o,&p,s.core.record.core.Revision,s.core.record.core.RecordSHA256,now)==nil {t.Fatal("MODEL unknown recovery replayed")}
	if _,err:=s.acquireRecoveryOwner(now.Add(2*time.Minute),now.Add(3*time.Minute));err==nil||d.writes!=before {t.Fatal("MODEL TTL unblocked uncertainty")}
	// A revocation racing the real stop must not discard its later partial
	// observation or rewrite the first reason. It still grants no new action.
	s,_,o,_,_,now=lifecycleRecoveryModelArmed(t)
	if s.revokeRecovery(o,"MODEL_revoker","EXPLICIT_REVOKED",now)!=nil {t.Fatal("MODEL revoke during stop")}
	first:=*s.core.record.core.Recovery.Failure
	if s.recordRecoveryFailure(o,"QUIESCENCE_REJECTED",&observation,now)!=nil||!reflect.DeepEqual(first,*s.core.record.core.Recovery.Failure)||len(s.core.record.core.Recovery.FailedQuiescence)!=1 {t.Fatal("MODEL late observation erased or first reason overwritten")}
	// Structural MODEL only: full late q facts likewise preserve the barrier.
	lateFact:=lifecycleRecoveryModelFact(*s.core.record.core.Recovery.StopBinding,now)
	next,_:=s.core.copyRecord();next.core.Recovery.Quiescence=&lateFact
	if s.core.commit(next,now)!=nil||s.core.record.core.Recovery.Phase!="RECOVERY_UNKNOWN" {t.Fatal("MODEL late settled fact erased")}
	if _,err:=s.armRecoveryStart(o,now);err==nil {t.Fatal("MODEL late settled fact cleared revocation")}
}
func TestLifecycleRecoveryRevokedHistoryPersistsAcrossNextPlanAndNewOwner(t *testing.T) {
	s,_,o,p,now:=lifecycleRecoveryModelPlanned(t)
	if s.revokeRecovery(o,"MODEL_revoker","EXPLICIT_REVOKED",now)!=nil {t.Fatal("MODEL revoke")}
	original,err:=lifecycleV3Source(s.core.record.core);if err!=nil {t.Fatal("MODEL source")}
	newPlan,err:=newLabRecoveryPlan(original,"labrec_"+strings.Repeat("2",32),p.descriptor().DeclaredInitiatorRef,p.descriptor().TargetArtifact,now,now.Add(time.Minute));if err!=nil {t.Fatal("MODEL new plan")}
	if s.beginRecovery(o,&newPlan,s.core.record.core.Revision,s.core.record.core.RecordSHA256,now)!=nil {t.Fatal("MODEL independent next plan")}
	if len(s.core.record.core.RecoveryHistory)!=1||s.core.record.core.RecoveryHistory[0].Revocation==nil {t.Fatal("MODEL revoked operation record erased")}
	if s.beginRecovery(o,&p,s.core.record.core.Revision,s.core.record.core.RecordSHA256,now)==nil {t.Fatal("MODEL revoked ID reused")}
}
func TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop(t *testing.T) {
	s,d,o,_,i,now:=lifecycleRecoveryStopModel(t);before:=d.writes
	w:=*s.core.record.core;w.Revision=^uint64(0)-15
	if lifecycleRecoveryReserve(&w)==nil {t.Fatal("MODEL no remaining revisions reserved")}
	w=*s.core.record.core;w.SourceV2.ControlBytes=bytes.Repeat([]byte("x"),maxLifecycleControlBytes)
	if lifecycleRecoveryReserve(&w)==nil {t.Fatal("MODEL inline source capacity ignored")}
	// Poisoned stores cannot dispatch; quota evaluation itself writes nothing.
	if d.writes!=before||s.core.record.core.Recovery.StopIntent!=nil {t.Fatal("MODEL reserve performed physical action")}
	if _,err:=s.armRecoveryStop(o,i,now);err!=nil {t.Fatal("MODEL bounded normal reserve")}
	// Fill the logical archive with individually valid independent plans. No
	// duplicated ID or malformed entry may mask the capacity rejection.
	full,disk,first,at:=lifecycleRecoveryModelStore(t);lease:=lifecycleRecoveryModelOwner(t,full,at)
	original,err:=lifecycleV3Source(full.core.record.core);if err!=nil {t.Fatal("MODEL source")}
	for n:=0;n<maxLifecycleHistory;n++ {
		p,err:=newLabRecoveryPlan(original,fmt.Sprintf("labrec_%032x",n+2),first.descriptor().DeclaredInitiatorRef,first.descriptor().TargetArtifact,at,at.Add(time.Minute))
		if err!=nil||full.beginRecovery(lease,&p,full.core.record.core.Revision,full.core.record.core.RecordSHA256,at)!=nil||full.revokeRecovery(lease,"MODEL_revoker","EXPLICIT_REVOKED",at)!=nil {t.Fatal("MODEL valid archive fill")}
	}
	before=disk.writes;bytesBefore:=bytes.Clone(disk.raw)
	last,err:=newLabRecoveryPlan(original,"labrec_"+strings.Repeat("f",32),first.descriptor().DeclaredInitiatorRef,first.descriptor().TargetArtifact,at,at.Add(time.Minute))
	if err!=nil||full.beginRecovery(lease,&last,full.core.record.core.Revision,full.core.record.core.RecordSHA256,at)==nil||disk.writes!=before||!bytes.Equal(bytesBefore,disk.raw)||len(full.core.record.core.RecoveryHistory)!=maxLifecycleHistory {t.Fatal("MODEL full history silently cleared or accepted")}
}
func TestLifecycleRecoveryForbidsHeadFactoryAndUnknownPhaseEscape(t *testing.T) {
	s,d,_,_,_,now:=lifecycleRecoveryModelArmed(t);before:=d.writes
	for _,phase:=range []string{"COMPLETED","APPROVED","PLANNED","NEW_EPOCH_STARTED"} {
		next,_:=s.core.copyRecord();next.core.Recovery.Phase=phase
		if s.core.commit(next,now)==nil {t.Fatal("MODEL missing physical capability advanced recovery")}
	}
	next,_:=s.core.copyRecord();next.core.Current.Head.Generation++
	if s.core.commit(next,now)==nil||d.writes!=before {t.Fatal("MODEL DTO head factory")}
}
func TestLifecycleRecoveryNilAndFormattedCapabilityValuesRemainOpaque(t *testing.T) {
	s,_,o,now:=lifecycleRecoveryModelQuiesced(t);p,err:=s.armRecoveryStart(o,now);if err!=nil {t.Fatal("MODEL permit")}
	needles:=[]string{o.core.nonce,s.core.record.core.SourceV2.ControlSHA256,p.core.fact.StartIntentSHA256}
	for _,v:=range []any{*s,s,*o,o,*p,p,lifecycleRecoveryStore{},lifecycleRecoveryOwnerToken{},labRecoveryStartPermit{},(*labRecoveryStartPermit)(nil)} {
		for _,format:=range []string{"%v","%+v","%#v","%d","%x","%p"} {raw:=fmt.Sprintf(format,v);for _,n:=range needles {if strings.Contains(raw,n) {t.Fatal("MODEL private capability debug")}}}
		raw,err:=json.Marshal(v);if err!=nil {t.Fatal("MODEL capability JSON")};for _,n:=range needles {if bytes.Contains(raw,[]byte(n)) {t.Fatal("MODEL private capability JSON")}}
	}
	var nilStore *lifecycleRecoveryStore;var nilPermit *labRecoveryStartPermit
	if nilStore.recordRecoveryFailure(nil,"QUIESCENCE_REJECTED",nil,now)==nil {t.Fatal("MODEL nil store")}
	if _,err:=nilPermit.consumeRecoveryStart(now);err==nil {t.Fatal("MODEL nil permit")}
	if _,err:=(&labRecoveryStartPermit{}).consumeRecoveryStart(now);err==nil {t.Fatal("MODEL zero permit")}
	if (&lifecycleRecoveryStore{core:&lifecycleRecoveryStoreCore{}}).close()==nil {t.Fatal("MODEL empty store core")}
	if json.Unmarshal([]byte(`{}`),p)==nil||p.core!=nil {t.Fatal("MODEL JSON restores permit")}
}
