package mihomodeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

func lifecycleRecoveryApprovalHash(a lifecycleRecoveryApproval) (string,error) {
	return lifecycleHash(struct {
		Schema string `json:"schema"`; RecoveryPlanSHA256 string `json:"recoveryPlanSHA256"`; DeclaredApproverRef string `json:"declaredApproverRef"`
		IssuedAt time.Time `json:"issuedAt"`; ExpiresAt time.Time `json:"expiresAt"`
	}{a.Schema,a.RecoveryPlanSHA256,a.DeclaredApproverRef,a.IssuedAt,a.ExpiresAt})
}
// A structural material constructor, not an authentication/approval service.
func newLifecycleRecoveryApproval(p *labRecoveryPlan,approver string,now,expires time.Time) (lifecycleRecoveryApproval,error) {
	if p==nil||p.validAt(now)!=nil||!planReference.MatchString(approver)||approver==p.descriptor().DeclaredInitiatorRef||!lifecycleTime(expires)||!expires.After(now)||expires.After(p.descriptor().ExpiresAt) {return lifecycleRecoveryApproval{},errLifecycleUnsafe}
	a:=lifecycleRecoveryApproval{"chengwang.mihomo-structural-recovery-approval/v1",p.descriptor().PlanSHA256,approver,now,expires,""};a.ApprovalSHA256,_=lifecycleRecoveryApprovalHash(a);return a,nil
}
func lifecycleRecoveryActionHash(a lifecycleRecoveryActionIntent) (string,error) {
	return lifecycleHash(struct {
		Schema string `json:"schema"`; Action string `json:"action"`; RecoveryID string `json:"recoveryId"`; RecoveryPlanSHA256 string `json:"recoveryPlanSHA256"`
		OwnerFence uint64 `json:"ownerFence"`; ArmedAt time.Time `json:"armedAt"`
	}{a.Schema,a.Action,a.RecoveryID,a.RecoveryPlanSHA256,a.OwnerFence,a.ArmedAt})
}
func lifecycleRecoveryNewIntent(a *lifecycleRecoveryTxn,action string,fence uint64,now time.Time) lifecycleRecoveryActionIntent {
	i:=lifecycleRecoveryActionIntent{"chengwang.mihomo-recovery-action-intent/v1",action,a.Plan.RecoveryID,a.Plan.PlanSHA256,fence,now,""};i.IntentSHA256,_=lifecycleRecoveryActionHash(i);return i
}
func lifecycleRecoveryPhaseTransition(a,b string) bool {
	if a==b {return true}
	switch a {
	case "PLANNED":return b=="APPROVED"||b=="REVOKED_UNSTARTED"
	case "APPROVED":return b=="STOP_ARMED"||b=="REVOKED_UNSTARTED"
	case "STOP_ARMED":return b=="OLD_EPOCH_QUIESCED"||b=="RECOVERY_UNKNOWN"
	case "OLD_EPOCH_QUIESCED":return b=="START_ARMED"||b=="RECOVERY_UNKNOWN"
	case "START_ARMED","NEW_EPOCH_STARTED","NEW_EPOCH_VERIFIED":return b=="RECOVERY_UNKNOWN"
	default:return false
	}
}
func lifecycleRecoveryIntentValid(i *lifecycleRecoveryActionIntent,a lifecycleRecoveryTxn,action string,at time.Time) bool {
	if i==nil {return false};digest,err:=lifecycleRecoveryActionHash(*i)
	return err==nil&&i.Schema=="chengwang.mihomo-recovery-action-intent/v1"&&i.Action==action&&i.RecoveryID==a.Plan.RecoveryID&&i.RecoveryPlanSHA256==a.Plan.PlanSHA256&&i.OwnerFence>0&&lifecycleTime(i.ArmedAt)&&!i.ArmedAt.Before(a.Plan.CreatedAt)&&i.ArmedAt.Before(a.Plan.ExpiresAt)&&!i.ArmedAt.After(at)&&digest==i.IntentSHA256&&lifecycleNonzeroHash(digest)
}
func lifecycleRecoveryIdentityMatches(i labKernelIdentity,h lifecycleHead) bool {
	return labQuiescenceIdentityValid(i)&&i.PID==h.PID&&i.StartTicks==h.StartTicks&&i.NetNSInode==h.NetNSInode&&i.ELFSHA256==h.KernelSHA256&&i.ControllerPort==h.ControllerPort&&i.MixedPort==h.MixedPort
}
func lifecycleRecoveryFailedObservationValid(o labQuiescenceObservation,at time.Time) bool {
	if o.Schema!=labQuiescenceObservationSchema {return false}
	// Closed source-owned outcome/code vocabulary, never error text or URLs.
	allowed:=map[string]map[string]bool{
		"ENTRY_REJECTED":{"ENTRY_REJECTED":true,"CONTEXT_REJECTED":true,"BINDING_REJECTED":true,"CLOCK_REJECTED":true,"PLATFORM_UNSUPPORTED":true},
		"OWNED_REJECTED":{"OWNED_REJECTED":true,"ATTEMPT_SPENT":true},
		"STOP_UNCERTAIN":{"STOP_UNCERTAIN":true},
		"FAILED":{"CONTEXT_REJECTED":true,"CLOCK_REJECTED":true,"NAMESPACE_REJECTED":true,"CONTROLLER_NOT_REFUSED":true,"MIXED_NOT_REFUSED":true,"ISSUER_REJECTED":true,"FACT_REJECTED":true},
		"QUIESCED":{"NONE":true},
	}
	if !allowed[o.Outcome][o.FailureCode] {return false}
	if o.StopInvoked {
		if o.StartedAt==nil||o.ReturnedAt==nil {return false}
	} else if o.StartedAt!=nil||o.StopReturned||o.Stop!=nil||o.StopErrorClass!=nil {return false}
	if o.StopReturned&&(o.Stop==nil||o.StopErrorClass==nil) {return false}
	if o.StopErrorClass!=nil {
		if !o.StopReturned||(*o.StopErrorClass!="NONE"&&*o.StopErrorClass!="CAPTURE_LIMIT_ONLY"&&*o.StopErrorClass!="FAILED") {return false}
		if *o.StopErrorClass!="FAILED"&&!labQuiescenceStopClassValid(o) {return false}
	}
	if o.StartupIdentity!=nil&&!labQuiescenceIdentityValid(*o.StartupIdentity) {return false}
	if o.NamespaceInode!=nil&&(*o.NamespaceInode==0||*o.NamespaceInode>1<<63-1) {return false}
	if o.StartedAt!=nil&&(!lifecycleTime(*o.StartedAt)||o.StartedAt.After(at)) {return false}
	if o.ReturnedAt!=nil&&(!lifecycleTime(*o.ReturnedAt)||o.ReturnedAt.After(at)||(o.StartedAt!=nil&&o.ReturnedAt.Before(*o.StartedAt)&&o.FailureCode!="CLOCK_REJECTED")) {return false}
	for _,p:=range []*labQuiescenceProbe{o.ControllerProbe,o.MixedProbe} {
		if p!=nil&&(p.Port<1024||(p.Result!="CONNECTION_REFUSED"&&p.Result!="CONNECTION_ACCEPTED"&&p.Result!="CONTEXT_REJECTED"&&p.Result!="TIMEOUT"&&p.Result!="OTHER")) {return false}
	}
	if o.Stop!=nil {
		s:=o.Stop
		if s.WaitErrorClass!=""&&s.WaitErrorClass!="NONE"&&s.WaitErrorClass!="NOT_WAITED"&&s.WaitErrorClass!="EXIT_STATUS"&&s.WaitErrorClass!="WAIT_ERROR" {return false}
		for _,v:=range []labKernelStream{s.Stdout,s.Stderr} {if v.Bytes<0||v.Bytes>64<<10||v.TotalBytes<int64(v.Bytes)||(v.SHA256!=""&&!lifecycleNonzeroHash(v.SHA256))||(v.SHA256==""&&(v.Bytes!=0||v.TotalBytes!=0||v.Complete||v.Truncated)) {return false}}
		if s.ExitCode!=nil&&(*s.ExitCode<0||*s.ExitCode>255)||s.Signal!=nil&&(*s.Signal<1||*s.Signal>64) {return false}
	}
	return true
}
func validateLifecycleRecoveryTxn(a lifecycleRecoveryTxn,original lifecycleRecord,at time.Time,revision uint64) error {
	if _,err:=labRecoveryPlanFromDescriptor(a.Plan,original);err!=nil {return errLifecycleUnsafe}
	if !lifecycleTime(a.UpdatedAt)||a.UpdatedAt.Before(a.Plan.CreatedAt)||a.UpdatedAt.After(at)||a.FailedQuiescence==nil||len(a.FailedQuiescence)>1 {return errLifecycleUnsafe}
	if p:=a.Approval;p!=nil {
		digest,_:=lifecycleRecoveryApprovalHash(*p)
		if p.Schema!="chengwang.mihomo-structural-recovery-approval/v1"||p.RecoveryPlanSHA256!=a.Plan.PlanSHA256||!planReference.MatchString(p.DeclaredApproverRef)||p.DeclaredApproverRef==a.Plan.DeclaredInitiatorRef||!lifecycleTime(p.IssuedAt)||!lifecycleTime(p.ExpiresAt)||p.IssuedAt.Before(a.Plan.CreatedAt)||p.IssuedAt.After(a.UpdatedAt)||!p.ExpiresAt.After(p.IssuedAt)||p.ExpiresAt.After(a.Plan.ExpiresAt)||digest!=p.ApprovalSHA256 {return errLifecycleUnsafe}
	}
	if v:=a.Revocation;v!=nil {
		if v.Revision==0||v.Revision>revision||!lifecycleTime(v.At)||v.At.Before(a.Plan.CreatedAt)||v.At.After(a.UpdatedAt)||!planReference.MatchString(v.ActorRef)||(v.Reason!="EXPLICIT_REVOKED"&&v.Reason!="AUTHORITY_CHANGED"&&v.Reason!="EXPIRED") {return errLifecycleUnsafe}
	}
	if a.StopIntent!=nil {
		b:=a.StopBinding
		if a.Approval==nil||!lifecycleRecoveryIntentValid(a.StopIntent,a,"STOP",a.UpdatedAt)||a.StopIntent.ArmedAt.Before(a.Approval.IssuedAt)||!a.StopIntent.ArmedAt.Before(a.Approval.ExpiresAt)||b==nil||
			b.RecoveryID!=a.Plan.RecoveryID||b.RecoveryPlanSHA256!=a.Plan.PlanSHA256||b.StopIntentSHA256!=a.StopIntent.IntentSHA256||b.OldEpochSHA256!=a.Plan.OldEpochSHA256||!b.ArmedAt.Equal(a.StopIntent.ArmedAt)||!b.ExpiresAt.Equal(a.Plan.ExpiresAt)||!lifecycleRecoveryIdentityMatches(b.ExpectedOldIdentity,*original.wire.Head) {return errLifecycleUnsafe}
	} else if a.StopBinding!=nil||a.Quiescence!=nil||a.StartIntent!=nil||a.Completion!=nil||len(a.FailedQuiescence)!=0 {return errLifecycleUnsafe}
	if q:=a.Quiescence;q!=nil {
		if a.StopBinding==nil||!labQuiescenceFactValid(*q,*a.StopBinding,q.ObservedAt)||q.ObservedAt.After(a.UpdatedAt) {return errLifecycleUnsafe}
	}
	if a.StartIntent!=nil {
		if a.Quiescence==nil||!lifecycleRecoveryIntentValid(a.StartIntent,a,"START",a.UpdatedAt)||a.StartIntent.OwnerFence!=a.StopIntent.OwnerFence||a.StartIntent.ArmedAt.Before(a.Quiescence.ObservedAt)||!a.StartIntent.ArmedAt.Before(a.Approval.ExpiresAt) {return errLifecycleUnsafe}
	}
	for _,o:=range a.FailedQuiescence {if !lifecycleRecoveryFailedObservationValid(o,a.UpdatedAt) {return errLifecycleUnsafe}}
	if f:=a.Failure;f!=nil {
		if !lifecycleTime(f.At)||f.At.Before(a.Plan.CreatedAt)||f.At.After(a.UpdatedAt)||(f.Code!="PROCESS_REOPENED"&&f.Code!="QUIESCENCE_REJECTED"&&f.Code!="SERVICE_CONTEXT_CANCELLED"&&f.Code!="AUTHORITY_CHANGED"&&f.Code!="EXPLICIT_REVOKED"&&f.Code!="EXPIRED"&&f.Code!="START_UNCERTAIN") {return errLifecycleUnsafe}
	}
	switch a.Phase {
	case "PLANNED":if a.Approval!=nil||a.Revocation!=nil||a.StopIntent!=nil||a.Failure!=nil {return errLifecycleUnsafe}
	case "APPROVED":if a.Approval==nil||a.Revocation!=nil||a.StopIntent!=nil||a.Failure!=nil {return errLifecycleUnsafe}
	case "REVOKED_UNSTARTED":if a.Revocation==nil||a.StopIntent!=nil||a.Failure!=nil {return errLifecycleUnsafe}
	case "STOP_ARMED":if a.StopIntent==nil||a.Quiescence!=nil||a.StartIntent!=nil||a.Revocation!=nil||a.Failure!=nil {return errLifecycleUnsafe}
	case "OLD_EPOCH_QUIESCED":if a.Quiescence==nil||a.StartIntent!=nil||a.Revocation!=nil||a.Failure!=nil {return errLifecycleUnsafe}
	case "START_ARMED":if a.StartIntent==nil||a.Revocation!=nil||a.Failure!=nil||a.Completion!=nil {return errLifecycleUnsafe}
	case "RECOVERY_UNKNOWN":if a.StopIntent==nil||a.Failure==nil||a.Completion!=nil {return errLifecycleUnsafe}
	case "COMPLETED":
		c:=a.Completion
		if c==nil||a.StartIntent==nil||a.Failure!=nil||!lifecycleTime(c.CommittedAt)||c.CommittedAt.After(at)||!c.CommittedAt.Equal(a.UpdatedAt)||c.CommitRevision==0||c.CommitRevision>revision||!reflect.DeepEqual(c.PreviousHead,*original.wire.Head)||
			c.PreviousHead.Generation>=^uint64(0)-1||c.Head.Generation!=c.PreviousHead.Generation+1||c.Head.PreviousHeadSHA256==nil||*c.Head.PreviousHeadSHA256!=c.PreviousHead.HeadSHA256||c.Head.DeviceRef!=c.PreviousHead.DeviceRef||c.Head.Scope!=c.PreviousHead.Scope||c.Head.ControllerPort!=c.PreviousHead.ControllerPort||c.Head.MixedPort!=c.PreviousHead.MixedPort||
			!reflect.DeepEqual(c.Head.Artifact,a.Plan.TargetArtifact)||!lifecycleNonzeroHash(c.EvidenceSHA256)||c.Head.VerificationSHA256!=c.EvidenceSHA256||c.Head.VerifiedAt.Before(a.StartIntent.ArmedAt)||c.Head.VerifiedAt.After(c.CommittedAt) {return errLifecycleUnsafe}
		oldEpoch,_:=labRecoveryEpochSHA256(c.PreviousHead,a.Plan.Provisioning);newEpoch,err:=labRecoveryEpochSHA256(c.Head,a.Plan.Provisioning)
		if err!=nil||oldEpoch==newEpoch {return errLifecycleUnsafe}
	default:return errLifecycleUnsafe
	}
	return nil
}

func (s *lifecycleRecoveryStore) beginRecovery(t *lifecycleRecoveryOwnerToken,p *labRecoveryPlan,expectedRevision uint64,expectedRecord string,now time.Time) error {
	if s==nil||s.core==nil {return errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return err};if err:=x.token(t,true,now);err!=nil {return err}
	if p==nil||p.validAt(now)!=nil||x.record.core.Revision!=expectedRevision||x.record.core.RecordSHA256!=expectedRecord||len(x.record.core.RetiredEpochs)!=0 {return errLifecycleUnsafe}
	original,err:=lifecycleV3Source(x.record.core);if err!=nil {return err}
	if _,err:=labRecoveryPlanFromDescriptor(p.descriptor(),original);err!=nil {return errLifecycleUnsafe}
	for _,a:=range x.record.core.RecoveryHistory {if a.Plan.RecoveryID==p.descriptor().RecoveryID||a.Plan.PlanSHA256==p.descriptor().PlanSHA256 {return errLifecycleUnsafe}}
	if a:=x.record.core.Recovery;a!=nil&&a.Phase!="REVOKED_UNSTARTED"&&a.Phase!="COMPLETED" {return errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return err};next.core.Recovery=&lifecycleRecoveryTxn{Plan:p.descriptor(),Phase:"PLANNED",FailedQuiescence:[]labQuiescenceObservation{},UpdatedAt:now}
	return x.commit(next,now)
}
func (s *lifecycleRecoveryStore) recordRecoveryApproval(t *lifecycleRecoveryOwnerToken,a lifecycleRecoveryApproval,now time.Time) error {
	if s==nil||s.core==nil {return errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return err};if err:=x.token(t,true,now);err!=nil {return err}
	old:=x.record.core.Recovery
	if old==nil||old.Phase!="PLANNED"||old.Revocation!=nil||!a.IssuedAt.Equal(now)||!now.Before(a.ExpiresAt)||!now.Before(old.Plan.ExpiresAt) {return errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return err};next.core.Recovery.Approval=&a;next.core.Recovery.Phase="APPROVED";next.core.Recovery.UpdatedAt=now;return x.commit(next,now)
}
func (s *lifecycleRecoveryStore) revokeRecovery(t *lifecycleRecoveryOwnerToken,actor,reason string,now time.Time) error {
	if s==nil||s.core==nil {return errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return err};if err:=x.token(t,false,now);err!=nil {return err}
	a:=x.record.core.Recovery
	if a==nil||a.Revocation!=nil||a.Phase=="COMPLETED"||a.Phase=="REVOKED_UNSTARTED"||!planReference.MatchString(actor)||(reason!="EXPLICIT_REVOKED"&&reason!="AUTHORITY_CHANGED"&&reason!="EXPIRED")||x.record.core.Revision==^uint64(0) {return errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return err};b:=next.core.Recovery;b.Revocation=&lifecycleRevocation{x.record.core.Revision+1,now,reason,actor};b.UpdatedAt=now
	if b.StopIntent==nil {b.Phase="REVOKED_UNSTARTED";next.core.RecoveryHistory=append(next.core.RecoveryHistory,*b)} else {b.Phase="RECOVERY_UNKNOWN";if b.Failure==nil {b.Failure=&lifecycleRecoveryFailure{reason,now}}}
	if err:=x.commit(next,now);err!=nil {return err};x.permit=nil;x.quiescenceSHA="";return nil
}

// Reserve a complete *size* envelope before physical dispatch. It is never
// encoded as evidence: fields are worst-case structural placeholders only.
// This includes the full retired ledger, terminal recovery archive, selected
// head/anchor, one bounded failed observation, and all remaining revisions.
func lifecycleRecoveryReserve(w *lifecycleV3Wire) error {
	if w==nil||w.Recovery==nil||w.Current.Head.Generation>=^uint64(0)-1||w.Revision>^uint64(0)-16||len(w.RecoveryHistory)+len(w.Current.Completed)+len(w.Current.Terminated)+1>maxLifecycleHistory {return errLifecycleUnsafe}
	raw,err:=json.Marshal(w);if err!=nil {return errLifecycleUnsafe}
	var future lifecycleV3Wire;if json.Unmarshal(raw,&future)!=nil {return errLifecycleUnsafe}
	a:=future.Recovery;h:=future.Current.Head;h.Artifact=cloneArtifactDescriptor(a.Plan.TargetArtifact);h.Generation++;prior:=h.HeadSHA256;h.PreviousHeadSHA256=&prior
	h.PID=1<<31-1;h.StartTicks=1<<63-1;h.NetNSInode=1<<63-1;h.HeadSHA256=strings.Repeat("f",64);h.VerificationSHA256=strings.Repeat("f",64);h.VerifiedAt=a.Plan.ExpiresAt
	a.Phase="COMPLETED";a.Completion=&lifecycleRecoveryCompletion{future.Current.Head,h,strings.Repeat("f",64),^uint64(0),a.Plan.ExpiresAt}
	if a.StopIntent==nil {i:=lifecycleRecoveryNewIntent(a,"STOP",^uint64(0),a.Plan.ExpiresAt);a.StopIntent=&i}
	if a.StartIntent==nil {i:=lifecycleRecoveryNewIntent(a,"START",^uint64(0),a.Plan.ExpiresAt);a.StartIntent=&i}
	future.RecoveryHistory=append(future.RecoveryHistory,*a)
	future.RetiredEpochs=append(future.RetiredEpochs,lifecycleRetiredEpoch{future.Current,a.Plan.ExpiresAt,^uint64(0),a.Plan.RecoveryID,strings.Repeat("f",64)})
	id:=a.Plan.RecoveryID
	future.Current=lifecycleEpochLedger{Anchor:lifecycleEpochAnchor{"RECOVERED_EPOCH",h,&id,future.SourceV2.ControlSHA256},Head:h,Tombstones:[]lifecycleTombstone{},Completed:[]lifecycleCompletion{},Terminated:[]lifecycleTerminalArchive{},Observations:[]lifecycleObservationRecord{}}
	size,err:=json.Marshal(future)
	// Remaining bounded quiescence/failed-observation/owner/JSON metadata is
	// <=32KiB: it contains fixed enums/numbers and hashes, no raw stream/body.
	// The complete variable-size artifact and both epoch ledgers are above.
	if err!=nil||len(size)>maxLifecycleControlBytes-(32<<10) {return errLifecycleUnsafe};return nil
}
func (s *lifecycleRecoveryStore) armRecoveryStop(t *lifecycleRecoveryOwnerToken,expected labKernelIdentity,now time.Time) (labQuiescenceBinding,error) {
	var zero labQuiescenceBinding
	if s==nil||s.core==nil {return zero,errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return zero,err};if err:=x.token(t,true,now);err!=nil {return zero,err}
	a:=x.record.core.Recovery
	if a==nil||a.Phase!="APPROVED"||a.Revocation!=nil||a.Approval==nil||!now.Before(a.Approval.ExpiresAt)||!now.Before(a.Plan.ExpiresAt)||!lifecycleRecoveryIdentityMatches(expected,x.record.core.Current.Head) {return zero,errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return zero,err};b:=next.core.Recovery;i:=lifecycleRecoveryNewIntent(b,"STOP",x.record.core.LastRecoveryFence,now)
	b.StopIntent=&i;binding:=labQuiescenceBinding{b.Plan.RecoveryID,b.Plan.PlanSHA256,i.IntentSHA256,b.Plan.OldEpochSHA256,expected,now,b.Plan.ExpiresAt};b.StopBinding=&binding;b.Phase="STOP_ARMED";b.UpdatedAt=now
	if lifecycleRecoveryReserve(next.core)!=nil {return zero,errLifecycleUnsafe}
	if err:=x.commit(next,now);err!=nil {return zero,err};return binding,nil
}
func (s *lifecycleRecoveryStore) recordRecoveryQuiescence(t *lifecycleRecoveryOwnerToken,q *labQuiescedEpoch,now time.Time) error {
	if s==nil||s.core==nil {return errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return err};if err:=x.token(t,false,now);err!=nil {return err}
	a:=x.record.core.Recovery
	if a==nil||(a.Phase!="STOP_ARMED"&&a.Phase!="RECOVERY_UNKNOWN")||a.StopBinding==nil||a.Quiescence!=nil||q==nil {return errLifecycleUnsafe}
	// Consume actual one-use issued provenance, not a serialized Fact DTO.
	fact,err:=q.consumeQuiescenceForRecord(*a.StopBinding,now);if err!=nil {return errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return err};b:=next.core.Recovery;b.Quiescence=&fact;b.UpdatedAt=now
	fresh:=a.Phase=="STOP_ARMED"&&a.Revocation==nil&&a.Approval!=nil&&now.Before(a.Approval.ExpiresAt)&&now.Before(a.Plan.ExpiresAt)&&x.record.core.RecoveryOwner!=nil&&now.Before(x.record.core.RecoveryOwner.ExpiresAt)&&labQuiescenceFactValid(fact,*a.StopBinding,now)
	if fresh {b.Phase="OLD_EPOCH_QUIESCED"}else{b.Phase="RECOVERY_UNKNOWN";if b.Failure==nil{b.Failure=&lifecycleRecoveryFailure{"EXPIRED",now}}}
	// Record a happened physical fact even if its authorization later expired.
	if err:=x.commit(next,now);err!=nil {return err}
	if b.Phase=="OLD_EPOCH_QUIESCED" {x.quiescenceSHA=fact.QuiescenceSHA256}else{x.quiescenceSHA=""}
	return nil
}
func (s *lifecycleRecoveryStore) recordRecoveryFailure(t *lifecycleRecoveryOwnerToken,code string,observed *labQuiescenceObservation,now time.Time) error {
	if s==nil||s.core==nil {return errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return err};if err:=x.token(t,false,now);err!=nil {return err}
	a:=x.record.core.Recovery
	if a==nil||a.StopIntent==nil||a.Phase=="COMPLETED"||a.Phase=="REVOKED_UNSTARTED"||(a.Failure!=nil&&(observed==nil||len(a.FailedQuiescence)!=0)) {return errLifecycleUnsafe}
	if code!="QUIESCENCE_REJECTED"&&code!="SERVICE_CONTEXT_CANCELLED"&&code!="AUTHORITY_CHANGED"&&code!="EXPLICIT_REVOKED"&&code!="EXPIRED"&&code!="START_UNCERTAIN" {return errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return err};b:=next.core.Recovery
	if b.Failure==nil {b.Failure=&lifecycleRecoveryFailure{code,now}}
	b.Phase="RECOVERY_UNKNOWN";b.UpdatedAt=now
	if observed!=nil {b.FailedQuiescence=append(b.FailedQuiescence,labQuiescenceCloneObservation(*observed))}
	if err:=x.commit(next,now);err!=nil {return err};x.permit=nil;x.quiescenceSHA="";return nil
}

type labRecoveryStartPermit struct{core *labRecoveryStartCore}
type labRecoveryStartFact struct {
	RecoveryID string
	RecoveryPlanSHA256 string
	StartIntentSHA256 string
	Revision uint64
	RecordSHA256 string
	TargetArtifact ArtifactDescriptor
	QuiescenceSHA256 string
	ArmedAt,ExpiresAt time.Time
}
type labRecoveryStartCore struct {store *lifecycleRecoveryStoreCore;fact labRecoveryStartFact;fence uint64}
func (labRecoveryStartPermit) String() string {return lifecycleRecoveryDebug}
func (labRecoveryStartPermit) GoString() string {return lifecycleRecoveryDebug}
func (labRecoveryStartPermit) Format(s fmt.State,_ rune) {_,_=io.WriteString(s,lifecycleRecoveryDebug)}
func (labRecoveryStartPermit) MarshalJSON() ([]byte,error) {return []byte(`{"scope":"ONE_USE_START_STRUCTURE_NOT_AUTHORIZATION"}`),nil}
func (p *labRecoveryStartPermit) UnmarshalJSON([]byte) error {if p!=nil {p.core=nil};return errLifecycleUnsafe}
func (s *lifecycleRecoveryStore) armRecoveryStart(t *lifecycleRecoveryOwnerToken,now time.Time) (*labRecoveryStartPermit,error) {
	if s==nil||s.core==nil {return nil,errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return nil,err};if err:=x.token(t,true,now);err!=nil {return nil,err}
	a:=x.record.core.Recovery
	if a==nil||a.Phase!="OLD_EPOCH_QUIESCED"||a.Quiescence==nil||a.Revocation!=nil||a.Approval==nil||!now.Before(a.Approval.ExpiresAt)||!now.Before(a.Plan.ExpiresAt)||x.quiescenceSHA!=a.Quiescence.QuiescenceSHA256||x.quiescenceSHA==""||x.permit!=nil {return nil,errLifecycleUnsafe}
	if !labQuiescenceFactValid(*a.Quiescence,*a.StopBinding,now) {return nil,errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return nil,err};b:=next.core.Recovery;i:=lifecycleRecoveryNewIntent(b,"START",x.record.core.LastRecoveryFence,now);b.StartIntent=&i;b.Phase="START_ARMED";b.UpdatedAt=now
	if lifecycleRecoveryReserve(next.core)!=nil {return nil,errLifecycleUnsafe}
	if err:=x.commit(next,now);err!=nil {return nil,err}
	w:=x.record.core
	p:=&labRecoveryStartPermit{core:&labRecoveryStartCore{store:x,fence:w.LastRecoveryFence,fact:labRecoveryStartFact{b.Plan.RecoveryID,b.Plan.PlanSHA256,i.IntentSHA256,w.Revision,w.RecordSHA256,cloneArtifactDescriptor(b.Plan.TargetArtifact),b.Quiescence.QuiescenceSHA256,now,b.Plan.ExpiresAt}}}
	x.permit=p.core;x.quiescenceSHA="";return p,nil
}
func (p *labRecoveryStartPermit) consumeRecoveryStart(now time.Time) (labRecoveryStartFact,error) {
	var zero labRecoveryStartFact
	if p==nil||p.core==nil||p.core.store==nil {return zero,errLifecycleUnsafe};c:=p.core;x:=c.store;x.mu.Lock();defer x.mu.Unlock()
	if x.permit!=c {return zero,errLifecycleUnsafe};x.permit=nil // bad attempts spend the exact issued entry
	if err:=x.verify();err!=nil {return zero,err};if err:=x.trustedNow(now);err!=nil {return zero,err}
	w:=x.record.core;a:=w.Recovery
	if a==nil||a.Phase!="START_ARMED"||a.Revocation!=nil||a.Approval==nil||!now.Before(a.Approval.ExpiresAt)||now.Before(c.fact.ArmedAt)||!now.Before(c.fact.ExpiresAt)||now.Sub(c.fact.ArmedAt)>30*time.Second||w.Revision!=c.fact.Revision||w.RecordSHA256!=c.fact.RecordSHA256||w.LastRecoveryFence!=c.fence||x.live==nil||w.RecoveryOwner==nil||!now.Before(w.RecoveryOwner.ExpiresAt) {return zero,errLifecycleUnsafe}
	f:=c.fact;f.TargetArtifact=cloneArtifactDescriptor(f.TargetArtifact);return f,nil
}
