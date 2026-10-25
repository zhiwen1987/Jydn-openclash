package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

type lifecycleRecoveryStore struct{ core *lifecycleRecoveryStoreCore }
type lifecycleRecoveryStoreCore struct {
	mu sync.Mutex
	disk lifecycleDisk
	record lifecycleV3Record
	raw []byte
	live *lifecycleRecoveryOwnerCore
	quiescenceSHA string
	permit *labRecoveryStartCore
	poisoned,closed bool
}
type lifecycleRecoveryOwnerToken struct{ core *lifecycleRecoveryOwnerCore }
type lifecycleRecoveryOwnerCore struct { store *lifecycleRecoveryStoreCore; nonce string; fence uint64 }

func (lifecycleRecoveryStore) String() string { return lifecycleRecoveryDebug }
func (lifecycleRecoveryStore) GoString() string { return lifecycleRecoveryDebug }
func (lifecycleRecoveryStore) Format(s fmt.State,_ rune) { _,_=io.WriteString(s,lifecycleRecoveryDebug) }
func (lifecycleRecoveryStore) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"PRIVATE_RECOVERY_STORE_NOT_AUTHORIZATION"}`),nil }
func (*lifecycleRecoveryStore) UnmarshalJSON([]byte) error { return errLifecycleUnsafe }
func (lifecycleRecoveryOwnerToken) String() string { return lifecycleRecoveryDebug }
func (lifecycleRecoveryOwnerToken) GoString() string { return lifecycleRecoveryDebug }
func (lifecycleRecoveryOwnerToken) Format(s fmt.State,_ rune) { _,_=io.WriteString(s,lifecycleRecoveryDebug) }
func (lifecycleRecoveryOwnerToken) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"IN_MEMORY_RECOVERY_OWNER_NOT_AUTHORIZATION"}`),nil }
func (t *lifecycleRecoveryOwnerToken) UnmarshalJSON([]byte) error { if t!=nil {t.core=nil};return errLifecycleUnsafe }

// A structural builder, not a migration permission or an owned-process proof.
// Only the future authenticated RecoveryPrepare coordinator may select it.
func buildLifecycleV3Evolution(originalRaw []byte,p *labRecoveryPlan,now time.Time) (lifecycleV3Record,error) {
	original,err:=decodeLifecycleRecord(originalRaw)
	if err!=nil||p==nil||p.validAt(now)!=nil||original.wire.Schema!=lifecycleSchemaV2||original.wire.Revision==^uint64(0) { return lifecycleV3Record{},errLifecycleUnsafe }
	if _,err:=labRecoveryPlanFromDescriptor(p.descriptor(),original);err!=nil { return lifecycleV3Record{},errLifecycleUnsafe }
	w:=&lifecycleV3Wire{Schema:lifecycleSchemaV3,Boundary:lifecycleBoundary,Revision:original.wire.Revision+1,LastTrustedAt:now,
		Provisioning:original.wire.V2.Provisioning,SourceV2:lifecycleLegacySnapshot{lifecycleSchemaV2,labConfigHash(originalRaw),original.wire.RecordSHA256,original.wire.Revision,bytes.Clone(originalRaw)},
		Current:lifecycleLegacyLedger(original,originalRaw),RetiredEpochs:[]lifecycleRetiredEpoch{},RecoveryHistory:[]lifecycleRecoveryTxn{}}
	w.RecordSHA256,err=lifecycleV3RecordHash(*w)
	r:=lifecycleV3Record{core:w};if err!=nil {return lifecycleV3Record{},errLifecycleUnsafe}
	raw,err:=encodeLifecycleV3Record(r);if err!=nil {return lifecycleV3Record{},err};return decodeLifecycleV3Record(raw)
}

// The old mutex and disk remain exclusive throughout handoff. The coordinator
// must already have checked current critical-admin authority and the actual
// owned epoch. Nothing here accepts an HTTP record, auth boolean or disk path.
func evolveLifecycleV2ForRecovery(old *lifecycleStore,p *labRecoveryPlan,now time.Time) (*lifecycleRecoveryStore,error) {
	if old==nil||old.lifecycleStoreCore==nil||old.mu==nil {return nil,errLifecycleUnsafe}
	old.mu.Lock();defer old.mu.Unlock()
	if err:=old.verify();err!=nil {return nil,err}
	if err:=old.trustedNow(now);err!=nil {return nil,err}
	r,err:=buildLifecycleV3Evolution(old.raw,p,now);if err!=nil {return nil,err}
	raw,err:=encodeLifecycleV3Record(r);if err!=nil {return nil,err}
	x:=&lifecycleRecoveryStoreCore{disk:old.disk,record:r,raw:bytes.Clone(raw)}
	s:=&lifecycleRecoveryStore{core:x}
	if err:=x.publish(raw);err!=nil {
		if x.poisoned { old.poisoned=true;old.live=nil }
		return nil,err
	}
	// Do not close the disk: the new object is now its sole close owner. The
	// original store/session/token cannot perform another read, write or close.
	old.live=nil;old.closed=true;old.disk=nil
	return s,nil
}

func lifecycleRecoveryDiskPresent(d lifecycleDisk) bool {
	if d==nil {return false};v:=reflect.ValueOf(d)
	switch v.Kind() {case reflect.Pointer,reflect.Map,reflect.Slice,reflect.Func,reflect.Chan,reflect.Interface:return !v.IsNil()};return true
}
func openLifecycleRecoveryStore(d lifecycleDisk,now time.Time) (*lifecycleRecoveryStore,error) {
	if !lifecycleRecoveryDiskPresent(d)||!lifecycleTime(now) {return nil,errLifecycleUnsafe}
	if err:=d.verify();err!=nil {return nil,err}
	raw,exists,err:=d.readControl();if err!=nil {return nil,err};if !exists {return nil,errLifecycleUnsafe}
	r,err:=decodeLifecycleV3Record(raw);if err!=nil {return nil,err};if now.Before(r.core.LastTrustedAt) {return nil,errLifecycleUnsafe}
	x:=&lifecycleRecoveryStoreCore{disk:d,record:r,raw:bytes.Clone(raw)};s:=&lifecycleRecoveryStore{core:x}
	// Reopening never restores an owner, consumed-q provenance or StartPermit.
	// Any armed physical action is uncertain; even a durable fact is not a new
	// permission to replay it. Preserve every original action/fact verbatim.
	if a:=r.core.Recovery;a!=nil&&a.Phase!="PLANNED"&&a.Phase!="APPROVED"&&a.Phase!="REVOKED_UNSTARTED"&&a.Phase!="COMPLETED"&&a.Phase!="RECOVERY_UNKNOWN" {
		next,err:=decodeLifecycleV3Record(raw);if err!=nil {return nil,err}
		next.core.Recovery.Phase="RECOVERY_UNKNOWN"
		if next.core.Recovery.Failure==nil {next.core.Recovery.Failure=&lifecycleRecoveryFailure{"PROCESS_REOPENED",now}}
		next.core.Recovery.UpdatedAt=now
		if err:=x.commit(next,now);err!=nil {return nil,err}
	}
	return s,nil
}
func (x *lifecycleRecoveryStoreCore) trustedNow(now time.Time) error {
	if x==nil||x.record.core==nil||!lifecycleTime(now)||now.Before(x.record.core.LastTrustedAt) {
		if x!=nil {x.poisoned=true;x.live=nil;x.permit=nil;x.quiescenceSHA=""};return errLifecycleUnsafe
	};return nil
}
func (x *lifecycleRecoveryStoreCore) verify() error {
	if x==nil||x.closed||x.record.core==nil||!lifecycleRecoveryDiskPresent(x.disk) {return errLifecycleUnsafe}
	if x.poisoned {return errLifecyclePoisoned}
	if err:=x.disk.verify();err!=nil {x.poisoned=true;return err}
	raw,exists,err:=x.disk.readControl()
	if err!=nil||!exists||!bytes.Equal(raw,x.raw) {x.poisoned=true;return errLifecycleUnsafe}
	r,err:=decodeLifecycleV3Record(raw)
	if err!=nil||r.core.RecordSHA256!=x.record.core.RecordSHA256||r.core.Revision!=x.record.core.Revision {x.poisoned=true;return errLifecycleUnsafe};return nil
}
func (x *lifecycleRecoveryStoreCore) publish(raw []byte) error {
	state,err:=x.disk.replaceControl(raw)
	if state==lifecycleUnknown||(state!=lifecycleNotCommitted&&state!=lifecycleCommitted)||(state==lifecycleCommitted&&err!=nil) {x.poisoned=true;return errLifecycleCommitUnknown}
	if state!=lifecycleCommitted {
		if errors.Is(err,errLifecycleUnsafe) {x.poisoned=true}
		if err!=nil {return err};return errLifecycleUnsafe
	}
	actual,exists,err:=x.disk.readControl()
	if err!=nil||!exists||!bytes.Equal(actual,raw)||x.disk.verify()!=nil {x.poisoned=true;return errLifecycleCommitUnknown}
	r,err:=decodeLifecycleV3Record(actual);if err!=nil {x.poisoned=true;return errLifecycleCommitUnknown}
	x.record=r;x.raw=bytes.Clone(raw);return nil
}
func (x *lifecycleRecoveryStoreCore) commit(next lifecycleV3Record,now time.Time) error {
	if err:=x.verify();err!=nil {return err};if err:=x.trustedNow(now);err!=nil {return err}
	if next.core==nil||x.record.core.Revision==^uint64(0)||next.core.Revision!=x.record.core.Revision||next.core.RecordSHA256!=x.record.core.RecordSHA256||!lifecycleV3Transition(x.record.core,next.core) {return errLifecycleUnsafe}
	if next.core.LastRecoveryFence!=x.record.core.LastRecoveryFence {
		o:=x.record.core.RecoveryOwner;n:=next.core.RecoveryOwner
		if (o!=nil&&now.Before(o.ExpiresAt))||n==nil||!n.AcquiredAt.Equal(now)||!n.RenewedAt.Equal(now)||!n.ExpiresAt.After(now)||n.ExpiresAt.Sub(now)>5*time.Minute {return errLifecycleUnsafe}
	}
	next.core.Revision=x.record.core.Revision+1;next.core.LastTrustedAt=now
	next.core.RecordSHA256,_=lifecycleV3RecordHash(*next.core)
	raw,err:=encodeLifecycleV3Record(next);if err!=nil {return err};return x.publish(raw)
}
func (x *lifecycleRecoveryStoreCore) copyRecord() (lifecycleV3Record,error) {return decodeLifecycleV3Record(x.raw)}
func (x *lifecycleRecoveryStoreCore) token(t *lifecycleRecoveryOwnerToken,fresh bool,now time.Time) error {
	if err:=x.trustedNow(now);err!=nil {return err}
	o:=x.record.core.RecoveryOwner
	if t==nil||t.core==nil||x.live!=t.core||t.core.store!=x||o==nil||t.core.nonce!=o.OwnerNonce||t.core.fence!=o.Fence {return errLifecycleUnsafe}
	if fresh&&!now.Before(o.ExpiresAt) {return errLifecycleUnsafe};return nil
}
// This is only a process-local structural lease. No Principal, JSON owner or
// ApprovalMaterial becomes authentication or a stop/start capability here.
func (s *lifecycleRecoveryStore) acquireRecoveryOwner(now,expires time.Time) (*lifecycleRecoveryOwnerToken,error) {
	if s==nil||s.core==nil {return nil,errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if err:=x.verify();err!=nil {return nil,err};if err:=x.trustedNow(now);err!=nil {return nil,err}
	w:=x.record.core
	if !lifecycleTime(expires)||!expires.After(now)||expires.Sub(now)>5*time.Minute||w.LastRecoveryFence==^uint64(0)||(w.RecoveryOwner!=nil&&now.Before(w.RecoveryOwner.ExpiresAt)) {return nil,errLifecycleUnsafe}
	if a:=w.Recovery;a!=nil&&a.Phase!="REVOKED_UNSTARTED"&&a.Phase!="COMPLETED"&&a.Phase!="PLANNED"&&a.Phase!="APPROVED" {return nil,errLifecycleUnsafe}
	var nonce [32]byte;if _,err:=io.ReadFull(rand.Reader,nonce[:]);err!=nil {return nil,errLifecycleUnsafe}
	next,err:=x.copyRecord();if err!=nil {return nil,err}
	next.core.LastRecoveryFence++;next.core.RecoveryOwner=&lifecycleOwner{hex.EncodeToString(nonce[:]),next.core.LastRecoveryFence,now,now,expires}
	if err:=x.commit(next,now);err!=nil {return nil,err}
	t:=&lifecycleRecoveryOwnerToken{core:&lifecycleRecoveryOwnerCore{x,next.core.RecoveryOwner.OwnerNonce,next.core.LastRecoveryFence}};x.live=t.core
	return t,nil
}
func (s *lifecycleRecoveryStore) close() error {
	if s==nil||s.core==nil {return errLifecycleUnsafe};x:=s.core;x.mu.Lock();defer x.mu.Unlock()
	if x.closed {return nil};x.live=nil;x.permit=nil;x.quiescenceSHA=""
	if !lifecycleRecoveryDiskPresent(x.disk) {return errLifecycleUnsafe}
	if err:=x.disk.close();err!=nil {x.poisoned=true;return err};x.closed=true;return nil
}

func lifecycleV3Transition(a,b *lifecycleV3Wire) bool {
	if a==nil||b==nil||a.Schema!=b.Schema||a.Boundary!=b.Boundary||a.Provisioning!=b.Provisioning||!reflect.DeepEqual(a.SourceV2,b.SourceV2)||!reflect.DeepEqual(a.Current,b.Current)||!reflect.DeepEqual(a.RetiredEpochs,b.RetiredEpochs)||len(b.RecoveryHistory)<len(a.RecoveryHistory)||!reflect.DeepEqual(b.RecoveryHistory[:len(a.RecoveryHistory)],a.RecoveryHistory) {return false}
	// No head advancement/epoch factory in this initial, capability-incomplete
	// extension. A future source-owned collector transition is separately gated.
	if b.LastRecoveryFence==a.LastRecoveryFence {
		if !reflect.DeepEqual(a.RecoveryOwner,b.RecoveryOwner) {return false}
	} else if a.LastRecoveryFence==^uint64(0)||b.LastRecoveryFence!=a.LastRecoveryFence+1||b.RecoveryOwner==nil {return false}
	if a.Recovery==nil {return len(a.RecoveryHistory)==len(b.RecoveryHistory)&&(b.Recovery==nil||b.Recovery.Phase=="PLANNED")}
	if b.Recovery==nil {return false}
	if a.Recovery.Plan.PlanSHA256!=b.Recovery.Plan.PlanSHA256 {
		return (a.Recovery.Phase=="REVOKED_UNSTARTED"||a.Recovery.Phase=="COMPLETED")&&len(b.RecoveryHistory)==len(a.RecoveryHistory)&&b.Recovery.Phase=="PLANNED"
	}
	x,y:=a.Recovery,b.Recovery
	if !reflect.DeepEqual(x.Plan,y.Plan)||!lifecycleRecoveryPhaseTransition(x.Phase,y.Phase)||(x.Approval!=nil&&!reflect.DeepEqual(x.Approval,y.Approval))||(x.Revocation!=nil&&!reflect.DeepEqual(x.Revocation,y.Revocation))||(x.StopIntent!=nil&&!reflect.DeepEqual(x.StopIntent,y.StopIntent))||(x.StopBinding!=nil&&!reflect.DeepEqual(x.StopBinding,y.StopBinding))||(x.Quiescence!=nil&&!reflect.DeepEqual(x.Quiescence,y.Quiescence))||(x.StartIntent!=nil&&!reflect.DeepEqual(x.StartIntent,y.StartIntent))||(x.Failure!=nil&&!reflect.DeepEqual(x.Failure,y.Failure))||(x.Completion!=nil&&!reflect.DeepEqual(x.Completion,y.Completion))||len(y.FailedQuiescence)<len(x.FailedQuiescence)||!reflect.DeepEqual(y.FailedQuiescence[:len(x.FailedQuiescence)],x.FailedQuiescence)||y.UpdatedAt.Before(x.UpdatedAt) {return false}
	if y.Phase=="REVOKED_UNSTARTED"&&x.Phase!="REVOKED_UNSTARTED" {return len(b.RecoveryHistory)==len(a.RecoveryHistory)+1&&reflect.DeepEqual(b.RecoveryHistory[len(a.RecoveryHistory)],*y)}
	return len(b.RecoveryHistory)==len(a.RecoveryHistory)
}
