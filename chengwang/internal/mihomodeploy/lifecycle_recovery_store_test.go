package mihomodeploy

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func lifecycleRecoveryModelStore(t *testing.T) (*lifecycleRecoveryStore,*lifecycleModelDisk,labRecoveryPlan,time.Time) {
	t.Helper();r,p,_,now:=lifecycleV3Model(t);raw,err:=encodeLifecycleV3Record(r);if err!=nil {t.Fatal("MODEL encode")}
	d:=&lifecycleModelDisk{raw:raw,exists:true,state:lifecycleCommitted};s,err:=openLifecycleRecoveryStore(d,now);if err!=nil {t.Fatal("MODEL open")};return s,d,p,now
}
func lifecycleRecoveryModelOwner(t *testing.T,s *lifecycleRecoveryStore,now time.Time) *lifecycleRecoveryOwnerToken {
	t.Helper();o,err:=s.acquireRecoveryOwner(now,now.Add(time.Minute));if err!=nil {t.Fatal("MODEL owner")};return o
}
func lifecycleRecoveryModelPlanned(t *testing.T) (*lifecycleRecoveryStore,*lifecycleModelDisk,*lifecycleRecoveryOwnerToken,labRecoveryPlan,time.Time) {
	t.Helper();s,d,p,now:=lifecycleRecoveryModelStore(t);owner:=lifecycleRecoveryModelOwner(t,s,now)
	if err:=s.beginRecovery(owner,&p,s.core.record.core.Revision,s.core.record.core.RecordSHA256,now);err!=nil {t.Fatal("MODEL plan")};return s,d,owner,p,now
}

func TestLifecycleRecoveryEvolutionTransfersOneDiskAndInvalidatesOldOwner(t *testing.T) {
	p,original,now:=labRecoveryPlanModel(t);old,d:=lifecycleTestOpen(t,original)
	// MODEL a still-live legacy lease, not a restored authentication identity.
	old.live=&lifecycleOwnerToken{lifecycleOwnerCore:&lifecycleOwnerCore{old,original.wire.Owner.OwnerNonce,original.wire.Owner.Fence}};oldToken:=old.live
	s,err:=evolveLifecycleV2ForRecovery(old,&p,now)
	if err!=nil||s==nil||!old.closed||old.disk!=nil||old.live!=nil||d.closed||s.core.disk!=d {t.Fatal("MODEL nonexclusive handoff")}
	if oldToken!=nil&&old.live==oldToken {t.Fatal("MODEL old owner retained")}
	if old.verify()==nil||s.core.verify()!=nil {t.Fatal("MODEL wrong live store")}
	if s.close()!=nil||!d.closed {t.Fatal("MODEL sole disk close owner")}
}
func TestLifecycleRecoveryEvolutionWrongCASAndMarkerWriteNothing(t *testing.T) {
	for _,kind:=range []string{"record","marker","expired"} {
		p,original,now:=labRecoveryPlanModel(t);old,d:=lifecycleTestOpen(t,original);before:=bytes.Clone(d.raw)
		switch kind {case "record":p.core.descriptor.ExpectedRevision++
		case "marker":p.core.descriptor.Provisioning.MarkerSHA256=strings.Repeat("f",64)
		case "expired":now=p.descriptor().ExpiresAt}
		if _,err:=evolveLifecycleV2ForRecovery(old,&p,now);err==nil||d.writes!=0||!bytes.Equal(d.raw,before)||old.closed {t.Fatal("MODEL invalid evolution changed storage")}
	}
}
func TestLifecycleRecoveryEvolutionUncertainWritePoisonsLegacy(t *testing.T) {
	p,r,now:=labRecoveryPlanModel(t);old,d:=lifecycleTestOpen(t,r);d.state=lifecycleUnknown
	if _,err:=evolveLifecycleV2ForRecovery(old,&p,now);!errors.Is(err,errLifecycleCommitUnknown)||!old.poisoned||d.writes!=1 {t.Fatal("MODEL uncertain evolution hidden")}
	if old.verify()==nil {t.Fatal("MODEL legacy revived")}
}
func TestLifecycleRecoveryCommitRequiresActualExactReadback(t *testing.T) {
	s,d,_,now:=lifecycleRecoveryModelStore(t);d.corruptReadback=true
	if _,err:=s.acquireRecoveryOwner(now,now.Add(time.Minute));!errors.Is(err,errLifecycleCommitUnknown)||!s.core.poisoned||d.writes!=1 {t.Fatal("MODEL committed label trusted without readback")}
}
func TestLifecycleRecoveryDefinitePrecommitErrorIsNotUnknown(t *testing.T) {
	s,d,_,now:=lifecycleRecoveryModelStore(t);original:=bytes.Clone(d.raw);d.state=lifecycleNotCommitted;d.writeErr=errors.New("MODEL private I/O")
	_,err:=s.acquireRecoveryOwner(now,now.Add(time.Minute))
	if err==nil||errors.Is(err,errLifecycleCommitUnknown)||s.core.poisoned||!bytes.Equal(original,d.raw) {t.Fatal("MODEL precommit fact changed")}
	d.writeErr=errLifecycleUnsafe
	if _,err:=s.acquireRecoveryOwner(now,now.Add(time.Minute));err==nil||!s.core.poisoned {t.Fatal("MODEL integrity error not sticky")}
}
func TestLifecycleRecoveryMissingAndOldVersionControlNeverInitialize(t *testing.T) {
	d:=&lifecycleModelDisk{state:lifecycleCommitted}
	_,_,r,now:=lifecycleV3Model(t)
	if _,err:=openLifecycleRecoveryStore(d,now);err==nil||d.writes!=0 {t.Fatal("MODEL missing control initialized")}
	d.raw,_=encodeLifecycleRecord(r);d.exists=true
	if _,err:=openLifecycleRecoveryStore(d,now);err==nil||d.writes!=0 {t.Fatal("MODEL v2 automatically migrated")}
	var typedNil *lifecycleModelDisk
	if _,err:=openLifecycleRecoveryStore(typedNil,now);err==nil {t.Fatal("MODEL typed nil disk")}
}
func TestLifecycleRecoveryClockRollbackPermanentlyPoisonsLiveStore(t *testing.T) {
	s,_,_,now:=lifecycleRecoveryModelStore(t)
	if _,err:=s.acquireRecoveryOwner(now.Add(-time.Nanosecond),now.Add(time.Minute));err==nil||!s.core.poisoned {t.Fatal("MODEL clock rollback")}
	if _,err:=s.acquireRecoveryOwner(now,now.Add(time.Minute));!errors.Is(err,errLifecyclePoisoned) {t.Fatal("MODEL live store revived")}
	d:=s.core.disk
	fresh,err:=openLifecycleRecoveryStore(d,now);if err!=nil {t.Fatal("MODEL reopen last durable clock")}
	if _,err:=fresh.acquireRecoveryOwner(now.Add(-time.Nanosecond),now.Add(time.Minute));err==nil {t.Fatal("MODEL reopened accepted rollback")}
}
func TestLifecycleRecoveryRevisionFenceAndStaleCandidateRejectWithoutWrite(t *testing.T) {
	s,d,_,now:=lifecycleRecoveryModelStore(t);next,err:=s.core.copyRecord();if err!=nil {t.Fatal("MODEL copy")};next.core.Revision++
	if err:=s.core.commit(next,now);err==nil||d.writes!=0 {t.Fatal("MODEL stale CAS accepted")}
	next,_=s.core.copyRecord();next.core.Revision=^uint64(0);next.core.RecordSHA256,_=lifecycleV3RecordHash(*next.core)
	raw,err:=encodeLifecycleV3Record(next);if err!=nil {t.Fatal("MODEL max revision shape")};d.raw=raw;s.core.raw=bytes.Clone(raw);s.core.record=next
	if _,err:=s.acquireRecoveryOwner(now,now.Add(time.Minute));err==nil {t.Fatal("MODEL revision overflow")}
}
func TestLifecycleRecoveryLiveOwnerCannotBeRestoredFromJSONOrReopen(t *testing.T) {
	s,d,p,now:=lifecycleRecoveryModelStore(t);owner:=lifecycleRecoveryModelOwner(t,s,now)
	forged:=&lifecycleRecoveryOwnerToken{core:&lifecycleRecoveryOwnerCore{s.core,owner.core.nonce,owner.core.fence}}
	if s.beginRecovery(forged,&p,s.core.record.core.Revision,s.core.record.core.RecordSHA256,now)==nil {t.Fatal("MODEL copied fields minted owner")}
	fresh,err:=openLifecycleRecoveryStore(d,now);if err!=nil {t.Fatal("MODEL reopen")}
	if fresh.core.live!=nil||fresh.beginRecovery(owner,&p,fresh.core.record.core.Revision,fresh.core.record.core.RecordSHA256,now)==nil {t.Fatal("MODEL old owner adopted")}
	if _,err:=fresh.acquireRecoveryOwner(now,now.Add(time.Minute));err==nil {t.Fatal("MODEL active lease stolen")}
}
func TestLifecycleRecoveryImmutableHistoryAndOrdinaryUnknownSurviveNewOwner(t *testing.T) {
	s,_,owner,_,now:=lifecycleRecoveryModelPlanned(t);unknown:=s.core.record.core.Current.Active
	if s.revokeRecovery(owner,"MODEL_revoker","EXPLICIT_REVOKED",now)!=nil {t.Fatal("MODEL revoke")}
	history:=s.core.record.core.RecoveryHistory
	if len(history)!=1||history[0].Revocation==nil||!reflect.DeepEqual(unknown,s.core.record.core.Current.Active) {t.Fatal("MODEL history or UNKNOWN erased")}
	if _,err:=s.acquireRecoveryOwner(now.Add(time.Minute),now.Add(2*time.Minute));err!=nil {t.Fatal("MODEL expired terminal owner replacement")}
	next,_:=s.core.copyRecord();next.core.RecoveryHistory=[]lifecycleRecoveryTxn{}
	if s.core.commit(next,now.Add(time.Minute))==nil {t.Fatal("MODEL history deletion accepted")}
	if !reflect.DeepEqual(history,s.core.record.core.RecoveryHistory) {t.Fatal("MODEL history mutated")}
}
