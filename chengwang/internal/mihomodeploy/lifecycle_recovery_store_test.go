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
)

func lifecycleRecoveryTransactionModel(t *testing.T) (*lifecycleRecoveryStore, *lifecycleModelDisk, *lifecycleVerifiedBase, lifecycleV3Record, time.Time) {
	t.Helper()
	s, d, _, now := lifecycleRecoveryModelStore(t)
	b, err := s.core.verifiedBase()
	if err != nil { t.Fatal("MODEL verified base") }
	next, err := b.copyRecord()
	if err != nil { t.Fatal("MODEL detached draft") }
	return s, d, b, next, now
}

func TestLifecycleRecoveryVerifiedBaseRejectsForgedForeignAndStaleIdentity(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	copyCore := *b.core
	for _, forged := range []*lifecycleVerifiedBase{nil, {}, {core: &copyCore}} {
		if s.core.commitWithBase(forged, next, now) == nil || d.writes != 0 { t.Fatal("MODEL forged base published") }
	}
	foreign, _, _, _ := lifecycleRecoveryModelStore(t)
	if foreign.core.commitWithBase(b, next, now) == nil { t.Fatal("MODEL foreign store accepted base") }
	fresh, err := s.core.verifiedBase()
	if err != nil { t.Fatal("MODEL fresh operation") }
	defer fresh.release()
	if s.core.commitWithBase(b, next, now) == nil { t.Fatal("MODEL previous operation restored") }
	draft, err := fresh.copyRecord()
	if err != nil || s.core.commitWithBase(fresh, draft, now) != nil || d.writes != 1 { t.Fatal("MODEL legitimate single transaction") }
	if s.core.commitWithBase(fresh, draft, now) == nil || d.writes != 1 { t.Fatal("MODEL base replay") }
}

func TestLifecycleRecoveryVerifiedBaseCopiesAreDetachedAndRawTamperRejected(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	other, err := b.copyRecord()
	if err != nil { t.Fatal("MODEL other draft") }
	before := bytes.Clone(b.core.raw)
	next.core.SourceV2.ControlBytes[0] = '!'
	next.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	if !bytes.Equal(before, b.core.raw) || !bytes.Equal(other.core.SourceV2.ControlBytes, b.core.record.core.SourceV2.ControlBytes) || other.core.Current.Owner.OwnerNonce != b.core.record.core.Current.Owner.OwnerNonce { t.Fatal("MODEL draft aliases verified base") }
	b.core.raw[0] = '!'
	if s.core.commitWithBase(b, other, now) == nil || d.writes != 0 || !b.core.used { t.Fatal("MODEL changed snapshot bytes trusted") }
	b.core.raw = bytes.Clone(before)
	if s.core.commitWithBase(b, other, now) == nil || d.writes != 0 { t.Fatal("MODEL restored bytes revived spent base") }
}

func TestLifecycleRecoveryPreparedCandidateFullyValidatesAndSpendsFailedBase(t *testing.T) {
	s, d, _, _, now := lifecycleRecoveryModelPlanned(t)
	base, err := s.core.verifiedBase()
	if err != nil { t.Fatal("MODEL verified base") }
	defer base.release()
	next, err := base.copyRecord()
	if err != nil { t.Fatal("MODEL clone") }
	next.core.Recovery.Phase = "APPROVED"
	next.core.Recovery.Approval = &lifecycleRecoveryApproval{}
	if !lifecycleV3Transition(s.core.record.core, next.core) { t.Fatal("MODEL invalid candidate masked by transition gate") }
	before := d.writes
	if _, err := prepareLifecycleCandidate(base, next, now); err == nil || d.writes != before { t.Fatal("MODEL candidate semantics skipped") }
	valid, err := s.core.copyRecord()
	if err != nil { t.Fatal("MODEL original still valid") }
	if s.core.commitWithBase(base, valid, now) == nil || d.writes != before { t.Fatal("MODEL failed base reused") }
}

func TestLifecycleRecoveryPreparedCandidateDetachesAndRejectsCopiedCore(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	p, err := prepareLifecycleCandidate(b, next, now)
	if err != nil { t.Fatal("MODEL candidate preparation") }
	before := bytes.Clone(p.core.raw)
	next.core.SourceV2.ControlBytes[0] = '!'
	next.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	copyCore := *p.core
	if s.core.publishPrepared(&lifecyclePreparedCandidate{core: &copyCore}) == nil || d.writes != 0 { t.Fatal("MODEL copied core is not issued candidate") }
	if !bytes.Equal(before, p.core.raw) || p.core.record.core.SourceV2.ControlBytes[0] != '{' || p.core.record.core.Current.Owner.OwnerNonce == next.core.Current.Owner.OwnerNonce { t.Fatal("MODEL candidate aliases draft") }
	if s.core.publishPrepared(p) != nil || d.writes != 1 || !bytes.Equal(s.core.raw, before) { t.Fatal("MODEL actual prepared publication") }
	if s.core.publishPrepared(p) == nil || d.writes != 1 { t.Fatal("MODEL prepared candidate replayed") }
}

func TestLifecycleRecoveryPreparedPublicationRechecksActualDiskBytesAndCustody(t *testing.T) {
	for _, kind := range []string{"bytes", "missing", "custody"} {
		s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
		p, err := prepareLifecycleCandidate(b, next, now)
		if err != nil { t.Fatal("MODEL prepare") }
		switch kind { case "bytes": d.raw = append(d.raw, ' '); case "missing": d.exists = false; case "custody": d.verifyErr = errLifecycleUnsafe }
		if s.core.publishPrepared(p) == nil || d.writes != 0 || !s.core.poisoned { t.Fatal("MODEL actual precommit CAS/custody bypassed") }
		b.release()
	}
}

func TestLifecycleRecoveryPreparedReadbackAndUnknownRemainPoisoned(t *testing.T) {
	for _, kind := range []string{"readback", "unknown"} {
		s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
		p, err := prepareLifecycleCandidate(b, next, now)
		if err != nil { t.Fatal("MODEL prepare") }
		oldRevision := s.core.record.core.Revision
		if kind == "readback" { d.corruptReadback = true } else { d.state = lifecycleUnknown }
		if err := s.core.publishPrepared(p); !errors.Is(err, errLifecycleCommitUnknown) || !s.core.poisoned || s.core.record.core.Revision != oldRevision || d.writes != 1 { t.Fatal("MODEL uncertain publication hidden") }
		if s.core.publishPrepared(p) == nil || d.writes != 1 { t.Fatal("MODEL uncertain candidate replayed") }
		b.release()
	}
}

func TestLifecycleRecoveryTransactionCapabilitiesEndWithLockedOperation(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	p, err := prepareLifecycleCandidate(b, next, now)
	if err != nil { t.Fatal("MODEL prepare") }
	b.release()
	if s.core.publishPrepared(p) == nil || d.writes != 0 || s.core.activeBase != nil || s.core.activePrepared != nil { t.Fatal("MODEL released operation continued") }
	_, err = s.acquireRecoveryOwner(now, now.Add(time.Minute))
	if err != nil || s.core.activeBase != nil || s.core.activePrepared != nil { t.Fatal("MODEL successful operation retained validation cache") }
}

func TestLifecycleRecoveryRawPublisherRequiresActualLegacyEvolution(t *testing.T) {
	s, d, _, _ := lifecycleRecoveryModelStore(t)
	if s.core.publish(bytes.Clone(s.core.raw)) == nil || d.writes != 0 { t.Fatal("MODEL generic raw V3 publisher bypass") }
	p, old, now := labRecoveryPlanModel(t)
	oldRaw, err := encodeLifecycleRecord(old)
	if err != nil { t.Fatal("MODEL old source") }
	candidate, err := buildLifecycleV3Evolution(oldRaw, &p, now)
	if err != nil { t.Fatal("MODEL valid evolution") }
	raw, err := encodeLifecycleV3Record(candidate)
	if err != nil { t.Fatal("MODEL evolution bytes") }
	old.wire.Revision++; old = lifecycleTestSeal(t, old)
	otherRaw, err := encodeLifecycleRecord(old)
	if err != nil { t.Fatal("MODEL foreign canonical source") }
	actual := &lifecycleModelDisk{raw: otherRaw, exists: true, state: lifecycleCommitted}
	x := &lifecycleRecoveryStoreCore{disk: actual, record: candidate, raw: bytes.Clone(raw)}
	if x.publish(raw) == nil || actual.writes != 0 { t.Fatal("MODEL actual old snapshot not bound") }
}

func TestLifecycleRecoveryExternalInvalidBytesNeverAcquireVerifiedProof(t *testing.T) {
	s, d, _, now := lifecycleRecoveryModelStore(t)
	bad, err := s.core.copyRecord()
	if err != nil { t.Fatal("MODEL copy") }
	bad.core.Current.Head.VerificationSHA256 = "MODEL_invalid"
	bad = lifecycleV3Seal(t, bad)
	raw, err := json.Marshal(bad.core)
	if err != nil { t.Fatal("MODEL coherent outer hash") }
	d.raw = bytes.Clone(raw); s.core.raw = bytes.Clone(raw); s.core.record = bad
	if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || d.writes != 0 { t.Fatal("MODEL invalid external source gained proof") }
	if _, err := openLifecycleRecoveryStore(d, now); err == nil || d.writes != 0 { t.Fatal("MODEL reopen skipped full semantics") }
}

func TestLifecycleRecoveryTransactionOpaqueValuesAndPreparedRawTamper(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	p, err := prepareLifecycleCandidate(b, next, now)
	if err != nil { t.Fatal("MODEL prepare") }
	needle := next.core.Current.Owner.OwnerNonce
	for _, v := range []any{*b, b, *p, p} {
		for _, format := range []string{"%v", "%+v", "%#v", "%x", "%d", "%p"} { if strings.Contains(fmt.Sprintf(format, v), needle) { t.Fatal("MODEL transaction debug leak") } }
		if _, err := json.Marshal(v); err == nil { t.Fatal("MODEL transaction serialized") }
	}
	p.core.raw[0] = '!'
	if s.core.publishPrepared(p) == nil || d.writes != 0 { t.Fatal("MODEL changed prepared bytes published") }
	fresh, fd, fb, draft, at := lifecycleRecoveryTransactionModel(t)
	defer fb.release()
	changed, err := prepareLifecycleCandidate(fb, draft, at)
	if err != nil { t.Fatal("MODEL second prepare") }
	// Deliberate same-package private-state mutation is an internal consistency
	// check; no public API exposes this record or changes raw with it.
	changed.core.record.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	if fresh.core.publishPrepared(changed) == nil || fd.writes != 0 { t.Fatal("MODEL private metadata/raw mismatch published") }
}

func lifecycleRecoveryModelStore(t *testing.T) (*lifecycleRecoveryStore, *lifecycleModelDisk, labRecoveryPlan, time.Time) {
	t.Helper()
	r, p, _, now := lifecycleV3Model(t)
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL encode")
	}
	d := &lifecycleModelDisk{raw: raw, exists: true, state: lifecycleCommitted}
	s, err := openLifecycleRecoveryStore(d, now)
	if err != nil {
		t.Fatal("MODEL open")
	}
	return s, d, p, now
}
func lifecycleRecoveryModelOwner(t *testing.T, s *lifecycleRecoveryStore, now time.Time) *lifecycleRecoveryOwnerToken {
	t.Helper()
	o, err := s.acquireRecoveryOwner(now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("MODEL owner")
	}
	return o
}
func lifecycleRecoveryModelPlanned(t *testing.T) (*lifecycleRecoveryStore, *lifecycleModelDisk, *lifecycleRecoveryOwnerToken, labRecoveryPlan, time.Time) {
	t.Helper()
	s, d, p, now := lifecycleRecoveryModelStore(t)
	owner := lifecycleRecoveryModelOwner(t, s, now)
	if err := s.beginRecovery(owner, &p, s.core.record.core.Revision, s.core.record.core.RecordSHA256, now); err != nil {
		t.Fatal("MODEL plan")
	}
	return s, d, owner, p, now
}

func TestLifecycleRecoveryEvolutionTransfersOneDiskAndInvalidatesOldOwner(t *testing.T) {
	p, original, now := labRecoveryPlanModel(t)
	old, d := lifecycleTestOpen(t, original)
	// MODEL a still-live legacy lease, not a restored authentication identity.
	old.live = &lifecycleOwnerToken{lifecycleOwnerCore: &lifecycleOwnerCore{old, original.wire.Owner.OwnerNonce, original.wire.Owner.Fence}}
	oldToken := old.live
	s, err := evolveLifecycleV2ForRecovery(old, &p, now)
	if err != nil || s == nil || !old.closed || old.disk != nil || old.live != nil || d.closed || s.core.disk != d {
		t.Fatal("MODEL nonexclusive handoff")
	}
	if oldToken != nil && old.live == oldToken {
		t.Fatal("MODEL old owner retained")
	}
	if old.verify() == nil || s.core.verify() != nil {
		t.Fatal("MODEL wrong live store")
	}
	if s.close() != nil || !d.closed {
		t.Fatal("MODEL sole disk close owner")
	}
}
func TestLifecycleRecoveryEvolutionWrongCASAndMarkerWriteNothing(t *testing.T) {
	for _, kind := range []string{"record", "marker", "expired"} {
		p, original, now := labRecoveryPlanModel(t)
		old, d := lifecycleTestOpen(t, original)
		before := bytes.Clone(d.raw)
		switch kind {
		case "record":
			p.core.descriptor.ExpectedRevision++
		case "marker":
			p.core.descriptor.Provisioning.MarkerSHA256 = strings.Repeat("f", 64)
		case "expired":
			now = p.descriptor().ExpiresAt
		}
		if _, err := evolveLifecycleV2ForRecovery(old, &p, now); err == nil || d.writes != 0 || !bytes.Equal(d.raw, before) || old.closed {
			t.Fatal("MODEL invalid evolution changed storage")
		}
	}
}
func TestLifecycleRecoveryEvolutionUncertainWritePoisonsLegacy(t *testing.T) {
	p, r, now := labRecoveryPlanModel(t)
	old, d := lifecycleTestOpen(t, r)
	d.state = lifecycleUnknown
	if _, err := evolveLifecycleV2ForRecovery(old, &p, now); !errors.Is(err, errLifecycleCommitUnknown) || !old.poisoned || d.writes != 1 {
		t.Fatal("MODEL uncertain evolution hidden")
	}
	if old.verify() == nil {
		t.Fatal("MODEL legacy revived")
	}
}
func TestLifecycleRecoveryCommitRequiresActualExactReadback(t *testing.T) {
	s, d, _, now := lifecycleRecoveryModelStore(t)
	d.corruptReadback = true
	if _, err := s.acquireRecoveryOwner(now, now.Add(time.Minute)); !errors.Is(err, errLifecycleCommitUnknown) || !s.core.poisoned || d.writes != 1 {
		t.Fatal("MODEL committed label trusted without readback")
	}
}
func TestLifecycleRecoveryDefinitePrecommitErrorIsNotUnknown(t *testing.T) {
	s, d, _, now := lifecycleRecoveryModelStore(t)
	original := bytes.Clone(d.raw)
	d.state = lifecycleNotCommitted
	d.writeErr = errors.New("MODEL private I/O")
	_, err := s.acquireRecoveryOwner(now, now.Add(time.Minute))
	if err == nil || errors.Is(err, errLifecycleCommitUnknown) || s.core.poisoned || !bytes.Equal(original, d.raw) {
		t.Fatal("MODEL precommit fact changed")
	}
	d.writeErr = errLifecycleUnsafe
	if _, err := s.acquireRecoveryOwner(now, now.Add(time.Minute)); err == nil || !s.core.poisoned {
		t.Fatal("MODEL integrity error not sticky")
	}
}
func TestLifecycleRecoveryMissingAndOldVersionControlNeverInitialize(t *testing.T) {
	d := &lifecycleModelDisk{state: lifecycleCommitted}
	_, _, r, now := lifecycleV3Model(t)
	if _, err := openLifecycleRecoveryStore(d, now); err == nil || d.writes != 0 {
		t.Fatal("MODEL missing control initialized")
	}
	d.raw, _ = encodeLifecycleRecord(r)
	d.exists = true
	if _, err := openLifecycleRecoveryStore(d, now); err == nil || d.writes != 0 {
		t.Fatal("MODEL v2 automatically migrated")
	}
	var typedNil *lifecycleModelDisk
	if _, err := openLifecycleRecoveryStore(typedNil, now); err == nil {
		t.Fatal("MODEL typed nil disk")
	}
}
func TestLifecycleRecoveryClockRollbackPermanentlyPoisonsLiveStore(t *testing.T) {
	s, _, _, now := lifecycleRecoveryModelStore(t)
	if _, err := s.acquireRecoveryOwner(now.Add(-time.Nanosecond), now.Add(time.Minute)); err == nil || !s.core.poisoned {
		t.Fatal("MODEL clock rollback")
	}
	if _, err := s.acquireRecoveryOwner(now, now.Add(time.Minute)); !errors.Is(err, errLifecyclePoisoned) {
		t.Fatal("MODEL live store revived")
	}
	d := s.core.disk
	fresh, err := openLifecycleRecoveryStore(d, now)
	if err != nil {
		t.Fatal("MODEL reopen last durable clock")
	}
	if _, err := fresh.acquireRecoveryOwner(now.Add(-time.Nanosecond), now.Add(time.Minute)); err == nil {
		t.Fatal("MODEL reopened accepted rollback")
	}
}
func TestLifecycleRecoveryRevisionFenceAndStaleCandidateRejectWithoutWrite(t *testing.T) {
	s, d, _, now := lifecycleRecoveryModelStore(t)
	next, err := s.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL copy")
	}
	next.core.Revision++
	if err := s.core.commit(next, now); err == nil || d.writes != 0 {
		t.Fatal("MODEL stale CAS accepted")
	}
	next, _ = s.core.copyRecord()
	next.core.Revision = ^uint64(0)
	next.core.RecordSHA256, _ = lifecycleV3RecordHash(*next.core)
	raw, err := encodeLifecycleV3Record(next)
	if err != nil {
		t.Fatal("MODEL max revision shape")
	}
	d.raw = raw
	s.core.raw = bytes.Clone(raw)
	s.core.record = next
	if _, err := s.acquireRecoveryOwner(now, now.Add(time.Minute)); err == nil {
		t.Fatal("MODEL revision overflow")
	}
}
func TestLifecycleRecoveryLiveOwnerCannotBeRestoredFromJSONOrReopen(t *testing.T) {
	s, d, p, now := lifecycleRecoveryModelStore(t)
	owner := lifecycleRecoveryModelOwner(t, s, now)
	forged := &lifecycleRecoveryOwnerToken{core: &lifecycleRecoveryOwnerCore{s.core, owner.core.nonce, owner.core.fence}}
	if s.beginRecovery(forged, &p, s.core.record.core.Revision, s.core.record.core.RecordSHA256, now) == nil {
		t.Fatal("MODEL copied fields minted owner")
	}
	fresh, err := openLifecycleRecoveryStore(d, now)
	if err != nil {
		t.Fatal("MODEL reopen")
	}
	if fresh.core.live != nil || fresh.beginRecovery(owner, &p, fresh.core.record.core.Revision, fresh.core.record.core.RecordSHA256, now) == nil {
		t.Fatal("MODEL old owner adopted")
	}
	if _, err := fresh.acquireRecoveryOwner(now, now.Add(time.Minute)); err == nil {
		t.Fatal("MODEL active lease stolen")
	}
}
func TestLifecycleRecoveryImmutableHistoryAndOrdinaryUnknownSurviveNewOwner(t *testing.T) {
	s, _, owner, _, now := lifecycleRecoveryModelPlanned(t)
	unknown := s.core.record.core.Current.Active
	if s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL revoke")
	}
	history := s.core.record.core.RecoveryHistory
	if len(history) != 1 || history[0].Revocation == nil || !reflect.DeepEqual(unknown, s.core.record.core.Current.Active) {
		t.Fatal("MODEL history or UNKNOWN erased")
	}
	if _, err := s.acquireRecoveryOwner(now.Add(time.Minute), now.Add(2*time.Minute)); err != nil {
		t.Fatal("MODEL expired terminal owner replacement")
	}
	next, _ := s.core.copyRecord()
	next.core.RecoveryHistory = []lifecycleRecoveryTxn{}
	if s.core.commit(next, now.Add(time.Minute)) == nil {
		t.Fatal("MODEL history deletion accepted")
	}
	if !reflect.DeepEqual(history, s.core.record.core.RecoveryHistory) {
		t.Fatal("MODEL history mutated")
	}
}
