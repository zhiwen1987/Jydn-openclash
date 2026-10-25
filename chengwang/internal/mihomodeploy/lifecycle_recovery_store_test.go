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
	if err != nil {
		t.Fatal("MODEL verified base")
	}
	next, err := b.copyRecord()
	if err != nil {
		t.Fatal("MODEL detached draft")
	}
	return s, d, b, next, now
}

func TestLifecycleRecoveryVerifiedBaseRejectsForgedForeignAndStaleIdentity(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	copyCore := *b.core
	for _, forged := range []*lifecycleVerifiedBase{nil, {}, {core: &copyCore}} {
		if s.core.commitWithBase(forged, next, now) == nil || d.writes != 0 {
			t.Fatal("MODEL forged base published")
		}
	}
	foreign, _, _, _ := lifecycleRecoveryModelStore(t)
	if foreign.core.commitWithBase(b, next, now) == nil {
		t.Fatal("MODEL foreign store accepted base")
	}
	fresh, err := s.core.verifiedBase()
	if err != nil {
		t.Fatal("MODEL fresh operation")
	}
	defer fresh.release()
	if s.core.commitWithBase(b, next, now) == nil {
		t.Fatal("MODEL previous operation restored")
	}
	draft, err := fresh.copyRecord()
	if err != nil || s.core.commitWithBase(fresh, draft, now) != nil || d.writes != 1 {
		t.Fatal("MODEL legitimate single transaction")
	}
	if s.core.commitWithBase(fresh, draft, now) == nil || d.writes != 1 {
		t.Fatal("MODEL base replay")
	}
}

func TestLifecycleRecoveryVerifiedBaseCopiesAreDetachedAndRawTamperRejected(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	other, err := b.copyRecord()
	if err != nil {
		t.Fatal("MODEL other draft")
	}
	before := bytes.Clone(b.core.raw)
	next.core.SourceV2.ControlBytes[0] = '!'
	next.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	if !bytes.Equal(before, b.core.raw) || !bytes.Equal(other.core.SourceV2.ControlBytes, b.core.record.core.SourceV2.ControlBytes) || other.core.Current.Owner.OwnerNonce != b.core.record.core.Current.Owner.OwnerNonce {
		t.Fatal("MODEL draft aliases verified base")
	}
	b.core.raw[0] = '!'
	if s.core.commitWithBase(b, other, now) == nil || d.writes != 0 || !b.core.used {
		t.Fatal("MODEL changed snapshot bytes trusted")
	}
	b.core.raw = bytes.Clone(before)
	if s.core.commitWithBase(b, other, now) == nil || d.writes != 0 {
		t.Fatal("MODEL restored bytes revived spent base")
	}
}

func TestLifecycleRecoveryPreparedCandidateFullyValidatesAndSpendsFailedBase(t *testing.T) {
	s, d, _, _, now := lifecycleRecoveryModelPlanned(t)
	base, err := s.core.verifiedBase()
	if err != nil {
		t.Fatal("MODEL verified base")
	}
	defer base.release()
	next, err := base.copyRecord()
	if err != nil {
		t.Fatal("MODEL clone")
	}
	next.core.Recovery.Phase = "APPROVED"
	next.core.Recovery.Approval = &lifecycleRecoveryApproval{}
	if !lifecycleV3Transition(s.core.record.core, next.core) {
		t.Fatal("MODEL invalid candidate masked by transition gate")
	}
	before := d.writes
	if _, err := prepareLifecycleCandidate(base, next, now); err == nil || d.writes != before {
		t.Fatal("MODEL candidate semantics skipped")
	}
	valid, err := s.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL original still valid")
	}
	if s.core.commitWithBase(base, valid, now) == nil || d.writes != before {
		t.Fatal("MODEL failed base reused")
	}
}

func TestLifecycleRecoveryPreparedCandidateDetachesAndRejectsCopiedCore(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	p, err := prepareLifecycleCandidate(b, next, now)
	if err != nil {
		t.Fatal("MODEL candidate preparation")
	}
	before := bytes.Clone(p.core.raw)
	next.core.SourceV2.ControlBytes[0] = '!'
	next.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	copyCore := *p.core
	if s.core.publishPrepared(&lifecyclePreparedCandidate{core: &copyCore}) == nil || d.writes != 0 {
		t.Fatal("MODEL copied core is not issued candidate")
	}
	if !bytes.Equal(before, p.core.raw) || p.core.record.core.SourceV2.ControlBytes[0] != '{' || p.core.record.core.Current.Owner.OwnerNonce == next.core.Current.Owner.OwnerNonce {
		t.Fatal("MODEL candidate aliases draft")
	}
	if s.core.publishPrepared(p) != nil || d.writes != 1 || !bytes.Equal(s.core.raw, before) {
		t.Fatal("MODEL actual prepared publication")
	}
	if s.core.publishPrepared(p) == nil || d.writes != 1 {
		t.Fatal("MODEL prepared candidate replayed")
	}
}

func TestLifecycleRecoveryPreparedPublicationRechecksActualDiskBytesAndCustody(t *testing.T) {
	for _, kind := range []string{"bytes", "missing", "custody"} {
		s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
		p, err := prepareLifecycleCandidate(b, next, now)
		if err != nil {
			t.Fatal("MODEL prepare")
		}
		switch kind {
		case "bytes":
			d.raw = append(d.raw, ' ')
		case "missing":
			d.exists = false
		case "custody":
			d.verifyErr = errLifecycleUnsafe
		}
		if s.core.publishPrepared(p) == nil || d.writes != 0 || !s.core.poisoned {
			t.Fatal("MODEL actual precommit CAS/custody bypassed")
		}
		b.release()
	}
}

func TestLifecycleRecoveryPreparedReadbackAndUnknownRemainPoisoned(t *testing.T) {
	for _, kind := range []string{"readback", "unknown"} {
		s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
		p, err := prepareLifecycleCandidate(b, next, now)
		if err != nil {
			t.Fatal("MODEL prepare")
		}
		oldRevision := s.core.record.core.Revision
		if kind == "readback" {
			d.corruptReadback = true
		} else {
			d.state = lifecycleUnknown
		}
		if err := s.core.publishPrepared(p); !errors.Is(err, errLifecycleCommitUnknown) || !s.core.poisoned || s.core.record.core.Revision != oldRevision || d.writes != 1 {
			t.Fatal("MODEL uncertain publication hidden")
		}
		if s.core.publishPrepared(p) == nil || d.writes != 1 {
			t.Fatal("MODEL uncertain candidate replayed")
		}
		b.release()
	}
}

func TestLifecycleRecoveryTransactionCapabilitiesEndWithLockedOperation(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	p, err := prepareLifecycleCandidate(b, next, now)
	if err != nil {
		t.Fatal("MODEL prepare")
	}
	b.release()
	if s.core.publishPrepared(p) == nil || d.writes != 0 || s.core.activeBase != nil || s.core.activePrepared != nil {
		t.Fatal("MODEL released operation continued")
	}
	_, err = s.acquireRecoveryOwner(now, now.Add(time.Minute))
	if err != nil || s.core.activeBase != nil || s.core.activePrepared != nil {
		t.Fatal("MODEL successful operation retained validation cache")
	}
}

func TestLifecycleRecoveryRawPublisherRequiresActualLegacyEvolution(t *testing.T) {
	s, d, _, _ := lifecycleRecoveryModelStore(t)
	if s.core.publish(bytes.Clone(s.core.raw)) == nil || d.writes != 0 {
		t.Fatal("MODEL generic raw V3 publisher bypass")
	}
	p, old, now := labRecoveryPlanModel(t)
	oldRaw, err := encodeLifecycleRecord(old)
	if err != nil {
		t.Fatal("MODEL old source")
	}
	candidate, err := buildLifecycleV3Evolution(oldRaw, &p, now)
	if err != nil {
		t.Fatal("MODEL valid evolution")
	}
	raw, err := encodeLifecycleV3Record(candidate)
	if err != nil {
		t.Fatal("MODEL evolution bytes")
	}
	old.wire.Revision++
	old = lifecycleTestSeal(t, old)
	otherRaw, err := encodeLifecycleRecord(old)
	if err != nil {
		t.Fatal("MODEL foreign canonical source")
	}
	actual := &lifecycleModelDisk{raw: otherRaw, exists: true, state: lifecycleCommitted}
	x := &lifecycleRecoveryStoreCore{disk: actual, record: candidate, raw: bytes.Clone(raw)}
	if x.publish(raw) == nil || actual.writes != 0 {
		t.Fatal("MODEL actual old snapshot not bound")
	}
}

func TestLifecycleRecoveryExternalInvalidBytesNeverAcquireVerifiedProof(t *testing.T) {
	s, d, _, now := lifecycleRecoveryModelStore(t)
	bad, err := s.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL copy")
	}
	bad.core.Current.Head.VerificationSHA256 = "MODEL_invalid"
	bad = lifecycleV3Seal(t, bad)
	raw, err := json.Marshal(bad.core)
	if err != nil {
		t.Fatal("MODEL coherent outer hash")
	}
	d.raw = bytes.Clone(raw)
	s.core.raw = bytes.Clone(raw)
	s.core.record = bad
	if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || d.writes != 0 {
		t.Fatal("MODEL invalid external source gained proof")
	}
	if _, err := openLifecycleRecoveryStore(d, now); err == nil || d.writes != 0 {
		t.Fatal("MODEL reopen skipped full semantics")
	}
}

func TestLifecycleRecoveryTransactionOpaqueValuesAndPreparedRawTamper(t *testing.T) {
	s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	p, err := prepareLifecycleCandidate(b, next, now)
	if err != nil {
		t.Fatal("MODEL prepare")
	}
	needle := next.core.Current.Owner.OwnerNonce
	for _, v := range []any{*b, b, *p, p} {
		for _, format := range []string{"%v", "%+v", "%#v", "%x", "%d", "%p"} {
			if strings.Contains(fmt.Sprintf(format, v), needle) {
				t.Fatal("MODEL transaction debug leak")
			}
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("MODEL transaction serialized")
		}
	}
	p.core.raw[0] = '!'
	if s.core.publishPrepared(p) == nil || d.writes != 0 {
		t.Fatal("MODEL changed prepared bytes published")
	}
	fresh, fd, fb, draft, at := lifecycleRecoveryTransactionModel(t)
	defer fb.release()
	changed, err := prepareLifecycleCandidate(fb, draft, at)
	if err != nil {
		t.Fatal("MODEL second prepare")
	}
	// Deliberate same-package private-state mutation is an internal consistency
	// check; no public API exposes this record or changes raw with it.
	changed.core.record.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	if fresh.core.publishPrepared(changed) == nil || fd.writes != 0 {
		t.Fatal("MODEL private metadata/raw mismatch published")
	}
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

func TestLifecycleRecoveryValidatedSnapshotRejectsCoordinatedCanonicalReplacement(t *testing.T) {
	s, d, _, _ := lifecycleRecoveryModelStore(t)
	next, err := s.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL copy")
	}
	next.core.Revision++
	next = lifecycleV3Seal(t, next)
	raw, err := encodeLifecycleV3Record(next)
	if err != nil {
		t.Fatal("MODEL replacement must be independently valid canonical bytes")
	}
	// Even a valid, rehashed record cannot replace the store's actually
	// validated image just by coordinating disk and mutable private fields.
	d.raw, s.core.raw, s.core.record = bytes.Clone(raw), bytes.Clone(raw), next
	if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || s.core.validated != nil || d.writes != 0 {
		t.Fatal("MODEL coordinated replacement gained validation proof")
	}
}

func TestLifecycleRecoveryValidatedSnapshotBindsNestedRecordNotJustOuterHash(t *testing.T) {
	s, d, _, _ := lifecycleRecoveryModelStore(t)
	before := bytes.Clone(s.core.raw)
	oldHash := s.core.record.core.RecordSHA256
	s.core.record.core.Current.Head.VerificationSHA256 = strings.Repeat("e", 64)
	if s.core.record.core.RecordSHA256 != oldHash || !bytes.Equal(s.core.raw, before) {
		t.Fatal("MODEL mutation precondition")
	}
	if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || d.writes != 0 {
		t.Fatal("MODEL equal outer hash hid nested mutation")
	}
}

func TestLifecycleRecoveryValidatedSnapshotIssuerBindingRejectsRewrittenImageFields(t *testing.T) {
	s, d, _, _ := lifecycleRecoveryModelStore(t)
	next, err := s.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL copy")
	}
	next.core.Revision++
	next = lifecycleV3Seal(t, next)
	raw, err := encodeLifecycleV3Record(next)
	if err != nil {
		t.Fatal("MODEL independently valid replacement")
	}
	// Rewriting the image's visible private metadata too must still fail its
	// original issuer closure. This does not claim protection against arbitrary
	// malicious code replacing executable functions inside this package.
	s.core.validated.canonical = string(raw)
	s.core.validated.rawSHA256 = labConfigHash(raw)
	d.raw, s.core.raw, s.core.record = bytes.Clone(raw), bytes.Clone(raw), next
	if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || d.writes != 0 {
		t.Fatal("MODEL rewritten image metadata replaced issuer evidence")
	}
}

func TestLifecycleRecoveryValidatedSnapshotRejectsMissingCopiedAndForeignImage(t *testing.T) {
	for _, kind := range []string{"missing", "copied", "foreign", "copied-store"} {
		s, d, _, _ := lifecycleRecoveryModelStore(t)
		switch kind {
		case "missing":
			s.core.validated = nil
		case "copied":
			copyImage := *s.core.validated
			s.core.validated = &copyImage
		case "foreign":
			other, _, _, _ := lifecycleRecoveryModelStore(t)
			s.core.validated = other.core.validated
		case "copied-store":
			copyStore := *s.core
			s.core = &copyStore
		}
		if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || d.writes != 0 {
			t.Fatal("MODEL missing/copied/foreign image admitted")
		}
	}
}

func TestLifecycleRecoveryValidatedSnapshotRejectsOlderImageAndDurableRollback(t *testing.T) {
	s, d, _, now := lifecycleRecoveryModelStore(t)
	oldImage := s.core.validated
	oldRaw := bytes.Clone(s.core.raw)
	oldRecord, err := s.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL copy")
	}
	if _, err := s.acquireRecoveryOwner(now, now.Add(time.Minute)); err != nil || s.core.validated == oldImage || s.core.validationGeneration <= oldImage.generation {
		t.Fatal("MODEL actual successful publication did not advance image")
	}
	// A retained older issued image is not permission to roll the same store
	// back, even when all ordinary durable/raw/typed values are restored.
	s.core.validated = oldImage
	s.core.raw, d.raw, s.core.record = bytes.Clone(oldRaw), bytes.Clone(oldRaw), oldRecord
	before := d.writes
	if _, err := s.core.verifiedBase(); err == nil || !s.core.poisoned || d.writes != before {
		t.Fatal("MODEL older image revived after durable rollback")
	}
}

func TestLifecycleRecoveryValidatedSnapshotReturnedCopiesDoNotAliasImage(t *testing.T) {
	s, d, b, draft, _ := lifecycleRecoveryTransactionModel(t)
	defer b.release()
	image := s.core.validated
	canonical := image.canonical
	draft.core.SourceV2.ControlBytes[0] = '!'
	b.core.record.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
	if image.canonical != canonical || string(s.core.raw) != canonical || string(d.raw) != canonical || s.core.record.core.Current.Owner.OwnerNonce == b.core.record.core.Current.Owner.OwnerNonce {
		t.Fatal("MODEL returned typed/base record aliases store image")
	}
	if err := s.core.verify(); err != nil || s.core.validated != image {
		t.Fatal("MODEL detached mutation changed trusted image")
	}
}

func TestLifecycleRecoveryValidatedSnapshotRechecksMemoryAfterBaseAndPreparation(t *testing.T) {
	for _, kind := range []string{"after-base", "after-preparation"} {
		s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
		if kind == "after-base" {
			s.core.record.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
			if _, err := prepareLifecycleCandidate(b, next, now); err == nil || d.writes != 0 {
				t.Fatal("MODEL changed base metadata admitted to preparation")
			}
		} else {
			p, err := prepareLifecycleCandidate(b, next, now)
			if err != nil {
				t.Fatal("MODEL prepare")
			}
			s.core.record.core.Current.Owner.OwnerNonce = strings.Repeat("e", 64)
			if s.core.publishPrepared(p) == nil || d.writes != 0 || !s.core.poisoned {
				t.Fatal("MODEL changed base metadata passed final precommit")
			}
		}
		b.release()
	}
}

func TestLifecycleRecoveryValidatedSnapshotFailedPublicationNeverAdoptsCandidate(t *testing.T) {
	for _, kind := range []string{"not-committed", "unknown", "readback"} {
		s, d, b, next, now := lifecycleRecoveryTransactionModel(t)
		image, generation := s.core.validated, s.core.validationGeneration
		p, err := prepareLifecycleCandidate(b, next, now)
		if err != nil {
			t.Fatal("MODEL prepare")
		}
		switch kind {
		case "not-committed":
			d.state, d.writeErr = lifecycleNotCommitted, errors.New("MODEL private write failure")
		case "unknown":
			d.state = lifecycleUnknown
		case "readback":
			d.corruptReadback = true
		}
		if s.core.publishPrepared(p) == nil || s.core.validationGeneration != generation || d.writes != 1 {
			t.Fatal("MODEL unsuccessful publication advanced image")
		}
		if kind == "not-committed" {
			if s.core.validated != image || s.core.poisoned {
				t.Fatal("MODEL definite uncommitted error discarded valid old image")
			}
		} else if !s.core.poisoned || s.core.validated != nil {
			t.Fatal("MODEL uncertain write retained reusable image")
		}
		b.release()
	}
}

func TestLifecycleRecoveryValidatedSnapshotCloseAndRollbackInvalidateImage(t *testing.T) {
	for _, kind := range []string{"close", "clock"} {
		s, d, _, now := lifecycleRecoveryModelStore(t)
		image := s.core.validated
		if kind == "close" {
			if s.close() != nil || !d.closed {
				t.Fatal("MODEL close")
			}
		} else if s.core.trustedNow(now.Add(-time.Nanosecond)) == nil {
			t.Fatal("MODEL rollback")
		}
		if s.core.validated != nil {
			t.Fatal("MODEL ended store retained image")
		}
		s.core.validated = image
		if _, err := s.core.verifiedBase(); err == nil || d.writes != 0 {
			t.Fatal("MODEL ended store image revived")
		}
	}
}

func TestLifecycleRecoveryValidatedSnapshotReopenStillRejectsMalformedArchive(t *testing.T) {
	s, d, owner, _, now := lifecycleRecoveryModelPlanned(t)
	if s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL archive")
	}
	next, err := s.core.copyRecord()
	if err != nil || len(next.core.RecoveryHistory) != 1 {
		t.Fatal("MODEL archived copy")
	}
	next.core.RecoveryHistory[0].Plan.PlanSHA256 = strings.Repeat("e", 64)
	next = lifecycleV3Seal(t, next)
	raw, err := json.Marshal(next.core)
	if err != nil {
		t.Fatal("MODEL malformed archived wire")
	}
	d.raw = raw
	before := d.writes
	if _, err := openLifecycleRecoveryStore(d, now); err == nil || d.writes != before {
		t.Fatal("MODEL reopen reused live cache instead of full validation")
	}
}

func TestLifecycleRecoveryValidatedSnapshotRefreshPreservesEveryArchivedPlan(t *testing.T) {
	s, d, first, now := lifecycleRecoveryModelStore(t)
	owner := lifecycleRecoveryModelOwner(t, s, now)
	original, err := lifecycleV3Source(s.core.record.core)
	if err != nil {
		t.Fatal("MODEL original source")
	}
	for n := 0; n < 4; n++ {
		previous := s.core.validated
		plan, err := newLabRecoveryPlan(original, fmt.Sprintf("labrec_%032x", n+2), first.descriptor().DeclaredInitiatorRef, first.descriptor().TargetArtifact, now, now.Add(time.Minute))
		if err != nil || s.beginRecovery(owner, &plan, s.core.record.core.Revision, s.core.record.core.RecordSHA256, now) != nil || s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
			t.Fatal("MODEL complete independently valid plan/revoke")
		}
		if s.core.validated == previous || len(s.core.record.core.RecoveryHistory) != n+1 || string(d.raw) != s.core.validated.canonical || string(s.core.raw) != s.core.validated.canonical {
			t.Fatal("MODEL successful image did not preserve all archive bytes")
		}
	}
	if _, err := decodeLifecycleV3Record(d.raw); err != nil {
		t.Fatal("MODEL final bytes fail original complete external decoder")
	}
	t.Run("canonical_max_revision_reaches_overflow_guard", func(t *testing.T) {
		maximal, err := s.core.copyRecord()
		if err != nil {
			t.Fatal("MODEL maximum revision copy")
		}
		maximal.core.Revision = ^uint64(0)
		maximal = lifecycleV3Seal(t, maximal)
		raw, err := encodeLifecycleV3Record(maximal)
		if err != nil {
			t.Fatal("MODEL maximum revision must be valid canonical input")
		}
		freshDisk := &lifecycleModelDisk{raw: bytes.Clone(raw), exists: true, state: lifecycleCommitted}
		fresh, err := openLifecycleRecoveryStore(freshDisk, now)
		if err != nil || fresh.core.validated == nil {
			t.Fatal("MODEL maximum revision failed strict open/issuance")
		}
		base, err := fresh.core.verifiedBase()
		if err != nil {
			t.Fatal("MODEL maximum revision did not pass actual snapshot verification")
		}
		base.release()
		if _, err := fresh.acquireRecoveryOwner(now.Add(time.Minute), now.Add(2*time.Minute)); err == nil || freshDisk.writes != 0 || fresh.core.poisoned || fresh.core.record.core.Revision != ^uint64(0) {
			t.Fatal("MODEL maximum revision overflow guard did not reject before write")
		}
	})
}
