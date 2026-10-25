//go:build linux

package mihomodeploy

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

// STRUCTURE MODEL ONLY. Reuses the explicitly fake retained-process model.
// Neither this model nor any test below calls a valid native Start, Stop,
// Signal, observe or listener function on os.Process{Pid:...}.
func labRecoveryStartedIssuedModel(t *testing.T) (*labRecoveryStartedEpoch, labRecoveryStartedBinding, time.Time) {
	t.Helper()
	b, f, now := labRecoveryStartedModel(t)
	k, _, _, _ := labQuiescenceOwnedModel(t)
	id := *f.Observation.StartupIdentity
	k.process.Pid = id.PID
	k.bound = id
	pid, ticks := id.PID, id.StartTicks
	k.observedPID = &pid
	k.observedTicks = &ticks
	k.input.commit = id.SourceCommit
	k.input.binaryHash = id.ELFSHA256
	k.input.binaryBytes = id.ELFBytes
	seal, err := labRecoveryStartedSeal(k, id)
	if err != nil {
		t.Fatal("STRUCTURE MODEL retained startup")
	}
	i := &labRecoveryStartedIssuer{claimed: map[*labRecoveryStartCore]bool{}, issued: map[*labRecoveryStartedEpochCore]bool{}}
	x := &labRecoveryStartedEpochCore{issuer: i, owner: k, seal: seal, nonce: [32]byte{1}, fact: f}
	i.issued[x] = true // private MODEL assembly, never a production DTO factory
	return &labRecoveryStartedEpoch{core: x}, b, now
}

// STRUCTURE MODEL ONLY. Derive a fresh, canonical unowned V3 fixture from
// the existing model's original legacy bytes and source-selected ports. The
// short lease is issued through acquireRecoveryOwner, never by rewriting an
// already-open store or its private validation image. Every subsequent state
// uses the real structural transition's write/readback path; no native action
// or authenticated authority is created by this helper.
func labRecoveryStartedShortLeaseQuiescedModel(t *testing.T) (*lifecycleRecoveryStore, *lifecycleModelDisk, *lifecycleRecoveryOwnerToken, time.Time) {
	t.Helper()
	seed, _, _, plan, identity, now := lifecycleRecoveryStopModel(t)
	r, err := buildLifecycleV3Evolution(seed.core.record.core.SourceV2.ControlBytes, &plan, now)
	if err != nil {
		t.Fatal("MODEL fresh unowned evolution")
	}
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL fresh unowned canonical bytes")
	}
	d := &lifecycleModelDisk{raw: append([]byte(nil), raw...), exists: true, state: lifecycleCommitted}
	s, err := openLifecycleRecoveryStore(d, now)
	if err != nil || d.writes != 0 {
		t.Fatal("MODEL fresh strict open")
	}
	owner, err := s.acquireRecoveryOwner(now, now.Add(time.Millisecond))
	if err != nil || d.writes != 1 || !s.core.record.core.RecoveryOwner.ExpiresAt.Equal(now.Add(time.Millisecond)) {
		t.Fatal("MODEL actual short owner issuance")
	}
	if s.beginRecovery(owner, &plan, s.core.record.core.Revision, s.core.record.core.RecordSHA256, now) != nil || d.writes != 2 {
		t.Fatal("MODEL short owner plan transition")
	}
	approval, err := newLifecycleRecoveryApproval(&plan, "MODEL_independent_approver", now, now.Add(time.Minute))
	if err != nil || s.recordRecoveryApproval(owner, approval, now) != nil || d.writes != 3 {
		t.Fatal("MODEL short owner approval transition")
	}
	binding, err := s.armRecoveryStop(owner, identity, now)
	if err != nil || d.writes != 4 {
		t.Fatal("MODEL short owner stop transition")
	}
	fact := lifecycleRecoveryModelFact(binding, now)
	if !labQuiescenceFactValid(fact, binding, now) || s.recordRecoveryQuiescence(owner, lifecycleRecoveryIssuedModel(t, binding, fact), now) != nil || d.writes != 5 {
		t.Fatal("MODEL short owner actual once fact transition")
	}
	base, err := s.core.verifiedBase()
	if err != nil {
		t.Fatal("MODEL short owner actual verified post-readback state")
	}
	base.release()
	return s, d, owner, now
}

func TestLabRecoveryStartedInputMustMatchOriginalKernelCustody(t *testing.T) {
	b, _, _ := labRecoveryStartedModel(t)
	in := &labKernelInput{&labKernelInputCore{commit: b.ExpectedOldIdentity.SourceCommit, binaryHash: b.ExpectedOldIdentity.ELFSHA256, binaryBytes: b.ExpectedOldIdentity.ELFBytes}}
	if !labRecoveryStartedInputMatches(in, b) {
		t.Fatal("MODEL input match")
	}
	for _, mutate := range []func(*labKernelInputCore){func(v *labKernelInputCore) { v.commit = "" }, func(v *labKernelInputCore) { v.binaryHash = "" }, func(v *labKernelInputCore) { v.binaryBytes++ }} {
		copy := *in.labKernelInputCore
		mutate(&copy)
		if labRecoveryStartedInputMatches(&labKernelInput{&copy}, b) {
			t.Fatal("MODEL mismatched input")
		}
	}
	if labRecoveryStartedInputMatches(nil, b) || labRecoveryStartedInputMatches(&labKernelInput{}, b) {
		t.Fatal("MODEL empty input")
	}
}

func TestLabRecoveryStartedEntryCanceledContextDoesNotConsumeOrInvokeStart(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var typedNil *labQuiescenceNilContext
	for _, ctx := range []context.Context{nil, typedNil, canceled} {
		s, _, owner, now := lifecycleRecoveryModelQuiesced(t)
		p, err := s.armRecoveryStart(owner, now)
		if err != nil {
			t.Fatal("MODEL arm")
		}
		k, q, o, err := startOwnedRecoveryKernel(ctx, &labKernelInput{&labKernelInputCore{}}, &ArtifactStore{}, p)
		if err == nil || k != nil || q != nil || o.PermitConsumed || o.StartInvoked || o.StartReturned || o.StartObservation != nil || o.StartedAt != nil || o.ReturnedAt != nil {
			t.Fatal("MODEL rejected entry invented native action")
		}
		if _, err := p.consumeRecoveryStart(now); err != nil {
			t.Fatal("MODEL rejected context consumed real permit")
		}
	}
}

func TestLabRecoveryStartedBindingComesFromConsumedCurrentWAL(t *testing.T) {
	s, _, owner, now := lifecycleRecoveryModelQuiesced(t)
	p, err := s.armRecoveryStart(owner, now)
	if err != nil {
		t.Fatal("MODEL arm")
	}
	if _, err := labRecoveryStartedBindingFromPermit(p, p.core.fact, now); err == nil {
		t.Fatal("MODEL unconsumed permit source")
	}
	f, err := p.consumeRecoveryStart(now)
	if err != nil {
		t.Fatal("MODEL consume")
	}
	b, err := labRecoveryStartedBindingFromPermit(p, f, now)
	if err != nil || !reflect.DeepEqual(b.TargetArtifact, s.core.record.core.Recovery.Plan.TargetArtifact) || b.ExpectedOldIdentity != s.core.record.core.Recovery.Quiescence.Binding.ExpectedOldIdentity || b.StartMillis != 10000 {
		t.Fatal("MODEL actual WAL projection")
	}
	f.TargetArtifact.Config.Capabilities = nil
	if _, err := labRecoveryStartedBindingFromPermit(p, f, now); err == nil {
		t.Fatal("MODEL substituted full artifact")
	}
	if _, err := p.consumeRecoveryStart(now); err == nil {
		t.Fatal("MODEL permit replay")
	}
	if _, err := labRecoveryStartedBindingFromPermit(p, p.core.fact, now.Add(11*time.Second)); err == nil {
		t.Fatal("MODEL expired start budget")
	}
	for _, kind := range []string{"revokedDuringPreparation", "ownerExpiredDuringPreparation", "casChangedDuringPreparation", "ownerLostDuringPreparation", "initialBindingChanged"} {
		t.Run(kind, func(t *testing.T) {
			var s *lifecycleRecoveryStore
			var d *lifecycleModelDisk
			var owner *lifecycleRecoveryOwnerToken
			var now time.Time
			if kind == "ownerExpiredDuringPreparation" {
				s, d, owner, now = labRecoveryStartedShortLeaseQuiescedModel(t)
			} else {
				s, d, owner, now = lifecycleRecoveryModelQuiesced(t)
			}
			p, err := s.armRecoveryStart(owner, now)
			if err != nil {
				t.Fatal("MODEL fresh permit")
			}
			f, err := p.consumeRecoveryStart(now)
			if err != nil {
				t.Fatal("MODEL first actual consumption")
			}
			initial, err := labRecoveryStartedBindingFromPermit(p, f, now)
			if err != nil {
				t.Fatal("MODEL initial verified binding")
			}
			if labRecoveryStartedFinalGate(p, f, initial, now) != nil {
				t.Fatal("MODEL unchanged current final gate")
			}
			at := now.Add(2 * time.Millisecond)
			if !labRecoveryStartedBindingValid(initial, at) || !at.Before(s.core.record.core.Recovery.Approval.ExpiresAt) {
				t.Fatal("MODEL target final gate masked by unrelated expiry")
			}
			switch kind {
			case "revokedDuringPreparation":
				if s.revokeRecovery(owner, "MODEL_current_revoker", "EXPLICIT_REVOKED", at) != nil {
					t.Fatal("MODEL actual durable revocation")
				}
			case "casChangedDuringPreparation":
				s.core.mu.Lock()
				next, copyErr := s.core.copyRecord()
				var commitErr error
				if copyErr == nil {
					commitErr = s.core.commit(next, at)
				}
				s.core.mu.Unlock()
				if copyErr != nil || commitErr != nil || s.core.record.core.Revision == f.Revision || s.core.record.core.RecordSHA256 == f.RecordSHA256 {
					t.Fatal("MODEL actual canonical CAS commit")
				}
			case "ownerLostDuringPreparation":
				s.core.live = nil
			case "initialBindingChanged":
				initial.ExpectedOldIdentity.StartTicks++
			case "ownerExpiredDuringPreparation":
				if at.Before(s.core.record.core.RecoveryOwner.ExpiresAt) || s.core.record.core.Revision != f.Revision || s.core.record.core.Recovery.Revocation != nil {
					t.Fatal("MODEL expiry case not isolated")
				}
				if s.core.verify() != nil || s.core.poisoned {
					t.Fatal("MODEL expiry fixture rejected by earlier actual-WAL validation")
				}
			}
			before := d.writes
			if labRecoveryStartedFinalGate(p, f, initial, at) == nil {
				t.Fatal("MODEL changed preparation state admitted final Start gate")
			}
			if d.writes != before || s.core.permit != nil {
				t.Fatal("MODEL final gate wrote state or minted permit")
			}
			if kind == "ownerExpiredDuringPreparation" && s.core.poisoned {
				t.Fatal("MODEL owner expiry hidden by earlier poisoned-store gate")
			}
			if _, err := p.consumeRecoveryStart(at); err == nil {
				t.Fatal("MODEL rejected final gate revived consumed permit")
			}
			// No native function is invoked in this model. The production entry
			// returns STATE_REJECTED before its one original Start call site.
		})
	}
}

func TestLabRecoveryStartedIssuerClaimsArePermanentAndBounded(t *testing.T) {
	i := &labRecoveryStartedIssuer{claimed: map[*labRecoveryStartCore]bool{}, issued: map[*labRecoveryStartedEpochCore]bool{}}
	if i.claim(nil) {
		t.Fatal("MODEL nil claim")
	}
	for n := 0; n < maxLabRecoveryStartedClaims; n++ {
		p := &labRecoveryStartCore{fence: uint64(n + 1)}
		if !i.claim(p) || i.claim(p) {
			t.Fatal("MODEL claim replay")
		}
	}
	if i.claim(&labRecoveryStartCore{}) {
		t.Fatal("MODEL unbounded issuance")
	}
}

func TestLabRecoveryStartedRecordOnlyRetainsNaturalExitAndLateFact(t *testing.T) {
	q, b, now := labRecoveryStartedIssuedModel(t)
	// The MODEL original handle is closed/Wait-returned, so record-only cannot
	// accidentally rely on identity(), which rejects before native I/O.
	if _, err := q.core.owner.identity(); err == nil {
		t.Fatal("MODEL should be naturally exited")
	}
	f, err := q.consumeStartedEpochForRecord(b, now.Add(24*time.Hour))
	if err != nil || !f.ObservedAt.Equal(now) || !labRecoveryStartedFactValid(f, b, now.Add(24*time.Hour)) {
		t.Fatal("MODEL late source fact lost")
	}
	if _, err := q.consumeStartedEpochForRecord(b, now); err == nil {
		t.Fatal("MODEL record replay")
	}
}

func TestLabRecoveryStartedCopiesAndConcurrentConsumersShareOneEntry(t *testing.T) {
	q, b, now := labRecoveryStartedIssuedModel(t)
	copy := *q
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for _, cap := range []*labRecoveryStartedEpoch{q, &copy} {
		wg.Add(1)
		go func(cap *labRecoveryStartedEpoch) {
			defer wg.Done()
			f, err := cap.consumeStartedEpochForRecord(b, now)
			if err == nil {
				mu.Lock()
				success++
				mu.Unlock()
				f.Binding.TargetArtifact.Config.Capabilities[0] = "MODEL_mutated_return"
			}
		}(cap)
	}
	wg.Wait()
	if success != 1 || !labRecoveryStartedFactValid(q.core.fact, b, now) {
		t.Fatal("MODEL alias replay or detached result")
	}
}

func TestLabRecoveryStartedBadRecordAttemptSpendsAndCannotRevive(t *testing.T) {
	for _, kind := range []string{"clock", "zeroClock", "zone", "binding", "nonce", "digest", "process", "owner", "seal"} {
		t.Run(kind, func(t *testing.T) {
			q, b, now := labRecoveryStartedIssuedModel(t)
			copy := *q
			at := now
			bad := labRecoveryStartedCloneBinding(b)
			switch kind {
			case "clock":
				at = now.Add(-time.Nanosecond)
			case "zeroClock":
				at = time.Time{}
			case "zone":
				at = now.In(time.FixedZone("notUTC", 0))
			case "binding":
				bad.Revision++
			case "nonce":
				q.core.nonce = [32]byte{}
			case "digest":
				q.core.fact.StartedSHA256 = "bad"
			case "process":
				q.core.owner.process = &os.Process{Pid: q.core.seal.identity.PID}
			case "owner":
				q.core.owner = &ownedLabKernel{}
			case "seal":
				q.core.seal = nil
			}
			if _, err := q.consumeStartedEpochForRecord(bad, at); err == nil {
				t.Fatal("MODEL invalid record admitted")
			}
			if _, err := copy.consumeStartedEpochForRecord(b, now); err == nil {
				t.Fatal("MODEL failed attempt revived")
			}
		})
	}
}

func TestLabRecoveryStartedStrictFreshnessCannotFallBackAfterSpend(t *testing.T) {
	for _, late := range []bool{false, true} {
		q, b, now := labRecoveryStartedIssuedModel(t)
		copy := *q
		at := now
		if late {
			at = now.Add(31 * time.Second)
		} // short-circuits before any fake native observation
		if _, err := q.consumeStartedEpoch(b, at); err == nil {
			t.Fatal("MODEL strict consumed expired or exited epoch")
		}
		if _, err := copy.consumeStartedEpochForRecord(b, now); err == nil {
			t.Fatal("MODEL strict failure replayed into record-only")
		}
	}
}

func TestLabRecoveryStartedForeignRegistryAndJSONAreNotIssuers(t *testing.T) {
	q, b, now := labRecoveryStartedIssuedModel(t)
	forgedCore := *q.core
	forged := &labRecoveryStartedEpoch{core: &forgedCore}
	if _, err := forged.consumeStartedEpochForRecord(b, now); err == nil {
		t.Fatal("MODEL copied core acquired registry membership")
	}
	raw, err := json.Marshal(q.core.fact)
	if err != nil {
		t.Fatal("MODEL JSON")
	}
	var restored labRecoveryStartedEpoch
	if json.Unmarshal(raw, &restored) == nil || restored.core != nil {
		t.Fatal("MODEL facts recreated issued cap")
	}
	if _, err := q.consumeStartedEpochForRecord(b, now); err != nil {
		t.Fatal("MODEL foreign request spent actual entry")
	}
}
