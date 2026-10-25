package mihomodeploy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// MODEL ONLY: this constructs one structural recovered ledger. It issues no
// Completion, runtime handoff, owner token, or permission to touch a real disk.
func lifecycleCurrentEpochModel(t *testing.T) *lifecycleV3Wire {
	t.Helper()
	r, plan, _, _ := lifecycleV3Model(t)
	w := r.core
	l := w.Current
	previous := l.Head.HeadSHA256
	l.Head.Generation++
	l.Head.PreviousHeadSHA256 = &previous
	var err error
	l.Head.HeadSHA256, err = lifecycleHeadHash(l.Head)
	if err != nil {
		t.Fatal(err)
	}
	id := plan.core.descriptor.RecoveryID
	l.Anchor = lifecycleEpochAnchor{Kind: "RECOVERED_EPOCH", InitialHead: l.Head, RecoveryID: &id,
		SourceControlSHA256: w.SourceV2.ControlSHA256}
	l.Active = nil
	l.Tombstones = []lifecycleTombstone{}
	l.Completed = []lifecycleCompletion{}
	l.Terminated = []lifecycleTerminalArchive{}
	l.Observations = []lifecycleObservationRecord{}
	w.Current = l
	if validateLifecycleEpochLedger(l, w.LastTrustedAt, w.Revision) != nil {
		t.Fatal("MODEL recovered ledger invalid")
	}
	return w
}

func TestLifecycleCurrentEpochProjectionDoesNotRelaxLegacyGenesis(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	r, raw, err := lifecycleCurrentProjection(w)
	if err != nil || r.wire == nil || r.wire.Head.Generation < 2 {
		t.Fatal("MODEL recovered projection unavailable", err)
	}
	if _, err := decodeLifecycleRecord(raw); err == nil {
		t.Fatal("MODEL recovered projection bypassed unchanged legacy genesis")
	}
	l, err := lifecycleCurrentLedgerFromProjection(r.wire, w.Current.Anchor)
	if err != nil || !reflect.DeepEqual(l, w.Current) {
		t.Fatal("MODEL explicit epoch roundtrip lost source ledger", err)
	}
}

func TestLifecycleCurrentEpochProjectionDetachesNestedMutableState(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	before, _ := json.Marshal(w)
	r, raw, err := lifecycleCurrentProjection(w)
	if err != nil || r.wire.Owner == nil || r.wire.Head.PreviousHeadSHA256 == nil {
		t.Fatal("MODEL projection", err)
	}
	r.wire.Owner.OwnerNonce = strings.Repeat("a", 64)
	*r.wire.Head.PreviousHeadSHA256 = strings.Repeat("b", 64)
	r.wire.Head.PID++
	r.wire.V2.Completed = append(r.wire.V2.Completed, lifecycleCompletion{})
	raw[0] = '!'
	after, _ := json.Marshal(w)
	if string(before) != string(after) {
		t.Fatal("MODEL projection aliased source ledger")
	}
	second, secondRaw, err := lifecycleCurrentProjection(w)
	if err != nil || second.wire.Head.PID != w.Current.Head.PID || secondRaw[0] != '{' {
		t.Fatal("MODEL previous consumer corrupted later projection")
	}
}

func TestLifecycleCurrentEpochLedgerRejectsResealedCorruptProjection(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	for _, kind := range []string{"nil-head", "nil-v2", "foreign-schema", "nil-tombstones", "head-chain", "bad-fence", "digest"} {
		t.Run(kind, func(t *testing.T) {
			r, _, err := lifecycleCurrentProjection(w)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "nil-head": r.wire.Head = nil
			case "nil-v2": r.wire.V2 = nil
			case "foreign-schema": r.wire.Schema = lifecycleSchema
			case "nil-tombstones": r.wire.Tombstones = nil
			case "head-chain": r.wire.Head.Generation++
			case "bad-fence": r.wire.LastFence++
			}
			r.wire.RecordSHA256, _ = lifecycleRecordHash(*r.wire)
			if kind == "digest" { r.wire.RecordSHA256 = strings.Repeat("f", 64) }
			if _, err := lifecycleCurrentLedgerFromProjection(r.wire, w.Current.Anchor); err == nil {
				t.Fatal("MODEL corrupt projection accepted after outer reseal")
			}
		})
	}
}

func TestLifecycleCurrentEpochMutationRejectsOwnerAndRevisionBypass(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	old, _, err := lifecycleCurrentProjection(w)
	if err != nil || old.wire.Owner == nil { t.Fatal("MODEL owner missing", err) }
	now := w.LastTrustedAt.Add(time.Second)
	for _, kind := range []string{"valid-renew", "revision", "clock", "nonce", "fence-jump", "early-takeover", "owner-nil", "foreign-provisioning", "head-replacement"} {
		t.Run(kind, func(t *testing.T) {
			next, _, err := lifecycleCurrentProjection(w)
			if err != nil { t.Fatal(err) }
			next.wire.Revision++
			next.wire.LastTrustedAt = now
			next.wire.Owner.RenewedAt = now
			next.wire.Owner.ExpiresAt = next.wire.Owner.ExpiresAt.Add(time.Second)
			switch kind {
			case "revision": next.wire.Revision++
			case "clock": next.wire.LastTrustedAt = w.LastTrustedAt.Add(-time.Second)
			case "nonce": next.wire.Owner.OwnerNonce = strings.Repeat("c", 64)
			case "fence-jump": next.wire.LastFence += 2
			case "early-takeover":
				next.wire.LastFence++
				next.wire.Owner.Fence++
				next.wire.Owner.AcquiredAt = now
			case "owner-nil": next.wire.Owner = nil
			case "foreign-provisioning": next.wire.V2.Provisioning.RuntimeID = "foreign"
			case "head-replacement": next.wire.Head.PID++
			}
			accepted := lifecycleCurrentMutationValid(old.wire, next.wire, now, lifecycleNoNewEvidence)
			if accepted != (kind == "valid-renew") {
				t.Fatalf("MODEL mutation acceptance %v", accepted)
			}
		})
	}
}

func TestLifecycleCurrentEpochGenericCandidateCannotIssuePublication(t *testing.T) {
	x := &lifecycleRecoveryStoreCore{}
	if x.currentEpochTransition(nil, lifecycleV3Record{}) {
		t.Fatal("MODEL unissued publication accepted")
	}
	x.currentPublication = &lifecycleCurrentEpochPublication{canonical: "caller digest"}
	if x.currentEpochTransition(&lifecycleVerifiedBase{}, lifecycleV3Record{}) {
		t.Fatal("MODEL DTO publication accepted")
	}
	if _, _, err := adoptLifecycleCurrentEpoch(nil, nil); err == nil {
		t.Fatal("MODEL nil handoff issued writer")
	}
}

// MODEL ONLY: this assembles the minimum already-issued in-memory identities
// needed to test facade binding. It creates no completion capability and makes
// no disk publication.
func lifecycleCurrentEpochBindingModel(t *testing.T) (*lifecycleStore, *lifecycleRecoveryStoreCore, *lifecycleCurrentEpochBackend) {
	t.Helper()
	w := lifecycleCurrentEpochModel(t)
	if w.Recovery == nil || w.Current.Owner == nil {
		t.Fatal("MODEL recovery/owner missing")
	}
	w.Recovery.Phase = "COMPLETED"
	w.RecoveryHistory = []lifecycleRecoveryTxn{*w.Recovery}
	id := w.Recovery.Plan.RecoveryID
	w.Current.Anchor.RecoveryID = &id
	r, raw, err := lifecycleCurrentProjection(w)
	if err != nil {
		t.Fatal("MODEL projection", err)
	}
	disk := &lifecycleModelDisk{}
	x := &lifecycleRecoveryStoreCore{disk: disk, record: lifecycleV3Record{core: w}}
	s := &lifecycleStore{lifecycleStoreCore: &lifecycleStoreCore{mu: &x.mu, disk: disk, record: r, raw: raw}}
	anchor, err := lifecycleHash(w.Current.Anchor)
	if err != nil {
		t.Fatal("MODEL anchor", err)
	}
	token := &lifecycleRecoveryCurrentOwnerCore{store: x, epochIndex: uint64(len(w.RetiredEpochs)), anchorSHA256: anchor,
		nonce: w.Current.Owner.OwnerNonce, fence: w.Current.Owner.Fence}
	b := &lifecycleCurrentEpochBackend{store: x, token: token, projection: s}
	b.identity = b
	s.currentEpoch = b
	x.currentLive = token
	b.binding = func(candidate *lifecycleCurrentEpochBackend) bool {
		return candidate == b && candidate.identity == b && candidate.store == x && candidate.token == token &&
			candidate.projection == s && s.currentEpoch == candidate && s.mu == &x.mu && lifecycleRecoverySameDisk(s.disk, x.disk)
	}
	return s, x, b
}

func TestLifecycleCurrentEpochNilHandoffRejectsBeforeRecoveryMutation(t *testing.T) {
	live := &lifecycleRecoveryCurrentOwnerCore{}
	x := &lifecycleRecoveryStoreCore{currentLive: live}
	if _, _, err := adoptLifecycleCurrentEpoch(nil, &lifecycleRecoveryStore{core: x}); err == nil || x.currentLive != live || x.poisoned {
		t.Fatal("MODEL nil handoff reached or mutated recovery custody")
	}
}

func TestLifecycleCurrentEpochCopiedReceiverCannotUseOrRetireBackend(t *testing.T) {
	s, x, _ := lifecycleCurrentEpochBindingModel(t)
	if _, err := s.currentEpochBinding(); err != nil {
		t.Fatal("MODEL original projection lost binding", err)
	}
	wrapperCopy := *s
	forgedWrapper := &wrapperCopy
	if _, err := forgedWrapper.currentEpochBinding(); err == nil {
		t.Fatal("MODEL copied wrapper retained backend binding")
	}
	coreCopy := *s.lifecycleStoreCore
	forgedCore := &lifecycleStore{lifecycleStoreCore: &coreCopy}
	live := x.currentLive
	if _, err := forgedCore.currentEpochBinding(); err == nil || forgedCore.retireCurrentEpoch() == nil || x.currentLive != live {
		t.Fatal("MODEL copied core used or retired real backend")
	}
}

func TestLifecycleCurrentEpochRollbackPoisonsBothStoresPermanently(t *testing.T) {
	s, x, b := lifecycleCurrentEpochBindingModel(t)
	s.live = &lifecycleOwnerToken{lifecycleOwnerCore: &lifecycleOwnerCore{store: s}}
	x.currentPublication = &lifecycleCurrentEpochPublication{}
	x.validated = &lifecycleValidatedSnapshot{}
	rollback := s.record.wire.LastTrustedAt.Add(-time.Nanosecond)
	if s.trustedCurrentEpoch(b, rollback) == nil || !s.poisoned || s.live != nil || !x.poisoned ||
		x.currentLive != nil || x.currentPublication != nil || x.validated != nil {
		t.Fatal("MODEL rollback did not irreversibly poison both store views")
	}
	if _, err := s.currentEpochBinding(); err == nil {
		t.Fatal("MODEL poisoned current epoch recovered its binding")
	}
}

func TestLifecycleV3GlobalBudgetCountsEveryEpochAndUniqueRecovery(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	w.Recovery = nil
	w.RecoveryHistory = make([]lifecycleRecoveryTxn, 100)
	w.RetiredEpochs = []lifecycleRetiredEpoch{{Ledger: lifecycleEpochLedger{
		Completed: make([]lifecycleCompletion, 50), Terminated: make([]lifecycleTerminalArchive, 50),
		Observations: make([]lifecycleObservationRecord, 100),
	}}}
	w.Current.Completed = make([]lifecycleCompletion, 55)
	w.Current.Terminated = []lifecycleTerminalArchive{}
	w.Current.Observations = make([]lifecycleObservationRecord, 155)
	history, observations, ok := lifecycleV3GlobalBudget(w)
	if !ok || history != 255 || observations != 255 {
		t.Fatalf("MODEL 255 budget mismatch history=%d observations=%d", history, observations)
	}
	w.Current.Terminated = append(w.Current.Terminated, lifecycleTerminalArchive{})
	w.Current.Observations = append(w.Current.Observations, lifecycleObservationRecord{})
	history, observations, ok = lifecycleV3GlobalBudget(w)
	if !ok || history != 256 || observations != 256 {
		t.Fatalf("MODEL 256 budget mismatch history=%d observations=%d", history, observations)
	}
	w.Recovery = &lifecycleRecoveryTxn{Plan: labRecoveryPlanDescriptor{RecoveryID: "MODEL-UNARCHIVED"}}
	history, observations, ok = lifecycleV3GlobalBudget(w)
	if !ok || history != 257 || observations != 256 {
		t.Fatalf("MODEL unique Recovery branch missing history=%d observations=%d", history, observations)
	}
}

func TestLifecycleCurrentEpochObservationCapacityCountsRetiredEpochs(t *testing.T) {
	s, x, b := lifecycleCurrentEpochBindingModel(t)
	x.record.core.RetiredEpochs = append(x.record.core.RetiredEpochs, lifecycleRetiredEpoch{Ledger: lifecycleEpochLedger{
		Observations: make([]lifecycleObservationRecord, maxLifecycleHistory),
	}})
	b.token.epochIndex = uint64(len(x.record.core.RetiredEpochs))
	if err := s.currentEpochObservationCapacity(s.record.wire.LastTrustedAt); err == nil {
		t.Fatal("MODEL retired observations did not exhaust global budget")
	}
}

func TestLifecycleCurrentEpochHandoffRequiresCompletedHistoryTail(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	if lifecycleCurrentHandoffHistoryPaired(w) || w.Recovery == nil {
		t.Fatal("MODEL uncompleted recovery paired with current epoch")
	}
	w.Recovery.Phase = "COMPLETED"
	w.RecoveryHistory = []lifecycleRecoveryTxn{*w.Recovery}
	id := w.Recovery.Plan.RecoveryID
	w.Current.Anchor.RecoveryID = &id
	if !lifecycleCurrentHandoffHistoryPaired(w) {
		t.Fatal("MODEL exact completed history tail not paired")
	}
	w.RecoveryHistory[0].UpdatedAt = w.RecoveryHistory[0].UpdatedAt.Add(time.Nanosecond)
	if lifecycleCurrentHandoffHistoryPaired(w) {
		t.Fatal("MODEL changed history tail remained paired")
	}
}

func TestLifecycleCurrentEpochReverseProjectionDetachesNestedState(t *testing.T) {
	w := lifecycleCurrentEpochModel(t)
	r, _, err := lifecycleCurrentProjection(w)
	if err != nil || r.wire.Head.PreviousHeadSHA256 == nil || r.wire.Owner == nil {
		t.Fatal("MODEL projection unavailable", err)
	}
	before, _ := json.Marshal(r.wire)
	ledger, err := lifecycleCurrentLedgerFromProjection(r.wire, w.Current.Anchor)
	if err != nil || ledger.Head.PreviousHeadSHA256 == nil || ledger.Owner == nil {
		t.Fatal("MODEL reverse projection unavailable", err)
	}
	*ledger.Head.PreviousHeadSHA256 = strings.Repeat("d", 64)
	ledger.Owner.OwnerNonce = strings.Repeat("e", 64)
	ledger.Completed = append(ledger.Completed, lifecycleCompletion{})
	after, _ := json.Marshal(r.wire)
	if string(before) != string(after) {
		t.Fatal("MODEL reverse projection aliased caller-owned state")
	}
}
