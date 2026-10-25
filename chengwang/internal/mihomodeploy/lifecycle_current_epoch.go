package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"
)

// This adapter reuses the ordinary journal's mutation guards without making a
// recovered epoch look like a persisted V2 genesis. Its projection is private
// memory only. Every actual publication remains a complete strict V3 record.
// The recovery runtime retains exclusive ownership of the real disk and Close.
type lifecycleCurrentEpochBackend struct {
	identity   *lifecycleCurrentEpochBackend
	store      *lifecycleRecoveryStoreCore
	token      *lifecycleRecoveryCurrentOwnerCore
	projection *lifecycleStore
	binding    func(*lifecycleCurrentEpochBackend) bool
}

// Only commitCurrentEpoch installs this proof, under the shared actual store
// mutex, after the unchanged ordinary commitTransition mutation guards pass.
// No decoded value or caller-supplied hash can issue a publication proof.
type lifecycleCurrentEpochPublication struct {
	base      *lifecycleVerifiedBaseCore
	backend   *lifecycleCurrentEpochBackend
	canonical string
	binding   func(*lifecycleCurrentEpochPublication, *lifecycleRecoveryStoreCore, *lifecycleVerifiedBaseCore) bool
}

func (lifecycleCurrentEpochBackend) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private current epoch adapter; not authorization")
}
func (lifecycleCurrentEpochBackend) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (*lifecycleCurrentEpochBackend) UnmarshalJSON([]byte) error  { return errLifecycleUnsafe }
func (lifecycleCurrentEpochPublication) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private current epoch publication; not authorization")
}
func (lifecycleCurrentEpochPublication) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (*lifecycleCurrentEpochPublication) UnmarshalJSON([]byte) error  { return errLifecycleUnsafe }

func lifecycleCurrentProjection(w *lifecycleV3Wire) (lifecycleRecord, []byte, error) {
	if w == nil || validateLifecycleEpochLedger(w.Current, w.LastTrustedAt, w.Revision) != nil {
		return lifecycleRecord{}, nil, errLifecycleUnsafe
	}
	l := w.Current
	projection := &lifecycleWire{Schema: lifecycleSchemaV2, Boundary: lifecycleBoundary,
		Revision: w.Revision, LastTrustedAt: w.LastTrustedAt, LastFence: l.LastFence,
		Head: &l.Head, Owner: l.Owner, Active: l.Active, Tombstones: l.Tombstones,
		V2: &lifecycleV2Wire{Provisioning: w.Provisioning, Completed: l.Completed,
			Observations: l.Observations, Terminated: l.Terminated}}
	var err error
	projection.RecordSHA256, err = lifecycleRecordHash(*projection)
	if err != nil {
		return lifecycleRecord{}, nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return lifecycleRecord{}, nil, errLifecycleUnsafe
	}
	// Detach every pointer and slice. This is deliberately not a call to the
	// old strict V2 decoder, whose genesis rule remains unchanged.
	var detached lifecycleWire
	if json.Unmarshal(raw, &detached) != nil {
		return lifecycleRecord{}, nil, errLifecycleUnsafe
	}
	return lifecycleRecord{wire: &detached}, raw, nil
}

func adoptLifecycleCurrentEpoch(h *lifecycleRecoveryCurrentHandoff, recovery *lifecycleRecoveryStore) (*lifecycleStore, *lifecycleOwnerToken, error) {
	if h == nil || recovery == nil || recovery.core == nil {
		return nil, nil, errLifecycleUnsafe
	}
	x := recovery.core
	issued, err := h.consumeCurrent(x)
	if err != nil || issued == nil || issued.core == nil {
		return nil, nil, errLifecycleUnsafe
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.verify() != nil || x.currentLive != issued.core || !lifecycleCurrentHandoffHistoryPaired(x.record.core) {
		x.poisoned = true
		x.currentLive = nil
		x.currentPublication = nil
		x.validated = nil
		return nil, nil, errLifecycleUnsafe
	}
	r, raw, err := lifecycleCurrentProjection(x.record.core)
	if err != nil {
		x.poisoned, x.currentLive = true, nil
		return nil, nil, err
	}
	s := &lifecycleStore{lifecycleStoreCore: &lifecycleStoreCore{mu: &x.mu, disk: x.disk, record: r, raw: raw}}
	b := &lifecycleCurrentEpochBackend{store: x, token: issued.core, projection: s}
	b.identity = b
	s.currentEpoch = b
	original := issued.core
	b.binding = func(candidate *lifecycleCurrentEpochBackend) bool {
		return candidate == b && candidate.identity == b && candidate.store == x && candidate.token == original &&
			candidate.projection == s && s.currentEpoch == candidate && s.mu == &x.mu && lifecycleRecoverySameDisk(s.disk, x.disk)
	}
	if err := s.verifyCurrentEpoch(); err != nil {
		x.poisoned, x.currentLive = true, nil
		return nil, nil, err
	}
	owner := &lifecycleOwnerToken{lifecycleOwnerCore: &lifecycleOwnerCore{store: s, nonce: original.nonce, fence: original.fence}}
	s.live = owner
	return s, owner, nil
}

// Caller holds exactly x.mu, also installed as the ordinary facade mutex.
func (s *lifecycleStore) currentEpochBinding() (*lifecycleCurrentEpochBackend, error) {
	if s == nil || s.lifecycleStoreCore == nil || s.closed || s.poisoned || s.currentEpoch == nil {
		return nil, errLifecycleUnsafe
	}
	b := s.currentEpoch
	if b.identity != b || b.projection != s || b.binding == nil || !b.binding(b) || b.store == nil || b.token == nil {
		return nil, errLifecycleUnsafe
	}
	x, token := b.store, b.token
	w := x.record.core
	if x.closed || x.poisoned || x.currentLive != token || w == nil || token.store != x || !lifecycleCurrentHandoffHistoryPaired(w) ||
		token.epochIndex != uint64(len(w.RetiredEpochs)) || w.Current.Anchor.Kind != "RECOVERED_EPOCH" ||
		w.Current.Owner == nil || w.Current.Owner.OwnerNonce != token.nonce || w.Current.Owner.Fence != token.fence || w.Current.LastFence != token.fence {
		return nil, errLifecycleUnsafe
	}
	anchor, err := lifecycleHash(w.Current.Anchor)
	if err != nil || anchor != token.anchorSHA256 {
		return nil, errLifecycleUnsafe
	}
	return b, nil
}

func (s *lifecycleStore) verifyCurrentEpoch() error {
	b, err := s.currentEpochBinding()
	if err != nil {
		return err
	}
	if err := b.store.verify(); err != nil {
		s.poisoned, s.live = true, nil
		return err
	}
	_, expected, err := lifecycleCurrentProjection(b.store.record.core)
	actual, marshalErr := json.Marshal(s.record.wire)
	if err != nil || marshalErr != nil || !bytes.Equal(expected, s.raw) || !bytes.Equal(actual, expected) {
		s.poisoned, s.live = true, nil
		b.store.poisoned, b.store.currentLive = true, nil
		return errLifecycleUnsafe
	}
	return nil
}

func (s *lifecycleStore) copyCurrentEpochProjection() (lifecycleRecord, error) {
	if err := s.verifyCurrentEpoch(); err != nil {
		return lifecycleRecord{}, err
	}
	r, _, err := lifecycleCurrentProjection(s.currentEpoch.store.record.core)
	return r, err
}

func lifecycleCurrentLedgerFromProjection(w *lifecycleWire, anchor lifecycleEpochAnchor) (lifecycleEpochLedger, error) {
	if w == nil || w.Schema != lifecycleSchemaV2 || w.Boundary != lifecycleBoundary || w.Head == nil || w.V2 == nil ||
		!lifecycleTime(w.LastTrustedAt) {
		return lifecycleEpochLedger{}, errLifecycleUnsafe
	}
	hash, err := lifecycleRecordHash(*w)
	if err != nil || hash != w.RecordSHA256 {
		return lifecycleEpochLedger{}, errLifecycleUnsafe
	}
	l := lifecycleEpochLedger{Anchor: anchor, Head: *w.Head, Owner: w.Owner, LastFence: w.LastFence,
		Active: w.Active, Tombstones: w.Tombstones, Completed: w.V2.Completed,
		Terminated: w.V2.Terminated, Observations: w.V2.Observations}
	if validateLifecycleEpochLedger(l, w.LastTrustedAt, w.Revision) != nil {
		return lifecycleEpochLedger{}, errLifecycleUnsafe
	}
	// The reverse adapter is also a custody boundary. Do not let a caller keep
	// aliases into the V3 draft through nested pointers, byte slices or history.
	raw, err := json.Marshal(l)
	if err != nil {
		return lifecycleEpochLedger{}, errLifecycleUnsafe
	}
	var detached lifecycleEpochLedger
	if json.Unmarshal(raw, &detached) != nil || validateLifecycleEpochLedger(detached, w.LastTrustedAt, w.Revision) != nil {
		return lifecycleEpochLedger{}, errLifecycleUnsafe
	}
	return detached, nil
}

func (s *lifecycleStore) commitCurrentEpoch(next lifecycleRecord, now time.Time, mode lifecycleEvidenceTransition) error {
	// This method is a private publication entrance in its own right. Bind the
	// old ordinary projection to the actual WAL before comparing any mutation;
	// a same-package caller must not substitute a fabricated old history.
	if err := s.verifyCurrentEpoch(); err != nil {
		return err
	}
	b, err := s.currentEpochBinding()
	if err != nil {
		return err
	}
	x := b.store
	if err := s.trustedCurrentEpoch(b, now); err != nil {
		return err
	}
	base, err := x.verifiedBase()
	if err != nil {
		return err
	}
	defer base.release()
	if next.wire == nil || x.record.core.Revision == ^uint64(0) || next.wire.Revision != x.record.core.Revision+1 ||
		!next.wire.LastTrustedAt.Equal(now) || next.wire.V2 == nil || next.wire.V2.Provisioning != x.record.core.Provisioning ||
		!lifecycleCurrentMutationValid(s.record.wire, next.wire, now, mode) {
		return errLifecycleUnsafe
	}
	ledger, err := lifecycleCurrentLedgerFromProjection(next.wire, x.record.core.Current.Anchor)
	if err != nil {
		return err
	}
	draft, err := base.copyRecord()
	if err != nil {
		return err
	}
	draft.core.Current = ledger
	canonical, err := json.Marshal(draft.core)
	if err != nil {
		return errLifecycleUnsafe
	}
	proof := &lifecycleCurrentEpochPublication{base: base.core, backend: b, canonical: string(canonical)}
	proof.binding = func(candidate *lifecycleCurrentEpochPublication, owner *lifecycleRecoveryStoreCore, issued *lifecycleVerifiedBaseCore) bool {
		return candidate == proof && owner == x && issued == base.core && candidate.base == issued &&
			candidate.backend == b && candidate.canonical == string(canonical) && x.currentLive == b.token
	}
	x.currentPublication = proof
	defer func() { x.currentPublication = nil }()
	if err := x.commitWithBase(base, draft, now); err != nil {
		// No ambiguous publication can keep a usable owner/projection alive.
		s.poisoned, s.live = true, nil
		x.poisoned, x.currentLive = true, nil
		return err
	}
	// Only exact successful V3 readback may update the in-memory projection.
	r, raw, err := lifecycleCurrentProjection(x.record.core)
	if err != nil {
		s.poisoned, s.live = true, nil
		x.poisoned, x.currentLive = true, nil
		return errLifecycleUnsafe
	}
	s.record, s.raw = r, raw
	b.token.nonce, b.token.fence = r.wire.Owner.OwnerNonce, r.wire.LastFence
	return nil
}

func (s *lifecycleStore) trustedCurrentEpoch(b *lifecycleCurrentEpochBackend, now time.Time) error {
	if b == nil || b.store == nil {
		return errLifecycleUnsafe
	}
	if err := s.trustedNow(now); err != nil {
		// A rollback/invalid trusted clock poisons both views of the same WAL.
		// Clearing every ephemeral publication/owner cache prevents recovery by
		// retaining an already issued current-epoch capability.
		x := b.store
		x.poisoned = true
		x.currentLive = nil
		x.currentPublication = nil
		x.validated = nil
		return err
	}
	return nil
}

// Recheck the ordinary mutation invariants at this private publication entrance
// as well. Calling commitCurrentEpoch directly cannot bypass commitTransition.
// Legacy commitTransition retains its original checks and wire representation.
func lifecycleCurrentMutationValid(old, next *lifecycleWire, now time.Time, mode lifecycleEvidenceTransition) bool {
	if old == nil || next == nil || old.Schema != lifecycleSchemaV2 || next.Schema != lifecycleSchemaV2 ||
		old.V2 == nil || next.V2 == nil || !lifecycleTime(now) || now.Before(old.LastTrustedAt) ||
		old.Revision == ^uint64(0) || next.Revision != old.Revision+1 || !next.LastTrustedAt.Equal(now) {
		return false
	}
	if mode == lifecycleAppendCompletion && (len(next.V2.Completed) == 0 || !next.V2.Completed[len(next.V2.Completed)-1].CommittedAt.Equal(now)) {
		return false
	}
	if mode == lifecycleAppendTermination && (len(next.V2.Terminated) == 0 || !next.V2.Terminated[len(next.V2.Terminated)-1].CommittedAt.Equal(now)) {
		return false
	}
	if next.Active != nil && ((next.Active.Phase == "DISPATCH_ARMED" && old.Revision > ^uint64(0)-3) ||
		(next.Active.Phase == "ACKNOWLEDGED" && old.Revision > ^uint64(0)-2)) {
		return false
	}
	if !lifecycleV2Transition(old, next, mode) || len(next.Tombstones) < len(old.Tombstones) ||
		!reflect.DeepEqual(next.Tombstones[:len(old.Tombstones)], old.Tombstones) {
		return false
	}
	if next.LastFence != old.LastFence && (old.LastFence == ^uint64(0) || next.LastFence != old.LastFence+1) {
		return false
	}
	if next.LastFence == old.LastFence {
		if (old.Owner == nil) != (next.Owner == nil) {
			return false
		}
		if old.Owner != nil && (next.Owner.OwnerNonce != old.Owner.OwnerNonce || next.Owner.Fence != old.Owner.Fence ||
			!next.Owner.AcquiredAt.Equal(old.Owner.AcquiredAt) || next.Owner.RenewedAt.Before(old.Owner.RenewedAt) || next.Owner.ExpiresAt.Before(old.Owner.ExpiresAt)) {
			return false
		}
	} else if next.Owner == nil || (old.Owner != nil && now.Before(old.Owner.ExpiresAt)) ||
		!next.Owner.AcquiredAt.Equal(now) || !next.Owner.RenewedAt.Equal(now) {
		return false
	}
	if old.Active != nil && next.Active != nil && old.Active.Plan.PlanSHA256 == next.Active.Plan.PlanSHA256 {
		a, b := old.Active, next.Active
		if !lifecyclePhaseTransition(a.Phase, b.Phase) || !reflect.DeepEqual(a.Plan, b.Plan) || b.Attempt < a.Attempt ||
			(a.Intent != nil && !reflect.DeepEqual(a.Intent, b.Intent)) || (a.Result != nil && !reflect.DeepEqual(a.Result, b.Result)) ||
			(a.Approval != nil && !reflect.DeepEqual(a.Approval, b.Approval)) || len(b.AuditProjection) < len(a.AuditProjection) ||
			!reflect.DeepEqual(b.AuditProjection[:len(a.AuditProjection)], a.AuditProjection) {
			return false
		}
		if a.Revocation != nil && (b.Revocation == nil || b.Revocation.Revision < a.Revocation.Revision ||
			(b.Revocation.Revision == a.Revocation.Revision && !reflect.DeepEqual(a.Revocation, b.Revocation))) {
			return false
		}
	} else if old.Active != nil && !lifecycleTerminal(old.Active.Phase) {
		return false
	}
	if next.Active != nil && (old.Active == nil || old.Active.Plan.PlanSHA256 != next.Active.Plan.PlanSHA256) {
		for _, tombstone := range old.Tombstones {
			if tombstone.OperationID == next.Active.Plan.OperationID || tombstone.PlanSHA256 == next.Active.Plan.PlanSHA256 {
				return false
			}
		}
	}
	return true
}

func (x *lifecycleRecoveryStoreCore) currentEpochTransition(base *lifecycleVerifiedBase, next lifecycleV3Record) bool {
	p := x.currentPublication
	if p == nil || p.binding == nil || base == nil || !p.binding(p, x, base.core) || next.core == nil ||
		p.backend == nil || p.backend.store != x || x.currentLive != p.backend.token ||
		x.record.core == nil || next.core.Current.Anchor.Kind != "RECOVERED_EPOCH" ||
		!reflect.DeepEqual(next.core.Current.Anchor, x.record.core.Current.Anchor) {
		return false
	}
	canonical, err := json.Marshal(next.core)
	if err != nil || string(canonical) != p.canonical {
		return false
	}
	var projection lifecycleV3Wire
	if json.Unmarshal(canonical, &projection) != nil {
		return false
	}
	projection.Current = x.record.core.Current
	return reflect.DeepEqual(&projection, x.record.core)
}

// lifecycleCurrentHandoffHistoryPaired is a read-only structural postcondition
// for the A+B completion handoff. Full record verification remains authoritative;
// this predicate only states the additional C contract that the active completed
// recovery is exactly the tail archived by that completion and owns Current.
func lifecycleCurrentHandoffHistoryPaired(w *lifecycleV3Wire) bool {
	if w == nil || w.Recovery == nil || w.Recovery.Phase != "COMPLETED" || len(w.RecoveryHistory) == 0 ||
		w.Current.Anchor.Kind != "RECOVERED_EPOCH" || w.Current.Anchor.RecoveryID == nil {
		return false
	}
	tail := &w.RecoveryHistory[len(w.RecoveryHistory)-1]
	return tail.Phase == "COMPLETED" && tail.Plan.RecoveryID == *w.Current.Anchor.RecoveryID &&
		tail.Plan.RecoveryID == w.Recovery.Plan.RecoveryID && reflect.DeepEqual(tail, w.Recovery)
}

// lifecycleV3GlobalBudget is the pure C-side walk of the V3 validator's two
// global budgets. It deliberately counts an unarchived current Recovery once.
// The helper performs no validation and grants no capability.
func lifecycleV3GlobalBudget(w *lifecycleV3Wire) (history, observations int, ok bool) {
	if w == nil {
		return 0, 0, false
	}
	recoveryIDs := make(map[string]bool, len(w.RecoveryHistory))
	for i := range w.RecoveryHistory {
		a := &w.RecoveryHistory[i]
		recoveryIDs[a.Plan.RecoveryID] = true
		history++
		observations += len(a.FailedQuiescence)
	}
	if w.Recovery != nil && !recoveryIDs[w.Recovery.Plan.RecoveryID] {
		history++
		observations += len(w.Recovery.FailedQuiescence)
	}
	addLedger := func(l *lifecycleEpochLedger) {
		history += len(l.Completed) + len(l.Terminated)
		observations += len(l.Observations)
	}
	for i := range w.RetiredEpochs {
		addLedger(&w.RetiredEpochs[i].Ledger)
	}
	addLedger(&w.Current)
	return history, observations, true
}

func (s *lifecycleStore) currentEpochObservationCapacity(now time.Time) error {
	b, err := s.currentEpochBinding()
	if err != nil {
		return err
	}
	_, observations, ok := lifecycleV3GlobalBudget(b.store.record.core)
	if !ok || observations >= maxLifecycleHistory {
		return errLifecycleUnsafe
	}
	// The supplied raw byte count is the complete verified V3 WAL, not the
	// smaller V2-shaped projection. The ordinary conservative envelope is more
	// than one fixed-size observation and preserves the original revision room.
	return lifecycleReserveCapacity(s.record.wire, len(b.store.raw), now)
}

func (s *lifecycleStore) reserveCurrentEpochCapacity(now time.Time) error {
	b, err := s.currentEpochBinding()
	if err != nil {
		return err
	}
	w := b.store.record.core
	history, observations, ok := lifecycleV3GlobalBudget(w)
	if !ok || history >= maxLifecycleHistory || observations >= maxLifecycleHistory {
		return errLifecycleUnsafe
	}
	// The full WAL, not the smaller ephemeral projection, pays the reserve.
	return lifecycleReserveCapacity(s.record.wire, len(b.store.raw), now)
}

func (s *lifecycleStore) retireCurrentEpoch() error {
	if s == nil || s.lifecycleStoreCore == nil {
		return errLifecycleUnsafe
	}
	b := s.currentEpoch
	if b == nil || b.store == nil || b.projection != s || b.identity != b || b.binding == nil || !b.binding(b) {
		return errLifecycleUnsafe
	}
	if b.store.currentLive == b.token {
		b.store.currentLive = nil
	}
	// No close of the shared real disk: runtime.recovery remains its owner.
	return nil
}
