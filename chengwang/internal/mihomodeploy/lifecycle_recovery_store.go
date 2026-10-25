package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

type lifecycleRecoveryStore struct{ core *lifecycleRecoveryStoreCore }
type lifecycleRecoveryStoreCore struct {
	mu            sync.Mutex
	disk          lifecycleDisk
	record        lifecycleV3Record
	raw           []byte
	live          *lifecycleRecoveryOwnerCore
	quiescenceSHA string
	permit        *labRecoveryStartCore
	// Issuance identities only, scoped to one locked operation. They are
	// released on every exit and are never a cross-operation validation cache.
	activeBase     *lifecycleVerifiedBaseCore
	activePrepared *lifecyclePreparedCandidateCore
	// An exact, private canonical image already fully validated by open or a
	// successful publication. This is not an action/owner/approval capability.
	validated            *lifecycleValidatedSnapshot
	validationGeneration uint64
	poisoned, closed     bool
}

// Strings detach the trusted bytes from all mutable disk/raw/draft slices.
// The self identity rejects copied proof fields; the store binding prevents a
// proof from another store (including a shallow-copied core) being adopted.
// Only open's full decoder and publishPrepared's actual readback issue one.
type lifecycleValidatedSnapshot struct {
	store      *lifecycleRecoveryStoreCore
	identity   *lifecycleValidatedSnapshot
	canonical  string
	rawSHA256  string
	generation uint64
	binding    func(*lifecycleValidatedSnapshot, *lifecycleRecoveryStoreCore) bool
}

func (lifecycleValidatedSnapshot) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, lifecycleRecoveryDebug)
}
func (lifecycleValidatedSnapshot) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (*lifecycleValidatedSnapshot) UnmarshalJSON([]byte) error  { return errLifecycleUnsafe }

type lifecycleRecoveryOwnerToken struct{ core *lifecycleRecoveryOwnerCore }
type lifecycleRecoveryOwnerCore struct {
	store *lifecycleRecoveryStoreCore
	nonce string
	fence uint64
}

type lifecycleVerifiedBase struct{ core *lifecycleVerifiedBaseCore }
type lifecycleVerifiedBaseCore struct {
	store     *lifecycleRecoveryStoreCore
	raw       []byte
	rawSHA256 string
	record    lifecycleV3Record
	used      bool
}
type lifecyclePreparedCandidate struct {
	core *lifecyclePreparedCandidateCore
}
type lifecyclePreparedCandidateCore struct {
	store        *lifecycleRecoveryStoreCore
	base         *lifecycleVerifiedBaseCore
	before       []byte
	beforeSHA256 string
	raw          []byte
	rawSHA256    string
	record       lifecycleV3Record
}

func (lifecycleVerifiedBase) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, lifecycleRecoveryDebug)
}
func (lifecycleVerifiedBase) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (*lifecycleVerifiedBase) UnmarshalJSON([]byte) error  { return errLifecycleUnsafe }
func (lifecyclePreparedCandidate) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, lifecycleRecoveryDebug)
}
func (lifecyclePreparedCandidate) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (*lifecyclePreparedCandidate) UnmarshalJSON([]byte) error  { return errLifecycleUnsafe }

func (b *lifecycleVerifiedBase) release() {
	if b == nil || b.core == nil || b.core.store == nil {
		return
	}
	x := b.core.store
	if x.activeBase == b.core {
		x.activeBase = nil
		x.activePrepared = nil
	}
}
func (b *lifecycleVerifiedBase) issuedTo(x *lifecycleRecoveryStoreCore) bool {
	return b != nil && b.core != nil && x != nil && b.core.store == x && x.activeBase == b.core
}
func (b *lifecycleVerifiedBase) intact(x *lifecycleRecoveryStoreCore) bool {
	return b.issuedTo(x) && !x.closed && !x.poisoned && x.record.core != nil && b.core.record.core != nil &&
		len(b.core.raw) != 0 && labConfigHash(b.core.raw) == b.core.rawSHA256 && bytes.Equal(x.raw, b.core.raw) && reflect.DeepEqual(x.record.core, b.core.record.core)
}
func (b *lifecycleVerifiedBase) valid(x *lifecycleRecoveryStoreCore) bool {
	return b.intact(x) && !b.core.used
}
func (b *lifecycleVerifiedBase) copyRecord() (lifecycleV3Record, error) {
	if b == nil || b.core == nil || !b.valid(b.core.store) {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	// These exact bytes came from full external canonical/semantic validation.
	// Typed decoding detaches all pointers/slices without validating them twice.
	var w lifecycleV3Wire
	if json.Unmarshal(b.core.raw, &w) != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	return lifecycleV3Record{core: &w}, nil
}

func (lifecycleRecoveryStore) String() string   { return lifecycleRecoveryDebug }
func (lifecycleRecoveryStore) GoString() string { return lifecycleRecoveryDebug }
func (lifecycleRecoveryStore) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, lifecycleRecoveryDebug)
}
func (lifecycleRecoveryStore) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"PRIVATE_RECOVERY_STORE_NOT_AUTHORIZATION"}`), nil
}
func (*lifecycleRecoveryStore) UnmarshalJSON([]byte) error { return errLifecycleUnsafe }
func (lifecycleRecoveryOwnerToken) String() string         { return lifecycleRecoveryDebug }
func (lifecycleRecoveryOwnerToken) GoString() string       { return lifecycleRecoveryDebug }
func (lifecycleRecoveryOwnerToken) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, lifecycleRecoveryDebug)
}
func (lifecycleRecoveryOwnerToken) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"IN_MEMORY_RECOVERY_OWNER_NOT_AUTHORIZATION"}`), nil
}
func (t *lifecycleRecoveryOwnerToken) UnmarshalJSON([]byte) error {
	if t != nil {
		t.core = nil
	}
	return errLifecycleUnsafe
}

// A structural builder, not a migration permission or an owned-process proof.
// Only the future authenticated RecoveryPrepare coordinator may select it.
func buildLifecycleV3Evolution(originalRaw []byte, p *labRecoveryPlan, now time.Time) (lifecycleV3Record, error) {
	original, err := decodeLifecycleRecord(originalRaw)
	if err != nil || p == nil || p.validAt(now) != nil || original.wire.Schema != lifecycleSchemaV2 || original.wire.Revision == ^uint64(0) {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	if _, err := labRecoveryPlanFromDescriptor(p.descriptor(), original); err != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	w := &lifecycleV3Wire{Schema: lifecycleSchemaV3, Boundary: lifecycleBoundary, Revision: original.wire.Revision + 1, LastTrustedAt: now,
		Provisioning: original.wire.V2.Provisioning, SourceV2: lifecycleLegacySnapshot{lifecycleSchemaV2, labConfigHash(originalRaw), original.wire.RecordSHA256, original.wire.Revision, bytes.Clone(originalRaw)},
		Current: lifecycleLegacyLedger(original, originalRaw), RetiredEpochs: []lifecycleRetiredEpoch{}, RecoveryHistory: []lifecycleRecoveryTxn{}}
	w.RecordSHA256, err = lifecycleV3RecordHash(*w)
	r := lifecycleV3Record{core: w}
	if err != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		return lifecycleV3Record{}, err
	}
	return decodeLifecycleV3Record(raw)
}

// The old mutex and disk remain exclusive throughout handoff. The coordinator
// must already have checked current critical-admin authority and the actual
// owned epoch. Nothing here accepts an HTTP record, auth boolean or disk path.
func evolveLifecycleV2ForRecovery(old *lifecycleStore, p *labRecoveryPlan, now time.Time) (*lifecycleRecoveryStore, error) {
	if old == nil || old.lifecycleStoreCore == nil || old.mu == nil {
		return nil, errLifecycleUnsafe
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	if err := old.verify(); err != nil {
		return nil, err
	}
	if err := old.trustedNow(now); err != nil {
		return nil, err
	}
	r, err := buildLifecycleV3Evolution(old.raw, p, now)
	if err != nil {
		return nil, err
	}
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		return nil, err
	}
	x := &lifecycleRecoveryStoreCore{disk: old.disk, record: r, raw: bytes.Clone(raw)}
	s := &lifecycleRecoveryStore{core: x}
	if err := x.publish(raw); err != nil {
		if x.poisoned {
			old.poisoned = true
			old.live = nil
		}
		return nil, err
	}
	// Do not close the disk: the new object is now its sole close owner. The
	// original store/session/token cannot perform another read, write or close.
	old.live = nil
	old.closed = true
	old.disk = nil
	return s, nil
}

func lifecycleRecoveryDiskPresent(d lifecycleDisk) bool {
	if d == nil {
		return false
	}
	v := reflect.ValueOf(d)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !v.IsNil()
	}
	return true
}
func openLifecycleRecoveryStore(d lifecycleDisk, now time.Time) (*lifecycleRecoveryStore, error) {
	if !lifecycleRecoveryDiskPresent(d) || !lifecycleTime(now) {
		return nil, errLifecycleUnsafe
	}
	if err := d.verify(); err != nil {
		return nil, err
	}
	raw, exists, err := d.readControl()
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errLifecycleUnsafe
	}
	r, err := decodeLifecycleV3Record(raw)
	if err != nil {
		return nil, err
	}
	if now.Before(r.core.LastTrustedAt) {
		return nil, errLifecycleUnsafe
	}
	x := &lifecycleRecoveryStoreCore{disk: d, record: r, raw: bytes.Clone(raw)}
	// The actual disk bytes have just passed the complete external decoder,
	// canonical comparison and all history/semantic checks. No caller-supplied
	// boolean or digest can construct this owner-bound image through an API.
	x.validationGeneration = 1
	image := &lifecycleValidatedSnapshot{store: x, canonical: string(raw), rawSHA256: labConfigHash(raw), generation: x.validationGeneration}
	image.identity = image
	sealedCanonical, sealedDigest, sealedGeneration := image.canonical, image.rawSHA256, image.generation
	image.binding = func(candidate *lifecycleValidatedSnapshot, owner *lifecycleRecoveryStoreCore) bool {
		return candidate == image && owner == x && candidate.identity == image && candidate.store == owner &&
			candidate.canonical == sealedCanonical && candidate.rawSHA256 == sealedDigest && candidate.generation == sealedGeneration && owner.validationGeneration == sealedGeneration
	}
	x.validated = image
	s := &lifecycleRecoveryStore{core: x}
	// Reopening never restores an owner, consumed-q provenance or StartPermit.
	// Any armed physical action is uncertain; even a durable fact is not a new
	// permission to replay it. Preserve every original action/fact verbatim.
	if a := r.core.Recovery; a != nil && a.Phase != "PLANNED" && a.Phase != "APPROVED" && a.Phase != "REVOKED_UNSTARTED" && a.Phase != "COMPLETED" && a.Phase != "RECOVERY_UNKNOWN" {
		next, err := decodeLifecycleV3Record(raw)
		if err != nil {
			return nil, err
		}
		next.core.Recovery.Phase = "RECOVERY_UNKNOWN"
		if next.core.Recovery.Failure == nil {
			next.core.Recovery.Failure = &lifecycleRecoveryFailure{"PROCESS_REOPENED", now}
		}
		next.core.Recovery.UpdatedAt = now
		if err := x.commit(next, now); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (x *lifecycleRecoveryStoreCore) trustedNow(now time.Time) error {
	if x == nil || x.record.core == nil || !lifecycleTime(now) || now.Before(x.record.core.LastTrustedAt) {
		if x != nil {
			x.poisoned = true
			x.live = nil
			x.permit = nil
			x.quiescenceSHA = ""
			x.activeBase = nil
			x.activePrepared = nil
			x.validated = nil
		}
		return errLifecycleUnsafe
	}
	return nil
}
func (x *lifecycleRecoveryStoreCore) verify() error {
	base, err := x.verifiedBase()
	if err != nil {
		return err
	}
	base.release()
	return nil
}
func (x *lifecycleRecoveryStoreCore) verifiedBase() (*lifecycleVerifiedBase, error) {
	if x == nil || x.closed || x.record.core == nil || !lifecycleRecoveryDiskPresent(x.disk) {
		return nil, errLifecycleUnsafe
	}
	// Starting even a failed new operation invalidates an earlier capability.
	x.activeBase = nil
	x.activePrepared = nil
	if x.poisoned {
		return nil, errLifecyclePoisoned
	}
	if err := x.disk.verify(); err != nil {
		x.poisoned = true
		x.validated = nil
		return nil, err
	}
	raw, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw, x.raw) {
		x.poisoned = true
		x.validated = nil
		return nil, errLifecycleUnsafe
	}
	// Reuse only this exact previously validated canonical image. All actual
	// custody/read checks above still occur on every operation. A missing or
	// changed image is rejected, never silently re-sealed from changed input.
	image := x.validated
	if image == nil || image.store != x || image.identity != image || image.binding == nil || !image.binding(image, x) || image.generation == 0 || image.generation != x.validationGeneration || len(image.canonical) == 0 ||
		labConfigHash([]byte(image.canonical)) != image.rawSHA256 || !bytes.Equal(raw, []byte(image.canonical)) {
		x.poisoned = true
		x.validated = nil
		return nil, errLifecycleUnsafe
	}
	// Bind every typed/nested field, including nil versus empty values, rather
	// than trusting only a record digest/revision that private-state mutation
	// could leave unchanged. This is consistency with known canonical bytes,
	// not an alternate validator for external bytes or new candidates.
	canonical, err := json.Marshal(x.record.core)
	if err != nil || !bytes.Equal(canonical, []byte(image.canonical)) {
		x.poisoned = true
		x.validated = nil
		return nil, errLifecycleUnsafe
	}
	// The source is already fully validated and exact-byte matched above.
	// Typed decoding creates an independent base without repeating token,
	// canonical and complete-history validation of this unchanged image.
	var detached lifecycleV3Wire
	if json.Unmarshal(raw, &detached) != nil {
		x.poisoned = true
		x.validated = nil
		return nil, errLifecycleUnsafe
	}
	r := lifecycleV3Record{core: &detached}
	b := &lifecycleVerifiedBase{core: &lifecycleVerifiedBaseCore{store: x, raw: bytes.Clone(raw), rawSHA256: labConfigHash(raw), record: r}}
	x.activeBase = b.core
	return b, nil
}
func (x *lifecycleRecoveryStoreCore) publish(raw []byte) error {
	// This raw compatibility entry is used by V2 evolution. It is not an
	// unchecked generic publisher or a fabricated V3 verified base.
	if x == nil || x.closed || x.poisoned || !lifecycleRecoveryDiskPresent(x.disk) {
		return errLifecycleUnsafe
	}
	x.activeBase = nil
	x.activePrepared = nil
	defer func() { x.activePrepared = nil }()
	if err := x.disk.verify(); err != nil {
		x.poisoned = true
		x.validated = nil
		return err
	}
	before, exists, err := x.disk.readControl()
	if err != nil || !exists {
		x.poisoned = true
		x.validated = nil
		return errLifecycleUnsafe
	}
	old, err := decodeLifecycleRecord(before)
	if err != nil || old.wire.Schema != lifecycleSchemaV2 {
		x.poisoned = true
		x.validated = nil
		return errLifecycleUnsafe
	}
	ownedRaw := bytes.Clone(raw)
	r, err := decodeLifecycleV3Record(ownedRaw)
	if err != nil || old.wire.Revision == ^uint64(0) || r.core.Revision != old.wire.Revision+1 ||
		!bytes.Equal(r.core.SourceV2.ControlBytes, before) || r.core.LastTrustedAt.Before(old.wire.LastTrustedAt) ||
		r.core.Recovery != nil || r.core.RecoveryOwner != nil || r.core.LastRecoveryFence != 0 || len(r.core.RetiredEpochs) != 0 || len(r.core.RecoveryHistory) != 0 {
		return errLifecycleUnsafe
	}
	p := &lifecyclePreparedCandidate{core: &lifecyclePreparedCandidateCore{store: x, before: bytes.Clone(before), beforeSHA256: labConfigHash(before), raw: ownedRaw, rawSHA256: labConfigHash(ownedRaw), record: r}}
	x.activePrepared = p.core
	return x.publishPrepared(p)
}
func (x *lifecycleRecoveryStoreCore) publishPrepared(p *lifecyclePreparedCandidate) error {
	if x == nil || p == nil || p.core == nil || x.activePrepared != p.core || p.core.store != x {
		return errLifecycleUnsafe
	}
	c := p.core
	x.activePrepared = nil // an admitted publication attempt spends this entry
	if x.closed || x.poisoned || x.validationGeneration == ^uint64(0) || !lifecycleRecoveryDiskPresent(x.disk) || c.record.core == nil ||
		labConfigHash(c.raw) != c.rawSHA256 || labConfigHash(c.before) != c.beforeSHA256 ||
		(c.base != nil && (x.activeBase != c.base || !c.base.used || c.base.store != x)) {
		return errLifecycleUnsafe
	}
	// Defensive private metadata/raw consistency, not another semantic pass.
	canonical, err := json.Marshal(c.record.core)
	if err != nil || !bytes.Equal(canonical, c.raw) {
		return errLifecycleUnsafe
	}
	// A fresh actual custody/read/CAS check remains immediately before replace.
	if err := x.disk.verify(); err != nil {
		x.poisoned = true
		x.validated = nil
		return err
	}
	before, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(before, c.before) ||
		(c.base != nil && (!bytes.Equal(x.raw, c.before) || x.record.core == nil || !reflect.DeepEqual(x.record.core, c.base.record.core))) {
		x.poisoned = true
		x.validated = nil
		return errLifecycleUnsafe
	}
	state, err := x.disk.replaceControl(c.raw)
	if state == lifecycleUnknown || (state != lifecycleNotCommitted && state != lifecycleCommitted) || (state == lifecycleCommitted && err != nil) {
		x.poisoned = true
		x.validated = nil
		return errLifecycleCommitUnknown
	}
	if state != lifecycleCommitted {
		if errors.Is(err, errLifecycleUnsafe) {
			x.poisoned = true
			x.validated = nil
		}
		if err != nil {
			return err
		}
		return errLifecycleUnsafe
	}
	actual, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(actual, c.raw) || x.disk.verify() != nil {
		x.poisoned = true
		x.validated = nil
		return errLifecycleCommitUnknown
	}
	// Every actual byte equals the fully validated prepared canonical bytes.
	// Its typed record is an independent private decode, never caller input.
	x.record = c.record
	x.raw = bytes.Clone(c.raw)
	// This issuance is after full candidate validation, actual replace,
	// exact readback and post-read custody. Failed/unknown writes never adopt
	// the candidate image; reopening always validates external bytes afresh.
	x.validationGeneration++
	image := &lifecycleValidatedSnapshot{store: x, canonical: string(actual), rawSHA256: labConfigHash(actual), generation: x.validationGeneration}
	image.identity = image
	sealedCanonical, sealedDigest, sealedGeneration := image.canonical, image.rawSHA256, image.generation
	image.binding = func(candidate *lifecycleValidatedSnapshot, owner *lifecycleRecoveryStoreCore) bool {
		return candidate == image && owner == x && candidate.identity == image && candidate.store == owner &&
			candidate.canonical == sealedCanonical && candidate.rawSHA256 == sealedDigest && candidate.generation == sealedGeneration && owner.validationGeneration == sealedGeneration
	}
	x.validated = image
	return nil
}
func (x *lifecycleRecoveryStoreCore) commit(next lifecycleV3Record, now time.Time) error {
	base, err := x.verifiedBase()
	if err != nil {
		return err
	}
	defer base.release()
	return x.commitWithBase(base, next, now)
}
func (x *lifecycleRecoveryStoreCore) commitWithBase(base *lifecycleVerifiedBase, next lifecycleV3Record, now time.Time) error {
	if !base.issuedTo(x) || base.core.used {
		return errLifecycleUnsafe
	}
	p, err := prepareLifecycleCandidate(base, next, now)
	if err != nil {
		return err
	}
	return x.publishPrepared(p)
}
func prepareLifecycleCandidate(base *lifecycleVerifiedBase, next lifecycleV3Record, now time.Time) (*lifecyclePreparedCandidate, error) {
	if base == nil || base.core == nil || !base.issuedTo(base.core.store) || base.core.used {
		return nil, errLifecycleUnsafe
	}
	x := base.core.store
	base.core.used = true // invalid candidate/clock/CAS cannot reuse this base
	if !base.intact(x) {
		return nil, errLifecycleUnsafe
	}
	if err := x.trustedNow(now); err != nil {
		return nil, err
	}
	if next.core == nil || x.record.core.Revision == ^uint64(0) || next.core.Revision != x.record.core.Revision || next.core.RecordSHA256 != x.record.core.RecordSHA256 || !lifecycleV3Transition(x.record.core, next.core) {
		return nil, errLifecycleUnsafe
	}
	if next.core.LastRecoveryFence != x.record.core.LastRecoveryFence {
		o := x.record.core.RecoveryOwner
		n := next.core.RecoveryOwner
		if (o != nil && now.Before(o.ExpiresAt)) || n == nil || !n.AcquiredAt.Equal(now) || !n.RenewedAt.Equal(now) || !n.ExpiresAt.After(now) || n.ExpiresAt.Sub(now) > 5*time.Minute {
			return nil, errLifecycleUnsafe
		}
	}
	next.core.Revision = x.record.core.Revision + 1
	next.core.LastTrustedAt = now
	next.core.RecordSHA256, _ = lifecycleV3RecordHash(*next.core)
	raw, err := encodeLifecycleV3Record(next)
	if err != nil {
		return nil, err
	}
	var owned lifecycleV3Wire
	if json.Unmarshal(raw, &owned) != nil {
		return nil, errLifecycleUnsafe
	}
	c := &lifecyclePreparedCandidateCore{store: x, base: base.core, before: bytes.Clone(base.core.raw), beforeSHA256: base.core.rawSHA256, raw: bytes.Clone(raw), rawSHA256: labConfigHash(raw), record: lifecycleV3Record{core: &owned}}
	p := &lifecyclePreparedCandidate{core: c}
	x.activePrepared = c
	return p, nil
}
func (x *lifecycleRecoveryStoreCore) copyRecord() (lifecycleV3Record, error) {
	return decodeLifecycleV3Record(x.raw)
}
func (x *lifecycleRecoveryStoreCore) token(t *lifecycleRecoveryOwnerToken, fresh bool, now time.Time) error {
	if err := x.trustedNow(now); err != nil {
		return err
	}
	o := x.record.core.RecoveryOwner
	if t == nil || t.core == nil || x.live != t.core || t.core.store != x || o == nil || t.core.nonce != o.OwnerNonce || t.core.fence != o.Fence {
		return errLifecycleUnsafe
	}
	if fresh && !now.Before(o.ExpiresAt) {
		return errLifecycleUnsafe
	}
	return nil
}

// This is only a process-local structural lease. No Principal, JSON owner or
// ApprovalMaterial becomes authentication or a stop/start capability here.
func (s *lifecycleRecoveryStore) acquireRecoveryOwner(now, expires time.Time) (*lifecycleRecoveryOwnerToken, error) {
	if s == nil || s.core == nil {
		return nil, errLifecycleUnsafe
	}
	x := s.core
	x.mu.Lock()
	defer x.mu.Unlock()
	base, err := x.verifiedBase()
	if err != nil {
		return nil, err
	}
	defer base.release()
	if err := x.trustedNow(now); err != nil {
		return nil, err
	}
	w := x.record.core
	if !lifecycleTime(expires) || !expires.After(now) || expires.Sub(now) > 5*time.Minute || w.LastRecoveryFence == ^uint64(0) || (w.RecoveryOwner != nil && now.Before(w.RecoveryOwner.ExpiresAt)) {
		return nil, errLifecycleUnsafe
	}
	if a := w.Recovery; a != nil && a.Phase != "REVOKED_UNSTARTED" && a.Phase != "COMPLETED" && a.Phase != "PLANNED" && a.Phase != "APPROVED" {
		return nil, errLifecycleUnsafe
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, errLifecycleUnsafe
	}
	next, err := base.copyRecord()
	if err != nil {
		return nil, err
	}
	next.core.LastRecoveryFence++
	next.core.RecoveryOwner = &lifecycleOwner{hex.EncodeToString(nonce[:]), next.core.LastRecoveryFence, now, now, expires}
	if err := x.commitWithBase(base, next, now); err != nil {
		return nil, err
	}
	t := &lifecycleRecoveryOwnerToken{core: &lifecycleRecoveryOwnerCore{x, next.core.RecoveryOwner.OwnerNonce, next.core.LastRecoveryFence}}
	x.live = t.core
	return t, nil
}
func (s *lifecycleRecoveryStore) close() error {
	if s == nil || s.core == nil {
		return errLifecycleUnsafe
	}
	x := s.core
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	x.live = nil
	x.permit = nil
	x.quiescenceSHA = ""
	x.activeBase = nil
	x.activePrepared = nil
	x.validated = nil
	if !lifecycleRecoveryDiskPresent(x.disk) {
		return errLifecycleUnsafe
	}
	if err := x.disk.close(); err != nil {
		x.poisoned = true
		return err
	}
	x.closed = true
	return nil
}

func lifecycleV3Transition(a, b *lifecycleV3Wire) bool {
	if a == nil || b == nil || a.Schema != b.Schema || a.Boundary != b.Boundary || a.Provisioning != b.Provisioning || !reflect.DeepEqual(a.SourceV2, b.SourceV2) || !reflect.DeepEqual(a.Current, b.Current) || !reflect.DeepEqual(a.RetiredEpochs, b.RetiredEpochs) || len(b.RecoveryHistory) < len(a.RecoveryHistory) || !reflect.DeepEqual(b.RecoveryHistory[:len(a.RecoveryHistory)], a.RecoveryHistory) {
		return false
	}
	// No head advancement/epoch factory in this initial, capability-incomplete
	// extension. A future source-owned collector transition is separately gated.
	if b.LastRecoveryFence == a.LastRecoveryFence {
		if !reflect.DeepEqual(a.RecoveryOwner, b.RecoveryOwner) {
			return false
		}
	} else if a.LastRecoveryFence == ^uint64(0) || b.LastRecoveryFence != a.LastRecoveryFence+1 || b.RecoveryOwner == nil {
		return false
	}
	if a.Recovery == nil {
		return len(a.RecoveryHistory) == len(b.RecoveryHistory) && (b.Recovery == nil || b.Recovery.Phase == "PLANNED")
	}
	if b.Recovery == nil {
		return false
	}
	if a.Recovery.Plan.PlanSHA256 != b.Recovery.Plan.PlanSHA256 {
		return (a.Recovery.Phase == "REVOKED_UNSTARTED" || a.Recovery.Phase == "COMPLETED") && len(b.RecoveryHistory) == len(a.RecoveryHistory) && b.Recovery.Phase == "PLANNED"
	}
	x, y := a.Recovery, b.Recovery
	if !reflect.DeepEqual(x.Plan, y.Plan) || !lifecycleRecoveryPhaseTransition(x.Phase, y.Phase) || (x.Approval != nil && !reflect.DeepEqual(x.Approval, y.Approval)) || (x.Revocation != nil && !reflect.DeepEqual(x.Revocation, y.Revocation)) || (x.StopIntent != nil && !reflect.DeepEqual(x.StopIntent, y.StopIntent)) || (x.StopBinding != nil && !reflect.DeepEqual(x.StopBinding, y.StopBinding)) || (x.Quiescence != nil && !reflect.DeepEqual(x.Quiescence, y.Quiescence)) || (x.StartIntent != nil && !reflect.DeepEqual(x.StartIntent, y.StartIntent)) || (x.Failure != nil && !reflect.DeepEqual(x.Failure, y.Failure)) || (x.Completion != nil && !reflect.DeepEqual(x.Completion, y.Completion)) || len(y.FailedQuiescence) < len(x.FailedQuiescence) || !reflect.DeepEqual(y.FailedQuiescence[:len(x.FailedQuiescence)], x.FailedQuiescence) || y.UpdatedAt.Before(x.UpdatedAt) {
		return false
	}
	if y.Phase == "REVOKED_UNSTARTED" && x.Phase != "REVOKED_UNSTARTED" {
		return len(b.RecoveryHistory) == len(a.RecoveryHistory)+1 && reflect.DeepEqual(b.RecoveryHistory[len(a.RecoveryHistory)], *y)
	}
	return len(b.RecoveryHistory) == len(a.RecoveryHistory)
}
