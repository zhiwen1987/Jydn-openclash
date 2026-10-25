package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
)

type lifecycleRecoveryStore struct{ core *lifecycleRecoveryStoreCore }
type lifecycleRecoveryStoreCore struct {
	mu                 sync.Mutex
	disk               lifecycleDisk
	record             lifecycleV3Record
	raw                []byte
	live               *lifecycleRecoveryOwnerCore
	quiescenceSHA      string
	permit             *labRecoveryStartCore
	startedRecord      *lifecycleStartedPublication
	verificationRecord *lifecycleVerificationPublication
	completionRecord   *lifecycleCompletionPublication
	// Ephemeral custody from an actually consumed Started core and successful
	// S1 disk publication. Never decoded or persisted; reopen starts with nil.
	retainedStarted    *labRecoveryStartedCustody
	retainedVerified   *labRecoveryVerifiedCustody
	currentLive        *lifecycleRecoveryCurrentOwnerCore
	currentPublication *lifecycleCurrentEpochPublication
	reconcilePermit    *labRecoveryReconcilePermitCore
	terminalReentry    *labRecoveryTerminalReentryPermitCore
	absenceCustody     *labRecoveryAbsenceCustodyCore
	absentStartPermit  *labRecoveryAbsentStartPermitCore
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
	if a := r.core.Recovery; a != nil && a.Phase != "PLANNED" && a.Phase != "APPROVED" && a.Phase != "REVOKED_UNSTARTED" && a.Phase != "COMPLETED" && a.Phase != "RECOVERY_UNKNOWN" && a.Phase != "FAILED_RECONCILED" {
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
			x.retainedStarted = nil
			x.live = nil
			x.permit = nil
			x.startedRecord = nil
			x.verificationRecord = nil
			x.completionRecord = nil
			x.quiescenceSHA = ""
			x.activeBase = nil
			x.activePrepared = nil
			x.validated = nil
			x.retainedVerified = nil
			x.currentLive = nil
			x.currentPublication = nil
			x.reconcilePermit = nil
			x.terminalReentry = nil
			x.absenceCustody = nil
			x.absentStartPermit = nil
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
		x.retainedStarted = nil
		x.validated = nil
		return nil, err
	}
	raw, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw, x.raw) {
		x.poisoned = true
		x.retainedStarted = nil
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
		x.retainedStarted = nil
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
		x.retainedStarted = nil
		x.validated = nil
		return nil, errLifecycleUnsafe
	}
	// The source is already fully validated and exact-byte matched above.
	// A closed typed copy creates an independent base without repeating token,
	// canonical and complete-history validation of this unchanged image.
	r, err := cloneTrustedLifecycleV3(x.record, raw)
	if err != nil {
		x.poisoned = true
		x.retainedStarted = nil
		x.validated = nil
		return nil, errLifecycleUnsafe
	}
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
		x.retainedStarted = nil
		x.validated = nil
		return err
	}
	before, exists, err := x.disk.readControl()
	if err != nil || !exists {
		x.poisoned = true
		x.retainedStarted = nil
		x.validated = nil
		return errLifecycleUnsafe
	}
	old, err := decodeLifecycleRecord(before)
	if err != nil || old.wire.Schema != lifecycleSchemaV2 {
		x.poisoned = true
		x.retainedStarted = nil
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
		x.retainedStarted = nil
		x.validated = nil
		return err
	}
	before, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(before, c.before) ||
		(c.base != nil && (!bytes.Equal(x.raw, c.before) || x.record.core == nil || !reflect.DeepEqual(x.record.core, c.base.record.core))) {
		x.poisoned = true
		x.retainedStarted = nil
		x.validated = nil
		return errLifecycleUnsafe
	}
	// Full-history validation and the final disk CAS may take time. A
	// Completion must still have a live window immediately before replace;
	// an earlier cap check cannot authorize a late head/owner publication.
	if x.completionRecord != nil && !x.completionFreshBeforeReplace(c) {
		x.poisoned = true
		x.live, x.retainedStarted, x.retainedVerified, x.currentLive = nil, nil, nil, nil
		x.validated = nil
		return errLifecycleUnsafe
	}
	state, err := x.disk.replaceControl(c.raw)
	if state == lifecycleUnknown || (state != lifecycleNotCommitted && state != lifecycleCommitted) || (state == lifecycleCommitted && err != nil) {
		x.poisoned = true
		x.retainedStarted = nil
		x.validated = nil
		return errLifecycleCommitUnknown
	}
	if state != lifecycleCommitted {
		if errors.Is(err, errLifecycleUnsafe) {
			x.poisoned = true
			x.retainedStarted = nil
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
		x.retainedStarted = nil
		x.validated = nil
		return errLifecycleCommitUnknown
	}
	// Every actual byte equals the fully validated prepared canonical bytes.
	// Its typed record is an independent private copy, never caller input.
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

// These two entry points are intentionally closed over the complete
// begin/revoke draft construction. copyRecord performs the unchanged full
// base.intact check and JSON detachment; after it returns, only local detached
// field changes occur before the same stack spends the base. There is no
// interface, callback or unlock in that interval. The prepared candidate is
// published immediately and is never returned from either entry point.
func (x *lifecycleRecoveryStoreCore) commitFreshRecoveryBegin(base *lifecycleVerifiedBase, descriptor labRecoveryPlanDescriptor, now time.Time) error {
	next, err := base.copyRecord()
	if err != nil {
		return err
	}
	next.core.Recovery = &lifecycleRecoveryTxn{Plan: descriptor, Phase: "PLANNED", FailedQuiescence: []labQuiescenceObservation{}, UpdatedAt: now}
	if !base.issuedTo(x) || base.core.used {
		return errLifecycleUnsafe
	}
	base.core.used = true
	prepared, err := prepareLifecycleCandidateAfterVerifiedBase(x, base, next, now)
	if err != nil {
		return err
	}
	return x.publishPrepared(prepared)
}

func (x *lifecycleRecoveryStoreCore) commitFreshRecoveryRevoke(base *lifecycleVerifiedBase, actor, reason string, now time.Time) error {
	next, err := base.copyRecord()
	if err != nil {
		return err
	}
	b := next.core.Recovery
	b.Revocation = &lifecycleRevocation{x.record.core.Revision + 1, now, reason, actor}
	b.UpdatedAt = now
	if b.StopIntent == nil {
		b.Phase = "REVOKED_UNSTARTED"
		next.core.RecoveryHistory = append(next.core.RecoveryHistory, *b)
	} else {
		b.Phase = "RECOVERY_UNKNOWN"
		if b.Failure == nil {
			b.Failure = &lifecycleRecoveryFailure{reason, now}
		}
	}
	if !base.issuedTo(x) || base.core.used {
		return errLifecycleUnsafe
	}
	base.core.used = true
	prepared, err := prepareLifecycleCandidateAfterVerifiedBase(x, base, next, now)
	if err != nil {
		return err
	}
	return x.publishPrepared(prepared)
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
	return prepareLifecycleCandidateAfterVerifiedBase(x, base, next, now)
}

// The caller has just performed base.intact and spent this exact active base.
// It grants no authority: every transition, clock, fence, complete-history,
// canonical clone and publication check below remains unchanged.
func prepareLifecycleCandidateAfterVerifiedBase(x *lifecycleRecoveryStoreCore, base *lifecycleVerifiedBase, next lifecycleV3Record, now time.Time) (*lifecyclePreparedCandidate, error) {
	if x == nil || base == nil || base.core == nil || !base.issuedTo(x) || !base.core.used {
		return nil, errLifecycleUnsafe
	}
	if err := x.trustedNow(now); err != nil {
		return nil, err
	}
	if next.core == nil || x.record.core.Revision == ^uint64(0) || next.core.Revision != x.record.core.Revision || next.core.RecordSHA256 != x.record.core.RecordSHA256 {
		return nil, errLifecycleUnsafe
	}
	// An issued Completion publication is an exclusive transition kind. It may
	// never fall through to a generic, S1, verification or current-epoch branch
	// if its cap/base/checkpoint gate rejects the candidate.
	transition := false
	if x.completionRecord != nil {
		transition = x.completionRecordTransition(base, next)
	} else {
		transition = lifecycleV3Transition(x.record.core, next.core) || x.startedRecordTransition(base, next) ||
			x.verificationRecordTransition(base, next) || x.currentEpochTransition(base, next)
	}
	if !transition {
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
	raw, err := sealLifecycleV3Candidate(next)
	if err != nil {
		return nil, err
	}
	owned, err := cloneTrustedLifecycleV3(next, raw)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	c := &lifecyclePreparedCandidateCore{store: x, base: base.core, before: bytes.Clone(base.core.raw), beforeSHA256: base.core.rawSHA256, raw: bytes.Clone(raw), rawSHA256: labConfigHash(raw), record: owned}
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
	if a := w.Recovery; a != nil && a.Phase != "REVOKED_UNSTARTED" && a.Phase != "COMPLETED" && a.Phase != "FAILED_RECONCILED" && a.Phase != "PLANNED" && a.Phase != "APPROVED" {
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
	x.startedRecord = nil
	x.verificationRecord = nil
	x.completionRecord = nil
	x.retainedStarted = nil
	x.retainedVerified = nil
	x.currentLive = nil
	x.currentPublication = nil
	x.reconcilePermit = nil
	x.terminalReentry = nil
	x.absenceCustody = nil
	x.absentStartPermit = nil
	x.quiescenceSHA = ""
	x.activeBase = nil
	x.activePrepared = nil
	x.validated = nil
	if !lifecycleRecoveryDiskPresent(x.disk) {
		return errLifecycleUnsafe
	}
	if err := x.disk.close(); err != nil {
		x.poisoned = true
		x.retainedStarted = nil
		return err
	}
	x.closed = true
	return nil
}

func lifecycleV3Transition(a, b *lifecycleV3Wire) bool {
	if a == nil || b == nil || a.Schema != b.Schema || a.Boundary != b.Boundary || a.Provisioning != b.Provisioning || !reflect.DeepEqual(a.SourceV2, b.SourceV2) || !reflect.DeepEqual(a.Current, b.Current) || !reflect.DeepEqual(a.RetiredEpochs, b.RetiredEpochs) || len(b.RecoveryHistory) < len(a.RecoveryHistory) || !reflect.DeepEqual(b.RecoveryHistory[:len(a.RecoveryHistory)], a.RecoveryHistory) {
		return false
	}
	// Apply this before the nil/replacement/history early returns as well.
	// Only the separate actual-capability recorder may append execution facts.
	var beforeExecution, afterExecution *lifecycleRecoveryExecution
	if a.Recovery != nil {
		beforeExecution = a.Recovery.Execution
	}
	if b.Recovery != nil {
		afterExecution = b.Recovery.Execution
	}
	if !reflect.DeepEqual(beforeExecution, afterExecution) {
		return false
	}
	for _, appended := range b.RecoveryHistory[len(a.RecoveryHistory):] {
		if appended.Execution != nil {
			return false
		}
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
		return (a.Recovery.Phase == "REVOKED_UNSTARTED" || a.Recovery.Phase == "COMPLETED" || a.Recovery.Phase == "FAILED_RECONCILED") && len(b.RecoveryHistory) == len(a.RecoveryHistory) && b.Recovery.Phase == "PLANNED"
	}
	x, y := a.Recovery, b.Recovery
	if !reflect.DeepEqual(x.Plan, y.Plan) || !lifecycleRecoveryPhaseTransition(x.Phase, y.Phase) || (x.Approval != nil && !reflect.DeepEqual(x.Approval, y.Approval)) || (x.Revocation != nil && !reflect.DeepEqual(x.Revocation, y.Revocation)) || (x.StopIntent != nil && !reflect.DeepEqual(x.StopIntent, y.StopIntent)) || (x.StopBinding != nil && !reflect.DeepEqual(x.StopBinding, y.StopBinding)) || (x.Quiescence != nil && !reflect.DeepEqual(x.Quiescence, y.Quiescence)) || (x.StartIntent != nil && !reflect.DeepEqual(x.StartIntent, y.StartIntent)) || (x.Failure != nil && !reflect.DeepEqual(x.Failure, y.Failure)) || (x.Completion != nil && !reflect.DeepEqual(x.Completion, y.Completion)) || (x.Reconciliation != nil && !reflect.DeepEqual(x.Reconciliation, y.Reconciliation)) || len(y.FailedQuiescence) < len(x.FailedQuiescence) || !reflect.DeepEqual(y.FailedQuiescence[:len(x.FailedQuiescence)], x.FailedQuiescence) || y.UpdatedAt.Before(x.UpdatedAt) {
		return false
	}
	if y.Phase == "REVOKED_UNSTARTED" && x.Phase != "REVOKED_UNSTARTED" {
		return len(b.RecoveryHistory) == len(a.RecoveryHistory)+1 && reflect.DeepEqual(b.RecoveryHistory[len(a.RecoveryHistory)], *y)
	}
	if y.Phase == "FAILED_RECONCILED" && x.Phase == "RECOVERY_UNKNOWN" {
		return len(b.RecoveryHistory) == len(a.RecoveryHistory)+1 && reflect.DeepEqual(b.RecoveryHistory[len(a.RecoveryHistory)], *y)
	}
	return len(b.RecoveryHistory) == len(a.RecoveryHistory)
}

// This is a copy contract, not a validation/owner/approval capability. The
// two callers must first establish their existing exact canonical source or
// fully validated candidate. Unknown fields/codecs fail closed before copying.
// Every local struct is written as a complete positional literal: adding a
// field requires an explicit copy update rather than a silent shallow alias.
// Source-bound Linux Go1.23.12 diagnostic at commit 69c2fc2 observed 63 structs,
// 457 fields and 86 mutable slots (67 pointers, 19 slices). Later graph changes
// still fail closed until a new actual diagnostic supplies their exact pin.
const lifecycleCloneSchemaSHA256 = "ee925968d830156c5a5c0c366e28722e278b1d54284712ebc28b47a8ed7e4d61"

var errLifecycleCloneRepresentation = errors.New("trusted record copy requires original JSON representation")

// Go type/tag/method metadata is immutable within this binary. Cache only its
// closed-schema check, never a record, field value, owner or validation result.
var lifecycleCloneTypeSchema = sync.OnceValue(func() bool {
	return lifecycleCloneTypeSchemaFor(reflect.TypeOf(lifecycleV3Wire{}))
})

func lifecycleCloneTypeSchemaFor(root reflect.Type) bool {
	digest, walked := lifecycleCloneTypeShape(root)
	return walked && digest == lifecycleCloneSchemaSHA256
}

// This pure metadata walk deliberately exposes its completion independently
// of the fixed Wire-domain digest, so codec/type negative controls cannot be
// masked by merely giving a synthetic root a different type name.
func lifecycleCloneTypeShape(root reflect.Type) (string, bool) {
	if root == nil {
		return "", false
	}
	seen := map[reflect.Type]bool{}
	rows := []string{}
	jsonM := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	jsonU := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	textM := reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	textU := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	var visit func(reflect.Type) bool
	visit = func(t reflect.Type) bool {
		if seen[t] {
			return true
		}
		seen[t] = true
		row := t.PkgPath() + "|" + t.String() + "|" + t.Kind().String() + "\n"
		if t == reflect.TypeOf(time.Time{}) {
			rows = append(rows, row)
			return true // standard-library leaf; noncanonical representations fall back
		}
		knownCodec := t == reflect.TypeOf(json.RawMessage{}) ||
			(t.Kind() == reflect.Pointer && (t.Elem() == reflect.TypeOf(time.Time{}) || t.Elem() == reflect.TypeOf(json.RawMessage{})))
		if !knownCodec {
			for _, codec := range []reflect.Type{jsonM, jsonU, textM, textU} {
				if t.Implements(codec) || reflect.PointerTo(t).Implements(codec) {
					return false
				}
			}
		}
		switch t.Kind() {
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if f.PkgPath != "" || !visit(f.Type) {
					return false
				}
				row += f.Name + "|" + f.Type.String() + "|" + string(f.Tag) + "|" + strconv.FormatBool(f.Anonymous) + "\n"
			}
		case reflect.Pointer, reflect.Slice:
			if !visit(t.Elem()) {
				return false
			}
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		default:
			return false // no generic maps, interfaces, functions or hidden graphs
		}
		rows = append(rows, row)
		return true
	}
	if !visit(root) {
		return "", false
	}
	sort.Strings(rows)
	digest := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(digest[:]), true
}

type lifecycleCloneState struct{ err error }

func cloneTrustedLifecycleV3(in lifecycleV3Record, raw []byte) (lifecycleV3Record, error) {
	if in.core == nil || !lifecycleCloneTypeSchema() {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	c := &lifecycleCloneState{}
	out := c.wire(*in.core)
	if c.err == errLifecycleCloneRepresentation {
		// Match the exact old copy on known representation-changing leaves.
		// This flag only requests the original operation; it grants no trust.
		return lifecycleTrustedJSONCopy(raw)
	}
	// This compares every value/nil distinction, not just a digest or revision.
	// It is not a substitute for any caller's original semantic/custody gates.
	if c.err != nil || !reflect.DeepEqual(in.core, &out) {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	return lifecycleV3Record{core: &out}, nil
}

func lifecycleTrustedJSONCopy(raw []byte) (lifecycleV3Record, error) {
	if len(raw) == 0 || len(raw) > maxLifecycleControlBytes {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	var out lifecycleV3Wire
	if json.Unmarshal(raw, &out) != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	return lifecycleV3Record{core: &out}, nil
}

func (c *lifecycleCloneState) text(in string) string {
	if !utf8.ValidString(in) {
		c.err = errLifecycleCloneRepresentation // original JSON replaces invalid UTF-8
	}
	return in
}

func (c *lifecycleCloneState) timestamp(in time.Time) time.Time {
	// The ordinary canonical UTC/no-monotonic leaf is a value. Other admitted
	// offsets/named locations/monotonic values use the exact original raw copy.
	if in.Location() != time.UTC || in != in.Round(0) {
		c.err = errLifecycleCloneRepresentation
	}
	return in
}

func lifecycleClonePointer[T any](in *T, copyValue func(T) T) *T {
	if in == nil {
		return nil
	}
	out := copyValue(*in)
	return &out // allocate per path; do not memoize shared input pointers
}

func lifecycleCloneSlice[T any](in []T, copyValue func(T) T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in)) // preserve nonnil empty; no shared spare capacity
	for i := range in {
		out[i] = copyValue(in[i])
	}
	return out
}

func lifecycleCloneScalar[T ~int | ~uint64 | ~bool](in T) T { return in }

func lifecycleCloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// Imported struct conversions are closed over their exact fields/types.
// They avoid unkeyed imported literals (go vet) without allowing new fields.
type lifecycleCloneScopeShape struct {
	TenantID    string
	SiteID      string
	ObjectType  string
	ObjectID    string
	Environment string
}

type lifecycleCloneReloadShape struct {
	State      mihomo.ReloadState `json:"state"`
	Dispatched bool               `json:"dispatched"`
	StatusCode int                `json:"statusCode"`
}

func (c *lifecycleCloneState) scope(v authz.ResourceScope) authz.ResourceScope {
	return authz.ResourceScope(lifecycleCloneScopeShape{c.text(v.TenantID), c.text(v.SiteID), c.text(v.ObjectType), c.text(v.ObjectID), c.text(v.Environment)})
}

func (c *lifecycleCloneState) reload(v mihomo.ReloadResult) mihomo.ReloadResult {
	return mihomo.ReloadResult(lifecycleCloneReloadShape{mihomo.ReloadState(c.text(string(v.State))), v.Dispatched, v.StatusCode})
}

func (c *lifecycleCloneState) requirement(v LabPolicyRequirement) LabPolicyRequirement {
	return LabPolicyRequirement{c.text(v.Kind), c.text(v.Path)}
}

func (c *lifecycleCloneState) blocker(v LabConfigBlocker) LabConfigBlocker {
	return LabConfigBlocker{LabConfigCode(c.text(string(v.Code))), c.text(v.Path)}
}

func (c *lifecycleCloneState) config(v LabConfigDescriptor) LabConfigDescriptor {
	return LabConfigDescriptor{c.text(v.Schema), c.text(v.Scope), c.text(v.SHA256), v.Bytes, c.text(v.DraftSHA256), c.text(v.RequirementsSHA256), lifecycleCloneSlice(v.Capabilities, c.text), lifecycleCloneSlice(v.Requirements, c.requirement), v.Admissible, lifecycleCloneSlice(v.Blockers, c.blocker)}
}

func (c *lifecycleCloneState) artifact(v ArtifactDescriptor) ArtifactDescriptor {
	return ArtifactDescriptor{c.text(v.Schema), c.text(v.RecordSHA256), c.config(v.Config), c.text(v.SourceSpecSHA256), v.SourceSpecBytes, v.ControllerPort, v.MixedPort}
}

func (c *lifecycleCloneState) target(v TargetBinding) TargetBinding {
	return TargetBinding{c.text(v.DeviceRef), c.scope(v.Scope), v.Generation, c.text(v.HeadSHA256), c.text(v.KernelSHA256), v.PID, v.StartTicks, v.NetNSInode, v.ControllerPort, v.MixedPort}
}

func (c *lifecycleCloneState) backup(v BackupDescriptor) BackupDescriptor {
	return BackupDescriptor{c.text(v.Schema), c.text(v.BackupSHA256), c.text(v.OperationID), c.artifact(v.Artifact), c.target(v.Target)}
}

func (c *lifecycleCloneState) plan(v PlanDescriptor) PlanDescriptor {
	return PlanDescriptor{c.text(v.Schema), c.text(v.Boundary), c.text(v.OperationID), c.text(v.DeclaredInitiatorRef), c.target(v.Target), c.artifact(v.Artifact), c.backup(v.Backup), c.timestamp(v.CreatedAt), c.timestamp(v.ExpiresAt), c.text(v.PlanSHA256)}
}

func (c *lifecycleCloneState) material(v ApprovalMaterial) ApprovalMaterial {
	return ApprovalMaterial{c.text(v.PlanSHA256), c.scope(v.Scope), c.text(v.InitiatorRef), c.text(v.ApproverRef), c.timestamp(v.IssuedAt), c.timestamp(v.ExpiresAt)}
}

func (c *lifecycleCloneState) head(v lifecycleHead) lifecycleHead {
	return lifecycleHead{c.text(v.Schema), c.text(v.DeviceRef), c.scope(v.Scope), v.Generation, c.artifact(v.Artifact), c.text(v.KernelSHA256), v.PID, v.StartTicks, v.NetNSInode, v.ControllerPort, v.MixedPort, c.text(v.VerificationSHA256), c.timestamp(v.VerifiedAt), lifecycleClonePointer(v.PreviousHeadSHA256, c.text), c.text(v.HeadSHA256)}
}

func (c *lifecycleCloneState) owner(v lifecycleOwner) lifecycleOwner {
	return lifecycleOwner{c.text(v.OwnerNonce), v.Fence, c.timestamp(v.AcquiredAt), c.timestamp(v.RenewedAt), c.timestamp(v.ExpiresAt)}
}

func (c *lifecycleCloneState) approval(v lifecycleApproval) lifecycleApproval {
	return lifecycleApproval{c.material(v.Material), c.text(v.ApprovalID), lifecycleClonePointer(v.AuthoritySnapshotRef, c.text)}
}

func (c *lifecycleCloneState) revocation(v lifecycleRevocation) lifecycleRevocation {
	return lifecycleRevocation{v.Revision, c.timestamp(v.At), c.text(v.Reason), c.text(v.ActorRef)}
}

func (c *lifecycleCloneState) intent(v lifecycleIntent) lifecycleIntent {
	return lifecycleIntent{c.text(v.Schema), c.text(v.OperationID), c.text(v.PlanSHA256), c.text(v.ExpectedHeadSHA256), c.text(v.CandidateRecordSHA256), c.text(v.BackupSHA256), v.OwnerFence, c.timestamp(v.ArmedAt), c.text(v.IntentSHA256)}
}

func (c *lifecycleCloneState) gate(v labServiceGateFact) labServiceGateFact {
	return labServiceGateFact{c.text(v.OperationID), c.text(v.PlanSHA256), c.text(v.IntentSHA256), c.text(v.Reason), c.timestamp(v.ObservedAt)}
}

func (c *lifecycleCloneState) result(v lifecycleResult) lifecycleResult {
	return lifecycleResult{c.reload(v.Reload), c.timestamp(v.ObservedAt), c.text(v.Origin), lifecycleClonePointer(v.ServiceGate, c.gate)}
}

func (c *lifecycleCloneState) readback(v lifecycleReadback) lifecycleReadback {
	return lifecycleReadback{c.text(v.Conclusion), c.text(v.EvidenceSHA256), c.timestamp(v.ObservedAt)}
}

func (c *lifecycleCloneState) active(v lifecycleActive) lifecycleActive {
	if v.Recovery != nil {
		// Existing lifecycle validation forbids this field. In particular a
		// pointer to nil RawMessage must not gain authority by copying as null.
		c.err = errLifecycleCloneRepresentation
	}
	return lifecycleActive{c.plan(v.Plan), c.text(v.Phase), lifecycleClonePointer(v.Approval, c.approval), lifecycleClonePointer(v.Revocation, c.revocation), v.Attempt, lifecycleClonePointer(v.Intent, c.intent), lifecycleClonePointer(v.Result, c.result), lifecycleClonePointer(v.Readback, c.readback), lifecycleCloneSlice(v.AuditProjection, c.text), nil}
}

func (c *lifecycleCloneState) tombstone(v lifecycleTombstone) lifecycleTombstone {
	return lifecycleTombstone{c.text(v.OperationID), c.text(v.PlanSHA256), v.Attempt, lifecycleClonePointer(v.IntentSHA256, c.text), c.text(v.Phase), v.TerminalRevision}
}

func (c *lifecycleCloneState) provisioning(v lifecycleProvisioning) lifecycleProvisioning {
	return lifecycleProvisioning{c.text(v.Schema), c.text(v.RuntimeID), c.text(v.MarkerSHA256)}
}

func (c *lifecycleCloneState) completion(v lifecycleCompletion) lifecycleCompletion {
	return lifecycleCompletion{c.head(v.PreviousHead), c.head(v.Head), c.active(v.Active), c.owner(v.Owner), v.CommitRevision, c.timestamp(v.CommittedAt)}
}

func (c *lifecycleCloneState) observation(v lifecycleObservationRecord) lifecycleObservationRecord {
	return lifecycleObservationRecord{c.text(v.OperationID), c.text(v.PlanSHA256), c.text(v.IntentSHA256), c.readback(v.Readback), v.CommitRevision}
}

func (c *lifecycleCloneState) terminal(v lifecycleTerminalArchive) lifecycleTerminalArchive {
	return lifecycleTerminalArchive{c.head(v.Head), c.active(v.Active), c.owner(v.Owner), v.CommitRevision, c.timestamp(v.CommittedAt)}
}

func (c *lifecycleCloneState) source(v lifecycleLegacySnapshot) lifecycleLegacySnapshot {
	return lifecycleLegacySnapshot{c.text(v.Schema), c.text(v.ControlSHA256), c.text(v.RecordSHA256), v.Revision, lifecycleCloneBytes(v.ControlBytes)}
}

func (c *lifecycleCloneState) anchor(v lifecycleEpochAnchor) lifecycleEpochAnchor {
	return lifecycleEpochAnchor{c.text(v.Kind), c.head(v.InitialHead), lifecycleClonePointer(v.RecoveryID, c.text), c.text(v.SourceControlSHA256)}
}

func (c *lifecycleCloneState) ledger(v lifecycleEpochLedger) lifecycleEpochLedger {
	return lifecycleEpochLedger{c.anchor(v.Anchor), c.head(v.Head), lifecycleClonePointer(v.Owner, c.owner), v.LastFence, lifecycleClonePointer(v.Active, c.active), lifecycleCloneSlice(v.Tombstones, c.tombstone), lifecycleCloneSlice(v.Completed, c.completion), lifecycleCloneSlice(v.Terminated, c.terminal), lifecycleCloneSlice(v.Observations, c.observation)}
}

func (c *lifecycleCloneState) retired(v lifecycleRetiredEpoch) lifecycleRetiredEpoch {
	return lifecycleRetiredEpoch{c.ledger(v.Ledger), c.timestamp(v.RetiredAt), v.CommitRevision, c.text(v.RecoveryID), c.text(v.LedgerSHA256)}
}

func (c *lifecycleCloneState) budgets(v labRecoveryBudgets) labRecoveryBudgets {
	return labRecoveryBudgets{v.StopMillis, v.StartMillis, v.VerificationMillis, v.CommitMillis}
}

func (c *lifecycleCloneState) recoveryPlan(v labRecoveryPlanDescriptor) labRecoveryPlanDescriptor {
	return labRecoveryPlanDescriptor{Schema: c.text(v.Schema), Boundary: c.text(v.Boundary), RecoveryID: c.text(v.RecoveryID),
		UnknownOperationID: c.text(v.UnknownOperationID), OriginalPlanSHA256: c.text(v.OriginalPlanSHA256), OriginalIntentSHA256: c.text(v.OriginalIntentSHA256),
		DeclaredInitiatorRef: c.text(v.DeclaredInitiatorRef), ExpectedRevision: v.ExpectedRevision, ExpectedRecordSHA256: c.text(v.ExpectedRecordSHA256),
		PreviousHeadSHA256: c.text(v.PreviousHeadSHA256), PreviousHeadGeneration: v.PreviousHeadGeneration, Provisioning: c.provisioning(v.Provisioning),
		OldEpochSHA256: c.text(v.OldEpochSHA256), TargetArtifact: c.artifact(v.TargetArtifact), Budgets: c.budgets(v.Budgets), CreatedAt: c.timestamp(v.CreatedAt),
		ExpiresAt: c.timestamp(v.ExpiresAt), Source: lifecycleClonePointer(v.Source, c.recoveryPlanSource), StartMode: c.text(v.StartMode), PlanSHA256: c.text(v.PlanSHA256)}
}

func (c *lifecycleCloneState) recoveryCheckpoint(v lifecycleRecoveryRootCheckpoint) lifecycleRecoveryRootCheckpoint {
	return lifecycleRecoveryRootCheckpoint{Schema: c.text(v.Schema), Revision: v.Revision, RecordSHA256: c.text(v.RecordSHA256), LastTrustedAt: c.timestamp(v.LastTrustedAt),
		RecoveryOwner: lifecycleClonePointer(v.RecoveryOwner, c.owner), LastRecoveryFence: v.LastRecoveryFence, CurrentEpochPosition: v.CurrentEpochPosition,
		CurrentLedgerSHA256: c.text(v.CurrentLedgerSHA256), RetiredPrefixCount: v.RetiredPrefixCount, RetiredPrefixSHA256: c.text(v.RetiredPrefixSHA256),
		RecoveryHistoryPrefixCount: v.RecoveryHistoryPrefixCount, RecoveryHistoryPrefixSHA256: c.text(v.RecoveryHistoryPrefixSHA256), RecoveryKind: c.text(v.RecoveryKind)}
}

func (c *lifecycleCloneState) recoveryPlanSource(v labRecoveryPlanSource) labRecoveryPlanSource {
	return labRecoveryPlanSource{Schema: c.text(v.Schema), Root: c.recoveryCheckpoint(v.Root)}
}

func (c *lifecycleCloneState) recoveryApproval(v lifecycleRecoveryApproval) lifecycleRecoveryApproval {
	return lifecycleRecoveryApproval{c.text(v.Schema), c.text(v.RecoveryPlanSHA256), c.text(v.DeclaredApproverRef), c.timestamp(v.IssuedAt), c.timestamp(v.ExpiresAt), c.text(v.ApprovalSHA256)}
}

func (c *lifecycleCloneState) action(v lifecycleRecoveryActionIntent) lifecycleRecoveryActionIntent {
	return lifecycleRecoveryActionIntent{c.text(v.Schema), c.text(v.Action), c.text(v.RecoveryID), c.text(v.RecoveryPlanSHA256), v.OwnerFence, c.timestamp(v.ArmedAt), c.text(v.IntentSHA256)}
}

func (c *lifecycleCloneState) failure(v lifecycleRecoveryFailure) lifecycleRecoveryFailure {
	return lifecycleRecoveryFailure{c.text(v.Code), c.timestamp(v.At)}
}

func (c *lifecycleCloneState) cleanupProbe(v lifecycleRecoveryCleanupProbe) lifecycleRecoveryCleanupProbe {
	return lifecycleRecoveryCleanupProbe{c.text(v.Role), c.probe(v.Probe), c.timestamp(v.ObservedAt)}
}

func (c *lifecycleCloneState) cleanedKernel(v lifecycleRecoveryCleanedKernel) lifecycleRecoveryCleanedKernel {
	return lifecycleRecoveryCleanedKernel{c.identity(v.Identity), c.exit(v.Exit)}
}

func (c *lifecycleCloneState) cleanup(v lifecycleRecoveryCleanupFact) lifecycleRecoveryCleanupFact {
	return lifecycleRecoveryCleanupFact{c.text(v.Schema), c.text(v.RecoveryID), c.text(v.FailureCode), c.cleanedKernel(v.Old),
		lifecycleClonePointer(v.New, c.cleanedKernel), lifecycleClonePointer(v.Attempt, c.startObservation), lifecycleCloneSlice(v.Probes, c.cleanupProbe), c.text(v.SourceReceiptSHA256), c.timestamp(v.ObservedAt), c.text(v.CleanupSHA256)}
}

func (c *lifecycleCloneState) reconciliation(v lifecycleRecoveryReconciliation) lifecycleRecoveryReconciliation {
	return lifecycleRecoveryReconciliation{c.text(v.Schema), c.recoveryCheckpoint(v.OriginalUnknownRoot), c.timestamp(v.OriginalTxnUpdatedAt),
		c.cleanup(v.Cleanup), v.CommitRevision, c.timestamp(v.ReconciledAt)}
}

func (c *lifecycleCloneState) recoveryCompletion(v lifecycleRecoveryCompletion) lifecycleRecoveryCompletion {
	return lifecycleRecoveryCompletion{c.head(v.PreviousHead), c.head(v.Head), c.text(v.EvidenceSHA256), v.CommitRevision, c.timestamp(v.CommittedAt)}
}

func (c *lifecycleCloneState) identity(v labKernelIdentity) labKernelIdentity {
	return labKernelIdentity{v.PID, v.StartTicks, v.NetNSInode, c.text(v.ELFSHA256), v.ELFBytes, c.text(v.SourceCommit), c.text(v.ArtifactSHA256), v.ControllerPort, v.MixedPort}
}

func (c *lifecycleCloneState) stream(v labKernelStream) labKernelStream {
	return labKernelStream{v.Bytes, v.TotalBytes, c.text(v.SHA256), v.Truncated, v.Complete}
}

func (c *lifecycleCloneState) exit(v labKernelExit) labKernelExit {
	return labKernelExit{v.Started, v.WaitReturned, c.text(v.WaitErrorClass), lifecycleClonePointer(v.ExitCode, lifecycleCloneScalar[int]), lifecycleClonePointer(v.Signal, lifecycleCloneScalar[int]), v.TermSent, v.KillSent, lifecycleClonePointer(v.GroupAbsent, lifecycleCloneScalar[bool]), c.stream(v.Stdout), c.stream(v.Stderr)}
}

func (c *lifecycleCloneState) binding(v labQuiescenceBinding) labQuiescenceBinding {
	return labQuiescenceBinding{c.text(v.RecoveryID), c.text(v.RecoveryPlanSHA256), c.text(v.StopIntentSHA256), c.text(v.OldEpochSHA256), c.identity(v.ExpectedOldIdentity), c.timestamp(v.ArmedAt), c.timestamp(v.ExpiresAt)}
}

func (c *lifecycleCloneState) probe(v labQuiescenceProbe) labQuiescenceProbe {
	return labQuiescenceProbe{v.Port, v.Attempted, c.text(v.Result)}
}

func (c *lifecycleCloneState) quiescenceObservation(v labQuiescenceObservation) labQuiescenceObservation {
	return labQuiescenceObservation{c.text(v.Schema), lifecycleClonePointer(v.StartupIdentity, c.identity), v.StopInvoked, v.StopReturned, lifecycleClonePointer(v.StopErrorClass, c.text), lifecycleClonePointer(v.Stop, c.exit), lifecycleClonePointer(v.NamespaceInode, lifecycleCloneScalar[uint64]), lifecycleClonePointer(v.ControllerProbe, c.probe), lifecycleClonePointer(v.MixedProbe, c.probe), lifecycleClonePointer(v.StartedAt, c.timestamp), lifecycleClonePointer(v.ReturnedAt, c.timestamp), c.text(v.Outcome), c.text(v.FailureCode)}
}

func (c *lifecycleCloneState) fact(v labQuiescenceFact) labQuiescenceFact {
	return labQuiescenceFact{c.text(v.Schema), c.binding(v.Binding), c.quiescenceObservation(v.Observation), c.timestamp(v.ObservedAt), c.text(v.QuiescenceSHA256)}
}

func (c *lifecycleCloneState) kernelStartObservation(v labKernelStartObservation) labKernelStartObservation {
	return labKernelStartObservation{v.Attempted, lifecycleClonePointer(v.Started, lifecycleCloneScalar[bool]), lifecycleClonePointer(v.PID, lifecycleCloneScalar[int]), lifecycleClonePointer(v.StartTicks, lifecycleCloneScalar[uint64]), lifecycleClonePointer(v.WaitReturned, lifecycleCloneScalar[bool]), c.text(v.WaitErrorClass), lifecycleClonePointer(v.ExitCode, lifecycleCloneScalar[int]), lifecycleClonePointer(v.Signal, lifecycleCloneScalar[int]), lifecycleClonePointer(v.TermSent, lifecycleCloneScalar[bool]), lifecycleClonePointer(v.KillSent, lifecycleCloneScalar[bool]), lifecycleClonePointer(v.GroupAbsent, lifecycleCloneScalar[bool]), lifecycleClonePointer(v.Stdout, c.stream), lifecycleClonePointer(v.Stderr, c.stream)}
}

func (c *lifecycleCloneState) startObservation(v labRecoveryStartObservation) labRecoveryStartObservation {
	return labRecoveryStartObservation{c.text(v.Schema), v.PermitConsumed, v.StartInvoked, v.StartReturned, lifecycleClonePointer(v.StartErrorClass, c.text), lifecycleClonePointer(v.StartObservation, c.kernelStartObservation), lifecycleClonePointer(v.StartupIdentity, c.identity), lifecycleClonePointer(v.VerifiedIdentity, c.identity), lifecycleClonePointer(v.NamespaceInode, lifecycleCloneScalar[uint64]), lifecycleClonePointer(v.ListenersBefore, lifecycleCloneScalar[bool]), lifecycleClonePointer(v.ListenersAfter, lifecycleCloneScalar[bool]), lifecycleClonePointer(v.StartedAt, c.timestamp), lifecycleClonePointer(v.ReturnedAt, c.timestamp), c.text(v.Outcome), c.text(v.FailureCode)}
}

func (c *lifecycleCloneState) startedBinding(v labRecoveryStartedBinding) labRecoveryStartedBinding {
	return labRecoveryStartedBinding{RecoveryID: c.text(v.RecoveryID), RecoveryPlanSHA256: c.text(v.RecoveryPlanSHA256), StartIntentSHA256: c.text(v.StartIntentSHA256),
		Revision: v.Revision, RecordSHA256: c.text(v.RecordSHA256), TargetArtifact: c.artifact(v.TargetArtifact), QuiescenceSHA256: c.text(v.QuiescenceSHA256),
		ArmedAt: c.timestamp(v.ArmedAt), ExpiresAt: c.timestamp(v.ExpiresAt), ExpectedOldIdentity: c.identity(v.ExpectedOldIdentity), StartMillis: v.StartMillis,
		StartMode: c.text(v.StartMode), AbsenceCleanupSHA256: c.text(v.AbsenceCleanupSHA256)}
}

func (c *lifecycleCloneState) startedFact(v labRecoveryStartedFact) labRecoveryStartedFact {
	return labRecoveryStartedFact{c.text(v.Schema), c.startedBinding(v.Binding), c.startObservation(v.Observation), c.timestamp(v.ObservedAt), c.text(v.StartedSHA256)}
}

func (c *lifecycleCloneState) execution(v lifecycleRecoveryExecution) lifecycleRecoveryExecution {
	return lifecycleRecoveryExecution{Schema: c.text(v.Schema), Started: c.startedFact(v.Started), ArmedOwner: c.owner(v.ArmedOwner),
		ArmedLastTrustedAt: c.timestamp(v.ArmedLastTrustedAt), ArmedLastRecoveryFence: v.ArmedLastRecoveryFence, ArmedRecoveryUpdatedAt: c.timestamp(v.ArmedRecoveryUpdatedAt),
		ArmedFailedQuiescence: lifecycleCloneSlice(v.ArmedFailedQuiescence, c.quiescenceObservation), StartedCommitRevision: v.StartedCommitRevision,
		RecordedAt: c.timestamp(v.RecordedAt), Verification: lifecycleClonePointer(v.Verification, c.verification),
		CompletionSource: lifecycleClonePointer(v.CompletionSource, c.recoveryCompletionSource)}
}

func (c *lifecycleCloneState) recoveryCompletionSource(v lifecycleRecoveryCompletionSource) lifecycleRecoveryCompletionSource {
	return lifecycleRecoveryCompletionSource{Schema: c.text(v.Schema), Root: c.recoveryCheckpoint(v.Root), CommitDeadline: c.timestamp(v.CommitDeadline)}
}

func (c *lifecycleCloneState) verificationSample(v labRecoverySampleWindow) labRecoverySampleWindow {
	return labRecoverySampleWindow{c.timestamp(v.StartedAt), c.timestamp(v.CompletedAt)}
}

func (c *lifecycleCloneState) verificationReadback(v mihomo.LabTargetReadbackReport) mihomo.LabTargetReadbackReport {
	return mihomo.LabTargetReadbackReport{c.text(v.Schema), mihomo.LabTargetReadbackConclusion(c.text(string(v.Conclusion))), v.SampleCount, v.RequestsObserved, c.text(v.TargetProjectionSHA256), lifecycleClonePointer(v.ObservedProjectionSHA256, c.text), v.DataplaneProven, v.FullPayloadProven, v.AuthorizationProven, v.Production}
}

func (c *lifecycleCloneState) localBody(v labLocalBody) labLocalBody {
	return labLocalBody{c.text(v.SHA256), v.Bytes, v.Complete}
}

func (c *lifecycleCloneState) localCounter(v labLocalCounter) labLocalCounter {
	return labLocalCounter{c.text(v.Role), v.ConnectIngress, v.TunnelRequests, v.ForwardInvocations, v.OriginRequests, v.Rejected}
}

func (c *lifecycleCloneState) localRoute(v labLocalRoute) labLocalRoute {
	return labLocalRoute{c.text(v.Phase), c.text(v.NonceSHA256), lifecycleClonePointer(v.ClientResponse, c.localBody), lifecycleClonePointer(v.ProxyResponse, c.localBody), lifecycleClonePointer(v.OriginResponse, c.localBody), lifecycleCloneSlice(v.CountersBefore, c.localCounter), lifecycleCloneSlice(v.CountersAfter, c.localCounter), v.Matched}
}

func (c *lifecycleCloneState) localMarker(v labRecoveryLocalMarkerValue) labRecoveryLocalMarkerValue {
	return labRecoveryLocalMarkerValue{c.text(v.Schema), c.text(v.Scope), c.text(v.ExpectedRole), c.text(v.ExpectedMarkerSHA256), v.ExpectedMarkerBytes, c.timestamp(v.StartedAt), c.timestamp(v.ReturnedAt), v.HandlerCompleted, v.ClientNaturalEOF, v.ProxyNaturalEOF, v.OriginWriteComplete, v.LocalProxyMarkerProven, c.localRoute(v.Route)}
}

func (c *lifecycleCloneState) verificationObserved(v lifecycleRecoveryObservedFact) lifecycleRecoveryObservedFact {
	return lifecycleRecoveryObservedFact{c.text(v.Schema), c.text(v.RecoveryID), c.text(v.PlanSHA256), c.text(v.StartIntentSHA256), c.text(v.StartedSHA256), v.SourceRevision, c.text(v.SourceRecordSHA256), v.OwnerFence, c.artifact(v.Artifact), c.identity(v.StartupIdentity), c.timestamp(v.EntryAt), c.timestamp(v.Deadline), lifecycleCloneSlice(v.SampleTimes, c.verificationSample), c.timestamp(v.ObservedAt), c.verificationReadback(v.Readback), c.text(v.TranscriptSHA256), lifecycleCloneSlice(v.BodySHA256s, c.text), c.text(v.VerificationSHA256), lifecycleClonePointer(v.LocalPath, c.localMarker), c.text(v.LocalMarkerSHA256)}
}

func (c *lifecycleCloneState) verification(v lifecycleRecoveryVerification) lifecycleRecoveryVerification {
	return lifecycleRecoveryVerification{c.text(v.Schema), c.verificationObserved(v.Observation), c.text(v.ObservationSHA256), c.owner(v.SourceOwner), c.timestamp(v.SourceLastTrustedAt), v.SourceLastRecoveryFence, c.timestamp(v.SourceRecoveryUpdatedAt), lifecycleCloneSlice(v.SourceFailedQuiescence, c.quiescenceObservation), v.VerificationCommitRevision, c.timestamp(v.RecordedAt)}
}

func (c *lifecycleCloneState) recovery(v lifecycleRecoveryTxn) lifecycleRecoveryTxn {
	return lifecycleRecoveryTxn{c.recoveryPlan(v.Plan), c.text(v.Phase), lifecycleClonePointer(v.Approval, c.recoveryApproval), lifecycleClonePointer(v.Revocation, c.revocation), lifecycleClonePointer(v.StopIntent, c.action), lifecycleClonePointer(v.StopBinding, c.binding), lifecycleClonePointer(v.Quiescence, c.fact), lifecycleCloneSlice(v.FailedQuiescence, c.quiescenceObservation), lifecycleClonePointer(v.StartIntent, c.action), lifecycleClonePointer(v.Completion, c.recoveryCompletion), lifecycleClonePointer(v.Failure, c.failure), c.timestamp(v.UpdatedAt), lifecycleClonePointer(v.Execution, c.execution), lifecycleClonePointer(v.Reconciliation, c.reconciliation)}
}

func (c *lifecycleCloneState) wire(v lifecycleV3Wire) lifecycleV3Wire {
	return lifecycleV3Wire{c.text(v.Schema), c.text(v.Boundary), v.Revision, c.text(v.RecordSHA256), c.timestamp(v.LastTrustedAt), c.provisioning(v.Provisioning), c.source(v.SourceV2), c.ledger(v.Current), lifecycleCloneSlice(v.RetiredEpochs, c.retired), lifecycleClonePointer(v.RecoveryOwner, c.owner), v.LastRecoveryFence, lifecycleClonePointer(v.Recovery, c.recovery), lifecycleCloneSlice(v.RecoveryHistory, c.recovery)}
}
