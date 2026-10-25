package mihomodeploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"chengwang/internal/authz"
)

const lifecycleRecoveryCompletionSourceSchema = "chengwang.mihomo-recovery-completion-source/v1"

type lifecycleRecoveryCompletionSource struct {
	Schema         string                          `json:"schema"`
	Root           lifecycleRecoveryRootCheckpoint `json:"root"`
	CommitDeadline time.Time                       `json:"commitDeadline"`
}

// Durable S2 custody is issued only after the exact verification candidate was
// replaced, read back, and validated. It is process-local and never reopened.
type labRecoveryVerifiedCustody struct {
	store     *lifecycleRecoveryStoreCore
	disk      lifecycleDisk
	owner     *lifecycleRecoveryOwnerCore
	started   *labRecoveryStartedCustody
	record    *labRecoveryVerificationRecordCore
	canonical string
	claimed   bool
	binding   func(*labRecoveryVerifiedCustody, *lifecycleRecoveryStoreCore) bool
}

func (c *labRecoveryVerifiedCustody) matches(x *lifecycleRecoveryStoreCore) bool {
	if c == nil || x == nil || c.binding == nil || !c.binding(c, x) || x.retainedVerified != c || x.closed || x.poisoned || x.live != c.owner ||
		!lifecycleRecoverySameDisk(x.disk, c.disk) || string(x.raw) != c.canonical || x.record.core == nil || x.record.core.Recovery == nil ||
		x.record.core.Recovery.Execution == nil || x.record.core.Recovery.Execution.Schema != lifecycleRecoveryVerifiedExecutionSchema ||
		x.record.core.Recovery.Execution.Verification == nil || x.record.core.Recovery.Execution.CompletionSource != nil {
		return false
	}
	return c.record != nil && c.started != nil && c.record.custody == c.started && reflect.DeepEqual(x.record.core.Recovery.Execution.Verification.Observation, c.record.value)
}

func (labRecoveryVerifiedCustody) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (*labRecoveryVerifiedCustody) UnmarshalJSON([]byte) error  { return errLifecycleUnsafe }
func (labRecoveryVerifiedCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private recorded verification custody")
}

type labRecoveryCompletionCap struct{ core *labRecoveryCompletionCapCore }
type labRecoveryCompletionCapCore struct {
	collector *labRecoveryCollector
	custody   *labRecoveryVerifiedCustody
	store     *lifecycleRecoveryStoreCore
	disk      lifecycleDisk
	owner     *lifecycleRecoveryOwnerCore
	caller    context.Context
	service   context.Context
	canonical string
	deadline  time.Time
	binding   func(*labRecoveryCompletionCapCore) bool
}

type labRecoveryCompletionIssuer struct {
	mu     sync.Mutex
	issued map[*labRecoveryCompletionCapCore]bool
}

var processLabRecoveryCompletionIssuer = labRecoveryCompletionIssuer{
	issued: map[*labRecoveryCompletionCapCore]bool{},
}

// consumed is only a registry identity check. The caller must independently
// retain the store lock, exact base and cap bindings, and current S2 custody.
func (i *labRecoveryCompletionIssuer) consumed(c *labRecoveryCompletionCapCore) bool {
	if i == nil || c == nil || c.custody == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return c.custody.claimed && !i.issued[c]
}

func (labRecoveryCompletionCap) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private one-use recovery completion capability")
}
func (labRecoveryCompletionCap) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryCompletionCap) UnmarshalJSON([]byte) error {
	if c != nil {
		c.core = nil
	}
	return errLifecycleUnsafe
}

type labRecoveryCompleteGuard struct {
	base    *labAuthorityCore
	store   *lifecycleRecoveryStoreCore
	custody *labRecoveryVerifiedCustody
}

func (g *labRecoveryCompleteGuard) release() {
	if g != nil && g.store != nil && g.base != nil {
		g.store.mu.Unlock()
		g.base.mu.Unlock()
		g.store, g.base = nil, nil
	}
}

// COMPLETE rechecks all three retained principals under the current policy.
// The returned guard is a point-in-time source observation, not durable or
// externally atomic authorization.
func (a *labRecoveryAuthority) authorizeComplete(headers []string, h *labRecoverySession, expected *labRecoveryVerifiedCustody, now time.Time) (*labRecoveryCompleteGuard, error) {
	c, b, now, err := a.lock(now)
	if err != nil {
		return nil, err
	}
	s, err := c.session(h)
	if err != nil {
		b.mu.Unlock()
		return nil, err
	}
	if err := labRecoveryAuthorityLockStore(s.store, s.owner, true, now); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	g := &labRecoveryCompleteGuard{base: b, store: s.store.core}
	fail := func() (*labRecoveryCompleteGuard, error) {
		g.release()
		return nil, labAuthorityFailure("completion_source_invalid")
	}
	active, err := c.binding(b, s, now, true)
	if err != nil {
		return fail()
	}
	x := s.store.core
	q := x.retainedVerified
	if active.Phase != "START_ARMED" || active.Completion != nil || active.Failure != nil || active.Revocation != nil || active.Execution == nil ||
		active.Execution.Schema != lifecycleRecoveryVerifiedExecutionSchema || active.Execution.Verification == nil || active.Execution.CompletionSource != nil ||
		q == nil || !q.matches(x) || expected != nil && expected != q || now.Before(active.Execution.Verification.RecordedAt) ||
		!now.Before(active.Execution.Verification.Observation.Deadline) {
		return fail()
	}
	p, executorRef, err := b.authenticate(headers, now)
	if err != nil {
		g.release()
		return nil, err
	}
	if err := b.current(s.initiatorRef, s.initiatorID, authz.ActionPrepareLabRecovery, "", "", now); err != nil {
		g.release()
		return nil, err
	}
	if err := b.current(s.approverRef, s.approverID, authz.ActionApproveLabRecovery, s.initiatorID, "", now); err != nil {
		g.release()
		return nil, err
	}
	if err := b.evaluate(p, authz.ActionExecuteLabRecovery, s.initiatorID, s.approverID, now); err != nil {
		g.release()
		return nil, err
	}
	if err := b.current(executorRef, p.ID, authz.ActionExecuteLabRecovery, s.initiatorID, s.approverID, now); err != nil {
		g.release()
		return nil, err
	}
	if x.verify() != nil || !q.matches(x) {
		return fail()
	}
	g.custody = q
	return g, nil
}

func lifecycleRecoveryCompletionDeadline(a *lifecycleRecoveryTxn, owner *lifecycleOwner, now time.Time) (time.Time, bool) {
	if a == nil || a.Execution == nil || a.Execution.Verification == nil || a.Approval == nil || owner == nil || !lifecycleTime(now) {
		return time.Time{}, false
	}
	deadline := now.Add(time.Duration(a.Plan.Budgets.CommitMillis) * time.Millisecond)
	for _, bound := range []time.Time{a.Plan.ExpiresAt, a.Approval.ExpiresAt, owner.ExpiresAt, a.Execution.Verification.Observation.Deadline} {
		if !lifecycleTime(bound) {
			return time.Time{}, false
		}
		if bound.Before(deadline) {
			deadline = bound
		}
	}
	return deadline, now.Before(deadline)
}

// The collector owns the actual new kernel. No fact DTO, durable S2 record, or
// copied guard can issue this completion capability.
func (c *labRecoveryCollector) completionCap(ctx context.Context, headers []string) (*labRecoveryCompletionCap, error) {
	if c == nil || artifactContext(ctx) != nil || c.service == nil || c.service.core == nil {
		return nil, errLabRecoveryCollector
	}
	// Establish the only permitted order before authorizeComplete acquires the
	// base authority and recovery store. Source-owned custody and kernel reads
	// remain enabled; this point-in-time check dispatches no process or HTTP.
	serviceCore := c.service.core
	serviceCore.mu.Lock()
	defer serviceCore.mu.Unlock()
	now := time.Now().UTC()
	guard, err := c.authority.authorizeComplete(headers, c.session, nil, now)
	if err != nil {
		return nil, err
	}
	defer guard.release()
	q := guard.custody
	if q == nil || q.started == nil || !c.currentKernelLocked(serviceCore, q.started) || artifactContext(serviceCore.ctx) != nil {
		return nil, errLabRecoveryCollector
	}
	w := guard.store.record.core
	deadline, ok := lifecycleRecoveryCompletionDeadline(w.Recovery, w.RecoveryOwner, now)
	if !ok {
		return nil, errLabRecoveryCollector
	}
	core := &labRecoveryCompletionCapCore{collector: c, custody: q, store: guard.store, disk: guard.store.disk, owner: q.owner,
		caller: ctx, service: serviceCore.ctx, canonical: q.canonical, deadline: deadline}
	collector, custody, store, disk, owner, caller, service, canonical, sealedDeadline := c, q, guard.store, guard.store.disk, q.owner, ctx, serviceCore.ctx, q.canonical, deadline
	core.binding = func(candidate *labRecoveryCompletionCapCore) bool {
		return candidate == core && candidate.collector == collector && candidate.custody == custody && candidate.store == store && candidate.owner == owner &&
			candidate.canonical == canonical && candidate.deadline.Equal(sealedDeadline) && lifecycleRecoverySameDisk(candidate.disk, disk) &&
			labRecoverySameContext(candidate.caller, caller) && labRecoverySameContext(candidate.service, service)
	}
	i := &processLabRecoveryCompletionIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	admittedAt := time.Now().UTC()
	// authorizeComplete still holds this custody's store mutex here. Claim the
	// exact retained S2 once under that lock; a consumed or rejected cap never
	// makes the custody mintable again.
	if q.claimed || len(i.issued) >= labRecoveryObservationLimit || admittedAt.Before(now) || !admittedAt.Before(deadline) || !core.binding(core) ||
		artifactContext(ctx) != nil || artifactContext(service) != nil || !c.currentKernelLocked(serviceCore, q.started) {
		return nil, errLabRecoveryCollector
	}
	q.claimed = true
	i.issued[core] = true
	return &labRecoveryCompletionCap{core: core}, nil
}

func lifecycleRecoveryCompletionSourceValid(a lifecycleRecoveryTxn, at time.Time, revision uint64) bool {
	if a.Execution == nil || a.Execution.Schema != lifecycleRecoveryCompletedExecutionSchema || a.Execution.Verification == nil || a.Execution.CompletionSource == nil || a.Completion == nil {
		return false
	}
	s := a.Execution.CompletionSource
	return s.Schema == lifecycleRecoveryCompletionSourceSchema && lifecycleRecoveryCheckpointValid(s.Root) && s.Root.RecoveryKind == lifecycleRecoveryCheckpointVerified &&
		s.Root.Revision == a.Execution.Verification.VerificationCommitRevision && s.Root.LastTrustedAt.Equal(a.Execution.Verification.RecordedAt) &&
		lifecycleTime(s.CommitDeadline) && s.CommitDeadline.After(s.Root.LastTrustedAt) && !a.Completion.CommittedAt.After(s.CommitDeadline) &&
		a.Completion.CommitRevision == s.Root.Revision+1 && a.Completion.CommitRevision <= revision && a.Completion.CommittedAt.Equal(a.UpdatedAt) && !a.Completion.CommittedAt.After(at)
}

func lifecycleRecoveryCompletionPreimage(w *lifecycleV3Wire, a lifecycleRecoveryTxn) ([]byte, error) {
	return lifecycleRecoveryCompletionPreimageScoped(w, a, newLifecycleV3DecodeScope())
}

func lifecycleRecoveryCompletionPreimageScoped(w *lifecycleV3Wire, a lifecycleRecoveryTxn, scope *lifecycleV3DecodeScope) ([]byte, error) {
	if scope == nil || w == nil || !lifecycleRecoveryCompletionSourceValid(a, w.LastTrustedAt, w.Revision) {
		return nil, errLifecycleUnsafe
	}
	return lifecycleRecoveryCheckpointPreimageScoped(w, a.Execution.CompletionSource.Root, &a, scope)
}

// lifecycleRecoveryCompletionProspectiveRoot constructs only the final
// revision/time metadata that prepareLifecycleCandidate will later seal. It
// does not mutate the draft, advance the store, skip strict validation, or
// grant publication authority. Production may use it only through the
// cap/base-bound completionPublicationPreimage method below.
func lifecycleRecoveryCompletionProspectiveRoot(w *lifecycleV3Wire, a lifecycleRecoveryTxn) (*lifecycleV3Wire, error) {
	if w == nil || w.Revision == ^uint64(0) || a.Completion == nil || !lifecycleTime(a.Completion.CommittedAt) ||
		a.Completion.CommitRevision != w.Revision+1 || !a.Completion.CommittedAt.Equal(a.UpdatedAt) || a.Completion.CommittedAt.Before(w.LastTrustedAt) {
		return nil, errLifecycleUnsafe
	}
	final := *w
	final.Revision = a.Completion.CommitRevision
	final.LastTrustedAt = a.Completion.CommittedAt
	if !lifecycleRecoveryCompletionSourceValid(a, final.LastTrustedAt, final.Revision) {
		return nil, errLifecycleUnsafe
	}
	return &final, nil
}

type lifecycleCompletionPublication struct {
	base                *lifecycleVerifiedBaseCore
	cap                 *labRecoveryCompletionCapCore
	canonical           string
	preflight           bool
	transitionAttempted bool
	transitionAdmitted  bool
	binding             func(*lifecycleCompletionPublication, *lifecycleRecoveryStoreCore, *lifecycleVerifiedBaseCore, *labRecoveryCompletionCapCore) bool
}

// completionPublicationPreflight retains the original early error boundary
// without reconstructing the full checkpoint root twice. It proves every
// process-local binding and the exact prospective metadata before commit enters
// its transition selector. The transition still performs the sole strict
// checkpoint reconstruction before any candidate can be sealed or published.
func (x *lifecycleRecoveryStoreCore) completionPublicationPreflight(base *lifecycleVerifiedBase, next lifecycleV3Record) (*lifecycleV3Wire, error) {
	p := x.completionRecord
	if p == nil || p.binding == nil || p.cap == nil || base == nil || !base.intact(x) || !p.binding(p, x, base.core, p.cap) ||
		p.cap.binding == nil || !p.cap.binding(p.cap) || p.cap.store != x || p.cap.owner != x.live || !p.cap.custody.matches(x) ||
		!processLabRecoveryCompletionIssuer.consumed(p.cap) || next.core == nil || next.core.Recovery == nil || next.core.Recovery.Completion == nil {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(next.core)
	if err != nil || string(raw) != p.canonical || !next.core.Recovery.Completion.CommittedAt.Before(p.cap.deadline) {
		return nil, errLifecycleUnsafe
	}
	final, err := lifecycleRecoveryCompletionProspectiveRoot(next.core, *next.core.Recovery)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	return final, nil
}

// completionPublicationPreimage is the sole production strict reconstruction
// path. The draft remains at the old root revision/time; a detached metadata
// view reaches the unchanged persisted validator only after preflight bindings.
func (x *lifecycleRecoveryStoreCore) completionPublicationPreimage(base *lifecycleVerifiedBase, next lifecycleV3Record) ([]byte, error) {
	final, err := x.completionPublicationPreflight(base, next)
	if err != nil {
		return nil, err
	}
	return lifecycleRecoveryCompletionPreimage(final, *next.core.Recovery)
}

func (x *lifecycleRecoveryStoreCore) completionRecordTransition(base *lifecycleVerifiedBase, next lifecycleV3Record) bool {
	p := x.completionRecord
	if p == nil || p.binding == nil || base == nil || !p.preflight || p.transitionAttempted || p.transitionAdmitted || next.core == nil || next.core.Recovery == nil {
		return false
	}
	p.transitionAttempted = true
	if next.core.Recovery.Phase != "COMPLETED" || next.core.Recovery.Execution == nil || next.core.Recovery.Execution.Schema != lifecycleRecoveryCompletedExecutionSchema {
		return false
	}
	preimage, err := x.completionPublicationPreimage(base, next)
	if err != nil || !bytes.Equal(preimage, base.core.raw) || !bytes.Equal(preimage, []byte(p.cap.canonical)) {
		return false
	}
	p.transitionAdmitted = true
	return true
}

// Called under the actual store mutex after the final custody/read/CAS check.
// This closes expiry/cancellation during expensive validation. Authorization
// remains a point-in-time check; no cross-store atomic revocation is claimed.
func (x *lifecycleRecoveryStoreCore) completionFreshBeforeReplace(candidate *lifecyclePreparedCandidateCore) bool {
	if x == nil || candidate == nil || candidate.record.core == nil {
		return false
	}
	p := x.completionRecord
	if p == nil || p.cap == nil || p.base == nil || p.binding == nil || !p.preflight || !p.transitionAttempted || !p.transitionAdmitted || candidate.base != p.base ||
		!p.binding(p, x, p.base, p.cap) || p.cap.binding == nil || !p.cap.binding(p.cap) ||
		p.cap.store != x || p.cap.owner != x.live || p.cap.custody == nil || !p.cap.custody.matches(x) ||
		!processLabRecoveryCompletionIssuer.consumed(p.cap) {
		return false
	}
	now := time.Now().UTC()
	return !now.Before(candidate.record.core.LastTrustedAt) && now.Before(p.cap.deadline) &&
		artifactContext(p.cap.caller) == nil && artifactContext(p.cap.service) == nil
}

type lifecycleRecoveryCurrentHandoff struct {
	core *lifecycleRecoveryCurrentHandoffCore
}
type lifecycleRecoveryCurrentHandoffCore struct {
	store        *lifecycleRecoveryStoreCore
	disk         lifecycleDisk
	canonical    string
	epochIndex   uint64
	anchorSHA256 string
	headSHA256   string
	owner        lifecycleOwner
	binding      func(*lifecycleRecoveryCurrentHandoffCore) bool
	used         bool
}
type lifecycleRecoveryCurrentOwnerToken struct {
	core *lifecycleRecoveryCurrentOwnerCore
}
type lifecycleRecoveryCurrentOwnerCore struct {
	store        *lifecycleRecoveryStoreCore
	epochIndex   uint64
	anchorSHA256 string
	nonce        string
	fence        uint64
}

func (lifecycleRecoveryCurrentHandoff) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (h *lifecycleRecoveryCurrentHandoff) UnmarshalJSON([]byte) error {
	if h != nil {
		h.core = nil
	}
	return errLifecycleUnsafe
}
func (lifecycleRecoveryCurrentOwnerToken) MarshalJSON() ([]byte, error) {
	return nil, errLifecycleUnsafe
}
func (t *lifecycleRecoveryCurrentOwnerToken) UnmarshalJSON([]byte) error {
	if t != nil {
		t.core = nil
	}
	return errLifecycleUnsafe
}

func (h *lifecycleRecoveryCurrentHandoff) consumeCurrent(expected *lifecycleRecoveryStoreCore) (*lifecycleRecoveryCurrentOwnerToken, error) {
	if h == nil || h.core == nil || expected == nil {
		return nil, errLifecycleUnsafe
	}
	c := h.core
	x := c.store
	if x != expected {
		return nil, errLifecycleUnsafe
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if c.used {
		return nil, errLifecycleUnsafe
	}
	c.used = true
	if c.binding == nil || !c.binding(c) || x.verify() != nil || x.closed || x.poisoned || !lifecycleRecoverySameDisk(x.disk, c.disk) ||
		string(x.raw) != c.canonical || x.record.core == nil || uint64(len(x.record.core.RetiredEpochs)) != c.epochIndex ||
		x.record.core.Current.Owner == nil || !reflect.DeepEqual(*x.record.core.Current.Owner, c.owner) || x.record.core.Current.LastFence != c.owner.Fence ||
		x.record.core.Current.Head.HeadSHA256 != c.headSHA256 {
		return nil, errLifecycleUnsafe
	}
	anchorSHA, err := lifecycleHash(x.record.core.Current.Anchor)
	if err != nil || anchorSHA != c.anchorSHA256 || x.currentLive != nil {
		return nil, errLifecycleUnsafe
	}
	tokenCore := &lifecycleRecoveryCurrentOwnerCore{store: x, epochIndex: c.epochIndex, anchorSHA256: c.anchorSHA256, nonce: c.owner.OwnerNonce, fence: c.owner.Fence}
	x.currentLive = tokenCore
	return &lifecycleRecoveryCurrentOwnerToken{core: tokenCore}, nil
}

func lifecycleRecoveryNewCurrentOwner(now time.Time) (lifecycleOwner, error) {
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return lifecycleOwner{}, errLifecycleUnsafe
	}
	return lifecycleOwner{OwnerNonce: hex.EncodeToString(nonce[:]), Fence: 1, AcquiredAt: now, RenewedAt: now, ExpiresAt: now.Add(10 * time.Minute)}, nil
}

func (s *lifecycleRecoveryStore) recordRecoveryCompletion(t *lifecycleRecoveryOwnerToken, cap *labRecoveryCompletionCap, now time.Time) (*lifecycleRecoveryCurrentHandoff, error) {
	var core *labRecoveryCompletionCapCore
	if cap != nil {
		core = cap.core
	}
	i := &processLabRecoveryCompletionIssuer
	i.mu.Lock()
	known := core != nil && i.issued[core]
	delete(i.issued, core)
	i.mu.Unlock()
	if !known || core.binding == nil || !core.binding(core) || s == nil || s.core == nil || core.store != s.core ||
		artifactContext(core.caller) != nil || artifactContext(core.service) != nil || core.collector == nil ||
		core.collector.service == nil || core.collector.service.core == nil {
		return nil, errLifecycleUnsafe
	}
	// Keep the source-owned service stable before entering the store. The lock
	// intentionally spans canonical reconstruction, disk CAS/fsync and readback;
	// this blocks service inspection/close for the commit but prevents a store
	// -> service edge. External authority remains a point-in-time check.
	serviceCore := core.collector.service.core
	serviceCore.mu.Lock()
	defer serviceCore.mu.Unlock()
	if !core.collector.currentKernelLocked(serviceCore, core.custody.started) {
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
	actualNow := time.Now().UTC()
	if x.token(t, true, now) != nil || x.live != core.owner || !lifecycleRecoverySameDisk(x.disk, core.disk) || now.After(actualNow) ||
		!now.Before(core.deadline) || !actualNow.Before(core.deadline) || !core.custody.matches(x) {
		return nil, errLifecycleUnsafe
	}
	source, err := decodeLifecycleV3Record([]byte(core.canonical))
	if err != nil || source.core.Recovery == nil || source.core.RecoveryOwner == nil || !reflect.DeepEqual(source.core, x.record.core) {
		return nil, errLifecycleUnsafe
	}
	a := source.core.Recovery
	if a.Phase != "START_ARMED" || a.Completion != nil || a.Failure != nil || a.Revocation != nil || a.Execution == nil ||
		a.Execution.Schema != lifecycleRecoveryVerifiedExecutionSchema || a.Execution.Verification == nil || a.Execution.CompletionSource != nil ||
		now.Before(a.Execution.Verification.RecordedAt) {
		return nil, errLifecycleUnsafe
	}
	next, err := base.copyRecord()
	if err != nil || next.core.Revision == ^uint64(0) || next.core.Current.Head.Generation >= ^uint64(0)-1 ||
		len(next.core.RetiredEpochs) >= maxLifecycleHistory || len(next.core.RecoveryHistory) >= maxLifecycleHistory {
		return nil, errLifecycleUnsafe
	}
	checkpoint, err := lifecycleRecoveryCheckpoint(source.core, lifecycleRecoveryCheckpointVerified)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	b := next.core.Recovery
	b.Execution.Schema = lifecycleRecoveryCompletedExecutionSchema
	b.Execution.CompletionSource = &lifecycleRecoveryCompletionSource{Schema: lifecycleRecoveryCompletionSourceSchema, Root: checkpoint, CommitDeadline: core.deadline}
	previous := next.core.Current.Head
	observation := b.Execution.Verification.Observation
	id := observation.StartupIdentity
	head := previous
	head.Generation++
	head.Artifact = cloneArtifactDescriptor(b.Plan.TargetArtifact)
	head.KernelSHA256, head.PID, head.StartTicks, head.NetNSInode = id.ELFSHA256, id.PID, id.StartTicks, id.NetNSInode
	head.ControllerPort, head.MixedPort = id.ControllerPort, id.MixedPort
	prior := previous.HeadSHA256
	head.PreviousHeadSHA256 = &prior
	head.VerificationSHA256, head.VerifiedAt = observation.VerificationSHA256, observation.ObservedAt
	head.HeadSHA256, err = lifecycleHeadHash(head)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	commitRevision := next.core.Revision + 1
	b.Phase = "COMPLETED"
	b.Completion = &lifecycleRecoveryCompletion{PreviousHead: previous, Head: head, EvidenceSHA256: observation.VerificationSHA256, CommitRevision: commitRevision, CommittedAt: now}
	b.UpdatedAt = now
	retiredSHA, err := lifecycleHash(next.core.Current)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	next.core.RetiredEpochs = append(next.core.RetiredEpochs, lifecycleRetiredEpoch{Ledger: next.core.Current, RetiredAt: now, CommitRevision: commitRevision, RecoveryID: b.Plan.RecoveryID, LedgerSHA256: retiredSHA})
	next.core.RecoveryHistory = append(next.core.RecoveryHistory, *b)
	newOwner, err := lifecycleRecoveryNewCurrentOwner(now)
	if err != nil {
		return nil, err
	}
	recoveryID := b.Plan.RecoveryID
	next.core.Current = lifecycleEpochLedger{Anchor: lifecycleEpochAnchor{Kind: "RECOVERED_EPOCH", InitialHead: head, RecoveryID: &recoveryID, SourceControlSHA256: next.core.SourceV2.ControlSHA256},
		Head: head, Owner: &newOwner, LastFence: newOwner.Fence, Tombstones: []lifecycleTombstone{}, Completed: []lifecycleCompletion{}, Terminated: []lifecycleTerminalArchive{}, Observations: []lifecycleObservationRecord{}}
	canonical, err := json.Marshal(next.core)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	proof := &lifecycleCompletionPublication{base: base.core, cap: core, canonical: string(canonical)}
	x.completionRecord = proof
	defer func() { x.completionRecord = nil }()
	image := proof.canonical
	issued := core
	proof.binding = func(candidate *lifecycleCompletionPublication, owner *lifecycleRecoveryStoreCore, original *lifecycleVerifiedBaseCore, cap *labRecoveryCompletionCapCore) bool {
		return candidate == proof && owner == x && original == base.core && cap == issued && candidate.base == original && candidate.cap == issued && candidate.canonical == image
	}
	if _, err := x.completionPublicationPreflight(base, next); err != nil {
		return nil, errLifecycleUnsafe
	}
	proof.preflight = true
	if err := x.commitWithBase(base, next, now); err != nil {
		// Before this optimization, strict-preimage rejection happened in the
		// early preflight and did not poison the store. Preserve that boundary;
		// once the transition was admitted, every later failure remains sticky.
		if !proof.transitionAttempted || proof.transitionAdmitted {
			x.poisoned = true
			x.live, x.retainedStarted, x.retainedVerified, x.currentLive = nil, nil, nil, nil
			x.validated = nil
		}
		return nil, err
	}
	x.retainedStarted, x.retainedVerified = nil, nil
	anchorSHA, err := lifecycleHash(x.record.core.Current.Anchor)
	if err != nil {
		x.poisoned = true
		x.live, x.currentLive, x.validated = nil, nil, nil
		return nil, errLifecycleUnsafe
	}
	h := &lifecycleRecoveryCurrentHandoffCore{store: x, disk: x.disk, canonical: string(x.raw), epochIndex: uint64(len(x.record.core.RetiredEpochs)),
		anchorSHA256: anchorSHA, headSHA256: x.record.core.Current.Head.HeadSHA256, owner: newOwner}
	store, disk, sealed, epoch, anchor, sealedHeadSHA, owner := x, x.disk, h.canonical, h.epochIndex, h.anchorSHA256, h.headSHA256, h.owner
	h.binding = func(candidate *lifecycleRecoveryCurrentHandoffCore) bool {
		return candidate == h && candidate.store == store && lifecycleRecoverySameDisk(candidate.disk, disk) && candidate.canonical == sealed && candidate.epochIndex == epoch &&
			candidate.anchorSHA256 == anchor && candidate.headSHA256 == sealedHeadSHA && reflect.DeepEqual(candidate.owner, owner)
	}
	return &lifecycleRecoveryCurrentHandoff{core: h}, nil
}
