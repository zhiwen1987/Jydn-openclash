package mihomodeploy

import (
	"fmt"
	"io"
	"reflect"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

const labRecoveryAuthorityDebug = "private current recovery authorization check; not an execution permit"
const maxLabRecoveryAuthorityBindings = 256

type labRecoveryAuthority struct{ core *labRecoveryAuthorityCore }
type labRecoveryInitiator struct{ core *labRecoveryInitiatorCore }
type labRecoverySession struct{ core *labRecoverySessionCore }
type labRecoveryCheck struct{ core *labRecoveryCheckCore }

// The existing authority mutex protects ALL these fields. There is no second
// manager, clock, caller-principal factory, independently ordered mutex or
// serialized source of identity. Base and manager remain borrowed.
type labRecoveryAuthorityCore struct {
	base       *labAuthority
	initiators map[*labRecoveryInitiator]*labRecoveryInitiatorCore
	sessions   map[*labRecoverySession]*labRecoverySessionCore
	closed     bool
}
type labRecoveryInitiatorCore struct {
	authority *labRecoveryAuthorityCore
	id        string
	ref       authn.SnapshotRef
	actorRef  string
}
type labRecoverySessionCore struct {
	authority      *labRecoveryAuthorityCore
	store          *lifecycleRecoveryStore
	storeCore      *lifecycleRecoveryStoreCore
	owner          *lifecycleRecoveryOwnerToken
	fence          uint64
	plan           labRecoveryPlanDescriptor
	boundRevision  uint64
	initiatorID    string
	initiatorRef   authn.SnapshotRef
	initiatorActor string
	approverID     string
	approverRef    authn.SnapshotRef
	material       *lifecycleRecoveryApproval
}
type labRecoveryCheckCore struct {
	action       string
	actorRef     string
	recoveryID   string
	planSHA256   string
	revision     uint64
	recordSHA256 string
	fence        uint64
	intentSHA256 string
}

func labRecoveryAuthorityJSON() []byte {
	return []byte(`{"scope":"CURRENT_RECOVERY_AUTHORIZATION_CHECK_NOT_EXECUTION"}`)
}
func (labRecoveryAuthority) String() string   { return labRecoveryAuthorityDebug }
func (labRecoveryAuthority) GoString() string { return labRecoveryAuthorityDebug }
func (labRecoveryAuthority) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, labRecoveryAuthorityDebug)
}
func (labRecoveryAuthority) MarshalJSON() ([]byte, error) { return labRecoveryAuthorityJSON(), nil }
func (labRecoveryInitiator) String() string               { return labRecoveryAuthorityDebug }
func (labRecoveryInitiator) GoString() string             { return labRecoveryAuthorityDebug }
func (labRecoveryInitiator) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, labRecoveryAuthorityDebug)
}
func (labRecoveryInitiator) MarshalJSON() ([]byte, error) { return labRecoveryAuthorityJSON(), nil }
func (labRecoverySession) String() string                 { return labRecoveryAuthorityDebug }
func (labRecoverySession) GoString() string               { return labRecoveryAuthorityDebug }
func (labRecoverySession) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, labRecoveryAuthorityDebug)
}
func (labRecoverySession) MarshalJSON() ([]byte, error) { return labRecoveryAuthorityJSON(), nil }
func (labRecoveryCheck) String() string                 { return labRecoveryAuthorityDebug }
func (labRecoveryCheck) GoString() string               { return labRecoveryAuthorityDebug }
func (labRecoveryCheck) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, labRecoveryAuthorityDebug)
}
func (labRecoveryCheck) MarshalJSON() ([]byte, error) { return labRecoveryAuthorityJSON(), nil }
func (a *labRecoveryAuthority) UnmarshalJSON([]byte) error {
	if a != nil {
		a.core = nil
	}
	return labAuthorityFailure("binding_invalid")
}
func (h *labRecoveryInitiator) UnmarshalJSON([]byte) error {
	if h != nil {
		h.core = nil
	}
	return labAuthorityFailure("binding_invalid")
}
func (s *labRecoverySession) UnmarshalJSON([]byte) error {
	if s != nil {
		s.core = nil
	}
	return labAuthorityFailure("binding_invalid")
}
func (c *labRecoveryCheck) UnmarshalJSON([]byte) error {
	if c != nil {
		c.core = nil
	}
	return labAuthorityFailure("binding_invalid")
}

func newLabRecoveryAuthority(base *labAuthority, now time.Time) (*labRecoveryAuthority, error) {
	if base == nil || base.core == nil || !lifecycleTime(now) {
		return nil, labAuthorityFailure("configuration_invalid")
	}
	b, _, err := base.lock(now)
	if err != nil {
		return nil, err
	}
	defer b.mu.Unlock()
	if b.manager == nil || b.scope.ObjectType != LabObjectType || b.scope.Environment != LabEnvironment {
		return nil, labAuthorityFailure("configuration_invalid")
	}
	for _, v := range []string{b.scope.TenantID, b.scope.SiteID, b.scope.ObjectType, b.scope.ObjectID, b.scope.Environment} {
		if !planReference.MatchString(v) {
			return nil, labAuthorityFailure("configuration_invalid")
		}
	}
	return &labRecoveryAuthority{core: &labRecoveryAuthorityCore{base: base, initiators: map[*labRecoveryInitiator]*labRecoveryInitiatorCore{}, sessions: map[*labRecoverySession]*labRecoverySessionCore{}}}, nil
}

// Returns the one existing base mutex locked. A base poison/close retires all
// recovery methods too; this wrapper cannot recover a new clock or manager.
func (a *labRecoveryAuthority) lock(now time.Time) (*labRecoveryAuthorityCore, *labAuthorityCore, time.Time, error) {
	if a == nil || a.core == nil || a.core.base == nil || a.core.base.core == nil {
		return nil, nil, time.Time{}, labAuthorityFailure("authority_unavailable")
	}
	c := a.core
	// Reject a noncanonical clock through the same base poison path, instead
	// of creating a separate wrapper clock which could revive stale sessions.
	if !lifecycleTime(now) {
		now = time.Time{}
	}
	b, now, err := c.base.lock(now)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if c.closed || c.initiators == nil || c.sessions == nil {
		b.mu.Unlock()
		return nil, nil, time.Time{}, labAuthorityFailure("authority_closed")
	}
	return c, b, now, nil
}

func (a *labRecoveryAuthority) captureInitiator(headers []string, now time.Time) (*labRecoveryInitiator, error) {
	c, b, now, err := a.lock(now)
	if err != nil {
		return nil, err
	}
	defer b.mu.Unlock()
	p, ref, err := b.authenticate(headers, now)
	if err != nil {
		return nil, err
	}
	if err := b.evaluate(p, authz.ActionPrepareLabRecovery, "", "", now); err != nil {
		return nil, err
	}
	if len(c.initiators)+len(c.sessions) >= maxLabRecoveryAuthorityBindings {
		return nil, labAuthorityFailure("binding_limit")
	}
	h := &labRecoveryInitiator{core: &labRecoveryInitiatorCore{c, p.ID, ref, labActorReference(b.scope, p.ID)}}
	c.initiators[h] = h.core
	return h, nil
}
func (a *labRecoveryAuthority) initiatorReference(h *labRecoveryInitiator) (string, error) {
	if a == nil || a.core == nil || a.core.base == nil || a.core.base.core == nil {
		return "", labAuthorityFailure("authority_unavailable")
	}
	c, b := a.core, a.core.base.core
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.closed || b.closed || b.poisoned || h == nil || h.core == nil || c.initiators[h] != h.core || h.core.authority != c {
		return "", labAuthorityFailure("binding_invalid")
	}
	return h.core.actorRef, nil
}
func (a *labRecoveryAuthority) discardInitiator(h *labRecoveryInitiator) {
	if a == nil || a.core == nil || a.core.base == nil || a.core.base.core == nil {
		return
	}
	c, b := a.core, a.core.base.core
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(c.initiators, h)
}

// Call only under base.core.mu. Never call an authority method while already
// holding the store mutex. No external process/HTTP action happens under it.
func labRecoveryAuthorityLockStore(s *lifecycleRecoveryStore, o *lifecycleRecoveryOwnerToken, fresh bool, now time.Time) error {
	if s == nil || s.core == nil {
		return labAuthorityFailure("binding_invalid")
	}
	x := s.core
	x.mu.Lock()
	if err := x.verify(); err != nil {
		x.mu.Unlock()
		return labAuthorityFailure("wal_unavailable")
	}
	if err := x.token(o, fresh, now); err != nil {
		x.mu.Unlock()
		return labAuthorityFailure("owner_invalid")
	}
	return nil
}

func (a *labRecoveryAuthority) bindPlan(h *labRecoveryInitiator, store *lifecycleRecoveryStore, owner *lifecycleRecoveryOwnerToken, now time.Time) (*labRecoverySession, error) {
	c, b, now, err := a.lock(now)
	if err != nil {
		return nil, err
	}
	defer b.mu.Unlock()
	if h == nil || h.core == nil || c.initiators[h] != h.core || h.core.authority != c || len(c.sessions) >= maxLabRecoveryAuthorityBindings {
		return nil, labAuthorityFailure("binding_invalid")
	}
	if err := labRecoveryAuthorityLockStore(store, owner, true, now); err != nil {
		return nil, err
	}
	defer store.core.mu.Unlock()
	w := store.core.record.core
	if w == nil || w.Current.Head.Scope != b.scope || w.Current.Head.DeviceRef != b.scope.ObjectID || w.RecoveryOwner == nil || w.Recovery == nil || w.Recovery.Phase != "PLANNED" || w.Recovery.Revocation != nil || w.Recovery.Approval != nil || w.Recovery.StopIntent != nil || w.Recovery.Plan.DeclaredInitiatorRef != h.core.actorRef {
		return nil, labAuthorityFailure("binding_invalid")
	}
	original, err := lifecycleV3Source(w)
	if err != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	p, err := labRecoveryPlanFromDescriptor(w.Recovery.Plan, original)
	if err != nil || p.validAt(now) != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	for _, s := range c.sessions {
		if s.storeCore == store.core && s.plan.RecoveryID == w.Recovery.Plan.RecoveryID {
			return nil, labAuthorityFailure("binding_exists")
		}
	}
	if err := b.current(h.core.ref, h.core.id, authz.ActionPrepareLabRecovery, "", "", now); err != nil {
		return nil, err
	}
	if err := store.core.verify(); err != nil {
		return nil, labAuthorityFailure("wal_unavailable")
	}
	s := &labRecoverySession{core: &labRecoverySessionCore{authority: c, store: store, storeCore: store.core, owner: owner, fence: w.RecoveryOwner.Fence,
		plan: p.descriptor(), boundRevision: w.Revision, initiatorID: h.core.id, initiatorRef: h.core.ref, initiatorActor: h.core.actorRef}}
	c.sessions[s] = s.core
	delete(c.initiators, h)
	return s, nil
}
func (c *labRecoveryAuthorityCore) session(h *labRecoverySession) (*labRecoverySessionCore, error) {
	if h == nil || h.core == nil || h.core.authority != c || c.sessions[h] != h.core {
		return nil, labAuthorityFailure("session_invalid")
	}
	return h.core, nil
}

// Caller holds base and the exact bound store mutex. Structural WAL material
// does not replace the actual retained SnapshotRefs/current policy below.
func (c *labRecoveryAuthorityCore) binding(b *labAuthorityCore, s *labRecoverySessionCore, now time.Time, approved bool) (*lifecycleRecoveryTxn, error) {
	if s.store == nil || s.store.core == nil || s.store.core != s.storeCore {
		return nil, labAuthorityFailure("binding_invalid")
	}
	w := s.store.core.record.core
	if w == nil || w.RecoveryOwner == nil || w.RecoveryOwner.Fence != s.fence || w.Revision < s.boundRevision || w.Current.Head.Scope != b.scope || w.Current.Head.DeviceRef != b.scope.ObjectID ||
		w.Recovery == nil || !reflect.DeepEqual(w.Recovery.Plan, s.plan) || w.Recovery.Plan.DeclaredInitiatorRef != s.initiatorActor || w.Recovery.Revocation != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	original, err := lifecycleV3Source(w)
	if err != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	p, err := labRecoveryPlanFromDescriptor(w.Recovery.Plan, original)
	if err != nil || p.validAt(now) != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	if approved {
		a := w.Recovery.Approval
		if s.material == nil || s.approverID == "" || a == nil || !reflect.DeepEqual(*a, *s.material) || !now.Before(a.ExpiresAt) || a.DeclaredApproverRef != labActorReference(b.scope, s.approverID) ||
			a.DeclaredApproverRef == s.initiatorActor || a.RecoveryPlanSHA256 != s.plan.PlanSHA256 {
			return nil, labAuthorityFailure("approval_not_bound")
		}
	}
	return w.Recovery, nil
}

func (a *labRecoveryAuthority) approve(headers []string, h *labRecoverySession, now time.Time) (lifecycleRecoveryApproval, error) {
	var zero lifecycleRecoveryApproval
	c, b, now, err := a.lock(now)
	if err != nil {
		return zero, err
	}
	defer b.mu.Unlock()
	s, err := c.session(h)
	if err != nil {
		return zero, err
	}
	if err := labRecoveryAuthorityLockStore(s.store, s.owner, true, now); err != nil {
		return zero, err
	}
	defer s.store.core.mu.Unlock()
	active, err := c.binding(b, s, now, false)
	if err != nil {
		return zero, err
	}
	if active.Phase != "PLANNED" || active.Approval != nil || active.StopIntent != nil {
		return zero, labAuthorityFailure("binding_invalid")
	}
	if err := b.current(s.initiatorRef, s.initiatorID, authz.ActionPrepareLabRecovery, "", "", now); err != nil {
		return zero, err
	}
	p, ref, err := b.authenticate(headers, now)
	if err != nil {
		return zero, err
	}
	if err := b.evaluate(p, authz.ActionApproveLabRecovery, s.initiatorID, "", now); err != nil {
		return zero, err
	}
	if err := b.current(s.initiatorRef, s.initiatorID, authz.ActionPrepareLabRecovery, "", "", now); err != nil {
		return zero, err
	}
	if s.material != nil {
		if s.approverID != p.ID || s.approverRef != ref {
			return zero, labAuthorityFailure("approval_not_bound")
		}
		if err := s.store.core.verify(); err != nil {
			return zero, labAuthorityFailure("wal_unavailable")
		}
		return *s.material, nil
	}
	original, err := lifecycleV3Source(s.store.core.record.core)
	if err != nil {
		return zero, labAuthorityFailure("binding_invalid")
	}
	plan, err := labRecoveryPlanFromDescriptor(s.plan, original)
	if err != nil {
		return zero, labAuthorityFailure("binding_invalid")
	}
	material, err := newLifecycleRecoveryApproval(&plan, labActorReference(b.scope, p.ID), now, s.plan.ExpiresAt)
	if err != nil {
		return zero, labAuthorityFailure("binding_invalid")
	}
	if err := s.store.core.verify(); err != nil {
		return zero, labAuthorityFailure("wal_unavailable")
	}
	s.approverID, s.approverRef, s.material = p.ID, ref, &material
	return material, nil
}

func labRecoveryMakeCheck(b *labAuthorityCore, s *labRecoverySessionCore, p authz.Principal, action, intent string) labRecoveryCheck {
	w := s.store.core.record.core
	return labRecoveryCheck{core: &labRecoveryCheckCore{action, labActorReference(b.scope, p.ID), w.Recovery.Plan.RecoveryID, w.Recovery.Plan.PlanSHA256, w.Revision, w.RecordSHA256, w.LastRecoveryFence, intent}}
}

// This returns only a point-in-time authorization observation. It consumes no
// StartPermit and calls no Stop/Start/Do; the physical entry must independently
// apply source-owned ownership, once-only and final fresh authorization gates.
func (a *labRecoveryAuthority) authorizeStep(headers []string, h *labRecoverySession, step string, now time.Time) (labRecoveryCheck, error) {
	var zero labRecoveryCheck
	c, b, now, err := a.lock(now)
	if err != nil {
		return zero, err
	}
	defer b.mu.Unlock()
	if step != "STOP" && step != "START" {
		return zero, labAuthorityFailure("dispatch_phase_invalid")
	}
	s, err := c.session(h)
	if err != nil {
		return zero, err
	}
	if err := labRecoveryAuthorityLockStore(s.store, s.owner, true, now); err != nil {
		return zero, err
	}
	defer s.store.core.mu.Unlock()
	active, err := c.binding(b, s, now, true)
	if err != nil {
		return zero, err
	}
	intent := ""
	if step == "STOP" {
		if active.Phase != "STOP_ARMED" || active.StopIntent == nil || active.StopBinding == nil || active.Quiescence != nil || active.StartIntent != nil || active.StopIntent.OwnerFence != s.fence {
			return zero, labAuthorityFailure("dispatch_phase_invalid")
		}
		intent = active.StopIntent.IntentSHA256
	} else {
		x := s.store.core
		permit := x.permit
		if active.Phase != "START_ARMED" || active.StopIntent == nil || active.StopBinding == nil || active.Quiescence == nil || active.StartIntent == nil || permit == nil || permit.store != x || permit.fence != s.fence ||
			permit.fact.RecoveryID != s.plan.RecoveryID || permit.fact.RecoveryPlanSHA256 != s.plan.PlanSHA256 || permit.fact.StartIntentSHA256 != active.StartIntent.IntentSHA256 ||
			permit.fact.Revision != x.record.core.Revision || permit.fact.RecordSHA256 != x.record.core.RecordSHA256 || permit.fact.QuiescenceSHA256 != active.Quiescence.QuiescenceSHA256 ||
			!reflect.DeepEqual(permit.fact.TargetArtifact, s.plan.TargetArtifact) || !permit.fact.ArmedAt.Equal(active.StartIntent.ArmedAt) || !permit.fact.ExpiresAt.Equal(s.plan.ExpiresAt) ||
			now.Before(permit.fact.ArmedAt) || now.Sub(permit.fact.ArmedAt) > 30*time.Second || !labQuiescenceFactValid(*active.Quiescence, *active.StopBinding, now) {
			return zero, labAuthorityFailure("dispatch_phase_invalid")
		}
		intent = active.StartIntent.IntentSHA256
	}
	p, executorRef, err := b.authenticate(headers, now)
	if err != nil {
		return zero, err
	}
	if err := b.current(s.initiatorRef, s.initiatorID, authz.ActionPrepareLabRecovery, "", "", now); err != nil {
		return zero, err
	}
	if err := b.current(s.approverRef, s.approverID, authz.ActionApproveLabRecovery, s.initiatorID, "", now); err != nil {
		return zero, err
	}
	if err := b.evaluate(p, authz.ActionExecuteLabRecovery, s.initiatorID, s.approverID, now); err != nil {
		return zero, err
	}
	if err := b.current(executorRef, p.ID, authz.ActionExecuteLabRecovery, s.initiatorID, s.approverID, now); err != nil {
		return zero, err
	}
	if err := s.store.core.verify(); err != nil {
		return zero, labAuthorityFailure("wal_unavailable")
	}
	s.boundRevision = s.store.core.record.core.Revision
	return labRecoveryMakeCheck(b, s, p, "RECOVERY_"+step+"_AUTHORIZATION_CHECK", intent), nil
}

// A short source gate, never held over process/artifact/HTTP/diagnostic IO.
// Existing authority -> store order is preserved; the caller may take only
// the observation issuer's short registry mutex before release.
type labRecoveryVerifyGuard struct {
	base    *labAuthorityCore
	store   *lifecycleRecoveryStoreCore
	custody *labRecoveryStartedCustody
}

func (g *labRecoveryVerifyGuard) release() {
	if g != nil && g.store != nil && g.base != nil {
		g.store.mu.Unlock()
		g.base.mu.Unlock()
		g.store, g.base = nil, nil
	}
}

// VERIFY is a new private observation step under the existing critical
// Execute/Admin policy, not a new authz action or a reusable dispatch permit.
func (a *labRecoveryAuthority) authorizeVerify(headers []string, h *labRecoverySession, expected *labRecoveryStartedCustody, now time.Time) (*labRecoveryVerifyGuard, error) {
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
	g := &labRecoveryVerifyGuard{base: b, store: s.store.core}
	fail := func() (*labRecoveryVerifyGuard, error) {
		g.release()
		return nil, labAuthorityFailure("verification_source_invalid")
	}
	active, err := c.binding(b, s, now, true)
	if err != nil {
		return fail()
	}
	x := s.store.core
	q := x.retainedStarted
	if active.Phase != "START_ARMED" || active.Execution == nil || active.Completion != nil || active.Failure != nil ||
		active.StartIntent == nil || active.Quiescence == nil || active.StopBinding == nil || q == nil || !q.matches(x) || (expected != nil && expected != q) ||
		now.Before(active.Execution.RecordedAt) || now.Before(active.Execution.Started.ObservedAt) || now.Sub(active.Execution.Started.ObservedAt) > 30*time.Second {
		return fail()
	}
	p, verifierRef, err := b.authenticate(headers, now)
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
	if err := b.current(verifierRef, p.ID, authz.ActionExecuteLabRecovery, s.initiatorID, s.approverID, now); err != nil {
		g.release()
		return nil, err
	}
	if x.verify() != nil || !q.matches(x) {
		return fail()
	}
	g.custody = q
	return g, nil
}

// Cancellation is not a new physical action. It intentionally does not demand
// the old initiator's still-active identity/lease/approval. The caller itself
// must authenticate currently; a matched approver is accepted only through an
// actual retained session plus exact durable material. Nil session: Admin only.
func (a *labRecoveryAuthority) authorizeRevoke(headers []string, store *lifecycleRecoveryStore, owner *lifecycleRecoveryOwnerToken, h *labRecoverySession, now time.Time) (labRecoveryCheck, error) {
	var zero labRecoveryCheck
	c, b, now, err := a.lock(now)
	if err != nil {
		return zero, err
	}
	defer b.mu.Unlock()
	if err := labRecoveryAuthorityLockStore(store, owner, false, now); err != nil {
		return zero, err
	}
	defer store.core.mu.Unlock()
	w := store.core.record.core
	if w == nil || w.Recovery == nil || w.Current.Head.Scope != b.scope || w.Current.Head.DeviceRef != b.scope.ObjectID || w.Recovery.Phase == "COMPLETED" || w.Recovery.Phase == "REVOKED_UNSTARTED" {
		return zero, labAuthorityFailure("binding_invalid")
	}
	p, _, err := b.authenticate(headers, now)
	if err != nil {
		return zero, err
	}
	approved := ""
	admin := false
	for _, role := range p.Roles {
		if role == authz.RoleAdmin {
			admin = true
		}
	}
	if !admin {
		s, err := c.session(h)
		if err != nil || s.store != store || s.storeCore != store.core || s.owner != owner || s.fence != w.LastRecoveryFence || !reflect.DeepEqual(s.plan, w.Recovery.Plan) || s.material == nil || w.Recovery.Approval == nil ||
			!reflect.DeepEqual(*s.material, *w.Recovery.Approval) || s.approverID != p.ID || w.Recovery.Approval.DeclaredApproverRef != labActorReference(b.scope, p.ID) {
			return zero, labAuthorityFailure("authorization_denied")
		}
		approved = s.approverID
	}
	if err := b.evaluate(p, authz.ActionRevokeLabRecovery, "", approved, now); err != nil {
		return zero, err
	}
	if err := store.core.verify(); err != nil {
		return zero, labAuthorityFailure("wal_unavailable")
	}
	view := &labRecoverySessionCore{store: store}
	return labRecoveryMakeCheck(b, view, p, "RECOVERY_REVOKE_AUTHORIZATION_CHECK", ""), nil
}

func (a *labRecoveryAuthority) authorizeRead(headers []string, now time.Time) error {
	_, b, now, err := a.lock(now)
	if err != nil {
		return err
	}
	defer b.mu.Unlock()
	p, _, err := b.authenticate(headers, now)
	if err != nil {
		return err
	}
	return b.evaluate(p, authz.ActionReadLabRecovery, "", "", now)
}
func (a *labRecoveryAuthority) close() error {
	if a == nil || a.core == nil || a.core.base == nil || a.core.base.core == nil {
		return labAuthorityFailure("authority_unavailable")
	}
	c, b := a.core, a.core.base.core
	b.mu.Lock()
	defer b.mu.Unlock()
	c.closed = true
	c.initiators = nil
	c.sessions = nil
	return nil
}
