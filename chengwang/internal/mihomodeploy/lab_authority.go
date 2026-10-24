package mihomodeploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

const labAuthorityDebug = "private laboratory authorization check; not an execution permit"
const maxLabAuthorityBindings = 256

type labAuthorityError struct{ code string }

func (*labAuthorityError) Error() string    { return "Mihomo laboratory authorization check rejected" }
func labAuthorityFailure(code string) error { return &labAuthorityError{code: code} }
func labAuthorityErrorCode(err error) string {
	var failure *labAuthorityError
	if errors.As(err, &failure) && failure != nil {
		return failure.code
	}
	return "authority_unavailable"
}

// All capabilities below are private, single-pointer wrappers. In particular,
// fmt's unsupported-verb fallback must not reflect identity/ref/nonce fields.
// They are process-local trusted-code bindings, not signatures or defenses
// against malicious same-package code, reflection/unsafe or another binary.
type labAuthority struct{ core *labAuthorityCore }
type labInitiator struct{ core *labInitiatorCore }
type labSession struct{ core *labSessionCore }
type labAuthorityCheck struct{ core *labAuthorityCheckCore }

type labAuthorityCore struct {
	mu         sync.Mutex
	manager    *authn.SnapshotManager // borrowed; the startup owner closes it
	scope      authz.ResourceScope
	lastTime   time.Time
	closed     bool
	poisoned   bool
	initiators map[*labInitiator]*labInitiatorCore
	sessions   map[*labSession]*labSessionCore
}
type labInitiatorCore struct {
	authority *labAuthorityCore
	id        string
	ref       authn.SnapshotRef
	actorRef  string
}
type labSessionCore struct {
	authority      *labAuthorityCore
	store          *lifecycleStore
	owner          *lifecycleOwnerToken
	fence          uint64
	plan           PlanDescriptor
	boundRevision  uint64
	initiatorID    string
	initiatorRef   authn.SnapshotRef
	initiatorActor string
	approverID     string
	approverRef    authn.SnapshotRef
	material       *ApprovalMaterial
	approvalID     string
}
type labAuthorityCheckCore struct {
	action      string
	actorRef    string
	operationID string
	planSHA256  string
	revision    uint64
	fence       uint64
	intentSHA   string
}

func (labAuthority) String() string                    { return labAuthorityDebug }
func (labAuthority) GoString() string                  { return labAuthorityDebug }
func (labAuthority) Format(s fmt.State, _ rune)        { _, _ = io.WriteString(s, labAuthorityDebug) }
func (labAuthority) MarshalJSON() ([]byte, error)      { return labAuthorityJSON(), nil }
func (labInitiator) String() string                    { return labAuthorityDebug }
func (labInitiator) GoString() string                  { return labAuthorityDebug }
func (labInitiator) Format(s fmt.State, _ rune)        { _, _ = io.WriteString(s, labAuthorityDebug) }
func (labInitiator) MarshalJSON() ([]byte, error)      { return labAuthorityJSON(), nil }
func (labSession) String() string                      { return labAuthorityDebug }
func (labSession) GoString() string                    { return labAuthorityDebug }
func (labSession) Format(s fmt.State, _ rune)          { _, _ = io.WriteString(s, labAuthorityDebug) }
func (labSession) MarshalJSON() ([]byte, error)        { return labAuthorityJSON(), nil }
func (labAuthorityCheck) String() string               { return labAuthorityDebug }
func (labAuthorityCheck) GoString() string             { return labAuthorityDebug }
func (labAuthorityCheck) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, labAuthorityDebug) }
func (labAuthorityCheck) MarshalJSON() ([]byte, error) { return labAuthorityJSON(), nil }
func labAuthorityJSON() []byte                         { return []byte(`{"scope":"LAB_AUTHORIZATION_CHECK_NOT_EXECUTION"}`) }
func (v *labInitiator) UnmarshalJSON([]byte) error {
	if v != nil {
		*v = labInitiator{}
	}
	return labAuthorityFailure("binding_invalid")
}
func (v *labSession) UnmarshalJSON([]byte) error {
	if v != nil {
		*v = labSession{}
	}
	return labAuthorityFailure("binding_invalid")
}
func (v *labAuthorityCheck) UnmarshalJSON([]byte) error {
	if v != nil {
		*v = labAuthorityCheck{}
	}
	return labAuthorityFailure("binding_invalid")
}

// scope comes only from trusted startup configuration. No action accepts a
// caller Principal, role, scope, risk, approval flag or SnapshotRef.
func newLabAuthority(manager *authn.SnapshotManager, scope authz.ResourceScope) (*labAuthority, error) {
	if manager == nil || scope.ObjectType != LabObjectType || scope.Environment != LabEnvironment {
		return nil, labAuthorityFailure("configuration_invalid")
	}
	for _, value := range []string{scope.TenantID, scope.SiteID, scope.ObjectType, scope.ObjectID, scope.Environment} {
		if !planReference.MatchString(value) {
			return nil, labAuthorityFailure("configuration_invalid")
		}
	}
	return &labAuthority{core: &labAuthorityCore{manager: manager, scope: scope,
		initiators: make(map[*labInitiator]*labInitiatorCore), sessions: make(map[*labSession]*labSessionCore)}}, nil
}

func (a *labAuthority) lock(now time.Time) (*labAuthorityCore, time.Time, error) {
	if a == nil || a.core == nil {
		return nil, time.Time{}, labAuthorityFailure("authority_unavailable")
	}
	c := a.core
	c.mu.Lock()
	if c.closed || c.poisoned {
		c.mu.Unlock()
		return nil, time.Time{}, labAuthorityFailure("authority_closed")
	}
	now = now.UTC()
	if !planTime(now) || (!c.lastTime.IsZero() && now.Before(c.lastTime)) {
		c.poisoned = true
		c.initiators = nil
		c.sessions = nil
		c.mu.Unlock()
		return nil, time.Time{}, labAuthorityFailure("clock_invalid")
	}
	c.lastTime = now
	return c, now, nil
}

func labActorReference(scope authz.ResourceScope, id string) string {
	raw, _ := json.Marshal(struct {
		TenantID string `json:"tenantID"`
		ID       string `json:"principalID"`
	}{scope.TenantID, id})
	return labConfigHash(append([]byte("chengwang.mihomo-lab-actor/v1\n"), raw...))
}

func (c *labAuthorityCore) authenticate(headers []string, now time.Time) (authz.Principal, authn.SnapshotRef, error) {
	principal, ref, err := c.manager.AuthenticateAuthorizationValues(headers, now)
	if err != nil {
		if failure := labAuthoritySnapshotFailure(err); failure != nil {
			return authz.Principal{}, authn.SnapshotRef{}, failure
		}
		return authz.Principal{}, authn.SnapshotRef{}, labAuthorityFailure("authentication_rejected")
	}
	return principal, ref, nil
}
func labAuthoritySnapshotFailure(err error) error {
	if errors.Is(err, authn.ErrSnapshotClock) {
		return labAuthorityFailure("clock_invalid")
	}
	if errors.Is(err, authn.ErrSnapshotClosed) {
		return labAuthorityFailure("authority_closed")
	}
	if errors.Is(err, authn.ErrSnapshotUnavailable) || errors.Is(err, authn.ErrSnapshotUnsupported) {
		return labAuthorityFailure("authority_unavailable")
	}
	return nil
}
func (c *labAuthorityCore) evaluate(p authz.Principal, action authz.Action, initiator, approver string, now time.Time) error {
	decision := authz.Evaluate(authz.Request{Principal: p, Action: action, Resource: c.scope,
		Risk: authz.RiskCritical, InitiatorID: initiator, ApprovedByID: approver}, now)
	if !decision.Allowed || decision.BreakGlass {
		return labAuthorityFailure("authorization_denied")
	}
	return nil
}
func (c *labAuthorityCore) current(ref authn.SnapshotRef, id string, action authz.Action, initiator, approver string, now time.Time) error {
	p, err := c.manager.CurrentPrincipal(ref, id, now)
	if err != nil {
		if failure := labAuthoritySnapshotFailure(err); failure != nil {
			return failure
		}
	}
	if err != nil || p.ID != id {
		return labAuthorityFailure("snapshot_stale")
	}
	return c.evaluate(p, action, initiator, approver, now)
}

// Read authentication is independent of issued write sessions. It neither
// restores approval from JSON nor grants a dispatch capability.
func (a *labAuthority) authorizeRead(headers []string, now time.Time) error {
	c, now, err := a.lock(now)
	if err != nil {
		return err
	}
	defer c.mu.Unlock()
	p, _, err := c.authenticate(headers, now)
	if err != nil {
		return err
	}
	return c.evaluate(p, authz.ActionReadResource, "", "", now)
}

// Starting preparation requires the same current real identities as dispatch,
// but is not the later PREPARED/ARMED permission check and grants no PUT.
func (a *labAuthority) authorizeExecutionStart(headers []string, h *labSession, now time.Time) error {
	c, now, err := a.lock(now)
	if err != nil {
		return err
	}
	defer c.mu.Unlock()
	s, err := c.session(h)
	if err != nil {
		return err
	}
	if err := labAuthorityLockStore(s.store, s.owner, true, now); err != nil {
		return err
	}
	defer s.store.mu.Unlock()
	active, err := c.binding(s, now, true)
	if err != nil {
		return err
	}
	if active.Phase != "APPROVED" || active.Attempt != 0 || active.Intent != nil {
		return labAuthorityFailure("dispatch_phase_invalid")
	}
	p, _, err := c.authenticate(headers, now)
	if err != nil {
		return err
	}
	if err := c.current(s.initiatorRef, s.initiatorID, authz.ActionCreateOperation, "", "", now); err != nil {
		return err
	}
	if err := c.current(s.approverRef, s.approverID, authz.ActionApproveOperation, s.initiatorID, "", now); err != nil {
		return err
	}
	return c.evaluate(p, authz.ActionExecuteOperation, s.initiatorID, s.approverID, now)
}

func (a *labAuthority) authenticateInitiator(headers []string, now time.Time) (*labInitiator, error) {
	c, now, err := a.lock(now)
	if err != nil {
		return nil, err
	}
	defer c.mu.Unlock()
	p, ref, err := c.authenticate(headers, now)
	if err != nil {
		return nil, err
	}
	if err := c.evaluate(p, authz.ActionCreateOperation, "", "", now); err != nil {
		return nil, err
	}
	if len(c.initiators) >= maxLabAuthorityBindings {
		return nil, labAuthorityFailure("binding_limit")
	}
	h := &labInitiator{core: &labInitiatorCore{authority: c, id: p.ID, ref: ref, actorRef: labActorReference(c.scope, p.ID)}}
	c.initiators[h] = h.core
	return h, nil
}
func (a *labAuthority) initiatorReference(h *labInitiator) (string, error) {
	if a == nil || a.core == nil {
		return "", labAuthorityFailure("authority_unavailable")
	}
	c := a.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned || h == nil || h.core == nil || c.initiators[h] != h.core || h.core.authority != c {
		return "", labAuthorityFailure("binding_invalid")
	}
	return h.core.actorRef, nil
}
func (a *labAuthority) discardInitiator(h *labInitiator) {
	if a == nil || a.core == nil {
		return
	}
	a.core.mu.Lock()
	defer a.core.mu.Unlock()
	delete(a.core.initiators, h)
}

// Lock ordering is authority.mu -> store.mu -> SnapshotManager internal mutex.
// Callers must not enter these methods while already holding store.mu. The
// process-bound global/directory writer locks remain the disk owner's job.
func labAuthorityLockStore(s *lifecycleStore, owner *lifecycleOwnerToken, fresh bool, now time.Time) error {
	if s == nil || s.lifecycleStoreCore == nil || s.mu == nil {
		return labAuthorityFailure("binding_invalid")
	}
	s.mu.Lock()
	if err := s.verify(); err != nil {
		s.mu.Unlock()
		return labAuthorityFailure("wal_unavailable")
	}
	if err := s.token(owner, fresh, now); err != nil {
		s.mu.Unlock()
		return labAuthorityFailure("owner_invalid")
	}
	return nil
}

func (a *labAuthority) bindPlan(h *labInitiator, store *lifecycleStore, owner *lifecycleOwnerToken, now time.Time) (*labSession, error) {
	c, now, err := a.lock(now)
	if err != nil {
		return nil, err
	}
	defer c.mu.Unlock()
	if h == nil || h.core == nil || c.initiators[h] != h.core || h.core.authority != c || len(c.sessions) >= maxLabAuthorityBindings {
		return nil, labAuthorityFailure("binding_invalid")
	}
	if err := labAuthorityLockStore(store, owner, true, now); err != nil {
		return nil, err
	}
	defer store.mu.Unlock()
	w := store.record.wire
	if w == nil || w.Head == nil || w.Active == nil || w.Active.Phase != "PLANNED" || w.Active.Revocation != nil || w.Active.Attempt != 0 || w.Active.Approval != nil || w.Active.Plan.Target.Scope != c.scope || w.Active.Plan.Target.DeviceRef != c.scope.ObjectID {
		return nil, labAuthorityFailure("binding_invalid")
	}
	p, err := lifecyclePlan(w.Active.Plan)
	if err != nil || validatePreparationPlan(p, now) != nil || p.Descriptor().DeclaredInitiatorRef != h.core.actorRef {
		return nil, labAuthorityFailure("binding_invalid")
	}
	for _, existing := range c.sessions {
		if existing.store == store && existing.plan.OperationID == p.Descriptor().OperationID {
			return nil, labAuthorityFailure("binding_exists")
		}
	}
	if err := c.current(h.core.ref, h.core.id, authz.ActionCreateOperation, "", "", now); err != nil {
		return nil, err
	}
	if err := store.verify(); err != nil {
		return nil, labAuthorityFailure("wal_unavailable")
	}
	session := &labSession{core: &labSessionCore{authority: c, store: store, owner: owner,
		fence: w.Owner.Fence, plan: p.Descriptor(), boundRevision: w.Revision,
		initiatorID: h.core.id, initiatorRef: h.core.ref, initiatorActor: h.core.actorRef}}
	c.sessions[session] = session.core
	delete(c.initiators, h)
	return session, nil
}

func (c *labAuthorityCore) session(h *labSession) (*labSessionCore, error) {
	if h == nil || h.core == nil || h.core.authority != c || c.sessions[h] != h.core {
		return nil, labAuthorityFailure("session_invalid")
	}
	return h.core, nil
}

// Caller holds both authority and store mutexes. No expected caller DTO is
// compared as truth: read current verified WAL, owner, scope and full plan.
func (c *labAuthorityCore) binding(s *labSessionCore, now time.Time, approved bool) (*lifecycleActive, error) {
	w := s.store.record.wire
	if w == nil || w.Head == nil || w.Owner == nil || w.Owner.Fence != s.fence || w.Revision < s.boundRevision || w.Active == nil ||
		!reflect.DeepEqual(w.Active.Plan, s.plan) || w.Active.Plan.Target.Scope != c.scope || w.Active.Plan.Target.DeviceRef != c.scope.ObjectID ||
		w.Active.Plan.DeclaredInitiatorRef != s.initiatorActor || w.Active.Revocation != nil || w.Active.Result != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	p, err := lifecyclePlan(w.Active.Plan)
	if err != nil || validatePreparationPlan(p, now) != nil {
		return nil, labAuthorityFailure("binding_invalid")
	}
	if approved {
		v := w.Active.Approval
		if s.material == nil || v == nil || s.approverID == "" || v.AuthoritySnapshotRef != nil || v.ApprovalID != s.approvalID ||
			!reflect.DeepEqual(v.Material, *s.material) || ValidateApprovalMaterial(p, v.Material, now) != nil ||
			v.Material.InitiatorRef != labActorReference(c.scope, s.initiatorID) || v.Material.ApproverRef != labActorReference(c.scope, s.approverID) {
			return nil, labAuthorityFailure("approval_not_bound")
		}
	}
	return w.Active, nil
}

// ApprovalMaterial is output metadata only, not a dispatch ticket. Coordinator
// must durably record it and separately call authorizeDispatch on actual WAL.
func (a *labAuthority) approve(headers []string, h *labSession, now time.Time) (ApprovalMaterial, error) {
	c, now, err := a.lock(now)
	if err != nil {
		return ApprovalMaterial{}, err
	}
	defer c.mu.Unlock()
	s, err := c.session(h)
	if err != nil {
		return ApprovalMaterial{}, err
	}
	if err := labAuthorityLockStore(s.store, s.owner, true, now); err != nil {
		return ApprovalMaterial{}, err
	}
	defer s.store.mu.Unlock()
	active, err := c.binding(s, now, false)
	if err != nil || active.Phase != "PLANNED" || active.Approval != nil || active.Attempt != 0 {
		return ApprovalMaterial{}, labAuthorityFailure("binding_invalid")
	}
	if err := c.current(s.initiatorRef, s.initiatorID, authz.ActionCreateOperation, "", "", now); err != nil {
		return ApprovalMaterial{}, err
	}
	p, ref, err := c.authenticate(headers, now)
	if err != nil {
		return ApprovalMaterial{}, err
	}
	if p.ID == s.initiatorID {
		return ApprovalMaterial{}, labAuthorityFailure("self_approval")
	}
	if err := c.evaluate(p, authz.ActionApproveOperation, s.initiatorID, "", now); err != nil {
		return ApprovalMaterial{}, err
	}
	// A replacement between the first activity read and approver auth retires
	// the original initiator ref. Recheck instead of mixing two epochs.
	if err := c.current(s.initiatorRef, s.initiatorID, authz.ActionCreateOperation, "", "", now); err != nil {
		return ApprovalMaterial{}, err
	}
	if s.material != nil {
		if s.approverID != p.ID || s.approverRef != ref {
			return ApprovalMaterial{}, labAuthorityFailure("approval_not_bound")
		}
		return *s.material, nil
	}
	material := ApprovalMaterial{PlanSHA256: s.plan.PlanSHA256, Scope: c.scope, InitiatorRef: s.initiatorActor,
		ApproverRef: labActorReference(c.scope, p.ID), IssuedAt: now, ExpiresAt: s.plan.ExpiresAt}
	plan, err := lifecyclePlan(s.plan)
	if err != nil || ValidateApprovalMaterial(plan, material, now) != nil {
		return ApprovalMaterial{}, labAuthorityFailure("binding_invalid")
	}
	if err := s.store.verify(); err != nil {
		return ApprovalMaterial{}, labAuthorityFailure("wal_unavailable")
	}
	s.approverID, s.approverRef, s.approvalID = p.ID, ref, lifecycleApprovalID(s.plan)
	s.material = &material
	return material, nil
}

func labCheck(s *labSessionCore, actor authz.Principal, scope authz.ResourceScope, action string) labAuthorityCheck {
	w := s.store.record.wire
	check := &labAuthorityCheckCore{action: action, actorRef: labActorReference(scope, actor.ID), operationID: s.plan.OperationID,
		planSHA256: s.plan.PlanSHA256, revision: w.Revision, fence: w.Owner.Fence}
	if w.Active.Intent != nil {
		check.intentSHA = w.Active.Intent.IntentSHA256
	}
	return labAuthorityCheck{core: check}
}

// A check is only point-in-time metadata. No API accepts it as an executable
// permit; coordinator must still perform head/source/audit/preparation/owned
// identity, live-lock and one-Do gates, and recheck just before the actual Do.
func (a *labAuthority) authorizeDispatch(headers []string, h *labSession, now time.Time) (labAuthorityCheck, error) {
	c, now, err := a.lock(now)
	if err != nil {
		return labAuthorityCheck{}, err
	}
	defer c.mu.Unlock()
	s, err := c.session(h)
	if err != nil {
		return labAuthorityCheck{}, err
	}
	if err := labAuthorityLockStore(s.store, s.owner, true, now); err != nil {
		return labAuthorityCheck{}, err
	}
	defer s.store.mu.Unlock()
	active, err := c.binding(s, now, true)
	if err != nil {
		return labAuthorityCheck{}, err
	}
	if (active.Phase != "PREPARED" || active.Attempt != 0 || active.Intent != nil) &&
		(active.Phase != "DISPATCH_ARMED" || active.Attempt != 1 || active.Intent == nil || active.Intent.OwnerFence != s.fence) {
		return labAuthorityCheck{}, labAuthorityFailure("dispatch_phase_invalid")
	}
	p, _, err := c.authenticate(headers, now)
	if err != nil {
		return labAuthorityCheck{}, err
	}
	if err := c.current(s.initiatorRef, s.initiatorID, authz.ActionCreateOperation, "", "", now); err != nil {
		return labAuthorityCheck{}, err
	}
	if err := c.current(s.approverRef, s.approverID, authz.ActionApproveOperation, s.initiatorID, "", now); err != nil {
		return labAuthorityCheck{}, err
	}
	if err := c.evaluate(p, authz.ActionExecuteOperation, s.initiatorID, s.approverID, now); err != nil {
		return labAuthorityCheck{}, err
	}
	if err := s.store.verify(); err != nil {
		return labAuthorityCheck{}, labAuthorityFailure("wal_unavailable")
	}
	s.boundRevision = s.store.record.wire.Revision
	return labCheck(s, p, c.scope, "DISPATCH_AUTHORIZATION_CHECK"), nil
}

// Without a live issued session only a current scoped Admin may cancel. We
// never invent an initiator ID from an opaque persisted ref to evaluate the
// Approve policy. Revoke only authorizes cancellation, never a new PUT.
func (a *labAuthority) authorizeRevoke(headers []string, store *lifecycleStore, owner *lifecycleOwnerToken, h *labSession, now time.Time) (labAuthorityCheck, error) {
	c, now, err := a.lock(now)
	if err != nil {
		return labAuthorityCheck{}, err
	}
	defer c.mu.Unlock()
	if err := labAuthorityLockStore(store, owner, false, now); err != nil {
		return labAuthorityCheck{}, err
	}
	defer store.mu.Unlock()
	w := store.record.wire
	if w == nil || w.Head == nil || w.Active == nil || lifecycleTerminal(w.Active.Phase) || w.Active.Plan.Target.Scope != c.scope || w.Active.Plan.Target.DeviceRef != c.scope.ObjectID {
		return labAuthorityCheck{}, labAuthorityFailure("binding_invalid")
	}
	p, _, err := c.authenticate(headers, now)
	if err != nil {
		return labAuthorityCheck{}, err
	}
	allowed := false
	for _, role := range p.Roles {
		if role == authz.RoleAdmin && c.evaluate(p, authz.ActionCreateOperation, "", "", now) == nil {
			allowed = true
		}
	}
	s, sessionErr := c.session(h)
	if !allowed && sessionErr == nil && s.store == store && reflect.DeepEqual(s.plan, w.Active.Plan) {
		if p.ID == s.initiatorID {
			allowed = c.evaluate(p, authz.ActionCreateOperation, "", "", now) == nil
		}
		if p.ID == s.approverID && s.material != nil && w.Active.Approval != nil && reflect.DeepEqual(*s.material, w.Active.Approval.Material) {
			allowed = c.evaluate(p, authz.ActionApproveOperation, s.initiatorID, "", now) == nil
		}
	}
	if !allowed {
		return labAuthorityCheck{}, labAuthorityFailure("authorization_denied")
	}
	if err := store.verify(); err != nil {
		return labAuthorityCheck{}, labAuthorityFailure("wal_unavailable")
	}
	view := &labSessionCore{store: store, plan: w.Active.Plan}
	return labCheck(view, p, c.scope, "REVOKE_AUTHORIZATION_CHECK"), nil
}

func (a *labAuthority) close() error {
	if a == nil || a.core == nil {
		return labAuthorityFailure("authority_unavailable")
	}
	c := a.core
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.initiators = nil
	c.sessions = nil
	return nil
}
