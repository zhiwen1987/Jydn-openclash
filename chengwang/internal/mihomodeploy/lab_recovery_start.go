package mihomodeploy

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

const labRecoveryStartObservationSchema = "chengwang.mihomo-owned-recovery-start-observation/v1"
const labRecoveryStartedFactSchema = "chengwang.mihomo-owned-recovery-start-fact/v1"
const labRecoveryStartedDebug = "private observed recovery start; not authorization"
const maxLabRecoveryStartedClaims = 64

var errLabRecoveryStart = errors.New("owned laboratory recovery start is not proven")

// This detached binding comes only from the consumed permit and its current
// locked WAL. It is a structural association, never authority to execute.
type labRecoveryStartedBinding struct {
	RecoveryID          string             `json:"recoveryId"`
	RecoveryPlanSHA256  string             `json:"recoveryPlanSHA256"`
	StartIntentSHA256   string             `json:"startIntentSHA256"`
	Revision            uint64             `json:"revision"`
	RecordSHA256        string             `json:"recordSHA256"`
	TargetArtifact      ArtifactDescriptor `json:"targetArtifact"`
	QuiescenceSHA256    string             `json:"quiescenceSHA256"`
	ArmedAt             time.Time          `json:"armedAt"`
	ExpiresAt           time.Time          `json:"expiresAt"`
	ExpectedOldIdentity labKernelIdentity  `json:"expectedOldIdentity"`
	StartMillis         uint32             `json:"startMillis"`
}

// Null is unobserved. StartInvoked means entry into the existing native
// function; only StartObservation.Started reports whether Cmd.Start succeeded.
// These fields do not assert Wait, complete stdout, authorization or new head.
type labRecoveryStartObservation struct {
	Schema           string                     `json:"schema"`
	PermitConsumed   bool                       `json:"permitConsumed"`
	StartInvoked     bool                       `json:"startInvoked"`
	StartReturned    bool                       `json:"startReturned"`
	StartErrorClass  *string                    `json:"startErrorClass"`
	StartObservation *labKernelStartObservation `json:"startObservation"`
	StartupIdentity  *labKernelIdentity         `json:"startupIdentity"`
	VerifiedIdentity *labKernelIdentity         `json:"verifiedIdentity"`
	NamespaceInode   *uint64                    `json:"namespaceInode"`
	ListenersBefore  *bool                      `json:"listenersBefore"`
	ListenersAfter   *bool                      `json:"listenersAfter"`
	StartedAt        *time.Time                 `json:"startedAt"`
	ReturnedAt       *time.Time                 `json:"returnedAt"`
	Outcome          string                     `json:"outcome"`
	FailureCode      string                     `json:"failureCode"`
}

type labRecoveryStartedFact struct {
	Schema        string                      `json:"schema"`
	Binding       labRecoveryStartedBinding   `json:"binding"`
	Observation   labRecoveryStartObservation `json:"observation"`
	ObservedAt    time.Time                   `json:"observedAt"`
	StartedSHA256 string                      `json:"startedSHA256"`
}

type labRecoveryStartedIssuer struct {
	mu      sync.Mutex
	claimed map[*labRecoveryStartCore]bool
	issued  map[*labRecoveryStartedEpochCore]bool
}

var processLabRecoveryStartedIssuer = labRecoveryStartedIssuer{
	claimed: map[*labRecoveryStartCore]bool{}, issued: map[*labRecoveryStartedEpochCore]bool{},
}

type labRecoveryStartedEpochCore struct {
	issuer *labRecoveryStartedIssuer
	owner  *ownedLabKernel
	seal   *labRecoveryStartedOwnerSeal
	nonce  [32]byte
	fact   labRecoveryStartedFact
}

// Value copies alias one private registry entry. JSON is never a constructor.
type labRecoveryStartedEpoch struct{ core *labRecoveryStartedEpochCore }

func (labRecoveryStartedEpoch) String() string   { return labRecoveryStartedDebug }
func (labRecoveryStartedEpoch) GoString() string { return labRecoveryStartedDebug }
func (labRecoveryStartedEpoch) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, labRecoveryStartedDebug)
}
func (labRecoveryStartedEpoch) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"OBSERVED_START_NOT_AUTHORIZATION_OR_HEAD"}`), nil
}
func (*labRecoveryStartedEpoch) UnmarshalJSON([]byte) error { return errLabRecoveryStart }

func (i *labRecoveryStartedIssuer) claim(p *labRecoveryStartCore) bool {
	if i == nil || p == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.claimed == nil || i.issued == nil || i.claimed[p] || len(i.claimed) >= maxLabRecoveryStartedClaims {
		return false
	}
	i.claimed[p] = true
	return true
}

func labRecoveryStartedCloneBinding(b labRecoveryStartedBinding) labRecoveryStartedBinding {
	b.TargetArtifact = cloneArtifactDescriptor(b.TargetArtifact)
	return b
}

func labRecoveryStartedBindingValid(b labRecoveryStartedBinding, now time.Time) bool {
	return labRecoveryID.MatchString(b.RecoveryID) && lifecycleNonzeroHash(b.RecoveryPlanSHA256) &&
		lifecycleNonzeroHash(b.StartIntentSHA256) && b.Revision > 0 && lifecycleNonzeroHash(b.RecordSHA256) &&
		lifecycleArtifactDescriptorValid(b.TargetArtifact) && b.TargetArtifact.Config.Admissible &&
		lifecycleNonzeroHash(b.QuiescenceSHA256) && labQuiescenceIdentityValid(b.ExpectedOldIdentity) &&
		b.TargetArtifact.ControllerPort == b.ExpectedOldIdentity.ControllerPort && b.TargetArtifact.MixedPort == b.ExpectedOldIdentity.MixedPort &&
		b.StartMillis == labRecoveryFixedBudgets().StartMillis && lifecycleTime(b.ArmedAt) && lifecycleTime(b.ExpiresAt) && lifecycleTime(now) &&
		b.ExpiresAt.After(b.ArmedAt) && b.ExpiresAt.Sub(b.ArmedAt) <= 5*time.Minute &&
		!now.Before(b.ArmedAt) && now.Before(b.ExpiresAt) && !now.After(b.ArmedAt.Add(time.Duration(b.StartMillis)*time.Millisecond))
}

func labRecoveryStartedIdentityValid(id labKernelIdentity, b labRecoveryStartedBinding) bool {
	old := b.ExpectedOldIdentity
	return labQuiescenceIdentityValid(id) && (id.PID != old.PID || id.StartTicks != old.StartTicks) &&
		id.NetNSInode == old.NetNSInode && id.ELFSHA256 == old.ELFSHA256 && id.ELFBytes == old.ELFBytes &&
		id.SourceCommit == old.SourceCommit && id.ControllerPort == old.ControllerPort && id.MixedPort == old.MixedPort &&
		id.ArtifactSHA256 == b.TargetArtifact.Config.SHA256
}

func labRecoveryStartedCloneStart(v labKernelStartObservation) labKernelStartObservation {
	if v.Started != nil {
		n := *v.Started
		v.Started = &n
	}
	if v.PID != nil {
		n := *v.PID
		v.PID = &n
	}
	if v.StartTicks != nil {
		n := *v.StartTicks
		v.StartTicks = &n
	}
	if v.WaitReturned != nil {
		n := *v.WaitReturned
		v.WaitReturned = &n
	}
	if v.ExitCode != nil {
		n := *v.ExitCode
		v.ExitCode = &n
	}
	if v.Signal != nil {
		n := *v.Signal
		v.Signal = &n
	}
	if v.TermSent != nil {
		n := *v.TermSent
		v.TermSent = &n
	}
	if v.KillSent != nil {
		n := *v.KillSent
		v.KillSent = &n
	}
	if v.GroupAbsent != nil {
		n := *v.GroupAbsent
		v.GroupAbsent = &n
	}
	if v.Stdout != nil {
		n := *v.Stdout
		v.Stdout = &n
	}
	if v.Stderr != nil {
		n := *v.Stderr
		v.Stderr = &n
	}
	return v
}

func labRecoveryStartedCloneObservation(v labRecoveryStartObservation) labRecoveryStartObservation {
	if v.StartErrorClass != nil {
		n := *v.StartErrorClass
		v.StartErrorClass = &n
	}
	if v.StartObservation != nil {
		n := labRecoveryStartedCloneStart(*v.StartObservation)
		v.StartObservation = &n
	}
	if v.StartupIdentity != nil {
		n := *v.StartupIdentity
		v.StartupIdentity = &n
	}
	if v.VerifiedIdentity != nil {
		n := *v.VerifiedIdentity
		v.VerifiedIdentity = &n
	}
	if v.NamespaceInode != nil {
		n := *v.NamespaceInode
		v.NamespaceInode = &n
	}
	if v.ListenersBefore != nil {
		n := *v.ListenersBefore
		v.ListenersBefore = &n
	}
	if v.ListenersAfter != nil {
		n := *v.ListenersAfter
		v.ListenersAfter = &n
	}
	if v.StartedAt != nil {
		n := *v.StartedAt
		v.StartedAt = &n
	}
	if v.ReturnedAt != nil {
		n := *v.ReturnedAt
		v.ReturnedAt = &n
	}
	return v
}

func labRecoveryStartedCloneFact(f labRecoveryStartedFact) labRecoveryStartedFact {
	f.Binding = labRecoveryStartedCloneBinding(f.Binding)
	f.Observation = labRecoveryStartedCloneObservation(f.Observation)
	return f
}

func labRecoveryStartedFactHash(f labRecoveryStartedFact) (string, error) {
	return lifecycleHash(struct {
		Schema      string                      `json:"schema"`
		Binding     labRecoveryStartedBinding   `json:"binding"`
		Observation labRecoveryStartObservation `json:"observation"`
		ObservedAt  time.Time                   `json:"observedAt"`
	}{f.Schema, f.Binding, f.Observation, f.ObservedAt})
}

// Source-proof validation at the original observation time is also usable by
// the durable codec. Current permission and current liveness are separate.
func labRecoveryStartedFactValid(f labRecoveryStartedFact, b labRecoveryStartedBinding, now time.Time) bool {
	o := f.Observation
	if f.Schema != labRecoveryStartedFactSchema || !reflect.DeepEqual(f.Binding, b) || !labRecoveryStartedBindingValid(b, f.ObservedAt) ||
		!lifecycleTime(now) || now.Before(f.ObservedAt) || o.Schema != labRecoveryStartObservationSchema ||
		!o.PermitConsumed || !o.StartInvoked || !o.StartReturned || o.StartErrorClass == nil || *o.StartErrorClass != "NONE" ||
		o.Outcome != "STARTED" || o.FailureCode != "NONE" || o.StartObservation == nil ||
		o.StartupIdentity == nil || o.VerifiedIdentity == nil || *o.StartupIdentity != *o.VerifiedIdentity ||
		!labRecoveryStartedIdentityValid(*o.StartupIdentity, b) || o.NamespaceInode == nil || *o.NamespaceInode != b.ExpectedOldIdentity.NetNSInode ||
		o.ListenersBefore == nil || !*o.ListenersBefore || o.ListenersAfter == nil || !*o.ListenersAfter ||
		o.StartedAt == nil || o.ReturnedAt == nil || !lifecycleTime(*o.StartedAt) || !lifecycleTime(*o.ReturnedAt) ||
		o.StartedAt.Before(b.ArmedAt) || o.ReturnedAt.Before(*o.StartedAt) || !f.ObservedAt.Equal(*o.ReturnedAt) {
		return false
	}
	s := o.StartObservation
	if !s.Attempted || s.Started == nil || !*s.Started || s.PID == nil || *s.PID != o.StartupIdentity.PID ||
		s.StartTicks == nil || *s.StartTicks != o.StartupIdentity.StartTicks || s.WaitReturned == nil || *s.WaitReturned ||
		s.WaitErrorClass != "NOT_WAITED" || s.ExitCode != nil || s.Signal != nil || s.GroupAbsent != nil ||
		s.TermSent == nil || *s.TermSent || s.KillSent == nil || *s.KillSent || s.Stdout == nil || s.Stderr == nil {
		return false
	}
	h, err := labRecoveryStartedFactHash(f)
	return err == nil && lifecycleNonzeroHash(h) && h == f.StartedSHA256
}

func (q *labRecoveryStartedEpoch) consumeStartedEpochForRecord(b labRecoveryStartedBinding, now time.Time) (labRecoveryStartedFact, error) {
	return q.consume(b, now, false)
}

func (q *labRecoveryStartedEpoch) consumeStartedEpoch(b labRecoveryStartedBinding, now time.Time) (labRecoveryStartedFact, error) {
	return q.consume(b, now, true)
}

func (q *labRecoveryStartedEpoch) consume(b labRecoveryStartedBinding, now time.Time, strict bool) (labRecoveryStartedFact, error) {
	var zero labRecoveryStartedFact
	if q == nil || q.core == nil || q.core.issuer == nil {
		return zero, errLabRecoveryStart
	}
	x := q.core
	i := x.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.issued[x] {
		return zero, errLabRecoveryStart
	}
	delete(i.issued, x) // every known entry is spent, including rejected attempts
	if x.nonce == ([32]byte{}) || x.owner == nil || x.seal == nil || !labRecoveryStartedFactValid(x.fact, b, now) ||
		!labRecoveryStartedOwnerMatches(x.owner, x.seal, *x.fact.Observation.StartupIdentity) {
		return zero, errLabRecoveryStart
	}
	if strict {
		if !labRecoveryStartedBindingValid(b, now) || now.Sub(x.fact.ObservedAt) > 30*time.Second || !labRecoveryStartedOwnerCurrent(x.owner, *x.fact.Observation.StartupIdentity) {
			return zero, errLabRecoveryStart
		}
	}
	return labRecoveryStartedCloneFact(x.fact), nil
}

// Called only after the actual one-use permit is consumed. This second locked
// source read prevents caller-supplied identity/budgets/descriptors replacing
// the full current WAL. It grants no ongoing authorization outside this step.
func labRecoveryStartedBindingFromPermit(p *labRecoveryStartPermit, f labRecoveryStartFact, now time.Time) (labRecoveryStartedBinding, error) {
	var zero labRecoveryStartedBinding
	if p == nil || p.core == nil || p.core.store == nil {
		return zero, errLabRecoveryStart
	}
	x := p.core.store
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.verify() != nil || x.trustedNow(now) != nil || x.permit != nil || !reflect.DeepEqual(p.core.fact, f) {
		return zero, errLabRecoveryStart
	}
	w := x.record.core
	a := w.Recovery
	if x.live == nil || x.live.store != x || w.RecoveryOwner == nil || x.live.nonce != w.RecoveryOwner.OwnerNonce ||
		x.live.fence != w.RecoveryOwner.Fence || w.RecoveryOwner.Fence != p.core.fence || !now.Before(w.RecoveryOwner.ExpiresAt) ||
		a == nil || a.Phase != "START_ARMED" || a.Revocation != nil || a.Quiescence == nil || a.StartIntent == nil || a.Approval == nil ||
		!now.Before(a.Approval.ExpiresAt) || w.Revision != f.Revision || w.RecordSHA256 != f.RecordSHA256 || w.LastRecoveryFence != p.core.fence ||
		a.Plan.RecoveryID != f.RecoveryID || a.Plan.PlanSHA256 != f.RecoveryPlanSHA256 || a.StartIntent.IntentSHA256 != f.StartIntentSHA256 ||
		!a.StartIntent.ArmedAt.Equal(f.ArmedAt) || !a.Plan.ExpiresAt.Equal(f.ExpiresAt) || !reflect.DeepEqual(a.Plan.TargetArtifact, f.TargetArtifact) ||
		a.Quiescence.QuiescenceSHA256 != f.QuiescenceSHA256 {
		return zero, errLabRecoveryStart
	}
	b := labRecoveryStartedBinding{f.RecoveryID, f.RecoveryPlanSHA256, f.StartIntentSHA256, f.Revision, f.RecordSHA256,
		cloneArtifactDescriptor(f.TargetArtifact), f.QuiescenceSHA256, f.ArmedAt, f.ExpiresAt,
		a.Quiescence.Binding.ExpectedOldIdentity, a.Plan.Budgets.StartMillis}
	if !labRecoveryStartedBindingValid(b, now) {
		return zero, errLabRecoveryStart
	}
	return b, nil
}

// Re-read the same actual current WAL after private preparation and immediately
// before the sole native call. This neither restores nor consumes a permit.
// The returned point-in-time check cannot make a later OS action atomic with
// credential revocation; the coordinator must still serialize its own gates.
func labRecoveryStartedFinalGate(p *labRecoveryStartPermit, f labRecoveryStartFact, expected labRecoveryStartedBinding, now time.Time) error {
	current, err := labRecoveryStartedBindingFromPermit(p, f, now)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errLabRecoveryStart
	}
	return nil
}
