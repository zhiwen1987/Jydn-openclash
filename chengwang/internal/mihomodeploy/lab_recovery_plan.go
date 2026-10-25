package mihomodeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"chengwang/internal/authz"
)

const labRecoveryPlanSchema = "chengwang.mihomo-lab-recovery-plan/v1"
const labRecoveryPlanBoundary = "STRUCTURAL_RECOVERY_PLAN_NOT_AUTHORIZATION"
const labRecoveryPlanDebug = "private structural recovery plan; not authorization"

var labRecoveryID = regexp.MustCompile(`^labrec_[a-f0-9]{32}$`)

// These budgets are declarations, not evidence of measured deadlines or an
// implemented coordinator. No caller can expand the source-fixed values.
type labRecoveryBudgets struct {
	StopMillis         uint32 `json:"stopMillis"`
	StartMillis        uint32 `json:"startMillis"`
	VerificationMillis uint32 `json:"verificationMillis"`
	CommitMillis       uint32 `json:"commitMillis"`
}

func labRecoveryFixedBudgets() labRecoveryBudgets {
	return labRecoveryBudgets{3000, 10000, 10000, 5000}
}

type labRecoveryPlanDescriptor struct {
	Schema                 string                `json:"schema"`
	Boundary               string                `json:"boundary"`
	RecoveryID             string                `json:"recoveryId"`
	UnknownOperationID     string                `json:"unknownOperationId"`
	OriginalPlanSHA256     string                `json:"originalPlanSHA256"`
	OriginalIntentSHA256   string                `json:"originalIntentSHA256"`
	DeclaredInitiatorRef   string                `json:"declaredInitiatorRef"`
	ExpectedRevision       uint64                `json:"expectedRevision"`
	ExpectedRecordSHA256   string                `json:"expectedRecordSHA256"`
	PreviousHeadSHA256     string                `json:"previousHeadSHA256"`
	PreviousHeadGeneration uint64                `json:"previousHeadGeneration"`
	Provisioning           lifecycleProvisioning `json:"provisioning"`
	OldEpochSHA256         string                `json:"oldEpochSHA256"`
	TargetArtifact         ArtifactDescriptor    `json:"targetArtifact"`
	Budgets                labRecoveryBudgets    `json:"budgets"`
	CreatedAt              time.Time             `json:"createdAt"`
	ExpiresAt              time.Time             `json:"expiresAt"`
	PlanSHA256             string                `json:"planSHA256"`
}

// The ordered binding is exactly the descriptor without its own digest.
// Its schema domain-separates it from the old publish plan and epoch hashes.
type labRecoveryPlanBinding struct {
	Schema                 string                `json:"schema"`
	Boundary               string                `json:"boundary"`
	RecoveryID             string                `json:"recoveryId"`
	UnknownOperationID     string                `json:"unknownOperationId"`
	OriginalPlanSHA256     string                `json:"originalPlanSHA256"`
	OriginalIntentSHA256   string                `json:"originalIntentSHA256"`
	DeclaredInitiatorRef   string                `json:"declaredInitiatorRef"`
	ExpectedRevision       uint64                `json:"expectedRevision"`
	ExpectedRecordSHA256   string                `json:"expectedRecordSHA256"`
	PreviousHeadSHA256     string                `json:"previousHeadSHA256"`
	PreviousHeadGeneration uint64                `json:"previousHeadGeneration"`
	Provisioning           lifecycleProvisioning `json:"provisioning"`
	OldEpochSHA256         string                `json:"oldEpochSHA256"`
	TargetArtifact         ArtifactDescriptor    `json:"targetArtifact"`
	Budgets                labRecoveryBudgets    `json:"budgets"`
	CreatedAt              time.Time             `json:"createdAt"`
	ExpiresAt              time.Time             `json:"expiresAt"`
}

func labRecoveryPlanDigest(d labRecoveryPlanDescriptor) (string, error) {
	return lifecycleHash(labRecoveryPlanBinding{d.Schema, d.Boundary, d.RecoveryID, d.UnknownOperationID,
		d.OriginalPlanSHA256, d.OriginalIntentSHA256, d.DeclaredInitiatorRef, d.ExpectedRevision,
		d.ExpectedRecordSHA256, d.PreviousHeadSHA256, d.PreviousHeadGeneration, d.Provisioning,
		d.OldEpochSHA256, d.TargetArtifact, d.Budgets, d.CreatedAt, d.ExpiresAt})
}

// One opaque pointer keeps even fmt's unsupported-verb value reflection from
// expanding the original record, private process metadata or descriptor.
type labRecoveryPlan struct{ core *labRecoveryPlanCore }
type labRecoveryPlanCore struct{ descriptor labRecoveryPlanDescriptor }

// A context is local to one complete validation, never persisted or shared
// across records/commits. Only actual canonical legacy bytes construct it.
// Its decoded record is detached and read-only for the context's lifetime;
// it is not a caller assertion that a record has already been validated. Each
// validation is sequential; a context is never shared between goroutines.
type labRecoveryPlanValidationContext struct{ core *labRecoveryPlanValidationCore }
type labRecoveryPlanValidationCore struct {
	original lifecycleRecord
	epoch string
	// Exact full descriptor JSON, including nil versus [] and every field.
	// A RecordSHA256/Config.SHA256 alone cannot serve as a memoization key.
	targets map[string]struct{}
}

func newLabRecoveryPlanValidationContext(raw []byte) (*labRecoveryPlanValidationContext, error) {
	r, err := decodeLifecycleRecord(raw)
	if err != nil || r.wire == nil || r.wire.Schema != lifecycleSchemaV2 || r.wire.V2 == nil || r.wire.Head == nil ||
		r.wire.Active == nil || r.wire.Active.Phase != "UNKNOWN" || r.wire.Active.Attempt != 1 || r.wire.Active.Intent == nil {
		return nil, errLifecycleUnsafe
	}
	epoch, err := labRecoveryEpochSHA256(*r.wire.Head, r.wire.V2.Provisioning)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	return &labRecoveryPlanValidationContext{core: &labRecoveryPlanValidationCore{original: r, epoch: epoch, targets: map[string]struct{}{}}}, nil
}

func (c *labRecoveryPlanValidationContext) validTarget(d ArtifactDescriptor) bool {
	if c == nil || c.core == nil || c.core.targets == nil {
		return false
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return false
	}
	key := string(raw)
	if _, ok := c.core.targets[key]; ok {
		return true
	}
	if !lifecycleArtifactDescriptorValid(d) || !d.Config.Admissible {
		return false
	}
	c.core.targets[key] = struct{}{}
	return true
}

// All per-plan fields, times and the complete ordered digest are checked on
// every entry. Only immutable source parsing/epoch derivation and an exact
// repeated target descriptor's validation are shared within this one pass.
func (c *labRecoveryPlanValidationContext) validateDescriptor(d labRecoveryPlanDescriptor) error {
	if c == nil || c.core == nil || c.core.original.wire == nil || c.core.original.wire.Schema != lifecycleSchemaV2 || c.core.original.wire.Head == nil || c.core.original.wire.Active == nil ||
		c.core.original.wire.Active.Phase != "UNKNOWN" || c.core.original.wire.Active.Attempt != 1 || c.core.original.wire.Active.Intent == nil || c.core.original.wire.V2 == nil || !lifecycleNonzeroHash(c.core.epoch) || c.core.targets == nil {
		return errLifecycleUnsafe
	}
	w := c.core.original.wire
	a := w.Active
	if d.Schema != labRecoveryPlanSchema || d.Boundary != labRecoveryPlanBoundary || !labRecoveryID.MatchString(d.RecoveryID) || !planReference.MatchString(d.DeclaredInitiatorRef) ||
		d.UnknownOperationID != a.Plan.OperationID || d.OriginalPlanSHA256 != a.Plan.PlanSHA256 || d.OriginalIntentSHA256 != a.Intent.IntentSHA256 ||
		d.ExpectedRevision != w.Revision || d.ExpectedRecordSHA256 != w.RecordSHA256 || d.PreviousHeadSHA256 != w.Head.HeadSHA256 ||
		d.PreviousHeadGeneration != w.Head.Generation || d.Provisioning != w.V2.Provisioning || d.OldEpochSHA256 != c.core.epoch || d.Budgets != labRecoveryFixedBudgets() ||
		!lifecycleTime(d.CreatedAt) || !lifecycleTime(d.ExpiresAt) || d.CreatedAt.Before(w.LastTrustedAt) || !d.ExpiresAt.After(d.CreatedAt) || d.ExpiresAt.Sub(d.CreatedAt) > 5*time.Minute ||
		d.TargetArtifact.ControllerPort != w.Head.ControllerPort || d.TargetArtifact.MixedPort != w.Head.MixedPort || !c.validTarget(d.TargetArtifact) {
		return errLifecycleUnsafe
	}
	hash, err := labRecoveryPlanDigest(d)
	if err != nil || !lifecycleNonzeroHash(d.PlanSHA256) || hash != d.PlanSHA256 {
		return errLifecycleUnsafe
	}
	return nil
}

func (labRecoveryPlan) String() string             { return labRecoveryPlanDebug }
func (labRecoveryPlan) GoString() string           { return labRecoveryPlanDebug }
func (labRecoveryPlan) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labRecoveryPlanDebug) }
func (labRecoveryPlan) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"STRUCTURAL_RECOVERY_PLAN_NOT_AUTHORIZATION"}`), nil
}
func (p *labRecoveryPlan) UnmarshalJSON([]byte) error {
	if p != nil {
		*p = labRecoveryPlan{}
	}
	return errLifecycleUnsafe
}

// This binds declared old-epoch identity only, not liveness, ownership,
// quiescence or authority to stop/start. Artifact/generation/head hashes are
// intentionally absent: a reload within the same physical epoch is stable.
func labRecoveryEpochSHA256(h lifecycleHead, p lifecycleProvisioning) (string, error) {
	for _, s := range []string{h.DeviceRef, h.Scope.TenantID, h.Scope.SiteID, h.Scope.ObjectType, h.Scope.ObjectID, h.Scope.Environment} {
		if !planReference.MatchString(s) {
			return "", errLifecycleUnsafe
		}
	}
	if h.Scope.ObjectType != LabObjectType || h.Scope.Environment != LabEnvironment || h.DeviceRef != h.Scope.ObjectID ||
		!lifecycleNonzeroHash(h.KernelSHA256) || h.PID < 2 || h.PID > 1<<31-1 || h.StartTicks == 0 || h.StartTicks > 1<<63-1 ||
		h.NetNSInode == 0 || h.NetNSInode > 1<<63-1 || h.ControllerPort < 1024 || h.MixedPort < 1024 || h.ControllerPort == h.MixedPort ||
		p.Schema != "chengwang.mihomo-lab-provision-binding/v1" || !lifecycleNonzeroHash(p.RuntimeID) || !lifecycleNonzeroHash(p.MarkerSHA256) {
		return "", errLifecycleUnsafe
	}
	return lifecycleHash(struct {
		Schema         string                `json:"schema"`
		DeviceRef      string                `json:"deviceRef"`
		Scope          authz.ResourceScope   `json:"scope"`
		Provisioning   lifecycleProvisioning `json:"provisioning"`
		KernelSHA256   string                `json:"kernelSHA256"`
		PID            int                   `json:"pid"`
		StartTicks     uint64                `json:"startTicks"`
		NetNSInode     uint64                `json:"netNSInode"`
		ControllerPort uint16                `json:"controllerPort"`
		MixedPort      uint16                `json:"mixedPort"`
	}{"chengwang.mihomo-owned-epoch-binding/v1", h.DeviceRef, h.Scope, p, h.KernelSHA256, h.PID, h.StartTicks, h.NetNSInode, h.ControllerPort, h.MixedPort})
}

func newLabRecoveryPlan(original lifecycleRecord, recoveryID, initiator string, target ArtifactDescriptor, now, expires time.Time) (labRecoveryPlan, error) {
	// As with the existing descriptor constructors, the trusted caller must
	// prevent concurrent input mutation while this detached copy is made.
	// Authenticate nothing: canonical record parsing provides structural
	// detachment only. Old expiry/revocation cannot authorize or forbid a new
	// independently approved recovery; its original facts remain bound intact.
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	context, err := newLabRecoveryPlanValidationContext(raw)
	if err != nil || !context.validTarget(target) {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	copy := context.core.original
	a := copy.wire.Active
	d := labRecoveryPlanDescriptor{labRecoveryPlanSchema, labRecoveryPlanBoundary, recoveryID, a.Plan.OperationID,
		a.Plan.PlanSHA256, a.Intent.IntentSHA256, initiator, copy.wire.Revision, copy.wire.RecordSHA256,
		copy.wire.Head.HeadSHA256, copy.wire.Head.Generation, copy.wire.V2.Provisioning, context.core.epoch,
		cloneArtifactDescriptor(target), labRecoveryFixedBudgets(), now, expires, ""}
	d.PlanSHA256, err = labRecoveryPlanDigest(d)
	if err != nil || context.validateDescriptor(d) != nil {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	return labRecoveryPlan{core: &labRecoveryPlanCore{descriptor: d}}, nil
}

func (p *labRecoveryPlan) descriptor() labRecoveryPlanDescriptor {
	if p == nil || p.core == nil {
		return labRecoveryPlanDescriptor{}
	}
	d := p.core.descriptor
	d.TargetArtifact = cloneArtifactDescriptor(d.TargetArtifact)
	return d
}

func labRecoveryPlanFromDescriptor(d labRecoveryPlanDescriptor, original lifecycleRecord) (labRecoveryPlan, error) {
	// Serialized structural declarations reconstruct no authority or owned
	// capability. Every original-bound field must be derivable again.
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	context, err := newLabRecoveryPlanValidationContext(raw)
	if err != nil || context.validateDescriptor(d) != nil {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	d.TargetArtifact = cloneArtifactDescriptor(d.TargetArtifact)
	return labRecoveryPlan{core: &labRecoveryPlanCore{descriptor: d}}, nil
}

func (p *labRecoveryPlan) validAt(now time.Time) error {
	if p == nil || p.core == nil || !lifecycleTime(now) {
		return errLifecycleUnsafe
	}
	d := p.descriptor()
	if d.Schema != labRecoveryPlanSchema || d.Boundary != labRecoveryPlanBoundary || !lifecycleTime(d.CreatedAt) || !lifecycleTime(d.ExpiresAt) ||
		now.Before(d.CreatedAt) || !now.Before(d.ExpiresAt) || !d.ExpiresAt.After(d.CreatedAt) || d.ExpiresAt.Sub(d.CreatedAt) > 5*time.Minute ||
		!lifecycleNonzeroHash(d.PlanSHA256) || d.Budgets != labRecoveryFixedBudgets() || !lifecycleArtifactDescriptorValid(d.TargetArtifact) {
		return errLifecycleUnsafe
	}
	hash, err := labRecoveryPlanDigest(d)
	if err != nil || hash != d.PlanSHA256 {
		return errLifecycleUnsafe
	}
	return nil
}
