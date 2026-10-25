package mihomodeploy

import (
	"fmt"
	"io"
	"reflect"
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

func (labRecoveryPlan) String() string   { return labRecoveryPlanDebug }
func (labRecoveryPlan) GoString() string { return labRecoveryPlanDebug }
func (labRecoveryPlan) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labRecoveryPlanDebug) }
func (labRecoveryPlan) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"STRUCTURAL_RECOVERY_PLAN_NOT_AUTHORIZATION"}`), nil
}
func (p *labRecoveryPlan) UnmarshalJSON([]byte) error {
	if p != nil { *p = labRecoveryPlan{} }
	return errLifecycleUnsafe
}

// This binds declared old-epoch identity only, not liveness, ownership,
// quiescence or authority to stop/start. Artifact/generation/head hashes are
// intentionally absent: a reload within the same physical epoch is stable.
func labRecoveryEpochSHA256(h lifecycleHead, p lifecycleProvisioning) (string, error) {
	for _, s := range []string{h.DeviceRef, h.Scope.TenantID, h.Scope.SiteID, h.Scope.ObjectType, h.Scope.ObjectID, h.Scope.Environment} {
		if !planReference.MatchString(s) { return "", errLifecycleUnsafe }
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
	if err != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	copy, err := decodeLifecycleRecord(raw)
	if err != nil || copy.wire == nil || copy.wire.Schema != lifecycleSchemaV2 || copy.wire.V2 == nil || copy.wire.Head == nil ||
		copy.wire.Active == nil || copy.wire.Active.Phase != "UNKNOWN" || copy.wire.Active.Attempt != 1 || copy.wire.Active.Intent == nil ||
		!labRecoveryID.MatchString(recoveryID) || !planReference.MatchString(initiator) || !lifecycleTime(now) || !lifecycleTime(expires) ||
		now.Before(copy.wire.LastTrustedAt) || !expires.After(now) || expires.Sub(now) > 5*time.Minute ||
		!lifecycleArtifactDescriptorValid(target) || !target.Config.Admissible ||
		target.ControllerPort != copy.wire.Head.ControllerPort || target.MixedPort != copy.wire.Head.MixedPort {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	epoch, err := labRecoveryEpochSHA256(*copy.wire.Head, copy.wire.V2.Provisioning)
	if err != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	a := copy.wire.Active
	d := labRecoveryPlanDescriptor{labRecoveryPlanSchema, labRecoveryPlanBoundary, recoveryID, a.Plan.OperationID,
		a.Plan.PlanSHA256, a.Intent.IntentSHA256, initiator, copy.wire.Revision, copy.wire.RecordSHA256,
		copy.wire.Head.HeadSHA256, copy.wire.Head.Generation, copy.wire.V2.Provisioning, epoch,
		cloneArtifactDescriptor(target), labRecoveryFixedBudgets(), now, expires, ""}
	d.PlanSHA256, err = labRecoveryPlanDigest(d)
	if err != nil || !lifecycleNonzeroHash(d.PlanSHA256) { return labRecoveryPlan{}, errLifecycleUnsafe }
	return labRecoveryPlan{core: &labRecoveryPlanCore{descriptor: d}}, nil
}

func (p *labRecoveryPlan) descriptor() labRecoveryPlanDescriptor {
	if p == nil || p.core == nil { return labRecoveryPlanDescriptor{} }
	d := p.core.descriptor
	d.TargetArtifact = cloneArtifactDescriptor(d.TargetArtifact)
	return d
}

func labRecoveryPlanFromDescriptor(d labRecoveryPlanDescriptor, original lifecycleRecord) (labRecoveryPlan, error) {
	// Serialized structural declarations reconstruct no authority or owned
	// capability. Every original-bound field must be derivable again.
	if !lifecycleArtifactDescriptorValid(d.TargetArtifact) { return labRecoveryPlan{}, errLifecycleUnsafe }
	d.TargetArtifact = cloneArtifactDescriptor(d.TargetArtifact)
	p, err := newLabRecoveryPlan(original, d.RecoveryID, d.DeclaredInitiatorRef, d.TargetArtifact, d.CreatedAt, d.ExpiresAt)
	if err != nil || !reflect.DeepEqual(p.descriptor(), d) { return labRecoveryPlan{}, errLifecycleUnsafe }
	return p, nil
}

func (p *labRecoveryPlan) validAt(now time.Time) error {
	if p == nil || p.core == nil || !lifecycleTime(now) { return errLifecycleUnsafe }
	d := p.descriptor()
	if d.Schema != labRecoveryPlanSchema || d.Boundary != labRecoveryPlanBoundary || !lifecycleTime(d.CreatedAt) || !lifecycleTime(d.ExpiresAt) ||
		now.Before(d.CreatedAt) || !now.Before(d.ExpiresAt) || !d.ExpiresAt.After(d.CreatedAt) || d.ExpiresAt.Sub(d.CreatedAt) > 5*time.Minute ||
		!lifecycleNonzeroHash(d.PlanSHA256) || d.Budgets != labRecoveryFixedBudgets() || !lifecycleArtifactDescriptorValid(d.TargetArtifact) {
		return errLifecycleUnsafe
	}
	hash, err := labRecoveryPlanDigest(d)
	if err != nil || hash != d.PlanSHA256 { return errLifecycleUnsafe }
	return nil
}
