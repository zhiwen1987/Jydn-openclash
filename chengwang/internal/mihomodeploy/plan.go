package mihomodeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"chengwang/internal/authz"
)

const (
	LabEnvironment = "isolated-lab"
	LabObjectType = "mihomo-lab"
	LabPlanSchema = "chengwang.mihomo-lab-plan/v1"
	LabPlanBoundary = "STRUCTURAL_ISOLATED_LAB_PLAN_NOT_AUTHORIZATION"
)

var planReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var planHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// TargetBinding is declared identity metadata, not evidence that the process
// exists or is owned. It has no caller-controlled host, URL or credential.
// The later isolated executor must construct 127.0.0.1 endpoints itself and
// recheck the process, namespace, listeners and durable generation/head.
type TargetBinding struct {
	DeviceRef string `json:"deviceRef"`
	Scope authz.ResourceScope `json:"scope"`
	Generation uint64 `json:"generation"`
	HeadSHA256 string `json:"headSHA256"`
	KernelSHA256 string `json:"kernelSHA256"`
	PID int `json:"pid"`
	StartTicks uint64 `json:"startTicks"`
	NetNSInode uint64 `json:"netNSInode"`
	ControllerPort uint16 `json:"controllerPort"`
	MixedPort uint16 `json:"mixedPort"`
}

type PlanCode string

const (
	PlanInvalid PlanCode = "lab_plan_invalid"
	PlanExpired PlanCode = "lab_plan_expired"
	PlanTargetMismatch PlanCode = "lab_plan_target_mismatch"
	PlanArtifactInvalid PlanCode = "lab_plan_artifact_invalid"
	PlanBackupInvalid PlanCode = "lab_plan_backup_invalid"
	PlanApprovalInvalid PlanCode = "lab_plan_approval_material_invalid"
	PlanApprovalExpired PlanCode = "lab_plan_approval_material_expired"
)

// PlanError deliberately carries no input, cause, address or configuration.
type PlanError struct { Code PlanCode }

func (*PlanError) Error() string { return "Mihomo laboratory plan rejected" }

func planFailure(code PlanCode) error { return &PlanError{Code: code} }

// PlanSpec contains public descriptors only. DeclaredInitiatorRef is an opaque
// declaration to bind approval material, never an authenticated principal.
type PlanSpec struct {
	OperationID string
	DeclaredInitiatorRef string
	Target TargetBinding
	Artifact ArtifactDescriptor
	Backup BackupDescriptor
	ExpiresAt time.Time
}

type planBinding struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	OperationID string `json:"operationId"`
	DeclaredInitiatorRef string `json:"declaredInitiatorRef"`
	Target TargetBinding `json:"target"`
	Artifact ArtifactDescriptor `json:"artifact"`
	Backup BackupDescriptor `json:"backup"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Plan is immutable outside this package. Its zero value and JSON imports do
// not create a plan, authorize a write, acquire a lease or commit any file.
type Plan struct {
	binding planBinding
	sha256 string
}

type PlanDescriptor struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	OperationID string `json:"operationId"`
	DeclaredInitiatorRef string `json:"declaredInitiatorRef"`
	Target TargetBinding `json:"target"`
	Artifact ArtifactDescriptor `json:"artifact"`
	Backup BackupDescriptor `json:"backup"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	PlanSHA256 string `json:"planSHA256"`
}

func validateTargetBinding(target TargetBinding) error {
	for _, value := range []string{target.DeviceRef, target.Scope.TenantID, target.Scope.SiteID,
		target.Scope.ObjectType, target.Scope.ObjectID, target.Scope.Environment} {
		if !planReference.MatchString(value) { return planFailure(PlanInvalid) }
	}
	if target.Scope.Environment != LabEnvironment || target.Scope.ObjectType != LabObjectType ||
		target.Scope.ObjectID != target.DeviceRef || target.Generation == 0 || target.Generation == ^uint64(0) ||
		!planHash.MatchString(target.HeadSHA256) || !planHash.MatchString(target.KernelSHA256) ||
		target.HeadSHA256 == strings.Repeat("0", 64) || target.KernelSHA256 == strings.Repeat("0", 64) ||
		target.PID < 2 || target.PID > 1<<31-1 || target.StartTicks == 0 ||
		target.StartTicks > 1<<63-1 || target.NetNSInode == 0 || target.NetNSInode > 1<<63-1 ||
		target.ControllerPort < 1024 || target.MixedPort < 1024 ||
		target.ControllerPort == target.MixedPort {
		return planFailure(PlanInvalid)
	}
	return nil
}

func clonePlanBinding(binding planBinding) planBinding {
	binding.Artifact = cloneArtifactDescriptor(binding.Artifact)
	binding.Backup.Artifact = cloneArtifactDescriptor(binding.Backup.Artifact)
	return binding
}

func planTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

// NewPlan verifies descriptor structure and canonical bindings only. The caller
// supplies one trusted time observation; this function never reads the clock.
// Passing validation is not proof of private-file durability or runtime state.
func NewPlan(spec PlanSpec, now time.Time) (Plan, error) {
	// Callers must not concurrently mutate inputs during this copy. Subsequent
	// validation and all retained state use only the detached descriptors.
	spec.Artifact = cloneArtifactDescriptor(spec.Artifact)
	spec.Backup.Artifact = cloneArtifactDescriptor(spec.Backup.Artifact)
	if !planReference.MatchString(spec.OperationID) || !planReference.MatchString(spec.DeclaredInitiatorRef) ||
		!planTime(now) || !planTime(spec.ExpiresAt) {
		return Plan{}, planFailure(PlanInvalid)
	}
	now, expires := now.UTC(), spec.ExpiresAt.UTC()
	if !expires.After(now) { return Plan{}, planFailure(PlanExpired) }
	if validateTargetBinding(spec.Target) != nil { return Plan{}, planFailure(PlanInvalid) }
	if validateArtifactDescriptor(spec.Artifact) != nil || !spec.Artifact.Config.Admissible {
		return Plan{}, planFailure(PlanArtifactInvalid)
	}
	if validateBackupDescriptor(spec.Backup) != nil || !spec.Backup.Artifact.Config.Admissible {
		return Plan{}, planFailure(PlanBackupInvalid)
	}
	if spec.Backup.OperationID != spec.OperationID || spec.Backup.Target != spec.Target {
		return Plan{}, planFailure(PlanTargetMismatch)
	}
	if spec.Artifact.ControllerPort != spec.Target.ControllerPort || spec.Artifact.MixedPort != spec.Target.MixedPort ||
		spec.Backup.Artifact.ControllerPort != spec.Target.ControllerPort || spec.Backup.Artifact.MixedPort != spec.Target.MixedPort {
		return Plan{}, planFailure(PlanTargetMismatch)
	}
	binding := clonePlanBinding(planBinding{Schema: LabPlanSchema, Boundary: LabPlanBoundary,
		OperationID: spec.OperationID, DeclaredInitiatorRef: spec.DeclaredInitiatorRef, Target: spec.Target,
		Artifact: spec.Artifact, Backup: spec.Backup, CreatedAt: now, ExpiresAt: expires})
	raw, err := json.Marshal(binding)
	if err != nil { return Plan{}, planFailure(PlanInvalid) }
	return Plan{binding: binding, sha256: labConfigHash(raw)}, nil
}

// Descriptor returns detached metadata. It cannot be imported as authority.
func (p Plan) Descriptor() PlanDescriptor {
	b := clonePlanBinding(p.binding)
	return PlanDescriptor{Schema: b.Schema, Boundary: b.Boundary, OperationID: b.OperationID,
		DeclaredInitiatorRef: b.DeclaredInitiatorRef, Target: b.Target, Artifact: b.Artifact,
		Backup: b.Backup, CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt, PlanSHA256: p.sha256}
}

func (p Plan) MarshalJSON() ([]byte, error) { return json.Marshal(p.Descriptor()) }
func (p Plan) String() string { raw, _ := p.MarshalJSON(); return string(raw) }
func (p Plan) GoString() string { return p.String() }

// Formatter protects typed nil pointers too. Value copies are protected by the
// value-receiver String/GoString/MarshalJSON methods, not by pointer methods.
func (p *Plan) Format(state fmt.State, verb rune) {
	if p == nil { _, _ = io.WriteString(state, "<nil>"); return }
	_, _ = io.WriteString(state, p.String())
}

// ApprovalMaterial is untrusted structural material, not an approval ticket.
// Opaque references do not authenticate people. A later trusted service must
// check real authn/RBAC, revocation, write gates and the actual initiator again.
// This type has no Approved, Permit or authority-producing method.
type ApprovalMaterial struct {
	PlanSHA256 string `json:"planSHA256"`
	Scope authz.ResourceScope `json:"scope"`
	InitiatorRef string `json:"initiatorRef"`
	ApproverRef string `json:"approverRef"`
	IssuedAt time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ValidateApprovalMaterial checks consistency only; nil is not authorization.
// It changes no plan, store, operation, target or caller permissions.
func ValidateApprovalMaterial(plan Plan, material ApprovalMaterial, now time.Time) error {
	if !planHash.MatchString(plan.sha256) || plan.binding.Schema != LabPlanSchema || plan.binding.Boundary != LabPlanBoundary ||
		!planTime(now) || !planTime(material.IssuedAt) || !planTime(material.ExpiresAt) {
		return planFailure(PlanApprovalInvalid)
	}
	raw, err := json.Marshal(plan.binding)
	if err != nil || labConfigHash(raw) != plan.sha256 { return planFailure(PlanApprovalInvalid) }
	now, issued, expires := now.UTC(), material.IssuedAt.UTC(), material.ExpiresAt.UTC()
	if !now.Before(plan.binding.ExpiresAt) || !expires.After(now) { return planFailure(PlanApprovalExpired) }
	if material.PlanSHA256 != plan.sha256 || material.Scope != plan.binding.Target.Scope ||
		!planReference.MatchString(material.InitiatorRef) || material.InitiatorRef != plan.binding.DeclaredInitiatorRef ||
		!planReference.MatchString(material.ApproverRef) || material.ApproverRef == material.InitiatorRef ||
		issued.Before(plan.binding.CreatedAt) || issued.After(now) || !expires.After(issued) || expires.After(plan.binding.ExpiresAt) {
		return planFailure(PlanApprovalInvalid)
	}
	return nil
}
