package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"
)

const ReloadPreparationSchema = "chengwang.mihomo-lab-reload-preparation/v1"
const ReloadPreparationBoundary = "PRIVATE_INPUTS_VERIFIED_NOT_RUNTIME_OR_AUTHORIZATION"

type PrepareCode string

const (
	PrepareInvalidPlan PrepareCode = "lab_reload_prepare_invalid_plan"
	PrepareExpiredPlan PrepareCode = "lab_reload_prepare_expired_plan"
	PrepareArtifactMismatch PrepareCode = "lab_reload_prepare_artifact_mismatch"
	PrepareBackupMismatch PrepareCode = "lab_reload_prepare_backup_mismatch"
	PrepareControllerMismatch PrepareCode = "lab_reload_prepare_controller_identity_mismatch"
)

// PrepareError never retains private bytes, input fields, filesystem paths or
// causes. Context and private-store failures keep their existing safe classes.
type PrepareError struct { Code PrepareCode }

func (*PrepareError) Error() string { return "Mihomo laboratory reload preparation rejected" }
func prepareFailure(code PrepareCode) error { return &PrepareError{Code: code} }

// ReloadPreparationDescriptor describes the private inputs checked at one
// caller-supplied trusted time. It is not a permit or proof of current runtime.
type ReloadPreparationDescriptor struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	Plan PlanDescriptor `json:"plan"`
	PreparedAt time.Time `json:"preparedAt"`
}

// PreparedReload owns private immutable body copies. JSON imports and its zero
// value cannot populate these fields. No approval, I/O or execution method is
// supplied: a future executor must still enforce RBAC, leases and durable WAL.
type PreparedReload struct {
	descriptor ReloadPreparationDescriptor
	candidate []byte
	backup []byte
}

func (p *PreparedReload) CandidateBytes() []byte {
	if p == nil { return nil }; return bytes.Clone(p.candidate)
}
func (p *PreparedReload) BackupBytes() []byte {
	if p == nil { return nil }; return bytes.Clone(p.backup)
}
func (p PreparedReload) Descriptor() ReloadPreparationDescriptor {
	d := p.descriptor
	d.Plan.Artifact = cloneArtifactDescriptor(d.Plan.Artifact)
	d.Plan.Backup.Artifact = cloneArtifactDescriptor(d.Plan.Backup.Artifact)
	return d
}
func (p PreparedReload) MarshalJSON() ([]byte, error) { return json.Marshal(p.Descriptor()) }
func (p PreparedReload) String() string { raw, _ := p.MarshalJSON(); return string(raw) }
func (p PreparedReload) GoString() string { return p.String() }
func (p *PreparedReload) Format(state fmt.State, verb rune) {
	if p == nil { _, _ = io.WriteString(state, "<nil>"); return }
	_, _ = io.WriteString(state, p.String())
}

func validatePreparationPlan(plan Plan, now time.Time) error {
	if !planTime(now) || !planTime(plan.binding.CreatedAt) || !planTime(plan.binding.ExpiresAt) ||
		now.Before(plan.binding.CreatedAt) || !planHash.MatchString(plan.sha256) {
		return prepareFailure(PrepareInvalidPlan)
	}
	if !now.Before(plan.binding.ExpiresAt) { return prepareFailure(PrepareExpiredPlan) }
	// Reconstruct through the real Plan constructor, not a digest-only check:
	// every target, artifact, backup, admission and port invariant is rechecked.
	rebuilt, err := NewPlan(PlanSpec{OperationID: plan.binding.OperationID,
		DeclaredInitiatorRef: plan.binding.DeclaredInitiatorRef, Target: plan.binding.Target,
		Artifact: plan.binding.Artifact, Backup: plan.binding.Backup,
		ExpiresAt: plan.binding.ExpiresAt}, plan.binding.CreatedAt)
	if err != nil || rebuilt.sha256 != plan.sha256 || !reflect.DeepEqual(rebuilt.Descriptor(), plan.Descriptor()) {
		return prepareFailure(PrepareInvalidPlan)
	}
	return nil
}

// PrepareReload rereads actual private source/config records under the store
// lock, using only the supplied trusted time. The caller must not mutate Plan
// internals concurrently (they are private). This performs no controller call,
// dispatch reservation, approval, lease acquisition or durable lifecycle write.
func (s *ArtifactStore) PrepareReload(ctx context.Context, plan Plan, now time.Time) (*PreparedReload, error) {
	if err := artifactContext(ctx); err != nil { return nil, err }
	if err := validatePreparationPlan(plan, now); err != nil { return nil, err }
	c, err := s.lock(ctx)
	if err != nil { return nil, err }; defer c.mu.Unlock()
	actualNew, candidate, candidateSource, err := c.load(plan.binding.Artifact.RecordSHA256)
	if err == nil { err = artifactContext(ctx) }
	if err != nil { return nil, err }
	if !reflect.DeepEqual(actualNew, plan.binding.Artifact) { return nil, prepareFailure(PrepareArtifactMismatch) }
	actualBackup, err := c.loadBackup(plan.binding.Backup.BackupSHA256)
	if err == nil { err = artifactContext(ctx) }
	if err != nil { return nil, err }
	if actualBackup.OperationID != plan.binding.OperationID || actualBackup.Target != plan.binding.Target ||
		!reflect.DeepEqual(actualBackup, plan.binding.Backup) { return nil, prepareFailure(PrepareBackupMismatch) }
	actualOld, backup, backupSource, err := c.load(actualBackup.Artifact.RecordSHA256)
	if err == nil { err = artifactContext(ctx) }
	if err != nil { return nil, err }
	if !reflect.DeepEqual(actualOld, actualBackup.Artifact) { return nil, prepareFailure(PrepareBackupMismatch) }
	// Upstream's payload reload ApplyConfig excludes ExternalController.
	// Changing its secret here would not rotate the running controller. Compare
	// the actual private source values; never export their values or own hash.
	if candidateSource.ControllerSecret != backupSource.ControllerSecret ||
		candidateSource.ControllerPort != backupSource.ControllerPort || candidateSource.MixedPort != backupSource.MixedPort ||
		candidateSource.ControllerPort != plan.binding.Target.ControllerPort || candidateSource.MixedPort != plan.binding.Target.MixedPort ||
		backupSource.ControllerPort != plan.binding.Target.ControllerPort || backupSource.MixedPort != plan.binding.Target.MixedPort {
		return nil, prepareFailure(PrepareControllerMismatch)
	}
	if err := artifactContext(ctx); err != nil { return nil, err }
	return &PreparedReload{descriptor: ReloadPreparationDescriptor{Schema: ReloadPreparationSchema,
		Boundary: ReloadPreparationBoundary, Plan: plan.Descriptor(), PreparedAt: now.UTC()},
		candidate: candidate.Bytes(), backup: backup.Bytes()}, nil
}
