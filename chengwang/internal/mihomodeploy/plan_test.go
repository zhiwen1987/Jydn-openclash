package mihomodeploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authz"
)

// Synthetic descriptor metadata tests only: no private-file durability,
// authenticated identity, real kernel, controller or network is exercised.
func planTestFixture(t *testing.T) (PlanSpec, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 123456789, time.UTC)
	target := TargetBinding{DeviceRef: "lab-device-a", Scope: authz.ResourceScope{
		TenantID: "lab-tenant", SiteID: "lab-site", ObjectType: LabObjectType,
		ObjectID: "lab-device-a", Environment: LabEnvironment}, Generation: 7,
		HeadSHA256: strings.Repeat("1", 64), KernelSHA256: strings.Repeat("2", 64),
		PID: 1234, StartTicks: 4567, NetNSInode: 8901, ControllerPort: 19090, MixedPort: 18080}
	oldSpec := labConfigTestSpec()
	old, err := newArtifactDescriptor(labConfigTestBuild(t, oldSpec).Descriptor(), strings.Repeat("3", 64), 512,
		oldSpec.ControllerPort, oldSpec.MixedPort)
	if err != nil { t.Fatal("synthetic old descriptor rejected") }
	newSpec := labConfigTestSpec(); newSpec.DefaultTarget = "REJECT"
	candidate, err := newArtifactDescriptor(labConfigTestBuild(t, newSpec).Descriptor(), strings.Repeat("4", 64), 513,
		newSpec.ControllerPort, newSpec.MixedPort)
	if err != nil { t.Fatal("synthetic candidate descriptor rejected") }
	backup, err := newBackupDescriptor("operation-a", old, target)
	if err != nil { t.Fatal("synthetic backup binding rejected") }
	return PlanSpec{OperationID: "operation-a", DeclaredInitiatorRef: "opaque-initiator-a", Target: target,
		Artifact: candidate, Backup: backup, ExpiresAt: now.Add(10 * time.Minute)}, now
}

func planTestBuild(t *testing.T, spec PlanSpec, now time.Time) Plan {
	t.Helper(); plan, err := NewPlan(spec, now)
	if err != nil { t.Fatal("synthetic plan rejected") }; return plan
}

func planTestReject(t *testing.T, spec PlanSpec, now time.Time, code PlanCode) {
	t.Helper(); plan, err := NewPlan(spec, now); var typed *PlanError
	if !errors.As(err, &typed) || typed.Code != code || plan.sha256 != "" {
		t.Fatal("expected closed plan rejection and zero plan")
	}
	if err.Error() != "Mihomo laboratory plan rejected" { t.Fatal("error exported input detail") }
}

func planTestApproval(plan Plan, now time.Time) ApprovalMaterial {
	d := plan.Descriptor()
	return ApprovalMaterial{PlanSHA256: d.PlanSHA256, Scope: d.Target.Scope,
		InitiatorRef: d.DeclaredInitiatorRef, ApproverRef: "opaque-approver-b",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
}

func planTestRebind(t *testing.T, spec *PlanSpec) {
	t.Helper()
	var err error
	spec.Backup, err = newBackupDescriptor(spec.OperationID, spec.Backup.Artifact, spec.Target)
	if err != nil { t.Fatal("synthetic rebind rejected") }
}

func TestLabPlanBindsCanonicalCandidateBackupAndTarget(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); d := p.Descriptor()
	if d.Schema != LabPlanSchema || d.Boundary != LabPlanBoundary || !planHash.MatchString(d.PlanSHA256) ||
		d.Target != spec.Target || d.Backup.OperationID != spec.OperationID || d.Artifact.RecordSHA256 != spec.Artifact.RecordSHA256 ||
		d.Backup.BackupSHA256 != spec.Backup.BackupSHA256 || !d.CreatedAt.Equal(now) || !d.ExpiresAt.Equal(spec.ExpiresAt) {
		t.Fatal("canonical binding lost declared metadata")
	}
}

func TestLabPlanEquivalentUTCTimesHaveSameDigest(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now)
	spec.ExpiresAt = spec.ExpiresAt.In(time.FixedZone("synthetic", 8*60*60))
	q := planTestBuild(t, spec, now.In(time.FixedZone("other", -5*60*60)))
	if p.Descriptor().PlanSHA256 != q.Descriptor().PlanSHA256 || q.Descriptor().CreatedAt.Location() != time.UTC ||
		q.Descriptor().ExpiresAt.Location() != time.UTC { t.Fatal("equivalent instants not canonical UTC") }
}

func TestLabPlanEachTargetIdentityFieldChangesDigest(t *testing.T) {
	changes := []func(*TargetBinding){
		func(v *TargetBinding) { v.DeviceRef = "lab-device-b"; v.Scope.ObjectID = v.DeviceRef },
		func(v *TargetBinding) { v.Scope.TenantID = "tenant-b" }, func(v *TargetBinding) { v.Scope.SiteID = "site-b" },
		func(v *TargetBinding) { v.Generation++ }, func(v *TargetBinding) { v.HeadSHA256 = strings.Repeat("5", 64) },
		func(v *TargetBinding) { v.KernelSHA256 = strings.Repeat("6", 64) }, func(v *TargetBinding) { v.PID++ },
		func(v *TargetBinding) { v.StartTicks++ }, func(v *TargetBinding) { v.NetNSInode++ },
		func(v *TargetBinding) { v.ControllerPort++ }, func(v *TargetBinding) { v.MixedPort++ },
	}
	for i, change := range changes {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			spec, now := planTestFixture(t); before := planTestBuild(t, spec, now).Descriptor().PlanSHA256
			change(&spec.Target)
			for _, selected := range []*ArtifactDescriptor{&spec.Artifact, &spec.Backup.Artifact} {
				updated, err := newArtifactDescriptor(selected.Config, selected.SourceSpecSHA256, selected.SourceSpecBytes, spec.Target.ControllerPort, spec.Target.MixedPort)
				if err != nil { t.Fatal("synthetic target port binding rejected") }; *selected = updated
			}
			planTestRebind(t, &spec)
			if planTestBuild(t, spec, now).Descriptor().PlanSHA256 == before { t.Fatal("target identity absent from digest") }
		})
	}
}

func TestLabPlanOperationInitiatorAndTimeAreDigestBound(t *testing.T) {
	for i, change := range []func(*PlanSpec, *time.Time){
		func(s *PlanSpec, _ *time.Time) { s.OperationID = "operation-b" },
		func(s *PlanSpec, _ *time.Time) { s.DeclaredInitiatorRef = "opaque-initiator-b" },
		func(s *PlanSpec, _ *time.Time) { s.ExpiresAt = s.ExpiresAt.Add(time.Nanosecond) },
		func(_ *PlanSpec, now *time.Time) { *now = now.Add(time.Nanosecond) },
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			spec, now := planTestFixture(t); before := planTestBuild(t, spec, now).Descriptor().PlanSHA256
			change(&spec, &now); planTestRebind(t, &spec)
			if planTestBuild(t, spec, now).Descriptor().PlanSHA256 == before { t.Fatal("immutable plan input absent from digest") }
		})
	}
}

func TestLabPlanCandidateAndOldArtifactLineageAreDigestBound(t *testing.T) {
	for _, old := range []bool{false, true} {
		spec, now := planTestFixture(t); before := planTestBuild(t, spec, now).Descriptor().PlanSHA256
		selected := &spec.Artifact; if old { selected = &spec.Backup.Artifact }
		updated, err := newArtifactDescriptor(selected.Config, strings.Repeat("7", 64), selected.SourceSpecBytes+1, selected.ControllerPort, selected.MixedPort)
		if err != nil { t.Fatal("synthetic lineage rejected") }; *selected = updated; planTestRebind(t, &spec)
		if planTestBuild(t, spec, now).Descriptor().PlanSHA256 == before { t.Fatal("artifact lineage absent from digest") }
	}
}

func TestLabPlanRejectsEmptyWildcardAndNonLabScopes(t *testing.T) {
	for _, change := range []func(*TargetBinding){
		func(v *TargetBinding) { v.DeviceRef = "" }, func(v *TargetBinding) { v.Scope.TenantID = "" },
		func(v *TargetBinding) { v.Scope.SiteID = "" }, func(v *TargetBinding) { v.Scope.ObjectType = "" },
		func(v *TargetBinding) { v.Scope.ObjectID = "" }, func(v *TargetBinding) { v.Scope.Environment = "" },
		func(v *TargetBinding) { v.Scope.Environment = "production" }, func(v *TargetBinding) { v.Scope.ObjectType = "device" },
		func(v *TargetBinding) { v.Scope.SiteID = "*" }, func(v *TargetBinding) { v.Scope.ObjectID = "different" },
		func(v *TargetBinding) { v.Scope.TenantID = " tenant" }, func(v *TargetBinding) { v.DeviceRef = "http://127.0.0.1" },
	} {
		spec, now := planTestFixture(t); change(&spec.Target); planTestReject(t, spec, now, PlanInvalid)
	}
}

func TestLabPlanRejectsZeroOrMalformedKernelAndProcessIdentity(t *testing.T) {
	for _, change := range []func(*TargetBinding){
		func(v *TargetBinding) { v.Generation = 0 }, func(v *TargetBinding) { v.Generation = ^uint64(0) },
		func(v *TargetBinding) { v.HeadSHA256 = "" }, func(v *TargetBinding) { v.HeadSHA256 = strings.Repeat("0", 64) },
		func(v *TargetBinding) { v.KernelSHA256 = strings.Repeat("A", 64) }, func(v *TargetBinding) { v.KernelSHA256 = strings.Repeat("0", 64) },
		func(v *TargetBinding) { v.PID = 0 }, func(v *TargetBinding) { v.PID = 1 }, func(v *TargetBinding) { v.PID = -1 },
		func(v *TargetBinding) { v.PID = 1<<31 - 1; v.PID++ },
		func(v *TargetBinding) { v.StartTicks = 0 }, func(v *TargetBinding) { v.NetNSInode = 0 },
		func(v *TargetBinding) { v.StartTicks = ^uint64(0) }, func(v *TargetBinding) { v.NetNSInode = ^uint64(0) },
	} {
		spec, now := planTestFixture(t); change(&spec.Target); planTestReject(t, spec, now, PlanInvalid)
	}
}

func TestLabPlanRejectsPrivilegedMissingAndCollidingPorts(t *testing.T) {
	for _, change := range []func(*TargetBinding){func(v *TargetBinding) { v.ControllerPort = 0 },
		func(v *TargetBinding) { v.MixedPort = 0 }, func(v *TargetBinding) { v.ControllerPort = 1023 },
		func(v *TargetBinding) { v.MixedPort = 80 }, func(v *TargetBinding) { v.MixedPort = v.ControllerPort }} {
		spec, now := planTestFixture(t); change(&spec.Target); planTestReject(t, spec, now, PlanInvalid)
	}
}

func TestLabPlanRejectsInvalidOperationAndDeclaredInitiatorReferences(t *testing.T) {
	for _, bad := range []string{"", " leading", "trailing ", "*", "../device", "secret\nvalue", strings.Repeat("x", 129)} {
		for _, initiator := range []bool{false, true} {
			spec, now := planTestFixture(t); if initiator { spec.DeclaredInitiatorRef = bad } else { spec.OperationID = bad }
			planTestReject(t, spec, now, PlanInvalid)
		}
	}
}

func TestLabPlanRejectsZeroExpiredAndUnencodableTimes(t *testing.T) {
	spec, now := planTestFixture(t)
	planTestReject(t, spec, time.Time{}, PlanInvalid)
	for _, expiry := range []time.Time{now, now.Add(-time.Nanosecond)} {
		spec.ExpiresAt = expiry; planTestReject(t, spec, now, PlanExpired)
	}
	for _, expiry := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		spec.ExpiresAt = expiry; planTestReject(t, spec, now, PlanInvalid)
	}
}

func TestLabPlanRejectsArtifactRecordSourceAndConfigTampering(t *testing.T) {
	for _, change := range []func(*ArtifactDescriptor){
		func(v *ArtifactDescriptor) { v.Schema = "other" }, func(v *ArtifactDescriptor) { v.RecordSHA256 = strings.Repeat("8", 64) },
		func(v *ArtifactDescriptor) { v.SourceSpecSHA256 = "private body" }, func(v *ArtifactDescriptor) { v.SourceSpecBytes = 0 },
		func(v *ArtifactDescriptor) { v.Config.SHA256 = strings.Repeat("9", 64) },
		func(v *ArtifactDescriptor) { v.Config.Capabilities = append(v.Config.Capabilities, "private") },
	} {
		spec, now := planTestFixture(t); change(&spec.Artifact); planTestReject(t, spec, now, PlanArtifactInvalid)
	}
}

func TestLabPlanRejectsNonAdmissibleCandidateAndBackupConfiguration(t *testing.T) {
	for _, old := range []bool{false, true} {
		spec, now := planTestFixture(t); selected := &spec.Artifact; want := PlanArtifactInvalid
		if old { selected = &spec.Backup.Artifact; want = PlanBackupInvalid }
		selected.Config.Admissible = false
		selected.Config.Requirements = []LabPolicyRequirement{{Kind: "external", Path: "policy"}}
		planTestReject(t, spec, now, want)
	}
}

func TestLabPlanRejectsBackupSchemaHashAndOldRecordTampering(t *testing.T) {
	for _, change := range []func(*BackupDescriptor){
		func(v *BackupDescriptor) { v.Schema = "other" }, func(v *BackupDescriptor) { v.BackupSHA256 = strings.Repeat("a", 64) },
		func(v *BackupDescriptor) { v.Artifact.RecordSHA256 = strings.Repeat("b", 64) },
	} {
		spec, now := planTestFixture(t); change(&spec.Backup); planTestReject(t, spec, now, PlanBackupInvalid)
	}
}

func TestLabPlanRejectsValidBackupFromAnotherOperation(t *testing.T) {
	spec, now := planTestFixture(t); var err error
	spec.Backup, err = newBackupDescriptor("different-operation", spec.Backup.Artifact, spec.Target)
	if err != nil { t.Fatal("synthetic backup rejected") }; planTestReject(t, spec, now, PlanTargetMismatch)
}

func TestLabPlanRejectsEveryValidButDifferentBackupTargetField(t *testing.T) {
	for _, change := range []func(*TargetBinding){
		func(v *TargetBinding) { v.DeviceRef = "other"; v.Scope.ObjectID = "other" },
		func(v *TargetBinding) { v.Scope.TenantID = "other" }, func(v *TargetBinding) { v.Scope.SiteID = "other" },
		func(v *TargetBinding) { v.Generation++ }, func(v *TargetBinding) { v.HeadSHA256 = strings.Repeat("c", 64) },
		func(v *TargetBinding) { v.KernelSHA256 = strings.Repeat("d", 64) }, func(v *TargetBinding) { v.PID++ },
		func(v *TargetBinding) { v.StartTicks++ }, func(v *TargetBinding) { v.NetNSInode++ },
		func(v *TargetBinding) { v.ControllerPort++ }, func(v *TargetBinding) { v.MixedPort++ },
	} {
		spec, now := planTestFixture(t); target := spec.Target; change(&target); var err error
		if target.ControllerPort != spec.Backup.Artifact.ControllerPort || target.MixedPort != spec.Backup.Artifact.MixedPort {
			old := spec.Backup.Artifact
			spec.Backup.Artifact, err = newArtifactDescriptor(old.Config, old.SourceSpecSHA256, old.SourceSpecBytes, target.ControllerPort, target.MixedPort)
			if err != nil { t.Fatal("synthetic alternate backup ports rejected") }
		}
		spec.Backup, err = newBackupDescriptor(spec.OperationID, spec.Backup.Artifact, target)
		if err != nil { t.Fatal("synthetic different target rejected") }; planTestReject(t, spec, now, PlanTargetMismatch)
	}
}

func TestLabPlanRejectsCandidateOrBackupPortsThatDifferFromTarget(t *testing.T) {
	for _, old := range []bool{false, true} {
		spec, now := planTestFixture(t); selected := &spec.Artifact; if old { selected = &spec.Backup.Artifact }
		updated, err := newArtifactDescriptor(selected.Config, selected.SourceSpecSHA256, selected.SourceSpecBytes, selected.ControllerPort+1, selected.MixedPort)
		if err != nil { t.Fatal("synthetic alternate ports rejected") }; *selected = updated
		if old {
			target := spec.Target; target.ControllerPort = updated.ControllerPort
			spec.Backup, err = newBackupDescriptor(spec.OperationID, updated, target)
			if err != nil { t.Fatal("synthetic port-consistent backup rejected") }
		} else { planTestRebind(t, &spec) }
		planTestReject(t, spec, now, PlanTargetMismatch)
	}
}

func TestLabPlanOwnsInputDescriptorsAfterConstruction(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); before := p.String()
	spec.Artifact.Config.Capabilities[0] = "changed"
	spec.Backup.Artifact.Config.Capabilities[0] = "changed"
	spec.Artifact.Config.Requirements = append(spec.Artifact.Config.Requirements, LabPolicyRequirement{Kind: "changed"})
	spec.Backup.Artifact.Config.Blockers = append(spec.Backup.Artifact.Config.Blockers, LabConfigBlocker{Code: LabConfigInvalid})
	spec.Target.Scope.SiteID = "changed"
	if p.String() != before { t.Fatal("plan retained caller aliases") }
}

func TestLabPlanDescriptorsCannotMutateStoredOrLaterViews(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); before := p.String(); d := p.Descriptor()
	d.Artifact.Config.Capabilities[0] = "changed"; d.Backup.Artifact.Config.Capabilities[0] = "changed"
	d.Artifact.Config.Requirements = append(d.Artifact.Config.Requirements, LabPolicyRequirement{Kind: "changed"})
	d.Backup.Artifact.Config.Blockers = append(d.Backup.Artifact.Config.Blockers, LabConfigBlocker{Code: LabConfigInvalid})
	d.Target.Scope.TenantID = "changed"; d.PlanSHA256 = "changed"
	if p.String() != before { t.Fatal("descriptor returned an alias") }
}

func TestLabPlanPointerValueAndNilFormattingAreMetadataOnly(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); expected, err := json.Marshal(p.Descriptor())
	if err != nil { t.Fatal("descriptor encoding failed") }
	for _, value := range []any{p, &p} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(verb, value) != string(expected) { t.Fatal("formatter reflected private plan representation") }
		}
		raw, err := json.Marshal(value); if err != nil || string(raw) != string(expected) { t.Fatal("JSON exported non-descriptor state") }
	}
	var absent *Plan
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} { if fmt.Sprintf(verb, absent) != "<nil>" { t.Fatal("nil formatting not fixed") } }
	raw, err := json.Marshal(absent); if err != nil || string(raw) != "null" { t.Fatal("nil JSON not null") }
	for _, forbidden := range []string{"http://", "127.0.0.1", "synthetic-private-", "secret", "payload", "binding\":", "sha256\":"} {
		if strings.Contains(string(expected), forbidden) { t.Fatal("private address/body/state escaped descriptor") }
	}
}

func TestLabPlanZeroValueAndJSONImportDoNotAcquireAuthority(t *testing.T) {
	spec, now := planTestFixture(t); original := planTestBuild(t, spec, now); raw, _ := json.Marshal(original)
	var imported Plan
	if json.Unmarshal(raw, &imported) != nil { t.Fatal("synthetic JSON decoding unexpectedly failed") }
	for _, p := range []Plan{{}, imported} {
		if p.Descriptor().PlanSHA256 != "" || ValidateApprovalMaterial(p, planTestApproval(original, now), now) == nil {
			t.Fatal("zero/imported metadata became a valid plan")
		}
	}
}

func TestLabPlanApprovalMaterialIsBoundAndDoesNotMutatePlan(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); before := p.String()
	material := planTestApproval(p, now)
	if ValidateApprovalMaterial(p, material, now) != nil || p.String() != before { t.Fatal("matching structural material failed or changed plan") }
	if p.Descriptor().Boundary != LabPlanBoundary { t.Fatal("structural-only boundary lost") }
	for _, name := range []string{"Approved", "Permit", "Authorize", "Execute", "Reload", "ArmDispatch"} {
		if _, ok := reflect.TypeOf(p).MethodByName(name); ok { t.Fatal("pure plan exposed an execution/authority method") }
	}
}

func TestLabPlanApprovalRejectsOtherPlanOrAnyDifferentScope(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now)
	for _, change := range []func(*ApprovalMaterial){
		func(v *ApprovalMaterial) { v.PlanSHA256 = strings.Repeat("e", 64) },
		func(v *ApprovalMaterial) { v.Scope.TenantID = "other" }, func(v *ApprovalMaterial) { v.Scope.SiteID = "other" },
		func(v *ApprovalMaterial) { v.Scope.ObjectType = "other" }, func(v *ApprovalMaterial) { v.Scope.ObjectID = "other" },
		func(v *ApprovalMaterial) { v.Scope.Environment = "production" },
	} {
		v := planTestApproval(p, now); change(&v); if ValidateApprovalMaterial(p, v, now) == nil { t.Fatal("other plan/scope material accepted") }
	}
}

func TestLabPlanApprovalRejectsSelfChangedOrMalformedOpaqueReferences(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now)
	for _, change := range []func(*ApprovalMaterial){
		func(v *ApprovalMaterial) { v.ApproverRef = v.InitiatorRef }, func(v *ApprovalMaterial) { v.InitiatorRef = "other" },
		func(v *ApprovalMaterial) { v.ApproverRef = "" }, func(v *ApprovalMaterial) { v.InitiatorRef = "" },
		func(v *ApprovalMaterial) { v.ApproverRef = " raw actor " }, func(v *ApprovalMaterial) { v.ApproverRef = strings.Repeat("x", 129) },
	} {
		v := planTestApproval(p, now); change(&v); if ValidateApprovalMaterial(p, v, now) == nil { t.Fatal("invalid identity declaration accepted") }
	}
}

func TestLabPlanApprovalRejectsExpiredFutureAndOutsidePlanTimes(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now)
	for _, change := range []func(*ApprovalMaterial){
		func(v *ApprovalMaterial) { v.IssuedAt = time.Time{} }, func(v *ApprovalMaterial) { v.ExpiresAt = time.Time{} },
		func(v *ApprovalMaterial) { v.IssuedAt = now.Add(-time.Nanosecond) },
		func(v *ApprovalMaterial) { v.IssuedAt = now.Add(time.Nanosecond) },
		func(v *ApprovalMaterial) { v.ExpiresAt = now }, func(v *ApprovalMaterial) { v.ExpiresAt = now.Add(-time.Nanosecond) },
		func(v *ApprovalMaterial) { v.ExpiresAt = spec.ExpiresAt.Add(time.Nanosecond) },
		func(v *ApprovalMaterial) { v.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		v := planTestApproval(p, now); change(&v); if ValidateApprovalMaterial(p, v, now) == nil { t.Fatal("invalid approval time accepted") }
	}
	v := planTestApproval(p, now)
	for _, clock := range []time.Time{{}, spec.ExpiresAt, spec.ExpiresAt.Add(time.Second)} {
		if ValidateApprovalMaterial(p, v, clock) == nil { t.Fatal("invalid current time accepted") }
	}
}

func TestLabPlanApprovalExactExpiryBoundaryAndEquivalentZones(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); material := planTestApproval(p, now)
	material.ExpiresAt = spec.ExpiresAt.In(time.FixedZone("synthetic", 8*60*60))
	material.IssuedAt = now.In(time.FixedZone("synthetic", 8*60*60))
	if ValidateApprovalMaterial(p, material, now) != nil { t.Fatal("valid exact plan expiry rejected") }
	if ValidateApprovalMaterial(p, material, spec.ExpiresAt.Add(-time.Nanosecond)) != nil { t.Fatal("live material rejected before exact expiry") }
	if ValidateApprovalMaterial(p, material, spec.ExpiresAt) == nil { t.Fatal("expired material accepted at boundary") }
}

func TestLabPlanApprovalRejectsTamperedPrivateBindingWithoutGrantingWrites(t *testing.T) {
	spec, now := planTestFixture(t); p := planTestBuild(t, spec, now); material := planTestApproval(p, now)
	p.binding.Target.Generation++
	if ValidateApprovalMaterial(p, material, now) == nil { t.Fatal("private binding digest mismatch accepted") }
	var typed *PlanError
	if !errors.As(ValidateApprovalMaterial(Plan{}, material, now), &typed) || typed.Code != PlanApprovalInvalid {
		t.Fatal("zero plan did not return safe structural classification")
	}
}
