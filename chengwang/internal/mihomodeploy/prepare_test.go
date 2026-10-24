package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The generic tests use the existing explicit in-memory disk fault model but
// execute the actual Put/CreateBackup/NewPlan/PrepareReload implementation.
// They are not filesystem, kernel, controller or authenticated-RBAC evidence.
func prepareFixture(t *testing.T, store *ArtifactStore, changedSecret bool) (Plan, time.Time, []byte, []byte) {
	t.Helper()
	ctx := context.Background()
	oldSpec := artifactFixtureSpec()
	old, err := store.Put(ctx, oldSpec)
	if err != nil {
		t.Fatal("old fixture put failed")
	}
	newSpec := artifactFixtureSpec()
	newSpec.DefaultTarget = "REJECT"
	newSpec.Draft.Name = "prepared-candidate"
	if changedSecret {
		newSpec.ControllerSecret = strings.Repeat("z", 40)
	}
	candidate, err := store.Put(ctx, newSpec)
	if err != nil {
		t.Fatal("candidate fixture put failed")
	}
	backup, err := store.CreateBackup(ctx, "prepare-operation", artifactFixtureTarget(), old.RecordSHA256)
	if err != nil {
		t.Fatal("fixture backup failed")
	}
	now := time.Date(2026, 10, 24, 14, 0, 0, 123456789, time.UTC)
	plan, err := NewPlan(PlanSpec{OperationID: "prepare-operation", DeclaredInitiatorRef: "opaque-initiator",
		Target: artifactFixtureTarget(), Artifact: candidate, Backup: backup, ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal("fixture plan failed")
	}
	newBody, _ := BuildLabConfig(newSpec)
	oldBody, _ := BuildLabConfig(oldSpec)
	return plan, now, newBody.Bytes(), oldBody.Bytes()
}

func prepareTestCode(t *testing.T, result *PreparedReload, err error, code PrepareCode) {
	t.Helper()
	var typed *PrepareError
	if result != nil || !errors.As(err, &typed) || typed.Code != code || err.Error() != "Mihomo laboratory reload preparation rejected" {
		t.Fatal("expected safe preparation rejection")
	}
}

func prepareRehash(plan *Plan) {
	raw, _ := json.Marshal(plan.binding)
	plan.sha256 = labConfigHash(raw)
}

func TestReloadPreparationReturnsExactNewAndCompleteOldPrivateBytes(t *testing.T) {
	store, disk := syntheticArtifactStore()
	plan, now, candidate, backup := prepareFixture(t, store, false)
	indexWrites, objectWrites := disk.indexWrites, disk.objectWrites
	prepared, err := store.PrepareReload(context.Background(), plan, now)
	if err != nil || prepared == nil || !bytes.Equal(prepared.CandidateBytes(), candidate) || !bytes.Equal(prepared.BackupBytes(), backup) {
		t.Fatal("preparation lost exact private bodies")
	}
	if bytes.Equal(candidate, backup) || !bytes.Contains(backup, []byte(artifactFixtureSpec().ControllerSecret)) {
		t.Fatal("fixture did not contain full distinct private bodies")
	}
	if disk.indexWrites != indexWrites || disk.objectWrites != objectWrites {
		t.Fatal("read-only preparation persisted a dispatch or artifact")
	}
	d := prepared.Descriptor()
	if d.Schema != ReloadPreparationSchema || d.Boundary != ReloadPreparationBoundary || !reflect.DeepEqual(d.Plan, plan.Descriptor()) || !d.PreparedAt.Equal(now) {
		t.Fatal("safe preparation metadata changed binding")
	}
}

func TestReloadPreparationRejectsActualControllerSecretRotation(t *testing.T) {
	store, disk := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, true)
	indexWrites, objectWrites := disk.indexWrites, disk.objectWrites
	result, err := store.PrepareReload(context.Background(), plan, now)
	prepareTestCode(t, result, err, PrepareControllerMismatch)
	if store.core.poisoned || disk.indexWrites != indexWrites || disk.objectWrites != objectWrites {
		t.Fatal("policy rejection changed private store state")
	}
	for _, secret := range []string{strings.Repeat("q", 40), strings.Repeat("z", 40)} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), secret) {
			t.Fatal("secret escaped rejection")
		}
	}
}

func TestReloadPreparationRevalidatesFullPlanNotOnlyItsDigest(t *testing.T) {
	for _, change := range []func(*Plan){
		func(p *Plan) { p.binding.Target.Scope.Environment = "production" },
		func(p *Plan) { p.binding.Target.Generation = ^uint64(0) },
		func(p *Plan) { p.binding.Target.HeadSHA256 = strings.Repeat("0", 64) },
		func(p *Plan) { p.binding.Target.ControllerPort++ },
		func(p *Plan) { p.binding.Artifact.Config.Admissible = false },
		func(p *Plan) { p.binding.Backup.OperationID = "different" },
		func(p *Plan) { p.binding.Schema = "imported-other-schema" },
		func(p *Plan) { p.binding.Boundary = "caller-permit" },
	} {
		store, disk := syntheticArtifactStore()
		plan, now, _, _ := prepareFixture(t, store, false)
		change(&plan)
		prepareRehash(&plan)
		reads := 0
		disk.onRead = func() { reads++ }
		result, err := store.PrepareReload(context.Background(), plan, now)
		prepareTestCode(t, result, err, PrepareInvalidPlan)
		if reads != 0 {
			t.Fatal("invalid plan reached private input reads")
		}
	}
}

func TestReloadPreparationRejectsZeroImportedAndDigestTamperedPlans(t *testing.T) {
	store, disk := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, false)
	raw, _ := json.Marshal(plan)
	var imported Plan
	if json.Unmarshal(raw, &imported) != nil {
		t.Fatal("fixture import failed")
	}
	tampered := plan
	tampered.sha256 = strings.Repeat("f", 64)
	reads := 0
	disk.onRead = func() { reads++ }
	for _, value := range []Plan{{}, imported, tampered} {
		result, err := store.PrepareReload(context.Background(), value, now)
		prepareTestCode(t, result, err, PrepareInvalidPlan)
	}
	if reads != 0 {
		t.Fatal("invalid/imported plan reached private disk")
	}
}

func TestReloadPreparationRejectsExpiredFutureAndZeroTrustedTimes(t *testing.T) {
	store, disk := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, false)
	reads := 0
	disk.onRead = func() { reads++ }
	for _, clock := range []time.Time{{}, now.Add(-time.Nanosecond)} {
		result, err := store.PrepareReload(context.Background(), plan, clock)
		prepareTestCode(t, result, err, PrepareInvalidPlan)
	}
	for _, clock := range []time.Time{plan.binding.ExpiresAt, plan.binding.ExpiresAt.Add(time.Second)} {
		result, err := store.PrepareReload(context.Background(), plan, clock)
		prepareTestCode(t, result, err, PrepareExpiredPlan)
	}
	if reads != 0 {
		t.Fatal("invalid time caused private reads")
	}
}

func TestReloadPreparationUsesOneCallerTimeAndCanonicalUTCMetadata(t *testing.T) {
	store, _ := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, false)
	local := now.Add(time.Second).In(time.FixedZone("synthetic", 8*60*60))
	prepared, err := store.PrepareReload(context.Background(), plan, local)
	if err != nil || !prepared.Descriptor().PreparedAt.Equal(local) || prepared.Descriptor().PreparedAt.Location() != time.UTC {
		t.Fatal("preparation did not use caller instant in UTC")
	}
}

func TestReloadPreparationRejectsAnotherValidTargetOrBackupOperation(t *testing.T) {
	for _, differentOperation := range []bool{false, true} {
		store, _ := syntheticArtifactStore()
		original, now, _, _ := prepareFixture(t, store, false)
		spec := PlanSpec{OperationID: original.binding.OperationID, DeclaredInitiatorRef: original.binding.DeclaredInitiatorRef,
			Target: original.binding.Target, Artifact: original.binding.Artifact, Backup: original.binding.Backup, ExpiresAt: original.binding.ExpiresAt}
		if differentOperation {
			spec.OperationID = "other-operation"
		} else {
			spec.Target.Generation++
		}
		var err error
		spec.Backup, err = newBackupDescriptor(spec.OperationID, spec.Backup.Artifact, spec.Target)
		if err != nil {
			t.Fatal("synthetic different backup invalid")
		}
		plan := planTestBuild(t, spec, now)
		result, err := store.PrepareReload(context.Background(), plan, now)
		if result != nil || !errors.Is(err, ErrArtifactNotFound) {
			t.Fatal("unrecorded other operation/target backup accepted")
		}
	}
}

func TestReloadPreparationRejectsUnstoredCanonicalCandidate(t *testing.T) {
	store, _ := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, false)
	config := plan.binding.Artifact
	other, err := newArtifactDescriptor(config.Config, strings.Repeat("d", 64), config.SourceSpecBytes+1, config.ControllerPort, config.MixedPort)
	if err != nil {
		t.Fatal("synthetic alternate descriptor rejected")
	}
	plan = planTestBuild(t, PlanSpec{OperationID: plan.binding.OperationID, DeclaredInitiatorRef: plan.binding.DeclaredInitiatorRef,
		Target: plan.binding.Target, Artifact: other, Backup: plan.binding.Backup, ExpiresAt: plan.binding.ExpiresAt}, now)
	result, err := store.PrepareReload(context.Background(), plan, now)
	if result != nil || !errors.Is(err, ErrArtifactNotFound) {
		t.Fatal("unrecorded candidate metadata accepted")
	}
}

func TestReloadPreparationRereadsAndRejectsCorruptPrivateSourceOrBody(t *testing.T) {
	for _, kind := range []string{"candidate_source", "candidate_body", "backup_source", "backup_body", "backup_record"} {
		t.Run(kind, func(t *testing.T) {
			store, disk := syntheticArtifactStore()
			plan, now, _, _ := prepareFixture(t, store, false)
			id := plan.binding.Artifact.SourceSpecSHA256
			switch kind {
			case "candidate_body":
				id = plan.binding.Artifact.Config.SHA256
			case "backup_source":
				id = plan.binding.Backup.Artifact.SourceSpecSHA256
			case "backup_body":
				id = plan.binding.Backup.Artifact.Config.SHA256
			case "backup_record":
				id = plan.binding.Backup.BackupSHA256
			}
			disk.objects[id] = []byte("synthetic-corrupt-private-value")
			result, err := store.PrepareReload(context.Background(), plan, now)
			if result != nil || err == nil || !store.core.poisoned {
				t.Fatal("corrupt private object prepared or store not poisoned")
			}
		})
	}
}

func TestReloadPreparationRejectsClosedPoisonedNilAndUnsafeStores(t *testing.T) {
	for _, failure := range []string{"closed", "poisoned", "unsafe", "nil", "zero"} {
		store, disk := syntheticArtifactStore()
		plan, now, _, _ := prepareFixture(t, store, false)
		switch failure {
		case "closed":
			_ = store.Close()
		case "poisoned":
			disk.writeUnknown = true
			changed := artifactFixtureSpec()
			changed.Draft.Name = "uncertain-index"
			if _, err := store.Put(context.Background(), changed); !errors.Is(err, ErrArtifactCommitUnknown) {
				t.Fatal("uncertain fixture was not unknown")
			}
		case "unsafe":
			disk.verifyError = true
		case "nil":
			store = nil
		case "zero":
			store = &ArtifactStore{}
		}
		result, err := store.PrepareReload(context.Background(), plan, now)
		if result != nil || err == nil {
			t.Fatal("unusable store prepared private inputs")
		}
	}
}

type prepareNilContext struct{ context.Context }

func TestReloadPreparationCanceledNilAndTypedNilContextsReadNothing(t *testing.T) {
	store, disk := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, false)
	reads := 0
	disk.onRead = func() { reads++ }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, value := range []context.Context{ctx, nil, (*prepareNilContext)(nil)} {
		result, err := store.PrepareReload(value, plan, now)
		if result != nil || err == nil {
			t.Fatal("invalid context prepared inputs")
		}
	}
	if reads != 0 {
		t.Fatal("invalid context caused private reads")
	}
}

func TestReloadPreparationCancellationDuringPrivateReadNeverReturnsBytes(t *testing.T) {
	for _, phase := range []int{1, 4, 10} {
		store, disk := syntheticArtifactStore()
		plan, now, _, _ := prepareFixture(t, store, false)
		ctx, cancel := context.WithCancel(context.Background())
		reads := 0
		disk.onRead = func() {
			reads++
			if reads == phase {
				cancel()
			}
		}
		result, err := store.PrepareReload(ctx, plan, now)
		cancel()
		if result != nil || !errors.Is(err, context.Canceled) || store.core.poisoned {
			t.Fatal("canceled read leaked bytes or became corruption")
		}
	}
}

func TestReloadPreparationReturnedBytesAndMetadataAreDetached(t *testing.T) {
	store, _ := syntheticArtifactStore()
	plan, now, candidate, backup := prepareFixture(t, store, false)
	prepared, err := store.PrepareReload(context.Background(), plan, now)
	if err != nil {
		t.Fatal("fixture prepare failed")
	}
	newView, oldView := prepared.CandidateBytes(), prepared.BackupBytes()
	newView[0] ^= 1
	oldView[0] ^= 1
	d := prepared.Descriptor()
	d.Plan.Artifact.Config.Capabilities[0] = "mutated"
	d.Plan.Backup.Artifact.Config.Capabilities[0] = "mutated"
	d.Plan.Artifact.Config.Requirements = append(d.Plan.Artifact.Config.Requirements, LabPolicyRequirement{Kind: "mutated"})
	d.Plan.Backup.Artifact.Config.Blockers = append(d.Plan.Backup.Artifact.Config.Blockers, LabConfigBlocker{Code: LabConfigInvalid})
	if !bytes.Equal(prepared.CandidateBytes(), candidate) || !bytes.Equal(prepared.BackupBytes(), backup) || prepared.Descriptor().Plan.Artifact.Config.Capabilities[0] == "mutated" || prepared.Descriptor().Plan.Backup.Artifact.Config.Capabilities[0] == "mutated" {
		t.Fatal("prepared snapshot returned aliases")
	}
	if store.Close() != nil || !bytes.Equal(prepared.BackupBytes(), backup) {
		t.Fatal("owned snapshot depended on live store backing")
	}
}

func TestReloadPreparationValueCopiesAndFormattingNeverReflectPrivateBodies(t *testing.T) {
	store, _ := syntheticArtifactStore()
	plan, now, candidate, backup := prepareFixture(t, store, false)
	prepared, err := store.PrepareReload(context.Background(), plan, now)
	if err != nil {
		t.Fatal("fixture prepare failed")
	}
	expected, err := json.Marshal(prepared.Descriptor())
	if err != nil {
		t.Fatal("metadata JSON failed")
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(expected, &keys) != nil || len(keys) != 4 || keys["schema"] == nil || keys["boundary"] == nil || keys["plan"] == nil || keys["preparedAt"] == nil {
		t.Fatal("metadata public shape grew a private field")
	}
	valueCopy := *prepared
	for _, value := range []any{prepared, valueCopy, &valueCopy} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(verb, value) != string(expected) {
				t.Fatal("debug formatter reflected secret-bearing backing fields")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || !bytes.Equal(raw, expected) {
			t.Fatal("JSON exported private backing")
		}
	}
	for _, body := range [][]byte{candidate, backup} {
		for _, forbidden := range []string{string(body), base64.StdEncoding.EncodeToString(body), hex.EncodeToString(body)} {
			if strings.Contains(string(expected), forbidden) {
				t.Fatal("encoded private body escaped metadata")
			}
		}
	}
	if strings.Contains(string(expected), artifactFixtureSpec().ControllerSecret) || strings.Contains(string(expected), "127.0.0.1") {
		t.Fatal("private controller material escaped metadata")
	}
}

func TestReloadPreparationNilZeroAndJSONImportDoNotBecomePrivateInputs(t *testing.T) {
	var absent *PreparedReload
	if absent.CandidateBytes() != nil || absent.BackupBytes() != nil {
		t.Fatal("nil preparation invented bodies")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(verb, absent) != "<nil>" {
			t.Fatal("nil formatting unsafe")
		}
	}
	raw, err := json.Marshal(absent)
	if err != nil || string(raw) != "null" {
		t.Fatal("nil JSON unsafe")
	}
	store, _ := syntheticArtifactStore()
	plan, now, _, _ := prepareFixture(t, store, false)
	prepared, err := store.PrepareReload(context.Background(), plan, now)
	if err != nil {
		t.Fatal("fixture prepare failed")
	}
	raw, _ = json.Marshal(prepared)
	var imported PreparedReload
	if json.Unmarshal(raw, &imported) != nil || imported.CandidateBytes() != nil || imported.BackupBytes() != nil {
		t.Fatal("JSON import invented private bytes")
	}
	for _, name := range []string{"Apply", "Reload", "Execute", "Permit", "Approved", "ArmDispatch"} {
		if _, exists := reflect.TypeOf(prepared).MethodByName(name); exists {
			t.Fatal("preparation object grants execution")
		}
	}
}

func TestReloadPreparationIndependentCallsKeepPrivateSnapshotsSeparate(t *testing.T) {
	store, _ := syntheticArtifactStore()
	plan, now, candidate, backup := prepareFixture(t, store, false)
	first, err := store.PrepareReload(context.Background(), plan, now)
	if err != nil {
		t.Fatal("first prepare failed")
	}
	second, err := store.PrepareReload(context.Background(), plan, now.Add(time.Second))
	if err != nil {
		t.Fatal("second prepare failed")
	}
	first.candidate[0] ^= 1
	first.backup[0] ^= 1
	if !bytes.Equal(second.CandidateBytes(), candidate) || !bytes.Equal(second.BackupBytes(), backup) {
		t.Fatal("two snapshots shared backing slices")
	}
	if first.Descriptor().PreparedAt.Equal(second.Descriptor().PreparedAt) {
		t.Fatal("trusted observation times lost")
	}
}

func TestReloadPreparationLinuxRealPrivateStoreReopenKeepsCompleteInputs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable private-store integration only")
	}
	path := filepath.Join(t.TempDir(), "artifacts")
	store, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal("actual private store open failed")
	}
	t.Cleanup(func() { _ = store.Close() })
	plan, now, candidate, backup := prepareFixture(t, store, false)
	if store.Close() != nil {
		t.Fatal("actual private store close failed")
	}
	reopened, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal("actual private store reopen failed")
	}
	defer reopened.Close()
	prepared, err := reopened.PrepareReload(context.Background(), plan, now)
	if err != nil || !bytes.Equal(prepared.CandidateBytes(), candidate) || !bytes.Equal(prepared.BackupBytes(), backup) {
		t.Fatal("actual complete private inputs lost after reopen")
	}
}
