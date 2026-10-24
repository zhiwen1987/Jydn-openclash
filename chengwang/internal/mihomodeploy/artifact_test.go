package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"chengwang/internal/authz"
	"chengwang/internal/domain"
)

// An explicit in-memory disk model for fault contracts; never production Open.
type syntheticArtifactDisk struct {
	objects                           map[string][]byte
	index                             []byte
	indexWrites, objectWrites         int
	writeError, putError, verifyError bool
	writeUnknown, putUnknown          bool
	closed                            bool
	onRead                            func()
	unsafeObjectAt                    int
	putResultError                    error
}

func (d *syntheticArtifactDisk) verify() error {
	if d.verifyError || d.closed {
		return ErrArtifactUnsafe
	}
	return nil
}
func (d *syntheticArtifactDisk) readIndex() ([]byte, bool, error) {
	return append([]byte{}, d.index...), d.index != nil, nil
}
func (d *syntheticArtifactDisk) writeIndex(raw []byte) (bool, error) {
	d.indexWrites++
	if d.writeUnknown {
		d.index = append([]byte{}, raw...)
		return true, ErrArtifactCommitUnknown
	}
	if d.writeError {
		return false, ErrArtifactUnsafe
	}
	d.index = append([]byte{}, raw...)
	return false, nil
}
func (d *syntheticArtifactDisk) readObject(id string, limit int) ([]byte, error) {
	if d.onRead != nil {
		d.onRead()
	}
	raw, ok := d.objects[id]
	if !ok || len(raw) > limit {
		return nil, ErrArtifactUnsafe
	}
	return append([]byte{}, raw...), nil
}
func (d *syntheticArtifactDisk) putObject(raw []byte) (bool, error) {
	d.objectWrites++
	if d.putUnknown {
		d.objects[labConfigHash(raw)] = append([]byte{}, raw...)
		return true, ErrArtifactCommitUnknown
	}
	if d.putError || d.unsafeObjectAt == d.objectWrites {
		return false, ErrArtifactUnsafe
	}
	if d.putResultError != nil {
		return false, d.putResultError
	}
	d.objects[labConfigHash(raw)] = append([]byte{}, raw...)
	return false, nil
}
func (d *syntheticArtifactDisk) close() error { d.closed = true; return nil }
func syntheticArtifactStore() (*ArtifactStore, *syntheticArtifactDisk) {
	d := &syntheticArtifactDisk{objects: map[string][]byte{}}
	index := artifactIndex{artifactIndexSchema, 1, []string{}, []string{}}
	d.index, _ = json.Marshal(index)
	return &ArtifactStore{core: &artifactCore{disk: d, index: index}}, d
}
func artifactFixtureSpec() LabConfigSpec {
	return LabConfigSpec{MixedPort: 18401, ControllerPort: 18402, ControllerSecret: strings.Repeat("q", 40), DefaultTarget: "DIRECT", Draft: domain.PolicyDraft{Name: "artifact-test"}}
}
func artifactFixtureTarget() TargetBinding {
	return TargetBinding{DeviceRef: "lab-device", Scope: authz.ResourceScope{TenantID: "tenant", SiteID: "site", Environment: LabEnvironment, ObjectType: LabObjectType, ObjectID: "lab-device"}, Generation: 7, HeadSHA256: strings.Repeat("a", 64), KernelSHA256: strings.Repeat("b", 64), PID: 123, StartTicks: 456, NetNSInode: 789, ControllerPort: 18402, MixedPort: 18401}
}
func storedArtifactFixture(t *testing.T) (*ArtifactStore, *syntheticArtifactDisk, ArtifactDescriptor) {
	t.Helper()
	s, disk := syntheticArtifactStore()
	d, err := s.Put(context.Background(), artifactFixtureSpec())
	if err != nil {
		t.Fatalf("fixture artifact: %v", err)
	}
	return s, disk, d
}

func TestArtifactDescriptorBindsCompleteCompilationInputAndPorts(t *testing.T) {
	a, err := BuildLabConfig(artifactFixtureSpec())
	if err != nil {
		t.Fatal(err)
	}
	d, err := newArtifactDescriptor(a.Descriptor(), strings.Repeat("c", 64), 100, 18402, 18401)
	if err != nil || validateArtifactDescriptor(d) != nil {
		t.Fatal("descriptor rejected")
	}
	other, err := newArtifactDescriptor(a.Descriptor(), strings.Repeat("d", 64), 100, 18402, 18401)
	if err != nil || other.RecordSHA256 == d.RecordSHA256 || other.Config.SHA256 != d.Config.SHA256 {
		t.Fatal("source identity not bound")
	}
	changed := d
	changed.ControllerPort++
	if validateArtifactDescriptor(changed) == nil {
		t.Fatal("listener metadata unbound")
	}
	changed = d
	changed.Config.Capabilities = append([]string{}, d.Config.Capabilities...)
	changed.Config.Capabilities[0] = "not-supported"
	if validateArtifactDescriptor(changed) == nil {
		t.Fatal("unbound capability accepted")
	}
}
func TestArtifactStorePersistsExactConfigAndUnredactedPrivateSource(t *testing.T) {
	s, disk, d := storedArtifactFixture(t)
	a, err := s.ReadPrivate(context.Background(), d.RecordSHA256)
	if err != nil || a.AdmissionError() != nil {
		t.Fatal("private read failed")
	}
	built, _ := BuildLabConfig(artifactFixtureSpec())
	if !bytes.Equal(a.Bytes(), built.Bytes()) || labConfigHash(a.Bytes()) != d.Config.SHA256 {
		t.Fatal("not exact configuration bytes")
	}
	var source artifactSourceWire
	if artifactDecode(disk.objects[d.SourceSpecSHA256], &source) != nil || source.ControllerSecret != artifactFixtureSpec().ControllerSecret || source.MixedPort != d.MixedPort {
		t.Fatal("redacted or incomplete source persisted")
	}
	returned := a.Bytes()
	returned[0] ^= 1
	again, err := s.ReadPrivate(context.Background(), d.RecordSHA256)
	if err != nil || !bytes.Equal(again.Bytes(), built.Bytes()) {
		t.Fatal("returned bytes alias stored content")
	}
}
func TestArtifactDescriptorsAreDetachedAndPutIsIdempotent(t *testing.T) {
	s, disk, d := storedArtifactFixture(t)
	writes := disk.indexWrites
	d.Config.Capabilities[0] = "caller-mutated"
	again, err := s.Put(context.Background(), artifactFixtureSpec())
	if err != nil || disk.indexWrites != writes || again.Config.Capabilities[0] != "static_domain_suffix_rules" {
		t.Fatal("idempotency or detached metadata failed")
	}
	view, err := s.Describe(context.Background(), again.RecordSHA256)
	if err != nil {
		t.Fatal(err)
	}
	view.Config.Capabilities[0] = "changed"
	view, err = s.Describe(context.Background(), again.RecordSHA256)
	if err != nil || view.Config.Capabilities[0] != "static_domain_suffix_rules" {
		t.Fatal("view aliases store")
	}
	spec := artifactFixtureSpec()
	spec.Draft.Name = "different-source-same-kernel-config"
	different, err := s.Put(context.Background(), spec)
	if err != nil || different.Config.SHA256 != again.Config.SHA256 || different.RecordSHA256 == again.RecordSHA256 || different.Config.DraftSHA256 == again.Config.DraftSHA256 {
		t.Fatal("same YAML collapsed different source policy")
	}
}
func TestArtifactStoreRejectsPolicyRequirementsBeforeAnyPersistence(t *testing.T) {
	s, disk := syntheticArtifactStore()
	spec := artifactFixtureSpec()
	spec.Draft.Businesses = []domain.BusinessPolicy{{ID: "business", Name: "Business", Domains: []string{"example.com"}, Strategy: "DIRECT", Fallback: "DIRECT"}}
	if _, err := s.Put(context.Background(), spec); !errors.Is(err, ErrArtifactBinding) {
		t.Fatal("requirements bypassed")
	}
	if len(disk.objects) != 0 || disk.indexWrites != 0 {
		t.Fatal("blocked policy persisted")
	}
}
func TestArtifactStorePrecommitFailureDoesNotPublishReference(t *testing.T) {
	s, disk := syntheticArtifactStore()
	disk.writeError = true
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactUnsafe) {
		t.Fatal("write fault hidden")
	}
	if len(s.core.index.Artifacts) != 0 || s.core.poisoned {
		t.Fatal("precommit incorrectly published or uncertain")
	}
	disk.writeError = false
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); err != nil {
		t.Fatal("safe idempotent retry failed")
	}
	for _, failure := range []error{ErrArtifactLimit, errors.New("synthetic definite no-write I/O failure")} {
		model, ioDisk := syntheticArtifactStore()
		ioDisk.putResultError = failure
		if _, err := model.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, failure) {
			t.Fatal("definite object rejection changed category")
		}
		if model.core.poisoned || len(model.core.index.Artifacts) != 0 {
			t.Fatal("definite rejection confused with integrity/uncertain failure")
		}
		ioDisk.putResultError = nil
		if _, err := model.Put(context.Background(), artifactFixtureSpec()); err != nil {
			t.Fatal("definite no-write failure blocked safe retry")
		}
	}
}
func TestArtifactStoreUnknownIndexCommitPoisonsAllSubsequentAccess(t *testing.T) {
	s, disk := syntheticArtifactStore()
	disk.writeUnknown = true
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactCommitUnknown) {
		t.Fatal("uncertain index called success")
	}
	if _, err := s.Describe(context.Background(), strings.Repeat("a", 64)); !errors.Is(err, ErrArtifactPoisoned) {
		t.Fatal("unknown store remained readable")
	}
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactPoisoned) {
		t.Fatal("unknown write retried blindly")
	}
}
func TestArtifactStoreUnknownObjectCommitAlsoPoisons(t *testing.T) {
	s, disk := syntheticArtifactStore()
	disk.putUnknown = true
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactCommitUnknown) {
		t.Fatal("uncertain body hidden")
	}
	if !s.core.poisoned || len(s.core.index.Artifacts) != 0 {
		t.Fatal("uncertain blob admitted")
	}
}
func TestArtifactStoreRejectsCorruptOrSwappedPrivateObjects(t *testing.T) {
	for _, kind := range []string{"config", "source", "record"} {
		t.Run(kind, func(t *testing.T) {
			s, disk, d := storedArtifactFixture(t)
			id := d.Config.SHA256
			if kind == "source" {
				id = d.SourceSpecSHA256
			}
			if kind == "record" {
				id = d.RecordSHA256
			}
			disk.objects[id] = []byte("corrupt synthetic body")
			if _, err := s.ReadPrivate(context.Background(), d.RecordSHA256); err == nil || !s.core.poisoned {
				t.Fatal("corruption accepted or store remained writable")
			}
			model, ioDisk, old := storedArtifactFixture(t)
			failureOffset := 1
			if kind == "source" {
				failureOffset = 2
			}
			if kind == "record" {
				failureOffset = 3
			}
			ioDisk.unsafeObjectAt = ioDisk.objectWrites + failureOffset
			candidate := artifactFixtureSpec()
			candidate.DefaultTarget = "REJECT"
			if _, err := model.Put(context.Background(), candidate); !errors.Is(err, ErrArtifactUnsafe) || !model.core.poisoned {
				t.Fatal("unsafe object write did not poison")
			}
			if _, err := model.Describe(context.Background(), old.RecordSHA256); !errors.Is(err, ErrArtifactPoisoned) {
				t.Fatal("unsafe write left reads enabled")
			}
			ioDisk.unsafeObjectAt = 0
			beforeWrites := ioDisk.objectWrites
			if _, err := model.Put(context.Background(), candidate); !errors.Is(err, ErrArtifactPoisoned) || ioDisk.objectWrites != beforeWrites {
				t.Fatal("different write bypassed observed integrity failure")
			}
		})
	}
}
func TestArtifactPrivateSourceMustRebuildExactDescriptorAndPayload(t *testing.T) {
	s, disk, d := storedArtifactFixture(t)
	raw := disk.objects[d.SourceSpecSHA256]
	var source artifactSourceWire
	if artifactDecode(raw, &source) != nil {
		t.Fatal("source fixture")
	}
	source.ControllerSecret = strings.Repeat("z", 40)
	changed, _ := json.Marshal(source)
	disk.objects[d.SourceSpecSHA256] = changed
	if _, err := s.ReadPrivate(context.Background(), d.RecordSHA256); err == nil {
		t.Fatal("source changed without binding rejected")
	}
}
func TestArtifactBackupUsesDurableOldBytesAndExactOperationTarget(t *testing.T) {
	s, _, d := storedArtifactFixture(t)
	target := artifactFixtureTarget()
	b, err := s.CreateBackup(context.Background(), "operation-one", target, d.RecordSHA256)
	if err != nil || validateBackupDescriptor(b) != nil || b.Artifact.Config.SHA256 != d.Config.SHA256 {
		t.Fatal("backup failed")
	}
	old, err := s.ReadBackupPrivate(context.Background(), b.BackupSHA256, "operation-one", target)
	if err != nil || labConfigHash(old.Bytes()) != d.Config.SHA256 || len(old.Bytes()) != d.Config.Bytes {
		t.Fatal("backup is not exact")
	}
	if _, err := s.ReadBackupPrivate(context.Background(), b.BackupSHA256, "other-operation", target); !errors.Is(err, ErrArtifactBinding) {
		t.Fatal("cross-operation restore")
	}
	changes := []TargetBinding{target, target, target, target, target, target}
	changes[0].Generation++
	changes[1].KernelSHA256 = strings.Repeat("c", 64)
	changes[2].PID++
	changes[3].StartTicks++
	changes[4].NetNSInode++
	changes[5].HeadSHA256 = strings.Repeat("d", 64)
	for _, wrong := range changes {
		if _, err := s.ReadBackupPrivate(context.Background(), b.BackupSHA256, "operation-one", wrong); !errors.Is(err, ErrArtifactBinding) {
			t.Fatal("target epoch substitution")
		}
	}
}
func TestArtifactBackupCannotBeSynthesizedFromMissingArtifactOrWrongPorts(t *testing.T) {
	s, _, d := storedArtifactFixture(t)
	if _, err := s.CreateBackup(context.Background(), "operation", artifactFixtureTarget(), strings.Repeat("a", 64)); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatal("backup invented from metadata")
	}
	target := artifactFixtureTarget()
	target.MixedPort++
	if _, err := s.CreateBackup(context.Background(), "operation", target, d.RecordSHA256); !errors.Is(err, ErrArtifactBinding) {
		t.Fatal("wrong listener bound")
	}
}
func TestArtifactBackupRemainsExactWhenNewCandidateIsStored(t *testing.T) {
	s, disk, d := storedArtifactFixture(t)
	target := artifactFixtureTarget()
	b, err := s.CreateBackup(context.Background(), "operation", target, d.RecordSHA256)
	if err != nil {
		t.Fatal(err)
	}
	writes := disk.indexWrites
	again, err := s.CreateBackup(context.Background(), "operation", target, d.RecordSHA256)
	if err != nil || !reflect.DeepEqual(b, again) || disk.indexWrites != writes {
		t.Fatal("backup idempotency failed")
	}
	spec := artifactFixtureSpec()
	spec.DefaultTarget = "REJECT"
	if _, err := s.Put(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	a, err := s.ReadBackupPrivate(context.Background(), b.BackupSHA256, "operation", target)
	if err != nil || labConfigHash(a.Bytes()) != d.Config.SHA256 {
		t.Fatal("new candidate replaced old backup")
	}
}
func TestArtifactStoreCancellationNilHandlesAndCloseFailClosed(t *testing.T) {
	s, disk := syntheticArtifactStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Put(ctx, artifactFixtureSpec()); !errors.Is(err, context.Canceled) || disk.objectWrites != 0 {
		t.Fatal("canceled persistence occurred")
	}
	if _, err := s.Put(nil, artifactFixtureSpec()); err == nil {
		t.Fatal("nil context")
	}
	stored, model, descriptor := storedArtifactFixture(t)
	backup, err := stored.CreateBackup(context.Background(), "operation", artifactFixtureTarget(), descriptor.RecordSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"duplicate-put", "duplicate-backup", "read"} {
		active, stop := context.WithCancel(context.Background())
		model.onRead = stop
		var err error
		if action == "duplicate-put" {
			_, err = stored.Put(active, artifactFixtureSpec())
		}
		if action == "duplicate-backup" {
			_, err = stored.CreateBackup(active, "operation", artifactFixtureTarget(), descriptor.RecordSHA256)
		}
		if action == "read" {
			_, err = stored.ReadBackupPrivate(active, backup.BackupSHA256, "operation", artifactFixtureTarget())
		}
		model.onRead = nil
		stop()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation during private reads was hidden")
		}
	}
	var missing *ArtifactStore
	if _, err := missing.ReadPrivate(context.Background(), "invalid"); err == nil {
		t.Fatal("nil handle accepted")
	}
	if s.Close() != nil || s.Close() != nil {
		t.Fatal("close not idempotent")
	}
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactPoisoned) {
		t.Fatal("closed handle used")
	}
}
func TestArtifactStoreDebugJSONValueAndPointerNeverReflectPrivateState(t *testing.T) {
	s, _, _ := storedArtifactFixture(t)
	for _, value := range []any{s, *s} {
		for _, format := range []string{"%v", "%+v", "%#v", "%x"} {
			want := "private Mihomo artifact store"
			if format == "%x" {
				want = fmt.Sprintf("%x", want)
			}
			if fmt.Sprintf(format, value) != want {
				t.Fatal("store formatter exposes private representation")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"PRIVATE_ARTIFACT_STORE_NOT_DEPLOYMENT"}` {
			t.Fatal("store JSON leaked")
		}
	}
}
func TestArtifactIndexAndPrivateCodecRejectAliasesDuplicatesAndUnknownKeys(t *testing.T) {
	for _, raw := range []string{`{"schema":"x","schema":"y"}`, `{"Schema":"x"}`, `{"schema":"x","unexpected":1}`, `null`, `{} {}`} {
		var index artifactIndex
		if artifactDecode([]byte(raw), &index) == nil {
			t.Fatal("noncanonical private record accepted")
		}
	}
	for _, v := range []artifactIndex{{}, {artifactIndexSchema, 1, nil, []string{}}, {artifactIndexSchema, 1, []string{strings.Repeat("a", 64), strings.Repeat("a", 64)}, []string{}}} {
		if validateArtifactIndex(v) == nil {
			t.Fatal("invalid index")
		}
	}
}
func TestArtifactStoreQuotaAndRevisionOverflowDoNotPublish(t *testing.T) {
	s, disk := syntheticArtifactStore()
	s.core.index.Revision = ^uint64(0)
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactLimit) {
		t.Fatal("revision wrapped")
	}
	if disk.indexWrites != 0 || len(s.core.index.Artifacts) != 0 {
		t.Fatal("overflow committed")
	}
}
