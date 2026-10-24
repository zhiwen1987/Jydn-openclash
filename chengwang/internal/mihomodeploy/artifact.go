package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"sync"

	"chengwang/internal/domain"
)

const (
	ArtifactSchema = "chengwang.mihomo-artifact/v1"
	BackupSchema = "chengwang.mihomo-backup/v1"
	artifactRecordSchema = "chengwang.mihomo-artifact-record/v1"
	backupRecordSchema = "chengwang.mihomo-backup-record/v1"
	artifactIndexSchema = "chengwang.mihomo-artifact-index/v1"
	maxArtifactRecords = 64
	maxBackupRecords = 128
	maxArtifactObjects = 512
	maxArtifactAggregateBytes = 64 << 20
	maxSourceSpecBytes = 2 << 20
	maxArtifactIndexBytes = 64 << 10
)

var (
	ErrArtifactUnsafe = errors.New("private Mihomo artifact store rejected")
	ErrArtifactNotFound = errors.New("private Mihomo artifact not found")
	ErrArtifactLimit = errors.New("private Mihomo artifact store limit reached")
	ErrArtifactBinding = errors.New("private Mihomo artifact binding rejected")
	ErrArtifactCommitUnknown = errors.New("private Mihomo artifact durability is uncertain")
	ErrArtifactPoisoned = errors.New("private Mihomo artifact store is fail-closed")
	ErrArtifactUnsupported = errors.New("private Mihomo artifact durability unsupported")
	artifactDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
	artifactOperation = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
)

// ArtifactDescriptor is safe immutable metadata, not a runtime/admission receipt.
// Config and source input have independent hashes; identical YAML need not mean
// identical policy requirements or original compilation input.
type ArtifactDescriptor struct {
	Schema string `json:"schema"`
	RecordSHA256 string `json:"recordSHA256"`
	Config LabConfigDescriptor `json:"config"`
	SourceSpecSHA256 string `json:"sourceSpecSHA256"`
	SourceSpecBytes int `json:"sourceSpecBytes"`
	ControllerPort uint16 `json:"controllerPort"`
	MixedPort uint16 `json:"mixedPort"`
}

// A backup pins an exact prior artifact and its complete declared target epoch.
// The caller must independently establish target truth and own the target lease.
// Creating this reference never applies, authorizes or verifies a deployment.
type BackupDescriptor struct {
	Schema string `json:"schema"`
	BackupSHA256 string `json:"backupSHA256"`
	OperationID string `json:"operationId"`
	Artifact ArtifactDescriptor `json:"artifact"`
	Target TargetBinding `json:"target"`
}

type artifactRecord struct {
	Schema string `json:"schema"`
	Config LabConfigDescriptor `json:"config"`
	SourceSpecSHA256 string `json:"sourceSpecSHA256"`
	SourceSpecBytes int `json:"sourceSpecBytes"`
	ControllerPort uint16 `json:"controllerPort"`
	MixedPort uint16 `json:"mixedPort"`
}
type backupRecord struct {
	Schema string `json:"schema"`
	OperationID string `json:"operationId"`
	Artifact ArtifactDescriptor `json:"artifact"`
	Target TargetBinding `json:"target"`
}
type artifactIndex struct {
	Schema string `json:"schema"`
	Revision uint64 `json:"revision"`
	Artifacts []string `json:"artifacts"`
	Backups []string `json:"backups"`
}

// Deliberately private explicit codec: LabConfigSpec.MarshalJSON is redacted and
// must never be used as the persisted compilation input. Never log this wire.
type artifactSourceWire struct {
	Schema string `json:"schema"`
	MixedPort uint16 `json:"mixedPort"`
	ControllerPort uint16 `json:"controllerPort"`
	ControllerSecret string `json:"controllerSecret"`
	DefaultTarget string `json:"defaultTarget"`
	Draft domain.PolicyDraft `json:"draft"`
	HTTPNodes []LabHTTPNode `json:"httpNodes"`
}

type artifactDisk interface {
	verify() error
	readIndex() ([]byte, bool, error)
	writeIndex([]byte) (bool, error)
	readObject(string, int) ([]byte, error)
	putObject([]byte) (bool, error)
	close() error
}

type artifactCore struct {
	mu sync.Mutex
	disk artifactDisk
	index artifactIndex
	closed, poisoned bool
}
type ArtifactStore struct { core *artifactCore }
func (ArtifactStore) String() string { return "private Mihomo artifact store" }
func (ArtifactStore) GoString() string { return "private Mihomo artifact store" }
func (ArtifactStore) MarshalJSON() ([]byte, error) { return []byte(`{"scope":"PRIVATE_ARTIFACT_STORE_NOT_DEPLOYMENT"}`), nil }

func cloneArtifactDescriptor(value ArtifactDescriptor) ArtifactDescriptor {
	a := &LabConfigArtifact{descriptor: value.Config}
	value.Config = a.Descriptor()
	return value
}
func artifactRecordFor(d ArtifactDescriptor) artifactRecord {
	return artifactRecord{artifactRecordSchema, d.Config, d.SourceSpecSHA256, d.SourceSpecBytes, d.ControllerPort, d.MixedPort}
}
func backupRecordFor(d BackupDescriptor) backupRecord {
	return backupRecord{backupRecordSchema, d.OperationID, d.Artifact, d.Target}
}
func newArtifactDescriptor(config LabConfigDescriptor, sourceSHA256 string, sourceBytes int, controllerPort, mixedPort uint16) (ArtifactDescriptor, error) {
	config = (&LabConfigArtifact{descriptor: config}).Descriptor()
	d := ArtifactDescriptor{Schema: ArtifactSchema, Config: config, SourceSpecSHA256: sourceSHA256, SourceSpecBytes: sourceBytes, ControllerPort: controllerPort, MixedPort: mixedPort}
	raw, err := json.Marshal(artifactRecordFor(d))
	if err != nil { return ArtifactDescriptor{}, ErrArtifactUnsafe }
	d.RecordSHA256 = labConfigHash(raw)
	if err := validateArtifactDescriptor(d); err != nil { return ArtifactDescriptor{}, err }
	return cloneArtifactDescriptor(d), nil
}
func validateArtifactDescriptor(d ArtifactDescriptor) error {
	c := d.Config
	wantCapabilities := []string{"static_domain_suffix_rules", "explicit_selectors", "loopback_http_nodes", "private_loopback_controller", "built_in_dns_disabled"}
	if d.Schema != ArtifactSchema || !artifactDigest.MatchString(d.RecordSHA256) || !artifactDigest.MatchString(d.SourceSpecSHA256) || d.SourceSpecBytes < 1 || d.SourceSpecBytes > maxSourceSpecBytes || d.ControllerPort < 1024 || d.MixedPort < 1024 || d.ControllerPort == d.MixedPort || c.Schema != "chengwang.mihomo-lab-config/v1" || c.Scope != LabConfigScope || !artifactDigest.MatchString(c.SHA256) || c.Bytes < 1 || c.Bytes > MaxLabConfigBytes || !artifactDigest.MatchString(c.DraftSHA256) || !artifactDigest.MatchString(c.RequirementsSHA256) || !c.Admissible || len(c.Requirements) != 0 || len(c.Blockers) != 0 || !reflect.DeepEqual(c.Capabilities, wantCapabilities) { return ErrArtifactBinding }
	req, err := json.Marshal(struct { Schema string `json:"schema"`; Draft string `json:"draftSHA256"`; Requirements []LabPolicyRequirement `json:"requirements"` }{"chengwang.lab-policy-requirements/v1", c.DraftSHA256, []LabPolicyRequirement{}})
	if err != nil || labConfigHash(req) != c.RequirementsSHA256 { return ErrArtifactBinding }
	raw, err := json.Marshal(artifactRecordFor(d))
	if err != nil || labConfigHash(raw) != d.RecordSHA256 { return ErrArtifactBinding }
	return nil
}
func newBackupDescriptor(operationID string, artifact ArtifactDescriptor, target TargetBinding) (BackupDescriptor, error) {
	d := BackupDescriptor{Schema: BackupSchema, OperationID: operationID, Artifact: cloneArtifactDescriptor(artifact), Target: target}
	raw, err := json.Marshal(backupRecordFor(d))
	if err != nil { return BackupDescriptor{}, ErrArtifactUnsafe }
	d.BackupSHA256 = labConfigHash(raw)
	if err := validateBackupDescriptor(d); err != nil { return BackupDescriptor{}, err }
	return d, nil
}
func validateBackupDescriptor(d BackupDescriptor) error {
	if d.Schema != BackupSchema || !artifactOperation.MatchString(d.OperationID) || !artifactDigest.MatchString(d.BackupSHA256) || validateArtifactDescriptor(d.Artifact) != nil || validateTargetBinding(d.Target) != nil || d.Artifact.ControllerPort != d.Target.ControllerPort || d.Artifact.MixedPort != d.Target.MixedPort { return ErrArtifactBinding }
	raw, err := json.Marshal(backupRecordFor(d))
	if err != nil || labConfigHash(raw) != d.BackupSHA256 { return ErrArtifactBinding }
	return nil
}

func artifactDecode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw)); d.DisallowUnknownFields()
	if d.Decode(value) != nil { return ErrArtifactUnsafe }
	var extra any
	if d.Decode(&extra) != io.EOF { return ErrArtifactUnsafe }
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) { return ErrArtifactUnsafe }
	return nil
}
func artifactContext(ctx context.Context) error {
	if ctx == nil { return ErrArtifactUnsafe }
	v := reflect.ValueOf(ctx)
	if v.Kind() == reflect.Pointer && v.IsNil() { return ErrArtifactUnsafe }
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) { return context.DeadlineExceeded }
		return context.Canceled
	}
	return nil
}
func (s *ArtifactStore) lock(ctx context.Context) (*artifactCore, error) {
	if err := artifactContext(ctx); err != nil { return nil, err }
	if s == nil || s.core == nil { return nil, ErrArtifactUnsafe }
	c := s.core; c.mu.Lock()
	if err := artifactContext(ctx); err != nil { c.mu.Unlock(); return nil, err }
	if c.closed || c.poisoned { c.mu.Unlock(); return nil, ErrArtifactPoisoned }
	if c.disk.verify() != nil { c.poisoned = true; c.mu.Unlock(); return nil, ErrArtifactUnsafe }
	return c, nil
}

func OpenArtifactStore(directory string) (*ArtifactStore, error) {
	disk, err := openArtifactDisk(directory)
	if err != nil { return nil, err }
	keep := false
	defer func() { if !keep { _ = disk.close() } }()
	c := &artifactCore{disk: disk}
	raw, exists, err := disk.readIndex()
	if err != nil { return nil, ErrArtifactUnsafe }
	if exists {
		if artifactDecode(raw, &c.index) != nil || validateArtifactIndex(c.index) != nil { return nil, ErrArtifactUnsafe }
	} else {
		c.index = artifactIndex{artifactIndexSchema, 1, []string{}, []string{}}
		raw, _ := json.Marshal(c.index)
		uncertain, err := disk.writeIndex(raw)
		if uncertain { return nil, ErrArtifactCommitUnknown }
		if err != nil { return nil, ErrArtifactUnsafe }
	}
	// Reopen validates every referenced body/source/backup, not just the index.
	for _, id := range c.index.Artifacts { if _, _, _, err := c.load(id); err != nil { return nil, err } }
	for _, id := range c.index.Backups { if _, err := c.loadBackup(id); err != nil { return nil, err } }
	keep = true
	return &ArtifactStore{core: c}, nil
}
func validateArtifactIndex(v artifactIndex) error {
	if v.Schema != artifactIndexSchema || v.Revision == 0 || v.Artifacts == nil || v.Backups == nil || len(v.Artifacts) > maxArtifactRecords || len(v.Backups) > maxBackupRecords { return ErrArtifactUnsafe }
	for _, list := range [][]string{v.Artifacts, v.Backups} {
		seen := map[string]bool{}
		for _, id := range list { if !artifactDigest.MatchString(id) || seen[id] { return ErrArtifactUnsafe }; seen[id] = true }
	}
	return nil
}
func artifactContains(values []string, id string) bool { for _, value := range values { if value == id { return true } }; return false }
func (c *artifactCore) save(next artifactIndex) error {
	if c.index.Revision == math.MaxUint64 { return ErrArtifactLimit }
	next.Revision = c.index.Revision + 1
	if validateArtifactIndex(next) != nil { return ErrArtifactUnsafe }
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > maxArtifactIndexBytes { return ErrArtifactLimit }
	uncertain, err := c.disk.writeIndex(raw)
	if uncertain { c.poisoned = true; return ErrArtifactCommitUnknown }
	if err != nil { return ErrArtifactUnsafe }
	c.index = next
	return nil
}
func (c *artifactCore) put(raw []byte) error {
	uncertain, err := c.disk.putObject(raw)
	if uncertain { c.poisoned = true; return ErrArtifactCommitUnknown }
	// A known unsafe object is an integrity observation, not a transient write
	// rejection. A different later Put must not bypass that failed observation.
	if errors.Is(err, ErrArtifactUnsafe) { c.poisoned = true }
	if err != nil { return err }
	return nil
}
// Put captures owned private bytes and rejects any mismatch before publishing a
// reference. As with other Go value/slice APIs, callers must not concurrently
// mutate spec while it is being read. Context checks cooperate before/after
// phases; mutex and filesystem calls are not hard preemptible deadlines.
func (s *ArtifactStore) Put(ctx context.Context, spec LabConfigSpec) (ArtifactDescriptor, error) {
	if err := artifactContext(ctx); err != nil { return ArtifactDescriptor{}, err }
	artifact, err := BuildLabConfig(spec)
	if err != nil || artifact.AdmissionError() != nil { return ArtifactDescriptor{}, ErrArtifactBinding }
	wire := artifactSourceWire{"chengwang.mihomo-artifact-source/v1", spec.MixedPort, spec.ControllerPort, spec.ControllerSecret, spec.DefaultTarget, spec.Draft, spec.HTTPNodes}
	source, err := json.Marshal(wire)
	if err != nil || len(source) > maxSourceSpecBytes { return ArtifactDescriptor{}, ErrArtifactLimit }
	var owned artifactSourceWire
	if artifactDecode(source, &owned) != nil { return ArtifactDescriptor{}, ErrArtifactUnsafe }
	rebuilt, err := BuildLabConfig(LabConfigSpec{owned.MixedPort, owned.ControllerPort, owned.ControllerSecret, owned.DefaultTarget, owned.Draft, owned.HTTPNodes})
	if err != nil || rebuilt.AdmissionError() != nil || !bytes.Equal(rebuilt.Bytes(), artifact.Bytes()) || !reflect.DeepEqual(rebuilt.Descriptor(), artifact.Descriptor()) { return ArtifactDescriptor{}, ErrArtifactBinding }
	artifact = rebuilt
	d, err := newArtifactDescriptor(artifact.Descriptor(), labConfigHash(source), len(source), owned.ControllerPort, owned.MixedPort)
	if err != nil { return ArtifactDescriptor{}, err }
	c, err := s.lock(ctx)
	if err != nil { return ArtifactDescriptor{}, err }; defer c.mu.Unlock()
	if artifactContains(c.index.Artifacts, d.RecordSHA256) {
		stored, _, _, err := c.load(d.RecordSHA256)
		if err == nil { err = artifactContext(ctx) }
		if err != nil { return ArtifactDescriptor{}, err }; return stored, nil
	}
	if len(c.index.Artifacts) >= maxArtifactRecords { return ArtifactDescriptor{}, ErrArtifactLimit }
	record, _ := json.Marshal(artifactRecordFor(d))
	for _, raw := range [][]byte{artifact.Bytes(), source, record} { if err := c.put(raw); err != nil { return ArtifactDescriptor{}, err } }
	if err := artifactContext(ctx); err != nil { return ArtifactDescriptor{}, err }
	next := c.index; next.Artifacts = append(append([]string{}, c.index.Artifacts...), d.RecordSHA256)
	if err := c.save(next); err != nil { return ArtifactDescriptor{}, err }
	return cloneArtifactDescriptor(d), nil
}
func (c *artifactCore) object(id string, limit int) ([]byte, error) {
	raw, err := c.disk.readObject(id, limit)
	if err != nil || labConfigHash(raw) != id { c.poisoned = true; return nil, ErrArtifactUnsafe }
	return raw, nil
}
func (c *artifactCore) load(id string) (result ArtifactDescriptor, payload *LabConfigArtifact, source artifactSourceWire, err error) {
	defer func() { if err != nil && !errors.Is(err, ErrArtifactNotFound) { c.poisoned = true } }()
	if !artifactContains(c.index.Artifacts, id) { return ArtifactDescriptor{}, nil, source, ErrArtifactNotFound }
	raw, err := c.object(id, 64 << 10)
	if err != nil { return ArtifactDescriptor{}, nil, source, err }
	var record artifactRecord
	if artifactDecode(raw, &record) != nil || record.Schema != artifactRecordSchema { return ArtifactDescriptor{}, nil, source, ErrArtifactUnsafe }
	d, err := newArtifactDescriptor(record.Config, record.SourceSpecSHA256, record.SourceSpecBytes, record.ControllerPort, record.MixedPort)
	if err != nil || d.RecordSHA256 != id { return ArtifactDescriptor{}, nil, source, ErrArtifactBinding }
	sourceRaw, err := c.object(d.SourceSpecSHA256, maxSourceSpecBytes)
	if err != nil || len(sourceRaw) != d.SourceSpecBytes || artifactDecode(sourceRaw, &source) != nil || source.Schema != "chengwang.mihomo-artifact-source/v1" { return ArtifactDescriptor{}, nil, source, ErrArtifactUnsafe }
	spec := LabConfigSpec{source.MixedPort, source.ControllerPort, source.ControllerSecret, source.DefaultTarget, source.Draft, source.HTTPNodes}
	a, err := BuildLabConfig(spec)
	if err != nil || a.AdmissionError() != nil || !reflect.DeepEqual(a.Descriptor(), d.Config) || source.ControllerPort != d.ControllerPort || source.MixedPort != d.MixedPort { return ArtifactDescriptor{}, nil, source, ErrArtifactBinding }
	config, err := c.object(d.Config.SHA256, MaxLabConfigBytes)
	if err != nil || len(config) != d.Config.Bytes || !bytes.Equal(config, a.Bytes()) { return ArtifactDescriptor{}, nil, source, ErrArtifactUnsafe }
	return cloneArtifactDescriptor(d), a, source, nil
}
func (s *ArtifactStore) Describe(ctx context.Context, id string) (ArtifactDescriptor, error) {
	c, err := s.lock(ctx); if err != nil { return ArtifactDescriptor{}, err }; defer c.mu.Unlock()
	d, _, _, err := c.load(id)
	if err == nil { err = artifactContext(ctx) }
	if err != nil { return ArtifactDescriptor{}, err }; return d, nil
}
func (s *ArtifactStore) ReadPrivate(ctx context.Context, id string) (*LabConfigArtifact, error) {
	c, err := s.lock(ctx); if err != nil { return nil, err }; defer c.mu.Unlock()
	_, a, _, err := c.load(id)
	if err == nil { err = artifactContext(ctx) }
	if err != nil { return nil, err }; return a, nil
}
func (s *ArtifactStore) CreateBackup(ctx context.Context, operationID string, old TargetBinding, id string) (BackupDescriptor, error) {
	c, err := s.lock(ctx); if err != nil { return BackupDescriptor{}, err }; defer c.mu.Unlock()
	d, _, _, err := c.load(id)
	if err != nil { return BackupDescriptor{}, err }
	b, err := newBackupDescriptor(operationID, d, old)
	if err != nil { return BackupDescriptor{}, err }
	if err := artifactContext(ctx); err != nil { return BackupDescriptor{}, err }
	if artifactContains(c.index.Backups, b.BackupSHA256) {
		stored, err := c.loadBackup(b.BackupSHA256)
		if err == nil { err = artifactContext(ctx) }
		if err != nil { return BackupDescriptor{}, err }; return stored, nil
	}
	if len(c.index.Backups) >= maxBackupRecords { return BackupDescriptor{}, ErrArtifactLimit }
	raw, _ := json.Marshal(backupRecordFor(b))
	if err := c.put(raw); err != nil { return BackupDescriptor{}, err }
	if err := artifactContext(ctx); err != nil { return BackupDescriptor{}, err }
	next := c.index; next.Backups = append(append([]string{}, c.index.Backups...), b.BackupSHA256)
	if err := c.save(next); err != nil { return BackupDescriptor{}, err }
	return b, nil
}
func (c *artifactCore) loadBackup(id string) (result BackupDescriptor, err error) {
	defer func() { if err != nil && !errors.Is(err, ErrArtifactNotFound) { c.poisoned = true } }()
	if !artifactContains(c.index.Backups, id) { return BackupDescriptor{}, ErrArtifactNotFound }
	raw, err := c.object(id, 128 << 10)
	if err != nil { return BackupDescriptor{}, err }
	var record backupRecord
	if artifactDecode(raw, &record) != nil || record.Schema != backupRecordSchema { return BackupDescriptor{}, ErrArtifactUnsafe }
	b, err := newBackupDescriptor(record.OperationID, record.Artifact, record.Target)
	if err != nil || b.BackupSHA256 != id { return BackupDescriptor{}, ErrArtifactBinding }
	d, _, _, err := c.load(b.Artifact.RecordSHA256)
	if err != nil || !reflect.DeepEqual(d, b.Artifact) { return BackupDescriptor{}, ErrArtifactBinding }
	return b, nil
}
func (s *ArtifactStore) ReadBackupPrivate(ctx context.Context, id, operationID string, expected TargetBinding) (*LabConfigArtifact, error) {
	c, err := s.lock(ctx); if err != nil { return nil, err }; defer c.mu.Unlock()
	b, err := c.loadBackup(id)
	if err != nil { return nil, err }
	if operationID != b.OperationID || validateTargetBinding(expected) != nil || !reflect.DeepEqual(expected, b.Target) { return nil, ErrArtifactBinding }
	_, a, _, err := c.load(b.Artifact.RecordSHA256)
	if err == nil { err = artifactContext(ctx) }
	if err != nil { return nil, err }; return a, nil
}
func (s *ArtifactStore) Close() error {
	if s == nil || s.core == nil { return ErrArtifactUnsafe }
	c := s.core; c.mu.Lock(); defer c.mu.Unlock()
	if c.closed { return nil }; c.closed = true
	if c.disk.close() != nil { return ErrArtifactUnsafe }; return nil
}
