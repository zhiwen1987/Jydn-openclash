// Package restorecontracts defines strict, side-effect-free contracts for a
// future probe-state restore coordinator. Parsing a document only validates
// claims; it does not prove that a collector is truthful, that storage is
// WORM, or that any live restore action is safe to perform.
package restorecontracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	BackupV3Schema          = "chengwang.m2b-probe-backup/v3"
	RestoreEvidenceV1Schema = "chengwang.probe-restore-evidence/v1"
	AnchorV1Schema          = "chengwang.probe-restore-anchor/v1"
	CheckpointV1Schema      = "chengwang.probe-receipt-checkpoint/v1"

	MaxDocumentBytes = 128 * 1024
	MaxJSONDepth     = 16
	MaxChecks        = 32
	MaxReceiptCount  = 1_000_000_000

	maxFutureSkewSeconds = int64(5)
	maxUnix              = int64(253402300799)
	maxBackupLifetime    = int64(3600)
	maxEvidenceAgeNS     = uint64(300 * time.Second)
	maxClaimsAge         = 10 * time.Minute
	maxMinimumRetention  = 10 * 365 * 24 * time.Hour
)

var (
	ErrInvalidDocument = errors.New("invalid restore contract document")
	safeID             = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	safeReason         = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	journalHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	backupIDPattern    = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
	imageRefPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,511}$`)
	posixPathPattern   = regexp.MustCompile(`^/(?:[A-Za-z0-9_][A-Za-z0-9._-]*)(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*$`)
	bootIDPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
	base64Pattern      = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	wormBackendClasses = map[string]bool{
		"REMOTE_OBJECT_LOCK":        true,
		"REMOTE_APPEND_ONLY_LEDGER": true,
		"HARDWARE_MONOTONIC":        true,
	}
	signerAlgorithms = map[string]bool{
		"ED25519":           true,
		"ECDSA_P256_SHA256": true,
	}
)

type CandidateIdentity struct {
	CandidateID      string `json:"candidateId"`
	ProjectName      string `json:"projectName"`
	ServiceName      string `json:"serviceName"`
	CandidateRoot    string `json:"candidateRoot"`
	StateMountTarget string `json:"stateMountTarget"`
}

type ConfigurationBinding struct {
	ImageID                    string `json:"imageId"`
	ImageManifestDigest        string `json:"imageManifestDigest"`
	ImageReference             string `json:"imageReference"`
	ComposeSourceSHA256        string `json:"composeSourceSha256"`
	ComposeRenderedSHA256      string `json:"composeRenderedSha256"`
	ProbeEnvSHA256             string `json:"probeEnvSha256"`
	CatalogSHA256              string `json:"catalogSha256"`
	DotCASHA256                string `json:"dotCaSha256"`
	EgressPolicySHA256         string `json:"egressPolicySha256"`
	ConfigurationBindingSHA256 string `json:"configurationBindingSha256"`
}

type BackupState struct {
	ArchiveSHA256          string `json:"archiveSha256"`
	TreeSHA256             string `json:"treeSha256"`
	ValidationReportSHA256 string `json:"validationReportSha256"`
	RelationshipComplete   bool   `json:"relationshipComplete"`
}

type BackupV3 struct {
	Schema                  string               `json:"schema"`
	BackupID                string               `json:"backupId"`
	CreatedUnix             int64                `json:"createdUnix"`
	ExpiresUnix             int64                `json:"expiresUnix"`
	SourceBootID            string               `json:"sourceBootId"`
	WasRunningBeforeQuiesce bool                 `json:"wasRunningBeforeQuiesce"`
	Candidate               CandidateIdentity    `json:"candidate"`
	Configuration           ConfigurationBinding `json:"configuration"`
	State                   BackupState          `json:"state"`
}

// StateOnlyCurrent is independently observed current configuration. It is not
// populated from the backup being validated.
type StateOnlyCurrent struct {
	Candidate     CandidateIdentity
	Configuration ConfigurationBinding
}

type Collector struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	BinarySHA256 string `json:"binarySha256"`
}

type StateObject struct {
	Present bool   `json:"present"`
	SHA256  string `json:"sha256"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	MountID uint64 `json:"mountId"`
}

type Topology struct {
	Live  StateObject `json:"live"`
	Stage StateObject `json:"stage"`
}

type EvidenceCheck struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	EvidenceSHA256 string `json:"evidenceSha256"`
}

type EvidenceBinding struct {
	BackupID                   string `json:"backupId"`
	BackupManifestSHA256       string `json:"backupManifestSha256"`
	ConfigurationBindingSHA256 string `json:"configurationBindingSha256"`
	OldStateTreeSHA256         string `json:"oldStateTreeSha256"`
	NewStateTreeSHA256         string `json:"newStateTreeSha256"`
}

type EvidencePayload struct {
	SubjectSHA256 string          `json:"subjectSha256"`
	Topology      Topology        `json:"topology"`
	Checks        []EvidenceCheck `json:"checks"`
}

type RestoreEvidenceV1 struct {
	Schema                    string            `json:"schema"`
	Kind                      string            `json:"kind"`
	OperationID               string            `json:"operationId"`
	TransitionSequence        uint64            `json:"transitionSequence"`
	FromPhase                 string            `json:"fromPhase"`
	TargetPhase               string            `json:"targetPhase"`
	ReasonCode                string            `json:"reasonCode"`
	PreviousJournalHeadSHA256 string            `json:"previousJournalHeadSha256"`
	CapturedUnix              int64             `json:"capturedUnix"`
	ExpiresUnix               int64             `json:"expiresUnix"`
	BootID                    string            `json:"bootId"`
	BoottimeNS                uint64            `json:"boottimeNs"`
	Candidate                 CandidateIdentity `json:"candidate"`
	Binding                   EvidenceBinding   `json:"binding"`
	Collector                 Collector         `json:"collector"`
	PayloadSchema             string            `json:"payloadSchema"`
	Payload                   EvidencePayload   `json:"payload"`
}

// ParsedEvidence carries the SHA-256 of the exact input bytes. This is the
// digest a coordinator may pass to proberestore as EvidenceSHA256. Re-encoded
// JSON is deliberately never used for that purpose.
type ParsedEvidence struct {
	document  RestoreEvidenceV1
	rawSHA256 string
}

type CASBinding struct {
	BackendID        string `json:"backendId"`
	ObjectKey        string `json:"objectKey"`
	ExpectedVersion  string `json:"expectedVersion"`
	CommittedVersion string `json:"committedVersion"`
}

type WORMBinding struct {
	BackendClass       string `json:"backendClass"`
	BackendID          string `json:"backendId"`
	ObjectKey          string `json:"objectKey"`
	ObjectVersion      string `json:"objectVersion"`
	RetentionUntilUnix int64  `json:"retentionUntilUnix"`
	Independent        bool   `json:"independent"`
}

type Signer struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
}

type RestoreAnchorV1 struct {
	Schema                   string      `json:"schema"`
	CandidateID              string      `json:"candidateId"`
	OperationID              string      `json:"operationId"`
	Generation               uint64      `json:"generation"`
	JournalHeadSHA256        string      `json:"journalHeadSha256"`
	Phase                    string      `json:"phase"`
	BackupID                 string      `json:"backupId"`
	BackupManifestSHA256     string      `json:"backupManifestSha256"`
	ControlRecordSHA256      string      `json:"controlRecordSha256"`
	ReceiptAccumulatorSHA256 string      `json:"receiptAccumulatorSha256"`
	BootID                   string      `json:"bootId"`
	PreviousAnchorSHA256     string      `json:"previousAnchorSha256"`
	CreatedUnix              int64       `json:"createdUnix"`
	CAS                      CASBinding  `json:"cas"`
	WORM                     WORMBinding `json:"worm"`
	Signer                   Signer      `json:"signer"`
	Signature                string      `json:"signature"`
}

type ReceiptIndex struct {
	BackendID     string `json:"backendId"`
	ObjectKey     string `json:"objectKey"`
	ObjectVersion string `json:"objectVersion"`
	RootSHA256    string `json:"rootSha256"`
	Count         uint64 `json:"count"`
}

type ReceiptIndexes struct {
	Operations ReceiptIndex `json:"operations"`
	Backups    ReceiptIndex `json:"backups"`
	Manifests  ReceiptIndex `json:"manifests"`
}

type ReceiptCheckpointV1 struct {
	Schema                   string         `json:"schema"`
	CandidateID              string         `json:"candidateId"`
	CheckpointGeneration     uint64         `json:"checkpointGeneration"`
	ThroughGeneration        uint64         `json:"throughGeneration"`
	CreatedUnix              int64          `json:"createdUnix"`
	ReceiptCount             uint64         `json:"receiptCount"`
	ReceiptAccumulatorSHA256 string         `json:"receiptAccumulatorSha256"`
	PreviousCheckpointSHA256 string         `json:"previousCheckpointSha256"`
	AnchorSHA256             string         `json:"anchorSha256"`
	Indexes                  ReceiptIndexes `json:"indexes"`
	CAS                      CASBinding     `json:"cas"`
	WORM                     WORMBinding    `json:"worm"`
	Signer                   Signer         `json:"signer"`
	Signature                string         `json:"signature"`
}

type EvidenceContext struct {
	Now                       time.Time
	OperationID               string
	TransitionSequence        uint64
	FromPhase                 string
	Kind                      string
	ReasonCode                string
	TargetPhase               string
	PreviousJournalHeadSHA256 string
	BootID                    string
	CurrentBoottimeNS         uint64
	MaxBoottimeAgeNS          uint64
	Candidate                 CandidateIdentity
	Binding                   EvidenceBinding
	SubjectSHA256             string
	Collector                 Collector
	Topology                  Topology
	RawBytesSHA256            string
}

type AnchorContext struct {
	Now                      time.Time
	CandidateID              string
	OperationID              string
	Generation               uint64
	PreviousAnchorSHA256     string
	BootID                   string
	MaxAge                   time.Duration
	JournalHeadSHA256        string
	Phase                    string
	BackupID                 string
	BackupManifestSHA256     string
	ControlRecordSHA256      string
	ReceiptAccumulatorSHA256 string
	BackendClass             string
	CASBackendID             string
	CASObjectKey             string
	WORMBackendID            string
	WORMObjectKey            string
	CASExpectedVersion       string
	SignerKeyID              string
	SignerAlgorithm          string
	MinimumRetention         time.Duration
}

type CheckpointContext struct {
	Now                      time.Time
	CandidateID              string
	CheckpointGeneration     uint64
	PreviousCheckpointSHA256 string
	AnchorSHA256             string
	MaxAge                   time.Duration
	ThroughGeneration        uint64
	ReceiptCount             uint64
	ReceiptAccumulatorSHA256 string
	Indexes                  ReceiptIndexes
	BackendClass             string
	CASBackendID             string
	CASObjectKey             string
	WORMBackendID            string
	WORMObjectKey            string
	CASExpectedVersion       string
	SignerKeyID              string
	SignerAlgorithm          string
	MinimumRetention         time.Duration
}

type ParsedBackupV3 struct {
	document BackupV3
	parsedAt time.Time
}

type UnverifiedAnchorClaims struct {
	document RestoreAnchorV1
}

type UnverifiedReceiptCheckpointClaims struct {
	document ReceiptCheckpointV1
}

func ParseBackupV3(data []byte, now time.Time) (ParsedBackupV3, error) {
	var v BackupV3
	if err := strictDecode(data, &v); err != nil {
		return ParsedBackupV3{}, err
	}
	if err := validateBackup(v, now); err != nil {
		return ParsedBackupV3{}, err
	}
	return ParsedBackupV3{document: v, parsedAt: now.UTC()}, nil
}

func ParseRestoreEvidenceV1(data []byte, context EvidenceContext) (ParsedEvidence, error) {
	var v RestoreEvidenceV1
	if err := strictDecode(data, &v); err != nil {
		return ParsedEvidence{}, err
	}
	rawSHA256 := rawDigestBytes(data)
	if err := validateEvidence(v, context, rawSHA256); err != nil {
		return ParsedEvidence{}, err
	}
	return ParsedEvidence{document: v, rawSHA256: rawSHA256}, nil
}

func ParseUnverifiedAnchorClaims(data []byte, context AnchorContext) (UnverifiedAnchorClaims, error) {
	var v RestoreAnchorV1
	if err := strictDecode(data, &v); err != nil {
		return UnverifiedAnchorClaims{}, err
	}
	if err := validateAnchor(v, context); err != nil {
		return UnverifiedAnchorClaims{}, err
	}
	return UnverifiedAnchorClaims{document: v}, nil
}

func ParseUnverifiedReceiptCheckpointClaims(data []byte, context CheckpointContext) (UnverifiedReceiptCheckpointClaims, error) {
	var v ReceiptCheckpointV1
	if err := strictDecode(data, &v); err != nil {
		return UnverifiedReceiptCheckpointClaims{}, err
	}
	if err := validateCheckpoint(v, context); err != nil {
		return UnverifiedReceiptCheckpointClaims{}, err
	}
	return UnverifiedReceiptCheckpointClaims{document: v}, nil
}

func (b ParsedBackupV3) ValidateStateOnly(now time.Time, current StateOnlyCurrent) error {
	if b.document.Schema == "" || b.parsedAt.IsZero() {
		return invalid("zero-value parsed backup is invalid")
	}
	if err := validateBackup(b.document, now); err != nil {
		return err
	}
	if now.UTC().Before(b.parsedAt) {
		return invalid("state-only validation time moved backwards")
	}
	if b.document.Candidate != current.Candidate {
		return invalid("state-only candidate identity differs")
	}
	if b.document.Configuration != current.Configuration {
		left, right := configurationFields(b.document.Configuration), configurationFields(current.Configuration)
		for i := range left {
			if left[i].value != right[i].value {
				return invalid("state-only %s differs", left[i].name)
			}
		}
		return invalid("state-only configuration differs")
	}
	return nil
}

func (b ParsedBackupV3) Snapshot() BackupV3 { return b.document }
func (e ParsedEvidence) Snapshot() RestoreEvidenceV1 {
	copy := e.document
	copy.Payload.Checks = append([]EvidenceCheck(nil), e.document.Payload.Checks...)
	return copy
}
func (e ParsedEvidence) RawSHA256() string                                { return e.rawSHA256 }
func (a UnverifiedAnchorClaims) Snapshot() RestoreAnchorV1                { return a.document }
func (c UnverifiedReceiptCheckpointClaims) Snapshot() ReceiptCheckpointV1 { return c.document }

func ComputeConfigurationBinding(candidate CandidateIdentity, configuration ConfigurationBinding) (string, error) {
	if err := validateCandidate(candidate); err != nil {
		return "", err
	}
	copy := configuration
	copy.ConfigurationBindingSHA256 = ""
	if err := validateConfiguration(copy, false); err != nil {
		return "", err
	}
	payload := struct {
		Schema        string               `json:"schema"`
		Candidate     CandidateIdentity    `json:"candidate"`
		Configuration ConfigurationBinding `json:"configuration"`
	}{"chengwang.probe-state-only-binding/v1", candidate, copy}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return digestBytes(b), nil
}

func strictDecode(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxDocumentBytes {
		return invalid("document size must be between 1 and %d bytes", MaxDocumentBytes)
	}
	if err := scanJSON(data); err != nil {
		return err
	}
	var shape any
	shapeDecoder := json.NewDecoder(bytes.NewReader(data))
	shapeDecoder.UseNumber()
	if err := shapeDecoder.Decode(&shape); err != nil {
		return invalid("shape decode: %v", err)
	}
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer || targetType.Elem().Kind() != reflect.Struct {
		return invalid("strict decoder target must point to a struct")
	}
	if err := validateRequiredShape(shape, targetType.Elem(), "$", 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalid("strict decode: %v", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}
	return nil
}

func validateRequiredShape(value any, expected reflect.Type, location string, depth int) error {
	if depth > MaxJSONDepth {
		return invalid("JSON depth exceeds %d", MaxJSONDepth)
	}
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return invalid("%s must be an object", location)
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < expected.NumField(); i++ {
			field := expected.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			fields[tag] = field.Type
		}
		for name, fieldType := range fields {
			child, exists := object[name]
			if !exists {
				return invalid("%s is missing required field %q", location, name)
			}
			if child == nil {
				return invalid("%s.%s must not be null", location, name)
			}
			if err := validateRequiredShape(child, fieldType, location+"."+name, depth+1); err != nil {
				return err
			}
		}
		for name := range object {
			if _, exists := fields[name]; !exists {
				return invalid("%s contains unknown field %q", location, name)
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return invalid("%s must be an array", location)
		}
		for i, child := range array {
			if child == nil {
				return invalid("%s[%d] must not be null", location, i)
			}
			if err := validateRequiredShape(child, expected.Elem(), fmt.Sprintf("%s[%d]", location, i), depth+1); err != nil {
				return err
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return invalid("%s must be a string", location)
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return invalid("%s must be a boolean", location)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number, ok := value.(json.Number)
		if !ok {
			return invalid("%s must be an integer", location)
		}
		if _, err := strconv.ParseInt(number.String(), 10, expected.Bits()); err != nil {
			return invalid("%s integer is out of range", location)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		number, ok := value.(json.Number)
		if !ok {
			return invalid("%s must be an unsigned integer", location)
		}
		if _, err := strconv.ParseUint(number.String(), 10, expected.Bits()); err != nil {
			return invalid("%s unsigned integer is out of range", location)
		}
	default:
		return invalid("%s uses unsupported contract type %s", location, expected.Kind())
	}
	return nil
}

type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

func scanJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	stack := make([]jsonFrame, 0, MaxJSONDepth)
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) != 0 {
				return invalid("unterminated JSON")
			}
			return nil
		}
		if err != nil {
			return invalid("JSON syntax: %v", err)
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, jsonFrame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				stack = append(stack, jsonFrame{})
			case '}', ']':
				if len(stack) == 0 {
					return invalid("unexpected JSON delimiter")
				}
				stack = stack[:len(stack)-1]
				markValueConsumed(stack)
			}
			if len(stack) > MaxJSONDepth {
				return invalid("JSON depth exceeds %d", MaxJSONDepth)
			}
		case nil:
			return invalid("null values are forbidden")
		case json.Number:
			if strings.ContainsAny(value.String(), ".eE") {
				return invalid("floating-point numbers are forbidden")
			}
			if _, err := strconv.ParseInt(value.String(), 10, 64); err != nil {
				if _, unsignedErr := strconv.ParseUint(value.String(), 10, 64); unsignedErr != nil {
					return invalid("JSON integer is out of range")
				}
			}
			markValueConsumed(stack)
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				frame := &stack[len(stack)-1]
				if _, exists := frame.keys[value]; exists {
					return invalid("duplicate JSON key %q", value)
				}
				frame.keys[value] = struct{}{}
				frame.expectKey = false
			} else {
				markValueConsumed(stack)
			}
		default:
			markValueConsumed(stack)
		}
	}
}

func markValueConsumed(stack []jsonFrame) {
	if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
		stack[len(stack)-1].expectKey = true
	}
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("multiple JSON documents are forbidden")
		}
		return invalid("trailing JSON: %v", err)
	}
	return nil
}

func validateBackup(v BackupV3, now time.Time) error {
	if v.Schema != BackupV3Schema || !backupIDPattern.MatchString(v.BackupID) {
		return invalid("backup schema or backupId is invalid")
	}
	if err := validateWindow(v.CreatedUnix, v.ExpiresUnix, now, maxBackupLifetime); err != nil {
		return fmt.Errorf("%w: backup %v", ErrInvalidDocument, err)
	}
	if !bootIDPattern.MatchString(v.SourceBootID) {
		return invalid("sourceBootId is invalid")
	}
	if err := validateCandidate(v.Candidate); err != nil {
		return err
	}
	if err := validateConfiguration(v.Configuration, true); err != nil {
		return err
	}
	want, err := ComputeConfigurationBinding(v.Candidate, v.Configuration)
	if err != nil || v.Configuration.ConfigurationBindingSHA256 != want {
		return invalid("configuration binding digest mismatch")
	}
	if !isDigest(v.State.ArchiveSHA256) || !isDigest(v.State.TreeSHA256) || !isDigest(v.State.ValidationReportSHA256) {
		return invalid("backup state digest is invalid")
	}
	if !v.State.RelationshipComplete {
		return invalid("relationshipComplete must be true")
	}
	return nil
}

func validateEvidence(v RestoreEvidenceV1, c EvidenceContext, rawSHA256 string) error {
	if v.Schema != RestoreEvidenceV1Schema || !safeID.MatchString(v.OperationID) || v.TransitionSequence < 2 {
		return invalid("evidence schema, operationId, or sequence is invalid")
	}
	phase, ok := evidencePhases[v.Kind]
	if !ok || v.TargetPhase != phase || !validPhase(v.FromPhase) || !validEvidenceReason(v.Kind, v.ReasonCode) {
		return invalid("evidence kind, phase, or reason binding is invalid")
	}
	if !isJournalHash(v.PreviousJournalHeadSHA256) || !bootIDPattern.MatchString(v.BootID) || v.BoottimeNS == 0 {
		return invalid("evidence journal head or boot binding is invalid")
	}
	if err := validateWindow(v.CapturedUnix, v.ExpiresUnix, c.Now, evidenceMaxLifetime(v.Kind)); err != nil {
		return fmt.Errorf("%w: evidence %v", ErrInvalidDocument, err)
	}
	if err := validateCandidate(v.Candidate); err != nil {
		return err
	}
	if err := validateEvidenceBinding(v.Binding); err != nil {
		return err
	}
	if err := validateCollector(v.Collector); err != nil {
		return err
	}
	if v.PayloadSchema != "chengwang.probe-restore-evidence."+strings.ToLower(strings.ReplaceAll(v.Kind, "_", "-"))+"/v1" {
		return invalid("payload schema does not match evidence kind")
	}
	if err := validatePayload(v.Kind, v.Payload); err != nil {
		return err
	}
	if c.OperationID == "" || v.OperationID != c.OperationID || v.TransitionSequence != c.TransitionSequence || v.FromPhase != c.FromPhase || v.Kind != c.Kind || v.ReasonCode != c.ReasonCode || v.TargetPhase != c.TargetPhase || v.PreviousJournalHeadSHA256 != c.PreviousJournalHeadSHA256 || v.BootID != c.BootID || v.Candidate != c.Candidate || v.Binding != c.Binding || v.Payload.SubjectSHA256 != c.SubjectSHA256 || v.Collector != c.Collector || v.Payload.Topology != c.Topology {
		return invalid("evidence does not match its independent operation context")
	}
	if !isJournalHash(c.RawBytesSHA256) || rawSHA256 != c.RawBytesSHA256 {
		return invalid("evidence raw bytes do not match the independent SHA-256 context")
	}
	if c.CurrentBoottimeNS == 0 || c.MaxBoottimeAgeNS == 0 || c.MaxBoottimeAgeNS > maxEvidenceAgeNS || v.BoottimeNS > c.CurrentBoottimeNS || c.CurrentBoottimeNS-v.BoottimeNS > c.MaxBoottimeAgeNS {
		return invalid("evidence boottime is future, stale, or lacks a bounded independent context")
	}
	if err := validateEvidenceTopology(v); err != nil {
		return err
	}
	return nil
}

type topologyClass string

const (
	topologyOldOnly topologyClass = "OLD_ONLY"
	topologyOldNew  topologyClass = "OLD_NEW"
	topologyNewOld  topologyClass = "NEW_OLD"
)

func classifyTopology(topology Topology, binding EvidenceBinding) (topologyClass, error) {
	live, stage := topology.Live, topology.Stage
	switch {
	case live.Present && live.SHA256 == binding.OldStateTreeSHA256 && !stage.Present:
		return topologyOldOnly, nil
	case live.Present && stage.Present && live.SHA256 == binding.OldStateTreeSHA256 && stage.SHA256 == binding.NewStateTreeSHA256:
		return topologyOldNew, nil
	case live.Present && stage.Present && live.SHA256 == binding.NewStateTreeSHA256 && stage.SHA256 == binding.OldStateTreeSHA256:
		return topologyNewOld, nil
	default:
		return "", invalid("topology does not bind live/stage identities to old/new state digests")
	}
}

func validateEvidenceTopology(v RestoreEvidenceV1) error {
	contract, exists := evidenceTopology[v.Kind]
	if !exists || !contract.from[v.FromPhase] {
		return invalid("evidence kind is not permitted from phase %s", v.FromPhase)
	}
	if contract.allowAnyStructuredTopology {
		// validatePayload has already enforced the exact StateObject shape, and
		// the independent EvidenceContext has already bound these exact values.
		// Rescue and lockdown must remain recordable when identity is unknown or
		// contradictory; their checks, not a familiar digest pair, prove safety.
		return nil
	}
	class, err := classifyTopology(v.Payload.Topology, v.Binding)
	if err != nil {
		return err
	}
	allowed := contract.classes
	if contract.dynamic {
		allowed = phaseTopologyClasses(v.FromPhase)
	}
	if !allowed[class] {
		return invalid("topology class %s is unsafe for %s from %s", class, v.Kind, v.FromPhase)
	}
	return nil
}

type evidenceTopologyContract struct {
	from                       map[string]bool
	classes                    map[topologyClass]bool
	dynamic                    bool
	allowAnyStructuredTopology bool
}

func phases(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func classes(values ...topologyClass) map[topologyClass]bool {
	result := make(map[topologyClass]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func phaseTopologyClasses(phase string) map[topologyClass]bool {
	switch phase {
	case "NEW", "LOCKED", "INPUT_VERIFIED", "LIVE_QUIESCED", "CURRENT_BACKUP_DURABLE":
		return classes(topologyOldOnly)
	case "STAGED", "STAGED_VALIDATED", "SWITCH_ARMED", "STATE_ROLLBACK_EXCHANGED", "ROLLBACK_CONTAINER_RECREATED", "ROLLBACK_EGRESS_REBOUND", "ROLLBACK_CONTAINER_STARTED", "ROLLBACK_HEALTH_PASSED", "ROLLED_BACK":
		return classes(topologyOldNew)
	case "STATE_EXCHANGED", "CONTAINER_RECREATED", "EGRESS_REBOUND", "CONTAINER_STARTED", "LOCAL_HEALTH_PASSED", "INDEPENDENT_PROBE_PASSED", "ROLLBACK_ARMED", "COMMITTED":
		return classes(topologyNewOld)
	}
	return map[topologyClass]bool{}
}

func validateAnchor(v RestoreAnchorV1, c AnchorContext) error {
	if v.Schema != AnchorV1Schema || !safeID.MatchString(v.CandidateID) || !safeID.MatchString(v.OperationID) || v.Generation == 0 {
		return invalid("anchor schema or identity is invalid")
	}
	if !isJournalHash(v.JournalHeadSHA256) {
		return invalid("anchor journal head is invalid")
	}
	for _, value := range []string{v.BackupManifestSHA256, v.ControlRecordSHA256, v.ReceiptAccumulatorSHA256, v.PreviousAnchorSHA256} {
		if !isDigest(value) {
			return invalid("anchor digest is invalid")
		}
	}
	if !backupIDPattern.MatchString(v.BackupID) || !validPhase(v.Phase) || !bootIDPattern.MatchString(v.BootID) {
		return invalid("anchor backup, phase, or boot binding is invalid")
	}
	if err := validateClaimsContext(c.MaxAge, c.MinimumRetention); err != nil {
		return err
	}
	if err := validateCAS(v.CAS); err != nil {
		return err
	}
	if err := validateWORM(v.WORM, v.CreatedUnix, c.Now); err != nil {
		return err
	}
	if err := validateSigner(v.Signer, v.Signature); err != nil {
		return err
	}
	if err := validatePointInTime(v.CreatedUnix, c.Now, c.MaxAge); err != nil {
		return err
	}
	if c.CandidateID == "" || v.CandidateID != c.CandidateID || v.OperationID != c.OperationID || v.Generation != c.Generation || v.PreviousAnchorSHA256 != c.PreviousAnchorSHA256 || v.BootID != c.BootID || v.JournalHeadSHA256 != c.JournalHeadSHA256 || v.Phase != c.Phase || v.BackupID != c.BackupID || v.BackupManifestSHA256 != c.BackupManifestSHA256 || v.ControlRecordSHA256 != c.ControlRecordSHA256 || v.ReceiptAccumulatorSHA256 != c.ReceiptAccumulatorSHA256 || v.CAS.BackendID != c.CASBackendID || v.CAS.ObjectKey != c.CASObjectKey || v.CAS.ExpectedVersion != c.CASExpectedVersion || v.WORM.BackendClass != c.BackendClass || v.WORM.BackendID != c.WORMBackendID || v.WORM.ObjectKey != c.WORMObjectKey || v.Signer.KeyID != c.SignerKeyID || v.Signer.Algorithm != c.SignerAlgorithm {
		return invalid("anchor does not match its independent CAS context")
	}
	if v.WORM.RetentionUntilUnix < c.Now.UTC().Add(c.MinimumRetention).Unix() {
		return invalid("anchor retention is shorter than the independently required minimum")
	}
	return nil
}

func validateCheckpoint(v ReceiptCheckpointV1, c CheckpointContext) error {
	if v.Schema != CheckpointV1Schema || !safeID.MatchString(v.CandidateID) || v.CheckpointGeneration == 0 || v.ThroughGeneration == 0 || v.ThroughGeneration > v.CheckpointGeneration || v.ReceiptCount == 0 || v.ReceiptCount > MaxReceiptCount {
		return invalid("checkpoint identity, generation, or receipt count is invalid")
	}
	for _, value := range []string{v.ReceiptAccumulatorSHA256, v.PreviousCheckpointSHA256, v.AnchorSHA256} {
		if !isDigest(value) {
			return invalid("checkpoint digest is invalid")
		}
	}
	indexes := []ReceiptIndex{v.Indexes.Operations, v.Indexes.Backups, v.Indexes.Manifests}
	keys := map[string]bool{}
	for _, index := range indexes {
		if !safeID.MatchString(index.BackendID) || !versionPattern.MatchString(index.ObjectKey) || !versionPattern.MatchString(index.ObjectVersion) || !isDigest(index.RootSHA256) || index.Count != v.ReceiptCount {
			return invalid("checkpoint exact replay index is invalid")
		}
		key := index.ObjectKey
		if keys[key] {
			return invalid("checkpoint replay index object keys must be distinct")
		}
		keys[key] = true
	}
	if err := validateClaimsContext(c.MaxAge, c.MinimumRetention); err != nil {
		return err
	}
	if err := validateCAS(v.CAS); err != nil {
		return err
	}
	if err := validateWORM(v.WORM, v.CreatedUnix, c.Now); err != nil {
		return err
	}
	if err := validateSigner(v.Signer, v.Signature); err != nil {
		return err
	}
	if err := validatePointInTime(v.CreatedUnix, c.Now, c.MaxAge); err != nil {
		return err
	}
	if c.CandidateID == "" || v.CandidateID != c.CandidateID || v.CheckpointGeneration != c.CheckpointGeneration || v.ThroughGeneration != c.ThroughGeneration || v.ReceiptCount != c.ReceiptCount || v.ReceiptAccumulatorSHA256 != c.ReceiptAccumulatorSHA256 || v.PreviousCheckpointSHA256 != c.PreviousCheckpointSHA256 || v.AnchorSHA256 != c.AnchorSHA256 || v.Indexes != c.Indexes || v.CAS.BackendID != c.CASBackendID || v.CAS.ObjectKey != c.CASObjectKey || v.CAS.ExpectedVersion != c.CASExpectedVersion || v.WORM.BackendClass != c.BackendClass || v.WORM.BackendID != c.WORMBackendID || v.WORM.ObjectKey != c.WORMObjectKey || v.Signer.KeyID != c.SignerKeyID || v.Signer.Algorithm != c.SignerAlgorithm {
		return invalid("checkpoint does not match its independent rotation context")
	}
	if v.WORM.RetentionUntilUnix < c.Now.UTC().Add(c.MinimumRetention).Unix() {
		return invalid("checkpoint retention is shorter than the independently required minimum")
	}
	return nil
}

func validateClaimsContext(maxAge, minimumRetention time.Duration) error {
	if maxAge <= 0 || maxAge > maxClaimsAge {
		return invalid("claims MaxAge must be positive and at most %s", maxClaimsAge)
	}
	if minimumRetention <= 0 || minimumRetention > maxMinimumRetention {
		return invalid("minimum retention must be positive and bounded")
	}
	return nil
}

func validEvidenceReason(kind, reason string) bool {
	if !safeReason.MatchString(reason) {
		return false
	}
	if kind == "LOCKDOWN_VERIFIED" {
		return reason == "LOCKDOWN_VERIFIED"
	}
	return true
}

func validateCandidate(v CandidateIdentity) error {
	if !safeID.MatchString(v.CandidateID) || !safeID.MatchString(v.ProjectName) || !safeID.MatchString(v.ServiceName) || !isCleanAbsolutePOSIXPath(v.CandidateRoot) || !isCleanAbsolutePOSIXPath(v.StateMountTarget) {
		return invalid("candidate identity, service, root, or state mount target is invalid")
	}
	return nil
}

func validateConfiguration(v ConfigurationBinding, requireBinding bool) error {
	for _, value := range []string{v.ImageID, v.ImageManifestDigest, v.ComposeSourceSHA256, v.ComposeRenderedSHA256, v.ProbeEnvSHA256, v.CatalogSHA256, v.DotCASHA256, v.EgressPolicySHA256} {
		if !isDigest(value) {
			return invalid("configuration digest is invalid")
		}
	}
	if !imageRefPattern.MatchString(v.ImageReference) {
		return invalid("image reference is invalid")
	}
	if requireBinding && !isDigest(v.ConfigurationBindingSHA256) {
		return invalid("configuration binding digest is invalid")
	}
	if !requireBinding && v.ConfigurationBindingSHA256 != "" {
		return invalid("configuration binding must be blank while computing")
	}
	return nil
}

type namedValue struct{ name, value string }

func configurationFields(v ConfigurationBinding) []namedValue {
	return []namedValue{
		{"imageId", v.ImageID}, {"imageManifestDigest", v.ImageManifestDigest}, {"imageReference", v.ImageReference},
		{"composeSourceSha256", v.ComposeSourceSHA256}, {"composeRenderedSha256", v.ComposeRenderedSHA256},
		{"probeEnvSha256", v.ProbeEnvSHA256}, {"catalogSha256", v.CatalogSHA256}, {"dotCaSha256", v.DotCASHA256},
		{"egressPolicySha256", v.EgressPolicySHA256}, {"configurationBindingSha256", v.ConfigurationBindingSHA256},
	}
}

func validateEvidenceBinding(v EvidenceBinding) error {
	if !backupIDPattern.MatchString(v.BackupID) {
		return invalid("evidence backupId is invalid")
	}
	for _, value := range []string{v.BackupManifestSHA256, v.ConfigurationBindingSHA256, v.OldStateTreeSHA256, v.NewStateTreeSHA256} {
		if !isDigest(value) {
			return invalid("evidence binding digest is invalid")
		}
	}
	if v.OldStateTreeSHA256 == v.NewStateTreeSHA256 {
		return invalid("old and new state tree digests must differ")
	}
	return nil
}

func validateCollector(v Collector) error {
	if !safeID.MatchString(v.Name) || !versionPattern.MatchString(v.Version) || !isDigest(v.BinarySHA256) {
		return invalid("collector identity is invalid")
	}
	return nil
}

func validatePayload(kind string, v EvidencePayload) error {
	if !isDigest(v.SubjectSHA256) || len(v.Checks) == 0 || len(v.Checks) > MaxChecks {
		return invalid("evidence payload subject or check count is invalid")
	}
	if err := validateStateObject(v.Topology.Live); err != nil {
		return err
	}
	if err := validateStateObject(v.Topology.Stage); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, check := range v.Checks {
		if !safeReason.MatchString(check.Name) || !check.Passed || !isDigest(check.EvidenceSHA256) || seen[check.Name] {
			return invalid("evidence check is invalid, failed, or duplicated")
		}
		seen[check.Name] = true
	}
	for _, required := range requiredChecks[kind] {
		if !seen[required] {
			return invalid("required evidence check %s is missing", required)
		}
	}
	return nil
}

func validateStateObject(v StateObject) error {
	if v.Present {
		if !isDigest(v.SHA256) || v.Device == 0 || v.Inode == 0 || v.MountID == 0 {
			return invalid("present state object identity is incomplete")
		}
		return nil
	}
	if v.SHA256 != "" || v.Device != 0 || v.Inode != 0 || v.MountID != 0 {
		return invalid("absent state object carries identity")
	}
	return nil
}

func validateCAS(v CASBinding) error {
	if !safeID.MatchString(v.BackendID) || !versionPattern.MatchString(v.ObjectKey) || !versionPattern.MatchString(v.ExpectedVersion) || !versionPattern.MatchString(v.CommittedVersion) || v.ExpectedVersion == v.CommittedVersion {
		return invalid("CAS binding is invalid or did not advance")
	}
	return nil
}

func validateWORM(v WORMBinding, created int64, now time.Time) error {
	if !wormBackendClasses[v.BackendClass] {
		return invalid("WORM backend class is not independently anchored")
	}
	if now.IsZero() || !safeID.MatchString(v.BackendID) || !versionPattern.MatchString(v.ObjectKey) || !versionPattern.MatchString(v.ObjectVersion) || !v.Independent || v.RetentionUntilUnix > maxUnix || v.RetentionUntilUnix <= created || v.RetentionUntilUnix <= now.UTC().Unix() {
		return invalid("WORM binding or retention is invalid")
	}
	return nil
}

func validateSigner(v Signer, signature string) error {
	padding := len(signature) - len(strings.TrimRight(signature, "="))
	if !safeID.MatchString(v.KeyID) || !signerAlgorithms[v.Algorithm] || len(signature) < 4 || len(signature) > 96 || len(signature)%4 != 0 || padding > 2 || !base64Pattern.MatchString(signature) {
		return invalid("signer or signature encoding is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil {
		return invalid("signature is not strict base64")
	}
	switch v.Algorithm {
	case "ED25519":
		if len(decoded) != 64 {
			return invalid("ED25519 signature claim must contain exactly 64 bytes")
		}
	case "ECDSA_P256_SHA256":
		var pair struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(decoded, &pair)
		order, ok := new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
		if !ok || err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
			return invalid("ECDSA signature claim is not a strict positive P-256 DER pair")
		}
		canonical, marshalErr := asn1.Marshal(pair)
		if marshalErr != nil || !bytes.Equal(decoded, canonical) || pair.R.Sign() <= 0 || pair.S.Sign() <= 0 || pair.R.Cmp(order) >= 0 || pair.S.Cmp(order) >= 0 {
			return invalid("ECDSA signature claim is not a strict positive P-256 DER pair")
		}
	}
	return nil
}

func validateWindow(captured, expires int64, now time.Time, maximumLifetime int64) error {
	if now.IsZero() {
		return errors.New("independent current time is required")
	}
	current := now.UTC().Unix()
	if captured <= 0 || expires > maxUnix || expires <= captured || expires-captured > maximumLifetime || captured > current+maxFutureSkewSeconds || expires <= current {
		return errors.New("time window is stale, future-dated, reversed, or excessive")
	}
	return nil
}

func validatePointInTime(created int64, now time.Time, maxAge time.Duration) error {
	if now.IsZero() || created <= 0 || created > maxUnix || created > now.UTC().Unix()+maxFutureSkewSeconds {
		return invalid("point-in-time evidence is invalid or future-dated")
	}
	if maxAge > 0 && now.UTC().Unix()-created > int64(maxAge/time.Second) {
		return invalid("point-in-time evidence is stale")
	}
	return nil
}

func isCleanAbsolutePOSIXPath(value string) bool {
	return len(value) >= 2 && len(value) <= 1024 && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00') && !strings.Contains(value, "\\") && posixPathPattern.MatchString(value) && path.Clean(value) == value
}

func isDigest(value string) bool      { return digestPattern.MatchString(value) }
func isJournalHash(value string) bool { return journalHashPattern.MatchString(value) }

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rawDigestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func invalid(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidDocument, fmt.Sprintf(format, values...))
}

var evidencePhases = map[string]string{
	"LOCK_ACQUIRED": "LOCKED", "INPUT_BOUND": "INPUT_VERIFIED", "LIVE_QUIESCED": "LIVE_QUIESCED",
	"ROLLBACK_BACKUP_DURABLE": "CURRENT_BACKUP_DURABLE", "STAGE_DURABLE": "STAGED",
	"STAGE_VALIDATED": "STAGED_VALIDATED", "SWITCH_ARMED": "SWITCH_ARMED", "STATE_EXCHANGED": "STATE_EXCHANGED",
	"CONTAINER_RECREATED": "CONTAINER_RECREATED", "EGRESS_REBOUND": "EGRESS_REBOUND",
	"CONTAINER_STARTED": "CONTAINER_STARTED", "LOCAL_HEALTH": "LOCAL_HEALTH_PASSED",
	"INDEPENDENT_HEALTH": "INDEPENDENT_PROBE_PASSED", "COMMIT": "COMMITTED",
	"ROLLBACK_ARMED": "ROLLBACK_ARMED", "ROLLBACK_STATE_EXCHANGED": "STATE_ROLLBACK_EXCHANGED",
	"ROLLBACK_CONTAINER_RECREATED": "ROLLBACK_CONTAINER_RECREATED", "ROLLBACK_EGRESS_REBOUND": "ROLLBACK_EGRESS_REBOUND",
	"ROLLBACK_CONTAINER_STARTED": "ROLLBACK_CONTAINER_STARTED", "ROLLBACK_HEALTH": "ROLLBACK_HEALTH_PASSED",
	"ROLLBACK_COMMIT": "ROLLED_BACK", "RESCUE_REQUIRED": "RESCUE_REQUIRED", "LOCKDOWN_VERIFIED": "RESCUE_LOCKDOWN",
	"FAILURE_RECORDED": "FAILED",
}

var journalPhaseSet = map[string]bool{
	"NEW": true, "LOCKED": true, "INPUT_VERIFIED": true, "LIVE_QUIESCED": true,
	"CURRENT_BACKUP_DURABLE": true, "STAGED": true, "STAGED_VALIDATED": true, "SWITCH_ARMED": true,
	"STATE_EXCHANGED": true, "CONTAINER_RECREATED": true, "EGRESS_REBOUND": true, "CONTAINER_STARTED": true,
	"LOCAL_HEALTH_PASSED": true, "INDEPENDENT_PROBE_PASSED": true, "COMMITTED": true, "ROLLBACK_ARMED": true,
	"STATE_ROLLBACK_EXCHANGED": true, "ROLLBACK_CONTAINER_RECREATED": true, "ROLLBACK_EGRESS_REBOUND": true,
	"ROLLBACK_CONTAINER_STARTED": true, "ROLLBACK_HEALTH_PASSED": true, "ROLLED_BACK": true, "FAILED": true,
	"RESCUE_REQUIRED": true, "RESCUE_LOCKDOWN": true,
}

var evidenceTopology = map[string]evidenceTopologyContract{
	"LOCK_ACQUIRED":                {from: phases("NEW"), classes: classes(topologyOldOnly)},
	"INPUT_BOUND":                  {from: phases("LOCKED"), classes: classes(topologyOldOnly)},
	"LIVE_QUIESCED":                {from: phases("INPUT_VERIFIED"), classes: classes(topologyOldOnly)},
	"ROLLBACK_BACKUP_DURABLE":      {from: phases("LIVE_QUIESCED"), classes: classes(topologyOldOnly)},
	"STAGE_DURABLE":                {from: phases("CURRENT_BACKUP_DURABLE"), classes: classes(topologyOldNew)},
	"STAGE_VALIDATED":              {from: phases("STAGED"), classes: classes(topologyOldNew)},
	"SWITCH_ARMED":                 {from: phases("STAGED_VALIDATED"), classes: classes(topologyOldNew)},
	"STATE_EXCHANGED":              {from: phases("SWITCH_ARMED"), classes: classes(topologyNewOld)},
	"CONTAINER_RECREATED":          {from: phases("STATE_EXCHANGED"), classes: classes(topologyNewOld)},
	"EGRESS_REBOUND":               {from: phases("CONTAINER_RECREATED"), classes: classes(topologyNewOld)},
	"CONTAINER_STARTED":            {from: phases("EGRESS_REBOUND"), classes: classes(topologyNewOld)},
	"LOCAL_HEALTH":                 {from: phases("CONTAINER_STARTED"), classes: classes(topologyNewOld)},
	"INDEPENDENT_HEALTH":           {from: phases("LOCAL_HEALTH_PASSED"), classes: classes(topologyNewOld)},
	"COMMIT":                       {from: phases("INDEPENDENT_PROBE_PASSED"), classes: classes(topologyNewOld)},
	"ROLLBACK_ARMED":               {from: phases("STATE_EXCHANGED", "CONTAINER_RECREATED", "EGRESS_REBOUND", "CONTAINER_STARTED", "LOCAL_HEALTH_PASSED", "INDEPENDENT_PROBE_PASSED"), classes: classes(topologyNewOld)},
	"ROLLBACK_STATE_EXCHANGED":     {from: phases("ROLLBACK_ARMED"), classes: classes(topologyOldNew)},
	"ROLLBACK_CONTAINER_RECREATED": {from: phases("STATE_ROLLBACK_EXCHANGED"), classes: classes(topologyOldNew)},
	"ROLLBACK_EGRESS_REBOUND":      {from: phases("ROLLBACK_CONTAINER_RECREATED"), classes: classes(topologyOldNew)},
	"ROLLBACK_CONTAINER_STARTED":   {from: phases("ROLLBACK_EGRESS_REBOUND"), classes: classes(topologyOldNew)},
	"ROLLBACK_HEALTH":              {from: phases("ROLLBACK_CONTAINER_STARTED"), classes: classes(topologyOldNew)},
	"ROLLBACK_COMMIT":              {from: phases("ROLLBACK_HEALTH_PASSED"), classes: classes(topologyOldNew)},
	"FAILURE_RECORDED":             {from: phases("NEW", "LOCKED", "INPUT_VERIFIED", "LIVE_QUIESCED", "CURRENT_BACKUP_DURABLE", "STAGED", "STAGED_VALIDATED", "SWITCH_ARMED"), dynamic: true},
	"RESCUE_REQUIRED":              {from: phases("NEW", "LOCKED", "INPUT_VERIFIED", "LIVE_QUIESCED", "CURRENT_BACKUP_DURABLE", "STAGED", "STAGED_VALIDATED", "SWITCH_ARMED", "STATE_EXCHANGED", "CONTAINER_RECREATED", "EGRESS_REBOUND", "CONTAINER_STARTED", "LOCAL_HEALTH_PASSED", "INDEPENDENT_PROBE_PASSED", "ROLLBACK_ARMED", "STATE_ROLLBACK_EXCHANGED", "ROLLBACK_CONTAINER_RECREATED", "ROLLBACK_EGRESS_REBOUND", "ROLLBACK_CONTAINER_STARTED", "ROLLBACK_HEALTH_PASSED"), allowAnyStructuredTopology: true},
	"LOCKDOWN_VERIFIED":            {from: phases("RESCUE_REQUIRED"), allowAnyStructuredTopology: true},
}

var requiredChecks = map[string][]string{
	"LOCK_ACQUIRED":                {"LIFECYCLE_LOCK_UNIQUE", "JOURNAL_WRITER_LOCK_UNIQUE"},
	"INPUT_BOUND":                  {"BACKUP_V3_VALID", "STATE_ONLY_BINDING_EQUAL"},
	"LIVE_QUIESCED":                {"CONTAINER_STOPPED", "NO_STATE_WRITERS"},
	"ROLLBACK_BACKUP_DURABLE":      {"OLD_STATE_BACKUP_FSYNCED"},
	"STAGE_DURABLE":                {"STAGE_TREE_FSYNCED"},
	"STAGE_VALIDATED":              {"RELATIONSHIP_COMPLETE"},
	"SWITCH_ARMED":                 {"RENAME_EXCHANGE_SUPPORTED", "TOPOLOGY_OLD_NEW"},
	"STATE_EXCHANGED":              {"TOPOLOGY_NEW_OLD"},
	"CONTAINER_RECREATED":          {"CONTAINER_RECREATED_STOPPED"},
	"EGRESS_REBOUND":               {"DEFAULT_DENY_BOUND_TO_NEW_IDENTITY"},
	"CONTAINER_STARTED":            {"CONTAINER_RUNNING"},
	"LOCAL_HEALTH":                 {"LOCAL_HEALTH_PASSED", "EGRESS_COUNTERS_ADVANCED"},
	"INDEPENDENT_HEALTH":           {"INDEPENDENT_PROBE_PASSED"},
	"COMMIT":                       {"FINAL_TOPOLOGY_NEW_LIVE"},
	"ROLLBACK_ARMED":               {"TOPOLOGY_NEW_OLD"},
	"ROLLBACK_STATE_EXCHANGED":     {"TOPOLOGY_OLD_NEW"},
	"ROLLBACK_CONTAINER_RECREATED": {"CONTAINER_RECREATED_STOPPED"},
	"ROLLBACK_EGRESS_REBOUND":      {"DEFAULT_DENY_BOUND_TO_NEW_IDENTITY"},
	"ROLLBACK_CONTAINER_STARTED":   {"CONTAINER_RUNNING"},
	"ROLLBACK_HEALTH":              {"LOCAL_HEALTH_PASSED"},
	"ROLLBACK_COMMIT":              {"FINAL_TOPOLOGY_OLD_LIVE"},
	"RESCUE_REQUIRED":              {"AUTOMATIC_RECOVERY_UNSAFE"},
	"LOCKDOWN_VERIFIED":            {"NO_RUNNING_CONTAINER", "NO_STATE_WRITERS", "NO_EGRESS"},
	"FAILURE_RECORDED":             {"FAILURE_EVIDENCE_DURABLE"},
}

func evidenceMaxLifetime(kind string) int64 {
	switch kind {
	case "STAGE_DURABLE", "STAGE_VALIDATED", "ROLLBACK_BACKUP_DURABLE":
		return 300
	default:
		return 30
	}
}

func validPhase(phase string) bool {
	return journalPhaseSet[phase]
}

// EvidenceKinds returns a stable copy for schema/test parity checks.
func EvidenceKinds() []string {
	result := make([]string, 0, len(evidencePhases))
	for item := range evidencePhases {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func JournalPhases() []string {
	result := make([]string, 0, len(journalPhaseSet))
	for item := range journalPhaseSet {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}
