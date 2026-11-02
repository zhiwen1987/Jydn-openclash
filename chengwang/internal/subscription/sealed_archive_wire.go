package subscription

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	sealedArchiveMetaSchemaV8       = "chengwang.subscription-archive-meta/v2"
	sealedArchiveCandidateSchemaV8  = "chengwang.subscription-archive-candidate-envelope/v2"
	sealedArchiveGenesisSchemaV8    = "chengwang.subscription-archive-genesis-envelope/v2"
	sealedArchiveHistorySchemaV8    = "chengwang.subscription-archive-history-segment-envelope/v2"
	sealedArchiveIntentCoreSchemaV8 = "chengwang.subscription-archive-migration-intent-core/v2"
	sealedArchiveIntentSchemaV8     = "chengwang.subscription-archive-migration-intent-envelope/v2"
	sealedArchiveReceiptSchemaV8    = "chengwang.subscription-archive-shadow-receipt-envelope/v2"

	sealedArchiveCandidateKindV1 = "candidate/v1"
	sealedArchiveGenesisKindV1   = "genesis/v1"
	sealedArchiveHistoryKindV1   = "history-segment/v1"
	sealedArchiveIntentKindV1    = "migration-intent/v1"
	sealedArchiveReceiptKindV1   = "shadow-receipt/v1"

	sealedArchivePolicyV8   = "chengwang.p207a-sealed-archive/v8-behavior-b-peak-temp-codec-set-full-golden"
	sealedArchiveCodecV8    = "chengwang.subscription-store/v1-go-json@3444578ed42454fb460d6c3b45242c6717786782"
	sealedArchiveCommitV8   = "3444578ed42454fb460d6c3b45242c6717786782"
	sealedArchiveTreeV8     = "fb5bcebd073aeacb301f7025adcc56dbe79ce8ee"
	sealedArchiveCodecSetV8 = "20cdf1e7cb741ad5cf0a3f1502a4e144a1d058c388cb2e193b2ea64b1e2b91d7"

	sealedArchiveMaxBytes        = uint64(64 << 20)
	sealedArchiveObjectMaxBytes  = uint64(16 << 20)
	sealedArchiveCandidateMax    = uint32(64)
	sealedArchiveFinalEntryMax   = uint32(69)
	sealedArchivePeakEntryMax    = uint32(70)
	sealedArchiveMetaMaxBytes    = 4096
	sealedArchiveIntentMaxBytes  = 262144
	sealedArchiveReceiptMaxBytes = 262144
	sealedArchiveTokenMax        = 1 << 20
	sealedArchiveDepthMax        = 32
	sealedArchiveStringMax       = 1398104
)

const (
	CodeArchiveInvalid              Code = "subscription_archive_invalid"
	CodeArchiveLimit                Code = "subscription_archive_limit"
	CodeArchiveKindUnsupported      Code = "subscription_archive_kind_unsupported"
	CodeArchiveNameUnsafe           Code = "subscription_archive_name_unsafe"
	CodeArchiveAuthenticationFailed Code = "subscription_archive_authentication_failed"
	CodeArchiveConflict             Code = "subscription_archive_conflict"
	CodeArchiveReconstructionFailed Code = "subscription_archive_reconstruction_failed"
	CodeArchivePlatformUnsupported  Code = "subscription_archive_platform_unsupported"
)

var sealedArchiveHex32Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var sealedArchiveHexU64Pattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
var sealedArchiveCommandPattern = regexp.MustCompile(`^cmd_[0-9a-f]{32}$`)
var sealedArchiveContentNamePattern = regexp.MustCompile(`^(candidate-v1|genesis-v1|history-segment-v1)-([0-9a-f]{64})\.json$`)

type sealedArchiveNameClassV8 uint8

const (
	sealedArchiveNameInvalidV8 sealedArchiveNameClassV8 = iota
	sealedArchiveNameMetaV8
	sealedArchiveNameLockV8
	sealedArchiveNameIntentV8
	sealedArchiveNameReceiptV8
	sealedArchiveNameContentV8
)

type sealedArchiveParsedNameV8 struct {
	Class     sealedArchiveNameClassV8
	Kind      string
	Reference string
	Temporary bool
}

type archiveBudgetV1 struct {
	ArchiveMaxBytes uint64 `json:"archiveMaxBytes"`
	ObjectMaxBytes  uint64 `json:"objectMaxBytes"`
	CandidateMax    uint32 `json:"candidateMax"`
	FinalEntryMax   uint32 `json:"finalEntryMax"`
	PeakEntryMax    uint32 `json:"peakEntryMax"`
}

type archiveByteIdentityV1 struct {
	Length uint64 `json:"length"`
	SHA256 string `json:"sha256"`
}

type archivePosixIdentityV1 struct {
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	Mode      uint32 `json:"mode"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	LinkCount uint64 `json:"linkCount"`
}

type archiveRootIdentityV1 struct {
	Identity        archivePosixIdentityV1 `json:"identity"`
	FilesystemMagic uint64                 `json:"filesystemMagic"`
}

type archiveDirectoryAnchorV1 struct {
	Identity       archivePosixIdentityV1 `json:"identity"`
	EntryCount     uint32                 `json:"entryCount"`
	EntrySetSHA256 string                 `json:"entrySetSha256"`
}

type archiveFileAnchorV1 struct {
	Identity archivePosixIdentityV1 `json:"identity"`
	Length   uint64                 `json:"length"`
	SHA256   string                 `json:"sha256"`
}

type archiveEvidenceAnchorV1 struct {
	Root            archiveDirectoryAnchorV1 `json:"root"`
	Lock            archiveFileAnchorV1      `json:"lock"`
	Log             archiveFileAnchorV1      `json:"log"`
	Checkpoint      archiveFileAnchorV1      `json:"checkpoint"`
	EventCount      uint64                   `json:"eventCount"`
	EventHead       string                   `json:"eventHead"`
	CheckpointCount uint64                   `json:"checkpointCount"`
	CheckpointHead  string                   `json:"checkpointHead"`
}

type archiveMainCheckpointV1 struct {
	Present   bool   `json:"present"`
	CommandID string `json:"commandId"`
	Epoch     string `json:"epoch"`
}

type archiveMainAnchorV1 struct {
	Root                    archiveDirectoryAnchorV1 `json:"root"`
	Lock                    archiveFileAnchorV1      `json:"lock"`
	Snapshot                archiveFileAnchorV1      `json:"snapshot"`
	StoreSchema             string                   `json:"storeSchema"`
	IdentityKeyID           string                   `json:"identityKeyId"`
	AuditCount              uint32                   `json:"auditCount"`
	AuditHead               string                   `json:"auditHead"`
	CommandCount            uint32                   `json:"commandCount"`
	ApprovalCount           uint32                   `json:"approvalCount"`
	LatestRefreshCheckpoint archiveMainCheckpointV1  `json:"latestRefreshCheckpoint"`
}

type archiveRefreshAbsenceV1 struct {
	Parent      archiveRootIdentityV1 `json:"parent"`
	ChildNameID string                `json:"childNameId"`
}

type archiveRefreshPresentV1 struct {
	Root                 archiveDirectoryAnchorV1 `json:"root"`
	Lock                 archiveFileAnchorV1      `json:"lock"`
	Snapshot             archiveFileAnchorV1      `json:"snapshot"`
	StoreSchema          string                   `json:"storeSchema"`
	IdentityKeyID        string                   `json:"identityKeyId"`
	Epoch                string                   `json:"epoch"`
	CheckpointReady      bool                     `json:"checkpointReady"`
	CheckpointID         string                   `json:"checkpointId"`
	PreviousCheckpointID string                   `json:"previousCheckpointId"`
	LastSequence         uint64                   `json:"lastSequence"`
	ClockState           string                   `json:"clockState"`
	ClockReasonSHA256    string                   `json:"clockReasonSha256"`
	RunningCount         uint32                   `json:"runningCount"`
	UnknownCount         uint32                   `json:"unknownCount"`
	ReservationCount     uint32                   `json:"reservationCount"`
	ReservedCommands     uint32                   `json:"reservedCommands"`
	ReservedCandidates   uint32                   `json:"reservedCandidates"`
	ReservedDomainAudit  uint32                   `json:"reservedDomainAudit"`
	ReservedBytes        uint64                   `json:"reservedBytes"`
	PendingRotation      bool                     `json:"pendingRotation"`
}

type archiveRefreshSourceV1 struct {
	State   string                   `json:"state"`
	Absence *archiveRefreshAbsenceV1 `json:"absence,omitempty"`
	Present *archiveRefreshPresentV1 `json:"present,omitempty"`
}

type archiveFrozenSourcesV1 struct {
	Evidence archiveEvidenceAnchorV1 `json:"evidence"`
	Main     archiveMainAnchorV1     `json:"main"`
	Refresh  archiveRefreshSourceV1  `json:"refresh"`
}

type archiveSourceRevisionV1 struct {
	RepositoryCommit string `json:"repositoryCommit"`
	RepositoryTree   string `json:"repositoryTree"`
	CodecSetSHA256   string `json:"codecSetSha256"`
}

type archiveMetaV2 struct {
	Schema          string `json:"schema"`
	FormatVersion   uint32 `json:"formatVersion"`
	ArchiveKey      []byte `json:"archiveKey"`
	KeyID           string `json:"keyId"`
	ArchiveMaxBytes uint64 `json:"archiveMaxBytes"`
	ObjectMaxBytes  uint64 `json:"objectMaxBytes"`
	CandidateMax    uint32 `json:"candidateMax"`
	FinalEntryMax   uint32 `json:"finalEntryMax"`
	PeakEntryMax    uint32 `json:"peakEntryMax"`
}

type archiveIntentCoreV1 struct {
	Schema         string                  `json:"schema"`
	ObservedAt     string                  `json:"observedAt"`
	Nonce          []byte                  `json:"nonce"`
	KeyID          string                  `json:"keyId"`
	ArchiveRoot    archiveRootIdentityV1   `json:"archiveRoot"`
	FrozenSources  archiveFrozenSourcesV1  `json:"frozenSources"`
	SourceRevision archiveSourceRevisionV1 `json:"sourceRevision"`
	CodecID        string                  `json:"codecId"`
	PolicyID       string                  `json:"policyId"`
	Budget         archiveBudgetV1         `json:"budget"`
	OriginalV1     archiveByteIdentityV1   `json:"originalV1"`
	CandidateCount uint32                  `json:"candidateCount"`
}

type archiveIntentPayloadV1 struct {
	Core         archiveIntentCoreV1 `json:"core"`
	MigrationID  string              `json:"migrationId"`
	ArchiveEpoch string              `json:"archiveEpoch"`
}

type archiveIntentEnvelopeV1 struct {
	Schema    string                 `json:"schema"`
	Kind      string                 `json:"kind"`
	Reference string                 `json:"reference"`
	Payload   archiveIntentPayloadV1 `json:"payload"`
	Seal      string                 `json:"seal"`
}

type archiveCandidatePayloadV1 struct {
	MigrationID  string         `json:"migrationId"`
	ArchiveEpoch string         `json:"archiveEpoch"`
	Ordinal      uint32         `json:"ordinal"`
	Candidate    storeCandidate `json:"candidate"`
}

type archiveCandidateEnvelopeV1 struct {
	Schema    string                    `json:"schema"`
	Kind      string                    `json:"kind"`
	Reference string                    `json:"reference"`
	Payload   archiveCandidatePayloadV1 `json:"payload"`
	Seal      string                    `json:"seal"`
}

type archiveCandidateLinkV1 struct {
	Ordinal   uint32 `json:"ordinal"`
	Reference string `json:"reference"`
}

type archiveGenesisPayloadV1 struct {
	MigrationID     string                   `json:"migrationId"`
	ArchiveEpoch    string                   `json:"archiveEpoch"`
	KeyID           string                   `json:"keyId"`
	IntentReference string                   `json:"intentReference"`
	StoreSchema     string                   `json:"storeSchema"`
	IdentityKey     []byte                   `json:"identityKey"`
	Sources         []SourceView             `json:"sources"`
	Candidates      []archiveCandidateLinkV1 `json:"candidates"`
	Requests        []storeRequest           `json:"requests"`
	Audit           []storeAudit             `json:"audit"`
	Commands        []controlCommandDisk     `json:"commands"`
	Approvals       []ControlApproval        `json:"approvals"`
	OriginalV1      archiveByteIdentityV1    `json:"originalV1"`
	FrozenSources   archiveFrozenSourcesV1   `json:"frozenSources"`
	SourceRevision  archiveSourceRevisionV1  `json:"sourceRevision"`
	CodecID         string                   `json:"codecId"`
	PolicyID        string                   `json:"policyId"`
	Budget          archiveBudgetV1          `json:"budget"`
}

type archiveGenesisEnvelopeV1 struct {
	Schema    string                  `json:"schema"`
	Kind      string                  `json:"kind"`
	Reference string                  `json:"reference"`
	Payload   archiveGenesisPayloadV1 `json:"payload"`
	Seal      string                  `json:"seal"`
}

type archiveReceiptCountsV1 struct {
	CandidateObjects uint32 `json:"candidateObjects"`
	ContentObjects   uint32 `json:"contentObjects"`
	FixedDocuments   uint32 `json:"fixedDocuments"`
	LockEntries      uint32 `json:"lockEntries"`
	FinalEntries     uint32 `json:"finalEntries"`
	PeakEntries      uint32 `json:"peakEntries"`
}

type archiveReceiptBytesV2 struct {
	PreReceiptFinalBytes uint64 `json:"preReceiptFinalBytes"`
	ReceiptBytesHex      string `json:"receiptBytesHex"`
	FinalBytesHex        string `json:"finalBytesHex"`
	MaxTempBytesHex      string `json:"maxTempBytesHex"`
	PeakBytesHex         string `json:"peakBytesHex"`
}

type archiveReconstructionV1 struct {
	Length uint64 `json:"length"`
	SHA256 string `json:"sha256"`
	Result string `json:"result"`
}

type archiveBlockerCountV1 struct {
	Class string `json:"class"`
	Count uint32 `json:"count"`
}

type archiveLimitationsV1 struct {
	HMACScope                     string `json:"hmacScope"`
	WholeAnchorRollbackProtection string `json:"wholeAnchorRollbackProtection"`
	OldBinaryConstraint           string `json:"oldBinaryConstraint"`
	BackupProof                   bool   `json:"backupProof"`
	SelectorAuthority             bool   `json:"selectorAuthority"`
	CapacityReleased              bool   `json:"capacityReleased"`
}

type archiveReceiptPayloadV2 struct {
	MigrationID         string                  `json:"migrationId"`
	ArchiveEpoch        string                  `json:"archiveEpoch"`
	KeyID               string                  `json:"keyId"`
	IntentReference     string                  `json:"intentReference"`
	GenesisReference    string                  `json:"genesisReference"`
	FrozenSourcesSHA256 string                  `json:"frozenSourcesSha256"`
	CandidateReferences []string                `json:"candidateReferences"`
	Counts              archiveReceiptCountsV1  `json:"counts"`
	Bytes               archiveReceiptBytesV2   `json:"bytes"`
	Budget              archiveBudgetV1         `json:"budget"`
	Reconstruction      archiveReconstructionV1 `json:"reconstruction"`
	Blockers            []archiveBlockerCountV1 `json:"blockers"`
	Limitations         archiveLimitationsV1    `json:"limitations"`
	ShadowOnly          bool                    `json:"shadowOnly"`
	Activatable         bool                    `json:"activatable"`
}

type archiveReceiptEnvelopeV1 struct {
	Schema    string                  `json:"schema"`
	Kind      string                  `json:"kind"`
	Reference string                  `json:"reference"`
	Payload   archiveReceiptPayloadV2 `json:"payload"`
	Seal      string                  `json:"seal"`
}

type sealedArchiveCanonicalValue interface {
	archiveFrozenSourcesV1 | archiveMetaV2 | archiveIntentCoreV1 | archiveIntentPayloadV1 |
		archiveIntentEnvelopeV1 | archiveCandidatePayloadV1 | archiveCandidateEnvelopeV1 |
		archiveGenesisPayloadV1 | archiveGenesisEnvelopeV1 | archiveReceiptPayloadV2 |
		archiveReceiptEnvelopeV1 | archiveHistoryPayloadV1 | archiveHistoryEnvelopeV1
}

type sealedArchivePersistedValue interface {
	archiveMetaV2 | archiveIntentEnvelopeV1 | archiveCandidateEnvelopeV1 |
		archiveGenesisEnvelopeV1 | archiveReceiptEnvelopeV1 | archiveHistoryEnvelopeV1
}

type sealedArchiveDecodedValue interface {
	archiveFrozenSourcesV1 | archiveMetaV2 | archiveIntentCoreV1 | archiveIntentPayloadV1 |
		archiveIntentEnvelopeV1 | archiveCandidatePayloadV1 | archiveCandidateEnvelopeV1 |
		archiveGenesisPayloadV1 | archiveReceiptPayloadV2 |
		archiveGenesisEnvelopeV1 | archiveReceiptEnvelopeV1 | archiveHistoryPayloadV1 | archiveHistoryEnvelopeV1
}

type sealedArchiveEnvelopePayload interface {
	archiveIntentPayloadV1 | archiveCandidatePayloadV1 | archiveGenesisPayloadV1 |
		archiveReceiptPayloadV2 | archiveHistoryPayloadV1
}

func sealedArchiveSourceRevisionV8() archiveSourceRevisionV1 {
	return archiveSourceRevisionV1{RepositoryCommit: sealedArchiveCommitV8, RepositoryTree: sealedArchiveTreeV8, CodecSetSHA256: sealedArchiveCodecSetV8}
}

func sealedArchiveDefaultBudgetV8(max uint64) archiveBudgetV1 {
	return archiveBudgetV1{ArchiveMaxBytes: max, ObjectMaxBytes: sealedArchiveObjectMaxBytes, CandidateMax: sealedArchiveCandidateMax, FinalEntryMax: sealedArchiveFinalEntryMax, PeakEntryMax: sealedArchivePeakEntryMax}
}

func sealedArchiveFail(code Code) error { return fail(code) }

func sealedArchiveValidHex32(value string) bool { return sealedArchiveHex32Pattern.MatchString(value) }

func sealedArchiveFrame(domain string, fields ...[]byte) ([]byte, error) {
	limits := map[string]int{
		"chengwang/archive/key-id/v1":           1,
		"chengwang/archive/subkey/v1":           1,
		"chengwang/archive/reference/v1":        3,
		"chengwang/archive/seal/v1":             4,
		"chengwang/archive/epoch/v1":            1,
		"chengwang/archive/source-key-id/v1":    2,
		"chengwang/archive/source-entry-set/v1": 1,
		"chengwang/archive/absence-child/v1":    1,
	}
	count, ok := limits[domain]
	if !ok || len(fields) != count || len(fields)+1 > 5 {
		return nil, sealedArchiveFail(CodeArchiveInvalid)
	}
	switch domain {
	case "chengwang/archive/key-id/v1":
		if len(fields[0]) != sha256.Size {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/subkey/v1":
		if string(fields[0]) != "reference" && string(fields[0]) != "seal" {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/reference/v1":
		if len(fields[0]) > 128 || len(fields[1]) > 32 {
			return nil, sealedArchiveFail(CodeArchiveLimit)
		}
		if len(fields[0]) == 0 || len(fields[1]) == 0 || !sealedArchiveASCII(fields[0]) || !sealedArchiveASCII(fields[1]) {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/seal/v1":
		if len(fields[0]) > 128 || len(fields[1]) > 32 {
			return nil, sealedArchiveFail(CodeArchiveLimit)
		}
		if len(fields[0]) == 0 || len(fields[1]) == 0 || !sealedArchiveASCII(fields[0]) || !sealedArchiveASCII(fields[1]) || !sealedArchiveValidHex32(string(fields[2])) {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/epoch/v1":
		if !sealedArchiveValidHex32(string(fields[0])) {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/source-key-id/v1":
		if (string(fields[0]) != "main-v1" && string(fields[0]) != "refresh-v3") || len(fields[1]) != sha256.Size {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/source-entry-set/v1":
		if len(fields[0]) > 4096 {
			return nil, sealedArchiveFail(CodeArchiveLimit)
		}
		if len(fields[0]) < 2 {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	case "chengwang/archive/absence-child/v1":
		if !sealedArchiveValidChildName(string(fields[0])) {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
	}
	values := append([][]byte{[]byte(domain)}, fields...)
	total := uint64(0)
	for _, value := range values {
		if len(value) > int(sealedArchiveObjectMaxBytes) {
			return nil, sealedArchiveFail(CodeArchiveLimit)
		}
		total += 4 + uint64(len(value))
		if total > 16777728 {
			return nil, sealedArchiveFail(CodeArchiveLimit)
		}
	}
	result := make([]byte, 0, int(total))
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		result = append(result, length[:]...)
		result = append(result, value...)
	}
	return result, nil
}

func sealedArchiveKeys(key []byte) (string, []byte, []byte, error) {
	if len(key) != sha256.Size {
		return "", nil, nil, sealedArchiveFail(CodeArchiveInvalid)
	}
	keyFrame, err := sealedArchiveFrame("chengwang/archive/key-id/v1", key)
	if err != nil {
		return "", nil, nil, err
	}
	keyHash := sha256.Sum256(keyFrame)
	subkey := func(label string) ([]byte, error) {
		framed, frameErr := sealedArchiveFrame("chengwang/archive/subkey/v1", []byte(label))
		if frameErr != nil {
			return nil, frameErr
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(framed)
		return mac.Sum(nil), nil
	}
	kref, err := subkey("reference")
	if err != nil {
		return "", nil, nil, err
	}
	kseal, err := subkey("seal")
	if err != nil {
		return "", nil, nil, err
	}
	return hex.EncodeToString(keyHash[:]), kref, kseal, nil
}

func sealedArchiveReference(kref []byte, schema, kind string, payload []byte) (string, error) {
	if len(kref) != sha256.Size {
		return "", sealedArchiveFail(CodeArchiveInvalid)
	}
	if !sealedArchiveSchemaKind(schema, kind) {
		return "", sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if len(payload) > int(sealedArchiveObjectMaxBytes) {
		return "", sealedArchiveFail(CodeArchiveLimit)
	}
	framed, err := sealedArchiveFrame("chengwang/archive/reference/v1", []byte(schema), []byte(kind), payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, kref)
	_, _ = mac.Write(framed)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func sealedArchiveSeal(kseal []byte, schema, kind, reference string, payload []byte) (string, error) {
	if len(kseal) != sha256.Size {
		return "", sealedArchiveFail(CodeArchiveInvalid)
	}
	if !sealedArchiveSchemaKind(schema, kind) {
		return "", sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if len(payload) > int(sealedArchiveObjectMaxBytes) {
		return "", sealedArchiveFail(CodeArchiveLimit)
	}
	if !sealedArchiveValidHex32(reference) {
		return "", sealedArchiveFail(CodeArchiveInvalid)
	}
	framed, err := sealedArchiveFrame("chengwang/archive/seal/v1", []byte(schema), []byte(kind), []byte(reference), payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, kseal)
	_, _ = mac.Write(framed)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func sealedArchiveEpoch(kref []byte, migrationID string) (string, error) {
	if len(kref) != sha256.Size || !sealedArchiveValidHex32(migrationID) {
		return "", sealedArchiveFail(CodeArchiveInvalid)
	}
	framed, err := sealedArchiveFrame("chengwang/archive/epoch/v1", []byte(migrationID))
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, kref)
	_, _ = mac.Write(framed)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func sealedArchiveSourceKeyID(role string, key []byte) (string, error) {
	if (role != "main-v1" && role != "refresh-v3") || len(key) != sha256.Size {
		return "", sealedArchiveFail(CodeArchiveInvalid)
	}
	framed, err := sealedArchiveFrame("chengwang/archive/source-key-id/v1", []byte(role), key)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(framed)
	return hex.EncodeToString(digest[:]), nil
}
func sealedArchiveSchemaKind(schema, kind string) bool {
	switch kind {
	case sealedArchiveCandidateKindV1:
		return schema == sealedArchiveCandidateSchemaV8
	case sealedArchiveGenesisKindV1:
		return schema == sealedArchiveGenesisSchemaV8
	case sealedArchiveHistoryKindV1:
		return schema == sealedArchiveHistorySchemaV8
	case sealedArchiveIntentKindV1:
		return schema == sealedArchiveIntentCoreSchemaV8 || schema == sealedArchiveIntentSchemaV8
	case sealedArchiveReceiptKindV1:
		return schema == sealedArchiveReceiptSchemaV8
	default:
		return false
	}
}

func sealedArchiveCanonical[T sealedArchiveCanonicalValue](value T) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, sealedArchiveFail(CodeArchiveInvalid)
	}
	return raw, nil
}

func sealedArchivePersisted[T sealedArchivePersistedValue](value T, limit int) ([]byte, error) {
	raw, err := sealedArchiveCanonical(value)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > limit {
		return nil, sealedArchiveFail(CodeArchiveLimit)
	}
	return raw, nil
}

func sealedArchiveScanJSON(raw []byte, persisted bool, limit int) ([]byte, error) {
	if len(raw) == 0 || !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, sealedArchiveFail(CodeArchiveInvalid)
	}
	if len(raw) > limit {
		return nil, sealedArchiveFail(CodeArchiveLimit)
	}
	value := raw
	if persisted {
		if raw[len(raw)-1] != '\n' || len(raw) > 1 && raw[len(raw)-2] == '\n' {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
		value = raw[:len(raw)-1]
	} else if bytes.ContainsRune(raw, '\n') {
		return nil, sealedArchiveFail(CodeArchiveInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	tokens := 0
	nextToken := func() (json.Token, error) {
		tokens++
		if tokens > sealedArchiveTokenMax {
			return nil, sealedArchiveFail(CodeArchiveLimit)
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, sealedArchiveFail(CodeArchiveInvalid)
		}
		return token, nil
	}
	var visit func(int) error
	visit = func(depth int) error {
		if depth > sealedArchiveDepthMax {
			return sealedArchiveFail(CodeArchiveLimit)
		}
		token, err := nextToken()
		if err != nil {
			return err
		}
		if token == nil {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		if text, ok := token.(string); ok && len([]byte(text)) > sealedArchiveStringMax {
			return sealedArchiveFail(CodeArchiveLimit)
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				key, keyErr := nextToken()
				if keyErr != nil {
					return keyErr
				}
				name, nameOK := key.(string)
				if !nameOK || seen[name] {
					return sealedArchiveFail(CodeArchiveInvalid)
				}
				if len([]byte(name)) > sealedArchiveStringMax {
					return sealedArchiveFail(CodeArchiveLimit)
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			end, endErr := nextToken()
			if endErr != nil {
				return endErr
			}
			if end != json.Delim('}') {
				return sealedArchiveFail(CodeArchiveInvalid)
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			end, endErr := nextToken()
			if endErr != nil {
				return endErr
			}
			if end != json.Delim(']') {
				return sealedArchiveFail(CodeArchiveInvalid)
			}
		default:
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		return nil
	}
	if err := visit(0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, sealedArchiveFail(CodeArchiveInvalid)
	}
	return value, nil
}

func sealedArchiveDecode[T sealedArchiveDecodedValue](raw []byte, persisted bool, limit int, dst *T) error {
	value, err := sealedArchiveScanJSON(raw, persisted, limit)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(value, canonical) {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	return nil
}

func sealedArchiveValidateBudget(value archiveBudgetV1) error {
	if value.ArchiveMaxBytes == 0 || value.ArchiveMaxBytes > sealedArchiveMaxBytes || value.ObjectMaxBytes != sealedArchiveObjectMaxBytes || value.CandidateMax != sealedArchiveCandidateMax || value.FinalEntryMax != sealedArchiveFinalEntryMax || value.PeakEntryMax != sealedArchivePeakEntryMax {
		return sealedArchiveFail(CodeArchiveLimit)
	}
	return nil
}

func sealedArchiveValidateObservedAt(value string) error {
	if len(value) < 20 || len(value) > 30 || !strings.HasSuffix(value, "Z") {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	return nil
}

func sealedArchiveValidatePosix(value archivePosixIdentityV1) error {
	// Exact owner, mode, type, link and native-filesystem safety are A1 source
	// acquisition rules. A0 preserves these unsigned stat values verbatim.
	return nil
}

func sealedArchiveASCII(value []byte) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}

func sealedArchiveValidateDirectory(value archiveDirectoryAnchorV1) error {
	if err := sealedArchiveValidatePosix(value.Identity); err != nil {
		return err
	}
	if value.EntryCount < 2 || value.EntryCount > 4 || !sealedArchiveValidHex32(value.EntrySetSHA256) {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	return nil
}

func sealedArchiveValidateFile(value archiveFileAnchorV1) error {
	if err := sealedArchiveValidatePosix(value.Identity); err != nil {
		return err
	}
	if !sealedArchiveValidHex32(value.SHA256) {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	return nil
}

func sealedArchiveValidateFrozen(value archiveFrozenSourcesV1) error {
	if err := sealedArchiveValidateDirectory(value.Evidence.Root); err != nil {
		return err
	}
	for _, file := range []archiveFileAnchorV1{value.Evidence.Lock, value.Evidence.Log, value.Evidence.Checkpoint} {
		if err := sealedArchiveValidateFile(file); err != nil {
			return err
		}
	}
	if !sealedArchiveValidHex32(value.Evidence.EventHead) || !sealedArchiveValidHex32(value.Evidence.CheckpointHead) || value.Evidence.EventCount != value.Evidence.CheckpointCount || value.Evidence.EventHead != value.Evidence.CheckpointHead {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	if value.Evidence.EventCount == 0 && value.Evidence.EventHead != strings.Repeat("0", 64) {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	if err := sealedArchiveValidateDirectory(value.Main.Root); err != nil {
		return err
	}
	if err := sealedArchiveValidateFile(value.Main.Lock); err != nil {
		return err
	}
	if err := sealedArchiveValidateFile(value.Main.Snapshot); err != nil {
		return err
	}
	if value.Main.AuditCount > MaxAuditEntries || value.Main.CommandCount > MaxControlCommands || value.Main.ApprovalCount > MaxControlCommands {
		return sealedArchiveFail(CodeArchiveLimit)
	}
	if value.Main.StoreSchema != storeSchema || !sealedArchiveValidHex32(value.Main.IdentityKeyID) || !sealedArchiveValidHex32(value.Main.AuditHead) {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	checkpoint := value.Main.LatestRefreshCheckpoint
	if checkpoint.Present != (checkpoint.CommandID != "") || checkpoint.Present != (checkpoint.Epoch != "") || checkpoint.Present && (!sealedArchiveCommandPattern.MatchString(checkpoint.CommandID) || !sealedArchiveValidHex32(checkpoint.Epoch)) {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	switch value.Refresh.State {
	case "absent":
		if value.Refresh.Absence == nil || value.Refresh.Present != nil || !sealedArchiveValidHex32(value.Refresh.Absence.ChildNameID) {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		if err := sealedArchiveValidatePosix(value.Refresh.Absence.Parent.Identity); err != nil {
			return err
		}
	case "present":
		if value.Refresh.Present == nil || value.Refresh.Absence != nil {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		present := value.Refresh.Present
		if err := sealedArchiveValidateDirectory(present.Root); err != nil {
			return err
		}
		if err := sealedArchiveValidateFile(present.Lock); err != nil {
			return err
		}
		if err := sealedArchiveValidateFile(present.Snapshot); err != nil {
			return err
		}
		if present.RunningCount > 1 || present.UnknownCount > MaxSources || present.ReservationCount > 1 || present.ReservedCommands > 1 || present.ReservedCandidates > 1 || present.ReservedDomainAudit > 1 || present.ReservedBytes > sealedArchiveObjectMaxBytes {
			return sealedArchiveFail(CodeArchiveLimit)
		}
		if present.StoreSchema != refreshSchema || !sealedArchiveValidHex32(present.IdentityKeyID) || !sealedArchiveValidHex32(present.Epoch) || !sealedArchiveValidHex32(present.ClockReasonSHA256) {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		if present.ClockState != string(RefreshClockNormal) && present.ClockState != string(RefreshClockFrozen) {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		if present.ClockState == string(RefreshClockNormal) && present.ClockReasonSHA256 != strings.Repeat("0", 64) {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		for _, id := range []string{present.CheckpointID, present.PreviousCheckpointID} {
			if id != "" && !sealedArchiveCommandPattern.MatchString(id) {
				return sealedArchiveFail(CodeArchiveInvalid)
			}
		}
		if present.CheckpointReady != (present.CheckpointID != "") || present.CheckpointReady && present.PreviousCheckpointID != "" {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
		if present.ClockState == string(RefreshClockFrozen) && present.ClockReasonSHA256 == strings.Repeat("0", 64) {
			return sealedArchiveFail(CodeArchiveInvalid)
		}
	default:
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	return nil
}

func sealedArchiveValidateSafeName(name string) error {
	_, err := sealedArchiveParseNameV8(name)
	return err
}

func sealedArchiveParseNameV8(name string) (sealedArchiveParsedNameV8, error) {
	var result sealedArchiveParsedNameV8
	if name == "" || len([]byte(name)) > 255 || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00") || strings.ContainsFunc(name, unicode.IsControl) {
		return result, sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	base := name
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".tmp") {
		if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".tmp") {
			return result, sealedArchiveFail(CodeArchiveNameUnsafe)
		}
		base = strings.TrimSuffix(strings.TrimPrefix(name, "."), ".tmp")
		if base == "" || strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".tmp") {
			return result, sealedArchiveFail(CodeArchiveNameUnsafe)
		}
		result.Temporary = true
	}
	switch base {
	case "archive.meta":
		result.Class = sealedArchiveNameMetaV8
	case "archive.lock":
		if result.Temporary {
			return sealedArchiveParsedNameV8{}, sealedArchiveFail(CodeArchiveNameUnsafe)
		}
		result.Class = sealedArchiveNameLockV8
	case "migration.intent.json":
		result.Class = sealedArchiveNameIntentV8
		result.Kind = sealedArchiveIntentKindV1
	case "shadow.receipt.json":
		result.Class = sealedArchiveNameReceiptV8
		result.Kind = sealedArchiveReceiptKindV1
	default:
		matches := sealedArchiveContentNamePattern.FindStringSubmatch(base)
		if len(matches) != 3 {
			return sealedArchiveParsedNameV8{}, sealedArchiveFail(CodeArchiveNameUnsafe)
		}
		result.Class = sealedArchiveNameContentV8
		result.Reference = matches[2]
		switch matches[1] {
		case "candidate-v1":
			result.Kind = sealedArchiveCandidateKindV1
		case "genesis-v1":
			result.Kind = sealedArchiveGenesisKindV1
		case "history-segment-v1":
			result.Kind = sealedArchiveHistoryKindV1
		default:
			return sealedArchiveParsedNameV8{}, sealedArchiveFail(CodeArchiveNameUnsafe)
		}
	}
	return result, nil
}

func sealedArchiveContentName(kind, reference string) (string, error) {
	if !sealedArchiveValidHex32(reference) {
		return "", sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	tag := ""
	switch kind {
	case sealedArchiveCandidateKindV1:
		tag = "candidate-v1"
	case sealedArchiveGenesisKindV1:
		tag = "genesis-v1"
	case sealedArchiveHistoryKindV1:
		tag = "history-segment-v1"
	default:
		return "", sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	name := tag + "-" + reference + ".json"
	parsed, err := sealedArchiveParseNameV8(name)
	if err != nil || parsed.Class != sealedArchiveNameContentV8 || parsed.Kind != kind || parsed.Reference != reference || parsed.Temporary {
		return "", sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	return name, nil
}

func sealedArchiveHexU64(value uint64) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return hex.EncodeToString(raw[:])
}

func sealedArchiveParseHexU64(value string) (uint64, error) {
	if !sealedArchiveHexU64Pattern.MatchString(value) {
		return 0, sealedArchiveFail(CodeArchiveInvalid)
	}
	raw, _ := hex.DecodeString(value)
	return binary.BigEndian.Uint64(raw), nil
}

func sealedArchiveCheckedAdd(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		if value > math.MaxUint64-result {
			return 0, sealedArchiveFail(CodeArchiveLimit)
		}
		result += value
	}
	return result, nil
}

func sealedArchiveValidChildName(value string) bool {
	if value == "" || value == "." || value == ".." || len([]byte(value)) > 255 || !utf8.ValidString(value) || strings.ContainsAny(value, "/\\\x00") {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func sealedArchiveAbsenceChildID(value string) (string, error) {
	if !sealedArchiveValidChildName(value) {
		return "", sealedArchiveFail(CodeArchiveInvalid)
	}
	framed, err := sealedArchiveFrame("chengwang/archive/absence-child/v1", []byte(value))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(framed)
	return hex.EncodeToString(digest[:]), nil
}
