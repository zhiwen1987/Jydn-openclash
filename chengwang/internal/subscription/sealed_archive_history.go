package subscription

import (
	"crypto/sha256"
	"math"
)

type archiveHistoryEntryV1 struct {
	Request storeRequest `json:"request"`
	Audit   storeAudit   `json:"audit"`
}

type archiveHistoryPayloadV1 struct {
	MigrationID       string                  `json:"migrationId"`
	ArchiveEpoch      string                  `json:"archiveEpoch"`
	SegmentOrdinal    uint64                  `json:"segmentOrdinal"`
	PreviousKind      string                  `json:"previousKind"`
	PreviousReference string                  `json:"previousReference"`
	FirstSequence     uint64                  `json:"firstSequence"`
	LastSequence      uint64                  `json:"lastSequence"`
	BaseHash          string                  `json:"baseHash"`
	ThroughHash       string                  `json:"throughHash"`
	Entries           []archiveHistoryEntryV1 `json:"entries"`
}

type archiveHistoryEnvelopeV1 struct {
	Schema    string                  `json:"schema"`
	Kind      string                  `json:"kind"`
	Reference string                  `json:"reference"`
	Payload   archiveHistoryPayloadV1 `json:"payload"`
	Seal      string                  `json:"seal"`
}

type sealedArchiveHistoryInputV8 struct {
	ArchiveKey        []byte
	MigrationID       string
	ArchiveEpoch      string
	SegmentOrdinal    uint64
	PreviousKind      string
	PreviousReference string
	FirstSequence     uint64
	BaseHash          string
	Entries           []archiveHistoryEntryV1
}

type sealedArchiveHistoryFixtureV8 struct {
	File      sealedArchiveV8File
	Reference string
	Seal      string
}

func buildSealedArchiveHistoryFixtureV8(input sealedArchiveHistoryInputV8) (sealedArchiveHistoryFixtureV8, error) {
	var empty sealedArchiveHistoryFixtureV8
	if len(input.ArchiveKey) != sha256.Size || !sealedArchiveValidHex32(input.MigrationID) || !sealedArchiveValidHex32(input.ArchiveEpoch) || input.SegmentOrdinal == 0 || !sealedArchiveValidHex32(input.PreviousReference) || !sealedArchiveValidHex32(input.BaseHash) || input.FirstSequence == 0 || input.Entries == nil || len(input.Entries) == 0 {
		return empty, sealedArchiveFail(CodeArchiveInvalid)
	}
	if len(input.Entries) > MaxAuditEntries || uint64(len(input.Entries)-1) > math.MaxUint64-input.FirstSequence {
		return empty, sealedArchiveFail(CodeArchiveLimit)
	}
	expectedPreviousKind := sealedArchiveHistoryKindV1
	if input.SegmentOrdinal == 1 {
		expectedPreviousKind = sealedArchiveGenesisKindV1
	}
	if input.PreviousKind != expectedPreviousKind {
		return empty, sealedArchiveFail(CodeArchiveConflict)
	}
	last := input.FirstSequence + uint64(len(input.Entries)-1)
	previous := input.BaseHash
	for i, entry := range input.Entries {
		audit := entry.Audit
		expectedSequence := input.FirstSequence + uint64(i)
		if audit.Sequence != expectedSequence || audit.PreviousHash != previous || audit.Hash != storeAuditHash(audit) || entry.Request.Key != audit.Key || entry.Request.Fingerprint != audit.RequestDigest || entry.Request.Action != audit.Action || entry.Request.SourceID != audit.SourceID || entry.Request.CandidateID != audit.CandidateID {
			return empty, sealedArchiveFail(CodeArchiveReconstructionFailed)
		}
		previous = audit.Hash
	}
	payload := archiveHistoryPayloadV1{
		MigrationID: input.MigrationID, ArchiveEpoch: input.ArchiveEpoch,
		SegmentOrdinal: input.SegmentOrdinal, PreviousKind: input.PreviousKind,
		PreviousReference: input.PreviousReference, FirstSequence: input.FirstSequence,
		LastSequence: last, BaseHash: input.BaseHash, ThroughHash: previous,
		Entries: append([]archiveHistoryEntryV1{}, input.Entries...),
	}
	_, kref, kseal, err := sealedArchiveKeys(input.ArchiveKey)
	if err != nil {
		return empty, err
	}
	payloadRaw, err := sealedArchiveCanonical(payload)
	if err != nil {
		return empty, err
	}
	reference, err := sealedArchiveReference(kref, sealedArchiveHistorySchemaV8, sealedArchiveHistoryKindV1, payloadRaw)
	if err != nil {
		return empty, err
	}
	sealValue, err := sealedArchiveSeal(kseal, sealedArchiveHistorySchemaV8, sealedArchiveHistoryKindV1, reference, payloadRaw)
	if err != nil {
		return empty, err
	}
	envelope := archiveHistoryEnvelopeV1{Schema: sealedArchiveHistorySchemaV8, Kind: sealedArchiveHistoryKindV1, Reference: reference, Payload: payload, Seal: sealValue}
	raw, err := sealedArchivePersisted(envelope, int(sealedArchiveObjectMaxBytes))
	if err != nil {
		return empty, err
	}
	name, err := sealedArchiveContentName(sealedArchiveHistoryKindV1, reference)
	if err != nil {
		return empty, err
	}
	result := sealedArchiveHistoryFixtureV8{File: sealedArchiveV8File{Name: name, Bytes: raw}, Reference: reference, Seal: sealValue}
	if err := validateSealedArchiveHistoryV8(result.File, input.ArchiveKey, input.PreviousKind, input.PreviousReference, input.FirstSequence, input.BaseHash); err != nil {
		return empty, err
	}
	return result, nil
}

func validateSealedArchiveHistoryV8(file sealedArchiveV8File, archiveKey []byte, expectedPreviousKind, expectedPreviousReference string, expectedFirstSequence uint64, expectedBaseHash string) error {
	if len(archiveKey) != sha256.Size || !sealedArchiveValidHex32(expectedPreviousReference) || !sealedArchiveValidHex32(expectedBaseHash) || expectedFirstSequence == 0 {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	var envelope archiveHistoryEnvelopeV1
	if err := sealedArchiveDecode(file.Bytes, true, int(sealedArchiveObjectMaxBytes), &envelope); err != nil {
		return err
	}
	if envelope.Schema != sealedArchiveHistorySchemaV8 || envelope.Kind != sealedArchiveHistoryKindV1 {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	_, kref, kseal, err := sealedArchiveKeys(archiveKey)
	if err != nil {
		return err
	}
	if err := sealedArchiveVerifyEnvelopeV8(envelope.Schema, envelope.Kind, envelope.Reference, envelope.Seal, envelope.Payload, kref, kseal); err != nil {
		return err
	}
	payload := envelope.Payload
	if !sealedArchiveValidHex32(payload.MigrationID) || !sealedArchiveValidHex32(payload.ArchiveEpoch) || payload.SegmentOrdinal == 0 || payload.PreviousKind != expectedPreviousKind || payload.PreviousReference != expectedPreviousReference || payload.FirstSequence != expectedFirstSequence || payload.BaseHash != expectedBaseHash || payload.Entries == nil || len(payload.Entries) == 0 {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	if len(payload.Entries) > MaxAuditEntries || uint64(len(payload.Entries)-1) > math.MaxUint64-payload.FirstSequence {
		return sealedArchiveFail(CodeArchiveLimit)
	}
	if payload.LastSequence != payload.FirstSequence+uint64(len(payload.Entries)-1) {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	if payload.SegmentOrdinal == 1 && payload.PreviousKind != sealedArchiveGenesisKindV1 || payload.SegmentOrdinal > 1 && payload.PreviousKind != sealedArchiveHistoryKindV1 {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	previous := payload.BaseHash
	for i, entry := range payload.Entries {
		audit := entry.Audit
		if audit.Sequence != payload.FirstSequence+uint64(i) || audit.PreviousHash != previous || audit.Hash != storeAuditHash(audit) || entry.Request.Key != audit.Key || entry.Request.Fingerprint != audit.RequestDigest || entry.Request.Action != audit.Action || entry.Request.SourceID != audit.SourceID || entry.Request.CandidateID != audit.CandidateID {
			return sealedArchiveFail(CodeArchiveReconstructionFailed)
		}
		previous = audit.Hash
	}
	if payload.ThroughHash != previous {
		return sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	name, err := sealedArchiveContentName(sealedArchiveHistoryKindV1, envelope.Reference)
	if err != nil || name != file.Name {
		return sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	return nil
}
