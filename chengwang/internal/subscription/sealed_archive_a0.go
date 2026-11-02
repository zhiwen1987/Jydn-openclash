package subscription

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
)

// sealedArchiveV8Input contains only caller-frozen in-memory values. It has no
// path, store handle, clock, random source, selector, or activation authority.
type sealedArchiveV8Input struct {
	ArchiveKey    []byte
	Nonce         []byte
	ObservedAt    string
	ArchiveRoot   archiveRootIdentityV1
	FrozenSources archiveFrozenSourcesV1
	Budget        archiveBudgetV1
	OriginalV1    []byte
}

type sealedArchiveV8File struct {
	Name  string
	Bytes []byte
}

type sealedArchiveV8Identity struct {
	KeyID               string
	MigrationID         string
	ArchiveEpoch        string
	IntentReference     string
	IntentSeal          string
	CandidateReferences []string
	CandidateSeals      []string
	GenesisReference    string
	GenesisSeal         string
	ReceiptReference    string
	ReceiptSeal         string
	FrozenSourcesSHA256 string
}

type sealedArchiveV8BytePlan struct {
	MetaBytes            uint64
	IntentBytes          uint64
	CandidateBytes       []uint64
	GenesisBytes         uint64
	PreReceiptFinalBytes uint64
	Q                    uint64
	ReceiptBytes         uint64
	FinalBytes           uint64
	MaxTempBytes         uint64
	PeakBytes            uint64
	FinalEntries         uint32
	PeakEntries          uint32
}

// sealedArchiveV8Plan is a pure-memory byte plan. A caller must not infer
// filesystem publication, activation, capacity release, or runtime state.
type sealedArchiveV8Plan struct {
	Meta       sealedArchiveV8File
	Lock       sealedArchiveV8File
	Intent     sealedArchiveV8File
	Candidates []sealedArchiveV8File
	Genesis    sealedArchiveV8File
	Receipt    sealedArchiveV8File
	Identity   sealedArchiveV8Identity
	Bytes      sealedArchiveV8BytePlan
}

func buildSealedArchiveV8(input sealedArchiveV8Input) (sealedArchiveV8Plan, error) {
	return sealedArchiveBuildV8(input, true)
}

func sealedArchiveBuildV8(input sealedArchiveV8Input, verify bool) (sealedArchiveV8Plan, error) {
	var empty sealedArchiveV8Plan
	state, original, err := sealedArchiveValidateInputV8(input)
	if err != nil {
		return empty, err
	}
	keyID, kref, kseal, err := sealedArchiveKeys(input.ArchiveKey)
	if err != nil {
		return empty, err
	}
	meta := archiveMetaV2{
		Schema: sealedArchiveMetaSchemaV8, FormatVersion: 2,
		ArchiveKey: append([]byte{}, input.ArchiveKey...), KeyID: keyID,
		ArchiveMaxBytes: input.Budget.ArchiveMaxBytes, ObjectMaxBytes: input.Budget.ObjectMaxBytes,
		CandidateMax: input.Budget.CandidateMax, FinalEntryMax: input.Budget.FinalEntryMax, PeakEntryMax: input.Budget.PeakEntryMax,
	}
	metaRaw, err := sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
	if err != nil {
		return empty, err
	}
	core := archiveIntentCoreV1{
		Schema: sealedArchiveIntentCoreSchemaV8, ObservedAt: input.ObservedAt,
		Nonce: append([]byte{}, input.Nonce...), KeyID: keyID, ArchiveRoot: input.ArchiveRoot,
		FrozenSources: input.FrozenSources, SourceRevision: sealedArchiveSourceRevisionV8(),
		CodecID: sealedArchiveCodecV8, PolicyID: sealedArchivePolicyV8, Budget: input.Budget,
		OriginalV1: original, CandidateCount: uint32(len(state.Candidates)),
	}
	coreRaw, err := sealedArchiveCanonical(core)
	if err != nil {
		return empty, err
	}
	migrationID, err := sealedArchiveReference(kref, sealedArchiveIntentCoreSchemaV8, sealedArchiveIntentKindV1, coreRaw)
	if err != nil {
		return empty, err
	}
	epoch, err := sealedArchiveEpoch(kref, migrationID)
	if err != nil {
		return empty, err
	}
	intentPayload := archiveIntentPayloadV1{Core: core, MigrationID: migrationID, ArchiveEpoch: epoch}
	intentRaw, intentReference, intentSeal, err := sealedArchiveMakeIntentV8(kref, kseal, intentPayload)
	if err != nil {
		return empty, err
	}

	candidateFiles := make([]sealedArchiveV8File, 0, len(state.Candidates))
	candidateReferences := make([]string, 0, len(state.Candidates))
	candidateSeals := make([]string, 0, len(state.Candidates))
	candidateLinks := make([]archiveCandidateLinkV1, 0, len(state.Candidates))
	candidateSizes := make([]uint64, 0, len(state.Candidates))
	for i, candidate := range state.Candidates {
		payload := archiveCandidatePayloadV1{MigrationID: migrationID, ArchiveEpoch: epoch, Ordinal: uint32(i), Candidate: candidate}
		raw, reference, candidateSeal, buildErr := sealedArchiveMakeCandidateV8(kref, kseal, payload)
		if buildErr != nil {
			return empty, buildErr
		}
		name, nameErr := sealedArchiveContentName(sealedArchiveCandidateKindV1, reference)
		if nameErr != nil {
			return empty, nameErr
		}
		candidateFiles = append(candidateFiles, sealedArchiveV8File{Name: name, Bytes: raw})
		candidateReferences = append(candidateReferences, reference)
		candidateSeals = append(candidateSeals, candidateSeal)
		candidateLinks = append(candidateLinks, archiveCandidateLinkV1{Ordinal: uint32(i), Reference: reference})
		candidateSizes = append(candidateSizes, uint64(len(raw)))
	}

	genesisPayload := archiveGenesisPayloadV1{
		MigrationID: migrationID, ArchiveEpoch: epoch, KeyID: keyID, IntentReference: intentReference,
		StoreSchema: state.Schema, IdentityKey: append([]byte{}, state.IdentityKey...),
		Sources: append([]SourceView{}, state.Sources...), Candidates: candidateLinks,
		Requests: append([]storeRequest{}, state.Requests...), Audit: append([]storeAudit{}, state.Audit...),
		Commands: append([]controlCommandDisk{}, state.Commands...), Approvals: append([]ControlApproval{}, state.Approvals...),
		OriginalV1: original, FrozenSources: input.FrozenSources, SourceRevision: sealedArchiveSourceRevisionV8(),
		CodecID: sealedArchiveCodecV8, PolicyID: sealedArchivePolicyV8, Budget: input.Budget,
	}
	genesisRaw, genesisReference, genesisSeal, err := sealedArchiveMakeGenesisV8(kref, kseal, genesisPayload)
	if err != nil {
		return empty, err
	}
	genesisName, err := sealedArchiveContentName(sealedArchiveGenesisKindV1, genesisReference)
	if err != nil {
		return empty, err
	}

	pre, err := sealedArchiveCheckedAdd(uint64(len(metaRaw)), uint64(len(intentRaw)), uint64(len(genesisRaw)))
	if err != nil {
		return empty, err
	}
	q := uint64(len(metaRaw))
	for _, size := range candidateSizes {
		pre, err = sealedArchiveCheckedAdd(pre, size)
		if err != nil {
			return empty, err
		}
		if size > q {
			q = size
		}
	}
	if uint64(len(intentRaw)) > q {
		q = uint64(len(intentRaw))
	}
	if uint64(len(genesisRaw)) > q {
		q = uint64(len(genesisRaw))
	}

	frozenRaw, err := sealedArchiveCanonical(input.FrozenSources)
	if err != nil {
		return empty, err
	}
	frozenHash := sha256.Sum256(frozenRaw)
	receiptReferences := append([]string{}, candidateReferences...)
	sort.Strings(receiptReferences)
	counts := archiveReceiptCountsV1{
		CandidateObjects: uint32(len(state.Candidates)), ContentObjects: uint32(len(state.Candidates)) + 1,
		FixedDocuments: 3, LockEntries: 1, FinalEntries: uint32(len(state.Candidates)) + 5, PeakEntries: uint32(len(state.Candidates)) + 6,
	}
	if err := sealedArchiveValidateEntryLimitsV8(counts.CandidateObjects, counts.FinalEntries, counts.PeakEntries, input.Budget); err != nil {
		return empty, err
	}
	baseReceipt := archiveReceiptPayloadV2{
		MigrationID: migrationID, ArchiveEpoch: epoch, KeyID: keyID, IntentReference: intentReference,
		GenesisReference: genesisReference, FrozenSourcesSHA256: hex.EncodeToString(frozenHash[:]),
		CandidateReferences: receiptReferences, Counts: counts, Budget: input.Budget,
		Reconstruction: archiveReconstructionV1{Length: original.Length, SHA256: original.SHA256, Result: "strict-v1-exact"},
		Blockers:       sealedArchiveBlockersV8(state, input.FrozenSources.Refresh),
		Limitations: archiveLimitationsV1{
			HMACScope: "same-root-integrity-only", WholeAnchorRollbackProtection: "requires-external-witness",
			OldBinaryConstraint: "none", BackupProof: false, SelectorAuthority: false, CapacityReleased: false,
		},
		ShadowOnly: true, Activatable: false,
	}
	placeholderPayload := baseReceipt
	placeholderPayload.Bytes = archiveReceiptBytesV2{
		PreReceiptFinalBytes: pre, ReceiptBytesHex: strings.Repeat("0", 16), FinalBytesHex: strings.Repeat("0", 16),
		MaxTempBytesHex: strings.Repeat("0", 16), PeakBytesHex: strings.Repeat("0", 16),
	}
	placeholder := archiveReceiptEnvelopeV1{
		Schema: sealedArchiveReceiptSchemaV8, Kind: sealedArchiveReceiptKindV1,
		Reference: strings.Repeat("0", 64), Payload: placeholderPayload, Seal: strings.Repeat("0", 64),
	}
	placeholderRaw, err := sealedArchivePersisted(placeholder, sealedArchiveReceiptMaxBytes)
	if err != nil {
		return empty, err
	}
	r := uint64(len(placeholderRaw))
	f, err := sealedArchiveCheckedAdd(pre, r)
	if err != nil {
		return empty, err
	}
	m := sealedArchiveMaxTempV8(q, r)
	peak, err := sealedArchiveCheckedAdd(f, m)
	if err != nil {
		return empty, sealedArchiveFail(CodeArchiveLimit)
	}
	if err := sealedArchiveValidateByteLimitsV8(f, peak, input.Budget); err != nil {
		return empty, err
	}
	finalReceiptPayload := baseReceipt
	finalReceiptPayload.Bytes = archiveReceiptBytesV2{
		PreReceiptFinalBytes: pre, ReceiptBytesHex: sealedArchiveHexU64(r), FinalBytesHex: sealedArchiveHexU64(f),
		MaxTempBytesHex: sealedArchiveHexU64(m), PeakBytesHex: sealedArchiveHexU64(peak),
	}
	receiptRaw, receiptReference, receiptSeal, err := sealedArchiveMakeReceiptV8(kref, kseal, finalReceiptPayload)
	if err != nil {
		return empty, err
	}
	if uint64(len(receiptRaw)) != r {
		return empty, sealedArchiveFail(CodeArchiveConflict)
	}
	plan := sealedArchiveV8Plan{
		Meta:       sealedArchiveV8File{Name: "archive.meta", Bytes: metaRaw},
		Lock:       sealedArchiveV8File{Name: "archive.lock", Bytes: []byte{}},
		Intent:     sealedArchiveV8File{Name: "migration.intent.json", Bytes: intentRaw},
		Candidates: candidateFiles,
		Genesis:    sealedArchiveV8File{Name: genesisName, Bytes: genesisRaw},
		Receipt:    sealedArchiveV8File{Name: "shadow.receipt.json", Bytes: receiptRaw},
		Identity: sealedArchiveV8Identity{
			KeyID: keyID, MigrationID: migrationID, ArchiveEpoch: epoch,
			IntentReference: intentReference, IntentSeal: intentSeal,
			CandidateReferences: candidateReferences, CandidateSeals: candidateSeals,
			GenesisReference: genesisReference, GenesisSeal: genesisSeal,
			ReceiptReference: receiptReference, ReceiptSeal: receiptSeal,
			FrozenSourcesSHA256: hex.EncodeToString(frozenHash[:]),
		},
		Bytes: sealedArchiveV8BytePlan{
			MetaBytes: uint64(len(metaRaw)), IntentBytes: uint64(len(intentRaw)), CandidateBytes: candidateSizes,
			GenesisBytes: uint64(len(genesisRaw)), PreReceiptFinalBytes: pre, Q: q, ReceiptBytes: r,
			FinalBytes: f, MaxTempBytes: m, PeakBytes: peak, FinalEntries: counts.FinalEntries, PeakEntries: counts.PeakEntries,
		},
	}
	if verify {
		if err := validateSealedArchiveV8Plan(plan); err != nil {
			return empty, err
		}
	}
	return sealedArchiveClonePlanV8(plan), nil
}

func sealedArchiveValidateInputV8(input sealedArchiveV8Input) (storeSnapshot, archiveByteIdentityV1, error) {
	var state storeSnapshot
	var identity archiveByteIdentityV1
	if len(input.ArchiveKey) != sha256.Size || len(input.Nonce) != sha256.Size {
		return state, identity, sealedArchiveFail(CodeArchiveInvalid)
	}
	if err := sealedArchiveValidateObservedAt(input.ObservedAt); err != nil {
		return state, identity, err
	}
	if err := sealedArchiveValidatePosix(input.ArchiveRoot.Identity); err != nil {
		return state, identity, err
	}
	if err := sealedArchiveValidateBudget(input.Budget); err != nil {
		return state, identity, err
	}
	if err := sealedArchiveValidateFrozen(input.FrozenSources); err != nil {
		return state, identity, err
	}
	if uint64(len(input.OriginalV1)) > sealedArchiveObjectMaxBytes {
		return state, identity, sealedArchiveFail(CodeArchiveLimit)
	}
	if storeDecode(input.OriginalV1, &state) != nil || storeValidate(state) != nil {
		return state, identity, sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	canonical, err := storeEncode(state)
	if err != nil || !bytes.Equal(canonical, input.OriginalV1) {
		return state, identity, sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	digest := sha256.Sum256(input.OriginalV1)
	identity = archiveByteIdentityV1{Length: uint64(len(input.OriginalV1)), SHA256: hex.EncodeToString(digest[:])}
	main := input.FrozenSources.Main
	mainKeyID, err := sealedArchiveSourceKeyID("main-v1", state.IdentityKey)
	if err != nil {
		return state, identity, err
	}
	auditHead := strings.Repeat("0", 64)
	if len(state.Audit) != 0 {
		auditHead = state.Audit[len(state.Audit)-1].Hash
	}
	if main.Snapshot.Length != identity.Length || main.Snapshot.SHA256 != identity.SHA256 || main.IdentityKeyID != mainKeyID || main.AuditCount != uint32(len(state.Audit)) || main.AuditHead != auditHead || main.CommandCount != uint32(len(state.Commands)) || main.ApprovalCount != uint32(len(state.Approvals)) {
		return state, identity, sealedArchiveFail(CodeArchiveConflict)
	}
	if err := sealedArchiveValidateMainCheckpointV8(state, main.LatestRefreshCheckpoint); err != nil {
		return state, identity, err
	}
	return state, identity, nil
}

func sealedArchiveValidateMainCheckpointV8(state storeSnapshot, checkpoint archiveMainCheckpointV1) error {
	if !checkpoint.Present {
		// The wire summary has no scope field, so A0 cannot infer whether a
		// marker in another scope is the caller-selected latest checkpoint.
		return nil
	}
	for _, disk := range state.Commands {
		command := disk.Record
		if command.ID != checkpoint.CommandID {
			continue
		}
		if !command.Acknowledged || command.Result == nil || command.Result.State != "failed" || command.Result.ReferenceID != refreshCheckpointPrefix+checkpoint.Epoch {
			return sealedArchiveFail(CodeArchiveConflict)
		}
		return nil
	}
	return sealedArchiveFail(CodeArchiveConflict)
}

func sealedArchiveMakeIntentV8(kref, kseal []byte, payload archiveIntentPayloadV1) ([]byte, string, string, error) {
	payloadRaw, err := sealedArchiveCanonical(payload)
	if err != nil {
		return nil, "", "", err
	}
	reference, err := sealedArchiveReference(kref, sealedArchiveIntentSchemaV8, sealedArchiveIntentKindV1, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	seal, err := sealedArchiveSeal(kseal, sealedArchiveIntentSchemaV8, sealedArchiveIntentKindV1, reference, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	raw, err := sealedArchivePersisted(archiveIntentEnvelopeV1{Schema: sealedArchiveIntentSchemaV8, Kind: sealedArchiveIntentKindV1, Reference: reference, Payload: payload, Seal: seal}, sealedArchiveIntentMaxBytes)
	return raw, reference, seal, err
}

func sealedArchiveMakeCandidateV8(kref, kseal []byte, payload archiveCandidatePayloadV1) ([]byte, string, string, error) {
	payloadRaw, err := sealedArchiveCanonical(payload)
	if err != nil {
		return nil, "", "", err
	}
	reference, err := sealedArchiveReference(kref, sealedArchiveCandidateSchemaV8, sealedArchiveCandidateKindV1, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	seal, err := sealedArchiveSeal(kseal, sealedArchiveCandidateSchemaV8, sealedArchiveCandidateKindV1, reference, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	raw, err := sealedArchivePersisted(archiveCandidateEnvelopeV1{Schema: sealedArchiveCandidateSchemaV8, Kind: sealedArchiveCandidateKindV1, Reference: reference, Payload: payload, Seal: seal}, int(sealedArchiveObjectMaxBytes))
	return raw, reference, seal, err
}

func sealedArchiveMakeGenesisV8(kref, kseal []byte, payload archiveGenesisPayloadV1) ([]byte, string, string, error) {
	payloadRaw, err := sealedArchiveCanonical(payload)
	if err != nil {
		return nil, "", "", err
	}
	reference, err := sealedArchiveReference(kref, sealedArchiveGenesisSchemaV8, sealedArchiveGenesisKindV1, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	seal, err := sealedArchiveSeal(kseal, sealedArchiveGenesisSchemaV8, sealedArchiveGenesisKindV1, reference, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	raw, err := sealedArchivePersisted(archiveGenesisEnvelopeV1{Schema: sealedArchiveGenesisSchemaV8, Kind: sealedArchiveGenesisKindV1, Reference: reference, Payload: payload, Seal: seal}, int(sealedArchiveObjectMaxBytes))
	return raw, reference, seal, err
}

func sealedArchiveMakeReceiptV8(kref, kseal []byte, payload archiveReceiptPayloadV2) ([]byte, string, string, error) {
	payloadRaw, err := sealedArchiveCanonical(payload)
	if err != nil {
		return nil, "", "", err
	}
	reference, err := sealedArchiveReference(kref, sealedArchiveReceiptSchemaV8, sealedArchiveReceiptKindV1, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	seal, err := sealedArchiveSeal(kseal, sealedArchiveReceiptSchemaV8, sealedArchiveReceiptKindV1, reference, payloadRaw)
	if err != nil {
		return nil, "", "", err
	}
	raw, err := sealedArchivePersisted(archiveReceiptEnvelopeV1{Schema: sealedArchiveReceiptSchemaV8, Kind: sealedArchiveReceiptKindV1, Reference: reference, Payload: payload, Seal: seal}, sealedArchiveReceiptMaxBytes)
	return raw, reference, seal, err
}

func sealedArchiveBlockersV8(state storeSnapshot, refresh archiveRefreshSourceV1) []archiveBlockerCountV1 {
	var running, unknown, reservation, rotation, frozen uint32
	if refresh.Present != nil {
		running = refresh.Present.RunningCount
		unknown = refresh.Present.UnknownCount
		reservation = refresh.Present.ReservationCount
		if refresh.Present.PendingRotation {
			rotation = 1
		}
		if refresh.Present.ClockState == string(RefreshClockFrozen) {
			frozen = 1
		}
	}
	var prepared, unacknowledged uint32
	for _, command := range state.Commands {
		if command.Record.Result == nil {
			prepared++
		} else if !command.Record.Acknowledged {
			unacknowledged++
		}
	}
	return []archiveBlockerCountV1{
		{Class: "refresh_running", Count: running},
		{Class: "refresh_unknown", Count: unknown},
		{Class: "refresh_retained_reservation", Count: reservation},
		{Class: "control_prepared_resultless", Count: prepared},
		{Class: "control_unacknowledged", Count: unacknowledged},
		{Class: "refresh_pending_rotation", Count: rotation},
		{Class: "refresh_clock_frozen", Count: frozen},
	}
}

func sealedArchiveMaxTempV8(q, receiptBytes uint64) uint64 {
	if receiptBytes > q {
		return receiptBytes
	}
	return q
}

func sealedArchiveValidateByteLimitsV8(finalBytes, peakBytes uint64, budget archiveBudgetV1) error {
	if finalBytes > budget.ArchiveMaxBytes || peakBytes > budget.ArchiveMaxBytes || finalBytes > sealedArchiveMaxBytes || peakBytes > sealedArchiveMaxBytes {
		return sealedArchiveFail(CodeArchiveLimit)
	}
	return nil
}

func sealedArchiveValidateEntryLimitsV8(candidateObjects, finalEntries, peakEntries uint32, budget archiveBudgetV1) error {
	if candidateObjects > sealedArchiveCandidateMax || finalEntries > budget.FinalEntryMax || peakEntries > budget.PeakEntryMax || finalEntries > sealedArchiveFinalEntryMax || peakEntries > sealedArchivePeakEntryMax {
		return sealedArchiveFail(CodeArchiveLimit)
	}
	return nil
}

func validateSealedArchiveV8Plan(plan sealedArchiveV8Plan) error {
	if plan.Meta.Name != "archive.meta" || plan.Lock.Name != "archive.lock" || len(plan.Lock.Bytes) != 0 || plan.Intent.Name != "migration.intent.json" || plan.Receipt.Name != "shadow.receipt.json" {
		return sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	if plan.Candidates == nil {
		return sealedArchiveFail(CodeArchiveInvalid)
	}
	if len(plan.Candidates) > int(sealedArchiveCandidateMax) {
		return sealedArchiveFail(CodeArchiveLimit)
	}
	for _, file := range append(append([]sealedArchiveV8File{}, plan.Candidates...), plan.Genesis) {
		if err := sealedArchiveValidateSafeName(file.Name); err != nil {
			return err
		}
	}
	var meta archiveMetaV2
	if err := sealedArchiveDecode(plan.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta); err != nil {
		return err
	}
	if meta.Schema != sealedArchiveMetaSchemaV8 || meta.FormatVersion != 2 {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	budget := archiveBudgetV1{ArchiveMaxBytes: meta.ArchiveMaxBytes, ObjectMaxBytes: meta.ObjectMaxBytes, CandidateMax: meta.CandidateMax, FinalEntryMax: meta.FinalEntryMax, PeakEntryMax: meta.PeakEntryMax}
	if err := sealedArchiveValidateBudget(budget); err != nil {
		return err
	}
	keyID, kref, kseal, err := sealedArchiveKeys(meta.ArchiveKey)
	if err != nil || keyID != meta.KeyID {
		return sealedArchiveFail(CodeArchiveAuthenticationFailed)
	}
	var intent archiveIntentEnvelopeV1
	if err := sealedArchiveDecode(plan.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &intent); err != nil {
		return err
	}
	if err := sealedArchiveVerifyIntentV8(intent, kref, kseal, keyID, budget); err != nil {
		return err
	}
	candidates := make([]archiveCandidateEnvelopeV1, len(plan.Candidates))
	for i := range plan.Candidates {
		if err := sealedArchiveDecode(plan.Candidates[i].Bytes, true, int(sealedArchiveObjectMaxBytes), &candidates[i]); err != nil {
			return err
		}
		if err := sealedArchiveVerifyCandidateV8(candidates[i], kref, kseal, intent.Payload.MigrationID, intent.Payload.ArchiveEpoch, uint32(i), plan.Candidates[i].Name); err != nil {
			return err
		}
	}
	var genesis archiveGenesisEnvelopeV1
	if err := sealedArchiveDecode(plan.Genesis.Bytes, true, int(sealedArchiveObjectMaxBytes), &genesis); err != nil {
		return err
	}
	if genesis.Schema != sealedArchiveGenesisSchemaV8 || genesis.Kind != sealedArchiveGenesisKindV1 {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if err := sealedArchiveVerifyEnvelopeV8(genesis.Schema, genesis.Kind, genesis.Reference, genesis.Seal, genesis.Payload, kref, kseal); err != nil {
		return err
	}
	genesisName, err := sealedArchiveContentName(sealedArchiveGenesisKindV1, genesis.Reference)
	if err != nil || genesisName != plan.Genesis.Name {
		return sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	if err := sealedArchiveVerifyGenesisLinksV8(genesis.Payload, intent, candidates, keyID, budget); err != nil {
		return err
	}
	state := storeSnapshot{
		Schema: genesis.Payload.StoreSchema, IdentityKey: append([]byte{}, genesis.Payload.IdentityKey...),
		Sources: append([]SourceView{}, genesis.Payload.Sources...), Candidates: []storeCandidate{},
		Requests: append([]storeRequest{}, genesis.Payload.Requests...), Audit: append([]storeAudit{}, genesis.Payload.Audit...),
		Commands: append([]controlCommandDisk{}, genesis.Payload.Commands...), Approvals: append([]ControlApproval{}, genesis.Payload.Approvals...),
	}
	for _, candidate := range candidates {
		state.Candidates = append(state.Candidates, candidate.Payload.Candidate)
	}
	if storeValidate(state) != nil {
		return sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	original, err := storeEncode(state)
	if err != nil {
		return sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	digest := sha256.Sum256(original)
	if genesis.Payload.OriginalV1.Length != uint64(len(original)) || genesis.Payload.OriginalV1.SHA256 != hex.EncodeToString(digest[:]) {
		return sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	var second storeSnapshot
	if storeDecode(original, &second) != nil || storeValidate(second) != nil {
		return sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	secondRaw, err := storeEncode(second)
	if err != nil || !bytes.Equal(secondRaw, original) {
		return sealedArchiveFail(CodeArchiveReconstructionFailed)
	}
	var receipt archiveReceiptEnvelopeV1
	if err := sealedArchiveDecode(plan.Receipt.Bytes, true, sealedArchiveReceiptMaxBytes, &receipt); err != nil {
		return err
	}
	if receipt.Schema != sealedArchiveReceiptSchemaV8 || receipt.Kind != sealedArchiveReceiptKindV1 {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if err := sealedArchiveVerifyEnvelopeV8(receipt.Schema, receipt.Kind, receipt.Reference, receipt.Seal, receipt.Payload, kref, kseal); err != nil {
		return err
	}
	if err := sealedArchiveValidateReceiptPlanV8(plan, receipt.Payload, budget); err != nil {
		return err
	}
	input := sealedArchiveV8Input{
		ArchiveKey: append([]byte{}, meta.ArchiveKey...), Nonce: append([]byte{}, intent.Payload.Core.Nonce...),
		ObservedAt: intent.Payload.Core.ObservedAt, ArchiveRoot: intent.Payload.Core.ArchiveRoot,
		FrozenSources: intent.Payload.Core.FrozenSources, Budget: budget, OriginalV1: original,
	}
	expected, err := sealedArchiveBuildV8(input, false)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(sealedArchiveClonePlanV8(plan), expected) {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	return nil
}

func sealedArchiveValidateReceiptPlanV8(plan sealedArchiveV8Plan, receipt archiveReceiptPayloadV2, budget archiveBudgetV1) error {
	pre, err := sealedArchiveCheckedAdd(uint64(len(plan.Meta.Bytes)), uint64(len(plan.Intent.Bytes)), uint64(len(plan.Genesis.Bytes)))
	if err != nil {
		return err
	}
	q := uint64(len(plan.Meta.Bytes))
	if uint64(len(plan.Intent.Bytes)) > q {
		q = uint64(len(plan.Intent.Bytes))
	}
	if uint64(len(plan.Genesis.Bytes)) > q {
		q = uint64(len(plan.Genesis.Bytes))
	}
	for _, candidate := range plan.Candidates {
		pre, err = sealedArchiveCheckedAdd(pre, uint64(len(candidate.Bytes)))
		if err != nil {
			return err
		}
		if uint64(len(candidate.Bytes)) > q {
			q = uint64(len(candidate.Bytes))
		}
	}
	r, err := sealedArchiveParseHexU64(receipt.Bytes.ReceiptBytesHex)
	if err != nil {
		return err
	}
	f, err := sealedArchiveParseHexU64(receipt.Bytes.FinalBytesHex)
	if err != nil {
		return err
	}
	m, err := sealedArchiveParseHexU64(receipt.Bytes.MaxTempBytesHex)
	if err != nil {
		return err
	}
	peak, err := sealedArchiveParseHexU64(receipt.Bytes.PeakBytesHex)
	if err != nil {
		return err
	}
	expectedF, err := sealedArchiveCheckedAdd(pre, r)
	if err != nil {
		return err
	}
	expectedM := sealedArchiveMaxTempV8(q, r)
	expectedPeak, err := sealedArchiveCheckedAdd(expectedF, expectedM)
	if err != nil {
		return err
	}
	candidateCount := uint32(len(plan.Candidates))
	expectedCounts := archiveReceiptCountsV1{
		CandidateObjects: candidateCount, ContentObjects: candidateCount + 1,
		FixedDocuments: 3, LockEntries: 1, FinalEntries: candidateCount + 5, PeakEntries: candidateCount + 6,
	}
	if receipt.Bytes.PreReceiptFinalBytes != pre || r != uint64(len(plan.Receipt.Bytes)) || f != expectedF || m != expectedM || peak != expectedPeak || receipt.Counts != expectedCounts {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	if err := sealedArchiveValidateEntryLimitsV8(expectedCounts.CandidateObjects, expectedCounts.FinalEntries, expectedCounts.PeakEntries, budget); err != nil {
		return err
	}
	if err := sealedArchiveValidateByteLimitsV8(f, peak, budget); err != nil {
		return err
	}
	return nil
}

func sealedArchiveVerifyIntentV8(intent archiveIntentEnvelopeV1, kref, kseal []byte, keyID string, budget archiveBudgetV1) error {
	if intent.Schema != sealedArchiveIntentSchemaV8 || intent.Kind != sealedArchiveIntentKindV1 {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if err := sealedArchiveVerifyEnvelopeV8(intent.Schema, intent.Kind, intent.Reference, intent.Seal, intent.Payload, kref, kseal); err != nil {
		return err
	}
	core := intent.Payload.Core
	if core.Schema != sealedArchiveIntentCoreSchemaV8 || core.KeyID != keyID || len(core.Nonce) != sha256.Size || core.SourceRevision != sealedArchiveSourceRevisionV8() || core.CodecID != sealedArchiveCodecV8 || core.PolicyID != sealedArchivePolicyV8 || core.Budget != budget || core.CandidateCount > sealedArchiveCandidateMax {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	if err := sealedArchiveValidateObservedAt(core.ObservedAt); err != nil {
		return err
	}
	if err := sealedArchiveValidateFrozen(core.FrozenSources); err != nil {
		return err
	}
	coreRaw, err := sealedArchiveCanonical(core)
	if err != nil {
		return err
	}
	migrationID, err := sealedArchiveReference(kref, sealedArchiveIntentCoreSchemaV8, sealedArchiveIntentKindV1, coreRaw)
	if err != nil || migrationID != intent.Payload.MigrationID {
		return sealedArchiveFail(CodeArchiveAuthenticationFailed)
	}
	epoch, err := sealedArchiveEpoch(kref, migrationID)
	if err != nil || epoch != intent.Payload.ArchiveEpoch {
		return sealedArchiveFail(CodeArchiveAuthenticationFailed)
	}
	return nil
}

func sealedArchiveVerifyCandidateV8(candidate archiveCandidateEnvelopeV1, kref, kseal []byte, migrationID, epoch string, ordinal uint32, name string) error {
	if candidate.Schema != sealedArchiveCandidateSchemaV8 || candidate.Kind != sealedArchiveCandidateKindV1 {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if err := sealedArchiveVerifyEnvelopeV8(candidate.Schema, candidate.Kind, candidate.Reference, candidate.Seal, candidate.Payload, kref, kseal); err != nil {
		return err
	}
	if candidate.Payload.MigrationID != migrationID || candidate.Payload.ArchiveEpoch != epoch || candidate.Payload.Ordinal != ordinal {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	expected, err := sealedArchiveContentName(sealedArchiveCandidateKindV1, candidate.Reference)
	if err != nil || expected != name {
		return sealedArchiveFail(CodeArchiveNameUnsafe)
	}
	return nil
}

func sealedArchiveVerifyGenesisLinksV8(genesis archiveGenesisPayloadV1, intent archiveIntentEnvelopeV1, candidates []archiveCandidateEnvelopeV1, keyID string, budget archiveBudgetV1) error {
	core := intent.Payload.Core
	if genesis.MigrationID != intent.Payload.MigrationID || genesis.ArchiveEpoch != intent.Payload.ArchiveEpoch || genesis.KeyID != keyID || genesis.IntentReference != intent.Reference || genesis.StoreSchema != storeSchema || genesis.OriginalV1 != core.OriginalV1 || !reflect.DeepEqual(genesis.FrozenSources, core.FrozenSources) || genesis.SourceRevision != core.SourceRevision || genesis.CodecID != core.CodecID || genesis.PolicyID != core.PolicyID || genesis.Budget != budget || len(genesis.Candidates) != len(candidates) || uint32(len(candidates)) != core.CandidateCount || genesis.Sources == nil || genesis.Candidates == nil || genesis.Requests == nil || genesis.Audit == nil || genesis.Commands == nil || genesis.Approvals == nil {
		return sealedArchiveFail(CodeArchiveConflict)
	}
	for i, link := range genesis.Candidates {
		if link.Ordinal != uint32(i) || link.Reference != candidates[i].Reference {
			return sealedArchiveFail(CodeArchiveConflict)
		}
	}
	return nil
}

func sealedArchiveVerifyEnvelopeV8[T sealedArchiveEnvelopePayload](schema, kind, reference, sealValue string, payload T, kref, kseal []byte) error {
	if !sealedArchiveSchemaKind(schema, kind) {
		return sealedArchiveFail(CodeArchiveKindUnsupported)
	}
	if !sealedArchiveValidHex32(reference) || !sealedArchiveValidHex32(sealValue) {
		return sealedArchiveFail(CodeArchiveAuthenticationFailed)
	}
	payloadRaw, err := sealedArchiveCanonical(payload)
	if err != nil {
		return err
	}
	expectedReference, err := sealedArchiveReference(kref, schema, kind, payloadRaw)
	if err != nil {
		return err
	}
	expectedSeal, err := sealedArchiveSeal(kseal, schema, kind, expectedReference, payloadRaw)
	if err != nil {
		return err
	}
	referenceRaw, referenceErr := hex.DecodeString(reference)
	expectedReferenceRaw, _ := hex.DecodeString(expectedReference)
	sealRaw, sealErr := hex.DecodeString(sealValue)
	expectedSealRaw, _ := hex.DecodeString(expectedSeal)
	if referenceErr != nil || sealErr != nil || !hmac.Equal(referenceRaw, expectedReferenceRaw) || !hmac.Equal(sealRaw, expectedSealRaw) {
		return sealedArchiveFail(CodeArchiveAuthenticationFailed)
	}
	return nil
}

func sealedArchiveClonePlanV8(plan sealedArchiveV8Plan) sealedArchiveV8Plan {
	cloneFile := func(file sealedArchiveV8File) sealedArchiveV8File {
		return sealedArchiveV8File{Name: file.Name, Bytes: append([]byte{}, file.Bytes...)}
	}
	result := plan
	result.Meta = cloneFile(plan.Meta)
	result.Lock = cloneFile(plan.Lock)
	result.Intent = cloneFile(plan.Intent)
	result.Candidates = make([]sealedArchiveV8File, len(plan.Candidates))
	for i := range plan.Candidates {
		result.Candidates[i] = cloneFile(plan.Candidates[i])
	}
	result.Genesis = cloneFile(plan.Genesis)
	result.Receipt = cloneFile(plan.Receipt)
	result.Identity.CandidateReferences = append([]string{}, plan.Identity.CandidateReferences...)
	result.Identity.CandidateSeals = append([]string{}, plan.Identity.CandidateSeals...)
	result.Bytes.CandidateBytes = append([]uint64{}, plan.Bytes.CandidateBytes...)
	return result
}
