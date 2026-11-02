package subscription

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

//go:embed testdata/FULL-CHAIN-GOLDEN-v8.json
var sealedArchiveGoldenV8Raw []byte

const sealedArchiveGoldenV8SHA256 = "b6cc264cb39159cee11745fd2e3ed13980c0a18bdf867505bf2629dbcbe7b3ab"

type sealedArchiveGoldenRecord struct {
	Length uint64 `json:"length"`
	SHA256 string `json:"sha256"`
	Base64 string `json:"base64"`
}

type sealedArchiveGoldenV8 struct {
	PolicyID       string `json:"policyId"`
	ValidFullChain struct {
		PublicInputs struct {
			ArchiveKeyHex           string   `json:"archiveKeyHex"`
			NonceHex                string   `json:"nonceHex"`
			MainIdentityKeyHex      string   `json:"mainIdentityKeyHex"`
			CandidateRawUTF8        string   `json:"candidateRawUtf8"`
			ObservedAt              string   `json:"observedAt"`
			EmbeddedV1Times         []string `json:"embeddedV1Times"`
			RefreshAbsenceChildName string   `json:"refreshAbsenceChildName"`
			EvidenceCheckpointUTF8  string   `json:"evidenceCheckpointUtf8"`
			EvidenceEntrySetBase64  string   `json:"evidenceEntrySetBase64"`
			MainEntrySetBase64      string   `json:"mainEntrySetBase64"`
		} `json:"publicInputs"`
		Objects struct {
			Meta                       sealedArchiveGoldenRecord   `json:"meta"`
			IntentCore                 sealedArchiveGoldenRecord   `json:"intentCore"`
			IntentPayload              sealedArchiveGoldenRecord   `json:"intentPayload"`
			IntentEnvelope             sealedArchiveGoldenRecord   `json:"intentEnvelope"`
			CandidatePayloads          []sealedArchiveGoldenRecord `json:"candidatePayloads"`
			CandidateEnvelopes         []sealedArchiveGoldenRecord `json:"candidateEnvelopes"`
			GenesisPayload             sealedArchiveGoldenRecord   `json:"genesisPayload"`
			GenesisEnvelope            sealedArchiveGoldenRecord   `json:"genesisEnvelope"`
			ReceiptPlaceholderEnvelope sealedArchiveGoldenRecord   `json:"receiptPlaceholderEnvelope"`
			ReceiptPayload             sealedArchiveGoldenRecord   `json:"receiptPayload"`
			ReceiptEnvelope            sealedArchiveGoldenRecord   `json:"receiptEnvelope"`
			OriginalV1                 sealedArchiveGoldenRecord   `json:"originalV1"`
			FrozenSources              sealedArchiveGoldenRecord   `json:"frozenSources"`
		} `json:"objects"`
		Derived struct {
			KeyID               string   `json:"keyId"`
			MigrationID         string   `json:"migrationId"`
			ArchiveEpoch        string   `json:"archiveEpoch"`
			IntentReference     string   `json:"intentReference"`
			IntentSeal          string   `json:"intentSeal"`
			CandidateReferences []string `json:"candidateReferences"`
			CandidateSeals      []string `json:"candidateSeals"`
			CandidateBasenames  []string `json:"candidateBasenames"`
			GenesisReference    string   `json:"genesisReference"`
			GenesisSeal         string   `json:"genesisSeal"`
			GenesisBasename     string   `json:"genesisBasename"`
			ReceiptReference    string   `json:"receiptReference"`
			ReceiptSeal         string   `json:"receiptSeal"`
			FrozenSourcesSHA256 string   `json:"frozenSourcesSha256"`
		} `json:"derived"`
		Plan struct {
			SMeta        uint64   `json:"sMeta"`
			SIntent      uint64   `json:"sIntent"`
			SCandidates  []uint64 `json:"sCandidates"`
			SGenesis     uint64   `json:"sGenesis"`
			Pre          uint64   `json:"pre"`
			Q            uint64   `json:"Q"`
			R            uint64   `json:"R"`
			F            uint64   `json:"F"`
			M            uint64   `json:"M"`
			Peak         uint64   `json:"Peak"`
			FinalEntries uint32   `json:"finalEntries"`
			PeakEntries  uint32   `json:"peakEntries"`
		} `json:"plan"`
	} `json:"validFullChain"`
	CalculatedNegatives struct {
		Budget struct {
			MinimalAcceptedFixedPoint struct {
				ArchiveMaxBytes uint64 `json:"archiveMaxBytes"`
				Plan            struct {
					Pre  uint64 `json:"pre"`
					Q    uint64 `json:"Q"`
					R    uint64 `json:"R"`
					F    uint64 `json:"F"`
					M    uint64 `json:"M"`
					Peak uint64 `json:"Peak"`
				} `json:"plan"`
				IntentCoreSHA256 string `json:"intentCoreSha256"`
				ReceiptReference string `json:"receiptReference"`
			} `json:"minimalAcceptedFixedPoint"`
			OneBelow struct {
				ArchiveMaxBytes uint64 `json:"archiveMaxBytes"`
				WouldBePeak     uint64 `json:"wouldBePeak"`
			} `json:"oneBelow"`
		} `json:"budget"`
	} `json:"calculatedNegatives"`
}

func sealedArchiveGoldenV8Fixture(t *testing.T) sealedArchiveGoldenV8 {
	t.Helper()
	digest := sha256.Sum256(sealedArchiveGoldenV8Raw)
	if hex.EncodeToString(digest[:]) != sealedArchiveGoldenV8SHA256 {
		t.Fatal("sealed archive golden file identity differs from accepted v8")
	}
	var golden sealedArchiveGoldenV8
	if json.Unmarshal(sealedArchiveGoldenV8Raw, &golden) != nil || golden.PolicyID != sealedArchivePolicyV8 || len(golden.ValidFullChain.Objects.CandidatePayloads) != 1 || len(golden.ValidFullChain.Objects.CandidateEnvelopes) != 1 || len(golden.ValidFullChain.Derived.CandidateReferences) != 1 || len(golden.ValidFullChain.Derived.CandidateSeals) != 1 || len(golden.ValidFullChain.Derived.CandidateBasenames) != 1 {
		t.Fatal("sealed archive golden fixture is invalid")
	}
	return golden
}

func sealedArchiveGoldenBytes(t *testing.T, record sealedArchiveGoldenRecord) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(record.Base64)
	if err != nil || uint64(len(raw)) != record.Length {
		t.Fatal("sealed archive golden byte record is invalid")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != record.SHA256 {
		t.Fatal("sealed archive golden byte digest is invalid")
	}
	return raw
}

func sealedArchiveGoldenInputV8(t *testing.T, max uint64) (sealedArchiveV8Input, sealedArchiveGoldenV8) {
	t.Helper()
	golden := sealedArchiveGoldenV8Fixture(t)
	var meta archiveMetaV2
	if sealedArchiveDecode(sealedArchiveGoldenBytes(t, golden.ValidFullChain.Objects.Meta), true, sealedArchiveMetaMaxBytes, &meta) != nil {
		t.Fatal("sealed archive golden meta decode failed")
	}
	var core archiveIntentCoreV1
	if sealedArchiveDecode(sealedArchiveGoldenBytes(t, golden.ValidFullChain.Objects.IntentCore), false, sealedArchiveIntentMaxBytes, &core) != nil {
		t.Fatal("sealed archive golden core decode failed")
	}
	core.Budget.ArchiveMaxBytes = max
	return sealedArchiveV8Input{
		ArchiveKey: append([]byte{}, meta.ArchiveKey...), Nonce: append([]byte{}, core.Nonce...),
		ObservedAt: core.ObservedAt, ArchiveRoot: core.ArchiveRoot, FrozenSources: core.FrozenSources,
		Budget: core.Budget, OriginalV1: sealedArchiveGoldenBytes(t, golden.ValidFullChain.Objects.OriginalV1),
	}, golden
}

func sealedArchiveRequireCode(t *testing.T, err error, code Code) {
	t.Helper()
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code != code || err.Error() != string(code) {
		t.Fatal("sealed archive returned the wrong closed error")
	}
}

func sealedArchiveRequireClosed(t *testing.T, err error) {
	t.Helper()
	var failure *Failure
	if !errors.As(err, &failure) || err.Error() != string(failure.Code) {
		t.Fatal("sealed archive did not return a closed failure")
	}
}

func sealedArchiveReplaceGenesisV8(t *testing.T, plan sealedArchiveV8Plan, edit func(*archiveGenesisPayloadV1)) sealedArchiveV8Plan {
	t.Helper()
	var meta archiveMetaV2
	var envelope archiveGenesisEnvelopeV1
	if sealedArchiveDecode(plan.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta) != nil || sealedArchiveDecode(plan.Genesis.Bytes, true, int(sealedArchiveObjectMaxBytes), &envelope) != nil {
		t.Fatal("sealed archive genesis mutation fixture decode failed")
	}
	_, kref, kseal, err := sealedArchiveKeys(meta.ArchiveKey)
	if err != nil {
		t.Fatal("sealed archive genesis mutation keys failed")
	}
	edit(&envelope.Payload)
	raw, reference, _, err := sealedArchiveMakeGenesisV8(kref, kseal, envelope.Payload)
	if err != nil {
		t.Fatal("sealed archive genesis mutation reseal failed")
	}
	name, err := sealedArchiveContentName(sealedArchiveGenesisKindV1, reference)
	if err != nil {
		t.Fatal("sealed archive genesis mutation name failed")
	}
	result := sealedArchiveClonePlanV8(plan)
	result.Genesis = sealedArchiveV8File{Name: name, Bytes: raw}
	return result
}

func sealedArchiveReplaceHistoryV8(t *testing.T, file sealedArchiveV8File, archiveKey []byte, edit func(*archiveHistoryPayloadV1)) sealedArchiveV8File {
	t.Helper()
	var envelope archiveHistoryEnvelopeV1
	if sealedArchiveDecode(file.Bytes, true, int(sealedArchiveObjectMaxBytes), &envelope) != nil {
		t.Fatal("sealed archive history mutation fixture decode failed")
	}
	_, kref, kseal, err := sealedArchiveKeys(archiveKey)
	if err != nil {
		t.Fatal("sealed archive history mutation keys failed")
	}
	edit(&envelope.Payload)
	payloadRaw, err := sealedArchiveCanonical(envelope.Payload)
	if err != nil {
		t.Fatal("sealed archive history mutation canonicalization failed")
	}
	reference, err := sealedArchiveReference(kref, sealedArchiveHistorySchemaV8, sealedArchiveHistoryKindV1, payloadRaw)
	if err != nil {
		t.Fatal("sealed archive history mutation reference failed")
	}
	sealValue, err := sealedArchiveSeal(kseal, sealedArchiveHistorySchemaV8, sealedArchiveHistoryKindV1, reference, payloadRaw)
	if err != nil {
		t.Fatal("sealed archive history mutation seal failed")
	}
	raw, err := sealedArchivePersisted(archiveHistoryEnvelopeV1{Schema: sealedArchiveHistorySchemaV8, Kind: sealedArchiveHistoryKindV1, Reference: reference, Payload: envelope.Payload, Seal: sealValue}, int(sealedArchiveObjectMaxBytes))
	if err != nil {
		t.Fatal("sealed archive history mutation envelope failed")
	}
	name, err := sealedArchiveContentName(sealedArchiveHistoryKindV1, reference)
	if err != nil {
		t.Fatal("sealed archive history mutation name failed")
	}
	return sealedArchiveV8File{Name: name, Bytes: raw}
}

func sealedArchiveConcreteDecodeV8(name string, raw []byte) error {
	switch name {
	case "frozen-sources":
		var value archiveFrozenSourcesV1
		return sealedArchiveDecode(raw, false, int(sealedArchiveObjectMaxBytes), &value)
	case "meta":
		var value archiveMetaV2
		return sealedArchiveDecode(raw, true, sealedArchiveMetaMaxBytes, &value)
	case "intent-core":
		var value archiveIntentCoreV1
		return sealedArchiveDecode(raw, false, sealedArchiveIntentMaxBytes, &value)
	case "intent-payload":
		var value archiveIntentPayloadV1
		return sealedArchiveDecode(raw, false, sealedArchiveIntentMaxBytes, &value)
	case "intent-envelope":
		var value archiveIntentEnvelopeV1
		return sealedArchiveDecode(raw, true, sealedArchiveIntentMaxBytes, &value)
	case "candidate-payload":
		var value archiveCandidatePayloadV1
		return sealedArchiveDecode(raw, false, int(sealedArchiveObjectMaxBytes), &value)
	case "candidate-envelope":
		var value archiveCandidateEnvelopeV1
		return sealedArchiveDecode(raw, true, int(sealedArchiveObjectMaxBytes), &value)
	case "genesis-payload":
		var value archiveGenesisPayloadV1
		return sealedArchiveDecode(raw, false, int(sealedArchiveObjectMaxBytes), &value)
	case "genesis-envelope":
		var value archiveGenesisEnvelopeV1
		return sealedArchiveDecode(raw, true, int(sealedArchiveObjectMaxBytes), &value)
	case "receipt-payload":
		var value archiveReceiptPayloadV2
		return sealedArchiveDecode(raw, false, sealedArchiveReceiptMaxBytes, &value)
	case "receipt-envelope":
		var value archiveReceiptEnvelopeV1
		return sealedArchiveDecode(raw, true, sealedArchiveReceiptMaxBytes, &value)
	case "history-payload":
		var value archiveHistoryPayloadV1
		return sealedArchiveDecode(raw, false, int(sealedArchiveObjectMaxBytes), &value)
	case "history-envelope":
		var value archiveHistoryEnvelopeV1
		return sealedArchiveDecode(raw, true, int(sealedArchiveObjectMaxBytes), &value)
	default:
		return sealedArchiveFail(CodeArchiveInvalid)
	}
}

func sealedArchiveObjectMutationsV8(raw []byte, objectStart int) [][]byte {
	if objectStart < 0 || objectStart >= len(raw) || raw[objectStart] != '{' || objectStart+2 >= len(raw) || raw[objectStart+1] != '"' {
		return nil
	}
	colonRelative := bytes.IndexByte(raw[objectStart+1:], ':')
	if colonRelative < 2 {
		return nil
	}
	colon := objectStart + 1 + colonRelative
	key := append([]byte{}, raw[objectStart+2:colon-1]...)
	valueStart := colon + 1
	depth := 0
	inString := false
	escaped := false
	valueEnd := -1
	fieldEnd := -1
	for i := valueStart; i < len(raw); i++ {
		character := raw[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == '"' {
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				valueEnd = i
				fieldEnd = i
				i = len(raw)
			} else {
				depth--
			}
		case ',':
			if depth == 0 {
				valueEnd = i
				fieldEnd = i + 1
				i = len(raw)
			}
		}
	}
	if valueEnd < valueStart || fieldEnd <= objectStart+1 {
		return nil
	}
	insert := func(value []byte) []byte {
		result := append([]byte{}, raw[:objectStart+1]...)
		result = append(result, value...)
		return append(result, raw[objectStart+1:]...)
	}
	unknown := insert([]byte(`"unknown":0,`))
	duplicateField := append(append([]byte{'"'}, key...), []byte(`":0,`)...)
	duplicate := insert(duplicateField)
	missing := append([]byte{}, raw[:objectStart+1]...)
	missing = append(missing, raw[fieldEnd:]...)
	nullValue := append([]byte{}, raw[:valueStart]...)
	nullValue = append(nullValue, []byte("null")...)
	nullValue = append(nullValue, raw[valueEnd:]...)
	return [][]byte{unknown, duplicate, missing, nullValue}
}

func sealedArchiveBase64LexicalMutationsV8(raw, decoded []byte) [][]byte {
	encoded := []byte(base64.StdEncoding.EncodeToString(decoded))
	if len(encoded) < 2 || !bytes.Contains(raw, encoded) {
		return nil
	}
	url := append([]byte{}, encoded...)
	url[0] = '_'
	unpadded := bytes.TrimRight(encoded, "=")
	if bytes.Equal(unpadded, encoded) {
		unpadded = encoded[:len(encoded)-1]
	}
	whitespace := append(append([]byte{}, encoded[:1]...), append([]byte{' '}, encoded[1:]...)...)
	extraPadding := append(append([]byte{}, encoded...), '=')
	result := make([][]byte, 0, 5)
	for _, replacement := range [][]byte{[]byte("***"), url, unpadded, whitespace, extraPadding} {
		result = append(result, bytes.Replace(raw, encoded, replacement, 1))
	}
	return result
}

func sealedArchiveOneByteStringV8(t *testing.T, value string, index int) string {
	t.Helper()
	if index < 0 || index >= len(value) || value[index] >= utf8.RuneSelf {
		t.Fatal("sealed archive one-byte string mutation input is invalid")
	}
	result := []byte(value)
	if result[index] == '0' {
		result[index] = '1'
	} else {
		result[index] = '0'
	}
	differences := 0
	for i := range result {
		if result[i] != value[i] {
			differences++
		}
	}
	if len(result) != len(value) || differences != 1 {
		t.Fatal("sealed archive string mutation was not exactly one byte")
	}
	return string(result)
}

func sealedArchiveOneByteBytesV8(t *testing.T, value []byte, index int) []byte {
	t.Helper()
	if index < 0 || index >= len(value) {
		t.Fatal("sealed archive one-byte byte-slice mutation input is invalid")
	}
	result := append([]byte{}, value...)
	result[index] ^= 1
	differences := 0
	for i := range result {
		if result[i] != value[i] {
			differences++
		}
	}
	if len(result) != len(value) || differences != 1 {
		t.Fatal("sealed archive byte-slice mutation was not exactly one byte")
	}
	return result
}

func sealedArchiveCompareRecord(t *testing.T, actual []byte, record sealedArchiveGoldenRecord) {
	t.Helper()
	if !bytes.Equal(actual, sealedArchiveGoldenBytes(t, record)) {
		t.Fatal("sealed archive output differs from the frozen golden")
	}
}

func TestSealedArchiveV8FullChainGolden(t *testing.T) {
	input, golden := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	plan, err := buildSealedArchiveV8(input)
	if err != nil {
		t.Fatal("sealed archive full-chain build failed")
	}
	objects := golden.ValidFullChain.Objects
	sealedArchiveCompareRecord(t, plan.Meta.Bytes, objects.Meta)
	sealedArchiveCompareRecord(t, plan.Intent.Bytes, objects.IntentEnvelope)
	if len(plan.Candidates) != 1 {
		t.Fatal("sealed archive candidate count differs from the frozen golden")
	}
	sealedArchiveCompareRecord(t, plan.Candidates[0].Bytes, objects.CandidateEnvelopes[0])
	sealedArchiveCompareRecord(t, plan.Genesis.Bytes, objects.GenesisEnvelope)
	sealedArchiveCompareRecord(t, plan.Receipt.Bytes, objects.ReceiptEnvelope)
	derived := golden.ValidFullChain.Derived
	if plan.Identity.KeyID != derived.KeyID || plan.Identity.MigrationID != derived.MigrationID || plan.Identity.ArchiveEpoch != derived.ArchiveEpoch || plan.Identity.IntentReference != derived.IntentReference || plan.Identity.IntentSeal != derived.IntentSeal || plan.Identity.GenesisReference != derived.GenesisReference || plan.Identity.GenesisSeal != derived.GenesisSeal || plan.Identity.ReceiptReference != derived.ReceiptReference || plan.Identity.ReceiptSeal != derived.ReceiptSeal || plan.Identity.FrozenSourcesSHA256 != derived.FrozenSourcesSHA256 || !reflectStringsEqual(plan.Identity.CandidateReferences, derived.CandidateReferences) || !reflectStringsEqual(plan.Identity.CandidateSeals, derived.CandidateSeals) {
		t.Fatal("sealed archive identity differs from the frozen golden")
	}
	if len(derived.CandidateBasenames) != 1 || plan.Candidates[0].Name != derived.CandidateBasenames[0] || plan.Genesis.Name != derived.GenesisBasename {
		t.Fatal("sealed archive basename differs from the frozen golden")
	}
	expected := golden.ValidFullChain.Plan
	if plan.Bytes.MetaBytes != expected.SMeta || plan.Bytes.IntentBytes != expected.SIntent || !reflectUint64Equal(plan.Bytes.CandidateBytes, expected.SCandidates) || plan.Bytes.GenesisBytes != expected.SGenesis || plan.Bytes.PreReceiptFinalBytes != expected.Pre || plan.Bytes.Q != expected.Q || plan.Bytes.ReceiptBytes != expected.R || plan.Bytes.FinalBytes != expected.F || plan.Bytes.MaxTempBytes != expected.M || plan.Bytes.PeakBytes != expected.Peak || plan.Bytes.FinalEntries != expected.FinalEntries || plan.Bytes.PeakEntries != expected.PeakEntries {
		t.Fatal("sealed archive byte plan differs from the frozen golden")
	}
	if validateSealedArchiveV8Plan(plan) != nil {
		t.Fatal("sealed archive full-chain validation failed")
	}
	sealedArchiveAssertPayloadRecords(t, plan, golden)
	sealedArchiveAssertPublicInputs(t, input, golden)
	var source storeSnapshot
	if storeDecode(input.OriginalV1, &source) != nil {
		t.Fatal("sealed archive privacy fixture decode failed")
	}
	sentinels := [][]byte{
		[]byte(base64.StdEncoding.EncodeToString(input.ArchiveKey)),
		[]byte(base64.StdEncoding.EncodeToString(input.Nonce)),
		[]byte(base64.StdEncoding.EncodeToString(source.IdentityKey)),
		source.Candidates[0].Raw,
		[]byte(source.Candidates[0].Nodes[0].PrivateName),
		source.Candidates[0].Nodes[0].Config,
	}
	for _, sentinel := range sentinels {
		if len(sentinel) != 0 && bytes.Contains(plan.Receipt.Bytes, sentinel) {
			t.Fatal("sealed archive receipt exposed a private sentinel")
		}
	}
}

func sealedArchiveAssertPublicInputs(t *testing.T, input sealedArchiveV8Input, golden sealedArchiveGoldenV8) {
	t.Helper()
	public := golden.ValidFullChain.PublicInputs
	if hex.EncodeToString(input.ArchiveKey) != public.ArchiveKeyHex || hex.EncodeToString(input.Nonce) != public.NonceHex || input.ObservedAt != public.ObservedAt || len(public.EmbeddedV1Times) != 2 {
		t.Fatal("sealed archive public inputs differ from the frozen golden")
	}
	var state storeSnapshot
	if storeDecode(input.OriginalV1, &state) != nil || hex.EncodeToString(state.IdentityKey) != public.MainIdentityKeyHex || string(state.Candidates[0].Raw) != public.CandidateRawUTF8 || state.Audit[0].At.Format(time.RFC3339Nano) != public.EmbeddedV1Times[0] || state.Audit[1].At.Format(time.RFC3339Nano) != public.EmbeddedV1Times[1] {
		t.Fatal("sealed archive source-backed public inputs differ")
	}
	childID, err := sealedArchiveAbsenceChildID(public.RefreshAbsenceChildName)
	if err != nil || input.FrozenSources.Refresh.Absence == nil || childID != input.FrozenSources.Refresh.Absence.ChildNameID {
		t.Fatal("sealed archive absence-child vector differs")
	}
	entrySets := []struct {
		encoded  string
		expected string
	}{
		{public.EvidenceEntrySetBase64, input.FrozenSources.Evidence.Root.EntrySetSHA256},
		{public.MainEntrySetBase64, input.FrozenSources.Main.Root.EntrySetSHA256},
	}
	for _, entrySet := range entrySets {
		raw, decodeErr := base64.StdEncoding.DecodeString(entrySet.encoded)
		framed, frameErr := sealedArchiveFrame("chengwang/archive/source-entry-set/v1", raw)
		digest := sha256.Sum256(framed)
		if decodeErr != nil || frameErr != nil || hex.EncodeToString(digest[:]) != entrySet.expected {
			t.Fatal("sealed archive source entry-set vector differs")
		}
	}
	checkpoint := []byte(public.EvidenceCheckpointUTF8)
	checkpointDigest := sha256.Sum256(checkpoint)
	if uint64(len(checkpoint)) != input.FrozenSources.Evidence.Checkpoint.Length || hex.EncodeToString(checkpointDigest[:]) != input.FrozenSources.Evidence.Checkpoint.SHA256 {
		t.Fatal("sealed archive evidence checkpoint vector differs")
	}
}

func sealedArchiveAssertPayloadRecords(t *testing.T, plan sealedArchiveV8Plan, golden sealedArchiveGoldenV8) {
	t.Helper()
	var intent archiveIntentEnvelopeV1
	var candidate archiveCandidateEnvelopeV1
	var genesis archiveGenesisEnvelopeV1
	var receipt archiveReceiptEnvelopeV1
	if sealedArchiveDecode(plan.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &intent) != nil || sealedArchiveDecode(plan.Candidates[0].Bytes, true, int(sealedArchiveObjectMaxBytes), &candidate) != nil || sealedArchiveDecode(plan.Genesis.Bytes, true, int(sealedArchiveObjectMaxBytes), &genesis) != nil || sealedArchiveDecode(plan.Receipt.Bytes, true, sealedArchiveReceiptMaxBytes, &receipt) != nil {
		t.Fatal("sealed archive concrete envelope decode failed")
	}
	objects := golden.ValidFullChain.Objects
	coreRaw, _ := sealedArchiveCanonical(intent.Payload.Core)
	intentPayload, _ := sealedArchiveCanonical(intent.Payload)
	candidatePayload, _ := sealedArchiveCanonical(candidate.Payload)
	genesisPayload, _ := sealedArchiveCanonical(genesis.Payload)
	receiptPayload, _ := sealedArchiveCanonical(receipt.Payload)
	frozenSources, _ := sealedArchiveCanonical(intent.Payload.Core.FrozenSources)
	placeholderPayload := receipt.Payload
	placeholderPayload.Bytes = archiveReceiptBytesV2{
		PreReceiptFinalBytes: receipt.Payload.Bytes.PreReceiptFinalBytes,
		ReceiptBytesHex:      strings.Repeat("0", 16), FinalBytesHex: strings.Repeat("0", 16),
		MaxTempBytesHex: strings.Repeat("0", 16), PeakBytesHex: strings.Repeat("0", 16),
	}
	placeholder, _ := sealedArchivePersisted(archiveReceiptEnvelopeV1{
		Schema: sealedArchiveReceiptSchemaV8, Kind: sealedArchiveReceiptKindV1,
		Reference: strings.Repeat("0", 64), Payload: placeholderPayload, Seal: strings.Repeat("0", 64),
	}, sealedArchiveReceiptMaxBytes)
	sealedArchiveCompareRecord(t, coreRaw, objects.IntentCore)
	sealedArchiveCompareRecord(t, intentPayload, objects.IntentPayload)
	sealedArchiveCompareRecord(t, candidatePayload, objects.CandidatePayloads[0])
	sealedArchiveCompareRecord(t, genesisPayload, objects.GenesisPayload)
	sealedArchiveCompareRecord(t, receiptPayload, objects.ReceiptPayload)
	sealedArchiveCompareRecord(t, frozenSources, objects.FrozenSources)
	sealedArchiveCompareRecord(t, placeholder, objects.ReceiptPlaceholderEnvelope)
}

func reflectStringsEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func reflectUint64Equal(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestSealedArchiveV8BudgetFixedPoint(t *testing.T) {
	input, golden := sealedArchiveGoldenInputV8(t, 18440)
	plan, err := buildSealedArchiveV8(input)
	if err != nil {
		t.Fatal("sealed archive exact budget fixed point was rejected")
	}
	expected := golden.CalculatedNegatives.Budget.MinimalAcceptedFixedPoint
	if expected.ArchiveMaxBytes != 18440 || plan.Bytes.PreReceiptFinalBytes != expected.Plan.Pre || plan.Bytes.Q != expected.Plan.Q || plan.Bytes.ReceiptBytes != expected.Plan.R || plan.Bytes.FinalBytes != expected.Plan.F || plan.Bytes.MaxTempBytes != expected.Plan.M || plan.Bytes.PeakBytes != expected.Plan.Peak || plan.Identity.ReceiptReference != expected.ReceiptReference {
		t.Fatal("sealed archive exact budget fixed point differs from the frozen golden")
	}
	var intent archiveIntentEnvelopeV1
	if sealedArchiveDecode(plan.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &intent) != nil {
		t.Fatal("sealed archive fixed-point intent decode failed")
	}
	coreRaw, _ := sealedArchiveCanonical(intent.Payload.Core)
	digest := sha256.Sum256(coreRaw)
	if hex.EncodeToString(digest[:]) != expected.IntentCoreSHA256 {
		t.Fatal("sealed archive fixed-point core digest differs from the frozen golden")
	}
	input.Budget.ArchiveMaxBytes = 18439
	_, err = buildSealedArchiveV8(input)
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
	if golden.CalculatedNegatives.Budget.OneBelow.ArchiveMaxBytes != 18439 || golden.CalculatedNegatives.Budget.OneBelow.WouldBePeak != 18440 || expected.Plan.F > 18439 || expected.Plan.Peak != 18440 {
		t.Fatal("sealed archive one-below fixture is invalid")
	}
	if _, err := sealedArchiveCheckedAdd(^uint64(0), 1); err == nil {
		t.Fatal("sealed archive checked addition accepted overflow")
	}
	_, err = sealedArchiveReference(make([]byte, 32), sealedArchiveCandidateSchemaV8, sealedArchiveCandidateKindV1, make([]byte, int(sealedArchiveObjectMaxBytes)+1))
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
	zeroBudget := sealedArchiveDefaultBudgetV8(0)
	sealedArchiveRequireCode(t, sealedArchiveValidateBudget(zeroBudget), CodeArchiveLimit)
	overBudget := sealedArchiveDefaultBudgetV8(sealedArchiveMaxBytes + 1)
	sealedArchiveRequireCode(t, sealedArchiveValidateBudget(overBudget), CodeArchiveLimit)
	boundaryBudget := sealedArchiveDefaultBudgetV8(100)
	if sealedArchiveValidateByteLimitsV8(100, 100, boundaryBudget) != nil || sealedArchiveValidateByteLimitsV8(90, 100, boundaryBudget) != nil {
		t.Fatal("sealed archive rejected an exact F or Peak budget fit")
	}
	// A valid fixed point always has Peak >= F, so the shared production helper
	// is called directly with an intentionally isolated F-over boundary.
	sealedArchiveRequireCode(t, sealedArchiveValidateByteLimitsV8(101, 100, boundaryBudget), CodeArchiveLimit)
	sealedArchiveRequireCode(t, sealedArchiveValidateByteLimitsV8(90, 101, boundaryBudget), CodeArchiveLimit)
	if sealedArchiveMaxTempV8(100, 99) != 100 || sealedArchiveMaxTempV8(99, 100) != 100 || sealedArchiveMaxTempV8(100, 100) != 100 {
		t.Fatal("sealed archive max-temp Q/R boundary failed")
	}
	// Candidate 65 implies final 70 and peak 71 in the fixed A1 layout, so
	// those three invalid boundaries are not independently reachable through
	// a valid receipt. The shared production limit helper proves each gate.
	sealedArchiveRequireCode(t, sealedArchiveValidateEntryLimitsV8(65, 69, 70, sealedArchiveDefaultBudgetV8(sealedArchiveMaxBytes)), CodeArchiveLimit)
	sealedArchiveRequireCode(t, sealedArchiveValidateEntryLimitsV8(64, 70, 70, sealedArchiveDefaultBudgetV8(sealedArchiveMaxBytes)), CodeArchiveLimit)
	sealedArchiveRequireCode(t, sealedArchiveValidateEntryLimitsV8(64, 69, 71, sealedArchiveDefaultBudgetV8(sealedArchiveMaxBytes)), CodeArchiveLimit)
}

func TestSealedArchiveV8PrimitiveAndNameBoundaries(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyID, kref, kseal, err := sealedArchiveKeys(key)
	if err != nil || keyID != "b23449188d711441f7a168a4c1b5b7068a65cd7d579d9b2365a1356b14db7c63" || hex.EncodeToString(kref) != "828cee68df3f2399635381f826b576459f3e8a8d8c38b6d80cf733970d598a36" || hex.EncodeToString(kseal) != "030d1081b36a94ec0053b084ff294080fbee49433ae3aa4f0d59b8efcc56d2a2" {
		t.Fatal("sealed archive public key vectors differ")
	}
	for _, size := range []int{255, 256, 65535, 65536} {
		payload := bytes.Repeat([]byte{'x'}, size)
		framed, frameErr := sealedArchiveFrame("chengwang/archive/reference/v1", []byte(sealedArchiveCandidateSchemaV8), []byte(sealedArchiveCandidateKindV1), payload)
		lengthOffset := len(framed) - size - 4
		if frameErr != nil || len(framed) != 4+len("chengwang/archive/reference/v1")+4+len(sealedArchiveCandidateSchemaV8)+4+len(sealedArchiveCandidateKindV1)+4+size || binary.BigEndian.Uint32(framed[lengthOffset:lengthOffset+4]) != uint32(size) {
			t.Fatal("sealed archive U32 frame boundary failed")
		}
	}
	if _, err := sealedArchiveFrame("chengwang/archive/subkey/v1", []byte("wrong")); err == nil {
		t.Fatal("sealed archive accepted an unknown subkey label")
	}
	if _, err := sealedArchiveFrame("unknown", []byte{}); err == nil {
		t.Fatal("sealed archive accepted an unknown frame domain")
	}
	_, err = sealedArchiveFrame("chengwang/archive/reference/v2", []byte(sealedArchiveCandidateSchemaV8), []byte(sealedArchiveCandidateKindV1), []byte{})
	sealedArchiveRequireCode(t, err, CodeArchiveInvalid)
	_, err = sealedArchiveFrame("chengwang/archive/key-id/v1")
	sealedArchiveRequireCode(t, err, CodeArchiveInvalid)
	_, err = sealedArchiveFrame("chengwang/archive/reference/v1", bytes.Repeat([]byte{'s'}, 129), []byte(sealedArchiveCandidateKindV1), []byte{})
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
	_, err = sealedArchiveFrame("chengwang/archive/source-entry-set/v1", bytes.Repeat([]byte{'x'}, 4097))
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
	_, err = sealedArchiveScanJSON(bytes.Repeat([]byte{'x'}, sealedArchiveMetaMaxBytes+1), true, sealedArchiveMetaMaxBytes)
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
	depthBoundary := []byte(strings.Repeat("[", sealedArchiveDepthMax) + "0" + strings.Repeat("]", sealedArchiveDepthMax))
	if _, err := sealedArchiveScanJSON(depthBoundary, false, int(sealedArchiveObjectMaxBytes)); err != nil {
		t.Fatal("sealed archive rejected the exact depth boundary")
	}
	depthOver := []byte(strings.Repeat("[", sealedArchiveDepthMax+1) + "0" + strings.Repeat("]", sealedArchiveDepthMax+1))
	sealedArchiveRequireCode(t, func() error {
		_, scanErr := sealedArchiveScanJSON(depthOver, false, int(sealedArchiveObjectMaxBytes))
		return scanErr
	}(), CodeArchiveLimit)
	stringBoundary := []byte(`"` + strings.Repeat("s", sealedArchiveStringMax) + `"`)
	if _, err := sealedArchiveScanJSON(stringBoundary, false, int(sealedArchiveObjectMaxBytes)); err != nil {
		t.Fatal("sealed archive rejected the exact string boundary")
	}
	stringOver := []byte(`"` + strings.Repeat("s", sealedArchiveStringMax+1) + `"`)
	sealedArchiveRequireCode(t, func() error {
		_, scanErr := sealedArchiveScanJSON(stringOver, false, int(sealedArchiveObjectMaxBytes))
		return scanErr
	}(), CodeArchiveLimit)
	tokenBoundary := []byte("[" + strings.Repeat("0,", sealedArchiveTokenMax-3) + "0]")
	if _, err := sealedArchiveScanJSON(tokenBoundary, false, int(sealedArchiveObjectMaxBytes)); err != nil {
		t.Fatal("sealed archive rejected the exact token boundary")
	}
	tokenOver := append(append([]byte{}, tokenBoundary[:len(tokenBoundary)-1]...), ',', '0', ']')
	sealedArchiveRequireCode(t, func() error {
		_, scanErr := sealedArchiveScanJSON(tokenOver, false, int(sealedArchiveObjectMaxBytes))
		return scanErr
	}(), CodeArchiveLimit)
	reference := strings.Repeat("a", 64)
	name, err := sealedArchiveContentName(sealedArchiveCandidateKindV1, reference)
	parsed, parseErr := sealedArchiveParseNameV8(name)
	parsedTemp, tempErr := sealedArchiveParseNameV8("." + name + ".tmp")
	if err != nil || parseErr != nil || tempErr != nil || parsed.Class != sealedArchiveNameContentV8 || parsed.Kind != sealedArchiveCandidateKindV1 || parsed.Reference != reference || parsed.Temporary || parsedTemp.Class != parsed.Class || parsedTemp.Kind != parsed.Kind || parsedTemp.Reference != parsed.Reference || !parsedTemp.Temporary {
		t.Fatal("sealed archive safe-name round trip failed")
	}
	fixedNames := []struct {
		name      string
		class     sealedArchiveNameClassV8
		kind      string
		temporary bool
	}{
		{"archive.meta", sealedArchiveNameMetaV8, "", false},
		{".archive.meta.tmp", sealedArchiveNameMetaV8, "", true},
		{"archive.lock", sealedArchiveNameLockV8, "", false},
		{"migration.intent.json", sealedArchiveNameIntentV8, sealedArchiveIntentKindV1, false},
		{".migration.intent.json.tmp", sealedArchiveNameIntentV8, sealedArchiveIntentKindV1, true},
		{"shadow.receipt.json", sealedArchiveNameReceiptV8, sealedArchiveReceiptKindV1, false},
		{".shadow.receipt.json.tmp", sealedArchiveNameReceiptV8, sealedArchiveReceiptKindV1, true},
	}
	for _, expected := range fixedNames {
		actual, fixedErr := sealedArchiveParseNameV8(expected.name)
		if fixedErr != nil || actual.Class != expected.class || actual.Kind != expected.kind || actual.Reference != "" || actual.Temporary != expected.temporary {
			t.Fatal("sealed archive fixed-name parser round trip failed")
		}
	}
	for _, kind := range []string{sealedArchiveCandidateKindV1, sealedArchiveGenesisKindV1, sealedArchiveHistoryKindV1} {
		contentName, contentErr := sealedArchiveContentName(kind, reference)
		content, contentParseErr := sealedArchiveParseNameV8(contentName)
		if contentErr != nil || contentParseErr != nil || content.Class != sealedArchiveNameContentV8 || content.Kind != kind || content.Reference != reference || content.Temporary {
			t.Fatal("sealed archive content-name parser round trip failed")
		}
	}
	for _, unsafe := range []string{
		"candidate/v1-" + reference + ".json",
		"candidate-v1\\" + reference + ".json",
		name + "\x1f",
		"candidate-v1-" + reference[:63] + ".json",
		"candidate-v1-" + reference + "0.json",
		"candidate-v1-g" + reference[1:] + ".json",
		"candidate-v1-" + reference + ".txt",
		"prefix-" + name,
		name + "-suffix",
		"archive.meta.json",
		"migration.intent.v2.json",
		"../" + name,
		strings.ToUpper(name),
		".archive.lock.tmp",
		"." + name + ".tmp.tmp",
		"unknown.json",
		".",
		"..",
		"\x00",
		"é",
		strings.Repeat("a", 256),
	} {
		sealedArchiveRequireCode(t, sealedArchiveValidateSafeName(unsafe), CodeArchiveNameUnsafe)
	}
	for _, unsafeChild := range []string{"", ".", "..", "a/b", "a\\b", "\x00", "line\nfeed", strings.Repeat("a", 256)} {
		if sealedArchiveValidChildName(unsafeChild) {
			t.Fatal("sealed archive accepted an unsafe source child")
		}
	}
	for _, validTime := range []string{"2026-11-02T12:34:56Z", "2026-11-02T12:34:56.123456789Z", "9999-12-31T23:59:59.999999999Z"} {
		if sealedArchiveValidateObservedAt(validTime) != nil {
			t.Fatal("sealed archive rejected a canonical archive time")
		}
	}
	for _, invalidTime := range []string{"0001-01-01T00:00:00Z", "2026-11-02T12:34:56+00:00", "2026-11-02T12:34:56.0Z", "2026-11-02T12:34:56.100Z", "2026-11-02T12:34:56z", "2026-11-02T12:34:60Z", "2026-11-02 12:34:56Z", "2026-11-02T12:34:56.1234567890Z"} {
		if sealedArchiveValidateObservedAt(invalidTime) == nil {
			t.Fatal("sealed archive accepted a noncanonical archive time")
		}
	}
}

func TestSealedArchiveV8StrictCanonicalAndAuthentication(t *testing.T) {
	input, golden := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	plan, err := buildSealedArchiveV8(input)
	if err != nil {
		t.Fatal("sealed archive canonical fixture build failed")
	}
	metaPrefix := []byte(`{"schema":"chengwang.subscription-archive-meta/v2","formatVersion":2,`)
	reorderedMetaPrefix := []byte(`{"formatVersion":2,"schema":"chengwang.subscription-archive-meta/v2",`)
	archiveKeyBase64 := []byte(base64.StdEncoding.EncodeToString(input.ArchiveKey))
	base64URL := append([]byte{}, archiveKeyBase64...)
	base64URL[0] = '_'
	base64Unpadded := bytes.TrimSuffix(archiveKeyBase64, []byte("="))
	base64Whitespace := append(append([]byte{}, archiveKeyBase64[:4]...), append([]byte{' '}, archiveKeyBase64[4:]...)...)
	base64ExtraPadding := append(append([]byte{}, archiveKeyBase64...), '=')
	base64WrongLength := []byte(base64.StdEncoding.EncodeToString(input.ArchiveKey[:len(input.ArchiveKey)-1]))
	cases := []struct {
		name string
		edit func(sealedArchiveV8Plan) sealedArchiveV8Plan
		code Code
	}{
		{"bom", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append([]byte{0xef, 0xbb, 0xbf}, value.Meta.Bytes...)
			return value
		}, CodeArchiveInvalid},
		{"missing-lf", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append([]byte{}, value.Meta.Bytes[:len(value.Meta.Bytes)-1]...)
			return value
		}, CodeArchiveInvalid},
		{"double-lf", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append(append([]byte{}, value.Meta.Bytes...), '\n')
			return value
		}, CodeArchiveInvalid},
		{"trailing", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append(append([]byte{}, value.Meta.Bytes...), 'x')
			return value
		}, CodeArchiveInvalid},
		{"whitespace", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append(append([]byte{}, value.Meta.Bytes[:len(value.Meta.Bytes)-1]...), ' ', '\n')
			return value
		}, CodeArchiveInvalid},
		{"field-order", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, metaPrefix, reorderedMetaPrefix, 1)
			return value
		}, CodeArchiveInvalid},
		{"missing", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, metaPrefix, []byte(`{"formatVersion":2,`), 1)
			return value
		}, CodeArchiveInvalid},
		{"unknown", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append([]byte(`{"unknown":0,`), value.Meta.Bytes[1:]...)
			return value
		}, CodeArchiveInvalid},
		{"duplicate", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append([]byte(`{"schema":"chengwang.subscription-archive-meta/v2",`), value.Meta.Bytes[1:]...)
			return value
		}, CodeArchiveInvalid},
		{"null", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var meta archiveMetaV2
			_ = sealedArchiveDecode(value.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta)
			meta.ArchiveKey = nil
			value.Meta.Bytes, _ = sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
			return value
		}, CodeArchiveInvalid},
		{"integer", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, []byte(`"formatVersion":2`), []byte(`"formatVersion":2.0`), 1)
			return value
		}, CodeArchiveInvalid},
		{"integer-exponent", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, []byte(`"formatVersion":2`), []byte(`"formatVersion":2e0`), 1)
			return value
		}, CodeArchiveInvalid},
		{"integer-leading-zero", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, []byte(`"formatVersion":2`), []byte(`"formatVersion":02`), 1)
			return value
		}, CodeArchiveInvalid},
		{"integer-negative", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, []byte(`"formatVersion":2`), []byte(`"formatVersion":-1`), 1)
			return value
		}, CodeArchiveInvalid},
		{"integer-overflow", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, []byte(`"formatVersion":2`), []byte(`"formatVersion":4294967296`), 1)
			return value
		}, CodeArchiveInvalid},
		{"base64", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, archiveKeyBase64, []byte("***"), 1)
			return value
		}, CodeArchiveInvalid},
		{"base64url", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, archiveKeyBase64, base64URL, 1)
			return value
		}, CodeArchiveInvalid},
		{"base64-unpadded", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, archiveKeyBase64, base64Unpadded, 1)
			return value
		}, CodeArchiveInvalid},
		{"base64-whitespace", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, archiveKeyBase64, base64Whitespace, 1)
			return value
		}, CodeArchiveInvalid},
		{"base64-padding", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, archiveKeyBase64, base64ExtraPadding, 1)
			return value
		}, CodeArchiveInvalid},
		{"base64-wrong-length", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = bytes.Replace(value.Meta.Bytes, archiveKeyBase64, base64WrongLength, 1)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"invalid-utf8", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			value.Meta.Bytes = append([]byte{}, value.Meta.Bytes...)
			value.Meta.Bytes[1] = 0xff
			return value
		}, CodeArchiveInvalid},
		{"schema", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Schema = "unknown/v2"
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveKindUnsupported},
		{"kind", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Kind = "unknown/v1"
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveKindUnsupported},
		{"schema-one-byte", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Schema = sealedArchiveOneByteStringV8(t, envelope.Schema, len(envelope.Schema)-1)
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveKindUnsupported},
		{"kind-one-byte", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Kind = sealedArchiveOneByteStringV8(t, envelope.Kind, len(envelope.Kind)-1)
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveKindUnsupported},
		{"archive-key", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var meta archiveMetaV2
			_ = sealedArchiveDecode(value.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta)
			meta.ArchiveKey[0] ^= 1
			value.Meta.Bytes, _ = sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"key-id-hex", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var meta archiveMetaV2
			_ = sealedArchiveDecode(value.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta)
			meta.KeyID = strings.ToUpper(meta.KeyID)
			value.Meta.Bytes, _ = sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"key-id-short", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var meta archiveMetaV2
			_ = sealedArchiveDecode(value.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta)
			meta.KeyID = meta.KeyID[:63]
			value.Meta.Bytes, _ = sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"key-id-long", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var meta archiveMetaV2
			_ = sealedArchiveDecode(value.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta)
			meta.KeyID += "0"
			value.Meta.Bytes, _ = sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"key-id-nonhex", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var meta archiveMetaV2
			_ = sealedArchiveDecode(value.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta)
			meta.KeyID = "g" + meta.KeyID[1:]
			value.Meta.Bytes, _ = sealedArchivePersisted(meta, sealedArchiveMetaMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"payload", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveCandidateEnvelopeV1
			_ = sealedArchiveDecode(value.Candidates[0].Bytes, true, int(sealedArchiveObjectMaxBytes), &envelope)
			envelope.Payload.Candidate.Raw[0] ^= 1
			value.Candidates[0].Bytes, _ = sealedArchivePersisted(envelope, int(sealedArchiveObjectMaxBytes))
			return value
		}, CodeArchiveAuthenticationFailed},
		{"reference", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Reference = strings.ToUpper(envelope.Reference)
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"reference-one-byte", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Reference = sealedArchiveOneByteStringV8(t, envelope.Reference, 0)
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"reference-short", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Reference = envelope.Reference[:63]
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"reference-long", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Reference += "0"
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"reference-nonhex", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Reference = "g" + envelope.Reference[1:]
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"seal", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Seal = strings.Repeat("0", 64)
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"seal-one-byte", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Seal = sealedArchiveOneByteStringV8(t, envelope.Seal, 0)
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"seal-short", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Seal = envelope.Seal[:63]
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"seal-long", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Seal += "0"
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
		{"seal-nonhex", func(value sealedArchiveV8Plan) sealedArchiveV8Plan {
			var envelope archiveIntentEnvelopeV1
			_ = sealedArchiveDecode(value.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &envelope)
			envelope.Seal = "g" + envelope.Seal[1:]
			value.Intent.Bytes, _ = sealedArchivePersisted(envelope, sealedArchiveIntentMaxBytes)
			return value
		}, CodeArchiveAuthenticationFailed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mutated := test.edit(sealedArchiveClonePlanV8(plan))
			sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(mutated), test.code)
		})
	}
	var meta archiveMetaV2
	var intent archiveIntentEnvelopeV1
	if sealedArchiveDecode(plan.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta) != nil || sealedArchiveDecode(plan.Intent.Bytes, true, sealedArchiveIntentMaxBytes, &intent) != nil {
		t.Fatal("sealed archive semantic mutation fixture decode failed")
	}
	keyID, kref, kseal, err := sealedArchiveKeys(meta.ArchiveKey)
	if err != nil {
		t.Fatal("sealed archive semantic mutation keys failed")
	}
	budget := sealedArchiveDefaultBudgetV8(meta.ArchiveMaxBytes)
	semantic := []struct {
		name string
		code Code
		edit func(*archiveIntentPayloadV1)
	}{
		{"source-revision", CodeArchiveConflict, func(value *archiveIntentPayloadV1) {
			value.Core.SourceRevision.RepositoryCommit = strings.Repeat("0", 40)
		}},
		{"source-revision-commit-one-byte", CodeArchiveConflict, func(value *archiveIntentPayloadV1) {
			value.Core.SourceRevision.RepositoryCommit = sealedArchiveOneByteStringV8(t, value.Core.SourceRevision.RepositoryCommit, 0)
		}},
		{"source-revision-tree-one-byte", CodeArchiveConflict, func(value *archiveIntentPayloadV1) {
			value.Core.SourceRevision.RepositoryTree = sealedArchiveOneByteStringV8(t, value.Core.SourceRevision.RepositoryTree, 0)
		}},
		{"source-revision-codec-set-one-byte", CodeArchiveConflict, func(value *archiveIntentPayloadV1) {
			value.Core.SourceRevision.CodecSetSHA256 = sealedArchiveOneByteStringV8(t, value.Core.SourceRevision.CodecSetSHA256, 0)
		}},
		{"codec", CodeArchiveConflict, func(value *archiveIntentPayloadV1) { value.Core.CodecID = "unknown" }},
		{"codec-one-byte", CodeArchiveConflict, func(value *archiveIntentPayloadV1) {
			value.Core.CodecID = sealedArchiveOneByteStringV8(t, value.Core.CodecID, 0)
		}},
		{"policy", CodeArchiveConflict, func(value *archiveIntentPayloadV1) { value.Core.PolicyID = "unknown" }},
		{"policy-one-byte", CodeArchiveConflict, func(value *archiveIntentPayloadV1) {
			value.Core.PolicyID = sealedArchiveOneByteStringV8(t, value.Core.PolicyID, 0)
		}},
		{"budget", CodeArchiveConflict, func(value *archiveIntentPayloadV1) { value.Core.Budget.CandidateMax-- }},
		{"nonce", CodeArchiveConflict, func(value *archiveIntentPayloadV1) { value.Core.Nonce = []byte{1} }},
		{"nonce-one-byte", CodeArchiveAuthenticationFailed, func(value *archiveIntentPayloadV1) {
			value.Core.Nonce = sealedArchiveOneByteBytesV8(t, value.Core.Nonce, 0)
		}},
		{"time", CodeArchiveInvalid, func(value *archiveIntentPayloadV1) { value.Core.ObservedAt = "2026-11-02T12:34:56+00:00" }},
		{"time-one-byte", CodeArchiveInvalid, func(value *archiveIntentPayloadV1) {
			value.Core.ObservedAt = sealedArchiveOneByteStringV8(t, value.Core.ObservedAt, len(value.Core.ObservedAt)-1)
		}},
		{"migration-id", CodeArchiveAuthenticationFailed, func(value *archiveIntentPayloadV1) { value.MigrationID = strings.Repeat("0", 64) }},
		{"migration-id-one-byte", CodeArchiveAuthenticationFailed, func(value *archiveIntentPayloadV1) {
			value.MigrationID = sealedArchiveOneByteStringV8(t, value.MigrationID, 0)
		}},
		{"epoch", CodeArchiveAuthenticationFailed, func(value *archiveIntentPayloadV1) { value.ArchiveEpoch = strings.Repeat("0", 64) }},
		{"epoch-one-byte", CodeArchiveAuthenticationFailed, func(value *archiveIntentPayloadV1) {
			value.ArchiveEpoch = sealedArchiveOneByteStringV8(t, value.ArchiveEpoch, 0)
		}},
	}
	for _, test := range semantic {
		t.Run(test.name, func(t *testing.T) {
			payload := intent.Payload
			payload.Core.Nonce = append([]byte{}, intent.Payload.Core.Nonce...)
			test.edit(&payload)
			raw, _, _, buildErr := sealedArchiveMakeIntentV8(kref, kseal, payload)
			if buildErr != nil {
				t.Fatal("sealed archive semantic mutation reseal failed")
			}
			var mutated archiveIntentEnvelopeV1
			if sealedArchiveDecode(raw, true, sealedArchiveIntentMaxBytes, &mutated) != nil {
				t.Fatal("sealed archive semantic mutation decode failed")
			}
			sealedArchiveRequireCode(t, sealedArchiveVerifyIntentV8(mutated, kref, kseal, keyID, budget), test.code)
		})
	}
	wrongKref := append([]byte{}, kref...)
	wrongKref[0] ^= 1
	sealedArchiveRequireCode(t, sealedArchiveVerifyEnvelopeV8(intent.Schema, intent.Kind, intent.Reference, intent.Seal, intent.Payload, wrongKref, kseal), CodeArchiveAuthenticationFailed)
	wrongKseal := append([]byte{}, kseal...)
	wrongKseal[0] ^= 1
	sealedArchiveRequireCode(t, sealedArchiveVerifyEnvelopeV8(intent.Schema, intent.Kind, intent.Reference, intent.Seal, intent.Payload, kref, wrongKseal), CodeArchiveAuthenticationFailed)
	payloadRaw, _ := sealedArchiveCanonical(intent.Payload)
	wrongSchemaReference, _ := sealedArchiveReference(kref, sealedArchiveIntentCoreSchemaV8, sealedArchiveIntentKindV1, payloadRaw)
	wrongSchemaSeal, _ := sealedArchiveSeal(kseal, sealedArchiveIntentCoreSchemaV8, sealedArchiveIntentKindV1, wrongSchemaReference, payloadRaw)
	wrongSchema := intent
	wrongSchema.Schema = sealedArchiveIntentCoreSchemaV8
	wrongSchema.Reference = wrongSchemaReference
	wrongSchema.Seal = wrongSchemaSeal
	sealedArchiveRequireCode(t, sealedArchiveVerifyIntentV8(wrongSchema, kref, kseal, keyID, budget), CodeArchiveKindUnsupported)
	var candidate archiveCandidateEnvelopeV1
	if sealedArchiveDecode(plan.Candidates[0].Bytes, true, int(sealedArchiveObjectMaxBytes), &candidate) != nil {
		t.Fatal("sealed archive typed candidate mutation decode failed")
	}
	candidatePayloadRaw, _ := sealedArchiveCanonical(candidate.Payload)
	candidate.Reference, _ = sealedArchiveReference(kref, sealedArchiveGenesisSchemaV8, sealedArchiveGenesisKindV1, candidatePayloadRaw)
	candidate.Seal, _ = sealedArchiveSeal(kseal, sealedArchiveGenesisSchemaV8, sealedArchiveGenesisKindV1, candidate.Reference, candidatePayloadRaw)
	candidate.Schema = sealedArchiveGenesisSchemaV8
	candidate.Kind = sealedArchiveGenesisKindV1
	sealedArchiveRequireCode(t, sealedArchiveVerifyCandidateV8(candidate, kref, kseal, intent.Payload.MigrationID, intent.Payload.ArchiveEpoch, 0, plan.Candidates[0].Name), CodeArchiveKindUnsupported)
	var receipt archiveReceiptEnvelopeV1
	if sealedArchiveDecode(plan.Receipt.Bytes, true, sealedArchiveReceiptMaxBytes, &receipt) != nil {
		t.Fatal("sealed archive receipt fixed-point mutation decode failed")
	}
	peak, parseErr := sealedArchiveParseHexU64(receipt.Payload.Bytes.PeakBytesHex)
	if parseErr != nil {
		t.Fatal("sealed archive receipt fixed-point mutation parse failed")
	}
	receipt.Payload.Bytes.PeakBytesHex = sealedArchiveHexU64(peak + 1)
	mutatedReceipt, _, _, buildErr := sealedArchiveMakeReceiptV8(kref, kseal, receipt.Payload)
	if buildErr != nil {
		t.Fatal("sealed archive receipt fixed-point mutation reseal failed")
	}
	mutatedPlan := sealedArchiveClonePlanV8(plan)
	mutatedPlan.Receipt.Bytes = mutatedReceipt
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(mutatedPlan), CodeArchiveConflict)
	hexFields := []func(*archiveReceiptBytesV2, string){
		func(value *archiveReceiptBytesV2, replacement string) { value.ReceiptBytesHex = replacement },
		func(value *archiveReceiptBytesV2, replacement string) { value.FinalBytesHex = replacement },
		func(value *archiveReceiptBytesV2, replacement string) { value.MaxTempBytesHex = replacement },
		func(value *archiveReceiptBytesV2, replacement string) { value.PeakBytesHex = replacement },
	}
	for _, replacement := range []string{strings.Repeat("0", 15), strings.Repeat("0", 17), "g" + strings.Repeat("0", 15)} {
		for _, setField := range hexFields {
			payload := receipt.Payload
			setField(&payload.Bytes, replacement)
			raw, _, _, hexErr := sealedArchiveMakeReceiptV8(kref, kseal, payload)
			if hexErr != nil {
				t.Fatal("sealed archive HexU64 mutation reseal failed")
			}
			hexPlan := sealedArchiveClonePlanV8(plan)
			hexPlan.Receipt.Bytes = raw
			sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(hexPlan), CodeArchiveInvalid)
		}
	}
	var source storeSnapshot
	if storeDecode(input.OriginalV1, &source) != nil {
		t.Fatal("sealed archive concrete canonical source decode failed")
	}
	history, historyErr := buildSealedArchiveHistoryFixtureV8(sealedArchiveHistoryInputV8{
		ArchiveKey: input.ArchiveKey, MigrationID: plan.Identity.MigrationID, ArchiveEpoch: plan.Identity.ArchiveEpoch,
		SegmentOrdinal: 1, PreviousKind: sealedArchiveGenesisKindV1, PreviousReference: plan.Identity.GenesisReference,
		FirstSequence: 1, BaseHash: strings.Repeat("0", 64),
		Entries: []archiveHistoryEntryV1{{Request: source.Requests[0], Audit: source.Audit[0]}, {Request: source.Requests[1], Audit: source.Audit[1]}},
	})
	if historyErr != nil {
		t.Fatal("sealed archive concrete canonical history fixture failed")
	}
	var historyEnvelope archiveHistoryEnvelopeV1
	if sealedArchiveDecode(history.File.Bytes, true, int(sealedArchiveObjectMaxBytes), &historyEnvelope) != nil {
		t.Fatal("sealed archive concrete canonical history decode failed")
	}
	historyPayload, _ := sealedArchiveCanonical(historyEnvelope.Payload)
	objects := golden.ValidFullChain.Objects
	concrete := []struct {
		name         string
		raw          []byte
		nestedMarker []byte
	}{
		{"frozen-sources", sealedArchiveGoldenBytes(t, objects.FrozenSources), []byte(`"evidence":{`)},
		{"meta", plan.Meta.Bytes, nil},
		{"intent-core", sealedArchiveGoldenBytes(t, objects.IntentCore), []byte(`"archiveRoot":{`)},
		{"intent-payload", sealedArchiveGoldenBytes(t, objects.IntentPayload), []byte(`"core":{`)},
		{"intent-envelope", plan.Intent.Bytes, []byte(`"payload":{`)},
		{"candidate-payload", sealedArchiveGoldenBytes(t, objects.CandidatePayloads[0]), []byte(`"candidate":{`)},
		{"candidate-envelope", plan.Candidates[0].Bytes, []byte(`"payload":{`)},
		{"genesis-payload", sealedArchiveGoldenBytes(t, objects.GenesisPayload), []byte(`"originalV1":{`)},
		{"genesis-envelope", plan.Genesis.Bytes, []byte(`"payload":{`)},
		{"receipt-payload", sealedArchiveGoldenBytes(t, objects.ReceiptPayload), []byte(`"bytes":{`)},
		{"receipt-envelope", plan.Receipt.Bytes, []byte(`"payload":{`)},
		{"history-payload", historyPayload, []byte(`"entries":[{`)},
		{"history-envelope", history.File.Bytes, []byte(`"payload":{`)},
	}
	for _, fixture := range concrete {
		t.Run("canonical-"+fixture.name, func(t *testing.T) {
			mutations := sealedArchiveObjectMutationsV8(fixture.raw, 0)
			if len(mutations) != 4 {
				t.Fatal("sealed archive top-level canonical mutation setup failed")
			}
			for _, mutation := range mutations {
				sealedArchiveRequireCode(t, sealedArchiveConcreteDecodeV8(fixture.name, mutation), CodeArchiveInvalid)
			}
			if fixture.nestedMarker != nil {
				marker := bytes.Index(fixture.raw, fixture.nestedMarker)
				if marker < 0 {
					t.Fatal("sealed archive nested canonical marker is missing")
				}
				nested := sealedArchiveObjectMutationsV8(fixture.raw, marker+len(fixture.nestedMarker)-1)
				if len(nested) != 4 {
					t.Fatal("sealed archive nested canonical mutation setup failed")
				}
				for _, mutation := range nested {
					sealedArchiveRequireCode(t, sealedArchiveConcreteDecodeV8(fixture.name, mutation), CodeArchiveInvalid)
				}
			}
		})
	}
	var intentCore archiveIntentCoreV1
	var candidatePayload archiveCandidatePayloadV1
	var genesisPayload archiveGenesisPayloadV1
	intentCoreRaw := sealedArchiveGoldenBytes(t, objects.IntentCore)
	candidateGoldenPayloadRaw := sealedArchiveGoldenBytes(t, objects.CandidatePayloads[0])
	genesisPayloadRaw := sealedArchiveGoldenBytes(t, objects.GenesisPayload)
	if sealedArchiveDecode(intentCoreRaw, false, sealedArchiveIntentMaxBytes, &intentCore) != nil ||
		sealedArchiveDecode(candidateGoldenPayloadRaw, false, int(sealedArchiveObjectMaxBytes), &candidatePayload) != nil ||
		sealedArchiveDecode(genesisPayloadRaw, false, int(sealedArchiveObjectMaxBytes), &genesisPayload) != nil {
		t.Fatal("sealed archive base64 lexical fixture decode failed")
	}
	base64Fields := []struct {
		name    string
		raw     []byte
		decoded []byte
	}{
		{"intent-core", intentCoreRaw, intentCore.Nonce},
		{"candidate-payload", candidateGoldenPayloadRaw, candidatePayload.Candidate.Raw},
		{"genesis-payload", genesisPayloadRaw, genesisPayload.IdentityKey},
	}
	for _, fixture := range base64Fields {
		mutations := sealedArchiveBase64LexicalMutationsV8(fixture.raw, fixture.decoded)
		if len(mutations) != 5 {
			t.Fatal("sealed archive concrete base64 mutation setup failed")
		}
		for _, mutation := range mutations {
			sealedArchiveRequireCode(t, sealedArchiveConcreteDecodeV8(fixture.name, mutation), CodeArchiveInvalid)
		}
	}
}

func TestSealedArchiveV8LosslessUsesAuthoritativeStoreValidation(t *testing.T) {
	input, _ := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	if !bytes.Contains(input.OriginalV1, []byte("+08:00")) {
		t.Fatal("sealed archive embedded non-Z time fixture is missing")
	}
	mutations := []func(*storeSnapshot){
		func(state *storeSnapshot) { state.Candidates[0].Raw[0] ^= 1 },
		func(state *storeSnapshot) {
			state.Candidates[0].Nodes[0].Config = json.RawMessage(`{"name":"changed"}`)
		},
		func(state *storeSnapshot) { state.Candidates[0].Nodes[0].PrivateName += "-changed" },
		func(state *storeSnapshot) {
			state.Candidates[0].View.Nodes[0].ID = "node_00000000000000000000000000000000"
		},
		func(state *storeSnapshot) { state.Sources[0].LatestCandidateID = "" },
		func(state *storeSnapshot) { state.IdentityKey[0] ^= 1 },
		func(state *storeSnapshot) { state.Requests[1].Fingerprint = strings.Repeat("0", 64) },
		func(state *storeSnapshot) { state.Requests[1].Action = "rollback" },
		func(state *storeSnapshot) { state.Audit[1].Hash = strings.Repeat("0", 64) },
	}
	for _, mutation := range mutations {
		var state storeSnapshot
		if storeDecode(input.OriginalV1, &state) != nil {
			t.Fatal("sealed archive v1 fixture decode failed")
		}
		mutation(&state)
		raw, err := storeEncode(state)
		if err != nil {
			t.Fatal("sealed archive v1 mutation encode failed")
		}
		mutated := sealedArchiveInputForStateV8(t, input, state, raw)
		_, err = buildSealedArchiveV8(mutated)
		sealedArchiveRequireCode(t, err, CodeArchiveReconstructionFailed)
	}
	badUnion := input
	badUnion.FrozenSources.Refresh = archiveRefreshSourceV1{State: "absent"}
	_, err := buildSealedArchiveV8(badUnion)
	sealedArchiveRequireCode(t, err, CodeArchiveInvalid)
	badUnion = input
	badUnion.FrozenSources.Refresh.Present = &archiveRefreshPresentV1{}
	_, err = buildSealedArchiveV8(badUnion)
	sealedArchiveRequireCode(t, err, CodeArchiveInvalid)
	present := archiveRefreshPresentV1{
		Root: input.FrozenSources.Main.Root, Lock: input.FrozenSources.Main.Lock, Snapshot: input.FrozenSources.Main.Snapshot,
		StoreSchema: refreshSchema, IdentityKeyID: strings.Repeat("1", 64), Epoch: strings.Repeat("2", 64),
		CheckpointReady: true, ClockState: string(RefreshClockNormal), ClockReasonSHA256: strings.Repeat("0", 64),
	}
	badRefresh := input.FrozenSources
	badRefresh.Refresh = archiveRefreshSourceV1{State: "present", Present: &present}
	sealedArchiveRequireCode(t, sealedArchiveValidateFrozen(badRefresh), CodeArchiveInvalid)
	present.CheckpointReady = false
	present.ClockState = string(RefreshClockFrozen)
	badRefresh.Refresh.Present = &present
	sealedArchiveRequireCode(t, sealedArchiveValidateFrozen(badRefresh), CodeArchiveInvalid)
	var keyState storeSnapshot
	if storeDecode(input.OriginalV1, &keyState) != nil {
		t.Fatal("sealed archive source-key substitution fixture decode failed")
	}
	mainKeyID, mainErr := sealedArchiveSourceKeyID("main-v1", keyState.IdentityKey)
	refreshKeyID, refreshErr := sealedArchiveSourceKeyID("refresh-v3", keyState.IdentityKey)
	if mainErr != nil || refreshErr != nil || mainKeyID == refreshKeyID {
		t.Fatal("sealed archive source-key contexts are not separated")
	}
	badSourceKey := input
	badSourceKey.FrozenSources.Main.IdentityKeyID = refreshKeyID
	_, err = buildSealedArchiveV8(badSourceKey)
	sealedArchiveRequireCode(t, err, CodeArchiveConflict)
}

func sealedArchiveInputForStateV8(t *testing.T, base sealedArchiveV8Input, state storeSnapshot, raw []byte) sealedArchiveV8Input {
	t.Helper()
	result := base
	result.OriginalV1 = append([]byte{}, raw...)
	digest := sha256.Sum256(raw)
	result.FrozenSources.Main.Snapshot.Length = uint64(len(raw))
	result.FrozenSources.Main.Snapshot.SHA256 = hex.EncodeToString(digest[:])
	keyID, err := sealedArchiveSourceKeyID("main-v1", state.IdentityKey)
	if err != nil {
		t.Fatal("sealed archive source key identity failed")
	}
	result.FrozenSources.Main.IdentityKeyID = keyID
	result.FrozenSources.Main.AuditCount = uint32(len(state.Audit))
	result.FrozenSources.Main.AuditHead = strings.Repeat("0", 64)
	if len(state.Audit) != 0 {
		result.FrozenSources.Main.AuditHead = state.Audit[len(state.Audit)-1].Hash
	}
	result.FrozenSources.Main.CommandCount = uint32(len(state.Commands))
	result.FrozenSources.Main.ApprovalCount = uint32(len(state.Approvals))
	return result
}

func TestSealedArchiveV8EmptyAndCandidate64Reconstruction(t *testing.T) {
	base, _ := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	var goldenState storeSnapshot
	if storeDecode(base.OriginalV1, &goldenState) != nil {
		t.Fatal("sealed archive v1 fixture decode failed")
	}
	empty := storeSnapshot{Schema: storeSchema, IdentityKey: append([]byte{}, goldenState.IdentityKey...), Sources: []SourceView{}, Candidates: []storeCandidate{}, Requests: []storeRequest{}, Audit: []storeAudit{}}
	emptyRaw, err := storeEncode(empty)
	if err != nil {
		t.Fatal("sealed archive empty v1 encode failed")
	}
	emptyInput := sealedArchiveInputForStateV8(t, base, empty, emptyRaw)
	emptyPlan, err := buildSealedArchiveV8(emptyInput)
	if err != nil || len(emptyPlan.Candidates) != 0 || emptyPlan.Bytes.FinalEntries != 5 || emptyPlan.Bytes.PeakEntries != 6 {
		t.Fatal("sealed archive empty reconstruction failed")
	}
	state64 := sealedArchiveCandidateStateV8(t, 64)
	raw64, err := storeEncode(state64)
	if err != nil {
		t.Fatal("sealed archive 64-candidate v1 encode failed")
	}
	input64 := sealedArchiveInputForStateV8(t, base, state64, raw64)
	plan64, err := buildSealedArchiveV8(input64)
	if err != nil || len(plan64.Candidates) != 64 || plan64.Bytes.FinalEntries != 69 || plan64.Bytes.PeakEntries != 70 {
		t.Fatal("sealed archive 64-candidate reconstruction failed")
	}
	overPlan := sealedArchiveClonePlanV8(plan64)
	overPlan.Candidates = append(overPlan.Candidates, overPlan.Candidates[0])
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(overPlan), CodeArchiveLimit)
	state65 := sealedArchiveCandidateStateUncheckedV8(t, 65)
	if uint32(len(state65.Candidates))+5 != 70 || uint32(len(state65.Candidates))+6 != 71 {
		t.Fatal("sealed archive 65-candidate entry boundary fixture is invalid")
	}
	raw65, err := storeEncode(state65)
	if err != nil {
		t.Fatal("sealed archive 65-candidate source encode failed")
	}
	_, err = buildSealedArchiveV8(sealedArchiveInputForStateV8(t, base, state65, raw65))
	sealedArchiveRequireCode(t, err, CodeArchiveReconstructionFailed)

	state2 := sealedArchiveCandidateStateV8(t, 2)
	raw2, err := storeEncode(state2)
	if err != nil {
		t.Fatal("sealed archive two-candidate source encode failed")
	}
	plan2, err := buildSealedArchiveV8(sealedArchiveInputForStateV8(t, base, state2, raw2))
	if err != nil {
		t.Fatal("sealed archive two-candidate plan failed")
	}
	removed := sealedArchiveClonePlanV8(plan2)
	removed.Candidates = removed.Candidates[:1]
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(removed), CodeArchiveConflict)
	reordered := sealedArchiveClonePlanV8(plan2)
	reordered.Candidates[0], reordered.Candidates[1] = reordered.Candidates[1], reordered.Candidates[0]
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(reordered), CodeArchiveConflict)
	duplicated := sealedArchiveClonePlanV8(plan2)
	duplicated.Candidates[1] = duplicated.Candidates[0]
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(duplicated), CodeArchiveConflict)
	var meta archiveMetaV2
	var candidate archiveCandidateEnvelopeV1
	if sealedArchiveDecode(plan2.Meta.Bytes, true, sealedArchiveMetaMaxBytes, &meta) != nil || sealedArchiveDecode(plan2.Candidates[0].Bytes, true, int(sealedArchiveObjectMaxBytes), &candidate) != nil {
		t.Fatal("sealed archive candidate-link mutation fixture decode failed")
	}
	_, kref, kseal, err := sealedArchiveKeys(meta.ArchiveKey)
	if err != nil {
		t.Fatal("sealed archive candidate-link mutation keys failed")
	}
	candidate.Payload.Ordinal++
	mutatedRaw, mutatedReference, _, err := sealedArchiveMakeCandidateV8(kref, kseal, candidate.Payload)
	if err != nil {
		t.Fatal("sealed archive candidate-link mutation reseal failed")
	}
	mutatedName, err := sealedArchiveContentName(sealedArchiveCandidateKindV1, mutatedReference)
	if err != nil {
		t.Fatal("sealed archive candidate-link mutation name failed")
	}
	ordinal := sealedArchiveClonePlanV8(plan2)
	ordinal.Candidates[0] = sealedArchiveV8File{Name: mutatedName, Bytes: mutatedRaw}
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(ordinal), CodeArchiveConflict)
}

func TestSealedArchiveV8MixedLifecycleReconstruction(t *testing.T) {
	base, _ := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	var state storeSnapshot
	if storeDecode(base.OriginalV1, &state) != nil {
		t.Fatal("sealed archive mixed-lifecycle fixture decode failed")
	}
	source := state.Sources[0]
	firstID := state.Candidates[0].View.ID
	previous := state.Audit[len(state.Audit)-1].Hash
	at := state.Audit[len(state.Audit)-1].At
	appendAudit := func(action, result, candidateID string, revision uint64) {
		key := sealedArchiveTestHex(fmt.Sprintf("mixed-key-%d", revision))
		fingerprint := sealedArchiveTestHex(fmt.Sprintf("mixed-request-%d", revision))
		at = at.Add(time.Second)
		audit := storeAudit{Sequence: uint64(len(state.Audit) + 1), Actor: "fixture-actor", Scope: source.Scope, SourceID: source.ID, CandidateID: candidateID, Revision: revision, Action: action, Result: result, Key: key, RequestDigest: fingerprint, At: at, PreviousHash: previous}
		audit.Hash = storeAuditHash(audit)
		state.Requests = append(state.Requests, storeRequest{Key: key, Fingerprint: fingerprint, Action: action, SourceID: source.ID, CandidateID: candidateID})
		state.Audit = append(state.Audit, audit)
		previous = audit.Hash
	}
	appendAudit("decide", string(CandidateAdmitted), firstID, 3)
	state.Candidates[0].View.State = CandidateAdmitted
	source.Revision = 3
	source.AcceptedCandidateID = firstID
	source.UpdatedAt = at
	appendAudit("rollback", string(CandidateAdmitted), firstID, 4)
	source.Revision = 4
	source.UpdatedAt = at
	raw := []byte("http://proxy-second.example:8080#second\n")
	parsed, err := Parse(ParseInput{Scope: source.Scope, SourceID: source.ID, Format: FormatURI, Content: raw, IdentityKey: state.IdentityKey})
	if err != nil || len(parsed.Nodes) != 1 {
		t.Fatal("sealed archive mixed-lifecycle candidate parse failed")
	}
	secondID := "cand_" + keyedDigest(state.IdentityKey, []byte("candidate"), []byte(scopeKey(source.Scope)), []byte(source.ID), []byte(parsed.Digest))[:32]
	at = at.Add(time.Second)
	secondView := CandidateView{ID: secondID, SourceID: source.ID, Scope: source.Scope, Digest: parsed.Digest, Format: parsed.Format, State: CandidateQuarantined, BaseRevision: 5, NodeCount: 1, DuplicateCount: 0, Nodes: []NodeView{}, CreatedAt: at}
	second := storeCandidate{View: secondView, Raw: append([]byte{}, raw...), Nodes: []storeNode{}}
	for _, node := range parsed.Nodes {
		second.View.Nodes = append(second.View.Nodes, nodeView(node))
		second.Nodes = append(second.Nodes, storeNode{ID: node.ID, Protocol: node.Protocol, PrivateName: node.PrivateName, Config: append(json.RawMessage{}, node.Config...), CredentialConfigured: node.CredentialConfigured})
	}
	state.Candidates = append(state.Candidates, second)
	at = at.Add(-time.Second)
	appendAudit("import", string(CandidateQuarantined), secondID, 5)
	source.Revision = 5
	source.LatestCandidateID = secondID
	source.UpdatedAt = at
	appendAudit("decide", string(CandidateRejected), secondID, 6)
	state.Candidates[1].View.State = CandidateRejected
	source.Revision = 6
	source.UpdatedAt = at
	state.Sources[0] = source
	if storeValidate(state) != nil {
		t.Fatal("sealed archive mixed-lifecycle fixture failed authoritative validation")
	}
	original, err := storeEncode(state)
	if err != nil {
		t.Fatal("sealed archive mixed-lifecycle fixture encode failed")
	}
	input := sealedArchiveInputForStateV8(t, base, state, original)
	if plan, err := buildSealedArchiveV8(input); err != nil || validateSealedArchiveV8Plan(plan) != nil {
		t.Fatal("sealed archive mixed-lifecycle reconstruction failed")
	}
}

func sealedArchiveCandidateStateV8(t *testing.T, count int) storeSnapshot {
	t.Helper()
	state := sealedArchiveCandidateStateUncheckedV8(t, count)
	if storeValidate(state) != nil {
		t.Fatal("sealed archive candidate fixture failed authoritative validation")
	}
	return state
}

func sealedArchiveCandidateStateUncheckedV8(t *testing.T, count int) storeSnapshot {
	t.Helper()
	identityKey := make([]byte, 32)
	for i := range identityKey {
		identityKey[i] = byte(0x20 + i)
	}
	scope := Scope{TenantID: "tenant-fixture", SiteID: "site-fixture", Environment: "test"}
	sourceID := "src_" + strings.Repeat("2", 32)
	actor := "fixture-actor"
	start, _ := time.Parse(time.RFC3339, "2026-11-02T20:02:00+08:00")
	state := storeSnapshot{Schema: storeSchema, IdentityKey: identityKey, Sources: []SourceView{}, Candidates: []storeCandidate{}, Requests: []storeRequest{}, Audit: []storeAudit{}}
	createKey := sealedArchiveTestHex("create-key")
	createRequest := sealedArchiveTestHex("create-request")
	first := storeAudit{Sequence: 1, Actor: actor, Scope: scope, SourceID: sourceID, Revision: 1, Action: "create", Result: "created", Key: createKey, RequestDigest: createRequest, At: start, PreviousHash: strings.Repeat("0", 64)}
	first.Hash = storeAuditHash(first)
	state.Requests = append(state.Requests, storeRequest{Key: createKey, Fingerprint: createRequest, Action: "create", SourceID: sourceID})
	state.Audit = append(state.Audit, first)
	previous := first.Hash
	latest := ""
	accepted := ""
	revision := uint64(1)
	for i := 0; i < count; i++ {
		raw := []byte(fmt.Sprintf("http://proxy-%03d.example:8080#node-%03d\n", i, i))
		parsed, err := Parse(ParseInput{Scope: scope, SourceID: sourceID, Format: FormatURI, Content: raw, IdentityKey: identityKey})
		if err != nil || len(parsed.Nodes) != 1 {
			t.Fatal("sealed archive candidate fixture parse failed")
		}
		candidateID := "cand_" + keyedDigest(identityKey, []byte("candidate"), []byte(scopeKey(scope)), []byte(sourceID), []byte(parsed.Digest))[:32]
		revision++
		at := start.Add(time.Duration(len(state.Audit)) * time.Second)
		view := CandidateView{ID: candidateID, SourceID: sourceID, Scope: scope, Digest: parsed.Digest, Format: parsed.Format, State: CandidateQuarantined, BaseRevision: revision, NodeCount: 1, DuplicateCount: 0, Nodes: []NodeView{}, CreatedAt: at}
		private := storeCandidate{View: view, Raw: append([]byte{}, raw...), Nodes: []storeNode{}}
		for _, node := range parsed.Nodes {
			private.View.Nodes = append(private.View.Nodes, nodeView(node))
			private.Nodes = append(private.Nodes, storeNode{ID: node.ID, Protocol: node.Protocol, PrivateName: node.PrivateName, Config: append(json.RawMessage{}, node.Config...), CredentialConfigured: node.CredentialConfigured})
		}
		state.Candidates = append(state.Candidates, private)
		key := sealedArchiveTestHex(fmt.Sprintf("import-key-%d", i))
		fingerprint := sealedArchiveTestHex(fmt.Sprintf("import-request-%d", i))
		audit := storeAudit{Sequence: uint64(len(state.Audit) + 1), Actor: actor, Scope: scope, SourceID: sourceID, CandidateID: candidateID, Revision: revision, Action: "import", Result: string(CandidateQuarantined), Key: key, RequestDigest: fingerprint, At: at, PreviousHash: previous}
		audit.Hash = storeAuditHash(audit)
		state.Requests = append(state.Requests, storeRequest{Key: key, Fingerprint: fingerprint, Action: "import", SourceID: sourceID, CandidateID: candidateID})
		state.Audit = append(state.Audit, audit)
		previous = audit.Hash
		latest = candidateID
		if i%3 != 2 {
			revision++
			result := CandidateAdmitted
			if i%3 == 1 {
				result = CandidateRejected
			}
			decisionKey := sealedArchiveTestHex(fmt.Sprintf("decision-key-%d", i))
			decisionRequest := sealedArchiveTestHex(fmt.Sprintf("decision-request-%d", i))
			decisionAt := start.Add(time.Duration(len(state.Audit)) * time.Second)
			decision := storeAudit{Sequence: uint64(len(state.Audit) + 1), Actor: actor, Scope: scope, SourceID: sourceID, CandidateID: candidateID, Revision: revision, Action: "decide", Result: string(result), Key: decisionKey, RequestDigest: decisionRequest, At: decisionAt, PreviousHash: previous}
			decision.Hash = storeAuditHash(decision)
			state.Requests = append(state.Requests, storeRequest{Key: decisionKey, Fingerprint: decisionRequest, Action: "decide", SourceID: sourceID, CandidateID: candidateID})
			state.Audit = append(state.Audit, decision)
			previous = decision.Hash
			state.Candidates[len(state.Candidates)-1].View.State = result
			if result == CandidateAdmitted {
				accepted = candidateID
			}
		}
	}
	state.Sources = append(state.Sources, SourceView{ID: sourceID, Scope: scope, Label: "Fixture Source", Revision: revision, LatestCandidateID: latest, AcceptedCandidateID: accepted, UpdatedAt: state.Audit[len(state.Audit)-1].At})
	return state
}

func sealedArchiveTestHex(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func TestSealedArchiveV8AllControlStatesAndCheckpoint(t *testing.T) {
	base, _ := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	var state storeSnapshot
	if storeDecode(base.OriginalV1, &state) != nil {
		t.Fatal("sealed archive control fixture decode failed")
	}
	scope := state.Sources[0].Scope
	sourceID := state.Sources[0].ID
	candidate := state.Candidates[0].View
	committedDigest := sealedArchiveTestHex("control-committed")
	committedOwner := "fixture-control-committed"
	committedCore := "ctl_" + committedDigest[:60]
	committedActor := controlActor(state.IdentityKey, scope, committedOwner)
	committedKey := keyedDigest(state.IdentityKey, []byte("idempotency"), []byte(scopeKey(scope)), []byte(committedActor), []byte(committedCore))
	state.Requests[1].Key = committedKey
	state.Audit[1].Actor = committedActor
	state.Audit[1].Key = committedKey
	state.Audit[1].Hash = storeAuditHash(state.Audit[1])
	at := state.Audit[1].At
	preparedAt := state.Audit[0].At
	makeCommand := func(label, owner, kind string, result *ControlResult, acknowledged bool) controlCommandDisk {
		digest := sealedArchiveTestHex(label)
		disk := controlCommandDisk{
			Record: ControlCommand{
				ID: "cmd_" + digest[:32], Scope: scope, ActorID: controlActor(state.IdentityKey, scope, owner),
				Kind: kind, SourceID: sourceID, ExpectedRevision: 2,
				Fingerprint: "hmac-sha256:" + sealedArchiveTestHex(label+"-fingerprint"),
				PreparedAt:  preparedAt, PreparedAuditHash: state.Audit[0].Hash,
				Result: result, Acknowledged: acknowledged,
			},
			OwnerID: owner, CoreKey: "ctl_" + digest[:60], KeyDigest: digest,
		}
		if acknowledged {
			disk.Record.ResultAuditHash = sealedArchiveTestHex(label + "-result-audit")
		}
		disk.Seal = controlCommandSeal(state.IdentityKey, disk)
		return disk
	}
	committedResult := &ControlResult{SourceID: sourceID, CandidateID: candidate.ID, Revision: 2, Digest: candidate.Digest, State: "committed", LocalAuditHash: state.Audit[1].Hash, CompletedAt: at}
	committed := makeCommand("control-committed", committedOwner, "fetch", committedResult, true)
	committed.CoreKey = committedCore
	committed.Record.ActorID = committedActor
	committed.Seal = controlCommandSeal(state.IdentityKey, committed)
	prepared := makeCommand("control-prepared", "fixture-control-prepared", "fetch", nil, false)
	noop := makeCommand("control-noop", "fixture-control-noop", "fetch", &ControlResult{SourceID: sourceID, CandidateID: candidate.ID, Revision: 2, Digest: candidate.Digest, State: "noop", CompletedAt: at}, false)
	failedEpoch := sealedArchiveTestHex("refresh-checkpoint")
	failed := makeCommand("control-failed", "fixture-control-failed", "fetch", &ControlResult{SourceID: sourceID, State: "failed", Code: "subscription_unavailable", ReferenceID: refreshCheckpointPrefix + failedEpoch, CompletedAt: at}, true)
	unknown := makeCommand("control-unknown", "fixture-control-unknown", "fetch", &ControlResult{SourceID: sourceID, State: "unknown", Code: "subscription_commit_unknown", StateMayHaveChanged: true, CompletedAt: at}, false)
	approvedDigest := sealedArchiveTestHex("control-approved")
	approvedID := "cmd_" + approvedDigest[:32]
	policyDigest := "hmac-sha256:" + sealedArchiveTestHex("control-policy")
	approved := makeCommand("control-approved", "fixture-control-approved", "approve", &ControlResult{SourceID: sourceID, Revision: 2, State: "approved", ReferenceID: "fixture-policy", PolicyRevision: 1, PolicyDigest: policyDigest, ApprovalID: approvedID, CompletedAt: at}, false)
	approval := ControlApproval{CommandID: approvedID, Scope: scope, SourceID: sourceID, ReferenceID: "fixture-policy", PolicyRevision: 1, PolicyDigest: policyDigest, SourceRevision: 2, ApprovedAt: at}
	approval.Seal = controlApprovalSeal(state.IdentityKey, approval)
	state.Commands = []controlCommandDisk{prepared, committed, noop, failed, unknown, approved}
	state.Approvals = []ControlApproval{approval}
	if storeValidate(state) != nil {
		t.Fatal("sealed archive all-control-state fixture failed authoritative validation")
	}
	raw, err := storeEncode(state)
	if err != nil {
		t.Fatal("sealed archive all-control-state fixture encode failed")
	}
	input := sealedArchiveInputForStateV8(t, base, state, raw)
	input.FrozenSources.Main.LatestRefreshCheckpoint = archiveMainCheckpointV1{Present: true, CommandID: failed.Record.ID, Epoch: failedEpoch}
	plan, err := buildSealedArchiveV8(input)
	if err != nil || validateSealedArchiveV8Plan(plan) != nil {
		t.Fatal("sealed archive all-control-state reconstruction failed")
	}
	badCheckpoint := input
	badCheckpoint.FrozenSources.Main.LatestRefreshCheckpoint = archiveMainCheckpointV1{Present: true, CommandID: prepared.Record.ID, Epoch: failedEpoch}
	_, err = buildSealedArchiveV8(badCheckpoint)
	sealedArchiveRequireCode(t, err, CodeArchiveConflict)
	var receipt archiveReceiptEnvelopeV1
	if sealedArchiveDecode(plan.Receipt.Bytes, true, sealedArchiveReceiptMaxBytes, &receipt) != nil || len(receipt.Payload.Blockers) != 7 || receipt.Payload.Blockers[3].Count != 1 || receipt.Payload.Blockers[4].Count != 3 {
		t.Fatal("sealed archive control blockers are incorrect")
	}
	commandSeal := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.Commands[0].Seal = strings.Repeat("0", 64)
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(commandSeal), CodeArchiveReconstructionFailed)
	ack := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.Commands[1].Record.Acknowledged = false
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(ack), CodeArchiveReconstructionFailed)
	commandResult := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.Commands[1].Record.Result.Revision++
		payload.Commands[1].Seal = controlCommandSeal(payload.IdentityKey, payload.Commands[1])
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(commandResult), CodeArchiveReconstructionFailed)
	approvalSeal := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.Approvals[0].Seal = strings.Repeat("0", 64)
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(approvalSeal), CodeArchiveReconstructionFailed)
	approvalPayload := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.Approvals[0].PolicyRevision++
		payload.Approvals[0].Seal = controlApprovalSeal(payload.IdentityKey, payload.Approvals[0])
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(approvalPayload), CodeArchiveReconstructionFailed)
	originalIdentity := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.OriginalV1.Length++
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(originalIdentity), CodeArchiveReconstructionFailed)
	originalDigest := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.OriginalV1.SHA256 = strings.Repeat("0", 64)
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(originalDigest), CodeArchiveReconstructionFailed)
	originalDigestOneByte := sealedArchiveReplaceGenesisV8(t, plan, func(payload *archiveGenesisPayloadV1) {
		payload.OriginalV1.SHA256 = sealedArchiveOneByteStringV8(t, payload.OriginalV1.SHA256, 0)
	})
	sealedArchiveRequireCode(t, validateSealedArchiveV8Plan(originalDigestOneByte), CodeArchiveReconstructionFailed)
}

func TestSealedArchiveV8NearObjectLimitFitsAndBudgetExpansionFails(t *testing.T) {
	base, _ := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	var state storeSnapshot
	if storeDecode(base.OriginalV1, &state) != nil {
		t.Fatal("sealed archive near-limit fixture decode failed")
	}
	scope := state.Sources[0].Scope
	sourceID := state.Sources[0].ID
	preparedAt := state.Audit[len(state.Audit)-1].At
	const commandCount = 3880
	commands := make([]controlCommandDisk, 0, commandCount)
	padding := strings.Repeat("x", 3500)
	for i := 0; i < commandCount; i++ {
		label := fmt.Sprintf("near-limit-%04d", i)
		owner := label + "-" + padding
		digest := sealedArchiveTestHex(label)
		disk := controlCommandDisk{
			Record: ControlCommand{
				ID: "cmd_" + digest[:32], Scope: scope, ActorID: controlActor(state.IdentityKey, scope, owner),
				Kind: "fetch", SourceID: sourceID, ExpectedRevision: state.Sources[0].Revision,
				Fingerprint: "hmac-sha256:" + sealedArchiveTestHex(label+"-fingerprint"),
				PreparedAt:  preparedAt, PreparedAuditHash: state.Audit[len(state.Audit)-1].Hash,
			},
			OwnerID: owner, CoreKey: "ctl_" + digest[:60], KeyDigest: digest,
		}
		disk.Seal = controlCommandSeal(state.IdentityKey, disk)
		commands = append(commands, disk)
	}
	state.Commands = commands
	if storeValidate(state) != nil {
		t.Fatal("sealed archive near-limit fixture failed authoritative validation")
	}
	raw, err := storeEncode(state)
	if err != nil || len(raw) < 15<<20 || len(raw) > MaxStoreBytes {
		t.Fatal("sealed archive near-limit source fixture is outside its required range")
	}
	input := sealedArchiveInputForStateV8(t, base, state, raw)
	plan, err := buildSealedArchiveV8(input)
	if err != nil || plan.Bytes.GenesisBytes > sealedArchiveObjectMaxBytes || plan.Bytes.PeakBytes > sealedArchiveMaxBytes {
		t.Fatal("sealed archive near-limit plan failed")
	}
	input.Budget.ArchiveMaxBytes = plan.Bytes.PeakBytes - 1
	_, err = buildSealedArchiveV8(input)
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
}

func TestSealedArchiveV8HistoryFixture(t *testing.T) {
	input, _ := sealedArchiveGoldenInputV8(t, sealedArchiveMaxBytes)
	plan, err := buildSealedArchiveV8(input)
	if err != nil {
		t.Fatal("sealed archive history base plan failed")
	}
	var state storeSnapshot
	if storeDecode(input.OriginalV1, &state) != nil {
		t.Fatal("sealed archive history v1 decode failed")
	}
	entries := []archiveHistoryEntryV1{{Request: state.Requests[0], Audit: state.Audit[0]}, {Request: state.Requests[1], Audit: state.Audit[1]}}
	firstInput := sealedArchiveHistoryInputV8{
		ArchiveKey: input.ArchiveKey, MigrationID: plan.Identity.MigrationID, ArchiveEpoch: plan.Identity.ArchiveEpoch,
		SegmentOrdinal: 1, PreviousKind: sealedArchiveGenesisKindV1, PreviousReference: plan.Identity.GenesisReference,
		FirstSequence: 1, BaseHash: strings.Repeat("0", 64), Entries: entries,
	}
	first, err := buildSealedArchiveHistoryFixtureV8(firstInput)
	if err != nil {
		t.Fatal("sealed archive first history fixture failed")
	}
	secondEntries := sealedArchiveHistoryEntriesV8(state.Requests[1], state.Audit[1], 3, 2)
	second, err := buildSealedArchiveHistoryFixtureV8(sealedArchiveHistoryInputV8{
		ArchiveKey: input.ArchiveKey, MigrationID: plan.Identity.MigrationID, ArchiveEpoch: plan.Identity.ArchiveEpoch,
		SegmentOrdinal: 2, PreviousKind: sealedArchiveHistoryKindV1, PreviousReference: first.Reference,
		FirstSequence: 3, BaseHash: state.Audit[1].Hash, Entries: secondEntries,
	})
	if err != nil || validateSealedArchiveHistoryV8(second.File, input.ArchiveKey, sealedArchiveHistoryKindV1, first.Reference, 3, state.Audit[1].Hash) != nil {
		t.Fatal("sealed archive chained history fixture failed")
	}
	maxOrdinal, err := buildSealedArchiveHistoryFixtureV8(sealedArchiveHistoryInputV8{
		ArchiveKey: input.ArchiveKey, MigrationID: plan.Identity.MigrationID, ArchiveEpoch: plan.Identity.ArchiveEpoch,
		SegmentOrdinal: math.MaxUint64, PreviousKind: sealedArchiveHistoryKindV1, PreviousReference: first.Reference,
		FirstSequence: 3, BaseHash: state.Audit[1].Hash, Entries: secondEntries,
	})
	if err != nil || validateSealedArchiveHistoryV8(maxOrdinal.File, input.ArchiveKey, sealedArchiveHistoryKindV1, first.Reference, 3, state.Audit[1].Hash) != nil {
		t.Fatal("sealed archive rejected the exact segment-ordinal maximum")
	}
	ordinalOverflow := sealedArchiveV8File{Name: maxOrdinal.File.Name, Bytes: bytes.Replace(maxOrdinal.File.Bytes, []byte(`"segmentOrdinal":18446744073709551615`), []byte(`"segmentOrdinal":18446744073709551616`), 1)}
	sealedArchiveRequireCode(t, validateSealedArchiveHistoryV8(ordinalOverflow, input.ArchiveKey, sealedArchiveHistoryKindV1, first.Reference, 3, state.Audit[1].Hash), CodeArchiveInvalid)
	largeEntries := sealedArchiveHistoryEntriesV8(state.Requests[1], state.Audit[1], 1, MaxAuditEntries)
	largeEntries[0].Audit.PreviousHash = strings.Repeat("0", 64)
	largeEntries[0].Audit.Hash = storeAuditHash(largeEntries[0].Audit)
	for i := 1; i < len(largeEntries); i++ {
		largeEntries[i].Audit.PreviousHash = largeEntries[i-1].Audit.Hash
		largeEntries[i].Audit.Hash = storeAuditHash(largeEntries[i].Audit)
	}
	if _, err := buildSealedArchiveHistoryFixtureV8(sealedArchiveHistoryInputV8{
		ArchiveKey: input.ArchiveKey, MigrationID: plan.Identity.MigrationID, ArchiveEpoch: plan.Identity.ArchiveEpoch,
		SegmentOrdinal: 1, PreviousKind: sealedArchiveGenesisKindV1, PreviousReference: plan.Identity.GenesisReference,
		FirstSequence: 1, BaseHash: strings.Repeat("0", 64), Entries: largeEntries,
	}); err != nil {
		t.Fatal("sealed archive 4096-entry history fixture failed")
	}
	tooManyEntries := append(append([]archiveHistoryEntryV1{}, largeEntries...), largeEntries[0])
	_, err = buildSealedArchiveHistoryFixtureV8(sealedArchiveHistoryInputV8{
		ArchiveKey: input.ArchiveKey, MigrationID: plan.Identity.MigrationID, ArchiveEpoch: plan.Identity.ArchiveEpoch,
		SegmentOrdinal: 1, PreviousKind: sealedArchiveGenesisKindV1, PreviousReference: plan.Identity.GenesisReference,
		FirstSequence: 1, BaseHash: strings.Repeat("0", 64), Entries: tooManyEntries,
	})
	sealedArchiveRequireCode(t, err, CodeArchiveLimit)
	invalidInputs := []sealedArchiveHistoryInputV8{}
	empty := firstInput
	empty.Entries = []archiveHistoryEntryV1{}
	invalidInputs = append(invalidInputs, empty)
	zeroOrdinal := firstInput
	zeroOrdinal.SegmentOrdinal = 0
	invalidInputs = append(invalidInputs, zeroOrdinal)
	wrongKind := firstInput
	wrongKind.PreviousKind = sealedArchiveHistoryKindV1
	invalidInputs = append(invalidInputs, wrongKind)
	zeroFirst := firstInput
	zeroFirst.FirstSequence = 0
	invalidInputs = append(invalidInputs, zeroFirst)
	overflow := firstInput
	overflow.FirstSequence = math.MaxUint64
	invalidInputs = append(invalidInputs, overflow)
	wrongBase := firstInput
	wrongBase.BaseHash = strings.Repeat("1", 64)
	invalidInputs = append(invalidInputs, wrongBase)
	gap := firstInput
	gap.Entries = append([]archiveHistoryEntryV1{}, entries...)
	gap.Entries[1].Audit.Sequence++
	invalidInputs = append(invalidInputs, gap)
	overlap := firstInput
	overlap.FirstSequence = 2
	invalidInputs = append(invalidInputs, overlap)
	duplicate := firstInput
	duplicate.Entries = append([]archiveHistoryEntryV1{}, entries...)
	duplicate.Entries[1].Audit.Sequence = duplicate.Entries[0].Audit.Sequence
	duplicate.Entries[1].Audit.Hash = storeAuditHash(duplicate.Entries[1].Audit)
	invalidInputs = append(invalidInputs, duplicate)
	reversed := firstInput
	reversed.Entries = []archiveHistoryEntryV1{entries[1], entries[0]}
	invalidInputs = append(invalidInputs, reversed)
	wrongPrevious := firstInput
	wrongPrevious.Entries = append([]archiveHistoryEntryV1{}, entries...)
	wrongPrevious.Entries[1].Audit.PreviousHash = strings.Repeat("1", 64)
	wrongPrevious.Entries[1].Audit.Hash = storeAuditHash(wrongPrevious.Entries[1].Audit)
	invalidInputs = append(invalidInputs, wrongPrevious)
	pair := firstInput
	pair.Entries = append([]archiveHistoryEntryV1{}, entries...)
	pair.Entries[1].Request.Action = "rollback"
	invalidInputs = append(invalidInputs, pair)
	hash := firstInput
	hash.Entries = append([]archiveHistoryEntryV1{}, entries...)
	hash.Entries[1].Audit.Hash = strings.Repeat("0", 64)
	invalidInputs = append(invalidInputs, hash)
	for _, invalid := range invalidInputs {
		_, buildErr := buildSealedArchiveHistoryFixtureV8(invalid)
		sealedArchiveRequireClosed(t, buildErr)
	}
	sealedArchiveRequireCode(t, validateSealedArchiveHistoryV8(first.File, input.ArchiveKey, sealedArchiveGenesisKindV1, strings.Repeat("0", 64), 1, strings.Repeat("0", 64)), CodeArchiveConflict)
	sealedArchiveRequireCode(t, validateSealedArchiveHistoryV8(first.File, input.ArchiveKey, sealedArchiveGenesisKindV1, plan.Identity.GenesisReference, 2, strings.Repeat("0", 64)), CodeArchiveConflict)
	lastRange := sealedArchiveReplaceHistoryV8(t, first.File, input.ArchiveKey, func(payload *archiveHistoryPayloadV1) { payload.LastSequence++ })
	sealedArchiveRequireCode(t, validateSealedArchiveHistoryV8(lastRange, input.ArchiveKey, sealedArchiveGenesisKindV1, plan.Identity.GenesisReference, 1, strings.Repeat("0", 64)), CodeArchiveConflict)
	invertedRange := sealedArchiveReplaceHistoryV8(t, first.File, input.ArchiveKey, func(payload *archiveHistoryPayloadV1) { payload.LastSequence = 0 })
	sealedArchiveRequireCode(t, validateSealedArchiveHistoryV8(invertedRange, input.ArchiveKey, sealedArchiveGenesisKindV1, plan.Identity.GenesisReference, 1, strings.Repeat("0", 64)), CodeArchiveConflict)
	through := sealedArchiveReplaceHistoryV8(t, first.File, input.ArchiveKey, func(payload *archiveHistoryPayloadV1) { payload.ThroughHash = strings.Repeat("0", 64) })
	sealedArchiveRequireCode(t, validateSealedArchiveHistoryV8(through, input.ArchiveKey, sealedArchiveGenesisKindV1, plan.Identity.GenesisReference, 1, strings.Repeat("0", 64)), CodeArchiveReconstructionFailed)
}

func sealedArchiveHistoryEntriesV8(request storeRequest, template storeAudit, first, count int) []archiveHistoryEntryV1 {
	result := make([]archiveHistoryEntryV1, 0, count)
	previous := template.Hash
	for i := 0; i < count; i++ {
		audit := template
		audit.Sequence = uint64(first + i)
		audit.PreviousHash = previous
		audit.Hash = storeAuditHash(audit)
		result = append(result, archiveHistoryEntryV1{Request: request, Audit: audit})
		previous = audit.Hash
	}
	return result
}
