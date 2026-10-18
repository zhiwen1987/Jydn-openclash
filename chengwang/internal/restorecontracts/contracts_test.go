package restorecontracts

import (
	"bytes"
	"chengwang/internal/proberestore"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var testNow = time.Unix(1_800_000_000, 0).UTC()

func hash(ch byte) string { return "sha256:" + strings.Repeat(string(ch), 64) }

func testRoot() string {
	return "/var/lib/chengwang/candidate"
}

func validCandidate() CandidateIdentity {
	return CandidateIdentity{CandidateID: "site-a", ProjectName: "probe-a", ServiceName: "probe-agent", CandidateRoot: testRoot(), StateMountTarget: "/var/lib/chengwang-probe"}
}

func validConfiguration(t testing.TB) ConfigurationBinding {
	t.Helper()
	v := ConfigurationBinding{
		ImageID: hash('1'), ImageManifestDigest: hash('2'), ImageReference: "chengwang/probe@sha256:0123456789abcdef",
		ComposeSourceSHA256: hash('3'), ComposeRenderedSHA256: hash('4'), ProbeEnvSHA256: hash('5'),
		CatalogSHA256: hash('6'), DotCASHA256: hash('7'), EgressPolicySHA256: hash('8'),
	}
	binding, err := ComputeConfigurationBinding(validCandidate(), v)
	if err != nil {
		t.Fatal(err)
	}
	v.ConfigurationBindingSHA256 = binding
	return v
}

func validBackup(t testing.TB) BackupV3 {
	t.Helper()
	return BackupV3{
		Schema: BackupV3Schema, BackupID: "backup-0123456789abcdef0123456789abcdef", CreatedUnix: testNow.Unix() - 10,
		ExpiresUnix: testNow.Unix() + 300, SourceBootID: "123e4567-e89b-42d3-a456-426614174000",
		WasRunningBeforeQuiesce: true, Candidate: validCandidate(), Configuration: validConfiguration(t),
		State: BackupState{ArchiveSHA256: hash('9'), TreeSHA256: hash('a'), ValidationReportSHA256: hash('b'), RelationshipComplete: true},
	}
}

func validStateObject(ch byte) StateObject {
	return StateObject{Present: true, SHA256: hash(ch), Device: 1, Inode: uint64(ch), MountID: 2}
}

func checksFor(kind string) []EvidenceCheck {
	result := make([]EvidenceCheck, 0, len(requiredChecks[kind]))
	for i, name := range requiredChecks[kind] {
		result = append(result, EvidenceCheck{Name: name, Passed: true, EvidenceSHA256: hash(byte('c' + i))})
	}
	return result
}

func validEvidence(kind string) RestoreEvidenceV1 {
	phase := evidencePhases[kind]
	contract := evidenceTopology[kind]
	from := ""
	for item := range contract.from {
		from = item
		break
	}
	if kind == "RESCUE_REQUIRED" {
		from = "STATE_EXCHANGED"
	}
	class := topologyOldOnly
	for item := range contract.classes {
		class = item
		break
	}
	if contract.dynamic {
		for item := range phaseTopologyClasses(from) {
			class = item
			break
		}
	}
	topology := topologyFor(class)
	return RestoreEvidenceV1{
		Schema: RestoreEvidenceV1Schema, Kind: kind, OperationID: "restore-01", TransitionSequence: 2,
		FromPhase: from, TargetPhase: phase, ReasonCode: kind, PreviousJournalHeadSHA256: strings.Repeat("d", 64), CapturedUnix: testNow.Unix() - 1,
		ExpiresUnix: testNow.Unix() + 20, BootID: "123e4567-e89b-42d3-a456-426614174000", BoottimeNS: 99,
		Candidate:     validCandidate(),
		Binding:       EvidenceBinding{BackupID: "backup-1123456789abcdef0123456789abcdef", BackupManifestSHA256: hash('e'), ConfigurationBindingSHA256: hash('f'), OldStateTreeSHA256: hash('1'), NewStateTreeSHA256: hash('2')},
		Collector:     Collector{Name: "restore-coordinator", Version: "1.0.0", BinarySHA256: hash('3')},
		PayloadSchema: "chengwang.probe-restore-evidence." + strings.ToLower(strings.ReplaceAll(kind, "_", "-")) + "/v1",
		Payload:       EvidencePayload{SubjectSHA256: hash('4'), Topology: topology, Checks: checksFor(kind)},
	}
}

func topologyFor(class topologyClass) Topology {
	absent := StateObject{}
	switch class {
	case topologyOldOnly:
		return Topology{Live: validStateObject('1'), Stage: absent}
	case topologyOldNew:
		return Topology{Live: validStateObject('1'), Stage: validStateObject('2')}
	case topologyNewOld:
		return Topology{Live: validStateObject('2'), Stage: validStateObject('1')}
	default:
		panic("unknown topology class")
	}
}

func evidenceContext(v RestoreEvidenceV1) EvidenceContext {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return EvidenceContext{Now: testNow, OperationID: v.OperationID, TransitionSequence: v.TransitionSequence, FromPhase: v.FromPhase, Kind: v.Kind, ReasonCode: v.ReasonCode, TargetPhase: v.TargetPhase, PreviousJournalHeadSHA256: v.PreviousJournalHeadSHA256, BootID: v.BootID, CurrentBoottimeNS: v.BoottimeNS + uint64(time.Second), MaxBoottimeAgeNS: uint64(2 * time.Second), Candidate: v.Candidate, Binding: v.Binding, SubjectSHA256: v.Payload.SubjectSHA256, Collector: v.Collector, Topology: v.Payload.Topology, RawBytesSHA256: rawDigestBytes(data)}
}

func validCAS() CASBinding {
	return CASBinding{BackendID: "anchor-service", ObjectKey: "candidate/site-a", ExpectedVersion: "v41", CommittedVersion: "v42"}
}

func validWORM() WORMBinding {
	return WORMBinding{BackendClass: "REMOTE_OBJECT_LOCK", BackendID: "remote-vault", ObjectKey: "candidate/site-a", ObjectVersion: "object-v42", RetentionUntilUnix: testNow.Add(365 * 24 * time.Hour).Unix(), Independent: true}
}

func validSigner() Signer    { return Signer{KeyID: "restore-key-01", Algorithm: "ED25519"} }
func validSignature() string { return base64.StdEncoding.EncodeToString(make([]byte, 64)) }

func validAnchor() RestoreAnchorV1 {
	return RestoreAnchorV1{
		Schema: AnchorV1Schema, CandidateID: "site-a", OperationID: "restore-01", Generation: 42,
		JournalHeadSHA256: strings.Repeat("1", 64), Phase: "SWITCH_ARMED", BackupID: "backup-1123456789abcdef0123456789abcdef", BackupManifestSHA256: hash('2'),
		ControlRecordSHA256: hash('3'), ReceiptAccumulatorSHA256: hash('4'), BootID: "123e4567-e89b-42d3-a456-426614174000",
		PreviousAnchorSHA256: hash('5'), CreatedUnix: testNow.Unix() - 1, CAS: validCAS(), WORM: validWORM(), Signer: validSigner(), Signature: validSignature(),
	}
}

func anchorContext(v RestoreAnchorV1) AnchorContext {
	return AnchorContext{Now: testNow, CandidateID: v.CandidateID, OperationID: v.OperationID, Generation: v.Generation, PreviousAnchorSHA256: v.PreviousAnchorSHA256, BootID: v.BootID, MaxAge: 5 * time.Minute, JournalHeadSHA256: v.JournalHeadSHA256, Phase: v.Phase, BackupID: v.BackupID, BackupManifestSHA256: v.BackupManifestSHA256, ControlRecordSHA256: v.ControlRecordSHA256, ReceiptAccumulatorSHA256: v.ReceiptAccumulatorSHA256, BackendClass: v.WORM.BackendClass, CASBackendID: v.CAS.BackendID, CASObjectKey: v.CAS.ObjectKey, WORMBackendID: v.WORM.BackendID, WORMObjectKey: v.WORM.ObjectKey, CASExpectedVersion: v.CAS.ExpectedVersion, SignerKeyID: v.Signer.KeyID, SignerAlgorithm: v.Signer.Algorithm, MinimumRetention: 24 * time.Hour}
}

func validCheckpoint() ReceiptCheckpointV1 {
	operations := ReceiptIndex{BackendID: "remote-vault", ObjectKey: "indexes/operations", ObjectVersion: "index-v40", RootSHA256: hash('6'), Count: 10}
	backups := ReceiptIndex{BackendID: "remote-vault", ObjectKey: "indexes/backups", ObjectVersion: "index-v41", RootSHA256: hash('7'), Count: 10}
	manifests := ReceiptIndex{BackendID: "remote-vault", ObjectKey: "indexes/manifests", ObjectVersion: "index-v42", RootSHA256: hash('8'), Count: 10}
	return ReceiptCheckpointV1{
		Schema: CheckpointV1Schema, CandidateID: "site-a", CheckpointGeneration: 42, ThroughGeneration: 40,
		CreatedUnix: testNow.Unix() - 1, ReceiptCount: 10, ReceiptAccumulatorSHA256: hash('7'),
		PreviousCheckpointSHA256: hash('8'), AnchorSHA256: hash('9'), Indexes: ReceiptIndexes{Operations: operations, Backups: backups, Manifests: manifests},
		CAS: validCAS(), WORM: validWORM(), Signer: validSigner(), Signature: validSignature(),
	}
}

func checkpointContext(v ReceiptCheckpointV1) CheckpointContext {
	return CheckpointContext{Now: testNow, CandidateID: v.CandidateID, CheckpointGeneration: v.CheckpointGeneration, PreviousCheckpointSHA256: v.PreviousCheckpointSHA256, AnchorSHA256: v.AnchorSHA256, MaxAge: 5 * time.Minute, ThroughGeneration: v.ThroughGeneration, ReceiptCount: v.ReceiptCount, ReceiptAccumulatorSHA256: v.ReceiptAccumulatorSHA256, Indexes: v.Indexes, BackendClass: v.WORM.BackendClass, CASBackendID: v.CAS.BackendID, CASObjectKey: v.CAS.ObjectKey, WORMBackendID: v.WORM.BackendID, WORMObjectKey: v.WORM.ObjectKey, CASExpectedVersion: v.CAS.ExpectedVersion, SignerKeyID: v.Signer.KeyID, SignerAlgorithm: v.Signer.Algorithm, MinimumRetention: 24 * time.Hour}
}

func encode(t testing.TB, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoldenContractsParse(t *testing.T) {
	backup := validBackup(t)
	if got, err := ParseBackupV3(encode(t, backup), testNow); err != nil || got.Snapshot() != backup {
		t.Fatalf("backup golden: got=%+v err=%v", got.Snapshot(), err)
	}
	evidence := validEvidence("INPUT_BOUND")
	parsed, err := ParseRestoreEvidenceV1(encode(t, evidence), evidenceContext(evidence))
	if err != nil || parsed.Snapshot().OperationID != evidence.OperationID || !isJournalHash(parsed.RawSHA256()) {
		t.Fatalf("evidence golden: got=%+v err=%v", parsed, err)
	}
	anchor := validAnchor()
	if _, err := ParseUnverifiedAnchorClaims(encode(t, anchor), anchorContext(anchor)); err != nil {
		t.Fatalf("anchor golden: %v", err)
	}
	checkpoint := validCheckpoint()
	if _, err := ParseUnverifiedReceiptCheckpointClaims(encode(t, checkpoint), checkpointContext(checkpoint)); err != nil {
		t.Fatalf("checkpoint golden: %v", err)
	}
}

func TestStrictJSONRejectsStructuralAmbiguity(t *testing.T) {
	valid := encode(t, validBackup(t))
	cases := map[string][]byte{
		"duplicate": bytes.Replace(valid, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1),
		"unknown":   bytes.Replace(valid, []byte(`"backupId":`), []byte(`"unknown":true,"backupId":`), 1),
		"null":      bytes.Replace(valid, []byte(`"backupId":"backup-0123456789abcdef0123456789abcdef"`), []byte(`"backupId":null`), 1),
		"float":     bytes.Replace(valid, []byte(fmt.Sprintf(`"createdUnix":%d`, testNow.Unix()-10)), []byte(`"createdUnix":1.5`), 1),
		"implicit":  bytes.Replace(valid, []byte(`"relationshipComplete":true`), []byte(`"relationshipComplete":"true"`), 1),
		"multiple":  append(append([]byte{}, valid...), valid...),
		"oversize":  []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
		"deep":      []byte(strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBackupV3(input, testNow); !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type jsonPathStep struct {
	key   string
	index int
	array bool
}

func collectJSONFieldPaths(value any, prefix []jsonPathStep, result *[][]jsonPathStep) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			path := append(append([]jsonPathStep(nil), prefix...), jsonPathStep{key: key})
			*result = append(*result, path)
			collectJSONFieldPaths(child, path, result)
		}
	case []any:
		for index, child := range typed {
			path := append(append([]jsonPathStep(nil), prefix...), jsonPathStep{index: index, array: true})
			collectJSONFieldPaths(child, path, result)
		}
	}
}

func deleteJSONField(t *testing.T, input []byte, target []jsonPathStep) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	current := value
	for _, step := range target[:len(target)-1] {
		if step.array {
			current = current.([]any)[step.index]
		} else {
			current = current.(map[string]any)[step.key]
		}
	}
	last := target[len(target)-1]
	if last.array {
		t.Fatal("field deletion path ended at array index")
	}
	delete(current.(map[string]any), last.key)
	return encode(t, value)
}

func TestEveryRequiredFieldDeletionRejected(t *testing.T) {
	backup := validBackup(t)
	evidence := validEvidence("INPUT_BOUND")
	anchor := validAnchor()
	checkpoint := validCheckpoint()
	documents := []struct {
		name  string
		bytes []byte
		parse func([]byte) error
	}{
		{"backup", encode(t, backup), func(data []byte) error { _, err := ParseBackupV3(data, testNow); return err }},
		{"evidence", encode(t, evidence), func(data []byte) error { _, err := ParseRestoreEvidenceV1(data, evidenceContext(evidence)); return err }},
		{"anchor", encode(t, anchor), func(data []byte) error {
			_, err := ParseUnverifiedAnchorClaims(data, anchorContext(anchor))
			return err
		}},
		{"checkpoint", encode(t, checkpoint), func(data []byte) error {
			_, err := ParseUnverifiedReceiptCheckpointClaims(data, checkpointContext(checkpoint))
			return err
		}},
	}
	for _, document := range documents {
		t.Run(document.name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal(document.bytes, &value); err != nil {
				t.Fatal(err)
			}
			var paths [][]jsonPathStep
			collectJSONFieldPaths(value, nil, &paths)
			if len(paths) < 10 {
				t.Fatalf("unexpectedly shallow fixture: %d fields", len(paths))
			}
			for index, fieldPath := range paths {
				last := fieldPath[len(fieldPath)-1]
				if last.array {
					continue
				}
				if err := document.parse(deleteJSONField(t, document.bytes, fieldPath)); !errors.Is(err, ErrInvalidDocument) {
					t.Fatalf("field deletion %d (%s) was accepted: %v", index, last.key, err)
				}
			}
		})
	}
}

func TestBackupSemanticBoundaries(t *testing.T) {
	cases := map[string]func(*BackupV3){
		"backup id":     func(v *BackupV3) { v.BackupID = "UPPER" },
		"path relative": func(v *BackupV3) { v.Candidate.CandidateRoot = "relative/path" },
		"path unclean":  func(v *BackupV3) { v.Candidate.CandidateRoot = testRoot() + "/../candidate" },
		"windows path":  func(v *BackupV3) { v.Candidate.CandidateRoot = `C:\ProgramData\candidate` },
		"unc path":      func(v *BackupV3) { v.Candidate.CandidateRoot = `\\server\candidate` },
		"mount target":  func(v *BackupV3) { v.Candidate.StateMountTarget = "/var/lib/../probe" },
		"digest":        func(v *BackupV3) { v.State.TreeSHA256 = strings.Repeat("a", 64) },
		"relationship":  func(v *BackupV3) { v.State.RelationshipComplete = false },
		"boot":          func(v *BackupV3) { v.SourceBootID = "not-a-boot-id" },
		"expired":       func(v *BackupV3) { v.ExpiresUnix = testNow.Unix() },
		"future":        func(v *BackupV3) { v.CreatedUnix = testNow.Unix() + 6; v.ExpiresUnix = testNow.Unix() + 60 },
		"lifetime":      func(v *BackupV3) { v.ExpiresUnix = v.CreatedUnix + maxBackupLifetime + 1 },
		"binding":       func(v *BackupV3) { v.Configuration.ConfigurationBindingSHA256 = hash('f') },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := validBackup(t)
			mutate(&v)
			if _, err := ParseBackupV3(encode(t, v), testNow); err == nil {
				t.Fatal("invalid backup accepted")
			}
		})
	}
}

func TestStateOnlyRejectsEveryBindingDifference(t *testing.T) {
	backup := validBackup(t)
	base := StateOnlyCurrent{Candidate: backup.Candidate, Configuration: backup.Configuration}
	parsed, err := ParseBackupV3(encode(t, backup), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.ValidateStateOnly(testNow, base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*StateOnlyCurrent){
		"candidate":        func(v *StateOnlyCurrent) { v.Candidate.CandidateID = "site-b" },
		"project":          func(v *StateOnlyCurrent) { v.Candidate.ProjectName = "probe-b" },
		"service":          func(v *StateOnlyCurrent) { v.Candidate.ServiceName = "probe-other" },
		"root":             func(v *StateOnlyCurrent) { v.Candidate.CandidateRoot += "-other" },
		"mount target":     func(v *StateOnlyCurrent) { v.Candidate.StateMountTarget += "-other" },
		"image id":         func(v *StateOnlyCurrent) { v.Configuration.ImageID = hash('a') },
		"manifest":         func(v *StateOnlyCurrent) { v.Configuration.ImageManifestDigest = hash('a') },
		"reference":        func(v *StateOnlyCurrent) { v.Configuration.ImageReference = "other/image:fixed" },
		"compose source":   func(v *StateOnlyCurrent) { v.Configuration.ComposeSourceSHA256 = hash('a') },
		"compose rendered": func(v *StateOnlyCurrent) { v.Configuration.ComposeRenderedSHA256 = hash('a') },
		"env":              func(v *StateOnlyCurrent) { v.Configuration.ProbeEnvSHA256 = hash('a') },
		"catalog":          func(v *StateOnlyCurrent) { v.Configuration.CatalogSHA256 = hash('a') },
		"ca":               func(v *StateOnlyCurrent) { v.Configuration.DotCASHA256 = hash('a') },
		"egress":           func(v *StateOnlyCurrent) { v.Configuration.EgressPolicySHA256 = hash('a') },
		"binding":          func(v *StateOnlyCurrent) { v.Configuration.ConfigurationBindingSHA256 = hash('a') },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			current := base
			mutate(&current)
			if err := parsed.ValidateStateOnly(testNow, current); err == nil || !strings.Contains(err.Error(), "state-only") {
				t.Fatalf("difference accepted: %v", err)
			}
		})
	}
}

func TestEveryEvidenceKindHasExactPhaseAndRequiredChecks(t *testing.T) {
	for _, kind := range EvidenceKinds() {
		t.Run(kind, func(t *testing.T) {
			v := validEvidence(kind)
			if _, err := ParseRestoreEvidenceV1(encode(t, v), evidenceContext(v)); err != nil {
				t.Fatal(err)
			}
			v.TargetPhase = "LOCKED"
			if evidencePhases[kind] == "LOCKED" {
				v.TargetPhase = "COMMITTED"
			}
			if _, err := ParseRestoreEvidenceV1(encode(t, v), evidenceContext(v)); err == nil {
				t.Fatal("kind/phase mismatch accepted")
			}
		})
	}
}

func TestEvidenceTopologyMatrix(t *testing.T) {
	if len(EvidenceKinds()) != 24 {
		t.Fatalf("kind count=%d", len(EvidenceKinds()))
	}
	allClasses := []topologyClass{topologyOldOnly, topologyOldNew, topologyNewOld}
	for _, kind := range EvidenceKinds() {
		t.Run(kind, func(t *testing.T) {
			contract := evidenceTopology[kind]
			for from := range contract.from {
				base := validEvidence(kind)
				base.FromPhase = from
				allowed := contract.classes
				if contract.allowAnyStructuredTopology {
					allowed = classes(topologyOldOnly, topologyOldNew, topologyNewOld)
				} else if contract.dynamic {
					allowed = phaseTopologyClasses(from)
				}
				for _, class := range allClasses {
					value := base
					value.Payload.Topology = topologyFor(class)
					_, err := ParseRestoreEvidenceV1(encode(t, value), evidenceContext(value))
					if allowed[class] && err != nil {
						t.Fatalf("from=%s allowed topology %s rejected: %v", from, class, err)
					}
					if !allowed[class] && err == nil {
						t.Fatalf("from=%s unsafe topology %s accepted", from, class)
					}
				}
				malformed := base
				malformed.Payload.Topology.Live.SHA256 = hash('f')
				_, err := ParseRestoreEvidenceV1(encode(t, malformed), evidenceContext(malformed))
				if contract.allowAnyStructuredTopology && err != nil {
					t.Fatalf("from=%s structured unknown topology rejected: %v", from, err)
				}
				if !contract.allowAnyStructuredTopology && err == nil {
					t.Fatalf("from=%s digest-unbound topology accepted", from)
				}
			}
			for _, phase := range JournalPhases() {
				if !contract.from[phase] {
					value := validEvidence(kind)
					value.FromPhase = phase
					if _, err := ParseRestoreEvidenceV1(encode(t, value), evidenceContext(value)); err == nil {
						t.Fatalf("invalid fromPhase %s accepted", phase)
					}
					break
				}
			}
		})
	}
}

func TestEvidenceTransitionsMatchProbeRestore(t *testing.T) {
	journalPhases := proberestore.Phases()
	wantPhases := make([]string, 0, len(journalPhases))
	for _, phase := range journalPhases {
		wantPhases = append(wantPhases, string(phase))
	}
	sort.Strings(wantPhases)
	if !reflect.DeepEqual(wantPhases, JournalPhases()) {
		t.Fatalf("phase drift: restorecontracts=%v proberestore=%v", JournalPhases(), wantPhases)
	}

	evidencePairs := map[string]string{}
	for kind, contract := range evidenceTopology {
		target := evidencePhases[kind]
		for from := range contract.from {
			key := from + "\x00" + target
			if previous, duplicate := evidencePairs[key]; duplicate {
				t.Fatalf("duplicate evidence transition %s -> %s: %s and %s", from, target, previous, kind)
			}
			evidencePairs[key] = kind
		}
	}
	for _, from := range journalPhases {
		for _, to := range journalPhases {
			_, hasEvidence := evidencePairs[string(from)+"\x00"+string(to)]
			if hasEvidence != proberestore.CanTransition(from, to) {
				t.Fatalf("transition drift %s -> %s: evidence=%v journal=%v", from, to, hasEvidence, proberestore.CanTransition(from, to))
			}
		}
	}
}

func structuredUnknownTopologies() map[string]Topology {
	return map[string]Topology{
		"both absent":    {},
		"new single":     {Live: validStateObject('2')},
		"unknown single": {Live: validStateObject('a')},
		"stage only":     {Stage: validStateObject('b')},
		"same digest":    {Live: validStateObject('1'), Stage: validStateObject('1')},
		"unknown pair":   {Live: validStateObject('a'), Stage: validStateObject('b')},
	}
}

func TestRescueAndLockdownPreserveUnknownTopology(t *testing.T) {
	for _, kind := range []string{"RESCUE_REQUIRED", "LOCKDOWN_VERIFIED"} {
		for name, topology := range structuredUnknownTopologies() {
			t.Run(kind+"/"+name, func(t *testing.T) {
				value := validEvidence(kind)
				value.Payload.Topology = topology
				if _, err := ParseRestoreEvidenceV1(encode(t, value), evidenceContext(value)); err != nil {
					t.Fatalf("strictly shaped unknown topology rejected: %v", err)
				}
			})
		}
	}
	for _, kind := range []string{"INPUT_BOUND", "FAILURE_RECORDED"} {
		for name, topology := range structuredUnknownTopologies() {
			t.Run(kind+"/"+name, func(t *testing.T) {
				value := validEvidence(kind)
				value.Payload.Topology = topology
				if _, err := ParseRestoreEvidenceV1(encode(t, value), evidenceContext(value)); err == nil {
					t.Fatal("unknown topology accepted outside rescue/lockdown")
				}
			})
		}
	}
	for _, kind := range []string{"RESCUE_REQUIRED", "LOCKDOWN_VERIFIED"} {
		t.Run(kind+"/malformed", func(t *testing.T) {
			value := validEvidence(kind)
			value.Payload.Topology = Topology{Live: StateObject{Present: false, SHA256: hash('a')}}
			if _, err := ParseRestoreEvidenceV1(encode(t, value), evidenceContext(value)); err == nil {
				t.Fatal("malformed absent object accepted")
			}
		})
		t.Run(kind+"/context mismatch", func(t *testing.T) {
			value := validEvidence(kind)
			value.Payload.Topology = structuredUnknownTopologies()["unknown pair"]
			context := evidenceContext(value)
			context.Topology.Live.Inode++
			if _, err := ParseRestoreEvidenceV1(encode(t, value), context); err == nil {
				t.Fatal("unknown topology not bound to independent context")
			}
		})
	}
}

func TestEvidenceReasonPolicyMatchesJournal(t *testing.T) {
	lockdown := validEvidence("LOCKDOWN_VERIFIED")
	lockdown.ReasonCode = "OPERATOR_OVERRIDE"
	if _, err := ParseRestoreEvidenceV1(encode(t, lockdown), evidenceContext(lockdown)); err == nil {
		t.Fatal("lockdown with non-verification reason accepted")
	}
	for _, kind := range EvidenceKinds() {
		if kind == "LOCKDOWN_VERIFIED" {
			continue
		}
		value := validEvidence(kind)
		value.ReasonCode = "OPERATOR_APPROVED"
		if _, err := ParseRestoreEvidenceV1(encode(t, value), evidenceContext(value)); err != nil {
			t.Fatalf("journal-safe independent reason rejected for %s: %v", kind, err)
		}
	}
	invalid := validEvidence("INPUT_BOUND")
	invalid.ReasonCode = "not-safe"
	if _, err := ParseRestoreEvidenceV1(encode(t, invalid), evidenceContext(invalid)); err == nil {
		t.Fatal("journal-unsafe reason accepted")
	}

	journal, err := proberestore.New(
		"restore-01",
		proberestore.Identity{CandidateID: "site-a", ProjectID: "probe-a", BackupID: "backup-a"},
		proberestore.Digests{
			BackupManifestSHA256: strings.Repeat("1", 64), BindingSHA256: strings.Repeat("2", 64),
			OldStateSHA256: strings.Repeat("3", 64), NewStateSHA256: strings.Repeat("4", 64),
		},
		testNow.Add(-time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Transition(proberestore.TransitionRequest{To: proberestore.PhaseLocked, ReasonCode: "OPERATOR_APPROVED", EvidenceSHA256: strings.Repeat("5", 64), At: testNow}); err != nil {
		t.Fatalf("journal rejected general safe reason: %v", err)
	}
	rescueJournal, err := journal.Transition(proberestore.TransitionRequest{To: proberestore.PhaseRescueRequired, ReasonCode: "AUTOMATIC_RECOVERY_UNSAFE", EvidenceSHA256: strings.Repeat("6", 64), At: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rescueJournal.Transition(proberestore.TransitionRequest{To: proberestore.PhaseRescueLockdown, ReasonCode: "OPERATOR_OVERRIDE", EvidenceSHA256: strings.Repeat("7", 64), At: testNow}); !errors.Is(err, proberestore.ErrInvalidTransition) {
		t.Fatalf("journal accepted non-verification lockdown reason: %v", err)
	}
	if _, err := rescueJournal.Transition(proberestore.TransitionRequest{To: proberestore.PhaseRescueLockdown, ReasonCode: "LOCKDOWN_VERIFIED", EvidenceSHA256: strings.Repeat("7", 64), At: testNow}); err != nil {
		t.Fatalf("journal rejected verified lockdown reason: %v", err)
	}
}

func TestValidatedObjectsAreOpaqueSnapshots(t *testing.T) {
	backup := validBackup(t)
	parsed, err := ParseBackupV3(encode(t, backup), testNow)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := parsed.Snapshot()
	snapshot.BackupID = "backup-ffffffffffffffffffffffffffffffff"
	if parsed.Snapshot().BackupID != backup.BackupID {
		t.Fatal("backup snapshot mutated parsed object")
	}
	if err := parsed.ValidateStateOnly(testNow, StateOnlyCurrent{Candidate: backup.Candidate, Configuration: backup.Configuration}); err != nil {
		t.Fatal(err)
	}
	if err := (ParsedBackupV3{}).ValidateStateOnly(testNow, StateOnlyCurrent{}); err == nil {
		t.Fatal("zero parsed backup validated")
	}

	evidence := validEvidence("INPUT_BOUND")
	parsedEvidence, err := ParseRestoreEvidenceV1(encode(t, evidence), evidenceContext(evidence))
	if err != nil {
		t.Fatal(err)
	}
	evidenceSnapshot := parsedEvidence.Snapshot()
	evidenceSnapshot.OperationID = "restore-mutated"
	evidenceSnapshot.Payload.Checks[0].Name = "MUTATED"
	if parsedEvidence.Snapshot().OperationID != evidence.OperationID {
		t.Fatal("evidence snapshot mutated parsed object")
	}
	if parsedEvidence.Snapshot().Payload.Checks[0].Name != evidence.Payload.Checks[0].Name {
		t.Fatal("evidence check slice mutated parsed object")
	}
	anchor := validAnchor()
	claims, err := ParseUnverifiedAnchorClaims(encode(t, anchor), anchorContext(anchor))
	if err != nil {
		t.Fatal(err)
	}
	anchorSnapshot := claims.Snapshot()
	anchorSnapshot.Generation++
	if claims.Snapshot().Generation != anchor.Generation {
		t.Fatal("anchor claim snapshot mutated opaque claims")
	}
}

func TestEvidenceContextFreshnessBootAndRawDigest(t *testing.T) {
	v := validEvidence("INPUT_BOUND")
	cases := map[string]func(*EvidenceContext){
		"operation":          func(c *EvidenceContext) { c.OperationID = "restore-other" },
		"sequence":           func(c *EvidenceContext) { c.TransitionSequence++ },
		"from":               func(c *EvidenceContext) { c.FromPhase = "COMMITTED" },
		"kind":               func(c *EvidenceContext) { c.Kind = "LOCK_ACQUIRED" },
		"reason":             func(c *EvidenceContext) { c.ReasonCode = "OTHER_REASON" },
		"phase":              func(c *EvidenceContext) { c.TargetPhase = "COMMITTED" },
		"head":               func(c *EvidenceContext) { c.PreviousJournalHeadSHA256 = strings.Repeat("0", 64) },
		"boot":               func(c *EvidenceContext) { c.BootID = "223e4567-e89b-42d3-a456-426614174000" },
		"candidate":          func(c *EvidenceContext) { c.Candidate.CandidateID = "site-b" },
		"binding":            func(c *EvidenceContext) { c.Binding.BackupID = "backup-2123456789abcdef0123456789abcdef" },
		"subject":            func(c *EvidenceContext) { c.SubjectSHA256 = hash('a') },
		"collector":          func(c *EvidenceContext) { c.Collector.Name = "other-collector" },
		"topology":           func(c *EvidenceContext) { c.Topology.Live.Inode++ },
		"raw bytes":          func(c *EvidenceContext) { c.RawBytesSHA256 = strings.Repeat("0", 64) },
		"future boottime":    func(c *EvidenceContext) { c.CurrentBoottimeNS = v.BoottimeNS - 1 },
		"stale boottime":     func(c *EvidenceContext) { c.CurrentBoottimeNS = v.BoottimeNS + uint64(3*time.Second) },
		"zero max boottime":  func(c *EvidenceContext) { c.MaxBoottimeAgeNS = 0 },
		"unbounded boottime": func(c *EvidenceContext) { c.MaxBoottimeAgeNS = maxEvidenceAgeNS + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			context := evidenceContext(v)
			mutate(&context)
			if _, err := ParseRestoreEvidenceV1(encode(t, v), context); err == nil {
				t.Fatal("context mismatch accepted")
			}
		})
	}

	data := encode(t, v)
	first, err := ParseRestoreEvidenceV1(data, evidenceContext(v))
	if err != nil {
		t.Fatal(err)
	}
	spaced := append([]byte(" \n"), data...)
	spacedContext := evidenceContext(v)
	spacedContext.RawBytesSHA256 = rawDigestBytes(spaced)
	second, err := ParseRestoreEvidenceV1(spaced, spacedContext)
	if err != nil {
		t.Fatal(err)
	}
	if first.RawSHA256() == second.RawSHA256() {
		t.Fatal("raw-byte digest ignored byte-level evidence identity")
	}

	stale := v
	stale.ExpiresUnix = testNow.Unix()
	if _, err := ParseRestoreEvidenceV1(encode(t, stale), evidenceContext(stale)); err == nil {
		t.Fatal("stale evidence accepted")
	}
	badTopology := v
	badTopology.Payload.Topology.Live.Present = false
	if _, err := ParseRestoreEvidenceV1(encode(t, badTopology), evidenceContext(badTopology)); err == nil {
		t.Fatal("absent topology object with identity accepted")
	}
	missing := v
	missing.Payload.Checks = missing.Payload.Checks[:1]
	if len(requiredChecks[v.Kind]) > 1 {
		if _, err := ParseRestoreEvidenceV1(encode(t, missing), evidenceContext(missing)); err == nil {
			t.Fatal("missing required check accepted")
		}
	}
}

func TestAnchorClaimsRequireTrustedContext(t *testing.T) {
	v := validAnchor()
	if _, err := ParseUnverifiedAnchorClaims(encode(t, v), anchorContext(v)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*RestoreAnchorV1, *AnchorContext){
		"candidate mismatch":        func(_ *RestoreAnchorV1, c *AnchorContext) { c.CandidateID = "site-b" },
		"operation mismatch":        func(_ *RestoreAnchorV1, c *AnchorContext) { c.OperationID = "restore-other" },
		"zero current time":         func(_ *RestoreAnchorV1, c *AnchorContext) { c.Now = time.Time{} },
		"local backend":             func(v *RestoreAnchorV1, _ *AnchorContext) { v.WORM.BackendClass = "LOCAL_FILE" },
		"not independent":           func(v *RestoreAnchorV1, _ *AnchorContext) { v.WORM.Independent = false },
		"no CAS advance":            func(v *RestoreAnchorV1, _ *AnchorContext) { v.CAS.CommittedVersion = v.CAS.ExpectedVersion },
		"generation mismatch":       func(_ *RestoreAnchorV1, c *AnchorContext) { c.Generation++ },
		"previous mismatch":         func(_ *RestoreAnchorV1, c *AnchorContext) { c.PreviousAnchorSHA256 = hash('0') },
		"boot mismatch":             func(_ *RestoreAnchorV1, c *AnchorContext) { c.BootID = "223e4567-e89b-42d3-a456-426614174000" },
		"journal mismatch":          func(_ *RestoreAnchorV1, c *AnchorContext) { c.JournalHeadSHA256 = strings.Repeat("0", 64) },
		"phase mismatch":            func(_ *RestoreAnchorV1, c *AnchorContext) { c.Phase = "COMMITTED" },
		"backup mismatch":           func(_ *RestoreAnchorV1, c *AnchorContext) { c.BackupID = "backup-2123456789abcdef0123456789abcdef" },
		"manifest mismatch":         func(_ *RestoreAnchorV1, c *AnchorContext) { c.BackupManifestSHA256 = hash('0') },
		"control mismatch":          func(_ *RestoreAnchorV1, c *AnchorContext) { c.ControlRecordSHA256 = hash('0') },
		"receipt root mismatch":     func(_ *RestoreAnchorV1, c *AnchorContext) { c.ReceiptAccumulatorSHA256 = hash('0') },
		"backend class mismatch":    func(_ *RestoreAnchorV1, c *AnchorContext) { c.BackendClass = "HARDWARE_MONOTONIC" },
		"CAS backend mismatch":      func(_ *RestoreAnchorV1, c *AnchorContext) { c.CASBackendID = "other-cas" },
		"CAS key mismatch":          func(_ *RestoreAnchorV1, c *AnchorContext) { c.CASObjectKey = "candidate/other" },
		"CAS version mismatch":      func(_ *RestoreAnchorV1, c *AnchorContext) { c.CASExpectedVersion = "v40" },
		"WORM backend mismatch":     func(_ *RestoreAnchorV1, c *AnchorContext) { c.WORMBackendID = "other-worm" },
		"WORM key mismatch":         func(_ *RestoreAnchorV1, c *AnchorContext) { c.WORMObjectKey = "candidate/other" },
		"signer key mismatch":       func(_ *RestoreAnchorV1, c *AnchorContext) { c.SignerKeyID = "other-key" },
		"signer algorithm mismatch": func(_ *RestoreAnchorV1, c *AnchorContext) { c.SignerAlgorithm = "ECDSA_P256_SHA256" },
		"zero max age":              func(_ *RestoreAnchorV1, c *AnchorContext) { c.MaxAge = 0 },
		"unbounded max age":         func(_ *RestoreAnchorV1, c *AnchorContext) { c.MaxAge = maxClaimsAge + time.Second },
		"zero retention":            func(_ *RestoreAnchorV1, c *AnchorContext) { c.MinimumRetention = 0 },
		"unbounded retention":       func(_ *RestoreAnchorV1, c *AnchorContext) { c.MinimumRetention = maxMinimumRetention + time.Second },
		"short retention":           func(v *RestoreAnchorV1, _ *AnchorContext) { v.WORM.RetentionUntilUnix = testNow.Add(time.Hour).Unix() },
		"invalid base64":            func(v *RestoreAnchorV1, _ *AnchorContext) { v.Signature = strings.Repeat("!", 88) },
		"wrong ED25519 length": func(v *RestoreAnchorV1, _ *AnchorContext) {
			v.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63))
		},
		"stale": func(v *RestoreAnchorV1, _ *AnchorContext) {
			v.CreatedUnix = testNow.Add(-10*time.Minute - time.Second).Unix()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value, context := validAnchor(), anchorContext(validAnchor())
			mutate(&value, &context)
			if _, err := ParseUnverifiedAnchorClaims(encode(t, value), context); err == nil {
				t.Fatal("invalid anchor accepted")
			}
		})
	}
	ecdsa := validAnchor()
	ecdsa.Signer.Algorithm = "ECDSA_P256_SHA256"
	ecdsa.Signature = "MAYCAQECAQE="
	if _, err := ParseUnverifiedAnchorClaims(encode(t, ecdsa), anchorContext(ecdsa)); err != nil {
		t.Fatalf("structurally valid ECDSA claim rejected: %v", err)
	}
	ecdsa.Signature = "MAMCAQE="
	if _, err := ParseUnverifiedAnchorClaims(encode(t, ecdsa), anchorContext(ecdsa)); err == nil {
		t.Fatal("malformed ECDSA DER claim accepted")
	}
}

func TestCheckpointClaimsRequireIndependentIndexes(t *testing.T) {
	v := validCheckpoint()
	if _, err := ParseUnverifiedReceiptCheckpointClaims(encode(t, v), checkpointContext(v)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ReceiptCheckpointV1, *CheckpointContext){
		"candidate mismatch": func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.CandidateID = "site-b" },
		"zero current time":  func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.Now = time.Time{} },
		"operation count":    func(v *ReceiptCheckpointV1, _ *CheckpointContext) { v.Indexes.Operations.Count-- },
		"backup count":       func(v *ReceiptCheckpointV1, _ *CheckpointContext) { v.Indexes.Backups.Count-- },
		"manifest count":     func(v *ReceiptCheckpointV1, _ *CheckpointContext) { v.Indexes.Manifests.Count-- },
		"duplicate object key": func(v *ReceiptCheckpointV1, c *CheckpointContext) {
			v.Indexes.Backups.ObjectKey = v.Indexes.Operations.ObjectKey
			c.Indexes = v.Indexes
		},
		"through ahead":          func(v *ReceiptCheckpointV1, _ *CheckpointContext) { v.ThroughGeneration = v.CheckpointGeneration + 1 },
		"anchor mismatch":        func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.AnchorSHA256 = hash('0') },
		"previous mismatch":      func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.PreviousCheckpointSHA256 = hash('0') },
		"generation mismatch":    func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.CheckpointGeneration++ },
		"through mismatch":       func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.ThroughGeneration++ },
		"receipt count mismatch": func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.ReceiptCount++ },
		"receipt root mismatch":  func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.ReceiptAccumulatorSHA256 = hash('0') },
		"index backend mismatch": func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.Indexes.Operations.BackendID = "other-index" },
		"index key mismatch":     func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.Indexes.Backups.ObjectKey = "indexes/other" },
		"index version mismatch": func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.Indexes.Manifests.ObjectVersion = "index-v99" },
		"index root mismatch":    func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.Indexes.Operations.RootSHA256 = hash('0') },
		"CAS backend mismatch":   func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.CASBackendID = "other-cas" },
		"CAS key mismatch":       func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.CASObjectKey = "candidate/other" },
		"CAS version mismatch":   func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.CASExpectedVersion = "v40" },
		"WORM backend mismatch":  func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.WORMBackendID = "other-worm" },
		"WORM key mismatch":      func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.WORMObjectKey = "candidate/other" },
		"signer mismatch":        func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.SignerKeyID = "other-key" },
		"zero max age":           func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.MaxAge = 0 },
		"unbounded max age":      func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.MaxAge = maxClaimsAge + time.Second },
		"zero retention":         func(_ *ReceiptCheckpointV1, c *CheckpointContext) { c.MinimumRetention = 0 },
		"short retention": func(v *ReceiptCheckpointV1, _ *CheckpointContext) {
			v.WORM.RetentionUntilUnix = testNow.Add(time.Hour).Unix()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value, context := validCheckpoint(), checkpointContext(validCheckpoint())
			mutate(&value, &context)
			if _, err := ParseUnverifiedReceiptCheckpointClaims(encode(t, value), context); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
}

func TestAnchorAndCheckpointBoundaries(t *testing.T) {
	anchor := validAnchor()
	anchor.CreatedUnix = testNow.Add(-maxClaimsAge).Unix()
	anchor.WORM.RetentionUntilUnix = testNow.Add(maxMinimumRetention).Unix()
	anchorCtx := anchorContext(anchor)
	anchorCtx.MaxAge = maxClaimsAge
	anchorCtx.MinimumRetention = maxMinimumRetention
	if _, err := ParseUnverifiedAnchorClaims(encode(t, anchor), anchorCtx); err != nil {
		t.Fatalf("inclusive anchor boundaries rejected: %v", err)
	}

	checkpoint := validCheckpoint()
	checkpoint.CheckpointGeneration = ^uint64(0)
	checkpoint.ThroughGeneration = ^uint64(0)
	checkpoint.ReceiptCount = MaxReceiptCount
	checkpoint.Indexes.Operations.Count = MaxReceiptCount
	checkpoint.Indexes.Backups.Count = MaxReceiptCount
	checkpoint.Indexes.Manifests.Count = MaxReceiptCount
	checkpoint.WORM.RetentionUntilUnix = testNow.Add(maxMinimumRetention).Unix()
	checkpointCtx := checkpointContext(checkpoint)
	checkpointCtx.MaxAge = maxClaimsAge
	checkpointCtx.MinimumRetention = maxMinimumRetention
	if _, err := ParseUnverifiedReceiptCheckpointClaims(encode(t, checkpoint), checkpointCtx); err != nil {
		t.Fatalf("inclusive checkpoint boundaries rejected: %v", err)
	}

	anchor.WORM.RetentionUntilUnix = maxUnix + 1
	if _, err := ParseUnverifiedAnchorClaims(encode(t, anchor), anchorContext(anchor)); err == nil {
		t.Fatal("retention past supported Unix range accepted")
	}
}

func FuzzParseBackupV3NeverPanics(f *testing.F) {
	f.Add(encode(f, validBackup(f)))
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseBackupV3(input, testNow)
	})
}

func TestParsedBackupV3RetainsExactRawDigest(t *testing.T) {
	v := validBackup(t)
	compact, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ParseBackupV3(compact, testNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseBackupV3(indented, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if first.RawSHA256() != rawDigestBytes(compact) || second.RawSHA256() != rawDigestBytes(indented) {
		t.Fatal("parsed backup did not retain the exact raw-byte digest")
	}
	if first.RawSHA256() == second.RawSHA256() {
		t.Fatal("different raw encodings unexpectedly share a digest")
	}
}

func FuzzParseRestoreEvidenceV1NeverPanics(f *testing.F) {
	v := validEvidence("INPUT_BOUND")
	f.Add(encode(f, v))
	f.Add([]byte(`[]`))
	context := evidenceContext(v)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseRestoreEvidenceV1(input, context)
	})
}

func FuzzParseUnverifiedAnchorClaimsNeverPanics(f *testing.F) {
	v := validAnchor()
	f.Add(encode(f, v))
	f.Add([]byte(`{"schema":null}`))
	context := anchorContext(v)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseUnverifiedAnchorClaims(input, context)
	})
}

func FuzzParseUnverifiedReceiptCheckpointClaimsNeverPanics(f *testing.F) {
	v := validCheckpoint()
	f.Add(encode(f, v))
	f.Add([]byte(`[]`))
	context := checkpointContext(v)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseUnverifiedReceiptCheckpointClaims(input, context)
	})
}
