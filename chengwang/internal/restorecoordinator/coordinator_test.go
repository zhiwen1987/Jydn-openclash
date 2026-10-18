package restorecoordinator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"chengwang/internal/proberestore"
	"chengwang/internal/restorecontracts"
	"chengwang/internal/restoreevidence"
)

var coordinatorNow = time.Unix(1_800_000_000, 0).UTC()

func coordinatorDigest(ch byte) string { return "sha256:" + strings.Repeat(string(ch), 64) }

func coordinatorCandidate() restorecontracts.CandidateIdentity {
	return restorecontracts.CandidateIdentity{
		CandidateID: "site-a", ProjectName: "probe-a", ServiceName: "probe-agent",
		CandidateRoot: "/var/lib/chengwang/candidate", StateMountTarget: "/var/lib/chengwang-probe",
	}
}

func coordinatorConfiguration(t testing.TB) restorecontracts.ConfigurationBinding {
	t.Helper()
	v := restorecontracts.ConfigurationBinding{
		ImageID: coordinatorDigest('1'), ImageManifestDigest: coordinatorDigest('2'), ImageReference: "chengwang/probe@sha256:0123456789abcdef",
		ComposeSourceSHA256: coordinatorDigest('3'), ComposeRenderedSHA256: coordinatorDigest('4'), ProbeEnvSHA256: coordinatorDigest('5'),
		CatalogSHA256: coordinatorDigest('6'), DotCASHA256: coordinatorDigest('7'), EgressPolicySHA256: coordinatorDigest('8'),
	}
	binding, err := restorecontracts.ComputeConfigurationBinding(coordinatorCandidate(), v)
	if err != nil {
		t.Fatal(err)
	}
	v.ConfigurationBindingSHA256 = binding
	return v
}

func preparedFixture(t testing.TB) (PreparedOperation, []byte) {
	t.Helper()
	doc := restorecontracts.BackupV3{
		Schema: restorecontracts.BackupV3Schema, BackupID: "backup-0123456789abcdef0123456789abcdef",
		CreatedUnix: coordinatorNow.Unix() - 10, ExpiresUnix: coordinatorNow.Unix() + 300,
		SourceBootID: "123e4567-e89b-42d3-a456-426614174000", WasRunningBeforeQuiesce: true,
		Candidate: coordinatorCandidate(), Configuration: coordinatorConfiguration(t),
		State: restorecontracts.BackupState{ArchiveSHA256: coordinatorDigest('9'), TreeSHA256: coordinatorDigest('a'), ValidationReportSHA256: coordinatorDigest('b'), RelationshipComplete: true},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare("restore-01", raw, coordinatorNow, restorecontracts.StateOnlyCurrent{Candidate: doc.Candidate, Configuration: doc.Configuration}, coordinatorDigest('c'))
	if err != nil {
		t.Fatal(err)
	}
	return prepared, raw
}

type memoryJournalStore struct {
	journal *proberestore.Journal
	saves   int
	loadErr error
	saveErr error
}

func (s *memoryJournalStore) Load() (proberestore.Journal, error) {
	if s.loadErr != nil {
		return proberestore.Journal{}, s.loadErr
	}
	if s.journal == nil {
		return proberestore.Journal{}, os.ErrNotExist
	}
	return cloneJournal(*s.journal), nil
}
func (s *memoryJournalStore) Create(j proberestore.Journal) error {
	if s.journal != nil {
		return errors.New("already exists")
	}
	copy := cloneJournal(j)
	s.journal = &copy
	return nil
}
func (s *memoryJournalStore) Save(j proberestore.Journal) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	copy := cloneJournal(j)
	s.journal = &copy
	s.saves++
	return nil
}

type memoryEvidenceRecord struct {
	parsed      restorecontracts.ParsedEvidence
	raw         []byte
	digest      string
	reliability restoreevidence.Reliability
	state       restoreevidence.CommitState
}

func (r memoryEvidenceRecord) Evidence() restorecontracts.ParsedEvidence { return r.parsed }
func (r memoryEvidenceRecord) RawSHA256() string                         { return r.digest }
func (r memoryEvidenceRecord) Reliability() restoreevidence.Reliability  { return r.reliability }
func (r memoryEvidenceRecord) CommitState() restoreevidence.CommitState  { return r.state }
func (r memoryEvidenceRecord) RawBytes() []byte                          { return append([]byte(nil), r.raw...) }

type memoryEvidenceStore struct {
	records     map[string]memoryEvidenceRecord
	publishes   int
	reads       int
	reliability restoreevidence.Reliability
	state       restoreevidence.CommitState
	publishErr  error
	readErr     error
}

func (s *memoryEvidenceStore) parse(raw []byte, context restorecontracts.EvidenceContext) (memoryEvidenceRecord, error) {
	var doc restorecontracts.RestoreEvidenceV1
	if err := json.Unmarshal(raw, &doc); err != nil {
		return memoryEvidenceRecord{}, err
	}
	context.Now = coordinatorNow
	context.CurrentBoottimeNS = doc.BoottimeNS + uint64(time.Second)
	context.MaxBoottimeAgeNS = uint64(2 * time.Second)
	parsed, err := restorecontracts.ParseRestoreEvidenceV1(raw, context)
	if err != nil {
		return memoryEvidenceRecord{}, err
	}
	reliability := s.reliability
	if reliability == "" {
		reliability = restoreevidence.ReliabilityLinuxDurable
	}
	state := s.state
	if state == "" {
		state = restoreevidence.Committed
	}
	return memoryEvidenceRecord{parsed: parsed, raw: append([]byte(nil), raw...), digest: sha256Hex(raw), reliability: reliability, state: state}, nil
}
func (s *memoryEvidenceStore) Publish(raw []byte, context restorecontracts.EvidenceContext) (evidenceRecord, error) {
	s.publishes++
	if s.publishErr != nil {
		return memoryEvidenceRecord{}, s.publishErr
	}
	record, err := s.parse(raw, context)
	if err != nil {
		return memoryEvidenceRecord{}, err
	}
	if s.records == nil {
		s.records = map[string]memoryEvidenceRecord{}
	}
	s.records[context.RawBytesSHA256] = record
	return record, nil
}
func (s *memoryEvidenceStore) Read(context restorecontracts.EvidenceContext) (evidenceRecord, error) {
	s.reads++
	if s.readErr != nil {
		return memoryEvidenceRecord{}, s.readErr
	}
	record, exists := s.records[context.RawBytesSHA256]
	if !exists {
		return memoryEvidenceRecord{}, os.ErrNotExist
	}
	return s.parse(record.raw, context)
}

func transitionEvidence(t testing.TB, prepared PreparedOperation, journal proberestore.Journal, kind string) TransitionInput {
	t.Helper()
	from, to, resolvedKind, reason, _, err := requestedTransition(journal.Phase, kind)
	if err != nil || journal.Phase != from {
		t.Fatalf("cannot build transition %s from %s: %v", kind, journal.Phase, err)
	}
	topology := restorecontracts.Topology{
		Live: restorecontracts.StateObject{Present: true, SHA256: prepared.binding.OldStateTreeSHA256, Device: 1, Inode: 10, MountID: 2},
	}
	checks := map[string][]string{
		"LOCK_ACQUIRED":    {"LIFECYCLE_LOCK_UNIQUE", "JOURNAL_WRITER_LOCK_UNIQUE"},
		"INPUT_BOUND":      {"BACKUP_V3_VALID", "STATE_ONLY_BINDING_EQUAL"},
		"FAILURE_RECORDED": {"FAILURE_EVIDENCE_DURABLE"},
	}[resolvedKind]
	evidenceChecks := make([]restorecontracts.EvidenceCheck, 0, len(checks))
	for i, name := range checks {
		evidenceChecks = append(evidenceChecks, restorecontracts.EvidenceCheck{Name: name, Passed: true, EvidenceSHA256: coordinatorDigest(byte('d' + i))})
	}
	collector := restorecontracts.Collector{Name: "restore-coordinator", Version: "1.0.0", BinarySHA256: coordinatorDigest('f')}
	subject := coordinatorDigest('e')
	doc := restorecontracts.RestoreEvidenceV1{
		Schema: restorecontracts.RestoreEvidenceV1Schema, Kind: resolvedKind, OperationID: journal.OperationID,
		TransitionSequence: journal.Sequence + 1, FromPhase: string(from), TargetPhase: string(to), ReasonCode: reason,
		PreviousJournalHeadSHA256: journal.Events[len(journal.Events)-1].Hash,
		CapturedUnix:              coordinatorNow.Unix(), ExpiresUnix: coordinatorNow.Unix() + 20,
		BootID: "123e4567-e89b-42d3-a456-426614174000", BoottimeNS: uint64(99 * time.Second),
		Candidate: prepared.candidate, Binding: prepared.binding, Collector: collector,
		PayloadSchema: "chengwang.probe-restore-evidence." + strings.ToLower(strings.ReplaceAll(resolvedKind, "_", "-")) + "/v1",
		Payload:       restorecontracts.EvidencePayload{SubjectSHA256: subject, Topology: topology, Checks: evidenceChecks},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return TransitionInput{Kind: resolvedKind, RawEvidence: raw, BootID: doc.BootID, SubjectSHA256: subject, Collector: collector, Topology: topology}
}

func TestPrepareBindsExactBackupBytes(t *testing.T) {
	prepared, raw := preparedFixture(t)
	sum := sha256.Sum256(raw)
	if prepared.journal.Digests.BackupManifestSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("journal does not bind exact backup bytes")
	}
	if prepared.binding.BackupManifestSHA256 != "sha256:"+prepared.journal.Digests.BackupManifestSHA256 {
		t.Fatal("evidence binding and journal manifest digest diverged")
	}
}

func TestPrepareRejectsSameOldAndTargetState(t *testing.T) {
	prepared, raw := preparedFixture(t)
	doc := prepared.Binding()
	current := restorecontracts.StateOnlyCurrent{Candidate: prepared.Candidate(), Configuration: coordinatorConfiguration(t)}
	if _, err := Prepare("restore-02", raw, coordinatorNow, current, doc.NewStateTreeSHA256); !errors.Is(err, ErrInvalidPreparedOperation) {
		t.Fatalf("got %v", err)
	}
}

func TestCoordinatorAdvancesOnlyThroughInputVerified(t *testing.T) {
	prepared, _ := preparedFixture(t)
	journalStore := &memoryJournalStore{}
	evidenceStore := &memoryEvidenceStore{}
	coordinator, err := newWithStores(journalStore, evidenceStore)
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(prepared)
	if err != nil || created.Code() != OutcomeCreatedNew || created.Phase() != proberestore.PhaseNew {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	lockInput := transitionEvidence(t, prepared, created.Journal(), "LOCK_ACQUIRED")
	locked, err := coordinator.Advance(prepared, lockInput)
	if err != nil || locked.Code() != OutcomeAdvancedLocked || locked.Phase() != proberestore.PhaseLocked {
		t.Fatalf("lock=%+v err=%v", locked, err)
	}
	inputBound := transitionEvidence(t, prepared, locked.Journal(), "INPUT_BOUND")
	verified, err := coordinator.Advance(prepared, inputBound)
	if err != nil || verified.Code() != OutcomeAdvancedInputVerified || verified.Phase() != proberestore.PhaseInputVerified {
		t.Fatalf("input=%+v err=%v", verified, err)
	}
	publishes, saves := evidenceStore.publishes, journalStore.saves
	blocked, err := coordinator.Advance(prepared, TransitionInput{Kind: "LIVE_QUIESCED"})
	if err != nil || blocked.Code() != OutcomeBlockedBeforeLive || blocked.Phase() != proberestore.PhaseInputVerified {
		t.Fatalf("boundary=%+v err=%v", blocked, err)
	}
	if evidenceStore.publishes != publishes || journalStore.saves != saves {
		t.Fatal("live boundary touched an evidence or journal writer")
	}
}

func TestCoordinatorHasNoProductionConstructor(t *testing.T) {
	prepared, _ := preparedFixture(t)
	var coordinator *Coordinator
	if _, err := coordinator.Create(prepared); !errors.Is(err, ErrTrustedInputsUnavailable) {
		t.Fatalf("nil coordinator got %v", err)
	}
	coordinator = &Coordinator{}
	if _, err := coordinator.Advance(prepared, TransitionInput{}); !errors.Is(err, ErrTrustedInputsUnavailable) {
		t.Fatalf("zero coordinator got %v", err)
	}
}

func TestCoordinatorProductionSurfaceRemainsBlocked(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate coordinator source")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(source), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			if spec.Path.Value == `"os/exec"` || spec.Path.Value == `"net"` || strings.Contains(spec.Path.Value, "docker") {
				t.Fatalf("live execution dependency is forbidden in %s: %s", filepath.Base(path), spec.Path.Value)
			}
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !function.Name.IsExported() || function.Type.Results == nil {
				continue
			}
			returnsCoordinator := false
			ast.Inspect(function.Type.Results, func(node ast.Node) bool {
				if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "Coordinator" {
					returnsCoordinator = true
				}
				return true
			})
			if returnsCoordinator {
				t.Fatalf("exported Coordinator factory %s in %s is forbidden until trusted inputs exist", function.Name.Name, filepath.Base(path))
			}
		}
	}
}

func TestCoordinatorIdempotentAfterJournalCommit(t *testing.T) {
	prepared, _ := preparedFixture(t)
	journalStore := &memoryJournalStore{}
	evidenceStore := &memoryEvidenceStore{}
	coordinator, _ := newWithStores(journalStore, evidenceStore)
	_, _ = coordinator.Create(prepared)
	input := transitionEvidence(t, prepared, *journalStore.journal, "LOCK_ACQUIRED")
	first, err := coordinator.Advance(prepared, input)
	if err != nil {
		t.Fatal(err)
	}
	saves := journalStore.saves
	second, err := coordinator.Advance(prepared, input)
	if err != nil || second.Code() != OutcomeAlreadyApplied || second.Phase() != first.Phase() {
		t.Fatalf("retry=%+v err=%v", second, err)
	}
	if journalStore.saves != saves {
		t.Fatal("idempotent retry wrote another journal event")
	}
}

func TestCoordinatorRetriesEvidenceCommittedBeforeJournalSave(t *testing.T) {
	prepared, _ := preparedFixture(t)
	journalStore := &memoryJournalStore{}
	evidenceStore := &memoryEvidenceStore{}
	coordinator, _ := newWithStores(journalStore, evidenceStore)
	_, _ = coordinator.Create(prepared)
	input := transitionEvidence(t, prepared, *journalStore.journal, "LOCK_ACQUIRED")
	journalStore.saveErr = errors.New("injected save failure")
	if _, err := coordinator.Advance(prepared, input); err == nil {
		t.Fatal("injected journal failure was accepted")
	}
	if journalStore.journal.Phase != proberestore.PhaseNew || len(evidenceStore.records) != 1 {
		t.Fatal("failure did not preserve committed evidence and prior journal")
	}
	journalStore.saveErr = nil
	result, err := coordinator.Advance(prepared, input)
	if err != nil || result.Phase() != proberestore.PhaseLocked || result.Sequence() != 2 {
		t.Fatalf("retry=%+v err=%v", result, err)
	}
}

func TestCoordinatorRebuildsPreparedModelFromDurableIdentity(t *testing.T) {
	prepared, raw := preparedFixture(t)
	journalStore := &memoryJournalStore{}
	evidenceStore := &memoryEvidenceStore{}
	coordinator, _ := newWithStores(journalStore, evidenceStore)
	_, _ = coordinator.Create(prepared)
	input := transitionEvidence(t, prepared, *journalStore.journal, "LOCK_ACQUIRED")
	locked, err := coordinator.Advance(prepared, input)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := Prepare("restore-01", raw, coordinatorNow.Add(time.Second), restorecontracts.StateOnlyCurrent{
		Candidate: prepared.Candidate(), Configuration: coordinatorConfiguration(t),
	}, prepared.Binding().OldStateTreeSHA256)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := coordinator.Advance(rebuilt, input)
	if err != nil || confirmed.Code() != OutcomeAlreadyApplied || confirmed.Phase() != locked.Phase() {
		t.Fatalf("reconcile=%+v err=%v", confirmed, err)
	}
	if _, err := coordinator.Create(rebuilt); !errors.Is(err, ErrResumeRequired) {
		t.Fatalf("Create accepted non-NEW journal: %v", err)
	}
}

func TestCoordinatorIdempotenceRequiresExactTailEvent(t *testing.T) {
	prepared, _ := preparedFixture(t)
	journalStore := &memoryJournalStore{}
	evidenceStore := &memoryEvidenceStore{}
	coordinator, _ := newWithStores(journalStore, evidenceStore)
	_, _ = coordinator.Create(prepared)
	input := transitionEvidence(t, prepared, *journalStore.journal, "LOCK_ACQUIRED")
	if _, err := coordinator.Advance(prepared, input); err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(input.RawEvidence)
	alternate, err := prepared.journal.Transition(proberestore.TransitionRequest{
		To: proberestore.PhaseLocked, ReasonCode: "OTHER_REASON", EvidenceSHA256: digest, At: coordinatorNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	journalStore.journal = &alternate
	if _, err := coordinator.Advance(prepared, input); !errors.Is(err, ErrOperationMismatch) {
		t.Fatalf("different valid tail event got %v", err)
	}
}

func TestCoordinatorFailureRetryIsIdempotentFromEveryPreLivePhase(t *testing.T) {
	for _, target := range []proberestore.Phase{proberestore.PhaseNew, proberestore.PhaseLocked, proberestore.PhaseInputVerified} {
		t.Run(string(target), func(t *testing.T) {
			prepared, _ := preparedFixture(t)
			journalStore := &memoryJournalStore{}
			evidenceStore := &memoryEvidenceStore{}
			coordinator, _ := newWithStores(journalStore, evidenceStore)
			created, err := coordinator.Create(prepared)
			if err != nil {
				t.Fatal(err)
			}
			current := created
			if target == proberestore.PhaseLocked || target == proberestore.PhaseInputVerified {
				current, err = coordinator.Advance(prepared, transitionEvidence(t, prepared, current.Journal(), "LOCK_ACQUIRED"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if target == proberestore.PhaseInputVerified {
				current, err = coordinator.Advance(prepared, transitionEvidence(t, prepared, current.Journal(), "INPUT_BOUND"))
				if err != nil {
					t.Fatal(err)
				}
			}
			failure := transitionEvidence(t, prepared, current.Journal(), "FAILURE_RECORDED")
			failed, err := coordinator.Advance(prepared, failure)
			if err != nil || failed.Phase() != proberestore.PhaseFailed {
				t.Fatalf("failure transition=%+v err=%v", failed, err)
			}
			saves := journalStore.saves
			retried, err := coordinator.Advance(prepared, failure)
			if err != nil || retried.Code() != OutcomeAlreadyApplied || retried.Phase() != proberestore.PhaseFailed {
				t.Fatalf("failure retry=%+v err=%v", retried, err)
			}
			if journalStore.saves != saves {
				t.Fatal("failure retry appended another journal event")
			}
		})
	}
}

func TestCoordinatorRejectsDiagnosticOrUncommittedEvidence(t *testing.T) {
	for name, testCase := range map[string]struct {
		reliability restoreevidence.Reliability
		state       restoreevidence.CommitState
	}{
		"diagnostic":  {restoreevidence.ReliabilityDiagnostic, restoreevidence.Committed},
		"uncommitted": {restoreevidence.ReliabilityLinuxDurable, restoreevidence.NotCommitted},
		"uncertain":   {restoreevidence.ReliabilityLinuxDurable, restoreevidence.Uncertain},
	} {
		t.Run(name, func(t *testing.T) {
			prepared, _ := preparedFixture(t)
			journalStore := &memoryJournalStore{}
			evidenceStore := &memoryEvidenceStore{reliability: testCase.reliability, state: testCase.state}
			coordinator, _ := newWithStores(journalStore, evidenceStore)
			_, _ = coordinator.Create(prepared)
			input := transitionEvidence(t, prepared, *journalStore.journal, "LOCK_ACQUIRED")
			if _, err := coordinator.Advance(prepared, input); !errors.Is(err, ErrEvidenceNotDurable) {
				t.Fatalf("got %v", err)
			}
			if journalStore.saves != 0 {
				t.Fatal("journal advanced without durable evidence")
			}
		})
	}
}

func TestCoordinatorRejectsEveryIndependentContextMismatch(t *testing.T) {
	mutations := map[string]func(*TransitionInput){
		"boot":      func(input *TransitionInput) { input.BootID = "223e4567-e89b-42d3-a456-426614174000" },
		"subject":   func(input *TransitionInput) { input.SubjectSHA256 = coordinatorDigest('1') },
		"collector": func(input *TransitionInput) { input.Collector.BinarySHA256 = coordinatorDigest('2') },
		"topology":  func(input *TransitionInput) { input.Topology.Live.Inode++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			prepared, _ := preparedFixture(t)
			journalStore := &memoryJournalStore{}
			evidenceStore := &memoryEvidenceStore{}
			coordinator, _ := newWithStores(journalStore, evidenceStore)
			_, _ = coordinator.Create(prepared)
			input := transitionEvidence(t, prepared, *journalStore.journal, "LOCK_ACQUIRED")
			mutate(&input)
			if _, err := coordinator.Advance(prepared, input); err == nil {
				t.Fatal("mismatched context was accepted")
			}
			if journalStore.saves != 0 {
				t.Fatal("mismatched context advanced the journal")
			}
		})
	}
}

func TestCoordinatorAllowsOnlyExactPreLiveRequests(t *testing.T) {
	allowed := map[string]bool{
		"NEW/LOCK_ACQUIRED": true, "LOCKED/LOCK_ACQUIRED": true,
		"LOCKED/INPUT_BOUND": true, "INPUT_VERIFIED/INPUT_BOUND": true,
		"NEW/FAILURE_RECORDED": true, "LOCKED/FAILURE_RECORDED": true, "INPUT_VERIFIED/FAILURE_RECORDED": true,
		"FAILED/FAILURE_RECORDED":      true,
		"INPUT_VERIFIED/LIVE_QUIESCED": true,
	}
	for _, phase := range proberestore.Phases() {
		for _, kind := range restorecontracts.EvidenceKinds() {
			_, _, _, _, _, err := requestedTransition(phase, kind)
			if (err == nil) != allowed[string(phase)+"/"+kind] {
				t.Fatalf("phase=%s kind=%s err=%v", phase, kind, err)
			}
		}
	}
}

func TestCoordinatorActualTransitionSetIsExact(t *testing.T) {
	want := map[string]bool{
		"NEW/LOCKED": true, "LOCKED/INPUT_VERIFIED": true,
		"NEW/FAILED": true, "LOCKED/FAILED": true, "INPUT_VERIFIED/FAILED": true,
	}
	got := map[string]bool{}
	for _, from := range proberestore.Phases() {
		for _, kind := range []string{"LOCK_ACQUIRED", "INPUT_BOUND", "FAILURE_RECORDED"} {
			modelFrom, to, _, _, _, err := requestedTransition(from, kind)
			if err == nil && from == modelFrom && from != to {
				got[string(from)+"/"+string(to)] = true
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("transition count=%d want=%d got=%v", len(got), len(want), got)
	}
	for transition := range want {
		if !got[transition] {
			t.Fatalf("missing transition %s", transition)
		}
	}
}
