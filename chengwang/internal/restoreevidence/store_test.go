package restoreevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"chengwang/internal/restorecontracts"
)

var fixtureNow = time.Unix(1_800_000_000, 0).UTC()

const fixtureBootID = "123e4567-e89b-42d3-a456-426614174000"

func testDigest(ch byte) string { return "sha256:" + strings.Repeat(string(ch), 64) }

type testOptions struct {
	clock clockFunc
	fault faultInjector
}

func openForTest(dir string, options testOptions) (*Store, error) {
	return openWithOptions(dir, storeOptions{clock: options.clock, fault: options.fault})
}

func evidenceFixture(t testing.TB) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
	t.Helper()
	candidate := restorecontracts.CandidateIdentity{
		CandidateID: "site-a", ProjectName: "probe-a", ServiceName: "probe-agent",
		CandidateRoot: "/var/lib/chengwang/candidate", StateMountTarget: "/var/lib/chengwang-probe",
	}
	binding := restorecontracts.EvidenceBinding{
		BackupID: "backup-1123456789abcdef0123456789abcdef", BackupManifestSHA256: testDigest('e'),
		ConfigurationBindingSHA256: testDigest('f'), OldStateTreeSHA256: testDigest('1'), NewStateTreeSHA256: testDigest('2'),
	}
	topology := restorecontracts.Topology{
		Live:  restorecontracts.StateObject{Present: true, SHA256: binding.OldStateTreeSHA256, Device: 1, Inode: 10, MountID: 2},
		Stage: restorecontracts.StateObject{},
	}
	collector := restorecontracts.Collector{Name: "restore-coordinator", Version: "1.0.0", BinarySHA256: testDigest('3')}
	v := restorecontracts.RestoreEvidenceV1{
		Schema: restorecontracts.RestoreEvidenceV1Schema, Kind: "INPUT_BOUND", OperationID: "restore-01", TransitionSequence: 2,
		FromPhase: "LOCKED", TargetPhase: "INPUT_VERIFIED", ReasonCode: "INPUT_BOUND",
		PreviousJournalHeadSHA256: strings.Repeat("d", 64), CapturedUnix: fixtureNow.Unix() - 1, ExpiresUnix: fixtureNow.Unix() + 20,
		BootID: fixtureBootID, BoottimeNS: uint64(99 * time.Second), Candidate: candidate, Binding: binding, Collector: collector,
		PayloadSchema: "chengwang.probe-restore-evidence.input-bound/v1",
		Payload: restorecontracts.EvidencePayload{SubjectSHA256: testDigest('4'), Topology: topology, Checks: []restorecontracts.EvidenceCheck{
			{Name: "BACKUP_V3_VALID", Passed: true, EvidenceSHA256: testDigest('5')},
			{Name: "STATE_ONLY_BINDING_EQUAL", Passed: true, EvidenceSHA256: testDigest('6')},
		}},
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	rawHash := sha256.Sum256(raw)
	context := restorecontracts.EvidenceContext{
		Now: fixtureNow, OperationID: v.OperationID, TransitionSequence: v.TransitionSequence, FromPhase: v.FromPhase, Kind: v.Kind,
		ReasonCode: v.ReasonCode, TargetPhase: v.TargetPhase, PreviousJournalHeadSHA256: v.PreviousJournalHeadSHA256,
		BootID: v.BootID, CurrentBoottimeNS: uint64(100 * time.Second), MaxBoottimeAgeNS: uint64(2 * time.Second),
		Candidate: v.Candidate, Binding: v.Binding, SubjectSHA256: v.Payload.SubjectSHA256, Collector: v.Collector, Topology: v.Payload.Topology,
		RawBytesSHA256: hex.EncodeToString(rawHash[:]),
	}
	clock := clockSnapshot{Wall: fixtureNow, BootID: fixtureBootID, BoottimeNS: uint64(100 * time.Second)}
	return raw, context, clock
}

func TestClockObservationRejectsRollbackAndBootChange(t *testing.T) {
	t.Run("wall rollback", func(t *testing.T) {
		items := []clockSnapshot{{Wall: fixtureNow, BootID: fixtureBootID, BoottimeNS: 10}, {Wall: fixtureNow.Add(-time.Second), BootID: fixtureBootID, BoottimeNS: 11}}
		s := &Store{clock: func() (clockSnapshot, error) { v := items[0]; items = items[1:]; return v, nil }}
		if _, err := s.observeClock(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.observeClock(); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("boottime rollback", func(t *testing.T) {
		items := []clockSnapshot{{Wall: fixtureNow, BootID: fixtureBootID, BoottimeNS: 11}, {Wall: fixtureNow.Add(time.Second), BootID: fixtureBootID, BoottimeNS: 10}}
		s := &Store{clock: func() (clockSnapshot, error) { v := items[0]; items = items[1:]; return v, nil }}
		_, _ = s.observeClock()
		if _, err := s.observeClock(); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("boot changed", func(t *testing.T) {
		items := []clockSnapshot{{Wall: fixtureNow, BootID: fixtureBootID, BoottimeNS: 10}, {Wall: fixtureNow.Add(time.Second), BootID: "223e4567-e89b-42d3-a456-426614174000", BoottimeNS: 11}}
		s := &Store{clock: func() (clockSnapshot, error) { v := items[0]; items = items[1:]; return v, nil }}
		_, _ = s.observeClock()
		if _, err := s.observeClock(); !errors.Is(err, ErrBootMismatch) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestZeroStoreFailsClosed(t *testing.T) {
	raw, context, _ := evidenceFixture(t)
	var s *Store
	result, err := s.Publish(raw, context)
	if !errors.Is(err, ErrClosed) || result.CommitState() != NotCommitted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := s.Read(context); !errors.Is(err, ErrClosed) {
		t.Fatalf("read error=%v", err)
	}
}

func TestEvidenceNameRejectsPathSeparators(t *testing.T) {
	_, context, _ := evidenceFixture(t)
	for _, bad := range []string{"../restore", "a/b", `a\b`, "a\x00b"} {
		context.OperationID = bad
		if _, err := evidenceNameFromContext(context); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestResultRawBytesAreCopied(t *testing.T) {
	raw := []byte("evidence")
	r := Result{raw: append([]byte(nil), raw...)}
	copy := r.RawBytes()
	copy[0] = 'X'
	if string(r.RawBytes()) != "evidence" {
		t.Fatal("caller mutated retained raw evidence")
	}
}
