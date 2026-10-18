//go:build linux && restorecoordinator_root

package restorecoordinator

import (
	"encoding/json"
	"errors"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"chengwang/internal/proberestore"
	"chengwang/internal/restorecontracts"
	"chengwang/internal/restoreevidence"
)

const linuxClockBoottime = 7

func rootCoordinatorDirectory(t testing.TB) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("authoritative coordinator integration test requires uid 0")
	}
	root := os.Getenv("RESTORECOORDINATOR_ROOT_TEST_DIR")
	if root == "" || !pathpkg.IsAbs(root) || pathpkg.Clean(root) != root || root == "/root" || !strings.HasPrefix(root, "/root/") {
		t.Fatal("RESTORECOORDINATOR_ROOT_TEST_DIR must be a clean absolute directory below /root")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
		t.Fatal("root fixture must be root:root and not group/world writable")
	}
	dir, err := os.MkdirTemp(root, "case-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	if uint64(fs.Type) != 0xef53 && uint64(fs.Type) != 0x58465342 {
		t.Fatalf("fixture filesystem must be ext4 or XFS, got type=0x%x", uint64(fs.Type))
	}
	return dir
}

func rootClock(t testing.TB) (time.Time, string, uint64) {
	t.Helper()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, linuxClockBoottime, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	return time.Now().UTC(), strings.TrimSpace(string(boot)), uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func rootPrepared(t testing.TB, now time.Time) PreparedOperation {
	t.Helper()
	candidate := coordinatorCandidate()
	configuration := coordinatorConfiguration(t)
	doc := restorecontracts.BackupV3{
		Schema: restorecontracts.BackupV3Schema, BackupID: "backup-1123456789abcdef0123456789abcdef",
		CreatedUnix: now.Unix() - 10, ExpiresUnix: now.Unix() + 300,
		SourceBootID: "123e4567-e89b-42d3-a456-426614174000", WasRunningBeforeQuiesce: true,
		Candidate: candidate, Configuration: configuration,
		State: restorecontracts.BackupState{ArchiveSHA256: coordinatorDigest('9'), TreeSHA256: coordinatorDigest('a'), ValidationReportSHA256: coordinatorDigest('b'), RelationshipComplete: true},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare("restore-root-01", raw, now, restorecontracts.StateOnlyCurrent{Candidate: candidate, Configuration: configuration}, coordinatorDigest('c'))
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func rootTransitionInput(t testing.TB, prepared PreparedOperation, journal proberestore.Journal, kind string) TransitionInput {
	t.Helper()
	now, bootID, boottime := rootClock(t)
	from, to, resolvedKind, reason, _, err := requestedTransition(journal.Phase, kind)
	if err != nil {
		t.Fatal(err)
	}
	topology := restorecontracts.Topology{Live: restorecontracts.StateObject{
		Present: true, SHA256: prepared.binding.OldStateTreeSHA256, Device: 1, Inode: 10, MountID: 2,
	}}
	checkNames := map[string][]string{
		"LOCK_ACQUIRED": {"LIFECYCLE_LOCK_UNIQUE", "JOURNAL_WRITER_LOCK_UNIQUE"},
		"INPUT_BOUND":   {"BACKUP_V3_VALID", "STATE_ONLY_BINDING_EQUAL"},
	}[resolvedKind]
	checks := make([]restorecontracts.EvidenceCheck, 0, len(checkNames))
	for i, name := range checkNames {
		checks = append(checks, restorecontracts.EvidenceCheck{Name: name, Passed: true, EvidenceSHA256: coordinatorDigest(byte('d' + i))})
	}
	collector := restorecontracts.Collector{Name: "restore-coordinator", Version: "1.0.0", BinarySHA256: coordinatorDigest('f')}
	subject := coordinatorDigest('e')
	doc := restorecontracts.RestoreEvidenceV1{
		Schema: restorecontracts.RestoreEvidenceV1Schema, Kind: resolvedKind, OperationID: journal.OperationID,
		TransitionSequence: journal.Sequence + 1, FromPhase: string(from), TargetPhase: string(to), ReasonCode: reason,
		PreviousJournalHeadSHA256: journal.Events[len(journal.Events)-1].Hash,
		CapturedUnix:              now.Unix(), ExpiresUnix: now.Unix() + 20, BootID: bootID, BoottimeNS: boottime,
		Candidate: prepared.candidate, Binding: prepared.binding, Collector: collector,
		PayloadSchema: "chengwang.probe-restore-evidence." + strings.ToLower(strings.ReplaceAll(resolvedKind, "_", "-")) + "/v1",
		Payload:       restorecontracts.EvidencePayload{SubjectSHA256: subject, Topology: topology, Checks: checks},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return TransitionInput{Kind: resolvedKind, RawEvidence: raw, BootID: bootID, SubjectSHA256: subject, Collector: collector, Topology: topology}
}

func TestLinuxCoordinatorRealStoresStopBeforeLiveMutation(t *testing.T) {
	root := rootCoordinatorDirectory(t)
	journalDir := filepath.Join(root, "journal")
	evidenceDir := filepath.Join(root, "evidence")
	for _, dir := range []string{journalDir, evidenceDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	journalStore, err := proberestore.Open(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journalStore.Close() })
	evidenceStore, err := restoreevidence.Open(evidenceDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = evidenceStore.Close() })
	coordinator, err := newWithStores(journalStore, durableEvidenceStore{store: evidenceStore})
	if err != nil {
		t.Fatal(err)
	}
	now, _, _ := rootClock(t)
	prepared := rootPrepared(t, now)
	created, err := coordinator.Create(prepared)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := coordinator.Advance(prepared, rootTransitionInput(t, prepared, created.Journal(), "LOCK_ACQUIRED"))
	if err != nil {
		t.Fatal(err)
	}
	inputBound := rootTransitionInput(t, prepared, locked.Journal(), "INPUT_BOUND")
	verified, err := coordinator.Advance(prepared, inputBound)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Phase() != proberestore.PhaseInputVerified || verified.Sequence() != 3 {
		t.Fatalf("unexpected final pre-live journal: phase=%s sequence=%d", verified.Phase(), verified.Sequence())
	}
	blocked, err := coordinator.Advance(prepared, TransitionInput{Kind: "LIVE_QUIESCED"})
	if err != nil || blocked.Code() != OutcomeBlockedBeforeLive {
		t.Fatalf("live boundary was not blocked: outcome=%+v err=%v", blocked, err)
	}
	reopenedJournal, err := proberestore.Open(journalDir)
	if !errors.Is(err, proberestore.ErrStoreLocked) || reopenedJournal != nil {
		t.Fatalf("journal writer lock not retained: store=%v err=%v", reopenedJournal, err)
	}
	if err := journalStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := evidenceStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedJournal, err = proberestore.Open(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedJournal.Close() })
	reopenedEvidence, err := restoreevidence.Open(evidenceDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedEvidence.Close() })
	resumed, err := newWithStores(reopenedJournal, durableEvidenceStore{store: reopenedEvidence})
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := resumed.Advance(prepared, inputBound)
	if err != nil || confirmed.Code() != OutcomeAlreadyApplied || confirmed.Phase() != proberestore.PhaseInputVerified {
		t.Fatalf("reopen reconciliation failed: outcome=%+v err=%v", confirmed, err)
	}
}
