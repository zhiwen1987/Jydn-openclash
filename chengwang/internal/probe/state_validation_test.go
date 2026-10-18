package probe

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type stateValidationFixture struct {
	catalog Catalog
	spool   string
	ledger  string
	base    time.Time
	result  ProbeResult
}

func TestValidateStateSnapshotRoundTripIsReadOnlyAndRestartStable(t *testing.T) {
	fixture := createSettledStateFixture(t)
	before := snapshotTestTree(t, fixture.spool, fixture.ledger)
	first, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	after := snapshotTestTree(t, fixture.spool, fixture.ledger)
	if before != after {
		t.Fatal("read-only state validation changed the snapshot")
	}
	if first.SnapshotDigest != second.SnapshotDigest || first.Schema != StateValidationSchemaV1 || first.SpoolResults != 1 || first.LatestSettled != 1 || first.LatestInFlight != 0 || first.MissingRetainedEvidence != 0 || !first.RelationshipComplete || !first.AdvisoryOnly || !first.ReadOnlyValidation {
		t.Fatalf("unexpected validation reports: first=%+v second=%+v", first, second)
	}
}

func TestStateTreeDigestV1GoldenAndFieldBinding(t *testing.T) {
	entries := []stateTreeEntry{
		{relative: "ledger/.", digest: "directory", mode: os.ModeDir | 0o700, owner: 10001, group: 10001, nlink: 2, identity: "ignored-one"},
		{relative: "spool/segments/a.json", digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", size: 3, mode: 0o600, owner: 10001, group: 10001, nlink: 1, identity: "ignored-two"},
	}
	const expected = "sha256:a62b62b75b297d30df9978097711eb1a21db143be9acff842120ebc603f6a87a"
	if actual := digestStateTree(entries); actual != expected {
		t.Fatalf("state tree digest = %s, want frozen v1 golden %s", actual, expected)
	}
	identityOnly := append([]stateTreeEntry(nil), entries...)
	identityOnly[0].identity = "different-but-not-in-preimage"
	if actual := digestStateTree(identityOnly); actual != expected {
		t.Fatalf("identity unexpectedly entered v1 preimage: %s", actual)
	}
	mutations := map[string]func([]stateTreeEntry){
		"relative": func(value []stateTreeEntry) { value[1].relative += ".changed" },
		"size":     func(value []stateTreeEntry) { value[1].size++ },
		"mode":     func(value []stateTreeEntry) { value[1].mode = 0o400 },
		"owner":    func(value []stateTreeEntry) { value[1].owner++ },
		"group":    func(value []stateTreeEntry) { value[1].group++ },
		"nlink":    func(value []stateTreeEntry) { value[1].nlink++ },
		"digest":   func(value []stateTreeEntry) { value[1].digest = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := append([]stateTreeEntry(nil), entries...)
			mutate(changed)
			if actual := digestStateTree(changed); actual == expected {
				t.Fatalf("%s is not bound by the v1 digest", name)
			}
		})
	}
}

func TestStateValidationReportV1WireFieldsUnchanged(t *testing.T) {
	raw, err := json.Marshal(StateValidationReport{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"schema", "catalogDigest", "snapshotDigest", "readPathDigest", "ledgerWriterPathDigest",
		"relationshipScope", "spoolResults", "ledgerSnapshots", "latestSequence", "latestStarts",
		"latestInFlight", "latestSettled", "latestRateLimits", "advisoryOnly", "readOnlyValidation",
		"securityMetadataVerified", "ownerUid", "ownerGid", "expectedOwnerUid", "expectedOwnerGid",
		"missingRetainedEvidence", "relationshipComplete",
	}
	if len(fields) != len(expected) {
		t.Fatalf("v1 report field count = %d, want %d: %s", len(fields), len(expected), raw)
	}
	for _, name := range expected {
		if _, exists := fields[name]; !exists {
			t.Fatalf("v1 report field %q is missing", name)
		}
	}
	if _, exists := fields["stateTreeDigestSchema"]; exists {
		t.Fatal("v1 report unexpectedly serialized the digest schema identifier")
	}
}

func TestLockedStateSnapshotHoldsBothWriterLocksUntilClose(t *testing.T) {
	fixture := createSettledStateFixture(t)
	snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{}); !errors.Is(err, ErrSpoolLocked) {
		t.Fatalf("spool writer error = %v, want ErrSpoolLocked", err)
	}
	if _, err := OpenStartLedger(fixture.ledger, fixture.catalog, StartLedgerOptions{Now: func() time.Time { return fixture.base.Add(time.Second) }}); !errors.Is(err, ErrStartLedgerLocked) {
		t.Fatalf("ledger writer error = %v, want ErrStartLedgerLocked", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{})
	if err != nil {
		t.Fatalf("spool lock was not released: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenStartLedger(fixture.ledger, fixture.catalog, StartLedgerOptions{Now: func() time.Time { return fixture.base.Add(time.Second) }})
	if err != nil {
		t.Fatalf("ledger lock was not released: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockedStateSnapshotReleasesSpoolWhenLedgerLockFails(t *testing.T) {
	fixture := createSettledStateFixture(t)
	ledger, err := OpenStartLedger(fixture.ledger, fixture.catalog, StartLedgerOptions{Now: func() time.Time { return fixture.base.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if _, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
	}); !errors.Is(err, ErrSpoolLocked) {
		t.Fatalf("acquire error = %v, want underlying lock error", err)
	}
	store, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{})
	if err != nil {
		t.Fatalf("spool lock leaked after ledger acquisition failure: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockedStateSnapshotVerifyDetectsMutationAndPoisons(t *testing.T) {
	for _, stateTree := range []string{"spool", "ledger"} {
		t.Run(stateTree, func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
				Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer snapshot.Close()
			path := onlyTestFile(t, filepath.Join(fixture.spool, spoolSegmentsDirectory), ".json")
			if stateTree == "ledger" {
				path = onlyTestFile(t, filepath.Join(fixture.ledger, startLedgerSnapshotsDir), ".json")
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := append([]byte(nil), original...)
			changed[0] ^= 1
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := snapshot.Report(); err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("equal-length mutation report error = %v", err)
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := snapshot.Report(); err == nil || !strings.Contains(err.Error(), "poisoned") {
				t.Fatalf("poisoned report error = %v", err)
			}
			if err := snapshot.Verify(); err == nil || !strings.Contains(err.Error(), "poisoned") {
				t.Fatalf("poisoned verification error = %v", err)
			}
		})
	}
}

func TestLockedStateSnapshotSemanticFailureReleasesBothLocks(t *testing.T) {
	cases := []struct {
		name, errorContains string
		corrupt             func(*testing.T, stateValidationFixture)
	}{
		{"spool", "invalid probe spool", func(t *testing.T, fixture stateValidationFixture) {
			segment := onlyTestFile(t, filepath.Join(fixture.spool, spoolSegmentsDirectory), ".json")
			if err := os.WriteFile(segment, []byte(`{"schema":"unknown"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"ledger", "binding_invalid", func(t *testing.T, fixture stateValidationFixture) {
			mutateLatestLedgerSnapshot(t, fixture, func(state *startLedgerDisk) { state.Schema = "chengwang.probe-start-ledger/v999" })
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			testCase.corrupt(t, fixture)
			if _, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
				Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
			}); err == nil || !strings.Contains(err.Error(), testCase.errorContains) {
				t.Fatalf("semantic validation error = %v", err)
			}
			for _, lockPath := range []string{
				filepath.Join(fixture.spool, spoolLockFilename),
				filepath.Join(fixture.ledger, startLedgerLockFilename),
			} {
				if err := runStateLockAttemptHelper(lockPath); err != nil {
					t.Fatalf("validation failure leaked lock %s: %v", lockPath, err)
				}
			}
		})
	}
}

func TestLockedStateSnapshotDetectsLockPathReplacement(t *testing.T) {
	for _, stateTree := range []string{"spool", "ledger"} {
		t.Run(stateTree, func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
				Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer snapshot.Close()
			lockPath := filepath.Join(fixture.spool, spoolLockFilename)
			if stateTree == "ledger" {
				lockPath = filepath.Join(fixture.ledger, startLedgerLockFilename)
			}
			if err := os.Remove(lockPath); err != nil {
				t.Skipf("platform did not permit replacement of an open lock path: %v", err)
			}
			if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := snapshot.Verify(); err == nil || !strings.Contains(err.Error(), "verification failed") {
				t.Fatalf("lock replacement did not fail closed: %v", err)
			}
			if err := snapshot.Verify(); err == nil || !strings.Contains(err.Error(), "poisoned") {
				t.Fatalf("lock replacement did not sticky-poison the snapshot: %v", err)
			}
		})
	}
}

func TestLockedStateSnapshotSharedLifecycleAndCloseIdempotence(t *testing.T) {
	fixture := createSettledStateFixture(t)
	snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := snapshot.Report()
	if err != nil {
		t.Fatal(err)
	}
	if report.SnapshotDigest == "" || report.Schema != StateValidationSchemaV1 || StateTreeDigestSchemaV1 != "chengwang.probe-state-tree/v1" {
		t.Fatalf("unexpected report or digest schema: %+v", report)
	}
	alias := *snapshot
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("second close error = %v", err)
	}
	if _, err := snapshot.Report(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("report after alias close error = %v", err)
	}
	if err := snapshot.Verify(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("verify after alias close error = %v", err)
	}
}

func TestLockedStateSnapshotMatchesCompatibilityWrapper(t *testing.T) {
	fixture := createSettledStateFixture(t)
	options := StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(time.Second)}
	legacy, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, options)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, options)
	if err != nil {
		t.Fatal(err)
	}
	locked, reportErr := snapshot.Report()
	closeErr := snapshot.Close()
	if reportErr != nil || closeErr != nil {
		t.Fatal(errors.Join(reportErr, closeErr))
	}
	if !reflect.DeepEqual(legacy, locked) {
		t.Fatalf("compatibility report differs: legacy=%+v locked=%+v", legacy, locked)
	}
}

func TestLockedStateSnapshotDetectsRootRebinding(t *testing.T) {
	for _, stateTree := range []string{"spool", "ledger"} {
		t.Run(stateTree, func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
				Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer snapshot.Close()
			root := fixture.spool
			if stateTree == "ledger" {
				root = fixture.ledger
			}
			moved := root + "-moved"
			if err := os.Rename(root, moved); err != nil {
				t.Skipf("platform did not permit replacement of an open state root: %v", err)
			}
			copyTestTree(t, moved, root)
			if err := snapshot.Verify(); err == nil {
				t.Fatal("root rebinding unexpectedly verified")
			}
		})
	}
}

func TestLockedStateSnapshotNilAndZeroValuesFailClosed(t *testing.T) {
	var nilSnapshot *LockedStateSnapshot
	if _, err := nilSnapshot.Report(); err == nil {
		t.Fatal("nil report unexpectedly succeeded")
	}
	if err := nilSnapshot.Verify(); err == nil {
		t.Fatal("nil verify unexpectedly succeeded")
	}
	if err := nilSnapshot.Close(); err != nil {
		t.Fatalf("nil close error = %v", err)
	}
	zero := &LockedStateSnapshot{}
	if _, err := zero.Report(); err == nil {
		t.Fatal("zero report unexpectedly succeeded")
	}
	if err := zero.Verify(); err == nil {
		t.Fatal("zero verify unexpectedly succeeded")
	}
	if err := zero.Close(); err != nil {
		t.Fatalf("zero close error = %v", err)
	}
}

func TestLockedStateSnapshotConcurrentLifecycleIsSerialized(t *testing.T) {
	fixture := createSettledStateFixture(t)
	snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 24)
	for index := 0; index < 24; index++ {
		wait.Add(1)
		go func(operation int) {
			defer wait.Done()
			var operationErr error
			switch operation % 3 {
			case 0:
				_, operationErr = snapshot.Report()
			case 1:
				operationErr = snapshot.Verify()
			default:
				operationErr = snapshot.Close()
			}
			if operationErr != nil && !strings.Contains(operationErr.Error(), "closed") {
				errorsSeen <- operationErr
			}
		}(index)
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("unexpected concurrent lifecycle error: %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("final idempotent close error = %v", err)
	}
}

func TestLockedStateSnapshotInteroperatesWithWriterLocksAcrossProcesses(t *testing.T) {
	fixture := createSettledStateFixture(t)
	options := StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(time.Second)}
	spoolLock := filepath.Join(fixture.spool, spoolLockFilename)
	ledgerLock := filepath.Join(fixture.ledger, startLedgerLockFilename)

	t.Run("validator blocks both child writers and releases them", func(t *testing.T) {
		snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, options)
		if err != nil {
			t.Fatal(err)
		}
		for _, lockPath := range []string{spoolLock, ledgerLock} {
			if err := runStateLockAttemptHelper(lockPath); err == nil || !strings.Contains(err.Error(), "exit status 23") {
				t.Fatalf("child writer was not blocked for %s: %v", lockPath, err)
			}
		}
		if err := snapshot.Close(); err != nil {
			t.Fatal(err)
		}
		for _, lockPath := range []string{spoolLock, ledgerLock} {
			if err := runStateLockAttemptHelper(lockPath); err != nil {
				t.Fatalf("child writer remained blocked after close for %s: %v", lockPath, err)
			}
		}
	})

	t.Run("child ledger writer blocks validator without leaking spool lock", func(t *testing.T) {
		command, input := startStateLockHoldingHelper(t, ledgerLock)
		if _, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, options); !errors.Is(err, ErrSpoolLocked) {
			t.Fatalf("validator error = %v, want cross-process lock conflict", err)
		}
		if err := input.Close(); err != nil {
			t.Fatal(err)
		}
		if err := command.Wait(); err != nil {
			t.Fatalf("lock helper exit: %v", err)
		}
		snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, options)
		if err != nil {
			t.Fatalf("validator locks did not recover after child release: %v", err)
		}
		if err := snapshot.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLockedStateSnapshotDescriptorsDoNotSurviveExec(t *testing.T) {
	fixture := createSettledStateFixture(t)
	snapshot, err := AcquireLockedStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	command, input := startStateLockHoldingHelper(t, "")
	defer func() {
		_ = input.Close()
		_ = command.Wait()
	}()
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{})
	if err != nil {
		t.Fatalf("exec child inherited validator lock descriptor: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateValidationLockHelper(t *testing.T) {
	mode := os.Getenv("CHENGWANG_STATE_LOCK_HELPER")
	if mode == "" {
		return
	}
	if mode == "attempt-writer" {
		lock, err := acquireSpoolProcessLock(os.Args[len(os.Args)-1])
		if errors.Is(err, ErrSpoolLocked) {
			os.Exit(23)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(24)
		}
		if err := lock.release(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(25)
		}
		os.Exit(0)
	}
	if mode == "hold-writer" {
		lockPath := os.Args[len(os.Args)-1]
		var lock *spoolProcessLock
		var err error
		if lockPath != "" {
			lock, err = acquireSpoolProcessLock(lockPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(26)
			}
		}
		fmt.Println("READY")
		_, _ = io.Copy(io.Discard, os.Stdin)
		if lock != nil {
			if err := lock.release(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(27)
			}
		}
		os.Exit(0)
	}
	os.Exit(28)
}

func runStateLockAttemptHelper(lockPath string) error {
	command := exec.Command(os.Args[0], "-test.run=^TestStateValidationLockHelper$", "--", lockPath)
	command.Env = append(os.Environ(), "CHENGWANG_STATE_LOCK_HELPER=attempt-writer")
	return command.Run()
}

func startStateLockHoldingHelper(t *testing.T, lockPath string) (*exec.Cmd, io.WriteCloser) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestStateValidationLockHelper$", "--", lockPath)
	command.Env = append(os.Environ(), "CHENGWANG_STATE_LOCK_HELPER=hold-writer")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "READY" {
		_ = input.Close()
		_ = command.Wait()
		t.Fatalf("lock helper did not become ready: line=%q err=%v", line, err)
	}
	return command, input
}

func TestValidateStateSnapshotUsesExplicitWriterLedgerBindingForStagedCopy(t *testing.T) {
	fixture := createSettledStateFixture(t)
	staged := filepath.Join(t.TempDir(), "staged-ledger")
	copyTestTree(t, fixture.ledger, staged)
	// This is a namespace identity string only: it deliberately does not exist
	// on the host and is lexically below the host spool path. Neither fact may
	// affect validation; only its digest binding in the ledger matters.
	writerPath := filepath.Join(fixture.spool, "container-namespace-only", "ledger")
	stagedFixture := fixture
	stagedFixture.ledger = staged
	mutateLatestLedgerSnapshot(t, stagedFixture, func(state *startLedgerDisk) {
		state.DirectoryDigest = digestStartLedgerDirectory(writerPath)
	})
	report, err := ValidateStateSnapshot(fixture.spool, staged, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second), ExpectedLedgerWriterDirectory: writerPath,
	})
	if err != nil {
		t.Fatalf("staged snapshot did not validate against its writer binding: %v", err)
	}
	if report.LatestSettled != 1 {
		t.Fatalf("unexpected staged validation report: %+v", report)
	}
	wrongWriter := filepath.Join(t.TempDir(), "wrong-writer-ledger")
	if _, err := ValidateStateSnapshot(fixture.spool, staged, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second), ExpectedLedgerWriterDirectory: wrongWriter,
	}); err == nil || !strings.Contains(err.Error(), "binding_invalid") {
		t.Fatalf("wrong writer ledger binding error = %v", err)
	}
	if _, err := ValidateStateSnapshot(fixture.spool, staged, StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second), ExpectedLedgerWriterDirectory: "relative/writer",
	}); err == nil || !strings.Contains(err.Error(), "clean absolute") {
		t.Fatalf("relative writer ledger binding error = %v", err)
	}
}

func TestValidateStateSnapshotEnforcesExpectedOwnerFailClosed(t *testing.T) {
	fixture := createSettledStateFixture(t)
	info, err := os.Lstat(fixture.spool)
	if err != nil {
		t.Fatal(err)
	}
	owner, group, _, err := validateStateSecurity(info, true)
	if err != nil {
		t.Fatal(err)
	}
	options := StateValidationOptions{
		Catalog: fixture.catalog, Now: fixture.base.Add(time.Second),
		ExpectedOwnerUID: owner, ExpectedOwnerGID: group, EnforceExpectedOwner: true,
	}
	if !stateSecurityMetadataAvailable() {
		if _, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, options); err == nil || !strings.Contains(err.Error(), "ownership metadata is unavailable") {
			t.Fatalf("missing metadata error = %v", err)
		}
		return
	}
	report, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, options)
	if err != nil {
		t.Fatal(err)
	}
	if !report.SecurityMetadataVerified || report.OwnerUID != owner || report.OwnerGID != group {
		t.Fatalf("owner evidence missing from report: %+v", report)
	}
	options.ExpectedOwnerUID++
	if _, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, options); err == nil || !strings.Contains(err.Error(), "state owner") {
		t.Fatalf("wrong owner error = %v", err)
	}
}

func TestValidateStateSnapshotRejectsCorruptionAndUnknownSchema(t *testing.T) {
	t.Run("corrupt spool", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		segment := onlyTestFile(t, filepath.Join(fixture.spool, spoolSegmentsDirectory), ".json")
		if err := os.WriteFile(segment, []byte(`{"schema":"unknown"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		assertStateValidationFails(t, fixture, "invalid probe spool")
	})

	t.Run("unknown ledger schema", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		mutateLatestLedgerSnapshot(t, fixture, func(state *startLedgerDisk) { state.Schema = "chengwang.probe-start-ledger/v999" })
		assertStateValidationFails(t, fixture, "binding_invalid")
	})
}

func TestValidateStateSnapshotRejectsNonMonotonicRetainedLedgerClock(t *testing.T) {
	fixture := createSettledStateFixture(t)
	directory := filepath.Join(fixture.ledger, startLedgerSnapshotsDir)
	path := onlyTestFile(t, directory, ".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var prior startLedgerDisk
	if err := json.Unmarshal(raw, &prior); err != nil {
		t.Fatal(err)
	}
	prior.Sequence--
	prior.LastClock = prior.LastClock.Add(100 * time.Millisecond)
	prior.Digest, err = digestStartLedgerState(prior)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, startLedgerFileName(prior)), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	assertStateValidationFails(t, fixture, "not monotonic")
}

func TestValidateStateSnapshotRejectsDuplicateEvidenceAndMismatchedSettlement(t *testing.T) {
	t.Run("duplicate evidence reference", func(t *testing.T) {
		fixture := createInflightStateFixture(t)
		store, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{})
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return fixture.base.Add(300 * time.Millisecond) }
		first := validTestResult(fixture.base.Add(100*time.Millisecond), "duplicate-result-one")
		first.EvidenceRef = "active-start"
		second := validTestResult(fixture.base.Add(200*time.Millisecond), "duplicate-result-two")
		second.EvidenceRef = "active-start"
		if err := store.Append(first); err != nil {
			t.Fatal(err)
		}
		if err := store.Append(second); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		assertStateValidationFails(t, fixture, "duplicate spool evidence reference")
	})

	t.Run("settlement identity mismatch", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		mutateLatestLedgerSnapshot(t, fixture, func(state *startLedgerDisk) { state.Starts[0].ResultRunID = "different-result" })
		assertStateValidationFails(t, fixture, "wrong retained spool result")
	})
}

func TestValidateStateSnapshotReportsLegitimateRetentionGaps(t *testing.T) {
	t.Run("settled result evicted by max entries one", func(t *testing.T) {
		fixture := createRetentionFixture(t, false)
		report, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
			Catalog: fixture.catalog, Now: fixture.base.Add(2 * time.Second), SpoolMaxEntries: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.SpoolResults != 1 || report.MissingRetainedEvidence != 1 || report.RelationshipComplete {
			t.Fatalf("retention gap was not reported conservatively: %+v", report)
		}
	})

	t.Run("rate-limit source evicted by max entries one", func(t *testing.T) {
		fixture := createRetentionFixture(t, true)
		report, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{
			Catalog: fixture.catalog, Now: fixture.base.Add(2 * time.Second), SpoolMaxEntries: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.SpoolResults != 1 || report.LatestRateLimits != 1 || report.MissingRetainedEvidence != 1 || report.RelationshipComplete {
			t.Fatalf("rate-limit retention gap was not reported conservatively: %+v", report)
		}
	})
}

func TestValidateStateSnapshotRejectsUnsafeFilesystemState(t *testing.T) {
	t.Run("unexpected root entry", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.spool, "operator-note"), []byte("unexpected"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertStateValidationFails(t, fixture, "unexpected spool state root entry")
	})

	t.Run("nonempty writer lock", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.ledger, startLedgerLockFilename), []byte("not-a-lock"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertStateValidationFails(t, fixture, "writer lock file must be empty")
	})

	t.Run("missing writer lock", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		if err := os.Remove(filepath.Join(fixture.spool, spoolLockFilename)); err != nil {
			t.Fatal(err)
		}
		assertStateValidationFails(t, fixture, "is missing")
	})

	t.Run("active writer lock", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		store, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		assertStateValidationFails(t, fixture, "state writer must be stopped")
	})

	t.Run("writer lock replaced by directory", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		lockPath := filepath.Join(fixture.spool, spoolLockFilename)
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(lockPath, 0o700); err != nil {
			t.Fatal(err)
		}
		assertStateValidationFails(t, fixture, "writer lock must be a regular file")
	})

	t.Run("overlapping roots", func(t *testing.T) {
		fixture := createSettledStateFixture(t)
		_, err := ValidateStateSnapshot(fixture.spool, filepath.Join(fixture.spool, spoolSegmentsDirectory), StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(time.Second)})
		if err == nil || !strings.Contains(err.Error(), "non-overlapping") {
			t.Fatalf("overlap error = %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("setuid state file", func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			segment := onlyTestFile(t, filepath.Join(fixture.spool, spoolSegmentsDirectory), ".json")
			if err := os.Chmod(segment, os.FileMode(0o600)|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
			assertStateValidationFails(t, fixture, "permissions")
		})

		t.Run("group-readable file", func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			segment := onlyTestFile(t, filepath.Join(fixture.spool, spoolSegmentsDirectory), ".json")
			if err := os.Chmod(segment, 0o640); err != nil {
				t.Fatal(err)
			}
			assertStateValidationFails(t, fixture, "permissions")
		})

		t.Run("hard-linked file", func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			segment := onlyTestFile(t, filepath.Join(fixture.spool, spoolSegmentsDirectory), ".json")
			link := filepath.Join(t.TempDir(), "segment-link.json")
			if err := os.Link(segment, link); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			assertStateValidationFails(t, fixture, "hard link")
		})

		t.Run("symbolic-link root", func(t *testing.T) {
			fixture := createSettledStateFixture(t)
			link := filepath.Join(t.TempDir(), "spool-link")
			if err := os.Symlink(fixture.spool, link); err != nil {
				t.Skipf("symbolic links unavailable: %v", err)
			}
			_, err := ValidateStateSnapshot(link, fixture.ledger, StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(time.Second)})
			if err == nil || !strings.Contains(err.Error(), "symbolic link") {
				t.Fatalf("symlink error = %v", err)
			}
		})
	}
}

func createSettledStateFixture(t *testing.T) stateValidationFixture {
	t.Helper()
	fixture := createInflightStateFixture(t)
	store, err := OpenStore(fixture.spool, fixture.catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result := validTestResult(fixture.base.Add(100*time.Millisecond), "settled-result")
	current := result.CompletedAt
	result.EvidenceRef = "active-start"
	store.now = func() time.Time { return current }
	if err := store.Append(result); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenStartLedger(fixture.ledger, fixture.catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Settle("active-start", result); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.result = result
	return fixture
}

func createInflightStateFixture(t *testing.T) stateValidationFixture {
	t.Helper()
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	spoolDirectory := t.TempDir()
	ledgerDirectory := t.TempDir()
	store, err := OpenStore(spoolDirectory, catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	current := base
	ledger, err := OpenStartLedger(ledgerDirectory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordStart("active-start", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	return stateValidationFixture{catalog: catalog, spool: spoolDirectory, ledger: ledgerDirectory, base: base}
}

func createRetentionFixture(t *testing.T, firstRateLimited bool) stateValidationFixture {
	t.Helper()
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	fixture := stateValidationFixture{catalog: catalog, spool: t.TempDir(), ledger: t.TempDir(), base: base}
	store, err := OpenStore(fixture.spool, catalog, StoreLimits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenStartLedger(fixture.ledger, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordStart("first-start", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	first := validTestResult(base.Add(10*time.Millisecond), "first-result")
	if firstRateLimited {
		first = rateLimitedLedgerResult(base.Add(10*time.Millisecond), "first-result", 1800)
	}
	first.EvidenceRef = "first-start"
	store.now = func() time.Time { return first.CompletedAt }
	if err := store.Append(first); err != nil {
		t.Fatal(err)
	}
	current = first.CompletedAt
	if err := ledger.Settle("first-start", first); err != nil {
		t.Fatal(err)
	}

	current = base.Add(time.Second)
	if err := ledger.RecordStart("second-start", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	second := validTestResult(current.Add(10*time.Millisecond), "second-result")
	second.EvidenceRef = "second-start"
	store.now = func() time.Time { return second.CompletedAt }
	if err := store.Append(second); err != nil {
		t.Fatal(err)
	}
	current = second.CompletedAt
	if err := ledger.Settle("second-start", second); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertStateValidationFails(t *testing.T, fixture stateValidationFixture, contains string) {
	t.Helper()
	_, err := ValidateStateSnapshot(fixture.spool, fixture.ledger, StateValidationOptions{Catalog: fixture.catalog, Now: fixture.base.Add(2 * time.Minute)})
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("validation error = %v, want containing %q", err, contains)
	}
}

func onlyTestFile(t *testing.T, directory, suffix string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for index := len(entries) - 1; index >= 0; index-- {
		if strings.HasSuffix(entries[index].Name(), suffix) {
			return filepath.Join(directory, entries[index].Name())
		}
	}
	t.Fatalf("no %s file in %s", suffix, directory)
	return ""
}

func mutateLatestLedgerSnapshot(t *testing.T, fixture stateValidationFixture, mutate func(*startLedgerDisk)) {
	t.Helper()
	mutateLedgerSnapshotAt(t, fixture, -1, mutate)
}

func mutateLedgerSnapshotAt(t *testing.T, fixture stateValidationFixture, index int, mutate func(*startLedgerDisk)) {
	t.Helper()
	directory := filepath.Join(fixture.ledger, startLedgerSnapshotsDir)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var snapshots []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			snapshots = append(snapshots, filepath.Join(directory, entry.Name()))
		}
	}
	if len(snapshots) == 0 {
		t.Fatal("no ledger snapshots")
	}
	if index < 0 {
		index = len(snapshots) - 1
	}
	if index >= len(snapshots) {
		t.Fatalf("ledger snapshot index %d out of range", index)
	}
	path := snapshots[index]
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state startLedgerDisk
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	mutate(&state)
	state.Digest, err = digestStartLedgerState(state)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(directory, startLedgerFileName(state))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}
}

func snapshotTestTree(t *testing.T, roots ...string) string {
	t.Helper()
	var result strings.Builder
	for _, root := range roots {
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			fmtValue := relative + ":" + info.Mode().String() + ":" + time.Unix(0, info.ModTime().UnixNano()).UTC().Format(time.RFC3339Nano)
			if info.Mode().IsRegular() {
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				fmtValue += ":" + string(raw)
			}
			result.WriteString(fmtValue)
			result.WriteByte('\n')
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return result.String()
}

func copyTestTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
}
