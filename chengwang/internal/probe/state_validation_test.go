package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
