package operation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileStoreRestartRestoresLifecycleAndIdempotency(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created, wasCreated, err := store.Create(validRequest("restart-key"))
	if err != nil || !wasCreated {
		t.Fatalf("create: created=%v err=%v", wasCreated, err)
	}
	created, err = store.Transition(created.ID, StatusPrechecking, "prechecks passed")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != StatusPrechecking || len(restored.Events) != 2 {
		t.Fatalf("lifecycle not restored: %+v", restored)
	}
	again, wasCreated, err := reopened.Create(validRequest("restart-key"))
	if err != nil {
		t.Fatal(err)
	}
	if wasCreated || again.ID != created.ID {
		t.Fatalf("idempotency did not survive restart: created=%v op=%+v", wasCreated, again)
	}
	changed := validRequest("restart-key")
	changed.Scope = "different"
	if _, _, err := reopened.Create(changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected conflict after restart, got %v", err)
	}
}

func TestFileStoreConcurrentCreateAndTransition(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const workers = 48
	var createWG sync.WaitGroup
	var creations atomic.Int32
	ids := make(chan string, workers)
	for range workers {
		createWG.Add(1)
		go func() {
			defer createWG.Done()
			op, created, err := store.Create(validRequest("durable-concurrent"))
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			if created {
				creations.Add(1)
			}
			ids <- op.ID
		}()
	}
	createWG.Wait()
	close(ids)
	if creations.Load() != 1 {
		t.Fatalf("expected exactly one create, got %d", creations.Load())
	}
	var id string
	for candidate := range ids {
		if id == "" {
			id = candidate
		}
		if id != candidate {
			t.Fatalf("concurrent idempotent create returned %q and %q", id, candidate)
		}
	}

	var transitionWG sync.WaitGroup
	var wins atomic.Int32
	for range workers {
		transitionWG.Add(1)
		go func() {
			defer transitionWG.Done()
			if _, err := store.Transition(id, StatusAwaitingApproval, "approval requested"); err == nil {
				wins.Add(1)
			}
		}()
	}
	transitionWG.Wait()
	if wins.Load() != 1 {
		t.Fatalf("expected one transition winner, got %d", wins.Load())
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(store.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	op, err := reopened.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusAwaitingApproval || len(op.Events) != 2 || op.Events[1].Sequence != 2 {
		t.Fatalf("invalid persisted concurrent result: %+v", op)
	}
}

func TestFileStoreWriteFailureDoesNotMutateMemoryOrDurableState(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	op, _, err := store.Create(validRequest("existing"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	store.write = func(string, diskSnapshot) writeResult {
		return writeResult{state: commitNotCommitted, err: errors.New("simulated disk failure")}
	}

	if _, _, err := store.Create(validRequest("must-not-exist")); err == nil || !strings.Contains(err.Error(), "simulated disk failure") {
		t.Fatalf("expected simulated create failure, got %v", err)
	}
	listed, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(listed); got != 1 {
		t.Fatalf("failed create changed in-memory list length to %d", got)
	}
	if _, err := store.Transition(op.ID, StatusPrechecking, "must not commit"); err == nil || !strings.Contains(err.Error(), "simulated disk failure") {
		t.Fatalf("expected simulated transition failure, got %v", err)
	}
	unchanged, err := store.Get(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != StatusPlanned || len(unchanged.Events) != 1 {
		t.Fatalf("failed transition changed memory: %+v", unchanged)
	}
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed writes changed the durable snapshot")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.Get(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	listed, err = reopened.List()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != StatusPlanned || len(listed) != 1 {
		t.Fatalf("restart observed failed mutation: %+v", restored)
	}
}

func TestFileStoreUncertainCommitPoisonsUntilRestart(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	op, _, err := store.Create(validRequest("uncertain-base"))
	if err != nil {
		t.Fatal(err)
	}
	store.write = func(path string, snapshot diskSnapshot) writeResult {
		return writeSnapshotAtomicallyWithSync(path, snapshot, func(string) error {
			return errors.New("simulated directory sync failure")
		})
	}

	if _, err := store.Transition(op.ID, StatusPrechecking, "rename commits before sync failure"); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("transition error = %v, want uncertain commit", err)
	}
	if _, err := store.Get(op.ID); !errors.Is(err, ErrStorePoisoned) || !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("poisoned Get error = %v", err)
	}
	if listed, err := store.List(); listed != nil || !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("poisoned List = %+v, %v", listed, err)
	}
	if _, _, err := store.Create(validRequest("blocked-after-uncertain")); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("write after uncertain commit error = %v", err)
	}
	if _, err := store.Transition(op.ID, StatusFailed, "blocked after uncertain"); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("transition after uncertain commit error = %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(directory)
	if err != nil {
		t.Fatalf("reopen after uncertain commit: %v", err)
	}
	defer reopened.Close()
	restored, err := reopened.Get(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != StatusPrechecking || len(restored.Events) != 2 {
		t.Fatalf("restart did not report disk-visible committed candidate: %+v", restored)
	}
}

func TestFileStoreExclusiveProcessLockAndClose(t *testing.T) {
	directory := t.TempDir()
	first, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	op, _, err := first.Create(validRequest("close-boundary"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(directory); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second writer error = %v, want store locked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get("missing"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Get after Close error = %v", err)
	}
	if listed, err := first.List(); listed != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("List after Close = %+v, %v", listed, err)
	}
	if _, _, err := first.Create(validRequest("after-close")); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Create after Close error = %v", err)
	}
	if _, err := first.Transition(op.ID, StatusPrechecking, "after close"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Transition after Close error = %v", err)
	}
	second, err := NewFileStore(directory)
	if err != nil {
		t.Fatalf("lock was not released by Close: %v", err)
	}
	defer second.Close()
}

func TestFileStoreRejectsNonRegularAndSymlinkLockFiles(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Mkdir(filepath.Join(directory, fileStoreLockName), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileStore(directory); err == nil {
			t.Fatal("directory lock file was accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "lock-target")
		if err := os.WriteFile(target, []byte("not a lock"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, fileStoreLockName)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("Windows symlink creation unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := NewFileStore(directory); err == nil {
			t.Fatal("symlink lock file was accepted")
		}
	})
}

func TestFileStoreRejectsSymlinkInParentPath(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(base, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := NewFileStore(filepath.Join(linkedParent, "store")); err == nil {
		t.Fatal("parent-path symlink was accepted")
	}
}

func TestFileStoreRejectsSnapshotSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "snapshot-target")
	if err := os.WriteFile(target, []byte(`{"version":2,"operations":[],"idempotency":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, fileStoreName)); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := NewFileStore(directory); err == nil {
		t.Fatal("snapshot symlink was accepted")
	}
}

func TestReadSnapshotDetectsPathReplacementBetweenLstatAndOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, fileStoreName)
	otherPath := filepath.Join(directory, "other.json")
	original := []byte(`{"version":2,"operations":[],"idempotency":[]}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readSnapshotFileWithOpen(path, func(string) (*os.File, error) {
		return os.Open(otherPath)
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("path replacement error = %v", err)
	}
}

func TestFileStoreRejectsOversizedSnapshotBeforeDecode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, fileStoreName)
	oversized := make([]byte, maxSnapshotBytes+1)
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(directory); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("oversized snapshot error = %v", err)
	}
}

func TestSnapshotCollectionAndEventLimitsApplyToV2AndLegacy(t *testing.T) {
	tooManyOperations := diskSnapshot{
		Version: fileStoreSchemaVersion, Operations: make([]Operation, maxOperations+1),
		Idempotency: []diskIdempotencyRecord{},
	}
	if err := validateSnapshot(tooManyOperations); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("operation count error = %v", err)
	}
	encodedOperations, err := json.Marshal(tooManyOperations)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeAndValidateSnapshot(encodedOperations); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("decoded operation count error = %v", err)
	}
	tooManyIdempotency := diskSnapshot{
		Version: fileStoreSchemaVersion, Operations: []Operation{},
		Idempotency: make([]diskIdempotencyRecord, maxIdempotencyRecords+1),
	}
	if err := validateSnapshot(tooManyIdempotency); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("idempotency count error = %v", err)
	}

	memory := NewMemoryStore()
	op, _, err := memory.Create(validRequest("event-limit-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	op.Events = make([]Event, maxEventsPerOperation+1)
	eventSnapshot := diskSnapshot{
		Version: fileStoreSchemaVersion, Operations: []Operation{op}, Idempotency: []diskIdempotencyRecord{},
	}
	if err := validateSnapshot(eventSnapshot); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("event count error = %v", err)
	}

	legacy := op
	legacy.IdentityBinding = ""
	legacy.InitiatorID = ""
	legacy.ApprovedByID = ""
	legacy.Events = op.Events[:1]
	legacy.Environment = strings.Repeat("e", maxEnvironmentBytes+1)
	legacySnapshot := diskSnapshot{
		Version: legacySchemaVersion, Operations: []Operation{legacy}, Idempotency: []diskIdempotencyRecord{},
	}
	if err := validateLegacySnapshot(legacySnapshot); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("legacy field limit error = %v", err)
	}
	encodedLegacy, err := json.Marshal(legacySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeAndValidateSnapshot(encodedLegacy); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("decoded legacy field limit error = %v", err)
	}
}

func TestFileStorePrivatePermissionsAndAtomicCleanup(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-operation-store")
	store, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.Create(validRequest("permissions")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		directoryInfo, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if got := directoryInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("directory mode = %o, want 700", got)
		}
		fileInfo, err := os.Stat(store.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("snapshot mode = %o, want 600", got)
		}
		lockInfo, err := os.Stat(filepath.Join(directory, fileStoreLockName))
		if err != nil {
			t.Fatal(err)
		}
		if got := lockInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("lock mode = %o, want 600", got)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != fileStoreLockName || entries[1].Name() != fileStoreName {
		t.Fatalf("atomic writer left unexpected files: %+v", entries)
	}
}

func TestFileStoreReturnedOperationsAreDetachedAndOrdered(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	store.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Second) }
	first, _, err := store.Create(validRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.Create(validRequest("second"))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ID != first.ID || listed[1].ID != second.ID {
		t.Fatalf("unexpected list ordering: %+v", listed)
	}
	listed[0].Events[0].Reason = "caller mutation"
	stored, err := store.Get(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Events[0].Reason == "caller mutation" {
		t.Fatal("caller mutated durable store state")
	}
	if _, err := store.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestFileStoreMatchesMemoryStoreValidationAndTerminalSemantics(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	invalid := validRequest("")
	if _, _, err := store.Create(invalid); err == nil {
		t.Fatal("expected create validation error")
	}
	if _, err := store.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected get not found, got %v", err)
	}
	if _, err := store.Transition("missing", StatusPrechecking, "check"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected transition not found, got %v", err)
	}
	op, _, err := store.Create(validRequest("matching-semantics"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(op.ID, StatusSucceeded, "skip required gates"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
	if _, err := store.Transition(op.ID, StatusPrechecking, "token=must-not-persist"); !errors.Is(err, ErrSensitiveReason) {
		t.Fatalf("expected sensitive reason rejection, got %v", err)
	}
	if _, err := store.Transition(op.ID, StatusFailed, "precheck failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(op.ID, StatusPrechecking, "must remain frozen"); !errors.Is(err, ErrTerminalOperation) {
		t.Fatalf("expected terminal operation error, got %v", err)
	}
	stored, err := store.Get(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != StatusFailed || len(stored.Events) != 2 {
		t.Fatalf("rejected transitions mutated state: %+v", stored)
	}
}

func TestFileStoreRejectsCorruptSnapshotsOnRestart(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, original []byte, snapshot diskSnapshot) []byte
	}{
		{
			name: "unknown top-level field",
			mutate: func(t *testing.T, original []byte, _ diskSnapshot) []byte {
				return []byte(strings.Replace(string(original), `"version": 2,`, `"version": 2, "unknown": true,`, 1))
			},
		},
		{
			name: "unknown nested field",
			mutate: func(t *testing.T, original []byte, _ diskSnapshot) []byte {
				return []byte(strings.Replace(string(original), `"id":`, `"unknown": true, "id":`, 1))
			},
		},
		{
			name: "unknown operation status",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Operations[0].Status = Status("unknown")
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "unknown event status",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Operations[0].Events[0].To = Status("unknown")
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "invalid event sequence",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Operations[0].Events[0].Sequence = 2
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "status differs from tail event",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Operations[0].Status = StatusPrechecking
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "duplicate operation ID",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Operations = append(snapshot.Operations, snapshot.Operations[0])
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "duplicate idempotency key",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Idempotency = append(snapshot.Idempotency, snapshot.Idempotency[0])
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "idempotency digest conflict",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Idempotency[0].Digest = strings.Repeat("0", 64)
				return marshalSnapshotForTest(t, snapshot)
			},
		},
		{
			name: "missing idempotency record",
			mutate: func(t *testing.T, _ []byte, snapshot diskSnapshot) []byte {
				snapshot.Idempotency = []diskIdempotencyRecord{}
				return marshalSnapshotForTest(t, snapshot)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			store, err := NewFileStore(directory)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Create(validRequest("corrupt-" + test.name)); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(store.path)
			if err != nil {
				t.Fatal(err)
			}
			var snapshot diskSnapshot
			if err := json.Unmarshal(original, &snapshot); err != nil {
				t.Fatal(err)
			}
			corrupted := test.mutate(t, original, snapshot)
			if err := os.WriteFile(store.path, corrupted, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(directory); err == nil {
				t.Fatal("corrupt snapshot was accepted")
			}
		})
	}
}

func TestFileStoreRejectsMalformedAndIncompleteSnapshot(t *testing.T) {
	for name, contents := range map[string]string{
		"malformed":          `{`,
		"empty":              ``,
		"wrong version":      `{"version":99,"operations":[],"idempotency":[]}`,
		"missing arrays":     `{"version":1}`,
		"multiple documents": `{"version":1,"operations":[],"idempotency":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, fileStoreName), []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(directory); err == nil {
				t.Fatal("invalid snapshot was accepted")
			}
		})
	}
}

func TestFileStoreMigratesV1WithoutInventingIdentityAndFreezesIt(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	op, _, err := store.Create(validRequest("legacy-migration"))
	if err != nil {
		t.Fatal(err)
	}
	legacyOperation := op
	legacyOperation.InitiatorID = ""
	legacyOperation.ApprovedByID = ""
	legacyOperation.IdentityBinding = ""
	legacyDigest, err := legacyRequestDigest(CreateRequest{
		Environment: legacyOperation.Environment, Scope: legacyOperation.Scope,
		TargetVersion: legacyOperation.TargetVersion, Risk: legacyOperation.Risk,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := diskSnapshot{
		Version:    legacySchemaVersion,
		Operations: []Operation{legacyOperation},
		Idempotency: []diskIdempotencyRecord{{
			Key: "legacy-migration", OperationID: op.ID, Digest: hex.EncodeToString(legacyDigest[:]),
		}},
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	encoded = []byte(strings.Replace(string(encoded), `,"identityBinding":""`, "", 1))
	if bytes.Contains(encoded, []byte("identityBinding")) {
		t.Fatalf("legacy fixture unexpectedly contains new identity field: %s", encoded)
	}
	if err := os.WriteFile(store.path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	migrated, err := reopened.Get(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.IdentityBinding != IdentityBindingLegacyUnbound || migrated.InitiatorID != "" || migrated.ApprovedByID != "" {
		t.Fatalf("migration invented identity: %+v", migrated)
	}
	if migrated.Status != legacyOperation.Status || len(migrated.Events) != len(legacyOperation.Events) {
		t.Fatalf("migration lost lifecycle data: %+v", migrated)
	}
	if _, err := reopened.Transition(op.ID, StatusPrechecking, "must stay frozen"); !errors.Is(err, ErrIdentityUnbound) {
		t.Fatalf("legacy transition error = %v, want identity unbound", err)
	}
	if _, _, err := reopened.Create(validRequest("legacy-migration")); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("legacy key was rebound to a guessed initiator: %v", err)
	}
	durable, err := os.ReadFile(reopened.path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot diskSnapshot
	if err := json.Unmarshal(durable, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != fileStoreSchemaVersion {
		t.Fatalf("persisted migrated version = %d", snapshot.Version)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	last, err := NewFileStore(directory)
	if err != nil {
		t.Fatalf("reopen migrated v2 snapshot: %v", err)
	}
	defer last.Close()
}

func marshalSnapshotForTest(t *testing.T, snapshot diskSnapshot) []byte {
	t.Helper()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
