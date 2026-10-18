package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppendAndVerifyChain(t *testing.T) {
	store := openTestStore(t)
	first, err := store.Append(testEvent("policy.validate"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Append(testEvent("policy.publish"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ActorID != "unknown" || first.TraceID != "unknown" {
		t.Fatalf("empty identities must be explicit unknown: %+v", first)
	}
	if first.PreviousHash != genesisHash || second.PreviousHash != first.Hash {
		t.Fatal("unexpected chain linkage")
	}
	report, err := store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || report.Count != 2 || report.LastHash != second.Hash {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestStatusIsCachedAndFullVerifyRefreshesIt(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	initial := store.Status()
	if !initial.Valid || initial.VerifiedAt.IsZero() || initial.Count != 0 {
		t.Fatalf("invalid initial cached status: %+v", initial)
	}
	event, err := store.Append(testEvent("status.test"))
	if err != nil {
		t.Fatal(err)
	}
	afterAppend := store.Status()
	if !afterAppend.Valid || afterAppend.Count != 1 || afterAppend.LastHash != event.Hash || afterAppend.VerifiedAt.IsZero() {
		t.Fatalf("append did not advance cached status: %+v", afterAppend)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointFilename), []byte(`{"count":0,"lastHash":"`+genesisHash+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cached := store.Status(); !cached.Valid || cached.Count != 1 {
		t.Fatalf("cached status changed without a verifier: %+v", cached)
	}
	if report, err := store.Verify(); err == nil || report.Valid {
		t.Fatalf("full verifier did not detect checkpoint tampering: report=%+v err=%v", report, err)
	}
	if cached := store.Status(); cached.Valid || cached.Issue == "" || cached.VerifiedAt.IsZero() {
		t.Fatalf("failed verification did not refresh cached status: %+v", cached)
	}
}

func TestVerifyDetectsTamperingAndReordering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{
			name: "edited",
			mutate: func(lines []string) []string {
				lines[0] = strings.Replace(lines[0], "policy.validate", "policy.changed", 1)
				return lines
			},
		},
		{
			name: "reordered",
			mutate: func(lines []string) []string {
				lines[0], lines[1] = lines[1], lines[0]
				return lines
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store := mustOpen(t, dir)
			mustAppend(t, store, "policy.validate")
			mustAppend(t, store, "policy.publish")
			path := filepath.Join(dir, logFilename)
			lines := readLines(t, path)
			writeLines(t, path, tc.mutate(lines))
			report, err := store.Verify()
			if !errors.Is(err, ErrIntegrity) || report.Valid {
				t.Fatalf("expected integrity failure, report=%+v err=%v", report, err)
			}
		})
	}
}

func TestVerifyDetectsTruncationAndAcceptsFreshEmptyLog(t *testing.T) {
	empty := openTestStore(t)
	report, err := empty.Verify()
	if err != nil || !report.Valid || report.Count != 0 || report.LastHash != genesisHash {
		t.Fatalf("fresh empty store should verify: report=%+v err=%v", report, err)
	}

	for _, keepLines := range []int{1, 0} {
		t.Run(fmt.Sprintf("keep-%d-lines", keepLines), func(t *testing.T) {
			dir := t.TempDir()
			store := mustOpen(t, dir)
			mustAppend(t, store, "first")
			mustAppend(t, store, "second")
			lines := readLines(t, filepath.Join(dir, logFilename))
			writeLines(t, filepath.Join(dir, logFilename), lines[:keepLines])
			report, err = store.Verify()
			if !errors.Is(err, ErrIntegrity) || report.Issue != "log_truncated" {
				t.Fatalf("expected truncation, report=%+v err=%v", report, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("startup should fail closed after truncation: %v", err)
			}
		})
	}
}

func TestConcurrentAppendProducesValidChain(t *testing.T) {
	store := openTestStore(t)
	const workers = 40
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Append(EvidenceEvent{
				Action: "probe.complete",
				Target: fmt.Sprintf("node-%d", i),
				Result: "success",
				Data:   map[string]string{"summaryRef": fmt.Sprintf("probe/%d", i)},
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	report, err := store.Verify()
	if err != nil || !report.Valid || report.Count != workers {
		t.Fatalf("invalid concurrent chain: report=%+v err=%v", report, err)
	}
}

func TestAppendRejectsSecretAndRawBodyKeys(t *testing.T) {
	store := openTestStore(t)
	for _, key := range []string{
		"password", "API_TOKEN", "client-Secret", "privateKey", "Authorization",
		"access.key", "cookie", "request_body", "payload",
	} {
		t.Run(key, func(t *testing.T) {
			event := testEvent("unsafe")
			event.Data = map[string]string{key: "must-not-be-written"}
			if _, err := store.Append(event); err == nil {
				t.Fatalf("expected %q to be rejected", key)
			}
		})
	}
	report, err := store.Verify()
	if err != nil || report.Count != 0 {
		t.Fatalf("rejected events reached log: report=%+v err=%v", report, err)
	}
}

func TestRestartContinuesExistingChain(t *testing.T) {
	dir := t.TempDir()
	firstStore := mustOpen(t, dir)
	first := mustAppend(t, firstStore, "first")
	if err := firstStore.Close(); err != nil {
		t.Fatal(err)
	}
	secondStore := mustOpen(t, dir)
	second := mustAppend(t, secondStore, "second")
	if second.PreviousHash != first.Hash {
		t.Fatalf("restart did not continue chain: got %s want %s", second.PreviousHash, first.Hash)
	}
	report, err := secondStore.Verify()
	if err != nil || report.Count != 2 {
		t.Fatalf("restart chain invalid: report=%+v err=%v", report, err)
	}
}

func TestAppendOnceNormalizesKeyAndReturnsOriginalEvent(t *testing.T) {
	store := openTestStore(t)
	original, created, err := store.AppendOnce(testEvent("policy.publish"), "  REQUEST-42  ")
	if err != nil || !created {
		t.Fatalf("first append: event=%+v created=%v err=%v", original, created, err)
	}
	retryInput := testEvent("policy.publish")
	retryInput.OccurredAt = original.OccurredAt.Add(24 * time.Hour)
	retry, created, err := store.AppendOnce(retryInput, "request-42")
	if err != nil || created {
		t.Fatalf("retry: event=%+v created=%v err=%v", retry, created, err)
	}
	if !reflect.DeepEqual(retry, original) {
		t.Fatalf("retry must return exact original event:\n got %+v\nwant %+v", retry, original)
	}
	if original.IdempotencyKey != "request-42" {
		t.Fatalf("key was not canonicalized: %q", original.IdempotencyKey)
	}
	report, err := store.Verify()
	if err != nil || report.Count != 1 {
		t.Fatalf("retry must not append: report=%+v err=%v", report, err)
	}
}

func TestAppendOnceConflictIsStableAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	firstStore := mustOpen(t, dir)
	original, created, err := firstStore.AppendOnce(testEvent("policy.validate"), "deploy/site-a")
	if err != nil || !created {
		t.Fatalf("first append: created=%v err=%v", created, err)
	}
	if err := firstStore.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := mustOpen(t, dir)
	retry, created, err := restarted.AppendOnce(testEvent("policy.validate"), "DEPLOY/SITE-A")
	if err != nil || created || retry.ID != original.ID {
		t.Fatalf("restart retry: event=%+v created=%v err=%v", retry, created, err)
	}
	conflicting := testEvent("policy.publish")
	if _, _, err := restarted.AppendOnce(conflicting, "deploy/site-a"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected stable conflict error, got %v", err)
	}
	report, err := restarted.Verify()
	if err != nil || report.Count != 1 {
		t.Fatalf("conflict must not append: report=%+v err=%v", report, err)
	}
}

func TestAppendOnceReturnedDataCannotMutateStoredOriginal(t *testing.T) {
	store := openTestStore(t)
	input := testEvent("policy.validate")
	original, created, err := store.AppendOnce(input, "immutable-result")
	if err != nil || !created {
		t.Fatalf("first append: created=%v err=%v", created, err)
	}
	input.Data["summaryRef"] = "caller-mutated-input"
	original.Data["summaryRef"] = "caller-mutated-result"

	retry, created, err := store.AppendOnce(testEvent("policy.validate"), "immutable-result")
	if err != nil || created {
		t.Fatalf("retry: created=%v err=%v", created, err)
	}
	if got := retry.Data["summaryRef"]; got != "sha256:example" {
		t.Fatalf("stored event was mutable through caller map: %q", got)
	}
}

func TestConcurrentAppendOnceHasOneWinner(t *testing.T) {
	store := openTestStore(t)
	const workers = 64
	type result struct {
		event   EvidenceEvent
		created bool
		err     error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			event, created, err := store.AppendOnce(testEvent("probe.complete"), "probe/node-a/epoch-7")
			results <- result{event: event, created: created, err: err}
		}()
	}
	wg.Wait()
	close(results)

	createdCount := 0
	var observed EvidenceEvent
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if observed.ID == "" {
			observed = result.event
		} else if !reflect.DeepEqual(result.event, observed) {
			t.Fatalf("callers observed different committed events: got %+v want %+v", result.event, observed)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count=%d want 1", createdCount)
	}
	report, err := store.Verify()
	if err != nil || report.Count != 1 {
		t.Fatalf("concurrent retry appended more than once: report=%+v err=%v", report, err)
	}
}

func TestAppendOnceValidationAndAppendBoundary(t *testing.T) {
	store := openTestStore(t)
	withID := testEvent("policy.validate")
	withID.ID = "caller-controlled"
	if _, err := store.Append(withID); err == nil || !strings.Contains(err.Error(), "id is managed") {
		t.Fatalf("Append accepted caller-supplied id: %v", err)
	}
	if _, _, err := store.AppendOnce(withID, "caller-id"); err == nil || !strings.Contains(err.Error(), "id is managed") {
		t.Fatalf("AppendOnce accepted caller-supplied id: %v", err)
	}
	event := testEvent("policy.validate")
	event.IdempotencyKey = "already-set"
	if _, err := store.Append(event); err == nil {
		t.Fatal("ordinary Append accepted an idempotency key")
	}
	if _, _, err := store.AppendOnce(testEvent("policy.validate"), "   "); err == nil {
		t.Fatal("AppendOnce accepted a blank key")
	}
	if _, _, err := store.AppendOnce(testEvent("policy.validate"), strings.Repeat("a", maxIdempotencyKeyBytes+1)); err == nil {
		t.Fatal("AppendOnce accepted an oversized key")
	}
	unsafe := testEvent("policy.validate")
	unsafe.Data = map[string]string{"access_token": "must-not-be-written"}
	if _, _, err := store.AppendOnce(unsafe, "safe-key"); err == nil {
		t.Fatal("AppendOnce bypassed secret-key validation")
	}
	report, err := store.Verify()
	if err != nil || report.Count != 0 {
		t.Fatalf("invalid events reached log: report=%+v err=%v", report, err)
	}
}

func TestOpenRejectsDuplicateEventIDs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first := storedTestEvent(t, "first", "first-key", genesisHash)
	second := storedTestEvent(t, "second", "second-key", first.Hash)
	second.ID = first.ID
	secondHash, err := eventHash(second)
	if err != nil {
		t.Fatal(err)
	}
	second.Hash = secondHash
	firstLine, _ := json.Marshal(first)
	secondLine, _ := json.Marshal(second)
	contents := append(append(append([]byte{}, firstLine...), '\n'), secondLine...)
	contents = append(contents, '\n')
	if err := os.WriteFile(filepath.Join(dir, logFilename), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	cp, _ := json.Marshal(checkpoint{Count: 2, LastHash: second.Hash})
	if err := os.WriteFile(filepath.Join(dir, checkpointFilename), cp, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "duplicate_event_id") {
		t.Fatalf("expected duplicate event id integrity failure, got %v", err)
	}
}

func TestOpenAcceptsLegacyLogWithoutIdempotencyKey(t *testing.T) {
	dir := t.TempDir()
	timestamp := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	type legacyEvent struct {
		ID           string            `json:"id"`
		TraceID      string            `json:"traceId"`
		ActorID      string            `json:"actorId"`
		Action       string            `json:"action"`
		Target       string            `json:"target"`
		Result       string            `json:"result"`
		OccurredAt   time.Time         `json:"occurredAt"`
		Data         map[string]string `json:"data,omitempty"`
		PreviousHash string            `json:"previousHash"`
		Hash         string            `json:"hash"`
	}
	legacy := legacyEvent{
		ID: "evt-legacy", TraceID: "trace-legacy", ActorID: "actor-legacy",
		Action: "policy.validate", Target: "routing/default", Result: "success",
		OccurredAt: timestamp, Data: map[string]string{"summaryRef": "sha256:legacy"},
		PreviousHash: genesisHash,
	}
	withoutHash, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(withoutHash)
	legacy.Hash = hex.EncodeToString(digest[:])
	line, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, logFilename), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	cp, err := json.Marshal(checkpoint{Count: 1, LastHash: legacy.Hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointFilename), cp, 0o600); err != nil {
		t.Fatal(err)
	}
	store := mustOpen(t, dir)
	report, err := store.Verify()
	if err != nil || !report.Valid || report.Count != 1 {
		t.Fatalf("legacy log rejected: report=%+v err=%v", report, err)
	}
}

func TestOpenRejectsConflictingDuplicateIdempotencyKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first := storedTestEvent(t, "first", "same-key", genesisHash)
	second := storedTestEvent(t, "second", "same-key", first.Hash)
	firstLine, _ := json.Marshal(first)
	secondLine, _ := json.Marshal(second)
	contents := append(append(append([]byte{}, firstLine...), '\n'), secondLine...)
	contents = append(contents, '\n')
	if err := os.WriteFile(filepath.Join(dir, logFilename), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	cp, _ := json.Marshal(checkpoint{Count: 2, LastHash: second.Hash})
	if err := os.WriteFile(filepath.Join(dir, checkpointFilename), cp, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "idempotency_conflict") {
		t.Fatalf("expected idempotency conflict integrity failure, got %v", err)
	}
}

func TestPartialLineIsRejected(t *testing.T) {
	dir := t.TempDir()
	store := mustOpen(t, dir)
	mustAppend(t, store, "first")
	file, err := os.OpenFile(filepath.Join(dir, logFilename), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{\"id\":"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	report, err := store.Verify()
	if !errors.Is(err, ErrIntegrity) || report.Issue != "partial_line" {
		t.Fatalf("expected partial line failure: report=%+v err=%v", report, err)
	}
}

func TestCheckpointFailurePoisonsStoreAndRestartDetectsStaleCheckpoint(t *testing.T) {
	dir := t.TempDir()
	store := mustOpen(t, dir)
	mustAppend(t, store, "first")

	injected := errors.New("injected checkpoint failure")
	store.checkpointCommit = func(checkpoint) error { return injected }
	if _, err := store.Append(testEvent("second")); !errors.Is(err, ErrStorePoisoned) || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("checkpoint failure must poison store: %v", err)
	}
	linesAfterFailure := readLines(t, filepath.Join(dir, logFilename))
	if len(linesAfterFailure) != 2 {
		t.Fatalf("the synced event should remain observable, got %d lines", len(linesAfterFailure))
	}

	if _, err := store.Append(testEvent("must-not-append")); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("poisoned store accepted append: %v", err)
	}
	if _, _, err := store.AppendOnce(testEvent("must-not-append-once"), "after-poison"); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("poisoned store accepted AppendOnce: %v", err)
	}
	if got := len(readLines(t, filepath.Join(dir, logFilename))); got != len(linesAfterFailure) {
		t.Fatalf("poisoned store changed log: got %d lines want %d", got, len(linesAfterFailure))
	}

	report, err := store.Verify()
	if !errors.Is(err, ErrIntegrity) || !errors.Is(err, ErrStorePoisoned) || report.Issue != "checkpoint_stale" {
		t.Fatalf("Verify must expose the on-disk mismatch: report=%+v err=%v", report, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "checkpoint_stale") {
		t.Fatalf("restart must reject stale checkpoint: %v", err)
	}
}

func TestDirectorySyncFailurePoisonsStoreAndVerifyReportsOperationalState(t *testing.T) {
	dir := t.TempDir()
	store := mustOpen(t, dir)
	called := 0
	store.syncDir = func(path string) error {
		called++
		if path != dir {
			t.Fatalf("synced directory %q want %q", path, dir)
		}
		return errors.New("injected directory sync failure")
	}

	if _, err := store.Append(testEvent("first")); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("directory sync uncertainty must poison store: %v", err)
	}
	if called != 1 {
		t.Fatalf("directory sync calls=%d want 1", called)
	}
	if _, err := store.Append(testEvent("must-not-append")); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("poisoned store accepted append: %v", err)
	}
	if called != 1 {
		t.Fatalf("blocked append unexpectedly attempted a commit; sync calls=%d", called)
	}

	report, err := store.Verify()
	if !errors.Is(err, ErrStorePoisoned) || report.Valid || report.Issue != "store_poisoned" {
		t.Fatalf("Verify hid operational uncertainty: report=%+v err=%v", report, err)
	}
	if report.Count != 1 || report.ExpectedCount != 1 {
		t.Fatalf("Verify should retain the currently observed disk facts: %+v", report)
	}

	// Without a crash the renamed checkpoint is visible and a fresh Open can
	// prove the current files agree. If a real crash lost the rename, Open would
	// instead reject the stale checkpoint as covered by the preceding test.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := mustOpen(t, dir)
	if report, err := restarted.Verify(); err != nil || !report.Valid || report.Count != 1 {
		t.Fatalf("fresh verification of visible files failed: report=%+v err=%v", report, err)
	}
}

func TestOpenHoldsExclusiveLifecycleWriterLock(t *testing.T) {
	dir := t.TempDir()
	first := mustOpen(t, dir)
	if _, err := Open(dir); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second writer must be rejected, got %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := mustOpen(t, dir)
	if _, err := second.Append(testEvent("after-lock-release")); err != nil {
		t.Fatalf("released lifecycle lock was not reusable: %v", err)
	}
}

func TestClosedStoreFailsClosed(t *testing.T) {
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
	if _, err := store.Append(testEvent("after-close")); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed store accepted append: %v", err)
	}
	if report, err := store.Verify(); !errors.Is(err, ErrStoreClosed) || report.Issue != "store_closed" {
		t.Fatalf("closed Verify was not explicit: report=%+v err=%v", report, err)
	}
}

func TestOpenRejectsNonRegularStoreFiles(t *testing.T) {
	for _, filename := range []string{logFilename, checkpointFilename, lockFilename} {
		t.Run(filename, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, filename), 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("non-regular %s accepted: %v", filename, err)
			}
		})
	}
}

func TestOpenRejectsNonDirectoryStorePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("non-directory evidence path was accepted")
	}
}

func TestOpenRejectsSymbolicLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation and ACL semantics require privileged integration coverage")
	}
	realDir := t.TempDir()
	linkedDir := filepath.Join(t.TempDir(), "linked-evidence")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := Open(linkedDir); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("symbolic-link directory accepted: %v", err)
	}

	for _, filename := range []string{logFilename, checkpointFilename, lockFilename} {
		t.Run(filename, func(t *testing.T) {
			dir := t.TempDir()
			store := mustOpen(t, dir)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, filename)); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "external-file")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, filename)); err != nil {
				t.Skipf("file symbolic links unavailable: %v", err)
			}
			if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("symbolic-link %s accepted: %v", filename, err)
			}
		})
	}
}

func TestOpenRequiresExactPOSIXPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows FileMode does not represent ACLs")
	}
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "permissions must be 0700") {
			t.Fatalf("insecure directory permissions accepted: %v", err)
		}
	})
	for _, filename := range []string{logFilename, checkpointFilename, lockFilename} {
		t.Run(filename, func(t *testing.T) {
			dir := t.TempDir()
			store := mustOpen(t, dir)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, filename), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "permissions must be 0600") {
				t.Fatalf("insecure %s permissions accepted: %v", filename, err)
			}
		})
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	return mustOpen(t, t.TempDir())
}

func mustOpen(t *testing.T, dir string) *Store {
	t.Helper()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close evidence store: %v", err)
		}
	})
	return store
}

func testEvent(action string) EvidenceEvent {
	return EvidenceEvent{
		Action: action,
		Target: "routing/default",
		Result: "success",
		Data:   map[string]string{"summaryRef": "sha256:example"},
	}
}

func mustAppend(t *testing.T, store *Store, action string) EvidenceEvent {
	t.Helper()
	event, err := store.Append(testEvent(action))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func storedTestEvent(t *testing.T, action, key, previousHash string) EvidenceEvent {
	t.Helper()
	event := testEvent(action)
	event.ID = "evt-" + action
	event.TraceID = "trace-test"
	event.ActorID = "actor-test"
	event.OccurredAt = time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	event.IdempotencyKey = key
	event.PreviousHash = previousHash
	hash, err := eventHash(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Hash = hash
	return event
}
