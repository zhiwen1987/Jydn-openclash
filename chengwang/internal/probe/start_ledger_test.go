package probe

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartLedgerRestoresRecentStartsAndInflightAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordStart("run-one", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	current = base.Add(time.Second)
	if err := ledger.RecordStart("run-two", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	result := validTestResult(base, "run-one")
	result.EvidenceRef = "run-one"
	current = base.Add(1100 * time.Millisecond)
	if err := ledger.Settle("run-one", result); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Settle("run-one", result); err != nil {
		t.Fatalf("exact settlement replay was not idempotent: %v", err)
	}
	conflicting := result
	conflicting.RunID = "different-result-run"
	if err := ledger.Settle("run-one", conflicting); err == nil {
		t.Fatal("different result run was accepted for an already settled start")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	current = base.Add(30 * time.Second)
	restored, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	snapshot, err := restored.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RecentStartTimes) != 2 {
		t.Fatalf("recent starts = %d, want 2", len(snapshot.RecentStartTimes))
	}
	if len(snapshot.InFlight) != 1 || snapshot.InFlight[0].StartID != "run-two" {
		t.Fatalf("unexpected restored in-flight records: %+v", snapshot.InFlight)
	}
}

func TestStartLedgerSettlementRetainsMinuteBudgetAndRateLimit(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	if err := ledger.RecordStart("start-rate", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	rateResult := rateLimitedLedgerResult(base.Add(50*time.Millisecond), "rate-run", 1800)
	rateResult.EvidenceRef = "start-rate"
	current = rateResult.CompletedAt
	if err := ledger.Settle("start-rate", rateResult); err != nil {
		t.Fatal(err)
	}

	current = base.Add(2 * time.Second)
	if err := ledger.RecordStart("start-success", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	success := validTestResult(current.Add(50*time.Millisecond), "success-run")
	success.EvidenceRef = "start-success"
	current = success.CompletedAt
	if err := ledger.Settle("start-success", success); err != nil {
		t.Fatal(err)
	}

	snapshot, err := ledger.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RecentStartTimes) != 2 {
		t.Fatalf("settled starts disappeared from minute budget: %+v", snapshot.RecentStartTimes)
	}
	wantNotBefore := rateResult.CompletedAt.Add(30 * time.Minute)
	if got := snapshot.NotBefore[catalog.Probes[0].ID]; !got.Equal(wantNotBefore) {
		t.Fatalf("rate limit notBefore = %v, want %v", got, wantNotBefore)
	}
	if len(snapshot.RateLimits) != 1 || snapshot.RateLimits[0].SourceRunID != "rate-run" {
		t.Fatalf("successful settlement erased rate-limit evidence: %+v", snapshot.RateLimits)
	}
}

func TestStartLedgerPrunesOnlyExpiredBudgetWindow(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{MaxEntries: 2, Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("run-one", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	current = base.Add(time.Second)
	if err := ledger.RecordStart("run-two", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	current = base.Add(2 * time.Second)
	if err := ledger.RecordStart("run-three", catalog.Probes[0].ID, current); !errors.Is(err, ErrStartLedgerFull) {
		t.Fatalf("third start error = %v, want ErrStartLedgerFull", err)
	}

	current = base.Add(72 * time.Second)
	if err := ledger.RecordStart("run-three", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ledger.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RecentStartTimes) != 1 || !snapshot.RecentStartTimes[0].Equal(current) {
		t.Fatalf("expired start budget was not pruned: %+v", snapshot.RecentStartTimes)
	}
}

func TestStartLedgerByteBudgetRefusesUnboundedGrowth(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{
		MaxEntries: MaximumStartLedgerEntries,
		MaxBytes:   MinimumStartLedgerBytes,
		Now:        func() time.Time { return current },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	bounded := false
	for i := 0; i < MaximumStartLedgerEntries; i++ {
		startID := strings.Repeat("x", 110) + "-" + time.Unix(int64(i), 0).UTC().Format("150405")
		if err := ledger.RecordStart(startID, catalog.Probes[0].ID, current); err != nil {
			if !errors.Is(err, ErrStartLedgerFull) {
				t.Fatalf("byte budget error = %v, want ErrStartLedgerFull", err)
			}
			bounded = true
			break
		}
	}
	if !bounded {
		t.Fatal("configured byte budget did not bound ledger growth")
	}
}

func TestStartLedgerRejectsClockRollbackAndFutureSnapshot(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := t.TempDir()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	current = base.Add(10 * time.Second)
	if err := ledger.RecordStart("future-run", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	current = base.Add(9 * time.Second)
	if _, err := ledger.Snapshot(); !errors.Is(err, ErrStartLedgerClock) {
		t.Fatalf("rollback snapshot error = %v, want ErrStartLedgerClock", err)
	}
	if health := ledger.Health(); health.Healthy || health.Writable || health.Issue != "clock_rollback" {
		t.Fatalf("clock rollback did not fail closed: %+v", health)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	current = base
	if _, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }}); err == nil || !strings.Contains(err.Error(), "clock_invalid") {
		t.Fatalf("future snapshot open error = %v, want clock_invalid", err)
	}
}

func TestStartLedgerRejectsFutureStartWithoutPersistingIt(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("future-run", catalog.Probes[0].ID, base.Add(time.Second)); !errors.Is(err, ErrStartLedgerClock) {
		t.Fatalf("future start error = %v, want ErrStartLedgerClock", err)
	}
	if snapshot := ledger.Health(); snapshot.Healthy || snapshot.Writable || len(snapshot.RecentStartTimes) != 0 {
		t.Fatalf("future start did not fail closed cleanly: %+v", snapshot)
	}
}

func TestStartLedgerUsesCommitClockForConcurrentStartOrdering(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	current = base.Add(10 * time.Second)
	if err := ledger.RecordStart("first-start", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	current = base.Add(11 * time.Second)
	if err := ledger.RecordStart("sampled-before-prior-commit", catalog.Probes[0].ID, base.Add(9*time.Second)); err != nil {
		t.Fatalf("a recent caller sample must not be mistaken for clock rollback: %v", err)
	}
	snapshot, err := ledger.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.InFlight) != 2 || !snapshot.InFlight[1].StartedAt.Equal(current) {
		t.Fatalf("ledger did not bind the second start to its commit clock: %+v", snapshot.InFlight)
	}
}

func TestStartLedgerFutureSettlementFailsClosed(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("future-settlement", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	result := validTestResult(base, "future-result")
	result.EvidenceRef = "future-settlement"
	if err := ledger.Settle("future-settlement", result); !errors.Is(err, ErrStartLedgerClock) {
		t.Fatalf("future settlement error = %v, want ErrStartLedgerClock", err)
	}
	if health := ledger.Health(); health.Healthy || health.Writable || health.Issue != "future_time_invalid" {
		t.Fatalf("future settlement did not fail closed: %+v", health)
	}
}

func TestStartLedgerRecoveredFutureSettlementFailsClosed(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("future-recovered-settlement", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	result := validTestResult(base, "future-recovered-result")
	result.EvidenceRef = "future-recovered-settlement"
	if err := ledger.SettleRecovered("future-recovered-settlement", result); !errors.Is(err, ErrStartLedgerClock) {
		t.Fatalf("future recovered settlement error = %v, want ErrStartLedgerClock", err)
	}
	if health := ledger.Health(); health.Healthy || health.Writable || health.Issue != "future_time_invalid" {
		t.Fatalf("future recovered settlement did not fail closed: %+v", health)
	}
}

func TestStartLedgerRejectsSettlementEvidenceMismatch(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("expected-start", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	result := validTestResult(base, "result-run")
	result.EvidenceRef = "different-start"
	if err := ledger.Settle("expected-start", result); err == nil || !strings.Contains(err.Error(), "evidence reference mismatch") {
		t.Fatalf("mismatched evidence reference was accepted: %v", err)
	}
}

func TestStartLedgerRecoveredSettlementAcceptsExpiredVerifiedEvidence(t *testing.T) {
	catalog := testSpoolCatalog(t)
	catalog.Probes[0].IntervalSeconds = 30
	catalog.Probes[0].TTLSeconds = 30
	catalog.Digest = ""
	digest, err := DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Digest = digest
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("crash-start", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	result := validTestResult(base, "crash-result")
	result.CatalogDigest = catalog.Digest
	result.ExpiresAt = result.CompletedAt.Add(30 * time.Second)
	result.Layers.DNS.ExpiresAt = result.ExpiresAt
	result.Layers.Connect.ExpiresAt = result.ExpiresAt
	result.Layers.TLS.ExpiresAt = result.ExpiresAt
	result.Layers.HTTP.ExpiresAt = result.ExpiresAt
	result.Layers.Business.ExpiresAt = result.ExpiresAt
	result.EvidenceRef = "crash-start"
	current = base.Add(40 * time.Second)
	if err := ledger.Settle("crash-start", result); err == nil || !strings.Contains(err.Error(), "expired_result") {
		t.Fatalf("live settlement accepted expired evidence: %v", err)
	}
	if err := ledger.SettleRecovered("crash-start", result); err != nil {
		t.Fatalf("verified crash recovery could not settle historical evidence: %v", err)
	}
	if snapshot, err := ledger.Snapshot(); err != nil || len(snapshot.InFlight) != 0 {
		t.Fatalf("recovered start remained in flight: snapshot=%+v err=%v", snapshot, err)
	}
}

func TestStartLedgerHealthUsesCurrentTimeForExpiry(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.RecordStart("expiring-start", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	current = base.Add(71 * time.Second)
	health := ledger.Health()
	if len(health.RecentStartTimes) != 0 || len(health.InFlight) != 0 {
		t.Fatalf("health retained expired start state: %+v", health)
	}
}

func TestStartLedgerCleansOnlyInterruptedRegularTempFiles(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(directory, startLedgerSnapshotsDir, ".start-ledger-crash.tmp")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatalf("regular interrupted temp blocked recovery: %v", err)
	}
	defer reopened.Close()
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted temp was not removed: %v", err)
	}
}

func TestStartLedgerDetectsRuntimeRollbackAfterReadOnlySnapshot(t *testing.T) {
	catalog := testSpoolCatalog(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(t.TempDir(), catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	current = base.Add(30 * time.Second)
	if _, err := ledger.Snapshot(); err != nil {
		t.Fatal(err)
	}
	current = base.Add(20 * time.Second)
	if _, err := ledger.Snapshot(); !errors.Is(err, ErrStartLedgerClock) {
		t.Fatalf("runtime rollback error = %v, want ErrStartLedgerClock", err)
	}
}

func TestStartLedgerIsCatalogAndDirectoryBound(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := filepath.Join(t.TempDir(), "ledger-a")
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	otherCatalog := catalog
	otherCatalog.Revision = "other"
	digest, err := DigestCatalog(otherCatalog)
	if err != nil {
		t.Fatal(err)
	}
	otherCatalog.Digest = digest
	if _, err := OpenStartLedger(directory, otherCatalog, StartLedgerOptions{Now: func() time.Time { return base }}); err == nil || !strings.Contains(err.Error(), "binding_invalid") {
		t.Fatalf("catalog mismatch error = %v", err)
	}

	moved := filepath.Join(filepath.Dir(directory), "ledger-b")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStartLedger(moved, catalog, StartLedgerOptions{Now: func() time.Time { return base }}); err == nil || !strings.Contains(err.Error(), "binding_invalid") {
		t.Fatalf("directory mismatch error = %v", err)
	}
}

func TestStartLedgerUsesExclusiveWriterLock(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := t.TempDir()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	first, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }}); !errors.Is(err, ErrStartLedgerLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second writer error = %v, want ErrStartLedgerLocked", err)
	}
}

func TestStartLedgerPersistenceFailureFreezesAndRecovers(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := t.TempDir()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := base
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	ledger.syncDir = func(string) error { return errors.New("injected sync failure") }
	current = base.Add(time.Second)
	if err := ledger.RecordStart("durable-run", catalog.Probes[0].ID, current); err == nil {
		t.Fatal("injected persistence failure was ignored")
	}
	if health := ledger.Health(); health.Healthy || health.Writable || health.Issue != "persistence_failed" {
		t.Fatalf("persistence failure did not freeze ledger: %+v", health)
	}
	if err := ledger.RecordStart("blocked-run", catalog.Probes[0].ID, current); !errors.Is(err, ErrStartLedgerReadOnly) {
		t.Fatalf("write after persistence failure = %v, want read-only", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	current = base.Add(2 * time.Second)
	restored, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	snapshot, err := restored.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RecentStartTimes) != 1 || len(snapshot.InFlight) != 1 || snapshot.InFlight[0].StartID != "durable-run" {
		t.Fatalf("committed snapshot was not recovered: %+v", snapshot)
	}
}

func TestStartLedgerRejectsTamperingAndDuplicateJSONKeys(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := t.TempDir()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, startLedgerSnapshotsDir))
	if err != nil || len(entries) != 1 {
		t.Fatalf("snapshot entries = %v, err = %v", entries, err)
	}
	path := filepath.Join(directory, startLedgerSnapshotsDir, entries[0].Name())
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `"schema":`, `"schema":"duplicate","schema":`, 1))
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }}); err == nil || !strings.Contains(err.Error(), "duplicate JSON") {
		t.Fatalf("duplicate-key snapshot error = %v", err)
	}
}

func TestStartLedgerUsesV2SchemaAndRejectsV1(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := t.TempDir()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, startLedgerSnapshotsDir))
	if err != nil || len(entries) != 1 {
		t.Fatalf("snapshot entries = %v, err = %v", entries, err)
	}
	path := filepath.Join(directory, startLedgerSnapshotsDir, entries[0].Name())
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state startLedgerDisk
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatal(err)
	}
	if StartLedgerSchemaV2 != "chengwang.probe-start-ledger/v2" {
		t.Fatalf("schema constant = %q, want v2", StartLedgerSchemaV2)
	}
	if state.Schema != StartLedgerSchemaV2 {
		t.Fatalf("persisted schema = %q, want v2", state.Schema)
	}

	state.Schema = "chengwang.probe-start-ledger/v1"
	digest, err := digestStartLedgerState(state)
	if err != nil {
		t.Fatal(err)
	}
	state.Digest = digest
	payload, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }}); err == nil || !strings.Contains(err.Error(), "binding_invalid") {
		t.Fatalf("legacy v1 snapshot error = %v, want binding_invalid", err)
	}
}

func TestStartLedgerPersistsNoNetworkOrCredentialMaterial(t *testing.T) {
	catalog := testSpoolCatalog(t)
	directory := t.TempDir()
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenStartLedger(directory, catalog, StartLedgerOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordStart("safe-run", catalog.Probes[0].ID, base); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, startLedgerSnapshotsDir))
	if err != nil || len(entries) != 1 {
		t.Fatalf("snapshot entries = %v, err = %v", entries, err)
	}
	payload, err := os.ReadFile(filepath.Join(directory, startLedgerSnapshotsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"https://", catalog.Probes[0].Host, "password", "credential", "127.0.0.1"} {
		if strings.Contains(string(payload), prohibited) {
			t.Fatalf("ledger persisted prohibited material %q: %s", prohibited, payload)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []string{"schema", "catalogDigest", "directoryDigest", "agentId", "sequence", "lastClock", "starts", "digest"} {
		delete(decoded, allowed)
	}
	delete(decoded, "rateLimits")
	if len(decoded) != 0 {
		t.Fatalf("unexpected top-level persisted fields: %+v", decoded)
	}
}

func rateLimitedLedgerResult(at time.Time, runID string, retrySeconds int64) ProbeResult {
	result := validTestResult(at, runID)
	status := 429
	result.Conclusion = ConclusionRateLimited
	result.Outcome = OutcomeIndeterminate
	result.HTTPStatus = &status
	result.ErrorClass = "rate_limited"
	result.Layers.Business.State = LayerRateLimited
	result.Layers.Business.Reason = "rate_limited"
	result.Layers.Business.RetryAfterSeconds = retrySeconds
	return result
}
