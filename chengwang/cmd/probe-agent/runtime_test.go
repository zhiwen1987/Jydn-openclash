package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"chengwang/internal/probe"
)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (log *eventLog) add(event string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.events = append(log.events, event)
}

func (log *eventLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

type fakeResolver struct{}

func (fakeResolver) ResolveHost(context.Context, string) (probe.DNSResolution, error) {
	return probe.DNSResolution{CanonicalChain: []string{"canary.example.com"}, Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}, nil
}

type fakeExecutor struct {
	log    *eventLog
	result probe.ProbeResult
	called chan struct{}
}

func (executor *fakeExecutor) ResolveAndRun(context.Context, probe.Catalog, string, probe.Resolver) probe.ProbeResult {
	executor.log.add("network")
	if executor.called != nil {
		close(executor.called)
	}
	return executor.result
}

type fakeStore struct {
	log       *eventLog
	appendErr error
}

func (store *fakeStore) Append(result probe.ProbeResult) error {
	store.log.add("spool:" + result.EvidenceRef)
	return store.appendErr
}

func (*fakeStore) Close() error { return nil }

type fakeLedger struct {
	log       *eventLog
	recordErr error
	settleErr error
	settled   chan struct{}
}

func (ledger *fakeLedger) RecordStart(startID, probeID string, _ time.Time) error {
	ledger.log.add("start:" + startID + ":" + probeID)
	return ledger.recordErr
}

func (ledger *fakeLedger) Settle(startID string, _ probe.ProbeResult) error {
	ledger.log.add("settle:" + startID)
	if ledger.settled != nil {
		close(ledger.settled)
	}
	return ledger.settleErr
}

func (ledger *fakeLedger) SettleRecovered(startID string, result probe.ProbeResult) error {
	ledger.log.add("recover:" + startID + ":" + result.RunID)
	return ledger.settleErr
}

func (*fakeLedger) Close() error { return nil }

func TestBuildSchedulerEnforcesDurableStartNetworkSpoolSettleOrder(t *testing.T) {
	log := &eventLog{}
	settled := make(chan struct{})
	catalog := commandTestCatalog(t)
	base := time.Now().UTC()
	current := base.Add(time.Hour)
	executor := &fakeExecutor{log: log, result: probe.ProbeResult{ProbeID: catalog.Probes[0].ID}}
	store := &fakeStore{log: log}
	ledger := &fakeLedger{log: log, settled: settled}
	scheduler, err := buildScheduler(catalog, executor, fakeResolver{}, store, ledger, schedulerInputs{
		anchor: base, concurrency: 1, queueSize: 1, startsPerMinute: 1,
		newStartID: func() (string, error) { return "start-1", nil },
		now:        func() time.Time { return current },
	})
	if err != nil {
		t.Fatalf("buildScheduler() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	scheduler.DispatchDue(current)
	select {
	case <-settled:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not settle local fake result")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Scheduler.Run() error = %v", err)
	}
	want := []string{"start:start-1:canary", "network", "spool:start-1", "settle:start-1"}
	if got := log.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}
}

func TestBuildSchedulerFailsClosedBeforeNetworkAndBeforeSettlement(t *testing.T) {
	catalog := commandTestCatalog(t)
	base := time.Now().UTC()
	current := base.Add(time.Hour)

	t.Run("start persistence failure", func(t *testing.T) {
		log := &eventLog{}
		executor := &fakeExecutor{log: log, called: make(chan struct{})}
		ledger := &fakeLedger{log: log, recordErr: errors.New("disk failed")}
		scheduler := mustTestScheduler(t, catalog, executor, &fakeStore{log: log}, ledger, base, &current)
		runOneCycle(t, scheduler, current)
		if got := log.snapshot(); !reflect.DeepEqual(got, []string{"start:start-1:canary"}) {
			t.Fatalf("events = %v", got)
		}
		status := scheduler.Status()
		if status.StorageHealthy || status.StorageIssue != "start_persistence_failed" {
			t.Fatalf("status = %+v", status)
		}
	})

	t.Run("spool failure", func(t *testing.T) {
		log := &eventLog{}
		settled := make(chan struct{})
		executor := &fakeExecutor{log: log, result: probe.ProbeResult{ProbeID: "canary"}}
		ledger := &fakeLedger{log: log, settled: settled}
		scheduler := mustTestScheduler(t, catalog, executor, &fakeStore{log: log, appendErr: errors.New("full")}, ledger, base, &current)
		runOneCycle(t, scheduler, current)
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			if scheduler.Status().SinkFailures == 1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case <-settled:
			t.Fatal("ledger settled despite spool failure")
		default:
		}
		want := []string{"start:start-1:canary", "network", "spool:start-1"}
		if got := log.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("events = %v, want %v", got, want)
		}
	})
}

func TestMergeNotBeforeKeepsLatestVerifiedDeadline(t *testing.T) {
	base := time.Now().UTC()
	merged := mergeNotBefore(
		map[string]time.Time{"one": base.Add(time.Minute), "two": base.Add(3 * time.Minute)},
		map[string]time.Time{"one": base.Add(2 * time.Minute), "two": base.Add(time.Minute), "three": base.Add(4 * time.Minute)},
	)
	if !merged["one"].Equal(base.Add(2*time.Minute)) || !merged["two"].Equal(base.Add(3*time.Minute)) || !merged["three"].Equal(base.Add(4*time.Minute)) {
		t.Fatalf("merged deadlines = %v", merged)
	}
}

func TestReconcileInflightResultsIsExactAndUsesRecoverySettlement(t *testing.T) {
	log := &eventLog{}
	ledger := &fakeLedger{log: log}
	state := probe.StartLedgerSnapshot{InFlight: []probe.StartLedgerEntry{{StartID: "start-1", ProbeID: "canary"}}}
	result := probe.ProbeResult{RunID: "run-1", ProbeID: "canary", EvidenceRef: "start-1"}
	if err := reconcileInflightResults(ledger, state, []probe.ProbeResult{result}); err != nil {
		t.Fatal(err)
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, []string{"recover:start-1:run-1"}) {
		t.Fatalf("recovery events = %v", got)
	}
	if err := reconcileInflightResults(ledger, state, []probe.ProbeResult{result, result}); err == nil {
		t.Fatal("ambiguous persisted results were accepted")
	}
	wrong := result
	wrong.ProbeID = "other"
	if err := reconcileInflightResults(ledger, state, []probe.ProbeResult{wrong}); err == nil {
		t.Fatal("wrong-probe persisted result was accepted")
	}
}

func TestCrashWindowRecoveryWithRealStoreAndLedger(t *testing.T) {
	t.Run("fresh evidence survives a second restart", func(t *testing.T) {
		catalog := commandTestCatalog(t)
		base := time.Now().UTC().Add(-time.Second)
		current := base
		spoolDirectory := t.TempDir()
		ledgerDirectory := t.TempDir()
		result := commandTestResult(catalog, base, "fresh-result", "fresh-start")
		stageCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, "fresh-start", []probe.ProbeResult{result})

		current = base.Add(10 * time.Second)
		recoverCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, func(snapshot probe.StartLedgerSnapshot) {
			if len(snapshot.InFlight) != 0 || len(snapshot.RecentStartTimes) != 1 {
				t.Fatalf("fresh recovery snapshot = %+v", snapshot)
			}
		})

		current = base.Add(20 * time.Second)
		recoverCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, func(snapshot probe.StartLedgerSnapshot) {
			if len(snapshot.InFlight) != 0 || len(snapshot.RecentStartTimes) != 1 {
				t.Fatalf("second restart was not idempotent: %+v", snapshot)
			}
		})
	})

	t.Run("expired 429 restores NotBefore once", func(t *testing.T) {
		catalog := commandTestCatalog(t)
		base := time.Now().UTC().Add(-time.Second)
		current := base
		spoolDirectory := t.TempDir()
		ledgerDirectory := t.TempDir()
		result := commandTestResult(catalog, base, "rate-result", "rate-start")
		status := 429
		result.Conclusion = probe.ConclusionRateLimited
		result.Outcome = probe.OutcomeIndeterminate
		result.HTTPStatus = &status
		result.ErrorClass = "rate_limited"
		result.Layers.Business.State = probe.LayerRateLimited
		result.Layers.Business.Reason = "rate_limited"
		result.Layers.Business.RetryAfterSeconds = 120
		stageCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, "rate-start", []probe.ProbeResult{result})

		wantNotBefore := result.CompletedAt.Add(120 * time.Second)
		current = base.Add(65 * time.Second)
		recoverCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, func(snapshot probe.StartLedgerSnapshot) {
			if len(snapshot.InFlight) != 0 || len(snapshot.RateLimits) != 1 || !snapshot.NotBefore[catalog.Probes[0].ID].Equal(wantNotBefore) {
				t.Fatalf("expired 429 recovery snapshot = %+v", snapshot)
			}
		})

		current = base.Add(66 * time.Second)
		recoverCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, func(snapshot probe.StartLedgerSnapshot) {
			if len(snapshot.InFlight) != 0 || len(snapshot.RateLimits) != 1 || !snapshot.NotBefore[catalog.Probes[0].ID].Equal(wantNotBefore) {
				t.Fatalf("second 429 restart was not idempotent: %+v", snapshot)
			}
		})
	})

	t.Run("duplicate evidence fails closed", func(t *testing.T) {
		catalog := commandTestCatalog(t)
		base := time.Now().UTC().Add(-time.Second)
		current := base
		spoolDirectory := t.TempDir()
		ledgerDirectory := t.TempDir()
		first := commandTestResult(catalog, base, "duplicate-one", "duplicate-start")
		second := commandTestResult(catalog, base.Add(time.Millisecond), "duplicate-two", "duplicate-start")
		stageCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, "duplicate-start", []probe.ProbeResult{first, second})

		current = base.Add(10 * time.Second)
		store, ledger, state, report := openCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current)
		defer store.Close()
		defer ledger.Close()
		if err := reconcileInflightResults(ledger, state, report.Results); err == nil {
			t.Fatal("duplicate persisted evidence was accepted")
		}
		snapshot, err := ledger.Snapshot()
		if err != nil || len(snapshot.InFlight) != 1 || snapshot.InFlight[0].StartID != "duplicate-start" {
			t.Fatalf("duplicate evidence mutated ledger: snapshot=%+v err=%v", snapshot, err)
		}
	})

	t.Run("wrong evidence reference remains in flight", func(t *testing.T) {
		catalog := commandTestCatalog(t)
		base := time.Now().UTC().Add(-time.Second)
		current := base
		spoolDirectory := t.TempDir()
		ledgerDirectory := t.TempDir()
		wrong := commandTestResult(catalog, base, "wrong-reference-result", "other-start")
		stageCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, "expected-start", []probe.ProbeResult{wrong})

		current = base.Add(10 * time.Second)
		recoverCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, &current, func(snapshot probe.StartLedgerSnapshot) {
			if len(snapshot.InFlight) != 1 || snapshot.InFlight[0].StartID != "expected-start" {
				t.Fatalf("wrong evidence reference settled a start: %+v", snapshot)
			}
		})
	})
}

func TestApplicationInitializesWithoutNetworkAndReleasesLocksOnCancellation(t *testing.T) {
	base := t.TempDir()
	catalog := commandTestCatalog(t)
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(base, "catalog.json")
	if err := os.WriteFile(catalogPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := replaceArgument(validArguments(base), "--catalog", catalogPath)
	value, err := parseConfig(arguments, nil)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	app, err := newApplication(value)
	if err != nil {
		t.Fatalf("newApplication() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := app.run(ctx); err != nil {
		t.Fatalf("application.run(canceled) error = %v", err)
	}

	// Reopening both exclusive writers proves graceful shutdown closed both
	// lock handles. No dispatch occurred, so the fixed public test endpoint was
	// never contacted.
	store, err := probe.OpenStore(value.spoolDirectory, catalog, probe.StoreLimits{
		MaxEntries: value.spoolMaxEntries, MaxBytes: value.spoolMaxBytes,
	})
	if err != nil {
		t.Fatalf("reopen result store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close reopened result store: %v", err)
	}
	ledger, err := probe.OpenStartLedger(value.ledgerDirectory, catalog, probe.StartLedgerOptions{
		MaxEntries: value.ledgerMaxEntries, MaxBytes: value.ledgerMaxBytes,
	})
	if err != nil {
		t.Fatalf("reopen start ledger: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatalf("close reopened start ledger: %v", err)
	}
}

func mustTestScheduler(t *testing.T, catalog probe.Catalog, executor probeExecutor, store resultStore, ledger durableLedger, anchor time.Time, current *time.Time) *probe.Scheduler {
	t.Helper()
	scheduler, err := buildScheduler(catalog, executor, fakeResolver{}, store, ledger, schedulerInputs{
		anchor: anchor, concurrency: 1, queueSize: 1, startsPerMinute: 1,
		newStartID: func() (string, error) { return "start-1", nil },
		now:        func() time.Time { return *current },
	})
	if err != nil {
		t.Fatalf("buildScheduler() error = %v", err)
	}
	return scheduler
}

func runOneCycle(t *testing.T, scheduler *probe.Scheduler, at time.Time) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	scheduler.DispatchDue(at)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		status := scheduler.Status()
		if status.Active == 0 && (status.Canceled > 0 || status.Completed > 0) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Scheduler.Run() error = %v", err)
	}
}

func commandTestCatalog(t *testing.T) probe.Catalog {
	t.Helper()
	raw := []byte(`{
  "schema":"chengwang.probe-catalog/v1",
  "revision":"test-v1",
  "agent":{"id":"test-agent","independence":"P1","advisoryOnly":true},
  "paths":[{"id":"direct","kind":"direct"}],
  "probes":[{
    "id":"canary","pathId":"direct","kind":"https","host":"canary.example.com","port":443,
    "requestPath":"/healthz","method":"GET","expectedStatus":[200],"requiredMarker":"owned",
    "intervalSeconds":30,"timeoutSeconds":1,"ttlSeconds":60,"maxBodyBytes":1024
  }]
}`)
	catalog, err := probe.ParseCatalogBytes(raw)
	if err != nil {
		t.Fatalf("ParseCatalogBytes() error = %v", err)
	}
	return catalog
}

func commandTestResult(catalog probe.Catalog, attempted time.Time, runID, evidenceRef string) probe.ProbeResult {
	target := catalog.Probes[0]
	completed := attempted.Add(100 * time.Millisecond)
	expires := completed.Add(time.Duration(target.TTLSeconds) * time.Second)
	available := probe.LayerResult{State: probe.LayerAvailable, ObservedAt: completed, ExpiresAt: expires, Reason: "contract_matched"}
	status := 200
	return probe.ProbeResult{
		SchemaVersion: probe.ResultSchemaV1, RunID: runID, ProbeID: target.ID,
		CatalogDigest: catalog.Digest, AgentID: catalog.Agent.ID, Independence: catalog.Agent.Independence,
		PathID: target.PathID, AttemptedAt: attempted, CompletedAt: completed, ExpiresAt: expires,
		Conclusion: probe.ConclusionAvailable, Outcome: probe.OutcomePass, HTTPStatus: &status,
		ContentDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		EvidenceRef:   evidenceRef, AdvisoryOnly: true,
		Layers: probe.LayerResults{DNS: available, Connect: available, TLS: available, HTTP: available, Business: available},
	}
}

func stageCrashWindow(t *testing.T, spoolDirectory, ledgerDirectory string, catalog probe.Catalog, current *time.Time, startID string, results []probe.ProbeResult) {
	t.Helper()
	store, err := probe.OpenStore(spoolDirectory, catalog, probe.StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := probe.OpenStartLedger(ledgerDirectory, catalog, probe.StartLedgerOptions{Now: func() time.Time { return *current }})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := ledger.RecordStart(startID, catalog.Probes[0].ID, *current); err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if err := store.Append(result); err != nil {
			t.Fatal(err)
		}
	}
	// Closing without Settle models a process crash after immutable evidence was
	// committed but before the corresponding ledger mutation.
	if err := errors.Join(ledger.Close(), store.Close()); err != nil {
		t.Fatal(err)
	}
}

func openCrashWindow(t *testing.T, spoolDirectory, ledgerDirectory string, catalog probe.Catalog, current *time.Time) (*probe.Store, *probe.StartLedger, probe.StartLedgerSnapshot, probe.ReadReport) {
	t.Helper()
	store, err := probe.OpenStore(spoolDirectory, catalog, probe.StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := probe.OpenStartLedger(ledgerDirectory, catalog, probe.StartLedgerOptions{Now: func() time.Time { return *current }})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	state, err := ledger.Snapshot()
	if err != nil {
		ledger.Close()
		store.Close()
		t.Fatal(err)
	}
	report, err := probe.ReadStore(spoolDirectory, probe.ReadOptions{Catalog: catalog, Now: *current, IncludeExpired: true})
	if err != nil || !report.Healthy {
		ledger.Close()
		store.Close()
		t.Fatalf("read crash-window evidence: report=%+v err=%v", report, err)
	}
	return store, ledger, state, report
}

func recoverCrashWindow(t *testing.T, spoolDirectory, ledgerDirectory string, catalog probe.Catalog, current *time.Time, assert func(probe.StartLedgerSnapshot)) {
	t.Helper()
	store, ledger, state, report := openCrashWindow(t, spoolDirectory, ledgerDirectory, catalog, current)
	if err := reconcileInflightResults(ledger, state, report.Results); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ledger.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	assert(snapshot)
	if err := errors.Join(ledger.Close(), store.Close()); err != nil {
		t.Fatal(err)
	}
}
