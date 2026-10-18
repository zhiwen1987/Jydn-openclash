package probe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerDefaultsValidationAndDeterministicJitter(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	run := func(context.Context) ProbeResult { return ProbeResult{} }
	scheduler, err := NewScheduler([]Task{schedulerTask("one", "one.example", 30*time.Second, 10*time.Second, run)}, SchedulerOptions{Anchor: anchor})
	if err != nil {
		t.Fatal(err)
	}
	if scheduler.concurrency != 2 || cap(scheduler.queue) != DefaultProbeQueueSize {
		t.Fatalf("unexpected defaults: concurrency=%d queue=%d", scheduler.concurrency, cap(scheduler.queue))
	}
	first, _ := scheduler.NextDue("one")
	secondScheduler, err := NewScheduler([]Task{schedulerTask("one", "one.example", 30*time.Second, time.Second, run)}, SchedulerOptions{Anchor: anchor})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := secondScheduler.NextDue("one")
	if !first.Equal(second) || first.Before(anchor.Add(MinimumProbeInterval)) || first.After(anchor.Add(36*time.Second)) {
		t.Fatalf("jitter not deterministic and bounded: first=%s second=%s", first, second)
	}
	if _, err := NewScheduler([]Task{schedulerTask("bad", "bad.example", 29*time.Second, time.Second, run)}, SchedulerOptions{}); err == nil {
		t.Fatal("expected sub-minimum interval rejection")
	}
	if _, err := NewScheduler([]Task{schedulerTask("bad", "bad.example", 30*time.Second, 11*time.Second, run)}, SchedulerOptions{}); err == nil {
		t.Fatal("expected oversized timeout rejection")
	}
	if _, err := NewScheduler(make([]Task, MaxCatalogTargets+1), SchedulerOptions{}); err == nil {
		t.Fatal("expected oversized task set rejection")
	}
}

func TestSchedulerBoundsConcurrencyAndPreventsProbeOverlap(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	started := make(chan string, 4)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	makeRun := func(id string) func(context.Context) ProbeResult {
		return func(ctx context.Context) ProbeResult {
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			started <- id
			select {
			case <-release:
			case <-ctx.Done():
			}
			active.Add(-1)
			return ProbeResult{}
		}
	}
	tasks := []Task{
		schedulerTask("a", "a.example", 30*time.Second, 10*time.Second, makeRun("a")),
		schedulerTask("b", "b.example", 30*time.Second, 10*time.Second, makeRun("b")),
		schedulerTask("c", "c.example", 30*time.Second, 10*time.Second, makeRun("c")),
	}
	scheduler, err := NewScheduler(tasks, SchedulerOptions{
		Anchor: anchor, QueueSize: 3, GlobalConcurrency: 2,
		Now: func() time.Time { return anchor.Add(3 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(anchor.Add(time.Minute))
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	// Dispatch far beyond the next due while the same probes are active. No
	// probe may be queued a second time.
	scheduler.DispatchDue(anchor.Add(3 * time.Minute))
	if maximum.Load() != 2 {
		t.Fatalf("maximum concurrency=%d want 2", maximum.Load())
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Completed < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if status := scheduler.Status(); status.Completed != 3 || status.Started != 3 {
		t.Fatalf("unexpected completion after overlap attempt: %+v", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerAllowsOnlyOneQueuedOrRunningProbePerHost(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	run := func(context.Context) ProbeResult { return ProbeResult{} }
	scheduler, err := NewScheduler([]Task{
		schedulerTask("a", "shared.example", 30*time.Second, time.Second, run),
		schedulerTask("b", "shared.example", 30*time.Second, time.Second, run),
	}, SchedulerOptions{Anchor: anchor, GlobalConcurrency: 2, QueueSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.DispatchDue(anchor.Add(time.Minute))
	status := scheduler.Status()
	if status.Queued != 1 || status.QueueSkipped != 1 {
		t.Fatalf("same-host tasks were queued together: %+v", status)
	}
}

func TestSchedulerQueueBudgetAndClockRollbackFreeze(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	run := func(context.Context) ProbeResult { return ProbeResult{} }
	tasks := []Task{
		schedulerTask("a", "a.example", 30*time.Second, time.Second, run),
		schedulerTask("b", "b.example", 30*time.Second, time.Second, run),
		schedulerTask("c", "c.example", 30*time.Second, time.Second, run),
	}
	budgeted, err := NewScheduler(tasks, SchedulerOptions{Anchor: anchor, GlobalConcurrency: 1, QueueSize: 3, MaxStartsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	budgeted.DispatchDue(anchor.Add(time.Minute))
	if status := budgeted.Status(); status.Queued != 1 || status.BudgetSkipped != 2 {
		t.Fatalf("budget not enforced: %+v", status)
	}
	queued, err := NewScheduler(tasks[:2], SchedulerOptions{Anchor: anchor, GlobalConcurrency: 1, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	queued.DispatchDue(anchor.Add(time.Minute))
	if status := queued.Status(); status.Queued != 1 || status.QueueSkipped != 1 {
		t.Fatalf("queue not bounded: %+v", status)
	}
	queued.DispatchDue(anchor.Add(30 * time.Second))
	status := queued.Status()
	if status.ClockHealthy || status.ClockIssue != "clock_rollback" {
		t.Fatalf("clock rollback did not freeze scheduler: %+v", status)
	}
	before := status.Queued
	queued.DispatchDue(anchor.Add(10 * time.Minute))
	if after := queued.Status(); after.Queued != before {
		t.Fatalf("frozen scheduler changed queue: before=%d after=%d", before, after.Queued)
	}
}

func TestSchedulerQueuedReservationDoesNotExpireBeforeNetworkStart(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	tasks := []Task{
		schedulerTask("a", "a.example", 30*time.Second, time.Second, func(context.Context) ProbeResult { return ProbeResult{} }),
		schedulerTask("b", "b.example", 30*time.Second, time.Second, func(context.Context) ProbeResult { return ProbeResult{} }),
	}
	scheduler, err := NewScheduler(tasks, SchedulerOptions{Anchor: anchor, GlobalConcurrency: 1, QueueSize: 2, MaxStartsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.DispatchDue(anchor.Add(time.Minute))
	scheduler.DispatchDue(anchor.Add(2 * time.Minute))
	status := scheduler.Status()
	if status.Queued != 1 || scheduler.startReservations != 1 || status.BudgetSkipped < 2 {
		t.Fatalf("old queued reservation allowed a new minute burst: reservations=%d status=%+v", scheduler.startReservations, status)
	}
}

func TestSchedulerCancellationDoesNotPublishSyntheticFailure(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	started := make(chan struct{})
	var sinkCalls atomic.Int32
	run := func(ctx context.Context) ProbeResult {
		close(started)
		<-ctx.Done()
		return ProbeResult{SchemaVersion: ResultSchemaV1, Outcome: OutcomeFail}
	}
	scheduler, err := NewScheduler([]Task{schedulerTask("a", "a.example", 30*time.Second, 10*time.Second, run)}, SchedulerOptions{
		Anchor: anchor, GlobalConcurrency: 1, QueueSize: 1,
		Sink: func(context.Context, ProbeResult) error { sinkCalls.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(anchor.Add(time.Minute))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if sinkCalls.Load() != 0 {
		t.Fatalf("canceled run published %d results", sinkCalls.Load())
	}
	if scheduler.Status().Canceled != 1 {
		t.Fatalf("canceled run not accounted: %+v", scheduler.Status())
	}
}

func waitForSchedulerRunning(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !scheduler.Status().Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !scheduler.Status().Running {
		t.Fatal("scheduler did not enter running state")
	}
}

func TestSchedulerConcurrentStatusIsSafe(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	scheduler, err := NewScheduler([]Task{schedulerTask("a", "a.example", 30*time.Second, time.Second, func(context.Context) ProbeResult { return ProbeResult{} })}, SchedulerOptions{Anchor: anchor})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() { defer group.Done(); _ = scheduler.Status() }()
	}
	group.Wait()
}

func TestSchedulerDurablyRecordsStartBeforeNetworkAndBindsEvidence(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	now := anchor.Add(time.Minute)
	var recorded atomic.Bool
	var ran atomic.Bool
	captured := make(chan ProbeResult, 1)
	task := schedulerTask("durable", "durable.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		if !recorded.Load() {
			t.Error("task ran before its durable start was recorded")
		}
		ran.Store(true)
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, Now: func() time.Time { return now }, GlobalConcurrency: 1, QueueSize: 1,
		NewStartID: func() (string, error) { return "durable-start", nil },
		RecordStart: func(_ context.Context, startID, probeID string, startedAt time.Time) error {
			if startID != "durable-start" || probeID != "durable" || !startedAt.Equal(now) {
				t.Fatalf("unexpected durable start: %q %q %s", startID, probeID, startedAt)
			}
			recorded.Store(true)
			return nil
		},
		Sink: func(_ context.Context, result ProbeResult) error { captured <- result; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(now)
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Completed != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var persisted ProbeResult
	select {
	case persisted = <-captured:
	case <-time.After(time.Second):
		t.Fatal("durable result was not persisted")
	}
	if !ran.Load() || persisted.EvidenceRef != "durable-start" {
		t.Fatalf("durable execution was not bound to evidence: ran=%v result=%+v", ran.Load(), persisted)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerStartPersistenceFailurePreventsNetworkAndFreezes(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	now := anchor.Add(time.Minute)
	var ran atomic.Bool
	task := schedulerTask("blocked", "blocked.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		ran.Store(true)
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, Now: func() time.Time { return now }, GlobalConcurrency: 1, QueueSize: 1,
		NewStartID: func() (string, error) { return "blocked-start", nil },
		RecordStart: func(context.Context, string, string, time.Time) error {
			return errors.New("injected durable start failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(now)
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().StorageHealthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := scheduler.Status()
	if ran.Load() || status.StorageHealthy || status.StorageIssue != "start_persistence_failed" || status.Started != 0 {
		t.Fatalf("start persistence did not fail closed: ran=%v status=%+v", ran.Load(), status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerStaleDurableStartNeverReachesNetwork(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	current := anchor.Add(time.Minute)
	var clockMu sync.Mutex
	now := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return current
	}
	var ran atomic.Bool
	task := schedulerTask("stale", "stale.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		ran.Store(true)
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, Now: now, GlobalConcurrency: 1, QueueSize: 1,
		NewStartID: func() (string, error) { return "stale-start", nil },
		RecordStart: func(context.Context, string, string, time.Time) error {
			clockMu.Lock()
			current = current.Add(MaximumStartPersistenceDelay + time.Second)
			clockMu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.DispatchDue(now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().StorageHealthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := scheduler.Status()
	if ran.Load() || status.StorageHealthy || status.StorageIssue != "start_persistence_stale" || status.Started != 0 {
		t.Fatalf("stale durable start was not blocked: ran=%v status=%+v", ran.Load(), status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerClassifiesLedgerClockFailures(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	task := schedulerTask("clock", "clock.example", 30*time.Second, time.Second, func(context.Context) ProbeResult { return ProbeResult{} })
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, Now: func() time.Time { return anchor.Add(time.Minute) }, GlobalConcurrency: 1, QueueSize: 1,
		NewStartID:  func() (string, error) { return "clock-start", nil },
		RecordStart: func(context.Context, string, string, time.Time) error { return ErrStartLedgerClock },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(anchor.Add(time.Minute))
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().ClockHealthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := scheduler.Status()
	if status.ClockHealthy || status.ClockIssue != "clock_rollback" || status.StorageIssue != "start_persistence_failed" {
		t.Fatalf("ledger clock error was misclassified: %+v", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerRejectsClockRollbackBetweenDispatchAndDurableStart(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	current := anchor.Add(time.Minute)
	var recorded atomic.Bool
	var ran atomic.Bool
	task := schedulerTask("rollback-start", "rollback.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		ran.Store(true)
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, Now: func() time.Time { return current }, GlobalConcurrency: 1, QueueSize: 1,
		NewStartID: func() (string, error) { return "rollback-start-id", nil },
		RecordStart: func(context.Context, string, string, time.Time) error {
			recorded.Store(true)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.DispatchDue(current)
	current = anchor.Add(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Canceled != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := scheduler.Status()
	if recorded.Load() || ran.Load() || status.ClockHealthy || status.ClockIssue != "clock_rollback" || status.Started != 0 {
		t.Fatalf("pre-network rollback did not fail closed: recorded=%v ran=%v status=%+v", recorded.Load(), ran.Load(), status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerAppliesRetryAfterAndRestoresPersistedBackoff(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	now := anchor.Add(time.Minute)
	result := ProbeResult{Conclusion: ConclusionRateLimited, Outcome: OutcomeIndeterminate, Layers: LayerResults{Business: LayerResult{RetryAfterSeconds: 1800}}}
	task := schedulerTask("limited", "limited.example", 30*time.Second, time.Second, func(context.Context) ProbeResult { return result })
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{Anchor: anchor, Now: func() time.Time { return now }, GlobalConcurrency: 1, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(now)
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Completed != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	wantNotBefore := now.Add(30 * time.Minute)
	got, _ := scheduler.NextDue("limited")
	if got.Before(wantNotBefore) {
		t.Fatalf("Retry-After was not applied: got %s want >= %s", got, wantNotBefore)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	restored, err := NewScheduler([]Task{task}, SchedulerOptions{Anchor: anchor, InitialNotBefore: map[string]time.Time{"limited": wantNotBefore}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = restored.NextDue("limited")
	if !got.Equal(wantNotBefore) {
		t.Fatalf("persisted backoff was not restored: got %s want %s", got, wantNotBefore)
	}
}

func TestSchedulerIgnoresRetryAfterOnNonRateLimitedResult(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	now := anchor.Add(time.Minute)
	result := ProbeResult{Conclusion: ConclusionUnknown, Outcome: OutcomeIndeterminate, Layers: LayerResults{Business: LayerResult{RetryAfterSeconds: 1800}}}
	task := schedulerTask("ordinary", "ordinary.example", 30*time.Second, time.Second, func(context.Context) ProbeResult { return result })
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{Anchor: anchor, Now: func() time.Time { return now }, GlobalConcurrency: 1, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(now)
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Completed != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got, _ := scheduler.NextDue("ordinary")
	if !got.Before(now.Add(30 * time.Minute)) {
		t.Fatalf("non-rate-limited result applied forged backoff: %s", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRestoreSchedulerStatePreservesBackoffAndMinuteBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	catalog := testSpoolCatalog(t)
	target := catalog.Probes[0]
	result := validTestResult(now.Add(-20*time.Second), "restore-rate-limit")
	result.Conclusion = ConclusionRateLimited
	result.Outcome = OutcomeIndeterminate
	result.ErrorClass = "rate_limited"
	result.Layers.Business.State = LayerRateLimited
	result.Layers.Business.Reason = "rate_limited"
	result.Layers.Business.RetryAfterSeconds = 1800
	status := 429
	result.HTTPStatus = &status
	notBefore, starts, err := RestoreSchedulerState(catalog, []ProbeResult{result}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := result.CompletedAt.Add(30 * time.Minute)
	if !notBefore[target.ID].Equal(want) || len(starts) != 1 || !starts[0].Equal(result.AttemptedAt) {
		t.Fatalf("state was not restored: notBefore=%v starts=%v", notBefore, starts)
	}
	task := schedulerTask(target.ID, target.Host, 30*time.Second, time.Second, func(context.Context) ProbeResult { return ProbeResult{} })
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: now, InitialNotBefore: notBefore, InitialStartTimes: starts,
		GlobalConcurrency: 1, QueueSize: 1, MaxStartsPerMinute: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.DispatchDue(want)
	if status := scheduler.Status(); status.Queued != 1 {
		t.Fatalf("expired start budget did not clear at restored not-before: %+v", status)
	}
}

func TestRestoreSchedulerStateIgnoresSameProbeFromDifferentCatalog(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	result := validTestResult(now.Add(-20*time.Second), "foreign-catalog")
	result.Conclusion = ConclusionRateLimited
	result.Outcome = OutcomeIndeterminate
	result.ErrorClass = "rate_limited"
	result.Layers.Business.State = LayerRateLimited
	result.Layers.Business.Reason = "rate_limited"
	result.Layers.Business.RetryAfterSeconds = 1800
	status := 429
	result.HTTPStatus = &status

	catalog := validCatalog()
	catalog.Revision = "2026-10-18.2"
	digest, err := DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Digest = digest
	notBefore, starts, err := RestoreSchedulerState(catalog, []ProbeResult{result}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(notBefore) != 0 || len(starts) != 0 {
		t.Fatalf("foreign catalog state was restored: notBefore=%v starts=%v", notBefore, starts)
	}
}

func TestSchedulerDiscardsCompletionWhenClockRollsBackDuringRun(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	current := anchor.Add(time.Minute)
	var clockMu sync.Mutex
	now := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return current
	}
	var sinkCalls atomic.Int32
	task := schedulerTask("a", "a.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		clockMu.Lock()
		current = anchor.Add(-time.Second)
		clockMu.Unlock()
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, Now: now, GlobalConcurrency: 1, QueueSize: 1,
		Sink: func(context.Context, ProbeResult) error { sinkCalls.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(now())
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Canceled != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := scheduler.Status()
	if status.ClockHealthy || status.ClockIssue != "clock_rollback" || sinkCalls.Load() != 0 {
		t.Fatalf("runtime clock rollback was not fail-closed: status=%+v sink=%d", status, sinkCalls.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerDropsQueuedWorkAfterClockRollback(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	var runs atomic.Int32
	task := schedulerTask("a", "a.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		runs.Add(1)
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{Anchor: anchor, GlobalConcurrency: 1, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.DispatchDue(anchor.Add(time.Minute))
	scheduler.DispatchDue(anchor.Add(30 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().Queued != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 0 {
		t.Fatalf("queued task ran after clock rollback: %d", runs.Load())
	}
}

func TestSchedulerFreezesWhenResultCannotBePersisted(t *testing.T) {
	anchor := time.Unix(1_700_000_000, 0).UTC()
	var runs atomic.Int32
	task := schedulerTask("a", "a.example", 30*time.Second, time.Second, func(context.Context) ProbeResult {
		runs.Add(1)
		return ProbeResult{}
	})
	scheduler, err := NewScheduler([]Task{task}, SchedulerOptions{
		Anchor: anchor, GlobalConcurrency: 1, QueueSize: 1,
		Sink: func(context.Context, ProbeResult) error { return context.DeadlineExceeded },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitForSchedulerRunning(t, scheduler)
	scheduler.DispatchDue(anchor.Add(time.Minute))
	deadline := time.Now().Add(time.Second)
	for scheduler.Status().SinkFailures != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := scheduler.Status()
	if status.StorageHealthy || status.StorageIssue != "result_persistence_failed" || status.SinkFailures != 1 {
		t.Fatalf("scheduler did not fail closed on sink failure: %+v", status)
	}
	scheduler.DispatchDue(anchor.Add(10 * time.Minute))
	time.Sleep(10 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("frozen scheduler continued probing: runs=%d", runs.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func schedulerTask(id, host string, interval, timeout time.Duration, run func(context.Context) ProbeResult) Task {
	return Task{Target: Target{
		ID: id, PathID: "direct", Kind: ProbeHTTPS, Host: host, Port: 443,
		RequestPath: "/", Method: "GET", ExpectedStatus: []int{200},
		IntervalSeconds: int(interval / time.Second), TimeoutSeconds: int(timeout / time.Second),
		TTLSeconds: int(interval/time.Second) * 2, MaxBodyBytes: 1024,
	}, Run: run}
}
