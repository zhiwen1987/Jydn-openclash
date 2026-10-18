package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"chengwang/internal/probe"
)

type probeExecutor interface {
	ResolveAndRun(context.Context, probe.Catalog, string, probe.Resolver) probe.ProbeResult
}

type resultStore interface {
	Append(probe.ProbeResult) error
	Close() error
}

type durableLedger interface {
	RecordStart(string, string, time.Time) error
	Settle(string, probe.ProbeResult) error
	SettleRecovered(string, probe.ProbeResult) error
	Close() error
}

type application struct {
	scheduler *probe.Scheduler
	store     resultStore
	ledger    durableLedger
}

func newApplication(value config) (_ *application, err error) {
	catalog, err := loadCatalog(value.catalogPath)
	if err != nil {
		return nil, err
	}
	roots, err := loadCAPool(value.doTCAPath)
	if err != nil {
		return nil, err
	}
	resolver, err := probe.NewFixedDoTResolver(probe.FixedDoTResolverConfig{
		Upstream: value.doTUpstream, ServerName: value.doTServerName,
		RootCAs: roots, Timeout: value.resolverTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create fixed DoT resolver: %w", err)
	}
	runner, err := probe.NewRunner(value.runnerTimeout)
	if err != nil {
		return nil, fmt.Errorf("create probe runner: %w", err)
	}
	store, err := probe.OpenStore(value.spoolDirectory, catalog, probe.StoreLimits{
		MaxEntries: value.spoolMaxEntries, MaxBytes: value.spoolMaxBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("open result spool: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, store.Close())
		}
	}()
	ledger, err := probe.OpenStartLedger(value.ledgerDirectory, catalog, probe.StartLedgerOptions{
		MaxEntries: value.ledgerMaxEntries, MaxBytes: value.ledgerMaxBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("open durable start ledger: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, ledger.Close())
		}
	}()

	ledgerState, err := ledger.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("restore durable start state: %w", err)
	}
	if !ledgerState.Healthy || !ledgerState.Writable {
		return nil, fmt.Errorf("durable start ledger is unhealthy: %s", ledgerState.Issue)
	}
	anchor := time.Now()
	report, err := probe.ReadStore(value.spoolDirectory, probe.ReadOptions{
		Catalog: catalog, Limit: probe.MaximumReadResults, Now: anchor,
		MaxEntries: value.spoolMaxEntries, MaxBytes: value.spoolMaxBytes,
		IncludeExpired: true,
	})
	if err != nil {
		return nil, fmt.Errorf("read verified result spool: %w", err)
	}
	if !report.Healthy {
		return nil, fmt.Errorf("result spool is unhealthy: %s", report.Issue)
	}
	if err := reconcileInflightResults(ledger, ledgerState, report.Results); err != nil {
		return nil, fmt.Errorf("reconcile durable starts: %w", err)
	}
	ledgerState, err = ledger.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("refresh durable start state: %w", err)
	}
	anchor = time.Now()
	spoolNotBefore, _, err := probe.RestoreSchedulerState(catalog, report.Results, anchor)
	if err != nil {
		return nil, fmt.Errorf("restore verified spool scheduler state: %w", err)
	}
	initialNotBefore := mergeNotBefore(spoolNotBefore, ledgerState.NotBefore)
	scheduler, err := buildScheduler(catalog, runner, resolver, store, ledger, schedulerInputs{
		anchor: anchor, initialNotBefore: initialNotBefore,
		initialStartTimes: ledgerState.RecentStartTimes,
		concurrency:       value.concurrency, queueSize: value.queueSize,
		startsPerMinute: value.startsPerMinute,
	})
	if err != nil {
		return nil, err
	}
	return &application{scheduler: scheduler, store: store, ledger: ledger}, nil
}

func reconcileInflightResults(ledger durableLedger, state probe.StartLedgerSnapshot, results []probe.ProbeResult) error {
	if len(state.InFlight) == 0 {
		return nil
	}
	byStart := make(map[string][]probe.ProbeResult)
	for _, result := range results {
		if result.EvidenceRef != "" {
			byStart[result.EvidenceRef] = append(byStart[result.EvidenceRef], result)
		}
	}
	for _, entry := range state.InFlight {
		matches := byStart[entry.StartID]
		if len(matches) == 0 {
			continue
		}
		if len(matches) != 1 || matches[0].ProbeID != entry.ProbeID {
			return fmt.Errorf("start %q has ambiguous persisted result evidence", entry.StartID)
		}
		if err := ledger.SettleRecovered(entry.StartID, matches[0]); err != nil {
			return fmt.Errorf("settle recovered start %q: %w", entry.StartID, err)
		}
	}
	return nil
}

type schedulerInputs struct {
	anchor            time.Time
	initialNotBefore  map[string]time.Time
	initialStartTimes []time.Time
	concurrency       int
	queueSize         int
	startsPerMinute   int
	newStartID        func() (string, error)
	now               func() time.Time
}

func buildScheduler(catalog probe.Catalog, executor probeExecutor, resolver probe.Resolver, store resultStore, ledger durableLedger, inputs schedulerInputs) (*probe.Scheduler, error) {
	if executor == nil || resolver == nil || store == nil || ledger == nil {
		return nil, errors.New("probe runtime dependency is nil")
	}
	tasks := make([]probe.Task, 0, len(catalog.Probes))
	for _, catalogTarget := range catalog.Probes {
		target := catalogTarget
		tasks = append(tasks, probe.Task{Target: target, Run: func(ctx context.Context) probe.ProbeResult {
			return executor.ResolveAndRun(ctx, catalog, target.ID, resolver)
		}})
	}
	options := probe.SchedulerOptions{
		GlobalConcurrency: inputs.concurrency, QueueSize: inputs.queueSize,
		MaxStartsPerMinute: inputs.startsPerMinute, Anchor: inputs.anchor,
		InitialNotBefore: inputs.initialNotBefore, InitialStartTimes: inputs.initialStartTimes,
		Now: inputs.now, NewStartID: inputs.newStartID,
		RecordStart: func(_ context.Context, startID, probeID string, startedAt time.Time) error {
			return ledger.RecordStart(startID, probeID, startedAt)
		},
		Sink: func(_ context.Context, result probe.ProbeResult) error {
			if result.EvidenceRef == "" {
				return errors.New("probe result has no durable start reference")
			}
			// The immutable evidence segment must exist before the corresponding
			// start can be settled. A spool failure leaves the durable start in
			// flight and freezes the scheduler instead of losing the attempt.
			if err := store.Append(result); err != nil {
				return fmt.Errorf("append result spool: %w", err)
			}
			if err := ledger.Settle(result.EvidenceRef, result); err != nil {
				return fmt.Errorf("settle durable start: %w", err)
			}
			return nil
		},
	}
	return probe.NewScheduler(tasks, options)
}

func mergeNotBefore(first, second map[string]time.Time) map[string]time.Time {
	merged := make(map[string]time.Time, len(first)+len(second))
	for id, deadline := range first {
		merged[id] = deadline
	}
	for id, deadline := range second {
		if deadline.After(merged[id]) {
			merged[id] = deadline
		}
	}
	return merged
}

func (app *application) run(ctx context.Context) (err error) {
	if app == nil || app.scheduler == nil || app.store == nil || app.ledger == nil {
		return errors.New("probe application is incomplete")
	}
	defer func() {
		err = errors.Join(err, app.ledger.Close(), app.store.Close())
	}()
	return app.scheduler.Run(ctx)
}
