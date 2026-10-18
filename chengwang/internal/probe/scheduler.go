package probe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	MinimumProbeInterval     = 30 * time.Second
	MaximumProbeTimeout      = 10 * time.Second
	DefaultProbeConcurrency  = 2
	DefaultProbeQueueSize    = 256
	DefaultProbeStartsMinute = 20
	// A durable start write that takes longer than this is treated as stale and
	// the network task is not allowed to begin. The ledger retains a matching
	// padding window so restart recovery cannot age the budget out early.
	MaximumStartPersistenceDelay = 10 * time.Second
)

// Task is deliberately a closed-over, pre-validated catalog operation. The
// scheduler never accepts a URL, host, header, or request body from callers.
type Task struct {
	Target Target
	Run    func(context.Context) ProbeResult
}

type ResultSink func(context.Context, ProbeResult) error

// DurableStartRecorder commits a start before Task.Run can perform network
// I/O. startID is copied into ProbeResult.EvidenceRef for settlement by Sink.
type DurableStartRecorder func(context.Context, string, string, time.Time) error

type SchedulerOptions struct {
	GlobalConcurrency  int
	QueueSize          int
	MaxStartsPerMinute int
	Anchor             time.Time
	InitialNotBefore   map[string]time.Time
	InitialStartTimes  []time.Time
	Now                func() time.Time
	Sink               ResultSink
	RecordStart        DurableStartRecorder
	NewStartID         func() (string, error)
}

type SchedulerStatus struct {
	Running        bool      `json:"running"`
	ClockHealthy   bool      `json:"clockHealthy"`
	ClockIssue     string    `json:"clockIssue,omitempty"`
	StorageHealthy bool      `json:"storageHealthy"`
	StorageIssue   string    `json:"storageIssue,omitempty"`
	LastClock      time.Time `json:"lastClock,omitempty"`
	Queued         int       `json:"queued"`
	Active         int       `json:"active"`
	Started        uint64    `json:"started"`
	Completed      uint64    `json:"completed"`
	Canceled       uint64    `json:"canceled"`
	BudgetSkipped  uint64    `json:"budgetSkipped"`
	QueueSkipped   uint64    `json:"queueSkipped"`
	SinkFailures   uint64    `json:"sinkFailures"`
}

type scheduledTask struct {
	task    Task
	nextDue time.Time
	cycle   uint64
	queued  bool
	running bool
}

// Scheduler provides only bounded advisory execution. It neither mutates
// routing nor fabricates a failed ProbeResult when shutdown cancels work.
type Scheduler struct {
	mu          sync.Mutex
	startMu     sync.Mutex
	tasks       map[string]*scheduledTask
	orderedIDs  []string
	hostBusy    map[string]bool
	queue       chan string
	concurrency int
	maxStarts   int
	now         func() time.Time
	sink        ResultSink
	recordStart DurableStartRecorder
	newStartID  func() (string, error)
	startTimes  []time.Time
	// startReservations counts queued/running tasks that have not yet crossed
	// the pre-network durable-start boundary. It prevents a deep queue from
	// bypassing the starts-per-minute budget when an old minute rolls over.
	startReservations int
	lastClock         time.Time
	frozen            bool
	startedRun        bool
	status            SchedulerStatus
	wakeEvery         time.Duration
}

func NewScheduler(tasks []Task, options SchedulerOptions) (*Scheduler, error) {
	if len(tasks) == 0 {
		return nil, errors.New("at least one probe task is required")
	}
	if len(tasks) > MaxCatalogTargets {
		return nil, fmt.Errorf("probe task count exceeds %d", MaxCatalogTargets)
	}
	if options.GlobalConcurrency == 0 {
		options.GlobalConcurrency = DefaultProbeConcurrency
	}
	if options.QueueSize == 0 {
		options.QueueSize = DefaultProbeQueueSize
	}
	if options.MaxStartsPerMinute == 0 {
		options.MaxStartsPerMinute = DefaultProbeStartsMinute
	}
	if options.GlobalConcurrency < 1 || options.GlobalConcurrency > 16 {
		return nil, errors.New("probe concurrency must be between 1 and 16")
	}
	if options.QueueSize < options.GlobalConcurrency || options.QueueSize > DefaultProbeQueueSize {
		return nil, fmt.Errorf("probe queue size must be between concurrency and %d", DefaultProbeQueueSize)
	}
	if options.MaxStartsPerMinute < 1 || options.MaxStartsPerMinute > DefaultProbeStartsMinute {
		return nil, fmt.Errorf("probe start budget must be between 1 and %d per minute", DefaultProbeStartsMinute)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RecordStart != nil && options.NewStartID == nil {
		options.NewStartID = randomRunID
	}
	if options.RecordStart == nil && options.NewStartID != nil {
		return nil, errors.New("start ID generator requires a durable start recorder")
	}
	anchor := options.Anchor
	if anchor.IsZero() {
		anchor = options.Now()
	}
	s := &Scheduler{
		tasks: make(map[string]*scheduledTask, len(tasks)), hostBusy: make(map[string]bool), queue: make(chan string, options.QueueSize),
		concurrency: options.GlobalConcurrency, maxStarts: options.MaxStartsPerMinute,
		now: options.Now, sink: options.Sink, recordStart: options.RecordStart, newStartID: options.NewStartID,
		lastClock: anchor, wakeEvery: time.Second,
		status: SchedulerStatus{ClockHealthy: true, StorageHealthy: true, LastClock: anchor},
	}
	for _, startedAt := range options.InitialStartTimes {
		if startedAt.After(anchor) {
			return nil, errors.New("initial probe start time is in the future")
		}
		if startedAt.After(anchor.Add(-time.Minute)) {
			s.startTimes = append(s.startTimes, startedAt)
		}
	}
	if len(s.startTimes) > s.maxStarts {
		return nil, errors.New("initial probe start times exceed the configured minute budget")
	}
	sort.Slice(s.startTimes, func(i, j int) bool { return s.startTimes[i].Before(s.startTimes[j]) })
	for _, task := range tasks {
		if err := ValidateTarget(task.Target); err != nil {
			return nil, fmt.Errorf("invalid scheduled target: %w", err)
		}
		if task.Run == nil {
			return nil, fmt.Errorf("probe %q runner is required", task.Target.ID)
		}
		if _, exists := s.tasks[task.Target.ID]; exists {
			return nil, fmt.Errorf("duplicate probe task %q", task.Target.ID)
		}
		interval := time.Duration(task.Target.IntervalSeconds) * time.Second
		nextDue := anchor.Add(deterministicInterval(task.Target.ID, 0, interval))
		if notBefore := options.InitialNotBefore[task.Target.ID]; notBefore.After(nextDue) {
			nextDue = notBefore
		}
		s.tasks[task.Target.ID] = &scheduledTask{task: task, nextDue: nextDue}
		s.orderedIDs = append(s.orderedIDs, task.Target.ID)
	}
	sort.Strings(s.orderedIDs)
	return s, nil
}

// RestoreSchedulerState reconstructs persisted rate-limit state from verified
// spool results. The returned values can be passed to NewScheduler; no result
// is made fresher and no network request is performed.
func RestoreSchedulerState(catalog Catalog, results []ProbeResult, now time.Time) (map[string]time.Time, []time.Time, error) {
	notBefore := make(map[string]time.Time)
	starts := make([]time.Time, 0)
	binding, err := bindCatalog(catalog)
	if err != nil {
		return notBefore, starts, fmt.Errorf("bind scheduler catalog: %w", err)
	}
	if now.IsZero() {
		return notBefore, starts, errors.New("scheduler restore time is required")
	}
	for _, result := range results {
		if validateSpoolResult(result, binding, now, defaultFutureSkew, false, false) != "" || result.CompletedAt.After(now) {
			continue
		}
		if result.AttemptedAt.After(now.Add(-time.Minute)) {
			starts = append(starts, result.AttemptedAt)
		}
		if retrySeconds := result.Layers.Business.RetryAfterSeconds; result.Conclusion == ConclusionRateLimited && result.Outcome == OutcomeIndeterminate && retrySeconds > 0 && retrySeconds <= int64(maxRetryAfter/time.Second) {
			candidate := result.CompletedAt.Add(time.Duration(retrySeconds) * time.Second)
			if candidate.After(now) && candidate.After(notBefore[result.ProbeID]) {
				notBefore[result.ProbeID] = candidate
			}
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].Before(starts[j]) })
	return notBefore, starts, nil
}

// Run owns the worker lifetime and blocks until ctx is canceled. A Scheduler
// is single-use so that stale queued jobs cannot leak into a later lifecycle.
func (s *Scheduler) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.startedRun {
		s.mu.Unlock()
		return errors.New("probe scheduler is single-use")
	}
	s.startedRun = true
	s.status.Running = true
	s.mu.Unlock()

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	for i := 0; i < s.concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.worker(workerCtx)
		}()
	}
	ticker := time.NewTicker(s.wakeEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			workers.Wait()
			s.mu.Lock()
			s.status.Running = false
			s.status.Queued = len(s.queue)
			s.mu.Unlock()
			return nil
		case <-ticker.C:
			s.dispatchCurrent()
		}
	}
}

func (s *Scheduler) dispatchCurrent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatchDueLocked(s.now())
}

// DispatchDue is exported to permit deterministic local acceptance tests. It
// never bypasses overlap, queue, clock, or starts-per-minute budgets.
func (s *Scheduler) DispatchDue(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatchDueLocked(now)
}

func (s *Scheduler) dispatchDueLocked(now time.Time) {
	if s.frozen {
		return
	}
	if now.Before(s.lastClock) {
		s.frozen = true
		s.status.ClockHealthy = false
		s.status.ClockIssue = "clock_rollback"
		return
	}
	s.lastClock = now
	s.status.LastClock = now
	s.pruneStartTimesLocked(now)
	for _, id := range s.orderedIDs {
		state := s.tasks[id]
		if now.Before(state.nextDue) || state.queued || state.running {
			continue
		}
		if s.hostBusy[state.task.Target.Host] {
			// Host concurrency is intentionally one. The skipped occurrence is
			// kept due so it can run after the host is released instead of being
			// starved by a lexically earlier probe for the same host.
			s.status.QueueSkipped++
			continue
		}
		state.cycle++
		interval := time.Duration(state.task.Target.IntervalSeconds) * time.Second
		state.nextDue = now.Add(deterministicInterval(id, state.cycle, interval))
		if len(s.startTimes)+s.startReservations >= s.maxStarts {
			s.status.BudgetSkipped++
			continue
		}
		select {
		case s.queue <- id:
			state.queued = true
			s.hostBusy[state.task.Target.Host] = true
			s.startReservations++
			s.status.Queued = len(s.queue)
		default:
			s.status.QueueSkipped++
		}
	}
}

func (s *Scheduler) worker(root context.Context) {
	for {
		select {
		case <-root.Done():
			return
		case id := <-s.queue:
			s.mu.Lock()
			state := s.tasks[id]
			if state == nil {
				s.mu.Unlock()
				continue
			}
			if root.Err() != nil || s.frozen || state.running {
				state.queued = false
				s.releaseStartReservationLocked()
				delete(s.hostBusy, state.task.Target.Host)
				s.status.Queued = len(s.queue)
				s.status.Canceled++
				s.mu.Unlock()
				continue
			}
			state.queued = false
			state.running = true
			s.status.Queued = len(s.queue)
			s.status.Active++
			task := state.task
			s.mu.Unlock()

			// Serialize the pre-network start boundary. The clock sample is
			// taken while holding s.mu so a concurrent completion cannot make a
			// legitimate sample look like a rollback merely through lock order.
			s.startMu.Lock()
			s.mu.Lock()
			startedAt := s.now()
			if startedAt.Before(s.lastClock) {
				s.frozen = true
				s.status.ClockHealthy = false
				s.status.ClockIssue = "clock_rollback"
				state.running = false
				s.releaseStartReservationLocked()
				delete(s.hostBusy, state.task.Target.Host)
				s.status.Active--
				s.status.Canceled++
				s.mu.Unlock()
				s.startMu.Unlock()
				continue
			}
			s.lastClock = startedAt
			s.status.LastClock = startedAt
			s.mu.Unlock()

			startID := ""
			if s.recordStart != nil {
				generated, err := s.newStartID()
				if err != nil || !spoolIdentityPattern.MatchString(generated) {
					s.startMu.Unlock()
					s.failStart(state, "start_id_unavailable")
					continue
				}
				if err := s.recordStart(root, generated, task.Target.ID, startedAt); err != nil {
					s.startMu.Unlock()
					if errors.Is(err, ErrStartLedgerClock) {
						s.failStartClock(state, "clock_rollback")
					} else {
						s.failStart(state, "start_persistence_failed")
					}
					continue
				}
				startID = generated
			}
			s.mu.Lock()
			networkAt := s.now()
			if networkAt.Before(s.lastClock) {
				s.frozen = true
				s.status.ClockHealthy = false
				s.status.ClockIssue = "clock_rollback"
			}
			if networkAt.Sub(startedAt) > MaximumStartPersistenceDelay {
				s.frozen = true
				s.status.StorageHealthy = false
				s.status.StorageIssue = "start_persistence_stale"
			}
			if root.Err() != nil || s.frozen {
				state.running = false
				s.releaseStartReservationLocked()
				delete(s.hostBusy, state.task.Target.Host)
				s.status.Active--
				s.status.Canceled++
				s.mu.Unlock()
				s.startMu.Unlock()
				continue
			}
			s.pruneStartTimesLocked(networkAt)
			s.releaseStartReservationLocked()
			if len(s.startTimes) >= s.maxStarts {
				state.running = false
				delete(s.hostBusy, state.task.Target.Host)
				s.status.Active--
				s.status.Canceled++
				s.status.BudgetSkipped++
				s.mu.Unlock()
				s.startMu.Unlock()
				continue
			}
			s.startTimes = append(s.startTimes, networkAt)
			s.lastClock = networkAt
			s.status.LastClock = networkAt
			s.status.Started++
			s.mu.Unlock()
			s.startMu.Unlock()

			runCtx, cancel := context.WithTimeout(root, time.Duration(task.Target.TimeoutSeconds)*time.Second)
			result := task.Run(runCtx)
			cancel()
			if startID != "" {
				result.EvidenceRef = startID
			}

			s.mu.Lock()
			state.running = false
			delete(s.hostBusy, state.task.Target.Host)
			s.status.Active--
			completionNow := s.now()
			if completionNow.Before(s.lastClock) {
				s.frozen = true
				s.status.ClockHealthy = false
				s.status.ClockIssue = "clock_rollback"
			}
			if root.Err() != nil || s.frozen {
				s.status.Canceled++
				s.mu.Unlock()
				continue
			}
			s.lastClock = completionNow
			s.status.LastClock = completionNow
			s.status.Completed++
			if retrySeconds := result.Layers.Business.RetryAfterSeconds; result.Conclusion == ConclusionRateLimited && result.Outcome == OutcomeIndeterminate && retrySeconds > 0 && retrySeconds <= int64(maxRetryAfter/time.Second) {
				notBefore := completionNow.Add(time.Duration(retrySeconds) * time.Second)
				if notBefore.After(state.nextDue) {
					state.nextDue = notBefore
				}
			}
			s.mu.Unlock()

			if s.sink != nil {
				if err := s.sink(root, result); err != nil {
					s.mu.Lock()
					s.status.SinkFailures++
					s.status.StorageHealthy = false
					s.status.StorageIssue = "result_persistence_failed"
					if errors.Is(err, ErrStartLedgerClock) {
						s.status.ClockHealthy = false
						s.status.ClockIssue = "clock_rollback"
					}
					s.frozen = true
					s.mu.Unlock()
				}
			}
		}
	}
}

func (s *Scheduler) pruneStartTimesLocked(now time.Time) {
	cutoff := now.Add(-time.Minute)
	first := 0
	for first < len(s.startTimes) && s.startTimes[first].Before(cutoff) {
		first++
	}
	if first > 0 {
		s.startTimes = append([]time.Time(nil), s.startTimes[first:]...)
	}
}

func (s *Scheduler) releaseStartReservationLocked() {
	if s.startReservations > 0 {
		s.startReservations--
	}
}

func (s *Scheduler) failStart(state *scheduledTask, issue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state.running = false
	s.releaseStartReservationLocked()
	delete(s.hostBusy, state.task.Target.Host)
	s.status.Active--
	s.status.Canceled++
	s.status.StorageHealthy = false
	s.status.StorageIssue = issue
	s.frozen = true
}

func (s *Scheduler) failStartClock(state *scheduledTask, issue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state.running = false
	s.releaseStartReservationLocked()
	delete(s.hostBusy, state.task.Target.Host)
	s.status.Active--
	s.status.Canceled++
	s.status.ClockHealthy = false
	s.status.ClockIssue = issue
	s.status.StorageHealthy = false
	s.status.StorageIssue = "start_persistence_failed"
	s.frozen = true
}

func (s *Scheduler) Status() SchedulerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.status
	status.Queued = len(s.queue)
	return status
}

func (s *Scheduler) NextDue(probeID string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.tasks[probeID]
	if !ok {
		return time.Time{}, false
	}
	return state.nextDue, true
}

func deterministicInterval(probeID string, cycle uint64, interval time.Duration) time.Duration {
	input := make([]byte, len(probeID)+8)
	copy(input, probeID)
	binary.BigEndian.PutUint64(input[len(probeID):], cycle)
	digest := sha256.Sum256(input)
	// Stable -20%..+20% jitter, clamped so the effective interval never
	// violates the absolute 30-second floor.
	span := int64(interval / 5)
	if span == 0 {
		return interval
	}
	offset := int64(binary.BigEndian.Uint64(digest[:8])%uint64(2*span+1)) - span
	result := interval + time.Duration(offset)
	if result < MinimumProbeInterval {
		return MinimumProbeInterval
	}
	return result
}
