package probeview

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"chengwang/internal/probe"
)

var (
	ErrInvalidConfig = errors.New("invalid probe view configuration")
	ErrAlreadyRun    = errors.New("probe view worker already started")
)

type Config struct {
	Catalog      probe.Catalog
	SpoolDir     string
	PollInterval time.Duration
	CacheMaxAge  time.Duration
}

type readFunc func(context.Context, string, probe.SecureReadOptions) (probe.SecureReadReport, error)

// Provider owns exactly one synchronous worker. Only that worker accesses the
// spool. The unexported clock/reader seams exist for same-package tests, not as
// configurable trust bypasses. Published snapshots are never mutated.
type Provider struct {
	config Config
	now    func() time.Time
	read   readFunc
	uid    uint32
	gid    uint32

	mu           sync.Mutex
	started      bool
	running      bool
	highWall     int64
	haveWall     bool
	clockInvalid bool
	clockVersion uint64
	snapshot     *Details
}

// New performs only CPU/string validation. Catalog must have been obtained by
// the runtime's secure catalog reader. New never stats, opens, creates or
// repairs either the catalog or spool.
func New(config Config) (*Provider, error) {
	if config.PollInterval < time.Second || config.PollInterval > 60*time.Second || config.CacheMaxAge < config.PollInterval || config.CacheMaxAge > 300*time.Second {
		return nil, ErrInvalidConfig
	}
	if config.SpoolDir == "" || !filepath.IsAbs(config.SpoolDir) || filepath.Clean(config.SpoolDir) != config.SpoolDir {
		return nil, ErrInvalidConfig
	}
	catalog := cloneCatalog(config.Catalog)
	digest, err := probe.DigestCatalog(catalog)
	if err != nil || catalog.Digest == "" || catalog.Digest != digest {
		return nil, ErrInvalidConfig
	}
	config.Catalog = catalog
	p := &Provider{config: config, now: time.Now, read: probe.ReadStoreSecure, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	p.snapshot = p.empty("pending", "not_started")
	return p, nil
}

func cloneCatalog(c probe.Catalog) probe.Catalog {
	c.Paths = append([]probe.Path(nil), c.Paths...)
	c.Probes = append([]probe.Target(nil), c.Probes...)
	for i := range c.Probes {
		c.Probes[i].AllowedCNAMEs = append([]string(nil), c.Probes[i].AllowedCNAMEs...)
		c.Probes[i].ExpectedStatus = append([]int(nil), c.Probes[i].ExpectedStatus...)
	}
	return c
}

// Run blocks until its worker has actually finished; it never abandons a read
// goroutine on a timeout. Read cancellation is cooperative, bounded by the
// strict local-filesystem reader's checkpoints. Arbitrary kernel D-state I/O
// cannot be promised a hard wall-clock deadline; callers must not report a
// successful shutdown or close worker-owned resources without joining Run.
func (p *Provider) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return ErrAlreadyRun
	}
	p.started, p.running = true, true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		p.refresh(ctx)
		if ctx.Err() != nil {
			return nil
		}
		timer := time.NewTimer(p.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// sampleWallLocked serializes sampling itself, avoiding a false rollback when
// two callers take wall times in one order and acquire the mutex in another.
func (p *Provider) sampleWallLocked() time.Time {
	now := p.now().UTC()
	wall := now.UnixNano()
	if now.IsZero() || (p.haveWall && wall < p.highWall) {
		p.clockInvalid = true
		p.clockVersion++
	} else {
		p.highWall, p.haveWall = wall, true
	}
	return now
}

func (p *Provider) refresh(ctx context.Context) {
	p.mu.Lock()
	now := p.sampleWallLocked()
	version := p.clockVersion
	canRecover := !now.IsZero() && now.UnixNano() >= p.highWall
	p.mu.Unlock()
	readTimeout := p.config.PollInterval
	if readTimeout > 5*time.Second {
		readTimeout = 5 * time.Second
	}
	readCtx, cancel := context.WithTimeout(ctx, readTimeout)
	report, err := p.read(readCtx, p.config.SpoolDir, probe.SecureReadOptions{
		ReadOptions: probe.ReadOptions{Catalog: p.config.Catalog, Limit: probe.MaximumReadResults, Now: now, IncludeExpired: false},
		OwnerUID:    p.uid, OwnerGID: p.gid,
	})
	cancel()
	if ctx.Err() != nil {
		return
	}
	var next *Details
	if err != nil {
		next = p.empty("unknown", readReason(err))
		next.Status.CachedAt = timePtr(now)
	} else if !p.validReport(report) {
		next = p.empty("unknown", "read_unavailable")
		next.Status.CachedAt = timePtr(now)
	} else {
		next = p.build(report, now)
	}
	p.mu.Lock()
	// A rollback observed during this read invalidates it. Catching up the
	// wall clock alone is insufficient: a new successful secure read is needed.
	if err == nil && next.Status.StorageHealthy && version == p.clockVersion && canRecover {
		p.clockInvalid = false
	}
	p.snapshot = next
	p.mu.Unlock()
}

func validCounts(r probe.SecureReadReport) bool {
	return r.ValidTotal >= 0 && r.ExpiredTotal >= 0 && r.ExpiredTotal <= r.ValidTotal &&
		r.EligibleTotal == r.ValidTotal-r.ExpiredTotal && r.Returned == len(r.Results) &&
		r.Returned >= 0 && r.Returned <= probe.MaximumReadResults && r.Returned <= r.EligibleTotal &&
		r.Rejected >= 0 && r.Truncated == (r.EligibleTotal > r.Returned)
}

func (p *Provider) validReport(report probe.SecureReadReport) bool {
	if !validCounts(report) {
		return false
	}
	paths := make(map[string]string, len(p.config.Catalog.Probes))
	for _, target := range p.config.Catalog.Probes {
		paths[target.ID] = target.PathID
	}
	for _, result := range report.Results {
		path, ok := paths[result.ProbeID]
		if !ok || result.PathID != path || result.AgentID != p.config.Catalog.Agent.ID || result.CatalogDigest != p.config.Catalog.Digest || result.Independence != probe.IndependenceP1 || !result.AdvisoryOnly {
			return false
		}
	}
	return true
}

func readReason(err error) string {
	switch {
	case errors.Is(err, probe.ErrSecureUnsupported):
		return "platform_unsupported"
	case errors.Is(err, probe.ErrSecureLimit):
		return "limit_rejected"
	case errors.Is(err, probe.ErrSecureUnsafe), errors.Is(err, probe.ErrSecureChanged), errors.Is(err, probe.ErrSecureInvalid):
		return "storage_rejected"
	default:
		return "read_unavailable"
	}
}

func (p *Provider) empty(state, reason string) *Details {
	status := Status{Schema: "chengwang.probe-view-status/v1", Configured: true, AdvisoryOnly: true, State: state, Reason: reason, ClockHealthy: true}
	status.Coverage = Coverage{DeclaredTargets: len(p.config.Catalog.Probes), TargetsMissing: len(p.config.Catalog.Probes), Partial: true}
	d := &Details{Schema: "chengwang.probe-view-details/v1", Status: status, CatalogDigest: p.config.Catalog.Digest, AgentID: p.config.Catalog.Agent.ID, Independence: probe.IndependenceP1, AdvisoryOnly: true, Targets: make([]Target, 0, len(p.config.Catalog.Probes)), Samples: []Sample{}}
	for _, target := range p.config.Catalog.Probes {
		d.Targets = append(d.Targets, Target{ProbeID: target.ID, PathID: target.PathID, State: probe.ConclusionUnknown, Reason: reason})
	}
	sort.Slice(d.Targets, func(i, j int) bool {
		if d.Targets[i].ProbeID == d.Targets[j].ProbeID {
			return d.Targets[i].PathID < d.Targets[j].PathID
		}
		return d.Targets[i].ProbeID < d.Targets[j].ProbeID
	})
	return d
}

func (p *Provider) build(report probe.SecureReadReport, now time.Time) *Details {
	d := p.empty("ready", "ok")
	d.Status.StorageHealthy = report.Healthy && report.Rejected == 0
	d.Status.CachedAt = timePtr(now)
	expires := now.Add(p.config.CacheMaxAge)
	counts := make(map[string]int, len(d.Targets))
	timeReason := ""
	for _, result := range report.Results {
		counts[result.ProbeID+"\x00"+result.PathID]++
		if result.ExpiresAt.Before(expires) {
			expires = result.ExpiresAt
		}
		if result.CompletedAt.After(now) || result.AttemptedAt.After(now) {
			timeReason = "no_current_evidence"
		}
		// Layer TTL may precede result TTL by the duration of the request.
		// Never expose an expired green layer while only the result is live.
		for _, layer := range []probe.LayerResult{result.Layers.DNS, result.Layers.Connect, result.Layers.TLS, result.Layers.HTTP, result.Layers.Business} {
			if layer.ExpiresAt.Before(expires) {
				expires = layer.ExpiresAt
			}
		}
		if !expires.After(now) {
			timeReason = "evidence_expired"
		}
		d.Samples = append(d.Samples, projectSample(result))
	}
	d.Status.ExpiresAt = timePtr(expires)
	aggregates := probe.AggregateByProbe(report.Results, now)
	byTarget := make(map[string]probe.ProbeAggregate, len(aggregates))
	for _, a := range aggregates {
		byTarget[a.ProbeID+"\x00"+a.PathID] = a
	}
	covered := 0
	for i := range d.Targets {
		t := &d.Targets[i]
		t.Reason = "no_current_evidence"
		key := t.ProbeID + "\x00" + t.PathID
		t.RetainedSamples = counts[key]
		if a, ok := byTarget[key]; ok {
			covered++
			t.State, t.Reason = a.State, safeReason(a.Reason)
			t.ObservedAt, t.ExpiresAt = cloneTime(a.ObservedAt), cloneTime(a.ExpiresAt)
			t.ConsecutiveSuccess, t.ConsecutiveFailure = a.ConsecutiveSuccess, a.ConsecutiveFailure
		}
	}
	partial := covered < len(d.Targets) || report.Truncated || report.Rejected > 0
	d.Status.Coverage = Coverage{DeclaredTargets: len(d.Targets), TargetsWithSamples: covered, TargetsMissing: len(d.Targets) - covered, RetainedSamples: len(report.Results), ValidTotal: report.ValidTotal, ExpiredTotal: report.ExpiredTotal, EligibleTotal: report.EligibleTotal, RejectedTotal: report.Rejected, Truncated: report.Truncated, Partial: partial}
	d.Rejections = rejectionCounts(report.Issues)
	if !d.Status.StorageHealthy {
		d.Status.State, d.Status.Reason = "unknown", "content_rejected"
	} else if timeReason != "" {
		d.Status.State, d.Status.Reason = "unknown", timeReason
	} else if partial {
		d.Status.State, d.Status.Reason = "partial", "partial_coverage"
		if len(report.Results) == 0 {
			d.Status.Reason = "no_current_evidence"
			if report.ExpiredTotal > 0 {
				d.Status.Reason = "evidence_expired"
			}
		}
	}
	return d
}

// statusLocked is fixed work regardless of catalog size and never reads disk.
func (p *Provider) statusLocked(now time.Time) Status {
	s := p.snapshot.Status
	s.CachedAt, s.ExpiresAt = cloneTime(s.CachedAt), cloneTime(s.ExpiresAt)
	s.Running = p.running
	s.ClockHealthy = !p.clockInvalid
	switch {
	case p.clockInvalid:
		s.State, s.Reason = "unknown", "clock_rollback"
	case p.started && !p.running:
		s.State, s.Reason = "unknown", "stopped"
	case s.ExpiresAt != nil && !now.Before(*s.ExpiresAt):
		s.State, s.Reason = "unknown", "cache_expired"
		if s.CachedAt != nil && s.ExpiresAt.Before(s.CachedAt.Add(p.config.CacheMaxAge)) {
			s.Reason = "evidence_expired"
		}
	}
	return s
}

func (p *Provider) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.statusLocked(p.sampleWallLocked())
}

func (p *Provider) Details() Details {
	p.mu.Lock()
	status := p.statusLocked(p.sampleWallLocked())
	base := p.snapshot
	p.mu.Unlock()
	d := *base
	d.Status = status
	d.Targets = append([]Target{}, base.Targets...)
	d.Samples = append([]Sample{}, base.Samples...)
	for i := range d.Targets {
		d.Targets[i].ObservedAt = cloneTime(d.Targets[i].ObservedAt)
		d.Targets[i].ExpiresAt = cloneTime(d.Targets[i].ExpiresAt)
	}
	for i := range d.Samples {
		if d.Samples[i].HTTPStatus != nil {
			httpStatus := *d.Samples[i].HTTPStatus
			d.Samples[i].HTTPStatus = &httpStatus
		}
	}
	if status.State == "unknown" || status.State == "pending" {
		// The retained counts describe historical cache coverage; samples are
		// intentionally hidden rather than exposing expired/future green layers.
		d.Samples = []Sample{}
		for i := range d.Targets {
			d.Targets[i].State, d.Targets[i].Reason = probe.ConclusionUnknown, status.Reason
			d.Targets[i].ConsecutiveSuccess, d.Targets[i].ConsecutiveFailure = 0, 0
		}
	}
	return d
}

func timePtr(value time.Time) *time.Time { return &value }

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	return timePtr(*value)
}
