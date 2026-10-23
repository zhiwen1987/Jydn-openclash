package probeview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/internal/probe"
)

var viewTestTime = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func viewCatalog(t *testing.T, count int) probe.Catalog {
	t.Helper()
	c := probe.Catalog{Schema: probe.CatalogSchemaV1, Revision: "readback-test", Agent: probe.AgentSpec{ID: "private-agent", Independence: probe.IndependenceP1, AdvisoryOnly: true}, Paths: []probe.Path{{ID: "private-path", Kind: probe.PathKindDirect}}}
	for i := 0; i < count; i++ {
		c.Probes = append(c.Probes, probe.Target{ID: fmt.Sprintf("private-target-%03d", i), PathID: "private-path", Kind: probe.ProbeHTTPS, Host: "secret.example.com", Port: 443, RequestPath: "/private-request", Method: "GET", ExpectedStatus: []int{200}, RequiredMarker: "secret-marker", IntervalSeconds: 30, TimeoutSeconds: 2, TTLSeconds: 60, MaxBodyBytes: 1024})
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c, err = probe.ParseCatalogBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func viewProvider(t *testing.T, count int) (*Provider, *atomic.Int64) {
	t.Helper()
	p, err := New(Config{Catalog: viewCatalog(t, count), SpoolDir: filepath.Join(t.TempDir(), "nonexistent-spool"), PollInterval: time.Second, CacheMaxAge: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	wall := &atomic.Int64{}
	wall.Store(viewTestTime.UnixNano())
	p.now = func() time.Time { return time.Unix(0, wall.Load()).UTC() }
	return p, wall
}

func viewResult(p *Provider, target int, offset time.Duration, conclusion probe.Conclusion, outcome probe.Outcome) probe.ProbeResult {
	completed := viewTestTime.Add(offset)
	observed := completed.Add(-time.Millisecond)
	expires := completed.Add(time.Minute)
	layer := probe.LayerResult{State: probe.LayerAvailable, ObservedAt: observed, ExpiresAt: expires, Reason: "contract_matched"}
	httpStatus := 200
	return probe.ProbeResult{SchemaVersion: probe.ResultSchemaV1, RunID: fmt.Sprintf("run-%d-%d", target, completed.UnixNano()), ProbeID: p.config.Catalog.Probes[target].ID, PathID: p.config.Catalog.Probes[target].PathID, CatalogDigest: p.config.Catalog.Digest, AgentID: p.config.Catalog.Agent.ID, Independence: probe.IndependenceP1, AdvisoryOnly: true, AttemptedAt: completed.Add(-time.Second), CompletedAt: completed, ExpiresAt: expires, Conclusion: conclusion, Outcome: outcome, HTTPStatus: &httpStatus, Layers: probe.LayerResults{DNS: layer, Connect: layer, TLS: layer, HTTP: layer, Business: layer}}
}

func viewReport(results ...probe.ProbeResult) probe.SecureReadReport {
	return probe.SecureReadReport{ReadReport: probe.ReadReport{Healthy: true, Results: results}, ValidTotal: len(results), EligibleTotal: len(results), Returned: len(results)}
}

func viewPublish(p *Provider, report probe.SecureReadReport) {
	p.read = func(context.Context, string, probe.SecureReadOptions) (probe.SecureReadReport, error) {
		return report, nil
	}
	p.refresh(context.Background())
}

func assertViewHidden(t *testing.T, p *Provider, reason string) {
	t.Helper()
	d := p.Details()
	if d.Status.State != "unknown" || d.Status.Reason != reason || len(d.Samples) != 0 {
		t.Fatalf("invalid view is not hidden: %+v", d)
	}
	for _, target := range d.Targets {
		if target.State != probe.ConclusionUnknown || target.Reason != reason || target.ConsecutiveSuccess != 0 || target.ConsecutiveFailure != 0 {
			t.Fatalf("invalid target remained current: %+v", target)
		}
	}
}

func TestProbeViewP1NewAndDisabledAreZeroIO(t *testing.T) {
	p, _ := viewProvider(t, 1)
	p.read = func(context.Context, string, probe.SecureReadOptions) (probe.SecureReadReport, error) {
		panic("request performed I/O")
	}
	if _, err := os.Lstat(p.config.SpoolDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("New created or accessed an expected-missing spool: %v", err)
	}
	if p.Status().State != "pending" || len(p.Details().Targets) != 1 {
		t.Fatal("pending cache is not available without I/O")
	}
	disabled := DisabledStatus()
	if disabled.Configured || disabled.Running || disabled.State != "disabled" || disabled.Reason != "disabled" || !disabled.AdvisoryOnly {
		t.Fatalf("invalid disabled status: %+v", disabled)
	}
	if _, err := os.Lstat(p.config.SpoolDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache request created a spool")
	}
}

func TestProbeViewP1ConfigurationBoundsAndCatalogDigest(t *testing.T) {
	p, _ := viewProvider(t, 1)
	valid := p.config
	bad := []Config{valid, valid, valid, valid, valid, valid, valid}
	bad[0].PollInterval = time.Second - 1
	bad[1].PollInterval = 60*time.Second + 1
	bad[2].CacheMaxAge = time.Second - 1
	bad[3].CacheMaxAge = 300*time.Second + 1
	bad[4].SpoolDir = "relative-spool"
	bad[5].Catalog.Digest = ""
	bad[6].Catalog = cloneCatalog(valid.Catalog)
	bad[6].Catalog.Probes[0].Host = "changed.example.com"
	for i, config := range bad {
		if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("bad configuration %d accepted: %v", i, err)
		}
	}
	valid.PollInterval, valid.CacheMaxAge = 60*time.Second, 300*time.Second
	if _, err := New(valid); err != nil {
		t.Fatal(err)
	}
}

func TestProbeViewP1CatalogIsDeeplyOwned(t *testing.T) {
	catalog := viewCatalog(t, 1)
	catalog.Probes[0].AllowedCNAMEs = []string{"alias.example.com"}
	var err error
	catalog.Digest, err = probe.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Catalog: catalog, SpoolDir: filepath.Join(t.TempDir(), "missing"), PollInterval: time.Second, CacheMaxAge: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	catalog.Paths[0].ID = "mutated"
	catalog.Probes[0].ID = "mutated"
	catalog.Probes[0].ExpectedStatus[0] = 403
	catalog.Probes[0].AllowedCNAMEs[0] = "mutated.example.com"
	if p.config.Catalog.Probes[0].ID == "mutated" || p.config.Catalog.Paths[0].ID == "mutated" || p.config.Catalog.Probes[0].ExpectedStatus[0] != 200 || p.config.Catalog.Probes[0].AllowedCNAMEs[0] != "alias.example.com" {
		t.Fatal("caller catalog aliases provider state")
	}
}

func TestProbeViewP1ReadUsesFixedNowOwnerAndLimits(t *testing.T) {
	p, _ := viewProvider(t, 1)
	calls := 0
	p.read = func(ctx context.Context, dir string, options probe.SecureReadOptions) (probe.SecureReadReport, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second || ctx.Err() != nil || dir != p.config.SpoolDir || !options.Now.Equal(viewTestTime) || options.IncludeExpired || options.Limit != 200 || options.OwnerUID != uint32(os.Geteuid()) || options.OwnerGID != uint32(os.Getegid()) || options.Catalog.Digest != p.config.Catalog.Digest {
			t.Fatal("secure reader contract changed")
		}
		return viewReport(), nil
	}
	p.refresh(context.Background())
	if calls != 1 || !p.Status().CachedAt.Equal(viewTestTime) {
		t.Fatal("read did not publish its fixed time")
	}
}

func TestProbeViewP1AnonymousStatusIsFixedSafeCacheOnly(t *testing.T) {
	p, _ := viewProvider(t, 256)
	calls := 0
	p.read = func(context.Context, string, probe.SecureReadOptions) (probe.SecureReadReport, error) {
		calls++
		return viewReport(), nil
	}
	p.refresh(context.Background())
	for i := 0; i < 1000; i++ {
		raw, err := json.Marshal(p.Status())
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private-agent", "private-path", "private-target", "secret.example.com", "private-request", "secret-marker", "catalogDigest", "agentId", "probeId", "pathId", "samples", "targets\""} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("anonymous identity leak: %s", secret)
			}
		}
	}
	if calls != 1 {
		t.Fatalf("Status read disk %d times", calls)
	}
}

func TestProbeViewP1DetailsAreExplicitDeepCopies(t *testing.T) {
	p, _ := viewProvider(t, 1)
	result := viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	result.EvidenceRef = "private-evidence"
	viewPublish(p, viewReport(result))
	d := p.Details()
	d.Targets[0].ProbeID = "mutated"
	*d.Targets[0].ObservedAt = time.Time{}
	*d.Status.CachedAt = time.Time{}
	*d.Samples[0].HTTPStatus = 999
	d.Samples[0].Layers.DNS.Reason = "mutated"
	again := p.Details()
	if again.Targets[0].ProbeID == "mutated" || again.Targets[0].ObservedAt.IsZero() || again.Status.CachedAt.IsZero() || *again.Samples[0].HTTPStatus != 200 || again.Samples[0].Layers.DNS.Reason == "mutated" {
		t.Fatal("public DTO mutated cached snapshot")
	}
	raw, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"evidenceRef", "private-evidence", "stageTimings", "contentDigest", "secret.example.com", "private-request", "secret-marker"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("details leaked non-allowlisted field: %s", forbidden)
		}
	}
}

func TestProbeViewP1TwoPassThreeFailureHysteresis(t *testing.T) {
	p, _ := viewProvider(t, 1)
	pass1 := viewResult(p, 0, -4*time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	pass2 := viewResult(p, 0, -3*time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	viewPublish(p, viewReport(pass1))
	if p.Details().Targets[0].State != probe.ConclusionDegraded {
		t.Fatal("one success became available")
	}
	viewPublish(p, viewReport(pass1, pass2))
	if p.Details().Targets[0].State != probe.ConclusionAvailable {
		t.Fatal("two successes did not confirm availability")
	}
	fail1 := viewResult(p, 0, -3*time.Second, probe.ConclusionUnavailable, probe.OutcomeFail)
	fail2 := viewResult(p, 0, -2*time.Second, probe.ConclusionUnavailable, probe.OutcomeFail)
	fail3 := viewResult(p, 0, -time.Second, probe.ConclusionUnavailable, probe.OutcomeFail)
	viewPublish(p, viewReport(fail1, fail2))
	if p.Details().Targets[0].State != probe.ConclusionDegraded {
		t.Fatal("two failures became unavailable")
	}
	viewPublish(p, viewReport(fail1, fail2, fail3))
	if got := p.Details().Targets[0]; got.State != probe.ConclusionUnavailable || got.ConsecutiveFailure != 3 {
		t.Fatalf("three failures not confirmed: %+v", got)
	}
}

func TestProbeViewP1RestrictedAndRateLimitedStayDistinct(t *testing.T) {
	p, _ := viewProvider(t, 1)
	for _, status := range []int{403, 429} {
		conclusion, class := probe.ConclusionRestricted, "restricted"
		if status == 429 {
			conclusion, class = probe.ConclusionRateLimited, "rate_limited"
		}
		result := viewResult(p, 0, -time.Second, conclusion, probe.OutcomeIndeterminate)
		result.HTTPStatus, result.ErrorClass = &status, class
		viewPublish(p, viewReport(result))
		if got := p.Details().Targets[0]; got.State != conclusion || got.Reason != class {
			t.Fatalf("HTTP %d was promoted or collapsed: %+v", status, got)
		}
	}
}

func TestProbeViewP1Global200WindowDoesNotClaim256Coverage(t *testing.T) {
	p, _ := viewProvider(t, 256)
	results := make([]probe.ProbeResult, 200)
	for i := range results {
		results[i] = viewResult(p, i, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	}
	report := viewReport(results...)
	report.ValidTotal, report.EligibleTotal, report.Truncated = 300, 300, true
	viewPublish(p, report)
	d := p.Details()
	if len(d.Targets) != 256 || len(d.Samples) != 200 || d.Status.State != "partial" || d.Status.Coverage.TargetsWithSamples != 200 || d.Status.Coverage.TargetsMissing != 56 || !d.Status.Coverage.Truncated || !d.Status.Coverage.Partial {
		t.Fatalf("global result window masqueraded as complete coverage: %+v", d.Status)
	}
	for _, target := range d.Targets[200:] {
		if target.State != probe.ConclusionUnknown || target.Reason != "no_current_evidence" || target.RetainedSamples != 0 {
			t.Fatal("unobserved catalog target was not explicitly unknown")
		}
	}
}

func TestProbeViewP1EvidenceTTLIsNotRenewedByPolling(t *testing.T) {
	p, wall := viewProvider(t, 1)
	result := viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	result.ExpiresAt = viewTestTime.Add(time.Second)
	result.Layers = probe.LayerResults{DNS: probe.LayerResult{ExpiresAt: result.ExpiresAt}, Connect: probe.LayerResult{ExpiresAt: result.ExpiresAt}, TLS: probe.LayerResult{ExpiresAt: result.ExpiresAt}, HTTP: probe.LayerResult{ExpiresAt: result.ExpiresAt}, Business: probe.LayerResult{ExpiresAt: result.ExpiresAt}}
	viewPublish(p, viewReport(result))
	first := *p.Status().ExpiresAt
	wall.Store(viewTestTime.Add(500 * time.Millisecond).UnixNano())
	viewPublish(p, viewReport(result))
	if !p.Status().ExpiresAt.Equal(first) {
		t.Fatal("poll extended original evidence TTL")
	}
	wall.Store(first.UnixNano())
	assertViewHidden(t, p, "evidence_expired")
	if p.Details().Status.Coverage.RetainedSamples != 1 {
		t.Fatal("historical retained count was silently changed at expiry")
	}
}

func TestProbeViewP1CacheAgeAndLayerTTLBoundDetails(t *testing.T) {
	p, wall := viewProvider(t, 1)
	p.config.CacheMaxAge = 2 * time.Second
	result := viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	viewPublish(p, viewReport(result))
	wall.Store(viewTestTime.Add(2 * time.Second).UnixNano())
	assertViewHidden(t, p, "cache_expired")
	p, wall = viewProvider(t, 1)
	result = viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	result.Layers.DNS.ExpiresAt = viewTestTime.Add(time.Second)
	viewPublish(p, viewReport(result))
	wall.Store(viewTestTime.Add(time.Second).UnixNano())
	assertViewHidden(t, p, "evidence_expired")
}

func TestProbeViewP1WallRollbackRequiresCatchupAndNewRead(t *testing.T) {
	p, wall := viewProvider(t, 1)
	report := viewReport(viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass))
	viewPublish(p, report)
	wall.Store(viewTestTime.Add(time.Second).UnixNano())
	_ = p.Status()
	wall.Store(viewTestTime.UnixNano())
	assertViewHidden(t, p, "clock_rollback")
	viewPublish(p, report)
	assertViewHidden(t, p, "clock_rollback")
	wall.Store(viewTestTime.Add(time.Second).UnixNano())
	assertViewHidden(t, p, "clock_rollback")
	viewPublish(p, report)
	if !p.Status().ClockHealthy || len(p.Details().Samples) != 1 {
		t.Fatal("caught-up clock plus a fresh strict read did not recover")
	}
	wall.Store(viewTestTime.Add(2 * time.Second).UnixNano())
	_ = p.Details()
	wall.Store(viewTestTime.Add(time.Second).UnixNano())
	viewPublish(p, report)
	assertViewHidden(t, p, "clock_rollback")
}

func TestProbeViewP1FutureAndNormalExpiredEvidenceAreNotGreen(t *testing.T) {
	p, _ := viewProvider(t, 1)
	viewPublish(p, viewReport(viewResult(p, 0, time.Second, probe.ConclusionAvailable, probe.OutcomePass)))
	assertViewHidden(t, p, "no_current_evidence")
	report := viewReport()
	report.ValidTotal, report.ExpiredTotal = 2, 2
	viewPublish(p, report)
	d := p.Details()
	if d.Status.State != "partial" || d.Status.Reason != "evidence_expired" || !d.Status.StorageHealthy || d.Status.Coverage.ExpiredTotal != 2 || d.Status.Coverage.RejectedTotal != 0 || len(d.Samples) != 0 {
		t.Fatalf("normal expiry was confused with corrupt storage: %+v", d.Status)
	}
}

func TestProbeViewP1ReadFailuresNeverPreserveGreenCache(t *testing.T) {
	p, _ := viewProvider(t, 1)
	for _, failure := range []struct {
		err    error
		reason string
	}{{probe.ErrSecureUnsupported, "platform_unsupported"}, {probe.ErrSecureLimit, "limit_rejected"}, {probe.ErrSecureUnsafe, "storage_rejected"}, {probe.ErrSecureChanged, "storage_rejected"}, {probe.ErrSecureInvalid, "storage_rejected"}, {probe.ErrSecureIO, "read_unavailable"}, {context.DeadlineExceeded, "read_unavailable"}} {
		viewPublish(p, viewReport(viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)))
		p.read = func(context.Context, string, probe.SecureReadOptions) (probe.SecureReadReport, error) {
			return viewReport(), failure.err
		}
		p.refresh(context.Background())
		assertViewHidden(t, p, failure.reason)
		if p.Status().StorageHealthy {
			t.Fatal("failed read was marked healthy")
		}
	}
}

func TestProbeViewP1ContentRejectionsCannotRevealOlderGreen(t *testing.T) {
	p, _ := viewProvider(t, 1)
	report := viewReport(viewResult(p, 0, -2*time.Second, probe.ConclusionAvailable, probe.OutcomePass), viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass))
	report.Healthy = false
	for _, reason := range []string{
		"segment_size_invalid", "segment_json_duplicate_key", "segment_json_invalid", "unknown_schema", "unknown_result_schema",
		"content_digest_mismatch", "content_digest_invalid", "filename_mismatch",
		"catalog_digest_mismatch", "catalog_membership_mismatch", "future_result", "duplicate_run_id",
		"result_identity_invalid", "result_not_advisory", "result_time_invalid", "result_contract_time_invalid", "result_value_invalid", "result_enum_invalid", "evidence_ref_invalid", "result_layer_invalid", "result_http_status_invalid",
	} {
		report.Issues = append(report.Issues, probe.ReadIssue{File: "private-file", Reason: reason})
	}
	report.Rejected = len(report.Issues)
	viewPublish(p, report)
	assertViewHidden(t, p, "content_rejected")
	if got := p.Details().Rejections; got != (Rejections{Format: 5, Integrity: 3, Catalog: 2, Future: 1, Duplicate: 1, Semantic: 9}) {
		t.Fatalf("closed rejection counters incorrect: %+v", got)
	}
	raw, _ := json.Marshal(p.Details())
	if strings.Contains(string(raw), "private-file") {
		t.Fatal("read issue filename escaped")
	}
}

func TestProbeViewP1MalformedCountsAndCrossScopeFailClosed(t *testing.T) {
	p, _ := viewProvider(t, 1)
	good := viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass)
	for i := 0; i < 7; i++ {
		report := viewReport(good)
		switch i {
		case 0:
			report.Returned = 2
		case 1:
			report.ExpiredTotal = 2
		case 2:
			report.Truncated = true
		case 3:
			report.Results[0].AgentID = "other-agent"
		case 4:
			report.Results[0].CatalogDigest = "other-catalog"
		case 5:
			report.Results[0].PathID = "other-path"
		case 6:
			report.Results[0].ProbeID = "other-probe"
		}
		viewPublish(p, report)
		assertViewHidden(t, p, "read_unavailable")
	}
}

func TestProbeViewP1ConcurrentSnapshotsDoNotAlias(t *testing.T) {
	p, _ := viewProvider(t, 1)
	report := viewReport(viewResult(p, 0, -time.Second, probe.ConclusionAvailable, probe.OutcomePass))
	viewPublish(p, report)
	var wg sync.WaitGroup
	errorsCh := make(chan string, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				d := p.Details()
				if len(d.Samples) != 1 || *d.Samples[0].HTTPStatus != 200 || p.Status().Coverage.RetainedSamples != 1 {
					errorsCh <- "inconsistent published snapshot"
					return
				}
				*d.Samples[0].HTTPStatus = 999
				d.Targets[0].ProbeID = "mutated"
			}
		}()
	}
	for i := 0; i < 200; i++ {
		p.refresh(context.Background())
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("snapshot readers did not join")
	}
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
}

func TestProbeViewP1SingleWorkerCancellationActuallyJoins(t *testing.T) {
	p, _ := viewProvider(t, 1)
	entered := make(chan struct{})
	var calls, active atomic.Int32
	p.read = func(ctx context.Context, _ string, _ probe.SecureReadOptions) (probe.SecureReadReport, error) {
		if active.Add(1) != 1 {
			t.Error("overlapping reads")
		}
		defer active.Add(-1)
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-ctx.Done()
		return probe.SecureReadReport{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("worker leaked after failed assertion")
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read never started")
	}
	if err := p.Run(ctx); !errors.Is(err, ErrAlreadyRun) {
		t.Fatalf("second Run accepted: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		// Leave a result for the unconditional cleanup join above.
		done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop")
	}
	if active.Load() != 0 || calls.Load() != 1 || p.Status().Running || p.Status().Reason != "stopped" {
		t.Fatal("shutdown succeeded before the reader actually exited")
	}
}
