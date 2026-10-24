package overview

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/observation"
	"chengwang/internal/probeview"
)

type observationFixture struct { value observation.Status; calls int; after func() }
func (s *observationFixture) Status() observation.Status {
	if s == nil { panic("typed nil observation must not be called") }
	s.calls++
	if s.after != nil { s.after() }
	return s.value
}
func (*observationFixture) Detail(int) observation.Detail { panic("private detail must not be read") }

type probeFixture struct { value probeview.Status; calls int; after func() }
func (s *probeFixture) Status() probeview.Status {
	if s == nil { panic("typed nil probe must not be called") }
	s.calls++
	if s.after != nil { s.after() }
	return s.value
}
func (*probeFixture) Details() probeview.Details { panic("private probe details must not be read") }

func fixedNow() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 123456789, time.UTC) }
func timeValue(value time.Time) *time.Time { return &value }
func observationValue(now time.Time) observation.Status {
	observed := now.Add(-time.Second)
	return observation.Status{Configured: true, Mode: "passive_read_only", Running: true, Fresh: true,
		LastAttemptAt: timeValue(observed.Add(-time.Second)), LastSuccessAt: timeValue(observed),
		Controller: observation.Layer{State: observation.StateAvailable, ObservedAt: timeValue(observed), ExpiresAt: timeValue(now.Add(time.Minute)), Reason: "source private reason must not escape"},
		Storage: observation.Layer{State: observation.StateAvailable}, Clock: observation.Layer{State: observation.StateAvailable}}
}
func probeValue(now time.Time) probeview.Status {
	return probeview.Status{Schema: "chengwang.probe-view-status/v1", Configured: true, Running: true, AdvisoryOnly: true, State: "ready", Reason: "ok", ClockHealthy: true, StorageHealthy: true,
		CachedAt: timeValue(now.Add(-time.Second)), ExpiresAt: timeValue(now.Add(time.Minute)),
		Coverage: probeview.Coverage{DeclaredTargets: 2, TargetsWithSamples: 2, RetainedSamples: 3, ValidTotal: 4, ExpiredTotal: 1, EligibleTotal: 3}}
}
func configured(t *testing.T, config Config) *Provider {
	t.Helper()
	if config.Mode == "" { config.Mode = "candidate" }
	if config.Now == nil { config.Now = fixedNow }
	p, err := New(config)
	if err != nil { t.Fatal("safe provider construction failed") }
	return p
}
func snapshot(t *testing.T, p *Provider) PublicSnapshot {
	t.Helper()
	value, err := p.Snapshot(context.Background())
	if err != nil || Validate(value) != nil { t.Fatal("safe cached projection failed") }
	return value
}

func TestOverviewConstructorIsCacheSilentAndPreservesCustomMode(t *testing.T) {
	o := &observationFixture{value: observationValue(fixedNow())}
	p := &probeFixture{value: probeValue(fixedNow())}
	for _, mode := range []string{"Shadow", "lab.prod", "实际证据", strings.Repeat("a", 64)} {
		provider, err := New(Config{Mode: mode, Observation: o, Probes: p, Now: fixedNow})
		if err != nil || provider.config.Mode != mode || o.calls != 0 || p.calls != 0 { t.Fatal("construction read sources or changed mode") }
	}
	for _, mode := range []string{"", " candidate", "candidate ", "a\nb", "a\u202eb", strings.Repeat("a", 65), string([]byte{0xff})} {
		if _, err := New(Config{Mode: mode}); !errors.Is(err, ErrInvalidProjection) || strings.Contains(err.Error(), mode) && mode != "" { t.Fatal("unsafe mode accepted or reflected") }
	}
}

func TestOverviewNilAndTypedNilSourcesAreExplicitUnknown(t *testing.T) {
	var o *observationFixture
	var q *probeFixture
	for _, config := range []Config{{}, {Observation: o, Probes: q}} {
		value := snapshot(t, configured(t, config))
		if value.DataSource != "live" || value.Coverage.State != "none" || len(value.Coverage.Missing) != 7 || value.Observation.Controller.State != "unknown" || value.Probe.Coverage != nil { t.Fatal("missing sources became measured zero or health") }
		raw, err := json.Marshal(value)
		if err != nil { t.Fatal(err) }
		for _, token := range []string{`"lastAttemptAt":null`, `"cachedAt":null`, `"coverage":null`, `"sourceCount":null`, `"nodeCount":null`} {
			if !strings.Contains(string(raw), token) { t.Fatal("required nullable field omitted") }
		}
	}
}

func TestOverviewCurrentControllerDoesNotClaimBusinessOrDNSHealth(t *testing.T) {
	o := &observationFixture{value: observationValue(fixedNow())}
	value := snapshot(t, configured(t, Config{Observation: o, SubscriptionConfigured: true}))
	if !value.Observation.Fresh || value.Coverage.State != "partial" || len(value.Coverage.Missing) != 6 || !value.Unsupported.Businesses || !value.Unsupported.EndToEndDNS { t.Fatal("controller evidence expanded into unsupported health") }
	if !value.Subscription.Configured || value.Subscription.SourceCount != nil || value.Subscription.NodeCount != nil || value.Subscription.InventoryState != "protected_not_read" || o.calls != 1 { t.Fatal("subscription inventory was invented") }
	if value.Observation.Controller.Reason != "cache_current" { t.Fatal("source reason copied") }
}

func TestOverviewStoppedCollectorInvalidatesStillFreshCache(t *testing.T) {
	o := &observationFixture{value: observationValue(fixedNow())}; o.value.Running = false
	value := snapshot(t, configured(t, Config{Observation: o}))
	if value.Observation.Fresh || !value.Observation.Stale || value.Observation.Controller.State != "unknown" || value.Observation.Controller.Reason != "worker_stopped" || value.Coverage.State != "none" { t.Fatal("stopped worker retained current health") }
}

func TestOverviewExpiryDoesNotRenewOriginalEvidenceTimes(t *testing.T) {
	now := fixedNow(); o := &observationFixture{value: observationValue(now)}; o.value.Controller.ExpiresAt = timeValue(now)
	value := snapshot(t, configured(t, Config{Observation: o}))
	if value.Observation.Fresh || !value.Observation.Stale || value.Observation.Controller.State != "degraded" || !value.Observation.Controller.ExpiresAt.Equal(now) { t.Fatal("assembly renewed expired evidence") }
}

func TestOverviewClockRollbackRetainsHistoryWithoutCurrentClaims(t *testing.T) {
	now := fixedNow(); future := now.Add(time.Minute)
	o := &observationFixture{value: observationValue(future)}; o.value.Fresh = false; o.value.Stale = true; o.value.Clock.State = observation.StateUnavailable
	q := &probeFixture{value: probeValue(future)}; q.value.ClockHealthy = false
	value := snapshot(t, configured(t, Config{Observation: o, Probes: q}))
	if value.Observation.Controller.State != "unknown" || value.Observation.Fresh || value.Probe.Coverage != nil || value.Probe.State != "unknown" || value.Coverage.State != "none" { t.Fatal("rollback retained current evidence") }
	if !value.Observation.LastSuccessAt.After(value.GeneratedAt) || !value.Probe.CachedAt.After(value.GeneratedAt) { t.Fatal("rollback history was fabricated or dropped") }
}

func TestOverviewProbeCoverageIsAnonymousCurrentViewNotBusinessHealth(t *testing.T) {
	q := &probeFixture{value: probeValue(fixedNow())}
	value := snapshot(t, configured(t, Config{Probes: q}))
	if value.Probe.CoverageState != "current" || value.Probe.Coverage.TargetsWithSamples != 2 || value.Coverage.State != "partial" || len(value.Coverage.Missing) != 6 || !value.Unsupported.Businesses { t.Fatal("probe view coverage was misrepresented") }
	raw, _ := json.Marshal(value)
	for _, key := range []string{`"agentId"`, `"probeId"`, `"pathId"`, `"catalogDigest"`, `"targets"`, `"samples"`} {
		if strings.Contains(string(raw), key) { t.Fatal("anonymous projection exposed private identities") }
	}
}

func TestOverviewExpiredStoppedAndUntrustedProbeHidesHistoricalCounts(t *testing.T) {
	for _, alter := range []func(*probeview.Status){func(s *probeview.Status) { s.ExpiresAt = timeValue(fixedNow()) }, func(s *probeview.Status) { s.Running = false }, func(s *probeview.Status) { s.ClockHealthy = false }, func(s *probeview.Status) { s.StorageHealthy = false }, func(s *probeview.Status) { s.State, s.Reason = "unknown", "read_unavailable" }} {
		q := &probeFixture{value: probeValue(fixedNow())}; alter(&q.value)
		value := snapshot(t, configured(t, Config{Probes: q}))
		if value.Probe.Coverage != nil || value.Probe.CoverageState != "unavailable" || value.Coverage.State != "none" { t.Fatal("historical coverage reported as current") }
	}
}

func TestOverviewRejectsMalformedProbeSourceWithoutRawErrors(t *testing.T) {
	for _, alter := range []func(*probeview.Status){func(s *probeview.Status) { s.Schema = "PRIVATE_URL" }, func(s *probeview.Status) { s.Reason = "PRIVATE_TOKEN" }, func(s *probeview.Status) { s.State = "healthy" }, func(s *probeview.Status) { s.AdvisoryOnly = false }, func(s *probeview.Status) { s.Coverage.TargetsMissing = 1 }, func(s *probeview.Status) { s.Coverage.RetainedSamples = 201 }, func(s *probeview.Status) { s.Coverage.EligibleTotal = -1 }, func(s *probeview.Status) { s.CachedAt = timeValue(fixedNow().Add(time.Second)) }, func(s *probeview.Status) { s.ExpiresAt = s.CachedAt }, func(s *probeview.Status) { s.ExpiresAt = timeValue(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)) }} {
		q := &probeFixture{value: probeValue(fixedNow())}; alter(&q.value)
		_, err := configured(t, Config{Probes: q}).Snapshot(context.Background())
		if !errors.Is(err, ErrInvalidProjection) || err.Error() != "overview projection invalid" { t.Fatal("malformed source accepted or raw error reflected") }
	}
}

func TestOverviewRejectsMalformedObservationAndHealthyClockFuture(t *testing.T) {
	for _, alter := range []func(*observation.Status){func(s *observation.Status) { s.Mode = "PRIVATE_MODE" }, func(s *observation.Status) { s.Controller.State = "healthy" }, func(s *observation.Status) { s.ConsecutiveFailures = -1 }, func(s *observation.Status) { s.Stale = true }, func(s *observation.Status) { s.Controller.ObservedAt = nil }, func(s *observation.Status) { s.Controller.ExpiresAt = s.Controller.ObservedAt }, func(s *observation.Status) { s.LastAttemptAt = timeValue(fixedNow().Add(time.Second)) }} {
		o := &observationFixture{value: observationValue(fixedNow())}; alter(&o.value)
		_, err := configured(t, Config{Observation: o}).Snapshot(context.Background())
		if !errors.Is(err, ErrInvalidProjection) { t.Fatal("malformed observation accepted") }
	}
}

func TestOverviewProjectionOwnsTimesCoverageAndMissingList(t *testing.T) {
	now := fixedNow(); o := &observationFixture{value: observationValue(now)}; q := &probeFixture{value: probeValue(now)}
	p := configured(t, Config{Observation: o, Probes: q}); first := snapshot(t, p)
	*o.value.Controller.ObservedAt = now.Add(-time.Hour); q.value.Coverage.TargetsWithSamples = 0
	if !first.Observation.Controller.ObservedAt.Equal(now.Add(-time.Second)) || first.Probe.Coverage.TargetsWithSamples != 2 { t.Fatal("public DTO aliases source memory") }
	first.Coverage.Missing[0] = "private"; first.Probe.Coverage.TargetsMissing = 99
	o.value = observationValue(now); q.value = probeValue(now); second := snapshot(t, p)
	if second.Coverage.Missing[0] != "businesses" || second.Probe.Coverage.TargetsMissing != 0 { t.Fatal("responses share mutable storage") }
}

func TestOverviewNormalizesSourceZeroTimesAndOffsetsWithoutInventingEvidence(t *testing.T) {
	o := &observationFixture{value: observationValue(fixedNow())}; o.value.Storage.ObservedAt = timeValue(time.Time{})
	o.value.Controller.ObservedAt = timeValue(o.value.Controller.ObservedAt.In(time.FixedZone("fixture", 3600)))
	value := snapshot(t, configured(t, Config{Observation: o}))
	if value.Observation.Storage.ObservedAt != nil || value.Observation.Controller.ObservedAt.Location() != time.UTC { t.Fatal("source zero/offset time not safely normalized") }
	for _, now := range []time.Time{time.Time{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		_, err := configured(t, Config{Now: func() time.Time { return now }}).Snapshot(context.Background())
		if !errors.Is(err, ErrInvalidProjection) { t.Fatal("invalid assembly clock accepted") }
	}
}

func TestOverviewCanceledBeforeReadNeverCallsSources(t *testing.T) {
	o := &observationFixture{}; q := &probeFixture{}; ctx, cancel := context.WithCancel(context.Background()); cancel()
	_, err := configured(t, Config{Observation: o, Probes: q}).Snapshot(ctx)
	if !errors.Is(err, context.Canceled) || o.calls != 0 || q.calls != 0 { t.Fatal("pre-canceled read reached cache") }
}

func TestOverviewCanceledAfterObservationSkipsProbeAndClock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	o := &observationFixture{value: observationValue(fixedNow()), after: cancel}; q := &probeFixture{}; clockCalls := 0
	_, err := configured(t, Config{Observation: o, Probes: q, Now: func() time.Time { clockCalls++; return fixedNow() }}).Snapshot(ctx)
	if !errors.Is(err, context.Canceled) || o.calls != 1 || q.calls != 0 || clockCalls != 0 { t.Fatal("canceled read continued") }
}

func TestOverviewCanceledAfterProbeSkipsAssembly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	q := &probeFixture{value: probeValue(fixedNow()), after: cancel}; clockCalls := 0
	_, err := configured(t, Config{Probes: q, Now: func() time.Time { clockCalls++; return fixedNow() }}).Snapshot(ctx)
	if !errors.Is(err, context.Canceled) || q.calls != 1 || clockCalls != 0 { t.Fatal("canceled probe read assembled a report") }
}

func TestOverviewSequentialSourcesSampleClockOnlyAfterBothGetters(t *testing.T) {
	order := []string{}; o := &observationFixture{value: observationValue(fixedNow()), after: func() { order = append(order, "observation") }}
	q := &probeFixture{value: probeValue(fixedNow()), after: func() { order = append(order, "probe") }}
	snapshot(t, configured(t, Config{Observation: o, Probes: q, Now: func() time.Time { order = append(order, "clock"); return fixedNow() }}))
	if !reflect.DeepEqual(order, []string{"observation", "probe", "clock"}) { t.Fatal("assembly time or cache ownership ordering changed") }
}

func TestOverviewValidatorRejectsMalformedAlternateDTOWithoutPanic(t *testing.T) {
	for _, alter := range []func(*PublicSnapshot){func(s *PublicSnapshot) { s.Schema = "PRIVATE" }, func(s *PublicSnapshot) { s.DataSource = "demo" }, func(s *PublicSnapshot) { s.ReadOnly = false }, func(s *PublicSnapshot) { s.Subscription.SourceCount = new(int) }, func(s *PublicSnapshot) { s.Unsupported.Businesses = false }, func(s *PublicSnapshot) { s.Coverage.Missing = nil }, func(s *PublicSnapshot) { s.Coverage.State = "covered" }, func(s *PublicSnapshot) { s.Observation.Fresh = true; s.Observation.Controller.State = "available"; s.Observation.LastSuccessAt = timeValue(fixedNow()) }, func(s *PublicSnapshot) { s.Probe.Coverage = &ProbeCoverage{} }} {
		value := snapshot(t, configured(t, Config{})); alter(&value)
		if !errors.Is(Validate(value), ErrInvalidProjection) { t.Fatal("malformed alternate DTO accepted") }
	}
	for _, alter := range []func(*PublicSnapshot){
		func(s *PublicSnapshot) { s.Observation.Controller.Reason = "not_configured" },
		func(s *PublicSnapshot) { s.Observation.Storage.Reason = "storage_unhealthy" },
		func(s *PublicSnapshot) { s.Observation.Clock.Reason = "clock_untrusted" },
		func(s *PublicSnapshot) { s.Observation.Fresh = false; s.Observation.Stale = true; s.Observation.Controller.State = "unknown"; s.Observation.Controller.Reason = "storage_unhealthy"; s.Coverage = coverageFor(s.Observation, s.Probe) },
	} {
		o := &observationFixture{value: observationValue(fixedNow())}
		value := snapshot(t, configured(t, Config{Observation: o})); alter(&value)
		if !errors.Is(Validate(value), ErrInvalidProjection) { t.Fatal("contradictory alternate layer role/state/reason accepted") }
	}
}

func TestOverviewValidatorMissingFreshObservedTimeReturnsError(t *testing.T) {
	o := &observationFixture{value: observationValue(fixedNow())}
	value := snapshot(t, configured(t, Config{Observation: o}))
	// Keep configured/running/fresh and LastSuccessAt valid so this reaches
	// the alternate-provider fresh branch rather than disabled rejection.
	value.Observation.Controller.ObservedAt = nil
	value.Observation.Controller.ExpiresAt = nil
	if !errors.Is(Validate(value), ErrInvalidProjection) { t.Fatal("missing fresh observation time accepted") }
}
