package probe

import (
	"testing"
	"time"
)

func TestAggregateRequiresTwoSuccessesAndKeepsBusinessesSeparate(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	internet := resultForAggregate("internet", "path-a", now.Add(-20*time.Second), ConclusionAvailable, OutcomePass)
	businessFailure := resultForAggregate("gemini", "path-a", now.Add(-20*time.Second), ConclusionUnavailable, OutcomeFail)
	got := AggregateByProbe([]ProbeResult{internet, businessFailure}, now)
	if len(got) != 2 {
		t.Fatalf("got %d aggregates", len(got))
	}
	if got[0].ProbeID != "gemini" || got[0].State != ConclusionDegraded {
		t.Fatalf("business should be independently degraded: %+v", got[0])
	}
	if got[1].ProbeID != "internet" || got[1].State != ConclusionDegraded {
		t.Fatalf("one internet success must not turn green: %+v", got[1])
	}
}

func TestAggregateHysteresisAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	results := []ProbeResult{
		resultForAggregate("business", "path-a", now.Add(-40*time.Second), ConclusionUnavailable, OutcomeFail),
		resultForAggregate("business", "path-a", now.Add(-30*time.Second), ConclusionUnavailable, OutcomeFail),
		resultForAggregate("business", "path-a", now.Add(-20*time.Second), ConclusionUnavailable, OutcomeFail),
	}
	got := AggregateByProbe(results, now)
	if len(got) != 1 || got[0].State != ConclusionUnavailable || got[0].ConsecutiveFailure != 3 {
		t.Fatalf("expected confirmed unavailable: %+v", got)
	}

	firstSuccess := resultForAggregate("business", "path-a", now.Add(-10*time.Second), ConclusionAvailable, OutcomePass)
	got = AggregateByProbe(append(results, firstSuccess), now)
	if got[0].State != ConclusionDegraded || got[0].ConsecutiveSuccess != 1 {
		t.Fatalf("one recovery success must remain degraded: %+v", got[0])
	}
	secondSuccess := resultForAggregate("business", "path-a", now.Add(-5*time.Second), ConclusionAvailable, OutcomePass)
	got = AggregateByProbe(append(results, firstSuccess, secondSuccess), now)
	if got[0].State != ConclusionAvailable || got[0].ConsecutiveSuccess != 2 {
		t.Fatalf("two recovery successes should confirm available: %+v", got[0])
	}

	expiredAt := now.Add(-time.Second)
	secondSuccess.ExpiresAt = expiredAt
	got = AggregateByProbe([]ProbeResult{secondSuccess}, now)
	if got[0].State != ConclusionUnknown || got[0].Reason != "evidence_stale_or_clock_invalid" {
		t.Fatalf("expired evidence must be unknown: %+v", got[0])
	}
}

func TestAggregateRestrictedAndRateLimitedNeverBecomeAvailable(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	restricted := resultForAggregate("chat", "path-a", now.Add(-5*time.Second), ConclusionRestricted, OutcomeIndeterminate)
	restricted.ErrorClass = "restricted"
	rateLimited := resultForAggregate("api", "path-a", now.Add(-5*time.Second), ConclusionRateLimited, OutcomeIndeterminate)
	got := AggregateByProbe([]ProbeResult{restricted, rateLimited}, now)
	if got[0].State != ConclusionRateLimited || got[1].State != ConclusionRestricted {
		t.Fatalf("restricted semantics were promoted: %+v", got)
	}
}

func TestAggregateDoesNotMixCatalogOrAgentGenerations(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	first := resultForAggregate("chat", "path-a", now.Add(-10*time.Second), ConclusionAvailable, OutcomePass)
	second := resultForAggregate("chat", "path-a", now.Add(-5*time.Second), ConclusionAvailable, OutcomePass)
	second.CatalogDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	third := resultForAggregate("chat", "path-a", now.Add(-3*time.Second), ConclusionAvailable, OutcomePass)
	third.AgentID = "agent-b"
	got := AggregateByProbe([]ProbeResult{first, second, third}, now)
	if len(got) != 3 {
		t.Fatalf("catalog/agent generations were mixed: %+v", got)
	}
	for _, aggregate := range got {
		if aggregate.State == ConclusionAvailable {
			t.Fatalf("single evidence from a generation became available: %+v", aggregate)
		}
	}
}

func resultForAggregate(probeID, pathID string, completed time.Time, conclusion Conclusion, outcome Outcome) ProbeResult {
	return ProbeResult{
		SchemaVersion: ResultSchemaV1,
		RunID:         probeID + completed.Format("150405"), ProbeID: probeID,
		CatalogDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AgentID:       "agent-a", Independence: IndependenceP1, PathID: pathID,
		AttemptedAt: completed.Add(-time.Second), CompletedAt: completed, ExpiresAt: completed.Add(time.Minute),
		Conclusion: conclusion, Outcome: outcome, AdvisoryOnly: true,
	}
}
