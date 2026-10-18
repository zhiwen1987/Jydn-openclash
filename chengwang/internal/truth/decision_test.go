package truth

import (
	"sync"
	"testing"
	"time"
)

type testState struct{ Revision string }

var baseTime = time.Date(2026, 10, 18, 8, 0, 0, 0, time.UTC)

func validStates() (*Desired[testState], *Actual[testState], *Observed[testState], Policy) {
	desired := &Desired[testState]{Known: true, Value: testState{Revision: "v2"}, DeclaredAt: baseTime, Revision: "v2"}
	actual := &Actual[testState]{Known: true, Value: testState{Revision: "v1"}, Source: SourceDeviceReadback, ReadAt: baseTime, EvidenceRef: "device://router/config/sha256:actual"}
	observed := &Observed[testState]{
		Known: true, Value: testState{Revision: "healthy"}, Source: SourceActiveProbe,
		ObservedAt: baseTime, ExpiresAt: baseTime.Add(2 * time.Minute), Confidence: 0.95,
		EvidenceRef: "probe://run/123",
	}
	return desired, actual, observed, Policy{FreshFor: time.Minute, MinConfidence: 0.8}
}

func TestDecideAllowsOnlyCompleteFreshEvidence(t *testing.T) {
	desired, actual, observed, policy := validStates()
	decision := Decide(baseTime.Add(30*time.Second), desired, actual, observed, policy)
	if !decision.Allowed || decision.Freshness != FreshnessFresh || len(decision.Reasons) != 0 {
		t.Fatalf("expected coordination to be allowed, got %+v", decision)
	}
}

func TestFreshnessBoundaryTimes(t *testing.T) {
	_, _, observed, policy := validStates()
	tests := []struct {
		name string
		now  time.Time
		want Freshness
		code BlockCode
	}{
		{name: "observation instant is fresh", now: baseTime, want: FreshnessFresh},
		{name: "just before stale boundary is fresh", now: baseTime.Add(time.Minute - time.Nanosecond), want: FreshnessFresh},
		{name: "stale boundary is stale", now: baseTime.Add(time.Minute), want: FreshnessStale, code: BlockObservedStale},
		{name: "just before expiry is stale", now: baseTime.Add(2*time.Minute - time.Nanosecond), want: FreshnessStale, code: BlockObservedStale},
		{name: "expiry instant is expired", now: baseTime.Add(2 * time.Minute), want: FreshnessExpired, code: BlockObservedExpired},
		{name: "after expiry is expired", now: baseTime.Add(3 * time.Minute), want: FreshnessExpired, code: BlockObservedExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reasons := AssessObservation(tt.now, observed, policy)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if tt.code == "" && len(reasons) != 0 {
				t.Fatalf("unexpected reasons: %+v", reasons)
			}
			if tt.code != "" && !hasCode(reasons, tt.code) {
				t.Fatalf("missing block code %q in %+v", tt.code, reasons)
			}
		})
	}
}

func TestMissingEvidenceIsUnknownAndBlocked(t *testing.T) {
	desired, actual, observed, policy := validStates()
	observed.EvidenceRef = "  "
	decision := Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
	assertBlocked(t, decision, FreshnessUnknown, BlockObservedEvidenceMissing)
}

func TestLowConfidenceIsFreshButBlocked(t *testing.T) {
	desired, actual, observed, policy := validStates()
	observed.Confidence = policy.MinConfidence - 0.01
	decision := Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
	assertBlocked(t, decision, FreshnessFresh, BlockObservedConfidenceLow)

	observed.Confidence = policy.MinConfidence
	decision = Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
	if !decision.Allowed {
		t.Fatalf("confidence at threshold should be accepted: %+v", decision)
	}
}

func TestCacheAndDemoSourcesAreRejected(t *testing.T) {
	for _, source := range []Source{SourceCache, SourceDemo} {
		t.Run(string(source)+" actual", func(t *testing.T) {
			desired, actual, observed, policy := validStates()
			actual.Source = source
			decision := Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
			assertBlocked(t, decision, FreshnessFresh, BlockActualSourceUntrusted)
		})
		t.Run(string(source)+" observed", func(t *testing.T) {
			desired, actual, observed, policy := validStates()
			observed.Source = source
			decision := Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
			assertBlocked(t, decision, FreshnessUnknown, BlockObservedSourceUntrusted)
		})
	}
}

func TestActualUnknownBlocksCoordination(t *testing.T) {
	desired, actual, observed, policy := validStates()
	actual.Known = false
	decision := Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
	assertBlocked(t, decision, FreshnessFresh, BlockActualUnknown)
}

func TestClockRollbackMakesObservationUnknown(t *testing.T) {
	desired, actual, observed, policy := validStates()
	decision := Decide(baseTime.Add(-time.Nanosecond), desired, actual, observed, policy)
	assertBlocked(t, decision, FreshnessUnknown, BlockClockRollback)
}

func TestInvalidObservationTimesAreUnknown(t *testing.T) {
	_, _, observed, policy := validStates()
	for _, expiresAt := range []time.Time{time.Time{}, observed.ObservedAt, observed.ObservedAt.Add(-time.Second)} {
		copy := *observed
		copy.ExpiresAt = expiresAt
		freshness, reasons := AssessObservation(baseTime, &copy, policy)
		if freshness != FreshnessUnknown || !hasCode(reasons, BlockObservedTimeInvalid) {
			t.Fatalf("invalid times should be unknown, got freshness=%q reasons=%+v", freshness, reasons)
		}
	}
}

func TestMissingDesiredAndInvalidPolicyReturnStructuredReasons(t *testing.T) {
	_, actual, observed, _ := validStates()
	decision := Decide[testState](baseTime, nil, actual, observed, Policy{})
	if decision.Allowed || decision.Freshness != FreshnessUnknown {
		t.Fatalf("unsafe decision: %+v", decision)
	}
	for _, code := range []BlockCode{BlockInvalidPolicy, BlockDesiredMissing} {
		if !hasCode(decision.Reasons, code) {
			t.Fatalf("missing %q in %+v", code, decision.Reasons)
		}
	}
}

func TestDecisionIsSafeForConcurrentReadOnlyEvaluation(t *testing.T) {
	desired, actual, observed, policy := validStates()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				decision := Decide(baseTime.Add(time.Second), desired, actual, observed, policy)
				if !decision.Allowed {
					t.Errorf("concurrent read-only decision unexpectedly blocked: %+v", decision)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func assertBlocked(t *testing.T, decision Decision, freshness Freshness, code BlockCode) {
	t.Helper()
	if decision.Allowed || decision.Freshness != freshness || !hasCode(decision.Reasons, code) {
		t.Fatalf("expected blocked %q/%q, got %+v", freshness, code, decision)
	}
}

func hasCode(reasons []BlockReason, code BlockCode) bool {
	for _, item := range reasons {
		if item.Code == code {
			return true
		}
	}
	return false
}
