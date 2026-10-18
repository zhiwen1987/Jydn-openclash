// Package truth models the three different kinds of state used by a safe
// reconciliation loop. Desired, Actual, and Observed are intentionally
// separate types: none of them is a cache or fallback for another.
package truth

import "time"

// Source identifies where a fact came from. Sources are classified by their
// intended use; an observation is not automatically authoritative actual
// configuration, even when both originated from the same device.
type Source string

const (
	SourceRuntimeConfiguration Source = "runtime_configuration"
	SourceDeviceReadback       Source = "device_readback"
	SourceRuntimeAPI           Source = "runtime_api"
	SourceActiveProbe          Source = "active_probe"
	SourceDeviceTelemetry      Source = "device_telemetry"

	// SourceCache and SourceDemo are named so callers can preserve provenance.
	// They are deliberately rejected by coordination decisions.
	SourceCache Source = "cache"
	SourceDemo  Source = "demo"
)

// Desired is operator or policy intent. Known must be true for the value to be
// eligible for coordination. A zero value is never inferred to be intent.
type Desired[T any] struct {
	Known      bool      `json:"known"`
	Value      T         `json:"value"`
	DeclaredAt time.Time `json:"declaredAt"`
	Revision   string    `json:"revision,omitempty"`
}

// Actual is authoritative applied configuration read from the target or its
// runtime configuration interface. Cached, demo, and observational data must
// not be copied into Actual.
type Actual[T any] struct {
	Known       bool      `json:"known"`
	Value       T         `json:"value"`
	Source      Source    `json:"source"`
	ReadAt      time.Time `json:"readAt"`
	EvidenceRef string    `json:"evidenceRef,omitempty"`
}

// Observed is measured runtime evidence. Every usable observation must carry
// provenance, a bounded lifetime, confidence, and a durable evidence reference.
type Observed[T any] struct {
	Known       bool      `json:"known"`
	Value       T         `json:"value"`
	Source      Source    `json:"source"`
	ObservedAt  time.Time `json:"observedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Confidence  float64   `json:"confidence"`
	EvidenceRef string    `json:"evidenceRef"`
}

// Freshness is the temporal usability of an observation.
type Freshness string

const (
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessExpired Freshness = "expired"
	FreshnessUnknown Freshness = "unknown"
)

// Policy defines how long an observation remains fresh and the minimum
// confidence required for coordination. It does not extend ExpiresAt.
type Policy struct {
	FreshFor      time.Duration `json:"freshFor"`
	MinConfidence float64       `json:"minConfidence"`
}

// DefaultPolicy is deliberately conservative; callers should use a
// domain-specific policy when a business probe has a different validity period.
func DefaultPolicy() Policy {
	return Policy{FreshFor: 30 * time.Second, MinConfidence: 0.8}
}

// BlockCode is stable for machines; Message is intended for operators.
type BlockCode string

const (
	BlockInvalidPolicy             BlockCode = "invalid_policy"
	BlockDesiredMissing            BlockCode = "desired_missing"
	BlockActualUnknown             BlockCode = "actual_unknown"
	BlockActualSourceUntrusted     BlockCode = "actual_source_untrusted"
	BlockObservedMissing           BlockCode = "observed_missing"
	BlockObservedEvidenceMissing   BlockCode = "observed_evidence_missing"
	BlockObservedSourceUntrusted   BlockCode = "observed_source_untrusted"
	BlockObservedTimeInvalid       BlockCode = "observed_time_invalid"
	BlockClockRollback             BlockCode = "clock_rollback"
	BlockObservedStale             BlockCode = "observed_stale"
	BlockObservedExpired           BlockCode = "observed_expired"
	BlockObservedConfidenceInvalid BlockCode = "observed_confidence_invalid"
	BlockObservedConfidenceLow     BlockCode = "observed_confidence_low"
)

type BlockReason struct {
	Code    BlockCode `json:"code"`
	Field   string    `json:"field"`
	Message string    `json:"message"`
}

// Decision is a gate, not a reconciliation result. Allowed means the caller
// has enough trustworthy state to start coordination; it does not mean Desired
// already equals Actual or that a mutation succeeded.
type Decision struct {
	Allowed     bool          `json:"allowed"`
	EvaluatedAt time.Time     `json:"evaluatedAt"`
	Freshness   Freshness     `json:"freshness"`
	Reasons     []BlockReason `json:"reasons"`
}
