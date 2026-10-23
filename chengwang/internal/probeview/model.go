// Package probeview publishes bounded, advisory-only, read-only probe views.
// It neither runs probes nor authorizes routing or device changes.
package probeview

import (
	"time"

	"chengwang/internal/probe"
)

type Coverage struct {
	DeclaredTargets    int  `json:"declaredTargets"`
	TargetsWithSamples int  `json:"targetsWithSamples"`
	TargetsMissing     int  `json:"targetsMissing"`
	RetainedSamples    int  `json:"retainedSamples"`
	ValidTotal         int  `json:"validTotal"`
	ExpiredTotal       int  `json:"expiredTotal"`
	EligibleTotal      int  `json:"eligibleTotal"`
	RejectedTotal      int  `json:"rejectedTotal"`
	Truncated          bool `json:"truncated"`
	Partial            bool `json:"partial"`
}

// Status deliberately contains no catalog, agent, probe, path or file identity.
// Ready describes the availability of the readback view, not business health.
type Status struct {
	Schema         string     `json:"schema"`
	Configured     bool       `json:"configured"`
	Running        bool       `json:"running"`
	AdvisoryOnly   bool       `json:"advisoryOnly"`
	State          string     `json:"state"`
	Reason         string     `json:"reason"`
	ClockHealthy   bool       `json:"clockHealthy"`
	StorageHealthy bool       `json:"storageHealthy"`
	CachedAt       *time.Time `json:"cachedAt,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	Coverage       Coverage   `json:"coverage"`
}

type Target struct {
	ProbeID            string           `json:"probeId"`
	PathID             string           `json:"pathId"`
	State              probe.Conclusion `json:"state"`
	Reason             string           `json:"reason"`
	ObservedAt         *time.Time       `json:"observedAt,omitempty"`
	ExpiresAt          *time.Time       `json:"expiresAt,omitempty"`
	ConsecutiveSuccess int              `json:"consecutiveSuccess"`
	ConsecutiveFailure int              `json:"consecutiveFailure"`
	RetainedSamples    int              `json:"retainedSamples"`
}

// These projections are explicit allowlists, not aliases of probe result types.
type Layer struct {
	State             probe.LayerState `json:"state"`
	ObservedAt        time.Time        `json:"observedAt"`
	ExpiresAt         time.Time        `json:"expiresAt"`
	LatencyMillis     int64            `json:"latencyMillis"`
	RetryAfterSeconds int64            `json:"retryAfterSeconds,omitempty"`
	Reason            string           `json:"reason"`
}

type Layers struct {
	DNS      Layer `json:"dns"`
	Connect  Layer `json:"connect"`
	TLS      Layer `json:"tls"`
	HTTP     Layer `json:"http"`
	Business Layer `json:"business"`
}

type Sample struct {
	RunID         string           `json:"runId"`
	ProbeID       string           `json:"probeId"`
	PathID        string           `json:"pathId"`
	AttemptedAt   time.Time        `json:"attemptedAt"`
	CompletedAt   time.Time        `json:"completedAt"`
	ExpiresAt     time.Time        `json:"expiresAt"`
	Conclusion    probe.Conclusion `json:"conclusion"`
	Outcome       probe.Outcome    `json:"outcome"`
	HTTPStatus    *int             `json:"httpStatus,omitempty"`
	ResponseBytes int64            `json:"responseBytes,omitempty"`
	ErrorClass    string           `json:"errorClass,omitempty"`
	Layers        Layers           `json:"layers"`
}

type Rejections struct {
	Format    int `json:"format"`
	Integrity int `json:"integrity"`
	Catalog   int `json:"catalog"`
	Future    int `json:"future"`
	Duplicate int `json:"duplicate"`
	Semantic  int `json:"semantic"`
}

type Details struct {
	Schema        string                  `json:"schema"`
	Status        Status                  `json:"status"`
	CatalogDigest string                  `json:"catalogDigest"`
	AgentID       string                  `json:"agentId"`
	Independence  probe.IndependenceLevel `json:"independence"`
	AdvisoryOnly  bool                    `json:"advisoryOnly"`
	Targets       []Target                `json:"targets"`
	Samples       []Sample                `json:"samples"`
	Rejections    Rejections              `json:"rejections"`
}

func DisabledStatus() Status {
	return Status{Schema: "chengwang.probe-view-status/v1", AdvisoryOnly: true, State: "disabled", Reason: "disabled"}
}
