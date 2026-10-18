package observation

import "time"

// State is deliberately conservative: unavailable is based on a failed
// measurement, while unknown means the layer has never been measured.
type State string

const (
	StateUnknown     State = "unknown"
	StateAvailable   State = "available"
	StateDegraded    State = "degraded"
	StateUnavailable State = "unavailable"
)

type Layer struct {
	State      State      `json:"state"`
	ObservedAt *time.Time `json:"observedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Reason     string     `json:"reason"`
}

// Sample contains bounded passive facts derived from one Mihomo Controller
// read. It does not claim that nodes, the internet, DNS, or a business work.
type Sample struct {
	Sequence           uint64    `json:"sequence"`
	AttemptedAt        time.Time `json:"attemptedAt"`
	CompletedAt        time.Time `json:"completedAt"`
	DurationMillis     int64     `json:"durationMillis"`
	Success            bool      `json:"success"`
	ErrorClass         string    `json:"errorClass,omitempty"`
	ControllerVersion  string    `json:"controllerVersion,omitempty"`
	ProxyObjectCount   int       `json:"proxyObjectCount,omitempty"`
	SelectorGroupCount int       `json:"selectorGroupCount,omitempty"`
	LeafProxyCount     int       `json:"leafProxyCount,omitempty"`
	RuleCount          int       `json:"ruleCount,omitempty"`
}

type Status struct {
	Configured          bool       `json:"configured"`
	Mode                string     `json:"mode"`
	Running             bool       `json:"running"`
	Fresh               bool       `json:"fresh"`
	Stale               bool       `json:"stale"`
	LastAttemptAt       *time.Time `json:"lastAttemptAt,omitempty"`
	LastSuccessAt       *time.Time `json:"lastSuccessAt,omitempty"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	Controller          Layer      `json:"controller"`
	NodeTechnical       Layer      `json:"nodeTechnical"`
	Internet            Layer      `json:"internet"`
	Business            Layer      `json:"business"`
	DNS                 Layer      `json:"dns"`
	Storage             Layer      `json:"storage"`
	Clock               Layer      `json:"clock"`
}

type Detail struct {
	Status  Status   `json:"status"`
	Samples []Sample `json:"samples"`
}
