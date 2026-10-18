// Package probe defines the advisory-only active-probe contract. Probe results
// describe one configured business target and path; they are not node-health
// claims and they never authorize routing changes.
package probe

import (
	"net/netip"
	"time"
)

const (
	CatalogSchemaV1 = "chengwang.probe-catalog/v1"
	ResultSchemaV1  = "chengwang.probe-result/v1"
)

type IndependenceLevel string

const (
	IndependenceP0 IndependenceLevel = "P0"
	IndependenceP1 IndependenceLevel = "P1"
	IndependenceP2 IndependenceLevel = "P2"
	IndependenceP3 IndependenceLevel = "P3"
	IndependenceP4 IndependenceLevel = "P4"
)

type AgentSpec struct {
	ID           string            `json:"id"`
	Independence IndependenceLevel `json:"independence"`
	AdvisoryOnly bool              `json:"advisoryOnly"`
}

// Path is a named, pre-provisioned egress path. The catalog cannot contain
// proxy URLs, credentials, namespaces, interfaces, or arbitrary commands.
type Path struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

const PathKindDirect = "direct"

type ProbeKind string

const ProbeHTTPS ProbeKind = "https"

// Target is an immutable allowlisted request. It deliberately has no request
// headers, body, cookie, script, proxy, resolver, or redirect configuration.
type Target struct {
	ID              string    `json:"id"`
	PathID          string    `json:"pathId"`
	Kind            ProbeKind `json:"kind"`
	Host            string    `json:"host"`
	AllowedCNAMEs   []string  `json:"allowedCNAMEs,omitempty"`
	Port            uint16    `json:"port"`
	RequestPath     string    `json:"requestPath"`
	Method          string    `json:"method"`
	ExpectedStatus  []int     `json:"expectedStatus"`
	RequiredMarker  string    `json:"requiredMarker,omitempty"`
	IntervalSeconds int       `json:"intervalSeconds"`
	TimeoutSeconds  int       `json:"timeoutSeconds"`
	TTLSeconds      int       `json:"ttlSeconds"`
	MaxBodyBytes    int64     `json:"maxBodyBytes"`
}

// ProbeSpec is retained as a descriptive alias for callers constructing a
// catalog. Runtime APIs use Target to emphasize that only catalog entries run.
type ProbeSpec = Target

type Catalog struct {
	Schema   string    `json:"schema"`
	Revision string    `json:"revision"`
	Agent    AgentSpec `json:"agent"`
	Paths    []Path    `json:"paths"`
	Probes   []Target  `json:"probes"`
	Digest   string    `json:"-"`
}

type LayerState string

const (
	LayerUnknown     LayerState = "unknown"
	LayerAvailable   LayerState = "available"
	LayerDegraded    LayerState = "degraded"
	LayerRestricted  LayerState = "restricted"
	LayerUnavailable LayerState = "unavailable"
	LayerRateLimited LayerState = "rate_limited"
)

type LayerResult struct {
	State             LayerState `json:"state"`
	ObservedAt        time.Time  `json:"observedAt"`
	ExpiresAt         time.Time  `json:"expiresAt"`
	LatencyMillis     int64      `json:"latencyMillis"`
	RetryAfterSeconds int64      `json:"retryAfterSeconds,omitempty"`
	Reason            string     `json:"reason"`
}

type LayerResults struct {
	DNS      LayerResult `json:"dns"`
	Connect  LayerResult `json:"connect"`
	TLS      LayerResult `json:"tls"`
	HTTP     LayerResult `json:"http"`
	Business LayerResult `json:"business"`
}

type Conclusion string

const (
	ConclusionUnknown     Conclusion = "unknown"
	ConclusionAvailable   Conclusion = "available"
	ConclusionDegraded    Conclusion = "degraded"
	ConclusionRestricted  Conclusion = "restricted"
	ConclusionUnavailable Conclusion = "unavailable"
	ConclusionRateLimited Conclusion = "rate_limited"
)

type Outcome string

const (
	OutcomePass          Outcome = "pass"
	OutcomeFail          Outcome = "fail"
	OutcomeIndeterminate Outcome = "indeterminate"
)

type StageTimings struct {
	DNSMillis     int64 `json:"dnsMillis"`
	ConnectMillis int64 `json:"connectMillis"`
	TLSMillis     int64 `json:"tlsMillis"`
	HTTPMillis    int64 `json:"httpMillis"`
	TotalMillis   int64 `json:"totalMillis"`
}

// ProbeResult is evidence about exactly one target/path attempt. AdvisoryOnly
// must remain true in v1; downstream code must not use it as a switch command.
type ProbeResult struct {
	SchemaVersion string            `json:"schemaVersion"`
	RunID         string            `json:"runId"`
	ProbeID       string            `json:"probeId"`
	CatalogDigest string            `json:"catalogDigest"`
	AgentID       string            `json:"agentId"`
	Independence  IndependenceLevel `json:"independence"`
	PathID        string            `json:"pathId"`
	AttemptedAt   time.Time         `json:"attemptedAt"`
	CompletedAt   time.Time         `json:"completedAt"`
	ExpiresAt     time.Time         `json:"expiresAt"`
	Conclusion    Conclusion        `json:"conclusion"`
	Outcome       Outcome           `json:"outcome"`
	StageTimings  StageTimings      `json:"stageTimings"`
	HTTPStatus    *int              `json:"httpStatus,omitempty"`
	ResponseBytes int64             `json:"responseBytes"`
	ContentDigest string            `json:"contentDigest,omitempty"`
	ErrorClass    string            `json:"errorClass,omitempty"`
	EvidenceRef   string            `json:"evidenceRef,omitempty"`
	AdvisoryOnly  bool              `json:"advisoryOnly"`
	Layers        LayerResults      `json:"layers"`
}

// ResolvedTarget is a one-attempt destination plan. IP is pinned after every
// DNS answer has passed the address policy; Host/ServerName retain TLS SNI.
type ResolvedTarget struct {
	TargetID       string       `json:"targetId"`
	Host           string       `json:"host"`
	CanonicalChain []string     `json:"canonicalChain"`
	CanonicalName  string       `json:"canonicalName"`
	ServerName     string       `json:"serverName"`
	Port           uint16       `json:"port"`
	IP             netip.Addr   `json:"ip"`
	ValidatedIPs   []netip.Addr `json:"validatedIps"`
	DialAddress    string       `json:"dialAddress"`
}
