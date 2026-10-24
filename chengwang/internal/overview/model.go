// Package overview projects existing anonymous cache summaries. It cannot read
// inventory, refresh an upstream, or authorize any device or business action.
package overview

import "time"

const Schema = "chengwang.overview-snapshot/v1"

type PublicSnapshot struct {
	Schema       string              `json:"schema"`
	DataSource   string              `json:"dataSource"`
	GeneratedAt  time.Time           `json:"generatedAt"`
	Mode         string              `json:"mode"`
	ReadOnly     bool                `json:"readOnly"`
	AdvisoryOnly bool                `json:"advisoryOnly"`
	Coverage     Coverage            `json:"coverage"`
	Observation  ObservationSummary  `json:"observation"`
	Probe        ProbeSummary        `json:"probe"`
	Subscription SubscriptionSummary `json:"subscription"`
	Unsupported  Unsupported         `json:"unsupported"`
}

type Coverage struct {
	State   string   `json:"state"`
	Missing []string `json:"missing"`
}

type Layer struct {
	State      string     `json:"state"`
	Reason     string     `json:"reason"`
	ObservedAt *time.Time `json:"observedAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
}

type ObservationSummary struct {
	Configured          bool       `json:"configured"`
	Running             bool       `json:"running"`
	Fresh               bool       `json:"fresh"`
	Stale               bool       `json:"stale"`
	LastAttemptAt       *time.Time `json:"lastAttemptAt"`
	LastSuccessAt       *time.Time `json:"lastSuccessAt"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	Controller          Layer      `json:"controller"`
	Storage             Layer      `json:"storage"`
	Clock               Layer      `json:"clock"`
}

type ProbeSummary struct {
	Configured     bool           `json:"configured"`
	Running        bool           `json:"running"`
	State          string         `json:"state"`
	Reason         string         `json:"reason"`
	ClockHealthy   bool           `json:"clockHealthy"`
	StorageHealthy bool           `json:"storageHealthy"`
	CachedAt       *time.Time     `json:"cachedAt"`
	ExpiresAt      *time.Time     `json:"expiresAt"`
	CoverageState  string         `json:"coverageState"`
	Coverage       *ProbeCoverage `json:"coverage"`
}

type ProbeCoverage struct {
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

type SubscriptionSummary struct {
	Configured     bool   `json:"configured"`
	InventoryState string `json:"inventoryState"`
	SourceCount    *int   `json:"sourceCount"`
	NodeCount      *int   `json:"nodeCount"`
}

type Unsupported struct {
	Businesses      bool `json:"businesses"`
	NodePools       bool `json:"nodePools"`
	EndToEndDNS     bool `json:"endToEndDNS"`
	DeviceInventory bool `json:"deviceInventory"`
	TrafficTopology bool `json:"trafficTopology"`
}
