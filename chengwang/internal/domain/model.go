package domain

import "time"

type Strategy string

const (
	StrategyDefault Strategy = "默认策略"
	StrategyDirect  Strategy = "DIRECT"
	StrategyReject  Strategy = "REJECT"
	StrategyStable  Strategy = "稳定自动"
	StrategyAuto    Strategy = "自动选择"
	StrategyManual  Strategy = "手动选择"
)

type PolicyDraft struct {
	Name       string           `json:"name"`
	Base       string           `json:"baseVersion"`
	Businesses []BusinessPolicy `json:"businesses"`
	Pools      []NodePool       `json:"pools"`
	DNS        DNSPolicy        `json:"dns"`
}

type BusinessPolicy struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Domains             []string `json:"domains"`
	Strategy            string   `json:"strategy"`
	Candidates          []string `json:"candidates"`
	Fallback            string   `json:"fallback"`
	SkipEmptyPools      bool     `json:"skipEmptyPools"`
	FailuresToSwitch    int      `json:"failuresToSwitch"`
	ProbeIntervalSec    int      `json:"probeIntervalSec"`
	SessionStickyMin    int      `json:"sessionStickyMin"`
	SwitchCooldownSec   int      `json:"switchCooldownSec"`
	RequireCapabilities []string `json:"requireCapabilities,omitempty"`
}

type NodePool struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Members      []string `json:"members"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type DNSPolicy struct {
	DomesticResolvers []string `json:"domesticResolvers"`
	OverseasResolvers []string `json:"overseasResolvers"`
	HijackPort53      bool     `json:"hijackPort53"`
	LeakProtection    bool     `json:"leakProtection"`
}

type ValidationIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Issues []ValidationIssue `json:"issues"`
}

type Version struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"createdAt"`
	Author    string      `json:"author"`
	Draft     PolicyDraft `json:"draft"`
	Digest    string      `json:"digest"`
}

type BusinessStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Strategy    string `json:"strategy"`
	ActiveRoute string `json:"activeRoute"`
	Status      string `json:"status"`
}

type PoolStatus struct {
	Name      string  `json:"name"`
	Region    string  `json:"region"`
	LatencyMS int     `json:"latencyMs"`
	LossRate  float64 `json:"lossRate"`
	Available int     `json:"available"`
	Total     int     `json:"total"`
	Status    string  `json:"status"`
}

type Event struct {
	At     time.Time `json:"at"`
	Type   string    `json:"type"`
	Reason string    `json:"reason"`
	Result string    `json:"result"`
}

type ProxyInterface struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	Core           string   `json:"core"`
	Listen         string   `json:"listen"`
	Port           int      `json:"port"`
	UDP            bool     `json:"udp"`
	LANAccess      bool     `json:"lanAccess"`
	AuthMode       string   `json:"authMode"`
	AuthReference  string   `json:"authReference,omitempty"`
	TLS            bool     `json:"tls"`
	TLSReference   string   `json:"tlsReference,omitempty"`
	AccessScope    string   `json:"accessScope"`
	AllowedCIDRs   []string `json:"allowedCidrs,omitempty"`
	MaxConnections int      `json:"maxConnections"`
	IdleTimeoutSec int      `json:"idleTimeoutSec"`
	RateLimitMbps  int      `json:"rateLimitMbps"`
	AuditEnabled   bool     `json:"auditEnabled"`
	Enabled        bool     `json:"enabled"`
	Status         string   `json:"status"`
	RoutingProfile string   `json:"routingProfile"`
	Description    string   `json:"description,omitempty"`
}

type Snapshot struct {
	Product       string           `json:"product"`
	Version       string           `json:"version"`
	Mode          string           `json:"mode"`
	Status        string           `json:"status"`
	DataSource    string           `json:"dataSource"`
	PublishLocked bool             `json:"publishLocked"`
	Businesses    []BusinessStatus `json:"businesses"`
	Pools         []PoolStatus     `json:"pools"`
	Interfaces    []ProxyInterface `json:"interfaces"`
	Events        []Event          `json:"events"`
	Draft         PolicyDraft      `json:"draft"`
}
