package routing

import "net/netip"

type Layer int

const (
	LayerSafety Layer = iota + 1
	LayerCustomBusiness
	LayerDomestic
	LayerOverseasBusiness
	LayerRegionNetwork
	LayerFallback
)

type Operator string

const (
	MatchAny Operator = "any"
	MatchAll Operator = "all"
)

type ConditionType string

const (
	DomainExact     ConditionType = "domain_exact"
	DomainSuffix    ConditionType = "domain_suffix"
	DomainKeyword   ConditionType = "domain_keyword"
	GeoSite         ConditionType = "geosite"
	IPCIDR          ConditionType = "ip_cidr"
	GeoIP           ConditionType = "geoip"
	ASN             ConditionType = "asn"
	SourceIP        ConditionType = "source_ip"
	SourceDevice    ConditionType = "source_device"
	DestinationPort ConditionType = "destination_port"
	Network         ConditionType = "network"
	Process         ConditionType = "process"
)

type Condition struct {
	Type  ConditionType `json:"type"`
	Value string        `json:"value"`
	Not   bool          `json:"not,omitempty"`
}

type ConditionGroup struct {
	Operator   Operator    `json:"operator"`
	Conditions []Condition `json:"conditions"`
}

type Action struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type Rule struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Layer    Layer            `json:"layer"`
	Priority int              `json:"priority"`
	Enabled  bool             `json:"enabled"`
	Groups   []ConditionGroup `json:"groups"`
	Action   Action           `json:"action"`
}

type Traffic struct {
	SourceIP      netip.Addr `json:"-"`
	SourceDevice  string     `json:"sourceDevice"`
	DestinationIP netip.Addr `json:"-"`
	Domain        string     `json:"domain"`
	Port          uint16     `json:"port"`
	Network       string     `json:"network"`
	Process       string     `json:"process"`
}

type Evidence struct {
	RuleID    string   `json:"ruleId"`
	RuleName  string   `json:"ruleName"`
	Layer     Layer    `json:"layer"`
	MatchedBy []string `json:"matchedBy"`
	Action    Action   `json:"action"`
}

type Decision struct {
	Matched  bool     `json:"matched"`
	Action   Action   `json:"action"`
	Evidence Evidence `json:"evidence"`
}

type SetResolver interface {
	InGeoSite(set, domain string) bool
	InGeoIP(country string, ip netip.Addr) bool
	InASN(asn string, ip netip.Addr) bool
}
