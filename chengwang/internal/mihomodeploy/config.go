// Package mihomodeploy provides isolated laboratory deployment primitives.
// 本切片不是生产发布器，也不代表完整 Clash/业务策略已被实现或验收。
package mihomodeploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"chengwang/internal/domain"
	"go.yaml.in/yaml/v3"
)

const LabConfigScope = "ISOLATED_LOOPBACK_MIHOMO_STATIC_SUBSET_NOT_PRODUCTION"
const MaxLabConfigBytes = 1 << 20
const labDefaultSelector = "默认策略"
const labBusinessPrefix = "cw.business."

// LabHTTPNode has no arbitrary protocol, URL, authentication or YAML extension.
type LabHTTPNode struct {
	ID     string
	Server string
	Port   uint16
}

// LabConfigSpec is private configuration input; do not log or JSON-export it.
type LabConfigSpec struct {
	MixedPort        uint16
	ControllerPort   uint16
	ControllerSecret string
	DefaultTarget    string
	Draft            domain.PolicyDraft
	HTTPNodes        []LabHTTPNode
}

func (LabConfigSpec) String() string   { return "private Mihomo laboratory specification" }
func (LabConfigSpec) GoString() string { return "private Mihomo laboratory specification" }
func (LabConfigSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Scope string `json:"scope"`
	}{LabConfigScope})
}

type LabConfigCode string

const (
	LabConfigInvalid              LabConfigCode = "lab_config_invalid"
	LabConfigDuplicate            LabConfigCode = "lab_config_duplicate_name"
	LabConfigReference            LabConfigCode = "lab_config_missing_reference"
	LabConfigEmptyPool            LabConfigCode = "lab_config_empty_pool"
	LabConfigCycle                LabConfigCode = "lab_config_reference_cycle"
	LabConfigUnsupportedStrategy  LabConfigCode = "lab_config_unsupported_strategy"
	LabConfigUnsupportedDNS       LabConfigCode = "lab_config_unsupported_dns"
	LabConfigExternalRequirements LabConfigCode = "lab_config_external_policy_requirements_unmet"
)

// Blocker paths contain only fixed field labels and numeric indexes, never IDs.
type LabConfigBlocker struct {
	Code LabConfigCode `json:"code"`
	Path string        `json:"path"`
}

type LabConfigError struct {
	Code     LabConfigCode
	blockers []LabConfigBlocker
}

func (*LabConfigError) Error() string { return "Mihomo laboratory configuration rejected" }
func (e *LabConfigError) Blockers() []LabConfigBlocker {
	if e == nil {
		return nil
	}
	return append([]LabConfigBlocker(nil), e.blockers...)
}

// Requirements describe controller obligations; their values stay in the
// original immutable draft digest. There is no evidence-bypass option here.
type LabPolicyRequirement struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type LabConfigDescriptor struct {
	Schema             string                 `json:"schema"`
	Scope              string                 `json:"scope"`
	SHA256             string                 `json:"sha256"`
	Bytes              int                    `json:"bytes"`
	DraftSHA256        string                 `json:"draftSHA256"`
	RequirementsSHA256 string                 `json:"requirementsSHA256"`
	Capabilities       []string               `json:"capabilities"`
	Requirements       []LabPolicyRequirement `json:"requirements"`
	Admissible         bool                   `json:"admissible"`
	Blockers           []LabConfigBlocker     `json:"blockers"`
}

// LabConfigArtifact owns secret YAML. Only Bytes deliberately discloses it to
// the private lifecycle writer; formatters/JSON expose safe metadata alone.
type labConfigArtifactCore struct {
	raw        []byte
	descriptor LabConfigDescriptor
}

// Unsupported fmt verbs may bypass Formatter. A copied wrapper therefore has
// only an opaque pointer, never inline secret YAML or its reversible byte slice.
type LabConfigArtifact struct{ *labConfigArtifactCore }

func (a *LabConfigArtifact) Bytes() []byte {
	if a == nil || a.labConfigArtifactCore == nil {
		return nil
	}
	return append([]byte(nil), a.raw...)
}
func (a *LabConfigArtifact) Descriptor() LabConfigDescriptor {
	if a == nil || a.labConfigArtifactCore == nil {
		return LabConfigDescriptor{}
	}
	d := a.descriptor
	d.Capabilities = append([]string{}, d.Capabilities...)
	d.Requirements = append([]LabPolicyRequirement{}, d.Requirements...)
	d.Blockers = append([]LabConfigBlocker{}, d.Blockers...)
	return d
}

// Value receivers also protect ordinary value copies from fmt reflection of
// the private byte slice. Pointer-only formatters would leak reversible bytes.
func (a LabConfigArtifact) MarshalJSON() ([]byte, error) { return json.Marshal((&a).Descriptor()) }
func (a LabConfigArtifact) String() string               { raw, _ := a.MarshalJSON(); return string(raw) }
func (a LabConfigArtifact) GoString() string             { return a.String() }
func (a LabConfigArtifact) Format(state fmt.State, verb rune) {
	formatLabMetadata(state, verb, a.String())
}
func formatLabMetadata(state fmt.State, verb rune, text string) {
	switch verb {
	case 's', 'q', 'x', 'X':
		_, _ = fmt.Fprintf(state, fmt.FormatString(state, verb), text)
	default:
		_, _ = io.WriteString(state, text)
	}
}

// AdmissionError is mandatory before any lifecycle admission/start. Parsing
// YAML or passing the kernel's -t cannot discharge external policy obligations.
func (a *LabConfigArtifact) AdmissionError() error {
	if a == nil || a.labConfigArtifactCore == nil || len(a.raw) == 0 || len(a.raw) != a.descriptor.Bytes || labConfigHash(a.raw) != a.descriptor.SHA256 {
		return labConfigFailure(LabConfigInvalid, "artifact")
	}
	if !a.descriptor.Admissible || len(a.descriptor.Requirements) != 0 {
		return labConfigFailure(LabConfigExternalRequirements, "policyRequirements")
	}
	return nil
}

var labName = regexp.MustCompile(`^[\pL\pN][\pL\pN._ -]{0,63}$`)
var labSecret = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
var labCapability = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var labDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func labConfigFailure(code LabConfigCode, path string) error {
	return &LabConfigError{Code: code, blockers: []LabConfigBlocker{{Code: code, Path: path}}}
}
func labConfigHash(raw []byte) string {
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}
func labConfigPath(field string, index int, child string) string {
	return field + "[" + strconv.Itoa(index) + "]." + child
}
func labConfigText(value string, maximum int, required bool) bool {
	return utf8.ValidString(value) && len(value) <= maximum && (!required || value != "") && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}
func labConfigReserved(value string) bool {
	// Fixed upstream 88dcbf7 config/config.go:892-897 preinstalls these
	// adapters; :977-989 also constructs GLOBAL. Never shadow their names.
	switch value {
	case "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL":
		return true
	}
	switch domain.Strategy(value) {
	case domain.StrategyDefault, domain.StrategyDirect, domain.StrategyReject, domain.StrategyStable, domain.StrategyAuto, domain.StrategyManual:
		return true
	}
	return strings.HasPrefix(value, labBusinessPrefix)
}
func labConfigID(value string) bool {
	return labName.MatchString(value) && labConfigText(value, 256, true) && !labConfigReserved(value)
}
func labConfigDomain(value string) (string, bool) {
	if !labConfigText(value, 255, true) {
		return "", false
	}
	value = strings.ToLower(strings.TrimPrefix(value, "+."))
	if len(value) == 0 || len(value) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", false
	}
	for _, part := range strings.Split(value, ".") {
		if !labDomainLabel.MatchString(part) {
			return "", false
		}
	}
	return value, true
}
func labConfigCapabilities(values []string) bool {
	if len(values) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !labCapability.MatchString(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

type labProxy struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Server string `yaml:"server"`
	Port   uint16 `yaml:"port"`
}
type labGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}
type labEnabled struct {
	Enable bool `yaml:"enable"`
}
type labProfile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}
type labGeoURLs struct {
	GeoIP   string `yaml:"geoip"`
	GeoSite string `yaml:"geosite"`
	MMDB    string `yaml:"mmdb"`
	ASN     string `yaml:"asn"`
}
type labCors struct {
	AllowOrigins        []string `yaml:"allow-origins"`
	AllowPrivateNetwork bool     `yaml:"allow-private-network"`
}
type labDNS struct {
	Enable            bool     `yaml:"enable"`
	Listen            string   `yaml:"listen"`
	IPv6              bool     `yaml:"ipv6"`
	EnhancedMode      string   `yaml:"enhanced-mode"`
	Nameserver        []string `yaml:"nameserver"`
	DefaultNameserver []string `yaml:"default-nameserver"`
	Fallback          []string `yaml:"fallback"`
}
type labRawConfig struct {
	Port                   uint16     `yaml:"port"`
	SocksPort              uint16     `yaml:"socks-port"`
	RedirPort              uint16     `yaml:"redir-port"`
	TProxyPort             uint16     `yaml:"tproxy-port"`
	MixedPort              uint16     `yaml:"mixed-port"`
	AllowLAN               bool       `yaml:"allow-lan"`
	BindAddress            string     `yaml:"bind-address"`
	Mode                   string     `yaml:"mode"`
	IPv6                   bool       `yaml:"ipv6"`
	LogLevel               string     `yaml:"log-level"`
	FindProcessMode        string     `yaml:"find-process-mode"`
	ExternalController     string     `yaml:"external-controller"`
	ExternalControllerUnix string     `yaml:"external-controller-unix"`
	ExternalControllerPipe string     `yaml:"external-controller-pipe"`
	ExternalControllerTLS  string     `yaml:"external-controller-tls"`
	ExternalControllerCors labCors    `yaml:"external-controller-cors"`
	ExternalUI             string     `yaml:"external-ui"`
	ExternalUIURL          string     `yaml:"external-ui-url"`
	Secret                 string     `yaml:"secret"`
	GeoAutoUpdate          bool       `yaml:"geo-auto-update"`
	GeodataMode            bool       `yaml:"geodata-mode"`
	GeoXURL                labGeoURLs `yaml:"geox-url"`
	DNS                    labDNS     `yaml:"dns"`
	Tun                    labEnabled `yaml:"tun"`
	Sniffer                labEnabled `yaml:"sniffer"`
	NTP                    labEnabled `yaml:"ntp"`
	Profile                labProfile `yaml:"profile"`
	Proxies                []labProxy `yaml:"proxies"`
	Groups                 []labGroup `yaml:"proxy-groups"`
	Rules                  []string   `yaml:"rules"`
}

func renderedLabConfig(mixedPort, controllerPort uint16, secret string, proxies []labProxy, groups []labGroup, rules []string) labRawConfig {
	return labRawConfig{MixedPort: mixedPort, BindAddress: "127.0.0.1", Mode: "rule", LogLevel: "silent", FindProcessMode: "off",
		ExternalController: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(controllerPort))), Secret: secret,
		ExternalControllerCors: labCors{AllowOrigins: []string{}},
		DNS:                    labDNS{EnhancedMode: "redir-host", Nameserver: []string{"127.0.0.1:1"}, DefaultNameserver: []string{"127.0.0.1:1"}, Fallback: []string{}},
		Proxies:                proxies, Groups: groups, Rules: rules}
}

// BuildLabConfig produces full typed YAML, never arbitrary YAML/provider input.
// Ordinary select choices are kernel-expressible. Controller obligations are
// retained as immutable requirements and block admission, rather than silently
// being interpreted as DIRECT. This builder accepts no capability evidence:
// that executor/evidence contract is a later SYS-06 dependency.
//
// Reference parser: MetaCubeX/mihomo commit
// 88dcbf7f1614a67c3b36b848ee3592dfa92ada36 config/config.go. Its parseDNS needs
// a nonempty default-nameserver even when enable=false. The inert loopback
// bootstrap is not an assertion that the OS resolver or all DNS disappears.
// Actual pinned-kernel -t and data-plane tests have NOT run in this builder.
func BuildLabConfig(spec LabConfigSpec) (*LabConfigArtifact, error) {
	if spec.MixedPort < 1024 || spec.ControllerPort < 1024 || spec.MixedPort == spec.ControllerPort || !labSecret.MatchString(spec.ControllerSecret) {
		return nil, labConfigFailure(LabConfigInvalid, "listeners")
	}
	draft := spec.Draft
	if !labConfigText(draft.Name, 160, true) || !labConfigText(draft.Base, 128, false) || len(spec.HTTPNodes) > 128 || len(draft.Pools) > 128 || len(draft.Businesses) > 128 {
		return nil, labConfigFailure(LabConfigInvalid, "draft")
	}
	if len(draft.DNS.DomesticResolvers) != 0 || len(draft.DNS.OverseasResolvers) != 0 || draft.DNS.HijackPort53 || draft.DNS.LeakProtection {
		return nil, labConfigFailure(LabConfigUnsupportedDNS, "dns")
	}
	names := map[string]bool{"DIRECT": true, "REJECT": true, labDefaultSelector: true}
	endpoints := map[string]bool{}
	proxies := make([]labProxy, 0, len(spec.HTTPNodes))
	for i, node := range spec.HTTPNodes {
		path := labConfigPath("httpNodes", i, "definition")
		address, err := netip.ParseAddr(node.Server)
		if !labConfigID(node.ID) || err != nil || !address.Is4() || !address.IsLoopback() || node.Port < 1024 || node.Port == spec.MixedPort || node.Port == spec.ControllerPort {
			return nil, labConfigFailure(LabConfigInvalid, path)
		}
		endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(node.Port)))
		if names[node.ID] || endpoints[endpoint] {
			return nil, labConfigFailure(LabConfigDuplicate, path)
		}
		names[node.ID], endpoints[endpoint] = true, true
		proxies = append(proxies, labProxy{Name: node.ID, Type: "http", Server: address.String(), Port: node.Port})
	}
	for i, pool := range draft.Pools {
		path := labConfigPath("pools", i, "id")
		if !labConfigID(pool.ID) || !labConfigText(pool.Name, 160, false) || !labConfigCapabilities(pool.Capabilities) {
			return nil, labConfigFailure(LabConfigInvalid, path)
		}
		if names[pool.ID] {
			return nil, labConfigFailure(LabConfigDuplicate, path)
		}
		names[pool.ID] = true
	}
	resolve := func(value string, path string) error {
		if value == string(domain.StrategyStable) || value == string(domain.StrategyAuto) || value == string(domain.StrategyManual) {
			return labConfigFailure(LabConfigUnsupportedStrategy, path)
		}
		if !names[value] {
			return labConfigFailure(LabConfigReference, path)
		}
		return nil
	}
	if spec.DefaultTarget == labDefaultSelector {
		return nil, labConfigFailure(LabConfigCycle, "defaultTarget")
	}
	if err := resolve(spec.DefaultTarget, "defaultTarget"); err != nil {
		return nil, err
	}
	groups := []labGroup{{Name: labDefaultSelector, Type: "select", Proxies: []string{spec.DefaultTarget}}}
	requirements := make([]LabPolicyRequirement, 0)
	addRequirement := func(kind, path string) {
		requirements = append(requirements, LabPolicyRequirement{Kind: kind, Path: path})
	}
	for i, pool := range draft.Pools {
		path := labConfigPath("pools", i, "members")
		if len(pool.Members) == 0 {
			return nil, labConfigFailure(LabConfigEmptyPool, path)
		}
		if len(pool.Members) > 256 {
			return nil, labConfigFailure(LabConfigInvalid, path)
		}
		seen := map[string]bool{}
		for _, member := range pool.Members {
			if err := resolve(member, path); err != nil {
				return nil, err
			}
			if seen[member] {
				return nil, labConfigFailure(LabConfigDuplicate, path)
			}
			seen[member] = true
		}
		groups = append(groups, labGroup{Name: pool.ID, Type: "select", Proxies: append([]string{}, pool.Members...)})
		if len(pool.Capabilities) != 0 {
			addRequirement("capability_eligibility", labConfigPath("pools", i, "capabilities"))
		}
	}
	rules := make([]string, 0)
	seenBusiness, seenDomain := map[string]bool{}, map[string]bool{}
	for i, business := range draft.Businesses {
		path := labConfigPath("businesses", i, "definition")
		if !labName.MatchString(business.ID) || !labConfigText(business.ID, 256, true) || !labConfigText(business.Name, 160, false) || len(business.Domains) == 0 || len(business.Domains) > 64 || len(business.Candidates) > 256 || !labConfigCapabilities(business.RequireCapabilities) {
			return nil, labConfigFailure(LabConfigInvalid, path)
		}
		selector := labBusinessPrefix + business.ID
		if seenBusiness[business.ID] || names[selector] {
			return nil, labConfigFailure(LabConfigDuplicate, path)
		}
		seenBusiness[business.ID] = true
		choices := []string{business.Strategy}
		selected := map[string]bool{business.Strategy: true}
		candidateSeen := map[string]bool{}
		for _, candidate := range business.Candidates {
			if candidateSeen[candidate] {
				return nil, labConfigFailure(LabConfigDuplicate, labConfigPath("businesses", i, "candidates"))
			}
			candidateSeen[candidate] = true
			if !selected[candidate] {
				choices = append(choices, candidate)
				selected[candidate] = true
			}
		}
		for _, choice := range choices {
			if err := resolve(choice, labConfigPath("businesses", i, "strategy")); err != nil {
				return nil, err
			}
		}
		groups = append(groups, labGroup{Name: selector, Type: "select", Proxies: choices})
		for _, value := range business.Domains {
			name, ok := labConfigDomain(value)
			if !ok {
				return nil, labConfigFailure(LabConfigInvalid, labConfigPath("businesses", i, "domains"))
			}
			if seenDomain[name] {
				return nil, labConfigFailure(LabConfigDuplicate, labConfigPath("businesses", i, "domains"))
			}
			seenDomain[name] = true
			if len(rules) >= 2048 {
				return nil, labConfigFailure(LabConfigInvalid, "rules")
			}
			rules = append(rules, "DOMAIN-SUFFIX,"+name+","+selector)
		}
		if business.Fallback != "" {
			if business.Fallback != "previous_stable" {
				if err := resolve(business.Fallback, labConfigPath("businesses", i, "fallback")); err != nil {
					return nil, err
				}
			}
			addRequirement("fallback_policy", labConfigPath("businesses", i, "fallback"))
		}
		if business.SkipEmptyPools {
			addRequirement("skip_empty_pool_policy", labConfigPath("businesses", i, "skipEmptyPools"))
		}
		if business.FailuresToSwitch < 0 || business.FailuresToSwitch > 10 || business.ProbeIntervalSec < 0 || business.ProbeIntervalSec > 2147483647 || business.SessionStickyMin < 0 || business.SessionStickyMin > 2147483647 || business.SwitchCooldownSec < 0 || business.SwitchCooldownSec > 2147483647 {
			return nil, labConfigFailure(LabConfigInvalid, path)
		}
		for _, item := range []struct {
			value       int
			kind, field string
		}{
			{business.FailuresToSwitch, "failure_threshold_policy", "failuresToSwitch"}, {business.ProbeIntervalSec, "probe_schedule_policy", "probeIntervalSec"},
			{business.SessionStickyMin, "session_stickiness_policy", "sessionStickyMin"}, {business.SwitchCooldownSec, "switch_cooldown_policy", "switchCooldownSec"},
		} {
			if item.value != 0 {
				addRequirement(item.kind, labConfigPath("businesses", i, item.field))
			}
		}
		if len(business.RequireCapabilities) != 0 {
			addRequirement("capability_eligibility", labConfigPath("businesses", i, "requireCapabilities"))
		}
	}
	graph := make(map[string][]string, len(groups))
	for _, group := range groups {
		if _, exists := graph[group.Name]; exists {
			return nil, labConfigFailure(LabConfigDuplicate, "selectors")
		}
		graph[group.Name] = group.Proxies
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(name string) bool {
		if visiting[name] {
			return false
		}
		if visited[name] {
			return true
		}
		visiting[name] = true
		for _, child := range graph[name] {
			if _, isGroup := graph[child]; isGroup && !visit(child) {
				return false
			}
		}
		visiting[name], visited[name] = false, true
		return true
	}
	for name := range graph {
		if !visit(name) {
			return nil, labConfigFailure(LabConfigCycle, "selectors")
		}
	}
	sort.Slice(proxies, func(i, j int) bool { return proxies[i].Name < proxies[j].Name })
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	rules = append(rules, "MATCH,"+labDefaultSelector)
	config := renderedLabConfig(spec.MixedPort, spec.ControllerPort, spec.ControllerSecret, proxies, groups, rules)
	raw, err := yaml.Marshal(config)
	if err != nil || len(raw) == 0 || len(raw) > MaxLabConfigBytes {
		return nil, labConfigFailure(LabConfigInvalid, "artifact")
	}
	draftRaw, err := json.Marshal(draft)
	if err != nil {
		return nil, labConfigFailure(LabConfigInvalid, "draft")
	}
	draftHash := labConfigHash(draftRaw)
	requirementRaw, err := json.Marshal(struct {
		Schema       string                 `json:"schema"`
		Draft        string                 `json:"draftSHA256"`
		Requirements []LabPolicyRequirement `json:"requirements"`
	}{"chengwang.lab-policy-requirements/v1", draftHash, requirements})
	if err != nil {
		return nil, labConfigFailure(LabConfigInvalid, "requirements")
	}
	blockers := make([]LabConfigBlocker, 0)
	if len(requirements) != 0 {
		blockers = append(blockers, LabConfigBlocker{Code: LabConfigExternalRequirements, Path: "policyRequirements"})
	}
	descriptor := LabConfigDescriptor{Schema: "chengwang.mihomo-lab-config/v1", Scope: LabConfigScope, SHA256: labConfigHash(raw), Bytes: len(raw),
		DraftSHA256: draftHash, RequirementsSHA256: labConfigHash(requirementRaw),
		Capabilities: []string{"static_domain_suffix_rules", "explicit_selectors", "loopback_http_nodes", "private_loopback_controller", "built_in_dns_disabled"},
		Requirements: requirements, Admissible: len(blockers) == 0, Blockers: blockers}
	return &LabConfigArtifact{labConfigArtifactCore: &labConfigArtifactCore{raw: append([]byte(nil), raw...), descriptor: descriptor}}, nil
}
