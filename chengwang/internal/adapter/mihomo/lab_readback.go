package mihomo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const labReadbackLabel = "private fixed-kernel laboratory projection; not authorization or full payload proof"
const labReadbackDefault = "默认策略"
const labReadbackBusiness = "cw.business."
const labReadbackBodyLimit = 8 << 20
const labReadbackProxyLimit = 392
const labReadbackRuleLimit = 2049
const labReadbackMemberLimit = 66052

var ErrLabReadbackInput = errors.New("laboratory readback input rejected")
var ErrLabReadbackUnavailable = errors.New("laboratory readback unavailable")
var ErrLabReadbackShape = errors.New("laboratory readback shape rejected")
var ErrLabReadbackLimit = errors.New("laboratory readback resource limit reached")

type LabSelectorSpec struct {
	Name    string
	Members []string
}
type LabRuleSpec struct {
	Type    string
	Payload string
	Proxy   string
}

// These declarations are structure, never evidence that an artifact was read,
// admitted, started, authenticated or approved. Derive them from private owned
// rendered input; endpoint/secret/DNS fields are not observable via these GETs.
type LabExpectedSpec struct {
	MixedPort uint16
	HTTPNames []string
	Selectors []LabSelectorSpec
	Rules     []LabRuleSpec
}
type LabExpectation struct{ core *labExpectedCore }
type labExpectedCore struct {
	projection  labProjection
	digest      string
	constructed bool
}
type LabSamples struct{ core *labSamplesCore }
type labSamplesCore struct {
	samples  [2]labSample
	requests int
}
type labSample struct {
	projection         labProjection
	digest, witness    string
	started, completed time.Time
}
type LabReadbackClient struct{ core *labReaderCore }
type labReaderCore struct {
	endpoint, secret string
	timeout          time.Duration
	client           *http.Client
	captureMu        sync.Mutex
	capture          *labEvidenceCore
}

func (LabExpectation) String() string             { return labReadbackLabel }
func (LabExpectation) GoString() string           { return labReadbackLabel }
func (LabExpectation) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labReadbackLabel) }
func (LabExpectation) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"EXPECTED_PROJECTION_NOT_AUTHORIZATION"}`), nil
}
func (p *LabExpectation) UnmarshalJSON([]byte) error {
	if p != nil {
		*p = LabExpectation{}
	}
	return ErrLabReadbackInput
}
func (LabSamples) String() string             { return labReadbackLabel }
func (LabSamples) GoString() string           { return labReadbackLabel }
func (LabSamples) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labReadbackLabel) }
func (LabSamples) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"PRIVATE_NONATOMIC_HTTP_PROJECTION_SAMPLES"}`), nil
}
func (p *LabSamples) UnmarshalJSON([]byte) error {
	if p != nil {
		*p = LabSamples{}
	}
	return ErrLabReadbackInput
}
func (LabReadbackClient) String() string             { return labReadbackLabel }
func (LabReadbackClient) GoString() string           { return labReadbackLabel }
func (LabReadbackClient) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labReadbackLabel) }
func (LabReadbackClient) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"FIXED_LOOPBACK_READONLY_LAB_CLIENT"}`), nil
}
func (p *LabReadbackClient) UnmarshalJSON([]byte) error {
	if p != nil {
		*p = LabReadbackClient{}
	}
	return ErrLabReadbackInput
}

type LabReadbackConclusion string

const (
	LabStableNewProjection LabReadbackConclusion = "STABLE_NEW_PROJECTION"
	LabStableOldProjection LabReadbackConclusion = "STABLE_OLD_PROJECTION"
	LabProjectionAmbiguous LabReadbackConclusion = "AMBIGUOUS"
	LabProjectionDrift     LabReadbackConclusion = "DRIFT"
	LabProjectionUnstable  LabReadbackConclusion = "UNSTABLE"
)

// A conclusion compares HTTP projections only. This DTO intentionally cannot
// grant full-payload, process identity, authorization or data-plane success.
type LabReadbackReport struct {
	Conclusion                LabReadbackConclusion `json:"conclusion"`
	SampleCount               int                   `json:"sampleCount"`
	RequestsObserved          int                   `json:"requestsObserved"`
	PreviousProjectionSHA256  string                `json:"previousProjectionSHA256"`
	CandidateProjectionSHA256 string                `json:"candidateProjectionSHA256"`
	ObservedProjectionSHA256  *string               `json:"observedProjectionSHA256"`
	DataplaneProven           bool                  `json:"dataplaneProven"`
	FullPayloadProven         bool                  `json:"fullPayloadProven"`
	AuthorizationProven       bool                  `json:"authorizationProven"`
	Production                bool                  `json:"production"`
}
type labProjection struct {
	General json.RawMessage      `json:"general"`
	Proxies []labProxyProjection `json:"proxies"`
	Rules   []labRuleProjection  `json:"rules"`
}
type labProxyProjection struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	UDP           bool     `json:"udp"`
	Now           *string  `json:"now"`
	All           []string `json:"all"`
	TestURL       *string  `json:"testUrl"`
	Hidden        *bool    `json:"hidden"`
	Icon          *string  `json:"icon"`
	EmptyFallback *string  `json:"emptyFallback"`
	UOT           bool     `json:"uot"`
	XUDP          bool     `json:"xudp"`
	TFO           bool     `json:"tfo"`
	MPTCP         bool     `json:"mptcp"`
	SMUX          bool     `json:"smux"`
	Interface     string   `json:"interface"`
	RoutingMark   int64    `json:"routing-mark"`
	Provider      string   `json:"provider-name"`
	Dialer        string   `json:"dialer-proxy"`
}
type labRuleProjection struct {
	Index    int    `json:"index"`
	Type     string `json:"type"`
	Payload  string `json:"payload"`
	Proxy    string `json:"proxy"`
	Size     int    `json:"size"`
	Disabled bool   `json:"disabled"`
}

var labBuiltins = map[string]string{"DIRECT": "Direct", "REJECT": "Reject", "REJECT-DROP": "RejectDrop", "COMPATIBLE": "Compatible", "PASS": "Pass", "PASS-RULE": "PassRule"}

// This is a fixed-source candidate, not a captured GET. Primary88dcbf7:
// config.DefaultRawConfig.Stack=TunMips ->parseTun ->LastTunConf ->
// constant.TUNStack.MarshalText/String yields Mips. parseIPV6 clears inet6
// before parseTun because the builder emits ipv6:false. Real CI must confirm.
const labGeneralTemplate = `{"port":0,"socks-port":0,"redir-port":0,"tproxy-port":0,"mixed-port":%d,"tun":{"enable":false,"device":"","stack":"Mips","dns-hijack":["0.0.0.0:53"],"auto-route":true,"auto-detect-interface":true,"inet4-address":["198.18.0.1/30"],"file-descriptor":0,"recvmsgx":true,"processors-per-channel":1},"tuic-server":{"enable":false,"listen":"","certificate":"","private-key":"","ech-key":"","mux-option":{"brutal":{"enabled":false}}},"ss-config":"","vmess-config":"","authentication":null,"skip-auth-prefixes":null,"lan-allowed-ips":["0.0.0.0/0","::/0"],"lan-disallowed-ips":null,"allow-lan":false,"bind-address":"127.0.0.1","inbound-tfo":false,"inbound-mptcp":false,"mode":"rule","unified-delay":false,"log-level":"silent","ipv6":false,"interface-name":"","routing-mark":0,"geox-url":{"geo-ip":"","mmdb":"","asn":"","geo-site":""},"geo-auto-update":false,"geo-update-interval":24,"geodata-mode":false,"geodata-loader":"memconservative","geosite-matcher":"succinct","tcp-concurrent":false,"find-process-mode":"off","sniffing":false,"global-ua":"clash.meta/v1.19.32","etag-support":true,"keep-alive-idle":0,"keep-alive-interval":0,"disable-keep-alive":false}`

func labDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func labCanonical(value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, ErrLabReadbackShape
	}
	return b, nil
}
func labProjectionDigest(p labProjection) (string, error) {
	raw, err := labCanonical(p)
	if err != nil {
		return "", err
	}
	return labDigest(raw), nil
}
func labText(v string, max int) bool {
	return len(v) <= max && utf8.ValidString(v) && strings.TrimSpace(v) == v && !strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}
func labName(v string) bool {
	if v == "" || !labText(v, 268) {
		return false
	}
	for i, r := range v {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && (i == 0 || !strings.ContainsRune("._ -", r)) {
			return false
		}
	}
	return true
}
func labDomain(v string) bool {
	if v == "" || len(v) > 253 || strings.ToLower(v) != v {
		return false
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
func labString(v any, max int) (string, bool) { s, ok := v.(string); return s, ok && labText(s, max) }
func labBool(v any) (bool, bool)              { b, ok := v.(bool); return b, ok }
func labInteger(v any, min, max int64) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil && i >= min && i <= max && strconv.FormatInt(i, 10) == string(n)
}
func labUnsigned(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := strconv.ParseUint(string(n), 10, 64)
	return err == nil && strconv.FormatUint(i, 10) == string(n)
}
func labObject(v any, keys ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, false
		}
	}
	return m, true
}
func labStrings(v any, max int) ([]string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) > max {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		s, ok := labString(v, 4096)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func labJSONToken(d *json.Decoder, depth int) error {
	if depth > 24 {
		return ErrLabReadbackLimit
	}
	t, err := d.Token()
	if err != nil {
		return ErrLabReadbackShape
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return ErrLabReadbackShape
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			k, err := d.Token()
			s, ok := k.(string)
			if err != nil || !ok || seen[s] {
				return ErrLabReadbackShape
			}
			seen[s] = true
		}
		if err := labJSONToken(d, depth+1); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrLabReadbackShape
	}
	return nil
}
func labDecode(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > labReadbackBodyLimit {
		return nil, ErrLabReadbackLimit
	}
	if !utf8.Valid(raw) {
		return nil, ErrLabReadbackShape
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := labJSONToken(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrLabReadbackShape
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return nil, ErrLabReadbackShape
	}
	return value, nil
}
func labGeneral(port uint16) (json.RawMessage, error) {
	v, err := labDecode([]byte(fmt.Sprintf(labGeneralTemplate, port)))
	if err != nil {
		return nil, err
	}
	return labCanonical(v)
}

// Validate all actual types/keys, retaining actual drift values rather than
// filling absent fields with defaults. Only telemetry is intentionally removed.
func labSameShape(actual, template any) bool {
	switch expected := template.(type) {
	case map[string]any:
		m, ok := actual.(map[string]any)
		if !ok || len(m) != len(expected) {
			return false
		}
		for k, t := range expected {
			v, ok := m[k]
			if !ok || !labSameShape(v, t) {
				return false
			}
		}
		return true
	case []any:
		a, ok := actual.([]any)
		if !ok || len(a) > 1024 {
			return false
		}
		for _, v := range a {
			if _, ok := labString(v, 4096); !ok {
				return false
			}
		}
		return true
	case nil:
		if actual == nil {
			return true
		}
		_, ok := labStrings(actual, 1024)
		return ok
	case string:
		_, ok := labString(actual, 4096)
		return ok
	case bool:
		_, ok := labBool(actual)
		return ok
	case json.Number:
		_, ok := labInteger(actual, -1, 1<<31-1)
		return ok
	default:
		return false
	}
}
func labReadGeneral(v any) (json.RawMessage, error) {
	t, err := labDecode([]byte(fmt.Sprintf(labGeneralTemplate, 0)))
	if err != nil || !labSameShape(v, t) {
		return nil, ErrLabReadbackShape
	}
	m := v.(map[string]any)
	for key, values := range map[string][]string{"mode": {"rule", "global", "direct"}, "log-level": {"debug", "info", "warning", "error", "silent"}, "find-process-mode": {"off", "strict", "always"}, "geodata-loader": {"memconservative", "standard"}, "geosite-matcher": {"succinct", "mph"}} {
		valid := false
		for _, allowed := range values {
			valid = valid || m[key] == allowed
		}
		if !valid {
			return nil, ErrLabReadbackShape
		}
	}
	tun := m["tun"].(map[string]any)
	stackOK := false
	for _, stack := range []string{"Mips", "Mixed", "System", "gVisor"} {
		stackOK = stackOK || tun["stack"] == stack
	}
	if !stackOK {
		return nil, ErrLabReadbackShape
	}
	for _, k := range []string{"port", "socks-port", "redir-port", "tproxy-port", "mixed-port"} {
		if _, ok := labInteger(m[k], 0, 65535); !ok {
			return nil, ErrLabReadbackShape
		}
	}
	// Unexpected credential-bearing inbound configuration is outside this
	// reader's subset. Reject before retaining any normalized projection.
	tuic := m["tuic-server"].(map[string]any)
	for _, k := range []string{"certificate", "private-key", "ech-key"} {
		if tuic[k] != "" {
			return nil, ErrLabReadbackShape
		}
	}
	if m["ss-config"] != "" || m["vmess-config"] != "" {
		return nil, ErrLabReadbackShape
	}
	return labCanonical(v)
}

// Inputs must not be concurrently mutated while being copied. Retained state
// is detached after construction. This constructor grants no execution right.
func NewLabExpectation(spec LabExpectedSpec) (LabExpectation, error) {
	if spec.MixedPort < 1024 || spec.HTTPNames == nil || spec.Selectors == nil || spec.Rules == nil || len(spec.HTTPNames) > 128 || len(spec.Selectors) > 257 || len(spec.Rules) < 1 || len(spec.Rules) > labReadbackRuleLimit {
		return LabExpectation{}, ErrLabReadbackInput
	}
	names := map[string]string{}
	for n, t := range labBuiltins {
		names[n] = t
	}
	names["GLOBAL"] = "Selector"
	httpNames := append([]string{}, spec.HTTPNames...)
	sort.Strings(httpNames)
	for _, n := range httpNames {
		if !labName(n) || len(n) > 256 || strings.HasPrefix(n, labReadbackBusiness) || names[n] != "" || n == labReadbackDefault {
			return LabExpectation{}, ErrLabReadbackInput
		}
		names[n] = "Http"
	}
	groups := make([]LabSelectorSpec, 0, len(spec.Selectors))
	foundDefault := false
	for _, g := range spec.Selectors {
		limit := 256
		if strings.HasPrefix(g.Name, labReadbackBusiness) {
			limit = 257
		}
		if !labName(g.Name) || names[g.Name] != "" || g.Members == nil || len(g.Members) < 1 || len(g.Members) > limit {
			return LabExpectation{}, ErrLabReadbackInput
		}
		if g.Name == labReadbackDefault {
			if len(g.Members) != 1 {
				return LabExpectation{}, ErrLabReadbackInput
			}
			foundDefault = true
		}
		names[g.Name] = "Selector"
		groups = append(groups, LabSelectorSpec{Name: g.Name, Members: append([]string{}, g.Members...)})
	}
	if !foundDefault {
		return LabExpectation{}, ErrLabReadbackInput
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	byName := map[string][]string{}
	for _, g := range groups {
		seen := map[string]bool{}
		for _, m := range g.Members {
			if names[m] == "" || m == "GLOBAL" || seen[m] || (labBuiltins[m] != "" && m != "DIRECT" && m != "REJECT") {
				return LabExpectation{}, ErrLabReadbackInput
			}
			seen[m] = true
		}
		byName[g.Name] = g.Members
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(n string) bool {
		if visiting[n] {
			return false
		}
		if done[n] {
			return true
		}
		visiting[n] = true
		for _, m := range byName[n] {
			if names[m] == "Selector" && !visit(m) {
				return false
			}
		}
		visiting[n] = false
		done[n] = true
		return true
	}
	for n := range byName {
		if !visit(n) {
			return LabExpectation{}, ErrLabReadbackInput
		}
	}
	global := []string{"DIRECT", "REJECT"}
	global = append(global, httpNames...)
	for _, g := range groups {
		global = append(global, g.Name)
	}
	byName["GLOBAL"] = global
	var udp func(string) bool
	udp = func(n string) bool {
		if names[n] == "Selector" {
			return udp(byName[n][0])
		}
		return names[n] != "Http"
	}
	p := labProjection{Proxies: make([]labProxyProjection, 0, len(names)), Rules: make([]labRuleProjection, 0, len(spec.Rules))}
	var err error
	p.General, err = labGeneral(spec.MixedPort)
	if err != nil {
		return LabExpectation{}, ErrLabReadbackInput
	}
	total := 0
	for n, t := range names {
		proxy := labProxyProjection{Name: n, Type: t, UDP: udp(n)}
		if t == "Selector" {
			all := byName[n]
			total += len(all)
			if total > labReadbackMemberLimit {
				return LabExpectation{}, ErrLabReadbackLimit
			}
			now, url, icon, fallback, hidden := all[0], "", "", "COMPATIBLE", false
			proxy.Now = &now
			proxy.All = append([]string{}, all...)
			proxy.TestURL = &url
			proxy.Icon = &icon
			proxy.Hidden = &hidden
			proxy.EmptyFallback = &fallback
		}
		p.Proxies = append(p.Proxies, proxy)
	}
	sort.Slice(p.Proxies, func(i, j int) bool { return p.Proxies[i].Name < p.Proxies[j].Name })
	seenDomains := map[string]bool{}
	for i, r := range spec.Rules {
		if i == len(spec.Rules)-1 {
			if r.Type != "Match" || r.Payload != "" || r.Proxy != labReadbackDefault {
				return LabExpectation{}, ErrLabReadbackInput
			}
		} else if r.Type != "DomainSuffix" || !labDomain(r.Payload) || seenDomains[r.Payload] || !strings.HasPrefix(r.Proxy, labReadbackBusiness) || names[r.Proxy] != "Selector" {
			return LabExpectation{}, ErrLabReadbackInput
		}
		seenDomains[r.Payload] = true
		p.Rules = append(p.Rules, labRuleProjection{Index: i, Type: r.Type, Payload: r.Payload, Proxy: r.Proxy, Size: -1})
	}
	hash, err := labProjectionDigest(p)
	if err != nil {
		return LabExpectation{}, err
	}
	return LabExpectation{core: &labExpectedCore{projection: p, digest: hash, constructed: true}}, nil
}

// ProjectionSHA256 returns only structural metadata, never raw values or an
// authorization receipt. Same-package replacement/unsafe code is not a trust
// boundary; public JSON and zero values cannot construct this private core.
func (e *LabExpectation) ProjectionSHA256() (string, error) {
	if e == nil || e.core == nil || !e.core.constructed {
		return "", ErrLabReadbackInput
	}
	hash, err := labProjectionDigest(e.core.projection)
	if err != nil || hash != e.core.digest {
		return "", ErrLabReadbackInput
	}
	return hash, nil
}

func NewLabReadbackClient(controllerPort uint16, secret string, timeout time.Duration) (*LabReadbackClient, error) {
	if controllerPort < 1024 || len(secret) < 32 || len(secret) > 128 {
		return nil, ErrLabReadbackInput
	}
	for _, r := range secret {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' && r != '-' {
			return nil, ErrLabReadbackInput
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 30*time.Second {
		return nil, ErrLabReadbackInput
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: timeout}
	return &LabReadbackClient{core: &labReaderCore{endpoint: "http://127.0.0.1:" + strconv.Itoa(int(controllerPort)), secret: secret, timeout: timeout,
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}}, nil
}
func labContextOK(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v := reflect.ValueOf(ctx)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Slice, reflect.Interface:
		if v.IsNil() {
			return false
		}
	}
	return ctx.Err() == nil
}
func (c *LabReadbackClient) get(ctx context.Context, path string, capture *labEvidenceCore) (value any, failure error) {
	if c == nil || c.core == nil || c.core.client == nil {
		return nil, ErrLabReadbackUnavailable
	}
	if path != "/version" && path != "/configs" && path != "/proxies" && path != "/rules" {
		return nil, ErrLabReadbackInput
	}
	record := capture.begin(path)
	if capture != nil && record == nil {
		return nil, ErrLabReadbackInput
	}
	defer func() {
		if record != nil {
			record.ContextState = labEvidenceContext(ctx)
		}
	}()
	fail := func(code string, err error) (any, error) { labEvidenceTerminal(record, code); return nil, err }
	if !labContextOK(ctx) {
		return fail("CONTEXT", ErrLabReadbackUnavailable)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.core.endpoint+path, nil)
	if err != nil {
		return fail("INPUT", ErrLabReadbackInput)
	}
	req.Close = true
	req.Header.Set("Authorization", "Bearer "+c.core.secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if record != nil {
		record.RequestBuilt = true
	}
	if !labContextOK(ctx) {
		return fail("CONTEXT", ErrLabReadbackUnavailable)
	}
	if record != nil {
		record.DoInvoked = true
	}
	resp, err := c.core.client.Do(req)
	if err != nil {
		labEvidenceTerminal(record, "NETWORK")
	}
	if resp != nil && record != nil {
		if !labEvidenceResponse(record, resp) {
			record.LimitReached = true
			labEvidenceTerminal(record, "LIMIT")
		}
	}
	closed := false
	closeBody := func() error {
		if closed || resp == nil || resp.Body == nil {
			return nil
		}
		closed = true
		if record != nil {
			record.CloseAttempted = true
		}
		err := resp.Body.Close()
		if record != nil {
			code := labEvidenceError(err)
			record.CloseErrorClass = &code
		}
		return err
	}
	defer func() {
		if closeErr := closeBody(); closeErr != nil {
			labEvidenceTerminal(record, "CLOSE")
			if failure == nil {
				value = nil
				failure = ErrLabReadbackUnavailable
			}
		}
	}()
	if err != nil {
		return fail("NETWORK", ErrLabReadbackUnavailable)
	}
	if resp == nil || resp.Body == nil {
		return fail("INTERNAL", ErrLabReadbackUnavailable)
	}
	if record != nil && record.Headers == nil {
		return fail("LIMIT", ErrLabReadbackLimit)
	}
	if resp.StatusCode != 200 || len(resp.Header.Values("Set-Cookie")) != 0 {
		return fail("STATUS", ErrLabReadbackUnavailable)
	}
	if resp.ContentLength > labReadbackBodyLimit {
		if record != nil {
			record.LimitReached = true
		}
		return fail("LIMIT", ErrLabReadbackLimit)
	}
	if resp.ContentLength < -1 || resp.Uncompressed {
		return fail("HEADER", ErrLabReadbackShape)
	}
	ct := resp.Header.Values("Content-Type")
	if len(ct) != 1 {
		return fail("HEADER", ErrLabReadbackShape)
	}
	media, params, err := mime.ParseMediaType(ct[0])
	if err != nil || media != "application/json" || len(params) > 1 {
		return fail("HEADER", ErrLabReadbackShape)
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return fail("HEADER", ErrLabReadbackShape)
		}
	}
	ce := resp.Header.Values("Content-Encoding")
	if len(ce) > 1 || (len(ce) == 1 && ce[0] != "identity") {
		return fail("HEADER", ErrLabReadbackShape)
	}
	if len(resp.TransferEncoding) > 1 || (len(resp.TransferEncoding) == 1 && resp.TransferEncoding[0] != "chunked") {
		return fail("HEADER", ErrLabReadbackShape)
	}
	if record != nil {
		record.ReadAttempted = true
	}
	raw, eof, err := labReadEntity(resp.Body)
	capture.retain(record, raw, eof, err)
	if err != nil {
		return fail("READ", ErrLabReadbackUnavailable)
	}
	if len(raw) > labReadbackBodyLimit {
		return fail("LIMIT", ErrLabReadbackLimit)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != int64(len(raw)) {
		return fail("READ", ErrLabReadbackUnavailable)
	}
	if !labContextOK(ctx) {
		return fail("CONTEXT", ErrLabReadbackUnavailable)
	}
	if closeErr := closeBody(); closeErr != nil {
		return fail("CLOSE", ErrLabReadbackUnavailable)
	}
	if !labContextOK(ctx) {
		return fail("CONTEXT", ErrLabReadbackUnavailable)
	}
	value, err = labDecode(raw)
	if err != nil {
		code := "JSON"
		if record != nil {
			record.ParseState = "JSON_REJECTED"
		}
		if errors.Is(err, ErrLabReadbackLimit) {
			code = "LIMIT"
			if record != nil {
				record.LimitReached = true
			}
		}
		return fail(code, err)
	}
	if record != nil {
		record.ParseState = "JSON_ACCEPTED"
	}
	return value, nil
}
func labTimestamp(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) > 35 {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && t.Year() >= 1 && t.Year() <= 9999
}
func labHistory(v any, nullable bool) bool {
	if v == nil {
		return nullable
	}
	a, ok := v.([]any)
	if !ok || len(a) > 10 {
		return false
	}
	for _, item := range a {
		m, ok := labObject(item, "time", "delay")
		if !ok || !labTimestamp(m["time"]) {
			return false
		}
		if _, ok := labInteger(m["delay"], 0, 65535); !ok {
			return false
		}
	}
	return true
}
func labTelemetry(m map[string]any) bool {
	if _, ok := labBool(m["alive"]); !ok || !labHistory(m["history"], false) {
		return false
	}
	extra, ok := m["extra"].(map[string]any)
	if !ok {
		return false
	}
	for key, value := range extra {
		u, err := url.Parse(key)
		if err != nil || len(key) > 2048 || !labText(key, 2048) || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
		state, ok := labObject(value, "alive", "history")
		if !ok {
			return false
		}
		if _, ok := labBool(state["alive"]); !ok || !labHistory(state["history"], true) {
			return false
		}
	}
	return true
}
func labUUID(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || len(s) != 36 {
		return "", false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", false
			}
		} else if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return s, true
}
func labReadProxies(value any) ([]labProxyProjection, string, error) {
	root, ok := labObject(value, "proxies")
	if !ok {
		return nil, "", ErrLabReadbackShape
	}
	proxies, ok := root["proxies"].(map[string]any)
	if !ok || len(proxies) > labReadbackProxyLimit {
		return nil, "", ErrLabReadbackLimit
	}
	common := []string{"type", "history", "extra", "alive", "name", "udp", "uot", "xudp", "tfo", "mptcp", "smux", "interface", "routing-mark", "provider-name", "dialer-proxy"}
	out := make([]labProxyProjection, 0, len(proxies))
	ids := map[string]string{}
	total := 0
	for name, value := range proxies {
		if !labName(name) {
			return nil, "", ErrLabReadbackShape
		}
		raw, ok := value.(map[string]any)
		if !ok {
			return nil, "", ErrLabReadbackShape
		}
		kind, ok := labString(raw["type"], 32)
		if !ok {
			return nil, "", ErrLabReadbackShape
		}
		keys := append([]string{}, common...)
		if kind == "Selector" {
			keys = append(keys, "now", "all", "testUrl", "hidden", "icon", "emptyFallback")
		} else {
			keys = append(keys, "id")
			if kind != "Http" {
				builtin, exists := labBuiltins[name]
				if !exists || builtin != kind {
					return nil, "", ErrLabReadbackShape
				}
			}
		}
		m, ok := labObject(value, keys...)
		if !ok || m["name"] != name || !labTelemetry(m) {
			return nil, "", ErrLabReadbackShape
		}
		p := labProxyProjection{Name: name, Type: kind}
		booleans := []*bool{&p.UDP, &p.UOT, &p.XUDP, &p.TFO, &p.MPTCP, &p.SMUX}
		for i, k := range []string{"udp", "uot", "xudp", "tfo", "mptcp", "smux"} {
			b, ok := labBool(m[k])
			if !ok {
				return nil, "", ErrLabReadbackShape
			}
			*booleans[i] = b
		}
		var good bool
		p.Interface, good = labString(m["interface"], 256)
		if !good {
			return nil, "", ErrLabReadbackShape
		}
		p.Provider, good = labString(m["provider-name"], 268)
		if !good {
			return nil, "", ErrLabReadbackShape
		}
		p.Dialer, good = labString(m["dialer-proxy"], 268)
		if !good {
			return nil, "", ErrLabReadbackShape
		}
		p.RoutingMark, good = labInteger(m["routing-mark"], -1<<31, 1<<31-1)
		if !good {
			return nil, "", ErrLabReadbackShape
		}
		if kind == "Selector" {
			now, ok := labString(m["now"], 268)
			if !ok || !labName(now) {
				return nil, "", ErrLabReadbackShape
			}
			all, ok := labStrings(m["all"], labReadbackProxyLimit)
			if !ok || len(all) == 0 {
				return nil, "", ErrLabReadbackShape
			}
			total += len(all)
			if total > labReadbackMemberLimit {
				return nil, "", ErrLabReadbackLimit
			}
			seen := map[string]bool{}
			hasNow := false
			for _, member := range all {
				if !labName(member) || seen[member] {
					return nil, "", ErrLabReadbackShape
				}
				seen[member] = true
				hasNow = hasNow || member == now
			}
			if !hasNow {
				return nil, "", ErrLabReadbackShape
			}
			u, ok := labString(m["testUrl"], 2048)
			if !ok {
				return nil, "", ErrLabReadbackShape
			}
			icon, ok := labString(m["icon"], 2048)
			if !ok {
				return nil, "", ErrLabReadbackShape
			}
			fallback, ok := labString(m["emptyFallback"], 268)
			if !ok || !labName(fallback) {
				return nil, "", ErrLabReadbackShape
			}
			hidden, ok := labBool(m["hidden"])
			if !ok {
				return nil, "", ErrLabReadbackShape
			}
			p.Now = &now
			p.All = all
			p.TestURL = &u
			p.Icon = &icon
			p.EmptyFallback = &fallback
			p.Hidden = &hidden
		} else {
			id, ok := labUUID(m["id"])
			if !ok {
				return nil, "", ErrLabReadbackShape
			}
			ids[name] = id
		}
		out = append(out, p)
	}
	for _, p := range out {
		for _, name := range p.All {
			if _, exists := proxies[name]; !exists {
				return nil, "", ErrLabReadbackShape
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	raw, err := labCanonical(ids)
	if err != nil {
		return nil, "", err
	}
	return out, labDigest(raw), nil
}
func labReadRules(value any) ([]labRuleProjection, error) {
	root, ok := labObject(value, "rules")
	if !ok {
		return nil, ErrLabReadbackShape
	}
	rows, ok := root["rules"].([]any)
	if !ok || len(rows) < 1 || len(rows) > labReadbackRuleLimit {
		return nil, ErrLabReadbackLimit
	}
	out := make([]labRuleProjection, 0, len(rows))
	for i, row := range rows {
		m, ok := labObject(row, "index", "type", "payload", "proxy", "size", "extra")
		if !ok {
			return nil, ErrLabReadbackShape
		}
		index, ok := labInteger(m["index"], 0, labReadbackRuleLimit-1)
		if !ok || int(index) != i {
			return nil, ErrLabReadbackShape
		}
		size, ok := labInteger(m["size"], -1, -1)
		if !ok {
			return nil, ErrLabReadbackShape
		}
		kind, ok := labString(m["type"], 32)
		if !ok || (kind != "DomainSuffix" && kind != "Match") {
			return nil, ErrLabReadbackShape
		}
		payload, ok := labString(m["payload"], 253)
		if !ok || (kind == "DomainSuffix" && !labDomain(payload)) || (kind == "Match" && payload != "") {
			return nil, ErrLabReadbackShape
		}
		proxy, ok := labString(m["proxy"], 268)
		if !ok || !labName(proxy) {
			return nil, ErrLabReadbackShape
		}
		extra, ok := labObject(m["extra"], "disabled", "hitCount", "hitAt", "missCount", "missAt")
		if !ok || !labUnsigned(extra["hitCount"]) || !labUnsigned(extra["missCount"]) || !labTimestamp(extra["hitAt"]) || !labTimestamp(extra["missAt"]) {
			return nil, ErrLabReadbackShape
		}
		disabled, ok := labBool(extra["disabled"])
		if !ok {
			return nil, ErrLabReadbackShape
		}
		out = append(out, labRuleProjection{Index: i, Type: kind, Payload: payload, Proxy: proxy, Size: int(size), Disabled: disabled})
	}
	return out, nil
}
func (c *LabReadbackClient) ReadStable(ctx context.Context) (LabSamples, error) {
	if c == nil || c.core == nil || c.core.client == nil || !labContextOK(ctx) {
		return LabSamples{}, ErrLabReadbackUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, c.core.timeout)
	defer cancel()
	return c.readStable(ctx, nil)
}

func (c *LabReadbackClient) readStable(ctx context.Context, capture *labEvidenceCore) (LabSamples, error) {
	core := &labSamplesCore{}
	for round := 0; round < 2; round++ {
		sample := labSample{started: time.Now().UTC()}
		v, err := c.get(ctx, "/version", capture)
		if err != nil {
			return LabSamples{}, err
		}
		core.requests++
		version, ok := labObject(v, "meta", "version")
		if !ok || version["meta"] != true || version["version"] != "v1.19.32" {
			capture.shape(ErrLabReadbackShape)
			return LabSamples{}, ErrLabReadbackShape
		}
		capture.shape(nil)
		v, err = c.get(ctx, "/configs", capture)
		if err != nil {
			return LabSamples{}, err
		}
		core.requests++
		sample.projection.General, err = labReadGeneral(v)
		if err != nil {
			capture.shape(err)
			return LabSamples{}, err
		}
		capture.shape(nil)
		v, err = c.get(ctx, "/proxies", capture)
		if err != nil {
			return LabSamples{}, err
		}
		core.requests++
		sample.projection.Proxies, sample.witness, err = labReadProxies(v)
		if err != nil {
			capture.shape(err)
			return LabSamples{}, err
		}
		capture.shape(nil)
		v, err = c.get(ctx, "/rules", capture)
		if err != nil {
			return LabSamples{}, err
		}
		core.requests++
		sample.projection.Rules, err = labReadRules(v)
		if err != nil {
			capture.shape(err)
			return LabSamples{}, err
		}
		proxyNames := map[string]bool{}
		for _, p := range sample.projection.Proxies {
			proxyNames[p.Name] = true
		}
		for _, r := range sample.projection.Rules {
			if !proxyNames[r.Proxy] {
				capture.shape(ErrLabReadbackShape)
				return LabSamples{}, ErrLabReadbackShape
			}
		}
		capture.shape(nil)
		sample.digest, err = labProjectionDigest(sample.projection)
		if err != nil || !labContextOK(ctx) {
			return LabSamples{}, ErrLabReadbackUnavailable
		}
		sample.completed = time.Now().UTC()
		core.samples[round] = sample
	}
	return LabSamples{core: core}, nil
}
func CompareLabReadback(samples LabSamples, previous, candidate LabExpectation) (LabReadbackReport, error) {
	if samples.core == nil || previous.core == nil || candidate.core == nil || samples.core.requests != 8 {
		return LabReadbackReport{}, ErrLabReadbackInput
	}
	if _, err := previous.ProjectionSHA256(); err != nil {
		return LabReadbackReport{}, err
	}
	if _, err := candidate.ProjectionSHA256(); err != nil {
		return LabReadbackReport{}, err
	}
	r := LabReadbackReport{SampleCount: 2, RequestsObserved: 8, PreviousProjectionSHA256: previous.core.digest, CandidateProjectionSHA256: candidate.core.digest}
	a, b := samples.core.samples[0], samples.core.samples[1]
	for _, s := range []labSample{a, b} {
		hash, err := labProjectionDigest(s.projection)
		if err != nil || hash != s.digest || s.witness == "" || s.started.IsZero() || s.completed.IsZero() {
			return LabReadbackReport{}, ErrLabReadbackInput
		}
	}
	if a.digest != b.digest || a.witness != b.witness || a.completed.Before(a.started) || b.started.Before(a.completed) || b.completed.Before(b.started) {
		r.Conclusion = LabProjectionUnstable
		return r, nil
	}
	hash := b.digest
	r.ObservedProjectionSHA256 = &hash
	switch {
	case hash == previous.core.digest && hash == candidate.core.digest:
		r.Conclusion = LabProjectionAmbiguous
	case hash == candidate.core.digest:
		r.Conclusion = LabStableNewProjection
	case hash == previous.core.digest:
		r.Conclusion = LabStableOldProjection
	default:
		r.Conclusion = LabProjectionDrift
	}
	return r, nil
}
