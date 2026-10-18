package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"chengwang/internal/domain"
)

const (
	maxResponseBytes = 8 << 20
	maxProxyEntries  = 20_000
	maxRuleEntries   = 50_000
	maxProxyMembers  = 100_000
)

// HTTPError reports only the upstream status. Controller response bodies are
// deliberately omitted because they may contain configuration details.
type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("mihomo controller returned HTTP %d", e.StatusCode)
}

type VersionInfo struct {
	Version string `json:"version"`
	Meta    bool   `json:"meta"`
	Premium bool   `json:"premium"`
}

type ConfigSummary struct {
	Mode               string `json:"mode"`
	AllowLAN           bool   `json:"allowLan"`
	BindAddress        string `json:"bindAddress"`
	IPv6               bool   `json:"ipv6"`
	Port               int    `json:"port"`
	SocksPort          int    `json:"socksPort"`
	MixedPort          int    `json:"mixedPort"`
	RedirPort          int    `json:"redirPort"`
	TProxyPort         int    `json:"tproxyPort"`
	ExternalController string `json:"externalController"`
}

type ProxyState struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	Now  string   `json:"now,omitempty"`
	All  []string `json:"all,omitempty"`
}

type RuleState struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

type RuntimeSnapshot struct {
	ObservedAt time.Time     `json:"observedAt"`
	Version    VersionInfo   `json:"version"`
	Config     ConfigSummary `json:"config"`
	Proxies    []ProxyState  `json:"proxies"`
	Rules      []RuleState   `json:"rules"`
}

type Drift struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
	Message  string `json:"message"`
}

type ReadbackCounts struct {
	ExpectedGroups int `json:"expectedGroups"`
	ObservedGroups int `json:"observedGroups"`
	ExpectedRules  int `json:"expectedRules"`
	ObservedRules  int `json:"observedRules"`
}

type ReadbackReport struct {
	ObservedAt        time.Time      `json:"observedAt"`
	ControllerVersion string         `json:"controllerVersion"`
	Match             bool           `json:"match"`
	Counts            ReadbackCounts `json:"counts"`
	Drifts            []Drift        `json:"drifts"`
}

// Client is a read-only Mihomo Controller API adapter. It issues GET requests
// only and never calls reload, selector switching, cache deletion or restart
// endpoints.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	token      string
	now        func() time.Time
}

// ClientOptions defines the only supported remote credential boundary.
// AllowedHosts contains exact hostnames that may receive a controller token
// over HTTPS. It never permits non-loopback plaintext HTTP.
type ClientOptions struct {
	AllowedHosts []string
}

func New(rawURL, token string, timeout time.Duration) (*Client, error) {
	return NewWithOptions(rawURL, token, timeout, ClientOptions{})
}

func NewWithOptions(rawURL, token string, timeout time.Duration, options ClientOptions) (*Client, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("mihomo controller URL is empty")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse mihomo controller URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("mihomo controller URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("mihomo controller URL must contain only scheme, host and optional base path")
	}
	if token != "" {
		host := strings.ToLower(parsed.Hostname())
		ip := net.ParseIP(host)
		loopback := ip != nil && ip.IsLoopback()
		if parsed.Scheme == "http" && !loopback {
			return nil, errors.New("mihomo controller token requires HTTPS or a literal loopback IP")
		}
		if !loopback && !allowedControllerHost(host, options.AllowedHosts) {
			return nil, errors.New("mihomo controller host is not in the credential allowlist")
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Controller credentials must never inherit process-wide HTTP(S)_PROXY
	// settings. Operators that need a proxy must design and configure an
	// explicit trusted transport rather than silently exporting a Bearer.
	transport.Proxy = nil
	return &Client{
		baseURL: parsed,
		token:   token,
		now:     time.Now,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func allowedControllerHost(host string, allowed []string) bool {
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSpace(item), host) {
			return true
		}
	}
	return false
}

func (c *Client) ReadRuntime(ctx context.Context) (RuntimeSnapshot, error) {
	var version versionResponse
	var config configResponse
	var proxies proxyResponse
	var rules ruleResponse

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	requests := []struct {
		path string
		dst  any
	}{
		{path: "/version", dst: &version},
		{path: "/configs", dst: &config},
		{path: "/proxies", dst: &proxies},
		{path: "/rules", dst: &rules},
	}

	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	for _, request := range requests {
		request := request
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.getJSON(ctx, request.path, request.dst); err != nil {
				errOnce.Do(func() {
					firstErr = fmt.Errorf("read %s: %w", request.path, err)
					cancel()
				})
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return RuntimeSnapshot{}, firstErr
	}
	if len(proxies.Proxies) > maxProxyEntries {
		return RuntimeSnapshot{}, errors.New("mihomo proxy response exceeds entry limit")
	}
	if len(rules.Rules) > maxRuleEntries {
		return RuntimeSnapshot{}, errors.New("mihomo rule response exceeds entry limit")
	}

	proxyStates := make([]ProxyState, 0, len(proxies.Proxies))
	totalMembers := 0
	for name, proxy := range proxies.Proxies {
		var members []string
		if proxy.All != nil {
			totalMembers += len(proxy.All)
			if totalMembers > maxProxyMembers {
				return RuntimeSnapshot{}, errors.New("mihomo proxy members exceed entry limit")
			}
			members = append([]string{}, proxy.All...)
		}
		proxyStates = append(proxyStates, ProxyState{
			Name: name,
			Type: proxy.Type,
			Now:  proxy.Now,
			All:  members,
		})
	}
	sort.Slice(proxyStates, func(i, j int) bool { return proxyStates[i].Name < proxyStates[j].Name })

	ruleStates := make([]RuleState, 0, len(rules.Rules))
	for _, rule := range rules.Rules {
		ruleStates = append(ruleStates, RuleState{Type: rule.Type, Payload: rule.Payload, Proxy: rule.Proxy})
	}

	return RuntimeSnapshot{
		ObservedAt: c.now().UTC(),
		Version: VersionInfo{
			Version: version.Version,
			Meta:    version.Meta,
			Premium: version.Premium,
		},
		Config: ConfigSummary{
			Mode:               config.Mode,
			AllowLAN:           config.AllowLAN,
			BindAddress:        config.BindAddress,
			IPv6:               config.IPv6,
			Port:               config.Port,
			SocksPort:          config.SocksPort,
			MixedPort:          config.MixedPort,
			RedirPort:          config.RedirPort,
			TProxyPort:         config.TProxyPort,
			ExternalController: config.ExternalController,
		},
		Proxies: proxyStates,
		Rules:   ruleStates,
	}, nil
}

func (c *Client) Readback(ctx context.Context, desired domain.PolicyDraft) (ReadbackReport, error) {
	snapshot, err := c.ReadRuntime(ctx)
	if err != nil {
		return ReadbackReport{}, err
	}
	return Compare(desired, snapshot), nil
}

func (c *Client) getJSON(ctx context.Context, route string, dst any) error {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + "/" + strings.TrimLeft(route, "/")
	endpoint.RawPath = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode}
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(payload) > maxResponseBytes {
		return errors.New("mihomo controller response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode mihomo response: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("mihomo controller returned multiple JSON values")
	}
	return nil
}

type versionResponse struct {
	Version string `json:"version"`
	Meta    bool   `json:"meta"`
	Premium bool   `json:"premium"`
}

type configResponse struct {
	Mode               string `json:"mode"`
	AllowLAN           bool   `json:"allow-lan"`
	BindAddress        string `json:"bind-address"`
	IPv6               bool   `json:"ipv6"`
	Port               int    `json:"port"`
	SocksPort          int    `json:"socks-port"`
	MixedPort          int    `json:"mixed-port"`
	RedirPort          int    `json:"redir-port"`
	TProxyPort         int    `json:"tproxy-port"`
	ExternalController string `json:"external-controller"`
}

type proxyResponse struct {
	Proxies map[string]struct {
		Type string   `json:"type"`
		Now  string   `json:"now"`
		All  []string `json:"all"`
	} `json:"proxies"`
}

type ruleResponse struct {
	Rules []struct {
		Type    string `json:"type"`
		Payload string `json:"payload"`
		Proxy   string `json:"proxy"`
	} `json:"rules"`
}
