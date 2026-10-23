package subscription

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"chengwang/internal/probe"
)

const (
	fetchConnectTimeout = 3 * time.Second
	fetchTLSTimeout     = 5 * time.Second
	fetchHeaderTimeout  = 5 * time.Second
	fetchTotalTimeout   = 15 * time.Second
	fetchMaxHeaderBytes = 32 << 10
)

// SourcePolicy is trusted configuration, not a request supplied by a user.
// The exact approved URL can contain a secret query and must remain private.
type SourcePolicy struct {
	Scope         Scope    `json:"scope"`
	SourceID      string   `json:"sourceId"`
	URL           string   `json:"-"`
	AllowedCNAMEs []string `json:"-"`
}

func (SourcePolicy) String() string   { return "subscription source policy" }
func (SourcePolicy) GoString() string { return "subscription source policy" }

// FetchConfig accepts only the complete trusted resolver contract. It has no
// system-resolver fallback, proxy, insecure TLS or private-address option.
type FetchConfig struct {
	Resolver probe.Resolver `json:"-"`
	RootCAs  *x509.CertPool `json:"-"`
}

func (FetchConfig) String() string   { return "subscription fetch configuration" }
func (FetchConfig) GoString() string { return "subscription fetch configuration" }

// FetchResult contains private bytes, not a parsed/admitted/available resource.
type FetchResult struct {
	Scope         Scope     `json:"scope"`
	SourceID      string    `json:"sourceId"`
	AttemptedAt   time.Time `json:"attemptedAt"`
	CompletedAt   time.Time `json:"completedAt"`
	ResponseBytes int       `json:"responseBytes"`
	Content       []byte    `json:"-"`
}

func (FetchResult) String() string   { return "subscription fetched bytes" }
func (FetchResult) GoString() string { return "subscription fetched bytes" }

type Fetcher struct {
	policy     SourcePolicy
	requestURL *url.URL
	target     probe.Target
	resolver   probe.Resolver
	rootCAs    *x509.CertPool
	// Tests in this package may map a validated public pin to a loopback TLS
	// fixture. Production construction never installs this unexported seam.
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func (Fetcher) String() string   { return "subscription fetcher" }
func (Fetcher) GoString() string { return "subscription fetcher" }

func NewFetcher(policy SourcePolicy, config FetchConfig) (*Fetcher, error) {
	if !validScope(policy.Scope) || !validSource(policy.SourceID) || nilFetchResolver(config.Resolver) {
		return nil, fail(CodeFetchPolicy)
	}
	parsed, target, err := validateFetchPolicy(policy)
	if err != nil {
		return nil, err
	}
	policy.AllowedCNAMEs = append([]string(nil), policy.AllowedCNAMEs...)
	var roots *x509.CertPool
	if config.RootCAs != nil {
		roots = config.RootCAs.Clone()
	}
	return &Fetcher{policy: policy, requestURL: parsed, target: target, resolver: config.Resolver, rootCAs: roots}, nil
}

func nilFetchResolver(resolver probe.Resolver) bool {
	if resolver == nil {
		return true
	}
	value := reflect.ValueOf(resolver)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validateFetchPolicy(policy SourcePolicy) (*url.URL, probe.Target, error) {
	invalid := func() (*url.URL, probe.Target, error) { return nil, probe.Target{}, fail(CodeFetchPolicy) }
	if len(policy.URL) == 0 || len(policy.URL) > MaxScalarBytes {
		return invalid()
	}
	for _, value := range []byte(policy.URL) {
		if value <= 0x20 || value >= 0x7f || value == '\\' || value == '#' {
			return invalid()
		}
	}
	parsed, err := url.Parse(policy.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.ForceQuery || parsed.String() != policy.URL {
		return invalid()
	}
	host := parsed.Hostname()
	if parsed.Host != host && parsed.Host != host+":443" {
		return invalid()
	}
	if parsed.RawPath != "" || strings.Contains(parsed.EscapedPath(), "%") || strings.Contains(parsed.Path, "//") {
		return invalid()
	}
	for _, part := range strings.Split(parsed.Path, "/") {
		if part == "." || part == ".." {
			return invalid()
		}
	}
	// Query values are opaque and never decoded or re-encoded. Only canonical
	// printable escapes are allowed; controls/double escapes stay rejected.
	for at := 0; at < len(parsed.RawQuery); at++ {
		if parsed.RawQuery[at] != '%' {
			continue
		}
		if at+2 >= len(parsed.RawQuery) {
			return invalid()
		}
		hi, lo := fetchHex(parsed.RawQuery[at+1]), fetchHex(parsed.RawQuery[at+2])
		if hi < 0 || lo < 0 {
			return invalid()
		}
		value := byte(hi*16 + lo)
		if value <= 0x20 || value >= 0x7f || value == '%' || value == '\\' {
			return invalid()
		}
		at += 2
	}
	// ResolveAndPin's target describes DNS/TLS identity only. Its probe-body
	// budget and path do not replace the independent fetch URL/body limits.
	target := probe.Target{ID: policy.SourceID, PathID: "direct", Kind: probe.ProbeHTTPS,
		Host: host, AllowedCNAMEs: append([]string(nil), policy.AllowedCNAMEs...), Port: 443,
		RequestPath: "/", Method: "GET", ExpectedStatus: []int{200}, IntervalSeconds: 60,
		TimeoutSeconds: 5, TTLSeconds: 60, MaxBodyBytes: 1024}
	if probe.ValidateTarget(target) != nil {
		return invalid()
	}
	return parsed, target, nil
}

func fetchHex(value byte) int {
	if value >= '0' && value <= '9' {
		return int(value - '0')
	}
	if value >= 'A' && value <= 'F' {
		return int(value-'A') + 10
	}
	return -1
}

type fetchResolverObservation struct {
	resolver probe.Resolver
	failed   bool
}

func (resolver *fetchResolverObservation) ResolveHost(ctx context.Context, host string) (probe.DNSResolution, error) {
	snapshot, err := resolver.resolver.ResolveHost(ctx, host)
	resolver.failed = err != nil
	return snapshot, err
}

func (fetcher *Fetcher) transport(resolved probe.ResolvedTarget) *http.Transport {
	var dialed atomic.Bool
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(fetcher.target.Host, "443") ||
				!dialed.CompareAndSwap(false, true) || probe.ValidateResolvedTarget(fetcher.target, resolved) != nil {
				return nil, errors.New("subscription dial rejected")
			}
			connectCtx, cancel := context.WithTimeout(ctx, fetchConnectTimeout)
			defer cancel()
			if fetcher.dialContext != nil {
				return fetcher.dialContext(connectCtx, "tcp", resolved.DialAddress)
			}
			dialer := net.Dialer{Timeout: fetchConnectTimeout, KeepAlive: -1}
			return dialer.DialContext(connectCtx, "tcp", resolved.DialAddress)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: fetcher.target.Host,
			RootCAs: fetcher.rootCAs, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:    fetchTLSTimeout,
		ResponseHeaderTimeout:  fetchHeaderTimeout,
		MaxResponseHeaderBytes: fetchMaxHeaderBytes,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
}

func (fetcher *Fetcher) Fetch(parent context.Context) (FetchResult, error) {
	if fetcher == nil || parent == nil || fetcher.requestURL == nil || nilFetchResolver(fetcher.resolver) {
		return FetchResult{}, fail(CodeFetchPolicy)
	}
	if parent.Err() != nil {
		return FetchResult{}, fail(CodeFetchUnavailable)
	}
	attempted := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, fetchTotalTimeout)
	defer cancel()
	resolver := &fetchResolverObservation{resolver: fetcher.resolver}
	resolved, err := probe.ResolveAndPin(ctx, resolver, fetcher.target)
	if err != nil {
		if resolver.failed || ctx.Err() != nil {
			return FetchResult{}, fail(CodeFetchUnavailable)
		}
		return FetchResult{}, fail(CodeFetchPolicy)
	}
	transport := fetcher.transport(resolved)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: fetchTotalTimeout, CheckRedirect: probe.NoRedirect}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fetcher.requestURL.String(), nil)
	if err != nil {
		return FetchResult{}, fail(CodeFetchPolicy)
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return FetchResult{}, fail(CodeFetchUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		return FetchResult{}, fail(CodeFetchRateLimited)
	}
	if response.StatusCode != http.StatusOK {
		return FetchResult{}, fail(CodeFetchHTTP)
	}
	encodings := response.Header.Values("Content-Encoding")
	if response.Uncompressed || len(encodings) > 1 || (len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity")) ||
		len(response.Header.Values("Set-Cookie")) != 0 {
		return FetchResult{}, fail(CodeFetchHTTP)
	}
	if response.ContentLength > MaxInputBytes {
		return FetchResult{}, fail(CodeInputLimit)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, MaxInputBytes+1))
	if len(content) > MaxInputBytes {
		return FetchResult{}, fail(CodeInputLimit)
	}
	if err != nil || ctx.Err() != nil {
		return FetchResult{}, fail(CodeFetchUnavailable)
	}
	if len(content) == 0 {
		return FetchResult{}, fail(CodeEmpty)
	}
	completed := time.Now().UTC()
	if completed.Before(attempted) {
		return FetchResult{}, fail(CodeFetchUnavailable)
	}
	return FetchResult{Scope: fetcher.policy.Scope, SourceID: fetcher.policy.SourceID, AttemptedAt: attempted,
		CompletedAt: completed, ResponseBytes: len(content), Content: content}, nil
}
