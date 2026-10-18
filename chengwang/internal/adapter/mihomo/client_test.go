package mihomo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/internal/domain"
)

func TestReadRuntimeUsesAuthenticatedGETOnly(t *testing.T) {
	var mu sync.Mutex
	paths := make(map[string]int)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unsafe method %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer controller-secret" {
			t.Fatalf("authorization header missing")
		}
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"v1.19.0","meta":true}`))
		case "/configs":
			_, _ = w.Write([]byte(`{"mode":"rule","allow-lan":true,"bind-address":"*","ipv6":false,"mixed-port":7890,"external-controller":"127.0.0.1:9090"}`))
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{"chatgpt_pool":{"type":"Selector","now":"美国-01","all":["美国-01","日本-01"]}}}`))
		case "/rules":
			_, _ = w.Write([]byte(`{"rules":[{"type":"DomainSuffix","payload":"chatgpt.com","proxy":"chatgpt_pool"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()

	client, err := New(controller.URL, "controller-secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC) }
	snapshot, err := client.ReadRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version.Version != "v1.19.0" || snapshot.Config.Mode != "rule" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if len(snapshot.Proxies) != 1 || snapshot.Proxies[0].Name != "chatgpt_pool" || len(snapshot.Rules) != 1 {
		t.Fatalf("runtime data missing: %+v", snapshot)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/version", "/configs", "/proxies", "/rules"} {
		if paths[path] != 1 {
			t.Fatalf("path %s called %d times", path, paths[path])
		}
	}
}

func TestControllerRedirectIsNotFollowed(t *testing.T) {
	redirectReached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectReached = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer controller.Close()

	client, err := New(controller.URL, "must-not-leak", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.getJSON(context.Background(), "/version", &versionResponse{})
	var upstream *HTTPError
	if !errors.As(err, &upstream) || upstream.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect status error, got %v", err)
	}
	if redirectReached {
		t.Fatal("redirect was followed and could leak the controller token")
	}
}

func TestControllerTokenRejectsNonLoopbackPlaintextAndRequiresRemoteAllowlist(t *testing.T) {
	if _, err := New("http://192.0.2.10:9090", "secret", time.Second); err == nil {
		t.Fatal("controller token was allowed over non-loopback plaintext HTTP")
	}
	if _, err := New("http://localhost:9090", "secret", time.Second); err == nil {
		t.Fatal("hostname-based loopback was accepted for plaintext credentials")
	}
	if _, err := New("https://controller.example", "secret", time.Second); err == nil {
		t.Fatal("remote controller token was allowed without an origin allowlist")
	}
	if _, err := NewWithOptions("https://controller.example", "secret", time.Second, ClientOptions{AllowedHosts: []string{"controller.example"}}); err != nil {
		t.Fatalf("explicit HTTPS controller allowlist was rejected: %v", err)
	}
}

func TestControllerTransportIgnoresEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		http.Error(w, "proxy must not receive controller traffic", http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"v1"}`))
		case "/configs":
			_, _ = w.Write([]byte(`{}`))
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{}}`))
		case "/rules":
			_, _ = w.Write([]byte(`{"rules":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()
	client, err := New(controller.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxyCalls.Load() != 0 {
		t.Fatalf("environment proxy received %d controller requests", proxyCalls.Load())
	}
}

func TestCompareReportsExactMatch(t *testing.T) {
	desired := domain.PolicyDraft{
		Pools:      []domain.NodePool{{ID: "chatgpt_pool", Members: []string{"美国-01", "日本-01"}}},
		Businesses: []domain.BusinessPolicy{{ID: "chatgpt", Strategy: "chatgpt_pool", Domains: []string{"chatgpt.com"}}},
	}
	actual := RuntimeSnapshot{
		ObservedAt: time.Now().UTC(),
		Version:    VersionInfo{Version: "v1.19.0"},
		Proxies:    []ProxyState{{Name: "chatgpt_pool", All: []string{"美国-01", "日本-01"}}},
		Rules:      []RuleState{{Type: "DOMAIN-SUFFIX", Payload: "chatgpt.com", Proxy: "chatgpt_pool"}},
	}
	report := Compare(desired, actual)
	if !report.Match || len(report.Drifts) != 0 {
		t.Fatalf("expected exact match, got %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("report did not encode")
	}
}

func TestCompareReportsGroupAndRuleDrift(t *testing.T) {
	desired := domain.PolicyDraft{
		Pools: []domain.NodePool{
			{ID: "chatgpt_pool", Members: []string{"美国-01", "日本-01"}},
			{ID: "missing_pool", Members: []string{"新加坡-01"}},
		},
		Businesses: []domain.BusinessPolicy{
			{ID: "chatgpt", Strategy: "chatgpt_pool", Domains: []string{"chatgpt.com", "openai.com"}},
		},
	}
	actual := RuntimeSnapshot{
		Proxies: []ProxyState{{Name: "chatgpt_pool", All: []string{"日本-01", "美国-01"}}},
		Rules:   []RuleState{{Type: "DomainSuffix", Payload: "chatgpt.com", Proxy: "DIRECT"}},
	}
	report := Compare(desired, actual)
	if report.Match || len(report.Drifts) != 4 {
		t.Fatalf("expected four drifts, got %+v", report)
	}
	want := map[string]bool{
		"group_members_mismatch": false,
		"missing_proxy_group":    false,
		"rule_target_mismatch":   false,
		"missing_domain_rule":    false,
	}
	for _, drift := range report.Drifts {
		want[drift.Kind] = true
	}
	for kind, found := range want {
		if !found {
			t.Fatalf("missing drift kind %s: %+v", kind, report.Drifts)
		}
	}
}

func TestNewRejectsCredentialBearingURL(t *testing.T) {
	if _, err := New("http://user:password@127.0.0.1:9090", "", time.Second); err == nil {
		t.Fatal("expected credential-bearing URL to be rejected")
	}
}
