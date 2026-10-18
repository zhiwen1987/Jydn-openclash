package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/control"
	"chengwang/internal/evidence"
	"chengwang/internal/operation"
	"chengwang/internal/store"
)

type fakeEvidenceVerifier struct {
	report evidence.VerifyReport
	err    error
}

var testManagementScope = authz.ResourceScope{
	TenantID: "tenant-a", SiteID: "site-a", ObjectType: "router", ObjectID: "router-a", Environment: "shadow",
}

type fakeAuthenticator struct{}

func (fakeAuthenticator) AuthenticateAuthorizationValues(values []string, _ time.Time) (authz.Principal, error) {
	if len(values) != 1 || values[0] != "Bearer test-management-token" {
		return authz.Principal{}, errors.New("denied")
	}
	return authz.Principal{
		ID: "admin-id", TenantID: "tenant-a", Roles: []authz.Role{authz.RoleAdmin},
		AllowedScopes: []authz.ResourceScope{testManagementScope},
	}, nil
}

func managementRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer test-management-token")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func (f fakeEvidenceVerifier) Verify() (evidence.VerifyReport, error) {
	report := f.report
	if report.VerifiedAt.IsZero() {
		report.VerifiedAt = time.Now().UTC()
	}
	return report, f.err
}

func (f fakeEvidenceVerifier) Status() evidence.VerifyReport {
	report, _ := f.Verify()
	return report
}

type fakeMihomoReader struct {
	snapshot mihomo.RuntimeSnapshot
	report   mihomo.ReadbackReport
	err      error
}

type countingMihomoReader struct {
	mu       sync.Mutex
	calls    int
	started  chan struct{}
	release  chan struct{}
	snapshot mihomo.RuntimeSnapshot
}

func (f *countingMihomoReader) ReadRuntime(ctx context.Context) (mihomo.RuntimeSnapshot, error) {
	f.mu.Lock()
	f.calls++
	started := f.started
	release := f.release
	f.started = nil
	f.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return mihomo.RuntimeSnapshot{}, ctx.Err()
		}
	}
	return f.snapshot, nil
}

func (f *countingMihomoReader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *countingMihomoReader) startedChannel() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

type countingEvidenceVerifier struct {
	mu          sync.Mutex
	verifyCalls int
	statusCalls int
	report      evidence.VerifyReport
}

func (f *countingEvidenceVerifier) Verify() (evidence.VerifyReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls++
	return f.report, nil
}

func (f *countingEvidenceVerifier) Status() evidence.VerifyReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls++
	return f.report
}

func (f *countingEvidenceVerifier) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyCalls, f.statusCalls
}

func (f fakeMihomoReader) ReadRuntime(context.Context) (mihomo.RuntimeSnapshot, error) {
	return f.snapshot, f.err
}

func testServer(t *testing.T, publish bool, token string) http.Handler {
	t.Helper()
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Mode: "shadow", AdminToken: token, AllowPublish: publish, Versions: versions})
}

func TestSnapshotIsReadOnlyAndPublishLocked(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d", recorder.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &result)
	if result["publishLocked"] != true || result["mode"] != "shadow" {
		t.Fatalf("unsafe snapshot: %v", result)
	}
	if result["status"] != "演示快照 · 未配置 Mihomo 实时读回" {
		t.Fatalf("snapshot falsely claims live data: %v", result["status"])
	}
	if result["dataSource"] != "demo" {
		t.Fatalf("snapshot data source is not explicit: %v", result["dataSource"])
	}
}

func TestPublishFailsClosed(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "secret").ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/publish", bytes.NewBufferString(`{}`)))
	if recorder.Code != http.StatusLocked {
		t.Fatalf("expected locked, got %d", recorder.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if recorder.Header().Get("X-Frame-Options") != "DENY" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers missing: %v", recorder.Header())
	}
}

func TestEvidenceIntegrityReturnsOnlyVerifyReport(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	report := evidence.VerifyReport{
		Valid: true, Count: 3, ExpectedCount: 3,
		LastHash: "abc", ExpectedLastHash: "abc",
	}
	handler := New(Options{
		Mode: "shadow", Versions: versions,
		Evidence: fakeEvidenceVerifier{report: report},
		Authn:    fakeAuthenticator{}, ManagementScope: testManagementScope,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, managementRequest(http.MethodGet, "/api/v1/evidence/integrity", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"valid", "count", "expectedCount", "lastHash", "expectedLastHash", "verifiedAt"} {
		if _, ok := result[key]; !ok {
			t.Fatalf("verify report field %q missing: %v", key, result)
		}
	}
	for key := range result {
		switch key {
		case "valid", "count", "expectedCount", "lastHash", "expectedLastHash", "issue", "verifiedAt":
		default:
			t.Fatalf("integrity endpoint leaked non-report field %q: %v", key, result)
		}
	}
}

func TestEvidenceIntegrityFailsClosedWithoutVerifier(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/evidence/integrity", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != "diagnostic_auth_not_configured" {
		t.Fatalf("unexpected report: %+v", result)
	}
}

func TestEvidenceVerificationFailureDegradesHealthWithoutLeakingError(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{
		Mode: "shadow", Versions: versions,
		Evidence: fakeEvidenceVerifier{err: errors.New("private filesystem detail")},
		Authn:    fakeAuthenticator{}, ManagementScope: testManagementScope,
	})

	integrity := httptest.NewRecorder()
	handler.ServeHTTP(integrity, managementRequest(http.MethodGet, "/api/v1/evidence/integrity", nil))
	if integrity.Code != http.StatusServiceUnavailable || bytes.Contains(integrity.Body.Bytes(), []byte("private")) {
		t.Fatalf("integrity failure was not safely reported: %d %s", integrity.Code, integrity.Body.String())
	}
	var report evidence.VerifyReport
	if err := json.Unmarshal(integrity.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.Issue != "verification_failed" {
		t.Fatalf("unexpected failure report: %+v", report)
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	var result struct {
		Status             string `json:"status"`
		EvidenceConfigured bool   `json:"evidenceConfigured"`
		EvidenceIntegrity  bool   `json:"evidenceIntegrity"`
	}
	if err := json.Unmarshal(health.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "degraded" || !result.EvidenceConfigured || result.EvidenceIntegrity {
		t.Fatalf("health did not degrade: %+v", result)
	}
}

func TestVerifiedEvidenceIsHealthyAndImplementedLocal(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	verifier := fakeEvidenceVerifier{report: evidence.VerifyReport{Valid: true}}
	handler := New(Options{Mode: "shadow", Versions: versions, Evidence: verifier})

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	var healthResult map[string]any
	if err := json.Unmarshal(health.Body.Bytes(), &healthResult); err != nil {
		t.Fatal(err)
	}
	if healthResult["status"] != "ok" || healthResult["evidenceConfigured"] != true || healthResult["evidenceIntegrity"] != true {
		t.Fatalf("verified evidence did not produce healthy status: %v", healthResult)
	}

	capabilities := httptest.NewRecorder()
	handler.ServeHTTP(capabilities, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	var capabilityResult struct {
		Capabilities []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(capabilities.Body.Bytes(), &capabilityResult); err != nil {
		t.Fatal(err)
	}
	if got := stateFor(capabilityResult.Capabilities, "local_evidence_chain"); got != "implemented_local" {
		t.Fatalf("verified evidence capability reported as %q", got)
	}
}

func TestCapabilitiesEndpointIsTruthfulWhenMihomoIsUnconfigured(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		GeneratedAt              string `json:"generatedAt"`
		ProductionControlEnabled bool   `json:"productionControlEnabled"`
		OverallState             string `json:"overallState"`
		Capabilities             []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, result.GeneratedAt); err != nil {
		t.Fatalf("generatedAt is not RFC3339: %q: %v", result.GeneratedAt, err)
	}
	if result.ProductionControlEnabled || result.OverallState != "foundation" {
		t.Fatalf("unsafe capability summary: %+v", result)
	}
	if stateFor(result.Capabilities, "mihomo_runtime_readback") != "blocked" {
		t.Fatalf("unconfigured Mihomo adapter was not blocked: %+v", result.Capabilities)
	}
	for _, id := range []string{"router_publish", "dns_execution", "automatic_repair"} {
		if got := stateFor(result.Capabilities, id); got != "design_only" {
			t.Fatalf("%s falsely reported as %q", id, got)
		}
	}
	if got := stateFor(result.Capabilities, "real_authentication"); got != "blocked" {
		t.Fatalf("unconfigured local authentication reported as %q", got)
	}
}

func TestCapabilitiesEndpointReportsConfiguredMihomoAsReadOnly(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{Mode: "shadow", Versions: versions, Mihomo: fakeMihomoReader{}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	var result struct {
		Capabilities []struct {
			ID       string `json:"id"`
			State    string `json:"state"`
			ReadOnly bool   `json:"readOnly"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Capabilities {
		if item.ID == "mihomo_runtime_readback" {
			if item.State != "live_readonly" || !item.ReadOnly {
				t.Fatalf("configured Mihomo is not explicitly read-only: %+v", item)
			}
			return
		}
	}
	t.Fatal("mihomo_runtime_readback missing")
}

func stateFor(items []struct {
	ID    string `json:"id"`
	State string `json:"state"`
}, id string) string {
	for _, item := range items {
		if item.ID == id {
			return item.State
		}
	}
	return ""
}

func TestProxyInterfacesAreShadowConfiguredAndValid(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/proxy/interfaces", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d", recorder.Code)
	}
	var result struct {
		Mode          string `json:"mode"`
		PublishLocked bool   `json:"publishLocked"`
		Interfaces    []any  `json:"interfaces"`
		Validation    struct {
			Valid bool `json:"valid"`
		} `json:"validation"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Mode != "shadow" || !result.PublishLocked || !result.Validation.Valid || len(result.Interfaces) != 6 {
		t.Fatalf("unexpected proxy interface response: %+v", result)
	}
}

func TestProxyInterfaceValidationRejectsLANWithoutAuth(t *testing.T) {
	body := `[{"id":"lan_http","name":"LAN HTTP","type":"http","core":"Mihomo","listen":"0.0.0.0","port":7890,"udp":false,"lanAccess":true,"authMode":"none","tls":false,"accessScope":"lan","maxConnections":100,"idleTimeoutSec":300,"rateLimitMbps":0,"auditEnabled":true,"enabled":true,"status":"draft","routingProfile":"家庭主网"}]`
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/proxy/interfaces/validate", bytes.NewBufferString(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d", recorder.Code)
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected unauthenticated LAN proxy to fail validation")
	}
}

func TestMihomoStatusFailsClosedWhenUnconfigured(t *testing.T) {
	recorder := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/kernels/mihomo/status", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", recorder.Code)
	}
}

func TestMihomoReadbackReturnsObservedReport(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wantTime := time.Date(2026, 10, 18, 6, 0, 0, 0, time.UTC)
	handler := New(Options{
		Mode:     "shadow",
		Versions: versions,
		Mihomo: fakeMihomoReader{snapshot: mihomo.RuntimeSnapshot{
			ObservedAt: wantTime,
			Proxies:    []mihomo.ProxyState{{Name: "stable_pool", All: []string{"node-01"}}},
			Rules:      []mihomo.RuleState{{Type: "DOMAIN-SUFFIX", Payload: "example.com", Proxy: "DIRECT"}},
		}},
		Authn: fakeAuthenticator{}, ManagementScope: testManagementScope,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, managementRequest(http.MethodPost, "/api/v1/kernels/mihomo/readback", bytes.NewBufferString(validReadbackDraft)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result mihomo.ReadbackReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Match || !result.ObservedAt.Equal(wantTime) {
		t.Fatalf("unexpected report: %+v", result)
	}
}

func TestMihomoReadbackRejectsInvalidDesiredState(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{Mode: "shadow", Versions: versions, Mihomo: fakeMihomoReader{}, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, managementRequest(http.MethodPost, "/api/v1/kernels/mihomo/readback", bytes.NewBufferString(`{"name":""}`)))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestMihomoAuthFailureIsRedacted(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{
		Mode:     "shadow",
		Versions: versions,
		Mihomo:   fakeMihomoReader{err: fmt.Errorf("controller body contained a secret: %w", &mihomo.HTTPError{StatusCode: http.StatusUnauthorized})},
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/kernels/mihomo/status", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("secret")) {
		t.Fatalf("upstream error details leaked: %s", recorder.Body.String())
	}
}

func TestMihomoStatusEndToEndWithController(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"v1.19.0","meta":true}`))
		case "/configs":
			_, _ = w.Write([]byte(`{"mode":"rule","mixed-port":7890}`))
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{"稳定自动":{"type":"URLTest","now":"新加坡-01","all":["香港-01","新加坡-01"]}}}`))
		case "/rules":
			_, _ = w.Write([]byte(`{"rules":[{"type":"DomainSuffix","payload":"example.com","proxy":"稳定自动"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()
	client, err := mihomo.New(controller.URL, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{Mode: "shadow", Versions: versions, Mihomo: client})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/kernels/mihomo/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Configured bool      `json:"configured"`
		Reachable  bool      `json:"reachable"`
		Fresh      bool      `json:"fresh"`
		ObservedAt time.Time `json:"observedAt"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Configured || !result.Reachable || !result.Fresh || result.ObservedAt.IsZero() {
		t.Fatalf("unexpected end-to-end snapshot: %+v", result)
	}
}

func TestAnonymousDiagnosticRoutesFailBeforeSensitiveWork(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reader := &countingMihomoReader{snapshot: mihomo.RuntimeSnapshot{ObservedAt: time.Now().UTC()}}
	handler := New(Options{Mode: "shadow", Versions: versions, Mihomo: reader})
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/v1/versions", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/kernels/mihomo/runtime", nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/kernels/mihomo/readback", bytes.NewBufferString(validReadbackDraft)),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "diagnostic_auth_not_configured") {
			t.Fatalf("anonymous diagnostic route did not fail closed: %s %d %s", request.URL.Path, recorder.Code, recorder.Body.String())
		}
	}
	if got := reader.callCount(); got != 0 {
		t.Fatalf("anonymous protected routes triggered %d Mihomo reads", got)
	}
}

func TestPublicMihomoStatusIsRedactedAndRefreshIsCoalesced(t *testing.T) {
	reader := &countingMihomoReader{
		started: make(chan struct{}), release: make(chan struct{}),
		snapshot: mihomo.RuntimeSnapshot{
			ObservedAt: time.Now().UTC(), Version: mihomo.VersionInfo{Version: "sensitive-version"},
			Config:  mihomo.ConfigSummary{ExternalController: "0.0.0.0:9090"},
			Proxies: []mihomo.ProxyState{{Name: "secret-node"}}, Rules: []mihomo.RuleState{{Payload: "secret.example"}},
		},
	}
	handler := New(Options{Mode: "shadow", Mihomo: reader})
	const requests = 32
	codes := make(chan int, requests)
	bodies := make(chan string, requests)
	for range requests {
		go func() {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/kernels/mihomo/status", nil))
			codes <- recorder.Code
			bodies <- recorder.Body.String()
		}()
	}
	<-reader.startedChannel()
	close(reader.release)
	for range requests {
		code := <-codes
		body := <-bodies
		if code != http.StatusOK && code != http.StatusTooManyRequests {
			t.Fatalf("unexpected admission result %d: %s", code, body)
		}
		for _, secret := range []string{"sensitive-version", "secret-node", "secret.example", "0.0.0.0:9090"} {
			if strings.Contains(body, secret) {
				t.Fatalf("public status leaked %q: %s", secret, body)
			}
		}
		if code == http.StatusOK {
			var fields map[string]any
			if err := json.Unmarshal([]byte(body), &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"version", "config", "proxies", "rules"} {
				if _, exists := fields[key]; exists {
					t.Fatalf("public status leaked field %q: %s", key, body)
				}
			}
		}
	}
	if got := reader.callCount(); got != 1 {
		t.Fatalf("coalesced status made %d upstream reads, want 1", got)
	}
}

func TestBearerOnUntrustedCleartextIsRejectedBeforeAuthenticationOrMihomo(t *testing.T) {
	reader := &countingMihomoReader{snapshot: mihomo.RuntimeSnapshot{ObservedAt: time.Now().UTC()}}
	handler := New(Options{
		Mode: "shadow", Mihomo: reader, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kernels/mihomo/runtime", nil)
	req.RemoteAddr = "192.0.2.44:12345"
	req.Host = "127.0.0.1:7811"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Authorization", "Bearer test-management-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUpgradeRequired || !strings.Contains(recorder.Body.String(), "secure_transport_required") {
		t.Fatalf("cleartext bearer was not rejected: %d %s", recorder.Code, recorder.Body.String())
	}
	if got := reader.callCount(); got != 0 {
		t.Fatalf("rejected bearer triggered %d Mihomo reads", got)
	}
}

func TestPublicHealthUsesCachedEvidenceAndFullVerifyIsProtected(t *testing.T) {
	verifier := &countingEvidenceVerifier{report: evidence.VerifyReport{
		Valid: true, LastHash: strings.Repeat("0", 64), ExpectedLastHash: strings.Repeat("0", 64), VerifiedAt: time.Now().UTC(),
	}}
	handler := New(Options{
		Mode: "shadow", Evidence: verifier, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope,
	})
	for i := 0; i < 20; i++ {
		for _, path := range []string{"/api/v1/health", "/api/v1/capabilities"} {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s returned %d", path, recorder.Code)
			}
		}
	}
	verifyCalls, statusCalls := verifier.counts()
	if verifyCalls != 0 || statusCalls != 40 {
		t.Fatalf("public status performed full scans: verify=%d status=%d", verifyCalls, statusCalls)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, managementRequest(http.MethodGet, "/api/v1/evidence/integrity", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorized full verification failed: %d %s", recorder.Code, recorder.Body.String())
	}
	verifyCalls, _ = verifier.counts()
	if verifyCalls != 1 {
		t.Fatalf("authorized integrity endpoint performed %d scans", verifyCalls)
	}
}

const validReadbackDraft = `{
  "name":"readback",
  "pools":[{"id":"stable_pool","name":"Stable","members":["node-01"]}],
  "businesses":[{
    "id":"example",
    "name":"Example",
    "domains":["example.com"],
    "strategy":"DIRECT",
    "candidates":["DIRECT"],
    "fallback":"DIRECT",
    "skipEmptyPools":true,
    "failuresToSwitch":3,
    "probeIntervalSec":30,
    "sessionStickyMin":30,
    "switchCooldownSec":300
  }],
  "dns":{
    "domesticResolvers":["223.5.5.5"],
    "overseasResolvers":["https://1.1.1.1/dns-query"],
    "hijackPort53":true,
    "leakProtection":true
  }
}`

type operationFixture struct {
	handler    http.Handler
	tokens     map[string]string
	operations *operation.FileStore
	evidence   *evidence.Store
	identities *authn.Store
}

func newOperationFixture(t *testing.T, writes bool) operationFixture {
	t.Helper()
	root := t.TempDir()
	evidenceStore, err := evidence.Open(filepath.Join(root, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = evidenceStore.Close() })
	operationStore, err := operation.NewFileStore(filepath.Join(root, "operations"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = operationStore.Close() })
	scope := authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", ObjectType: "router", ObjectID: "router-a", Environment: "shadow"}
	roles := map[string][]authz.Role{
		"viewer":   {authz.RoleViewer},
		"operator": {authz.RoleOperator},
		"approver": {authz.RoleApprover},
		"admin":    {authz.RoleAdmin},
	}
	config := authn.File{Version: authn.FileVersion}
	tokens := make(map[string]string, len(roles))
	for name, assigned := range roles {
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			t.Fatal(err)
		}
		tokens[name] = token
		config.Identities = append(config.Identities, authn.Identity{
			TokenID: name + "-token", TokenHash: hash,
			Principal: authz.Principal{ID: name + "-id", TenantID: "tenant-a", Roles: assigned, AllowedScopes: []authz.ResourceScope{scope}},
		})
	}
	identityDir := filepath.Join(root, "identities")
	if err := os.Mkdir(identityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(identityDir, "identities.json")
	if err := os.WriteFile(identityPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(identityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(identityPath, 0o600); err != nil {
		t.Fatal(err)
	}
	identityStore, err := authn.Open(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	controlService, err := control.New(operationStore, evidenceStore)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := store.NewVersionStore(filepath.Join(root, "versions"))
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{
		Mode: "shadow", Versions: versions, Evidence: evidenceStore, Authn: identityStore,
		Operations: operationStore, Control: controlService, OperationWritesEnabled: writes, ManagementScope: scope,
	})
	return operationFixture{handler: handler, tokens: tokens, operations: operationStore, evidence: evidenceStore, identities: identityStore}
}

func operationRequest(method, target, body, token, idempotency string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.RemoteAddr = "127.0.0.1:12345"
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	return req
}

const lowOperationBody = `{"resource":{"tenantId":"tenant-a","siteId":"site-a","objectType":"router","objectId":"router-a","environment":"shadow"},"risk":"low","targetVersion":"version-1"}`
const highOperationBody = `{"resource":{"tenantId":"tenant-a","siteId":"site-a","objectType":"router","objectId":"router-a","environment":"shadow"},"risk":"high","targetVersion":"version-2"}`
const operationScopeQuery = "tenantId=tenant-a&siteId=site-a&objectType=router&objectId=router-a&environment=shadow"
const transitionScope = `"resource":{"tenantId":"tenant-a","siteId":"site-a","objectType":"router","objectId":"router-a","environment":"shadow"}`

func TestOperationEndpointsRequireConfiguredAuthenticationAndRejectDuplicateAuthorization(t *testing.T) {
	unconfigured := httptest.NewRecorder()
	testServer(t, false, "").ServeHTTP(unconfigured, httptest.NewRequest(http.MethodGet, "/api/v1/operations?"+operationScopeQuery, nil))
	if unconfigured.Code != http.StatusServiceUnavailable || !bytes.Contains(unconfigured.Body.Bytes(), []byte(localRecordEffect)) {
		t.Fatalf("unconfigured operation endpoint: %d %s", unconfigured.Code, unconfigured.Body.String())
	}

	fixture := newOperationFixture(t, true)
	req := operationRequest(http.MethodGet, "/api/v1/operations?"+operationScopeQuery, "", fixture.tokens["viewer"], "")
	req.Header.Add("Authorization", "Bearer "+fixture.tokens["viewer"])
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate Authorization was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestConfiguredShadowOperationCapabilitiesRemainNonProduction(t *testing.T) {
	fixture := newOperationFixture(t, false)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("capabilities status: %d %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		ProductionControlEnabled bool `json:"productionControlEnabled"`
		Capabilities             []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ProductionControlEnabled || stateFor(result.Capabilities, "real_authentication") != "implemented_local" ||
		stateFor(result.Capabilities, "durable_operation_control") != "implemented_local" {
		t.Fatalf("capability report overstated or omitted local dependencies: %+v", result)
	}
}

func TestOperationPermissionScopeAndForbiddenBodyFields(t *testing.T) {
	fixture := newOperationFixture(t, true)

	viewerCreate := httptest.NewRecorder()
	fixture.handler.ServeHTTP(viewerCreate, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["viewer"], "viewer-create"))
	if viewerCreate.Code != http.StatusForbidden {
		t.Fatalf("viewer create should be forbidden: %d %s", viewerCreate.Code, viewerCreate.Body.String())
	}

	operatorHigh := httptest.NewRecorder()
	fixture.handler.ServeHTTP(operatorHigh, operationRequest(http.MethodPost, "/api/v1/operations", highOperationBody, fixture.tokens["operator"], "operator-high"))
	if operatorHigh.Code != http.StatusForbidden {
		t.Fatalf("operator high-risk create should be forbidden: %d %s", operatorHigh.Code, operatorHigh.Body.String())
	}

	wrongScope := strings.Replace(lowOperationBody, `"tenant-a"`, `"tenant-b"`, 1)
	denied := httptest.NewRecorder()
	fixture.handler.ServeHTTP(denied, operationRequest(http.MethodPost, "/api/v1/operations", wrongScope, fixture.tokens["operator"], "wrong-scope"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create should be forbidden: %d %s", denied.Code, denied.Body.String())
	}

	forbiddenField := strings.TrimSuffix(lowOperationBody, "}") + `,"principal":{"id":"forged"}}`
	invalid := httptest.NewRecorder()
	fixture.handler.ServeHTTP(invalid, operationRequest(http.MethodPost, "/api/v1/operations", forbiddenField, fixture.tokens["operator"], "forged-body"))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("caller-supplied principal was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestOperationCreateListAndIdempotencyUseSummariesOnly(t *testing.T) {
	fixture := newOperationFixture(t, true)
	var first operationEnvelope
	for attempt := 0; attempt < 2; attempt++ {
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "same-create-key"))
		wantStatus := http.StatusCreated
		if attempt == 1 {
			wantStatus = http.StatusOK
		}
		if recorder.Code != wantStatus {
			t.Fatalf("create attempt %d: %d %s", attempt, recorder.Code, recorder.Body.String())
		}
		var response operationEnvelope
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Effect != localRecordEffect || response.DeviceActionsExecuted || response.Operation == nil {
			t.Fatalf("unsafe operation response: %+v", response)
		}
		if attempt == 0 {
			first = response
		} else if response.Operation.ID != first.Operation.ID || response.Created == nil || *response.Created {
			t.Fatalf("idempotent replay created a new operation: first=%+v replay=%+v", first, response)
		}
	}

	list := httptest.NewRecorder()
	fixture.handler.ServeHTTP(list, operationRequest(http.MethodGet, "/api/v1/operations?"+operationScopeQuery, "", fixture.tokens["viewer"], ""))
	if list.Code != http.StatusOK || bytes.Contains(list.Body.Bytes(), []byte(`"events"`)) || bytes.Contains(list.Body.Bytes(), []byte(`"initiatorId"`)) {
		t.Fatalf("list is not a safe summary: %d %s", list.Code, list.Body.String())
	}
}

func TestOperationWriteGateEvidencePreflightAndWriteFailureFailClosed(t *testing.T) {
	locked := newOperationFixture(t, false)
	response := httptest.NewRecorder()
	locked.handler.ServeHTTP(response, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, locked.tokens["operator"], "locked"))
	if response.Code != http.StatusLocked {
		t.Fatalf("write gate did not fail closed: %d %s", response.Code, response.Body.String())
	}
	items, _ := locked.operations.List()
	if len(items) != 0 {
		t.Fatal("disabled write gate mutated operation store")
	}

	fixture := newOperationFixture(t, true)
	versions, _ := store.NewVersionStore(t.TempDir())
	controlService, _ := control.New(fixture.operations, failingEvidenceAppender{})
	badWriteHandler := New(Options{
		Mode: "shadow", Versions: versions, Evidence: fixture.evidence, Authn: fixture.identities,
		Operations: fixture.operations, Control: controlService, OperationWritesEnabled: true,
	})
	failed := httptest.NewRecorder()
	badWriteHandler.ServeHTTP(failed, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "audit-fails"))
	if failed.Code != http.StatusServiceUnavailable || !bytes.Contains(failed.Body.Bytes(), []byte(`"audit_degraded"`)) {
		t.Fatalf("evidence append failure was not explicit: %d %s", failed.Code, failed.Body.String())
	}
	items, _ = fixture.operations.List()
	if len(items) != 0 {
		t.Fatal("pre-evidence failure mutated operation store")
	}

	badIntegrity := New(Options{
		Mode: "shadow", Versions: versions, Evidence: fakeEvidenceVerifier{report: evidence.VerifyReport{Valid: false, Issue: "chain_mismatch"}},
		Authn: fixture.identities, Operations: fixture.operations, Control: controlService, OperationWritesEnabled: true,
	})
	rejected := httptest.NewRecorder()
	badIntegrity.ServeHTTP(rejected, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "bad-chain"))
	if rejected.Code != http.StatusServiceUnavailable || !bytes.Contains(rejected.Body.Bytes(), []byte(`"evidence_integrity_unavailable"`)) {
		t.Fatalf("bad chain did not disable writes: %d %s", rejected.Code, rejected.Body.String())
	}
}

func TestUnauthorizedOperationCannotTriggerFullEvidenceVerification(t *testing.T) {
	fixture := newOperationFixture(t, true)
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	verifier := &countingEvidenceVerifier{report: evidence.VerifyReport{Valid: true, VerifiedAt: time.Now().UTC()}}
	handler := New(Options{
		Mode: "shadow", Versions: versions, Evidence: verifier, Authn: fixture.identities,
		Operations: fixture.operations, Control: mustControl(t, fixture.operations, fixture.evidence),
		OperationWritesEnabled: true,
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["viewer"], "viewer-denied"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer write returned %d: %s", response.Code, response.Body.String())
	}
	verifyCalls, statusCalls := verifier.counts()
	if verifyCalls != 0 || statusCalls != 1 {
		t.Fatalf("operation preflight scans = %d, cached status calls = %d", verifyCalls, statusCalls)
	}
}

func mustControl(t *testing.T, operations *operation.FileStore, evidenceStore *evidence.Store) *control.Service {
	t.Helper()
	service, err := control.New(operations, evidenceStore)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type failingEvidenceAppender struct{}

func (failingEvidenceAppender) AppendOnce(evidence.EvidenceEvent, string) (evidence.EvidenceEvent, bool, error) {
	return evidence.EvidenceEvent{}, false, errors.New("injected evidence failure")
}

func TestOperationTransitionPolicyApprovalAndExecutorLock(t *testing.T) {
	fixture := newOperationFixture(t, true)
	create := httptest.NewRecorder()
	fixture.handler.ServeHTTP(create, operationRequest(http.MethodPost, "/api/v1/operations", highOperationBody, fixture.tokens["admin"], "high-create"))
	if create.Code != http.StatusCreated {
		t.Fatalf("high-risk create failed: %d %s", create.Code, create.Body.String())
	}
	var created operationEnvelope
	_ = json.Unmarshal(create.Body.Bytes(), &created)
	id := created.Operation.ID

	requestApproval := httptest.NewRecorder()
	fixture.handler.ServeHTTP(requestApproval, operationRequest(http.MethodPost, "/api/v1/operations/"+id+"/transitions", `{`+transitionScope+`,"to":"awaiting_approval"}`, fixture.tokens["admin"], "request-approval"))
	if requestApproval.Code != http.StatusOK {
		t.Fatalf("request approval failed: %d %s", requestApproval.Code, requestApproval.Body.String())
	}

	selfApproval := httptest.NewRecorder()
	fixture.handler.ServeHTTP(selfApproval, operationRequest(http.MethodPost, "/api/v1/operations/"+id+"/transitions", `{`+transitionScope+`,"to":"prechecking"}`, fixture.tokens["admin"], "self-approval"))
	if selfApproval.Code != http.StatusForbidden {
		t.Fatalf("self approval was not denied: %d %s", selfApproval.Code, selfApproval.Body.String())
	}

	approve := httptest.NewRecorder()
	fixture.handler.ServeHTTP(approve, operationRequest(http.MethodPost, "/api/v1/operations/"+id+"/transitions", `{`+transitionScope+`,"to":"prechecking"}`, fixture.tokens["approver"], "independent-approval"))
	if approve.Code != http.StatusOK {
		t.Fatalf("independent approval failed: %d %s", approve.Code, approve.Body.String())
	}

	execute := httptest.NewRecorder()
	fixture.handler.ServeHTTP(execute, operationRequest(http.MethodPost, "/api/v1/operations/"+id+"/transitions", `{`+transitionScope+`,"to":"executing"}`, fixture.tokens["admin"], "execute"))
	if execute.Code != http.StatusLocked || !bytes.Contains(execute.Body.Bytes(), []byte(`"executor_not_configured"`)) {
		t.Fatalf("executor stage was not locked: %d %s", execute.Code, execute.Body.String())
	}
}

func TestOperationNotFoundDoesNotRevealCrossScopeExistence(t *testing.T) {
	fixture := newOperationFixture(t, true)
	create := httptest.NewRecorder()
	fixture.handler.ServeHTTP(create, operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "create-visible"))
	var created operationEnvelope
	_ = json.Unmarshal(create.Body.Bytes(), &created)

	missing := httptest.NewRecorder()
	fixture.handler.ServeHTTP(missing, operationRequest(http.MethodPost, "/api/v1/operations/missing/transitions", `{`+transitionScope+`,"to":"prechecking"}`, fixture.tokens["operator"], "missing"))
	wrongObjectScope := strings.Replace(transitionScope, `"router-a"`, `"router-b"`, 1)
	hidden := httptest.NewRecorder()
	fixture.handler.ServeHTTP(hidden, operationRequest(http.MethodPost, "/api/v1/operations/"+created.Operation.ID+"/transitions", `{`+wrongObjectScope+`,"to":"prechecking"}`, fixture.tokens["operator"], "hidden"))
	if missing.Code != http.StatusNotFound || hidden.Code != http.StatusNotFound || missing.Body.String() != hidden.Body.String() {
		t.Fatalf("existence leaked: missing=%d %s hidden=%d %s", missing.Code, missing.Body.String(), hidden.Code, hidden.Body.String())
	}
}

func TestCommitUnknownHTTPResponseDoesNotClaimOperationState(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeControlError(recorder, &control.ServiceError{
		Code: control.CodeCommitUnknown, Stage: "transition", Partial: true,
		Cause: operation.ErrCommitUncertain,
	}, operation.Operation{ID: "stale-operation", Status: operation.StatusPlanned})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("commit unknown status = %d", recorder.Code)
	}
	var response operationEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "commit_unknown" || response.Operation != nil || response.DeviceActionsExecuted || response.Effect != localRecordEffect {
		t.Fatalf("commit unknown response made an unsafe claim: %+v", response)
	}
}

func TestOperationListLimitTotalTruncatedAndStableStoreOrder(t *testing.T) {
	fixture := newOperationFixture(t, true)
	resource := authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", ObjectType: "router", ObjectID: "router-a", Environment: "shadow"}
	scopeRef, err := control.ScopeReference(resource)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < defaultOperationLimit+1; index++ {
		_, created, err := fixture.operations.Create(operation.CreateRequest{
			IdempotencyKey: fmt.Sprintf("list-%03d", index), InitiatorID: "operator-id",
			Environment: "shadow", Scope: scopeRef, TargetVersion: fmt.Sprintf("version-%03d", index), Risk: operation.RiskLow,
		})
		if err != nil || !created {
			t.Fatalf("seed operation %d: created=%v err=%v", index, created, err)
		}
	}
	stored, err := fixture.operations.List()
	if err != nil {
		t.Fatal(err)
	}

	assertList := func(target string, wantLength int, wantTruncated bool) operationListEnvelope {
		t.Helper()
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, operationRequest(http.MethodGet, target, "", fixture.tokens["viewer"], ""))
		if recorder.Code != http.StatusOK {
			t.Fatalf("list status: %d %s", recorder.Code, recorder.Body.String())
		}
		var response operationListEnvelope
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != defaultOperationLimit+1 || len(response.Operations) != wantLength || response.Truncated != wantTruncated || response.DeviceActionsExecuted || response.Effect != localRecordEffect {
			t.Fatalf("unexpected list envelope: %+v", response)
		}
		for index := range response.Operations {
			if response.Operations[index].ID != stored[index].ID {
				t.Fatalf("list order changed at %d: got %q want %q", index, response.Operations[index].ID, stored[index].ID)
			}
		}
		return response
	}
	assertList("/api/v1/operations?"+operationScopeQuery, defaultOperationLimit, true)
	assertList("/api/v1/operations?"+operationScopeQuery+"&limit=2", 2, true)
	assertList("/api/v1/operations?"+operationScopeQuery+"&limit=200", defaultOperationLimit+1, false)

	for _, limit := range []string{"0", "201", "abc", "", "2&limit=3"} {
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, operationRequest(http.MethodGet, "/api/v1/operations?"+operationScopeQuery+"&limit="+limit, "", fixture.tokens["viewer"], ""))
		if recorder.Code != http.StatusBadRequest || !bytes.Contains(recorder.Body.Bytes(), []byte(`"deviceActionsExecuted":false`)) {
			t.Fatalf("invalid limit %q: %d %s", limit, recorder.Code, recorder.Body.String())
		}
	}
}

func TestOperationPOSTRequiresJSONAndDistinguishesOversizedBodies(t *testing.T) {
	fixture := newOperationFixture(t, true)

	unauthenticated := operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, "", "unauth-media")
	unauthenticated.Header.Set("Content-Type", "text/plain")
	unauthenticatedRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("media validation ran before authentication: %d %s", unauthenticatedRecorder.Code, unauthenticatedRecorder.Body.String())
	}

	plain := operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "plain-media")
	plain.Header.Set("Content-Type", "text/plain")
	plainRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(plainRecorder, plain)
	if plainRecorder.Code != http.StatusUnsupportedMediaType || !bytes.Contains(plainRecorder.Body.Bytes(), []byte(`"deviceActionsExecuted":false`)) {
		t.Fatalf("plain body was not rejected safely: %d %s", plainRecorder.Code, plainRecorder.Body.String())
	}

	charset := operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "charset-json")
	charset.Header.Set("Content-Type", "application/json; charset=utf-8")
	charsetRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(charsetRecorder, charset)
	if charsetRecorder.Code != http.StatusCreated {
		t.Fatalf("JSON charset was rejected: %d %s", charsetRecorder.Code, charsetRecorder.Body.String())
	}

	oversizedBody := lowOperationBody + strings.Repeat(" ", maxOperationBodyBytes+1)
	oversized := operationRequest(http.MethodPost, "/api/v1/operations", oversizedBody, fixture.tokens["operator"], "oversized-json")
	oversizedRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(oversizedRecorder, oversized)
	if oversizedRecorder.Code != http.StatusRequestEntityTooLarge || !bytes.Contains(oversizedRecorder.Body.Bytes(), []byte(`"request_body_too_large"`)) {
		t.Fatalf("oversized body response: %d %s", oversizedRecorder.Code, oversizedRecorder.Body.String())
	}

	for name, body := range map[string]string{"empty": "", "multiple": lowOperationBody + `{}`, "unknown": strings.TrimSuffix(lowOperationBody, "}") + `,"traceId":"forged"}`} {
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, operationRequest(http.MethodPost, "/api/v1/operations", body, fixture.tokens["operator"], "invalid-json-"+name))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s body: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func TestOperationWriteGatePrecedesMediaTypeValidation(t *testing.T) {
	fixture := newOperationFixture(t, false)
	req := operationRequest(http.MethodPost, "/api/v1/operations", lowOperationBody, fixture.tokens["operator"], "locked-media")
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusLocked || !bytes.Contains(recorder.Body.Bytes(), []byte(`"operation_writes_disabled"`)) {
		t.Fatalf("write gate priority changed: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestOperationMethodErrorsUseSafeEnvelope(t *testing.T) {
	for _, target := range []string{"/api/v1/operations", "/api/v1/operations/op-unknown/transitions"} {
		recorder := httptest.NewRecorder()
		testServer(t, false, "").ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, target, nil))
		if recorder.Code != http.StatusMethodNotAllowed || !bytes.Contains(recorder.Body.Bytes(), []byte(`"deviceActionsExecuted":false`)) || !bytes.Contains(recorder.Body.Bytes(), []byte(`"effect":"local_record_only"`)) {
			t.Fatalf("unsafe method error for %s: %d %s", target, recorder.Code, recorder.Body.String())
		}
	}
}
