package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"chengwang/internal/probeview"
)

type probeReadAPIFixture struct {
	status                   probeview.Status
	detail                   probeview.Details
	statusCalls, detailCalls int
}

func (p *probeReadAPIFixture) Status() probeview.Status   { p.statusCalls++; return p.status }
func (p *probeReadAPIFixture) Details() probeview.Details { p.detailCalls++; return p.detail }

func probeAPIReader(t *testing.T) *probeReadAPIFixture {
	t.Helper()
	p := &probeReadAPIFixture{status: probeview.DisabledStatus()}
	raw := `{"schema":"chengwang.probe-view-details/v1","catalogDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","agentId":"fixture-agent","independence":"P1","advisoryOnly":true,"targets":[{"probeId":"business-a","pathId":"path-a","state":"unknown","reason":"no_current_evidence"}],"samples":[]}`
	if json.Unmarshal([]byte(raw), &p.detail) != nil {
		t.Fatal("invalid safe DTO fixture")
	}
	p.detail.Status = p.status
	return p
}

func TestProbeReadAPIAnonymousStatusIsMinimalCacheOnly(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probes/status", nil))
	if w.Code != 200 || p.statusCalls != 1 || p.detailCalls != 0 {
		t.Fatal("anonymous status accessed details")
	}
	var value map[string]any
	if json.Unmarshal(w.Body.Bytes(), &value) != nil {
		t.Fatal("invalid status JSON")
	}
	for _, key := range []string{"catalogDigest", "agentId", "probeId", "pathId", "runId", "targets", "samples", "url", "file"} {
		if _, ok := value[key]; ok {
			t.Fatal("anonymous status exposed identity or detail")
		}
	}
	if strings.Contains(w.Body.String(), "business-a") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("anonymous cache projection leaked")
	}
}

func TestProbeReadAPIDisabledStatusAndProtectedDetails(t *testing.T) {
	h := New(Options{Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probes/status", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"configured":false`) || !strings.Contains(w.Body.String(), `"state":"disabled"`) {
		t.Fatal("disabled status not explicit")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, managementRequest(http.MethodGet, "/api/v1/probes/details", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"probe_not_configured"`) {
		t.Fatal("disabled details not fixed unavailable")
	}
}

func TestProbeReadAPIUnauthorizedDoesNotReadDetails(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	for _, values := range [][]string{nil, {"Bearer wrong"}, {"Bearer test-management-token", "Bearer test-management-token"}} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/probes/details", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		for _, value := range values {
			r.Header.Add("Authorization", value)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 || p.detailCalls != 0 || p.statusCalls != 0 {
			t.Fatal("unauthorized request accessed cache")
		}
	}
}

func TestProbeReadAPIPlaintextCredentialsFailBeforeDetails(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	r := managementRequest(http.MethodGet, "/api/v1/probes/details", nil)
	r.RemoteAddr = "10.88.0.20:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUpgradeRequired || p.detailCalls != 0 {
		t.Fatal("plaintext credentials reached details")
	}
}

func TestProbeReadAPICrossScopeFailsBeforeDetails(t *testing.T) {
	p := probeAPIReader(t)
	scope := testManagementScope
	scope.SiteID = "other-site"
	h := New(Options{Probes: p, Authn: fakeAuthenticator{}, ManagementScope: scope})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, managementRequest(http.MethodGet, "/api/v1/probes/details", nil))
	if w.Code != 403 || p.detailCalls != 0 {
		t.Fatal("cross-scope request reached details")
	}
}

func TestProbeReadAPIReadResourceReturnsBoundedSafeDetails(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, managementRequest(http.MethodGet, "/api/v1/probes/details", nil))
	if w.Code != 200 || p.detailCalls != 1 || p.statusCalls != 0 || !strings.Contains(w.Body.String(), "business-a") {
		t.Fatal("authorized details not returned")
	}
	for _, forbidden := range []string{`"url"`, `"host"`, `"requestPath"`, `"body"`, `"header"`, `"evidenceRef"`, `"stageTimings"`, `"file"`} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("unsafe detail field serialized")
		}
	}
}

func TestProbeReadAPIMethodsAndQueriesNeverTriggerReads(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	for _, request := range []*http.Request{httptest.NewRequest(http.MethodPost, "/api/v1/probes/status", nil), httptest.NewRequest(http.MethodGet, "/api/v1/probes/status?refresh=true", nil), managementRequest(http.MethodPost, "/api/v1/probes/details", nil), managementRequest(http.MethodGet, "/api/v1/probes/details?path=sentinel-private", nil)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request)
		if (w.Code != 400 && w.Code != 405) || p.detailCalls != 0 || p.statusCalls != 0 || strings.Contains(w.Body.String(), "sentinel-private") {
			t.Fatal("unsupported request triggered a cache read or reflected query")
		}
	}
}

func TestProbeReadAPIRejectsOversizedProjectionWithoutPartialSuccess(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})
	for _, raw := range []string{
		`{"targets":[` + strings.Repeat(`{},`, 256) + `{}],"samples":[]}`,
		`{"targets":[],"samples":[` + strings.Repeat(`{},`, 200) + `{}]}`,
		`{"targets":[{"reason":"` + strings.Repeat("sentinel-private-", 1<<17) + `"}],"samples":[]}`,
	} {
		if json.Unmarshal([]byte(raw), &p.detail) != nil {
			t.Fatal("invalid oversized fixture")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, managementRequest(http.MethodGet, "/api/v1/probes/details", nil))
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"probe_projection_invalid"`) || strings.Contains(w.Body.String(), `"targets"`) || strings.Contains(w.Body.String(), "sentinel-private") {
			t.Fatal("oversized projection partially exposed")
		}
	}
}

func TestProbeReadAPIMissingIdentityPrecedesDisabledAndQueryChecks(t *testing.T) {
	h := New(Options{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probes/details?refresh=true", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"diagnostic_auth_not_configured"`) {
		t.Fatal("probe route bypassed management preflight")
	}
}

func TestProbeReadAPILegacyObservationAndWriteGatesRemainDisabled(t *testing.T) {
	p := probeAPIReader(t)
	h := New(Options{Probes: p})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/observations/status", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"mode":"disabled"`) || p.statusCalls != 0 || p.detailCalls != 0 {
		t.Fatal("probe injection changed passive observation semantics")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/probes/details", nil))
	if w.Code != 503 || p.detailCalls != 0 {
		t.Fatal("probe route opened a write or bypassed identity")
	}
}
