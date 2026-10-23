package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"chengwang/internal/capability"
	"chengwang/internal/probeview"
)

type probeCapabilityNoRead struct{}

func (probeCapabilityNoRead) Status() probeview.Status {
	panic("capability inventory must not read probe status")
}
func (probeCapabilityNoRead) Details() probeview.Details {
	panic("capability inventory must not read protected probe details")
}

func probeCapabilityResponse(t *testing.T, handler http.Handler) (capability.Report, capability.Item, string) {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("anonymous capability inventory response failed")
	}
	var report capability.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal("invalid capability report")
	}
	if report.ProductionControlEnabled || report.OverallState != "foundation" {
		t.Fatal("capability inventory escalated production readiness")
	}
	for _, item := range report.Capabilities {
		if item.ID == "probe_evidence_readback" {
			return report, item, w.Body.String()
		}
	}
	t.Fatal("probe readback capability missing")
	return report, capability.Item{}, ""
}

func TestProbeCapabilitiesAPIUnconfiguredIsBlocked(t *testing.T) {
	_, item, _ := probeCapabilityResponse(t, New(Options{}))
	if item.State != capability.StateBlocked || !item.ReadOnly || len(item.Evidence) != 0 {
		t.Fatal("unconfigured readback was reported available")
	}
}

func TestProbeCapabilitiesAPIConfiguredCacheIsNotRead(t *testing.T) {
	_, item, body := probeCapabilityResponse(t, New(Options{Probes: probeCapabilityNoRead{}}))
	if item.State != capability.StateImplementedLocal || !item.ReadOnly || len(item.Evidence) != 2 {
		t.Fatal("configured readback fact is inaccurate")
	}
	if item.Evidence[0] != "GET /api/v1/probes/status" || item.Evidence[1] != "GET /api/v1/probes/details" {
		t.Fatal("readback inventory advertised execution or mutation")
	}
	for _, field := range []string{`"samples"`, `"targets"`, `"catalogDigest"`, `"runId"`, `"probeId"`, `"pathId"`} {
		if strings.Contains(body, field) {
			t.Fatal("anonymous inventory disclosed probe evidence")
		}
	}
}

func TestProbeCapabilitiesAPIExpiredEvidenceDoesNotClaimHealth(t *testing.T) {
	p := probeAPIReader(t)
	p.status.Configured = true
	p.status.State = "partial"
	p.status.Reason = "evidence_expired"
	p.status.Coverage.ExpiredTotal = 6
	_, item, body := probeCapabilityResponse(t, New(Options{Probes: p}))
	if p.statusCalls != 0 || p.detailCalls != 0 || item.State != capability.StateImplementedLocal {
		t.Fatal("configuration fact depended on cached health")
	}
	if strings.Contains(body, "evidence_expired") || strings.Contains(body, `"available"`) || len(item.Limitations) == 0 {
		t.Fatal("capability report conflated configured and healthy")
	}
}

func TestProbeCapabilitiesAPIReportsDetachedProjection(t *testing.T) {
	h := New(Options{Probes: probeCapabilityNoRead{}})
	first, item, _ := probeCapabilityResponse(t, h)
	item.Evidence[0] = "POST /sentinel-mutation"
	item.Limitations[0] = "sentinel-removed-boundary"
	first.Capabilities = nil
	_, second, body := probeCapabilityResponse(t, h)
	if second.Evidence[0] != "GET /api/v1/probes/status" || strings.Contains(body, "sentinel-") {
		t.Fatal("a returned report contaminated a later request")
	}
}
