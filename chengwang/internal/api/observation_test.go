package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"chengwang/internal/observation"
	"chengwang/internal/store"
)

type fakeObservationReader struct {
	status      observation.Status
	detail      observation.Detail
	statusCalls int
	detailCalls int
}

func (f *fakeObservationReader) Status() observation.Status {
	f.statusCalls++
	return f.status
}

func (f *fakeObservationReader) Detail(_ int) observation.Detail {
	f.detailCalls++
	return f.detail
}

func TestObservationStatusIsAnonymousMinimalAndNeverReturnsSamples(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeObservationReader{status: observation.Status{
		Configured: true, Mode: "passive_read_only", Running: true, Fresh: true,
		Controller: observation.Layer{State: observation.StateAvailable, Reason: "ok"},
		Business:   observation.Layer{State: observation.StateUnknown, Reason: "not measured"},
	}}
	handler := New(Options{Mode: "shadow", Versions: versions, Observation: reader})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/observations/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"samples", "proxies", "nodes", "providers", "rules", "targets"} {
		if _, ok := result[forbidden]; ok {
			t.Fatalf("anonymous status exposed %q: %v", forbidden, result)
		}
	}
	if strings.Contains(recorder.Body.String(), "secret-node") || reader.statusCalls != 1 || reader.detailCalls != 0 {
		t.Fatalf("anonymous endpoint read details or leaked data: calls=%d/%d body=%s", reader.statusCalls, reader.detailCalls, recorder.Body.String())
	}
}

func TestObservationHistoryRejectsBeforeReadingDetails(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeObservationReader{}
	handler := New(Options{Mode: "shadow", Versions: versions, Observation: reader})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/observations/mihomo/history", nil))
	if recorder.Code != http.StatusServiceUnavailable || reader.detailCalls != 0 {
		t.Fatalf("history did not fail before reading details: %d calls=%d", recorder.Code, reader.detailCalls)
	}
}

func TestObservationHistoryRequiresSecureManagementAndReturnsBoundedDetail(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reader := &fakeObservationReader{detail: observation.Detail{Samples: []observation.Sample{{Sequence: 1, AttemptedAt: now, CompletedAt: now, Success: true}}}}
	handler := New(Options{Mode: "shadow", Versions: versions, Observation: reader, Authn: fakeAuthenticator{}, ManagementScope: testManagementScope})

	plainLAN := httptest.NewRequest(http.MethodGet, "/api/v1/observations/mihomo/history", nil)
	plainLAN.RemoteAddr = "10.88.0.20:1234"
	plainLAN.Header.Set("Authorization", "Bearer test-management-token")
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, plainLAN)
	if rejected.Code != http.StatusUpgradeRequired || reader.detailCalls != 0 {
		t.Fatalf("LAN plaintext history was not rejected before read: %d calls=%d", rejected.Code, reader.detailCalls)
	}

	accepted := httptest.NewRecorder()
	handler.ServeHTTP(accepted, managementRequest(http.MethodGet, "/api/v1/observations/mihomo/history", nil))
	if accepted.Code != http.StatusOK || reader.detailCalls != 1 || !strings.Contains(accepted.Body.String(), `"sequence":1`) {
		t.Fatalf("protected history failed: %d calls=%d body=%s", accepted.Code, reader.detailCalls, accepted.Body.String())
	}
}
