package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"chengwang/internal/capability"
)

func TestVerifyPassesOnlyForLockedTruthfulRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch r.URL.Path {
		case "/api/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok","mode":"shadow","mihomoReadbackConfigured":true,"evidenceConfigured":true,"evidenceIntegrity":true}`))
		case "/api/v1/capabilities":
			items := make([]capability.Item, 15)
			items[0] = capability.Item{ID: "real_authentication", State: capability.StateBlocked}
			items[1] = capability.Item{ID: "durable_operation_control", State: capability.StateBlocked}
			_ = json.NewEncoder(w).Encode(capability.Report{ProductionControlEnabled: false, Capabilities: items})
		case "/api/v1/operations":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"effect":"local_record_only","deviceActionsExecuted":false,"code":"operation_control_not_configured"}`))
		case "/api/v1/attestation/shadow":
			_, _ = w.Write([]byte(`{"mode":"shadow","productionControlEnabled":false,"identityConfigured":false,"operationWritesEnabled":false,"deviceActionsExecuted":false,"evidence":{"valid":true,"count":0,"verifiedAt":"2026-10-18T00:00:00Z"},"mihomo":{"configured":true,"reachable":true,"fresh":true,"lastSuccessfulAt":"2026-10-18T00:00:00Z"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	r, err := verify(context.Background(), server.URL, 15)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed || len(r.Checks) != 5 {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestVerifyDetectsUnsafeCapabilityClaim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch r.URL.Path {
		case "/api/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok","mode":"shadow","mihomoReadbackConfigured":true,"evidenceConfigured":true,"evidenceIntegrity":true}`))
		case "/api/v1/capabilities":
			items := make([]capability.Item, 15)
			items[0] = capability.Item{ID: "real_authentication", State: capability.StateImplementedLocal}
			items[1] = capability.Item{ID: "durable_operation_control", State: capability.StateImplementedLocal}
			_ = json.NewEncoder(w).Encode(capability.Report{ProductionControlEnabled: true, Capabilities: items})
		case "/api/v1/operations":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"effect":"local_record_only","deviceActionsExecuted":false,"code":"operation_control_not_configured"}`))
		case "/api/v1/attestation/shadow":
			_, _ = w.Write([]byte(`{"mode":"shadow","productionControlEnabled":false,"identityConfigured":false,"operationWritesEnabled":false,"deviceActionsExecuted":false,"evidence":{"valid":true,"count":1,"verifiedAt":"2026-10-18T00:00:00Z"},"mihomo":{"configured":true,"reachable":true,"fresh":true,"lastSuccessfulAt":"2026-10-18T00:00:00Z"}}`))
		}
	}))
	defer server.Close()

	r, err := verify(context.Background(), server.URL, 15)
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed {
		t.Fatal("unsafe capability claim must fail acceptance")
	}
	if r.Checks[2].Passed {
		t.Fatalf("capability_truth unexpectedly passed: %+v", r.Checks[2])
	}
}

func TestVerifyRejectsRedirectCredentialsAndOversize(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/", http.StatusFound)
	}))
	defer redirect.Close()
	r, err := verify(context.Background(), redirect.URL, 15)
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed || r.Checks[0].Passed {
		t.Fatal("redirected health request must fail")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := verify(ctx, "http://user:secret@example.invalid", 15); err == nil {
		t.Fatal("base URL credentials must be rejected")
	}
	if _, err := verify(ctx, "http://example.invalid/control", 15); err == nil {
		t.Fatal("base URL path must be rejected")
	}

	oversize := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		_, _ = w.Write(make([]byte, maxResponseBytes))
	}))
	defer oversize.Close()
	r, err = verify(context.Background(), oversize.URL, 15)
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed || r.Checks[0].Passed {
		t.Fatal("oversize health response must fail")
	}
}
