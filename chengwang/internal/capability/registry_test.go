package capability

import (
	"testing"
	"time"
)

func TestBuildReportsOnlyAllowedStatesAndUniqueCapabilities(t *testing.T) {
	report := Build(time.Date(2026, 10, 18, 14, 35, 12, 987654321, time.FixedZone("CST", 8*60*60)), false, false, false, false, false)
	if report.GeneratedAt != "2026-10-18T06:35:12Z" {
		t.Fatalf("unexpected RFC3339 timestamp: %q", report.GeneratedAt)
	}
	if report.ProductionControlEnabled || report.OverallState != "foundation" {
		t.Fatalf("unsafe report header: %+v", report)
	}
	allowed := map[State]bool{
		StateLiveReadOnly: true, StateImplementedLocal: true, StateDesignOnly: true, StateBlocked: true,
	}
	seen := map[string]bool{}
	for _, item := range report.Capabilities {
		if !allowed[item.State] {
			t.Fatalf("capability %q has unsupported state %q", item.ID, item.State)
		}
		if item.ID == "" || seen[item.ID] {
			t.Fatalf("empty or duplicate capability id %q", item.ID)
		}
		seen[item.ID] = true
		if len(item.Limitations) == 0 {
			t.Fatalf("capability %q does not disclose limitations", item.ID)
		}
	}
	for _, required := range []string{
		"control_health", "policy_validation", "mihomo_compilation", "local_version_store",
		"proxy_interface_validation", "mihomo_runtime_readback", "router_publish",
		"local_evidence_chain",
		"durable_operation_control",
		"subscription_orchestration", "dns_execution", "active_business_probes",
		"automatic_repair", "multi_kernel_runtime", "real_authentication",
	} {
		if !seen[required] {
			t.Fatalf("required capability %q missing", required)
		}
	}
}

func TestMihomoReadbackStateTracksAdapterConfiguration(t *testing.T) {
	unconfigured := find(t, Build(time.Now(), false, false, false, false, false), "mihomo_runtime_readback")
	if unconfigured.State != StateBlocked || len(unconfigured.Evidence) != 0 {
		t.Fatalf("unconfigured adapter falsely reported available: %+v", unconfigured)
	}
	configured := find(t, Build(time.Now(), true, false, false, false, false), "mihomo_runtime_readback")
	if configured.State != StateLiveReadOnly || !configured.ReadOnly || len(configured.Evidence) != 2 {
		t.Fatalf("configured adapter state is inaccurate: %+v", configured)
	}
}

func TestUnimplementedProductionCapabilitiesStayDesignOnly(t *testing.T) {
	report := Build(time.Now(), true, false, false, false, false)
	for _, id := range []string{
		"router_publish", "subscription_orchestration", "dns_execution", "active_business_probes",
		"automatic_repair", "multi_kernel_runtime",
	} {
		item := find(t, report, id)
		if item.State != StateDesignOnly {
			t.Fatalf("%s falsely reported as implemented: %+v", id, item)
		}
	}
}

func TestIdentityAndOperationCapabilitiesRequireRuntimeDependencies(t *testing.T) {
	unconfigured := Build(time.Now(), false, true, true, false, false)
	if find(t, unconfigured, "real_authentication").State != StateBlocked ||
		find(t, unconfigured, "durable_operation_control").State != StateBlocked {
		t.Fatal("unconfigured identity or operation control was reported implemented")
	}
	configured := Build(time.Now(), false, true, true, true, true)
	if find(t, configured, "real_authentication").State != StateImplementedLocal ||
		find(t, configured, "durable_operation_control").State != StateImplementedLocal {
		t.Fatal("configured local dependencies were not reported implemented_local")
	}
	if configured.ProductionControlEnabled {
		t.Fatal("local shadow records must never enable production control")
	}
}

func TestEvidenceChainRequiresConfigurationAndSuccessfulVerification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
		valid      bool
		want       State
	}{
		{name: "unconfigured", want: StateBlocked},
		{name: "verification failed", configured: true, want: StateBlocked},
		{name: "verified", configured: true, valid: true, want: StateImplementedLocal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := find(t, Build(time.Now(), false, tc.configured, tc.valid, false, false), "local_evidence_chain")
			if item.State != tc.want || item.ReadOnly {
				t.Fatalf("unexpected evidence capability: %+v", item)
			}
			if tc.configured && len(item.Evidence) != 1 {
				t.Fatalf("configured verifier must expose its integrity endpoint: %+v", item)
			}
			if len(item.Limitations) < 3 {
				t.Fatalf("evidence limitations are incomplete: %+v", item)
			}
		})
	}
}

func find(t *testing.T, report Report, id string) Item {
	t.Helper()
	for _, item := range report.Capabilities {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("capability %q not found", id)
	return Item{}
}
