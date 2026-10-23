package capability

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProbeReadbackCapabilityDefaultsBlocked(t *testing.T) {
	now := time.Date(2026, 10, 23, 1, 2, 3, 456, time.UTC)
	legacy := find(t, Build(now, false, false, false, false, false), "probe_evidence_readback")
	typed := find(t, BuildWithRuntime(now, RuntimeFacts{}), "probe_evidence_readback")
	if !reflect.DeepEqual(legacy, typed) || typed.State != StateBlocked || !typed.ReadOnly || len(typed.Evidence) != 0 {
		t.Fatalf("default configuration must expose only a blocked read-only import: %+v", typed)
	}
	if !strings.Contains(strings.Join(typed.Limitations, "\n"), "默认关闭") {
		t.Fatal("default-disabled boundary is missing")
	}
}

func TestProbeReadbackCapabilityConfiguredIsReadOnlyLocal(t *testing.T) {
	item := find(t, BuildWithRuntime(time.Now(), RuntimeFacts{ProbeReadbackConfigured: true}), "probe_evidence_readback")
	if item.State != StateImplementedLocal || !item.ReadOnly || item.Domain != "observability" {
		t.Fatalf("configured import must remain implemented_local and read-only: %+v", item)
	}
	if item.State == StateLiveReadOnly {
		t.Fatal("configuration alone cannot attest live readback health")
	}
}

func TestProbeReadbackCapabilityEvidenceIsGETOnly(t *testing.T) {
	item := find(t, BuildWithRuntime(time.Now(), RuntimeFacts{ProbeReadbackConfigured: true}), "probe_evidence_readback")
	want := []string{"GET /api/v1/probes/status", "GET /api/v1/probes/details"}
	if !reflect.DeepEqual(item.Evidence, want) {
		t.Fatalf("only the two cached GET routes may be advertised: %+v", item.Evidence)
	}
}

func TestProbeReadbackCapabilityDisclosesConfigurationNotHealth(t *testing.T) {
	item := find(t, BuildWithRuntime(time.Now(), RuntimeFacts{ProbeReadbackConfigured: true}), "probe_evidence_readback")
	limitations := strings.Join(item.Limitations, "\n")
	for _, required := range []string{
		"仅表示已配置", "不表示证据新鲜、完整、健康或生产验收通过", "有界缓存",
		"不触发探测或请求时读盘", "身份与范围授权", "standalone probe-agent", "advisory",
		"不执行设备动作", "没有启动、停止或调度 agent 的 API", "不证明公网可达性或生产验证",
	} {
		if !strings.Contains(limitations, required) {
			t.Fatalf("capability boundary %q is missing", required)
		}
	}
}

func TestProbeReadbackRuntimeFactsPreserveLegacyCapabilities(t *testing.T) {
	now := time.Date(2026, 10, 23, 1, 2, 3, 456, time.FixedZone("CST", 8*60*60))
	for mask := 0; mask < 64; mask++ {
		facts := RuntimeFacts{
			MihomoConfigured: mask&1 != 0, EvidenceConfigured: mask&2 != 0,
			EvidenceValid: mask&4 != 0, IdentityConfigured: mask&8 != 0,
			OperationControlConfigured: mask&16 != 0, ObservationConfigured: mask&32 != 0,
		}
		legacy := Build(now, facts.MihomoConfigured, facts.EvidenceConfigured, facts.EvidenceValid,
			facts.IdentityConfigured, facts.OperationControlConfigured, facts.ObservationConfigured)
		typed := BuildWithRuntime(now, facts)
		if !reflect.DeepEqual(legacy, typed) {
			t.Fatalf("legacy wrapper differs for runtime mask %d", mask)
		}
		facts.ProbeReadbackConfigured = true
		configured := BuildWithRuntime(now, facts)
		if configured.GeneratedAt != legacy.GeneratedAt || configured.OverallState != legacy.OverallState ||
			configured.ProductionControlEnabled != legacy.ProductionControlEnabled || len(configured.Capabilities) != len(legacy.Capabilities) {
			t.Fatalf("probe configuration changed the report contract for mask %d", mask)
		}
		for i, item := range legacy.Capabilities {
			if item.ID != "probe_evidence_readback" && !reflect.DeepEqual(item, configured.Capabilities[i]) {
				t.Fatalf("probe configuration changed legacy capability %q", item.ID)
			}
		}
	}
	// Every call owns its slices; callers cannot corrupt another report or a
	// future Build result through any capability or nested slice.
	facts := RuntimeFacts{MihomoConfigured: true, EvidenceConfigured: true, EvidenceValid: true,
		IdentityConfigured: true, OperationControlConfigured: true, ObservationConfigured: true, ProbeReadbackConfigured: true}
	want := BuildWithRuntime(now, facts)
	want.Capabilities = append([]Item(nil), want.Capabilities...)
	for i := range want.Capabilities {
		want.Capabilities[i].Evidence = append([]string{}, want.Capabilities[i].Evidence...)
		want.Capabilities[i].Limitations = append([]string{}, want.Capabilities[i].Limitations...)
	}
	mutated := BuildWithRuntime(now, facts)
	for i := range mutated.Capabilities {
		mutated.Capabilities[i].ID = "changed"
		if len(mutated.Capabilities[i].Evidence) != 0 {
			mutated.Capabilities[i].Evidence[0] = "changed"
		}
		mutated.Capabilities[i].Limitations[0] = "changed"
	}
	if !reflect.DeepEqual(want, BuildWithRuntime(now, facts)) {
		t.Fatal("a caller mutated another report or a future build")
	}
}

func TestProbeReadbackLegacyOptionalObservationArityPreserved(t *testing.T) {
	now := time.Now()
	without := Build(now, false, false, false, false, false)
	oneFalse := Build(now, false, false, false, false, false, false)
	oneTrue := Build(now, false, false, false, false, false, true)
	twoTrue := Build(now, false, false, false, false, false, true, true)
	twoMixed := Build(now, false, false, false, false, false, false, true)
	for _, report := range []Report{without, oneFalse, twoTrue, twoMixed} {
		if !reflect.DeepEqual(report, without) || find(t, report, "continuous_passive_observation").State != StateBlocked {
			t.Fatal("legacy optional observation must be enabled only by exactly one true argument")
		}
		if find(t, report, "probe_evidence_readback").State != StateBlocked {
			t.Fatal("legacy optional arguments must never configure probe readback")
		}
	}
	if find(t, oneTrue, "continuous_passive_observation").State != StateLiveReadOnly ||
		find(t, oneTrue, "probe_evidence_readback").State != StateBlocked {
		t.Fatal("one observation argument must retain its original meaning")
	}
}

func TestProbeReadbackCapabilityNeverEnablesProduction(t *testing.T) {
	for mask := 0; mask < 128; mask++ {
		facts := RuntimeFacts{
			MihomoConfigured: mask&1 != 0, EvidenceConfigured: mask&2 != 0,
			EvidenceValid: mask&4 != 0, IdentityConfigured: mask&8 != 0,
			OperationControlConfigured: mask&16 != 0, ObservationConfigured: mask&32 != 0,
			ProbeReadbackConfigured: mask&64 != 0,
		}
		report := BuildWithRuntime(time.Now(), facts)
		if report.ProductionControlEnabled || report.OverallState != "foundation" {
			t.Fatalf("runtime mask %d enabled production control", mask)
		}
		item := find(t, report, "probe_evidence_readback")
		want := StateBlocked
		if facts.ProbeReadbackConfigured {
			want = StateImplementedLocal
		}
		if item.State != want || !item.ReadOnly {
			t.Fatalf("probe configuration was confused with unrelated facts for mask %d", mask)
		}
	}
}

func TestProbeReadbackBusinessProbeScopeRemainsDesignOnly(t *testing.T) {
	report := BuildWithRuntime(time.Now(), RuntimeFacts{ProbeReadbackConfigured: true})
	item := find(t, report, "active_business_probes")
	if item.State != StateDesignOnly || !item.ReadOnly || len(item.Evidence) != 0 {
		t.Fatalf("full business probing must remain design_only: %+v", item)
	}
	limitations := strings.Join(item.Limitations, "\n")
	for _, required := range []string{"已有 standalone probe-agent", "HTTP、TLS、DNS", "完整节点、地区、账号与企业业务评估及生产验证闭环"} {
		if !strings.Contains(limitations, required) {
			t.Fatalf("accurate remaining scope %q is missing", required)
		}
	}
}
