package capability

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionCapabilityDefaultsBlockedAndLegacyCompatible(t *testing.T) {
	now := time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC)
	zero := find(t, BuildWithRuntime(now, RuntimeFacts{}), "subscription_local_admission")
	legacy := find(t, Build(now, false, false, false, false, false), "subscription_local_admission")
	legacyConfigured := find(t, Build(now, true, true, true, true, true, true), "subscription_local_admission")
	if !reflect.DeepEqual(zero, legacy) || zero.State != StateBlocked || zero.ReadOnly || len(zero.Evidence) != 0 {
		t.Fatalf("default subscription inventory is inaccurate: %+v", zero)
	}
	if legacyConfigured.State != StateBlocked || len(legacyConfigured.Evidence) != 0 {
		t.Fatal("legacy runtime flags implicitly enabled a subscription backend")
	}
}

func TestSubscriptionCapabilityRequiresBackendAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		backend    bool
		identity   bool
		want       State
		limitation string
	}{
		{name: "neither", want: StateBlocked, limitation: "未配置合法范围的本地订阅后端"},
		{name: "identity only", identity: true, want: StateBlocked, limitation: "未配置合法范围的本地订阅后端"},
		{name: "backend only", backend: true, want: StateBlocked, limitation: "未配置本地身份"},
		{name: "both", backend: true, identity: true, want: StateImplementedLocal, limitation: "仅表示本地订阅后端与身份已配置"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := BuildWithRuntime(time.Now(), RuntimeFacts{SubscriptionConfigured: tc.backend, IdentityConfigured: tc.identity})
			item := find(t, report, "subscription_local_admission")
			if item.State != tc.want || item.ReadOnly || item.Domain != "subscription" || report.ProductionControlEnabled || report.OverallState != "foundation" {
				t.Fatalf("configuration escalated the subscription inventory: %+v", item)
			}
			if !strings.Contains(strings.Join(item.Limitations, "\n"), tc.limitation) {
				t.Fatal("missing dependency disclosure")
			}
			if tc.want == StateBlocked && len(item.Evidence) != 0 {
				t.Fatal("blocked subscription API was advertised as configured")
			}
		})
	}
}

func TestSubscriptionCapabilityDisclosesLocalWriteAndPolicyBoundaries(t *testing.T) {
	item := find(t, BuildWithRuntime(time.Now(), RuntimeFacts{SubscriptionConfigured: true, IdentityConfigured: true}), "subscription_local_admission")
	limitations := strings.Join(item.Limitations, "\n")
	for _, required := range []string{
		"本地订阅后端与身份已配置", "不证明接口健康、写入授权或生产可用", "两层独立订阅写门", "本清单不表示写门已开启",
		"身份与范围授权", "不代表策略目录就绪或来源已批准", "引用、批准及策略和来源版本", "没有自动订阅刷新调度",
		"不执行设备发布、内核重载、节点切换或生产流量接管", "不代表当前主体获准操作、业务健康或生产验收通过",
	} {
		if !strings.Contains(limitations, required) {
			t.Fatalf("subscription boundary %q is missing", required)
		}
	}
}

func TestSubscriptionCapabilityListsImplementedLocalRoutes(t *testing.T) {
	item := find(t, BuildWithRuntime(time.Now(), RuntimeFacts{SubscriptionConfigured: true, IdentityConfigured: true}), "subscription_local_admission")
	want := []string{
		"GET /api/v1/subscriptions/access",
		"GET /api/v1/subscriptions/sources",
		"POST /api/v1/subscriptions/sources",
		"GET /api/v1/subscriptions/sources/{sourceId}/access",
		"GET /api/v1/subscriptions/sources/{sourceId}/candidates",
		"POST /api/v1/subscriptions/sources/{sourceId}/candidates",
		"GET /api/v1/subscriptions/sources/{sourceId}/candidates/{candidateId}/nodes",
		"POST /api/v1/subscriptions/sources/{sourceId}/approvals",
		"POST /api/v1/subscriptions/sources/{sourceId}/fetches",
		"POST /api/v1/subscriptions/sources/{sourceId}/decisions",
		"POST /api/v1/subscriptions/sources/{sourceId}/rollbacks",
		"GET /api/v1/subscriptions/commands/{commandId}",
	}
	if !reflect.DeepEqual(item.Evidence, want) {
		t.Fatalf("local subscription entry points are incomplete: %+v", item.Evidence)
	}
}

func TestSubscriptionRuntimeFactsPreserveUnrelatedCapabilities(t *testing.T) {
	now := time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC)
	for mask := 0; mask < 128; mask++ {
		facts := RuntimeFacts{
			MihomoConfigured: mask&1 != 0, EvidenceConfigured: mask&2 != 0, EvidenceValid: mask&4 != 0,
			IdentityConfigured: mask&8 != 0, OperationControlConfigured: mask&16 != 0,
			ObservationConfigured: mask&32 != 0, ProbeReadbackConfigured: mask&64 != 0,
		}
		before := BuildWithRuntime(now, facts)
		facts.SubscriptionConfigured = true
		after := BuildWithRuntime(now, facts)
		if before.GeneratedAt != after.GeneratedAt || before.OverallState != after.OverallState || before.ProductionControlEnabled != after.ProductionControlEnabled || len(before.Capabilities) != len(after.Capabilities) {
			t.Fatalf("subscription configuration changed the report contract for mask %d", mask)
		}
		for i, item := range before.Capabilities {
			if item.ID != "subscription_local_admission" && !reflect.DeepEqual(item, after.Capabilities[i]) {
				t.Fatalf("subscription configuration changed unrelated capability %q", item.ID)
			}
		}
	}
}

func TestSubscriptionOrchestrationRemainsDesignOnlyWithLocalFoundation(t *testing.T) {
	report := BuildWithRuntime(time.Now(), RuntimeFacts{SubscriptionConfigured: true, IdentityConfigured: true})
	item := find(t, report, "subscription_orchestration")
	if item.State != StateDesignOnly || !item.ReadOnly || len(item.Evidence) != 0 {
		t.Fatal("local subscription admission escalated full orchestration")
	}
	limitations := strings.Join(item.Limitations, "\n")
	for _, required := range []string{"已有本地来源", "受控批准抓取", "准入回退与回执底座", "自动刷新调度", "完整节点评估", "数据面应用及生产验证尚未闭环"} {
		if !strings.Contains(limitations, required) {
			t.Fatalf("orchestration inventory omitted boundary %q", required)
		}
	}
}

func TestEvidenceCapabilityDoesNotDenyConfiguredLocalIdentity(t *testing.T) {
	for _, identity := range []bool{false, true} {
		item := find(t, BuildWithRuntime(time.Now(), RuntimeFacts{EvidenceConfigured: true, EvidenceValid: true, IdentityConfigured: identity}), "local_evidence_chain")
		limitations := strings.Join(item.Limitations, "\n")
		if strings.Contains(limitations, "尚无真实用户身份") {
			t.Fatal("evidence inventory contradicted the configured local identity mechanism")
		}
		for _, required := range []string{"本地静态身份机制不等于企业身份体系", "尚未对全部 HTTP 请求形成审计事件", "不是 WORM", "没有独立副本", "不代表生产审计闭环"} {
			if !strings.Contains(limitations, required) {
				t.Fatalf("evidence boundary %q is missing", required)
			}
		}
	}
}

func TestConfiguredReadOnlyAdaptersDoNotClaimConnectionOrProduction(t *testing.T) {
	report := BuildWithRuntime(time.Now(), RuntimeFacts{MihomoConfigured: true, ObservationConfigured: true})
	for _, id := range []string{"mihomo_runtime_readback", "continuous_passive_observation"} {
		item := find(t, report, id)
		if item.State != StateLiveReadOnly || !item.ReadOnly {
			t.Fatal("read-only configuration wire state changed")
		}
		if !strings.Contains(strings.Join(item.Limitations, "\n"), "不代表连接成功、证据新鲜、健康或生产验收通过") {
			t.Fatal("configured adapter was conflated with observed health")
		}
	}
}

func TestSubscriptionCapabilityReportsAreDetached(t *testing.T) {
	now := time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC)
	facts := RuntimeFacts{SubscriptionConfigured: true, IdentityConfigured: true}
	want := BuildWithRuntime(now, facts)
	changed := BuildWithRuntime(now, facts)
	for i := range changed.Capabilities {
		if changed.Capabilities[i].ID == "subscription_local_admission" {
			changed.Capabilities[i].Evidence[0] = "POST /sentinel-mutation"
			changed.Capabilities[i].Limitations[0] = "sentinel-removed-boundary"
			changed.Capabilities[i].State = StateLiveReadOnly
		}
	}
	if got := BuildWithRuntime(now, facts); !reflect.DeepEqual(want, got) {
		t.Fatal("mutating a returned subscription item contaminated a later report")
	}
}
