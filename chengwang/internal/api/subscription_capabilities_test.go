package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/capability"
	"chengwang/internal/subscriptionctl"
)

type subscriptionCapabilityBackend struct {
	scope      authz.ResourceScope
	scopeCalls int
}

var _ subscriptionctl.Backend = (*subscriptionCapabilityBackend)(nil)
var _ subscriptionctl.AccessReader = (*subscriptionCapabilityBackend)(nil)

func (b *subscriptionCapabilityBackend) Scope() authz.ResourceScope {
	b.scopeCalls++
	return b.scope
}
func (*subscriptionCapabilityBackend) ListSources(context.Context, authz.Principal) (subscriptionctl.SourcePage, error) {
	panic("capability inventory must not list protected subscription sources")
}
func (*subscriptionCapabilityBackend) ListCandidates(context.Context, authz.Principal, string, subscriptionctl.ListQuery) (subscriptionctl.CandidatePage, error) {
	panic("capability inventory must not list protected subscription candidates")
}
func (*subscriptionCapabilityBackend) ListNodes(context.Context, authz.Principal, string, string, subscriptionctl.ListQuery) (subscriptionctl.NodePage, error) {
	panic("capability inventory must not list protected subscription nodes")
}
func (*subscriptionCapabilityBackend) Execute(context.Context, authz.Principal, subscriptionctl.Command) (subscriptionctl.Receipt, error) {
	panic("capability inventory must not execute a subscription command")
}
func (*subscriptionCapabilityBackend) ReadReceipt(context.Context, authz.Principal, string) (subscriptionctl.Receipt, error) {
	panic("capability inventory must not read a protected subscription receipt")
}
func (*subscriptionCapabilityBackend) RecordDenied(context.Context, authz.Principal, authz.Action, subscriptionctl.Code) error {
	panic("anonymous capability inventory must not write a subscription denial audit")
}
func (*subscriptionCapabilityBackend) Access(context.Context, authz.Principal, string) (subscriptionctl.AccessView, error) {
	panic("capability inventory must not read protected subscription access or policy readiness")
}

type subscriptionCapabilityAuth struct{}

var _ Authenticator = (*subscriptionCapabilityAuth)(nil)

func (*subscriptionCapabilityAuth) AuthenticateAuthorizationValues([]string, time.Time) (authz.Principal, error) {
	panic("anonymous capability inventory must not authenticate an identity")
}

func subscriptionCapabilityResponse(t *testing.T, handler http.Handler) (capability.Report, string) {
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
		t.Fatal("subscription configuration escalated production readiness")
	}
	return report, w.Body.String()
}

func subscriptionCapabilityItem(t *testing.T, report capability.Report, id string) capability.Item {
	t.Helper()
	var item capability.Item
	count := 0
	for _, candidate := range report.Capabilities {
		if candidate.ID == id {
			item = candidate
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one capability %q", id)
	}
	return item
}

func TestSubscriptionCapabilitiesAPIDefaultIsBlocked(t *testing.T) {
	report, _ := subscriptionCapabilityResponse(t, New(Options{}))
	item := subscriptionCapabilityItem(t, report, "subscription_local_admission")
	if item.State != capability.StateBlocked || item.ReadOnly || len(item.Evidence) != 0 {
		t.Fatal("unconfigured subscription API was reported implemented")
	}
}

func TestSubscriptionCapabilitiesAPIRequiresConfiguredBackendScopeAndIdentity(t *testing.T) {
	for _, name := range []string{"nil backend", "typed nil backend", "wrong object type", "missing tenant", "nil identity", "typed nil identity", "configured write gate closed", "configured write gate open"} {
		t.Run(name, func(t *testing.T) {
			backend := &subscriptionCapabilityBackend{scope: subscriptionAPIScope}
			o := Options{Subscriptions: backend, Authn: &subscriptionCapabilityAuth{}}
			want := capability.StateBlocked
			scopeCalls := 1
			switch name {
			case "nil backend":
				o.Subscriptions = nil
				scopeCalls = 0
			case "typed nil backend":
				var absent *subscriptionCapabilityBackend
				o.Subscriptions = absent
				scopeCalls = 0
			case "wrong object type":
				backend.scope.ObjectType = "control-plane"
			case "missing tenant":
				backend.scope.TenantID = ""
			case "nil identity":
				o.Authn = nil
			case "typed nil identity":
				var absent *subscriptionCapabilityAuth
				o.Authn = absent
			case "configured write gate closed":
				want = capability.StateImplementedLocal
			case "configured write gate open":
				o.SubscriptionWritesEnabled = true
				want = capability.StateImplementedLocal
			}
			handler := New(o)
			for i := 0; i < 2; i++ {
				report, _ := subscriptionCapabilityResponse(t, handler)
				item := subscriptionCapabilityItem(t, report, "subscription_local_admission")
				if item.State != want || item.ReadOnly || backend.scopeCalls != scopeCalls {
					t.Fatalf("backend/identity configuration fact is inaccurate: %s", name)
				}
				if want == capability.StateBlocked && len(item.Evidence) != 0 {
					t.Fatal("unconfigured protected subscription routes were advertised")
				}
				if name == "nil identity" || name == "typed nil identity" {
					if subscriptionCapabilityItem(t, report, "real_authentication").State != capability.StateBlocked {
						t.Fatal("nil identity was reported configured")
					}
				}
			}
		})
	}
}

func TestSubscriptionCapabilitiesAPIUsesOnlyCachedScope(t *testing.T) {
	backend := &subscriptionCapabilityBackend{scope: subscriptionAPIScope}
	handler := New(Options{Subscriptions: backend, Authn: &subscriptionCapabilityAuth{}})
	if backend.scopeCalls != 1 {
		t.Fatal("subscription scope was not captured at construction")
	}
	backend.scope = authz.ResourceScope{}
	for i := 0; i < 3; i++ {
		report, _ := subscriptionCapabilityResponse(t, handler)
		if subscriptionCapabilityItem(t, report, "subscription_local_admission").State != capability.StateImplementedLocal || backend.scopeCalls != 1 {
			t.Fatal("anonymous capability inventory reread the backend scope")
		}
	}
}

func TestSubscriptionCapabilitiesAPIWriteGateDoesNotGrantHealthOrExposeState(t *testing.T) {
	for _, writes := range []bool{false, true} {
		backend := &subscriptionCapabilityBackend{scope: subscriptionAPIScope}
		report, body := subscriptionCapabilityResponse(t, New(Options{Subscriptions: backend, Authn: &subscriptionCapabilityAuth{}, SubscriptionWritesEnabled: writes}))
		item := subscriptionCapabilityItem(t, report, "subscription_local_admission")
		if item.State != capability.StateImplementedLocal || item.ReadOnly || len(item.Evidence) != 12 || backend.scopeCalls != 1 {
			t.Fatal("independent write gate changed the configuration inventory")
		}
		limitations := strings.Join(item.Limitations, "\n")
		for _, required := range []string{"两层独立订阅写门", "不表示写门已开启", "不代表策略目录就绪或来源已批准", "不执行设备发布", "不代表当前主体获准操作、业务健康或生产验收通过"} {
			if !strings.Contains(limitations, required) {
				t.Fatalf("subscription inventory omitted boundary %q", required)
			}
		}
		for _, field := range []string{`"sources":`, `"candidates":`, `"nodes":`, `"commandId":`, `"policyDigest":`, `"approvalId":`, `"identityKey":`, `"enabled":`, `"healthy":`, `"policyReady":`, `"sourceApproved":`} {
			if strings.Contains(body, field) {
				t.Fatal("anonymous inventory exposed protected state or invented readiness")
			}
		}
		for _, id := range []string{"subscription_orchestration", "router_publish", "active_business_probes", "automatic_repair", "multi_kernel_runtime"} {
			if subscriptionCapabilityItem(t, report, id).State != capability.StateDesignOnly {
				t.Fatalf("local subscription configuration escalated %s", id)
			}
		}
	}
}

func TestSubscriptionCapabilitiesAPIReportsDetachedProjection(t *testing.T) {
	backend := &subscriptionCapabilityBackend{scope: subscriptionAPIScope}
	handler := New(Options{Subscriptions: backend, Authn: &subscriptionCapabilityAuth{}})
	first, _ := subscriptionCapabilityResponse(t, handler)
	item := subscriptionCapabilityItem(t, first, "subscription_local_admission")
	item.Evidence[0] = "POST /sentinel-mutation"
	item.Limitations[0] = "sentinel-removed-boundary"
	first.Capabilities = nil
	second, body := subscriptionCapabilityResponse(t, handler)
	if subscriptionCapabilityItem(t, second, "subscription_local_admission").Evidence[0] != "GET /api/v1/subscriptions/access" || strings.Contains(body, "sentinel-") || backend.scopeCalls != 1 {
		t.Fatal("returned subscription inventory contaminated a later request")
	}
}
