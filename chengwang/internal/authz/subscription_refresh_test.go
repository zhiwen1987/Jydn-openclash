package authz

import (
	"testing"
	"time"
)

func TestSubscriptionRefreshRequiresDedicatedMachineRole(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
		request := subscriptionRequest(role, ActionRefreshSubscription)
		if decision := Evaluate(request, testNow); decision.Allowed {
			t.Fatalf("human role %q obtained refresh execution", role)
		}
	}
	request := subscriptionRequest(RoleSubscriptionRefresher, ActionRefreshSubscription)
	if decision := Evaluate(request, testNow); !decision.Allowed {
		t.Fatalf("dedicated refresh role denied: %s", decision.Code)
	}
	request.BreakGlass = &BreakGlass{Explicit: true, Reason: "fixture", IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute), AuditEnabled: true}
	request.Principal.BreakGlassEligible = true
	if decision := Evaluate(request, testNow); decision.Allowed || decision.Code != ReasonDenySubscriptionBreakGlassForbidden {
		t.Fatal("subscription refresh accepted break glass")
	}
}
