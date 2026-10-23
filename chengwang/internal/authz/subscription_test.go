package authz

import (
	"strings"
	"testing"
	"time"
)

func subscriptionRequest(role Role, action Action) Request {
	r := ResourceScope{TenantID: "tenant-a", SiteID: "site-a", Environment: "isolated", ObjectType: "subscription-source", ObjectID: "src_" + strings.Repeat("a", 32)}
	if action == ActionManageSubscriptionSource {
		r.ObjectType, r.ObjectID = "subscription-store", "local"
	}
	return Request{Principal: Principal{ID: "operator@example/path", TenantID: r.TenantID, Roles: []Role{role}, AllowedScopes: []ResourceScope{{TenantID: r.TenantID, SiteID: r.SiteID, Environment: r.Environment}}}, Action: action, Resource: r}
}
func subscriptionActions() []Action {
	return []Action{ActionReadSubscription, ActionManageSubscriptionSource, ActionImportSubscription, ActionDecideSubscription, ActionApproveSubscriptionSource, ActionFetchSubscription, ActionRollbackSubscription}
}

func TestSubscriptionAuthzRoleMatrix(t *testing.T) {
	want := map[Role]map[Action]bool{
		RoleViewer: {ActionReadSubscription: true}, RoleAuditor: {ActionReadSubscription: true},
		RoleOperator: {ActionReadSubscription: true, ActionManageSubscriptionSource: true, ActionImportSubscription: true, ActionFetchSubscription: true},
		RoleApprover: {ActionReadSubscription: true, ActionDecideSubscription: true, ActionApproveSubscriptionSource: true, ActionRollbackSubscription: true},
	}
	for _, role := range []Role{RoleViewer, RoleAuditor, RoleOperator, RoleApprover, RoleAdmin} {
		for _, action := range subscriptionActions() {
			d := Evaluate(subscriptionRequest(role, action), testNow)
			expected := role == RoleAdmin || want[role][action]
			if d.Allowed != expected || d.BreakGlass {
				t.Fatal("subscription role matrix")
			}
		}
	}
}
func TestSubscriptionAuthzCrossTenantAndSiteDenied(t *testing.T) {
	for _, action := range subscriptionActions() {
		for _, which := range []string{"tenant", "site", "environment"} {
			r := subscriptionRequest(RoleAdmin, action)
			switch which {
			case "tenant":
				r.Resource.TenantID = "tenant-b"
			case "site":
				r.Resource.SiteID = "site-b"
			case "environment":
				r.Resource.Environment = "production"
			}
			if Evaluate(r, testNow).Allowed {
				t.Fatal("subscription scope crossed")
			}
		}
	}
}
func TestSubscriptionAuthzObjectGrantsAreExact(t *testing.T) {
	r := subscriptionRequest(RoleOperator, ActionImportSubscription)
	r.Principal.AllowedScopes = []ResourceScope{r.Resource}
	if !Evaluate(r, testNow).Allowed {
		t.Fatal("matching source grant")
	}
	r.Resource.ObjectID = "src_" + strings.Repeat("b", 32)
	if Evaluate(r, testNow).Allowed {
		t.Fatal("source grant crossed")
	}
}
func TestSubscriptionAuthzControlAndDraftDoNotGrantSubscription(t *testing.T) {
	for _, action := range subscriptionActions() {
		r := subscriptionRequest(RoleAdmin, action)
		r.Principal.AllowedScopes[0].ObjectType = "control-plane"
		if Evaluate(r, testNow).Allowed {
			t.Fatal("generic control grant widened")
		}
		r.Principal.AllowedScopes[0].ObjectType = "draft"
		if Evaluate(r, testNow).Allowed {
			t.Fatal("draft grant widened")
		}
	}
}
func TestSubscriptionAuthzBreakGlassAlwaysDenied(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
		for _, action := range subscriptionActions() {
			r := subscriptionRequest(role, action)
			r.Principal.BreakGlassEligible = true
			r.BreakGlass = &BreakGlass{Explicit: true, Reason: "fixture", IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute), AuditEnabled: true}
			d := Evaluate(r, testNow)
			if d.Allowed || d.Code != ReasonDenySubscriptionBreakGlassForbidden {
				t.Fatal("subscription emergency bypass")
			}
		}
	}
}
func TestSubscriptionAuthzUnknownAndMixedRolesDenied(t *testing.T) {
	for _, action := range subscriptionActions() {
		r := subscriptionRequest(RoleAdmin, action)
		r.Principal.Roles = append(r.Principal.Roles, Role("owner"))
		if Evaluate(r, testNow).Allowed {
			t.Fatal("unknown mixed role")
		}
		r.Principal.Roles = nil
		if Evaluate(r, testNow).Allowed {
			t.Fatal("missing role")
		}
	}
}
func TestSubscriptionAuthzInvalidResourcesFailClosed(t *testing.T) {
	for _, action := range subscriptionActions() {
		for _, field := range []string{"tenant", "site", "environment", "type", "id"} {
			r := subscriptionRequest(RoleAdmin, action)
			switch field {
			case "tenant":
				r.Resource.TenantID = ""
			case "site":
				r.Resource.SiteID = ""
			case "environment":
				r.Resource.Environment = ""
			case "type":
				r.Resource.ObjectType = "control-plane"
			case "id":
				r.Resource.ObjectID = "../local"
			}
			if Evaluate(r, testNow).Allowed {
				t.Fatal("invalid subscription resource")
			}
		}
	}
}
func TestSubscriptionAuthzCollectionCannotMutateSource(t *testing.T) {
	for _, action := range []Action{ActionImportSubscription, ActionDecideSubscription, ActionApproveSubscriptionSource, ActionFetchSubscription, ActionRollbackSubscription} {
		r := subscriptionRequest(RoleAdmin, action)
		r.Resource.ObjectType, r.Resource.ObjectID = "subscription-store", "local"
		if Evaluate(r, testNow).Allowed {
			t.Fatal("source action on collection")
		}
	}
	r := subscriptionRequest(RoleViewer, ActionReadSubscription)
	r.Resource.ObjectType, r.Resource.ObjectID = "subscription-store", "local"
	if !Evaluate(r, testNow).Allowed {
		t.Fatal("authorized collection read")
	}
}
func TestSubscriptionAuthzCombinedRolesStayScoped(t *testing.T) {
	r := subscriptionRequest(RoleOperator, ActionDecideSubscription)
	r.Principal.Roles = []Role{RoleOperator, RoleApprover}
	if !Evaluate(r, testNow).Allowed {
		t.Fatal("explicit combined role denied")
	}
	r.Resource.SiteID = "other"
	if Evaluate(r, testNow).Allowed {
		t.Fatal("combined role bypassed scope")
	}
}
func TestSubscriptionAuthzNonSubscriptionPoliciesUnchanged(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
		r := baseRequest(role, ActionDisableAudit)
		if d := Evaluate(r, testNow); d.Allowed || d.Code != ReasonDenyAuditDisableForbidden {
			t.Fatal("audit invariant changed")
		}
	}
	r := baseRequest(RoleAdmin, Action("subscription.future"))
	if d := Evaluate(r, testNow); d.Allowed || d.Code != ReasonDenyUnknownAction {
		t.Fatal("unknown subscription action")
	}
}
