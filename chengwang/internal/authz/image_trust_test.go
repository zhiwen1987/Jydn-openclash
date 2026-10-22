package authz

import (
	"testing"
	"time"
)

func TestImageTrustRoleMatrix(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
		for _, action := range []Action{ActionReadImageTrust, ActionUpdateImageTrust, ActionVerifyImageTrust} {
			t.Run(string(role)+"/"+string(action), func(t *testing.T) {
				request := baseRequest(role, action)
				want := action == ActionReadImageTrust || role == RoleAdmin || role == RoleOperator && action == ActionVerifyImageTrust
				decision := Evaluate(request, testNow)
				if decision.Allowed != want {
					t.Fatalf("role=%s action=%s decision=%+v want=%v", role, action, decision, want)
				}
			})
		}
	}
}

func TestImageTrustBreakGlassAlwaysDenied(t *testing.T) {
	for _, action := range []Action{ActionReadImageTrust, ActionUpdateImageTrust, ActionVerifyImageTrust} {
		for _, role := range []Role{RoleViewer, RoleAdmin} {
			r := baseRequest(role, action)
			r.Principal.BreakGlassEligible = true
			r.BreakGlass = &BreakGlass{Explicit: true, Reason: "incident", IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute), AuditEnabled: true}
			assertDecision(t, Evaluate(r, testNow), false, ReasonDenyImageTrustBreakGlassForbidden)
		}
	}
}

func TestImageTrustScopeAndUnknownIdentityDenied(t *testing.T) {
	for _, action := range []Action{ActionReadImageTrust, ActionUpdateImageTrust, ActionVerifyImageTrust} {
		for name, mutate := range map[string]func(*Request){
			"tenant":           func(r *Request) { r.Resource.TenantID = "other" },
			"site":             func(r *Request) { r.Resource.SiteID = "other" },
			"object_type":      func(r *Request) { r.Resource.ObjectType = "other" },
			"object_id":        func(r *Request) { r.Resource.ObjectID = "other" },
			"environment":      func(r *Request) { r.Resource.Environment = "other" },
			"unknown_role":     func(r *Request) { r.Principal.Roles = append(r.Principal.Roles, Role("root")) },
			"unknown_action":   func(r *Request) { r.Action = Action("image_trust.bootstrap") },
			"missing_identity": func(r *Request) { r.Principal.ID = "" },
		} {
			t.Run(string(action)+"/"+name, func(t *testing.T) {
				r := baseRequest(RoleAdmin, action)
				r.Resource = ResourceScope{TenantID: r.Principal.TenantID, SiteID: "site", ObjectType: "image-trust", ObjectID: "trust", Environment: "isolated"}
				r.Principal.AllowedScopes = []ResourceScope{r.Resource}
				mutate(&r)
				if decision := Evaluate(r, testNow); decision.Allowed {
					t.Fatalf("invalid identity/scope allowed: %+v", decision)
				}
			})
		}
	}
}
