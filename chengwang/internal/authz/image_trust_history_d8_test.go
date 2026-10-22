package authz

import (
	"testing"
	"time"
)

func TestImageTrustHistoryD8RoleScopeAndBreakGlass(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			r := baseRequest(role, ActionHistoryImageTrust)
			want := role == RoleAuditor || role == RoleAdmin
			if got := Evaluate(r, testNow); got.Allowed != want {
				t.Fatalf("history role decision=%+v want=%v", got, want)
			}
			r.Principal.BreakGlassEligible = true
			r.BreakGlass = &BreakGlass{Explicit: true, Reason: "incident", IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute), AuditEnabled: true}
			assertDecision(t, Evaluate(r, testNow), false, ReasonDenyImageTrustBreakGlassForbidden)
		})
	}
	for _, field := range []string{"tenant", "site", "object", "environment", "unknown-role"} {
		t.Run(field, func(t *testing.T) {
			r := baseRequest(RoleAdmin, ActionHistoryImageTrust)
			r.Resource = ResourceScope{TenantID: r.Principal.TenantID, SiteID: "site", ObjectType: "image-trust", ObjectID: "store", Environment: "candidate"}
			r.Principal.AllowedScopes = []ResourceScope{r.Resource}
			switch field {
			case "tenant":
				r.Resource.TenantID = "other"
			case "site":
				r.Resource.SiteID = "other"
			case "object":
				r.Resource.ObjectID = "other"
			case "environment":
				r.Resource.Environment = "other"
			case "unknown-role":
				r.Principal.Roles = append(r.Principal.Roles, "owner")
			}
			if Evaluate(r, testNow).Allowed {
				t.Fatal("history escaped fixed scope")
			}
		})
	}
}
