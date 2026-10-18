package authz

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 18, 8, 0, 0, 0, time.UTC)

func TestRoleMatrix(t *testing.T) {
	roles := []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin}
	actions := []Action{
		ActionReadResource,
		ActionReadEvidence,
		ActionCreateDraft,
		ActionCreateOperation,
		ActionExecuteOperation,
		ActionApproveOperation,
		ActionDisableAudit,
	}
	want := map[Role]map[Action]bool{
		RoleViewer: {
			ActionReadResource: true,
		},
		RoleOperator: {
			ActionReadResource:     true,
			ActionCreateDraft:      true,
			ActionCreateOperation:  true,
			ActionExecuteOperation: true,
		},
		RoleApprover: {
			ActionReadResource:     true,
			ActionReadEvidence:     true,
			ActionApproveOperation: true,
		},
		RoleAuditor: {
			ActionReadEvidence: true,
		},
		RoleAdmin: {
			ActionReadResource:     true,
			ActionReadEvidence:     true,
			ActionCreateDraft:      true,
			ActionCreateOperation:  true,
			ActionExecuteOperation: true,
			ActionApproveOperation: true,
		},
	}

	for _, role := range roles {
		for _, action := range actions {
			t.Run(fmt.Sprintf("%s/%s", role, action), func(t *testing.T) {
				req := baseRequest(role, action)
				decision := Evaluate(req, testNow)
				if decision.Allowed != want[role][action] {
					t.Fatalf("Evaluate() = %+v, want allowed=%v", decision, want[role][action])
				}
				if action == ActionDisableAudit && decision.Code != ReasonDenyAuditDisableForbidden {
					t.Fatalf("audit disable code = %q, want %q", decision.Code, ReasonDenyAuditDisableForbidden)
				}
			})
		}
	}
}

func TestOperatorRiskBoundary(t *testing.T) {
	for _, action := range []Action{ActionCreateDraft, ActionCreateOperation, ActionExecuteOperation} {
		for _, risk := range []Risk{RiskLow, RiskMedium} {
			req := baseRequest(RoleOperator, action)
			req.Risk = risk
			assertDecision(t, Evaluate(req, testNow), true, ReasonAllowRolePolicy)
		}
		for _, risk := range []Risk{RiskHigh, RiskCritical} {
			req := baseRequest(RoleOperator, action)
			req.Risk = risk
			if risk == RiskCritical && action == ActionExecuteOperation {
				req.ApprovedByID = "approver-2"
			}
			assertDecision(t, Evaluate(req, testNow), false, ReasonDenyRiskNotPermitted)
		}
	}
}

func TestMissingAndUnknownInputsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Request)
		code ReasonCode
	}{
		{"identity", func(r *Request) { r.Principal.ID = "" }, ReasonDenyIdentityMissing},
		{"principal tenant", func(r *Request) { r.Principal.TenantID = "" }, ReasonDenyTenantMissing},
		{"resource tenant", func(r *Request) { r.Resource.TenantID = "" }, ReasonDenyTenantMissing},
		{"roles", func(r *Request) { r.Principal.Roles = nil }, ReasonDenyRoleMissing},
		{"unknown role", func(r *Request) { r.Principal.Roles = []Role{"owner"} }, ReasonDenyUnknownRole},
		{"unknown role mixed with admin", func(r *Request) { r.Principal.Roles = []Role{RoleAdmin, "owner"} }, ReasonDenyUnknownRole},
		{"unknown action", func(r *Request) { r.Action = "operation.destroy" }, ReasonDenyUnknownAction},
		{"risk missing", func(r *Request) { r.Risk = "" }, ReasonDenyRiskMissing},
		{"unknown risk", func(r *Request) { r.Risk = "extreme" }, ReasonDenyUnknownRisk},
		{"scope missing", func(r *Request) { r.Principal.AllowedScopes = nil }, ReasonDenyScopeMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseRequest(RoleAdmin, ActionCreateOperation)
			tt.edit(&req)
			assertDecision(t, Evaluate(req, testNow), false, tt.code)
		})
	}

	// The all-zero value is the strongest expression of default deny.
	assertDecision(t, Evaluate(Request{}, testNow), false, ReasonDenyIdentityMissing)
}

func TestTenantAndResourceScopes(t *testing.T) {
	tests := []struct {
		name     string
		grant    ResourceScope
		resource ResourceScope
		allowed  bool
	}{
		{
			name:     "tenant wide",
			grant:    ResourceScope{TenantID: "tenant-a"},
			resource: ResourceScope{TenantID: "tenant-a", SiteID: "site-1", ObjectType: "router", ObjectID: "r1", Environment: "production"},
			allowed:  true,
		},
		{
			name:     "exact object scope",
			grant:    ResourceScope{TenantID: "tenant-a", SiteID: "site-1", ObjectType: "router", ObjectID: "r1", Environment: "production"},
			resource: ResourceScope{TenantID: "tenant-a", SiteID: "site-1", ObjectType: "router", ObjectID: "r1", Environment: "production"},
			allowed:  true,
		},
		{
			name:     "cross tenant",
			grant:    ResourceScope{TenantID: "tenant-a"},
			resource: ResourceScope{TenantID: "tenant-b"},
		},
		{
			name:     "site mismatch",
			grant:    ResourceScope{TenantID: "tenant-a", SiteID: "site-1"},
			resource: ResourceScope{TenantID: "tenant-a", SiteID: "site-2"},
		},
		{
			name:     "object type mismatch",
			grant:    ResourceScope{TenantID: "tenant-a", ObjectType: "router"},
			resource: ResourceScope{TenantID: "tenant-a", ObjectType: "dns"},
		},
		{
			name:     "object id mismatch",
			grant:    ResourceScope{TenantID: "tenant-a", ObjectType: "router", ObjectID: "r1"},
			resource: ResourceScope{TenantID: "tenant-a", ObjectType: "router", ObjectID: "r2"},
		},
		{
			name:     "environment mismatch",
			grant:    ResourceScope{TenantID: "tenant-a", Environment: "staging"},
			resource: ResourceScope{TenantID: "tenant-a", Environment: "production"},
		},
		{
			name:     "narrow grant does not cover missing target field",
			grant:    ResourceScope{TenantID: "tenant-a", SiteID: "site-1"},
			resource: ResourceScope{TenantID: "tenant-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseRequest(RoleViewer, ActionReadResource)
			req.Principal.AllowedScopes = []ResourceScope{tt.grant}
			req.Resource = tt.resource
			decision := Evaluate(req, testNow)
			if decision.Allowed != tt.allowed {
				t.Fatalf("Evaluate() = %+v, want allowed=%v", decision, tt.allowed)
			}
			if !tt.allowed && decision.Code != ReasonDenyScopeMismatch {
				t.Fatalf("code = %q, want %q", decision.Code, ReasonDenyScopeMismatch)
			}
		})
	}
}

func TestSeparationOfDuties(t *testing.T) {
	t.Run("approver cannot approve own high risk operation", func(t *testing.T) {
		req := baseRequest(RoleApprover, ActionApproveOperation)
		req.Risk = RiskHigh
		req.InitiatorID = req.Principal.ID
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenySelfApproval)
	})
	t.Run("approver cannot approve own critical operation", func(t *testing.T) {
		req := baseRequest(RoleApprover, ActionApproveOperation)
		req.Risk = RiskCritical
		req.InitiatorID = req.Principal.ID
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenySelfApproval)
	})
	t.Run("admin cannot approve own critical operation", func(t *testing.T) {
		req := baseRequest(RoleAdmin, ActionApproveOperation)
		req.Risk = RiskCritical
		req.InitiatorID = req.Principal.ID
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenySelfApproval)
	})
	t.Run("high risk approval needs a known initiator", func(t *testing.T) {
		req := baseRequest(RoleApprover, ActionApproveOperation)
		req.Risk = RiskHigh
		req.InitiatorID = ""
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenyInitiatorMissing)
	})
	t.Run("different approver may approve", func(t *testing.T) {
		req := baseRequest(RoleApprover, ActionApproveOperation)
		req.Risk = RiskCritical
		req.InitiatorID = "operator-2"
		assertDecision(t, Evaluate(req, testNow), true, ReasonAllowRolePolicy)
	})
	t.Run("critical execution requires independent approval", func(t *testing.T) {
		req := baseRequest(RoleAdmin, ActionExecuteOperation)
		req.Risk = RiskCritical
		req.ApprovedByID = ""
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenyIndependentApprovalRequired)
		req.ApprovedByID = req.InitiatorID
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenyIndependentApprovalRequired)
		req.ApprovedByID = "approver-2"
		assertDecision(t, Evaluate(req, testNow), true, ReasonAllowRolePolicy)
	})
}

func TestBreakGlass(t *testing.T) {
	valid := func() *BreakGlass {
		return &BreakGlass{
			Explicit:     true,
			Reason:       "restore production connectivity during declared incident",
			IssuedAt:     testNow.Add(-time.Minute),
			ExpiresAt:    testNow.Add(10 * time.Minute),
			AuditEnabled: true,
		}
	}
	base := func() Request {
		req := baseRequest(RoleViewer, ActionExecuteOperation)
		req.Principal.BreakGlassEligible = true
		req.Risk = RiskHigh
		req.BreakGlass = valid()
		return req
	}

	t.Run("eligible principal receives bounded elevation", func(t *testing.T) {
		decision := Evaluate(base(), testNow)
		assertDecision(t, decision, true, ReasonAllowBreakGlass)
		if !decision.BreakGlass {
			t.Fatal("decision must identify break-glass use")
		}
	})

	tests := []struct {
		name string
		edit func(*Request)
		code ReasonCode
	}{
		{"not eligible", func(r *Request) { r.Principal.BreakGlassEligible = false }, ReasonDenyBreakGlassNotEligible},
		{"not explicit", func(r *Request) { r.BreakGlass.Explicit = false }, ReasonDenyBreakGlassNotExplicit},
		{"reason missing", func(r *Request) { r.BreakGlass.Reason = "  " }, ReasonDenyBreakGlassReasonMissing},
		{"reason too large", func(r *Request) { r.BreakGlass.Reason = string(make([]byte, 513)) }, ReasonDenyBreakGlassReasonMissing},
		{"audit disabled", func(r *Request) { r.BreakGlass.AuditEnabled = false }, ReasonDenyBreakGlassAuditRequired},
		{"issued in future", func(r *Request) { r.BreakGlass.IssuedAt = testNow.Add(time.Second) }, ReasonDenyBreakGlassTimeInvalid},
		{"expiry before issue", func(r *Request) { r.BreakGlass.ExpiresAt = r.BreakGlass.IssuedAt }, ReasonDenyBreakGlassTimeInvalid},
		{"expired", func(r *Request) { r.BreakGlass.ExpiresAt = testNow }, ReasonDenyBreakGlassExpired},
		{"too long", func(r *Request) {
			r.BreakGlass.ExpiresAt = r.BreakGlass.IssuedAt.Add(MaxBreakGlassDuration + time.Nanosecond)
		}, ReasonDenyBreakGlassDurationExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base()
			tt.edit(&req)
			assertDecision(t, Evaluate(req, testNow), false, tt.code)
		})
	}

	t.Run("cannot disable audit", func(t *testing.T) {
		req := base()
		req.Action = ActionDisableAudit
		req.Risk = ""
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenyAuditDisableForbidden)
	})
	t.Run("cannot bypass self approval", func(t *testing.T) {
		req := base()
		req.Action = ActionApproveOperation
		req.Risk = RiskCritical
		req.InitiatorID = req.Principal.ID
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenySelfApproval)
	})
	t.Run("cannot authorize unknown action", func(t *testing.T) {
		req := base()
		req.Action = "system.unbounded"
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenyUnknownAction)
	})
	t.Run("cannot cross tenant boundary", func(t *testing.T) {
		req := base()
		req.Resource.TenantID = "tenant-b"
		assertDecision(t, Evaluate(req, testNow), false, ReasonDenyScopeMismatch)
	})
}

func TestEvaluateIsSafeForConcurrentUse(t *testing.T) {
	req := baseRequest(RoleAdmin, ActionCreateOperation)
	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range 100 {
				decision := Evaluate(req, testNow)
				if !decision.Allowed || decision.Code != ReasonAllowRolePolicy {
					t.Errorf("unexpected decision: %+v", decision)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func baseRequest(role Role, action Action) Request {
	risk := Risk("")
	if requiresRisk(action) {
		risk = RiskLow
	}
	return Request{
		Principal: Principal{
			ID:       "principal-1",
			TenantID: "tenant-a",
			Roles:    []Role{role},
			AllowedScopes: []ResourceScope{{
				TenantID: "tenant-a",
			}},
		},
		Action:      action,
		Resource:    ResourceScope{TenantID: "tenant-a", SiteID: "site-1", ObjectType: "router", ObjectID: "r1", Environment: "production"},
		Risk:        risk,
		InitiatorID: "operator-1",
	}
}

func assertDecision(t *testing.T, got Decision, allowed bool, code ReasonCode) {
	t.Helper()
	if got.Allowed != allowed || got.Code != code {
		t.Fatalf("decision = %+v, want allowed=%v code=%q", got, allowed, code)
	}
	if !allowed && got.BreakGlass {
		t.Fatalf("denied decision must not be marked break-glass: %+v", got)
	}
}
