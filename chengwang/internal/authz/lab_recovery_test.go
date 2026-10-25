package authz

import (
	"reflect"
	"testing"
	"time"
)

// All new cases are policy MODELs. IDs/roles are supplied facts, not actual
// credential authentication, durable approval, owned stop/start or recovery.
func labRecoveryModelRequest(role Role, action Action) Request {
	scope := ResourceScope{TenantID: "tenant-a", SiteID: "site-a", ObjectType: "mihomo-lab", ObjectID: "lab-a", Environment: "isolated-lab"}
	return Request{Principal: Principal{ID: "actor-a", TenantID: scope.TenantID, Roles: []Role{role}, AllowedScopes: []ResourceScope{scope}},
		Action: action, Resource: scope, Risk: RiskCritical, InitiatorID: "initiator-a", ApprovedByID: "actor-a"}
}

func labRecoveryModelActions() []Action {
	return []Action{ActionReadLabRecovery, ActionPrepareLabRecovery, ActionApproveLabRecovery, ActionExecuteLabRecovery, ActionRevokeLabRecovery}
}

func TestLabRecoveryModelExactActionAndReasonStrings(t *testing.T) {
	actions := labRecoveryModelActions()
	want := []Action{"mihomo_lab.recovery.read", "mihomo_lab.recovery.prepare", "mihomo_lab.recovery.approve", "mihomo_lab.recovery.execute", "mihomo_lab.recovery.revoke"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatal("MODEL action contract drift")
	}
	reasons := []ReasonCode{ReasonDenyLabRecoveryResourceInvalid, ReasonDenyLabRecoveryCriticalRequired, ReasonDenyLabRecoveryBreakGlassForbidden, ReasonDenyLabRecoveryRevokerMismatch}
	if !reflect.DeepEqual(reasons, []ReasonCode{"deny_lab_recovery_resource_invalid", "deny_lab_recovery_critical_required", "deny_lab_recovery_break_glass_forbidden", "deny_lab_recovery_revoker_mismatch"}) {
		t.Fatal("MODEL reason contract drift")
	}
}

func TestLabRecoveryModelFiveRoleMatrix(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
		for _, action := range labRecoveryModelActions() {
			r := labRecoveryModelRequest(role, action)
			want := action == ActionReadLabRecovery || role == RoleAdmin || role == RoleApprover && (action == ActionApproveLabRecovery || action == ActionRevokeLabRecovery)
			code := ReasonDenyRoleNotPermitted
			if want {
				code = ReasonAllowRolePolicy
			}
			assertDecision(t, Evaluate(r, testNow), want, code)
		}
	}
}

func TestLabRecoveryModelRoleUnionCannotBypassRecoveryInvariants(t *testing.T) {
	for _, roles := range [][]Role{{RoleViewer, RoleAuditor}, {RoleOperator, RoleApprover}, {RoleApprover, RoleViewer, RoleOperator}} {
		r := labRecoveryModelRequest(RoleViewer, ActionExecuteLabRecovery)
		r.Principal.Roles = roles
		assertDecision(t, Evaluate(r, testNow), false, ReasonDenyRoleNotPermitted)
	}
	r := labRecoveryModelRequest(RoleApprover, ActionApproveLabRecovery)
	r.Principal.Roles = []Role{RoleViewer, RoleApprover, RoleAdmin}
	r.InitiatorID = r.Principal.ID
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenySelfApproval)
	r = labRecoveryModelRequest(RoleOperator, ActionPrepareLabRecovery)
	r.Principal.Roles = []Role{RoleOperator, RoleAdmin}
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
}

func TestLabRecoveryModelEveryWriteRequiresExplicitCriticalRisk(t *testing.T) {
	for _, action := range labRecoveryModelActions()[1:] {
		for _, risk := range []Risk{"", RiskLow, RiskMedium, RiskHigh, Risk("future")} {
			r := labRecoveryModelRequest(RoleAdmin, action)
			r.Risk = risk
			want := ReasonDenyLabRecoveryCriticalRequired
			if risk == "" {
				want = ReasonDenyRiskMissing
			}
			if risk == "future" {
				want = ReasonDenyUnknownRisk
			}
			assertDecision(t, Evaluate(r, testNow), false, want)
		}
	}
	r := labRecoveryModelRequest(RoleAuditor, ActionReadLabRecovery)
	r.Risk = ""
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
}

func TestLabRecoveryModelIndependentApprovalCannotBeSelfOrMissing(t *testing.T) {
	for _, role := range []Role{RoleApprover, RoleAdmin} {
		for _, initiator := range []string{"", " ", "actor-a", " actor-a "} {
			r := labRecoveryModelRequest(role, ActionApproveLabRecovery)
			r.InitiatorID = initiator
			want := ReasonDenySelfApproval
			if initiator == "" || initiator == " " {
				want = ReasonDenyInitiatorMissing
			}
			assertDecision(t, Evaluate(r, testNow), false, want)
		}
	}
}

func TestLabRecoveryModelExecuteNeedsDistinctApprovedIdentityFact(t *testing.T) {
	r := labRecoveryModelRequest(RoleAdmin, ActionExecuteLabRecovery)
	r.InitiatorID = ""
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyInitiatorMissing)
	for _, approved := range []string{"", " ", "initiator-a", " initiator-a "} {
		r = labRecoveryModelRequest(RoleAdmin, ActionExecuteLabRecovery)
		r.ApprovedByID = approved
		assertDecision(t, Evaluate(r, testNow), false, ReasonDenyIndependentApprovalRequired)
	}
	r = labRecoveryModelRequest(RoleAdmin, ActionExecuteLabRecovery)
	r.InitiatorID = r.Principal.ID
	r.ApprovedByID = "separate-approver"
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
}

func TestLabRecoveryModelRevokeRequiresMatchingApproverOrAdmin(t *testing.T) {
	for _, approved := range []string{"", " ", "different-approver"} {
		r := labRecoveryModelRequest(RoleApprover, ActionRevokeLabRecovery)
		r.ApprovedByID = approved
		assertDecision(t, Evaluate(r, testNow), false, ReasonDenyLabRecoveryRevokerMismatch)
	}
	r := labRecoveryModelRequest(RoleApprover, ActionRevokeLabRecovery)
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
	r.Principal.Roles = []Role{RoleViewer, RoleApprover}
	r.ApprovedByID = "different-approver"
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyLabRecoveryRevokerMismatch)
	r.Principal.Roles = []Role{RoleApprover, RoleAdmin}
	r.ApprovedByID = ""
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
	r = labRecoveryModelRequest(RoleViewer, ActionRevokeLabRecovery)
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyRoleNotPermitted)
}

func TestLabRecoveryModelAllFiveTargetScopeComponentsAreMandatory(t *testing.T) {
	for _, action := range labRecoveryModelActions() {
		for _, field := range []string{"tenant", "site", "type", "object", "environment"} {
			r := labRecoveryModelRequest(RoleAdmin, action)
			// Keep a matching broad grant so the resource completeness gate,
			// rather than a mismatched explicit grant, must reject the target.
			r.Principal.AllowedScopes = []ResourceScope{{TenantID: "tenant-a"}}
			switch field {
			case "tenant":
				r.Resource.TenantID = ""
			case "site":
				r.Resource.SiteID = ""
			case "type":
				r.Resource.ObjectType = ""
			case "object":
				r.Resource.ObjectID = ""
			case "environment":
				r.Resource.Environment = ""
			}
			want := ReasonDenyLabRecoveryResourceInvalid
			if field == "tenant" {
				want = ReasonDenyTenantMissing
			}
			assertDecision(t, Evaluate(r, testNow), false, want)
		}
	}
}

func TestLabRecoveryModelFiveScopeDriftsCannotCrossGrant(t *testing.T) {
	for _, field := range []string{"tenant", "site", "type", "object", "environment"} {
		r := labRecoveryModelRequest(RoleAdmin, ActionExecuteLabRecovery)
		switch field {
		case "tenant":
			r.Resource.TenantID = "tenant-b"
		case "site":
			r.Resource.SiteID = "site-b"
		case "type":
			r.Resource.ObjectType = "router"
		case "object":
			r.Resource.ObjectID = "lab-b"
		case "environment":
			r.Resource.Environment = "production"
		}
		assertDecision(t, Evaluate(r, testNow), false, ReasonDenyScopeMismatch)
	}
}

func TestLabRecoveryModelFixedLabTypeEnvironmentRejectEvenBroadGrant(t *testing.T) {
	for _, action := range labRecoveryModelActions() {
		for _, field := range []string{"type", "environment", "space-site", "space-object"} {
			r := labRecoveryModelRequest(RoleAdmin, action)
			r.Principal.AllowedScopes = []ResourceScope{{TenantID: "tenant-a"}}
			switch field {
			case "type":
				r.Resource.ObjectType = "router"
			case "environment":
				r.Resource.Environment = "production"
			case "space-site":
				r.Resource.SiteID = " \t"
			case "space-object":
				r.Resource.ObjectID = " \t"
			}
			assertDecision(t, Evaluate(r, testNow), false, ReasonDenyLabRecoveryResourceInvalid)
		}
	}
}

func TestLabRecoveryModelNoBreakGlassCanAuthorizeAnyRecoveryAction(t *testing.T) {
	for _, action := range labRecoveryModelActions() {
		for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin} {
			for _, malformed := range []bool{false, true} {
				r := labRecoveryModelRequest(role, action)
				r.Principal.BreakGlassEligible = true
				r.BreakGlass = &BreakGlass{Explicit: true, Reason: "MODEL emergency", IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute), AuditEnabled: true}
				if malformed {
					r.BreakGlass = &BreakGlass{}
				}
				assertDecision(t, Evaluate(r, testNow), false, ReasonDenyLabRecoveryBreakGlassForbidden)
			}
		}
	}
}

func TestLabRecoveryModelUnknownActionsRolesAndMissingIdentityStayDenied(t *testing.T) {
	r := labRecoveryModelRequest(RoleAdmin, Action("mihomo_lab.recovery.future"))
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyUnknownAction)
	r = labRecoveryModelRequest(RoleAdmin, ActionPrepareLabRecovery)
	r.Principal.Roles = []Role{RoleAdmin, Role("superadmin")}
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyUnknownRole)
	r = labRecoveryModelRequest(RoleAdmin, ActionPrepareLabRecovery)
	r.Principal.ID = ""
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyIdentityMissing)
	r = labRecoveryModelRequest(RoleAdmin, ActionPrepareLabRecovery)
	r.Principal.AllowedScopes = nil
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyScopeMissing)
}

func TestLabRecoveryModelOldOperationApprovalDoesNotAliasRecoveryAction(t *testing.T) {
	// Evaluate proves policy facts only. This checks action separation, not
	// cryptographic approval authenticity or a real authority capability.
	r := baseRequest(RoleOperator, ActionExecuteOperation)
	r.Risk = RiskMedium
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
	r.Action = ActionExecuteLabRecovery
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyLabRecoveryResourceInvalid)
	r = labRecoveryModelRequest(RoleOperator, ActionExecuteLabRecovery)
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyRoleNotPermitted)
	r = labRecoveryModelRequest(RoleApprover, ActionPrepareLabRecovery)
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyRoleNotPermitted)
}

func TestLabRecoveryModelOldCriticalOperationInvariantsRemainUnchanged(t *testing.T) {
	r := baseRequest(RoleAdmin, ActionApproveOperation)
	r.Risk = RiskCritical
	r.InitiatorID = r.Principal.ID
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenySelfApproval)
	r = baseRequest(RoleAdmin, ActionExecuteOperation)
	r.Risk = RiskCritical
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyIndependentApprovalRequired)
	r.ApprovedByID = "separate-approver"
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
	r = baseRequest(RoleOperator, ActionExecuteOperation)
	r.Risk = RiskCritical
	r.ApprovedByID = "separate-approver"
	assertDecision(t, Evaluate(r, testNow), false, ReasonDenyRiskNotPermitted)
}

func TestLabRecoveryModelExistingGrantWildcardsRemainScoped(t *testing.T) {
	for _, action := range labRecoveryModelActions() {
		r := labRecoveryModelRequest(RoleAdmin, action)
		r.Principal.AllowedScopes = []ResourceScope{{TenantID: r.Principal.TenantID}}
		assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
		r.Resource.TenantID = "another-tenant"
		assertDecision(t, Evaluate(r, testNow), false, ReasonDenyScopeMismatch)
	}
	r := baseRequest(RoleViewer, ActionReadResource)
	assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
}

func TestLabRecoveryModelEvaluationDoesNotMutateCallerFacts(t *testing.T) {
	r := labRecoveryModelRequest(RoleAdmin, ActionExecuteLabRecovery)
	roles := append([]Role(nil), r.Principal.Roles...)
	scopes := append([]ResourceScope(nil), r.Principal.AllowedScopes...)
	for range 3 {
		assertDecision(t, Evaluate(r, testNow), true, ReasonAllowRolePolicy)
	}
	if !reflect.DeepEqual(r.Principal.Roles, roles) || !reflect.DeepEqual(r.Principal.AllowedScopes, scopes) {
		t.Fatal("MODEL policy mutated caller facts")
	}
}
