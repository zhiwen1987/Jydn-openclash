package authz

import (
	"strings"
	"time"
)

// Evaluate returns a deterministic, default-deny authorization decision at
// the supplied time. Supplying time explicitly makes expiry decisions
// repeatable and keeps clock access out of policy evaluation.
func Evaluate(request Request, now time.Time) Decision {
	principal := request.Principal
	if strings.TrimSpace(principal.ID) == "" {
		return deny(ReasonDenyIdentityMissing)
	}
	if strings.TrimSpace(principal.TenantID) == "" || strings.TrimSpace(request.Resource.TenantID) == "" {
		return deny(ReasonDenyTenantMissing)
	}
	if !knownAction(request.Action) {
		return deny(ReasonDenyUnknownAction)
	}
	if len(principal.Roles) == 0 {
		return deny(ReasonDenyRoleMissing)
	}
	for _, role := range principal.Roles {
		if !knownRole(role) {
			return deny(ReasonDenyUnknownRole)
		}
	}
	if requiresRisk(request.Action) {
		if request.Risk == "" {
			return deny(ReasonDenyRiskMissing)
		}
		if !knownRisk(request.Risk) {
			return deny(ReasonDenyUnknownRisk)
		}
	}
	if len(principal.AllowedScopes) == 0 {
		return deny(ReasonDenyScopeMissing)
	}
	if !scopeAllowed(principal, request.Resource) {
		return deny(ReasonDenyScopeMismatch)
	}

	// These are invariant safety gates. Emergency elevation cannot bypass them.
	if request.BreakGlass != nil && (request.Action == ActionReadImageTrust || request.Action == ActionUpdateImageTrust || request.Action == ActionVerifyImageTrust || request.Action == ActionHistoryImageTrust) {
		return deny(ReasonDenyImageTrustBreakGlassForbidden)
	}
	if request.Action == ActionDisableAudit {
		return deny(ReasonDenyAuditDisableForbidden)
	}
	if request.Action == ActionApproveOperation &&
		(request.Risk == RiskHigh || request.Risk == RiskCritical) {
		if strings.TrimSpace(request.InitiatorID) == "" {
			return deny(ReasonDenyInitiatorMissing)
		}
		if sameIdentity(principal.ID, request.InitiatorID) {
			return deny(ReasonDenySelfApproval)
		}
	}
	if request.Action == ActionExecuteOperation && request.Risk == RiskCritical {
		if strings.TrimSpace(request.InitiatorID) == "" {
			return deny(ReasonDenyInitiatorMissing)
		}
		if strings.TrimSpace(request.ApprovedByID) == "" || sameIdentity(request.ApprovedByID, request.InitiatorID) {
			return deny(ReasonDenyIndependentApprovalRequired)
		}
	}

	if request.BreakGlass != nil {
		if code := validateBreakGlass(principal, *request.BreakGlass, now.UTC()); code != "" {
			return deny(code)
		}
		return Decision{Allowed: true, Code: ReasonAllowBreakGlass, BreakGlass: true}
	}

	allowed, riskDenied := roleAllows(principal.Roles, request.Action, request.Risk)
	if allowed {
		return Decision{Allowed: true, Code: ReasonAllowRolePolicy}
	}
	if riskDenied {
		return deny(ReasonDenyRiskNotPermitted)
	}
	return deny(ReasonDenyRoleNotPermitted)
}

func deny(code ReasonCode) Decision { return Decision{Code: code} }

func knownRole(role Role) bool {
	switch role {
	case RoleViewer, RoleOperator, RoleApprover, RoleAuditor, RoleAdmin:
		return true
	default:
		return false
	}
}

func knownAction(action Action) bool {
	switch action {
	case ActionReadResource, ActionReadEvidence, ActionCreateDraft,
		ActionCreateOperation, ActionExecuteOperation, ActionApproveOperation,
		ActionDisableAudit, ActionReadImageTrust, ActionUpdateImageTrust, ActionVerifyImageTrust, ActionHistoryImageTrust:
		return true
	default:
		return false
	}
}

func knownRisk(risk Risk) bool {
	switch risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return true
	default:
		return false
	}
}

func requiresRisk(action Action) bool {
	switch action {
	case ActionCreateDraft, ActionCreateOperation, ActionExecuteOperation, ActionApproveOperation:
		return true
	default:
		return false
	}
}

func scopeAllowed(principal Principal, resource ResourceScope) bool {
	if principal.TenantID != resource.TenantID {
		return false
	}
	for _, grant := range principal.AllowedScopes {
		if grant.TenantID != principal.TenantID {
			continue
		}
		if fieldMatches(grant.SiteID, resource.SiteID) &&
			fieldMatches(grant.ObjectType, resource.ObjectType) &&
			fieldMatches(grant.ObjectID, resource.ObjectID) &&
			fieldMatches(grant.Environment, resource.Environment) {
			return true
		}
	}
	return false
}

func fieldMatches(grant, target string) bool {
	return grant == "" || grant == target
}

func roleAllows(roles []Role, action Action, risk Risk) (allowed bool, riskDenied bool) {
	for _, role := range roles {
		switch role {
		case RoleViewer:
			if action == ActionReadResource || action == ActionReadImageTrust {
				return true, false
			}
		case RoleOperator:
			switch action {
			case ActionReadResource, ActionReadImageTrust, ActionVerifyImageTrust:
				return true, false
			case ActionCreateDraft, ActionCreateOperation, ActionExecuteOperation:
				if risk == RiskLow || risk == RiskMedium {
					return true, false
				}
				riskDenied = true
			}
		case RoleApprover:
			if action == ActionReadResource || action == ActionReadEvidence || action == ActionApproveOperation || action == ActionReadImageTrust {
				return true, false
			}
		case RoleAuditor:
			if action == ActionReadEvidence || action == ActionReadImageTrust || action == ActionHistoryImageTrust {
				return true, false
			}
		case RoleAdmin:
			switch action {
			case ActionReadResource, ActionReadEvidence, ActionCreateDraft,
				ActionCreateOperation, ActionExecuteOperation, ActionApproveOperation,
				ActionReadImageTrust, ActionUpdateImageTrust, ActionVerifyImageTrust, ActionHistoryImageTrust:
				return true, false
			}
		}
	}
	return false, riskDenied
}

func validateBreakGlass(principal Principal, emergency BreakGlass, now time.Time) ReasonCode {
	if !principal.BreakGlassEligible {
		return ReasonDenyBreakGlassNotEligible
	}
	if !emergency.Explicit {
		return ReasonDenyBreakGlassNotExplicit
	}
	if strings.TrimSpace(emergency.Reason) == "" || len(emergency.Reason) > 512 {
		return ReasonDenyBreakGlassReasonMissing
	}
	if !emergency.AuditEnabled {
		return ReasonDenyBreakGlassAuditRequired
	}
	issuedAt := emergency.IssuedAt.UTC()
	expiresAt := emergency.ExpiresAt.UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || issuedAt.After(now) || !expiresAt.After(issuedAt) {
		return ReasonDenyBreakGlassTimeInvalid
	}
	if !expiresAt.After(now) {
		return ReasonDenyBreakGlassExpired
	}
	if expiresAt.Sub(issuedAt) > MaxBreakGlassDuration {
		return ReasonDenyBreakGlassDurationExceeded
	}
	return ""
}

func sameIdentity(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	return left != "" && left == right
}
