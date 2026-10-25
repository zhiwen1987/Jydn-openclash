package authz

import "strings"

// These actions describe only recovery policy. Evaluate does not authenticate
// IDs, validate a saved approval, own a process, issue a recovery capability or
// prove that stop/start is safe. The future authority must supply current real
// identities, independent approval and its bound recovery plan at every gate.
func labRecoveryAction(action Action) bool {
	switch action {
	case ActionReadLabRecovery, ActionPrepareLabRecovery, ActionApproveLabRecovery,
		ActionExecuteLabRecovery, ActionRevokeLabRecovery:
		return true
	default:
		return false
	}
}

func labRecoveryResource(resource ResourceScope) bool {
	for _, part := range []string{resource.TenantID, resource.SiteID, resource.ObjectType, resource.ObjectID, resource.Environment} {
		if strings.TrimSpace(part) == "" {
			return false
		}
	}
	return resource.ObjectType == "mihomo-lab" && resource.Environment == "isolated-lab"
}

func labRecoveryHasRole(roles []Role, wanted Role) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}

// Global identity/known-role/tenant/scope validation precedes this action-only
// invariant. No valid emergency token or additional role can bypass it.
func labRecoveryInvariant(request Request) ReasonCode {
	if !labRecoveryResource(request.Resource) {
		return ReasonDenyLabRecoveryResourceInvalid
	}
	if request.BreakGlass != nil {
		return ReasonDenyLabRecoveryBreakGlassForbidden
	}
	if request.Action != ActionReadLabRecovery && request.Risk != RiskCritical {
		return ReasonDenyLabRecoveryCriticalRequired
	}
	switch request.Action {
	case ActionApproveLabRecovery:
		if strings.TrimSpace(request.InitiatorID) == "" {
			return ReasonDenyInitiatorMissing
		}
		if sameIdentity(request.Principal.ID, request.InitiatorID) {
			return ReasonDenySelfApproval
		}
	case ActionExecuteLabRecovery:
		if strings.TrimSpace(request.InitiatorID) == "" {
			return ReasonDenyInitiatorMissing
		}
		if strings.TrimSpace(request.ApprovedByID) == "" || sameIdentity(request.ApprovedByID, request.InitiatorID) {
			return ReasonDenyIndependentApprovalRequired
		}
	case ActionRevokeLabRecovery:
		if !labRecoveryHasRole(request.Principal.Roles, RoleAdmin) && labRecoveryHasRole(request.Principal.Roles, RoleApprover) &&
			!sameIdentity(request.Principal.ID, request.ApprovedByID) {
			return ReasonDenyLabRecoveryRevokerMismatch
		}
	}
	return ""
}

func labRecoveryRoleAllows(role Role, action Action) bool {
	switch action {
	case ActionReadLabRecovery:
		return role == RoleViewer || role == RoleOperator || role == RoleApprover || role == RoleAuditor || role == RoleAdmin
	case ActionPrepareLabRecovery, ActionExecuteLabRecovery:
		return role == RoleAdmin
	case ActionApproveLabRecovery, ActionRevokeLabRecovery:
		return role == RoleApprover || role == RoleAdmin
	default:
		return false
	}
}
