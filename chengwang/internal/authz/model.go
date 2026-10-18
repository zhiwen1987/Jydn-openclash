// Package authz provides deterministic authorization decisions for Chengwang.
//
// It deliberately does not authenticate principals or parse passwords, API
// keys, sessions, or JWTs. Callers must establish identity and roles before
// constructing a Principal. A zero-value request always fails closed.
package authz

import "time"

// Role is a coarse-grained responsibility assigned by a trusted identity
// system. ResourceScope narrows every role grant.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleApprover Role = "approver"
	RoleAuditor  Role = "auditor"
	RoleAdmin    Role = "admin"
)

// Action is an operation evaluated by the authorization policy. Unknown
// actions are denied; adding a constant alone does not grant it to any role.
type Action string

const (
	ActionReadResource     Action = "resource.read"
	ActionReadEvidence     Action = "evidence.read"
	ActionCreateDraft      Action = "draft.create"
	ActionCreateOperation  Action = "operation.create"
	ActionExecuteOperation Action = "operation.execute"
	ActionApproveOperation Action = "operation.approve"
	ActionDisableAudit     Action = "audit.disable"
)

// Risk is the immutable risk classification of a draft or operation.
type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// ResourceScope identifies a target or a grant. TenantID is always required.
// Empty optional fields in a grant mean all values within that tenant. A
// non-empty grant field must exactly match the corresponding target field.
type ResourceScope struct {
	TenantID    string `json:"tenantId"`
	SiteID      string `json:"siteId,omitempty"`
	ObjectType  string `json:"objectType,omitempty"`
	ObjectID    string `json:"objectId,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// Principal is an already authenticated identity. Authorization never trusts
// a caller merely because a role string is present: identity, tenant, roles,
// and at least one matching AllowedScope are all required.
type Principal struct {
	ID                 string          `json:"id"`
	TenantID           string          `json:"tenantId"`
	Roles              []Role          `json:"roles"`
	AllowedScopes      []ResourceScope `json:"allowedScopes"`
	BreakGlassEligible bool            `json:"breakGlassEligible"`
}

// BreakGlass is an explicit, bounded emergency elevation request. It can
// override ordinary role permissions only. It cannot override tenant/scope,
// unknown-action, audit, or separation-of-duty gates.
type BreakGlass struct {
	Explicit     bool      `json:"explicit"`
	Reason       string    `json:"reason"`
	IssuedAt     time.Time `json:"issuedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	AuditEnabled bool      `json:"auditEnabled"`
}

// Request contains only authorization facts. InitiatorID identifies the
// creator of an operation. ApprovedByID is required when executing a critical
// operation and must identify a different principal.
type Request struct {
	Principal    Principal     `json:"principal"`
	Action       Action        `json:"action"`
	Resource     ResourceScope `json:"resource"`
	Risk         Risk          `json:"risk,omitempty"`
	InitiatorID  string        `json:"initiatorId,omitempty"`
	ApprovedByID string        `json:"approvedById,omitempty"`
	BreakGlass   *BreakGlass   `json:"breakGlass,omitempty"`
}

// ReasonCode is stable machine-readable policy output.
type ReasonCode string

const (
	ReasonAllowRolePolicy                 ReasonCode = "allow_role_policy"
	ReasonAllowBreakGlass                 ReasonCode = "allow_break_glass"
	ReasonDenyIdentityMissing             ReasonCode = "deny_identity_missing"
	ReasonDenyTenantMissing               ReasonCode = "deny_tenant_missing"
	ReasonDenyRoleMissing                 ReasonCode = "deny_role_missing"
	ReasonDenyUnknownRole                 ReasonCode = "deny_unknown_role"
	ReasonDenyUnknownAction               ReasonCode = "deny_unknown_action"
	ReasonDenyRiskMissing                 ReasonCode = "deny_risk_missing"
	ReasonDenyUnknownRisk                 ReasonCode = "deny_unknown_risk"
	ReasonDenyScopeMissing                ReasonCode = "deny_scope_missing"
	ReasonDenyScopeMismatch               ReasonCode = "deny_scope_mismatch"
	ReasonDenyRoleNotPermitted            ReasonCode = "deny_role_not_permitted"
	ReasonDenyRiskNotPermitted            ReasonCode = "deny_risk_not_permitted"
	ReasonDenyInitiatorMissing            ReasonCode = "deny_initiator_missing"
	ReasonDenySelfApproval                ReasonCode = "deny_self_approval"
	ReasonDenyIndependentApprovalRequired ReasonCode = "deny_independent_approval_required"
	ReasonDenyAuditDisableForbidden       ReasonCode = "deny_audit_disable_forbidden"
	ReasonDenyBreakGlassNotEligible       ReasonCode = "deny_break_glass_not_eligible"
	ReasonDenyBreakGlassNotExplicit       ReasonCode = "deny_break_glass_not_explicit"
	ReasonDenyBreakGlassReasonMissing     ReasonCode = "deny_break_glass_reason_missing"
	ReasonDenyBreakGlassTimeInvalid       ReasonCode = "deny_break_glass_time_invalid"
	ReasonDenyBreakGlassExpired           ReasonCode = "deny_break_glass_expired"
	ReasonDenyBreakGlassDurationExceeded  ReasonCode = "deny_break_glass_duration_exceeded"
	ReasonDenyBreakGlassAuditRequired     ReasonCode = "deny_break_glass_audit_required"
)

// Decision is intentionally small: callers persist the stable reason code in
// the evidence log and must not infer permission from an empty error.
type Decision struct {
	Allowed    bool       `json:"allowed"`
	Code       ReasonCode `json:"code"`
	BreakGlass bool       `json:"breakGlass"`
}

// MaxBreakGlassDuration is the longest emergency elevation window accepted by
// this package. Renewals require a new explicit decision and audit record.
const MaxBreakGlassDuration = 15 * time.Minute
