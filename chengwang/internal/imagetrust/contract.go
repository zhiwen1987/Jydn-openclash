// Package imagetrust defines the Go 1.23 product API boundary for the optional
// isolated Go 1.25 managed verification backend. DTOs never confer deployment
// authority. No implementation, bootstrap key or Registry credential lives here.
package imagetrust

import (
	"chengwang/internal/authz"
	"context"
)

const (
	MaxCatalogueBytes  = 256 << 10
	MaxApprovalBytes   = 64 << 10
	MaxBundleBytes     = 1 << 20
	MaxRootBytes       = 1 << 20
	MaxVerifyBodyBytes = 3 << 20
	StatusBoundary     = "ADVISORY_TRUST_POLICY_STATE"
	VerifiedBoundary   = "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND"
	HistoryBoundary    = "ADVISORY_TRUST_OPERATION_HISTORY"
)

type Code string

const (
	CodeInvalid       Code = "image_trust_invalid"
	CodeForbidden     Code = "image_trust_forbidden"
	CodeLocked        Code = "image_trust_writes_disabled"
	CodeUnavailable   Code = "image_trust_unavailable"
	CodeConflict      Code = "image_trust_conflict"
	CodeBusy          Code = "image_trust_busy"
	CodeAuditDegraded Code = "image_trust_audit_degraded"
	CodeCanceled      Code = "image_trust_canceled"
)

// Error contains only safe classifications. StateMayHaveChanged is never a
// successful outcome and must not cause automatic retry or grant recreation.
type Error struct {
	Code                Code
	StateMayHaveChanged bool
}

func (e *Error) Error() string {
	if e == nil {
		return string(CodeUnavailable)
	}
	return string(e.Code)
}

type PolicyStatus struct {
	PolicyID       string `json:"policyId"`
	GrantID        string `json:"grantId"`
	Revision       uint64 `json:"revision"`
	ManifestSHA256 string `json:"manifestSHA256"`
	State          string `json:"state"`
}

type Status struct {
	Boundary               string         `json:"boundary"`
	Authorization          string         `json:"authorization"`
	DeviceActionsExecuted  bool           `json:"deviceActionsExecuted"`
	Healthy                bool           `json:"healthy"`
	Fresh                  bool           `json:"fresh"`
	StoreID                string         `json:"storeId"`
	Generation             uint64         `json:"generation"`
	CatalogueSHA256        string         `json:"catalogueSHA256"`
	NotAfterUnix           int64          `json:"notAfterUnix"`
	Sequence               uint64         `json:"sequence"`
	LedgerEntries          int            `json:"ledgerEntries"`
	LedgerCapacity         int            `json:"ledgerCapacity"`
	Reserved               int            `json:"reserved"`
	Consumed               int            `json:"consumed"`
	RevokedKeys            int            `json:"revokedKeys"`
	RevokedApprovals       int            `json:"revokedApprovals"`
	RevokedManifests       int            `json:"revokedManifests"`
	Policies               []PolicyStatus `json:"policies"`
	RefreshRequired        bool           `json:"refreshRequired"`
	RefreshFresh           bool           `json:"refreshFresh"`
	RefreshLastSuccessUnix int64          `json:"refreshLastSuccessUnix"`
	RefreshUntilUnix       int64          `json:"refreshUntilUnix"`
	RecoveryCompleted      int            `json:"recoveryCompleted"`
	ObservedAtUnix         int64          `json:"observedAtUnix"`
	AuditVerifiedAtUnix    int64          `json:"auditVerifiedAtUnix"`
}

type HistoryRequest struct {
	Limit    int
	Offset   int
	Sequence uint64
}

type HistoryEntry struct {
	OperationID       string `json:"operationId"`
	ActorID           string `json:"actorId"`
	Kind              string `json:"kind"`
	State             string `json:"state"`
	Outcome           string `json:"outcome"`
	Acknowledged      bool   `json:"acknowledged"`
	PolicyID          string `json:"policyId"`
	GrantID           string `json:"grantId"`
	Generation        uint64 `json:"generation"`
	CatalogueSHA256   string `json:"catalogueSHA256"`
	PreparedAuditHash string `json:"preparedAuditHash"`
	ResultAuditHash   string `json:"resultAuditHash"`
	PreparedAtUnix    int64  `json:"preparedAtUnix"`
	ResultAtUnix      int64  `json:"resultAtUnix"`
}

// History is a detached read projection. Audit timestamps of zero mean unknown,
// not an inferred operation time. Sequence fences pagination against changes.
type History struct {
	Boundary              string         `json:"boundary"`
	Authorization         string         `json:"authorization"`
	DeviceActionsExecuted bool           `json:"deviceActionsExecuted"`
	ObservedAtUnix        int64          `json:"observedAtUnix"`
	Sequence              uint64         `json:"sequence"`
	Total                 int            `json:"total"`
	Offset                int            `json:"offset"`
	Limit                 int            `json:"limit"`
	Entries               []HistoryEntry `json:"entries"`
}

// VerifyRequest does not accept a principal, scope, URL, Registry roots/token,
// grant ID, bootstrap anchor, current time or caller-chosen operation nonce.
type VerifyRequest struct {
	PolicyID    string `json:"policyId"`
	Approval    []byte `json:"approval"`
	Bundle      []byte `json:"bundle"`
	TrustedRoot []byte `json:"trustedRoot"`
}

// Receipt is a sanitized observation, not an opaque ManagedResult or permit.
// It must never be deserialized and passed to a device executor as authority.
type Receipt struct {
	Boundary              string `json:"boundary"`
	Authorization         string `json:"authorization"`
	DeviceActionsExecuted bool   `json:"deviceActionsExecuted"`
	Verified              bool   `json:"verified"`
	GrantID               string `json:"grantId"`
	CatalogueSHA256       string `json:"catalogueSHA256"`
	Generation            uint64 `json:"generation"`
	ManifestSHA256        string `json:"manifestSHA256"`
	EvidenceSHA256        string `json:"evidenceSHA256"`
}

// Scope is a constant-cost, immutable trusted configuration getter. Each
// operation rechecks RBAC, fixed scope and its own write gate. HTTP checks do
// not replace backend authorization. Implementations do not own their Stores.
type Backend interface {
	Scope() authz.ResourceScope
	Status(context.Context, authz.Principal) (Status, error)
	Update(context.Context, authz.Principal, []byte) (Status, error)
	Verify(context.Context, authz.Principal, VerifyRequest) (Receipt, error)
}

// HistoryBackend is optional so existing product backends cannot accidentally
// expose journal records merely because they implement the mutation interface.
type HistoryBackend interface {
	History(context.Context, authz.Principal, HistoryRequest) (History, error)
}
