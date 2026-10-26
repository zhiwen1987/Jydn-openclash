// Package subscriptionctl is the authenticated, local-only subscription
// application boundary. Inventory admission never authorizes device actions.
package subscriptionctl

import (
	"context"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/control"
	"chengwang/internal/subscription"
)

const Boundary = "LOCAL_SUBSCRIPTION_ADMISSION_ONLY"
const MaxPageSize = 100
const MaxCommandRecords = 4096

type Code string

const (
	CodeInvalid          Code = "subscription_command_invalid"
	CodeForbidden        Code = "subscription_forbidden"
	CodeLocked           Code = "subscription_writes_disabled"
	CodeUnavailable      Code = "subscription_unavailable"
	CodeConflict         Code = "subscription_command_conflict"
	CodeNotFound         Code = "subscription_command_not_found"
	CodeAuditDegraded    Code = "subscription_audit_degraded"
	CodeCommitUnknown    Code = "subscription_commit_unknown"
	CodeCanceled         Code = "subscription_command_canceled"
	CodeApprovalRequired Code = "subscription_approval_required"
	CodeLimit            Code = "subscription_command_limit"
	CodeFetchPolicy      Code = "subscription_fetch_policy_rejected"
	CodeFetchUnavailable Code = "subscription_fetch_unavailable"
	CodeFetchHTTP        Code = "subscription_fetch_http_rejected"
	CodeFetchRateLimited Code = "subscription_fetch_rate_limited"
)

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

type Kind string

const (
	Create   Kind = "create"
	Import   Kind = "import"
	Decide   Kind = "decide"
	Rollback Kind = "rollback"
	Approve  Kind = "approve"
	Fetch    Kind = "fetch"
)

// Only the authenticated adapter supplies actor identity. URLs, paths, CA and
// DNS configuration are never accepted as commands from an HTTP client.
type Command struct {
	Kind             Kind
	IdempotencyKey   string `json:"-"`
	SourceID         string
	CandidateID      string
	ExpectedRevision uint64
	ExpectedDigest   string
	Label            string
	Format           subscription.Format
	Content          []byte `json:"-"`
	Decision         subscription.CandidateState
	ReferenceID      string
	PolicyRevision   uint64
	ApprovalID       string
	// Automated fields are package/service inputs from trusted refresh policy;
	// the HTTP decoder never accepts them.
	Automated              bool   `json:"-"`
	ApprovalSourceRevision uint64 `json:"-"`
	ApprovalMaxAgeSeconds  uint64 `json:"-"`
	refreshReference       authn.SnapshotRef
	freshIdentityRequired  bool
}

func (Command) String() string   { return "subscription private command" }
func (Command) GoString() string { return "subscription private command" }

type Receipt struct {
	CommandID           string    `json:"commandId"`
	Kind                Kind      `json:"kind"`
	SourceID            string    `json:"sourceId,omitempty"`
	CandidateID         string    `json:"candidateId,omitempty"`
	Revision            uint64    `json:"revision"`
	CandidateDigest     string    `json:"candidateDigest,omitempty"`
	State               string    `json:"state"`
	Code                Code      `json:"code,omitempty"`
	Replayed            bool      `json:"replayed"`
	StateMayHaveChanged bool      `json:"stateMayHaveChanged"`
	AuditRecorded       bool      `json:"auditRecorded"`
	PreparedAuditHash   string    `json:"preparedAuditHash,omitempty"`
	ResultAuditHash     string    `json:"resultAuditHash,omitempty"`
	LocalAuditHash      string    `json:"localAuditHash,omitempty"`
	ReferenceID         string    `json:"referenceId,omitempty"`
	PolicyRevision      uint64    `json:"policyRevision,omitempty"`
	PolicyDigest        string    `json:"policyDigest,omitempty"`
	ApprovalID          string    `json:"approvalId,omitempty"`
	CompletedAt         time.Time `json:"completedAt,omitempty"`
}

type ListQuery struct {
	Limit, Offset int
	Revision      uint64
}
type SourcePage struct {
	Sources []subscription.SourceView `json:"sources"`
	Total   int                       `json:"total"`
}

// Summary deliberately contains no node array or imported private name.
type CandidateSummary struct {
	ID             string                      `json:"id"`
	SourceID       string                      `json:"sourceId"`
	Digest         string                      `json:"digest"`
	Format         subscription.Format         `json:"format"`
	State          subscription.CandidateState `json:"state"`
	BaseRevision   uint64                      `json:"baseRevision"`
	NodeCount      int                         `json:"nodeCount"`
	DuplicateCount int                         `json:"duplicateCount"`
	CreatedAt      time.Time                   `json:"createdAt"`
}
type CandidatePage struct {
	Candidates []CandidateSummary `json:"candidates"`
	Total      int                `json:"total"`
	Revision   uint64             `json:"revision"`
	NextOffset *int               `json:"nextOffset,omitempty"`
}
type NodePage struct {
	Nodes      []subscription.NodeView `json:"nodes"`
	Total      int                     `json:"total"`
	Revision   uint64                  `json:"revision"`
	NextOffset *int                    `json:"nextOffset,omitempty"`
}

// Material includes ALL effective private inputs (URL, CNAMEs, resolver,
// trust roots and secret version). The service seals it with its persistent
// private identity key and scope/source binding. It must never be returned
// as a plain SHA256 dictionary oracle or serialized to a client/log.
type PolicyDescriptor struct {
	ReferenceID string
	Revision    uint64
	Material    []byte `json:"-"`
}

func (PolicyDescriptor) String() string   { return "subscription private policy descriptor" }
func (PolicyDescriptor) GoString() string { return "subscription private policy descriptor" }

type PolicyProvider interface {
	Describe(string) (PolicyDescriptor, error) // immutable CPU-only metadata
	Fetch(context.Context, subscription.Scope, string, string) (subscription.FetchResult, error)
}

// RefreshPolicyProvider exposes only safe scheduler bindings. Network policy
// and secret material remain behind PolicyProvider.Fetch/Describe.
type RefreshPolicyProvider interface {
	RefreshBindings() ([]subscription.RefreshBinding, error)
}

type RefreshPage struct {
	Refreshes []subscription.RefreshView `json:"refreshes"`
	Total     int                        `json:"total"`
	Capacity  subscription.StoreCapacity `json:"capacity"`
}

type RefreshReader interface {
	ListRefreshes(context.Context, authz.Principal) (RefreshPage, error)
	ReadRefresh(context.Context, authz.Principal, string) (subscription.RefreshView, error)
}

type RefreshIdentityProvider interface {
	TrustedPrincipal(string, time.Time) (authz.Principal, authn.SnapshotRef, error)
	CurrentPrincipal(authn.SnapshotRef, string, time.Time) (authz.Principal, error)
}

type Config struct {
	Scope             authz.ResourceScope
	Store             *subscription.Store           `json:"-"`
	RefreshStore      *subscription.RefreshStore    `json:"-"`
	RefreshRecovery   *subscription.RefreshRecovery `json:"-"`
	RefreshIdentity   RefreshIdentityProvider       `json:"-"`
	RefreshIdentityID string                        `json:"-"`
	Audit             control.EvidenceAppender      `json:"-"`
	Policies          PolicyProvider                `json:"-"`
	WritesEnabled     bool
}

func (Config) String() string   { return "subscription application configuration" }
func (Config) GoString() string { return "subscription application configuration" }

type Backend interface {
	Scope() authz.ResourceScope
	ListSources(context.Context, authz.Principal) (SourcePage, error)
	ListCandidates(context.Context, authz.Principal, string, ListQuery) (CandidatePage, error)
	ListNodes(context.Context, authz.Principal, string, string, ListQuery) (NodePage, error)
	Execute(context.Context, authz.Principal, Command) (Receipt, error)
	ReadReceipt(context.Context, authz.Principal, string) (Receipt, error)
	RecordDenied(context.Context, authz.Principal, authz.Action, Code) error
}

// ActionFor is closed: an unknown command can never fall through to a generic
// resource or operation grant. The constants are implemented in authz.
func ActionFor(kind Kind) authz.Action {
	switch kind {
	case Create:
		return authz.ActionManageSubscriptionSource
	case Import:
		return authz.ActionImportSubscription
	case Decide:
		return authz.ActionDecideSubscription
	case Rollback:
		return authz.ActionRollbackSubscription
	case Approve:
		return authz.ActionApproveSubscriptionSource
	case Fetch:
		return authz.ActionFetchSubscription
	default:
		return ""
	}
}

func Resource(scope authz.ResourceScope, sourceID string) authz.ResourceScope {
	if sourceID != "" {
		scope.ObjectType, scope.ObjectID = "subscription-source", sourceID
	}
	return scope
}
