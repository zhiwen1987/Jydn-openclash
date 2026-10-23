// Package subscription implements the private subscription admission core.
// Parsing, fetching and local admission do not prove node availability and
// cannot publish a configuration, mutate a pool, or execute a device action.
package subscription

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const (
	MaxInputBytes   = 1 << 20
	MaxNodes        = 1024
	MaxSources      = 32
	MaxCandidates   = 64
	MaxStoreBytes   = 16 << 20
	MaxScalarBytes  = 4096
	MaxDepth        = 16
	MaxSyntaxNodes  = 32768
	MaxAuditEntries = 4096
)

type Code string

const (
	CodeInputInvalid        Code = "subscription_input_invalid"
	CodeInputLimit          Code = "subscription_input_limit"
	CodeFormatUnsupported   Code = "subscription_format_unsupported"
	CodeProtocolUnsupported Code = "subscription_protocol_unsupported"
	CodeEmpty               Code = "subscription_empty"
	CodeConflict            Code = "subscription_conflict"
	CodeScopeDenied         Code = "subscription_scope_denied"
	CodeNotFound            Code = "subscription_not_found"
	CodeStoreUnsafe         Code = "subscription_store_unsafe"
	CodeStoreLocked         Code = "subscription_store_locked"
	CodeStoreClosed         Code = "subscription_store_closed"
	CodeStoreLimit          Code = "subscription_store_limit"
	CodeCommitUncertain     Code = "subscription_commit_uncertain"
	CodeFetchPolicy         Code = "subscription_fetch_policy_rejected"
	CodeFetchUnavailable    Code = "subscription_fetch_unavailable"
	CodeFetchHTTP           Code = "subscription_fetch_http_rejected"
	CodeFetchRateLimited    Code = "subscription_fetch_rate_limited"
)

// Failure retains no URL, parser fragment, credential or upstream error.
type Failure struct{ Code Code }

func (e *Failure) Error() string { return string(e.Code) }
func fail(code Code) error       { return &Failure{Code: code} }

type Scope struct {
	TenantID    string `json:"tenantId"`
	SiteID      string `json:"siteId"`
	Environment string `json:"environment"`
}

var scopePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var sourcePattern = regexp.MustCompile(`^src_[a-f0-9]{32}$`)
var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{15,127}$`)

func validScope(scope Scope) bool {
	return scopePart.MatchString(scope.TenantID) && scopePart.MatchString(scope.SiteID) && scopePart.MatchString(scope.Environment)
}
func validSource(id string) bool { return sourcePattern.MatchString(id) }
func scopeKey(scope Scope) string {
	return scope.TenantID + "\x00" + scope.SiteID + "\x00" + scope.Environment
}

type Format string

const (
	FormatAuto      Format = "auto"
	FormatMihomo    Format = "mihomo-provider-yaml"
	FormatURI       Format = "uri-list"
	FormatBase64URI Format = "base64-uri-list"
)

// ParseInput is private ingress. JSON encoding cannot export content or key.
type ParseInput struct {
	Scope       Scope  `json:"scope"`
	SourceID    string `json:"sourceId"`
	Format      Format `json:"format"`
	Content     []byte `json:"-"`
	IdentityKey []byte `json:"-"`
}

func (ParseInput) String() string   { return "subscription private parse input" }
func (ParseInput) GoString() string { return "subscription private parse input" }

// ParsedNode is a private adapter record. Config is the canonical node object
// including credentials; only a deliberately private persistence DTO may encode
// it. Original names are private too: imported names can contain secrets.
type ParsedNode struct {
	ID                   string          `json:"id"`
	Protocol             string          `json:"protocol"`
	PrivateName          string          `json:"-"`
	Config               json.RawMessage `json:"-"`
	CredentialConfigured bool            `json:"credentialConfigured"`
}

func (ParsedNode) String() string   { return "subscription private parsed node" }
func (ParsedNode) GoString() string { return "subscription private parsed node" }

type Parsed struct {
	Format         Format       `json:"format"`
	Digest         string       `json:"digest"`
	Nodes          []ParsedNode `json:"-"`
	DuplicateCount int          `json:"duplicateCount"`
}

func (Parsed) String() string   { return "subscription private parsed content" }
func (Parsed) GoString() string { return "subscription private parsed content" }

type NodeView struct {
	ID                   string `json:"id"`
	Label                string `json:"label"`
	Protocol             string `json:"protocol"`
	CredentialConfigured bool   `json:"credentialConfigured"`
	State                string `json:"state"`
}

func nodeView(node ParsedNode) NodeView {
	label := "节点"
	if len(node.ID) >= 12 {
		label += "-" + node.ID[len(node.ID)-8:]
	}
	return NodeView{ID: node.ID, Label: label, Protocol: node.Protocol, CredentialConfigured: node.CredentialConfigured, State: "unknown"}
}

// keyedDigest is opaque outside this private store. Plain hashes of passwords
// or name/index-based IDs must not become publicly enumerable node identities.
func keyedDigest(key []byte, fields ...[]byte) string {
	h := hmac.New(sha256.New, key)
	for _, field := range fields {
		// Length-free separators are unambiguous because the private byte fields
		// are each separately hashed before inclusion.
		digest := sha256.Sum256(field)
		_, _ = h.Write(digest[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

type CandidateState string

const (
	CandidateQuarantined CandidateState = "quarantined"
	CandidateAdmitted    CandidateState = "admitted_local"
	CandidateRejected    CandidateState = "rejected"
)

type SourceView struct {
	ID                  string    `json:"id"`
	Scope               Scope     `json:"scope"`
	Label               string    `json:"label"`
	Revision            uint64    `json:"revision"`
	AcceptedCandidateID string    `json:"acceptedCandidateId,omitempty"`
	LatestCandidateID   string    `json:"latestCandidateId,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type CandidateView struct {
	ID             string         `json:"id"`
	SourceID       string         `json:"sourceId"`
	Scope          Scope          `json:"scope"`
	Digest         string         `json:"digest"`
	Format         Format         `json:"format"`
	State          CandidateState `json:"state"`
	BaseRevision   uint64         `json:"baseRevision"`
	NodeCount      int            `json:"nodeCount"`
	DuplicateCount int            `json:"duplicateCount"`
	Nodes          []NodeView     `json:"nodes"`
	CreatedAt      time.Time      `json:"createdAt"`
}

type ImportRequest struct {
	Scope            Scope
	SourceID         string
	ExpectedRevision uint64
	ActorID          string
	IdempotencyKey   string
	Format           Format
	Content          []byte `json:"-"`
}

func (ImportRequest) String() string   { return "subscription private import request" }
func (ImportRequest) GoString() string { return "subscription private import request" }

type DecisionRequest struct {
	Scope            Scope
	SourceID         string
	CandidateID      string
	ExpectedRevision uint64
	ExpectedDigest   string
	ActorID          string
	IdempotencyKey   string
	Decision         CandidateState // admitted_local or rejected; never a device action.
}

// Actor and idempotency values come from an authenticated caller in a future
// product adapter. The core does not authenticate a user or grant API rights.
func validActor(value string) bool { return scopePart.MatchString(value) }
func validIdempotency(value string) bool {
	return strings.TrimSpace(value) == value && idempotencyPattern.MatchString(value)
}
