// Package operation contains the in-process operation lifecycle used to make
// potentially disruptive changes explicit and auditable.
//
// The package deliberately does not accept arbitrary event metadata. Events
// contain lifecycle facts only, so callers cannot accidentally persist request
// headers, credentials, configuration bodies, or other secret-bearing fields.
package operation

import "time"

// Status is the lifecycle state of an operation.
type Status string

const (
	StatusPlanned          Status = "planned"
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusPrechecking      Status = "prechecking"
	StatusExecuting        Status = "executing"
	StatusVerifying        Status = "verifying"
	StatusObserving        Status = "observing"
	StatusSucceeded        Status = "succeeded"
	StatusPartial          Status = "partial"
	StatusRolledBack       Status = "rolled_back"
	StatusFailed           Status = "failed"
	StatusManualTakeover   Status = "manual_takeover"
)

// Risk is the declared operational risk. It is immutable after creation.
type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// IdentityBinding records whether the initiator was durably bound from an
// authenticated principal when the operation was created. Legacy snapshots
// predate that guarantee and are preserved read-only instead of guessing an
// identity during migration.
type IdentityBinding string

const (
	IdentityBindingDurable       IdentityBinding = "durable"
	IdentityBindingLegacyUnbound IdentityBinding = "legacy_unbound"
)

// CreateRequest contains the immutable identity and execution boundary of an
// operation. IdempotencyKey is scoped to one store; FileStore persists that
// association across restarts of its single controller.
type CreateRequest struct {
	IdempotencyKey string `json:"idempotencyKey"`
	InitiatorID    string `json:"initiatorId"`
	Environment    string `json:"environment"`
	Scope          string `json:"scope"`
	TargetVersion  string `json:"targetVersion"`
	Risk           Risk   `json:"risk"`
}

// Event records a single accepted state transition. Sequence starts at one
// and is strictly increasing within an operation.
type Event struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
	From     Status    `json:"from,omitempty"`
	To       Status    `json:"to"`
	Reason   string    `json:"reason"`
}

// Operation is an immutable request plus its current lifecycle and events.
// Store methods return detached copies so callers cannot mutate stored state.
type Operation struct {
	ID              string          `json:"id"`
	InitiatorID     string          `json:"initiatorId,omitempty"`
	ApprovedByID    string          `json:"approvedById,omitempty"`
	IdentityBinding IdentityBinding `json:"identityBinding"`
	Environment     string          `json:"environment"`
	Scope           string          `json:"scope"`
	TargetVersion   string          `json:"targetVersion"`
	Risk            Risk            `json:"risk"`
	Status          Status          `json:"status"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	Events          []Event         `json:"events"`
}

// Terminal reports whether no further state transition may be accepted.
func (o Operation) Terminal() bool { return IsTerminal(o.Status) }

// IsTerminal reports whether status completes the operation lifecycle.
func IsTerminal(status Status) bool {
	switch status {
	case StatusSucceeded, StatusPartial, StatusRolledBack, StatusFailed, StatusManualTakeover:
		return true
	default:
		return false
	}
}
