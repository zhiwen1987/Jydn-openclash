package operation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound            = errors.New("operation not found")
	ErrIdempotencyConflict = errors.New("idempotency key reused with a different request")
	ErrInvalidTransition   = errors.New("invalid operation state transition")
	ErrTerminalOperation   = errors.New("terminal operation cannot transition")
	ErrSensitiveReason     = errors.New("transition reason contains a secret-bearing field")
	ErrIdentityUnbound     = errors.New("operation identity is not durably bound")
	ErrApprovalRequired    = errors.New("operation requires an independent durable approval")
	ErrInvalidApprover     = errors.New("approver must be a different authenticated identity")
)

var sensitiveReasonPattern = regexp.MustCompile(`(?i)(authorization|proxy-authorization|password|passwd|token|secret|api[-_ ]?key|cookie|set-cookie)\s*[:=]`)

const (
	maxIdentityBytes      = 128
	maxEnvironmentBytes   = 128
	maxScopeBytes         = 512
	maxTargetVersionBytes = 256
)

type idempotencyRecord struct {
	operationID string
	digest      [sha256.Size]byte
}

// MemoryStore is a concurrency-safe, process-local operation store.
//
// It is intentionally non-persistent and non-distributed: all operations and
// idempotency records are lost on process restart, and multiple processes do
// not coordinate. Production execution must replace it with a durable store
// before operations can survive restarts or run across replicas.
type MemoryStore struct {
	mu          sync.RWMutex
	operations  map[string]*Operation
	idempotency map[string]idempotencyRecord
	now         func() time.Time
	newID       func(time.Time) (string, error)
}

// NewMemoryStore creates an empty process-local operation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		operations:  make(map[string]*Operation),
		idempotency: make(map[string]idempotencyRecord),
		now:         func() time.Time { return time.Now().UTC() },
		newID:       randomOperationID,
	}
}

// Create returns the operation associated with req. created is false when an
// identical request already owns the idempotency key. Reusing that key with a
// different payload returns ErrIdempotencyConflict.
func (s *MemoryStore) Create(req CreateRequest) (operation Operation, created bool, err error) {
	if err := validateCreateRequest(req); err != nil {
		return Operation{}, false, err
	}
	digest, err := requestDigest(req)
	if err != nil {
		return Operation{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.idempotency[req.IdempotencyKey]; ok {
		if record.digest != digest {
			return Operation{}, false, ErrIdempotencyConflict
		}
		return cloneOperation(*s.operations[record.operationID]), false, nil
	}
	if len(s.operations) >= maxOperations || len(s.idempotency) >= maxIdempotencyRecords {
		return Operation{}, false, ErrStoreLimit
	}

	now := s.now().UTC()
	id, err := s.newID(now)
	if err != nil {
		return Operation{}, false, fmt.Errorf("generate operation ID: %w", err)
	}
	if _, exists := s.operations[id]; exists {
		return Operation{}, false, fmt.Errorf("generate operation ID: collision %q", id)
	}
	op := &Operation{
		ID:              id,
		InitiatorID:     strings.TrimSpace(req.InitiatorID),
		IdentityBinding: IdentityBindingDurable,
		Environment:     strings.TrimSpace(req.Environment),
		Scope:           strings.TrimSpace(req.Scope),
		TargetVersion:   strings.TrimSpace(req.TargetVersion),
		Risk:            req.Risk,
		Status:          StatusPlanned,
		CreatedAt:       now,
		UpdatedAt:       now,
		Events: []Event{{
			Sequence: 1,
			At:       now,
			To:       StatusPlanned,
			Reason:   "operation planned",
		}},
	}
	s.operations[id] = op
	s.idempotency[req.IdempotencyKey] = idempotencyRecord{operationID: id, digest: digest}
	return cloneOperation(*op), true, nil
}

// Get returns a detached snapshot of an operation.
func (s *MemoryStore) Get(id string) (Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return cloneOperation(*op), nil
}

// List returns detached snapshots ordered by creation time and then ID.
func (s *MemoryStore) List() []Operation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Operation, 0, len(s.operations))
	for _, op := range s.operations {
		result = append(result, cloneOperation(*op))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// Transition atomically applies an allowed state transition and appends an
// event. reason is required and length-bounded; no arbitrary metadata or
// secret-bearing fields are accepted by this API.
func (s *MemoryStore) Transition(id string, to Status, reason string) (Operation, error) {
	return s.TransitionWithApproval(id, to, reason, "")
}

// TransitionWithApproval atomically binds approverID only for a successful
// awaiting_approval -> prechecking transition. The durable initiator and
// approver identities are immutable afterwards.
func (s *MemoryStore) TransitionWithApproval(id string, to Status, reason, approverID string) (Operation, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Operation{}, errors.New("transition reason is required")
	}
	if len(reason) > 512 {
		return Operation{}, errors.New("transition reason exceeds 512 bytes")
	}
	if sensitiveReasonPattern.MatchString(reason) {
		return Operation{}, ErrSensitiveReason
	}
	if !isKnownStatus(to) {
		return Operation{}, fmt.Errorf("%w: unknown destination %q", ErrInvalidTransition, to)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if len(op.Events) >= maxEventsPerOperation {
		return Operation{}, ErrStoreLimit
	}
	if IsTerminal(op.Status) {
		return Operation{}, fmt.Errorf("%w: %s", ErrTerminalOperation, op.Status)
	}
	if !allowedTransitions[op.Status][to] {
		return Operation{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, op.Status, to)
	}
	approvalID, err := validateIdentityTransition(*op, to, approverID)
	if err != nil {
		return Operation{}, err
	}

	now := s.now().UTC()
	if now.Before(op.UpdatedAt) {
		// Preserve monotonic event timestamps even if the wall clock moves back.
		now = op.UpdatedAt
	}
	from := op.Status
	op.Status = to
	if approvalID != "" {
		op.ApprovedByID = approvalID
	}
	op.UpdatedAt = now
	op.Events = append(op.Events, Event{
		Sequence: uint64(len(op.Events) + 1),
		At:       now,
		From:     from,
		To:       to,
		Reason:   reason,
	})
	return cloneOperation(*op), nil
}

// AllowedTransitions returns a copy of the explicit next-state set.
func AllowedTransitions(from Status) []Status {
	next := allowedTransitions[from]
	result := make([]Status, 0, len(next))
	for status, allowed := range next {
		if allowed {
			result = append(result, status)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

var allowedTransitions = map[Status]map[Status]bool{
	StatusPlanned: {
		StatusAwaitingApproval: true,
		StatusPrechecking:      true,
		StatusFailed:           true,
		StatusManualTakeover:   true,
	},
	StatusAwaitingApproval: {
		StatusPrechecking:    true,
		StatusFailed:         true,
		StatusManualTakeover: true,
	},
	StatusPrechecking: {
		StatusExecuting:      true,
		StatusFailed:         true,
		StatusManualTakeover: true,
	},
	StatusExecuting: {
		StatusVerifying:      true,
		StatusPartial:        true,
		StatusRolledBack:     true,
		StatusFailed:         true,
		StatusManualTakeover: true,
	},
	StatusVerifying: {
		StatusObserving:      true,
		StatusSucceeded:      true,
		StatusPartial:        true,
		StatusRolledBack:     true,
		StatusFailed:         true,
		StatusManualTakeover: true,
	},
	StatusObserving: {
		StatusSucceeded:      true,
		StatusPartial:        true,
		StatusRolledBack:     true,
		StatusFailed:         true,
		StatusManualTakeover: true,
	},
}

func isKnownStatus(status Status) bool {
	switch status {
	case StatusPlanned, StatusAwaitingApproval, StatusPrechecking, StatusExecuting,
		StatusVerifying, StatusObserving, StatusSucceeded, StatusPartial,
		StatusRolledBack, StatusFailed, StatusManualTakeover:
		return true
	default:
		return false
	}
}

func validateCreateRequest(req CreateRequest) error {
	switch {
	case strings.TrimSpace(req.IdempotencyKey) == "":
		return errors.New("idempotency key is required")
	case len(req.IdempotencyKey) > 200:
		return errors.New("idempotency key exceeds 200 bytes")
	case strings.TrimSpace(req.InitiatorID) == "":
		return errors.New("initiator identity is required")
	case req.InitiatorID != strings.TrimSpace(req.InitiatorID):
		return errors.New("initiator identity must be normalized")
	case len(req.InitiatorID) > maxIdentityBytes:
		return fmt.Errorf("%w: initiator identity exceeds %d bytes", ErrStoreLimit, maxIdentityBytes)
	case strings.TrimSpace(req.Environment) == "":
		return errors.New("environment is required")
	case len(req.Environment) > maxEnvironmentBytes:
		return fmt.Errorf("%w: environment exceeds %d bytes", ErrStoreLimit, maxEnvironmentBytes)
	case strings.TrimSpace(req.Scope) == "":
		return errors.New("scope is required")
	case len(req.Scope) > maxScopeBytes:
		return fmt.Errorf("%w: scope exceeds %d bytes", ErrStoreLimit, maxScopeBytes)
	case strings.TrimSpace(req.TargetVersion) == "":
		return errors.New("target version is required")
	case len(req.TargetVersion) > maxTargetVersionBytes:
		return fmt.Errorf("%w: target version exceeds %d bytes", ErrStoreLimit, maxTargetVersionBytes)
	}
	switch req.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return nil
	default:
		return fmt.Errorf("unsupported risk %q", req.Risk)
	}
}

func requestDigest(req CreateRequest) ([sha256.Size]byte, error) {
	// Hash a normalized immutable payload. The key itself identifies the record
	// and is intentionally excluded from the comparison payload.
	payload := struct {
		InitiatorID   string `json:"initiatorId"`
		Environment   string `json:"environment"`
		Scope         string `json:"scope"`
		TargetVersion string `json:"targetVersion"`
		Risk          Risk   `json:"risk"`
	}{
		InitiatorID:   strings.TrimSpace(req.InitiatorID),
		Environment:   strings.TrimSpace(req.Environment),
		Scope:         strings.TrimSpace(req.Scope),
		TargetVersion: strings.TrimSpace(req.TargetVersion),
		Risk:          req.Risk,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func legacyRequestDigest(req CreateRequest) ([sha256.Size]byte, error) {
	payload := struct {
		Environment   string `json:"environment"`
		Scope         string `json:"scope"`
		TargetVersion string `json:"targetVersion"`
		Risk          Risk   `json:"risk"`
	}{
		Environment:   strings.TrimSpace(req.Environment),
		Scope:         strings.TrimSpace(req.Scope),
		TargetVersion: strings.TrimSpace(req.TargetVersion),
		Risk:          req.Risk,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validateIdentityTransition(op Operation, to Status, approverID string) (string, error) {
	if op.IdentityBinding != IdentityBindingDurable || strings.TrimSpace(op.InitiatorID) == "" {
		return "", ErrIdentityUnbound
	}
	approverID = strings.TrimSpace(approverID)
	if len(approverID) > maxIdentityBytes {
		return "", fmt.Errorf("%w: approver identity exceeds %d bytes", ErrStoreLimit, maxIdentityBytes)
	}
	isApproval := op.Status == StatusAwaitingApproval && to == StatusPrechecking
	if isApproval {
		if approverID == "" || approverID == op.InitiatorID {
			return "", ErrInvalidApprover
		}
		if op.ApprovedByID != "" && op.ApprovedByID != approverID {
			return "", ErrInvalidApprover
		}
		return approverID, nil
	}
	if approverID != "" {
		return "", ErrInvalidApprover
	}
	if (op.Risk == RiskHigh || op.Risk == RiskCritical) && op.Status == StatusPlanned && to == StatusPrechecking {
		return "", ErrApprovalRequired
	}
	if op.Risk == RiskCritical && to == StatusExecuting &&
		(strings.TrimSpace(op.ApprovedByID) == "" || op.ApprovedByID == op.InitiatorID) {
		return "", ErrApprovalRequired
	}
	return "", nil
}

func randomOperationID(now time.Time) (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "op-" + now.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(bytes), nil
}

func cloneOperation(op Operation) Operation {
	op.Events = append([]Event(nil), op.Events...)
	return op
}

// Compile-time guard against accidentally broadening IDs with unsafe text.
var operationIDPattern = regexp.MustCompile(`^op-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[a-f0-9]{24}$`)
