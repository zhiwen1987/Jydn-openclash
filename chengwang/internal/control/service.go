// Package control coordinates authorization, durable operation state and
// append-only evidence for planned changes.
//
// It deliberately does not execute device actions. Reaching an "executing"
// lifecycle state records intent only; a separate, future executor must own
// any interaction with routers, resolvers or proxy processes.
package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/operation"
)

// OperationStore is the minimum state store required by Service. Both the
// in-memory and file-backed operation stores implement this interface.
type OperationStore interface {
	Create(operation.CreateRequest) (operation.Operation, bool, error)
	Get(string) (operation.Operation, error)
	TransitionWithApproval(string, operation.Status, string, string) (operation.Operation, error)
}

// EvidenceAppender appends an event at most once for an idempotency key.
// Implementations must return the existing event when the same key and
// semantic event are replayed, and reject reuse of a key for different event
// content. OccurredAt and store-managed ID/hash fields are not semantic: the
// first durable append owns those values.
//
// evidence.Store implements this interface directly.
type EvidenceAppender interface {
	AppendOnce(event evidence.EvidenceEvent, idempotencyKey string) (record evidence.EvidenceEvent, appended bool, err error)
}

// ErrorCode is a stable machine-readable control-service outcome.
type ErrorCode string

const (
	CodeAuthorizationDenied ErrorCode = "authorization_denied"
	CodeScopeMismatch       ErrorCode = "scope_mismatch"
	CodeInvalidRequest      ErrorCode = "invalid_request"
	CodeOperationStore      ErrorCode = "operation_store_failed"
	CodeIdempotencyConflict ErrorCode = "idempotency_conflict"
	CodeAuditDegraded       ErrorCode = "audit_degraded"
	CodeCommitUnknown       ErrorCode = "commit_unknown"
	CodeNotFound            ErrorCode = "not_found"
	CodeTransitionConflict  ErrorCode = "transition_conflict"
	CodeApprovalRequired    ErrorCode = "approval_required"
	CodeIdentityUnbound     ErrorCode = "identity_unbound"
)

// ServiceError preserves a stable code and stage without requiring callers to
// parse implementation error text. Partial is true only when operation state
// changed but the corresponding result evidence was not confirmed durable.
type ServiceError struct {
	Code        ErrorCode
	Stage       string
	Partial     bool
	AuthzReason authz.ReasonCode
	Cause       error
}

func (e *ServiceError) Error() string {
	if e == nil {
		return ""
	}
	message := string(e.Code)
	if e.Stage != "" {
		message += ": " + e.Stage
	}
	if e.AuthzReason != "" {
		message += ": " + string(e.AuthzReason)
	}
	return message
}

func (e *ServiceError) Unwrap() error { return e.Cause }

// Outcome is a stable, non-optimistic service result. AuditDegraded is never
// equivalent to completion even when the local operation state changed.
type Outcome string

const (
	OutcomePlanned       Outcome = "planned"
	OutcomeTransitioned  Outcome = "transitioned"
	OutcomeRejected      Outcome = "rejected"
	OutcomeAuditDegraded Outcome = "audit_degraded"
	OutcomeCommitUnknown Outcome = "commit_unknown"
)

// CreateRequest contains authenticated authorization facts plus the immutable
// operation request. Scope and environment are derived from Resource so the
// authorized resource cannot diverge from the persisted operation target.
type CreateRequest struct {
	Principal      authz.Principal
	Resource       authz.ResourceScope
	Risk           authz.Risk
	TargetVersion  string
	IdempotencyKey string
	TraceID        string
}

type CreateResult struct {
	Operation     operation.Operation
	Created       bool
	AuditRecorded bool
	Outcome       Outcome
}

// TransitionRequest changes lifecycle state only. It does not accept identity
// metadata: the authenticated Principal is the actor, while initiator and
// approver facts are read exclusively from durable operation state.
type TransitionRequest struct {
	Principal      authz.Principal
	Resource       authz.ResourceScope
	OperationID    string
	To             operation.Status
	IdempotencyKey string
	TraceID        string
}

type TransitionResult struct {
	Operation     operation.Operation
	Applied       bool
	Replayed      bool
	AuditRecorded bool
	Outcome       Outcome
}

// Service performs local orchestration only.
type Service struct {
	operations OperationStore
	evidence   EvidenceAppender
	now        func() time.Time
	mu         sync.Mutex
}

// New constructs a control service. Dependencies are mandatory so an
// accidentally unaudited or non-persistent mode cannot be selected by a zero
// value.
func New(operations OperationStore, evidenceAppender EvidenceAppender) (*Service, error) {
	if operations == nil {
		return nil, errors.New("operation store is required")
	}
	if evidenceAppender == nil {
		return nil, errors.New("evidence appender is required")
	}
	return &Service{
		operations: operations,
		evidence:   evidenceAppender,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

// Create authorizes, durably records pre-evidence, persists a planned
// operation, then records result evidence. A pre-evidence failure cannot
// mutate operation state. A result-evidence failure is explicit and a replay
// can repair it without creating a second operation.
func (s *Service) Create(req CreateRequest) (CreateResult, error) {
	if err := validateControlKey(req.IdempotencyKey); err != nil {
		return CreateResult{Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "validate", false, "", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	decision := authz.Evaluate(authz.Request{
		Principal: req.Principal,
		Action:    authz.ActionCreateOperation,
		Resource:  req.Resource,
		Risk:      req.Risk,
	}, s.now().UTC())
	if !decision.Allowed {
		return CreateResult{Outcome: OutcomeRejected}, serviceError(CodeAuthorizationDenied, "authorize", false, decision.Code, nil)
	}

	opRisk, err := operationRisk(req.Risk)
	if err != nil {
		return CreateResult{Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "validate", false, "", err)
	}
	scopeRef, err := ScopeReference(req.Resource)
	if err != nil {
		return CreateResult{Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "scope", false, "", err)
	}
	digest := digestText(req.IdempotencyKey)
	baseData := map[string]string{
		"idempotencyDigest": digest,
		"requestDigest":     compositeDigest(strings.TrimSpace(req.Principal.ID), scopeRef, string(req.Risk), strings.TrimSpace(req.TargetVersion)),
		"risk":              string(req.Risk),
		"scopeRef":          scopeRef,
	}
	_, _, err = s.evidence.AppendOnce(evidence.EvidenceEvent{
		TraceID:    traceReference(req.TraceID, digest),
		ActorID:    opaqueReference("actor", req.Principal.ID),
		Action:     "operation.create.pre",
		Target:     scopeRef,
		Result:     "authorized",
		OccurredAt: s.now().UTC(),
		Data:       cloneData(baseData),
	}, evidenceKey("create-pre", digest))
	if err != nil {
		if errors.Is(err, evidence.ErrIdempotencyConflict) {
			return CreateResult{Outcome: OutcomeRejected}, serviceError(CodeIdempotencyConflict, "create_pre_evidence", false, "", err)
		}
		return CreateResult{Outcome: OutcomeAuditDegraded}, serviceError(CodeAuditDegraded, "create_pre_evidence", false, "", err)
	}
	op, created, err := s.operations.Create(operation.CreateRequest{
		IdempotencyKey: req.IdempotencyKey,
		InitiatorID:    strings.TrimSpace(req.Principal.ID),
		Environment:    req.Resource.Environment,
		Scope:          scopeRef,
		TargetVersion:  req.TargetVersion,
		Risk:           opRisk,
	})
	if err != nil {
		baseData["errorClass"] = classifyStoreError(err)
		if commitUnknown(err) {
			_, _, auditErr := s.evidence.AppendOnce(evidence.EvidenceEvent{
				TraceID:    traceReference(req.TraceID, digest),
				ActorID:    opaqueReference("actor", req.Principal.ID),
				Action:     "operation.create.result",
				Target:     scopeRef,
				Result:     "unknown",
				OccurredAt: s.now().UTC(),
				Data:       cloneData(baseData),
			}, evidenceKey("create-unknown", digest, baseData["requestDigest"]))
			if auditErr != nil {
				return CreateResult{Outcome: OutcomeAuditDegraded}, serviceError(CodeAuditDegraded, "create_unknown_evidence", true, "", errors.Join(err, auditErr))
			}
			return CreateResult{AuditRecorded: true, Outcome: OutcomeCommitUnknown}, serviceError(CodeCommitUnknown, "create", true, "", err)
		}
		_, _, auditErr := s.evidence.AppendOnce(evidence.EvidenceEvent{
			TraceID:    traceReference(req.TraceID, digest),
			ActorID:    opaqueReference("actor", req.Principal.ID),
			Action:     "operation.create.result",
			Target:     scopeRef,
			Result:     "rejected",
			OccurredAt: s.now().UTC(),
			Data:       cloneData(baseData),
		}, evidenceKey("create-rejected", digest, baseData["requestDigest"], baseData["errorClass"]))
		if auditErr != nil {
			return CreateResult{Outcome: OutcomeAuditDegraded}, serviceError(CodeAuditDegraded, "create_result_evidence", false, "", errors.Join(err, auditErr))
		}
		code := CodeOperationStore
		if errors.Is(err, operation.ErrIdempotencyConflict) {
			code = CodeIdempotencyConflict
		}
		return CreateResult{AuditRecorded: true, Outcome: OutcomeRejected}, serviceError(code, "create", false, "", err)
	}

	result := CreateResult{Operation: op, Created: created, Outcome: OutcomePlanned}
	baseData["operationId"] = op.ID
	_, _, err = s.evidence.AppendOnce(evidence.EvidenceEvent{
		TraceID:    traceReference(req.TraceID, digest),
		ActorID:    opaqueReference("actor", req.Principal.ID),
		Action:     "operation.create.result",
		Target:     "operation/" + op.ID,
		Result:     "planned",
		OccurredAt: s.now().UTC(),
		Data:       cloneData(baseData),
	}, evidenceKey("create-result", digest))
	if err != nil {
		result.Outcome = OutcomeAuditDegraded
		return result, serviceError(CodeAuditDegraded, "create_evidence", true, "", err)
	}
	result.AuditRecorded = true
	return result, nil
}

// Transition authorizes and records a lifecycle transition. Authorization and
// durable pre-evidence both precede local state mutation. Result evidence is
// append-once, so a retry can repair an ambiguous or failed result append
// without applying the transition twice.
func (s *Service) Transition(req TransitionRequest) (TransitionResult, error) {
	if strings.TrimSpace(req.OperationID) == "" {
		return TransitionResult{Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "validate", false, "", errors.New("operation ID is required"))
	}
	if err := validateControlKey(req.IdempotencyKey); err != nil {
		return TransitionResult{Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "validate", false, "", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.operations.Get(req.OperationID)
	if err != nil {
		if commitUnknown(err) {
			return TransitionResult{Outcome: OutcomeCommitUnknown}, serviceError(CodeCommitUnknown, "read", true, "", err)
		}
		code := CodeOperationStore
		if errors.Is(err, operation.ErrNotFound) {
			code = CodeNotFound
		}
		return TransitionResult{Outcome: OutcomeRejected}, serviceError(code, "read", false, "", err)
	}
	scopeRef, err := ScopeReference(req.Resource)
	if err != nil {
		return TransitionResult{Operation: current, Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "scope", false, "", err)
	}
	if current.Scope != scopeRef || current.Environment != strings.TrimSpace(req.Resource.Environment) {
		return TransitionResult{Operation: current, Outcome: OutcomeRejected}, serviceError(CodeScopeMismatch, "scope", false, "", nil)
	}

	risk, err := authorizationRisk(current.Risk)
	if err != nil {
		return TransitionResult{Operation: current, Outcome: OutcomeRejected}, serviceError(CodeInvalidRequest, "risk", false, "", err)
	}
	digest := digestText(req.IdempotencyKey)
	marker := transitionMarker(digest)
	prior, replay := findTransition(current, marker)
	if replay && prior.To != req.To {
		return TransitionResult{Operation: current, Outcome: OutcomeRejected}, serviceError(CodeIdempotencyConflict, "transition_replay", false, "", operation.ErrIdempotencyConflict)
	}
	if replay && prior.From == operation.StatusAwaitingApproval && prior.To == operation.StatusPrechecking &&
		current.ApprovedByID != strings.TrimSpace(req.Principal.ID) {
		return TransitionResult{Operation: current, Outcome: OutcomeRejected},
			serviceError(CodeAuthorizationDenied, "approval_replay_actor", false, "", nil)
	}
	actionFrom := current.Status
	if replay {
		actionFrom = prior.From
	}
	action := transitionAction(actionFrom, req.To)
	decision := authz.Evaluate(authz.Request{
		Principal:    req.Principal,
		Action:       action,
		Resource:     req.Resource,
		Risk:         risk,
		InitiatorID:  current.InitiatorID,
		ApprovedByID: current.ApprovedByID,
	}, s.now().UTC())
	if !decision.Allowed {
		return TransitionResult{Operation: current, Outcome: OutcomeRejected}, serviceError(CodeAuthorizationDenied, "authorize", false, decision.Code, nil)
	}

	from := current.Status
	if replay {
		from = prior.From
	}
	baseData := map[string]string{
		"operationId":       current.ID,
		"idempotencyDigest": digest,
		"from":              string(from),
		"to":                string(req.To),
		"risk":              string(risk),
		"scopeRef":          scopeRef,
	}
	preKey := evidenceKey("transition-pre", current.ID, digest)
	_, _, err = s.evidence.AppendOnce(evidence.EvidenceEvent{
		TraceID:    traceReference(req.TraceID, digest),
		ActorID:    opaqueReference("actor", req.Principal.ID),
		Action:     "operation.transition.pre",
		Target:     "operation/" + current.ID,
		Result:     "authorized",
		OccurredAt: s.now().UTC(),
		Data:       cloneData(baseData),
	}, preKey)
	if err != nil {
		if errors.Is(err, evidence.ErrIdempotencyConflict) {
			return TransitionResult{Operation: current, Outcome: OutcomeRejected}, serviceError(CodeIdempotencyConflict, "transition_pre_evidence", false, "", err)
		}
		return TransitionResult{Operation: current, Outcome: OutcomeAuditDegraded}, serviceError(CodeAuditDegraded, "transition_pre_evidence", false, "", err)
	}

	if replay {
		result := TransitionResult{Operation: current, Replayed: true, Outcome: OutcomeTransitioned}
		if err := s.appendTransitionResult(req, current, digest, baseData, "applied"); err != nil {
			result.Outcome = OutcomeAuditDegraded
			return result, serviceError(CodeAuditDegraded, "transition_result_evidence", true, "", err)
		}
		result.AuditRecorded = true
		return result, nil
	}

	approverID := ""
	if current.Status == operation.StatusAwaitingApproval && req.To == operation.StatusPrechecking {
		approverID = strings.TrimSpace(req.Principal.ID)
	}
	updated, transitionErr := s.operations.TransitionWithApproval(current.ID, req.To, marker, approverID)
	if transitionErr != nil {
		baseData["errorClass"] = classifyStoreError(transitionErr)
		if commitUnknown(transitionErr) {
			if auditErr := s.appendTransitionResult(req, current, digest, baseData, "unknown", baseData["errorClass"]); auditErr != nil {
				return TransitionResult{Operation: current, Outcome: OutcomeAuditDegraded}, serviceError(CodeAuditDegraded, "transition_unknown_evidence", true, "", errors.Join(transitionErr, auditErr))
			}
			return TransitionResult{Operation: current, AuditRecorded: true, Outcome: OutcomeCommitUnknown}, serviceError(CodeCommitUnknown, "transition", true, "", transitionErr)
		}
		if auditErr := s.appendTransitionResult(req, current, digest, baseData, "rejected", baseData["errorClass"]); auditErr != nil {
			return TransitionResult{Operation: current, Outcome: OutcomeAuditDegraded}, serviceError(CodeAuditDegraded, "transition_result_evidence", false, "", errors.Join(transitionErr, auditErr))
		}
		code := operationErrorCode(transitionErr)
		return TransitionResult{Operation: current, AuditRecorded: true, Outcome: OutcomeRejected}, serviceError(code, "transition", false, "", transitionErr)
	}

	result := TransitionResult{Operation: updated, Applied: true, Outcome: OutcomeTransitioned}
	if err := s.appendTransitionResult(req, updated, digest, baseData, "applied"); err != nil {
		result.Outcome = OutcomeAuditDegraded
		return result, serviceError(CodeAuditDegraded, "transition_result_evidence", true, "", err)
	}
	result.AuditRecorded = true
	return result, nil
}

func (s *Service) appendTransitionResult(req TransitionRequest, op operation.Operation, digest string, data map[string]string, result string, keyParts ...string) error {
	_, _, err := s.evidence.AppendOnce(evidence.EvidenceEvent{
		TraceID:    traceReference(req.TraceID, digest),
		ActorID:    opaqueReference("actor", req.Principal.ID),
		Action:     "operation.transition.result",
		Target:     "operation/" + op.ID,
		Result:     result,
		OccurredAt: s.now().UTC(),
		Data:       cloneData(data),
	}, evidenceKey("transition-result-"+result, append([]string{op.ID, digest}, keyParts...)...))
	return err
}

func transitionAction(from, to operation.Status) authz.Action {
	if from == operation.StatusAwaitingApproval && to == operation.StatusPrechecking {
		return authz.ActionApproveOperation
	}
	switch to {
	case operation.StatusPrechecking, operation.StatusExecuting, operation.StatusVerifying,
		operation.StatusObserving, operation.StatusSucceeded, operation.StatusPartial,
		operation.StatusRolledBack:
		return authz.ActionExecuteOperation
	default:
		// authz has no broad "manage" permission. CreateOperation is the
		// narrowest existing management permission and retains the same risk
		// and scope gates for request-approval, failure and manual takeover.
		return authz.ActionCreateOperation
	}
}

func findTransition(op operation.Operation, marker string) (operation.Event, bool) {
	for _, event := range op.Events {
		if event.Reason == marker {
			return event, true
		}
	}
	return operation.Event{}, false
}

func transitionMarker(digest string) string { return "control transition " + digest }

func operationRisk(risk authz.Risk) (operation.Risk, error) {
	switch risk {
	case authz.RiskLow:
		return operation.RiskLow, nil
	case authz.RiskMedium:
		return operation.RiskMedium, nil
	case authz.RiskHigh:
		return operation.RiskHigh, nil
	case authz.RiskCritical:
		return operation.RiskCritical, nil
	default:
		return "", fmt.Errorf("unknown risk %q", risk)
	}
}

func authorizationRisk(risk operation.Risk) (authz.Risk, error) {
	switch risk {
	case operation.RiskLow:
		return authz.RiskLow, nil
	case operation.RiskMedium:
		return authz.RiskMedium, nil
	case operation.RiskHigh:
		return authz.RiskHigh, nil
	case operation.RiskCritical:
		return authz.RiskCritical, nil
	default:
		return "", fmt.Errorf("unknown risk %q", risk)
	}
}

// ScopeReference returns the opaque, deterministic scope reference persisted
// in operation and evidence records. It contains no raw tenant or object name.
func ScopeReference(scope authz.ResourceScope) (string, error) {
	if strings.TrimSpace(scope.TenantID) == "" {
		return "", errors.New("scope tenant is required")
	}
	payload, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "scope-" + hex.EncodeToString(digest[:]), nil
}

func validateControlKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("idempotency key is required")
	}
	if len(key) > 200 {
		return errors.New("idempotency key exceeds 200 bytes")
	}
	return nil
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func opaqueReference(kind, value string) string {
	return kind + "-" + digestText(value)
}

func traceReference(traceID, fallback string) string {
	if strings.TrimSpace(traceID) == "" {
		return "trace-" + fallback
	}
	return opaqueReference("trace", traceID)
}

func cloneData(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func classifyStoreError(err error) string {
	switch {
	case errors.Is(err, operation.ErrNotFound):
		return "not_found"
	case errors.Is(err, operation.ErrInvalidTransition):
		return "invalid_transition"
	case errors.Is(err, operation.ErrTerminalOperation):
		return "terminal"
	case errors.Is(err, operation.ErrSensitiveReason):
		return "sensitive_reason"
	case errors.Is(err, operation.ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, operation.ErrIdentityUnbound):
		return "identity_unbound"
	case errors.Is(err, operation.ErrApprovalRequired):
		return "approval_required"
	case errors.Is(err, operation.ErrInvalidApprover):
		return "invalid_approver"
	case commitUnknown(err):
		return "commit_unknown"
	default:
		return "store_error"
	}
}

func commitUnknown(err error) bool {
	return errors.Is(err, operation.ErrCommitUncertain) || errors.Is(err, operation.ErrStorePoisoned)
}

func operationErrorCode(err error) ErrorCode {
	switch {
	case errors.Is(err, operation.ErrNotFound):
		return CodeNotFound
	case errors.Is(err, operation.ErrIdempotencyConflict):
		return CodeIdempotencyConflict
	case errors.Is(err, operation.ErrInvalidTransition), errors.Is(err, operation.ErrTerminalOperation):
		return CodeTransitionConflict
	case errors.Is(err, operation.ErrApprovalRequired), errors.Is(err, operation.ErrInvalidApprover):
		return CodeApprovalRequired
	case errors.Is(err, operation.ErrIdentityUnbound):
		return CodeIdentityUnbound
	default:
		return CodeOperationStore
	}
}

func evidenceKey(kind string, parts ...string) string {
	return "op-" + kind + ":" + compositeDigest(append([]string{kind}, parts...)...)
}

func compositeDigest(parts ...string) string {
	encoded, _ := json.Marshal(parts)
	return digestText(string(encoded))
}

func serviceError(code ErrorCode, stage string, partial bool, reason authz.ReasonCode, cause error) *ServiceError {
	return &ServiceError{Code: code, Stage: stage, Partial: partial, AuthzReason: reason, Cause: cause}
}
