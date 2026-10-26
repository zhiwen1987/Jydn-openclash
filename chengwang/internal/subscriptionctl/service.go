package subscriptionctl

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/subscription"
)

var ctlPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var ctlSource = regexp.MustCompile(`^src_[a-f0-9]{32}$`)
var ctlCandidate = regexp.MustCompile(`^cand_[a-f0-9]{32}$`)
var ctlCommand = regexp.MustCompile(`^cmd_[a-f0-9]{32}$`)
var ctlKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{15,127}$`)
var ctlHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ctlDigest = regexp.MustCompile(`^hmac-sha256:[a-f0-9]{64}$`)

type Service struct {
	*serviceCore
}
type serviceCore struct {
	config                    Config
	scope                     subscription.Scope
	actor                     func(string) string
	mu                        sync.Mutex
	inflight                  map[string]bool
	sources                   map[string]bool
	denials                   atomic.Uint32
	refreshBusy               atomic.Bool
	capacityMu                sync.Mutex
	now                       func() time.Time
	refreshRetryWait          func(context.Context, time.Duration) bool
	refreshStoreCall          func(string, func() error) error
	refreshStorageMu          sync.RWMutex
	refreshStoragePending     bool
	refreshStorageRetryCount  uint32
	refreshStorageNextRetryAt time.Time
	// Package-private test seam; production always reads the Store's actual
	// immutable audit/request projection, never a caller-provided receipt.
	mutationReceipt func(subscription.Scope, string, string) (subscription.MutationReceipt, bool, error)
}

func (Service) String() string   { return "subscription application service" }
func (Service) GoString() string { return "subscription application service" }

func ctlError(code Code, changed bool) error { return &Error{Code: code, StateMayHaveChanged: changed} }
func ctlNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Func, reflect.Map, reflect.Chan, reflect.Slice, reflect.Interface:
		return v.IsNil()
	}
	return false
}
func ctlCanceled(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }

func New(ctx context.Context, config Config) (*Service, error) {
	if ctx == nil {
		return nil, ctlError(CodeInvalid, false)
	}
	if ctx.Err() != nil {
		return nil, ctlError(CodeCanceled, false)
	}
	r := config.Scope
	if !ctlPart.MatchString(r.TenantID) || !ctlPart.MatchString(r.SiteID) || !ctlPart.MatchString(r.Environment) || r.ObjectType != "subscription-store" || !ctlPart.MatchString(r.ObjectID) || config.Store == nil || ctlNil(config.Audit) {
		return nil, ctlError(CodeInvalid, false)
	}
	refreshConfigured := config.RefreshStore != nil || config.RefreshRecovery != nil || !ctlNil(config.RefreshIdentity) || config.RefreshIdentityID != ""
	if refreshConfigured && (config.RefreshStore == nil || config.RefreshRecovery == nil || ctlNil(config.RefreshIdentity) || !ctlPart.MatchString(config.RefreshIdentityID)) {
		return nil, ctlError(CodeInvalid, false)
	}
	s := &Service{serviceCore: &serviceCore{config: config, scope: subscription.Scope{TenantID: r.TenantID, SiteID: r.SiteID, Environment: r.Environment}, inflight: map[string]bool{}, sources: map[string]bool{}, now: func() time.Time { return time.Now().UTC() }, refreshRetryWait: func(ctx context.Context, delay time.Duration) bool {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}, refreshStoreCall: func(_ string, operation func() error) error { return operation() }}}
	actor, err := config.Store.ControlActorFactory(s.scope)
	if err != nil {
		return nil, ctlMap(err, false)
	}
	s.actor = actor
	s.mutationReceipt = config.Store.MutationReceipt
	if err := s.Recover(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Service) Scope() authz.ResourceScope {
	if s == nil || s.serviceCore == nil {
		return authz.ResourceScope{}
	}
	return s.config.Scope
}
func (s *Service) authorize(ctx context.Context, p authz.Principal, action authz.Action, source string) error {
	if s == nil || s.serviceCore == nil || s.config.Store == nil {
		return ctlError(CodeUnavailable, false)
	}
	if ctlCanceled(ctx) {
		return ctlError(CodeCanceled, false)
	}
	if p.ID == "" || len(p.ID) > 4096 || !utf8.ValidString(p.ID) || strings.TrimSpace(p.ID) != p.ID || strings.ContainsFunc(p.ID, unicode.IsControl) {
		return ctlError(CodeForbidden, false)
	}
	decision := authz.Evaluate(authz.Request{Principal: p, Action: action, Resource: Resource(s.config.Scope, source)}, s.now().UTC())
	if !decision.Allowed {
		return ctlError(CodeForbidden, false)
	}
	return nil
}
func ctlMap(err error, changed bool) error {
	if err == nil {
		return nil
	}
	var own *Error
	if errors.As(err, &own) {
		return own
	}
	var core *subscription.Failure
	if errors.As(err, &core) {
		switch core.Code {
		case subscription.CodeConflict:
			return ctlError(CodeConflict, changed)
		case subscription.CodeNotFound:
			return ctlError(CodeNotFound, changed)
		case subscription.CodeScopeDenied:
			return ctlError(CodeForbidden, changed)
		case subscription.CodeInputLimit, subscription.CodeStoreLimit:
			return ctlError(CodeLimit, changed)
		case subscription.CodeInputInvalid, subscription.CodeFormatUnsupported, subscription.CodeProtocolUnsupported, subscription.CodeEmpty:
			return ctlError(CodeInvalid, changed)
		case subscription.CodeCommitUncertain:
			return ctlError(CodeCommitUnknown, true)
		case subscription.CodeFetchPolicy:
			return ctlError(CodeFetchPolicy, changed)
		case subscription.CodeFetchUnavailable:
			return ctlError(CodeFetchUnavailable, changed)
		case subscription.CodeFetchHTTP:
			return ctlError(CodeFetchHTTP, changed)
		case subscription.CodeFetchRateLimited:
			return ctlError(CodeFetchRateLimited, changed)
		}
	}
	return ctlError(CodeUnavailable, changed)
}
func ctlCode(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeUnavailable
}

func (s *Service) ListSources(ctx context.Context, p authz.Principal) (SourcePage, error) {
	if err := s.authorize(ctx, p, authz.ActionReadSubscription, ""); err != nil {
		return SourcePage{}, err
	}
	items, err := s.config.Store.Sources(s.scope)
	if err != nil {
		return SourcePage{}, ctlMap(err, false)
	}
	if len(items) > subscription.MaxSources {
		return SourcePage{}, ctlError(CodeLimit, false)
	}
	return SourcePage{Sources: items, Total: len(items)}, nil
}
func ctlQuery(q ListQuery) (ListQuery, error) {
	if q.Limit == 0 {
		q.Limit = MaxPageSize
	}
	if q.Limit < 1 || q.Limit > MaxPageSize || q.Offset < 0 || q.Offset > subscription.MaxNodes || q.Offset > 0 && q.Revision == 0 {
		return q, ctlError(CodeInvalid, false)
	}
	return q, nil
}
func (s *Service) ListCandidates(ctx context.Context, p authz.Principal, source string, q ListQuery) (CandidatePage, error) {
	if err := s.authorize(ctx, p, authz.ActionReadSubscription, source); err != nil {
		return CandidatePage{}, err
	}
	if !ctlSource.MatchString(source) {
		return CandidatePage{}, ctlError(CodeInvalid, false)
	}
	q, err := ctlQuery(q)
	if err != nil {
		return CandidatePage{}, err
	}
	before, err := s.config.Store.Source(s.scope, source)
	if err != nil {
		return CandidatePage{}, ctlMap(err, false)
	}
	if q.Revision != 0 && q.Revision != before.Revision {
		return CandidatePage{}, ctlError(CodeConflict, false)
	}
	items, err := s.config.Store.Candidates(s.scope, source)
	if err != nil {
		return CandidatePage{}, ctlMap(err, false)
	}
	after, err := s.config.Store.Source(s.scope, source)
	if err != nil {
		return CandidatePage{}, ctlMap(err, false)
	}
	if before.Revision != after.Revision {
		return CandidatePage{}, ctlError(CodeConflict, false)
	}
	page := CandidatePage{Candidates: []CandidateSummary{}, Total: len(items), Revision: after.Revision}
	if q.Offset > len(items) {
		return CandidatePage{}, ctlError(CodeInvalid, false)
	}
	end := q.Offset + q.Limit
	if end > len(items) {
		end = len(items)
	}
	for _, v := range items[q.Offset:end] {
		page.Candidates = append(page.Candidates, CandidateSummary{ID: v.ID, SourceID: v.SourceID, Digest: v.Digest, Format: v.Format, State: v.State, BaseRevision: v.BaseRevision, NodeCount: v.NodeCount, DuplicateCount: v.DuplicateCount, CreatedAt: v.CreatedAt})
	}
	if end < len(items) {
		n := end
		page.NextOffset = &n
	}
	return page, nil
}
func (s *Service) ListNodes(ctx context.Context, p authz.Principal, source, candidate string, q ListQuery) (NodePage, error) {
	if err := s.authorize(ctx, p, authz.ActionReadSubscription, source); err != nil {
		return NodePage{}, err
	}
	if !ctlSource.MatchString(source) || !ctlCandidate.MatchString(candidate) {
		return NodePage{}, ctlError(CodeInvalid, false)
	}
	q, err := ctlQuery(q)
	if err != nil {
		return NodePage{}, err
	}
	before, err := s.config.Store.Source(s.scope, source)
	if err != nil {
		return NodePage{}, ctlMap(err, false)
	}
	if q.Revision != 0 && q.Revision != before.Revision {
		return NodePage{}, ctlError(CodeConflict, false)
	}
	value, err := s.config.Store.Candidate(s.scope, source, candidate)
	if err != nil {
		return NodePage{}, ctlMap(err, false)
	}
	after, err := s.config.Store.Source(s.scope, source)
	if err != nil {
		return NodePage{}, ctlMap(err, false)
	}
	if before.Revision != after.Revision {
		return NodePage{}, ctlError(CodeConflict, false)
	}
	if q.Offset > len(value.Nodes) {
		return NodePage{}, ctlError(CodeInvalid, false)
	}
	end := q.Offset + q.Limit
	if end > len(value.Nodes) {
		end = len(value.Nodes)
	}
	page := NodePage{Nodes: append([]subscription.NodeView{}, value.Nodes[q.Offset:end]...), Total: len(value.Nodes), Revision: after.Revision}
	if end < len(value.Nodes) {
		n := end
		page.NextOffset = &n
	}
	return page, nil
}

func ctlValidCommand(c Command) bool {
	if !ctlKey.MatchString(c.IdempotencyKey) || ActionFor(c.Kind) == "" {
		return false
	}
	if c.Automated {
		if c.Kind != Fetch || c.ApprovalSourceRevision == 0 || c.ApprovalMaxAgeSeconds < uint64(subscription.MinRefreshInterval/time.Second) || c.ApprovalMaxAgeSeconds > uint64(subscription.MaxApprovalTTL/time.Second) {
			return false
		}
	} else if c.ApprovalSourceRevision != 0 || c.ApprovalMaxAgeSeconds != 0 {
		return false
	}
	if c.Kind == Create {
		return c.SourceID == "" && c.CandidateID == "" && c.ExpectedRevision == 0 && c.ExpectedDigest == "" && c.Label != "" && len(c.Label) <= 128 && c.Format == "" && len(c.Content) == 0 && c.Decision == "" && c.ReferenceID == "" && c.PolicyRevision == 0 && c.ApprovalID == ""
	}
	if !ctlSource.MatchString(c.SourceID) || c.ExpectedRevision == 0 || c.Label != "" {
		return false
	}
	switch c.Kind {
	case Import:
		return c.CandidateID == "" && c.ExpectedDigest == "" && len(c.Content) > 0 && len(c.Content) <= subscription.MaxInputBytes && c.Decision == "" && c.ReferenceID == "" && c.PolicyRevision == 0 && c.ApprovalID == "" && (c.Format == "" || c.Format == subscription.FormatAuto || c.Format == subscription.FormatMihomo || c.Format == subscription.FormatURI || c.Format == subscription.FormatBase64URI)
	case Decide:
		return ctlCandidate.MatchString(c.CandidateID) && ctlDigest.MatchString(c.ExpectedDigest) && c.Format == "" && len(c.Content) == 0 && (c.Decision == subscription.CandidateAdmitted || c.Decision == subscription.CandidateRejected) && c.ReferenceID == "" && c.PolicyRevision == 0 && c.ApprovalID == ""
	case Rollback:
		return ctlCandidate.MatchString(c.CandidateID) && c.ExpectedDigest == "" && c.Format == "" && len(c.Content) == 0 && c.Decision == "" && c.ReferenceID == "" && c.PolicyRevision == 0 && c.ApprovalID == ""
	case Approve:
		return c.CandidateID == "" && c.ExpectedDigest == "" && c.Format == "" && len(c.Content) == 0 && c.Decision == "" && ctlPart.MatchString(c.ReferenceID) && c.PolicyRevision > 0 && c.ApprovalID == ""
	case Fetch:
		return c.CandidateID == "" && c.ExpectedDigest == "" && c.Format == "" && len(c.Content) == 0 && c.Decision == "" && c.ReferenceID == "" && c.PolicyRevision > 0 && ctlCommand.MatchString(c.ApprovalID)
	}
	return false
}
func ctlMaterial(c Command) []byte {
	// Command's public JSON intentionally hides Content. The private canonical
	// fingerprint MUST include it and every effective argument.
	value := struct {
		Kind                  Kind
		SourceID, CandidateID string
		ExpectedRevision      uint64
		ExpectedDigest, Label string
		Format                subscription.Format
		ContentSHA256         [32]byte
		ContentBytes          int
		Decision              subscription.CandidateState
		ReferenceID           string
		PolicyRevision        uint64
		ApprovalID            string
	}{c.Kind, c.SourceID, c.CandidateID, c.ExpectedRevision, c.ExpectedDigest, c.Label, c.Format, sha256.Sum256(c.Content), len(c.Content), c.Decision, c.ReferenceID, c.PolicyRevision, c.ApprovalID}
	raw, _ := json.Marshal(value)
	if c.Automated {
		extended := struct {
			Base                   json.RawMessage
			Automated              bool
			ApprovalSourceRevision uint64
			ApprovalMaxAgeSeconds  uint64
		}{raw, true, c.ApprovalSourceRevision, c.ApprovalMaxAgeSeconds}
		raw, _ = json.Marshal(extended)
	}
	return raw
}
func (s *Service) claim(id, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == "" {
		source = "collection"
	}
	if s.inflight[id] || s.sources[source] {
		return ctlError(CodeConflict, false)
	}
	if len(s.inflight) >= 16 {
		return ctlError(CodeLimit, false)
	}
	s.inflight[id] = true
	s.sources[source] = true
	return nil
}
func (s *Service) release(id, source string) {
	if source == "" {
		source = "collection"
	}
	s.mu.Lock()
	delete(s.inflight, id)
	delete(s.sources, source)
	s.mu.Unlock()
}

func (s *Service) Execute(ctx context.Context, p authz.Principal, c Command) (Receipt, error) {
	if s == nil || s.serviceCore == nil {
		return Receipt{}, ctlError(CodeUnavailable, false)
	}
	if s.config.RefreshStore != nil {
		if !s.capacityMu.TryLock() {
			return Receipt{}, ctlError(CodeConflict, false)
		}
		if s.refreshBusy.Load() {
			s.capacityMu.Unlock()
			return Receipt{}, ctlError(CodeConflict, false)
		}
	} else {
		s.capacityMu.Lock()
	}
	defer s.capacityMu.Unlock()
	return s.execute(ctx, p, c, ActionFor(c.Kind))
}

func (s *Service) executeRefreshLocked(ctx context.Context, attempt subscription.RefreshView, c Command) (Receipt, error) {
	if s == nil || s.serviceCore == nil || ctlNil(s.config.RefreshIdentity) || s.config.RefreshStore == nil || !c.Automated || c.Kind != Fetch {
		return Receipt{}, ctlError(CodeForbidden, false)
	}
	p, ref, err := s.config.RefreshIdentity.TrustedPrincipal(s.config.RefreshIdentityID, s.now().UTC())
	if err != nil {
		return Receipt{}, refreshIdentityError(err)
	}
	if !s.refreshPrincipalCurrent(p, c.SourceID) {
		return Receipt{}, ctlError(CodeForbidden, false)
	}
	c.refreshReference, c.freshIdentityRequired = ref, true
	identity, err := s.config.Store.ControlIdentity(s.scope, p.ID, c.IdempotencyKey, ctlMaterial(c))
	if err != nil {
		return Receipt{}, ctlMap(err, false)
	}
	if err = s.retryRefreshStoreStage(ctx, "bind", func() error {
		return s.config.RefreshStore.BindCommand(s.scope, c.SourceID, attempt, p.ID, identity.ID)
	}); err != nil {
		return Receipt{}, ctlMap(err, false)
	}
	receipt, executeErr := s.execute(ctx, p, c, authz.ActionRefreshSubscription)
	record, exists, readErr := s.config.Store.ControlCommand(s.scope, identity.ID)
	if readErr != nil {
		return receipt, ctlMap(readErr, true)
	}
	var persisted *subscription.ControlCommand
	if exists {
		persisted = &record
	}
	if err = s.retryRefreshStoreStage(ctx, "reservation", func() error {
		return s.config.RefreshStore.ReconcileReservation(s.scope, c.SourceID, attempt, persisted)
	}); err != nil {
		return receipt, ctlMap(err, true)
	}
	return receipt, executeErr
}

func (s *Service) ensureManualCapacity(c Command) error {
	if s.config.RefreshStore == nil {
		return nil
	}
	cap, err := s.config.Store.Capacity(s.scope)
	if err != nil {
		return ctlMap(err, false)
	}
	reserved, err := s.config.RefreshStore.ReservedCapacity()
	if err != nil {
		return ctlMap(err, false)
	}
	commands, candidates, audit, bytes := 1, 0, 0, 64*1024
	switch c.Kind {
	case Import, Fetch:
		candidates = 1
		audit = 1
		bytes = subscription.MaxRefreshReservationBytes
	case Create, Decide, Rollback:
		audit = 1
	}
	if cap.CommandsUsed+reserved.CommandsUsed+commands > cap.CommandsMax || cap.CandidatesUsed+reserved.CandidatesUsed+candidates > cap.CandidatesMax || cap.DomainAuditUsed+reserved.DomainAuditUsed+audit > cap.DomainAuditMax || cap.EncodedBytes+reserved.EncodedBytes+bytes > cap.EncodedBytesMax {
		return ctlError(CodeLimit, false)
	}
	return nil
}

func (s *Service) execute(ctx context.Context, p authz.Principal, c Command, action authz.Action) (Receipt, error) {
	if err := s.authorize(ctx, p, action, c.SourceID); err != nil {
		return Receipt{}, err
	}
	if !s.config.WritesEnabled {
		return Receipt{}, ctlError(CodeLocked, false)
	}
	if !ctlValidCommand(c) {
		return Receipt{}, ctlError(CodeInvalid, false)
	}
	// Own the private command bytes before fingerprinting and the audit gap.
	c.Content = append([]byte(nil), c.Content...)
	identity, err := s.config.Store.ControlIdentity(s.scope, p.ID, c.IdempotencyKey, ctlMaterial(c))
	if err != nil {
		return Receipt{}, ctlMap(err, false)
	}
	if err := s.claim(identity.ID, c.SourceID); err != nil {
		return Receipt{}, err
	}
	defer s.release(identity.ID, c.SourceID)
	if old, exists, err := s.config.Store.ControlCommand(s.scope, identity.ID); err != nil {
		return Receipt{}, ctlMap(err, false)
	} else if exists {
		if old.OwnerID != p.ID || old.Fingerprint != identity.Fingerprint || old.Kind != string(c.Kind) {
			return Receipt{}, ctlError(CodeConflict, false)
		}
		if err := s.recoverOne(ctx, old); err != nil {
			return ctlReceipt(old, true), err
		}
		old, _, err = s.config.Store.ControlCommand(s.scope, identity.ID)
		if err != nil {
			return Receipt{CommandID: identity.ID, Kind: c.Kind, SourceID: c.SourceID, StateMayHaveChanged: true, Replayed: true}, ctlError(CodeAuditDegraded, true)
		}
		receipt := ctlReceipt(old, true)
		if receipt.Code != "" {
			return receipt, ctlError(receipt.Code, receipt.StateMayHaveChanged)
		}
		return receipt, nil
	}
	if !c.Automated {
		if err := s.ensureManualCapacity(c); err != nil {
			return Receipt{}, err
		}
	}
	command := subscription.ControlCommand{ID: identity.ID, Scope: s.scope, ActorID: identity.ActorID, OwnerID: p.ID, CoreKey: identity.CoreKey, KeyDigest: identity.KeyDigest, Fingerprint: identity.Fingerprint, Kind: string(c.Kind), SourceID: c.SourceID, ExpectedRevision: c.ExpectedRevision}
	prepared, err := s.appendAudit(command, nil)
	if err != nil {
		return Receipt{}, ctlError(CodeAuditDegraded, false)
	}
	command.PreparedAuditHash, command.PreparedAt = prepared.Hash, prepared.OccurredAt
	created, err := s.config.Store.RecordControlPrepared(command)
	if err != nil {
		return ctlReceipt(command, false), ctlMap(err, false)
	}
	if !created {
		return ctlReceipt(command, true), ctlError(CodeCommitUnknown, true)
	}
	// Independently enforce authorization and cancellation at the real side
	// effect boundary, rather than trusting an API adapter's preflight.
	var result subscription.ControlResult
	if err = s.authorize(ctx, p, action, c.SourceID); err == nil {
		result, err = s.executeDomain(ctx, p, c, command, action)
	}
	if err != nil {
		classified := ctlMap(err, false)
		code := ctlCode(classified)
		var detail *Error
		changed := errors.As(classified, &detail) && detail.StateMayHaveChanged
		state := "failed"
		if changed {
			state = "unknown"
			code = CodeCommitUnknown
		}
		result = subscription.ControlResult{SourceID: c.SourceID, Revision: c.ExpectedRevision, State: state, Code: string(code), StateMayHaveChanged: changed, CompletedAt: time.Now().UTC()}
	}
	if persistErr := s.config.Store.RecordControlResult(s.scope, command.ID, result); persistErr != nil {
		if result.State == "unknown" {
			return ctlReceiptWith(command, result, false), ctlError(CodeCommitUnknown, true)
		}
		return ctlReceiptWith(command, result, false), ctlError(CodeAuditDegraded, true)
	}
	command.Result = &result
	if auditErr := s.completeAudit(command); auditErr != nil {
		receipt := ctlReceipt(command, false)
		receipt.StateMayHaveChanged = true
		return receipt, ctlError(CodeAuditDegraded, true)
	}
	command.Acknowledged = true
	stored, _, readErr := s.config.Store.ControlCommand(s.scope, command.ID)
	if readErr != nil {
		return ctlReceipt(command, false), ctlError(CodeAuditDegraded, true)
	}
	receipt := ctlReceipt(stored, false)
	if err != nil {
		return receipt, ctlError(Code(result.Code), result.StateMayHaveChanged)
	}
	return receipt, nil
}

func ctlResult(m subscription.MutationReceipt) subscription.ControlResult {
	return subscription.ControlResult{SourceID: m.SourceID, CandidateID: m.CandidateID, Revision: m.Revision, Digest: m.Digest, State: "committed", LocalAuditHash: m.LocalAuditHash, CompletedAt: m.CompletedAt}
}
func (s *Service) executeDomain(ctx context.Context, p authz.Principal, c Command, record subscription.ControlCommand, action authz.Action) (subscription.ControlResult, error) {
	var view subscription.CandidateView
	var err error
	switch c.Kind {
	case Create:
		_, err = s.config.Store.CreateSource(s.scope, c.Label, record.ActorID, record.CoreKey)
	case Import:
		view, err = s.config.Store.Import(subscription.ImportRequest{Scope: s.scope, SourceID: c.SourceID, ExpectedRevision: c.ExpectedRevision, ActorID: record.ActorID, IdempotencyKey: record.CoreKey, Format: c.Format, Content: append([]byte{}, c.Content...)})
	case Decide:
		_, err = s.config.Store.Decide(subscription.DecisionRequest{Scope: s.scope, SourceID: c.SourceID, CandidateID: c.CandidateID, ExpectedRevision: c.ExpectedRevision, ExpectedDigest: c.ExpectedDigest, ActorID: record.ActorID, IdempotencyKey: record.CoreKey, Decision: c.Decision})
	case Rollback:
		_, err = s.config.Store.Rollback(s.scope, c.SourceID, c.CandidateID, c.ExpectedRevision, record.ActorID, record.CoreKey)
	case Approve:
		if ctlNil(s.config.Policies) {
			return subscription.ControlResult{}, ctlError(CodeApprovalRequired, false)
		}
		descriptor, describeErr := s.config.Policies.Describe(c.ReferenceID)
		if describeErr != nil || descriptor.ReferenceID != c.ReferenceID || descriptor.Revision != c.PolicyRevision || len(descriptor.Material) == 0 {
			return subscription.ControlResult{}, ctlError(CodeApprovalRequired, false)
		}
		digest, sealErr := s.config.Store.SealPolicy(s.scope, c.SourceID, descriptor.Material)
		if sealErr != nil {
			return subscription.ControlResult{}, sealErr
		}
		if ctlCanceled(ctx) {
			return subscription.ControlResult{}, ctlError(CodeCanceled, false)
		}
		a, approveErr := s.config.Store.RecordApproval(s.scope, record.ID, c.ReferenceID, c.PolicyRevision, digest, c.ExpectedRevision)
		if approveErr != nil {
			return subscription.ControlResult{}, approveErr
		}
		return ctlApprovalResult(a), nil
	case Fetch:
		approval, checkErr := s.fetchApproval(c)
		if checkErr != nil {
			return subscription.ControlResult{}, checkErr
		}
		if ctlCanceled(ctx) {
			return subscription.ControlResult{}, ctlError(CodeCanceled, false)
		}
		if c.freshIdentityRequired {
			if ctlNil(s.config.RefreshIdentity) || c.refreshReference == (authn.SnapshotRef{}) {
				return subscription.ControlResult{}, ctlError(CodeForbidden, false)
			}
			fresh, freshErr := s.config.RefreshIdentity.CurrentPrincipal(c.refreshReference, p.ID, s.now().UTC())
			if freshErr != nil {
				return subscription.ControlResult{}, refreshIdentityError(freshErr)
			}
			if !s.refreshPrincipalCurrent(fresh, c.SourceID) {
				return subscription.ControlResult{}, ctlError(CodeForbidden, false)
			}
			if err := s.authorize(ctx, fresh, action, c.SourceID); err != nil {
				return subscription.ControlResult{}, err
			}
			p = fresh
		}
		fetched, fetchErr := s.config.Policies.Fetch(ctx, s.scope, c.SourceID, approval.ReferenceID)
		if fetchErr != nil {
			if ctlCanceled(ctx) {
				return subscription.ControlResult{}, ctlError(CodeCanceled, false)
			}
			return subscription.ControlResult{}, ctlMap(fetchErr, false)
		}
		again, checkErr := s.fetchApproval(c)
		if checkErr != nil {
			return subscription.ControlResult{}, checkErr
		}
		if again.CommandID != approval.CommandID || again.PolicyDigest != approval.PolicyDigest {
			return subscription.ControlResult{}, ctlError(CodeApprovalRequired, false)
		}
		if fetched.Scope != s.scope || fetched.SourceID != c.SourceID || len(fetched.Content) == 0 || len(fetched.Content) > subscription.MaxInputBytes || fetched.ResponseBytes != len(fetched.Content) || fetched.AttemptedAt.IsZero() || fetched.CompletedAt.Before(fetched.AttemptedAt) {
			return subscription.ControlResult{}, ctlError(CodeFetchPolicy, false)
		}
		if c.freshIdentityRequired {
			fresh, freshErr := s.config.RefreshIdentity.CurrentPrincipal(c.refreshReference, p.ID, s.now().UTC())
			if freshErr != nil {
				return subscription.ControlResult{}, refreshIdentityError(freshErr)
			}
			if !s.refreshPrincipalCurrent(fresh, c.SourceID) {
				return subscription.ControlResult{}, ctlError(CodeForbidden, false)
			}
			if err := s.authorize(ctx, fresh, action, c.SourceID); err != nil {
				return subscription.ControlResult{}, err
			}
			p = fresh
		}
		view, err = s.config.Store.Import(subscription.ImportRequest{Scope: s.scope, SourceID: c.SourceID, ExpectedRevision: c.ExpectedRevision, ActorID: record.ActorID, IdempotencyKey: record.CoreKey, Format: subscription.FormatAuto, Content: append([]byte{}, fetched.Content...)})
	}
	if err != nil {
		return subscription.ControlResult{}, err
	}
	m, exists, err := s.mutationReceipt(s.scope, record.ActorID, record.CoreKey)
	if err != nil {
		return subscription.ControlResult{}, ctlError(CodeCommitUnknown, true)
	}
	if exists {
		return ctlResult(m), nil
	}
	if c.Kind == Import || c.Kind == Fetch {
		return subscription.ControlResult{SourceID: c.SourceID, CandidateID: view.ID, Revision: c.ExpectedRevision, Digest: view.Digest, State: "noop", CompletedAt: time.Now().UTC()}, nil
	}
	return subscription.ControlResult{}, ctlError(CodeCommitUnknown, true)
}
func ctlApprovalResult(a subscription.ControlApproval) subscription.ControlResult {
	return subscription.ControlResult{SourceID: a.SourceID, Revision: a.SourceRevision, State: "approved", ReferenceID: a.ReferenceID, PolicyRevision: a.PolicyRevision, PolicyDigest: a.PolicyDigest, ApprovalID: a.CommandID, CompletedAt: a.ApprovedAt}
}
func (s *Service) fetchApproval(c Command) (subscription.ControlApproval, error) {
	if ctlNil(s.config.Policies) {
		return subscription.ControlApproval{}, ctlError(CodeApprovalRequired, false)
	}
	a, exists, err := s.config.Store.CurrentApproval(s.scope, c.SourceID)
	if err != nil {
		return a, err
	}
	if !exists || a.CommandID != c.ApprovalID || a.PolicyRevision != c.PolicyRevision {
		return a, ctlError(CodeApprovalRequired, false)
	}
	d, err := s.config.Policies.Describe(a.ReferenceID)
	if err != nil || d.ReferenceID != a.ReferenceID || d.Revision != a.PolicyRevision || len(d.Material) == 0 {
		return a, ctlError(CodeApprovalRequired, false)
	}
	digest, err := s.config.Store.SealPolicy(s.scope, c.SourceID, d.Material)
	if err != nil {
		return a, err
	}
	if digest != a.PolicyDigest {
		return a, ctlError(CodeApprovalRequired, false)
	}
	source, err := s.config.Store.Source(s.scope, c.SourceID)
	if err != nil {
		return a, err
	}
	if source.Revision != c.ExpectedRevision {
		return a, ctlError(CodeConflict, false)
	}
	if c.Automated {
		now := s.now().UTC()
		if a.SourceRevision != c.ApprovalSourceRevision || a.SourceRevision != c.ExpectedRevision || now.Before(a.ApprovedAt) || !now.Before(a.ApprovedAt.Add(time.Duration(c.ApprovalMaxAgeSeconds)*time.Second)) {
			return a, ctlError(CodeApprovalRequired, false)
		}
	}
	return a, nil
}

func (s *Service) auditEvent(c subscription.ControlCommand, r *subscription.ControlResult) evidence.EvidenceEvent {
	target := s.config.Scope.ObjectID
	if c.SourceID != "" {
		target = c.SourceID
	}
	stage := "prepared"
	at := c.PreparedAt
	data := map[string]string{"tenantId": c.Scope.TenantID, "siteId": c.Scope.SiteID, "environment": c.Scope.Environment, "managementObject": s.config.Scope.ObjectID, "kind": c.Kind, "commandDigest": c.Fingerprint}
	if r != nil {
		stage = "result"
		at = r.CompletedAt
		data["state"] = r.State
		data["code"] = r.Code
		data["sourceId"] = r.SourceID
		data["candidateId"] = r.CandidateID
		data["revision"] = strconv.FormatUint(r.Revision, 10)
		data["candidateDigest"] = r.Digest
		data["localAuditHash"] = r.LocalAuditHash
		data["approvalId"] = r.ApprovalID
		data["policyDigest"] = r.PolicyDigest
		data["policyRevision"] = strconv.FormatUint(r.PolicyRevision, 10)
		data["stateMayHaveChanged"] = strconv.FormatBool(r.StateMayHaveChanged)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return evidence.EvidenceEvent{TraceID: c.ID, ActorID: c.ActorID, Action: "subscription.command." + stage, Target: "subscription/" + target, Result: stage, OccurredAt: at, Data: data}
}
func (s *Service) appendAudit(c subscription.ControlCommand, r *subscription.ControlResult) (evidence.EvidenceEvent, error) {
	want := s.auditEvent(c, r)
	stage := "prepared"
	if r != nil {
		stage = "result"
	}
	key := "subscription/" + c.ID + "/" + stage
	record, _, err := s.config.Audit.AppendOnce(want, key)
	if err != nil {
		return evidence.EvidenceEvent{}, ctlError(CodeAuditDegraded, r != nil)
	}
	if record.TraceID != want.TraceID || record.ActorID != want.ActorID || record.Action != want.Action || record.Target != want.Target || record.Result != want.Result || !reflect.DeepEqual(record.Data, want.Data) || record.IdempotencyKey != key || !ctlHash.MatchString(record.Hash) || !ctlHash.MatchString(record.PreviousHash) || record.ID == "" || record.OccurredAt.IsZero() {
		return evidence.EvidenceEvent{}, ctlError(CodeAuditDegraded, r != nil)
	}
	copyRecord := record
	copyRecord.Hash = ""
	raw, _ := json.Marshal(copyRecord)
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != record.Hash {
		return evidence.EvidenceEvent{}, ctlError(CodeAuditDegraded, r != nil)
	}
	return record, nil
}
func (s *Service) completeAudit(c subscription.ControlCommand) error {
	record, err := s.appendAudit(c, c.Result)
	if err != nil {
		return err
	}
	if err = s.config.Store.AcknowledgeControl(s.scope, c.ID, record.Hash); err != nil {
		return ctlError(CodeAuditDegraded, true)
	}
	return nil
}
func (s *Service) Recover(ctx context.Context) error {
	if s == nil || s.serviceCore == nil {
		return ctlError(CodeUnavailable, false)
	}
	if ctlCanceled(ctx) {
		return ctlError(CodeCanceled, false)
	}
	commands, err := s.config.Store.ControlCommands(s.scope)
	if err != nil {
		return ctlMap(err, false)
	}
	for _, c := range commands {
		if ctlCanceled(ctx) {
			return ctlError(CodeCanceled, false)
		}
		if err := s.recoverCurrent(ctx, c); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) recoverCurrent(ctx context.Context, c subscription.ControlCommand) error {
	if err := s.claim(c.ID, c.SourceID); err != nil {
		return err
	}
	defer s.release(c.ID, c.SourceID)
	// The listing predates this lease. An Execute may have completed in
	// between; never derive unknown from an obsolete nil-result snapshot.
	current, exists, err := s.config.Store.ControlCommand(s.scope, c.ID)
	if err != nil {
		return ctlMap(err, true)
	}
	if !exists {
		return ctlError(CodeUnavailable, true)
	}
	return s.recoverOne(ctx, current)
}
func (s *Service) recoverOne(ctx context.Context, c subscription.ControlCommand) error {
	if ctlCanceled(ctx) {
		return ctlError(CodeCanceled, false)
	}
	// Verify the exact existing prepared semantic record; AppendOnce cannot
	// silently substitute a different actor, target or fingerprint.
	prepared, err := s.appendAudit(c, nil)
	if err != nil || prepared.Hash != c.PreparedAuditHash {
		return ctlError(CodeAuditDegraded, c.Result != nil)
	}
	if c.Result == nil {
		m, exists, readErr := s.config.Store.MutationReceipt(s.scope, c.ActorID, c.CoreKey)
		if readErr != nil {
			return ctlMap(readErr, true)
		}
		result := subscription.ControlResult{SourceID: c.SourceID, Revision: c.ExpectedRevision, State: "unknown", Code: string(CodeCommitUnknown), StateMayHaveChanged: true, CompletedAt: time.Now().UTC()}
		if exists {
			result = ctlResult(m)
		} else if c.Kind == string(Approve) {
			if a, found, err := s.config.Store.ApprovalForCommand(s.scope, c.ID); err != nil {
				return ctlMap(err, true)
			} else if found {
				result = ctlApprovalResult(a)
			}
		}
		if err := s.config.Store.RecordControlResult(s.scope, c.ID, result); err != nil {
			return ctlMap(err, true)
		}
		c.Result = &result
	}
	result, err := s.appendAudit(c, c.Result)
	if err != nil {
		return ctlError(CodeAuditDegraded, true)
	}
	if c.Acknowledged && result.Hash != c.ResultAuditHash {
		return ctlError(CodeAuditDegraded, true)
	}
	if !c.Acknowledged {
		if err := s.config.Store.AcknowledgeControl(s.scope, c.ID, result.Hash); err != nil {
			return ctlError(CodeAuditDegraded, true)
		}
	}
	return nil
}

func ctlReceipt(c subscription.ControlCommand, replayed bool) Receipt {
	r := Receipt{CommandID: c.ID, Kind: Kind(c.Kind), SourceID: c.SourceID, Revision: c.ExpectedRevision, State: "prepared", Code: CodeCommitUnknown, StateMayHaveChanged: true, Replayed: replayed, PreparedAuditHash: c.PreparedAuditHash}
	if c.Result != nil {
		v := c.Result
		r.SourceID, r.CandidateID, r.Revision, r.CandidateDigest = v.SourceID, v.CandidateID, v.Revision, v.Digest
		r.State, r.Code, r.StateMayHaveChanged = v.State, Code(v.Code), v.StateMayHaveChanged
		r.LocalAuditHash, r.ReferenceID, r.PolicyRevision, r.PolicyDigest, r.ApprovalID, r.CompletedAt = v.LocalAuditHash, v.ReferenceID, v.PolicyRevision, v.PolicyDigest, v.ApprovalID, v.CompletedAt
	}
	r.ResultAuditHash, r.AuditRecorded = c.ResultAuditHash, c.Acknowledged
	return r
}
func ctlReceiptWith(c subscription.ControlCommand, result subscription.ControlResult, replayed bool) Receipt {
	c.Result = &result
	return ctlReceipt(c, replayed)
}
func (s *Service) ReadReceipt(ctx context.Context, p authz.Principal, id string) (Receipt, error) {
	if err := s.authorize(ctx, p, authz.ActionReadSubscription, ""); err != nil {
		return Receipt{}, err
	}
	if !ctlCommand.MatchString(id) {
		return Receipt{}, ctlError(CodeInvalid, false)
	}
	c, exists, err := s.config.Store.ControlCommand(s.scope, id)
	if err != nil {
		return Receipt{}, ctlMap(err, false)
	}
	if !exists {
		return Receipt{}, ctlError(CodeNotFound, false)
	}
	source := c.SourceID
	if source == "" && c.Result != nil {
		source = c.Result.SourceID
	}
	if source != "" {
		if err := s.authorize(ctx, p, authz.ActionReadSubscription, source); err != nil {
			return Receipt{}, err
		}
	}
	if c.OwnerID != p.ID {
		allowed := false
		for _, role := range p.Roles {
			allowed = allowed || role == authz.RoleAdmin || role == authz.RoleAuditor
		}
		if !allowed {
			return Receipt{}, ctlError(CodeForbidden, false)
		}
	}
	return ctlReceipt(c, false), nil
}

// Denial logging is bounded to 4096 attempts per Service lifetime. This is not
// an across-restart or distributed rate limit. It performs no private read,
// policy lookup or network call and accepts only safe closed classifications.
func (s *Service) RecordDenied(ctx context.Context, p authz.Principal, action authz.Action, code Code) error {
	if s == nil || s.serviceCore == nil || s.actor == nil || ctlNil(s.config.Audit) {
		return ctlError(CodeUnavailable, false)
	}
	if ctlCanceled(ctx) {
		return ctlError(CodeCanceled, false)
	}
	if !ctlKnownCode(code) {
		return ctlError(CodeInvalid, false)
	}
	category := "unknown"
	for _, kind := range []Kind{Create, Import, Decide, Rollback, Approve, Fetch} {
		if ActionFor(kind) == action {
			category = string(kind)
		}
	}
	if action == authz.ActionReadSubscription {
		category = "read"
	}
	for {
		old := s.denials.Load()
		if old >= MaxCommandRecords {
			return ctlError(CodeLimit, false)
		}
		if s.denials.CompareAndSwap(old, old+1) {
			break
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ctlError(CodeUnavailable, false)
	}
	id := "denied_" + hex.EncodeToString(nonce[:])
	actor := "unidentified"
	if len(p.ID) <= 4096 {
		actor = s.actor(p.ID)
	}
	_, _, err := s.config.Audit.AppendOnce(evidence.EvidenceEvent{TraceID: id, ActorID: actor, Action: "subscription.command.denied", Target: "subscription/" + s.config.Scope.ObjectID, Result: "denied", OccurredAt: time.Now().UTC(), Data: map[string]string{"category": category, "classification": string(code)}}, "subscription/"+id)
	if err != nil {
		return ctlError(CodeAuditDegraded, false)
	}
	return nil
}
func ctlKnownCode(code Code) bool {
	switch code {
	case CodeInvalid, CodeForbidden, CodeLocked, CodeUnavailable, CodeConflict, CodeNotFound, CodeAuditDegraded, CodeCommitUnknown, CodeCanceled, CodeApprovalRequired, CodeLimit,
		CodeFetchPolicy, CodeFetchUnavailable, CodeFetchHTTP, CodeFetchRateLimited:
		return true
	}
	return false
}

var _ Backend = (*Service)(nil)
