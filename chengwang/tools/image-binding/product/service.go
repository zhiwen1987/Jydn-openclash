// Package product connects the real managed verifier to the optional product
// API. It neither authenticates external credentials nor grants device action
// authority: principals must come from the trusted authn boundary.
package product

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"

	binding "chengwang/image-binding"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

const MaxVerificationStartsPerMinute = 4
const auditFreshness = 30 * time.Second

// Config contains trusted server configuration only. No request may override
// Scope, Roots, bearer credentials, stores or the independently enabled gate.
type Config struct {
	Store               *truststate.Store
	Audit               *evidence.Store
	Scope               authz.ResourceScope
	WritesEnabled       bool
	RegistryRoots       *x509.CertPool
	RegistryBearerToken string
}

type Service struct {
	store         *truststate.Store
	audit         *evidence.Store
	scope         authz.ResourceScope
	writesEnabled bool
	roots         *x509.CertPool
	bearer        string
	mu            sync.RWMutex
	auditMu       sync.Mutex
	poisoned      bool
	// Test-only hook. Never exported or configured by the HTTP composition.
	fault func(string)
}

var _ imagetrust.Backend = (*Service)(nil)

// Capacity is fixed across Service instances in this process, with no queue
// and no attacker-keyed maps. Restarting the process resets this DoS budget;
// durable signed grant consumption, not this rate budget, prevents replay.
var processVerificationBudget = struct {
	sync.Mutex
	busy   bool
	starts [MaxVerificationStartsPerMinute]time.Time
	last   time.Time
}{}

func New(ctx context.Context, c Config) (*Service, error) {
	if ctx == nil || ctx.Err() != nil || c.Store == nil || c.Audit == nil || c.RegistryRoots == nil || !scopeValid(c.Scope) || !validBearer(c.RegistryBearerToken) {
		return nil, failure(imagetrust.CodeInvalid, false)
	}
	state, err := c.Store.Inspect(ctx)
	if err != nil || state.Authorization != "BLOCKED" || state.Catalogue.StoreID != c.Scope.ObjectID {
		return nil, failure(imagetrust.CodeUnavailable, false)
	}
	s := &Service{store: c.Store, audit: c.Audit, scope: c.Scope, writesEnabled: c.WritesEnabled, roots: c.RegistryRoots.Clone(), bearer: c.RegistryBearerToken}
	if err = s.checkAudit(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(imagetrust.CodeCanceled, false)
	}
	return s, nil
}

func (s *Service) Scope() authz.ResourceScope {
	if s == nil {
		return authz.ResourceScope{}
	}
	return s.scope
}

func (s *Service) Status(ctx context.Context, actor authz.Principal) (imagetrust.Status, error) {
	if err := s.authorize(ctx, actor, authz.ActionReadImageTrust, false); err != nil {
		return imagetrust.Status{}, err
	}
	return s.status(ctx)
}

func (s *Service) status(ctx context.Context) (imagetrust.Status, error) {
	if s.unavailable() {
		return imagetrust.Status{}, failure(imagetrust.CodeUnavailable, false)
	}
	state, err := s.store.Inspect(ctx)
	if err != nil {
		return imagetrust.Status{}, classify(ctx, err, false)
	}
	if state.Authorization != "BLOCKED" || state.Catalogue.StoreID != s.scope.ObjectID {
		return imagetrust.Status{}, failure(imagetrust.CodeUnavailable, false)
	}
	states := make(map[string]string, len(state.Consumptions))
	reserved, consumed := 0, 0
	for _, entry := range state.Consumptions {
		states[entry.GrantID] = entry.Status
		switch entry.Status {
		case "RESERVED":
			reserved++
		case "CONSUMED":
			consumed++
		}
	}
	policies := make([]imagetrust.PolicyStatus, 0, len(state.Catalogue.Grants))
	for _, grant := range state.Catalogue.Grants {
		status := states[grant.ID]
		if status == "" {
			status = "AVAILABLE"
			if !state.CatalogueValid {
				status = "EXPIRED"
			}
		}
		policies = append(policies, imagetrust.PolicyStatus{PolicyID: grant.PolicyID, GrantID: grant.ID, Revision: grant.Revision, ManifestSHA256: grant.ManifestSHA256, State: status})
	}
	auditState := s.audit.Status()
	if ctx.Err() != nil {
		return imagetrust.Status{}, failure(imagetrust.CodeCanceled, false)
	}
	return imagetrust.Status{Boundary: imagetrust.StatusBoundary, Authorization: "BLOCKED", DeviceActionsExecuted: false, Healthy: validAuditStatus(auditState, time.Now()), Fresh: state.CatalogueValid, StoreID: state.Catalogue.StoreID, Generation: state.Catalogue.Generation, CatalogueSHA256: state.Catalogue.SHA256, NotAfterUnix: state.Catalogue.NotAfterUnix, Sequence: state.Sequence, LedgerEntries: state.LedgerUsed, LedgerCapacity: state.LedgerCapacity, Reserved: reserved, Consumed: consumed, RevokedKeys: state.Catalogue.RevokedKeyCount, RevokedApprovals: state.Catalogue.RevokedApprovalCount, RevokedManifests: state.Catalogue.RevokedManifestCount, Policies: policies}, nil
}

func (s *Service) Update(ctx context.Context, actor authz.Principal, raw []byte) (imagetrust.Status, error) {
	if err := s.authorize(ctx, actor, authz.ActionUpdateImageTrust, true); err != nil {
		return imagetrust.Status{}, err
	}
	if len(raw) == 0 || len(raw) > imagetrust.MaxCatalogueBytes {
		return imagetrust.Status{}, failure(imagetrust.CodeInvalid, false)
	}
	raw = bytes.Clone(raw)
	op, err := s.preAudit(ctx, actor, "image_trust.update", map[string]string{"catalogueSHA256": digest(raw)})
	if err != nil {
		return imagetrust.Status{}, err
	}
	if s.unavailable() {
		return imagetrust.Status{}, failure(imagetrust.CodeUnavailable, false)
	}
	storeErr := s.store.Update(ctx, raw)
	if err = s.resultAudit(actor, op, "image_trust.update", storeErr == nil, nil); err != nil {
		return imagetrust.Status{}, err
	}
	if storeErr != nil {
		return imagetrust.Status{}, classify(ctx, storeErr, true)
	}
	status, err := s.status(ctx)
	if err != nil {
		return imagetrust.Status{}, failure(imagetrust.CodeUnavailable, true)
	}
	return status, nil
}

func (s *Service) Verify(ctx context.Context, actor authz.Principal, request imagetrust.VerifyRequest) (imagetrust.Receipt, error) {
	if err := s.authorize(ctx, actor, authz.ActionVerifyImageTrust, true); err != nil {
		return imagetrust.Receipt{}, err
	}
	if !policyIDValid(request.PolicyID) || len(request.Approval) == 0 || len(request.Approval) > imagetrust.MaxApprovalBytes || len(request.Bundle) == 0 || len(request.Bundle) > imagetrust.MaxBundleBytes || len(request.TrustedRoot) == 0 || len(request.TrustedRoot) > imagetrust.MaxRootBytes {
		return imagetrust.Receipt{}, failure(imagetrust.CodeInvalid, false)
	}
	if !reserveVerification(time.Now()) {
		return imagetrust.Receipt{}, failure(imagetrust.CodeBusy, false)
	}
	defer releaseVerification()
	request.Approval, request.Bundle, request.TrustedRoot = bytes.Clone(request.Approval), bytes.Clone(request.Bundle), bytes.Clone(request.TrustedRoot)
	op, err := s.preAudit(ctx, actor, "image_trust.verify", map[string]string{"policyId": request.PolicyID, "approvalSHA256": digest(request.Approval), "bundleSHA256": digest(request.Bundle), "rootSHA256": digest(request.TrustedRoot)})
	if err != nil {
		return imagetrust.Receipt{}, err
	}
	if s.unavailable() {
		return imagetrust.Receipt{}, failure(imagetrust.CodeUnavailable, false)
	}
	result, bindErr := binding.ManagedBind(ctx, s.store, request.PolicyID, request.Approval, request.Bundle, request.TrustedRoot, s.roots, s.bearer)
	valid := bindErr == nil && result.Verified() && result.Authorization() == "BLOCKED" && result.Boundary() == imagetrust.VerifiedBoundary
	projection := map[string]string{}
	if valid {
		projection["grantId"] = result.GrantID()
		projection["evidenceSHA256"] = result.EvidenceSHA256()
		projection["manifestSHA256"] = result.Binding().ManifestSHA256()
		projection["catalogueSHA256"] = result.CatalogueSHA256()
	}
	if err = s.resultAudit(actor, op, "image_trust.verify", valid, projection); err != nil {
		return imagetrust.Receipt{}, err
	}
	if !valid {
		return imagetrust.Receipt{}, classify(ctx, bindErr, true)
	}
	if ctx.Err() != nil {
		return imagetrust.Receipt{}, failure(imagetrust.CodeCanceled, true)
	}
	if s.unavailable() {
		return imagetrust.Receipt{}, failure(imagetrust.CodeUnavailable, true)
	}
	if err = s.finalVerifyState(ctx, request.PolicyID, result); err != nil {
		return imagetrust.Receipt{}, err
	}
	return imagetrust.Receipt{Boundary: imagetrust.VerifiedBoundary, Authorization: "BLOCKED", DeviceActionsExecuted: false, Verified: true, GrantID: result.GrantID(), CatalogueSHA256: result.CatalogueSHA256(), Generation: result.CatalogueGeneration(), ManifestSHA256: result.Binding().ManifestSHA256(), EvidenceSHA256: result.EvidenceSHA256()}, nil
}

func (s *Service) finalVerifyState(ctx context.Context, policyID string, r binding.ManagedResult) error {
	state, err := s.store.Inspect(ctx)
	if err != nil {
		return classify(ctx, err, true)
	}
	if !state.CatalogueValid || state.Catalogue.Generation != r.CatalogueGeneration() || state.Catalogue.SHA256 != r.CatalogueSHA256() || state.Catalogue.StoreID != s.scope.ObjectID {
		return failure(imagetrust.CodeConflict, true)
	}
	active := false
	for _, grant := range state.Catalogue.Grants {
		if grant.ID == r.GrantID() && grant.PolicyID == policyID && grant.ManifestSHA256 == r.Binding().ManifestSHA256() && grant.ApprovalSHA256 == r.Binding().ApprovalSHA256() && grant.Revision == r.Binding().PolicyRevision() {
			active = true
			break
		}
	}
	consumed := false
	for _, entry := range state.Consumptions {
		if entry.GrantID == r.GrantID() && entry.PolicyID == policyID && entry.Status == "CONSUMED" && entry.CatalogueSHA256 == r.CatalogueSHA256() && entry.Generation == r.CatalogueGeneration() && entry.ManifestSHA256 == r.Binding().ManifestSHA256() && entry.ApprovalSHA256 == r.Binding().ApprovalSHA256() && entry.EvidenceSHA256 == r.EvidenceSHA256() {
			consumed = true
			break
		}
	}
	if !active || !consumed || r.ValidUntilUnix() <= time.Now().Unix() || ctx.Err() != nil || s.unavailable() {
		return failure(imagetrust.CodeInvalid, true)
	}
	return nil
}

func (s *Service) authorize(ctx context.Context, actor authz.Principal, action authz.Action, write bool) error {
	// This remains mandatory even if callers bypass the HTTP router. Principal
	// authentication is the responsibility of the trusted composition/authn.
	if s == nil {
		return failure(imagetrust.CodeUnavailable, false)
	}
	decision := authz.Evaluate(authz.Request{Principal: actor, Action: action, Resource: s.scope}, time.Now())
	if !decision.Allowed || decision.BreakGlass {
		return failure(imagetrust.CodeForbidden, false)
	}
	if ctx == nil || ctx.Err() != nil {
		return failure(imagetrust.CodeCanceled, false)
	}
	if write && !s.writesEnabled {
		return failure(imagetrust.CodeLocked, false)
	}
	if s.unavailable() {
		return failure(imagetrust.CodeUnavailable, false)
	}
	return nil
}

func (s *Service) preAudit(ctx context.Context, actor authz.Principal, action string, data map[string]string) (string, error) {
	if ctx.Err() != nil {
		return "", failure(imagetrust.CodeCanceled, false)
	}
	if err := s.checkAudit(); err != nil {
		s.poison()
		return "", err
	}
	opRaw := make([]byte, 16)
	if _, err := rand.Read(opRaw); err != nil {
		return "", failure(imagetrust.CodeUnavailable, false)
	}
	op := hex.EncodeToString(opRaw)
	if s.fault != nil {
		s.fault("before-pre-audit")
	}
	if err := s.appendAudit(evidence.EvidenceEvent{TraceID: op, ActorID: actor.ID, Action: action, Target: "image-trust/" + s.scope.ObjectID, Result: "prepared", Data: data}, "image-trust/"+op+"/prepared"); err != nil {
		s.poison()
		return "", failure(imagetrust.CodeAuditDegraded, false)
	}
	if err := s.checkAudit(); err != nil {
		s.poison()
		return "", failure(imagetrust.CodeAuditDegraded, false)
	}
	if ctx.Err() != nil {
		return "", failure(imagetrust.CodeCanceled, false)
	}
	return op, nil
}

func (s *Service) resultAudit(actor authz.Principal, op, action string, success bool, data map[string]string) error {
	if s.fault != nil {
		s.fault("before-result-audit")
	}
	// Verification consumption is an observed SDK/store outcome, not an HTTP
	// success or delivery receipt. The final catalogue/freshness check can still
	// reject after this audit; neither that rejection nor lost delivery unburns
	// the grant. Audit and trust state deliberately remain separate stores.
	result := auditResultLabel(action, success)
	if err := s.checkAudit(); err != nil {
		s.poison()
		return failure(imagetrust.CodeAuditDegraded, true)
	}
	if err := s.appendAudit(evidence.EvidenceEvent{TraceID: op, ActorID: actor.ID, Action: action, Target: "image-trust/" + s.scope.ObjectID, Result: result, Data: data}, "image-trust/"+op+"/result"); err != nil {
		s.poison()
		return failure(imagetrust.CodeAuditDegraded, true)
	}
	if err := s.checkAudit(); err != nil {
		s.poison()
		return failure(imagetrust.CodeAuditDegraded, true)
	}
	return nil
}

func auditResultLabel(action string, success bool) string {
	if !success {
		return "rejected"
	}
	if action == "image_trust.verify" {
		return "verification_consumed"
	}
	return "completed"
}

func (s *Service) checkAudit() error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	return s.checkAuditLocked()
}

func (s *Service) appendAudit(event evidence.EvidenceEvent, key string) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if err := s.checkAuditLocked(); err != nil {
		return err
	}
	if _, created, err := s.audit.AppendOnce(event, key); err != nil || !created {
		return failure(imagetrust.CodeAuditDegraded, false)
	}
	return s.checkAuditLocked()
}

func (s *Service) checkAuditLocked() error {
	// Other product components may share this real evidence Store. A legitimate
	// append can advance Status between Verify's return and our read. Retry a
	// bounded number of times rather than accepting a mismatched cached head.
	for attempt := 0; attempt < 3; attempt++ {
		report, err := s.audit.Verify()
		if err != nil || !report.Valid {
			return failure(imagetrust.CodeAuditDegraded, false)
		}
		status := s.audit.Status()
		if !validAuditStatus(status, time.Now()) {
			return failure(imagetrust.CodeAuditDegraded, false)
		}
		if report.Count == status.Count && report.LastHash == status.LastHash && report.ExpectedCount == status.ExpectedCount && report.ExpectedLastHash == status.ExpectedLastHash {
			return nil
		}
	}
	return failure(imagetrust.CodeAuditDegraded, false)
}
func validAuditStatus(r evidence.VerifyReport, now time.Time) bool {
	return r.Valid && r.Issue == "" && r.Count == r.ExpectedCount && r.LastHash == r.ExpectedLastHash && !r.VerifiedAt.IsZero() && !r.VerifiedAt.After(now) && now.Sub(r.VerifiedAt) <= auditFreshness
}
func (s *Service) unavailable() bool { s.mu.RLock(); defer s.mu.RUnlock(); return s.poisoned }
func (s *Service) poison()           { s.mu.Lock(); s.poisoned = true; s.mu.Unlock() }
func reserveVerification(now time.Time) bool {
	b := &processVerificationBudget
	b.Lock()
	defer b.Unlock()
	if b.busy || now.IsZero() || !b.last.IsZero() && now.Before(b.last) {
		return false
	}
	b.last = now
	for i, at := range b.starts {
		if at.IsZero() || now.Sub(at) >= time.Minute {
			b.starts[i] = now
			b.busy = true
			return true
		}
	}
	return false
}
func releaseVerification() {
	processVerificationBudget.Lock()
	processVerificationBudget.busy = false
	processVerificationBudget.Unlock()
}
func scopeValid(s authz.ResourceScope) bool {
	return clean(s.TenantID, 128) && clean(s.SiteID, 128) && clean(s.Environment, 128) && s.ObjectType == "image-trust" && len(s.ObjectID) == 32 && hexText(s.ObjectID)
}
func clean(s string, max int) bool {
	return s != "" && len(s) <= max && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
func policyIDValid(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-')) {
			return false
		}
	}
	return true
}
func hexText(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validBearer(s string) bool {
	if len(s) > 8192 {
		return false
	}
	for _, c := range s {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func failure(code imagetrust.Code, changed bool) error {
	return &imagetrust.Error{Code: code, StateMayHaveChanged: changed}
}
func classify(ctx context.Context, err error, changed bool) error {
	if ctx == nil || ctx.Err() != nil {
		return failure(imagetrust.CodeCanceled, changed)
	}
	if errors.Is(err, truststate.ErrReplay) {
		return failure(imagetrust.CodeConflict, changed)
	}
	if errors.Is(err, truststate.ErrPoisoned) || errors.Is(err, truststate.ErrClosed) || errors.Is(err, truststate.ErrUnsupported) || errors.Is(err, truststate.ErrCapacity) {
		return failure(imagetrust.CodeUnavailable, changed)
	}
	return failure(imagetrust.CodeInvalid, changed)
}
