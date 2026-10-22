package product

import (
	"bytes"
	"context"
	"errors"
	"time"

	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

const refreshRejectionCapacity = 16

type refreshRejectionKey struct {
	generation uint64
	baseSHA256 string
	rawSHA256  string
}

// These methods are trusted composition hooks, not HTTP routes. The fixed
// automation identity can install only signed next-generation catalogues via
// the same audited Update path. It has no externally usable credential.
func (s *Service) RefreshSnapshot(ctx context.Context) (uint64, string, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.unavailable() {
		return 0, "", failure(imagetrust.CodeUnavailable, false)
	}
	state, err := s.store.Inspect(ctx)
	if err != nil {
		return 0, "", failure(imagetrust.CodeUnavailable, false)
	}
	return state.Catalogue.Generation, state.Catalogue.SHA256, nil
}

func (s *Service) ApplyRefresh(ctx context.Context, raw []byte) error {
	if s == nil || s.refreshMaxAge <= 0 {
		return failure(imagetrust.CodeLocked, false)
	}
	actor := authz.Principal{ID: "image-trust-refresh", TenantID: s.scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{s.scope}}
	if err := s.authorize(ctx, actor, authz.ActionUpdateImageTrust, true); err != nil {
		return err
	}
	// A second trusted caller cannot create a waiting queue or race the ring.
	// This mutex is independent of the ordinary administrator Update path.
	if !s.refreshApplyMu.TryLock() {
		return failure(imagetrust.CodeBusy, false)
	}
	defer s.refreshApplyMu.Unlock()
	if len(raw) == 0 || len(raw) > imagetrust.MaxCatalogueBytes {
		return failure(imagetrust.CodeInvalid, false)
	}
	raw = bytes.Clone(raw)
	if err := s.checkAudit(); err != nil {
		s.poison()
		return err
	}
	before, err := s.previewRefresh(ctx, raw, false)
	if err != nil {
		return err
	}
	s.refreshRejectionBase(before.BaseGeneration, before.BaseSHA256)
	key := refreshRejectionKey{before.BaseGeneration, before.BaseSHA256, digest(raw)}
	if !before.Eligible {
		for _, retained := range s.refreshRejected {
			if retained == key {
				// Preview is a real current-state/signature/time check, not an
				// imported receipt. A future NotBefore may now be eligible and
				// must reach the original transactional Update instead.
				if auditErr := s.checkAudit(); auditErr != nil {
					s.poison()
					return failure(imagetrust.CodeAuditDegraded, false)
				}
				if ctx.Err() != nil {
					return failure(imagetrust.CodeCanceled, false)
				}
				if s.unavailable() {
					return failure(imagetrust.CodeUnavailable, false)
				}
				return failure(imagetrust.CodeInvalid, false)
			}
		}
	}
	status, err := s.Update(ctx, actor, raw)
	if err == nil {
		s.refreshRejectionBase(status.Generation, status.CatalogueSHA256)
		return nil
	}
	var rejected *imagetrust.Error
	if !errors.As(err, &rejected) || rejected.Code != imagetrust.CodeInvalid || !rejected.StateMayHaveChanged {
		return err
	}
	// CodeInvalid/changed=true is returned by Update only after its complete
	// REJECTED result audit and ACK. Do not retain uncertain/canceled failures,
	// and do not key on sequence: the rejection's own journal advanced it.
	after, previewErr := s.previewRefresh(ctx, raw, true)
	if previewErr != nil {
		return previewErr
	}
	if auditErr := s.checkAudit(); auditErr != nil {
		s.poison()
		return failure(imagetrust.CodeAuditDegraded, true)
	}
	s.refreshRejectionBase(after.BaseGeneration, after.BaseSHA256)
	if !after.Eligible && before.BaseGeneration == after.BaseGeneration && before.BaseSHA256 == after.BaseSHA256 {
		s.refreshRejected[s.refreshRejectNext] = key
		s.refreshRejectNext = (s.refreshRejectNext + 1) % len(s.refreshRejected)
	}
	return err
}

// previewRefresh distinguishes a healthy but ineligible candidate (nil error)
// from a store/context/integrity failure. The latter must never become a cached
// ordinary rejection or mask poison, even on a previously remembered digest.
func (s *Service) previewRefresh(ctx context.Context, raw []byte, changed bool) (truststate.UpdatePreview, error) {
	preview, err := s.store.PreviewUpdate(ctx, raw)
	if err != nil {
		if ctx == nil || ctx.Err() != nil {
			return truststate.UpdatePreview{}, failure(imagetrust.CodeCanceled, changed)
		}
		s.poison()
		return truststate.UpdatePreview{}, failure(imagetrust.CodeUnavailable, changed)
	}
	if ctx.Err() != nil {
		return truststate.UpdatePreview{}, failure(imagetrust.CodeCanceled, changed)
	}
	if s.unavailable() {
		return truststate.UpdatePreview{}, failure(imagetrust.CodeUnavailable, changed)
	}
	return preview, nil
}

// Called only under refreshApplyMu. The Service's store/anchor/scope are fixed;
// a newly observed catalogue base invalidates the entire previous working set.
func (s *Service) refreshRejectionBase(generation uint64, hash string) {
	if generation != s.refreshRejectBase || hash != s.refreshRejectBaseSHA256 {
		s.refreshRejected = [refreshRejectionCapacity]refreshRejectionKey{}
		s.refreshRejectNext = 0
		s.refreshRejectBase, s.refreshRejectBaseSHA256 = generation, hash
	}
}

func (s *Service) ConfirmRefresh(ctx context.Context, generation uint64, hash string) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.refreshMaxAge <= 0 || s.unavailable() {
		return failure(imagetrust.CodeUnavailable, false)
	}
	state, err := s.store.Inspect(ctx)
	if err != nil || !state.CatalogueValid || state.Catalogue.Generation != generation || state.Catalogue.SHA256 != hash {
		return failure(imagetrust.CodeConflict, false)
	}
	now := time.Now()
	until := now.Add(s.refreshMaxAge)
	if expiry := time.Unix(state.Catalogue.NotAfterUnix, 0); expiry.Before(until) {
		until = expiry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || !s.refreshAt.IsZero() && (now.Before(s.refreshAt) || now.UnixNano() < s.refreshAt.UnixNano()) || ctx.Err() != nil {
		return failure(imagetrust.CodeUnavailable, false)
	}
	s.refreshAt, s.refreshUntil, s.refreshGeneration, s.refreshHash = now, until, generation, hash
	return nil
}

func (s *Service) sourceBound(ctx context.Context) (*truststate.SourceBound, error) {
	if s.refreshMaxAge == 0 {
		return nil, nil
	}
	state, err := s.store.Inspect(ctx)
	if err != nil {
		return nil, failure(imagetrust.CodeUnavailable, false)
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.poisoned || s.refreshAt.IsZero() || now.Before(s.refreshAt) || now.UnixNano() < s.refreshAt.UnixNano() || !now.Before(s.refreshUntil) || now.UnixNano() >= s.refreshUntil.UnixNano() || !state.CatalogueValid || state.Catalogue.Generation != s.refreshGeneration || state.Catalogue.SHA256 != s.refreshHash {
		return nil, failure(imagetrust.CodeUnavailable, false)
	}
	return &truststate.SourceBound{Generation: s.refreshGeneration, CatalogueSHA256: s.refreshHash, FreshUntilUnixNano: s.refreshUntil.UnixNano()}, nil
}

// A second source read may itself observe a newer, freshly confirmed
// catalogue. That is not permission to return a result from the old one.
// Expiry/cancellation are tested after this potentially expensive read.
func (s *Service) finalSourceState(ctx context.Context, generation uint64, hash string, validUntilUnix int64) error {
	if ctx == nil {
		return failure(imagetrust.CodeCanceled, true)
	}
	bound, err := s.sourceBound(ctx)
	if err != nil {
		return failure(imagetrust.CodeUnavailable, true)
	}
	if bound != nil && (bound.Generation != generation || bound.CatalogueSHA256 != hash) {
		return failure(imagetrust.CodeConflict, true)
	}
	if validUntilUnix <= time.Now().Unix() || ctx.Err() != nil || s.unavailable() {
		return failure(imagetrust.CodeInvalid, true)
	}
	return nil
}

// Maintenance refreshes cached audit verification and reports fatal integrity
// or lifetime failures. It never silently clears poison or repairs files. A
// trusted supervisor may restart a candidate, whose constructor reconciles
// healthy durable outbox gaps before accepting any request.
func (s *Service) Maintenance(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.unavailable() {
		return failure(imagetrust.CodeUnavailable, false)
	}
	if err := s.checkAudit(); err != nil {
		s.poison()
		return err
	}
	if _, err := s.store.Inspect(ctx); err != nil {
		s.poison()
		return failure(imagetrust.CodeUnavailable, false)
	}
	return nil
}
