package product

import (
	"context"
	"time"

	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

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
	_, err := s.Update(ctx, actor, raw)
	return err
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
	if s.poisoned || !s.refreshAt.IsZero() && now.Before(s.refreshAt) || ctx.Err() != nil {
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
	if s.poisoned || s.refreshAt.IsZero() || now.Before(s.refreshAt) || !now.Before(s.refreshUntil) || !state.CatalogueValid || state.Catalogue.Generation != s.refreshGeneration || state.Catalogue.SHA256 != s.refreshHash {
		return nil, failure(imagetrust.CodeUnavailable, false)
	}
	return &truststate.SourceBound{Generation: s.refreshGeneration, CatalogueSHA256: s.refreshHash, FreshUntilUnixNano: s.refreshUntil.UnixNano()}, nil
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
