package truststate

import (
	"bytes"
	"context"

	"chengwang/image-binding/trustcatalog"
	bolt "go.etcd.io/bbolt"
)

// UpdatePreview is advisory metadata, not a ticket, signature receipt or write
// authorization. Eligible always needs revalidation in the real Update
// transaction. No signed envelopes, keys or ledger capabilities are returned.
type UpdatePreview struct {
	BaseGeneration uint64 `json:"baseGeneration"`
	BaseSHA256     string `json:"baseSHA256"`
	Eligible       bool   `json:"eligible"`
}

// PreviewUpdate repeats the actual current-anchor signature, transition and
// time checks without a durable write. It is used only to avoid recording the
// same automatically rejected candidate again, never to skip verification.
// The existing in-memory clock high-water may advance; the database record,
// sequence, last durable wall time, journal and ledger never do. An unhealthy
// store/clock/context returns an error, not a healthy candidate rejection.
func (s *Store) PreviewUpdate(ctx context.Context, raw []byte) (UpdatePreview, error) {
	if s == nil || contextError(ctx) != nil || len(raw) == 0 || len(raw) > trustcatalog.MaxEnvelopeBytes {
		return UpdatePreview{}, ErrInvalid
	}
	raw = bytes.Clone(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return UpdatePreview{}, err
	}
	var out UpdatePreview
	err := s.db.View(func(tx *bolt.Tx) error {
		r, current, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		now, err := s.now(r)
		if err != nil {
			return s.poison()
		}
		_, err = trustcatalog.Advance(current, raw, now)
		out = UpdatePreview{BaseGeneration: current.Generation(), BaseSHA256: current.SHA256(), Eligible: err == nil}
		return nil
	})
	if err != nil {
		return UpdatePreview{}, err
	}
	if s.platform.verify() != nil {
		return UpdatePreview{}, s.poison()
	}
	if contextError(ctx) != nil {
		return UpdatePreview{}, ErrInvalid
	}
	return out, nil
}
