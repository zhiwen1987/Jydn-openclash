package truststate

import (
	"context"

	"chengwang/image-binding/trustcatalog"
	bolt "go.etcd.io/bbolt"
)

type GrantConsumption struct {
	GrantID         string `json:"grantID"`
	PolicyID        string `json:"policyID"`
	ApprovalSHA256  string `json:"approvalSHA256"`
	ManifestSHA256  string `json:"manifestSHA256"`
	Generation      uint64 `json:"generation"`
	CatalogueSHA256 string `json:"catalogueSHA256"`
	Status          string `json:"status"`
	EvidenceSHA256  string `json:"evidenceSHA256"`
}

// Inspection is a detached audit projection, never an authorization ticket.
// It contains no keys, raw policies, signed envelopes or ticket token hashes.
type Inspection struct {
	Authorization   string               `json:"authorization"`
	Catalogue       trustcatalog.Summary `json:"catalogue"`
	CatalogueValid  bool                 `json:"catalogueValid"`
	Sequence        uint64               `json:"sequence"`
	LedgerCapacity  int                  `json:"ledgerCapacity"`
	LedgerUsed      int                  `json:"ledgerUsed"`
	LedgerRemaining int                  `json:"ledgerRemaining"`
	Consumptions    []GrantConsumption   `json:"consumptions"`
}

// Inspect never initializes storage, advances a sequence, records an observed
// time, or changes the clock high-water mark. Expired catalogues remain visible
// as metadata, with CatalogueValid=false. Integrity failures still poison the
// process instance, just as they do for the mutation methods.
func (s *Store) Inspect(ctx context.Context) (Inspection, error) {
	if s == nil || contextError(ctx) != nil {
		return Inspection{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return Inspection{}, err
	}
	var out Inspection
	err := s.db.View(func(tx *bolt.Tx) error {
		r, cat, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		now := s.clock()
		if now.IsZero() || now.UnixNano() < r.LastWallUnixNano || now.UnixNano() < s.lastObserved {
			return ErrInvalid
		}
		out = Inspection{Authorization: "BLOCKED", Catalogue: cat.Summary(), CatalogueValid: cat.ValidAt(now), Sequence: r.Sequence, LedgerCapacity: maxLedgerEntries, LedgerUsed: len(r.Ledger), LedgerRemaining: maxLedgerEntries - len(r.Ledger), Consumptions: make([]GrantConsumption, 0, len(r.Ledger))}
		for _, e := range r.Ledger {
			out.Consumptions = append(out.Consumptions, GrantConsumption{GrantID: e.GrantID, PolicyID: e.PolicyID, ApprovalSHA256: e.ApprovalSHA256, ManifestSHA256: e.ManifestSHA256, Generation: e.Generation, CatalogueSHA256: e.CatalogueSHA256, Status: e.Status, EvidenceSHA256: e.EvidenceSHA256})
		}
		return nil
	})
	if err != nil {
		return Inspection{}, err
	}
	if s.platform.verify() != nil {
		return Inspection{}, s.poison()
	}
	if contextError(ctx) != nil {
		return Inspection{}, ErrInvalid
	}
	return out, nil
}
