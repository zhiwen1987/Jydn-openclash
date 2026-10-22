package truststate

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"chengwang/image-binding/trustcatalog"
	bolt "go.etcd.io/bbolt"
)

const (
	MaxOperations               = 4096
	OutcomeRejected             = "REJECTED"
	OutcomeInterrupted          = "INTERRUPTED"
	OutcomeCatalogueCommitted   = "CATALOGUE_COMMITTED"
	OutcomeVerificationReserved = "VERIFICATION_RESERVED_NOT_COMPLETED"
	OutcomeVerificationConsumed = "VERIFICATION_CONSUMED"
)

// SourceBound is an optional trusted-server freshness constraint, not an HTTP
// input or a substitute for catalogue/approval signatures. A non-nil bound is
// checked inside the same transaction which burns the signed grant.
type SourceBound struct {
	Generation         uint64
	CatalogueSHA256    string
	FreshUntilUnixNano int64
}

type Operation struct {
	ID                string            `json:"id"`
	ActorID           string            `json:"actorID"`
	ScopeSHA256       string            `json:"scopeSHA256"`
	Kind              string            `json:"kind"`
	Data              map[string]string `json:"data"`
	AuditBaseCount    uint64            `json:"auditBaseCount"`
	AuditBaseHash     string            `json:"auditBaseHash"`
	PreparedAuditHash string            `json:"preparedAuditHash"`
}

// JournalEntry is a detached public outbox projection. Its state records local
// database facts, never HTTP delivery or deployment authority. The evidence
// store must independently prove PreparedAuditHash and ResultAuditHash exist.
type JournalEntry struct {
	Operation       Operation         `json:"operation"`
	State           string            `json:"state"`
	Outcome         string            `json:"outcome"`
	OutcomeData     map[string]string `json:"outcomeData"`
	Acknowledged    bool              `json:"acknowledged"`
	ResultAuditHash string            `json:"resultAuditHash"`
	GrantID         string            `json:"grantID"`
	Generation      uint64            `json:"generation"`
	CatalogueSHA256 string            `json:"catalogueSHA256"`
	ManifestSHA256  string            `json:"manifestSHA256"`
	EvidenceSHA256  string            `json:"evidenceSHA256"`
}

var errUnchanged = errors.New("journal already durably matches")
var journalPublicID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
var journalPolicyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s *Store) PrepareOperation(ctx context.Context, op Operation) error {
	op = cloneOperation(op)
	if !validOperation(op) {
		return ErrInvalid
	}
	return s.mutateJournal(ctx, func(r *stateRecord) error {
		if old := journalByID(r, op.ID); old != nil {
			if reflect.DeepEqual(old.Operation, op) {
				return errUnchanged
			}
			return ErrReplay
		}
		if len(r.Journal) >= MaxOperations {
			return ErrCapacity
		}
		r.Journal = append(r.Journal, JournalEntry{Operation: op, State: "PREPARED", OutcomeData: map[string]string{}})
		return nil
	})
}

func (s *Store) BindPreparedAudit(ctx context.Context, id, auditHash string) error {
	if !validID(id) || !auditHashValid(auditHash) {
		return ErrInvalid
	}
	return s.mutateJournal(ctx, func(r *stateRecord) error {
		entry := journalByID(r, id)
		if entry == nil {
			return ErrInvalid
		}
		if entry.Operation.PreparedAuditHash != "" {
			if entry.Operation.PreparedAuditHash == auditHash {
				return errUnchanged
			}
			return ErrReplay
		}
		if entry.State != "PREPARED" || entry.Outcome != "" || entry.Acknowledged {
			return ErrInvalid
		}
		entry.Operation.PreparedAuditHash = auditHash
		return nil
	})
}

// FinishOperation seals only outcomes justified by the already committed
// database phase. In particular, callers cannot mint CONSUMED or COMMITTED by
// supplying an enum; those phases arise only in their original transactions.
func (s *Store) FinishOperation(ctx context.Context, id, outcome string, data map[string]string) error {
	if !validID(id) || !validPublicData(data) {
		return ErrInvalid
	}
	data = cloneData(data)
	return s.mutateJournal(ctx, func(r *stateRecord) error {
		entry := journalByID(r, id)
		if entry == nil || !auditHashValid(entry.Operation.PreparedAuditHash) {
			return ErrInvalid
		}
		expected := outcomeForState(entry.State, outcome)
		if expected == "" || expected != outcome {
			return ErrInvalid
		}
		canonical := data
		if entry.State == "RESERVED" || entry.State == "CONSUMED" {
			canonical = verificationOutcomeData(*entry)
		}
		if entry.State == "COMMITTED" {
			canonical = map[string]string{"catalogueSHA256": entry.CatalogueSHA256}
		}
		if entry.Outcome != "" {
			if entry.Outcome == outcome && reflect.DeepEqual(entry.OutcomeData, canonical) {
				return errUnchanged
			}
			return ErrReplay
		}
		if entry.Acknowledged {
			return ErrReplay
		}
		entry.Outcome = outcome
		entry.OutcomeData = canonical
		return nil
	})
}

func (s *Store) AcknowledgeOperation(ctx context.Context, id, resultAuditHash string) error {
	if !validID(id) || !auditHashValid(resultAuditHash) {
		return ErrInvalid
	}
	return s.mutateJournal(ctx, func(r *stateRecord) error {
		entry := journalByID(r, id)
		if entry == nil || entry.Outcome == "" || !auditHashValid(entry.Operation.PreparedAuditHash) {
			return ErrInvalid
		}
		if entry.Acknowledged {
			if entry.ResultAuditHash == resultAuditHash {
				return errUnchanged
			}
			return ErrReplay
		}
		entry.Acknowledged = true
		entry.ResultAuditHash = resultAuditHash
		return nil
	})
}

// Journal is read-only and returns copies. Empty legacy records are accepted;
// removal of any journal from the same open Store is rejected by readCurrent.
func (s *Store) Journal(ctx context.Context) ([]JournalEntry, error) {
	if s == nil || contextError(ctx) != nil {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	var result []JournalEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		r, _, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		result = cloneJournal(r.Journal)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.platform.verify() != nil {
		return nil, s.poison()
	}
	if contextError(ctx) != nil {
		return nil, ErrInvalid
	}
	return result, nil
}

func (s *Store) mutateJournal(ctx context.Context, mutate func(*stateRecord) error) error {
	if s == nil || contextError(ctx) != nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return err
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		r, _, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		now, err := s.now(r)
		if err != nil {
			return s.poison()
		}
		if err = mutate(&r); err != nil {
			return err
		}
		if validateJournal(r) != nil {
			return ErrInvalid
		}
		return s.put(tx, &r, now)
	})
	if errors.Is(err, errUnchanged) {
		if s.platform.verify() != nil {
			return s.poison()
		}
		if contextError(ctx) != nil {
			return ErrInvalid
		}
		return nil
	}
	return s.afterTransaction(ctx, err)
}

func journalByID(r *stateRecord, id string) *JournalEntry {
	for i := range r.Journal {
		if r.Journal[i].Operation.ID == id {
			return &r.Journal[i]
		}
	}
	return nil
}
func readyOperation(e *JournalEntry, kind string) bool {
	return e != nil && e.Operation.Kind == kind && e.State == "PREPARED" && e.Outcome == "" && !e.Acknowledged && auditHashValid(e.Operation.PreparedAuditHash)
}
func validSourceBound(b *SourceBound, c trustcatalog.Catalogue, now time.Time) bool {
	return b == nil || b.Generation == c.Generation() && b.CatalogueSHA256 == c.SHA256() && b.FreshUntilUnixNano > now.UnixNano() && b.FreshUntilUnixNano <= c.Summary().NotAfterUnix*int64(time.Second)
}
func validOperation(op Operation) bool {
	if !validID(op.ID) || !journalPublicID.MatchString(op.ActorID) || !validHash(op.ScopeSHA256) || !auditHashValid(op.AuditBaseHash) || op.PreparedAuditHash != "" && !auditHashValid(op.PreparedAuditHash) || !validPublicData(op.Data) {
		return false
	}
	if op.AuditBaseCount == 0 && op.AuditBaseHash != strings.Repeat("0", 64) {
		return false
	}
	switch op.Kind {
	case "update":
		return validHash(op.Data["catalogueSHA256"])
	case "verify":
		return journalPolicyID.MatchString(op.Data["policyId"]) && validHash(op.Data["approvalSHA256"]) && validHash(op.Data["bundleSHA256"]) && validHash(op.Data["rootSHA256"])
	}
	return false
}
func validPublicData(data map[string]string) bool {
	if len(data) > 16 {
		return false
	}
	for key, value := range data {
		switch key {
		case "catalogueSHA256", "approvalSHA256", "bundleSHA256", "rootSHA256", "manifestSHA256", "evidenceSHA256", "sourceSHA256", "refreshSourceSHA256":
			if !validHash(value) {
				return false
			}
		case "policyId":
			if !journalPolicyID.MatchString(value) {
				return false
			}
		case "grantId":
			if !validID(value) {
				return false
			}
		case "code", "reasonCode":
			if !journalPolicyID.MatchString(value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func outcomeForState(state, requested string) string {
	switch state {
	case "PREPARED":
		if requested == OutcomeRejected || requested == OutcomeInterrupted {
			return requested
		}
	case "RESERVED":
		return OutcomeVerificationReserved
	case "COMMITTED":
		return OutcomeCatalogueCommitted
	case "CONSUMED":
		return OutcomeVerificationConsumed
	}
	return ""
}
func verificationOutcomeData(e JournalEntry) map[string]string {
	data := map[string]string{"grantId": e.GrantID, "manifestSHA256": e.ManifestSHA256, "catalogueSHA256": e.CatalogueSHA256}
	if e.EvidenceSHA256 != "" {
		data["evidenceSHA256"] = e.EvidenceSHA256
	}
	return data
}
func validateJournal(r stateRecord) error {
	if len(r.Journal) > MaxOperations {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, e := range r.Journal {
		if !validOperation(e.Operation) || seen[e.Operation.ID] || !validPublicData(e.OutcomeData) || e.OutcomeData == nil {
			return ErrInvalid
		}
		seen[e.Operation.ID] = true
		if e.Acknowledged {
			if e.Outcome == "" || !auditHashValid(e.ResultAuditHash) {
				return ErrInvalid
			}
		} else if e.ResultAuditHash != "" {
			return ErrInvalid
		}
		if e.Outcome != "" && (outcomeForState(e.State, e.Outcome) != e.Outcome || !auditHashValid(e.Operation.PreparedAuditHash)) {
			return ErrInvalid
		}
		switch e.State {
		case "PREPARED":
			if e.GrantID != "" || e.Generation != 0 || e.CatalogueSHA256 != "" || e.ManifestSHA256 != "" || e.EvidenceSHA256 != "" {
				return ErrInvalid
			}
		case "COMMITTED":
			if e.Operation.Kind != "update" || e.Outcome != OutcomeCatalogueCommitted || e.Generation == 0 || e.Generation > uint64(len(r.History)) || e.CatalogueSHA256 != hash(r.History[e.Generation-1]) || e.Operation.Data["catalogueSHA256"] != e.CatalogueSHA256 || e.GrantID != "" || e.ManifestSHA256 != "" || e.EvidenceSHA256 != "" || !reflect.DeepEqual(e.OutcomeData, map[string]string{"catalogueSHA256": e.CatalogueSHA256}) {
				return ErrInvalid
			}
		case "RESERVED", "CONSUMED":
			if e.Operation.Kind != "verify" || !validID(e.GrantID) || e.Generation == 0 || e.Generation > uint64(len(r.History)) || e.CatalogueSHA256 != hash(r.History[e.Generation-1]) || !validHash(e.ManifestSHA256) || !auditHashValid(e.Operation.PreparedAuditHash) {
				return ErrInvalid
			}
			if e.State == "CONSUMED" && (e.Outcome != OutcomeVerificationConsumed || !validHash(e.EvidenceSHA256)) {
				return ErrInvalid
			}
			if e.State == "RESERVED" && e.EvidenceSHA256 != "" {
				return ErrInvalid
			}
			if e.Outcome != "" && !reflect.DeepEqual(e.OutcomeData, verificationOutcomeData(e)) {
				return ErrInvalid
			}
			found := false
			for _, l := range r.Ledger {
				if l.OperationID == e.Operation.ID {
					if l.GrantID != e.GrantID || l.Status != e.State || l.Generation != e.Generation || l.CatalogueSHA256 != e.CatalogueSHA256 || l.ManifestSHA256 != e.ManifestSHA256 || l.EvidenceSHA256 != e.EvidenceSHA256 || l.PolicyID != e.Operation.Data["policyId"] {
						return ErrInvalid
					}
					found = true
				}
			}
			if !found {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	for _, l := range r.Ledger {
		if l.OperationID != "" && !seen[l.OperationID] {
			return ErrInvalid
		}
	}
	return nil
}
func auditHashValid(s string) bool { return len(s) == 64 && validHex(s) }
func cloneData(m map[string]string) map[string]string {
	r := make(map[string]string, len(m))
	for k, v := range m {
		r[k] = v
	}
	return r
}
func cloneOperation(op Operation) Operation { op.Data = cloneData(op.Data); return op }
func cloneJournal(entries []JournalEntry) []JournalEntry {
	r := make([]JournalEntry, 0, len(entries))
	for _, e := range entries {
		e.Operation = cloneOperation(e.Operation)
		e.OutcomeData = cloneData(e.OutcomeData)
		r = append(r, e)
	}
	return r
}
