package product

import (
	"context"
	"encoding/json"

	"chengwang/image-binding/truststate"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

func (s *Service) scopeDigest() string { raw, _ := json.Marshal(s.scope); return digest(raw) }

func (s *Service) preparedEvent(op truststate.Operation) evidence.EvidenceEvent {
	return evidence.EvidenceEvent{TraceID: op.ID, ActorID: op.ActorID, Action: "image_trust." + op.Kind, Target: "image-trust/" + s.scope.ObjectID, Result: "prepared", Data: op.Data}
}

func (s *Service) resultEvent(e truststate.JournalEntry) evidence.EvidenceEvent {
	result := "rejected"
	switch e.Outcome {
	case truststate.OutcomeCatalogueCommitted:
		result = "completed"
	case truststate.OutcomeVerificationConsumed:
		result = "verification_consumed"
	case truststate.OutcomeInterrupted:
		result = "interrupted"
	}
	return evidence.EvidenceEvent{TraceID: e.Operation.ID, ActorID: e.Operation.ActorID, Action: "image_trust." + e.Operation.Kind, Target: "image-trust/" + s.scope.ObjectID, Result: result, Data: e.OutcomeData}
}

func eventMatches(actual, expected evidence.EvidenceEvent) bool {
	if actual.TraceID != expected.TraceID || actual.ActorID != expected.ActorID || actual.Action != expected.Action || actual.Target != expected.Target || actual.Result != expected.Result || len(actual.Data) != len(expected.Data) {
		return false
	}
	for key, value := range expected.Data {
		if actual.Data[key] != value {
			return false
		}
	}
	return true
}

func (s *Service) appendDurableAudit(event evidence.EvidenceEvent, key string, allowExisting bool) (evidence.EvidenceEvent, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if err := s.checkAuditLocked(); err != nil {
		return evidence.EvidenceEvent{}, err
	}
	persisted, created, err := s.audit.AppendOnce(event, key)
	if err != nil || !created && !allowExisting {
		return evidence.EvidenceEvent{}, failure(imagetrust.CodeAuditDegraded, false)
	}
	if err := s.checkAuditLocked(); err != nil {
		return evidence.EvidenceEvent{}, err
	}
	return persisted, nil
}

func (s *Service) operation(ctx context.Context, id string) (truststate.JournalEntry, error) {
	entries, err := s.store.Journal(ctx)
	if err != nil {
		return truststate.JournalEntry{}, err
	}
	for _, e := range entries {
		if e.Operation.ID == id {
			return e, nil
		}
	}
	return truststate.JournalEntry{}, truststate.ErrInvalid
}

func (s *Service) sealOperation(ctx context.Context, id string, recovering bool) (truststate.JournalEntry, error) {
	e, err := s.operation(ctx, id)
	if err != nil {
		return e, err
	}
	if e.Outcome != "" {
		return e, nil
	}
	outcome := truststate.OutcomeRejected
	if recovering {
		outcome = truststate.OutcomeInterrupted
	}
	switch e.State {
	case "RESERVED":
		outcome = truststate.OutcomeVerificationReserved
	case "COMMITTED":
		outcome = truststate.OutcomeCatalogueCommitted
	case "CONSUMED":
		outcome = truststate.OutcomeVerificationConsumed
	}
	if err = s.store.FinishOperation(ctx, id, outcome, map[string]string{}); err != nil {
		return e, err
	}
	return s.operation(ctx, id)
}

// reconcile runs only during construction, before the Service is published.
// It never calls Registry/SDK or replays a domain mutation. Existing ACKed
// records must still exist in the original verified audit prefix. Incomplete
// intents may complete audit delivery, never regain a grant or HTTP success.
func (s *Service) reconcile(ctx context.Context) error {
	entries, err := s.store.Journal(ctx)
	if err != nil {
		return failure(imagetrust.CodeUnavailable, false)
	}
	view, err := s.audit.RecoverySnapshot()
	if err != nil {
		return failure(imagetrust.CodeAuditDegraded, false)
	}
	// Validate all retained bindings before writing even the first repair.
	for _, e := range entries {
		if ctx.Err() != nil || e.Operation.ScopeSHA256 != s.scopeDigest() {
			return failure(imagetrust.CodeUnavailable, false)
		}
		base, ok := view.HashAt(e.Operation.AuditBaseCount)
		if !ok || base != e.Operation.AuditBaseHash {
			return failure(imagetrust.CodeAuditDegraded, false)
		}
		prepared, found := view.Lookup("image-trust/" + e.Operation.ID + "/prepared")
		if found && !eventMatches(prepared, s.preparedEvent(e.Operation)) || e.Operation.PreparedAuditHash != "" && (!found || prepared.Hash != e.Operation.PreparedAuditHash) {
			return failure(imagetrust.CodeAuditDegraded, false)
		}
		result, foundResult := view.Lookup("image-trust/" + e.Operation.ID + "/result")
		if foundResult && (e.Outcome == "" || !eventMatches(result, s.resultEvent(e))) {
			return failure(imagetrust.CodeAuditDegraded, false)
		}
		if e.Acknowledged && (!foundResult || result.Hash != e.ResultAuditHash) {
			return failure(imagetrust.CodeAuditDegraded, false)
		}
	}
	for _, e := range entries {
		if e.Acknowledged {
			continue
		}
		if ctx.Err() != nil {
			return failure(imagetrust.CodeCanceled, true)
		}
		key := "image-trust/" + e.Operation.ID
		prepared, err := s.appendDurableAudit(s.preparedEvent(e.Operation), key+"/prepared", true)
		if err != nil {
			return err
		}
		if err = s.store.BindPreparedAudit(ctx, e.Operation.ID, prepared.Hash); err != nil {
			return failure(imagetrust.CodeUnavailable, true)
		}
		sealed, err := s.sealOperation(ctx, e.Operation.ID, true)
		if err != nil {
			return failure(imagetrust.CodeUnavailable, true)
		}
		result, err := s.appendDurableAudit(s.resultEvent(sealed), key+"/result", true)
		if err != nil {
			return failure(imagetrust.CodeAuditDegraded, true)
		}
		if err = s.store.AcknowledgeOperation(ctx, e.Operation.ID, result.Hash); err != nil {
			return failure(imagetrust.CodeUnavailable, true)
		}
		s.recovered++
	}
	return s.checkAudit()
}
