package product

import (
	"context"
	"time"

	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

var _ imagetrust.HistoryBackend = (*Service)(nil)

func (s *Service) History(ctx context.Context, actor authz.Principal, request imagetrust.HistoryRequest) (imagetrust.History, error) {
	if err := s.authorize(ctx, actor, authz.ActionHistoryImageTrust, false); err != nil {
		return imagetrust.History{}, err
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	if request.Limit < 1 || request.Limit > 50 || request.Offset < 0 || request.Offset > truststate.MaxOperations {
		return imagetrust.History{}, failure(imagetrust.CodeInvalid, false)
	}
	before, err := s.store.Inspect(ctx)
	if err != nil {
		return imagetrust.History{}, classify(ctx, err, false)
	}
	if request.Sequence != 0 && request.Sequence != before.Sequence {
		return imagetrust.History{}, failure(imagetrust.CodeConflict, false)
	}
	entries, err := s.store.Journal(ctx)
	if err != nil {
		return imagetrust.History{}, classify(ctx, err, false)
	}
	view, err := s.audit.RecoverySnapshot()
	if err != nil {
		s.poison()
		return imagetrust.History{}, failure(imagetrust.CodeAuditDegraded, false)
	}
	// A legitimate operation may seal its outcome between Journal and the audit
	// snapshot. Fence that race before treating an apparent binding mismatch as
	// corruption; otherwise a normal writer could poison a healthy reader.
	middle, err := s.store.Inspect(ctx)
	if err != nil {
		return imagetrust.History{}, classify(ctx, err, false)
	}
	if middle.Sequence != before.Sequence {
		return imagetrust.History{}, failure(imagetrust.CodeConflict, false)
	}
	// Validate every retained cross-store binding, not just the requested page.
	// Historical records never become authority through this read projection.
	projected := make([]imagetrust.HistoryEntry, 0, len(entries))
	for _, entry := range entries {
		value, err := s.historyEntry(entry, view)
		if err != nil {
			s.poison()
			return imagetrust.History{}, err
		}
		projected = append(projected, value)
	}
	after, err := s.store.Inspect(ctx)
	if err != nil {
		return imagetrust.History{}, classify(ctx, err, false)
	}
	if before.Sequence != after.Sequence || request.Sequence != 0 && request.Sequence != after.Sequence {
		return imagetrust.History{}, failure(imagetrust.CodeConflict, false)
	}
	if ctx.Err() != nil {
		return imagetrust.History{}, failure(imagetrust.CodeCanceled, false)
	}
	start := request.Offset
	if start > len(projected) {
		start = len(projected)
	}
	end := start + request.Limit
	if end > len(projected) {
		end = len(projected)
	}
	return imagetrust.History{Boundary: imagetrust.HistoryBoundary, Authorization: "BLOCKED", DeviceActionsExecuted: false, ObservedAtUnix: time.Now().UTC().Unix(), Sequence: after.Sequence, Total: len(projected), Offset: request.Offset, Limit: request.Limit, Entries: append([]imagetrust.HistoryEntry{}, projected[start:end]...)}, nil
}

func (s *Service) historyEntry(entry truststate.JournalEntry, view evidence.RecoveryView) (imagetrust.HistoryEntry, error) {
	if entry.Operation.ScopeSHA256 != s.scopeDigest() {
		return imagetrust.HistoryEntry{}, failure(imagetrust.CodeUnavailable, false)
	}
	base, ok := view.HashAt(entry.Operation.AuditBaseCount)
	if !ok || base != entry.Operation.AuditBaseHash {
		return imagetrust.HistoryEntry{}, failure(imagetrust.CodeAuditDegraded, false)
	}
	prepared, preparedFound := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
	if preparedFound && !eventMatches(prepared, s.preparedEvent(entry.Operation)) || entry.Operation.PreparedAuditHash != "" && (!preparedFound || prepared.Hash != entry.Operation.PreparedAuditHash) {
		return imagetrust.HistoryEntry{}, failure(imagetrust.CodeAuditDegraded, false)
	}
	result, resultFound := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
	if resultFound && (entry.Outcome == "" || !eventMatches(result, s.resultEvent(entry))) || entry.Acknowledged && (!resultFound || result.Hash != entry.ResultAuditHash) {
		return imagetrust.HistoryEntry{}, failure(imagetrust.CodeAuditDegraded, false)
	}
	preparedAt, resultAt := int64(0), int64(0)
	if entry.Operation.PreparedAuditHash != "" {
		preparedAt = prepared.OccurredAt.Unix()
	}
	if entry.ResultAuditHash != "" {
		if !resultFound || result.Hash != entry.ResultAuditHash {
			return imagetrust.HistoryEntry{}, failure(imagetrust.CodeAuditDegraded, false)
		}
		resultAt = result.OccurredAt.Unix()
	}
	return imagetrust.HistoryEntry{OperationID: entry.Operation.ID, ActorID: entry.Operation.ActorID, Kind: entry.Operation.Kind, State: entry.State, Outcome: entry.Outcome, Acknowledged: entry.Acknowledged, PolicyID: entry.Operation.Data["policyId"], GrantID: entry.GrantID, Generation: entry.Generation, CatalogueSHA256: entry.CatalogueSHA256, PreparedAuditHash: entry.Operation.PreparedAuditHash, ResultAuditHash: entry.ResultAuditHash, PreparedAtUnix: preparedAt, ResultAtUnix: resultAt}, nil
}
