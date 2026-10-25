package mihomodeploy

import (
	"encoding/json"
	"reflect"
	"time"
)

const lifecycleRecoveryRootCheckpointSchema = "chengwang.mihomo-recovery-root-checkpoint/v1"

const (
	lifecycleRecoveryCheckpointNone        = "NONE"
	lifecycleRecoveryCheckpointHistoryTail = "HISTORY_TAIL"
	lifecycleRecoveryCheckpointVerified    = "ACTIVE_VERIFIED"
	lifecycleRecoveryCheckpointUnknown     = "RECOVERY_UNKNOWN_ORIGINAL"
)

// A checkpoint names an exact earlier V3 root without embedding that root.
// Current is recovered from the matching epoch ledger, while both append-only
// prefixes remain independently length- and hash-bound. Recovery is either
// absent, the exact history tail, or derived from the completed transaction by
// removing only the v3 completion source and terminal fields.
type lifecycleRecoveryRootCheckpoint struct {
	Schema                      string          `json:"schema"`
	Revision                    uint64          `json:"revision"`
	RecordSHA256                string          `json:"recordSHA256"`
	LastTrustedAt               time.Time       `json:"lastTrustedAt"`
	RecoveryOwner               *lifecycleOwner `json:"recoveryOwner"`
	LastRecoveryFence           uint64          `json:"lastRecoveryFence"`
	CurrentEpochPosition        uint64          `json:"currentEpochPosition"`
	CurrentLedgerSHA256         string          `json:"currentLedgerSHA256"`
	RetiredPrefixCount          uint64          `json:"retiredPrefixCount"`
	RetiredPrefixSHA256         string          `json:"retiredPrefixSHA256"`
	RecoveryHistoryPrefixCount  uint64          `json:"recoveryHistoryPrefixCount"`
	RecoveryHistoryPrefixSHA256 string          `json:"recoveryHistoryPrefixSHA256"`
	RecoveryKind                string          `json:"recoveryKind"`
}

func cloneLifecycleRecoveryRootCheckpoint(v lifecycleRecoveryRootCheckpoint) lifecycleRecoveryRootCheckpoint {
	return lifecycleRecoveryRootCheckpoint{Schema: v.Schema, Revision: v.Revision, RecordSHA256: v.RecordSHA256, LastTrustedAt: v.LastTrustedAt,
		RecoveryOwner: lifecycleClonePointer(v.RecoveryOwner, func(o lifecycleOwner) lifecycleOwner { return o }), LastRecoveryFence: v.LastRecoveryFence,
		CurrentEpochPosition: v.CurrentEpochPosition, CurrentLedgerSHA256: v.CurrentLedgerSHA256, RetiredPrefixCount: v.RetiredPrefixCount,
		RetiredPrefixSHA256: v.RetiredPrefixSHA256, RecoveryHistoryPrefixCount: v.RecoveryHistoryPrefixCount,
		RecoveryHistoryPrefixSHA256: v.RecoveryHistoryPrefixSHA256, RecoveryKind: v.RecoveryKind}
}

func lifecycleRecoveryRetiredPrefixHash(v []lifecycleRetiredEpoch) (string, error) {
	return lifecycleHash(struct {
		Schema  string                  `json:"schema"`
		Entries []lifecycleRetiredEpoch `json:"entries"`
	}{"chengwang.mihomo-recovery-retired-prefix/v1", v})
}

func lifecycleRecoveryHistoryPrefixHash(v []lifecycleRecoveryTxn) (string, error) {
	return lifecycleHash(struct {
		Schema  string                 `json:"schema"`
		Entries []lifecycleRecoveryTxn `json:"entries"`
	}{"chengwang.mihomo-recovery-history-prefix/v1", v})
}

func lifecycleRecoveryCheckpoint(w *lifecycleV3Wire, kind string) (lifecycleRecoveryRootCheckpoint, error) {
	var zero lifecycleRecoveryRootCheckpoint
	if w == nil || w.Current.Completed == nil || w.Current.Terminated == nil || w.Current.Observations == nil || w.Current.Tombstones == nil ||
		w.RetiredEpochs == nil || w.RecoveryHistory == nil || len(w.RetiredEpochs) > maxLifecycleHistory || len(w.RecoveryHistory) > maxLifecycleHistory {
		return zero, errLifecycleUnsafe
	}
	switch kind {
	case lifecycleRecoveryCheckpointNone:
		if w.Recovery != nil {
			return zero, errLifecycleUnsafe
		}
	case lifecycleRecoveryCheckpointHistoryTail:
		if w.Recovery == nil || len(w.RecoveryHistory) == 0 || !reflect.DeepEqual(*w.Recovery, w.RecoveryHistory[len(w.RecoveryHistory)-1]) ||
			(w.Recovery.Phase != "COMPLETED" && w.Recovery.Phase != "REVOKED_UNSTARTED" && w.Recovery.Phase != "FAILED_RECONCILED") {
			return zero, errLifecycleUnsafe
		}
	case lifecycleRecoveryCheckpointVerified:
		if w.Recovery == nil || w.Recovery.Phase != "START_ARMED" || w.Recovery.Completion != nil || w.Recovery.Failure != nil || w.Recovery.Revocation != nil ||
			w.Recovery.Execution == nil || !lifecycleRecoveryExecutionVerifiedSchema(w.Recovery.Execution.Schema) || w.Recovery.Execution.Verification == nil || w.Recovery.Execution.CompletionSource != nil {
			return zero, errLifecycleUnsafe
		}
	case lifecycleRecoveryCheckpointUnknown:
		if w.Recovery == nil || w.Recovery.Phase != "RECOVERY_UNKNOWN" || w.Recovery.Failure == nil || w.Recovery.Reconciliation != nil {
			return zero, errLifecycleUnsafe
		}
	default:
		return zero, errLifecycleUnsafe
	}
	ledgerSHA, err := lifecycleHash(w.Current)
	if err != nil {
		return zero, errLifecycleUnsafe
	}
	retiredSHA, err := lifecycleRecoveryRetiredPrefixHash(w.RetiredEpochs)
	if err != nil {
		return zero, errLifecycleUnsafe
	}
	historySHA, err := lifecycleRecoveryHistoryPrefixHash(w.RecoveryHistory)
	if err != nil {
		return zero, errLifecycleUnsafe
	}
	owner := lifecycleClonePointer(w.RecoveryOwner, func(v lifecycleOwner) lifecycleOwner { return v })
	return lifecycleRecoveryRootCheckpoint{
		Schema: lifecycleRecoveryRootCheckpointSchema, Revision: w.Revision, RecordSHA256: w.RecordSHA256, LastTrustedAt: w.LastTrustedAt,
		RecoveryOwner: owner, LastRecoveryFence: w.LastRecoveryFence, CurrentEpochPosition: uint64(len(w.RetiredEpochs)), CurrentLedgerSHA256: ledgerSHA,
		RetiredPrefixCount: uint64(len(w.RetiredEpochs)), RetiredPrefixSHA256: retiredSHA,
		RecoveryHistoryPrefixCount: uint64(len(w.RecoveryHistory)), RecoveryHistoryPrefixSHA256: historySHA, RecoveryKind: kind,
	}, nil
}

func lifecycleRecoveryCheckpointValid(c lifecycleRecoveryRootCheckpoint) bool {
	if c.Schema != lifecycleRecoveryRootCheckpointSchema || c.Revision == 0 || !lifecycleNonzeroHash(c.RecordSHA256) || !lifecycleTime(c.LastTrustedAt) ||
		c.CurrentEpochPosition != c.RetiredPrefixCount || c.CurrentEpochPosition > maxLifecycleHistory || c.RecoveryHistoryPrefixCount > maxLifecycleHistory ||
		!lifecycleNonzeroHash(c.CurrentLedgerSHA256) || !lifecycleNonzeroHash(c.RetiredPrefixSHA256) || !lifecycleNonzeroHash(c.RecoveryHistoryPrefixSHA256) {
		return false
	}
	if c.RecoveryOwner == nil {
		if c.LastRecoveryFence != 0 {
			return false
		}
	} else if c.RecoveryOwner.Fence == 0 || c.RecoveryOwner.Fence != c.LastRecoveryFence || !lifecycleNonzeroHash(c.RecoveryOwner.OwnerNonce) ||
		!lifecycleTime(c.RecoveryOwner.AcquiredAt) || !lifecycleTime(c.RecoveryOwner.RenewedAt) || !lifecycleTime(c.RecoveryOwner.ExpiresAt) ||
		c.RecoveryOwner.RenewedAt.Before(c.RecoveryOwner.AcquiredAt) || !c.RecoveryOwner.ExpiresAt.After(c.RecoveryOwner.RenewedAt) {
		return false
	}
	switch c.RecoveryKind {
	case lifecycleRecoveryCheckpointNone:
		return c.RecoveryHistoryPrefixCount == 0
	case lifecycleRecoveryCheckpointHistoryTail:
		return c.RecoveryHistoryPrefixCount > 0
	case lifecycleRecoveryCheckpointVerified:
		return true
	case lifecycleRecoveryCheckpointUnknown:
		return true
	default:
		return false
	}
}

func lifecycleRecoveryVerifiedFromCompleted(a lifecycleRecoveryTxn) (*lifecycleRecoveryTxn, error) {
	if a.Phase != "COMPLETED" || a.Completion == nil || a.Failure != nil || a.Revocation != nil || a.Execution == nil ||
		!lifecycleRecoveryExecutionCompletedSchema(a.Execution.Schema) || a.Execution.Verification == nil || a.Execution.CompletionSource == nil {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	var source lifecycleRecoveryTxn
	if json.Unmarshal(raw, &source) != nil {
		return nil, errLifecycleUnsafe
	}
	source.Phase = "START_ARMED"
	source.Completion = nil
	source.UpdatedAt = source.Execution.CompletionSource.Root.LastTrustedAt
	verifiedSchema, ok := lifecycleRecoveryCompletedToVerifiedSchema(source.Execution.Schema)
	if !ok {
		return nil, errLifecycleUnsafe
	}
	source.Execution.Schema = verifiedSchema
	source.Execution.CompletionSource = nil
	return &source, nil
}

func lifecycleRecoveryUnknownFromReconciled(a lifecycleRecoveryTxn) (*lifecycleRecoveryTxn, error) {
	r := a.Reconciliation
	if a.Phase != "FAILED_RECONCILED" || r == nil || a.Failure == nil || a.Completion != nil || !lifecycleTime(r.OriginalTxnUpdatedAt) {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	var source lifecycleRecoveryTxn
	if json.Unmarshal(raw, &source) != nil {
		return nil, errLifecycleUnsafe
	}
	source.Phase = "RECOVERY_UNKNOWN"
	source.UpdatedAt = r.OriginalTxnUpdatedAt
	source.Reconciliation = nil
	return &source, nil
}

// Reconstructs exact earlier root bytes from immutable ledgers and bounded
// prefixes. It never accepts caller-provided root bytes or truncates a suffix
// without a stored position and digest.
func lifecycleRecoveryCheckpointPreimage(w *lifecycleV3Wire, c lifecycleRecoveryRootCheckpoint, completed *lifecycleRecoveryTxn) ([]byte, error) {
	return lifecycleRecoveryCheckpointPreimageScoped(w, c, completed, newLifecycleV3DecodeScope())
}

func lifecycleRecoveryCheckpointPreimageScoped(w *lifecycleV3Wire, c lifecycleRecoveryRootCheckpoint, completed *lifecycleRecoveryTxn, scope *lifecycleV3DecodeScope) ([]byte, error) {
	if scope == nil || w == nil || !lifecycleRecoveryCheckpointValid(c) || c.CurrentEpochPosition > uint64(len(w.RetiredEpochs)) ||
		c.RetiredPrefixCount > uint64(len(w.RetiredEpochs)) || c.RecoveryHistoryPrefixCount > uint64(len(w.RecoveryHistory)) {
		return nil, errLifecycleUnsafe
	}
	if scope.charge(int(c.RetiredPrefixCount)+int(c.RecoveryHistoryPrefixCount)+1) != nil {
		return nil, errLifecycleUnsafe
	}
	retired := w.RetiredEpochs[:int(c.RetiredPrefixCount)]
	history := w.RecoveryHistory[:int(c.RecoveryHistoryPrefixCount)]
	retiredSHA, err := lifecycleRecoveryRetiredPrefixHash(retired)
	if err != nil || retiredSHA != c.RetiredPrefixSHA256 {
		return nil, errLifecycleUnsafe
	}
	historySHA, err := lifecycleRecoveryHistoryPrefixHash(history)
	if err != nil || historySHA != c.RecoveryHistoryPrefixSHA256 {
		return nil, errLifecycleUnsafe
	}
	var current lifecycleEpochLedger
	if c.CurrentEpochPosition < uint64(len(w.RetiredEpochs)) {
		current = w.RetiredEpochs[int(c.CurrentEpochPosition)].Ledger
	} else if c.CurrentEpochPosition == uint64(len(w.RetiredEpochs)) {
		current = w.Current
	} else {
		return nil, errLifecycleUnsafe
	}
	ledgerSHA, err := lifecycleHash(current)
	if err != nil || ledgerSHA != c.CurrentLedgerSHA256 {
		return nil, errLifecycleUnsafe
	}
	var recovery *lifecycleRecoveryTxn
	switch c.RecoveryKind {
	case lifecycleRecoveryCheckpointNone:
	case lifecycleRecoveryCheckpointHistoryTail:
		if len(history) == 0 {
			return nil, errLifecycleUnsafe
		}
		v := history[len(history)-1]
		recovery = &v
	case lifecycleRecoveryCheckpointVerified:
		if completed == nil {
			return nil, errLifecycleUnsafe
		}
		recovery, err = lifecycleRecoveryVerifiedFromCompleted(*completed)
		if err != nil {
			return nil, errLifecycleUnsafe
		}
	case lifecycleRecoveryCheckpointUnknown:
		if completed == nil {
			return nil, errLifecycleUnsafe
		}
		recovery, err = lifecycleRecoveryUnknownFromReconciled(*completed)
		if err != nil {
			return nil, errLifecycleUnsafe
		}
	default:
		return nil, errLifecycleUnsafe
	}
	source := &lifecycleV3Wire{Schema: w.Schema, Boundary: w.Boundary, Revision: c.Revision, RecordSHA256: c.RecordSHA256, LastTrustedAt: c.LastTrustedAt,
		Provisioning: w.Provisioning, SourceV2: w.SourceV2, Current: current, RetiredEpochs: append([]lifecycleRetiredEpoch{}, retired...),
		RecoveryOwner: lifecycleClonePointer(c.RecoveryOwner, func(v lifecycleOwner) lifecycleOwner { return v }), LastRecoveryFence: c.LastRecoveryFence,
		Recovery: recovery, RecoveryHistory: append([]lifecycleRecoveryTxn{}, history...)}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > maxLifecycleControlBytes {
		return nil, errLifecycleUnsafe
	}
	decoded, err := decodeLifecycleV3RecordScoped(raw, scope)
	if err != nil || decoded.core.Revision != c.Revision || decoded.core.RecordSHA256 != c.RecordSHA256 || !bytesEqualLifecycleRoot(decoded.core, source) {
		return nil, errLifecycleUnsafe
	}
	return raw, nil
}

func bytesEqualLifecycleRoot(a, b *lifecycleV3Wire) bool { return reflect.DeepEqual(a, b) }
