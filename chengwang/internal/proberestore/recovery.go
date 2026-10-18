package proberestore

import "fmt"

type Topology struct {
	LivePresent  bool
	LiveSHA256   string
	StagePresent bool
	StageSHA256  string
}
type RecoveryAction string

const (
	RecoveryCommitted        RecoveryAction = "COMMITTED"
	RecoveryRestoreOld       RecoveryAction = "RESTORE_OLD_RUNTIME"
	RecoveryRollbackExchange RecoveryAction = "ROLLBACK_EXCHANGE"
	RecoveryContinueRollback RecoveryAction = "CONTINUE_ROLLBACK"
	RecoveryRescueRequired   RecoveryAction = "RESCUE_REQUIRED"
	RecoveryRescueLockdown   RecoveryAction = "RESCUE_LOCKDOWN_CONFIRMED"
)

type RecoveryDecision struct {
	Action     RecoveryAction
	ReasonCode string
}

// DecideRecovery combines lifecycle interval and observed object identity. A
// terminal/rescue phase is never overridden merely because a familiar digest
// pair happens to be present.
func DecideRecovery(j Journal, t Topology) (RecoveryDecision, error) {
	if err := j.Validate(); err != nil {
		return RecoveryDecision{}, err
	}
	if !t.LivePresent && t.LiveSHA256 != "" {
		return RecoveryDecision{}, fmt.Errorf("%w: absent live object has digest", ErrInvalidJournal)
	}
	if !t.StagePresent && t.StageSHA256 != "" {
		return RecoveryDecision{}, fmt.Errorf("%w: absent stage object has digest", ErrInvalidJournal)
	}
	if t.LivePresent && !isHash(t.LiveSHA256) {
		return RecoveryDecision{}, fmt.Errorf("%w: invalid live digest", ErrInvalidJournal)
	}
	if t.StagePresent && !isHash(t.StageSHA256) {
		return RecoveryDecision{}, fmt.Errorf("%w: invalid stage digest", ErrInvalidJournal)
	}
	old, newHash := j.Digests.OldStateSHA256, j.Digests.NewStateSHA256
	oldSingle := t.LivePresent && t.LiveSHA256 == old && !t.StagePresent
	oldNew := t.LivePresent && t.StagePresent && t.LiveSHA256 == old && t.StageSHA256 == newHash
	newOld := t.LivePresent && t.StagePresent && t.LiveSHA256 == newHash && t.StageSHA256 == old
	newSingle := t.LivePresent && t.LiveSHA256 == newHash && !t.StagePresent
	if j.Phase == PhaseRescueRequired {
		return RecoveryDecision{RecoveryRescueRequired, "LOCKDOWN_MUST_BE_VERIFIED"}, nil
	}
	if j.Phase == PhaseRescueLockdown {
		return RecoveryDecision{RecoveryRescueLockdown, "RESCUE_PHASE_FAIL_CLOSED"}, nil
	}
	switch j.Phase {
	case PhaseCommitted:
		if newOld || newSingle {
			return RecoveryDecision{RecoveryCommitted, "COMMITTED_NEW_LIVE"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "COMMITTED_TOPOLOGY_CONTRADICTION"}, nil
	case PhaseRolledBack:
		if oldNew || oldSingle {
			return RecoveryDecision{RecoveryRestoreOld, "ROLLED_BACK_OLD_LIVE"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "ROLLED_BACK_TOPOLOGY_CONTRADICTION"}, nil
	case PhaseFailed:
		if oldNew || oldSingle {
			return RecoveryDecision{RecoveryRestoreOld, "FAILED_WITH_OLD_LIVE"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "FAILED_TOPOLOGY_CONTRADICTION"}, nil
	}
	if j.Phase == PhaseSwitchArmed {
		if oldNew {
			return RecoveryDecision{RecoveryRestoreOld, "SWITCH_ARMED_UNEXCHANGED"}, nil
		}
		if newOld {
			return RecoveryDecision{RecoveryRollbackExchange, "ARMED_EXCHANGE_OBSERVED"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "PRE_SWITCH_TOPOLOGY_CONTRADICTION"}, nil
	}
	if isPreSwitch(j.Phase) {
		if oldNew || oldSingle {
			return RecoveryDecision{RecoveryRestoreOld, "PRE_SWITCH_OLD_LIVE"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "PRE_SWITCH_TOPOLOGY_CONTRADICTION"}, nil
	}
	if isForwardPostSwitch(j.Phase) {
		if newOld {
			return RecoveryDecision{RecoveryRollbackExchange, "POST_SWITCH_ROLLBACK_REQUIRED"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "POST_SWITCH_TOPOLOGY_CONTRADICTION"}, nil
	}
	if isRollbackPreExchange(j.Phase) {
		if newOld {
			return RecoveryDecision{RecoveryContinueRollback, "ROLLBACK_PENDING"}, nil
		}
		if oldNew {
			return RecoveryDecision{RecoveryRestoreOld, "ROLLBACK_EXCHANGE_OBSERVED"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "ROLLBACK_PENDING_TOPOLOGY_CONTRADICTION"}, nil
	}
	if isRollbackPostExchange(j.Phase) {
		if oldNew || oldSingle {
			return RecoveryDecision{RecoveryRestoreOld, "ROLLBACK_OLD_LIVE"}, nil
		}
		return RecoveryDecision{RecoveryRescueRequired, "ROLLBACK_TOPOLOGY_CONTRADICTION"}, nil
	}
	return RecoveryDecision{RecoveryRescueRequired, "UNKNOWN_PHASE_INTERVAL"}, nil
}
func isPreSwitch(p Phase) bool {
	switch p {
	case PhaseNew, PhaseLocked, PhaseInputVerified, PhaseLiveQuiesced, PhaseCurrentBackupDurable, PhaseStaged, PhaseStagedValidated:
		return true
	}
	return false
}
func isForwardPostSwitch(p Phase) bool {
	switch p {
	case PhaseStateExchanged, PhaseContainerRecreated, PhaseEgressRebound, PhaseContainerStarted, PhaseLocalHealthPassed, PhaseIndependentProbePassed:
		return true
	}
	return false
}
func isRollbackPreExchange(p Phase) bool { return p == PhaseRollbackArmed }
func isRollbackPostExchange(p Phase) bool {
	switch p {
	case PhaseStateRollbackExchanged, PhaseRollbackContainerRecreated, PhaseRollbackEgressRebound, PhaseRollbackContainerStarted, PhaseRollbackHealthPassed:
		return true
	}
	return false
}
