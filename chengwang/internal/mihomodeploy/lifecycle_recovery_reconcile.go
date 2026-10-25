package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

const lifecycleRecoveryReconciliationSchema = "chengwang.mihomo-recovery-reconciliation/v1"
const lifecycleRecoveryCleanupSchema = "chengwang.mihomo-owned-recovery-cleanup/v1"

// A reconcile permit is an exact pre-physical-action reservation. Only the
// Linux source coordinator may combine it with its separately registered
// cleanup custody. Neither this value nor persisted cleanup evidence is an
// authorization or a generic callback/factory.
type labRecoveryReconcilePermit struct{ core *labRecoveryReconcilePermitCore }
type labRecoveryReconcilePermitCore struct {
	runtime          *labLifecycleRuntimeCore
	service          *labServiceCore
	store            *lifecycleRecoveryStoreCore
	disk             lifecycleDisk
	owner            *lifecycleRecoveryOwnerCore
	nonce            string
	fence            uint64
	recoveryID       string
	revision         uint64
	recordSHA256     string
	canonical        string
	originalRoot     lifecycleRecoveryRootCheckpoint
	unknownUpdatedAt time.Time
	used             bool
	binding          func(*labRecoveryReconcilePermitCore) bool
}

type labRecoveryTerminalReentryPermit struct{ core *labRecoveryTerminalReentryPermitCore }
type labRecoveryTerminalReentryPermitCore struct {
	runtime      *labLifecycleRuntimeCore
	service      *labServiceCore
	store        *lifecycleRecoveryStoreCore
	disk         lifecycleDisk
	terminalPlan string
	terminalRoot string
	terminalCanonical string
	cleanupSHA   string
	fence        uint64
	used         bool
	binding      func(*labRecoveryTerminalReentryPermitCore) bool
}

type labRecoveryAbsenceCustodyCore struct {
	runtime    *labLifecycleRuntimeCore
	service    *labServiceCore
	store      *lifecycleRecoveryStoreCore
	disk       lifecycleDisk
	cleanupSHA string
	terminalRoot string
	terminalCanonical string
	planSHA, recoveryID string
	ownerNonce string
	ownerFence uint64
	reentry *labRecoveryTerminalReentryPermitCore
	oldIdentity labKernelIdentity
	binding    func(*labRecoveryAbsenceCustodyCore) bool
}

type labRecoveryAbsentStartPermit struct{ core *labRecoveryAbsentStartPermitCore }
type labRecoveryAbsentStartPermitCore struct {
	store        *lifecycleRecoveryStoreCore
	absence      *labRecoveryAbsenceCustodyCore
	recoveryID   string
	planSHA256   string
	intentSHA256 string
	revision     uint64
	recordSHA256 string
	fence        uint64
	deadline     time.Time
	used         bool
}
type labRecoveryAbsentStartFact struct {
	RecoveryID, PlanSHA256, StartIntentSHA256 string
	Revision uint64
	RecordSHA256 string
	TargetArtifact ArtifactDescriptor
	ArmedAt, ExpiresAt time.Time
}

func (labRecoveryReconcilePermit) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, lifecycleRecoveryDebug) }
func (labRecoveryReconcilePermit) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (p *labRecoveryReconcilePermit) UnmarshalJSON([]byte) error { if p != nil { p.core = nil }; return errLifecycleUnsafe }
func (labRecoveryTerminalReentryPermit) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, lifecycleRecoveryDebug) }
func (labRecoveryTerminalReentryPermit) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (p *labRecoveryTerminalReentryPermit) UnmarshalJSON([]byte) error { if p != nil { p.core = nil }; return errLifecycleUnsafe }
func (labRecoveryAbsentStartPermit) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, lifecycleRecoveryDebug) }
func (labRecoveryAbsentStartPermit) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (p *labRecoveryAbsentStartPermit) UnmarshalJSON([]byte) error { if p != nil { p.core = nil }; return errLifecycleUnsafe }

func lifecycleRecoveryCleanupHash(v lifecycleRecoveryCleanupFact) (string, error) {
	v.CleanupSHA256 = ""
	return lifecycleHash(v)
}

func lifecycleRecoveryCleanupProbeValid(v lifecycleRecoveryCleanupProbe, role string, port uint16, previous, observed time.Time) bool {
	return v.Role == role && lifecycleTime(v.ObservedAt) && !v.ObservedAt.Before(previous) && !v.ObservedAt.After(observed) &&
		v.Probe.Port == port && v.Probe.Attempted && v.Probe.Result == "CONNECTION_REFUSED"
}

func lifecycleRecoveryCleanupAttemptFailureValid(outcome, code string) bool {
	switch outcome {
	case "ENTRY_REJECTED":
		switch code {
		case "CONTEXT_OR_INPUT_REJECTED", "PERMIT_REJECTED", "BINDING_REJECTED", "ATTEMPT_SPENT", "INPUT_REJECTED",
			"NAMESPACE_REJECTED", "ARTIFACT_REJECTED", "BUDGET_REJECTED", "STATE_REJECTED":
			return true
		}
	case "START_UNCERTAIN":
		switch code {
		case "START_REJECTED", "BUDGET_REJECTED", "IDENTITY_REJECTED", "LISTENERS_REJECTED", "OWNED_REJECTED", "ISSUER_REJECTED", "FACT_REJECTED":
			return true
		}
	case "STARTED":
		return code == "NONE"
	}
	return false
}

func lifecycleRecoveryCleanupAttemptStreamValid(v *labKernelStream) bool {
	return v != nil && v.Bytes >= 0 && v.Bytes <= 64<<10 && v.TotalBytes >= int64(v.Bytes) &&
		lifecycleNonzeroHash(v.SHA256) && (!v.Truncated || v.TotalBytes > int64(v.Bytes))
}

func lifecycleRecoveryCleanupAttemptKernelValid(v *labKernelStartObservation) bool {
	if v == nil {
		return true
	}
	if (v.Stdout == nil) != (v.Stderr == nil) || (v.Stdout != nil &&
		(!lifecycleRecoveryCleanupAttemptStreamValid(v.Stdout) || !lifecycleRecoveryCleanupAttemptStreamValid(v.Stderr))) {
		return false
	}
	switch v.WaitErrorClass {
	case "NOT_WAITED", "NONE", "EXIT_STATUS", "WAIT_ERROR":
	default:
		return false
	}
	if v.Started == nil {
		return v.PID == nil && v.StartTicks == nil && v.WaitReturned == nil && v.ExitCode == nil && v.Signal == nil &&
			v.TermSent == nil && v.KillSent == nil && v.GroupAbsent == nil && v.WaitErrorClass == "NOT_WAITED"
	}
	if v.WaitReturned == nil || (v.ExitCode != nil && v.Signal != nil) ||
		(v.ExitCode != nil && (*v.ExitCode < 0 || *v.ExitCode > 255)) ||
		(v.Signal != nil && (*v.Signal <= 0 || *v.Signal > 255)) {
		return false
	}
	if *v.Started {
		if !v.Attempted || v.PID == nil || *v.PID <= 0 || v.StartTicks == nil || *v.StartTicks == 0 ||
			v.TermSent == nil || v.KillSent == nil {
			return false
		}
	} else if v.PID != nil || v.StartTicks != nil || v.TermSent != nil || v.KillSent != nil {
		return false
	}
	if !*v.WaitReturned {
		return v.WaitErrorClass == "NOT_WAITED" && v.ExitCode == nil && v.Signal == nil && v.GroupAbsent == nil
	}
	return v.WaitErrorClass != "NOT_WAITED" && v.GroupAbsent != nil && v.Stdout != nil && v.Stdout.Complete && v.Stderr.Complete
}

func lifecycleRecoveryCleanupAttemptIdentityValid(id labKernelIdentity, old labKernelIdentity, target ArtifactDescriptor) bool {
	return labQuiescenceIdentityValid(id) && (id.PID != old.PID || id.StartTicks != old.StartTicks) &&
		id.NetNSInode == old.NetNSInode && id.ELFSHA256 == old.ELFSHA256 && id.ELFBytes == old.ELFBytes &&
		id.SourceCommit == old.SourceCommit && id.ArtifactSHA256 == target.Config.SHA256 &&
		id.ControllerPort == target.ControllerPort && id.MixedPort == target.MixedPort
}

func lifecycleRecoveryCleanupUnstartedAttemptValid(v *labKernelStartObservation) bool {
	if v == nil {
		return true
	}
	if v.Started == nil || *v.Started || v.PID != nil || v.StartTicks != nil || v.WaitReturned == nil || *v.WaitReturned ||
		v.WaitErrorClass != "NOT_WAITED" || v.ExitCode != nil || v.Signal != nil || v.TermSent != nil || v.KillSent != nil || v.GroupAbsent != nil {
		return false
	}
	if !v.Attempted {
		return v.Stdout == nil && v.Stderr == nil
	}
	if v.Stdout == nil || v.Stderr == nil {
		return false
	}
	want := labKernelStream{SHA256: labConfigHash(nil), Complete: true}
	return *v.Stdout == want && *v.Stderr == want
}

func lifecycleRecoveryCleanupAttemptValid(v *labRecoveryStartObservation, absent bool, next *lifecycleRecoveryCleanedKernel,
	old labKernelIdentity, target ArtifactDescriptor, observedAt time.Time) bool {
	if v == nil {
		return next == nil
	}
	wantSchema := labRecoveryStartObservationSchema
	if absent {
		wantSchema = labRecoveryAbsentStartObservationSchema
	}
	if v.Schema != wantSchema || !lifecycleRecoveryCleanupAttemptFailureValid(v.Outcome, v.FailureCode) ||
		!lifecycleRecoveryCleanupAttemptKernelValid(v.StartObservation) {
		return false
	}
	if !v.StartInvoked {
		if v.StartReturned || v.StartErrorClass != nil || v.StartObservation != nil || v.StartupIdentity != nil ||
			v.VerifiedIdentity != nil || v.ListenersBefore != nil || v.ListenersAfter != nil || v.StartedAt != nil || v.ReturnedAt != nil ||
			v.Outcome != "ENTRY_REJECTED" || next != nil {
			return false
		}
		if v.FailureCode == "CONTEXT_OR_INPUT_REJECTED" || v.FailureCode == "PERMIT_REJECTED" {
			return !v.PermitConsumed && v.NamespaceInode == nil
		}
		switch v.FailureCode {
		case "BINDING_REJECTED", "ATTEMPT_SPENT", "INPUT_REJECTED":
			return v.PermitConsumed && v.NamespaceInode == nil
		case "NAMESPACE_REJECTED":
			return v.PermitConsumed && (v.NamespaceInode == nil || *v.NamespaceInode != 0 && *v.NamespaceInode != old.NetNSInode)
		case "ARTIFACT_REJECTED", "BUDGET_REJECTED", "STATE_REJECTED":
			return v.PermitConsumed && v.NamespaceInode != nil && *v.NamespaceInode == old.NetNSInode
		}
		return false
	}
	if !v.PermitConsumed || !v.StartReturned || v.StartErrorClass == nil || v.StartedAt == nil || v.ReturnedAt == nil ||
		!lifecycleTime(*v.StartedAt) || !lifecycleTime(*v.ReturnedAt) || v.ReturnedAt.Before(*v.StartedAt) ||
		v.ReturnedAt.After(observedAt) || v.NamespaceInode == nil || *v.NamespaceInode != old.NetNSInode ||
		v.Outcome == "ENTRY_REJECTED" {
		return false
	}
	if (*v.StartErrorClass == "FAILED") != (v.FailureCode == "START_REJECTED") ||
		(*v.StartErrorClass != "FAILED" && *v.StartErrorClass != "NONE") {
		return false
	}
	if v.ListenersBefore != nil && !*v.ListenersBefore ||
		v.VerifiedIdentity != nil && v.StartupIdentity == nil ||
		v.StartupIdentity != nil && !lifecycleRecoveryCleanupAttemptIdentityValid(*v.StartupIdentity, old, target) ||
		v.VerifiedIdentity != nil && !lifecycleRecoveryCleanupAttemptIdentityValid(*v.VerifiedIdentity, old, target) ||
		v.ListenersAfter != nil && (v.ListenersBefore == nil || !*v.ListenersBefore || v.VerifiedIdentity == nil) {
		return false
	}
	if next == nil {
		return v.Outcome == "START_UNCERTAIN" && v.FailureCode == "START_REJECTED" && *v.StartErrorClass == "FAILED" &&
			v.StartupIdentity == nil && v.VerifiedIdentity == nil && v.ListenersBefore == nil && v.ListenersAfter == nil &&
			lifecycleRecoveryCleanupUnstartedAttemptValid(v.StartObservation)
	}
	s := v.StartObservation
	if s == nil || !s.Attempted || s.Started == nil || !*s.Started || s.PID == nil || s.StartTicks == nil || s.Stdout == nil || s.Stderr == nil ||
		!lifecycleRecoveryCleanupAttemptIdentityValid(next.Identity, old, target) {
		return false
	}
	startupMatches := v.StartupIdentity != nil && *v.StartupIdentity == next.Identity
	verifiedMatches := v.VerifiedIdentity != nil && *v.VerifiedIdentity == next.Identity
	startMatchesNext := *s.PID == next.Identity.PID && *s.StartTicks == next.Identity.StartTicks
	startMatchesStartup := v.StartupIdentity != nil && *s.PID == v.StartupIdentity.PID && *s.StartTicks == v.StartupIdentity.StartTicks
	lateIdentityMismatch := v.FailureCode == "IDENTITY_REJECTED" && v.StartupIdentity != nil && v.VerifiedIdentity != nil &&
		*v.StartupIdentity != *v.VerifiedIdentity && startMatchesStartup && verifiedMatches
	if !startMatchesNext && !lateIdentityMismatch ||
		v.ListenersAfter != nil && !*v.ListenersAfter && v.FailureCode != "LISTENERS_REJECTED" {
		return false
	}
	full := startupMatches && verifiedMatches && v.ListenersBefore != nil && *v.ListenersBefore &&
		v.ListenersAfter != nil && *v.ListenersAfter
	if v.Outcome == "START_UNCERTAIN" {
		// The normal and OLD_EPOCH_ABSENT Linux producers share this exact
		// sequence: START_REJECTED is the sole return immediately after the
		// native call; BUDGET_REJECTED is checked immediately after that call or
		// after the complete listener/owner prefix; every other code is emitted
		// at the named stage in between. New is source-owned cleanup evidence,
		// never authority reconstructed from these serialized fields.
		switch v.FailureCode {
		case "START_REJECTED":
			return *v.StartErrorClass == "FAILED" && v.StartupIdentity == nil && v.VerifiedIdentity == nil &&
				v.ListenersBefore == nil && v.ListenersAfter == nil
		case "BUDGET_REJECTED":
			return *v.StartErrorClass == "NONE" &&
				(v.StartupIdentity == nil && v.VerifiedIdentity == nil && v.ListenersBefore == nil && v.ListenersAfter == nil || full)
		case "IDENTITY_REJECTED":
			return *v.StartErrorClass == "NONE" && v.VerifiedIdentity == nil && v.ListenersAfter == nil &&
				(v.StartupIdentity == nil && v.ListenersBefore == nil || startupMatches && v.ListenersBefore != nil && *v.ListenersBefore) ||
				*v.StartErrorClass == "NONE" && v.ListenersBefore != nil && *v.ListenersBefore && v.ListenersAfter == nil && lateIdentityMismatch
		case "LISTENERS_REJECTED":
			return *v.StartErrorClass == "NONE" && startupMatches &&
				(v.ListenersBefore == nil && v.VerifiedIdentity == nil && v.ListenersAfter == nil ||
					v.ListenersBefore != nil && *v.ListenersBefore && verifiedMatches &&
						v.ListenersAfter != nil && !*v.ListenersAfter)
		case "OWNED_REJECTED", "ISSUER_REJECTED", "FACT_REJECTED":
			return *v.StartErrorClass == "NONE" && full
		}
		return false
	}
	return v.Outcome == "STARTED" && v.FailureCode == "NONE" && *v.StartErrorClass == "NONE" && full &&
		s.WaitReturned != nil && !*s.WaitReturned && s.WaitErrorClass == "NOT_WAITED" && s.ExitCode == nil && s.Signal == nil &&
		s.GroupAbsent == nil && s.TermSent != nil && !*s.TermSent && s.KillSent != nil && !*s.KillSent && s.Stdout != nil && s.Stderr != nil
}

func lifecycleRecoveryCleanupValid(v lifecycleRecoveryCleanupFact, a lifecycleRecoveryTxn, source lifecycleHead, expectedAbsentOld *labKernelIdentity, at time.Time) bool {
	if v.Schema != lifecycleRecoveryCleanupSchema || v.RecoveryID != a.Plan.RecoveryID || a.Failure == nil || v.FailureCode != a.Failure.Code ||
		!lifecycleTime(v.ObservedAt) || v.ObservedAt.After(at) || !lifecycleNonzeroHash(v.SourceReceiptSHA256) || !lifecycleNonzeroHash(v.CleanupSHA256) ||
		v.Old.Identity.PID != source.PID || !lifecycleRecoveryIdentityMatches(v.Old.Identity, source) || !labQuiescenceExitDrained(v.Old.Exit) || v.Probes == nil || len(v.Probes) != 4 {
		return false
	}
	absent := a.Plan.Schema == labRecoveryPlanSchemaV3 && a.Plan.StartMode == labRecoveryStartModeOldEpochAbsent
	if a.Quiescence != nil {
		if absent {
			return false
		}
		o := a.Quiescence.Observation
		if o.Stop == nil || o.StartupIdentity == nil || !reflect.DeepEqual(v.Old.Identity, *o.StartupIdentity) || !reflect.DeepEqual(v.Old.Exit, *o.Stop) {
			return false
		}
	} else if absent {
		if a.StopIntent != nil || a.StopBinding != nil || expectedAbsentOld == nil || v.Old.Identity != *expectedAbsentOld {
			return false
		}
	} else if a.StopBinding == nil || v.Old.Identity != a.StopBinding.ExpectedOldIdentity {
		return false
	}
	if a.Execution == nil {
		if !lifecycleRecoveryCleanupAttemptValid(v.Attempt, absent, v.New, v.Old.Identity, a.Plan.TargetArtifact, v.ObservedAt) {
			return false
		}
		if v.New != nil && !labQuiescenceExitDrained(v.New.Exit) {
			return false
		}
	} else {
		started := a.Execution.Started.Observation.StartupIdentity
		if v.Attempt != nil || started == nil || v.New == nil || v.New.Identity != *started || !labQuiescenceExitDrained(v.New.Exit) {
			return false
		}
	}
	roles := []string{"OLD_CONTROLLER", "OLD_MIXED", "NEW_CONTROLLER", "NEW_MIXED"}
	ports := []uint16{source.ControllerPort, source.MixedPort, a.Plan.TargetArtifact.ControllerPort, a.Plan.TargetArtifact.MixedPort}
	previous := a.UpdatedAt
	for i := range v.Probes {
		if !lifecycleRecoveryCleanupProbeValid(v.Probes[i], roles[i], ports[i], previous, v.ObservedAt) {
			return false
		}
		previous = v.Probes[i].ObservedAt
	}
	want, err := lifecycleRecoveryCleanupHash(v)
	return err == nil && want == v.CleanupSHA256
}

func validateLifecycleRecoveryReconciliationScoped(w *lifecycleV3Wire, a lifecycleRecoveryTxn, scope *lifecycleV3DecodeScope) error {
	r := a.Reconciliation
	if w == nil || scope == nil || a.Phase != "FAILED_RECONCILED" || r == nil || r.Schema != lifecycleRecoveryReconciliationSchema ||
		a.Failure == nil || a.Completion != nil || !lifecycleTime(r.OriginalTxnUpdatedAt) || !lifecycleTime(r.ReconciledAt) ||
		!r.ReconciledAt.Equal(a.UpdatedAt) || r.OriginalTxnUpdatedAt.After(r.ReconciledAt) || r.CommitRevision == 0 || r.CommitRevision > w.Revision ||
		r.OriginalUnknownRoot.RecoveryKind != lifecycleRecoveryCheckpointUnknown || r.OriginalUnknownRoot.Revision == ^uint64(0) ||
		r.CommitRevision != r.OriginalUnknownRoot.Revision+1 || !r.OriginalUnknownRoot.LastTrustedAt.Equal(r.OriginalTxnUpdatedAt) {
		return errLifecycleUnsafe
	}
	context, err := lifecycleRecoveryPlanContextScoped(w, a.Plan, scope)
	if err != nil {
		return errLifecycleUnsafe
	}
	raw, err := lifecycleRecoveryCheckpointPreimageScoped(w, r.OriginalUnknownRoot, &a, scope)
	if err != nil {
		return errLifecycleUnsafe
	}
	original, err := decodeLifecycleV3RecordScoped(raw, scope)
	if err != nil || original.core.Recovery == nil || original.core.Recovery.Phase != "RECOVERY_UNKNOWN" ||
		original.core.Recovery.Reconciliation != nil || !original.core.Recovery.UpdatedAt.Equal(r.OriginalTxnUpdatedAt) {
		return errLifecycleUnsafe
	}
	want, err := lifecycleRecoveryUnknownFromReconciled(a)
	if err != nil || !reflect.DeepEqual(*original.core.Recovery, *want) || original.core.RecordSHA256 != r.OriginalUnknownRoot.RecordSHA256 ||
		!lifecycleRecoveryCleanupValid(r.Cleanup, *want, context.core.head, context.core.absenceOld, r.ReconciledAt) {
		return errLifecycleUnsafe
	}
	return nil
}

func lifecycleRecoveryMaxCleanupAttempt(absent bool, id labKernelIdentity, stream labKernelStream, when time.Time) *labRecoveryStartObservation {
	schema := labRecoveryStartObservationSchema
	if absent {
		schema = labRecoveryAbsentStartObservationSchema
	}
	started, waited, sent, before, after := true, false, false, true, false
	class := "NONE"
	pid, ticks, inode := id.PID, id.StartTicks, id.NetNSInode
	attemptStream := stream
	attemptStream.Truncated, attemptStream.Complete = false, false
	start := labKernelStartObservation{Attempted: true, Started: &started, PID: &pid, StartTicks: &ticks, WaitReturned: &waited,
		WaitErrorClass: "NOT_WAITED", TermSent: &sent, KillSent: &sent, Stdout: &attemptStream, Stderr: &attemptStream}
	return &labRecoveryStartObservation{Schema: schema, PermitConsumed: true, StartInvoked: true, StartReturned: true,
		StartErrorClass: &class, StartObservation: &start, StartupIdentity: &id, VerifiedIdentity: &id, NamespaceInode: &inode,
		ListenersBefore: &before, ListenersAfter: &after, StartedAt: &when, ReturnedAt: &when,
		Outcome: "START_UNCERTAIN", FailureCode: "LISTENERS_REJECTED"}
}

func lifecycleRecoveryReconcileReservationBytes(w *lifecycleV3Wire, attempt *labRecoveryStartObservation) ([]byte, error) {
	if w == nil || w.Recovery == nil || w.Recovery.Failure == nil {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	var future lifecycleV3Wire
	if json.Unmarshal(raw, &future) != nil {
		return nil, errLifecycleUnsafe
	}
	hash := strings.Repeat("f", 64)
	when := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	max := ^uint64(0)
	maxSigned := uint64(1<<63 - 1)
	maxHistory := uint64(maxLifecycleHistory)
	code, group := 255, true
	stream := labKernelStream{Bytes: 64 << 10, TotalBytes: 1<<63 - 1, SHA256: hash, Truncated: true, Complete: true}
	exit := labKernelExit{Started: true, WaitReturned: true, WaitErrorClass: "EXIT_STATUS", ExitCode: &code, GroupAbsent: &group, Stdout: stream, Stderr: stream}
	id := labKernelIdentity{PID: 1<<31 - 1, StartTicks: maxSigned, NetNSInode: maxSigned, ELFSHA256: hash, ELFBytes: 128 << 20, SourceCommit: strings.Repeat("f", 40), ArtifactSHA256: hash, ControllerPort: 28412, MixedPort: 28411}
	id.ArtifactSHA256 = future.Recovery.Plan.TargetArtifact.Config.SHA256
	if attempt == nil {
		attempt = lifecycleRecoveryMaxCleanupAttempt(future.Recovery.Plan.Schema == labRecoveryPlanSchemaV3 && future.Recovery.Plan.StartMode == labRecoveryStartModeOldEpochAbsent, id, stream, when)
	}
	probe := func(role string, port uint16) lifecycleRecoveryCleanupProbe { return lifecycleRecoveryCleanupProbe{Role: role, Probe: labQuiescenceProbe{Port: port, Attempted: true, Result: "CONNECTION_REFUSED"}, ObservedAt: when} }
	cleanup := lifecycleRecoveryCleanupFact{Schema: lifecycleRecoveryCleanupSchema, RecoveryID: future.Recovery.Plan.RecoveryID, FailureCode: future.Recovery.Failure.Code,
		Old: lifecycleRecoveryCleanedKernel{Identity: id, Exit: exit}, New: &lifecycleRecoveryCleanedKernel{Identity: id, Exit: exit},
		Attempt: attempt, Probes: []lifecycleRecoveryCleanupProbe{probe("OLD_CONTROLLER", 28412), probe("OLD_MIXED", 28411), probe("NEW_CONTROLLER", 28412), probe("NEW_MIXED", 28411)},
		SourceReceiptSHA256: hash, ObservedAt: when, CleanupSHA256: hash}
	owner := &lifecycleOwner{OwnerNonce: hash, Fence: max, AcquiredAt: when, RenewedAt: when, ExpiresAt: when}
	future.Revision, future.RecordSHA256, future.LastTrustedAt, future.LastRecoveryFence = max, hash, when, max
	future.Recovery.Phase = "FAILED_RECONCILED"
	future.Recovery.Reconciliation = &lifecycleRecoveryReconciliation{Schema: lifecycleRecoveryReconciliationSchema,
		OriginalUnknownRoot: lifecycleRecoveryRootCheckpoint{Schema: lifecycleRecoveryRootCheckpointSchema, Revision: max, RecordSHA256: hash,
			LastTrustedAt: when, RecoveryOwner: owner, LastRecoveryFence: max, CurrentEpochPosition: maxHistory, CurrentLedgerSHA256: hash,
			RetiredPrefixCount: maxHistory, RetiredPrefixSHA256: hash, RecoveryHistoryPrefixCount: maxHistory,
			RecoveryHistoryPrefixSHA256: hash, RecoveryKind: lifecycleRecoveryCheckpointUnknown},
		OriginalTxnUpdatedAt: future.Recovery.UpdatedAt, Cleanup: cleanup, CommitRevision: max, ReconciledAt: when}
	future.Recovery.UpdatedAt = when
	future.RecoveryHistory = append(future.RecoveryHistory, *future.Recovery)
	encoded, err := json.Marshal(&future)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	return encoded, nil
}

func lifecycleRecoveryReconcileReserve(w *lifecycleV3Wire) error {
	if w == nil || w.Recovery == nil || w.Recovery.Phase != "RECOVERY_UNKNOWN" || w.Recovery.Failure == nil ||
		len(w.RecoveryHistory) >= maxLifecycleHistory || w.Revision == ^uint64(0) {
		return errLifecycleUnsafe
	}
	encoded, err := lifecycleRecoveryReconcileReservationBytes(w, nil)
	if err != nil || len(encoded) > maxLifecycleControlBytes {
		return errLifecycleUnsafe
	}
	return nil
}

// Called only by the same warm Linux coordinator after a fresh Prepare policy
// check. It reserves the complete WAL before that coordinator touches a kernel.
func (r *labLifecycleRuntime) armRecoveryReconcile(service *LabService, s *lifecycleRecoveryStore, t *lifecycleRecoveryOwnerToken, now time.Time) (*labRecoveryReconcilePermit, error) {
	if r == nil || r.core == nil || service == nil || service.core == nil || s == nil || s.core == nil { return nil, errLifecycleUnsafe }
	c, x := r.core, s.core
	c.mu.Lock(); defer c.mu.Unlock()
	x.mu.Lock(); defer x.mu.Unlock()
	if c.closed || c.poisoned || c.recovery != s || c.store != nil || c.current != nil || service.core.runtime != r ||
		!lifecycleRecoverySameDisk(c.disk, x.disk) || x.reconcilePermit != nil || x.closed || x.poisoned { return nil, errLifecycleUnsafe }
	base, err := x.verifiedBase(); if err != nil { return nil, err }; defer base.release()
	if x.token(t, false, now) != nil { return nil, errLifecycleUnsafe }
	a := x.record.core.Recovery
	if a == nil || a.Phase != "RECOVERY_UNKNOWN" || a.Failure == nil || a.Reconciliation != nil || lifecycleRecoveryReconcileReserve(x.record.core) != nil { return nil, errLifecycleUnsafe }
	root, err := lifecycleRecoveryCheckpoint(x.record.core, lifecycleRecoveryCheckpointUnknown); if err != nil { return nil, errLifecycleUnsafe }
	p := &labRecoveryReconcilePermitCore{runtime: c, service: service.core, store: x, disk: x.disk, owner: t.core, nonce: t.core.nonce, fence: t.core.fence,
		recoveryID: a.Plan.RecoveryID, revision: x.record.core.Revision, recordSHA256: x.record.core.RecordSHA256, canonical: string(x.raw), originalRoot: root, unknownUpdatedAt: a.UpdatedAt}
	canonical, owner, runtime, svc, disk := p.canonical, p.owner, c, service.core, x.disk
	p.binding = func(candidate *labRecoveryReconcilePermitCore) bool { return candidate == p && candidate.store == x && candidate.runtime == runtime && candidate.service == svc &&
		candidate.owner == owner && candidate.canonical == canonical && lifecycleRecoverySameDisk(candidate.disk, disk) }
	x.reconcilePermit = p
	return &labRecoveryReconcilePermit{core: p}, nil
}

func (s *lifecycleRecoveryStore) recordRecoveryReconciled(t *lifecycleRecoveryOwnerToken, permit *labRecoveryReconcilePermit, custody *labRecoveryCleanupCustody, now time.Time) (out *labRecoveryTerminalReentryPermit, err error) {
	if permit == nil || permit.core == nil || custody == nil { return nil, errLifecycleUnsafe }
	fact, consumeErr := custody.consumeRecoveryReconciliation(permit, now)
	if s == nil || s.core == nil { return nil, errLifecycleUnsafe }
	x, p := s.core, permit.core
	x.mu.Lock(); defer x.mu.Unlock()
	consumed := true
	defer func() { if consumed && err != nil { x.poisoned = true; x.reconcilePermit = nil; x.terminalReentry = nil; x.absenceCustody = nil; x.live = nil } }()
	base, e := x.verifiedBase(); if e != nil { return nil, e }; defer base.release()
	if consumeErr != nil || p.used || x.reconcilePermit != p || p.binding == nil || !p.binding(p) { return nil, errLifecycleUnsafe }
	p.used = true; x.reconcilePermit = nil
	if x.token(t, false, now) != nil || p.owner != t.core || p.nonce != t.core.nonce || p.fence != t.core.fence ||
		x.record.core.Revision != p.revision || x.record.core.RecordSHA256 != p.recordSHA256 || !bytes.Equal(x.raw, []byte(p.canonical)) { return nil, errLifecycleUnsafe }
	a := x.record.core.Recovery
	checkpoint, e := lifecycleRecoveryCheckpoint(x.record.core, lifecycleRecoveryCheckpointUnknown)
	var context *labRecoveryPlanValidationContext
	contextErr := errLifecycleUnsafe
	if a != nil {
		context, contextErr = lifecycleRecoveryPlanContext(x.record.core, a.Plan)
	}
	if e != nil || a == nil || a.Phase != "RECOVERY_UNKNOWN" || a.Plan.RecoveryID != p.recoveryID || !reflect.DeepEqual(checkpoint, p.originalRoot) ||
		contextErr != nil || context == nil || context.core == nil || !a.UpdatedAt.Equal(p.unknownUpdatedAt) ||
		!lifecycleRecoveryCleanupValid(fact, *a, context.core.head, context.core.absenceOld, now) { return nil, errLifecycleUnsafe }
	next, e := base.copyRecord(); if e != nil || next.core.Revision == ^uint64(0) { return nil, errLifecycleUnsafe }
	b := next.core.Recovery
	b.Phase = "FAILED_RECONCILED"
	b.Reconciliation = &lifecycleRecoveryReconciliation{Schema: lifecycleRecoveryReconciliationSchema, OriginalUnknownRoot: p.originalRoot,
		OriginalTxnUpdatedAt: p.unknownUpdatedAt, Cleanup: fact, CommitRevision: next.core.Revision + 1, ReconciledAt: now}
	b.UpdatedAt = now
	next.core.RecoveryHistory = append(next.core.RecoveryHistory, *b)
	if e = x.commitWithBase(base, next, now); e != nil { return nil, e }
	root := x.record.core.RecordSHA256
	terminalCanonical := string(x.raw)
	reentry := &labRecoveryTerminalReentryPermitCore{runtime: p.runtime, service: p.service, store: x, disk: x.disk, terminalPlan: b.Plan.PlanSHA256, terminalRoot: root, terminalCanonical: terminalCanonical, cleanupSHA: fact.CleanupSHA256, fence: x.record.core.LastRecoveryFence}
	reentry.binding = func(candidate *labRecoveryTerminalReentryPermitCore) bool { return candidate == reentry && candidate.runtime == p.runtime && candidate.service == p.service && candidate.store == x && candidate.terminalRoot == root && candidate.terminalCanonical == terminalCanonical && candidate.cleanupSHA == fact.CleanupSHA256 && lifecycleRecoverySameDisk(candidate.disk, x.disk) }
	absence := &labRecoveryAbsenceCustodyCore{runtime: p.runtime, service: p.service, store: x, disk: x.disk, cleanupSHA: fact.CleanupSHA256,
		terminalRoot: root, terminalCanonical: terminalCanonical, reentry: reentry, oldIdentity: fact.Old.Identity}
	absence.binding = func(candidate *labRecoveryAbsenceCustodyCore) bool { return candidate == absence && candidate.runtime == p.runtime && candidate.service == p.service && candidate.store == x && candidate.cleanupSHA == fact.CleanupSHA256 &&
		candidate.terminalRoot == root && candidate.terminalCanonical == terminalCanonical && candidate.reentry == reentry && candidate.oldIdentity == fact.Old.Identity && candidate.planSHA == "" && candidate.recoveryID == "" && candidate.ownerNonce == "" && candidate.ownerFence == 0 && lifecycleRecoverySameDisk(candidate.disk, x.disk) }
	x.absenceCustody, x.terminalReentry = absence, reentry
	consumed = false
	return &labRecoveryTerminalReentryPermit{core: reentry}, nil
}

// recordRecoveryAbsentReentry consumes D's source-owned retained cleanup
// custody after an unstarted v3 plan was revoked. It performs no physical
// action and cannot recreate custody from the durable cleanup DTO.
func (s *lifecycleRecoveryStore) recordRecoveryAbsentReentry(t *lifecycleRecoveryOwnerToken, custody *labRecoveryAbsentReentryCustody, now time.Time) (*labRecoveryTerminalReentryPermit, error) {
	if s == nil || s.core == nil || custody == nil {
		return nil, errLifecycleUnsafe
	}
	x := s.core
	x.mu.Lock()
	absence := x.absenceCustody
	x.mu.Unlock()
	if absence == nil || custody.consumeRecoveryAbsentReentry(absence, now) != nil {
		return nil, errLifecycleUnsafe
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	oldReentry := absence.reentry
	if x.token(t, true, now) != nil || x.absenceCustody != absence || absence.binding == nil || !absence.binding(absence) ||
		oldReentry == nil || oldReentry.binding == nil || !oldReentry.binding(oldReentry) || !oldReentry.used ||
		(x.terminalReentry != nil && x.terminalReentry != oldReentry) || !lifecycleRecoverySameDisk(absence.disk, x.disk) ||
		absence.store != x || absence.runtime == nil || absence.service == nil || x.verify() != nil {
		return nil, errLifecycleUnsafe
	}
	w, a := x.record.core, x.record.core.Recovery
	canonicalBytes, canonicalErr := json.Marshal(w)
	if a == nil || a.Phase != "REVOKED_UNSTARTED" || a.Plan.Schema != labRecoveryPlanSchemaV3 || a.Plan.StartMode != labRecoveryStartModeOldEpochAbsent ||
		a.Revocation == nil || a.Execution != nil || a.Failure != nil || a.Completion != nil || a.Reconciliation != nil ||
		a.Plan.PlanSHA256 != absence.planSHA || a.Plan.RecoveryID != absence.recoveryID || x.record.core.RecoveryOwner == nil ||
		absence.ownerNonce != t.core.nonce || absence.ownerFence != t.core.fence || w.LastRecoveryFence != t.core.fence ||
		canonicalErr != nil || !bytes.Equal(x.raw, canonicalBytes) {
		return nil, errLifecycleUnsafe
	}
	root, canonical, plan, cleanup, fence := w.RecordSHA256, string(x.raw), a.Plan.PlanSHA256, absence.cleanupSHA, w.LastRecoveryFence
	reentry := &labRecoveryTerminalReentryPermitCore{runtime: absence.runtime, service: absence.service, store: x, disk: x.disk,
		terminalPlan: plan, terminalRoot: root, terminalCanonical: canonical, cleanupSHA: cleanup, fence: fence}
	reentry.binding = func(candidate *labRecoveryTerminalReentryPermitCore) bool {
		return candidate == reentry && candidate.runtime == absence.runtime && candidate.service == absence.service && candidate.store == x &&
			lifecycleRecoverySameDisk(candidate.disk, x.disk) && candidate.terminalPlan == plan && candidate.terminalRoot == root &&
			candidate.terminalCanonical == canonical && candidate.cleanupSHA == cleanup && candidate.fence == fence
	}
	rebound := &labRecoveryAbsenceCustodyCore{runtime: absence.runtime, service: absence.service, store: x, disk: x.disk, cleanupSHA: cleanup,
		terminalRoot: root, terminalCanonical: canonical, reentry: reentry, oldIdentity: absence.oldIdentity}
	rebound.binding = func(candidate *labRecoveryAbsenceCustodyCore) bool {
		return candidate == rebound && candidate.runtime == absence.runtime && candidate.service == absence.service && candidate.store == x &&
			lifecycleRecoverySameDisk(candidate.disk, x.disk) && candidate.cleanupSHA == cleanup && candidate.terminalRoot == root &&
			candidate.terminalCanonical == canonical && candidate.reentry == reentry && candidate.oldIdentity == absence.oldIdentity &&
			candidate.planSHA == "" && candidate.recoveryID == "" && candidate.ownerNonce == "" && candidate.ownerFence == 0
	}
	x.absenceCustody, x.terminalReentry = rebound, reentry
	return &labRecoveryTerminalReentryPermit{core: reentry}, nil
}

// A v3 plan is minted only after a new owner was acquired from the exact warm
// terminal root. The persisted terminal/cleanup DTO cannot recreate this
// process-local reentry chain, and a cold opener has no terminalReentry core.
func newLabRecoveryPlanV3(t *lifecycleRecoveryOwnerToken, permit *labRecoveryTerminalReentryPermit, recoveryID, initiator string, target ArtifactDescriptor, now, expires time.Time) (labRecoveryPlan, error) {
	if permit == nil || permit.core == nil || permit.core.store == nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	p, x := permit.core, permit.core.store
	x.mu.Lock(); defer x.mu.Unlock()
	if p.used || x.terminalReentry != p || p.binding == nil || !p.binding(p) || p.cleanupSHA == "" || x.absenceCustody == nil ||
		x.absenceCustody.binding == nil || !x.absenceCustody.binding(x.absenceCustody) || x.absenceCustody.cleanupSHA != p.cleanupSHA ||
		x.token(t, true, now) != nil || x.record.core.Recovery == nil ||
		x.record.core.Recovery.Plan.PlanSHA256 != p.terminalPlan || x.record.core.LastRecoveryFence != p.fence+1 || x.record.core.Revision == 0 {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	terminal := x.record.core.Recovery
	if terminal.Phase != "FAILED_RECONCILED" && (terminal.Phase != "REVOKED_UNSTARTED" || terminal.Plan.Schema != labRecoveryPlanSchemaV3 ||
		terminal.Plan.StartMode != labRecoveryStartModeOldEpochAbsent || terminal.Revocation == nil || terminal.Execution != nil || terminal.Failure != nil || terminal.Completion != nil) {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	previous, err := decodeLifecycleV3Record([]byte(p.terminalCanonical))
	if err != nil || previous.core.RecordSHA256 != p.terminalRoot || previous.core.Revision == ^uint64(0) || x.record.core.Revision != previous.core.Revision+1 ||
		!lifecycleV3Transition(previous.core, x.record.core) { return labRecoveryPlan{}, errLifecycleUnsafe }
	checkpoint, err := lifecycleRecoveryCheckpoint(x.record.core, lifecycleRecoveryCheckpointHistoryTail)
	if err != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	a := x.record.core.Current.Active
	if a == nil || a.Phase != "UNKNOWN" || a.Intent == nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	epoch, err := labRecoveryEpochSHA256(x.record.core.Current.Head, x.record.core.Provisioning)
	if err != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	d := labRecoveryPlanDescriptor{Schema: labRecoveryPlanSchemaV3, Boundary: labRecoveryPlanBoundary, RecoveryID: recoveryID,
		UnknownOperationID: a.Plan.OperationID, OriginalPlanSHA256: a.Plan.PlanSHA256, OriginalIntentSHA256: a.Intent.IntentSHA256,
		DeclaredInitiatorRef: initiator, ExpectedRevision: x.record.core.Revision, ExpectedRecordSHA256: x.record.core.RecordSHA256,
		PreviousHeadSHA256: x.record.core.Current.Head.HeadSHA256, PreviousHeadGeneration: x.record.core.Current.Head.Generation,
		Provisioning: x.record.core.Provisioning, OldEpochSHA256: epoch, TargetArtifact: cloneArtifactDescriptor(target), Budgets: labRecoveryFixedBudgets(),
		CreatedAt: now, ExpiresAt: expires, Source: &labRecoveryPlanSource{Schema: labRecoveryPlanSourceSchema, Root: checkpoint}, StartMode: labRecoveryStartModeOldEpochAbsent}
	d.PlanSHA256, err = labRecoveryPlanDigest(d)
	context, contextErr := lifecycleRecoveryPlanContext(x.record.core, d)
	if err != nil || contextErr != nil || context.validateDescriptor(d) != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	p.used = true
	return labRecoveryPlan{core: &labRecoveryPlanCore{descriptor: d, reentry: p, store: x}}, nil
}

// Warm REVOKED_UNSTARTED reentry keeps the old owned epoch. Its permit is
// minted only by D's retained live-kernel custody; no cold JSON path calls it.
func newLabRecoveryPlanV2Reentry(t *lifecycleRecoveryOwnerToken, permit *labRecoveryTerminalReentryPermit, recoveryID, initiator string, target ArtifactDescriptor, now, expires time.Time) (labRecoveryPlan, error) {
	if permit == nil || permit.core == nil || permit.core.store == nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	p, x := permit.core, permit.core.store
	x.mu.Lock(); defer x.mu.Unlock()
	if p.used || p.cleanupSHA != "" || x.terminalReentry != p || p.binding == nil || !p.binding(p) || x.token(t, true, now) != nil ||
		x.record.core.Recovery == nil || x.record.core.Recovery.Phase != "REVOKED_UNSTARTED" || x.record.core.Recovery.Plan.PlanSHA256 != p.terminalPlan ||
		x.record.core.LastRecoveryFence != p.fence+1 { return labRecoveryPlan{}, errLifecycleUnsafe }
	previous, err := decodeLifecycleV3Record([]byte(p.terminalCanonical))
	if err != nil || previous.core.RecordSHA256 != p.terminalRoot || previous.core.Revision == ^uint64(0) || x.record.core.Revision != previous.core.Revision+1 || !lifecycleV3Transition(previous.core, x.record.core) {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	checkpoint, err := lifecycleRecoveryCheckpoint(x.record.core, lifecycleRecoveryCheckpointHistoryTail)
	if err != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	a := x.record.core.Current.Active
	if a == nil || a.Phase != "UNKNOWN" || a.Intent == nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	epoch, err := labRecoveryEpochSHA256(x.record.core.Current.Head, x.record.core.Provisioning)
	if err != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	d := labRecoveryPlanDescriptor{Schema: labRecoveryPlanSchemaV2, Boundary: labRecoveryPlanBoundary, RecoveryID: recoveryID,
		UnknownOperationID: a.Plan.OperationID, OriginalPlanSHA256: a.Plan.PlanSHA256, OriginalIntentSHA256: a.Intent.IntentSHA256,
		DeclaredInitiatorRef: initiator, ExpectedRevision: x.record.core.Revision, ExpectedRecordSHA256: x.record.core.RecordSHA256,
		PreviousHeadSHA256: x.record.core.Current.Head.HeadSHA256, PreviousHeadGeneration: x.record.core.Current.Head.Generation,
		Provisioning: x.record.core.Provisioning, OldEpochSHA256: epoch, TargetArtifact: cloneArtifactDescriptor(target), Budgets: labRecoveryFixedBudgets(),
		CreatedAt: now, ExpiresAt: expires, Source: &labRecoveryPlanSource{Schema: labRecoveryPlanSourceSchema, Root: checkpoint}}
	d.PlanSHA256, err = labRecoveryPlanDigest(d)
	context, contextErr := lifecycleRecoveryPlanContext(x.record.core, d)
	if err != nil || contextErr != nil || context.validateDescriptor(d) != nil { return labRecoveryPlan{}, errLifecycleUnsafe }
	p.used = true
	return labRecoveryPlan{core: &labRecoveryPlanCore{descriptor: d, reentry: p, store: x}}, nil
}

// Caller holds store.mu after the successful PLANNED publication.
func lifecycleRecoveryBindAbsenceToPlan(x *lifecycleRecoveryStoreCore, p *labRecoveryPlan, owner *lifecycleRecoveryOwnerToken) error {
	if x == nil || p == nil || p.core == nil || owner == nil || owner.core == nil || p.core.reentry == nil || x.absenceCustody == nil ||
		x.absenceCustody.binding == nil || !x.absenceCustody.binding(x.absenceCustody) || x.absenceCustody.reentry != p.core.reentry ||
		x.record.core == nil || x.record.core.Recovery == nil || x.record.core.Recovery.Phase != "PLANNED" || x.record.core.RecoveryOwner == nil || x.live != owner.core {
		return errLifecycleUnsafe
	}
	old, d, reentry := x.absenceCustody, p.core.descriptor, p.core.reentry
	bound := &labRecoveryAbsenceCustodyCore{runtime: old.runtime, service: old.service, store: x, disk: x.disk, cleanupSHA: old.cleanupSHA,
		terminalRoot: old.terminalRoot, terminalCanonical: old.terminalCanonical, planSHA: d.PlanSHA256, recoveryID: d.RecoveryID,
		ownerNonce: owner.core.nonce, ownerFence: owner.core.fence, reentry: reentry, oldIdentity: old.oldIdentity}
	bound.binding = func(candidate *labRecoveryAbsenceCustodyCore) bool { return candidate == bound && candidate.runtime == old.runtime && candidate.service == old.service && candidate.store == x &&
		lifecycleRecoverySameDisk(candidate.disk, x.disk) && candidate.cleanupSHA == old.cleanupSHA && candidate.terminalRoot == old.terminalRoot &&
		candidate.terminalCanonical == old.terminalCanonical && candidate.planSHA == d.PlanSHA256 && candidate.recoveryID == d.RecoveryID &&
		candidate.ownerNonce == owner.core.nonce && candidate.ownerFence == owner.core.fence && candidate.reentry == reentry && candidate.oldIdentity == old.oldIdentity }
	x.absenceCustody = bound
	return nil
}

func lifecycleRecoveryPlanReentryValid(x *lifecycleRecoveryStoreCore, p *labRecoveryPlan, absent bool) bool {
	if x == nil || p == nil || p.core == nil || p.core.store != x || p.core.reentry == nil || x.terminalReentry != p.core.reentry ||
		!p.core.reentry.used || p.core.reentry.binding == nil || !p.core.reentry.binding(p.core.reentry) {
		return false
	}
	if absent {
		return p.core.reentry.cleanupSHA != "" && x.absenceCustody != nil && x.absenceCustody.binding != nil && x.absenceCustody.binding(x.absenceCustody) && x.absenceCustody.reentry == p.core.reentry
	}
	return p.core.reentry.cleanupSHA == ""
}

// The D bridge owns this type and its registry. Its consume method performs a
// fresh two-port refusal observation while retaining the same warm source.
// No serialized cleanup fact can satisfy this parameter.
func (s *lifecycleRecoveryStore) armRecoveryAbsentStart(t *lifecycleRecoveryOwnerToken, custody *labRecoveryAbsentStartCustody, now time.Time) (*labRecoveryAbsentStartPermit, error) {
	if s == nil || s.core == nil || custody == nil { return nil, errLifecycleUnsafe }
	x := s.core
	x.mu.Lock(); defer x.mu.Unlock()
	base, err := x.verifiedBase(); if err != nil { return nil, err }; defer base.release()
	if x.token(t, true, now) != nil || x.absenceCustody == nil || x.absenceCustody.binding == nil || !x.absenceCustody.binding(x.absenceCustody) ||
		x.absentStartPermit != nil { return nil, errLifecycleUnsafe }
	// Consumption performs the actual late refusal probes and is deliberately
	// before every phase rejection: an admitted bad attempt is not replayable.
	if err := custody.consumeRecoveryAbsentStart(x.absenceCustody, now); err != nil { return nil, errLifecycleUnsafe }
	a := x.record.core.Recovery
	if a == nil || a.Phase != "APPROVED" || a.Plan.Schema != labRecoveryPlanSchemaV3 || a.Plan.StartMode != labRecoveryStartModeOldEpochAbsent ||
		a.Approval == nil || a.Revocation != nil || a.StopIntent != nil || a.StopBinding != nil || a.Quiescence != nil || a.StartIntent != nil || a.Failure != nil || a.Execution != nil ||
		!now.Before(a.Approval.ExpiresAt) || !now.Before(a.Plan.ExpiresAt) { return nil, errLifecycleUnsafe }
	next, err := base.copyRecord(); if err != nil { return nil, errLifecycleUnsafe }
	b := next.core.Recovery
	i := lifecycleRecoveryNewIntent(b, "START", x.record.core.LastRecoveryFence, now)
	b.StartIntent, b.Phase, b.UpdatedAt = &i, "START_ARMED", now
	if lifecycleRecoveryReserve(next.core) != nil { return nil, errLifecycleUnsafe }
	if err := x.commitWithBase(base, next, now); err != nil { return nil, err }
	w := x.record.core
	p := &labRecoveryAbsentStartPermitCore{store: x, absence: x.absenceCustody, recoveryID: b.Plan.RecoveryID, planSHA256: b.Plan.PlanSHA256,
		intentSHA256: i.IntentSHA256, revision: w.Revision, recordSHA256: w.RecordSHA256, fence: w.LastRecoveryFence, deadline: b.Plan.ExpiresAt}
	x.absentStartPermit = p
	return &labRecoveryAbsentStartPermit{core: p}, nil
}

func (p *labRecoveryAbsentStartPermit) consumeRecoveryAbsentStart(now time.Time) (labRecoveryAbsentStartFact, error) {
	var zero labRecoveryAbsentStartFact
	if p == nil || p.core == nil || p.core.store == nil { return zero, errLifecycleUnsafe }
	c, x := p.core, p.core.store
	x.mu.Lock(); defer x.mu.Unlock()
	if c.used || x.absentStartPermit != c { return zero, errLifecycleUnsafe }
	c.used = true; x.absentStartPermit = nil
	if x.verify() != nil || x.trustedNow(now) != nil || c.absence == nil || c.absence != x.absenceCustody || c.absence.binding == nil || !c.absence.binding(c.absence) ||
		x.record.core.Revision != c.revision || x.record.core.RecordSHA256 != c.recordSHA256 || x.record.core.LastRecoveryFence != c.fence ||
		x.record.core.RecoveryOwner == nil || x.live == nil || !now.Before(x.record.core.RecoveryOwner.ExpiresAt) || now.Before(x.record.core.LastTrustedAt) || !now.Before(c.deadline) {
		return zero, errLifecycleUnsafe
	}
	a := x.record.core.Recovery
	if a == nil || a.Phase != "START_ARMED" || a.Plan.Schema != labRecoveryPlanSchemaV3 || a.Plan.StartMode != labRecoveryStartModeOldEpochAbsent ||
		a.StopIntent != nil || a.Quiescence != nil || a.StartIntent == nil || a.StartIntent.IntentSHA256 != c.intentSHA256 || a.Execution != nil {
		return zero, errLifecycleUnsafe
	}
	return labRecoveryAbsentStartFact{RecoveryID: c.recoveryID, PlanSHA256: c.planSHA256, StartIntentSHA256: c.intentSHA256,
		Revision: c.revision, RecordSHA256: c.recordSHA256, TargetArtifact: cloneArtifactDescriptor(a.Plan.TargetArtifact), ArmedAt: a.StartIntent.ArmedAt, ExpiresAt: c.deadline}, nil
}
