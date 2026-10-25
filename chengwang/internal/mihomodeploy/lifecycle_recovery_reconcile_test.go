//go:build linux

package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// MODEL only: this builds persisted data to test the strict decoder and exact
// original-root reconstruction. It never mints cleanup/reentry/start custody.
func lifecycleRecoveryReconciledRecordModel(t *testing.T) (lifecycleV3Record, []byte, lifecycleRecoveryRootCheckpoint) {
	t.Helper()
	s, _, owner, _, binding, now := lifecycleRecoveryModelArmed(t)
	if s.recordRecoveryFailure(owner, "START_UNCERTAIN", nil, now) != nil { t.Fatal("MODEL unknown") }
	original := bytes.Clone(s.core.raw)
	checkpoint, err := lifecycleRecoveryCheckpoint(s.core.record.core, lifecycleRecoveryCheckpointUnknown)
	if err != nil { t.Fatal("MODEL unknown checkpoint") }
	var w lifecycleV3Wire
	if json.Unmarshal(original, &w) != nil { t.Fatal("MODEL original copy") }
	reconciledAt := now.Add(time.Second)
	exitCode, absent := 0, true
	stream := labKernelStream{Bytes: 0, TotalBytes: 0, SHA256: labConfigHash(nil), Complete: true}
	exit := labKernelExit{Started: true, WaitReturned: true, WaitErrorClass: "NONE", ExitCode: &exitCode, GroupAbsent: &absent, Stdout: stream, Stderr: stream}
	probe := func(role string, port uint16) lifecycleRecoveryCleanupProbe {
		return lifecycleRecoveryCleanupProbe{Role: role, Probe: labQuiescenceProbe{Port: port, Attempted: true, Result: "CONNECTION_REFUSED"}, ObservedAt: reconciledAt}
	}
	cleanup := lifecycleRecoveryCleanupFact{Schema: lifecycleRecoveryCleanupSchema, RecoveryID: w.Recovery.Plan.RecoveryID,
		FailureCode: w.Recovery.Failure.Code, Old: lifecycleRecoveryCleanedKernel{Identity: binding.ExpectedOldIdentity, Exit: exit},
		Probes: []lifecycleRecoveryCleanupProbe{probe("OLD_CONTROLLER", 28412), probe("OLD_MIXED", 28411), probe("NEW_CONTROLLER", 28412), probe("NEW_MIXED", 28411)},
		SourceReceiptSHA256: strings.Repeat("a", 64), ObservedAt: reconciledAt}
	cleanup.CleanupSHA256, _ = lifecycleRecoveryCleanupHash(cleanup)
	originalTxn := *w.Recovery
	w.Revision++
	w.LastTrustedAt = reconciledAt
	w.Recovery.Phase = "FAILED_RECONCILED"
	w.Recovery.Reconciliation = &lifecycleRecoveryReconciliation{Schema: lifecycleRecoveryReconciliationSchema, OriginalUnknownRoot: checkpoint,
		OriginalTxnUpdatedAt: originalTxn.UpdatedAt, Cleanup: cleanup, CommitRevision: w.Revision, ReconciledAt: reconciledAt}
	w.Recovery.UpdatedAt = reconciledAt
	w.RecoveryHistory = append(w.RecoveryHistory, *w.Recovery)
	w.RecordSHA256, err = lifecycleV3RecordHash(w)
	if err != nil { t.Fatal("MODEL root hash") }
	return lifecycleV3Record{core: &w}, original, checkpoint
}

func TestLifecycleRecoveryReconciledStrictlyRestoresOriginalUnknown(t *testing.T) {
	final, original, checkpoint := lifecycleRecoveryReconciledRecordModel(t)
	if validateLifecycleV3Record(final) != nil { t.Fatal("MODEL reconciled record rejected") }
	preimage, err := lifecycleRecoveryCheckpointPreimage(final.core, checkpoint, final.core.Recovery)
	if err != nil || !bytes.Equal(preimage, original) { t.Fatal("MODEL original UNKNOWN not exact") }
	decoded, err := decodeLifecycleV3Record(preimage)
	if err != nil || decoded.core.Recovery == nil || decoded.core.Recovery.Phase != "RECOVERY_UNKNOWN" || decoded.core.Recovery.Reconciliation != nil {
		t.Fatal("MODEL original facts not restored")
	}
	terminal := *final.core.Recovery
	terminal.Reconciliation.Cleanup.Probes[0].Probe.Result = "CONNECTION_ACCEPTED"
	if validateLifecycleV3Record(lifecycleV3Record{core: final.core}) == nil { t.Fatal("MODEL cleanup tamper accepted") }
}

func TestLifecycleRecoveryReconcileCompatibilityAndAuthorityNegatives(t *testing.T) {
	txn, err := json.Marshal(lifecycleRecoveryTxn{Phase: "RECOVERY_UNKNOWN", FailedQuiescence: []labQuiescenceObservation{}})
	if err != nil || bytes.Contains(txn, []byte("reconciliation")) { t.Fatal("old txn nil bytes changed") }
	plan, err := json.Marshal(labRecoveryPlanDescriptor{Schema: labRecoveryPlanSchemaV2})
	if err != nil || bytes.Contains(plan, []byte("startMode")) { t.Fatal("old plan nil bytes changed") }
	if !lifecycleRecoveryPhaseTransition("RECOVERY_UNKNOWN", "FAILED_RECONCILED") || lifecycleRecoveryPhaseTransition("RECOVERY_UNKNOWN", "PLANNED") {
		t.Fatal("reconcile phase boundary")
	}
	if _, err := newLabRecoveryPlanV3(nil, nil, "labrec_"+strings.Repeat("1", 32), "MODEL_actor", ArtifactDescriptor{}, time.Now().UTC(), time.Now().UTC().Add(time.Minute)); err == nil {
		t.Fatal("serialized/cold plan minted authority")
	}
	p := &labRecoveryTerminalReentryPermit{core: &labRecoveryTerminalReentryPermitCore{}}
	copyCore := *p.core
	if _, err := newLabRecoveryPlanV3(nil, &labRecoveryTerminalReentryPermit{core: &copyCore}, "labrec_"+strings.Repeat("2", 32), "MODEL_actor", ArtifactDescriptor{}, time.Now().UTC(), time.Now().UTC().Add(time.Minute)); err == nil {
		t.Fatal("copied reentry minted plan")
	}
	_ = reflect.TypeOf(p) // keep the opaque wrapper in the compile-time contract
}

func TestLifecycleRecoveryReconcileReserveRejectsFullHistoryBeforeAction(t *testing.T) {
	final, _, _ := lifecycleRecoveryReconciledRecordModel(t)
	w := *final.core
	w.Recovery.Phase = "RECOVERY_UNKNOWN"
	w.Recovery.Reconciliation = nil
	w.RecoveryHistory = make([]lifecycleRecoveryTxn, maxLifecycleHistory)
	if lifecycleRecoveryReconcileReserve(&w) == nil { t.Fatal("MODEL full history reserved physical action") }
}

func TestLifecycleRecoveryReconcileReserveAccountsForCompleteAttemptAtControlLimit(t *testing.T) {
	final, _, _ := lifecycleRecoveryReconciledRecordModel(t)
	w := *final.core
	w.Recovery.Phase = "RECOVERY_UNKNOWN"
	w.Recovery.Reconciliation = nil
	w.RecoveryHistory = nil
	maxEncoded, err := lifecycleRecoveryReconcileReservationBytes(&w, nil)
	if err != nil {
		t.Fatal("MODEL complete Attempt reservation")
	}
	var reserved lifecycleV3Wire
	if json.Unmarshal(maxEncoded, &reserved) != nil || reserved.Recovery == nil || reserved.Recovery.Reconciliation == nil ||
		reserved.Recovery.Reconciliation.Cleanup.Attempt == nil || reserved.Recovery.Reconciliation.Cleanup.New == nil {
		t.Fatal("MODEL complete Attempt reservation shape")
	}
	maximum := reserved.Recovery.Reconciliation.Cleanup
	if !labQuiescenceExitDrained(maximum.Old.Exit) || !labQuiescenceExitDrained(maximum.New.Exit) ||
		maximum.Old.Exit.WaitErrorClass != "EXIT_STATUS" || maximum.New.Exit.WaitErrorClass != "EXIT_STATUS" ||
		maximum.Old.Exit.ExitCode == nil || *maximum.Old.Exit.ExitCode != 255 ||
		maximum.New.Exit.ExitCode == nil || *maximum.New.Exit.ExitCode != 255 {
		t.Fatal("MODEL reservation did not use the longest legal terminal exit")
	}
	shorter := labRecoveryStartedCloneObservation(*maximum.Attempt)
	if shorter.StartObservation == nil || shorter.StartObservation.TermSent == nil ||
		shorter.StartObservation.KillSent == nil || shorter.StartObservation.Stdout == nil || shorter.StartObservation.Stderr == nil {
		t.Fatal("MODEL maximum Attempt booleans absent")
	}
	if *shorter.StartObservation.TermSent || *shorter.StartObservation.KillSent || shorter.StartObservation.GroupAbsent != nil ||
		*shorter.StartObservation.WaitReturned || shorter.StartObservation.WaitErrorClass != "NOT_WAITED" ||
		shorter.StartObservation.Stdout.Truncated || shorter.StartObservation.Stdout.Complete ||
		shorter.StartObservation.Stderr.Truncated || shorter.StartObservation.Stderr.Complete {
		t.Fatal("MODEL maximum Attempt did not use longer false encodings")
	}
	yes := true
	shorter.StartObservation.TermSent, shorter.StartObservation.KillSent = &yes, &yes
	shorter.StartObservation.Stdout.Truncated, shorter.StartObservation.Stdout.Complete = true, true
	shorter.StartObservation.Stderr.Truncated, shorter.StartObservation.Stderr.Complete = true, true
	shorterEncoded, err := lifecycleRecoveryReconcileReservationBytes(&w, &shorter)
	if err != nil || len(maxEncoded) != len(shorterEncoded)+6 {
		t.Fatal("MODEL independent legal boolean variants did not prove the maximum Attempt length")
	}
	absent := maximum.Attempt.Schema == labRecoveryAbsentStartObservationSchema
	old, target, observedAt := maximum.New.Identity, w.Recovery.Plan.TargetArtifact, maximum.ObservedAt
	old.PID--
	old.StartTicks--
	check := func(label string, attempt *labRecoveryStartObservation, next *lifecycleRecoveryCleanedKernel) {
		t.Helper()
		if !lifecycleRecoveryCleanupAttemptValid(attempt, absent, next, old, target, observedAt) {
			t.Fatal("MODEL enumerated producer Attempt rejected: " + label)
		}
		raw, encodeErr := lifecycleRecoveryReconcileReservationBytes(&w, attempt)
		if encodeErr != nil || len(raw) > len(maxEncoded) {
			t.Fatal("MODEL accepted producer Attempt exceeded reserved WAL bytes: " + label)
		}
	}
	check("reserved-listener-after", maximum.Attempt, maximum.New)
	entry := func(code string) *labRecoveryStartObservation {
		v := &labRecoveryStartObservation{Schema: maximum.Attempt.Schema, Outcome: "ENTRY_REJECTED", FailureCode: code}
		switch code {
		case "BINDING_REJECTED", "ATTEMPT_SPENT", "INPUT_REJECTED":
			v.PermitConsumed = true
		case "NAMESPACE_REJECTED":
			v.PermitConsumed = true
			inode := old.NetNSInode - 1
			v.NamespaceInode = &inode
		case "ARTIFACT_REJECTED", "BUDGET_REJECTED", "STATE_REJECTED":
			v.PermitConsumed = true
			inode := old.NetNSInode
			v.NamespaceInode = &inode
		}
		return v
	}
	for _, code := range []string{"CONTEXT_OR_INPUT_REJECTED", "PERMIT_REJECTED", "BINDING_REJECTED", "ATTEMPT_SPENT", "INPUT_REJECTED",
		"NAMESPACE_REJECTED", "ARTIFACT_REJECTED", "BUDGET_REJECTED", "STATE_REJECTED"} {
		check("entry-"+code, entry(code), nil)
	}
	namespaceReadFailure := entry("NAMESPACE_REJECTED")
	namespaceReadFailure.NamespaceInode = nil
	check("entry-NAMESPACE_REJECTED-read-failure", namespaceReadFailure, nil)
	namespaceMaximum := entry("NAMESPACE_REJECTED")
	maximumInode := ^uint64(0)
	namespaceMaximum.NamespaceInode = &maximumInode
	check("entry-NAMESPACE_REJECTED-maximum-inode", namespaceMaximum, nil)
	for _, term := range []bool{false, true} {
		for _, kill := range []bool{false, true} {
			for _, stdoutTruncated := range []bool{false, true} {
				for _, stdoutComplete := range []bool{false, true} {
					for _, stderrTruncated := range []bool{false, true} {
						for _, stderrComplete := range []bool{false, true} {
							v := labRecoveryStartedCloneObservation(*maximum.Attempt)
							v.StartObservation.TermSent, v.StartObservation.KillSent = &term, &kill
							v.StartObservation.Stdout.Truncated, v.StartObservation.Stdout.Complete = stdoutTruncated, stdoutComplete
							v.StartObservation.Stderr.Truncated, v.StartObservation.Stderr.Complete = stderrTruncated, stderrComplete
							check("live-not-waited-boolean-product", &v, maximum.New)
						}
					}
				}
			}
		}
	}
	for _, term := range []bool{false, true} {
		for _, kill := range []bool{false, true} {
			for _, group := range []bool{false, true} {
				for _, stdoutTruncated := range []bool{false, true} {
					for _, stderrTruncated := range []bool{false, true} {
						v := labRecoveryStartedCloneObservation(*maximum.Attempt)
						waited, code := true, 255
						v.StartObservation.WaitReturned, v.StartObservation.ExitCode = &waited, &code
						v.StartObservation.WaitErrorClass, v.StartObservation.GroupAbsent = "EXIT_STATUS", &group
						v.StartObservation.TermSent, v.StartObservation.KillSent = &term, &kill
						v.StartObservation.Stdout.Truncated, v.StartObservation.Stderr.Truncated = stdoutTruncated, stderrTruncated
						v.StartObservation.Stdout.Complete, v.StartObservation.Stderr.Complete = true, true
						check("waited-terminal-boolean-product", &v, maximum.New)
					}
				}
			}
		}
	}
	signalVariant := labRecoveryStartedCloneObservation(*maximum.Attempt)
	waited, signal, group := true, 255, false
	signalVariant.StartObservation.WaitReturned, signalVariant.StartObservation.Signal = &waited, &signal
	signalVariant.StartObservation.WaitErrorClass, signalVariant.StartObservation.GroupAbsent = "EXIT_STATUS", &group
	signalVariant.StartObservation.Stdout.Complete, signalVariant.StartObservation.Stderr.Complete = true, true
	check("waited-signal-terminal", &signalVariant, maximum.New)
	for _, class := range []string{"NONE", "WAIT_ERROR"} {
		waitClassVariant := labRecoveryStartedCloneObservation(*maximum.Attempt)
		waited, group := true, false
		waitClassVariant.StartObservation.WaitReturned, waitClassVariant.StartObservation.GroupAbsent = &waited, &group
		waitClassVariant.StartObservation.WaitErrorClass = class
		waitClassVariant.StartObservation.ExitCode, waitClassVariant.StartObservation.Signal = nil, nil
		waitClassVariant.StartObservation.Stdout.Complete, waitClassVariant.StartObservation.Stderr.Complete = true, true
		check("waited-class-"+class, &waitClassVariant, maximum.New)
	}
	for _, code := range []string{"BUDGET_REJECTED", "OWNED_REJECTED", "ISSUER_REJECTED", "FACT_REJECTED"} {
		v := labRecoveryStartedCloneObservation(*maximum.Attempt)
		v.FailureCode = code
		yes := true
		v.ListenersAfter = &yes
		check("full-stage-"+code, &v, maximum.New)
	}
	earlyBudget := labRecoveryStartedCloneObservation(*maximum.Attempt)
	earlyBudget.FailureCode = "BUDGET_REJECTED"
	earlyBudget.StartupIdentity, earlyBudget.VerifiedIdentity = nil, nil
	earlyBudget.ListenersBefore, earlyBudget.ListenersAfter = nil, nil
	check("budget-before-identity", &earlyBudget, maximum.New)
	earlyIdentity := labRecoveryStartedCloneObservation(*maximum.Attempt)
	earlyIdentity.FailureCode = "IDENTITY_REJECTED"
	earlyIdentity.StartupIdentity, earlyIdentity.VerifiedIdentity = nil, nil
	earlyIdentity.ListenersBefore, earlyIdentity.ListenersAfter = nil, nil
	check("identity-before-startup-observation", &earlyIdentity, maximum.New)
	startedAttempt := labRecoveryStartedCloneObservation(*maximum.Attempt)
	startedAttempt.Outcome, startedAttempt.FailureCode = "STARTED", "NONE"
	yes = true
	startedAttempt.ListenersAfter = &yes
	check("started-none", &startedAttempt, maximum.New)
	listenerEarly := labRecoveryStartedCloneObservation(*maximum.Attempt)
	listenerEarly.VerifiedIdentity, listenerEarly.ListenersBefore, listenerEarly.ListenersAfter = nil, nil, nil
	check("listener-before", &listenerEarly, maximum.New)
	identityLate := labRecoveryStartedCloneObservation(*maximum.Attempt)
	identityLate.FailureCode, identityLate.VerifiedIdentity, identityLate.ListenersAfter = "IDENTITY_REJECTED", nil, nil
	check("identity-after-listener", &identityLate, maximum.New)
	identityMismatch := labRecoveryStartedCloneObservation(identityLate)
	startup := maximum.New.Identity
	startup.PID -= 2
	startup.StartTicks -= 2
	identityMismatch.StartupIdentity, identityMismatch.VerifiedIdentity = &startup, &maximum.New.Identity
	identityMismatch.StartObservation.PID, identityMismatch.StartObservation.StartTicks = &startup.PID, &startup.StartTicks
	check("identity-mismatch", &identityMismatch, maximum.New)
	startRejected := labRecoveryStartedCloneObservation(*maximum.Attempt)
	failed := "FAILED"
	startRejected.StartErrorClass, startRejected.FailureCode = &failed, "START_REJECTED"
	startRejected.StartupIdentity, startRejected.VerifiedIdentity = nil, nil
	startRejected.ListenersBefore, startRejected.ListenersAfter = nil, nil
	check("started-handle-start-rejected", &startRejected, maximum.New)
	typedFalse := labRecoveryStartedCloneObservation(startRejected)
	notStarted, notWaited := false, false
	typedFalse.StartObservation = &labKernelStartObservation{Attempted: true, Started: &notStarted, WaitReturned: &notWaited,
		WaitErrorClass: "NOT_WAITED", Stdout: &labKernelStream{SHA256: labConfigHash(nil), Complete: true},
		Stderr: &labKernelStream{SHA256: labConfigHash(nil), Complete: true}}
	check("typed-false-new-nil", &typedFalse, nil)
	plainStartRejected := labRecoveryStartedCloneObservation(startRejected)
	plainStartRejected.StartObservation = nil
	check("plain-start-rejected-new-nil", &plainStartRejected, nil)
	preCommandStartRejected := labRecoveryStartedCloneObservation(typedFalse)
	preCommandStartRejected.StartObservation.Attempted = false
	preCommandStartRejected.StartObservation.Stdout, preCommandStartRejected.StartObservation.Stderr = nil, nil
	check("pre-command-start-rejected-new-nil", &preCommandStartRejected, nil)
	absentWire := w
	absentTxn := *w.Recovery
	absentTxn.Plan = w.Recovery.Plan
	absentTxn.Plan.Schema, absentTxn.Plan.StartMode = labRecoveryPlanSchemaV3, labRecoveryStartModeOldEpochAbsent
	absentWire.Recovery = &absentTxn
	absentReserved, absentErr := lifecycleRecoveryReconcileReservationBytes(&absentWire, nil)
	absentAttempt := lifecycleRecoveryMaxCleanupAttempt(true, maximum.New.Identity, *maximum.Attempt.StartObservation.Stdout, observedAt)
	absentExplicit, absentExplicitErr := lifecycleRecoveryReconcileReservationBytes(&absentWire, absentAttempt)
	if absentErr != nil || absentExplicitErr != nil || len(absentReserved) != len(absentExplicit) ||
		absentAttempt.Schema != labRecoveryAbsentStartObservationSchema {
		t.Fatal("MODEL absent reservation did not select its exact maximum Attempt schema")
	}
	fits := func(n int) bool {
		w.SourceV2.ControlBytes = bytes.Repeat([]byte{255}, n)
		return lifecycleRecoveryReconcileReserve(&w) == nil
	}
	low, high := 0, maxLifecycleControlBytes
	for low < high {
		mid := low + (high-low+1)/2
		if fits(mid) {
			low = mid
		} else {
			high = mid - 1
		}
	}
	if low == 0 || !fits(low) {
		t.Fatal("MODEL complete Attempt positive boundary rejected")
	}
	negative := 0
	for n := low + 1; n <= low+4096 && n <= maxLifecycleControlBytes; n++ {
		w.SourceV2.ControlBytes = bytes.Repeat([]byte{255}, n)
		short, err := lifecycleRecoveryReconcileReservationBytes(&w, &shorter)
		if err == nil && len(short) <= maxLifecycleControlBytes && lifecycleRecoveryReconcileReserve(&w) != nil {
			negative = n
			break
		}
	}
	if negative == 0 {
		t.Fatal("MODEL did not expose complete-Attempt reserve boundary")
	}
}

func TestLifecycleRecoveryCleanupAttemptRejectsSparseOrForeignShapes(t *testing.T) {
	_, _, _, _, binding, now := lifecycleRecoveryModelArmed(t)
	old := binding.ExpectedOldIdentity
	next := old
	next.PID++
	next.StartTicks++
	next.ArtifactSHA256 = binding.TargetArtifact.Config.SHA256
	next.ControllerPort = binding.TargetArtifact.ControllerPort
	next.MixedPort = binding.TargetArtifact.MixedPort
	stream := labKernelStream{Bytes: 0, TotalBytes: 0, SHA256: labConfigHash(nil), Complete: true}
	exitCode, group := 0, true
	exit := labKernelExit{Started: true, WaitReturned: true, WaitErrorClass: "NONE", ExitCode: &exitCode,
		GroupAbsent: &group, Stdout: stream, Stderr: stream}
	cleaned := &lifecycleRecoveryCleanedKernel{Identity: next, Exit: exit}
	attempt := lifecycleRecoveryMaxCleanupAttempt(false, next, stream, now)
	if !lifecycleRecoveryCleanupAttemptValid(attempt, false, cleaned, old, binding.TargetArtifact, now) {
		t.Fatal("MODEL complete source Attempt rejected")
	}
	if lifecycleRecoveryCleanupAttemptValid(attempt, false, nil, old, binding.TargetArtifact, now) {
		t.Fatal("MODEL complete owned Attempt accepted without New")
	}
	foreign := labRecoveryStartedCloneObservation(*attempt)
	foreign.StartupIdentity.ArtifactSHA256 = strings.Repeat("f", 64)
	if lifecycleRecoveryCleanupAttemptValid(&foreign, false, cleaned, old, binding.TargetArtifact, now) {
		t.Fatal("MODEL foreign Attempt identity accepted")
	}
	sparse := labRecoveryStartObservation{Schema: labRecoveryStartObservationSchema, Outcome: "ENTRY_REJECTED",
		FailureCode: "CONTEXT_OR_INPUT_REJECTED", StartupIdentity: &next}
	if lifecycleRecoveryCleanupAttemptValid(&sparse, false, nil, old, binding.TargetArtifact, now) {
		t.Fatal("MODEL sparse New-nil Attempt fields accepted")
	}
	wrongSchema := labRecoveryStartedCloneObservation(*attempt)
	wrongSchema.Schema = labRecoveryAbsentStartObservationSchema
	if lifecycleRecoveryCleanupAttemptValid(&wrongSchema, false, cleaned, old, binding.TargetArtifact, now) {
		t.Fatal("MODEL normal/absent Attempt schema crossed")
	}

	owned := func(absent bool, code string) labRecoveryStartObservation {
		v := labRecoveryStartedCloneObservation(*lifecycleRecoveryMaxCleanupAttempt(absent, next, stream, now))
		waited, sent := false, false
		v.StartObservation.WaitReturned = &waited
		v.StartObservation.WaitErrorClass = "NOT_WAITED"
		v.StartObservation.ExitCode, v.StartObservation.Signal, v.StartObservation.GroupAbsent = nil, nil, nil
		v.StartObservation.TermSent, v.StartObservation.KillSent = &sent, &sent
		v.Outcome, v.FailureCode = "START_UNCERTAIN", code
		class := "NONE"
		v.StartErrorClass = &class
		v.StartupIdentity, v.VerifiedIdentity, v.ListenersBefore, v.ListenersAfter = nil, nil, nil, nil
		return v
	}
	full := func(v *labRecoveryStartObservation) {
		before, after := true, true
		startup, verified := next, next
		v.StartupIdentity, v.VerifiedIdentity = &startup, &verified
		v.ListenersBefore, v.ListenersAfter = &before, &after
	}
	for _, absent := range []bool{false, true} {
		for _, code := range []string{"START_REJECTED", "BUDGET_REJECTED", "IDENTITY_REJECTED", "LISTENERS_REJECTED", "OWNED_REJECTED", "ISSUER_REJECTED", "FACT_REJECTED"} {
			v := owned(absent, code)
			switch code {
			case "START_REJECTED":
				failed := "FAILED"
				v.StartErrorClass = &failed
			case "LISTENERS_REJECTED":
				startup := next
				v.StartupIdentity = &startup
			case "OWNED_REJECTED", "ISSUER_REJECTED", "FACT_REJECTED":
				full(&v)
			}
			if !lifecycleRecoveryCleanupAttemptValid(&v, absent, cleaned, old, binding.TargetArtifact, now) {
				t.Fatal("MODEL legal producer post-Start branch rejected: " + code)
			}
			if code != "START_REJECTED" && lifecycleRecoveryCleanupAttemptValid(&v, absent, nil, old, binding.TargetArtifact, now) {
				t.Fatal("MODEL post-Start owned branch accepted without New: " + code)
			}
		}

		listenerAfter := owned(absent, "LISTENERS_REJECTED")
		before, after := true, false
		startup, verified := next, next
		listenerAfter.StartupIdentity, listenerAfter.VerifiedIdentity = &startup, &verified
		listenerAfter.ListenersBefore, listenerAfter.ListenersAfter = &before, &after
		if !lifecycleRecoveryCleanupAttemptValid(&listenerAfter, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL post-verification listener failure rejected")
		}
		lateBudget := owned(absent, "BUDGET_REJECTED")
		full(&lateBudget)
		if !lifecycleRecoveryCleanupAttemptValid(&lateBudget, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL late post-owner budget failure rejected")
		}
		partialBudget := owned(absent, "BUDGET_REJECTED")
		startup = next
		partialBudget.StartupIdentity = &startup
		if lifecycleRecoveryCleanupAttemptValid(&partialBudget, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL impossible mid-pipeline budget failure accepted")
		}
		lateIdentity := owned(absent, "IDENTITY_REJECTED")
		startup = next
		lateIdentity.StartupIdentity = &startup
		lateIdentity.ListenersBefore = &before
		if !lifecycleRecoveryCleanupAttemptValid(&lateIdentity, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL post-listener identity failure rejected")
		}
		mismatchedStartup := next
		mismatchedStartup.PID++
		mismatchedStartup.StartTicks++
		lateMismatch := labRecoveryStartedCloneObservation(lateIdentity)
		lateMismatch.StartupIdentity, lateMismatch.VerifiedIdentity = &mismatchedStartup, &next
		lateMismatch.StartObservation.PID, lateMismatch.StartObservation.StartTicks = &mismatchedStartup.PID, &mismatchedStartup.StartTicks
		if !lifecycleRecoveryCleanupAttemptValid(&lateMismatch, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL actual late identity mismatch rejected")
		}
		startupCleaned := *cleaned
		startupCleaned.Identity = mismatchedStartup
		if lifecycleRecoveryCleanupAttemptValid(&lateMismatch, absent, &startupCleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL late identity mismatch did not bind New to the actual verified cleanup identity")
		}
		foreignVerified := next
		foreignVerified.ArtifactSHA256 = strings.Repeat("e", 64)
		lateMismatch.VerifiedIdentity = &foreignVerified
		if lifecycleRecoveryCleanupAttemptValid(&lateMismatch, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL foreign late verified identity authorized cleanup")
		}

		started := owned(absent, "FACT_REJECTED")
		full(&started)
		started.Outcome, started.FailureCode = "STARTED", "NONE"
		if !lifecycleRecoveryCleanupAttemptValid(&started, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL complete successful producer observation rejected")
		}
		if lifecycleRecoveryCleanupAttemptValid(&started, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL STARTED/NONE accepted without New")
		}

		typedFailure := owned(absent, "START_REJECTED")
		failed, notStarted := "FAILED", false
		typedFailure.StartErrorClass = &failed
		typedFailure.StartObservation.Started = &notStarted
		typedFailure.StartObservation.PID, typedFailure.StartObservation.StartTicks = nil, nil
		typedFailure.StartObservation.TermSent, typedFailure.StartObservation.KillSent = nil, nil
		typedFailure.StartObservation.WaitReturned = &notStarted
		typedFailure.StartObservation.WaitErrorClass = "NOT_WAITED"
		typedFailure.StartObservation.ExitCode, typedFailure.StartObservation.Signal, typedFailure.StartObservation.GroupAbsent = nil, nil, nil
		emptyStream := labKernelStream{SHA256: labConfigHash(nil), Complete: true}
		typedFailure.StartObservation.Stdout, typedFailure.StartObservation.Stderr = &emptyStream, &emptyStream
		if typedFailure.StartObservation.Stdout == nil || typedFailure.StartObservation.Stderr == nil ||
			!lifecycleRecoveryCleanupAttemptValid(&typedFailure, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL typed Started=false startup failure metadata rejected")
		}
		if lifecycleRecoveryCleanupAttemptValid(&typedFailure, absent, cleaned, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL non-started typed failure accepted an identified New kernel")
		}
		preCommand := labRecoveryStartedCloneObservation(typedFailure)
		preCommand.StartObservation.Attempted = false
		preCommand.StartObservation.Stdout, preCommand.StartObservation.Stderr = nil, nil
		if !lifecycleRecoveryCleanupAttemptValid(&preCommand, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL pre-command typed Started=false failure rejected")
		}
		for name, mutate := range map[string]func(*labKernelStartObservation){
			"unknown-start": func(v *labKernelStartObservation) { v.Started = nil },
			"terminal-wait": func(v *labKernelStartObservation) {
				waited, group, code := true, true, 1
				v.WaitReturned, v.GroupAbsent, v.ExitCode, v.WaitErrorClass = &waited, &group, &code, "EXIT_STATUS"
			},
			"incomplete-stream": func(v *labKernelStartObservation) { v.Stdout.Complete = false },
			"truncated-stream": func(v *labKernelStartObservation) { v.Stdout.Truncated, v.Stdout.TotalBytes = true, 1 },
			"nonempty-stream": func(v *labKernelStartObservation) {
				v.Stdout.Bytes, v.Stdout.TotalBytes, v.Stdout.SHA256 = 1, 1, labConfigHash([]byte("x"))
			},
		} {
			invalid := labRecoveryStartedCloneObservation(typedFailure)
			mutate(invalid.StartObservation)
			if lifecycleRecoveryCleanupAttemptValid(&invalid, absent, nil, old, binding.TargetArtifact, now) {
				t.Fatal("MODEL impossible typed Started=false producer shape accepted: " + name)
			}
		}
		attemptedFalseWithStreams := labRecoveryStartedCloneObservation(preCommand)
		attemptedFalseWithStreams.StartObservation.Stdout, attemptedFalseWithStreams.StartObservation.Stderr = &emptyStream, &emptyStream
		if lifecycleRecoveryCleanupAttemptValid(&attemptedFalseWithStreams, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL pre-command typed failure accepted post-pipe streams")
		}
		plainFailure := typedFailure
		plainFailure.StartObservation = nil
		if !lifecycleRecoveryCleanupAttemptValid(&plainFailure, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL plain unowned START_REJECTED rejected")
		}
		lostOwned := owned(absent, "START_REJECTED")
		lostOwned.StartErrorClass = &failed
		if lifecycleRecoveryCleanupAttemptValid(&lostOwned, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL started START_REJECTED erased its owned New kernel")
		}

		emptyStarted := owned(absent, "BUDGET_REJECTED")
		emptyStarted.Outcome, emptyStarted.FailureCode = "STARTED", "NONE"
		emptyStarted.StartObservation = nil
		if lifecycleRecoveryCleanupAttemptValid(&emptyStarted, absent, nil, old, binding.TargetArtifact, now) {
			t.Fatal("MODEL empty STARTED/NONE facts accepted")
		}

		preCases := []labRecoveryStartObservation{
			{PermitConsumed: false, Outcome: "ENTRY_REJECTED", FailureCode: "CONTEXT_OR_INPUT_REJECTED"},
			{PermitConsumed: false, Outcome: "ENTRY_REJECTED", FailureCode: "PERMIT_REJECTED"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "BINDING_REJECTED"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "ATTEMPT_SPENT"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "INPUT_REJECTED"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "NAMESPACE_REJECTED"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "ARTIFACT_REJECTED"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "BUDGET_REJECTED"},
			{PermitConsumed: true, Outcome: "ENTRY_REJECTED", FailureCode: "STATE_REJECTED"},
		}
		for index := range preCases {
			v := &preCases[index]
			if absent {
				v.Schema = labRecoveryAbsentStartObservationSchema
			} else {
				v.Schema = labRecoveryStartObservationSchema
			}
			switch v.FailureCode {
			case "NAMESPACE_REJECTED":
				ns := ^uint64(0)
				v.NamespaceInode = &ns
			case "ARTIFACT_REJECTED", "BUDGET_REJECTED", "STATE_REJECTED":
				ns := old.NetNSInode
				v.NamespaceInode = &ns
			}
			if !lifecycleRecoveryCleanupAttemptValid(v, absent, nil, old, binding.TargetArtifact, now) {
				t.Fatal("MODEL legal pre-Start branch rejected: " + v.FailureCode)
			}
			if lifecycleRecoveryCleanupAttemptValid(v, absent, cleaned, old, binding.TargetArtifact, now) {
				t.Fatal("MODEL pre-Start branch accepted New: " + v.FailureCode)
			}
			if v.FailureCode == "NAMESPACE_REJECTED" {
				expected := old.NetNSInode
				v.NamespaceInode = &expected
				if lifecycleRecoveryCleanupAttemptValid(v, absent, nil, old, binding.TargetArtifact, now) {
					t.Fatal("MODEL expected namespace was mislabeled as NAMESPACE_REJECTED")
				}
			}
		}
	}
}

func TestLifecycleRecoveryAbsentCleanupRequiresPersistedSourceIdentity(t *testing.T) {
	final, _, _ := lifecycleRecoveryReconciledRecordModel(t)
	a := *final.core.Recovery
	cleanup := a.Reconciliation.Cleanup
	a.Phase = "RECOVERY_UNKNOWN"
	a.Reconciliation = nil
	a.Plan.Schema = labRecoveryPlanSchemaV3
	a.Plan.StartMode = labRecoveryStartModeOldEpochAbsent
	a.StopIntent, a.StopBinding, a.Quiescence = nil, nil, nil
	expected := cleanup.Old.Identity
	if !lifecycleRecoveryCleanupValid(cleanup, a, final.core.Current.Head, &expected, cleanup.ObservedAt) {
		t.Fatal("MODEL exact persisted absent cleanup identity rejected")
	}
	wrong := expected
	wrong.StartTicks++
	if lifecycleRecoveryCleanupValid(cleanup, a, final.core.Current.Head, &wrong, cleanup.ObservedAt) {
		t.Fatal("MODEL foreign absent cleanup identity accepted")
	}
}

func TestLifecycleRecoveryAbsentExecutionSchemaPairsAreClosed(t *testing.T) {
	verified, ok := lifecycleRecoveryStartedToVerifiedSchema(lifecycleRecoveryAbsentExecutionSchema)
	if !ok || verified != lifecycleRecoveryAbsentVerifiedExecutionSchema {
		t.Fatal("MODEL absent started/verified pair")
	}
	completed, ok := lifecycleRecoveryVerifiedToCompletedSchema(verified)
	if !ok || completed != lifecycleRecoveryAbsentCompletedExecutionSchema {
		t.Fatal("MODEL absent verified/completed pair")
	}
	back, ok := lifecycleRecoveryCompletedToVerifiedSchema(completed)
	if !ok || back != verified {
		t.Fatal("MODEL absent completion reverse pair")
	}
	if _, ok := lifecycleRecoveryStartedToVerifiedSchema(lifecycleRecoveryAbsentCompletedExecutionSchema); ok {
		t.Fatal("MODEL completed schema crossed into started transition")
	}
}
