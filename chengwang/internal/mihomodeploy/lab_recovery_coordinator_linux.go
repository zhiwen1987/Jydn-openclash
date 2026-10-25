//go:build linux

package mihomodeploy

import (
	"context"
	"reflect"
	"time"
)

func (c *labRecoveryCoordinator) recoveryFailure(op *labRecoveryOperation, code string, observed *labQuiescenceObservation) error {
	if c != nil && op != nil && op.store != nil && op.owner != nil {
		if err := op.store.recordRecoveryFailure(op.owner, code, observed, time.Now().UTC()); err != nil {
			return err
		}
		if c.service == nil || c.service.core == nil {
			return errLifecycleUnsafe
		}
		c.service.core.mu.Lock()
		op.failureCode, op.failureRecorded = code, true
		c.service.core.mu.Unlock()
		return nil
	}
	return errLifecycleUnsafe
}

func (c *labRecoveryCoordinator) retainNextKernel(op *labRecoveryOperation, next *ownedLabKernel) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || next == nil {
		return
	}
	s := c.service.core
	s.mu.Lock()
	op.next = next
	s.kernel = next
	s.kernelSettled = false
	s.kernelStreamsSaved = false
	s.kernelCloseObservation = nil
	s.mu.Unlock()
}

// reconcileSettledFailure consumes no physical handle. The only retryable
// failures are authorization or arm failures before a core permit exists. The
// initial automatic attempt plus one explicit Execute retry is the complete
// budget. Once armed/committing, every failure is terminal because the permit
// or custody may already be consumed and the disk commit may be uncertain.
func (c *labRecoveryCoordinator) reconciliationPrePermitFailure(op *labRecoveryOperation, custody *labRecoveryCleanupCustody) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || custody == nil {
		return
	}
	s := c.service.core
	s.mu.Lock()
	locked := op.reconciliationPrePermitFailed()
	s.mu.Unlock()
	if !locked || custody.issuer == nil {
		return
	}
	issuer := custody.issuer
	// No service/store/owned-core lock is held while the process-global
	// registry decides claim versus discard. Exactly one side can win.
	if issuer.discard(custody, op) {
		s.mu.Lock()
		if op.cleanup == custody {
			op.cleanup = nil
		}
		s.mu.Unlock()
	}
}

func (c *labRecoveryCoordinator) reconcileSettledFailure(headers []string, precheck labRecoveryCheck, op *labRecoveryOperation, custody *labRecoveryCleanupCustody) (*labRecoveryTerminalReentryPermit, error) {
	if c == nil || c.service == nil || c.service.core == nil || c.authority == nil || op == nil ||
		op.store == nil || op.owner == nil || custody == nil {
		return nil, errLifecycleUnsafe
	}
	if precheck.core == nil {
		var err error
		precheck, err = c.authority.authorizeReconcile(headers, op.session, time.Now().UTC())
		if err != nil {
			return nil, err
		}
	}
	s := c.service.core
	s.mu.Lock()
	if !op.beginCurrentAuthorizedReconciliationAttempt(custody, precheck) {
		s.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	failureCode := op.failureCode
	runtime, store, owner, session := s.runtime, op.store, op.owner, op.session
	s.mu.Unlock()
	if failureCode == "" || runtime == nil || session == nil {
		c.reconciliationPrePermitFailure(op, custody)
		return nil, errLifecycleUnsafe
	}
	permit, err := runtime.armRecoveryReconcile(c.service, store, owner, time.Now().UTC())
	if err != nil || permit == nil || permit.core == nil {
		c.reconciliationPrePermitFailure(op, custody)
		if err != nil {
			return nil, err
		}
		return nil, errLifecycleUnsafe
	}

	s.mu.Lock()
	if op.reconcileState != labRecoveryReconcileReady || op.cleanup != custody || !custody.matches(op) {
		op.reconcileState = labRecoveryReconcileLocked
		s.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	op.reconcileState = labRecoveryReconcileArmed
	s.mu.Unlock()
	// Arming does not replace current authorization. Recheck the exact same
	// initiator immediately before capability consumption/publication.
	check, err := c.authority.authorizeReconcile(headers, session, time.Now().UTC())
	if err != nil || check.core == nil {
		s.mu.Lock()
		op.reconcileState = labRecoveryReconcileLocked
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, errLifecycleUnsafe
	}
	p := permit.core
	if !op.reconciliationCheckMatches(check) || check.core.recoveryID != p.recoveryID ||
		check.core.planSHA256 != op.plan.PlanSHA256 || check.core.revision != p.revision || check.core.recordSHA256 != p.recordSHA256 ||
		check.core.fence != p.fence || check.core.intentSHA256 != failureCode {
		s.mu.Lock()
		op.reconcileState = labRecoveryReconcileLocked
		s.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	s.mu.Lock()
	if op.reconcileState != labRecoveryReconcileArmed || op.cleanup != custody || !custody.matches(op) ||
		!op.reconciliationCheckCurrent(check) {
		op.reconcileState = labRecoveryReconcileLocked
		s.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	op.reconcileState = labRecoveryReconcileCommitting
	s.mu.Unlock()
	reentry, err := store.recordRecoveryReconciled(owner, permit, custody, time.Now().UTC())
	if err != nil || reentry == nil || reentry.core == nil {
		s.mu.Lock()
		op.reconcileState = labRecoveryReconcileLocked
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, errLifecycleUnsafe
	}
	s.mu.Lock()
	if op.reconcileState != labRecoveryReconcileCommitting || op.cleanup != custody {
		op.reconcileState = labRecoveryReconcileLocked
		s.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	op.reentry = reentry
	op.reconcileState = labRecoveryReconcileCommitted
	if op.failure != nil {
		op.failure.CleanupState = "SETTLED"
		op.failure.CleanupSHA256 = custody.digest
		op.failure.NextAction = "CREATE_RECOVERY"
	}
	s.mu.Unlock()
	return reentry, nil
}

func (c *labRecoveryCoordinator) retryPlatformReconciliation(headers []string, precheck labRecoveryCheck, op *labRecoveryOperation) error {
	if c == nil || c.service == nil || c.service.core == nil || op == nil {
		return errLifecycleUnsafe
	}
	s := c.service.core
	s.mu.Lock()
	if !op.reconciliationRetryable() {
		s.mu.Unlock()
		return errLifecycleUnsafe
	}
	custody := op.cleanup
	s.mu.Unlock()
	_, err := c.reconcileSettledFailure(headers, precheck, op, custody)
	return err
}

func (c *labRecoveryCoordinator) settlePlatformFailure(op *labRecoveryOperation, headers []string) *LabRecoveryFailureView {
	view := &LabRecoveryFailureView{Schema: LabRecoveryFailureViewSchema, CleanupState: "PENDING", NextAction: "CLOSE_REQUIRED"}
	if c == nil || c.service == nil || c.service.core == nil || op == nil {
		return view
	}
	s := c.service.core
	s.mu.Lock()
	failureCode := op.failureCode
	if failureCode == "" {
		s.mu.Unlock()
		return view
	}
	view.Code = failureCode
	old, oldIdentity, next, diagnostics := op.old, op.oldIdentity, op.next, s.diagnostics
	var expectedOldExit *labKernelExit
	if op.oldExit != nil {
		clone := labQuiescenceCloneExit(*op.oldExit)
		expectedOldExit = &clone
	}
	var quiescence *labQuiescenceObservation
	if op.quiescence != nil {
		clone := labQuiescenceCloneObservation(*op.quiescence)
		quiescence = &clone
	}
	var nextIdentity *labKernelIdentity
	if op.nextIdentity != nil {
		clone := *op.nextIdentity
		nextIdentity = &clone
	}
	var attempt *labRecoveryStartObservation
	if !op.startedRecorded && op.startObservation != nil {
		clone := labRecoveryStartedCloneObservation(*op.startObservation)
		attempt = &clone
	}
	runtime, store, owner := s.runtime, op.store, op.owner
	currentMatches := next != nil && s.kernel == next || next == nil && op.sourceCleanup == nil && s.kernel == old
	if next == nil && op.sourceCleanup != nil && s.kernel != nil {
		currentMatches = op.sourceCleanup.next != nil && s.kernel.ownedLabKernelCore == op.sourceCleanup.next ||
			op.sourceCleanup.next == nil && s.kernel.ownedLabKernelCore == op.sourceCleanup.old
	}
	if old == nil || !labQuiescenceIdentityValid(oldIdentity) || runtime == nil || runtime.core == nil ||
		store == nil || store.core == nil || owner == nil || owner.core == nil ||
		!currentMatches {
		s.mu.Unlock()
		return view
	}
	s.mu.Unlock()
	if diagnostics == nil {
		return view
	}

	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	oldExit, oldStopErr := labRecoverySettleOwnedKernel(cleanup, old, quiescence, expectedOldExit)
	oldStdout, oldStderr, oldStreamsErr := labServiceKernelStreams(old)
	var nextExit *labKernelExit
	var nextStdout, nextStderr []byte
	var nextStopErr, nextStreamsErr error
	var unstartedReceipt *labRecoveryUnstartedCleanupReceipt
	if next != nil {
		if nextIdentity == nil {
			observation, stdout, stderr, unstartedErr := labRecoverySettleUnstartedKernel(cleanup, next)
			if unstartedErr == nil {
				unstartedReceipt, nextStdout, nextStderr = &observation, stdout, stderr
			}
		}
		if unstartedReceipt == nil {
			exit, stopErr := labRecoverySettleOwnedKernel(cleanup, next, nil, nil)
			nextExit, nextStopErr = &exit, stopErr
			nextStdout, nextStderr, nextStreamsErr = labServiceKernelStreams(next)
		}
	}
	cancel()
	unstartedRebound := unstartedReceipt == nil
	if unstartedReceipt != nil {
		s.mu.Lock()
		unstartedRebound = labRecoveryRebindUnstartedKernelLocked(s, next, old, oldExit, oldStreamsErr == nil)
		s.mu.Unlock()
	}
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	probes := labRecoveryCleanupProbes(probeCtx, oldIdentity)
	probeCancel()
	observedAt := time.Now().UTC()
	stage, stageErr := labRecoveryCaptureNamespace(op.id)
	digest := ""
	var canonical []byte
	saveErr := errLifecycleUnsafe
	nextSettled := next == nil || unstartedReceipt != nil && unstartedRebound || nextIdentity != nil && nextExit != nil && nextStopErr == nil
	physicalSettled := oldStopErr == nil && nextStreamsErr == nil && nextSettled
	if stageErr == nil && oldStreamsErr == nil && nextStreamsErr == nil {
		digest, canonical, saveErr = diagnostics.recoveryCleanup(stage, op.id, failureCode, observedAt,
			oldIdentity, oldExit, oldStdout, oldStderr, nextIdentity, nextExit, nextStdout, nextStderr, unstartedReceipt, probes, physicalSettled)
	}
	if lifecycleNonzeroHash(digest) {
		view.CleanupSHA256 = digest
		view.CleanupState = "UNCERTAIN"
	}
	settled := physicalSettled && oldStreamsErr == nil && nextStreamsErr == nil &&
		stageErr == nil && saveErr == nil && lifecycleNonzeroHash(digest)
	if settled {
		view.CleanupState = "SETTLED"
		view.NextAction = "CORE_RECONCILIATION_REQUIRED"
	}
	if settled && len(canonical) != 0 {
		custody := &labRecoveryCleanupCustody{issuer: &processLabRecoveryCleanupIssuer, operation: op,
			service: s, runtime: runtime.core, store: store.core, disk: runtime.core.disk, diagnostics: diagnostics.core, owner: owner.core,
			old: old.ownedLabKernelCore, next: nil, oldIdentity: oldIdentity, nextIdentity: nextIdentity,
			oldExit: labQuiescenceCloneExit(oldExit), nextExit: nextExit, attempt: attempt, probes: probes,
			oldStdoutSHA256: labConfigHash(oldStdout), oldStderrSHA256: labConfigHash(oldStderr),
			oldStdoutBytes: len(oldStdout), oldStderrBytes: len(oldStderr), observedAt: observedAt,
			failureCode: failureCode, canonical: string(canonical), digest: digest, settled: true}
		if next != nil && unstartedReceipt == nil {
			custody.next = next.ownedLabKernelCore
			custody.nextStdoutSHA256, custody.nextStderrSHA256 = labConfigHash(nextStdout), labConfigHash(nextStderr)
			custody.nextStdoutBytes, custody.nextStderrBytes = len(nextStdout), len(nextStderr)
			clone := labQuiescenceCloneExit(*nextExit)
			custody.nextExit = &clone
		}
		if unstartedReceipt != nil {
			u := &labRecoveryUnstartedCleanupCustody{issuer: custody.issuer, parent: custody, operation: op,
				service: s, kernel: next.ownedLabKernelCore, observation: labRecoveryStartedCloneStart(unstartedReceipt.Observation),
				stdout: unstartedReceipt.Stdout, stderr: unstartedReceipt.Stderr,
				stdoutSHA256: labConfigHash(nextStdout), stderrSHA256: labConfigHash(nextStderr),
				stdoutBytes: len(nextStdout), stderrBytes: len(nextStderr), observedAt: unstartedReceipt.ObservedAt}
			operation, service, kernel, sealedObservation := op, s, next.ownedLabKernelCore, labRecoveryStartedCloneStart(unstartedReceipt.Observation)
			stdoutMeta, stderrMeta, stdoutSHA, stderrSHA := unstartedReceipt.Stdout, unstartedReceipt.Stderr, u.stdoutSHA256, u.stderrSHA256
			stdoutBytes, stderrBytes, sealedAt := u.stdoutBytes, u.stderrBytes, u.observedAt
			u.binding = func(candidate *labRecoveryUnstartedCleanupCustody, parent *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
				return candidate == u && parent == custody && current == operation && candidate.parent == custody &&
					candidate.operation == operation && candidate.service == service && candidate.kernel == kernel &&
					reflect.DeepEqual(candidate.observation, sealedObservation) && candidate.stdout == stdoutMeta && candidate.stderr == stderrMeta &&
					candidate.stdoutSHA256 == stdoutSHA && candidate.stderrSHA256 == stderrSHA &&
					candidate.stdoutBytes == stdoutBytes && candidate.stderrBytes == stderrBytes && candidate.observedAt.Equal(sealedAt) &&
					labRecoveryUnstartedCleanupCurrent(candidate)
			}
			custody.unstartedNext = u
		}
		operation, service, runtimeCore, storeCore, disk, diagnosticsCore, ownerCore := op, s, runtime.core, store.core, runtime.core.disk, diagnostics.core, owner.core
		oldCore, nextCore, unstartedCore, sealed, sealedDigest, sealedAt, sealedFailure := custody.old, custody.next, custody.unstartedNext, custody.canonical, digest, observedAt, failureCode
		custody.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
			return candidate == custody && current == operation && candidate.operation == operation &&
				candidate.service == service && candidate.runtime == runtimeCore && candidate.store == storeCore &&
				candidate.disk == disk && candidate.diagnostics == diagnosticsCore && candidate.owner == ownerCore && candidate.old == oldCore && candidate.next == nextCore && candidate.unstartedNext == unstartedCore &&
				candidate.canonical == sealed && candidate.digest == sealedDigest && candidate.observedAt.Equal(sealedAt) && candidate.failureCode == sealedFailure &&
				candidate.settled &&
				labConfigHash([]byte(candidate.canonical)) == candidate.digest
		}
		if custody.issuer.issue(custody) {
			s.mu.Lock()
			op.cleanup = custody
			op.reconcileState = labRecoveryReconcileReady
			s.mu.Unlock()
			if reentry, reconcileErr := c.reconcileSettledFailure(headers, labRecoveryCheck{}, op, custody); reconcileErr == nil && reentry != nil {
				view.NextAction = "CREATE_RECOVERY"
			} else {
				s.mu.Lock()
				state := op.reconcileState
				s.mu.Unlock()
				if state == labRecoveryReconcileLocked {
					view.CleanupState, view.NextAction = "UNCERTAIN", "CLOSE_REQUIRED"
				}
			}
		} else {
			view.CleanupState, view.CleanupSHA256, view.NextAction = "UNCERTAIN", digest, "CLOSE_REQUIRED"
		}
	}
	s.mu.Lock()
	current := old
	currentExit := oldExit
	currentStopErr, currentStreamsErr := oldStopErr, oldStreamsErr
	if next != nil && unstartedReceipt == nil {
		current, currentExit, currentStopErr, currentStreamsErr = next, *nextExit, nextStopErr, nextStreamsErr
	}
	if s.kernel == current {
		clone := labQuiescenceCloneExit(currentExit)
		s.kernelCloseObservation = &clone
		s.kernelSettled = currentStopErr == nil
		s.kernelStreamsSaved = currentStreamsErr == nil && saveErr == nil
		s.ready = false
	}
	s.mu.Unlock()
	return view
}

// The caller holds the exact service mutex. A failed wrapper with no OS
// process is no longer the live service kernel after its source cleanup joins;
// the already-settled old handle remains the warm ownership anchor used by the
// FAILED_RECONCILED -> OLD_EPOCH_ABSENT custody chain.
func labRecoveryRebindUnstartedKernelLocked(s *labServiceCore, failed, old *ownedLabKernel, oldExit labKernelExit, streamsSaved bool) bool {
	if s == nil || failed == nil || failed.ownedLabKernelCore == nil || old == nil || old.ownedLabKernelCore == nil ||
		failed.ownedLabKernelCore == old.ownedLabKernelCore || s.kernel != failed || !labQuiescenceExitDrained(oldExit) {
		return false
	}
	clone := labQuiescenceCloneExit(oldExit)
	s.kernel = old
	s.kernelCloseObservation = &clone
	s.kernelSettled = true
	s.kernelStreamsSaved = streamsSaved
	s.ready = false
	return true
}

func labRecoverySettleOwnedKernel(ctx context.Context, kernel *ownedLabKernel, observed *labQuiescenceObservation, expected *labKernelExit) (labKernelExit, error) {
	if kernel == nil || kernel.ownedLabKernelCore == nil {
		return labKernelExit{}, errLifecycleUnsafe
	}
	if expected != nil && labQuiescenceExitDrained(*expected) {
		actual, err := kernel.ownedLabKernelCore.exitSnapshot()
		if (err == nil || err == errLabKernelStop) && labQuiescenceExitDrained(actual) && labQuiescenceExitEqual(actual, *expected) {
			return actual, nil
		}
		return actual, errLifecycleUnsafe
	}
	if observed != nil && observed.StopInvoked && observed.StopReturned && observed.Stop != nil && labQuiescenceExitDrained(*observed.Stop) {
		actual, err := kernel.ownedLabKernelCore.exitSnapshot()
		if (err == nil || err == errLabKernelStop) && labQuiescenceExitDrained(actual) && labQuiescenceExitEqual(actual, *observed.Stop) {
			return actual, nil
		}
		return actual, errLifecycleUnsafe
	}
	exit, err := kernel.stop(ctx)
	if (err == nil || err == errLabKernelStop) && labQuiescenceExitDrained(exit) {
		return exit, nil
	}
	return exit, errLifecycleUnsafe
}

// labRecoverySettleUnstartedKernel consumes an owned wrapper only after the
// native Start result is known to be false and no os.Process, PID or start tick
// ever existed. It does not manufacture Wait, identity or complete-stream
// facts. A wrapper with an actual or uncertain process must use the ordinary
// owned stop path instead.
func labRecoverySettleUnstartedKernel(ctx context.Context, kernel *ownedLabKernel) (labRecoveryUnstartedCleanupReceipt, []byte, []byte, error) {
	var zero labRecoveryUnstartedCleanupReceipt
	if ctx == nil || ctx.Err() != nil || kernel == nil || kernel.ownedLabKernelCore == nil {
		return zero, nil, nil, errLifecycleUnsafe
	}
	c := kernel.ownedLabKernelCore
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	c.mu.Lock()
	if c.closed || !c.startKnown || c.process != nil || c.observedPID != nil || c.observedTicks != nil ||
		c.exit.Started || c.exit.WaitReturned || c.exit.WaitErrorClass != "NOT_WAITED" || c.done == nil || c.cancel == nil ||
		c.stdout == nil || c.stderr == nil {
		c.mu.Unlock()
		return zero, nil, nil, errLifecycleUnsafe
	}
	c.closed = true
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return zero, nil, nil, errLifecycleUnsafe
	}
	if !labRecoveryUnstartedKernelState(c) {
		return zero, nil, nil, errLifecycleUnsafe
	}
	observation := kernel.startObservation()
	stdout, stdoutMeta := c.stdout.snapshot()
	stderr, stderrMeta := c.stderr.snapshot()
	observedAt := time.Now().UTC()
	receipt := labRecoveryUnstartedCleanupReceipt{Schema: labRecoveryUnstartedCleanupSchema,
		Observation: labRecoveryStartedCloneStart(observation), Stdout: stdoutMeta, Stderr: stderrMeta, ObservedAt: observedAt}
	if !labRecoveryUnstartedCleanupReceiptValid(receipt) ||
		!labRecoveryCleanupStreamSnapshotMatches(stdoutMeta, stdout) || !labRecoveryCleanupStreamSnapshotMatches(stderrMeta, stderr) {
		return zero, nil, nil, errLifecycleUnsafe
	}
	return receipt, stdout, stderr, nil
}

func labRecoveryUnstartedKernelState(c *ownedLabKernelCore) bool {
	if c == nil {
		return false
	}
	select {
	case <-c.done:
	default:
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed && c.startKnown && c.process == nil && c.observedPID == nil && c.observedTicks == nil &&
		!c.exit.Started && !c.exit.WaitReturned && c.exit.WaitErrorClass == "NOT_WAITED" &&
		c.exit.ExitCode == nil && c.exit.Signal == nil && !c.exit.TermSent && !c.exit.KillSent && c.exit.GroupAbsent == nil
}

func labRecoveryUnstartedCleanupCurrent(custody *labRecoveryUnstartedCleanupCustody) bool {
	if custody == nil || custody.kernel == nil {
		return false
	}
	c := custody.kernel
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if !labRecoveryUnstartedKernelState(c) {
		return false
	}
	observation := (&ownedLabKernel{c}).startObservation()
	stdout, stdoutMeta := c.stdout.snapshot()
	stderr, stderrMeta := c.stderr.snapshot()
	return reflect.DeepEqual(observation, custody.observation) && stdoutMeta == custody.stdout && stderrMeta == custody.stderr &&
		len(stdout) == custody.stdoutBytes && len(stderr) == custody.stderrBytes &&
		labConfigHash(stdout) == custody.stdoutSHA256 && labConfigHash(stderr) == custody.stderrSHA256
}

func labRecoveryCleanupProbes(ctx context.Context, old labKernelIdentity) [4]labRecoveryCleanupProbe {
	roles := [4]string{"OLD_CONTROLLER", "OLD_MIXED", "NEW_CONTROLLER", "NEW_MIXED"}
	ports := [4]uint16{old.ControllerPort, old.MixedPort, old.ControllerPort, old.MixedPort}
	var out [4]labRecoveryCleanupProbe
	for i := range out {
		out[i] = labRecoveryCleanupProbe{Role: roles[i], ObservedAt: time.Now().UTC(), Probe: labQuiescenceDial(ctx, ports[i])}
	}
	return out
}

// executePlatform runs only after the generic coordinator has acquired the
// service close exclusion and marked busy. The service lifetime owns all
// physical work even when the originating HTTP request is cancelled.
func (c *labRecoveryCoordinator) executePlatform(ctx context.Context, headers []string, op *labRecoveryOperation) (_ LabRecoveryView, returned error) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || op.store == nil || op.owner == nil || op.session == nil || artifactContext(ctx) != nil {
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	s := c.service.core
	s.mu.Lock()
	old := s.kernel
	input := s.input
	artifacts := s.artifacts
	s.mu.Unlock()
	if old == nil || input == nil || artifacts == nil {
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	if op.plan.Schema == labRecoveryPlanSchemaV3 && op.plan.StartMode == labRecoveryStartModeOldEpochAbsent && op.sourceCleanup != nil {
		return c.executeAbsentPlatform(ctx, headers, op, input, artifacts)
	}
	oldIdentity, err := old.identity()
	if err != nil {
		return LabRecoveryView{}, err
	}
	s.mu.Lock()
	op.old, op.oldIdentity = old, oldIdentity
	s.mu.Unlock()
	binding, err := op.store.armRecoveryStop(op.owner, oldIdentity, time.Now().UTC())
	if err != nil {
		return LabRecoveryView{}, err
	}
	s.mu.Lock()
	op.physical = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		alreadyFailed, completionCommitted := op.failureCode != "", op.completionCommitted
		s.mu.Unlock()
		if returned == nil || alreadyFailed || completionCommitted {
			return
		}
		code := "START_UNCERTAIN"
		if ctx.Err() != nil {
			code = "SERVICE_CONTEXT_CANCELLED"
		}
		if failureErr := c.recoveryFailure(op, code, nil); failureErr != nil {
			returned = failureErr
		}
	}()
	stopCheck, err := c.authority.authorizeStep(headers, op.session, "STOP", time.Now().UTC())
	if err != nil || stopCheck.core == nil {
		if failureErr := c.recoveryFailure(op, "AUTHORITY_CHANGED", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	op.executorRef = stopCheck.core.actorRef
	stopCtx, stopCancel := context.WithTimeout(ctx, time.Duration(op.plan.Budgets.StopMillis)*time.Millisecond)
	quiesced, observation, err := quiesceOwnedLabKernel(stopCtx, old, binding)
	stopCancel()
	cloneObservation := labQuiescenceCloneObservation(observation)
	s.mu.Lock()
	op.quiescence = &cloneObservation
	if observation.Stop != nil && labQuiescenceExitDrained(*observation.Stop) {
		cloneExit := labQuiescenceCloneExit(*observation.Stop)
		op.oldExit = &cloneExit
	}
	s.mu.Unlock()
	if err != nil {
		if failureErr := c.recoveryFailure(op, "QUIESCENCE_REJECTED", &observation); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		return LabRecoveryView{}, err
	}
	if err := op.store.recordRecoveryQuiescence(op.owner, quiesced, time.Now().UTC()); err != nil {
		return LabRecoveryView{}, err
	}
	s.mu.Lock()
	if s.kernel == old {
		s.kernelSettled = true
	}
	s.mu.Unlock()
	permit, err := op.store.armRecoveryStart(op.owner, time.Now().UTC())
	if err != nil {
		return LabRecoveryView{}, err
	}
	startCheck, err := c.authority.authorizeStep(headers, op.session, "START", time.Now().UTC())
	if err != nil || startCheck.core == nil || startCheck.core.actorRef != op.executorRef {
		if failureErr := c.recoveryFailure(op, "AUTHORITY_CHANGED", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	next, started, startObservation, err := startOwnedRecoveryKernel(ctx, input, artifacts, permit)
	cloneStart := labRecoveryStartedCloneObservation(startObservation)
	s.mu.Lock()
	op.startObservation = &cloneStart
	if startObservation.StartupIdentity != nil {
		cloneIdentity := *startObservation.StartupIdentity
		op.nextIdentity = &cloneIdentity
	}
	s.mu.Unlock()
	if next != nil {
		c.retainNextKernel(op, next)
		if identity, identityErr := next.identity(); identityErr == nil {
			s.mu.Lock()
			cloneIdentity := identity
			op.nextIdentity = &cloneIdentity
			s.mu.Unlock()
		}
	}
	if err != nil || next == nil || started == nil || !startObservation.StartInvoked || !startObservation.StartReturned || startObservation.Outcome != "STARTED" {
		if failureErr := c.recoveryFailure(op, "START_UNCERTAIN", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	if err := op.store.recordRecoveryStarted(op.owner, started, time.Now().UTC()); err != nil {
		if failureErr := c.recoveryFailure(op, "START_UNCERTAIN", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		return LabRecoveryView{}, err
	}
	s.mu.Lock()
	op.startedRecorded = true
	s.mu.Unlock()
	if identity, identityErr := next.identity(); identityErr == nil {
		s.mu.Lock()
		cloneIdentity := identity
		op.nextIdentity = &cloneIdentity
		s.mu.Unlock()
	}
	stage, err := labRecoveryCaptureNamespace(op.id)
	if err != nil {
		return LabRecoveryView{}, err
	}
	collector, err := newLabRecoveryCollectorAt(c.service, c.authority, op.session, next, stage)
	if err != nil {
		return LabRecoveryView{}, err
	}
	err = labRecoveryWithRecordContext(ctx, time.Duration(op.plan.Budgets.VerificationMillis)*time.Millisecond, func(verifyCtx context.Context) error {
		observed, collectErr := collector.collect(verifyCtx, headers)
		if collectErr != nil {
			return collectErr
		}
		_, recordCap, consumeErr := collector.consumeForRecord(verifyCtx, headers, observed)
		if consumeErr != nil {
			return consumeErr
		}
		if recordCap == nil || recordCap.core == nil {
			return errLifecycleUnsafe
		}
		return op.store.recordRecoveryVerification(op.owner, recordCap, time.Now().UTC())
	})
	if err != nil {
		return LabRecoveryView{}, err
	}
	var ordinaryCollector *labCollector
	var handoff *lifecycleRecoveryCurrentHandoff
	err = labRecoveryWithRecordContext(ctx, 5*time.Second, func(completionCtx context.Context) error {
		completionCap, capErr := collector.completionCap(completionCtx, headers)
		if capErr != nil {
			return capErr
		}
		if completionCap == nil || completionCap.core == nil {
			return errLifecycleUnsafe
		}
		ordinaryCollector, capErr = newLabCollector(artifacts, next, s.fixture, s.diagnostics, s.scope)
		if capErr != nil {
			return capErr
		}
		handoff, capErr = op.store.recordRecoveryCompletion(op.owner, completionCap, time.Now().UTC())
		return capErr
	})
	if err != nil || handoff == nil {
		if ordinaryCollector != nil {
			ordinaryCollector.close()
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	s.mu.Lock()
	op.completionCommitted = true
	s.mu.Unlock()
	facade, ordinaryOwner, err := s.runtime.adoptCurrentEpoch(handoff, op.store)
	if err != nil || facade == nil || ordinaryOwner == nil {
		ordinaryCollector.close()
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}

	s.mu.Lock()
	if s.closed || s.closing || s.runtime == nil || s.kernel != next || s.recovery != c {
		s.ready = false
		s.mu.Unlock()
		ordinaryCollector.close()
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	oldCollector := s.collector
	s.store, s.owner, s.kernel, s.collector = facade, ordinaryOwner, next, ordinaryCollector
	s.kernelSettled = false
	s.kernelStreamsSaved = false
	s.kernelCloseObservation = nil
	s.ready = true
	result, viewErr := c.viewLocked(op, false)
	s.mu.Unlock()
	if oldCollector != nil {
		oldCollector.close()
	}
	if viewErr != nil {
		return LabRecoveryView{}, viewErr
	}
	return result, nil
}

func (c *labRecoveryCoordinator) executeAbsentPlatform(ctx context.Context, headers []string, op *labRecoveryOperation, input *labKernelInput, artifacts *ArtifactStore) (_ LabRecoveryView, returned error) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || op.store == nil || op.owner == nil ||
		op.sourceCleanup == nil || op.sourceReentry == nil || op.sourceReentry.core == nil {
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	s := c.service.core
	s.mu.Lock()
	source := op.sourceCleanup
	if source.old == nil || !labQuiescenceIdentityValid(source.oldIdentity) || !labQuiescenceExitDrained(source.oldExit) || s.kernel == nil ||
		(source.next != nil && s.kernel.ownedLabKernelCore != source.next) || (source.next == nil && s.kernel.ownedLabKernelCore != source.old) {
		s.mu.Unlock()
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	exit := labQuiescenceCloneExit(source.oldExit)
	op.old, op.oldIdentity, op.oldExit = &ownedLabKernel{source.old}, source.oldIdentity, &exit
	op.physical = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		alreadyFailed, completionCommitted := op.failureCode != "", op.completionCommitted
		s.mu.Unlock()
		if returned == nil || alreadyFailed || completionCommitted {
			return
		}
		code := "START_UNCERTAIN"
		if ctx.Err() != nil {
			code = "SERVICE_CONTEXT_CANCELLED"
		}
		if failureErr := c.recoveryFailure(op, code, nil); failureErr != nil {
			returned = failureErr
		}
	}()
	prepareCheck, err := c.authority.authorizeStep(headers, op.session, "ABSENT_PREPARE", time.Now().UTC())
	if err != nil || prepareCheck.core == nil {
		if failureErr := c.recoveryFailure(op, "AUTHORITY_CHANGED", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	op.executorRef = prepareCheck.core.actorRef
	custody, err := c.newAbsentStartCustody(ctx, op)
	if err != nil {
		return LabRecoveryView{}, err
	}
	permit, err := op.store.armRecoveryAbsentStart(op.owner, custody, time.Now().UTC())
	if err != nil {
		return LabRecoveryView{}, err
	}
	startCheck, err := c.authority.authorizeStep(headers, op.session, "START", time.Now().UTC())
	if err != nil || startCheck.core == nil || startCheck.core.actorRef != op.executorRef {
		if failureErr := c.recoveryFailure(op, "AUTHORITY_CHANGED", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	return c.executeRecoveryStart(ctx, headers, op, artifacts, func() (*ownedLabKernel, *labRecoveryStartedEpoch, labRecoveryStartObservation, error) {
		return startOwnedAbsentRecoveryKernel(ctx, input, artifacts, permit)
	})
}

func (c *labRecoveryCoordinator) newAbsentStartCustody(ctx context.Context, op *labRecoveryOperation) (*labRecoveryAbsentStartCustody, error) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || op.store == nil || op.store.core == nil ||
		op.owner == nil || op.owner.core == nil || op.sourceReentry == nil || op.sourceReentry.core == nil || artifactContext(ctx) != nil {
		return nil, errLifecycleUnsafe
	}
	s, reentry := c.service.core, op.sourceReentry.core
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	controllerAt := time.Now().UTC()
	controller := labQuiescenceDial(probeCtx, 28412)
	mixedAt := time.Now().UTC()
	mixed := labQuiescenceDial(probeCtx, 28411)
	cancel()
	observedAt := time.Now().UTC()
	if controller.Result != "CONNECTION_REFUSED" || mixed.Result != "CONNECTION_REFUSED" ||
		reentry.runtime == nil || reentry.service != s || reentry.store != op.store.core || reentry.disk == nil ||
		!lifecycleRecoverySameDisk(reentry.disk, s.runtime.core.disk) || !lifecycleNonzeroHash(reentry.cleanupSHA) ||
		!lifecycleNonzeroHash(reentry.terminalRoot) || len(reentry.terminalCanonical) == 0 || !lifecycleNonzeroHash(op.plan.PlanSHA256) {
		return nil, errLifecycleUnsafe
	}
	custody := &labRecoveryAbsentStartCustody{issuer: &processLabRecoveryAbsentStartIssuer, operation: op,
		service: s, runtime: s.runtime.core, store: op.store.core, disk: s.runtime.core.disk, owner: op.owner.core,
		reentry: reentry, oldIdentity: op.oldIdentity, cleanupSHA: reentry.cleanupSHA, terminalRoot: reentry.terminalRoot,
		terminalCanonical: reentry.terminalCanonical, planSHA: op.plan.PlanSHA256, recoveryID: op.id,
		probes: [2]labRecoveryCleanupProbe{{Role: "CONTROLLER", ObservedAt: controllerAt, Probe: controller},
			{Role: "MIXED", ObservedAt: mixedAt, Probe: mixed}}, observedAt: observedAt}
	operation, service, runtime, store, disk, owner, sourceReentry, oldIdentity := op, s, s.runtime.core, op.store.core, s.runtime.core.disk, op.owner.core, reentry, op.oldIdentity
	cleanupSHA, terminalRoot, terminalCanonical, planSHA, recoveryID, probes, sealedAt := custody.cleanupSHA, custody.terminalRoot, custody.terminalCanonical, custody.planSHA, custody.recoveryID, custody.probes, custody.observedAt
	custody.binding = func(candidate *labRecoveryAbsentStartCustody) bool {
		return candidate == custody && candidate.operation == operation && candidate.service == service &&
			candidate.runtime == runtime && candidate.store == store && candidate.disk == disk && candidate.owner == owner &&
			candidate.reentry == sourceReentry && candidate.oldIdentity == oldIdentity && candidate.cleanupSHA == cleanupSHA && candidate.terminalRoot == terminalRoot &&
			candidate.terminalCanonical == terminalCanonical && candidate.planSHA == planSHA && candidate.recoveryID == recoveryID &&
			candidate.probes == probes && candidate.observedAt.Equal(sealedAt)
	}
	if !custody.issuer.issue(custody) {
		return nil, errLifecycleUnsafe
	}
	return custody, nil
}

func (c *labRecoveryCoordinator) executeRecoveryStart(ctx context.Context, headers []string, op *labRecoveryOperation, artifacts *ArtifactStore,
	start func() (*ownedLabKernel, *labRecoveryStartedEpoch, labRecoveryStartObservation, error)) (LabRecoveryView, error) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || start == nil {
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	s := c.service.core
	next, started, startObservation, err := start()
	cloneStart := labRecoveryStartedCloneObservation(startObservation)
	s.mu.Lock()
	op.startObservation = &cloneStart
	if startObservation.StartupIdentity != nil {
		cloneIdentity := *startObservation.StartupIdentity
		op.nextIdentity = &cloneIdentity
	}
	s.mu.Unlock()
	if next != nil {
		c.retainNextKernel(op, next)
		if identity, identityErr := next.identity(); identityErr == nil {
			s.mu.Lock()
			cloneIdentity := identity
			op.nextIdentity = &cloneIdentity
			s.mu.Unlock()
		}
	}
	if err != nil || next == nil || started == nil || !startObservation.StartInvoked || !startObservation.StartReturned || startObservation.Outcome != "STARTED" {
		if failureErr := c.recoveryFailure(op, "START_UNCERTAIN", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	if err := op.store.recordRecoveryStarted(op.owner, started, time.Now().UTC()); err != nil {
		if failureErr := c.recoveryFailure(op, "START_UNCERTAIN", nil); failureErr != nil {
			return LabRecoveryView{}, failureErr
		}
		return LabRecoveryView{}, err
	}
	s.mu.Lock()
	op.startedRecorded = true
	s.mu.Unlock()
	if identity, identityErr := next.identity(); identityErr == nil {
		s.mu.Lock()
		cloneIdentity := identity
		op.nextIdentity = &cloneIdentity
		s.mu.Unlock()
	}
	stage, err := labRecoveryCaptureNamespace(op.id)
	if err != nil {
		return LabRecoveryView{}, err
	}
	collector, err := newLabRecoveryCollectorAt(c.service, c.authority, op.session, next, stage)
	if err != nil {
		return LabRecoveryView{}, err
	}
	err = labRecoveryWithRecordContext(ctx, time.Duration(op.plan.Budgets.VerificationMillis)*time.Millisecond, func(verifyCtx context.Context) error {
		observed, collectErr := collector.collect(verifyCtx, headers)
		if collectErr != nil {
			return collectErr
		}
		_, recordCap, consumeErr := collector.consumeForRecord(verifyCtx, headers, observed)
		if consumeErr != nil {
			return consumeErr
		}
		if recordCap == nil || recordCap.core == nil {
			return errLifecycleUnsafe
		}
		return op.store.recordRecoveryVerification(op.owner, recordCap, time.Now().UTC())
	})
	if err != nil {
		return LabRecoveryView{}, err
	}
	var ordinaryCollector *labCollector
	var handoff *lifecycleRecoveryCurrentHandoff
	err = labRecoveryWithRecordContext(ctx, 5*time.Second, func(completionCtx context.Context) error {
		completionCap, capErr := collector.completionCap(completionCtx, headers)
		if capErr != nil {
			return capErr
		}
		if completionCap == nil || completionCap.core == nil {
			return errLifecycleUnsafe
		}
		ordinaryCollector, capErr = newLabCollector(artifacts, next, s.fixture, s.diagnostics, s.scope)
		if capErr != nil {
			return capErr
		}
		handoff, capErr = op.store.recordRecoveryCompletion(op.owner, completionCap, time.Now().UTC())
		return capErr
	})
	if err != nil || handoff == nil {
		if ordinaryCollector != nil {
			ordinaryCollector.close()
		}
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	s.mu.Lock()
	op.completionCommitted = true
	s.mu.Unlock()
	facade, ordinaryOwner, err := s.runtime.adoptCurrentEpoch(handoff, op.store)
	if err != nil || facade == nil || ordinaryOwner == nil {
		ordinaryCollector.close()
		if err != nil {
			return LabRecoveryView{}, err
		}
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	s.mu.Lock()
	if s.closed || s.closing || s.runtime == nil || s.kernel != next || s.recovery != c {
		s.ready = false
		s.mu.Unlock()
		ordinaryCollector.close()
		return LabRecoveryView{}, errLifecycleUnsafe
	}
	oldCollector := s.collector
	s.store, s.owner, s.kernel, s.collector = facade, ordinaryOwner, next, ordinaryCollector
	s.kernelSettled = false
	s.kernelStreamsSaved = false
	s.kernelCloseObservation = nil
	s.ready = true
	result, viewErr := c.viewLocked(op, false)
	s.mu.Unlock()
	if oldCollector != nil {
		oldCollector.close()
	}
	if viewErr != nil {
		return LabRecoveryView{}, viewErr
	}
	return result, nil
}
