package mihomodeploy

import (
	"reflect"
	"time"
)

// consumeRecoveryReconciliation is the only bridge from source-owned cleanup
// observations to the core terminal-reconciliation transition. Registry
// consumption is deliberately first: a malformed, stale or foreign permit
// poisons this exact custody rather than turning cleanup into an oracle or a
// retryable authority source.
func (c *labRecoveryCleanupCustody) consumeRecoveryReconciliation(p *labRecoveryReconcilePermit, now time.Time) (lifecycleRecoveryCleanupFact, error) {
	var zero lifecycleRecoveryCleanupFact
	if c == nil || c.issuer == nil {
		return zero, errLifecycleUnsafe
	}
	i := c.issuer
	unstarted, claimed := i.claim(c)
	if !claimed {
		return zero, errLifecycleUnsafe
	}

	if p == nil || p.core == nil || p.core.binding == nil || !p.core.binding(p.core) ||
		c.binding == nil || !c.binding(c, c.operation) || !c.settled || !lifecycleTime(now) ||
		!lifecycleTime(c.observedAt) || now.Before(c.observedAt) || len(c.canonical) == 0 ||
		!lifecycleNonzeroHash(c.digest) || labConfigHash([]byte(c.canonical)) != c.digest {
		return zero, errLifecycleUnsafe
	}
	pc := p.core
	if pc.service != c.service || pc.runtime != c.runtime || pc.store != c.store || pc.owner != c.owner ||
		c.service == nil || c.runtime == nil || c.store == nil || c.disk == nil || c.diagnostics == nil || c.owner == nil ||
		pc.disk == nil || !lifecycleRecoverySameDisk(pc.disk, c.disk) || !lifecycleRecoverySameDisk(c.store.disk, c.disk) ||
		c.runtime.disk != c.disk || pc.recoveryID != c.operation.id || pc.recoveryID == "" ||
		pc.nonce == "" || pc.nonce != c.owner.nonce || pc.fence == 0 || pc.fence != c.owner.fence ||
		pc.revision == 0 || !lifecycleNonzeroHash(pc.recordSHA256) || len(pc.canonical) == 0 ||
		!lifecycleTime(pc.unknownUpdatedAt) || c.observedAt.Before(pc.unknownUpdatedAt) {
		return zero, errLifecycleUnsafe
	}
	if c.old == nil || !labQuiescenceIdentityValid(c.oldIdentity) || !labQuiescenceExitDrained(c.oldExit) ||
		(c.next != nil && unstarted != nil) ||
		(c.next == nil) != (c.nextIdentity == nil) || (c.next == nil) != (c.nextExit == nil) {
		return zero, errLifecycleUnsafe
	}
	if c.next != nil && (c.next == c.old || !labQuiescenceIdentityValid(*c.nextIdentity) ||
		(*c.nextIdentity == c.oldIdentity) || !labQuiescenceExitDrained(*c.nextExit)) {
		return zero, errLifecycleUnsafe
	}
	if !labRecoveryCleanupProbesValid(c.probes, c.oldIdentity, c.observedAt) ||
		!labRecoveryCleanupKernelCurrent(c.old, c.oldExit, c.oldStdoutSHA256, c.oldStderrSHA256, c.oldStdoutBytes, c.oldStderrBytes) {
		return zero, errLifecycleUnsafe
	}
	if c.next != nil && !labRecoveryCleanupKernelCurrent(c.next, *c.nextExit, c.nextStdoutSHA256, c.nextStderrSHA256, c.nextStdoutBytes, c.nextStderrBytes) {
		return zero, errLifecycleUnsafe
	}
	if unstarted != nil && unstarted.consumeRecoveryUnstartedCleanup(c, c.operation, c.attempt, now) != nil {
		return zero, errLifecycleUnsafe
	}

	fact := lifecycleRecoveryCleanupFact{Schema: lifecycleRecoveryCleanupSchema, RecoveryID: pc.recoveryID,
		FailureCode: c.failureCode, Old: lifecycleRecoveryCleanedKernel{Identity: c.oldIdentity, Exit: labQuiescenceCloneExit(c.oldExit)},
		SourceReceiptSHA256: c.digest, ObservedAt: c.observedAt}
	if c.attempt != nil {
		attempt := labRecoveryStartedCloneObservation(*c.attempt)
		fact.Attempt = &attempt
	}
	if c.next != nil {
		next := lifecycleRecoveryCleanedKernel{Identity: *c.nextIdentity, Exit: labQuiescenceCloneExit(*c.nextExit)}
		fact.New = &next
	}
	fact.Probes = make([]lifecycleRecoveryCleanupProbe, len(c.probes))
	for index, probe := range c.probes {
		fact.Probes[index] = lifecycleRecoveryCleanupProbe{Role: probe.Role, Probe: probe.Probe, ObservedAt: probe.ObservedAt}
	}
	var err error
	fact.CleanupSHA256, err = lifecycleRecoveryCleanupHash(fact)
	if err != nil || !lifecycleNonzeroHash(fact.CleanupSHA256) {
		return zero, errLifecycleUnsafe
	}
	return fact, nil
}

func (c *labRecoveryUnstartedCleanupCustody) consumeRecoveryUnstartedCleanup(parent *labRecoveryCleanupCustody,
	op *labRecoveryOperation, attempt *labRecoveryStartObservation, now time.Time) error {
	if c == nil || parent == nil || op == nil || attempt == nil || attempt.StartObservation == nil || !c.used ||
		c.issuer != parent.issuer || c.parent != parent || c.operation != op || c.service != parent.service ||
		c.kernel == nil || c.binding == nil || !lifecycleTime(now) || !lifecycleTime(c.observedAt) || now.Before(c.observedAt) ||
		!reflect.DeepEqual(*attempt.StartObservation, c.observation) || !c.binding(c, parent, op) {
		return errLifecycleUnsafe
	}
	v := c.observation
	if v.Started == nil || *v.Started || v.PID != nil || v.StartTicks != nil || v.WaitReturned == nil || *v.WaitReturned ||
		v.WaitErrorClass != "NOT_WAITED" || v.ExitCode != nil || v.Signal != nil || v.TermSent != nil || v.KillSent != nil || v.GroupAbsent != nil ||
		(v.Stdout == nil) != (v.Stderr == nil) || (v.Stdout != nil && (!reflect.DeepEqual(*v.Stdout, c.stdout) || !reflect.DeepEqual(*v.Stderr, c.stderr))) {
		return errLifecycleUnsafe
	}
	return nil
}

func labRecoveryCleanupKernelCurrent(core *ownedLabKernelCore, want labKernelExit, stdoutSHA, stderrSHA string, stdoutBytes, stderrBytes int) bool {
	if core == nil || !labQuiescenceExitDrained(want) || !lifecycleNonzeroHash(stdoutSHA) || !lifecycleNonzeroHash(stderrSHA) ||
		stdoutBytes < 0 || stdoutBytes > 64<<10 || stderrBytes < 0 || stderrBytes > 64<<10 {
		return false
	}
	actual, err := core.exitSnapshot()
	if (err != nil && err != errLabKernelStop) || !labQuiescenceExitDrained(actual) || !labQuiescenceExitEqual(actual, want) {
		return false
	}
	stdout, stderr, err := labServiceKernelStreams(&ownedLabKernel{core})
	return err == nil && len(stdout) == stdoutBytes && len(stderr) == stderrBytes &&
		labConfigHash(stdout) == stdoutSHA && labConfigHash(stderr) == stderrSHA &&
		labRecoveryCleanupStreamMatches(actual.Stdout, stdout) && labRecoveryCleanupStreamMatches(actual.Stderr, stderr)
}

func labRecoveryCleanupProbesValid(probes [4]labRecoveryCleanupProbe, old labKernelIdentity, observedAt time.Time) bool {
	roles := [4]string{"OLD_CONTROLLER", "OLD_MIXED", "NEW_CONTROLLER", "NEW_MIXED"}
	ports := [4]uint16{old.ControllerPort, old.MixedPort, old.ControllerPort, old.MixedPort}
	last := time.Time{}
	for index, value := range probes {
		if value.Role != roles[index] || !lifecycleTime(value.ObservedAt) || value.ObservedAt.After(observedAt) ||
			(!last.IsZero() && value.ObservedAt.Before(last)) || value.Probe.Port != ports[index] ||
			!value.Probe.Attempted || value.Probe.Result != "CONNECTION_REFUSED" {
			return false
		}
		last = value.ObservedAt
	}
	return true
}

func (c *labRecoveryAbsentStartCustody) consumeRecoveryAbsentStart(a *labRecoveryAbsenceCustodyCore, now time.Time) error {
	if c == nil || c.issuer == nil {
		return errLifecycleUnsafe
	}
	i := c.issuer
	i.mu.Lock()
	if c.used || i.issued == nil || !i.issued[c] {
		i.mu.Unlock()
		return errLifecycleUnsafe
	}
	delete(i.issued, c)
	c.used = true
	i.mu.Unlock()
	if a == nil || a.binding == nil || !a.binding(a) || c.binding == nil || !c.binding(c) ||
		!lifecycleTime(now) || !lifecycleTime(c.observedAt) || now.Before(c.observedAt) ||
		c.service == nil || c.runtime == nil || c.store == nil || c.disk == nil || c.owner == nil || c.reentry == nil ||
		a.service != c.service || a.runtime != c.runtime || a.store != c.store || a.reentry != c.reentry ||
		a.disk == nil || !lifecycleRecoverySameDisk(a.disk, c.disk) || !lifecycleRecoverySameDisk(c.store.disk, c.disk) ||
		c.runtime.disk != c.disk || a.cleanupSHA != c.cleanupSHA || a.terminalRoot != c.terminalRoot ||
		a.terminalCanonical != c.terminalCanonical || a.planSHA != c.planSHA || a.recoveryID != c.recoveryID ||
		a.oldIdentity != c.oldIdentity || !labQuiescenceIdentityValid(c.oldIdentity) ||
		a.ownerNonce != c.owner.nonce || a.ownerFence != c.owner.fence || !lifecycleNonzeroHash(c.cleanupSHA) ||
		!lifecycleNonzeroHash(c.terminalRoot) || len(c.terminalCanonical) == 0 || !lifecycleNonzeroHash(c.planSHA) ||
		!labRecoveryID.MatchString(c.recoveryID) {
		return errLifecycleUnsafe
	}
	roles := [2]string{"CONTROLLER", "MIXED"}
	ports := [2]uint16{28412, 28411}
	last := time.Time{}
	for index, probe := range c.probes {
		if probe.Role != roles[index] || !lifecycleTime(probe.ObservedAt) || probe.ObservedAt.After(c.observedAt) ||
			(!last.IsZero() && probe.ObservedAt.Before(last)) || probe.Probe.Port != ports[index] ||
			!probe.Probe.Attempted || probe.Probe.Result != "CONNECTION_REFUSED" {
			return errLifecycleUnsafe
		}
		last = probe.ObservedAt
	}
	return nil
}

func (c *labRecoveryAbsentReentryCustody) consumeRecoveryAbsentReentry(a *labRecoveryAbsenceCustodyCore, now time.Time) error {
	if c == nil || c.issuer == nil {
		return errLifecycleUnsafe
	}
	i := c.issuer
	i.mu.Lock()
	if c.used || i.issued == nil || !i.issued[c] {
		i.mu.Unlock()
		return errLifecycleUnsafe
	}
	delete(i.issued, c)
	c.used = true
	i.mu.Unlock()
	if a == nil || a.binding == nil || !a.binding(a) || c.binding == nil || !c.binding(c) || !lifecycleTime(now) ||
		c.operation == nil || c.service == nil || c.runtime == nil || c.store == nil || c.disk == nil || c.owner == nil ||
		c.reentry == nil || c.sourceCleanup == nil || a.service != c.service || a.runtime != c.runtime || a.store != c.store ||
		a.reentry != c.reentry || a.disk == nil || !lifecycleRecoverySameDisk(a.disk, c.disk) || !lifecycleRecoverySameDisk(c.store.disk, c.disk) ||
		c.runtime.disk != c.disk || a.cleanupSHA != c.cleanupSHA || a.terminalRoot != c.terminalRoot ||
		a.terminalCanonical != c.terminalCanonical || a.planSHA != c.planSHA || a.recoveryID != c.recoveryID ||
		a.ownerNonce != c.owner.nonce || a.ownerFence != c.owner.fence || a.oldIdentity != c.oldIdentity ||
		!labQuiescenceIdentityValid(c.oldIdentity) || !lifecycleNonzeroHash(c.cleanupSHA) || !lifecycleNonzeroHash(c.terminalRoot) ||
		len(c.terminalCanonical) == 0 || !lifecycleNonzeroHash(c.planSHA) || !labRecoveryID.MatchString(c.recoveryID) {
		return errLifecycleUnsafe
	}
	return nil
}

func (c *labRecoveryLiveReentryCustody) consumeRecoveryLiveReentry(runtime *labLifecycleRuntime, store *lifecycleRecoveryStore, owner *lifecycleRecoveryOwnerToken, now time.Time) (*labRecoveryTerminalReentryPermit, error) {
	if c == nil || c.issuer == nil {
		return nil, errLifecycleUnsafe
	}
	i := c.issuer
	i.mu.Lock()
	if c.used || i.issued == nil || !i.issued[c] {
		i.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	delete(i.issued, c)
	c.used = true
	i.mu.Unlock()
	if c.binding == nil || !c.binding(c) || runtime == nil || runtime.core == nil || runtime.core != c.runtime ||
		store == nil || store.core == nil || store.core != c.store || owner == nil || owner.core == nil || owner.core != c.owner ||
		c.service == nil || c.kernel == nil || c.disk == nil || !lifecycleTime(now) || !labRecoveryID.MatchString(c.recoveryID) {
		return nil, errLifecycleUnsafe
	}
	currentIdentity, err := (&ownedLabKernel{c.kernel}).identity()
	if err != nil || currentIdentity != c.identity || !labQuiescenceIdentityValid(currentIdentity) {
		return nil, errLifecycleUnsafe
	}
	r := runtime.core
	r.mu.Lock()
	defer r.mu.Unlock()
	x := store.core
	x.mu.Lock()
	defer x.mu.Unlock()
	if r.closed || r.poisoned || r.recovery != store || r.store != nil || r.current != nil || r.disk != c.disk ||
		c.service.runtime == nil || c.service.runtime.core != r || c.service.kernel == nil || c.service.kernel.ownedLabKernelCore != c.kernel ||
		!lifecycleRecoverySameDisk(r.disk, x.disk) || x.closed || x.poisoned || x.terminalReentry != nil ||
		x.token(owner, true, now) != nil || x.record.core == nil || x.record.core.Recovery == nil ||
		x.record.core.Recovery.Phase != "REVOKED_UNSTARTED" || x.record.core.Recovery.Plan.RecoveryID != c.recoveryID ||
		!lifecycleRecoveryIdentityMatches(c.identity, x.record.core.Current.Head) || x.record.core.LastRecoveryFence != owner.core.fence ||
		x.record.core.RecordSHA256 == "" || len(x.raw) == 0 || x.verify() != nil {
		return nil, errLifecycleUnsafe
	}
	terminalPlan, terminalRoot, terminalCanonical, fence := x.record.core.Recovery.Plan.PlanSHA256, x.record.core.RecordSHA256, string(x.raw), x.record.core.LastRecoveryFence
	p := &labRecoveryTerminalReentryPermitCore{runtime: r, service: c.service, store: x, disk: x.disk,
		terminalPlan: terminalPlan, terminalRoot: terminalRoot, terminalCanonical: terminalCanonical, fence: fence}
	runtimeCore, serviceCore, storeCore, disk := r, c.service, x, x.disk
	p.binding = func(candidate *labRecoveryTerminalReentryPermitCore) bool {
		return candidate == p && candidate.runtime == runtimeCore && candidate.service == serviceCore && candidate.store == storeCore &&
			candidate.terminalPlan == terminalPlan && candidate.terminalRoot == terminalRoot && candidate.terminalCanonical == terminalCanonical &&
			candidate.cleanupSHA == "" && candidate.fence == fence && lifecycleRecoverySameDisk(candidate.disk, disk)
	}
	x.terminalReentry = p
	return &labRecoveryTerminalReentryPermit{core: p}, nil
}
