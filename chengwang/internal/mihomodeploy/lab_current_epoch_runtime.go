package mihomodeploy

import "time"

// The caller owns the service's close/busy exclusion while rebinding. Runtime
// registers the facade before returning it, so any subsequent service failure
// retains one cleanup owner for both the facade and the underlying real disk.
func (r *labLifecycleRuntime) adoptCurrentEpoch(h *lifecycleRecoveryCurrentHandoff, recovery *lifecycleRecoveryStore) (*lifecycleStore, *lifecycleOwnerToken, error) {
	if r == nil || r.core == nil || recovery == nil || recovery.core == nil {
		return nil, nil, errLifecycleUnsafe
	}
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned || c.store != nil || c.current != nil || c.recovery != recovery ||
		!lifecycleRecoverySameDisk(c.disk, recovery.core.disk) {
		return nil, nil, errLifecycleUnsafe
	}
	s, owner, err := adoptLifecycleCurrentEpoch(h, recovery)
	if err != nil {
		return nil, nil, err
	}
	c.current = s
	return s, owner, nil
}

// beginNextRecovery pairs the durable V2 recovery begin with retirement of the
// exact ordinary facade registered by the preceding Completion. It mints no
// authority and never closes the shared real disk, which remains owned by the
// recovery runtime. The caller owns service close/busy exclusion.
func (r *labLifecycleRuntime) beginNextRecovery(current *lifecycleStore, recovery *lifecycleRecoveryStore, owner *lifecycleRecoveryOwnerToken, plan *labRecoveryPlan, expectedRevision uint64, expectedRecordSHA256 string, now time.Time) error {
	if r == nil || r.core == nil || current == nil || recovery == nil || recovery.core == nil || owner == nil || plan == nil {
		return errLifecycleUnsafe
	}
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned || c.store != nil || c.current != current || c.recovery != recovery ||
		!lifecycleRecoverySameDisk(c.disk, recovery.core.disk) || current.lifecycleStoreCore == nil || current.currentEpoch == nil {
		return errLifecycleUnsafe
	}
	if err := recovery.beginRecovery(owner, plan, expectedRevision, expectedRecordSHA256, now); err != nil {
		return err
	}
	// beginRecovery(v2) has already cleared currentLive. close now invalidates
	// the exact facade/token without closing recovery's shared disk owner.
	if err := current.close(); err != nil {
		c.poisoned = true
		return err
	}
	c.current = nil
	return nil
}

// beginRecoveryWithoutCurrent covers only an unstarted, revoked first recovery:
// no Completion ever issued a current facade, so there is nothing to close or
// reconstruct. A later recovered epoch is v2 and deliberately remains rejected
// here until the core owns a typed terminal-reconciliation contract; D must not
// fabricate currentLive or revive a consumed handoff.
func (r *labLifecycleRuntime) beginRecoveryWithoutCurrent(recovery *lifecycleRecoveryStore, owner *lifecycleRecoveryOwnerToken, plan *labRecoveryPlan, expectedRevision uint64, expectedRecordSHA256 string, now time.Time) error {
	if r == nil || r.core == nil || recovery == nil || recovery.core == nil || owner == nil || plan == nil || plan.core == nil ||
		plan.core.descriptor.Schema != labRecoveryPlanSchema {
		return errLifecycleUnsafe
	}
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned || c.store != nil || c.current != nil || c.recovery != recovery ||
		!lifecycleRecoverySameDisk(c.disk, recovery.core.disk) {
		return errLifecycleUnsafe
	}
	return recovery.beginRecovery(owner, plan, expectedRevision, expectedRecordSHA256, now)
}

// recoverySnapshot takes the established runtime -> recovery-store lock order.
// It never adopts a kernel, reconstructs an owner, or grants a write capability.
// present distinguishes a failed V3 read from an actual ordinary V2 runtime;
// failures cannot silently fall back to a retired legacy writer.
func (r *labLifecycleRuntime) recoverySnapshot() (record lifecycleV3Record, present bool, err error) {
	if r == nil || r.core == nil {
		return lifecycleV3Record{}, false, errLifecycleUnsafe
	}
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned {
		return lifecycleV3Record{}, true, errLifecycleUnsafe
	}
	if c.recovery == nil {
		return lifecycleV3Record{}, false, nil
	}
	if c.store != nil || c.recovery.core == nil || c.disk == nil {
		return lifecycleV3Record{}, true, errLifecycleUnsafe
	}
	x := c.recovery.core
	x.mu.Lock()
	defer x.mu.Unlock()
	if !lifecycleRecoverySameDisk(c.disk, x.disk) {
		return lifecycleV3Record{}, true, errLifecycleUnsafe
	}
	base, err := x.verifiedBase()
	if err != nil {
		return lifecycleV3Record{}, true, err
	}
	defer base.release()
	copy, err := base.copyRecord()
	return copy, true, err
}
