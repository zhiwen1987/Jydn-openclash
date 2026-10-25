package mihomodeploy

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
