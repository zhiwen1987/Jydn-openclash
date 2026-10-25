//go:build linux && chengwang_mihomo_recovery_native

package mihomodeploy

import (
	"encoding/json"
	"sync"
	"time"
)

// Observations are diagnostics only: no callback, no error return, no reset,
// no authority and no way to redirect an OS call. Exact source callsites emit
// helper dispatch and OS-attempt observations; the test only reads snapshots.
// Core numbers are local labels for original core pointers, never PID authority.
type labNativeRecoveryCall struct {
	Sequence int       `json:"sequence"`
	Kind     string    `json:"kind"`
	Core     uint64    `json:"core"`
	At       time.Time `json:"at"`
}

type labNativeRecoveryEventCheckpoint struct {
	Stage        string `json:"stage"`
	Count        int    `json:"count"`
	LastSequence int    `json:"lastSequence"`
	EventsSHA256 string `json:"eventsSHA256"`
}

// Digest is over the actual immutable snapshot's Go JSON bytes, with struct
// order sequence/kind/core/at. It is an evidence association, never authority.
func labNativeRecoveryEventSnapshot(stage string) ([]labNativeRecoveryCall, labNativeRecoveryEventCheckpoint, error) {
	var zero labNativeRecoveryEventCheckpoint
	known := false
	for _, name := range []string{"before-permit-cap-replay", "after-permit-cap-replay", "before-runner-replay", "after-runner-replay",
		"before-cleanup", "after-cleanup", "before-cleanup-replay", "after-cleanup-replay", "before-reopen", "after-reopen"} {
		if stage == name {
			known = true
		}
	}
	events, bounded := labNativeRecoveryReadCalls()
	if !known || !bounded || len(events) > 256 {
		return nil, zero, errLabKernelInput
	}
	last := 0
	for i, e := range events {
		if e.Sequence != i+1 {
			return nil, zero, errLabKernelInput
		}
		last = e.Sequence
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return nil, zero, errLabKernelInput
	}
	return events, labNativeRecoveryEventCheckpoint{stage, len(events), last, labConfigHash(raw)}, nil
}

type labNativeRecoveryCalls struct {
	mu       sync.Mutex
	cores    map[*ownedLabKernelCore]uint64
	events   []labNativeRecoveryCall
	overflow bool
}

var processLabNativeRecoveryCalls = labNativeRecoveryCalls{
	cores:  map[*ownedLabKernelCore]uint64{},
	events: []labNativeRecoveryCall{},
}

func labNativeRecoveryObserve(core *ownedLabKernelCore, kind string) {
	c := &processLabNativeRecoveryCalls
	c.mu.Lock()
	defer c.mu.Unlock()
	known := false
	for _, name := range []string{"KERNEL_OS_START_ATTEMPT", "KERNEL_OS_START_RETURN", "KERNEL_OS_WAIT_ENTER", "KERNEL_OS_WAIT_RETURN",
		"OWNED_STOP_HELPER_ENTER", "KERNEL_OS_TERM_ATTEMPT", "KERNEL_OS_TERM_RETURN", "KERNEL_OS_KILL_ATTEMPT", "KERNEL_OS_KILL_RETURN",
		"RECOVERY_STOP_DISPATCH", "RECOVERY_START_DISPATCH", "SYNTAX_OS_START_ATTEMPT", "SYNTAX_OS_START_RETURN"} {
		if kind == name {
			known = true
		}
	}
	if !known || len(c.events) >= 256 || (core != nil && c.cores[core] == 0 && len(c.cores) >= 4) {
		c.overflow = true
		return
	}
	var id uint64
	if core != nil {
		id = c.cores[core]
		if id == 0 {
			id = uint64(len(c.cores) + 1)
			c.cores[core] = id
		}
	}
	c.events = append(c.events, labNativeRecoveryCall{len(c.events) + 1, kind, id, time.Now().UTC()})
}

func labNativeRecoveryReadCalls() ([]labNativeRecoveryCall, bool) {
	c := &processLabNativeRecoveryCalls
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]labNativeRecoveryCall{}, c.events...), !c.overflow
}

// Lookup never creates an entry or increments a counter. It associates the
// original retained handle with the label emitted by the actual OS callsite.
func labNativeRecoveryReadCore(k *ownedLabKernel) (uint64, bool) {
	if k == nil || k.ownedLabKernelCore == nil {
		return 0, false
	}
	c := &processLabNativeRecoveryCalls
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.cores[k.ownedLabKernelCore]
	return id, id != 0 && !c.overflow
}
