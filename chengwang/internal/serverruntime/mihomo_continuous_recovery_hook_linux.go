//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native

package serverruntime

import (
	"errors"
	"sync"

	"chengwang/internal/mihomodeploy"
)

var errLabContinuousRecoveryHarness = errors.New("isolated continuous recovery harness unavailable")

type labContinuousRecoveryHarnessResult struct {
	handle *mihomodeploy.LabContinuousRecoveryFaultHandle
	err    error
}

var processLabContinuousRecoveryHarness = struct {
	sync.Mutex
	armed    bool
	consumed bool
	result   chan labContinuousRecoveryHarnessResult
}{}

// armLabContinuousRecoveryHarness is process-local and one-way. It has no
// reset, environment, HTTP, Options or serialized-capability input.
func armLabContinuousRecoveryHarness() (<-chan labContinuousRecoveryHarnessResult, error) {
	i := &processLabContinuousRecoveryHarness
	i.Lock()
	defer i.Unlock()
	if i.armed || i.consumed || i.result != nil {
		return nil, errLabContinuousRecoveryHarness
	}
	i.armed = true
	i.result = make(chan labContinuousRecoveryHarnessResult, 1)
	return i.result, nil
}

// RunWith calls this after it has installed the actual runtime cleanup owner,
// but before it publishes a handler or listener. An unarmed exact-tag build is
// a no-op so unrelated tests under the same positive tags remain independent.
func bindLabContinuousRecoveryHarness(runtime *MihomoLabRuntime) error {
	i := &processLabContinuousRecoveryHarness
	i.Lock()
	if !i.armed {
		i.Unlock()
		return nil
	}
	if i.consumed || i.result == nil {
		i.Unlock()
		return errLabContinuousRecoveryHarness
	}
	i.consumed = true
	result := i.result
	i.Unlock()

	if runtime == nil || runtime.core == nil {
		err := errLabContinuousRecoveryHarness
		result <- labContinuousRecoveryHarnessResult{err: err}
		return err
	}
	c := runtime.core
	c.mu.Lock()
	service := c.service
	valid := c.ready && c.writable && !c.closing && !c.closed && service != nil
	c.mu.Unlock()
	if !valid {
		err := errLabContinuousRecoveryHarness
		result <- labContinuousRecoveryHarnessResult{err: err}
		return err
	}
	handle, err := mihomodeploy.BeginLabContinuousRecoveryResponseLoss(service)
	if err != nil || handle == nil {
		if err == nil {
			err = errLabContinuousRecoveryHarness
		}
		result <- labContinuousRecoveryHarnessResult{err: err}
		return err
	}
	result <- labContinuousRecoveryHarnessResult{handle: handle}
	return nil
}
