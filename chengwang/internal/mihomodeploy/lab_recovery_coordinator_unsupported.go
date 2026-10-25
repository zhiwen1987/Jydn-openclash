//go:build !linux

package mihomodeploy

import "context"

func (c *labRecoveryCoordinator) executePlatform(context.Context, []string, *labRecoveryOperation) (LabRecoveryView, error) {
	return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
}

func (c *labRecoveryCoordinator) settlePlatformFailure(op *labRecoveryOperation, _ []string) *LabRecoveryFailureView {
	code := "START_UNCERTAIN"
	if op != nil && op.failureCode != "" {
		code = op.failureCode
	}
	return &LabRecoveryFailureView{Schema: LabRecoveryFailureViewSchema, Code: code,
		CleanupState: "PENDING", NextAction: "CLOSE_REQUIRED"}
}

func (c *labRecoveryCoordinator) retryPlatformReconciliation(_ []string, _ labRecoveryCheck, op *labRecoveryOperation) error {
	if c != nil && c.service != nil && c.service.core != nil && op != nil {
		c.service.core.mu.Lock()
		op.reconcileState = labRecoveryReconcileLocked
		c.service.core.mu.Unlock()
	}
	return errLifecycleUnsafe
}
