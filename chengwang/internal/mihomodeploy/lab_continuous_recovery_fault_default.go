//go:build !linux || !chengwang_mihomo_recovery_continuous_fault || !chengwang_mihomo_recovery_native

package mihomodeploy

import "chengwang/internal/adapter/mihomo"

// Ordinary builds retain the exact no-fault execution path. These hooks own no
// registry, counter, callback or transport capability.
func labContinuousRecoveryBeforeReload(*labServiceCore, *mihomo.WriteClient, *PreparedReload, string, string) error {
	return nil
}

func labContinuousRecoveryAfterReload(*labServiceCore, *mihomo.WriteClient, *PreparedReload, string, string, mihomo.ReloadResult) {
}
