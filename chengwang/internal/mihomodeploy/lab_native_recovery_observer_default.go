//go:build !linux || !chengwang_mihomo_recovery_native

package mihomodeploy

// Normal builds retain no native-acceptance registry, counter or callback.
func labNativeRecoveryObserve(*ownedLabKernelCore, string) {}

func labNativeRecoveryObserveCancelKillAttempt(*ownedLabKernelCore)   {}
func labNativeRecoveryObserveCancelKillReturn(*ownedLabKernelCore)    {}
func labNativeRecoveryObserveIdentityKillAttempt(*ownedLabKernelCore) {}
func labNativeRecoveryObserveIdentityKillReturn(*ownedLabKernelCore)  {}
func labNativeRecoveryObserveStopKillAttempt(*ownedLabKernelCore)     {}
func labNativeRecoveryObserveStopKillReturn(*ownedLabKernelCore)      {}
