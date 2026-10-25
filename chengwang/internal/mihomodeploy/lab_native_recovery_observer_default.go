//go:build !linux || !chengwang_mihomo_recovery_native

package mihomodeploy

// Normal builds retain no native-acceptance registry, counter or callback.
func labNativeRecoveryObserve(*ownedLabKernelCore, string) {}
