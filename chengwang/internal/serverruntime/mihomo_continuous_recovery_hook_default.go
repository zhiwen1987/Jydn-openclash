//go:build !linux || !chengwang_mihomo_service || !chengwang_mihomo_recovery_native || !chengwang_mihomo_recovery_continuous_fault || chengwang_mihomo_faults || chengwang_mihomo_completion_native

package serverruntime

// The ordinary product and every other laboratory tag selection have no
// observer. The exact continuous-Recovery experiment supplies the complement.
func bindLabContinuousRecoveryHarness(*MihomoLabRuntime) error { return nil }
