//go:build !linux || !chengwang_mihomo_service || !chengwang_mihomo_recovery_native || !chengwang_mihomo_recovery_continuous_fault || chengwang_mihomo_faults || chengwang_mihomo_completion_native

package serverruntime

import (
	"time"

	"chengwang/internal/authn"
)

func claimLabContinuousRecoveryCredentials(Config, time.Time) (*authn.Store, *authn.SnapshotManager, bool, error) {
	return nil, nil, false, nil
}

// The ordinary product and every other laboratory tag selection have no
// observer. The exact continuous-Recovery experiment supplies the complement.
func bindLabContinuousRecoveryHarness(*MihomoLabRuntime, *authn.Store) error { return nil }
