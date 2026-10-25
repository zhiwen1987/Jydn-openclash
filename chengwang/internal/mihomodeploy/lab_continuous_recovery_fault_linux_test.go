//go:build linux && chengwang_mihomo_recovery_continuous_fault && chengwang_mihomo_recovery_native

package mihomodeploy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLabContinuousRecoveryFaultZeroAndDebugRemainNonAuthorityMODEL(t *testing.T) {
	var zero LabContinuousRecoveryFaultHandle
	raw, err := json.Marshal(zero)
	if err != nil || string(raw) != `{"scope":"PRIVATE_CONTINUOUS_RECOVERY_FAULT_NOT_AUTHORIZATION"}` {
		t.Fatal("MODEL zero debug JSON changed")
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", zero, zero, zero)
	if strings.Contains(formatted, "127.0.0.1") || strings.Contains(formatted, "28412") || strings.Contains(formatted, "nonce") {
		t.Fatal("MODEL debug formatting leaked private state")
	}
	if _, err := BeginLabContinuousRecoveryResponseLoss(nil); err == nil {
		t.Fatal("MODEL nil service issued schedule")
	}
	if _, err := zero.Observe(); err == nil || zero.Close() == nil {
		t.Fatal("MODEL zero handle became usable")
	}
	if json.Unmarshal([]byte(`{"scope":"PRIVATE_CONTINUOUS_RECOVERY_FAULT_NOT_AUTHORIZATION"}`), &zero) == nil {
		t.Fatal("MODEL JSON reconstructed schedule")
	}
}
