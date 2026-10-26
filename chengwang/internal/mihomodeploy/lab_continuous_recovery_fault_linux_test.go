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
	t.Run("create-stage-is-exact-bounded-diagnostic-only", func(t *testing.T) {
		service := &labServiceCore{}
		foreign := &labServiceCore{}
		core := &labContinuousRecoveryFaultCore{service: service, recoveryCreatesBounded: true}
		core.identity = core
		diagnostic := &processLabContinuousRecoveryCreateDiagnostic
		diagnostic.mu.Lock()
		previous := diagnostic.core
		diagnostic.core = core
		diagnostic.mu.Unlock()
		t.Cleanup(func() {
			diagnostic.mu.Lock()
			diagnostic.core = previous
			diagnostic.mu.Unlock()
		})
		labContinuousRecoveryRecoveryCreateStage(foreign, "ENTERED")
		labContinuousRecoveryRecoveryCreateStage(service, "ENTERED")
		labContinuousRecoveryRecoveryCreateStage(service, "ACCEPTED")
		diagnostic.mu.Lock()
		got := append([]LabContinuousRecoveryCreateStage(nil), core.recoveryCreates...)
		bounded := core.recoveryCreatesBounded
		diagnostic.mu.Unlock()
		if !bounded || len(got) != 2 || got[0].Sequence != 1 || got[0].Stage != "ENTERED" ||
			got[1].Sequence != 2 || got[1].Stage != "ACCEPTED" {
			t.Fatal("MODEL create-stage diagnostic lost exact source binding")
		}
		labContinuousRecoveryRecoveryCreateStage(service, "dynamic-error-text")
		diagnostic.mu.Lock()
		bounded = core.recoveryCreatesBounded
		diagnostic.mu.Unlock()
		if bounded {
			t.Fatal("MODEL dynamic create-stage diagnostic was accepted")
		}
	})
}
