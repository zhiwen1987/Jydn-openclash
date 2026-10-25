package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

// MODEL HTTP boundary only. These values prove request routing/envelopes, not
// authentication, WAL mutation, owned kernel cleanup or recovery completion.
const recoveryAPIModelID = "labrec_22222222222222222222222222222222"

type recoveryAPIModelBackend struct {
	scope   authz.ResourceScope
	view    mihomodeploy.LabRecoveryView
	err     error
	action  string
	headers []string
	id      string
}

func newRecoveryAPIModel(scope authz.ResourceScope) *recoveryAPIModelBackend {
	return &recoveryAPIModelBackend{scope: scope, view: mihomodeploy.LabRecoveryView{
		Schema: mihomodeploy.LabRecoveryViewSchema, Boundary: mihomodeploy.LabBackendBoundary,
		RecoveryID: recoveryAPIModelID, Phase: "PLANNED", Revision: 7,
		PlanSHA256: labAPIModelHash("b"), UnknownOperationID: labAPIModelID,
		OriginalPlanSHA256: labAPIModelHash("a"), PreviousHeadSHA256: labAPIModelHash("c"),
		HeadSHA256: labAPIModelHash("c"), HeadGeneration: 3,
		TargetArtifactRecordSHA256: labAPIModelHash("d"), TargetConfigSHA256: labAPIModelHash("e"),
		ExpiresAt: time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC), Proof: mihomodeploy.LabProofView{},
	}}
}

func (b *recoveryAPIModelBackend) Scope() authz.ResourceScope { return b.scope }
func (b *recoveryAPIModelBackend) record(action, id string, headers []string) {
	b.action, b.id, b.headers = action, id, append([]string(nil), headers...)
}
func (b *recoveryAPIModelBackend) Create(_ context.Context, h []string, _ mihomodeploy.LabRecoveryCreateRequest) (mihomodeploy.LabRecoveryView, error) {
	b.record("create", "", h)
	return b.view, b.err
}
func (b *recoveryAPIModelBackend) Inspect(_ context.Context, h []string, id string) (mihomodeploy.LabRecoveryView, error) {
	b.record("inspect", id, h)
	return b.view, b.err
}
func (b *recoveryAPIModelBackend) Approve(_ context.Context, h []string, id string, _ mihomodeploy.LabRecoveryApprovalRequest) (mihomodeploy.LabRecoveryView, error) {
	b.record("approve", id, h)
	return b.view, b.err
}
func (b *recoveryAPIModelBackend) Execute(_ context.Context, h []string, id string, _ mihomodeploy.LabRecoveryExecuteRequest) (mihomodeploy.LabRecoveryView, error) {
	b.record("execute", id, h)
	return b.view, b.err
}
func (b *recoveryAPIModelBackend) Revoke(_ context.Context, h []string, id string, _ mihomodeploy.LabRecoveryRevokeRequest) (mihomodeploy.LabRecoveryView, error) {
	b.record("revoke", id, h)
	return b.view, b.err
}

func recoveryAPIModelHandler(b *recoveryAPIModelBackend) http.Handler {
	lab := newLabAPIModel()
	lab.scope = b.scope
	return New(Options{MihomoLab: lab, MihomoRecoveries: b, MihomoRecoveryWritesEnabled: true})
}

func recoveryAPICreateBody() string {
	return `{"unknownOperationId":"` + labAPIModelID + `","originalPlanSHA256":"` + labAPIModelHash("a") + `","revision":7,"ttlSeconds":60}`
}
func recoveryAPICASBody() string {
	return `{"planSHA256":"` + labAPIModelHash("b") + `","revision":7}`
}
func recoveryAPIRevokeBody() string {
	return `{"planSHA256":"` + labAPIModelHash("b") + `","revision":7,"reason":"SAFETY_STOP"}`
}

func TestMihomoRecoveryAPIMutatingSuccessAndReplayAlwaysReportChangedMODEL(t *testing.T) {
	scope := newLabAPIModel().scope
	for _, replayed := range []bool{false, true} {
		for _, tc := range []struct {
			path, body, action string
			status             int
		}{
			{mihomoRecoveryPrefix, recoveryAPICreateBody(), "create", http.StatusCreated},
			{mihomoRecoveryPrefix + "/" + recoveryAPIModelID + "/approvals", recoveryAPICASBody(), "approve", http.StatusOK},
			{mihomoRecoveryPrefix + "/" + recoveryAPIModelID + "/execute", recoveryAPICASBody(), "execute", http.StatusOK},
			{mihomoRecoveryPrefix + "/" + recoveryAPIModelID + "/revocations", recoveryAPIRevokeBody(), "revoke", http.StatusOK},
		} {
			backend := newRecoveryAPIModel(scope)
			backend.view.Replayed = replayed
			response := labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodPost, tc.path, tc.body))
			if response.Code != tc.status || backend.action != tc.action || len(backend.headers) != 1 || backend.headers[0] != labAPIModelToken ||
				!strings.Contains(response.Body.String(), `"stateMayHaveChanged":true`) {
				t.Fatal("MODEL successful recovery mutation was reported as read-only or misrouted")
			}
		}
	}
}

func TestMihomoRecoveryAPIInspectRemainsReadOnlyAndFailureStatusIsStrictMODEL(t *testing.T) {
	backend := newRecoveryAPIModel(newLabAPIModel().scope)
	response := labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodGet, mihomoRecoveryPrefix+"/"+recoveryAPIModelID, ""))
	if response.Code != http.StatusOK || backend.action != "inspect" || !strings.Contains(response.Body.String(), `"stateMayHaveChanged":false`) {
		t.Fatal("MODEL Inspect did not remain read-only")
	}
	backend = newRecoveryAPIModel(newLabAPIModel().scope)
	backend.err = &mihomodeploy.LabBackendError{Code: mihomodeploy.LabBackendUnavailable, StateMayHaveChanged: true}
	response = labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodPost, mihomoRecoveryPrefix+"/"+recoveryAPIModelID+"/execute", recoveryAPICASBody()))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"stateMayHaveChanged":true`) {
		t.Fatal("MODEL physical mutation uncertainty was hidden")
	}
	backend = newRecoveryAPIModel(newLabAPIModel().scope)
	backend.err = &mihomodeploy.LabBackendError{Code: mihomodeploy.LabBackendConflict, StateMayHaveChanged: false}
	response = labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodPost, mihomoRecoveryPrefix+"/"+recoveryAPIModelID+"/approvals", recoveryAPICASBody()))
	if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), `"stateMayHaveChanged":true`) {
		t.Fatal("MODEL rejected precondition falsely reported mutation")
	}
}

func TestMihomoRecoveryAPIInspectExposesOnlyBoundedFailureExitMODEL(t *testing.T) {
	backend := newRecoveryAPIModel(newLabAPIModel().scope)
	backend.view.Phase = "RECOVERY_UNKNOWN"
	backend.view.WriteBlocked = true
	backend.view.Failure = &mihomodeploy.LabRecoveryFailureView{Schema: mihomodeploy.LabRecoveryFailureViewSchema,
		Code: "SERVICE_CONTEXT_CANCELLED", CleanupState: "SETTLED", CleanupSHA256: labAPIModelHash("f"),
		NextAction: "CORE_RECONCILIATION_REQUIRED"}
	response := labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodGet, mihomoRecoveryPrefix+"/"+recoveryAPIModelID, ""))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"cleanupState":"SETTLED"`) ||
		!strings.Contains(response.Body.String(), `"nextAction":"CORE_RECONCILIATION_REQUIRED"`) ||
		!strings.Contains(response.Body.String(), `"stateMayHaveChanged":false`) {
		t.Fatal("MODEL Inspect hid or expanded the bounded failure exit")
	}
	backend.view.Failure.CleanupSHA256 = ""
	response = labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodGet, mihomoRecoveryPrefix+"/"+recoveryAPIModelID, ""))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "SERVICE_CONTEXT_CANCELLED") {
		t.Fatal("MODEL invalid cleanup receipt escaped strict response validation")
	}
}

func TestMihomoRecoveryAPIInspectExposesReconciledFreshCreateExitMODEL(t *testing.T) {
	backend := newRecoveryAPIModel(newLabAPIModel().scope)
	backend.view.Phase = "FAILED_RECONCILED"
	backend.view.WriteBlocked = false
	backend.view.Failure = &mihomodeploy.LabRecoveryFailureView{Schema: mihomodeploy.LabRecoveryFailureViewSchema,
		Code: "START_UNCERTAIN", CleanupState: "SETTLED", CleanupSHA256: labAPIModelHash("c"), NextAction: "CREATE_RECOVERY"}
	response := labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodGet, mihomoRecoveryPrefix+"/"+recoveryAPIModelID, ""))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"phase":"FAILED_RECONCILED"`) ||
		!strings.Contains(response.Body.String(), `"nextAction":"CREATE_RECOVERY"`) ||
		!strings.Contains(response.Body.String(), `"stateMayHaveChanged":false`) {
		t.Fatal("MODEL reconciled failure did not expose the bounded fresh Create exit")
	}
	backend.view.Failure.NextAction = "CORE_RECONCILIATION_REQUIRED"
	response = labAPICall(recoveryAPIModelHandler(backend), labAPIRequest(http.MethodGet, mihomoRecoveryPrefix+"/"+recoveryAPIModelID, ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("MODEL terminal phase accepted a pre-terminal next action")
	}
}
