//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native

package serverruntime

// This opt-in test uses one actual RunWith listener, normal TLS, the private
// identity file, the real API/backend/service/runtime/disk chain and the fixed
// source-owned LOSS/PASS/LOSS schedule. It is not production evidence.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

const continuousRecoveryReportPath = labServiceE2EPrivate + "/continuous-recovery-report.private.json"

type continuousRecoveryHTTPOriginal struct {
	Sequence           int    `json:"sequence"`
	Case               string `json:"case"`
	Role               string `json:"role"`
	Method             string `json:"method"`
	Path               string `json:"path"`
	RequestBodySHA256  string `json:"requestBodySHA256"`
	StatusCode         *int   `json:"statusCode"`
	ResponseBodySHA256 string `json:"responseBodySHA256"`
	ResponseBodyB64    []byte `json:"responseBodyB64"`
	ErrorClass         string `json:"errorClass"`
}

type continuousRecoveryHeadState struct {
	Stage string                   `json:"stage"`
	View  mihomodeploy.LabHeadView `json:"view"`
}

type continuousRecoveryOperationState struct {
	Stage string                         `json:"stage"`
	View  mihomodeploy.LabDeploymentView `json:"view"`
}

type continuousRecoveryRecoveryState struct {
	Stage string                       `json:"stage"`
	View  mihomodeploy.LabRecoveryView `json:"view"`
}

type continuousRecoveryReport struct {
	Schema                  string                                              `json:"schema"`
	Scope                   string                                              `json:"scope"`
	SourceCommit            string                                              `json:"sourceCommit"`
	Outcome                 string                                              `json:"outcome"`
	FailureCode             string                                              `json:"failureCode"`
	HTTP                    []continuousRecoveryHTTPOriginal                    `json:"http"`
	Initial                 *mihomodeploy.LabAcceptanceState                    `json:"initial"`
	Heads                   []continuousRecoveryHeadState                       `json:"heads"`
	Operations              []continuousRecoveryOperationState                  `json:"operations"`
	Recoveries              []continuousRecoveryRecoveryState                   `json:"recoveries"`
	CallsBefore             mihomo.ReloadCounters                               `json:"callsBefore"`
	CallsAfter              mihomo.ReloadCounters                               `json:"callsAfter"`
	FaultBeforeCleanup      *mihomodeploy.LabContinuousRecoveryFaultObservation `json:"faultBeforeCleanup"`
	FaultAfterCleanup       *mihomodeploy.LabContinuousRecoveryFaultObservation `json:"faultAfterCleanup"`
	FaultClosed             *mihomodeploy.LabContinuousRecoveryFaultObservation `json:"faultClosed"`
	ClosedPorts             []serviceClosedPort                                 `json:"closedPorts"`
	RuntimeReturned         bool                                                `json:"runtimeReturned"`
	RuntimeErrorClass       string                                              `json:"runtimeErrorClass"`
	PrivateWALDecodedByTest bool                                                `json:"privateWALDecodedByTest"`
	Production              bool                                                `json:"production"`
	FullPayloadProven       bool                                                `json:"fullPayloadProven"`
	InternetBusinessProven  bool                                                `json:"internetBusinessProven"`
}

type continuousRecoveryHTTPS struct {
	t      *testing.T
	base   string
	client *http.Client
	tokens map[string]string
	report *continuousRecoveryReport
}

func continuousRecoveryHash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (h continuousRecoveryHTTPS) fail(code, message string) {
	h.t.Helper()
	h.report.FailureCode = code
	h.t.Fatal(message)
}

func (h continuousRecoveryHTTPS) call(name, role, method, path string, body any, want int, result any) {
	h.t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			h.fail("REQUEST_ENCODING", "continuous recovery request encoding failed")
		}
	}
	request, err := http.NewRequest(method, h.base+path, bytes.NewReader(payload))
	if err != nil {
		h.fail("REQUEST_BUILD", "continuous recovery HTTPS request failed")
	}
	if role != "anonymous" {
		token := h.tokens[role]
		if token == "" {
			h.fail("IDENTITY_INPUT", "continuous recovery role token missing")
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	row := continuousRecoveryHTTPOriginal{Sequence: len(h.report.HTTP) + 1, Case: name, Role: role,
		Method: method, Path: path, RequestBodySHA256: continuousRecoveryHash(payload), ErrorClass: "NONE"}
	response, err := h.client.Do(request)
	if err != nil {
		row.ErrorClass = "RESPONSE_NOT_OBSERVED"
		h.report.HTTP = append(h.report.HTTP, row)
		h.fail("HTTP_TRANSPORT", "continuous recovery HTTPS response not observed")
	}
	status := response.StatusCode
	row.StatusCode = &status
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	closeErr := response.Body.Close()
	row.ResponseBodySHA256 = continuousRecoveryHash(raw)
	row.ResponseBodyB64 = append([]byte(nil), raw...)
	if readErr != nil || closeErr != nil || len(raw) > 16<<10 || !json.Valid(raw) {
		row.ErrorClass = "BODY"
	}
	h.report.HTTP = append(h.report.HTTP, row)
	if row.ErrorClass != "NONE" || status != want {
		h.fail("HTTP_RESULT", "continuous recovery HTTPS result mismatch")
	}
	var envelope struct {
		Boundary            string          `json:"boundary"`
		Code                string          `json:"code"`
		StateMayHaveChanged bool            `json:"stateMayHaveChanged"`
		Result              json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Boundary != mihomodeploy.LabBackendBoundary ||
		envelope.Code != "mihomo_lab_ok" || envelope.StateMayHaveChanged != (method == http.MethodPost) ||
		len(envelope.Result) == 0 || result == nil || json.Unmarshal(envelope.Result, result) != nil {
		h.fail("HTTP_BODY", "continuous recovery HTTPS body rejected")
	}
}

func (h continuousRecoveryHTTPS) head(stage string) mihomodeploy.LabHeadView {
	h.t.Helper()
	var view mihomodeploy.LabHeadView
	h.call(stage+"_HEAD", "viewer", http.MethodGet, "/api/v1/lab/mihomo/head", nil, http.StatusOK, &view)
	h.report.Heads = append(h.report.Heads, continuousRecoveryHeadState{Stage: stage, View: view})
	return view
}

func (h continuousRecoveryHTTPS) candidate(stage string) mihomodeploy.LabCandidateView {
	h.t.Helper()
	var view mihomodeploy.LabCandidateListView
	h.call(stage+"_CANDIDATES", "viewer", http.MethodGet, "/api/v1/lab/mihomo/candidates", nil, http.StatusOK, &view)
	if view.WriteBlocked || len(view.Candidates) != 2 {
		h.fail("CANDIDATES", "continuous recovery candidates unavailable")
	}
	current := 0
	var next mihomodeploy.LabCandidateView
	for _, candidate := range view.Candidates {
		if candidate.IsCurrent {
			current++
		} else {
			next = candidate
		}
	}
	if current != 1 || len(next.RecordSHA256) != 64 {
		h.fail("CANDIDATES", "continuous recovery next candidate missing")
	}
	return next
}

func (h continuousRecoveryHTTPS) deploy(stage string, candidate mihomodeploy.LabCandidateView, expected mihomo.ReloadState) mihomodeploy.LabDeploymentView {
	h.t.Helper()
	prefix := "/api/v1/lab/mihomo/deployments"
	var planned mihomodeploy.LabDeploymentView
	h.call(stage+"_CREATE", "admin", http.MethodPost, prefix,
		mihomodeploy.LabCreateRequest{CandidateRecordSHA256: candidate.RecordSHA256, TTLSeconds: 300}, http.StatusCreated, &planned)
	if planned.Phase != "PLANNED" || planned.CandidateRecordSHA256 != candidate.RecordSHA256 || planned.Transport != nil {
		h.fail("DEPLOY_PLAN", "continuous recovery deployment plan mismatch")
	}
	var approved mihomodeploy.LabDeploymentView
	h.call(stage+"_APPROVE", "approver", http.MethodPost, prefix+"/"+planned.OperationID+"/approvals",
		mihomodeploy.LabApprovalRequest{PlanSHA256: planned.PlanSHA256, Revision: planned.Revision}, http.StatusOK, &approved)
	if approved.Phase != "APPROVED" || approved.PlanSHA256 != planned.PlanSHA256 || approved.Transport != nil {
		h.fail("DEPLOY_APPROVAL", "continuous recovery deployment approval mismatch")
	}
	var executed mihomodeploy.LabDeploymentView
	h.call(stage+"_EXECUTE", "admin", http.MethodPost, prefix+"/"+planned.OperationID+"/execute",
		mihomodeploy.LabExecuteRequest{PlanSHA256: approved.PlanSHA256, Revision: approved.Revision}, http.StatusOK, &executed)
	if executed.OperationID != planned.OperationID || executed.PlanSHA256 != planned.PlanSHA256 || executed.Transport == nil ||
		executed.Transport.Origin != "ADAPTER" || !executed.Transport.Result.Dispatched || executed.Transport.Result.State != expected {
		h.fail("DEPLOY_EXECUTE", "continuous recovery deployment transport mismatch")
	}
	if expected == mihomo.ReloadUnknown {
		if executed.Phase != "UNKNOWN" || !executed.WriteBlocked || executed.HeadAdvanced || executed.Transport.Result.StatusCode != 0 ||
			executed.Observation == nil || !executed.Observation.LocalRouteVerified || executed.Observation.Conclusion != mihomo.LabStableNewProjection {
			h.fail("DEPLOY_UNKNOWN", "continuous recovery UNKNOWN barrier mismatch")
		}
	} else if expected == mihomo.ReloadAcknowledged {
		if executed.Phase != "COMPLETED" || executed.WriteBlocked || !executed.HeadAdvanced || executed.Transport.Result.StatusCode != http.StatusNoContent ||
			executed.Observation == nil || !executed.Observation.LocalRouteVerified {
			h.fail("DEPLOY_ACK", "continuous recovery acknowledged deployment mismatch")
		}
	} else {
		h.fail("DEPLOY_STATE", "continuous recovery unexpected deployment state")
	}
	var inspected mihomodeploy.LabDeploymentView
	h.call(stage+"_INSPECT", "auditor", http.MethodGet, prefix+"/"+planned.OperationID, nil, http.StatusOK, &inspected)
	if inspected.OperationID != executed.OperationID || inspected.Phase != executed.Phase || inspected.Revision != executed.Revision ||
		inspected.PlanSHA256 != executed.PlanSHA256 || inspected.HeadSHA256 != executed.HeadSHA256 || inspected.HeadGeneration != executed.HeadGeneration {
		h.fail("DEPLOY_INSPECT", "continuous recovery deployment readback mismatch")
	}
	h.report.Operations = append(h.report.Operations, continuousRecoveryOperationState{Stage: stage, View: inspected})
	return inspected
}

func (h continuousRecoveryHTTPS) recover(stage string, unknown mihomodeploy.LabDeploymentView) mihomodeploy.LabRecoveryView {
	h.t.Helper()
	prefix := "/api/v1/lab/mihomo/recoveries"
	var planned mihomodeploy.LabRecoveryView
	h.call(stage+"_CREATE", "admin", http.MethodPost, prefix, mihomodeploy.LabRecoveryCreateRequest{
		UnknownOperationID: unknown.OperationID, OriginalPlanSHA256: unknown.PlanSHA256, Revision: unknown.Revision, TTLSeconds: 300,
	}, http.StatusCreated, &planned)
	if planned.Phase != "PLANNED" || planned.UnknownOperationID != unknown.OperationID ||
		planned.OriginalPlanSHA256 != unknown.PlanSHA256 || planned.HeadAdvanced || !planned.WriteBlocked {
		h.fail("RECOVERY_PLAN", "continuous recovery plan mismatch")
	}
	var inspected mihomodeploy.LabRecoveryView
	h.call(stage+"_INSPECT_PLANNED", "auditor", http.MethodGet, prefix+"/"+planned.RecoveryID, nil, http.StatusOK, &inspected)
	if inspected.RecoveryID != planned.RecoveryID || inspected.Phase != planned.Phase || inspected.Revision != planned.Revision ||
		inspected.PlanSHA256 != planned.PlanSHA256 || inspected.UnknownOperationID != unknown.OperationID {
		h.fail("RECOVERY_INSPECT", "continuous recovery planned readback mismatch")
	}
	var approved mihomodeploy.LabRecoveryView
	h.call(stage+"_APPROVE", "approver", http.MethodPost, prefix+"/"+planned.RecoveryID+"/approvals",
		mihomodeploy.LabRecoveryApprovalRequest{PlanSHA256: planned.PlanSHA256, Revision: planned.Revision}, http.StatusOK, &approved)
	if approved.Phase != "APPROVED" || approved.PlanSHA256 != planned.PlanSHA256 || approved.RecoveryID != planned.RecoveryID {
		h.fail("RECOVERY_APPROVAL", "continuous recovery independent approval mismatch")
	}
	var completed mihomodeploy.LabRecoveryView
	h.call(stage+"_EXECUTE", "admin", http.MethodPost, prefix+"/"+planned.RecoveryID+"/execute",
		mihomodeploy.LabRecoveryExecuteRequest{PlanSHA256: approved.PlanSHA256, Revision: approved.Revision}, http.StatusOK, &completed)
	if completed.Phase != "COMPLETED" || completed.RecoveryID != planned.RecoveryID || completed.PlanSHA256 != planned.PlanSHA256 ||
		completed.UnknownOperationID != unknown.OperationID || completed.OriginalPlanSHA256 != unknown.PlanSHA256 ||
		completed.WriteBlocked || !completed.HeadAdvanced || completed.HeadSHA256 == completed.PreviousHeadSHA256 || completed.Failure != nil {
		h.fail("RECOVERY_COMPLETE", "continuous recovery completion mismatch")
	}
	var final mihomodeploy.LabRecoveryView
	h.call(stage+"_INSPECT_COMPLETED", "auditor", http.MethodGet, prefix+"/"+planned.RecoveryID, nil, http.StatusOK, &final)
	if final.RecoveryID != completed.RecoveryID || final.Phase != completed.Phase || final.Revision != completed.Revision ||
		final.HeadSHA256 != completed.HeadSHA256 || final.HeadGeneration != completed.HeadGeneration || !final.HeadAdvanced {
		h.fail("RECOVERY_READBACK", "continuous recovery completion readback mismatch")
	}
	h.report.Recoveries = append(h.report.Recoveries, continuousRecoveryRecoveryState{Stage: stage, View: final})
	return final
}

func continuousRecoveryObserveValid(observation mihomodeploy.LabContinuousRecoveryFaultObservation) bool {
	if !observation.NativeCallsBounded || observation.BoundOperations != 3 || observation.ObservedResults != 3 ||
		observation.InitialCore == 0 || observation.RecoveredCore == nil || *observation.RecoveredCore == 0 ||
		*observation.RecoveredCore == observation.InitialCore || observation.Transport.BoundChildren != 3 ||
		observation.Transport.UnderlyingRoundTrips != 3 || observation.Transport.Injected != 2 || len(observation.Transport.Steps) != 3 {
		return false
	}
	for index, step := range observation.Transport.Steps {
		sequence := index + 1
		action := "LOSS"
		state := "INJECTED"
		injected := true
		if sequence == 2 {
			action, state, injected = "PASS", "PASSTHROUGH", false
		}
		if step.Sequence != sequence || step.Action != action || step.State != state || step.UnderlyingRoundTrips != 1 ||
			step.Injected != injected || step.StatusCode == nil || *step.StatusCode != http.StatusNoContent {
			return false
		}
	}
	previous := 0
	for _, call := range observation.NativeCalls {
		if call.Sequence <= previous || call.At.IsZero() {
			return false
		}
		previous = call.Sequence
	}
	return true
}

func continuousRecoveryCleanupCalls(before, after []mihomodeploy.LabContinuousRecoveryNativeCall) bool {
	if len(after) <= len(before) {
		return false
	}
	want := map[string]bool{"OWNED_STOP_HELPER_ENTER": false, "KERNEL_OS_TERM_ATTEMPT": false,
		"KERNEL_OS_TERM_RETURN": false, "KERNEL_OS_WAIT_RETURN": false}
	for _, call := range after[len(before):] {
		if _, ok := want[call.Kind]; ok {
			want[call.Kind] = true
		}
	}
	for _, present := range want {
		if !present {
			return false
		}
	}
	return true
}

func continuousRecoverySuccessReportValid(report *continuousRecoveryReport) bool {
	if report == nil || report.Schema != "chengwang.mihomo-continuous-recovery-http-experiment/v1" ||
		report.Scope != "ACTUAL_ISOLATED_HTTPS_UNKNOWN_RECOVERY_ACK_UNKNOWN_RECOVERY_NOT_PRODUCTION" ||
		len(report.SourceCommit) != 40 || report.Outcome != "PASS" || report.FailureCode != "NONE" ||
		report.Initial == nil || len(report.HTTP) != 31 || len(report.Heads) != 6 || len(report.Operations) != 3 ||
		len(report.Recoveries) != 2 || len(report.ClosedPorts) != 6 || !report.RuntimeReturned ||
		report.RuntimeErrorClass != "NONE" || report.PrivateWALDecodedByTest || report.Production ||
		report.FullPayloadProven || report.InternetBusinessProven || report.FaultBeforeCleanup == nil ||
		report.FaultAfterCleanup == nil || report.FaultClosed == nil {
		return false
	}
	if report.CallsAfter.ReloadInvocations != report.CallsBefore.ReloadInvocations+3 ||
		report.CallsAfter.DoInvocations != report.CallsBefore.DoInvocations+3 ||
		report.FaultBeforeCleanup.State != "TERMINAL" || report.FaultAfterCleanup.State != "TERMINAL" ||
		report.FaultClosed.State != "CLOSED" || !continuousRecoveryObserveValid(*report.FaultBeforeCleanup) ||
		!continuousRecoveryObserveValid(*report.FaultAfterCleanup) || !continuousRecoveryObserveValid(*report.FaultClosed) ||
		!continuousRecoveryCleanupCalls(report.FaultBeforeCleanup.NativeCalls, report.FaultAfterCleanup.NativeCalls) {
		return false
	}
	for index, item := range report.HTTP {
		roleValid := item.Role == "viewer" || item.Role == "admin" || item.Role == "approver" || item.Role == "auditor"
		if item.Sequence != index+1 || !roleValid || (item.Method != http.MethodGet && item.Method != http.MethodPost) ||
			len(item.Path) == 0 || item.Path[0] != '/' || len(item.RequestBodySHA256) != 64 || item.StatusCode == nil ||
			*item.StatusCode < 200 || *item.StatusCode >= 300 || len(item.ResponseBodySHA256) != 64 ||
			len(item.ResponseBodyB64) == 0 || !json.Valid(item.ResponseBodyB64) || item.ErrorClass != "NONE" {
			return false
		}
	}
	for _, port := range report.ClosedPorts {
		if port.Port < 1 || port.Port > 65535 || !port.ConnectAttempted || port.Accepted || port.ErrorClass != "CONNECTION_REFUSED" {
			return false
		}
	}
	return true
}

func TestMihomoContinuousRecoveryHTTPSUnknownRecoveryAckUnknownRecovery(t *testing.T) {
	report := continuousRecoveryReport{Schema: "chengwang.mihomo-continuous-recovery-http-experiment/v1",
		Scope:        "ACTUAL_ISOLATED_HTTPS_UNKNOWN_RECOVERY_ACK_UNKNOWN_RECOVERY_NOT_PRODUCTION",
		SourceCommit: os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"), Outcome: "FAIL", FailureCode: "NOT_COMPLETED",
		HTTP: []continuousRecoveryHTTPOriginal{}, Heads: []continuousRecoveryHeadState{},
		Operations: []continuousRecoveryOperationState{}, Recoveries: []continuousRecoveryRecoveryState{},
		ClosedPorts: []serviceClosedPort{}, RuntimeErrorClass: "NOT_OBSERVED"}
	var fault *mihomodeploy.LabContinuousRecoveryFaultHandle
	faultClosed := false
	defer func() {
		if fault != nil {
			if report.FaultAfterCleanup == nil {
				if observed, err := fault.Observe(); err == nil {
					report.FaultAfterCleanup = &observed
				}
			}
			if !faultClosed {
				if err := fault.Close(); err != nil {
					t.Error("continuous recovery fault handle did not close")
				} else {
					faultClosed = true
					if observed, observeErr := fault.Observe(); observeErr == nil {
						report.FaultClosed = &observed
					}
				}
			}
		}
		if t.Failed() {
			report.Outcome = "FAIL"
		}
		raw, err := json.Marshal(report)
		if err != nil || serviceE2EWrite(continuousRecoveryReportPath, append(raw, '\n')) != nil {
			t.Error("private continuous recovery report was not durably written")
		}
	}()
	if os.Geteuid() != 10001 || os.Getegid() != 10001 || len(report.SourceCommit) != 40 {
		report.FailureCode = "ENVELOPE"
		t.Fatal("actual continuous recovery envelope required")
	}
	inputs := runtimeSubscriptionInputs(t)
	cfg := inputs.config
	cfg.Mode = mihomodeploy.LabEnvironment
	cfg.IdentitiesFile = MihomoLabIdentityFile
	cfg.MihomoLabEnabled = true
	cfg.SubscriptionsEnabled, cfg.SubscriptionWritesEnabled = false, false
	scope := authz.ResourceScope{TenantID: cfg.TenantID, SiteID: cfg.SiteID, ObjectType: mihomodeploy.LabObjectType,
		ObjectID: cfg.ManagementObjectID, Environment: mihomodeploy.LabEnvironment}
	profile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		name := string(role)
		digest := sha256.Sum256([]byte(inputs.tokens[name]))
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: "continuous-" + name,
			TokenHash: hex.EncodeToString(digest[:]), Principal: authz.Principal{ID: "continuous-" + name,
				TenantID: scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	rawProfile, err := json.Marshal(profile)
	if err != nil || serviceE2EWrite(MihomoLabIdentityFile, rawProfile) != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("continuous recovery private identity file")
	}
	privateTokens, err := json.Marshal(inputs.tokens)
	if err != nil || serviceE2EWrite(filepath.Dir(MihomoLabIdentityFile)+"/http-secrets.private.json", privateTokens) != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("continuous recovery private token fence")
	}
	privateTLSKey, err := os.ReadFile(cfg.TLSKeyFile)
	if err != nil || serviceE2EWrite(filepath.Dir(MihomoLabIdentityFile)+"/tls-key.private.pem", privateTLSKey) != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("continuous recovery private TLS fence")
	}
	hookResults, err := armLabContinuousRecoveryHarness()
	if err != nil {
		report.FailureCode = "HOOK_ARM"
		t.Fatal("continuous recovery source hook did not arm")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	addresses := make(chan string, 1)
	runtimeDone := make(chan error, 1)
	go func() {
		runtimeDone <- RunWith(Options{Context: ctx, Config: &cfg, Signals: signals, ShutdownTimeout: 20 * time.Second,
			Listen: func(network, address string) (net.Listener, error) {
				listener, listenErr := net.Listen(network, address)
				if listenErr == nil {
					addresses <- listener.Addr().String()
				}
				return listener, listenErr
			}})
	}()
	runtimeObserved := false
	stopRuntime := func() {
		if runtimeObserved {
			return
		}
		select {
		case signals <- os.Interrupt:
		default:
			cancel()
		}
		select {
		case stopErr := <-runtimeDone:
			runtimeObserved = true
			report.RuntimeReturned = true
			if stopErr != nil {
				report.RuntimeErrorClass = "FAILED"
				t.Error("continuous recovery runtime close failed")
			} else {
				report.RuntimeErrorClass = "NONE"
			}
		case <-time.After(25 * time.Second):
			report.RuntimeErrorClass = "UNOBSERVED"
			t.Error("continuous recovery runtime close was not observed")
		}
	}
	defer stopRuntime()
	var address string
	startTimer := time.NewTimer(35 * time.Second)
	defer startTimer.Stop()
	for address == "" || fault == nil {
		select {
		case address = <-addresses:
		case result := <-hookResults:
			if result.err != nil || result.handle == nil {
				report.FailureCode = "HOOK_BIND"
				t.Fatal("continuous recovery source hook did not bind")
			}
			fault = result.handle
		case startErr := <-runtimeDone:
			runtimeObserved = true
			report.RuntimeReturned = true
			report.RuntimeErrorClass = "FAILED"
			report.FailureCode = "RUNTIME_START"
			if startErr == nil {
				t.Fatal("continuous recovery runtime exited before listen")
			}
			t.Fatal("continuous recovery runtime startup failed")
		case <-startTimer.C:
			report.FailureCode = "RUNTIME_START"
			t.Fatal("continuous recovery runtime listener or hook not observed")
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{RootCAs: inputs.roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 45 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 50 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	https := continuousRecoveryHTTPS{t: t, base: "https://" + address, client: client, tokens: inputs.tokens, report: &report}
	initial, err := mihomodeploy.ReadIsolatedLabAcceptanceState()
	if err != nil || initial.WALSchema != "chengwang.mihomo-lifecycle/v2" || initial.Head.Generation != 1 ||
		initial.ActiveOperationID != nil || len(initial.Completed) != 0 || len(initial.Terminated) != 0 || !initial.PrivateWALValidated {
		report.FailureCode = "INITIAL_STATE"
		t.Fatal("continuous recovery initial actual state missing")
	}
	report.Initial = &initial
	initialHead := https.head("INITIAL")
	if initialHead.Generation != initial.Head.Generation || initialHead.HeadSHA256 != initial.Head.HeadSHA256 || initialHead.WriteBlocked {
		report.FailureCode = "INITIAL_HEAD"
		t.Fatal("continuous recovery initial HTTP head mismatch")
	}
	report.CallsBefore = mihomo.ObserveReloadCounters()
	firstTarget := https.candidate("FIRST")
	firstUnknown := https.deploy("FIRST_UNKNOWN", firstTarget, mihomo.ReloadUnknown)
	firstUnknownHead := https.head("FIRST_UNKNOWN")
	if firstUnknownHead.Generation != initialHead.Generation || firstUnknownHead.HeadSHA256 != initialHead.HeadSHA256 ||
		!firstUnknownHead.WriteBlocked || firstUnknownHead.ActiveOperationID == nil || *firstUnknownHead.ActiveOperationID != firstUnknown.OperationID {
		report.FailureCode = "FIRST_UNKNOWN_HEAD"
		t.Fatal("first UNKNOWN did not retain and block the actual head")
	}
	firstRecovery := https.recover("FIRST_RECOVERY", firstUnknown)
	firstRecoveredHead := https.head("FIRST_RECOVERED")
	if firstRecoveredHead.Generation != initialHead.Generation+1 || firstRecoveredHead.HeadSHA256 != firstRecovery.HeadSHA256 ||
		firstRecoveredHead.ArtifactRecordSHA256 != firstRecovery.TargetArtifactRecordSHA256 || firstRecoveredHead.WriteBlocked || firstRecoveredHead.ActiveOperationID != nil {
		report.FailureCode = "FIRST_RECOVERED_HEAD"
		t.Fatal("first recovery did not publish the actual current head")
	}
	ackTarget := https.candidate("ACK")
	acknowledged := https.deploy("ORDINARY_ACK", ackTarget, mihomo.ReloadAcknowledged)
	ackHead := https.head("ORDINARY_ACK")
	if ackHead.Generation != firstRecoveredHead.Generation+1 || ackHead.HeadSHA256 != acknowledged.HeadSHA256 ||
		ackHead.ArtifactRecordSHA256 != acknowledged.CandidateRecordSHA256 || ackHead.WriteBlocked || ackHead.ActiveOperationID != nil {
		report.FailureCode = "ACK_HEAD"
		t.Fatal("ordinary acknowledged publish did not advance the recovered epoch")
	}
	secondTarget := https.candidate("SECOND")
	secondUnknown := https.deploy("SECOND_UNKNOWN", secondTarget, mihomo.ReloadUnknown)
	secondUnknownHead := https.head("SECOND_UNKNOWN")
	if secondUnknownHead.Generation != ackHead.Generation || secondUnknownHead.HeadSHA256 != ackHead.HeadSHA256 ||
		!secondUnknownHead.WriteBlocked || secondUnknownHead.ActiveOperationID == nil || *secondUnknownHead.ActiveOperationID != secondUnknown.OperationID {
		report.FailureCode = "SECOND_UNKNOWN_HEAD"
		t.Fatal("second UNKNOWN did not retain and block the current head")
	}
	secondRecovery := https.recover("SECOND_RECOVERY", secondUnknown)
	finalHead := https.head("SECOND_RECOVERED")
	if finalHead.Generation != ackHead.Generation+1 || finalHead.HeadSHA256 != secondRecovery.HeadSHA256 ||
		finalHead.ArtifactRecordSHA256 != secondRecovery.TargetArtifactRecordSHA256 || finalHead.WriteBlocked || finalHead.ActiveOperationID != nil {
		report.FailureCode = "SECOND_RECOVERED_HEAD"
		t.Fatal("second recovery did not publish the final actual head")
	}
	report.CallsAfter = mihomo.ObserveReloadCounters()
	if report.CallsAfter.ReloadInvocations != report.CallsBefore.ReloadInvocations+3 ||
		report.CallsAfter.DoInvocations != report.CallsBefore.DoInvocations+3 {
		report.FailureCode = "DISPATCH_COUNT"
		t.Fatal("continuous recovery did not issue exactly three physical reloads")
	}
	beforeCleanup, err := fault.Observe()
	if err != nil || beforeCleanup.State != "TERMINAL" || beforeCleanup.Transport.State != "TERMINAL" ||
		!continuousRecoveryObserveValid(beforeCleanup) {
		report.FailureCode = "FAULT_OBSERVATION"
		t.Fatal("continuous recovery source-owned schedule was not terminal")
	}
	report.FaultBeforeCleanup = &beforeCleanup
	stopRuntime()
	if !report.RuntimeReturned || report.RuntimeErrorClass != "NONE" {
		report.FailureCode = "CLEANUP"
		t.Fatal("continuous recovery runtime did not close cleanly")
	}
	afterCleanup, err := fault.Observe()
	if err != nil || afterCleanup.State != "TERMINAL" || afterCleanup.Transport.State != "TERMINAL" ||
		!continuousRecoveryObserveValid(afterCleanup) || !continuousRecoveryCleanupCalls(beforeCleanup.NativeCalls, afterCleanup.NativeCalls) {
		report.FailureCode = "CLEANUP_CALLS"
		t.Fatal("continuous recovery final owned cleanup callsites missing")
	}
	report.FaultAfterCleanup = &afterCleanup
	ports := []int{28411, 28412, 28413, 28414, 28415}
	_, managementPort, splitErr := net.SplitHostPort(address)
	parsedPort, parseErr := strconv.Atoi(managementPort)
	if splitErr != nil || parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
		report.FailureCode = "CLEANUP_PORT"
		t.Fatal("continuous recovery management listener address invalid")
	}
	ports = append(ports, parsedPort)
	for _, port := range ports {
		connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		fact := serviceClosedPort{Port: port, ConnectAttempted: true, ErrorClass: "UNCLASSIFIED"}
		if dialErr == nil {
			fact.Accepted = true
			_ = connection.Close()
		} else if errors.Is(dialErr, syscall.ECONNREFUSED) {
			fact.ErrorClass = "CONNECTION_REFUSED"
		}
		report.ClosedPorts = append(report.ClosedPorts, fact)
		if fact.Accepted || fact.ErrorClass != "CONNECTION_REFUSED" {
			report.FailureCode = "CLEANUP_PORT"
			t.Fatal("continuous recovery listener closure was not proved")
		}
	}
	if err := fault.Close(); err != nil {
		report.FailureCode = "FAULT_CLOSE"
		t.Fatal("continuous recovery fault handle close failed")
	}
	faultClosed = true
	closedObservation, err := fault.Observe()
	if err != nil || closedObservation.State != "CLOSED" || !continuousRecoveryObserveValid(closedObservation) {
		report.FailureCode = "FAULT_CLOSE"
		t.Fatal("continuous recovery closed observation unavailable")
	}
	report.FaultClosed = &closedObservation
	report.Outcome, report.FailureCode = "PASS", "NONE"
	if !continuousRecoverySuccessReportValid(&report) {
		report.FailureCode = "REPORT_CONTRACT"
		t.Fatal("continuous recovery report contract rejected")
	}
}
