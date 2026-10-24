//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults

package serverruntime

// Actual product HTTP/kernel experiment with an explicit client-side transport
// response-loss fault. The real controller response is observed separately; it
// is never copied into the adapter's UNKNOWN result or treated as recovery.
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
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

type unknownServiceReport struct {
	Schema                  string                                  `json:"schema"`
	Scope                   string                                  `json:"scope"`
	SourceCommit            string                                  `json:"sourceCommit"`
	Outcome                 string                                  `json:"outcome"`
	FailureCode             string                                  `json:"failureCode"`
	HTTP                    []serviceHTTPOriginal                   `json:"http"`
	Before                  *mihomodeploy.LabAcceptanceState        `json:"before"`
	After                   *mihomodeploy.LabUnknownAcceptanceState `json:"after"`
	Replay                  *mihomodeploy.LabUnknownAcceptanceState `json:"replay"`
	Final                   *mihomodeploy.LabUnknownAcceptanceState `json:"final"`
	Fault                   *mihomo.LabReloadFaultObservation       `json:"fault"`
	CallsBefore             mihomo.ReloadCounters                   `json:"callsBefore"`
	CallsAfter              mihomo.ReloadCounters                   `json:"callsAfter"`
	CallsReplay             mihomo.ReloadCounters                   `json:"callsReplay"`
	CallsFinal              mihomo.ReloadCounters                   `json:"callsFinal"`
	ControllerReceivedCount *uint64                                 `json:"controllerReceivedCount"`
	ClosedPorts             []serviceClosedPort                     `json:"closedPorts"`
	RuntimeReturned         bool                                    `json:"runtimeReturned"`
	RuntimeErrorClass       string                                  `json:"runtimeErrorClass"`
	Production              bool                                    `json:"production"`
	FullPayloadProven       bool                                    `json:"fullPayloadProven"`
	InternetBusinessProven  bool                                    `json:"internetBusinessProven"`
}

func TestMihomoServiceHTTPUnknownOutcomeBlocksReplayAndNewPlan(t *testing.T) {
	report := unknownServiceReport{Schema: "chengwang.mihomo-unknown-http-experiment/v1",
		Scope:        "ACTUAL_FIXED_KERNEL_UNKNOWN_OUTCOME_NO_RESEND_NOT_RECOVERY_OR_PRODUCTION",
		SourceCommit: os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"), Outcome: "FAIL", FailureCode: "NOT_COMPLETED",
		HTTP: []serviceHTTPOriginal{}, RuntimeErrorClass: "NOT_OBSERVED"}
	defer func() {
		if t.Failed() {
			report.Outcome = "FAIL"
		}
		raw, err := json.Marshal(report)
		if err != nil || serviceE2EWrite(labServiceE2EPrivate+"/unknown-report.private.json", raw) != nil {
			t.Error("private unknown experiment report was not durably written")
		}
	}()
	if os.Geteuid() != 10001 || os.Getegid() != 10001 || len(report.SourceCommit) != 40 {
		report.FailureCode = "ENVELOPE"
		t.Fatal("actual service envelope required")
	}
	// Reuse the existing genuine CA/leaf generation and trust pool. Its old
	// subscription scope is replaced below; it grants this service no authority.
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
		hash := sha256.Sum256([]byte(inputs.tokens[name]))
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: "lab-" + name, TokenHash: hex.EncodeToString(hash[:]),
			Principal: authz.Principal{ID: "lab-" + name, TenantID: scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	wrong, wrongHash, err := authn.GenerateToken(32)
	if err != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("wrong-scope credential generation")
	}
	inputs.tokens["wrong-scope"] = wrong
	wrongScope := scope
	wrongScope.SiteID = "different-site"
	profile.Identities = append(profile.Identities, authn.Identity{TokenID: "lab-wrong-scope", TokenHash: wrongHash,
		Principal: authz.Principal{ID: "lab-wrong-scope", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{wrongScope}}})
	rawProfile, err := json.Marshal(profile)
	if err != nil || serviceE2EWrite(MihomoLabIdentityFile, rawProfile) != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("private current identity file")
	}
	// Plaintext exists only as an explicit private publication fence. Neither
	// HTTP originals nor the report retain Authorization values.
	privateTokens, err := json.Marshal(inputs.tokens)
	if err != nil || serviceE2EWrite(filepath.Dir(MihomoLabIdentityFile)+"/http-secrets.private.json", privateTokens) != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("private HTTP disclosure fence")
	}
	// Retain the actual private leaf key as fence input only. No private key is
	// a public artifact; the producer reads its bytes at a source-fixed path.
	privateTLSKey, err := os.ReadFile(cfg.TLSKeyFile)
	if err != nil || serviceE2EWrite(filepath.Dir(MihomoLabIdentityFile)+"/tls-key.private.pem", privateTLSKey) != nil {
		report.FailureCode = "IDENTITY_INPUT"
		t.Fatal("private TLS disclosure fence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	address := make(chan string, 1)
	runtimeDone := make(chan error, 1)
	options := Options{Context: ctx, Config: &cfg, Signals: signals, ShutdownTimeout: 15 * time.Second,
		Listen: func(network, addr string) (net.Listener, error) {
			listener, err := net.Listen(network, addr)
			if err == nil {
				address <- listener.Addr().String()
			}
			return listener, err
		}}
	go func() { runtimeDone <- RunWith(options) }()
	runtimeObserved := false
	defer func() {
		if runtimeObserved {
			return
		}
		signals <- os.Interrupt
		select {
		case err := <-runtimeDone:
			report.RuntimeReturned = true
			if err == nil {
				report.RuntimeErrorClass = "NONE"
			} else {
				report.RuntimeErrorClass = "FAILED"
				t.Error("actual runtime close failed")
			}
		case <-time.After(20 * time.Second):
			report.RuntimeErrorClass = "UNOBSERVED"
			t.Error("actual runtime close was not observed")
		}
	}()
	var endpoint string
	select {
	case value := <-address:
		endpoint = "https://" + value
	case <-runtimeDone:
		runtimeObserved = true
		report.RuntimeReturned = true
		report.RuntimeErrorClass = "FAILED"
		report.FailureCode = "RUNTIME_START"
		t.Fatal("actual product startup failed")
	case <-time.After(30 * time.Second):
		report.FailureCode = "RUNTIME_START"
		t.Fatal("actual product listener not observed")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{RootCAs: inputs.roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 35 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(name, role, method, path string, body any, want int, result any) {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal("source request encoding")
			}
		}
		request, err := http.NewRequest(method, endpoint+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal("source HTTPS request")
		}
		if role != "anonymous" {
			request.Header.Set("Authorization", "Bearer "+inputs.tokens[role])
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		row := serviceHTTPOriginal{Sequence: len(report.HTTP) + 1, Case: name, Role: role, Method: method, Path: path,
			RequestBody: append([]byte{}, payload...), ErrorClass: "NONE"}
		response, err := client.Do(request)
		if err != nil {
			row.ErrorClass = "RESPONSE_NOT_OBSERVED"
			report.HTTP = append(report.HTTP, row)
			if want != 0 {
				report.FailureCode = "HTTP_TRANSPORT"
				t.Fatal("actual HTTPS response not observed")
			}
			return
		}
		status := response.StatusCode
		row.StatusCode = &status
		data, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
		closeErr := response.Body.Close()
		row.ResponseBody = append([]byte{}, data...)
		if readErr != nil || closeErr != nil || len(data) > 16<<10 {
			row.ErrorClass = "BODY"
		}
		report.HTTP = append(report.HTTP, row)
		if row.ErrorClass != "NONE" || status != want || want == 0 {
			report.FailureCode = "HTTP_RESULT"
			t.Fatal("actual HTTPS result mismatch")
		}
		if result != nil {
			var envelope struct {
				Boundary            string          `json:"boundary"`
				Code                string          `json:"code"`
				StateMayHaveChanged bool            `json:"stateMayHaveChanged"`
				Result              json.RawMessage `json:"result"`
			}
			if json.Unmarshal(data, &envelope) != nil || envelope.Boundary != mihomodeploy.LabBackendBoundary ||
				envelope.Code != "mihomo_lab_ok" || json.Unmarshal(envelope.Result, result) != nil {
				report.FailureCode = "HTTP_BODY"
				t.Fatal("actual HTTPS body rejected")
			}
		}
	}
	const prefix = "/api/v1/lab/mihomo"
	call("ANONYMOUS_CANDIDATES", "anonymous", "GET", prefix+"/candidates", nil, 401, nil)
	var candidates mihomodeploy.LabCandidateListView
	call("ACTUAL_CANDIDATES", "viewer", "GET", prefix+"/candidates", nil, 200, &candidates)
	if len(candidates.Candidates) != 2 || candidates.WriteBlocked {
		report.FailureCode = "INITIAL_HEAD"
		t.Fatal("actual candidates not ready")
	}
	var candidate string
	for _, value := range candidates.Candidates {
		if !value.IsCurrent {
			candidate = value.RecordSHA256
		}
	}
	if len(candidate) != 64 {
		report.FailureCode = "INITIAL_HEAD"
		t.Fatal("actual candidate record missing")
	}
	before, err := mihomodeploy.ReadIsolatedLabAcceptanceState()
	if err != nil || before.Head.Generation != 1 || before.ActiveOperationID != nil || len(before.Completed) != 0 || before.UnknownObservationCount != 0 {
		report.FailureCode = "INITIAL_HEAD"
		t.Fatal("actual bootstrap state missing")
	}
	report.Before = &before
	create := mihomodeploy.LabCreateRequest{CandidateRecordSHA256: candidate, TTLSeconds: 300}
	call("VIEWER_CREATE_DENIED", "viewer", "POST", prefix+"/deployments", create, 403, nil)
	call("SCOPE_CREATE_DENIED", "wrong-scope", "POST", prefix+"/deployments", create, 403, nil)
	var planned mihomodeploy.LabDeploymentView
	call("CREATE_ACTUAL_PLAN", "admin", "POST", prefix+"/deployments", create, 201, &planned)
	if planned.Phase != "PLANNED" || planned.Transport != nil {
		report.FailureCode = "PLAN"
		t.Fatal("actual plan mismatch")
	}
	id := planned.OperationID
	approval := mihomodeploy.LabApprovalRequest{PlanSHA256: planned.PlanSHA256, Revision: planned.Revision}
	call("SELF_APPROVAL_DENIED", "admin", "POST", prefix+"/deployments/"+id+"/approvals", approval, 403, nil)
	var approved mihomodeploy.LabDeploymentView
	call("CURRENT_INDEPENDENT_APPROVAL", "approver", "POST", prefix+"/deployments/"+id+"/approvals", approval, 200, &approved)
	if approved.Phase != "APPROVED" || approved.Transport != nil {
		report.FailureCode = "APPROVAL"
		t.Fatal("actual independent approval missing")
	}
	report.CallsBefore = mihomo.ObserveReloadCounters()
	if report.CallsBefore.ReloadInvocations != 0 || report.CallsBefore.DoInvocations != 0 {
		report.FailureCode = "DISPATCH_COUNT"
		t.Fatal("fresh experiment process already wrote")
	}
	fault, err := mihomo.BeginLabReloadResponseLoss()
	if err != nil {
		report.FailureCode = "FAULT_SETUP"
		t.Fatal("actual fault capability unavailable")
	}
	execute := mihomodeploy.LabExecuteRequest{PlanSHA256: approved.PlanSHA256, Revision: approved.Revision}
	var unknown mihomodeploy.LabDeploymentView
	call("ACTUAL_EXECUTE_UNKNOWN", "admin", "POST", prefix+"/deployments/"+id+"/execute", execute, 200, &unknown)
	observation, err := fault.Observe()
	if err != nil {
		report.FailureCode = "FAULT_OBSERVATION"
		t.Fatal("actual fault observation unavailable")
	}
	report.Fault = &observation
	if observation.Schema != "chengwang.mihomo-reload-response-loss-observation/v1" || observation.State != "INJECTED" || !observation.Claimed ||
		observation.UnderlyingRoundTrips != 1 || observation.StatusCode == nil || *observation.StatusCode != 204 || observation.BodyBytes == nil || *observation.BodyBytes != 0 ||
		observation.EOFObserved == nil || !*observation.EOFObserved || observation.CloseSucceeded == nil || !*observation.CloseSucceeded || !observation.Injected || observation.FailureCode != nil {
		report.FailureCode = "FAULT_OBSERVATION"
		t.Fatal("actual controller response loss was not observed")
	}
	if unknown.Phase != "UNKNOWN" || !unknown.WriteBlocked || unknown.HeadAdvanced || unknown.Replayed || unknown.HeadGeneration != 1 || unknown.HeadSHA256 != before.Head.HeadSHA256 ||
		unknown.Transport == nil || unknown.Transport.Origin != "ADAPTER" || unknown.Transport.GateReason != nil || unknown.Transport.Result.State != mihomo.ReloadUnknown ||
		!unknown.Transport.Result.Dispatched || unknown.Transport.Result.StatusCode != 0 || unknown.Observation == nil || !unknown.Observation.LocalRouteVerified ||
		unknown.Observation.Conclusion != mihomo.LabStableNewProjection {
		report.FailureCode = "UNKNOWN_BARRIER"
		t.Fatal("observed candidate state overrode original unknown outcome")
	}
	after, err := mihomodeploy.ReadIsolatedLabUnknownAcceptanceState()
	if err != nil || after.ActiveAttempt != 1 || after.ActiveTransport == nil || !reflect.DeepEqual(after.ActiveTransport, unknown.Transport) ||
		after.LastObservation == nil || after.LastObservation.OperationID != id || after.LastObservation.PlanSHA256 != planned.PlanSHA256 ||
		after.LastObservation.EvidenceSHA256 != unknown.Observation.EvidenceSHA256 || after.State.UnknownObservationCount != 1 ||
		after.State.Head.Generation != 1 || after.State.Head.HeadSHA256 != before.Head.HeadSHA256 || !after.State.Head.WriteBlocked || len(after.State.Completed) != 0 || len(after.State.Terminated) != 0 {
		report.FailureCode = "DURABLE_UNKNOWN"
		t.Fatal("actual unknown record or original head was not preserved")
	}
	report.After = &after
	report.CallsAfter = mihomo.ObserveReloadCounters()
	if report.CallsAfter.ReloadInvocations != 1 || report.CallsAfter.DoInvocations != 1 {
		report.FailureCode = "DISPATCH_COUNT"
		t.Fatal("actual unknown used more than one reload or Do")
	}
	var inspected mihomodeploy.LabDeploymentView
	call("INSPECT_UNKNOWN", "admin", "GET", prefix+"/deployments/"+id, nil, 200, &inspected)
	if !reflect.DeepEqual(inspected, unknown) {
		report.FailureCode = "UNKNOWN_READBACK"
		t.Fatal("inspection rewrote original unknown facts")
	}
	var head mihomodeploy.LabHeadView
	call("HEAD_REMAINS_OLD", "admin", "GET", prefix+"/head", nil, 200, &head)
	if head.Generation != 1 || head.HeadSHA256 != before.Head.HeadSHA256 || head.VerificationSHA256 != before.Head.VerificationSHA256 ||
		head.ConfigSHA256 != before.Head.ConfigSHA256 || !head.WriteBlocked || head.ActiveOperationID == nil || *head.ActiveOperationID != id {
		report.FailureCode = "UNKNOWN_HEAD"
		t.Fatal("candidate projection advanced writable head")
	}
	var blocked mihomodeploy.LabCandidateListView
	call("CANDIDATES_CURRENT_UNKNOWN", "viewer", "GET", prefix+"/candidates", nil, 200, &blocked)
	if !blocked.WriteBlocked || len(blocked.Candidates) != 2 {
		report.FailureCode = "UNKNOWN_HEAD"
		t.Fatal("unknown candidate list unblocked")
	}
	for _, candidate := range blocked.Candidates {
		if candidate.IsCurrent {
			report.FailureCode = "UNKNOWN_HEAD"
			t.Fatal("uncertain runtime called a current writable artifact")
		}
	}
	var replayed mihomodeploy.LabDeploymentView
	call("REPLAY_UNKNOWN_NO_NEW_DO", "admin", "POST", prefix+"/deployments/"+id+"/execute", execute, 200, &replayed)
	originalReplay := unknown
	originalReplay.Replayed = true
	if !reflect.DeepEqual(replayed, originalReplay) {
		report.FailureCode = "REPLAY"
		t.Fatal("replay rewrote unknown facts")
	}
	replay, err := mihomodeploy.ReadIsolatedLabUnknownAcceptanceState()
	if err != nil || !reflect.DeepEqual(replay, after) {
		report.FailureCode = "REPLAY"
		t.Fatal("replay changed durable unknown record")
	}
	report.Replay = &replay
	report.CallsReplay = mihomo.ObserveReloadCounters()
	if report.CallsReplay != report.CallsAfter {
		report.FailureCode = "REPLAY"
		t.Fatal("unknown replay sent another request")
	}
	// Reusing candidateB is essential: oldbase would be rejected by the
	// same-config guard even if the UNKNOWN barrier had regressed.
	call("CREATE_BLOCKED_BY_UNKNOWN", "admin", "POST", prefix+"/deployments", create, 409, nil)
	var finalView mihomodeploy.LabDeploymentView
	call("INSPECT_AFTER_BLOCKED_CREATE", "admin", "GET", prefix+"/deployments/"+id, nil, 200, &finalView)
	if !reflect.DeepEqual(finalView, unknown) {
		report.FailureCode = "NEW_PLAN_BLOCK"
		t.Fatal("blocked plan changed unknown operation")
	}
	final, err := mihomodeploy.ReadIsolatedLabUnknownAcceptanceState()
	if err != nil || !reflect.DeepEqual(final, after) {
		report.FailureCode = "NEW_PLAN_BLOCK"
		t.Fatal("blocked plan modified actual WAL")
	}
	report.Final = &final
	report.CallsFinal = mihomo.ObserveReloadCounters()
	if report.CallsFinal != report.CallsAfter {
		report.FailureCode = "NEW_PLAN_BLOCK"
		t.Fatal("blocked plan sent another request")
	}
	latestFault, faultErr := fault.Observe()
	if faultErr != nil || !reflect.DeepEqual(latestFault, *report.Fault) {
		report.FailureCode = "REPLAY"
		t.Fatal("fault receipt changed after blocked operations")
	}
	signals <- os.Interrupt
	select {
	case err := <-runtimeDone:
		runtimeObserved = true
		report.RuntimeReturned = true
		if err != nil {
			report.RuntimeErrorClass = "FAILED"
			report.FailureCode = "CLEANUP"
			t.Fatal("actual product cleanup failed")
		}
		report.RuntimeErrorClass = "NONE"
	case <-time.After(20 * time.Second):
		report.FailureCode = "CLEANUP"
		t.Fatal("actual product stop was not observed")
	}
	for _, port := range []int{28411, 28412, 28413, 28414, 28415} {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		fact := serviceClosedPort{Port: port, ConnectAttempted: true, ErrorClass: "UNCLASSIFIED"}
		if err == nil {
			fact.Accepted = true
			_ = connection.Close()
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			fact.ErrorClass = "CONNECTION_REFUSED"
		}
		report.ClosedPorts = append(report.ClosedPorts, fact)
		if fact.Accepted || fact.ErrorClass != "CONNECTION_REFUSED" {
			report.FailureCode = "CLEANUP"
			t.Fatal("local listener closure was not proved")
		}
	}
	report.Outcome, report.FailureCode = "PASS", "NONE"
}
