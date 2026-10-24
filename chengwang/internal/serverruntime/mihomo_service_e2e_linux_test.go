//go:build linux && chengwang_mihomo_service

package serverruntime

// This opt-in test requires the root-owned isolated CI envelope and the real
// pinned kernel. There is no skip, fake Backend, controller response or seed
// head. The response-drop case is an explicit post-handler transport fault.
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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

const labServiceE2EPrivate = "/tmp/chengwang-mihomo-service-private"

type serviceHTTPOriginal struct {
	Sequence int `json:"sequence"`
	Case string `json:"case"`
	Role string `json:"role"`
	Method string `json:"method"`
	Path string `json:"path"`
	RequestBody []byte `json:"requestBody"`
	StatusCode *int `json:"statusCode"`
	ResponseBody []byte `json:"responseBody"`
	ErrorClass string `json:"errorClass"`
}
type serviceDroppedResponse struct {
	HandlerCompleted bool `json:"handlerCompleted"`
	GeneratedStatus int `json:"generatedStatus"`
	GeneratedBody []byte `json:"generatedBody"`
	ConnectionClosed bool `json:"connectionClosed"`
}
type serviceClosedPort struct {
	Port int `json:"port"`
	ConnectAttempted bool `json:"connectAttempted"`
	Accepted bool `json:"accepted"`
	ErrorClass string `json:"errorClass"`
}
type serviceE2EReport struct {
	Schema string `json:"schema"`
	Scope string `json:"scope"`
	SourceCommit string `json:"sourceCommit"`
	Outcome string `json:"outcome"`
	FailureCode string `json:"failureCode"`
	HTTP []serviceHTTPOriginal `json:"http"`
	Dropped serviceDroppedResponse `json:"dropped"`
	Before *mihomodeploy.LabAcceptanceState `json:"before"`
	After *mihomodeploy.LabAcceptanceState `json:"after"`
	Replay *mihomodeploy.LabAcceptanceState `json:"replay"`
	CallsBefore mihomo.ReloadCounters `json:"callsBefore"`
	CallsAfter mihomo.ReloadCounters `json:"callsAfter"`
	CallsReplay mihomo.ReloadCounters `json:"callsReplay"`
	ControllerReceivedCount *uint64 `json:"controllerReceivedCount"`
	ClosedPorts []serviceClosedPort `json:"closedPorts"`
	RuntimeReturned bool `json:"runtimeReturned"`
	RuntimeErrorClass string `json:"runtimeErrorClass"`
	Production bool `json:"production"`
	FullPayloadProven bool `json:"fullPayloadProven"`
	InternetBusinessProven bool `json:"internetBusinessProven"`
}

func serviceE2EWrite(path string, raw []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil { return err }
	f := os.NewFile(uintptr(fd), "isolated service acceptance evidence")
	if _, err = f.Write(raw); err == nil { err = f.Sync() }
	closed := f.Close()
	if err != nil { return err }; if closed != nil { return closed }
	d, err := os.Open(filepath.Dir(path)); if err != nil { return err }; defer d.Close()
	return d.Sync()
}

func TestMihomoServiceHTTPApprovalReloadReadbackAndReplay(t *testing.T) {
	report := serviceE2EReport{Schema: "chengwang.mihomo-service-http-experiment/v1",
		Scope: "ACTUAL_ISOLATED_PRODUCT_HTTP_AND_LOCAL_POSTCONDITION_NOT_FULL_SYSTEM_OR_PRODUCTION",
		SourceCommit: os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"), Outcome: "FAIL", FailureCode: "NOT_COMPLETED",
		HTTP: []serviceHTTPOriginal{}, RuntimeErrorClass: "NOT_OBSERVED"}
	defer func() {
		if t.Failed() { report.Outcome = "FAIL" }
		raw, err := json.Marshal(report)
		if err != nil || serviceE2EWrite(labServiceE2EPrivate+"/e2e-report.private.json", raw) != nil {
			t.Error("private service experiment report was not durably written")
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
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: "lab-"+name, TokenHash: hex.EncodeToString(hash[:]),
			Principal: authz.Principal{ID: "lab-"+name, TenantID: scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	wrong, wrongHash, err := authn.GenerateToken(32)
	if err != nil { report.FailureCode = "IDENTITY_INPUT"; t.Fatal("wrong-scope credential generation") }
	inputs.tokens["wrong-scope"] = wrong
	wrongScope := scope; wrongScope.SiteID = "different-site"
	profile.Identities = append(profile.Identities, authn.Identity{TokenID: "lab-wrong-scope", TokenHash: wrongHash,
		Principal: authz.Principal{ID: "lab-wrong-scope", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{wrongScope}}})
	rawProfile, err := json.Marshal(profile)
	if err != nil || serviceE2EWrite(MihomoLabIdentityFile, rawProfile) != nil {
		report.FailureCode = "IDENTITY_INPUT"; t.Fatal("private current identity file")
	}
	// Plaintext exists only as an explicit private publication fence. Neither
	// HTTP originals nor the report retain Authorization values.
	privateTokens, err := json.Marshal(inputs.tokens)
	if err != nil || serviceE2EWrite(filepath.Dir(MihomoLabIdentityFile)+"/http-secrets.private.json", privateTokens) != nil {
		report.FailureCode = "IDENTITY_INPUT"; t.Fatal("private HTTP disclosure fence")
	}
	// Retain the actual private leaf key as fence input only. No private key is
	// a public artifact; the producer reads its bytes at a source-fixed path.
	privateTLSKey, err := os.ReadFile(cfg.TLSKeyFile)
	if err != nil || serviceE2EWrite(filepath.Dir(MihomoLabIdentityFile)+"/tls-key.private.pem", privateTLSKey) != nil {
		report.FailureCode = "IDENTITY_INPUT"; t.Fatal("private TLS disclosure fence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	address := make(chan string, 1)
	runtimeDone := make(chan error, 1)
	var faultMu sync.Mutex
	dropPending := true
	drop := serviceDroppedResponse{}
	options := Options{Context: ctx, Config: &cfg, Signals: signals, ShutdownTimeout: 15*time.Second,
		Listen: func(network, addr string) (net.Listener, error) {
			listener, err := net.Listen(network, addr)
			if err == nil { address <- listener.Addr().String() }
			return listener, err
		},
		WebFactory: func(actual http.Handler) (http.Handler, error) {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				faultMu.Lock()
				selected := dropPending && r.Method == "POST" && r.URL.Path == "/api/v1/lab/mihomo/deployments"
				if selected { dropPending = false }
				faultMu.Unlock()
				if !selected { actual.ServeHTTP(w, r); return }
				generated := httptest.NewRecorder()
				actual.ServeHTTP(generated, r)
				fact := serviceDroppedResponse{HandlerCompleted: true, GeneratedStatus: generated.Code,
					GeneratedBody: append([]byte(nil), generated.Body.Bytes()...)}
				if hijacker, ok := w.(http.Hijacker); ok {
					connection, _, err := hijacker.Hijack()
					if err == nil { fact.ConnectionClosed = connection.Close() == nil }
				}
				faultMu.Lock(); drop = fact; faultMu.Unlock()
			}), nil
		}}
	go func() { runtimeDone <- RunWith(options) }()
	runtimeObserved := false
	defer func() {
		if runtimeObserved { return }
		signals <- os.Interrupt
		select {
		case err := <-runtimeDone:
			report.RuntimeReturned = true
			if err == nil { report.RuntimeErrorClass = "NONE" } else { report.RuntimeErrorClass = "FAILED"; t.Error("actual runtime close failed") }
		case <-time.After(20*time.Second): report.RuntimeErrorClass = "UNOBSERVED"; t.Error("actual runtime close was not observed")
		}
	}()
	var endpoint string
	select {
	case value := <-address: endpoint = "https://"+value
	case <-runtimeDone:
		runtimeObserved = true; report.RuntimeReturned = true; report.RuntimeErrorClass = "FAILED"
		report.FailureCode = "RUNTIME_START"; t.Fatal("actual product startup failed")
	case <-time.After(30*time.Second): report.FailureCode = "RUNTIME_START"; t.Fatal("actual product listener not observed")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{RootCAs: inputs.roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 35*time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 40*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(name, role, method, path string, body any, want int, result any) {
		t.Helper()
		var payload []byte
		if body != nil { var err error; payload, err = json.Marshal(body); if err != nil { t.Fatal("source request encoding") } }
		request, err := http.NewRequest(method, endpoint+path, bytes.NewReader(payload))
		if err != nil { t.Fatal("source HTTPS request") }
		if role != "anonymous" { request.Header.Set("Authorization", "Bearer "+inputs.tokens[role]) }
		if body != nil { request.Header.Set("Content-Type", "application/json") }
		row := serviceHTTPOriginal{Sequence: len(report.HTTP)+1, Case: name, Role: role, Method: method, Path: path,
			RequestBody: append([]byte{}, payload...), ErrorClass: "NONE"}
		response, err := client.Do(request)
		if err != nil {
			row.ErrorClass = "RESPONSE_NOT_OBSERVED"; report.HTTP = append(report.HTTP, row)
			if want != 0 { report.FailureCode = "HTTP_TRANSPORT"; t.Fatal("actual HTTPS response not observed") }; return
		}
		status := response.StatusCode; row.StatusCode = &status
		data, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
		closeErr := response.Body.Close(); row.ResponseBody = append([]byte{}, data...)
		if readErr != nil || closeErr != nil || len(data) > 16<<10 { row.ErrorClass = "BODY" }
		report.HTTP = append(report.HTTP, row)
		if row.ErrorClass != "NONE" || status != want || want == 0 { report.FailureCode = "HTTP_RESULT"; t.Fatal("actual HTTPS result mismatch") }
		if result != nil {
			var envelope struct { Boundary string `json:"boundary"`; Code string `json:"code"`; StateMayHaveChanged bool `json:"stateMayHaveChanged"`; Result json.RawMessage `json:"result"` }
			if json.Unmarshal(data, &envelope) != nil || envelope.Boundary != mihomodeploy.LabBackendBoundary ||
				envelope.Code != "mihomo_lab_ok" || json.Unmarshal(envelope.Result, result) != nil { report.FailureCode = "HTTP_BODY"; t.Fatal("actual HTTPS body rejected") }
		}
	}
	const prefix = "/api/v1/lab/mihomo"
	call("ANONYMOUS_CANDIDATES", "anonymous", "GET", prefix+"/candidates", nil, 401, nil)
	var candidates mihomodeploy.LabCandidateListView
	call("ACTUAL_CANDIDATES", "viewer", "GET", prefix+"/candidates", nil, 200, &candidates)
	if len(candidates.Candidates) != 2 || candidates.WriteBlocked { report.FailureCode = "INITIAL_HEAD"; t.Fatal("actual admitted candidates not ready") }
	var candidate string
	for _, value := range candidates.Candidates { if !value.IsCurrent { candidate = value.RecordSHA256 } }
	if len(candidate) != 64 { report.FailureCode = "INITIAL_HEAD"; t.Fatal("actual candidate record missing") }
	before, err := mihomodeploy.ReadIsolatedLabAcceptanceState()
	if err != nil || before.Head.Generation != 1 || len(before.Completed) != 0 { report.FailureCode = "INITIAL_HEAD"; t.Fatal("actual owned bootstrap state missing") }
	report.Before = &before
	report.CallsBefore = mihomo.ObserveReloadCounters()
	create := mihomodeploy.LabCreateRequest{CandidateRecordSHA256: candidate, TTLSeconds: 300}
	// These two calls are forwarded directly; the transport fault is selected
	// only for the successful admin create below.
	faultMu.Lock(); dropPending = false; faultMu.Unlock()
	call("VIEWER_CREATE_DENIED", "viewer", "POST", prefix+"/deployments", create, 403, nil)
	call("SCOPE_CREATE_DENIED", "wrong-scope", "POST", prefix+"/deployments", create, 403, nil)
	faultMu.Lock(); dropPending = true; faultMu.Unlock()
	call("CREATE_RESPONSE_DROPPED_AFTER_HANDLER", "admin", "POST", prefix+"/deployments", create, 0, nil)
	faultMu.Lock(); report.Dropped = drop; faultMu.Unlock()
	if !report.Dropped.HandlerCompleted || report.Dropped.GeneratedStatus != 201 || !report.Dropped.ConnectionClosed { report.FailureCode = "DROP_FAULT"; t.Fatal("actual response-drop fault not observed") }
	var head mihomodeploy.LabHeadView
	call("FIND_OPERATION_AFTER_DROP", "admin", "GET", prefix+"/head", nil, 200, &head)
	if head.ActiveOperationID == nil { report.FailureCode = "OPERATION_DISCOVERY"; t.Fatal("durable operation not discoverable after dropped response") }
	id := *head.ActiveOperationID
	var planned mihomodeploy.LabDeploymentView
	call("INSPECT_CREATED_OPERATION", "admin", "GET", prefix+"/deployments/"+id, nil, 200, &planned)
	if planned.Phase != "PLANNED" || planned.Transport != nil { report.FailureCode = "PLAN"; t.Fatal("actual plan state mismatch") }
	approval := mihomodeploy.LabApprovalRequest{PlanSHA256: planned.PlanSHA256, Revision: planned.Revision}
	call("SELF_APPROVAL_DENIED", "admin", "POST", prefix+"/deployments/"+id+"/approvals", approval, 403, nil)
	var approved mihomodeploy.LabDeploymentView
	call("CURRENT_INDEPENDENT_APPROVAL", "approver", "POST", prefix+"/deployments/"+id+"/approvals", approval, 200, &approved)
	if approved.Phase != "APPROVED" || approved.Transport != nil { report.FailureCode = "APPROVAL"; t.Fatal("actual independent approval missing") }
	execute := mihomodeploy.LabExecuteRequest{PlanSHA256: approved.PlanSHA256, Revision: approved.Revision}
	var completed mihomodeploy.LabDeploymentView
	call("ACTUAL_EXECUTE", "admin", "POST", prefix+"/deployments/"+id+"/execute", execute, 200, &completed)
	if completed.Phase != "COMPLETED" || !completed.HeadAdvanced || completed.HeadGeneration != 2 || completed.Transport == nil ||
		completed.Transport.Origin != "ADAPTER" || completed.Transport.Result.StatusCode != 204 || completed.Observation == nil || !completed.Observation.LocalRouteVerified {
		report.FailureCode = "COMPLETE"; t.Fatal("actual product lifecycle did not complete")
	}
	after, err := mihomodeploy.ReadIsolatedLabAcceptanceState()
	if err != nil || after.Head.Generation != 2 || len(after.Completed) != 1 || after.Completed[0].OperationID != id ||
		after.Head.HeadSHA256 != completed.HeadSHA256 || after.Head.HeadSHA256 == before.Head.HeadSHA256 { report.FailureCode = "DURABLE_COMPLETE"; t.Fatal("actual typed head completion missing") }
	report.After = &after
	report.CallsAfter = mihomo.ObserveReloadCounters()
	if report.CallsAfter.ReloadInvocations != report.CallsBefore.ReloadInvocations+1 || report.CallsAfter.DoInvocations != report.CallsBefore.DoInvocations+1 {
		report.FailureCode = "DISPATCH_COUNT"; t.Fatal("actual reload or Do count mismatch")
	}
	var replayed mihomodeploy.LabDeploymentView
	call("REPLAY_EXECUTE_NO_NEW_SEND", "admin", "POST", prefix+"/deployments/"+id+"/execute", execute, 200, &replayed)
	if !replayed.Replayed || replayed.HeadSHA256 != completed.HeadSHA256 { report.FailureCode = "REPLAY"; t.Fatal("actual replay result mismatch") }
	replay, err := mihomodeploy.ReadIsolatedLabAcceptanceState()
	if err != nil || replay.ControlSHA256 != after.ControlSHA256 || replay.Head.HeadSHA256 != after.Head.HeadSHA256 || len(replay.Completed) != 1 { report.FailureCode = "REPLAY"; t.Fatal("replay changed the actual durable record") }
	report.Replay = &replay
	report.CallsReplay = mihomo.ObserveReloadCounters()
	if report.CallsReplay != report.CallsAfter { report.FailureCode = "REPLAY"; t.Fatal("replay invoked an additional reload or Do") }
	signals <- os.Interrupt
	select {
	case err := <-runtimeDone:
		runtimeObserved = true; report.RuntimeReturned = true
		if err != nil { report.RuntimeErrorClass = "FAILED"; report.FailureCode = "CLEANUP"; t.Fatal("actual product cleanup failed") }
		report.RuntimeErrorClass = "NONE"
	case <-time.After(20*time.Second): report.FailureCode = "CLEANUP"; t.Fatal("actual product stop not observed")
	}
	for _, port := range []int{28411, 28412, 28413, 28414, 28415} {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		fact := serviceClosedPort{Port: port, ConnectAttempted: true, ErrorClass: "UNCLASSIFIED"}
		if err == nil { fact.Accepted = true; _ = connection.Close() } else if errors.Is(err, syscall.ECONNREFUSED) { fact.ErrorClass = "CONNECTION_REFUSED" }
		report.ClosedPorts = append(report.ClosedPorts, fact)
		if fact.Accepted || fact.ErrorClass != "CONNECTION_REFUSED" { report.FailureCode = "CLEANUP"; t.Fatal("local listener closure was not proved") }
	}
	report.Outcome, report.FailureCode = "PASS", "NONE"
}
