package serverruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/evidence"
)

func runtimeD9Config(t *testing.T) Config {
	t.Helper()
	return Config{Addr: "127.0.0.1:0", DataDir: t.TempDir(), Mode: "candidate", TenantID: "runtime-tenant", SiteID: "runtime-site", ManagementObjectID: "runtime-control"}
}

func runtimeD9Listener(t *testing.T) (func(string, string) (net.Listener, error), <-chan string) {
	t.Helper()
	address := make(chan string, 1)
	return func(network, addr string) (net.Listener, error) {
		listener, err := net.Listen(network, addr)
		if err == nil {
			address <- listener.Addr().String()
		}
		return listener, err
	}, address
}

func runtimeD9Address(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case address := <-ch:
		return address
	case <-time.After(3 * time.Second):
		t.Fatal("real runtime did not listen")
		return ""
	}
}

func runtimeD9Result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(4 * time.Second):
		t.Fatal("real runtime failed to join")
		return nil
	}
}

func TestServerRuntimeD9TypedConfigDoesNotReadOrMutateEnvironment(t *testing.T) {
	c := runtimeD9Config(t)
	t.Setenv("CHENGWANG_OPERATION_WRITES_ENABLED", "invalid-but-irrelevant-to-explicit-config")
	t.Setenv("CHENGWANG_ADDR", "invalid-but-not-used")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen, address := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: time.Second, WriteTimeout: 3 * time.Minute, MaxHeaderBytes: 16 << 10})
	}()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("http://" + runtimeD9Address(t, address) + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || !json.Valid(raw) {
		t.Fatal("actual full product health failed")
	}
	cancel()
	if err := runtimeD9Result(t, done); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CHENGWANG_ADDR") != "invalid-but-not-used" {
		t.Fatal("runtime mutated process environment")
	}
	audit, err := OpenEvidenceStore(c.DataDir)
	if err != nil {
		t.Fatal("audit lock retained", err)
	}
	defer audit.Close()
	ops, err := OpenOperationStore(c.DataDir)
	if err != nil {
		t.Fatal("operation lock retained", err)
	}
	defer ops.Close()
}

func TestServerRuntimeD9AcceptedHandlersDrainBeforeStoresClose(t *testing.T) {
	c := runtimeD9Config(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	listen, address := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: 2 * time.Second, WebFactory: func(api http.Handler) (http.Handler, error) {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/accepted-block" {
					api.ServeHTTP(w, r)
					return
				}
				close(entered)
				<-r.Context().Done()
				close(canceled)
				<-release
				w.WriteHeader(204)
			}), nil
		}})
	}()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	requestDone := make(chan struct{})
	url := "http://" + runtimeD9Address(t, address) + "/accepted-block"
	go func() {
		defer close(requestDone)
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(url)
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real accepted HTTP handler missing")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel accepted request")
	}
	select {
	case <-done:
		t.Fatal("runtime returned while accepted handler still active")
	default:
	}
	if audit, err := OpenEvidenceStore(c.DataDir); err == nil {
		_ = audit.Close()
		t.Fatal("audit closed before request drain")
	}
	if ops, err := OpenOperationStore(c.DataDir); err == nil {
		_ = ops.Close()
		t.Fatal("operation store closed before request drain")
	}
	close(release)
	released = true
	if err := runtimeD9Result(t, done); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("client request not joined")
	}
	audit, err := OpenEvidenceStore(c.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = audit.Close()
	ops, err := OpenOperationStore(c.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = ops.Close()
}

func TestServerRuntimeD9FactoryRecoveryPrecedesListenerAndUsesSharedScope(t *testing.T) {
	c := runtimeD9Config(t)
	private := t.TempDir()
	if os.Chmod(private, 0700) != nil {
		t.Fatal("private fixture")
	}
	profile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	// Empty real identity profiles are valid but grant nobody authority. This
	// test exercises construction ordering, not a fake verifier or permission.
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	c.IdentitiesFile = filepath.Join(private, "identities.json")
	if os.WriteFile(c.IdentitiesFile, raw, 0600) != nil {
		t.Fatal("identity fixture")
	}
	called, closed := false, false
	err = RunWith(Options{Config: &c, Listen: func(string, string) (net.Listener, error) {
		t.Error("listener reached before successful factory recovery")
		return nil, errors.New("unexpected listener")
	}, ShutdownTimeout: time.Second, TrustFactory: func(ctx context.Context, deps TrustDependencies) (TrustComponent, error) {
		called = true
		if deps.TenantID != c.TenantID || deps.SiteID != c.SiteID || deps.Environment != c.Mode || deps.AuditDir != filepath.Join(c.DataDir, "evidence") || ctx.Err() != nil {
			t.Error("trusted dependencies not fixed")
		}
		report, err := deps.Audit.Verify()
		if err != nil || !report.Valid || report.Count != 0 {
			t.Error("shared audit unavailable before recovery")
		}
		return TrustComponent{Close: func() error { closed = true; _, err := deps.Audit.Verify(); return err }}, nil
	}})
	if err == nil || !called || !closed {
		t.Fatal("incomplete factory did not fail before listener or close its own component")
	}
	audit, err := evidence.Open(filepath.Join(c.DataDir, "evidence"))
	if err != nil {
		t.Fatal("shared audit remained locked", err)
	}
	_ = audit.Close()
}

func TestServerRuntimeD9ValidationBeforeDataAndNilTrustRemainUnavailable(t *testing.T) {
	for _, kind := range []string{"negative-write-timeout", "negative-header-limit", "missing-real-identity", "cleartext-non-loopback"} {
		t.Run(kind, func(t *testing.T) {
			c := runtimeD9Config(t)
			c.DataDir = filepath.Join(c.DataDir, "must-not-exist")
			o := Options{Config: &c, Listen: net.Listen, ShutdownTimeout: time.Second}
			switch kind {
			case "negative-write-timeout":
				o.WriteTimeout = -time.Second
			case "negative-header-limit":
				o.MaxHeaderBytes = -1
			case "missing-real-identity":
				o.TrustFactory = func(context.Context, TrustDependencies) (TrustComponent, error) {
					t.Error("factory called before identity validation")
					return TrustComponent{}, nil
				}
			case "cleartext-non-loopback":
				c.Addr = "0.0.0.0:0"
				c.AdminToken = "test-only-not-a-live-token"
			}
			if RunWith(o) == nil {
				t.Fatal("unsafe startup accepted")
			}
			if _, err := os.Stat(c.DataDir); !os.IsNotExist(err) {
				t.Fatal("rejected startup created data")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := runtimeD9Config(t)
	listen, address := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: time.Second})
	}()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	r, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("http://" + runtimeD9Address(t, address) + "/api/v1/image-trust")
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode == 200 {
		t.Fatal("default nil backend became available")
	}
	cancel()
	if err := runtimeD9Result(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestServerRuntimeD9AdmissionStopsBeforeWait(t *testing.T) {
	called := false
	a := &admissionHandler{next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })}
	a.stop()
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	a.active.Wait()
	if called || w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("stopped runtime admitted a new handler")
	}
}
