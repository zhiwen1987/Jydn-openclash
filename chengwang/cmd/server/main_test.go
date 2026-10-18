package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingListener struct {
	err error
}

func (listener *failingListener) Accept() (net.Conn, error) { return nil, listener.err }
func (listener *failingListener) Close() error              { return nil }
func (listener *failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestOpenEvidenceStoreUsesDedicatedDataSubdirectory(t *testing.T) {
	dataDir := t.TempDir()
	store, err := openEvidenceStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.Verify()
	if err != nil || !report.Valid || report.Count != 0 {
		t.Fatalf("new evidence store is not valid: report=%+v err=%v", report, err)
	}
	for _, name := range []string{"events.jsonl", "checkpoint.json"} {
		if _, err := os.Stat(filepath.Join(dataDir, "evidence", name)); err != nil {
			t.Fatalf("evidence file %q was not created in dedicated directory: %v", name, err)
		}
	}
}

func TestOpenEvidenceStoreFailsClosedOnExistingCorruption(t *testing.T) {
	dataDir := t.TempDir()
	store, err := openEvidenceStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(dataDir, "evidence", "checkpoint.json")
	if err := os.WriteFile(checkpoint, []byte(`{"count":1,"lastHash":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openEvidenceStore(dataDir); err == nil {
		t.Fatal("expected existing evidence corruption to fail closed")
	}
}

func TestStrictOperationWriteEnvironment(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
		ok    bool
	}{
		{value: "", want: false, ok: true},
		{value: "false", want: false, ok: true},
		{value: "true", want: true, ok: true},
		{value: "TRUE", ok: false},
		{value: "1", ok: false},
		{value: " true", ok: false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("CHENGWANG_OPERATION_WRITES_ENABLED", tc.value)
			got, err := strictBoolEnv("CHENGWANG_OPERATION_WRITES_ENABLED")
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("value %q: got=%v err=%v", tc.value, got, err)
			}
		})
	}
}

func TestIdentityStoreIsOptionalButConfiguredInvalidFileFails(t *testing.T) {
	store, err := openIdentityStore("")
	if err != nil || store != nil {
		t.Fatalf("absent identity file must keep anonymous read-only startup available: store=%v err=%v", store, err)
	}
	if optionalAuthenticator(store) != nil {
		t.Fatal("absent identity store became a non-nil authenticator interface")
	}
	directory := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "identities.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"identities":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openIdentityStore(path); err == nil {
		t.Fatal("configured invalid identity file must fail startup")
	}
}

func TestOpenOperationStoreUsesDedicatedPersistentDirectory(t *testing.T) {
	dataDir := t.TempDir()
	first, err := openOperationStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "operations", "operations.json")); err != nil {
		t.Fatalf("operation snapshot not created in dedicated directory: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openOperationStore(dataDir)
	if err != nil {
		t.Fatalf("operation store did not reopen after restart boundary: %v", err)
	}
	defer reopened.Close()
	items, err := reopened.List()
	if err != nil || len(items) != 0 {
		t.Fatalf("unexpected reopened operation store: items=%v err=%v", items, err)
	}
}

func TestRunRejectsInvalidWriteGateBeforeCreatingStores(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "must-not-exist")
	t.Setenv("CHENGWANG_DATA_DIR", dataDir)
	t.Setenv("CHENGWANG_IDENTITIES_FILE", "")
	t.Setenv("CHENGWANG_OPERATION_WRITES_ENABLED", "yes")
	if err := run(); err == nil {
		t.Fatal("invalid operation write gate was accepted")
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("invalid startup mutated data directory: %v", err)
	}
}

func TestTLSConfigurationAndLoopbackBoundary(t *testing.T) {
	if _, err := loadTLSConfig("cert.pem", ""); err == nil {
		t.Fatal("incomplete TLS pair was accepted")
	}
	for _, tc := range []struct {
		address  string
		loopback bool
	}{
		{address: "127.0.0.1:7811", loopback: true},
		{address: "[::1]:7811", loopback: true},
		{address: "0.0.0.0:7811", loopback: false},
		{address: ":7811", loopback: false},
		{address: "localhost:7811", loopback: false},
	} {
		if got := listenerAddressIsLoopback(tc.address); got != tc.loopback {
			t.Fatalf("listenerAddressIsLoopback(%q) = %t", tc.address, got)
		}
	}
}

func TestRunRejectsBearerCredentialsOnNonLoopbackCleartextBeforeCreatingStores(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "must-not-exist")
	t.Setenv("CHENGWANG_ADDR", "0.0.0.0:7811")
	t.Setenv("CHENGWANG_DATA_DIR", dataDir)
	t.Setenv("CHENGWANG_IDENTITIES_FILE", "")
	t.Setenv("CHENGWANG_ADMIN_TOKEN", "configured-placeholder")
	t.Setenv("CHENGWANG_TLS_CERT_FILE", "")
	t.Setenv("CHENGWANG_TLS_KEY_FILE", "")
	if err := run(); err == nil || !strings.Contains(err.Error(), "require TLS") {
		t.Fatalf("cleartext credential startup error = %v", err)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("rejected startup mutated data directory: %v", err)
	}
}

func TestServeUntilShutdownPropagatesListenerFailure(t *testing.T) {
	sentinel := errors.New("accept failed")
	server := &http.Server{Handler: http.NotFoundHandler()}
	err := serveUntilShutdown(server, &failingListener{err: sentinel}, nil, time.Second)
	if !errors.Is(err, sentinel) {
		t.Fatalf("listener failure was not propagated: %v", err)
	}
}

func TestServeUntilShutdownStopsAfterInjectedSignal(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})}
	signals := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(server, listener, signals, time.Second)
	}()

	response, err := (&http.Client{Timeout: time.Second}).Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("server did not become reachable: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status before shutdown: %d", response.StatusCode)
	}

	signals <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("graceful shutdown did not finish")
	}
}

func TestRunWithSignalUnwindsPersistentStores(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("CHENGWANG_ADDR", "127.0.0.1:0")
	t.Setenv("CHENGWANG_DATA_DIR", dataDir)
	t.Setenv("CHENGWANG_IDENTITIES_FILE", "")
	t.Setenv("CHENGWANG_OPERATION_WRITES_ENABLED", "false")
	t.Setenv("CHENGWANG_MIHOMO_URL", "")
	t.Setenv("CHENGWANG_WEB_DIR", "")
	t.Setenv("CHENGWANG_MODE", "shadow")
	t.Setenv("CHENGWANG_ADMIN_TOKEN", "")
	t.Setenv("CHENGWANG_ALLOW_PUBLISH", "false")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- runWith(runOptions{
			listen: func(_, _ string) (net.Listener, error) {
				return listener, nil
			},
			signals:         signals,
			shutdownTimeout: time.Second,
		})
	}()

	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, requestErr := client.Get("http://" + listener.Addr().String() + "/api/v1/health")
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runWith did not start serving: %v", requestErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	signals <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runWith did not shut down cleanly: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runWith did not return after shutdown signal")
	}

	evidenceStore, err := openEvidenceStore(dataDir)
	if err != nil {
		t.Fatalf("evidence store lock was not released: %v", err)
	}
	if err := evidenceStore.Close(); err != nil {
		t.Fatal(err)
	}
	operationStore, err := openOperationStore(dataDir)
	if err != nil {
		t.Fatalf("operation store lock was not released: %v", err)
	}
	if err := operationStore.Close(); err != nil {
		t.Fatal(err)
	}
}
