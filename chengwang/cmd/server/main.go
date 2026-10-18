package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/control"
	"chengwang/internal/evidence"
	"chengwang/internal/operation"
	"chengwang/internal/store"
	"chengwang/internal/webui"
)

const gracefulShutdownTimeout = 10 * time.Second

const evidenceReverifyInterval = 30 * time.Second

type runOptions struct {
	listen          func(network, address string) (net.Listener, error)
	signals         <-chan os.Signal
	shutdownTimeout time.Duration
}

func main() {
	// run fully unwinds (including persistent-store Close calls) before the
	// process exits with a non-zero status. log.Fatal would call os.Exit from
	// inside the error branch and makes that lifecycle guarantee less obvious.
	if err := run(); err != nil {
		log.Printf("chengwang stopped with error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, shutdownSignals()...)
	defer signal.Stop(signals)

	return runWith(runOptions{
		listen:          net.Listen,
		signals:         signals,
		shutdownTimeout: gracefulShutdownTimeout,
	})
}

func runWith(options runOptions) error {
	if options.listen == nil {
		return errors.New("listen function is required")
	}
	if options.shutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}

	addr := envOr("CHENGWANG_ADDR", "127.0.0.1:7811")
	dataDir := envOr("CHENGWANG_DATA_DIR", "./data")
	identityStore, err := openIdentityStore(os.Getenv("CHENGWANG_IDENTITIES_FILE"))
	if err != nil {
		return fmt.Errorf("initialize identity store: %w", err)
	}
	adminToken := os.Getenv("CHENGWANG_ADMIN_TOKEN")
	tlsConfig, err := loadTLSConfig(os.Getenv("CHENGWANG_TLS_CERT_FILE"), os.Getenv("CHENGWANG_TLS_KEY_FILE"))
	if err != nil {
		return fmt.Errorf("initialize TLS: %w", err)
	}
	if (identityStore != nil || adminToken != "") && tlsConfig == nil && !listenerAddressIsLoopback(addr) {
		return errors.New("configured bearer credentials require TLS or a loopback listener")
	}
	managementScope := authz.ResourceScope{
		TenantID:    os.Getenv("CHENGWANG_MANAGEMENT_TENANT_ID"),
		SiteID:      os.Getenv("CHENGWANG_MANAGEMENT_SITE_ID"),
		ObjectType:  "control-plane",
		ObjectID:    envOr("CHENGWANG_MANAGEMENT_OBJECT_ID", "local"),
		Environment: envOr("CHENGWANG_MODE", "shadow"),
	}
	if identityStore != nil && strings.TrimSpace(managementScope.TenantID) == "" {
		return errors.New("CHENGWANG_MANAGEMENT_TENANT_ID is required when identities are configured")
	}
	operationWritesEnabled, err := strictBoolEnv("CHENGWANG_OPERATION_WRITES_ENABLED")
	if err != nil {
		return fmt.Errorf("initialize operation write gate: %w", err)
	}
	versions, err := store.NewVersionStore(dataDir)
	if err != nil {
		return fmt.Errorf("initialize version store: %w", err)
	}
	evidenceStore, err := openEvidenceStore(dataDir)
	if err != nil {
		return fmt.Errorf("initialize evidence store: %w", err)
	}
	defer evidenceStore.Close()
	reverifyContext, stopReverify := context.WithCancel(context.Background())
	reverifyDone := startEvidenceReverification(reverifyContext, evidenceStore, evidenceReverifyInterval)
	defer func() {
		stopReverify()
		<-reverifyDone
	}()
	operationStore, err := openOperationStore(dataDir)
	if err != nil {
		return fmt.Errorf("initialize operation store: %w", err)
	}
	defer operationStore.Close()
	controlService, err := control.New(operationStore, evidenceStore)
	if err != nil {
		return fmt.Errorf("initialize operation control: %w", err)
	}

	var mihomoReader api.MihomoReader
	if controllerURL := os.Getenv("CHENGWANG_MIHOMO_URL"); controllerURL != "" {
		client, err := mihomo.NewWithOptions(controllerURL, os.Getenv("CHENGWANG_MIHOMO_TOKEN"), 5*time.Second, mihomo.ClientOptions{
			AllowedHosts: splitCSV(os.Getenv("CHENGWANG_MIHOMO_ALLOWED_HOSTS")),
		})
		if err != nil {
			return fmt.Errorf("initialize mihomo read-only adapter: %w", err)
		}
		mihomoReader = client
	}

	var handler http.Handler = api.New(api.Options{
		Mode:                   envOr("CHENGWANG_MODE", "shadow"),
		AdminToken:             adminToken,
		AllowPublish:           os.Getenv("CHENGWANG_ALLOW_PUBLISH") == "true",
		Versions:               versions,
		Mihomo:                 mihomoReader,
		Evidence:               evidenceStore,
		Authn:                  optionalAuthenticator(identityStore),
		Operations:             operationStore,
		Control:                controlService,
		OperationWritesEnabled: operationWritesEnabled,
		ManagementScope:        managementScope,
		EvidenceMaxAge:         2 * time.Minute,
	})
	if webDir := os.Getenv("CHENGWANG_WEB_DIR"); webDir != "" {
		handler, err = webui.New(webDir, handler)
		if err != nil {
			return fmt.Errorf("initialize web console: %w", err)
		}
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := options.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	scheme := "http"
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
		scheme = "https"
	}
	log.Printf("chengwang listening on %s://%s (mode=%s)", scheme, listener.Addr(), envOr("CHENGWANG_MODE", "shadow"))
	return serveUntilShutdown(server, listener, options.signals, options.shutdownTimeout)
}

func loadTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("CHENGWANG_TLS_CERT_FILE and CHENGWANG_TLS_KEY_FILE must be configured together")
	}
	if certPath == "" {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

func listenerAddressIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func startEvidenceReverification(ctx context.Context, store *evidence.Store, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = store.Verify()
			}
		}
	}()
	return done
}

func serveUntilShutdown(server *http.Server, listener net.Listener, signals <-chan os.Signal, timeout time.Duration) error {
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case received, ok := <-signals:
		if ok {
			log.Printf("received shutdown signal %s", received)
		} else {
			log.Printf("shutdown signal channel closed")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		// Shutdown can time out while a handler is still active. Close forces the
		// listener/connections down so runWith can unwind and close its stores.
		closeErr := server.Close()
		if closeErr != nil {
			return errors.Join(fmt.Errorf("graceful shutdown: %w", err), fmt.Errorf("force close: %w", closeErr))
		}
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
	log.Printf("chengwang shutdown complete")
	return nil
}

func openEvidenceStore(dataDir string) (*evidence.Store, error) {
	return evidence.Open(filepath.Join(dataDir, "evidence"))
}

func openOperationStore(dataDir string) (*operation.FileStore, error) {
	return operation.NewFileStore(filepath.Join(dataDir, "operations"))
}

func openIdentityStore(path string) (*authn.Store, error) {
	if path == "" {
		return nil, nil
	}
	return authn.Open(path)
}

// optionalAuthenticator prevents a typed nil *authn.Store from becoming a
// non-nil interface. Without this boundary, an absent identity file would be
// reported as configured even though every credential must fail.
func optionalAuthenticator(store *authn.Store) api.Authenticator {
	if store == nil {
		return nil
	}
	return store
}

func strictBoolEnv(key string) (bool, error) {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" || value == "false" {
		return false, nil
	}
	if value == "true" {
		return true, nil
	}
	return false, fmt.Errorf("%s must be exactly true or false", key)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
