// Package serverruntime shares product composition without importing any
// optional verifier SDK into the Go 1.23 parent module.
package serverruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/control"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	"chengwang/internal/observation"
	"chengwang/internal/operation"
	"chengwang/internal/overview"
	"chengwang/internal/probe"
	"chengwang/internal/probeview"
	"chengwang/internal/store"
	"chengwang/internal/subscription"
	"chengwang/internal/subscriptionctl"
	"chengwang/internal/subscriptionpolicy"
	"chengwang/internal/webui"
)

type Config struct {
	Addr, DataDir, IdentitiesFile, AdminToken       string
	TLSCertFile, TLSKeyFile                         string
	TenantID, SiteID, ManagementObjectID            string
	Mode, WebDir                                    string
	AllowPublish, OperationWritesEnabled            bool
	LiveOverviewEnabled                             bool
	MihomoLabEnabled                                bool
	MihomoURL, MihomoToken                          string
	MihomoAllowedHosts                              []string
	ObservationInterval, ObservationTTL             time.Duration
	ProbeReadEnabled                                bool
	ProbeCatalogFile, ProbeSpoolDir                 string
	ProbePollInterval, ProbeCacheMaxAge             time.Duration
	SubscriptionsEnabled, SubscriptionWritesEnabled bool
	SubscriptionPolicyFile                          string
}

type TrustDependencies struct {
	Audit                         *evidence.Store
	AuditDir                      string
	TenantID, SiteID, Environment string
}

// A factory cannot replace identity resolution, API options or unrelated write
// gates. Construction/reconciliation finishes before any worker starts. Audit
// is borrowed: the runtime, not the factory, owns its lifetime.
type TrustFactory func(context.Context, TrustDependencies) (TrustComponent, error)
type TrustComponent struct {
	Backend       imagetrust.Backend
	WritesEnabled bool
	Run           func(context.Context) error
	Close         func() error
}
type Options struct {
	Listen          func(string, string) (net.Listener, error)
	Signals         <-chan os.Signal
	ShutdownTimeout time.Duration
	WriteTimeout    time.Duration // zero: 15s normally, 30s with subscriptions enabled
	MaxHeaderBytes  int           // zero preserves net/http's original default
	Context         context.Context
	Config          *Config
	TrustFactory    TrustFactory
	WebFactory      func(http.Handler) (http.Handler, error)
}

func ConfigFromEnvironment() (Config, error) {
	c := Config{Addr: envOr("CHENGWANG_ADDR", "127.0.0.1:7811"), DataDir: envOr("CHENGWANG_DATA_DIR", "./data"), IdentitiesFile: os.Getenv("CHENGWANG_IDENTITIES_FILE"), AdminToken: os.Getenv("CHENGWANG_ADMIN_TOKEN"), TLSCertFile: os.Getenv("CHENGWANG_TLS_CERT_FILE"), TLSKeyFile: os.Getenv("CHENGWANG_TLS_KEY_FILE"), TenantID: os.Getenv("CHENGWANG_MANAGEMENT_TENANT_ID"), SiteID: os.Getenv("CHENGWANG_MANAGEMENT_SITE_ID"), ManagementObjectID: envOr("CHENGWANG_MANAGEMENT_OBJECT_ID", "local"), Mode: envOr("CHENGWANG_MODE", "shadow"), WebDir: os.Getenv("CHENGWANG_WEB_DIR"), AllowPublish: os.Getenv("CHENGWANG_ALLOW_PUBLISH") == "true", MihomoURL: os.Getenv("CHENGWANG_MIHOMO_URL"), MihomoToken: os.Getenv("CHENGWANG_MIHOMO_TOKEN"), MihomoAllowedHosts: splitCSV(os.Getenv("CHENGWANG_MIHOMO_ALLOWED_HOSTS"))}
	var err error
	c.OperationWritesEnabled, err = StrictBoolEnv("CHENGWANG_OPERATION_WRITES_ENABLED")
	if err != nil {
		return Config{}, fmt.Errorf("initialize operation write gate: %w", err)
	}
	if c.MihomoURL != "" {
		c.ObservationInterval, err = durationEnv("CHENGWANG_OBSERVATION_INTERVAL", 30*time.Second)
		if err != nil {
			return Config{}, err
		}
		c.ObservationTTL, err = durationEnv("CHENGWANG_OBSERVATION_TTL", 2*time.Minute)
		if err != nil {
			return Config{}, err
		}
	}
	if err := probeConfigFromEnvironment(&c); err != nil {
		return Config{}, err
	}
	if err := subscriptionConfigFromEnvironment(&c); err != nil {
		return Config{}, err
	}
	if err := overviewConfigFromEnvironment(&c); err != nil {
		return Config{}, err
	}
	if err := mihomoLabConfigFromEnvironment(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func RunWith(options Options) (result error) {
	if options.Listen == nil || options.ShutdownTimeout <= 0 || options.WriteTimeout < 0 || options.MaxHeaderBytes < 0 {
		return errors.New("listener and positive shutdown timeout are required")
	}
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return errors.New("runtime context already canceled")
	}
	c := Config{}
	if options.Config == nil {
		var err error
		c, err = ConfigFromEnvironment()
		if err != nil {
			return err
		}
	} else {
		c = *options.Config
		c.MihomoAllowedHosts = append([]string(nil), c.MihomoAllowedHosts...)
	}
	if err := validateProbeConfig(c); err != nil {
		return err
	}
	if c.Addr == "" {
		c.Addr = "127.0.0.1:7811"
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.Mode == "" {
		c.Mode = "shadow"
	}
	if c.ManagementObjectID == "" {
		c.ManagementObjectID = "local"
	}
	if err := validateSubscriptionConfig(c); err != nil {
		return err
	}
	if err := validateMihomoLabConfig(c); err != nil {
		return err
	}
	if c.MihomoLabEnabled && (options.TrustFactory != nil || (options.WriteTimeout > 0 && options.WriteTimeout < 45*time.Second)) {
		return errMihomoLabRuntime
	}
	if c.SubscriptionsEnabled && options.WriteTimeout > 0 && options.WriteTimeout < 30*time.Second {
		return errors.New("subscription response timeout must be at least 30 seconds")
	}
	identity, err := OpenIdentityStore(c.IdentitiesFile)
	if err != nil {
		return fmt.Errorf("initialize identity store: %w", err)
	}
	tlsConfig, err := LoadTLSConfig(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("initialize TLS: %w", err)
	}
	if (identity != nil || c.AdminToken != "" || options.TrustFactory != nil) && tlsConfig == nil && !ListenerAddressIsLoopback(c.Addr) {
		return errors.New("configured bearer credentials require TLS or a loopback listener")
	}
	if identity != nil && strings.TrimSpace(c.TenantID) == "" {
		return errors.New("management tenant is required when identities are configured")
	}
	if c.SubscriptionsEnabled && (identity == nil || tlsConfig == nil) {
		return errors.New("subscription admission requires real identities and TLS")
	}
	if options.TrustFactory != nil && (identity == nil || strings.TrimSpace(c.TenantID) == "" || strings.TrimSpace(c.SiteID) == "") {
		return errors.New("trusted composition requires real identity and fixed management scope")
	}
	if c.MihomoURL != "" && (c.ObservationInterval <= 0 || c.ObservationTTL <= 0) {
		return errors.New("observation intervals must be positive")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var probes *probeview.Provider
	if c.ProbeReadEnabled {
		uid, gid := os.Geteuid(), os.Getegid()
		if uid < 0 || gid < 0 {
			return errors.New("initialize probe reader failed")
		}
		catalog, err := probe.ReadCatalogSecure(ctx, c.ProbeCatalogFile, probe.SecureFileOwner{UID: uint32(uid), GID: uint32(gid)})
		if err != nil {
			return errors.New("initialize probe reader failed")
		}
		probes, err = probeview.New(probeview.Config{Catalog: catalog, SpoolDir: c.ProbeSpoolDir, PollInterval: c.ProbePollInterval, CacheMaxAge: c.ProbeCacheMaxAge})
		if err != nil {
			return errors.New("initialize probe reader failed")
		}
	}
	// Never close databases beneath still-running handlers or workers. A
	// timeout leaves resources retained and reports failure; the failed process
	// must be terminated, not reused as a successfully stopped runtime.
	quiescent := true
	var closers []func() error
	defer func() {
		if !quiescent {
			return
		}
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i](); err != nil {
				result = errors.Join(result, errors.New("runtime resource close failed"))
			}
		}
	}()
	versions, err := store.NewVersionStore(c.DataDir)
	if err != nil {
		return fmt.Errorf("initialize version store: %w", err)
	}
	audit, err := OpenEvidenceStore(c.DataDir)
	if err != nil {
		return fmt.Errorf("initialize evidence store: %w", err)
	}
	closers = append(closers, audit.Close)
	var mihomoLab *MihomoLabRuntime
	if c.MihomoLabEnabled {
		mihomoLab, err = OpenMihomoLabRuntime(ctx, c)
		if mihomoLab != nil {
			closers = append(closers, func() error {
				closing, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				return mihomoLab.Close(closing)
			})
		}
		if err != nil {
			return errMihomoLabRuntime
		}
		if err := bindLabContinuousRecoveryHarness(mihomoLab); err != nil {
			return errMihomoLabRuntime
		}
	}
	var subscriptions subscriptionctl.Backend
	if c.SubscriptionsEnabled {
		var policies subscriptionctl.PolicyProvider
		if c.SubscriptionPolicyFile != "" {
			catalog, loadErr := subscriptionpolicy.LoadSecure(ctx, c.SubscriptionPolicyFile, subscriptionpolicy.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())})
			if loadErr != nil {
				return errors.New("initialize subscription policy failed")
			}
			if catalog.Scope() != (subscription.Scope{TenantID: c.TenantID, SiteID: c.SiteID, Environment: c.Mode}) {
				return errors.New("subscription policy scope mismatch")
			}
			policies = catalog
		}
		path, pathErr := filepath.Abs(filepath.Join(c.DataDir, "subscriptions"))
		if pathErr != nil {
			return errors.New("initialize subscription storage failed")
		}
		inventory, openErr := subscription.OpenStore(path)
		if openErr != nil {
			return errors.New("initialize subscription storage failed")
		}
		closers = append(closers, inventory.Close)
		application, applicationErr := subscriptionctl.New(ctx, subscriptionctl.Config{Scope: authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, Environment: c.Mode, ObjectType: "subscription-store", ObjectID: c.ManagementObjectID}, Store: inventory, Audit: audit, Policies: policies, WritesEnabled: c.SubscriptionWritesEnabled})
		if applicationErr != nil {
			return errors.New("initialize subscription recovery failed")
		}
		subscriptions = application
	}
	var trust TrustComponent
	if options.TrustFactory != nil {
		trust, err = options.TrustFactory(ctx, TrustDependencies{Audit: audit, AuditDir: filepath.Join(c.DataDir, "evidence"), TenantID: c.TenantID, SiteID: c.SiteID, Environment: c.Mode})
		if err != nil {
			return errors.New("initialize trusted component failed")
		}
		if trust.Close != nil {
			closers = append(closers, trust.Close)
		}
		if nilBackend(trust.Backend) || trust.Run == nil || trust.Close == nil {
			return errors.New("trusted component is incomplete")
		}
		scope := trust.Backend.Scope()
		if scope.TenantID != c.TenantID || scope.SiteID != c.SiteID || scope.Environment != c.Mode || scope.ObjectType != "image-trust" || !hexID(scope.ObjectID) {
			return errors.New("trusted component fixed scope mismatch")
		}
	}
	ops, err := OpenOperationStore(c.DataDir)
	if err != nil {
		return fmt.Errorf("initialize operation store: %w", err)
	}
	closers = append(closers, ops.Close)
	controller, err := control.New(ops, audit)
	if err != nil {
		return fmt.Errorf("initialize operation control: %w", err)
	}
	var reader api.MihomoReader
	var observer api.ObservationReader
	var collector *observation.Collector
	if c.MihomoURL != "" {
		client, err := mihomo.NewWithOptions(c.MihomoURL, c.MihomoToken, 5*time.Second, mihomo.ClientOptions{AllowedHosts: c.MihomoAllowedHosts})
		if err != nil {
			return errors.New("initialize read-only Mihomo adapter failed")
		}
		serialized, err := observation.NewSerializedReader(client)
		if err != nil {
			return errors.New("initialize shared Mihomo reader failed")
		}
		reader = serialized
		observations, err := observation.OpenStore(filepath.Join(c.DataDir, "observations"), 4096)
		if err != nil {
			return errors.New("initialize observation store failed")
		}
		closers = append(closers, observations.Close)
		collector, err = observation.NewCollector(serialized, observations, c.ObservationInterval, c.ObservationTTL)
		if err != nil {
			return errors.New("initialize observation collector failed")
		}
		observer = collector
	}
	management := authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: "control-plane", ObjectID: c.ManagementObjectID, Environment: c.Mode}
	var probeReader api.ProbeReader
	if probes != nil {
		probeReader = probes // Do not put a typed nil pointer in the API interface.
	}
	var actualOverview overview.SnapshotProvider
	if c.LiveOverviewEnabled {
		actualOverview, err = overview.New(overview.Config{Mode: c.Mode, Observation: observer, Probes: probeReader, SubscriptionConfigured: c.SubscriptionsEnabled})
		if err != nil {
			return errors.New("initialize actual overview failed")
		}
	}
	apiOptions := api.Options{Mode: c.Mode, AdminToken: c.AdminToken, AllowPublish: c.AllowPublish, Versions: versions, Mihomo: reader, Evidence: audit, Authn: OptionalAuthenticator(identity), Operations: ops, Control: controller, OperationWritesEnabled: c.OperationWritesEnabled, ManagementScope: management, EvidenceMaxAge: 2 * time.Minute, Observation: observer, Overview: actualOverview, Probes: probeReader, ImageTrust: trust.Backend, ImageTrustWritesEnabled: trust.WritesEnabled, Subscriptions: subscriptions, SubscriptionWritesEnabled: c.SubscriptionWritesEnabled}
	apiOptions = mihomoLab.ApplyAPIOptions(apiOptions)
	var handler http.Handler = api.New(apiOptions)
	if options.WebFactory != nil {
		handler, err = options.WebFactory(handler)
	} else if c.WebDir != "" {
		handler, err = webui.New(c.WebDir, handler)
	}
	if err != nil || handler == nil {
		return errors.New("initialize web console failed")
	}
	admission := &admissionHandler{next: handler}
	writeTimeout := options.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 15 * time.Second
		if c.SubscriptionsEnabled {
			writeTimeout = 30 * time.Second
		}
		if c.MihomoLabEnabled {
			writeTimeout = 45 * time.Second
		}
	}
	server := &http.Server{Handler: admission, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: writeTimeout, MaxHeaderBytes: options.MaxHeaderBytes, IdleTimeout: 60 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := options.Listen("tcp", c.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	var workers sync.WaitGroup
	workerCount := 1 // Evidence reverification is always present.
	if collector != nil {
		workerCount++
	}
	if trust.Run != nil {
		workerCount++
	}
	if probes != nil {
		workerCount++
	}
	workerErrors := make(chan error, workerCount)
	startWorker := func(run func(context.Context) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_ = run(ctx)
			if ctx.Err() == nil {
				select {
				case workerErrors <- errors.New("runtime worker exited unexpectedly"):
				case <-ctx.Done():
				}
			}
		}()
	}
	// All constructors and recovery finish before any worker starts.
	quiescent = false
	startWorker(func(ctx context.Context) error { <-StartEvidenceReverification(ctx, audit, 30*time.Second); return nil })
	if collector != nil {
		startWorker(func(ctx context.Context) error { <-collector.Run(ctx); return nil })
	}
	if trust.Run != nil {
		startWorker(trust.Run)
	}
	if probes != nil {
		startWorker(probes.Run)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	log.Printf("chengwang listening (mode=%s)", c.Mode)
	serveReturned := false
	select {
	case err := <-served:
		serveReturned = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			result = fmt.Errorf("serve HTTP: %w", err)
		}
	case <-options.Signals:
	case <-ctx.Done():
	case result = <-workerErrors:
	}
	admission.stop()
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), options.ShutdownTimeout)
	defer stop()
	if result != nil {
		_ = server.Close()
	} else if err := server.Shutdown(shutdown); err != nil {
		result = fmt.Errorf("graceful shutdown: %w", err)
		_ = server.Close()
	}
	if !serveReturned {
		select {
		case err := <-served:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				result = errors.Join(result, fmt.Errorf("serve HTTP: %w", err))
			}
		case <-shutdown.Done():
			return errors.Join(result, errors.New("HTTP serve did not stop; resources retained"))
		}
	}
	drained := make(chan struct{})
	go func() { admission.active.Wait(); workers.Wait(); close(drained) }()
	select {
	case <-drained:
		quiescent = true
		return result
	default:
	}
	select {
	case <-drained:
		quiescent = true
		return result
	case <-shutdown.Done():
		return errors.Join(result, errors.New("runtime handlers or workers did not drain; resources retained"))
	}
}

type admissionHandler struct {
	mu      sync.Mutex
	stopped bool
	active  sync.WaitGroup
	next    http.Handler
}

func (a *admissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "runtime stopping", http.StatusServiceUnavailable)
		return
	}
	a.active.Add(1)
	a.mu.Unlock()
	defer a.active.Done()
	a.next.ServeHTTP(w, r)
}
func (a *admissionHandler) stop() { a.mu.Lock(); a.stopped = true; a.mu.Unlock() }
func nilBackend(b imagetrust.Backend) bool {
	if b == nil {
		return true
	}
	v := reflect.ValueOf(b)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func hexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Exported only within the parent internal tree, these retain the old command's
// private test seams as delegates rather than duplicate implementations.
func LoadTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("TLS certificate and key must be configured together")
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
func ListenerAddressIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
func OpenEvidenceStore(dataDir string) (*evidence.Store, error) {
	return evidence.Open(filepath.Join(dataDir, "evidence"))
}
func OpenOperationStore(dataDir string) (*operation.FileStore, error) {
	return operation.NewFileStore(filepath.Join(dataDir, "operations"))
}
func OpenIdentityStore(path string) (*authn.Store, error) {
	if path == "" {
		return nil, nil
	}
	return authn.Open(path)
}
func OptionalAuthenticator(s *authn.Store) api.Authenticator {
	if s == nil {
		return nil
	}
	return s
}
func StrictBoolEnv(key string) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" || v == "false" {
		return false, nil
	}
	if v == "true" {
		return true, nil
	}
	return false, fmt.Errorf("%s must be exactly true or false", key)
}
func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(v, ",") {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}
func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration: %w", key, err)
	}
	return value, nil
}
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func StartEvidenceReverification(ctx context.Context, s *evidence.Store, interval time.Duration) <-chan struct{} {
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
				_, _ = s.Verify()
			}
		}
	}()
	return done
}

// The standalone seam has no persistent resources to protect. The complete
// runtime additionally tracks admission, request cancellation and worker drain.
func ServeUntilShutdown(server *http.Server, listener net.Listener, signals <-chan os.Signal, timeout time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-signals:
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		closeErr := server.Close()
		return errors.Join(fmt.Errorf("graceful shutdown: %w", err), closeErr)
	}
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
	return nil
}
