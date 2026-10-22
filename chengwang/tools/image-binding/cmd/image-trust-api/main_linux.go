//go:build linux

// image-trust-api is an opt-in candidate composition of the product API and
// the managed backend. It is not installed by the original product server.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"chengwang/image-binding/product"
	"chengwang/image-binding/refresh"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
)

var errConfiguration = errors.New("image trust candidate configuration rejected")

type configuration struct {
	Addr                   string `json:"addr"`
	StorePath              string `json:"storePath"`
	AnchorFile             string `json:"anchorFile"`
	IdentitiesFile         string `json:"identitiesFile"`
	AuditDir               string `json:"auditDir"`
	RegistryCAFile         string `json:"registryCAFile"`
	RegistryTokenFile      string `json:"registryTokenFile"`
	TLSCertFile            string `json:"tlsCertFile"`
	TLSKeyFile             string `json:"tlsKeyFile"`
	TenantID               string `json:"tenantId"`
	SiteID                 string `json:"siteId"`
	Environment            string `json:"environment"`
	WritesEnabled          bool   `json:"writesEnabled"`
	RefreshEnabled         bool   `json:"refreshEnabled"`
	RefreshURL             string `json:"refreshURL"`
	RefreshIP              string `json:"refreshIP"`
	RefreshSPKI            string `json:"refreshSPKI"`
	RefreshCAFile          string `json:"refreshCAFile"`
	RefreshIntervalSeconds int64  `json:"refreshIntervalSeconds"`
	RefreshMaxAgeSeconds   int64  `json:"refreshMaxAgeSeconds"`
	RefreshTimeoutSeconds  int64  `json:"refreshTimeoutSeconds"`
	WebDir                 string `json:"webDir"`
}

func main() {
	file := flag.String("config", "", "absolute private candidate configuration file (no HTTP bootstrap)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if flag.NArg() != 0 || run(ctx, *file, net.Listen) != nil {
		// No raw paths, file contents, TLS parser errors or Registry credentials.
		log.Print("image trust candidate stopped without deployment authorization")
		os.Exit(1)
	}
}

func run(ctx context.Context, file string, listen func(string, string) (net.Listener, error)) error {
	if ctx == nil || listen == nil || ctx.Err() != nil {
		return errConfiguration
	}
	ctx, cancelBackground := context.WithCancel(ctx)
	defer cancelBackground()
	raw, err := readPrivate(file, 16<<10)
	if err != nil {
		return errConfiguration
	}
	var config configuration
	if strictDecode(raw, &config) != nil || config.TenantID == "" || config.SiteID == "" || (config.Environment != "candidate" && config.Environment != "shadow") {
		return errConfiguration
	}
	for _, path := range []string{config.StorePath, config.AuditDir, config.IdentitiesFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return errConfiguration
		}
	}
	if config.Addr == "" {
		config.Addr = "127.0.0.1:7812"
	}
	host, _, err := net.SplitHostPort(config.Addr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return errConfiguration // Do not resolve a mutable hostname for bind scope.
	}
	var tlsConfig *tls.Config
	if config.TLSCertFile != "" || config.TLSKeyFile != "" {
		cert, e1 := readPrivate(config.TLSCertFile, 256<<10)
		key, e2 := readPrivate(config.TLSKeyFile, 64<<10)
		pair, e3 := tls.X509KeyPair(cert, key)
		if e1 != nil || e2 != nil || e3 != nil {
			return errConfiguration
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	}
	if !ip.IsLoopback() && tlsConfig == nil {
		return errConfiguration
	}
	anchorRaw, err := readPrivate(config.AnchorFile, 8<<10)
	if err != nil {
		return errConfiguration
	}
	var anchor trustcatalog.Anchor
	if strictDecode(anchorRaw, &anchor) != nil {
		return errConfiguration
	}
	identityRaw, err := readPrivate(config.IdentitiesFile, 1<<20)
	var identityProfile authn.File
	if err != nil || strictDecode(identityRaw, &identityProfile) != nil {
		return errConfiguration
	}
	identities, err := authn.Open(config.IdentitiesFile)
	if err != nil {
		return errConfiguration
	}
	ca, err := readPrivate(config.RegistryCAFile, 256<<10)
	if err != nil {
		return errConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errConfiguration
	}
	bearer := ""
	if config.RegistryTokenFile != "" {
		secret, err := readPrivate(config.RegistryTokenFile, 512)
		if err != nil {
			return errConfiguration
		}
		bearer = strings.TrimSuffix(strings.TrimSuffix(string(secret), "\n"), "\r")
	}
	refreshClient, err := configuredRefresh(config)
	if err != nil {
		return errConfiguration
	}
	web, err := loadWebBundle(config.WebDir)
	if err != nil {
		return errConfiguration
	}
	refreshMaxAge := time.Duration(0)
	if refreshClient != nil {
		refreshMaxAge = refreshClient.MaxAge()
	}
	// Never Create or reset from this process. Deletion is not recovery.
	store, err := truststate.Open(ctx, config.StorePath, anchor)
	if err != nil {
		return errConfiguration
	}
	defer store.Close()
	if requireExistingAudit(config.AuditDir) != nil {
		return errConfiguration
	}
	audit, err := evidence.Open(config.AuditDir)
	if err != nil {
		return errConfiguration
	}
	defer audit.Close()
	scope := authz.ResourceScope{TenantID: config.TenantID, SiteID: config.SiteID, ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: config.Environment}
	backend, err := product.New(ctx, product.Config{Store: store, Audit: audit, Scope: scope, WritesEnabled: config.WritesEnabled, RegistryRoots: roots, RegistryBearerToken: bearer, RefreshMaxAge: refreshMaxAge})
	if err != nil {
		return errConfiguration
	}
	productAPI := api.New(api.Options{Mode: "candidate", Authn: identities, Evidence: audit, ManagementScope: scope, ImageTrust: backend, ImageTrustWritesEnabled: config.WritesEnabled})
	// Reuse the product's actual routes without exposing unrelated optional
	// subsystems (versions, operations, publishing or device actions).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		candidateSecurityHeaders(w)
		switch r.URL.Path {
		case "/api/v1/health", "/api/v1/image-trust", "/api/v1/image-trust/catalogue", "/api/v1/image-trust/verifications", "/api/v1/image-trust/history":
			productAPI.ServeHTTP(w, r)
		default:
			if web != nil && web.serve(w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "candidate_route_disabled", "authorization": "BLOCKED", "deviceActionsExecuted": false})
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := listen("tcp", config.Addr)
	if err != nil {
		return errConfiguration
	}
	defer listener.Close()
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	// Workers are joined before either persistent Store closes, including a
	// listener/Serve failure. Cancellation alone is not permission to leave a
	// refresh callback writing into a closed audit or trust database.
	var workers sync.WaitGroup
	backgroundErrors := make(chan error, 2)
	defer func() {
		cancelBackground()
		workers.Wait()
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := backend.Maintenance(ctx); err != nil {
					if ctx.Err() == nil {
						backgroundErrors <- errConfiguration
					}
					return
				}
			}
		}
	}()
	if refreshClient != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := refreshClient.Run(ctx, func(attempt context.Context) error {
				return refreshOnce(attempt, backend, refreshClient)
			})
			if ctx.Err() == nil {
				// A driver unexpectedly returning is not a silently healthy
				// refresh loop. Never log its configured endpoint or TLS error.
				_ = err
				backgroundErrors <- errConfiguration
			}
		}()
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			return errConfiguration
		}
		return nil
	case <-backgroundErrors:
		cancelBackground()
		_ = server.Close()
		<-finished
		return errConfiguration
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			<-finished
			return errConfiguration
		}
		if err := <-finished; !errors.Is(err, http.ErrServerClosed) {
			return errConfiguration
		}
		return nil
	}
}

// Automatic refresh is an explicit privileged composition choice, never an
// HTTP-supplied URL or an implicit side effect of enabling ordinary writes.
func configuredRefresh(c configuration) (*refresh.Client, error) {
	configured := c.RefreshURL != "" || c.RefreshIP != "" || c.RefreshSPKI != "" || c.RefreshCAFile != "" || c.RefreshIntervalSeconds != 0 || c.RefreshMaxAgeSeconds != 0 || c.RefreshTimeoutSeconds != 0
	if !c.RefreshEnabled {
		if configured {
			return nil, errConfiguration
		}
		return nil, nil
	}
	if !c.WritesEnabled || c.RefreshURL == "" || c.RefreshIP == "" || c.RefreshSPKI == "" || c.RefreshCAFile == "" {
		return nil, errConfiguration
	}
	for _, seconds := range []int64{c.RefreshIntervalSeconds, c.RefreshMaxAgeSeconds, c.RefreshTimeoutSeconds} {
		if seconds < 0 || seconds > 24*60*60 {
			return nil, errConfiguration
		}
	}
	ca, err := readPrivate(c.RefreshCAFile, 256<<10)
	if err != nil {
		return nil, errConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errConfiguration
	}
	client, err := refresh.New(refresh.Config{BaseURL: c.RefreshURL, IP: c.RefreshIP, SPKI: c.RefreshSPKI, Roots: roots, Interval: time.Duration(c.RefreshIntervalSeconds) * time.Second, MaxAge: time.Duration(c.RefreshMaxAgeSeconds) * time.Second, Timeout: time.Duration(c.RefreshTimeoutSeconds) * time.Second})
	if err != nil {
		return nil, errConfiguration
	}
	return client, nil
}

func refreshOnce(ctx context.Context, backend *product.Service, client *refresh.Client) error {
	generation, hash, err := backend.RefreshSnapshot(ctx)
	if err != nil {
		return err
	}
	raws, err := client.Fetch(ctx, generation, hash)
	if err != nil {
		return err
	}
	// Fetch verifies transport framing and a contiguous generation sequence;
	// only ApplyRefresh verifies catalogue signatures and commits trust state.
	for _, raw := range raws {
		if generation == ^uint64(0) {
			return errConfiguration
		}
		if err := backend.ApplyRefresh(ctx, raw); err != nil {
			return err
		}
		generation++
		sum := sha256.Sum256(raw)
		hash = "sha256:" + hex.EncodeToString(sum[:])
	}
	// A concurrent manual update is not evidence that this fetch observed its
	// newer generation. Confirm the exact fetched target, never a blind readback.
	return backend.ConfirmRefresh(ctx, generation, hash)
}

// Strict duplicate rejection precedes typed decoding at every nesting depth.
// This is configuration parsing, not a competing catalogue verifier.
func strictDecode(raw []byte, destination any) error {
	// Private Linux paths/IDs use literal UTF-8, not JSON escape aliases.
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\\') {
		return errConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errConfiguration
		}
		token, err := decoder.Token()
		if err != nil {
			return errConfiguration
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		if delimiter != '{' && delimiter != '[' {
			return errConfiguration
		}
		seen := map[string]bool{}
		for decoder.More() {
			if delimiter == '{' {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return errConfiguration
				}
				seen[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		close, err := decoder.Token()
		if err != nil || (delimiter == '{' && close != json.Delim('}')) || (delimiter == '[' && close != json.Delim(']')) {
			return errConfiguration
		}
		return nil
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || value(0) != nil {
		return errConfiguration
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errConfiguration
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(any)) != io.EOF {
		return errConfiguration
	}
	var supplied any
	if json.Unmarshal(raw, &supplied) != nil || !exactFieldNames(supplied, reflect.TypeOf(destination)) {
		return errConfiguration
	}
	return nil
}

func exactFieldNames(supplied any, typ reflect.Type) bool {
	if supplied == nil {
		return true
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	// time.Time and other explicitly typed JSON scalars parse themselves.
	if reflect.PointerTo(typ).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return true
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := supplied.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for key, nested := range object {
			field, ok := fields[key]
			if !ok || !exactFieldNames(nested, field) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return true
		}
		values, ok := supplied.([]any)
		if !ok {
			return false
		}
		for _, nested := range values {
			if !exactFieldNames(nested, typ.Elem()) {
				return false
			}
		}
	case reflect.Map:
		object, ok := supplied.(map[string]any)
		if !ok || typ.Key().Kind() != reflect.String {
			return false
		}
		for _, nested := range object {
			if !exactFieldNames(nested, typ.Elem()) {
				return false
			}
		}
	}
	return true
}
