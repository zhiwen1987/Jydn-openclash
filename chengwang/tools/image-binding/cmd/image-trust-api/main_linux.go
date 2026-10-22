//go:build linux

// image-trust-api is an opt-in candidate composition of the product API and
// the managed backend. It is not installed by the original product server.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"chengwang/image-binding/product"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
)

var errConfiguration = errors.New("image trust candidate configuration rejected")

type configuration struct {
	Addr              string `json:"addr"`
	StorePath         string `json:"storePath"`
	AnchorFile        string `json:"anchorFile"`
	IdentitiesFile    string `json:"identitiesFile"`
	AuditDir          string `json:"auditDir"`
	RegistryCAFile    string `json:"registryCAFile"`
	RegistryTokenFile string `json:"registryTokenFile"`
	TLSCertFile       string `json:"tlsCertFile"`
	TLSKeyFile        string `json:"tlsKeyFile"`
	TenantID          string `json:"tenantId"`
	SiteID            string `json:"siteId"`
	Environment       string `json:"environment"`
	WritesEnabled     bool   `json:"writesEnabled"`
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
	if _, err := readPrivate(config.IdentitiesFile, 1<<20); err != nil {
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
	// Never Create or reset from this process. Deletion is not recovery.
	store, err := truststate.Open(ctx, config.StorePath, anchor)
	if err != nil {
		return errConfiguration
	}
	defer store.Close()
	audit, err := evidence.Open(config.AuditDir)
	if err != nil {
		return errConfiguration
	}
	defer audit.Close()
	scope := authz.ResourceScope{TenantID: config.TenantID, SiteID: config.SiteID, ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: config.Environment}
	backend, err := product.New(ctx, product.Config{Store: store, Audit: audit, Scope: scope, WritesEnabled: config.WritesEnabled, RegistryRoots: roots, RegistryBearerToken: bearer})
	if err != nil {
		return errConfiguration
	}
	productAPI := api.New(api.Options{Mode: "candidate", Authn: identities, Evidence: audit, ManagementScope: scope, ImageTrust: backend, ImageTrustWritesEnabled: config.WritesEnabled})
	// Reuse the product's actual routes without exposing unrelated optional
	// subsystems (versions, operations, publishing or device actions).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health", "/api/v1/image-trust", "/api/v1/image-trust/catalogue", "/api/v1/image-trust/verifications":
			productAPI.ServeHTTP(w, r)
		default:
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
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			return errConfiguration
		}
		return nil
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
	canonical, err := json.Marshal(destination)
	if err != nil {
		return errConfiguration
	}
	var supplied, exact any
	if json.Unmarshal(raw, &supplied) != nil || json.Unmarshal(canonical, &exact) != nil || !exactFieldNames(supplied, exact) {
		return errConfiguration
	}
	return nil
}

func exactFieldNames(supplied, exact any) bool {
	switch value := supplied.(type) {
	case map[string]any:
		canonical, ok := exact.(map[string]any)
		if !ok {
			return false
		}
		for key, nested := range value {
			expected, ok := canonical[key]
			if !ok || !exactFieldNames(nested, expected) {
				return false
			}
		}
	case []any:
		canonical, ok := exact.([]any)
		if !ok || len(value) != len(canonical) {
			return false
		}
		for i, nested := range value {
			if !exactFieldNames(nested, canonical[i]) {
				return false
			}
		}
	}
	return true
}
