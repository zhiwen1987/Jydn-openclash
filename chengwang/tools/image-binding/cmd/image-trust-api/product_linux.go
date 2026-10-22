//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"chengwang/image-binding/product"
	"chengwang/image-binding/refresh"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/serverruntime"
	"golang.org/x/sys/unix"
)

// Full-product composition is explicit and remains candidate-only. It neither
// reads nor modifies process-global environment overrides, deployment files,
// host trust roots or the original product server's optional write switches.
type productConfiguration struct {
	Addr               string `json:"addr"`
	DataDir            string `json:"dataDir"`
	IdentitiesFile     string `json:"identitiesFile"`
	TLSCertFile        string `json:"tlsCertFile"`
	TLSKeyFile         string `json:"tlsKeyFile"`
	TenantID           string `json:"tenantId"`
	SiteID             string `json:"siteId"`
	Environment        string `json:"environment"`
	ManagementObjectID string `json:"managementObjectId"`
}

func runProduct(ctx context.Context, trustFile, productFile string, listen func(string, string) (net.Listener, error)) error {
	return runProductWithRequestObserver(ctx, trustFile, productFile, listen, nil)
}

// The process-local observer is used by the real TLS negative fixture to count
// HTTP handlers reached after handshake, not to intercept or mock responses.
// No configuration or HTTP request can supply it or use it to grant access.
func runProductWithRequestObserver(ctx context.Context, trustFile, productFile string, listen func(string, string) (net.Listener, error), observe func(*http.Request)) error {
	if ctx == nil || listen == nil || ctx.Err() != nil {
		return errConfiguration
	}
	raw, err := readPrivate(productFile, 16<<10)
	if err != nil {
		return errConfiguration
	}
	var p productConfiguration
	if strictDecode(raw, &p) != nil || p.Environment != "candidate" || p.TenantID == "" || p.SiteID == "" || p.ManagementObjectID == "" || p.Addr == "" {
		return errConfiguration
	}
	if !filepath.IsAbs(p.DataDir) || filepath.Clean(p.DataDir) != p.DataDir || p.DataDir == "/" || strings.ContainsAny(p.DataDir, "\\\x00") {
		return errConfiguration
	}
	var directory unix.Stat_t
	if unix.Lstat(p.DataDir, &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&07777 != 0700 || directory.Uid != uint32(os.Geteuid()) || directory.Gid != uint32(os.Getegid()) {
		return errConfiguration
	}
	host, port, err := net.SplitHostPort(p.Addr)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || net.ParseIP(host) == nil || portErr != nil || strconv.FormatUint(portNumber, 10) != port {
		return errConfiguration
	}
	trustRaw, err := readPrivate(trustFile, 16<<10)
	if err != nil {
		return errConfiguration
	}
	var c configuration
	if strictDecode(trustRaw, &c) != nil || c.Addr != p.Addr || c.IdentitiesFile != p.IdentitiesFile || c.TLSCertFile != p.TLSCertFile || c.TLSKeyFile != p.TLSKeyFile || c.TenantID != p.TenantID || c.SiteID != p.SiteID || c.Environment != p.Environment || c.AuditDir != filepath.Join(p.DataDir, "evidence") {
		return errConfiguration
	}
	// requireExistingAudit traverses the DataDir ancestry without symlinks and
	// checks an already provisioned private checkpoint. The shared runtime's
	// ordinary evidence initialization cannot hide a missing trust audit here.
	if requireExistingAudit(c.AuditDir) != nil || !filepath.IsAbs(c.StorePath) || filepath.Clean(c.StorePath) != c.StorePath || c.StorePath == "/" {
		return errConfiguration
	}
	identityRaw, identityErr := readPrivate(p.IdentitiesFile, 1<<20)
	var identities authn.File
	if identityErr != nil || strictDecode(identityRaw, &identities) != nil {
		return errConfiguration
	}
	cert, e1 := readPrivate(p.TLSCertFile, 256<<10)
	key, e2 := readPrivate(p.TLSKeyFile, 64<<10)
	_, e3 := tls.X509KeyPair(cert, key)
	if e1 != nil || e2 != nil || e3 != nil {
		return errConfiguration // Even loopback full-product mode requires TLS.
	}
	anchorRaw, err := readPrivate(c.AnchorFile, 8<<10)
	var anchor trustcatalog.Anchor
	if err != nil || strictDecode(anchorRaw, &anchor) != nil {
		return errConfiguration
	}
	registryCA, err := readPrivate(c.RegistryCAFile, 256<<10)
	if err != nil {
		return errConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(registryCA) {
		return errConfiguration
	}
	bearer := ""
	if c.RegistryTokenFile != "" {
		secret, err := readPrivate(c.RegistryTokenFile, 512)
		if err != nil {
			return errConfiguration
		}
		bearer = strings.TrimSuffix(strings.TrimSuffix(string(secret), "\n"), "\r")
	}
	refresher, err := configuredRefresh(c)
	if err != nil {
		return errConfiguration
	}
	web, err := loadWebBundle(c.WebDir)
	if err != nil {
		return errConfiguration
	}
	config := serverruntime.Config{
		Addr: p.Addr, DataDir: p.DataDir, IdentitiesFile: p.IdentitiesFile,
		TLSCertFile: p.TLSCertFile, TLSKeyFile: p.TLSKeyFile,
		TenantID: p.TenantID, SiteID: p.SiteID, ManagementObjectID: p.ManagementObjectID, Mode: p.Environment,
		// Zero-valued publish/operation/admin/Mihomo options are intentional:
		// incoming HTTP or inherited environment cannot reopen those domains.
	}
	opts := serverruntime.Options{
		Context: ctx, Config: &config, Listen: listen, ShutdownTimeout: 10 * time.Second,
		WriteTimeout: 3 * time.Minute, MaxHeaderBytes: 16 << 10,
		WebFactory: func(api http.Handler) (http.Handler, error) {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				candidateSecurityHeaders(w)
				if observe != nil {
					observe(r)
				}
				if web != nil && web.serve(w, r) {
					return
				}
				api.ServeHTTP(w, r)
			}), nil
		},
		TrustFactory: func(ctx context.Context, deps serverruntime.TrustDependencies) (serverruntime.TrustComponent, error) {
			if deps.Audit == nil || deps.AuditDir != c.AuditDir || deps.TenantID != c.TenantID || deps.SiteID != c.SiteID || deps.Environment != c.Environment {
				return serverruntime.TrustComponent{}, errConfiguration
			}
			store, err := truststate.Open(ctx, c.StorePath, anchor)
			if err != nil {
				return serverruntime.TrustComponent{}, errConfiguration
			}
			maxAge := time.Duration(0)
			if refresher != nil {
				maxAge = refresher.MaxAge()
			}
			scope := authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: c.Environment}
			backend, err := product.New(ctx, product.Config{Store: store, Audit: deps.Audit, Scope: scope, WritesEnabled: c.WritesEnabled, RegistryRoots: roots, RegistryBearerToken: bearer, RefreshMaxAge: maxAge})
			if err != nil {
				_ = store.Close()
				return serverruntime.TrustComponent{}, errConfiguration
			}
			return serverruntime.TrustComponent{Backend: backend, WritesEnabled: c.WritesEnabled, Run: func(ctx context.Context) error {
				return runProductTrustWorkers(ctx, backend, refresher)
			}, Close: store.Close}, nil
		},
	}
	if serverruntime.RunWith(opts) != nil {
		// The full runtime's diagnostics may contain deployment paths. The CLI
		// keeps the existing candidate's deliberately generic error boundary.
		return errConfiguration
	}
	return nil
}

func runProductTrustWorkers(ctx context.Context, backend *product.Service, refresher *refresh.Client) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	errors := make(chan error, 2)
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
						errors <- errConfiguration
					}
					return
				}
			}
		}
	}()
	if refresher != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_ = refresher.Run(ctx, func(attempt context.Context) error { return refreshOnce(attempt, backend, refresher) })
			if ctx.Err() == nil {
				errors <- errConfiguration
			}
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case <-errors:
		return errConfiguration
	}
}
