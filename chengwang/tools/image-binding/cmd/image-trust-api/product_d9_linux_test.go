//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

type productD9Fixture struct {
	candidate                  candidateFixture
	config                     productConfiguration
	file                       string
	roots                      *x509.CertPool
	managementToken, bothToken string
}

func newProductD9Fixture(t *testing.T) productD9Fixture {
	t.Helper()
	return productD9FromCandidate(t, newCandidateFixture(t, true))
}

func productD9FromCandidate(t *testing.T, f candidateFixture) productD9Fixture {
	t.Helper()
	root := filepath.Dir(f.file)
	data := filepath.Join(root, "data")
	if os.Mkdir(data, 0700) != nil {
		t.Fatal("create private product fixture")
	}
	f.config.AuditDir = filepath.Join(data, "evidence")
	audit, err := evidence.Open(f.config.AuditDir)
	if err != nil {
		t.Fatal("provision existing shared audit")
	}
	if audit.Close() != nil {
		t.Fatal("release fixture audit")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate private TLS fixture")
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(9001), Subject: pkix.Name{CommonName: "isolated-product-d9"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal("create TLS fixture certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("create TLS fixture key")
	}
	f.config.TLSCertFile, f.config.TLSKeyFile = filepath.Join(root, "server-cert.pem"), filepath.Join(root, "server-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	candidatePrivateFile(t, f.config.TLSCertFile, certPEM)
	candidatePrivateFile(t, f.config.TLSKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("provision explicit test TLS trust")
	}
	p := productConfiguration{Addr: f.config.Addr, DataDir: data, IdentitiesFile: f.config.IdentitiesFile, TLSCertFile: f.config.TLSCertFile, TLSKeyFile: f.config.TLSKeyFile, TenantID: f.config.TenantID, SiteID: f.config.SiteID, Environment: "candidate", ManagementObjectID: "product-d9"}
	profileRaw, err := readPrivate(f.config.IdentitiesFile, 1<<20)
	var profile authn.File
	if err != nil || strictDecode(profileRaw, &profile) != nil {
		t.Fatal("load real fixture identities")
	}
	trustScope := profile.Identities[0].Principal.AllowedScopes[0]
	managementScope := authz.ResourceScope{TenantID: p.TenantID, SiteID: p.SiteID, ObjectType: "control-plane", ObjectID: p.ManagementObjectID, Environment: p.Environment}
	generated := make([]string, 0, 2)
	for i, scopes := range [][]authz.ResourceScope{{managementScope}, {managementScope, trustScope}} {
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			t.Fatal("generate independent fixture identity")
		}
		generated = append(generated, token)
		id := []string{"product-management-only", "product-combined"}[i]
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: id, TokenHash: hash, Principal: authz.Principal{ID: id, TenantID: p.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: scopes}})
	}
	candidatePrivateFile(t, f.config.IdentitiesFile, candidateJSON(t, profile))
	f.writeConfig(t)
	file := filepath.Join(root, "product.json")
	candidatePrivateFile(t, file, candidateJSON(t, p))
	return productD9Fixture{candidate: f, config: p, file: file, roots: roots, managementToken: generated[0], bothToken: generated[1]}
}

func TestCandidateD9ProductRejectsConfigurationBeforeListen(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *productD9Fixture)
	}{
		{"missing-tls", func(t *testing.T, f *productD9Fixture) {
			f.config.TLSCertFile = ""
			f.config.TLSKeyFile = ""
			f.candidate.config.TLSCertFile = ""
			f.candidate.config.TLSKeyFile = ""
		}},
		{"tenant-mismatch", func(t *testing.T, f *productD9Fixture) { f.config.TenantID = "other" }},
		{"site-mismatch", func(t *testing.T, f *productD9Fixture) { f.config.SiteID = "other" }},
		{"noncandidate", func(t *testing.T, f *productD9Fixture) {
			f.config.Environment = "production"
			f.candidate.config.Environment = "production"
		}},
		{"identity-mismatch", func(t *testing.T, f *productD9Fixture) {
			f.config.IdentitiesFile = filepath.Join(filepath.Dir(f.file), "other.json")
		}},
		{"audit-mismatch", func(t *testing.T, f *productD9Fixture) {
			f.candidate.config.AuditDir = filepath.Join(filepath.Dir(f.file), "audit")
		}},
		{"address-mismatch", func(t *testing.T, f *productD9Fixture) { f.config.Addr = "127.0.0.1:1" }},
		{"mutable-hostname", func(t *testing.T, f *productD9Fixture) {
			f.config.Addr = "localhost:0"
			f.candidate.config.Addr = f.config.Addr
		}},
		{"noncanonical-port", func(t *testing.T, f *productD9Fixture) {
			f.config.Addr = "127.0.0.1:00"
			f.candidate.config.Addr = f.config.Addr
		}},
		{"root-data", func(t *testing.T, f *productD9Fixture) { f.config.DataDir = "/" }},
		{"relative-data", func(t *testing.T, f *productD9Fixture) { f.config.DataDir = "relative" }},
		{"wide-data-mode", func(t *testing.T, f *productD9Fixture) {
			if os.Chmod(f.config.DataDir, 0755) != nil {
				t.Fatal("change fixture mode")
			}
		}},
		{"missing-audit", func(t *testing.T, f *productD9Fixture) {
			if os.Remove(filepath.Join(f.candidate.config.AuditDir, "checkpoint.json")) != nil {
				t.Fatal("remove fixture checkpoint")
			}
		}},
		{"missing-store", func(t *testing.T, f *productD9Fixture) {
			f.candidate.config.StorePath = filepath.Join(filepath.Dir(f.file), "absent-store")
		}},
		{"empty-management-object", func(t *testing.T, f *productD9Fixture) { f.config.ManagementObjectID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProductD9Fixture(t)
			tc.mutate(t, &f)
			candidatePrivateFile(t, f.file, candidateJSON(t, f.config))
			f.candidate.writeConfig(t)
			called := false
			err := runProduct(context.Background(), f.candidate.file, f.file, func(string, string) (net.Listener, error) { called = true; return nil, errors.New("unexpected listen") })
			if err != errConfiguration || called {
				t.Fatal("invalid full product config reached listener")
			}
			if tc.name == "missing-store" {
				if _, err := os.Lstat(f.candidate.config.StorePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing trust store bootstrapped")
				}
			}
			if tc.name == "missing-audit" {
				if _, err := os.Lstat(filepath.Join(f.candidate.config.AuditDir, "checkpoint.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing audit silently reinitialized")
				}
			}
		})
	}
}

func TestCandidateD9ProductStrictPrivateConfiguration(t *testing.T) {
	for _, kind := range []string{"unknown-field", "duplicate-field", "case-alias", "null", "trailing", "wide-file-mode", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newProductD9Fixture(t)
			raw := candidateJSON(t, f.config)
			switch kind {
			case "unknown-field":
				raw = append([]byte(`{"publish":true,`), raw[1:]...)
			case "duplicate-field":
				raw = append([]byte(`{"addr":"127.0.0.1:0",`), raw[1:]...)
			case "case-alias":
				raw = bytes.Replace(raw, []byte(`"addr"`), []byte(`"Addr"`), 1)
			case "null":
				raw = []byte(`null`)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			}
			candidatePrivateFile(t, f.file, raw)
			switch kind {
			case "wide-file-mode":
				if os.Chmod(f.file, 0644) != nil {
					t.Fatal("fixture chmod")
				}
			case "symlink":
				target := f.file + ".original"
				if os.Rename(f.file, target) != nil || os.Symlink(target, f.file) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink":
				if os.Link(f.file, f.file+".alias") != nil {
					t.Fatal("fixture hardlink")
				}
			}
			called := false
			if runProduct(context.Background(), f.candidate.file, f.file, func(string, string) (net.Listener, error) { called = true; return nil, errors.New("unexpected listen") }) != errConfiguration || called {
				t.Fatal("unsafe product config reached listener")
			}
		})
	}
}

func TestCandidateD9ProductRealTLSSharedAuditScopesAndLockedWrites(t *testing.T) {
	f := newProductD9Fixture(t)
	// An inherited legacy configuration must not replace this private candidate
	// composition, reopen unrelated writes or cause a controller connection.
	for name, value := range map[string]string{"CHENGWANG_ADDR": "0.0.0.0:1", "CHENGWANG_ALLOW_PUBLISH": "true", "CHENGWANG_OPERATION_WRITES_ENABLED": "true", "CHENGWANG_IDENTITIES_FILE": "/not-this-product-profile", "CHENGWANG_MIHOMO_URL": "http://127.0.0.1:1", "CHENGWANG_WEB_DIR": "/not-this-candidate-bundle"} {
		t.Setenv(name, value)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- runProduct(ctx, f.candidate.file, f.file, func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != f.config.Addr {
				return nil, errConfiguration
			}
			listener, err := net.Listen(network, address)
			if err == nil {
				ready <- listener.Addr().String()
			}
			return listener, err
		})
	}()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				t.Error("product candidate did not join")
			}
		}
	})
	var address string
	select {
	case address = <-ready:
	case <-done:
		stopped = true
		t.Fatal("product failed before listen")
	case <-time.After(5 * time.Second):
		t.Fatal("product did not listen")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path, token string, want int) []byte {
		t.Helper()
		var requestBody io.Reader
		if method != http.MethodGet {
			requestBody = bytes.NewReader([]byte(`{"invalid":"do not parse before locked write gate"}`))
		}
		request, err := http.NewRequest(method, "https://"+address+path, requestBody)
		if err != nil {
			t.Fatal("build fixture request")
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("real product TLS request failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != want || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatalf("real product path=%s status=%d want=%d", path, response.StatusCode, want)
		}
		for _, secret := range []string{f.candidate.token, f.managementToken, f.bothToken, "BEGIN PRIVATE KEY"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("product response exposed private material")
			}
		}
		return raw
	}
	call(http.MethodGet, "/api/v1/health", "", http.StatusOK)
	call(http.MethodGet, "/api/v1/versions", "", http.StatusUnauthorized)
	call(http.MethodGet, "/api/v1/versions", f.candidate.token, http.StatusForbidden)
	call(http.MethodGet, "/api/v1/versions", f.managementToken, http.StatusOK)
	call(http.MethodGet, "/api/v1/image-trust", f.managementToken, http.StatusForbidden)
	var status imagetrust.Status
	if json.Unmarshal(call(http.MethodGet, "/api/v1/image-trust", f.candidate.token, http.StatusOK), &status) != nil || status.Boundary != imagetrust.StatusBoundary || status.Authorization != "BLOCKED" || status.DeviceActionsExecuted || status.Generation != 1 || status.Sequence != f.candidate.sequence {
		t.Fatal("real trust backend was not composed")
	}
	query := "/api/v1/operations?tenantId=" + f.config.TenantID + "&siteId=" + f.config.SiteID + "&objectType=control-plane&objectId=" + f.config.ManagementObjectID + "&environment=candidate"
	call(http.MethodGet, query, f.bothToken, http.StatusOK)
	call(http.MethodPost, "/api/v1/operations", f.bothToken, http.StatusLocked)
	call(http.MethodPost, "/api/v1/publish", f.bothToken, http.StatusLocked)
	call(http.MethodPut, "/api/v1/image-trust/catalogue", f.bothToken, http.StatusLocked)
	call(http.MethodPost, "/api/v1/image-trust/verifications", f.bothToken, http.StatusLocked)
	var attestation struct {
		Mode                   string `json:"mode"`
		IdentityConfigured     bool   `json:"identityConfigured"`
		OperationWritesEnabled bool   `json:"operationWritesEnabled"`
		DeviceActionsExecuted  bool   `json:"deviceActionsExecuted"`
	}
	if json.Unmarshal(call(http.MethodGet, "/api/v1/attestation/shadow", "", http.StatusOK), &attestation) != nil || attestation.Mode != "candidate" || !attestation.IdentityConfigured || attestation.OperationWritesEnabled || attestation.DeviceActionsExecuted {
		t.Fatal("inherited environment changed candidate gates")
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal("full product failed to shut down")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("full product did not release stores")
	}
	store, err := truststate.Open(context.Background(), f.candidate.config.StorePath, f.candidate.anchor)
	if err != nil {
		t.Fatal("product retained trust lock")
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil || state.Sequence != f.candidate.sequence || state.LedgerUsed != 0 {
		t.Fatal("read/locked product calls mutated trust")
	}
	audit, err := evidence.Open(f.candidate.config.AuditDir)
	if err != nil {
		t.Fatal("product retained shared audit lock")
	}
	report, verifyErr := audit.Verify()
	closeErr = audit.Close()
	if verifyErr != nil || closeErr != nil || !report.Valid || report.Count != 0 {
		t.Fatal("product reads mutated shared audit")
	}
}

func TestCandidateD9ProductInvalidContextAndListener(t *testing.T) {
	if runProduct(nil, "", "", net.Listen) != errConfiguration {
		t.Fatal("nil context accepted")
	}
	if runProduct(context.Background(), "", "", nil) != errConfiguration {
		t.Fatal("nil listener accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if runProduct(ctx, "", "", net.Listen) != errConfiguration {
		t.Fatal("cancelled context accepted")
	}
}

func productD9Start(t *testing.T, f productD9Fixture) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- runProduct(ctx, f.candidate.file, f.file, func(network, addr string) (net.Listener, error) {
			listener, err := net.Listen(network, addr)
			if err == nil {
				ready <- listener.Addr().String()
			}
			return listener, err
		})
	}()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			stopped = true
			if err != nil {
				t.Error("complete product runtime did not stop cleanly")
			}
		case <-time.After(12 * time.Second):
			t.Error("complete product runtime did not join")
		}
	}
	t.Cleanup(stop)
	select {
	case address := <-ready:
		return address, stop
	case <-done:
		stopped = true
		cancel()
		t.Fatal("complete product runtime failed before listener")
	case <-time.After(5 * time.Second):
		t.Fatal("complete product runtime failed to listen")
	}
	return "", stop
}

func TestCandidateD9ProductAutomaticTLSRefreshUsesSharedAudit(t *testing.T) {
	base, next := candidateD7Fixture(t)
	f := productD9FromCandidate(t, base)
	var requests atomic.Uint64
	var invalid atomic.Bool
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || r.Method != http.MethodGet || r.URL.Path != "/feed/latest.json" || r.Header.Get("Authorization") != "" {
			invalid.Store(true)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(next)))
		_, _ = w.Write(next)
	}))
	t.Cleanup(feed.Close)
	c := &f.candidate.config
	c.WritesEnabled, c.RefreshEnabled = true, true
	c.RefreshURL, c.RefreshIP = feed.URL+"/feed", "127.0.0.1"
	c.RefreshSPKI = candidateHash(feed.Certificate().RawSubjectPublicKeyInfo)
	c.RefreshCAFile = filepath.Join(filepath.Dir(f.file), "refresh-ca.pem")
	c.RefreshIntervalSeconds, c.RefreshMaxAgeSeconds, c.RefreshTimeoutSeconds = 1, 3, 1
	candidatePrivateFile(t, c.RefreshCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: feed.Certificate().Raw}))
	candidateD7Write(t, f.candidate)
	address, stop := productD9Start(t, f)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	deadline := time.Now().Add(8 * time.Second)
	for {
		request, err := http.NewRequest(http.MethodGet, "https://"+address+"/api/v1/image-trust", nil)
		if err != nil {
			t.Fatal("build full product trust request")
		}
		request.Header.Set("Authorization", "Bearer "+f.candidate.token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("full product trust HTTPS failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		var status imagetrust.Status
		if readErr != nil || response.StatusCode != 200 || json.Unmarshal(raw, &status) != nil {
			t.Fatal("full product returned invalid actual trust status")
		}
		if status.Generation == 2 && status.CatalogueSHA256 == candidateHash(next) && status.RevokedManifests == 1 && status.RefreshRequired && status.RefreshFresh && status.RefreshLastSuccessUnix > 0 && status.Authorization == "BLOCKED" && !status.DeviceActionsExecuted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("full product did not install actual signed revocation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	before := requests.Load()
	time.Sleep(40 * time.Millisecond)
	if before == 0 || requests.Load() != before || invalid.Load() {
		t.Fatal("full product refresh survived shutdown or used invalid transport")
	}
	store, err := truststate.Open(context.Background(), c.StorePath, f.candidate.anchor)
	if err != nil {
		t.Fatal("full product retained real trust lock")
	}
	state, inspectErr := store.Inspect(context.Background())
	journal, journalErr := store.Journal(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || journalErr != nil || closeErr != nil || state.Catalogue.Generation != 2 || state.Catalogue.SHA256 != candidateHash(next) || state.LedgerUsed != 0 || len(journal) != 1 || !journal[0].Acknowledged {
		t.Fatal("full product refresh lacked durable acknowledged trust update")
	}
	audit, err := evidence.Open(c.AuditDir)
	if err != nil {
		t.Fatal("full product retained shared audit lock")
	}
	report, verifyErr := audit.Verify()
	closeErr = audit.Close()
	if verifyErr != nil || closeErr != nil || !report.Valid || report.Count != 2 {
		t.Fatal("full product refresh did not use actual shared audit")
	}
}

func TestCandidateD9ProductRefreshCancellationJoinsBeforeSharedClose(t *testing.T) {
	base, _ := candidateD7Fixture(t)
	f := productD9FromCandidate(t, base)
	entered, canceled := make(chan struct{}, 1), make(chan struct{}, 1)
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		select {
		case canceled <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(feed.Close)
	c := &f.candidate.config
	c.WritesEnabled, c.RefreshEnabled = true, true
	c.RefreshURL, c.RefreshIP = feed.URL, "127.0.0.1"
	c.RefreshSPKI = candidateHash(feed.Certificate().RawSubjectPublicKeyInfo)
	c.RefreshCAFile = filepath.Join(filepath.Dir(f.file), "refresh-ca.pem")
	c.RefreshTimeoutSeconds = 30
	candidatePrivateFile(t, c.RefreshCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: feed.Certificate().Raw}))
	candidateD7Write(t, f.candidate)
	_, stop := productD9Start(t, f)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("complete runtime did not start real HTTPS refresh")
	}
	start := time.Now()
	stop()
	if time.Since(start) >= 5*time.Second {
		t.Fatal("complete runtime waited for transport timeout instead of cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("real HTTPS refresh survived runtime join")
	}
	store, err := truststate.Open(context.Background(), c.StorePath, f.candidate.anchor)
	if err != nil {
		t.Fatal("joined runtime retained trust lock")
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil || state.Sequence != f.candidate.sequence || state.Catalogue.Generation != 1 || state.LedgerUsed != 0 {
		t.Fatal("canceled full product refresh changed trust")
	}
	audit, err := evidence.Open(c.AuditDir)
	if err != nil {
		t.Fatal("joined runtime retained shared audit lock")
	}
	report, verifyErr := audit.Verify()
	closeErr = audit.Close()
	if verifyErr != nil || closeErr != nil || !report.Valid || report.Count != 0 {
		t.Fatal("canceled source request altered shared audit")
	}
}

func TestCandidateD9ProductInFlightRequestRetainsTrustAndAuditUntilDrain(t *testing.T) {
	f := newProductD9Fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, done := make(chan string, 1), make(chan error, 1)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	released, stopped := false, false
	t.Cleanup(func() {
		cancel()
		if !released {
			close(release)
		}
		if !stopped {
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				t.Error("in-flight product runtime did not join")
			}
		}
	})
	go func() {
		done <- runProductWithRequestObserver(ctx, f.candidate.file, f.file, func(network, addr string) (net.Listener, error) {
			listener, err := net.Listen(network, addr)
			if err == nil {
				ready <- listener.Addr().String()
			}
			return listener, err
		}, func(r *http.Request) {
			close(entered)
			<-r.Context().Done()
			close(canceled)
			<-release
		})
	}()
	var address string
	select {
	case address = <-ready:
	case <-done:
		stopped = true
		t.Fatal("actual in-flight runtime failed before listener")
	case <-time.After(5 * time.Second):
		t.Fatal("actual runtime did not listen")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		request, err := http.NewRequest(http.MethodGet, "https://"+address+"/api/v1/image-trust", nil)
		if err != nil {
			return
		}
		request.Header.Set("Authorization", "Bearer "+f.candidate.token)
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual HTTPS request was not accepted")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not cancel accepted HTTPS request")
	}
	select {
	case <-done:
		stopped = true
		t.Fatal("runtime returned before real request drain")
	default:
	}
	lockCtx, lockCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	store, err := truststate.Open(lockCtx, f.candidate.config.StorePath, f.candidate.anchor)
	lockCancel()
	if err == nil {
		_ = store.Close()
		t.Fatal("trust closed beneath accepted HTTPS handler")
	}
	if audit, err := evidence.Open(f.candidate.config.AuditDir); err == nil {
		_ = audit.Close()
		t.Fatal("shared audit closed beneath accepted HTTPS handler")
	}
	close(release)
	released = true
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal("drained actual product runtime failed")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("drained runtime failed to release stores")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("real client did not finish")
	}
	store, err = truststate.Open(context.Background(), f.candidate.config.StorePath, f.candidate.anchor)
	if err != nil {
		t.Fatal("drained runtime retained trust lock")
	}
	_ = store.Close()
	audit, err := evidence.Open(f.candidate.config.AuditDir)
	if err != nil {
		t.Fatal("drained runtime retained audit lock")
	}
	_ = audit.Close()
}
