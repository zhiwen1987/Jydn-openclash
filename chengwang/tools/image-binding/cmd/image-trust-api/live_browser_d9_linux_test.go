//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/product"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"golang.org/x/sys/unix"
)

type browserD9Authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

func browserD9CA(t *testing.T, serial int64) browserD9Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate private browser fixture authority")
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "D9 isolated browser fixture CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create private browser fixture authority")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse private browser fixture authority")
	}
	return browserD9Authority{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func browserD9Leaf(t *testing.T, authority browserD9Authority, kind string, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate temporary browser TLS key")
	}
	now := time.Now()
	ip := net.ParseIP("127.0.0.1")
	if kind == "wrong-san" {
		ip = net.ParseIP("127.0.0.2")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "D9 isolated candidate leaf"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute), IPAddresses: []net.IP{ip}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if kind == "expired" {
		template.NotBefore = now.Add(-2 * time.Hour)
		template.NotAfter = now.Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, &key.PublicKey, authority.key)
	if err != nil {
		t.Fatal("create temporary browser TLS certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode temporary browser TLS key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

type browserD9Endpoint struct {
	config             configuration
	trustFile          string
	productFile        string
	anchor             trustcatalog.Anchor
	sequence           uint64
	requests           atomic.Uint64
	statusRequests     atomic.Uint64
	historyRequests    atomic.Uint64
	operationsRequests atomic.Uint64
	capabilityRequests atomic.Uint64
	writeRequests      atomic.Uint64
	done               chan error
	started            bool
	stopped            bool
}

func browserD9Prepare(t *testing.T, ctx context.Context, directory, webDir, certFile, keyFile string, registryCA []byte, identities authn.File) *browserD9Endpoint {
	t.Helper()
	if os.Mkdir(directory, 0700) != nil || os.Mkdir(filepath.Join(directory, "data"), 0700) != nil {
		t.Fatal("create private browser product runtime")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate temporary signed fixture catalogue")
	}
	key := trustcatalog.Key{ID: trustcatalog.KeyID(public), PublicKey: public}
	approverPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate independent inert fixture approver")
	}
	approver := trustcatalog.Key{ID: trustcatalog.KeyID(approverPublic), PublicKey: approverPublic}
	now := time.Now().Unix()
	doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: strings.Repeat("a", 32), Generation: 1, NotBeforeUnix: now - 30, NotAfterUnix: now + 1200, RootKeys: []trustcatalog.Key{key}, Threshold: 1, Approvers: []trustcatalog.Key{approver}, Grants: []trustcatalog.Grant{}, PolicyFloors: map[string]uint64{}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	for i := 0; i < 25; i++ {
		policy := fmt.Sprintf("ui-fixture-policy-%02d", i)
		doc.Grants = append(doc.Grants, trustcatalog.Grant{ID: fmt.Sprintf("%032x", i+1), PolicyID: policy, ApproverKeyID: approver.ID, ApprovalSHA256: candidateHash([]byte("inert-approval-" + policy)), ManifestSHA256: candidateHash([]byte("inert-manifest-" + policy)), Revision: 1})
		doc.PolicyFloors[policy] = 1
	}
	initial := candidateD7Signed(t, doc, key, private)
	anchor := trustcatalog.Anchor{StoreID: doc.StoreID, InitialSHA256: candidateHash(initial), Keys: []trustcatalog.Key{key}, Threshold: 1}
	c := configuration{Addr: "127.0.0.1:0", StorePath: filepath.Join(directory, "trust"), AnchorFile: filepath.Join(directory, "anchor.json"), IdentitiesFile: filepath.Join(directory, "identities.json"), AuditDir: filepath.Join(directory, "data", "evidence"), RegistryCAFile: filepath.Join(directory, "registry-ca.pem"), TLSCertFile: certFile, TLSKeyFile: keyFile, TenantID: "ui-fixture-tenant", SiteID: "ui-fixture-site", Environment: "candidate", WebDir: webDir}
	f := &browserD9Endpoint{config: c, trustFile: filepath.Join(directory, "trust-config.json"), productFile: filepath.Join(directory, "product-config.json"), anchor: anchor, done: make(chan error, 1)}
	candidatePrivateFile(t, c.AnchorFile, candidateJSON(t, anchor))
	candidatePrivateFile(t, c.RegistryCAFile, registryCA)
	candidatePrivateFile(t, c.IdentitiesFile, candidateJSON(t, identities))
	candidatePrivateFile(t, f.trustFile, candidateJSON(t, c))
	candidatePrivateFile(t, f.productFile, candidateJSON(t, map[string]any{"addr": c.Addr, "dataDir": filepath.Join(directory, "data"), "identitiesFile": c.IdentitiesFile, "tlsCertFile": c.TLSCertFile, "tlsKeyFile": c.TLSKeyFile, "tenantId": c.TenantID, "siteId": c.SiteID, "environment": c.Environment, "managementObjectId": "ui-fixture-management"}))
	t.Cleanup(func() {
		for _, file := range []string{c.IdentitiesFile, f.trustFile, f.productFile} {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				t.Error("remove private browser runtime input")
			}
		}
	})
	store, err := truststate.Create(ctx, c.StorePath, anchor, initial)
	if err != nil {
		t.Fatal("create actual product trust store")
	}
	defer store.Close()
	audit, err := evidence.Open(c.AuditDir)
	if err != nil {
		t.Fatal("create actual shared product audit")
	}
	defer audit.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(registryCA) {
		t.Fatal("load explicit public fixture Registry authority")
	}
	scope := authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: "image-trust", ObjectID: doc.StoreID, Environment: c.Environment}
	backend, err := product.New(ctx, product.Config{Store: store, Audit: audit, Scope: scope, WritesEnabled: true, RegistryRoots: roots})
	if err != nil {
		t.Fatal("compose actual fixture backend")
	}
	actor := authz.Principal{ID: "ui-fixture-admin", TenantID: c.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope}}
	for generation := uint64(2); generation <= 3; generation++ {
		doc.Generation = generation
		if _, err := backend.Update(ctx, actor, candidateD7Signed(t, doc, key, private)); err != nil {
			t.Fatal("commit actual signed fixture update")
		}
	}
	for i := 0; i < 20; i++ {
		if _, err := backend.Update(ctx, actor, []byte(`{}`)); err == nil {
			t.Fatal("unsigned product fixture update accepted")
		}
	}
	before, inspectErr := store.Inspect(ctx)
	journal, journalErr := store.Journal(ctx)
	verified, auditErr := audit.Verify()
	if inspectErr != nil || journalErr != nil || auditErr != nil || !verified.Valid || verified.Count != 44 || len(journal) != 22 || before.Catalogue.Generation != 3 || len(before.Catalogue.Grants) != 25 || before.LedgerUsed != 0 {
		t.Fatal("shared product fixture facts incomplete")
	}
	for _, entry := range journal {
		if !entry.Acknowledged {
			t.Fatal("product fixture operation lacks durable acknowledgement")
		}
	}
	f.sequence = before.Sequence
	return f
}

// The ordinary/race no-environment branch is inert. The offline browser gate
// starts this exact helper separately; every endpoint is the actual complete
// product composition. No API response, TLS verification or handler is mocked.
func TestCandidateD9LiveHTTPSProductBrowserFixture(t *testing.T) {
	root := os.Getenv("CHENGWANG_D9_UI_FIXTURE_ROOT")
	if root == "" {
		return
	}
	runRoot, webDir := os.Getenv("RUN_ROOT"), os.Getenv("CHENGWANG_D9_UI_WEB_DIR")
	var stat unix.Stat_t
	entries, err := os.ReadDir(root)
	if runRoot == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(root, filepath.Clean(runRoot)+string(os.PathSeparator)) || webDir == "" || unix.Lstat(root, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || err != nil || len(entries) != 0 {
		t.Fatal("private HTTPS product fixture path rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	trusted, unrelated := browserD9CA(t, 100), browserD9CA(t, 101)
	caFile, serverCertFile := filepath.Join(root, "ca.pem"), filepath.Join(root, "server-cert.pem")
	candidatePrivateFile(t, caFile, trusted.pem)
	profile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	tokens := map[authz.Role]string{}
	managementScope := authz.ResourceScope{TenantID: "ui-fixture-tenant", SiteID: "ui-fixture-site", ObjectType: "control-plane", ObjectID: "ui-fixture-management", Environment: "candidate"}
	trustScope := managementScope
	trustScope.ObjectType, trustScope.ObjectID = "image-trust", strings.Repeat("a", 32)
	for _, role := range []authz.Role{authz.RoleAuditor, authz.RoleViewer} {
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			t.Fatal("generate private product browser identity")
		}
		tokens[role] = token
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: "ui-fixture-" + string(role), TokenHash: hash, Principal: authz.Principal{ID: "ui-fixture-" + string(role), TenantID: managementScope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{managementScope, trustScope}}})
	}
	wrongToken, _, err := authn.GenerateToken(32)
	if err != nil {
		t.Fatal("generate unrelated product browser token")
	}
	var endpoints []*browserD9Endpoint
	privateFiles := []string{caFile, serverCertFile, filepath.Join(root, "ready.json"), filepath.Join(root, ".ready.tmp")}
	t.Cleanup(func() {
		cancel()
		for _, endpoint := range endpoints {
			if endpoint.started && !endpoint.stopped {
				select {
				case <-endpoint.done:
					endpoint.stopped = true
				case <-time.After(12 * time.Second):
					t.Error("product browser runtime failed to stop")
				}
			}
		}
		for _, file := range privateFiles {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				t.Error("remove temporary TLS/browser material")
			}
		}
	})
	urls := map[string]string{}
	for index, kind := range []string{"trusted", "untrusted", "wrong-san", "expired"} {
		authority := trusted
		if kind == "untrusted" {
			authority = unrelated
		}
		certificate, private := browserD9Leaf(t, authority, kind, int64(200+index))
		certFile := filepath.Join(root, kind+"-server-cert.pem")
		if kind == "trusted" {
			certFile = serverCertFile
		}
		keyFile := filepath.Join(root, kind+"-server-key.private.pem")
		privateFiles = append(privateFiles, certFile, keyFile)
		candidatePrivateFile(t, certFile, certificate)
		candidatePrivateFile(t, keyFile, private)
		endpoint := browserD9Prepare(t, ctx, filepath.Join(root, kind), webDir, certFile, keyFile, trusted.pem, profile)
		endpoints = append(endpoints, endpoint)
		ready := make(chan string, 1)
		endpoint.started = true
		go func() {
			endpoint.done <- runProductWithRequestObserver(ctx, endpoint.trustFile, endpoint.productFile, func(network, address string) (net.Listener, error) {
				listener, err := net.Listen(network, address)
				if err == nil {
					ready <- "https://" + listener.Addr().String() + "/trust.html"
				}
				return listener, err
			}, func(request *http.Request) {
				endpoint.requests.Add(1)
				if request.Method != http.MethodGet && request.Method != http.MethodHead {
					endpoint.writeRequests.Add(1)
				}
				switch request.URL.Path {
				case "/api/v1/image-trust":
					endpoint.statusRequests.Add(1)
				case "/api/v1/image-trust/history":
					endpoint.historyRequests.Add(1)
				case "/api/v1/operations":
					endpoint.operationsRequests.Add(1)
				case "/api/v1/capabilities":
					endpoint.capabilityRequests.Add(1)
				}
			})
		}()
		select {
		case urls[kind] = <-ready:
		case <-endpoint.done:
			endpoint.stopped = true
			t.Fatal("complete HTTPS product runtime failed before listener")
		case <-time.After(6 * time.Second):
			t.Fatal("complete HTTPS product listener was not ready")
		}
	}
	readyObject := map[string]any{"url": urls["trusted"], "auditorToken": tokens[authz.RoleAuditor], "viewerToken": tokens[authz.RoleViewer], "wrongToken": wrongToken, "productScope": managementScope, "tls": map[string]string{"caFile": caFile, "serverCertFile": serverCertFile, "untrustedURL": urls["untrusted"], "wrongSANURL": urls["wrong-san"], "expiredURL": urls["expired"]}}
	raw, err := json.Marshal(readyObject)
	if err != nil {
		t.Fatal("encode private HTTPS readiness")
	}
	file, err := os.OpenFile(filepath.Join(root, ".ready.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create private HTTPS readiness")
	}
	_, writeErr := file.Write(raw)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || os.Rename(filepath.Join(root, ".ready.tmp"), filepath.Join(root, "ready.json")) != nil {
		t.Fatal("publish private HTTPS readiness")
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("HTTPS product browser fixture exceeded lifetime")
		case <-ticker.C:
			for _, endpoint := range endpoints {
				select {
				case <-endpoint.done:
					endpoint.stopped = true
					t.Fatal("complete product runtime exited before stop")
				default:
				}
			}
			if unix.Lstat(filepath.Join(root, "stop"), &stat) != nil {
				continue
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
				t.Fatal("unsafe product browser stop signal")
			}
			cancel()
			for index, endpoint := range endpoints {
				select {
				case err := <-endpoint.done:
					endpoint.stopped = true
					if err != nil {
						t.Fatal("complete HTTPS product shutdown failed")
					}
				case <-time.After(12 * time.Second):
					t.Fatal("complete HTTPS product retained runtime")
				}
				if endpoint.writeRequests.Load() != 0 || index != 0 && endpoint.requests.Load() != 0 {
					t.Fatal("TLS negative reached actual HTTP handler or browser used writes")
				}
				if index == 0 && (endpoint.statusRequests.Load() == 0 || endpoint.historyRequests.Load() == 0 || endpoint.operationsRequests.Load() == 0 || endpoint.capabilityRequests.Load() == 0) {
					t.Fatal("browser did not read actual product and trust APIs")
				}
				store, err := truststate.Open(context.Background(), endpoint.config.StorePath, endpoint.anchor)
				if err != nil {
					t.Fatal("complete product retained managed lock")
				}
				state, inspectErr := store.Inspect(context.Background())
				journal, journalErr := store.Journal(context.Background())
				closeErr := store.Close()
				if inspectErr != nil || journalErr != nil || closeErr != nil || state.Sequence != endpoint.sequence || state.Catalogue.Generation != 3 || len(state.Catalogue.Grants) != 25 || state.LedgerUsed != 0 || len(journal) != 22 {
					t.Fatal("complete product browser changed managed state")
				}
				audit, err := evidence.Open(endpoint.config.AuditDir)
				if err != nil {
					t.Fatal("complete product retained shared audit lock")
				}
				verified, verifyErr := audit.Verify()
				closeErr = audit.Close()
				if verifyErr != nil || closeErr != nil || !verified.Valid || verified.Count != 44 {
					t.Fatal("complete product browser changed or damaged shared audit")
				}
			}
			t.Log("CANDIDATE_D9_HTTPS_PRODUCT_FIXTURE=PASS actual_product_runtime=true shared_audit=true journal=22 audit=44 readonly=true negative_http=0 authorization=BLOCKED")
			return
		}
	}
}
