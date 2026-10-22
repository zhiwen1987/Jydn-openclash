//go:build linux

package binding_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/product"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	"github.com/google/go-containerregistry/pkg/registry"
)

type managedAPIFixture struct {
	m          managedMaterial
	store      *truststate.Store
	audit      *evidence.Store
	identities *authn.Store
	scope      authz.ResourceScope
	service    *product.Service
	api        *httptest.Server
	registry   *httptest.Server
	roots      *x509.CertPool
	storePath  string
	auditPath  string
	tokens     map[string]string
	requests   atomic.Int32
}

func newManagedAPIFixture(t *testing.T, kind verifier.Kind, intercept func(http.ResponseWriter, *http.Request) bool) *managedAPIFixture {
	t.Helper()
	f := &managedAPIFixture{tokens: map[string]string{}}
	transport := minimalRegistryWithBlobMediaType(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	f.registry = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if intercept != nil && intercept(w, r) {
			return
		}
		transport.ServeHTTP(w, r)
	}))
	t.Cleanup(f.registry.Close)
	f.m = newManagedMaterial(t, signedImage(t, f.registry.URL, kind, hashed(f.registry.Certificate().RawSubjectPublicKeyInfo)))
	uploadImage(t, f.registry.Client(), f.registry.URL, f.m.material)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.registry.Certificate())
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	f.storePath, f.auditPath = filepath.Join(base, "trusted"), filepath.Join(base, "audit")
	var err error
	f.store, err = truststate.Create(context.Background(), f.storePath, f.m.anchor, f.m.catalogue)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	f.audit, err = evidence.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.audit.Close() })
	f.scope = authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", ObjectType: "image-trust", ObjectID: f.m.anchor.StoreID, Environment: "candidate"}
	identityFile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	for _, name := range []string{"admin", "operator", "viewer", "other-tenant", "other-site", "other-object", "other-environment"} {
		role := authz.RoleOperator
		if name == "admin" {
			role = authz.RoleAdmin
		}
		if name == "viewer" {
			role = authz.RoleViewer
		}
		scope := f.scope
		if name == "other-tenant" {
			scope.TenantID = "tenant-b"
		}
		if name == "other-site" {
			scope.SiteID = "site-b"
		}
		if name == "other-object" {
			scope.ObjectID = strings.Repeat("f", 32)
		}
		if name == "other-environment" {
			scope.Environment = "production"
		}
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			t.Fatal(err)
		}
		f.tokens[name] = token
		identityFile.Identities = append(identityFile.Identities, authn.Identity{TokenID: "token-" + name, TokenHash: hash, Principal: authz.Principal{ID: "actor-" + name, TenantID: scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	credentials := filepath.Join(base, "identities.json")
	if err := os.WriteFile(credentials, encode(t, identityFile), 0600); err != nil {
		t.Fatal(err)
	}
	f.identities, err = authn.Open(credentials)
	if err != nil {
		t.Fatal(err)
	}
	f.recompose(t, true)
	return f
}

func (f *managedAPIFixture) recompose(t *testing.T, writes bool) {
	t.Helper()
	service, err := product.New(context.Background(), product.Config{Store: f.store, Audit: f.audit, Scope: f.scope, WritesEnabled: writes, RegistryRoots: f.roots})
	if err != nil {
		t.Fatal(err)
	}
	f.service = service
	f.api = httptest.NewTLSServer(api.New(api.Options{Mode: "candidate", Authn: f.identities, ImageTrust: service, ImageTrustWritesEnabled: writes}))
	t.Cleanup(f.api.Close)
}

func (f *managedAPIFixture) body(t *testing.T) []byte {
	return encode(t, imagetrust.VerifyRequest{PolicyID: "isolated-fixture", Approval: f.m.approval, Bundle: f.m.bundle, TrustedRoot: f.m.root})
}

func managedAPIRequest(t *testing.T, server *httptest.Server, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("isolated product HTTP request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

func TestManagedAPIRealLifecycleAndBoundaries(t *testing.T) {
	f := newManagedAPIFixture(t, verifier.KindDSSE, nil)
	body := f.body(t)
	before, _ := f.store.Inspect(context.Background())
	requestsBefore, auditBefore := f.requests.Load(), f.audit.Status().Count
	for _, test := range []struct {
		name, method, path, actor string
		body                      []byte
		status                    int
	}{
		{"anonymous", http.MethodPost, "/api/v1/image-trust/verifications", "", body, 401},
		{"wrong-role", http.MethodPost, "/api/v1/image-trust/verifications", "viewer", body, 403},
		{"tenant", http.MethodPost, "/api/v1/image-trust/verifications", "other-tenant", body, 403},
		{"site", http.MethodPost, "/api/v1/image-trust/verifications", "other-site", body, 403},
		{"object", http.MethodPost, "/api/v1/image-trust/verifications", "other-object", body, 403},
		{"environment", http.MethodPost, "/api/v1/image-trust/verifications", "other-environment", body, 403},
		{"query", http.MethodPost, "/api/v1/image-trust/verifications?scope=production", "operator", body, 400},
		{"identity-injection", http.MethodPost, "/api/v1/image-trust/verifications", "operator", append(append([]byte{}, body[:len(body)-1]...), []byte(`,"principal":{"roles":["admin"]}}`)...), 400},
		{"duplicate", http.MethodPost, "/api/v1/image-trust/verifications", "operator", []byte(`{"policyId":"x","policyId":"y","approval":"YQ==","bundle":"YQ==","trustedRoot":"YQ=="}`), 400},
		{"noncanonical-base64", http.MethodPost, "/api/v1/image-trust/verifications", "operator", []byte(`{"policyId":"x","approval":"YR==","bundle":"YQ==","trustedRoot":"YQ=="}`), 400},
		{"operator-cannot-update", http.MethodPut, "/api/v1/image-trust/catalogue", "operator", f.m.catalogue, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, _ := managedAPIRequest(t, f.api, test.method, test.path, f.tokens[test.actor], test.body)
			if code != test.status {
				t.Fatalf("status=%d want=%d", code, test.status)
			}
		})
	}
	locked := httptest.NewTLSServer(api.New(api.Options{Authn: f.identities, ImageTrust: f.service, ImageTrustWritesEnabled: false}))
	for _, path := range []string{"/api/v1/image-trust/verifications", "/api/v1/image-trust/catalogue"} {
		method := http.MethodPost
		raw := body
		if strings.HasSuffix(path, "catalogue") {
			method = http.MethodPut
			raw = f.m.catalogue
		}
		if code, _ := managedAPIRequest(t, locked, method, path, f.tokens["admin"], raw); code != 423 {
			t.Fatal("API gate did not lock state consumption")
		}
	}
	locked.Close()
	after, err := f.store.Inspect(context.Background())
	if err != nil || after.Sequence != before.Sequence || after.LedgerUsed != 0 || f.requests.Load() != requestsBefore || f.audit.Status().Count != auditBefore {
		t.Fatal("denied HTTP request reached persistence, audit or Registry")
	}
	var invalid trustcatalog.Envelope
	if err := json.Unmarshal(f.m.catalogue, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid.Signatures[0].Signature[0] ^= 1
	for _, raw := range [][]byte{encode(t, invalid), f.m.catalogue} {
		code, _ := managedAPIRequest(t, f.api, http.MethodPut, "/api/v1/image-trust/catalogue", f.tokens["admin"], raw)
		if code == 200 {
			t.Fatal("admin bypassed signature or exact generation")
		}
	}
	after, err = f.store.Inspect(context.Background())
	if err != nil || after.Sequence != before.Sequence || after.LedgerUsed != 0 {
		t.Fatal("invalid signed update mutated state")
	}
	code, raw := managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], body)
	var receipt imagetrust.Receipt
	if code != 200 || json.Unmarshal(raw, &receipt) != nil || !receipt.Verified || receipt.Authorization != "BLOCKED" || receipt.DeviceActionsExecuted || receipt.GrantID != f.m.document.Grants[0].ID || receipt.ManifestSHA256 != hashed(f.m.manifest) {
		t.Fatalf("real product composition failed status=%d", code)
	}
	for _, token := range f.tokens {
		if bytes.Contains(raw, []byte(token)) {
			t.Fatal("credential in verification response")
		}
	}
	f.api.Close()
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := truststate.Open(context.Background(), f.storePath, f.m.anchor)
	if err != nil {
		t.Fatal(err)
	}
	f.store = reopened
	f.recompose(t, true)
	count := f.requests.Load()
	code, raw = managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], body)
	if code != http.StatusBadRequest || !bytes.Contains(raw, []byte(`"code":"image_trust_invalid"`)) || f.requests.Load() != count || bytes.Contains(raw, []byte(`"verified":true`)) {
		t.Fatal("HTTP replay or restart reached Registry/success")
	}
	code, raw = managedAPIRequest(t, f.api, http.MethodGet, "/api/v1/image-trust", f.tokens["viewer"], nil)
	var status imagetrust.Status
	if code != 200 || json.Unmarshal(raw, &status) != nil || status.Consumed != 1 || status.LedgerEntries != 1 || status.Authorization != "BLOCKED" || len(status.Policies) != 1 || status.Policies[0].State != "CONSUMED" {
		t.Fatal("real durable status did not report consumption")
	}
	for _, forbidden := range []string{`"payload"`, `"publicKey"`, `"bundle"`, `"token"`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("raw trust material in status")
		}
	}
	auditRaw, err := os.ReadFile(filepath.Join(f.auditPath, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(auditRaw, []byte(`"actorId":"actor-operator"`)) || !bytes.Contains(auditRaw, []byte(`"result":"verification_consumed"`)) {
		t.Fatal("authenticated actor or completion audit missing")
	}
	for _, token := range f.tokens {
		if bytes.Contains(auditRaw, []byte(token)) {
			t.Fatal("credential in audit")
		}
	}
	if bytes.Contains(auditRaw, []byte(base64.StdEncoding.EncodeToString(f.m.bundle))) {
		t.Fatal("raw bundle in audit")
	}
	if report, err := f.audit.Verify(); err != nil || !report.Valid {
		t.Fatal("product audit invalid")
	}
}

func TestManagedAPIAuditFailureAfterConsumption(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var enabled atomic.Bool
	var heads atomic.Int32
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unblock) }) }
	f := newManagedAPIFixture(t, verifier.KindDSSE, func(_ http.ResponseWriter, r *http.Request) bool {
		// HEAD/GET/HEAD for the initial manifest and the final manifest check.
		if enabled.Load() && r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") && heads.Add(1) == 4 {
			close(entered)
			<-unblock
		}
		return false
	})
	defer release()
	enabled.Store(true)
	request, err := http.NewRequest(http.MethodPost, f.api.URL+"/api/v1/image-trust/verifications", bytes.NewReader(f.body(t)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.tokens["operator"])
	request.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	response := make(chan *http.Response, 1)
	errors := make(chan error, 1)
	go func() {
		r, e := f.api.Client().Do(request)
		if e != nil {
			errors <- e
			return
		}
		response <- r
	}()
	select {
	case <-entered:
	case <-errors:
		t.Fatal("audit-fault HTTP transport failed")
	case <-ctx.Done():
		t.Fatal("verification never reached final Registry check")
	}
	if err := f.audit.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case r := <-response:
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 503 || !bytes.Contains(raw, []byte(`"stateMayHaveChanged":true`)) || bytes.Contains(raw, []byte(`"verified":true`)) {
			t.Fatal("post-consumption audit failure claimed success or safe retry")
		}
	case <-errors:
		t.Fatal("audit-fault call did not return safe error")
	case <-ctx.Done():
		t.Fatal("audit-fault request did not terminate")
	}
	state, err := f.store.Inspect(context.Background())
	if err != nil || state.LedgerUsed != 1 || state.Consumptions[0].Status != "CONSUMED" || len(state.Consumptions[0].EvidenceSHA256) != 71 {
		t.Fatal("audit failure test did not reach genuine durable verification")
	}
	if code, _ := managedAPIRequest(t, f.api, http.MethodGet, "/api/v1/image-trust", f.tokens["admin"], nil); code != 503 {
		t.Fatal("audit failure did not poison product service")
	}
}

func TestManagedAPINetworkRevocationAndBusy(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var enabled atomic.Bool
	var once, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unblock) }) }
	f := newManagedAPIFixture(t, verifier.KindMessageSignature, func(_ http.ResponseWriter, r *http.Request) bool {
		if enabled.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") {
			once.Do(func() { close(entered); <-unblock })
		}
		return false
	})
	defer release()
	enabled.Store(true)
	body := f.body(t)
	request, err := http.NewRequest(http.MethodPost, f.api.URL+"/api/v1/image-trust/verifications", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.tokens["operator"])
	request.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	response := make(chan *http.Response, 1)
	errors := make(chan error, 1)
	go func() {
		r, e := f.api.Client().Do(request)
		if e != nil {
			errors <- e
			return
		}
		response <- r
	}()
	select {
	case <-entered:
	case <-errors:
		t.Fatal("product verification transport failed")
	case <-ctx.Done():
		t.Fatal("product did not reach real Registry")
	}
	for i := 0; i < 4; i++ {
		if code, _ := managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], body); code != 429 {
			t.Fatal("busy verification queued or consumed another grant")
		}
	}
	revoked := f.m.document
	revoked.Generation++
	revoked.Grants = []trustcatalog.Grant{}
	revoked.RevokedManifests = []string{hashed(f.m.manifest)}
	if code, _ := managedAPIRequest(t, f.api, http.MethodPut, "/api/v1/image-trust/catalogue", f.tokens["admin"], signManagedCatalogue(t, revoked, f.m.rootKey)); code != 200 {
		t.Fatal("catalogue update could not interleave with Registry read")
	}
	release()
	select {
	case r := <-response:
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode == 200 || !bytes.Contains(raw, []byte(`"stateMayHaveChanged":true`)) {
			t.Fatal("revoked HTTP request returned success/optimistic state")
		}
	case <-errors:
		t.Fatal("product did not return safe rejection")
	case <-ctx.Done():
		t.Fatal("revoked product call did not terminate")
	}
	state, err := f.store.Inspect(context.Background())
	if err != nil || state.Catalogue.Generation != 2 || state.LedgerUsed != 1 || state.Consumptions[0].Status != "RESERVED" {
		t.Fatal("revocation or busy requests changed consumption incorrectly")
	}
}
