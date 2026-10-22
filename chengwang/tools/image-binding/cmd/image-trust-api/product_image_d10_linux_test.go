//go:build linux && productimage

package main

// This opt-in CI fixture provisions temporary inert materials, never a server.
// The product under test must be the actual image entrypoint. It is not a
// production bootstrap, recovery tool, approval source or deployment permit.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"chengwang/image-binding/product"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	"golang.org/x/sys/unix"
)

var imageD10Kinds = []string{"trusted", "untrusted", "wrong-san", "expired"}

type imageD10Expected struct {
	Version   int                `json:"version"`
	Endpoints []imageD10Endpoint `json:"endpoints"`
}

type imageD10Endpoint struct {
	Kind          string              `json:"kind"`
	Anchor        trustcatalog.Anchor `json:"anchor"`
	Sequence      uint64              `json:"sequence"`
	CatalogueHash string              `json:"catalogueHash"`
	JournalHash   string              `json:"journalHash"`
	AuditHash     string              `json:"auditHash"`
}

type imageD10Ready struct {
	URL          string              `json:"url"`
	AuditorToken string              `json:"auditorToken"`
	ViewerToken  string              `json:"viewerToken"`
	WrongToken   string              `json:"wrongToken"`
	ProductScope authz.ResourceScope `json:"productScope"`
	TLS          struct {
		CAFile         string `json:"caFile"`
		ServerCertFile string `json:"serverCertFile"`
		UntrustedURL   string `json:"untrustedURL"`
		WrongSANURL    string `json:"wrongSANURL"`
		ExpiredURL     string `json:"expiredURL"`
	} `json:"tls"`
}

type imageD10Negative struct {
	Kind         string `json:"kind"`
	OriginalHash string `json:"originalHash"`
	AlteredHash  string `json:"alteredHash"`
}

func imageD10Fail(t *testing.T) {
	t.Helper()
	t.Fatal("isolated product image fixture rejected")
}

func imageD10JSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		imageD10Fail(t)
	}
	return raw
}

func imageD10Directory(t *testing.T, path string, exact bool) {
	t.Helper()
	var metadata unix.Stat_t
	if unix.Lstat(path, &metadata) != nil || metadata.Mode&unix.S_IFMT != unix.S_IFDIR || metadata.Uid != 10001 || metadata.Gid != 10001 || metadata.Mode&0022 != 0 || exact && metadata.Mode&07777 != 0700 {
		imageD10Fail(t)
	}
}

func imageD10Write(t *testing.T, path string, raw []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		imageD10Fail(t)
	}
	_, writeErr := file.Write(raw)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		imageD10Fail(t)
	}
}

func imageD10Private(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := readPrivate(path, 128<<10)
	if err != nil {
		imageD10Fail(t)
	}
	return raw
}

func imageD10Absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		imageD10Fail(t)
	}
}

func imageD10ExpectedRead(t *testing.T, root string) imageD10Expected {
	t.Helper()
	var expected imageD10Expected
	if strictDecode(imageD10Private(t, filepath.Join(root, "expected.private.json")), &expected) != nil || expected.Version != 1 || len(expected.Endpoints) != 4 {
		imageD10Fail(t)
	}
	for index, endpoint := range expected.Endpoints {
		if endpoint.Kind != imageD10Kinds[index] || endpoint.Sequence == 0 || endpoint.Anchor.StoreID != strings.Repeat("a", 32) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(endpoint.CatalogueHash) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(endpoint.JournalHash) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(endpoint.AuditHash) {
			imageD10Fail(t)
		}
	}
	return expected
}

// Every action uses a fixed, private test root and refuses arbitrary paths.
// prepare leaves its materials for the image; there is deliberately no cleanup
// callback deleting them when this short-lived preparer process exits.
func TestCandidateD10ProductImageFixture(t *testing.T) {
	root, action := os.Getenv("CHENGWANG_D10_ROOT"), os.Getenv("CHENGWANG_D10_ACTION")
	if os.Geteuid() != 10001 || os.Getegid() != 10001 || !regexp.MustCompile(`^/tmp/chengwang-product-image-[a-f0-9]{32}$`).MatchString(root) || filepath.Clean(root) != root {
		imageD10Fail(t)
	}
	imageD10Directory(t, root, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch action {
	case "prepare":
		imageD10Prepare(t, ctx, root)
		t.Log("D10_PRODUCT_IMAGE_PREPARE=PASS endpoints=4 journal=22 audit=44 ledger=0 server_started=false authorization=BLOCKED")
	case "verify":
		imageD10Absent(t, filepath.Join(root, "negative.private.json"))
		imageD10Verify(t, ctx, root, imageD10ExpectedRead(t, root))
		t.Log("D10_PRODUCT_IMAGE_VERIFY=PASS endpoints=4 journal=22 audit=44 ledger=0 state_unchanged=true locks_released=true authorization=BLOCKED")
	case "read":
		imageD10Read(t, ctx, root)
		t.Log("D10_PRODUCT_IMAGE_READ=PASS normal_tls=true generation=3 journal=22 ledger=0 parent_api=true viewer403=true wrong401=true writes423=true authorization=BLOCKED")
	case "negative-prepare", "negative-restore":
		imageD10NegativeAction(t, ctx, root, action)
		if action == "negative-prepare" {
			t.Log("D10_PRODUCT_IMAGE_NEGATIVE_PREPARE=PASS owned_input_only=true authorization=BLOCKED")
		} else {
			t.Log("D10_PRODUCT_IMAGE_NEGATIVE_RESTORE=PASS original_input_restored=true authorization=BLOCKED")
		}
	default:
		imageD10Fail(t)
	}
}

func imageD10Prepare(t *testing.T, ctx context.Context, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		imageD10Fail(t)
	}
	for _, entry := range entries {
		if entry.Name() == ".fixture-owner" {
			identity := strings.TrimPrefix(filepath.Base(root), "chengwang-product-image-")
			if !bytes.Equal(imageD10Private(t, filepath.Join(root, ".fixture-owner")), []byte(identity+"\n")) {
				imageD10Fail(t)
			}
			continue
		}
		if entry.Name() != "bin" && entry.Name() != "evidence" && entry.Name() != "tmp" {
			imageD10Fail(t)
		}
		imageD10Directory(t, filepath.Join(root, entry.Name()), false)
	}
	trusted, unrelated := browserD9CA(t, 100), browserD9CA(t, 101)
	imageD10Write(t, filepath.Join(root, "ca.pem"), trusted.pem)
	management := authz.ResourceScope{TenantID: "ui-fixture-tenant", SiteID: "ui-fixture-site", ObjectType: "control-plane", ObjectID: "ui-fixture-management", Environment: "candidate"}
	trustScope := management
	trustScope.ObjectType, trustScope.ObjectID = "image-trust", strings.Repeat("a", 32)
	identities := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	tokens := map[authz.Role]string{}
	for _, role := range []authz.Role{authz.RoleAuditor, authz.RoleViewer, authz.RoleAdmin} {
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			imageD10Fail(t)
		}
		tokens[role] = token
		identities.Identities = append(identities.Identities, authn.Identity{TokenID: "ui-fixture-" + string(role), TokenHash: hash, Principal: authz.Principal{ID: "ui-fixture-" + string(role), TenantID: management.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{management, trustScope}}})
	}
	wrong, _, err := authn.GenerateToken(32)
	if err != nil {
		imageD10Fail(t)
	}
	imageD10Write(t, filepath.Join(root, "admin-token.private"), []byte(tokens[authz.RoleAdmin]))
	expected := imageD10Expected{Version: 1, Endpoints: []imageD10Endpoint{}}
	for index, kind := range imageD10Kinds {
		directory := filepath.Join(root, kind)
		if os.Mkdir(directory, 0700) != nil || os.Mkdir(filepath.Join(directory, "data"), 0700) != nil {
			imageD10Fail(t)
		}
		authority := trusted
		if kind == "untrusted" {
			authority = unrelated
		}
		certificate, privateKey := browserD9Leaf(t, authority, kind, int64(200+index))
		certPath, keyPath := filepath.Join(directory, "server-cert.pem"), filepath.Join(directory, "server-key.private.pem")
		imageD10Write(t, certPath, certificate)
		imageD10Write(t, keyPath, privateKey)
		if kind == "trusted" {
			imageD10Write(t, filepath.Join(root, "server-cert.pem"), certificate)
		}
		public, signingKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			imageD10Fail(t)
		}
		key := trustcatalog.Key{ID: trustcatalog.KeyID(public), PublicKey: public}
		approverPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			imageD10Fail(t)
		}
		approver := trustcatalog.Key{ID: trustcatalog.KeyID(approverPublic), PublicKey: approverPublic}
		now := time.Now().Unix()
		doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: trustScope.ObjectID, Generation: 1, NotBeforeUnix: now - 30, NotAfterUnix: now + 1200, RootKeys: []trustcatalog.Key{key}, Threshold: 1, Approvers: []trustcatalog.Key{approver}, Grants: []trustcatalog.Grant{}, PolicyFloors: map[string]uint64{}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
		for i := 0; i < 25; i++ {
			policyID := fmt.Sprintf("ui-fixture-policy-%02d", i)
			doc.Grants = append(doc.Grants, trustcatalog.Grant{ID: fmt.Sprintf("%032x", i+1), PolicyID: policyID, ApproverKeyID: approver.ID, ApprovalSHA256: candidateHash([]byte("inert-approval-" + policyID)), ManifestSHA256: candidateHash([]byte("inert-manifest-" + policyID)), Revision: 1})
			doc.PolicyFloors[policyID] = 1
		}
		initial := candidateD7Signed(t, doc, key, signingKey)
		anchor := trustcatalog.Anchor{StoreID: doc.StoreID, InitialSHA256: candidateHash(initial), Keys: []trustcatalog.Key{key}, Threshold: 1}
		config := configuration{Addr: fmt.Sprintf("127.0.0.1:%d", 17812+index), StorePath: filepath.Join(directory, "trust"), AnchorFile: filepath.Join(directory, "anchor.json"), IdentitiesFile: filepath.Join(directory, "identities.json"), AuditDir: filepath.Join(directory, "data", "evidence"), RegistryCAFile: filepath.Join(directory, "registry-ca.pem"), TLSCertFile: certPath, TLSKeyFile: keyPath, TenantID: management.TenantID, SiteID: management.SiteID, Environment: "candidate", WebDir: "/app/web", WritesEnabled: false}
		imageD10Write(t, config.AnchorFile, imageD10JSON(t, anchor))
		imageD10Write(t, config.RegistryCAFile, trusted.pem)
		imageD10Write(t, config.IdentitiesFile, imageD10JSON(t, identities))
		imageD10Write(t, filepath.Join(directory, "trust-config.json"), imageD10JSON(t, config))
		productConfig := productConfiguration{Addr: config.Addr, DataDir: filepath.Join(directory, "data"), IdentitiesFile: config.IdentitiesFile, TLSCertFile: certPath, TLSKeyFile: keyPath, TenantID: management.TenantID, SiteID: management.SiteID, Environment: management.Environment, ManagementObjectID: management.ObjectID}
		imageD10Write(t, filepath.Join(directory, "product-config.json"), imageD10JSON(t, productConfig))
		expected.Endpoints = append(expected.Endpoints, imageD10Seed(t, ctx, kind, config, anchor, initial, doc, key, signingKey, trusted.pem))
	}
	ready := imageD10Ready{URL: "https://127.0.0.1:17812/trust.html", AuditorToken: tokens[authz.RoleAuditor], ViewerToken: tokens[authz.RoleViewer], WrongToken: wrong, ProductScope: management}
	ready.TLS.CAFile, ready.TLS.ServerCertFile = filepath.Join(root, "ca.pem"), filepath.Join(root, "server-cert.pem")
	ready.TLS.UntrustedURL, ready.TLS.WrongSANURL, ready.TLS.ExpiredURL = "https://127.0.0.1:17813/trust.html", "https://127.0.0.1:17814/trust.html", "https://127.0.0.1:17815/trust.html"
	imageD10Write(t, filepath.Join(root, "expected.private.json"), imageD10JSON(t, expected))
	imageD10Verify(t, ctx, root, expected)
	imageD10Write(t, filepath.Join(root, "ready.json"), imageD10JSON(t, ready))
}

func imageD10Seed(t *testing.T, ctx context.Context, kind string, config configuration, anchor trustcatalog.Anchor, initial []byte, doc trustcatalog.Document, key trustcatalog.Key, signingKey ed25519.PrivateKey, registryCA []byte) imageD10Endpoint {
	t.Helper()
	store, err := truststate.Create(ctx, config.StorePath, anchor, initial)
	if err != nil {
		imageD10Fail(t)
	}
	defer func() {
		if store.Close() != nil {
			imageD10Fail(t)
		}
	}()
	audit, err := evidence.Open(config.AuditDir)
	if err != nil {
		imageD10Fail(t)
	}
	defer func() {
		if audit.Close() != nil {
			imageD10Fail(t)
		}
	}()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(registryCA) {
		imageD10Fail(t)
	}
	scope := authz.ResourceScope{TenantID: config.TenantID, SiteID: config.SiteID, ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: config.Environment}
	backend, err := product.New(ctx, product.Config{Store: store, Audit: audit, Scope: scope, WritesEnabled: true, RegistryRoots: roots})
	if err != nil {
		imageD10Fail(t)
	}
	actor := authz.Principal{ID: "ui-fixture-admin", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope}}
	for generation := uint64(2); generation <= 3; generation++ {
		doc.Generation = generation
		if _, err := backend.Update(ctx, actor, candidateD7Signed(t, doc, key, signingKey)); err != nil {
			imageD10Fail(t)
		}
	}
	for i := 0; i < 20; i++ {
		if _, err := backend.Update(ctx, actor, []byte(`{}`)); err == nil {
			imageD10Fail(t)
		}
	}
	return imageD10Snapshot(t, ctx, kind, anchor, store, audit)
}

func imageD10Snapshot(t *testing.T, ctx context.Context, kind string, anchor trustcatalog.Anchor, store *truststate.Store, audit *evidence.Store) imageD10Endpoint {
	t.Helper()
	state, stateErr := store.Inspect(ctx)
	journal, journalErr := store.Journal(ctx)
	report, auditErr := audit.Verify()
	if stateErr != nil || journalErr != nil || auditErr != nil || !state.CatalogueValid || state.Authorization != "BLOCKED" || state.Catalogue.Generation != 3 || len(state.Catalogue.Grants) != 25 || state.LedgerUsed != 0 || len(state.Consumptions) != 0 || len(journal) != 22 || !report.Valid || report.Count != 44 {
		imageD10Fail(t)
	}
	for _, entry := range journal {
		if !entry.Acknowledged || entry.Operation.PreparedAuditHash == "" || entry.ResultAuditHash == "" {
			imageD10Fail(t)
		}
	}
	return imageD10Endpoint{Kind: kind, Anchor: anchor, Sequence: state.Sequence, CatalogueHash: candidateHash(imageD10JSON(t, state.Catalogue)), JournalHash: candidateHash(imageD10JSON(t, journal)), AuditHash: report.LastHash}
}

func imageD10Verify(t *testing.T, ctx context.Context, root string, expected imageD10Expected) {
	t.Helper()
	for _, endpoint := range expected.Endpoints {
		directory := filepath.Join(root, endpoint.Kind)
		imageD10Directory(t, directory, true)
		store, err := truststate.Open(ctx, filepath.Join(directory, "trust"), endpoint.Anchor)
		if err != nil {
			imageD10Fail(t)
		}
		audit, err := evidence.Open(filepath.Join(directory, "data", "evidence"))
		if err != nil {
			_ = store.Close()
			imageD10Fail(t)
		}
		actual := imageD10Snapshot(t, ctx, endpoint.Kind, endpoint.Anchor, store, audit)
		auditClose, storeClose := audit.Close(), store.Close()
		if auditClose != nil || storeClose != nil || !bytes.Equal(imageD10JSON(t, actual), imageD10JSON(t, endpoint)) {
			imageD10Fail(t)
		}
	}
}

func imageD10Read(t *testing.T, ctx context.Context, root string) {
	t.Helper()
	expected := imageD10ExpectedRead(t, root)
	var ready imageD10Ready
	management := authz.ResourceScope{TenantID: "ui-fixture-tenant", SiteID: "ui-fixture-site", ObjectType: "control-plane", ObjectID: "ui-fixture-management", Environment: "candidate"}
	if strictDecode(imageD10Private(t, filepath.Join(root, "ready.json")), &ready) != nil || ready.URL != "https://127.0.0.1:17812/trust.html" || ready.ProductScope != management {
		imageD10Fail(t)
	}
	admin := string(imageD10Private(t, filepath.Join(root, "admin-token.private")))
	secrets := []string{admin, ready.AuditorToken, ready.ViewerToken, ready.WrongToken}
	for _, secret := range secrets {
		if len(secret) < 32 || len(secret) > 4096 || strings.ContainsAny(secret, "\r\n ,") {
			imageD10Fail(t)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(imageD10Private(t, filepath.Join(root, "ca.pem"))) {
		imageD10Fail(t)
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path, token string, want int) []byte {
		t.Helper()
		var body io.Reader
		if method != http.MethodGet {
			body = strings.NewReader(`{"invalid":"write gate must refuse before parsing"}`)
		}
		request, err := http.NewRequestWithContext(ctx, method, "https://127.0.0.1:17812"+path, body)
		if err != nil {
			imageD10Fail(t)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			imageD10Fail(t)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(raw) > 1<<20 || response.StatusCode != want || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
			imageD10Fail(t)
		}
		for _, secret := range append(secrets, "BEGIN PRIVATE KEY") {
			if bytes.Contains(raw, []byte(secret)) {
				imageD10Fail(t)
			}
		}
		return raw
	}
	var status imagetrust.Status
	if json.Unmarshal(call(http.MethodGet, "/api/v1/image-trust", ready.AuditorToken, http.StatusOK), &status) != nil || status.Boundary != imagetrust.StatusBoundary || status.Authorization != "BLOCKED" || status.DeviceActionsExecuted || status.StoreID != expected.Endpoints[0].Anchor.StoreID || status.Generation != 3 || status.Sequence != expected.Endpoints[0].Sequence || status.LedgerEntries != 0 || status.Reserved != 0 || status.Consumed != 0 || len(status.Policies) != 25 {
		imageD10Fail(t)
	}
	var history imagetrust.History
	if json.Unmarshal(call(http.MethodGet, "/api/v1/image-trust/history?limit=50", ready.AuditorToken, http.StatusOK), &history) != nil || history.Boundary != imagetrust.HistoryBoundary || history.Authorization != "BLOCKED" || history.DeviceActionsExecuted || history.Total != 22 || len(history.Entries) != 22 || history.Sequence != status.Sequence {
		imageD10Fail(t)
	}
	for _, entry := range history.Entries {
		if !entry.Acknowledged {
			imageD10Fail(t)
		}
	}
	query := url.Values{"tenantId": {"ui-fixture-tenant"}, "siteId": {"ui-fixture-site"}, "objectType": {"control-plane"}, "objectId": {"ui-fixture-management"}, "environment": {"candidate"}}
	var operations struct {
		Effect                string            `json:"effect"`
		DeviceActionsExecuted bool              `json:"deviceActionsExecuted"`
		Operations            []json.RawMessage `json:"operations"`
		Total                 int               `json:"total"`
		Truncated             bool              `json:"truncated"`
	}
	if json.Unmarshal(call(http.MethodGet, "/api/v1/operations?"+query.Encode(), ready.ViewerToken, http.StatusOK), &operations) != nil || operations.Effect != "local_record_only" || operations.DeviceActionsExecuted || operations.Total != 0 || operations.Truncated || operations.Operations == nil || len(operations.Operations) != 0 {
		imageD10Fail(t)
	}
	var capabilities struct {
		ProductionControlEnabled bool              `json:"productionControlEnabled"`
		Capabilities             []json.RawMessage `json:"capabilities"`
	}
	if json.Unmarshal(call(http.MethodGet, "/api/v1/capabilities", "", http.StatusOK), &capabilities) != nil || capabilities.ProductionControlEnabled || len(capabilities.Capabilities) == 0 {
		imageD10Fail(t)
	}
	call(http.MethodGet, "/api/v1/image-trust/history", ready.ViewerToken, http.StatusForbidden)
	call(http.MethodGet, "/api/v1/image-trust", ready.WrongToken, http.StatusUnauthorized)
	call(http.MethodGet, "/api/v1/image-trust", "", http.StatusUnauthorized)
	call(http.MethodPost, "/api/v1/operations", admin, http.StatusLocked)
	call(http.MethodPost, "/api/v1/publish", admin, http.StatusLocked)
	call(http.MethodPut, "/api/v1/image-trust/catalogue", admin, http.StatusLocked)
	call(http.MethodPost, "/api/v1/image-trust/verifications", admin, http.StatusLocked)
}

func imageD10NegativePath(t *testing.T, root, kind string) string {
	t.Helper()
	base := filepath.Join(root, "trusted")
	switch kind {
	case "missing-checkpoint":
		return filepath.Join(base, "data", "evidence", "checkpoint.json")
	case "missing-tls":
		return filepath.Join(base, "server-key.private.pem")
	case "wrong-mode":
		return filepath.Join(base, "identities.json")
	case "unknown-config":
		return filepath.Join(base, "product-config.json")
	default:
		imageD10Fail(t)
		return ""
	}
}

func imageD10NegativeAction(t *testing.T, ctx context.Context, root, action string) {
	t.Helper()
	kind := os.Getenv("CHENGWANG_D10_NEGATIVE")
	path := imageD10NegativePath(t, root, kind)
	backup, marker := path+".d10-backup.private", filepath.Join(root, "negative.private.json")
	if action == "negative-prepare" {
		imageD10Absent(t, marker)
		imageD10Absent(t, backup)
		imageD10Verify(t, ctx, root, imageD10ExpectedRead(t, root))
		original := imageD10Private(t, path)
		record := imageD10Negative{Kind: kind, OriginalHash: candidateHash(original)}
		if kind == "unknown-config" {
			var object map[string]json.RawMessage
			if strictDecode(original, &object) != nil || object == nil {
				imageD10Fail(t)
			}
			object["d10UnknownField"] = json.RawMessage(`true`)
			altered := imageD10JSON(t, object)
			record.AlteredHash = candidateHash(altered)
			imageD10Write(t, marker, imageD10JSON(t, record))
			if os.Rename(path, backup) != nil {
				imageD10Fail(t)
			}
			imageD10Write(t, path, altered)
		} else {
			imageD10Write(t, marker, imageD10JSON(t, record))
			if kind == "wrong-mode" {
				if os.Chmod(path, 0644) != nil {
					imageD10Fail(t)
				}
			} else if os.Rename(path, backup) != nil {
				imageD10Fail(t)
			}
		}
		return
	}
	var record imageD10Negative
	if strictDecode(imageD10Private(t, marker), &record) != nil || record.Kind != kind || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(record.OriginalHash) {
		imageD10Fail(t)
	}
	if kind == "unknown-config" && !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(record.AlteredHash) || kind != "unknown-config" && record.AlteredHash != "" {
		imageD10Fail(t)
	}
	// Permit only the exact original already restored after a short-lived
	// preparer crash; never synthesize a replacement or overwrite another file.
	if raw, err := readPrivate(path, 128<<10); err == nil && candidateHash(raw) == record.OriginalHash {
		imageD10Absent(t, backup)
		if os.Remove(marker) != nil {
			imageD10Fail(t)
		}
		imageD10Verify(t, ctx, root, imageD10ExpectedRead(t, root))
		return
	}
	if kind == "wrong-mode" {
		var metadata unix.Stat_t
		if unix.Lstat(path, &metadata) != nil || metadata.Mode&unix.S_IFMT != unix.S_IFREG || metadata.Mode&07777 != 0644 || metadata.Uid != 10001 || metadata.Gid != 10001 || metadata.Nlink != 1 || metadata.Size <= 0 || metadata.Size > 128<<10 {
			imageD10Fail(t)
		}
		// The parent path is fixed inside the already checked private root. A
		// no-follow FD prevents restoring an attacker-replaced symbolic link.
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			imageD10Fail(t)
		}
		file := os.NewFile(uintptr(fd), "owned-negative-input")
		var opened unix.Stat_t
		if unix.Fstat(fd, &opened) != nil || opened.Dev != metadata.Dev || opened.Ino != metadata.Ino || opened.Mode != metadata.Mode || opened.Nlink != 1 || opened.Uid != 10001 || opened.Gid != 10001 {
			_ = file.Close()
			imageD10Fail(t)
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
		chmodErr := error(nil)
		if readErr == nil && candidateHash(raw) == record.OriginalHash {
			chmodErr = file.Chmod(0600)
		} else {
			chmodErr = errConfiguration
		}
		closeErr := file.Close()
		if chmodErr != nil || closeErr != nil {
			imageD10Fail(t)
		}
	} else {
		if candidateHash(imageD10Private(t, backup)) != record.OriginalHash {
			imageD10Fail(t)
		}
		if kind == "unknown-config" {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				if err != nil || candidateHash(imageD10Private(t, path)) != record.AlteredHash || os.Remove(path) != nil {
					imageD10Fail(t)
				}
			}
		} else {
			imageD10Absent(t, path)
		}
		if os.Rename(backup, path) != nil {
			imageD10Fail(t)
		}
	}
	if candidateHash(imageD10Private(t, path)) != record.OriginalHash || os.Remove(marker) != nil {
		imageD10Fail(t)
	}
	imageD10Verify(t, ctx, root, imageD10ExpectedRead(t, root))
}
