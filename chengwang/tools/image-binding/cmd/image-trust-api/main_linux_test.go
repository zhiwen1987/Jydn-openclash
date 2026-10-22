//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

func candidateJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func candidateHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func candidatePrivateFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

type candidateFixture struct {
	config     configuration
	file       string
	anchor     trustcatalog.Anchor
	catalogue  []byte
	token      string
	sequence   uint64
	auditCount uint64
}

func newCandidateFixture(t *testing.T, createStore bool) candidateFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := trustcatalog.Key{ID: trustcatalog.KeyID(public), PublicKey: public}
	now := time.Now()
	doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: strings.Repeat("a", 32), Generation: 1, NotBeforeUnix: now.Unix() - 30, NotAfterUnix: now.Unix() + 1200, RootKeys: []trustcatalog.Key{key}, Threshold: 1, Approvers: []trustcatalog.Key{}, Grants: []trustcatalog.Grant{}, PolicyFloors: map[string]uint64{}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	payload := candidateJSON(t, doc)
	catalogue := candidateJSON(t, trustcatalog.Envelope{Payload: payload, Signatures: []trustcatalog.Signature{{KeyID: key.ID, Signature: ed25519.Sign(private, append([]byte(trustcatalog.Schema+"\x00"), payload...))}}})
	anchor := trustcatalog.Anchor{StoreID: doc.StoreID, InitialSHA256: candidateHash(catalogue), Keys: []trustcatalog.Key{key}, Threshold: 1}
	config := configuration{Addr: "127.0.0.1:0", StorePath: filepath.Join(dir, "trust"), AnchorFile: filepath.Join(dir, "anchor.json"), IdentitiesFile: filepath.Join(dir, "identities.json"), AuditDir: filepath.Join(dir, "audit"), RegistryCAFile: filepath.Join(dir, "registry-ca.pem"), TenantID: "tenant-a", SiteID: "site-a", Environment: "candidate"}
	file := filepath.Join(dir, "candidate.json")
	f := candidateFixture{config: config, file: file, anchor: anchor, catalogue: catalogue}
	candidatePrivateFile(t, config.AnchorFile, candidateJSON(t, anchor))
	// Only a public test CA certificate reaches disk. All signing keys remain
	// in this test process; the candidate receives no private bootstrap key.
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-candidate-test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	candidatePrivateFile(t, config.RegistryCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
	token, tokenHash, err := authn.GenerateToken(32)
	if err != nil {
		t.Fatal(err)
	}
	f.token = token
	scope := authz.ResourceScope{TenantID: config.TenantID, SiteID: config.SiteID, ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: config.Environment}
	identities := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{{TokenID: "candidate-admin", TokenHash: tokenHash, Principal: authz.Principal{ID: "candidate-admin", TenantID: config.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope}}}}}
	candidatePrivateFile(t, config.IdentitiesFile, candidateJSON(t, identities))
	if createStore {
		store, err := truststate.Create(context.Background(), config.StorePath, anchor, catalogue)
		if err != nil {
			t.Fatal(err)
		}
		state, inspectErr := store.Inspect(context.Background())
		closeErr := store.Close()
		if inspectErr != nil || closeErr != nil {
			t.Fatal(inspectErr, closeErr)
		}
		f.sequence = state.Sequence
	}
	audit, err := evidence.Open(config.AuditDir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := audit.Verify()
	closeErr := audit.Close()
	if err != nil || closeErr != nil || !report.Valid {
		t.Fatal(err, closeErr)
	}
	f.auditCount = report.Count
	f.writeConfig(t)
	return f
}
func (f candidateFixture) writeConfig(t *testing.T) {
	t.Helper()
	// Exercise the absent-field default, not an explicit false switch.
	var object map[string]any
	if err := json.Unmarshal(candidateJSON(t, f.config), &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "writesEnabled")
	candidatePrivateFile(t, f.file, candidateJSON(t, object))
}

func TestCandidateStrictConfigurationDecode(t *testing.T) {
	for name, raw := range map[string][]byte{
		"duplicate":        []byte(`{"tenantId":"a","tenantId":"b"}`),
		"case_alias":       []byte(`{"tenantId":"a","TenantID":"b"}`),
		"write_alias":      []byte(`{"writesEnabled":false,"WritesEnabled":true}`),
		"escaped_alias":    []byte(`{"tenantId":"a","\u0074enantId":"b"}`),
		"invalid_utf8":     []byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'},
		"nested_duplicate": []byte(`{"scope":{"id":"a","id":"b"}}`),
		"unknown":          []byte(`{"tenantId":"a","bootstrap":true}`),
		"null":             []byte(`null`),
		"trailing":         []byte(`{"tenantId":"a"} {}`),
		"deep":             []byte(`{"x":[[[[[[[[[[[0]]]]]]]]]]]}`),
		"empty":            nil,
	} {
		t.Run(name, func(t *testing.T) {
			var config configuration
			if err := strictDecode(raw, &config); err != errConfiguration {
				t.Fatal("malformed configuration accepted", err)
			}
		})
	}
	var config configuration
	if err := strictDecode([]byte(`{"tenantId":"tenant-a","siteId":"site-a","environment":"candidate"}`), &config); err != nil || config.WritesEnabled {
		t.Fatal("valid configuration/default write gate", err)
	}
}

func TestCandidateRejectRelativeStatePaths(t *testing.T) {
	for _, field := range []string{"store", "audit", "identities"} {
		t.Run(field, func(t *testing.T) {
			fixture := newCandidateFixture(t, true)
			switch field {
			case "store":
				fixture.config.StorePath = "relative-store"
			case "audit":
				fixture.config.AuditDir = "relative-audit"
			case "identities":
				fixture.config.IdentitiesFile = "relative-identities"
			}
			fixture.writeConfig(t)
			listened := false
			if err := run(context.Background(), fixture.file, func(string, string) (net.Listener, error) { listened = true; return nil, errors.New("not allowed") }); err != errConfiguration || listened {
				t.Fatal("relative state path reached listener")
			}
		})
	}
}

func TestCandidateStrictIdentityProfile(t *testing.T) {
	fixture := newCandidateFixture(t, true)
	raw, err := readPrivate(fixture.config.IdentitiesFile, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"role-case-alias":  bytes.Replace(raw, []byte(`"roles":`), []byte(`"Roles":`), 1),
		"role-duplicate":   bytes.Replace(raw, []byte(`"roles":`), []byte(`"roles":["viewer"],"roles":`), 1),
		"scope-case-alias": bytes.Replace(raw, []byte(`"allowedScopes":`), []byte(`"AllowedScopes":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var file authn.File
			if strictDecode(bad, &file) != errConfiguration {
				t.Fatal("ambiguous private identity profile accepted")
			}
		})
	}
	var profile authn.File
	if strictDecode(raw, &profile) != nil {
		t.Fatal("valid identity profile rejected")
	}
	// Exact field checks must not reject legitimate explicitly false/zero
	// omitempty fields or typed timestamp scalars merely because marshal omits them.
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		t.Fatal("invalid identity fixture")
	}
	identity := object["identities"].([]any)[0].(map[string]any)
	identity["disabled"] = false
	identity["expiresAt"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if strictDecode(candidateJSON(t, object), &profile) != nil || profile.Identities[0].Disabled || profile.Identities[0].ExpiresAt == nil {
		t.Fatal("valid explicit identity defaults/timestamp rejected")
	}
}

func TestCandidatePrivateFilesRejectUnsafeInputs(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "directory_mode", "directory_symlink", "ancestor_write", "relative", "unclean", "missing", "directory", "empty", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "input")
			candidatePrivateFile(t, path, []byte("fixture"))
			var err error
			switch kind {
			case "symlink":
				original := path + ".original"
				err = os.Rename(path, original)
				if err == nil {
					err = os.Symlink(original, path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			case "mode":
				err = os.Chmod(path, 0644)
			case "directory_mode":
				err = os.Chmod(dir, 0755)
			case "directory_symlink":
				link := dir + "-link"
				err = os.Symlink(dir, link)
				path = filepath.Join(link, "input")
			case "ancestor_write":
				parent := filepath.Join(dir, "unsafe")
				err = os.Mkdir(parent, 0700)
				if err == nil {
					err = os.Chmod(parent, 0777)
				}
				leaf := filepath.Join(parent, "private")
				if err == nil {
					err = os.Mkdir(leaf, 0700)
				}
				path = filepath.Join(leaf, "input")
				if err == nil {
					candidatePrivateFile(t, path, []byte("fixture"))
				}
			case "relative":
				path = "relative-private-input"
			case "unclean":
				path = dir + "/./input"
			case "missing":
				path = filepath.Join(dir, "missing")
			case "directory":
				path = dir
			case "empty":
				candidatePrivateFile(t, path, nil)
			case "oversized":
				candidatePrivateFile(t, path, bytes.Repeat([]byte("x"), 1025))
			}
			if err != nil {
				t.Fatal(err)
			}
			if raw, err := readPrivate(path, 1024); err != errConfiguration || raw != nil {
				t.Fatal("unsafe private input accepted", err)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "input")
		candidatePrivateFile(t, path, []byte("fixture"))
		raw, err := readPrivate(path, 1024)
		if err != nil || string(raw) != "fixture" {
			t.Fatal("valid private file rejected", err)
		}
	})
}

func TestCandidateNonLoopbackRequiresTLSBeforeListen(t *testing.T) {
	for _, address := range []string{"0.0.0.0:7812", "10.88.0.20:7812", "[::]:7812", "candidate.invalid:7812"} {
		t.Run(address, func(t *testing.T) {
			f := newCandidateFixture(t, true)
			f.config.Addr = address
			f.writeConfig(t)
			called := false
			err := run(context.Background(), f.file, func(string, string) (net.Listener, error) { called = true; return nil, errors.New("unexpected listen") })
			if err != errConfiguration || called {
				t.Fatal("candidate listened insecurely", err)
			}
		})
	}
}

func TestCandidateMissingStoreNeverBootstraps(t *testing.T) {
	f := newCandidateFixture(t, false)
	called := false
	err := run(context.Background(), f.file, func(string, string) (net.Listener, error) { called = true; return nil, errors.New("unexpected listen") })
	if err != errConfiguration || called {
		t.Fatal("missing store reached listener", err)
	}
	if _, err := os.Lstat(f.config.StorePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate initialized missing trust store", err)
	}
}

func TestCandidateRunAuthenticatedReadDefaultLockedAndGracefulClose(t *testing.T) {
	f := newCandidateFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, f.file, func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != "127.0.0.1:0" {
				return nil, errors.New("unexpected listener configuration")
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
				t.Error("candidate failed to close")
			}
		}
	})
	var address string
	select {
	case address = <-ready:
	case err := <-done:
		stopped = true
		t.Fatal("candidate failed before listener", err)
	case <-time.After(5 * time.Second):
		t.Fatal("candidate listener did not start")
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	call := func(method, path string, body []byte, authenticated bool, want int) []byte {
		t.Helper()
		request, err := http.NewRequest(method, "http://"+address+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			request.Header.Set("Authorization", "Bearer "+f.token)
		}
		if method == http.MethodPut || method == http.MethodPost {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(readErr, closeErr)
		}
		if response.StatusCode != want {
			t.Fatalf("method=%s status=%d want=%d", method, response.StatusCode, want)
		}
		if bytes.Contains(raw, []byte(f.token)) || bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) {
			t.Fatal("candidate exposed secret")
		}
		return raw
	}
	call(http.MethodGet, "/api/v1/image-trust", nil, false, http.StatusUnauthorized)
	for _, path := range []string{"/api/v1/snapshot", "/api/v1/versions", "/api/v1/operations", "/api/v1/publish"} {
		raw := call(http.MethodGet, path, nil, true, http.StatusNotFound)
		if !bytes.Contains(raw, []byte(`"code":"candidate_route_disabled"`)) {
			t.Fatal("unconfigured product subsystem was exposed")
		}
	}
	decodeStatus := func(raw []byte) imagetrust.Status {
		t.Helper()
		var status imagetrust.Status
		if err := json.Unmarshal(raw, &status); err != nil {
			t.Fatal(err)
		}
		if status.Authorization != "BLOCKED" || status.Boundary != imagetrust.StatusBoundary || status.DeviceActionsExecuted || !status.Healthy || !status.Fresh || status.StoreID != f.anchor.StoreID || status.Generation != 1 || status.CatalogueSHA256 != candidateHash(f.catalogue) || status.Sequence != f.sequence || status.LedgerEntries != 0 {
			t.Fatalf("candidate status not trusted advisory read: %+v", status)
		}
		return status
	}
	decodeStatus(call(http.MethodGet, "/api/v1/image-trust", nil, true, http.StatusOK))
	for _, endpoint := range []struct{ method, path string }{{http.MethodPut, "/api/v1/image-trust/catalogue"}, {http.MethodPost, "/api/v1/image-trust/verifications"}} {
		raw := call(endpoint.method, endpoint.path, []byte(`{"untrusted":"must not be parsed before locked gate"}`), true, http.StatusLocked)
		var result struct {
			Code                string `json:"code"`
			Authorization       string `json:"authorization"`
			StateMayHaveChanged bool   `json:"stateMayHaveChanged"`
		}
		if err := json.Unmarshal(raw, &result); err != nil || result.Code != string(imagetrust.CodeLocked) || result.Authorization != "BLOCKED" || result.StateMayHaveChanged {
			t.Fatal("default write gate did not fail before state", err)
		}
	}
	decodeStatus(call(http.MethodGet, "/api/v1/image-trust", nil, true, http.StatusOK))
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal("graceful cancellation failed", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("candidate did not stop gracefully")
	}
	store, err := truststate.Open(context.Background(), f.config.StorePath, f.anchor)
	if err != nil {
		t.Fatal("candidate retained store lock", err)
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil || state.Sequence != f.sequence || state.LedgerUsed != 0 || state.Catalogue.SHA256 != candidateHash(f.catalogue) {
		t.Fatal("locked/read requests changed persistent state", inspectErr, closeErr)
	}
	audit, err := evidence.Open(f.config.AuditDir)
	if err != nil {
		t.Fatal("candidate retained audit lock", err)
	}
	report, verifyErr := audit.Verify()
	closeErr = audit.Close()
	if verifyErr != nil || closeErr != nil || !report.Valid || report.Count != f.auditCount {
		t.Fatal("denied requests changed audit or failed graceful release", verifyErr, closeErr)
	}
}
