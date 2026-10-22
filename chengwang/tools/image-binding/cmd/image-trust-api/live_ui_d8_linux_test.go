//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// This helper is started only by the offline browser gate. Normal ordinary
// and race suites execute its harmless no-environment branch. No HTTP routes,
// fake API responses, signing keys or ready-file contents are printed.
func TestCandidateD8LiveUIFixture(t *testing.T) {
	root := os.Getenv("CHENGWANG_D8_UI_FIXTURE_ROOT")
	if root == "" {
		return
	}
	runRoot := os.Getenv("RUN_ROOT")
	webDir := os.Getenv("CHENGWANG_D8_UI_WEB_DIR")
	if runRoot == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(root, filepath.Clean(runRoot)+string(os.PathSeparator)) || webDir == "" {
		t.Fatal("live browser fixture paths rejected")
	}
	var stat unix.Stat_t
	if unix.Lstat(root, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		t.Fatal("live browser fixture directory is not private")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("live browser fixture directory must be empty")
	}
	base := newCandidateFixture(t, false)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate temporary catalogue authority")
	}
	key := trustcatalog.Key{ID: trustcatalog.KeyID(public), PublicKey: public}
	now := time.Now().Unix()
	doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: base.anchor.StoreID, Generation: 1, NotBeforeUnix: now - 30, NotAfterUnix: now + 1200, RootKeys: []trustcatalog.Key{key}, Threshold: 1, Approvers: []trustcatalog.Key{}, Grants: []trustcatalog.Grant{}, PolicyFloors: map[string]uint64{}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	approverPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate independent inert approval public key")
	}
	approver := trustcatalog.Key{ID: trustcatalog.KeyID(approverPublic), PublicKey: approverPublic}
	doc.Approvers = []trustcatalog.Key{approver}
	for i := 0; i < 25; i++ {
		policy := fmt.Sprintf("ui-fixture-policy-%02d", i)
		doc.Grants = append(doc.Grants, trustcatalog.Grant{ID: fmt.Sprintf("%032x", i+1), PolicyID: policy, ApproverKeyID: approver.ID, ApprovalSHA256: candidateHash([]byte("inert-approval-" + policy)), ManifestSHA256: candidateHash([]byte("inert-manifest-" + policy)), Revision: 1})
		doc.PolicyFloors[policy] = 1
	}
	initial := candidateD7Signed(t, doc, key, private)
	anchor := trustcatalog.Anchor{StoreID: doc.StoreID, InitialSHA256: candidateHash(initial), Keys: []trustcatalog.Key{key}, Threshold: 1}
	c := configuration{Addr: "127.0.0.1:0", StorePath: filepath.Join(root, "trust"), AnchorFile: filepath.Join(root, "anchor.json"), IdentitiesFile: filepath.Join(root, "identities.json"), AuditDir: filepath.Join(root, "audit"), RegistryCAFile: filepath.Join(root, "registry-ca.pem"), TenantID: "ui-fixture-tenant", SiteID: "ui-fixture-site", Environment: "candidate", WebDir: webDir}
	candidatePrivateFile(t, c.AnchorFile, candidateJSON(t, anchor))
	ca, err := readPrivate(base.config.RegistryCAFile, 256<<10)
	if err != nil {
		t.Fatal("load temporary public Registry CA")
	}
	candidatePrivateFile(t, c.RegistryCAFile, ca)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("load temporary explicit Registry roots")
	}
	scope := authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: c.Environment}
	profile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	tokens := map[authz.Role]string{}
	for _, role := range []authz.Role{authz.RoleAuditor, authz.RoleViewer} {
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			t.Fatal("generate temporary UI credential")
		}
		tokens[role] = token
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: "ui-fixture-" + string(role), TokenHash: hash, Principal: authz.Principal{ID: "ui-fixture-" + string(role), TenantID: c.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	wrongToken, _, err := authn.GenerateToken(32)
	if err != nil {
		t.Fatal("generate unrecognized UI credential")
	}
	candidatePrivateFile(t, c.IdentitiesFile, candidateJSON(t, profile))
	configPath, readyPath := filepath.Join(root, "candidate.json"), filepath.Join(root, "ready.json")
	readyTemporary := filepath.Join(root, ".ready.tmp")
	candidatePrivateFile(t, configPath, candidateJSON(t, c))
	defer func() {
		// Do not upload or retain usable bearer credentials after this helper.
		for _, path := range []string{readyPath, readyTemporary, c.IdentitiesFile, configPath} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Error("remove private browser fixture input")
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	store, err := truststate.Create(ctx, c.StorePath, anchor, initial)
	if err != nil {
		t.Fatal("create actual isolated trust Store")
	}
	audit, err := evidence.Open(c.AuditDir)
	if err != nil {
		_ = store.Close()
		t.Fatal("create actual isolated audit Store")
	}
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
			t.Fatal("unsigned fixture update accepted")
		}
	}
	before, err := store.Inspect(ctx)
	journal, journalErr := store.Journal(ctx)
	report, auditErr := audit.Verify()
	if err != nil || journalErr != nil || auditErr != nil || len(journal) != 22 || report.Count != 44 || !report.Valid || before.Catalogue.Generation != 3 || len(before.Catalogue.Grants) != 25 || before.LedgerUsed != 0 {
		t.Fatal("actual browser fixture facts incomplete")
	}
	for _, entry := range journal {
		if !entry.Acknowledged {
			t.Fatal("fixture operation lacks durable audit acknowledgement")
		}
	}
	if audit.Close() != nil || store.Close() != nil {
		t.Fatal("release setup Store locks")
	}
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, configPath, func(network, address string) (net.Listener, error) {
			listener, err := net.Listen(network, address)
			if err != nil {
				return nil, errConfiguration
			}
			ready := struct {
				URL          string `json:"url"`
				AuditorToken string `json:"auditorToken"`
				ViewerToken  string `json:"viewerToken"`
				WrongToken   string `json:"wrongToken"`
			}{"http://" + listener.Addr().String() + "/trust.html", tokens[authz.RoleAuditor], tokens[authz.RoleViewer], wrongToken}
			raw, err := json.Marshal(ready)
			if err != nil {
				_ = listener.Close()
				return nil, errConfiguration
			}
			file, err := os.OpenFile(readyTemporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				_ = listener.Close()
				return nil, errConfiguration
			}
			_, writeErr := file.Write(raw)
			syncErr := file.Sync()
			closeErr := file.Close()
			if writeErr != nil || syncErr != nil || closeErr != nil || os.Rename(readyTemporary, readyPath) != nil {
				_ = listener.Close()
				return nil, errConfiguration
			}
			return listener, nil
		})
	}()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("real browser fixture exceeded fixed lifetime")
		case err := <-finished:
			t.Fatal("candidate exited before browser stop signal", err)
		case <-ticker.C:
			var stop unix.Stat_t
			if unix.Lstat(filepath.Join(root, "stop"), &stop) == nil {
				if stop.Mode&unix.S_IFMT != unix.S_IFREG || stop.Nlink != 1 || stop.Uid != uint32(os.Geteuid()) {
					t.Fatal("unsafe browser stop file")
				}
				cancel()
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal("candidate browser fixture shutdown failed")
					}
				case <-time.After(12 * time.Second):
					t.Fatal("candidate browser fixture failed to join")
				}
				store, err := truststate.Open(context.Background(), c.StorePath, anchor)
				if err != nil {
					t.Fatal("browser candidate retained managed lock")
				}
				after, inspectErr := store.Inspect(context.Background())
				closeErr := store.Close()
				if inspectErr != nil || closeErr != nil || after.Sequence != before.Sequence || after.Catalogue.Generation != 3 || len(after.Catalogue.Grants) != 25 || after.LedgerUsed != 0 {
					t.Fatal("read-only browser flow mutated actual trust state")
				}
				audit, err := evidence.Open(c.AuditDir)
				if err != nil {
					t.Fatal("browser candidate retained audit lock")
				}
				afterAudit, verifyErr := audit.Verify()
				closeErr = audit.Close()
				if verifyErr != nil || closeErr != nil || !afterAudit.Valid || afterAudit.Count != report.Count {
					t.Fatal("browser read flow mutated or damaged actual audit")
				}
				t.Log("CANDIDATE_D8_UI_FIXTURE=PASS actual_candidate=true journal=22 audit=44 readonly=true authorization=BLOCKED")
				return
			}
		}
	}
}
