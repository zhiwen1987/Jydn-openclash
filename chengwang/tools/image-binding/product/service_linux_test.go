//go:build linux

package product

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

type productFixture struct {
	service           *Service
	store             *truststate.Store
	audit             *evidence.Store
	anchor            trustcatalog.Anchor
	doc               trustcatalog.Document
	initial, approval []byte
	root              ed25519.PrivateKey
	path, auditPath   string
}

func productJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func newProductFixture(t *testing.T, writes bool) productFixture {
	t.Helper()
	resetProductBudget()
	rootPub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approverPub, approver, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	manifest := digest([]byte("inert-product-fixture-image"))
	approverKey := trustcatalog.Key{ID: trustcatalog.KeyID(approverPub), PublicKey: approverPub}
	rootKey := trustcatalog.Key{ID: trustcatalog.KeyID(rootPub), PublicKey: rootPub}
	payload := productJSON(t, map[string]any{"schema": "chengwang.image-approval/v1", "policyID": "fixture-policy", "revision": uint64(1), "approverKeyID": approverKey.ID, "notBeforeUnix": now - 60, "notAfterUnix": now + 1800, "reference": "registry.fixture.invalid/team/image@" + manifest, "os": "linux", "architecture": "amd64", "variant": "", "registryIPs": []string{"127.0.0.1"}, "registrySPKISHA256": digest([]byte("transport-spki")), "signature": map[string]any{"artifactSHA256": manifest, "trustedRootSHA256": digest([]byte("sigstore-root")), "logID": fmt.Sprintf("%064x", 1), "issuer": "https://issuer.fixture.invalid", "san": "product-builder@fixture.invalid", "kind": "message-signature"}})
	approval := productJSON(t, map[string]any{"payload": payload, "signature": ed25519.Sign(approver, append([]byte("chengwang.image-approval/v1\x00"), payload...))})
	doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: "22222222222222222222222222222222", Generation: 1, NotBeforeUnix: now - 60, NotAfterUnix: now + 3600, RootKeys: []trustcatalog.Key{rootKey}, Threshold: 1, Approvers: []trustcatalog.Key{approverKey}, Grants: []trustcatalog.Grant{{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", PolicyID: "fixture-policy", ApprovalSHA256: digest(payload), ApproverKeyID: approverKey.ID, ManifestSHA256: manifest, Revision: 1}}, PolicyFloors: map[string]uint64{"fixture-policy": 1}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	f := productFixture{root: root, doc: doc, approval: approval}
	f.initial = f.sign(t, doc)
	f.anchor = trustcatalog.Anchor{StoreID: doc.StoreID, InitialSHA256: digest(f.initial), Keys: []trustcatalog.Key{rootKey}, Threshold: 1}
	base := t.TempDir()
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	f.path = filepath.Join(base, "trust")
	f.auditPath = filepath.Join(base, "audit")
	f.store, err = truststate.Create(context.Background(), f.path, f.anchor, f.initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	f.audit, err = evidence.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.audit.Close() })
	f.service, err = New(context.Background(), Config{Store: f.store, Audit: f.audit, Scope: authz.ResourceScope{TenantID: "tenant-fixture", SiteID: "site-fixture", ObjectType: "image-trust", ObjectID: doc.StoreID, Environment: "candidate"}, WritesEnabled: writes, RegistryRoots: x509.NewCertPool(), RegistryBearerToken: "TEST-ONLY-SERVER-TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f productFixture) sign(t *testing.T, doc trustcatalog.Document) []byte {
	t.Helper()
	payload := productJSON(t, doc)
	return productJSON(t, trustcatalog.Envelope{Payload: payload, Signatures: []trustcatalog.Signature{{KeyID: trustcatalog.KeyID(f.root.Public().(ed25519.PublicKey)), Signature: ed25519.Sign(f.root, append([]byte(trustcatalog.Schema+"\x00"), payload...))}}})
}
func (f productFixture) actor(role authz.Role) authz.Principal {
	return authz.Principal{ID: "fixture-actor", TenantID: f.service.scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{f.service.scope}}
}
func (f productFixture) request() imagetrust.VerifyRequest {
	return imagetrust.VerifyRequest{PolicyID: "fixture-policy", Approval: bytes.Clone(f.approval), Bundle: []byte("invalid-real-sigstore-bundle"), TrustedRoot: []byte("invalid-real-trusted-root")}
}
func expectCode(t *testing.T, err error, code imagetrust.Code, changed bool) {
	t.Helper()
	var typed *imagetrust.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.StateMayHaveChanged != changed {
		t.Fatalf("got %v (%#v), want %s changed=%v", err, typed, code, changed)
	}
}
func resetProductBudget() {
	processVerificationBudget.Lock()
	processVerificationBudget.busy = false
	processVerificationBudget.starts = [MaxVerificationStartsPerMinute]time.Time{}
	processVerificationBudget.last = time.Time{}
	processVerificationBudget.Unlock()
}

func TestProductBackendDirectRBACAndWriteGateNoConsumption(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			actor := f.actor(role)
			if state, err := f.service.Status(ctx, actor); err != nil || state.Authorization != "BLOCKED" || state.DeviceActionsExecuted {
				t.Fatalf("read role %s: %v", role, err)
			}
			_, err := f.service.Update(ctx, actor, nil)
			want := imagetrust.CodeForbidden
			if role == authz.RoleAdmin {
				want = imagetrust.CodeInvalid
			}
			expectCode(t, err, want, false)
			_, err = f.service.Verify(ctx, actor, imagetrust.VerifyRequest{})
			want = imagetrust.CodeForbidden
			if role == authz.RoleOperator || role == authz.RoleAdmin {
				want = imagetrust.CodeInvalid
			}
			expectCode(t, err, want, false)
		})
	}
	for _, kind := range []string{"anonymous", "tenant", "site", "object", "environment", "unknown-role"} {
		t.Run(kind, func(t *testing.T) {
			actor := f.actor(authz.RoleAdmin)
			switch kind {
			case "anonymous":
				actor = authz.Principal{}
			case "tenant":
				actor.TenantID = "other-tenant"
			case "site":
				actor.AllowedScopes[0].SiteID = "other-site"
			case "object":
				actor.AllowedScopes[0].ObjectID = "other-store"
			case "environment":
				actor.AllowedScopes[0].Environment = "production"
			case "unknown-role":
				actor.Roles = []authz.Role{"owner"}
			}
			_, err := f.service.Status(ctx, actor)
			expectCode(t, err, imagetrust.CodeForbidden, false)
			_, err = f.service.Update(ctx, actor, f.initial)
			expectCode(t, err, imagetrust.CodeForbidden, false)
			_, err = f.service.Verify(ctx, actor, f.request())
			expectCode(t, err, imagetrust.CodeForbidden, false)
		})
	}
	state, err := f.store.Inspect(ctx)
	if err != nil || state.Sequence != 1 || state.LedgerUsed != 0 || f.audit.Status().Count != 0 {
		t.Fatal("rejected request changed state or audit")
	}
	locked := newProductFixture(t, false)
	_, err = locked.service.Verify(ctx, locked.actor(authz.RoleAdmin), locked.request())
	expectCode(t, err, imagetrust.CodeLocked, false)
	_, err = locked.service.Update(ctx, locked.actor(authz.RoleAdmin), locked.initial)
	expectCode(t, err, imagetrust.CodeLocked, false)
	if state, err = locked.store.Inspect(ctx); err != nil || state.LedgerUsed != 0 || state.Sequence != 1 || locked.audit.Status().Count != 0 {
		t.Fatal("disabled writes changed state")
	}
}

func TestProductBackendStatusReadOnlyAndNoSecrets(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	before, err := f.store.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		status, err := f.service.Status(ctx, f.actor(authz.RoleViewer))
		if err != nil {
			t.Fatal(err)
		}
		raw := productJSON(t, status)
		if status.Boundary != imagetrust.StatusBoundary || status.Authorization != "BLOCKED" || status.DeviceActionsExecuted || !status.Healthy || !status.Fresh || len(status.Policies) != 1 || status.Policies[0].State != "AVAILABLE" {
			t.Fatal("bad status projection")
		}
		for _, excluded := range [][]byte{[]byte("publicKey"), []byte("payload"), []byte("signature"), []byte("token"), []byte("TEST-ONLY-SERVER-TOKEN"), f.approval, f.initial} {
			if bytes.Contains(raw, excluded) {
				t.Fatal("status contains excluded material")
			}
		}
	}
	after, err := f.store.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Sequence != after.Sequence || before.LedgerUsed != after.LedgerUsed || f.audit.Status().Count != 0 {
		t.Fatal("Status wrote state")
	}
	view := f.service.Scope()
	view.ObjectID = "attacker"
	if f.service.Scope().ObjectID != f.doc.StoreID {
		t.Fatal("Scope mutable")
	}
}

func TestProductBackendCatalogueUpdateRealAuditAndSignature(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	admin := f.actor(authz.RoleAdmin)
	for _, bad := range [][]byte{[]byte("{}"), f.initial} {
		if _, err := f.service.Update(ctx, admin, bad); err == nil {
			t.Fatal("unsigned or replayed catalogue accepted")
		}
	}
	state, err := f.store.Inspect(ctx)
	if err != nil || state.Sequence != 1 {
		t.Fatal("rejected catalogue changed state")
	}
	doc := f.doc
	doc.Generation = 2
	doc.Grants = []trustcatalog.Grant{}
	doc.RevokedApprovals = []string{f.doc.Grants[0].ApprovalSHA256}
	status, err := f.service.Update(ctx, admin, f.sign(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if status.Generation != 2 || status.RevokedApprovals != 1 || status.Authorization != "BLOCKED" || status.DeviceActionsExecuted {
		t.Fatal("signed update not reflected")
	}
	if report, err := f.audit.Verify(); err != nil || !report.Valid || report.Count != 6 {
		t.Fatalf("expected prepared/result for each attempt: %+v %v", report, err)
	}
	log, err := os.ReadFile(filepath.Join(f.auditPath, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range [][]byte{[]byte("TEST-ONLY-SERVER-TOKEN"), f.initial, f.approval, f.sign(t, doc), []byte("publicKey")} {
		if bytes.Contains(log, excluded) {
			t.Fatal("audit leaked raw input or credentials")
		}
	}
}

func TestProductBackendAuditFailureBeforeMutationAndAfterCommit(t *testing.T) {
	for _, stage := range []string{"before-pre-audit", "before-result-audit"} {
		t.Run(stage, func(t *testing.T) {
			f := newProductFixture(t, true)
			ctx := context.Background()
			doc := f.doc
			doc.Generation = 2
			f.service.fault = func(at string) {
				if at == stage {
					_ = f.audit.Close()
				}
			}
			_, err := f.service.Update(ctx, f.actor(authz.RoleAdmin), f.sign(t, doc))
			changed := stage == "before-result-audit"
			expectCode(t, err, imagetrust.CodeAuditDegraded, changed)
			state, err := f.store.Inspect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(1)
			if changed {
				want = 2
			}
			if state.Catalogue.Generation != want {
				t.Fatal("audit failure mutation boundary mismatch")
			}
			if _, err = f.service.Status(ctx, f.actor(authz.RoleViewer)); err == nil {
				t.Fatal("sticky failed service returned healthy status")
			}
			f.service.fault = nil
			if _, err = f.service.Update(ctx, f.actor(authz.RoleAdmin), f.sign(t, doc)); err == nil {
				t.Fatal("failed service recovered without explicit re-provisioning")
			}
			_ = f.store.Close()
			reopened, err := truststate.Open(ctx, f.path, f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			state, err = reopened.Inspect(ctx)
			if err != nil || state.Catalogue.Generation != want {
				t.Fatal("uncertain mutation did not survive restart")
			}
		})
	}
}

func TestProductBackendRealVerifierBurnsGrantAndAuditsFailure(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	request := f.request()
	_, err := f.service.Verify(ctx, f.actor(authz.RoleOperator), request)
	expectCode(t, err, imagetrust.CodeInvalid, true)
	state, err := f.store.Inspect(ctx)
	if err != nil || state.LedgerUsed != 1 || state.Consumptions[0].Status != "RESERVED" {
		t.Fatal("real ManagedBind did not burn grant before invalid Sigstore rejection")
	}
	if report, err := f.audit.Verify(); err != nil || !report.Valid || report.Count != 2 {
		t.Fatal("verification failure missing audit pair")
	}
	_, err = f.service.Verify(ctx, f.actor(authz.RoleOperator), request)
	if err == nil {
		t.Fatal("signed grant replay accepted")
	}
	state, err = f.store.Inspect(ctx)
	if err != nil || state.LedgerUsed != 1 {
		t.Fatal("replay changed grant history")
	}
}

func TestProductBackendAuditFailureAfterVerifierBurn(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	f.service.fault = func(stage string) {
		if stage == "before-result-audit" {
			_ = f.audit.Close()
		}
	}
	_, err := f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request())
	expectCode(t, err, imagetrust.CodeAuditDegraded, true)
	state, err := f.store.Inspect(ctx)
	if err != nil || state.LedgerUsed != 1 || state.Consumptions[0].Status != "RESERVED" {
		t.Fatal("failed result audit released verifier reservation")
	}
	if _, err = f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request()); err == nil {
		t.Fatal("poisoned verifier service resumed")
	}
	_ = f.store.Close()
	reopened, err := truststate.Open(ctx, f.path, f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.Begin(ctx, "fixture-policy", f.approval); !errors.Is(err, truststate.ErrReplay) {
		t.Fatalf("audit failure revived grant after restart: %v", err)
	}
}

func TestProductBackendTamperedAuditRefusesWrites(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	if _, _, err := f.audit.AppendOnce(evidence.EvidenceEvent{TraceID: "fixture-audit", ActorID: "fixture-actor", Action: "image_trust.read", Target: "image-trust/" + f.doc.StoreID, Result: "observed"}, "fixture-seed"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.auditPath, "events.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("observed"), []byte("tampered"), 1)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	doc := f.doc
	doc.Generation = 2
	_, err = f.service.Update(ctx, f.actor(authz.RoleAdmin), f.sign(t, doc))
	expectCode(t, err, imagetrust.CodeAuditDegraded, false)
	state, err := f.store.Inspect(ctx)
	if err != nil || state.Sequence != 1 || state.LedgerUsed != 0 {
		t.Fatal("tampered audit allowed state change")
	}
}

func TestProductBackendBusyAndRateBudgetNoReservation(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	actor := f.actor(authz.RoleOperator)
	if !reserveVerification(time.Now()) {
		t.Fatal("cannot reserve process slot")
	}
	_, err := f.service.Verify(ctx, actor, f.request())
	expectCode(t, err, imagetrust.CodeBusy, false)
	releaseVerification()
	resetProductBudget()
	now := time.Now()
	for i := 0; i < MaxVerificationStartsPerMinute; i++ {
		if !reserveVerification(now) {
			t.Fatal("budget unexpectedly exhausted")
		}
		releaseVerification()
	}
	_, err = f.service.Verify(ctx, actor, f.request())
	expectCode(t, err, imagetrust.CodeBusy, false)
	// A second Service instance must not reset or bypass the process budget.
	other, err := New(ctx, Config{Store: f.store, Audit: f.audit, Scope: f.service.Scope(), WritesEnabled: true, RegistryRoots: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.Verify(ctx, actor, f.request())
	expectCode(t, err, imagetrust.CodeBusy, false)
	state, err := f.store.Inspect(ctx)
	if err != nil || state.LedgerUsed != 0 || f.audit.Status().Count != 0 {
		t.Fatal("rate/slot rejection consumed grant or audited")
	}
}

func TestProductBackendConcurrentHealthyAuditAndUpdate(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	doc := f.doc
	doc.Generation = 2
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for j := 0; j < 8; j++ {
				if err := f.service.appendAudit(evidence.EvidenceEvent{TraceID: fmt.Sprintf("audit-%d-%d", worker, j), ActorID: "fixture-actor", Action: "image_trust.read", Target: "image-trust/" + f.doc.StoreID, Result: "observed"}, fmt.Sprintf("health-%d-%d", worker, j)); err != nil {
					t.Errorf("healthy concurrent audit failed: %v", err)
					return
				}
			}
		}(i)
	}
	close(start)
	if _, err := f.service.Update(ctx, f.actor(authz.RoleAdmin), f.sign(t, doc)); err != nil {
		t.Errorf("update racing healthy audit: %v", err)
	}
	wg.Wait()
	if f.service.unavailable() {
		t.Fatal("healthy concurrency poisoned service")
	}
	if report, err := f.audit.Verify(); err != nil || !report.Valid || report.Count != 34 {
		t.Fatalf("concurrent audit loss: %+v %v", report, err)
	}
}

func TestProductBackendConstructorFixedScopeAndAuditHealth(t *testing.T) {
	f := newProductFixture(t, true)
	base := Config{Store: f.store, Audit: f.audit, Scope: f.service.Scope(), RegistryRoots: x509.NewCertPool()}
	for _, kind := range []string{"nil-store", "nil-audit", "nil-roots", "wrong-store", "missing-tenant", "missing-site", "missing-env", "wrong-type", "header-token", "space-token", "tab-token", "unicode-token"} {
		t.Run(kind, func(t *testing.T) {
			c := base
			switch kind {
			case "nil-store":
				c.Store = nil
			case "nil-audit":
				c.Audit = nil
			case "nil-roots":
				c.RegistryRoots = nil
			case "wrong-store":
				c.Scope.ObjectID = "33333333333333333333333333333333"
			case "missing-tenant":
				c.Scope.TenantID = ""
			case "missing-site":
				c.Scope.SiteID = ""
			case "missing-env":
				c.Scope.Environment = ""
			case "wrong-type":
				c.Scope.ObjectType = "router"
			case "header-token":
				c.RegistryBearerToken = "unsafe\r\nheader"
			case "space-token":
				c.RegistryBearerToken = "unsafe token"
			case "tab-token":
				c.RegistryBearerToken = "unsafe\ttoken"
			case "unicode-token":
				c.RegistryBearerToken = "unsafe令牌"
			}
			if _, err := New(context.Background(), c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if err := f.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), base); err == nil {
		t.Fatal("closed audit accepted")
	}
}

func TestProductBackendAuditStatusFreshness(t *testing.T) {
	now := time.Now()
	healthy := evidence.VerifyReport{Valid: true, Count: 1, ExpectedCount: 1, LastHash: "public-head", ExpectedLastHash: "public-head", VerifiedAt: now}
	if !validAuditStatus(healthy, now) {
		t.Fatal("current matching audit rejected")
	}
	for _, kind := range []string{"stale", "future", "invalid", "issue", "count", "head"} {
		t.Run(kind, func(t *testing.T) {
			r := healthy
			switch kind {
			case "stale":
				r.VerifiedAt = now.Add(-auditFreshness - time.Nanosecond)
			case "future":
				r.VerifiedAt = now.Add(time.Nanosecond)
			case "invalid":
				r.Valid = false
			case "issue":
				r.Issue = "checkpoint_stale"
			case "count":
				r.ExpectedCount++
			case "head":
				r.ExpectedLastHash = "other"
			}
			if validAuditStatus(r, now) {
				t.Fatal("bad/stale audit accepted")
			}
		})
	}
}

func TestProductBackendAuditResultSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		success      bool
		want         string
	}{
		{"verification-consumed", "image_trust.verify", true, "verification_consumed"},
		{"verification-rejected", "image_trust.verify", false, "rejected"},
		{"catalogue-committed", "image_trust.update", true, "completed"},
		{"catalogue-rejected", "image_trust.update", false, "rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditResultLabel(tc.action, tc.success); got != tc.want {
				t.Fatalf("result label=%s want %s", got, tc.want)
			}
		})
	}
	// This formatter test is not evidence of actual verifier success. Full HTTP
	// tests separately bind verification_consumed to a real CONSUMED ledger.
	// A subsequent response rejection or audit failure never restores the grant.
}
