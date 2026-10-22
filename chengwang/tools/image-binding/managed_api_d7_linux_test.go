//go:build linux

package binding_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/product"
	"chengwang/image-binding/refresh"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/api"
	"chengwang/internal/evidence"
)

// Each real SDK scenario has a fresh process-level verification budget; this
// does not expose a production reset hook or relax the existing 4/min limit.
func TestManagedAPID7FullRefreshAndConsumedRecovery(t *testing.T) {
	mode := os.Getenv("CHENGWANG_D7_REAL_API_TEST")
	if mode == "" {
		for _, kind := range []string{"consumed-recovery", "refresh-revocation"} {
			t.Run(kind, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedAPID7FullRefreshAndConsumedRecovery$", "-test.timeout=80s")
				command.Env = append(os.Environ(), "CHENGWANG_D7_REAL_API_TEST="+kind)
				output, err := command.CombinedOutput()
				if err != nil || !bytes.Contains(output, []byte("PRODUCT_D7_REAL_API=PASS mode="+kind)) {
					t.Fatalf("isolated API subprocess failed: %v\n%s", err, output)
				}
				t.Log("PRODUCT_D7_REAL_API=PASS mode=" + kind)
			})
		}
		return
	}
	switch mode {
	case "consumed-recovery":
		d7ConsumedRecovery(t)
	case "refresh-revocation":
		d7RefreshRevocation(t)
	default:
		t.Fatal("invalid test subprocess mode")
	}
	t.Log("PRODUCT_D7_REAL_API=PASS mode=" + mode)
}

func d7ConsumedRecovery(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var enabled atomic.Bool
	var heads atomic.Int32
	var released sync.Once
	release := func() { released.Do(func() { close(unblock) }) }
	defer release()
	f := newManagedAPIFixture(t, verifier.KindDSSE, func(_ http.ResponseWriter, r *http.Request) bool {
		if enabled.Load() && r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") && heads.Add(1) == 4 {
			close(entered)
			<-unblock
		}
		return false
	})
	enabled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.api.URL+"/api/v1/image-trust/verifications", bytes.NewReader(f.body(t)))
	request.Header.Set("Authorization", "Bearer "+f.tokens["operator"])
	request.Header.Set("Content-Type", "application/json")
	finished := make(chan *http.Response, 1)
	failed := make(chan error, 1)
	go func() {
		r, err := f.api.Client().Do(request)
		if err != nil {
			failed <- err
		} else {
			finished <- r
		}
	}()
	select {
	case <-entered:
	case <-failed:
		t.Fatal("verification transport failed")
	case <-ctx.Done():
		t.Fatal("real verification did not reach final read")
	}
	if err := f.audit.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case response := <-finished:
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 503 || !bytes.Contains(raw, []byte(`"stateMayHaveChanged":true`)) || bytes.Contains(raw, []byte(`"verified":true`)) {
			t.Fatal("uncertain audit reported successful delivery")
		}
	case <-failed:
		t.Fatal("verification did not return classified error")
	case <-ctx.Done():
		t.Fatal("verification did not finish")
	}
	state, err := f.store.Inspect(ctx)
	if err != nil || state.LedgerUsed != 1 || state.Consumptions[0].Status != "CONSUMED" {
		t.Fatal("genuine consumption was not durable")
	}
	f.api.Close()
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = truststate.Open(ctx, f.storePath, f.m.anchor)
	if err != nil {
		t.Fatal(err)
	}
	f.audit, err = evidence.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	requests := f.requests.Load()
	f.recompose(t, true) // New reconciles the missing result without Registry.
	if f.requests.Load() != requests {
		t.Fatal("recovery repeated Registry verification")
	}
	journal, err := f.store.Journal(ctx)
	if err != nil || len(journal) != 1 || !journal[0].Acknowledged || journal[0].Outcome != truststate.OutcomeVerificationConsumed || journal[0].EvidenceSHA256 != state.Consumptions[0].EvidenceSHA256 {
		t.Fatal("consumed recovery lost real evidence")
	}
	view, err := f.audit.RecoverySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	result, ok := view.Lookup("image-trust/" + journal[0].Operation.ID + "/result")
	if !ok || result.Result != "verification_consumed" || result.Hash != journal[0].ResultAuditHash {
		t.Fatal("recovered audit claims wrong semantics")
	}
	count := f.audit.Status().Count
	f.api.Close()
	f.recompose(t, true)
	if f.audit.Status().Count != count {
		t.Fatal("repeated recovery duplicated audit")
	}
	if code, raw := managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], f.body(t)); code == 200 || bytes.Contains(raw, []byte(`"verified":true`)) {
		t.Fatal("consumed grant revived after recovery")
	}
	if f.requests.Load() != requests {
		t.Fatal("replay reached Registry")
	}
}

func d7RefreshRevocation(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var enabled atomic.Bool
	var once, released sync.Once
	release := func() { released.Do(func() { close(unblock) }) }
	defer release()
	f := newManagedAPIFixture(t, verifier.KindMessageSignature, func(_ http.ResponseWriter, r *http.Request) bool {
		if enabled.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") {
			once.Do(func() { close(entered); <-unblock })
		}
		return false
	})
	var sourceMu sync.RWMutex
	latest := bytes.Clone(f.m.catalogue)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest.json" {
			http.NotFound(w, r)
			return
		}
		sourceMu.RLock()
		defer sourceMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(latest)
	}))
	defer source.Close()
	roots := x509.NewCertPool()
	roots.AddCert(source.Certificate())
	client, err := refresh.New(refresh.Config{BaseURL: source.URL, IP: "127.0.0.1", SPKI: hashed(source.Certificate().RawSubjectPublicKeyInfo), Roots: roots, Interval: time.Second, MaxAge: time.Minute, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.api.Close()
	f.service, err = product.New(context.Background(), product.Config{Store: f.store, Audit: f.audit, Scope: f.scope, WritesEnabled: true, RegistryRoots: f.roots, RefreshMaxAge: client.MaxAge()})
	if err != nil {
		t.Fatal(err)
	}
	f.api = httptest.NewTLSServer(api.New(api.Options{Mode: "candidate", Authn: f.identities, ImageTrust: f.service, ImageTrustWritesEnabled: true}))
	t.Cleanup(f.api.Close)
	before, _ := f.store.Inspect(context.Background())
	count := f.audit.Status().Count
	if code, _ := managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], f.body(t)); code != 503 {
		t.Fatal("unconfirmed source allowed verification")
	}
	after, _ := f.store.Inspect(context.Background())
	if after.Sequence != before.Sequence || f.audit.Status().Count != count {
		t.Fatal("unconfirmed API consumed durable state")
	}
	apply := func() error {
		g, h, err := f.service.RefreshSnapshot(context.Background())
		if err != nil {
			return err
		}
		raws, err := client.Fetch(context.Background(), g, h)
		if err != nil {
			return err
		}
		for _, raw := range raws {
			if err = f.service.ApplyRefresh(context.Background(), raw); err != nil {
				return err
			}
		}
		if len(raws) > 0 {
			g += uint64(len(raws))
			h = hashed(raws[len(raws)-1])
		}
		return f.service.ConfirmRefresh(context.Background(), g, h)
	}
	if err = apply(); err != nil {
		t.Fatal(err)
	}
	enabled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.api.URL+"/api/v1/image-trust/verifications", bytes.NewReader(f.body(t)))
	request.Header.Set("Authorization", "Bearer "+f.tokens["operator"])
	request.Header.Set("Content-Type", "application/json")
	finished := make(chan *http.Response, 1)
	failed := make(chan error, 1)
	go func() {
		r, err := f.api.Client().Do(request)
		if err != nil {
			failed <- err
		} else {
			finished <- r
		}
	}()
	select {
	case <-entered:
	case <-failed:
		t.Fatal("verification transport failed")
	case <-ctx.Done():
		t.Fatal("verification did not reach Registry")
	}
	doc := f.m.document
	doc.Generation++
	doc.Grants = []trustcatalog.Grant{}
	doc.RevokedManifests = []string{hashed(f.m.manifest)}
	sourceMu.Lock()
	latest = signManagedCatalogue(t, doc, f.m.rootKey)
	sourceMu.Unlock()
	if err = apply(); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case response := <-finished:
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode == 200 || bytes.Contains(raw, []byte(`"verified":true`)) {
			t.Fatal("automatically refreshed revocation failed to stop in-flight verification")
		}
	case <-failed:
		t.Fatal("no classified response")
	case <-ctx.Done():
		t.Fatal("revoked verification stuck")
	}
	state, err := f.store.Inspect(ctx)
	if err != nil || state.Catalogue.Generation != 2 || state.LedgerUsed != 1 || state.Consumptions[0].Status != "RESERVED" {
		t.Fatal("refresh revoked reservation incorrectly")
	}
}
