//go:build linux

package binding_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	binding "chengwang/image-binding"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"github.com/google/go-containerregistry/pkg/registry"
)

func TestManagedBindPersistentReplay(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			var requests atomic.Int32
			service := minimalRegistryWithBlobMediaType(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); service.ServeHTTP(w, r) }))
			defer server.Close()
			m := newManagedMaterial(t, signedImage(t, server.URL, kind, hashed(server.Certificate().RawSubjectPublicKeyInfo)))
			uploadImage(t, server.Client(), server.URL, m.material)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			path := filepath.Join(t.TempDir(), "trusted")
			store, err := truststate.Create(context.Background(), path, m.anchor, m.catalogue)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			result, err := binding.ManagedBind(context.Background(), store, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
			if err != nil {
				t.Fatalf("managed bind: %v", err)
			}
			assertManaged(t, result, m)
			before := requests.Load()
			for _, id := range []string{"isolated-fixture", "isolated-fixture-alternate"} {
				r, e := binding.ManagedBind(context.Background(), store, id, m.approval, m.bundle, m.root, roots, "")
				if e != binding.ErrManagedInvalid || !reflect.DeepEqual(r, binding.ManagedResult{}) {
					t.Fatal("grant replay or changed caller policy was accepted")
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := truststate.Open(context.Background(), path, m.anchor)
			if err != nil {
				t.Fatal(err)
			}
			store = reopened
			r, e := binding.ManagedBind(context.Background(), store, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
			if e != binding.ErrManagedInvalid || r.Verified() || requests.Load() != before {
				t.Fatal("reopen forgot consumption or replay reached Registry")
			}
		})
	}
}

func TestManagedFailureBurnsGrant(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid signature reached Registry") }))
	defer server.Close()
	m := newManagedMaterial(t, signedImage(t, server.URL, verifier.KindDSSE, hashed(server.Certificate().RawSubjectPublicKeyInfo)))
	path := filepath.Join(t.TempDir(), "trusted")
	s, err := truststate.Create(context.Background(), path, m.anchor, m.catalogue)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r, e := binding.ManagedBind(context.Background(), s, "isolated-fixture", m.approval, []byte(`{"verified":true}`), m.root, nil, "")
	if e != binding.ErrManagedInvalid || !reflect.DeepEqual(r, binding.ManagedResult{}) {
		t.Fatal("invalid signature accepted")
	}
	if _, err := s.Begin(context.Background(), "isolated-fixture", m.approval); !errors.Is(err, truststate.ErrReplay) {
		t.Fatalf("failed attempt did not persist reservation: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := truststate.Open(context.Background(), path, m.anchor)
	if err != nil {
		t.Fatal(err)
	}
	s = reopened
	if _, err := s.Begin(context.Background(), "isolated-fixture", m.approval); !errors.Is(err, truststate.ErrReplay) {
		t.Fatalf("reopened failed attempt forgot reservation: %v", err)
	}
}

func TestManagedConcurrentSingleWinner(t *testing.T) {
	service := minimalRegistryWithBlobMediaType(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	server := httptest.NewTLSServer(service)
	defer server.Close()
	m := newManagedMaterial(t, signedImage(t, server.URL, verifier.KindMessageSignature, hashed(server.Certificate().RawSubjectPublicKeyInfo)))
	uploadImage(t, server.Client(), server.URL, m.material)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	s, err := truststate.Create(context.Background(), filepath.Join(t.TempDir(), "trusted"), m.anchor, m.catalogue)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var winners atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := binding.ManagedBind(context.Background(), s, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
			if e == nil && r.Verified() {
				winners.Add(1)
			} else if e != binding.ErrManagedInvalid {
				t.Errorf("unexpected concurrent result: %v", e)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("managed winners=%d", winners.Load())
	}
}

func TestManagedRevocationDuringRegistryRead(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			entered, unblock := make(chan struct{}), make(chan struct{})
			var blocked, releaseOnce sync.Once
			service := minimalRegistryWithBlobMediaType(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") {
					blocked.Do(func() { close(entered); <-unblock })
				}
				service.ServeHTTP(w, r)
			}))
			defer server.Close()
			release := func() { releaseOnce.Do(func() { close(unblock) }) }
			defer release()
			m := newManagedMaterial(t, signedImage(t, server.URL, kind, hashed(server.Certificate().RawSubjectPublicKeyInfo)))
			uploadImage(t, server.Client(), server.URL, m.material)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			s, err := truststate.Create(context.Background(), filepath.Join(t.TempDir(), "trusted"), m.anchor, m.catalogue)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			type reply struct {
				result binding.ManagedResult
				err    error
			}
			done := make(chan reply, 1)
			go func() {
				r, e := binding.ManagedBind(ctx, s, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
				done <- reply{r, e}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("managed call did not reach actual Registry")
			}
			revoked := m.document
			revoked.Generation++
			revoked.Grants = []trustcatalog.Grant{}
			revoked.RevokedManifests = []string{hashed(m.manifest)}
			if err := s.Update(context.Background(), signManagedCatalogue(t, revoked, m.rootKey)); err != nil {
				t.Fatalf("in-flight revocation: %v", err)
			}
			release()
			select {
			case r := <-done:
				if r.err != binding.ErrManagedInvalid || r.result.Verified() {
					t.Fatal("revoked in-flight grant returned managed success")
				}
			case <-ctx.Done():
				t.Fatal("managed revocation did not terminate")
			}
		})
	}
}

func TestManagedOpaqueAndInvalidInputs(t *testing.T) {
	var r binding.ManagedResult
	if err := json.Unmarshal([]byte(`{"managed":true,"authorization":"ALLOWED","binding":{"verified":true}}`), &r); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, binding.ManagedResult{}) || r.Verified() || r.Boundary() != "" || r.Authorization() != "BLOCKED" {
		t.Fatal("imported managed receipt minted authority")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		v, e := binding.ManagedBind(ctx, nil, "", nil, nil, nil, nil, "")
		if e != binding.ErrManagedInvalid || v.Verified() {
			t.Fatal("nil trust state accepted")
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	v, e := binding.ManagedBind(ctx, nil, "", nil, nil, nil, nil, "")
	if !errors.Is(e, context.Canceled) || v.Verified() {
		t.Fatal("cancellation minted authority")
	}
}

func TestManagedGrantRenewalAndRevocation(t *testing.T) {
	var requests atomic.Int32
	service := minimalRegistryWithBlobMediaType(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); service.ServeHTTP(w, r) }))
	defer server.Close()
	m := newManagedMaterial(t, signedImage(t, server.URL, verifier.KindDSSE, hashed(server.Certificate().RawSubjectPublicKeyInfo)))
	uploadImage(t, server.Client(), server.URL, m.material)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	s, err := truststate.Create(context.Background(), filepath.Join(t.TempDir(), "trusted"), m.anchor, m.catalogue)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := binding.ManagedBind(context.Background(), s, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
	if err != nil {
		t.Fatal(err)
	}
	assertManaged(t, r, m)
	initial := m.catalogue
	renewed := m.document
	renewed.Generation++
	renewed.Grants = append([]trustcatalog.Grant(nil), renewed.Grants...)
	renewed.Grants[0].ID = randomManagedID(t)
	raw := signManagedCatalogue(t, renewed, m.rootKey)
	if err := s.Update(context.Background(), raw); err != nil {
		t.Fatal("authorized fresh grant failed", err)
	}
	m.document, m.catalogue = renewed, raw
	r, err = binding.ManagedBind(context.Background(), s, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
	if err != nil {
		t.Fatal("fresh signed grant did not allow a new attempt", err)
	}
	assertManaged(t, r, m)
	if err := s.Update(context.Background(), initial); err == nil {
		t.Fatal("catalogue rollback was accepted")
	}
	revoked := renewed
	revoked.Generation++
	revoked.Grants = []trustcatalog.Grant{}
	revoked.RevokedApprovals = []string{m.trust.PolicySHA256}
	if err := s.Update(context.Background(), signManagedCatalogue(t, revoked, m.rootKey)); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	r, err = binding.ManagedBind(context.Background(), s, "isolated-fixture", m.approval, m.bundle, m.root, roots, "")
	if err != binding.ErrManagedInvalid || r.Verified() || requests.Load() != before {
		t.Fatal("revoked approval reached Registry or returned success")
	}
	resurrected := revoked
	resurrected.Generation++
	resurrected.Grants = append([]trustcatalog.Grant(nil), renewed.Grants...)
	resurrected.Grants[0].ID = randomManagedID(t)
	if err := s.Update(context.Background(), signManagedCatalogue(t, resurrected, m.rootKey)); err == nil {
		t.Fatal("new nonce resurrected a revoked approval")
	}
}
