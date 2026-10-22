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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	verifier "chengwang-image-verifier"
	binding "chengwang/image-binding"
	"github.com/google/go-containerregistry/pkg/registry"
)

func TestBindSignedRegistryImage(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			var mutations, reads atomic.Int32
			service := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet || r.Method == http.MethodHead {
					reads.Add(1)
				} else {
					mutations.Add(1)
				}
				service.ServeHTTP(w, r)
			}))
			defer server.Close()
			m := signedImage(t, server.URL, kind, hashed(server.Certificate().RawSubjectPublicKeyInfo))
			uploadImage(t, server.Client(), server.URL, m)
			mutationsBefore := mutations.Load()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			result, err := binding.Bind(context.Background(), m.trust, m.approval, m.bundle, m.root, roots, "")
			if err != nil {
				t.Fatalf("binding failed: %v", err)
			}
			assertBinding(t, result, m)
			if mutations.Load() != mutationsBefore || reads.Load() < 12 {
				t.Fatal("product binding wrote to Registry or missed complete readback")
			}
		})
	}
}

func assertBinding(t *testing.T, result binding.Result, m material) {
	t.Helper()
	if !result.Verified() || result.Boundary() != binding.Boundary || result.Authorization() != "BLOCKED" || result.Reference() != m.reference || result.ManifestSHA256() != hashed(m.manifest) || result.ConfigSHA256() != hashed(m.config) || result.BundleSHA256() != hashed(m.bundle) || result.TrustedRootSHA256() != hashed(m.root) || result.ApprovalSHA256() != m.trust.PolicySHA256 || result.GraphSHA256() == "" || result.PolicyID() != "isolated-fixture" || result.PolicyRevision() != 1 || result.ApproverKeyID() != m.trust.KeyID || result.RegistryHost() == "" || result.ObservedAt().IsZero() {
		t.Fatal("binding omitted or confused an independent identity")
	}
	raw, err := json.Marshal(result)
	if err != nil || string(raw) != "{}" {
		t.Fatal("binding result exported a transferable receipt")
	}
}

func TestRejectInvalidBeforeRegistryAccess(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "must not reach registry", 500)
	}))
	defer server.Close()
	m := signedImage(t, server.URL, verifier.KindMessageSignature, hashed(server.Certificate().RawSubjectPublicKeyInfo))
	for _, name := range []string{"approval", "bundle", "root", "key", "pin", "revision", "canceled", "nil_context"} {
		t.Run(name, func(t *testing.T) {
			approval, bundle, root := append([]byte(nil), m.approval...), append([]byte(nil), m.bundle...), append([]byte(nil), m.root...)
			trust := m.trust
			ctx := context.Background()
			want := binding.ErrInvalid
			switch name {
			case "approval":
				approval = []byte(`{"status":"approved"}`)
			case "bundle":
				bundle = []byte(`{"verified":true}`)
			case "root":
				root = []byte(`{}`)
			case "key":
				trust.KeyID = "attacker"
			case "pin":
				trust.PolicySHA256 = "sha256:" + strings.Repeat("1", 64)
			case "revision":
				trust.Revision++
			case "canceled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
				want = context.Canceled
			case "nil_context":
				ctx = nil
			}
			result, err := binding.Bind(ctx, trust, approval, bundle, root, nil, "")
			if !errors.Is(err, want) || !reflect.DeepEqual(result, binding.Result{}) || requests.Load() != 0 {
				t.Fatal("invalid input triggered Registry access or minted result")
			}
		})
	}
}

func TestRejectOtherSignerAndRegistryTamper(t *testing.T) {
	var tamper atomic.Bool
	service := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tamper.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "1")
			w.Write([]byte("x"))
			return
		}
		service.ServeHTTP(w, r)
	}))
	defer server.Close()
	m := signedImage(t, server.URL, verifier.KindDSSE, hashed(server.Certificate().RawSubjectPublicKeyInfo))
	uploadImage(t, server.Client(), server.URL, m)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	other := signedImage(t, server.URL, verifier.KindDSSE, hashed(server.Certificate().RawSubjectPublicKeyInfo))
	result, err := binding.Bind(context.Background(), m.trust, m.approval, other.bundle, other.root, roots, "")
	if err != binding.ErrInvalid || result.Verified() {
		t.Fatal("other signer/root escaped approval")
	}
	tamper.Store(true)
	result, err = binding.Bind(context.Background(), m.trust, m.approval, m.bundle, m.root, roots, "")
	if err != binding.ErrInvalid || !reflect.DeepEqual(result, binding.Result{}) {
		t.Fatal("Registry blob tamper escaped signature/digest graph")
	}
}

func TestRejectSameSignerDifferentManifest(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			var requests atomic.Int32
			service := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				service.ServeHTTP(w, r)
			}))
			defer server.Close()
			registrySPKI := hashed(server.Certificate().RawSubjectPublicKeyInfo)
			m := signedImage(t, server.URL, kind, registrySPKI)
			// A newline preserves valid OCI JSON and all config/layer descriptors,
			// but changes the actual immutable manifest bytes and image digest.
			manifestB := append(append([]byte(nil), m.manifest...), '\n')
			if !json.Valid(manifestB) || hashed(m.manifest) == hashed(manifestB) {
				t.Fatal("cross-image fixture is not distinct valid manifest JSON")
			}
			bundleA, bundleB, rootRaw, expectedA, expectedB := signedBundlePair(t, kind, m.manifest, manifestB, m.repository)
			expectedAForB := expectedA
			expectedAForB.ArtifactSHA256 = expectedB.ArtifactSHA256
			if expectedAForB != expectedB || expectedA.ArtifactSHA256 == expectedB.ArtifactSHA256 {
				t.Fatal("cross-image fixture changed trust, signer policy or subject rather than just image identity")
			}
			for _, tc := range []struct {
				bundle   []byte
				expected verifier.Expected
			}{{bundleA, expectedA}, {bundleB, expectedB}} {
				result, err := verifier.Verify(context.Background(), tc.expected, tc.bundle, rootRaw)
				if err != nil || !result.Verified() || result.Authorization() != "BLOCKED" {
					t.Fatalf("independent same-signer artifact proof is invalid: %v", err)
				}
			}
			m.bundle, m.root = bundleA, rootRaw
			approveImage(t, &m, expectedA, registrySPKI)
			uploadImage(t, server.Client(), server.URL, m)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			result, err := binding.Bind(context.Background(), m.trust, m.approval, m.bundle, m.root, roots, "")
			if err != nil {
				t.Fatalf("matching approved image A failed before negative test: %v", err)
			}
			assertBinding(t, result, m)
			before := requests.Load()
			result, err = binding.Bind(context.Background(), m.trust, m.approval, bundleB, rootRaw, roots, "")
			if err != binding.ErrInvalid || !reflect.DeepEqual(result, binding.Result{}) || requests.Load() != before {
				t.Fatal("different image with same signer/root escaped approval or triggered Registry access")
			}
		})
	}
}

func TestBindingZeroAndImportedReceiptsHaveNoAuthority(t *testing.T) {
	var r binding.Result
	if err := json.Unmarshal([]byte(`{"verified":true,"authorization":"ALLOWED"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Verified() || r.Boundary() != "" || r.Authorization() != "BLOCKED" || r.Reference() != "" || r.ApprovalSHA256() != "" || !r.ObservedAt().IsZero() {
		t.Fatal("imported receipt minted authority")
	}
}
