//go:build registrycli && linux

package binding_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	binding "chengwang/image-binding"
	"chengwang/image-binding/truststate"
	"chengwang/internal/imagetrust"
)

func TestRegistryCLIBindingLifecycle(t *testing.T) {
	const endpoint = "https://registry.fixture.invalid:5443"
	if os.Getenv("REGISTRYCLI_ENDPOINT") != endpoint || os.Getenv("REGISTRYCLI_IP") != "127.0.0.1" {
		t.Fatal("isolated Distribution fixture not provided")
	}
	caPEM, err := os.ReadFile(os.Getenv("REGISTRYCLI_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("fixture CA rejected")
	}
	certPEM, err := os.ReadFile(os.Getenv("REGISTRYCLI_SERVER_CERT_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("fixture server certificate missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "registry.fixture.invalid:5443" {
			return nil, net.InvalidAddrError("not the isolated fixture")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, "127.0.0.1:5443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			m := signedImage(t, endpoint, kind, hashed(cert.RawSubjectPublicKeyInfo))
			uploadImage(t, client, endpoint, m)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result, err := binding.Bind(ctx, m.trust, m.approval, m.bundle, m.root, roots, "")
			if err != nil {
				t.Fatalf("real Distribution binding: %v", err)
			}
			assertBinding(t, result, m)
			// The same unmodified Distribution service also exercises managed
			// trust resolution and durable one-use consumption. No SDK metadata
			// adapter is present in this test or in the product reader.
			managed := newManagedMaterial(t, m)
			statePath := filepath.Join(t.TempDir(), "managed-trust")
			store, err := truststate.Create(ctx, statePath, managed.anchor, managed.catalogue)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			managedResult, err := binding.ManagedBind(ctx, store, "isolated-fixture", managed.approval, managed.bundle, managed.root, roots, "")
			if err != nil {
				t.Fatalf("real Distribution managed binding: %v", err)
			}
			assertManaged(t, managedResult, managed)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := truststate.Open(ctx, statePath, managed.anchor)
			if err != nil {
				t.Fatal(err)
			}
			store = reopened
			managedResult, err = binding.ManagedBind(ctx, store, "isolated-fixture", managed.approval, managed.bundle, managed.root, roots, "")
			if err != binding.ErrManagedInvalid || managedResult.Verified() {
				t.Fatal("real Distribution grant replay after reopen was accepted")
			}
			fmt.Fprintf(os.Stdout, "MANAGED_REAL_DISTRIBUTION=PASS kind=%s replay=rejected reopen=true\n", kind)
			// A separate signed grant proves the complete product HTTP path,
			// not just a mock backend or an in-memory Registry adapter.
			f := &managedAPIFixture{m: newManagedMaterial(t, m), roots: roots}
			prepareManagedAPI(t, f)
			code, raw := managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], f.body(t))
			var receipt imagetrust.Receipt
			if code != http.StatusOK || json.Unmarshal(raw, &receipt) != nil || !receipt.Verified || receipt.Authorization != "BLOCKED" || receipt.DeviceActionsExecuted || receipt.ManifestSHA256 != hashed(m.manifest) || receipt.GrantID != f.m.document.Grants[0].ID {
				t.Fatal("product HTTP did not bind real Distribution")
			}
			state, err := f.store.Inspect(ctx)
			if err != nil || state.LedgerUsed != 1 || state.Consumptions[0].Status != "CONSUMED" || state.Consumptions[0].EvidenceSHA256 != receipt.EvidenceSHA256 {
				t.Fatal("product HTTP success omitted durable consumption")
			}
			code, _ = managedAPIRequest(t, f.api, http.MethodPost, "/api/v1/image-trust/verifications", f.tokens["operator"], f.body(t))
			if code != http.StatusBadRequest {
				t.Fatal("product HTTP replay was not rejected by managed binding")
			}
			fmt.Fprintf(os.Stdout, "PRODUCT_API_REAL_DISTRIBUTION=PASS kind=%s authenticated=true scoped=true consumed=true replay=rejected authorization=BLOCKED\n", kind)
			m.approval = []byte(`{"status":"approved"}`)
			result, err = binding.Bind(ctx, m.trust, m.approval, m.bundle, m.root, roots, "")
			if err != binding.ErrInvalid || result.Verified() {
				t.Fatal("real Registry bypassed approval")
			}
		})
	}
	io.WriteString(os.Stdout, "REAL_DISTRIBUTION_BINDING=PASS message=true dsse=true product_image_executed=false authorization=BLOCKED\n")
}
