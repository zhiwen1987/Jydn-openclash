//go:build registrycli

package binding_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	binding "chengwang/image-binding"
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
			m.approval = []byte(`{"status":"approved"}`)
			result, err = binding.Bind(ctx, m.trust, m.approval, m.bundle, m.root, roots, "")
			if err != binding.ErrInvalid || result.Verified() {
				t.Fatal("real Registry bypassed approval")
			}
		})
	}
	io.WriteString(os.Stdout, "REAL_DISTRIBUTION_BINDING=PASS message=true dsse=true product_image_executed=false authorization=BLOCKED\n")
}
