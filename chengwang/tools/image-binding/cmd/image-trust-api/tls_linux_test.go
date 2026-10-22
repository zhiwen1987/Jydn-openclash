//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"chengwang/image-binding/truststate"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

// This starts the real opt-in candidate composition over TLS. The ephemeral
// TLS fixture private key is not a catalogue/bootstrap key and is never logged
// or copied into evidence artifacts. No certificate-verification bypass exists.
func TestCandidateTLSListenerRequiresValidExplicitTrust(t *testing.T) {
	f := newCandidateFixture(t, true)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate ephemeral TLS fixture")
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(23), Subject: pkix.Name{CommonName: "candidate-loopback-tls-fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal("create ephemeral TLS certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("encode ephemeral TLS fixture")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	f.config.TLSCertFile = filepath.Join(filepath.Dir(f.file), "candidate-server-cert.pem")
	f.config.TLSKeyFile = filepath.Join(filepath.Dir(f.file), "candidate-server-key.pem")
	candidatePrivateFile(t, f.config.TLSCertFile, certPEM)
	candidatePrivateFile(t, f.config.TLSKeyFile, keyPEM)
	f.config.Addr = "0.0.0.0:0"
	f.writeConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, f.file, func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != "0.0.0.0:0" {
				return nil, errConfiguration
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				return nil, err
			}
			_, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				_ = listener.Close()
				return nil, errConfiguration
			}
			ready <- net.JoinHostPort("127.0.0.1", port)
			return listener, nil
		})
	}()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				t.Error("TLS candidate failed to shut down")
			}
		}
	})
	var address string
	select {
	case address = <-ready:
	case <-done:
		stopped = true
		t.Fatal("TLS candidate failed before listener")
	case <-time.After(5 * time.Second):
		t.Fatal("TLS candidate listener did not start")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("load explicit TLS fixture trust")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodGet, "https://"+address+"/api/v1/image-trust", nil)
	if err != nil {
		t.Fatal("build TLS candidate request")
	}
	request.Header.Set("Authorization", "Bearer "+f.token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("explicitly trusted HTTPS request failed")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("candidate did not serve authenticated verified TLS status")
	}
	var status imagetrust.Status
	if json.Unmarshal(raw, &status) != nil || status.Authorization != "BLOCKED" || status.Boundary != imagetrust.StatusBoundary || status.DeviceActionsExecuted || !status.Healthy || !status.Fresh || status.StoreID != f.anchor.StoreID || status.Sequence != f.sequence || status.LedgerEntries != 0 {
		t.Fatal("TLS candidate returned invalid advisory state")
	}
	if bytes.Contains(raw, []byte(f.token)) || bytes.Contains(raw, keyPEM) || bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("TLS candidate exposed excluded material")
	}
	// The same credentials over plaintext must not yield authenticated state.
	plainTransport := &http.Transport{Proxy: nil}
	defer plainTransport.CloseIdleConnections()
	plainClient := &http.Client{Transport: plainTransport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	plain, err := http.NewRequest(http.MethodGet, "http://"+address+"/api/v1/image-trust", nil)
	if err != nil {
		t.Fatal("build plaintext negative request")
	}
	plain.Header.Set("Authorization", "Bearer "+f.token)
	if plainResponse, plainErr := plainClient.Do(plain); plainErr == nil {
		body, e := io.ReadAll(io.LimitReader(plainResponse.Body, 1<<20))
		_ = plainResponse.Body.Close()
		if e != nil || plainResponse.StatusCode >= 200 && plainResponse.StatusCode < 300 || bytes.Contains(body, []byte(f.anchor.StoreID)) || bytes.Contains(body, []byte(`"generation"`)) {
			t.Fatal("plaintext reached authenticated TLS status")
		}
	}
	// An unrelated explicit CA pool cannot authenticate the TLS endpoint.
	wrongPublic, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate unrelated test CA")
	}
	wrongTemplate := &x509.Certificate{SerialNumber: big.NewInt(24), Subject: pkix.Name{CommonName: "unrelated-candidate-test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	wrongDER, err := x509.CreateCertificate(rand.Reader, wrongTemplate, wrongTemplate, wrongPublic, wrongPrivate)
	if err != nil {
		t.Fatal("create unrelated test CA")
	}
	wrongCA, err := x509.ParseCertificate(wrongDER)
	if err != nil {
		t.Fatal("parse unrelated test CA")
	}
	wrongRoots := x509.NewCertPool()
	wrongRoots.AddCert(wrongCA)
	wrongTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: wrongRoots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	defer wrongTransport.CloseIdleConnections()
	wrongClient := &http.Client{Transport: wrongTransport, Timeout: 5 * time.Second}
	wrongRequest := request.Clone(context.Background())
	if wrongResponse, wrongErr := wrongClient.Do(wrongRequest); wrongErr == nil {
		_ = wrongResponse.Body.Close()
		t.Fatal("untrusted HTTPS certificate was accepted")
	} else {
		var unknownAuthority x509.UnknownAuthorityError
		if !errors.As(wrongErr, &unknownAuthority) {
			t.Fatal("wrong CA did not fail certificate authority validation")
		}
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal("TLS candidate did not stop gracefully")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("TLS candidate did not release lifecycle stores")
	}
	store, err := truststate.Open(context.Background(), f.config.StorePath, f.anchor)
	if err != nil {
		t.Fatal("TLS candidate retained trust store lock")
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr = store.Close()
	if inspectErr != nil || closeErr != nil || state.Sequence != f.sequence || state.LedgerUsed != 0 {
		t.Fatal("TLS candidate read-only requests changed trust state")
	}
	audit, err := evidence.Open(f.config.AuditDir)
	if err != nil {
		t.Fatal("TLS candidate retained audit lock")
	}
	report, verifyErr := audit.Verify()
	closeErr = audit.Close()
	if verifyErr != nil || closeErr != nil || !report.Valid || report.Count != f.auditCount {
		t.Fatal("TLS candidate denied/read requests changed audit state")
	}
}
