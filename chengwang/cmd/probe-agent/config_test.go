package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseConfigRequiresStrictFixedInputs(t *testing.T) {
	base := t.TempDir()
	args := validArguments(base)
	parsed, err := parseConfig(args, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if parsed.doTUpstream.String() != "192.0.2.53:853" || parsed.doTServerName != "resolver.example.com" {
		t.Fatalf("unexpected fixed DoT config: %+v", parsed)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"duplicate", append(args, "--catalog=other.json"), "duplicate flag --catalog"},
		{"positional", append(args, "unexpected"), "only named --flag"},
		{"hostname upstream", replaceArgument(args, "--dot-upstream", "resolver.example.com:853"), "fixed IP:port"},
		{"zero port", replaceArgument(args, "--dot-upstream", "192.0.2.53:0"), "fixed IP:port"},
		{"missing SNI", replaceArgument(args, "--dot-server-name", ""), "--dot-server-name is required"},
		{"overlapping stores", replaceArgument(args, "--ledger-dir", filepath.Join(base, "spool", "ledger")), "non-overlapping"},
		{"catalog in store", replaceArgument(args, "--catalog", filepath.Join(base, "spool", "catalog.json")), "outside writable"},
		{"bad concurrency", replaceArgument(args, "--concurrency", "17"), "between 1 and 16"},
		{"health in spool", append(args, "--health-file", filepath.Join(base, "spool", "health.json")), "outside writable"},
		{"health replaces catalog", append(args, "--health-file", filepath.Join(base, "catalog.json")), "must not replace --catalog"},
		{"health whitespace", append(args, "--health-file", " "+filepath.Join(base, "health.json")), "surrounding whitespace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseConfig(test.args, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseConfig() error = %v, want containing %q", err, test.want)
			}
		})
	}
	if _, err := parseConfig([]string{"--help"}, &bytes.Buffer{}); err != flag.ErrHelp {
		t.Fatalf("parseConfig(--help) error = %v, want flag.ErrHelp", err)
	}
}

func TestReadRegularFileRejectsNonRegularSymlinkAndOversize(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular.txt")
	if err := os.WriteFile(regular, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, err := readRegularFile(regular, 2); err != nil || string(content) != "ok" {
		t.Fatalf("readRegularFile() = %q, %v", content, err)
	}
	if _, err := readRegularFile(directory, 100); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if _, err := readRegularFile(regular, 1); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	symlink := filepath.Join(directory, "link.txt")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := readRegularFile(symlink, 100); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestLoadCAPoolAcceptsOnlyCertificatePEM(t *testing.T) {
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "ca.pem")
	certificate := testCertificatePEM(t)
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if pool, err := loadCAPool(certificatePath); err != nil || pool == nil {
		t.Fatalf("loadCAPool() = %v, %v", pool, err)
	}
	invalidPath := filepath.Join(directory, "invalid.pem")
	if err := os.WriteFile(invalidPath, append(certificate, []byte("trailing")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCAPool(invalidPath); err == nil || !strings.Contains(err.Error(), "non-PEM") {
		t.Fatalf("trailing data error = %v", err)
	}
}

func validArguments(base string) []string {
	return []string{
		"--catalog", filepath.Join(base, "catalog.json"),
		"--spool-dir", filepath.Join(base, "spool"),
		"--ledger-dir", filepath.Join(base, "ledger"),
		"--dot-upstream", "192.0.2.53:853",
		"--dot-server-name", "resolver.example.com",
		"--concurrency", "2",
	}
}

func replaceArgument(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for index := range result {
		if result[index] == name && index+1 < len(result) {
			result[index+1] = value
			return result
		}
	}
	return result
}

func testCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
