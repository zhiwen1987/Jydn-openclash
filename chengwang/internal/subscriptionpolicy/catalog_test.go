//go:build linux

package subscriptionpolicy

// These are native Linux file-custody and loopback DoT integration tests, not
// proof of successful HTTPS fetch against a public pin or production approval.
// There is deliberately no fetch dial hook and no target-address bypass.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/subscription"
)

const policySecret = "private-subscription-policy-sentinel"
const policyReference = "enterprise-a"
const policySourceID = "src_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var policyScope = subscription.Scope{TenantID: "tenant-a", SiteID: "site-a", Environment: "isolated"}

type policyCertificates struct {
	pem  string
	leaf tls.Certificate
}

func policyCA(t *testing.T) policyCertificates {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture CA key")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated policy CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture CA certificate")
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fixture CA parse")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture leaf key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"dot.policy.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal("fixture leaf certificate")
	}
	return policyCertificates{pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		leaf: tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}}
}

func policyConfig(t *testing.T) map[string]any {
	t.Helper()
	ca := policyCA(t)
	return map[string]any{"version": 1,
		"scope":    map[string]any{"tenantId": policyScope.TenantID, "siteId": policyScope.SiteID, "environment": policyScope.Environment},
		"resolver": map[string]any{"upstream": "127.0.0.1:1853", "serverName": "dot.policy.example", "caPEM": ca.pem},
		"sources": []any{map[string]any{"referenceId": policyReference, "revision": uint64(1), "secretVersion": "secret-v1",
			"url":           "https://subscription.example/subscription?token=" + policySecret,
			"allowedCnames": []any{"edge.subscription.example"}, "caPEM": ca.pem}}}
}
func policyEntry(config map[string]any) map[string]any {
	return config["sources"].([]any)[0].(map[string]any)
}
func policyBytes(t *testing.T, config map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal("fixture JSON")
	}
	return raw
}
func policyParsed(t *testing.T, config map[string]any) *Catalog {
	t.Helper()
	result, err := ParseBytes(policyBytes(t, config))
	if err != nil {
		t.Fatal("parse valid trusted fixture")
	}
	return result
}
func policyDescriptor(t *testing.T, catalog *Catalog, reference string) []byte {
	t.Helper()
	descriptor, err := catalog.Describe(reference)
	if err != nil {
		t.Fatal("describe configured reference")
	}
	return descriptor.Material
}
func policyInvalid(t *testing.T, raw []byte) {
	t.Helper()
	catalog, err := ParseBytes(raw)
	if catalog != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid configuration accepted or unsafe error")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), policySecret) {
		t.Fatal("private parse error")
	}
}
func policyOwner() Owner { return Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())} }
func policyFile(t *testing.T) (string, []byte) {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0o700) != nil {
		t.Fatal("fixture private directory")
	}
	raw := policyBytes(t, policyConfig(t))
	path := filepath.Join(directory, "catalog.json")
	if os.WriteFile(path, raw, 0o600) != nil || os.Chmod(path, 0o600) != nil {
		t.Fatal("fixture private file")
	}
	return path, raw
}
func policyFetchCode(t *testing.T, err error, code subscription.Code) {
	t.Helper()
	var failure *subscription.Failure
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatal("expected closed fetch failure")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), policySecret) {
		t.Fatal("private fetch failure")
	}
}

func TestSubscriptionPolicyP205ParseValidAndImmutable(t *testing.T) {
	config := policyConfig(t)
	raw := policyBytes(t, config)
	catalog, err := ParseBytes(raw)
	if err != nil {
		t.Fatal("parse valid private catalog")
	}
	material := policyDescriptor(t, catalog, policyReference)
	for index := range raw {
		raw[index] = 'x'
	}
	policyEntry(config)["url"] = "https://changed.example/"
	if !bytes.Equal(material, policyDescriptor(t, catalog, policyReference)) {
		t.Fatal("caller mutated catalog")
	}
	scope := catalog.Scope()
	scope.SiteID = "other"
	if catalog.Scope() != policyScope {
		t.Fatal("scope not a value copy")
	}
}

func TestSubscriptionPolicyP205StrictJSON(t *testing.T) {
	raw := policyBytes(t, policyConfig(t))
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`[]`), append(append([]byte{}, raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1),
		append([]byte("\xff"), raw...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":NaN`), 1),
		[]byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))} {
		policyInvalid(t, bad)
	}
	config := policyConfig(t)
	policyEntry(config)["unknown"] = policySecret
	policyInvalid(t, policyBytes(t, config))
}

func TestSubscriptionPolicyP205FieldTypesAndRequired(t *testing.T) {
	for _, field := range []string{"referenceId", "revision", "secretVersion", "url", "allowedCnames", "caPEM"} {
		config := policyConfig(t)
		delete(policyEntry(config), field)
		policyInvalid(t, policyBytes(t, config))
		config = policyConfig(t)
		policyEntry(config)[field] = nil
		policyInvalid(t, policyBytes(t, config))
	}
	for _, field := range []string{"upstream", "serverName", "caPEM"} {
		config := policyConfig(t)
		config["resolver"].(map[string]any)[field] = 17
		policyInvalid(t, policyBytes(t, config))
	}
	config := policyConfig(t)
	config["scope"].(map[string]any)["tenantId"] = "../secret"
	policyInvalid(t, policyBytes(t, config))
}

func TestSubscriptionPolicyP205VersionAndSourceBudgets(t *testing.T) {
	for _, value := range []any{0, 2, "1", 1.5, -1, nil} {
		config := policyConfig(t)
		config["version"] = value
		policyInvalid(t, policyBytes(t, config))
	}
	for _, value := range []any{0, -1, 1.5, "1", json.Number("18446744073709551616")} {
		config := policyConfig(t)
		policyEntry(config)["revision"] = value
		policyInvalid(t, policyBytes(t, config))
	}
	config := policyConfig(t)
	entry := policyEntry(config)
	entries := make([]any, 0, 32)
	for index := 0; index < 32; index++ {
		copy := make(map[string]any)
		for k, v := range entry {
			copy[k] = v
		}
		copy["referenceId"] = fmt.Sprintf("ref-%d", index)
		entries = append(entries, copy)
	}
	config["sources"] = entries
	policyParsed(t, config)
	config["sources"] = append(entries, entries[0])
	policyInvalid(t, policyBytes(t, config))
	policyInvalid(t, bytes.Repeat([]byte(" "), MaxCatalogBytes+1))
}

func TestSubscriptionPolicyP205ExactHTTPSAndCNAMEs(t *testing.T) {
	for _, value := range []string{"http://subscription.example/", "https://127.0.0.1/", "https://user:secret@subscription.example/",
		"https://subscription.example:444/", "https://subscription.example/a/../b", "https://subscription.example/%2F", "https://subscription.example/#fragment"} {
		config := policyConfig(t)
		policyEntry(config)["url"] = value
		policyInvalid(t, policyBytes(t, config))
	}
	for _, aliases := range []any{[]any{"edge.subscription.example", "edge.subscription.example"}, []any{1}, []any{"*.example"}, []any{"127.0.0.1"}} {
		config := policyConfig(t)
		policyEntry(config)["allowedCnames"] = aliases
		policyInvalid(t, policyBytes(t, config))
	}
}

func TestSubscriptionPolicyP205FixedDoTOnly(t *testing.T) {
	for _, upstream := range []string{"resolver.example:853", "127.0.0.1", "0.0.0.0:853", "224.0.0.1:853", "[fe80::1%lo]:853", "[::ffff:127.0.0.1]:853"} {
		config := policyConfig(t)
		config["resolver"].(map[string]any)["upstream"] = upstream
		policyInvalid(t, policyBytes(t, config))
	}
	config := policyConfig(t)
	config["resolver"].(map[string]any)["timeout"] = 0
	policyInvalid(t, policyBytes(t, config))
	config = policyConfig(t)
	config["resolver"].(map[string]any)["serverName"] = "127.0.0.1"
	policyInvalid(t, policyBytes(t, config))
}

func TestSubscriptionPolicyP205RootPools(t *testing.T) {
	for _, where := range []string{"source", "resolver"} {
		for _, ca := range []string{"", "garbage " + policySecret, "-----BEGIN PRIVATE KEY-----\n" + policySecret, strings.Repeat("x", 65537)} {
			config := policyConfig(t)
			target := policyEntry(config)
			if where == "resolver" {
				target = config["resolver"].(map[string]any)
			}
			target["caPEM"] = ca
			policyInvalid(t, policyBytes(t, config))
		}
	}
	config := policyConfig(t)
	bundle := policyCA(t).pem + policyCA(t).pem
	policyEntry(config)["caPEM"] = bundle
	policyParsed(t, config)
	config = policyConfig(t)
	ca := policyEntry(config)["caPEM"].(string)
	policyEntry(config)["caPEM"] = ca + "PRIVATE KEY " + policySecret
	policyInvalid(t, policyBytes(t, config))
	config = policyConfig(t)
	policyEntry(config)["caPEM"] = "-----BEGIN CERTIFICATE-----\ninvalid\n" + ca
	policyInvalid(t, policyBytes(t, config))
	config = policyConfig(t)
	leaf := policyCA(t).leaf.Certificate[0]
	policyEntry(config)["caPEM"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
	policyInvalid(t, policyBytes(t, config))
}

func TestSubscriptionPolicyP205MaterialBindsAllInputs(t *testing.T) {
	config := policyConfig(t)
	baseline := policyDescriptor(t, policyParsed(t, config), policyReference)
	mutations := []func(map[string]any){
		func(c map[string]any) { c["scope"].(map[string]any)["tenantId"] = "tenant-b" },
		func(c map[string]any) { c["scope"].(map[string]any)["siteId"] = "site-b" },
		func(c map[string]any) { c["scope"].(map[string]any)["environment"] = "other" },
		func(c map[string]any) { policyEntry(c)["revision"] = 2 },
		func(c map[string]any) { policyEntry(c)["secretVersion"] = "secret-v2" },
		func(c map[string]any) {
			policyEntry(c)["url"] = "https://subscription.example/other?token=" + policySecret
		},
		func(c map[string]any) { policyEntry(c)["allowedCnames"] = []any{"other.subscription.example"} },
		func(c map[string]any) { policyEntry(c)["caPEM"] = policyCA(t).pem },
		func(c map[string]any) { c["resolver"].(map[string]any)["upstream"] = "127.0.0.1:1854" },
		func(c map[string]any) { c["resolver"].(map[string]any)["serverName"] = "other.policy.example" },
		func(c map[string]any) { c["resolver"].(map[string]any)["caPEM"] = policyCA(t).pem },
	}
	for _, mutate := range mutations {
		var copy map[string]any
		if json.Unmarshal(policyBytes(t, config), &copy) != nil {
			t.Fatal("copy fixture")
		}
		mutate(copy)
		if bytes.Equal(baseline, policyDescriptor(t, policyParsed(t, copy), policyReference)) {
			t.Fatal("effective input absent from material")
		}
	}
	if !bytes.Contains(baseline, []byte(policySecret)) || !bytes.Contains(baseline, []byte(`"resolverTimeoutSeconds":5`)) {
		t.Fatal("private complete material missing")
	}
	policyEntry(config)["referenceId"] = "enterprise-b"
	if bytes.Equal(baseline, policyDescriptor(t, policyParsed(t, config), "enterprise-b")) {
		t.Fatal("reference absent from material")
	}
	policyEntry(config)["referenceId"] = policyReference
	policyEntry(config)["caPEM"] = policyEntry(config)["caPEM"].(string) + policyCA(t).pem
	if bytes.Equal(baseline, policyDescriptor(t, policyParsed(t, config), policyReference)) {
		t.Fatal("bundle addition absent from material")
	}
}

func TestSubscriptionPolicyP205MaterialCanonicalOrder(t *testing.T) {
	config := policyConfig(t)
	policyEntry(config)["allowedCnames"] = []any{"z.subscription.example", "a.subscription.example"}
	first := policyDescriptor(t, policyParsed(t, config), policyReference)
	policyEntry(config)["allowedCnames"] = []any{"a.subscription.example", "z.subscription.example"}
	second := policyDescriptor(t, policyParsed(t, config), policyReference)
	if !bytes.Equal(first, second) {
		t.Fatal("allowlist order changed effective material")
	}
	spaced := append([]byte(" \n"), policyBytes(t, config)...)
	spaced = append(spaced, '\n')
	catalog, err := ParseBytes(spaced)
	if err != nil || !bytes.Equal(first, policyDescriptor(t, catalog, policyReference)) {
		t.Fatal("JSON whitespace changed canonical material")
	}
}

func TestSubscriptionPolicyP205DescribeCopies(t *testing.T) {
	catalog := policyParsed(t, policyConfig(t))
	first, err := catalog.Describe(policyReference)
	if err != nil || first.ReferenceID != policyReference || first.Revision != 1 {
		t.Fatal("descriptor identity")
	}
	original := append([]byte(nil), first.Material...)
	first.Material[0] = 'x'
	first.ReferenceID = "changed"
	first.Revision++
	if !bytes.Equal(original, policyDescriptor(t, catalog, policyReference)) {
		t.Fatal("descriptor aliases immutable private material")
	}
}

func TestSubscriptionPolicyP205ScopeAndReferenceRejected(t *testing.T) {
	catalog := policyParsed(t, policyConfig(t))
	if _, err := catalog.Describe(policySecret); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown reference accepted")
	}
	wrong := policyScope
	wrong.SiteID = "foreign"
	if _, err := catalog.Fetch(context.Background(), wrong, policySourceID, policyReference); !errors.Is(err, ErrScopeDenied) {
		t.Fatal("scope mismatch accepted")
	}
	if _, err := catalog.Fetch(context.Background(), policyScope, policySourceID, policySecret); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown fetch reference accepted")
	}
	config := policyConfig(t)
	policyEntry(config)["referenceId"] = strings.Repeat("a", 65)
	policyInvalid(t, policyBytes(t, config))
}

func TestSubscriptionPolicyP205SourceIDRejected(t *testing.T) {
	catalog := policyParsed(t, policyConfig(t))
	for _, id := range []string{"", "src_abc", "src_" + strings.Repeat("A", 32), policySecret} {
		if _, err := catalog.Fetch(context.Background(), policyScope, id, policyReference); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid source binding accepted")
		}
	}
}

func TestSubscriptionPolicyP205NilAndZero(t *testing.T) {
	for _, catalog := range []*Catalog{nil, {}} {
		if _, err := catalog.Describe(policyReference); !errors.Is(err, ErrUnavailable) {
			t.Fatal("zero directory describe")
		}
		if _, err := catalog.Fetch(context.Background(), policyScope, policySourceID, policyReference); !errors.Is(err, ErrUnavailable) {
			t.Fatal("zero directory fetch")
		}
		if catalog.Scope() != (subscription.Scope{}) {
			t.Fatal("zero directory scope")
		}
	}
}

func TestSubscriptionPolicyP205PrivateFmtAndJSON(t *testing.T) {
	catalog := policyParsed(t, policyConfig(t))
	descriptor, _ := catalog.Describe(policyReference)
	for _, value := range []any{catalog, *catalog, struct{ Catalog Catalog }{*catalog}, descriptor} {
		printed := fmt.Sprintf("%v %+v %#v", value, value, value)
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(printed, policySecret) || bytes.Contains(encoded, []byte(policySecret)) || strings.Contains(printed, "BEGIN CERTIFICATE") || bytes.Contains(encoded, []byte("BEGIN CERTIFICATE")) {
			t.Fatal("private directory formatted or serialized")
		}
	}
}

func TestSubscriptionPolicyP205ContextCancellation(t *testing.T) {
	path, _ := policyFile(t)
	catalog := policyParsed(t, policyConfig(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadSecure(ctx, path, policyOwner()); !errors.Is(err, context.Canceled) {
		t.Fatal("load ignored cancellation")
	}
	if _, err := catalog.Fetch(ctx, policyScope, policySourceID, policyReference); !errors.Is(err, context.Canceled) {
		t.Fatal("fetch ignored cancellation")
	}
	if _, err := LoadSecure(nil, path, policyOwner()); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil load context")
	}
	if _, err := catalog.Fetch(nil, policyScope, policySourceID, policyReference); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil fetch context")
	}
}

func TestSubscriptionPolicyP205SecureLoadAndNoMutation(t *testing.T) {
	path, raw := policyFile(t)
	before, _ := os.Stat(path)
	catalog, err := LoadSecure(context.Background(), path, policyOwner())
	if err != nil || catalog.Scope() != policyScope {
		t.Fatal("secure native load failed")
	}
	after, _ := os.Stat(path)
	bytesAfter, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(raw, bytesAfter) || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("secure load modified input")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("load created hidden state")
	}
}

func TestSubscriptionPolicyP205SecureRejectsPermissions(t *testing.T) {
	path, _ := policyFile(t)
	if os.Chmod(path, 0o644) != nil {
		t.Fatal("fixture mode")
	}
	if _, err := LoadSecure(context.Background(), path, policyOwner()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("public file accepted")
	}
	if os.Chmod(path, 0o600) != nil || os.Chmod(filepath.Dir(path), 0o755) != nil {
		t.Fatal("fixture directory mode")
	}
	if _, err := LoadSecure(context.Background(), path, policyOwner()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("public parent accepted")
	}
}

func TestSubscriptionPolicyP205SecureRejectsSymlinkAndHardlink(t *testing.T) {
	path, raw := policyFile(t)
	link := filepath.Join(filepath.Dir(path), "alias.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture symlink")
	}
	if _, err := LoadSecure(context.Background(), link, policyOwner()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlink accepted")
	}
	if os.Remove(link) != nil || os.Link(path, link) != nil {
		t.Fatal("fixture hardlink")
	}
	if _, err := LoadSecure(context.Background(), path, policyOwner()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("hardlink accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("link rejection repaired input")
	}
}

func TestSubscriptionPolicyP205SecureRejectsFIFO(t *testing.T) {
	if os.Getenv("CHENGWANG_POLICY_FIFO_CHILD") == "1" {
		_, err := LoadSecure(context.Background(), os.Getenv("CHENGWANG_POLICY_FIFO_PATH"), policyOwner())
		if !errors.Is(err, ErrUnsafe) {
			t.Fatal("FIFO was not safely rejected")
		}
		return
	}
	directory := t.TempDir()
	if os.Chmod(directory, 0o700) != nil {
		t.Fatal("FIFO parent")
	}
	path := filepath.Join(directory, "catalog.json")
	if syscall.Mkfifo(path, 0o600) != nil {
		t.Fatal("FIFO fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSubscriptionPolicyP205SecureRejectsFIFO$", "-test.count=1")
	command.Env = append(os.Environ(), "CHENGWANG_POLICY_FIFO_CHILD=1", "CHENGWANG_POLICY_FIFO_PATH="+path)
	if _, err := command.CombinedOutput(); err != nil || ctx.Err() != nil {
		t.Fatal("nonblocking FIFO rejection failed its subprocess deadline")
	}
}

func TestSubscriptionPolicyP205SecureRejectsOwnerAndFilesystem(t *testing.T) {
	path, _ := policyFile(t)
	owner := policyOwner()
	owner.UID++
	if _, err := LoadSecure(context.Background(), path, owner); !errors.Is(err, ErrUnsafe) {
		t.Fatal("wrong owner accepted")
	}
	for _, kind := range []int64{0xef53, 0x58465342, 0x01021994} {
		if !supportedFilesystem(kind, false) {
			t.Fatal("native FS rejected")
		}
	}
	if supportedFilesystem(0x794c7630, false) || !supportedFilesystem(0x794c7630, true) || supportedFilesystem(0x6969, true) {
		t.Fatal("filesystem custody policy")
	}
}

func TestSubscriptionPolicyP205SecureDetectsHeldMutation(t *testing.T) {
	path, _ := policyFile(t)
	held, err := os.Open(path)
	if err != nil {
		t.Fatal("held fixture FD")
	}
	defer held.Close()
	before, err := observeFile(held)
	if err != nil {
		t.Fatal("observe held fixture")
	}
	if os.Chmod(path, 0o400) != nil {
		t.Fatal("controlled metadata mutation")
	}
	after, err := observeFile(held)
	if err != nil || before == after || checkRegular(after, policyOwner(), before.device) != ErrUnsafe {
		t.Fatal("held FD metadata mutation undetected")
	}
	if _, err := LoadSecure(context.Background(), path, policyOwner()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("mutated custody accepted")
	}
}

func TestSubscriptionPolicyP205SecureRejectsPathsAndBudgets(t *testing.T) {
	for _, path := range []string{"", ".", "/", "/tmp/../private.json", "/tmp//private.json", "/tmp/private.json/", "/tmp/\x00secret"} {
		if _, err := LoadSecure(context.Background(), path, policyOwner()); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe path shape accepted")
		}
	}
	path, _ := policyFile(t)
	if os.WriteFile(path, bytes.Repeat([]byte("x"), MaxCatalogBytes+1), 0o600) != nil {
		t.Fatal("large fixture")
	}
	if _, err := LoadSecure(context.Background(), path, policyOwner()); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized private file accepted")
	}
}

type policyDoT struct {
	listener    net.Listener
	done        chan struct{}
	mutex       sync.Mutex
	connections map[net.Conn]bool
	workers     sync.WaitGroup
	queries     atomic.Int32
	handshakes  atomic.Int32
	pendingTLS  chan struct{}
	address     string
}

func policyDoTServer(t *testing.T, certificate tls.Certificate, answer netip.Addr, stall bool) *policyDoT {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("DoT fixture listen")
	}
	server := &policyDoT{listener: listener, done: make(chan struct{}), connections: make(map[net.Conn]bool), pendingTLS: make(chan struct{}, 4), address: listener.Addr().String()}
	go func() {
		defer close(server.done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			server.mutex.Lock()
			server.connections[connection] = true
			server.mutex.Unlock()
			server.workers.Add(1)
			go func() {
				defer server.workers.Done()
				defer func() {
					_ = connection.Close()
					server.mutex.Lock()
					delete(server.connections, connection)
					server.mutex.Unlock()
				}()
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				if stall {
					var one [1]byte
					if _, err := io.ReadFull(connection, one[:]); err != nil || one[0] != 0x16 {
						return
					}
					// An actual TLS handshake record has arrived; no TLS/DNS
					// response is sent before the caller cancels or expires.
					server.pendingTLS <- struct{}{}
					var rest [4096]byte
					for {
						if _, err := connection.Read(rest[:]); err != nil {
							return
						}
					}
				}
				secure := tls.Server(connection, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
				if secure.Handshake() != nil {
					return
				}
				server.handshakes.Add(1)
				var frame [2]byte
				if _, err := io.ReadFull(secure, frame[:]); err != nil {
					return
				}
				length := int(binary.BigEndian.Uint16(frame[:]))
				if length < 17 || length > 4096 {
					return
				}
				query := make([]byte, length)
				if _, err := io.ReadFull(secure, query); err != nil {
					return
				}
				if binary.BigEndian.Uint16(query[2:4]) != 0x0100 || binary.BigEndian.Uint16(query[4:6]) != 1 {
					return
				}
				at := 12
				var labels []string
				for at < len(query) && query[at] != 0 {
					count := int(query[at])
					at++
					if count > 63 || at+count > len(query) {
						return
					}
					labels = append(labels, string(query[at:at+count]))
					at += count
				}
				if at+5 != len(query) || strings.Join(labels, ".") != "subscription.example" || binary.BigEndian.Uint16(query[at+3:]) != 1 {
					return
				}
				kind := binary.BigEndian.Uint16(query[at+1:])
				if kind != 1 && kind != 28 {
					return
				}
				server.queries.Add(1)
				response := append([]byte(nil), query...)
				binary.BigEndian.PutUint16(response[2:4], 0x8180)
				if kind == 1 {
					binary.BigEndian.PutUint16(response[6:8], 1)
					response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4)
					ip := answer.As4()
					response = append(response, ip[:]...)
				}
				binary.BigEndian.PutUint16(frame[:], uint16(len(response)))
				_, _ = secure.Write(append(frame[:], response...))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-server.done
		server.mutex.Lock()
		for connection := range server.connections {
			_ = connection.Close()
		}
		server.mutex.Unlock()
		server.workers.Wait()
	})
	return server
}

func policyNetworkCatalog(t *testing.T, roots string, server *policyDoT, serverName string) *Catalog {
	t.Helper()
	config := policyConfig(t)
	resolver := config["resolver"].(map[string]any)
	resolver["upstream"], resolver["serverName"], resolver["caPEM"] = server.address, serverName, roots
	return policyParsed(t, config)
}

func TestSubscriptionPolicyP205DoTNormalTLS(t *testing.T) {
	certificates := policyCA(t)
	server := policyDoTServer(t, certificates.leaf, netip.MustParseAddr("8.8.4.4"), false)
	catalog := policyNetworkCatalog(t, certificates.pem, server, "dot.policy.example")
	result, err := catalog.core.resolver.ResolveHost(context.Background(), "subscription.example")
	if err != nil || len(result.Addresses) != 1 || result.Addresses[0].String() != "8.8.4.4" || len(result.CanonicalChain) != 1 || result.CanonicalChain[0] != "subscription.example" || server.queries.Load() != 2 || server.handshakes.Load() != 2 {
		t.Fatal("real normal TLS DoT A/AAAA fixture failed")
	}
}

func TestSubscriptionPolicyP205DoTWrongTrust(t *testing.T) {
	certificates := policyCA(t)
	server := policyDoTServer(t, certificates.leaf, netip.MustParseAddr("8.8.4.4"), false)
	catalog := policyNetworkCatalog(t, policyCA(t).pem, server, "dot.policy.example")
	_, err := catalog.Fetch(context.Background(), policyScope, policySourceID, policyReference)
	policyFetchCode(t, err, subscription.CodeFetchUnavailable)
	if server.queries.Load() != 0 {
		t.Fatal("wrong CA sent DNS query")
	}
}

func TestSubscriptionPolicyP205DoTWrongName(t *testing.T) {
	certificates := policyCA(t)
	server := policyDoTServer(t, certificates.leaf, netip.MustParseAddr("8.8.4.4"), false)
	catalog := policyNetworkCatalog(t, certificates.pem, server, "wrong.policy.example")
	_, err := catalog.Fetch(context.Background(), policyScope, policySourceID, policyReference)
	policyFetchCode(t, err, subscription.CodeFetchUnavailable)
	if server.queries.Load() != 0 {
		t.Fatal("wrong SAN sent DNS query")
	}
}

func TestSubscriptionPolicyP205DoTTimeoutAndCancellation(t *testing.T) {
	certificates := policyCA(t)
	server := policyDoTServer(t, certificates.leaf, netip.MustParseAddr("8.8.4.4"), true)
	catalog := policyNetworkCatalog(t, certificates.pem, server, "dot.policy.example")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := catalog.Fetch(ctx, policyScope, policySourceID, policyReference); finished <- err }()
	select {
	case <-server.pendingTLS:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not receive TLS handshake before cancellation")
	}
	cancel()
	select {
	case err := <-finished:
		policyFetchCode(t, err, subscription.CodeFetchUnavailable)
	case <-time.After(2 * time.Second):
		t.Fatal("pending TLS cancellation did not join")
	}
	deadline, stop := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer stop()
	go func() {
		_, err := catalog.Fetch(deadline, policyScope, policySourceID, policyReference)
		finished <- err
	}()
	select {
	case <-server.pendingTLS:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not receive TLS handshake for deadline variant")
	}
	select {
	case err := <-finished:
		policyFetchCode(t, err, subscription.CodeFetchUnavailable)
		if !errors.Is(deadline.Err(), context.DeadlineExceeded) {
			t.Fatal("pending TLS returned before its deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending TLS deadline did not join")
	}
	if server.queries.Load() != 0 || resolverTimeout != 5*time.Second {
		t.Fatal("DoT timeout contract")
	}
}

func TestSubscriptionPolicyP205FetchUsesConfiguredResolver(t *testing.T) {
	certificates := policyCA(t)
	server := policyDoTServer(t, certificates.leaf, netip.MustParseAddr("127.0.0.1"), false)
	catalog := policyNetworkCatalog(t, certificates.pem, server, "dot.policy.example")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	result, err := catalog.Fetch(context.Background(), policyScope, policySourceID, policyReference)
	policyFetchCode(t, err, subscription.CodeFetchPolicy)
	if len(result.Content) != 0 || server.queries.Load() != 2 {
		t.Fatal("fetch did not use complete fixed DoT or accepted private pin")
	}
}

func TestSubscriptionPolicyP205PlatformBoundary(t *testing.T) {
	if supportedFilesystem(0, false) || supportedFilesystem(0x794c7630, false) {
		t.Fatal("unsupported native storage fallback")
	}
	path, _ := policyFile(t)
	if _, err := LoadSecure(context.Background(), path, policyOwner()); err != nil {
		t.Fatal("Linux secure runtime entry unavailable")
	}
	// Cross-platform implementation is build-selected and explicitly returns
	// ErrUnsupported; there is no os.ReadFile fallback or platform skip here.
}
