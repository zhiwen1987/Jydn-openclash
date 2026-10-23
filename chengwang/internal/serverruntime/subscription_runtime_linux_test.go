//go:build linux

package serverruntime

// Actual product RunWith, TCP+normal TLS, real identities, private inventory
// and external evidence are exercised here. This is not a separate cmd/server
// process, public subscription service, actual power loss, or production proof.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/subscription"
	"chengwang/internal/subscriptionctl"
)

type runtimeSubscriptionFixture struct {
	config Config
	roots  *x509.CertPool
	tokens map[string]string
	ca     []byte
}

func runtimeSubscriptionInputs(t *testing.T) runtimeSubscriptionFixture {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private runtime directory")
	}
	c := Config{Addr: "127.0.0.1:0", DataDir: filepath.Join(root, "data"), Mode: "candidate", TenantID: "sub-tenant", SiteID: "sub-site", ManagementObjectID: "local", SubscriptionsEnabled: true, SubscriptionWritesEnabled: true, IdentitiesFile: filepath.Join(root, "identities.json"), TLSCertFile: filepath.Join(root, "server.pem"), TLSKeyFile: filepath.Join(root, "server-key.pem")}
	if os.Mkdir(c.DataDir, 0700) != nil {
		t.Fatal("private runtime data")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("CA key")
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-subscription-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("CA certificate")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TLS key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), DNSNames: []string{"subscription.example", "resolver.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal("TLS certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode TLS key")
	}
	if os.WriteFile(c.TLSCertFile, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caPEM...), 0600) != nil || os.WriteFile(c.TLSKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600) != nil {
		t.Fatal("write private TLS inputs")
	}
	profile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	tokens := map[string]string{}
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		token, hash, err := authn.GenerateToken(32)
		if err != nil {
			t.Fatal("generate isolated token")
		}
		name := string(role)
		tokens[name] = token
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: name, TokenHash: hash, Principal: authz.Principal{ID: name + "@example/sso", TenantID: c.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{{TenantID: c.TenantID, SiteID: c.SiteID, Environment: c.Mode}}}})
	}
	token, hash, err := authn.GenerateToken(32)
	if err != nil {
		t.Fatal("foreign identity")
	}
	tokens["foreign"] = token
	profile.Identities = append(profile.Identities, authn.Identity{TokenID: "foreign", TokenHash: hash, Principal: authz.Principal{ID: "foreign@example/sso", TenantID: "other-tenant", Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{{TenantID: "other-tenant", SiteID: c.SiteID, Environment: c.Mode}}}})
	raw, err := json.Marshal(profile)
	if err != nil || os.WriteFile(c.IdentitiesFile, raw, 0600) != nil {
		t.Fatal("real private identity file")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("normal trust roots")
	}
	return runtimeSubscriptionFixture{config: c, roots: roots, tokens: tokens, ca: caPEM}
}

type runtimeSubscriptionServer struct {
	base   string
	client *http.Client
	stop   func()
}

func runtimeSubscriptionStart(t *testing.T, f runtimeSubscriptionFixture) runtimeSubscriptionServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listen, addresses := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &f.config, Context: ctx, Listen: listen, ShutdownTimeout: 3 * time.Second})
	}()
	var address string
	select {
	case address = <-addresses:
	case <-time.After(5 * time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("subscription runtime initialization did not join after cancellation")
		}
		t.Fatal("actual subscription runtime did not listen")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			client.CloseIdleConnections()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("actual runtime did not stop normally")
				}
			case <-time.After(5 * time.Second):
				t.Error("actual runtime did not join")
			}
		})
	}
	t.Cleanup(stop)
	return runtimeSubscriptionServer{base: "https://" + address, client: client, stop: stop}
}
func runtimeSubscriptionRequest(t *testing.T, s runtimeSubscriptionServer, token, method, path, key string, body any) (int, json.RawMessage, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal("encode command")
		}
	}
	req, err := http.NewRequest(method, s.base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("build actual request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	response, err := s.client.Do(req)
	if err != nil {
		t.Fatal("actual normal TLS request failed")
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || len(raw) >= 2<<20 {
		t.Fatal("response read budget")
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("normal TLS was not verified")
	}
	var envelope struct {
		Boundary              string          `json:"boundary"`
		Authorization         string          `json:"authorization"`
		DeviceActionsExecuted bool            `json:"deviceActionsExecuted"`
		Result                json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Boundary != subscriptionctl.Boundary || envelope.Authorization != "BLOCKED" || envelope.DeviceActionsExecuted {
		t.Fatal("unsafe local API boundary")
	}
	return response.StatusCode, envelope.Result, raw
}
func runtimeSubscriptionCreate(t *testing.T, s runtimeSubscriptionServer, f runtimeSubscriptionFixture, key, label string) subscriptionctl.Receipt {
	t.Helper()
	status, result, _ := runtimeSubscriptionRequest(t, s, f.tokens["operator"], "POST", "/api/v1/subscriptions/sources", key, map[string]any{"label": label})
	var receipt subscriptionctl.Receipt
	if status != 200 && status != 201 || json.Unmarshal(result, &receipt) != nil || receipt.SourceID == "" || !receipt.AuditRecorded {
		t.Fatal("create real source")
	}
	return receipt
}
func runtimeSubscriptionImport(t *testing.T, s runtimeSubscriptionServer, f runtimeSubscriptionFixture, source string, revision uint64, key, content string) subscriptionctl.Receipt {
	t.Helper()
	status, result, raw := runtimeSubscriptionRequest(t, s, f.tokens["operator"], "POST", "/api/v1/subscriptions/sources/"+source+"/candidates", key, map[string]any{"expectedRevision": revision, "format": "auto", "contentBase64": base64.StdEncoding.EncodeToString([]byte(content))})
	var receipt subscriptionctl.Receipt
	if status != 200 && status != 201 || json.Unmarshal(result, &receipt) != nil || receipt.CandidateID == "" || !receipt.AuditRecorded || bytes.Contains(raw, []byte("runtime-private-password")) {
		t.Fatal("import real private candidate")
	}
	return receipt
}
func TestServerRuntimeP205NormalTLSMultiSourceAdmissionAndRestart(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	s := runtimeSubscriptionStart(t, f)
	a := runtimeSubscriptionCreate(t, s, f, "runtime-create-a-0001", "来源甲")
	b := runtimeSubscriptionCreate(t, s, f, "runtime-create-b-0001", "来源乙")
	const content = "proxies:\n  - name: private-runtime-private-password\n    type: trojan\n    server: node.example\n    port: 443\n    password: runtime-private-password\n"
	ca := runtimeSubscriptionImport(t, s, f, a.SourceID, a.Revision, "runtime-import-a-0001", content)
	cb := runtimeSubscriptionImport(t, s, f, b.SourceID, b.Revision, "runtime-import-b-0001", content)
	for _, c := range []subscriptionctl.Receipt{ca, cb} {
		status, result, raw := runtimeSubscriptionRequest(t, s, f.tokens["approver"], "POST", "/api/v1/subscriptions/sources/"+c.SourceID+"/decisions", "runtime-admit-"+c.SourceID, map[string]any{"candidateId": c.CandidateID, "expectedRevision": c.Revision, "expectedDigest": c.CandidateDigest, "decision": "admitted_local"})
		var r subscriptionctl.Receipt
		if status != 200 || json.Unmarshal(result, &r) != nil || !r.AuditRecorded || r.Revision != c.Revision+1 || bytes.Contains(raw, []byte("runtime-private-password")) {
			t.Fatal("real local admission")
		}
	}
	status, _, _ := runtimeSubscriptionRequest(t, s, f.tokens["operator"], "POST", "/api/v1/subscriptions/sources/"+a.SourceID+"/candidates", "runtime-bad-a-0001", map[string]any{"expectedRevision": ca.Revision + 1, "format": "auto", "contentBase64": base64.StdEncoding.EncodeToString([]byte("proxies: []"))})
	if status < 400 {
		t.Fatal("bad source update accepted")
	}
	s.stop()
	s = runtimeSubscriptionStart(t, f)
	status, result, raw := runtimeSubscriptionRequest(t, s, f.tokens["viewer"], "GET", "/api/v1/subscriptions/sources", "", nil)
	var page subscriptionctl.SourcePage
	if status != 200 || json.Unmarshal(result, &page) != nil || len(page.Sources) != 2 || bytes.Contains(raw, []byte("node.example")) || bytes.Contains(raw, []byte("runtime-private-password")) {
		t.Fatal("restarted private inventory projection")
	}
	for _, source := range page.Sources {
		if source.AcceptedCandidateID == "" || source.Revision != 3 {
			t.Fatal("bad update or restart lost local accepted version")
		}
	}
	status, result, _ = runtimeSubscriptionRequest(t, s, f.tokens["operator"], "GET", "/api/v1/subscriptions/commands/"+ca.CommandID, "", nil)
	var receipt subscriptionctl.Receipt
	if status != 200 || json.Unmarshal(result, &receipt) != nil || receipt.Revision != ca.Revision || receipt.CandidateID != ca.CandidateID {
		t.Fatal("immutable historical command readback")
	}
}
func TestServerRuntimeP205IndependentRolesAndTenantOverTLS(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	s := runtimeSubscriptionStart(t, f)
	for _, role := range []string{"viewer", "approver", "auditor", "foreign"} {
		status, _, _ := runtimeSubscriptionRequest(t, s, f.tokens[role], "POST", "/api/v1/subscriptions/sources", "runtime-denied-"+role+"-0001", map[string]any{"label": "拒绝"})
		if status != 403 {
			t.Fatal("role or tenant bypass")
		}
	}
	a := runtimeSubscriptionCreate(t, s, f, "runtime-allowed-source-0001", "单源")
	status, _, _ := runtimeSubscriptionRequest(t, s, f.tokens["operator"], "POST", "/api/v1/subscriptions/sources/"+a.SourceID+"/approvals", "runtime-operator-approve-0001", map[string]any{"referenceId": "fixture", "policyRevision": 1, "expectedRevision": a.Revision})
	if status != 403 {
		t.Fatal("operator self approved remote source")
	}
	status, result, _ := runtimeSubscriptionRequest(t, s, f.tokens["viewer"], "GET", "/api/v1/subscriptions/sources", "", nil)
	var page subscriptionctl.SourcePage
	if status != 200 || json.Unmarshal(result, &page) != nil || len(page.Sources) != 1 {
		t.Fatal("denied writes changed real inventory")
	}
}
func TestServerRuntimeP205DisabledDoesNotOpenSubscriptionPaths(t *testing.T) {
	c := runtimeD9Config(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen, addresses := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: time.Second})
	}()
	address := runtimeD9Address(t, addresses)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get("http://" + address + "/api/v1/health")
	if err != nil {
		t.Fatal("disabled runtime health")
	}
	_ = response.Body.Close()
	client.CloseIdleConnections()
	cancel()
	if runtimeD9Result(t, done) != nil {
		t.Fatal("disabled runtime join")
	}
	if _, err := os.Lstat(filepath.Join(c.DataDir, "subscriptions")); !os.IsNotExist(err) {
		t.Fatal("disabled component opened subscription state")
	}
}
func TestServerRuntimeP205WriteGateCannotMutateRealInventory(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	f.config.SubscriptionWritesEnabled = false
	s := runtimeSubscriptionStart(t, f)
	status, _, _ := runtimeSubscriptionRequest(t, s, f.tokens["admin"], "POST", "/api/v1/subscriptions/sources", "runtime-write-locked-0001", map[string]any{"label": "锁定"})
	if status != 423 {
		t.Fatal("runtime independent write gate")
	}
	status, result, _ := runtimeSubscriptionRequest(t, s, f.tokens["viewer"], "GET", "/api/v1/subscriptions/sources", "", nil)
	var page subscriptionctl.SourcePage
	if status != 200 || json.Unmarshal(result, &page) != nil || len(page.Sources) != 0 {
		t.Fatal("locked command touched real inventory")
	}
}
func TestServerRuntimeP205UnsafeStoreFailsBeforeListen(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	target := filepath.Join(f.config.DataDir, "subscriptions")
	if os.Symlink(filepath.Dir(f.config.DataDir), target) != nil {
		t.Fatal("unsafe store fixture")
	}
	called := false
	err := RunWith(Options{Config: &f.config, Listen: func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("unexpected listener")
	}, ShutdownTimeout: time.Second})
	if err == nil || called || strings.Contains(err.Error(), target) {
		t.Fatal("unsafe inventory reached listener or leaked path")
	}
}
func TestServerRuntimeP205UnsafePolicyFailsBeforeStoreAndListen(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	f.config.SubscriptionPolicyFile = filepath.Join(filepath.Dir(f.config.DataDir), "unsafe-policy.json")
	if os.WriteFile(f.config.SubscriptionPolicyFile, []byte("private-policy-sentinel"), 0644) != nil {
		t.Fatal("unsafe policy fixture")
	}
	called := false
	err := RunWith(Options{Config: &f.config, Listen: func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("unexpected listener")
	}, ShutdownTimeout: time.Second})
	if err == nil || called || strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), f.config.SubscriptionPolicyFile) {
		t.Fatal("unsafe policy reached listener or leaked")
	}
	if _, err := os.Lstat(filepath.Join(f.config.DataDir, "subscriptions")); !os.IsNotExist(err) {
		t.Fatal("policy rejection happened after inventory opened")
	}
}
func TestServerRuntimeP205ShutdownReleasesInventoryAndAudit(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	s := runtimeSubscriptionStart(t, f)
	_ = runtimeSubscriptionCreate(t, s, f, "runtime-before-stop-0001", "关闭验收")
	s.stop()
	inventory, err := subscription.OpenStore(filepath.Join(f.config.DataDir, "subscriptions"))
	if err != nil {
		t.Fatal("subscription lifecycle lock retained")
	}
	if inventory.Close() != nil {
		t.Fatal("reopened inventory close")
	}
	audit, err := OpenEvidenceStore(f.config.DataDir)
	if err != nil {
		t.Fatal("external evidence lock retained")
	}
	if report, err := audit.Verify(); err != nil || !report.Valid || report.Count < 2 {
		t.Fatal("actual external command evidence not durable")
	}
	_ = audit.Close()
}
func TestServerRuntimeP205TypedConfigIgnoresSubscriptionEnvironment(t *testing.T) {
	f := runtimeSubscriptionInputs(t)
	t.Setenv("CHENGWANG_SUBSCRIPTIONS_ENABLED", "not-valid-but-ignored")
	t.Setenv("CHENGWANG_SUBSCRIPTION_POLICY_FILE", "private-environment-sentinel")
	s := runtimeSubscriptionStart(t, f)
	status, _, _ := runtimeSubscriptionRequest(t, s, f.tokens["viewer"], "GET", "/api/v1/subscriptions/sources", "", nil)
	if status != 200 || os.Getenv("CHENGWANG_SUBSCRIPTION_POLICY_FILE") != "private-environment-sentinel" {
		t.Fatal("explicit subscription composition read or mutated environment")
	}
}
