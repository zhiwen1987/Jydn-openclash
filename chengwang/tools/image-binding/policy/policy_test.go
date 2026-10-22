package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
)

var testNow = time.Unix(1800000000, 0).UTC()

const testArtifact = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testRoot = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testSPKI = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
const testRepository = "registry.example.test/team/app"

func testKey() ed25519.PrivateKey {
	// Deliberately public deterministic TEST ONLY key, never a release approver.
	seed := sha256.Sum256([]byte("TEST-ONLY-DO-NOT-TRUST-KEY-0000001"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func testDocument() map[string]any {
	return map[string]any{
		"schema": Schema, "policyID": "test-policy-001", "revision": uint64(7), "approverKeyID": "test-only-key",
		"notBeforeUnix": testNow.Unix() - 60, "notAfterUnix": testNow.Unix() + 3600,
		"reference": testRepository + "@" + testArtifact, "os": "linux", "architecture": "amd64", "variant": "",
		"registryIPs":        []string{"192.0.2.10", "2001:db8::10"},
		"registrySPKISHA256": testSPKI,
		"signature": map[string]any{"artifactSHA256": testArtifact, "trustedRootSHA256": testRoot,
			"logID": strings.Repeat("c", 64), "issuer": "https://issuer.example.test", "san": "https://builder.example.test/workflow",
			"kind": "dsse", "subjectName": testRepository, "predicateType": "https://slsa.dev/provenance/v1"},
	}
}

func signRaw(t *testing.T, raw []byte) (Trust, []byte) {
	t.Helper()
	private := testKey()
	sig := ed25519.Sign(private, append([]byte(signingDomain), raw...))
	envelope, err := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return Trust{KeyID: "test-only-key", PublicKey: private.Public().(ed25519.PublicKey), PolicySHA256: digest(raw), Revision: 7}, envelope
}
func signDocument(t *testing.T, m map[string]any) (Trust, []byte) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, raw)
}
func requireInvalid(t *testing.T, ctx context.Context, trust Trust, raw []byte, now time.Time) {
	t.Helper()
	a, err := Verify(ctx, trust, raw, now)
	if err != ErrInvalid || !reflect.DeepEqual(a, Approved{}) || a.ValidAt(now) {
		t.Fatalf("failure not opaque/closed: approved=%#v error=%v", a, err)
	}
}

func TestVerifySignedApproval(t *testing.T) {
	trust, raw := signDocument(t, testDocument())
	a, err := Verify(context.Background(), trust, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !a.ValidAt(testNow) || a.SHA256() != trust.PolicySHA256 || a.ID() != "test-policy-001" || a.Revision() != 7 || a.KeyID() != trust.KeyID || a.Reference() != testRepository+"@"+testArtifact || a.OS() != "linux" || a.Architecture() != "amd64" || a.Variant() != "" || a.NotAfterUnix() != testNow.Unix()+3600 {
		t.Fatalf("incomplete approved identity: %#v", a)
	}
	expected := verifier.Expected{ArtifactSHA256: testArtifact, TrustedRootSHA256: testRoot, LogID: strings.Repeat("c", 64), Issuer: "https://issuer.example.test", SAN: "https://builder.example.test/workflow", Kind: verifier.KindDSSE, SubjectName: testRepository, PredicateType: "https://slsa.dev/provenance/v1"}
	if a.SignatureExpected() != expected {
		t.Fatal("signature policy changed")
	}
	if a.RegistrySPKISHA256() != testSPKI {
		t.Fatal("registry TLS identity not bound")
	}
	ips := a.RegistryIPs()
	if !reflect.DeepEqual(ips, []string{"192.0.2.10", "2001:db8::10"}) {
		t.Fatal("IPs changed")
	}
	ips[0] = "203.0.113.99"
	expected.Issuer = "https://mutated.invalid"
	if a.RegistryIPs()[0] != "192.0.2.10" || a.SignatureExpected().Issuer == expected.Issuer {
		t.Fatal("mutable result escaped")
	}
	for i := range raw {
		raw[i] = 0
	}
	for i := range trust.PublicKey {
		trust.PublicKey[i] = 0
	}
	if !a.ValidAt(testNow) || a.Reference() != testRepository+"@"+testArtifact {
		t.Fatal("result retained mutable caller input")
	}
}

func TestValidityBoundariesAndRealClock(t *testing.T) {
	trust, raw := signDocument(t, testDocument())
	a, err := Verify(context.Background(), trust, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		now   time.Time
		valid bool
	}{
		"before": {testNow.Add(-61 * time.Second), false}, "inclusive-start": {testNow.Add(-60 * time.Second), true},
		"last-nanosecond": {testNow.Add(3600*time.Second - time.Nanosecond), true}, "exclusive-expiry": {testNow.Add(3600 * time.Second), false},
		"after": {testNow.Add(3601 * time.Second), false}, "zero": {time.Time{}, false},
		"offset-and-nanos": {testNow.In(time.FixedZone("test", 8*3600)).Add(123 * time.Nanosecond), true},
	} {
		t.Run(name, func(t *testing.T) {
			if a.ValidAt(tc.now) != tc.valid {
				t.Fatal("wrong validity")
			}
			if !tc.valid {
				requireInvalid(t, context.Background(), trust, raw, tc.now)
			}
		})
	}
	now := time.Now()
	m := testDocument()
	m["notBeforeUnix"], m["notAfterUnix"] = now.Unix()-1, now.Unix()+60
	trust, raw = signDocument(t, m)
	if a, err := Verify(context.Background(), trust, raw, now); err != nil || !a.ValidAt(now) {
		t.Fatalf("ordinary real time rejected: %v", err)
	}
	m = testDocument()
	m["notBeforeUnix"], m["notAfterUnix"] = testNow.Unix(), testNow.Unix()+86400
	trust, raw = signDocument(t, m)
	if _, err := Verify(context.Background(), trust, raw, testNow); err != nil {
		t.Fatal("24h window rejected")
	}
}

func TestNumericAndEnvelopeBoundaries(t *testing.T) {
	m := testDocument()
	m["revision"] = ^uint64(0)
	trust, raw := signDocument(t, m)
	trust.Revision = ^uint64(0)
	if a, err := Verify(context.Background(), trust, raw, testNow); err != nil || a.Revision() != ^uint64(0) {
		t.Fatalf("uint64 exact revision rejected: %v", err)
	}
	trust, raw = signDocument(t, testDocument())
	raw = append(raw, []byte(strings.Repeat(" ", MaxEnvelopeBytes-len(raw)))...)
	if len(raw) != MaxEnvelopeBytes {
		t.Fatal("incorrect boundary test")
	}
	if _, err := Verify(context.Background(), trust, raw, testNow); err != nil {
		t.Fatal("bounded trailing whitespace rejected", err)
	}
	requireInvalid(t, context.Background(), trust, append(raw, ' '), testNow)
	payload, _ := json.Marshal(testDocument())
	for _, numeric := range []string{"18446744073709551616", "7.0", "-1", "1e20"} {
		p := []byte(strings.Replace(string(payload), `"revision":7`, `"revision":`+numeric, 1))
		trust, raw = signRaw(t, p)
		requireInvalid(t, context.Background(), trust, raw, testNow)
	}
	for _, key := range []string{"notBeforeUnix", "notAfterUnix"} {
		m := testDocument()
		m[key] = uint64(253402300800)
		trust, raw := signDocument(t, m)
		requireInvalid(t, context.Background(), trust, raw, testNow)
	}
}

func TestTrustSignatureAndPinFailures(t *testing.T) {
	for name, mutate := range map[string]func(*Trust, *[]byte){
		"wrong-key-id":   func(tr *Trust, _ *[]byte) { tr.KeyID = "another-key" },
		"wrong-key":      func(tr *Trust, _ *[]byte) { tr.PublicKey = make([]byte, 32) },
		"short-key":      func(tr *Trust, _ *[]byte) { tr.PublicKey = tr.PublicKey[:31] },
		"nil-key":        func(tr *Trust, _ *[]byte) { tr.PublicKey = nil },
		"wrong-pin":      func(tr *Trust, _ *[]byte) { tr.PolicySHA256 = testRoot },
		"uppercase-pin":  func(tr *Trust, _ *[]byte) { tr.PolicySHA256 = strings.ToUpper(tr.PolicySHA256) },
		"wrong-revision": func(tr *Trust, _ *[]byte) { tr.Revision++ },
		"zero-revision":  func(tr *Trust, _ *[]byte) { tr.Revision = 0 },
		"signature-tamper": func(_ *Trust, raw *[]byte) {
			var e map[string]string
			_ = json.Unmarshal(*raw, &e)
			sig, _ := base64.StdEncoding.DecodeString(e["signature"])
			sig[0] ^= 1
			e["signature"] = base64.StdEncoding.EncodeToString(sig)
			*raw, _ = json.Marshal(e)
		},
		"unsigned-edited-payload": func(tr *Trust, raw *[]byte) {
			var e map[string]string
			_ = json.Unmarshal(*raw, &e)
			p, _ := base64.StdEncoding.DecodeString(e["payload"])
			p = []byte(strings.Replace(string(p), "test-policy-001", "test-policy-002", 1))
			tr.PolicySHA256 = digest(p)
			e["payload"] = base64.StdEncoding.EncodeToString(p)
			*raw, _ = json.Marshal(e)
		},
		"unsigned-spki-substitution": func(tr *Trust, raw *[]byte) {
			var e map[string]string
			_ = json.Unmarshal(*raw, &e)
			p, _ := base64.StdEncoding.DecodeString(e["payload"])
			p = []byte(strings.Replace(string(p), testSPKI, testRoot, 1))
			tr.PolicySHA256 = digest(p)
			e["payload"] = base64.StdEncoding.EncodeToString(p)
			*raw, _ = json.Marshal(e)
		},
		"missing-domain": func(_ *Trust, raw *[]byte) {
			var e map[string]string
			_ = json.Unmarshal(*raw, &e)
			p, _ := base64.StdEncoding.DecodeString(e["payload"])
			e["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(testKey(), p))
			*raw, _ = json.Marshal(e)
		},
	} {
		t.Run(name, func(t *testing.T) {
			trust, raw := signDocument(t, testDocument())
			mutate(&trust, &raw)
			requireInvalid(t, context.Background(), trust, raw, testNow)
		})
	}
	trust, raw := signDocument(t, testDocument())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireInvalid(t, ctx, trust, raw, testNow)
	requireInvalid(t, nil, trust, raw, testNow)
}

func TestSignedInvalidDocuments(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"schema":             func(m map[string]any) { m["schema"] = "other/v1" },
		"approved-boolean":   func(m map[string]any) { m["status"] = "approved" },
		"unknown":            func(m map[string]any) { m["extra"] = "secret" },
		"alias":              func(m map[string]any) { m["policy_id"] = m["policyID"]; delete(m, "policyID") },
		"case":               func(m map[string]any) { m["PolicyID"] = m["policyID"]; delete(m, "policyID") },
		"empty-policy":       func(m map[string]any) { m["policyID"] = "" },
		"wrong-key-id":       func(m map[string]any) { m["approverKeyID"] = "other" },
		"revision":           func(m map[string]any) { m["revision"] = 8 },
		"revision-string":    func(m map[string]any) { m["revision"] = "7" },
		"revision-fraction":  func(m map[string]any) { m["revision"] = 7.5 },
		"revision-null":      func(m map[string]any) { m["revision"] = nil },
		"negative-time":      func(m map[string]any) { m["notBeforeUnix"] = -1 },
		"time-fraction":      func(m map[string]any) { m["notBeforeUnix"] = float64(testNow.Unix()) + .5 },
		"zero-window":        func(m map[string]any) { m["notAfterUnix"] = m["notBeforeUnix"] },
		"window-too-long":    func(m map[string]any) { m["notAfterUnix"] = testNow.Unix() - 60 + 86401 },
		"expiry":             func(m map[string]any) { m["notAfterUnix"] = testNow.Unix() },
		"not-yet-valid":      func(m map[string]any) { m["notBeforeUnix"] = testNow.Unix() + 1 },
		"empty-platform":     func(m map[string]any) { m["architecture"] = "" },
		"platform-alias":     func(m map[string]any) { m["os"] = "Linux" },
		"variant-type":       func(m map[string]any) { m["variant"] = false },
		"null-variant":       func(m map[string]any) { m["variant"] = nil },
		"tag-reference":      func(m map[string]any) { m["reference"] = testRepository + ":latest" },
		"digest-mismatch":    func(m map[string]any) { m["reference"] = testRepository + "@" + testRoot },
		"dsse-wrong-subject": func(m map[string]any) { m["signature"].(map[string]any)["subjectName"] = "another/repo" },
		"signature-unknown":  func(m map[string]any) { m["signature"].(map[string]any)["approved"] = true },
		"signature-alias": func(m map[string]any) {
			s := m["signature"].(map[string]any)
			s["artifact_sha256"] = s["artifactSHA256"]
			delete(s, "artifactSHA256")
		},
		"signature-null":     func(m map[string]any) { m["signature"] = nil },
		"signature-kind":     func(m map[string]any) { m["signature"].(map[string]any)["kind"] = "auto" },
		"signature-issuer":   func(m map[string]any) { m["signature"].(map[string]any)["issuer"] = "http://issuer.test" },
		"signature-log-id":   func(m map[string]any) { m["signature"].(map[string]any)["logID"] = "short" },
		"signature-root-pin": func(m map[string]any) { m["signature"].(map[string]any)["trustedRootSHA256"] = "latest" },
		"signature-san":      func(m map[string]any) { m["signature"].(map[string]any)["san"] = "line\nsecret" },
		"spki-empty":         func(m map[string]any) { m["registrySPKISHA256"] = "" },
		"spki-uppercase":     func(m map[string]any) { m["registrySPKISHA256"] = strings.ToUpper(testSPKI) },
		"spki-short":         func(m map[string]any) { m["registrySPKISHA256"] = "sha256:" + strings.Repeat("d", 63) },
		"spki-nonhex":        func(m map[string]any) { m["registrySPKISHA256"] = "sha256:" + strings.Repeat("g", 64) },
		"spki-unprefixed":    func(m map[string]any) { m["registrySPKISHA256"] = strings.Repeat("d", 64) },
		"spki-null":          func(m map[string]any) { m["registrySPKISHA256"] = nil },
		"spki-number":        func(m map[string]any) { m["registrySPKISHA256"] = 42 },
		"spki-alias": func(m map[string]any) {
			m["registry_spki_sha256"] = m["registrySPKISHA256"]
			delete(m, "registrySPKISHA256")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := testDocument()
			mutate(m)
			trust, raw := signDocument(t, m)
			requireInvalid(t, context.Background(), trust, raw, testNow)
		})
	}
	for _, key := range []string{"schema", "policyID", "revision", "approverKeyID", "notBeforeUnix", "notAfterUnix", "reference", "os", "architecture", "variant", "registryIPs", "registrySPKISHA256", "signature"} {
		t.Run("missing-"+key, func(t *testing.T) {
			m := testDocument()
			delete(m, key)
			trust, raw := signDocument(t, m)
			requireInvalid(t, context.Background(), trust, raw, testNow)
		})
	}
}

func TestRegistryIPPolicies(t *testing.T) {
	for name, ips := range map[string][]any{
		"empty": {}, "duplicate": {"192.0.2.10", "192.0.2.10"}, "hostname": {"registry.example.test"}, "zone": {"fe80::1%eth0"},
		"noncanonical-v6": {"2001:0db8::1"}, "uppercase-v6": {"2001:DB8::1"}, "mapped": {"::ffff:192.0.2.10"}, "zero": {"0.0.0.0"},
		"multicast": {"ff02::1"}, "leadingzero": {"192.000.2.10"}, "port": {"192.0.2.10:443"}, "type": {42},
		"too-many": {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9"},
	} {
		t.Run(name, func(t *testing.T) {
			m := testDocument()
			m["registryIPs"] = ips
			trust, raw := signDocument(t, m)
			requireInvalid(t, context.Background(), trust, raw, testNow)
		})
	}
	for _, ips := range [][]string{{"10.88.0.240"}, {"127.0.0.1", "::1"}, {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8"}} {
		m := testDocument()
		m["registryIPs"] = ips
		trust, raw := signDocument(t, m)
		if _, err := Verify(context.Background(), trust, raw, testNow); err != nil {
			t.Fatalf("explicit approved IPs rejected: %v", err)
		}
	}
}

func TestReferenceAndMessagePolicies(t *testing.T) {
	for _, repo := range []string{"registry.example.test:5000/team/app", "[2001:db8::1]:5000/team/app", "10.88.0.240:5000/team/app"} {
		m := testDocument()
		m["reference"] = repo + "@" + testArtifact
		m["signature"].(map[string]any)["subjectName"] = repo
		trust, raw := signDocument(t, m)
		if _, err := Verify(context.Background(), trust, raw, testNow); err != nil {
			t.Fatalf("valid explicit reference rejected %s: %v", repo, err)
		}
	}
	for _, repo := range []string{"https://registry.test/team/app", "user:secret@registry.test/team/app", "Registry.test/team/app", "registry.test/team/../app", "registry.test/team//app", "registry.test/team/app?x=1", "registry.test:00080/team/app", "registry.test:0/team/app", "registry.test:65536/team/app", "registry.test:/team/app", "registry.test/team/app:tag", "registry.test/team/%61pp", "registry.test./team/app"} {
		t.Run(repo, func(t *testing.T) {
			m := testDocument()
			m["reference"] = repo + "@" + testArtifact
			m["signature"].(map[string]any)["subjectName"] = repo
			trust, raw := signDocument(t, m)
			requireInvalid(t, context.Background(), trust, raw, testNow)
		})
	}
	m := testDocument()
	s := m["signature"].(map[string]any)
	s["kind"] = "message-signature"
	delete(s, "subjectName")
	delete(s, "predicateType")
	trust, raw := signDocument(t, m)
	if _, err := Verify(context.Background(), trust, raw, testNow); err != nil {
		t.Fatal("message signature policy rejected", err)
	}
	s["subjectName"] = "unexpected"
	trust, raw = signDocument(t, m)
	requireInvalid(t, context.Background(), trust, raw, testNow)
}

func TestStrictJSONAndEnvelope(t *testing.T) {
	m := testDocument()
	payload, _ := json.Marshal(m)
	for name, raw := range map[string][]byte{
		"duplicate":         []byte(strings.Replace(string(payload), "{", "{\"policyID\":\"duplicate\",", 1)),
		"escaped-duplicate": []byte(strings.Replace(string(payload), "{", "{\"policy\\u0049D\":\"duplicate\",", 1)),
		"duplicate-signer":  []byte(strings.Replace(string(payload), "\"signature\":{", "\"signature\":{\"kind\":\"dsse\",", 1)),
		"trailing":          append(bytesCopy(payload), []byte(" {}")...), "invalid-utf8": {0xff}, "null": []byte("null"),
		"depth":             []byte(`{"x":` + strings.Repeat("[", 10) + "1" + strings.Repeat("]", 10) + "}"),
		"nodes":             []byte(`{"x":[` + strings.Repeat("1,", 257) + "1]}"),
		"surrogate":         []byte(strings.Replace(string(payload), "test-policy-001", `\ud800`, 1)),
		"exponent-revision": []byte(strings.Replace(string(payload), `"revision":7`, `"revision":7e0`, 1)),
	} {
		t.Run("payload-"+name, func(t *testing.T) {
			trust, envelope := signRaw(t, raw)
			requireInvalid(t, context.Background(), trust, envelope, testNow)
		})
	}
	trust, envelope := signRaw(t, payload)
	for name, raw := range map[string][]byte{
		"duplicate": []byte(strings.Replace(string(envelope), "{", "{\"payload\":\"AA==\",", 1)),
		"unknown":   []byte(strings.Replace(string(envelope), "{", "{\"approved\":true,", 1)),
		"alias":     []byte(strings.Replace(string(envelope), "\"payload\":", "\"Payload\":", 1)),
		"null":      []byte(`{"payload":null,"signature":"AA=="}`), "empty": {}, "array": []byte("[]"),
		"trailing": append(bytesCopy(envelope), []byte(" null")...), "over-limit": []byte(strings.Repeat(" ", MaxEnvelopeBytes+1)),
		"noncanonical-base64": []byte(`{"payload":"AB==","signature":"AA=="}`), "base64-newline": []byte(`{"payload":"AA==\n","signature":"AA=="}`),
	} {
		t.Run("envelope-"+name, func(t *testing.T) { requireInvalid(t, context.Background(), trust, raw, testNow) })
	}
	var e map[string]string
	_ = json.Unmarshal(envelope, &e)
	for _, bad := range []string{"", base64.StdEncoding.EncodeToString(make([]byte, 63)), base64.StdEncoding.EncodeToString(make([]byte, 65)), "DO_NOT_LEAK"} {
		e["signature"] = bad
		raw, _ := json.Marshal(e)
		requireInvalid(t, context.Background(), trust, raw, testNow)
	}
}
func bytesCopy(b []byte) []byte { return append([]byte(nil), b...) }

func TestZeroValueCannotBeImportedAsApproval(t *testing.T) {
	var a Approved
	if err := json.Unmarshal([]byte(`{"verified":true,"registrySPKISHA256":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","policy":{"reference":"bad","registrySPKI":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}`), &a); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, Approved{}) || a.ValidAt(testNow) || a.SHA256() != "" || a.ID() != "" || a.Revision() != 0 || a.Reference() != "" || a.OS() != "" || a.Architecture() != "" || a.Variant() != "" || a.RegistryIPs() != nil || a.RegistrySPKISHA256() != "" || a.SignatureExpected() != (verifier.Expected{}) || a.KeyID() != "" || a.NotAfterUnix() != 0 {
		t.Fatal("zero value admitted an imported approval")
	}
	raw, err := json.Marshal(a)
	if err != nil || string(raw) != "{}" {
		t.Fatal("opaque internal state exported")
	}
}
