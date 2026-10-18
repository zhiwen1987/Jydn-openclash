package attestation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignVerifyAndPublicExport(t *testing.T) {
	signer := testSigner(t, 'a')
	payload := testPayload(t, 7)
	envelope, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(envelope, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := VerifyJSON(wire, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != envelope {
		t.Fatal("wire round trip changed envelope")
	}

	exported, err := signer.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed := strings.Repeat("a", ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed([]byte(seed))
	if strings.Contains(string(exported), base64.RawURLEncoding.EncodeToString([]byte(seed))) ||
		strings.Contains(string(exported), base64.RawURLEncoding.EncodeToString(private)) ||
		strings.Contains(string(exported), `"material"`) {
		t.Fatal("public export contains private material")
	}
	publicKey, err := ParsePublicKey(exported)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(envelope, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestParseEnvelopeRejectsUnknownTrailingAndOversize(t *testing.T) {
	signer := testSigner(t, 'w')
	envelope, err := signer.Sign(testPayload(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(string(wire), "}") + `,"extra":true}`
	for name, input := range map[string][]byte{
		"unknown":  []byte(unknown),
		"trailing": append(append([]byte(nil), wire...), wire...),
		"oversize": []byte(strings.Repeat("x", maxEnvelopeBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvelope(input); err == nil {
				t.Fatal("expected strict envelope rejection")
			}
		})
	}
}

func TestVerifyRejectsTamperingWrongKeyAndUntrustedMetadata(t *testing.T) {
	signer := testSigner(t, 'b')
	envelope, err := signer.Sign(testPayload(t, 10))
	if err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.Payload.EvidenceCount++
	if err := Verify(tampered, signer.PublicKey()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered payload: got %v", err)
	}
	wrongSigner := testSigner(t, 'c')
	if err := Verify(envelope, wrongSigner.PublicKey()); err == nil {
		t.Fatal("wrong public key must fail")
	}
	algorithm := envelope
	algorithm.Algorithm = "Ed25519ph"
	if err := Verify(algorithm, signer.PublicKey()); err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("algorithm claim should be rejected before use: %v", err)
	}
	version := envelope
	version.Version++
	if err := Verify(version, signer.PublicKey()); err == nil || !strings.Contains(err.Error(), "envelope version") {
		t.Fatalf("envelope version claim should be rejected: %v", err)
	}
	payloadVersion := envelope
	payloadVersion.Payload.Version++
	if err := Verify(payloadVersion, signer.PublicKey()); err == nil || !strings.Contains(err.Error(), "payload version") {
		t.Fatalf("payload version claim should be rejected: %v", err)
	}
}

func TestSequenceVerifierRejectsDuplicateAndRollback(t *testing.T) {
	signer := testSigner(t, 'd')
	tracker := NewSequenceVerifier()
	sequence := func(value uint64) Envelope {
		payload := testPayload(t, value)
		envelope, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	if err := tracker.VerifyAndAdvance(sequence(4), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := tracker.VerifyAndAdvance(sequence(4), signer.PublicKey()); !errors.Is(err, ErrSequenceReplay) {
		t.Fatalf("duplicate: got %v", err)
	}
	if err := tracker.VerifyAndAdvance(sequence(3), signer.PublicKey()); !errors.Is(err, ErrSequenceReplay) {
		t.Fatalf("rollback: got %v", err)
	}
	if err := tracker.VerifyAndAdvance(sequence(5), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}

	// A separately scoped instance has its own monotonic sequence.
	other := testPayload(t, 1)
	other.InstanceID = "instance-2"
	envelope, err := signer.Sign(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.VerifyAndAdvance(envelope, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestSequenceVerifierConcurrentDuplicateHasOneWinner(t *testing.T) {
	signer := testSigner(t, 'q')
	envelope, err := signer.Sign(testPayload(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the useful zero value as well as the concurrent replay boundary.
	var tracker SequenceVerifier
	var accepted atomic.Int64
	var replayed atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := tracker.VerifyAndAdvance(envelope, signer.PublicKey())
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrSequenceReplay):
				replayed.Add(1)
			default:
				t.Errorf("unexpected verification error: %v", err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || replayed.Load() != 31 {
		t.Fatalf("accepted=%d replayed=%d", accepted.Load(), replayed.Load())
	}
}

func TestLoadPrivateKeySeedAndPrivateKeyFormats(t *testing.T) {
	seed := []byte(strings.Repeat("e", ed25519.SeedSize))
	for _, tc := range []struct {
		name, materialType string
		material           []byte
	}{
		{"seed", MaterialSeed, seed},
		{"private key", MaterialPrivateKey, ed25519.NewKeyFromSeed(seed)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePrivateKeyFile(t, privateKeyFile{
				Version: PrivateKeyFileVersion, Algorithm: Algorithm, Encoding: Encoding,
				MaterialType: tc.materialType,
				Material:     base64.RawURLEncoding.EncodeToString(tc.material),
			})
			signer, err := LoadPrivateKey(path)
			if err != nil {
				t.Fatal(err)
			}
			if signer.KeyID() == "" {
				t.Fatal("missing key id")
			}
		})
	}
}

func TestLoadPrivateKeyRejectsAmbiguousMalformedAndLeakyErrors(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", ed25519.SeedSize)))
	cases := []struct {
		name string
		body string
	}{
		{"raw seed", secret},
		{"PEM", "-----BEGIN PRIVATE KEY-----\n" + secret + "\n-----END PRIVATE KEY-----"},
		{"unknown field", `{"version":1,"algorithm":"Ed25519","encoding":"base64url","materialType":"seed","material":"` + secret + `","extra":true}`},
		{"unknown type", `{"version":1,"algorithm":"Ed25519","encoding":"base64url","materialType":"auto","material":"` + secret + `"}`},
		{"wrong algorithm", `{"version":1,"algorithm":"RSA","encoding":"base64url","materialType":"seed","material":"` + secret + `"}`},
		{"multiple values", `{"version":1} {"version":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRawPrivateKey(t, []byte(tc.body))
			_, err := LoadPrivateKey(path)
			if err == nil {
				t.Fatal("expected strict loader rejection")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error leaked private material")
			}
		})
	}

	badPrivate := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", ed25519.SeedSize)))
	badPrivate[len(badPrivate)-1] ^= 1
	path := writePrivateKeyFile(t, privateKeyFile{
		Version: 1, Algorithm: Algorithm, Encoding: Encoding, MaterialType: MaterialPrivateKey,
		Material: base64.RawURLEncoding.EncodeToString(badPrivate),
	})
	if _, err := LoadPrivateKey(path); err == nil || strings.Contains(err.Error(), base64.RawURLEncoding.EncodeToString(badPrivate)) {
		t.Fatalf("expected non-leaky inconsistent private-key rejection: %v", err)
	}
}

func TestLoadPrivateKeyRejectsPermissionsSymlinkAndOversize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows FileMode does not expose ACL equivalence")
	}
	document := privateKeyFile{
		Version: 1, Algorithm: Algorithm, Encoding: Encoding, MaterialType: MaterialSeed,
		Material: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("f", ed25519.SeedSize))),
	}
	body, _ := json.Marshal(document)

	t.Run("directory permissions", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "key.json")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(path); err == nil || !strings.Contains(err.Error(), "0700") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("file permissions", func(t *testing.T) {
		dir := secureTempDir(t)
		path := filepath.Join(dir, "key.json")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(path); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := secureTempDir(t)
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, body, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "key.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := LoadPrivateKey(link); err == nil || !strings.Contains(err.Error(), "symbolic") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		dir := secureTempDir(t)
		path := filepath.Join(dir, "key.json")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", maxPrivateKeyFileSize+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestPayloadInputBoundaries(t *testing.T) {
	valid := testPayload(t, 1)
	cases := []struct {
		name string
		edit func(*Payload)
	}{
		{"zero sequence", func(p *Payload) { p.Sequence = 0 }},
		{"empty instance", func(p *Payload) { p.InstanceID = "" }},
		{"long site", func(p *Payload) { p.SiteID = strings.Repeat("x", maxIDBytes+1) }},
		{"short nonce", func(p *Payload) { p.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, minNonceBytes-1)) }},
		{"padded nonce", func(p *Payload) { p.Nonce += "=" }},
		{"noncanonical time", func(p *Payload) { p.GeneratedAt = "2026-10-18T12:00:00+08:00" }},
		{"non-genesis hash with zero count", func(p *Payload) { p.EvidenceCount = 0 }},
		{"missing hash", func(p *Payload) { p.EvidenceLastHash = "" }},
		{"uppercase hash", func(p *Payload) { p.EvidenceLastHash = strings.ToUpper(p.EvidenceLastHash) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := valid
			tc.edit(&payload)
			if _, err := testSigner(t, 'g').Sign(payload); err == nil {
				t.Fatal("expected input boundary rejection")
			}
		})
	}
	zero := valid
	zero.EvidenceCount, zero.EvidenceLastHash = 0, strings.Repeat("0", 64)
	if _, err := testSigner(t, 'h').Sign(zero); err != nil {
		t.Fatalf("empty evidence chain should be representable: %v", err)
	}
}

func testSigner(t *testing.T, fill byte) *Signer {
	t.Helper()
	seed := []byte(strings.Repeat(string(fill), ed25519.SeedSize))
	signer, err := NewSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testPayload(t *testing.T, sequence uint64) Payload {
	t.Helper()
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", minNonceBytes)))
	payload, err := NewPayload(9, strings.Repeat("a", 64), time.Date(2026, 10, 18, 8, 0, 0, 123, time.UTC), "instance-1", "site-1", nonce, sequence)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func writePrivateKeyFile(t *testing.T, document privateKeyFile) string {
	t.Helper()
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return writeRawPrivateKey(t, body)
}

func writeRawPrivateKey(t *testing.T, body []byte) string {
	t.Helper()
	dir := secureTempDir(t)
	path := filepath.Join(dir, "private-key.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
