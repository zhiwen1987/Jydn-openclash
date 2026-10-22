package binding_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/merkle/rfc6962"
)

const sctFixtureIssuer = "https://issuer.fixture.invalid"
const sctFixtureIdentity = "builder@fixture.invalid"

// signedBundle constructs ephemeral, real test-only signatures and PKI. No key
// is persisted or installed as product trust. It follows the upstream Sigstore
// SCT fixture pattern and CT v1 precertificate serialization, without replacing
// any verifier, threshold, signature check, or trusted-material implementation.
func signedBundle(t *testing.T, kind verifier.Kind, artifact []byte, subjectName string) (bundleRaw, rootRaw []byte, expected verifier.Expected) {
	t.Helper()
	factory := newSigningFactory(t)
	object, body, expected := factory.artifact(t, kind, artifact, subjectName)
	leafHash := rfc6962.DefaultHasher.HashLeaf(body)
	bundleRaw = factory.finish(t, object, body, expected, 0, 1, leafHash, nil)
	return bundleRaw, bytes.Clone(factory.rootRaw), expected
}

// signedBundlePair signs two distinct artifacts with the exact same CA, leaf,
// SCT, Rekor key and trust-root bytes. Both entries share one honest two-leaf
// Merkle tree/checkpoint, not two conflicting size-one snapshots of the log.
func signedBundlePair(t *testing.T, kind verifier.Kind, artifactA, artifactB []byte, subjectName string) (bundleA, bundleB, rootRaw []byte, expectedA, expectedB verifier.Expected) {
	t.Helper()
	if sha256.Sum256(artifactA) == sha256.Sum256(artifactB) {
		t.Fatal("cross-binding fixture requires distinct artifact hashes")
	}
	factory := newSigningFactory(t)
	objectA, bodyA, expectedA := factory.artifact(t, kind, artifactA, subjectName)
	objectB, bodyB, expectedB := factory.artifact(t, kind, artifactB, subjectName)
	hashA, hashB := rfc6962.DefaultHasher.HashLeaf(bodyA), rfc6962.DefaultHasher.HashLeaf(bodyB)
	rootHash := rfc6962.DefaultHasher.HashChildren(hashA, hashB)
	bundleA = factory.finish(t, objectA, bodyA, expectedA, 0, 2, rootHash, [][]byte{hashB})
	bundleB = factory.finish(t, objectB, bodyB, expectedB, 1, 2, rootHash, [][]byte{hashA})
	return bundleA, bundleB, bytes.Clone(factory.rootRaw), expectedA, expectedB
}

type signingFactory struct {
	now     time.Time
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
	logKey  *ecdsa.PrivateKey
	logID   [32]byte
	rootRaw []byte
}

func newSigningFactory(t *testing.T) *signingFactory {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootCert, rootKey, err := ca.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, issuerKey, err := ca.GenerateFulcioIntermediate(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := fixtureECDSAKey(t)
	ctKey := fixtureECDSAKey(t)
	ctID := fixturePublicKeyHash(t, ctKey)
	leaf := fixtureLeafWithSCT(t, now, leafKey, issuerCert, issuerKey, ctKey, ctID)
	logKey := fixtureECDSAKey(t)
	logID := fixturePublicKeyHash(t, logKey)
	log := func(uri string, id [32]byte, key *ecdsa.PrivateKey) *root.TransparencyLog {
		return &root.TransparencyLog{BaseURL: uri, ID: id[:], ValidityPeriodStart: now.Add(-time.Hour), ValidityPeriodEnd: now.Add(time.Hour), HashFunc: crypto.SHA256, PublicKey: key.Public(), SignatureHashFunc: crypto.SHA256}
	}
	trusted, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{&root.FulcioCertificateAuthority{URI: "https://fulcio.fixture.invalid", Root: rootCert, Intermediates: []*x509.Certificate{issuerCert}, ValidityPeriodStart: now.Add(-time.Hour), ValidityPeriodEnd: now.Add(time.Hour)}},
		map[string]*root.TransparencyLog{hex.EncodeToString(ctID[:]): log("https://ct.fixture.invalid", ctID, ctKey)}, nil,
		map[string]*root.TransparencyLog{hex.EncodeToString(logID[:]): log("https://rekor.fixture.invalid", logID, logKey)})
	if err != nil {
		t.Fatal(err)
	}
	rootRaw, err := trusted.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return &signingFactory{now: now, leaf: leaf, leafKey: leafKey, logKey: logKey, logID: logID, rootRaw: rootRaw}
}

func (f *signingFactory) artifact(t *testing.T, kind verifier.Kind, artifact []byte, subjectName string) (object map[string]any, body []byte, expected verifier.Expected) {
	t.Helper()
	if kind != verifier.KindMessageSignature && kind != verifier.KindDSSE {
		t.Fatal("unsupported signing fixture kind")
	}
	leaf, leafKey := f.leaf, f.leafKey
	artifactHash := sha256.Sum256(artifact)
	rootHash := sha256.Sum256(f.rootRaw)
	expected = verifier.Expected{Kind: kind, ArtifactSHA256: "sha256:" + hex.EncodeToString(artifactHash[:]), Issuer: sctFixtureIssuer, SAN: sctFixtureIdentity, LogID: hex.EncodeToString(f.logID[:]), TrustedRootSHA256: "sha256:" + hex.EncodeToString(rootHash[:])}
	toSign := artifact
	var statement, envelope []byte
	if kind == verifier.KindDSSE {
		expected.SubjectName, expected.PredicateType = subjectName, "https://slsa.dev/provenance/v1"
		statement = signingJSON(t, map[string]any{
			"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": subjectName, "digest": map[string]string{"sha256": hex.EncodeToString(artifactHash[:])}}},
			"predicateType": expected.PredicateType, "predicate": map[string]any{"testOnly": true},
		})
		toSign = dsse.PAE("application/vnd.in-toto+json", statement)
	}
	signingHash := sha256.Sum256(toSign)
	artifactSignature, err := ecdsa.SignASN1(rand.Reader, leafKey, signingHash[:])
	if err != nil {
		t.Fatal(err)
	}
	props := types.ArtifactProperties{PublicKeyBytes: [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}, PKIFormat: "x509", SignatureBytes: artifactSignature}
	rekorKind := hashedrekord.KIND
	if kind == verifier.KindDSSE {
		envelope = signingJSON(t, dsse.Envelope{PayloadType: "application/vnd.in-toto+json", Payload: base64.StdEncoding.EncodeToString(statement), Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(artifactSignature)}}})
		props.ArtifactBytes, rekorKind = envelope, "dsse"
	} else {
		props.ArtifactHash = hex.EncodeToString(artifactHash[:])
	}
	proposed, err := types.NewProposedEntry(context.Background(), rekorKind, "0.0.1", props)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.CreateVersionedEntry(proposed)
	if err != nil {
		t.Fatal(err)
	}
	body, err = types.CanonicalizeEntry(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	object = map[string]any{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{"certificate": map[string]any{"rawBytes": leaf.Raw}},
	}
	if kind == verifier.KindDSSE {
		object["dsseEnvelope"] = map[string]any{"payload": statement, "payloadType": "application/vnd.in-toto+json", "signatures": []any{map[string]any{"sig": artifactSignature}}}
	} else {
		object["messageSignature"] = map[string]any{"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": artifactHash[:]}, "signature": artifactSignature}
	}
	return object, body, expected
}

func (f *signingFactory) finish(t *testing.T, object map[string]any, body []byte, expected verifier.Expected, index, treeSize int64, rootHash []byte, siblings [][]byte) []byte {
	t.Helper()
	logSigner, err := signature.LoadECDSASignerVerifier(f.logKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	integrated := f.now.Unix()
	setPayload := tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: integrated, LogIndex: index, LogID: expected.LogID}
	canonical, err := jsoncanonicalizer.Transform(signingJSON(t, setPayload))
	if err != nil {
		t.Fatal(err)
	}
	set, err := logSigner.SignMessage(bytes.NewReader(canonical))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := util.CreateAndSignCheckpoint(context.Background(), "rekor.fixture.invalid", 123, uint64(treeSize), rootHash, logSigner)
	if err != nil {
		t.Fatal(err)
	}
	rekorKind := hashedrekord.KIND
	if expected.Kind == verifier.KindDSSE {
		rekorKind = "dsse"
	}
	hashes := make([]any, len(siblings))
	for i, sibling := range siblings {
		hashes[i] = sibling
	}
	object["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{map[string]any{
		"logIndex": strconv.FormatInt(index, 10), "logId": map[string]any{"keyId": f.logID[:]}, "kindVersion": map[string]any{"kind": rekorKind, "version": "0.0.1"},
		"integratedTime": strconv.FormatInt(integrated, 10), "inclusionPromise": map[string]any{"signedEntryTimestamp": set}, "canonicalizedBody": body,
		"inclusionProof": map[string]any{"logIndex": strconv.FormatInt(index, 10), "treeSize": strconv.FormatInt(treeSize, 10), "rootHash": rootHash, "hashes": hashes, "checkpoint": map[string]any{"envelope": string(checkpoint)}},
	}}
	return signingJSON(t, object)
}

func fixtureECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func fixturePublicKeyHash(t *testing.T, key *ecdsa.PrivateKey) [32]byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(der)
}
func signingJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixtureLeafWithSCT(t *testing.T, now time.Time, leafKey *ecdsa.PrivateKey, issuer *x509.Certificate, issuerKey, ctKey *ecdsa.PrivateKey, ctID [32]byte) *x509.Certificate {
	t.Helper()
	issuerExtension := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte(sctFixtureIssuer)}
	poisonExtension := pkix.Extension{Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTPoison), Critical: true, Value: []byte{5, 0}}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), EmailAddresses: []string{sctFixtureIdentity}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, ExtraExtensions: []pkix.Extension{issuerExtension, poisonExtension}}
	preDER, err := x509.CreateCertificate(rand.Reader, template, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	preCert, err := ctx509.ParseCertificate(preDER)
	if err != nil {
		t.Fatal(err)
	}
	ctIssuer, err := ctx509.ParseCertificate(issuer.Raw)
	if err != nil {
		t.Fatal(err)
	}
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: ctID}, Timestamp: uint64(now.UnixMilli())}
	merkleLeaf, err := ct.MerkleTreeLeafFromChain([]*ctx509.Certificate{preCert, ctIssuer}, ct.PrecertLogEntryType, sct.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: *merkleLeaf})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(serialized)
	sig, err := ecdsa.SignASN1(rand.Reader, ctKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sct.Signature = ct.DigitallySigned{Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: sig}
	list, err := x509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		t.Fatal(err)
	}
	encodedList, err := cttls.Marshal(*list)
	if err != nil {
		t.Fatal(err)
	}
	asnList, err := asn1.Marshal(encodedList)
	if err != nil {
		t.Fatal(err)
	}
	template.ExtraExtensions = []pkix.Extension{issuerExtension, {Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: asnList}}
	finalDER, err := x509.CreateCertificate(rand.Reader, template, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	final, err := x509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatal(err)
	}
	// Independent CT-library roundtrip ensures the final SCT-bearing certificate
	// reconstructs exactly the precertificate input actually signed above.
	finalCT, err := ctx509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{finalCT, ctIssuer}, sct.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.TimestampedEntry.PrecertEntry.TBSCertificate, merkleLeaf.TimestampedEntry.PrecertEntry.TBSCertificate) {
		t.Fatal("precertificate/final SCT input mismatch")
	}
	return final
}

func TestGeneratedSigningMaterial(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			bundleRaw, rootRaw, expected := signedBundle(t, kind, []byte("ephemeral signed artifact fixture"), "registry.fixture.invalid/team/image")
			result, err := verifier.Verify(context.Background(), expected, bundleRaw, rootRaw)
			if err != nil || !result.Verified() || result.Authorization() != "BLOCKED" {
				t.Fatalf("real generated proof rejected: %v", err)
			}
			if !strings.HasPrefix(result.BundleSHA256(), "sha256:") {
				t.Fatal("missing material identity")
			}
		})
	}
}

func TestGeneratedSameSignerPair(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			bundleA, bundleB, rootRaw, expectedA, expectedB := signedBundlePair(t, kind, []byte("artifact A: distinct immutable bytes"), []byte("artifact B: distinct immutable bytes"), "registry.fixture.invalid/team/image")
			if expectedA.ArtifactSHA256 == expectedB.ArtifactSHA256 {
				t.Fatal("pair did not distinguish artifact identity")
			}
			aAsB := expectedA
			aAsB.ArtifactSHA256 = expectedB.ArtifactSHA256
			if aAsB != expectedB {
				t.Fatal("pair changed signer, trust root, log, subject or signature policy")
			}
			var objectA, objectB map[string]any
			if json.Unmarshal(bundleA, &objectA) != nil || json.Unmarshal(bundleB, &objectB) != nil {
				t.Fatal("invalid fixture JSON")
			}
			vmA, vmB := objectA["verificationMaterial"].(map[string]any), objectB["verificationMaterial"].(map[string]any)
			if vmA["certificate"].(map[string]any)["rawBytes"] != vmB["certificate"].(map[string]any)["rawBytes"] {
				t.Fatal("pair used different leaf cert or SCT")
			}
			proofA := vmA["tlogEntries"].([]any)[0].(map[string]any)["inclusionProof"].(map[string]any)
			proofB := vmB["tlogEntries"].([]any)[0].(map[string]any)["inclusionProof"].(map[string]any)
			if proofA["treeSize"] != "2" || proofB["treeSize"] != "2" || proofA["rootHash"] != proofB["rootHash"] || proofA["logIndex"] != "0" || proofB["logIndex"] != "1" {
				t.Fatal("pair did not share one consistent Merkle tree")
			}
			for _, tc := range []struct {
				name     string
				bundle   []byte
				expected verifier.Expected
				valid    bool
			}{
				{"A-for-A", bundleA, expectedA, true}, {"B-for-B", bundleB, expectedB, true},
				{"B-cannot-satisfy-A", bundleB, expectedA, false}, {"A-cannot-satisfy-B", bundleA, expectedB, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					result, err := verifier.Verify(context.Background(), tc.expected, tc.bundle, rootRaw)
					if tc.valid {
						if err != nil || !result.Verified() || result.Authorization() != "BLOCKED" {
							t.Fatalf("matching proof rejected: %v", err)
						}
					} else if err != verifier.ErrInvalid || result != (verifier.Result{}) {
						t.Fatal("cross-artifact proof accepted or leaked nonzero result")
					}
				})
			}
		})
	}
}
