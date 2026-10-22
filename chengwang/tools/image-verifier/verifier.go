// Package verifier verifies bounded, offline Sigstore bundles using the
// official Sigstore implementation. Results are advisory, never authorization.
package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

const MaxBundleBytes = 1 << 20
const MaxRootBytes = 1 << 20

type Kind string

const (
	KindMessageSignature Kind = "message-signature"
	KindDSSE             Kind = "dsse"
)

var ErrInvalid = errors.New("invalid Sigstore verification input or proof")

// Expected must come from independently approved caller policy, not values
// extracted from a candidate bundle. Pinning a supplied root is not TUF trust.
type Expected struct {
	ArtifactSHA256    string
	TrustedRootSHA256 string
	LogID             string
	Issuer            string
	SAN               string
	Kind              Kind
	SubjectName       string
	PredicateType     string
}

// Result cannot be constructed from JSON or an externally supplied receipt.
// It intentionally omits certificates, predicates, and third-party errors.
type Result struct {
	verified     bool
	artifactHash string
	bundleHash   string
	rootHash     string
}

func (r Result) Verified() bool { return r.verified }
func (r Result) Boundary() string {
	if !r.verified {
		return ""
	}
	return "ADVISORY_SIGSTORE_BUNDLE_VERIFIED"
}
func (r Result) Authorization() string     { return "BLOCKED" }
func (r Result) ArtifactSHA256() string    { return r.artifactHash }
func (r Result) BundleSHA256() string      { return r.bundleHash }
func (r Result) TrustedRootSHA256() string { return r.rootHash }

// Verify makes no network or filesystem calls. The upstream crypto API is not
// cancellable: ctx is checked before/after, not a promise to interrupt crypto.
// Execute in an externally limited process for hard time/CPU/memory bounds.
// Callers must not mutate input slices concurrently with this call.
func Verify(ctx context.Context, expected Expected, bundleRaw, rootRaw []byte) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !validExpected(expected) || len(bundleRaw) == 0 || len(bundleRaw) > MaxBundleBytes || len(rootRaw) == 0 || len(rootRaw) > MaxRootBytes {
		return Result{}, ErrInvalid
	}
	// Own the bytes used by both the digest pin and all downstream parsers.
	bundleRaw = bytes.Clone(bundleRaw)
	rootRaw = bytes.Clone(rootRaw)
	if digest(rootRaw) != expected.TrustedRootSHA256 {
		return Result{}, ErrInvalid
	}
	rootMap, err := strictJSON(rootRaw)
	if err != nil || !canonicalProtoObject(rootMap, (&prototrustroot.TrustedRoot{}).ProtoReflect().Descriptor()) {
		return Result{}, ErrInvalid
	}
	var rootProto prototrustroot.TrustedRoot
	if protojson.Unmarshal(rootRaw, &rootProto) != nil || !validRoot(&rootProto, expected.LogID) {
		return Result{}, ErrInvalid
	}
	trusted, err := root.NewTrustedRootFromJSON(rootRaw)
	if err != nil {
		return Result{}, ErrInvalid
	}
	bundleMap, err := strictJSON(bundleRaw)
	if err != nil {
		return Result{}, ErrInvalid
	}
	b := &bundle.Bundle{}
	if b.UnmarshalJSON(bundleRaw) != nil || !canonicalProtoObject(bundleMap, b.ProtoReflect().Descriptor()) {
		return Result{}, ErrInvalid
	}
	integratedTime, ok := validBundle(b, expected)
	if !ok {
		return Result{}, ErrInvalid
	}
	identity, err := verify.NewShortCertificateIdentity(expected.Issuer, "", expected.SAN, "")
	if err != nil {
		return Result{}, ErrInvalid
	}
	v, err := verify.NewVerifier(trusted,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
		verify.WithSignedCertificateTimestamps(1))
	if err != nil {
		return Result{}, ErrInvalid
	}
	artifactDigest, _ := hex.DecodeString(strings.TrimPrefix(expected.ArtifactSHA256, "sha256:"))
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	verified, err := v.Verify(b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", artifactDigest),
		verify.WithCertificateIdentity(identity)))
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err != nil || verified == nil || verified.Signature == nil || verified.Signature.Certificate == nil || verified.VerifiedIdentity == nil || len(verified.VerifiedTimestamps) != 1 {
		return Result{}, ErrInvalid
	}
	ts := verified.VerifiedTimestamps[0]
	if ts.Type != "Tlog" || !ts.Timestamp.Equal(time.Unix(integratedTime, 0)) {
		return Result{}, ErrInvalid
	}
	if expected.Kind == KindDSSE {
		s := verified.Statement
		if s == nil || s.GetType() != "https://in-toto.io/Statement/v1" || s.GetPredicateType() != expected.PredicateType || len(s.GetSubject()) != 1 || s.GetSubject()[0].GetName() != expected.SubjectName || len(s.GetSubject()[0].GetDigest()) != 1 || s.GetSubject()[0].GetDigest()["sha256"] != strings.TrimPrefix(expected.ArtifactSHA256, "sha256:") {
			return Result{}, ErrInvalid
		}
	} else if verified.Statement != nil {
		return Result{}, ErrInvalid
	}
	return Result{verified: true, artifactHash: expected.ArtifactSHA256, bundleHash: digest(bundleRaw), rootHash: expected.TrustedRootSHA256}, nil
}

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func hexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func pinnedDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && hexDigest(strings.TrimPrefix(s, "sha256:"))
}

func cleanText(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n\t")
}

func httpsIdentity(s string) bool {
	u, err := url.Parse(s)
	return cleanText(s, 2048) && err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func validExpected(e Expected) bool {
	if !pinnedDigest(e.ArtifactSHA256) || !pinnedDigest(e.TrustedRootSHA256) || !hexDigest(e.LogID) || !httpsIdentity(e.Issuer) || !cleanText(e.SAN, 2048) {
		return false
	}
	switch e.Kind {
	case KindMessageSignature:
		return e.SubjectName == "" && e.PredicateType == ""
	case KindDSSE:
		return cleanText(e.SubjectName, 2048) && httpsIdentity(e.PredicateType)
	default:
		return false
	}
}

func validRoot(r *prototrustroot.TrustedRoot, expectedLogID string) bool {
	if r.GetMediaType() != root.TrustedRootMediaType01 || len(r.GetTlogs()) == 0 || len(r.GetTlogs()) > 8 || len(r.GetCtlogs()) == 0 || len(r.GetCtlogs()) > 8 || len(r.GetCertificateAuthorities()) == 0 || len(r.GetCertificateAuthorities()) > 8 || len(r.GetTimestampAuthorities()) > 8 {
		return false
	}
	for _, logs := range [][]*prototrustroot.TransparencyLogInstance{r.GetTlogs(), r.GetCtlogs()} {
		seen := map[string]bool{}
		for _, log := range logs {
			id := hex.EncodeToString(log.GetLogId().GetKeyId())
			if !hexDigest(id) || seen[id] || log.GetHashAlgorithm() != protocommon.HashAlgorithm_SHA2_256 || len(log.GetPublicKey().GetRawBytes()) == 0 || len(log.GetPublicKey().GetRawBytes()) > 16384 {
				return false
			}
			seen[id] = true
		}
	}
	found := false
	for _, log := range r.GetTlogs() {
		found = found || hex.EncodeToString(log.GetLogId().GetKeyId()) == expectedLogID
	}
	for _, authorities := range [][]*prototrustroot.CertificateAuthority{r.GetCertificateAuthorities(), r.GetTimestampAuthorities()} {
		for _, authority := range authorities {
			certs := authority.GetCertChain().GetCertificates()
			if len(certs) == 0 || len(certs) > 8 {
				return false
			}
			for _, cert := range certs {
				if len(cert.GetRawBytes()) == 0 || len(cert.GetRawBytes()) > 16384 {
					return false
				}
			}
		}
	}
	return found
}

func validBundle(b *bundle.Bundle, e Expected) (int64, bool) {
	if b.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" && b.MediaType != "application/vnd.dev.sigstore.bundle+json;version=0.3" {
		return 0, false
	}
	vm := b.GetVerificationMaterial()
	cert := vm.GetCertificate().GetRawBytes()
	if len(cert) == 0 || len(cert) > 16384 || vm.GetTimestampVerificationData() != nil || len(vm.GetTlogEntries()) != 1 {
		return 0, false
	}
	t := vm.GetTlogEntries()[0]
	p := t.GetInclusionProof()
	// Rekor v1 uses a global entry index (SET) and a shard-local proof index.
	// They legitimately differ. The SDK verifies each against the same body:
	// SET binds the global index; Merkle proof/checkpoint bind the local index.
	if hex.EncodeToString(t.GetLogId().GetKeyId()) != e.LogID || t.GetIntegratedTime() <= 0 || t.GetLogIndex() < 0 || len(t.GetInclusionPromise().GetSignedEntryTimestamp()) == 0 || len(t.GetInclusionPromise().GetSignedEntryTimestamp()) > 16384 || p == nil || p.GetTreeSize() <= 0 || p.GetLogIndex() < 0 || p.GetLogIndex() >= p.GetTreeSize() || len(p.GetRootHash()) != 32 || len(p.GetHashes()) > 63 {
		return 0, false
	}
	// Checkpoint is multiline signed text, not a URL or a one-line policy field.
	if len(p.GetCheckpoint().GetEnvelope()) == 0 || len(p.GetCheckpoint().GetEnvelope()) > 16384 {
		return 0, false
	}
	for _, hash := range p.GetHashes() {
		if len(hash) != 32 {
			return 0, false
		}
	}
	if len(t.GetCanonicalizedBody()) == 0 || len(t.GetCanonicalizedBody()) > 256<<10 {
		return 0, false
	}
	body, err := strictJSON(t.GetCanonicalizedBody())
	if err != nil || !validRekorBody(body, e.Kind) || textValue(body["kind"]) != t.GetKindVersion().GetKind() || textValue(body["apiVersion"]) != t.GetKindVersion().GetVersion() {
		return 0, false
	}
	switch e.Kind {
	case KindMessageSignature:
		msg := b.GetMessageSignature()
		if msg == nil || msg.GetMessageDigest().GetAlgorithm() != protocommon.HashAlgorithm_SHA2_256 || len(msg.GetMessageDigest().GetDigest()) != 32 || hex.EncodeToString(msg.GetMessageDigest().GetDigest()) != strings.TrimPrefix(e.ArtifactSHA256, "sha256:") || len(msg.GetSignature()) == 0 || len(msg.GetSignature()) > 16384 {
			return 0, false
		}
	case KindDSSE:
		env := b.GetDsseEnvelope()
		if env == nil || env.GetPayloadType() != "application/vnd.in-toto+json" || len(env.GetPayload()) == 0 || len(env.GetPayload()) > 256<<10 || len(env.GetSignatures()) != 1 || len(env.GetSignatures()[0].GetSig()) == 0 || len(env.GetSignatures()[0].GetSig()) > 16384 {
			return 0, false
		}
		statement, err := strictJSON(env.GetPayload())
		if err != nil || !validStatement(statement, e) {
			return 0, false
		}
	default:
		return 0, false
	}
	return t.GetIntegratedTime(), true
}

func validStatement(m map[string]any, e Expected) bool {
	if !onlyKeys(m, "_type", "subject", "predicateType", "predicate") || textValue(m["_type"]) != "https://in-toto.io/Statement/v1" || textValue(m["predicateType"]) != e.PredicateType || object(m["predicate"]) == nil {
		return false
	}
	subjects, ok := m["subject"].([]any)
	if !ok || len(subjects) != 1 {
		return false
	}
	s := object(subjects[0])
	d := object(s["digest"])
	return onlyKeys(s, "name", "digest") && len(s) == 2 && textValue(s["name"]) == e.SubjectName && len(d) == 1 && textValue(d["sha256"]) == strings.TrimPrefix(e.ArtifactSHA256, "sha256:")
}

// Keep the supported Rekor v1 schemas explicit. The SDK performs the actual
// signature/key/digest linkage; this rejects unknown or ambiguous JSON first.
func validRekorBody(m map[string]any, kind Kind) bool {
	if !onlyKeys(m, "apiVersion", "kind", "spec") || len(m) != 3 || textValue(m["apiVersion"]) != "0.0.1" {
		return false
	}
	s := object(m["spec"])
	if kind == KindMessageSignature {
		data := object(s["data"])
		sig := object(s["signature"])
		pk := object(sig["publicKey"])
		return textValue(m["kind"]) == "hashedrekord" && onlyKeys(s, "data", "signature") && len(s) == 2 && onlyKeys(data, "hash") && validHash(object(data["hash"])) && onlyKeys(sig, "content", "publicKey") && len(sig) == 2 && textValue(sig["content"]) != "" && onlyKeys(pk, "content") && textValue(pk["content"]) != ""
	}
	if textValue(m["kind"]) != "dsse" || !onlyKeys(s, "envelopeHash", "payloadHash", "signatures") || len(s) != 3 || !validHash(object(s["envelopeHash"])) || !validHash(object(s["payloadHash"])) {
		return false
	}
	sigs, ok := s["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return false
	}
	sig := object(sigs[0])
	return onlyKeys(sig, "signature", "verifier") && len(sig) == 2 && textValue(sig["signature"]) != "" && textValue(sig["verifier"]) != ""
}

func validHash(m map[string]any) bool {
	return onlyKeys(m, "algorithm", "value") && len(m) == 2 && textValue(m["algorithm"]) == "sha256" && hexDigest(textValue(m["value"]))
}
