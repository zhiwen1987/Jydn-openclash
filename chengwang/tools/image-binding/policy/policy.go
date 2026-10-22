// Package policy verifies an independently pinned Ed25519 image approval.
// It does not fetch keys, approve deployments, or accept status booleans.
package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	verifier "chengwang-image-verifier"
	"chengwang/internal/restoreimage"
)

const MaxEnvelopeBytes = 64 << 10
const MaxPolicyBytes = 64 << 10
const Schema = "chengwang.image-approval/v1"
const signingDomain = Schema + "\x00"

var ErrInvalid = errors.New("invalid image approval")

type Trust struct {
	KeyID        string
	PublicKey    ed25519.PublicKey
	PolicySHA256 string
	Revision     uint64
}

type document struct {
	id, keyID, reference, os, architecture, variant string
	registrySPKI                                    string
	revision                                        uint64
	notBefore, notAfter                             int64
	ips                                             []string
	signature                                       verifier.Expected
}

// Approved has no public fields or deserialization constructor. An imported
// JSON receipt or a zero value cannot establish approval.
type Approved struct {
	verified bool
	sha256   string
	policy   document
}

func (a Approved) ValidAt(now time.Time) bool {
	return a.verified && !now.IsZero() && now.UTC().Unix() >= a.policy.notBefore && now.UTC().Unix() < a.policy.notAfter
}
func (a Approved) SHA256() string                       { return a.sha256 }
func (a Approved) ID() string                           { return a.policy.id }
func (a Approved) Revision() uint64                     { return a.policy.revision }
func (a Approved) Reference() string                    { return a.policy.reference }
func (a Approved) OS() string                           { return a.policy.os }
func (a Approved) Architecture() string                 { return a.policy.architecture }
func (a Approved) Variant() string                      { return a.policy.variant }
func (a Approved) RegistryIPs() []string                { return append([]string(nil), a.policy.ips...) }
func (a Approved) RegistrySPKISHA256() string           { return a.policy.registrySPKI }
func (a Approved) SignatureExpected() verifier.Expected { return a.policy.signature }
func (a Approved) KeyID() string                        { return a.policy.keyID }
func (a Approved) NotAfterUnix() int64                  { return a.policy.notAfter }

// Verify accepts only raw policy bytes signed under the exact domain separator
// and an independently supplied hash, approver key, and exact revision. Input
// slices and trust.PublicKey must not be mutated concurrently during this call.
// Every failure, including cancellation, returns a zero Approved and ErrInvalid.
func Verify(ctx context.Context, trust Trust, envelopeRaw []byte, now time.Time) (Approved, error) {
	if ctx == nil || ctx.Err() != nil || now.IsZero() || !identifier(trust.KeyID) || len(trust.PublicKey) != ed25519.PublicKeySize || !pinnedDigest(trust.PolicySHA256) || trust.Revision == 0 {
		return Approved{}, ErrInvalid
	}
	if len(envelopeRaw) == 0 || len(envelopeRaw) > MaxEnvelopeBytes {
		return Approved{}, ErrInvalid
	}
	publicKey := bytes.Clone(trust.PublicKey)
	envelope, err := strictObject(bytes.Clone(envelopeRaw))
	if err != nil || !exactKeys(envelope, "payload", "signature") {
		return Approved{}, ErrInvalid
	}
	payload, ok := base64Value(envelope["payload"], MaxPolicyBytes)
	if !ok {
		return Approved{}, ErrInvalid
	}
	signature, ok := base64Value(envelope["signature"], ed25519.SignatureSize)
	if !ok || len(signature) != ed25519.SignatureSize || digest(payload) != trust.PolicySHA256 {
		return Approved{}, ErrInvalid
	}
	message := make([]byte, 0, len(signingDomain)+len(payload))
	message = append(message, signingDomain...)
	message = append(message, payload...)
	if !ed25519.Verify(publicKey, message, signature) || ctx.Err() != nil {
		return Approved{}, ErrInvalid
	}
	m, err := strictObject(payload)
	if err != nil {
		return Approved{}, ErrInvalid
	}
	d, ok := parseDocument(m)
	if !ok || d.keyID != trust.KeyID || d.revision != trust.Revision {
		return Approved{}, ErrInvalid
	}
	a := Approved{verified: true, sha256: trust.PolicySHA256, policy: d}
	if !a.ValidAt(now) || ctx.Err() != nil {
		return Approved{}, ErrInvalid
	}
	return a, nil
}

func parseDocument(m map[string]any) (document, bool) {
	var d document
	if !exactKeys(m, "schema", "policyID", "revision", "approverKeyID", "notBeforeUnix", "notAfterUnix", "reference", "os", "architecture", "variant", "registryIPs", "registrySPKISHA256", "signature") || text(m["schema"]) != Schema {
		return d, false
	}
	for _, key := range []string{"schema", "policyID", "approverKeyID", "reference", "os", "architecture", "variant", "registrySPKISHA256"} {
		if _, ok := m[key].(string); !ok {
			return document{}, false
		}
	}
	d.id, d.keyID, d.reference = text(m["policyID"]), text(m["approverKeyID"]), text(m["reference"])
	d.os, d.architecture, d.variant = text(m["os"]), text(m["architecture"]), text(m["variant"])
	d.registrySPKI = text(m["registrySPKISHA256"])
	if !pinnedDigest(d.registrySPKI) {
		return document{}, false
	}
	var ok bool
	if d.revision, ok = unsigned(m["revision"]); !ok || d.revision == 0 {
		return document{}, false
	}
	if d.notBefore, ok = unix(m["notBeforeUnix"]); !ok {
		return document{}, false
	}
	if d.notAfter, ok = unix(m["notAfterUnix"]); !ok || d.notAfter <= d.notBefore || d.notAfter-d.notBefore > 86400 {
		return document{}, false
	}
	if !identifier(d.id) || !identifier(d.keyID) || !platformToken(d.os, false) || !platformToken(d.architecture, false) || !platformToken(d.variant, true) {
		return document{}, false
	}
	repository, hash, ok := reference(d.reference)
	if !ok || !restoreimage.ValidateExpected(restoreimage.Expected{Reference: d.reference, OS: d.os, Architecture: d.architecture, Variant: d.variant}) {
		return document{}, false
	}
	ips, ok := m["registryIPs"].([]any)
	if !ok || len(ips) == 0 || len(ips) > 8 {
		return document{}, false
	}
	seen := map[string]bool{}
	for _, v := range ips {
		s := text(v)
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Zone() != "" || addr.String() != s || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() || seen[s] {
			return document{}, false
		}
		seen[s] = true
		d.ips = append(d.ips, s)
	}
	d.signature, ok = parseSignature(m["signature"])
	if !ok || d.signature.ArtifactSHA256 != hash || d.signature.Kind == verifier.KindDSSE && d.signature.SubjectName != repository {
		return document{}, false
	}
	return d, true
}

func parseSignature(v any) (verifier.Expected, bool) {
	m, ok := v.(map[string]any)
	if !ok || !onlyKeys(m, "artifactSHA256", "trustedRootSHA256", "logID", "issuer", "san", "kind", "subjectName", "predicateType") {
		return verifier.Expected{}, false
	}
	for _, key := range []string{"artifactSHA256", "trustedRootSHA256", "logID", "issuer", "san", "kind"} {
		if _, ok := m[key].(string); !ok {
			return verifier.Expected{}, false
		}
	}
	for _, key := range []string{"subjectName", "predicateType"} {
		if value, exists := m[key]; exists {
			if _, ok := value.(string); !ok {
				return verifier.Expected{}, false
			}
		}
	}
	e := verifier.Expected{ArtifactSHA256: text(m["artifactSHA256"]), TrustedRootSHA256: text(m["trustedRootSHA256"]), LogID: text(m["logID"]), Issuer: text(m["issuer"]), SAN: text(m["san"]), Kind: verifier.Kind(text(m["kind"])), SubjectName: text(m["subjectName"]), PredicateType: text(m["predicateType"])}
	if !pinnedDigest(e.ArtifactSHA256) || !pinnedDigest(e.TrustedRootSHA256) || !hexDigest(e.LogID) || !httpsURL(e.Issuer) || !clean(e.SAN, 2048) {
		return verifier.Expected{}, false
	}
	switch e.Kind {
	case verifier.KindMessageSignature:
		return e, e.SubjectName == "" && e.PredicateType == ""
	case verifier.KindDSSE:
		return e, clean(e.SubjectName, 2048) && httpsURL(e.PredicateType)
	default:
		return verifier.Expected{}, false
	}
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var platformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
var repositoryPartPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
var hostnamePartPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func identifier(s string) bool { return idPattern.MatchString(s) }
func platformToken(s string, empty bool) bool {
	return empty && s == "" || platformPattern.MatchString(s)
}
func clean(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return clean(s, 2048) && err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

// reference accepts an explicit, canonical registry/repository and immutable
// sha256 only. No scheme, tag, query, credentials, traversal, or implicit host.
func reference(s string) (string, string, bool) {
	if len(s) > 2048 || strings.Count(s, "@") != 1 {
		return "", "", false
	}
	repo, hash, _ := strings.Cut(s, "@")
	host, path, ok := strings.Cut(repo, "/")
	if !ok || host == "" || path == "" || !pinnedDigest(hash) || host != strings.ToLower(host) {
		return "", "", false
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	hostname := u.Hostname()
	if addr, err := netip.ParseAddr(hostname); err == nil {
		if addr.String() != hostname || addr.Zone() != "" || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() || addr.Is6() && !strings.HasPrefix(host, "[") {
			return "", "", false
		}
	} else {
		if len(hostname) == 0 || len(hostname) > 253 || strings.ContainsAny(hostname, ":[]%") {
			return "", "", false
		}
		for _, label := range strings.Split(hostname, ".") {
			if !hostnamePartPattern.MatchString(label) {
				return "", "", false
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return "", "", false
		}
	} else if strings.HasSuffix(host, ":") {
		return "", "", false
	}
	if len(path) > 255 {
		return "", "", false
	}
	for _, part := range strings.Split(path, "/") {
		if !repositoryPartPattern.MatchString(part) {
			return "", "", false
		}
	}
	return repo, hash, true
}

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}
func pinnedDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && hexDigest(strings.TrimPrefix(s, "sha256:"))
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
func base64Value(v any, limit int) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) > 0 && len(b) <= limit && base64.StdEncoding.EncodeToString(b) == s
}
func unsigned(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	x, err := strconv.ParseUint(string(n), 10, 64)
	return x, err == nil && strconv.FormatUint(x, 10) == string(n)
}
func unix(v any) (int64, bool) {
	x, ok := unsigned(v)
	return int64(x), ok && x > 0 && x <= 253402300799
}
func text(v any) string { s, _ := v.(string); return s }
func exactKeys(m map[string]any, keys ...string) bool {
	return len(m) == len(keys) && onlyKeys(m, keys...)
}
func onlyKeys(m map[string]any, keys ...string) bool {
	if m == nil {
		return false
	}
	for key := range m {
		found := false
		for _, allowed := range keys {
			if key == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
