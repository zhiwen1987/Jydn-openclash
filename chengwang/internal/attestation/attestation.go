// Package attestation signs bounded, canonical evidence-summary statements.
//
// An attestation proves that a holder of the configured Ed25519 private key
// signed the exact payload. It does not provide WORM storage, a trusted clock,
// or persistence for replay state. Verifiers must obtain the public key through
// an independently trusted channel.
package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	EnvelopeVersion = 1
	PayloadVersion  = 1
	Algorithm       = "Ed25519"
	Encoding        = "base64url"

	minNonceBytes    = 16
	maxNonceBytes    = 64
	maxIDBytes       = 128
	maxEnvelopeBytes = 4096
)

var (
	safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`)
	lowerSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	genesisHash    = strings.Repeat("0", 64)

	// ErrInvalidSignature means the envelope was structurally valid but was
	// not signed by the supplied public key.
	ErrInvalidSignature = errors.New("attestation signature is invalid")
	// ErrSequenceReplay covers both a duplicate sequence and a rollback to an
	// earlier sequence within one SequenceVerifier process lifetime.
	ErrSequenceReplay = errors.New("attestation sequence is duplicate or rolled back")
)

// Payload is the signed evidence summary. GeneratedAt is canonical UTC
// RFC3339Nano text; it records a signer claim and is not a trusted timestamp.
type Payload struct {
	Version          int    `json:"version"`
	EvidenceCount    uint64 `json:"evidenceCount"`
	EvidenceLastHash string `json:"evidenceLastHash"`
	GeneratedAt      string `json:"generatedAt"`
	InstanceID       string `json:"instanceId"`
	SiteID           string `json:"siteId"`
	Nonce            string `json:"nonce"`
	Sequence         uint64 `json:"sequence"`
}

// Envelope contains a payload and its detached Ed25519 signature. Algorithm
// and version fields are validated against package constants; Verify never
// uses them to select a cryptographic primitive.
type Envelope struct {
	Version   int     `json:"version"`
	Algorithm string  `json:"algorithm"`
	KeyID     string  `json:"keyId"`
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`
}

// PublicKeyDocument is safe to distribute. It contains no private-key or seed
// material, but consumers must still authenticate its delivery channel.
type PublicKeyDocument struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	Encoding  string `json:"encoding"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

// Signer owns an immutable in-memory copy of one Ed25519 private key.
type Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

// MarshalEnvelope emits the strict, versioned wire representation. It checks
// structural boundaries but cannot establish authenticity; call Verify with a
// trusted public key after parsing an envelope received from another party.
func MarshalEnvelope(envelope Envelope) ([]byte, error) {
	if err := validateEnvelopeStructure(envelope); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation envelope: %w", err)
	}
	if len(encoded) > maxEnvelopeBytes {
		return nil, errors.New("attestation envelope exceeds size limit")
	}
	return encoded, nil
}

// ParseEnvelope decodes exactly one bounded JSON envelope and rejects unknown
// fields before cryptographic verification.
func ParseEnvelope(data []byte) (Envelope, error) {
	if len(data) == 0 || len(data) > maxEnvelopeBytes {
		return Envelope{}, errors.New("attestation envelope size is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, errors.New("decode attestation envelope: invalid strict JSON")
	}
	if err := ensureKeyJSONEOF(decoder); err != nil {
		return Envelope{}, errors.New("decode attestation envelope: invalid strict JSON")
	}
	if err := validateEnvelopeStructure(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// VerifyJSON performs strict bounded parsing followed by fixed-algorithm
// cryptographic verification.
func VerifyJSON(data []byte, publicKey ed25519.PublicKey) (Envelope, error) {
	envelope, err := ParseEnvelope(data)
	if err != nil {
		return Envelope{}, err
	}
	if err := Verify(envelope, publicKey); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// NewSigner validates and defensively copies an Ed25519 private key. File
// based production callers should normally use LoadPrivateKey.
func NewSigner(privateKey ed25519.PrivateKey) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("Ed25519 private key must be 64 bytes")
	}
	derived := ed25519.NewKeyFromSeed(privateKey.Seed())
	if subtle.ConstantTimeCompare(privateKey, derived) != 1 {
		return nil, errors.New("Ed25519 private key is internally inconsistent")
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	publicCopy := append(ed25519.PublicKey(nil), derived.Public().(ed25519.PublicKey)...)
	return &Signer{private: privateCopy, public: publicCopy, keyID: keyID(publicCopy)}, nil
}

// KeyID returns a SHA-256 fingerprint of the public key, not secret material.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// PublicKey returns a defensive copy of the signer's public key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	if s == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), s.public...)
}

// PublicKeyDocument returns the exportable public-only representation.
func (s *Signer) PublicKeyDocument() (PublicKeyDocument, error) {
	if s == nil || len(s.public) != ed25519.PublicKeySize {
		return PublicKeyDocument{}, errors.New("signer is not configured")
	}
	return PublicKeyDocument{
		Version: PublicKeyFileVersion, Algorithm: Algorithm, Encoding: Encoding,
		KeyID: s.keyID, PublicKey: base64.RawURLEncoding.EncodeToString(s.public),
	}, nil
}

// MarshalPublicKey returns strict JSON containing public information only.
func (s *Signer) MarshalPublicKey() ([]byte, error) {
	document, err := s.PublicKeyDocument()
	if err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

// Sign validates the complete payload boundary before signing its canonical
// representation. The caller controls sequence and time claims.
func (s *Signer) Sign(payload Payload) (Envelope, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize || len(s.public) != ed25519.PublicKeySize {
		return Envelope{}, errors.New("signer is not configured")
	}
	if err := validatePayload(payload); err != nil {
		return Envelope{}, err
	}
	message, err := signingBytes(EnvelopeVersion, Algorithm, s.keyID, payload)
	if err != nil {
		return Envelope{}, err
	}
	signature := ed25519.Sign(s.private, message)
	return Envelope{
		Version: EnvelopeVersion, Algorithm: Algorithm, KeyID: s.keyID, Payload: payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

// Verify validates every untrusted envelope field and always performs
// Ed25519 verification with the caller-supplied public key. It never selects
// an algorithm or schema from envelope claims.
func Verify(envelope Envelope, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("Ed25519 public key must be 32 bytes")
	}
	if err := validateEnvelopeStructure(envelope); err != nil {
		return err
	}
	expectedKeyID := keyID(publicKey)
	if subtle.ConstantTimeCompare([]byte(envelope.KeyID), []byte(expectedKeyID)) != 1 {
		return errors.New("attestation key id does not match supplied public key")
	}
	signature, err := decodeCanonicalBase64("signature", envelope.Signature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	message, err := signingBytes(EnvelopeVersion, Algorithm, expectedKeyID, envelope.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func validateEnvelopeStructure(envelope Envelope) error {
	if envelope.Version != EnvelopeVersion {
		return fmt.Errorf("unsupported attestation envelope version %d", envelope.Version)
	}
	if envelope.Algorithm != Algorithm {
		return errors.New("unsupported attestation algorithm")
	}
	if !strings.HasPrefix(envelope.KeyID, "sha256:") || !lowerSHA256.MatchString(strings.TrimPrefix(envelope.KeyID, "sha256:")) {
		return errors.New("attestation key id is invalid")
	}
	if err := validatePayload(envelope.Payload); err != nil {
		return err
	}
	if _, err := decodeCanonicalBase64("signature", envelope.Signature, ed25519.SignatureSize, ed25519.SignatureSize); err != nil {
		return err
	}
	return nil
}

// GenerateNonce returns a cryptographically random canonical base64url nonce.
func GenerateNonce(size int) (string, error) {
	if size < minNonceBytes || size > maxNonceBytes {
		return "", fmt.Errorf("nonce entropy must be between %d and %d bytes", minNonceBytes, maxNonceBytes)
	}
	material := make([]byte, size)
	if _, err := rand.Read(material); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(material), nil
}

// NewPayload normalizes a UTC timestamp and supplies the fixed payload
// version. It does not claim that generatedAt came from a trusted clock.
func NewPayload(evidenceCount uint64, evidenceLastHash string, generatedAt time.Time, instanceID, siteID, nonce string, sequence uint64) (Payload, error) {
	payload := Payload{
		Version: PayloadVersion, EvidenceCount: evidenceCount, EvidenceLastHash: evidenceLastHash,
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339Nano), InstanceID: instanceID,
		SiteID: siteID, Nonce: nonce, Sequence: sequence,
	}
	if err := validatePayload(payload); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

// SequenceVerifier adds in-process duplicate/rollback protection after
// cryptographic verification. Its state is intentionally not durable; callers
// needing restart-safe monotonicity must persist it in a trusted atomic store.
type SequenceVerifier struct {
	mu   sync.Mutex
	last map[string]uint64
}

// NewSequenceVerifier creates an empty in-memory replay boundary.
func NewSequenceVerifier() *SequenceVerifier {
	return &SequenceVerifier{last: make(map[string]uint64)}
}

// VerifyAndAdvance verifies the signature and atomically advances the maximum
// sequence for the public-key/site/instance scope.
func (v *SequenceVerifier) VerifyAndAdvance(envelope Envelope, publicKey ed25519.PublicKey) error {
	if v == nil {
		return errors.New("sequence verifier is not configured")
	}
	if err := Verify(envelope, publicKey); err != nil {
		return err
	}
	scope := envelope.KeyID + "\x00" + envelope.Payload.SiteID + "\x00" + envelope.Payload.InstanceID
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.last == nil {
		v.last = make(map[string]uint64)
	}
	if envelope.Payload.Sequence <= v.last[scope] {
		return ErrSequenceReplay
	}
	v.last[scope] = envelope.Payload.Sequence
	return nil
}

type canonicalStatement struct {
	Domain          string  `json:"domain"`
	EnvelopeVersion int     `json:"envelopeVersion"`
	Algorithm       string  `json:"algorithm"`
	KeyID           string  `json:"keyId"`
	Payload         Payload `json:"payload"`
}

func signingBytes(version int, algorithm, signerKeyID string, payload Payload) ([]byte, error) {
	return json.Marshal(canonicalStatement{
		Domain: "chengwang.evidence-attestation", EnvelopeVersion: version,
		Algorithm: algorithm, KeyID: signerKeyID, Payload: payload,
	})
}

func validatePayload(payload Payload) error {
	if payload.Version != PayloadVersion {
		return fmt.Errorf("unsupported attestation payload version %d", payload.Version)
	}
	if payload.EvidenceCount > math.MaxInt64 {
		return errors.New("evidence count exceeds signed 64-bit interoperability limit")
	}
	if !lowerSHA256.MatchString(payload.EvidenceLastHash) {
		return errors.New("evidence last hash must be a lowercase SHA-256 hexadecimal digest")
	}
	if payload.EvidenceCount == 0 && payload.EvidenceLastHash != genesisHash {
		return errors.New("empty evidence chain must use the SHA-256 genesis hash")
	}
	if err := validateIdentifier("instance id", payload.InstanceID); err != nil {
		return err
	}
	if err := validateIdentifier("site id", payload.SiteID); err != nil {
		return err
	}
	if payload.Sequence == 0 || payload.Sequence > math.MaxInt64 {
		return errors.New("sequence must be between 1 and the signed 64-bit maximum")
	}
	if _, err := decodeCanonicalBase64("nonce", payload.Nonce, minNonceBytes, maxNonceBytes); err != nil {
		return err
	}
	if len(payload.GeneratedAt) < len("2000-01-01T00:00:00Z") || len(payload.GeneratedAt) > len("2000-01-01T00:00:00.000000000Z") {
		return errors.New("generatedAt must be canonical UTC RFC3339Nano")
	}
	parsed, err := time.Parse(time.RFC3339Nano, payload.GeneratedAt)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != payload.GeneratedAt {
		return errors.New("generatedAt must be canonical UTC RFC3339Nano")
	}
	return nil
}

func validateIdentifier(name, value string) error {
	if value == "" || len(value) > maxIDBytes || strings.TrimSpace(value) != value || !safeIdentifier.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func decodeCanonicalBase64(name, value string, min, max int) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < min || len(decoded) > max || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	return decoded, nil
}

func keyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}
