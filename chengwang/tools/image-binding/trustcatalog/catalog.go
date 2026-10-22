// Package trustcatalog authenticates a narrow, append-only image approval
// catalogue. It is not a TUF implementation and grants no deployment authority.
package trustcatalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"chengwang/image-binding/policy"
)

const Schema = "chengwang.trust-catalog/v1"
const MaxEnvelopeBytes = 256 << 10
const MaxHistory = 64
const MaxHistoryBytes = 4 << 20
const MaxHistoricalGrants = 4096
const signingDomain = Schema + "\x00"

var ErrInvalid = errors.New("invalid trust catalogue")

type Key struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"publicKey"`
}
type Anchor struct {
	StoreID       string `json:"storeID"`
	InitialSHA256 string `json:"initialSHA256"`
	Keys          []Key  `json:"keys"`
	Threshold     int    `json:"threshold"`
}
type Grant struct {
	ID             string `json:"id"`
	PolicyID       string `json:"policyID"`
	ApprovalSHA256 string `json:"approvalSHA256"`
	ApproverKeyID  string `json:"approverKeyID"`
	ManifestSHA256 string `json:"manifestSHA256"`
	Revision       uint64 `json:"revision"`
}
type Document struct {
	Schema           string            `json:"schema"`
	StoreID          string            `json:"storeID"`
	Generation       uint64            `json:"generation"`
	NotBeforeUnix    int64             `json:"notBeforeUnix"`
	NotAfterUnix     int64             `json:"notAfterUnix"`
	RootKeys         []Key             `json:"rootKeys"`
	Threshold        int               `json:"threshold"`
	Approvers        []Key             `json:"approvers"`
	Grants           []Grant           `json:"grants"`
	PolicyFloors     map[string]uint64 `json:"policyFloors"`
	RevokedKeys      []string          `json:"revokedKeys"`
	RevokedApprovals []string          `json:"revokedApprovals"`
	RevokedManifests []string          `json:"revokedManifests"`
}
type Signature struct {
	KeyID     string `json:"keyID"`
	Signature []byte `json:"signature"`
}
type Envelope struct {
	Payload    []byte      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// Catalogue has no public fields or import constructor. Its JSON form is {},
// and deserializing that form never authenticates a catalogue.
type Catalogue struct {
	verified   bool
	document   Document
	digest     string
	count      int
	bytes      int
	historical map[string]Grant
}

// KeyID binds an identifier to the exact 32-byte Ed25519 public key.
// Invalid key lengths have no identifier.
func KeyID(publicKey []byte) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	h := sha256.Sum256(publicKey)
	return hex.EncodeToString(h[:])
}
func (c Catalogue) Generation() uint64 { return c.document.Generation }
func (c Catalogue) SHA256() string     { return c.digest }
func (c Catalogue) StoreID() string    { return c.document.StoreID }
func (c Catalogue) ValidAt(now time.Time) bool {
	return c.verified && !now.IsZero() && now.Unix() >= c.document.NotBeforeUnix && now.Unix() < c.document.NotAfterUnix
}
func (c Catalogue) Resolve(policyID string, now time.Time) (Grant, policy.Trust, bool) {
	if !c.ValidAt(now) {
		return Grant{}, policy.Trust{}, false
	}
	for _, g := range c.document.Grants {
		if g.PolicyID != policyID {
			continue
		}
		for _, key := range c.document.Approvers {
			if key.ID == g.ApproverKeyID {
				return g, policy.Trust{KeyID: key.ID, PublicKey: bytes.Clone(key.PublicKey), PolicySHA256: g.ApprovalSHA256, Revision: g.Revision}, true
			}
		}
	}
	return Grant{}, policy.Trust{}, false
}

// Replay authenticates history, not freshness. Callers must check ValidAt at
// every decision; expired historical metadata can still authenticate rotation.
// The anchor must come from a separately protected provisioning channel.
func Replay(anchor Anchor, history [][]byte) (Catalogue, error) {
	if !hexValue(anchor.StoreID, 32) || !digestValue(anchor.InitialSHA256) || !validKeys(anchor.Keys, anchor.Threshold, 8) || len(history) == 0 || len(history) > MaxHistory {
		return Catalogue{}, ErrInvalid
	}
	if digest(history[0]) != anchor.InitialSHA256 {
		return Catalogue{}, ErrInvalid
	}
	var previous Catalogue
	for i, raw := range history {
		d, signatures, err := parse(raw)
		if err != nil || d.StoreID != anchor.StoreID {
			return Catalogue{}, ErrInvalid
		}
		if i == 0 {
			if d.Generation != 1 || !verifyThreshold(d, signatures, anchor.Keys, anchor.Threshold) || !verifyThreshold(d, signatures, d.RootKeys, d.Threshold) {
				return Catalogue{}, ErrInvalid
			}
		} else if !validNext(previous, d, signatures) {
			return Catalogue{}, ErrInvalid
		}
		previous, err = accept(previous, d, raw)
		if err != nil {
			return Catalogue{}, ErrInvalid
		}
	}
	return previous, nil
}

// Advance accepts precisely the next generation, authenticates both old and
// new root thresholds, and requires the new catalogue to be current now.
func Advance(previous Catalogue, raw []byte, now time.Time) (Catalogue, error) {
	if !previous.verified || now.IsZero() {
		return Catalogue{}, ErrInvalid
	}
	d, signatures, err := parse(raw)
	if err != nil || !validNext(previous, d, signatures) {
		return Catalogue{}, ErrInvalid
	}
	next, err := accept(previous, d, raw)
	if err != nil || !next.ValidAt(now) {
		return Catalogue{}, ErrInvalid
	}
	return next, nil
}

type authenticatedSignature struct {
	keyID                    string
	publicPayload, signature []byte
}

func verifyThreshold(d Document, signatures []authenticatedSignature, keys []Key, threshold int) bool {
	if threshold < 1 || threshold > len(keys) {
		return false
	}
	valid := 0
	for _, key := range keys {
		for _, s := range signatures {
			if s.keyID == key.ID && ed25519.Verify(key.PublicKey, s.publicPayload, s.signature) {
				valid++
				break
			}
		}
	}
	return valid >= threshold
}

func validNext(previous Catalogue, d Document, signatures []authenticatedSignature) bool {
	p := previous.document
	return previous.verified && p.Generation != math.MaxUint64 && d.Generation == p.Generation+1 && d.StoreID == p.StoreID && verifyThreshold(d, signatures, p.RootKeys, p.Threshold) && verifyThreshold(d, signatures, d.RootKeys, d.Threshold)
}

func accept(previous Catalogue, d Document, raw []byte) (Catalogue, error) {
	if previous.count >= MaxHistory || previous.bytes > MaxHistoryBytes-len(raw) {
		return Catalogue{}, ErrInvalid
	}
	historical := make(map[string]Grant, len(previous.historical)+len(d.Grants))
	for id, g := range previous.historical {
		historical[id] = g
	}
	if previous.verified {
		p := previous.document
		if !containsAll(d.RevokedKeys, p.RevokedKeys) || !containsAll(d.RevokedApprovals, p.RevokedApprovals) || !containsAll(d.RevokedManifests, p.RevokedManifests) {
			return Catalogue{}, ErrInvalid
		}
		for id, floor := range p.PolicyFloors {
			if d.PolicyFloors[id] < floor {
				return Catalogue{}, ErrInvalid
			}
		}
	}
	for _, g := range d.Grants {
		if old, found := historical[g.ID]; found && old != g {
			return Catalogue{}, ErrInvalid
		}
		historical[g.ID] = g
	}
	if len(historical) > MaxHistoricalGrants {
		return Catalogue{}, ErrInvalid
	}
	return Catalogue{verified: true, document: d, digest: digest(raw), count: previous.count + 1, bytes: previous.bytes + len(raw), historical: historical}, nil
}
func containsAll(current, previous []string) bool {
	set := make(map[string]bool, len(current))
	for _, value := range current {
		set[value] = true
	}
	for _, value := range previous {
		if !set[value] {
			return false
		}
	}
	return true
}
func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}
