package trustcatalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type testSigner struct {
	key     Key
	private ed25519.PrivateKey
}

func newSigner(t *testing.T) testSigner {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{Key{ID: KeyID(pub), PublicKey: pub}, private}
}
func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func signPayload(t *testing.T, payload []byte, signers ...testSigner) []byte {
	t.Helper()
	e := Envelope{Payload: payload, Signatures: []Signature{}}
	message := append([]byte(signingDomain), payload...)
	for _, signer := range signers {
		e.Signatures = append(e.Signatures, Signature{KeyID: signer.key.ID, Signature: ed25519.Sign(signer.private, message)})
	}
	return marshal(t, e)
}
func signDocument(t *testing.T, d Document, signers ...testSigner) []byte {
	t.Helper()
	return signPayload(t, marshal(t, d), signers...)
}
func copyDocument(t *testing.T, d Document) Document {
	t.Helper()
	var copied Document
	if err := json.Unmarshal(marshal(t, d), &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}
func fixture(t *testing.T) (Document, Anchor, []byte, testSigner, testSigner, time.Time) {
	t.Helper()
	root, approver := newSigner(t), newSigner(t)
	now := time.Unix(1800000000, 123456789)
	d := Document{Schema: Schema, StoreID: strings.Repeat("a", 32), Generation: 1, NotBeforeUnix: now.Unix() - 60, NotAfterUnix: now.Unix() + 3600, RootKeys: []Key{root.key}, Threshold: 1, Approvers: []Key{approver.key}, Grants: []Grant{{ID: strings.Repeat("b", 32), PolicyID: "business", ApprovalSHA256: "sha256:" + strings.Repeat("c", 64), ApproverKeyID: approver.key.ID, ManifestSHA256: "sha256:" + strings.Repeat("d", 64), Revision: 1}}, PolicyFloors: map[string]uint64{"business": 1}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	raw := signDocument(t, d, root)
	a := Anchor{StoreID: d.StoreID, InitialSHA256: digest(raw), Keys: []Key{root.key}, Threshold: 1}
	return d, a, raw, root, approver, now
}
func replay(t *testing.T, anchor Anchor, history ...[]byte) Catalogue {
	t.Helper()
	c, err := Replay(anchor, history)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func rejectReplay(t *testing.T, anchor Anchor, history ...[]byte) {
	t.Helper()
	c, err := Replay(anchor, history)
	if err != ErrInvalid || c.verified || c.Generation() != 0 || c.SHA256() != "" {
		t.Fatalf("invalid history obtained authority: %+v %v", c, err)
	}
}
func rejectAdvance(t *testing.T, previous Catalogue, raw []byte, now time.Time) {
	t.Helper()
	c, err := Advance(previous, raw, now)
	if err != ErrInvalid || c.verified || c.Generation() != 0 || c.SHA256() != "" {
		t.Fatalf("invalid update obtained authority: %+v %v", c, err)
	}
}

func TestCatalogueLifecycle(t *testing.T) {
	d, anchor, raw, root, approver, now := fixture(t)
	c := replay(t, anchor, raw)
	if !c.ValidAt(now) || c.Generation() != 1 || c.SHA256() != digest(raw) || c.StoreID() != anchor.StoreID {
		t.Fatal("catalogue identities")
	}
	g, trust, ok := c.Resolve("business", now)
	if !ok || g != d.Grants[0] || trust.KeyID != approver.key.ID || trust.PolicySHA256 != g.ApprovalSHA256 || trust.Revision != 1 || !bytes.Equal(trust.PublicKey, approver.key.PublicKey) {
		t.Fatal("bound trust")
	}
	trust.PublicKey[0] ^= 1
	_, again, ok := c.Resolve("business", now)
	if !ok || !bytes.Equal(again.PublicKey, approver.key.PublicKey) {
		t.Fatal("public key alias")
	}
	if _, _, ok := c.Resolve("missing", now); ok {
		t.Fatal("unknown policy resolved")
	}
	for _, when := range []time.Time{{}, time.Unix(d.NotBeforeUnix-1, 0), time.Unix(d.NotAfterUnix, 0)} {
		if c.ValidAt(when) {
			t.Fatal("invalid time")
		}
		if _, _, ok := c.Resolve("business", when); ok {
			t.Fatal("expired resolve")
		}
	}
	if !c.ValidAt(time.Unix(d.NotBeforeUnix, 0)) {
		t.Fatal("inclusive start")
	}
	d.Generation = 2
	nextRaw := signDocument(t, d, root)
	next, err := Advance(c, nextRaw, now)
	if err != nil || next.Generation() != 2 || c.Generation() != 1 || next.SHA256() != digest(nextRaw) {
		t.Fatal("advance mutated previous", err)
	}
	if resumed := replay(t, anchor, raw, nextRaw); resumed.SHA256() != next.SHA256() {
		t.Fatal("replay mismatch")
	}
}

func TestCatalogueRootThresholdRotation(t *testing.T) {
	d, anchor, raw, root, _, now := fixture(t)
	c := replay(t, anchor, raw)
	r2, r3 := newSigner(t), newSigner(t)
	d.Generation = 2
	d.RootKeys = []Key{r2.key, r3.key}
	d.Threshold = 2
	for name, signers := range map[string][]testSigner{"old_only": {root}, "new_only": {r2, r3}, "partial_new": {root, r2}, "duplicated_new": {root, r2, r2}, "wrong_signer": {root, newSigner(t), r3}} {
		t.Run(name, func(t *testing.T) { rejectAdvance(t, c, signDocument(t, d, signers...), now) })
	}
	raw2 := signDocument(t, d, root, r2, r3)
	next, err := Advance(c, raw2, now)
	if err != nil {
		t.Fatal(err)
	}
	d.Generation = 3
	t.Run("retired_root", func(t *testing.T) { rejectAdvance(t, next, signDocument(t, d, root), now) })
	if _, err := Advance(next, signDocument(t, d, r2, r3), now); err != nil {
		t.Fatal("new threshold rejected", err)
	}
	t.Run("initial_anchor_and_self", func(t *testing.T) {
		d.Generation = 1
		initial := signDocument(t, d, root, r2, r3)
		anchor.InitialSHA256 = digest(initial)
		if _, err := Replay(anchor, [][]byte{initial}); err != nil {
			t.Fatal(err)
		}
		bad := signDocument(t, d, root)
		anchor.InitialSHA256 = digest(bad)
		rejectReplay(t, anchor, bad)
		bad = signDocument(t, d, r2, r3)
		anchor.InitialSHA256 = digest(bad)
		rejectReplay(t, anchor, bad)
	})
}

func TestCatalogueExpiredHistoryAndFinalFreshness(t *testing.T) {
	d, anchor, _, root, _, now := fixture(t)
	d.NotBeforeUnix = now.Unix() - 172800
	d.NotAfterUnix = d.NotBeforeUnix + 3600
	old := signDocument(t, d, root)
	anchor.InitialSHA256 = digest(old)
	c := replay(t, anchor, old)
	if c.ValidAt(now) {
		t.Fatal("expired history is current")
	}
	d.Generation = 2
	d.NotBeforeUnix = now.Unix() - 60
	d.NotAfterUnix = now.Unix() + 3600
	fresh := signDocument(t, d, root)
	next, err := Advance(c, fresh, now)
	if err != nil || !next.ValidAt(now) {
		t.Fatal(err)
	}
	if !replay(t, anchor, old, fresh).ValidAt(now) {
		t.Fatal("fresh final")
	}
	d.Generation = 3
	d.NotAfterUnix = now.Unix()
	d.NotBeforeUnix = now.Unix() - 3600
	expired := signDocument(t, d, root)
	rejectAdvance(t, next, expired, now)
	if replay(t, anchor, old, fresh, expired).ValidAt(now) {
		t.Fatal("expired final accepted as current")
	}
	d.NotBeforeUnix = now.Unix() + 1
	d.NotAfterUnix = now.Unix() + 3600
	rejectAdvance(t, next, signDocument(t, d, root), now)
	rejectAdvance(t, next, fresh, time.Time{})
}

func TestCatalogueGenerationAndAnchorBinding(t *testing.T) {
	d, anchor, raw, root, _, now := fixture(t)
	c := replay(t, anchor, raw)
	for name, mutation := range map[string]func(*Document){"same_generation": func(d *Document) { d.NotAfterUnix++ }, "skip_generation": func(d *Document) { d.Generation = 3 }, "zero_generation": func(d *Document) { d.Generation = 0 }, "other_store": func(d *Document) { d.Generation = 2; d.StoreID = strings.Repeat("e", 32) }} {
		t.Run(name, func(t *testing.T) {
			v := copyDocument(t, d)
			mutation(&v)
			bad := signDocument(t, v, root)
			rejectAdvance(t, c, bad, now)
			rejectReplay(t, anchor, raw, bad)
		})
	}
	rejectReplay(t, anchor, raw, raw)
	rejectAdvance(t, Catalogue{}, raw, now)
	for name, mutation := range map[string]func(*Anchor){"pin": func(a *Anchor) { a.InitialSHA256 = "sha256:" + strings.Repeat("f", 64) }, "store": func(a *Anchor) { a.StoreID = strings.Repeat("f", 32) }, "key_id": func(a *Anchor) { a.Keys = []Key{{ID: strings.Repeat("e", 64), PublicKey: root.key.PublicKey}} }, "threshold": func(a *Anchor) { a.Threshold = 2 }, "duplicate_keys": func(a *Anchor) { a.Keys = []Key{root.key, root.key} }, "key_length": func(a *Anchor) { a.Keys = []Key{{ID: root.key.ID, PublicKey: root.key.PublicKey[:31]}} }} {
		t.Run("anchor_"+name, func(t *testing.T) { a := anchor; mutation(&a); rejectReplay(t, a, raw) })
	}
	if KeyID(nil) != "" || KeyID(make([]byte, 31)) != "" {
		t.Fatal("invalid key has ID")
	}
}

func TestCatalogueMonotonicFloorsAndRevocation(t *testing.T) {
	d, anchor, raw, root, approver, now := fixture(t)
	c := replay(t, anchor, raw)
	t.Run("floor_raise", func(t *testing.T) {
		v := copyDocument(t, d)
		v.Generation = 2
		v.PolicyFloors["business"] = 2
		v.Grants[0].ID = strings.Repeat("e", 32)
		v.Grants[0].Revision = 2
		if _, err := Advance(c, signDocument(t, v, root), now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("floor_rollback_nonzero", func(t *testing.T) {
		v := copyDocument(t, d)
		v.Generation = 2
		v.PolicyFloors["business"] = 2
		v.Grants = []Grant{}
		next, err := Advance(c, signDocument(t, v, root), now)
		if err != nil {
			t.Fatal(err)
		}
		v.Generation = 3
		v.PolicyFloors["business"] = 1
		rejectAdvance(t, next, signDocument(t, v, root), now)
		delete(v.PolicyFloors, "business")
		rejectAdvance(t, next, signDocument(t, v, root), now)
	})
	for _, kind := range []string{"key", "approval", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			v := copyDocument(t, d)
			v.Generation = 2
			v.Grants = []Grant{}
			switch kind {
			case "key":
				v.RevokedKeys = []string{approver.key.ID}
			case "approval":
				v.RevokedApprovals = []string{d.Grants[0].ApprovalSHA256}
			case "manifest":
				v.RevokedManifests = []string{d.Grants[0].ManifestSHA256}
			}
			next, err := Advance(c, signDocument(t, v, root), now)
			if err != nil {
				t.Fatal(err)
			}
			v.Generation = 3
			v.Grants = append([]Grant(nil), d.Grants...)
			rejectAdvance(t, next, signDocument(t, v, root), now)
			v.Grants = []Grant{}
			v.RevokedKeys = []string{}
			v.RevokedApprovals = []string{}
			v.RevokedManifests = []string{}
			rejectAdvance(t, next, signDocument(t, v, root), now)
		})
	}
	for name, mutation := range map[string]func(*Document){"floor_delete": func(d *Document) { d.Grants = []Grant{}; delete(d.PolicyFloors, "business") }, "floor_zero": func(d *Document) { d.PolicyFloors["business"] = 0 }, "floor_mismatch": func(d *Document) { d.PolicyFloors["business"] = 2 }, "unapproved_key": func(d *Document) { d.Grants[0].ApproverKeyID = root.key.ID }} {
		t.Run(name, func(t *testing.T) {
			v := copyDocument(t, d)
			v.Generation = 2
			mutation(&v)
			rejectAdvance(t, c, signDocument(t, v, root), now)
		})
	}
	t.Run("revoked_old_root_rotation", func(t *testing.T) {
		v := copyDocument(t, d)
		r2 := newSigner(t)
		v.Generation = 2
		v.RootKeys = []Key{r2.key}
		v.RevokedKeys = []string{root.key.ID}
		if _, err := Advance(c, signDocument(t, v, root, r2), now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("revoked_active_root", func(t *testing.T) {
		v := copyDocument(t, d)
		v.Generation = 2
		v.RevokedKeys = []string{root.key.ID}
		rejectAdvance(t, c, signDocument(t, v, root), now)
	})
}

func TestCatalogueHistoricalGrantIDCannotRebind(t *testing.T) {
	d, anchor, raw, root, _, now := fixture(t)
	c := replay(t, anchor, raw)
	removed := copyDocument(t, d)
	removed.Generation = 2
	removed.Grants = []Grant{}
	c, err := Advance(c, signDocument(t, removed, root), now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string]func(*Grant){"approval": func(g *Grant) { g.ApprovalSHA256 = "sha256:" + strings.Repeat("e", 64) }, "manifest": func(g *Grant) { g.ManifestSHA256 = "sha256:" + strings.Repeat("e", 64) }, "policy": func(g *Grant) { g.PolicyID = "other" }, "revision": func(g *Grant) { g.Revision = 2 }} {
		t.Run(name, func(t *testing.T) {
			v := copyDocument(t, d)
			v.Generation = 3
			mutation(&v.Grants[0])
			v.PolicyFloors[v.Grants[0].PolicyID] = v.Grants[0].Revision
			rejectAdvance(t, c, signDocument(t, v, root), now)
		})
	}
	t.Run("approver", func(t *testing.T) {
		v := copyDocument(t, d)
		v.Generation = 3
		newApprover := newSigner(t)
		v.Approvers = append(v.Approvers, newApprover.key)
		v.Grants[0].ApproverKeyID = newApprover.key.ID
		rejectAdvance(t, c, signDocument(t, v, root), now)
	})
	d.Generation = 3
	if _, err := Advance(c, signDocument(t, d, root), now); err != nil {
		t.Fatal("unchanged historical grant binding rejected", err)
	}
}

func TestCatalogueStrictJSONAndSignatures(t *testing.T) {
	d, anchor, raw, root, _, _ := fixture(t)
	payload := marshal(t, d)
	for name, mutate := range map[string]func([]byte) []byte{
		"extra":        func(p []byte) []byte { return append([]byte(`{"extra":0,`), p[1:]...) },
		"duplicate":    func(p []byte) []byte { return append([]byte(`{"generation":1,`), p[1:]...) },
		"case_alias":   func(p []byte) []byte { return bytes.Replace(p, []byte(`"generation"`), []byte(`"Generation"`), 1) },
		"escape_alias": func(p []byte) []byte { return bytes.Replace(p, []byte(`"generation"`), []byte(`"gen\u0065ration"`), 1) },
		"float": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"generation":1`), []byte(`"generation":1.0`), 1)
		},
		"exponent": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"generation":1`), []byte(`"generation":1e0`), 1)
		},
		"negative": func(p []byte) []byte { return bytes.Replace(p, []byte(`"generation":1`), []byte(`"generation":-1`), 1) },
		"overflow": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"generation":1`), []byte(`"generation":18446744073709551616`), 1)
		},
		"null_array": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"revokedKeys":[]`), []byte(`"revokedKeys":null`), 1)
		},
		"duplicate_floor": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"business":1`), []byte(`"business":1,"business":1`), 1)
		},
		"trailing":     func(p []byte) []byte { return append(p, []byte(` {}`)...) },
		"invalid_utf8": func(p []byte) []byte { return append(p, 0xff) },
		"depth":        func(p []byte) []byte { return []byte(`{"x":[[[[[[[[[[[[0]]]]]]]]]]]]}`) },
	} {
		t.Run("payload_"+name, func(t *testing.T) {
			bad := signPayload(t, mutate(bytes.Clone(payload)), root)
			a := anchor
			a.InitialSHA256 = digest(bad)
			rejectReplay(t, a, bad)
		})
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Envelope){"wrong_domain": func(e *Envelope) { e.Signatures[0].Signature = ed25519.Sign(root.private, e.Payload) }, "signature_byte": func(e *Envelope) { e.Signatures[0].Signature[0] ^= 1 }, "payload_byte": func(e *Envelope) { e.Payload[0] ^= 1 }, "duplicate_signature": func(e *Envelope) { e.Signatures = append(e.Signatures, e.Signatures[0]) }, "empty_signatures": func(e *Envelope) { e.Signatures = []Signature{} }, "unknown_signer": func(e *Envelope) { e.Signatures[0].KeyID = strings.Repeat("e", 64) }, "short_signature": func(e *Envelope) { e.Signatures[0].Signature = e.Signatures[0].Signature[:63] }} {
		t.Run("envelope_"+name, func(t *testing.T) {
			var e Envelope
			_ = json.Unmarshal(raw, &e)
			mutate(&e)
			bad := marshal(t, e)
			a := anchor
			a.InitialSHA256 = digest(bad)
			rejectReplay(t, a, bad)
		})
	}
	for name, mutate := range map[string]func([]byte) []byte{"duplicate_payload": func(p []byte) []byte { return append([]byte(`{"payload":"AA==",`), p[1:]...) }, "extra": func(p []byte) []byte { return append([]byte(`{"extra":0,`), p[1:]...) }, "base64_newline": func(p []byte) []byte {
		return bytes.Replace(p, []byte(base64.StdEncoding.EncodeToString(payload)), []byte(base64.StdEncoding.EncodeToString(payload)+"\n"), 1)
	}, "base64_unpadded": func(p []byte) []byte { return bytes.ReplaceAll(p, []byte("="), nil) }} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(bytes.Clone(raw))
			a := anchor
			a.InitialSHA256 = digest(bad)
			rejectReplay(t, a, bad)
		})
	}
}

func TestCatalogueStructuralResourceLimits(t *testing.T) {
	d, anchor, _, root, _, _ := fixture(t)
	for name, mutate := range map[string]func(*Document){
		"roots": func(d *Document) {
			for i := 0; i < 8; i++ {
				d.RootKeys = append(d.RootKeys, newSigner(t).key)
			}
		},
		"approvers": func(d *Document) {
			for i := 0; i < 64; i++ {
				d.Approvers = append(d.Approvers, newSigner(t).key)
			}
		},
		"grants": func(d *Document) {
			for i := 0; i < 256; i++ {
				g := d.Grants[0]
				g.ID = fmt.Sprintf("%032x", i+1)
				g.PolicyID = fmt.Sprintf("p%d", i)
				d.Grants = append(d.Grants, g)
				d.PolicyFloors[g.PolicyID] = 1
			}
		},
		"floors": func(d *Document) {
			for i := 0; i < 512; i++ {
				d.PolicyFloors[fmt.Sprintf("p%d", i)] = 1
			}
		},
		"revocations": func(d *Document) {
			for i := 0; i < 4097; i++ {
				d.RevokedKeys = append(d.RevokedKeys, fmt.Sprintf("%064x", i))
			}
		},
		"ttl":                func(d *Document) { d.NotAfterUnix = d.NotBeforeUnix + 86401 },
		"zero_ttl":           func(d *Document) { d.NotAfterUnix = d.NotBeforeUnix },
		"duplicate_root":     func(d *Document) { d.RootKeys = append(d.RootKeys, d.RootKeys[0]) },
		"duplicate_approver": func(d *Document) { d.Approvers = append(d.Approvers, d.Approvers[0]) },
		"duplicate_grant":    func(d *Document) { d.Grants = append(d.Grants, d.Grants[0]) },
		"duplicate_policy":   func(d *Document) { g := d.Grants[0]; g.ID = strings.Repeat("e", 32); d.Grants = append(d.Grants, g) },
		"duplicate_revocation": func(d *Document) {
			d.RevokedManifests = []string{"sha256:" + strings.Repeat("e", 64), "sha256:" + strings.Repeat("e", 64)}
		},
		"key_id_mismatch":     func(d *Document) { d.RootKeys[0].ID = strings.Repeat("e", 64) },
		"noncanonical_digest": func(d *Document) { d.Grants[0].ManifestSHA256 = strings.ToUpper(d.Grants[0].ManifestSHA256) },
		"negative_threshold":  func(d *Document) { d.Threshold = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			v := copyDocument(t, d)
			mutate(&v)
			bad := signDocument(t, v, root)
			a := anchor
			a.InitialSHA256 = digest(bad)
			rejectReplay(t, a, bad)
		})
	}
	t.Run("envelope_bytes", func(t *testing.T) {
		bad := bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1)
		a := anchor
		a.InitialSHA256 = digest(bad)
		rejectReplay(t, a, bad)
	})
	t.Run("empty_history", func(t *testing.T) { rejectReplay(t, anchor) })
	t.Run("anchor_root_budget", func(t *testing.T) {
		a := anchor
		for i := 0; i < 8; i++ {
			a.Keys = append(a.Keys, newSigner(t).key)
		}
		rejectReplay(t, a, signDocument(t, d, root))
	})
}

func TestCatalogueHistoryLimits(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		d, anchor, raw, root, _, now := fixture(t)
		history := [][]byte{raw}
		c := replay(t, anchor, raw)
		for i := 2; i <= MaxHistory; i++ {
			d.Generation = uint64(i)
			next := signDocument(t, d, root)
			var err error
			c, err = Advance(c, next, now)
			if err != nil {
				t.Fatal(i, err)
			}
			history = append(history, next)
		}
		if replay(t, anchor, history...).Generation() != MaxHistory {
			t.Fatal("history cap boundary")
		}
		d.Generation++
		next := signDocument(t, d, root)
		rejectAdvance(t, c, next, now)
		rejectReplay(t, anchor, append(history, next)...)
	})
	t.Run("total_bytes", func(t *testing.T) {
		d, anchor, _, root, _, now := fixture(t)
		for i := 0; i < 800; i++ {
			d.RevokedManifests = append(d.RevokedManifests, fmt.Sprintf("sha256:%064x", i))
		}
		raw := signDocument(t, d, root)
		if len(raw) > MaxEnvelopeBytes {
			t.Fatal("fixture exceeds envelope")
		}
		anchor.InitialSHA256 = digest(raw)
		history := [][]byte{raw}
		c := replay(t, anchor, raw)
		total := len(raw)
		for i := 2; i <= MaxHistory; i++ {
			d.Generation = uint64(i)
			next := signDocument(t, d, root)
			history = append(history, next)
			total += len(next)
			if total > MaxHistoryBytes {
				rejectAdvance(t, c, next, now)
				rejectReplay(t, anchor, history...)
				return
			}
			var err error
			c, err = Advance(c, next, now)
			if err != nil {
				t.Fatal(i, err)
			}
		}
		t.Fatal("fixture did not exceed history bytes")
	})
	t.Run("historical_grants", func(t *testing.T) {
		d, anchor, _, root, _, now := fixture(t)
		original := d.Grants[0]
		d.Grants = []Grant{}
		d.PolicyFloors = map[string]uint64{}
		for i := 0; i < 256; i++ {
			g := original
			g.PolicyID = fmt.Sprintf("p%d", i)
			g.ID = fmt.Sprintf("%032x", i+1)
			d.Grants = append(d.Grants, g)
			d.PolicyFloors[g.PolicyID] = 1
		}
		raw := signDocument(t, d, root)
		anchor.InitialSHA256 = digest(raw)
		history := [][]byte{raw}
		c := replay(t, anchor, raw)
		for gen := 2; gen <= 17; gen++ {
			d.Generation = uint64(gen)
			for i := range d.Grants {
				d.Grants[i].ID = fmt.Sprintf("%032x", (gen-1)*256+i+1)
			}
			next := signDocument(t, d, root)
			history = append(history, next)
			if gen == 17 {
				rejectAdvance(t, c, next, now)
				rejectReplay(t, anchor, history...)
				return
			}
			var err error
			c, err = Advance(c, next, now)
			if err != nil {
				t.Fatal(gen, err)
			}
		}
	})
}

func TestCatalogueZeroAndImportedReceiptsHaveNoAuthority(t *testing.T) {
	d, anchor, raw, _, _, now := fixture(t)
	c := replay(t, anchor, raw)
	encoded := marshal(t, c)
	if string(encoded) != "{}" {
		t.Fatal("private catalogue leaked")
	}
	for _, imported := range [][]byte{encoded, []byte(`{"verified":true,"generation":1}`)} {
		var value Catalogue
		if err := json.Unmarshal(imported, &value); err != nil {
			t.Fatal(err)
		}
		if value.ValidAt(now) {
			t.Fatal("JSON imported authority")
		}
		if _, _, ok := value.Resolve(d.Grants[0].PolicyID, now); ok {
			t.Fatal("JSON imported trust")
		}
		rejectAdvance(t, value, raw, now)
	}
}
