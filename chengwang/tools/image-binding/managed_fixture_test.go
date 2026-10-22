package binding_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	binding "chengwang/image-binding"
	"chengwang/image-binding/policy"
	"chengwang/image-binding/trustcatalog"
)

func assertManaged(t *testing.T, r binding.ManagedResult, m managedMaterial) {
	t.Helper()
	var envelope struct {
		Payload []byte `json:"payload"`
	}
	var approval struct {
		NotAfterUnix int64 `json:"notAfterUnix"`
	}
	if json.Unmarshal(m.approval, &envelope) != nil || json.Unmarshal(envelope.Payload, &approval) != nil {
		t.Fatal("invalid expiry fixture")
	}
	until := m.document.NotAfterUnix
	if approval.NotAfterUnix < until {
		until = approval.NotAfterUnix
	}
	if !r.Verified() || r.Authorization() != "BLOCKED" || r.Boundary() != binding.ManagedBoundary || r.GrantID() != m.document.Grants[0].ID || r.CatalogueGeneration() != m.document.Generation || r.CatalogueSHA256() != hashed(m.catalogue) || len(r.EvidenceSHA256()) != 71 || r.ValidUntilUnix() != until {
		t.Fatal("managed result omitted durable trust binding")
	}
	assertBinding(t, r.Binding(), m.material)
	raw, err := json.Marshal(r)
	if err != nil || string(raw) != "{}" {
		t.Fatal("managed evidence exported reusable authority")
	}
}

type managedMaterial struct {
	material
	anchor    trustcatalog.Anchor
	document  trustcatalog.Document
	catalogue []byte
	rootKey   ed25519.PrivateKey
}

func randomManagedID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw[:])
}

// Independent ephemeral approval/catalogue authorities exist only in tests.
// No key is written to disk or installed as product trust.
func newManagedMaterial(t *testing.T, m material) managedMaterial {
	t.Helper()
	var original struct {
		Payload   []byte `json:"payload"`
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(m.approval, &original); err != nil {
		t.Fatal(err)
	}
	var approval map[string]any
	if err := json.Unmarshal(original.Payload, &approval); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := trustcatalog.KeyID(public)
	approval["approverKeyID"] = keyID
	payload := encode(t, approval)
	m.trust = policy.Trust{KeyID: keyID, PublicKey: public, PolicySHA256: hashed(payload), Revision: m.trust.Revision}
	m.approval = encode(t, map[string]any{"payload": payload, "signature": ed25519.Sign(private, append([]byte(policy.Schema+"\x00"), payload...))})
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := trustcatalog.Key{ID: trustcatalog.KeyID(rootPublic), PublicKey: rootPublic}
	grant := trustcatalog.Grant{ID: randomManagedID(t), PolicyID: approval["policyID"].(string), ApprovalSHA256: m.trust.PolicySHA256, ApproverKeyID: keyID, ManifestSHA256: hashed(m.manifest), Revision: m.trust.Revision}
	now := time.Now().Unix()
	document := trustcatalog.Document{
		Schema: trustcatalog.Schema, StoreID: randomManagedID(t), Generation: 1,
		NotBeforeUnix: now - 10, NotAfterUnix: now + 600,
		RootKeys: []trustcatalog.Key{root}, Threshold: 1,
		Approvers: []trustcatalog.Key{{ID: keyID, PublicKey: public}}, Grants: []trustcatalog.Grant{grant},
		PolicyFloors: map[string]uint64{grant.PolicyID: grant.Revision},
		RevokedKeys:  []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{},
	}
	catalogue := signManagedCatalogue(t, document, rootPrivate)
	anchor := trustcatalog.Anchor{StoreID: document.StoreID, InitialSHA256: hashed(catalogue), Keys: []trustcatalog.Key{root}, Threshold: 1}
	c, err := trustcatalog.Replay(anchor, [][]byte{catalogue})
	if err != nil || !c.ValidAt(time.Now()) {
		t.Fatalf("invalid managed test catalogue: %v", err)
	}
	return managedMaterial{m, anchor, document, catalogue, rootPrivate}
}

func signManagedCatalogue(t *testing.T, d trustcatalog.Document, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	payload := encode(t, d)
	signatures := make([]trustcatalog.Signature, 0, len(keys))
	for _, key := range keys {
		signatures = append(signatures, trustcatalog.Signature{KeyID: trustcatalog.KeyID(key.Public().(ed25519.PublicKey)), Signature: ed25519.Sign(key, append([]byte(trustcatalog.Schema+"\x00"), payload...))})
	}
	return encode(t, trustcatalog.Envelope{Payload: payload, Signatures: signatures})
}
