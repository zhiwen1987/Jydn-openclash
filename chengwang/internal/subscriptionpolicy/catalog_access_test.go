package subscriptionpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"chengwang/internal/subscriptionctl"
)

func accessCatalogFixture() *Catalog {
	return &Catalog{core: &catalogCore{sources: map[string]source{
		"z-reference": {config: sourceConfig{ReferenceID: "z-reference", Revision: 2, URL: "https://secret.invalid/token", SecretVersion: "private-version", CAPEM: "private-ca"}, material: []byte("private-material")},
		"a-reference": {config: sourceConfig{ReferenceID: "a-reference", Revision: 1}},
	}}}
}
func TestSubscriptionCatalogAccessSortedDetachedReferences(t *testing.T) {
	c := accessCatalogFixture()
	entries, err := c.References()
	if err != nil || len(entries) != 2 || entries[0].ReferenceID != "a-reference" || entries[1].Revision != 2 {
		t.Fatal("directory order or revision invalid")
	}
	entries[0].ReferenceID = "mutated"
	again, err := c.References()
	if err != nil || again[0].ReferenceID != "a-reference" {
		t.Fatal("directory aliases immutable catalog")
	}
}
func TestSubscriptionCatalogAccessRejectsInvalidAndDuplicateReferences(t *testing.T) {
	for _, row := range []struct {
		key, id string
		rev     uint64
	}{{"valid", "invalid/secret", 1}, {"valid", "valid", 0}, {"different", "valid", 1}, {"valid", "", 1}} {
		c := &Catalog{core: &catalogCore{sources: map[string]source{row.key: {config: sourceConfig{ReferenceID: row.id, Revision: row.rev}}}}}
		entries, err := c.References()
		if !errors.Is(err, ErrUnavailable) || entries != nil {
			t.Fatal("invalid directory accepted")
		}
	}
	c := accessCatalogFixture()
	c.core.sources["duplicate-key"] = c.core.sources["a-reference"]
	if entries, err := c.References(); err == nil || entries != nil {
		t.Fatal("duplicate semantic reference accepted")
	}
}
func TestSubscriptionCatalogAccessBudgetsAndNilFailClosed(t *testing.T) {
	for _, c := range []*Catalog{nil, {}, {core: &catalogCore{}}, {core: &catalogCore{sources: map[string]source{}}}} {
		entries, err := c.References()
		if !errors.Is(err, ErrUnavailable) || entries != nil {
			t.Fatal("absent directory ready")
		}
	}
	c := &Catalog{core: &catalogCore{sources: map[string]source{}}}
	for i := 0; i < subscriptionctl.MaxPolicyReferences; i++ {
		id := fmt.Sprintf("ref-%02d", i)
		c.core.sources[id] = source{config: sourceConfig{ReferenceID: id, Revision: 1}}
	}
	if entries, err := c.References(); err != nil || len(entries) != subscriptionctl.MaxPolicyReferences {
		t.Fatal("boundary budget rejected")
	}
	c.core.sources["extra"] = source{config: sourceConfig{ReferenceID: "extra", Revision: 1}}
	if entries, err := c.References(); err == nil || entries != nil {
		t.Fatal("directory limit ignored")
	}
}
func TestSubscriptionCatalogAccessNeverExportsPrivateMaterial(t *testing.T) {
	c := accessCatalogFixture()
	entries, err := c.References()
	if err != nil {
		t.Fatal("directory unavailable")
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal("directory JSON")
	}
	for _, secret := range []string{"secret.invalid", "token", "private-version", "private-ca", "private-material", "url", "policyDigest", "secretVersion", "caPEM"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private catalog configuration escaped")
		}
	}
	var value []map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("directory shape")
	}
	for _, entry := range value {
		if len(entry) != 2 || entry["referenceId"] == nil || entry["revision"] == nil {
			t.Fatal("unexpected public policy field")
		}
	}
	// resolver and roots are deliberately absent: listing cannot need a dialer
	// or certificate processing, and must not Describe or fetch any policy.
}
