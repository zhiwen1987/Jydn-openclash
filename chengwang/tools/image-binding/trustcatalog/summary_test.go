package trustcatalog

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestProductCatalogueSummaryDetachedAndRedacted(t *testing.T) {
	doc, anchor, raw, _, _, now := fixture(t)
	cat := replay(t, anchor, raw)
	summary := cat.Summary()
	if summary.Generation != doc.Generation || summary.StoreID != doc.StoreID || summary.SHA256 != cat.SHA256() || summary.NotAfterUnix != doc.NotAfterUnix || summary.RootKeyCount != len(doc.RootKeys) || summary.ApproverCount != len(doc.Approvers) || len(summary.Grants) != len(doc.Grants) {
		t.Fatal("summary binding mismatch")
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range [][]byte{[]byte("publicKey"), []byte("payload"), []byte("signature"), raw} {
		if bytes.Contains(encoded, excluded) {
			t.Fatal("summary leaked excluded material")
		}
	}
	if len(summary.Grants) > 0 {
		summary.Grants[0].PolicyID = "changed"
	}
	for id := range summary.PolicyFloors {
		summary.PolicyFloors[id]++
	}
	if !cat.ValidAt(now) || cat.Summary().Grants[0].PolicyID != doc.Grants[0].PolicyID || cat.Summary().PolicyFloors[doc.Grants[0].PolicyID] != doc.PolicyFloors[doc.Grants[0].PolicyID] {
		t.Fatal("summary mutation changed opaque catalogue")
	}
	var imported Catalogue
	if err = json.Unmarshal(encoded, &imported); err != nil {
		t.Fatal(err)
	}
	if imported.ValidAt(now) || imported.Summary().Generation != 0 {
		t.Fatal("summary JSON acquired authority")
	}
}
